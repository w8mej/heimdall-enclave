//! The packaged 4-bit LLaDA-8B-Instruct (`enclave-pack --hf-llada`, in
//! target/llada-pack) served by the native worker's `llada-v1` graph.
//!
//! A semantic probe checks the converter's tensor roles independently of any
//! publisher code: with a wrong gate/up, attention or RoPE mapping the
//! unmasked answer to a factual question is not the expected word. Needs
//! MCPMAC_MLX_WORKER naming the native worker; without the worker or the
//! package the test reports a skip unless MCPMAC_REQUIRE_LLADA is set.

mod common;

use std::time::Instant;

use common::{mapped_package_or_skip, operator, ONE_MODEL_AT_A_TIME};
use enclave_model_runnerd::dfa::{ArgSchema, Dfa};
use enclave_model_runnerd::service::{RunnerRequest, RunnerResponse};

use enclave_model_runnerd::backends::mlx::runtime::MlxLlada;
use enclave_model_runnerd::classes::diffusion::DiffusionTokenModel;
use enclave_model_runnerd::manifest::ExecutionClass;
use enclave_model_runnerd::topology::OpAttestor;

fn chat(question: &str) -> String {
    format!("<|startoftext|><|start_header_id|>user<|end_header_id|>\n\n{question}<|eot_id|>\
        <|start_header_id|>assistant<|end_header_id|>\n\n")
}

fn argmax(row: &[f32]) -> u32 {
    row.iter().enumerate().fold((0, f32::NEG_INFINITY), |(bi, bv), (i, &v)| if v > bv { (i, v) } else { (bi, bv) }).0 as u32
}

#[test]
fn packaged_llada_answers_a_factual_question_on_the_gpu() {
    // One 8B model on the GPU at a time: run concurrently with the schema
    // test below, both miss their deadlines.
    let _serial = ONE_MODEL_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/llada-pack/llada-8b-instruct.safetensors");
    let required = std::env::var_os("MCPMAC_REQUIRE_LLADA").is_some();
    let (Some(_), Ok(bytes)) = (std::env::var_os("MCPMAC_MLX_WORKER"), std::fs::read(&path)) else {
        assert!(!required, "packaged LLaDA and MCPMAC_MLX_WORKER required");
        eprintln!("LLADA_RUNTIME_CHECKED=false; package or worker absent");
        return;
    };
    let mut idx = enclave_model_runnerd::safetensors::parse(&bytes).unwrap();
    let tokenizer = idx.metadata.remove(enclave_model_runnerd::backends::mlx::llada::TOKENIZER_KEY).unwrap();
    let mut attest = OpAttestor::new(ExecutionClass::DiscreteDiffusion, &[]);
    let started = Instant::now();
    let model = MlxLlada::load(&idx, tokenizer, &bytes, &mut attest).unwrap();
    let load_time = started.elapsed();
    drop(bytes);
    let tokenizer = model.tokenizer();
    let prompt = tokenizer.encode(&chat("What is the capital of France? Answer with one word.")).unwrap();
    let block = 8;
    let x = vec![None; block];
    let vocab = tokenizer.vocab();
    let mut times = Vec::new();
    let mut logits = Vec::new();
    for _ in 0..3 {
        let started = Instant::now();
        logits = model.logits(&prompt, &x).unwrap();
        times.push(started.elapsed());
    }
    assert_eq!(logits.len(), block * vocab);
    assert!(logits.iter().all(|v| v.is_finite()));
    let first = argmax(&logits[..vocab]);
    let word = String::from_utf8(tokenizer.decode(&[first]).unwrap()).unwrap();
    // Greedy fill of the whole block, one most-confident position per pass.
    let mut x = x;
    for _ in 0..block {
        let logits = model.logits(&prompt, &x).unwrap();
        let (pos, tok, _) = (0..block).filter(|i| x[*i].is_none()).map(|i| {
            let row = &logits[i * vocab..(i + 1) * vocab];
            let t = argmax(row);
            (i, t, row[t as usize])
        }).fold((0, 0, f32::NEG_INFINITY), |b, c| if c.2 > b.2 { c } else { b });
        x[pos] = Some(tok);
    }
    let ids: Vec<u32> = x.into_iter().flatten().filter(|t| !tokenizer.is_special(*t)).collect();
    let answer = String::from_utf8_lossy(&tokenizer.decode(&ids).unwrap()).into_owned();
    eprintln!("LLADA_RUNTIME: load {load_time:?}, forward {:?} for {} tokens, first {word:?}, filled {answer:?}",
        times, prompt.len() + block);
    assert_eq!(word.trim(), "Paris", "first masked position");
    assert!(answer.contains("Paris"), "{answer:?}");
}

/// End to end through the runner service: bind the published package, then
/// a schema-constrained generation on the token path. The output is a
/// grammar-accepted document carrying the answer the prompt asks for, and
/// the whole generation fits the manifest's signed deadline.
#[test]
fn packaged_llada_fills_a_schema_through_the_runner() {
    let Some(pack) = mapped_package_or_skip("llada-pack", "MCPMAC_REQUIRE_LLADA", "LLADA_SERVICE_CHECKED") else { return };
    let _serial = ONE_MODEL_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let service = pack.runner();
    let started = Instant::now();
    assert!(matches!(pack.bind_on(&service, &pack.bytes()), Ok(RunnerResponse::Bound { .. })), "bind");
    let bind_time = started.elapsed();
    let schema = ArgSchema::Object(vec![(
        "priority".into(),
        ArgSchema::Enum(["routine", "important", "urgent", "critical"].map(String::from).to_vec()),
    )]);
    let prompt = chat("Classify the support ticket priority as routine, important, urgent or critical. \
        Reply in JSON. Ticket: Production database is down and customers cannot log in.");
    let started = Instant::now();
    let response = service.handle(&operator(), RunnerRequest::GenerateStructured {
        schema: schema.clone(), len: 16, prompt: Some(prompt.into_bytes().into()),
    });
    let generate_time = started.elapsed();
    let Ok(RunnerResponse::Text(output)) = response else { panic!("{response:?}") };
    assert!(Dfa::compile(&schema).unwrap().accepts(&output));
    let doc: serde_json::Value = serde_json::from_slice(&output).unwrap();
    eprintln!("LLADA_SERVICE: bind {bind_time:?}, generate {generate_time:?}, output {}", String::from_utf8_lossy(&output));
    assert!(["urgent", "critical"].contains(&doc["priority"].as_str().unwrap()), "{doc}");
}
