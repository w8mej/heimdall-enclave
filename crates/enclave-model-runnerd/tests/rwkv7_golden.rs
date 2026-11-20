//! The RWKV-7 backend (World tokenizer, native `rwkv7-v1` graph, runner-owned
//! state) must reproduce the independent `rwkv` 0.8.32 reference recorded in
//! tests/data/rwkv7-golden.json. Needs the converted artifact
//! (scripts/fetch-trained-model.py rwkv7, then scripts/convert-rwkv7.py) and
//! MCPMAC_MLX_WORKER; otherwise it reports a skip unless
//! MCPMAC_REQUIRE_RWKV7 is set.

use enclave_model_runnerd::backends::mlx::rwkv7::MlxRwkv7;
use enclave_model_runnerd::classes::ssm::{RecurrentBackend, RecurrentTokenModel};
use enclave_model_runnerd::manifest::ExecutionClass;
use enclave_model_runnerd::safetensors::parse;
use enclave_model_runnerd::topology::OpAttestor;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Reference ran in fp32 on CPU with a different op order; logits are O(10).
const LOGIT_TOLERANCE: f32 = 2e-3;

fn golden() -> Value {
    serde_json::from_str(include_str!("data/rwkv7-golden.json")).unwrap()
}

fn artifact(golden: &Value) -> Option<Vec<u8>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/rwkv7-0.1b/rwkv7-0.1b.safetensors");
    let required = std::env::var_os("MCPMAC_REQUIRE_RWKV7").is_some();
    let worker = std::env::var_os("MCPMAC_MLX_WORKER").is_some();
    match std::fs::read(&path) {
        Ok(bytes) if worker => {
            assert_eq!(hex::encode(Sha256::digest(&bytes)), golden["artifact_sha256"].as_str().unwrap(), "artifact drifted");
            Some(bytes)
        }
        _ => {
            assert!(!required, "RWKV-7 artifact and MCPMAC_MLX_WORKER required");
            eprintln!("RWKV7_GOLDEN_CHECKED=false; artifact or native worker absent");
            None
        }
    }
}

fn ids(v: &Value) -> Vec<u32> {
    v.as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as u32).collect()
}

fn argmax(logits: &[f32]) -> u32 {
    let mut best = 0;
    for (i, v) in logits.iter().enumerate() {
        if *v > logits[best] {
            best = i;
        }
    }
    best as u32
}

#[test]
fn rwkv7_backend_matches_the_independent_reference() {
    let golden = golden();
    let Some(bytes) = artifact(&golden) else { return };
    let index = parse(&bytes).unwrap();
    let mut attest = OpAttestor::new(ExecutionClass::RecurrentSsmTtt, &[]);
    let model = MlxRwkv7::load(&index, &bytes, &mut attest).unwrap();
    let tm = model.token_model().unwrap();

    for case in golden["tokenizer"].as_array().unwrap() {
        let text = case["text"].as_str().unwrap().as_bytes();
        let expected = ids(&case["ids"]);
        assert_eq!(tm.encode(text).unwrap(), expected, "encode {:?}", case["text"]);
        let decoded: Vec<u8> = expected.iter().flat_map(|id| tm.token_bytes(*id).unwrap().to_vec()).collect();
        assert_eq!(decoded, text);
    }

    let width = model.width();
    let (c, per) = (768, width / 12);
    let mut worst = 0f32;
    for (case, greedy) in golden["logits"].as_array().unwrap().iter().zip(golden["greedy"].as_array().unwrap()) {
        let prompt = ids(&case["ids"]);
        let mut h = model.system_state();
        let logits = tm.advance(&mut h, &prompt).unwrap();
        // Batched and token-by-token advancing agree.
        let mut stepwise = model.system_state();
        let mut last = Vec::new();
        for id in &prompt {
            last = tm.advance(&mut stepwise, &[*id]).unwrap();
        }
        assert!(h.iter().zip(&stepwise).all(|(a, b)| (a - b).abs() < 1e-4), "batched vs stepwise state");
        assert!(logits.iter().zip(&last).all(|(a, b)| (a - b).abs() < 1e-4), "batched vs stepwise logits");

        for (want, got) in ids(&case["last_top10_ids"]).iter().zip(case["last_top10_logits"].as_array().unwrap()) {
            let reference = got.as_f64().unwrap() as f32;
            let ours = logits[*want as usize];
            worst = worst.max((ours - reference).abs());
            assert!((ours - reference).abs() < LOGIT_TOLERANCE, "{}: logit {want} {ours} vs {reference}", case["name"]);
        }
        assert_eq!(argmax(&logits), ids(&case["last_top10_ids"])[0]);

        // State layout: per layer att_x_prev[C], kv[H,N,N], ffn_x_prev[C].
        for row in case["state"].as_array().unwrap() {
            let layer = row["layer"].as_u64().unwrap() as usize;
            let chunk = &h[layer * per..(layer + 1) * per];
            for (i, v) in row["att_x_prev_head"].as_array().unwrap().iter().enumerate() {
                assert!((chunk[i] - v.as_f64().unwrap() as f32).abs() < 1e-3, "layer {layer} att_x[{i}]");
            }
            for (i, v) in row["kv_flat_head"].as_array().unwrap().iter().enumerate() {
                assert!((chunk[c + i] - v.as_f64().unwrap() as f32).abs() < 1e-3, "layer {layer} kv[{i}]");
            }
            let kv_sum: f32 = chunk[c..per - c].iter().sum();
            let reference = row["kv_sum"].as_f64().unwrap() as f32;
            assert!((kv_sum - reference).abs() < 1e-2 * reference.abs().max(1.0), "layer {layer} kv_sum {kv_sum} vs {reference}");
        }

        let mut produced = Vec::new();
        let mut next = argmax(&logits);
        while produced.len() < 24 && !tm.is_end(next) {
            produced.push(next);
            next = argmax(&tm.advance(&mut h, &[next]).unwrap());
        }
        assert_eq!(produced, ids(&greedy["greedy_new_ids"]), "{} greedy", case["name"]);
    }
    eprintln!("RWKV7_GOLDEN_CHECKED=true; max top-10 logit deviation {worst:e}");
}
