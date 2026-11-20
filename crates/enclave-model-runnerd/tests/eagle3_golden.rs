//! The EAGLE-3 backend (closed Qwen3 tokenizer, native `eagle3-v1` target and
//! draft graphs) and the speculative gate must reproduce the references in
//! tests/data/qwen3-eagle3-golden.json: transformers Qwen3 for the target,
//! the SpecForge draft forward for the draft. Needs the packaged artifact
//! (scripts/fetch-trained-model.py qwen3 and eagle3, then `enclave-pack
//! --hf-eagle3-target target/qwen3-0.6b --eagle3-head target/eagle3-qwen3-0.6b
//! --model-id qwen3-0_6b-eagle3 --out-dir target/eagle3-pack`) and
//! depot_MLX_WORKER; otherwise it reports a skip unless depot_REQUIRE_EAGLE3.

use enclave_model_runnerd::backends::mlx::eagle3::MlxEagle3;
use enclave_model_runnerd::classes::speculative::{
    DepthGate, FixedThermal, PowerSource, SpeculativeTokenModel, ThermalState,
};
use enclave_model_runnerd::manifest::ExecutionClass;
use enclave_model_runnerd::safetensors::parse;
use enclave_model_runnerd::topology::OpAttestor;
use serde_json::Value;

fn ids(v: &Value) -> Vec<u32> {
    v.as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as u32).collect()
}

fn artifact() -> Option<Vec<u8>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/eagle3-pack/qwen3-0_6b-eagle3.safetensors");
    match std::fs::read(&path) {
        Ok(bytes) if std::env::var_os("depot_MLX_WORKER").is_some() => Some(bytes),
        _ => {
            assert!(std::env::var_os("depot_REQUIRE_EAGLE3").is_none(), "EAGLE-3 artifact and depot_MLX_WORKER required");
            eprintln!("EAGLE3_GOLDEN_CHECKED=false; artifact or native worker absent");
            None
        }
    }
}

#[test]
fn eagle3_pair_and_gate_match_the_references() {
    let golden: Value = serde_json::from_str(include_str!("data/qwen3-eagle3-golden.json")).unwrap();
    let Some(bytes) = artifact() else { return };
    let index = parse(&bytes).unwrap();
    let mut attest = OpAttestor::new(ExecutionClass::SpeculativeOrRecurrentDepth, &[]);
    let pair = MlxEagle3::load(&index, &bytes, &mut attest).unwrap();
    let fw = pair.feature_width();
    let mut worst_feature = 0f32;
    for case in golden["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let prompt = ids(&case["ids"]);
        assert_eq!(pair.encode(case["text"].as_str().unwrap().as_bytes()).unwrap(), prompt, "{name} tokens");

        let (next, features) = pair.verify(&prompt, 1).unwrap();
        assert_eq!(next[0], ids(&case["last_top10_ids"])[0], "{name} target argmax");
        let last = &features[(prompt.len() - 1) * fw..prompt.len() * fw];
        for (j, f) in case["features_last"].as_array().unwrap().iter().enumerate() {
            let part = &last[j * 1024..(j + 1) * 1024];
            for (i, v) in f["head"].as_array().unwrap().iter().enumerate() {
                worst_feature = worst_feature.max((part[i] - v.as_f64().unwrap() as f32).abs());
            }
            let sum: f32 = part.iter().sum();
            let reference = f["sum"].as_f64().unwrap() as f32;
            assert!((sum - reference).abs() < 1e-2 * reference.abs().max(10.0), "{name} feature sum {j}: {sum} vs {reference}");
        }

        // Draft chain after the target's first token.
        let mut ctx = prompt.clone();
        ctx.push(next[0]);
        let chain = SpeculativeTokenModel::draft(&pair, &ctx, &features, 3).unwrap();
        assert_eq!(chain, ids(&case["draft_after_first"]["chain"]), "{name} draft chain");

        // Plain greedy decoding through verify.
        let mut greedy = Vec::new();
        let mut ctx = prompt.clone();
        for _ in 0..24 {
            let t = pair.verify(&ctx, 1).unwrap().0[0];
            if pair.is_end(t) {
                break;
            }
            greedy.push(t);
            ctx.push(t);
        }
        assert_eq!(greedy, ids(&case["greedy_new_ids"]), "{name} greedy");
    }
    assert!(worst_feature < 5e-2, "feature deviation {worst_feature}");

    // The gate's speculative output equals greedy target decoding.
    let gate = DepthGate::speculative(Box::new(pair), Box::new(FixedThermal(ThermalState::Nominal, PowerSource::Ac)), 8, 4, 4096).unwrap();
    for case in golden["cases"].as_array().unwrap() {
        let text = case["greedy_text"].as_str().unwrap().as_bytes();
        let n = text.len().min(48);
        let mut attest = OpAttestor::new(ExecutionClass::SpeculativeOrRecurrentDepth, &[]);
        let (out, zeroed) = gate.speculate(case["text"].as_str().unwrap().as_bytes(), n, 3, &mut attest).unwrap();
        assert_eq!(out, &text[..n], "{} speculative", case["name"]);
        eprintln!("{}: {} bytes, {} rejected drafts zeroized", case["name"], out.len(), zeroed);
    }
    eprintln!("EAGLE3_GOLDEN_CHECKED=true; max feature deviation {worst_feature:e}");
}
