//! The V-JEPA 2 backend (native `vjepa2-v1` encoder) must reproduce the
//! transformers 4.53.3 encoder recorded in tests/data/vjepa2-golden.json.
//! Needs the packaged artifact (scripts/fetch-trained-model.py vjepa2, then
//! `enclave-pack --class JEPA_EBM_WORLD_PLANNER --hf-vjepa2 target/vjepa2-vitl
//! --model-id vjepa2-vitl --out-dir target/vjepa2-pack`) and
//! depot_MLX_WORKER; otherwise it reports a skip unless depot_REQUIRE_VJEPA2.

use enclave_model_runnerd::backends::mlx::vjepa2::MlxVjepa2;
use enclave_model_runnerd::manifest::ExecutionClass;
use enclave_model_runnerd::safetensors::parse;
use enclave_model_runnerd::topology::OpAttestor;
use sha2::{Digest, Sha256};

/// The golden script's synthetic frames, pixel for pixel.
fn frame(name: &str) -> Vec<u8> {
    let mut px = vec![0u8; 256 * 256];
    for y in 0..256 {
        for x in 0..256 {
            px[y * 256 + x] = match name {
                "gradient" => x as u8,
                "flat_91" => 91,
                "flat_64" => 64,
                "ui_mock" => {
                    let inside = |y0: usize, y1: usize, x0: usize, x1: usize| (y0..y1).contains(&y) && (x0..x1).contains(&x);
                    if inside(168, 184, 112, 144) { 250 } else if inside(160, 192, 96, 160) { 30 }
                    else if inside(64, 96, 32, 224) { 200 } else if y < 32 { 40 } else { 235 }
                }
                other => panic!("unknown frame {other}"),
            };
        }
    }
    px
}

#[test]
fn vjepa2_encoder_matches_the_reference() {
    let golden: serde_json::Value = serde_json::from_str(include_str!("data/vjepa2-golden.json")).unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/vjepa2-pack/vjepa2-vitl.safetensors");
    let bytes = match std::fs::read(&path) {
        Ok(bytes) if std::env::var_os("depot_MLX_WORKER").is_some() => bytes,
        _ => {
            assert!(std::env::var_os("depot_REQUIRE_VJEPA2").is_none(), "V-JEPA 2 artifact and depot_MLX_WORKER required");
            eprintln!("VJEPA2_GOLDEN_CHECKED=false; artifact or native worker absent");
            return;
        }
    };
    let index = parse(&bytes).unwrap();
    let mut attest = OpAttestor::new(ExecutionClass::JepaEbmWorldPlanner, &[]);
    let model = MlxVjepa2::load(&index, &bytes, &mut attest).unwrap();
    let mut worst = 0f32;
    for case in golden["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let px = frame(name);
        assert_eq!(hex::encode(Sha256::digest(&px)), case["pixels_sha256"].as_str().unwrap(), "{name} pixels");
        let latent = model.latent(&px).unwrap();
        for (i, v) in case["pooled_head"].as_array().unwrap().iter().enumerate() {
            worst = worst.max((latent[i] - v.as_f64().unwrap() as f32).abs());
        }
        let norm = latent.iter().map(|v| v * v).sum::<f32>().sqrt();
        let reference = case["pooled_norm"].as_f64().unwrap() as f32;
        assert!((norm - reference).abs() < 1e-3 * reference, "{name} norm {norm} vs {reference}");
        let sum: f32 = latent.iter().sum();
        assert!((sum - case["pooled_sum"].as_f64().unwrap() as f32).abs() < 0.05, "{name} sum {sum}");
    }
    assert!(worst < 2e-3, "pooled latent deviation {worst}");
    eprintln!("VJEPA2_GOLDEN_CHECKED=true; max pooled deviation {worst:e}");
}
