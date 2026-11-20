//! Prompt 7B (GAP-33): Expected Calibration Error from real model inference
//! over TUF-pinned `{x, y}` corpus; companion FDs honored by UID 701;
//! skewed head failure gate.

use enclave_core::profile::Profile;
use enclave_model_runnerd::adapter::{CalibrationInput, EnclaveModelAdapter};
use enclave_model_runnerd::classes::speculative::{FixedThermal, PowerSource, ThermalState};
use enclave_model_runnerd::manifest::{ExecutionClass, ModelManifestV1};
use enclave_model_runnerd::safetensors::build_f32;
use enclave_model_runnerd::zoo::{self, package};
use serde_json::json;
use sha2::Digest;

fn nominal() -> Box<dyn enclave_model_runnerd::classes::speculative::ThermalProvider> {
    Box::new(FixedThermal(ThermalState::Nominal, PowerSource::Ac))
}

fn manifest(p: &zoo::Packaged) -> ModelManifestV1 {
    ModelManifestV1::from_json(&p.manifest_bytes()).unwrap()
}

#[test]
fn test_calibrated_reference_head_passes_admission() {
    let p = package(ExecutionClass::DiscriminativeRlcd).unwrap();
    let corpus = p.corpus.as_ref().expect("rlcd corpus");
    let pin = blake3::hash(corpus).to_hex().to_string();

    let adapter = EnclaveModelAdapter::bind(
        manifest(&p),
        &p.weights,
        Profile::L2,
        Some(CalibrationInput {
            corpus,
            pinned_blake3: &pin,
        }),
        nominal(),
    )
    .expect("reference RLCD model must pass admission");

    let ece = adapter.ece.expect("ece measured");
    assert!(
        ece <= 0.015,
        "calibrated reference head ECE {ece} must be <= 0.015"
    );
}

#[test]
fn test_skewed_head_with_identity_lut_fails_admission() {
    let p = package(ExecutionClass::DiscriminativeRlcd).unwrap();
    let corpus = p.corpus.as_ref().expect("rlcd corpus");
    let pin = blake3::hash(corpus).to_hex().to_string();

    // Create a model with a skewed head (biased logits towards class 0)
    let skewed_weights = build_f32(
        &[
            (
                "enclave_adapter.rlcd_head.weight",
                vec![4, 64],
                zoo::rlcd_reference_weights(),
            ),
            (
                "enclave_adapter.rlcd_head.bias",
                vec![4],
                vec![4.0, 0.0, 0.0, 0.0], // heavily biased
            ),
            (
                "enclave_adapter.ece_calibration_lut",
                vec![15],
                zoo::identity_lut(),
            ),
        ],
        &[],
    );

    let mut skewed_pkg = p.clone();
    skewed_pkg.weights = skewed_weights;
    let b3 = blake3::hash(&skewed_pkg.weights).to_hex().to_string();
    skewed_pkg.set_cas_root(&b3);
    skewed_pkg.manifest["artifact"]["sha256"] =
        json!(hex::encode(sha2::Sha256::digest(&skewed_pkg.weights)));

    let err = EnclaveModelAdapter::bind(
        manifest(&skewed_pkg),
        &skewed_pkg.weights,
        Profile::L2,
        Some(CalibrationInput {
            corpus,
            pinned_blake3: &pin,
        }),
        nominal(),
    )
    .expect_err("skewed head must fail admission with identity LUT");

    assert_eq!(err.reason, "ECE_ABOVE_BOUND");
}

#[test]
fn test_companion_fd_for_calibration_lut_honored() {
    let p = package(ExecutionClass::DiscriminativeRlcd).unwrap();
    let corpus = p.corpus.as_ref().expect("rlcd corpus");
    let pin = blake3::hash(corpus).to_hex().to_string();

    // Separate the LUT into a standalone companion artifact
    let lut_bytes = build_f32(
        &[(
            "enclave_adapter.ece_calibration_lut",
            vec![15],
            zoo::identity_lut(),
        )],
        &[],
    );
    let lut_b3 = blake3::hash(&lut_bytes).to_hex().to_string();

    // Model weights without the LUT embedded in the primary file
    let primary_weights = build_f32(
        &[
            (
                "enclave_adapter.rlcd_head.weight",
                vec![4, 64],
                zoo::rlcd_reference_weights(),
            ),
            (
                "enclave_adapter.rlcd_head.bias",
                vec![4],
                zoo::rlcd_reference_bias(),
            ),
        ],
        &[],
    );
    let primary_b3 = blake3::hash(&primary_weights).to_hex().to_string();

    let mut pkg = p.clone();
    pkg.weights = primary_weights;
    pkg.set_cas_root(&primary_b3);
    pkg.manifest["artifact"]["sha256"] = json!(hex::encode(sha2::Sha256::digest(&pkg.weights)));
    pkg.manifest["companion_safety_layers"] = json!([
        {
            "role": "ece_calibration_lut",
            "cas_uri": format!("cas://blake3-bao-v1/{lut_b3}"),
            "eager_hydrate_required": true
        }
    ]);

    // Bind with companion buffer
    let adapter = EnclaveModelAdapter::bind_with_companions(
        manifest(&pkg),
        &pkg.weights,
        &[&lut_bytes],
        Profile::L2,
        Some(CalibrationInput {
            corpus,
            pinned_blake3: &pin,
        }),
        nominal(),
    )
    .expect("model with companion LUT must pass admission");

    assert!(adapter.ece.unwrap() <= 0.015);
}

#[test]
fn test_companion_digest_mismatch_fails_admission() {
    let p = package(ExecutionClass::DiscriminativeRlcd).unwrap();
    let corpus = p.corpus.as_ref().expect("rlcd corpus");
    let pin = blake3::hash(corpus).to_hex().to_string();

    let lut_bytes = build_f32(
        &[(
            "enclave_adapter.ece_calibration_lut",
            vec![15],
            zoo::identity_lut(),
        )],
        &[],
    );
    let lut_b3 = blake3::hash(&lut_bytes).to_hex().to_string();

    let primary_weights = build_f32(
        &[
            (
                "enclave_adapter.rlcd_head.weight",
                vec![4, 64],
                zoo::rlcd_reference_weights(),
            ),
            (
                "enclave_adapter.rlcd_head.bias",
                vec![4],
                zoo::rlcd_reference_bias(),
            ),
        ],
        &[],
    );

    let mut pkg = p.clone();
    pkg.weights = primary_weights;
    let primary_b3 = blake3::hash(&pkg.weights).to_hex().to_string();
    pkg.set_cas_root(&primary_b3);
    pkg.manifest["artifact"]["sha256"] = json!(hex::encode(sha2::Sha256::digest(&pkg.weights)));
    pkg.manifest["companion_safety_layers"] = json!([
        {
            "role": "ece_calibration_lut",
            "cas_uri": format!("cas://blake3-bao-v1/{lut_b3}"),
            "eager_hydrate_required": true
        }
    ]);

    // Provide corrupted companion bytes
    let mut tampered_lut = lut_bytes.clone();
    tampered_lut[50] ^= 0xff;

    let err = EnclaveModelAdapter::bind_with_companions(
        manifest(&pkg),
        &pkg.weights,
        &[&tampered_lut],
        Profile::L2,
        Some(CalibrationInput {
            corpus,
            pinned_blake3: &pin,
        }),
        nominal(),
    )
    .expect_err("tampered companion must fail digest check");

    assert_eq!(err.reason, "COMPANION_DIGEST_MISMATCH");
}

#[test]
fn test_missing_eager_companion_fails_admission() {
    let p = package(ExecutionClass::DiscriminativeRlcd).unwrap();
    let corpus = p.corpus.as_ref().expect("rlcd corpus");
    let pin = blake3::hash(corpus).to_hex().to_string();

    let mut pkg = p.clone();
    pkg.manifest["companion_safety_layers"] = json!([
        {
            "role": "ece_calibration_lut",
            "cas_uri": "cas://blake3-bao-v1/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "eager_hydrate_required": true
        }
    ]);

    // No companion buffers supplied
    let err = EnclaveModelAdapter::bind_with_companions(
        manifest(&pkg),
        &pkg.weights,
        &[],
        Profile::L2,
        Some(CalibrationInput {
            corpus,
            pinned_blake3: &pin,
        }),
        nominal(),
    )
    .expect_err("missing eager companion must fail");

    assert_eq!(err.reason, "COMPANIONS_MISSING");
}

#[test]
fn f135_task_labels_are_independent_of_admitted_head() {
    use enclave_model_runnerd::classes::rlcd::LinearHead;
    use enclave_model_runnerd::ece::{verify_with_model, CalibrationLut};
    let corpus = zoo::calibrated_corpus();
    let items: Vec<serde_json::Value> = corpus
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_slice(l).unwrap())
        .collect();
    for (i, item) in items.iter().enumerate() {
        let expected = match i % 30 {
            0..=8 => 0,
            9..=15 => 1,
            16..=22 => 2,
            _ => 3,
        };
        assert_eq!(item["y"], expected);
        assert!(item["x"]
            .as_str()
            .unwrap()
            .contains(["routine", "important", "urgent", "critical"][expected as usize]));
    }
    let pin = blake3::hash(&corpus).to_hex().to_string();
    let good = LinearHead::new(
        zoo::rlcd_reference_weights(),
        zoo::rlcd_reference_bias(),
        4,
        64,
    )
    .unwrap();
    verify_with_model(&good, &CalibrationLut::identity(), &corpus, &pin, 0.015).unwrap();
    let wrong = LinearHead::new(
        zoo::rlcd_reference_weights(),
        vec![0.0, 9.0, 0.0, 0.0],
        4,
        64,
    )
    .unwrap();
    assert!(
        verify_with_model(&wrong, &CalibrationLut::identity(), &corpus, &pin, 0.015)
            .unwrap_err()
            .is("ECE_ABOVE_BOUND")
    );
    assert_eq!(
        zoo::calibrated_corpus(),
        corpus,
        "changing predictions never relabels the corpus"
    );
}

#[test]
fn f136_model_evaluation_rejects_precomputed_confidence_and_preserves_large_class_indices() {
    use enclave_model_runnerd::classes::rlcd::RlcdBackend;
    use enclave_model_runnerd::ece::{verify_with_model, CalibrationLut};
    #[derive(Debug)]
    struct Head;
    impl RlcdBackend for Head {
        fn classes(&self) -> usize {
            257
        }
        fn logits(&self, _: &[u8]) -> enclave_core::error::EnclaveResult<Vec<f32>> {
            let mut v = vec![0.0; 257];
            v[256] = 30.0;
            Ok(v)
        }
    }
    let check = |line: &str| {
        let corpus = line.repeat(300).into_bytes();
        let pin = blake3::hash(&corpus).to_hex().to_string();
        verify_with_model(&Head, &CalibrationLut([1.0; 15]), &corpus, &pin, 0.015)
    };
    assert!(check(concat!(r#"{"p":1.0,"y":1}"#, "\n"))
        .unwrap_err()
        .is("CALIBRATION_PRECOMPUTED_FORBIDDEN"));
    assert!(check(concat!(r#"{"x":"record","p":1.0,"y":256}"#, "\n"))
        .unwrap_err()
        .is("CALIBRATION_PRECOMPUTED_FORBIDDEN"));
    assert!(check(concat!(r#"{"x":"record","y":0}"#, "\n"))
        .unwrap_err()
        .is("ECE_ABOVE_BOUND"));
    assert!(check(concat!(r#"{"x":"record","y":257}"#, "\n"))
        .unwrap_err()
        .is("CALIBRATION_LABEL_RANGE"));
    assert!(check(concat!(r#"{"x":"record","y":256}"#, "\n")).is_ok());
}
