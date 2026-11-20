//! Real CoreML execution on Darwin, bounded graph/admission refusals elsewhere.
use enclave_core::profile::Profile;
use enclave_model_runnerd::adapter::{CalibrationInput, EnclaveModelAdapter};
use enclave_model_runnerd::backends::coreml::runtime::{CanonicalLinearGraph, CoreMlLinear};
#[cfg(target_os = "macos")]
use enclave_model_runnerd::classes::rlcd::{LinearHead, RlcdBackend};
use enclave_model_runnerd::classes::speculative::{FixedThermal, PowerSource, ThermalState};
use enclave_model_runnerd::manifest::{ExecutionClass, ModelManifestV1};
use enclave_model_runnerd::safetensors::{build_f32, parse};
use enclave_model_runnerd::topology::OpAttestor;
use enclave_model_runnerd::zoo;
use sha2::{Digest, Sha256};

fn checkpoint() -> Vec<u8> {
    // Repository-generated mechanical checkpoint under the repository Apache-2.0
    // license. Nonzero weights ensure reference comparisons observe the input.
    build_f32(&[
        ("enclave_adapter.rlcd_head.weight", vec![2, 4], vec![1., 2., -1., 0.5, -2., 0., 3., 1.]),
        ("enclave_adapter.rlcd_head.bias", vec![2], vec![0.25, -0.5]),
    ], &[("enclave_adapter.backend", "coreml_linear_v1")])
}

#[test]
fn canonical_graph_admits_only_bounded_finite_classifier_compute() {
    let mut allowed = OpAttestor::new(ExecutionClass::DiscriminativeRlcd, &[]);
    let graph = CanonicalLinearGraph::build(2, 2, &[1., 2., 3., 4.], &[0., 1.], &mut allowed).unwrap();
    let again = CanonicalLinearGraph::build(2, 2, &[1., 2., 3., 4.], &[0., 1.], &mut allowed).unwrap();
    assert_eq!(graph.model, again.model);
    assert_eq!(graph.sha256, hex::encode(Sha256::digest(&graph.model)));
    let altered = CanonicalLinearGraph::build(2, 2, &[1., 2., 3., 5.], &[0., 1.], &mut allowed).unwrap();
    assert_ne!(graph.sha256, altered.sha256);
    let mut denied = OpAttestor::new(ExecutionClass::ArCausal, &[]);
    assert!(CanonicalLinearGraph::build(2, 2, &[1.; 4], &[0.; 2], &mut denied).unwrap_err().is("GRAPH_OP_NOT_AUTHORISED"));
    for (k, d, w, b) in [(257, 1, vec![0.; 257], vec![0.; 257]), (2, 0, vec![], vec![0.; 2]),
        (2, 2, vec![f32::NAN; 4], vec![0.; 2]), (2, 2, vec![0.; 3], vec![0.; 2])] {
        assert!(CanonicalLinearGraph::build(k, d, &w, &b, &mut allowed).is_err());
    }
}

#[test]
fn actual_framework_load_refuses_unknown_checkpoint_tensors_before_native_compile() {
    let weights = build_f32(&[
        ("enclave_adapter.rlcd_head.weight", vec![2, 2], vec![0.; 4]),
        ("hidden.custom.operator", vec![1], vec![1.]),
    ], &[]);
    let mut attest = OpAttestor::new(ExecutionClass::DiscriminativeRlcd, &[]);
    let error = CoreMlLinear::load(&parse(&weights).unwrap(), &weights, &mut attest).unwrap_err();
    assert!(error.is(if cfg!(debug_assertions) { "COREML_UNSUPPORTED_CHECKPOINT_TENSOR" }
        else { "COREML_DEVELOPMENT_ONLY" }));
}

#[test]
fn real_coreml_prediction_matches_independent_dense_reference_or_platform_refuses() {
    let bytes = checkpoint();
    let index = parse(&bytes).unwrap();
    let mut attest = OpAttestor::new(ExecutionClass::DiscriminativeRlcd, &[]);
    let actual = CoreMlLinear::load(&index, &bytes, &mut attest);
    if !cfg!(debug_assertions) {
        assert!(actual.unwrap_err().is("COREML_DEVELOPMENT_ONLY"));
        return;
    }
    #[cfg(not(target_os = "macos"))]
    {
        assert!(actual.unwrap_err().is("COREML_PLATFORM_UNAVAILABLE"));
    }
    #[cfg(target_os = "macos")]
    {
        let actual = actual.unwrap();
        let reference = LinearHead::load(&index, &bytes).unwrap();
        let mut observations = Vec::new();
        for input in [b"alpha".as_slice(), b"zzzz", b"a different feature vector"] {
            let observed = actual.logits(input).unwrap();
            let expected = reference.logits(input).unwrap();
            assert_eq!(observed.len(), expected.len());
            for (a,b) in observed.iter().zip(expected) { assert!((a-b).abs() <= 1e-5, "{a} != {b}"); }
            observations.push(observed);
        }
        assert!(observations.windows(2).any(|pair| pair[0] != pair[1]));
    }
}

#[test]
fn actual_adapter_hash_and_framework_selection_are_not_declarations_only() {
    let mut packaged = zoo::package(ExecutionClass::DiscriminativeRlcd).unwrap();
    packaged.weights = build_f32(&[
        ("enclave_adapter.rlcd_head.weight", vec![4, 64], zoo::rlcd_reference_weights()),
        ("enclave_adapter.rlcd_head.bias", vec![4], zoo::rlcd_reference_bias()),
        ("enclave_adapter.ece_calibration_lut", vec![15], zoo::identity_lut()),
    ], &[("enclave_adapter.backend", "coreml_linear_v1")]);
    let b3 = blake3::hash(&packaged.weights).to_hex().to_string();
    packaged.set_cas_root(&b3);
    packaged.manifest["artifact"]["sha256"] = serde_json::json!(hex::encode(Sha256::digest(&packaged.weights)));
    let manifest: ModelManifestV1 = serde_json::from_value(packaged.manifest.clone()).unwrap();
    let corpus = packaged.corpus.as_deref().unwrap();
    let pin = blake3::hash(corpus).to_hex().to_string();
    let bind = |m| EnclaveModelAdapter::bind(m, &packaged.weights, Profile::L2,
        Some(CalibrationInput {corpus, pinned_blake3: &pin}),
        Box::new(FixedThermal(ThermalState::Nominal, PowerSource::Ac)));
    let result = bind(manifest.clone());
    if !cfg!(debug_assertions) {
        assert!(result.unwrap_err().is("COREML_DEVELOPMENT_ONLY"));
        return;
    }
    #[cfg(target_os = "macos")]
    { assert!(result.unwrap().ece.is_some()); }
    #[cfg(not(target_os = "macos"))]
    { assert!(result.unwrap_err().is("COREML_PLATFORM_UNAVAILABLE")); }
    let mut wrong = manifest;
    wrong.artifact.sha256 = "00".repeat(32);
    assert!(bind(wrong).unwrap_err().is("ARTIFACT_SHA256_MISMATCH"));
}
