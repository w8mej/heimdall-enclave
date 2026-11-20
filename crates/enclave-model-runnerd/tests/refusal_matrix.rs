//! M7 refusal matrix over the five real-weight packages (SmolLM2, RWKV-7,
//! Qwen3+EAGLE-3, V-JEPA 2, LLaDA-8B). Each mutation goes through the runner's own
//! `Bind` request and must refuse with a specific reason, after which a
//! generation request finds no bound model: nothing is released.
//!
//! Needs the packages under target/<name>-pack (scripts/l1-alpha-smoke.sh
//! inputs) and depot_MLX_WORKER for the positive control; otherwise it
//! reports a skip unless depot_REQUIRE_REFUSAL_MATRIX is set.

mod common;

use common::{mapped_package_or_skip, operator, package_or_skip, Package, ONE_MODEL_AT_A_TIME};
use enclave_core::error::EnclaveResult;
use enclave_model_runnerd::dfa::ArgSchema;
use enclave_model_runnerd::service::{RunnerRequest, RunnerResponse};
use serde_json::json;

/// A well-formed eager companion the packages never ship.
const MISSING_COMPANION_ROOT: &str = "1111111111111111111111111111111111111111111111111111111111111111";

/// Bind `inline` while UID 702 serves `published`; returns the bind result
/// and asserts no model is left bound afterwards when it fails.
fn bind(published: &Package, inline: &[u8]) -> EnclaveResult<RunnerResponse> {
    let service = published.runner();
    let result = published.bind_on(&service, inline);
    if result.is_err() {
        let probe = service.handle(&operator(), RunnerRequest::GenerateStructured { schema: ArgSchema::Bool, len: 1, prompt: None });
        assert!(probe.unwrap_err().is("MODEL_NOT_BOUND"), "a refused bind must leave nothing to generate from");
    } else {
        service.handle(&operator(), RunnerRequest::Unbind).unwrap();
    }
    result
}

fn refused(published: &Package, inline: &[u8], reason: &str, case: &str) {
    match bind(published, inline) {
        Ok(_) => panic!("{case}: bound, expected {reason}"),
        Err(e) => assert!(e.is(reason), "{case}: expected {reason}, got {e:?}"),
    }
}

/// Rename one header key (same length), so the artifact stays well formed
/// but no longer carries that companion.
fn without_key(pack: &Package, key: &str) -> Package {
    let header_len = u64::from_le_bytes(pack.prefix(8).try_into().unwrap()) as usize;
    let header = pack.prefix(8 + header_len);
    let header = &header[8..];
    let needle = format!("\"{key}\"");
    let mut renamed = needle.clone().into_bytes();
    let last = renamed.len() - 2;
    renamed[last] = if renamed[last] == b'X' { b'Y' } else { b'X' };
    let hits: Vec<usize> = header.windows(needle.len()).enumerate()
        .filter(|(_, w)| *w == needle.as_bytes()).map(|(i, _)| i).collect();
    assert_eq!(hits.len(), 1, "{key} must occur exactly once in the header");
    pack.patched(8 + hits[0], &renamed)
}

struct Model {
    dir: &'static str,
    /// A different class this checkpoint is not.
    wrong_class: &'static str,
    /// An embedded companion the backend needs (metadata or tensor key).
    companion: &'static str,
    /// Reason the backend gives when that companion is absent.
    companion_reason: &'static str,
}

fn matrix(model: Model) {
    matrix_of(model, package_or_skip)
}

fn matrix_of(model: Model, load: common::Loader) {
    let Some(pack) = load(model.dir, "depot_REQUIRE_REFUSAL_MATRIX", "REFUSAL_MATRIX_CHECKED") else { return };
    let _serial = ONE_MODEL_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());

    // Positive control: the unmodified package binds.
    assert!(matches!(bind(&pack, &pack.bytes()), Ok(RunnerResponse::Bound { .. })), "{}: control must bind", model.dir);

    // Mutated weights: one flipped byte in the last tensor's payload.
    let at = pack.len() - 1;
    let last = pack.byte_at(at);
    let flipped = pack.patched(at, &[last ^ 0x01]);
    refused(&flipped, &pack.bytes(), "ARTIFACT_SHA256_MISMATCH", "mutated weights");

    // Mutated manifest: the inline manifest differs from the signed target.
    let mut loosened = pack.manifest.clone();
    let caps = loosened["output_caps"]["max_output_bytes"].as_u64().unwrap();
    loosened["output_caps"]["max_output_bytes"] = json!(caps + 1);
    refused(&pack, &serde_json::to_vec(&loosened).unwrap(), "MODEL_MANIFEST_UNSIGNED", "mutated manifest");

    // Wrong class, honestly signed: the backend refuses a class it does not implement.
    let mut wrong = pack.clone();
    wrong.manifest["execution_class"] = json!(model.wrong_class);
    // An honest publisher drops diffusion-only caps with the class (the
    // manifest itself refuses them elsewhere: DIFFUSION_DEADLINE_WITHOUT_DIFFUSION).
    if let Some(caps) = wrong.manifest["output_caps"].as_object_mut() {
        caps.remove("diffusion_deadline_ms");
    }
    refused(&wrong, &wrong.bytes(), "FRAMEWORK_BACKEND_CLASS_UNSUPPORTED", "wrong class");

    // Missing companion (declared): an eager companion the source never supplies.
    let mut declared = pack.clone();
    declared.manifest["companion_safety_layers"] = json!([{
        "role": "ece_calibration_lut",
        "cas_uri": format!("cas://blake3-bao-v1/{MISSING_COMPANION_ROOT}"),
        "eager_hydrate_required": true,
    }]);
    refused(&declared, &declared.bytes(), "COMPANIONS_MISSING", "missing declared companion");

    // Missing companion (embedded): the artifact no longer carries it.
    let stripped = without_key(&pack, model.companion).redigest();
    refused(&stripped, &stripped.bytes(), model.companion_reason, "missing embedded companion");

    // Unsupported format, honestly signed.
    let mut gguf = pack.clone();
    gguf.manifest["artifact"]["format"] = json!("gguf");
    refused(&gguf, &gguf.bytes(), "ARTIFACT_FORMAT_UNSUPPORTED", "unsupported format");

    eprintln!("REFUSAL_MATRIX_CHECKED=true; {}", model.dir);
}

#[test]
fn smollm2_refusal_matrix() {
    matrix(Model { dir: "smollm2-pack", wrong_class: "RECURRENT_SSM_TTT", companion: "enclave_adapter.tokenizer", companion_reason: "TOKENIZER_MISSING" });
}

#[test]
fn rwkv7_refusal_matrix() {
    matrix(Model { dir: "rwkv7-pack", wrong_class: "AR_CAUSAL", companion: "enclave_adapter.tokenizer", companion_reason: "TOKENIZER_MISSING" });
}

#[test]
fn eagle3_refusal_matrix() {
    matrix(Model { dir: "eagle3-pack", wrong_class: "AR_CAUSAL", companion: "enclave_adapter.tokenizer_json", companion_reason: "TOKENIZER_MISSING" });
}

#[test]
fn vjepa2_refusal_matrix() {
    matrix(Model { dir: "vjepa2-pack", wrong_class: "AR_CAUSAL", companion: "enclave_adapter.safety_cone.weight", companion_reason: "TENSOR_MISSING" });
}

#[test]
fn llada_refusal_matrix() {
    matrix_of(Model { dir: "llada-pack", wrong_class: "AR_CAUSAL", companion: "enclave_adapter.tokenizer", companion_reason: "TOKENIZER_MISSING" }, mapped_package_or_skip);
}
