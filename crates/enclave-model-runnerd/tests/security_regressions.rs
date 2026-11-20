//! Behavioral security regressions for the production reference adapter.
use enclave_core::profile::Profile;
use enclave_model_runnerd::adapter::EnclaveModelAdapter;
use enclave_model_runnerd::classes::speculative::{FixedThermal, PowerSource, ThermalState};
use enclave_model_runnerd::manifest::{ExecutionClass, ModelManifestV1};
use enclave_model_runnerd::safetensors::{build_f32, parse};
use enclave_model_runnerd::zoo::{package, Packaged};
use sha2::{Digest, Sha256};

fn alter(p: &mut Packaged, tensor: Option<&str>, meta: Option<(&str, &str)>) {
    let idx = parse(&p.weights).unwrap();
    let mut tensors: Vec<(String, Vec<usize>, Vec<f32>)> = idx
        .tensors
        .iter()
        .map(|(name, t)| {
            (
                name.clone(),
                t.shape.clone(),
                idx.f32(&p.weights, name, &t.shape).unwrap(),
            )
        })
        .collect();
    if let Some(name) = tensor {
        tensors
            .iter_mut()
            .find(|t| t.0 == name)
            .unwrap()
            .2
            .fill(0.0);
    }
    let mut metadata = idx.metadata;
    if let Some((name, value)) = meta {
        metadata.insert(name.into(), value.into());
    }
    let refs: Vec<_> = tensors.into_iter().map(|(n, s, v)| (n, s, v)).collect();
    let borrowed: Vec<_> = refs
        .iter()
        .map(|(n, s, v)| (n.as_str(), s.clone(), v.clone()))
        .collect();
    let pairs: Vec<_> = metadata
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    p.weights = build_f32(&borrowed, &pairs);
    p.manifest["artifact"]["sha256"] = hex::encode(Sha256::digest(&p.weights)).into();
    p.set_cas_root(&blake3::hash(&p.weights).to_hex().to_string());
}
fn bind(p: &Packaged) -> enclave_core::error::EnclaveResult<EnclaveModelAdapter> {
    EnclaveModelAdapter::bind(
        ModelManifestV1::from_json(&p.manifest_bytes()).unwrap(),
        &p.weights,
        Profile::L2,
        None,
        Box::new(FixedThermal(ThermalState::Nominal, PowerSource::Ac)),
    )
}
#[test]
fn f137_zero_probes_and_invalid_thresholds_fail_at_actual_admission() {
    for (class, name) in [
        (
            ExecutionClass::SpeculativeOrRecurrentDepth,
            "enclave_adapter.latent_probe.weight",
        ),
        (
            ExecutionClass::JepaEbmWorldPlanner,
            "enclave_adapter.safety_cone.weight",
        ),
    ] {
        let mut p = package(class).unwrap();
        bind(&p).unwrap();
        alter(&mut p, Some(name), None);
        assert!(bind(&p).unwrap_err().is("SAFETY_PROBE_INVALID"));
    }
    for (class, key) in [
        (
            ExecutionClass::SpeculativeOrRecurrentDepth,
            "enclave_adapter.latent_probe.tau",
        ),
        (
            ExecutionClass::JepaEbmWorldPlanner,
            "enclave_adapter.safety_cone.tau",
        ),
    ] {
        for value in ["0", "1", "1.1", "inf", "NaN", "garbage"] {
            let mut p = package(class).unwrap();
            alter(&mut p, None, Some((key, value)));
            assert!(bind(&p).is_err(), "{key}={value}");
        }
    }
    let mut p = package(ExecutionClass::ByteOrConcept).unwrap();
    bind(&p).unwrap();
    alter(&mut p, Some("enclave_adapter.sonar_canaries"), None);
    assert!(bind(&p).unwrap_err().is("SAFETY_PROBE_INVALID"));
}
