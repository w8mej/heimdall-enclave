//! Real fixed-graph MLX computation when an explicit pinned local runtime exists;
//! otherwise the same selected backend must refuse without simulated output.
use enclave_model_runnerd::backends::mlx::runtime::MlxBigram;
use enclave_model_runnerd::classes::ar::{BigramLm, CausalBackend};
use enclave_model_runnerd::manifest::ExecutionClass;
use enclave_model_runnerd::safetensors::{build_f32, parse};
use enclave_model_runnerd::topology::OpAttestor;
use enclave_model_runnerd::zoo;
use enclave_model_runnerd::adapter::{EnclaveModelAdapter, Engine};
use enclave_model_runnerd::classes::speculative::{FixedThermal, PowerSource, ThermalState};
use enclave_model_runnerd::dfa::{ArgSchema, Dfa};
use enclave_core::profile::Profile;
use sha2::{Digest, Sha256};

/// Either the native worker or the Python worker pair is configured.
fn configured() -> bool {
    std::env::var_os("depot_MLX_WORKER").is_some()
        || (std::env::var_os("depot_MLX_PYTHON").is_some() && std::env::var_os("depot_MLX_SITE").is_some())
}

#[test]
fn real_mlx_checkpoint_computes_reference_logits_or_explicitly_refuses_unavailable_runtime() {
    if std::env::var_os("depot_REQUIRE_MLX").is_some() {
        assert!(cfg!(target_os="macos") && cfg!(debug_assertions), "MLX acceptance requires debug Darwin");
        assert!(configured(), "required MLX runtime configuration is missing");
    }
    let tensor = zoo::spelling_bigram(b"{\"ok\":true}", 4.);
    let bytes = build_f32(&[("enclave_adapter.ar.bigram", vec![256,256], tensor)],
        &[("enclave_adapter.backend", "mlx_bigram_v1")]);
    let index = parse(&bytes).unwrap();
    let reference = BigramLm::load(&index, &bytes).unwrap();
    let mut attest = OpAttestor::new(ExecutionClass::ArCausal, &[]);
    let actual = MlxBigram::load(&index, &bytes, &mut attest);
    if !cfg!(debug_assertions) {
        assert!(actual.unwrap_err().is("MLX_DEVELOPMENT_ONLY"));
    } else if !cfg!(target_os = "macos") {
        assert!(actual.unwrap_err().is("MLX_PLATFORM_UNAVAILABLE"));
    } else if !configured() {
        assert!(actual.unwrap_err().is("MLX_RUNTIME_NOT_CONFIGURED"));
        eprintln!("MLX_REAL_EXECUTION=false; explicit runtime configuration absent");
    } else {
        let actual = actual.unwrap();
        for prefix in [b"".as_slice(), b"{", b"{\"", b"{\"ok"] {
            assert_eq!(actual.next(prefix).unwrap(), reference.next(prefix).unwrap());
        }
        eprintln!("MLX_REAL_EXECUTION=true; 4 actual CPU evaluations match independent Rust reference");
    }
}

#[test]
fn framework_backend_cannot_satisfy_incompatible_signed_operator_family() {
    // The closed graph exporter itself must refuse before launching any worker.
    let weights = build_f32(&[("enclave_adapter.ar.bigram", vec![256,256], vec![0.;65536])], &[]);
    let index = parse(&weights).unwrap();
    let mut attest = OpAttestor::new(ExecutionClass::DiscriminativeRlcd, &[]);
    let result = MlxBigram::load(&index, &weights, &mut attest);
    if cfg!(debug_assertions) && cfg!(target_os = "macos") {
        assert!(result.unwrap_err().is("GRAPH_OP_NOT_AUTHORISED"));
    } else {
        assert!(result.is_err());
    }
}

#[test]
fn authenticated_adapter_routes_generation_through_actual_mlx_or_refuses() {
    let mut packaged = zoo::package(ExecutionClass::ArCausal).unwrap();
    let previous = parse(&packaged.weights).unwrap();
    packaged.weights = build_f32(&[
        ("lm_head.weight", vec![300,8], previous.f32(&packaged.weights,"lm_head.weight",&[300,8]).unwrap()),
        ("enclave_adapter.ar.bigram", vec![256,256], zoo::spelling_bigram(b"{\"ok\":true}",4.)),
    ], &[("enclave_adapter.backend","mlx_bigram_v1")]);
    let root = blake3::hash(&packaged.weights).to_hex().to_string();
    packaged.set_cas_root(&root);
    packaged.manifest["artifact"]["sha256"] = serde_json::json!(hex::encode(Sha256::digest(&packaged.weights)));
    let result = EnclaveModelAdapter::bind(serde_json::from_value(packaged.manifest).unwrap(),
        &packaged.weights, Profile::L2, None, Box::new(FixedThermal(ThermalState::Nominal,PowerSource::Ac)));
    if !cfg!(debug_assertions) {
        assert!(result.unwrap_err().is("MLX_DEVELOPMENT_ONLY"));
    } else if !cfg!(target_os="macos") {
        assert!(result.unwrap_err().is("MLX_PLATFORM_UNAVAILABLE"));
    } else if !configured() {
        assert!(result.unwrap_err().is("MLX_RUNTIME_NOT_CONFIGURED"));
    } else {
        let mut adapter=result.unwrap();
        let Engine::Ar(backend)=&adapter.engine else { panic!("expected actual causal backend"); };
        let grammar=Dfa::compile(&ArgSchema::Object(vec![("ok".into(),ArgSchema::Bool)])).unwrap();
        let output=enclave_model_runnerd::classes::ar::decode(backend.as_ref(),&grammar,64,
            adapter.controls.max_output_bytes,&mut adapter.attest).unwrap();
        assert_eq!(output,b"{\"ok\":true}");
        eprintln!("MLX_REAL_ADAPTER_GENERATION=true; exact typed JSON output observed");
    }
}
