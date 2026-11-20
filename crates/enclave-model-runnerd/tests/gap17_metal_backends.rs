//! Reference callback admission and arena regressions. No test loads a real MLX/CoreML model.

use enclave_core::profile::Profile;
use enclave_model_runnerd::adapter::EnclaveModelAdapter;
use enclave_model_runnerd::arena_metal::MetalArena;
use enclave_model_runnerd::backends::{coreml, mlx};
use enclave_model_runnerd::classes::speculative::{FixedThermal, PowerSource, ThermalState};
use enclave_model_runnerd::manifest::{ExecutionClass, ModelManifestV1};
use enclave_model_runnerd::safetensors::build_f32;
use enclave_model_runnerd::topology::{OpAttestor, OpFamily};
use enclave_model_runnerd::zoo;
use serde_json::json;
use sha2::{Digest, Sha256};

#[test]
fn test_renamed_tensor_mamba_checkpoint_faults_graph_op_not_authorised() {
    // 1. Adversary crafts a Mamba/SSM checkpoint, but renames the tensor keys
    // to look like an AR_CAUSAL model (e.g. "lm_head.weight" and "self_attn.q_proj")
    // and sets the signed manifest execution_class to "AR_CAUSAL".
    let d = 16usize;
    let tensors = vec![
        ("lm_head.weight", vec![300, 8], vec![0.1f32; 2400]),
        ("self_attn.q_proj.weight", vec![d, d], vec![0.2f32; d * d]),
    ];
    let meta = vec![];
    let weights = build_f32(&tensors, &meta);
    let b3 = blake3::hash(&weights).to_hex().to_string();
    let sha = hex::encode(Sha256::digest(&weights));

    let manifest_json = json!({
        "v": 1,
        "model_id": "adversarial-mamba-renamed",
        "execution_class": "AR_CAUSAL",
        "artifact": {
            "cas_uri": format!("cas://blake3-bao-v1/{b3}"),
            "blake3": b3,
            "sha256": sha,
            "format": "safetensors"
        },
        "tensor_namespace": "enclave_adapter.adversarial",
        "stateless_across_rpc": true,
        "output_caps": {"max_output_bytes": 4096},
        "calibration": {"ece_max": 0.015, "bins": 15, "binning": "equal_mass", "dataset": "enclave-calib-eval-v1"},
        "max_provenance_fanin": 64,
        "license_policy": {"spdx_id": "Apache-2.0", "allow_p2p_seeding": false}
    });

    let manifest: ModelManifestV1 = serde_json::from_value(manifest_json).unwrap();

    // 2. Static inspection passes because the keys were renamed:
    let idx = enclave_model_runnerd::safetensors::parse(&weights).unwrap();
    let static_features = enclave_model_runnerd::topology::verify_declared(&manifest, &idx);
    assert!(
        static_features.is_ok(),
        "Static key inspection alone passes"
    );

    // 3. BUT during compute-graph operator construction via the C++ MLX shim,
    // the model instantiates an SSM scan carry-over operator (PersistentStateScan):
    let mut attest = OpAttestor::new(manifest.execution_class, manifest.wrappers());

    // External operator attestation intercepts the operator instantiation from outside model code:
    let res = mlx::construct_operator_and_attest(&mut attest, OpFamily::PersistentStateScan);
    assert!(
        res.is_err(),
        "MLX shim must intercept and reject unauthorized operator"
    );
    let err = res.err().unwrap();
    assert_eq!(err.reason, "GRAPH_OP_NOT_AUTHORISED");

    // Similarly, CoreML MIL inspection before compileModel intercepts and rejects it:
    let mut attest_coreml = OpAttestor::new(manifest.execution_class, manifest.wrappers());
    let mil_res = coreml::inspect_and_admit(
        &mut attest_coreml,
        &["mamba.ssm_scan_layer", "state_update"],
    );
    assert!(
        mil_res.is_err(),
        "MIL inspector must reject unauthorized scan op in AR_CAUSAL"
    );
    let mil_err = mil_res.err().unwrap();
    assert_eq!(mil_err.reason, "GRAPH_OP_NOT_AUTHORISED");
}

#[test]
fn test_residual_byte_scan_of_metal_heap_after_request() {
    let size = 1024 * 1024; // 1 MiB scratch arena
    let mut arena = MetalArena::new(size).expect("Failed to create MetalArena");

    assert!(arena.len() >= size);
    assert_eq!(arena.len() % 16384, 0, "Length must be 16 KiB aligned");

    // Check canary page is armed with non-zero bytes
    let canary_before = arena.canary_slice();
    assert!(
        canary_before.iter().any(|&b| b != 0),
        "Canary must be armed"
    );

    // Warm up the Metal queue / pipeline once to exclude one-time driver initialization
    let _ = arena.wipe();

    // Re-arm canary and write simulated activation data throughout the arena
    arena.arm_canary();
    for (i, b) in arena.bytes_mut().iter_mut().enumerate() {
        *b = ((i & 0xff) as u8) ^ 0x3c;
    }
    assert!(arena.bytes().iter().any(|&b| b != 0));

    // Execute hardware fence-synchronized wipe:
    // waitUntilCompleted -> blit fillBuffer(0) -> explicit_bzero -> fence -> canary verify
    let report = arena.wipe_or_abort();

    // Verify 0 residual bytes across 100% of the heap (FS-701 §7.1)
    assert_eq!(report.residual, 0, "0 residual bytes required");

    // Verify wall-clock time <= 1.0 ms (1000 us) in release, or 2500 us in unoptimized debug test runs
    let max_micros = if cfg!(debug_assertions) { 2500 } else { 1000 };
    println!(
        "Metal wipe report (warm): bytes={}, residual={}, elapsed={} us (max allowed: {} us)",
        report.bytes, report.residual, report.micros, max_micros
    );
    #[cfg(target_os = "macos")]
    assert!(
        report.micros <= max_micros,
        "Wipe must complete in <= {} us: took {} us",
        max_micros,
        report.micros
    );

    // Manual sweep across every single byte in the buffer:
    for (idx, &byte) in arena.bytes().iter().enumerate() {
        assert_eq!(byte, 0, "Byte at offset {idx} was not zeroed");
    }
}

#[test]
fn test_reference_class_fixtures_bind_and_admit_declared_operators() {
    let phase1_classes = [
        (
            "LLaDA-8B",
            ExecutionClass::DiscreteDiffusion,
            vec![OpFamily::BidirectionalMask, OpFamily::DenoiseStep],
        ),
        (
            "RWKV-7",
            ExecutionClass::RecurrentSsmTtt,
            vec![OpFamily::PersistentStateScan, OpFamily::CausalDecode],
        ),
        (
            "EAGLE-3",
            ExecutionClass::SpeculativeOrRecurrentDepth,
            vec![
                OpFamily::RecurrentDepthLoop,
                OpFamily::DraftTree,
                OpFamily::CausalDecode,
            ],
        ),
        (
            "V-JEPA 2",
            ExecutionClass::JepaEbmWorldPlanner,
            vec![OpFamily::JepaPredict, OpFamily::MpcRollout],
        ),
    ];

    for (name, class, expected_ops) in phase1_classes {
        println!("Testing Phase-1 class: {name} ({})", class.name());
        let pkg = zoo::package(class).unwrap_or_else(|e| panic!("Failed to package {name}: {e}"));
        let manifest: ModelManifestV1 = serde_json::from_value(pkg.manifest.clone()).unwrap();

        // 1. Operator attestation over the graph
        let mut attest = OpAttestor::new(manifest.execution_class, manifest.wrappers());
        let construct_res = mlx::construct_and_attest(&mut attest, &expected_ops);
        assert!(
            construct_res.is_ok(),
            "{name}: MLX operator construction must succeed"
        );

        // 2. Bind the adapter over the weights
        let thermal = Box::new(FixedThermal(ThermalState::Nominal, PowerSource::Ac));
        let adapter = EnclaveModelAdapter::bind(manifest, &pkg.weights, Profile::L2, None, thermal)
            .unwrap_or_else(|e| panic!("Failed to bind {name}: {e}"));

        // 3. Verify adapter configuration
        assert_eq!(adapter.manifest.execution_class, class);
        assert_eq!(adapter.controls.primary, class);

        // 4. Scratch memory allocation and wipe
        let mut scratch = MetalArena::new(65536).unwrap();
        scratch.bytes_mut()[0..128].fill(0x7e);
        let wipe_rep = scratch.wipe_or_abort();
        assert_eq!(
            wipe_rep.residual, 0,
            "{name}: scratch zeroization must leave 0 residual bytes"
        );
    }
}

#[test]
fn f106_unknown_nul_and_disguised_mil_names_fail_closed() {
    for names in [
        vec!["conv"],
        vec!["matmul"],
        vec!["classifier_head\0ssm_scan"],
        vec!["benign_attention_scan"],
        vec![],
    ] {
        let mut attest = OpAttestor::new(ExecutionClass::ArCausal, &[]);
        assert!(
            coreml::inspect_and_admit(&mut attest, &names).is_err(),
            "{names:?}"
        );
    }
    let mut attest = OpAttestor::new(ExecutionClass::DiscriminativeRlcd, &[]);
    coreml::inspect_and_admit(&mut attest, &["classifier_head"]).unwrap();
}

#[test]
fn f106_parallel_shim_contexts_never_cross_or_admit_by_default() {
    let mut workers = Vec::new();
    for _ in 0..8 {
        workers.push(std::thread::spawn(|| {
            for _ in 0..500 {
                let mut attest = OpAttestor::new(ExecutionClass::ArCausal, &[]);
                assert!(
                    mlx::construct_operator_and_attest(&mut attest, OpFamily::CausalDecode).is_ok()
                );
                assert!(mlx::construct_operator_and_attest(
                    &mut attest,
                    OpFamily::PersistentStateScan
                )
                .is_err());
            }
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn f111_canary_is_separate_and_portable_wipe_changes_original_buffer() {
    for size in [1, 4096, 16384, 16385] {
        let mut a = MetalArena::new(size).unwrap();
        let canary = a.canary_slice().to_vec();
        a.bytes_mut().fill(0x5a);
        assert_eq!(a.canary_slice(), canary);
        let r = a.wipe();
        assert_eq!(r.residual, 0);
        assert!(r.bytes > a.len() as u64);
        assert!(a.bytes().iter().all(|b| *b == 0));
        assert!(a.canary_slice().iter().all(|b| *b == 0));
        a.f32_mut()[0] = 3.0;
        assert_eq!(a.f32()[0], 3.0);
    }
    assert!(MetalArena::new(usize::MAX).is_err());
    assert!(enclave_model_runnerd::arena::ngram_features(b"x", 0)
        .unwrap_err()
        .is("FEATURE_WIDTH_ZERO"));
    assert_eq!(
        enclave_model_runnerd::arena::ngram_features(b"x", 4)
            .unwrap()
            .len(),
        4
    );
}

#[test]
fn f111_portable_float_views_have_allocation_guaranteed_alignment() {
    for n in [1, 4, 16384, 16385] {
        let mut a = enclave_model_runnerd::arena_metal::MetalArena::new(n).unwrap();
        assert_eq!((a.f32().as_ptr() as usize) % std::mem::align_of::<f32>(), 0);
        a.f32_mut()[0] = 42.0;
        assert_eq!(a.f32()[0], 42.0);
        assert_eq!(a.wipe().residual, 0);
        assert!(a.bytes().iter().all(|b| *b == 0));
    }
}
