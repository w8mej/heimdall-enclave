//! FS-701 acceptance: every class gate catches unredacted PII on its output
//! path and wipes its continuous state; misclassification attacks fail closed.

use std::path::PathBuf;

use enclave_core::label::{Conf, Label, Taint};
use enclave_core::profile::Profile;
use enclave_core::secret::SecretKey32;
use enclave_model_runnerd::adapter::{CalibrationInput, EnclaveModelAdapter, Engine};
use enclave_model_runnerd::arena::{output_guard, ZeroizeTrigger};
use enclave_model_runnerd::classes::byte_concept::{
    byte_dfa_validate, canonicalize, Leace, SurrogateVerifier,
};
use enclave_model_runnerd::classes::diffusion::{
    milestones, BigramDenoiser, DiffusionBackend, DiffusionGate, ReferenceProbe,
};
use enclave_model_runnerd::classes::rlcd::{RlcdMode, RlcdOutput, RlcdRequest};
use enclave_model_runnerd::classes::speculative::{
    r_max, CadencePacer, FixedThermal, PowerSource, ThermalState,
};
use enclave_model_runnerd::classes::world::{
    mask_frame, total_energy, Action, Actuator, CdpPipeDriver, Frame, MicroCapabilities, Rect,
    ResolvedTarget,
};
use enclave_model_runnerd::dfa::{ArgSchema, Dfa};
use enclave_model_runnerd::manifest::{ExecutionClass, ModelManifestV1};
use enclave_model_runnerd::safetensors::{build_f32, parse};
use enclave_model_runnerd::topology::{OpAttestor, OpFamily};
use enclave_model_runnerd::zoo::{self, package, Packaged};

fn nominal() -> Box<FixedThermal> {
    Box::new(FixedThermal(ThermalState::Nominal, PowerSource::Ac))
}

fn manifest(p: &Packaged) -> ModelManifestV1 {
    serde_json::from_value(p.manifest.clone()).unwrap()
}

fn bind(class: ExecutionClass) -> EnclaveModelAdapter {
    let p = package(class).unwrap();
    let pin = blake3::hash(p.corpus.as_deref().unwrap_or(b""))
        .to_hex()
        .to_string();
    let calib = p.corpus.as_deref().map(|c| CalibrationInput {
        corpus: c,
        pinned_blake3: &pin,
    });
    EnclaveModelAdapter::bind(manifest(&p), &p.weights, Profile::L2, calib, nominal()).unwrap()
}

fn rebuild(p: &mut Packaged, tensors: &[(&str, Vec<usize>, Vec<f32>)], meta: &[(&str, &str)]) {
    p.weights = build_f32(tensors, meta);
    let b3 = blake3::hash(&p.weights).to_hex().to_string();
    p.set_cas_root(&b3);
    use sha2::Digest;
    p.manifest["artifact"]["sha256"] =
        serde_json::json!(hex::encode(sha2::Sha256::digest(&p.weights)));
}

#[test]
fn manifest_schema_fixtures() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas/examples");
    for ok in [
        "enclave-model.manifest.example.llada.json",
        "enclave-model.manifest.example.vjepa2.json",
    ] {
        ModelManifestV1::from_json(&std::fs::read(root.join(ok)).unwrap())
            .unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
    for (bad, reason) in [
        ("ece-0.02", "ECE_MAX_ABOVE_0_015"),
        (
            "upstream-tensor-names",
            "TENSOR_NAMESPACE_NOT_ENCLAVE_ADAPTER",
        ),
        ("world-planner-uncapped", "WORLD_PLANNER_CAPS_REQUIRED"),
    ] {
        let e = ModelManifestV1::from_json(
            &std::fs::read(root.join(format!("invalid/enclave-model.manifest.invalid.{bad}.json")))
                .unwrap(),
        )
        .unwrap_err();
        assert!(e.is(reason), "{bad}: {e}");
    }
    // Unknown fields and stateful-across-RPC manifests are refused.
    let mut v = package(ExecutionClass::ArCausal).unwrap().manifest;
    v["kv_cache_export"] = serde_json::json!(true);
    assert!(ModelManifestV1::from_json(&serde_json::to_vec(&v).unwrap())
        .unwrap_err()
        .is("MANIFEST_SCHEMA"));
    let mut v = package(ExecutionClass::ArCausal).unwrap().manifest;
    v["stateless_across_rpc"] = serde_json::json!(false);
    assert!(ModelManifestV1::from_json(&serde_json::to_vec(&v).unwrap())
        .unwrap_err()
        .is("STATEFUL_ACROSS_RPC"));
}

#[test]
fn every_zoo_class_binds_with_matching_topology() {
    for c in [
        ExecutionClass::ArCausal,
        ExecutionClass::DiscriminativeRlcd,
        ExecutionClass::DiscreteDiffusion,
        ExecutionClass::RecurrentSsmTtt,
        ExecutionClass::ByteOrConcept,
        ExecutionClass::SpeculativeOrRecurrentDepth,
        ExecutionClass::JepaEbmWorldPlanner,
    ] {
        let a = bind(c);
        assert_eq!(a.controls.primary, c);
    }
}

#[test]
fn misclassification_and_renaming_attacks_fail_closed() {
    // SSM tensors renamed to look like attention, declared AR_CAUSAL: the
    // `.ssm.` adapter tensors and `A_log` still give it away.
    let mut p = package(ExecutionClass::RecurrentSsmTtt).unwrap();
    p.manifest["execution_class"] = serde_json::json!("AR_CAUSAL");
    let e = EnclaveModelAdapter::bind(manifest(&p), &p.weights, Profile::L2, None, nominal())
        .unwrap_err();
    assert!(e.is("EXECUTION_CLASS_MISMATCH"), "{e}");
    // A hybrid AR + one recurrent layer upgrades to RECURRENT_SSM_TTT.
    let mut p = package(ExecutionClass::ArCausal).unwrap();
    let ar = parse(&p.weights).unwrap();
    let mut t: Vec<(&str, Vec<usize>, Vec<f32>)> = vec![(
        "lm_head.weight",
        vec![300, 8],
        p.weights[ar.tensors["lm_head.weight"].range.0..ar.tensors["lm_head.weight"].range.1]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| f32::from_le_bytes(*c))
            .collect(),
    )];
    t.push(("layers.7.mixer.A_log", vec![8], vec![0.0; 8]));
    t.push((
        "enclave_adapter.ar.bigram",
        vec![256, 256],
        vec![0.0; 65536],
    ));
    rebuild(&mut p, &t, &[]);
    assert!(
        EnclaveModelAdapter::bind(manifest(&p), &p.weights, Profile::L2, None, nominal())
            .unwrap_err()
            .is("EXECUTION_CLASS_MISMATCH")
    );
    // RLCD with a generative lm_head.
    let mut p = package(ExecutionClass::DiscriminativeRlcd).unwrap();
    rebuild(
        &mut p,
        &[
            (
                "enclave_adapter.rlcd_head.weight",
                vec![4, 64],
                vec![0.1; 256],
            ),
            (
                "enclave_adapter.ece_calibration_lut",
                vec![15],
                zoo::identity_lut(),
            ),
            ("lm_head.weight", vec![32000, 1], vec![0.0; 32000]),
        ],
        &[],
    );
    assert!(
        EnclaveModelAdapter::bind(manifest(&p), &p.weights, Profile::L2, None, nominal())
            .unwrap_err()
            .is("GENERATIVE_LM_HEAD_IN_RLCD")
    );
    // Draft head without the SPECULATIVE wrapper.
    let mut p = package(ExecutionClass::ArCausal).unwrap();
    rebuild(
        &mut p,
        &[
            ("lm_head.weight", vec![300, 8], vec![0.0; 2400]),
            (
                "enclave_adapter.ar.bigram",
                vec![256, 256],
                vec![0.0; 65536],
            ),
            (
                "enclave_adapter.eagle_fc.weight",
                vec![256, 256],
                vec![0.0; 65536],
            ),
        ],
        &[],
    );
    assert!(
        EnclaveModelAdapter::bind(manifest(&p), &p.weights, Profile::L2, None, nominal())
            .unwrap_err()
            .is("SPECULATIVE_WRAPPER_REQUIRED")
    );
    p.manifest["auxiliary_wrappers"] = serde_json::json!(["SPECULATIVE_OR_RECURRENT_DEPTH"]);
    let a =
        EnclaveModelAdapter::bind(manifest(&p), &p.weights, Profile::L2, None, nominal()).unwrap();
    assert_eq!(a.controls.cadence_ms, Some(20), "wrapper tightens pacing");
    // Topology fingerprint and artifact digest pinning.
    let mut p = package(ExecutionClass::DiscreteDiffusion).unwrap();
    p.manifest["topology_fingerprint_blake3"] = serde_json::json!("00".repeat(32));
    assert!(
        EnclaveModelAdapter::bind(manifest(&p), &p.weights, Profile::L2, None, nominal())
            .unwrap_err()
            .is("TOPOLOGY_FINGERPRINT_MISMATCH")
    );
    let p = package(ExecutionClass::DiscreteDiffusion).unwrap();
    let mut w = p.weights.clone();
    *w.last_mut().unwrap() ^= 1;
    assert!(
        EnclaveModelAdapter::bind(manifest(&p), &w, Profile::L2, None, nominal())
            .unwrap_err()
            .is("ARTIFACT_SHA256_MISMATCH")
    );
    // Profile floor.
    let mut p = package(ExecutionClass::DiscreteDiffusion).unwrap();
    p.manifest["security_controls"] = serde_json::json!({"min_swarm_profile": "L3"});
    assert!(
        EnclaveModelAdapter::bind(manifest(&p), &p.weights, Profile::L2, None, nominal())
            .unwrap_err()
            .is("PROFILE_BELOW_MODEL_MINIMUM")
    );
}

/// The diffusion generation deadline is a signed per-model field: 2 s when
/// absent, bounded by the manifest range, and refused at bind (never
/// clamped) when it exceeds the bound profile's ceiling.
#[test]
fn diffusion_deadline_is_signed_per_model_and_capped_by_profile() {
    let deadline_of = |ms: Option<u32>, profile: Profile| {
        let mut p = package(ExecutionClass::DiscreteDiffusion).unwrap();
        if let Some(ms) = ms {
            p.manifest["output_caps"]["diffusion_deadline_ms"] = serde_json::json!(ms);
        }
        EnclaveModelAdapter::bind(manifest(&p), &p.weights, profile, None, nominal()).map(|a| match &a.engine {
            Engine::Diffusion(g) => g.deadline(),
            _ => unreachable!("diffusion package binds a diffusion engine"),
        })
    };
    let secs = std::time::Duration::from_millis;
    assert_eq!(deadline_of(None, Profile::L3).unwrap(), secs(2_000));
    assert_eq!(deadline_of(Some(8_000), Profile::L1).unwrap(), secs(8_000));
    assert_eq!(deadline_of(Some(20_000), Profile::L1).unwrap(), secs(20_000));
    assert_eq!(deadline_of(Some(5_000), Profile::L3).unwrap(), secs(5_000));
    for (ms, profile) in [(10_001, Profile::L2), (5_001, Profile::L3), (8_000, Profile::L3)] {
        assert!(deadline_of(Some(ms), profile).unwrap_err().is("DIFFUSION_DEADLINE_ABOVE_PROFILE"), "{ms} {profile}");
    }
    for ms in [0, 20_001] {
        let mut p = package(ExecutionClass::DiscreteDiffusion).unwrap();
        p.manifest["output_caps"]["diffusion_deadline_ms"] = serde_json::json!(ms);
        let m: ModelManifestV1 = serde_json::from_value(p.manifest.clone()).unwrap();
        assert!(m.validate().unwrap_err().is("OUTPUT_CAP_DIFFUSION_DEADLINE"), "{ms}");
    }
    let mut p = package(ExecutionClass::ArCausal).unwrap();
    p.manifest["output_caps"]["diffusion_deadline_ms"] = serde_json::json!(4_000);
    let m: ModelManifestV1 = serde_json::from_value(p.manifest.clone()).unwrap();
    assert!(m.validate().unwrap_err().is("DIFFUSION_DEADLINE_WITHOUT_DIFFUSION"));
}

#[test]
fn runtime_graph_attestation() {
    let mut ar = OpAttestor::new(ExecutionClass::ArCausal, &[]);
    ar.admit(OpFamily::CausalDecode).unwrap();
    for op in [
        OpFamily::PersistentStateScan,
        OpFamily::BidirectionalMask,
        OpFamily::RecurrentDepthLoop,
        OpFamily::MpcRollout,
    ] {
        assert!(
            ar.admit(op).unwrap_err().is("GRAPH_OP_NOT_AUTHORISED"),
            "{op:?}"
        );
    }
    let mut ssm = OpAttestor::new(
        ExecutionClass::RecurrentSsmTtt,
        &[ExecutionClass::SpeculativeOrRecurrentDepth],
    );
    ssm.admit(OpFamily::DraftTree).unwrap();
    assert!(ssm.admit(OpFamily::MpcRollout).is_err());
    assert_eq!(ssm.operator_family_log_digest().len(), 64);
}

// ---------------------------------------------------------------- Class 1

#[test]
fn class1_rlcd_ece_gate_and_anti_binary_search() {
    let p = package(ExecutionClass::DiscriminativeRlcd).unwrap();
    let pin = blake3::hash(p.corpus.as_ref().unwrap())
        .to_hex()
        .to_string();
    // ECE gate: wrong corpus digest and an over-confident LUT are refused.
    assert!(EnclaveModelAdapter::bind(
        manifest(&p),
        &p.weights,
        Profile::L2,
        Some(CalibrationInput {
            corpus: p.corpus.as_ref().unwrap(),
            pinned_blake3: &"0".repeat(64)
        }),
        nominal()
    )
    .unwrap_err()
    .is("CALIBRATION_CORPUS_DIGEST"));
    assert!(
        EnclaveModelAdapter::bind(manifest(&p), &p.weights, Profile::L2, None, nominal())
            .unwrap_err()
            .is("ECE_CORPUS_REQUIRED")
    );
    let mut hot = p.clone();
    rebuild(
        &mut hot,
        &[
            (
                "enclave_adapter.rlcd_head.weight",
                vec![4, 64],
                zoo::weights("rlcd.w", 256, 1.0),
            ),
            (
                "enclave_adapter.ece_calibration_lut",
                vec![15],
                (0..15)
                    .map(|i| ((i as f32 + 0.5) / 15.0 + 0.1).min(1.0))
                    .collect(),
            ),
        ],
        &[],
    );
    let e = EnclaveModelAdapter::bind(
        manifest(&hot),
        &hot.weights,
        Profile::L2,
        Some(CalibrationInput {
            corpus: p.corpus.as_ref().unwrap(),
            pinned_blake3: &pin,
        }),
        nominal(),
    )
    .unwrap_err();
    assert!(e.is("ECE_ABOVE_BOUND"), "{e}");

    let mut a = EnclaveModelAdapter::bind(
        manifest(&p),
        &p.weights,
        Profile::L2,
        Some(CalibrationInput {
            corpus: p.corpus.as_ref().unwrap(),
            pinned_blake3: &pin,
        }),
        nominal(),
    )
    .unwrap();
    assert!(a.ece.unwrap() <= 0.015);
    let Engine::Rlcd(g) = &mut a.engine else {
        panic!()
    };
    let ssn_record = b"patient 123-45-6789 diagnosis code";
    // Typed output only: a huge cardinality (the 20-questions shortcut) is refused.
    assert!(g
        .evaluate(
            &RlcdRequest {
                input: ssn_record,
                cardinality: 1 << 20,
                mode: RlcdMode::Choice,
                entities: &[],
                conf: Conf::C4
            },
            1
        )
        .is_err());
    // Fan-in > 64 aborts, never truncates.
    let many: Vec<String> = (0..65).map(|i| format!("ek_{:032x}", i)).collect();
    assert!(g
        .evaluate(
            &RlcdRequest {
                input: ssn_record,
                cardinality: 4,
                mode: RlcdMode::Choice,
                entities: &many,
                conf: Conf::C4
            },
            1
        )
        .unwrap_err()
        .is("PROVENANCE_FANIN_EXCEEDED"));
    // Binary search over one entity: 1-bit probes exhaust 12 bits.
    let ek = vec![format!("ek_{:032x}", 7)];
    let mut ok = 0;
    let mut last = None;
    for i in 0..20 {
        match g.evaluate(
            &RlcdRequest {
                input: ssn_record,
                cardinality: 2,
                mode: RlcdMode::Threshold {
                    class: 1,
                    threshold_permille: 500,
                },
                entities: &ek,
                conf: Conf::C4,
            },
            10 + i,
        ) {
            Ok((RlcdOutput::Bool(_), mb)) => {
                assert_eq!(mb, 1000);
                ok += 1;
            }
            Ok(o) => panic!("{o:?}"),
            Err(e) => {
                last = Some(e);
                break;
            }
        }
    }
    assert_eq!(ok, 12, "exactly 12 one-bit probes fit the 12,000 mb budget");
    assert!(last.unwrap().is("QIF_BUDGET_EXCEEDED"));
    // Deciles charge log2(11) = 3460 mb.
    let (o, mb) = g
        .evaluate(
            &RlcdRequest {
                input: b"x",
                cardinality: 11,
                mode: RlcdMode::Decile,
                entities: &[format!("ek_{:032x}", 9)],
                conf: Conf::C2,
            },
            50,
        )
        .unwrap();
    assert!(matches!(o, RlcdOutput::Decile(d) if d <= 10));
    assert_eq!(mb, 3460);
    // Unstructured probes of the same payload share a SimHash fallback key.
    let mut denied = false;
    for i in 0..10 {
        if g.evaluate(
            &RlcdRequest {
                input: ssn_record,
                cardinality: 4,
                mode: RlcdMode::Choice,
                entities: &[],
                conf: Conf::C2,
            },
            100 + i,
        )
        .is_err()
        {
            denied = true;
            break;
        }
    }
    assert!(
        denied,
        "2-bit probes on one unstructured record must exhaust the fallback key"
    );
}

// ---------------------------------------------------------------- Class 2

#[derive(Debug)]
struct Spell(Vec<u8>);
impl DiffusionBackend for Spell {
    fn logits(
        &self,
        x: &[Option<u8>],
        _t: u32,
        _n: u32,
    ) -> enclave_core::error::EnclaveResult<Vec<[f32; 256]>> {
        Ok((0..x.len())
            .map(|i| {
                let mut l = [0f32; 256];
                if let Some(b) = self.0.get(i) {
                    l[*b as usize] = 10.0 - i as f32 * 0.01;
                }
                l
            })
            .collect())
    }
}

#[test]
fn class2_dingo_constrains_and_pii_is_caught() {
    let schema = ArgSchema::Object(vec![
        (
            "action".into(),
            ArgSchema::Enum(vec!["open".into(), "close".into()]),
        ),
        ("ticket".into(), ArgSchema::UInt { max_digits: 19 }),
        ("notify".into(), ArgSchema::Bool),
    ]);
    let dfa = Dfa::compile(&schema).unwrap();
    let mut at = OpAttestor::new(ExecutionClass::DiscreteDiffusion, &[]);
    // Reference denoiser: always produces a DFA-valid document.
    let a = bind(ExecutionClass::DiscreteDiffusion);
    let Engine::Diffusion(g) = &a.engine else {
        panic!()
    };
    let r = g.generate(&dfa, 64, &mut at).unwrap();
    assert!(
        dfa.accepts(&r.output),
        "{}",
        String::from_utf8_lossy(&r.output)
    );
    serde_json::from_slice::<serde_json::Value>(&r.output).unwrap();
    assert_eq!(r.wipe.residual, 0);
    assert!(r.steps <= 16);
    // A denoiser that tries to emit invalid JSON is forced back into the grammar.
    let g2 = DiffusionGate::new(
        Box::new(Spell(
            br#"{"action":"delete","ticket":1,"notify":maybe}"#.to_vec(),
        )),
        Box::new(ReferenceProbe),
        16,
        4096,
    )
    .unwrap();
    let r2 = g2.generate(&dfa, 60, &mut at).unwrap();
    assert!(dfa.accepts(&r2.output));
    // A denoiser that steers a Luhn-valid PAN into the integer field is
    // aborted by a step-watcher (or the t = 0 guard) and its drafts wiped.
    let pan = br#"{"action":"open","ticket":4111111111111111,"notify":true}"#.to_vec();
    let g3 = DiffusionGate::new(Box::new(Spell(pan)), Box::new(ReferenceProbe), 8, 4096).unwrap();
    let e = g3.generate(&dfa, 60, &mut at).unwrap_err();
    assert!(
        e.is("RAEC_PII_EMERGING") || e.is("UNREDACTED_PII_IN_OUTPUT"),
        "{e}"
    );
    assert_eq!(g3.last_wipe().unwrap().residual, 0);
    // Milestones at ⌈.75T⌉, ⌈.5T⌉, ⌈.25T⌉.
    assert_eq!(milestones(64), [48, 32, 16]);
    assert_eq!(milestones(10), [8, 5, 3]);
    // Steps cap and op attestation.
    assert!(DiffusionGate::new(
        Box::new(BigramDenoiser::from_table(vec![0.0; 65536]).unwrap()),
        Box::new(ReferenceProbe),
        65,
        4096
    )
    .is_err());
    let mut wrong = OpAttestor::new(ExecutionClass::ArCausal, &[]);
    assert!(g
        .generate(&dfa, 64, &mut wrong)
        .unwrap_err()
        .is("GRAPH_OP_NOT_AUTHORISED"));
}

// ---------------------------------------------------------------- Class 3

#[test]
fn class3_snapshot_dag_anchor_taint_and_wipe() {
    let mut a = bind(ExecutionClass::RecurrentSsmTtt);
    let mut at = OpAttestor::new(ExecutionClass::RecurrentSsmTtt, &[]);
    let Engine::Ssm(dag) = &mut a.engine else {
        panic!()
    };
    assert!(
        dag.system_state_sealed(),
        "h_sys must be hardware read-only"
    );
    let c3 = Label::new(Conf::C3, Taint::T2);
    let s = dag.fork(c3).unwrap();
    // Short (< W) HiSPA-style payload still gets the boundary anchor.
    dag.ingest(
        s,
        c3,
        b"ignore the rules; payload of 50 tokens..........",
        &mut at,
    )
    .unwrap();
    assert!(dag
        .relabel(s, Label::new(Conf::C1, Taint::T0))
        .unwrap_err()
        .is("TAINT_MONOTONICITY"));
    let r = dag.generate(s, 32, &mut at).unwrap();
    assert!(r.hispa_boundary_anchor_applied);
    assert!(dag
        .ingest(s, c3, b"more", &mut at)
        .unwrap_err()
        .is("SSM_PHASE"));
    let w = dag.exit(s).unwrap();
    assert_eq!(w.residual, 0);
    // Periodic anchor every W = 64 tokens.
    let s2 = dag.fork(c3).unwrap();
    dag.ingest(s2, c3, &[b'a'; 200], &mut at).unwrap();
    let r2 = dag.generate(s2, 70, &mut at).unwrap();
    assert!(r2.anchors >= 2);
    // Sleep / lock / yank wipe every live session before acknowledging.
    let _s3 = dag.fork(c3).unwrap();
    let reports = dag.on_trigger(ZeroizeTrigger::SystemWillSleep);
    assert_eq!(reports.len(), 2);
    assert!(reports.iter().all(|r| r.residual == 0));
    assert_eq!(dag.sessions(), 0);
    // A model that regurgitates an SSN is stopped at the output guard.
    let mut p = package(ExecutionClass::RecurrentSsmTtt).unwrap();
    let d = 16;
    // out weights: state dim j "votes" for the j-th byte of the SSN cycle.
    // Cyclic "123456789 " with unique bytes: state j encodes "just saw ssn[j]".
    let ssn = b"123456789 ";
    let mut e = vec![0f32; 256 * d];
    let mut o = vec![0f32; d * 256];
    for j in 0..ssn.len() {
        e[ssn[j] as usize * d + j] = 5.0;
        o[j * 256 + ssn[(j + 1) % ssn.len()] as usize] = 5.0;
    }
    rebuild(
        &mut p,
        &[
            ("backbone.mixer.A_log", vec![d], vec![5.0; d]),
            ("enclave_adapter.ssm.embed", vec![256, d], e),
            ("enclave_adapter.ssm.out", vec![d, 256], o),
            ("enclave_adapter.ssm.h_sys", vec![d], {
                let mut h = vec![0.0; d];
                h[ssn.len() - 1] = 1.0;
                h
            }),
        ],
        &[],
    );
    let mut a =
        EnclaveModelAdapter::bind(manifest(&p), &p.weights, Profile::L2, None, nominal()).unwrap();
    let Engine::Ssm(dag) = &mut a.engine else {
        panic!()
    };
    let s = dag.fork(c3).unwrap();
    let e = dag.generate(s, 24, &mut at).unwrap_err();
    assert!(e.is("UNREDACTED_PII_IN_OUTPUT"), "{e}");
    assert_eq!(dag.exit(s).unwrap().residual, 0);
}

// ---------------------------------------------------------------- Class 4

#[test]
fn class4_byte_dfa_surrogates_leace_and_canaries() {
    // NFC + zero-width stripping.
    assert_eq!(
        canonicalize("1\u{200B}2\u{200D}3-e\u{301}".as_bytes()).unwrap(),
        "123-\u{e9}"
    );
    // Raw SSN / PAN split across "patches" with separators is still caught.
    for bad in [
        &b"id 123-45-6789"[..],
        b"id 123 45 6789",
        b"card 4111-1111-1111-1111",
        b"x 4111.1111.1111.1111 y",
    ] {
        assert!(
            byte_dfa_validate(bad, None)
                .unwrap_err()
                .is("UNREDACTED_PII_IN_OUTPUT"),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
    // The review requires every valid SSN window, including one overlapping
    // a phone number; this ambiguity now receives the conservative decision.
    assert!(byte_dfa_validate(b"call 415-555-0100 on 2026-11-05", None).is_err());
    byte_dfa_validate(b"schedule on 2026-11-05", None).unwrap();
    // MAC-tagged surrogates verify; forged tags (confused deputy) do not.
    let v = SurrogateVerifier::new(SecretKey32::random());
    let core = "SYNTH-SSN-904-00-1182";
    let good = format!("subject {core}-{} ok", v.tag(core));
    byte_dfa_validate(good.as_bytes(), Some(&v)).unwrap();
    let forged = format!("subject {core}-a91f4c ok");
    assert!(byte_dfa_validate(forged.as_bytes(), Some(&v))
        .unwrap_err()
        .is("SURROGATE_FORGED"));
    assert!(byte_dfa_validate(good.as_bytes(), None)
        .unwrap_err()
        .is("SURROGATE_WITHOUT_SESSION_KEY"));
    // LEACE removes the PII subspace.
    let l = Leace::new(&[vec![1.0, 1.0, 0.0, 0.0], vec![0.0, 1.0, 1.0, 0.0]]).unwrap();
    let mut c = vec![3.0, -2.0, 5.0, 1.0];
    l.project(&mut c);
    assert!(l.residual(&c) < 1e-5);
    // End to end through the reference concept stack.
    let mut a = bind(ExecutionClass::ByteOrConcept);
    let mut at = OpAttestor::new(ExecutionClass::ByteOrConcept, &[]);
    let Engine::Concept(g) = &mut a.engine else {
        panic!()
    };
    let r = g
        .run("please close the ticket".as_bytes(), None, &mut at)
        .unwrap();
    assert!(["ticket closed", "escalate to tier two", "refund approved"]
        .contains(&std::str::from_utf8(&r.output).unwrap()));
    assert_eq!(r.wipe.residual, 0);
    assert!(g.validate_bytes(b"SSN 123-45-6789", None).is_err());
    // A codebook that can only decode to a raw SSN is blocked at the byte DFA.
    let mut p = package(ExecutionClass::ByteOrConcept).unwrap();
    let idx = parse(&p.weights).unwrap();
    let t = |n: &str, s: Vec<usize>| -> (String, Vec<usize>, Vec<f32>) {
        (n.to_owned(), s.clone(), idx.f32(&p.weights, n, &s).unwrap())
    };
    let ts = [
        t("enclave_adapter.lcm.sonar_encoder.proj", vec![16, 64]),
        t("enclave_adapter.lcm.concept_denoiser.weight", vec![16, 16]),
        t("enclave_adapter.leace_nullspace", vec![2, 16]),
        t("enclave_adapter.sonar_canaries", vec![1, 16]),
    ];
    let refs: Vec<(&str, Vec<usize>, Vec<f32>)> = ts
        .iter()
        .map(|(n, s, v)| (n.as_str(), s.clone(), v.clone()))
        .collect();
    rebuild(
        &mut p,
        &refs,
        &[("enclave_adapter.lcm.codebook", r#"["SSN 123-45-6789"]"#)],
    );
    let mut a =
        EnclaveModelAdapter::bind(manifest(&p), &p.weights, Profile::L2, None, nominal()).unwrap();
    let Engine::Concept(g) = &mut a.engine else {
        panic!()
    };
    assert!(g
        .run(b"anything", None, &mut at)
        .unwrap_err()
        .is("UNREDACTED_PII_IN_OUTPUT"));
    // SONAR canary: a denoiser that collapses every concept onto ±v, with
    // canaries at ±P⊥v, must trip the breaker.
    let leace_rows: Vec<Vec<f32>> = refs[2]
        .2
        .as_chunks::<16>()
        .0
        .iter()
        .map(|r| r.to_vec())
        .collect();
    let mut v: Vec<f32> = zoo::weights("canary.v", 16, 1.0);
    Leace::new(&leace_rows).unwrap().project(&mut v);
    let collapse: Vec<f32> = (0..16 * 16).map(|i| v[i / 16]).collect();
    let neg: Vec<f32> = v.iter().map(|x| -x).collect();
    let mut p = package(ExecutionClass::ByteOrConcept).unwrap();
    let mut canaries = v.clone();
    canaries.extend_from_slice(&neg);
    rebuild(
        &mut p,
        &[
            refs[0].clone(),
            (
                "enclave_adapter.lcm.concept_denoiser.weight",
                vec![16, 16],
                collapse,
            ),
            refs[2].clone(),
            ("enclave_adapter.sonar_canaries", vec![2, 16], canaries),
        ],
        &[("enclave_adapter.lcm.codebook", r#"["ok"]"#)],
    );
    let mut a =
        EnclaveModelAdapter::bind(manifest(&p), &p.weights, Profile::L2, None, nominal()).unwrap();
    let Engine::Concept(g) = &mut a.engine else {
        panic!()
    };
    assert!(g
        .run(b"anything at all", None, &mut at)
        .unwrap_err()
        .is("SONAR_CANARY_TRIPPED"));
    let mut p2 = package(ExecutionClass::ByteOrConcept).unwrap();
    p2.manifest["security_controls"]["smooth_lcm_sigma_min"] = serde_json::json!(-1.0);
    assert!(ModelManifestV1::from_json(&p2.manifest_bytes()).is_err());
}

// ---------------------------------------------------------------- Class 5

#[test]
fn class5_thermal_breaker_drafts_and_cadence() {
    assert_eq!(
        r_max(32, 8, ThermalState::Nominal, PowerSource::Ac).unwrap(),
        32
    );
    assert_eq!(
        r_max(32, 8, ThermalState::Nominal, PowerSource::Battery).unwrap(),
        8
    );
    assert_eq!(
        r_max(32, 8, ThermalState::Fair, PowerSource::Ac).unwrap(),
        8
    );
    assert_eq!(
        r_max(32, 8, ThermalState::Serious, PowerSource::Ac).unwrap(),
        4
    );
    assert!(r_max(32, 8, ThermalState::Critical, PowerSource::Ac)
        .unwrap_err()
        .is("THERMAL_CRITICAL_YIELD"));

    let a = bind(ExecutionClass::SpeculativeOrRecurrentDepth);
    let mut at = OpAttestor::new(ExecutionClass::SpeculativeOrRecurrentDepth, &[]);
    let Engine::Depth(g) = &a.engine else {
        panic!()
    };
    let (r, w) = g.think(b"status?", &mut at).unwrap();
    assert!(r.iterations >= 1 && r.iterations <= 8);
    assert_eq!(w.residual, 0);
    let (out, zeroed) = g.speculate(b"status?", 12, 4, &mut at).unwrap();
    assert_eq!(out.len(), 12);
    assert!(zeroed > 0, "rejected drafts must be zeroized");
    // Under thermal pressure the loop is clamped to 4 iterations.
    let p = package(ExecutionClass::SpeculativeOrRecurrentDepth).unwrap();
    let hot = EnclaveModelAdapter::bind(
        manifest(&p),
        &p.weights,
        Profile::L2,
        None,
        Box::new(FixedThermal(ThermalState::Serious, PowerSource::Battery)),
    )
    .unwrap();
    let Engine::Depth(gh) = &hot.engine else {
        panic!()
    };
    assert!(gh.think(b"status?", &mut at).unwrap().0.iterations <= 4);

    #[cfg(target_os = "macos")]
    {
        use enclave_model_runnerd::classes::speculative::{DarwinThermal, ThermalProvider};
        let dt = DarwinThermal::new();
        let (initial_t, initial_p) = dt.sample();
        println!(
            "Initial DarwinThermal telemetry: {:?}, {:?}",
            initial_t, initial_p
        );

        // Actual telemetry smoke only; the FixedThermal ladder above is the
        // portable injected test. Production exposes no simulation override.
        let _ = (initial_t, initial_p);
    }
    // Latent circuit breaker: a probe aligned with the attractor trips.
    let mut p = package(ExecutionClass::SpeculativeOrRecurrentDepth).unwrap();
    let idx = parse(&p.weights).unwrap();
    let get = |n: &str, s: &[usize]| idx.f32(&p.weights, n, s).unwrap();
    let core = vec![0.0f32; 256];
    let mut embed = vec![0.0f32; 256 * 16];
    for b in 0..256 {
        embed[b * 16] = 1.0;
    }
    let mut eye = core.clone();
    eye[0] = 3.0;
    let mut probe = vec![0.0f32; 16];
    probe[0] = 1.0;
    let ts = vec![
        ("enclave_adapter.recurrent_core.embed", vec![256, 16], embed),
        (
            "enclave_adapter.latent_thought_proj.weight",
            vec![16, 16],
            eye,
        ),
        (
            "enclave_adapter.recurrent_core.out",
            vec![256, 16],
            get("enclave_adapter.recurrent_core.out", &[256, 16]),
        ),
        ("enclave_adapter.latent_probe.weight", vec![16], probe),
    ];
    rebuild(
        &mut p,
        &ts,
        &[
            ("num_recurrent_steps", "8"),
            ("enclave_adapter.latent_probe.tau", "0.9"),
        ],
    );
    let b =
        EnclaveModelAdapter::bind(manifest(&p), &p.weights, Profile::L2, None, nominal()).unwrap();
    let Engine::Depth(gb) = &b.engine else {
        panic!()
    };
    assert!(gb
        .think(b"x", &mut at)
        .unwrap_err()
        .is("LATENT_CIRCUIT_BREAKER"));
    // Constant cadence: bursts are released one token per 20 ms tick.
    let mut pc = CadencePacer::new(1_000, 1);
    pc.push(b"abcdef");
    assert!(pc.release(1_019).is_empty());
    assert_eq!(pc.release(1_020), b"a");
    assert_eq!(pc.release(1_065), b"bc");
    assert_eq!(pc.yank(), 3);
    assert!(pc.release(2_000).is_empty());
    // Output guard on generated bytes.
    assert!(output_guard(b"key 4111111111111111", 4096).is_err());
}

// ---------------------------------------------------------------- Class 6

fn target(bundle: &str, origin: &str) -> ResolvedTarget {
    ResolvedTarget {
        app_bundle_id: bundle.into(),
        ax_role: "AXButton".into(),
        ax_title: "Submit".into(),
        url_origin: origin.into(),
        dom_selector: "#submit".into(),
    }
}

#[test]
fn class6_barrier_surprise_masking_and_cdp_sandbox() {
    // Energy barrier.
    assert_eq!(total_energy(f32::NAN, true, 0.0, 0.5, 100.0), f32::INFINITY);
    assert_eq!(total_energy(-f32::INFINITY, true, 0.0, 0.5, 100.0), -100.0);
    assert_eq!(total_energy(-1e9, false, 0.0, 0.5, 100.0), f32::INFINITY);
    assert_eq!(total_energy(1.0, true, 0.9, 0.5, 100.0), f32::INFINITY);
    // Pre-encoder masking zeroes PII boxes; fast scroll blurs the whole frame.
    let mut f = Frame {
        w: 8,
        h: 8,
        px: vec![200; 64],
    };
    mask_frame(
        &mut f,
        &[Rect {
            x: 0,
            y: 0,
            w: 4,
            h: 2,
        }],
        0.0,
        2000.0,
    )
    .unwrap();
    assert!(f.px[..4].iter().all(|p| *p == 0) && f.px[4] == 200);
    let mut f2 = Frame {
        w: 2,
        h: 1,
        px: vec![0, 200],
    };
    mask_frame(&mut f2, &[], 5000.0, 2000.0).unwrap();
    assert_eq!(f2.px, vec![100, 100]);

    let mut a = bind(ExecutionClass::JepaEbmWorldPlanner);
    let mut at = OpAttestor::new(ExecutionClass::JepaEbmWorldPlanner, &[]);
    let Engine::World(g) = &mut a.engine else {
        panic!()
    };
    let s = g
        .observe(
            Frame {
                w: 16,
                h: 16,
                px: (0..256).map(|i| i as u8).collect(),
            },
            &[],
            0.0,
        )
        .unwrap();
    let goal = g
        .observe(
            Frame {
                w: 16,
                h: 16,
                px: vec![128; 256],
            },
            &[],
            0.0,
        )
        .unwrap();
    let policy = MicroCapabilities {
        tools: 0b0110,
        origins: vec!["https://tickets.corp.internal".into()],
    };
    let cands = vec![
        Action {
            tool_id: 1,
            target: target("com.google.Chrome", "https://tickets.corp.internal"),
            params_q: vec![10, -3],
        },
        Action {
            tool_id: 2,
            target: target("com.apple.Terminal", "https://tickets.corp.internal"),
            params_q: vec![0],
        },
        Action {
            tool_id: 3,
            target: target("com.google.Chrome", "https://tickets.corp.internal"),
            params_q: vec![1],
        },
        Action {
            tool_id: 2,
            target: target("com.google.Chrome", "https://evil.example"),
            params_q: vec![1],
        },
    ];
    let plan = g.plan(&s, &goal, &cands, &policy, &mut at).unwrap();
    assert_eq!(
        plan.action.tool_id, 1,
        "only tool 1 on an allowed origin and non-forbidden app survives"
    );
    assert!(plan.vetoes >= 3);
    // Every candidate forbidden → no safe action.
    let e = g
        .plan(&s, &goal, &cands[1..2], &policy, &mut at)
        .unwrap_err();
    assert!(e.is("NO_SAFE_ACTION"));
    // Surprise gate.
    g.surprise(&plan.predicted, &plan.predicted).unwrap();
    let far: Vec<f32> = plan.predicted.iter().map(|x| x + 1.0).collect();
    assert!(g
        .surprise(&plan.predicted, &far)
        .unwrap_err()
        .is("WORLD_MODEL_SURPRISE_ABORT"));
    assert_eq!(g.end_episode().unwrap().residual, 0);

    // CDP pipe driver against a fake sandboxed browser.
    let (mut ours_w, theirs_r) = std::os::unix::net::UnixStream::pair().unwrap();
    let ours_r = ours_w.try_clone().unwrap();
    let browser = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let mut s = theirs_r;
        let mut seen = Vec::new();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        while seen.len() < 8 {
            let n = s.read(&mut chunk).unwrap();
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            while let Some(p) = buf.iter().position(|b| *b == 0) {
                let msg: serde_json::Value = serde_json::from_slice(&buf[..p]).unwrap();
                buf.drain(..=p);
                let id = msg["id"].clone();
                let result = match msg["method"].as_str().unwrap() {
                    "Page.getFrameTree" => {
                        serde_json::json!({"frameTree": {"frame": {"url": "https://tickets.corp.internal/page"}}})
                    }
                    "DOM.getDocument" => {
                        serde_json::json!({"root": {"nodeId": 1, "children": [{"nodeId": 42, "backendNodeId": 420, "attributes": ["id", "submit"]}]}})
                    }
                    "DOM.getNodeForLocation" => serde_json::json!({"backendNodeId": 420}),
                    "DOM.querySelector" => serde_json::json!({"nodeId": 42}),
                    "DOM.getBoxModel" => {
                        serde_json::json!({"model": {"content": [10.0, 20.0, 30.0, 20.0, 30.0, 40.0, 10.0, 40.0]}})
                    }
                    _ => serde_json::json!({}),
                };
                seen.push(msg);
                let mut out =
                    serde_json::to_vec(&serde_json::json!({"id": id, "result": result})).unwrap();
                out.push(0);
                s.write_all(&out).unwrap();
            }
        }
        seen
    });
    {
        let mut drv = CdpPipeDriver::new(&mut ours_w, ours_r);
        drv.execute(&cands[0]).unwrap();
        assert!(drv
            .execute(&cands[1])
            .unwrap_err()
            .is("ACTUATION_TARGET_FORBIDDEN"));
    }
    let seen = browser.join().unwrap();
    let click = seen
        .iter()
        .find(|m| m["method"] == "Input.dispatchMouseEvent")
        .unwrap();
    assert_eq!(click["method"], "Input.dispatchMouseEvent");
    assert_eq!(click["params"]["x"], 20.0);
    assert_eq!(click["params"]["y"], 30.0);
}

#[test]
fn f141_every_completed_digit_window_is_scanned_before_trailing_digits() {
    for text in [
        "4111 1111 1111 1111 12 27",
        "00000000000000000000041111111111111111227",
        "0000123-45-6789000000000000000000000000",
        "4111.1111.1111.1111.1227",
    ] {
        assert!(
            byte_dfa_validate(text.as_bytes(), None)
                .unwrap_err()
                .is("UNREDACTED_PII_IN_OUTPUT"),
            "{text}"
        );
    }
    for text in [
        "release 2026-11-05",
        "ticket 00000000",
        "12 / 34 / 56",
        "digits 999999999999999999999999999999",
    ] {
        byte_dfa_validate(text.as_bytes(), None).unwrap();
    }
    let verifier = SurrogateVerifier::new(SecretKey32::random());
    let core = "SYNTH-SSN-904-00-1182";
    byte_dfa_validate(
        format!("{core}-{}", verifier.tag(core)).as_bytes(),
        Some(&verifier),
    )
    .unwrap();
}

#[test]
fn f142_compatibility_invisibles_and_strong_surrogate_protocol() {
    for c in [
        '\u{202c}',
        '\u{202d}',
        '\u{2067}',
        '\u{2068}',
        '\u{2069}',
        '\u{200e}',
        '\u{200f}',
        '\u{061c}',
        '\u{00ad}',
        '\u{e0001}',
        '\u{e007f}',
    ] {
        assert_eq!(
            canonicalize(format!("１２{c}３４").as_bytes()).unwrap(),
            "1234"
        );
    }
    assert_eq!(
        canonicalize("café office ﬃ".as_bytes()).unwrap(),
        "café office ffi"
    );
    assert!(byte_dfa_validate("ＳＳＮ １２３－４５－６７８９".as_bytes(), None).is_err());
    let v = SurrogateVerifier::new(SecretKey32::new([7; 32]));
    let core = "SYNTH-SSN-904-00-1182";
    let tag = v.tag(core);
    assert_eq!(tag.len(), 32);
    assert_eq!(tag, "eogmelfldbbencfahabmgnnfjglgjcfk");
    byte_dfa_validate(format!("{core}-{tag}").as_bytes(), Some(&v)).unwrap();
    for forged in [
        format!("{core}-{}", &tag[..6]),
        format!("SYNTH-{}", v.tag("SYNTH")),
        format!("SYNTH--{}", v.tag("SYNTH-")),
        format!(
            "{core}-{}",
            SurrogateVerifier::new(SecretKey32::new([8; 32])).tag(core)
        ),
    ] {
        assert!(byte_dfa_validate(forged.as_bytes(), Some(&v))
            .unwrap_err()
            .is("SURROGATE_FORGED"));
    }
}

#[test]
fn f142_surprise_rejects_missing_extra_nan_and_infinite_coordinates() {
    let mut a = bind(ExecutionClass::JepaEbmWorldPlanner);
    let Engine::World(g) = &mut a.engine else {
        panic!()
    };
    let state = g
        .observe(
            Frame {
                w: 8,
                h: 8,
                px: vec![0; 64],
            },
            &[],
            0.0,
        )
        .unwrap();
    assert_eq!(g.surprise(&state, &state).unwrap(), 0.0);
    assert!(g
        .surprise(&state, &state[..state.len() - 1])
        .unwrap_err()
        .is("WORLD_MODEL_SURPRISE_SHAPE"));
    let mut extra = state.clone();
    extra.push(0.0);
    assert!(g.surprise(&state, &extra).is_err());
    for v in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        let mut malformed = state.clone();
        malformed[0] = v;
        assert!(g.surprise(&malformed, &state).is_err());
        assert!(g.surprise(&state, &malformed).is_err());
    }
}

#[test]
fn f142_final_guard_still_refuses_pii_when_step_probe_sees_no_complete_pattern() {
    use enclave_model_runnerd::classes::diffusion::{ProbeVerdict, StepProbe};
    #[derive(Debug)]
    struct NoMilestoneEvidence;
    impl StepProbe for NoMilestoneEvidence {
        fn inspect(&self, _: &[Option<u8>], _: u32) -> ProbeVerdict {
            ProbeVerdict::Clean
        }
    }
    let text = br#""4111111111111111""#;
    let dfa = Dfa::compile(&ArgSchema::Enum(vec!["4111111111111111".into()])).unwrap();
    let g = DiffusionGate::new(
        Box::new(Spell(text.to_vec())),
        Box::new(NoMilestoneEvidence),
        4,
        64,
    )
    .unwrap();
    let mut attest = OpAttestor::new(ExecutionClass::DiscreteDiffusion, &[]);
    assert!(g
        .generate(&dfa, text.len(), &mut attest)
        .unwrap_err()
        .is("UNREDACTED_PII_IN_OUTPUT"));
    assert_eq!(g.last_wipe().unwrap().residual, 0);
    // This compiler rejects binary/control content; padding applies only to JSON.
    assert!(Dfa::compile(&ArgSchema::Enum(vec!["tail\0".into()]))
        .unwrap_err()
        .is("SCHEMA_ENUM_CHARS"));
    let dfa = Dfa::compile(&ArgSchema::Enum(vec!["tail".into()])).unwrap();
    let content = serde_json::to_vec("tail").unwrap();
    let mut padded = content.clone();
    padded.extend_from_slice(&[0, 0, 0]);
    assert!(dfa.accepts(&padded));
    assert_eq!(enclave_model_runnerd::dfa::unpad(&padded), content);
}
