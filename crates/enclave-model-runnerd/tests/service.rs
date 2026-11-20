//! UID 701 service: cross-RPC statelessness (`F-027`), fail-closed dispatch,
//! zeroization triggers and the `adapter-audit.jsonl` receipt.

use enclave_core::ipc::PeerCredentials;
use enclave_core::label::{Conf, Label, Taint};
use enclave_core::profile::Profile;
use enclave_model_runnerd::arena::ZeroizeTrigger;
use enclave_model_runnerd::classes::speculative::{FixedThermal, PowerSource, ThermalState};
use enclave_model_runnerd::dfa::ArgSchema;
use enclave_model_runnerd::manifest::ExecutionClass;
use enclave_model_runnerd::service::{
    ResolvedWeights, RunnerConfig, RunnerRequest, RunnerResponse, RunnerService, WeightSource,
};
use enclave_model_runnerd::zoo::package;

struct NoCas;
impl WeightSource for NoCas {
    fn resolve(&self, _: &str) -> enclave_core::error::EnclaveResult<ResolvedWeights> {
        Err(enclave_core::err!(EPERM, "NO_CAS"))
    }
}

fn svc(pin: Option<String>, audit: Option<std::path::PathBuf>) -> std::sync::Arc<RunnerService> {
    RunnerService::start(
        RunnerConfig {
            dev_same_uid: true,
            profile: Profile::L2,
            audit_path: audit,
            calib_corpus_blake3: pin,
            thermal: Box::new(|| Box::new(FixedThermal(ThermalState::Nominal, PowerSource::Ac))),
            actuator: None,
            state_dir: None,
        },
        Box::new(NoCas),
    )
    .unwrap()
}

/// UID 703's epoch and SEP epoch key in these tests (GAP-27).
fn epoch_key() -> &'static enclave_crypto::epoch::EpochSigner {
    static K: std::sync::OnceLock<enclave_crypto::epoch::EpochSigner> = std::sync::OnceLock::new();
    K.get_or_init(enclave_crypto::epoch::EpochSigner::random)
}

const EPOCH: &str = "0b1f1d2e-5a64-4c8e-9d7a-1c4f5b6a7e82";

fn slot(n: u64) -> Option<enclave_core::seq::GovernedSlot> {
    Some(enclave_core::seq::GovernedSlot {
        epoch: epoch_key().sign(EPOCH),
        rpc_seq_u64: n,
    })
}

fn peer() -> PeerCredentials {
    PeerCredentials {
        uid: 704,
        gid: 704,
        pid: None,
        audit_token: None,
        code_identity: None,
        tls_channel_binding: None,
    }
}

/// Walk a CBOR item; return true if any IEEE-754 float (major 7, ai 25/26/27) occurs.
fn cbor_has_float(b: &[u8]) -> bool {
    fn item(b: &[u8], i: &mut usize) -> Option<bool> {
        let ib = *b.get(*i)?;
        *i += 1;
        let (major, ai) = (ib >> 5, ib & 0x1f);
        let arg = |i: &mut usize| -> Option<u64> {
            Some(match ai {
                0..=23 => ai as u64,
                24 => {
                    *i += 1;
                    *b.get(*i - 1)? as u64
                }
                25 => {
                    *i += 2;
                    u16::from_be_bytes(b.get(*i - 2..*i)?.try_into().ok()?) as u64
                }
                26 => {
                    *i += 4;
                    u32::from_be_bytes(b.get(*i - 4..*i)?.try_into().ok()?) as u64
                }
                27 => {
                    *i += 8;
                    u64::from_be_bytes(b.get(*i - 8..*i)?.try_into().ok()?)
                }
                _ => return None,
            })
        };
        match major {
            0 | 1 => {
                arg(i)?;
                Some(false)
            }
            2 | 3 => {
                let n = arg(i)? as usize;
                *i += n;
                Some(false)
            }
            4 => {
                let n = arg(i)?;
                let mut f = false;
                for _ in 0..n {
                    f |= item(b, i)?;
                }
                Some(f)
            }
            5 => {
                let n = arg(i)?;
                let mut f = false;
                for _ in 0..2 * n {
                    f |= item(b, i)?;
                }
                Some(f)
            }
            6 => {
                arg(i)?;
                item(b, i)
            }
            7 => {
                if matches!(ai, 25..=27) {
                    arg(i)?;
                    Some(true)
                } else {
                    Some(false)
                }
            }
            _ => None,
        }
    }
    let mut i = 0;
    item(b, &mut i).unwrap_or(true)
}

#[test]
fn responses_never_carry_floats_or_state() {
    let dir = std::env::temp_dir().join(format!(
        "runner-{}-{}",
        std::process::id(),
        enclave_core::rng::u64()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let rl = package(ExecutionClass::DiscriminativeRlcd).unwrap();
    let pin = blake3::hash(rl.corpus.as_ref().unwrap())
        .to_hex()
        .to_string();
    let s = svc(Some(pin), Some(dir.join("adapter-audit.jsonl")));
    // Unbound: fail closed.
    assert!(s
        .handle(
            &peer(),
            RunnerRequest::Declassify {
                payload: b"x".to_vec().into(),
                cardinality: 4,
                schema: "s".into(),
                slot: slot(1)
            }
        )
        .unwrap_err()
        .is("MODEL_NOT_BOUND"));
    let mut responses = vec![];
    responses.push(
        s.bind_bytes(&rl.manifest_bytes(), &rl.weights, rl.corpus.as_deref())
            .unwrap(),
    );
    responses.push(
        s.handle(
            &peer(),
            RunnerRequest::Declassify {
                payload: b"ticket body".to_vec().into(),
                cardinality: 4,
                schema: "ticket.priority".into(),
                slot: slot(2),
            },
        )
        .unwrap(),
    );
    assert!(matches!(responses.last().unwrap(), RunnerResponse::Declassified(i) if *i < 4));
    // GAP-27: a declassification needs UID 703's slot, signed by the pinned key,
    // and is journaled under that epoch and slot.
    assert!(s
        .handle(
            &peer(),
            RunnerRequest::Declassify {
                payload: b"x".to_vec().into(),
                cardinality: 4,
                schema: "s".into(),
                slot: None
            }
        )
        .unwrap_err()
        .is("DECLASSIFY_SLOT_REQUIRED"));
    let forged = Some(enclave_core::seq::GovernedSlot {
        epoch: enclave_crypto::epoch::EpochSigner::random().sign(EPOCH),
        rpc_seq_u64: 9,
    });
    assert!(s
        .handle(
            &peer(),
            RunnerRequest::Declassify {
                payload: b"x".to_vec().into(),
                cardinality: 4,
                schema: "s".into(),
                slot: forged
            }
        )
        .unwrap_err()
        .is("EPOCH_SIGNER_CHANGED"));
    let j = std::fs::read_to_string(dir.join("adapter-audit.jsonl")).unwrap();
    let line: serde_json::Value = j
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .find(|v| v["payload"]["event"] == "DECLASSIFY")
        .unwrap();
    assert_eq!(
        (
            line["boot_epoch_id"].as_str().unwrap(),
            line["rpc_seq_u64"].as_u64().unwrap(),
            line["payload"]["slot"].as_u64().unwrap()
        ),
        (EPOCH, 2, 2)
    );
    // Wrong cardinality / wrong request class.
    assert!(s
        .handle(
            &peer(),
            RunnerRequest::Declassify {
                payload: b"x".to_vec().into(),
                cardinality: 7,
                schema: "s".into(),
                slot: slot(3)
            }
        )
        .unwrap_err()
        .is("DECLASSIFY_CARDINALITY_MISMATCH"));
    assert!(s
        .handle(
            &peer(),
            RunnerRequest::SsmFork {
                label: Label::new(Conf::C3, Taint::T2)
            }
        )
        .unwrap_err()
        .is("REQUEST_CLASS_MISMATCH"));

    let ssm = package(ExecutionClass::RecurrentSsmTtt).unwrap();
    responses.push(
        s.bind_bytes(&ssm.manifest_bytes(), &ssm.weights, None)
            .unwrap(),
    );
    let RunnerResponse::Session(id) = s
        .handle(
            &peer(),
            RunnerRequest::SsmFork {
                label: Label::new(Conf::C3, Taint::T2),
            },
        )
        .unwrap()
    else {
        panic!()
    };
    s.handle(
        &peer(),
        RunnerRequest::SsmIngest {
            session: id,
            label: Label::new(Conf::C3, Taint::T2),
            bytes: b"hello".to_vec().into(),
        },
    )
    .unwrap();
    responses.push(
        s.handle(&peer(), RunnerRequest::SsmGenerate { session: id, n: 8 })
            .unwrap(),
    );
    // Lid close wipes the live session; it cannot be resumed.
    // GAP-39: a peer daemon cannot wipe UID 701; the operator / supervisor can.
    if enclave_core::ipc::geteuid() != 704 {
        assert!(s
            .handle(
                &peer(),
                RunnerRequest::Zeroize(ZeroizeTrigger::SystemWillSleep)
            )
            .unwrap_err()
            .is("WIPE_PEER_REJECTED"));
    }
    let op = PeerCredentials::local(enclave_core::ipc::geteuid(), 0);
    assert!(matches!(
        s.handle(&op, RunnerRequest::Zeroize(ZeroizeTrigger::SystemWillSleep))
            .unwrap(),
        RunnerResponse::Wiped(1)
    ));
    assert!(s
        .handle(&peer(), RunnerRequest::SsmGenerate { session: id, n: 1 })
        .unwrap_err()
        .is("UNKNOWN_SESSION"));

    let diff = package(ExecutionClass::DiscreteDiffusion).unwrap();
    responses.push(
        s.bind_bytes(&diff.manifest_bytes(), &diff.weights, None)
            .unwrap(),
    );
    let schema = ArgSchema::Object(vec![
        (
            "action".into(),
            ArgSchema::Enum(vec!["open".into(), "close".into()]),
        ),
        ("ticket".into(), ArgSchema::UInt { max_digits: 4 }),
    ]);
    responses.push(
        s.handle(
            &peer(),
            RunnerRequest::GenerateStructured { schema, len: 40, prompt: None },
        )
        .unwrap(),
    );
    responses.push(s.handle(&peer(), RunnerRequest::Status).unwrap());

    for r in &responses {
        let mut b = Vec::new();
        ciborium::into_writer(&enclave_core::ipc::Reply::Ok(r.clone()), &mut b).unwrap();
        assert!(!cbor_has_float(&b), "float crossed the RPC boundary: {r:?}");
    }
    let lines = std::fs::read_to_string(dir.join("adapter-audit.jsonl")).unwrap();
    assert!(
        lines.contains("execution_class_declared")
            && lines.contains("reference_operator_family_log_blake3")
    );
    enclave_core::audit::verify_journal(&dir.join("adapter-audit.jsonl"), None).unwrap();
    // Unpinned corpus is refused.
    let s2 = svc(None, None);
    assert!(s2
        .bind_bytes(&rl.manifest_bytes(), &rl.weights, rl.corpus.as_deref())
        .unwrap_err()
        .is("ECE_CORPUS_UNPINNED"));
}

#[test]
fn f107_journal_only_records_actual_arena_wipes() {
    let dir = std::env::temp_dir().join(format!("f107-{}", enclave_core::rng::u64()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("audit.jsonl");
    let s = svc(None, Some(path.clone()));
    let p = package(ExecutionClass::RecurrentSsmTtt).unwrap();
    s.bind_bytes(&p.manifest_bytes(), &p.weights, None).unwrap();
    s.handle(
        &peer(),
        RunnerRequest::SsmFork {
            label: Label::BOTTOM,
        },
    )
    .unwrap();
    let before = std::fs::read_to_string(&path).unwrap();
    for line in before.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(v["payload"].get("wipe_reports").is_none());
        assert!(v["payload"].get("mtlheap_dual_zeroize_verified").is_none());
    }
    s.handle(
        &PeerCredentials::local(0, 0),
        RunnerRequest::Zeroize(ZeroizeTrigger::ScreenLocked),
    )
    .unwrap();
    let after = std::fs::read_to_string(&path).unwrap();
    let last: serde_json::Value = serde_json::from_str(after.lines().last().unwrap()).unwrap();
    let measured = &last["payload"]["wipe_reports"];
    assert_eq!(measured["backend"], "cpu_guarded_arena");
    assert_eq!(measured["reports"].as_array().unwrap().len(), 1);
    assert!(measured["reports"][0]["bytes"].as_u64().unwrap() > 0);
    assert_eq!(measured["reports"][0]["residual"], 0);
    s.handle(
        &PeerCredentials::local(0, 0),
        RunnerRequest::Zeroize(ZeroizeTrigger::ScreenLocked),
    )
    .unwrap();
    let again = std::fs::read_to_string(&path).unwrap();
    let last: serde_json::Value = serde_json::from_str(again.lines().last().unwrap()).unwrap();
    assert!(last["payload"].get("wipe_reports").is_none());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn f109_payload_variation_rebind_and_restart_share_one_budget() {
    let dir = std::env::temp_dir().join(format!("f109-{}", enclave_core::rng::u64()));
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let p = package(ExecutionClass::DiscriminativeRlcd).unwrap();
    let pin = blake3::hash(p.corpus.as_ref().unwrap())
        .to_hex()
        .to_string();
    let make = || {
        RunnerService::start(
            RunnerConfig {
                dev_same_uid: true,
                profile: Profile::L2,
                audit_path: None,
                calib_corpus_blake3: Some(pin.clone()),
                thermal: Box::new(|| {
                    Box::new(FixedThermal(ThermalState::Nominal, PowerSource::Ac))
                }),
                actuator: None,
                state_dir: Some(dir.clone()),
            },
            Box::new(NoCas),
        )
        .unwrap()
    };
    for i in 0..7 {
        let s = make();
        s.bind_bytes(&p.manifest_bytes(), &p.weights, p.corpus.as_deref())
            .unwrap();
        let result = s.handle(
            &peer(),
            RunnerRequest::Declassify {
                payload: format!("one record: random suffix {}", enclave_core::rng::u64())
                    .into_bytes()
                    .into(),
                cardinality: 4,
                schema: "test".into(),
                slot: slot(100 + i),
            },
        );
        if i < 6 {
            assert!(result.is_ok(), "valid release {i}: {result:?}");
        } else {
            assert!(result.unwrap_err().is("QIF_BUDGET_EXCEEDED"));
        }
        // Binding again must not reset the durable release ledger.
        s.bind_bytes(&p.manifest_bytes(), &p.weights, p.corpus.as_deref())
            .unwrap();
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn f110_bind_matches_independent_manifest_target_and_propagates_corpus_failure() {
    struct Signed(enclave_model_runnerd::zoo::Packaged);
    impl WeightSource for Signed {
        fn resolve(&self, _: &str) -> enclave_core::error::EnclaveResult<ResolvedWeights> {
            Ok(ResolvedWeights {
                primary: enclave_model_runnerd::arena::WeightBytes::Owned(self.0.weights.clone()),
                companions: vec![],
            })
        }
        fn fetch_manifest(&self, id: &str) -> enclave_core::error::EnclaveResult<Vec<u8>> {
            assert_eq!(id, self.0.manifest["model_id"].as_str().unwrap());
            Ok(self.0.manifest_bytes())
        }
    }
    let p = package(ExecutionClass::ArCausal).unwrap();
    let make = |pin| {
        RunnerService::start(
            RunnerConfig {
                dev_same_uid: true,
                profile: Profile::L2,
                audit_path: None,
                calib_corpus_blake3: pin,
                thermal: Box::new(|| {
                    Box::new(FixedThermal(ThermalState::Nominal, PowerSource::Ac))
                }),
                actuator: None,
                state_dir: None,
            },
            Box::new(Signed(p.clone())),
        )
        .unwrap()
    };
    let request = |manifest: Vec<u8>| RunnerRequest::Bind {
        manifest: manifest.into(),
        cas_uri: p.manifest["artifact"]["cas_uri"].as_str().unwrap().into(),
        calibration_corpus: None,
    };
    let s = make(None);
    let op = PeerCredentials::local(0, 0);
    assert!(matches!(
        s.handle(&op, request(p.manifest_bytes())).unwrap(),
        RunnerResponse::Bound { .. }
    ));
    let mut forged = p.manifest.clone();
    forged["output_caps"]["max_output_bytes"] = 1024.into();
    assert!(s
        .handle(&op, request(serde_json::to_vec(&forged).unwrap()))
        .unwrap_err()
        .is("MODEL_MANIFEST_UNSIGNED"));
    let s = make(Some("1".repeat(64)));
    assert!(s
        .handle(&op, request(p.manifest_bytes()))
        .unwrap_err()
        .is("CORPUS_NOT_FOUND"));
    for id in ["../bad", "id/other", "", "x\0y", "x:target"] {
        assert!(enclave_model_runnerd::service::model_manifest_target(id).is_err());
    }
}

#[test]
fn f111_model_replacement_is_administrator_only_and_triggers_keep_their_cause() {
    let s = svc(None, None);
    if peer().uid != enclave_core::ipc::geteuid() {
        assert!(s
            .handle(&peer(), RunnerRequest::Unbind)
            .unwrap_err()
            .is("MODEL_ADMIN_REQUIRED"));
        assert!(s
            .handle(
                &peer(),
                RunnerRequest::Bind {
                    manifest: vec![].into(),
                    cas_uri: "bad".into(),
                    calibration_corpus: None
                }
            )
            .unwrap_err()
            .is("MODEL_ADMIN_REQUIRED"));
    }
    s.handle(&PeerCredentials::local(0, 0), RunnerRequest::Unbind)
        .unwrap();
    use enclave_core::power::WipeTrigger;
    for (input, expected) in [
        (WipeTrigger::SystemSleep, ZeroizeTrigger::SystemWillSleep),
        (WipeTrigger::SessionLocked, ZeroizeTrigger::ScreenLocked),
        (
            WipeTrigger::AuthenticatorYank,
            ZeroizeTrigger::YubiKeyRemoved,
        ),
        (
            WipeTrigger::ThunderboltHotPlugLocked,
            ZeroizeTrigger::TaintExit,
        ),
    ] {
        assert_eq!(
            enclave_model_runnerd::entry::runner_wipe_trigger(input),
            expected
        );
    }
}

#[test]
fn f133_journal_does_not_misrepresent_family_log_as_executed_graph() {
    let dir = std::env::temp_dir().join(format!("f133-{}", enclave_core::rng::u64()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("audit.jsonl");
    let s = svc(None, Some(path.clone()));
    let p = package(ExecutionClass::RecurrentSsmTtt).unwrap();
    s.bind_bytes(&p.manifest_bytes(), &p.weights, None).unwrap();
    s.handle(
        &peer(),
        RunnerRequest::SsmFork {
            label: Label::BOTTOM,
        },
    )
    .unwrap();
    let journal = std::fs::read_to_string(&path).unwrap();
    let value: serde_json::Value = serde_json::from_str(journal.lines().last().unwrap()).unwrap();
    let p = &value["payload"];
    assert_eq!(p["inference_backend"], "cpu_reference");
    assert!(
        p["reference_operator_family_log_blake3"]
            .as_str()
            .unwrap()
            .len()
            == 64
    );
    assert!(p.get("runtime_graph_ir_blake3").is_none());
    assert!(p.get("execution_class_enforced").is_none());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn f140_ssm_output_wire_carries_joined_label_across_boundary_anchor() {
    let s = svc(None, None);
    let p = package(ExecutionClass::RecurrentSsmTtt).unwrap();
    s.bind_bytes(&p.manifest_bytes(), &p.weights, None).unwrap();
    let low = Label::new(Conf::C1, Taint::T0);
    let high = Label::new(Conf::C4, Taint::T3);
    let RunnerResponse::Session(id) = s
        .handle(&peer(), RunnerRequest::SsmFork { label: low })
        .unwrap()
    else {
        panic!()
    };
    s.handle(
        &peer(),
        RunnerRequest::SsmIngest {
            session: id,
            label: high,
            bytes: b"tainted".to_vec().into(),
        },
    )
    .unwrap();
    for n in [1, 8] {
        let response = s
            .handle(&peer(), RunnerRequest::SsmGenerate { session: id, n })
            .unwrap();
        let mut wire = Vec::new();
        ciborium::into_writer(&response, &mut wire).unwrap();
        let decoded: RunnerResponse = ciborium::from_reader(&wire[..]).unwrap();
        let RunnerResponse::Ssm {
            label,
            boundary_anchor,
            output,
            ..
        } = decoded
        else {
            panic!()
        };
        assert_eq!(label, low.join(high));
        assert!(boundary_anchor);
        assert_eq!(output.len(), n as usize);
    }
}

#[test]
fn f140_owned_scope_wire_preserves_label_and_idempotent_cleanup() {
    let service = svc(None, None);
    let package = package(ExecutionClass::RecurrentSsmTtt).unwrap();
    service.bind_bytes(&package.manifest_bytes(), &package.weights, None).unwrap();
    let scope = [0x14; 32];
    let low = Label::new(Conf::C1, Taint::T0);
    let high = Label::new(Conf::C4, Taint::T3);
    let call = |request: RunnerRequest| {
        let mut encoded = Vec::new();
        ciborium::into_writer(&request, &mut encoded).unwrap();
        let decoded: RunnerRequest = ciborium::from_reader(&encoded[..]).unwrap();
        let response = service.handle(&peer(), decoded).unwrap();
        let mut encoded = Vec::new();
        ciborium::into_writer(&response, &mut encoded).unwrap();
        ciborium::from_reader::<RunnerResponse, _>(&encoded[..]).unwrap()
    };
    let RunnerResponse::Session(session) = call(RunnerRequest::SsmForkOwned { scope, label: low }) else { panic!() };
    assert!(matches!(call(RunnerRequest::SsmForkOwned { scope, label: low }), RunnerResponse::Session(id) if id == session));
    assert!(matches!(call(RunnerRequest::SsmIngestOwned { scope, label: high, bytes: b"private input".to_vec().into() }), RunnerResponse::Ok));
    let RunnerResponse::Ssm { label, output, boundary_anchor, .. } = call(RunnerRequest::SsmGenerateOwned { scope, n: 8 }) else { panic!() };
    assert_eq!(label, high);
    assert_eq!(output.len(), 8);
    assert!(boundary_anchor);
    assert!(matches!(call(RunnerRequest::SsmExitOwned { scope }), RunnerResponse::Wiped(1)));
    assert!(matches!(call(RunnerRequest::SsmExitOwned { scope }), RunnerResponse::Wiped(0)));
}
