//! Independent F140 owner/provenance/lifecycle audit. Private guarded CPU arenas,
//! sockets and synthetic keys only; no installed service or enrollment is changed.
use enclave_core::error::EnclaveResult;
use enclave_core::ipc::PeerCredentials;
use enclave_core::label::Label;
use enclave_core::profile::Profile;
use enclave_model_runnerd::classes::speculative::{FixedThermal, PowerSource, ThermalState};
use enclave_model_runnerd::manifest::ExecutionClass;
use enclave_model_runnerd::service::{ResolvedWeights, RunnerConfig, RunnerRequest, RunnerResponse, RunnerService, WeightSource};

struct NoCas;
impl WeightSource for NoCas {
    fn resolve(&self, _: &str) -> EnclaveResult<ResolvedWeights> {
        Err(enclave_core::err!(EPERM, "FIXTURE_NO_CAS"))
    }
}

fn owner(version: u32) -> PeerCredentials {
    let mut peer = PeerCredentials::local(704, 704);
    peer.pid = Some(4242);
    peer.audit_token = Some([0, 704, 704, 704, 704, 4242, 100, version]);
    peer
}

fn fixture() -> (std::sync::Arc<RunnerService>, u64) {
    let runner = RunnerService::start(RunnerConfig {
        dev_same_uid: false,
        profile: Profile::L2,
        audit_path: None,
        calib_corpus_blake3: None,
        thermal: Box::new(|| Box::new(FixedThermal(ThermalState::Nominal, PowerSource::Ac))),
        actuator: None,
        state_dir: None,
    }, Box::new(NoCas)).unwrap();
    let package = enclave_model_runnerd::zoo::package(ExecutionClass::RecurrentSsmTtt).unwrap();
    runner.bind_bytes(&package.manifest_bytes(), &package.weights, None).unwrap();
    let RunnerResponse::Session(session) = runner.handle(&owner(1), RunnerRequest::SsmFork { label: Label::BOTTOM }).unwrap() else { panic!("session response required"); };
    (runner, session)
}

#[test]
fn same_pid_different_pidversion_cannot_ingest_anothers_legacy_session() {
    let (runner, session) = fixture();
    let result = runner.handle(&owner(2), RunnerRequest::SsmIngest {
        session, label: Label::TOP, bytes: b"foreign input".to_vec().into(),
    });
    assert!(result.unwrap_err().is("SSM_SESSION_OWNER_MISMATCH"));
    assert!(matches!(runner.handle(&owner(1), RunnerRequest::SsmExit { session }).unwrap(), RunnerResponse::Wiped(1)));
}

#[test]
fn same_pid_different_pidversion_cannot_generate_from_anothers_legacy_session() {
    let (runner, session) = fixture();
    let result = runner.handle(&owner(2), RunnerRequest::SsmGenerate { session, n: 1 });
    assert!(result.unwrap_err().is("SSM_SESSION_OWNER_MISMATCH"));
    assert!(matches!(runner.handle(&owner(1), RunnerRequest::SsmExit { session }).unwrap(), RunnerResponse::Wiped(1)));
}

#[test]
fn same_pid_different_pidversion_cannot_exit_anothers_legacy_session() {
    let (runner, session) = fixture();
    let result = runner.handle(&owner(2), RunnerRequest::SsmExit { session });
    assert!(result.unwrap_err().is("SSM_SESSION_OWNER_MISMATCH"));
    assert!(matches!(runner.handle(&owner(1), RunnerRequest::SsmExit { session }).unwrap(), RunnerResponse::Wiped(1)));
}

use enclave_agent_runtime::cedar_engine::CedarEngine;
use enclave_agent_runtime::registry::{digest_tools_list, ToolRegistry};
use enclave_agent_runtime::service::{CustodyPort, Declassifier, IfcConfig, IfcRequest, IfcResponse, IfcService, NoCustody, StepUp};
use enclave_agent_runtime::ssm::RemoteSsmRunner;
use enclave_core::daemon::DaemonId;
use enclave_core::ifc_envelope::{IfcEnvelopeV1, QifPool};
use enclave_core::ipc::{self, Client};
use enclave_core::label::{Conf, SlotKind, Taint};
use enclave_core::runtime::DaemonArgs;
use enclave_core::user_turn::{AttachmentRef, UserTurnV1};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::time::Duration;

#[derive(Debug)]
struct RefuseDeclassification;
impl Declassifier for RefuseDeclassification {
    fn classify(&self, _: &[u8], _: u64, _: &str, _: &enclave_core::seq::GovernedSlot) -> EnclaveResult<u64> {
        Err(enclave_core::err!(EPERM, "FIXTURE_NO_DECLASSIFICATION"))
    }
}

#[derive(Debug, Default)]
struct FixtureCustody { sequence: Mutex<u64> }
impl CustodyPort for FixtureCustody {
    fn scrub_text(&self, text: &str, _: bool) -> EnclaveResult<String> {
        Ok(enclave_core::pii::scan(text).iter().fold(text.to_owned(), |s, finding| {
            s.replace(&text[finding.start..finding.end], "[REDACTED]")
        }))
    }
    fn authorize_intent(&self, draft: &enclave_core::intent_draft::IntentDraftV1) -> EnclaveResult<StepUp> {
        NoCustody.authorize_intent(draft)
    }
    fn allocate_slot(&self) -> EnclaveResult<(String, u64)> {
        let mut sequence = self.sequence.lock().unwrap(); *sequence += 1;
        Ok(("6f1c2c1e-3a54-4b8e-9d7a-0c4f5b6a7e81".into(), *sequence))
    }
    fn boot_epoch(&self) -> EnclaveResult<enclave_core::seq::BootEpoch> {
        static KEY: std::sync::OnceLock<enclave_crypto::epoch::EpochSigner> = std::sync::OnceLock::new();
        Ok(KEY.get_or_init(enclave_crypto::epoch::EpochSigner::random).sign("6f1c2c1e-3a54-4b8e-9d7a-0c4f5b6a7e81"))
    }
}

fn retaining_package() -> enclave_model_runnerd::zoo::Packaged {
    // Clean state is negative, x makes it positive, and the partial anchor
    // retains that sign. A full alpha=1 reset would make both cases emit B.
    let mut embedding = vec![0.0; 256]; embedding[b'x' as usize] = 8.0;
    let mut output = vec![0.0; 256]; output[b'A' as usize] = 1.0; output[b'B' as usize] = -1.0;
    let weights = enclave_model_runnerd::safetensors::build_f32(&[
        ("backbone.mixer.A_log", vec![1], vec![-1.0]),
        ("enclave_adapter.ssm.embed", vec![256, 1], embedding),
        ("enclave_adapter.ssm.out", vec![1, 256], output),
        ("enclave_adapter.ssm.h_sys", vec![1], vec![-1.0]),
    ], &[]);
    let mut package = enclave_model_runnerd::zoo::package(ExecutionClass::RecurrentSsmTtt).unwrap();
    package.weights = weights;
    package.set_cas_root(&blake3::hash(&package.weights).to_hex().to_string());
    package.manifest["artifact"]["sha256"] = json!(hex::encode(Sha256::digest(&package.weights)));
    package.manifest["security_controls"]["anchor_mix_alpha"] = json!(0.5);
    package
}

fn retaining_runner() -> Arc<RunnerService> {
    let runner = RunnerService::start(RunnerConfig {
        dev_same_uid: true, profile: Profile::L2, audit_path: None,
        calib_corpus_blake3: None,
        thermal: Box::new(|| Box::new(FixedThermal(ThermalState::Nominal, PowerSource::Ac))),
        actuator: None, state_dir: None,
    }, Box::new(NoCas)).unwrap();
    let package = retaining_package();
    runner.bind_bytes(&package.manifest_bytes(), &package.weights, None).unwrap(); runner
}

struct BridgeFixture {
    directory: PathBuf,
    runtime: Arc<IfcService>,
    runner: Arc<Mutex<Arc<RunnerService>>>,
    requests: Arc<Mutex<Vec<RunnerRequest>>>,
    fail_exit_before: Arc<AtomicBool>,
    fail_exit_after: Arc<AtomicBool>,
    wrong_exit_reply: Arc<AtomicBool>,
    downgrade: Arc<AtomicBool>,
    raise_label: Arc<AtomicBool>,
    inject_pii: Arc<AtomicBool>,
    block_generation: Arc<AtomicBool>,
    generation_entered: Arc<AtomicBool>,
    generation_release: Arc<AtomicBool>,
    stopped: Arc<AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
}
impl BridgeFixture {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let directory = PathBuf::from("/tmp").join(format!("f140-audit-{:x}", enclave_core::rng::u64()));
        std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let runner = Arc::new(Mutex::new(retaining_runner()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let fail_exit_before = Arc::new(AtomicBool::new(false));
        let fail_exit_after = Arc::new(AtomicBool::new(false));
        let wrong_exit_reply = Arc::new(AtomicBool::new(false));
        let downgrade = Arc::new(AtomicBool::new(false));
        let raise_label = Arc::new(AtomicBool::new(false));
        let inject_pii = Arc::new(AtomicBool::new(false));
        let block_generation = Arc::new(AtomicBool::new(false));
        let generation_entered = Arc::new(AtomicBool::new(false));
        let generation_release = Arc::new(AtomicBool::new(false));
        let stopped = Arc::new(AtomicBool::new(false));
        let listener = ipc::bind(&directory.join(DaemonId::ModelRunner.socket_name()), ipc::SocketAccess::OwnerOnly).unwrap();
        let (current, seen, before, after, wrong, low, high, pii, stop) = (runner.clone(), requests.clone(), fail_exit_before.clone(), fail_exit_after.clone(), wrong_exit_reply.clone(), downgrade.clone(), raise_label.clone(), inject_pii.clone(), stopped.clone());
        let (block, entered, release) = (block_generation.clone(), generation_entered.clone(), generation_release.clone());
        let runner_thread = std::thread::spawn(move || ipc::serve::<RunnerRequest, RunnerResponse, _>(listener,
            ipc::PeerPolicy::allow([ipc::geteuid()]), Arc::new(move |peer: &PeerCredentials, request: RunnerRequest| {
                let exit = matches!(&request, RunnerRequest::SsmExitOwned { .. });
                seen.lock().unwrap().push(request.clone());
                if exit && before.swap(false, Ordering::SeqCst) { return Err(enclave_core::err!(EIO, "FIXTURE_EXIT_BEFORE")); }
                let service = current.lock().unwrap().clone();
                let mut result = service.handle(peer, request);
                if exit && after.swap(false, Ordering::SeqCst) { return Err(enclave_core::err!(EIO, "FIXTURE_EXIT_AFTER")); }
                if exit && wrong.swap(false, Ordering::SeqCst) { return Ok(RunnerResponse::Ok); }
                if let Ok(RunnerResponse::Ssm { label, output, .. }) = &mut result {
                    if low.swap(false, Ordering::SeqCst) { *label = Label::BOTTOM; }
                    if high.swap(false, Ordering::SeqCst) { *label = Label::TOP; }
                    if pii.swap(false, Ordering::SeqCst) { *output = b"4111 1111 1111 1111".to_vec().into(); }
                    if block.swap(false, Ordering::SeqCst) {
                        entered.store(true, Ordering::SeqCst);
                        let deadline = std::time::Instant::now() + Duration::from_secs(3);
                        while !release.load(Ordering::SeqCst) {
                            if std::time::Instant::now() >= deadline { return Err(enclave_core::err!(EIO, "FIXTURE_BLOCK_TIMEOUT")); }
                            std::thread::sleep(Duration::from_millis(2));
                        }
                    }
                }
                result
            }), stop).unwrap());
        let args = DaemonArgs::parse(vec!["fixture".into(), "--dev-same-uid".into(), "--socket-dir".into(), directory.to_string_lossy().into_owned()]).unwrap();
        let tools = json!({"tools":[{"name":"read"}]});
        let registry = ToolRegistry::load(&serde_json::to_vec(&json!({"v":1,"servers":[{
            "server":"source", "tools_list_blake3":digest_tools_list(&tools).unwrap(),
            "tools":[{"name":"read","action_class":"A1","sink_clearance":"C4","namespace":"fixture",
                "canonical_verb":"Read","slots":{},"output_conf":"C3"}]
        }]})).unwrap()).unwrap();
        let runtime = IfcService::start_with_ssm(IfcConfig {
            profile: Profile::L2, audit_path: None,
            policy_key: ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng),
            limits: Default::default(), registry,
            cedar: Some(CedarEngine::baseline_bundle().unwrap()), state_dir: None,
            socket_dir: None, dev_same_uid: true,
        }, Box::new(RefuseDeclassification), Box::new(FixtureCustody::default()), Box::new(RemoteSsmRunner::new(args))).unwrap();
        let listener = ipc::bind(&directory.join(DaemonId::AgentRuntime.socket_name()), ipc::SocketAccess::OwnerOnly).unwrap();
        let (service, stop) = (runtime.clone(), stopped.clone());
        let runtime_thread = std::thread::spawn(move || ipc::serve::<IfcRequest, IfcResponse, _>(listener,
            ipc::PeerPolicy::allow([ipc::geteuid()]), Arc::new(move |peer: &PeerCredentials, request| service.handle(peer, request)), stop).unwrap());
        Self { directory, runtime, runner, requests, fail_exit_before, fail_exit_after, wrong_exit_reply, downgrade, raise_label, inject_pii, block_generation, generation_entered, generation_release, stopped,
            threads: vec![runner_thread, runtime_thread] }
    }
    fn call(&self, request: IfcRequest) -> EnclaveResult<IfcResponse> {
        let mut client = Client::connect(&self.directory.join(DaemonId::AgentRuntime.socket_name()), ipc::geteuid())?;
        client.set_timeout(Some(Duration::from_secs(10)))?; client.call(&request)
    }
    fn begin(&self) -> String {
        let IfcResponse::TurnPlan { turn_id, .. } = self.call(IfcRequest::BeginTurn {
            turn: UserTurnV1 { directive_short: "private SSM test".into(), attachments: vec![] },
            attachments: vec![], tools: vec![], holder_pk: None, budget_mb: 0,
        }).unwrap() else { panic!("turn plan required"); }; turn_id
    }
    fn input(&self, id: &str, bytes: &[u8], conf: Conf, source: &str) -> IfcEnvelopeV1 {
        let IfcResponse::Handle(envelope) = self.call(IfcRequest::IngestTurnToolOutput {
            turn_id: id.into(), server: "source".into(), tool_name: "read".into(),
            tools_list: json!({"tools":[{"name":"read"}]}).to_string(),
            payload: bytes.to_vec().into(), conf_hint: Some(conf), source_uri: format!("fixture://{source}"),
        }).unwrap() else { panic!("handle required"); }; envelope
    }
    fn ingest(&self, id: &str, envelopes: Vec<IfcEnvelopeV1>) -> EnclaveResult<IfcResponse> {
        self.call(IfcRequest::SsmIngestTurn { turn_id: id.into(), envelopes })
    }
    fn generate(&self, id: &str) -> EnclaveResult<IfcResponse> {
        self.call(IfcRequest::SsmGenerateTurn { turn_id: id.into(), n: 1 })
    }
    fn finish(&self, id: &str) -> EnclaveResult<IfcResponse> {
        self.call(IfcRequest::FinishTurn { turn_id: id.into(), cancelled: true })
    }
    fn scope(&self) -> [u8; 32] {
        self.requests.lock().unwrap().iter().rev().find_map(|request| match request {
            RunnerRequest::SsmForkOwned { scope, .. } => Some(*scope), _ => None,
        }).unwrap()
    }
    fn assert_scope_absent(&self, scope: [u8; 32]) {
        let mut client = Client::connect(&self.directory.join(DaemonId::ModelRunner.socket_name()), ipc::geteuid()).unwrap();
        let response: RunnerResponse = client.call(&RunnerRequest::SsmExitOwned { scope }).unwrap();
        assert!(matches!(response, RunnerResponse::Wiped(0)), "scope survived cleanup: {response:?}");
    }
}
impl Drop for BridgeFixture {
    fn drop(&mut self) {
        self.generation_release.store(true, Ordering::SeqCst);
        self.stopped.store(true, Ordering::SeqCst);
        for thread in self.threads.drain(..) { thread.join().unwrap(); }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn actual_socket_bridge_retains_input_influence_and_seals_label_entities_and_turn_lifetime() {
    let fixture = BridgeFixture::new();
    for (bytes, conf, expected) in [(b"x".as_slice(), Conf::C4, b"A".as_slice()), (b"y".as_slice(), Conf::C3, b"B".as_slice())] {
        let turn = fixture.begin();
        let source = fixture.input(&turn, bytes, conf, "retaining");
        fixture.ingest(&turn, vec![source.clone()]).unwrap();
        let scope = fixture.scope();
        for _ in 0..2 {
            let IfcResponse::Handle(output) = fixture.generate(&turn).unwrap() else { panic!("opaque generated handle required"); };
            assert_eq!(output.label, Label::new(conf, Taint::T3));
            assert_eq!(fixture.runtime.payload_for_test(&output.handle).unwrap(), expected);
            assert_eq!(output.entity_keys, source.entity_keys);
            assert_eq!(output.provenance_parents, Some(vec![source.handle.clone()]));
            assert_eq!(output.qif_pool, Some(QifPool::GlobalUnstructuredC3C424hPool));
            assert_eq!(output.slot_kind, Some(SlotKind::BoundLiteral));
            assert!(output.enclave_boot_mac.is_some());
        }
        assert!(matches!(fixture.finish(&turn).unwrap(), IfcResponse::TurnFinished { released: 3 }));
        assert!(fixture.runtime.payload_for_test(&source.handle).is_err());
        fixture.assert_scope_absent(scope);
    }
}

#[test]
fn forged_and_other_turn_envelopes_are_rejected_before_runner_mutation() {
    let fixture = BridgeFixture::new();
    let first = fixture.begin(); let second = fixture.begin();
    let source = fixture.input(&first, b"x", Conf::C4, "first");
    for mutation in 0..3 {
        let mut forged = source.clone();
        match mutation { 0 => forged.label = Label::BOTTOM, 1 => forged.entity_keys.clear(), _ => forged.payload_blake3 = Some("00".repeat(32)) }
        assert!(fixture.ingest(&first, vec![forged]).is_err());
    }
    assert!(fixture.ingest(&second, vec![source.clone()]).unwrap_err().is("SSM_INPUT_NOT_TURN_OWNED"));
    assert!(fixture.requests.lock().unwrap().is_empty(), "untrusted envelope reached runner");
    fixture.ingest(&first, vec![source]).unwrap();
    let IfcResponse::Handle(output) = fixture.generate(&first).unwrap() else { panic!(); };
    assert_eq!(output.label, Label::new(Conf::C4, Taint::T3));
    fixture.finish(&first).unwrap(); fixture.finish(&second).unwrap();
}

#[test]
fn finish_failures_keep_scope_and_handles_for_retry_and_lost_ack_is_idempotent() {
    let fixture = BridgeFixture::new();
    for mode in 0..3 {
        let turn = fixture.begin(); let source = fixture.input(&turn, b"x", Conf::C4, "retry");
        fixture.ingest(&turn, vec![source.clone()]).unwrap(); let scope = fixture.scope();
        let expected = match mode {
            0 => { fixture.fail_exit_before.store(true, Ordering::SeqCst); "FIXTURE_EXIT_BEFORE" },
            1 => { fixture.fail_exit_after.store(true, Ordering::SeqCst); "FIXTURE_EXIT_AFTER" },
            _ => { fixture.wrong_exit_reply.store(true, Ordering::SeqCst); "SSM_RUNNER_PROTOCOL" },
        };
        assert!(fixture.finish(&turn).unwrap_err().is(expected));
        assert_eq!(fixture.runtime.payload_for_test(&source.handle).unwrap(), b"x");
        assert!(fixture.generate(&turn).unwrap_err().is("TURN_CLOSING"));
        assert!(matches!(fixture.finish(&turn).unwrap(), IfcResponse::TurnFinished { released: 1 }));
        assert!(fixture.runtime.payload_for_test(&source.handle).is_err()); fixture.assert_scope_absent(scope);
    }
}

#[test]
fn receiver_refuses_downgrade_and_does_not_refork_after_uncertain_or_lost_state() {
    let fixture = BridgeFixture::new();
    for restart in [false, true] {
        let turn = fixture.begin(); let source = fixture.input(&turn, b"x", Conf::C4, "uncertainty");
        fixture.ingest(&turn, vec![source]).unwrap(); let scope = fixture.scope();
        if restart { *fixture.runner.lock().unwrap() = retaining_runner(); }
        else { fixture.downgrade.store(true, Ordering::SeqCst); }
        let expected = if restart { "UNKNOWN_SESSION" } else { "SSM_LABEL_DOWNGRADE" };
        assert!(fixture.generate(&turn).unwrap_err().is(expected));
        let calls = fixture.requests.lock().unwrap().len();
        assert!(fixture.generate(&turn).unwrap_err().is("SSM_SESSION_CLOSING"));
        assert_eq!(fixture.requests.lock().unwrap().len(), calls, "uncertain session was recreated");
        fixture.finish(&turn).unwrap(); fixture.assert_scope_absent(scope);
    }
}

#[test]
fn wipe_erases_local_payload_immediately_and_preserves_failed_remote_cleanup_for_retry() {
    let fixture = BridgeFixture::new();
    let turn = fixture.begin(); let source = fixture.input(&turn, b"x", Conf::C4, "wipe");
    fixture.ingest(&turn, vec![source.clone()]).unwrap(); let scope = fixture.scope();
    fixture.fail_exit_before.store(true, Ordering::SeqCst);
    assert!(fixture.call(IfcRequest::Wipe).unwrap_err().is("FIXTURE_EXIT_BEFORE"));
    assert!(fixture.runtime.payload_for_test(&source.handle).is_err());
    assert!(fixture.generate(&turn).unwrap_err().is("SSM_CLEANUP_PENDING"));
    assert!(matches!(fixture.call(IfcRequest::Wipe).unwrap(), IfcResponse::Ok));
    fixture.assert_scope_absent(scope);
    let IfcResponse::Status(status) = fixture.call(IfcRequest::Status).unwrap() else { panic!(); };
    assert!(status.state.contains("ssm_cleanup_pending=false"));
    let fresh = fixture.begin(); fixture.finish(&fresh).unwrap();
    // Successful cleanup must preserve an independently imposed quarantine.
    fixture.runtime.set_flow_state_for_test(enclave_agent_runtime::flow_fsm::FlowState::QuarantineAbort).unwrap();
    assert!(matches!(fixture.call(IfcRequest::Wipe).unwrap(), IfcResponse::Ok));
    assert!(fixture.call(IfcRequest::BeginTurn {
        turn: UserTurnV1 { directive_short: "must remain quarantined".into(), attachments: vec![] },
        attachments: vec![], tools: vec![], holder_pk: None, budget_mb: 0,
    }).unwrap_err().is("FLOW_FSM_INVALID_TRANSITION"));
}

#[test]
fn attachment_stub_is_usable_without_any_client_supplied_label_or_raw_session() {
    let fixture = BridgeFixture::new(); let bytes = b"x";
    let IfcResponse::TurnPlan { turn_id, context, .. } = fixture.call(IfcRequest::BeginTurn {
        turn: UserTurnV1 { directive_short: "opaque attachment fixture".into(), attachments: vec![AttachmentRef {
            handle: "$paste_0".into(), label: Label::ATTACHMENT_DEFAULT,
            blake3: blake3::hash(bytes).to_hex().to_string(), kind: None,
        }] }, attachments: vec![("$paste_0".into(), bytes.to_vec().into())], tools: vec![], holder_pk: None, budget_mb: 0,
    }).unwrap() else { panic!(); };
    fixture.call(IfcRequest::SsmIngestTurnHandles { turn_id: turn_id.clone(), handles: context.attachment_stubs }).unwrap();
    let IfcResponse::Handle(output) = fixture.generate(&turn_id).unwrap() else { panic!(); };
    assert_eq!(output.label, Label::ATTACHMENT_DEFAULT);
    assert_eq!(fixture.runtime.payload_for_test(&output.handle).unwrap(), b"A");
    fixture.finish(&turn_id).unwrap();
}

#[test]
fn cumulative_ingest_joins_both_labels_and_entity_lineage_before_generation() {
    let fixture = BridgeFixture::new(); let turn = fixture.begin();
    let first = fixture.input(&turn, b"x", Conf::C3, "first-entity");
    let second = fixture.input(&turn, b"y", Conf::C4, "second-entity");
    assert_ne!(first.entity_keys, second.entity_keys);
    fixture.ingest(&turn, vec![first.clone()]).unwrap();
    fixture.ingest(&turn, vec![second.clone()]).unwrap();
    let IfcResponse::Handle(output) = fixture.generate(&turn).unwrap() else { panic!(); };
    assert_eq!(output.label, first.label.join(second.label));
    let expected: std::collections::BTreeSet<_> = first.entity_keys.iter().chain(&second.entity_keys).cloned().collect();
    assert_eq!(output.entity_keys.into_iter().collect::<std::collections::BTreeSet<_>>(), expected);
    assert_eq!(output.provenance_parents, Some(vec![first.handle, second.handle]));
    assert_eq!(fixture.runtime.payload_for_test(&output.handle).unwrap(), b"A");
    fixture.finish(&turn).unwrap();
}

#[test]
fn production_adapter_rejects_wrong_uid_before_transmitting_a_scope_or_input() {
    use enclave_agent_runtime::ssm::SsmPort;
    let fixture = BridgeFixture::new();
    assert_ne!(ipc::geteuid(), DaemonId::ModelRunner.uid(), "fixture must run outside installed model-runner account");
    let args = DaemonArgs::parse(vec!["fixture".into(), "--socket-dir".into(), fixture.directory.to_string_lossy().into_owned()]).unwrap();
    let port = RemoteSsmRunner::new(args);
    assert!(port.fork([37; 32], Label::TOP).unwrap_err().is("SERVER_UID_MISMATCH"));
    assert!(fixture.requests.lock().unwrap().is_empty());
}

#[test]
fn another_real_process_cannot_generate_or_finish_the_owners_turn() {
    let fixture = BridgeFixture::new(); let turn = fixture.begin();
    let source = fixture.input(&turn, b"x", Conf::C4, "process-owner");
    fixture.ingest(&turn, vec![source]).unwrap();
    let calls = fixture.requests.lock().unwrap().len();
    // The child supplies only wire requests. PID and Darwin audit pidversion
    // are read by the real IPC server; they are never copied from a wire field.
    let script = r#"
import os,socket,struct
def head(major,n):
    if n<24:return bytes([(major<<5)|n])
    if n<256:return bytes([(major<<5)|24,n])
    return bytes([(major<<5)|25])+struct.pack('>H',n)
def text(value):
    value=value.encode();return head(3,len(value))+value
def exact(s,n):
    result=b''
    while len(result)<n:
        more=s.recv(n-len(result));assert more;result+=more
    return result
for operation,field,value in [('SsmGenerateTurn','n',b'\x01'),('FinishTurn','cancelled',b'\xf5')]:
    body=b'\xa1'+text(operation)+b'\xa2'+text('turn_id')+text(os.environ['F140_TURN'])+text(field)+value
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.settimeout(5);s.connect(os.environ['F140_SOCKET']);s.sendall(struct.pack('>I',len(body))+body)
        n=struct.unpack('>I',exact(s,4))[0];assert n<=1048576
        reply=exact(s,n);assert b'TURN_OWNER_REJECTED' in reply,reply
"#;
    let result = std::process::Command::new("python3").arg("-c").arg(script)
        .env("F140_TURN", &turn).env("F140_SOCKET", fixture.directory.join(DaemonId::AgentRuntime.socket_name())).output().unwrap();
    assert!(result.status.success(), "child {:?}: {}", result.status.code(), String::from_utf8_lossy(&result.stderr));
    assert_eq!(fixture.requests.lock().unwrap().len(), calls);
    let IfcResponse::Handle(output) = fixture.generate(&turn).unwrap() else { panic!(); };
    assert_eq!(output.label, Label::TOP);
    fixture.finish(&turn).unwrap();
}

#[test]
fn scanner_raised_output_floor_survives_later_safe_output_without_inventing_runner_taint() {
    let fixture = BridgeFixture::new(); let turn = fixture.begin();
    let source = fixture.input(&turn, b"x", Conf::C3, "scanner-floor");
    fixture.ingest(&turn, vec![source]).unwrap();
    fixture.inject_pii.store(true, Ordering::SeqCst);
    let IfcResponse::Handle(first) = fixture.call(IfcRequest::SsmGenerateTurn { turn_id: turn.clone(), n: 32 }).unwrap() else { panic!(); };
    assert_eq!(first.label, Label::TOP);
    assert_eq!(fixture.runtime.payload_for_test(&first.handle).unwrap(), b"[REDACTED]");
    let IfcResponse::Handle(second) = fixture.generate(&turn).unwrap() else { panic!(); };
    assert_eq!(second.label, Label::TOP);
    assert!(enclave_core::pii::scan(std::str::from_utf8(&fixture.runtime.payload_for_test(&second.handle).unwrap()).unwrap()).is_empty());
    fixture.finish(&turn).unwrap();
}

#[test]
fn a_higher_runner_label_cannot_be_lowered_by_a_later_generation_response() {
    let fixture = BridgeFixture::new(); let turn = fixture.begin();
    let source = fixture.input(&turn, b"x", Conf::C3, "runner-floor");
    fixture.ingest(&turn, vec![source]).unwrap();
    fixture.raise_label.store(true, Ordering::SeqCst);
    let IfcResponse::Handle(first) = fixture.generate(&turn).unwrap() else { panic!(); };
    assert_eq!(first.label, Label::TOP);
    assert!(fixture.generate(&turn).unwrap_err().is("SSM_LABEL_DOWNGRADE"));
    fixture.finish(&turn).unwrap();
}

#[test]
fn wipe_during_real_runner_reply_erases_locally_and_prevents_late_handle_publication() {
    let fixture = BridgeFixture::new(); let turn = fixture.begin();
    let source = fixture.input(&turn, b"x", Conf::C4, "concurrent-wipe");
    fixture.ingest(&turn, vec![source.clone()]).unwrap(); let scope = fixture.scope();
    fixture.block_generation.store(true, Ordering::SeqCst);
    let (runtime_path, generation_turn) = (fixture.directory.join(DaemonId::AgentRuntime.socket_name()), turn.clone());
    let generation = std::thread::spawn(move || -> EnclaveResult<IfcResponse> {
        Client::connect(&runtime_path, ipc::geteuid())?.call(&IfcRequest::SsmGenerateTurn { turn_id: generation_turn, n: 1 })
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !fixture.generation_entered.load(Ordering::SeqCst) {
        assert!(std::time::Instant::now() < deadline, "generation did not reach real runner response");
        std::thread::sleep(Duration::from_millis(2));
    }
    let runtime_path = fixture.directory.join(DaemonId::AgentRuntime.socket_name());
    let wipe = std::thread::spawn(move || -> EnclaveResult<IfcResponse> {
        Client::connect(&runtime_path, ipc::geteuid())?.call(&IfcRequest::Wipe)
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while fixture.runtime.payload_for_test(&source.handle).is_ok() {
        assert!(std::time::Instant::now() < deadline, "wipe waited for generation before local erasure");
        std::thread::sleep(Duration::from_millis(2));
    }
    fixture.generation_release.store(true, Ordering::SeqCst);
    assert!(generation.join().unwrap().unwrap_err().is("SSM_CLEANUP_PENDING"));
    assert!(matches!(wipe.join().unwrap().unwrap(), IfcResponse::Ok));
    fixture.assert_scope_absent(scope);
    assert!(fixture.generate(&turn).unwrap_err().is("TURN_UNKNOWN"));
}
