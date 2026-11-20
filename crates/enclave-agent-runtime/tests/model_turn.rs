//! Turn-scoped non-session generation through the real UID 704 → 701 socket
//! adapter. All fixtures are private; no installed daemon or model is touched.
use std::path::PathBuf;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};

use enclave_agent_runtime::model_turn::{Action, ArgSchema, ModelTurnRequest, PlanInput, ResolvedTarget};
use enclave_agent_runtime::service::{CustodyPort, Declassifier, IfcConfig, IfcRequest, IfcResponse, IfcService, StepUp};
use enclave_agent_runtime::ssm::RemoteSsmRunner;
use enclave_core::error::EnclaveResult;
use enclave_core::ifc_envelope::IfcEnvelopeV1;
use enclave_core::ipc::{self, PeerCredentials};
use enclave_core::label::{Conf, Label};
use enclave_core::runtime::DaemonArgs;
use enclave_core::user_turn::{AttachmentRef, UserTurnV1};
use serde::{Deserialize, Serialize};

const SENTINEL: &[u8] = b"model-generated-sentinel";

#[derive(Debug)]
struct Fixed;
impl Declassifier for Fixed {
    fn classify(&self, _: &[u8], _: u64, _: &str, _: &enclave_core::seq::GovernedSlot) -> EnclaveResult<u64> { Ok(0) }
}

#[derive(Debug, Default)]
struct Vault(Mutex<u64>);
impl CustodyPort for Vault {
    fn scrub_text(&self, text: &str, _: bool) -> EnclaveResult<String> {
        Ok(enclave_core::pii::scan(text).iter().fold(text.to_owned(), |t, f| t.replace(&text[f.start..f.end], "[REDACTED]")))
    }
    fn authorize_intent(&self, _: &enclave_core::intent_draft::IntentDraftV1) -> EnclaveResult<StepUp> {
        Err(enclave_core::err!(EPERM, "FIXTURE_NO_HW"))
    }
    fn allocate_slot(&self) -> EnclaveResult<(String, u64)> {
        let mut n = self.0.lock().unwrap();
        *n += 1;
        Ok(("6f1c2c1e-3a54-4b8e-9d7a-0c4f5b6a7e81".into(), *n))
    }
    fn boot_epoch(&self) -> EnclaveResult<enclave_core::seq::BootEpoch> {
        Ok(enclave_crypto::epoch::EpochSigner::random().sign("6f1c2c1e-3a54-4b8e-9d7a-0c4f5b6a7e81"))
    }
}

/// Runner-side request shapes (decoded exactly as UID 701 would).
#[derive(Debug, Deserialize)]
enum Request {
    GenerateStructured { schema: ciborium::Value, len: u32, prompt: Option<serde_bytes::ByteBuf> },
    Think { prompt: serde_bytes::ByteBuf, n: u32, k: u32 },
    Plan { w: u32, h: u32, candidates: Vec<Action>, tools_mask: u64 },
    CancelGeneration,
}

#[derive(Serialize)]
enum Response {
    Text(serde_bytes::ByteBuf),
    Planned { action: Action, vetoes: u32, actuated: bool },
    Ok,
}

#[derive(Clone, Copy, Default, PartialEq)]
enum Reply { #[default] Sentinel, C4, Binary, Oversize, Wrong, Slow }

#[derive(Default)]
struct Wire { calls: usize, prompts: Vec<Vec<u8>>, reply: Reply, cancels: usize }

/// How long a `Slow` reply holds the runner call unless cancelled.
const SLOW_CALL: std::time::Duration = std::time::Duration::from_secs(10);

struct Fixture {
    dir: PathBuf,
    svc: Arc<IfcService>,
    wire: Arc<Mutex<Wire>>,
    /// Ends a `Slow` call early (set by a runner cancel or by the test).
    release: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Fixture {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("model-turn-{}", enclave_core::rng::u64()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let args = DaemonArgs::parse(vec![
            "fixture".into(), "--dev-same-uid".into(), "--no-audit".into(),
            "--socket-dir".into(), dir.to_string_lossy().into_owned(),
        ]).unwrap();
        let listener = ipc::bind(&args.socket_path(enclave_core::daemon::DaemonId::ModelRunner), ipc::SocketAccess::OwnerOnly).unwrap();
        let wire = Arc::new(Mutex::new(Wire::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let (w, st, rel) = (wire.clone(), stop.clone(), release.clone());
        let thread = std::thread::spawn(move || {
            ipc::serve::<Request, Response, _>(listener, ipc::PeerPolicy::allow([ipc::geteuid()]), Arc::new(move |_: &PeerCredentials, r: Request| {
                if matches!(r, Request::CancelGeneration) {
                    w.lock().unwrap().cancels += 1;
                    rel.store(true, Ordering::SeqCst);
                    return Ok(Response::Ok);
                }
                let mut w = w.lock().unwrap();
                w.calls += 1;
                let len = match &r {
                    Request::GenerateStructured { len, prompt, .. } => {
                        w.prompts.push(prompt.as_ref().map(|p| p.to_vec()).unwrap_or_default());
                        *len
                    }
                    Request::Think { prompt, n, .. } => { w.prompts.push(prompt.to_vec()); *n }
                    Request::Plan { candidates, .. } => {
                        return Ok(Response::Planned { action: candidates[0].clone(), vetoes: 0, actuated: false });
                    }
                    Request::CancelGeneration => unreachable!("answered above"),
                };
                if w.reply == Reply::Slow {
                    drop(w);
                    let started = std::time::Instant::now();
                    while !rel.load(Ordering::SeqCst) && started.elapsed() < SLOW_CALL {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    return Ok(Response::Text(SENTINEL.to_vec().into()));
                }
                Ok(match w.reply {
                    Reply::Sentinel => Response::Text(SENTINEL.to_vec().into()),
                    Reply::C4 => Response::Text(b"4111 1111 1111 1111".to_vec().into()),
                    Reply::Binary => Response::Text(vec![255].into()),
                    Reply::Oversize => Response::Text(vec![b'x'; 65537.max(len as usize + 1)].into()),
                    Reply::Wrong => Response::Ok,
                    Reply::Slow => unreachable!("answered above"),
                })
            }), st).unwrap()
        });
        let cfg = IfcConfig {
            profile: enclave_core::profile::Profile::L2, audit_path: None,
            policy_key: ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng), limits: Default::default(),
            registry: enclave_agent_runtime::registry::ToolRegistry::empty(),
            cedar: Some(enclave_agent_runtime::cedar_engine::CedarEngine::baseline_bundle().unwrap()),
            state_dir: None, socket_dir: None, dev_same_uid: true,
        };
        let svc = IfcService::start_with_ssm(cfg, Box::new(Fixed), Box::new(Vault::default()), Box::new(RemoteSsmRunner::new(args))).unwrap();
        Self { dir, svc, wire, release, stop, thread: Some(thread) }
    }

    fn begin(&self, bytes: &[u8]) -> (String, String) {
        let attachment = AttachmentRef {
            handle: "$paste_0".into(), label: Label::ATTACHMENT_DEFAULT,
            blake3: blake3::hash(bytes).to_hex().to_string(), kind: None,
        };
        let turn = UserTurnV1 { directive_short: "model turn fixture".into(), attachments: vec![attachment] };
        let r = self.svc.handle(&owner(), IfcRequest::BeginTurn {
            turn, attachments: vec![("$paste_0".into(), bytes.to_vec().into())], tools: vec![], holder_pk: None, budget_mb: 0,
        }).unwrap();
        match r {
            IfcResponse::TurnPlan { turn_id, context, .. } => (turn_id, context.attachment_stubs[0].clone()),
            _ => panic!("turn plan expected"),
        }
    }

    fn generate(&self, id: &str, request: ModelTurnRequest) -> EnclaveResult<IfcEnvelopeV1> {
        match self.svc.handle(&owner(), IfcRequest::ModelGenerateTurn { turn_id: id.into(), request })? {
            IfcResponse::Handle(env) => Ok(env),
            _ => panic!("handle expected"),
        }
    }

    fn finish(&self, id: &str) -> EnclaveResult<IfcResponse> {
        self.svc.handle(&owner(), IfcRequest::FinishTurn { turn_id: id.into(), cancelled: false })
    }

    fn calls(&self) -> usize { self.wire.lock().unwrap().calls }

    fn cancels(&self) -> usize { self.wire.lock().unwrap().cancels }

    /// Start a generation for `id` on another thread and wait until the
    /// runner is inside the call.
    fn generate_in_background(&self, id: &str) -> std::thread::JoinHandle<EnclaveResult<IfcResponse>> {
        let (svc, id) = (self.svc.clone(), id.to_owned());
        let before = self.calls();
        let handle = std::thread::spawn(move || svc.handle(&owner(), IfcRequest::ModelGenerateTurn { turn_id: id, request: structured(None) }));
        let started = std::time::Instant::now();
        while self.calls() == before {
            assert!(started.elapsed() < std::time::Duration::from_secs(5), "runner call never started");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        handle
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn owner() -> PeerCredentials {
    let mut p = PeerCredentials::local(ipc::geteuid(), 0);
    p.pid = Some(4242);
    p
}

fn structured(prompt: Option<String>) -> ModelTurnRequest {
    ModelTurnRequest::Structured { schema: ArgSchema::Enum(vec!["routine".into()]), len: 64, prompt }
}

fn sample_plan() -> PlanInput {
    let target = ResolvedTarget {
        app_bundle_id: "org.example.browser".into(), ax_role: "AXButton".into(), ax_title: "Continue".into(),
        url_origin: "https://owned.invalid".into(), dom_selector: "#owned".into(),
    };
    PlanInput {
        w: 8, h: 8, px: vec![91; 64].into(), goal_px: vec![64; 64].into(), pii_boxes: vec![], scroll_velocity: 0,
        candidates: vec![Action { tool_id: 1, target, params_q: vec![0] }], tools_mask: 2,
        origins: vec!["https://owned.invalid".into()],
    }
}

#[test]
fn structured_output_is_sealed_with_prompt_provenance_and_never_returned_as_text() {
    let f = Fixture::new();
    let (id, h) = f.begin(b"trusted prompt attachment");
    let env = f.generate(&id, structured(Some(h.clone()))).unwrap();
    assert_eq!(f.svc.payload_for_test(&env.handle).unwrap(), SENTINEL);
    assert_eq!(env.provenance_parents, Some(vec![h]));
    assert!(Label::ATTACHMENT_DEFAULT.leq(env.label));
    let mut wire = Vec::new();
    ciborium::into_writer(&IfcResponse::Handle(env.clone()), &mut wire).unwrap();
    assert!(!wire.windows(SENTINEL.len()).any(|w| w == SENTINEL));
    assert_eq!(f.wire.lock().unwrap().prompts[0], b"trusted prompt attachment");
    f.finish(&id).unwrap();
    assert!(f.svc.payload_for_test(&env.handle).is_err());
}

#[test]
fn foreign_prompt_handle_is_refused_before_any_runner_call() {
    let f = Fixture::new();
    let (id, _) = f.begin(b"first owner");
    let (other, foreign) = f.begin(b"foreign owner");
    assert!(f.generate(&id, structured(Some(foreign))).is_err());
    assert!(f.generate(&id, structured(Some("not-a-handle".into()))).is_err());
    assert_eq!(f.calls(), 0);
    f.finish(&id).unwrap();
    f.finish(&other).unwrap();
}

#[test]
fn out_of_bounds_request_is_refused_before_any_runner_call() {
    let f = Fixture::new();
    let (id, h) = f.begin(b"prompt");
    let think = ModelTurnRequest::Think { prompt: h, n: 0, k: 4 };
    assert!(f.generate(&id, think).unwrap_err().is("MODEL_TURN_OUTPUT_BOUNDS"));
    assert_eq!(f.calls(), 0);
    f.finish(&id).unwrap();
}

#[test]
fn oversized_prompt_is_refused_before_any_runner_call() {
    let f = Fixture::new();
    let (id, h) = f.begin(&vec![b'a'; 250 * 1024 + 1]);
    assert!(f.generate(&id, structured(Some(h))).unwrap_err().is("MODEL_TURN_INPUT_BOUNDS"));
    assert_eq!(f.calls(), 0);
    f.finish(&id).unwrap();
}

#[test]
fn finished_turn_cannot_generate() {
    let f = Fixture::new();
    let (id, _) = f.begin(b"prompt");
    f.finish(&id).unwrap();
    assert!(f.generate(&id, structured(None)).is_err());
    assert_eq!(f.calls(), 0);
}

#[test]
fn c4_output_is_raised_and_scrubbed_before_sealing() {
    let f = Fixture::new();
    let (id, h) = f.begin(b"prompt");
    f.wire.lock().unwrap().reply = Reply::C4;
    let env = f.generate(&id, ModelTurnRequest::Think { prompt: h, n: 64, k: 4 }).unwrap();
    assert_eq!(env.label.c, Conf::C4);
    let sealed = f.svc.payload_for_test(&env.handle).unwrap();
    assert!(!sealed.windows(4).any(|w| w == b"4111"));
    f.finish(&id).unwrap();
}

#[test]
fn binary_oversize_and_wrong_replies_fail_closed() {
    for reply in [Reply::Binary, Reply::Oversize, Reply::Wrong] {
        let f = Fixture::new();
        let (id, _) = f.begin(b"prompt");
        f.wire.lock().unwrap().reply = reply;
        assert!(f.generate(&id, structured(None)).is_err());
        f.finish(&id).unwrap();
    }
}

#[test]
fn plan_seals_only_the_action_summary() {
    let f = Fixture::new();
    let (id, _) = f.begin(b"prompt");
    let env = f.generate(&id, ModelTurnRequest::Plan(sample_plan())).unwrap();
    let sealed: serde_json::Value = serde_json::from_slice(&f.svc.payload_for_test(&env.handle).unwrap()).unwrap();
    assert_eq!(sealed["origin"], "https://owned.invalid");
    assert_eq!(sealed["actuated"], false);
    assert!(env.provenance_parents.as_ref().is_none_or(|p| p.is_empty()));
    f.finish(&id).unwrap();
}

/// Cancelling a turn stops its in-flight runner call instead of waiting it
/// out, and the late result is never sealed into the finished turn.
#[test]
fn cancelling_a_turn_stops_its_inflight_generation_promptly() {
    let f = Fixture::new();
    f.wire.lock().unwrap().reply = Reply::Slow;
    let (id, _) = f.begin(b"prompt");
    let generation = f.generate_in_background(&id);
    let started = std::time::Instant::now();
    let finished = f.svc.handle(&owner(), IfcRequest::FinishTurn { turn_id: id.clone(), cancelled: true });
    assert!(matches!(finished, Ok(IfcResponse::TurnFinished { .. })), "{finished:?}");
    assert!(started.elapsed() < SLOW_CALL / 4, "finish waited {:?} for the runner call", started.elapsed());
    assert_eq!(f.cancels(), 1);
    assert!(generation.join().unwrap().is_err(), "a cancelled turn's result is never sealed");
}

/// Finishing one turn never cancels another turn's generation.
#[test]
fn finishing_another_turn_leaves_the_running_generation_alone() {
    let f = Fixture::new();
    f.wire.lock().unwrap().reply = Reply::Slow;
    let (running, _) = f.begin(b"running");
    let (other, _) = f.begin(b"other");
    let generation = f.generate_in_background(&running);
    let svc = f.svc.clone();
    let finish = std::thread::spawn(move || svc.handle(&owner(), IfcRequest::FinishTurn { turn_id: other, cancelled: true }));
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert_eq!(f.cancels(), 0);
    f.release.store(true, Ordering::SeqCst);
    assert!(matches!(generation.join().unwrap(), Ok(IfcResponse::Handle(_))));
    assert!(matches!(finish.join().unwrap(), Ok(IfcResponse::TurnFinished { .. })));
    assert_eq!(f.cancels(), 0);
}
