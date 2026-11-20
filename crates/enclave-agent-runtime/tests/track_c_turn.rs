//! Track C through UID 704. `A3` reveal: only a handle the calling turn owns
//! is revealed, its exact sealed bytes go to custody (UID 703) with an `A3`
//! draft, and the caller receives only the approved intent digest. `A2`
//! session lease: one `A2` draft per request, scoped to the turn, so custody's
//! lease spares repeat prompts within that turn only.
use std::path::PathBuf;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};

use enclave_agent_runtime::model_turn::{ArgSchema, ModelTurnRequest};

use enclave_agent_runtime::service::{CustodyPort, Declassifier, IfcConfig, IfcRequest, IfcResponse, IfcService, IntentLifetimeV1, StepUp};
use enclave_agent_runtime::ssm::RemoteSsmRunner;
use enclave_core::error::EnclaveResult;
use enclave_core::intent_draft::IntentDraftV1;
use enclave_core::ipc::{self, PeerCredentials};
use enclave_core::label::{Conf, Label};
use enclave_core::profile::{ActionClass, Profile};
use enclave_core::runtime::DaemonArgs;
use enclave_core::user_turn::{AttachmentRef, UserTurnV1};

const SECRET: &[u8] = b"sealed model output fixture";
/// A card number: model output carrying it is scrubbed and floored at C4.
const CARD: &[u8] = b"4111 1111 1111 1111";

/// Runner-side request shapes (decoded as UID 701 would).
#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)] // Mirrors the wire shape; the stub ignores the fields.
enum Request {
    GenerateStructured { schema: ciborium::Value, len: u32, prompt: Option<serde_bytes::ByteBuf> },
    CancelGeneration,
}

#[derive(serde::Serialize)]
enum Response {
    Text(serde_bytes::ByteBuf),
    Ok,
}

#[derive(Debug)]
struct Fixed;
impl Declassifier for Fixed {
    fn classify(&self, _: &[u8], _: u64, _: &str, _: &enclave_core::seq::GovernedSlot) -> EnclaveResult<u64> { Ok(0) }
}

/// Custody fake: records each reveal request; can refuse like a declined sheet.
/// Reveal requests custody received: (value, draft).
type Reveals = Arc<Mutex<Vec<(Vec<u8>, IntentDraftV1)>>>;

#[derive(Debug, Default)]
struct Vault {
    reveals: Reveals,
    leases: Arc<Mutex<Vec<IntentDraftV1>>>,
    decline: bool,
}

impl CustodyPort for Vault {
    fn scrub_text(&self, text: &str, _: bool) -> EnclaveResult<String> {
        Ok(enclave_core::pii::scan(text).iter().fold(text.to_owned(), |t, f| t.replace(&text[f.start..f.end], "[REDACTED]")))
    }
    fn authorize_intent(&self, draft: &IntentDraftV1) -> EnclaveResult<StepUp> {
        self.leases.lock().unwrap().push(draft.clone());
        if self.decline { enclave_core::fail!(EACCES, "TOUCH_ID_CANCELLED"); }
        let deadline = enclave_core::clock::boot_clock_ns() + 5_000_000_000;
        Ok(StepUp { d_jcs: "cd".repeat(32), factors: vec!["TouchIdCoreauthui".into()],
            lifetime: IntentLifetimeV1 { v: 1, valid_until_unix: None, deadline_boot_ns: Some(deadline) } })
    }
    fn allocate_slot(&self) -> EnclaveResult<(String, u64)> {
        Ok(("6f1c2c1e-3a54-4b8e-9d7a-0c4f5b6a7e81".into(), 1))
    }
    fn boot_epoch(&self) -> EnclaveResult<enclave_core::seq::BootEpoch> {
        Ok(enclave_crypto::epoch::EpochSigner::random().sign("6f1c2c1e-3a54-4b8e-9d7a-0c4f5b6a7e81"))
    }
    fn reveal(&self, value: &[u8], draft: &IntentDraftV1) -> EnclaveResult<String> {
        self.reveals.lock().unwrap().push((value.to_vec(), draft.clone()));
        if self.decline { enclave_core::fail!(EACCES, "TOUCH_ID_CANCELLED"); }
        Ok("ab".repeat(32))
    }
}

struct Fixture {
    dir: PathBuf,
    svc: Arc<IfcService>,
    reveals: Reveals,
    leases: Arc<Mutex<Vec<IntentDraftV1>>>,
    /// What the stub runner generates.
    output: Arc<Mutex<Vec<u8>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Fixture {
    fn new(decline: bool) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("reveal-turn-{}", enclave_core::rng::u64()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let args = DaemonArgs::parse(vec![
            "fixture".into(), "--dev-same-uid".into(), "--no-audit".into(),
            "--socket-dir".into(), dir.to_string_lossy().into_owned(),
        ]).unwrap();
        // Stub UID 701: every structured generation returns `output`.
        let listener = ipc::bind(&args.socket_path(enclave_core::daemon::DaemonId::ModelRunner), ipc::SocketAccess::OwnerOnly).unwrap();
        let output = Arc::new(Mutex::new(SECRET.to_vec()));
        let stop = Arc::new(AtomicBool::new(false));
        let (o, st) = (output.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            ipc::serve::<Request, Response, _>(listener, ipc::PeerPolicy::allow([ipc::geteuid()]), Arc::new(move |_: &PeerCredentials, r: Request| {
                Ok(match r {
                    Request::GenerateStructured { .. } => Response::Text(o.lock().unwrap().clone().into()),
                    Request::CancelGeneration => Response::Ok,
                })
            }), st).unwrap()
        });
        let cfg = IfcConfig {
            profile: Profile::L1, audit_path: None,
            policy_key: ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng), limits: Default::default(),
            registry: enclave_agent_runtime::registry::ToolRegistry::empty(),
            cedar: Some(enclave_agent_runtime::cedar_engine::CedarEngine::baseline_bundle().unwrap()),
            state_dir: None, socket_dir: None, dev_same_uid: true,
        };
        let vault = Vault { decline, ..Default::default() };
        let (reveals, leases) = (vault.reveals.clone(), vault.leases.clone());
        let svc = IfcService::start_with_ssm(cfg, Box::new(Fixed), Box::new(vault), Box::new(RemoteSsmRunner::new(args))).unwrap();
        Self { dir, svc, reveals, leases, output, stop, thread: Some(thread) }
    }

    /// Generate into a new sealed model-output handle owned by `turn`.
    fn generate(&self, turn: &str, prompt: &str, output: &[u8]) -> enclave_core::ifc_envelope::IfcEnvelopeV1 {
        *self.output.lock().unwrap() = output.to_vec();
        let request = ModelTurnRequest::Structured {
            schema: ArgSchema::Enum(vec!["routine".into()]), len: 64, prompt: Some(prompt.into()),
        };
        match self.svc.handle(&owner(), IfcRequest::ModelGenerateTurn { turn_id: turn.into(), request }).unwrap() {
            IfcResponse::Handle(env) => env,
            _ => panic!("handle expected"),
        }
    }

    /// Open a turn carrying `bytes` as its one attachment; returns (turn, handle).
    fn begin(&self, bytes: &[u8]) -> (String, String) {
        let attachment = AttachmentRef {
            handle: "$paste_0".into(), label: Label::ATTACHMENT_DEFAULT,
            blake3: blake3::hash(bytes).to_hex().to_string(), kind: None,
        };
        let turn = UserTurnV1 { directive_short: "reveal fixture".into(), attachments: vec![attachment] };
        match self.svc.handle(&owner(), IfcRequest::BeginTurn {
            turn, attachments: vec![("$paste_0".into(), bytes.to_vec().into())], tools: vec![], holder_pk: None, budget_mb: 0,
        }).unwrap() {
            IfcResponse::TurnPlan { turn_id, context, .. } => (turn_id, context.attachment_stubs[0].clone()),
            _ => panic!("turn plan expected"),
        }
    }

    fn reveal(&self, turn_id: &str, handle: &str) -> EnclaveResult<IfcResponse> {
        self.svc.handle(&owner(), IfcRequest::RevealTurnHandle { turn_id: turn_id.into(), handle: handle.into() })
    }

    fn calls(&self) -> usize { self.reveals.lock().unwrap().len() }

    fn lease(&self, turn_id: &str) -> EnclaveResult<IfcResponse> {
        self.svc.handle(&owner(), IfcRequest::BeginSessionLease { turn_id: turn_id.into() })
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() { let _ = thread.join(); }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn owner() -> PeerCredentials {
    let mut p = PeerCredentials::local(ipc::geteuid(), 0);
    p.pid = Some(4242);
    p
}

#[test]
fn a_turn_reveals_its_own_handle_and_the_caller_gets_only_the_digest() {
    let f = Fixture::new(false);
    let (turn, handle) = f.begin(SECRET);
    let response = f.reveal(&turn, &handle).unwrap();
    let IfcResponse::Revealed { d_jcs } = response else { panic!("revealed expected") };
    assert_eq!(d_jcs, "ab".repeat(32));
    let reveals = f.reveals.lock().unwrap();
    assert_eq!(reveals.len(), 1);
    let (value, draft) = &reveals[0];
    assert_eq!(value.as_slice(), SECRET, "custody receives the exact sealed bytes");
    assert_eq!((draft.action_class, draft.profile, draft.row_count_bound), (ActionClass::A3, Profile::L1, 1));
    assert_eq!(draft.data_class, Label::ATTACHMENT_DEFAULT.c);
}

#[test]
fn another_turns_handle_an_unknown_handle_or_a_finished_turn_reveal_nothing() {
    let f = Fixture::new(false);
    let (first, first_handle) = f.begin(SECRET);
    let (second, _) = f.begin(b"second turn");
    assert!(f.reveal(&second, &first_handle).is_err(), "cross-turn handle");
    assert!(f.reveal(&first, "h_unknown").is_err(), "unknown handle");
    assert!(f.reveal("t_unknown", &first_handle).is_err(), "unknown turn");
    f.svc.handle(&owner(), IfcRequest::FinishTurn { turn_id: first.clone(), cancelled: false }).unwrap();
    assert!(f.reveal(&first, &first_handle).is_err(), "finished turn");
    assert_eq!(f.calls(), 0, "nothing reached custody");
}

#[test]
fn a_declined_ceremony_is_an_error_not_a_reveal() {
    let f = Fixture::new(true);
    let (turn, handle) = f.begin(SECRET);
    let error = f.reveal(&turn, &handle).unwrap_err();
    assert!(error.is("TOUCH_ID_CANCELLED"), "{error}");
    assert_eq!(f.calls(), 1);
}

#[test]
fn sealed_model_output_is_revealed_with_its_label() {
    let f = Fixture::new(false);
    let (turn, prompt) = f.begin(b"classify this ticket");
    let env = f.generate(&turn, &prompt, SECRET);
    assert!(matches!(f.reveal(&turn, &env.handle).unwrap(), IfcResponse::Revealed { .. }));
    let reveals = f.reveals.lock().unwrap();
    assert_eq!(reveals[0].0.as_slice(), SECRET);
    assert_eq!(reveals[0].1.data_class, env.label.c, "the draft carries the handle's own label");
}

#[test]
fn c4_model_output_is_never_revealed() {
    let f = Fixture::new(false);
    let (turn, prompt) = f.begin(b"classify this ticket");
    let env = f.generate(&turn, &prompt, CARD);
    assert_eq!(env.label.c, Conf::C4, "a card number floors the output at C4");
    let error = f.reveal(&turn, &env.handle).unwrap_err();
    assert!(error.is("REVEAL_C4_REFUSED"), "{error}");
    assert_eq!(f.calls(), 0);
}

#[test]
fn a_session_lease_is_an_a2_draft_scoped_to_its_turn() {
    let f = Fixture::new(false);
    let (first, _) = f.begin(b"first");
    let (second, _) = f.begin(b"second");
    for turn in [&first, &first, &second] {
        let IfcResponse::SessionLeased { factors, .. } = f.lease(turn).unwrap() else { panic!("lease expected") };
        assert_eq!(factors, vec!["TouchIdCoreauthui".to_owned()]);
    }
    let drafts = f.leases.lock().unwrap();
    assert!(drafts.iter().all(|d| d.action_class == ActionClass::A2 && d.profile == Profile::L1
        && d.tool_name == "enclave://session/lease"));
    // Same turn, same lease scope (custody spares the prompt); another turn, another scope.
    assert_eq!(drafts[0].canonical_arguments_blake3, drafts[1].canonical_arguments_blake3);
    assert_ne!(drafts[0].canonical_arguments_blake3, drafts[2].canonical_arguments_blake3);
}

#[test]
fn no_lease_for_an_unknown_or_finished_turn_and_a_declined_lease_is_an_error() {
    let f = Fixture::new(false);
    assert!(f.lease("t_unknown").is_err());
    let (turn, _) = f.begin(b"x");
    f.svc.handle(&owner(), IfcRequest::FinishTurn { turn_id: turn.clone(), cancelled: false }).unwrap();
    assert!(f.lease(&turn).is_err());
    assert!(f.leases.lock().unwrap().is_empty(), "nothing reached custody");
    let declined = Fixture::new(true);
    let (turn, _) = declined.begin(b"x");
    assert!(declined.lease(&turn).unwrap_err().is("TOUCH_ID_CANCELLED"));
}
