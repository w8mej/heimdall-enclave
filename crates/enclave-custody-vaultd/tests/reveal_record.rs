//! Track C `A3` reveal: one record that UID 704 holds is shown only on the
//! trusted display, and only after the chained ceremony (Touch ID at `L1`)
//! approved an intent that custody built and bound to that exact value.
//! Simulated factors; the physical run is the supervised Track C ceremony.

use std::sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}};

use enclave_core::{error::EnclaveResult, ipc::PeerCredentials};
use enclave_core::profile::{ActionClass, Profile};
use enclave_core::secret::SecretBytes;
use enclave_custody_vaultd::biometric::{BiometricOutcome, BiometricPrompt, BiometricProvider};
use enclave_custody_vaultd::service::{
    HumanDisplay, RevealBytes, VaultConfig, VaultHardware, VaultRequest, VaultResponse, VaultService,
    MAX_REVEAL_BYTES, REVEAL_TOOL,
};

const SECRET: &str = "{\"priority\":\"critical\"}";

/// Counts shows and whether the single row was exactly `SECRET`; keeps no copy.
#[derive(Debug, Default)]
struct Shown {
    calls: AtomicUsize,
    exact: AtomicUsize,
}

#[derive(Debug)]
struct RecordingDisplay(Arc<Shown>);

impl HumanDisplay for RecordingDisplay {
    fn show(&mut self, values: &[SecretBytes]) -> EnclaveResult<()> {
        self.0.calls.fetch_add(1, Ordering::SeqCst);
        if values.len() == 1 && values[0].expose() == SECRET.as_bytes() {
            self.0.exact.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }
}

/// Wraps the simulated Touch ID: records each sheet's text, and can refuse.
#[derive(Debug)]
struct Sheet {
    inner: Box<dyn BiometricProvider + Send>,
    reasons: Arc<Mutex<Vec<String>>>,
    approve: bool,
}

impl BiometricProvider for Sheet {
    fn evaluate(&mut self, prompt: &BiometricPrompt) -> BiometricOutcome {
        self.reasons.lock().unwrap().push(prompt.localized_reason.clone());
        if self.approve { self.inner.evaluate(prompt) } else { BiometricOutcome::Cancelled }
    }
}

struct Rig {
    service: Arc<VaultService>,
    shown: Arc<Shown>,
    reasons: Arc<Mutex<Vec<String>>>,
}

fn rig(approve: bool) -> Rig {
    let mut hw = VaultHardware::simulated(Profile::L1, enclave_crypto::time::now_unix()).unwrap();
    let shown = Arc::new(Shown::default());
    let reasons = Arc::new(Mutex::new(Vec::new()));
    hw.display = Box::new(RecordingDisplay(shown.clone()));
    hw.biometric = Box::new(Sheet { inner: hw.biometric, reasons: reasons.clone(), approve });
    let service = VaultService::start(VaultConfig { profile: Profile::L1, ..Default::default() }, hw).unwrap();
    Rig { service, shown, reasons }
}

fn me() -> PeerCredentials {
    PeerCredentials::local(enclave_core::ipc::geteuid(), unsafe { libc::getegid() })
}

/// What UID 704 drafts; custody overrides the tool, verb and row bound.
fn draft(action: ActionClass) -> Box<enclave_core::intent_draft::IntentDraftV1> {
    Box::new(enclave_core::intent_draft::IntentDraftV1 {
        action_class: action,
        profile: Profile::L1,
        data_class: enclave_core::label::Conf::C1,
        tool_name: "depot://attacker/exfiltrate".into(),
        target_namespace: "turn".into(),
        canonical_verb: "Approve".into(),
        row_count_bound: 50,
        // UID 704 leaves the argument digests empty: custody binds the value's.
        arguments_jcs_sha256: String::new(),
        canonical_arguments_blake3: String::new(),
        policy_blake3: "ef".repeat(32),
        qif_millibits_delta: 0,
        org_root_mutation: false,
    })
}

fn reveal(value: &[u8], action: ActionClass) -> VaultRequest {
    VaultRequest::RevealRecord { value: RevealBytes(value.to_vec()), draft: draft(action) }
}

#[test]
fn l1_reveal_takes_one_touch_id_then_shows_exactly_the_value() {
    let r = rig(true);
    let response = r.service.handle(&me(), reveal(SECRET.as_bytes(), ActionClass::A3)).unwrap();
    assert!(matches!(response, VaultResponse::Delivered { rows: 1, .. }), "{response:?}");
    assert_eq!((r.shown.calls.load(Ordering::SeqCst), r.shown.exact.load(Ordering::SeqCst)), (1, 1));
    let reasons = r.reasons.lock().unwrap();
    assert_eq!(reasons.len(), 1, "exactly one Touch ID sheet");
    // The sheet text is custody's, whatever the caller drafted.
    assert!(reasons[0].starts_with(&format!("[A3] {REVEAL_TOOL} on turn (1 rows)")), "{}", reasons[0]);
    assert!(!reasons[0].contains("attacker") && !reasons[0].contains("critical"), "{}", reasons[0]);
}

#[test]
fn a_declined_touch_id_shows_nothing() {
    let r = rig(false);
    let error = r.service.handle(&me(), reveal(SECRET.as_bytes(), ActionClass::A3)).unwrap_err();
    assert_eq!(r.reasons.lock().unwrap().len(), 1, "the sheet was offered: {error}");
    assert_eq!(r.shown.calls.load(Ordering::SeqCst), 0, "declined, yet displayed: {error}");
}

#[test]
fn malformed_reveals_refuse_before_any_prompt_or_display() {
    let r = rig(true);
    let cases: [(VaultRequest, &str); 4] = [
        (reveal(SECRET.as_bytes(), ActionClass::A2), "REVEAL_ACTION_CLASS"),
        (reveal(SECRET.as_bytes(), ActionClass::A4), "REVEAL_ACTION_CLASS"),
        (reveal(b"", ActionClass::A3), "REVEAL_SIZE"),
        (reveal(&vec![b'x'; MAX_REVEAL_BYTES + 1], ActionClass::A3), "REVEAL_SIZE"),
    ];
    for (request, reason) in cases {
        let error = r.service.handle(&me(), request).unwrap_err();
        assert!(error.is(reason), "expected {reason}, got {error}");
    }
    let foreign = PeerCredentials::local(enclave_core::ipc::geteuid() + 1, 0);
    let error = r.service.handle(&foreign, reveal(SECRET.as_bytes(), ActionClass::A3)).unwrap_err();
    assert!(error.is("REVEAL_PEER_REJECTED"), "{error}");
    assert!(r.reasons.lock().unwrap().is_empty(), "no sheet for a refused request");
    assert_eq!(r.shown.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn a_reveal_request_never_prints_its_value() {
    let printed = format!("{:?}", reveal(SECRET.as_bytes(), ActionClass::A3));
    assert!(!printed.contains("critical") && printed.contains(&format!("RevealBytes({} bytes)", SECRET.len())), "{printed}");
}
