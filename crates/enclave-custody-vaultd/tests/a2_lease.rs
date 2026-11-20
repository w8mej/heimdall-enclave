//! Track C `A2` session lease (FS-703 §3.1, §4.1): the first `A2` approval
//! takes one Touch ID and grants a 15-minute lease for its scope; repeats in
//! that scope approve without a prompt; another scope prompts; screen lock
//! revokes every lease. Each approval still carries its own bounded dispatch
//! window. Simulated factors; the physical run is the supervised ceremony.

use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

use enclave_core::ipc::PeerCredentials;
use enclave_core::profile::{ActionClass, Profile};
use enclave_custody_vaultd::biometric::{BiometricOutcome, BiometricPrompt, BiometricProvider};
use enclave_custody_vaultd::zeroizer::TamperEvent;
use enclave_custody_vaultd::service::{VaultConfig, VaultHardware, VaultRequest, VaultResponse, VaultService};

#[derive(Debug)]
struct Counting {
    inner: Box<dyn BiometricProvider + Send>,
    prompts: Arc<AtomicUsize>,
}

impl BiometricProvider for Counting {
    fn evaluate(&mut self, prompt: &BiometricPrompt) -> BiometricOutcome {
        self.prompts.fetch_add(1, Ordering::SeqCst);
        self.inner.evaluate(prompt)
    }
}

fn me() -> PeerCredentials {
    PeerCredentials::local(enclave_core::ipc::geteuid(), unsafe { libc::getegid() })
}

/// An `A2` lease request scoped to `root` (the session's root digest).
fn lease(root: u8) -> VaultRequest {
    VaultRequest::AuthorizeIntent(enclave_core::intent_draft::IntentDraftV1 {
        action_class: ActionClass::A2,
        profile: Profile::L1,
        data_class: enclave_core::label::Conf::C1,
        tool_name: "enclave://session/lease".into(),
        target_namespace: "session".into(),
        canonical_verb: "Lease".into(),
        row_count_bound: 1,
        arguments_jcs_sha256: "00".repeat(32),
        canonical_arguments_blake3: format!("{root:02x}").repeat(32),
        policy_blake3: "ef".repeat(32),
        qif_millibits_delta: 0,
        org_root_mutation: false,
    })
}

fn approved(svc: &VaultService, request: VaultRequest) {
    let response = svc.handle(&me(), request).unwrap();
    let VaultResponse::IntentAuthorizedV2(grant) = response else { panic!("approval expected: {response:?}") };
    assert!(grant.factors.iter().any(|f| f == "TouchIdCoreauthui"), "{:?}", grant.factors);
    let deadline = grant.lifetime.deadline_boot_ns.expect("every approval has a dispatch window");
    let remaining = deadline.saturating_sub(enclave_core::clock::boot_clock_ns());
    assert!(remaining > 0 && remaining <= 10_000_000_000, "window {remaining} ns");
}

#[test]
fn one_touch_id_covers_a_session_until_scope_changes_or_the_screen_locks() {
    let mut hw = VaultHardware::simulated(Profile::L1, enclave_crypto::time::now_unix()).unwrap();
    let prompts = Arc::new(AtomicUsize::new(0));
    hw.biometric = Box::new(Counting { inner: hw.biometric, prompts: prompts.clone() });
    let svc = VaultService::start(VaultConfig { profile: Profile::L1, ..Default::default() }, hw).unwrap();
    approved(&svc, lease(0xa1));
    assert_eq!(prompts.load(Ordering::SeqCst), 1, "first A2 approval prompts");
    approved(&svc, lease(0xa1));
    approved(&svc, lease(0xa1));
    assert_eq!(prompts.load(Ordering::SeqCst), 1, "the lease spares repeat prompts");
    approved(&svc, lease(0xb2));
    assert_eq!(prompts.load(Ordering::SeqCst), 2, "another session root prompts");
    let VaultResponse::Zeroized(_) = svc.handle(&me(), VaultRequest::Tamper(TamperEvent::ScreenLock)).unwrap() else {
        panic!("screen lock wipes")
    };
    approved(&svc, lease(0xa1));
    assert_eq!(prompts.load(Ordering::SeqCst), 3, "screen lock revoked the lease");
}
