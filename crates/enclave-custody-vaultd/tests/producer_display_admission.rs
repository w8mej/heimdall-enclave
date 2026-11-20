//! Actual public display admission using existing simulated factors only.
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

use enclave_core::{error::EnclaveResult, ipc::PeerCredentials};
use enclave_core::profile::{ActionClass, Profile};
use enclave_core::secret::SecretBytes;
use enclave_custody_vaultd::biometric::{BiometricOutcome, BiometricPrompt, BiometricProvider};
use enclave_custody_vaultd::ingress::WitnessFold;
use enclave_custody_vaultd::service::{
    HumanDisplay, TokenizeItem, VaultConfig, VaultHardware, VaultRequest,
    VaultResponse, VaultService,
};

const ENTRY_LIMIT: usize = 4096;
const SYNTHETIC_EMAIL: &str = "fixture@example.com";

#[derive(Debug)]
struct RecordingDisplay {
    calls: Arc<AtomicUsize>,
    valid_single_row_batches: Arc<AtomicUsize>,
}

impl HumanDisplay for RecordingDisplay {
    fn show(&mut self, values: &[SecretBytes]) -> EnclaveResult<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if values.len() == 1 && values[0].expose() == SYNTHETIC_EMAIL.as_bytes() {
            self.valid_single_row_batches.fetch_add(1, Ordering::SeqCst);
        }
        // Retain only counters, never a plaintext copy or borrowed reference.
        Ok(())
    }
}

#[derive(Debug)]
struct CountingBiometric {
    inner: Box<dyn BiometricProvider + Send>,
    calls: Arc<AtomicUsize>,
}

impl BiometricProvider for CountingBiometric {
    fn evaluate(&mut self, prompt: &BiometricPrompt) -> BiometricOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        // Preserve the actual existing simulated signature/dwell provider.
        self.inner.evaluate(prompt)
    }
}

fn local_peer() -> PeerCredentials {
    PeerCredentials::local(enclave_core::ipc::geteuid(),unsafe{libc::getegid()})
}

fn detokenize_draft(profile: Profile) -> Box<enclave_core::intent_draft::IntentDraftV1> {
    Box::new(enclave_core::intent_draft::IntentDraftV1 {
        action_class: ActionClass::A3,
        profile,
        data_class: enclave_core::label::Conf::C3,
        tool_name: "detokenize_row".into(),
        target_namespace: "dev-billing".into(),
        canonical_verb: "Reveal".into(),
        row_count_bound: 1,
        arguments_jcs_sha256: "ab".repeat(32),
        canonical_arguments_blake3: "cd".repeat(32),
        policy_blake3: "ef".repeat(32),
        qif_millibits_delta: 0,
        org_root_mutation: false,
    })
}

fn next_slot(service: &VaultService, peer: &PeerCredentials) -> u64 {
    match service.handle(peer, VaultRequest::Status).unwrap() {
        VaultResponse::Status(status) => status.rpc_seq_u64,
        _ => panic!("actual Status response required"),
    }
}

// Fetch bounded windows through the actual public handler. Do not request one
// aggregate 4096-fold transport frame or pretend this direct API is UDS proof.
fn retained_snapshot(service: &VaultService, peer: &PeerCredentials, epoch: &str) -> Vec<WitnessFold> {
    let end = next_slot(service, peer);
    let mut folds = Vec::new();
    let mut start = 0;
    while start < end {
        let last = start.saturating_add(127).min(end - 1);
        match service.handle(peer, VaultRequest::FetchWitness {
            boot_epoch_id: epoch.to_owned(), s_start: start, s_end: last,
        }).unwrap() {
            VaultResponse::Witness { folds: batch, next_slot } => {
                assert_eq!(next_slot, end, "fixture has no concurrent writer");
                folds.extend(batch);
            }
            _ => panic!("actual FetchWitness response required"),
        }
        start = last + 1;
    }
    folds
}

fn actual_public_detokenize_display_capacity(profile: Profile) {
    let peer = local_peer();
    let display_calls = Arc::new(AtomicUsize::new(0));
    let valid_batches = Arc::new(AtomicUsize::new(0));
    let biometric_calls = Arc::new(AtomicUsize::new(0));
    let mut hardware = VaultHardware::simulated(profile, enclave_crypto::time::now_unix()).unwrap();
    hardware.display = Box::new(RecordingDisplay {
        calls: display_calls.clone(), valid_single_row_batches: valid_batches.clone(),
    });
    hardware.biometric = Box::new(CountingBiometric {
        inner: hardware.biometric, calls: biometric_calls.clone(),
    });
    let service = VaultService::start(VaultConfig {
        profile, audit_path: None, grant_key: None, state_dir: None,
        socket_dir: None, dev_same_uid: false,
    }, hardware).unwrap();
    let epoch = match service.handle(&peer, VaultRequest::BootEpoch).unwrap() {
        VaultResponse::Epoch(epoch) => epoch.boot_epoch_id,
        _ => panic!("actual BootEpoch response required"),
    };

    let surrogate = match service.handle(&peer, VaultRequest::Tokenize {
        items: vec![TokenizeItem { value: SYNTHETIC_EMAIL.into(), declared: None }],
        bulk_set: false, grant: None,
    }).unwrap() {
        VaultResponse::Tokens(tokens) => {
            assert_eq!(tokens.len(), 1);
            tokens[0].token.clone()
        }
        _ => panic!("actual Tokenize response required"),
    };
    let initial = retained_snapshot(&service, &peer, &epoch);
    assert_eq!(initial.len(), 1, "actual tokenize creates the first retained fold");

    // Positive control: the same real surrogate and supported A3 ceremony
    // decrypt to the expected synthetic value and call the actual display once.
    let prompts_before_control = biometric_calls.load(Ordering::SeqCst);
    match service.handle(&peer, VaultRequest::Detokenize {
        surrogates: vec![surrogate.clone()], draft: detokenize_draft(profile),
    }).unwrap() {
        VaultResponse::Delivered { rows, .. } => assert_eq!(rows, 1),
        _ => panic!("actual spare-capacity Detokenize must return Delivered"),
    }
    assert_eq!(display_calls.load(Ordering::SeqCst), 1);
    assert_eq!(valid_batches.load(Ordering::SeqCst), 1);
    assert_eq!(biometric_calls.load(Ordering::SeqCst), prompts_before_control + 1);
    assert_eq!(retained_snapshot(&service, &peer, &epoch).len(), 2);

    for _ in 2..ENTRY_LIMIT {
        match service.handle(&peer, VaultRequest::ScrubText {
            text: String::new(), bulk_set: false, grant: None,
        }).unwrap() {
            VaultResponse::Text(text) => assert!(text.is_empty()),
            _ => panic!("actual empty scrub response required"),
        }
    }
    let before = retained_snapshot(&service, &peer, &epoch);
    assert_eq!(before.len(), ENTRY_LIMIT, "fill the real4096-entry policy");
    assert!(before.windows(2).all(|pair| pair[0].rpc_seq_u64 < pair[1].rpc_seq_u64));
    assert!(before[1..].iter().all(|fold| fold.scrubbed.is_empty()));
    assert!(before[0] == initial[0], "original tokenize fold survives the fill");
    let candidate = next_slot(&service, &peer);
    let prompts_before_refusal = biometric_calls.load(Ordering::SeqCst);

    // Capture actual old behavior before asserting the repaired contract.
    // Old source displays a second batch, records R and evicts the oldest fold.
    let result = service.handle(&peer, VaultRequest::Detokenize {
        surrogates: vec![surrogate], draft: detokenize_draft(profile),
    });
    let named_capacity = result.as_ref().err().is_some_and(|error| error.is("WITNESS_RETENTION_CAPACITY"));
    let returned_delivered = matches!(result, Ok(VaultResponse::Delivered { rows: 1, .. }));
    let no_additional_display = display_calls.load(Ordering::SeqCst) == 1
        && valid_batches.load(Ordering::SeqCst) == 1;
    let second_ceremony_ran = biometric_calls.load(Ordering::SeqCst) == prompts_before_refusal + 1;
    let candidate_issued = next_slot(&service, &peer) == candidate + 1;
    let after = retained_snapshot(&service, &peer, &epoch);
    let all_previous_preserved = before == after;

    // Public semantic oracle for no R in this ephemeral registry. Perform it
    // after snapshot checks because a successful request reserves terminal T.
    let expected_tombstone_key = service.tombstone_public_key().unwrap();
    let tombstone = service.handle(&peer, VaultRequest::CoSignTombstone {
        slot_rpc_seq: candidate, boot_epoch_id: epoch.clone(),
    });
    let released_refusal = tombstone.as_ref().err().is_some_and(|error| error.is("TOMBSTONE_SLOT_RELEASED"));
    let no_release_record = match tombstone {
        Ok(VaultResponse::TombstoneSignature { signature, public_key }) => {
            let key: [u8; 32] = public_key.try_into().expect("actual tombstone public key");
            let signature = ed25519_dalek::Signature::from_slice(&signature).unwrap();
            key == expected_tombstone_key.to_bytes() && expected_tombstone_key
                .verify_strict(&enclave_core::audit::tombstone_message(candidate, &epoch), &signature)
                .is_ok()
        }
        _ => false,
    };
    drop(service);
    println!("WITNESS_DETOKENIZE_ADMISSION profile={profile:?} named_capacity={named_capacity} returned_delivered={returned_delivered} no_additional_display={no_additional_display} previous_preserved={all_previous_preserved} before_count={} after_count={} second_ceremony_ran={second_ceremony_ran} candidate_issued={candidate_issued} no_R={no_release_record} tombstone_released_refusal={released_refusal}", before.len(), after.len());
    assert_eq!((named_capacity, no_additional_display, all_previous_preserved,
        second_ceremony_ran, candidate_issued, no_release_record),
        (true, true, true, true, true, true),
        "Detokenize local retention refusal must precede display and egress R while preserving all previous witnesses");
}

#[test]
fn producer_actual_l1_detokenize_full_queue_refuses_before_display_and_preserves_witnesses() {
    actual_public_detokenize_display_capacity(Profile::L1);
}

#[test]
fn producer_actual_l2_detokenize_full_queue_refuses_before_display_and_preserves_witnesses() {
    actual_public_detokenize_display_capacity(Profile::L2);
}

#[test]
fn producer_actual_l3_detokenize_full_queue_refuses_before_display_and_preserves_witnesses() {
    actual_public_detokenize_display_capacity(Profile::L3);
}

const TERMINAL_T_FIXTURE_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Debug)]
struct PauseDelegatingBiometric {
    inner: Box<dyn BiometricProvider + Send>,
    armed: Arc<std::sync::atomic::AtomicBool>,
    entered: std::sync::mpsc::SyncSender<()>,
    resume: std::sync::mpsc::Receiver<()>,
    completed: Arc<AtomicUsize>,
}
impl BiometricProvider for PauseDelegatingBiometric {
    fn evaluate(&mut self, prompt: &BiometricPrompt) -> BiometricOutcome {
        if self.armed.swap(false, Ordering::SeqCst) {
            // Signal only a scheduling point. Supply no signature/factor/time.
            self.entered.try_send(()).expect("fixture pause signal");
            self.resume.recv_timeout(TERMINAL_T_FIXTURE_WAIT)
                .expect("fixture resume must precede existing ceremony budget");
        }
        let result = self.inner.evaluate(prompt);
        self.completed.fetch_add(1, Ordering::SeqCst);
        result
    }
}

// Any assertion/error unwind after spawn first releases the only artificial
// blocking gate and then joins its owned worker. All new channel waits have
// finite deadlines. Existing software ceremony runs unchanged; the retained
// external controller's command watchdog remains the hard whole-test bound.
struct TerminalTWorker {
    resume: Option<std::sync::mpsc::Sender<()>>,
    done: std::sync::mpsc::Receiver<()>,
    worker: Option<std::thread::JoinHandle<EnclaveResult<VaultResponse>>>,
}
impl TerminalTWorker {
    fn release_pause(&mut self) {
        if let Some(sender) = self.resume.take() { let _ = sender.send(()); }
    }
    fn finish(mut self) -> (bool, std::thread::Result<EnclaveResult<VaultResponse>>) {
        self.release_pause();
        let completed = self.done.recv_timeout(TERMINAL_T_FIXTURE_WAIT).is_ok();
        let joined = self.worker.take().unwrap().join();
        (completed, joined)
    }
}
impl Drop for TerminalTWorker {
    fn drop(&mut self) {
        self.release_pause();
        if let Some(worker) = self.worker.take() {
            let _ = self.done.recv_timeout(TERMINAL_T_FIXTURE_WAIT);
            let _ = worker.join();
        }
    }
}

fn terminal_t_signature_valid(
    response: EnclaveResult<VaultResponse>,
    expected: &ed25519_dalek::VerifyingKey,
    candidate: u64,
    epoch: &str,
) -> bool {
    let Ok(VaultResponse::TombstoneSignature { signature, public_key }) = response else { return false; };
    let Ok(key) = <[u8; 32]>::try_from(public_key) else { return false; };
    let Ok(signature) = ed25519_dalek::Signature::from_slice(&signature) else { return false; };
    key == expected.to_bytes() && expected.verify_strict(
        &enclave_core::audit::tombstone_message(candidate, epoch), &signature,
    ).is_ok()
}

fn actual_public_detokenize_terminal_t_before_display(profile: Profile) {
    let peer = local_peer();
    let display_calls = Arc::new(AtomicUsize::new(0));
    let valid_batches = Arc::new(AtomicUsize::new(0));
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let completed_delegations = Arc::new(AtomicUsize::new(0));
    let (entered_sender, entered) = std::sync::mpsc::sync_channel(1);
    let (resume_sender, resume) = std::sync::mpsc::channel();
    let mut hardware = VaultHardware::simulated(profile, enclave_crypto::time::now_unix()).unwrap();
    hardware.display = Box::new(RecordingDisplay {
        calls: display_calls.clone(), valid_single_row_batches: valid_batches.clone(),
    });
    hardware.biometric = Box::new(PauseDelegatingBiometric {
        inner: hardware.biometric, armed: armed.clone(), entered: entered_sender,
        resume, completed: completed_delegations.clone(),
    });
    let service = VaultService::start(VaultConfig {
        profile, audit_path: None, grant_key: None, state_dir: None,
        socket_dir: None, dev_same_uid: false,
    }, hardware).unwrap();
    let epoch = match service.handle(&peer, VaultRequest::BootEpoch).unwrap() {
        VaultResponse::Epoch(epoch) => epoch.boot_epoch_id,
        _ => panic!("actual BootEpoch required"),
    };
    let surrogate = match service.handle(&peer, VaultRequest::Tokenize {
        items: vec![TokenizeItem { value: SYNTHETIC_EMAIL.into(), declared: None }],
        bulk_set: false, grant: None,
    }).unwrap() {
        VaultResponse::Tokens(tokens) => {
            assert_eq!(tokens.len(), 1);
            tokens[0].token.clone()
        }
        _ => panic!("actual Tokenize required"),
    };

    // Spare capacity and real same-surrogate decryption/display establish a
    // meaningful positive control before the pause is armed.
    let control = service.handle(&peer, VaultRequest::Detokenize {
        surrogates: vec![surrogate.clone()], draft: detokenize_draft(profile),
    }).unwrap();
    assert!(matches!(control, VaultResponse::Delivered { rows: 1, .. }));
    assert_eq!(display_calls.load(Ordering::SeqCst), 1);
    assert_eq!(valid_batches.load(Ordering::SeqCst), 1);
    assert_eq!(completed_delegations.load(Ordering::SeqCst), 1);
    let before = retained_snapshot(&service, &peer, &epoch);
    assert_eq!(before.len(), 2, "spare-capacity control has two released witnesses");
    let candidate = next_slot(&service, &peer);
    let tombstone_key = service.tombstone_public_key().unwrap();

    armed.store(true, Ordering::SeqCst);
    let worker_service = service.clone();
    let (done_sender, done) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let result = worker_service.handle(&local_peer(), VaultRequest::Detokenize {
            surrogates: vec![surrogate], draft: detokenize_draft(profile),
        });
        let _ = done_sender.try_send(());
        result
    });
    let worker = TerminalTWorker { resume: Some(resume_sender), done, worker: Some(worker) };

    // Worker has issued its candidate but released State for the existing
    // ceremony. Main uses the actual independently authorized public T path.
    let pause_observed = entered.recv_timeout(TERMINAL_T_FIXTURE_WAIT).is_ok();
    let candidate_issued = pause_observed && next_slot(&service, &peer) == candidate + 1;
    let finalized_before_resume = candidate_issued && terminal_t_signature_valid(
        service.handle(&peer, VaultRequest::CoSignTombstone {
            slot_rpc_seq: candidate, boot_epoch_id: epoch.clone(),
        }), &tombstone_key, candidate, &epoch,
    );
    // Always unblock and join before all terminal contract assertions.
    let (completed_in_wait, joined) = worker.finish();
    let worker_joined_normally = joined.is_ok();
    let named_finalized = matches!(&joined, Ok(Err(error)) if error.is("TOMBSTONE_SLOT_FINALIZED"));
    let returned_delivered = matches!(&joined, Ok(Ok(VaultResponse::Delivered { .. })));
    let no_additional_display = display_calls.load(Ordering::SeqCst) == 1
        && valid_batches.load(Ordering::SeqCst) == 1;
    let delegated_second_completed = completed_delegations.load(Ordering::SeqCst) == 2;
    let after = retained_snapshot(&service, &peer, &epoch);
    let previous_preserved = before == after;
    // Repeated terminal T must remain legitimate after the joined request;
    // this is semantic ephemeral no-R, not disk durability/partial-fsync proof.
    let terminal_t_still_valid = terminal_t_signature_valid(
        service.handle(&peer, VaultRequest::CoSignTombstone {
            slot_rpc_seq: candidate, boot_epoch_id: epoch.clone(),
        }), &tombstone_key, candidate, &epoch,
    );
    drop(service);
    println!("DETOKENIZE_TERMINAL_T profile={profile:?} pause_observed={pause_observed} candidate_issued={candidate_issued} T_before_resume={finalized_before_resume} completed_in_wait={completed_in_wait} worker_joined_normally={worker_joined_normally} named_finalized={named_finalized} returned_delivered={returned_delivered} no_additional_display={no_additional_display} second_existing_biometric_completed={delegated_second_completed} prior_preserved={previous_preserved} T_still_valid={terminal_t_still_valid}");
    assert_eq!((pause_observed, candidate_issued, finalized_before_resume,
        completed_in_wait, worker_joined_normally, named_finalized,
        no_additional_display, delegated_second_completed, previous_preserved,
        terminal_t_still_valid), (true,true,true,true,true,true,true,true,true,true),
        "acknowledged terminal nonrelease must prevent actual later display, even when final commit already refuses R");
}

#[test]
fn producer_actual_l1_terminal_t_during_ceremony_prevents_later_display() {
    actual_public_detokenize_terminal_t_before_display(Profile::L1);
}
#[test]
fn producer_actual_l2_terminal_t_during_ceremony_prevents_later_display() {
    actual_public_detokenize_terminal_t_before_display(Profile::L2);
}
#[test]
fn producer_actual_l3_terminal_t_during_ceremony_prevents_later_display() {
    actual_public_detokenize_terminal_t_before_display(Profile::L3);
}

struct PersistenceFixtureDirectory(std::path::PathBuf);
impl PersistenceFixtureDirectory {
    fn create() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(format!(
            "mc-owned-egress-fault-{:x}", enclave_core::rng::u64(),
        ));
        // Construct ownership only after exclusive creation succeeds.
        std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for PersistenceFixtureDirectory {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

// These paths are both inside the freshly created, exclusively owned fixture.
// The original directory is moved, never deleted or rewritten by the fault.
struct OwnedEgressPathFault {
    live: std::path::PathBuf,
    moved: std::path::PathBuf,
    original_moved: bool,
    placeholder_created: bool,
}
impl OwnedEgressPathFault {
    fn new(state: &std::path::Path) -> Self {
        Self {
            live: state.join("egress"), moved: state.join("egress-owned-preserved"),
            original_moved: false, placeholder_created: false,
        }
    }
    fn install(&mut self) -> std::io::Result<()> {
        std::fs::rename(&self.live, &self.moved)?;
        self.original_moved = true;
        let placeholder = std::fs::OpenOptions::new()
            .write(true).create_new(true).open(&self.live)?;
        self.placeholder_created = true;
        drop(placeholder);
        Ok(())
    }
    fn restore(&mut self) -> std::io::Result<()> {
        if self.placeholder_created {
            std::fs::remove_file(&self.live)?;
            self.placeholder_created = false;
        }
        if self.original_moved {
            std::fs::rename(&self.moved, &self.live)?;
            self.original_moved = false;
        }
        if !self.live.is_dir() {
            return Err(std::io::Error::new(std::io::ErrorKind::Other,
                "owned egress directory was not restored"));
        }
        Ok(())
    }
}

// Own the fault and worker together: unwind cannot drop the worker's ordinary
// resume/join guard before attempting to restore its filesystem prerequisite.
struct PersistenceFaultWorker {
    worker: Option<TerminalTWorker>,
    fault: Option<OwnedEgressPathFault>,
}
impl PersistenceFaultWorker {
    fn install_fault(&mut self, state: &std::path::Path) -> std::io::Result<()> {
        // Install ownership before the first fallible path mutation.
        self.fault = Some(OwnedEgressPathFault::new(state));
        self.fault.as_mut().unwrap().install()
    }
    fn restore(&mut self) -> bool {
        self.fault.as_mut().map_or(true, |fault| fault.restore().is_ok())
    }
    fn finish(mut self) -> (bool, bool, std::thread::Result<EnclaveResult<VaultResponse>>) {
        let restored = self.restore();
        let mut worker = self.worker.take().unwrap();
        if !restored {
            // Never send a resume with the directory unrestored. Disconnect
            // the bounded artificial pause instead; its existing expect then
            // unwinds before invoking the delegated provider or display.
            drop(worker.resume.take());
        }
        let (completed, joined) = worker.finish();
        (restored, completed, joined)
    }
}
impl Drop for PersistenceFaultWorker {
    fn drop(&mut self) {
        let restored = self.restore();
        if let Some(mut worker) = self.worker.take() {
            if !restored { drop(worker.resume.take()); }
            // TerminalTWorker now resumes only after successful restoration,
            // or joins a disconnected pause without sending any resume.
            drop(worker);
        }
    }
}

fn actual_public_detokenize_after_observed_t_append_error(profile: Profile) {
    // Declaration order keeps this owned tree until service/worker teardown.
    let directory = PersistenceFixtureDirectory::create();
    let peer = local_peer();
    let display_calls = Arc::new(AtomicUsize::new(0));
    let valid_batches = Arc::new(AtomicUsize::new(0));
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let completed_delegations = Arc::new(AtomicUsize::new(0));
    let (entered_sender, entered) = std::sync::mpsc::sync_channel(1);
    let (resume_sender, resume) = std::sync::mpsc::channel();
    let mut hardware = VaultHardware::simulated(profile, enclave_crypto::time::now_unix()).unwrap();
    hardware.display = Box::new(RecordingDisplay {
        calls: display_calls.clone(), valid_single_row_batches: valid_batches.clone(),
    });
    hardware.biometric = Box::new(PauseDelegatingBiometric {
        inner: hardware.biometric, armed: armed.clone(), entered: entered_sender,
        resume, completed: completed_delegations.clone(),
    });
    let service = VaultService::start(VaultConfig {
        profile, audit_path: None, grant_key: None,
        state_dir: Some(directory.0.clone()), socket_dir: None, dev_same_uid: false,
    }, hardware).unwrap();
    let epoch = match service.handle(&peer, VaultRequest::BootEpoch).unwrap() {
        VaultResponse::Epoch(epoch) => epoch.boot_epoch_id,
        _ => panic!("actual BootEpoch required"),
    };
    let surrogate = match service.handle(&peer, VaultRequest::Tokenize {
        items: vec![TokenizeItem { value: SYNTHETIC_EMAIL.into(), declared: None }],
        bulk_set: false, grant: None,
    }).unwrap() {
        VaultResponse::Tokens(tokens) => {
            assert_eq!(tokens.len(), 1);
            tokens[0].token.clone()
        }
        _ => panic!("actual Tokenize required"),
    };
    let control = service.handle(&peer, VaultRequest::Detokenize {
        surrogates: vec![surrogate.clone()], draft: detokenize_draft(profile),
    }).unwrap();
    assert!(matches!(control, VaultResponse::Delivered { rows: 1, .. }));
    assert_eq!(display_calls.load(Ordering::SeqCst), 1);
    assert_eq!(valid_batches.load(Ordering::SeqCst), 1);
    assert_eq!(completed_delegations.load(Ordering::SeqCst), 1);
    let before = retained_snapshot(&service, &peer, &epoch);
    assert_eq!(before.len(), 2);
    let candidate = next_slot(&service, &peer);
    let log_path = directory.0.join("egress").join(format!("{epoch}.log"));

    armed.store(true, Ordering::SeqCst);
    let worker_service = service.clone();
    let (done_sender, done) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let result = worker_service.handle(&local_peer(), VaultRequest::Detokenize {
            surrogates: vec![surrogate], draft: detokenize_draft(profile),
        });
        let _ = done_sender.try_send(());
        result
    });
    let mut worker = PersistenceFaultWorker {
        worker: Some(TerminalTWorker {
            resume: Some(resume_sender), done, worker: Some(worker),
        }),
        fault: None,
    };

    let pause_observed = entered.recv_timeout(TERMINAL_T_FIXTURE_WAIT).is_ok();
    let candidate_issued = pause_observed && next_slot(&service, &peer) == candidate + 1;
    let mut pre_fault_log = Vec::new();
    let mut fault_exercised = false;
    let mut original_write_error = false;
    let mut fault_returned_no_signature = false;
    if candidate_issued {
        pre_fault_log = std::fs::read(&log_path).unwrap();
        assert!(!pre_fault_log.is_empty());
        worker.install_fault(&directory.0).unwrap();
        // This public request is nongoverned: it reaches the candidate's T
        // append directly, without an intervening I append for this request.
        let result = service.handle(&peer, VaultRequest::CoSignTombstone {
            slot_rpc_seq: candidate, boot_epoch_id: epoch.clone(),
        });
        original_write_error = matches!(&result, Err(error) if error.is("EGRESS_WRITE"));
        fault_returned_no_signature = !matches!(&result,
            Ok(VaultResponse::TombstoneSignature { .. }));
        fault_exercised = true;
    }
    // Remove the actual path fault before any resume. Current unpoisoned code
    // can append successfully again; a continuing ENOTDIR must not explain the
    // worker's later refusal. RAII does the same restore-before-resume on unwind.
    let path_restored = worker.restore();
    let pre_resume_log_preserved = path_restored && candidate_issued
        && std::fs::read(&log_path).is_ok_and(|bytes| bytes == pre_fault_log);
    let (restored_on_finish, completed_in_wait, joined) = worker.finish();
    let restored_before_resume = path_restored && restored_on_finish;
    let worker_joined_normally = joined.is_ok();
    let named_poison = matches!(&joined, Ok(Err(error)) if error.is("EGRESS_REGISTRY_POISONED"));
    let returned_delivered = matches!(&joined, Ok(Ok(VaultResponse::Delivered { .. })));
    let no_additional_display = display_calls.load(Ordering::SeqCst) == 1
        && valid_batches.load(Ordering::SeqCst) == 1;
    let delegated_second_completed = completed_delegations.load(Ordering::SeqCst) == 2;
    let after = retained_snapshot(&service, &peer, &epoch);
    let previous_preserved = before == after;
    let post_worker_log = std::fs::read(&log_path).unwrap();
    let log_preserved = candidate_issued && post_worker_log == pre_fault_log;
    let release_line = format!("R {candidate}");
    let candidate_r_present = post_worker_log.split(|byte| *byte == b'\n')
        .any(|line| line == release_line.as_bytes());

    // Actual subsequent public authority must stay closed despite restoration.
    // AllocateSlot may consume a sequencer value before I refuses; this test
    // deliberately makes no full-service sequence rollback assertion.
    let later_tombstone = service.handle(&peer, VaultRequest::CoSignTombstone {
        slot_rpc_seq: candidate, boot_epoch_id: epoch.clone(),
    });
    let later_tombstone_poisoned = matches!(&later_tombstone,
        Err(error) if error.is("EGRESS_REGISTRY_POISONED"));
    let later_no_signature = !matches!(&later_tombstone,
        Ok(VaultResponse::TombstoneSignature { .. }));
    let later_allocate_poisoned = matches!(service.handle(&peer, VaultRequest::AllocateSlot),
        Err(error) if error.is("EGRESS_REGISTRY_POISONED"));
    let log_preserved_after_authority = candidate_issued
        && std::fs::read(&log_path).unwrap() == pre_fault_log;
    drop(service);

    println!("DETOKENIZE_EGRESS_PERSISTENCE profile={profile:?} pause_observed={pause_observed} candidate_issued={candidate_issued} fault_exercised={fault_exercised} original_write_error={original_write_error} fault_no_signature={fault_returned_no_signature} restored_before_resume={restored_before_resume} pre_resume_log_preserved={pre_resume_log_preserved} completed_in_wait={completed_in_wait} worker_joined_normally={worker_joined_normally} named_poison={named_poison} returned_delivered={returned_delivered} no_additional_display={no_additional_display} second_existing_biometric_completed={delegated_second_completed} prior_preserved={previous_preserved} log_preserved={log_preserved} candidate_R_present={candidate_r_present} later_tombstone_poisoned={later_tombstone_poisoned} later_no_signature={later_no_signature} later_allocate_poisoned={later_allocate_poisoned} log_preserved_after_authority={log_preserved_after_authority}");
    assert_eq!((pause_observed, candidate_issued, fault_exercised,
        original_write_error, fault_returned_no_signature, restored_before_resume,
        pre_resume_log_preserved, completed_in_wait, worker_joined_normally,
        delegated_second_completed), (true,true,true,true,true,true,true,true,true,true),
        "owned path fault, restoration and existing ceremony must complete before contract classification");
    assert_eq!((named_poison, returned_delivered, no_additional_display,
        previous_preserved, log_preserved, candidate_r_present,
        later_tombstone_poisoned, later_no_signature, later_allocate_poisoned,
        log_preserved_after_authority), (true,false,true,true,true,false,true,true,true,true),
        "observed egress persistence error must fence later actual display and authority after the owned path is restored");
}

#[test]
fn producer_actual_l1_t_append_error_during_ceremony_fences_later_display_and_authority() {
    actual_public_detokenize_after_observed_t_append_error(Profile::L1);
}
#[test]
fn producer_actual_l2_t_append_error_during_ceremony_fences_later_display_and_authority() {
    actual_public_detokenize_after_observed_t_append_error(Profile::L2);
}
#[test]
fn producer_actual_l3_t_append_error_during_ceremony_fences_later_display_and_authority() {
    actual_public_detokenize_after_observed_t_append_error(Profile::L3);
}
