//! Local fence/debt regressions with real signed-epoch/journal/proof dispatch.
//! Same-UID test peers provide no installed or hardware identity authority.
use super::*;
use enclave_core::poseidon2::Poseidon2Sponge;
use enclave_core::quarantine_types::FaultKind;
use std::os::unix::fs::DirBuilderExt;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::time::{Duration, Instant};

#[path = "../tests/support/relay_peer.rs"]
mod relay_peer;

const WAIT: Duration = Duration::from_secs(15);

struct Pause { entered: SyncSender<()>, resume: Receiver<()> }
impl Pause {
    fn wait(self) {
        self.entered.send(()).unwrap();
        self.resume.recv_timeout(WAIT).unwrap();
    }
}
fn pause() -> (Pause, Receiver<()>, SyncSender<()>) {
    let (entered, observed) = mpsc::sync_channel(1);
    let (resume, resumed) = mpsc::sync_channel(1);
    (Pause { entered, resume: resumed }, observed, resume)
}

struct TestPeers {
    epoch: enclave_core::seq::BootEpoch,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    prepare_pause: Mutex<Option<Pause>>,
    fetch_pause: Mutex<Option<Pause>>,
    ack_pause: Mutex<Option<Pause>>,
    close_reply: AtomicBool,
}
struct Peer(Arc<TestPeers>);
impl Peers for Peer {
    fn cosign(&self, _: DaemonId, _: u64, _: &str) -> EnclaveResult<(Vec<u8>, Vec<u8>)> {
        panic!("a genuine streamed released slot must not be replaced with a tombstone")
    }
    fn prepare_relay(&self, frame: &[u8]) -> EnclaveResult<enclave_core::ipc::PreparedCall> {
        let received = self.0.received.clone();
        let ack_pause = self.0.ack_pause.lock().unwrap().take();
        let close = self.0.close_reply.load(Ordering::SeqCst);
        let prepared = relay_peer::prepare_with_reply(frame, move |bytes| {
            received.lock().unwrap().push(bytes);
            if let Some(pause) = ack_pause { pause.wait(); }
            if close { relay_peer::ReplyAction::Close } else { relay_peer::ReplyAction::Queued }
        })?;
        if let Some(pause) = self.0.prepare_pause.lock().unwrap().take() { pause.wait(); }
        Ok(prepared)
    }
    fn fetch_witness(&self, _: &str, _: u64, _: u64) -> EnclaveResult<(Vec<WitnessFold>, u64)> {
        // The actual proof must clone its witness from the service-owned cache.
        // Fixture-only pause after prove captured its entering chain state and
        // before it later snapshots the remaining proving context.
        if let Some(pause) = self.0.fetch_pause.lock().unwrap().take() { pause.wait(); }
        Ok((Vec::new(), 2))
    }
    fn boot_epoch(&self) -> EnclaveResult<enclave_core::seq::BootEpoch> {
        Ok(self.0.epoch.clone())
    }
}

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}
struct Fixture {
    directory: Directory,
    config: ZkConfig,
    service: Arc<ZkService>,
    peers: Arc<TestPeers>,
    epoch: String,
}
fn root() -> PeerCredentials { PeerCredentials::local(0, 0) }
fn unauthorized() -> PeerCredentials {
    PeerCredentials::local(if enclave_core::ipc::geteuid() == 703 { 704 } else { 703 }, 0)
}
fn fold() -> WitnessFold {
    // Match actual witness construction used by existing witness_soundness.
    let mut nonce = [0u8; 32];
    enclave_core::rng::fill(&mut nonce);
    let mut raw = Poseidon2Sponge::new();
    raw.absorb_bytes(b"depot-C_raw-v1", b"person@example.test");
    raw.absorb_bytes(b"depot-C_raw-blind-v1", &nonce);
    let raw = raw.finalize();
    let mut mac = Poseidon2Sponge::new();
    mac.absorb_bytes(b"depot-IngressMac-v1", &[99; 32]);
    mac.absorb_u64(1);
    for limb in raw.0 { mac.absorb_u32(limb); }
    WitnessFold { rpc_seq_u64: 1, scrubbed: b"[REDACTED_EMAIL]".to_vec(),
        c_raw: raw.to_hex(), h_ingress_mac: mac.finalize().to_hex() }
}
impl Fixture {
    fn new() -> Self {
        let base = std::env::temp_dir();
        let directory = Directory(base.canonicalize().unwrap()
            .join(format!("proof-fence-{:x}", enclave_core::rng::u64())));
        std::fs::DirBuilder::new().mode(0o700).create(&directory.0).unwrap();
        let epoch = enclave_core::seq::new_boot_epoch_id();
        let daemon = DaemonId::CustodyVault;
        let path = directory.0.join("logs").join(daemon.dir_name())
            .join(format!("{}-audit.jsonl", daemon.plist_suffix()));
        AuditJournal::open(&path, daemon, enclave_core::seq::new_boot_epoch_id()).unwrap()
            .append_at(&epoch, 1, json!({"event":"SCRUB_TEXT", "slot":1})).unwrap();
        let signer = enclave_crypto::epoch::EpochSigner::random();
        let peers = Arc::new(TestPeers { epoch: signer.sign(&epoch),
            received: Arc::new(Mutex::new(Vec::new())), prepare_pause: Mutex::new(None),
            fetch_pause: Mutex::new(None), ack_pause: Mutex::new(None),
            close_reply: AtomicBool::new(false) });
        let mut config = ZkConfig::new(Profile::L2, directory.0.join("state"));
        config.audit_path = Some(directory.0.join("auditor.jsonl"));
        config.journal_dir = Some(directory.0.join("logs"));
        config.hardware_batch_anchor_sigs = Some(vec!["3045".into()]);
        config.entity = "local-fence-fixture".into();
        config.id_enclave = [7; 32];
        let service = ZkService::start(config.clone(), Box::new(Peer(peers.clone()))).unwrap();
        service.ingest_witnesses(&epoch, vec![fold()]).unwrap();
        Self { directory, config, service, peers, epoch }
    }
    // A restart must end the old owner before opening persistent state.
    fn restart(self) -> Self {
        let Self { directory, config, service, peers, epoch } = self;
        assert_eq!(Arc::strong_count(&service), 1, "restart requires joined service workers");
        drop(service);
        let service = ZkService::start(config.clone(), Box::new(Peer(peers.clone()))).unwrap();
        Self { directory, config, service, peers, epoch }
    }
    fn request(&self) -> ZkRequest {
        ZkRequest::ProveEpoch(Box::new(ProveEpochRequest {
            boot_epoch_id: self.epoch.clone(), s_start: 1, s_end: 1,
        }))
    }
    fn worker(&self) -> std::thread::JoinHandle<EnclaveResult<ZkResponse>> {
        let service = self.service.clone(); let request = self.request();
        std::thread::spawn(move || service.handle(&root(), request))
    }
    fn assert_uncommitted(&self) {
        let state = self.service.lock().unwrap();
        assert_eq!(state.j_state, genesis());
        assert!(!state.proven.contains_key(&self.epoch));
        assert!(state.anchors.is_empty());
    }
    fn assert_no_success_event(&self) {
        let journal = match std::fs::read_to_string(self.directory.0.join("auditor.jsonl")) {
            Ok(journal) => journal,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => panic!("reading owned auditor fixture: {error}"),
        };
        assert!(!journal.contains("ROLLUP_PROVEN"));
        assert!(!journal.contains("HEARTBEAT_PROVEN"));
    }
    fn assert_debt(&self) {
        assert!(self.service.relay_failed.load(Ordering::SeqCst));
        let bytes = std::fs::read(&self.service.relay_debt_path).unwrap();
        assert!(!bytes.is_empty());
        assert!(!String::from_utf8_lossy(&bytes).contains("[REDACTED_EMAIL]"));
    }
}

#[test]
fn release_prepared_real_proof_wipe_refuses_old_frame_and_fresh_reingress_succeeds() {
    let fixture = Fixture::new();
    let (pause, entered, resume) = pause();
    *fixture.peers.prepare_pause.lock().unwrap() = Some(pause);
    let worker = fixture.worker(); entered.recv_timeout(WAIT).unwrap();
    fixture.assert_uncommitted();
    for _ in 0..2 { fixture.service.handle(&root(), ZkRequest::Wipe).unwrap(); }
    assert!(fixture.service.lock().unwrap().streamed_witnesses.is_empty());
    resume.send(()).unwrap();
    assert!(worker.join().unwrap().unwrap_err().is("PROOF_RELEASE_FENCED"));
    assert!(fixture.peers.received.lock().unwrap().is_empty());
    fixture.assert_uncommitted(); fixture.assert_no_success_event();
    assert!(!fixture.service.relay_debt_path.exists());
    assert!(!fixture.service.relay_failed.load(Ordering::SeqCst));
    fixture.service.ingest_witnesses(&fixture.epoch, vec![fold()]).unwrap();
    let ZkResponse::Proven { frames, relayed, .. } = fixture.service.handle(&root(), fixture.request()).unwrap()
        else { panic!("missing genuine fresh proof response") };
    assert!(relayed); assert_eq!(frames.len(), 1);
    assert_eq!(fixture.peers.received.lock().unwrap().len(), 1);
    assert_eq!(fixture.service.lock().unwrap().proven[&fixture.epoch], 1);
}

#[test]
fn release_prepared_real_proof_latched_fault_refuses_without_progress() {
    let fixture = Fixture::new(); let (pause, entered, resume) = pause();
    *fixture.peers.prepare_pause.lock().unwrap() = Some(pause);
    let worker = fixture.worker(); entered.recv_timeout(WAIT).unwrap();
    for at_ms in [1000, 2000] {
        fixture.service.handle(&root(), ZkRequest::ReportFault(FaultReport {
            kind: FaultKind::HeapTag, fault_addr: 0x10000, at_ms,
        })).unwrap();
    }
    assert!(fixture.service.lock().unwrap().quarantine.is_latched());
    resume.send(()).unwrap();
    assert!(worker.join().unwrap().unwrap_err().is("PROOF_RELEASE_FENCED"));
    assert!(fixture.peers.received.lock().unwrap().is_empty());
    fixture.assert_uncommitted(); fixture.assert_no_success_event();
}

#[test]
fn release_fault_persistence_failure_fences_and_keeps_admission_failed() {
    let fixture = Fixture::new(); let (pause, entered, resume) = pause();
    *fixture.peers.prepare_pause.lock().unwrap() = Some(pause);
    let worker = fixture.worker(); entered.recv_timeout(WAIT).unwrap();
    let sealed = fixture.config.quarantine_dir.join("quarantine.sealed");
    std::fs::remove_file(&sealed).unwrap(); std::fs::create_dir(&sealed).unwrap();
    assert!(fixture.service.handle(&root(), ZkRequest::ReportFault(FaultReport {
        kind: FaultKind::HeapTag, fault_addr: 0x10000, at_ms: 1000,
    })).is_err());
    resume.send(()).unwrap();
    assert!(worker.join().unwrap().unwrap_err().is("PROOF_RELEASE_FENCED"));
    assert!(fixture.peers.received.lock().unwrap().is_empty());
    assert!(fixture.service.relay_failed.load(Ordering::SeqCst));
    assert!(fixture.service.lock().unwrap().streamed_witnesses.is_empty());
    fixture.assert_uncommitted(); fixture.assert_no_success_event();
    assert!(fixture.service.handle(&root(), fixture.request()).unwrap_err().is("PROOF_DELIVERY_UNCERTAIN"));
}

#[test]
fn release_unauthorized_wipe_and_fault_do_not_cancel_legitimate_proof() {
    let fixture = Fixture::new(); let (pause, entered, resume) = pause();
    *fixture.peers.prepare_pause.lock().unwrap() = Some(pause);
    let worker = fixture.worker(); entered.recv_timeout(WAIT).unwrap();
    let generation = fixture.service.release_generation.load(Ordering::SeqCst);
    assert!(fixture.service.handle(&unauthorized(), ZkRequest::Wipe).unwrap_err().is("WIPE_PEER_REJECTED"));
    assert!(fixture.service.handle(&unauthorized(), ZkRequest::ReportFault(FaultReport {
        kind: FaultKind::HeapTag, fault_addr: 0x10000, at_ms: 1000,
    })).unwrap_err().is("FAULT_REPORTER_REJECTED"));
    assert_eq!(fixture.service.release_generation.load(Ordering::SeqCst), generation);
    assert!(!fixture.service.lock().unwrap().streamed_witnesses.is_empty());
    resume.send(()).unwrap();
    assert!(matches!(worker.join().unwrap().unwrap(), ZkResponse::Proven { relayed: true, .. }));
    assert_eq!(fixture.peers.received.lock().unwrap().len(), 1);
}

#[test]
fn release_concurrent_prove_and_heartbeat_are_busy_while_status_remains_available() {
    let fixture = Fixture::new(); let (pause, entered, resume) = pause();
    *fixture.peers.prepare_pause.lock().unwrap() = Some(pause);
    let worker = fixture.worker(); entered.recv_timeout(WAIT).unwrap();
    assert!(fixture.service.handle(&root(), fixture.request()).unwrap_err().is("PROOF_OPERATION_BUSY"));
    assert!(fixture.service.handle(&root(), ZkRequest::Heartbeat).unwrap_err().is("PROOF_OPERATION_BUSY"));
    assert!(matches!(fixture.service.handle(&root(), ZkRequest::Status).unwrap(), ZkResponse::Status(_)));
    resume.send(()).unwrap(); assert!(worker.join().unwrap().is_ok());
    assert_eq!(fixture.peers.received.lock().unwrap().len(), 1);
}

#[test]
fn release_completed_write_late_ack_after_wipe_preserves_uncertain_debt_and_restart_block() {
    let fixture = Fixture::new(); let (pause, entered, resume) = pause();
    *fixture.peers.ack_pause.lock().unwrap() = Some(pause);
    let worker = fixture.worker(); entered.recv_timeout(WAIT).unwrap();
    assert_eq!(fixture.peers.received.lock().unwrap().len(), 1);
    assert!(fixture.service.release_serial.try_lock().is_ok(), "reply wait held release serial");
    fixture.service.handle(&root(), ZkRequest::Wipe).unwrap();
    resume.send(()).unwrap();
    assert!(worker.join().unwrap().unwrap_err().is("PROOF_RELEASE_FENCED"));
    // The receiver already owns this valid pre-fence request. Conservative
    // debt blocks automatic retry; this test does not claim revocation.
    assert_eq!(fixture.peers.received.lock().unwrap().len(), 1);
    fixture.assert_uncommitted(); fixture.assert_no_success_event(); fixture.assert_debt();
    fixture.service.handle(&root(), ZkRequest::Wipe).unwrap();
    fixture.service.ingest_witnesses(&fixture.epoch, vec![fold()]).unwrap();
    assert!(fixture.service.handle(&root(), fixture.request()).unwrap_err().is("PROOF_DELIVERY_UNCERTAIN"));
    let fixture = fixture.restart();
    assert!(fixture.service.handle(&root(), fixture.request()).unwrap_err().is("PROOF_DELIVERY_UNCERTAIN"));
}

#[test]
fn release_lost_queued_reply_never_advances_or_retries_and_debt_survives_restart() {
    let fixture = Fixture::new(); fixture.peers.close_reply.store(true, Ordering::SeqCst);
    assert!(fixture.service.handle(&root(), fixture.request()).is_err());
    assert_eq!(fixture.peers.received.lock().unwrap().len(), 1);
    fixture.assert_uncommitted(); fixture.assert_no_success_event(); fixture.assert_debt();
    fixture.peers.close_reply.store(false, Ordering::SeqCst);
    assert!(fixture.service.handle(&root(), fixture.request()).unwrap_err().is("PROOF_DELIVERY_UNCERTAIN"));
    assert_eq!(fixture.peers.received.lock().unwrap().len(), 1);
    let fixture = fixture.restart();
    assert!(fixture.service.handle(&root(), fixture.request()).unwrap_err().is("PROOF_DELIVERY_UNCERTAIN"));
}

#[test]
fn release_pending_fence_count_remains_until_both_state_cleanups_finish() {
    let fixture = Fixture::new();
    let state = fixture.service.lock().unwrap();
    let mut workers = Vec::new();
    for expected in 1..=2 {
        let service = fixture.service.clone();
        workers.push(std::thread::spawn(move || service.handle(&root(), ZkRequest::Wipe)));
        let deadline = Instant::now() + WAIT;
        while fixture.service.release_generation.load(Ordering::SeqCst) != expected {
            assert!(Instant::now() < deadline, "fence did not advance before State cleanup");
            std::thread::yield_now();
        }
        assert_eq!(fixture.service.fence_pending.load(Ordering::SeqCst), expected);
        assert!(fixture.service.check_release(expected).unwrap_err().is("PROOF_RELEASE_FENCED"));
    }
    drop(state);
    for worker in workers { worker.join().unwrap().unwrap(); }
    assert_eq!(fixture.service.fence_pending.load(Ordering::SeqCst), 0);
    fixture.service.check_release(2).unwrap();
    assert!(fixture.service.check_release(0).unwrap_err().is("PROOF_RELEASE_FENCED"));
}

#[test]
fn release_generation_exhaustion_refuses_without_reusing_old_token() {
    let fixture = Fixture::new();
    fixture.service.release_generation.store(u64::MAX, Ordering::SeqCst);
    assert!(fixture.service.handle(&root(), ZkRequest::Wipe).unwrap_err().is("PROOF_GENERATION_EXHAUSTED"));
    assert_eq!(fixture.service.release_generation.load(Ordering::SeqCst), u64::MAX);
    assert!(fixture.service.relay_failed.load(Ordering::SeqCst));
    assert_eq!(fixture.service.fence_pending.load(Ordering::SeqCst), 0);
    assert!(fixture.service.check_release(u64::MAX).unwrap_err().is("PROOF_DELIVERY_UNCERTAIN"));
}

#[test]
fn release_pending_fence_count_exhaustion_never_wraps_into_admission() {
    let fixture = Fixture::new();
    fixture.service.fence_pending.store(u64::MAX, Ordering::SeqCst);
    assert!(fixture.service.handle(&root(), ZkRequest::Wipe).unwrap_err().is("PROOF_FENCE_COUNT_EXHAUSTED"));
    assert_eq!(fixture.service.fence_pending.load(Ordering::SeqCst), u64::MAX);
    assert_eq!(fixture.service.release_generation.load(Ordering::SeqCst), 0);
    assert!(fixture.service.relay_failed.load(Ordering::SeqCst));
    assert!(fixture.service.check_release(0).unwrap_err().is("PROOF_RELEASE_FENCED"));
}

#[test]
fn release_restart_observes_regular_symlink_fifo_directory_debt_without_consuming_it() {
    use std::os::unix::{ffi::OsStrExt, fs::symlink};
    for kind in ["regular", "dangling_symlink", "live_symlink", "fifo", "directory"] {
        let fixture = Fixture::new();
        let marker = fixture.service.relay_debt_path.clone();
        let target = fixture.directory.0.join("unrelated-evidence");
        match kind {
            "regular" => std::fs::write(&marker, b"uncertain proof intent\n").unwrap(),
            "dangling_symlink" => symlink(&target, &marker).unwrap(),
            "live_symlink" => {
                std::fs::write(&target, b"preserve this evidence\n").unwrap();
                symlink(&target, &marker).unwrap();
            }
            "fifo" => {
                let path = std::ffi::CString::new(marker.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
            "directory" => std::fs::create_dir(&marker).unwrap(),
            _ => unreachable!(),
        }
        let fixture = fixture.restart();
        assert!(fixture.service.handle(&root(), fixture.request()).unwrap_err().is("PROOF_DELIVERY_UNCERTAIN"), "{kind}");
        let metadata = std::fs::symlink_metadata(&marker).unwrap();
        if kind.ends_with("symlink") { assert!(metadata.file_type().is_symlink()); }
        if kind == "dangling_symlink" { assert!(!target.exists()); }
        if kind == "live_symlink" { assert_eq!(std::fs::read(&target).unwrap(), b"preserve this evidence\n"); }
        assert!(fixture.peers.received.lock().unwrap().is_empty());
    }
}

#[test]
fn release_prepared_real_l3_heartbeat_wipe_refuses_old_frame_and_fresh_heartbeat_succeeds() {
    let mut fixture = Fixture::new();
    let keys: Vec<_> = (0..32).map(|index| (
        format!("fixture-sep-{index}").into_bytes(), format!("fixture-yk-{index}").into_bytes(),
    )).collect();
    let tree = crate::cohort::CohortTree::build(keys.iter()
        .map(|(sep, yk)| crate::cohort::leaf(sep, yk)).collect()).unwrap();
    fixture.config.profile = Profile::L3;
    fixture.config.hardware_batch_anchor_sigs = None;
    fixture.config.hardware = Some(HardwareWitness { pk_sep: keys[0].0.clone(), pk_yk: keys[0].1.clone(),
        path: tree.path(0).unwrap(), root: tree.root(), cohort_size: tree.size() });
    // Synthetic cohort membership exercises the real L3 proof relation. It is
    // not SEP/YubiKey/installed issuer authority or physical erasure evidence.
    fixture = fixture.restart();
    let (pause, entered, resume) = pause();
    *fixture.peers.prepare_pause.lock().unwrap() = Some(pause);
    let service = fixture.service.clone();
    let worker = std::thread::spawn(move || service.handle(&root(), ZkRequest::Heartbeat));
    entered.recv_timeout(WAIT).unwrap();
    fixture.service.handle(&root(), ZkRequest::Wipe).unwrap(); resume.send(()).unwrap();
    assert!(worker.join().unwrap().unwrap_err().is("PROOF_RELEASE_FENCED"));
    assert!(fixture.peers.received.lock().unwrap().is_empty());
    fixture.assert_uncommitted(); fixture.assert_no_success_event();
    assert!(matches!(fixture.service.prove_heartbeat().unwrap(), ZkResponse::Proven { relayed: true, .. }));
    assert_eq!(fixture.peers.received.lock().unwrap().len(), 1);
}

#[test]
fn release_generic_series_fences_later_frame_and_keeps_first_handoff_debt() {
    let fixture = Fixture::new(); let (pause, entered, resume) = pause();
    *fixture.peers.ack_pause.lock().unwrap() = Some(pause);
    let service = fixture.service.clone();
    let worker = std::thread::spawn(move || {
        // Transport scheduling only: synthetic frame bytes do not assert a
        // valid multi-frame proof or bypass the public one-frame range cap.
        service.relay_frames(0, &[b"transport-first".to_vec(), b"transport-second".to_vec()]).map(|_| ())
    });
    entered.recv_timeout(WAIT).unwrap(); fixture.service.handle(&root(), ZkRequest::Wipe).unwrap();
    resume.send(()).unwrap();
    assert!(worker.join().unwrap().unwrap_err().is("PROOF_RELEASE_FENCED"));
    assert_eq!(*fixture.peers.received.lock().unwrap(), vec![b"transport-first".to_vec()]);
    fixture.assert_uncommitted(); fixture.assert_debt();
}

#[test]
fn release_real_memory_audit_failure_invalidates_prepared_proof_and_blocks_fresh_work() {
    use enclave_core::memory_budget::{AuxiliaryObservations, MemoryObservations};
    let fixture = Fixture::new(); let (pause, entered, resume) = pause();
    *fixture.peers.prepare_pause.lock().unwrap() = Some(pause);
    let worker = fixture.worker(); entered.recv_timeout(WAIT).unwrap();
    let mut observations = MemoryObservations { daemons: DaemonId::ALL.map(|daemon| Some(DaemonStatus {
        daemon_uid: daemon.uid(), binary: daemon.binary().into(), pid: 123,
        rss_bytes: 1, rss_ceiling_bytes: daemon.rss_ceiling_bytes(), boot_epoch_id: String::new(),
        rpc_seq_u64: 0, state: String::new(), phys_footprint_bytes: daemon.rss_ceiling_bytes(),
        phys_footprint_source: enclave_core::resource::FootprintSource::DarwinTaskVmInfo,
    })), auxiliary: AuxiliaryObservations::default() };
    observations.daemons[0].as_mut().unwrap().phys_footprint_bytes += 1;
    let writer = fixture.service.journal.lock().unwrap();
    assert!(fixture.service.handle(&root(), ZkRequest::ReportMemoryBreach(Box::new(observations)))
        .unwrap_err().is("AUDIT_WRITER_BUSY"));
    drop(writer); resume.send(()).unwrap();
    assert!(worker.join().unwrap().unwrap_err().is("PROOF_RELEASE_FENCED"));
    assert!(fixture.peers.received.lock().unwrap().is_empty());
    fixture.assert_uncommitted(); fixture.assert_no_success_event();
    assert!(fixture.service.memory_audit_failed.load(Ordering::SeqCst));
    assert!(fixture.service.memory_debt_path.is_file());
    assert!(fixture.service.handle(&root(), fixture.request()).unwrap_err().is("MEMORY_AUDIT_ADMISSION_BLOCKED"));
}

#[test]
fn release_acknowledged_frame_audit_failure_keeps_debt_without_success_reply() {
    let fixture = Fixture::new();
    let writer = fixture.service.journal.lock().unwrap();
    assert!(fixture.service.handle(&root(), fixture.request()).unwrap_err().is("AUDIT_WRITER_BUSY"));
    drop(writer);
    assert_eq!(fixture.peers.received.lock().unwrap().len(), 1);
    fixture.assert_debt(); fixture.assert_no_success_event();
    assert!(fixture.service.handle(&root(), fixture.request()).unwrap_err().is("PROOF_DELIVERY_UNCERTAIN"));
}

#[test]
fn release_failed_wipe_audit_keeps_separate_fence_debt_and_preserves_paused_frame_intent() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new(); let (pause, entered, resume) = pause();
    *fixture.peers.prepare_pause.lock().unwrap() = Some(pause);
    let worker = fixture.worker(); entered.recv_timeout(WAIT).unwrap();
    let intent = std::fs::read(&fixture.service.relay_debt_path).unwrap();
    let writer = fixture.service.journal.lock().unwrap();
    assert!(fixture.service.handle(&root(), ZkRequest::Wipe).unwrap_err().is("AUDIT_WRITER_BUSY"));
    drop(writer);
    assert_eq!(fixture.service.release_generation.load(Ordering::SeqCst), 1);
    assert!(fixture.service.lock().unwrap().streamed_witnesses.is_empty());
    assert!(fixture.service.fence_debt_path.is_file());
    assert_eq!(std::fs::read(&fixture.service.relay_debt_path).unwrap(), intent,
        "failed wipe audit must not overwrite the in-flight frame intent");
    resume.send(()).unwrap();
    assert!(worker.join().unwrap().unwrap_err().is("PROOF_RELEASE_FENCED"));
    assert!(fixture.peers.received.lock().unwrap().is_empty());
    fixture.assert_uncommitted(); fixture.assert_no_success_event();
    assert!(!fixture.service.relay_debt_path.exists(), "known zero-write intent may clear");
    let fence_debt = std::fs::read(&fixture.service.fence_debt_path).unwrap();
    fixture.service.handle(&root(), ZkRequest::Wipe).unwrap();
    fixture.service.ingest_witnesses(&fixture.epoch, vec![fold()]).unwrap();
    assert_eq!(std::fs::read(&fixture.service.fence_debt_path).unwrap(), fence_debt);
    assert!(fixture.service.handle(&root(), fixture.request()).unwrap_err().is("PROOF_DELIVERY_UNCERTAIN"));
    let fixture = fixture.restart();
    assert!(fixture.service.handle(&root(), fixture.request()).unwrap_err().is("PROOF_DELIVERY_UNCERTAIN"));
    // Startup must also preserve an ambiguous link and its owned target rather
    // than following it or treating a future dangling target as no debt.
    let target = fixture.directory.0.join("retained-fence-evidence");
    std::fs::rename(&fixture.service.fence_debt_path, &target).unwrap();
    symlink(&target, &fixture.service.fence_debt_path).unwrap();
    let fixture = fixture.restart();
    assert!(fixture.service.handle(&root(), fixture.request()).unwrap_err().is("PROOF_DELIVERY_UNCERTAIN"));
    assert!(std::fs::symlink_metadata(&fixture.service.fence_debt_path).unwrap().file_type().is_symlink());
    assert_eq!(std::fs::read(target).unwrap(), fence_debt);
}

#[test]
fn release_authorized_wipe_and_fault_purge_before_exhausted_rpc_sequence_and_keep_fence_debt() {
    for fault in [false, true] {
        let action = if fault { "fault" } else { "wipe" };
        let fixture = Fixture::new();
        fixture.service.handle(&root(), ZkRequest::DeferWitness {
            witness: ByteBuf::from(vec![9; 37]),
        }).unwrap();
        {
            let mut state = fixture.service.lock().unwrap();
            assert!(!state.streamed_witnesses.is_empty(), "{action}: seeded cache");
            assert_eq!(state.thermal.bytes(), 37, "{action}: seeded thermal owner");
            state.seq = RpcSequencer::new(enclave_core::seq::new_boot_epoch_id(), u64::MAX);
        }
        let generation = fixture.service.release_generation.load(Ordering::SeqCst);
        let request = if fault {
            ZkRequest::ReportFault(FaultReport {
                kind: FaultKind::HeapTag, fault_addr: 0x10000, at_ms: 1000,
            })
        } else { ZkRequest::Wipe };
        let error = fixture.service.handle(&root(), request).unwrap_err();
        assert!(error.is("RPC_SEQ_EXHAUSTED"), "{action}: {error}");
        {
            let state = fixture.service.lock().unwrap();
            assert!(state.streamed_witnesses.is_empty(), "{action}: failed audit sequence must not retain witnesses");
            assert_eq!(state.thermal.bytes(), 0, "{action}: failed audit sequence must not retain thermal payloads");
            assert_eq!(state.seq.current(), u64::MAX, "{action}: exhausted sequence must not reset");
        }
        assert_eq!(fixture.service.release_generation.load(Ordering::SeqCst), generation + 1, "{action}");
        assert_eq!(fixture.service.fence_pending.load(Ordering::SeqCst), 0, "{action}: cleanup completed");
        assert!(fixture.service.check_release(generation).unwrap_err().is("PROOF_RELEASE_FENCED"), "{action}");
        assert!(fixture.service.relay_failed.load(Ordering::SeqCst), "{action}: admission must fail closed");
        let debt = std::fs::read(&fixture.service.fence_debt_path).unwrap();
        assert!(!debt.is_empty(), "{action}: separate fence audit debt must persist");
        assert!(!String::from_utf8_lossy(&debt).contains("[REDACTED_EMAIL]"), "{action}: marker excludes witnesses");
        assert!(!fixture.service.relay_debt_path.exists(), "{action}: no frame was attempted");
        assert!(fixture.service.handle(&root(), fixture.request()).unwrap_err().is("PROOF_DELIVERY_UNCERTAIN"), "{action}");
        fixture.assert_uncommitted(); fixture.assert_no_success_event();
        assert!(fixture.peers.received.lock().unwrap().is_empty(), "{action}: no relay");
        // Restart resets the in-memory RPC sequence. Its fresh proof must still
        // refuse because the failed cancellation audit remains unresolved.
        let fixture = fixture.restart();
        assert!(fixture.service.handle(&root(), fixture.request()).unwrap_err().is("PROOF_DELIVERY_UNCERTAIN"), "{action}: restart");
        assert_eq!(std::fs::read(&fixture.service.fence_debt_path).unwrap(), debt, "{action}: restart preserves debt");
    }
}


// Context concurrency fixtures provide software-only synthetic membership.
// They make no installed-key, context-rotation or durable-progress claim.
type ContextSnapshot = (String, [u8; 32], [u8; 32], [u8; 32],
    serde_json::Value, Option<Vec<String>>, bool);

fn context_snapshot(service: &ZkService) -> ContextSnapshot {
    let state = service.lock().unwrap();
    (state.entity.clone(), state.id_enclave, state.policy_blake3,
        state.tuf_snapshot_root, serde_json::to_value(&state.hardware).unwrap(),
        state.hardware_batch_anchor_sigs.clone(), state.heartbeat)
}

fn context_expected(config: &ZkConfig) -> ContextSnapshot {
    (config.entity.clone(), config.id_enclave, config.policy_blake3,
        config.tuf_snapshot_root, serde_json::to_value(&config.hardware).unwrap(),
        config.hardware_batch_anchor_sigs.clone(), config.heartbeat)
}

fn context_apply(service: &ZkService, config: &ZkConfig) -> EnclaveResult<()> {
    service.set_context(config.entity.clone(), config.id_enclave,
        config.policy_blake3, config.tuf_snapshot_root, config.hardware.clone(),
        config.hardware_batch_anchor_sigs.clone(), config.heartbeat)
}

fn context_hardware(prefix: &str) -> HardwareWitness {
    let keys: Vec<_> = (0..32).map(|index| (
        format!("{prefix}-sep-{index}").into_bytes(),
        format!("{prefix}-member-{index}").into_bytes(),
    )).collect();
    let tree = crate::cohort::CohortTree::build(keys.iter()
        .map(|(sep, member)| crate::cohort::leaf(sep, member)).collect()).unwrap();
    HardwareWitness { pk_sep: keys[0].0.clone(), pk_yk: keys[0].1.clone(),
        path: tree.path(0).unwrap(), root: tree.root(), cohort_size: tree.size() }
}

fn context_replacement(config: &ZkConfig) -> ZkConfig {
    let mut replacement = config.clone();
    replacement.entity = "idle-context-replacement".into();
    replacement.id_enclave = [21; 32];
    replacement.policy_blake3 = [22; 32];
    replacement.tuf_snapshot_root = [23; 32];
    replacement.hardware = Some(context_hardware("replacement"));
    replacement.hardware_batch_anchor_sigs = Some(vec!["3046".into()]);
    replacement.heartbeat = !config.heartbeat;
    replacement
}

// All observations are captured before assertions. Always release and join
// both workers first, including old-source unexpected-success and timeout paths.
fn context_attempt_during_pause(
    fixture: &Fixture, entered: Receiver<()>, resume: SyncSender<()>,
    worker: std::thread::JoinHandle<EnclaveResult<ZkResponse>>,
    replacement: ZkConfig,
) -> ZkResponse {
    let entered_result = entered.recv_timeout(WAIT);
    let (sender, receiver) = mpsc::sync_channel(1);
    let service = fixture.service.clone();
    let setter = std::thread::spawn(move || {
        let result = context_apply(&service, &replacement);
        let observation = (result.is_ok(),
            result.as_ref().is_err_and(|error| error.is("PROOF_OPERATION_BUSY")),
            context_snapshot(&service));
        let _ = sender.send(observation.clone());
        observation
    });
    // This is bounded software test coordination, not a latency acceptance SLO.
    let observed_before_release = receiver.recv_timeout(Duration::from_secs(1));
    let _ = resume.try_send(());
    let worker_result = worker.join();
    let setter_result = setter.join();
    assert!(entered_result.is_ok(), "actual operation did not reach fixture pause");
    assert!(observed_before_release.is_ok(), "setter waited for active operation");
    let (accepted, refused_busy, observed_context) = setter_result.unwrap();
    assert_eq!((accepted, refused_busy), (false, true),
        "active operation must refuse context mutation");
    assert_eq!(observed_context, context_expected(&fixture.config));
    let response = worker_result.unwrap().unwrap();
    assert_eq!(context_snapshot(&fixture.service), context_expected(&fixture.config));
    assert!(!fixture.service.relay_failed.load(Ordering::SeqCst));
    assert!(!fixture.service.relay_debt_path.exists());
    response
}

#[test]
fn context_idle_update_changes_complete_context_and_idempotent_retry_succeeds() {
    let fixture = Fixture::new();
    let replacement = context_replacement(&fixture.config);
    let generation = fixture.service.release_generation.load(Ordering::SeqCst);
    let sequence = fixture.service.lock().unwrap().seq.current();
    context_apply(&fixture.service, &replacement).unwrap();
    assert_eq!(context_snapshot(&fixture.service), context_expected(&replacement));
    context_apply(&fixture.service, &replacement).unwrap();
    assert_eq!(context_snapshot(&fixture.service), context_expected(&replacement));
    assert_eq!(fixture.service.release_generation.load(Ordering::SeqCst), generation);
    assert_eq!(fixture.service.lock().unwrap().seq.current(), sequence);
    fixture.assert_uncommitted();
    assert!(fixture.peers.received.lock().unwrap().is_empty());
    assert!(!fixture.service.relay_debt_path.exists());
}

#[test]
fn context_actual_proof_refuses_update_between_chain_and_context_reads_then_idle_retry_succeeds() {
    let fixture = Fixture::new();
    let replacement = context_replacement(&fixture.config);
    let (pause, entered, resume) = pause();
    *fixture.peers.fetch_pause.lock().unwrap() = Some(pause);
    let worker = fixture.worker();
    let response = context_attempt_during_pause(&fixture, entered, resume, worker, replacement.clone());
    let ZkResponse::Proven { frames, relayed: true, .. } = response
        else { panic!("expected completed genuine proof"); };
    assert_eq!(frames.len(), 1);
    let frame = ComplianceRollupProofV1::decode(&frames[0]).unwrap();
    assert_eq!(frame.public_inputs.policy_blake3, hex::encode(fixture.config.policy_blake3));
    assert_eq!(frame.public_inputs.tuf_snapshot_root, hex::encode(fixture.config.tuf_snapshot_root));
    assert_eq!(frame.hardware_batch_anchor_sigs, fixture.config.hardware_batch_anchor_sigs);
    assert_eq!(fixture.peers.received.lock().unwrap().len(), 1);
    assert_eq!(fixture.service.lock().unwrap().proven[&fixture.epoch], 1);
    context_apply(&fixture.service, &replacement).unwrap();
    assert_eq!(context_snapshot(&fixture.service), context_expected(&replacement));
}

#[test]
fn context_actual_l3_heartbeat_refuses_update_during_prepared_relay_then_idle_retry_succeeds() {
    let mut fixture = Fixture::new();
    fixture.config.profile = Profile::L3;
    fixture.config.hardware_batch_anchor_sigs = None;
    fixture.config.hardware = Some(context_hardware("heartbeat"));
    fixture = fixture.restart();
    let replacement = context_replacement(&fixture.config);
    let (pause, entered, resume) = pause();
    *fixture.peers.prepare_pause.lock().unwrap() = Some(pause);
    let service = fixture.service.clone();
    let worker = std::thread::spawn(move || service.handle(&root(), ZkRequest::Heartbeat));
    let response = context_attempt_during_pause(&fixture, entered, resume, worker, replacement.clone());
    let ZkResponse::Proven { frames, relayed: true, .. } = response
        else { panic!("expected completed genuine heartbeat"); };
    assert_eq!(frames.len(), 1);
    let frame = ComplianceRollupProofV1::decode(&frames[0]).unwrap();
    assert_eq!(frame.profile, 3);
    assert_eq!(frame.heartbeat, Some(true));
    assert_eq!(frame.public_inputs.policy_blake3, hex::encode(fixture.config.policy_blake3));
    assert_eq!(frame.public_inputs.tuf_snapshot_root, hex::encode(fixture.config.tuf_snapshot_root));
    assert!(frame.hardware_batch_anchor_sigs.is_none());
    assert_eq!(fixture.peers.received.lock().unwrap().len(), 1);
    context_apply(&fixture.service, &replacement).unwrap();
    assert_eq!(context_snapshot(&fixture.service), context_expected(&replacement));
}

#[test]
fn context_busy_operation_refuses_before_state_lock_without_mutation() {
    let fixture = Fixture::new();
    let replacement = context_replacement(&fixture.config);
    let operation = fixture.service.proof_operation.lock().unwrap();
    let state = fixture.service.lock().unwrap();
    let (sender, receiver) = mpsc::sync_channel(1);
    let service = fixture.service.clone();
    let setter = std::thread::spawn(move || {
        let result = context_apply(&service, &replacement);
        let _ = sender.send(result.as_ref().is_err_and(|error| error.is("PROOF_OPERATION_BUSY")));
        result
    });
    let while_both_locked = receiver.recv_timeout(Duration::from_secs(1));
    drop(state);
    drop(operation);
    let result = setter.join();
    assert_eq!(while_both_locked.ok(), Some(true), "busy refusal must precede State access");
    assert!(result.unwrap().unwrap_err().is("PROOF_OPERATION_BUSY"));
    assert_eq!(context_snapshot(&fixture.service), context_expected(&fixture.config));
    fixture.assert_uncommitted();
    assert!(fixture.peers.received.lock().unwrap().is_empty());
    assert!(!fixture.service.relay_debt_path.exists());
}

#[test]
fn context_poisoned_operation_refuses_without_state_mutation() {
    let fixture = Fixture::new();
    let service = fixture.service.clone();
    let poisoned = std::thread::spawn(move || {
        let _operation = service.proof_operation.lock().unwrap();
        panic!("fixture poisons only the operation mutex");
    }).join();
    assert!(poisoned.is_err());
    let replacement = context_replacement(&fixture.config);
    assert!(context_apply(&fixture.service, &replacement).unwrap_err().is("PROOF_OPERATION_BUSY"));
    assert_eq!(context_snapshot(&fixture.service), context_expected(&fixture.config));
    fixture.assert_uncommitted();
    assert!(fixture.peers.received.lock().unwrap().is_empty());
    assert!(!fixture.service.relay_debt_path.exists());
}
