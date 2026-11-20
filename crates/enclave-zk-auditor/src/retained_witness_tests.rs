//! Bounded cache-owner regressions; no proof-wide cancellation/erasure claim.
use super::*;
use enclave_core::quarantine_types::FaultKind;
use std::os::unix::fs::DirBuilderExt;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::time::Duration;

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        // Owned private fixture beneath the platform temporary directory.
        let root = std::env::temp_dir().canonicalize().unwrap();
        let path = root.join(format!("retained-witness-{:x}", enclave_core::rng::u64()));
        std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct CachePeers {
    pause_fetch: Option<(SyncSender<()>, Mutex<Receiver<()>>)>,
}

impl Peers for CachePeers {
    fn cosign(&self, _: DaemonId, _: u64, _: &str) -> EnclaveResult<(Vec<u8>, Vec<u8>)> {
        panic!("cache tests never authorize a tombstone or generate a proof")
    }

    fn prepare_relay(&self, _: &[u8]) -> EnclaveResult<enclave_core::ipc::PreparedCall> {
        panic!("cache tests never relay")
    }

    fn fetch_witness(&self, _: &str, _: u64, _: u64) -> EnclaveResult<(Vec<WitnessFold>, u64)> {
        if let Some((entered, resume)) = &self.pause_fetch {
            entered.send(()).unwrap();
            resume.lock().unwrap().recv_timeout(Duration::from_secs(5)).unwrap();
        }
        Ok((Vec::new(), 8))
    }

    fn boot_epoch(&self) -> EnclaveResult<enclave_core::seq::BootEpoch> {
        panic!("private derivation tests do not simulate signed epoch admission")
    }
}

fn fixture(peers: CachePeers) -> (Directory, Arc<ZkService>) {
    let directory = Directory::new();
    let mut config = ZkConfig::new(Profile::L2, directory.0.join("state"));
    config.audit_path = Some(directory.0.join("auditor.jsonl"));
    config.journal_dir = Some(directory.0.join("logs"));
    config.entity = "cache-owner-regression".into();
    config.id_enclave = [1; 32];
    config.policy_blake3 = [2; 32];
    config.tuf_snapshot_root = [3; 32];
    config.heartbeat = true;
    let service = ZkService::start(config, Box::new(peers)).unwrap();
    (directory, service)
}

fn root() -> PeerCredentials {
    PeerCredentials::local(0, 0)
}

fn unauthorized() -> PeerCredentials {
    let uid = if enclave_core::ipc::geteuid() == 703 { 704 } else { 703 };
    PeerCredentials::local(uid, 0)
}

fn fold(slot: u64, bytes: &[u8]) -> WitnessFold {
    WitnessFold {
        rpc_seq_u64: slot,
        scrubbed: bytes.to_vec(),
        c_raw: "1".repeat(64),
        h_ingress_mac: "2".repeat(64),
    }
}

fn seed(service: &ZkService, epoch: &str) {
    service.ingest_witnesses(epoch, vec![fold(7, b"retained-private-fixture")]).unwrap();
    assert!(matches!(
        service.handle(&root(), ZkRequest::DeferWitness { witness: ByteBuf::from(vec![9; 37]) }).unwrap(),
        ZkResponse::Ok
    ));
}

fn assert_empty(service: &ZkService) {
    let state = service.lock().unwrap();
    assert!(state.streamed_witnesses.is_empty());
    assert_eq!(state.thermal.bytes(), 0);
}

fn assert_cached_bytes(cache: &crate::retained::RetainedWitnessCache, epoch: &str, expected: &[u8]) {
    let (mut folds, lease) = cache.snapshot_range(epoch, 7, 7).unwrap().into_parts();
    assert_eq!(folds.len(), 1);
    assert_eq!(folds[0].scrubbed, expected);
    for fold in &mut folds {
        fold.scrubbed.zeroize(); fold.c_raw.zeroize(); fold.h_ingress_mac.zeroize();
    }
    drop(folds); // Release the clone allocations before their registered lease.
    drop(lease);
}

fn assert_retained(service: &ZkService, epoch: &str) {
    let state = service.lock().unwrap();
    assert_cached_bytes(&state.streamed_witnesses, epoch, b"retained-private-fixture");
    assert_eq!(state.thermal.bytes(), 37);
}

fn fault(kind: FaultKind, fault_addr: u64, at_ms: u64) -> FaultReport {
    FaultReport { kind, fault_addr, at_ms }
}

fn released_slot(directory: &Directory, epoch: &str) {
    let daemon = DaemonId::CustodyVault;
    let path = directory.0.join("logs").join(daemon.dir_name())
        .join(format!("{}-audit.jsonl", daemon.plist_suffix()));
    AuditJournal::open(&path, daemon, enclave_core::seq::new_boot_epoch_id()).unwrap()
        .append_at(epoch, 7, json!({"event":"SCRUB_TEXT","slot":7})).unwrap();
}

fn request(epoch: &str) -> ProveEpochRequest {
    ProveEpochRequest { boot_epoch_id: epoch.into(), s_start: 7, s_end: 7 }
}

#[test]
fn retained_wipe_clears_all_epochs_preserves_progress_and_journals_repeated_wipes() {
    let (directory, service) = fixture(CachePeers { pause_fetch: None });
    let epoch = enclave_core::seq::new_boot_epoch_id();
    let other = enclave_core::seq::new_boot_epoch_id();
    seed(&service, &epoch);
    service.ingest_witnesses(&other, vec![fold(2, b"second-epoch"), fold(3, b"third-slot")]).unwrap();
    let anchor = enclave_core::audit::ChainAnchor { entries: 4, tip_blake3: [4; 32] };
    {
        let mut state = service.lock().unwrap();
        state.anchors.insert(703, anchor);
        state.proven.insert(epoch.clone(), 6);
        state.pinned.insert(703, vec![5; 32]);
        state.egress_streams.insert([6; 32], 9);
    }
    for _ in 0..2 {
        assert!(matches!(service.handle(&root(), ZkRequest::Wipe).unwrap(), ZkResponse::Ok));
        assert_empty(&service);
    }
    {
        let state = service.lock().unwrap();
        assert_eq!(state.profile, Profile::L2);
        assert_eq!(state.entity, "cache-owner-regression");
        assert_eq!(state.id_enclave, [1; 32]);
        assert_eq!(state.policy_blake3, [2; 32]);
        assert_eq!(state.tuf_snapshot_root, [3; 32]);
        assert!(state.heartbeat);
        assert!(!state.quarantine.is_latched());
        assert_eq!(state.j_state, genesis());
        assert_eq!(state.anchors[&703], anchor);
        assert_eq!(state.proven[&epoch], 6);
        assert_eq!(state.pinned[&703], vec![5; 32]);
        assert_eq!(state.egress_streams[&[6; 32]], 9);
    }
    let path = directory.0.join("auditor.jsonl");
    assert_eq!(enclave_core::audit::verify_journal(&path, None).unwrap().entries, 2);
    for line in std::fs::read_to_string(path).unwrap().lines() {
        let envelope: enclave_core::audit::EnclaveAuditEnvelopeV1 = serde_json::from_str(line).unwrap();
        assert_eq!(envelope.payload["event"], "WITNESS_WIPED");
    }
}

#[test]
fn retained_unauthorized_wipe_and_fault_preserve_cache_and_thermal() {
    let (directory, service) = fixture(CachePeers { pause_fetch: None });
    let epoch = enclave_core::seq::new_boot_epoch_id();
    seed(&service, &epoch);
    assert!(service.handle(&unauthorized(), ZkRequest::Wipe).unwrap_err().is("WIPE_PEER_REJECTED"));
    assert_retained(&service, &epoch);
    let report = fault(FaultKind::HeapTag, 0x10000, 1_000);
    assert!(service.handle(&unauthorized(), ZkRequest::ReportFault(report)).unwrap_err().is("FAULT_REPORTER_REJECTED"));
    assert_retained(&service, &epoch);
    assert!(!directory.0.join("auditor.jsonl").exists());
}

#[test]
fn retained_later_derivation_cannot_reuse_prewipe_streamed_fold() {
    let (directory, service) = fixture(CachePeers { pause_fetch: None });
    let epoch = enclave_core::seq::new_boot_epoch_id();
    released_slot(&directory, &epoch);
    seed(&service, &epoch);
    let derived = service.derive_chunks(&request(&epoch)).unwrap();
    assert!(matches!(&derived.chunks[0].0[0], Derived::Fold { seq: 7, scrubbed, .. } if scrubbed == b"retained-private-fixture"));
    drop(derived); // This case intentionally holds no in-flight pre-wipe clone.
    service.handle(&root(), ZkRequest::Wipe).unwrap();
    let derived = service.derive_chunks(&request(&epoch)).unwrap();
    assert!(matches!(&derived.chunks[0].0[0], Derived::Tombstone(7)));
    // Derivation does not authorize this tombstone: a real custody co-signer
    // must refuse its released slot. No proof or relay occurs in this fixture.
}

#[test]
fn retained_every_authorized_fault_response_wipes_both_stores() {
    let (_directory, service) = fixture(CachePeers { pause_fetch: None });
    let epoch = enclave_core::seq::new_boot_epoch_id();
    for (report, expected) in [
        (fault(FaultKind::Segv, 8, 1_000), Response::RestartThrottled),
        (fault(FaultKind::HeapTag, 0x10000, 2_000), Response::StrikeDelayRespawn),
        (fault(FaultKind::Pac, 0x10000, 3_000), Response::Latched),
    ] {
        seed(&service, &epoch);
        let ZkResponse::Fault(actual) = service.handle(&root(), ZkRequest::ReportFault(report)).unwrap() else { panic!("missing fault response") };
        assert_eq!(actual, expected);
        assert_empty(&service);
    }
}

#[test]
fn retained_fault_persistence_failure_still_wipes_before_returning_error() {
    let (directory, service) = fixture(CachePeers { pause_fetch: None });
    let epoch = enclave_core::seq::new_boot_epoch_id();
    seed(&service, &epoch);
    let sealed = directory.0.join("state/quarantine.sealed");
    std::fs::remove_file(&sealed).unwrap();
    std::fs::create_dir(&sealed).unwrap(); // Deterministic rename failure, including when tests run as root.
    assert!(service.handle(&root(), ZkRequest::ReportFault(fault(FaultKind::HeapTag, 0x10000, 1_000))).is_err());
    assert_empty(&service);
    assert!(!directory.0.join("auditor.jsonl").exists());
}

#[test]
fn retained_clear_state_can_replace_and_refill_but_latch_refuses_ingestion() {
    let (_directory, service) = fixture(CachePeers { pause_fetch: None });
    let epoch = enclave_core::seq::new_boot_epoch_id();
    seed(&service, &epoch);
    service.ingest_witnesses(&epoch, vec![fold(7, b"replacement")]).unwrap();
    assert_cached_bytes(&service.lock().unwrap().streamed_witnesses, &epoch, b"replacement");
    service.handle(&root(), ZkRequest::Wipe).unwrap();
    seed(&service, &epoch); // Wipe is a cache purge, not a permanent intake latch.
    assert_retained(&service, &epoch);
    for at in [1_000, 2_000] {
        service.handle(&root(), ZkRequest::ReportFault(fault(FaultKind::HeapTag, 0x10000, at))).unwrap();
    }
    let error = service.ingest_witnesses(&epoch, vec![fold(7, b"must-not-refill")]).unwrap_err();
    assert!(error.is("HARDWARE_INTEGRITY_QUARANTINE"));
    assert_empty(&service);
}

#[test]
fn retained_concurrent_derive_started_before_wipe_cannot_lookup_cleared_cache() {
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (resume_tx, resume_rx) = mpsc::sync_channel(1);
    let peers = CachePeers { pause_fetch: Some((entered_tx, Mutex::new(resume_rx))) };
    let (directory, service) = fixture(peers);
    let epoch = enclave_core::seq::new_boot_epoch_id();
    released_slot(&directory, &epoch);
    seed(&service, &epoch);
    let worker_service = service.clone();
    let prove_request = request(&epoch);
    let worker = std::thread::spawn(move || worker_service.derive_chunks(&prove_request));
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    // The actual derive operation has snapshotted anchors and is paused inside
    // peer fetch, before its later State-serialized cache lookup.
    service.handle(&root(), ZkRequest::Wipe).unwrap();
    assert_empty(&service);
    resume_tx.send(()).unwrap();
    let derived = worker.join().unwrap().unwrap();
    assert!(matches!(&derived.chunks[0].0[0], Derived::Tombstone(7)));
    // This covers cache lookup ordering only. A clone acquired before the wipe
    // can still outlive it; no complete proof-release fence is asserted.
}

#[test]
fn retained_witness_dispatch_acknowledges_only_successful_ingestion() {
    use crate::witness::{dispatch_witness_request, WitnessChannelRequest, WitnessChannelResponse};
    let (_directory, service) = fixture(CachePeers { pause_fetch: None });
    let epoch = enclave_core::seq::new_boot_epoch_id();
    let response = dispatch_witness_request(&service, WitnessChannelRequest::StreamWitness {
        boot_epoch_id: epoch.clone(), folds: vec![fold(7, b"accepted-ingress")],
    }).unwrap();
    assert_eq!(response, WitnessChannelResponse::Ack);
    assert_cached_bytes(&service.lock().unwrap().streamed_witnesses, &epoch, b"accepted-ingress");
    for at in [1_000, 2_000] {
        service.handle(&root(), ZkRequest::ReportFault(fault(FaultKind::HeapTag, 0x10000, at))).unwrap();
    }
    let error = dispatch_witness_request(&service, WitnessChannelRequest::StreamWitness {
        boot_epoch_id: epoch, folds: vec![fold(7, b"refused-ingress")],
    }).unwrap_err();
    assert!(error.is("HARDWARE_INTEGRITY_QUARANTINE"));
    assert_empty(&service);
    // The actual authenticated listener closes on this dispatch error before
    // response serialization. This unit test makes no kernel-UID703 IPC claim.
}

#[test]
fn retained_explicit_wipe_erases_initialized_live_and_spare_capacity() {
    fn buffer(len: usize, reserved: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(reserved);
        // Initialize every byte, including the region that will become spare.
        // This permits defined reads across capacity while allocation is owned.
        bytes.resize(bytes.capacity(), b'Z');
        bytes.truncate(len);
        bytes
    }
    let mut retained = RetainedWitness(WitnessFold {
        rpc_seq_u64: 7,
        scrubbed: buffer(19, 257),
        c_raw: String::from_utf8(buffer(64, 131)).unwrap(),
        h_ingress_mac: String::from_utf8(buffer(64, 193)).unwrap(),
    });
    let allocations = [
        (retained.0.scrubbed.as_ptr(), retained.0.scrubbed.capacity()),
        (retained.0.c_raw.as_ptr(), retained.0.c_raw.capacity()),
        (retained.0.h_ingress_mac.as_ptr(), retained.0.h_ingress_mac.capacity()),
    ];
    assert!(allocations[0].1 > retained.0.scrubbed.len());
    assert!(allocations[1].1 > retained.0.c_raw.len());
    assert!(allocations[2].1 > retained.0.h_ingress_mac.len());
    retained.wipe();
    assert!(retained.0.scrubbed.is_empty());
    assert!(retained.0.c_raw.is_empty());
    assert!(retained.0.h_ingress_mac.is_empty());
    // Obtain fresh pointers after zeroize's mutable accesses. The earlier
    // pointers are used only for equality, never for post-wipe dereferencing.
    let after = [
        (retained.0.scrubbed.as_ptr(), retained.0.scrubbed.capacity()),
        (retained.0.c_raw.as_ptr(), retained.0.c_raw.capacity()),
        (retained.0.h_ingress_mac.as_ptr(), retained.0.h_ingress_mac.capacity()),
    ];
    assert_eq!(allocations, after, "wipe must retain these live allocations until their owner is dropped");
    for (pointer, capacity) in after {
        // SAFETY: each allocation is still owned by `retained`, these fresh
        // post-wipe pointers retain its unchanged capacity, and every byte was
        // initialized above. No owner mutation occurs during this shared read
        // and none is after free.
        let bytes = unsafe { std::slice::from_raw_parts(pointer, capacity) };
        assert!(bytes.iter().all(|byte| *byte == 0), "retained or spare witness byte survived wipe");
    }
    // Drop calls this same wipe method again; no access occurs after Drop.
}
