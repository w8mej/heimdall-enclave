//! Actual service-owned journal fixtures, no native sampling or production issuer.
use super::*;
use enclave_core::memory_budget::{AuxiliaryObservations, MemoryObservations};
use std::os::unix::fs::DirBuilderExt;
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("memory-breach-{:x}", enclave_core::rng::u64()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct NoPeers;
impl Peers for NoPeers {
    fn cosign(&self, _: DaemonId, _: u64, _: &str) -> EnclaveResult<(Vec<u8>, Vec<u8>)> {
        panic!("no custody work")
    }
    fn prepare_relay(&self, _: &[u8]) -> EnclaveResult<enclave_core::ipc::PreparedCall> {
        panic!("no relay")
    }
    fn fetch_witness(&self, _: &str, _: u64, _: u64) -> EnclaveResult<(Vec<WitnessFold>, u64)> {
        panic!("no witnesses")
    }
    fn boot_epoch(&self) -> EnclaveResult<enclave_core::seq::BootEpoch> {
        panic!("no epoch authority")
    }
}
fn observations() -> MemoryObservations {
    MemoryObservations {
        daemons: DaemonId::ALL.map(|d| {
            Some(DaemonStatus {
                daemon_uid: d.uid(),
                binary: d.binary().into(),
                pid: 123,
                rss_bytes: 1,
                rss_ceiling_bytes: u64::MAX,
                boot_epoch_id: String::new(),
                rpc_seq_u64: 0,
                state: "do-not-journal-private-status".into(),
                phys_footprint_bytes: d.rss_ceiling_bytes(),
                phys_footprint_source: enclave_core::resource::FootprintSource::DarwinTaskVmInfo,
            })
        }),
        auxiliary: AuxiliaryObservations::default(),
    }
}
fn start_service(directory: &Directory, journal: bool) -> Arc<ZkService> {
    let mut config = ZkConfig::new(Profile::L2, directory.0.join("state"));
    if journal {
        config.audit_path = Some(directory.0.join("audit.jsonl"));
    }
    ZkService::start(config, Box::new(NoPeers)).unwrap()
}
fn root() -> PeerCredentials {
    PeerCredentials::local(0, 0)
}
fn request() -> ZkRequest {
    let mut observations = observations();
    observations.daemons[0]
        .as_mut()
        .unwrap()
        .phys_footprint_bytes += 1;
    ZkRequest::ReportMemoryBreach(Box::new(observations))
}
#[test]
fn memory_breach_authorized_durable_append_reopens_and_excludes_raw_status() {
    let directory = Directory::new();
    let service = start_service(&directory, true);
    assert!(service
        .handle(&PeerCredentials::local(704, 0), request())
        .unwrap_err()
        .is("MEMORY_BREACH_OPERATOR_ONLY"));
    assert!(service
        .handle(
            &root(),
            ZkRequest::ReportMemoryBreach(Box::new(observations()))
        )
        .unwrap_err()
        .is("MEMORY_BREACH_NOT_OBSERVED"));
    assert!(matches!(
        service.handle(&root(), request()).unwrap(),
        ZkResponse::MemoryBreachRecorded { log_seq: 1 }
    ));
    drop(service);
    let path = directory.0.join("audit.jsonl");
    assert_eq!(
        enclave_core::audit::verify_journal(&path, None)
            .unwrap()
            .entries,
        1
    );
    let line = std::fs::read_to_string(&path).unwrap();
    assert!(!line.contains("do-not-journal-private-status"));
    let event: enclave_core::audit::EnclaveAuditEnvelopeV1 =
        serde_json::from_str(line.trim()).unwrap();
    assert_eq!(event.payload["event"], "MEMORY_BUDGET_BREACH");
    assert_eq!(event.payload["observer_uid"], 0);
    let reopened = start_service(&directory, true);
    assert!(matches!(
        reopened.handle(&root(), request()).unwrap(),
        ZkResponse::MemoryBreachRecorded { log_seq: 2 }
    ));
}
#[test]
fn memory_breach_missing_or_failed_journal_never_acks_and_status_remains_available() {
    for journal in [false, true] {
        let directory = Directory::new();
        let service = start_service(&directory, journal);
        if journal {
            std::fs::create_dir(directory.0.join("audit.jsonl")).unwrap();
        }
        assert!(service.handle(&root(), request()).is_err());
        let begin = std::time::Instant::now();
        for _ in 0..3 {
            let ZkResponse::Status(status)=service.handle(&root(),ZkRequest::Status).unwrap() else{panic!()};
            assert!(status.state.contains("memory_breach_audit=failed"));
        }
        assert!(
            begin.elapsed() < std::time::Duration::from_secs(1),
            "Status unexpectedly retried journal I/O"
        );
        assert!(service.handle(&root(), request()).is_err());
    }
}

#[test]
fn memory_breach_failure_debt_survives_restart() {
    let directory = Directory::new();
    let service = start_service(&directory, false);
    assert!(service.handle(&root(), request()).is_err());
    drop(service);
    let reopened = start_service(&directory, true);
    let ZkResponse::Status(status)=reopened.handle(&root(),ZkRequest::Status).unwrap() else{panic!()};
    assert!(status.state.contains("memory_breach_audit=failed"));
    assert!(matches!(
        reopened.handle(&root(), request()).unwrap(),
        ZkResponse::MemoryBreachRecorded { log_seq: 1 }
    ));
    assert!(directory.0.join("state/memory-breach.pending").is_file());
}

#[test]
fn memory_breach_restart_preserves_regular_symlink_fifo_and_directory_debt_markers() {
    use std::os::unix::{ffi::OsStrExt, fs::symlink};
    for kind in [
        "regular",
        "dangling_symlink",
        "live_symlink",
        "fifo",
        "directory",
    ] {
        let directory = Directory::new();
        let initial = start_service(&directory, true);
        assert_eq!(initial.memory_audit_status(), "ok");
        drop(initial);
        let marker = directory.0.join("state/memory-breach.pending");
        let target = directory.0.join("unrelated-marker-target");
        match kind {
            "regular" => std::fs::write(&marker, b"uncertain debt\n").unwrap(),
            "dangling_symlink" => symlink(&target, &marker).unwrap(),
            "live_symlink" => {
                std::fs::write(&target, b"unrelated retained evidence\n").unwrap();
                symlink(&target, &marker).unwrap();
            }
            "fifo" => {
                let name = std::ffi::CString::new(marker.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
            "directory" => std::fs::create_dir(&marker).unwrap(),
            _ => unreachable!(),
        }
        let reopened = start_service(&directory, true);
        assert_eq!(
            reopened.memory_audit_status(),
            "failed",
            "marker kind {kind}"
        );
        let ZkResponse::Status(status)=reopened.handle(&root(),ZkRequest::Status).unwrap() else{panic!()};
        assert!(
            status.state.contains("memory_breach_audit=failed"),
            "marker kind {kind}"
        );
        // Startup observes the marker itself and neither consumes a FIFO nor
        // follows, replaces or deletes an ambiguous marker or its target.
        let metadata = std::fs::symlink_metadata(&marker).unwrap();
        if kind.ends_with("symlink") {
            assert!(metadata.file_type().is_symlink());
        }
        if kind == "dangling_symlink" {
            assert!(!target.exists());
        }
        if kind == "live_symlink" {
            assert_eq!(
                std::fs::read(&target).unwrap(),
                b"unrelated retained evidence\n"
            );
        }
        drop(reopened);
        assert_eq!(
            start_service(&directory, true).memory_audit_status(),
            "failed",
            "second restart {kind}"
        );
    }
}
#[test]
fn memory_breach_blocked_journal_does_not_block_status() {
    use std::os::unix::ffi::OsStrExt;
    let directory = Directory::new();
    let service = start_service(&directory, true);
    let path = directory.0.join("audit.jsonl");
    let fifo = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let worker = service.clone();
    let report = std::thread::spawn(move || worker.handle(&root(), request()));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while !service.memory_audit_pending.load(Ordering::SeqCst)
        && std::time::Instant::now() < deadline
    {
        std::thread::yield_now();
    }
    let worker = service.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    let status_worker = std::thread::spawn(move || {
        sender
            .send(worker.handle(&root(), ZkRequest::Status))
            .unwrap()
    });
    let observed = receiver.recv_timeout(std::time::Duration::from_secs(1));
    // Always release FIFO open before asserting, so even a failed regression
    // leaves no blocked worker or persistent fixture behind.
    let reader = std::thread::spawn(move || {
        let mut input = std::fs::File::open(path).unwrap();
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut input, &mut bytes).unwrap();
        bytes
    });
    assert!(report.join().unwrap().unwrap_err().is("AUDIT_NOT_REGULAR"));
    assert!(
        reader.join().unwrap().is_empty(),
        "nonregular journal received audit bytes"
    );
    status_worker.join().unwrap();
    let ZkResponse::Status(status)=observed.expect("Status waited for memory journal I/O").unwrap() else{panic!()};
    assert!(status.state.contains("memory_breach_audit=pending"));
    assert_eq!(service.memory_audit_status(), "failed");
}

#[test]
fn memory_breach_concurrent_busy_debt_survives_success_cleanup_and_restart() {
    let directory = Directory::new();
    let service = start_service(&directory, true);
    let barrier = Arc::new(std::sync::Barrier::new(2));
    *service.memory_cleanup_barrier.lock().unwrap() = Some(barrier.clone());
    let writer = service.clone();
    let successful = std::thread::spawn(move || writer.handle(&root(), request()));
    barrier.wait(); // Writer holds both writer/debt locks after the clean check.
    let busy_barrier = Arc::new(std::sync::Barrier::new(2));
    *service.memory_busy_barrier.lock().unwrap() = Some(busy_barrier.clone());
    let rejected = service.clone();
    let busy = std::thread::spawn(move || rejected.handle(&root(), request()));
    busy_barrier.wait(); // Confirms writer acquisition failed before cleanup resumes.
                         // A busy reporter must wait for debt cleanup's mutex, rather than placing a
                         // marker that the successful writer can subsequently delete.
    barrier.wait();
    assert!(matches!(
        successful.join().unwrap().unwrap(),
        ZkResponse::MemoryBreachRecorded { log_seq: 1 }
    ));
    assert!(busy.join().unwrap().unwrap_err().is("AUDIT_WRITER_BUSY"));
    assert_eq!(service.memory_audit_status(), "failed");
    drop(service);
    assert!(directory.0.join("state/memory-breach.pending").is_file());
    let reopened = start_service(&directory, true);
    assert_eq!(reopened.memory_audit_status(), "failed");
}
