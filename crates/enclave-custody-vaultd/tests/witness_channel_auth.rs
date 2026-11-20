//! Public client authentication and explicit development wiring regressions.
//! Owned synthetic marker; no real witness/private material is logged.
//! Execute only where actual current UID differs from the required server705.
use enclave_core::daemon::{DaemonId, WITNESS_SOCKET_NAME};
use enclave_core::ipc::{self, write_frame, ServeLimits};
use enclave_custody_vaultd::ingress::{WitnessFold, WitnessStreamClient};
use std::io::{Read, Write};
use std::os::unix::{fs::DirBuilderExt, net::{UnixListener, UnixStream}};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const MARKER: &[u8] = b"OWNED_SYNTHETIC_PRIVATE_WITNESS_MARKER";
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}
fn directory() -> Directory {
    let name = format!("wa{}-{:x}", std::process::id(), enclave_core::rng::u64() & 0xfffffff);
    let dir = Directory(std::env::temp_dir().join(name));
    std::fs::DirBuilder::new().mode(0o700).create(&dir.0).unwrap();
    let parent = dir.0.join(WITNESS_SOCKET_NAME).parent().unwrap().to_path_buf();
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(parent).unwrap();
    dir
}

#[derive(Debug)]
struct Observation {
    kernel_client_uid: u32,
    request_bytes: usize,
    complete_marker_observed: bool,
}

// The observer needs numeric UID only. On Darwin a client can close promptly
// after rejecting the server, making LOCAL_PEERTOKEN unavailable while the
// connection's numeric getpeereid remains available. Production still uses the
// complete peer_credentials/code verification path without this exception.
#[cfg(target_os = "macos")]
fn observer_kernel_uid(stream: &UnixStream) -> u32 {
    use std::os::fd::AsRawFd;
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: live owned socket and valid local output pointers.
    assert_eq!(unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) }, 0,
        "owned observer must obtain actual kernel numeric UID");
    uid
}
#[cfg(not(target_os = "macos"))]
fn observer_kernel_uid(stream: &UnixStream) -> u32 {
    ipc::peer_credentials(stream).unwrap().uid
}

fn read_owned_request(mut stream: UnixStream) -> Observation {
    let kernel_client_uid = observer_kernel_uid(&stream);
    stream.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let cap = ServeLimits::for_daemon(DaemonId::ZkAuditor, false).max_frame;
    let mut request = Vec::new();
    let mut expected = None;
    loop {
        if expected.is_some_and(|length| request.len() == length) { break; }
        assert!(Instant::now() < deadline, "owned rogue peer read deadline");
        let remaining = expected.unwrap_or(4usize).saturating_sub(request.len());
        let mut chunk = [0u8; 1024];
        let take = remaining.min(chunk.len());
        match stream.read(&mut chunk[..take]) {
            Ok(0) => break,
            Ok(count) => request.extend_from_slice(&chunk[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {},
            Err(error) => panic!("owned rogue peer read: {error}"),
        }
        if request.len() == 4 && expected.is_none() {
            let length = u32::from_be_bytes(request[..4].try_into().unwrap()) as usize;
            assert!(length <= cap, "owned test unexpectedly received oversized frame");
            expected = Some(4usize.checked_add(length).unwrap());
        }
    }
    let complete = expected.is_some_and(|length| request.len() == length);
    if complete {
        // Bare unit-enum Ack is CBOR text. Build it independently from the
        // producer's response enum and keep the owned reply bounded as well.
        let mut ack = Vec::new();
        ciborium::into_writer("Ack", &mut ack).unwrap();
        let mut framed = Vec::new();
        write_frame(&mut framed, &ack).unwrap();
        let mut sent = 0;
        while sent < framed.len() {
            assert!(Instant::now() < deadline, "owned rogue reply deadline");
            match stream.write(&framed[sent..]) {
                Ok(0) => panic!("owned rogue reply closed"),
                Ok(count) => sent += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(2)),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {},
                Err(error) => panic!("owned rogue reply: {error}"),
            }
        }
    }
    Observation { kernel_client_uid, request_bytes: request.len(),
        complete_marker_observed: complete && request.windows(MARKER.len()).any(|part| part == MARKER) }
}

#[test]
fn witness_default_client_rejects_actual_wrong_uid_before_any_request_or_witness_byte() {
    let actual_uid = ipc::geteuid();
    assert_ne!(actual_uid, DaemonId::ZkAuditor.uid(),
        "fixture requires actual host UID different from705; do not fabricate credentials");
    let dir = directory();
    let listener = UnixListener::bind(dir.0.join(WITNESS_SOCKET_NAME)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let peer = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            match listener.accept() {
                Ok((stream, _)) => return read_owned_request(stream),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => std::thread::sleep(Duration::from_millis(2)),
                Err(error) => panic!("owned rogue accept: {error}"),
            }
        }
    });
    let result = WitnessStreamClient::stream(&dir.0, "owned-epoch", vec![WitnessFold {
        rpc_seq_u64: 7, scrubbed: MARKER.to_vec(), c_raw: "a".repeat(64), h_ingress_mac: "b".repeat(64),
    }]);
    // Join before all terminal contract assertions, including old-source
    // unexpected success, so a failing red cannot abandon its observer.
    let observed = peer.join().unwrap();
    println!("WITNESS_WRONG_SERVER_AUTH observed_client_uid={} actual_server_uid={} request_bytes={} complete_synthetic_marker_observed={} client_returned_success={}",
        observed.kernel_client_uid, actual_uid, observed.request_bytes,
        observed.complete_marker_observed, result.is_ok());
    assert_eq!(observed.kernel_client_uid, actual_uid);
    assert_eq!((result.as_ref().is_err_and(|error| error.is("SERVER_UID_MISMATCH")),
        observed.request_bytes == 0, observed.complete_marker_observed),
        (true, true, false), "wrong server must refuse before any request byte");
}

#[test]
fn witness_explicit_development_mode_accepts_actual_same_uid_and_bare_ack() {
    let actual_uid = ipc::geteuid();
    let dir = directory();
    let listener = UnixListener::bind(dir.0.join(WITNESS_SOCKET_NAME)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let peer = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            match listener.accept() {
                Ok((stream, _)) => return read_owned_request(stream),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => std::thread::sleep(Duration::from_millis(2)),
                Err(error) => panic!("owned development accept: {error}"),
            }
        }
    });
    let result = WitnessStreamClient::stream_with_mode(&dir.0, "owned-epoch", vec![WitnessFold {
        rpc_seq_u64: 7, scrubbed: MARKER.to_vec(), c_raw: "a".repeat(64), h_ingress_mac: "b".repeat(64),
    }], true);
    let observed = peer.join().unwrap();
    assert_eq!(observed.kernel_client_uid, actual_uid);
    assert!(observed.request_bytes > 4 && observed.complete_marker_observed);
    result.unwrap();
}

#[test]
fn witness_vault_config_defaults_to_strict_production_identity() {
    assert!(!enclave_custody_vaultd::service::VaultConfig::default().dev_same_uid);
}
// Append-only proposal for crates/enclave-custody-vaultd/tests/witness_channel_auth.rs.
// Author: closure_documentation. Not compiled or executed by this lane.
// This exercises VaultConfig -> State -> release -> authenticated producer ->
// real configured receiver admission. It does not observe the private cache.
struct StoredModeNoPeers;
impl enclave_zk_auditor::service::Peers for StoredModeNoPeers {
    fn cosign(&self, _: DaemonId, _: u64, _: &str) -> enclave_core::EnclaveResult<(Vec<u8>, Vec<u8>)> {
        panic!("no proof/cosign in stored-mode fixture")
    }
    fn prepare_relay(&self, _: &[u8]) -> enclave_core::EnclaveResult<ipc::PreparedCall> {
        panic!("no relay in stored-mode fixture")
    }
    fn fetch_witness(&self, _: &str, _: u64, _: u64) -> enclave_core::EnclaveResult<(Vec<enclave_zk_auditor::witness::WitnessFold>, u64)> {
        panic!("no fallback fetch in stored-mode fixture")
    }
    fn boot_epoch(&self) -> enclave_core::EnclaveResult<enclave_core::seq::BootEpoch> {
        panic!("no proof epoch in stored-mode fixture")
    }
}

struct StoredModeServer {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<enclave_core::EnclaveResult<()>>>,
    done: std::sync::mpsc::Receiver<()>,
    path: PathBuf,
}
impl StoredModeServer {
    fn finish(mut self) -> (bool, std::thread::Result<enclave_core::EnclaveResult<()>>) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let prompt = self.done.recv_timeout(Duration::from_secs(2)).is_ok();
        if !prompt { let _ = UnixStream::connect(&self.path); }
        let stopped = self.worker.take().unwrap().join();
        (prompt, stopped)
    }
}
impl Drop for StoredModeServer {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = UnixStream::connect(&self.path);
            let _ = worker.join();
        }
    }
}

#[test]
fn witness_vault_release_preserves_explicit_stored_development_mode_to_real_receiver_admission() {
    use enclave_core::profile::Profile;
    use enclave_custody_vaultd::service::{VaultConfig, VaultHardware, VaultRequest, VaultResponse, VaultService};
    use enclave_zk_auditor::service::{ZkConfig, ZkService};
    use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}, mpsc};

    // The same actual host UID is the deliberately untrusted server in strict
    // mode, and the explicitly allowed server/client in development mode.
    let actual_uid = ipc::geteuid();
    assert_ne!(actual_uid, DaemonId::ZkAuditor.uid(), "fixture requires actual non705 UID");
    let mut counts = Vec::new();
    for dev_same_uid in [false, true] {
        let dir = directory();
        let path = dir.0.join(WITNESS_SOCKET_NAME);
        let listener = UnixListener::bind(&path).unwrap();
        let receiver = ZkService::start(
            ZkConfig::new(Profile::L2, dir.0.join("auditor")), Box::new(StoredModeNoPeers),
        ).unwrap();
        let admitted = Arc::new(AtomicUsize::new(0));
        let worker_admitted = admitted.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let (sender, done) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            // The receiver is explicitly development-only in BOTH subcases,
            // so strict refusal isolates the producer's stored mode wiring.
            let result = enclave_zk_auditor::witness::serve_witness_channel_with_mode_and_admission(
                listener, receiver, worker_stop, true,
                move || { worker_admitted.fetch_add(1, Ordering::SeqCst); Ok(()) },
            );
            let _ = sender.send(());
            result
        });
        let server = StoredModeServer { stop, worker: Some(worker), done, path };
        let service = VaultService::start(
            VaultConfig { profile: Profile::L2, socket_dir: Some(dir.0.clone()),
                dev_same_uid, ..VaultConfig::default() },
            VaultHardware::simulated(Profile::L2, enclave_crypto::time::now_unix()).unwrap(),
        ).unwrap();
        let synthetic = "ordinary owned synthetic fixture text";
        let response = service.handle(
            // local() takes (uid, gid), not pid. This in-process application
            // call uses actual identity values; the UDS path below obtains
            // its own genuine kernel peer credentials independently.
            &ipc::PeerCredentials::local(actual_uid, unsafe { libc::getegid() }),
            VaultRequest::ScrubText { text: synthetic.into(), bulk_set: false, grant: None },
        );
        // Join before terminal assertions. In both modes release returns Text:
        // the existing producer-error suppression remains a transaction debt.
        let (prompt, stopped) = server.finish();
        let count = admitted.load(Ordering::SeqCst);
        counts.push(count);
        assert!(prompt, "owned receiver must stop without cleanup wake");
        stopped.unwrap().unwrap();
        assert!(matches!(response, Ok(VaultResponse::Text(ref text)) if text == synthetic),
            "ordinary scrubbed release should finish; witness errors remain ignored");
    }
    assert_eq!(counts, vec![0, 1], "stored false must reject before receiver admission; explicit true must reach it");
}
