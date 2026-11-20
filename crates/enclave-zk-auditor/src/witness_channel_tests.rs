//! Actual witness listener policy, framing, recovery and lifecycle regressions.
//! Actual kernel same-UID fixtures, not installed703/signing acceptance.
use super::*;
use crate::service::{Peers, ZkConfig, ZkService};
use enclave_core::ipc::{self, FrameIoLimits, PeerPolicy};
use enclave_core::profile::Profile;
use enclave_core::seq::BootEpoch;
use enclave_core::{err, EnclaveResult};
use std::io::{Read, Write};
use std::os::unix::{
    fs::DirBuilderExt,
    net::{UnixListener, UnixStream},
};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc, Arc, Barrier,
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct NoPeers;
impl Peers for NoPeers {
    fn cosign(&self, _: DaemonId, _: u64, _: &str) -> EnclaveResult<(Vec<u8>, Vec<u8>)> {
        panic!("no proof in channel fixture")
    }
    fn prepare_relay(&self, _: &[u8]) -> EnclaveResult<ipc::PreparedCall> {
        panic!("no relay in channel fixture")
    }
    fn fetch_witness(&self, _: &str, _: u64, _: u64) -> EnclaveResult<(Vec<WitnessFold>, u64)> {
        panic!("no fetch in channel fixture")
    }
    fn boot_epoch(&self) -> EnclaveResult<BootEpoch> {
        panic!("no proof epoch in channel fixture")
    }
}
enum Mode {
    Inner(FrameIoLimits),
    Configured(bool),
    LegacyStrict,
}
struct Server {
    _directory: Directory,
    path: PathBuf,
    stop: Arc<AtomicBool>,
    done: mpsc::Receiver<()>,
    worker: Option<JoinHandle<EnclaveResult<()>>>,
}
impl Server {
    fn start(mode: Mode, admission: impl Fn() -> EnclaveResult<()> + Send + 'static) -> Self {
        let directory = Directory(std::env::temp_dir().join(format!(
            "wc{}-{:x}",
            std::process::id(),
            enclave_core::rng::u64() & 0xfffffff
        )));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory.0)
            .unwrap();
        let path = directory.0.join("w");
        let listener = UnixListener::bind(&path).unwrap();
        let service = ZkService::start(
            ZkConfig::new(Profile::L2, directory.0.join("state")),
            Box::new(NoPeers),
        )
        .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let (sender, done) = mpsc::sync_channel(1);
        let start = Arc::new(Barrier::new(2));
        let worker_start = start.clone();
        let worker = std::thread::spawn(move || {
            worker_start.wait();
            let result = match mode {
                Mode::Inner(frame_io) => serve_witness_channel_inner(
                    listener,
                    service,
                    worker_stop,
                    admission,
                    PeerPolicy::allow([ipc::geteuid()]),
                    frame_io,
                ),
                Mode::Configured(dev) => serve_witness_channel_with_mode_and_admission(
                    listener,
                    service,
                    worker_stop,
                    dev,
                    admission,
                ),
                Mode::LegacyStrict => {
                    serve_witness_channel_with_admission(listener, service, worker_stop, admission);
                    Ok(())
                }
            };
            let _ = sender.send(());
            result
        });
        start.wait();
        Self {
            _directory: directory,
            path,
            stop,
            done,
            worker: Some(worker),
        }
    }
    fn finish(mut self) -> (bool, std::thread::Result<EnclaveResult<()>>) {
        self.stop.store(true, Ordering::SeqCst);
        let prompt = self.done.recv_timeout(Duration::from_secs(2)).is_ok();
        if !prompt {
            let _ = UnixStream::connect(&self.path);
        }
        let result = self.worker.take().unwrap().join();
        (prompt, result)
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            self.stop.store(true, Ordering::SeqCst);
            let _ = UnixStream::connect(&self.path);
            let _ = worker.join();
        }
    }
}
fn io_timeout() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "owned fixture absolute deadline",
    )
}
fn read_exact_until(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> std::io::Result<()> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err(io_timeout());
        }
        match stream.read(bytes) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(2))
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
fn write_until(
    stream: &mut UnixStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> std::io::Result<()> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err(io_timeout());
        }
        match stream.write(bytes) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::WriteZero)),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(2))
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
fn request(slot: u64) -> Vec<u8> {
    let mut body = Vec::new();
    ciborium::into_writer(
        &WitnessChannelRequest::StreamWitness {
            boot_epoch_id: enclave_core::seq::new_boot_epoch_id(),
            folds: vec![WitnessFold {
                rpc_seq_u64: slot,
                scrubbed: b"owned-safe".to_vec(),
                c_raw: "a".repeat(64),
                h_ingress_mac: "b".repeat(64),
            }],
        },
        &mut body,
    )
    .unwrap();
    let mut framed = (body.len() as u32).to_be_bytes().to_vec();
    framed.extend(body);
    framed
}
fn exchange(path: &std::path::Path, framed: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_nonblocking(true)?;
    let deadline = Instant::now() + Duration::from_secs(3);
    write_until(&mut stream, framed, deadline)?;
    let mut size = [0; 4];
    read_exact_until(&mut stream, &mut size, deadline)?;
    let length = u32::from_be_bytes(size) as usize;
    if length > 1_048_576 {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
    }
    let mut body = vec![0; length];
    read_exact_until(&mut stream, &mut body, deadline)?;
    Ok(body)
}
fn is_ack(result: &std::io::Result<Vec<u8>>) -> bool {
    result.as_ref().is_ok_and(|body| {
        matches!(
            ciborium::from_reader::<WitnessChannelResponse, _>(body.as_slice()),
            Ok(WitnessChannelResponse::Ack)
        )
    })
}
fn short_limits() -> FrameIoLimits {
    FrameIoLimits {
        max_frame: ipc::ServeLimits::for_daemon(DaemonId::ZkAuditor, false).max_frame,
        frame_deadline: Duration::from_millis(250),
        idle_timeout: Duration::from_millis(200),
    }
}

#[test]
fn channel_explicit_development_mode_accepts_actual_kernel_peer_and_bare_ack() {
    let admitted = Arc::new(AtomicUsize::new(0));
    let recorded = admitted.clone();
    let server = Server::start(Mode::Configured(true), move || {
        recorded.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    let response = exchange(&server.path, &request(1));
    let (prompt, stopped) = server.finish();
    assert!(
        is_ack(&response),
        "actual same-UID request must reach real dispatch before Ack"
    );
    assert_eq!(admitted.load(Ordering::SeqCst), 1);
    assert!(prompt);
    stopped.unwrap().unwrap();
}

#[test]
fn channel_strict_and_legacy_wrappers_reject_actual_wrong_uid_before_admission() {
    assert_ne!(
        ipc::geteuid(),
        DaemonId::CustodyVault.uid(),
        "fixture requires actual non703 UID"
    );
    for mode in [Mode::Configured(false), Mode::LegacyStrict] {
        let admitted = Arc::new(AtomicUsize::new(0));
        let recorded = admitted.clone();
        let server = Server::start(mode, move || {
            recorded.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        let response = exchange(&server.path, &request(1));
        let (prompt, stopped) = server.finish();
        assert!(!is_ack(&response));
        assert_eq!(admitted.load(Ordering::SeqCst), 0);
        assert!(prompt);
        stopped.unwrap().unwrap();
    }
}

#[test]
fn channel_admission_refusal_has_no_ack_then_next_allowed_client_succeeds() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let recorded = attempts.clone();
    let server = Server::start(Mode::Inner(short_limits()), move || {
        if recorded.fetch_add(1, Ordering::SeqCst) == 0 {
            Err(err!(EPERM, "OWNED_TEST_ADMISSION_REFUSAL"))
        } else {
            Ok(())
        }
    });
    let first = exchange(&server.path, &request(1));
    let second = exchange(&server.path, &request(2));
    let (prompt, stopped) = server.finish();
    assert!(!is_ack(&first));
    assert!(is_ack(&second));
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert!(prompt);
    stopped.unwrap().unwrap();
}

fn slow_frame_refused_then_next_client_succeeds(body: bool) {
    let admitted = Arc::new(AtomicUsize::new(0));
    let recorded = admitted.clone();
    let server = Server::start(Mode::Inner(short_limits()), move || {
        recorded.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    let path = server.path.clone();
    let (cancel, cancelled) = mpsc::channel();
    let (started, first_byte_written) = mpsc::sync_channel(1);
    let first = std::thread::spawn(move || -> std::io::Result<Duration> {
        let mut stream = UnixStream::connect(path)?;
        stream.set_nonblocking(true)?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let framed = request(1);
        let already = if body { 5 } else { 1 };
        write_until(&mut stream, &framed[..already], deadline)?;
        let _ = started.send(());
        let mut last_write = Instant::now();
        let mut maximum_gap = Duration::ZERO;
        for byte in &framed[already..] {
            match cancelled.recv_timeout(Duration::from_millis(100)) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    maximum_gap = maximum_gap.max(last_write.elapsed());
                    break;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            maximum_gap = maximum_gap.max(last_write.elapsed());
            match write_until(&mut stream, std::slice::from_ref(byte), deadline) {
                Ok(()) => last_write = Instant::now(),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                    ) =>
                {
                    break
                }
                Err(error) => return Err(error),
            }
        }
        Ok(maximum_gap)
    });
    let entered = first_byte_written.recv_timeout(Duration::from_secs(1));
    let path = server.path.clone();
    let (sent, finished) = mpsc::sync_channel(1);
    let second = std::thread::spawn(move || {
        let response = exchange(&path, &request(2));
        let _ = sent.send(is_ack(&response));
        response
    });
    let recovered_while_first_still_incomplete = finished.recv_timeout(Duration::from_secs(1));
    let _ = cancel.send(());
    let first_result = first.join();
    let second_result = second.join();
    let (prompt, stopped) = server.finish();
    assert!(entered.is_ok());
    assert_eq!(
        recovered_while_first_still_incomplete.ok(),
        Some(true),
        "slow frame must not retain only listener past injected bound"
    );
    let maximum_gap = first_result.unwrap().unwrap();
    assert!(
        maximum_gap < Duration::from_millis(200),
        "fixture stalled past idle timeout; cannot attribute refusal to whole-frame deadline"
    );
    assert!(is_ack(&second_result.unwrap()));
    assert_eq!(
        admitted.load(Ordering::SeqCst),
        1,
        "incomplete first request must never reach admission/dispatch"
    );
    assert!(prompt);
    stopped.unwrap().unwrap();
}
#[test]
fn channel_header_trickle_cannot_renew_whole_frame_deadline_and_next_client_recovers() {
    slow_frame_refused_then_next_client_succeeds(false);
}
#[test]
fn channel_body_trickle_cannot_renew_whole_frame_deadline_and_next_client_recovers() {
    slow_frame_refused_then_next_client_succeeds(true);
}

#[test]
fn channel_idle_stop_completes_without_cleanup_wake_connection() {
    let server = Server::start(Mode::Inner(short_limits()), || Ok(()));
    // Scheduling opportunity following the start barrier; this is bounded idle
    // lifecycle coverage, not a deterministic observation of kernel accept entry.
    std::thread::sleep(Duration::from_millis(50));
    let (without_wake, stopped) = server.finish();
    assert!(
        without_wake,
        "new idle listener must observe stop without a wake connection"
    );
    stopped.unwrap().unwrap();
}

#[test]
fn channel_partial_frame_stop_is_bounded_by_test_io_limits_without_admission() {
    let admitted = Arc::new(AtomicUsize::new(0));
    let recorded = admitted.clone();
    let server = Server::start(Mode::Inner(short_limits()), move || {
        recorded.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    let mut stream = UnixStream::connect(&server.path).unwrap();
    stream.set_nonblocking(true).unwrap();
    let sent = write_until(
        &mut stream,
        &[0, 0],
        Instant::now() + Duration::from_secs(1),
    );
    // Active reads are bounded by frame/idle policy, not immediately cancelled.
    // Keep the peer alive while finish requests stop and awaits that bound.
    std::thread::sleep(Duration::from_millis(50));
    let (prompt, stopped) = server.finish();
    drop(stream);
    sent.unwrap();
    assert!(prompt);
    stopped.unwrap().unwrap();
    assert_eq!(admitted.load(Ordering::SeqCst), 0);
}

#[test]
fn channel_oversize_and_malformed_requests_do_not_admit_then_valid_client_recovers() {
    let admitted = Arc::new(AtomicUsize::new(0));
    let recorded = admitted.clone();
    let server = Server::start(Mode::Inner(short_limits()), move || {
        recorded.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    let oversize = exchange(&server.path, &((ipc::MAX_FRAME + 1) as u32).to_be_bytes());
    let malformed = exchange(&server.path, &[0, 0, 0, 1, 0xff]);
    let valid = exchange(&server.path, &request(3));
    let (prompt, stopped) = server.finish();
    assert!(!is_ack(&oversize) && !is_ack(&malformed));
    assert!(is_ack(&valid));
    assert_eq!(admitted.load(Ordering::SeqCst), 1);
    assert!(prompt);
    stopped.unwrap().unwrap();
}
