//! Actual Unix-socket regressions for the dedicated witness framing helpers.
//! Timing bounds coordinate owned fixtures; they are not production latency
//! or scheduler SLO acceptance.

use enclave_core::error::EnclaveResult;
use enclave_core::ipc::{read_frame_timed, write_frame_timed, FrameIoLimits, MAX_FRAME};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn limits(cap: usize, whole_ms: u64, idle_ms: u64) -> FrameIoLimits {
    FrameIoLimits { max_frame: cap, frame_deadline: Duration::from_millis(whole_ms),
        idle_timeout: Duration::from_millis(idle_ms) }
}

fn reason<T>(result: EnclaveResult<T>, expected: &str) {
    let error = match result { Err(error) => error, Ok(_) => panic!("unexpected frame success") };
    assert_eq!(error.reason, expected);
}

fn wire(body: &[u8]) -> Vec<u8> {
    let mut result = (body.len() as u32).to_be_bytes().to_vec();
    result.extend_from_slice(body);
    result
}

// Writer has its own absolute cleanup deadline. It never blocks inside an
// unbounded write_all and does not panic on the reader's expected close.
fn sender(mut peer: UnixStream, bytes: Vec<u8>, gap: Duration)
    -> (Arc<AtomicBool>, Arc<AtomicUsize>, thread::JoinHandle<()>)
{
    peer.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let sent = Arc::new(AtomicUsize::new(0));
    let stopped = stop.clone();
    let count = sent.clone();
    let worker = thread::spawn(move || {
        let end = Instant::now() + Duration::from_secs(3);
        let mut position = 0;
        while position < bytes.len() && !stopped.load(Ordering::SeqCst) {
            assert!(Instant::now() < end, "owned sender cleanup deadline");
            let next = if gap.is_zero() { bytes.len() } else { position + 1 };
            match peer.write(&bytes[position..next]) {
                Ok(0) => return,
                Ok(n) => { position += n; count.fetch_add(n, Ordering::SeqCst); }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(e) if matches!(e.kind(), std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset) => return,
                Err(e) => panic!("owned sender: {e}"),
            }
            if !gap.is_zero() && position < bytes.len() {
                let next_send = Instant::now() + gap;
                while Instant::now() < next_send && !stopped.load(Ordering::SeqCst) {
                    thread::sleep(next_send.saturating_duration_since(Instant::now()).min(Duration::from_millis(2)));
                }
            }
        }
    });
    (stop, sent, worker)
}

fn timed_read_with_open_peer(prefix: &[u8], config: FrameIoLimits, expected: &str) {
    let (mut reader, mut peer) = UnixStream::pair().unwrap();
    peer.write_all(prefix).unwrap(); // At most four fixture bytes.
    let (stop, forced, holder) = hold_unread_peer(peer);
    let start = Instant::now();
    let result = read_frame_timed(&mut reader, &config);
    let elapsed = start.elapsed();
    stop.store(true, Ordering::SeqCst);
    drop(reader);
    drop(holder.join().unwrap());
    assert!(!forced.load(Ordering::SeqCst), "read needed peer cleanup shutdown");
    reason(result, expected);
    assert!(elapsed >= Duration::from_millis(40), "timeout returned before fixture budget");
    assert!(elapsed < Duration::from_secs(2), "owned read exceeded cleanup allowance");
}

#[test]
fn witness_frame_policy_uses_existing_cap_whole_deadline_and_idle_window() {
    let actual = FrameIoLimits::witness();
    assert_eq!(actual.max_frame, 1_048_576);
    assert_eq!(actual.max_frame, MAX_FRAME);
    assert_eq!(actual.frame_deadline, Duration::from_secs(30));
    assert_eq!(actual.idle_timeout, Duration::from_millis(1500));
}

#[test]
fn timed_frame_reads_buffered_complete_body_after_peer_close() {
    let (mut reader, mut peer) = UnixStream::pair().unwrap();
    peer.write_all(&wire(b"buffered-before-close")).unwrap();
    drop(peer);
    let actual = read_frame_timed(&mut reader, &limits(64, 1000, 500)).unwrap();
    assert_eq!(actual.as_slice(), b"buffered-before-close");
}

#[test]
fn timed_frame_zero_body_retains_four_byte_header_contract() {
    let (mut reader, mut peer) = UnixStream::pair().unwrap();
    peer.write_all(&[0u8; 4]).unwrap();
    drop(peer);
    assert!(read_frame_timed(&mut reader, &limits(64, 1000, 500)).unwrap().is_empty());
}

#[test]
fn timed_frame_wait_for_first_byte_consumes_whole_frame_deadline() {
    timed_read_with_open_peer(&[], limits(64, 140, 700), "IPC_FRAME_DEADLINE");
}

#[test]
fn timed_frame_wait_for_first_byte_has_distinct_progress_idle_timeout() {
    timed_read_with_open_peer(&[], limits(64, 900, 120), "IPC_FRAME_IDLE_TIMEOUT");
}

#[test]
fn timed_frame_every_partial_header_expires_without_body_or_peer_close() {
    let header = 4u32.to_be_bytes();
    for length in 1..=3 {
        println!("partial header bytes={length}");
        timed_read_with_open_peer(&header[..length], limits(64, 110, 700), "IPC_FRAME_DEADLINE");
    }
}

#[test]
fn timed_frame_trickle_cannot_reset_whole_deadline_at_header_body_boundary() {
    let (mut reader, peer) = UnixStream::pair().unwrap();
    // Header finishes after about150ms, full body after about350ms. A wrong
    // reset at the header boundary would accept, while the220ms total must fail.
    let (stop, sent, worker) = sender(peer, wire(b"four"), Duration::from_millis(50));
    let start = Instant::now();
    let result = read_frame_timed(&mut reader, &limits(64, 220, 160));
    let elapsed = start.elapsed();
    stop.store(true, Ordering::SeqCst);
    drop(reader);
    worker.join().unwrap();
    reason(result, "IPC_FRAME_DEADLINE");
    assert!(sent.load(Ordering::SeqCst) >= 3, "actual trickle progression was not reached");
    assert!(elapsed >= Duration::from_millis(150));
    assert!(elapsed < Duration::from_secs(2));
}

#[test]
fn timed_frame_real_progress_renews_idle_without_replacing_whole_deadline() {
    let (mut reader, peer) = UnixStream::pair().unwrap();
    let (stop, sent, worker) = sender(peer, wire(b"abc"), Duration::from_millis(40));
    let start = Instant::now();
    let result = read_frame_timed(&mut reader, &limits(64, 1200, 130));
    let elapsed = start.elapsed();
    stop.store(true, Ordering::SeqCst);
    drop(reader);
    worker.join().unwrap();
    assert_eq!(result.unwrap().as_slice(), b"abc");
    assert_eq!(sent.load(Ordering::SeqCst), 7);
    assert!(elapsed >= Duration::from_millis(180), "fixture did not cross initial idle interval");
    assert!(elapsed < Duration::from_secs(2));
}

#[test]
fn timed_frame_exact_existing_global_body_cap_is_accepted() {
    let (mut reader, peer) = UnixStream::pair().unwrap();
    let (stop, sent, worker) = sender(peer, wire(&vec![0x5a; MAX_FRAME]), Duration::ZERO);
    let result = read_frame_timed(&mut reader, &limits(MAX_FRAME, 2000, 1000));
    stop.store(true, Ordering::SeqCst);
    drop(reader);
    worker.join().unwrap();
    let actual = result.unwrap();
    assert_eq!(actual.len(), MAX_FRAME);
    assert!(actual.iter().all(|byte| *byte == 0x5a));
    assert_eq!(sent.load(Ordering::SeqCst), MAX_FRAME + 4);
}

#[test]
fn timed_frame_oversize_header_refuses_before_waiting_for_missing_body() {
    for configured_cap in [32, MAX_FRAME] {
        let (mut reader, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(&((configured_cap + 1) as u32).to_be_bytes()).unwrap();
        // Keep the peer open and send no body: E2BIG must precede body read.
        let (stop, forced, holder) = hold_unread_peer(peer);
        let result = read_frame_timed(&mut reader, &limits(configured_cap, 1000, 500));
        stop.store(true, Ordering::SeqCst);
        drop(reader);
        drop(holder.join().unwrap());
        assert!(!forced.load(Ordering::SeqCst));
        reason(result, "IPC_FRAME_TOO_LARGE");
    }
}

#[test]
fn timed_frame_partial_body_eof_is_read_error_without_success() {
    let (mut reader, mut peer) = UnixStream::pair().unwrap();
    peer.write_all(&8u32.to_be_bytes()).unwrap();
    peer.write_all(b"part").unwrap();
    drop(peer);
    reason(read_frame_timed(&mut reader, &limits(64, 1000, 500)), "IPC_READ");
}

#[test]
fn timed_frame_write_excess_sends_no_header_byte() {
    let (mut writer, mut peer) = UnixStream::pair().unwrap();
    peer.set_nonblocking(true).unwrap();
    let result = write_frame_timed(&mut writer, &[1u8; 33], &limits(32, 1000, 500));
    let observed = peer.read(&mut [0u8; 1]);
    drop(writer);
    drop(peer);
    reason(result, "IPC_FRAME_TOO_LARGE");
    assert_eq!(observed.unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
}

fn constrain_send_buffer(stream: &UnixStream) {
    let desired: libc::c_int = 4096;
    // SAFETY: the borrowed stream owns a live socket; pointers/length refer
    // only to a properly aligned local integer for this synchronous call.
    let result = unsafe { libc::setsockopt(stream.as_raw_fd(), libc::SOL_SOCKET,
        libc::SO_SNDBUF, std::ptr::addr_of!(desired).cast(),
        std::mem::size_of_val(&desired) as libc::socklen_t) };
    assert_eq!(result, 0, "owned send-buffer setup must succeed");
    let mut actual: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&actual) as libc::socklen_t;
    // SAFETY: same live descriptor and valid writable integer/length storage.
    let result = unsafe { libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET,
        libc::SO_SNDBUF, std::ptr::addr_of_mut!(actual).cast(), &mut length) };
    assert_eq!(result, 0);
    assert!(actual > 0 && (actual as usize) < MAX_FRAME, "fixture must force real backpressure");
}

fn hold_unread_peer(peer: UnixStream)
    -> (Arc<AtomicBool>, Arc<AtomicBool>, thread::JoinHandle<UnixStream>)
{
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let forced = Arc::new(AtomicBool::new(false));
    let forced_cleanup = forced.clone();
    let holder = thread::spawn(move || {
        let end = Instant::now() + Duration::from_secs(3);
        while !stopped.load(Ordering::SeqCst) && Instant::now() < end {
            thread::sleep(Duration::from_millis(2));
        }
        if !stopped.load(Ordering::SeqCst) {
            forced_cleanup.store(true, Ordering::SeqCst);
            // A broken blocking reader/writer must still release for cleanup.
            let _ = peer.shutdown(std::net::Shutdown::Both);
        }
        peer
    });
    (stop, forced, holder)
}

fn unread_peer_write_timeout(config: FrameIoLimits, expected: &str) {
    let (mut writer, peer) = UnixStream::pair().unwrap();
    constrain_send_buffer(&writer);
    let (stop, forced, holder) = hold_unread_peer(peer);
    let start = Instant::now();
    let result = write_frame_timed(&mut writer, &vec![0x5a; MAX_FRAME], &config);
    let elapsed = start.elapsed();
    stop.store(true, Ordering::SeqCst);
    drop(writer);
    let mut peer = holder.join().unwrap();
    let bytes = drain_closed(&mut peer);
    reason(result, expected);
    assert!(!forced.load(Ordering::SeqCst), "frame writer needed cleanup shutdown");
    assert!(elapsed >= Duration::from_millis(40) && elapsed < Duration::from_secs(2));
    assert!(bytes.len() >= 4 && bytes.len() < MAX_FRAME + 4, "fixture must observe actual partial handoff");
    assert_eq!(&bytes[..4], &(MAX_FRAME as u32).to_be_bytes());
}

fn drain_closed(peer: &mut UnixStream) -> Vec<u8> {
    peer.set_nonblocking(true).unwrap();
    let end = Instant::now() + Duration::from_secs(3);
    let mut actual = Vec::new();
    loop {
        assert!(Instant::now() < end, "closed peer drain deadline");
        let mut chunk = [0u8; 8192];
        match peer.read(&mut chunk) {
            Ok(0) => return actual,
            Ok(count) => {
                assert!(actual.len() + count <= MAX_FRAME + 4, "unexpected excess wire bytes");
                actual.extend_from_slice(&chunk[..count]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(1)),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => panic!("closed peer drain: {error}"),
        }
    }
}

#[test]
fn timed_frame_write_backpressure_obeys_whole_frame_deadline() {
    unread_peer_write_timeout(limits(MAX_FRAME, 140, 700), "IPC_FRAME_DEADLINE");
}

#[test]
fn timed_frame_write_backpressure_retains_distinct_idle_timeout() {
    unread_peer_write_timeout(limits(MAX_FRAME, 1000, 120), "IPC_FRAME_IDLE_TIMEOUT");
}

#[test]
fn timed_frame_write_preserves_independent_raw_header_and_body_oracle() {
    let (mut writer, mut peer) = UnixStream::pair().unwrap();
    let result = write_frame_timed(&mut writer, b"ordinary", &limits(64, 1000, 500));
    drop(writer);
    let actual = drain_closed(&mut peer);
    result.unwrap();
    assert_eq!(actual, wire(b"ordinary"));
}

#[test]
fn timed_frame_larger_custom_limit_cannot_override_global_protocol_cap() {
    let (mut reader, mut peer) = UnixStream::pair().unwrap();
    peer.write_all(&((MAX_FRAME + 1) as u32).to_be_bytes()).unwrap();
    reason(read_frame_timed(&mut reader, &limits(2 * MAX_FRAME, 1000, 500)), "IPC_FRAME_TOO_LARGE");
    let (mut writer, mut observer) = UnixStream::pair().unwrap();
    observer.set_nonblocking(true).unwrap();
    let result = write_frame_timed(&mut writer, &vec![0; MAX_FRAME + 1], &limits(2 * MAX_FRAME, 1000, 500));
    let observed = observer.read(&mut [0; 1]);
    drop(writer);
    reason(result, "IPC_FRAME_TOO_LARGE");
    assert_eq!(observed.unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
}
