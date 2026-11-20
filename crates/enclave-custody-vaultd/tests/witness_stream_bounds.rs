//! Real witness-stream framing and encoding-allocation boundaries.

use enclave_core::daemon::{DaemonId, WITNESS_SOCKET_NAME};
use enclave_core::ipc::{read_frame, write_frame, ServeLimits};
use enclave_custody_vaultd::ingress::{
    WitnessChannelRequest, WitnessChannelResponse, WitnessFold, WitnessStreamClient,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::Read;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static MAX_REQUEST: Cell<usize> = const { Cell::new(0) };
    static REQUESTED: Cell<usize> = const { Cell::new(0) };
}

struct MeasuredAllocator;
fn observe(bytes: usize) {
    let _ = TRACK.try_with(|enabled| {
        if enabled.get() {
            MAX_REQUEST.with(|max| max.set(max.get().max(bytes)));
            REQUESTED.with(|sum| sum.set(sum.get().saturating_add(bytes)));
        }
    });
}
unsafe impl GlobalAlloc for MeasuredAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        observe(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        observe(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        observe(size);
        unsafe { System.realloc(ptr, layout, size) }
    }
}
#[global_allocator]
static ALLOCATOR: MeasuredAllocator = MeasuredAllocator;

struct Tracking;
impl Tracking {
    fn start() -> Self {
        MAX_REQUEST.with(|v| v.set(0));
        REQUESTED.with(|v| v.set(0));
        TRACK.with(|v| assert!(!v.replace(true)));
        Self
    }
    fn finish(self) -> (usize, usize) {
        drop(self);
        (MAX_REQUEST.with(Cell::get), REQUESTED.with(Cell::get))
    }
}
impl Drop for Tracking {
    fn drop(&mut self) { TRACK.with(|v| v.set(false)); }
}

struct SocketDir(PathBuf);
impl SocketDir {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!("wb{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir(&path).unwrap();
        std::fs::create_dir_all(path.join(WITNESS_SOCKET_NAME).parent().unwrap()).unwrap();
        Self(path)
    }
}
impl Drop for SocketDir {
    fn drop(&mut self) { std::fs::remove_dir_all(&self.0).unwrap(); }
}

fn cap() -> usize { ServeLimits::for_daemon(DaemonId::ZkAuditor, false).max_frame }
fn fold(bytes: usize) -> WitnessFold {
    WitnessFold { rpc_seq_u64: 7, scrubbed: vec![b'x'; bytes], c_raw: "a".repeat(64), h_ingress_mac: "b".repeat(64) }
}
fn encoded(epoch: &str, folds: &[WitnessFold]) -> Vec<u8> {
    let request = WitnessChannelRequest::StreamWitness { boot_epoch_id: epoch.into(), folds: folds.to_vec() };
    let mut body = Vec::new();
    ciborium::into_writer(&request, &mut body).unwrap();
    body
}
fn exact_folds(extra: usize) -> Vec<WitnessFold> {
    let mut folds = vec![fold(cap() - 1024)];
    let len = encoded("epoch", &folds).len();
    let padded = folds[0].scrubbed.len() + cap() - len + extra;
    folds[0].scrubbed.resize(padded, b'x');
    assert_eq!(encoded("epoch", &folds).len(), cap() + extra);
    folds
}

fn accepted(epoch: &str, folds: Vec<WitnessFold>, response: Vec<u8>) -> (enclave_core::error::EnclaveResult<()>, usize, usize) {
    let expected = encoded(epoch, &folds);
    let dir = SocketDir::new();
    let listener = UnixListener::bind(dir.0.join(WITNESS_SOCKET_NAME)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let peer = thread::spawn(move || {
        let end = Instant::now() + Duration::from_secs(5);
        let mut conn = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < end => thread::sleep(Duration::from_millis(2)),
                Err(e) => panic!("accept: {e}"),
            }
        };
        conn.set_nonblocking(false).unwrap();
        conn.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        conn.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        let actual = read_frame(&mut conn).unwrap();
        assert_eq!(actual.len(), expected.len(), "wire body length changed");
        assert!(actual == expected, "wire schema changed");
        let _: WitnessChannelRequest = ciborium::from_reader(actual.as_slice()).unwrap();
        write_frame(&mut conn, &response).unwrap();
    });
    let tracking = Tracking::start();
    let result = WitnessStreamClient::stream_with_mode(&dir.0, epoch, folds, true);
    let (max, total) = tracking.finish();
    peer.join().unwrap();
    (result, max, total)
}
fn ack() -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(&WitnessChannelResponse::Ack, &mut bytes).unwrap();
    bytes
}

fn refused(epoch: &str, folds: Vec<WitnessFold>) {
    let dir = SocketDir::new();
    let listener = UnixListener::bind(dir.0.join(WITNESS_SOCKET_NAME)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let peer = thread::spawn(move || {
        let end = Instant::now() + Duration::from_secs(2);
        loop {
            match listener.accept() {
                Ok((mut conn, _)) => {
                    // Darwin can reject SO_RCVTIMEO after the client has
                    // already closed. Observe EOF/first byte with a fixed
                    // deadline without configuring that disconnected socket.
                    conn.set_nonblocking(true).unwrap();
                    let read_end = Instant::now() + Duration::from_secs(3);
                    loop {
                        assert!(Instant::now() < read_end, "refusal peer did not reach EOF");
                        match conn.read(&mut [0u8; 1]) {
                            Ok(bytes) => return bytes,
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(2)),
                            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                            Err(e) => panic!("refusal peer read: {e}"),
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < end => thread::sleep(Duration::from_millis(2)),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return 0,
                Err(e) => panic!("accept: {e}"),
            }
        }
    });
    let tracking = Tracking::start();
    let result = WitnessStreamClient::stream_with_mode(&dir.0, epoch, folds, true);
    let (max, total) = tracking.finish();
    let wire_bytes = peer.join().unwrap();
    println!("stream allocation requests: max={max} cumulative={total}; wire_bytes={wire_bytes}");
    assert_eq!(result.unwrap_err().reason, "WITNESS_FRAME_TOO_LARGE");
    assert_eq!(wire_bytes, 0, "encoding refusal must precede every wire byte");
    assert!(max <= cap(), "oversized allocation request: {max} > {}", cap());
}

#[test]
fn witness_stream_small_valid_preserves_wire_and_ack() {
    let (result, max, _) = accepted("epoch", vec![fold(3)], ack());
    result.unwrap();
    assert!(max <= cap());
}
#[test]
fn witness_stream_exact_existing_frame_cap_is_accepted_with_bounded_encoding() {
    let (result, max, total) = accepted("epoch", exact_folds(0), ack());
    println!("stream allocation requests: max={max} cumulative={total}");
    result.unwrap();
    assert!(max <= cap(), "encoding allocation exceeds existing frame cap: {max}");
}
#[test]
fn witness_stream_cap_plus_one_refuses_without_transmit_or_oversize_allocation() { refused("epoch", exact_folds(1)); }
#[test]
fn witness_stream_large_scrubbed_refuses_without_transmit_or_oversize_allocation() { refused("epoch", vec![fold(4 * cap())]); }
#[test]
fn witness_stream_large_epoch_refuses_without_transmit_or_oversize_allocation() { refused(&"e".repeat(4 * cap()), vec![fold(0)]); }
#[test]
fn witness_stream_many_small_folds_refuse_without_transmit_or_oversize_allocation() { refused("epoch", (0..16384).map(|_| fold(0)).collect()); }
#[test]
fn witness_stream_absent_listener_preserves_best_effort_contract() {
    let dir = SocketDir::new();
    let epoch = "e".repeat(4 * cap());
    let tracking = Tracking::start();
    let result = WitnessStreamClient::stream(&dir.0, &epoch, vec![]);
    let (max, _) = tracking.finish();
    result.unwrap();
    assert!(max < cap());
}
#[test]
fn witness_stream_malformed_response_remains_decode_error() {
    let (result, _, _) = accepted("epoch", vec![fold(0)], vec![0xff]);
    assert_eq!(result.unwrap_err().reason, "WITNESS_DECODE");
}
#[test]
fn witness_stream_non_ack_remains_unexpected_response() {
    let mut response = Vec::new();
    ciborium::into_writer(&WitnessChannelResponse::Witness { folds: vec![], next_slot: 0 }, &mut response).unwrap();
    let (result, _, _) = accepted("epoch", vec![fold(0)], response);
    assert_eq!(result.unwrap_err().reason, "WITNESS_UNEXPECTED_RESP");
}
