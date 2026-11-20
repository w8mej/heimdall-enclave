//! Proposed public-API loopback regressions. No compiler/execution by author.
//! HTTP 200 here is software status acceptance, never authenticated custody.
use std::{io::{Read, Write}, net::{Shutdown, TcpListener, TcpStream}, sync::mpsc,
    thread::{self, JoinHandle}, time::{Duration, Instant}};
use enclave_swarm_syncd::outbox::{OutboxTransport, TcpOutboxTransport};

const PAYLOAD: &[u8] = b"owned-test-ciphertext";
const REQUEST_CAP: usize = 32 * 1024;
const HEADER_CAP: usize = 16 * 1024;

fn expected_request(host: &str) -> Vec<u8> {
    let mut request = format!("POST /v1/rollup HTTP/1.1\r\nHost: {host}\r\nContent-Type: message/ohttp-req\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", PAYLOAD.len()).into_bytes();
    request.extend_from_slice(PAYLOAD); request
}

// The server runs on the test thread: only the product call needs a worker.
// Drop closes every owned socket before always joining that worker, including
// assertion/setup unwinding. No detached or unjoined server thread exists.
struct Exchange {
    listener: Option<TcpListener>,
    peer: Option<TcpStream>,
    worker: Option<JoinHandle<bool>>,
    done: mpsc::Receiver<bool>,
    observed: Option<bool>,
}
impl Exchange {
    fn start(host: &str) -> Self {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap(); let host = host.to_owned();
        let (tx, done) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            let ok = TcpOutboxTransport::new(address, host).transmit(PAYLOAD).is_ok();
            let _ = tx.send(ok); ok
        });
        Self { listener: Some(listener), peer: None, worker: Some(worker), done, observed: None }
    }
    fn accept_or_completion(&mut self) -> bool {
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            match self.listener.as_ref().unwrap().accept() {
                Ok((peer, _)) => { peer.set_nonblocking(false).unwrap(); self.peer = Some(peer); return true; },
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {},
                Err(error) => panic!("owned listener accept failed: {error}"),
            }
            if self.observed.is_some() || Instant::now() >= deadline { return false; }
            match self.done.recv_timeout(Duration::from_millis(5)) {
                Ok(ok) => self.observed = Some(ok),
                Err(mpsc::RecvTimeoutError::Timeout) => {},
                Err(mpsc::RecvTimeoutError::Disconnected) => return false,
            }
            // A completed client is not by itself proof of no connect: the next
            // loop performs a final accept after observing completion, catching
            // a completed connection still queued before the client returned.
        }
    }
    fn close_peer(&mut self) {
        if let Some(peer) = self.peer.take() { let _ = peer.shutdown(Shutdown::Both); }
    }
    fn observe(&mut self, duration: Duration) -> bool {
        if self.observed.is_some() { return true; }
        match self.done.recv_timeout(duration) {
            Ok(ok) => { self.observed = Some(ok); true },
            Err(_) => false,
        }
    }
    fn finish(mut self) -> (bool, bool) {
        self.close_peer();
        // Stop the listener before joining: a product still trying to connect
        // cannot become stuck on a fixture that no longer services requests.
        self.listener.take();
        let joined = self.worker.take().unwrap().join();
        (joined.as_ref().is_ok_and(|ok| *ok), joined.is_ok())
    }
}
impl Drop for Exchange {
    fn drop(&mut self) {
        self.close_peer(); self.listener.take();
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}

#[derive(Debug)]
struct Outcome {
    accepted: bool,
    client_ok: bool,
    joined_without_panic: bool,
    request_complete: bool,
    request_exact: bool,
    request_bytes: usize,
    response_written: bool,
    completed_before_eof: bool,
    final_accept_after_completion: bool,
}

fn request(peer: &mut TcpStream) -> (Vec<u8>, bool) {
    peer.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut bytes = Vec::new(); let mut chunk = [0u8; 512];
    while Instant::now() < deadline && bytes.len() < REQUEST_CAP {
        let available = chunk.len().min(REQUEST_CAP - bytes.len());
        match peer.read(&mut chunk[..available]) {
            Ok(0) => break,
            Ok(count) => {
                bytes.extend_from_slice(&chunk[..count]);
                if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                    if bytes.len() >= end + 4 + PAYLOAD.len() { return (bytes, true); }
                }
            },
            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted) => {},
            Err(_) => break,
        }
    }
    (bytes, false)
}

fn exchange(host: &str, response: &[u8], hold_open: bool) -> Outcome {
    let mut running = Exchange::start(host);
    let accepted = running.accept_or_completion();
    let mut bytes = Vec::new(); let mut complete = false; let mut written = false;
    let mut before_eof = false;
    if accepted {
        let peer = running.peer.as_mut().unwrap();
        (bytes, complete) = request(peer);
        peer.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        written = peer.write_all(response).and_then(|_| peer.flush()).is_ok();
        if hold_open {
            // Deliberate channel coordination while this actual peer stays
            // open; no read timeout/latency SLO is inferred from this fixture.
            before_eof = running.observe(Duration::from_secs(3));
        }
        running.close_peer();
        running.observe(Duration::from_secs(5));
    }
    // For early validation refusal this is an accept after transmit completed.
    // It catches a connection queued just before a client-side refusal/return.
    let mut final_checked = false;
    let mut unexpected_connection = false;
    if running.observed.is_some() {
        final_checked = true;
        match running.listener.as_ref().unwrap().accept() {
            Ok((peer, _)) => { unexpected_connection = true; let _ = peer.shutdown(Shutdown::Both); },
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {},
            Err(error) => panic!("owned final accept failed: {error}"),
        }
    }
    let (client_ok, joined_without_panic) = running.finish();
    Outcome { accepted: accepted || unexpected_connection, client_ok, joined_without_panic,
        request_complete: complete, request_exact: bytes == expected_request(host), request_bytes: bytes.len(),
        response_written: written, completed_before_eof: before_eof,
        final_accept_after_completion: final_checked }
}

fn ordinary() -> Vec<u8> { b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec() }
fn padded_response(length: usize) -> Vec<u8> {
    let prefix = b"HTTP/1.1 200 OK\r\nX-Owned-Padding: "; let suffix = b"\r\n\r\n";
    assert!(length >= prefix.len() + suffix.len());
    let mut bytes = prefix.to_vec(); bytes.resize(length - suffix.len(), b'a'); bytes.extend_from_slice(suffix);
    assert_eq!(bytes.len(), length); bytes
}
fn assert_real_exchange(outcome: &Outcome) {
    assert!(outcome.accepted && outcome.joined_without_panic && outcome.request_complete && outcome.request_exact
        && outcome.response_written && outcome.final_accept_after_completion, "owned real exchange must complete: {outcome:?}");
}

#[test]
fn tcp_exact_status_accepts_http10_and_http11_200() {
    for version in ["HTTP/1.0", "HTTP/1.1"] {
        let response = format!("{version} 200 OK\r\nContent-Length: 0\r\n\r\n");
        let outcome = exchange("ledger.example", response.as_bytes(), false);
        assert_real_exchange(&outcome); assert!(outcome.client_ok, "{outcome:?}");
    }
}

#[test]
fn tcp_exact_status_refuses_2000_after_real_request() {
    let outcome = exchange("ledger.example", b"HTTP/1.1 2000 OK\r\nContent-Length: 0\r\n\r\n", false);
    assert_real_exchange(&outcome); assert!(!outcome.client_ok, "status2000 must not authorize acceptance: {outcome:?}");
}

#[test]
fn tcp_exact_status_refuses_200evil_after_real_request() {
    let outcome = exchange("ledger.example", b"HTTP/1.1 200evil\r\nContent-Length: 0\r\n\r\n", false);
    assert_real_exchange(&outcome); assert!(!outcome.client_ok, "status200evil must not authorize acceptance: {outcome:?}");
}

#[test]
fn tcp_header_budget_accepts_16384_and_refuses_16385_including_terminator() {
    let exact = exchange("ledger.example", &padded_response(HEADER_CAP), false);
    let excess = exchange("ledger.example", &padded_response(HEADER_CAP + 1), false);
    assert_real_exchange(&exact); assert_real_exchange(&excess);
    assert_eq!((exact.client_ok, excess.client_ok), (true, false), "exact={exact:?}; excess={excess:?}");
}

#[test]
fn tcp_complete_headers_return_before_coordinated_peer_eof() {
    let outcome = exchange("ledger.example", &ordinary(), true);
    assert_real_exchange(&outcome);
    assert!(outcome.client_ok && outcome.completed_before_eof,
        "complete software status must not wait for EOF; peer closed only after observation: {outcome:?}");
}

#[test]
fn tcp_host_hygiene_refuses_controls_space_nonascii_and_empty_before_connect() {
    let hosts = ["ledger.example\r\nX-Owned-Injected: yes", "ledger\rexample", "ledger\nexample",
        "ledger\0example", "ledger\u{7f}example", "ledger\texample", "ledger example", "ledger.\u{e9}xample", ""];
    // Finish every bounded exchange before asserting, so a baseline failure
    // reports all9observed variants rather than leaving later variants unreached.
    let outcomes: Vec<_> = hosts.iter().map(|host| exchange(host, &ordinary(), false)).collect();
    println!("owned Host hygiene observations: {outcomes:?}");
    for (index, outcome) in outcomes.iter().enumerate() {
        assert!(outcome.joined_without_panic && outcome.final_accept_after_completion, "case{index}: {outcome:?}");
        assert!(!outcome.client_ok && !outcome.accepted && outcome.request_bytes == 0,
            "Host hygiene must refuse before any connect; case{index}: {outcome:?}");
    }
}

#[test]
fn tcp_host_boundary_allows_1024_and_refuses_1025_before_connect() {
    let exact = exchange(&"h".repeat(1024), &ordinary(), false);
    let excess = exchange(&"h".repeat(1025), &ordinary(), false);
    assert_real_exchange(&exact);
    assert!(exact.client_ok && excess.joined_without_panic && excess.final_accept_after_completion
        && !excess.client_ok && !excess.accepted && excess.request_bytes == 0,
        "field hygiene is not DNS authentication; exact={exact:?}; excess={excess:?}");
}
