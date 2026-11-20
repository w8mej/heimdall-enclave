//! Real local TCP progress must not renew the transport's absolute deadline.
//! Uses only the existing public new/transmit API, including on old source.
//! This is software HTTP behavior, not an authenticated ledger receipt or SLO.
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{atomic::{AtomicBool, Ordering}, Arc};
use std::time::{Duration, Instant};

use enclave_swarm_syncd::outbox::{OutboxTransport, TcpOutboxTransport};

const PAYLOAD: &[u8] = b"payload";

#[derive(Debug)]
struct ServerObservation {
    request_header_bytes: usize,
    request_payload: Vec<u8>,
    progress_writes: usize,
    complete_header_sent: bool,
    response_write_error: Option<String>,
}

fn remaining(deadline: Instant) -> Result<Duration, String> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() { Err("owned server fixture deadline".into()) } else { Ok(left) }
}

fn one_byte(stream: &mut TcpStream, deadline: Instant) -> Result<u8, String> {
    loop {
        stream.set_read_timeout(Some(remaining(deadline)?)).map_err(|e| e.to_string())?;
        let mut byte = [0u8; 1];
        match stream.read(&mut byte) {
            Ok(1) => return Ok(byte[0]),
            Ok(_) => return Err("owned server fixture request EOF".into()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.to_string()),
        }
    }
}

fn serve(listener: TcpListener, stop: Arc<AtomicBool>) -> Result<ServerObservation, String> {
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let accept_deadline = Instant::now() + Duration::from_secs(5);
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if stop.load(Ordering::SeqCst) { return Err("transport stopped before owned accept".into()); }
                remaining(accept_deadline)?;
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.to_string()),
        }
    };
    // Darwin can inherit listener nonblocking state; timeout-based fixture
    // reads/writes require an explicitly blocking accepted stream.
    stream.set_nonblocking(false).map_err(|e| e.to_string())?;
    stream.set_write_timeout(Some(Duration::from_secs(2))).map_err(|e| e.to_string())?;
    let request_deadline = Instant::now() + Duration::from_secs(3);
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        if request.len() == 4096 { return Err("owned server request header ceiling".into()); }
        request.push(one_byte(&mut stream, request_deadline)?);
    }
    let text = std::str::from_utf8(&request).map_err(|e| e.to_string())?;
    if !text.starts_with("POST /v1/rollup HTTP/1.1\r\n")
        || !text.split("\r\n").any(|line| line == "Host: owned-gateway.invalid")
        || !text.split("\r\n").any(|line| line == "Content-Length: 7") {
        return Err("actual complete request did not match owned fixture".into());
    }
    let mut request_payload = Vec::with_capacity(PAYLOAD.len());
    for _ in 0..PAYLOAD.len() { request_payload.push(one_byte(&mut stream, request_deadline)?); }
    if request_payload != PAYLOAD { return Err("actual request payload mismatch".into()); }

    stream.write_all(b"HTTP/1.1 200 OK\r\nX-Owned-Slow: ").map_err(|e| e.to_string())?;
    let mut observed = ServerObservation {
        request_header_bytes: request.len(), request_payload,
        progress_writes: 0, complete_header_sent: false, response_write_error: None,
    };
    // Twenty-four actual writes at 500ms intervals keep every ordinary read
    // gap below the old 10s per-read timeout, yet defer a complete header until
    // about 12s. The successor's shared 10s deadline must expire first.
    for _ in 0..24 {
        if stop.load(Ordering::SeqCst) { return Ok(observed); }
        std::thread::sleep(Duration::from_millis(500));
        if stop.load(Ordering::SeqCst) { return Ok(observed); }
        match stream.write_all(b"x") {
            Ok(()) => observed.progress_writes += 1,
            // The deadline may close the client before its caller can set
            // stop. Record this ordinary race and let the parent result oracle
            // distinguish deadline refusal from an incidental socket failure.
            Err(error) => { observed.response_write_error = Some(error.to_string()); return Ok(observed); }
        }
    }
    if !stop.load(Ordering::SeqCst) {
        match stream.write_all(b"\r\n\r\n") {
            Ok(()) => observed.complete_header_sent = true,
            Err(error) => observed.response_write_error = Some(error.to_string()),
        }
    }
    // EOF releases old read_to_end only after the planned late completion.
    Ok(observed)
}

#[test]
fn tcp_slow_header_progress_cannot_extend_shared_absolute_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let server = std::thread::spawn(move || serve(listener, server_stop));
    let transport = TcpOutboxTransport::new(address, "owned-gateway.invalid");
    let started = Instant::now();
    // Cleanup also occurs after an unexpected transport panic. A caught panic
    // is then failed explicitly; it cannot masquerade as a returned refusal.
    let call = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| transport.transmit(PAYLOAD)));
    let elapsed = started.elapsed();
    stop.store(true, Ordering::SeqCst);
    let observed = server.join().expect("owned TCP server thread panicked")
        .expect("owned TCP fixture did not reach intended sustained-progress boundary");
    let result = call.expect("transport panicked instead of returning its result");
    println!("owned TCP slow header: elapsed_ms={}, request_header_bytes={}, progress_writes={}, complete_header_sent={}, software_ok={}, deadline_error={}, response_write_error={:?}",
        elapsed.as_millis(), observed.request_header_bytes, observed.progress_writes,
        observed.complete_header_sent, result.is_ok(), result.as_ref().is_err_and(|error| error.is("GATEWAY_DEADLINE")), observed.response_write_error);
    assert_eq!((result.as_ref().is_err_and(|error| error.is("GATEWAY_DEADLINE")),
        observed.complete_header_sent, observed.request_payload == PAYLOAD,
        observed.progress_writes >= 8),
        (true, false, true, true),
        "a real incomplete HTTP header made sustained progress beyond ordinary gaps; deadline must refuse before the fixture completes at about12s: result={result:?}, elapsed={elapsed:?}, observation={observed:?}");
}
