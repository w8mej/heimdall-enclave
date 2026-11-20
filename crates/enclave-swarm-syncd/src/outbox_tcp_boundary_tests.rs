//! Proposed private tests for root's bounded TCP helpers; no author execution.
//! Wire examples establish syntax behavior. Actual TCP send pressure uses a
//! shortened private budget, not production latency/SLO or receipt acceptance.
use super::*;
use std::io::Read;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[test]
fn gateway_parser_accepts_exact_ascii_status_and_refuses_malformed_wire_examples() {
    for bytes in [
        b"HTTP/1.0 200 OK\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 \r\nContent-Length: 0\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 \tOK\r\nX!#$%&'*+-.^_`|~: \tvalue\r\n\r\n".as_slice(),
    ] {
        gateway_validate_response(bytes).expect("valid explicit ASCII HTTP fixture");
    }
    for (label, bytes) in [
        ("empty", b"".as_slice()),
        ("only-terminator", b"\r\n\r\n".as_slice()),
        ("missing-terminator", b"HTTP/1.1 200 OK\r\n".as_slice()),
        ("http2", b"HTTP/2.0 200 OK\r\n\r\n".as_slice()),
        ("status-suffix-digit", b"HTTP/1.1 2000 OK\r\n\r\n".as_slice()),
        ("status-suffix-text", b"HTTP/1.1 200evil\r\n\r\n".as_slice()),
        ("status-tab-delimiter", b"HTTP/1.1 200\tOK\r\n\r\n".as_slice()),
        ("status-no-reason-separator", b"HTTP/1.1 200\r\n\r\n".as_slice()),
        ("status-nondigit", b"HTTP/1.1 20x OK\r\n\r\n".as_slice()),
        ("status-bare-cr", b"HTTP/1.1 200 OK\rInjected\r\n\r\n".as_slice()),
        ("header-no-colon", b"HTTP/1.1 200 OK\r\nContent-Length 0\r\n\r\n".as_slice()),
        ("header-empty-name", b"HTTP/1.1 200 OK\r\n: value\r\n\r\n".as_slice()),
        ("header-name-space", b"HTTP/1.1 200 OK\r\nBad Name: value\r\n\r\n".as_slice()),
        ("header-folded-line", b"HTTP/1.1 200 OK\r\nX: first\r\n second\r\n\r\n".as_slice()),
        ("header-bare-lf", b"HTTP/1.1 200 OK\r\nX: value\ninjected\r\n\r\n".as_slice()),
        ("header-nul", b"HTTP/1.1 200 OK\r\nX: value\0\r\n\r\n".as_slice()),
        ("header-del", b"HTTP/1.1 200 OK\r\nX: value\x7f\r\n\r\n".as_slice()),
        ("header-nonascii", b"HTTP/1.1 200 OK\r\nX: value\xff\r\n\r\n".as_slice()),
    ] {
        assert!(gateway_validate_response(bytes).unwrap_err().is("GATEWAY_RESPONSE_FORMAT"), "{label}");
    }
    assert!(gateway_validate_response(b"HTTP/1.1 403 Forbidden\r\n\r\n")
        .unwrap_err().is("GATEWAY_ERROR"));
    // Include the complete delimiter in the independently constructed limit.
    let prefix = b"HTTP/1.1 200 OK\r\nX-Padding: ";
    let mut exact = prefix.to_vec(); exact.resize(GATEWAY_HEADER_LIMIT - 4, b'x'); exact.extend_from_slice(b"\r\n\r\n");
    assert_eq!(exact.len(), 16_384); gateway_validate_response(&exact).unwrap();
    let mut excess = exact[..exact.len() - 4].to_vec(); excess.push(b'x'); excess.extend_from_slice(b"\r\n\r\n");
    assert_eq!(excess.len(), 16_385);
    assert!(gateway_validate_response(&excess).unwrap_err().is("GATEWAY_RESPONSE_FORMAT"));
}

fn socket_buffer(stream: &TcpStream, option: libc::c_int, requested: libc::c_int) -> libc::c_int {
    let result = unsafe { libc::setsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, option,
        (&requested as *const libc::c_int).cast(), std::mem::size_of_val(&requested) as libc::socklen_t) };
    assert_eq!(result, 0, "owned buffer setup: {}", std::io::Error::last_os_error());
    let mut actual: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&actual) as libc::socklen_t;
    let result = unsafe { libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, option,
        (&mut actual as *mut libc::c_int).cast(), &mut length) };
    assert_eq!(result, 0, "owned buffer observation: {}", std::io::Error::last_os_error());
    assert_eq!(length as usize, std::mem::size_of_val(&actual));
    actual
}

#[derive(Debug)]
struct PressureObservation { released_by_parent: bool, bytes: usize, exact_marker: bool }

#[test]
fn gateway_write_backpressure_expires_private_budget_after_real_partial_progress() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect_timeout(&listener.local_addr().unwrap(), Duration::from_secs(2)).unwrap();
    let (mut peer, _) = listener.accept().unwrap();
    peer.set_nonblocking(false).unwrap(); client.set_nonblocking(false).unwrap();
    let send_buffer = socket_buffer(&client, libc::SO_SNDBUF, 4096);
    let receive_buffer = socket_buffer(&peer, libc::SO_RCVBUF, 4096);
    // 2MiB is bounded and exceeds the observed buffers. Peer reads nothing
    // during the intended short write budget, establishing real backpressure.
    let payload = vec![0xa7u8; 2 * 1024 * 1024];
    let payload_length = payload.len();
    let (release_tx, release_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || -> Result<PressureObservation, String> {
        // A defective helper that waits indefinitely is released after3s so
        // cleanup remains possible and cannot be mistaken for a deadline pass.
        let released_by_parent = release_rx.recv_timeout(Duration::from_secs(3)).is_ok();
        let end = Instant::now() + Duration::from_secs(3);
        let mut bytes = 0usize; let mut exact_marker = true; let mut chunk = [0u8; 4096];
        loop {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() { return Err("owned peer drain deadline".into()); }
            peer.set_read_timeout(Some(left)).map_err(|e| e.to_string())?;
            match peer.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => {
                    bytes += count; exact_marker &= chunk[..count].iter().all(|byte| *byte == 0xa7);
                    if bytes > payload_length { return Err("owned peer received more than payload".into()); }
                },
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(PressureObservation { released_by_parent, bytes, exact_marker })
    });
    let started = Instant::now();
    let deadline = GatewayDeadline(started + Duration::from_millis(500));
    let call = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| gateway_write_all(&mut client, &payload, &deadline)));
    let elapsed = started.elapsed();
    // Always release/drop/join before examining the terminal result. No FD is
    // closed behind Rust ownership and no worker outlives this test's oracle.
    let shutdown = client.shutdown(Shutdown::Write); drop(client);
    let _ = release_tx.send(());
    let observation = worker.join().expect("owned pressure peer panicked")
        .expect("owned pressure peer failed before its observation");
    let result = call.expect("gateway helper panicked instead of returning");
    println!("owned send pressure: send_buffer={send_buffer}, receive_buffer={receive_buffer}, payload_bytes={payload_length}, elapsed_ms={}, observation={observation:?}, deadline_error={}",
        elapsed.as_millis(), result.as_ref().is_err_and(|error| error.is("GATEWAY_DEADLINE")));
    assert!(shutdown.is_ok());
    assert!(send_buffer > 0 && receive_buffer > 0 && (send_buffer as usize) < payload_length / 4
        && (receive_buffer as usize) < payload_length / 4, "owned buffer setup did not establish intended pressure");
    assert!(result.unwrap_err().is("GATEWAY_DEADLINE"));
    assert!(observation.released_by_parent && observation.exact_marker
        && observation.bytes > 0 && observation.bytes < payload_length,
        "actual partial write must precede deadline refusal, not fallback peer release: {observation:?}");
}

#[test]
fn gateway_zero_private_budget_refuses_before_any_actual_connect() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap(); listener.set_nonblocking(true).unwrap();
    let transport = TcpOutboxTransport::new(listener.local_addr().unwrap(), "owned-gateway.invalid");
    let result = transport.transmit_with_budget(b"small", Duration::ZERO);
    assert!(result.unwrap_err().is("GATEWAY_DEADLINE"));
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {},
        other => panic!("completed zero-budget call must leave no queued connection: {other:?}"),
    }
}
