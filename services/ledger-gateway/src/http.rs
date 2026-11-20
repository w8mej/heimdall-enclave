//! Bounded HTTP/1.1 fixture transport (DEFECT-F-94).
use crate::LedgerGateway;
use enclave_core::{err, error::EnclaveResult};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

const MAX_HEADER: usize = 16 * 1024;
const MAX_BODY: usize = 2 * 1024 * 1024;
const MAX_WORKERS: usize = 8;
const DEADLINE: Duration = Duration::from_secs(5);

fn request(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let invalid = || std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid request");
    let deadline = Instant::now() + DEADLINE;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = bytes.windows(4).position(|s| s == b"\r\n\r\n") {
            if pos + 4 > MAX_HEADER {
                return Err(invalid());
            }
            break pos + 4;
        }
        if bytes.len() >= MAX_HEADER {
            return Err(invalid());
        }
        stream.set_read_timeout(Some(
            deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or_else(invalid)?,
        ))?;
        let n = stream.read(&mut chunk[..(MAX_HEADER - bytes.len()).min(4096)])?;
        if n == 0 {
            return Err(invalid());
        }
        bytes.extend_from_slice(&chunk[..n]);
    };
    let headers = std::str::from_utf8(&bytes[..header_end - 4]).map_err(|_| invalid())?;
    let mut lines = headers.split("\r\n");
    if lines.next() != Some("POST /v1/rollup HTTP/1.1") {
        return Err(invalid());
    }
    let mut length = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(invalid)?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(invalid());
        }
        if name.eq_ignore_ascii_case("content-length") {
            let value = value.trim();
            if length.is_some() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid());
            }
            let n: usize = value.parse().map_err(|_| invalid())?;
            if n > MAX_BODY {
                return Err(invalid());
            }
            length = Some(n);
        }
    }
    let end = header_end + length.ok_or_else(invalid)?;
    if bytes.len() > end {
        return Err(invalid());
    }
    while bytes.len() < end {
        stream.set_read_timeout(Some(
            deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or_else(invalid)?,
        ))?;
        let remaining = (end - bytes.len()).min(chunk.len());
        let n = stream.read(&mut chunk[..remaining])?;
        if n == 0 {
            return Err(invalid());
        }
        bytes.extend_from_slice(&chunk[..n]);
    }
    Ok(bytes.split_off(header_end))
}

fn connection(mut stream: TcpStream, gateway: &LedgerGateway) {
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let result = request(&mut stream)
        .ok()
        .and_then(|b| gateway.handle_ohttp_post(&b).ok())
        .and_then(|r| enclave_core::ipc::to_cbor(&r).ok());
    let (status, content_type, body) = match result {
        Some(body) => ("200 OK", "application/cbor", body),
        None => ("403 Forbidden", "text/plain", b"request rejected".to_vec()),
    };
    let header = format!("HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    let _ = stream
        .write_all(header.as_bytes())
        .and_then(|_| stream.write_all(&body));
}

pub(super) fn serve(
    listener: TcpListener,
    gateway: Arc<LedgerGateway>,
    stop: Arc<AtomicBool>,
) -> EnclaveResult<()> {
    listener
        .set_nonblocking(true)
        .map_err(|e| err!(EIO, "TCP_NONBLOCKING", "{e}"))?;
    let active = Arc::new(AtomicUsize::new(0));
    let mut threads = Vec::new();
    while !stop.load(Ordering::Relaxed) {
        threads.retain(|h: &std::thread::JoinHandle<()>| !h.is_finished());
        match listener.accept() {
            Ok((stream, _)) => {
                if active
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                        (n < MAX_WORKERS).then_some(n + 1)
                    })
                    .is_err()
                {
                    continue;
                }
                let active = active.clone();
                let gateway = gateway.clone();
                let handle = std::thread::Builder::new()
                    .name("ledger-http".into())
                    .spawn(move || {
                        struct Guard(Arc<AtomicUsize>);
                        impl Drop for Guard {
                            fn drop(&mut self) {
                                self.0.fetch_sub(1, Ordering::SeqCst);
                            }
                        }
                        let _guard = Guard(active);
                        connection(stream, &gateway);
                    })
                    .map_err(|e| err!(EIO, "TCP_WORKER", "{e}"))?;
                threads.push(handle);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(e) => return Err(err!(EIO, "TCP_ACCEPT", "{e}")),
        }
    }
    for thread in threads {
        let _ = thread.join();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(data: Vec<u8>) -> std::io::Result<Vec<u8>> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let writer = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            let _ = s.write_all(&data);
        });
        let (mut stream, _) = listener.accept().unwrap();
        let result = request(&mut stream);
        writer.join().unwrap();
        result
    }
    #[test]
    fn bounded_valid_body_and_adversarial_lengths() {
        assert_eq!(
            parse(b"POST /v1/rollup HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc".to_vec()).unwrap(),
            b"abc"
        );
        for headers in [
            "Content-Length: 2097153",
            "Content-Length: 18446744073709551616",
            "Content-Length: 1\r\nContent-Length: 1",
            "Content-Length: 0\r\nTransfer-Encoding: chunked",
            "Content-Length: -1",
        ] {
            assert!(
                parse(format!("POST /v1/rollup HTTP/1.1\r\n{headers}\r\n\r\n").into_bytes())
                    .is_err(),
                "{headers}"
            );
        }
        assert!(parse(vec![b'x'; MAX_HEADER + 1]).is_err());
    }
    #[test]
    fn slow_drip_cannot_extend_absolute_header_or_body_deadline() {
        // Each write arrives much sooner than DEADLINE. A timeout reset after
        // each read would keep both peers alive until their entire stream ends.
        let cases: Vec<_> = [false, true].into_iter().map(|body| std::thread::spawn(move || {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let done = Arc::new(AtomicBool::new(false));
            let flag = done.clone();
            let sender = std::thread::spawn(move || {
                let mut peer = TcpStream::connect(address).unwrap();
                if body { peer.write_all(b"POST /v1/rollup HTTP/1.1\r\nContent-Length: 1000\r\n\r\n").unwrap(); }
                for _ in 0..100 {
                    if flag.load(Ordering::Relaxed) { break; }
                    if peer.write_all(b"x").is_err() { break; }
                    std::thread::sleep(Duration::from_millis(100));
                }
            });
            let (mut peer, _) = listener.accept().unwrap();
            let start = Instant::now();
            let result = request(&mut peer);
            let elapsed = start.elapsed();
            done.store(true, Ordering::Relaxed);
            drop(peer); sender.join().unwrap();
            assert!(result.is_err());
            assert!(elapsed >= DEADLINE - Duration::from_millis(200), "premature timeout: {elapsed:?}");
            assert!(elapsed < DEADLINE + Duration::from_secs(2), "slow drip extended deadline: {elapsed:?}");
        })).collect();
        for case in cases { case.join().unwrap(); }
    }

    #[test]
    fn slow_peer_does_not_serialize_accepts_and_errors_are_uniform() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (gw, _) = LedgerGateway::new(1, Default::default());
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let server = std::thread::spawn(move || serve(listener, Arc::new(gw), flag).unwrap());
        let slow = TcpStream::connect(addr).unwrap();
        let start = Instant::now();
        let mut replies = Vec::new();
        for body in ["x", "invalid ciphertext"] {
            let mut client = TcpStream::connect(addr).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            write!(
                client,
                "POST /v1/rollup HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).unwrap();
            replies.push(reply);
        }
        assert_eq!(replies[0], replies[1]);
        assert!(start.elapsed() < Duration::from_secs(4));
        drop(slow);
        stop.store(true, Ordering::Relaxed);
        server.join().unwrap();
    }
}
