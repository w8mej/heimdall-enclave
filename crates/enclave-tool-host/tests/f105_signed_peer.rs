//! Real Darwin peer authentication in private same-UID fixtures; no installed pins.
#![cfg(target_os = "macos")]

use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use enclave_core::codesign::CodeRequirement;
use enclave_core::ipc::{from_cbor, read_frame, to_cbor, write_frame, Reply};
use enclave_tool_host::{IpcEgressGateClient, ToolEgressProxy};
use enclave_zk_auditor::service::{ZkRequest, ZkResponse};
use enclave_zk_auditor::zk::redact::{evaluate_and_prove_chunk, MAX_CHUNK_SIZE};

const IDENTIFIER: &str = "com.depot.test.f105.gate";
const KEY: [u8; 32] = [42; 32]; // Public, synthetic test authority only.

// Accepted Darwin sockets on this host reject SO_RCVTIMEO with EINVAL. Use
// explicit bounded polling in the private fixture, keeping production I/O and
// all authentication checks untouched. The socket stays nonblocking throughout.
struct TimedPeer {
    socket: std::os::unix::net::UnixStream,
    deadline: Instant,
}
impl TimedPeer {
    fn wait(&self, event: libc::c_short) -> std::io::Result<()> {
        loop {
            let left = self.deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(std::io::ErrorKind::TimedOut.into());
            }
            let mut fd = libc::pollfd { fd: self.socket.as_raw_fd(), events: event, revents: 0 };
            let status = unsafe { libc::poll(&mut fd, 1, left.as_millis().clamp(1, 2000) as i32) };
            if status > 0 { return Ok(()); }
            if status == 0 { return Err(std::io::ErrorKind::TimedOut.into()); }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted { return Err(error); }
        }
    }
}
impl Read for TimedPeer {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        loop {
            self.wait(libc::POLLIN)?;
            match self.socket.read(bytes) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                result => return result,
            }
        }
    }
}
impl Write for TimedPeer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        loop {
            self.wait(libc::POLLOUT)?;
            match self.socket.write(bytes) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                result => return result,
            }
        }
    }
    fn flush(&mut self) -> std::io::Result<()> { self.socket.flush() }
}

struct Fixture {
    child: Child,
    dir: tempfile::TempDir,
    requirement: CodeRequirement,
}

impl Fixture {
    fn start(wrong_proof_key: bool) -> Self {
        let dir = tempfile::Builder::new().prefix("f105-").tempdir_in("/tmp").unwrap();
        let binary = dir.path().join("peer");
        fs::copy(std::env::current_exe().unwrap(), &binary).unwrap();
        let signed = Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-", "--identifier", IDENTIFIER])
            .arg(&binary).output().unwrap();
        assert!(signed.status.success(), "{}", String::from_utf8_lossy(&signed.stderr));
        let identity = Command::new("/usr/bin/codesign")
            .args(["--display", "--verbose=4"]).arg(&binary).output().unwrap();
        assert!(identity.status.success());
        let details = String::from_utf8(identity.stderr).unwrap();
        let cdhash = details.lines().find_map(|line| line.strip_prefix("CDHash=")).unwrap();
        assert_eq!(cdhash.len(), 40);
        assert!(details.lines().any(|line| line == format!("Identifier={IDENTIFIER}")));
        println!("F105 private peer identifier={IDENTIFIER} cdhash={cdhash}");
        let requirement = CodeRequirement {
            identifier: IDENTIFIER.into(), team_id: String::new(),
            cdhash_allowlist: vec![cdhash.into()],
        };
        let log = fs::File::create(dir.path().join("child.log")).unwrap();
        let child = Command::new(&binary)
            .args(["--exact", "peer_worker", "--nocapture", "--test-threads=1"])
            .env("F105_PRIVATE_DIRECTORY", dir.path())
            .env("F105_WRONG_PROOF_KEY", if wrong_proof_key { "1" } else { "0" })
            .stdin(Stdio::null()).stdout(log.try_clone().unwrap()).stderr(log)
            .spawn().unwrap();
        let mut fixture = Self { child, dir, requirement };
        let deadline = Instant::now() + Duration::from_secs(10);
        while !fixture.dir.path().join("ready").exists() {
            assert!(fixture.child.try_wait().unwrap().is_none(), "{}",
                fs::read_to_string(fixture.dir.path().join("child.log")).unwrap());
            assert!(Instant::now() < deadline, "private peer failed to bind");
            std::thread::sleep(Duration::from_millis(10));
        }
        let probe = std::os::unix::net::UnixStream::connect(fixture.dir.path().join("gate.sock")).unwrap();
        let peer = enclave_core::ipc::peer_credentials(&probe).unwrap();
        assert_eq!(peer.pid, Some(fixture.child.id() as i32));
        println!("F105 kernel peer pid={:?} token={:?}", peer.pid, peer.audit_token);
        drop(probe);
        fixture
    }

    fn proxy(&self, requirement: CodeRequirement, uid: u32) -> ToolEgressProxy {
        let client = IpcEgressGateClient::with_peer_requirement(
            self.dir.path().join("gate.sock"), uid,
            SigningKey::from_bytes(&KEY).verifying_key(), Duration::from_secs(2), requirement,
        );
        ToolEgressProxy::with_client(Arc::new(client), SigningKey::from_bytes(&KEY).verifying_key())
    }

    fn requests(&self) -> usize {
        fs::read_to_string(self.dir.path().join("requests")).unwrap().parse().unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Only this fixture-owned direct child is stopped; installed services are untouched.
        let _ = self.child.kill();
        let _ = self.child.wait();
        println!("F105 private child log: {}", fs::read_to_string(self.dir.path().join("child.log")).unwrap_or_default());
    }
}

// Invoked only in an independently ad-hoc-signed child image. The runner selects
// f105_ parent cases; this helper is not counted as a stand-alone regression.
#[test]
fn peer_worker() {
    let Some(directory) = std::env::var_os("F105_PRIVATE_DIRECTORY") else { return; };
    let directory = PathBuf::from(directory);
    let listener = UnixListener::bind(directory.join("gate.sock")).unwrap();
    listener.set_nonblocking(true).unwrap();
    fs::write(directory.join("requests"), "0").unwrap();
    fs::write(directory.join("ready"), b"ready").unwrap();
    let key = SigningKey::from_bytes(&if std::env::var("F105_WRONG_PROOF_KEY").unwrap() == "1" {
        [99; 32]
    } else { KEY });
    let deadline = Instant::now() + Duration::from_secs(40);
    let mut requests = 0;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((socket, _)) => {
                socket.set_nonblocking(true).unwrap();
                let mut stream = TimedPeer { socket, deadline: Instant::now() + Duration::from_secs(2) };
                // Identity/UID rejection closes the connection before even a frame header.
                let mut first = [0u8; 1];
                let count = match stream.read(&mut first) {
                    Ok(count) => count,
                    Err(error) if matches!(error.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof) => continue,
                    Err(error) => panic!("fixture request read: {error}"),
                };
                if count == 0 { continue; }
                requests += 1;
                fs::write(directory.join("requests"), requests.to_string()).unwrap();
                let frame = read_frame(&mut std::io::Cursor::new(first).chain(&mut stream)).unwrap();
                let ZkRequest::GateEgress { d_jcs, chunk } = from_cbor(&frame).unwrap() else {
                    panic!("unexpected fixture request");
                };
                let reply = match evaluate_and_prove_chunk(&key, &d_jcs, &chunk, 1) {
                    Ok(proof) => Reply::Ok(ZkResponse::EgressGated {
                        approved: true,
                        d_jcs_hash: *blake3::hash(&d_jcs).as_bytes(),
                        chunk_hash: *blake3::hash(&chunk).as_bytes(),
                        pi_redact: proof.to_bytes().unwrap().into(),
                    }),
                    Err(error) => Reply::<ZkResponse>::Err(error),
                };
                write_frame(&mut stream, &to_cbor(&reply).unwrap()).unwrap();
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("fixture accept: {error}"),
        }
    }
}

#[test]
fn f105_real_signed_peer_releases_clean_bytes_and_withholds_boundary_secrets() {
    let fixture = Fixture::start(false);
    let proxy = fixture.proxy(fixture.requirement.clone(), unsafe { libc::geteuid() });
    let payload = vec![b'X'; MAX_CHUNK_SIZE + 512];
    let mut sink = Vec::new();
    assert_eq!(proxy.stream_egress(b"independent context", &payload, &mut sink).unwrap(), payload.len());
    assert_eq!(sink, payload);
    assert_eq!(fixture.requests(), 2);
    for boundary in [MAX_CHUNK_SIZE, MAX_CHUNK_SIZE - 256] {
        let mut dirty = payload.clone();
        let secret_start = boundary - 5;
        dirty[secret_start..secret_start + 11].copy_from_slice(b"123-45-6789");
        let mut sink = Vec::new();
        assert!(proxy.stream_egress(b"independent context", &dirty, &mut sink)
            .unwrap_err().is("UNREDACTED_C4_IN_EGRESS"));
        assert!(sink.len() <= secret_start);
        assert!(sink.iter().all(|byte| *byte == b'X'));
    }
}

#[test]
fn f105_same_uid_wrong_binary_identity_receives_no_request_bytes() {
    let fixture = Fixture::start(false);
    let mut wrong_identifier = fixture.requirement.clone();
    wrong_identifier.identifier = "com.depot.test.f105.foreign".into();
    let mut wrong_hash = fixture.requirement.clone();
    wrong_hash.cdhash_allowlist = vec!["00".repeat(20)];
    let mut unpinned = fixture.requirement.clone();
    unpinned.cdhash_allowlist.clear();
    for requirement in [wrong_identifier, wrong_hash, unpinned] {
        let proxy = fixture.proxy(requirement, unsafe { libc::geteuid() });
        let mut sink = Vec::new();
        let error = proxy.stream_egress(b"must remain private", b"clean secret context", &mut sink).unwrap_err();
        assert!(error.to_string().contains("SERVER_CODESIGN_REJECTED"), "{error}");
        assert!(sink.is_empty());
    }
    // A positive request after the negatives flushes the child's accept loop.
    let proxy = fixture.proxy(fixture.requirement.clone(), unsafe { libc::geteuid() });
    proxy.stream_egress(b"positive", b"clean", &mut Vec::new()).unwrap();
    assert_eq!(fixture.requests(), 1, "a rejected connection disclosed a request byte");
}

#[test]
fn f105_uid_authentication_is_required_even_for_correctly_signed_peer() {
    let fixture = Fixture::start(false);
    let proxy = fixture.proxy(fixture.requirement.clone(), unsafe { libc::geteuid() }.wrapping_add(1));
    let mut sink = Vec::new();
    let error = proxy.stream_egress(b"private", b"clean", &mut sink).unwrap_err();
    assert!(error.to_string().contains("SERVER_UID_MISMATCH"), "{error}");
    assert!(sink.is_empty());
    let good = fixture.proxy(fixture.requirement.clone(), unsafe { libc::geteuid() });
    good.stream_egress(b"positive", b"clean", &mut Vec::new()).unwrap();
    assert_eq!(fixture.requests(), 1);
}

#[test]
fn f105_signed_code_identity_does_not_replace_independent_proof_key() {
    let fixture = Fixture::start(true);
    let proxy = fixture.proxy(fixture.requirement.clone(), unsafe { libc::geteuid() });
    let mut sink = Vec::new();
    assert!(proxy.stream_egress(b"context", b"clean", &mut sink).unwrap_err().is("SIGNER_MISMATCH"));
    assert!(sink.is_empty());
    assert_eq!(fixture.requests(), 1);
}
