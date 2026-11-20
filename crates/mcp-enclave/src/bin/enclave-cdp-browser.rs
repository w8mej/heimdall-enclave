//! `enclave-cdp-browser`: bounded CDP response fixture (GAP-34, FS-701 §4.6.6, ADR-018).
//! An explicit owned-document WebKit path provides bounded real DOM effects;
//! arbitrary/production navigation remains unavailable.
//!
//! Installed startup refuses until a real confined browser backend is available.
//! Debug builds can explicitly select response fixtures with same-UID peers.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::Parser;
use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde_json::{json, Value};

#[derive(Parser, Debug)]
#[command(
    name = "enclave-cdp-browser",
    about = "CDP fixture daemon; real browser launch/navigation is not implemented"
)]
struct Args {
    /// Protected deployment descriptor, selected before code identity or paths.
    #[arg(long)]
    deployment_target: Option<PathBuf>,

    /// Exact configured profile; required together with a deployment target.
    #[arg(long)]
    profile: Option<String>,

    /// Unix domain socket path.
    #[arg(long, default_value = "/var/run/enclave/browser/browser.sock")]
    socket: PathBuf,

    /// Throwaway user data directory base path.
    #[arg(long, default_value = "/var/db/enclave/browser")]
    throwaway_dir: PathBuf,

    /// Optional path to real Chrome/Chromium binary.
    #[arg(long)]
    browser_path: Option<PathBuf>,

    /// Optional pinned SHA-256 of the browser executable.
    #[arg(long)]
    expected_hash: Option<String>,

    /// Enable canned CDP replies for development tests (debug builds only).
    #[arg(long)]
    response_fixture: bool,

    /// Permit development peers with the current UID; requires response fixtures.
    #[arg(long)]
    dev_same_uid: bool,

    /// Real WebKit on a built-in offline document; requires debug same-UID mode.
    #[arg(long)]
    owned_webkit: bool,
}

fn bind_deployment(args: &Args) -> EnclaveResult<()> {
    let Some(path) = &args.deployment_target else {
        if args.profile.is_some() || enclave_core::deployment::selected().is_some() {
            fail!(EACCES, "DEPLOYMENT_MIXED_ARGUMENTS");
        }
        return Ok(());
    };
    if args.dev_same_uid || args.response_fixture || args.owned_webkit
        || args.browser_path.is_some() || args.expected_hash.is_some() {
        fail!(EACCES, "DEPLOYMENT_MIXED_ARGUMENTS");
    }
    let checked = enclave_core::deployment::load(path)?;
    let target = checked.target();
    let requested = args.profile.as_deref().ok_or_else(|| err!(EACCES, "DEPLOYMENT_PROFILE_MISMATCH"))?;
    if enclave_core::Profile::parse(requested)? != target.profile {
        fail!(EACCES, "DEPLOYMENT_PROFILE_MISMATCH");
    }
    if enclave_core::deployment::normalized_path(&args.socket)?
        != enclave_core::deployment::normalized_path(&target.layout.socket_root.join("browser/browser.sock"))?
        || enclave_core::deployment::normalized_path(&args.throwaway_dir)?
            != enclave_core::deployment::normalized_path(&target.layout.state_root.join("browser"))? {
        fail!(EACCES, "DEPLOYMENT_BROWSER_PATH_MISMATCH");
    }
    enclave_core::deployment::upgrade::assert_start_allowed(&checked)?;
    enclave_core::deployment::select(checked)?;
    enclave_core::deployment::startup_lease::retain_selected_startup_lease()
}

fn require_fixture_mode(args: &Args) -> EnclaveResult<()> {
    if args.owned_webkit {
        if !cfg!(debug_assertions) || !args.dev_same_uid || args.response_fixture
            || args.browser_path.is_some() || args.expected_hash.is_some() {
            fail!(EPERM, "OWNED_WEBKIT_REQUIRES_DEBUG_SAME_UID");
        }
        if !cfg!(target_os = "macos") { fail!(ENOSYS, "WEBKIT_PLATFORM_UNAVAILABLE"); }
        return Ok(());
    }
    if !args.response_fixture {
        fail!(ENOSYS, "BROWSER_BACKEND_UNAVAILABLE");
    }
    if !cfg!(debug_assertions) || !args.dev_same_uid {
        fail!(EPERM, "BROWSER_FIXTURE_REQUIRES_DEBUG_SAME_UID");
    }
    if args.browser_path.is_some() || args.expected_hash.is_some() {
        fail!(EINVAL, "BROWSER_FIXTURE_HAS_NO_BROWSER");
    }
    Ok(())
}

fn fixture_peer_policy() -> enclave_core::ipc::PeerPolicy {
    enclave_core::ipc::PeerPolicy::allow([enclave_core::ipc::geteuid()])
}

fn handle_cdp_client(stream: UnixStream, session_dir: &Path) -> EnclaveResult<()> {
    handle_cdp_client_with_limits(
        stream,
        session_dir,
        std::time::Duration::from_secs(5),
        std::time::Duration::from_secs(30),
    )
}

fn handle_cdp_client_with_limits(
    stream: UnixStream,
    session_dir: &Path,
    frame_limit: std::time::Duration,
    connection_limit: std::time::Duration,
) -> EnclaveResult<()> {
    handle_cdp_backend(stream, session_dir, frame_limit, connection_limit, None)
}

fn handle_cdp_backend(
    mut stream: UnixStream,
    session_dir: &Path,
    frame_limit: std::time::Duration,
    connection_limit: std::time::Duration,
    mut browser: Option<enclave_model_runnerd::owned_browser::OwnedWebKit>,
) -> EnclaveResult<()> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    // Bytes before this cursor have already been checked for a delimiter. An
    // incomplete frame must not force a quadratic rescan of its entire prefix.
    let mut scanned = 0;

    let connected = std::time::Instant::now();
    let connection_deadline = connected + connection_limit;
    let mut frame_started = connected;
    loop {
        let frame_deadline = frame_started + frame_limit;
        let (deadline, reason) = if connection_deadline <= frame_deadline {
            (connection_deadline, "CDP_CONNECTION_DEADLINE")
        } else {
            (frame_deadline, "CDP_FRAME_DEADLINE")
        };
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| err!(ETIMEDOUT, reason))?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|e| err!(EIO, "CDP_TIMEOUT", "{e}"))?;
        let n = match stream.read(&mut chunk) {
            Ok(n) => n,
            // Neither signals nor an early/rounded socket timeout reset an
            // absolute deadline. Recompute its remaining budget on each retry.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(e) => return Err(err!(EIO, "CDP_READ", "{e}")),
        };
        if std::time::Instant::now() >= deadline {
            fail!(ETIMEDOUT, reason);
        }
        if n == 0 {
            break;
        }
        if buf.len().saturating_add(n) > 1024 * 1024 {
            fail!(EINVAL, "CDP_FRAME_TOO_LARGE");
        }
        buf.extend_from_slice(&chunk[..n]);

        while let Some(relative_pos) = buf[scanned..].iter().position(|b| *b == 0) {
            let nul_pos = scanned + relative_pos;
            if std::time::Instant::now() >= connection_deadline {
                fail!(ETIMEDOUT, "CDP_CONNECTION_DEADLINE");
            }
            let msg_bytes = &buf[..nul_pos];
            let msg: Value = serde_json::from_slice(msg_bytes)
                .map_err(|e| err!(EINVAL, "CDP_JSON_PARSE", "{e}"))?;
            buf.drain(..=nul_pos);
            scanned = 0;
            frame_started = std::time::Instant::now();

            let id = msg.get("id").and_then(Value::as_u64).unwrap_or(0);
            let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
            let params = msg.get("params").cloned().unwrap_or(Value::Null);

            let mut failure = None;
            let result = if let Some(browser) = browser.as_mut() {
                match browser.dispatch(method, &params) {
                    Ok(result) => result,
                    Err(error) => { failure = Some(error.reason); Value::Null }
                }
            } else { match method {
                "DOM.getDocument" => json!({
                    "root": {
                        "nodeId": 1,
                        "backendNodeId": 1,
                        "nodeType": 9,
                        "nodeName": "#document",
                        "childNodeCount": 1
                    }
                }),
                "DOM.querySelector" => {
                    let selector = params.get("selector").and_then(Value::as_str).unwrap_or("");
                    if selector.is_empty() {
                        json!({"nodeId": 0})
                    } else if selector == "#delete-repo" {
                        json!({"nodeId": 10})
                    } else {
                        json!({"nodeId": 2})
                    }
                }
                "DOM.getBoxModel" => {
                    let node_id = params.get("nodeId").and_then(Value::as_u64).unwrap_or(0);
                    if node_id == 10 {
                        // #delete-repo coordinates
                        json!({
                            "model": {
                                "content": [100.0, 100.0, 250.0, 100.0, 250.0, 140.0, 100.0, 140.0],
                                "width": 150,
                                "height": 40
                            }
                        })
                    } else {
                        // Standard centered box model [x1, y1, x2, y2, x3, y3, x4, y4]
                        json!({
                            "model": {
                                "content": [100.0, 200.0, 200.0, 200.0, 200.0, 240.0, 100.0, 240.0],
                                "width": 100,
                                "height": 40
                            }
                        })
                    }
                }
                "Input.dispatchMouseEvent" => {
                    json!({})
                }
                "Page.navigate" => {
                    json!({"frameId": "enclave-main-frame"})
                }
                _ => json!({}),
            }};

            let response = if let Some(reason) = failure {
                json!({"id":id,"error":{"code":-32000,"message":reason}})
            } else { json!({"id":id,"result":result}) };

            let mut out = serde_json::to_vec(&response)
                .map_err(|e| err!(EIO, "CDP_RESPONSE_ENCODE", "{e}"))?;
            out.push(0);
            let mut written = 0;
            while written < out.len() {
                let remaining = connection_deadline
                    .checked_duration_since(std::time::Instant::now())
                    .filter(|d| !d.is_zero())
                    .ok_or_else(|| err!(ETIMEDOUT, "CDP_CONNECTION_DEADLINE"))?;
                stream
                    .set_write_timeout(Some(remaining.min(std::time::Duration::from_secs(5))))
                    .map_err(|e| err!(EIO, "CDP_TIMEOUT", "{e}"))?;
                match stream.write(&out[written..]) {
                    Ok(0) => fail!(EIO, "CDP_WRITE_ZERO"),
                    Ok(n) => written += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(err!(EIO, "CDP_WRITE", "{e}")),
                }
            }
            stream.flush().map_err(|e| err!(EIO, "CDP_FLUSH", "{e}"))?;
        }
        scanned = buf.len();
    }

    // Clean up throwaway session directory
    let _ = std::fs::remove_dir_all(session_dir);
    Ok(())
}

fn main() -> EnclaveResult<()> {
    let args = Args::parse();
    bind_deployment(&args)?;

    // Refuse before reading a supplied executable or changing socket/session
    // paths. A hash cannot turn these response fixtures into browser effects.
    require_fixture_mode(&args)?;
    // Verify native startup before touching a supplied socket/profile path.
    let mut prepared_browser = if args.owned_webkit {
        Some(enclave_model_runnerd::owned_browser::OwnedWebKit::new()?)
    } else { None };

    if let Some(parent) = args.socket.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(&args.socket);

    let listener = UnixListener::bind(&args.socket)
        .map_err(|e| err!(EIO, "BROWSER_BIND", "{}: {e}", args.socket.display()))?;

    std::fs::set_permissions(&args.socket, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| err!(EIO, "BROWSER_SOCKET_PERMISSIONS", "{e}"))?;

    let term = Arc::new(AtomicBool::new(false));
    enclave_core::runtime::install_signal_flag(term.clone());

    listener
        .set_nonblocking(true)
        .map_err(|e| err!(EIO, "BROWSER_NONBLOCK", "{e}"))?;

    while !term.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((s, _)) => {
                let _ = s.set_nonblocking(false);
                // Every reachable listener is an explicit same-UID fixture.
                let creds = match enclave_core::ipc::peer_credentials(&s) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Peer credentials error: {e}");
                        continue;
                    }
                };
                let policy = fixture_peer_policy();
                if let Err(e) = policy.check(&creds) {
                    eprintln!("Rejected browser peer: {e}");
                    continue;
                }
                s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .map_err(|e| err!(EIO, "CDP_TIMEOUT", "{e}"))?;
                s.set_write_timeout(Some(std::time::Duration::from_secs(5)))
                    .map_err(|e| err!(EIO, "CDP_TIMEOUT", "{e}"))?;

                let session_id = format!("session_{}", enclave_core::rng::u64());
                let session_dir = args.throwaway_dir.join(&session_id);
                let _ = std::fs::create_dir_all(&session_dir);

                if args.owned_webkit {
                    let browser = match prepared_browser.take() {
                        Some(browser) => browser,
                        None => enclave_model_runnerd::owned_browser::OwnedWebKit::new()?,
                    };
                    let _ = handle_cdp_backend(s, &session_dir,
                        std::time::Duration::from_secs(5), std::time::Duration::from_secs(30), Some(browser));
                } else {
                    let _ = handle_cdp_client(s, &session_dir);
                }
                let _ = std::fs::remove_dir_all(&session_dir);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(e) => {
                if term.load(Ordering::SeqCst) {
                    break;
                }
                eprintln!("Accept error: {e}");
            }
        }
    }

    let _ = std::fs::remove_file(&args.socket);
    Ok(())
}

#[cfg(test)]
mod f98_tests {
    use super::*;

    #[test]
    fn deployment_fixture_mix_refuses_before_missing_descriptor_read() {
        for mode in ["--response-fixture", "--dev-same-uid", "--owned-webkit"] {
            let args = Args::try_parse_from(["browser", "--deployment-target",
                "/missing-descriptor", "--profile", "L3", mode]).unwrap();
            assert!(bind_deployment(&args).unwrap_err().is("DEPLOYMENT_MIXED_ARGUMENTS"));
        }
        let args = Args::try_parse_from(["browser", "--profile", "L3"]).unwrap();
        assert!(bind_deployment(&args).unwrap_err().is("DEPLOYMENT_MIXED_ARGUMENTS"));
    }

    #[test]
    fn response_fixture_accepts_only_its_own_uid() {
        let uid = enclave_core::ipc::geteuid();
        let policy = fixture_peer_policy();
        let mut peer = enclave_core::ipc::PeerCredentials {
            uid, gid: uid, pid: Some(123), audit_token: None,
            code_identity: None, tls_channel_binding: None,
        };
        assert!(policy.check(&peer).is_ok());
        for other in [0, 501, 701, 702, uid.wrapping_add(1)] {
            if other == uid { continue; }
            peer.uid = other;
            assert!(policy.check(&peer).unwrap_err().is("PEER_UID_REJECTED"));
        }
    }

    fn read_response(stream: &mut UnixStream) -> Value {
        let mut bytes = Vec::new();
        loop {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            if byte[0] == 0 {
                break;
            }
            bytes.push(byte[0]);
        }
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn valid_frame_receives_response_before_deadline() {
        let (mut writer, reader) = UnixStream::pair().unwrap();
        writer
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let worker = std::thread::spawn(move || {
            handle_cdp_client_with_limits(
                reader,
                Path::new("/nonexistent/depot-f98"),
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(2),
            )
        });
        writer
            .write_all(b"{\"id\":7,\"method\":\"DOM.getDocument\"}\0")
            .unwrap();
        let response = read_response(&mut writer);
        assert_eq!(response["id"], 7);
        assert_eq!(response["result"]["root"]["nodeName"], "#document");
        writer.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(worker.join().unwrap().is_ok());
    }

    #[test]
    fn maximum_frame_and_following_coalesced_frames_remain_valid() {
        let (mut writer, reader) = UnixStream::pair().unwrap();
        writer
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        writer
            .set_write_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let worker = std::thread::spawn(move || {
            handle_cdp_client(reader, Path::new("/nonexistent/depot-f98"))
        });
        // A full 1MiB wire frame, including its delimiter, must fit. Its many
        // read boundaries exercise the incremental scan through a valid frame.
        let mut frame = b"{\"id\":8,\"method\":\"DOM.getDocument\"}".to_vec();
        frame.resize(1024 * 1024 - 1, b' ');
        frame.push(0);
        writer.write_all(&frame).unwrap();
        let response = read_response(&mut writer);
        assert_eq!(response["id"], 8);
        assert_eq!(response["result"]["root"]["nodeName"], "#document");

        // Processing a delimiter must reset the scan cursor, including when
        // the next read contains more than one complete frame.
        writer.write_all(b"{\"id\":9}\0{\"id\":10}\0").unwrap();
        assert_eq!(read_response(&mut writer)["id"], 9);
        assert_eq!(read_response(&mut writer)["id"], 10);
        writer.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(worker.join().unwrap().is_ok());
    }

    #[test]
    fn idle_reads_classify_the_first_absolute_deadline() {
        for (frame, connection, expected) in [
            (100, 1000, "CDP_FRAME_DEADLINE"),
            (1000, 100, "CDP_CONNECTION_DEADLINE"),
        ] {
            // Keep the peer open and silent so that EOF cannot satisfy the
            // deadline check, and use real socket timeouts on each platform.
            let (_writer, reader) = UnixStream::pair().unwrap();
            let started = std::time::Instant::now();
            let err = handle_cdp_client_with_limits(
                reader,
                Path::new("/nonexistent/depot-f98"),
                std::time::Duration::from_millis(frame),
                std::time::Duration::from_millis(connection),
            )
            .unwrap_err();
            assert!(err.is(expected), "expected {expected}, got {err}");
            assert_eq!(err.errno, enclave_core::error::Errno::ETIMEDOUT);
            assert!(started.elapsed() >= std::time::Duration::from_millis(100));
            assert!(started.elapsed() < std::time::Duration::from_secs(1));
        }
    }

    #[test]
    fn open_peer_socket_timeouts_accept_fractional_second_boundaries() {
        let (_peer, stream) = UnixStream::pair().unwrap();
        for nanos in [1, 999_999_999, 1_000_000_000, 1_000_000_001, 4_999_999_999] {
            let timeout = std::time::Duration::from_nanos(nanos);
            stream
                .set_read_timeout(Some(timeout))
                .unwrap_or_else(|e| panic!("read timeout {timeout:?}: {e}"));
            stream
                .set_write_timeout(Some(timeout))
                .unwrap_or_else(|e| panic!("write timeout {timeout:?}: {e}"));
        }
    }

    #[test]
    fn closed_peer_timeout_diagnostic_keeps_buffered_payload_distinct() {
        let (mut peer, mut stream) = UnixStream::pair().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let payload = b"queued bytes remain after the peer closes both directions";
        peer.write_all(payload).unwrap();
        drop(peer);
        let result = stream.set_read_timeout(Some(std::time::Duration::from_nanos(4_999_999_999)));
        // XNU may reject socket options after disconnection despite readable
        // queued bytes. This diagnostic is not a required failure or a browser
        // resource-limit test: accepted options on other kernels are also valid.
        if let Err(e) = &result {
            assert_eq!(e.raw_os_error(), Some(libc::EINVAL), "{e}");
        }
        eprintln!("closed-peer timeout update: {result:?}");
        let mut received = Vec::new();
        stream.read_to_end(&mut received).unwrap();
        assert_eq!(received, payload);
    }

    #[test]
    fn buffered_frames_with_unread_responses_obey_connection_deadline() {
        use std::os::fd::AsRawFd;
        let (mut writer, reader) = UnixStream::pair().unwrap();
        let send_buffer: libc::c_int = 1024;
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    reader.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    &send_buffer as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&send_buffer) as libc::socklen_t,
                )
            },
            0
        );
        let sender = std::thread::spawn(move || {
            let _ = writer.write_all(&b"{\"id\":1,\"method\":\"DOM.getDocument\"}\0".repeat(20000));
        });
        let started = std::time::Instant::now();
        assert!(handle_cdp_client_with_limits(
            reader,
            Path::new("/nonexistent/depot-f98"),
            std::time::Duration::from_secs(1),
            std::time::Duration::from_millis(150)
        )
        .is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        sender.join().unwrap();
    }

    #[test]
    fn slow_drip_incomplete_frame_has_absolute_deadline() {
        let (mut writer, reader) = UnixStream::pair().unwrap();
        let sender = std::thread::spawn(move || {
            for _ in 0..80 {
                if writer.write_all(b"x").is_err() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });
        let started = std::time::Instant::now();
        let err = handle_cdp_client(reader, Path::new("/nonexistent/depot-f98")).unwrap_err();
        assert!(err.is("CDP_FRAME_DEADLINE"), "{err}");
        assert!(started.elapsed() < std::time::Duration::from_secs(7));
        sender.join().unwrap();
    }

    #[test]
    fn unterminated_frames_are_bounded() {
        let (mut writer, reader) = UnixStream::pair().unwrap();
        let (classified, release_sender) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let _ = writer.write_all(&vec![b'x'; 1024 * 1024 + 1]);
            // Keep the attacker connection open until the resource decision.
            // Darwin rejects setsockopt on a fully disconnected peer even when
            // queued bytes remain; that is a different, legitimate fail-close.
            release_sender.recv().unwrap();
            drop(writer);
        });
        let started = std::time::Instant::now();
        let err = handle_cdp_client(reader, Path::new("/nonexistent/depot-f98")).unwrap_err();
        let elapsed = started.elapsed();
        classified.send(()).unwrap();
        thread.join().unwrap();
        assert!(
            err.is("CDP_FRAME_TOO_LARGE"),
            "expected resource limit before deadline, got {err} after {:?}",
            elapsed
        );
        assert!(elapsed < std::time::Duration::from_secs(5));
    }
}
