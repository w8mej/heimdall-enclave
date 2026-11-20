//! Actual same-UID authenticated UDS transport with synthetic CDP peers.
//! No installed browser, native authority, device or receiver-effect recall claim.
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use enclave_model_runnerd::classes::world::{Action, Actuator, CdpSocketActuator, ResolvedTarget};
use serde_json::{json, Value};

struct Socket { path: PathBuf, dir: PathBuf }
impl Socket {
    fn new() -> (Self, UnixListener) {
        // Short relative path also fits macOS's sockaddr_un in long checkouts.
        let dir = PathBuf::from(format!("target/cdp-bounded-{}", enclave_core::rng::u64()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s");
        let listener = UnixListener::bind(&path).unwrap();
        (Self { path, dir }, listener)
    }
    fn actuator(&self) -> CdpSocketActuator {
        CdpSocketActuator::new(&self.path).with_expected_uid(enclave_core::ipc::geteuid())
    }
}
impl Drop for Socket { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.dir); } }
fn accept(listener: UnixListener) -> UnixStream {
    let (stream, _) = listener.accept().unwrap();
    stream.set_nonblocking(false).unwrap();
    // macOS (BSD) rejects SO_RCVTIMEO/SO_SNDTIMEO with EINVAL once the peer
    // has already closed, as in the refusal tests. A closed peer needs no
    // timeout: reads then return end of file immediately.
    for timeout in [stream.set_read_timeout(Some(Duration::from_secs(2))),
                    stream.set_write_timeout(Some(Duration::from_secs(2)))] {
        if let Err(error) = timeout {
            assert_eq!(error.raw_os_error(), Some(libc::EINVAL), "socket timeout: {error}");
        }
    }
    // A peer that already closed has no retrievable credentials on macOS;
    // callers then assert that nothing was sent (`request` returns None).
    match enclave_core::ipc::peer_credentials(&stream) {
        Ok(peer) => assert_eq!(peer.uid, enclave_core::ipc::geteuid()),
        Err(error) => assert!(error.is("LOCAL_PEERTOKEN_UNAVAILABLE"), "{error}"),
    }
    stream
}
fn action() -> Action {
    Action { tool_id: 1, params_q: vec![0], target: ResolvedTarget {
        app_bundle_id: "org.example.browser".into(), ax_role: "AXButton".into(),
        ax_title: "Continue".into(), url_origin: "https://bounded.invalid".into(), dom_selector: "#continue".into(),
    }}
}
fn request(stream: &mut UnixStream) -> Option<Value> {
    let mut bytes = Vec::new(); let mut byte = [0];
    loop { match stream.read(&mut byte) { Ok(1) if byte[0] == 0 => return Some(serde_json::from_slice(&bytes).unwrap()),
        Ok(1) => bytes.push(byte[0]), Ok(_) => return None,
        Err(error) if matches!(error.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::BrokenPipe) => return None,
        Err(error) => panic!("peer read: {error}"), } }
}
fn send(stream: &mut UnixStream, value: Value) -> bool {
    let mut bytes = serde_json::to_vec(&value).unwrap(); bytes.push(0);
    stream.write_all(&bytes).is_ok()
}
fn result(method: &str) -> Value {
    match method {
        "Page.getFrameTree" => json!({"frameTree":{"frame":{"url":"https://bounded.invalid/page"}}}),
        "DOM.getDocument" => json!({"root":{"nodeId":1,"children":[{"nodeId":2,"backendNodeId":20,"attributes":["id","continue"]}]}}),
        "DOM.querySelector" => json!({"nodeId":2}),
        "DOM.getBoxModel" => json!({"model":{"content":[10,10,20,10,20,20,10,20]}}),
        "DOM.getNodeForLocation" => json!({"backendNodeId":20}),
        "Input.dispatchMouseEvent" => json!({}), _ => panic!("unexpected {method}"),
    }
}
#[test]
fn bounded_authenticated_positive_preserves_exact_eight_command_sequence() {
    let (socket, listener) = Socket::new();
    let peer = std::thread::spawn(move || {
        let mut stream = accept(listener); let mut methods = Vec::new(); let mut events = Vec::new();
        while let Some(req) = request(&mut stream) {
            let method = req["method"].as_str().unwrap(); methods.push(method.to_owned());
            if method == "Input.dispatchMouseEvent" { events.push(req["params"]["type"].as_str().unwrap().to_owned()); }
            assert!(send(&mut stream, json!({"id":req["id"],"result":result(method)})));
        }
        (methods, events)
    });
    let mut actuator = socket.actuator(); let end = Instant::now() + Duration::from_secs(1);
    actuator.prepare_bounded(&action(), end).unwrap(); actuator.execute_bounded(end).unwrap(); drop(actuator);
    let (methods, events) = peer.join().unwrap();
    assert_eq!(methods, ["Page.getFrameTree","DOM.getDocument","DOM.querySelector","DOM.getBoxModel","DOM.getNodeForLocation","Page.getFrameTree","Input.dispatchMouseEvent","Input.dispatchMouseEvent"]);
    assert_eq!(events, ["mousePressed","mouseReleased"]);
}
#[test]
fn continuous_notifications_cannot_renew_absolute_deadline_and_socket_closes() {
    let (socket, listener) = Socket::new();
    let peer = std::thread::spawn(move || {
        let mut stream = accept(listener); assert_eq!(request(&mut stream).unwrap()["id"], 1);
        let mut sent = 0;
        while send(&mut stream, json!({"method":"Runtime.consoleAPICalled","params":{}})) {
            sent += 1; std::thread::sleep(Duration::from_millis(2));
        }
        assert!(request(&mut stream).is_none()); sent
    });
    let mut actuator = socket.actuator(); let end = Instant::now() + Duration::from_millis(80);
    actuator.prepare_bounded(&action(), end).unwrap();
    assert!(actuator.execute_bounded(end).unwrap_err().is("CDP_DEADLINE"));
    assert!(Instant::now() >= end);
    assert!(actuator.execute_bounded(end + Duration::from_secs(1)).unwrap_err().is("ACTUATOR_NOT_PREPARED"));
    assert!(peer.join().unwrap() > 1);
}
#[test]
fn partial_reply_progress_and_idle_peer_cannot_renew_deadline() {
    for partial in [false, true] {
        let (socket, listener) = Socket::new();
        let peer = std::thread::spawn(move || {
            let mut stream = accept(listener); assert!(request(&mut stream).is_some());
            if partial {
                while stream.write_all(b" ").is_ok() { std::thread::sleep(Duration::from_millis(2)); }
            }
            assert!(request(&mut stream).is_none());
        });
        let mut actuator = socket.actuator(); let end = Instant::now() + Duration::from_millis(80);
        actuator.prepare_bounded(&action(), end).unwrap();
        assert!(actuator.execute_bounded(end).unwrap_err().is("CDP_DEADLINE"));
        peer.join().unwrap();
    }
}
#[test]
fn prepared_window_cannot_refresh_and_expired_caller_sends_no_command() {
    let (socket, listener) = Socket::new();
    let peer = std::thread::spawn(move || { let mut stream = accept(listener); assert!(request(&mut stream).is_none()); });
    let mut actuator = socket.actuator(); let end = Instant::now() + Duration::from_millis(30);
    actuator.prepare_bounded(&action(), end).unwrap(); actuator.prepare_bounded(&action(), end + Duration::from_secs(1)).unwrap();
    std::thread::sleep(Duration::from_millis(40));
    assert!(actuator.execute_bounded(end + Duration::from_secs(1)).unwrap_err().is("CDP_DEADLINE"));
    peer.join().unwrap();
    let mut missing = CdpSocketActuator::new("target/absent-cdp-socket");
    assert!(missing.prepare_bounded(&action(), Instant::now()).unwrap_err().is("CDP_DEADLINE"));
}
#[test]
fn timeout_after_press_closes_without_release_retry_or_reuse() {
    let (socket, listener) = Socket::new(); let effects = Arc::new(Mutex::new(Vec::new())); let observed = effects.clone();
    let peer = std::thread::spawn(move || {
        let mut stream = accept(listener);
        while let Some(req) = request(&mut stream) {
            let method = req["method"].as_str().unwrap();
            if method == "Input.dispatchMouseEvent" { observed.lock().unwrap().push(req["params"]["type"].clone());
                assert!(request(&mut stream).is_none()); return; }
            assert!(send(&mut stream, json!({"id":req["id"],"result":result(method)})));
        }
        panic!("never reached press");
    });
    let mut actuator = socket.actuator(); let end = Instant::now() + Duration::from_millis(150);
    actuator.prepare_bounded(&action(), end).unwrap();
    assert!(actuator.execute_bounded(end).unwrap_err().is("CDP_DEADLINE"));
    assert!(actuator.execute_bounded(end).unwrap_err().is("ACTUATOR_NOT_PREPARED"));
    peer.join().unwrap(); assert_eq!(*effects.lock().unwrap(), vec![json!("mousePressed")]);
}
#[test]
fn authenticated_wrong_uid_fails_before_any_command() {
    let (socket, listener) = Socket::new();
    let peer = std::thread::spawn(move || { let mut stream = accept(listener); assert!(request(&mut stream).is_none()); });
    let mut actuator = CdpSocketActuator::new(&socket.path).with_expected_uid(enclave_core::ipc::geteuid().checked_add(1).unwrap());
    assert!(actuator.prepare_bounded(&action(), Instant::now() + Duration::from_secs(1)).unwrap_err().is("BROWSER_PEER_UID_MISMATCH"));
    peer.join().unwrap();
}
#[test]
fn blocked_partial_request_write_uses_same_deadline_and_never_retries() {
    let (socket, listener) = Socket::new();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let peer = std::thread::spawn(move || {
        let mut stream = accept(listener);
        for expected in ["Page.getFrameTree", "DOM.getDocument"] {
            let req = request(&mut stream).unwrap(); assert_eq!(req["method"], expected);
            assert!(send(&mut stream, json!({"id":req["id"],"result":result(expected)})));
        }
        // Stop consuming before a request larger than the socket send buffer.
        resume_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let mut bytes = Vec::new(); stream.read_to_end(&mut bytes).unwrap();
        assert!(!bytes.is_empty()); assert!(!bytes.contains(&0), "a partially sent query is never retried/completed after timeout");
        bytes.len()
    });
    let mut actuator = socket.actuator(); let end = Instant::now() + Duration::from_millis(200);
    let mut a = action(); a.target.dom_selector = "x".repeat(enclave_core::ipc::MAX_FRAME / 2);
    actuator.prepare_bounded(&a, end).unwrap();
    assert!(actuator.execute_bounded(end).unwrap_err().is("CDP_DEADLINE"));
    resume_tx.send(()).unwrap(); assert!(peer.join().unwrap() < a.target.dom_selector.len());
}
#[test]
fn gate_cancellation_closes_prepared_connection_without_any_dispatch() {
    let (socket, listener) = Socket::new();
    let peer = std::thread::spawn(move || { let mut stream = accept(listener); assert!(request(&mut stream).is_none()); });
    let mut actuator = socket.actuator(); let end = Instant::now() + Duration::from_secs(1);
    actuator.prepare_bounded(&action(), end).unwrap(); actuator.cancel_bounded();
    assert!(actuator.execute_bounded(end).unwrap_err().is("ACTUATOR_NOT_PREPARED"));
    peer.join().unwrap();
}
#[test]
fn action_admission_caps_each_variable_input_and_escaped_frame_before_connect() {
    for field in 0..6 {
        let end = Instant::now() + Duration::from_secs(2);
        let mut a = action();
        let large = "x".repeat(enclave_core::ipc::MAX_FRAME + 1);
        match field { 0 => a.target.app_bundle_id = large, 1 => a.target.ax_role = large,
            2 => a.target.ax_title = large, 3 => a.target.url_origin = large,
            4 => a.target.dom_selector = large, _ => a.params_q = vec![0; large.len()] }
        // No listener exists. Size refusal must precede connection/authentication.
        let mut actuator = CdpSocketActuator::new("target/absent-cdp-size-socket");
        assert!(actuator.prepare_bounded(&a, end).unwrap_err().is("CDP_ACTION_TOO_LARGE"));
        assert!(actuator.execute_bounded(end).unwrap_err().is("ACTUATOR_NOT_PREPARED"));
    }
    let end = Instant::now() + Duration::from_secs(2);
    let mut a = action(); a.target.dom_selector = "\0".repeat(enclave_core::ipc::MAX_FRAME / 6 + 32);
    let mut actuator = CdpSocketActuator::new("target/absent-cdp-escaped-socket");
    assert!(actuator.prepare_bounded(&a, end).unwrap_err().is("CDP_FRAME_TOO_LARGE"));
}
