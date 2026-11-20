//! Real helper process: refuse unavailable actuation before filesystem effects.
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let path =
            std::env::temp_dir().join(format!("phase4-browser-{}", enclave_core::rng::u64()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_enclave-cdp-browser"))
}

#[test]
fn phase4_installed_browser_refuses_before_socket_or_profile_effects() {
    let dir = Fixture::new();
    let socket = dir.path().join("browser.sock");
    let profiles = dir.path().join("profiles");
    // An existing endpoint must survive refusal, including with a supplied pin.
    std::fs::write(&socket, b"preserve-existing-endpoint").unwrap();
    for extra in [
        vec![],
        vec![
            "--browser-path",
            "/missing/browser",
            "--expected-hash",
            "00",
        ],
    ] {
        let output = binary()
            .arg("--socket")
            .arg(&socket)
            .arg("--throwaway-dir")
            .arg(&profiles)
            .args(extra)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("BROWSER_BACKEND_UNAVAILABLE"));
        assert_eq!(
            std::fs::read(&socket).unwrap(),
            b"preserve-existing-endpoint"
        );
        assert!(!profiles.exists());
    }
}

#[test]
fn phase4_fixture_requires_explicit_development_and_has_no_real_browser() {
    let dir = Fixture::new();
    let socket = dir.path().join("browser.sock");
    for extra in [
        vec!["--response-fixture"],
        vec![
            "--response-fixture",
            "--dev-same-uid",
            "--browser-path",
            "/missing/browser",
        ],
        vec![
            "--response-fixture",
            "--dev-same-uid",
            "--expected-hash",
            "00",
        ],
    ] {
        let output = binary()
            .arg("--socket")
            .arg(&socket)
            .args(extra)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("BROWSER_FIXTURE_REQUIRES_DEBUG_SAME_UID")
                || stderr.contains("BROWSER_FIXTURE_HAS_NO_BROWSER"),
            "{stderr}"
        );
        assert!(!socket.exists());
    }
}

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn phase4_explicit_debug_fixture_still_serves_protocol_tests() {
    let dir = Fixture::new();
    let socket = dir.path().join("browser.sock");
    let mut child = OwnedChild(
        binary()
            .args(["--response-fixture", "--dev-same-uid"])
            .arg("--socket")
            .arg(&socket)
            .arg("--throwaway-dir")
            .arg(dir.path().join("profiles"))
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    if !cfg!(debug_assertions) {
        assert!(!child.0.wait().unwrap().success());
        assert!(!socket.exists());
        return;
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut stream = loop {
        if let Ok(stream) = UnixStream::connect(&socket) {
            break stream;
        }
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "fixture exited before listening"
        );
        assert!(Instant::now() < deadline, "fixture startup timed out");
        std::thread::sleep(Duration::from_millis(10));
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .write_all(b"{\"id\":7,\"method\":\"DOM.getDocument\"}\0")
        .unwrap();
    let mut bytes = Vec::new();
    for _ in 0..4096 {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        if byte[0] == 0 {
            break;
        }
        bytes.push(byte[0]);
    }
    let response: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(response["id"], 7);
    assert_eq!(response["result"]["root"]["nodeName"], "#document");
}

#[test]
fn phase4_owned_browser_requires_explicit_mode_and_supported_platform() {
    let dir = Fixture::new();
    let socket = dir.path().join("owned.sock");
    std::fs::write(&socket, b"preserve").unwrap();
    for flags in [vec!["--owned-webkit"], vec!["--owned-webkit", "--response-fixture", "--dev-same-uid"]] {
        let output = binary().args(flags).arg("--socket").arg(&socket).output().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("OWNED_WEBKIT_REQUIRES_DEBUG_SAME_UID"));
        assert_eq!(std::fs::read(&socket).unwrap(), b"preserve");
    }
    #[cfg(not(target_os = "macos"))]
    {
        let output = binary().args(["--owned-webkit", "--dev-same-uid"]).arg("--socket").arg(&socket).output().unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains("WEBKIT_PLATFORM_UNAVAILABLE") || error.contains("OWNED_WEBKIT_REQUIRES_DEBUG_SAME_UID"));
        assert_eq!(std::fs::read(&socket).unwrap(), b"preserve");
    }
}

#[cfg(target_os = "macos")]
#[test]
fn phase4_real_owned_webkit_observes_dom_effects_refusal_and_fresh_sessions() {
    use serde_json::{json, Value};
    if !cfg!(debug_assertions) { return; }
    fn call(stream: &mut UnixStream, method: &str, params: Value) -> Value {
        let mut request = serde_json::to_vec(&json!({"id":7,"method":method,"params":params})).unwrap();
        request.push(0);
        stream.write_all(&request).unwrap();
        let mut response = Vec::new();
        for _ in 0..65_536 {
            let mut byte=[0];stream.read_exact(&mut byte).unwrap();
            if byte[0]==0 { return serde_json::from_slice(&response).unwrap(); }
            response.push(byte[0]);
        }
        panic!("unbounded browser response");
    }
    fn query(stream: &mut UnixStream, selector: &str) -> u64 {
        call(stream,"DOM.querySelector",json!({"selector":selector}))["result"]["nodeId"].as_u64().unwrap()
    }
    fn click(stream: &mut UnixStream, node: u64) {
        let model=call(stream,"DOM.getBoxModel",json!({"nodeId":node}));
        let corners=model["result"]["model"]["content"].as_array().unwrap();
        let x=(corners[0].as_f64().unwrap()+corners[2].as_f64().unwrap())/2.;
        let y=(corners[1].as_f64().unwrap()+corners[5].as_f64().unwrap())/2.;
        for kind in ["mousePressed","mouseReleased"] {
            let response=call(stream,"Input.dispatchMouseEvent",json!({"type":kind,"x":x,"y":y,"button":"left"}));
            assert!(response.get("error").is_none(),"{response}");
        }
    }
    let dir=Fixture::new();let socket=dir.path().join("real.sock");
    let mut child=OwnedChild(binary().args(["--owned-webkit","--dev-same-uid"])
        .arg("--socket").arg(&socket).arg("--throwaway-dir").arg(dir.path().join("sessions"))
        .stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap());
    let deadline=Instant::now()+Duration::from_secs(20);
    let mut stream=loop {
        if let Ok(stream)=UnixStream::connect(&socket){break stream;}
        if let Some(status)=child.0.try_wait().unwrap() {
            let mut error=String::new();child.0.stderr.take().unwrap().read_to_string(&mut error).unwrap();
            panic!("real WebKit startup failed: {status}: {error}");
        }
        assert!(Instant::now()<deadline,"real WebKit startup timeout");
        std::thread::sleep(Duration::from_millis(10));
    };
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    assert_eq!(call(&mut stream,"DOM.getDocument",json!({}))["result"]["root"]["nodeName"],"#document");
    let counter=query(&mut stream,"#count");
    assert!(call(&mut stream,"DOM.getOuterHTML",json!({"nodeId":counter}))["result"]["outerHTML"].as_str().unwrap().contains(">0</output>"));
    let button=query(&mut stream,"#increment");click(&mut stream,button);
    assert!(call(&mut stream,"DOM.getOuterHTML",json!({"nodeId":counter}))["result"]["outerHTML"].as_str().unwrap().contains(">1</output>"));
    for (method,params) in [("Page.navigate",json!({"url":"https://example.invalid"})),
        ("Page.navigate",json!({"url":"file:///etc/passwd"})),
        ("Runtime.evaluate",json!({"expression":"fetch('https://example.invalid')"})),
        ("Input.dispatchMouseEvent",json!({"type":"mouseReleased","x":50,"y":50,"button":"left"}))] {
        assert!(call(&mut stream,method,params).get("error").is_some());
    }
    let entry=query(&mut stream,"#entry");click(&mut stream,entry);
    let text="owned quote '\" text";
    assert!(call(&mut stream,"Input.insertText",json!({"text":text})).get("error").is_none());
    assert!(call(&mut stream,"DOM.getOuterHTML",json!({"nodeId":entry}))["result"]["outerHTML"].as_str().unwrap().contains("owned quote"));
    drop(stream);
    // A new peer connection receives a new nonpersistent actual document.
    let mut second=UnixStream::connect(&socket).unwrap();
    second.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    let counter=query(&mut second,"#count");
    assert!(call(&mut second,"DOM.getOuterHTML",json!({"nodeId":counter}))["result"]["outerHTML"].as_str().unwrap().contains(">0</output>"));
}

/// Exercise the real socket actuator and independently observe the same live
/// WebKit document. The test relay forwards every actuator request/response
/// unchanged; its separate read-only queries inspect actual effects/identities.
#[cfg(all(target_os = "macos", debug_assertions))]
#[test]
fn phase4_owned_webkit_actual_actuator_observes_nested_effects_and_hostile_refusals() {
    use enclave_model_runnerd::classes::world::{Action, Actuator, CdpSocketActuator, ResolvedTarget};
    use enclave_model_runnerd::owned_browser::OWNED_DOCUMENT_ORIGIN;
    use serde_json::{json, Value};
    use std::os::unix::net::UnixListener;

    fn receive(stream: &mut UnixStream) -> Value {
        let mut bytes = Vec::new();
        for _ in 0..65_536 {
            let mut b = [0];
            stream.read_exact(&mut b).unwrap();
            if b[0] == 0 { return serde_json::from_slice(&bytes).unwrap(); }
            bytes.push(b[0]);
        }
        panic!("bounded owned-browser response exceeded");
    }
    fn send(stream: &mut UnixStream, value: &Value) {
        let mut bytes = serde_json::to_vec(value).unwrap();
        bytes.push(0);
        stream.write_all(&bytes).unwrap();
    }
    fn observe(stream: &mut UnixStream, method: &str, params: Value) -> Value {
        send(stream, &json!({"id":1_000_000,"method":method,"params":params}));
        let result = receive(stream);
        assert_eq!(result["id"], 1_000_000);
        result
    }
    fn query(stream: &mut UnixStream, selector: &str) -> u64 {
        observe(stream, "DOM.querySelector", json!({"nodeId":1,"selector":selector}))
            ["result"]["nodeId"].as_u64().filter(|n| *n >= 2).unwrap()
    }
    fn html(stream: &mut UnixStream, node: u64) -> String {
        observe(stream, "DOM.getOuterHTML", json!({"nodeId":node}))
            ["result"]["outerHTML"].as_str().unwrap().to_owned()
    }
    fn action(selector: &str, origin: &str) -> Action {
        Action { tool_id:1, params_q:vec![0,0], target:ResolvedTarget {
            app_bundle_id:"org.depot.owned-development-document".into(),
            ax_role:"AXButton".into(), ax_title:"Owned test action".into(),
            url_origin:origin.into(), dom_selector:selector.into(),
        }}
    }

    let dir = Fixture::new();
    let socket = dir.path().join("owned.sock");
    let mut child = OwnedChild(binary().args(["--owned-webkit", "--dev-same-uid"])
        .arg("--socket").arg(&socket).arg("--throwaway-dir").arg(dir.path().join("sessions"))
        .stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(20);
    let backend = loop {
        if let Ok(stream) = UnixStream::connect(&socket) { break stream; }
        if let Some(status) = child.0.try_wait().unwrap() {
            let mut error = String::new();
            child.0.stderr.take().unwrap().read_to_string(&mut error).unwrap();
            panic!("owned browser exited: {status}: {error}");
        }
        assert!(Instant::now() < deadline, "owned browser startup timeout");
        std::thread::sleep(Duration::from_millis(10));
    };
    let peer = enclave_core::ipc::peer_credentials(&backend).unwrap();
    assert_eq!(peer.uid, enclave_core::ipc::geteuid());
    backend.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    backend.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let relay_socket = dir.path().join("relay.sock");
    let listener = UnixListener::bind(&relay_socket).unwrap();
    let (ready, wait_ready) = std::sync::mpsc::channel();
    let relay = std::thread::spawn(move || {
        let mut backend = backend;
        let frame = observe(&mut backend, "Page.getFrameTree", json!({}));
        assert_eq!(frame["result"]["frameTree"]["frame"]["url"], format!("{OWNED_DOCUMENT_ORIGIN}/"));
        let frame_id = frame["result"]["frameTree"]["frame"]["id"].as_str().unwrap().to_owned();
        assert!(!frame_id.is_empty());
        let counter = query(&mut backend, "#count");
        let decoys = query(&mut backend, "#decoy-count");
        let old_increment = query(&mut backend, "#increment");
        let nested_hit = query(&mut backend, "#nested-hit");
        let overlay = query(&mut backend, "#occluder");
        assert!(html(&mut backend, counter).contains(">0</output>"));
        assert!(html(&mut backend, decoys).contains(">0</output>"));
        ready.send(()).unwrap();
        let (mut client, _) = listener.accept().unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        client.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut releases = Vec::new();
        let mut hits = Vec::new();
        loop {
            // EOF is the actuator dropping its live connection after all
            // assertions. No second document is used as an effect oracle.
            let mut first = [0];
            match client.read(&mut first) {
                Ok(0) => break,
                Ok(1) => {},
                other => panic!("actuator relay read: {other:?}"),
            }
            assert_ne!(first[0], 0);
            let mut bytes = vec![first[0]];
            loop {
                let mut b = [0];
                client.read_exact(&mut b).unwrap();
                if b[0] == 0 { break; }
                assert!(bytes.len() < 65_535);
                bytes.push(b[0]);
            }
            let request: Value = serde_json::from_slice(&bytes).unwrap();
            send(&mut backend, &request);
            let response = receive(&mut backend);
            assert_eq!(response["id"], request["id"]);
            if request["method"] == "DOM.getNodeForLocation" {
                hits.push(response["result"]["backendNodeId"].as_u64().unwrap());
            }
            if request["method"] == "Input.dispatchMouseEvent" && request["params"]["type"] == "mouseReleased" {
                assert!(response.get("error").is_none(), "{response}");
                releases.push((html(&mut backend, counter), html(&mut backend, decoys),
                    query(&mut backend, "#increment")));
            }
            send(&mut client, &response);
        }
        assert_eq!(releases.len(), 4, "only the four authorized actions may release");
        for (index, expected) in [1,2,2,3].into_iter().enumerate() {
            assert!(releases[index].0.contains(&format!(">{expected}</output>")), "{releases:?}");
            assert!(releases[index].1.contains(">0</output>"), "{releases:?}");
        }
        assert_eq!(hits.len(), 5);
        assert_eq!(hits[0], nested_hit, "actual descendant hit must pass");
        assert_eq!(hits[1], overlay, "actual unrelated overlay must refuse");
        assert_eq!(releases[0].2, old_increment);
        assert_eq!(releases[1].2, old_increment);
        assert_ne!(releases[2].2, old_increment, "replacement must acquire a new node identity");
        assert_eq!(releases[2].2, releases[3].2);
        for method in ["DOM.getBoxModel", "DOM.getOuterHTML"] {
            assert!(observe(&mut backend, method, json!({"nodeId":old_increment})).get("error").is_some());
        }
        assert!(html(&mut backend, counter).contains(">3</output>"));
        assert!(html(&mut backend, decoys).contains(">0</output>"));
        frame_id
    });
    wait_ready.recv_timeout(Duration::from_secs(15)).unwrap();
    let mut actuator = CdpSocketActuator::new(&relay_socket)
        .with_expected_uid(enclave_core::ipc::geteuid());
    actuator.execute(&action("#nested-increment", OWNED_DOCUMENT_ORIGIN)).unwrap();
    assert!(actuator.execute(&action("#increment", "https://other.invalid"))
        .unwrap_err().is("ACTUATION_ORIGIN_MISMATCH"));
    assert!(actuator.execute(&action("#delete-repo > button", OWNED_DOCUMENT_ORIGIN))
        .unwrap_err().is("ACTUATION_NODE_FORBIDDEN_OR_STALE"));
    assert!(actuator.execute(&action("#occluded", OWNED_DOCUMENT_ORIGIN))
        .unwrap_err().is("ACTUATION_OCCLUDED_OR_STALE"));
    actuator.execute(&action("#increment", OWNED_DOCUMENT_ORIGIN)).unwrap();
    actuator.execute(&action("#replace-increment", OWNED_DOCUMENT_ORIGIN)).unwrap();
    actuator.execute(&action("#increment", OWNED_DOCUMENT_ORIGIN)).unwrap();
    drop(actuator);
    let old_frame = relay.join().unwrap();
    // The helper creates a new actual document for the next connection. IDs
    // are scoped to that session; numeric node IDs may restart there.
    let mut fresh = UnixStream::connect(&socket).unwrap();
    fresh.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    fresh.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let frame = observe(&mut fresh, "Page.getFrameTree", json!({}));
    assert_eq!(frame["result"]["frameTree"]["frame"]["url"], format!("{OWNED_DOCUMENT_ORIGIN}/"));
    assert_ne!(frame["result"]["frameTree"]["frame"]["id"].as_str().unwrap(), old_frame);
    let counter = query(&mut fresh, "#count");
    assert!(html(&mut fresh, counter).contains(">0</output>"));
    let decoys = query(&mut fresh, "#decoy-count");
    assert!(html(&mut fresh, decoys).contains(">0</output>"));
    eprintln!("OWNED_WEBKIT_ACTUATOR_BRIDGE=true origin=true nested_hit=true forbidden_ancestor=true overlay=true replacement_identity=true fresh_session=true");
}
