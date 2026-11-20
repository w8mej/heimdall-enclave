//! Actual operator binary dispatch over owned, kernel-authenticated Unix IPC.
//!
//! Fresh-service tests use the actual IfcService snapshot. Historical buckets in
//! the other tests are explicitly synthetic reply fixtures: they test CLI wire
//! formatting and refusal only, and never establish elapsed observation windows,
//! installed identity, load acceptance, synchronization coverage or SLO success.

use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use enclave_agent_runtime::cedar_engine::CedarEngine;
use enclave_agent_runtime::policy_sli::{PolicyBucket, PolicySliSnapshot};
use enclave_agent_runtime::registry::ToolRegistry;
use enclave_agent_runtime::service::{Declassifier, IfcConfig, IfcRequest, IfcResponse, IfcService, NoCustody};
use enclave_core::daemon::DaemonId;
use enclave_core::error::EnclaveResult;
use enclave_core::ipc::{from_cbor, peer_credentials, read_frame, to_cbor, write_frame, Reply};
use enclave_core::profile::Profile;
use mcp_enclave::ctl::{Env, PolicySliExport};

const IO_DEADLINE: Duration = Duration::from_secs(5);
const CHILD_DEADLINE: Duration = Duration::from_secs(15);
const FIXTURE_AS_OF: u64 = 1_800_000_000;

#[derive(Debug)]
struct NoDeclass;

impl Declassifier for NoDeclass {
    fn classify(&self, _: &[u8], _: u64, _: &str, _: &enclave_core::seq::GovernedSlot) -> EnclaveResult<u64> {
        unreachable!("telemetry must never declassify")
    }
}

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn create() -> Self {
        let mut nonce = [0; 8];
        enclave_core::rng::fill(&mut nonce);
        // Keep the socket pathname below Darwin's short sun_path limit. Never
        // adopt or remove a pre-existing directory if the random name collides.
        let path = Path::new("/tmp").join(format!("mcpmac-sli-bin-{}", hex::encode(nonce)));
        std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}

impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct OwnedChild(Option<Child>);

impl OwnedChild {
    fn run(command: &mut Command) -> Output {
        let mut child = Self(Some(command.stdin(Stdio::null()).stdout(Stdio::piped())
            .stderr(Stdio::piped()).spawn().unwrap()));
        let deadline = Instant::now() + CHILD_DEADLINE;
        loop {
            if child.0.as_mut().unwrap().try_wait().unwrap().is_some() {
                return child.0.take().unwrap().wait_with_output().unwrap();
            }
            assert!(Instant::now() < deadline, "owned child exceeded its bounded deadline");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn invoke_binary(
    jsonl: bool,
    mutate_reply_fixture: impl FnOnce(&mut PolicySliSnapshot) + Send + 'static,
) -> Output {
    let directory = OwnedDirectory::create();
    let env = Env::dev(&directory.0, Profile::L2);
    std::fs::DirBuilder::new().mode(0o700).create(&env.socket_dir).unwrap();
    let socket = env.socket_dir.join(DaemonId::AgentRuntime.socket_name());
    // AgentRuntime's socket name includes its daemon-owned subdirectory.
    if socket.parent().unwrap() != env.socket_dir {
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(socket.parent().unwrap()).unwrap();
    }
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let service = IfcService::start(IfcConfig {
        profile: Profile::L2, audit_path: None,
        policy_key: SigningKey::generate(&mut rand_core::OsRng),
        limits: enclave_crypto::pop_biscuit::spec_limits(),
        registry: ToolRegistry::load(br#"{"v":1,"servers":[]}"#).unwrap(),
        cedar: Some(CedarEngine::baseline_bundle().unwrap()),
        state_dir: None, socket_dir: None, dev_same_uid: true,
    }, Box::new(NoDeclass), Box::new(NoCustody)).unwrap();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + IO_DEADLINE;
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "CLI did not connect before the listener deadline");
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("owned listener failed: {error}"),
            }
        };
        stream.set_read_timeout(Some(IO_DEADLINE)).unwrap();
        stream.set_write_timeout(Some(IO_DEADLINE)).unwrap();
        let peer = peer_credentials(&stream).unwrap();
        assert_eq!(peer.uid, enclave_core::ipc::geteuid());
        let request: IfcRequest = from_cbor(&read_frame(&mut stream).unwrap()).unwrap();
        assert!(matches!(request, IfcRequest::PolicySli), "exercise actual main dispatch");
        let mut response = service.handle(&peer, request);
        match &mut response {
            Ok(IfcResponse::PolicySli(snapshot)) => mutate_reply_fixture(snapshot),
            other => panic!("actual service did not supply telemetry: {other:?}"),
        }
        let reply = match response { Ok(value) => Reply::Ok(value), Err(error) => Reply::Err(error) };
        write_frame(&mut stream, &to_cbor(&reply).unwrap()).unwrap();
        peer.pid
    });
    let mut command = Command::new(env!("CARGO_BIN_EXE_mcp-enclave"));
    command.args(["--dev", "--state-dir"]).arg(&directory.0)
        .args(["--profile", "L2", "--json", "ifc", "policy-sli"]);
    if jsonl { command.arg("--jsonl"); }
    // Keep the child's PID before waiting so the server-side kernel receipt is
    // checked independently of any fields supplied in the service reply.
    let mut child = OwnedChild(Some(command.stdin(Stdio::null()).stdout(Stdio::piped())
        .stderr(Stdio::piped()).spawn().unwrap()));
    let child_pid = child.0.as_ref().unwrap().id();
    let deadline = Instant::now() + CHILD_DEADLINE;
    while child.0.as_mut().unwrap().try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "operator binary exceeded its bounded deadline");
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.0.take().unwrap().wait_with_output().unwrap();
    let observed_client_pid = server.join().unwrap();
    assert_eq!(observed_client_pid, Some(i32::try_from(child_pid).unwrap()),
        "supported Linux/macOS hosts must supply the actual kernel client PID");
    output
}

fn assert_success(output: &Output) {
    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
}

fn jsonl_receipt(output: &Output) -> serde_json::Value {
    assert_success(output);
    let receipt: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert!(receipt["snapshot"].get("buckets").is_none(), "metadata must stay outside strict rows");
    assert_eq!(receipt["peer_uid"], enclave_core::ipc::geteuid());
    assert_eq!(receipt["snapshot"]["runtime_pid"], std::process::id());
    assert_eq!(receipt["peer_pid"], std::process::id());
    assert_eq!(receipt["server_code_verified"], false);
    assert!(receipt["peer_code_identity"].is_null());
    assert_eq!(receipt["history_complete"], false);
    receipt
}

/// Explicit historical reply fixture. These counters did not elapse in this
/// process; actual kernel identity and the service's other metadata are kept.
fn synthetic_completed_minute(snapshot: &mut PolicySliSnapshot) {
    snapshot.as_of_unix_s = Some(FIXTURE_AS_OF);
    snapshot.clock_fault = false;
    snapshot.overflow = false;
    snapshot.observed_total = 7;
    snapshot.observed_errors = 0;
    snapshot.buckets = vec![PolicyBucket {
        minute: FIXTURE_AS_OF - 60, total: 7, bad: 2, unknown: 1, errors: 0,
    }];
    snapshot.current = Some(PolicyBucket {
        minute: FIXTURE_AS_OF, total: 0, bad: 0, unknown: 0, errors: 0,
    });
}

fn assert_real_aggregator_incomplete(rows: &[u8], as_of: u64) {
    let directory = OwnedDirectory::create();
    let input = directory.0.join("explicit-fixture.jsonl");
    std::fs::write(&input, rows).unwrap();
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/aggregate-sli.py");
    // Invoke the real bounded file/parser and aggregation functions. No Git or
    // installed/measurement provenance is invented for these fixture bytes.
    let program = r#"import importlib.util,json,pathlib,sys
spec=importlib.util.spec_from_file_location('aggregate',sys.argv[1]); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
rows,digest=m.read_input(pathlib.Path(sys.argv[2]),int(sys.argv[3])); report=m.aggregate(rows,int(sys.argv[3])); print(json.dumps(report)); sys.exit(1 if not report['complete'] else 0)
"#;
    let output = OwnedChild::run(Command::new("python3").args(["-B", "-c", program])
        .arg(script).arg(input).arg(as_of.to_string()));
    assert_eq!(output.status.code(), Some(1), "{}", String::from_utf8_lossy(&output.stderr));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "INCOMPLETE");
    assert_eq!(report["complete"], false);
    for metric in ["policy_evaluation", "swarm_sync"] {
        assert!(report["metrics"][metric]["decisions"].as_array().unwrap()
            .iter().all(|decision| decision["state"] == "UNKNOWN"));
    }
}

#[test]
fn actual_binary_json_exports_fresh_actual_service_snapshot() {
    let output = invoke_binary(false, |_| {});
    assert_success(&output);
    assert!(output.stderr.is_empty());
    let export: PolicySliExport = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(export.peer_uid, enclave_core::ipc::geteuid());
    assert_eq!(export.peer_pid, Some(std::process::id()));
    assert!(!export.server_code_verified && export.peer_code_identity.is_none());
    assert!(!export.history_complete);
    assert_eq!(export.exported_rows, 0);
    assert_eq!(export.snapshot.observed_total, 0);
    assert_eq!(export.snapshot.observed_errors, 0);
    assert!(export.snapshot.buckets.is_empty(), "never fabricate preboot or partial-minute rows");
    assert_eq!(export.snapshot.runtime_uid, enclave_core::ipc::geteuid());
    assert_eq!(export.snapshot.runtime_pid, std::process::id());
    assert!(export.snapshot.dev_same_uid);
}

#[test]
fn actual_binary_jsonl_keeps_fresh_receipt_separate_and_real_aggregator_incomplete() {
    let output = invoke_binary(true, |_| {});
    let receipt = jsonl_receipt(&output);
    assert!(output.stdout.is_empty());
    assert_eq!(receipt["exported_rows"], 0);
    assert_eq!(receipt["snapshot"]["observed_total"], 0);
    assert_real_aggregator_incomplete(&output.stdout, receipt["snapshot"]["as_of_unix_s"].as_u64().unwrap());
}

#[test]
fn actual_binary_formats_explicit_synthetic_rows_for_real_strict_aggregator() {
    let output = invoke_binary(true, synthetic_completed_minute);
    let receipt = jsonl_receipt(&output);
    assert_eq!(receipt["exported_rows"], 1);
    assert_eq!(output.stdout, b"{\"schema\":1,\"metric\":\"policy_evaluation\",\"minute\":1799999940,\"total\":7,\"bad\":2,\"unknown\":1}\n");
    assert_real_aggregator_incomplete(&output.stdout, FIXTURE_AS_OF);
}

#[test]
fn actual_binary_omits_explicit_synthetic_error_bucket_but_preserves_raw_diagnostics() {
    fn fixture(snapshot: &mut PolicySliSnapshot) {
        synthetic_completed_minute(snapshot);
        snapshot.buckets.insert(0, PolicyBucket {
            minute: FIXTURE_AS_OF - 120, total: 1, bad: 1, unknown: 0, errors: 1,
        });
        snapshot.observed_total += 1;
        snapshot.observed_errors = 1;
    }
    let raw = invoke_binary(false, fixture);
    assert_success(&raw);
    let export: PolicySliExport = serde_json::from_slice(&raw.stdout).unwrap();
    assert_eq!(export.snapshot.buckets[0].errors, 1);
    assert_eq!(export.snapshot.buckets[0].bad, 1);
    assert_eq!(export.snapshot.observed_errors, 1);
    assert_eq!(export.exported_rows, 1);
    let jsonl = invoke_binary(true, fixture);
    let receipt = jsonl_receipt(&jsonl);
    assert_eq!(receipt["exported_rows"], 1);
    assert_eq!(receipt["snapshot"]["observed_errors"], 1);
    let row: serde_json::Value = serde_json::from_slice(&jsonl.stdout).unwrap();
    assert_eq!(row["minute"], FIXTURE_AS_OF - 60);
    assert_real_aggregator_incomplete(&jsonl.stdout, FIXTURE_AS_OF);
}

#[test]
fn actual_binary_suppresses_explicit_synthetic_clock_fault_and_overflow_rows() {
    for clock_fault in [true, false] {
        let output = invoke_binary(true, move |snapshot| {
            synthetic_completed_minute(snapshot);
            snapshot.clock_fault = clock_fault;
            snapshot.overflow = !clock_fault;
            if clock_fault { snapshot.as_of_unix_s = None; }
        });
        let receipt = jsonl_receipt(&output);
        assert!(output.stdout.is_empty(), "fault diagnostics cannot become healthy rows");
        assert_eq!(receipt["exported_rows"], 0);
        assert_eq!(receipt["snapshot"]["clock_fault"], clock_fault);
        assert_eq!(receipt["snapshot"]["overflow"], !clock_fault);
        assert_eq!(receipt["snapshot"]["observed_total"], 7);
    }
}

#[test]
fn actual_binary_refuses_reply_uid_pid_and_mode_mismatches_without_healthy_stdout() {
    for jsonl in [false, true] {
        for mutate in [
            (|snapshot: &mut PolicySliSnapshot| snapshot.runtime_uid ^= 1) as fn(&mut PolicySliSnapshot),
            |snapshot| snapshot.runtime_pid = snapshot.runtime_pid.wrapping_add(1),
            |snapshot| snapshot.dev_same_uid = false,
        ] {
            let output = invoke_binary(jsonl, mutate);
            assert_eq!(output.status.code(), Some(1));
            assert!(output.stdout.is_empty(), "refused replies must never print a healthy export");
            assert!(String::from_utf8_lossy(&output.stderr).contains("POLICY_SLI_IDENTITY_MISMATCH"));
        }
    }
}
