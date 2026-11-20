//! Real service -> kernel-authenticated operator transport -> offline aggregator.
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use enclave_agent_runtime::cedar_engine::CedarEngine;
use enclave_agent_runtime::registry::ToolRegistry;
use enclave_agent_runtime::service::{Declassifier, IfcConfig, IfcRequest, IfcResponse, IfcService, NoCustody};
use enclave_core::daemon::DaemonId;
use enclave_core::error::EnclaveResult;
use enclave_core::ipc::{from_cbor, peer_credentials, read_frame, to_cbor, write_frame, Reply};
use enclave_core::profile::Profile;
use depot_enclave::ctl::{ifc_policy_sli, Env, PolicySliExport};

#[derive(Debug)]
struct NoDeclass;
impl Declassifier for NoDeclass {
    fn classify(&self, _: &[u8], _: u64, _: &str, _: &enclave_core::seq::GovernedSlot) -> EnclaveResult<u64> {
        unreachable!("telemetry must never declassify")
    }
}

fn acquire(mutate: impl FnOnce(&mut enclave_agent_runtime::policy_sli::PolicySliSnapshot) + Send + 'static) -> EnclaveResult<PolicySliExport> {
    let mut nonce = [0; 8];
    enclave_core::rng::fill(&mut nonce);
    // Keep the Unix socket pathname below Darwin's short sun_path limit.
    let dir = std::path::Path::new("/tmp").join(format!("depot-sli-{}", hex::encode(nonce)));
    let env = Env::dev(&dir, Profile::L2);
    let socket = env.socket_dir.join(DaemonId::AgentRuntime.socket_name());
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    let service = IfcService::start(IfcConfig {
        profile: Profile::L2, audit_path: None, policy_key: SigningKey::generate(&mut rand_core::OsRng),
        limits: enclave_crypto::pop_biscuit::spec_limits(),
        registry: ToolRegistry::load(br#"{"v":1,"servers":[]}"#).unwrap(),
        cedar: Some(CedarEngine::baseline_bundle().unwrap()), state_dir: None, socket_dir: None, dev_same_uid: true,
    }, Box::new(NoDeclass), Box::new(NoCustody)).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let peer = peer_credentials(&stream).unwrap();
        assert_eq!(peer.uid, enclave_core::ipc::geteuid());
        let request: IfcRequest = from_cbor(&read_frame(&mut stream).unwrap()).unwrap();
        assert!(matches!(request, IfcRequest::PolicySli));
        let mut response: EnclaveResult<IfcResponse> = service.handle(&peer, request);
        if let Ok(IfcResponse::PolicySli(snapshot)) = &mut response { mutate(snapshot); }
        let reply = match response { Ok(v) => Reply::Ok(v), Err(e) => Reply::Err(e) };
        write_frame(&mut stream, &to_cbor(&reply).unwrap()).unwrap();
    });
    let export = ifc_policy_sli(&env);
    server.join().unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    export
}

#[test]
fn policy_sli_actual_service_export_has_verified_kernel_peer_and_remains_incomplete_in_real_aggregator() {
    let export = acquire(|_| {}).unwrap();
    assert_eq!(export.peer_uid, enclave_core::ipc::geteuid());
    assert_eq!(export.peer_pid, Some(std::process::id()));
    assert!(!export.server_code_verified && export.peer_code_identity.is_none());
    assert!(!export.history_complete);
    assert_eq!(export.snapshot.observed_total, 0);
    assert!(export.snapshot.buckets.is_empty(), "never fabricate preboot coverage");
    let rows = export.snapshot.rows();
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/aggregate-sli.py");
    let program = r#"import importlib.util,json,sys
spec=importlib.util.spec_from_file_location('aggregate',sys.argv[1]); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
v=json.load(sys.stdin); result=m.aggregate(v['rows'],v['as_of']); print(json.dumps(result)); sys.exit(1 if not result['complete'] else 0)
"#;
    let mut child = Command::new("python3").args(["-c", program]).arg(&script)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    use std::io::Write;
    child.stdin.take().unwrap().write_all(&serde_json::to_vec(&serde_json::json!({
        "rows":rows,"as_of":export.snapshot.as_of_unix_s.unwrap()
    })).unwrap()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(1), "{}", String::from_utf8_lossy(&output.stderr));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "INCOMPLETE");
    for metric in ["policy_evaluation", "swarm_sync"] {
        assert!(report["metrics"][metric]["decisions"].as_array().unwrap().iter().all(|v| v["state"] == "UNKNOWN"));
    }
 }

#[test]
fn policy_sli_authenticated_transport_refuses_reply_uid_pid_and_mode_mismatches() {
    for mutate in [
        (|s: &mut enclave_agent_runtime::policy_sli::PolicySliSnapshot| s.runtime_uid ^= 1) as fn(&mut enclave_agent_runtime::policy_sli::PolicySliSnapshot),
        |s| s.runtime_pid = s.runtime_pid.wrapping_add(1),
        |s| s.dev_same_uid = false,
    ] {
        let error = acquire(mutate).unwrap_err();
        assert!(error.is("POLICY_SLI_IDENTITY_MISMATCH"), "{error}");
    }
}
