//! Full authorized plan -> independently configured issuer -> native host path.
//! Private fixture authorities are not production enrollment or installed services.
use ed25519_dalek::SigningKey;
use enclave_agent_runtime::execution_host::NativeToolDispatch;
use enclave_agent_runtime::registry::{digest_tools_list, ToolRegistry};
use enclave_agent_runtime::service::{
    CustodyPort, Declassifier, IfcConfig, IfcRequest, IfcResponse, IfcService,
};
use enclave_core::error::EnclaveResult;
use enclave_core::daemon::DaemonId;
use enclave_core::ipc::{self, PeerCredentials};
use enclave_core::profile::Profile;
use enclave_core::runtime::DaemonArgs;
use enclave_tool_host::artifacts::{sign_manifest, ApprovedModuleV1, ArtifactManifestV1};
use enclave_tool_host::{ticket::RowFormat, DurableToolHost};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

/// Private same-UID socket fixture. This is an IPC test transport, not a
/// production signing/enrollment or installed-daemon acceptance test.
struct ScopedServer {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<EnclaveResult<()>>>,
}
impl ScopedServer {
    fn start<Req, Resp, H>(path: &std::path::Path, handler: H) -> Self
    where
        Req: serde::de::DeserializeOwned + Send + 'static,
        Resp: Serialize + Send + 'static,
        H: Fn(&PeerCredentials, Req) -> EnclaveResult<Resp> + Send + Sync + 'static,
    {
        let listener = ipc::bind(path, ipc::SocketAccess::OwnerOnly).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let thread = std::thread::spawn(move || {
            ipc::serve_with::<Req, Resp, _>(
                listener,
                ipc::PeerPolicy::allow([ipc::geteuid()]),
                ipc::ServeLimits {
                    max_frame: 64 * 1024,
                    max_connections: 4,
                    max_per_uid: 4,
                    inflight_bytes: 256 * 1024,
                    frame_deadline: Duration::from_secs(2),
                },
                Arc::new(ipc::ServeStats::default()),
                Arc::new(handler),
                thread_stop,
            )
        });
        Self { stop, thread: Some(thread) }
    }
}
impl Drop for ScopedServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let result = self.thread.take().unwrap().join();
        if !std::thread::panicking() {
            result.expect("private IPC accept thread panicked").expect("private IPC server failed");
        }
    }
}

#[derive(Deserialize)]
enum CasFetchRequest {
    FetchHostConfig,
    FetchTarget { target: String },
}
#[derive(Serialize)]
enum CasFetchResponse {
    Bytes(serde_bytes::ByteBuf),
}

/// A bounded mock CAS responder gets actual entry past the host-floor
/// prerequisite. It does NOT verify TUF or establish authentic publisher trust;
/// genuine TUF/floor coverage belongs to the separate F118 integration tests.
struct MockCas {
    _server: ScopedServer,
    host_fetches: Arc<AtomicUsize>,
}
impl MockCas {
    fn start(fixture: &Fixture) -> Self {
        let host_config = enclave_core::host_config::EnclaveHostConfig {
            profile_floor: Profile::L1,
            ifc_grant_public_key: hex::encode(fixture.issuer.verifying_key().as_bytes()),
            ohttp_key_config: None,
            calibration_corpus_digest: "11".repeat(32),
            vk_digest: "22".repeat(32),
            mcp_lock_digest: blake3::hash(&std::fs::read(fixture.dir.path().join("lock.json")).unwrap()).to_hex().to_string(),
            fido_mds_allowlist_digest: "33".repeat(32),
            codesign_pins: None,
        }.to_json_bytes().unwrap();
        let host_fetches = Arc::new(AtomicUsize::new(0));
        let seen = host_fetches.clone();
        let socket = fixture.dir.path().join(DaemonId::SwarmSync.socket_name());
        let server = ScopedServer::start(&socket, move |_: &PeerCredentials, request: CasFetchRequest| {
            match request {
                CasFetchRequest::FetchHostConfig => {
                    if seen.fetch_add(1, Ordering::SeqCst) >= 8 {
                        return Err(enclave_core::err!(E2BIG, "MOCK_CAS_REQUEST_LIMIT"));
                    }
                    Ok(CasFetchResponse::Bytes(host_config.clone().into()))
                }
                CasFetchRequest::FetchTarget { target } => {
                    Err(enclave_core::err!(EACCES, "MOCK_CAS_TARGET_UNAVAILABLE", "{target}"))
                }
            }
        });
        Self { _server: server, host_fetches }
    }
    fn host_fetches(&self) -> usize {
        self.host_fetches.load(Ordering::SeqCst)
    }
}

fn run_entry_bounded(args: &[String]) -> std::process::Output {
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_enclave-agent-runtime"))
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let until = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if std::time::Instant::now() >= until {
            let _ = child.kill();
            let _ = child.wait();
            panic!("private entry child exceeded the three-second fixture deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[derive(Debug)]
struct NoDeclass;
impl Declassifier for NoDeclass {
    fn classify(
        &self,
        _: &[u8],
        _: u64,
        _: &str,
        _: &enclave_core::seq::GovernedSlot,
    ) -> EnclaveResult<u64> {
        unreachable!()
    }
}
#[derive(Debug, Default)]
struct Slots(Mutex<u64>);
impl CustodyPort for Slots {
    fn scrub_text(&self, text: &str, _: bool) -> EnclaveResult<String> {
        Ok(text.into())
    }
    fn authorize_intent(
        &self,
        _: &enclave_core::intent_draft::IntentDraftV1,
    ) -> EnclaveResult<enclave_agent_runtime::service::StepUp> {
        unreachable!()
    }
    fn allocate_slot(&self) -> EnclaveResult<(String, u64)> {
        let mut n = self.0.lock().unwrap();
        *n += 1;
        Ok(("6f1c2c1e-3a54-4b8e-9d7a-0c4f5b6a7e81".into(), *n))
    }
    fn boot_epoch(&self) -> EnclaveResult<enclave_core::seq::BootEpoch> {
        unreachable!()
    }
}
struct Fixture {
    dir: tempfile::TempDir,
    args: DaemonArgs,
    registry: ToolRegistry,
    issuer: SigningKey,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let root = dir.path().canonicalize().unwrap();
        let build = SigningKey::from_bytes(&[91; 32]);
        let issuer = SigningKey::from_bytes(&[92; 32]);
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true).max_wasm_stack(512 * 1024);
        let module=wasmtime::Module::new(&wasmtime::Engine::new(&config).unwrap(),r#"(module
          (memory (export "memory") 1)
          (func (export "alloc") (param i32) (result i32) i32.const 0)
          (func (export "run") (param i32 i32) (result i32) local.get 0 i32.const 5 i32.add i32.load8_u))"#).unwrap().serialize().unwrap();
        std::fs::write(root.join("approved.cwasm"), &module).unwrap();
        let tl = json!({"tools":[{"name":"read"}]});
        let now = enclave_tool_host::lifecycle::trusted_unix_ns().unwrap();
        let signed = sign_manifest(
            ArtifactManifestV1 {
                v: 1,
                issued_at_unix_ns: now,
                expires_at_unix_ns: now + 60_000_000_000,
                modules: vec![ApprovedModuleV1 {
                    server: "fixture".into(),
                    tool_name: "read".into(),
                    file_name: "approved.cwasm".into(),
                    module_blake3: *blake3::hash(&module).as_bytes(),
                    tools_list: tl.clone(),
                    row_format: RowFormat::JsonArray,
                    max_rows: 1,
                }],
            },
            &build,
        )
        .unwrap();
        std::fs::write(
            root.join("manifest.json"),
            serde_json::to_vec(&signed).unwrap(),
        )
        .unwrap();
        std::fs::write(
            root.join("build-public"),
            hex::encode(build.verifying_key().as_bytes()),
        )
        .unwrap();
        std::fs::write(root.join("issuer"), hex::encode([92; 32])).unwrap();
        std::fs::set_permissions(root.join("issuer"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let lock=serde_json::to_vec(&json!({"v":1,"servers":[{"server":"fixture",
            "tools_list_blake3":digest_tools_list(&tl).unwrap(),"tools":[{"name":"read","action_class":"A1",
                "sink_clearance":"C3","namespace":"dev-billing","canonical_verb":"Select","slots":{"n":"BOUND_LITERAL"},"output_conf":"C2"}]}]})).unwrap();
        std::fs::write(root.join("lock.json"), &lock).unwrap();
        let registry = ToolRegistry::load(&lock).unwrap();
        let mut args = DaemonArgs::parse([
            "fixture".into(),
            "--dev-same-uid".into(),
            "--no-audit".into(),
        ])
        .unwrap();
        args.extra = [
            ("mcp-lock-file", root.join("lock.json")),
            ("policy-key-file", root.join("issuer")),
            ("tool-artifact-manifest", root.join("manifest.json")),
            ("tool-build-key-file", root.join("build-public")),
            ("tool-artifact-dir", root.clone()),
            ("tool-replay-file", root.join("replay")),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.to_str().unwrap().into()))
        .collect();
        Self {
            dir,
            args,
            registry,
            issuer,
        }
    }
    fn provision(&self) {
        drop(
            DurableToolHost::provision(
                &self.dir.path().canonicalize().unwrap().join("replay"),
                self.issuer.verifying_key(),
                32,
            )
            .unwrap(),
        );
    }
    fn service(&self) -> std::sync::Arc<IfcService> {
        let port = NativeToolDispatch::from_args(&self.args, &self.registry, &self.issuer).unwrap();
        IfcService::start_with_dispatch(
            IfcConfig {
                profile: Profile::L2,
                audit_path: None,
                policy_key: self.issuer.clone(),
                limits: enclave_crypto::biscuit_auth::AuthorizerLimits {
                    max_time: Duration::from_millis(100),
                    ..enclave_crypto::pop_biscuit::spec_limits()
                },
                registry: self.registry.clone(),
                cedar: Some(
                    enclave_agent_runtime::cedar_engine::CedarEngine::baseline_bundle().unwrap(),
                ),
                state_dir: None,
                socket_dir: None,
                dev_same_uid: true,
            },
            Box::new(NoDeclass),
            Box::<Slots>::default(),
            Box::new(enclave_agent_runtime::ssm::NoSsm),
            port,
        )
        .unwrap()
    }
}
fn owner() -> PeerCredentials {
    let mut peer = PeerCredentials::local(ipc::geteuid(), 0);
    peer.pid = Some(std::process::id() as i32);
    peer
}
fn begin_request(tools: bool) -> IfcRequest {
    IfcRequest::BeginTurn {
        turn: enclave_core::user_turn::UserTurnV1 {
            directive_short: "native fixture".into(),
            attachments: vec![],
        },
        attachments: vec![],
        tools: if tools {
            vec![enclave_agent_runtime::turn::ToolSignature {
                name: "mcp://fixture/read".into(),
                description: String::new(),
                params: vec![],
            }]
        } else {
            vec![]
        },
        holder_pk: None,
        budget_mb: 0,
    }
}
fn begin(s: &IfcService, tools: bool) -> String {
    let IfcResponse::TurnPlan { turn_id, .. } =
        s.handle(&owner(), begin_request(tools)).unwrap()
    else {
        panic!()
    };
    turn_id
}
fn request(id: &str, n: u8) -> IfcRequest {
    IfcRequest::ExecuteTurnPlan {
        turn_id: id.into(),
        source: format!("tool_call(\"fixture\",\"read\",{{\"n\":{n}}})"),
        initial_handles: vec![],
        fuel_budget: 10_000,
        step_up: false,
    }
}

#[test]
fn authenticated_runtime_executes_selected_native_module_and_returns_only_sealed_refs() {
    let f = Fixture::new();
    f.provision();
    let service = f.service();
    let id = begin(&service, true);
    let IfcResponse::PlanExecuted {
        executed_tool_calls,
        output_refs,
        return_value,
    } = service.handle(&owner(), request(&id, 7)).unwrap()
    else {
        panic!()
    };
    assert_eq!(executed_tool_calls, 1);
    assert_eq!(output_refs.len(), 1);
    assert!(return_value.starts_with("Ref("));
    assert_eq!(
        service.payload_for_test(&output_refs[0].handle).unwrap(),
        br#"[{"result":55}]"#
    );
    assert!(output_refs[0].enclave_boot_mac.is_some());
    assert_eq!(output_refs[0].label.c, enclave_core::label::Conf::C2);
    let denied = begin(&service, false);
    assert!(service.handle(&owner(), request(&denied, 7)).is_err());
    assert!(service
        .handle(
            &owner(),
            IfcRequest::FinishTurn {
                turn_id: id,
                cancelled: false
            }
        )
        .is_ok());
    assert!(service.payload_for_test(&output_refs[0].handle).is_err());
    println!(
        "native fixture RSS bytes: {:?}; no installed-daemon ceiling acceptance claim",
        enclave_core::resource::current_rss_bytes()
    );
    drop(service);
    let reopened = f.service();
    let id = begin(&reopened, true);
    let IfcResponse::PlanExecuted { output_refs, .. } =
        reopened.handle(&owner(), request(&id, 8)).unwrap()
    else {
        panic!()
    };
    assert_eq!(
        reopened.payload_for_test(&output_refs[0].handle).unwrap(),
        br#"[{"result":56}]"#
    );
}

#[test]
fn startup_rejects_partial_unpinned_changed_issuer_and_missing_replay_configuration() {
    let mut f = Fixture::new();
    assert!(NativeToolDispatch::from_args(&f.args, &f.registry, &f.issuer).is_err());
    assert!(!f.dir.path().join("replay").exists());
    f.provision();
    assert!(NativeToolDispatch::from_args(&f.args, &ToolRegistry::empty(), &f.issuer).is_err());
    assert!(NativeToolDispatch::from_args(
        &f.args,
        &f.registry,
        &SigningKey::from_bytes(&[93; 32])
    )
    .is_err());
    let saved = f.args.extra.pop().unwrap();
    assert!(
        NativeToolDispatch::from_args(&f.args, &f.registry, &f.issuer)
            .unwrap_err()
            .is("TOOL_CONFIG_INCOMPLETE")
    );
    f.args.extra.push(saved);
    std::fs::set_permissions(
        f.dir.path().join("issuer"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(
        NativeToolDispatch::from_args(&f.args, &f.registry, &f.issuer)
            .unwrap_err()
            .is("TOOL_CONFIG_UNTRUSTED")
    );
}

#[test]
fn real_entry_refuses_unprovisioned_state_before_creating_listener() {
    let f = Fixture::new();
    let cas = MockCas::start(&f);
    let mut args = vec![
        "--dev-same-uid".to_owned(),
        "--no-audit".into(),
        "--socket-dir".into(),
        f.dir.path().to_str().unwrap().into(),
    ];
    for (key, value) in &f.args.extra {
        args.push(format!("--{key}"));
        args.push(value.clone());
    }
    let out = run_entry_bounded(&args);
    assert_eq!(cas.host_fetches(), 1, "entry must get past the mock host floor");
    assert!(!out.status.success());
    // This actual entry path rejects absent state; it cannot silently run an
    // unprotected transport or create the missing replay database.
    assert!(!f.dir.path().join("replay").exists());
    assert!(!f.dir.path().join(DaemonId::AgentRuntime.socket_name()).exists());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("TOOL_HOST_STATE"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn existing_launchd_state_path_can_load_explicit_operator_tool_configuration() {
    let f = Fixture::new();
    f.provision();
    let root = f.dir.path().canonicalize().unwrap();
    let config = json!({"v":1,"artifact_manifest":root.join("manifest.json"),
        "build_key_file":root.join("build-public"),"artifact_dir":root,"replay_file":root.join("replay")});
    std::fs::write(
        root.join("tool-execution.json"),
        serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    let mut args = f.args.clone();
    args.state_dir = Some(root.clone());
    args.extra.retain(|(name, _)| !name.starts_with("tool-"));
    drop(NativeToolDispatch::from_args(&args, &f.registry, &f.issuer).unwrap());
    std::fs::remove_file(root.join("replay")).unwrap();
    assert!(NativeToolDispatch::from_args(&args, &f.registry, &f.issuer).is_err());
    assert!(!root.join("replay").exists());
}

#[test]
fn actual_entry_key_reader_refuses_fifo_symlink_and_oversized_seed_without_hanging() {
    use std::os::unix::ffi::OsStrExt;
    let f = Fixture::new();
    let root = f.dir.path().canonicalize().unwrap();
    let path = root.join("issuer");
    let cas = MockCas::start(&f);
    let run = |expected_reason: &str| {
        let before = cas.host_fetches();
        let out = run_entry_bounded(&[
            "--dev-same-uid".into(),
            "--no-audit".into(),
            "--policy-key-file".into(),
            path.to_str().unwrap().into(),
            "--socket-dir".into(),
            root.to_str().unwrap().into(),
        ]);
        assert_eq!(cas.host_fetches(), before + 1, "entry must get past the mock host floor");
        assert!(!out.status.success());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(expected_reason), "expected {expected_reason}: {stderr}");
        assert!(!root.join(DaemonId::AgentRuntime.socket_name()).exists());
    };
    std::fs::remove_file(&path).unwrap();
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: NUL-terminated path is owned by this private fixture.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    run("TOOL_CONFIG_UNTRUSTED");
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(root.join("build-public"), &path).unwrap();
    run("TOOL_CONFIG_OPEN");
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, vec![b'0'; 4096]).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    run("TOOL_CONFIG_UNTRUSTED");
}


#[test]
fn private_ipc_authenticates_turn_and_executes_selected_native_artifact() {
    let fixture = Fixture::new();
    fixture.provision();
    let service = fixture.service();
    let handler = service.clone();
    let socket = fixture.dir.path().join(DaemonId::AgentRuntime.socket_name());
    let _server = ScopedServer::start(&socket, move |peer: &PeerCredentials, request: IfcRequest| {
        // These are actual kernel credentials obtained by ipc::serve, rather
        // than caller-supplied ownership fields or the direct-handle fixture.
        assert!(peer.pid.is_some_and(|pid| pid > 0));
        handler.handle(peer, request)
    });
    let mut client = ipc::Client::connect(&socket, ipc::geteuid()).unwrap();
    client.set_timeout(Some(Duration::from_secs(3))).unwrap();
    let IfcResponse::TurnPlan { turn_id, root_token, .. } =
        client.call::<_, IfcResponse>(&begin_request(true)).unwrap()
    else {
        panic!()
    };
    assert!(root_token.is_none(), "internal holder must stay private");
    let response: IfcResponse = client.call(&request(&turn_id, 7)).unwrap();
    let wire = ipc::to_cbor(&response).unwrap();
    let IfcResponse::PlanExecuted { executed_tool_calls, output_refs, return_value } = response
    else {
        panic!()
    };
    assert_eq!(executed_tool_calls, 1);
    assert_eq!(output_refs.len(), 1);
    assert!(return_value.starts_with("Ref("));
    let payload = br#"[{"result":55}]"#;
    assert_eq!(service.payload_for_test(&output_refs[0].handle).unwrap(), payload);
    assert!(!wire.windows(payload.len()).any(|window| window == payload));
    assert!(output_refs[0].enclave_boot_mac.is_some());
    assert_eq!(output_refs[0].label.c, enclave_core::label::Conf::C2);
    let response: IfcResponse = client.call(&IfcRequest::FinishTurn {
        turn_id,
        cancelled: false,
    }).unwrap();
    assert!(matches!(response, IfcResponse::TurnFinished { released: 1 }));
    assert!(service.payload_for_test(&output_refs[0].handle).is_err());
    // Drop the client before the scoped server stops accepting work.
    drop(client);
}
