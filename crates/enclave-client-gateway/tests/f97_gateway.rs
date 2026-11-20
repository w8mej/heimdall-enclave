//! Actual private gateway executable -> runtime IPC -> authorized native module.
//! Private fixture authorities are not production enrollment or installed services.
#[path = "support/turn_recovery_audit.rs"]
mod turn_recovery_audit;
use ed25519_dalek::SigningKey;
use enclave_agent_runtime::execution_host::NativeToolDispatch;
use enclave_agent_runtime::registry::{digest_tools_list, ToolRegistry};
use enclave_agent_runtime::service::{
    CustodyPort, Declassifier, IfcConfig, IfcRequest, IfcResponse, IfcService,
};
use enclave_core::error::EnclaveResult;
use enclave_core::ipc::PeerCredentials;
use enclave_core::profile::Profile;
use enclave_core::runtime::DaemonArgs;
use enclave_tool_host::artifacts::{sign_manifest, ApprovedModuleV1, ArtifactManifestV1};
use enclave_tool_host::{ticket::RowFormat, DurableToolHost};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::sync::Mutex;
use std::time::Duration;

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
struct ArtifactFixture {
    dir: tempfile::TempDir,
    args: DaemonArgs,
    registry: ToolRegistry,
    issuer: SigningKey,
}
impl ArtifactFixture {
    fn new() -> Self {
        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in("/tmp")
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

use enclave_client_gateway::{ClientGatewayRequest as Request, ClientGatewayResponse as Response};
use enclave_core::ipc::{self, Client, PeerPolicy};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

struct Running {
    artifacts: ArtifactFixture,
    service: Arc<IfcService>,
    gateway: std::process::Child,
    stop: Arc<AtomicBool>,
    server: Option<std::thread::JoinHandle<()>>,
}
impl Running {
    fn new() -> Self {
        let artifacts = ArtifactFixture::new();
        artifacts.provision();
        let service = artifacts.service();
        let listener = ipc::bind(&artifacts.dir.path().join("ifc/ifc.sock"), ipc::SocketAccess::OwnerOnly).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let halted = stop.clone();
        let handler = service.clone();
        let server = std::thread::spawn(move || ipc::serve::<IfcRequest, IfcResponse, _>(
            listener, PeerPolicy::allow([ipc::geteuid()]),
            Arc::new(move |peer: &PeerCredentials, req| handler.handle(peer, req)), halted).unwrap());
        let gateway = std::process::Command::new(env!("CARGO_BIN_EXE_enclave-client-gateway"))
            .args(["--dev-same-uid", "--no-audit", "--socket-dir"])
            .arg(artifacts.dir.path()).stdout(std::process::Stdio::null()).spawn().unwrap();
        let mut running = Self {artifacts,service,gateway,stop,server:Some(server)};
        let deadline = std::time::Instant::now()+Duration::from_secs(10);
        while !running.socket().exists() {
            assert!(running.gateway.try_wait().unwrap().is_none(), "gateway exited before listener");
            assert!(std::time::Instant::now()<deadline, "gateway startup deadline");
            std::thread::sleep(Duration::from_millis(10));
        }
        running
    }
    fn socket(&self) -> std::path::PathBuf {self.artifacts.dir.path().join("gateway/gateway.sock")}
    fn call(&self, req: &Request) -> EnclaveResult<Response> {
        Client::connect(&self.socket(),ipc::geteuid())?.call(req)
    }
    fn submit(&self, external: bool, tools: bool) -> (String, Option<serde_bytes::ByteBuf>) {
        let turn=enclave_core::user_turn::UserTurnV1 {directive_short:"native gateway fixture".into(), attachments:vec![]};
        let tools=if tools {vec![enclave_agent_runtime::turn::ToolSignature {name:"mcp://fixture/read".into(),description:String::new(),params:vec![]}]} else {vec![]};
        let request=if external {Request::SubmitTurn {turn,attachments:vec![],tools,budget_mb:0,holder_pk:Some([44;32])}}
            else {Request::SubmitExecutableTurn {turn,attachments:vec![],tools,budget_mb:0}};
        let Response::Plan {turn_id,root_token,..}=self.call(&request).unwrap() else {panic!("plan required")};
        (turn_id,root_token)
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        let _=self.gateway.kill(); let _=self.gateway.wait();
        self.stop.store(true,Ordering::SeqCst);
        if let Some(thread)=self.server.take(){let _=thread.join();}
    }
}
fn execute(turn_id: &str, n: u8) -> Request {
    Request::ExecuteTurnPlan {turn_id:turn_id.into(),source:format!("tool_call(\"fixture\",\"read\",{{\"n\":{n}}})"),
        initial_handles:vec![],fuel_budget:10_000,step_up:false}
}

#[test]
fn actual_gateway_executes_authorized_native_tool_and_reclaims_sealed_output() {
    let f=Running::new();
    let (id,token)=f.submit(false,true); assert!(token.is_none(),"private executor capability must never escape");
    let Response::PlanExecuted {executed_tool_calls,output_refs,return_value}=f.call(&execute(&id,7)).unwrap() else {panic!()};
    assert_eq!(executed_tool_calls,1); assert_eq!(output_refs.len(),1); assert!(return_value.starts_with("Ref("));
    assert!(output_refs[0].enclave_boot_mac.is_some());
    assert_eq!(output_refs[0].label.c,enclave_core::label::Conf::C2);
    assert_eq!(f.service.payload_for_test(&output_refs[0].handle).unwrap(),br#"[{"result":55}]"#);
    assert!(matches!(f.call(&Request::FinishTurn {turn_id:id.clone(),cancelled:false}).unwrap(),Response::Finished {released:1}));
    assert!(f.service.payload_for_test(&output_refs[0].handle).is_err());
    assert!(matches!(f.call(&Request::FinishTurn {turn_id:id,cancelled:false}).unwrap(),Response::Finished {released:0}));
}
#[test]
fn external_holder_flow_preserves_root_and_cannot_use_private_executor() {
    let f=Running::new(); let (id,token)=f.submit(true,true); assert!(token.is_some());
    assert!(f.call(&execute(&id,7)).is_err());
    f.call(&Request::FinishTurn {turn_id:id,cancelled:true}).unwrap();
}
#[test]
fn gateway_enforces_bounds_and_runtime_tool_scope() {
    let f=Running::new(); let (id,_)=f.submit(false,false);
    assert!(f.call(&execute(&id,7)).is_err(),"undeclared tool must not execute");
    for (source,handles,fuel) in [("x".repeat(65537),vec![],1),("0".into(),vec![],0),("0".into(),vec![],10001),("0".into(),vec![("x".into(),"h".into());65],1)] {
        let err=f.call(&Request::ExecuteTurnPlan {turn_id:id.clone(),source,initial_handles:handles,fuel_budget:fuel,step_up:false}).unwrap_err();
        assert!(err.is("PLAN_EXECUTION_BOUNDS"),"{err}");
    }
    f.call(&Request::FinishTurn {turn_id:id,cancelled:true}).unwrap();
}
#[test]
fn another_real_process_cannot_execute_or_finish_the_original_process_turn() {
    let f=Running::new(); let (id,_)=f.submit(false,true);
    let out=std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact","foreign_process_probe","--nocapture"])
        .env("F97_PROBE_SOCKET",f.socket()).env("F97_PROBE_TURN",&id).output().unwrap();
    assert!(out.status.success(),"{}{}",String::from_utf8_lossy(&out.stdout),String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("foreign process rejected"));
    assert!(f.call(&execute(&id,8)).is_ok());
    f.call(&Request::FinishTurn {turn_id:id,cancelled:false}).unwrap();
}
#[test]
fn foreign_process_probe() {
    let Some(path)=std::env::var_os("F97_PROBE_SOCKET") else {return};
    let id=std::env::var("F97_PROBE_TURN").unwrap();
    for request in [execute(&id,7),Request::FinishTurn {turn_id:id,cancelled:true}] {
        let err=Client::connect(std::path::Path::new(&path),ipc::geteuid()).unwrap().call::<_,Response>(&request).unwrap_err();
        assert!(err.is("GATEWAY_TURN_OWNER_REJECTED"),"{err}");
    }
    println!("foreign process rejected");
}
#[test]
fn actual_entry_refuses_production_identity_and_relative_path_without_listener() {
    let dir=tempfile::Builder::new().prefix("f97-entry-").tempdir_in("/tmp").unwrap();
    let out=std::process::Command::new(env!("CARGO_BIN_EXE_enclave-client-gateway"))
        .arg("--socket-dir").arg(dir.path()).output().unwrap();
    assert!(!out.status.success());
    assert!(!dir.path().join("gateway/gateway.sock").exists());
    let out=std::process::Command::new(env!("CARGO_BIN_EXE_enclave-client-gateway"))
        .args(["--dev-same-uid","--socket-dir","relative"]).output().unwrap();
    assert!(!out.status.success()); assert!(String::from_utf8_lossy(&out.stderr).contains("GATEWAY_ABSOLUTE_SOCKET_DIRECTORY"));
}

#[test]
fn dedicated_gateway_identity_cannot_invoke_global_runtime_controls() {
    let f=ArtifactFixture::new(); f.provision(); let service=f.service();
    let mut peer=PeerCredentials::local(enclave_core::daemon::GATEWAY_UID,enclave_core::daemon::GATEWAY_GID);
    peer.pid=Some(42);
    peer.code_identity=Some(enclave_core::codesign::CodeIdentity {identifier:enclave_core::daemon::GATEWAY_IDENTIFIER.into(),team_id:"fixture".into(),cdhash:"fixture".into()});
    for request in [IfcRequest::Wipe,IfcRequest::RefreshPolicy {bundle_json:None},IfcRequest::ReleaseHandles {handles:vec![]},
        IfcRequest::IngestToolOutput {server:"fixture".into(),tool_name:"read".into(),tools_list:"{}".into(),payload:b"[]".to_vec().into(),conf_hint:None,source_uri:"fixture".into()}] {
        assert!(service.handle(&peer,request).unwrap_err().is("GATEWAY_SCOPED_OPERATIONS_ONLY"));
    }
    let IfcResponse::TurnPlan {turn_id,..}=service.handle(&peer,IfcRequest::BeginTurn {
        turn:enclave_core::user_turn::UserTurnV1 {directive_short:"scoped fixture".into(),attachments:vec![]},
        attachments:vec![],tools:vec![],holder_pk:None,budget_mb:0}).unwrap() else {panic!()};
    service.handle(&peer,IfcRequest::FinishTurn {turn_id,cancelled:true}).unwrap();
    let policy=ipc::production_policy(enclave_core::daemon::DaemonId::AgentRuntime);
    assert_eq!(policy.code.get(&enclave_core::daemon::GATEWAY_UID),Some(&enclave_core::codesign::CodeRequirement::gateway()));
    for d in enclave_core::daemon::DaemonId::ALL {
        assert_ne!(d.uid(),enclave_core::daemon::GATEWAY_UID);
        if d!=enclave_core::daemon::DaemonId::AgentRuntime {assert!(!ipc::production_policy(d).allowed_uids.contains(&enclave_core::daemon::GATEWAY_UID));}
    }
}
