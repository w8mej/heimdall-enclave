//! Gateway deployment generation and actual CLI wire/lifecycle checks. No host installation.
use enclave_client_gateway::{ClientGatewayRequest as Request, ClientGatewayResponse as Response};
use enclave_core::ipc::{self, PeerCredentials};
use std::sync::{Arc, Mutex, atomic::{AtomicBool,Ordering}};
use std::os::unix::fs::DirBuilderExt;

#[test]
fn gateway_assets_keep_the_five_role_topology_and_narrow_runtime_admission() {
    use enclave_core::daemon::*;
    let layout=mcp_enclave::launchd::Layout::default();
    let plist=mcp_enclave::launchd::gateway_plist(&layout);
    assert_eq!(DaemonId::ALL.len(),5);
    assert!(plist.contains(&format!("<string>{GATEWAY_ACCOUNT}</string>")));
    assert!(plist.contains(&format!("{}/{GATEWAY_BINARY}",layout.bin_dir)));
    assert!(plist.contains("--sandbox-profile")); assert!(!plist.contains("--dev"));
    let provision=mcp_enclave::launchd::provision_script(&layout);
    assert!(provision.contains(&format!("mkuser {GATEWAY_ACCOUNT} {GATEWAY_UID} {GATEWAY_GID}")));
    assert!(provision.contains(&format!("addmember {} {GATEWAY_ACCOUNT}",DaemonId::AgentRuntime.client_group())));
    assert!(provision.contains("mkdirp /var/run/enclave/gateway _enclaveingress _enclaveingress 0755"));
    let profile=mcp_enclave::launchd::gateway_sandbox_profile(&layout);
    assert!(profile.contains("(deny default)"));
    assert!(profile.contains("(remote unix-socket (literal \"/private/var/run/enclave/ifc/ifc.sock\"))"));
    assert!(!profile.contains("tcp"));assert!(!profile.contains("udp"));
    for d in DaemonId::ALL {assert!(!profile.contains(&format!("file-write* (subpath \"/private/var/run/enclave/{}\")",d.dir_name())));}
    let root=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    assert_eq!(std::fs::read_to_string(root.join("launchd/com.enterprise.enclave.gateway.plist")).unwrap(),plist);
    assert_eq!(std::fs::read_to_string(root.join("launchd/gateway.sb")).unwrap(),profile);
    assert_eq!(std::fs::read_to_string(root.join("launchd/provision-accounts.sh")).unwrap(),provision);
    assert!(include_str!("../../../packaging/macos/build.sh").contains("enclave-client-gateway:com.enterprise.enclave.gateway"));
    assert!(include_str!("../../../packaging/macos/install.sh").contains(GATEWAY_IDENTIFIER));
    assert!(include_str!("../../../packaging/macos/uninstall.sh").contains(GATEWAY_BINARY));
}

struct CliFixture {
    root:std::path::PathBuf,
    requests:Arc<Mutex<Vec<(PeerCredentials,Request)>>>,
    stop:Arc<AtomicBool>,
    thread:Option<std::thread::JoinHandle<()>>,
}
impl CliFixture {
    fn new(execution_error:bool,first_finish_error:bool)->Self {
        let root=std::path::PathBuf::from("/tmp").join(format!("f97-cli-{:x}",enclave_core::rng::u64()));
        std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let requests=Arc::new(Mutex::new(Vec::new())); let observed=requests.clone();
        let stop=Arc::new(AtomicBool::new(false));let halted=stop.clone();
        let listener=ipc::bind(&root.join("run/gateway/gateway.sock"),ipc::SocketAccess::OwnerOnly).unwrap();
        let fail_finish=AtomicBool::new(first_finish_error);
        let thread=std::thread::spawn(move||ipc::serve::<Request,Response,_>(listener,ipc::PeerPolicy::allow([ipc::geteuid()]),
            Arc::new(move|peer:&PeerCredentials,request:Request|{
                observed.lock().unwrap().push((peer.clone(),request.clone()));
                match request {
                    Request::SubmitExecutableTurn {turn,..}=>Ok(Response::Plan {turn_id:"a".repeat(64),
                        context:enclave_agent_runtime::turn::PlanCompileContext {directive:turn.directive_short,attachment_stubs:vec![],tools:vec![]},root_token:None}),
                    Request::ExecuteTurnPlan {..} if execution_error=>Err(enclave_core::err!(EPERM,"FIXTURE_EXECUTION_DENIED")),
                    Request::ExecuteTurnPlan {..}=>Ok(Response::PlanExecuted {return_value:"Int(0)".into(),executed_tool_calls:0,output_refs:vec![]}),
                    Request::FinishTurn {..} if fail_finish.swap(false,Ordering::SeqCst)=>Err(enclave_core::err!(EIO,"FIXTURE_FINISH_RETRY")),
                    Request::FinishTurn {..}=>Ok(Response::Finished {released:0}),
                    _=>Err(enclave_core::err!(EINVAL,"FIXTURE_UNEXPECTED_REQUEST")),
                }
            }),halted).unwrap());
        Self {root,requests,stop,thread:Some(thread)}
    }
    fn run(&self)->std::process::Output {
        let path=self.root.join("plan with spaces $(ignored).star");
        std::fs::write(&path,"0").unwrap();
        // The CLI takes argument vectors, never a shell. Metacharacters remain data.
        std::process::Command::new(env!("CARGO_BIN_EXE_mcp-enclave"))
            .args(["--dev","--json","--state-dir"]).arg(&self.root)
            .args(["turn","execute","--directive","inspect $(ignored)","--source"]).arg(path)
            .args(["--tool","mcp://fixture/read","--budget-mb","0"]).output().unwrap()
    }
}
impl Drop for CliFixture {
    fn drop(&mut self){self.stop.store(true,Ordering::SeqCst);if let Some(t)=self.thread.take(){let _=t.join();}let _=std::fs::remove_dir_all(&self.root);}
}
#[test]
fn actual_cli_routes_explicit_execution_and_retries_finish_under_same_process() {
    let f=CliFixture::new(false,true);let out=f.run();
    assert!(out.status.success(),"{}",String::from_utf8_lossy(&out.stderr));
    let receipt:serde_json::Value=serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(receipt["status"],"executed");assert_eq!(receipt["references_reclaimed"],true);
    let requests=f.requests.lock().unwrap();assert_eq!(requests.len(),4);
    let owner=&requests[0].0;assert!(owner.pid.is_some());assert!(requests.iter().all(|(peer,_)|peer==owner));
    assert!(matches!(&requests[0].1,Request::SubmitExecutableTurn {turn,tools,..} if turn.directive_short=="inspect $(ignored)" && tools[0].name=="mcp://fixture/read"));
    assert!(matches!(&requests[1].1,Request::ExecuteTurnPlan {source,..} if source=="0"));
    assert!(matches!(&requests[2].1,Request::FinishTurn {cancelled:false,..}));
    assert!(matches!(&requests[3].1,Request::FinishTurn {cancelled:false,..}));
}
#[test]
fn actual_cli_cancels_on_execution_error_and_reports_failure() {
    let f=CliFixture::new(true,false);let out=f.run();assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("FIXTURE_EXECUTION_DENIED"));
    let requests=f.requests.lock().unwrap();assert_eq!(requests.len(),3);
    assert!(matches!(&requests[2].1,Request::FinishTurn {cancelled:true,..}));
}
