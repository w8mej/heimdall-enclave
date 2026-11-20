//! Actual console gateway → runtime sockets. The runtime port is a bounded
//! private in-memory runner fixture; runtime's companion suite exercises the
//! production authenticated socket adapter itself.
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc,Mutex,atomic::{AtomicBool,Ordering}};
use std::time::Duration;
use enclave_agent_runtime::{service::{IfcService,IfcConfig,IfcRequest,IfcResponse,Declassifier,NoCustody},ssm::{SsmPort,SsmOutput}};
use enclave_client_gateway::{ClientGateway,ClientGatewayRequest as Request,ClientGatewayResponse as Response};
use enclave_core::{error::EnclaveResult,ipc::{self,PeerCredentials},label::Label,secret::SecretBytes,user_turn::{UserTurnV1,AttachmentRef}};
#[derive(Debug)]struct NoDecl;
impl Declassifier for NoDecl {fn classify(&self,_:&[u8],_:u64,_:&str,_:&enclave_core::seq::GovernedSlot)->EnclaveResult<u64>{Err(enclave_core::err!(EPERM,"FIXTURE_NO_DECL"))}}
#[derive(Debug,Default)]struct Runner {sessions:Mutex<BTreeMap<[u8;32],Label>>,fail_exit:AtomicBool}
#[derive(Debug)]struct RunnerPort(Arc<Runner>);
impl SsmPort for RunnerPort {
    fn fork(&self,scope:[u8;32],label:Label)->EnclaveResult<()>{let mut s=self.0.sessions.lock().unwrap();assert!(s.len()<8);s.insert(scope,label);Ok(())}
    fn ingest(&self,scope:[u8;32],label:Label,_:&[u8])->EnclaveResult<()>{let mut s=self.0.sessions.lock().unwrap();let l=s.get_mut(&scope).unwrap();*l=l.join(label);Ok(())}
    fn generate(&self,scope:[u8;32],_:u32)->EnclaveResult<SsmOutput>{Ok(SsmOutput {label:*self.0.sessions.lock().unwrap().get(&scope).unwrap(),bytes:SecretBytes::from_slice(b"private model output")})}
    fn exit(&self,scope:[u8;32])->EnclaveResult<()>{if self.0.fail_exit.swap(false,Ordering::SeqCst){return Err(enclave_core::err!(EIO,"FIXTURE_EXIT_FAILED"));}self.0.sessions.lock().unwrap().remove(&scope);Ok(())}
}
struct Fixture {dir:PathBuf,runtime:Arc<IfcService>,runner:Arc<Runner>,stop:Arc<AtomicBool>,threads:Vec<std::thread::JoinHandle<()>>}
impl Fixture {
    fn new()->Self {
        use std::os::unix::fs::PermissionsExt;
        let dir=std::env::temp_dir().join(format!("f140g-{}",enclave_core::rng::u64()));std::fs::create_dir(&dir).unwrap();std::fs::set_permissions(&dir,std::fs::Permissions::from_mode(0o700)).unwrap();
        let runner=Arc::new(Runner::default());let runtime=IfcService::start_with_ssm(IfcConfig {profile:enclave_core::profile::Profile::L2,audit_path:None,policy_key:ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng),limits:Default::default(),registry:enclave_agent_runtime::registry::ToolRegistry::empty(),cedar:Some(enclave_agent_runtime::cedar_engine::CedarEngine::baseline_bundle().unwrap()),state_dir:None,socket_dir:None,dev_same_uid:true},Box::new(NoDecl),Box::new(NoCustody),Box::new(RunnerPort(runner.clone()))).unwrap();
        let stop=Arc::new(AtomicBool::new(false));let path=dir.join("ifc.sock");let listener=ipc::bind(&path,ipc::SocketAccess::OwnerOnly).unwrap();let (svc,s)=(runtime.clone(),stop.clone());let first=std::thread::spawn(move||ipc::serve::<IfcRequest,IfcResponse,_>(listener,ipc::PeerPolicy::allow([ipc::geteuid()]),Arc::new(move|p:&PeerCredentials,r|svc.handle(p,r)),s).unwrap());
        let gateway_path=dir.join("gateway.sock");let listener=ipc::bind(&gateway_path,ipc::SocketAccess::OwnerOnly).unwrap();let gateway=Arc::new(ClientGateway::new(gateway_path,path,1000,Duration::from_secs(600),true));let s=stop.clone();let second=std::thread::spawn(move||ipc::serve::<Request,Response,_>(listener,ipc::PeerPolicy::allow([ipc::geteuid()]),Arc::new(move|p:&PeerCredentials,r|gateway.handle_request(p,r)),s).unwrap());
        Self {dir,runtime,runner,stop,threads:vec![first,second]}
    }
    fn call(&self,r:Request)->EnclaveResult<Response>{ipc::Client::connect(&self.dir.join("gateway.sock"),ipc::geteuid())?.call(&r)}
    fn begin(&self)->(String,String){let bytes=b"private scoped attachment";match self.call(Request::SubmitTurn {turn:UserTurnV1 {directive_short:"gateway SSM fixture".into(),attachments:vec![AttachmentRef {handle:"$paste_0".into(),label:Label::ATTACHMENT_DEFAULT,blake3:blake3::hash(bytes).to_hex().to_string(),kind:None}]},attachments:vec![("$paste_0".into(),bytes.to_vec().into())],tools:vec![],budget_mb:0,holder_pk:None}).unwrap(){Response::Plan {turn_id,context,..}=>(turn_id,context.attachment_stubs[0].clone()),_=>panic!()}}
    fn ingest(&self,id:&str,h:&str)->EnclaveResult<Response>{self.call(Request::SsmIngestTurnHandles {turn_id:id.into(),handles:vec![h.into()]})}
    fn generate(&self,id:&str)->EnclaveResult<Response>{self.call(Request::SsmGenerateTurn {turn_id:id.into(),n:64})}
    fn finish(&self,id:&str)->EnclaveResult<Response>{self.call(Request::FinishTurn {turn_id:id.into(),cancelled:true})}
}
impl Drop for Fixture {fn drop(&mut self){self.stop.store(true,Ordering::SeqCst);for t in self.threads.drain(..){t.join().unwrap();}let _=std::fs::remove_dir_all(&self.dir);}}
#[test]
fn reachable_gateway_session_path_preserves_opaque_labeled_handle_and_recovers_quota(){
    let f=Fixture::new();for _ in 0..20 {let (id,h)=f.begin();assert!(matches!(f.ingest(&id,&h).unwrap(),Response::SsmIngested));let env=match f.generate(&id).unwrap(){Response::Handle(env)=>env,_=>panic!()};assert_eq!(env.label,Label::ATTACHMENT_DEFAULT);assert!(env.enclave_boot_mac.is_some());assert_eq!(env.provenance_parents,Some(vec![h.clone()]));assert_eq!(f.runtime.payload_for_test(&env.handle).unwrap(),b"private model output");assert!(matches!(f.finish(&id).unwrap(),Response::Finished {released:2}));assert!(f.runtime.payload_for_test(&env.handle).is_err());assert!(f.runner.sessions.lock().unwrap().is_empty());}
}
#[test]
fn gateway_retains_owner_on_remote_exit_failure_and_uses_exact_envelopes(){
    let f=Fixture::new();let (id,h)=f.begin();f.ingest(&id,&h).unwrap();let env=match f.generate(&id).unwrap(){Response::Handle(e)=>e,_=>panic!()};let (other,_)=f.begin();
    let mut forged=env.clone();forged.label=Label::BOTTOM;assert!(f.call(Request::SsmIngestTurn {turn_id:other.clone(),envelopes:vec![forged]}).is_err());
    f.runner.fail_exit.store(true,Ordering::SeqCst);assert!(f.finish(&id).unwrap_err().is("FIXTURE_EXIT_FAILED"));assert!(f.runtime.payload_for_test(&h).is_ok());assert!(f.generate(&id).unwrap_err().is("TURN_CLOSING"));
    f.finish(&id).unwrap();f.finish(&other).unwrap();assert!(f.runner.sessions.lock().unwrap().is_empty());
}
#[test]
fn other_real_process_cannot_ingest_generate_or_finish_turn_owned_by_submitter(){
    let f=Fixture::new();let (id,h)=f.begin();f.ingest(&id,&h).unwrap();
    let script=r#"
import os,socket,struct

def head(m,n):
    if n<24:return bytes([(m<<5)|n])
    if n<256:return bytes([(m<<5)|24,n])
    return bytes([(m<<5)|25])+struct.pack('>H',n)
def text(v):
    b=v.encode();return head(3,len(b))+b
def exact(s,n):
    b=b''
    while len(b)<n:
        c=s.recv(n-len(b));assert c;b+=c
    return b
for op in ['SsmGenerateTurn','SsmIngestTurnHandles','FinishTurn']:
    fields=text('turn_id')+text(os.environ['F140_TURN'])
    if op=='SsmGenerateTurn':fields+=text('n')+head(0,1)
    elif op=='SsmIngestTurnHandles':fields+=text('handles')+b'\x81'+text(os.environ['F140_HANDLE'])
    else:fields+=text('cancelled')+b'\xf5'
    body=b'\xa1'+text(op)+b'\xa2'+fields
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(10);s.connect(os.environ['F140_SOCKET']);s.sendall(struct.pack('>I',len(body))+body)
    n=struct.unpack('>I',exact(s,4))[0];assert n<=1048576
    reply=exact(s,n);assert b'GATEWAY_TURN_OWNER_REJECTED' in reply,reply;s.close()
"#;
    let result=std::process::Command::new("python3").arg("-c").arg(script).env("F140_TURN",&id).env("F140_HANDLE",&h).env("F140_SOCKET",f.dir.join("gateway.sock")).output().unwrap();assert!(result.status.success(),"child exit {:?}: {}",result.status.code(),String::from_utf8_lossy(&result.stderr));assert_eq!(f.runner.sessions.lock().unwrap().len(),1);f.finish(&id).unwrap();
}
