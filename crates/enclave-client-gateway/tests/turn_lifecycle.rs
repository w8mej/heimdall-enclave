//! F71 actual gateway -> kernel-authenticated runtime socket lifetimes.
//! Private fixtures only: no installed daemon or system account is changed.
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc,atomic::{AtomicBool,Ordering}};
use std::time::Duration;
use enclave_agent_runtime::service::{IfcConfig,IfcService,IfcRequest,IfcResponse,NoCustody,Declassifier};
use enclave_client_gateway::{ClientGateway,ClientGatewayRequest,ClientGatewayResponse};
use enclave_core::error::EnclaveResult;
use enclave_core::ipc::{self,PeerCredentials};
use enclave_core::user_turn::{UserTurnV1,AttachmentRef};
use enclave_core::label::Label;

#[derive(Debug)]
struct NoDeclassification;
impl Declassifier for NoDeclassification {
    fn classify(&self,_:&[u8],_:u64,_:&str,_:&enclave_core::seq::GovernedSlot)->EnclaveResult<u64>{
        Err(enclave_core::err!(EPERM,"FIXTURE_NO_DECLASSIFICATION"))
    }
}
struct Fixture {
    dir:PathBuf, runtime:Arc<IfcService>, stop:Arc<AtomicBool>, threads:Vec<std::thread::JoinHandle<()>>,
    fail_before:Arc<AtomicBool>, fail_after:Arc<AtomicBool>,
    lose_begin:Arc<AtomicBool>,fail_cancel:Arc<AtomicBool>,
}
impl Fixture {
    fn new(rate:usize)->Self {
        let dir=PathBuf::from("/tmp").join(format!("f71g-{}",enclave_core::rng::u64()));
        fs::create_dir(&dir).unwrap();fs::set_permissions(&dir,fs::Permissions::from_mode(0o700)).unwrap();
        let runtime=IfcService::start(IfcConfig {profile:enclave_core::profile::Profile::L2,audit_path:None,
            policy_key:ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng),limits:Default::default(),
            registry:enclave_agent_runtime::registry::ToolRegistry::load(br#"{"v":1,"servers":[]}"#).unwrap(),
            cedar:Some(enclave_agent_runtime::cedar_engine::CedarEngine::baseline_bundle().unwrap()),
            state_dir:None,socket_dir:None,dev_same_uid:true},Box::new(NoDeclassification),Box::new(NoCustody)).unwrap();
        let stop=Arc::new(AtomicBool::new(false));let fail_before=Arc::new(AtomicBool::new(false));let fail_after=Arc::new(AtomicBool::new(false));
        let lose_begin=Arc::new(AtomicBool::new(false));let fail_cancel=Arc::new(AtomicBool::new(false));
        let ifc_path=dir.join("ifc.sock");
        let listener=ipc::bind(&ifc_path,ipc::SocketAccess::OwnerOnly).unwrap();
        let (s,st,before,after)=(runtime.clone(),stop.clone(),fail_before.clone(),fail_after.clone());
        let (lost,cancel)=(lose_begin.clone(),fail_cancel.clone());
        let first=std::thread::spawn(move||ipc::serve::<IfcRequest,IfcResponse,_>(listener,
            ipc::PeerPolicy::allow([ipc::geteuid()]),Arc::new(move|p:&PeerCredentials,r:IfcRequest|{
                let finish=matches!(&r,IfcRequest::FinishTurn {..});
                let begin=matches!(&r,IfcRequest::BeginGatewayTurn {..});
                if matches!(&r,IfcRequest::CancelGatewaySubmission {..})&&cancel.swap(false,Ordering::SeqCst) {
                    return Err(enclave_core::err!(EIO,"FIXTURE_CANCEL_RETRY"));
                }
                if finish&&before.swap(false,Ordering::SeqCst){return Err(enclave_core::err!(EIO,"FIXTURE_RETRY_BEFORE_FINISH"));}
                let response=s.handle(p,r);
                if begin&&lost.swap(false,Ordering::SeqCst) {return Err(enclave_core::err!(EIO,"FIXTURE_LOST_BEGIN_REPLY"));}
                if finish&&after.swap(false,Ordering::SeqCst){return Err(enclave_core::err!(EIO,"FIXTURE_LOST_FINISH_REPLY"));}
                response
            }),st).unwrap());
        let path=dir.join("gateway.sock");
        let listener=ipc::bind(&path,ipc::SocketAccess::OwnerOnly).unwrap();
        let gateway=Arc::new(ClientGateway::new(path,ifc_path,rate,Duration::from_secs(600),true));let st=stop.clone();
        let second=std::thread::spawn(move||ipc::serve::<ClientGatewayRequest,ClientGatewayResponse,_>(listener,
            ipc::PeerPolicy::allow([ipc::geteuid()]),Arc::new(move|p:&PeerCredentials,r|gateway.handle_request(p,r)),st).unwrap());
        Self {dir,runtime,stop,threads:vec![first,second],fail_before,fail_after,lose_begin,fail_cancel}
    }
    fn client(&self)->ipc::Client {ipc::Client::connect(&self.dir.join("gateway.sock"),ipc::geteuid()).unwrap()}
    fn submit(&self,bytes:&[u8])->(String,Vec<String>) {
        let mut client=self.client();
        match client.call(&request(bytes)).unwrap() {
            ClientGatewayResponse::Plan {turn_id,context,..}=>(turn_id,context.attachment_stubs),other=>panic!("{other:?}"),
        }
    }
    fn finish(&self,id:&str,cancelled:bool)->EnclaveResult<ClientGatewayResponse> {
        self.client().call(&ClientGatewayRequest::FinishTurn {turn_id:id.into(),cancelled})
    }
}
impl Drop for Fixture {
    fn drop(&mut self){self.stop.store(true,Ordering::SeqCst);for t in self.threads.drain(..){t.join().unwrap();}let _=fs::remove_dir_all(&self.dir);}
}
fn request(bytes:&[u8])->ClientGatewayRequest {
    let attachments=vec![AttachmentRef {handle:"$paste_0".into(),label:Label::ATTACHMENT_DEFAULT,
        blake3:blake3::hash(bytes).to_hex().to_string(),kind:None}];
    ClientGatewayRequest::SubmitTurn {turn:UserTurnV1 {directive_short:"private gateway lifecycle fixture".into(),attachments},
        attachments:vec![("$paste_0".into(),bytes.to_vec().into())],tools:vec![],budget_mb:0,holder_pk:None}
}

#[test]
fn completed_and_cancelled_gateway_turns_reclaim_capacity_without_global_wipe() {
    let f=Fixture::new(1024);let bytes=vec![b'x';64*1024];
    for i in 0..256 {
        let (id,handles)=f.submit(&bytes);
        assert_eq!(f.runtime.payload_for_test(&handles[0]).unwrap(),bytes);
        assert!(matches!(f.finish(&id,i%2==0).unwrap(),ClientGatewayResponse::Finished {released:1}));
        assert!(f.runtime.payload_for_test(&handles[0]).is_err());
    }
}
#[test]
fn completion_remains_available_after_submission_rate_limit() {
    let f=Fixture::new(1);let (id,handles)=f.submit(b"rate fixture");
    let result:EnclaveResult<ClientGatewayResponse>=f.client().call(&request(b"must be throttled"));
    assert!(result.unwrap_err().is("ERR_GATEWAY_RATE_LIMITED"));
    f.finish(&id,true).unwrap();assert!(f.runtime.payload_for_test(&handles[0]).is_err());
}
#[test]
fn cancellation_failure_preserves_ownership_for_retry_and_lost_reply_recovers_local_quota() {
    let f=Fixture::new(1024);let (id,handles)=f.submit(b"retry private fixture");
    f.fail_before.store(true,Ordering::SeqCst);
    assert!(f.finish(&id,true).unwrap_err().is("FIXTURE_RETRY_BEFORE_FINISH"));
    assert_eq!(f.runtime.payload_for_test(&handles[0]).unwrap(),b"retry private fixture");
    assert!(matches!(f.finish(&id,true).unwrap(),ClientGatewayResponse::Finished {released:1}));
    let (id,handles)=f.submit(b"lost reply fixture");f.fail_after.store(true,Ordering::SeqCst);
    assert!(f.finish(&id,false).unwrap_err().is("FIXTURE_LOST_FINISH_REPLY"));
    assert!(f.runtime.payload_for_test(&handles[0]).is_err());
    assert!(matches!(f.finish(&id,false).unwrap(),ClientGatewayResponse::Finished {released:0}));
    let (id,_)=f.submit(b"later legitimate turn");f.finish(&id,false).unwrap();
}
#[test]
fn another_real_process_with_same_uid_cannot_cancel_the_submitters_turn() {
    let f=Fixture::new(1024);let (id,handles)=f.submit(b"process identity sentinel");
    // The child uses only stdlib sockets and a tiny CBOR encoder. Its peer PID
    // (and Darwin audit pidversion) comes from the kernel, never a test field.
    let script=r#"
import os,socket,struct

def head(major,n):
    if n<24:return bytes([(major<<5)|n])
    if n<256:return bytes([(major<<5)|24,n])
    return bytes([(major<<5)|25])+struct.pack('>H',n)
def text(value):
    b=value.encode();return head(3,len(b))+b
def exact(s,n):
    b=b''
    while len(b)<n:
        more=s.recv(n-len(b));assert more;b+=more
    return b
body=b'\xa1'+text('FinishTurn')+b'\xa2'+text('turn_id')+text(os.environ['F71_TURN'])+text('cancelled')+b'\xf5'
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(10);s.connect(os.environ['F71_SOCKET'])
s.sendall(struct.pack('>I',len(body))+body)
n=struct.unpack('>I',exact(s,4))[0];assert n<=1048576
reply=exact(s,n);assert b'GATEWAY_TURN_OWNER_REJECTED' in reply,reply
"#;
    let result=std::process::Command::new("python3").arg("-c").arg(script)
        .env("F71_TURN",&id).env("F71_SOCKET",f.dir.join("gateway.sock")).output().unwrap();
    assert!(result.status.success(),"child exit {:?}: {}",result.status.code(),String::from_utf8_lossy(&result.stderr));
    assert_eq!(f.runtime.payload_for_test(&handles[0]).unwrap(),b"process identity sentinel");
    f.finish(&id,true).unwrap();
}

#[test]
fn f71_pending_submission_cancel_failure_blocks_new_begin_without_touching_live_turn() {
    let f=Fixture::new(1024);let (sentinel,keep)=f.submit(b"live unaffected submission");
    f.lose_begin.store(true,Ordering::SeqCst);
    let result:EnclaveResult<ClientGatewayResponse>=f.client().call(&request(b"ambiguous reply"));
    assert!(result.unwrap_err().is("FIXTURE_LOST_BEGIN_REPLY"));
    f.fail_cancel.store(true,Ordering::SeqCst);
    let result:EnclaveResult<ClientGatewayResponse>=f.client().call(&request(b"must wait for reconciliation"));
    assert!(result.unwrap_err().is("FIXTURE_CANCEL_RETRY"));
    assert_eq!(f.runtime.payload_for_test(&keep[0]).unwrap(),b"live unaffected submission");
    // The retry reconciles the exact pending sequence and admits the next
    // legitimate request only after runtime cleanup acknowledgement.
    let (next,handles)=f.submit(b"later legitimate request");
    assert_eq!(f.runtime.payload_for_test(&keep[0]).unwrap(),b"live unaffected submission");
    assert_eq!(f.runtime.payload_for_test(&handles[0]).unwrap(),b"later legitimate request");
    f.finish(&next,false).unwrap();f.finish(&sentinel,false).unwrap();
}

#[test]
fn f71_handler_denies_foreign_identity_before_gateway_authority_ipc() {
    let dir=PathBuf::from("/tmp").join(format!("f71-denied-{}",enclave_core::rng::u64()));
    // No runtime socket exists. The identity error must occur before trying
    // to reconcile through that socket, including direct handler embeddings.
    let gateway=ClientGateway::new(dir.join("gateway.sock"),dir.join("absent.sock"),1,Duration::from_secs(60),true);
    let mut peer=PeerCredentials::local(ipc::geteuid()^1,0);peer.pid=Some(std::process::id() as i32);
    assert!(gateway.handle_request(&peer,request(b"unauthenticated"))
        .unwrap_err().is("ERR_GATEWAY_PEER_DENIED"));
}
