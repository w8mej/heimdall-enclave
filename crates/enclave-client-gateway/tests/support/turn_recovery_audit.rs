//! Independently authored observable recovery probes. Only owned fixture
//! processes and private sockets/files are used; installed services are untouched.
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant};

use enclave_agent_runtime::registry::ToolRegistry;
use enclave_agent_runtime::service::{Declassifier, IfcConfig, IfcRequest, IfcResponse, IfcService, NoCustody};
use enclave_client_gateway::{ClientGateway, ClientGatewayRequest as Request, ClientGatewayResponse as Response};
use enclave_core::error::EnclaveResult;
use enclave_core::ipc::{self, PeerCredentials};
use enclave_core::label::Label;
use enclave_core::profile::Profile;
use enclave_core::user_turn::{AttachmentRef, UserTurnV1};

#[derive(Debug)]
struct NoDeclass;
impl Declassifier for NoDeclass {
    fn classify(&self, _: &[u8], _: u64, _: &str, _: &enclave_core::seq::GovernedSlot) -> EnclaveResult<u64> {
        Err(enclave_core::err!(EPERM, "AUDIT_NO_DECLASSIFICATION"))
    }
}

struct Fixture {
    dir: PathBuf,
    runtime: Arc<IfcService>,
    stop: Arc<AtomicBool>,
    servers: Vec<std::thread::JoinHandle<()>>,
    gateway: Option<std::process::Child>,
    lose_begin: Arc<AtomicBool>,
    begun_handles: Arc<Mutex<Vec<Vec<String>>>>,
}
impl Fixture {
    fn new(binary_gateway: bool) -> Self {
        Self::new_inner(binary_gateway,false)
    }
    fn new_inner(binary_gateway: bool, wire_loss:bool) -> Self {
        let dir=PathBuf::from("/tmp").join(format!("tr-audit-{}",enclave_core::rng::u64()));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir,fs::Permissions::from_mode(0o700)).unwrap();
        let runtime=IfcService::start(IfcConfig {
            profile:Profile::L2, audit_path:None,
            policy_key:ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng),
            limits:Default::default(), registry:ToolRegistry::load(br#"{"v":1,"servers":[]}"#).unwrap(),
            cedar:Some(enclave_agent_runtime::cedar_engine::CedarEngine::baseline_bundle().unwrap()),
            state_dir:None,socket_dir:None,dev_same_uid:true,
        },Box::new(NoDeclass),Box::new(NoCustody)).unwrap();
        let stop=Arc::new(AtomicBool::new(false));
        let lose_begin=Arc::new(AtomicBool::new(false));
        let begun_handles=Arc::new(Mutex::new(Vec::new()));
        let runtime_socket=dir.join(if wire_loss {"ifc/upstream.sock"} else {"ifc/ifc.sock"});
        let listener=ipc::bind(&runtime_socket,ipc::SocketAccess::OwnerOnly).unwrap();
        let (service,halted,lose,seen)=(runtime.clone(),stop.clone(),lose_begin.clone(),begun_handles.clone());
        let server=std::thread::spawn(move||ipc::serve::<IfcRequest,IfcResponse,_>(listener,
            ipc::PeerPolicy::allow([ipc::geteuid()]),Arc::new(move|peer:&PeerCredentials,req|{
                let response=service.handle(peer,req)?;
                if let IfcResponse::TurnPlan {context,..}=&response {
                    seen.lock().unwrap().push(context.attachment_stubs.clone());
                    // The runtime has actually committed the turn, but the
                    // gateway receives neither its ID nor its successful reply.
                    if !wire_loss && lose.swap(false,Ordering::SeqCst) {
                        return Err(enclave_core::err!(EIO,"AUDIT_LOST_BEGIN_REPLY"));
                    }
                }
                Ok(response)
            }),halted).unwrap());
        let mut fixture=Self {dir,runtime,stop,servers:vec![server],gateway:None,lose_begin,begun_handles};
        if wire_loss {
            // A transparent fixture proxy discards the already-produced reply
            // by actually closing the socket. It runs in this same process so
            // the runtime's kernel peer identity is unchanged in this case.
            let listener=ipc::bind(&fixture.dir.join("ifc/ifc.sock"),ipc::SocketAccess::OwnerOnly).unwrap();
            listener.set_nonblocking(true).unwrap();
            let halted=fixture.stop.clone();let lose=fixture.lose_begin.clone();
            fixture.servers.push(std::thread::spawn(move||{
                while !halted.load(Ordering::SeqCst) {
                    let (mut client,_)=match listener.accept() {
                        Ok(pair)=>pair,
                        Err(error) if error.kind()==std::io::ErrorKind::WouldBlock=>{
                            std::thread::sleep(Duration::from_millis(5));continue;
                        },
                        Err(error)=>panic!("private proxy accept: {error}"),
                    };
                    // Darwin accept inherits the listener's O_NONBLOCK. Match
                    // the real IPC server before attempting a framed read;
                    // EAGAIN is not the intentional post-commit socket loss.
                    client.set_nonblocking(false).unwrap();
                    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    let mut upstream=std::os::unix::net::UnixStream::connect(&runtime_socket).unwrap();
                    upstream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    while let Ok(body)=ipc::read_frame(&mut client) {
                        let request:IfcRequest=ipc::from_cbor(&body).unwrap();
                        let request_kind=match request {
                            IfcRequest::BeginGatewayTurn {..}=>"begin",
                            IfcRequest::CancelGatewaySubmission {..}=>"cancel",
                            IfcRequest::RecoverGatewayTurns=>"recover",
                            IfcRequest::FinishTurn {..}=>"finish",
                            _=>"other",
                        };
                        ipc::write_frame(&mut upstream,&body).unwrap();
                        let reply=ipc::read_frame(&mut upstream).unwrap();
                        let is_plan=matches!(ipc::from_cbor::<ipc::Reply<IfcResponse>>(&reply).unwrap(),
                            ipc::Reply::Ok(IfcResponse::TurnPlan {..}));
                        eprintln!("private recovery proxy: {request_kind}, plan={is_plan}, loss_armed={}",lose.load(Ordering::SeqCst));
                        if is_plan && lose.swap(false,Ordering::SeqCst) {
                            let _=client.shutdown(std::net::Shutdown::Both);break;
                        }
                        if ipc::write_frame(&mut client,&reply).is_err() {break;}
                    }
                }
            }));
        }
        if binary_gateway {fixture.start_gateway();}
        else {
            let listener=ipc::bind(&fixture.socket(),ipc::SocketAccess::OwnerOnly).unwrap();
            let gateway=Arc::new(ClientGateway::new(fixture.socket(),fixture.dir.join("ifc/ifc.sock"),
                1024,Duration::from_secs(600),true));
            let halted=fixture.stop.clone();
            fixture.servers.push(std::thread::spawn(move||ipc::serve::<Request,Response,_>(listener,
                ipc::PeerPolicy::allow([ipc::geteuid()]),Arc::new(move|peer:&PeerCredentials,req|gateway.handle_request(peer,req)),halted).unwrap()));
        }
        fixture
    }
    fn socket(&self)->PathBuf {self.dir.join("gateway/gateway.sock")}
    fn start_gateway(&mut self) {
        assert!(self.gateway.is_none());
        let previous=fs::symlink_metadata(self.socket()).ok().map(|m|m.ino());
        self.gateway=Some(std::process::Command::new(env!("CARGO_BIN_EXE_enclave-client-gateway"))
            .args(["--dev-same-uid","--no-audit","--socket-dir"]).arg(&self.dir)
            .stdout(std::process::Stdio::null()).spawn().unwrap());
        let deadline=Instant::now()+Duration::from_secs(10);
        loop {
            assert!(self.gateway.as_mut().unwrap().try_wait().unwrap().is_none(),"owned gateway exited before ready");
            if fs::symlink_metadata(self.socket()).ok().map(|m|m.ino()).is_some_and(|inode|Some(inode)!=previous) {break;}
            assert!(Instant::now()<deadline,"owned gateway startup deadline");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn stop_gateway(&mut self) {
        if let Some(mut child)=self.gateway.take() {let _=child.kill();child.wait().unwrap();}
    }
    fn call(&self,request:&Request)->EnclaveResult<Response> {
        ipc::Client::connect(&self.socket(),ipc::geteuid())?.call(request)
    }
    fn submit(&self,text:&[u8])->(String,String) {
        match self.call(&request(text)).unwrap_or_else(|error|panic!("submission {} failed: {error}",String::from_utf8_lossy(text))) {
            Response::Plan {turn_id,context,..}=>{
                assert_eq!(context.attachment_stubs.len(),1);
                (turn_id,context.attachment_stubs[0].clone())
            },other=>panic!("expected plan, got {other:?}"),
        }
    }
    fn finish(&self,id:&str) {self.call(&Request::FinishTurn {turn_id:id.into(),cancelled:true}).unwrap();}
    fn runtime_sentinel(&self,bytes:&[u8])->(String,String) {
        let Request::SubmitExecutableTurn {turn,attachments,tools,budget_mb}=request(bytes) else {unreachable!()};
        let reply:IfcResponse=ipc::Client::connect(&self.dir.join("ifc/ifc.sock"),ipc::geteuid()).unwrap()
            .call(&IfcRequest::BeginTurn {turn,attachments,tools,budget_mb,holder_pk:None}).unwrap();
        let IfcResponse::TurnPlan {turn_id,context,..}=reply else {panic!("runtime sentinel needs a real turn")};
        (turn_id,context.attachment_stubs[0].clone())
    }
    fn finish_runtime(&self,id:&str) {
        let response:IfcResponse=ipc::Client::connect(&self.dir.join("ifc/ifc.sock"),ipc::geteuid()).unwrap()
            .call(&IfcRequest::FinishTurn {turn_id:id.into(),cancelled:true}).unwrap();
        assert!(matches!(response,IfcResponse::TurnFinished {..}));
    }
    fn last_handle(&self)->String {
        let seen=self.begun_handles.lock().unwrap();
        let handles=seen.last().expect("runtime actually created a turn");
        assert_eq!(handles.len(),1);handles[0].clone()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop_gateway();self.stop.store(true,Ordering::SeqCst);
        for server in self.servers.drain(..) {server.join().unwrap();}
        fs::remove_dir_all(&self.dir).unwrap();
    }
}
fn request(bytes:&[u8])->Request {
    let reference=AttachmentRef {handle:"$paste_0".into(),label:Label::ATTACHMENT_DEFAULT,
        blake3:blake3::hash(bytes).to_hex().to_string(),kind:None};
    Request::SubmitExecutableTurn {
        turn:UserTurnV1 {directive_short:"independent bounded recovery audit".into(),attachments:vec![reference]},
        attachments:vec![("$paste_0".into(),bytes.to_vec().into())],tools:vec![],budget_mb:0,
    }
}

fn lost_begin_case(wire_loss:bool) {
    let f=Fixture::new_inner(false,wire_loss);
    let (live,live_handle)=f.submit(b"live owner sentinel");
    let before=f.begun_handles.lock().unwrap().len();
    f.lose_begin.store(true,Ordering::SeqCst);
    // Both an immediate exact retry and a failed request followed by maintenance
    // are valid, provided the committed turn remains reachable for cleanup.
    let lost=f.call(&request(b"reply lost after actual runtime begin"));
    let committed:std::collections::BTreeSet<String>=f.begun_handles.lock().unwrap()[before..]
        .iter().flatten().cloned().collect();
    assert_eq!(committed.len(),1,"a lost Begin reply minted more than one turn");
    let returned_id=match lost {
        Ok(Response::Plan {turn_id,..})=>Some(turn_id),
        Err(error) if error.is("AUDIT_LOST_BEGIN_REPLY") || (wire_loss&&error.is("IPC_READ"))=>None,
        other=>panic!("unexpected Begin recovery outcome: {other:?}"),
    };
    if let Some(id)=returned_id {f.finish(&id);}
    let (fresh,fresh_handle)=f.submit(b"later legitimate turn");
    for orphan in committed {
        assert!(f.runtime.payload_for_test(&orphan).is_err(),"committed lost-reply turn leaked its payload");
    }
    assert_eq!(f.runtime.payload_for_test(&live_handle).unwrap(),b"live owner sentinel");
    assert_eq!(f.runtime.payload_for_test(&fresh_handle).unwrap(),b"later legitimate turn");
    f.finish(&fresh);f.finish(&live);
}

#[test]
fn lost_begin_reply_reclaims_the_committed_turn_without_losing_a_live_sentinel() {
    lost_begin_case(false);
}

#[test]
fn actual_socket_loss_after_committed_begin_does_not_strand_the_turn() {
    lost_begin_case(true);
}

#[test]
fn exited_console_child_is_reclaimed_while_the_live_parent_turn_survives() {
    let f=Fixture::new(false);
    let (live,live_handle)=f.submit(b"parent still alive");
    // Independent stdlib-only child sends the real framed gateway request.
    // Credential PID and Darwin pidversion are supplied by the kernel.
    let child=r#"
import json,os,socket,struct
def head(m,n):
    if n<24:return bytes([(m<<5)|n])
    if n<256:return bytes([(m<<5)|24,n])
    if n<65536:return bytes([(m<<5)|25])+struct.pack('>H',n)
    return bytes([(m<<5)|26])+struct.pack('>I',n)
def enc(v):
    if v is None:return b'\xf6'
    if v is False:return b'\xf4'
    if v is True:return b'\xf5'
    if isinstance(v,int):return head(0,v) if v>=0 else head(1,-1-v)
    if isinstance(v,str):
        b=v.encode();return head(3,len(b))+b
    if isinstance(v,bytes):return head(2,len(v))+v
    if isinstance(v,list):return head(4,len(v))+b''.join(enc(x) for x in v)
    if isinstance(v,dict):return head(5,len(v))+b''.join(enc(k)+enc(x) for k,x in v.items())
    raise AssertionError(type(v))
def exact(s,n):
    b=b''
    while len(b)<n:
        more=s.recv(n-len(b));assert more;b+=more
    return b
req=json.loads(os.environ['RECOVERY_REQUEST'])
for pair in req['SubmitExecutableTurn']['attachments']:pair[1]=bytes(pair[1])
body=enc(req)
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(10);s.connect(os.environ['RECOVERY_SOCKET'])
s.sendall(struct.pack('>I',len(body))+body)
n=struct.unpack('>I',exact(s,4))[0];assert 0<n<=1048576
reply=exact(s,n);assert b'Plan' in reply and b'attachment_stubs' in reply,reply
"#;
    let result=std::process::Command::new("python3").args(["-c",child])
        .env("RECOVERY_SOCKET",f.socket())
        .env("RECOVERY_REQUEST",serde_json::to_string(&request(b"dead child payload")).unwrap())
        .output().unwrap();
    assert!(result.status.success(),"owned child failed: {}",String::from_utf8_lossy(&result.stderr));
    let orphan=f.last_handle();
    let (fresh,_)=f.submit(b"parent recovery trigger");
    assert!(f.runtime.payload_for_test(&orphan).is_err(),"dead console process stranded a managed payload");
    assert_eq!(f.runtime.payload_for_test(&live_handle).unwrap(),b"parent still alive");
    f.finish(&fresh);f.finish(&live);
}

#[test]
fn restarted_gateway_reclaims_its_dead_incarnation_without_a_runtime_wipe() {
    let mut f=Fixture::new(true);
    let (sentinel,sentinel_handle)=f.runtime_sentinel(b"different live ingress owns this value");
    let (_,orphan)=f.submit(b"dead gateway incarnation");
    assert_eq!(f.runtime.payload_for_test(&orphan).unwrap(),b"dead gateway incarnation");
    f.stop_gateway();f.start_gateway();
    let (fresh,fresh_handle)=f.submit(b"new gateway legitimate use");
    assert!(f.runtime.payload_for_test(&orphan).is_err(),"gateway restart left the old runtime turn stranded");
    assert_eq!(f.runtime.payload_for_test(&sentinel_handle).unwrap(),b"different live ingress owns this value");
    assert_eq!(f.runtime.payload_for_test(&fresh_handle).unwrap(),b"new gateway legitimate use");
    f.finish(&fresh);f.finish_runtime(&sentinel);
}
