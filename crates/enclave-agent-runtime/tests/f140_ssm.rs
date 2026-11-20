//! F140 production socket-adapter regressions. All fixtures are private; no
//! installed daemon, account, policy or model cache is touched.
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc,Mutex,Condvar,atomic::{AtomicBool,Ordering}};
use std::time::Duration;
use enclave_agent_runtime::{service::{IfcService,IfcConfig,IfcRequest,IfcResponse,CustodyPort,Declassifier,StepUp},ssm::RemoteSsmRunner};
use enclave_core::{error::EnclaveResult,ipc::{self,PeerCredentials},label::{Label,Taint},runtime::DaemonArgs,user_turn::{UserTurnV1,AttachmentRef},ifc_envelope::{IfcEnvelopeV1,QifPool}};
use serde::{Serialize,Deserialize};

#[derive(Debug)] struct Fixed;
impl Declassifier for Fixed {
    fn classify(&self,_:&[u8],_:u64,_:&str,_:&enclave_core::seq::GovernedSlot)->EnclaveResult<u64>{Ok(0)}
}
#[derive(Debug,Default)] struct Vault(Mutex<u64>);
impl CustodyPort for Vault {
    fn scrub_text(&self,text:&str,_:bool)->EnclaveResult<String>{Ok(enclave_core::pii::scan(text).iter().fold(text.to_owned(),|t,f|t.replace(&text[f.start..f.end],"[REDACTED]")))}
    fn authorize_intent(&self,_:&enclave_core::intent_draft::IntentDraftV1)->EnclaveResult<StepUp>{Err(enclave_core::err!(EPERM,"FIXTURE_NO_HW"))}
    fn allocate_slot(&self)->EnclaveResult<(String,u64)>{let mut n=self.0.lock().unwrap();*n+=1;Ok(("6f1c2c1e-3a54-4b8e-9d7a-0c4f5b6a7e81".into(),*n))}
    fn boot_epoch(&self)->EnclaveResult<enclave_core::seq::BootEpoch>{Ok(enclave_crypto::epoch::EpochSigner::random().sign("6f1c2c1e-3a54-4b8e-9d7a-0c4f5b6a7e81"))}
}
#[derive(Deserialize)] enum Request {
    SsmForkOwned {scope:[u8;32],label:Label},
    SsmIngestOwned {scope:[u8;32],label:Label,bytes:serde_bytes::ByteBuf},
    SsmGenerateOwned {scope:[u8;32],n:u32},
    SsmExitOwned {scope:[u8;32]},
}
#[derive(Serialize)] enum Response {
    Session(u64), Ok, Wiped(usize),
    Ssm {label:Label,output:serde_bytes::ByteBuf,anchors:u32,boundary_anchor:bool},
    #[serde(rename="Ssm")] Missing {output:serde_bytes::ByteBuf,anchors:u32,boundary_anchor:bool},
}
#[derive(Default)] struct WireState {
    sessions:BTreeMap<[u8;32],Label>, ingests:Vec<(Label,Vec<u8>)>, forks:usize, exits:usize,
    fail_exit:usize, lost_fork:bool, lost_exit:bool, downgrade:bool, missing:bool, wrong:bool,
    oversize:bool, binary:bool, c4_once:bool, output_label:Option<Label>,
}
#[derive(Default)] struct Pause {state:Mutex<(bool,bool,bool)>,changed:Condvar}
impl Pause {
    fn arm(&self){*self.state.lock().unwrap()=(true,false,false);}
    fn entered(&self){let s=self.state.lock().unwrap();let (s,timeout)=self.changed.wait_timeout_while(s,Duration::from_secs(3),|s|!s.1).unwrap();assert!(s.1&&!timeout.timed_out(),"generation never entered");}
    fn resume(&self){let mut s=self.state.lock().unwrap();s.2=true;self.changed.notify_all();}
    fn pause(&self){let mut s=self.state.lock().unwrap();if s.0{s.1=true;self.changed.notify_all();while !s.2{s=self.changed.wait(s).unwrap();}s.0=false;}}
}
struct Fixture {dir:PathBuf,svc:Arc<IfcService>,state:Arc<Mutex<WireState>>,pause:Arc<Pause>,stop:Arc<AtomicBool>,thread:Option<std::thread::JoinHandle<()>>}
impl Fixture {
    fn new()->Self {Self::new_with_state(None)}
    fn new_with_state(state_dir:Option<PathBuf>)->Self {
        use std::os::unix::fs::PermissionsExt;
        let dir=std::env::temp_dir().join(format!("f140r-{}",enclave_core::rng::u64()));std::fs::create_dir(&dir).unwrap();std::fs::set_permissions(&dir,std::fs::Permissions::from_mode(0o700)).unwrap();
        let args=DaemonArgs::parse(vec!["fixture".into(),"--dev-same-uid".into(),"--no-audit".into(),"--socket-dir".into(),dir.to_string_lossy().into_owned()]).unwrap();
        let listener=ipc::bind(&args.socket_path(enclave_core::daemon::DaemonId::ModelRunner),ipc::SocketAccess::OwnerOnly).unwrap();
        let state=Arc::new(Mutex::new(WireState::default()));let stop=Arc::new(AtomicBool::new(false));let pause=Arc::new(Pause::default());let (s,st,p)=(state.clone(),stop.clone(),pause.clone());
        let thread=std::thread::spawn(move||ipc::serve::<Request,Response,_>(listener,ipc::PeerPolicy::allow([ipc::geteuid()]),Arc::new(move|_:&PeerCredentials,r:Request|{
            if matches!(&r,Request::SsmGenerateOwned {..}) {p.pause();}
            let mut s=s.lock().unwrap();
            match r {
                Request::SsmForkOwned {scope,label}=>{s.forks+=1;assert!(s.sessions.len()<8);s.sessions.insert(scope,label);if s.lost_fork {s.lost_fork=false;return Err(enclave_core::err!(EIO,"FIXTURE_LOST_FORK_REPLY"));}Ok(Response::Session(s.forks as u64))},
                Request::SsmIngestOwned {scope,label,bytes}=>{let floor=s.sessions.get_mut(&scope).ok_or_else(||enclave_core::err!(EINVAL,"UNKNOWN_SESSION"))?;*floor=floor.join(label);s.ingests.push((label,bytes.into_vec()));Ok(Response::Ok)},
                Request::SsmGenerateOwned {scope,n}=>{let label=*s.sessions.get(&scope).ok_or_else(||enclave_core::err!(EINVAL,"UNKNOWN_SESSION"))?;
                    if s.wrong{return Ok(Response::Ok);}
                    let bytes=if s.binary {vec![255]} else if s.c4_once {s.c4_once=false;b"4111 1111 1111 1111".to_vec()} else if s.oversize {vec![b'x';n as usize+1]} else {b"opaque-generated-sentinel".to_vec()};
                    if s.missing{return Ok(Response::Missing {output:bytes.into(),anchors:1,boundary_anchor:true});}
                    Ok(Response::Ssm {label:if s.downgrade{Label::BOTTOM}else{s.output_label.unwrap_or(label)},output:bytes.into(),anchors:1,boundary_anchor:true})},
                Request::SsmExitOwned {scope}=>{s.exits+=1;if s.fail_exit>0{s.fail_exit-=1;return Err(enclave_core::err!(EIO,"FIXTURE_EXIT_FAILED"));}let count=usize::from(s.sessions.remove(&scope).is_some());if s.lost_exit{s.lost_exit=false;return Err(enclave_core::err!(EIO,"FIXTURE_LOST_EXIT_REPLY"));}Ok(Response::Wiped(count))},
            }
        }),st).unwrap());
        let svc=IfcService::start_with_ssm(IfcConfig {profile:enclave_core::profile::Profile::L2,audit_path:None,policy_key:ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng),limits:Default::default(),registry:enclave_agent_runtime::registry::ToolRegistry::empty(),cedar:Some(enclave_agent_runtime::cedar_engine::CedarEngine::baseline_bundle().unwrap()),state_dir,socket_dir:None,dev_same_uid:true},Box::new(Fixed),Box::new(Vault::default()),Box::new(RemoteSsmRunner::new(args))).unwrap();
        Self {dir,svc,state,pause,stop,thread:Some(thread)}
    }
    fn begin(&self,bytes:&[u8])->(String,String){
        let r=self.svc.handle(&owner(),IfcRequest::BeginTurn {turn:UserTurnV1 {directive_short:"session bridge fixture".into(),attachments:vec![AttachmentRef {handle:"$paste_0".into(),label:Label::ATTACHMENT_DEFAULT,blake3:blake3::hash(bytes).to_hex().to_string(),kind:None}]},attachments:vec![("$paste_0".into(),bytes.to_vec().into())],tools:vec![],holder_pk:None,budget_mb:0}).unwrap();
        match r {IfcResponse::TurnPlan {turn_id,context,..}=>(turn_id,context.attachment_stubs[0].clone()),_=>panic!()}
    }
    fn ingest(&self,id:&str,handle:&str)->EnclaveResult<IfcResponse>{self.svc.handle(&owner(),IfcRequest::SsmIngestTurnHandles {turn_id:id.into(),handles:vec![handle.into()]})}
    fn generate(&self,id:&str)->EnclaveResult<IfcEnvelopeV1>{match self.svc.handle(&owner(),IfcRequest::SsmGenerateTurn {turn_id:id.into(),n:64})?{IfcResponse::Handle(env)=>Ok(env),_=>panic!()}}
    fn finish(&self,id:&str)->EnclaveResult<IfcResponse>{self.svc.handle(&owner(),IfcRequest::FinishTurn {turn_id:id.into(),cancelled:true})}
}
impl Drop for Fixture {fn drop(&mut self){self.pause.resume();self.stop.store(true,Ordering::SeqCst);self.thread.take().unwrap().join().unwrap();let _=std::fs::remove_dir_all(&self.dir);}}
fn owner()->PeerCredentials {let mut p=PeerCredentials::local(ipc::geteuid(),0);p.pid=Some(4242);p}

#[test]
fn real_remote_port_seals_mandatory_label_provenance_and_never_returns_plaintext(){
    let f=Fixture::new();let (id,h)=f.begin(b"actual trusted attachment");f.state.lock().unwrap().output_label=Some(Label::TOP);
    f.ingest(&id,&h).unwrap();let env=f.generate(&id).unwrap();assert_eq!(env.label,Label::TOP);assert_eq!(env.entity_keys.len(),1);assert_eq!(env.qif_pool,Some(QifPool::GlobalUnstructuredC3C424hPool));assert_eq!(env.provenance_parents,Some(vec![h.clone()]));assert!(env.provenance_dag_blake3.is_some());assert!(env.enclave_boot_mac.is_some());assert_eq!(f.svc.payload_for_test(&env.handle).unwrap(),b"opaque-generated-sentinel");
    let mut wire=Vec::new();ciborium::into_writer(&IfcResponse::Handle(env.clone()),&mut wire).unwrap();assert!(!wire.windows(25).any(|w|w==b"opaque-generated-sentinel"));
    let s=f.state.lock().unwrap();assert_eq!(s.ingests[0].0,Label::ATTACHMENT_DEFAULT);assert_eq!(s.ingests[0].1,b"actual trusted attachment");drop(s);
    f.finish(&id).unwrap();assert!(f.svc.payload_for_test(&env.handle).is_err());assert!(f.state.lock().unwrap().sessions.is_empty());
}
#[test]
fn exact_envelope_and_membership_are_checked_before_any_runner_mutation(){
    let f=Fixture::new();let (id,h)=f.begin(b"first owner");let (other,foreign)=f.begin(b"foreign owner");
    assert!(f.ingest(&id,&foreign).unwrap_err().is("SSM_INPUT_NOT_TURN_OWNED"));assert_eq!(f.state.lock().unwrap().forks,0);
    f.ingest(&other,&foreign).unwrap();let env=f.generate(&other).unwrap();
    let mut forged=env.clone();forged.label=Label::BOTTOM;
    assert!(f.svc.handle(&owner(),IfcRequest::SsmIngestTurn {turn_id:id.clone(),envelopes:vec![forged]}).is_err());assert_eq!(f.state.lock().unwrap().forks,1);
    assert!(f.svc.handle(&owner(),IfcRequest::SsmIngestTurn {turn_id:id.clone(),envelopes:vec![env]}).unwrap_err().is("SSM_INPUT_NOT_TURN_OWNED"));
    let mut stranger=owner();stranger.pid=Some(9999);assert!(f.svc.handle(&stranger,IfcRequest::SsmIngestTurnHandles {turn_id:id.clone(),handles:vec![h]}).unwrap_err().is("TURN_OWNER_REJECTED"));
    f.finish(&id).unwrap();f.finish(&other).unwrap();
}
#[test]
fn missing_downgraded_wrong_oversize_and_binary_outputs_fail_closed(){
    for mode in 0..5 {
        let f=Fixture::new();let (id,h)=f.begin(b"output boundary fixture");f.ingest(&id,&h).unwrap();
        {let mut s=f.state.lock().unwrap();match mode {0=>s.missing=true,1=>s.downgrade=true,2=>s.wrong=true,3=>s.oversize=true,_=>s.binary=true}}
        assert!(f.generate(&id).is_err());assert!(f.generate(&id).unwrap_err().is("SSM_SESSION_CLOSING"));f.finish(&id).unwrap();
    }
}
#[test]
fn lost_fork_reply_keeps_scope_cleanable_and_never_reforks(){
    let f=Fixture::new();let (id,h)=f.begin(b"fork uncertainty fixture");f.state.lock().unwrap().lost_fork=true;
    assert!(f.ingest(&id,&h).unwrap_err().is("FIXTURE_LOST_FORK_REPLY"));assert_eq!(f.state.lock().unwrap().sessions.len(),1);
    assert!(f.ingest(&id,&h).unwrap_err().is("SSM_SESSION_CLOSING"));assert_eq!(f.state.lock().unwrap().forks,1);
    f.finish(&id).unwrap();assert!(f.state.lock().unwrap().sessions.is_empty());
}
#[test]
fn finish_retries_failed_and_lost_successful_exits_without_releasing_parents(){
    let f=Fixture::new();let (id,h)=f.begin(b"finish retry fixture");f.ingest(&id,&h).unwrap();f.state.lock().unwrap().fail_exit=1;
    assert!(f.finish(&id).unwrap_err().is("FIXTURE_EXIT_FAILED"));assert_eq!(f.svc.payload_for_test(&h).unwrap(),b"finish retry fixture");assert!(f.generate(&id).unwrap_err().is("TURN_CLOSING"));
    f.state.lock().unwrap().lost_exit=true;assert!(f.finish(&id).unwrap_err().is("FIXTURE_LOST_EXIT_REPLY"));assert!(f.svc.payload_for_test(&h).is_ok());assert!(f.state.lock().unwrap().sessions.is_empty());
    f.finish(&id).unwrap();assert!(f.svc.payload_for_test(&h).is_err());assert_eq!(f.state.lock().unwrap().exits,3);
}
#[test]
fn emergency_wipe_erases_local_payload_before_failed_remote_exit_and_can_retry(){
    let f=Fixture::new();let (id,h)=f.begin(b"wipe immediate fixture");f.ingest(&id,&h).unwrap();f.state.lock().unwrap().fail_exit=1;
    assert!(f.svc.handle(&owner(),IfcRequest::Wipe).unwrap_err().is("FIXTURE_EXIT_FAILED"));assert!(f.svc.payload_for_test(&h).is_err());
    let status=f.svc.handle(&owner(),IfcRequest::Status).unwrap();match status {IfcResponse::Status(s)=>assert!(s.state.contains("ssm_cleanup_pending=true")),_=>panic!()}
    assert!(f.svc.handle(&owner(),IfcRequest::SubmitTurn {turn:UserTurnV1 {directive_short:"blocked".into(),attachments:vec![]},attachments:vec![],tools:vec![],holder_pk:None,budget_mb:0}).unwrap_err().is("SSM_CLEANUP_PENDING"));
    f.finish(&id).unwrap();f.svc.handle(&owner(),IfcRequest::Wipe).unwrap();
    match f.svc.handle(&owner(),IfcRequest::Status).unwrap(){IfcResponse::Status(s)=>assert!(s.state.contains("ssm_cleanup_pending=false")),_=>panic!()}
    // Retrying already sterile local memory must not create quarantine.
    let (next,_)=f.begin(b"later lifecycle after completed wipe");f.finish(&next).unwrap();
}
#[test]
fn cancellation_waits_for_outcall_without_blocking_status_or_publishing_late_output(){
    let f=Fixture::new();let (id,h)=f.begin(b"inflight generation fixture");f.ingest(&id,&h).unwrap();f.pause.arm();
    let svc=f.svc.clone();let gid=id.clone();let generate=std::thread::spawn(move||svc.handle(&owner(),IfcRequest::SsmGenerateTurn {turn_id:gid,n:64}));f.pause.entered();
    assert!(matches!(f.svc.handle(&owner(),IfcRequest::Status).unwrap(),IfcResponse::Status(_)));
    let svc=f.svc.clone();let fid=id.clone();let finish=std::thread::spawn(move||svc.handle(&owner(),IfcRequest::FinishTurn {turn_id:fid,cancelled:true}));
    let until=std::time::Instant::now()+Duration::from_secs(2);loop {let r=f.svc.handle(&owner(),IfcRequest::RetainTurnHandles {turn_id:id.clone(),envelopes:vec![]});if r.is_err(){break;}assert!(std::time::Instant::now()<until);std::thread::yield_now();}
    f.pause.resume();assert!(generate.join().unwrap().is_err());assert!(matches!(finish.join().unwrap().unwrap(),IfcResponse::TurnFinished {released:1}));assert!(f.svc.payload_for_test(&h).is_err());assert!(f.state.lock().unwrap().sessions.is_empty());
}
#[test]
fn multiple_inputs_repeated_generation_and_scanner_c4_floor_are_monotone(){
    let f=Fixture::new();let (id,h)=f.begin(b"input one");let (other,foreign)=f.begin(b"input two");f.ingest(&other,&foreign).unwrap();let second=f.generate(&other).unwrap();
    f.svc.handle(&owner(),IfcRequest::RetainTurnHandles {turn_id:id.clone(),envelopes:vec![second.clone()]}).unwrap();
    f.ingest(&id,&h).unwrap();f.svc.handle(&owner(),IfcRequest::SsmIngestTurn {turn_id:id.clone(),envelopes:vec![second]}).unwrap();
    f.state.lock().unwrap().c4_once=true;let a=f.generate(&id).unwrap();assert_eq!(a.label,Label::TOP);assert_eq!(a.entity_keys.len(),2);assert_eq!(a.provenance_parents.as_ref().unwrap().len(),2);assert!(!f.svc.payload_for_test(&a.handle).unwrap().windows(4).any(|w|w==b"4111"));
    let b=f.generate(&id).unwrap();assert_eq!(b.label,Label::TOP);assert_eq!(a.entity_keys,b.entity_keys);assert_eq!(a.qif_pool,b.qif_pool);
    f.finish(&other).unwrap();assert!(f.svc.payload_for_test(&foreign).is_err());assert!(f.svc.payload_for_test(&h).is_ok());f.finish(&id).unwrap();
}
#[test]
fn low_t2_runner_label_can_generate_repeatedly_while_outputs_remain_t3(){
    let f=Fixture::new();let (id,h)=f.begin(b"bounded classifier fixture");
    let env=match f.svc.handle(&owner(),IfcRequest::DeclassifyEnum {agent:"fixture".into(),handle:h,cardinality:2,schema:"enum".into()}).unwrap(){IfcResponse::Handle(env)=>env,_=>panic!()};assert_eq!(env.label.t,Taint::T2);
    f.svc.handle(&owner(),IfcRequest::SsmIngestTurn {turn_id:id.clone(),envelopes:vec![env.clone()]}).unwrap();
    let a=f.generate(&id).unwrap();let b=f.generate(&id).unwrap();assert_eq!(a.label.t,Taint::T3);assert_eq!(b.label.t,Taint::T3);assert_eq!(a.label.c,env.label.c);assert_eq!(b.label.c,env.label.c);f.finish(&id).unwrap();
}
#[test]
fn sequential_sessions_recover_runner_quota_over_eight_turns(){
    let f=Fixture::new();for i in 0..20 {let (id,h)=f.begin(format!("sequential input {i}").as_bytes());f.ingest(&id,&h).unwrap();f.generate(&id).unwrap();f.finish(&id).unwrap();assert!(f.state.lock().unwrap().sessions.is_empty());}assert_eq!(f.state.lock().unwrap().forks,20);
}

#[test]
fn late_quarantine_during_remote_generation_prevents_handle_publication(){
    let f=Fixture::new();let (id,h)=f.begin(b"late quarantine fixture");f.ingest(&id,&h).unwrap();f.pause.arm();
    let svc=f.svc.clone();let gid=id.clone();let generate=std::thread::spawn(move||svc.handle(&owner(),IfcRequest::SsmGenerateTurn {turn_id:gid,n:64}));f.pause.entered();
    f.svc.set_flow_state_for_test(enclave_agent_runtime::flow_fsm::FlowState::QuarantineAbort).unwrap();f.pause.resume();
    assert!(generate.join().unwrap().unwrap_err().is("FLOW_GATE_QUARANTINE_ABORT"));assert!(matches!(f.finish(&id).unwrap(),IfcResponse::TurnFinished {released:1}));
}
#[test]
fn runner_expiry_or_restart_never_reforks_and_discards_known_provenance(){
    let f=Fixture::new();let (id,h)=f.begin(b"expiry provenance fixture");f.ingest(&id,&h).unwrap();f.state.lock().unwrap().sessions.clear();
    assert!(f.generate(&id).unwrap_err().is("UNKNOWN_SESSION"));assert!(f.ingest(&id,&h).unwrap_err().is("SSM_SESSION_CLOSING"));assert_eq!(f.state.lock().unwrap().forks,1);f.finish(&id).unwrap();
}
#[test]
fn repeated_emergency_wipe_retries_scope_and_blocks_legacy_ingress_and_authorization(){
    let f=Fixture::new();let (id,h)=f.begin(b"wipe retry scope fixture");f.ingest(&id,&h).unwrap();f.state.lock().unwrap().fail_exit=1;
    assert!(f.svc.handle(&owner(),IfcRequest::Wipe).is_err());assert!(f.svc.payload_for_test(&h).is_err());
    assert!(f.svc.handle(&owner(),IfcRequest::IngestToolOutput {server:"unconfigured".into(),tool_name:"none".into(),tools_list:"{}".into(),payload:b"blocked ingress".to_vec().into(),conf_hint:None,source_uri:"fixture://blocked".into()}).unwrap_err().is("SSM_CLEANUP_PENDING"));
    assert!(f.svc.handle(&owner(),IfcRequest::AuthorizeToolCall {server:"unconfigured".into(),tool_name:"none".into(),args_jcs:b"{}".to_vec().into(),arg_handles:vec![],wire_cbor:vec![].into(),step_up:false}).unwrap_err().is("SSM_CLEANUP_PENDING"));
    f.svc.handle(&owner(),IfcRequest::Wipe).unwrap();assert_eq!(f.state.lock().unwrap().exits,2);assert!(f.state.lock().unwrap().sessions.is_empty());
    match f.svc.handle(&owner(),IfcRequest::Status).unwrap(){IfcResponse::Status(s)=>assert!(s.state.contains("ssm_cleanup_pending=false")),_=>panic!()}
    let (id,_)=f.begin(b"post retry fixture");f.finish(&id).unwrap();
}
#[test]
fn actual_remote_call_has_explicit_bounded_timeout_and_preserves_cleanup_scope(){
    let f=Fixture::new();let (id,h)=f.begin(b"timeout fixture");f.ingest(&id,&h).unwrap();f.pause.arm();
    let started=std::time::Instant::now();let svc=f.svc.clone();let gid=id.clone();let generate=std::thread::spawn(move||svc.handle(&owner(),IfcRequest::SsmGenerateTurn {turn_id:gid,n:64}));f.pause.entered();
    assert!(matches!(f.svc.handle(&owner(),IfcRequest::Status).unwrap(),IfcResponse::Status(_)));
    assert!(generate.join().unwrap().is_err());assert!(started.elapsed()<Duration::from_secs(12),"five-second per-call timeout was not enforced");assert_eq!(f.state.lock().unwrap().sessions.len(),1);f.pause.resume();f.finish(&id).unwrap();assert!(f.state.lock().unwrap().sessions.is_empty());
}

#[test]
fn generated_c4_literal_exposure_survives_finish_wipe_and_actual_runtime_restart(){
    let state_dir=std::env::temp_dir().join(format!("f140p-{}",enclave_core::rng::u64()));
    let f=Fixture::new_with_state(Some(state_dir.clone()));let (id,h)=f.begin(b"persist generated exposure fixture");f.ingest(&id,&h).unwrap();f.state.lock().unwrap().output_label=Some(Label::TOP);let env=f.generate(&id).unwrap();assert_eq!(env.label,Label::TOP);
    let read_floor=||{let (_,loaded)=enclave_core::sealed::SealedStore::open(&state_dir,"literal-exposure").unwrap();match loaded {enclave_core::sealed::Loaded::State(bytes)=>enclave_core::sealed::decode::<Label>(&bytes).unwrap(),_=>panic!("missing generated exposure")}};
    assert_eq!(read_floor(),Label::TOP);f.finish(&id).unwrap();f.svc.handle(&owner(),IfcRequest::Wipe).unwrap();assert_eq!(read_floor(),Label::TOP);drop(f);
    // Start a new real runtime after the original instance and all socket
    // fixtures have stopped. Startup saves its loaded heap exposure back to
    // this MAC/generation-checked store, so a missed load would overwrite TOP.
    let restarted=IfcService::start(IfcConfig {profile:enclave_core::profile::Profile::L2,audit_path:None,policy_key:ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng),limits:Default::default(),registry:enclave_agent_runtime::registry::ToolRegistry::empty(),cedar:Some(enclave_agent_runtime::cedar_engine::CedarEngine::baseline_bundle().unwrap()),state_dir:Some(state_dir.clone()),socket_dir:None,dev_same_uid:true},Box::new(Fixed),Box::new(Vault::default())).unwrap();
    assert_eq!(read_floor(),Label::TOP);assert!(restarted.payload_for_test(&env.handle).is_err());drop(restarted);std::fs::remove_dir_all(&state_dir).unwrap();
}

#[test]
fn wipe_retry_preserves_quarantine_that_existed_before_cleanup(){
    let f=Fixture::new();let (id,h)=f.begin(b"preexisting quarantine fixture");f.ingest(&id,&h).unwrap();
    f.svc.set_flow_state_for_test(enclave_agent_runtime::flow_fsm::FlowState::QuarantineAbort).unwrap();f.state.lock().unwrap().fail_exit=1;
    assert!(f.svc.handle(&owner(),IfcRequest::Wipe).unwrap_err().is("FIXTURE_EXIT_FAILED"));assert!(f.svc.payload_for_test(&h).is_err());
    f.svc.handle(&owner(),IfcRequest::Wipe).unwrap();assert!(f.state.lock().unwrap().sessions.is_empty());
    match f.svc.handle(&owner(),IfcRequest::Status).unwrap(){IfcResponse::Status(s)=>assert!(s.state.contains("ssm_cleanup_pending=false")),_=>panic!()}
    assert!(f.svc.handle(&owner(),IfcRequest::BeginTurn {turn:UserTurnV1 {directive_short:"quarantine cannot be reset by wipe".into(),attachments:vec![]},attachments:vec![],tools:vec![],holder_pk:None,budget_mb:0}).unwrap_err().is("FLOW_FSM_INVALID_TRANSITION"));
}
