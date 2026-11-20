//! F65: actual authenticated plan execution, never caller-selected labels or
//! an evaluator callback that bypasses the live authorization/accounting path.
use std::sync::{Arc,Mutex,atomic::{AtomicBool,Ordering}};
use std::time::{Duration,Instant};
use ed25519_dalek::SigningKey;
use enclave_agent_runtime::cedar_engine::CedarEngine;
use enclave_agent_runtime::plan::dispatch::{AuthorizedToolCall,ToolDispatchOutput,ToolDispatchPort};
use enclave_agent_runtime::registry::{ToolRegistry,digest_tools_list};
use enclave_agent_runtime::service::{CustodyPort,Declassifier,IfcConfig,IfcRequest,IfcResponse,IfcService,IntentLifetimeV1,StepUp};
use enclave_core::error::EnclaveResult;
use enclave_core::ifc_envelope::IfcEnvelopeV1;
use enclave_core::intent_draft::IntentDraftV1;
use enclave_core::ipc::PeerCredentials;
use enclave_core::label::{Conf,Taint};
use enclave_core::profile::Profile;
use enclave_core::user_turn::UserTurnV1;
use enclave_crypto::pop_biscuit::spec_limits;
use serde_json::{json,Value};

#[derive(Debug)] struct NoDeclass;
impl Declassifier for NoDeclass {
    fn classify(&self,_:&[u8],_:u64,_:&str,_:&enclave_core::seq::GovernedSlot)->EnclaveResult<u64> {unreachable!()}
}
#[derive(Debug,Default)] struct Vault {next:Mutex<u64>,drafts:Mutex<Vec<IntentDraftV1>>,scrubs:Mutex<usize>,lifetime:Mutex<Option<IntentLifetimeV1>>,delay_slot:AtomicBool}
#[derive(Debug)] struct VaultPort(Arc<Vault>);
impl CustodyPort for VaultPort {
    fn scrub_text(&self,text:&str,_:bool)->EnclaveResult<String> {
        *self.0.scrubs.lock().unwrap()+=1;
        Ok(enclave_core::pii::scan(text).iter().fold(text.to_owned(),|out,span|out.replace(&text[span.start..span.end],"[REDACTED_PAN_C4]")))
    }
    fn authorize_intent(&self,draft:&IntentDraftV1)->EnclaveResult<StepUp> {
        self.0.drafts.lock().unwrap().push(draft.clone());
        // Trusted software fixture only; actual native custody is tested separately.
        let lifetime=(*self.0.lifetime.lock().unwrap()).unwrap_or(IntentLifetimeV1 {
            v:1,valid_until_unix:None,
            deadline_boot_ns:Some(enclave_core::clock::boot_clock_ns()+10_000_000_000),
        });
        *self.0.lifetime.lock().unwrap()=Some(lifetime);
        Ok(StepUp {d_jcs:"ab".repeat(32),factors:vec!["TouchIdCoreauthui".into(),"YubikeyUp".into()],lifetime})
    }
    fn allocate_slot(&self)->EnclaveResult<(String,u64)> {
        if self.0.delay_slot.load(Ordering::SeqCst) {
            let deadline=self.0.lifetime.lock().unwrap().unwrap().deadline_boot_ns.unwrap();
            while enclave_core::clock::boot_clock_ns()<deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        let mut next=self.0.next.lock().unwrap();*next+=1;Ok(("6f1c2c1e-3a54-4b8e-9d7a-0c4f5b6a7e81".into(),*next))
    }
    fn boot_epoch(&self)->EnclaveResult<enclave_core::seq::BootEpoch> {unreachable!()}
}
fn tools_list()->Value {json!({"tools":[{"name":"read"},{"name":"export"},{"name":"narrow"}]})}
fn registry(qif:i64)->ToolRegistry {
    ToolRegistry::load(&serde_json::to_vec(&json!({"v":1,"servers":[{"server":"fixture",
        "tools_list_blake3":digest_tools_list(&tools_list()).unwrap(),"tools":[
            {"name":"read","action_class":"A1","sink_clearance":"C3","namespace":"dev-billing","canonical_verb":"Select",
             "slots":{"where_value":"BOUND_LITERAL"},"row_count_arg":"limit","max_rows":25,"qif_mb_per_call":qif,
             "output_conf":"C2","entity_key_fields":["customer_id"]},
            {"name":"export","action_class":"A3","sink_clearance":"C3","namespace":"dev-billing","canonical_verb":"Export",
             "slots":{"where_value":"BOUND_LITERAL"},"qif_mb_per_call":qif,"output_conf":"C2","entity_key_fields":["customer_id"]},
            {"name":"narrow","action_class":"A1","sink_clearance":"C1","namespace":"dev-billing","canonical_verb":"Select",
             "slots":{"where_value":"BOUND_LITERAL"},"output_conf":"C1"}
        ]}]})).unwrap()).unwrap()
}
#[derive(Debug,Default)] struct PortState {
    calls:Mutex<Vec<(String,Value,[u8;32],[u8;32],u64)>>,
    expiries:Mutex<Vec<Option<enclave_tool_host::lifecycle::DispatchExpiry>>>,
    output:Mutex<Option<Vec<u8>>>, fail:AtomicBool, wrong_pin:AtomicBool,
    block:AtomicBool, entered:AtomicBool, cancelled:AtomicBool,
    policy_refresh:Mutex<Option<(std::sync::Weak<IfcService>,Vec<u8>)>>,
    signed_policy_refresh:Mutex<Option<SignedPolicyRefresh>>,
}
#[derive(Debug)] struct Port(Arc<PortState>);
impl ToolDispatchPort for Port {
    fn execute(&self,call:AuthorizedToolCall,cancel:&AtomicBool)->EnclaveResult<ToolDispatchOutput> {
        self.0.expiries.lock().unwrap().push(call.dispatch_expiry().copied());
        self.0.calls.lock().unwrap().push((call.tool_name().into(),serde_json::from_slice(call.args_jcs()).unwrap(),
            *call.authorization_id(),*call.plan_blake3(),call.row_bound()));
        self.0.entered.store(true,Ordering::SeqCst);
        if let Some((service,policy))=self.0.policy_refresh.lock().unwrap().take() {
            service.upgrade().unwrap().handle(&owner(),IfcRequest::RefreshPolicy {bundle_json:Some(policy.into())}).unwrap();
        }
        if let Some(transition)=self.0.signed_policy_refresh.lock().unwrap().take() {
            transition.apply();
        }
        if self.0.block.load(Ordering::SeqCst) {
            let until=Instant::now()+Duration::from_secs(10);
            while !cancel.load(Ordering::SeqCst) && Instant::now()<until {std::thread::sleep(Duration::from_millis(2));}
            self.0.cancelled.store(cancel.load(Ordering::SeqCst),Ordering::SeqCst);
            assert!(cancel.load(Ordering::SeqCst),"test did not observe Finish/Wipe cancellation");
            // Deliberately return a late successful response; runtime must fence it.
        }
        if self.0.fail.load(Ordering::SeqCst) {
            return Err(enclave_core::err!(EIO,"UNTRUSTED_PORT_FAILURE","raw-confidential-output"));
        }
        Ok(ToolDispatchOutput {
            payload:self.0.output.lock().unwrap().clone().unwrap_or_else(||br#"{"customer_id":"c1","message":"from_tool"}"#.to_vec()),
            tools_list:if self.0.wrong_pin.load(Ordering::SeqCst) {r#"{"tools":[{"name":"changed"}]}"#.into()} else {tools_list().to_string()},
        })
    }
}
fn service(qif:i64,state:Arc<PortState>)->(Arc<IfcService>,Arc<Vault>) {
    service_profile(qif,state,Profile::L2)
}
fn service_profile(qif:i64,state:Arc<PortState>,profile:Profile)->(Arc<IfcService>,Arc<Vault>) {
    service_policy(qif,state,profile,CedarEngine::baseline_bundle().unwrap(),None)
}
fn service_policy(qif:i64,state:Arc<PortState>,profile:Profile,cedar:CedarEngine,socket_dir:Option<std::path::PathBuf>)->(Arc<IfcService>,Arc<Vault>) {
    service_policy_with_audit(qif,state,profile,cedar,socket_dir,None)
}
fn service_policy_with_audit(qif:i64,state:Arc<PortState>,profile:Profile,cedar:CedarEngine,socket_dir:Option<std::path::PathBuf>,audit_path:Option<std::path::PathBuf>)->(Arc<IfcService>,Arc<Vault>) {
    let vault=Arc::new(Vault::default());
    let cfg=IfcConfig {profile,audit_path,policy_key:SigningKey::generate(&mut rand_core::OsRng),
        limits:enclave_crypto::biscuit_auth::AuthorizerLimits {max_time:Duration::from_millis(100),..spec_limits()},
        registry:registry(qif),cedar:Some(cedar),state_dir:None,socket_dir,dev_same_uid:true};
    let svc=IfcService::start_with_dispatch(cfg,Box::new(NoDeclass),Box::new(VaultPort(vault.clone())),
        Box::new(enclave_agent_runtime::ssm::NoSsm),Box::new(Port(state))).unwrap();(svc,vault)
}
fn owner()->PeerCredentials {let mut p=PeerCredentials::local(enclave_core::ipc::geteuid(),0);p.pid=Some(4242);p}
fn begin(s:&IfcService,tools:&[&str],budget:i64,external:bool)->String {
    let response=s.handle(&owner(),IfcRequest::BeginTurn {turn:UserTurnV1 {directive_short:"fixture execution".into(),attachments:vec![]},
        attachments:vec![],tools:tools.iter().map(|tool|enclave_agent_runtime::turn::ToolSignature {
            name:format!("mcp://fixture/{tool}"),description:String::new(),params:vec![]}).collect(),
        holder_pk:external.then(||SigningKey::generate(&mut rand_core::OsRng).verifying_key().to_bytes()),budget_mb:budget}).unwrap();
    let IfcResponse::TurnPlan {turn_id,root_token,..}=response else {panic!("{response:?}")};
    assert_eq!(root_token.is_some(),external);turn_id
}
fn execute(s:&IfcService,id:&str,source:&str,handles:Vec<(String,String)>,step_up:bool)->EnclaveResult<IfcResponse> {
    s.handle(&owner(),request(id,source,handles,step_up))
}
fn request(id:&str,source:&str,initial_handles:Vec<(String,String)>,step_up:bool)->IfcRequest {
    IfcRequest::ExecuteTurnPlan {turn_id:id.into(),source:source.into(),initial_handles,fuel_budget:10_000,step_up}
}
fn ingress(s:&IfcService,id:&str,payload:&str,hint:Conf)->IfcEnvelopeV1 {
    let r=s.handle(&owner(),IfcRequest::IngestTurnToolOutput {turn_id:id.into(),server:"fixture".into(),tool_name:"read".into(),
        tools_list:tools_list().to_string(),payload:payload.as_bytes().to_vec().into(),conf_hint:Some(hint),source_uri:"mcp://fixture/read".into()}).unwrap();
    let IfcResponse::Handle(env)=r else {panic!("{r:?}")};env
}
const READ:&str=r#"tool_call("fixture", "read", {"limit": 1, "where_value": "hello"})"#;

// A real CAS service and real threshold-signed TUF target, not the lightweight
// fake-CAS policy stand-in retained in the older controlled-swap regression.
struct SignedPolicyRefresh {
    service:std::sync::Weak<IfcService>,
    cas:Arc<enclave_swarm_syncd::service::CasService>,
    metadata:(Vec<u8>,Vec<u8>,Vec<u8>),
    policy:Vec<u8>,
    path:std::path::PathBuf,
    applied:Arc<std::sync::atomic::AtomicUsize>,
}
impl std::fmt::Debug for SignedPolicyRefresh {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.write_str("SignedPolicyRefresh")}
}
impl SignedPolicyRefresh {
    fn apply(self) {
        use enclave_swarm_syncd::service::{CasRequest,CasResponse};
        let (timestamp,snapshot,targets)=self.metadata;
        let response=self.cas.handle(&owner(),CasRequest::TufRefresh {roots:vec![],
            timestamp:timestamp.into(),snapshot:snapshot.into(),targets:targets.into()}).unwrap();
        assert!(matches!(response,CasResponse::Tuf {versions:(2,2,2)}));
        // Provisioned generic policy payloads are verified by the production
        // FetchTarget reader against the newly accepted TUF target metadata.
        enclave_core::fsutil::write_private(&self.path,&self.policy).unwrap();
        let response=self.service.upgrade().unwrap().handle(&owner(),
            IfcRequest::RefreshPolicy {bundle_json:None}).unwrap();
        assert!(matches!(response,IfcResponse::Ok));
        assert_eq!(self.applied.fetch_add(1,Ordering::SeqCst),0);
    }
}
struct SignedCasFixture {
    base:std::path::PathBuf,
    socket_dir:std::path::PathBuf,
    cas:Arc<enclave_swarm_syncd::service::CasService>,
    stop:Arc<AtomicBool>,
    worker:Option<std::thread::JoinHandle<EnclaveResult<()>>>,
}
impl SignedCasFixture {
    fn new(root:Vec<u8>)->Self {
        use enclave_core::ipc::{PeerPolicy,SocketAccess};
        use enclave_swarm_syncd::service::{CasConfig,CasRequest,CasResponse,CasService};
        use std::os::unix::fs::DirBuilderExt;
        // Fixed canonical short private roots keep the real Darwin UDS path
        // below SUN_LEN. This owns no host daemon or existing socket.
        let parent=if cfg!(target_os="macos") {"/private/tmp"} else {"/tmp"};
        let base=std::path::PathBuf::from(parent).join(format!("p7t-{:x}",enclave_core::rng::u64()));
        std::fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        let socket_dir=base.join("r");
        let suffix=enclave_core::daemon::DaemonId::SwarmSync.dir_name();
        let socket=socket_dir.join(suffix).join(format!("{suffix}.sock"));
        enclave_core::fsutil::private_dir(socket.parent().unwrap()).unwrap();
        let listener=enclave_core::ipc::bind(&socket,SocketAccess::OwnerOnly).unwrap();
        let cas=CasService::start(CasConfig {dev_same_uid:true,profile:Profile::L2,
            store_dir:base.join("store"),audit_path:Some(base.join("cas-audit.jsonl")),
            ohttp_gateway:None,tuf_root:Some(root),state_dir:None,
            revocation:enclave_swarm_syncd::revocation::Enforcement::InProcess}).unwrap();
        let stop=Arc::new(AtomicBool::new(false));let end=stop.clone();let service=cas.clone();
        let worker=std::thread::spawn(move||enclave_core::ipc::serve::<CasRequest,CasResponse,_>(listener,
            PeerPolicy::allow([enclave_core::ipc::geteuid()]),
            Arc::new(move|peer:&PeerCredentials,request|service.handle(peer,request)),end));
        Self {base,socket_dir,cas,stop,worker:Some(worker)}
    }
    fn finish(&mut self) {
        self.stop.store(true,Ordering::SeqCst);
        self.worker.take().unwrap().join().unwrap().unwrap();
    }
}
impl Drop for SignedCasFixture {
    fn drop(&mut self) {
        self.stop.store(true,Ordering::SeqCst);
        if let Some(worker)=self.worker.take() {
            if !matches!(worker.join(),Ok(Ok(()))) {eprintln!("SIGNED_CAS_FIXTURE_FAILED_DURING_TEARDOWN");}
        }
        let _=std::fs::remove_dir_all(&self.base);
    }
}
fn signed_policy_metadata(repo:&enclave_crypto::tuf::RepoBuilder,version:u64,bytes:&[u8])->(Vec<u8>,Vec<u8>,Vec<u8>) {
    use enclave_agent_runtime::cedar_engine::CEDAR_BUNDLE_TARGET;
    const EXP:&str="2030-01-01T00:00:00Z";
    let targets=repo.targets(version,EXP,[(CEDAR_BUNDLE_TARGET.into(),
        enclave_crypto::tuf::target_file(bytes,None))].into_iter().collect()).unwrap();
    let snapshot=repo.snapshot(version,EXP,version,&targets).unwrap();
    let timestamp=repo.timestamp(version,EXP,version,&snapshot).unwrap();
    (timestamp,snapshot,targets)
}

#[test]
#[cfg(not(feature="simulation"))]
fn rd07_actual_signed_tuf_refresh_between_dispatches_denies_both_reached_branches_and_preserves_progress() {
    use enclave_agent_runtime::cedar_engine::{CedarBundle,BASELINE_POLICIES,DEFAULT_SCHEMA,CEDAR_BUNDLE_TARGET};
    use enclave_swarm_syncd::service::{CasRequest,CasResponse};
    const NARROW:&str=r#"tool_call("fixture", "narrow", {"where_value": "hello"})"#;
    for taken_then in [true,false] {
        let repo=enclave_crypto::tuf::RepoBuilder::new(3,2);
        let baseline=CedarBundle::baseline().to_json_bytes().unwrap();
        let strict=CedarBundle::new(DEFAULT_SCHEMA,format!("{BASELINE_POLICIES}\nforbid (principal, action, resource == MCPMac::Tool::\"mcp://fixture/read\");")).to_json_bytes().unwrap();
        let first_metadata=signed_policy_metadata(&repo,1,&baseline);
        let next_metadata=signed_policy_metadata(&repo,2,&strict);
        let mut cas=SignedCasFixture::new(repo.root("2030-01-01T00:00:00Z").unwrap());
        let path=cas.base.join("store").join(CEDAR_BUNDLE_TARGET);
        enclave_core::fsutil::write_private(&path,&baseline).unwrap();
        let (timestamp,snapshot,targets)=first_metadata.clone();
        assert!(matches!(cas.cas.handle(&owner(),CasRequest::TufRefresh {roots:vec![],
            timestamp:timestamp.into(),snapshot:snapshot.into(),targets:targets.into()}).unwrap(),
            CasResponse::Tuf {versions:(1,1,1)}));
        let port=Arc::new(PortState::default());let audit=cas.base.join("ifc-audit.jsonl");
        let baseline_engine=CedarEngine::baseline_bundle().unwrap();let baseline_digest=hex::encode(baseline_engine.bundle_blake3());
        let strict_digest=hex::encode(CedarEngine::from_bundle(&CedarBundle::from_json_bytes(&strict).unwrap()).unwrap().bundle_blake3());
        let (service,_)=service_policy_with_audit(0,port.clone(),Profile::L2,baseline_engine,
            Some(cas.socket_dir.clone()),Some(audit.clone()));
        // Load baseline through the actual same-UID IPC/TUF production path
        // before preflight, too. This is not installed UID/code-pin acceptance.
        assert!(matches!(service.handle(&owner(),IfcRequest::RefreshPolicy {bundle_json:None}).unwrap(),IfcResponse::Ok));
        let id=begin(&service,&["read","narrow"],12_000,false);
        let applied=Arc::new(std::sync::atomic::AtomicUsize::new(0));
        *port.signed_policy_refresh.lock().unwrap()=Some(SignedPolicyRefresh {service:Arc::downgrade(&service),
            cas:cas.cas.clone(),metadata:next_metadata,policy:strict.clone(),path,applied:applied.clone()});
        // Keep this policy-transition oracle in the C1 exposure domain. A
        // successful read would permanently raise this daemon's literal floor
        // to C2, correctly denying the unrelated C1 narrow sink even in a new
        // turn. The initial narrow dispatch still triggers the real signed
        // refresh; either reached read must then fail under the new policy.
        let source=format!("{NARROW}\nif {}:\n    {}\nelse:\n    {}",
            if taken_then {"True"} else {"False"},if taken_then {READ} else {NARROW},if taken_then {NARROW} else {READ});
        let error=execute(&service,&id,&source,vec![],false).unwrap_err();
        assert!(error.is("PLAN_TOOL_DENIED"),"{error}");
        assert!(error.detail.contains("dispatched_tool_calls=1"));
        assert!(error.detail.contains("do not retry automatically"));
        assert_eq!(port.calls.lock().unwrap().len(),1);
        assert_eq!(port.calls.lock().unwrap()[0].0,"narrow");
        assert_eq!(port.calls.lock().unwrap()[0].1,json!({"where_value":"hello"}));
        assert_eq!(applied.load(Ordering::SeqCst),1);
        assert!(port.signed_policy_refresh.lock().unwrap().is_none());
        let rows:Vec<Value>=std::fs::read_to_string(&audit).unwrap().lines().map(|line|serde_json::from_str(line).unwrap()).collect();
        let plan=rows.iter().find(|row|row["payload"]["event"]=="TURN_PLAN_EXECUTION").unwrap();
        assert_eq!(plan["payload"]["plan_blake3"],blake3::hash(source.as_bytes()).to_hex().to_string());
        assert_eq!(plan["payload"]["precheck_policy_blake3"],baseline_digest);
        assert_eq!(plan["payload"]["prechecked"],true);
        assert_eq!(plan["payload"]["executed_tool_calls"],1);assert_eq!(plan["payload"]["success"],false);
        let swaps:Vec<_>=rows.iter().filter(|row|row["payload"]["event"]=="POLICY_BUNDLE_HOTSWAP").collect();
        assert_eq!(swaps.len(),2);assert_eq!(swaps[0]["payload"]["policy_bundle_blake3"],baseline_digest);
        assert_eq!(swaps[1]["payload"]["policy_bundle_blake3"],strict_digest);
        assert!(swaps.iter().all(|row|row["payload"]["provenance"]=="tuf_signed"));
        // The old inline bundle may not bypass the currently served signed
        // target; rejected TUF replay may not roll the CAS target back either.
        let inline_error=service.handle(&owner(),IfcRequest::RefreshPolicy {bundle_json:Some(baseline.into())}).unwrap_err();
        assert!(inline_error.is("POLICY_INLINE_UNSIGNED"),"{inline_error}");
        assert!(inline_error.detail.contains("differs from the signed target"),"{inline_error}");
        let (timestamp,snapshot,targets)=first_metadata;
        assert!(cas.cas.handle(&owner(),CasRequest::TufRefresh {roots:vec![],timestamp:timestamp.into(),
            snapshot:snapshot.into(),targets:targets.into()}).unwrap_err().is("TUF_ROLLBACK"));
        assert_eq!(enclave_core::host_config::fetch_tuf_target(&cas.socket_dir,CEDAR_BUNDLE_TARGET,true).unwrap(),strict);
        let dead_id=begin(&service,&["read","narrow"],12_000,false);
        let dead=format!("{NARROW}\nif False:\n    {READ}");
        let dead_error=execute(&service,&dead_id,&dead,vec![],false).unwrap_err();
        assert!(dead_error.is("ERR_IFC_STATIC_CEDAR_DENIED"),"{dead_error}");
        assert_eq!(port.calls.lock().unwrap().len(),1,"new dead denied site must block the earlier allowed effect");
        let allowed_id=begin(&service,&["narrow"],12_000,false);
        assert!(matches!(execute(&service,&allowed_id,NARROW,vec![],false).unwrap(),
            IfcResponse::PlanExecuted {executed_tool_calls:1,..}));
        assert_eq!(port.calls.lock().unwrap().len(),2);
        assert_eq!(port.calls.lock().unwrap()[1].0,"narrow");
        assert_eq!(port.calls.lock().unwrap()[1].1,json!({"where_value":"hello"}));
        enclave_core::audit::verify_journal(&audit,None).unwrap();
        enclave_core::audit::verify_journal(&cas.base.join("cas-audit.jsonl"),None).unwrap();
        drop(service);cas.finish();
    }
}

#[test]
fn reached_tools_use_exact_materialized_bytes_and_refs_chain_with_provenance() {
    let port=Arc::new(PortState::default());let (s,_)=service(0,port.clone());
    let id=begin(&s,&["read"],12_000,false);
    let input=ingress(&s,&id,r#"{"customer_id":"source","secret":"private"}"#,Conf::C3);
    let source=r#"first = tool_call("fixture", "read", {"limit": 1, "where_value": [{"nested": seed}]})
second = tool_call("fixture", "read", {"limit": 1, "where_value": first})
second"#;
    let response=execute(&s,&id,source,vec![("seed".into(),input.handle.clone())],false).unwrap();
    let IfcResponse::PlanExecuted {return_value,executed_tool_calls,output_refs}=response else {panic!("{response:?}")};
    assert_eq!(executed_tool_calls,2);assert_eq!(output_refs.len(),2);
    let IfcResponse::PolicySli(telemetry)=s.handle(&owner(),IfcRequest::PolicySli).unwrap() else {unreachable!()};
    assert_eq!((telemetry.observed_total,telemetry.observed_errors),(2,0),"count actual reached PDP calls, not AST prechecks");
    assert!(return_value.starts_with("Ref("));assert!(!return_value.contains("from_tool"));assert!(!return_value.contains("private"));
    let calls=port.calls.lock().unwrap();
    assert_eq!(calls[0].1,json!({"limit":1,"where_value":[{"nested":{"customer_id":"source","secret":"private"}}]}));
    assert_eq!(calls[1].1,json!({"limit":1,"where_value":{"customer_id":"c1","message":"from_tool"}}));
    assert_ne!(calls[0].2,calls[1].2);assert_eq!(calls[0].3,*blake3::hash(source.as_bytes()).as_bytes());assert_eq!(calls[0].4,1);
    for out in &output_refs {assert_eq!(out.label.c,Conf::C3);assert_eq!(out.label.t,Taint::T3);assert!(out.enclave_boot_mac.is_some());}
    assert_eq!(output_refs[0].provenance_parents.as_ref().unwrap(),&vec![input.handle]);
    assert_eq!(output_refs[1].provenance_parents.as_ref().unwrap(),&vec![output_refs[0].handle.clone()]);
    for key in &input.entity_keys {assert!(output_refs[0].entity_keys.contains(key));assert!(output_refs[1].entity_keys.contains(key));}
    assert_eq!(output_refs[0].origin.tool_name.as_deref(),Some("mcp://fixture/read"));
}

#[test]
fn repeated_plans_share_exact_tool_scope_budget_and_call_allotment() {
    let port=Arc::new(PortState::default());let (s,_)=service(10,port.clone());let id=begin(&s,&["read"],20,false);
    execute(&s,&id,READ,vec![],false).unwrap();execute(&s,&id,READ,vec![],false).unwrap();
    assert!(execute(&s,&id,READ,vec![],false).is_err());assert_eq!(port.calls.lock().unwrap().len(),2);
    let port=Arc::new(PortState::default());let (s,_)=service(0,port.clone());let id=begin(&s,&["read"],0,false);
    for _ in 0..64 {execute(&s,&id,READ,vec![],false).unwrap();}
    assert!(execute(&s,&id,READ,vec![],false).is_err());assert_eq!(port.calls.lock().unwrap().len(),64);
}

#[test]
fn pdp_denials_and_invalid_rows_never_reach_transport() {
    let port=Arc::new(PortState::default());let (s,vault)=service(0,port.clone());let id=begin(&s,&["read","export","narrow"],12_000,false);
    for source in [r#"tool_call("fixture","missing",{})"#,r#"tool_call("fixture","read",{"limit":26})"#,
        r#"tool_call("fixture","export",{"where_value":"x"})"#] {
        assert!(execute(&s,&id,source,vec![],false).is_err(),"{source}");
    }
    let input=ingress(&s,&id,"private",Conf::C3);
    assert!(execute(&s,&id,r#"tool_call("fixture","narrow",{"where_value":seed})"#,vec![("seed".into(),input.handle.clone())],false).is_err());
    // Unknown structural slot must retain nested Ref taint.
    assert!(execute(&s,&id,r#"tool_call("fixture","read",{"limit":1,"query":{"nested":seed}})"#,vec![("seed".into(),input.handle)],false).is_err());
    assert!(port.calls.lock().unwrap().is_empty());assert!(vault.drafts.lock().unwrap().is_empty());
    // A granted target omitted from the private root still cannot execute.
    let other=begin(&s,&[],12_000,false);assert!(execute(&s,&other,READ,vec![],false).is_err());
    assert!(port.calls.lock().unwrap().is_empty());
}

#[test]
fn real_stepup_allows_a3_without_fixed_false_static_veto() {
    let port=Arc::new(PortState::default());let (s,vault)=service(0,port.clone());let id=begin(&s,&["export"],12_000,false);
    let source=r#"tool_call("fixture","export",{"where_value":"x"})"#;
    assert!(execute(&s,&id,source,vec![],false).is_err());
    execute(&s,&id,source,vec![],true).unwrap();assert_eq!(port.calls.lock().unwrap().len(),1);
    let expiry=port.expiries.lock().unwrap()[0].expect("received bounds reach actual port");
    assert_eq!(Some(expiry.boot_deadline_ns()),vault.lifetime.lock().unwrap().unwrap().deadline_boot_ns);
    let drafts=vault.drafts.lock().unwrap();assert_eq!(drafts.len(),1);
    let args=enclave_core::jcs::canonicalize(&json!({"where_value":"x"})).unwrap();
    assert_eq!(drafts[0].canonical_arguments_blake3,blake3::hash(&args).to_hex().to_string());
}

#[test]
fn owner_turn_and_typed_ref_boundaries_are_enforced() {
    let port=Arc::new(PortState::default());let (s,_)=service(0,port.clone());let id=begin(&s,&["read"],12_000,false);
    let input=ingress(&s,&id,"secret",Conf::C3);let other=begin(&s,&["read"],12_000,false);
    let mut intruder=owner();intruder.pid=Some(9999);
    assert!(s.handle(&intruder,request(&id,READ,vec![],false)).unwrap_err().is("TURN_OWNER_REJECTED"));
    assert!(execute(&s,&other,READ,vec![("seed".into(),input.handle.clone())],false).is_err());
    assert!(execute(&s,&id,READ,vec![("seed".into(),"$v_absent".into())],false).is_err());
    assert!(execute(&s,&id,r#"make_ref("$v_0","C1","T0")"#,vec![],false).is_err());
    assert!(execute(&s,&id,r#"Ref("$v_0","C1","T0")"#,vec![],false).is_err());
    assert!(port.calls.lock().unwrap().is_empty());
    let source=format!("tool_call(\"fixture\",\"read\",{{\"limit\":1,\"where_value\":{:?}}})",input.handle);
    execute(&s,&id,&source,vec![],false).unwrap();
    assert_eq!(port.calls.lock().unwrap()[0].1["where_value"],input.handle);
    let external=begin(&s,&["read"],12_000,true);
    assert!(execute(&s,&external,READ,vec![],false).unwrap_err().is("PLAN_EXTERNAL_HOLDER_UNSUPPORTED"));
}

#[test]
fn source_arguments_fuel_outputs_and_pins_are_bounded() {
    let port=Arc::new(PortState::default());let (s,_)=service(0,port.clone());let id=begin(&s,&["read"],12_000,false);
    assert!(execute(&s,&id,&"x".repeat(65537),vec![],false).is_err());
    for fuel in [0,10_001] {
        let mut req=request(&id,READ,vec![],false);if let IfcRequest::ExecuteTurnPlan {fuel_budget,..}=&mut req {*fuel_budget=fuel;}
        assert!(s.handle(&owner(),req).is_err());
    }
    assert!(execute(&s,&id,r#"tool_call("fixture","read",{"limit":1,"where_value":"x" * 70000})"#,vec![],false).is_err());
    assert!(port.calls.lock().unwrap().is_empty());
    port.wrong_pin.store(true,Ordering::SeqCst);assert!(execute(&s,&id,READ,vec![],false).is_err());
    assert!(s.handle(&owner(),IfcRequest::Status).is_ok());
    port.wrong_pin.store(false,Ordering::SeqCst);*port.output.lock().unwrap()=Some(vec![b'x';250*1024+1]);
    assert!(execute(&s,&id,READ,vec![],false).unwrap_err().is("PLAN_TOOL_OUTPUT_BOUNDS"));
}

#[test]
fn transport_errors_never_expose_payload_and_c4_outputs_are_scrubbed() {
    let port=Arc::new(PortState::default());let (s,vault)=service(0,port.clone());let id=begin(&s,&["read"],12_000,false);
    port.fail.store(true,Ordering::SeqCst);let error=execute(&s,&id,READ,vec![],false).unwrap_err();
    assert!(error.is("PLAN_TOOL_TRANSPORT_FAILED"));assert!(!error.to_string().contains("raw-confidential-output"));
    assert_eq!(error.detail,"dispatched_tool_calls=1; prior effects may exist; do not retry automatically");
    port.fail.store(false,Ordering::SeqCst);*port.output.lock().unwrap()=Some(b"PAN 4111 1111 1111 1111".to_vec());
    let IfcResponse::PlanExecuted {output_refs,..}=execute(&s,&id,READ,vec![],false).unwrap() else {panic!()};
    assert_eq!(*vault.scrubs.lock().unwrap(),1);assert_eq!(output_refs[0].label.c,Conf::C4);
    assert!(!String::from_utf8(s.payload_for_test(&output_refs[0].handle).unwrap()).unwrap().contains("4111"));
}

fn cancellation_case(wipe:bool) {
    let port=Arc::new(PortState::default());port.block.store(true,Ordering::SeqCst);
    let (s,_)=service(0,port.clone());let id=begin(&s,&["read"],12_000,false);
    let ingress=ingress(&s,&id,"input",Conf::C3);
    let work=s.clone();let tid=id.clone();let running=std::thread::spawn(move||execute(&work,&tid,READ,vec![],false));
    let until=Instant::now()+Duration::from_secs(5);
    while !port.entered.load(Ordering::SeqCst) && Instant::now()<until {std::thread::sleep(Duration::from_millis(2));}
    assert!(port.entered.load(Ordering::SeqCst));
    assert!(execute(&s,&id,READ,vec![],false).unwrap_err().is("PLAN_TURN_BUSY"));
    // Status is responsive while native transport is blocked.
    assert!(s.handle(&owner(),IfcRequest::Status).is_ok());
    let response=s.handle(&owner(),if wipe {IfcRequest::Wipe} else {IfcRequest::FinishTurn {turn_id:id.clone(),cancelled:true}}).unwrap();
    assert!(matches!(response,IfcResponse::Ok|IfcResponse::TurnFinished {..}));
    let error=running.join().unwrap().unwrap_err();
    assert!(error.detail.contains("dispatched_tool_calls=1"));
    assert!(error.detail.contains("do not retry automatically"));
    assert!(port.cancelled.load(Ordering::SeqCst));
    assert!(s.payload_for_test(&ingress.handle).is_err());
    assert!(execute(&s,&id,READ,vec![],false).is_err());
    let IfcResponse::Status(status)=s.handle(&owner(),IfcRequest::Status).unwrap() else {panic!()};assert!(status.state.contains("handles=0"));
}
#[test] fn finish_cancels_and_fences_late_tool_output() {cancellation_case(false);}
#[test] fn wipe_erases_locally_and_fences_late_tool_output() {cancellation_case(true);}

#[test]
fn l3_native_failures_have_only_sealed_abort() {
    let port=Arc::new(PortState::default());let (s,_)=service_profile(0,port.clone(),Profile::L3);let id=begin(&s,&["read"],12_000,false);
    assert!(execute(&s,&id,r#"tool_call("fixture","missing",{})"#,vec![],false).unwrap_err().is("ERR_IFC_SEALED_ABORT"));
    assert!(port.calls.lock().unwrap().is_empty());
}

#[test]
fn unconfigured_transport_fails_closed_and_unreached_sites_do_not_dispatch() {
    let vault=Arc::new(Vault::default());
    let cfg=IfcConfig {profile:Profile::L2,audit_path:None,policy_key:SigningKey::generate(&mut rand_core::OsRng),
        limits:enclave_crypto::biscuit_auth::AuthorizerLimits {max_time:Duration::from_millis(100),..spec_limits()},
        registry:registry(0),cedar:Some(CedarEngine::baseline_bundle().unwrap()),state_dir:None,socket_dir:None,dev_same_uid:true};
    let s=IfcService::start(cfg,Box::new(NoDeclass),Box::new(VaultPort(vault))).unwrap();
    let id=begin(&s,&["read"],12_000,false);
    assert!(execute(&s,&id,READ,vec![],false).unwrap_err().is("PLAN_TOOL_TRANSPORT_FAILED"));
    let source="if False:\n    tool_call(\"fixture\", \"read\", {\"limit\":1})\n42";
    let IfcResponse::PlanExecuted {return_value,executed_tool_calls,output_refs}=execute(&s,&id,source,vec![],false).unwrap() else {panic!()};
    assert_eq!(return_value,"42");assert_eq!(executed_tool_calls,0);assert!(output_refs.is_empty());
}

#[test]
fn live_subset_rejects_native_growth_before_evaluation() {
    let port=Arc::new(PortState::default());let (s,_)=service(0,port.clone());let id=begin(&s,&["read"],12_000,false);
    // These hazardous expressions must be rejected on the AST. No test relies
    // on actually allocating their requested strings/lists/ranges.
    for source in [r#""x" * 1000000000"#,r#"[0] * 1000000000"#,r#""x" + "y""#,
        r#""%1000000000s" % "x""#,r#""{:1000000000}".format("x")"#,r#"str([1,2,3])"#,
        "list(range(1000000000))", "for i in range(1000000000):\n    pass", "x = 1 << 1000000000",
        "x = []\nx.append(x)", "x = []\nx == x", "def f():\n    return f()\nf()"] {
        let error=execute(&s,&id,source,vec![],false).unwrap_err();
        assert!(error.is("PLAN_LIVE_SYNTAX_UNSUPPORTED") || error.is("PLAN_LIVE_LOOP_BOUND"),"{source}: {error}");
    }
    assert!(port.calls.lock().unwrap().is_empty());
}

#[test]
fn bounded_live_loops_boolean_conditions_and_scalar_comparisons_work() {
    let port=Arc::new(PortState::default());let (s,_)=service(0,port.clone());let id=begin(&s,&["read"],12_000,false);
    let source=r#"enabled = True
for i in range(3):
    if enabled and i < 2:
        last = tool_call("fixture", "read", {"limit":1,"where_value":[i, {"flag":enabled}]})
last"#;
    let IfcResponse::PlanExecuted {executed_tool_calls,..}=execute(&s,&id,source,vec![],false).unwrap() else {panic!()};
    assert_eq!(executed_tool_calls,2);assert_eq!(port.calls.lock().unwrap().len(),2);
    // Whole-plan scalar inference rejects aliases that can hold containers,
    // even when the container write sits in a different branch or loop body.
    for source in ["a = []\nb = a\nb == b", "a = 1\nif False:\n    a = []\na == a",
        "for i in range(2):\n    i = []\n    i == i"] {
        assert!(execute(&s,&id,source,vec![],false).unwrap_err().is("PLAN_LIVE_SYNTAX_UNSUPPORTED"));
    }
}

#[test]
fn live_return_never_recursively_formats_container_aliases() {
    let port=Arc::new(PortState::default());let (s,_)=service(0,port.clone());let id=begin(&s,&[],0,false);
    let source="x = [0]\nfor i in range(16):\n    x = [x,x]\nx";
    assert!(execute(&s,&id,source,vec![],false).unwrap_err().is("PLAN_RESULT_SCALAR_OR_REF_REQUIRED"));
    // No expensive recursive string rendering occurs before this rejection.
    let source=format!("{}0{}","[".repeat(33),"]".repeat(33));
    assert!(execute(&s,&id,&source,vec![],false).unwrap_err().is("PLAN_LIVE_PARSE_BOUNDS"));
    assert!(port.calls.lock().unwrap().is_empty());
}

#[test]
fn parser_screen_rejects_fstring_code_and_deep_indentation() {
    let port=Arc::new(PortState::default());let (s,_)=service(0,port.clone());let id=begin(&s,&[],0,false);
    for source in [r#"f"{'x' * 1000000000}""#, r#"F"{list(range(1000000000))}""#] {
        assert!(execute(&s,&id,source,vec![],false).unwrap_err().is("PLAN_LIVE_FSTRING_UNSUPPORTED"));
    }
    let mut nested=String::new();
    for level in 0..34 {nested.push_str(&" ".repeat(level));nested.push_str("if True:\n");}
    nested.push_str(&" ".repeat(34));nested.push_str("True");
    assert!(execute(&s,&id,&nested,vec![],false).unwrap_err().is("PLAN_LIVE_PARSE_BOUNDS"));
    let unary=format!("{}True","not ".repeat(300));
    assert!(execute(&s,&id,&unary,vec![],false).unwrap_err().is("PLAN_LIVE_WORK_BOUNDS"));
    assert!(port.calls.lock().unwrap().is_empty());
}

#[test]
fn live_ast_work_bounds_precede_recursive_frozen_validation() {
    // These small chains pass the lexical screen but exceed live AST depth.
    // Assignments also exercise the boolean/ternary forms visited by scalar
    // inference. Reflection at the end distinguishes the bounded guard from
    // the full frozen visitor without a large or hazardous stress input.
    let port=Arc::new(PortState::default());let (s,_)=service(0,port.clone());let id=begin(&s,&[],0,false);
    for source in [
        format!("{}getattr(None, 'x')","not ".repeat(48)),
        format!("result = {}getattr(None, 'x')\n0","True and ".repeat(48)),
        format!("result = {}getattr(None, 'x')\n0","True if True else ".repeat(48)),
    ] {
        let error=enclave_agent_runtime::plan::frozen::parse_frozen_plan(&source,Profile::L2)
            .err().expect("standalone frozen validation must reject reflection");
        assert!(error.is("STARLARK_DYNAMIC_ATTR_FORBIDDEN"),"{error}");
        let error=execute(&s,&id,&source,vec![],false).unwrap_err();
        assert!(error.is("PLAN_LIVE_WORK_BOUNDS"),"{error}");
    }
    assert!(port.calls.lock().unwrap().is_empty());
}

#[test]
fn rd07_all_branches_are_checked_before_dispatch_ceremony_or_charge() {
    for profile in [Profile::L1,Profile::L2,Profile::L3] {
        let port=Arc::new(PortState::default());let (s,vault)=service_profile(10,port.clone(),profile);
        let id=begin(&s,&["read","export"],10,false);
        let denied=r#"tool_call("fixture","export",{"where_value":"private"})"#;
        for source in [format!("{READ}\n{denied}"),format!("{denied}\n{READ}"),
            format!("{READ}\nif False:\n    {denied}"),
            format!("{READ}\nfor n in range(0):\n    {denied}")] {
            let error=execute(&s,&id,&source,vec![],false).unwrap_err();
            assert!(error.is(if profile==Profile::L3 {"ERR_IFC_SEALED_ABORT"} else {"ERR_IFC_STATIC_CEDAR_DENIED"}),"{error}");
            assert!(error.detail.is_empty());
            assert!(port.calls.lock().unwrap().is_empty());
            assert!(vault.drafts.lock().unwrap().is_empty());
            assert_eq!(*vault.next.lock().unwrap(),0,"preflight allocated an audit slot");
        }
        // Rejections neither consume the one-call budget nor invoke the vault.
        execute(&s,&id,READ,vec![],false).unwrap();
        assert_eq!(port.calls.lock().unwrap().len(),1);
    }
}

#[test]
fn rd07_unreachable_stepup_is_eligible_without_hardware_effects() {
    let port=Arc::new(PortState::default());let (s,vault)=service(0,port.clone());
    let id=begin(&s,&["read","export"],12_000,false);
    let source=format!("{READ}\nif False:\n    tool_call(\"fixture\",\"export\",{{\"where_value\":\"x\"}})");
    execute(&s,&id,&source,vec![],true).unwrap();
    assert_eq!(port.calls.lock().unwrap().len(),1);
    assert!(vault.drafts.lock().unwrap().is_empty());
}

#[test]
fn rd07_unknown_out_of_scope_and_malformed_dead_calls_prevent_earlier_effects() {
    let port=Arc::new(PortState::default());let (s,_)=service(0,port.clone());
    let id=begin(&s,&["read"],12_000,false);
    for denied in [r#"tool_call("fixture","missing",{})"#,r#"tool_call("fixture","export",{})"#,
        r#"tool_call("fixture","read")"#,r#"declassify_enum("x","enum",2)"#] {
        let source=format!("{READ}\nif False:\n    {denied}");
        assert!(execute(&s,&id,&source,vec![],true).is_err());
        assert!(port.calls.lock().unwrap().is_empty());
    }
}

#[test]
fn rd07_per_call_data_authorization_still_denies_after_eligible_prior_effect() {
    let port=Arc::new(PortState::default());let (s,_)=service(0,port.clone());
    let id=begin(&s,&["read","narrow"],12_000,false);
    // Both calls are eligible with C1/T1 facts. The first result is C2/T3,
    // so actual authorization refuses sending it to the C1 sink.
    let source=r#"first = tool_call("fixture","read",{"limit":1,"where_value":"x"})
tool_call("fixture","narrow",{"where_value":first})"#;
    let error=execute(&s,&id,source,vec![],false).unwrap_err();
    assert_eq!(port.calls.lock().unwrap().len(),1);
    assert!(error.detail.contains("dispatched_tool_calls=1"));
    assert!(error.detail.contains("do not retry automatically"));
    assert!(!error.detail.contains("from_tool"));
}

#[test]
fn rd07_policy_swap_after_preflight_is_enforced_before_next_dispatch() {
    use enclave_agent_runtime::cedar_engine::{CedarBundle,BASELINE_POLICIES,DEFAULT_SCHEMA,CEDAR_BUNDLE_TARGET};
    use enclave_core::ipc::{PeerPolicy,SocketAccess};
    #[derive(serde::Deserialize)] enum Req { FetchTarget {target:String} }
    #[derive(serde::Serialize)] enum Resp { Bytes(serde_bytes::ByteBuf) }
    let base=std::env::temp_dir().join(format!("p7-{:x}",enclave_core::rng::u64()));
    let socket_dir=base.join("run");
    let suffix=enclave_core::daemon::DaemonId::SwarmSync.dir_name();
    let socket=socket_dir.join(suffix).join(format!("{suffix}.sock"));
    enclave_core::fsutil::private_dir(socket.parent().unwrap()).unwrap();
    let listener=enclave_core::ipc::bind(&socket,SocketAccess::OwnerOnly).unwrap();
    let policy=CedarBundle::new(DEFAULT_SCHEMA,format!("{BASELINE_POLICIES}\nforbid (principal, action, resource == MCPMac::Tool::\"mcp://fixture/read\");")).to_json_bytes().unwrap();
    let stop=Arc::new(AtomicBool::new(false));let end=stop.clone();let signed=policy.clone();
    let server=std::thread::spawn(move||enclave_core::ipc::serve::<Req,Resp,_>(listener,
        PeerPolicy::allow([enclave_core::ipc::geteuid()]),Arc::new(move|_:&PeerCredentials,request:Req|{
            let Req::FetchTarget {target}=request;
            assert_eq!(target,CEDAR_BUNDLE_TARGET);
            Ok(Resp::Bytes(signed.clone().into()))
        }),end));
    let port=Arc::new(PortState::default());
    let (s,_)=service_policy(0,port.clone(),Profile::L2,CedarEngine::baseline_bundle().unwrap(),Some(socket_dir));
    let id=begin(&s,&["read"],12_000,false);
    *port.policy_refresh.lock().unwrap()=Some((Arc::downgrade(&s),policy));
    // Both sites passed the same baseline snapshot. The port swaps to an
    // independently served stricter policy after the first real dispatch.
    let error=execute(&s,&id,&format!("{READ}\n{READ}"),vec![],false).unwrap_err();
    assert_eq!(port.calls.lock().unwrap().len(),1);
    assert!(error.is("PLAN_TOOL_DENIED"),"{error}");
    assert!(error.detail.contains("dispatched_tool_calls=1"));
    stop.store(true,Ordering::SeqCst);server.join().unwrap().unwrap();
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn rd07_preflight_uses_verified_chain_principal_and_checks_a1_policy() {
    use enclave_agent_runtime::cedar_engine::{CedarBundle,BASELINE_POLICIES,DEFAULT_SCHEMA};
    let policy=CedarBundle::new(DEFAULT_SCHEMA,format!("{BASELINE_POLICIES}\nforbid (principal,action,resource) when {{ !(principal.role like \"chain:*\") }};"));
    let port=Arc::new(PortState::default());
    let (s,_)=service_policy(0,port.clone(),Profile::L2,CedarEngine::from_bundle(&policy).unwrap(),None);
    let id=begin(&s,&["read"],12_000,false);
    execute(&s,&id,READ,vec![],false).unwrap();
    let policy=CedarBundle::new(DEFAULT_SCHEMA,format!("{BASELINE_POLICIES}\nforbid (principal,action,resource == MCPMac::Tool::\"mcp://fixture/narrow\");"));
    let port=Arc::new(PortState::default());
    let (s,_)=service_policy(0,port.clone(),Profile::L2,CedarEngine::from_bundle(&policy).unwrap(),None);
    let id=begin(&s,&["read","narrow"],12_000,false);
    let source=format!("{READ}\nif False:\n    tool_call(\"fixture\",\"narrow\",{{}})");
    assert!(execute(&s,&id,&source,vec![],false).unwrap_err().is("ERR_IFC_STATIC_CEDAR_DENIED"));
    assert!(port.calls.lock().unwrap().is_empty());
}


#[test]
fn original_stepup_expiry_after_slot_work_refuses_before_dispatch() {
    let port=Arc::new(PortState::default());let (s,vault)=service(0,port.clone());
    let id=begin(&s,&["export"],12_000,false);
    *vault.lifetime.lock().unwrap()=Some(IntentLifetimeV1 {v:1,valid_until_unix:None,
        deadline_boot_ns:Some(enclave_core::clock::boot_clock_ns()+2_000_000_000)});
    vault.delay_slot.store(true,Ordering::SeqCst);
    let error=execute(&s,&id,r#"tool_call("fixture","export",{"where_value":"x"})"#,vec![],true).unwrap_err();
    assert!(error.is("TOOL_AUTHORITY_EXPIRED"),"{error}");
    assert_eq!(vault.drafts.lock().unwrap().len(),1);
    assert!(port.calls.lock().unwrap().is_empty());
}

#[test]
fn stepup_boolean_cannot_supply_missing_or_unsupported_custody_bounds() {
    for (lifetime,code) in [
        (IntentLifetimeV1 {v:1,valid_until_unix:None,deadline_boot_ns:None},"TOOL_AUTHORITY_LIFETIME_REQUIRED"),
        (IntentLifetimeV1 {v:2,valid_until_unix:None,deadline_boot_ns:Some(u64::MAX)},"TOOL_AUTHORITY_LIFETIME_VERSION"),
        (IntentLifetimeV1 {v:1,valid_until_unix:None,deadline_boot_ns:Some(u64::MAX)},"TOOL_AUTHORITY_LIFETIME_BOUND"),
    ] {
        let port=Arc::new(PortState::default());let (s,vault)=service(0,port.clone());
        let id=begin(&s,&["export"],12_000,false);*vault.lifetime.lock().unwrap()=Some(lifetime);
        let error=execute(&s,&id,r#"tool_call("fixture","export",{"where_value":"x"})"#,vec![],true).unwrap_err();
        assert!(error.is(code),"{error}");assert!(port.calls.lock().unwrap().is_empty());
    }
}
