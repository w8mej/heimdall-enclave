//! Bounded private processes and real TUF/CAS sockets; no installed services,
//! accounts, SEP/enrollment, network policy, or production authority changes.
use enclave_core::{daemon::DaemonId, host_config::{EnclaveHostConfig, HOST_CONFIG_TARGET}, ipc::PeerCredentials, profile::Profile};
use enclave_swarm_syncd::service::{CasConfig, CasRequest, CasResponse, CasService};
use mcp_enclave::devtuf::DevRepo;
use std::{path::{Path, PathBuf}, process::{Child, Command, Stdio}, sync::{Arc, atomic::{AtomicBool, Ordering}}, time::{Duration, Instant}};

fn config(floor: Profile) -> Vec<u8> {
    EnclaveHostConfig { profile_floor: floor, ifc_grant_public_key:hex::encode(ed25519_dalek::SigningKey::from_bytes(&[0x42;32]).verifying_key().to_bytes()), ohttp_key_config:None,
        calibration_corpus_digest:"01".repeat(32), vk_digest:"02".repeat(32), mcp_lock_digest:"03".repeat(32),
        fido_mds_allowlist_digest:"04".repeat(32), codesign_pins:None }.to_json_bytes().unwrap()
}
struct Process { child: Child, stderr: PathBuf }
impl Process {
    fn spawn(base: &Path, socket: &Path, d: DaemonId, profile: Profile, extra: &[String]) -> Self {
        let stderr=base.join(format!("child-{}-{}.log",d.uid(),enclave_core::rng::u64()));
        let file=std::fs::File::create(&stderr).unwrap();
        let child=Command::new(env!("CARGO_BIN_EXE_mcp-enclave"))
            .args(["__daemon", &d.uid().to_string(), "--socket-dir"]).arg(socket)
            .args(["--profile", &profile.to_string(), "--dev-same-uid", "--simulated-hardware", "--no-audit"])
            .args(extra).stdin(Stdio::null()).stdout(Stdio::null()).stderr(file).spawn().unwrap();
        Self {child,stderr}
    }
    fn expect_refusal(&mut self, reason: &str) {
        let deadline=Instant::now()+Duration::from_secs(8);
        loop {
            if let Some(status)=self.child.try_wait().unwrap() {
                let log=std::fs::read_to_string(&self.stderr).unwrap();
                assert!(!status.success(),"unexpected success: {log}");
                assert!(log.contains(reason),"expected {reason}, got {log}");
                return;
            }
            assert!(Instant::now()<deadline,"entry failed to refuse; log={}",std::fs::read_to_string(&self.stderr).unwrap());
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
impl Drop for Process { fn drop(&mut self) { let _=self.child.kill();let _=self.child.wait(); } }
struct Fixture { base:PathBuf, socket:PathBuf, store:PathBuf, repo:DevRepo, svc:Arc<CasService>, stop:Arc<AtomicBool>, thread:Option<std::thread::JoinHandle<()>> }
impl Fixture {
    fn new(floor:Profile)->Self {
        let base=PathBuf::from("/tmp").join(format!("mc-f118-{}",hex::encode(&enclave_core::rng::bytes32()[..12])));
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        // The real custody keyring rejects symlink ancestors. Resolve the
        // platform's /tmp alias only in this already-created private fixture;
        // production state traversal must retain its O_NOFOLLOW policy.
        let base=std::fs::canonicalize(&base).unwrap();
        let socket=base.join("run");let store=base.join("store");std::fs::create_dir_all(&store).unwrap();
        let mut repo=DevRepo::open(&base.join("authority")).unwrap();
        let bytes=config(floor);repo.add_target(HOST_CONFIG_TARGET,&bytes,serde_json::json!({})).unwrap();
        std::fs::write(store.join(HOST_CONFIG_TARGET),bytes).unwrap();
        let svc=CasService::start(CasConfig{dev_same_uid: true, profile:Profile::L1,store_dir:store.clone(),audit_path:None,ohttp_gateway:None,
            tuf_root:Some(std::fs::read(repo.repo_dir().join("root.json")).unwrap()),state_dir:None,
            revocation:enclave_swarm_syncd::revocation::Enforcement::InProcess}).unwrap();
        refresh(&svc,&repo);
        std::fs::create_dir_all(socket.join("cas")).unwrap();
        let listener=enclave_core::ipc::bind(&socket.join("cas/cas.sock"),enclave_core::ipc::SocketAccess::OwnerOnly).unwrap();
        let stop=Arc::new(AtomicBool::new(false));let flag=stop.clone();let server=svc.clone();
        let thread=std::thread::spawn(move || enclave_core::ipc::serve::<CasRequest,CasResponse,_>(listener,
            enclave_core::ipc::PeerPolicy::allow([enclave_core::ipc::geteuid()]),Arc::new(move |p:&PeerCredentials,r|server.handle(p,r)),flag).unwrap());
        Self{base,socket,store,repo,svc,stop,thread:Some(thread)}
    }
    fn set_floor(&mut self, floor:Profile) {
        let bytes=config(floor);self.repo.add_target(HOST_CONFIG_TARGET,&bytes,serde_json::json!({})).unwrap();
        std::fs::write(self.store.join(HOST_CONFIG_TARGET),bytes).unwrap();refresh(&self.svc,&self.repo);
    }
    fn child(&self,d:DaemonId,p:Profile)->Process {
        Process::spawn(&self.base,&self.socket,d,p,&["--state-dir".into(),self.base.join(format!("state-{}-{}",d.uid(),enclave_core::rng::u64())).display().to_string()])
    }
}
impl Drop for Fixture {fn drop(&mut self){self.stop.store(true,Ordering::SeqCst);if let Some(t)=self.thread.take(){t.join().unwrap();}let _=std::fs::remove_dir_all(&self.base);}}
fn refresh(svc:&CasService,repo:&DevRepo) {svc.handle(&PeerCredentials::local(0,0),refresh_request(repo)).unwrap();}
fn refresh_request(repo:&DevRepo)->CasRequest {
    let r=repo.repo_dir();CasRequest::TufRefresh{roots:vec![],timestamp:std::fs::read(r.join("timestamp.json")).unwrap().into(),
        snapshot:std::fs::read(r.join("snapshot.json")).unwrap().into(),targets:std::fs::read(r.join("targets.json")).unwrap().into()}
}
fn call(socket:&Path,d:DaemonId,request:impl serde::Serialize)->enclave_core::error::EnclaveResult<CasResponse> {
    enclave_core::ipc::Client::connect(&socket.join(d.socket_name()),enclave_core::ipc::geteuid())?.call(&request)
}
fn wait_socket(socket:&Path,d:DaemonId,p:&mut Process) {
    let start=Instant::now();loop {
        if enclave_core::ipc::Client::connect(&socket.join(d.socket_name()),enclave_core::ipc::geteuid()).is_ok(){return;}
        assert!(p.child.try_wait().unwrap().is_none(),"{d} child exited: {}",std::fs::read_to_string(&p.stderr).unwrap());
        assert!(start.elapsed()<Duration::from_secs(10),"socket timeout: {}",std::fs::read_to_string(&p.stderr).unwrap());
        std::thread::sleep(Duration::from_millis(20));
    }
}
#[test]
fn f118_all_five_entries_refuse_l1_under_signed_l3_floor() {
    let f=Fixture::new(Profile::L3);
    for d in DaemonId::ALL.into_iter().filter(|d|*d!=DaemonId::SwarmSync) {
        let mut p=f.child(d,Profile::L1);p.expect_refusal("HOST_PROFILE_BELOW_FLOOR");
        assert!(!f.socket.join(d.socket_name()).exists(),"refused entry published socket");
    }
    // Seed authentic persisted TUF trust for CAS, then invoke its real entry.
    let state=f.base.join("seeded-cas-state");
    let seeded_store=f.base.join("seeded-cas-store");std::fs::create_dir_all(&seeded_store).unwrap();
    std::fs::write(seeded_store.join(HOST_CONFIG_TARGET),config(Profile::L3)).unwrap();
    let svc=CasService::start(CasConfig{dev_same_uid: true, profile:Profile::L1,store_dir:seeded_store.clone(),audit_path:None,ohttp_gateway:None,
        tuf_root:Some(std::fs::read(f.repo.repo_dir().join("root.json")).unwrap()),state_dir:Some(state.clone()),
        revocation:enclave_swarm_syncd::revocation::Enforcement::InProcess}).unwrap();refresh(&svc,&f.repo);drop(svc);
    let isolated=f.base.join("isolated-run");
    let mut p=Process::spawn(&f.base,&isolated,DaemonId::SwarmSync,Profile::L1,&[
        "--state-dir".into(),state.display().to_string(),"--store-dir".into(),seeded_store.display().to_string()]);
    p.expect_refusal("HOST_PROFILE_BELOW_FLOOR");assert!(!isolated.join("cas/cas.sock").exists());
}
#[test]
fn f118_non_cas_entries_refuse_missing_or_tampered_config_before_startup() {
    let f=Fixture::new(Profile::L2);
    std::fs::write(f.store.join(HOST_CONFIG_TARGET),config(Profile::L1)).unwrap();
    for d in DaemonId::ALL.into_iter().filter(|d|*d!=DaemonId::SwarmSync) {
        let mut p=f.child(d,Profile::L3);p.expect_refusal("TUF_TARGET_");
    }
    std::fs::remove_file(f.store.join(HOST_CONFIG_TARGET)).unwrap();
    for d in DaemonId::ALL.into_iter().filter(|d|*d!=DaemonId::SwarmSync) {
        let mut p=f.child(d,Profile::L3);p.expect_refusal("TARGET_NOT_FOUND");
    }
}
#[test]
fn f118_cas_bootstrap_is_config_only_then_admits_the_signed_floor() {
    let f=Fixture::new(Profile::L2);let socket=f.base.join("boot-run");let store=f.base.join("boot-store");
    let mut p=Process::spawn(&f.base,&socket,DaemonId::SwarmSync,Profile::L2,&["--store-dir".into(),store.display().to_string(),
        "--state-dir".into(),f.base.join("boot-state").display().to_string()]);wait_socket(&socket,DaemonId::SwarmSync,&mut p);
    assert!(call(&socket,DaemonId::SwarmSync,CasRequest::Status).is_err());
    assert!(call(&socket,DaemonId::SwarmSync,CasRequest::Admit{target:"other.json".into(),bytes:b"{}".to_vec().into()}).is_err());
    assert!(matches!(call(&socket,DaemonId::SwarmSync,CasRequest::TufBootstrap{root:std::fs::read(f.repo.repo_dir().join("root.json")).unwrap().into()}).unwrap(),CasResponse::Tuf{..}));
    call(&socket,DaemonId::SwarmSync,refresh_request(&f.repo)).unwrap();
    assert!(call(&socket,DaemonId::SwarmSync,CasRequest::Status).is_err());
    call(&socket,DaemonId::SwarmSync,CasRequest::Admit{target:HOST_CONFIG_TARGET.into(),bytes:config(Profile::L2).into()}).unwrap();
    assert!(matches!(call(&socket,DaemonId::SwarmSync,CasRequest::Status).unwrap(),CasResponse::Status(s) if s.state.contains("profile=L2")));
    drop(p);
}
#[test]
fn f118_valid_entries_serve_then_recheck_a_raised_floor_and_allow_cleanup() {
    let mut f=Fixture::new(Profile::L1);
    for d in DaemonId::ALL.into_iter().filter(|d|*d!=DaemonId::SwarmSync) {
        let mut p=f.child(d,Profile::L1);wait_socket(&f.socket,d,&mut p);
        assert!(call(&f.socket,d,CasRequest::Status).is_ok(),"valid {d} refused");
        let turn_id = if d == DaemonId::AgentRuntime {
            let response: enclave_agent_runtime::service::IfcResponse = enclave_core::ipc::Client::connect(
                &f.socket.join(d.socket_name()), enclave_core::ipc::geteuid()).unwrap()
                .call(&enclave_agent_runtime::service::IfcRequest::BeginTurn {
                    turn: enclave_core::user_turn::UserTurnV1 { directive_short: "bounded cleanup fixture".into(), attachments: vec![] },
                    attachments: vec![], tools: vec![], holder_pk: None, budget_mb: 0,
                }).unwrap();
            match response { enclave_agent_runtime::service::IfcResponse::TurnPlan { turn_id, .. } => Some(turn_id), _ => panic!("no scoped turn") }
        } else { None };
        f.set_floor(Profile::L3);
        if let Some(turn_id) = turn_id {
            let response: enclave_agent_runtime::service::IfcResponse = enclave_core::ipc::Client::connect(
                &f.socket.join(d.socket_name()), enclave_core::ipc::geteuid()).unwrap()
                .call(&enclave_agent_runtime::service::IfcRequest::FinishTurn { turn_id, cancelled: true }).unwrap();
            assert!(matches!(response, enclave_agent_runtime::service::IfcResponse::TurnFinished { .. }));
        }
        let err=call(&f.socket,d,CasRequest::Status).unwrap_err();assert!(err.is("HOST_PROFILE_BELOW_FLOOR"),"{err:?}");
        // Use each daemon's real wire variant; response details intentionally differ.
        #[derive(serde::Serialize)] enum Cleanup {Wipe, Zeroize(enclave_model_runnerd::arena::ZeroizeTrigger), Tamper(enclave_custody_vaultd::zeroizer::TamperEvent)}
        let cleanup=match d {DaemonId::ModelRunner=>Cleanup::Zeroize(enclave_model_runnerd::arena::ZeroizeTrigger::TaskExit),
            DaemonId::CustodyVault=>Cleanup::Tamper(enclave_custody_vaultd::zeroizer::TamperEvent::ScreenLock),_=>Cleanup::Wipe};
        // Generic JSON value accepts all actual cleanup response variants.
        let result:enclave_core::error::EnclaveResult<serde_json::Value>=enclave_core::ipc::Client::connect(&f.socket.join(d.socket_name()),enclave_core::ipc::geteuid()).unwrap().call(&cleanup);
        assert!(result.is_ok(),"cleanup blocked for {d}: {result:?}");
        let mut env=mcp_enclave::ctl::Env::dev(&f.base,Profile::L1);env.socket_dir=f.socket.clone();
        let session=mcp_enclave::ctl::DevSession {pids:std::collections::BTreeMap::from([(d.uid(),p.child.id())]),profile:Some(Profile::L1),intent_helper_pid:None};
        std::fs::write(f.base.join("dev-session.json"),serde_json::to_vec(&session).unwrap()).unwrap();
        assert_eq!(mcp_enclave::ctl::stop(&env).unwrap(),1,"restricted private daemon could not be stopped");
        drop(p);
        let _=std::fs::remove_file(f.socket.join(d.socket_name()));f.set_floor(Profile::L1);
    }
}

#[test]
fn f118_fresh_cas_verifies_local_metadata_before_normal_serving() {
    let f=Fixture::new(Profile::L2);
    let socket=f.base.join("local-repo-run");
    let loader_store=f.base.join("loader-store");std::fs::create_dir_all(&loader_store).unwrap();
    std::fs::write(loader_store.join(HOST_CONFIG_TARGET),config(Profile::L2)).unwrap();
    let extra=vec!["--store-dir".into(),loader_store.display().to_string(),"--state-dir".into(),f.base.join("fresh-cas").display().to_string(),
        "--tuf-root".into(),f.repo.repo_dir().join("root.json").display().to_string(),"--tuf-repo".into(),f.repo.repo_dir().display().to_string()];
    let mut p=Process::spawn(&f.base,&socket,DaemonId::SwarmSync,Profile::L2,&extra);
    wait_socket(&socket,DaemonId::SwarmSync,&mut p);
    assert!(matches!(call(&socket,DaemonId::SwarmSync,CasRequest::Status).unwrap(),CasResponse::Status(s) if s.state.contains("profile=L2")));
    drop(p);
    let socket=f.base.join("below-local-run");
    let mut below=Process::spawn(&f.base,&socket,DaemonId::SwarmSync,Profile::L1,&extra);
    below.expect_refusal("HOST_PROFILE_BELOW_FLOOR");
    assert!(!socket.join("cas/cas.sock").exists());
}

#[test]
fn f140_scoped_runner_cleanup_survives_signed_profile_revocation() {
    use enclave_model_runnerd::service::{RunnerRequest, RunnerResponse};
    let mut f=Fixture::new(Profile::L1);
    let mut child=f.child(DaemonId::ModelRunner,Profile::L1);
    wait_socket(&f.socket,DaemonId::ModelRunner,&mut child);
    f.set_floor(Profile::L3);
    let connect=|| enclave_core::ipc::Client::connect(
        &f.socket.join(DaemonId::ModelRunner.socket_name()),enclave_core::ipc::geteuid()).unwrap();
    let refused:enclave_core::error::EnclaveResult<RunnerResponse>=connect().call(
        &RunnerRequest::SsmForkOwned {scope:[0x14;32],label:enclave_core::label::Label::BOTTOM});
    assert!(refused.unwrap_err().is("HOST_PROFILE_BELOW_FLOOR"));
    let exited:RunnerResponse=connect().call(&RunnerRequest::SsmExitOwned {scope:[0x14;32]}).unwrap();
    assert!(matches!(exited,RunnerResponse::Wiped(0)));
    let legacy:enclave_core::error::EnclaveResult<RunnerResponse>=connect().call(
        &RunnerRequest::SsmExit {session:140});
    assert!(legacy.unwrap_err().is("UNKNOWN_SESSION"),"legacy cleanup must reach authenticated service");
    // Missing configuration is a second fail-closed admission mode; cleanup
    // must remain reachable without claiming an absent arena was wiped.
    std::fs::remove_file(f.store.join(HOST_CONFIG_TARGET)).unwrap();
    let refused:enclave_core::error::EnclaveResult<RunnerResponse>=connect().call(&RunnerRequest::Status);
    assert!(refused.is_err());
    let exited:RunnerResponse=connect().call(&RunnerRequest::SsmExitOwned {scope:[0x14;32]}).unwrap();
    assert!(matches!(exited,RunnerResponse::Wiped(0)));
    assert!(child.child.try_wait().unwrap().is_none());
}
