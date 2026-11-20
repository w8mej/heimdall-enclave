//! Actual private TUF/CAS IPC and worker tests. No installed services or real
//! publisher authority is created by this explicitly local fixture.
use enclave_core::{ipc::PeerCredentials, profile::Profile};
use enclave_swarm_syncd::service::{CasConfig, CasRequest, CasResponse, CasService};
use depot_enclave::{ctl::Env, devtuf::DevRepo, deploy::{hydrate::{HydrationJob, run_worker_job_with_env}, EXIT_SUCCESS}};
use std::{path::PathBuf, sync::{Arc, atomic::{AtomicBool, Ordering}}};

const TARGET: &str = "large-model.bin";
struct Fixture { base: PathBuf, env: Env, stop: Arc<AtomicBool>, thread: Option<std::thread::JoinHandle<()>> }
impl Fixture {
    fn new(payload: &[u8]) -> Self {
        Self::with_profile(payload, Profile::L1)
    }
    fn with_profile(payload: &[u8], profile: Profile) -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let base = PathBuf::from("/tmp").join(format!("mc-f13-{}",hex::encode(&enclave_core::rng::bytes32()[..16])));
        std::fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        // Resolve Darwin's /tmp alias only for this already-created private
        // fixture. Production authority traversal keeps refusing symlinks.
        let base = base.canonicalize().unwrap();
        let env = Env::dev(&base,profile);
        let repo=base.join("tuf/repo"); let store=base.join("store");
        std::fs::create_dir_all(&store).unwrap();
        let mut authority=DevRepo::open(&base.join("tuf")).unwrap();
        authority.add_target(TARGET,payload,serde_json::json!({})).unwrap();
        std::fs::write(store.join(TARGET),payload).unwrap();
        let svc=CasService::start(CasConfig {dev_same_uid: true,  profile,store_dir:store,audit_path:None,ohttp_gateway:None,
            tuf_root:Some(std::fs::read(repo.join("root.json")).unwrap()),state_dir:Some(base.join("state")),
            revocation:enclave_swarm_syncd::revocation::Enforcement::InProcess }).unwrap();
        svc.handle(&PeerCredentials::local(0,0),CasRequest::TufRefresh { roots:vec![],
            timestamp:std::fs::read(repo.join("timestamp.json")).unwrap().into(),snapshot:std::fs::read(repo.join("snapshot.json")).unwrap().into(),
            targets:std::fs::read(repo.join("targets.json")).unwrap().into() }).unwrap();
        let dir=env.socket_dir.join("cas");std::fs::create_dir_all(&dir).unwrap();
        let listener=enclave_core::ipc::bind(&dir.join("cas.sock"),enclave_core::ipc::SocketAccess::OwnerOnly).unwrap();
        let stop=Arc::new(AtomicBool::new(false));let flag=stop.clone();
        let thread=std::thread::spawn(move|| { enclave_core::ipc::serve::<CasRequest,CasResponse,_>(listener,
            enclave_core::ipc::PeerPolicy::allow([enclave_core::ipc::geteuid()]),Arc::new(move |p:&PeerCredentials,r|svc.handle(p,r)),flag).unwrap() });
        Self {base,env,stop,thread:Some(thread)}
    }
    fn run(&self)->(i32,String,serde_json::Value) {
        let job=HydrationJob { job_id:"f13-large".into(),target:TARGET.into(),profile:self.env.profile.to_string(),created_at:1,source:"r2".into(),dmg_path:None };
        run_worker_job_with_env(&job,&self.base.join("jobs"),&self.base.join("hydrated"),&self.env)
    }
}
impl Drop for Fixture {fn drop(&mut self){self.stop.store(true,Ordering::SeqCst);self.thread.take().unwrap().join().unwrap();let _=std::fs::remove_dir_all(&self.base);}}
fn payload()->Vec<u8> { let mut b=vec![0u8;3*1024*1024+17];blake3::Hasher::new_derive_key("F13 signed streaming regression").finalize_xof().fill(&mut b);b }
#[test]
fn f13_authenticated_model_larger_than_ipc_frame_hydrates_exact_bytes() {
    let bytes=payload();let f=Fixture::new(&bytes);
    let (code,message,result)=f.run();
    assert_eq!(code,EXIT_SUCCESS,"{message}: {result}");
    assert_eq!(result["bytes_synced"],bytes.len());
    assert_eq!(result["status"],"completed");
    assert_eq!(result["bao_root"],blake3::hash(&bytes).to_hex().as_str());
    assert_eq!(std::fs::read(f.base.join("hydrated/models").join(TARGET)).unwrap(),bytes);
}

#[test]
fn f13_chunk_admission_then_snapshot_hydration_preserves_exact_bytes() {
    let bytes=payload();let f=Fixture::new(&bytes);
    let root=depot_enclave::artifact_stream::admit_reader(&f.env,TARGET,&mut std::io::Cursor::new(&bytes)).unwrap();
    assert_eq!(root,blake3::hash(&bytes).to_hex().as_str());
    // Require the actual CAS representation: the original loose target is gone.
    std::fs::remove_file(f.base.join("store").join(TARGET)).unwrap();
    let (code,message,result)=f.run();assert_eq!(code,EXIT_SUCCESS,"{message}: {result}");
    assert_eq!(std::fs::read(f.base.join("hydrated/models").join(TARGET)).unwrap(),bytes);
    assert!(std::fs::read_dir(f.base.join("hydrated/models")).unwrap().all(|e|!e.unwrap().file_name().to_string_lossy().starts_with(".hydrate-")));
}
#[test]
fn f13_corruption_preserves_previous_model_and_no_temporary_payload_remains() {
    let bytes=payload();let f=Fixture::new(&bytes);assert_eq!(f.run().0,EXIT_SUCCESS);
    let mut damaged=bytes.clone();let last=damaged.len()-1;damaged[last]^=1;
    std::fs::write(f.base.join("store").join(TARGET),damaged).unwrap();
    let (code,_,result)=f.run();assert_ne!(code,EXIT_SUCCESS);assert_eq!(result["bytes_synced"],0);
    assert_eq!(std::fs::read(f.base.join("hydrated/models").join(TARGET)).unwrap(),bytes);
    for leaf in ["models","chunks"] {
        assert!(std::fs::read_dir(f.base.join("hydrated").join(leaf)).unwrap().all(|e|!e.unwrap().file_name().to_string_lossy().starts_with(".hydrate-")));
    }
}
#[test]
fn f13_interrupted_reader_aborts_and_valid_retry_can_publish() {
    struct Broken {input:std::io::Cursor<Vec<u8>>,left:usize}
    impl std::io::Read for Broken {
        fn read(&mut self,b:&mut[u8])->std::io::Result<usize>{
            if self.left==0{return Err(std::io::Error::other("injected source interruption"));}
            let limit=b.len().min(self.left);let n=std::io::Read::read(&mut self.input,&mut b[..limit])?;self.left-=n;Ok(n)
        }
    }
    let bytes=payload();let f=Fixture::new(&bytes);
    let root=blake3::hash(&bytes).to_hex().to_string();
    assert!(depot_enclave::artifact_stream::admit_reader(&f.env,TARGET,&mut Broken{input:std::io::Cursor::new(bytes.clone()),left:400_000}).is_err());
    assert!(!f.base.join("store/manifests").join(format!("{root}.json")).exists());
    assert_eq!(depot_enclave::artifact_stream::admit_reader(&f.env,TARGET,&mut std::io::Cursor::new(bytes)).unwrap(),root);
}

#[test]
fn f13_operator_admission_streams_file_and_dev_signer_before_fixture_bind() {
    use enclave_core::{daemon::DaemonId, ipc};
    use enclave_model_runnerd::{manifest::ExecutionClass, service::{RunnerRequest, RunnerResponse}};
    let bytes=payload();let f=Fixture::with_profile(&bytes,Profile::L2);
    let root=blake3::hash(&bytes).to_hex().to_string();
    let weights=f.base.join("input.bin");std::fs::write(&weights,&bytes).unwrap();
    let package=enclave_model_runnerd::zoo::package(ExecutionClass::ArCausal).unwrap();
    let manifest=f.base.join("input.json");std::fs::write(&manifest,package.manifest_bytes()).unwrap();
    std::fs::create_dir(f.base.join("cas")).unwrap();
    let socket=f.env.socket_dir.join(DaemonId::ModelRunner.socket_name());
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    let listener=ipc::bind(&socket,ipc::SocketAccess::OwnerOnly).unwrap();
    let stop=Arc::new(AtomicBool::new(false));let flag=stop.clone();let expected=root.clone();
    // Only the last runner Bind is a fixture. This exercises the actual
    // operator admission, reader-based signer and real signed CAS protocol;
    // it does not claim the synthetic .bin is executable model topology.
    let thread=std::thread::spawn(move||ipc::serve::<RunnerRequest,RunnerResponse,_>(listener,
        ipc::PeerPolicy::allow([ipc::geteuid()]),Arc::new(move|_:&PeerCredentials,request| {
            let RunnerRequest::Bind { manifest,cas_uri,calibration_corpus }=request else {panic!("unexpected fixture request")};
            assert!(manifest.len()<64*1024);assert!(calibration_corpus.is_none());
            let parsed=enclave_model_runnerd::manifest::ModelManifestV1::from_json(&manifest).unwrap();
            assert_eq!(parsed.artifact.blake3,expected);assert_eq!(parsed.artifact.cas_uri,cas_uri);
            Ok(RunnerResponse::Bound {model_id:parsed.model_id,class:ExecutionClass::ArCausal,ece_ppm:None,topology_fingerprint:"fixture-bind-only".into()})
        }),flag).unwrap());
    let result=depot_enclave::ctl::model_admit(&f.env,ExecutionClass::ArCausal,&depot_enclave::ctl::AdmitInput {
        manifest:Some(manifest),weights:Some(weights),corpus:None,target:Some(TARGET.into()) });
    stop.store(true,Ordering::SeqCst);thread.join().unwrap();
    let admitted=result.unwrap();assert!(admitted.cas_uri.contains(&root));
    assert_eq!(admitted.topology_fingerprint,"fixture-bind-only");
    std::fs::remove_file(f.base.join("store").join(TARGET)).unwrap();
    let (code,message,result)=f.run();assert_eq!(code,EXIT_SUCCESS,"{message}: {result}");
    assert_eq!(std::fs::read(f.base.join("hydrated/models").join(TARGET)).unwrap(),bytes);
}
