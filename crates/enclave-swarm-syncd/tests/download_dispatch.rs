//! Real private loopback TLS/OCI and authenticated Unix IPC fixtures. The test
//! signer and local CA are fixture authority, not a production publisher/fleet.
use std::{collections::BTreeMap, fs, io::{Read, Write}, net::TcpListener,
    os::unix::fs::DirBuilderExt, path::PathBuf,
    sync::{Arc, Mutex, atomic::{AtomicBool, AtomicUsize, Ordering}}, time::{Duration, Instant}};
use enclave_core::{ipc::{self, PeerCredentials}, profile::Profile};
use enclave_crypto::tuf::{RepoBuilder, TargetFile, target_file};
use enclave_swarm_syncd::{service::{CasConfig, CasRequest, CasResponse, CasService},
    transport::registry::{DistributionConfig, RegistryConfig, DISTRIBUTION_CONFIG_TARGET}};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::json;

const NOW: i64 = 1_793_884_860;
const EXP: &str = "2030-01-01T00:00:00Z";
const TARGET: &str = "model.bin";
fn wall() -> i64 { NOW }
fn policy() -> serde_json::Value { json!({"classification":"public_l1","min_profile":"L1","license_policy":{"spdx_id":"LicenseRef-fixture","allow_p2p_seeding":false}}) }
fn bytes() -> Vec<u8> { let mut b=vec![0;3*1024*1024+19];
    blake3::Hasher::new_derive_key("F38 private TLS registry fixture").finalize_xof().fill(&mut b);b[..4].copy_from_slice(b"DATA");b }
#[derive(Clone, Copy, Debug)]
enum Behavior { Good, WrongLength, Truncated, Extra, Corrupt, Redirect, Chunked, DuplicateLength, LargeHeader, SlowHandshake, SlowBody, SlowMain }
struct Registry {
    config: RegistryConfig, stop: Arc<AtomicBool>, thread: Option<std::thread::JoinHandle<()>>,
    requests: Arc<Mutex<Vec<String>>>, connections: Arc<AtomicUsize>, body_started: Arc<AtomicBool>,
}
impl Registry {
    fn new(objects: BTreeMap<String,Vec<u8>>, behavior: Behavior) -> Self {
        let mut ca_params=rcgen::CertificateParams::new(vec![]);
        ca_params.is_ca=rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages=vec![rcgen::KeyUsagePurpose::KeyCertSign,rcgen::KeyUsagePurpose::CrlSign,rcgen::KeyUsagePurpose::DigitalSignature];
        let ca=rcgen::Certificate::from_params(ca_params).unwrap();
        let cert=rcgen::Certificate::from_params(rcgen::CertificateParams::new(vec!["localhost".into()])).unwrap();
        let leaf=cert.serialize_der_with_signer(&ca).unwrap();
        let root=ca.serialize_der().unwrap();
        let key=PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.serialize_private_key_der()));
        let tls=rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions().unwrap().with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(leaf)],key).unwrap();
        let tls=Arc::new(tls);
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();listener.set_nonblocking(true).unwrap();
        let config=RegistryConfig {address:listener.local_addr().unwrap().to_string(),server_name:"localhost".into(),repository:"models/private-fixture".into(),tls_roots_der:vec![hex::encode(root)],timeout_ms:2000};
        let stop=Arc::new(AtomicBool::new(false));let flag=stop.clone();
        let requests=Arc::new(Mutex::new(Vec::new()));let recorded=requests.clone();
        let connections=Arc::new(AtomicUsize::new(0));let connected=connections.clone();
        let body_started=Arc::new(AtomicBool::new(false));let body_flag=body_started.clone();
        let thread=std::thread::spawn(move|| {
            while !flag.load(Ordering::SeqCst) {
                let (socket,_)=match listener.accept() {Ok(v)=>v,Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>{std::thread::sleep(Duration::from_millis(2));continue},Err(e)=>panic!("{e}")};
                connected.fetch_add(1,Ordering::SeqCst);
                // Darwin accept inherits the listener's O_NONBLOCK; the
                // rustls fixture uses bounded blocking I/O on each accepted FD.
                socket.set_nonblocking(false).unwrap();
                socket.set_read_timeout(Some(Duration::from_millis(700))).unwrap();
                socket.set_write_timeout(Some(Duration::from_millis(700))).unwrap();
                if matches!(behavior,Behavior::SlowHandshake) {std::thread::sleep(Duration::from_millis(300));}
                let mut stream=rustls::StreamOwned::new(rustls::ServerConnection::new(tls.clone()).unwrap(),socket);
                let result=(||->std::io::Result<()> {
                    let mut header=Vec::new();
                    while !header.ends_with(b"\r\n\r\n") && header.len()<8192 {let mut b=[0u8];stream.read_exact(&mut b)?;header.push(b[0]);}
                    let text=String::from_utf8(header).unwrap();
                    assert!(!text.to_ascii_lowercase().contains("authorization:"),"no fixture bearer or ambient credential may be sent");
                    let path=text.lines().next().unwrap().split_whitespace().nth(1).unwrap().to_string();
                    recorded.lock().unwrap().push(path.clone());
                    let key=path.strip_prefix("/v2/models/private-fixture/blobs/sha256:").expect("fixed OCI repository/digest request");
                    let object=objects.get(key).expect("requested digest must come from signed fixture object");
                    if matches!(behavior,Behavior::Redirect) {stream.write_all(b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: http://127.0.0.1:1/leak\r\n\r\n")?;}
                    else if matches!(behavior,Behavior::LargeHeader) {stream.write_all(format!("HTTP/1.1 200 OK\r\nX-Fill: {}\r\nContent-Length: {}\r\n\r\n","a".repeat(17000),object.len()).as_bytes())?;}
                    else {
                        let declared=object.len()+usize::from(matches!(behavior,Behavior::WrongLength));
                        let extras=if matches!(behavior,Behavior::Chunked) {"Transfer-Encoding: chunked\r\n".to_string()}
                            else if matches!(behavior,Behavior::DuplicateLength) {format!("Content-Length: {declared}\r\n")} else {String::new()};
                        stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {declared}\r\nDocker-Content-Digest: sha256:{key}\r\n{extras}\r\n").as_bytes())?;
                        stream.flush()?;
                        if !matches!(behavior,Behavior::SlowMain) || object.starts_with(b"DATA") {body_flag.store(true,Ordering::SeqCst);}
                        if matches!(behavior,Behavior::SlowBody) || (matches!(behavior,Behavior::SlowMain) && object.starts_with(b"DATA")) {std::thread::sleep(Duration::from_millis(300));}
                        let mut body=object.clone();
                        match behavior {Behavior::Truncated=>{body.pop();},Behavior::Extra=>body.push(0),Behavior::Corrupt=>body[100000]^=1,_=>()}
                        stream.write_all(&body)?;
                    }
                    stream.conn.send_close_notify();stream.flush()?;Ok(())
                })();
                // Rejected certificates/HTTP framing and client timeouts are
                // expected negative outcomes, not server-test panics.
                if let Err(error)=result {eprintln!("F38 private registry {behavior:?}: {error}");}
            }
        });
        Self {config,stop,thread:Some(thread),requests,connections,body_started}
    }
}
impl Drop for Registry {fn drop(&mut self){self.stop.store(true,Ordering::SeqCst);self.thread.take().unwrap().join().unwrap();}}
struct Fixture {base:PathBuf,svc:Arc<CasService>,repo:RepoBuilder,peer:PeerCredentials,targets:BTreeMap<String,TargetFile>}
impl Fixture {
    fn new(config:Option<&RegistryConfig>, profile:Profile, companions:bool) -> Self {
        let base=PathBuf::from("/tmp").join(format!("mc-f38-{}",hex::encode(&enclave_core::rng::bytes32()[..12])));
        fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        let repo=RepoBuilder::new(3,2);let root=repo.root(EXP).unwrap();
        let svc=CasService::start_with_wall_clock(CasConfig {dev_same_uid: true, profile,store_dir:base.join("store"),audit_path:Some(base.join("audit.jsonl")),
            tuf_root:Some(root),ohttp_gateway:None,state_dir:None,revocation:enclave_swarm_syncd::revocation::Enforcement::InProcess},wall).unwrap();
        let mut p=policy();let payload=bytes();let companion=b"{\"calibration\":\"fixture-only\"}";
        let mut targets=BTreeMap::new();
        if companions {p["companion_safety_layers"]=json!([{"role":"fixture-calibration","blake3":blake3::hash(companion).to_hex().as_str(),"eager_hydrate_required":true}]);
            targets.insert("companion.json".into(),target_file(companion,Some(policy())));}
        targets.insert(TARGET.into(),target_file(&payload,Some(p)));
        if let Some(config)=config {let b=serde_json::to_vec(&DistributionConfig {version:1,l2:None,l3:None,l1:Some(config.clone())}).unwrap();
            targets.insert(DISTRIBUTION_CONFIG_TARGET.into(),target_file(&b,Some(json!({}))));fs::write(base.join("store").join(DISTRIBUTION_CONFIG_TARGET),b).unwrap();}
        let mut peer=PeerCredentials::local(ipc::geteuid(),0);peer.pid=Some(std::process::id() as i32);
        let f=Self {base,svc,repo,peer,targets};f.refresh(1,f.targets.clone());f
    }
    fn uri(&self)->String {format!("cas://blake3-bao-v1/{}?target={TARGET}&ns=models",blake3::hash(&bytes()).to_hex())}
    fn refresh(&self,version:u64,targets:BTreeMap<String,TargetFile>){
        let tg=self.repo.targets(version,EXP,targets).unwrap();let snapshot=self.repo.snapshot(version,EXP,version,&tg).unwrap();let timestamp=self.repo.timestamp(version,EXP,version,&snapshot).unwrap();
        self.svc.handle(&self.peer,CasRequest::TufRefresh {roots:vec![],timestamp:timestamp.into(),snapshot:snapshot.into(),targets:tg.into()}).unwrap();
    }
    fn hydrate(&self)->enclave_core::error::EnclaveResult<CasResponse>{self.svc.handle(&self.peer,CasRequest::Hydrate {cas_uri:self.uri()})}
    fn assert_unpublished(&self){let root=blake3::hash(&bytes()).to_hex().to_string();assert!(!self.base.join("store/manifests").join(format!("{root}.json")).exists());
        assert!(fs::read_dir(self.base.join("store/streaming-stages")).unwrap().all(|e|!e.unwrap().file_name().to_string_lossy().starts_with("stage-")));
        assert!(!fs::read_to_string(self.base.join("audit.jsonl")).unwrap().contains("\"event\":\"HYDRATED\""));}
}
impl Drop for Fixture {fn drop(&mut self){let _=fs::remove_dir_all(&self.base);}}
fn stage_counts(f:&Fixture)->enclave_swarm_syncd::sync_diagnostics::StageCounters {
    let CasResponse::SyncDiagnostics(snapshot)=f.svc.handle(&f.peer,CasRequest::SyncDiagnostics).unwrap() else {panic!("typed diagnostics");};
    assert!(snapshot.valid_measurement());assert_eq!(snapshot.availability,enclave_swarm_syncd::sync_diagnostics::CounterAvailability::Current);
    let stages=snapshot.stages.unwrap();
    assert_eq!(stages.quic_fetch,enclave_swarm_syncd::sync_diagnostics::StageCounters::default());
    assert_eq!(stages.ohttp_fetch,enclave_swarm_syncd::sync_diagnostics::StageCounters::default());
    stages.registry_fetch
}
fn assert_stages(f:&Fixture,started:u64,ok:u64,err:u64,in_flight:u64) {
    assert_eq!(stage_counts(f),enclave_swarm_syncd::sync_diagnostics::StageCounters {started,in_flight,returned_ok:ok,returned_err:err,abandoned_unknown:0});
}
fn objects(companions:bool)->BTreeMap<String,Vec<u8>> {use sha2::{Digest,Sha256};let mut values=vec![bytes()];if companions {values.push(b"{\"calibration\":\"fixture-only\"}".to_vec());}
    values.into_iter().map(|b|(hex::encode(Sha256::digest(&b)),b)).collect()}
#[test]
fn f38_real_tls_missing_blob_and_eager_companion_hydrate_through_authenticated_ipc() {
    let server=Registry::new(objects(true),Behavior::Good);let f=Fixture::new(Some(&server.config),Profile::L1,true);
    let path=f.base.join("cas.sock");let listener=ipc::bind(&path,ipc::SocketAccess::OwnerOnly).unwrap();let stop=Arc::new(AtomicBool::new(false));let flag=stop.clone();let svc=f.svc.clone();
    let thread=std::thread::spawn(move||ipc::serve::<CasRequest,CasResponse,_>(listener,ipc::PeerPolicy::allow([ipc::geteuid()]),Arc::new(move|p:&PeerCredentials,r|svc.handle(p,r)),flag).unwrap());
    let result=(|| {let mut client=ipc::Client::connect(&path,ipc::geteuid()).unwrap();client.set_timeout(Some(Duration::from_secs(5))).unwrap();
        // OpenTarget is the actual F13 worker API, so this also proves its
        // missing-object path reaches production network dispatch.
        let response:CasResponse=client.call(&CasRequest::OpenTarget {target:TARGET.into()}).unwrap();
        assert!(matches!(response,CasResponse::TargetFile {fds:1,length,..} if length==bytes().len() as u64));
        let mut fds=client.recv_fds(4).unwrap();assert_eq!(fds.len(),1);let mut file=fs::File::from(fds.pop().unwrap());let mut actual=Vec::new();file.read_to_end(&mut actual).unwrap();assert_eq!(actual,bytes());
        let response:CasResponse=client.call(&CasRequest::Hydrate {cas_uri:f.uri()}).unwrap();assert!(matches!(response,CasResponse::Admitted {root} if root==blake3::hash(&bytes()).to_hex().as_str()));
    });
    // Ensure the private listener is stopped even if the assertions panic.
    let caught=std::panic::catch_unwind(std::panic::AssertUnwindSafe(result));stop.store(true,Ordering::SeqCst);thread.join().unwrap();if let Err(e)=caught {std::panic::resume_unwind(e);}
    assert_eq!(server.requests.lock().unwrap().len(),2,"companion then main, without cache-hit refetch");
    assert_stages(&f,2,2,0,0);
    assert_eq!(enclave_swarm_syncd::cas::ContentStore::open(&f.base.join("store")).unwrap().get(&blake3::hash(&bytes()).to_hex().to_string()).unwrap(),bytes());
}
#[test]
fn f38_tls_wrong_ca_or_hostname_never_sends_http_or_publishes() {
    for wrong_name in [false,true] {let server=Registry::new(objects(false),Behavior::Good);let mut config=server.config.clone();
        let other=rcgen::generate_simple_self_signed(vec!["other.example".into()]).unwrap();
        if wrong_name {config.server_name="wrong.invalid".into();} else {config.tls_roots_der=vec![hex::encode(other.serialize_der().unwrap())];}
        let f=Fixture::new(Some(&config),Profile::L1,false);assert!(f.hydrate().unwrap_err().is("REGISTRY_TLS"));f.assert_unpublished();assert!(server.requests.lock().unwrap().is_empty());assert_eq!(server.connections.load(Ordering::SeqCst),1);assert_stages(&f,1,0,1,0);
    }
}
#[test]
fn f38_http_length_digest_encoding_redirect_and_header_failures_never_publish() {
    for behavior in [Behavior::WrongLength,Behavior::Truncated,Behavior::Extra,Behavior::Corrupt,Behavior::Redirect,Behavior::Chunked,Behavior::DuplicateLength,Behavior::LargeHeader] {
        let server=Registry::new(objects(false),behavior);let f=Fixture::new(Some(&server.config),Profile::L1,false);
        assert!(f.hydrate().is_err(),"{behavior:?}");f.assert_unpublished();assert_eq!(server.requests.lock().unwrap().len(),1,"must exercise authenticated HTTP: {behavior:?}");assert_stages(&f,1,0,1,0);
    }
}
#[test]
fn f38_total_deadline_covers_tls_handshake_and_body_while_status_stays_live() {
    for behavior in [Behavior::SlowHandshake,Behavior::SlowBody] {let server=Registry::new(objects(false),behavior);let mut cfg=server.config.clone();cfg.timeout_ms=100;
        let f=Fixture::new(Some(&cfg),Profile::L1,false);let svc=f.svc.clone();let peer=f.peer.clone();let uri=f.uri();let started=Instant::now();
        let thread=std::thread::spawn(move||svc.handle(&peer,CasRequest::Hydrate {cas_uri:uri}));
        let bound=Instant::now()+Duration::from_secs(2);while server.connections.load(Ordering::SeqCst)==0 && Instant::now()<bound {std::thread::sleep(Duration::from_millis(1));}
        let status_at=Instant::now();assert!(matches!(f.svc.handle(&f.peer,CasRequest::Status).unwrap(),CasResponse::Status(_)));assert!(status_at.elapsed()<Duration::from_millis(80),"network must not hold State mutex");
        assert!(thread.join().unwrap().is_err());assert!(started.elapsed()<Duration::from_secs(2));f.assert_unpublished();assert_stages(&f,1,0,1,0);
    }
}
#[test]
fn f38_unsigned_tampered_invalid_config_and_wrong_profile_never_connect() {
    for mode in 0..5 {let server=Registry::new(objects(false),Behavior::Good);let mut cfg=server.config.clone();if mode==2 {cfg.repository="models\r\nInjected: yes".into();}
        if mode==3 {cfg.address="registry.example:443".into();}
        let f=Fixture::new(if mode==0 {None}else{Some(&cfg)},if mode==4 {Profile::L2}else{Profile::L1},false);
        if mode==0 {fs::write(f.base.join("store").join(DISTRIBUTION_CONFIG_TARGET),serde_json::to_vec(&DistributionConfig {version:1,l2:None,l3:None,l1:Some(cfg)}).unwrap()).unwrap();}
        if mode==1 {fs::write(f.base.join("store").join(DISTRIBUTION_CONFIG_TARGET),b"tampered").unwrap();}
        assert!(f.hydrate().is_err(),"mode {mode}");f.assert_unpublished();assert_eq!(server.connections.load(Ordering::SeqCst),0,"mode {mode}");assert_stages(&f,0,0,0,0);
    }
}
#[test]
fn f38_metadata_change_or_wipe_interrupts_fetch_without_success_receipt() {
    for wipe in [false,true] {let server=Registry::new(objects(false),Behavior::SlowBody);let f=Fixture::new(Some(&server.config),Profile::L1,false);
        let svc=f.svc.clone();let peer=f.peer.clone();let uri=f.uri();let thread=std::thread::spawn(move||svc.handle(&peer,CasRequest::Hydrate {cas_uri:uri}));
        let bound=Instant::now()+Duration::from_secs(2);while !server.body_started.load(Ordering::SeqCst) && Instant::now()<bound {std::thread::sleep(Duration::from_millis(1));}
        assert!(server.body_started.load(Ordering::SeqCst));
        if wipe {f.svc.handle(&f.peer,CasRequest::Wipe).unwrap();} else {let mut changed=f.targets.clone();changed.get_mut(TARGET).unwrap().custom.as_mut().unwrap()["license_policy"]["spdx_id"]=json!("LicenseRef-changed");f.refresh(2,changed);}
        assert!(thread.join().unwrap().is_err());f.assert_unpublished();assert_stages(&f,1,0,1,0);
    }
}

#[test]
fn f38_companion_policy_rotation_during_main_transfer_never_acknowledges() {
    for mode in 0..3 {
        let server=Registry::new(objects(true),Behavior::SlowMain);
        let f=Fixture::new(Some(&server.config),Profile::L1,true);
        let svc=f.svc.clone();let peer=f.peer.clone();let uri=f.uri();
        let thread=std::thread::spawn(move||svc.handle(&peer,CasRequest::Hydrate {cas_uri:uri}));
        let bound=Instant::now()+Duration::from_secs(2);
        while !server.body_started.load(Ordering::SeqCst) && Instant::now()<bound {std::thread::sleep(Duration::from_millis(1));}
        assert!(server.body_started.load(Ordering::SeqCst));
        assert_eq!(server.requests.lock().unwrap().len(),2,"companion committed before main headers");
        let mut changed=f.targets.clone();let custom=changed.get_mut("companion.json").unwrap().custom.as_mut().unwrap();
        match mode {0=>custom["min_profile"]=json!("L3"),1=>custom["classification"]=json!("restricted_l3"),_=>custom["license_policy"]["spdx_id"]=json!("LicenseRef-rotated")}
        f.refresh(2,changed);
        assert!(thread.join().unwrap().is_err(),"mode {mode}");f.assert_unpublished();assert_stages(&f,2,1,1,0);
    }
}

#[test]
fn f38_policy_bearing_loose_source_exports_without_main_cas_manifest_or_network() {
    let f=Fixture::new(None,Profile::L1,false);
    fs::write(f.base.join("store").join(TARGET),bytes()).unwrap();
    let root=blake3::hash(&bytes()).to_hex().to_string();
    assert!(!f.base.join("store/manifests").join(format!("{root}.json")).exists());
    let path=f.base.join("cas.sock");let listener=ipc::bind(&path,ipc::SocketAccess::OwnerOnly).unwrap();
    let stop=Arc::new(AtomicBool::new(false));let flag=stop.clone();let svc=f.svc.clone();
    let thread=std::thread::spawn(move||ipc::serve::<CasRequest,CasResponse,_>(listener,ipc::PeerPolicy::allow([ipc::geteuid()]),Arc::new(move|p:&PeerCredentials,r|svc.handle(p,r)),flag).unwrap());
    let caught=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut client=ipc::Client::connect(&path,ipc::geteuid()).unwrap();
        let response:CasResponse=client.call(&CasRequest::OpenTarget {target:TARGET.into()}).unwrap();
        assert!(matches!(response,CasResponse::TargetFile {fds:1,length,..} if length==bytes().len() as u64));
        let mut fds=client.recv_fds(4).unwrap();assert_eq!(fds.len(),1);
        let mut actual=Vec::new();fs::File::from(fds.pop().unwrap()).read_to_end(&mut actual).unwrap();assert_eq!(actual,bytes());
    }));
    stop.store(true,Ordering::SeqCst);thread.join().unwrap();if let Err(e)=caught {std::panic::resume_unwind(e);}
    assert!(!f.base.join("store/manifests").join(format!("{root}.json")).exists());
}
