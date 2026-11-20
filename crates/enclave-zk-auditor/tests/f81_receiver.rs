//! Actual auditor request handlers and private executable with independent fixture trust.
use enclave_crypto::pqc::HybridSigningKey;
use enclave_zk_auditor::receiver_trust::ReceiverTrust;
use enclave_zk_auditor::rollup::ComplianceRollupProofV1 as Frame;
// Positive receiver fixtures use the same private proof/key format as ZkService.
use enclave_zk_auditor::zk::engine::{EpochStatement,SlotKind,prove_epoch_private as prove_epoch,hiding_vk_digest as vk_digest};
use enclave_zk_auditor::service::{ZkConfig,ZkRequest,ZkResponse,ZkService,Peers};
use enclave_core::{error::EnclaveResult,ipc::{self,PeerCredentials},profile::Profile};
use std::os::unix::fs::{DirBuilderExt,PermissionsExt};
struct Fixture {key:HybridSigningKey,first:Vec<u8>,second:Vec<u8>,forged_second:Vec<u8>,foreign:Vec<u8>}
fn fixtures()->&'static Fixture {
    static FIXTURE:std::sync::OnceLock<Fixture>=std::sync::OnceLock::new();
    FIXTURE.get_or_init(||{
        let key=HybridSigningKey::generate();let other=HybridSigningKey::generate();
        let nullifier_e=[4;32];
        let root=enclave_zk_auditor::cohort::digest_bytes(&enclave_core::poseidon2::hash_bytes(b"MCPMac-QifTree-v1",&nullifier_e));
        let st=EpochStatement {vk_digest:vk_digest(),profile:2,policy_blake3:[1;32],tuf_snapshot_root:[2;32],qif_cap_mb:12000,r_fleet_pk:[3;32],
            j_prev:[4;32],j_curr:[5;32],nullifier_e,qif_root_prev:root,qif_root_curr:root,s_start:1,s_end:1,used_in:0,used_out:3,cohort_size:0};
        let make=|statement:&EpochStatement,key:&HybridSigningKey|{
            let proof=prove_epoch(statement,&[SlotKind::Fold {delta_mb:3}]).unwrap();
            Frame::build(statement,proof,None,false,Some(vec![Frame::sign_l2_hybrid_anchor(statement,key)])).unwrap()
        };
        let first=make(&st,&key);let foreign=make(&st,&other);
        let next=EpochStatement {j_prev:st.j_curr,j_curr:[6;32],s_start:2,s_end:2,used_in:3,used_out:6,..st};
        let second=make(&next,&key);let forged_second=make(&next,&other);
        Fixture {key,first,second,forged_second,foreign}
    })
}
struct Directory(std::path::PathBuf);
impl Directory {fn new()->Self {
    let path=std::path::PathBuf::from("/tmp").join(format!("f81-{:x}",enclave_core::rng::u64()));
    std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();Self(path.canonicalize().unwrap())
}}
impl Drop for Directory {fn drop(&mut self){let _=std::fs::remove_dir_all(&self.0);}}
struct NoPeers;
impl Peers for NoPeers {
    fn cosign(&self,_:enclave_core::daemon::DaemonId,_:u64,_:&str)->EnclaveResult<(Vec<u8>,Vec<u8>)>{unreachable!()}
    fn prepare_relay(&self,_:&[u8])->EnclaveResult<enclave_core::ipc::PreparedCall>{unreachable!()}
    fn fetch_witness(&self,_:&str,_:u64,_:u64)->EnclaveResult<(Vec<enclave_zk_auditor::witness::WitnessFold>,u64)>{unreachable!()}
    fn boot_epoch(&self)->EnclaveResult<enclave_core::seq::BootEpoch>{unreachable!()}
}
fn service(dir:&Directory,trust:bool)->std::sync::Arc<ZkService> {
    let mut config=ZkConfig::new(Profile::L2,dir.0.clone());
    if trust {config.receiver_trust=Some(ReceiverTrust::l2_anchor(fixtures().key.verifying_key()).unwrap());}
    ZkService::start(config,Box::new(NoPeers)).unwrap()
}
fn frame(bytes:&[u8])->ZkRequest {ZkRequest::VerifyFrame {frame:bytes.to_vec().into()}}
fn series(bytes:&[&[u8]])->ZkRequest {ZkRequest::VerifySeries {frames:bytes.iter().map(|b|b.to_vec().into()).collect()}}
fn owner()->PeerCredentials {PeerCredentials::local(ipc::geteuid(),0)}
#[test]
fn actual_handlers_deny_missing_trust_and_foreign_signer_but_preserve_valid_frames_and_series() {
    let f=fixtures();let absent=Directory::new();let unconfigured=service(&absent,false);
    assert!(unconfigured.handle(&owner(),frame(&f.first)).unwrap_err().is("ROLLUP_RECEIVER_TRUST_REQUIRED"));
    assert!(unconfigured.handle(&owner(),series(&[&f.first,&f.second])).unwrap_err().is("ROLLUP_RECEIVER_TRUST_REQUIRED"));
    let configured=Directory::new();let s=service(&configured,true);
    assert!(matches!(s.handle(&owner(),frame(&f.first)).unwrap(),ZkResponse::Verified {profile:2,slots:1}));
    assert!(s.handle(&owner(),frame(&f.foreign)).is_err());
    assert!(matches!(s.handle(&owner(),series(&[&f.first,&f.second])).unwrap(),ZkResponse::SeriesVerified {profile:2,total_slots:2,used_out:6}));
    let err=s.handle(&owner(),series(&[&f.first,&f.forged_second])).unwrap_err();
    assert!(err.is("SERIES_FRAME_INVALID"),"{err}");
    assert!(s.handle(&owner(),series(&[&f.second,&f.first])).is_err(),"trust must not bypass chain checks");
}
fn document()->Vec<u8> {serde_json::to_vec(&serde_json::json!({"v":1,"authority":{"kind":"l2_hybrid_anchor","public_key_hex":hex::encode(fixtures().key.verifying_key().to_bytes())}})).unwrap()}
#[test]
fn bounded_trust_configuration_and_protected_operator_file_fail_closed() {
    let f=fixtures();let dir=Directory::new();let file=dir.0.join("trust.json");
    std::fs::write(&file,document()).unwrap();
    ReceiverTrust::from_operator_file(&file).unwrap().verify(&f.first,&[vk_digest()]).unwrap();
    for bytes in [b"{}".to_vec(),vec![b'x';16385],br#"{"v":2,"authority":{"kind":"l3_cohort","root_hex":"00","size":32}}"#.to_vec(),br#"{"v":1,"authority":{"kind":"l3_cohort","root_hex":"00","size":31}}"#.to_vec()] {assert!(ReceiverTrust::from_json(&bytes).is_err());}
    use std::os::unix::fs::symlink;
    symlink(&file,dir.0.join("symlink")).unwrap();assert!(ReceiverTrust::from_operator_file(&dir.0.join("symlink")).is_err());
    std::fs::set_permissions(&file,std::fs::Permissions::from_mode(0o666)).unwrap();assert!(ReceiverTrust::from_operator_file(&file).is_err());
    let fifo=dir.0.join("fifo");let c=std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe {libc::mkfifo(c.as_ptr(),0o600)},0);assert!(ReceiverTrust::from_operator_file(&fifo).is_err());
}
#[cfg(target_os = "macos")]
#[test]
fn actual_private_daemon_entry_loads_receiver_file_and_uses_strict_handler() {
    let f=fixtures();let dir=Directory::new();let trust=dir.0.join("trust.json");std::fs::write(&trust,document()).unwrap();
    // Private same-UID CAS transport supplies a validated fixture host floor.
    // It is intentionally not production TUF/signing evidence.
    #[derive(serde::Deserialize)] enum CasRequest {FetchHostConfig}
    #[derive(serde::Serialize)] enum CasResponse {Bytes(serde_bytes::ByteBuf)}
    let host=enclave_core::host_config::EnclaveHostConfig {
        profile_floor:Profile::L2,ifc_grant_public_key:"01".repeat(32),ohttp_key_config:None,
        calibration_corpus_digest:"02".repeat(32),vk_digest:"03".repeat(32),mcp_lock_digest:"04".repeat(32),fido_mds_allowlist_digest:"05".repeat(32),codesign_pins:None,
    }.to_json_bytes().unwrap();
    let stop=std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));let halted=stop.clone();
    let listener=ipc::bind(&dir.0.join("cas/cas.sock"),ipc::SocketAccess::OwnerOnly).unwrap();
    let server=std::thread::spawn(move||ipc::serve::<CasRequest,CasResponse,_>(listener,ipc::PeerPolicy::allow([ipc::geteuid()]),
        std::sync::Arc::new(move|_:&PeerCredentials,_|Ok(CasResponse::Bytes(host.clone().into()))),halted).unwrap());
    struct Server(std::sync::Arc<std::sync::atomic::AtomicBool>,Option<std::thread::JoinHandle<()>>);
    impl Drop for Server {fn drop(&mut self){self.0.store(true,std::sync::atomic::Ordering::SeqCst);if let Some(t)=self.1.take(){let _=t.join();}}}
    let _server=Server(stop,Some(server));
    let child=std::process::Command::new(env!("CARGO_BIN_EXE_enclave-zk-auditor"))
        .args(["--dev-same-uid","--no-audit","--profile","L2","--socket-dir"]).arg(&dir.0)
        .arg("--state-dir").arg(dir.0.join("state")).arg("--rollup-trust-file").arg(trust)
        .stdout(std::process::Stdio::null()).spawn().unwrap();
    struct Child(std::process::Child);impl Drop for Child {fn drop(&mut self){let _=self.0.kill();let _=self.0.wait();}}
    let mut child=Child(child);let path=dir.0.join("zk/zk.sock");let deadline=std::time::Instant::now()+std::time::Duration::from_secs(10);
    while !path.exists(){assert!(child.0.try_wait().unwrap().is_none(),"daemon exited");assert!(std::time::Instant::now()<deadline);std::thread::sleep(std::time::Duration::from_millis(10));}
    let response:ZkResponse=ipc::Client::connect(&path,ipc::geteuid()).unwrap().call(&frame(&f.first)).unwrap();
    assert!(matches!(response,ZkResponse::Verified {profile:2,slots:1}));
    let result=ipc::Client::connect(&path,ipc::geteuid()).unwrap().call::<_,ZkResponse>(&frame(&f.foreign));assert!(result.is_err());
}
