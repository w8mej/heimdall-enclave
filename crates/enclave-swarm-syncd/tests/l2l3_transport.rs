//! Bounded fixtures use the same network adapters and admission paths as entry.
//! Synthetic authorities establish software behavior, not installed/hardware acceptance.
use std::io::Cursor;
use enclave_core::secret::SecretKey32;
use enclave_crypto::{namespace::{self,WrappedNamespaceKey},tuf::target_file};
use enclave_swarm_syncd::{bao,snapshot_publication::SnapshotPublisher,transport::oblivious::{EncryptedTarget,verify_encrypted_streams}};

fn encrypted(plain:&[u8],key:&SecretKey32)->(Vec<u8>,Vec<u8>,EncryptedTarget) {
    let root=*blake3::hash(plain).as_bytes();let mut ciphertext=Vec::new();let mut records=Vec::new();let leaves=plain.len().div_ceil(namespace::PLAINTEXT_SIZE);
    for (index,chunk) in plain.chunks(namespace::PLAINTEXT_SIZE).enumerate() {let (bytes,record)=namespace::encrypt_chunk(key,&root,index as u64,index+1==leaves,chunk).unwrap();ciphertext.extend(bytes);records.extend(record);}
    let descriptor=EncryptedTarget {version:1,ciphertext_bao_root:bao::bao_root(&ciphertext),ciphertext_length:ciphertext.len() as u64,key_index_bao_root:bao::bao_root(&records),key_index_length:records.len() as u64,
        key:WrappedNamespaceKey {namespace:"models".into(),epoch:1,wrapping_epoch:1,envelope_hex:"00".repeat(72)}};
    (bao::encode_bao_stream(&ciphertext).unwrap(),bao::encode_bao_stream(&records).unwrap(),descriptor)
}
#[test]
fn f38_encrypted_streams_authenticate_both_roots_before_decryption_and_bound_leafs() {
    let key=SecretKey32::new([7;32]);let plain:Vec<u8>=(0..100_000).map(|i|(i%251) as u8).collect();let (ciphertext,records,descriptor)=encrypted(&plain,&key);
    let tf=target_file(&plain,None);let mut result=Vec::new();
    verify_encrypted_streams(&tf,&descriptor,&key,Cursor::new(&ciphertext),Cursor::new(&records),|bytes|{assert!(bytes.len()<=16368);result.extend_from_slice(bytes);Ok(())}).unwrap();assert_eq!(result,plain);
    for corrupt_keys in [false,true] {let mut c=ciphertext.clone();let mut r=records.clone();if corrupt_keys {let n=r.len()-1;r[n]^=1;}else {let n=c.len()-1;c[n]^=1;}
        assert!(verify_encrypted_streams(&tf,&descriptor,&key,Cursor::new(c),Cursor::new(r),|_|Ok(())).is_err());}
    assert!(verify_encrypted_streams(&tf,&descriptor,&SecretKey32::new([8;32]),Cursor::new(&ciphertext),Cursor::new(&records),|_|Ok(())).is_err());
    assert!(verify_encrypted_streams(&tf,&descriptor,&key,Cursor::new(&ciphertext[..ciphertext.len()-1]),Cursor::new(&records),|_|Ok(())).is_err());
    for keys_trailing in [false,true] {let mut c=ciphertext.clone();let mut r=records.clone();if keys_trailing {r.push(0);}else{c.push(0);}assert!(verify_encrypted_streams(&tf,&descriptor,&key,Cursor::new(c),Cursor::new(r),|_|Ok(())).is_err());}
}

use std::{fs,io::{Read,Write},net::TcpListener,os::unix::fs::{DirBuilderExt,PermissionsExt},path::PathBuf,process::{Child,Command},sync::{Arc,atomic::{AtomicBool,Ordering}},time::{Duration,Instant}};
use enclave_core::{error::EnclaveResult,ipc::{self,PeerCredentials},profile::Profile,err};
use enclave_crypto::{namespace::CasKeyLease,tuf::RepoBuilder};
use enclave_swarm_syncd::{service::{CasConfig,CasService,CasRequest,CasResponse},transport::{oblivious::{ObliviousConfig,RangeRequest,response_plaintext},registry::{RegistryConfig,DistributionConfig,DISTRIBUTION_CONFIG_TARGET},custody::{NamespaceCustody,NamespaceRelease}}};
use rustls::pki_types::{CertificateDer,PrivateKeyDer,PrivatePkcs8KeyDer};
use serde::{Serialize,Deserialize};
use serde_json::json;

#[derive(Serialize,Deserialize)]
struct RelayInput {certificate:Vec<u8>,private_key:Vec<u8>,gateway_seed:Vec<u8>,objects:std::collections::BTreeMap<String,Vec<u8>>,quantum:u32,behavior:String}
fn gateway(seed:&[u8])->ohttp_rfc::KeyConfig {ohttp_rfc::KeyConfig::derive(7,ohttp_rfc::hpke::Kem::X25519Sha256,vec![ohttp_rfc::SymmetricSuite::new(ohttp_rfc::hpke::Kdf::HkdfSha256,ohttp_rfc::hpke::Aead::ChaCha20Poly1305)],seed).unwrap()}
/// This subprocess is a synthetic relay/gateway fixture. The deployment's
/// noncollusion policy is not asserted by colocating both roles in this fixture.
#[test]
fn _l3_relay_gateway_worker() {
    let Some(directory)=std::env::var_os("MCPMAC_L3_PRIVATE_FIXTURE") else{return;};let base=PathBuf::from(directory);
    let input:RelayInput=serde_json::from_slice(&fs::read(base.join("input.json")).unwrap()).unwrap();
    let gateway=ohttp_rfc::Server::new(gateway(&input.gateway_seed)).unwrap();
    let tls=rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider())).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(vec![CertificateDer::from(input.certificate)],PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(input.private_key))).unwrap();
    let tls=Arc::new(tls);let listener=TcpListener::bind("127.0.0.1:0").unwrap();listener.set_nonblocking(true).unwrap();// Publish readiness only after the complete address is visible; exists()
    // must never expose a newly-created, still-empty fixture file.
    fs::write(base.join("address.pending"),listener.local_addr().unwrap().to_string()).unwrap();
    fs::rename(base.join("address.pending"),base.join("address")).unwrap();let mut requests=0;
    while !base.join("stop").exists() {
        let (socket,_)=match listener.accept() {Ok(v)=>v,Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>{std::thread::sleep(Duration::from_millis(2));continue;},Err(e)=>panic!("{e}")};socket.set_nonblocking(false).unwrap();socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();socket.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut stream=rustls::StreamOwned::new(rustls::ServerConnection::new(tls.clone()).unwrap(),socket);
        let outcome=(||->std::io::Result<()> {
            let mut head=vec![];while !head.ends_with(b"\r\n\r\n") {if head.len()>=16384{return Err(std::io::ErrorKind::InvalidData.into());}let mut byte=[0];stream.read_exact(&mut byte)?;head.push(byte[0]);}
            let head=String::from_utf8(head).unwrap();assert!(head.starts_with("POST /relay HTTP/1.1\r\n"));assert!(!head.contains("models"));assert!(!head.contains("cas/range"));
            let length=head.lines().find_map(|line|line.strip_prefix("Content-Length: ")).unwrap().trim().parse::<usize>().unwrap();assert_eq!(length,input.quantum as usize);
            let mut request=vec![0;length];stream.read_exact(&mut request)?;assert!(!request.windows(6).any(|b|b==b"models"));
            let (plain,response)=gateway.decapsulate(&request).unwrap();let (path,body)=enclave_crypto::ohttp::bhttp_parse(&plain).unwrap();assert_eq!(path,"/v1/cas/range");let request:RangeRequest=serde_json::from_slice(&body).unwrap();assert_eq!(request.version,1);assert_eq!(request.namespace,"models");assert!(request.length as usize<=input.quantum as usize-80);
            let object=input.objects.get(&request.ciphertext_root).unwrap();let start=request.offset as usize;let end=start+request.length as usize;assert!(end<=object.len());requests+=1;fs::write(base.join("requests"),requests.to_string())?;fs::write(base.join("started"),b"started")?;
            if input.behavior=="slow" {std::thread::sleep(Duration::from_millis(350));}
            let offset=if input.behavior=="context" {request.offset+1}else{request.offset};
            let mut payload=object[start..end].to_vec();if (input.behavior=="ciphertext"||(input.behavior=="late-ciphertext"&&object.len()>100_000))&&!payload.is_empty(){let last=payload.len()-1;payload[last]^=1;}
            let mut plain=response_plaintext(offset,&payload,input.quantum).unwrap();if input.behavior=="padding" {let last=plain.len()-1;plain[last]=1;}
            let mut ciphertext=response.encapsulate(&plain).unwrap();assert_eq!(ciphertext.len(),input.quantum as usize);if input.behavior=="response-auth" {ciphertext[100]^=1;}
            let length=ciphertext.len()+usize::from(input.behavior=="length");
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nContent-Type: message/ohttp-res\r\nConnection: close\r\n\r\n").as_bytes())?;stream.write_all(&ciphertext)?;stream.conn.send_close_notify();stream.flush()?;Ok(())
        })();if let Err(error)=outcome {eprintln!("private OHTTP negative-control disconnect: {error}");}
    }
}
struct Relay {base:PathBuf,config:ObliviousConfig,child:Child}
impl Relay {
    fn new(objects:std::collections::BTreeMap<String,Vec<u8>>,behavior:&str)->Self {
        let base=std::env::temp_dir().join(format!("mc-f38-ohttp-{}",hex::encode(&enclave_core::rng::bytes32()[..10])));fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        let mut params=rcgen::CertificateParams::new(vec![]);params.is_ca=rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);params.key_usages=vec![rcgen::KeyUsagePurpose::KeyCertSign,rcgen::KeyUsagePurpose::DigitalSignature];let ca=rcgen::Certificate::from_params(params).unwrap();let cert=rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let seed=enclave_core::rng::bytes32();let quantum=65536;let config=ObliviousConfig {relay:RegistryConfig {address:"127.0.0.1:1".into(),server_name:"localhost".into(),repository:"fixture/relay".into(),tls_roots_der:vec![hex::encode(ca.serialize_der().unwrap())],timeout_ms:10000},gateway_config_hex:hex::encode(gateway(&seed).encode().unwrap()),required_kem:0x20,gateway_authority:"fixture.gateway.invalid".into(),quantum,sealed:enclave_swarm_syncd::snapshot_publication::SealedConfig {volume_device:"/dev/disk99s1".into(),source_mount:base.join("source"),mount_root:base.join("mounts")}};
        let input=RelayInput {certificate:cert.serialize_der_with_signer(&ca).unwrap(),private_key:cert.serialize_private_key_der(),gateway_seed:seed.to_vec(),objects,quantum,behavior:behavior.into()};fs::write(base.join("input.json"),serde_json::to_vec(&input).unwrap()).unwrap();fs::set_permissions(base.join("input.json"),fs::Permissions::from_mode(0o600)).unwrap();
        let child=Command::new(std::env::current_exe().unwrap()).args(["--exact","_l3_relay_gateway_worker","--nocapture"]).env("MCPMAC_L3_PRIVATE_FIXTURE",&base).spawn().unwrap();
        let mut relay=Self {base,config,child};let deadline=Instant::now()+Duration::from_secs(5);while !relay.base.join("address").exists() && Instant::now()<deadline {assert!(relay.child.try_wait().unwrap().is_none(),"fixture exited early");std::thread::sleep(Duration::from_millis(5));}
        relay.config.relay.address=fs::read_to_string(relay.base.join("address")).expect("bounded fixture startup");relay
    }
    fn requests(&self)->usize {fs::read_to_string(self.base.join("requests")).unwrap_or_else(|_|"0".into()).parse().unwrap()}
}
impl Drop for Relay {fn drop(&mut self){let _=fs::write(self.base.join("stop"),b"stop");let end=Instant::now()+Duration::from_secs(3);while Instant::now()<end {if self.child.try_wait().unwrap().is_some(){let _=fs::remove_dir_all(&self.base);return;}std::thread::sleep(Duration::from_millis(5));}let _=self.child.kill();let _=self.child.wait();let _=fs::remove_dir_all(&self.base);}}
#[derive(Debug)]
struct FixtureCustody {key:SecretKey32,valid:AtomicBool}
impl NamespaceCustody for FixtureCustody {
    fn unwrap(&self,key:&WrappedNamespaceKey)->EnclaveResult<NamespaceRelease> {if key.namespace!="models"||key.epoch!=1||!self.valid.load(Ordering::SeqCst){return Err(err!(EACCES,"FIXTURE_KEY_REMOVED"));}Ok(NamespaceRelease {key:self.key.clone(),lease:CasKeyLease {enterprise:None,id:"private-fixture".into(),namespace:key.namespace.clone(),key_epoch:key.epoch,boot_epoch:"private-fixture".into(),generation:1,expires_unix:2_000_000_000}})}
    fn revalidate(&self,_:&CasKeyLease)->EnclaveResult<()> {if self.valid.load(Ordering::SeqCst){Ok(())}else{Err(err!(EACCES,"FIXTURE_KEY_REMOVED"))}}
}
fn companion_payload()->&'static [u8] {b"{\"calibration\":\"private-fixture\"}"}
fn fixture_payload()->Vec<u8> {let mut bytes=vec![0u8;192*1024+43];blake3::Hasher::new_derive_key("F38 bounded encrypted fixture").finalize_xof().fill(&mut bytes);bytes[..4].copy_from_slice(b"DATA");bytes}

/// Inert platform: ordinary private test files, never APFS or mount syscalls.
#[derive(Debug)]
struct FixtureSnapshotPlatform {fail:&'static str,snapshots:std::sync::atomic::AtomicUsize}
/// Composed route fixture for the broker's absent-root no-effect contract.
/// Ownership persistence/ambiguity is tested against Broker itself in its unit
/// suite. A returned/reopened FD is never forgotten merely because paths vanish.
#[derive(Debug)]
struct FixturePublisher {
    inner:enclave_swarm_syncd::snapshot_publication::SystemSnapshotPublisher,
    config:enclave_swarm_syncd::snapshot_publication::SealedConfig,
    exposed:std::sync::Mutex<std::collections::BTreeSet<String>>,
}
impl SnapshotPublisher for FixturePublisher {
    fn publish(&self,file:&fs::File,target:&enclave_crypto::tuf::TargetFile)->EnclaveResult<fs::File>{let file=self.inner.publish(file,target)?;self.exposed.lock().unwrap().insert(target.hashes["blake3"].clone());Ok(file)}
    fn reopen(&self,target:&enclave_crypto::tuf::TargetFile)->EnclaveResult<fs::File>{let file=self.inner.reopen(target)?;self.exposed.lock().unwrap().insert(target.hashes["blake3"].clone());Ok(file)}
    fn revoke(&self,target:&enclave_crypto::tuf::TargetFile)->EnclaveResult<()> {
        let root=&target.hashes["blake3"];
        if !self.exposed.lock().unwrap().contains(root)
            && !self.config.source_mount.join("artifacts").join(root).try_exists().map_err(|_|err!(EIO,"FIXTURE_OBSERVATION"))?
            && !self.config.mount_root.join(root).try_exists().map_err(|_|err!(EIO,"FIXTURE_OBSERVATION"))? {return Ok(());}
        self.inner.revoke(target)?;self.exposed.lock().unwrap().remove(root);Ok(())
    }
}
impl enclave_swarm_syncd::snapshot_publication::SnapshotPlatform for FixtureSnapshotPlatform {
    fn enforce_holders(&self,file:&std::fs::File,_:&str)->enclave_core::error::EnclaveResult<()> {
        assert!(file.metadata().unwrap().is_file());Ok(()) // inert orchestration only
    }
    fn validate_source(&self,_:&enclave_swarm_syncd::snapshot_publication::SealedConfig)->EnclaveResult<()> {Ok(())}
    fn require_capacity(&self,_:&enclave_swarm_syncd::snapshot_publication::SealedConfig,_:u64)->EnclaveResult<()> {Ok(())}
    fn cleanup_mount(&self,_:&enclave_swarm_syncd::snapshot_publication::SealedConfig,_:&str,mount:&std::path::Path)->EnclaveResult<()> {if mount.join("artifacts").exists(){fs::remove_dir_all(mount.join("artifacts")).unwrap();}Ok(())}
    fn clone_stage(&self,staged:&fs::File,destination:&std::path::Path)->EnclaveResult<()> {let mut source=staged.try_clone().unwrap();use std::io::Seek;source.rewind().unwrap();let mut file=fs::File::create(destination).unwrap();std::io::copy(&mut source,&mut file).unwrap();Ok(())}
    fn create_snapshot(&self,_:&std::path::Path,_:&str)->EnclaveResult<()> {let count=self.snapshots.fetch_add(1,Ordering::SeqCst);if self.fail=="snapshot"||(self.fail=="second-snapshot"&&count==1){return Err(err!(EACCES,"FIXTURE_SNAPSHOT_REFUSAL"));}Ok(())}
    fn mount_snapshot(&self,config:&enclave_swarm_syncd::snapshot_publication::SealedConfig,name:&str,mount:&std::path::Path)->EnclaveResult<()> {if self.fail=="mount"{return Err(err!(EACCES,"FIXTURE_MOUNT_REFUSAL"));}fs::create_dir(mount.join("artifacts")).unwrap();for file in fs::read_dir(config.source_mount.join("artifacts")).unwrap(){let file=file.unwrap();fs::copy(file.path(),mount.join("artifacts").join(file.file_name())).unwrap();}fs::write(config.source_mount.parent().unwrap().join(format!("fixture-published-{name}")),b"published").unwrap();Ok(())}
    fn verify_mount(&self,_:&enclave_swarm_syncd::snapshot_publication::SealedConfig,_:&str,mount:&std::path::Path)->EnclaveResult<()> {if self.fail=="flags"{return Err(err!(EACCES,"FIXTURE_FLAGS_REFUSAL"));}if mount.join("artifacts").is_dir(){Ok(())}else{Err(err!(EACCES,"FIXTURE_NOT_MOUNTED"))}}
    fn unmount(&self,mount:&std::path::Path)->EnclaveResult<()> {fs::remove_dir_all(mount.join("artifacts")).unwrap();Ok(())}
    fn delete_snapshot(&self,_:&std::path::Path,_:&str)->EnclaveResult<()> {Ok(())}
}
struct ServiceFixture {base:PathBuf,service:Arc<CasService>,peer:PeerCredentials,uri:String,key:Arc<FixtureCustody>,repo:RepoBuilder,targets:std::collections::BTreeMap<String,enclave_crypto::tuf::TargetFile>}
impl ServiceFixture {
    fn new(config:&ObliviousConfig,descriptor:&EncryptedTarget,key:SecretKey32)->Self {Self::new_with_failure(config,descriptor,key,"")}
    fn new_with_failure(config:&ObliviousConfig,descriptor:&EncryptedTarget,key:SecretKey32,fail:&'static str)->Self {Self::new_options(config,descriptor,key,fail,None)}
    fn new_options(config:&ObliviousConfig,descriptor:&EncryptedTarget,key:SecretKey32,fail:&'static str,companion:Option<&EncryptedTarget>)->Self {
        let companions=companion.map(|descriptor|vec![("calibration.json".into(),companion_payload().to_vec(),descriptor.clone())]).unwrap_or_default();Self::new_closure(config,descriptor,key,fail,companions)
    }
    fn new_closure(config:&ObliviousConfig,descriptor:&EncryptedTarget,key:SecretKey32,fail:&'static str,companions:Vec<(String,Vec<u8>,EncryptedTarget)>)->Self {
        let base=std::env::temp_dir().join(format!("mc-f38-l3-cas-{}",hex::encode(&enclave_core::rng::bytes32()[..10])));fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        let repo=RepoBuilder::new(3,2);let root=repo.root("2030-01-01T00:00:00Z").unwrap();let service=CasService::start(CasConfig {dev_same_uid: true, profile:Profile::L3,store_dir:base.join("store"),audit_path:Some(base.join("audit.jsonl")),tuf_root:Some(root),ohttp_gateway:None,state_dir:None,revocation:enclave_swarm_syncd::revocation::Enforcement::InProcess}).unwrap();
        // Snapshot configuration requires absolute canonical paths even when
        // TMPDIR is relative to keep Darwin's owned IPC fixture paths short.
        let absolute_base=fs::canonicalize(&base).unwrap();
        let mut config=config.clone();config.sealed.source_mount=absolute_base.join("source");config.sealed.mount_root=absolute_base.join("mounts");
        for directory in [&config.sealed.source_mount,&config.sealed.mount_root] {fs::DirBuilder::new().mode(0o700).create(directory).unwrap();}
        let publisher=enclave_swarm_syncd::snapshot_publication::SystemSnapshotPublisher::with_platform(config.sealed.clone(),Arc::new(FixtureSnapshotPlatform {fail,snapshots:std::sync::atomic::AtomicUsize::new(0)})).unwrap();
        service.set_snapshot_publisher(Arc::new(FixturePublisher{inner:publisher,config:config.sealed.clone(),exposed:Default::default()})).unwrap();
        let config=serde_json::to_vec(&DistributionConfig {version:1,l1:None,l2:None,l3:Some(config.clone())}).unwrap();fs::write(base.join("store").join(DISTRIBUTION_CONFIG_TARGET),&config).unwrap();
        let payload=fixture_payload();let mut targets=std::collections::BTreeMap::new();let mut custom=json!({"classification":"restricted_l3","min_profile":"L3","license_policy":{"spdx_id":"LicenseRef-private-fixture","allow_p2p_seeding":false},"encrypted_transport":descriptor});
        let mut eager=Vec::new();for (name,bytes,companion) in companions {
            eager.push(json!({"role":name,"blake3":blake3::hash(&bytes).to_hex().to_string(),"eager_hydrate_required":true}));
            targets.insert(name,target_file(&bytes,Some(json!({"classification":"restricted_l3","min_profile":"L3","license_policy":{"spdx_id":"LicenseRef-private-fixture","allow_p2p_seeding":false},"encrypted_transport":companion}))));
        }
        if !eager.is_empty(){custom["companion_safety_layers"]=json!(eager);}
        targets.insert("model.bin".into(),target_file(&payload,Some(custom)));targets.insert(DISTRIBUTION_CONFIG_TARGET.into(),target_file(&config,Some(json!({}))));
        let signed_targets=repo.targets(1,"2030-01-01T00:00:00Z",targets.clone()).unwrap();let snapshot=repo.snapshot(1,"2030-01-01T00:00:00Z",1,&signed_targets).unwrap();let timestamp=repo.timestamp(1,"2030-01-01T00:00:00Z",1,&snapshot).unwrap();let mut peer=PeerCredentials::local(ipc::geteuid(),0);peer.pid=Some(std::process::id() as i32);service.handle(&peer,CasRequest::TufRefresh {roots:vec![],timestamp:timestamp.into(),snapshot:snapshot.into(),targets:signed_targets.into()}).unwrap();
        let key=Arc::new(FixtureCustody {key,valid:AtomicBool::new(true)});service.set_namespace_custody(key.clone()).unwrap();let uri=format!("cas://blake3-bao-v1/{}?target=model.bin&ns=models",blake3::hash(&payload).to_hex());Self {base,service,peer,uri,key,repo,targets}
    }
    fn hydrate(&self)->EnclaveResult<CasResponse>{self.service.handle(&self.peer,CasRequest::Hydrate {cas_uri:self.uri.clone()})}
    fn unpublished(&self){let root=blake3::hash(&fixture_payload()).to_hex().to_string();assert!(!self.base.join("store/manifests").join(format!("{root}.json")).exists());assert!(!fs::read_to_string(self.base.join("audit.jsonl")).unwrap().contains("\"event\":\"HYDRATED\""));assert!(fs::read_dir(self.base.join("store/streaming-stages")).unwrap().all(|e|!e.unwrap().file_name().to_string_lossy().starts_with("stage-")));}
}
impl Drop for ServiceFixture {fn drop(&mut self){let _=fs::remove_dir_all(&self.base);}}
fn relay_objects(ciphertext:Vec<u8>,records:Vec<u8>,descriptor:&EncryptedTarget)->std::collections::BTreeMap<String,Vec<u8>> {[(descriptor.ciphertext_bao_root.clone(),ciphertext),(descriptor.key_index_bao_root.clone(),records)].into_iter().collect()}
fn assert_ohttp_stages(fixture:&ServiceFixture,started:u64,ok:u64,err:u64) {
    let CasResponse::SyncDiagnostics(snapshot)=fixture.service.handle(&fixture.peer,CasRequest::SyncDiagnostics).unwrap() else {panic!("typed diagnostics");};
    assert!(snapshot.valid_measurement());assert_eq!(snapshot.availability,enclave_swarm_syncd::sync_diagnostics::CounterAvailability::Current);
    let stages=snapshot.stages.unwrap();
    assert_eq!(stages.registry_fetch,enclave_swarm_syncd::sync_diagnostics::StageCounters::default());
    assert_eq!(stages.quic_fetch,enclave_swarm_syncd::sync_diagnostics::StageCounters::default());
    assert_eq!(stages.ohttp_fetch,enclave_swarm_syncd::sync_diagnostics::StageCounters {started,in_flight:0,returned_ok:ok,returned_err:err,abandoned_unknown:0});
}
#[test]
fn f38_l3_real_rfc_ohttp_empty_cache_hydrate_and_exact_readonly_open_target() {
    let key=SecretKey32::new([7;32]);let (ciphertext,records,descriptor)=encrypted(&fixture_payload(),&key);let relay=Relay::new(relay_objects(ciphertext,records,&descriptor),"good");let fixture=ServiceFixture::new(&relay.config,&descriptor,key);
    let listener=ipc::bind(&fixture.base.join("cas.sock"),ipc::SocketAccess::OwnerOnly).unwrap();let stop=Arc::new(AtomicBool::new(false));let flag=stop.clone();let svc=fixture.service.clone();
    let thread=std::thread::spawn(move||ipc::serve::<CasRequest,CasResponse,_>(listener,ipc::PeerPolicy::allow([ipc::geteuid()]),Arc::new(move|p:&PeerCredentials,r|svc.handle(p,r)),flag).unwrap());
    let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut client=ipc::Client::connect(&fixture.base.join("cas.sock"),ipc::geteuid()).unwrap();client.set_timeout(Some(Duration::from_secs(15))).unwrap();
        let response:CasResponse=client.call(&CasRequest::OpenTarget {target:"model.bin".into()}).unwrap();assert!(matches!(response,CasResponse::TargetFile {fds:1,length,..} if length==fixture_payload().len() as u64));
        let mut fds=client.recv_fds(4).unwrap();assert_eq!(fds.len(),1);let mut file=fs::File::from(fds.pop().unwrap());let mut bytes=Vec::new();file.read_to_end(&mut bytes).unwrap();assert_eq!(bytes,fixture_payload());assert!(file.write_all(b"X").is_err());
        use std::os::unix::fs::MetadataExt;
        let root=blake3::hash(&fixture_payload()).to_hex().to_string();let mounted=fs::metadata(fixture.base.join("mounts").join(&root).join("artifacts").join(&root)).unwrap();assert_eq!(file.metadata().unwrap().ino(),mounted.ino(),"SCM_RIGHTS must deliver the published snapshot fixture inode");
        let count=relay.requests();assert!(count>1);let response:CasResponse=client.call(&CasRequest::Hydrate {cas_uri:fixture.uri.clone()}).unwrap();assert!(matches!(response,CasResponse::Admitted {..}));assert_eq!(relay.requests(),count,"cached use must not refetch");
        let foreign=fixture.uri.replace("ns=models","ns=foreign");for request in [CasRequest::Hydrate{cas_uri:foreign.clone()},CasRequest::Resolve{cas_uri:foreign.clone()},CasRequest::Fetch{cas_uri:foreign}] {assert!(client.call::<_,CasResponse>(&request).is_err());}
        fixture.key.valid.store(false,Ordering::SeqCst);assert!(client.call::<_,CasResponse>(&CasRequest::Hydrate {cas_uri:fixture.uri.clone()}).is_err());
    }));
    stop.store(true,Ordering::SeqCst);thread.join().unwrap();if let Err(error)=result {std::panic::resume_unwind(error);}
    assert_ohttp_stages(&fixture,1,1,0);
}
#[test]
fn f38_l3_response_crypto_context_padding_length_and_bao_fail_without_publication() {
    for behavior in ["response-auth","context","padding","length","ciphertext"] {let key=SecretKey32::new([7;32]);let (ciphertext,records,descriptor)=encrypted(&fixture_payload(),&key);let relay=Relay::new(relay_objects(ciphertext,records,&descriptor),behavior);let fixture=ServiceFixture::new(&relay.config,&descriptor,key);assert!(fixture.hydrate().is_err(),"{behavior}");fixture.unpublished();assert!(relay.requests()>0);assert_ohttp_stages(&fixture,1,0,1);}
}
#[test]
fn f38_l3_custody_removal_and_wipe_interrupt_network_without_success_receipt() {
    for wipe in [false,true] {let key=SecretKey32::new([7;32]);let (ciphertext,records,descriptor)=encrypted(&fixture_payload(),&key);let relay=Relay::new(relay_objects(ciphertext,records,&descriptor),"slow");let fixture=ServiceFixture::new(&relay.config,&descriptor,key);let svc=fixture.service.clone();let peer=fixture.peer.clone();let uri=fixture.uri.clone();let thread=std::thread::spawn(move||svc.handle(&peer,CasRequest::Hydrate {cas_uri:uri}));let deadline=Instant::now()+Duration::from_secs(3);while !relay.base.join("started").exists()&&Instant::now()<deadline {std::thread::sleep(Duration::from_millis(2));}if !relay.base.join("started").exists(){let outcome=thread.join().unwrap();panic!("actual service exited before the first relay request: {outcome:?}");}
        if wipe {fixture.service.handle(&fixture.peer,CasRequest::Wipe).unwrap();}else{fixture.key.valid.store(false,Ordering::SeqCst);}assert!(thread.join().unwrap().is_err());fixture.unpublished();assert_ohttp_stages(&fixture,1,0,1);}
}

#[test]
fn f38_l3_snapshot_failures_follow_real_network_and_never_publish_or_receipt() {
    for failure in ["snapshot","mount","flags"] {
        let key=SecretKey32::new([7;32]);let (ciphertext,records,descriptor)=encrypted(&fixture_payload(),&key);let relay=Relay::new(relay_objects(ciphertext,records,&descriptor),"good");let fixture=ServiceFixture::new_with_failure(&relay.config,&descriptor,key,failure);
        assert!(fixture.hydrate().is_err(),"{failure}");assert!(relay.requests()>1);fixture.unpublished();
        assert_ohttp_stages(&fixture,1,1,0);
        let root=blake3::hash(&fixture_payload()).to_hex().to_string();
        if failure=="snapshot" {
            // A create error has an ambiguous effect. Preserve its evidence;
            // the broker ownership tests separately prove refusal on retry.
            assert!(fixture.base.join("mounts").join(&root).exists());assert!(fixture.base.join("source/artifacts").join(&root).exists());
        }else{assert!(!fixture.base.join("mounts").join(&root).exists());assert!(!fixture.base.join("source/artifacts").join(&root).exists());}
    }
}
#[test]
fn f38_l3_wipe_retracts_published_snapshot_and_cached_access_refuses_plain_cas_fallback() {
    let key=SecretKey32::new([7;32]);let (ciphertext,records,descriptor)=encrypted(&fixture_payload(),&key);let relay=Relay::new(relay_objects(ciphertext,records,&descriptor),"good");let fixture=ServiceFixture::new(&relay.config,&descriptor,key);
    fixture.hydrate().unwrap();fixture.service.handle(&fixture.peer,CasRequest::Wipe).unwrap();
    let root=blake3::hash(&fixture_payload()).to_hex().to_string();assert!(!fixture.base.join("mounts").join(&root).exists());assert!(!fixture.base.join("source/artifacts").join(&root).exists());
    assert!(fixture.hydrate().is_err());assert!(fixture.service.handle(&fixture.peer,CasRequest::OpenTarget{target:"model.bin".into()}).is_err());assert!(fixture.service.handle(&fixture.peer,CasRequest::Resolve{cas_uri:fixture.uri.clone()}).is_err());assert!(fixture.service.handle(&fixture.peer,CasRequest::Fetch{cas_uri:fixture.uri.clone()}).is_err());
}

#[test]
fn f38_l3_full_closure_network_verification_precedes_publication_and_later_publication_failure_rolls_back() {
    for network_failure in [true,false] {
        let key=SecretKey32::new([7;32]);let (ciphertext,records,descriptor)=encrypted(&fixture_payload(),&key);let (companion,companion_keys,companion_descriptor)=encrypted(companion_payload(),&key);
        let mut objects=relay_objects(ciphertext,records,&descriptor);objects.extend(relay_objects(companion,companion_keys,&companion_descriptor));let relay=Relay::new(objects,if network_failure{"late-ciphertext"}else{"good"});let fixture=ServiceFixture::new_options(&relay.config,&descriptor,key,if network_failure{""}else{"second-snapshot"},Some(&companion_descriptor));
        assert!(fixture.hydrate().is_err());fixture.unpublished();assert_ohttp_stages(&fixture,2,if network_failure{1}else{2},u64::from(network_failure));let root=blake3::hash(companion_payload()).to_hex().to_string();
        assert_eq!(fixture.base.join(format!("fixture-published-cas-{root}")).exists(),!network_failure,"all network verification precedes any publication; local second-publication failure must roll back the first");
        assert!(!fixture.base.join("store/manifests").join(format!("{root}.json")).exists());assert!(!fixture.base.join("mounts").join(&root).exists());assert!(!fixture.base.join("source/artifacts").join(&root).exists());
    }
}

#[derive(Debug)]
struct RetryPublisher {inner:enclave_swarm_syncd::snapshot_publication::SystemSnapshotPublisher,fail_once:AtomicBool,calls:std::sync::atomic::AtomicUsize}
impl enclave_swarm_syncd::snapshot_publication::SnapshotPublisher for RetryPublisher {
    fn publish(&self,file:&fs::File,target:&enclave_crypto::tuf::TargetFile)->EnclaveResult<fs::File> {self.inner.publish(file,target)}
    fn reopen(&self,target:&enclave_crypto::tuf::TargetFile)->EnclaveResult<fs::File> {self.inner.reopen(target)}
    fn revoke(&self,target:&enclave_crypto::tuf::TargetFile)->EnclaveResult<()> {self.calls.fetch_add(1,Ordering::SeqCst);if self.fail_once.swap(false,Ordering::SeqCst){return Err(err!(EAGAIN,"FIXTURE_TEARDOWN_BUSY"));}self.inner.revoke(target)}
}
#[derive(Debug)]
struct LostReplyPublisher {inner:enclave_swarm_syncd::snapshot_publication::SystemSnapshotPublisher,fail_cleanup_once:AtomicBool,retractions:std::sync::atomic::AtomicUsize}
impl SnapshotPublisher for LostReplyPublisher {
    fn publish(&self,file:&fs::File,target:&enclave_crypto::tuf::TargetFile)->EnclaveResult<fs::File>{drop(self.inner.publish(file,target)?);Err(err!(EIO,"FIXTURE_LOST_PUBLICATION_REPLY"))}
    fn reopen(&self,target:&enclave_crypto::tuf::TargetFile)->EnclaveResult<fs::File>{self.inner.reopen(target)}
    fn revoke(&self,target:&enclave_crypto::tuf::TargetFile)->EnclaveResult<()>{self.retractions.fetch_add(1,Ordering::SeqCst);if self.fail_cleanup_once.swap(false,Ordering::SeqCst){return Err(err!(EAGAIN,"FIXTURE_TEARDOWN_BUSY"));}self.inner.revoke(target)}
}
#[test]
fn f38_l3_lost_publication_reply_retains_original_retraction_authority_until_wipe_retry() {
    use enclave_swarm_syncd::snapshot_publication::{SealedConfig,SystemSnapshotPublisher};
    for fail_cleanup in [false,true] {
        let key=SecretKey32::new([7;32]);let (ciphertext,records,descriptor)=encrypted(&fixture_payload(),&key);let relay=Relay::new(relay_objects(ciphertext,records,&descriptor),"good");let fixture=ServiceFixture::new(&relay.config,&descriptor,key);
        let publisher=Arc::new(LostReplyPublisher{inner:SystemSnapshotPublisher::with_platform(SealedConfig{volume_device:"/dev/disk99s1".into(),source_mount:fs::canonicalize(&fixture.base).unwrap().join("source"),mount_root:fs::canonicalize(&fixture.base).unwrap().join("mounts")},Arc::new(FixtureSnapshotPlatform{fail:"",snapshots:std::sync::atomic::AtomicUsize::new(0)})).unwrap(),fail_cleanup_once:AtomicBool::new(fail_cleanup),retractions:std::sync::atomic::AtomicUsize::new(0)});
        fixture.service.set_snapshot_publisher(publisher.clone()).unwrap();let error=fixture.hydrate().unwrap_err();assert!(error.is(if fail_cleanup{"FIXTURE_TEARDOWN_BUSY"}else{"FIXTURE_LOST_PUBLICATION_REPLY"}));fixture.unpublished();
        assert_ohttp_stages(&fixture,1,1,0);
        let root=blake3::hash(&fixture_payload()).to_hex().to_string();assert_eq!(fixture.base.join("mounts").join(&root).exists(),fail_cleanup);
        if fail_cleanup {
            // New injected routing must never replace the original attempted
            // publication's cleanup capability after its reply was lost.
            fixture.service.set_snapshot_publisher(Arc::new(WrongPublisher)).unwrap();
            assert!(matches!(fixture.service.handle(&fixture.peer,CasRequest::Wipe).unwrap(),CasResponse::Wiped));
            assert_eq!(publisher.retractions.load(Ordering::SeqCst),2);assert!(!fixture.base.join("mounts").join(&root).exists());assert!(!fixture.base.join("source/artifacts").join(&root).exists());
        }else{assert_eq!(publisher.retractions.load(Ordering::SeqCst),1);}
    }
}

#[derive(Debug)]
struct WrongPublisher;
impl SnapshotPublisher for WrongPublisher {
    fn publish(&self,_:&fs::File,_:&enclave_crypto::tuf::TargetFile)->EnclaveResult<fs::File>{Err(err!(EACCES,"FIXTURE_WRONG_PUBLISHER"))}
    fn reopen(&self,_:&enclave_crypto::tuf::TargetFile)->EnclaveResult<fs::File>{Err(err!(EACCES,"FIXTURE_WRONG_PUBLISHER"))}
    fn revoke(&self,_:&enclave_crypto::tuf::TargetFile)->EnclaveResult<()>{Err(err!(EACCES,"FIXTURE_WRONG_PUBLISHER"))}
}
#[test]
fn f38_l3_revocation_retry_keeps_original_volume_authority_after_signed_config_rotation() {
    use enclave_swarm_syncd::snapshot_publication::{SealedConfig,SystemSnapshotPublisher};
    let key=SecretKey32::new([7;32]);let (ciphertext,records,descriptor)=encrypted(&fixture_payload(),&key);let relay=Relay::new(relay_objects(ciphertext,records,&descriptor),"good");let fixture=ServiceFixture::new(&relay.config,&descriptor,key);
    let publisher=Arc::new(RetryPublisher {inner:SystemSnapshotPublisher::with_platform(SealedConfig{volume_device:"/dev/disk99s1".into(),source_mount:fs::canonicalize(&fixture.base).unwrap().join("source"),mount_root:fs::canonicalize(&fixture.base).unwrap().join("mounts")},Arc::new(FixtureSnapshotPlatform{fail:"",snapshots:std::sync::atomic::AtomicUsize::new(0)})).unwrap(),fail_once:AtomicBool::new(false),calls:std::sync::atomic::AtomicUsize::new(0)});
    fixture.service.set_snapshot_publisher(publisher.clone()).unwrap();fixture.hydrate().unwrap();publisher.fail_once.store(true,Ordering::SeqCst);fixture.service.set_snapshot_publisher(Arc::new(WrongPublisher)).unwrap();
    let mut targets=fixture.targets.clone();targets.get_mut("model.bin").unwrap().custom.as_mut().unwrap()["revoked"]=json!(true);
    let mut config:DistributionConfig=serde_json::from_slice(&fs::read(fixture.base.join("store").join(DISTRIBUTION_CONFIG_TARGET)).unwrap()).unwrap();let sealed=&mut config.l3.as_mut().unwrap().sealed;sealed.source_mount=fs::canonicalize(&fixture.base).unwrap().join("rotated-source");sealed.mount_root=fs::canonicalize(&fixture.base).unwrap().join("rotated-mounts");let bytes=serde_json::to_vec(&config).unwrap();fs::write(fixture.base.join("store").join(DISTRIBUTION_CONFIG_TARGET),&bytes).unwrap();targets.insert(DISTRIBUTION_CONFIG_TARGET.into(),target_file(&bytes,Some(json!({}))));
    for version in [2,3] {let signed=fixture.repo.targets(version,"2030-01-01T00:00:00Z",targets.clone()).unwrap();let snapshot=fixture.repo.snapshot(version,"2030-01-01T00:00:00Z",version,&signed).unwrap();let timestamp=fixture.repo.timestamp(version,"2030-01-01T00:00:00Z",version,&snapshot).unwrap();let result=fixture.service.handle(&fixture.peer,CasRequest::TufRefresh{roots:vec![],timestamp:timestamp.into(),snapshot:snapshot.into(),targets:signed.into()});if version==2 {assert!(result.unwrap_err().is("FIXTURE_TEARDOWN_BUSY"));}else{result.unwrap();}}
    assert_eq!(publisher.calls.load(Ordering::SeqCst),2,"retry must preserve the original publisher despite new signed routing");let root=blake3::hash(&fixture_payload()).to_hex().to_string();assert!(!fixture.base.join("mounts").join(&root).exists());assert!(!fixture.base.join("source/artifacts").join(root).exists());
}

#[test]
fn f38_l3_concurrent_same_root_plan_cannot_retract_another_successful_plan() {
    let key=SecretKey32::new([7;32]);let (ciphertext,records,descriptor)=encrypted(&fixture_payload(),&key);let relay=Relay::new(relay_objects(ciphertext,records,&descriptor),"slow");let fixture=ServiceFixture::new(&relay.config,&descriptor,key);let service=fixture.service.clone();let peer=fixture.peer.clone();let uri=fixture.uri.clone();
    let first=std::thread::spawn(move||service.handle(&peer,CasRequest::Hydrate{cas_uri:uri}));let deadline=Instant::now()+Duration::from_secs(3);while !relay.base.join("started").exists()&&Instant::now()<deadline{std::thread::sleep(Duration::from_millis(2));}assert!(relay.base.join("started").exists());
    assert!(fixture.hydrate().unwrap_err().is("DOWNLOAD_ALREADY_ACTIVE"));assert!(matches!(first.join().unwrap().unwrap(),CasResponse::Admitted{..}));assert!(fixture.hydrate().is_ok());let root=blake3::hash(&fixture_payload()).to_hex().to_string();assert!(fixture.base.join("mounts").join(root).exists());assert_ohttp_stages(&fixture,1,1,0);
}

#[test]
fn f38_l3_five_artifact_eager_closure_preserves_session_limit_and_completes_atomically() {
    let key=SecretKey32::new([7;32]);let (ciphertext,records,descriptor)=encrypted(&fixture_payload(),&key);let mut objects=relay_objects(ciphertext,records,&descriptor);let mut companions=Vec::new();let mut roots=Vec::new();
    for index in 0..4 {let bytes=serde_json::to_vec(&json!({"calibration":index})).unwrap();let (ciphertext,records,descriptor)=encrypted(&bytes,&key);objects.extend(relay_objects(ciphertext,records,&descriptor));roots.push(blake3::hash(&bytes).to_hex().to_string());companions.push((format!("calibration-{index}.json"),bytes,descriptor));}
    let relay=Relay::new(objects,"good");let fixture=ServiceFixture::new_closure(&relay.config,&descriptor,key,"",companions);assert!(matches!(fixture.hydrate().unwrap(),CasResponse::Admitted{..}));
    roots.push(blake3::hash(&fixture_payload()).to_hex().to_string());for root in roots {assert!(fixture.base.join("mounts").join(&root).join("artifacts").join(&root).exists());assert!(fixture.base.join("store/manifests").join(format!("{root}.json")).exists());}
    let requests=relay.requests();assert!(fixture.hydrate().is_ok());assert_eq!(relay.requests(),requests);assert_ohttp_stages(&fixture,5,5,0);
}
