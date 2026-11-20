//! Actual production QUIC/HTTPS caller bridge; test-only configuration and clock.
use super::*;
use crate::{governance::Shard, seedgate::{HostConditions,SeedGateFSM}, transport::{iroh::{L2CapabilityPolicy,quota_test_support as support},quic_seed::SeedPeerAuthority,constant_time::{is_unavailable_frame,UNAVAILABLE_FRAME_SIZE}}};
use enclave_core::{enterprise_authority::{EnterpriseAuthority,EnterpriseMember,EnterprisePolicy,SignedEnterprisePolicy},profile::Profile};
use std::{fs::OpenOptions,os::unix::{fs::{OpenOptionsExt,PermissionsExt},io::AsRawFd},path::PathBuf,sync::{Mutex,atomic::{AtomicBool,AtomicUsize,Ordering}},thread};
const POLICY:[u8;32]=[9;32];
const PAYLOAD:&[u8]=b"actual QUIC quota payload";

fn private_write(path:&Path,bytes:&[u8]) {
    let mut file=OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).open(path).unwrap();
    file.write_all(bytes).unwrap();file.sync_all().unwrap();
}
struct IssuerThread {
    address:SocketAddr, stop:Arc<AtomicBool>, thread:Option<thread::JoinHandle<usize>>,
}
impl IssuerThread {
    fn start(root:Vec<u8>,cert:Vec<u8>,seed:[u8;32],policy:IssuerPolicy)->Self {
        let listener=std::net::TcpListener::bind("127.0.0.1:0").unwrap();listener.set_nonblocking(true).unwrap();let address=listener.local_addr().unwrap();
        let tls=issuer_server_config(cert,&seed,&[root]).unwrap();let stop=Arc::new(AtomicBool::new(false));let done=stop.clone();
        let thread=thread::spawn(move||{
            let mut served=0;
            while !done.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((socket,_))=>{
                        // Darwin accepted sockets can inherit listener flags.
                        socket.set_nonblocking(false).unwrap();let flags=unsafe{libc::fcntl(socket.as_raw_fd(),libc::F_GETFL)};
                        assert!(flags>=0&&flags&libc::O_NONBLOCK==0);
                        serve_issuer_connection(socket,tls.clone(),&policy).unwrap();served+=1;assert!(served<=4);
                    },
                    Err(error) if error.kind()==io::ErrorKind::WouldBlock=>thread::sleep(Duration::from_millis(2)),
                    Err(error)=>panic!("owned issuer accept failed: {:?}",error.kind()),
                }
            }
            served
        });
        Self{address,stop,thread:Some(thread)}
    }
    fn finish(&mut self)->usize {self.stop.store(true,Ordering::SeqCst);self.thread.take().unwrap().join().unwrap()}
}
impl Drop for IssuerThread {
    fn drop(&mut self) {
        self.stop.store(true,Ordering::SeqCst);
        if let Some(thread)=self.thread.take() {if thread.join().is_err(){eprintln!("SQ_ISSUER_THREAD_FAILED_DURING_TEARDOWN");}}
    }
}
#[derive(Clone)]
struct NetworkFixture {
    directory:PathBuf,root:Vec<u8>,client_seeds:[[u8;32];3],client_certs:[Vec<u8>;3],
    server_seed:[u8;32],server_cert:Vec<u8>,issuer_seed:[u8;32],issuer_cert:Vec<u8>,root_hash:String,
}
fn public(seed:&[u8;32])->[u8;32] {SigningKey::from_bytes(seed).verifying_key().to_bytes()}
impl NetworkFixture {
    fn new(run:&support::Run)->Self {
        let directory=run.fixture.join("state");std::fs::create_dir(&directory).unwrap();std::fs::set_permissions(&directory,std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut params=rcgen::CertificateParams::new(vec!["served-quota-ca".into()]);params.is_ca=rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);let ca=rcgen::Certificate::from_params(params).unwrap();
        let client_seeds=[enclave_core::rng::bytes32(),enclave_core::rng::bytes32(),enclave_core::rng::bytes32()];let server_seed=enclave_core::rng::bytes32();let issuer_seed=enclave_core::rng::bytes32();
        let identity=super::fence_tests::identity;
        Self{directory,root:ca.serialize_der().unwrap(),client_certs:[identity(&ca,client_seeds[0],"EU"),identity(&ca,client_seeds[1],"EU"),identity(&ca,client_seeds[2],"EU")],client_seeds,server_cert:identity(&ca,server_seed,"EU"),server_seed,issuer_cert:identity(&ca,issuer_seed,"EU"),issuer_seed,root_hash:crate::bao::bao_root(PAYLOAD)}
    }
    fn config(&self,index:usize,peer:SocketAddr,issuer:SocketAddr,issuer_public:&str)->L2QuicConfig {
        let cert=self.directory.join(format!("client-{index}.der"));let key=self.directory.join(format!("client-{index}.key"));
        if !cert.exists() {private_write(&cert,&self.client_certs[index]);private_write(&key,&self.client_seeds[index]);}
        let cfg=L2QuicConfig{peer:super::fence_tests::registry(peer,&self.root),issuer:super::fence_tests::registry(issuer,&self.root),client_certificate_der_path:cert.to_str().unwrap().into(),client_key_seed_path:key.to_str().unwrap().into(),peer_ed25519_hex:hex::encode(public(&self.server_seed)),issuer_public_key_hex:issuer_public.into(),policy_blake3:hex::encode(POLICY),shard:"EU".into(),poison_state_dir:self.directory.to_str().unwrap().into(),seed:None,total_timeout_ms:10_000,enterprise_authority:None};
        cfg.validate().unwrap();cfg
    }
}
struct Client {
    endpoint:quinn::Endpoint,connection:quinn::Connection,hello:SessionHello,token:Biscuit,holder:SigningKey,seq:u64,
}
impl Client {
    async fn connect(f:&NetworkFixture,index:usize,peer:SocketAddr,issuer:SocketAddr,issuer_public:&str)->Self {
        let cfg=f.config(index,peer,issuer,issuer_public);
        let tls=client_tls(&cfg.peer,&f.client_certs[index],&f.client_seeds[index]).unwrap();let crypto=quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
        let mut endpoint=quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        let connection=tokio::time::timeout(Duration::from_secs(5),endpoint.connect(peer,"localhost").unwrap()).await.unwrap().unwrap();
        let (server,shard,exporter)=connection_peer(&connection).unwrap();assert_eq!(server,public(&f.server_seed));assert_eq!(shard,"EU");assert_ne!(exporter,[0;32]);
        let hello:SessionHello=serde_json::from_slice(&tokio::time::timeout(Duration::from_secs(5),exchange(&connection,b"hello")).await.unwrap().unwrap()).unwrap();
        hello.verify().unwrap();assert_eq!(hello.server_key,server);assert_eq!(hello.client_key,public(&f.client_seeds[index]));assert_eq!(hello.exporter,exporter);
        let request=L2ChunkRequest{namespace_id:"models".into(),root_hash:f.root_hash.clone(),slice_index:0,pop_biscuit_token:None,client_node_id:hex::encode(hello.client_key)};
        // This uses the actual independently pinned mTLS HTTPS issuer, whose
        // worker thread authenticates the real client certificate itself.
        // No QUIC packet is needed for that synchronous bounded HTTPS exchange.
        let token=issuer_grant(&cfg,&f.client_certs[index],&f.client_seeds[index],&GrantRequest{session:hello.clone(),request},Instant::now()+Duration::from_secs(5)).unwrap();
        Self{endpoint,connection,hello,token,holder:SigningKey::from_bytes(&f.client_seeds[index]),seq:0}
    }
    async fn request(&mut self,root:&str)->Vec<u8> {
        let mut req=L2ChunkRequest{namespace_id:"models".into(),root_hash:root.into(),slice_index:0,pop_biscuit_token:None,client_node_id:hex::encode(self.hello.client_key)};
        let wire=pop_biscuit::make_call_sealed(&self.token,&self.holder,&self.hello.exporter,&req.capability_args().unwrap(),self.seq,Transport::MtlsExporter,WireClock{utc_epoch_ms_expiry:Some(now_ms().unwrap()+10_000),max_ttl_ms:Some(30_000),skew_ms:Some(2_000),..Default::default()}).unwrap();self.seq+=1;
        req.pop_biscuit_token=Some(wire.to_cbor().unwrap());let mut bytes=Vec::new();ciborium::into_writer(&req,&mut bytes).unwrap();
        // read_frame requires exact payload and actual FIN, rejecting trailing
        // bytes, reset, premature EOF and an incomplete frame.
        tokio::time::timeout(Duration::from_secs(5),exchange(&self.connection,&bytes)).await.unwrap().unwrap()
    }
    async fn close(&self) {
        self.connection.close(0u32.into(),b"quota fixture complete");self.endpoint.close(0u32.into(),b"quota fixture complete");
        tokio::time::timeout(Duration::from_secs(1),self.endpoint.wait_idle()).await.expect("owned client endpoint idle within bound");
    }
}
fn expect_data(bytes:&[u8]) {
    assert_eq!(bytes.len(),8+PAYLOAD.len());assert_eq!(&bytes[..8],&0u64.to_be_bytes());assert_eq!(&bytes[8..],PAYLOAD);
    assert_eq!(blake3::hash(&bytes[8..]),blake3::hash(PAYLOAD));assert!(!is_unavailable_frame(bytes));
}
fn expect_unavailable(bytes:&[u8]) {assert_eq!(bytes.len(),UNAVAILABLE_FRAME_SIZE);assert!(is_unavailable_frame(bytes));}
fn certificate_credit(node:&L2SwarmNode,key:[u8;32])->f64 {
    let (_,certificates)=node.quota_test_snapshots();let token=certificates[&hex::encode(key)].0;assert!(token>=1.0);token
}

#[test]
fn served_quic_shared_principal_51st_and_reconnect_refuse_other_principal_progresses() {
    let mut run=support::Run::new("transport::quic::quota_acceptance_tests::served_quic_shared_principal_51st_and_reconnect_refuse_other_principal_progresses",support::SQ07,90);
    let f=NetworkFixture::new(&run);let issuer=KeyPair::new();let issuer_public=hex::encode(issuer.public().to_bytes());
    let admin=SigningKey::from_bytes(&enclave_core::rng::bytes32());let now=enclave_crypto::time::now_unix();
    let membership=EnterpriseAuthority::ephemeral(admin.verifying_key().to_bytes(),SignedEnterprisePolicy::sign(EnterprisePolicy{version:1,revision:1,trust_domain:"quota.example".into(),issued_unix:now-1,expires_unix:now+3600,members:vec![EnterpriseMember{principal:"spiffe://quota.example/engineer/alice".into(),generation:1,holder_public_keys:vec![hex::encode(public(&f.client_seeds[0])),hex::encode(public(&f.client_seeds[1]))],namespaces:vec!["models".into()]},EnterpriseMember{principal:"spiffe://quota.example/engineer/bob".into(),generation:1,holder_public_keys:vec![hex::encode(public(&f.client_seeds[2]))],namespaces:vec!["models".into()]}]},&admin).unwrap());
    let mut gate=SeedGateFSM::new(Profile::L2);gate.update(HostConditions::default());let signer=Arc::new(SigningKey::from_bytes(&f.server_seed));
    let mut node=L2SwarmNode::new((*signer).clone(),Shard::EU,gate,L2CapabilityPolicy::new(issuer.public(),POLICY).with_enterprise_authority(membership));
    let t0=Instant::now();let clock=Arc::new(Mutex::new(t0));node.quota_test_clock(clock.clone());
    for seed in &f.client_seeds {node.authorize_peer(&hex::encode(public(seed)));}
    let node=Arc::new(node);let authority=SeedPeerAuthority::from_trusted_peers(f.directory.to_str().unwrap(),public(&f.server_seed),&f.client_seeds.iter().map(public).collect::<Vec<_>>()).unwrap();
    let mut issuer_thread=IssuerThread::start(f.root.clone(),f.issuer_cert.clone(),f.issuer_seed,IssuerPolicy{signing_key:issuer,policy:POLICY,grants:f.client_seeds.iter().map(|seed|(hex::encode(public(seed)),"models".into(),f.root_hash.clone())).collect(),servers:[(public(&f.server_seed),"EU".into())].into_iter().collect()});
    let reads=Arc::new(AtomicUsize::new(0));let count=reads.clone();let expected_root=f.root_hash.clone();
    let get=Arc::new(move|namespace:&str,root:&str,index:u64|{assert_eq!(namespace,"models");assert_eq!(root,expected_root);assert_eq!(index,0);count.fetch_add(1,Ordering::SeqCst);Some(PAYLOAD.to_vec())});
    let rt=tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let mut frames=Vec::new();
    let mut authenticated_connections=0;
    let mut idle_clients=0;
    rt.block_on(async {
        // All endpoint creation, connection drivers and serving tasks remain on
        // this same owned Tokio runtime; no context-dependent cross-runtime spawn.
        let endpoint=server_endpoint("127.0.0.1:0".parse().unwrap(),f.server_cert.clone(),&f.server_seed,&[f.root.clone()]).unwrap();let address=endpoint.local_addr().unwrap();
        let (stop,receiver)=tokio::sync::watch::channel(false);let mut task=tokio::spawn(serve(endpoint.clone(),node.clone(),signer,get,authority,receiver));
        let mut a=Client::connect(&f,0,address,issuer_thread.address,&issuer_public).await;
        authenticated_connections+=1;
        let mut b=Client::connect(&f,1,address,issuer_thread.address,&issuer_public).await;
        authenticated_connections+=1;
        let member_a=node.enterprise_authority().unwrap().authorize(&a.hello.client_key,"models",enclave_crypto::time::now_unix()).unwrap();let member_b=node.enterprise_authority().unwrap().authorize(&b.hello.client_key,"models",enclave_crypto::time::now_unix()).unwrap();assert_eq!(member_a.principal,member_b.principal);assert_ne!(a.hello.client_key,b.hello.client_key);
        run.complete(support::SQ07[0],serde_json::json!({"actual_mtls_connections":2,"same_signed_principal":true,"distinct_certificate_holders":true}));
        assert_ne!(a.hello.exporter,b.hello.exporter);assert_eq!(a.hello.epoch,node.authorization_epoch());assert_eq!(b.hello.epoch,node.authorization_epoch());
        for ordinal in 0..50 {
            let bytes=if ordinal<25 {a.request(&f.root_hash).await}else{b.request(&f.root_hash).await};expect_data(&bytes);assert_eq!(reads.load(Ordering::SeqCst),ordinal+1);
            frames.push(serde_json::json!({"request_ordinal":ordinal+1,"kind":"Data","body_bytes":bytes.len(),"body_hex":hex::encode(&bytes),"body_blake3":blake3::hash(&bytes).to_hex().to_string(),"clean_fin":true,"source_calls":reads.load(Ordering::SeqCst)}));
        }
        assert_eq!(a.seq,25);assert_eq!(b.seq,25);assert_eq!(node.quota_test_snapshots().0["spiffe://quota.example/engineer/alice"].0,0.0);
        run.complete(support::SQ07[1],serde_json::json!({"actual_session_signatures_verified":2,"actual_exporters_nonzero_distinct":true,"independent_https_grants":2,"actual_valid_pop_calls":a.seq+b.seq,"per_holder_calls":[a.seq,b.seq]}));
        run.complete(support::SQ07[2],serde_json::json!({"received_data":50,"source_calls":reads.load(Ordering::SeqCst),"per_holder_requests":[a.seq,b.seq],"actual_payload_blake3":blake3::hash(PAYLOAD).to_hex().to_string()}));
        let credit=certificate_credit(&node,a.hello.client_key);assert_eq!(credit,25.0);run.complete(support::SQ07[3],serde_json::json!({"certificate_tokens_before_51st":credit,"principal_tokens_before_51st":0}));
        let bytes=a.request(&f.root_hash).await;expect_unavailable(&bytes);assert_eq!(reads.load(Ordering::SeqCst),50);
        frames.push(serde_json::json!({"request_ordinal":51,"kind":"Unavailable","body_bytes":bytes.len(),"body_hex":hex::encode(&bytes),"body_blake3":blake3::hash(&bytes).to_hex().to_string(),"clean_fin":true,"source_delta":0}));
        run.complete(support::SQ07[4],serde_json::json!({"actual_body_bytes":bytes.len(),"source_calls":reads.load(Ordering::SeqCst),"source_delta":0,"valid_unavailable_magic":true,"certificate_tokens_after":certificate_credit(&node,a.hello.client_key)}));
        let old_exporter=a.hello.exporter;a.close().await;idle_clients+=1;
        let mut reconnected=Client::connect(&f,0,address,issuer_thread.address,&issuer_public).await;assert_ne!(old_exporter,reconnected.hello.exporter);assert_eq!(reconnected.hello.epoch,node.authorization_epoch());certificate_credit(&node,reconnected.hello.client_key);
        authenticated_connections+=1;
        let bytes=reconnected.request(&f.root_hash).await;expect_unavailable(&bytes);assert_eq!(reads.load(Ordering::SeqCst),50);
        frames.push(serde_json::json!({"request_ordinal":52,"kind":"Unavailable","body_bytes":bytes.len(),"body_hex":hex::encode(&bytes),"body_blake3":blake3::hash(&bytes).to_hex().to_string(),"clean_fin":true,"source_delta":0}));
        run.complete(support::SQ07[5],serde_json::json!({"new_real_tls_exporter":true,"source_calls":reads.load(Ordering::SeqCst),"source_delta":0,"actual_unavailable_body_bytes":bytes.len(),"certificate_tokens_after":certificate_credit(&node,reconnected.hello.client_key)}));
        let mut bob=Client::connect(&f,2,address,issuer_thread.address,&issuer_public).await;let other=node.enterprise_authority().unwrap().authorize(&bob.hello.client_key,"models",enclave_crypto::time::now_unix()).unwrap();assert_ne!(other.principal,member_a.principal);
        authenticated_connections+=1;
        let bytes=bob.request(&f.root_hash).await;expect_data(&bytes);assert_eq!(reads.load(Ordering::SeqCst),51);
        frames.push(serde_json::json!({"request_ordinal":53,"kind":"Data","body_bytes":bytes.len(),"body_hex":hex::encode(&bytes),"body_blake3":blake3::hash(&bytes).to_hex().to_string(),"clean_fin":true,"source_calls":reads.load(Ordering::SeqCst)}));
        run.complete(support::SQ07[6],serde_json::json!({"distinct_signed_principal":true,"actual_payload_bytes":PAYLOAD.len(),"actual_payload_blake3":blake3::hash(&bytes[8..]).to_hex().to_string(),"actual_success_fin":true,"source_calls":reads.load(Ordering::SeqCst)}));
        assert_eq!(frames.len(),53);assert_eq!(frames.iter().filter(|v|v["kind"]=="Data").count(),51);assert_eq!(frames.iter().filter(|v|v["kind"]=="Unavailable").count(),2);assert_eq!(*clock.lock().unwrap(),t0);
        assert_eq!(authenticated_connections,4);
        run.complete(support::SQ07[7],serde_json::json!({"actual_frames":frames,"received_data":51,"received_unavailable":2,"source_calls":reads.load(Ordering::SeqCst),"quota_clock_advanced":false,"serving_connections":authenticated_connections}));
        b.close().await;idle_clients+=1;reconnected.close().await;idle_clients+=1;bob.close().await;idle_clients+=1;
        stop.send(true).unwrap();tokio::time::timeout(Duration::from_secs(5),&mut task).await.expect("owned server stop/join deadline").unwrap().unwrap();
        endpoint.close(0u32.into(),b"quota fixture complete");tokio::time::timeout(Duration::from_secs(1),endpoint.wait_idle()).await.expect("owned server idle deadline");
    });
    rt.shutdown_timeout(Duration::from_secs(1));let grants=issuer_thread.finish();assert_eq!(grants,4);
    assert_eq!(idle_clients,authenticated_connections);
    run.complete(support::SQ07[8],serde_json::json!({"server_task_joined":true,"client_endpoints_idle":idle_clients,"server_endpoint_idle":true,"runtime_shutdown_returned":true,"actual_https_issuer_requests":grants,"issuer_thread_joined":true,"process_children":0,"client_idle_policy_ms":1000,"server_join_policy_ms":5000,"server_idle_policy_ms":1000,"runtime_shutdown_policy_ms":1000}));run.finish();
}
