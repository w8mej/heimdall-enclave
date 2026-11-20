//! Actual service dispatcher corruption and production typed seed authority binding.
//! Software loopback fixtures only; no installed authority or hardware claim.
use crate::transport::quic_fence_test_support::{
    self as support,
    Run,
    Role,
    Fault,
    Note,
    PollResult
};
use super::{
    process_peer_stops,
    MarkerProgress
};
use ed25519_dalek::SigningKey;
use enclave_core::{
    profile::Profile,
    secret::SecretKey32
};
use enclave_crypto::{
    biscuit_auth::KeyPair,
    namespace,
    tuf::target_file
};
use crate::{
    bao,
    governance::Shard,
    seedgate::{
        HostConditions,
        SeedGateFSM,
        Thermal
    },
    transport::{
        iroh::{
            L2CapabilityPolicy,
            L2SwarmNode
        },
        oblivious::EncryptedTarget,
        quic::{
            self,
            IssuerPolicy,
            L2QuicConfig,
            SEGMENT
        },
        registry::RegistryConfig,
    },
};
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::{
        BTreeMap,
        BTreeSet,
        HashMap
    },
    net::TcpListener,
    path::PathBuf,
    sync::{
        atomic::{
            AtomicBool,
            AtomicU64,
            AtomicUsize,
            Ordering
        },
        Arc,
    },
    thread,
    time::Duration,
};
const POLICY: [u8; 32] = [9; 32];
fn identity(ca: &rcgen::Certificate, seed: [u8; 32], shard: &str) -> Vec<u8> {
    let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let mut der = hex::decode("302e020100300506032b657004220420").unwrap();
    der.extend_from_slice(&seed);
    let mut p = rcgen::CertificateParams::new(vec!["localhost".into()]);
    p.alg = &rcgen::PKCS_ED25519;
    p.key_pair = Some(rcgen::KeyPair::from_der(&der).unwrap());
    p.subject_alt_names.push(rcgen::SanType::URI(format!( "spiffe://corporate.internal/shard/{shard}/node/{}", hex::encode(public) )));
    p.extended_key_usages = vec![ rcgen::ExtendedKeyUsagePurpose::ServerAuth, rcgen::ExtendedKeyUsagePurpose::ClientAuth, ];
    rcgen::Certificate::from_params(p) .unwrap() .serialize_der_with_signer(ca) .unwrap()
}
fn registry(address: std::net::SocketAddr, root: &[u8]) -> RegistryConfig {
    RegistryConfig {
        address: address.to_string(),
        server_name: "localhost".into(),
        repository: "fixture".into(),
        tls_roots_der: vec![hex::encode(root)],
        timeout_ms: 10_000,
    }
}
struct Fixture {
    streams: Arc<BTreeMap<String,
    Vec<u8>>>,
    server_seed: [u8;32],
    server_cert: Vec<u8>,
    path: PathBuf,
    cfg: L2QuicConfig,
    tf: enclave_crypto::tuf::TargetFile,
    target: EncryptedTarget,
    key: SecretKey32,
    payload: Vec<u8>,
    reads: Arc<AtomicUsize>,
    corrupt: Arc<AtomicBool>,
    hold: Arc<AtomicBool>,
    entered: Arc<AtomicBool>,
    node: Arc<L2SwarmNode>,
    delay_first_ms: Arc<AtomicU64>,
    revoke_after_first: Arc<AtomicBool>,
    issuer_grants: Arc<AtomicUsize>,
    stop: tokio::sync::watch::Sender<bool>,
    issuer_stop: Arc<AtomicBool>,
    server: Option<thread::JoinHandle<()>>,
    issuer: Option<thread::JoinHandle<()>>,
}
impl Fixture {
    fn new() -> Self {
        let path = support::fixture_path().join("network");
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut ca = rcgen::CertificateParams::new(vec!["fixture-ca".into()]);
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = rcgen::Certificate::from_params(ca).unwrap();
        let root = ca.serialize_der().unwrap();
        let client_seed = enclave_core::rng::bytes32();
        let server_seed = enclave_core::rng::bytes32();
        let issuer_seed = enclave_core::rng::bytes32();
        let client_cert = identity(&ca, client_seed, "EU");
        let server_cert = identity(&ca, server_seed, "EU");
        let issuer_cert = identity(&ca, issuer_seed, "EU");
        let client = SigningKey::from_bytes(&client_seed) .verifying_key() .to_bytes();
        let signer = Arc::new(SigningKey::from_bytes(&server_seed));
        let issuer_key = KeyPair::new();
        let issuer_public = issuer_key.public().to_bytes();
        // Separate independently pinned membership issuer, not the peer key.
        use enclave_core::enterprise_authority::{
            EnterpriseAuthority,
            EnterpriseMember,
            EnterprisePolicy,
            SignedEnterprisePolicy
        };
        let membership_issuer=SigningKey::from_bytes(&[42;32]);
        let now=enclave_crypto::time::now_unix();
        let membership=EnterpriseAuthority::ephemeral(membership_issuer.verifying_key().to_bytes(), SignedEnterprisePolicy::sign(EnterprisePolicy{
            version:1,
            revision:1,
            trust_domain:"fixture.example".into(),
            issued_unix:now-1,
            expires_unix:now+3600,
            members:vec![EnterpriseMember{
                principal:"spiffe://fixture.example/engineer/alice".into(),
                generation:1,
                holder_public_keys:vec![hex::encode(client)],
                namespaces:vec!["models".into()]
            }],
        }, &membership_issuer).unwrap());
        let mut seed = SeedGateFSM::new(Profile::L2);
        seed.update(HostConditions {
            ac_power: true,
            unmetered: true,
            hotspot: false,
            thermal: Thermal::Nominal,
            low_power: false,
        });
        let node = Arc::new(L2SwarmNode::new( SigningKey::from_bytes(&server_seed), Shard::EU, seed, L2CapabilityPolicy::new(issuer_key.public(), POLICY).with_enterprise_authority(membership), ));
        node.authorize_peer(&hex::encode(client));
        let payload: Vec<u8> = (0..=255) .cycle() .take(namespace::PLAINTEXT_SIZE * 3 + 77) .collect();
        let tf = target_file(&payload, None);
        let root_plain: [u8; 32] = hex::decode(&tf.hashes["blake3"]) .unwrap() .try_into() .unwrap();
        let key = SecretKey32::new([12; 32]);
        let mut ciphertext = Vec::new();
        let mut keys = Vec::new();
        let leaves = payload.len().div_ceil(namespace::PLAINTEXT_SIZE);
        for (i, chunk) in payload.chunks(namespace::PLAINTEXT_SIZE).enumerate() {
            let (c, k) = namespace::encrypt_chunk(&key, &root_plain, i as u64, i + 1 == leaves, chunk) .unwrap();
            ciphertext.extend_from_slice(&c);
            keys.extend_from_slice(&k);
        }
        let cipher_root = bao::bao_root(&ciphertext);
        let key_root = bao::bao_root(&keys);
        let mut streams = BTreeMap::new();
        streams.insert( cipher_root.clone(), bao::encode_bao_stream(&ciphertext).unwrap(), );
        streams.insert(key_root.clone(), bao::encode_bao_stream(&keys).unwrap());
        let target = EncryptedTarget {
            version: 1,
            ciphertext_bao_root: cipher_root.clone(),
            ciphertext_length: ciphertext.len() as u64,
            key_index_bao_root: key_root.clone(),
            key_index_length: keys.len() as u64,
            key: namespace::wrap("models", 1, 1, key.expose(), &SecretKey32::new([13; 32])) .unwrap(),
        };
        let streams=Arc::new(streams);
        let retained_streams=streams.clone();
        let retained_server_cert=server_cert.clone();
        let reads = Arc::new(AtomicUsize::new(0));
        let counted = reads.clone();
        let corrupt = Arc::new(AtomicBool::new(false));
        let inject = corrupt.clone();
        let hold = Arc::new(AtomicBool::new(false));
        let waiting = hold.clone();
        let entered = Arc::new(AtomicBool::new(false));
        let observed = entered.clone();
        let revoke_node = node.clone();
        let revoke_after_first = Arc::new(AtomicBool::new(false));
        let revoke = revoke_after_first.clone();
        let delay_first_ms = Arc::new(AtomicU64::new(0));
        let delayed = delay_first_ms.clone();
        let get = Arc::new(move |_namespace: &str, root: &str, index: u64| {
            let previous = counted.fetch_add(1, Ordering::SeqCst);
            if previous == 0 {
                let delay = delayed.load(Ordering::SeqCst).min(8_000);
                if delay > 0 {
                    thread::sleep(Duration::from_millis(delay));
                }
                if revoke.load(Ordering::SeqCst) {
                    revoke_node.authorized_peers.lock().unwrap().remove(&hex::encode(client));
                }
            }
            observed.store(true, Ordering::SeqCst);
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while waiting.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
                thread::sleep(Duration::from_millis(2));
            }
            let bytes = streams.get(root)?;
            let offset = usize::try_from(index).ok()?.checked_mul(SEGMENT)?;
            if offset >= bytes.len() {
                return None;
            }
            let mut result = bytes[offset..bytes.len().min(offset + SEGMENT)].to_vec();
            if inject.load(Ordering::SeqCst) {
                let last = result.len() - 1;
                result[last] ^= 0x80;
            }
            Some(result)
        });
        let peer_authority=crate::transport::quic_seed::SeedPeerAuthority::from_trusted_peers(path.canonicalize().unwrap().to_str().unwrap(), signer.verifying_key().to_bytes(), &[client]).unwrap();
        let serving_node=node.clone();
        let (stop, receiver) = tokio::sync::watch::channel(false);
        let (tx, rx) = std::sync::mpsc::channel();
        let roots = vec![root.clone()];
        let server = thread::spawn(move || {
            support::initialize_notes();
            let rt = tokio::runtime::Builder::new_current_thread() .enable_all() .build() .unwrap();
            rt.block_on(async {
                let endpoint = quic::server_endpoint( "127.0.0.1:0".parse().unwrap(), server_cert, &server_seed, &roots, ) .unwrap();
                tx.send(endpoint.local_addr().unwrap()).unwrap();
                quic::serve( endpoint, serving_node, signer, get, peer_authority, receiver, ) .await .unwrap();
            });
        });
        let address = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let issuer_address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let issuer_tls = quic::issuer_server_config(issuer_cert, &issuer_seed, &[root.clone()]).unwrap();
        let policy = IssuerPolicy {
            signing_key: issuer_key,
            policy: POLICY,
            grants: BTreeSet::from([ (hex::encode(client), "models".into(), cipher_root), (hex::encode(client), "models".into(), key_root), ]),
            servers: HashMap::from([( SigningKey::from_bytes(&server_seed) .verifying_key() .to_bytes(), "EU".into(), )]),
        };
        let issuer_stop = Arc::new(AtomicBool::new(false));
        let stopping = issuer_stop.clone();
        let issuer_grants = Arc::new(AtomicUsize::new(0));
        let grant_count = issuer_grants.clone();
        let issuer = thread::spawn(move || {
            while !stopping.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((socket, _)) => {
                        socket.set_nonblocking(false).unwrap();
                        if let Err(e) = {
                            grant_count.fetch_add(1, Ordering::SeqCst);
                            quic::serve_issuer_connection(socket, issuer_tls.clone(), &policy)
                        }
                        {
                            eprintln!("private issuer refusal: {e}");
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(e) => panic!("{e}"),
                }
            }
        });
        // Credentials/configuration require absolute paths even when the
        // fixture socket uses a short relative TMPDIR on Darwin.
        let credentials = path.canonicalize().unwrap();
        let cert_path = credentials.join("client.der");
        std::fs::write(&cert_path, client_cert).unwrap();
        let seed_path = credentials.join("client.key");
        std::fs::write(&seed_path, client_seed).unwrap();
        std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let cfg = L2QuicConfig {
            enterprise_authority:None,
            poison_state_dir: credentials.to_string_lossy().into_owned(),
            seed: None,
            total_timeout_ms: 30_000,
            peer: registry(address, &root),
            issuer: registry(issuer_address, &root),
            client_certificate_der_path: cert_path.display().to_string(),
            client_key_seed_path: seed_path.display().to_string(),
            peer_ed25519_hex: hex::encode( SigningKey::from_bytes(&server_seed) .verifying_key() .to_bytes(), ),
            issuer_public_key_hex: hex::encode(issuer_public),
            policy_blake3: hex::encode(POLICY),
            shard: "EU".into(),
        };
        Self {
            streams:retained_streams,
            server_seed,
            server_cert:retained_server_cert,
            path,
            cfg,
            tf,
            target,
            key,
            payload,
            reads,
            corrupt,
            hold,
            entered,
            node,
            delay_first_ms,
            revoke_after_first,
            issuer_grants,
            stop,
            issuer_stop,
            server: Some(server),
            issuer: Some(issuer),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _=self.stop.send(true);
        self.issuer_stop.store(true, Ordering::SeqCst);
        if let Some(server)=self.server.take(){
            server.join().unwrap();
        }
        self.issuer.take().unwrap().join().unwrap();
        std::fs::remove_dir_all(&self.path).unwrap();
    }
}
use enclave_core::{
    err,
    error::EnclaveResult,
    ipc::{
        self,
        PeerCredentials
    },
};
use enclave_crypto::{
    namespace::{
        CasKeyLease,
        WrappedNamespaceKey
    },
    tuf::{
        RepoBuilder,
        TargetFile
    },
};
use crate::{
    service::{
        CasConfig,
        CasRequest,
        CasResponse,
        CasService
    },
    transport::{
        custody::{
            NamespaceCustody,
            NamespaceRelease
        },
        registry::{
            DistributionConfig,
            DISTRIBUTION_CONFIG_TARGET
        },
    },
};
use std::io::{
    Read,
    Write
};
#[derive(Debug)]
struct ServiceCustody {
    key: SecretKey32,
    valid: AtomicBool,
}
impl NamespaceCustody for ServiceCustody {
    fn unwrap(&self, key: &WrappedNamespaceKey) -> EnclaveResult<NamespaceRelease> {
        if key.namespace != "models" || key.epoch != 1 || !self.valid.load(Ordering::SeqCst) {
            return Err(err!(EACCES, "FIXTURE_KEY_REMOVED"));
        }
        Ok(NamespaceRelease {
            key: self.key.clone(),
            lease: CasKeyLease {
                enterprise:None,
                id: "quic-private-fixture".into(),
                namespace: key.namespace.clone(),
                key_epoch: 1,
                boot_epoch: "fixture".into(),
                generation: 1,
                expires_unix: 2_000_000_000,
            },
        })
    }
    fn revalidate(&self, _: &CasKeyLease) -> EnclaveResult<()> {
        if self.valid.load(Ordering::SeqCst) {
            Ok(())
        }
        else {
            Err(err!(EACCES, "FIXTURE_KEY_REMOVED"))
        }
    }
}
struct ServiceFixture {
    base: PathBuf,
    service: Arc<CasService>,
    peer: PeerCredentials,
    repo: RepoBuilder,
    targets: BTreeMap<String,
    TargetFile>,
    uri: String,
    custody: Arc<ServiceCustody>,
}
impl ServiceFixture {
    fn new(network: &Fixture, wrong_key:bool) -> Self {
        let base = support::fixture_path().join("cas");
        std::fs::create_dir(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let repo = RepoBuilder::new(3, 2);
        let root = repo.root("2030-01-01T00:00:00Z").unwrap();
        let service = CasService::start(CasConfig {
            dev_same_uid: true,
            profile: Profile::L2,
            store_dir: base.join("store"),
            audit_path: Some(base.join("audit.jsonl")),
            tuf_root: Some(root),
            ohttp_gateway: None,
            state_dir: None,
            revocation: crate::revocation::Enforcement::InProcess,
        }) .unwrap();
        let config = serde_json::to_vec(&DistributionConfig {
            version: 1,
            l1: None,
            l2: Some(network.cfg.clone()),
            l3: None,
        }) .unwrap();
        std::fs::write(base.join("store").join(DISTRIBUTION_CONFIG_TARGET), &config).unwrap();
        let custom = serde_json::json!({
            "classification":"internal_l2",
            "min_profile":"L2",
            "jurisdiction_shard":"EU",
            "license_policy":{
                "spdx_id":"LicenseRef-private-QUIC-fixture",
                "allow_p2p_seeding":true
            },
            "encrypted_transport":network.target
        });
        let targets = [ ( "model.bin".into(), target_file(&network.payload, Some(custom)), ), ( DISTRIBUTION_CONFIG_TARGET.into(), target_file(&config, Some(serde_json::json!({
        }))), ), ] .into_iter() .collect();
        let mut peer = PeerCredentials::local(ipc::geteuid(), 0);
        peer.pid = Some(std::process::id() as i32);
        let custody = Arc::new(ServiceCustody {
            key: if wrong_key{
                SecretKey32::new([99;32])
            }
            else{
                network.key.clone()
            },
            valid: AtomicBool::new(true),
        });
        service.set_namespace_custody(custody.clone()).unwrap();
        let fixture = Self {
            base,
            service,
            peer,
            repo,
            targets,
            uri: format!( "cas://blake3-bao-v1/{}?target=model.bin&ns=models", blake3::hash(&network.payload).to_hex() ),
            custody,
        };
        fixture.refresh(1, fixture.targets.clone());
        fixture
    }
    fn refresh(&self, version: u64, targets: BTreeMap<String, TargetFile>) {
        let targets = self .repo .targets(version, "2030-01-01T00:00:00Z", targets) .unwrap();
        let snapshot = self .repo .snapshot(version, "2030-01-01T00:00:00Z", version, &targets) .unwrap();
        let timestamp = self .repo .timestamp(version, "2030-01-01T00:00:00Z", version, &snapshot) .unwrap();
        self.service .handle( &self.peer, CasRequest::TufRefresh {
            roots: vec![],
            timestamp: timestamp.into(),
            snapshot: snapshot.into(),
            targets: targets.into(),
        }, ) .unwrap();
    }
    fn unpublished(&self, network: &Fixture) {
        let root = blake3::hash(&network.payload).to_hex().to_string();
        assert!(!self .base .join("store/manifests") .join(format!("{root}.json")) .exists());
        assert!(!std::fs::read_to_string(self.base.join("audit.jsonl")) .unwrap() .contains("\"event\":\"HYDRATED\""));
        assert!(std::fs::read_dir(self.base.join("store/streaming-stages")) .unwrap() .all(|entry| !entry .unwrap() .file_name() .to_string_lossy() .starts_with("stage-")));
    }
}
impl Drop for ServiceFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}
struct ReverseServer {
    cfg:L2QuicConfig,
    authority:Arc<crate::transport::quic_seed::SeedPeerAuthority>,
    reads:Arc<AtomicUsize>,
    grants:Arc<AtomicUsize>,
    stop:tokio::sync::watch::Sender<bool>,
    issuer_stop:Arc<AtomicBool>,
    server:Option<thread::JoinHandle<()>>,
    issuer:Option<thread::JoinHandle<()>>,
    probes:tokio::sync::mpsc::Sender<std::sync::mpsc::Sender<Vec<Note>>>,
}
impl ReverseServer {
    fn new(network:&Fixture, service:&CasService)->Self {
        use crate::transport::quic_seed::SeedPeerAuthority;
        use enclave_core::enterprise_authority::{
            EnterpriseAuthority,
            EnterpriseMember,
            EnterprisePolicy,
            SignedEnterprisePolicy
        };
        let detector_seed:[u8;32]=std::fs::read(&network.cfg.client_key_seed_path).unwrap().try_into().unwrap();
        let detector=SigningKey::from_bytes(&detector_seed);
        let peer=SigningKey::from_bytes(&network.server_seed).verifying_key().to_bytes();
        let certificate=std::fs::read(&network.cfg.client_certificate_der_path).unwrap();
        let roots:Vec<_>=network.cfg.peer.tls_roots_der.iter().map(|r|hex::decode(r).unwrap()).collect();
        let root=roots[0].clone();
        // This is the exact private constructor also called by SeedListener::start.
        let authority=SeedPeerAuthority::with_peer_stops(&network.cfg.poison_state_dir, detector.verifying_key().to_bytes(), &[peer], service.process_peer_stops()).unwrap();
        assert!(Arc::ptr_eq(&service.process_peer_stops(), &process_peer_stops()));
        let same=service.process_peer_stops().reserve_domain(&network.cfg.poison_state_dir, detector.verifying_key().to_bytes(), &[peer]).unwrap();
        assert!(Arc::ptr_eq(&authority.peer(&peer).unwrap().stop, &same.peer(&peer).unwrap().stop));
        let issuer_key=KeyPair::new();
        let issuer_public=issuer_key.public().to_bytes();
        let membership_issuer=SigningKey::from_bytes(&enclave_core::rng::bytes32());
        let now=enclave_crypto::time::now_unix();
        let membership=EnterpriseAuthority::ephemeral(membership_issuer.verifying_key().to_bytes(), SignedEnterprisePolicy::sign(EnterprisePolicy{
            version:1,
            revision:1,
            trust_domain:"fixture.example".into(),
            issued_unix:now-1,
            expires_unix:now+3600,
            members:vec![EnterpriseMember{
                principal:"spiffe://fixture.example/engineer/reverse".into(),
                generation:1,
                holder_public_keys:vec![hex::encode(peer)],
                namespaces:vec!["models".into()]
            }]
        }, &membership_issuer).unwrap());
        let mut gate=SeedGateFSM::new(Profile::L2);
        gate.update(HostConditions{
            ac_power:true,
            unmetered:true,
            hotspot:false,
            thermal:Thermal::Nominal,
            low_power:false
        });
        let node=Arc::new(L2SwarmNode::new(detector.clone(), Shard::EU, gate, L2CapabilityPolicy::new(issuer_key.public(), POLICY).with_enterprise_authority(membership)));
        node.authorize_peer(&hex::encode(peer));
        let reads=Arc::new(AtomicUsize::new(0));
        let counted=reads.clone();
        let streams=network.streams.clone();
        let get=Arc::new(move|_namespace:&str, root:&str, index:u64|{
            counted.fetch_add(1, Ordering::SeqCst);
            let bytes=streams.get(root)?;
            let offset=usize::try_from(index).ok()?.checked_mul(SEGMENT)?;
            if offset>=bytes.len(){
                return None;
            }
            Some(bytes[offset..bytes.len().min(offset+SEGMENT)].to_vec())
        });
        let (stop, receiver)=tokio::sync::watch::channel(false);
        let (tx, rx)=std::sync::mpsc::sync_channel(1);
        let (probes, mut probe_rx)=tokio::sync::mpsc::channel::<std::sync::mpsc::Sender<Vec<Note>>>(4);
        let serving_authority=authority.clone();
        let server_certificate=certificate.clone();
        let server=thread::spawn(move||{
            support::initialize_notes();
            let runtime=tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            runtime.block_on(async move{
                let endpoint=quic::server_endpoint("127.0.0.1:0".parse().unwrap(), server_certificate, &detector_seed, &roots).unwrap();
                tx.send(endpoint.local_addr().unwrap()).unwrap();
                let serving=quic::serve(endpoint, node, Arc::new(detector), get, serving_authority, receiver);
                tokio::pin!(serving);
                loop{
                    tokio::select!{
                        result=&mut serving=>{
                            result.unwrap();
                            break;
                        },
                        Some(reply)=probe_rx.recv()=>{
                            reply.send(support::notes()).unwrap();
                        }
                    }
                }
            });
        });
        let address=rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();
        let issuer_address=listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let issuer_tls=quic::issuer_server_config(certificate, &detector_seed, &[root.clone()]).unwrap();
        let policy=IssuerPolicy{
            signing_key:issuer_key,
            policy:POLICY,
            grants:BTreeSet::from([(hex::encode(peer), "models".into(), network.target.ciphertext_bao_root.clone()), (hex::encode(peer), "models".into(), network.target.key_index_bao_root.clone())]),
            servers:HashMap::from([(SigningKey::from_bytes(&detector_seed).verifying_key().to_bytes(), "EU".into())])
        };
        let issuer_stop=Arc::new(AtomicBool::new(false));
        let stopping=issuer_stop.clone();
        let grants=Arc::new(AtomicUsize::new(0));
        let grant_count=grants.clone();
        let issuer=thread::spawn(move||{
            while !stopping.load(Ordering::SeqCst){
                match listener.accept(){
                    Ok((socket, _))=>{
                        // Darwin accept inherits O_NONBLOCK from this listener.
                        // The real issuer serves blocking TLS with socket deadlines.
                        use std::os::fd::AsRawFd;
                        let before=unsafe{libc::fcntl(socket.as_raw_fd(),libc::F_GETFL)};
                        assert!(before>=0,"reverse issuer F_GETFL before normalization");
                        socket.set_nonblocking(false).unwrap();
                        let after=unsafe{libc::fcntl(socket.as_raw_fd(),libc::F_GETFL)};
                        assert!(after>=0,"reverse issuer F_GETFL after normalization");
                        assert_eq!(after&libc::O_NONBLOCK,0,"reverse issuer socket must be blocking");
                        assert_eq!(before&!libc::O_NONBLOCK,after&!libc::O_NONBLOCK);
                        eprintln!("QF_REVERSE_ISSUER_BLOCKING {{\"flags_before\":{before},\"flags_after\":{after},\"blocking_verified\":true}}");
                        grant_count.fetch_add(1, Ordering::SeqCst);
                        quic::serve_issuer_connection(socket, issuer_tls.clone(), &policy).unwrap();
                    },
                    Err(error)if error.kind()==std::io::ErrorKind::WouldBlock=>thread::sleep(Duration::from_millis(2)),
                    Err(error)=>panic!("{error}")
                }
            }
        });
        let certificate_path=network.path.join("reverse-client.der");
        let seed_path=network.path.join("reverse-client.key");
        std::fs::write(&certificate_path, &network.server_cert).unwrap();
        std::fs::write(&seed_path, network.server_seed).unwrap();
        std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let cfg=L2QuicConfig{
            peer:registry(address, &root),
            issuer:registry(issuer_address, &root),
            client_certificate_der_path:certificate_path.canonicalize().unwrap().display().to_string(),
            client_key_seed_path:seed_path.canonicalize().unwrap().display().to_string(),
            peer_ed25519_hex:hex::encode(SigningKey::from_bytes(&detector_seed).verifying_key().to_bytes()),
            issuer_public_key_hex:hex::encode(issuer_public),
            policy_blake3:hex::encode(POLICY),
            shard:"EU".into(),
            poison_state_dir:network.cfg.poison_state_dir.clone(),
            seed:None,
            total_timeout_ms:5000,
            enterprise_authority:None
        };
        Self{
            cfg,
            authority,
            reads,
            grants,
            stop,
            issuer_stop,
            server:Some(server),
            issuer:Some(issuer),
            probes
        }
    }
    fn snapshot(&self)->Vec<Note>{
        let(tx, rx)=std::sync::mpsc::channel();
        self.probes.blocking_send(tx).unwrap();
        rx.recv_timeout(Duration::from_secs(5)).unwrap()
    }
    fn fetch(&self, network:&Fixture)->(EnclaveResult<()>, Vec<u8>){
        let mut bytes=Vec::new();
        let result=quic::fetch(&self.cfg, &network.tf, &network.target, &network.key, |chunk|{
            bytes.extend_from_slice(chunk);
            Ok(())
        });
        (result, bytes)
    }
}
impl Drop for ReverseServer{
    fn drop(&mut self){
        let _=self.stop.send(true);
        self.issuer_stop.store(true, Ordering::SeqCst);
        // Join both owned workers even when one failed. A caller already
        // unwinding must retain its original failure without a second panic.
        let server_failed=self.server.take().map(|server|server.join().is_err()).unwrap_or(false);
        let issuer_failed=self.issuer.take().map(|issuer|issuer.join().is_err()).unwrap_or(false);
        if server_failed||issuer_failed{
            eprintln!("QF_REVERSE_WORKER_FAILURE {{\"server_failed\":{server_failed},\"issuer_failed\":{issuer_failed}}}");
            if !std::thread::panicking(){
                panic!("owned reverse worker failed; see retained raw logs");
            }
        }
    }
}
fn protected_calls(notes:&[Note])->(usize, usize, usize){
    let mut polls=0;
    let mut positive=0;
    let mut finishes=0;
    for note in notes{
        match note{
            Note::PayloadPoll{
                result,
                ..
            }
            =>{
                polls+=1;
                if matches!(result, PollResult::Positive(_)){
                    positive+=1;
                }
            },
            Note::FinCall{
                ..
            }
            =>finishes+=1,
            _=>{
            }
        }
    }
    (polls, positive, finishes)
}
fn run_binding_child(){
    let case=support::case();
    let mut network=Fixture::new();
    network.cfg.total_timeout_ms=2000;
    network.cfg.peer.timeout_ms=1000;
    let service=ServiceFixture::new(&network, case=="local_key");
    let reverse=ReverseServer::new(&network, &service.service);
    let mut precondition=Vec::new();
    quic::fetch(&network.cfg, &network.tf, &network.target, &network.key, |bytes|{
        precondition.extend_from_slice(bytes);
        Ok(())
    }).unwrap();
    assert_eq!(precondition, network.payload);
    let(ok, bytes)=reverse.fetch(&network);
    ok.unwrap();
    assert_eq!(bytes, network.payload);
    let before=reverse.snapshot();
    let before_calls=protected_calls(&before);
    assert!(before_calls.1>0&&before_calls.2>0);
    let read_count=reverse.reads.load(Ordering::SeqCst);
    let grants=reverse.grants.load(Ordering::SeqCst);
    let ordinary=case=="transport_unavailable"||case=="local_key";
    if case=="transport_unavailable"{
        let _=network.stop.send(true);
        network.server.take().unwrap().join().unwrap();
    }
    else if !ordinary{
        network.corrupt.store(true, Ordering::SeqCst);
    }
    let forward_reads=network.reads.load(Ordering::SeqCst);
    let failure=service.service.handle(&service.peer, CasRequest::OpenTarget{
        target:"model.bin".into()
    }).unwrap_err();
    service.unpublished(&network);
    let CasResponse::SyncDiagnostics(snapshot)=service.service.handle(&service.peer, CasRequest::SyncDiagnostics).unwrap()else{
        panic!("diagnostics type")
    };
    assert!(snapshot.valid_measurement());
    let stages=snapshot.stages.unwrap();
    assert_eq!(stages.quic_fetch.started, 1);
    assert_eq!(stages.quic_fetch.returned_err, 1);
    assert_eq!(stages.quic_fetch.returned_ok, 0);
    assert_eq!(stages.quic_fetch.in_flight, 0);
    let peer:[u8;32]=hex::decode(&network.cfg.peer_ed25519_hex).unwrap().try_into().unwrap();
    let state=reverse.authority.peer(&peer).unwrap();
    assert_eq!(state.is_stopped(), !ordinary);
    assert!(!network.path.join(format!("{}.json", network.cfg.peer_ed25519_hex)).exists());
    let main_notes=support::notes();
    let observations:Vec<_>=main_notes.iter().filter_map(|note|if let Note::PublicationObservation{
        peer,
        detector,
        exporter,
        observed_blake3,
        stopped
    }
    =note{
        Some((*peer, *detector, *exporter, *observed_blake3, *stopped))
    }
    else{
        None
    }).collect();
    if ordinary{
        assert!(observations.is_empty(), "ordinary unavailable/local key failure cannot allege peer poison");
    }
    else{
        let want=match case.as_str(){
            "timestamp"=>"L2_POISON_TIMESTAMP",
            "serialization"=>"L2_POISON_SERIALIZATION",
            "marker_open"=>"L2_POISON_MARKER_CREATE",
            _=>panic!("unknown fixed binding case")
        };
        assert_eq!(failure.reason, want);
        assert!(network.reads.load(Ordering::SeqCst)>forward_reads);
        assert_eq!(observations.len(), 1);
        let(p, d, e, h, stopped)=observations[0];
        assert_eq!(p, peer);
        assert_eq!(d, quic::certificate_identity(&std::fs::read(&network.cfg.client_certificate_der_path).unwrap()).unwrap().0);
        assert_ne!(e, [0;32]);
        assert!(stopped);
        let expected_hashes:Vec<_>=network.streams.values().flat_map(|stream|stream.chunks(SEGMENT).map(|chunk|{
            let mut bytes=chunk.to_vec();
            let last=bytes.len()-1;
            bytes[last]^=0x80;
            *blake3::hash(&bytes).as_bytes()
        }).collect::<Vec<_>>()).collect();
        assert!(expected_hashes.contains(&h), "actual observed corrupt segment hash");
    }
    let(result, received)=reverse.fetch(&network);
    let after=reverse.snapshot();
    let after_calls=protected_calls(&after);
    if ordinary{
        result.unwrap();
        assert_eq!(received, network.payload);
        assert!(after_calls.1>before_calls.1&&after_calls.2>before_calls.2);
        assert!(state.clean_lease().is_ok());
    }
    else{
        assert!(result.is_err());
        assert!(received.is_empty());
        assert_eq!(after_calls, before_calls, "no new actual DATA poll or FIN after local stop");
        assert_eq!(reverse.reads.load(Ordering::SeqCst), read_count);
        assert!(state.clean_lease().is_err());
    }
    assert!(reverse.grants.load(Ordering::SeqCst)>grants, "postcondition reached actual authenticated hello and live issuer");
    // The reverse caller's ordinary unavailable result must not stop detector D.
    let detector=quic::certificate_identity(&std::fs::read(&network.cfg.client_certificate_der_path).unwrap()).unwrap().0;
    let d=process_peer_stops().reserve_domain(&network.cfg.poison_state_dir, peer, &[detector]).unwrap();
    assert!(!d.peer(&detector).unwrap().is_stopped());
    support::emit_child_receipt(&serde_json::json!({
        "case":case,
        "synthetic_publication_fault":!ordinary,
        "failure":failure,
        "forward_actual_reads_before":forward_reads,
        "forward_actual_reads_after":network.reads.load(Ordering::SeqCst),
        "actual_exporter_corruption_observations":observations,
        "same_service_process_stop":true,
        "marker_present":false,
        "protected_calls_before":before_calls,
        "protected_calls_after":after_calls,
        "reverse_received_bytes":received.len(),
        "reverse_actual_issuer_grants_before":grants,
        "reverse_actual_issuer_grants_after":reverse.grants.load(Ordering::SeqCst),
        "diagnostics_quic":stages.quic_fetch,
        "publisher_notes":main_notes,
        "reverse_notes_before":before,
        "reverse_notes_after":after,
        "marker_progress":MarkerProgress::NotObserved
    }));
}
/// Called by the exact actual-QUIC outer; owned children never emit outer receipts.
pub(crate) fn run_production_corruption_binding(outer:&str){
    if let Some(role)=support::child_role(outer){
        assert_eq!(role, Role::Sender);
        run_binding_child();
        return;
    }
    let mut run=Run::new(outer);
    let cases=["timestamp_pre_marker_stop", "serialization_pre_marker_stop", "marker_open_pre_marker_stop", "ordinary_transport_no_poison", "local_key_no_poison"];
    run.expect(&cases);
    for(case, fault, label)in [("timestamp", Some(Fault::PublisherTimestamp), cases[0]), ("serialization", Some(Fault::Serialization), cases[1]), ("marker_open", Some(Fault::MarkerCreate), cases[2]), ("transport_unavailable", None, cases[3]), ("local_key", None, cases[4])]{
        let faults=fault.map(|f|vec![(f, 1)]).unwrap_or_default();
        let mut child=run.spawn(Role::Sender, case, &[], &faults);
        child.wait_success();
        let receipt:serde_json::Value=serde_json::from_slice(&std::fs::read(run.fixture.join(format!("{case}-Sender-receipt.json"))).unwrap()).unwrap();
        assert_eq!(receipt["same_service_process_stop"], true);
        assert_eq!(receipt["marker_present"], false);
        run.complete(label);
    }
    run.finish();
}
