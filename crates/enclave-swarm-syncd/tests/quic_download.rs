//! Real private QUIC + independent mTLS HTTPS issuer; synthetic authorities only.
use ed25519_dalek::SigningKey;
use enclave_core::{profile::Profile, secret::SecretKey32};
use enclave_crypto::{biscuit_auth::KeyPair, namespace, tuf::target_file};
use enclave_swarm_syncd::{
    bao,
    governance::Shard,
    seedgate::{HostConditions, SeedGateFSM, Thermal},
    transport::{
        iroh::{L2CapabilityPolicy, L2SwarmNode},
        oblivious::EncryptedTarget,
        quic::{self, IssuerPolicy, L2QuicConfig, SEGMENT},
        registry::RegistryConfig,
    },
};
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::TcpListener,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
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
    p.subject_alt_names.push(rcgen::SanType::URI(format!(
        "spiffe://corporate.internal/shard/{shard}/node/{}",
        hex::encode(public)
    )));
    p.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];
    rcgen::Certificate::from_params(p)
        .unwrap()
        .serialize_der_with_signer(ca)
        .unwrap()
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
        let path = std::env::temp_dir().join(format!("mc-quic-{}", enclave_core::rng::u64()));
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
        let client = SigningKey::from_bytes(&client_seed)
            .verifying_key()
            .to_bytes();
        let signer = Arc::new(SigningKey::from_bytes(&server_seed));
        let issuer_key = KeyPair::new();
        let issuer_public = issuer_key.public().to_bytes();
        // Separate independently pinned membership issuer, not the peer key.
        use enclave_core::enterprise_authority::{EnterpriseAuthority,EnterpriseMember,EnterprisePolicy,SignedEnterprisePolicy};
        let membership_issuer=SigningKey::from_bytes(&[42;32]);let now=enclave_crypto::time::now_unix();
        let membership=EnterpriseAuthority::ephemeral(membership_issuer.verifying_key().to_bytes(),SignedEnterprisePolicy::sign(EnterprisePolicy{
            version:1,revision:1,trust_domain:"fixture.example".into(),issued_unix:now-1,expires_unix:now+3600,
            members:vec![EnterpriseMember{principal:"spiffe://fixture.example/engineer/alice".into(),generation:1,holder_public_keys:vec![hex::encode(client)],namespaces:vec!["models".into()]}],
        },&membership_issuer).unwrap());
        let mut seed = SeedGateFSM::new(Profile::L2);
        seed.update(HostConditions {
            ac_power: true,
            unmetered: true,
            hotspot: false,
            thermal: Thermal::Nominal,
            low_power: false,
        });
        let node = Arc::new(L2SwarmNode::new(
            SigningKey::from_bytes(&server_seed),
            Shard::EU,
            seed,
            L2CapabilityPolicy::new(issuer_key.public(), POLICY).with_enterprise_authority(membership),
        ));
        node.authorize_peer(&hex::encode(client));
        let payload: Vec<u8> = (0..=255)
            .cycle()
            .take(namespace::PLAINTEXT_SIZE * 3 + 77)
            .collect();
        let tf = target_file(&payload, None);
        let root_plain: [u8; 32] = hex::decode(&tf.hashes["blake3"])
            .unwrap()
            .try_into()
            .unwrap();
        let key = SecretKey32::new([12; 32]);
        let mut ciphertext = Vec::new();
        let mut keys = Vec::new();
        let leaves = payload.len().div_ceil(namespace::PLAINTEXT_SIZE);
        for (i, chunk) in payload.chunks(namespace::PLAINTEXT_SIZE).enumerate() {
            let (c, k) =
                namespace::encrypt_chunk(&key, &root_plain, i as u64, i + 1 == leaves, chunk)
                    .unwrap();
            ciphertext.extend_from_slice(&c);
            keys.extend_from_slice(&k);
        }
        let cipher_root = bao::bao_root(&ciphertext);
        let key_root = bao::bao_root(&keys);
        let mut streams = BTreeMap::new();
        streams.insert(
            cipher_root.clone(),
            bao::encode_bao_stream(&ciphertext).unwrap(),
        );
        streams.insert(key_root.clone(), bao::encode_bao_stream(&keys).unwrap());
        let target = EncryptedTarget {
            version: 1,
            ciphertext_bao_root: cipher_root.clone(),
            ciphertext_length: ciphertext.len() as u64,
            key_index_bao_root: key_root.clone(),
            key_index_length: keys.len() as u64,
            key: namespace::wrap("models", 1, 1, key.expose(), &SecretKey32::new([13; 32]))
                .unwrap(),
        };
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
        let peer_authority=enclave_swarm_syncd::transport::quic_seed::SeedPeerAuthority::from_trusted_peers(path.canonicalize().unwrap().to_str().unwrap(),signer.verifying_key().to_bytes(),&[client]).unwrap();
        let serving_node=node.clone();
        let (stop, receiver) = tokio::sync::watch::channel(false);
        let (tx, rx) = std::sync::mpsc::channel();
        let roots = vec![root.clone()];
        let server = thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let endpoint = quic::server_endpoint(
                    "127.0.0.1:0".parse().unwrap(),
                    server_cert,
                    &server_seed,
                    &roots,
                )
                .unwrap();
                tx.send(endpoint.local_addr().unwrap()).unwrap();
                quic::serve(
                    endpoint,
                    serving_node,
                    signer,
                    get,
                    peer_authority,
                    receiver,
                )
                .await
                .unwrap();
            });
        });
        let address = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let issuer_address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let issuer_tls =
            quic::issuer_server_config(issuer_cert, &issuer_seed, &[root.clone()]).unwrap();
        let policy = IssuerPolicy {
            signing_key: issuer_key,
            policy: POLICY,
            grants: BTreeSet::from([
                (hex::encode(client), "models".into(), cipher_root),
                (hex::encode(client), "models".into(), key_root),
            ]),
            servers: HashMap::from([(
                SigningKey::from_bytes(&server_seed)
                    .verifying_key()
                    .to_bytes(),
                "EU".into(),
            )]),
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
                        } {
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
            peer_ed25519_hex: hex::encode(
                SigningKey::from_bytes(&server_seed)
                    .verifying_key()
                    .to_bytes(),
            ),
            issuer_public_key_hex: hex::encode(issuer_public),
            policy_blake3: hex::encode(POLICY),
            shard: "EU".into(),
        };
        Self {
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
        self.stop.send(true).unwrap();
        self.issuer_stop.store(true, Ordering::SeqCst);
        self.server.take().unwrap().join().unwrap();
        self.issuer.take().unwrap().join().unwrap();
        std::fs::remove_dir_all(&self.path).unwrap();
    }
}
#[test]
fn real_quic_authenticated_empty_download_preserves_exact_plaintext() {
    let f = Fixture::new();
    let mut actual = Vec::new();
    quic::fetch(&f.cfg, &f.tf, &f.target, &f.key, |bytes| {
        assert!(bytes.len() <= namespace::PLAINTEXT_SIZE);
        actual.extend_from_slice(bytes);
        Ok(())
    })
    .unwrap();
    assert_eq!(actual, f.payload);
    assert!(f.reads.load(Ordering::SeqCst) > 0);
}
#[test]
fn real_quic_wrong_pin_shard_issuer_and_key_never_publish_success() {
    let f = Fixture::new();
    for change in 0..4 {
        let mut cfg = f.cfg.clone();
        match change {
            0 => cfg.peer_ed25519_hex = "ab".repeat(32),
            1 => cfg.shard = "US".into(),
            2 => cfg.issuer_public_key_hex = "ab".repeat(32),
            _ => cfg.policy_blake3 = "ab".repeat(32),
        }
        let mut accepted = 0;
        assert!(quic::fetch(&cfg, &f.tf, &f.target, &f.key, |bytes| {
            accepted += bytes.len();
            Ok(())
        })
        .is_err());
        assert_eq!(accepted, 0);
        assert_eq!(f.reads.load(Ordering::SeqCst), 0);
    }
}
#[test]
fn real_quic_bao_mismatch_and_namespace_key_refuse_before_plaintext() {
    let f = Fixture::new();
    let wrong_key = SecretKey32::new([99; 32]);
    let mut accepted = 0;
    assert!(quic::fetch(&f.cfg, &f.tf, &f.target, &wrong_key, |bytes| {
        accepted += bytes.len();
        Ok(())
    })
    .is_err());
    assert_eq!(accepted, 0);
    assert!(!f
        .path
        .join(format!("{}.json", f.cfg.peer_ed25519_hex))
        .exists());
    let mut good = Vec::new();
    quic::fetch(&f.cfg, &f.tf, &f.target, &f.key, |bytes| {
        good.extend_from_slice(bytes);
        Ok(())
    })
    .unwrap();
    assert_eq!(good, f.payload);
    let mut target = f.target.clone();
    target.ciphertext_bao_root = "ab".repeat(32);
    assert!(quic::fetch(&f.cfg, &f.tf, &target, &f.key, |_| panic!(
        "no unauthenticated plaintext"
    ))
    .is_err());
}

#[test]
fn real_quic_corruption_signs_exporter_receipt_and_persists_retry_quarantine() {
    let f = Fixture::new();
    f.corrupt.store(true, Ordering::SeqCst);
    assert!(quic::fetch(&f.cfg, &f.tf, &f.target, &f.key, |_| panic!(
        "corrupt first leaf"
    ))
    .is_err());
    let receipt: enclave_swarm_syncd::transport::receipt::PoisonReceipt = serde_json::from_slice(
        &std::fs::read(f.path.join(format!("{}.json", f.cfg.peer_ed25519_hex))).unwrap(),
    )
    .unwrap();
    receipt.verify().unwrap();
    assert_eq!(receipt.peer_id, f.cfg.peer_ed25519_hex);
    assert_eq!(
        receipt.detector_id,
        hex::encode(quic::certificate_identity(&std::fs::read(&f.cfg.client_certificate_der_path).unwrap()).unwrap().0)
    );
    assert_eq!(receipt.target_root, f.target.ciphertext_bao_root);
    assert_eq!(receipt.expected_hash, f.target.ciphertext_bao_root);
    assert_eq!(receipt.session_binding.len(), 64);
    assert_ne!(receipt.session_binding, "00".repeat(32));
    assert!(receipt.timestamp_utc_ms > 0);
    f.corrupt.store(false, Ordering::SeqCst);
    let reads = f.reads.load(Ordering::SeqCst);
    let error =
        quic::fetch(&f.cfg, &f.tf, &f.target, &f.key, |_| panic!("quarantined")).unwrap_err();
    assert!(error.is("PEER_QUARANTINED_BYZANTINE"));
    assert_eq!(reads, f.reads.load(Ordering::SeqCst));
}

use enclave_core::{
    err,
    error::EnclaveResult,
    ipc::{self, PeerCredentials},
};
use enclave_crypto::{
    namespace::{CasKeyLease, WrappedNamespaceKey},
    tuf::{RepoBuilder, TargetFile},
};
use enclave_swarm_syncd::{
    service::{CasConfig, CasRequest, CasResponse, CasService},
    transport::{
        custody::{NamespaceCustody, NamespaceRelease},
        registry::{DistributionConfig, DISTRIBUTION_CONFIG_TARGET},
    },
};
use std::io::{Read, Write};
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
        } else {
            Err(err!(EACCES, "FIXTURE_KEY_REMOVED"))
        }
    }
}
struct ServiceFixture {
    base: PathBuf,
    service: Arc<CasService>,
    peer: PeerCredentials,
    repo: RepoBuilder,
    targets: BTreeMap<String, TargetFile>,
    uri: String,
    custody: Arc<ServiceCustody>,
}
impl ServiceFixture {
    fn new(network: &Fixture) -> Self {
        let base = PathBuf::from("/tmp").join(format!("mqcas{:x}", enclave_core::rng::u64()));
        std::fs::create_dir(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let repo = RepoBuilder::new(3, 2);
        let root = repo.root("2030-01-01T00:00:00Z").unwrap();
        let service = CasService::start(CasConfig {dev_same_uid: true,
            profile: Profile::L2,
            store_dir: base.join("store"),
            audit_path: Some(base.join("audit.jsonl")),
            tuf_root: Some(root),
            ohttp_gateway: None,
            state_dir: None,
            revocation: enclave_swarm_syncd::revocation::Enforcement::InProcess,
        })
        .unwrap();
        let config = serde_json::to_vec(&DistributionConfig {
            version: 1,
            l1: None,
            l2: Some(network.cfg.clone()),
            l3: None,
        })
        .unwrap();
        std::fs::write(base.join("store").join(DISTRIBUTION_CONFIG_TARGET), &config).unwrap();
        let custom = serde_json::json!({"classification":"internal_l2","min_profile":"L2","jurisdiction_shard":"EU","license_policy":{"spdx_id":"LicenseRef-private-QUIC-fixture","allow_p2p_seeding":true},"encrypted_transport":network.target});
        let targets = [
            (
                "model.bin".into(),
                target_file(&network.payload, Some(custom)),
            ),
            (
                DISTRIBUTION_CONFIG_TARGET.into(),
                target_file(&config, Some(serde_json::json!({}))),
            ),
        ]
        .into_iter()
        .collect();
        let mut peer = PeerCredentials::local(ipc::geteuid(), 0);
        peer.pid = Some(std::process::id() as i32);
        let custody = Arc::new(ServiceCustody {
            key: network.key.clone(),
            valid: AtomicBool::new(true),
        });
        service.set_namespace_custody(custody.clone()).unwrap();
        let fixture = Self {
            base,
            service,
            peer,
            repo,
            targets,
            uri: format!(
                "cas://blake3-bao-v1/{}?target=model.bin&ns=models",
                blake3::hash(&network.payload).to_hex()
            ),
            custody,
        };
        fixture.refresh(1, fixture.targets.clone());
        fixture
    }
    fn refresh(&self, version: u64, targets: BTreeMap<String, TargetFile>) {
        let targets = self
            .repo
            .targets(version, "2030-01-01T00:00:00Z", targets)
            .unwrap();
        let snapshot = self
            .repo
            .snapshot(version, "2030-01-01T00:00:00Z", version, &targets)
            .unwrap();
        let timestamp = self
            .repo
            .timestamp(version, "2030-01-01T00:00:00Z", version, &snapshot)
            .unwrap();
        self.service
            .handle(
                &self.peer,
                CasRequest::TufRefresh {
                    roots: vec![],
                    timestamp: timestamp.into(),
                    snapshot: snapshot.into(),
                    targets: targets.into(),
                },
            )
            .unwrap();
    }
    fn unpublished(&self, network: &Fixture) {
        let root = blake3::hash(&network.payload).to_hex().to_string();
        assert!(!self
            .base
            .join("store/manifests")
            .join(format!("{root}.json"))
            .exists());
        assert!(!std::fs::read_to_string(self.base.join("audit.jsonl"))
            .unwrap()
            .contains("\"event\":\"HYDRATED\""));
        assert!(std::fs::read_dir(self.base.join("store/streaming-stages"))
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("stage-")));
    }
}
impl Drop for ServiceFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}
fn assert_quic_stages(fixture:&ServiceFixture,started:u64,ok:u64,err:u64) {
    let CasResponse::SyncDiagnostics(snapshot)=fixture.service.handle(&fixture.peer,CasRequest::SyncDiagnostics).unwrap() else {panic!("typed diagnostics");};
    assert!(snapshot.valid_measurement());assert_eq!(snapshot.availability,enclave_swarm_syncd::sync_diagnostics::CounterAvailability::Current);
    let stages=snapshot.stages.unwrap();
    assert_eq!(stages.registry_fetch,enclave_swarm_syncd::sync_diagnostics::StageCounters::default());
    assert_eq!(stages.ohttp_fetch,enclave_swarm_syncd::sync_diagnostics::StageCounters::default());
    assert_eq!(stages.quic_fetch,enclave_swarm_syncd::sync_diagnostics::StageCounters {started,in_flight:0,returned_ok:ok,returned_err:err,abandoned_unknown:0});
}
#[test]
fn l2_service_empty_cache_open_target_hydrates_quic_and_transfers_exact_readonly_fd() {
    let network = Fixture::new();
    let fixture = ServiceFixture::new(&network);
    let path = fixture.base.join("cas.sock");
    let listener = ipc::bind(&path, ipc::SocketAccess::OwnerOnly).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let service = fixture.service.clone();
    let worker = thread::spawn(move || {
        ipc::serve::<CasRequest, CasResponse, _>(
            listener,
            ipc::PeerPolicy::allow([ipc::geteuid()]),
            Arc::new(move |peer: &PeerCredentials, request| service.handle(peer, request)),
            flag,
        )
        .unwrap()
    });
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut client = ipc::Client::connect(&path, ipc::geteuid()).unwrap();
        client.set_timeout(Some(Duration::from_secs(15))).unwrap();
        let response: CasResponse = client
            .call(&CasRequest::OpenTarget {
                target: "model.bin".into(),
            })
            .unwrap();
        assert!(
            matches!(response,CasResponse::TargetFile{fds:1,length,..}if length==network.payload.len() as u64)
        );
        let mut fds = client.recv_fds(4).unwrap();
        assert_eq!(fds.len(), 1);
        let mut file = std::fs::File::from(fds.pop().unwrap());
        let mut bytes = vec![];
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, network.payload);
        assert!(file.write_all(b"X").is_err());
        let reads = network.reads.load(Ordering::SeqCst);
        assert!(reads > 1);
        let response: CasResponse = client
            .call(&CasRequest::Hydrate {
                cas_uri: fixture.uri.clone(),
            })
            .unwrap();
        assert!(matches!(response, CasResponse::Admitted { .. }));
        assert_eq!(reads, network.reads.load(Ordering::SeqCst));
        fixture.custody.valid.store(false, Ordering::SeqCst);
        assert!(client
            .call::<_, CasResponse>(&CasRequest::OpenTarget {
                target: "model.bin".into()
            })
            .is_err());
    }));
    stop.store(true, Ordering::SeqCst);
    worker.join().unwrap();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
    assert_quic_stages(&fixture,1,1,0);
}
#[test]
fn l2_service_custody_wipe_and_signed_policy_changes_abort_actual_quic_without_publication() {
    for mode in 0..4 {
        let network = Fixture::new();
        let fixture = ServiceFixture::new(&network);
        network.hold.store(true, Ordering::SeqCst);
        let service = fixture.service.clone();
        let peer = fixture.peer.clone();
        let uri = fixture.uri.clone();
        let worker =
            thread::spawn(move || service.handle(&peer, CasRequest::Hydrate { cas_uri: uri }));
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while !network.entered.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(2));
        }
        assert!(
            network.entered.load(Ordering::SeqCst),
            "actual authorized QUIC request must begin mode{mode}"
        );
        match mode {
            0 => {
                fixture.custody.valid.store(false, Ordering::SeqCst);
            }
            1 => {
                fixture
                    .service
                    .handle(&fixture.peer, CasRequest::Wipe)
                    .unwrap();
            }
            _ => {
                let mut changed = fixture.targets.clone();
                let custom = changed
                    .get_mut("model.bin")
                    .unwrap()
                    .custom
                    .as_mut()
                    .unwrap();
                if mode == 2 {
                    custom["license_policy"]["allow_p2p_seeding"] = serde_json::json!(false);
                } else {
                    custom["jurisdiction_shard"] = serde_json::json!("US");
                }
                fixture.refresh(2, changed);
            }
        }
        network.hold.store(false, Ordering::SeqCst);
        assert!(worker.join().unwrap().is_err(), "mode{mode}");
        fixture.unpublished(&network);
        assert_quic_stages(&fixture,1,0,1);
    }
}
#[test]
fn l2_service_license_shard_or_missing_custody_refuses_before_any_peer_storage() {
    for mode in 0..3 {
        let network = Fixture::new();
        let fixture = ServiceFixture::new(&network);
        match mode {
            0 => {
                let mut changed = fixture.targets.clone();
                changed
                    .get_mut("model.bin")
                    .unwrap()
                    .custom
                    .as_mut()
                    .unwrap()["license_policy"]["allow_p2p_seeding"] = serde_json::json!(false);
                fixture.refresh(2, changed);
            }
            1 => {
                let mut changed = fixture.targets.clone();
                changed
                    .get_mut("model.bin")
                    .unwrap()
                    .custom
                    .as_mut()
                    .unwrap()["jurisdiction_shard"] = serde_json::json!("US");
                fixture.refresh(2, changed);
            }
            _ => {
                fixture.custody.valid.store(false, Ordering::SeqCst);
            }
        }
        assert!(fixture
            .service
            .handle(
                &fixture.peer,
                CasRequest::Hydrate {
                    cas_uri: fixture.uri.clone()
                }
            )
            .is_err());
        assert_eq!(network.reads.load(Ordering::SeqCst), 0);
        fixture.unpublished(&network);
        assert_quic_stages(&fixture,0,0,0);
    }
}

#[test]
fn actual_quic_local_revocation_gate_denies_authorized_peer_before_storage() {
    let f = Fixture::new();
    f.node.authorized_peers.lock().unwrap().clear();
    let error = quic::fetch(&f.cfg, &f.tf, &f.target, &f.key, |_| {
        panic!("locally revoked peer")
    })
    .unwrap_err();
    assert!(error.is("BAO_SLICE_CORRUPT"));
    assert_eq!(f.reads.load(Ordering::SeqCst), 0);
    assert!(
        !f.path
            .join(format!("{}.json", f.cfg.peer_ed25519_hex))
            .exists(),
        "unavailable is not poison evidence"
    );
}

#[test]
fn actual_quic_rechecks_revocation_after_slow_source_before_any_response_bytes() {
    let f = Fixture::new();
    f.revoke_after_first.store(true, Ordering::SeqCst);
    assert!(quic::fetch(&f.cfg, &f.tf, &f.target, &f.key, |_| panic!(
        "first leaf needs second segment"
    ))
    .is_err());
    assert_eq!(
        f.reads.load(Ordering::SeqCst),
        1,
        "revocation inside source callback must refuse the first segment before response"
    );
}
#[test]
fn actual_quic_renews_independent_capabilities_during_one_bounded_download() {
    let f = Fixture::new();
    f.delay_first_ms.store(8_000, Ordering::SeqCst);
    let mut bytes = vec![];
    quic::fetch(&f.cfg, &f.tf, &f.target, &f.key, |part| {
        bytes.extend_from_slice(part);
        Ok(())
    })
    .unwrap();
    assert_eq!(bytes, f.payload);
    assert!(f.issuer_grants.load(Ordering::SeqCst)>=4,"both encrypted streams require fresh independently issued capabilities after the renewal interval");
}
#[test]
fn signed_total_deadline_expires_even_when_individual_peer_deadline_is_longer() {
    let f = Fixture::new();
    f.delay_first_ms.store(300, Ordering::SeqCst);
    let mut config = f.cfg.clone();
    config.total_timeout_ms = 100;
    let started = std::time::Instant::now();
    assert!(quic::fetch(&config, &f.tf, &f.target, &f.key, |_| panic!(
        "total deadline"
    ))
    .is_err());
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(
        !f.path
            .join(format!("{}.json", f.cfg.peer_ed25519_hex))
            .exists(),
        "timeout is not poison"
    );
    config.total_timeout_ms = 0;
    assert!(config
        .validate()
        .unwrap_err()
        .is("L2_TOTAL_DEADLINE_CONFIG"));
    config.total_timeout_ms = 28_800_001;
    assert!(config
        .validate()
        .unwrap_err()
        .is("L2_TOTAL_DEADLINE_CONFIG"));
}
#[test]
fn l2_cached_target_rechecks_current_signed_shard_and_namespace_without_refetch() {
    let network = Fixture::new();
    let f = ServiceFixture::new(&network);
    f.service
        .handle(
            &f.peer,
            CasRequest::Hydrate {
                cas_uri: f.uri.clone(),
            },
        )
        .unwrap();
    let reads = network.reads.load(Ordering::SeqCst);
    let foreign = f.uri.replace("ns=models", "ns=other");
    for request in [
        CasRequest::Hydrate {
            cas_uri: foreign.clone(),
        },
        CasRequest::Resolve {
            cas_uri: foreign.clone(),
        },
        CasRequest::Fetch { cas_uri: foreign },
    ] {
        assert!(f.service.handle(&f.peer, request).is_err());
    }
    let mut changed = f.targets.clone();
    changed
        .get_mut("model.bin")
        .unwrap()
        .custom
        .as_mut()
        .unwrap()["jurisdiction_shard"] = serde_json::json!("US");
    f.refresh(2, changed);
    for request in [
        CasRequest::Hydrate {
            cas_uri: f.uri.clone(),
        },
        CasRequest::Resolve {
            cas_uri: f.uri.clone(),
        },
        CasRequest::Fetch {
            cas_uri: f.uri.clone(),
        },
        CasRequest::OpenTarget {
            target: "model.bin".into(),
        },
    ] {
        assert!(f.service.handle(&f.peer, request).is_err());
    }
    assert_eq!(reads, network.reads.load(Ordering::SeqCst));
}

#[test]
fn actual_quic_rechecks_local_revocation_on_a_live_reused_connection() {
    let f = Fixture::new();
    let mut accepted = 0;
    let error = quic::fetch(&f.cfg, &f.tf, &f.target, &f.key, |bytes| {
        accepted += bytes.len();
        f.node.authorized_peers.lock().unwrap().clear();
        Ok(())
    })
    .unwrap_err();
    assert!(error.is("BAO_SLICE_CORRUPT"));
    assert_eq!(accepted, namespace::PLAINTEXT_SIZE);
    assert_eq!(f.reads.load(Ordering::SeqCst),3,"first leaf needs two cipher segments and one key-index segment; next request on this same connection must not access storage");
}
