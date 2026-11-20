//! Owned-process acceptance schedules at the real production QUIC handoffs.
use super::*;
use crate::{
    governance::Shard,
    seedgate::{
        HostConditions,
        SeedGateFSM
    },
    transport::{
        quic_fence_test_support as support,
        quic_seed::SeedPeerAuthority
    }
};
use enclave_core::{
    enterprise_authority::{
        EnterpriseAuthority,
        EnterpriseMember,
        EnterprisePolicy,
        SignedEnterprisePolicy
    },
    profile::Profile
};
use std::{
    cell::RefCell,
    fs::OpenOptions,
    os::unix::{
        fs::{
            MetadataExt,
            OpenOptionsExt,
            PermissionsExt
        },
        io::AsRawFd
    },
    path::PathBuf,
    sync::atomic::{
        AtomicBool,
        AtomicUsize,
        Ordering
    },
    thread
};
use support::{
    ClockResult,
    Fault,
    Guard,
    Note,
    PollResult,
    Role,
    Run,
    Stage
};
const POLICY: [u8; 32] = [9; 32];
thread_local! {
    static RESULTS: RefCell<Vec<serde_json::Value>>  = const {
        RefCell::new(Vec::new())
    };
}
pub(crate) fn wall_ms() -> u64 {
    now_ms().unwrap()
}
pub(super) fn record_release_result(node: &L2SwarmNode, peer: &L2AuthenticatedPeer, expires: u64, result: &EnclaveResult<()>) {
    if std::env::var_os("MCPMAC_QF_CHILD_CONFIG").is_none() {
        return;
    }
    probe_all(node);
    RESULTS.with(|values|values.borrow_mut().push(serde_json::json!( {
        "peer": hex::encode(peer.public_key),
        "expires_ms": expires,
        "outcome": match result {
            Ok(()) => "OK",
            Err(error) => error.reason.as_str()
        },
        "errno": result.as_ref().err().map(|e|format!("{:?}", e.errno)),
        "at_ms": wall_ms()
    })));
}
pub(super) fn record_refusal_complete(_node: &L2SwarmNode, _peer: &L2AuthenticatedPeer) {
    support::hook(Stage::ProbeCompleted, 1);
}
pub(super) fn probe_pending(node: &L2SwarmNode) {
    probe_all(node);
}
fn probe_all(node: &L2SwarmNode) {
    let authority = node.enterprise_authority().unwrap();
    let serial = authority.release_serial();
    let s = serial.try_lock().unwrap();
    support::note(Note::GuardProbe {
        operation: 0,
        guard: Guard::Serial,
        success: true
    });
    let q = node.quarantine_table.try_write_for_test().unwrap();
    support::note(Note::GuardProbe {
        operation: 0,
        guard: Guard::Quarantine,
        success: true
    });
    let p = node.authorized_peers.try_lock().unwrap();
    support::note(Note::GuardProbe {
        operation: 0,
        guard: Guard::AuthorizedPeers,
        success: true
    });
    let g = node.seed_gate.try_lock().unwrap();
    support::note(Note::GuardProbe {
        operation: 0,
        guard: Guard::SeedGate,
        success: true
    });
    let a = authority.try_current_guard().unwrap();
    support::note(Note::GuardProbe {
        operation: 0,
        guard: Guard::EnterpriseCurrent,
        success: true
    });
    drop(a);
    drop(g);
    drop(p);
    drop(q);
    drop(s);
}
pub(crate) fn identity(ca: &rcgen::Certificate, seed: [u8; 32], shard: &str) -> Vec<u8> {
    let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let mut der = hex::decode("302e020100300506032b657004220420").unwrap();
    der.extend_from_slice(&seed);
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]);
    params.alg = &rcgen::PKCS_ED25519;
    params.key_pair = Some(rcgen::KeyPair::from_der(&der).unwrap());
    params.subject_alt_names.push(rcgen::SanType::URI(format!("spiffe://corporate.internal/shard/{shard}/node/{}", hex::encode(public))));
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth, rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    rcgen::Certificate::from_params(params).unwrap().serialize_der_with_signer(ca).unwrap()
}
pub(crate) fn registry(address: SocketAddr, root: &[u8]) -> RegistryConfig {
    RegistryConfig {
        address: address.to_string(),
        server_name: "localhost".into(),
        repository: "fixture".into(),
        tls_roots_der: vec![hex::encode(root)],
        timeout_ms: 5_000
    }
}
#[derive(Serialize, Deserialize, Clone)] struct FixtureConfig {
    directory: PathBuf,
    root: Vec<u8>,
    client_seeds: [[u8; 32]; 2],
    client_certs: [Vec<u8>; 2],
    server_seed: [u8; 32],
    server_cert: Vec<u8>,
    issuer_seed: [u8; 32],
    issuer_cert: Vec<u8>,
    stream_root: String,
    small_window: bool
}
fn private_write(path: impl AsRef<Path>, bytes: &[u8]) {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn prepare(run: &Run, small_window: bool) {
    let directory = run.fixture.join("state");
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut ca = rcgen::CertificateParams::new(vec!["qf-ca".into()]);
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = rcgen::Certificate::from_params(ca).unwrap();
    let client_seeds = [enclave_core::rng::bytes32(), enclave_core::rng::bytes32()];
    let server_seed = enclave_core::rng::bytes32();
    let issuer_seed = enclave_core::rng::bytes32();
    let fixture = FixtureConfig {
        directory,
        root: ca.serialize_der().unwrap(),
        client_seeds,
        client_certs: [identity(&ca, client_seeds[0], "EU"), identity(&ca, client_seeds[1], "EU")],
        server_seed,
        server_cert: identity(&ca, server_seed, "EU"),
        issuer_seed,
        issuer_cert: identity(&ca, issuer_seed, "EU"),
        stream_root: crate::bao::bao_root(&vec![42; SEGMENT*2]),
        small_window
    };
    private_write(run.fixture.join("fixture.json"), &serde_json::to_vec(&fixture).unwrap());
}
fn fixture() -> FixtureConfig {
    serde_json::from_slice(&std::fs::read(support::fixture_path().join("fixture.json")).unwrap()).unwrap()
}
fn key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}
fn issuer_thread(f: &FixtureConfig, issuer: KeyPair) -> (SocketAddr, Arc<AtomicBool>, thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let tls = issuer_server_config(f.issuer_cert.clone(), &f.issuer_seed, &[f.root.clone()]).unwrap();
    let policy = IssuerPolicy {
        signing_key: issuer,
        policy: POLICY,
        grants: f.client_seeds.iter().map(|s|(hex::encode(key(s)), "models".into(), f.stream_root.clone())).collect(),
        servers: [(key(&f.server_seed), "EU".into())].into_iter().collect()
    };
    let stop = Arc::new(AtomicBool::new(false));
    let done = stop.clone();
    let thread = thread::spawn(move || {
        while !done.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((socket, _)) => {
                    socket.set_nonblocking(false).unwrap();
                    serve_issuer_connection(socket, tls.clone(), &policy).unwrap();
                },
                Err(error)if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(2)),
                Err(error) => panic!("{error}")
            }
        }
    });
    (address, stop, thread)
}
#[derive(Clone, Copy, Serialize)]
struct DriverIdleResult {
    completed: bool,
    elapsed_ms: u64
}
const MAX_RUNTIME_SPAWNS: usize = 16;
#[derive(Debug)]
struct RuntimeDispatch {
    owner_thread: thread::ThreadId,
    requested: AtomicUsize,
    started: AtomicUsize,
    owner_mismatches: AtomicUsize,
    start_threads: std::sync::Mutex<Vec<thread::ThreadId>>
}
fn bounded_runtime_increment(counter: &AtomicUsize) {
    counter.try_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
        if value<MAX_RUNTIME_SPAWNS {
            Some(value+1)
        } else {
            None
        }
    }).expect("fixture runtime spawn capacity");
}
impl RuntimeDispatch {
    fn receipt(&self) -> serde_json::Value {
        let observer_thread = thread::current().id();
        let threads = self.start_threads.lock().unwrap().clone();
        let requested = self.requested.load(Ordering::SeqCst);
        let started = self.started.load(Ordering::SeqCst);
        let mismatches = self.owner_mismatches.load(Ordering::SeqCst);
        let value = serde_json::json!({
            "owner_thread": format!("{:?}", self.owner_thread),
            "application_thread": format!("{observer_thread:?}"),
            "spawn_requested": requested,
            "spawn_started": started,
            "owner_mismatches": mismatches,
            "spawn_start_threads": threads.iter().map(|id|format!("{id:?}")).collect::<Vec<_>>()
        });
        let encoded = serde_json::to_string(&value).unwrap();
        assert!(encoded.len()<=1024);
        eprintln!("QF_FIXTURE_RUNTIME {encoded}");
        assert_ne!(observer_thread, self.owner_thread);
        assert!(started>=2, "actual endpoint and connection drivers must start");
        assert_eq!(started, requested);
        assert_eq!(mismatches, 0);
        assert_eq!(threads.len(), started);
        assert!(threads.iter().all(|id|*id == self.owner_thread));
        value
    }
}
#[derive(Debug)]
struct HandleQuinnRuntime {
    handle: tokio::runtime::Handle,
    dispatch: Arc<RuntimeDispatch>
}
impl quinn::Runtime for HandleQuinnRuntime {
    fn new_timer(&self, at: Instant) -> std::pin::Pin<Box<dyn quinn::AsyncTimer>> {
        let _entered = self.handle.enter();
        quinn::Runtime::new_timer(&quinn::TokioRuntime, at)
    }
    fn spawn(&self, future: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>) {
        bounded_runtime_increment(&self.dispatch.requested);
        let dispatch = self.dispatch.clone();
        self.handle.spawn(async move {
            let current = thread::current().id();
            bounded_runtime_increment(&dispatch.started);
            if current != dispatch.owner_thread {
                bounded_runtime_increment(&dispatch.owner_mismatches);
            }
            {
                let mut threads = dispatch.start_threads.lock().unwrap();
                assert!(threads.len()<MAX_RUNTIME_SPAWNS);
                threads.push(current);
            }
            future.await;
        });
    }
    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        let _entered = self.handle.enter();
        quinn::Runtime::wrap_udp_socket(&quinn::TokioRuntime, socket)
    }
    fn now(&self) -> Instant {
        let _entered = self.handle.enter();
        quinn::Runtime::now(&quinn::TokioRuntime)
    }
}
fn driver_quinn_runtime() -> (Arc<dyn quinn::Runtime>, Arc<RuntimeDispatch>) {
    let dispatch = Arc::new(RuntimeDispatch {
        owner_thread: thread::current().id(),
        requested: AtomicUsize::new(0),
        started: AtomicUsize::new(0),
        owner_mismatches: AtomicUsize::new(0),
        start_threads: std::sync::Mutex::new(Vec::with_capacity(MAX_RUNTIME_SPAWNS))
    });
    let runtime = Arc::new(HandleQuinnRuntime {
        handle: tokio::runtime::Handle::current(),
        dispatch: dispatch.clone()
    });
    (runtime, dispatch)
}
fn sender_lifecycle(events: &Arc<std::sync::Mutex<Vec<serde_json::Value>>>, started: Instant, stage: &'static str, driver_idle: Option<DriverIdleResult>) {
    let event = serde_json::json!({
        "role": "Sender",
        "stage": stage,
        "at_ms": wall_ms(),
        "elapsed_ms": u64::try_from(started.elapsed().as_millis()).unwrap(),
        "driver_idle": driver_idle
    });
    let encoded = serde_json::to_string(&event).unwrap();
    assert!(encoded.len()<=512);
    eprintln!("QF_FIXTURE_LIFECYCLE {encoded}");
    let mut events = events.lock().unwrap();
    assert!(events.len()<32);
    events.push(event);
}
fn sender() {
    let lifecycle_started = Instant::now();
    let lifecycle = Arc::new(std::sync::Mutex::new(Vec::with_capacity(32)));
    let f = fixture();
    let issuer = KeyPair::new();
    let issuer_verifier = issuer.public();
    let issuer_public = issuer_verifier.to_bytes();
    let (address, issuer_stop, issuer_thread) = issuer_thread(&f, issuer);
    let admin = SigningKey::from_bytes(&enclave_core::rng::bytes32());
    let now = enclave_crypto::time::now_unix();
    let membership = EnterpriseAuthority::ephemeral(admin.verifying_key().to_bytes(), SignedEnterprisePolicy::sign(EnterprisePolicy {
        version: 1,
        revision: 1,
        trust_domain: "fence.example".into(),
        issued_unix: now-1,
        expires_unix: now+3600,
        members: f.client_seeds.iter().enumerate().map(|(i, s)|EnterpriseMember {
            principal: format!("spiffe://fence.example/engineer/u{i}"),
            generation: 1,
            holder_public_keys: vec![hex::encode(key(s))],
            namespaces: vec!["models".into()]
        }).collect()
    }, &admin).unwrap());
    let mut gate = SeedGateFSM::new(Profile::L2);
    gate.update(HostConditions::default());
    let signer = Arc::new(SigningKey::from_bytes(&f.server_seed));
    let node = Arc::new(L2SwarmNode::new((*signer).clone(), Shard::EU, gate, super::super::iroh::L2CapabilityPolicy::new(issuer_verifier, POLICY).with_enterprise_authority(membership)));
    for seed in &f.client_seeds {
        node.authorize_peer(&hex::encode(key(seed)));
    }
    let authority = SeedPeerAuthority::from_trusted_peers(f.directory.to_str().unwrap(), key(&f.server_seed), &f.client_seeds.iter().map(key).collect::<Vec<_>>()).unwrap();
    // Both endpoint and connection drivers use the owned runtime Handle.
    // Endpoint creation alone does not bind Quinn's later connection spawns.
    let (driver_stop, mut driver_receiver) = tokio::sync::watch::channel(false);
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let driver_f = f.clone();
    let driver_lifecycle = lifecycle.clone();
    let driver = thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            let mut cfg = server_configuration(driver_f.server_cert, &driver_f.server_seed, &[driver_f.root]).unwrap();
            if driver_f.small_window {
                Arc::get_mut(&mut cfg.transport).unwrap().send_window(1024);
            }
            let (runtime, dispatch) = driver_quinn_runtime();
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.set_nonblocking(true).unwrap();
            let endpoint = quinn::Endpoint::new(quinn::EndpointConfig::default(), Some(cfg), socket, runtime).unwrap();
            tx.send(endpoint.clone()).unwrap();
            let _ = driver_receiver.changed().await;
            sender_lifecycle(&driver_lifecycle, lifecycle_started, "driver_close_before", None);
            endpoint.close(0u32.into(), b"fixture complete");
            sender_lifecycle(&driver_lifecycle, lifecycle_started, "driver_close_after", None);
            sender_lifecycle(&driver_lifecycle, lifecycle_started, "driver_idle_wait_before", None);
            let idle_started = Instant::now();
            let completed = tokio::time::timeout(Duration::from_secs(1), endpoint.wait_idle()).await.is_ok();
            let result = DriverIdleResult {
                completed,
                elapsed_ms: u64::try_from(idle_started.elapsed().as_millis()).unwrap()
            };
            sender_lifecycle(&driver_lifecycle, lifecycle_started, "driver_idle_wait_after", Some(result));
            (result, dispatch)
        })
    });
    let endpoint = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let peer_address = endpoint.local_addr().unwrap();
    private_write(support::fixture_path().join("addresses.json"), &serde_json::to_vec(&serde_json::json!( {
        "peer": peer_address,
        "issuer": address,
        "issuer_public": hex::encode(issuer_public)
    })).unwrap());
    support::hook(Stage::ChildReady, 0);
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let stop_path = support::fixture_path().join("receiver-done");
    let get = Arc::new(move|_: &str, _: &str, index: u64|match index {
        0 => Some(vec![42; 32]),
        1 => Some(vec![42; SEGMENT]),
        _ => None
    });
    rt.block_on(async {
        let (stop, receiver) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(serve(endpoint, node, signer, get, authority, receiver));
        let until = Instant::now()+Duration::from_secs(12);
        sender_lifecycle(&lifecycle, lifecycle_started, "receiver_done_wait_before", None);
        while !stop_path.exists() {
            assert!(Instant::now()<until, "receiver completion deadline");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        sender_lifecycle(&lifecycle, lifecycle_started, "receiver_done_wait_after", None);
        sender_lifecycle(&lifecycle, lifecycle_started, "serve_stop_before", None);
        stop.send(true).unwrap();
        sender_lifecycle(&lifecycle, lifecycle_started, "serve_stop_after", None);
        sender_lifecycle(&lifecycle, lifecycle_started, "serve_join_before", None);
        task.await.unwrap().unwrap();
        sender_lifecycle(&lifecycle, lifecycle_started, "serve_join_after", None);
    });
    // Drop the stopped serving runtime while the endpoint driver still runs.
    // Its detached production connection tasks must release their QUIC handles
    // before the driver is asked to drain and joined by this thread.
    sender_lifecycle(&lifecycle, lifecycle_started, "serving_runtime_drop_before", None);
    drop(rt);
    sender_lifecycle(&lifecycle, lifecycle_started, "serving_runtime_drop_after", None);
    sender_lifecycle(&lifecycle, lifecycle_started, "driver_stop_before", None);
    driver_stop.send(true).unwrap();
    sender_lifecycle(&lifecycle, lifecycle_started, "driver_stop_after", None);
    sender_lifecycle(&lifecycle, lifecycle_started, "driver_join_before", None);
    let (driver_idle, dispatch) = driver.join().unwrap();
    sender_lifecycle(&lifecycle, lifecycle_started, "driver_join_after", Some(driver_idle));
    sender_lifecycle(&lifecycle, lifecycle_started, "issuer_stop_before", None);
    issuer_stop.store(true, Ordering::SeqCst);
    sender_lifecycle(&lifecycle, lifecycle_started, "issuer_stop_after", None);
    sender_lifecycle(&lifecycle, lifecycle_started, "issuer_join_before", None);
    issuer_thread.join().unwrap();
    sender_lifecycle(&lifecycle, lifecycle_started, "issuer_join_after", None);
    let results = RESULTS.with(|v|v.borrow().clone());
    let runtime_dispatch = dispatch.receipt();
    sender_lifecycle(&lifecycle, lifecycle_started, "final_receipt_before", Some(driver_idle));
    let lifecycle = lifecycle.lock().unwrap().clone();
    support::emit_child_receipt(&serde_json::json!( {
        "role": "actual_production_sender",
        "notes": support::notes(),
        "releases": results,
        "lifecycle": lifecycle,
        "runtime_dispatch": runtime_dispatch,
        "driver_idle": driver_idle,
        "fixture_shutdown_status": if driver_idle.completed {
            "PASS_IDLE_COMPLETE"
        } else {
            "FAIL_IDLE_TIMEOUT"
        }
    }));
    assert!(driver_idle.completed, "fixture endpoint did not reach idle within one-second fixture teardown bound");
}
fn client_config(f: &FixtureConfig, index: usize) -> L2QuicConfig {
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(support::fixture_path().join("addresses.json")).unwrap()).unwrap();
    let credentials = support::fixture_path();
    let cert = credentials.join(format!("client{index}.der"));
    let seed = credentials.join(format!("client{index}.key"));
    if !cert.exists() {
        private_write(&cert, &f.client_certs[index]);
        private_write(&seed, &f.client_seeds[index]);
    }
    L2QuicConfig {
        peer: registry(v["peer"].as_str().unwrap().parse().unwrap(), &f.root),
        issuer: registry(v["issuer"].as_str().unwrap().parse().unwrap(), &f.root),
        client_certificate_der_path: cert.to_str().unwrap().into(),
        client_key_seed_path: seed.to_str().unwrap().into(),
        peer_ed25519_hex: hex::encode(key(&f.server_seed)),
        issuer_public_key_hex: v["issuer_public"].as_str().unwrap().into(),
        policy_blake3: hex::encode(POLICY),
        shard: "EU".into(),
        poison_state_dir: f.directory.to_str().unwrap().into(),
        seed: None,
        total_timeout_ms: 10_000,
        enterprise_authority: None
    }
}
struct ClientEndpoint {
    endpoint: quinn::Endpoint,
    stop: tokio::sync::watch::Sender<bool>,
    driver: Option<thread::JoinHandle<()>>,
    dispatch: Arc<RuntimeDispatch>
}
impl ClientEndpoint {
    fn finish(self) -> serde_json::Value {
        let dispatch = self.dispatch.clone();
        drop(self);
        dispatch.receipt()
    }
}
impl std::ops::Deref for ClientEndpoint {
    type Target = quinn::Endpoint;
    fn deref(&self) -> &Self::Target {
        &self.endpoint
    }
}
impl Drop for ClientEndpoint {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        if let Some(driver) = self.driver.take() {
            driver.join().unwrap();
        }
    }
}
async fn connected(f: &FixtureConfig, index: usize) -> (ClientEndpoint, quinn::Connection, SessionHello, L2QuicConfig) {
    let cfg = client_config(f, index);
    let tls = client_tls(&cfg.peer, &f.client_certs[index], &f.client_seeds[index]).unwrap();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    if f.small_window {
        let mut t = quinn::TransportConfig::default();
        t.stream_receive_window(1024u32.into());
        t.receive_window(1024u32.into());
        config.transport_config(Arc::new(t));
    }
    let (stop, mut done) = tokio::sync::watch::channel(false);
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let driver = thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            let (runtime, dispatch) = driver_quinn_runtime();
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.set_nonblocking(true).unwrap();
            let mut endpoint = quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime).unwrap();
            endpoint.set_default_client_config(config);
            tx.send((endpoint.clone(), dispatch)).unwrap();
            let _ = done.changed().await;
            endpoint.close(0u32.into(), b"client fixture complete");
        });
    });
    let (endpoint, dispatch) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let endpoint = ClientEndpoint {
        endpoint,
        stop,
        driver: Some(driver),
        dispatch
    };
    let connection = endpoint.connect(cfg.peer.address.parse().unwrap(), "localhost").unwrap().await.unwrap();
    let (public, shard, exporter) = connection_peer(&connection).unwrap();
    assert_eq!(public, key(&f.server_seed));
    assert_eq!(shard, "EU");
    let bytes = exchange(&connection, b"hello").await.unwrap();
    let hello: SessionHello = serde_json::from_slice(&bytes).unwrap();
    hello.verify().unwrap();
    assert_eq!(hello.client_key, key(&f.client_seeds[index]));
    assert_eq!(hello.exporter, exporter);
    assert_eq!(hello.server_key, public);
    (endpoint, connection, hello, cfg)
}
async fn request(f: &FixtureConfig, index: usize, connection: &quinn::Connection, hello: &SessionHello, cfg: &L2QuicConfig, slice: u64, short: bool) -> (quinn::RecvStream, u64) {
    let mut request = L2ChunkRequest {
        namespace_id: "models".into(),
        root_hash: f.stream_root.clone(),
        slice_index: slice,
        pop_biscuit_token: None,
        client_node_id: hex::encode(key(&f.client_seeds[index]))
    };
    let token = issuer_grant(cfg, &f.client_certs[index], &f.client_seeds[index], &GrantRequest {
        session: hello.clone(),
        request: request.clone()
    }, Instant::now()+Duration::from_secs(5)).unwrap();
    let expiry = wall_ms()+if short {
        200
    } else {
        30_000
    };
    let wire = pop_biscuit::make_call_sealed(&token, &SigningKey::from_bytes(&f.client_seeds[index]), &hello.exporter, &request.capability_args().unwrap(), 0, Transport::MtlsExporter, WireClock {
        utc_epoch_ms_expiry: Some(expiry),
        max_ttl_ms: Some(30_000),
        skew_ms: Some(2_000),
        ..Default::default()
    }).unwrap();
    request.pop_biscuit_token = Some(wire.to_cbor().unwrap());
    let mut bytes = Vec::new();
    ciborium::into_writer(&request, &mut bytes).unwrap();
    let (mut send, recv) = connection.open_bi().await.unwrap();
    write_frame(&mut send, &bytes).await.unwrap();
    (recv, expiry)
}
#[derive(Serialize, Deserialize, Debug)] struct Received {
    bytes: Vec<u8>,
    clean_eof: bool,
    reset: bool,
    declared: Option<usize>,
    complete_payload_received_ms: Option<u64>
}
fn exact_target_payload(bytes: &[u8], declared: Option<usize>) {
    assert_eq!(declared, Some(SEGMENT+8));
    assert_eq!(bytes.len(), SEGMENT+12);
    assert_eq!(&bytes[4..12], &1u64.to_be_bytes());
    assert!(bytes[12..].iter().all(|b|*b == 42));
}
async fn receive(mut recv: quinn::RecvStream, pause_exact: bool) -> Received {
    let mut bytes = Vec::new();
    let mut clean_eof = false;
    let mut reset = false;
    let mut declared = None;
    let mut prefix_reported = false;
    let mut complete_payload_received_ms = None;
    loop {
        let mut buffer = [0; 1024];
        match tokio::time::timeout(Duration::from_secs(3), recv.read(&mut buffer)).await {
            Ok(Ok(Some(n))) => {
                bytes.extend_from_slice(&buffer[..n]);
                if declared.is_none() && bytes.len() >= 4 {
                    declared = Some(u32::from_be_bytes(bytes[..4].try_into().unwrap())as usize);
                }
                if pause_exact && complete_payload_received_ms.is_none() && declared.is_some_and(|n|bytes.len() == n+4) {
                    exact_target_payload(&bytes, declared);
                    let received_ms = wall_ms();
                    complete_payload_received_ms = Some(received_ms);
                    private_write(support::fixture_path().join("target-payload-received.json"), &serde_json::to_vec(&serde_json::json!({
                        "complete_payload_received_ms": received_ms,
                        "received_bytes": bytes.len(),
                        "declared_bytes": declared,
                        "frame_blake3": blake3::hash(&bytes).to_hex().to_string(),
                        "slice_index": 1,
                        "barrier_stage": "LeaseAcquired",
                        "barrier_operation": 2
                    })).unwrap());
                    support::hook(Stage::LeaseAcquired, 2);
                }
                if !prefix_reported && declared.is_some_and(|n|n>10_000 && bytes.len()>4 && bytes.len()<n+4) {
                    let case = support::case();
                    if case == "partial_prefix" || case == "pending" {
                        prefix_reported = true;
                        support::hook(Stage::LeaseAcquired, if case == "pending" {
                            3
                        } else {
                            1
                        });
                    }
                }
            },
            Ok(Ok(None)) => {
                clean_eof = true;
                break;
            },
            Ok(Err(_)) => {
                reset = true;
                break;
            },
            Err(_) => panic!("receiver frame timed out")
        }
    }
    Received {
        bytes,
        clean_eof,
        reset,
        declared,
        complete_payload_received_ms
    }
}
fn valid_data(value: &Received, length: usize) {
    assert!(value.clean_eof && !value.reset);
    assert_eq!(value.declared, Some(length+8));
    assert_eq!(value.bytes.len(), length+12);
    assert_eq!(&value.bytes[4..12], &(if length == 32 {
        0u64
    } else {
        1u64
    }).to_be_bytes());
    assert!(value.bytes[12..].iter().all(|b|*b == 42));
}
fn padded(value: &Received) {
    assert!(value.clean_eof && !value.reset);
    assert_eq!(value.bytes.len(), 260);
    assert_eq!(value.declared, Some(256));
    assert!(super::super::constant_time::is_unavailable_frame(&value.bytes[4..]));
}
fn receiver() {
    let f = fixture();
    let case = support::case();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let result = rt.block_on(async {
        let precondition_index = if case == "restart" {
            1
        } else {
            0
        };
        let (endpoint, connection, hello, cfg) = connected(&f, precondition_index).await;
        let (recv, _) = request(&f, precondition_index, &connection, &hello, &cfg, 99, false).await;
        let missing = receive(recv, false).await;
        padded(&missing);
        let (recv, _) = request(&f, precondition_index, &connection, &hello, &cfg, 0, false).await;
        let precondition = receive(recv, false).await;
        valid_data(&precondition, 32);
        support::hook(Stage::ChildReady, 1);
        let mut extra = None;
        let (target_connection, target_hello, target_cfg, other_endpoint) = if case == "timeout" || case == "restart" {
            let index = if case == "timeout" {
                1
            } else {
                0
            };
            let (e, c, h, g) = connected(&f, index).await;
            (c, h, g, Some(e))
        } else {
            (connection.clone(), hello.clone(), cfg.clone(), None)
        };
        let target_index = if case == "timeout" {
            1
        } else {
            0
        };
        let short = case.contains("expiry");
        let (recv, expiry) = request(&f, target_index, &target_connection, &target_hello, &target_cfg, 1, short).await;
        private_write(support::fixture_path().join("target-expiry.json"), &serde_json::to_vec(&serde_json::json!( {
            "expires_ms": expiry
        })).unwrap());
        support::hook(Stage::ChildReady, 2);
        let complete_payload_barrier = ["fin_after_fence", "fin_expiry", "fin_clock"].contains(&case.as_str());
        let target = receive(recv, complete_payload_barrier).await;
        let target_completed_ms = wall_ms();
        if case == "timeout" {
            valid_data(&target, SEGMENT);
            support::hook(Stage::ProbeCompleted, 2);
            let (recv, _) = request(&f, 0, &connection, &hello, &cfg, 1, false).await;
            let denied = receive(recv, false).await;
            padded(&denied);
            extra = Some(denied);
        }
        if ["queued", "no_start", "payload_expiry", "payload_clock", "restart", "reuse"].contains(&case.as_str()) {
            padded(&target);
        } else if case != "timeout" {
            assert!(target.reset && !target.clean_eof, "partial DATA requires reset, got {target:?}");
        }
        if case == "restart" {
            let (recv, _) = request(&f, 1, &connection, &hello, &cfg, 0, false).await;
            valid_data(&receive(recv, false).await, 32);
        }
        connection.close(0u32.into(), b"receiver done");
        target_connection.close(0u32.into(), b"receiver done");
        let mut runtime_dispatch = vec![endpoint.finish()];
        if let Some(other) = other_endpoint {
            runtime_dispatch.push(other.finish());
        }
        serde_json::json!( {
            "role": "actual_authenticated_receiver",
            "precondition": precondition,
            "missing_unavailable": missing,
            "target": target,
            "runtime_dispatch": runtime_dispatch,
            "target_payload_barrier": if complete_payload_barrier {
                Some(serde_json::from_slice::<serde_json::Value>(&std::fs::read(support::fixture_path().join("target-payload-received.json")).unwrap()).unwrap())
            } else {
                None
            },
            "extra": extra,
            "expires_ms": expiry,
            "target_completed_ms": target_completed_ms,
            "notes": support::notes()
        })
    });
    support::emit_child_receipt(&result);
    private_write(support::fixture_path().join("receiver-done"), b"done");
}
fn publisher() {
    let f = fixture();
    let authority = SeedPeerAuthority::from_trusted_peers(f.directory.to_str().unwrap(), key(&f.server_seed), &[key(&f.client_seeds[0])]).unwrap();
    let state = authority.peer(&key(&f.client_seeds[0])).unwrap();
    let started_ms = wall_ms();
    let outcome = state.record(&SigningKey::from_bytes(&f.server_seed), &f.stream_root, 1, &[3; 16], &[7; 32], now_ms);
    let value = match outcome {
        Ok(outcome) => serde_json::json!( {
            "acknowledged": true,
            "outcome": format!("{outcome:?}")
        }),
        Err(failure) => serde_json::json!( {
            "acknowledged": false,
            "failure": format!("{failure:?}")
        })
    };
    assert!(state.is_stopped());
    support::emit_child_receipt(&serde_json::json!( {
        "publication": value,
        "started_ms": started_ms,
        "ended_ms": wall_ms(),
        "notes": support::notes()
    }));
}
fn lease_holder() {
    let f = fixture();
    let path = f.directory.join(format!("{}.qlock1", hex::encode(key(&f.client_seeds[0]))));
    let file = OpenOptions::new().read(true).write(true).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC).open(path).unwrap();
    let exclusive = support::case().starts_with("raw_ex_probe_");
    assert_eq!(unsafe {
        libc::flock(file.as_raw_fd(), if exclusive {
            libc::LOCK_EX|libc::LOCK_NB
        } else {
            libc::LOCK_SH|libc::LOCK_NB
        })
    }, 0);
    let metadata = file.metadata().unwrap();
    if exclusive { support::note(Note::GuardProbe {operation: 1, guard: Guard::FileExclusive, success: true}); }
    support::hook(Stage::LeaseAcquired, 1);
    drop(file);
    support::hook(Stage::LeaseReleased, 1);
    support::emit_child_receipt(&serde_json::json!( {
        "exclusive": exclusive,
        "device": metadata.dev(),
        "inode": metadata.ino(),
        "notes": support::notes()
    }));
}
fn child(name: &str) -> bool {
    let Some(role) = support::child_role(name)else {
        return false;
    };
    match role {
        Role::Sender => sender(),
        Role::Receiver => receiver(),
        Role::Publisher => publisher(),
        Role::LeaseHolder => lease_holder(),
        Role::Opener => panic!("no opener role in transport schedule")
    };
    true
}
fn start(run: &mut Run, case: &str, small: bool, pauses: &[(Stage, u64)], faults: &[(Fault, u64)], receiver_pauses: &[(Stage, u64)]) -> (support::OwnedChild, support::OwnedChild) {
    prepare(run, small);
    let mut selected = vec![(Stage::ChildReady, 0)];
    selected.extend_from_slice(pauses);
    let mut sender = run.spawn(Role::Sender, case, &selected, faults);
    sender.wait_reached(Stage::ChildReady, 0);
    sender.resume();
    let mut receiver_selected = vec![(Stage::ChildReady, 1)];
    receiver_selected.extend_from_slice(receiver_pauses);
    let mut receiver = run.spawn(Role::Receiver, case, &receiver_selected, &[]);
    receiver.wait_reached(Stage::ChildReady, 1);
    (sender, receiver)
}
fn notes(value: &serde_json::Value) -> Vec<Note> {
    serde_json::from_value(value["notes"].clone()).unwrap()
}
fn positive(notes: &[Note], from: u64) -> usize {
    notes.iter().filter_map(|n|match n {
        Note::PayloadPoll {
            operation,
            result: PollResult::Positive(n)
        }
        if *operation >= from => Some(*n),
        _ => None
    }).sum()
}
fn payload_poll_count(notes: &[Note], from: u64) -> usize {
    notes.iter().filter(|note| matches!(note, Note::PayloadPoll {operation, ..} if *operation >= from)).count()
}
fn fin_count(notes: &[Note], from: u64) -> usize {
    notes.iter().filter(|n|matches!(n, Note::FinCall {
        operation,
        ..
    }
    if *operation >= from)).count()
}
fn complete_children(sender: &mut support::OwnedChild, receiver: &mut support::OwnedChild) {
    receiver.wait_success();
    sender.wait_success();
}
fn file_ex_probe(run: &mut Run, case: &str) {
    let id = format!("raw_ex_probe_{case}");
    let f: FixtureConfig = serde_json::from_slice(&std::fs::read(run.fixture.join("fixture.json")).unwrap()).unwrap();
    let expected = std::fs::metadata(f.directory.join(format!("{}.qlock1", hex::encode(key(&f.client_seeds[0]))))).unwrap();
    let mut probe = run.spawn(Role::LeaseHolder, &id, &[], &[]);
    probe.wait_success();
    let receipt = case_receipt(run, "LeaseHolder", &id);
    assert_eq!(receipt["exclusive"], true);
    assert_eq!(receipt["inode"].as_u64().unwrap(), expected.ino());
    assert_eq!(receipt["device"].as_u64().unwrap(), expected.dev());
}
fn case_receipt(run: &Run, role: &str, case: &str) -> serde_json::Value {
    let suffix = format!("-{case}-{role}-receipt.json");
    let values: Vec<_ >= std::fs::read_dir(&run.evidence).unwrap().filter_map(|entry| {
        let path = entry.unwrap().path();
        if path.file_name()?.to_str()?.ends_with(&suffix) {
            Some(serde_json::from_slice::<serde_json::Value>(&std::fs::read(path).unwrap()).unwrap())
        } else {
            None
        }
    }).collect();
    assert_eq!(values.len(), 1, "exact receipt for {role}/{case}");
    values.into_iter().next().unwrap()
}
fn case_fence(run: &Run, case: &str) {
    let value = case_receipt(run, "Publisher", case);
    assert_eq!(value["publication"]["acknowledged"], true);
    assert!(notes(&value).iter().any(|n|matches!(n, Note::Stage {
        stage: Stage::FenceValidated,
        ..
    })));
}
fn clear_fixture(run: &Run, keep_state: bool) {
    for leaf in ["fixture.json", "addresses.json", "receiver-done", "target-expiry.json", "target-payload-received.json", "client0.der", "client0.key", "client1.der", "client1.key"] {
        if keep_state && leaf == "fixture.json" {
            continue;
        }
        let path = run.fixture.join(leaf);
        if path.exists() {
            std::fs::remove_file(path).unwrap();
        }
    }
    if !keep_state {
        std::fs::remove_dir_all(run.fixture.join("state")).unwrap();
    }
}
fn verify_no_target_methods(run: &Run, case: &str) {
    let sender = case_receipt(run, "Sender", case);
    let observed = notes(&sender);
    assert_eq!(payload_poll_count(&observed, 3), 0);
    assert_eq!(fin_count(&observed, 3), 0);
}
#[test]
fn qf_real_quic_payload_queued_before_clean_lease_cannot_complete_after_cross_process_fence() {
    const NAME: &str = "transport::quic::fence_tests::qf_real_quic_payload_queued_before_clean_lease_cannot_complete_after_cross_process_fence";
    if child(NAME) {
        return;
    }
    let mut run = Run::new(NAME);
    run.expect(&["cross_process_fence_before_fresh_payload_lease"]);
    let (mut sender, mut receiver) = start(&mut run, "queued", false, &[(Stage::BeforeCleanLease, 3)], &[], &[]);
    receiver.resume();
    sender.wait_reached(Stage::BeforeCleanLease, 3);
    let mut publisher = run.spawn(Role::Publisher, "queued", &[], &[]);
    publisher.wait_success();
    case_fence(&run, "queued");
    sender.resume();
    complete_children(&mut sender, &mut receiver);
    verify_no_target_methods(&run, "queued");
    run.complete("cross_process_fence_before_fresh_payload_lease");
    run.finish();
}
#[test]
fn qf_real_quic_one_held_clean_lease_is_prefence_and_publisher_waits_for_release() {
    const NAME: &str = "transport::quic::fence_tests::qf_real_quic_one_held_clean_lease_is_prefence_and_publisher_waits_for_release";
    if child(NAME) {
        return;
    }
    let mut run = Run::new(NAME);
    run.expect(&["held_sh_blocks_fence_one_positive_prefence_action"]);
    let (mut sender, mut receiver) = start(&mut run, "held_lease", true, &[(Stage::AfterCleanLeaseBeforeSerial, 3), (Stage::PositivePayloadReturned, 3)], &[], &[]);
    receiver.resume();
    sender.wait_reached(Stage::AfterCleanLeaseBeforeSerial, 3);
    let mut publisher = run.spawn(Role::Publisher, "held_lease", &[(Stage::ExclusiveWouldBlock, 1)], &[]);
    publisher.wait_reached(Stage::ExclusiveWouldBlock, 1);
    sender.resume();
    sender.wait_reached(Stage::PositivePayloadReturned, 3);
    publisher.resume();
    publisher.wait_success();
    case_fence(&run, "held_lease");
    sender.resume();
    complete_children(&mut sender, &mut receiver);
    let observed = notes(&case_receipt(&run, "Sender", "held_lease"));
    let n = positive(&observed, 3);
    assert!(n>0 && n<SEGMENT+12);
    assert_eq!(payload_poll_count(&observed, 4), 0);
    assert_eq!(fin_count(&observed, 3), 0);
    run.complete("held_sh_blocks_fence_one_positive_prefence_action");
    run.finish();
}
#[test]
fn qf_real_quic_payload_prefence_fin_postfence_never_completes_success() {
    const NAME: &str = "transport::quic::fence_tests::qf_real_quic_payload_prefence_fin_postfence_never_completes_success";
    if child(NAME) {
        return;
    }
    let mut run = Run::new(NAME);
    run.expect(&["complete_payload_received_before_separate_fin_fence"]);
    let (mut sender, mut receiver) = start(&mut run, "fin_after_fence", false, &[(Stage::PayloadCompleteBeforeFinLease, 4)], &[], &[(Stage::LeaseAcquired, 2)]);
    receiver.resume();
    sender.wait_reached(Stage::PayloadCompleteBeforeFinLease, 4);
    receiver.wait_reached(Stage::LeaseAcquired, 2);
    let mut publisher = run.spawn(Role::Publisher, "fin_after_fence", &[], &[]);
    publisher.wait_success();
    case_fence(&run, "fin_after_fence");
    sender.resume();
    receiver.resume();
    complete_children(&mut sender, &mut receiver);
    let observed = notes(&case_receipt(&run, "Sender", "fin_after_fence"));
    assert_eq!(positive(&observed, 3), SEGMENT+12);
    assert_eq!(fin_count(&observed, 3), 0);
    let received = case_receipt(&run, "Receiver", "fin_after_fence");
    assert_eq!(received["target"]["bytes"].as_array().unwrap().len(), SEGMENT+12);
    assert_eq!(received["target"]["clean_eof"], false);
    run.complete("complete_payload_received_before_separate_fin_fence");
    run.finish();
}
#[test]
fn qf_real_quic_actual_pending_drops_all_guards_and_next_poll_refuses() {
    const NAME: &str = "transport::quic::fence_tests::qf_real_quic_actual_pending_drops_all_guards_and_next_poll_refuses";
    if child(NAME) {
        return;
    }
    let mut run = Run::new(NAME);
    run.expect(&["actual_pending_guard_drop_cross_process_fence_credit_wakeup"]);
    let (mut sender, mut receiver) = start(&mut run, "pending", true, &[(Stage::PendingGuardsDropped, 4)], &[], &[(Stage::ChildReady, 2), (Stage::LeaseAcquired, 3)]);
    receiver.resume();
    receiver.wait_reached(Stage::ChildReady, 2);
    sender.wait_reached(Stage::PendingGuardsDropped, 4);
    let mut publisher = run.spawn(Role::Publisher, "pending", &[], &[]);
    publisher.wait_success();
    case_fence(&run, "pending");
    receiver.resume();
    receiver.wait_reached(Stage::LeaseAcquired, 3);
    sender.resume();
    receiver.resume();
    complete_children(&mut sender, &mut receiver);
    let observed = notes(&case_receipt(&run, "Sender", "pending"));
    assert!(observed.iter().any(|n|matches!(n, Note::PayloadPoll {
        operation: 4,
        result: PollResult::Pending
    })));
    let pending = observed.iter().position(|n|matches!(n, Note::PayloadPoll {
        operation: 4,
        result: PollResult::Pending
    })).unwrap();
    let reached = observed.iter().position(|n|matches!(n, Note::Stage {
        stage: Stage::PendingGuardsDropped,
        operation: 4
    })).unwrap();
    for guard in [Guard::Serial, Guard::Quarantine, Guard::AuthorizedPeers, Guard::SeedGate, Guard::EnterpriseCurrent] {
        assert!(observed[pending+1..reached].iter().any(|n|matches!(n, Note::GuardProbe {
            guard: g,
            success: true,
            ..
        }
        if *g == guard)));
    }
    assert!(observed.iter().any(|n|matches!(n, Note::Stage {
        stage: Stage::BeforeCleanLease,
        operation
    }
    if *operation>4)));
    assert_eq!(payload_poll_count(&observed, 5), 0);
    assert_eq!(fin_count(&observed, 3), 0);
    run.complete("actual_pending_guard_drop_cross_process_fence_credit_wakeup");
    run.finish();
}
#[test]
fn qf_real_quic_timeout_preserves_marker_stop_and_other_peer_progress() {
    const NAME: &str = "transport::quic::fence_tests::qf_real_quic_timeout_preserves_marker_stop_and_other_peer_progress";
    if child(NAME) {
        return;
    }
    let mut run = Run::new(NAME);
    run.expect(&["typed_500ms_fence_timeout_with_concurrent_honest_peer"]);
    let (mut sender, mut receiver) = start(&mut run, "timeout", false, &[], &[], &[(Stage::ProbeCompleted, 2)]);
    let mut lease = run.spawn(Role::LeaseHolder, "hold_sh", &[(Stage::LeaseAcquired, 1)], &[]);
    lease.wait_reached(Stage::LeaseAcquired, 1);
    let mut publisher = run.spawn(Role::Publisher, "timeout", &[(Stage::ExclusiveWouldBlock, 1)], &[]);
    publisher.wait_reached(Stage::ExclusiveWouldBlock, 1);
    publisher.resume();
    receiver.resume();
    receiver.wait_reached(Stage::ProbeCompleted, 2);
    publisher.wait_success();
    let publication = case_receipt(&run, "Publisher", "timeout");
    assert_eq!(publication["publication"]["acknowledged"], false);
    assert!(publication["publication"]["failure"].as_str().unwrap().contains("FenceTimeout"));
    let observed = notes(&publication);
    assert!(observed.iter().filter(|n|matches!(n, Note::Stage {
        stage: Stage::ExclusiveWouldBlock,
        ..
    })).count()>1);
    assert!(observed.iter().any(|n|matches!(n, Note::RetrySleepNanos(n)if *n>0)));
    lease.resume();
    lease.wait_success();
    receiver.resume();
    complete_children(&mut sender, &mut receiver);
    let received = case_receipt(&run, "Receiver", "timeout");
    let honest_done = received["target_completed_ms"].as_u64().unwrap();
    assert!(honest_done >= publication["started_ms"].as_u64().unwrap() && honest_done<publication["ended_ms"].as_u64().unwrap());
    let f: FixtureConfig = serde_json::from_slice(&std::fs::read(run.fixture.join("fixture.json")).unwrap()).unwrap();
    let marker = f.directory.join(format!("{}.json", hex::encode(key(&f.client_seeds[0]))));
    assert!(marker.is_file());
    run.record("timeout_marker", &serde_json::json!( {
        "inode": std::fs::metadata(&marker).unwrap().ino(),
        "blake3": blake3::hash(&std::fs::read(marker).unwrap()).to_hex().to_string(),
        "acknowledged": false
    }));
    run.complete("typed_500ms_fence_timeout_with_concurrent_honest_peer");
    run.finish();
}
#[test]
fn qf_real_quic_live_connection_reuse_and_process_restart_remain_quarantined() {
    const NAME: &str = "transport::quic::fence_tests::qf_real_quic_live_connection_reuse_and_process_restart_remain_quarantined";
    if child(NAME) {
        return;
    }
    let mut run = Run::new(NAME);
    run.expect(&["live_connection_reuse_refuses", "fresh_sender_publisher_marker_attach_refuses_honest_peer_works"]);
    let (mut sender, mut receiver) = start(&mut run, "reuse", false, &[], &[], &[]);
    let mut publisher = run.spawn(Role::Publisher, "reuse", &[], &[]);
    publisher.wait_success();
    case_fence(&run, "reuse");
    receiver.resume();
    complete_children(&mut sender, &mut receiver);
    verify_no_target_methods(&run, "reuse");
    let f: FixtureConfig = serde_json::from_slice(&std::fs::read(run.fixture.join("fixture.json")).unwrap()).unwrap();
    let marker = f.directory.join(format!("{}.json", hex::encode(key(&f.client_seeds[0]))));
    let before_inode = std::fs::metadata(&marker).unwrap().ino();
    let before_hash = blake3::hash(&std::fs::read(&marker).unwrap());
    run.complete("live_connection_reuse_refuses");
    clear_fixture(&run, true);
    let mut sender = run.spawn(Role::Sender, "restart", &[(Stage::ChildReady, 0)], &[]);
    sender.wait_reached(Stage::ChildReady, 0);
    sender.resume();
    let mut receiver = run.spawn(Role::Receiver, "restart", &[(Stage::ChildReady, 1)], &[]);
    receiver.wait_reached(Stage::ChildReady, 1);
    let mut publisher = run.spawn(Role::Publisher, "restart", &[], &[]);
    publisher.wait_success();
    case_fence(&run, "restart");
    assert!(case_receipt(&run, "Publisher", "restart")["publication"]["outcome"].as_str().unwrap().contains("ExistingOriginal"));
    receiver.resume();
    complete_children(&mut sender, &mut receiver);
    assert_eq!(std::fs::metadata(&marker).unwrap().ino(), before_inode);
    assert_eq!(blake3::hash(&std::fs::read(&marker).unwrap()), before_hash);
    run.record("persistent_original_marker", &serde_json::json!( {
        "inode": before_inode,
        "blake3": before_hash.to_hex().to_string()
    }));
    run.complete("fresh_sender_publisher_marker_attach_refuses_honest_peer_works");
    run.finish();
}
fn expiry(run: &Run) -> u64 {
    let path = run.fixture.join("target-expiry.json");
    let until = Instant::now()+Duration::from_secs(1);
    while !path.exists() {
        assert!(Instant::now()<until);
        thread::sleep(Duration::from_millis(1));
    }
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    value["expires_ms"].as_u64().unwrap()
}
fn assert_final_error(run: &Run, case: &str, operation: u64, reason: &str, clock_failure: bool, expiry: u64) {
    let value = case_receipt(run, "Sender", case);
    let observed = notes(&value);
    let stages = |stage|observed.iter().position(|n|matches!(n, Note::Stage {
        stage: s,
        operation: o
    }
    if *s == stage && *o == operation)).unwrap();
    assert!(stages(Stage::AfterCleanLeaseBeforeSerial)<stages(Stage::AllFinalGuardsHeld));
    assert!(stages(Stage::AllFinalGuardsHeld)<stages(Stage::FinalClockAttempt));
    assert!(stages(Stage::FinalClockAttempt)<stages(Stage::FinalClockResult));
    assert!(stages(Stage::FinalClockResult)<stages(Stage::FinalRefusalGuardsDropped));
    let result = value["releases"].as_array().unwrap().last().unwrap();
    assert_eq!(result["outcome"], reason);
    if !clock_failure {
        assert!(result["at_ms"].as_u64().unwrap() < expiry + 300, "expiry refusal must precede the unchanged 500 ms response deadline");
    }
    assert_eq!(result["errno"], if clock_failure {
        "EIO"
    } else {
        "EACCES"
    });
    assert!(observed.iter().any(|n|matches!(n, Note::Clock {
        operation: o,
        final_read: false,
        result: ClockResult::Value(v),
        ..
    }
    if *o == operation && *v <= expiry)));
    assert!(observed.iter().any(|n|match n {
        Note::Clock {
            operation: o,
            final_read: true,
            result: ClockResult::FixedError,
            ..
        } => *o == operation && clock_failure,
        Note::Clock {
            operation: o,
            final_read: true,
            result: ClockResult::Value(v),
            ..
        } => *o == operation && !clock_failure && *v>expiry,
        _ => false
    }));
    assert_eq!(fin_count(&observed, 3), 0);
    if operation == 3 {
        assert_eq!(payload_poll_count(&observed, 3), 0);
    } else {
        assert_eq!(positive(&observed, 3), SEGMENT+12);
        let receiver = case_receipt(run, "Receiver", case);
        let received: Received = serde_json::from_value(receiver["target"].clone()).unwrap();
        exact_target_payload(&received.bytes, received.declared);
        assert!(received.reset && !received.clean_eof);
        let received_ms = received.complete_payload_received_ms.unwrap();
        assert!(received_ms<expiry, "actual complete payload must precede signed expiry");
        assert_eq!(receiver["target_payload_barrier"]["complete_payload_received_ms"], received_ms);
        assert_eq!(receiver["target_payload_barrier"]["received_bytes"], SEGMENT+12);
        assert_eq!(receiver["target_payload_barrier"]["declared_bytes"], SEGMENT+8);
        assert_eq!(receiver["target_payload_barrier"]["frame_blake3"], blake3::hash(&received.bytes).to_hex().to_string());
    }
    let refusal = stages(Stage::FinalRefusalGuardsDropped);
    for guard in [Guard::Serial, Guard::Quarantine, Guard::AuthorizedPeers, Guard::SeedGate, Guard::EnterpriseCurrent] {
        assert!(observed[refusal+1..].iter().any(|n|matches!(n, Note::GuardProbe {
            guard: g,
            success: true,
            ..
        }
        if *g == guard)));
    }
}
#[test]
fn qf_real_quic_partial_frame_refusal_resets_and_no_start_refusal_stays_padded() {
    const NAME: &str = "transport::quic::fence_tests::qf_real_quic_partial_frame_refusal_resets_and_no_start_refusal_stays_padded";
    if child(NAME) {
        return;
    }
    let mut run = Run::new(NAME);
    run.expect(&["marker_before_first_data_stays_padded", "marker_after_proper_prefix_resets_without_fin", "payload_expiry_after_clean_lease_uses_fresh_final_clock", "fin_expiry_after_clean_lease_uses_own_fresh_final_clock", "payload_final_clock_failure_releases_every_guard", "fin_final_clock_failure_releases_every_guard"]);
    for(case, id, operation, is_marker, is_fault)in[("no_start", "marker_before_first_data_stays_padded", 3, true, false), ("partial_prefix", "marker_after_proper_prefix_resets_without_fin", 3, true, false), ("payload_expiry", "payload_expiry_after_clean_lease_uses_fresh_final_clock", 3, false, false), ("fin_expiry", "fin_expiry_after_clean_lease_uses_own_fresh_final_clock", 4, false, false), ("payload_clock", "payload_final_clock_failure_releases_every_guard", 3, false, true), ("fin_clock", "fin_final_clock_failure_releases_every_guard", 4, false, true)] {
        let stage = if case == "no_start" {
            Stage::BeforeCleanLease
        } else if case == "partial_prefix" {
            Stage::PositivePayloadReturned
        } else {
            Stage::AfterCleanLeaseBeforeSerial
        };
        let mut pauses = vec![(stage, operation)];
        if !is_marker {
            pauses.push((Stage::ProbeCompleted, 1));
        }
        let faults = if is_fault {
            vec![(Fault::FinalClock, operation)]
        } else {
            vec![]
        };
        let receiver_pauses = if case == "partial_prefix" {
            vec![(Stage::LeaseAcquired, 1)]
        } else if operation == 4 {
            vec![(Stage::LeaseAcquired, 2)]
        } else {
            vec![]
        };
        let (mut sender, mut receiver) = start(&mut run, case, case == "partial_prefix", &pauses, &faults, &receiver_pauses);
        receiver.resume();
        sender.wait_reached(stage, operation);
        let expires = expiry(&run);
        if is_marker {
            if case == "partial_prefix" {
                receiver.wait_reached(Stage::LeaseAcquired, 1);
            }
            let mut publisher = run.spawn(Role::Publisher, case, &[], &[]);
            publisher.wait_success();
            case_fence(&run, case);
            sender.resume();
            if case == "partial_prefix" {
                receiver.resume();
            }
        } else {
            if operation == 4 {
                receiver.wait_reached(Stage::LeaseAcquired, 2);
                let barrier: serde_json::Value = serde_json::from_slice(&std::fs::read(run.fixture.join("target-payload-received.json")).unwrap()).unwrap();
                let observed_ms = wall_ms();
                assert!(barrier["complete_payload_received_ms"].as_u64().unwrap()<expires);
                assert!(observed_ms<expires, "complete actual payload and held clean FIN lease must be observed while call remains valid");
                assert_eq!(barrier["received_bytes"], SEGMENT+12);
                assert_eq!(barrier["declared_bytes"], SEGMENT+8);
                assert_eq!(barrier["slice_index"], 1);
                assert_eq!(barrier["barrier_stage"], "LeaseAcquired");
                assert_eq!(barrier["barrier_operation"], 2);
                run.record(&format!("{case}_complete_payload_before_final_clock"), &serde_json::json!({
                    "receiver_barrier": barrier,
                    "coordinator_observed_ms": observed_ms,
                    "expires_ms": expires,
                    "sender_held_stage": "AfterCleanLeaseBeforeSerial",
                    "sender_held_operation": operation
                }));
            }
            if !is_fault {
                assert!(wall_ms()<expires, "must reach completed clean lease while call remains valid");
                while wall_ms() <= expires {
                    thread::sleep(Duration::from_millis(1));
                }
            }
            sender.resume();
            sender.wait_reached(Stage::ProbeCompleted, 1);
            file_ex_probe(&mut run, case);
            sender.resume();
            if operation == 4 {
                receiver.resume();
            }
        }
        complete_children(&mut sender, &mut receiver);
        if case == "no_start" {
            verify_no_target_methods(&run, case);
        } else if case == "partial_prefix" {
            let s = notes(&case_receipt(&run, "Sender", case));
            assert!(positive(&s, 3)>0 && positive(&s, 3)<SEGMENT+12);
            assert_eq!(payload_poll_count(&s, 4), 0);
            assert_eq!(fin_count(&s, 3), 0);
            let r = case_receipt(&run, "Receiver", case);
            let n = r["target"]["bytes"].as_array().unwrap().len();
            assert!(n>4 && n<SEGMENT+12);
            assert_eq!(r["target"]["clean_eof"], false);
        } else {
            assert_final_error(&run, case, operation, if is_fault {
                "L2_CLOCK"
            } else {
                "L2_RELEASE_REVOKED"
            }, is_fault, expires);
        }
        run.complete(id);
        clear_fixture(&run, false);
    }
    run.finish();
}
#[test]
fn qf_real_quic_production_authority_and_real_corruption_publication_share_stop() {
    const NAME: &str = "transport::quic::fence_tests::qf_real_quic_production_authority_and_real_corruption_publication_share_stop";
    super::super::quic_poison::service_binding_tests::run_production_corruption_binding(NAME);
}
