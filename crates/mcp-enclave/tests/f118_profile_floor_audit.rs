//! Independent bounded entry-path regressions. All processes, sockets, keys,
//! and files are private fixtures. The mock CAS checks entry behavior only;
//! the separate real-CAS test exercises locally signed TUF management routes.
mod common;
use enclave_core::{
    daemon::DaemonId,
    error::EnclaveResult,
    host_config::{EnclaveHostConfig, HOST_CONFIG_TARGET, MAX_HOST_CONFIG_BYTES},
    ipc::{Client, PeerCredentials},
    profile::Profile,
};
use enclave_model_runnerd::{arena::ZeroizeTrigger, service::{RunnerRequest, RunnerResponse}};
use enclave_swarm_syncd::service::{CasRequest, CasResponse};
use depot_enclave::devtuf::DevRepo;
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{atomic::{AtomicBool, AtomicUsize, Ordering}, Arc, Mutex},
    time::{Duration, Instant},
};

struct PrivateDir(PathBuf);
impl PrivateDir {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let path = PathBuf::from("/tmp").join(format!("f118-audit-{:x}", enclave_core::rng::u64()));
        std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for PrivateDir {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

fn config(floor: Profile) -> Vec<u8> {
    EnclaveHostConfig {
        profile_floor: floor,
        ifc_grant_public_key: "42".repeat(32),
        ohttp_key_config: None,
        calibration_corpus_digest: "01".repeat(32),
        vk_digest: "02".repeat(32),
        depot_lock_digest: "03".repeat(32),
        fido_mds_allowlist_digest: "04".repeat(32),
        codesign_pins: None,
    }.to_json_bytes().unwrap()
}

struct Process(Child);
impl Process {
    fn start(base: &Path, mesh: &Path, daemon: DaemonId, extra: &[String]) -> Self {
        let log = std::fs::File::create(base.join(format!("{}.log", daemon.uid()))).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_depot-enclave"))
            .args(["__daemon", &daemon.uid().to_string(), "--dev-same-uid", "--no-audit", "--profile", "L2", "--socket-dir"])
            .arg(mesh).args(extra).stdin(Stdio::null()).stdout(Stdio::null()).stderr(log)
            .spawn().unwrap();
        let mut process = Self(child);
        let deadline = Instant::now() + Duration::from_secs(10);
        while !mesh.join(daemon.socket_name()).exists() {
            assert!(process.0.try_wait().unwrap().is_none(), "daemon exited: {}",
                std::fs::read_to_string(base.join(format!("{}.log", daemon.uid()))).unwrap());
            assert!(Instant::now() < deadline, "daemon did not publish private socket");
            std::thread::sleep(Duration::from_millis(10));
        }
        process
    }
}
impl Drop for Process {
    fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
}

struct FixtureCas {
    bytes: Arc<Mutex<Vec<u8>>>,
    calls: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl FixtureCas {
    fn start(mesh: &Path) -> Self {
        let bytes = Arc::new(Mutex::new(config(Profile::L2)));
        let calls = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let listener = enclave_core::ipc::bind(&mesh.join(DaemonId::SwarmSync.socket_name()),
            enclave_core::ipc::SocketAccess::OwnerOnly).unwrap();
        let (payload, count, flag) = (bytes.clone(), calls.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            enclave_core::ipc::serve::<CasRequest, CasResponse, _>(listener,
                enclave_core::ipc::PeerPolicy::allow([enclave_core::ipc::geteuid()]),
                Arc::new(move |_: &PeerCredentials, req| {
                    match req {
                        CasRequest::FetchHostConfig => {},
                        CasRequest::FetchTarget { target } if target == HOST_CONFIG_TARGET => {},
                        _ => return Err(enclave_core::err!(EACCES, "FIXTURE_UNEXPECTED_REQUEST")),
                    }
                    count.fetch_add(1, Ordering::SeqCst);
                    Ok(CasResponse::Bytes(payload.lock().unwrap().clone().into()))
                }), flag).unwrap();
        });
        Self { bytes, calls, stop, thread: Some(thread) }
    }
    fn set(&self, bytes: Vec<u8>) { *self.bytes.lock().unwrap() = bytes; }
}
impl Drop for FixtureCas {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() { thread.join().unwrap(); }
    }
}

fn runner_call(mesh: &Path, request: RunnerRequest) -> EnclaveResult<RunnerResponse> {
    let mut client = Client::connect(&mesh.join(DaemonId::ModelRunner.socket_name()), enclave_core::ipc::geteuid())?;
    client.set_timeout(Some(Duration::from_secs(3)))?;
    client.call(&request)
}

#[test]
fn f118_audit_live_entry_refuses_invalid_and_unavailable_config_then_recovers() {
    let dir = PrivateDir::new();
    let mesh = dir.0.join("mesh");
    let cas = FixtureCas::start(&mesh);
    let _runner = Process::start(&dir.0, &mesh, DaemonId::ModelRunner, &[]);
    assert!(matches!(runner_call(&mesh, RunnerRequest::Status).unwrap(), RunnerResponse::Status(_)));

    for (bytes, reason) in [
        (b"{".to_vec(), "HOST_CONFIG_DECODE"),
        (vec![b' '; MAX_HOST_CONFIG_BYTES + 1], "HOST_CONFIG_TOO_LARGE"),
        (config(Profile::L3), "HOST_PROFILE_BELOW_FLOOR"),
    ] {
        cas.set(bytes);
        let before = cas.calls.load(Ordering::SeqCst);
        let error = runner_call(&mesh, RunnerRequest::Status).unwrap_err();
        assert!(error.is(reason), "expected {reason}: {error}");
        assert!(cas.calls.load(Ordering::SeqCst) > before, "entry reused cached admission");
        let calls = cas.calls.load(Ordering::SeqCst);
        assert!(matches!(runner_call(&mesh, RunnerRequest::Zeroize(ZeroizeTrigger::TaskExit)).unwrap(), RunnerResponse::Wiped(_)));
        assert_eq!(cas.calls.load(Ordering::SeqCst), calls, "cleanup contacted unavailable configuration authority");
        cas.set(config(Profile::L2));
        assert!(matches!(runner_call(&mesh, RunnerRequest::Status).unwrap(), RunnerResponse::Status(_)));
    }

    // Rename only this private fixture socket: new admission connections fail
    // immediately while the same running runner still accepts safety cleanup.
    let path = mesh.join(DaemonId::SwarmSync.socket_name());
    let parked = path.with_extension("offline");
    std::fs::rename(&path, &parked).unwrap();
    assert!(runner_call(&mesh, RunnerRequest::Status).unwrap_err().is("IPC_CONNECT"));
    assert!(matches!(runner_call(&mesh, RunnerRequest::Zeroize(ZeroizeTrigger::TaskExit)).unwrap(), RunnerResponse::Wiped(_)));
    std::fs::rename(&parked, &path).unwrap();
    assert!(matches!(runner_call(&mesh, RunnerRequest::Status).unwrap(), RunnerResponse::Status(_)));
}

fn cas_call(mesh: &Path, request: CasRequest) -> EnclaveResult<CasResponse> {
    let mut client = Client::connect(&mesh.join(DaemonId::SwarmSync.socket_name()), enclave_core::ipc::geteuid())?;
    client.set_timeout(Some(Duration::from_secs(3)))?;
    client.call(&request)
}

#[test]
fn f118_audit_restricted_cas_reserves_only_exact_host_configuration_routes() {
    let dir = PrivateDir::new();
    let mesh = dir.0.join("mesh");
    let mut repo = DevRepo::open(&dir.0.join("authority")).unwrap();
    let signed_config = config(Profile::L3);
    repo.add_target(HOST_CONFIG_TARGET, &signed_config, serde_json::json!({})).unwrap();
    repo.add_target("other.json", b"{}", serde_json::json!({})).unwrap();
    let repo_dir = repo.repo_dir();
    let _cas = Process::start(&dir.0, &mesh, DaemonId::SwarmSync, &[
        "--store-dir".into(), dir.0.join("store").display().to_string(),
        "--state-dir".into(), dir.0.join("state").display().to_string(),
        "--tuf-root".into(), repo_dir.join("root.json").display().to_string(),
    ]);
    cas_call(&mesh, CasRequest::TufRefresh {
        roots: vec![],
        timestamp: std::fs::read(repo_dir.join("timestamp.json")).unwrap().into(),
        snapshot: std::fs::read(repo_dir.join("snapshot.json")).unwrap().into(),
        targets: std::fs::read(repo_dir.join("targets.json")).unwrap().into(),
    }).unwrap();
    // Simulate an older provisioned loose copy. A verified canonical admission
    // must replace its authority rather than remain shadowed by stale bytes.
    std::fs::write(dir.0.join("store").join(HOST_CONFIG_TARGET), config(Profile::L2)).unwrap();
    cas_call(&mesh, CasRequest::Admit { target: HOST_CONFIG_TARGET.into(), bytes: signed_config.clone().into() }).unwrap();
    assert!(cas_call(&mesh, CasRequest::Status).unwrap_err().is("HOST_PROFILE_BELOW_FLOOR"));
    for request in [CasRequest::FetchHostConfig, CasRequest::FetchTarget { target: HOST_CONFIG_TARGET.into() }] {
        assert!(matches!(cas_call(&mesh, request).unwrap(), CasResponse::Bytes(bytes) if bytes.as_ref() == signed_config));
    }
    let mut requests = vec![
        CasRequest::Admit { target: "other.json".into(), bytes: b"{}".to_vec().into() },
        CasRequest::FetchTarget { target: "other.json".into() },
        CasRequest::OpenTarget { target: HOST_CONFIG_TARGET.into() },
        CasRequest::AdmitBegin { target: HOST_CONFIG_TARGET.into() },
    ];
    for alias in [format!("./{HOST_CONFIG_TARGET}"), format!("{HOST_CONFIG_TARGET}/../other.json"),
        HOST_CONFIG_TARGET.to_uppercase(), format!("{HOST_CONFIG_TARGET}\0")] {
        requests.push(CasRequest::FetchTarget { target: alias.clone() });
        requests.push(CasRequest::Admit { target: alias, bytes: signed_config.clone().into() });
    }
    for request in requests {
        let error = cas_call(&mesh, request.clone()).unwrap_err();
        assert!(error.is("HOST_PROFILE_BELOW_FLOOR"), "reserved-target bypass {request:?}: {error}");
    }
    assert!(matches!(cas_call(&mesh, CasRequest::Wipe).unwrap(), CasResponse::Wiped));

    // Reserved configuration routes remain subject to TUF revocation even
    // though the profile gate intentionally exempts them for recovery.
    repo.add_target(HOST_CONFIG_TARGET, &signed_config, serde_json::json!({"revoked": true})).unwrap();
    cas_call(&mesh, CasRequest::TufRefresh {
        roots: vec![],
        timestamp: std::fs::read(repo_dir.join("timestamp.json")).unwrap().into(),
        snapshot: std::fs::read(repo_dir.join("snapshot.json")).unwrap().into(),
        targets: std::fs::read(repo_dir.join("targets.json")).unwrap().into(),
    }).unwrap();
    for request in [CasRequest::FetchHostConfig, CasRequest::FetchTarget { target: HOST_CONFIG_TARGET.into() }, CasRequest::Status] {
        let error = cas_call(&mesh, request).unwrap_err();
        assert!(error.is("HOST_CONFIG_REVOKED"), "revoked host config accepted: {error}");
    }
    assert!(matches!(cas_call(&mesh, CasRequest::Wipe).unwrap(), CasResponse::Wiped));
}

#[test]
fn f118_audit_dev_start_preserves_live_restricted_socket_and_stop_checks_kernel_pid() {
    use std::os::unix::fs::MetadataExt;
    let dir = PrivateDir::new();
    let env = depot_enclave::ctl::Env::dev(&dir.0, Profile::L2);
    depot_enclave::ctl::prepare_dev_state_at(&env, &common::host_inputs(&dir.0)).unwrap();
    // Deliberately omit --tuf-repo: this real CAS entry is alive and restricted
    // pending metadata/configuration management, rather than a healthy daemon.
    let cas = Process::start(&dir.0, &env.socket_dir, DaemonId::SwarmSync, &[
        "--store-dir".into(), dir.0.join("empty-store").display().to_string(),
        "--state-dir".into(), dir.0.join("private-cas-state").display().to_string(),
        "--tuf-root".into(), dir.0.join("tuf/repo/root.json").display().to_string(),
    ]);
    let path = env.socket_dir.join(DaemonId::SwarmSync.socket_name());
    let old_socket = std::fs::metadata(&path).unwrap();
    let before = env.connect(DaemonId::SwarmSync).unwrap().server.pid;
    assert_eq!(before, Some(i32::try_from(cas.0.id()).unwrap()));
    let restricted = depot_enclave::ctl::status_of(&env, DaemonId::SwarmSync).unwrap_err();
    let start_error = depot_enclave::ctl::start(&env).unwrap_err();
    assert_eq!(start_error.reason, restricted.reason, "start must return the existing admission refusal");
    assert!(!env.audit_dir.join("cas/cas.log").exists(), "start prepared a duplicate daemon launch");
    let after = std::fs::metadata(&path).unwrap();
    assert_eq!((old_socket.dev(), old_socket.ino()), (after.dev(), after.ino()), "live socket was rebound");
    assert_eq!(env.connect(DaemonId::SwarmSync).unwrap().server.pid, before);

    // A forged session record must not turn the healthy-Status exemption into
    // permission to signal another process. Both children belong to this test.
    let mut unrelated = Process(Command::new("/bin/sleep").arg("60")
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    let session = |pid| depot_enclave::ctl::DevSession {
        pids: [(DaemonId::SwarmSync.uid(), pid)].into_iter().collect(),
        profile: Some(Profile::L2),
        intent_helper_pid: None,
    };
    let session_path = dir.0.join("dev-session.json");
    std::fs::write(&session_path, serde_json::to_vec(&session(unrelated.0.id())).unwrap()).unwrap();
    assert_eq!(depot_enclave::ctl::stop(&env).unwrap(), 0);
    assert!(unrelated.0.try_wait().unwrap().is_none(), "forged session signalled unrelated child");
    assert_eq!(env.connect(DaemonId::SwarmSync).unwrap().server.pid, before);
    std::fs::write(&session_path, serde_json::to_vec(&session(cas.0.id())).unwrap()).unwrap();
    assert_eq!(depot_enclave::ctl::stop(&env).unwrap(), 1);
    assert!(env.connect(DaemonId::SwarmSync).is_err(), "restricted genuine child was not stopped");
}
