//! Required TUF restart authority: exercise actual CAS startup and its daemon
//! entrypoint without mutable shared wall clocks or installed authority claims.

use std::{collections::BTreeMap, path::{Path, PathBuf}};
use enclave_core::{ipc::PeerCredentials, profile::Profile, sealed::SealedStore};
use enclave_crypto::tuf::RepoBuilder;
use enclave_swarm_syncd::service::{CasConfig, CasRequest, CasResponse, CasService};

const EXP: &str = "2030-01-01T00:00:00Z";
const NOW: i64 = 1_793_884_860;
fn wall() -> i64 { NOW }

struct Fixture { directory: PathBuf, repository: RepoBuilder, root: Vec<u8> }
impl Fixture {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let directory = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "depot-tuf-required-{}-{}", std::process::id(), enclave_core::rng::u64()));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let repository = RepoBuilder::new(3, 2);
        let root = repository.root(EXP).unwrap();
        Self { directory, repository, root }
    }
    fn state(&self) -> PathBuf { self.directory.join("state") }
    fn config(&self) -> CasConfig {
        CasConfig {
            dev_same_uid: true, profile: Profile::L1,
            store_dir: self.directory.join("store"), audit_path: None,
            tuf_root: Some(self.root.clone()), ohttp_gateway: None,
            state_dir: Some(self.state()),
            revocation: enclave_swarm_syncd::revocation::Enforcement::InProcess,
        }
    }
    fn start(&self) -> enclave_core::EnclaveResult<std::sync::Arc<CasService>> {
        CasService::start_with_wall_clock(self.config(), wall)
    }
    fn refresh(&self, service: &CasService, version: u64) -> enclave_core::EnclaveResult<CasResponse> {
        let targets = self.repository.targets(version, EXP, BTreeMap::new()).unwrap();
        let snapshot = self.repository.snapshot(version, EXP, version, &targets).unwrap();
        let timestamp = self.repository.timestamp(version, EXP, version, &snapshot).unwrap();
        service.handle(&PeerCredentials::local(0, 0), CasRequest::TufRefresh {
            roots: vec![], timestamp: timestamp.into(), snapshot: snapshot.into(), targets: targets.into(),
        })
    }
    fn assert_seed_only(&self, seed: &[u8]) {
        assert_eq!(std::fs::read(self.state().join("sealing.key")).unwrap(), seed);
        assert!(!self.state().join("tuf.sealed").exists());
        assert!(!self.state().join("tuf.gen").exists());
    }
}
impl Drop for Fixture {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.directory); }
}

#[test]
fn phase6_required_tuf_state_preserves_restart_floor_and_refuses_each_partial_loss() {
    for missing in ["state", "checkpoint", "both"] {
        let fixture = Fixture::new();
        let service = fixture.start().unwrap();
        fixture.refresh(&service, 7).unwrap();
        drop(service);
        let service = fixture.start().unwrap();
        assert!(fixture.refresh(&service, 5).unwrap_err().is("TUF_ROLLBACK"));
        match service.handle(&PeerCredentials::local(0, 0), CasRequest::Status).unwrap() {
            CasResponse::Status(status) => assert!(status.state.contains("tuf=Some((7, 7, 7))"), "{}", status.state),
            response => panic!("unexpected status: {response:?}"),
        }
        drop(service);
        let seed = std::fs::read(fixture.state().join("sealing.key")).unwrap();
        let state = std::fs::read(fixture.state().join("tuf.sealed")).unwrap();
        let checkpoint = std::fs::read(fixture.state().join("tuf.gen")).unwrap();
        if missing != "checkpoint" { std::fs::remove_file(fixture.state().join("tuf.sealed")).unwrap(); }
        if missing != "state" { std::fs::remove_file(fixture.state().join("tuf.gen")).unwrap(); }
        let error = fixture.start().unwrap_err();
        assert!(error.is("TUF_STATE"), "{missing}: {error}");
        assert_eq!(std::fs::read(fixture.state().join("sealing.key")).unwrap(), seed);
        for (name, retained, bytes) in [
            ("tuf.sealed", missing == "checkpoint", state),
            ("tuf.gen", missing == "state", checkpoint),
        ] {
            if retained { assert_eq!(std::fs::read(fixture.state().join(name)).unwrap(), bytes); }
            else { assert!(!fixture.state().join(name).exists(), "{missing}: recreated {name}"); }
        }
    }
}

#[test]
fn phase6_required_tuf_state_seed_only_interruption_never_bootstraps_install_root() {
    let fixture = Fixture::new();
    let (store, loaded) = SealedStore::open_required(&fixture.state(), "tuf").unwrap();
    assert!(matches!(loaded, enclave_core::sealed::Loaded::Fresh));
    drop(store);
    let seed = std::fs::read(fixture.state().join("sealing.key")).unwrap();
    for _ in 0..2 {
        assert!(fixture.start().unwrap_err().is("TUF_STATE"));
        fixture.assert_seed_only(&seed);
        assert!(!fixture.directory.join("store").exists(), "startup progressed past required trust");
    }
}

#[test]
fn phase6_required_tuf_state_actual_daemon_entry_refuses_before_listener_bind() {
    const CHILD_DIRECTORY: &str = "depot_TEST_TUF_REQUIRED_ENTRY_DIRECTORY";
    if let Some(directory) = std::env::var_os(CHILD_DIRECTORY) {
        // This branch runs only in the bounded test subprocess: the real
        // daemon entry may harden its process, so never invoke it in the parent.
        let directory = PathBuf::from(directory);
        // The subprocess working directory is the already-created private
        // fixture. Positively preserve supported relative development state
        // paths without changing the parent test process's working directory.
        let healthy = Fixture::new();
        let mut relative_config = healthy.config();
        relative_config.state_dir = Some(PathBuf::from("relative-state"));
        let service = CasService::start_with_wall_clock(relative_config.clone(), wall).unwrap();
        healthy.refresh(&service, 7).unwrap();
        drop(service);
        let service = CasService::start_with_wall_clock(relative_config, wall).unwrap();
        assert!(healthy.refresh(&service, 5).unwrap_err().is("TUF_ROLLBACK"));
        drop(service);
        assert!(directory.join("relative-state/tuf.sealed").is_file());
        assert!(directory.join("relative-state/tuf.gen").is_file());
        let args = enclave_core::runtime::DaemonArgs::parse([
            "enclave-swarm-syncd".to_owned(), "--dev-same-uid".into(),
            "--no-audit".into(), "--profile".into(), "L1".into(),
            "--socket-dir".into(), directory.join("run").display().to_string(),
            "--state-dir".into(), directory.join("state").display().to_string(),
            "--store-dir".into(), directory.join("store").display().to_string(),
            "--tuf-root".into(), directory.join("root.json").display().to_string(),
        ]).unwrap();
        let error = enclave_swarm_syncd::entry::run(args).unwrap_err();
        assert!(error.is("TUF_STATE"), "{error}");
        assert!(!directory.join("run/cas/cas.sock").exists());
        println!("EXPECTED_REQUIRED_TUF_STATE_ENTRY_REJECTION");
        return;
    }
    let fixture = Fixture::new();
    let service = fixture.start().unwrap();
    fixture.refresh(&service, 7).unwrap();
    drop(service);
    let seed = std::fs::read(fixture.state().join("sealing.key")).unwrap();
    std::fs::remove_file(fixture.state().join("tuf.sealed")).unwrap();
    std::fs::remove_file(fixture.state().join("tuf.gen")).unwrap();
    std::fs::write(fixture.directory.join("root.json"), &fixture.root).unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "phase6_required_tuf_state_actual_daemon_entry_refuses_before_listener_bind", "--nocapture"])
        .env(CHILD_DIRECTORY, &fixture.directory)
        .current_dir(&fixture.directory)
        .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if child.try_wait().unwrap().is_some() { break; }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!("daemon entry did not refuse within ten seconds: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stdout).contains("EXPECTED_REQUIRED_TUF_STATE_ENTRY_REJECTION"));
    fixture.assert_seed_only(&seed);
    assert!(!Path::new(&fixture.directory).join("run/cas/cas.sock").exists());
}
