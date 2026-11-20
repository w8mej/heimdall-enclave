//! Real-service exclusive state-directory ownership regressions.
use enclave_core::{EnclaveResult, daemon::DaemonId, ipc::{self, PeerCredentials}, profile::Profile, seq::BootEpoch};
use enclave_zk_auditor::{service::{Peers, ZkConfig, ZkRequest, ZkResponse, ZkService}, witness::WitnessFold};
use std::{collections::BTreeMap, fs, path::{Path, PathBuf}, process::{Child, Command, Stdio}, sync::Arc,
    time::{Duration, Instant}};
use std::os::unix::{ffi::OsStrExt, fs::{DirBuilderExt, MetadataExt}, process::ExitStatusExt};

const BUSY: &str = "AUDITOR_STATE_BUSY";
const CHILD_ENV: &str = "depot_OWNED_STATE_CHILD_FIXTURE";
const CHILD_TEST: &str = "state_owner_controlled_child_holder";
const CHILD_RELATIVE: &str = "depot_OWNED_STATE_CHILD_RELATIVE";
const WAIT: Duration = Duration::from_secs(5);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let base = std::env::temp_dir().canonicalize().unwrap();
        let path = base.join(format!("so{}-{:x}", std::process::id(), enclave_core::rng::u64()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
struct NoPeers;
impl Peers for NoPeers {
    fn cosign(&self, _: DaemonId, _: u64, _: &str) -> EnclaveResult<(Vec<u8>, Vec<u8>)> { panic!("no cosign") }
    fn prepare_relay(&self, _: &[u8]) -> EnclaveResult<ipc::PreparedCall> { panic!("no relay") }
    fn fetch_witness(&self, _: &str, _: u64, _: u64) -> EnclaveResult<(Vec<WitnessFold>, u64)> { panic!("no fetch") }
    fn boot_epoch(&self) -> EnclaveResult<BootEpoch> { panic!("no epoch") }
}
fn start(path: &Path) -> EnclaveResult<Arc<ZkService>> {
    ZkService::start(ZkConfig::new(Profile::L2, path.to_owned()), Box::new(NoPeers))
}
fn alive(service: &ZkService) -> bool {
    matches!(service.handle(&PeerCredentials::local(ipc::geteuid(), unsafe { libc::getegid() }),
        ZkRequest::Status), Ok(ZkResponse::Status(_)))
}
fn refused(result: &EnclaveResult<Arc<ZkService>>) -> bool {
    result.as_ref().is_err_and(|error| error.is(BUSY))
}

// Include object identity/metadata and a bounded digest of synthetic regular
// files. Never print state bytes or keys. Root directory atime is irrelevant.
type Snapshot = BTreeMap<Vec<u8>, (u64, u64, u32, u32, u32, u64, u64, [u8; 32])>;
fn snapshot(path: &Path) -> Snapshot {
    let mut out = BTreeMap::new();
    for entry in fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        let metadata = fs::symlink_metadata(entry.path()).unwrap();
        assert!(metadata.is_file(), "owned state fixture unexpectedly contains nonregular object");
        assert!(metadata.len() <= 1_048_576, "owned fixture state bound");
        let body = fs::read(entry.path()).unwrap();
        out.insert(entry.file_name().as_bytes().to_vec(), (metadata.dev(), metadata.ino(), metadata.mode(),
            metadata.uid(), metadata.gid(), metadata.nlink(), metadata.len(), *blake3::hash(&body).as_bytes()));
        assert!(out.len() <= 32, "owned fixture namespace bound");
    }
    out
}

#[test]
fn state_owner_second_actual_service_same_path_refuses_before_any_state_mutation() {
    let directory = Directory::new();
    let path = directory.0.join("state");
    let first = start(&path).unwrap();
    let before = snapshot(&path);
    let second = start(&path);
    let second_started = second.is_ok();
    let was_refused = refused(&second);
    let after = snapshot(&path);
    let first_alive = alive(&first);
    // Dispose of an accidentally admitted old service before contract asserts.
    drop(second); drop(first);
    println!("OWNED_STATE_SECOND_START second_started={second_started} state_unchanged={} first_alive={first_alive}", before == after);
    assert_eq!((was_refused, before == after, first_alive), (true, true, true),
        "same-directory second service must refuse before quarantine/epoch/audit initialization");
}

#[test]
fn state_owner_remains_until_last_service_arc_drops_then_reopen_succeeds() {
    let directory = Directory::new(); let path = directory.0.join("state");
    let service = start(&path).unwrap();
    let survivor = service.clone(); drop(service);
    let before = snapshot(&path);
    let attempted = start(&path);
    let held = refused(&attempted);
    let unchanged = snapshot(&path) == before;
    let survivor_alive = alive(&survivor);
    drop(attempted); drop(survivor);
    let reopened = start(&path);
    let released = reopened.as_ref().is_ok_and(|service| alive(service));
    drop(reopened);
    assert_eq!((held, unchanged, survivor_alive, released), (true, true, true, true));
}

#[test]
fn state_owner_independent_private_directories_allow_actual_services_together() {
    let directory = Directory::new();
    let first = start(&directory.0.join("a")).unwrap();
    let second = start(&directory.0.join("b"));
    let both_alive = alive(&first) && second.as_ref().is_ok_and(|service| alive(service));
    drop(second); drop(first);
    assert!(both_alive, "per-directory ownership must not impose a process-global singleton");
}

fn emit_child_log(root: &Path, name: &str) {
    use std::io::Read;
    let mut bytes = Vec::new();
    fs::File::open(root.join(name)).unwrap().take(16_385).read_to_end(&mut bytes).unwrap();
    assert!(bytes.len() <= 16_384, "owned child diagnostic bound");
    // One JSON-escaped line embeds the bounded exact diagnostic bytes in the
    // outer retained raw stdout without adding false libtest summary lines.
    // Child harness emits only fixture source/diagnostics, no state contents.
    let diagnostic = std::str::from_utf8(&bytes).unwrap();
    println!("OWNED_STATE_CHILD_LOG name={name} bytes={} text={}", bytes.len(), serde_json::to_string(diagnostic).unwrap());
}

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
}

#[test]
fn state_owner_controlled_child_holder() {
    let Some(root) = std::env::var_os(CHILD_ENV) else { return; };
    let root = PathBuf::from(root);
    assert!(root.is_absolute());
    let path=if std::env::var_os(CHILD_RELATIVE).is_some() {PathBuf::from("state")} else {root.join("state")};
    let service = start(&path).unwrap();
    assert!(alive(&service));
    // Ready is outside the state namespace and is published only after the
    // public start API returned a live held service. Parent owns this tree.
    use std::io::{Read, Write};
    let mut ready = fs::OpenOptions::new().create_new(true).write(true).open(root.join("ready")).unwrap();
    ready.write_all(b"owned holder ready\n").unwrap(); drop(ready);
    // Parent retains piped stdin while testing and deliberately SIGKILLs us;
    // reaching EOF before that is a fixture failure, not normal lease release.
    let mut byte = [0];
    std::io::stdin().read_exact(&mut byte).expect("holder must remain alive until parent kill");
    drop(service);
    panic!("unexpected graceful child command");
}

#[test]
fn state_owner_other_process_refuses_then_kernel_releases_after_controlled_crash() {
    controlled_child_ownership(false);
}

#[test]
fn state_owner_relative_config_in_owned_child_resolves_to_same_directory() {
    controlled_child_ownership(true);
}

fn controlled_child_ownership(relative:bool) {
    let directory = Directory::new(); let path = directory.0.join("state");
    let stdout = fs::OpenOptions::new().create_new(true).write(true).open(directory.0.join("child.stdout")).unwrap();
    let stderr = fs::OpenOptions::new().create_new(true).write(true).open(directory.0.join("child.stderr")).unwrap();
    let mut command=Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", CHILD_TEST, "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, &directory.0).current_dir(&directory.0)
        .stdin(Stdio::piped()).stdout(stdout).stderr(stderr);
    if relative {command.env(CHILD_RELATIVE,"1");} else {command.env_remove(CHILD_RELATIVE);}
    let mut child = OwnedChild(command.spawn().unwrap());
    let deadline = Instant::now() + WAIT;
    while !directory.0.join("ready").is_file() {
        if let Some(status) = child.0.try_wait().unwrap() {
            emit_child_log(&directory.0, "child.stdout");
            emit_child_log(&directory.0, "child.stderr");
            panic!("owned holder exited before ready: {status}");
        }
        if Instant::now() >= deadline {
            child.0.kill().unwrap(); child.0.wait().unwrap();
            emit_child_log(&directory.0, "child.stdout");
            emit_child_log(&directory.0, "child.stderr");
            panic!("owned holder ready deadline");
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let before = snapshot(&path);
    let attempted = start(&path);
    let held = refused(&attempted);
    let unchanged = snapshot(&path) == before;
    drop(attempted);
    child.0.kill().unwrap();
    let status = child.0.wait().unwrap();
    let signalled = status.signal() == Some(libc::SIGKILL);
    emit_child_log(&directory.0, "child.stdout");
    emit_child_log(&directory.0, "child.stderr");
    println!("OWNED_STATE_CHILD_EXIT signal={:?} held={held} state_unchanged={unchanged}", status.signal());
    let reopened = start(&path);
    let released = reopened.as_ref().is_ok_and(|service| alive(service));
    drop(reopened);
    // Kill/reap completes before all terminal ownership assertions.
    assert_eq!((held, unchanged, signalled, released), (true, true, true, true));
}

#[test]
fn state_owner_busy_refusal_precedes_alternate_audit_path_and_preserves_debt() {
    let directory=Directory::new();let path=directory.0.join("state");
    let service=start(&path).unwrap();
    fs::write(path.join("proof-release.pending"),b"owned synthetic debt\n").unwrap();
    let before=snapshot(&path);let audit_parent=directory.0.join("unused-audit");
    let audit=audit_parent.join("audit.jsonl");
    let mut config=ZkConfig::new(Profile::L2,path.clone());config.audit_path=Some(audit.clone());
    let attempted=ZkService::start(config,Box::new(NoPeers));
    let held=refused(&attempted);let unchanged=before==snapshot(&path);
    drop(attempted);drop(service);
    assert!(held && unchanged && !audit_parent.exists(),"busy startup must precede debt/audit initialization");
}

struct DropPeers { path:PathBuf, observed:Arc<std::sync::Mutex<Option<bool>>> }
impl Peers for DropPeers {
    fn cosign(&self,d:DaemonId,s:u64,e:&str)->EnclaveResult<(Vec<u8>,Vec<u8>)>{NoPeers.cosign(d,s,e)}
    fn prepare_relay(&self,f:&[u8])->EnclaveResult<ipc::PreparedCall>{NoPeers.prepare_relay(f)}
    fn fetch_witness(&self,e:&str,a:u64,b:u64)->EnclaveResult<(Vec<WitnessFold>,u64)>{NoPeers.fetch_witness(e,a,b)}
    fn boot_epoch(&self)->EnclaveResult<BootEpoch>{NoPeers.boot_epoch()}
}
impl Drop for DropPeers {
    fn drop(&mut self) {
        let attempt=enclave_core::sealed::StateDirectoryLease::acquire(&self.path);
        if let Ok(mut observed)=self.observed.lock() {
            *observed=Some(attempt.as_ref().is_err_and(|e|e.is("STATE_DIRECTORY_BUSY")));
        }
    }
}

#[test]
fn state_owner_lease_outlives_peer_destructor_during_final_service_teardown() {
    let directory=Directory::new();let path=directory.0.join("state");
    let observed=Arc::new(std::sync::Mutex::new(None));
    let service=ZkService::start(ZkConfig::new(Profile::L2,path.clone()),
        Box::new(DropPeers{path:path.clone(),observed:observed.clone()})).unwrap();
    drop(service);
    assert_eq!(*observed.lock().unwrap(),Some(true));
    let reopened=start(&path).unwrap();assert!(alive(&reopened));
}

#[test]
fn state_owner_startup_failure_destroys_peers_before_releasing_lease_then_reopens() {
    let directory=Directory::new();let path=directory.0.join("state");
    let audit=directory.0.join("invalid-audit");fs::create_dir(&audit).unwrap();
    let observed=Arc::new(std::sync::Mutex::new(None));
    let mut config=ZkConfig::new(Profile::L2,path.clone());config.audit_path=Some(audit);
    let failed=ZkService::start(config,Box::new(DropPeers{path:path.clone(),observed:observed.clone()}));
    assert!(failed.as_ref().is_err_and(|e|e.is("AUDIT_NOT_REGULAR")));
    assert_eq!(*observed.lock().unwrap(),Some(true));
    let reopened=start(&path).unwrap();assert!(alive(&reopened));
}

#[test]
fn state_owner_simultaneous_actual_starts_admit_exactly_one_service() {
    let directory=Directory::new();let path=directory.0.join("state");
    fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
    let barrier=Arc::new(std::sync::Barrier::new(3));
    let workers:Vec<_>=(0..2).map(|_| {
        let path=path.clone();let barrier=barrier.clone();
        std::thread::spawn(move || {barrier.wait();start(&path)})
    }).collect();
    barrier.wait();
    let results:Vec<_>=workers.into_iter().map(|worker|worker.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r|r.is_ok()).count(),1);
    assert_eq!(results.iter().filter(|r|refused(r)).count(),1);
    assert!(results.iter().filter_map(|r|r.as_ref().ok()).all(|s|alive(s)));
}
