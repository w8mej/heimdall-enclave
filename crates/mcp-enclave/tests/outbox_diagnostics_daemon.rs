//! PROPOSAL ONLY: copy to depot-enclave/tests/outbox_diagnostics_daemon.rs.
//! Existing generic client and request strings compile on the predecessor.
//! An old IPC_DECODE is a missing-endpoint capability failure, never evidence
//! that the old fixed-path health scanner actually reported healthy.
//! Real owned daemon/IPC/metadata; no installed signing or physical-I/O claim.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use enclave_core::{daemon::DaemonId, ipc::{self, Client}, profile::Profile};
use depot_enclave::ctl::Env;
use serde_json::{json, Value};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        // Canonical trusted temp ancestry and a short Darwin Unix socket path.
        let base = std::env::temp_dir().canonicalize().unwrap();
        let path = base.join(format!("mc-obd-{:016x}", enclave_core::rng::u64()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }

struct OwnedChild(Option<Child>);
impl OwnedChild {
    fn stop(mut self) {
        let child = self.0.as_mut().unwrap();
        // This is explicitly an owned forced-stop fixture, not graceful
        // persistence or power-loss testing. Wait before any terminal oracle.
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        self.0.take();
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) { if let Some(mut child) = self.0.take() { let _ = child.kill(); let _ = child.wait(); } }
}

struct Fixture { child: OwnedChild, env: Env, directory: Directory, queue: PathBuf, pid: u32 }
impl Fixture {
    fn new() -> Self {
        let directory = Directory::new();
        let env = Env::dev(&directory.0, Profile::L1);
        let store = directory.0.join("store");
        let queue = store.join("ohttp-outbox");
        let child = Command::new(env!("CARGO_BIN_EXE_depot-enclave"))
            .args(["__daemon", "702", "--dev-same-uid", "--simulated-hardware", "--profile", "L1", "--socket-dir"])
            .arg(&env.socket_dir).arg("--store-dir").arg(&store)
            .arg("--audit-dir").arg(&env.audit_dir)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let pid = child.id();
        let mut fixture = Self { child: OwnedChild(Some(child)), env, directory, queue, pid };
        let socket = fixture.env.socket_dir.join(DaemonId::SwarmSync.socket_name());
        let until = Instant::now() + Duration::from_secs(15);
        while !socket.exists() {
            assert!(fixture.child.0.as_mut().unwrap().try_wait().unwrap().is_none(), "owned daemon exited before readiness");
            assert!(Instant::now() < until, "owned daemon readiness timeout");
            thread::sleep(Duration::from_millis(5));
        }
        // Existing read-only diagnostics verifies the actual binary/socket/
        // service without requiring signed host-config admission for Status.
        // Kernel identity is independently checked by call() on every socket.
        let diagnostics = fixture.call("SyncDiagnostics").unwrap();
        assert_eq!(diagnostics["SyncDiagnostics"]["process_pid"].as_u64(), Some(u64::from(pid)));
        assert!(fixture.queue.is_dir());
        fixture
    }
    fn call(&self, request: &str) -> enclave_core::EnclaveResult<Value> {
        let client = Client::connect_verified_deadline(
            &self.env.socket_dir.join(DaemonId::SwarmSync.socket_name()),
            ipc::geteuid(), None, Duration::from_secs(3))?;
        assert_eq!(client.server.uid, ipc::geteuid());
        assert_eq!(client.server.pid.and_then(|pid| u32::try_from(pid).ok()), Some(self.pid));
        // A JSON string has the same CBOR wire as the serde unit variant,
        // without naming a newly added enum variant on the predecessor.
        client.prepare_call(&Value::String(request.into()))?.handoff()?.receive()
    }
    fn observe(&self) -> Value {
        match self.call("OutboxDiagnostics") {
            Ok(reply) => json!({"class":"response", "reply":reply}),
            Err(error) if error.is("IPC_DECODE") => json!({"class":"missing_endpoint", "reason":"IPC_DECODE"}),
            Err(error) => json!({"class":"other_error", "reason":error.reason}),
        }
    }
    fn put(&self, name: &str, length: u64) -> PathBuf {
        let path = self.queue.join(name);
        OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).unwrap().set_len(length).unwrap();
        path
    }
    fn stop(self) { let Self { child, env: _, directory, queue: _, pid: _ } = self; child.stop(); drop(directory); }
}

// Observe filesystem metadata without opening any payload contents. Logical
// length changes are fixture writes; this is no allocated-block footprint test.
fn inventory(path: &Path) -> BTreeMap<String, (u64, u64, u64, u32, u64)> {
    let mut result = BTreeMap::new();
    for entry in fs::read_dir(path).unwrap() {
        let entry = entry.unwrap(); let metadata = fs::symlink_metadata(entry.path()).unwrap();
        result.insert(entry.file_name().to_str().unwrap().to_owned(),
            (metadata.dev(), metadata.ino(), metadata.len(), metadata.mode(), metadata.nlink()));
    }
    result
}
fn journal(path: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(root: &Path, values: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(root).unwrap() {
            let entry = entry.unwrap(); let kind = entry.file_type().unwrap();
            if kind.is_dir() { walk(&entry.path(), values); }
            else { assert!(kind.is_file()); values.insert(entry.path(), fs::read(entry.path()).unwrap()); }
        }
    }
    let mut result = BTreeMap::new(); walk(path, &mut result); result
}
fn expected_current(observation: &Value, pending: u32, dead: u32, bytes: u64, pid: u32) -> bool {
    let snapshot = &observation["reply"]["OutboxDiagnostics"];
    observation["class"] == "response" && snapshot["schema"] == 1
        && snapshot["producer"] == "uid702-configured-outbox-v1"
        && snapshot["process_pid"].as_u64() == Some(u64::from(pid))
        && snapshot["process_uid"].as_u64() == Some(u64::from(ipc::geteuid()))
        && snapshot["dev_same_uid"] == true
        && snapshot["process_epoch_id"].as_str().is_some_and(|epoch| enclave_core::seq::validate_epoch_id(epoch).is_ok())
        && snapshot["observation"] == json!({"availability":"current", "counts":{
            "pending_frames":pending, "dead_frames":dead, "retained_bytes":bytes}})
}
fn expected_fault(observation: &Value, fault: &str) -> bool {
    observation["class"] == "response" && observation["reply"]["OutboxDiagnostics"]["observation"]
        == json!({"availability":"unavailable", "fault":fault})
}

#[test]
fn outbox_diagnostics_actual_daemon_reports_empty_pending_dead_and_preserves_queue_journal_counters() {
    let fixture = Fixture::new();
    let empty = fixture.observe();
    fixture.put("00000000000000000001.ohttp", 7);
    fixture.put("00000000000000000002.dead", 11);
    fixture.put("00000000000000000003.ohttp", 0);
    let before_files = inventory(&fixture.queue);
    let before_journal = journal(&fixture.env.audit_dir);
    let before_sync = fixture.call("SyncDiagnostics").unwrap();
    let first = fixture.observe(); let repeated = fixture.observe();
    let readonly = before_files == inventory(&fixture.queue)
        && before_journal == journal(&fixture.env.audit_dir)
        && before_sync == fixture.call("SyncDiagnostics").unwrap();
    let accepted = expected_current(&empty, 0, 0, 0, fixture.pid)
        && expected_current(&first, 2, 1, 18, fixture.pid) && first == repeated;
    fixture.stop();
    println!("OUTBOX_DIAGNOSTICS_DAEMON={}", json!({"empty":empty,"populated":first,"readonly":readonly,"joined":true}));
    assert!(accepted && readonly, "actual configured-outbox endpoint must return exact metadata without queue/journal/counter mutation");
}

#[test]
fn outbox_diagnostics_actual_daemon_missing_directory_stays_unknown_and_is_not_recreated() {
    let fixture = Fixture::new(); fs::remove_dir(&fixture.queue).unwrap();
    let before = journal(&fixture.env.audit_dir); let observation = fixture.observe();
    let untouched = !fixture.queue.exists() && before == journal(&fixture.env.audit_dir);
    let accepted = expected_fault(&observation, "unavailable");
    fixture.stop();
    println!("OUTBOX_DIAGNOSTICS_MISSING={}", json!({"observation":observation,"untouched":untouched,"joined":true}));
    assert!(accepted && untouched, "missing configured queue must export unavailable without counts or recreation");
}

#[test]
fn outbox_diagnostics_actual_daemon_stage_and_cooperative_lock_are_unknown_without_cleanup() {
    let fixture = Fixture::new(); let stage = fixture.put(".enqueue.pending", 9);
    let before = inventory(&fixture.queue); let staged = fixture.observe();
    let stage_preserved = inventory(&fixture.queue) == before; fs::remove_file(stage).unwrap();
    let directory = File::open(&fixture.queue).unwrap();
    assert_eq!(unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0);
    let busy = fixture.observe(); drop(directory);
    let recovered = fixture.observe();
    let accepted = expected_fault(&staged, "publication_recovery_required") && stage_preserved
        && expected_fault(&busy, "namespace_busy") && expected_current(&recovered, 0, 0, 0, fixture.pid);
    fixture.stop();
    println!("OUTBOX_DIAGNOSTICS_BUSY={}", json!({"staged":staged,"busy":busy,"recovered":recovered,"stage_preserved":stage_preserved,"joined":true}));
    assert!(accepted, "uncertain publication and cooperating lock must not become empty/healthy or trigger repair");
}

#[test]
fn outbox_diagnostics_actual_daemon_rejects_unsafe_names_symlinks_and_writable_entries() {
    let fixture = Fixture::new(); let mut rows = Vec::new(); let mut accepted = true;
    for variant in 0..3 {
        let path = match variant {
            0 => fixture.put("not-a-canonical-entry", 3),
            1 => { let path = fixture.queue.join("00000000000000000001.ohttp");
                std::os::unix::fs::symlink(fixture.directory.0.join("absent-private-canary"), &path).unwrap(); path },
            _ => { let path = fixture.put("00000000000000000001.ohttp", 3);
                fs::set_permissions(&path, fs::Permissions::from_mode(0o620)).unwrap(); path },
        };
        let before = inventory(&fixture.queue); let observation = fixture.observe();
        let untouched = before == inventory(&fixture.queue);
        accepted &= expected_fault(&observation, "invalid_namespace") && untouched;
        rows.push(json!({"variant":variant,"observation":observation,"untouched":untouched}));
        fs::remove_file(path).unwrap();
    }
    fixture.stop();
    println!("OUTBOX_DIAGNOSTICS_UNSAFE={}", json!({"rows":rows,"joined":true}));
    assert!(accepted, "unsafe owned fixtures must yield unavailable without changing custody");
}

#[test]
fn outbox_diagnostics_actual_daemon_reports_exact_and_excess_logical_quota_without_reading_payloads() {
    let fixture = Fixture::new(); let cap = 100 * 1024 * 1024_u64;
    let pending = fixture.put("00000000000000000001.ohttp", cap - 1);
    fixture.put("00000000000000000002.dead", 1);
    let at_cap = fixture.observe();
    OpenOptions::new().write(true).open(&pending).unwrap().set_len(cap).unwrap();
    let before = inventory(&fixture.queue); let over_cap = fixture.observe();
    let untouched = before == inventory(&fixture.queue);
    let accepted = expected_current(&at_cap, 1, 1, cap, fixture.pid)
        && expected_current(&over_cap, 1, 1, cap + 1, fixture.pid) && untouched;
    fixture.stop();
    println!("OUTBOX_DIAGNOSTICS_QUOTA={}", json!({"exact":at_cap,"excess":over_cap,"untouched":untouched,"joined":true}));
    assert!(accepted, "service reports real sparse logical lengths, including retained dead bytes, without mutating queue");
}
