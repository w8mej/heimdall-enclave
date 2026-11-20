//! Real process lifecycle of the release ledger, using reference model inputs.
//! The signed epoch is a software fixture, not a production SEP enrollment.
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use enclave_core::error::EnclaveResult;
use enclave_core::ipc::PeerCredentials;
use enclave_core::profile::Profile;
use enclave_core::seq::GovernedSlot;
use enclave_model_runnerd::classes::speculative::{FixedThermal, PowerSource, ThermalState};
use enclave_model_runnerd::manifest::ExecutionClass;
use enclave_model_runnerd::service::{ResolvedWeights, RunnerConfig, RunnerRequest, RunnerResponse, RunnerService, WeightSource};
use enclave_model_runnerd::zoo::package;

struct NoCas;
impl WeightSource for NoCas {
    fn resolve(&self, _: &str) -> EnclaveResult<ResolvedWeights> {
        Err(enclave_core::err!(EACCES, "NO_FIXTURE_CAS"))
    }
}

struct PrivateDir(PathBuf);
impl PrivateDir {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(format!("f109-{}", enclave_core::rng::u64()));
        std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for PrivateDir {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

fn service(dir: &Path) -> EnclaveResult<Arc<RunnerService>> {
    let model = package(ExecutionClass::DiscriminativeRlcd).unwrap();
    RunnerService::start(RunnerConfig {
        dev_same_uid: true,
        profile: Profile::L2,
        audit_path: None,
        calib_corpus_blake3: Some(blake3::hash(model.corpus.as_ref().unwrap()).to_hex().to_string()),
        thermal: Box::new(|| Box::new(FixedThermal(ThermalState::Nominal, PowerSource::Ac))),
        actuator: None,
        state_dir: Some(dir.to_owned()),
    }, Box::new(NoCas))
}

#[test]
fn f109_production_entry_requires_persistent_state_before_startup() {
    let dir = PrivateDir::new();
    let out = Command::new(env!("CARGO_BIN_EXE_enclave-model-runnerd"))
        .args(["--no-audit", "--socket-dir"]).arg(dir.0.join("sockets"))
        .output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("RUNNER_STATE_DIR_REQUIRED"),
        "production entry must reject a volatile budget before other startup effects: {}", String::from_utf8_lossy(&out.stderr));
    assert!(!dir.0.join("sockets").exists());
}

fn child(dir: &Path, mode: &str) -> Command {
    let mut c = Command::new(std::env::current_exe().unwrap());
    c.args(["--exact", "f109_real_process_restart_lock_and_tamper", "--nocapture"])
        .env("depot_F109_PROCESS_FIXTURE", dir)
        .env("depot_F109_PROCESS_MODE", mode);
    c
}

fn assert_child(dir: &Path, mode: &str) {
    let out = child(dir, mode).output().unwrap();
    assert!(out.status.success(), "child {mode}: {}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
}

#[test]
fn f109_real_process_restart_lock_and_tamper() {
    if let Some(dir) = std::env::var_os("depot_F109_PROCESS_FIXTURE") {
        let dir = PathBuf::from(dir);
        let mode = std::env::var("depot_F109_PROCESS_MODE").unwrap();
        if mode == "locked" {
            assert!(service(&dir).unwrap_err().is("RUNNER_QIF_BUSY"));
            return;
        }
        if mode == "tampered" {
            assert!(service(&dir).unwrap_err().is("STATE_TAMPERED"));
            return;
        }
        let svc = service(&dir).unwrap();
        if mode == "hold" {
            std::fs::write(dir.join("ready"), b"ready").unwrap();
            use std::io::Read;
            let mut byte = [0u8];
            std::io::stdin().read_exact(&mut byte).unwrap();
            return;
        }
        let model = package(ExecutionClass::DiscriminativeRlcd).unwrap();
        svc.bind_bytes(&model.manifest_bytes(), &model.weights, model.corpus.as_deref()).unwrap();
        let slot: GovernedSlot = serde_json::from_slice(&std::fs::read(dir.join("fixture-slot.json")).unwrap()).unwrap();
        let result = svc.handle(&PeerCredentials::local(704, 704), RunnerRequest::Declassify {
            payload: format!("same record with varying suffix {}", enclave_core::rng::u64()).into_bytes().into(),
            cardinality: 4, schema: "test".into(), slot: Some(slot),
        });
        if mode == "deny" {
            assert!(result.unwrap_err().is("QIF_BUDGET_EXCEEDED"));
        } else {
            assert!(matches!(result.unwrap(), RunnerResponse::Declassified(n) if n < 4));
        }
        return;
    }
    let dir = PrivateDir::new();
    let slot = GovernedSlot {
        epoch: enclave_crypto::epoch::EpochSigner::random().sign("0b1f1d2e-5a64-4c8e-9d7a-1c4f5b6a7e82"),
        rpc_seq_u64: 1,
    };
    std::fs::write(dir.0.join("fixture-slot.json"), serde_json::to_vec(&slot).unwrap()).unwrap();
    // Each output was durably settled by a different real OS process.
    for _ in 0..6 { assert_child(&dir.0, "release"); }
    assert_child(&dir.0, "deny");

    let mut holder = child(&dir.0, "hold").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !dir.0.join("ready").exists() {
        assert!(holder.try_wait().unwrap().is_none(), "holder exited early");
        assert!(std::time::Instant::now() < deadline, "holder readiness timeout");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let locked = child(&dir.0, "locked").output().unwrap();
    // Abrupt death must release the kernel lock without discarding the ledger.
    holder.kill().unwrap();
    holder.wait().unwrap();
    assert!(locked.status.success(), "concurrent writer was accepted: {}", String::from_utf8_lossy(&locked.stderr));
    assert_child(&dir.0, "deny");
    std::fs::write(dir.0.join("runner-qif-ledger.sealed"), b"corrupt").unwrap();
    assert_child(&dir.0, "tampered");
}

#[test]
fn f109_unsafe_state_and_lock_paths_refuse_without_repairing_permissions() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = PrivateDir::new();
    std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(service(&dir.0).unwrap_err().is("RUNNER_STATE_UNSAFE"));
    assert_eq!(std::fs::metadata(&dir.0).unwrap().permissions().mode() & 0o777, 0o777);
    std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    let target = dir.0.join("foreign");
    std::fs::write(&target, b"untouched").unwrap();
    let lock = dir.0.join("runner-qif-ledger.lock");
    symlink(&target, &lock).unwrap();
    assert!(service(&dir.0).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
    std::fs::remove_file(&lock).unwrap();
    std::fs::write(&lock, b"").unwrap();
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(service(&dir.0).unwrap_err().is("RUNNER_STATE_UNSAFE"));
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::hard_link(&lock, dir.0.join("lock-alias")).unwrap();
    assert!(service(&dir.0).unwrap_err().is("RUNNER_STATE_UNSAFE"));
}

#[test]
fn f109_existing_snapshot_aliases_refuse_before_reading_or_overwriting_targets() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    for name in ["sealing.key", "runner-qif-ledger.sealed", "runner-qif-ledger.gen",
        "epoch-signer.sealed", "epoch-signer.gen"] {
        for hardlink in [false, true] {
            let dir = PrivateDir::new();
            let target = dir.0.join("foreign-target");
            std::fs::write(&target, b"private fixture must remain unchanged").unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
            let leaf = dir.0.join(name);
            if hardlink { std::fs::hard_link(&target, &leaf).unwrap(); }
            else { symlink(&target, &leaf).unwrap(); }
            assert!(service(&dir.0).unwrap_err().is("RUNNER_STATE_UNSAFE"), "{name} hardlink={hardlink}");
            assert_eq!(std::fs::read(&target).unwrap(), b"private fixture must remain unchanged");
            assert!(!dir.0.join("runner-qif-ledger.sealed").exists() || name == "runner-qif-ledger.sealed");
        }
    }
}

fn release_request(slot: &GovernedSlot) -> RunnerRequest {
    RunnerRequest::Declassify {
        payload: format!("record suffix {}", enclave_core::rng::u64()).into_bytes().into(),
        cardinality: 4, schema: "fixture".into(), slot: Some(slot.clone()),
    }
}

fn fixture_slot() -> GovernedSlot {
    GovernedSlot {
        epoch: enclave_crypto::epoch::EpochSigner::random().sign("0b1f1d2e-5a64-4c8e-9d7a-1c4f5b6a7e82"),
        rpc_seq_u64: 1,
    }
}

#[test]
fn f109_classify_caller_labels_and_rebind_cannot_bypass_shared_release_pool() {
    use enclave_core::label::Conf;
    use enclave_model_runnerd::classes::rlcd::RlcdMode;
    let dir = PrivateDir::new();
    let model = package(ExecutionClass::DiscriminativeRlcd).unwrap();
    let svc = service(&dir.0).unwrap();
    let peer = PeerCredentials::local(704, 704);
    for n in 0..6 {
        svc.bind_bytes(&model.manifest_bytes(), &model.weights, model.corpus.as_deref()).unwrap();
        let result = svc.handle(&peer, RunnerRequest::Classify {
            payload: format!("record {n} random {}", enclave_core::rng::u64()).into_bytes().into(),
            mode: RlcdMode::Choice, cardinality: 4,
            entities: vec![format!("ek_{n:032x}")], conf: Conf::C1,
        }).unwrap();
        assert!(matches!(result, RunnerResponse::Rlcd { millibits: 2000, .. }));
    }
    let slot = fixture_slot();
    svc.bind_bytes(&model.manifest_bytes(), &model.weights, model.corpus.as_deref()).unwrap();
    assert!(svc.handle(&peer, release_request(&slot)).unwrap_err().is("QIF_BUDGET_EXCEEDED"));
    drop(svc);
    let svc = service(&dir.0).unwrap();
    svc.bind_bytes(&model.manifest_bytes(), &model.weights, model.corpus.as_deref()).unwrap();
    assert!(svc.handle(&peer, release_request(&slot)).unwrap_err().is("QIF_BUDGET_EXCEEDED"));
}

#[test]
fn f109_failed_checkpoint_save_releases_no_output_and_latches_across_rebind() {
    let dir = PrivateDir::new();
    let model = package(ExecutionClass::DiscriminativeRlcd).unwrap();
    let svc = service(&dir.0).unwrap();
    svc.bind_bytes(&model.manifest_bytes(), &model.weights, model.corpus.as_deref()).unwrap();
    let checkpoint = dir.0.join("runner-qif-ledger.gen");
    let saved_checkpoint = dir.0.join("saved-checkpoint");
    std::fs::rename(&checkpoint, &saved_checkpoint).unwrap();
    std::fs::create_dir(&checkpoint).unwrap();
    let slot = fixture_slot();
    let peer = PeerCredentials::local(704, 704);
    assert!(svc.handle(&peer, release_request(&slot)).unwrap_err().is("STATE_RENAME"));
    svc.bind_bytes(&model.manifest_bytes(), &model.weights, model.corpus.as_deref()).unwrap();
    assert!(svc.handle(&peer, release_request(&slot)).unwrap_err().is("RUNNER_QIF_PERSISTENCE_FAULT"));
    drop(svc);
    std::fs::remove_dir(&checkpoint).unwrap();
    std::fs::rename(&saved_checkpoint, &checkpoint).unwrap();
    // The failed release is conservatively charged in the already saved state.
    let svc = service(&dir.0).unwrap();
    svc.bind_bytes(&model.manifest_bytes(), &model.weights, model.corpus.as_deref()).unwrap();
    for _ in 0..5 { assert!(matches!(svc.handle(&peer, release_request(&slot)).unwrap(), RunnerResponse::Declassified(_))); }
    assert!(svc.handle(&peer, release_request(&slot)).unwrap_err().is("QIF_BUDGET_EXCEEDED"));
}
