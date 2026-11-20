//! Private per-instance egress append persistence Result-path tests.
//! Injected Result-path failures, not actual OS fsync or power-loss failures.

use super::EgressRegistry;
use crate::error::{EnclaveError, EnclaveResult, Errno};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AppendStage {
    Open,
    Write,
    FileSync,
    DirectoryOpen,
    DirectorySync,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    Before(AppendStage),
    PartialWrite(usize),
}

#[derive(Debug, Default)]
pub(super) struct AppendTestState {
    fault: Option<Fault>,
    stages: Vec<AppendStage>,
}

impl AppendTestState {
    pub(super) fn before(&mut self, stage: AppendStage) -> io::Result<()> {
        self.stages.push(stage);
        if self.fault == Some(Fault::Before(stage)) {
            self.fault = None;
            return Err(io::Error::other(format!(
                "injected append failure at {stage:?}"
            )));
        }
        Ok(())
    }

    pub(super) fn write_all(&mut self, file: &mut File, bytes: &[u8]) -> io::Result<()> {
        self.before(AppendStage::Write)?;
        if let Some(Fault::PartialWrite(prefix)) = self.fault {
            assert!(prefix > 0 && prefix < bytes.len());
            self.fault = None;
            // The real write_all algorithm sees a short, real write followed
            // by an injected error. No candidate bytes are synthesized in RAM.
            PartialWriter {
                file,
                remaining: prefix,
            }
            .write_all(bytes)
        } else {
            file.write_all(bytes)
        }
    }

    fn arm(&mut self, fault: Fault) {
        assert!(self.fault.is_none());
        self.stages.clear();
        self.fault = Some(fault);
    }
}

struct PartialWriter<'a> {
    file: &'a mut File,
    remaining: usize,
}
impl Write for PartialWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::other(
                "injected append failure after real prefix",
            ));
        }
        let n = self.file.write(&bytes[..bytes.len().min(self.remaining)])?;
        self.remaining -= n;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

struct OwnedDirectory(PathBuf);
impl OwnedDirectory {
    fn new() -> Self {
        // create_dir establishes ownership atomically; collisions are retried.
        loop {
            let path =
                std::env::temp_dir().join(format!("depot-egress-fault-{}", crate::rng::u64()));
            match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(_) => panic!("owned egress test directory creation failed"),
            }
        }
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

type Accepted = Vec<(String, BTreeSet<u64>, BTreeSet<u64>, BTreeSet<u64>)>;

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    accepted: Accepted,
    files: Vec<(String, Vec<u8>)>,
    stages: Vec<AppendStage>,
}
fn snapshot(registry: &EgressRegistry, directory: &Path) -> Snapshot {
    let accepted = registry
        .epochs
        .iter()
        .map(|(epoch, log)| {
            (
                epoch.clone(),
                log.issued.clone(),
                log.released.clone(),
                log.tombstoned.clone(),
            )
        })
        .collect();
    let mut files = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            assert!(entry.file_type().unwrap().is_file());
            (
                entry.file_name().into_string().unwrap(),
                std::fs::read(entry.path()).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Snapshot {
        accepted,
        files,
        stages: registry.append_test.stages.clone(),
    }
}

fn assert_poison(error: EnclaveError) {
    assert_eq!(error.errno, Errno::EIO);
    assert!(
        error.is("EGRESS_REGISTRY_POISONED"),
        "expected stable poison reason"
    );
    assert!(error.detail.is_empty());
}

fn assert_all_authority_fenced(registry: &mut EgressRegistry, directory: &Path, epoch: &str) {
    let before = snapshot(registry, directory);
    let other_epoch = crate::seq::new_boot_epoch_id();
    // Failed candidate, independent slot, independent epoch, and cached T.
    for (e, seq) in [
        (epoch, 100),
        (epoch, 101),
        (other_epoch.as_str(), 100),
        (epoch, 7),
    ] {
        assert_poison(registry.issued(e, seq).unwrap_err());
        assert_poison(registry.released(e, seq).unwrap_err());
        assert_poison(registry.reserve_nonrelease(e, seq).unwrap_err());
        assert_poison(registry.reserve_tombstone(e, seq).unwrap_err());
        assert_poison(registry.may_tombstone(e, seq).unwrap_err());
    }
    // Invalid input after poison cannot manufacture a healthy authority path.
    assert_poison(registry.issued("invalid epoch", 102).unwrap_err());
    assert_poison(registry.ensure_healthy().unwrap_err());
    assert_eq!(
        snapshot(registry, directory),
        before,
        "authority attempts must change neither accepted facts, real log bytes nor I/O counters"
    );
    // Reads remain historical facts. Their false values prove no disk absence.
    assert!(registry.was_issued(epoch, 7));
    assert!(registry.was_tombstoned(epoch, 7));
    assert!(registry.was_released(epoch, 9));
    assert_eq!(registry.released_in(epoch, 0, 99), vec![9]);
}

#[derive(Debug, Clone, Copy)]
enum Operation {
    I,
    R,
    T,
}
impl Operation {
    fn run(self, registry: &mut EgressRegistry, epoch: &str) -> EnclaveResult<()> {
        match self {
            Self::I => registry.issued(epoch, 100),
            Self::R => registry.released(epoch, 100),
            Self::T => registry.reserve_tombstone(epoch, 100),
        }
    }
    fn record(self) -> &'static [u8] {
        match self {
            Self::I => b"I 100\n",
            Self::R => b"R 100\n",
            Self::T => b"T 100\n",
        }
    }
}

fn fault_case(operation: Operation, fault: Fault) {
    use AppendStage::*;
    let owned = OwnedDirectory::new();
    let epoch = crate::seq::new_boot_epoch_id();
    let mut registry = EgressRegistry::open(owned.path()).unwrap();
    registry.issued(&epoch, 7).unwrap();
    registry.reserve_tombstone(&epoch, 7).unwrap();
    registry.released(&epoch, 9).unwrap();
    if !matches!(operation, Operation::I) {
        registry.issued(&epoch, 100).unwrap();
    }
    let log_path = owned.path().join(format!("{epoch}.log"));
    let before_bytes = std::fs::read(&log_path).unwrap();
    let before_accepted = snapshot(&registry, owned.path()).accepted;
    registry.append_test.arm(fault);
    let error = operation.run(&mut registry, &epoch).unwrap_err();
    assert_eq!(error.errno, Errno::EIO);
    let (reason, detail, stages, appended): (&str, String, Vec<AppendStage>, &[u8]) = match fault {
        Fault::PartialWrite(prefix) => (
            "EGRESS_WRITE",
            "injected append failure after real prefix".into(),
            vec![Open, Write],
            &operation.record()[..prefix],
        ),
        Fault::Before(stage) => {
            let stages = match stage {
                Open => vec![Open],
                Write => vec![Open, Write],
                FileSync => vec![Open, Write, FileSync],
                DirectoryOpen => vec![Open, Write, FileSync, DirectoryOpen],
                DirectorySync => vec![Open, Write, FileSync, DirectoryOpen, DirectorySync],
            };
            let reason = if matches!(stage, Open | Write) {
                "EGRESS_WRITE"
            } else {
                "EGRESS_FSYNC"
            };
            let appended = if matches!(stage, Open | Write) {
                &[][..]
            } else {
                operation.record()
            };
            (
                reason,
                format!("injected append failure at {stage:?}"),
                stages,
                appended,
            )
        }
    };
    // Assert the first original error unchanged, including detail; subsequent
    // authority errors have the distinct stable poison reason.
    assert_eq!(error.reason, reason);
    assert_eq!(error.detail, detail);
    assert_eq!(registry.append_test.stages, stages);
    assert!(
        registry.append_test.fault.is_none(),
        "one-shot failure must be consumed"
    );
    let mut expected = before_bytes;
    expected.extend_from_slice(appended);
    assert_eq!(std::fs::read(&log_path).unwrap(), expected);
    assert_eq!(snapshot(&registry, owned.path()).accepted, before_accepted);
    assert!(!registry.was_released(&epoch, 100));
    assert!(!registry.was_tombstoned(&epoch, 100));
    assert_eq!(
        registry.was_issued(&epoch, 100),
        !matches!(operation, Operation::I)
    );
    assert_all_authority_fenced(&mut registry, owned.path(), &epoch);
    println!("observed_result_fault op={operation:?} fault={fault:?} original_error_preserved=true real_bytes_checked=true later_authority_fenced=true no_further_io=true");
}

#[test]
fn partial_i_write_fences_all_later_authority() {
    fault_case(Operation::I, Fault::PartialWrite(2));
}
#[test]
fn partial_r_write_fences_all_later_authority() {
    fault_case(Operation::R, Fault::PartialWrite(2));
}
#[test]
fn partial_t_write_fences_all_later_authority() {
    fault_case(Operation::T, Fault::PartialWrite(2));
}
#[test]
fn full_r_then_file_sync_error_fences_all_later_authority() {
    fault_case(Operation::R, Fault::Before(AppendStage::FileSync));
}
#[test]
fn full_t_then_file_sync_error_fences_all_later_authority() {
    fault_case(Operation::T, Fault::Before(AppendStage::FileSync));
}
#[test]
fn full_r_then_directory_open_error_fences_all_later_authority() {
    fault_case(Operation::R, Fault::Before(AppendStage::DirectoryOpen));
}
#[test]
fn full_t_then_directory_open_error_fences_all_later_authority() {
    fault_case(Operation::T, Fault::Before(AppendStage::DirectoryOpen));
}
#[test]
fn full_r_then_directory_sync_error_fences_all_later_authority() {
    fault_case(Operation::R, Fault::Before(AppendStage::DirectorySync));
}
#[test]
fn full_t_then_directory_sync_error_fences_all_later_authority() {
    fault_case(Operation::T, Fault::Before(AppendStage::DirectorySync));
}
#[test]
fn i_open_error_fences_all_later_authority() {
    fault_case(Operation::I, Fault::Before(AppendStage::Open));
}
#[test]
fn r_open_error_fences_all_later_authority() {
    fault_case(Operation::R, Fault::Before(AppendStage::Open));
}
#[test]
fn t_open_error_fences_all_later_authority() {
    fault_case(Operation::T, Fault::Before(AppendStage::Open));
}

#[test]
fn healthy_native_control_preserves_existing_persistence_and_replay() {
    use AppendStage::*;
    let owned = OwnedDirectory::new();
    let epoch = crate::seq::new_boot_epoch_id();
    {
        let mut registry = EgressRegistry::open(owned.path()).unwrap();
        registry.issued(&epoch, 1).unwrap();
        assert_eq!(
            registry.append_test.stages,
            vec![Open, Write],
            "I remains historically unsynced"
        );
        registry.released(&epoch, 1).unwrap();
        registry.issued(&epoch, 2).unwrap();
        registry.reserve_tombstone(&epoch, 2).unwrap();
        let before = snapshot(&registry, owned.path());
        registry.reserve_tombstone(&epoch, 2).unwrap();
        registry.reserve_nonrelease(&epoch, 2).unwrap();
        registry.ensure_healthy().unwrap();
        assert_eq!(
            snapshot(&registry, owned.path()),
            before,
            "healthy cached T stays idempotent"
        );
    }
    // Ordinary complete-log replay is not uncertain-error recovery.
    let mut reopened = EgressRegistry::open(owned.path()).unwrap();
    assert!(reopened.was_released(&epoch, 1));
    assert!(reopened.was_tombstoned(&epoch, 2));
    assert_eq!(
        reopened.released(&epoch, 2).unwrap_err().reason,
        "TOMBSTONE_SLOT_FINALIZED"
    );
    assert_eq!(
        reopened.reserve_nonrelease(&epoch, 1).unwrap_err().reason,
        "TOMBSTONE_SLOT_RELEASED"
    );
    reopened.released(&epoch, 3).unwrap();
    reopened.ensure_healthy().unwrap();
    println!(
        "healthy_native_control=true ordinary_complete_log_replay=true historical_i_unsynced=true"
    );
}

fn validation_control(registry: &mut EgressRegistry) {
    let epoch = crate::seq::new_boot_epoch_id();
    registry.issued(&epoch, 1).unwrap();
    registry.released(&epoch, 1).unwrap();
    registry.issued(&epoch, 2).unwrap();
    registry.reserve_tombstone(&epoch, 2).unwrap();
    let before = registry.append_test.stages.clone();
    assert_eq!(
        registry.issued("invalid", 3).unwrap_err().reason,
        "BAD_BOOT_EPOCH_ID"
    );
    assert_eq!(
        registry.released("invalid", 3).unwrap_err().reason,
        "BAD_BOOT_EPOCH_ID"
    );
    assert_eq!(
        registry
            .reserve_nonrelease("invalid", 3)
            .unwrap_err()
            .reason,
        "BAD_BOOT_EPOCH_ID"
    );
    assert_eq!(
        registry.reserve_tombstone(&epoch, 99).unwrap_err().reason,
        "TOMBSTONE_SLOT_UNKNOWN"
    );
    assert_eq!(
        registry.may_tombstone(&epoch, 99).unwrap_err().reason,
        "TOMBSTONE_SLOT_UNKNOWN"
    );
    assert_eq!(
        registry.reserve_tombstone(&epoch, 1).unwrap_err().reason,
        "TOMBSTONE_SLOT_RELEASED"
    );
    assert_eq!(
        registry.reserve_nonrelease(&epoch, 1).unwrap_err().reason,
        "TOMBSTONE_SLOT_RELEASED"
    );
    assert_eq!(
        registry.may_tombstone(&epoch, 1).unwrap_err().reason,
        "TOMBSTONE_SLOT_RELEASED"
    );
    assert_eq!(
        registry.released(&epoch, 2).unwrap_err().reason,
        "TOMBSTONE_SLOT_FINALIZED"
    );
    assert_eq!(
        registry.append_test.stages, before,
        "ordinary invalid/policy calls perform no append I/O"
    );
    registry.ensure_healthy().unwrap();
    registry.issued(&epoch, 3).unwrap();
    registry.reserve_tombstone(&epoch, 3).unwrap();
    registry.released(&epoch, 4).unwrap();
    registry.ensure_healthy().unwrap();
}

#[test]
fn healthy_ephemeral_and_native_validation_refusals_do_not_poison() {
    let owned = OwnedDirectory::new();
    let mut native = EgressRegistry::open(owned.path()).unwrap();
    validation_control(&mut native);
    let mut ephemeral = EgressRegistry::ephemeral();
    validation_control(&mut ephemeral);
    assert!(ephemeral.append_test.stages.is_empty());
    println!("healthy_native_validation=true healthy_ephemeral_validation=true ordinary_errors_do_not_poison=true");
}

#[test]
fn failed_registry_does_not_poison_an_independent_different_path_instance() {
    let first = OwnedDirectory::new();
    let second = OwnedDirectory::new();
    assert_ne!(first.path(), second.path());
    let epoch = crate::seq::new_boot_epoch_id();
    let mut failed = EgressRegistry::open(first.path()).unwrap();
    failed.append_test.arm(Fault::Before(AppendStage::FileSync));
    assert!(failed
        .reserve_nonrelease(&epoch, 1)
        .unwrap_err()
        .is("EGRESS_FSYNC"));
    // Full bytes are present although this instance never accepted T in memory.
    assert_eq!(
        std::fs::read(first.path().join(format!("{epoch}.log"))).unwrap(),
        b"T 1\n"
    );
    assert!(!failed.was_tombstoned(&epoch, 1));
    assert_poison(failed.released(&epoch, 1).unwrap_err());
    let mut healthy = EgressRegistry::open(second.path()).unwrap();
    healthy.issued(&epoch, 1).unwrap();
    healthy.released(&epoch, 1).unwrap();
    healthy.issued(&epoch, 2).unwrap();
    healthy.reserve_tombstone(&epoch, 2).unwrap();
    healthy.ensure_healthy().unwrap();
    assert!(healthy.was_released(&epoch, 1));
    assert!(healthy.was_tombstoned(&epoch, 2));
    println!("different_owned_path_instance_independence=true same_path_restart_fencing_not_claimed=true");
}
