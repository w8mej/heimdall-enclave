//! Public egress replay framing tests with controlled, exclusively owned input.
//! These inputs model incomplete framing, not an observed kernel torn write.
#![cfg(unix)]

use enclave_core::egress::EgressRegistry;
use enclave_core::error::{EnclaveError, Errno};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new() -> Self {
        loop {
            let path = std::env::temp_dir().join(format!(
                "mc-er-{}", enclave_core::seq::new_boot_epoch_id(),
            ));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => {
                    let owned = Self(path);
                    assert_eq!(fs::metadata(&owned.0).unwrap().permissions().mode() & 0o7777, 0o700);
                    return owned;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("exclusive fixture directory creation failed: {error}"),
            }
        }
    }

    fn path(&self) -> &Path { &self.0 }

    fn remove(self) -> bool {
        // Drop is an additional best-effort cleanup if this explicit removal fails.
        fs::remove_dir_all(&self.0).is_ok()
    }
}

impl Drop for OwnedDirectory {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

#[derive(Debug, PartialEq, Eq)]
struct FileSnapshot {
    name: String,
    bytes: Vec<u8>,
    mode: u32,
}

fn snapshot(directory: &Path) -> Vec<FileSnapshot> {
    let mut files = fs::read_dir(directory).unwrap().map(|entry| {
        let entry = entry.unwrap();
        assert!(entry.file_type().unwrap().is_file(), "fixture only owns regular files here");
        let mode = entry.metadata().unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600, "every controlled file must retain private permissions");
        FileSnapshot {
            name: entry.file_name().into_string().unwrap(),
            bytes: fs::read(entry.path()).unwrap(),
            mode,
        }
    }).collect::<Vec<_>>();
    files.sort_by(|left, right| left.name.cmp(&right.name));
    files
}

fn create_owned_file(directory: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    assert_eq!(Path::new(name).components().count(), 1);
    let path = directory.join(name);
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(&path).unwrap();
    file.write_all(bytes).unwrap();
    drop(file);
    assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o7777, 0o600);
    path
}

#[derive(Debug, Clone, Copy)]
enum Record { I, R, T }

impl Record {
    fn name(self) -> &'static str {
        match self { Self::I => "I", Self::R => "R", Self::T => "T" }
    }

    fn write(self, writer: &mut EgressRegistry, epoch: &str) {
        match self {
            Self::I => writer.issued(epoch, 100).unwrap(),
            Self::R => writer.released(epoch, 100).unwrap(),
            Self::T => {
                writer.issued(epoch, 100).unwrap();
                writer.reserve_tombstone(epoch, 100).unwrap();
            }
        }
    }

    fn complete_bytes(self) -> &'static [u8] {
        match self {
            Self::I => b"I 100\n",
            Self::R => b"R 100\n",
            Self::T => b"I 100\nT 100\n",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Truncation { FinalLf, NumericPrefix }

impl Truncation {
    fn name(self) -> &'static str {
        match self { Self::FinalLf => "missing-final-lf", Self::NumericPrefix => "numeric-prefix" }
    }

    fn bytes(self, complete: &[u8]) -> &[u8] {
        assert!(complete.ends_with(b"100\n"));
        let removed = match self { Self::FinalLf => 1, Self::NumericPrefix => 2 };
        &complete[..complete.len() - removed]
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Facts {
    issued100: bool,
    released100: bool,
    tombstoned100: bool,
    issued10: bool,
    released10: bool,
    tombstoned10: bool,
    may_tombstone100: bool,
    may_tombstone10: bool,
    other_epoch77: bool,
}

impl Facts {
    fn read(registry: &EgressRegistry, epoch: &str, other: &str) -> Self {
        Self {
            issued100: registry.was_issued(epoch, 100),
            released100: registry.was_released(epoch, 100),
            tombstoned100: registry.was_tombstoned(epoch, 100),
            issued10: registry.was_issued(epoch, 10),
            released10: registry.was_released(epoch, 10),
            tombstoned10: registry.was_tombstoned(epoch, 10),
            may_tombstone100: registry.may_tombstone(epoch, 100).is_ok(),
            may_tombstone10: registry.may_tombstone(epoch, 10).is_ok(),
            other_epoch77: registry.was_issued(other, 77)
                && !registry.was_released(other, 77) && !registry.was_tombstoned(other, 77),
        }
    }

    fn expected(record: Record, truncation: Truncation) -> Self {
        let mut facts = Self { other_epoch77: true, ..Self::default() };
        match (record, truncation) {
            (Record::I, Truncation::FinalLf) => {
                facts.issued100 = true;
                facts.may_tombstone100 = true;
            }
            (Record::R, Truncation::FinalLf) => {
                facts.issued100 = true;
                facts.released100 = true;
            }
            (Record::T, Truncation::FinalLf) => {
                facts.issued100 = true;
                facts.tombstoned100 = true;
                facts.may_tombstone100 = true;
            }
            (Record::I, Truncation::NumericPrefix) => {
                facts.issued10 = true;
                facts.may_tombstone10 = true;
            }
            (Record::R, Truncation::NumericPrefix) => {
                facts.issued10 = true;
                facts.released10 = true;
            }
            (Record::T, Truncation::NumericPrefix) => {
                // The preceding complete I100 stays; the incomplete T rebinds to10.
                facts.issued100 = true;
                facts.tombstoned10 = true;
                facts.may_tombstone100 = true;
            }
        }
        facts
    }

    fn record100(&self, record: Record) -> bool {
        match record { Record::I => self.issued100, Record::R => self.released100, Record::T => self.tombstoned100 }
    }

    fn record10(&self, record: Record) -> bool {
        match record { Record::I => self.issued10, Record::R => self.released10, Record::T => self.tombstoned10 }
    }
}

fn public_incomplete_record_case(record: Record, truncation: Truncation) {
    let directory = OwnedDirectory::new();
    let epoch = enclave_core::seq::new_boot_epoch_id();
    let other = enclave_core::seq::new_boot_epoch_id();
    assert_ne!(epoch, other);
    let path = directory.path().join(format!("{epoch}.log"));
    let other_path = directory.path().join(format!("{other}.log"));
    let mut writer = EgressRegistry::open(directory.path()).unwrap();
    writer.issued(&other, 77).unwrap();
    record.write(&mut writer, &epoch);
    drop(writer);
    let complete = record.complete_bytes();
    assert_eq!(fs::read(&path).unwrap(), complete, "public writer must produce exact complete records");
    assert_eq!(fs::read(&other_path).unwrap(), b"I 77\n");
    let complete_snapshot = snapshot(directory.path());
    assert_eq!(complete_snapshot.len(), 2);
    let healthy = EgressRegistry::open(directory.path()).unwrap();
    let writer_control = healthy.ensure_healthy().is_ok()
        && Facts::read(&healthy, &epoch, &other) == Facts::expected(record, Truncation::FinalLf);
    drop(healthy);
    assert!(writer_control, "complete public-writer replay is a required positive control");
    assert_eq!(snapshot(directory.path()), complete_snapshot);

    // Controlled fixture edit after all registry owners are dropped; no crash claim.
    let candidate = truncation.bytes(complete);
    let mut file = OpenOptions::new().write(true).truncate(true).open(&path).unwrap();
    file.write_all(candidate).unwrap();
    drop(file);
    let candidate_bytes_exact = fs::read(&path).unwrap() == candidate;
    assert!(candidate_bytes_exact);
    assert!(!candidate.ends_with(b"\n"));
    assert_eq!(fs::read(&other_path).unwrap(), b"I 77\n");
    let before = snapshot(directory.path());
    let (accepted, observed_facts, error) = match EgressRegistry::open(directory.path()) {
        Ok(registry) => {
            let facts = Facts::read(&registry, &epoch, &other);
            drop(registry);
            (true, Some(facts), None)
        }
        Err(error) => (false, None, Some(error)),
    };
    let named_corrupt = error.as_ref().is_some_and(|error| {
        error.errno == Errno::EINVAL && error.is("EGRESS_LOG_CORRUPT")
            && error.detail == path.display().to_string()
    });
    let old_expected_facts = observed_facts.as_ref()
        .is_some_and(|facts| *facts == Facts::expected(record, truncation));
    let accepted_record100 = observed_facts.as_ref().is_some_and(|facts| facts.record100(record));
    let accepted_record10 = observed_facts.as_ref().is_some_and(|facts| facts.record10(record));
    let shorter_slot_owner_authority = observed_facts.as_ref().is_some_and(|facts| facts.may_tombstone10);
    let bytes_preserved = snapshot(directory.path()) == before;
    let other_epoch_bytes_preserved = fs::read(&other_path).unwrap() == b"I 77\n";
    let owned_tree_removed = directory.remove();
    println!("EGRESS_REPLAY_PUBLIC kind={} variant={} writer_control={writer_control} candidate_bytes_exact={candidate_bytes_exact} accepted={accepted} named_corrupt={named_corrupt} old_expected_facts={old_expected_facts} accepted_record100={accepted_record100} accepted_record10={accepted_record10} shorter_slot_owner_authority={shorter_slot_owner_authority} bytes_preserved={bytes_preserved} other_epoch_bytes_preserved={other_epoch_bytes_preserved} owned_tree_removed={owned_tree_removed}", record.name(), truncation.name());
    assert!(owned_tree_removed, "fixture cleanup must precede intended contract assertion");
    assert!(bytes_preserved && other_epoch_bytes_preserved, "public open must preserve every controlled file");
    assert!(!accepted && named_corrupt,
        "nonempty incomplete final record must refuse with exact EINVAL/EGRESS_LOG_CORRUPT and no partial registry");
}

#[test]
fn public_replay_rejects_unterminated_issued_record() {
    public_incomplete_record_case(Record::I, Truncation::FinalLf);
}

#[test]
fn public_replay_rejects_unterminated_released_record() {
    public_incomplete_record_case(Record::R, Truncation::FinalLf);
}

#[test]
fn public_replay_rejects_unterminated_tombstone_record() {
    public_incomplete_record_case(Record::T, Truncation::FinalLf);
}

#[test]
fn public_replay_rejects_numeric_prefix_rebound_issuance() {
    public_incomplete_record_case(Record::I, Truncation::NumericPrefix);
}

#[test]
fn public_replay_rejects_numeric_prefix_rebound_release() {
    public_incomplete_record_case(Record::R, Truncation::NumericPrefix);
}

#[test]
fn public_replay_rejects_numeric_prefix_rebound_tombstone() {
    public_incomplete_record_case(Record::T, Truncation::NumericPrefix);
}

enum Detail { FilePath, Exact(&'static str), Unspecified }

fn controlled_error_case(label: &str, filename: &str, bytes: &[u8], errno: Errno, reason: &str, detail: Detail) {
    let directory = OwnedDirectory::new();
    let path = create_owned_file(directory.path(), filename, bytes);
    let before = snapshot(directory.path());
    let error: Option<EnclaveError> = match EgressRegistry::open(directory.path()) {
        Ok(registry) => { drop(registry); None }
        Err(error) => Some(error),
    };
    let named_refusal = error.as_ref().is_some_and(|error| {
        error.errno == errno && error.is(reason) && match detail {
            Detail::FilePath => error.detail == path.display().to_string(),
            Detail::Exact(expected) => error.detail == expected,
            Detail::Unspecified => true,
        }
    });
    let bytes_preserved = snapshot(directory.path()) == before;
    let owned_tree_removed = directory.remove();
    println!("EGRESS_REPLAY_CONTROL case={label} named_refusal={named_refusal} bytes_preserved={bytes_preserved} owned_tree_removed={owned_tree_removed}");
    assert!(owned_tree_removed, "fixture cleanup failed");
    assert!(bytes_preserved, "open modified controlled error input");
    assert!(named_refusal, "expected existing exact error mapping for controlled input");
}

#[test]
fn public_replay_empty_directory_and_empty_epoch_file_remain_healthy() {
    let directory = OwnedDirectory::new();
    let epoch = enclave_core::seq::new_boot_epoch_id();
    let before_empty = snapshot(directory.path());
    assert!(before_empty.is_empty());
    let empty = EgressRegistry::open(directory.path()).unwrap();
    let empty_healthy = empty.ensure_healthy().is_ok() && !empty.was_issued(&epoch, 100);
    drop(empty);
    let empty_preserved = snapshot(directory.path()) == before_empty;
    create_owned_file(directory.path(), &format!("{epoch}.log"), b"");
    let before_file = snapshot(directory.path());
    let with_file = EgressRegistry::open(directory.path()).unwrap();
    let empty_file_healthy = with_file.ensure_healthy().is_ok()
        && !with_file.was_issued(&epoch, 100) && !with_file.was_released(&epoch, 100)
        && !with_file.was_tombstoned(&epoch, 100);
    drop(with_file);
    let file_preserved = snapshot(directory.path()) == before_file;
    let owned_tree_removed = directory.remove();
    assert!(owned_tree_removed, "fixture cleanup failed");
    assert!(empty_healthy && empty_preserved && empty_file_healthy && file_preserved);
}

#[test]
fn public_replay_complete_crlf_numeric_duplicates_and_epoch_isolation_remain_healthy() {
    let directory = OwnedDirectory::new();
    let epoch = enclave_core::seq::new_boot_epoch_id();
    let other = enclave_core::seq::new_boot_epoch_id();
    assert_ne!(epoch, other);
    create_owned_file(directory.path(), &format!("{epoch}.log"),
        b"I +0007\r\nI 7\r\nR +0009\r\nR 9\r\nT +0011\r\nT 11\r\n");
    create_owned_file(directory.path(), &format!("{other}.log"), b"I 7\nI 100\n");
    create_owned_file(directory.path(), "ignored-note.txt", b"not a log\0\xff");
    let before = snapshot(directory.path());
    let registry = EgressRegistry::open(directory.path()).unwrap();
    let healthy = registry.ensure_healthy().is_ok()
        && registry.was_issued(&epoch, 7) && registry.was_released(&epoch, 9)
        && registry.was_issued(&epoch, 9) && registry.was_tombstoned(&epoch, 11)
        && registry.may_tombstone(&epoch, 7).is_ok()
        && registry.released_in(&epoch, 0, 100) == vec![9]
        && registry.was_issued(&other, 7) && registry.was_issued(&other, 100)
        && !registry.was_issued(&epoch, 100) && !registry.was_released(&other, 9)
        && !registry.was_tombstoned(&other, 11);
    drop(registry);
    let bytes_preserved = snapshot(directory.path()) == before;
    let owned_tree_removed = directory.remove();
    assert!(owned_tree_removed, "fixture cleanup failed");
    assert!(healthy && bytes_preserved, "existing fully framed compatibility must be preserved");
}

#[test]
fn public_replay_malformed_complete_records_keep_corrupt_error_and_bytes() {
    for (label, bytes) in [
        ("unknown-kind", &b"X 1\n"[..]),
        ("missing-separator", &b"I\n"[..]),
        ("missing-number", &b"I \n"[..]),
        ("invalid-number", &b"I nope\n"[..]),
        ("number-overflow", &b"I 18446744073709551616\n"[..]),
        ("blank-record", &b"\n"[..]),
        ("interior-blank", &b"I 1\n\nR 1\n"[..]),
        ("later-malformed", &b"I 1\nR nope\n"[..]),
    ] {
        let filename = format!("{}.log", enclave_core::seq::new_boot_epoch_id());
        controlled_error_case(label, &filename, bytes, Errno::EINVAL, "EGRESS_LOG_CORRUPT", Detail::FilePath);
    }
}

#[test]
fn public_replay_malformed_incomplete_tails_keep_corrupt_error_and_bytes() {
    for (label, tail) in [
        ("tail-kind", &b"I"[..]), ("tail-issued-space", &b"I "[..]),
        ("tail-released-space", &b"R "[..]), ("tail-tombstone-space", &b"T "[..]),
        ("tail-digits", &b"12"[..]),
    ] {
        let filename = format!("{}.log", enclave_core::seq::new_boot_epoch_id());
        let mut bytes = b"I 7\n".to_vec();
        bytes.extend_from_slice(tail);
        controlled_error_case(label, &filename, &bytes, Errno::EINVAL, "EGRESS_LOG_CORRUPT", Detail::FilePath);
    }
}

#[test]
fn public_replay_invalid_utf8_keeps_read_error_and_exact_bytes() {
    let filename = format!("{}.log", enclave_core::seq::new_boot_epoch_id());
    controlled_error_case("invalid-utf8", &filename, b"I 7\n\xff\n", Errno::EIO, "EGRESS_READ", Detail::Unspecified);
}

#[test]
fn public_replay_invalid_epoch_keeps_filename_error_precedence() {
    // Malformed, unterminated content must not replace the earlier epoch error.
    controlled_error_case("invalid-epoch", "not-an-epoch.log", b"not a record", Errno::EINVAL,
        "BAD_BOOT_EPOCH_ID", Detail::Exact("\"not-an-epoch\""));
}

#[test]
fn public_replay_framed_release_tombstone_conflicts_keep_error_and_bytes() {
    for (label, bytes) in [
        ("release-then-tombstone", &b"I 7\nR 7\nT 7\n"[..]),
        ("tombstone-then-release", &b"I 7\nT 7\nR 7\n"[..]),
    ] {
        let filename = format!("{}.log", enclave_core::seq::new_boot_epoch_id());
        controlled_error_case(label, &filename, bytes, Errno::EINVAL, "EGRESS_LOG_CORRUPT",
            Detail::Exact("released and tombstoned slot"));
    }
}
