//! Candidate for crates/enclave-core/src/egress_replay_scan_tests.rs.
//! Tests inject an iterator Result into the production-shared private loader.
//! They do not cause or claim a native OS read_dir per-entry failure.

use super::{EgressRegistry, EpochLog};
use crate::error::Errno;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

const INJECTED_DETAIL: &str = "injected one-shot egress iterator entry Result";
const IGNORED_NAME: &str = "ignored-nonlog.txt";

struct OwnedDirectory(PathBuf);
impl OwnedDirectory {
    fn create() -> Self {
        loop {
            let path =
                std::env::temp_dir().join(format!("mc-egress-scan-owned-{:x}", crate::rng::u64()));
            match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(_) => panic!("exclusive owned scan fixture creation failed"),
            }
        }
    }
    fn remove(self) -> bool {
        std::fs::remove_dir_all(&self.0).is_ok()
    }
}
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn create_private_file(path: &Path, bytes: &[u8]) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

struct ScanFixture {
    owned: OwnedDirectory,
    first: String,
    second: String,
}
impl ScanFixture {
    fn create() -> Self {
        let owned = OwnedDirectory::create();
        let first = crate::seq::new_boot_epoch_id();
        let second = crate::seq::new_boot_epoch_id();
        assert_ne!(first, second);
        {
            // Real public writers establish healthy, fully framed I/R/T files.
            // No live registry/writer remains during injected iterator replay.
            let mut registry = EgressRegistry::open(&owned.0).unwrap();
            registry.issued(&first, 11).unwrap();
            registry.released(&first, 12).unwrap();
            registry.issued(&first, 13).unwrap();
            registry.reserve_tombstone(&first, 13).unwrap();
            registry.issued(&second, 21).unwrap();
            registry.released(&second, 22).unwrap();
            registry.issued(&second, 23).unwrap();
            registry.reserve_tombstone(&second, 23).unwrap();
        }
        create_private_file(
            &owned.0.join(IGNORED_NAME),
            b"ignored nonlog bytes without LF",
        );
        assert_eq!(
            std::fs::read(owned.0.join(format!("{first}.log"))).unwrap(),
            b"I 11\nR 12\nI 13\nT 13\n"
        );
        assert_eq!(
            std::fs::read(owned.0.join(format!("{second}.log"))).unwrap(),
            b"I 21\nR 22\nI 23\nT 23\n"
        );
        assert_eq!(
            std::fs::metadata(&owned.0).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for entry in std::fs::read_dir(&owned.0).unwrap() {
            assert_eq!(
                entry.unwrap().metadata().unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        Self {
            owned,
            first,
            second,
        }
    }

    fn entries(&self, order: [EntryKind; 3]) -> Vec<std::fs::DirEntry> {
        // Reacquire real native DirEntry objects for the same immutable owned
        // files for each control/fault pass. Reordering is only test scheduling.
        let mut entries = std::fs::read_dir(&self.owned.0)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), entry)
            })
            .collect::<BTreeMap<OsString, _>>();
        assert_eq!(entries.len(), 3);
        let ordered = order
            .into_iter()
            .map(|kind| {
                let name = match kind {
                    EntryKind::First => format!("{}.log", self.first),
                    EntryKind::Second => format!("{}.log", self.second),
                    EntryKind::Ignored => IGNORED_NAME.to_owned(),
                };
                entries.remove(&OsString::from(name)).unwrap()
            })
            .collect();
        assert!(entries.is_empty());
        ordered
    }

    fn snapshot(&self) -> Vec<(String, Vec<u8>)> {
        let mut result = std::fs::read_dir(&self.owned.0)
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
        result.sort_by(|a, b| a.0.cmp(&b.0));
        result
    }

    fn assert_complete(&self, maps: &BTreeMap<String, EpochLog>) {
        assert_eq!(maps.len(), 2);
        for (epoch, base) in [(&self.first, 10), (&self.second, 20)] {
            let log = maps.get(epoch).unwrap();
            assert_eq!(log.issued, BTreeSet::from([base + 1, base + 2, base + 3]));
            assert_eq!(log.released, BTreeSet::from([base + 2]));
            assert_eq!(log.tombstoned, BTreeSet::from([base + 3]));
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum EntryKind {
    First,
    Second,
    Ignored,
}

struct CountedEntries {
    entries: std::vec::IntoIter<io::Result<std::fs::DirEntry>>,
    yielded: Arc<AtomicUsize>,
    yielded_errors: Arc<AtomicUsize>,
}
impl Iterator for CountedEntries {
    type Item = io::Result<std::fs::DirEntry>;
    fn next(&mut self) -> Option<Self::Item> {
        let item = self.entries.next()?;
        self.yielded.fetch_add(1, Ordering::SeqCst);
        if item.is_err() {
            self.yielded_errors.fetch_add(1, Ordering::SeqCst);
        }
        Some(item)
    }
}
fn counted(
    entries: Vec<std::fs::DirEntry>,
    at: Option<usize>,
) -> (CountedEntries, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let mut entries = entries.into_iter().map(Ok).collect::<Vec<_>>();
    if let Some(at) = at {
        entries.insert(at, Err(io::Error::other(INJECTED_DETAIL)));
    }
    let yielded = Arc::new(AtomicUsize::new(0));
    let errors = Arc::new(AtomicUsize::new(0));
    (
        CountedEntries {
            entries: entries.into_iter(),
            yielded: yielded.clone(),
            yielded_errors: errors.clone(),
        },
        yielded,
        errors,
    )
}

fn scan_error_case(case: &str, order: [EntryKind; 3], error_at: usize) {
    let fixture = ScanFixture::create();
    let before = fixture.snapshot();
    let (control_entries, control_yields, control_errors) = counted(fixture.entries(order), None);
    let control = EgressRegistry::load_entries(control_entries).unwrap();
    fixture.assert_complete(&control);
    assert_eq!(control_yields.load(Ordering::SeqCst), 3);
    assert_eq!(control_errors.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.snapshot(), before);
    drop(control);

    let (entries, yielded, errors) = counted(fixture.entries(order), Some(error_at));
    let result = EgressRegistry::load_entries(entries);
    let returned_map = result.is_ok();
    let returned_epochs = result.as_ref().map(|maps| maps.len()).unwrap_or(0);
    // With the old extracted filter_map algorithm, this is a genuine returned
    // complete map despite the yielded error, not a missing-helper compilation.
    if let Ok(maps) = &result {
        fixture.assert_complete(maps);
    }
    let original_reason_detail = matches!(&result, Err(error)
        if error.errno == Errno::EIO && error.is("EGRESS_DIR") && error.detail == INJECTED_DETAIL);
    let observed_yields = yielded.load(Ordering::SeqCst);
    let error_actually_yielded_once = errors.load(Ordering::SeqCst) == 1;
    let yields_valid = observed_yields >= error_at + 1 && observed_yields <= 4;
    let bytes_unchanged = fixture.snapshot() == before;
    drop(result);
    let owned_tree_removed = fixture.owned.remove();
    println!("EGRESS_REPLAY_ENTRY_RESULT case={case} healthy_same_entries=true real_entries=3 error_actually_yielded_once={error_actually_yielded_once} yielded={observed_yields} yields_valid={yields_valid} original_reason_detail={original_reason_detail} returned_map={returned_map} returned_epochs={returned_epochs} bytes_unchanged={bytes_unchanged} owned_tree_removed={owned_tree_removed}");
    assert!(
        error_actually_yielded_once && yields_valid && bytes_unchanged && owned_tree_removed,
        "actual one-shot injected Result and preserved owned files are setup prerequisites"
    );
    assert!(
        original_reason_detail && !returned_map && returned_epochs == 0,
        "a yielded directory-entry error must refuse without returning any successful partial map"
    );
}

#[test]
fn injected_entry_error_before_first_real_entry_refuses_without_partial_map() {
    scan_error_case(
        "before-first",
        [EntryKind::First, EntryKind::Second, EntryKind::Ignored],
        0,
    );
}
#[test]
fn injected_entry_error_between_valid_real_epochs_refuses_without_partial_map() {
    scan_error_case(
        "between-epochs",
        [EntryKind::First, EntryKind::Second, EntryKind::Ignored],
        1,
    );
}
#[test]
fn injected_entry_error_after_all_valid_real_epochs_refuses_without_partial_map() {
    scan_error_case(
        "after-all",
        [EntryKind::Ignored, EntryKind::First, EntryKind::Second],
        3,
    );
}
#[test]
fn injected_entry_error_before_ignored_nonlog_entry_is_not_ignored() {
    scan_error_case(
        "before-ignored",
        [EntryKind::First, EntryKind::Ignored, EntryKind::Second],
        1,
    );
}
#[test]
fn injected_entry_error_after_ignored_nonlog_entry_is_not_ignored() {
    scan_error_case(
        "after-ignored",
        [EntryKind::First, EntryKind::Ignored, EntryKind::Second],
        2,
    );
}

type Facts = Vec<(String, BTreeSet<u64>, BTreeSet<u64>, BTreeSet<u64>)>;
fn facts(maps: &BTreeMap<String, EpochLog>) -> Facts {
    maps.iter()
        .map(|(epoch, log)| {
            (
                epoch.clone(),
                log.issued.clone(),
                log.released.clone(),
                log.tombstoned.clone(),
            )
        })
        .collect()
}

#[test]
fn shared_loader_healthy_real_entries_match_public_open_without_rewriting() {
    let fixture = ScanFixture::create();
    let before = fixture.snapshot();
    let (entries, yields, errors) = counted(
        fixture.entries([EntryKind::Second, EntryKind::Ignored, EntryKind::First]),
        None,
    );
    let loaded = EgressRegistry::load_entries(entries).unwrap();
    fixture.assert_complete(&loaded);
    let public = EgressRegistry::open(&fixture.owned.0).unwrap();
    assert_eq!(facts(&loaded), facts(&public.epochs));
    public.ensure_healthy().unwrap();
    let counts_valid = yields.load(Ordering::SeqCst) == 3 && errors.load(Ordering::SeqCst) == 0;
    let bytes_unchanged = fixture.snapshot() == before;
    drop(public);
    drop(loaded);
    let owned_tree_removed = fixture.owned.remove();
    println!("EGRESS_REPLAY_SCAN_CONTROL same_production_loader=true actual_public_open=true healthy_facts_match=true real_entries=3 counts_valid={counts_valid} bytes_unchanged={bytes_unchanged} owned_tree_removed={owned_tree_removed}");
    assert!(counts_valid && bytes_unchanged && owned_tree_removed);
}

#[test]
fn initial_directory_open_and_per_file_read_errors_remain_distinct() {
    let owned = OwnedDirectory::create();
    let non_directory = owned.0.join("non-directory");
    create_private_file(&non_directory, b"owned native read_dir open error control");
    let before = std::fs::read(&non_directory).unwrap();
    // private_dir preserves an existing regular path, so public open reaches
    // the actual initial read_dir call. This is not the injected entry branch.
    let expected_open = std::fs::read_dir(&non_directory).unwrap_err().to_string();
    let open_error = EgressRegistry::open(&non_directory).unwrap_err();
    let initial_mapping = open_error.errno == Errno::EIO
        && open_error.is("EGRESS_DIR")
        && open_error.detail == expected_open;
    let epoch_directory = owned
        .0
        .join(format!("{}.log", crate::seq::new_boot_epoch_id()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&epoch_directory)
        .unwrap();
    let expected_read = std::fs::read_to_string(&epoch_directory)
        .unwrap_err()
        .to_string();
    let read_error = EgressRegistry::open(&owned.0).unwrap_err();
    let file_mapping = read_error.errno == Errno::EIO
        && read_error.is("EGRESS_READ")
        && read_error.detail == expected_read;
    let bytes_unchanged =
        std::fs::read(&non_directory).unwrap() == before && epoch_directory.is_dir();
    let owned_tree_removed = owned.remove();
    println!("EGRESS_REPLAY_NATIVE_ERROR_CONTROL initial_open_mapping={initial_mapping} per_file_read_mapping={file_mapping} bytes_unchanged={bytes_unchanged} owned_tree_removed={owned_tree_removed} injected_entry_error=false");
    assert!(initial_mapping && file_mapping && bytes_unchanged && owned_tree_removed);
}
