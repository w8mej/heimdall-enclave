//! Real production inventory bound and aggregate-only retention. No payload reads.
use super::*;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, MetadataExt};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().canonicalize().unwrap()
            .join(format!("mc-ob-count-{:016x}", enclave_core::rng::u64()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap(); Self(path)
    }
}
impl Drop for Directory { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
fn create(directory: &Path, sequence: u64, suffix: &str) {
    fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(directory.join(format!("{sequence:020}.{suffix}"))).unwrap();
}
fn identity(path: &Path) -> (u64, u64, u64, u32, u64) {
    let value = fs::symlink_metadata(path).unwrap();
    (value.dev(), value.ino(), value.len(), value.mode(), value.nlink())
}

#[test]
fn diagnostics_full_production_inventory_counts_without_retaining_paths_and_excess_is_unknown() {
    assert_eq!(MAX_OUTBOX_DIRECTORY_ENTRIES, 65_536, "fixture uses full production limit");
    let directory = Directory::new();
    for sequence in 0..65_536_u64 {
        create(&directory.0, sequence, if sequence % 2 == 0 { "ohttp" } else { "dead" });
    }
    let first = directory.0.join("00000000000000000000.ohttp");
    let last = directory.0.join("00000000000000065535.dead");
    let identities = (identity(&first), identity(&last));
    let namespace = OutboxNamespace::try_lock(&directory.0).unwrap();
    let inventory = namespace.scan_with_collection(false, 0, false).unwrap();
    assert_eq!((inventory.pending_frames, inventory.dead_frames, inventory.total, inventory.maximum),
        (32_768, 32_768, 0, Some(65_535)));
    assert!(inventory.pending.is_empty() && inventory.pending.capacity() == 0,
        "aggregate diagnostics must retain no pending-name vector");
    drop(namespace);
    let observer = OutboxDiagnostics::new(directory.0.clone(), enclave_core::seq::new_boot_epoch_id(), true);
    let current = observer.snapshot();
    assert!(current.valid());
    assert_eq!(current.observation, OutboxObservation::Current { counts: OutboxCounts {
        pending_frames: 32_768, dead_frames: 32_768, retained_bytes: 0 } });
    create(&directory.0, 65_536, "ohttp");
    let excess = observer.snapshot();
    assert!(excess.valid());
    assert_eq!(excess.observation, OutboxObservation::Unavailable { fault: OutboxObservationFault::EntryLimit });
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 65_537);
    assert_eq!((identity(&first), identity(&last)), identities);
    println!("OUTBOX_DIAGNOSTICS_FULL_BOUNDARY: actual65536=32768pending+32768dead/0logicalbytes; names_retained=0; actual65537=entry_limit/unknown; boundary_inode_metadata_unchanged=true");
}
