//! Actual SOFTWARE unlink/FD/fsync/OS-lock fixtures only. No actual native
//! birth/guard/checked/provisioning/SOFTWARE/EX/event/proof is constructed.
//!
//! Native explicit Dedicated-release acceptance remains UNEXERCISED. A real
//! Registered-consuming owner must first pass complete native source/jobs/
//! metadata/pin/SOFTWARE/account/guard/crypto gates and carry the same actual
//! successful own-clear proof and original sameEX-to-Dedicated transition.
//! Execute one actual final release endpoint; observe that this actual owner
//! is taken once and its destructor returns, with original binding/event proof
//! retained. Independently test actual cooperating lifetime-SH admission in
//! the permitted native harness; owner-drop history itself proves no runtime
//! health, authenticated startup, physical behavior or tier qualification.
//! Refuse real guard/context/proof/earliest-expiry loss before take without
//! dropping Dedicated. Cross actual signed expiry/equality/rollback at the
//! endpoint and during final proof/guard observations. Late refusal retains
//! truthful actual take/drop history, all remaining original owners and every
//! error; it cannot reacquire, retry, recall startup or pass the old held-
//! Dedicated current API. Postrelease observer requires actual completed
//! history and exact original own-clear proof, with zero old lease checks.
//! No executable fixture fabricates those opaque native capabilities. Existing
//! generic real OS-flock test above/below covers ONLY its separate kernel scope.
use super::*;
use std::{
    cell::Cell,
    os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt},
    sync::Mutex,
};
static SERIAL: Mutex<()> = Mutex::new(());
fn sync(file: &File) -> EnclaveResult<()> {
    file.sync_all()
        .map_err(|_| err!(EIO, "DENIAL_FIXTURE_SYNC"))
}
fn open(path: &Path, directory: bool) -> File {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_CLOEXEC
                | if directory { libc::O_DIRECTORY } else { 0 },
        )
    };
    assert!(fd >= 0);
    unsafe { File::from_raw_fd(fd) }
}
struct Fixture {
    root: PathBuf,
    path: PathBuf,
    parent: File,
    marker: File,
    lifetime: File,
    bytes: Vec<u8>,
    protection: Protection,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::current_dir().unwrap().join(format!(
            ".denial-kernel-{}",
            hex::encode(enclave_core::rng::bytes32())
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join(UPGRADE_INHIBITION_LEAF);
        let bytes = b"SOFTWARE exact pending-marker fixture bytes".to_vec();
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            file.write_all(&bytes).unwrap();
        }
        let lifetime_path = root.join(STARTUP_LIFETIME_LEAF);
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&lifetime_path)
            .unwrap();
        let parent = open(&root, true);
        let marker = open(&path, false);
        let lifetime = open(&lifetime_path, false);
        let protection = Protection {
            owner: (unsafe { libc::geteuid() }, unsafe { libc::getegid() }),
            native_acl: false,
        };
        Self {
            root,
            path,
            parent,
            marker,
            lifetime,
            bytes,
            protection,
        }
    }
    fn attempt(&self) -> KernelRemovalAttempt {
        KernelRemovalAttempt::new(
            RemovalOriginal::capture(
                &self.parent,
                &self.marker,
                &self.path,
                &self.bytes,
                self.protection,
            )
            .unwrap(),
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn actual_unlink_keeps_same_readonly_original_inode_bytes_and_lifetime_with_two_syncs() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let f = Fixture::new();
    let mut a = f.attempt();
    let original = copy_stamp(&a.original.stamp);
    let fd = f.marker.as_raw_fd();
    let lifetime = FileStamp::of(&stat(&f.lifetime).unwrap());
    a.apply(&f.parent, &f.marker, &mut || Vec::new(), &mut sync)
        .unwrap();
    assert!(a.complete && !a.poisoned && a.record.attempted && a.record.verified);
    assert!(a.record.result == Some(Ok(())));
    assert!(!f.path.exists());
    assert_eq!(f.marker.as_raw_fd(), fd);
    assert_eq!(stat(&f.marker).unwrap().nlink(), 0);
    assert!(a.original.stamp == original);
    assert!(FileStamp::of(&stat(&f.lifetime).unwrap()) == lifetime);
    exact_bytes(&f.marker, &f.bytes).unwrap();
    assert_eq!(a.syncs.len(), 2);
    assert!(!a.syncs[0].parent && a.syncs[1].parent);
    assert!(a.syncs.iter().all(|s| s.error.is_none()));
    a.removed_current(&f.parent, &f.marker).unwrap();
    assert!(a
        .observations(&f.parent, &f.marker, &mut || Vec::new())
        .is_empty());
    // A software success is not an actual OwnedDenialRemoval proof.
    let ledger = DenialRemovalLedger::new();
    assert!(
        ledger.proof().is_none()
            && ledger.dedicated.is_none()
            && ledger.transition_failure.is_none()
    );
}
#[test]
fn same_real_os_lock_stays_exclusive_across_unlink_and_later_refusal_until_owner_drop() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let f = Fixture::new();
    let mut a = f.attempt();
    assert_eq!(
        unsafe { libc::flock(f.lifetime.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let contender = open(&f.root.join(STARTUP_LIFETIME_LEAF), false);
    assert_ne!(
        unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    a.apply(&f.parent, &f.marker, &mut || Vec::new(), &mut sync)
        .unwrap();
    assert_ne!(
        unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    assert!(a
        .apply(&f.parent, &f.marker, &mut || Vec::new(), &mut sync)
        .unwrap_err()
        .is("BIRTH_DENIAL_REMOVAL_NO_RETRY"));
    assert_ne!(
        unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    drop(f);
    assert_eq!(
        unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    // This is a real generic OS-lock owner, never ExclusiveStartupLease.
}
#[test]
fn fixed_marker_leaf_and_public_byte_bounds_refuse_without_an_effect() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let f = Fixture::new();
    for path in [
        f.root.join(STARTUP_LIFETIME_LEAF),
        f.root.join("foreign-marker"),
        f.root.join("UPGRADE-START-INHIBITION.json"),
    ] {
        assert!(
            RemovalOriginal::capture(&f.parent, &f.marker, &path, &f.bytes, f.protection).is_err()
        );
    }
    for bytes in [Vec::new(), vec![0; MAX_MARKER_BYTES + 1]] {
        assert!(
            RemovalOriginal::capture(&f.parent, &f.marker, &f.path, &bytes, f.protection).is_err()
        );
    }
    assert!(f.path.exists());
    assert_eq!(stat(&f.marker).unwrap().nlink(), 1);
}
#[test]
fn missing_replaced_symlinked_hardlinked_or_mutated_marker_never_becomes_owned_clear() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for kind in 0..6 {
        let f = Fixture::new();
        let mut a = f.attempt();
        match kind {
            0 => std::fs::remove_file(&f.path).unwrap(),
            1 => {
                std::fs::rename(&f.path, f.root.join("original")).unwrap();
                std::fs::write(&f.path, &f.bytes).unwrap();
            }
            2 => {
                std::fs::rename(&f.path, f.root.join("original")).unwrap();
                symlink(f.root.join("original"), &f.path).unwrap();
            }
            3 => std::fs::hard_link(&f.path, f.root.join("hardlink")).unwrap(),
            4 => {
                let mut bytes = f.bytes.clone();
                bytes[0] ^= 1;
                std::fs::write(&f.path, bytes).unwrap();
            }
            _ => std::fs::set_permissions(&f.path, std::fs::Permissions::from_mode(0o644)).unwrap(),
        }
        assert!(a
            .apply(&f.parent, &f.marker, &mut || Vec::new(), &mut sync)
            .is_err());
        assert!(!a.record.attempted && !a.complete && a.poisoned && a.removed.is_none());
        assert!(a.failure.is_some());
        assert_eq!(f.marker.as_raw_fd(), a.original.fd);
    }
}
#[test]
fn fd_flag_or_parent_metadata_drift_refuses_before_unlink_and_preserves_original() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for kind in 0..3 {
        let f = Fixture::new();
        let mut a = f.attempt();
        if kind == 0 {
            let status = unsafe { libc::fcntl(f.marker.as_raw_fd(), libc::F_GETFL) };
            assert!(
                unsafe {
                    libc::fcntl(
                        f.marker.as_raw_fd(),
                        libc::F_SETFL,
                        status & !libc::O_NONBLOCK,
                    )
                } >= 0
            );
        } else if kind == 1 {
            assert!(unsafe { libc::fcntl(f.marker.as_raw_fd(), libc::F_SETFD, 0) } >= 0);
        } else {
            std::fs::set_permissions(&f.root, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert!(a
            .apply(&f.parent, &f.marker, &mut || Vec::new(), &mut sync)
            .is_err());
        assert!(!a.record.attempted && a.poisoned && f.path.exists());
    }
}
#[test]
fn guard_refusal_before_and_after_actual_unlink_retains_primary_and_all_final_observations() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for after in [false, true] {
        let f = Fixture::new();
        let mut a = f.attempt();
        let error = a
            .apply(
                &f.parent,
                &f.marker,
                &mut || {
                    if !after || stat(&f.marker).unwrap().nlink() == 0 {
                        vec![err!(EACCES, "SOFTWARE_DENIAL_GUARD_LOST")]
                    } else {
                        Vec::new()
                    }
                },
                &mut sync,
            )
            .unwrap_err();
        assert!(error.is("SOFTWARE_DENIAL_GUARD_LOST"));
        assert_eq!(a.record.attempted, after);
        assert_eq!(stat(&f.marker).unwrap().nlink(), if after { 0 } else { 1 });
        let failure = a.failure.as_ref().unwrap();
        assert!(failure.error.is("SOFTWARE_DENIAL_GUARD_LOST"));
        assert!(failure
            .boundary_errors
            .iter()
            .any(|e| e.is("SOFTWARE_DENIAL_GUARD_LOST")));
        assert!(failure
            .final_errors
            .iter()
            .any(|e| e.is("SOFTWARE_DENIAL_GUARD_LOST")));
        assert!(a.poisoned && !a.complete && a.syncs.is_empty());
    }
}
#[test]
fn foreign_recreation_after_unlink_refuses_without_adopting_or_deleting_new_name() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let f = Fixture::new();
    let mut a = f.attempt();
    let injected = Cell::new(false);
    assert!(a
        .apply(
            &f.parent,
            &f.marker,
            &mut || {
                if !injected.get() && stat(&f.marker).unwrap().nlink() == 0 {
                    injected.set(true);
                    std::fs::write(&f.path, b"foreign successor").unwrap();
                }
                Vec::new()
            },
            &mut sync
        )
        .is_err());
    assert!(a.record.result == Some(Ok(())) && a.poisoned && !a.complete && a.record.verified);
    assert!(a.syncs.is_empty());
    assert_eq!(std::fs::read(&f.path).unwrap(), b"foreign successor");
    assert_ne!(
        stat(&f.marker).unwrap().ino(),
        std::fs::metadata(&f.path).unwrap().ino()
    );
    assert_eq!(stat(&f.marker).unwrap().nlink(), 0);
    exact_bytes(&f.marker, &f.bytes).unwrap();
    assert!(a
        .failure
        .as_ref()
        .unwrap()
        .final_errors
        .iter()
        .any(|e| e.is("BIRTH_DENIAL_NAME_PRESENT")));
}
#[test]
fn each_sync_fault_keeps_removed_original_and_exact_history_without_retry_or_rollback() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for failing in [0, 1] {
        let f = Fixture::new();
        let mut a = f.attempt();
        let calls = Cell::new(0);
        let error = a
            .apply(&f.parent, &f.marker, &mut || Vec::new(), &mut |file| {
                let index = calls.get();
                calls.set(index + 1);
                if index == failing {
                    Err(err!(EIO, "SOFTWARE_DENIAL_SYNC_FAULT"))
                } else {
                    sync(file)
                }
            })
            .unwrap_err();
        assert!(error.is("SOFTWARE_DENIAL_SYNC_FAULT"));
        assert_eq!(a.syncs.len(), failing + 1);
        assert!(
            a.record.verified
                && a.removed.is_some()
                && a.poisoned
                && !a.complete
                && !f.path.exists()
        );
        assert_eq!(stat(&f.marker).unwrap().nlink(), 0);
        let history = a.syncs.len();
        assert!(a
            .apply(&f.parent, &f.marker, &mut || Vec::new(), &mut sync)
            .unwrap_err()
            .is("BIRTH_DENIAL_REMOVAL_POISONED"));
        assert_eq!(a.syncs.len(), history);
        assert!(a
            .failure
            .as_ref()
            .unwrap()
            .error
            .is("SOFTWARE_DENIAL_SYNC_FAULT"));
    }
}
#[test]
fn late_final_refusal_preserves_durable_unlink_and_cannot_mint_a_native_proof() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let f = Fixture::new();
    let mut a = f.attempt();
    let syncs = Cell::new(0);
    let error = a
        .apply(
            &f.parent,
            &f.marker,
            &mut || {
                if syncs.get() == 2 {
                    vec![err!(EACCES, "SOFTWARE_DENIAL_LATE_FINAL_FAULT")]
                } else {
                    Vec::new()
                }
            },
            &mut |file| {
                sync(file)?;
                syncs.set(syncs.get() + 1);
                Ok(())
            },
        )
        .unwrap_err();
    assert!(error.is("SOFTWARE_DENIAL_LATE_FINAL_FAULT"));
    assert_eq!(a.syncs.len(), 2);
    assert!(a.record.verified && a.poisoned && !a.complete);
    assert_eq!(stat(&f.marker).unwrap().nlink(), 0);
    assert!(DenialRemovalLedger::new().proof().is_none());
}
#[test]
fn parent_link_projection_is_only_exact_single_entry_delta_and_never_a_native_proof() {
    parent_links_after(4, 4).unwrap();
    parent_links_after(4, 3).unwrap();
    for (before, after) in [(0, 0), (1, 0), (4, 5), (4, 2), (4, 1)] {
        assert!(parent_links_after(before, after).is_err());
    }
}

#[test]
fn ambiguous_reported_unlink_failure_keeps_original_history_and_never_installs_removal() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let f = Fixture::new();
    let mut a = f.attempt();
    a.ambiguous_unlink = true;
    let original = copy_stamp(&a.original.stamp);
    let fd = f.marker.as_raw_fd();
    assert!(a
        .apply(&f.parent, &f.marker, &mut || Vec::new(), &mut sync)
        .unwrap_err()
        .is("BIRTH_DENIAL_UNLINK_FAILED"));
    assert!(a.record.attempted && a.record.result == Some(Err(libc::EIO)) && !a.record.verified);
    assert!(a.removed.is_none() && !a.complete && a.poisoned && a.syncs.is_empty());
    assert!(a.original.stamp == original);
    assert_eq!(f.marker.as_raw_fd(), fd);
    assert_eq!(stat(&f.marker).unwrap().nlink(), 0);
    assert!(!f.path.exists());
    assert_eq!(a.record.held_after.as_ref().unwrap().links, 0);
    exact_bytes(&f.marker, &f.bytes).unwrap();
    let failure = a.failure.as_ref().unwrap();
    assert!(failure.error.is("BIRTH_DENIAL_UNLINK_FAILED"));
    assert!(!failure.final_errors.is_empty());
    let attempted = a.record.attempted;
    assert!(a
        .apply(&f.parent, &f.marker, &mut || Vec::new(), &mut sync)
        .is_err());
    assert_eq!(a.record.attempted, attempted);
    assert!(a.removed.is_none() && DenialRemovalLedger::new().proof().is_none());
}
#[test]
fn endpoint_refusal_after_slow_original_checks_prevents_actual_unlink_and_preserves_owner() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let f = Fixture::new();
    let mut a = f.attempt();
    let error = a
        .apply_with_endpoint(
            &f.parent,
            &f.marker,
            &mut || Vec::new(),
            &mut sync,
            &mut || Err(err!(EACCES, "SOFTWARE_DENIAL_FINAL_ENDPOINT")),
        )
        .unwrap_err();
    assert!(error.is("SOFTWARE_DENIAL_FINAL_ENDPOINT"));
    assert!(!a.record.attempted && a.syncs.is_empty() && a.poisoned && !a.complete);
    assert!(f.path.exists());
    assert_eq!(stat(&f.marker).unwrap().nlink(), 1);
    assert!(a
        .failure
        .as_ref()
        .unwrap()
        .final_errors
        .iter()
        .any(|error| error.is("SOFTWARE_DENIAL_FINAL_ENDPOINT")));
    assert!(DenialRemovalLedger::new().proof().is_none());
}
