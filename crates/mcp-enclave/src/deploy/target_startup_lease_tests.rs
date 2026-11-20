//! Ordinary SOFTWARE fixtures of private create/verification/error engines.
//! No fixture constructs a native context, checked target, guard, approval,
//! account admission, owned native marker or exclusive startup capability.
use super::*;
use enclave_core::deployment::upgrade::UPGRADE_INHIBITION_LEAF;
use std::{
    cell::Cell,
    os::unix::{
        ffi::OsStrExt,
        fs::{symlink, PermissionsExt},
    },
    path::PathBuf,
};

struct Fixture {
    root: PathBuf,
    parent: File,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::current_dir().unwrap().join(format!(
            ".native-startup-preparation-{}",
            hex::encode(enclave_core::rng::bytes32())
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let parent = File::open(&root).unwrap();
        Self { root, parent }
    }
    fn leaf(&self) -> PathBuf {
        self.root.join(STARTUP_LIFETIME_LEAF)
    }
    fn marker(&self) -> PathBuf {
        self.root.join(UPGRADE_INHIBITION_LEAF)
    }
    fn owner(&self) -> (u32, u32) {
        (unsafe { libc::geteuid() }, unsafe { libc::getegid() })
    }
    fn progress(&self) -> StartupLeaseProgress {
        StartupLeaseProgress::new("fixture", &"a".repeat(64))
    }
    fn run(
        &self,
        check: &mut impl FnMut() -> Vec<EnclaveError>,
        sync: &mut impl FnMut(&File) -> EnclaveResult<()>,
    ) -> Result<StartupLeaseProgress, StartupLeaseFailure> {
        let mut progress = self.progress();
        let mut boundary_errors = Vec::new();
        let operation = create_leaf(
            &self.parent,
            &mut progress,
            self.owner(),
            check,
            &mut boundary_errors,
            sync,
        );
        let finals = check();
        outcome(&mut progress, operation, boundary_errors, finals)?;
        Ok(progress)
    }
    fn existing(&self, bytes: &[u8], mode: u32) {
        std::fs::write(self.leaf(), bytes).unwrap();
        std::fs::set_permissions(self.leaf(), std::fs::Permissions::from_mode(mode)).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn sync(file: &File) -> EnclaveResult<()> {
    file.sync_all().map_err(|_| err!(EIO, "FIXTURE_SYNC"))
}
fn no_authority(progress: &StartupLeaseProgress) {
    assert!(
        !progress.mutation_allowed
            && !progress.activation_allowed
            && !progress.inactivity_proven
            && !progress.installation_supported
            && !progress.qualified
    );
}

#[test]
fn permanent_leaf_is_zero_single_link0644_and_syncs_file_then_parent() {
    let f = Fixture::new();
    let calls = Cell::new(0);
    let progress = f
        .run(&mut || Vec::new(), &mut |file| {
            calls.set(calls.get() + 1);
            let metadata = file.metadata().unwrap();
            if calls.get() == 1 {
                assert!(metadata.is_file());
            } else {
                assert_eq!(calls.get(), 2);
                assert!(metadata.is_dir());
            }
            sync(file)
        })
        .unwrap();
    assert!(
        progress.creation_attempted
            && !progress.existing_lease_observed
            && progress.lease_created
            && progress.protection_verified
            && progress.file_synced
            && progress.parent_synced
            && progress.lease_verified
            && progress.complete
            && !progress.uncertain_effects
    );
    assert_eq!(calls.get(), 2);
    no_authority(&progress);
    let metadata = std::fs::symlink_metadata(f.leaf()).unwrap();
    assert!(metadata.is_file());
    assert_eq!((metadata.uid(), metadata.gid()), f.owner());
    assert_eq!(
        (metadata.mode() & 0o7777, metadata.len(), metadata.nlink()),
        (0o644, 0, 1)
    );
    let file = open_fixed(&f.parent, STARTUP_LIFETIME_LEAF).unwrap();
    stamp(&file, f.owner(), 0o644, 0).unwrap();
    assert!(!f.marker().exists());
}
#[test]
fn preexisting_exact_leaf_is_refused_without_adoption_metadata_or_sync() {
    let f = Fixture::new();
    f.existing(b"", 0o644);
    let before = std::fs::symlink_metadata(f.leaf()).unwrap();
    let failure = f
        .run(&mut || Vec::new(), &mut |_| {
            panic!("existing leaf cannot reach sync")
        })
        .unwrap_err();
    assert!(failure.error.is("STARTUP_PREPARATION_ALREADY_EXISTS"));
    assert!(
        failure.progress.creation_attempted
            && failure.progress.existing_lease_observed
            && !failure.progress.lease_created
            && !failure.progress.complete
            && !failure.progress.uncertain_effects
    );
    let after = std::fs::symlink_metadata(f.leaf()).unwrap();
    assert_eq!(
        (
            before.ino(),
            before.mode(),
            before.ctime(),
            before.ctime_nsec()
        ),
        (after.ino(), after.mode(), after.ctime(), after.ctime_nsec())
    );
    no_authority(&failure.progress);
}
#[test]
fn every_existing_foreign_name_type_is_preserved_and_never_opened_or_synced() {
    for kind in [
        "partial",
        "symlink",
        "dangling",
        "fifo",
        "directory",
        "hardlink",
        "mode",
    ] {
        let f = Fixture::new();
        let sentinel = f.root.join("sentinel");
        std::fs::write(&sentinel, b"keep").unwrap();
        match kind {
            "symlink" => symlink(&sentinel, f.leaf()).unwrap(),
            "dangling" => symlink(f.root.join("missing"), f.leaf()).unwrap(),
            "fifo" => {
                let name = CString::new(f.leaf().as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
            "directory" => std::fs::create_dir(f.leaf()).unwrap(),
            "hardlink" => std::fs::hard_link(&sentinel, f.leaf()).unwrap(),
            "mode" => f.existing(b"", 0o666),
            _ => f.existing(b"partial", 0o600),
        }
        let before = std::fs::symlink_metadata(f.leaf()).unwrap();
        let failure = f
            .run(&mut || Vec::new(), &mut |_| {
                panic!("must not sync foreign entry")
            })
            .unwrap_err();
        assert!(failure.progress.existing_lease_observed && !failure.progress.lease_created);
        let after = std::fs::symlink_metadata(f.leaf()).unwrap();
        assert_eq!(
            (before.ino(), before.mode(), before.len(), before.nlink()),
            (after.ino(), after.mode(), after.len(), after.nlink())
        );
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"keep");
        no_authority(&failure.progress);
    }
}
#[test]
fn every_binding_boundary_refusal_preserves_new_names_and_honest_progress() {
    for fail_at in 1..=8 {
        let f = Fixture::new();
        let calls = Cell::new(0);
        let failure = f
            .run(
                &mut || {
                    calls.set(calls.get() + 1);
                    if calls.get() == fail_at {
                        vec![err!(ESTALE, "FIXTURE_BOUNDARY_LOST")]
                    } else {
                        Vec::new()
                    }
                },
                &mut sync,
            )
            .unwrap_err();
        assert!(failure.error.is("FIXTURE_BOUNDARY_LOST"));
        assert!(failure
            .boundary_errors
            .iter()
            .any(|e| e.is("FIXTURE_BOUNDARY_LOST")));
        assert_eq!(f.leaf().exists(), fail_at > 1);
        assert_eq!(failure.progress.lease_created, fail_at > 1);
        assert_eq!(failure.progress.uncertain_effects, fail_at > 1);
        assert!(!failure.progress.complete);
        no_authority(&failure.progress);
    }
}
#[test]
fn newly_created_leaf_after_immediate_binding_loss_is_retained_without_metadata_repair() {
    let f = Fixture::new();
    let calls = Cell::new(0);
    let failure = f
        .run(
            &mut || {
                calls.set(calls.get() + 1);
                if calls.get() == 2 {
                    vec![err!(ESTALE, "FIXTURE_GUARD_LOST")]
                } else {
                    Vec::new()
                }
            },
            &mut |_| panic!("post-create binding refusal must precede sync"),
        )
        .unwrap_err();
    assert!(
        failure.progress.lease_created
            && !failure.progress.protection_verified
            && !failure.progress.file_synced
            && !failure.progress.parent_synced
            && failure.progress.uncertain_effects
    );
    let metadata = std::fs::symlink_metadata(f.leaf()).unwrap();
    assert_eq!(metadata.len(), 0);
    assert_eq!(
        metadata.mode() & 0o077,
        0,
        "initial exclusive name is never created world-readable before protection"
    );
}
#[test]
fn file_or_parent_sync_failure_retains_leaf_and_completed_sync_prefix() {
    for fail_at in [1, 2] {
        let f = Fixture::new();
        let calls = Cell::new(0);
        let failure = f
            .run(&mut || Vec::new(), &mut |file| {
                calls.set(calls.get() + 1);
                if calls.get() == fail_at {
                    Err(err!(EIO, "FIXTURE_SYNC_FAILED"))
                } else {
                    sync(file)
                }
            })
            .unwrap_err();
        assert!(failure.error.is("FIXTURE_SYNC_FAILED"));
        assert_eq!(calls.get(), fail_at);
        assert!(
            failure.progress.lease_created
                && failure.progress.protection_verified
                && failure.progress.uncertain_effects
        );
        assert_eq!(failure.progress.file_synced, fail_at == 2);
        assert!(
            !failure.progress.parent_synced
                && !failure.progress.lease_verified
                && !failure.progress.complete
        );
        assert_eq!(std::fs::metadata(f.leaf()).unwrap().len(), 0);
        no_authority(&failure.progress);
    }
}
#[test]
fn original_error_all_boundary_errors_and_final_errors_are_preserved_together() {
    let f = Fixture::new();
    let calls = Cell::new(0);
    let failure = f
        .run(
            &mut || {
                calls.set(calls.get() + 1);
                if calls.get() >= 6 {
                    vec![
                        err!(ESTALE, "FIXTURE_CONTEXT_LOST"),
                        err!(EACCES, "FIXTURE_GUARD_LOST"),
                    ]
                } else {
                    Vec::new()
                }
            },
            &mut |_| Err(err!(EIO, "FIXTURE_ORIGINAL_SYNC")),
        )
        .unwrap_err();
    assert!(failure.error.is("FIXTURE_ORIGINAL_SYNC"));
    assert_eq!(failure.boundary_errors.len(), 2);
    assert_eq!(failure.final_errors.len(), 2);
    assert!(
        failure.boundary_errors[0].is("FIXTURE_CONTEXT_LOST")
            && failure.boundary_errors[1].is("FIXTURE_GUARD_LOST")
    );
    assert!(
        failure.final_errors[0].is("FIXTURE_CONTEXT_LOST")
            && failure.final_errors[1].is("FIXTURE_GUARD_LOST")
    );
    assert!(f.leaf().exists() && failure.progress.uncertain_effects);
    no_authority(&failure.progress);
}
#[test]
fn final_binding_failure_clears_complete_but_keeps_confirmed_sync_and_verification() {
    let f = Fixture::new();
    let calls = Cell::new(0);
    let failure = f
        .run(
            &mut || {
                calls.set(calls.get() + 1);
                if calls.get() == 9 {
                    vec![err!(ESTALE, "FIXTURE_FINAL_LOSS")]
                } else {
                    Vec::new()
                }
            },
            &mut sync,
        )
        .unwrap_err();
    assert!(failure.error.is("FIXTURE_FINAL_LOSS"));
    assert_eq!(calls.get(), 9);
    assert!(
        failure.progress.file_synced
            && failure.progress.parent_synced
            && failure.progress.lease_verified
            && !failure.progress.complete
            && failure.progress.uncertain_effects
    );
    no_authority(&failure.progress);
}
#[test]
fn named_inode_replacement_after_sync_is_detected_without_foreign_cleanup() {
    let f = Fixture::new();
    let calls = Cell::new(0);
    let failure = f
        .run(&mut || Vec::new(), &mut |file| {
            calls.set(calls.get() + 1);
            sync(file)?;
            if calls.get() == 2 {
                std::fs::rename(f.leaf(), f.root.join("original")).unwrap();
                f.existing(b"foreign", 0o644);
            }
            Ok(())
        })
        .unwrap_err();
    assert!(
        !failure.progress.complete
            && failure.progress.file_synced
            && failure.progress.parent_synced
            && failure.progress.uncertain_effects
    );
    assert_eq!(std::fs::read(f.leaf()).unwrap(), b"foreign");
    assert_eq!(std::fs::read(f.root.join("original")).unwrap(), b"");
}
#[test]
fn post_sync_protection_drift_is_refused_without_repair() {
    let f = Fixture::new();
    let calls = Cell::new(0);
    let failure = f
        .run(&mut || Vec::new(), &mut |file| {
            calls.set(calls.get() + 1);
            sync(file)?;
            if calls.get() == 2 {
                std::fs::set_permissions(f.leaf(), std::fs::Permissions::from_mode(0o666)).unwrap();
            }
            Ok(())
        })
        .unwrap_err();
    assert!(failure.error.is("STARTUP_PREPARATION_PROTECTION"));
    assert_eq!(std::fs::metadata(f.leaf()).unwrap().mode() & 0o7777, 0o666);
    assert!(failure.progress.uncertain_effects && !failure.progress.complete);
    no_authority(&failure.progress);
}
#[test]
fn create_failure_without_confirmed_inode_retains_uncertainty() {
    let f = Fixture::new();
    let regular = f.root.join("not-a-directory");
    std::fs::write(&regular, b"keep").unwrap();
    let parent = File::open(&regular).unwrap();
    let mut progress = f.progress();
    let mut boundary = Vec::new();
    let operation = create_leaf(
        &parent,
        &mut progress,
        f.owner(),
        &mut || Vec::new(),
        &mut boundary,
        &mut sync,
    );
    let failure = outcome(&mut progress, operation, boundary, Vec::new()).unwrap_err();
    assert!(failure.error.is("STARTUP_PREPARATION_CREATE_UNCERTAIN"));
    assert!(
        failure.progress.creation_attempted
            && !failure.progress.lease_created
            && !failure.progress.existing_lease_observed
            && failure.progress.uncertain_effects
    );
    assert_eq!(std::fs::read(regular).unwrap(), b"keep");
    assert!(!f.leaf().exists());
}
#[test]
fn writable_or_missing_nonblock_and_cloexec_flags_cannot_become_held_bindings() {
    let f = Fixture::new();
    f.existing(b"", 0o644);
    let name = CString::new(STARTUP_LIFETIME_LEAF).unwrap();
    for flags in [
        libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
        libc::O_RDONLY | libc::O_CLOEXEC,
        libc::O_RDONLY | libc::O_NONBLOCK,
    ] {
        let fd = unsafe {
            libc::openat(
                f.parent.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW,
            )
        };
        assert!(fd >= 0);
        let file = unsafe { File::from_raw_fd(fd) };
        assert!(stamp(&file, f.owner(), 0o644, 0).is_err());
    }
}
#[test]
fn reporting_completed_preparation_or_exclusion_never_creates_any_authority() {
    let f = Fixture::new();
    let mut progress = f.progress();
    progress.lease_created = true;
    progress.exclusive_acquired = true;
    outcome(&mut progress, Ok(()), Vec::new(), Vec::new()).unwrap();
    assert!(progress.complete);
    no_authority(&progress);
    let bytes = serde_json::to_value(&progress).unwrap();
    for key in [
        "mutation_allowed",
        "activation_allowed",
        "inactivity_proven",
        "installation_supported",
        "qualified",
    ] {
        assert_eq!(bytes[key], false);
    }
}
#[test]
fn completed_maintenance_callback_then_binding_loss_preserves_effect_uncertainty() {
    let f = Fixture::new();
    let mut progress = f.progress();
    progress.maintenance_operations_attempted = 1;
    let failure = outcome(
        &mut progress,
        Ok(()),
        Vec::new(),
        vec![err!(ESTALE, "FIXTURE_FINAL_LOSS")],
    )
    .unwrap_err();
    assert!(failure.progress.uncertain_effects && !failure.progress.complete);
    assert!(!failure.progress.maintenance_operation_failed);
    no_authority(&failure.progress);
}
#[test]
fn native_requirement_has_no_unsupported_or_nonroot_fallback() {
    #[cfg(not(target_os = "macos"))]
    assert!(require_native_root()
        .unwrap_err()
        .is("STARTUP_PREPARATION_NATIVE_ROOT_REQUIRED"));
    #[cfg(target_os = "macos")]
    if unsafe { libc::geteuid() } != 0 {
        assert!(require_native_root().is_err());
    }
}
