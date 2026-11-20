//! SOFTWARE fixed-marker fault fixtures. Real local filesystem operations,
//! explicit synthetic owner/check callbacks; no native/root/checked target,
//! account, software release or maintenance authority is manufactured.
use super::*;
use std::{
    cell::Cell,
    os::unix::fs::{symlink, PermissionsExt},
    path::PathBuf,
};

struct Fixture {
    root: PathBuf,
    parent: File,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::current_dir().unwrap().join(format!(
            ".upgrade-denial-{}",
            hex::encode(enclave_core::rng::bytes32())
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let parent = File::open(&root).unwrap();
        Self { root, parent }
    }
    fn marker(&self) -> PathBuf {
        self.root.join(UPGRADE_INHIBITION_LEAF)
    }
    fn owner(&self) -> (u32, u32) {
        (unsafe { libc::geteuid() }, unsafe { libc::getegid() })
    }
    fn receipt(&self) -> UpgradeInhibitionReceipt {
        let mut result = UpgradeInhibitionReceipt::new("upgrade-fixture", &"a".repeat(64));
        result.artifact_inventory_sha256 = Some("b".repeat(64));
        result
    }
    fn run(
        &self,
        check: &mut impl FnMut() -> EnclaveResult<()>,
        sync: &mut impl FnMut(&File) -> EnclaveResult<()>,
    ) -> InhibitionResult {
        let mut receipt = self.receipt();
        let mut errors = Vec::new();
        let operation = publish_marker(
            &self.parent,
            &mut receipt,
            self.owner(),
            check,
            &mut errors,
            sync,
        );
        let final_binding = check();
        // Keep the actual created FD across every final binding observation,
        // exactly as the production owned entry does, then report only data.
        let final_marker = operation
            .as_ref()
            .map(|created| created.assert_current(&self.parent))
            .unwrap_or(Ok(()));
        let final_errors = [final_binding, final_marker]
            .into_iter()
            .filter_map(Result::err)
            .collect();
        finish_all(receipt, operation.map(|_| ()), final_errors, errors)
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
fn no_authority(receipt: &UpgradeInhibitionReceipt) {
    assert!(
        !receipt.mutation_allowed
            && !receipt.activation_allowed
            && !receipt.inactivity_proven
            && !receipt.installation_supported
            && !receipt.qualified
    );
}

#[test]
fn complete_marker_has_exact_closed_public_binding_and_file_then_parent_sync() {
    let f = Fixture::new();
    let mut synced = Vec::new();
    let result = f
        .run(&mut || Ok(()), &mut |file| {
            synced.push(file.metadata().unwrap().is_dir());
            sync(file)
        })
        .unwrap();
    assert_eq!(synced, vec![false, true]);
    assert!(
        result.complete
            && result.marker_created
            && result.file_synced
            && result.parent_synced
            && result.marker_verified
            && !result.uncertain_effects
    );
    assert!(!result.existing_marker_observed);
    no_authority(&result);
    let bytes = std::fs::read(f.marker()).unwrap();
    let marker: Marker = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(marker.version, 1);
    assert_eq!(marker.kind, KIND);
    assert_eq!(marker.target_id, "upgrade-fixture");
    assert_eq!(marker.descriptor_sha256, "a".repeat(64));
    assert_eq!(marker.artifact_inventory_sha256, "b".repeat(64));
    assert_eq!(bytes, marker_bytes(&f.receipt()).unwrap());
    let m = std::fs::metadata(f.marker()).unwrap();
    assert_eq!((m.uid(), m.gid()), f.owner());
    assert_eq!(m.mode() & 0o7777, 0o600);
    assert_eq!(m.nlink(), 1);
    let mut value = serde_json::to_value(marker).unwrap();
    value["resume"] = serde_json::json!(true);
    assert!(serde_json::from_value::<Marker>(value).is_err());
}
#[test]
fn guard_or_context_refusal_before_creation_has_no_marker_effect() {
    let f = Fixture::new();
    let calls = Cell::new(0);
    let error = f
        .run(
            &mut || {
                calls.set(calls.get() + 1);
                Err(err!(ESTALE, "FIXTURE_GUARD_LOST"))
            },
            &mut sync,
        )
        .unwrap_err();
    assert!(calls.get() >= 2);
    assert!(
        !error.receipt.creation_attempted
            && !error.receipt.marker_created
            && !error.receipt.uncertain_effects
            && !error.receipt.complete
    );
    assert!(!f.marker().exists());
    assert!(error.final_binding_error.unwrap().is("FIXTURE_GUARD_LOST"));
    no_authority(&error.receipt);
}
#[test]
fn binding_loss_immediately_after_create_keeps_empty_fixed_denial_name() {
    let f = Fixture::new();
    let calls = Cell::new(0);
    let error = f
        .run(
            &mut || {
                calls.set(calls.get() + 1);
                if calls.get() == 2 {
                    Err(err!(ESTALE, "FIXTURE_CHANGED"))
                } else {
                    Ok(())
                }
            },
            &mut sync,
        )
        .unwrap_err();
    assert!(error.error.is("FIXTURE_CHANGED"));
    assert_eq!(std::fs::read(f.marker()).unwrap(), b"");
    assert!(
        error.receipt.marker_created
            && error.receipt.uncertain_effects
            && !error.receipt.file_synced
            && !error.receipt.parent_synced
            && !error.receipt.complete
    );
    assert_eq!(calls.get(), 3);
    no_authority(&error.receipt);
}
#[test]
fn existing_exact_marker_is_refused_without_adoption_overwrite_or_sync() {
    let f = Fixture::new();
    let bytes = marker_bytes(&f.receipt()).unwrap();
    std::fs::write(f.marker(), &bytes).unwrap();
    let before = std::fs::metadata(f.marker()).unwrap();
    let error = f
        .run(&mut || Ok(()), &mut |_| {
            panic!("must not sync existing marker")
        })
        .unwrap_err();
    assert!(error.error.is("DEPLOYMENT_UPGRADE_INHIBITED"));
    assert!(error.receipt.existing_marker_observed);
    assert!(!error.receipt.marker_created && !error.receipt.complete);
    assert_eq!(std::fs::read(f.marker()).unwrap(), bytes);
    let after = std::fs::metadata(f.marker()).unwrap();
    assert_eq!((before.ino(), before.mode()), (after.ino(), after.mode()));
}
#[test]
fn foreign_symlink_fifo_directory_and_empty_names_are_preserved() {
    for kind in ["symlink", "fifo", "directory", "empty"] {
        let f = Fixture::new();
        std::fs::write(f.root.join("sentinel"), b"keep").unwrap();
        match kind {
            "symlink" => symlink(f.root.join("sentinel"), f.marker()).unwrap(),
            "fifo" => {
                use std::os::unix::ffi::OsStrExt;
                let name = CString::new(f.marker().as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
            "directory" => std::fs::create_dir(f.marker()).unwrap(),
            _ => std::fs::write(f.marker(), b"").unwrap(),
        }
        let before = std::fs::symlink_metadata(f.marker()).unwrap();
        let error = f
            .run(&mut || Ok(()), &mut |_| {
                panic!("existing name must never reach sync")
            })
            .unwrap_err();
        assert!(error.receipt.existing_marker_observed && !error.receipt.marker_created);
        let after = std::fs::symlink_metadata(f.marker()).unwrap();
        assert_eq!((before.ino(), before.mode()), (after.ino(), after.mode()));
        assert_eq!(std::fs::read(f.root.join("sentinel")).unwrap(), b"keep");
    }
}
#[test]
fn file_and_parent_sync_failures_leave_exact_marker_and_honest_progress() {
    for fail_at in [1, 2] {
        let f = Fixture::new();
        let calls = Cell::new(0);
        let error = f
            .run(&mut || Ok(()), &mut |file| {
                calls.set(calls.get() + 1);
                if calls.get() == fail_at {
                    Err(err!(EIO, "FIXTURE_SYNC_FAILED"))
                } else {
                    sync(file)
                }
            })
            .unwrap_err();
        assert!(error.error.is("FIXTURE_SYNC_FAILED"));
        assert_eq!(calls.get(), fail_at);
        assert_eq!(
            std::fs::read(f.marker()).unwrap(),
            marker_bytes(&f.receipt()).unwrap()
        );
        assert!(
            error.receipt.marker_created
                && error.receipt.uncertain_effects
                && !error.receipt.marker_verified
                && !error.receipt.complete
        );
        assert_eq!(error.receipt.file_synced, fail_at == 2);
        assert!(!error.receipt.parent_synced);
        no_authority(&error.receipt);
    }
}
#[test]
fn original_sync_error_and_simultaneous_boundary_final_errors_all_survive() {
    let f = Fixture::new();
    let calls = Cell::new(0);
    let error = f
        .run(
            &mut || {
                calls.set(calls.get() + 1);
                if calls.get() >= 7 {
                    Err(err!(ESTALE, "FIXTURE_BINDING_LOST"))
                } else {
                    Ok(())
                }
            },
            &mut |_| Err(err!(EIO, "FIXTURE_ORIGINAL_SYNC")),
        )
        .unwrap_err();
    assert!(error.error.is("FIXTURE_ORIGINAL_SYNC"));
    assert!(error
        .boundary_errors
        .iter()
        .any(|error| error.is("FIXTURE_BINDING_LOST")));
    assert!(error
        .final_binding_error
        .unwrap()
        .is("FIXTURE_BINDING_LOST"));
    assert!(f.marker().exists());
}
#[test]
fn replaced_named_inode_during_parent_sync_is_detected_without_foreign_cleanup() {
    let f = Fixture::new();
    let calls = Cell::new(0);
    let error = f
        .run(&mut || Ok(()), &mut |file| {
            calls.set(calls.get() + 1);
            sync(file)?;
            if calls.get() == 2 {
                std::fs::rename(f.marker(), f.root.join("original-denial")).unwrap();
                std::fs::write(f.marker(), b"foreign").unwrap();
            }
            Ok(())
        })
        .unwrap_err();
    assert!(
        !error.receipt.complete
            && error.receipt.file_synced
            && error.receipt.parent_synced
            && error.receipt.uncertain_effects
    );
    assert_eq!(std::fs::read(f.marker()).unwrap(), b"foreign");
    assert_eq!(
        std::fs::read(f.root.join("original-denial")).unwrap(),
        marker_bytes(&f.receipt()).unwrap()
    );
}
#[test]
fn final_binding_loss_clears_complete_without_erasing_confirmed_sync_progress() {
    let f = Fixture::new();
    let calls = Cell::new(0);
    let error = f
        .run(
            &mut || {
                calls.set(calls.get() + 1);
                if calls.get() == 10 {
                    Err(err!(ESTALE, "FIXTURE_FINAL_LOSS"))
                } else {
                    Ok(())
                }
            },
            &mut sync,
        )
        .unwrap_err();
    assert!(error.error.is("FIXTURE_FINAL_LOSS"));
    assert!(
        error.receipt.file_synced
            && error.receipt.parent_synced
            && error.receipt.marker_verified
            && !error.receipt.complete
            && error.receipt.uncertain_effects
    );
    no_authority(&error.receipt);
    assert_eq!(
        std::fs::read(f.marker()).unwrap(),
        marker_bytes(&f.receipt()).unwrap()
    );
}
#[test]
fn missing_inventory_or_noncanonical_digest_cannot_reach_creation() {
    let f = Fixture::new();
    let mut receipt = f.receipt();
    receipt.artifact_inventory_sha256 = None;
    assert!(marker_bytes(&receipt).is_err());
    receipt = f.receipt();
    receipt.descriptor_sha256 = "A".repeat(64);
    assert!(marker_bytes(&receipt).is_err());
    assert!(!f.marker().exists());
}
#[test]
fn native_constructor_requirement_has_no_unsupported_platform_fallback() {
    #[cfg(not(target_os = "macos"))]
    assert!(require_native_root()
        .unwrap_err()
        .is("UPGRADE_INHIBITION_NATIVE_ROOT_REQUIRED"));
    #[cfg(target_os = "macos")]
    if unsafe { libc::geteuid() } != 0 {
        assert!(require_native_root().is_err());
    }
}

#[test]
fn actual_created_descriptor_survives_engine_return_and_matching_replacement_cannot_be_adopted() {
    let f = Fixture::new();
    let mut receipt = f.receipt();
    let mut errors = Vec::new();
    let created = publish_marker(
        &f.parent,
        &mut receipt,
        f.owner(),
        &mut || Ok(()),
        &mut errors,
        &mut sync,
    )
    .unwrap();
    let original = created.file.metadata().unwrap();
    created.assert_current(&f.parent).unwrap();
    // Exact same bytes and protection are deliberately insufficient. The old
    // inode stays held so an identical new name cannot inherit its provenance.
    std::fs::rename(f.marker(), f.root.join("original-denial")).unwrap();
    std::fs::write(f.marker(), marker_bytes(&f.receipt()).unwrap()).unwrap();
    std::fs::set_permissions(f.marker(), std::fs::Permissions::from_mode(0o600)).unwrap();
    let replacement = std::fs::metadata(f.marker()).unwrap();
    assert_ne!(original.ino(), replacement.ino());
    assert!(created.assert_current(&f.parent).is_err());
    assert_eq!(created.file.metadata().unwrap().ino(), original.ino());
    assert_eq!(
        std::fs::metadata(f.marker()).unwrap().ino(),
        replacement.ino()
    );
    assert_eq!(std::fs::read(f.marker()).unwrap(), created.bytes);
    no_authority(&receipt);
}
#[test]
fn matching_replacement_during_final_binding_refuses_and_keeps_both_inodes() {
    let f = Fixture::new();
    let calls = Cell::new(0);
    let failure = f
        .run(
            &mut || {
                calls.set(calls.get() + 1);
                if calls.get() == 10 {
                    std::fs::rename(f.marker(), f.root.join("original-denial")).unwrap();
                    std::fs::write(f.marker(), marker_bytes(&f.receipt()).unwrap()).unwrap();
                    std::fs::set_permissions(f.marker(), std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                }
                Ok(())
            },
            &mut sync,
        )
        .unwrap_err();
    assert!(
        failure.receipt.file_synced
            && failure.receipt.parent_synced
            && failure.receipt.marker_verified
            && !failure.receipt.complete
            && failure.receipt.uncertain_effects
    );
    assert!(failure
        .final_binding_errors
        .iter()
        .any(|e| e.is("UPGRADE_INHIBITION_MARKER_CHANGED")));
    assert_ne!(
        std::fs::metadata(f.marker()).unwrap().ino(),
        std::fs::metadata(f.root.join("original-denial"))
            .unwrap()
            .ino()
    );
}
#[test]
fn all_independent_final_failures_survive_original_operation_refusal() {
    let f = Fixture::new();
    let receipt = f.receipt();
    let failure = finish_all(
        receipt,
        Err(err!(EIO, "FIXTURE_ORIGINAL")),
        vec![
            err!(ESTALE, "FIXTURE_CONTEXT"),
            err!(ESTALE, "FIXTURE_MARKER"),
            err!(EACCES, "FIXTURE_GUARD"),
        ],
        vec![err!(ESTALE, "FIXTURE_BOUNDARY")],
    )
    .unwrap_err();
    assert!(failure.error.is("FIXTURE_ORIGINAL"));
    assert_eq!(failure.final_binding_errors.len(), 3);
    assert!(failure.final_binding_error.unwrap().is("FIXTURE_CONTEXT"));
    assert!(
        failure.final_binding_errors[1].is("FIXTURE_MARKER")
            && failure.final_binding_errors[2].is("FIXTURE_GUARD")
    );
    assert!(failure.boundary_errors[0].is("FIXTURE_BOUNDARY"));
    no_authority(&failure.receipt);
}
#[test]
fn created_owner_flag_content_and_link_drift_are_refused_without_name_cleanup() {
    for change in [
        "cloexec", "nonblock", "content", "mode", "hardlink", "missing",
    ] {
        let f = Fixture::new();
        let mut receipt = f.receipt();
        let mut errors = Vec::new();
        let created = publish_marker(
            &f.parent,
            &mut receipt,
            f.owner(),
            &mut || Ok(()),
            &mut errors,
            &mut sync,
        )
        .unwrap();
        match change {
            "cloexec" => assert_eq!(
                unsafe { libc::fcntl(created.file.as_raw_fd(), libc::F_SETFD, 0) },
                0
            ),
            "nonblock" => assert_eq!(
                unsafe { libc::fcntl(created.file.as_raw_fd(), libc::F_SETFL, 0) },
                0
            ),
            "content" => {
                let mut bytes = created.bytes.clone();
                bytes[0] = b'[';
                std::fs::write(f.marker(), bytes).unwrap();
            }
            "mode" => std::fs::set_permissions(f.marker(), std::fs::Permissions::from_mode(0o644))
                .unwrap(),
            "hardlink" => std::fs::hard_link(f.marker(), f.root.join("alias")).unwrap(),
            _ => std::fs::remove_file(f.marker()).unwrap(),
        }
        let before = std::fs::symlink_metadata(f.marker()).ok();
        assert!(created.assert_current(&f.parent).is_err());
        let after = std::fs::symlink_metadata(f.marker()).ok();
        assert_eq!(
            before
                .as_ref()
                .map(|m| (m.ino(), m.mode(), m.len(), m.nlink())),
            after
                .as_ref()
                .map(|m| (m.ino(), m.mode(), m.len(), m.nlink()))
        );
    }
}
