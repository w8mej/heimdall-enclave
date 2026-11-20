//! Actual local directory-FD primitives only. No checked target, guard, native
//! session, signature verifier or installation capability is constructed.
use super::*;
use std::os::unix::fs::{symlink, DirBuilderExt, PermissionsExt};

struct Fixture {
    path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let path = std::env::current_dir().unwrap().join(format!(
            ".intent-console-{}",
            hex::encode(enclave_core::rng::bytes32())
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self { path }
    }
    fn parent(&self) -> File {
        let name = CString::new(self.path.as_os_str().as_bytes()).unwrap();
        opened(unsafe {
            libc::open(
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC,
            )
        })
        .unwrap()
    }
    fn leaf(&self) -> PathBuf {
        self.path.join("12345")
    }
    fn kernel(&self) -> KernelDirectory {
        KernelDirectory::new(
            self.parent(),
            self.leaf(),
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
        )
        .unwrap()
    }
    fn existing(&self, mode: u32) {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(self.leaf())
            .unwrap();
        std::fs::set_permissions(self.leaf(), std::fs::Permissions::from_mode(mode)).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[test]
fn exact_existing_directory_is_observed_with_no_metadata_or_durability_writes() {
    let fixture = Fixture::new();
    fixture.existing(0o2710);
    let before = stamp(&std::fs::symlink_metadata(fixture.leaf()).unwrap());
    let mut kernel = fixture.kernel();
    kernel.advance().unwrap();
    kernel.current().unwrap();
    assert_eq!(kernel.phase, Phase::Complete);
    assert!(kernel.receipt.existing_exact);
    assert!(
        !kernel.receipt.mkdir.attempted
            && !kernel.receipt.chown.attempted
            && !kernel.receipt.chmod.attempted
    );
    assert!(!kernel.receipt.child_sync.attempted && !kernel.receipt.parent_sync.attempted);
    assert_eq!(
        before,
        stamp(&std::fs::symlink_metadata(fixture.leaf()).unwrap())
    );
    assert!(
        !kernel.receipt.complete,
        "kernel-only fixture cannot certify native completion"
    );
}

#[test]
fn wrong_mode_existing_inode_and_contents_are_preserved_on_refusal() {
    let fixture = Fixture::new();
    fixture.existing(0o700);
    std::fs::write(fixture.leaf().join("preserve"), b"original").unwrap();
    let before = stamp(&std::fs::symlink_metadata(fixture.leaf()).unwrap());
    let mut kernel = fixture.kernel();
    assert!(kernel
        .advance()
        .unwrap_err()
        .is("INTENT_DIRECTORY_EXISTING_METADATA"));
    assert!(kernel.child.is_some() && kernel.original.is_some());
    assert!(kernel.failed);
    assert_eq!(
        before,
        stamp(&std::fs::symlink_metadata(fixture.leaf()).unwrap())
    );
    assert_eq!(
        std::fs::read(fixture.leaf().join("preserve")).unwrap(),
        b"original"
    );
    assert!(
        !kernel.receipt.mkdir.attempted
            && !kernel.receipt.chown.attempted
            && !kernel.receipt.chmod.attempted
    );
}

#[test]
fn symlink_and_regular_file_are_never_adopted_or_repaired() {
    for link in [false, true] {
        let fixture = Fixture::new();
        let outside = fixture.path.join("outside");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&outside)
            .unwrap();
        if link {
            symlink(&outside, fixture.leaf()).unwrap();
        } else {
            std::fs::write(fixture.leaf(), b"preserve-file").unwrap();
        }
        let before = stamp(&std::fs::symlink_metadata(fixture.leaf()).unwrap());
        let mut kernel = fixture.kernel();
        assert!(kernel.advance().is_err());
        assert_eq!(
            before,
            stamp(&std::fs::symlink_metadata(fixture.leaf()).unwrap())
        );
        assert!(!kernel.receipt.mkdir.attempted && !kernel.receipt.chown.attempted);
        if !link {
            assert_eq!(std::fs::read(fixture.leaf()).unwrap(), b"preserve-file");
        }
    }
}

#[test]
fn absent_numeric_leaf_is_created_and_only_same_original_fd_metadata_is_changed() {
    let fixture = Fixture::new();
    let sibling = fixture.path.join("untouched");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&sibling)
        .unwrap();
    let sibling_before = stamp(&std::fs::metadata(&sibling).unwrap());
    let mut kernel = fixture.kernel();
    kernel.advance().unwrap();
    assert_eq!(kernel.phase, Phase::Absent);
    kernel.advance().unwrap();
    assert_eq!(kernel.phase, Phase::Opened);
    let original = kernel.original.clone().unwrap();
    let fd = kernel.child.as_ref().unwrap().as_raw_fd();
    while kernel.phase != Phase::Complete {
        kernel.advance().unwrap();
    }
    kernel.current().unwrap();
    let final_m = directory_stat(kernel.child.as_ref().unwrap()).unwrap();
    assert_eq!(
        (
            final_m.dev(),
            final_m.ino(),
            kernel.child.as_ref().unwrap().as_raw_fd()
        ),
        (original.dev, original.ino, fd)
    );
    assert_eq!(
        (final_m.uid(), final_m.gid(), final_m.mode() & 0o7777),
        (
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            0o2710
        )
    );
    for step in [
        &kernel.receipt.mkdir,
        &kernel.receipt.chown,
        &kernel.receipt.chmod,
        &kernel.receipt.child_sync,
        &kernel.receipt.parent_sync,
    ] {
        assert!(step.attempted);
        assert_eq!(step.returned_success, Some(true));
    }
    assert_eq!(kernel.original.as_ref(), Some(&original));
    assert_eq!(sibling_before, stamp(&std::fs::metadata(&sibling).unwrap()));
    assert!(!kernel.receipt.existing_exact && !kernel.receipt.complete);
}

#[test]
fn name_appearing_after_absence_never_becomes_an_adopted_existing_leaf() {
    let fixture = Fixture::new();
    let mut kernel = fixture.kernel();
    kernel.advance().unwrap();
    fixture.existing(0o2710);
    let before = stamp(&std::fs::metadata(fixture.leaf()).unwrap());
    assert!(kernel
        .advance()
        .unwrap_err()
        .is("INTENT_DIRECTORY_APPEARED"));
    assert!(kernel.failed && !kernel.receipt.existing_exact && !kernel.receipt.mkdir.attempted);
    assert_eq!(before, stamp(&std::fs::metadata(fixture.leaf()).unwrap()));
}

#[test]
fn actual_eexist_return_after_probe_is_retained_without_adoption_or_chown() {
    let fixture = Fixture::new();
    let mut kernel = fixture.kernel();
    kernel.advance().unwrap();
    // Actual race at the last gate/syscall boundary. This invokes only the
    // private kernel primitive, never the native gated constructor.
    fixture.existing(0o2710);
    let before = stamp(&std::fs::metadata(fixture.leaf()).unwrap());
    assert!(kernel
        .advance_after_native_gate()
        .unwrap_err()
        .is("INTENT_DIRECTORY_CREATE_UNCERTAIN"));
    assert!(kernel.receipt.mkdir.attempted);
    assert_eq!(kernel.receipt.mkdir.returned_success, Some(false));
    assert_eq!(kernel.receipt.mkdir.errno, Some(libc::EEXIST));
    assert!(
        kernel.failed
            && kernel.child.is_none()
            && !kernel.receipt.existing_exact
            && !kernel.receipt.chown.attempted
    );
    assert_eq!(before, stamp(&std::fs::metadata(fixture.leaf()).unwrap()));
}

#[test]
fn created_inode_replacement_is_not_mutated_and_original_is_retained() {
    let fixture = Fixture::new();
    let mut kernel = fixture.kernel();
    kernel.advance().unwrap();
    kernel.advance().unwrap();
    let original = kernel.original.clone().unwrap();
    let moved = fixture.path.join("original-moved");
    std::fs::rename(fixture.leaf(), &moved).unwrap();
    fixture.existing(0o700);
    let replacement = stamp(&std::fs::metadata(fixture.leaf()).unwrap());
    assert!(kernel.advance().unwrap_err().is("INTENT_DIRECTORY_CHANGED"));
    assert!(!kernel.receipt.chown.attempted);
    assert_eq!(kernel.original.as_ref(), Some(&original));
    assert_eq!(
        replacement,
        stamp(&std::fs::metadata(fixture.leaf()).unwrap())
    );
    assert_eq!(original.ino, std::fs::metadata(moved).unwrap().ino());
}

#[test]
fn named_unlink_refuses_even_if_detached_held_directory_link_count_stays_positive() {
    let fixture = Fixture::new();
    let mut kernel = fixture.kernel();
    kernel.advance().unwrap();
    kernel.advance().unwrap();
    std::fs::remove_dir(fixture.leaf()).unwrap();
    assert!(kernel.advance().is_err());
    assert!(
        kernel.receipt.mkdir.attempted && !kernel.receipt.chown.attempted && kernel.child.is_some()
    );
    assert!(!kernel.receipt.complete);
}

#[test]
fn mode_or_fd_flag_changes_poison_without_advancing_syscall_history() {
    for change_mode in [false, true] {
        let fixture = Fixture::new();
        let mut kernel = fixture.kernel();
        kernel.advance().unwrap();
        kernel.advance().unwrap();
        let original = kernel.original.clone().unwrap();
        if change_mode {
            std::fs::set_permissions(fixture.leaf(), std::fs::Permissions::from_mode(0o750))
                .unwrap();
        } else {
            let fd = kernel.child.as_ref().unwrap().as_raw_fd();
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            assert!(flags >= 0);
            assert_eq!(
                unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) },
                0
            );
        }
        assert!(kernel.advance().is_err());
        assert!(kernel.failed && !kernel.receipt.chown.attempted);
        assert_eq!(kernel.original.as_ref(), Some(&original));
        // A transient condition recovering cannot authorize a second attempt.
        if change_mode {
            std::fs::set_permissions(
                fixture.leaf(),
                std::fs::Permissions::from_mode(original.mode & 0o7777),
            )
            .unwrap();
        } else {
            let fd = kernel.child.as_ref().unwrap().as_raw_fd();
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            assert!(flags >= 0);
            assert_eq!(
                unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
                0
            );
        }
        kernel.current().unwrap();
        assert!(kernel
            .advance()
            .unwrap_err()
            .is("INTENT_DIRECTORY_ATTEMPT_POISONED"));
        assert!(
            !kernel.receipt.chown.attempted
                && !kernel.receipt.chmod.attempted
                && !kernel.receipt.complete
        );
    }
}

#[test]
fn late_boundary_refusal_does_not_erase_actual_successful_metadata_prefix() {
    let fixture = Fixture::new();
    let mut kernel = fixture.kernel();
    for _ in 0..4 {
        kernel.advance().unwrap();
    } // probe, mkdir, chown, chmod
    assert_eq!(kernel.phase, Phase::Chmodded);
    std::fs::set_permissions(fixture.leaf(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(kernel.advance().is_err());
    assert_eq!(kernel.receipt.mkdir.returned_success, Some(true));
    assert_eq!(kernel.receipt.chown.returned_success, Some(true));
    assert_eq!(kernel.receipt.chmod.returned_success, Some(true));
    assert!(
        !kernel.receipt.child_sync.attempted
            && !kernel.receipt.parent_sync.attempted
            && !kernel.receipt.complete
    );
    let output = serde_json::to_string(&kernel.receipt).unwrap();
    assert!(output.contains("INTENT_DIRECTORY_CHANGED"));
}

#[cfg(not(target_os = "macos"))]
#[test]
fn unavailable_platform_never_manufactures_native_console_identity() {
    assert!(native_session()
        .unwrap_err()
        .is("INTENT_DIRECTORY_NATIVE_REQUIRED"));
}

// Genuine native approval/guard/current Aqua UID+AuditID, original package/code
// verification, distinct UID:8703 creation, injected native ACL/session/marker/
// guard/deadline failures and actual fixed launchctl/helper reciprocal IPC must
// be exercised by the coordinator's authorized protected host procedure.
// These ordinary local-FD tests establish none of those native capabilities.
