//! SOFTWARE filesystem fixtures. Synthetic private ancestry only; no checked
//! deployment, native root, maintenance, release or activation capability.
use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::current_dir().unwrap().join(format!(
            ".upgrade-gate-{}",
            hex::encode(crate::rng::bytes32())
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        for child in ["support", "support/inner"] {
            let path = root.join(child);
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self { root }
    }
    fn parent(&self) -> PathBuf {
        self.root.join("support/inner")
    }
    fn marker(&self) -> PathBuf {
        self.parent().join(UPGRADE_INHIBITION_LEAF)
    }
    fn held(&self) -> Ancestry {
        for path in [self.root.clone(), self.root.join("support"), self.parent()] {
            let m = std::fs::metadata(path).unwrap();
            assert_eq!(m.uid(), unsafe { libc::geteuid() });
            assert_eq!(m.mode() & 0o7777, 0o700);
        }
        Ancestry::fixture(&self.root, &["support", "inner"]).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn confident_absence_is_read_only_and_missing_parent_never_becomes_absent_success() {
    let f = Fixture::new();
    let held = f.held();
    marker_absent(held.parent()).unwrap();
    held.current().unwrap();
    assert!(!f.marker().exists());
    assert!(Ancestry::fixture(&f.root, &["missing", "support"]).is_err());
    assert!(!f.root.join("missing").exists());
}
#[test]
fn all_present_bytes_including_empty_partial_unknown_and_apparent_completion_deny() {
    for bytes in [
        b"".as_slice(),
        b"{",
        b"null",
        b"{}",
        b"{\"complete\":true}",
        b"{\"version\":999}",
    ] {
        let f = Fixture::new();
        std::fs::write(f.marker(), bytes).unwrap();
        let before = std::fs::read(f.marker()).unwrap();
        assert!(marker_absent(f.held().parent())
            .unwrap_err()
            .is("DEPLOYMENT_UPGRADE_INHIBITED"));
        assert_eq!(std::fs::read(f.marker()).unwrap(), before);
    }
}
#[test]
fn symlink_and_dangling_symlink_names_deny_without_following_or_repair() {
    for dangling in [false, true] {
        let f = Fixture::new();
        let destination = f.root.join("sentinel");
        if !dangling {
            std::fs::write(&destination, b"sentinel").unwrap();
        }
        symlink(&destination, f.marker()).unwrap();
        assert!(marker_absent(f.held().parent())
            .unwrap_err()
            .is("DEPLOYMENT_UPGRADE_INHIBITED"));
        assert!(std::fs::symlink_metadata(f.marker())
            .unwrap()
            .file_type()
            .is_symlink());
        if !dangling {
            assert_eq!(std::fs::read(&destination).unwrap(), b"sentinel");
        } else {
            assert!(!destination.exists());
        }
    }
}
#[test]
fn fifo_directory_and_hardlinked_names_deny_without_open_or_changes() {
    for kind in ["fifo", "directory", "hardlink"] {
        let f = Fixture::new();
        match kind {
            "fifo" => {
                let name = CString::new(f.marker().as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
            "directory" => std::fs::create_dir(f.marker()).unwrap(),
            _ => {
                std::fs::write(f.root.join("sentinel"), b"untouched").unwrap();
                std::fs::hard_link(f.root.join("sentinel"), f.marker()).unwrap();
            }
        }
        let before = std::fs::symlink_metadata(f.marker()).unwrap();
        assert!(marker_absent(f.held().parent())
            .unwrap_err()
            .is("DEPLOYMENT_UPGRADE_INHIBITED"));
        let after = std::fs::symlink_metadata(f.marker()).unwrap();
        assert_eq!(
            (before.dev(), before.ino(), before.mode(), before.nlink()),
            (after.dev(), after.ino(), after.mode(), after.nlink())
        );
    }
}
#[test]
fn marker_permission_bits_do_not_change_presence_denial() {
    for mode in [0o000, 0o600, 0o644, 0o777] {
        let f = Fixture::new();
        std::fs::write(f.marker(), b"existing").unwrap();
        std::fs::set_permissions(f.marker(), std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(marker_absent(f.held().parent())
            .unwrap_err()
            .is("DEPLOYMENT_UPGRADE_INHIBITED"));
        assert_eq!(
            std::fs::symlink_metadata(f.marker()).unwrap().mode() & 0o777,
            mode
        );
    }
}
#[test]
fn nofollow_parent_symlink_and_unsafe_parent_modes_refuse() {
    let f = Fixture::new();
    symlink(f.parent(), f.root.join("alias")).unwrap();
    assert!(Ancestry::fixture(&f.root, &["alias"]).is_err());
    std::fs::set_permissions(
        f.root.join("support"),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    assert!(Ancestry::fixture(&f.root, &["support", "inner"]).is_err());
}
#[test]
fn held_ancestry_rejects_named_directory_replacement_and_symlink_substitution() {
    for symlink_replacement in [false, true] {
        let f = Fixture::new();
        let held = f.held();
        std::fs::rename(f.root.join("support"), f.root.join("old-support")).unwrap();
        if symlink_replacement {
            symlink(f.root.join("old-support"), f.root.join("support")).unwrap();
        } else {
            std::fs::create_dir(f.root.join("support")).unwrap();
        }
        assert!(held.current().is_err());
        assert!(marker_absent(held.parent()).is_ok()); // A raw detached FD alone is insufficient.
    }
}
#[test]
fn held_ancestry_rejects_permissions_drift_but_not_unrelated_new_public_entries() {
    let f = Fixture::new();
    let held = f.held();
    std::fs::write(f.parent().join("unrelated"), b"public").unwrap();
    held.current().unwrap();
    std::fs::set_permissions(f.parent(), std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(held.current().is_err());
}
#[test]
fn status_errors_cannot_be_interpreted_as_absence() {
    let f = Fixture::new();
    let regular = f.root.join("regular");
    std::fs::write(&regular, b"file").unwrap();
    assert!(marker_absent(&File::open(regular).unwrap())
        .unwrap_err()
        .is("UPGRADE_INHIBITION_STATUS_UNKNOWN"));
}

// These are real-kernel private engine fixtures only. No native root, checked
// target, genuine ExclusiveStartupLease, host guard or SOFTWARE owner is faked.
// A synthetic ordinary readonly File owns actual EX while the same production
// ancestry transition engine performs real fchmod/readback/fsync operations.
struct ModeFixture {
    fixture: Fixture,
    ancestry: Ancestry,
    lock: File,
}
impl ModeFixture {
    fn new() -> Self {
        let fixture = Fixture::new();
        let ancestry = fixture.held();
        let leaf = fixture.parent().join("synthetic-mode-lock");
        std::fs::write(&leaf, b"").unwrap();
        let lock = File::open(&leaf).unwrap();
        assert_eq!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        Self {
            fixture,
            ancestry,
            lock,
        }
    }
    fn owner(&self) -> (u32, u32) {
        (unsafe { libc::geteuid() }, unsafe { libc::getegid() })
    }
    fn path(&self) -> PathBuf {
        self.fixture.parent()
    }
    fn contended(&self) {
        let other = File::open(self.fixture.parent().join("synthetic-mode-lock")).unwrap();
        assert_eq!(
            unsafe { libc::flock(other.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            -1
        );
        let errno = std::io::Error::last_os_error().raw_os_error();
        assert!(errno == Some(libc::EAGAIN) || errno == Some(libc::EWOULDBLOCK));
    }
    fn run(
        &mut self,
        check: &mut impl FnMut(&File) -> Vec<crate::error::EnclaveError>,
        observed: &mut Vec<crate::error::EnclaveError>,
        sync: &mut impl FnMut(&File) -> EnclaveResult<()>,
    ) -> directory_mode::ModeOutcome {
        let path = self.path();
        let owner = self.owner();
        self.ancestry
            .change_original_mode(&path, owner, false, check, observed, sync)
    }
}
fn mode_sync(file: &File) -> EnclaveResult<()> {
    file.sync_all()
        .map_err(|_| err!(EIO, "SYNTHETIC_MODE_SYNC"))
}

#[test]
fn own_directory_mode_event_keeps_immutable_originals_and_readonly_fds_with_exact_delta() {
    let mut f = ModeFixture::new();
    let path = f.path();
    let before = std::fs::metadata(&path).unwrap();
    let fd = f.ancestry.nodes[2].file.as_raw_fd();
    let original = f.ancestry.nodes[2].stamp;
    let outcome = f.run(&mut |_| Vec::new(), &mut Vec::new(), &mut mode_sync);
    outcome.operation.unwrap();
    assert!(
        outcome.effect.syscall_attempted()
            && outcome.effect.syscall_succeeded()
            && outcome.effect.metadata_verified()
            && outcome.effect.durability_completed()
    );
    let event = outcome.change.unwrap();
    let after = std::fs::metadata(&path).unwrap();
    assert_eq!(
        (
            before.dev(),
            before.ino(),
            before.uid(),
            before.gid(),
            before.nlink()
        ),
        (
            after.dev(),
            after.ino(),
            after.uid(),
            after.gid(),
            after.nlink()
        )
    );
    assert_eq!(after.mode() & 0o7777, 0o755);
    assert_eq!(
        (before.mtime(), before.mtime_nsec()),
        (after.mtime(), after.mtime_nsec())
    );
    assert!(f.ancestry.nodes[2].stamp == original);
    assert_eq!(f.ancestry.nodes[2].file.as_raw_fd(), fd);
    assert!(f.ancestry.nodes[2].stamp.mode & 0o7777 == 0o700);
    f.ancestry.current().unwrap();
    f.contended();
    let named = open_child(
        &f.ancestry.nodes[1].file,
        f.ancestry.nodes[2].name.as_ref().unwrap(),
    )
    .unwrap();
    event
        .verify_recipient(
            &path,
            &f.ancestry.nodes[2].file,
            &named,
            event.before(),
            false,
        )
        .unwrap();
    assert!(event
        .verify_recipient(
            &path,
            &f.ancestry.nodes[2].file,
            &named,
            event.after(),
            false
        )
        .unwrap_err()
        .is("DIRECTORY_MODE_EVENT_ORIGINAL_MISMATCH"));
    let access = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    assert_eq!(access & libc::O_ACCMODE, libc::O_RDONLY);
    assert_ne!(access & libc::O_NONBLOCK, 0);
    assert_ne!(
        unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    let repeated = f.run(&mut |_| Vec::new(), &mut Vec::new(), &mut mode_sync);
    assert!(repeated
        .operation
        .unwrap_err()
        .is("DIRECTORY_MODE_EXTERNAL_OR_REPEATED"));
    assert!(!repeated.effect.syscall_attempted() && repeated.change.is_none());
    f.contended();
}

#[test]
fn pre_effect_guard_wrong_owner_mode_path_and_external_anchor_never_mutate_or_mint_event() {
    for variant in ["guard", "owner", "mode", "path", "external"] {
        let mut f = ModeFixture::new();
        let mut path = f.path();
        let mut owner = f.owner();
        if variant == "owner" {
            owner.0 = owner.0.wrapping_add(1);
        }
        if variant == "mode" {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o750)).unwrap();
            // A separately original synthetic750 node, never a product refresh.
            f.ancestry = Ancestry::fixture(&f.fixture.root, &["support", "inner"]).unwrap();
        }
        if variant == "path" {
            path = f.fixture.root.join("not-held");
        }
        if variant == "external" {
            path = f.fixture.root.clone();
        }
        let before = std::fs::metadata(f.path()).unwrap();
        let mut observed = Vec::new();
        let outcome = f.ancestry.change_original_mode(
            &path,
            owner,
            false,
            &mut |_| {
                if variant == "guard" {
                    vec![err!(EACCES, "SYNTHETIC_MODE_GUARD")]
                } else {
                    Vec::new()
                }
            },
            &mut observed,
            &mut mode_sync,
        );
        assert!(
            outcome.operation.is_err()
                && !outcome.effect.syscall_attempted()
                && outcome.change.is_none(),
            "{variant}"
        );
        let after = std::fs::metadata(f.path()).unwrap();
        assert_eq!(
            (before.dev(), before.ino(), before.mode()),
            (after.dev(), after.ino(), after.mode())
        );
        f.contended();
        assert!(!f.fixture.root.join("not-held").exists());
        if variant == "guard" {
            assert!(observed.iter().any(|e| e.is("SYNTHETIC_MODE_GUARD")));
        }
    }
}

#[test]
fn later_guard_and_sync_refusals_retain_actual_applied_event_overlay_and_original_lock() {
    for variant in ["guard", "sync"] {
        let mut f = ModeFixture::new();
        let path = f.path();
        let original = f.ancestry.nodes[2].stamp;
        let mut observed = Vec::new();
        let outcome = f.run(
            &mut |_| {
                if variant == "guard" && std::fs::metadata(&path).unwrap().mode() & 0o7777 == 0o755
                {
                    vec![err!(EACCES, "SYNTHETIC_MODE_POST_GATE")]
                } else {
                    Vec::new()
                }
            },
            &mut observed,
            &mut |file| {
                if variant == "sync" {
                    Err(err!(EIO, "SYNTHETIC_MODE_SYNC_REFUSED"))
                } else {
                    mode_sync(file)
                }
            },
        );
        let error = outcome.operation.unwrap_err();
        assert!(error.is(if variant == "guard" {
            "SYNTHETIC_MODE_POST_GATE"
        } else {
            "SYNTHETIC_MODE_SYNC_REFUSED"
        }));
        assert!(
            outcome.effect.syscall_succeeded()
                && outcome.effect.metadata_verified()
                && !outcome.effect.durability_completed()
        );
        let event = outcome
            .change
            .as_ref()
            .expect("verified own effect survives overall refusal");
        assert_eq!(event.before().mode & 0o7777, 0o700);
        assert_eq!(event.after().mode & 0o7777, 0o755);
        assert!(!event.durable());
        assert!(f.ancestry.nodes[2].stamp == original);
        f.ancestry.current().unwrap();
        f.contended();
        assert_eq!(f.lock.metadata().unwrap().len(), 0);
        assert_eq!(std::fs::metadata(path).unwrap().mode() & 0o7777, 0o755);
        if variant == "guard" {
            assert!(observed.iter().any(|e| e.is("SYNTHETIC_MODE_POST_GATE")));
        }
    }
}

#[test]
fn named_original_replacement_or_symlink_and_descriptor_flag_loss_refuse_without_adoption() {
    for variant in ["replace", "symlink", "flags"] {
        let mut f = ModeFixture::new();
        let path = f.path();
        let original = std::fs::metadata(&path).unwrap();
        let moved = f.fixture.root.join("detached-inner");
        if variant == "flags" {
            let fd = f.ancestry.nodes[2].file.as_raw_fd();
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert_eq!(
                unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
                0
            );
        } else {
            std::fs::rename(&path, &moved).unwrap();
            if variant == "symlink" {
                symlink(&moved, &path).unwrap();
            } else {
                std::fs::create_dir(&path).unwrap();
            }
        }
        let outcome = f.run(&mut |_| Vec::new(), &mut Vec::new(), &mut mode_sync);
        assert!(
            outcome.operation.is_err()
                && !outcome.effect.syscall_attempted()
                && outcome.change.is_none()
        );
        let held = f.ancestry.nodes[2].file.metadata().unwrap();
        assert_eq!(
            (held.dev(), held.ino(), held.mode()),
            (original.dev(), original.ino(), original.mode())
        );
        if variant != "flags" {
            let observer = File::open(moved.join("synthetic-mode-lock")).unwrap();
            assert_eq!(
                unsafe { libc::flock(observer.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
                -1
            );
            assert!(std::fs::symlink_metadata(&path).unwrap().ino() != original.ino());
        } else {
            f.contended();
        }
    }
}

#[test]
fn valid_event_refuses_wrong_recipient_and_later_foreign_metadata_without_rebaselining() {
    let mut f = ModeFixture::new();
    let path = f.path();
    let outcome = f.run(&mut |_| Vec::new(), &mut Vec::new(), &mut mode_sync);
    outcome.operation.unwrap();
    let event = outcome.change.unwrap();
    let node = &f.ancestry.nodes[2];
    let named = open_child(&f.ancestry.nodes[1].file, node.name.as_ref().unwrap()).unwrap();
    assert!(event
        .verify_recipient(&f.fixture.root, &node.file, &named, event.before(), false)
        .is_err());
    assert!(event
        .verify_recipient(
            &path,
            &f.ancestry.nodes[1].file,
            &named,
            event.before(),
            false
        )
        .is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o750)).unwrap();
    assert!(event
        .verify_recipient(&path, &node.file, &named, event.before(), false)
        .is_err());
    assert!(f.ancestry.current().is_err());
    assert_eq!(event.after().mode & 0o7777, 0o755);
    f.contended();
}

#[test]
fn retained_mode_outcome_keeps_actual_applied_event_and_kernel_ex_until_refusal_drop() {
    for variant in ["sync", "final"] {
        let mut f = ModeFixture::new();
        let path = f.path();
        let original = f.ancestry.nodes[2].stamp;
        let observer = File::open(path.join("synthetic-mode-lock")).unwrap();
        let mut observed = Vec::new();
        let outcome = f.run(&mut |_| Vec::new(), &mut observed, &mut |file| {
            if variant == "sync" {
                Err(err!(EIO, "SYNTHETIC_MODE_PRIMARY_SYNC"))
            } else {
                mode_sync(file)
            }
        });
        let final_errors = vec![
            err!(ESTALE, "SYNTHETIC_MODE_FINAL_FIRST"),
            err!(EACCES, "SYNTHETIC_MODE_FINAL_SECOND"),
        ];
        let refusal = directory_mode::resolve_retained(
            f,
            outcome.operation,
            observed,
            final_errors,
            Some(outcome.effect),
            outcome.change,
        )
        .err()
        .expect("actual final failure retains original owner");
        assert!(refusal.error.is(if variant == "sync" {
            "SYNTHETIC_MODE_PRIMARY_SYNC"
        } else {
            "SYNTHETIC_MODE_FINAL_FIRST"
        }));
        assert_eq!(refusal.final_errors.len(), 2);
        assert!(refusal.change.is_some());
        assert!(refusal.effect.as_ref().unwrap().metadata_verified());
        assert!(refusal.owner.ancestry.nodes[2].stamp == original);
        refusal.owner.contended();
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o7777, 0o755);
        // These pure fixture probes do not forge a native EX or retry a
        // failed product capability. Observe only the actual kernel owner.
        assert_eq!(
            unsafe { libc::flock(observer.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) },
            -1
        );
        drop(refusal);
        assert_eq!(
            unsafe { libc::flock(observer.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
    }
}

#[test]
fn real_chmod_followed_by_unproven_metadata_or_name_never_mints_overlay_or_event() {
    for variant in ["mode", "replacement"] {
        let mut f = ModeFixture::new();
        let path = f.path();
        let original = f.ancestry.nodes[2].stamp;
        let moved = f.fixture.root.join("actual-original-after-chmod");
        let mut observed = Vec::new();
        let outcome = f.ancestry.fixture_mode_post_syscall(
            &path,
            &mut || {
                if variant == "mode" {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o750))
                        .unwrap();
                } else {
                    std::fs::rename(&path, &moved).unwrap();
                    std::fs::create_dir(&path).unwrap();
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                        .unwrap();
                }
            },
            &mut observed,
        );
        assert!(
            outcome.operation.is_err()
                && outcome.effect.syscall_attempted()
                && outcome.effect.syscall_succeeded()
        );
        assert!(
            !outcome.effect.metadata_verified()
                && !outcome.effect.durability_completed()
                && outcome.change.is_none()
        );
        assert!(f.ancestry.nodes[2].mode_change.is_none() && f.ancestry.nodes[2].stamp == original);
        assert!(!observed.is_empty());
        assert!(f.ancestry.current().is_err());
        let held = f.ancestry.nodes[2].file.metadata().unwrap();
        assert_eq!((held.dev(), held.ino()), (original.dev, original.ino));
        let lock = if variant == "mode" {
            path.join("synthetic-mode-lock")
        } else {
            moved.join("synthetic-mode-lock")
        };
        let observer = File::open(lock).unwrap();
        assert_eq!(
            unsafe { libc::flock(observer.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            -1
        );
        // Real unknown/partial effects remain in place; neither original nor
        // foreign replacement metadata is restored, removed or adopted.
        assert_eq!(
            held.mode() & 0o7777,
            if variant == "mode" { 0o750 } else { 0o755 }
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn native_acl_readonly_directory_syscall_and_full_sync_engine_without_native_capability() {
    let mut f = ModeFixture::new();
    let path = f.path();
    let owner = f.owner();
    let outcome = f.ancestry.change_original_mode(
        &path,
        owner,
        true,
        &mut |_| Vec::new(),
        &mut Vec::new(),
        &mut crate::fsutil::full_fsync,
    );
    outcome.operation.unwrap();
    assert!(outcome.effect.durability_completed());
    let event = outcome.change.unwrap();
    let node = &f.ancestry.nodes[2];
    let named = open_child(&f.ancestry.nodes[1].file, node.name.as_ref().unwrap()).unwrap();
    event
        .verify_recipient(&path, &node.file, &named, event.before(), true)
        .unwrap();
    f.contended();
    // Actual Darwin ACL/FD/sync mechanism only; no genuine public native/root
    // EX, checked target, birth, software approval or installation is supplied.
}
