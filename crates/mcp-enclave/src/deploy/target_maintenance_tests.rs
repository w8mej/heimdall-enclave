//! Private software fixture roots only. No test calls the native constructor on
//! macOS or creates the fixed host lock, changes a service, or claims inactivity.
use super::*;
use std::{
    os::unix::fs::{symlink, DirBuilderExt, PermissionsExt},
    path::PathBuf,
    sync::{Arc, Barrier},
};

struct Root {
    path: PathBuf,
    owner: Owner,
}
impl Root {
    fn new() -> Self {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!(
                "maintenance-fixture-{:x}",
                enclave_core::rng::u64()
            ));
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&path)
            .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        for child in ["a", "a/b"] {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(path.join(child))
                .unwrap();
        }
        Self {
            path: path.canonicalize().unwrap(),
            owner: Owner {
                uid: unsafe { libc::geteuid() },
                gid: unsafe { libc::getegid() },
            },
        }
    }
    fn parent(&self) -> PathBuf {
        self.path.join("a/b")
    }
    fn leaf(&self) -> PathBuf {
        self.parent().join(LOCK_LEAF)
    }
    fn ancestry(&self) -> EnclaveResult<Ancestry> {
        Ancestry::fixture(&self.path, &["a", "b"], self.owner)
    }
    fn acquire(&self) -> EnclaveResult<HostMaintenanceGuard> {
        HostMaintenanceGuard::acquire_ancestry(self.ancestry()?)
    }
    fn write(&self, bytes: &[u8], mode: u32) {
        std::fs::write(self.leaf(), bytes).unwrap();
        std::fs::set_permissions(self.leaf(), std::fs::Permissions::from_mode(mode)).unwrap();
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[test]
fn fixed_native_route_root_gate_and_no_platform_fallback_have_no_selected_path_inputs() {
    assert_eq!(NATIVE_PARENT, "/private/var/run");
    assert_eq!(LOCK_LEAF, "depot-deployment-maintenance.lock");
    assert!(require_root(0).is_ok());
    assert!(require_root(501)
        .unwrap_err()
        .is("MAINTENANCE_ROOT_REQUIRED"));
    #[cfg(not(target_os = "macos"))]
    assert!(HostMaintenanceGuard::acquire()
        .err()
        .unwrap()
        .is("MAINTENANCE_NATIVE_REQUIRED"));
}

#[test]
#[ignore = "requires a genuine nonroot pathname owner; shared workspace chown may report success without effect"]
fn full_path_nonroot_lock_owner_is_refused_only_after_observed_owner_transition() {
    // Production ownership predicate is exercised on a real non-root inode,
    // not on a neutral-owner fixture or a synthetic Metadata value. An anonymous
    // memfd would already fail nlink1, independently of the owner being tested.
    let root = Root::new();
    root.write(b"", 0o600);
    if unsafe { libc::geteuid() } == 0 {
        let leaf = name(root.leaf().as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(leaf.as_ptr(), 1, 1) }, 0);
    }
    let actual = std::fs::metadata(root.leaf()).unwrap();
    assert_ne!(actual.uid(), 0);
    assert!(actual.is_file());
    assert_eq!(actual.mode() & 0o7777, 0o600);
    assert_eq!(actual.nlink(), 1);
    assert_eq!(actual.len(), 0);
    // Match the genuinely observed GID so owner mismatch is the sole failing
    // metadata clause. The native production constructor always uses ROOT.
    assert!(!protected_lock(
        &actual,
        Owner {
            uid: 0,
            gid: actual.gid()
        }
    ));
    assert!(!protected_lock(&actual, Owner::ROOT));
}

#[test]
fn create_only_empty_lock_has_exact_metadata_and_persists_after_drop() {
    let root = Root::new();
    assert!(!root.leaf().exists());
    let mut guard = root.acquire().unwrap();
    guard.assert_held().unwrap();
    let held = std::fs::metadata(root.leaf()).unwrap();
    assert!(protected_lock(&held, root.owner));
    assert_eq!(
        unsafe { libc::fcntl(guard.file.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        libc::FD_CLOEXEC
    );
    assert!(std::fs::read_dir(root.parent())
        .unwrap()
        .all(|entry| entry.unwrap().file_name() == LOCK_LEAF));
    drop(guard);
    assert!(same_inode(&held, &std::fs::metadata(root.leaf()).unwrap()));
    root.acquire().unwrap().assert_held().unwrap();
}

#[test]
fn existing_lock_is_never_replaced_truncated_chmodded_or_unlinked() {
    let root = Root::new();
    root.write(b"", 0o600);
    let before = Stamp::of(&std::fs::metadata(root.leaf()).unwrap());
    {
        let mut guard = root.acquire().unwrap();
        guard.assert_held().unwrap();
    }
    assert!(before == Stamp::of(&std::fs::metadata(root.leaf()).unwrap()));
    for (bytes, mode) in [
        (b"preserve bytes".as_slice(), 0o600),
        (b"", 0o644),
        (b"", 0o660),
        (b"", 0o4600),
    ] {
        root.write(bytes, mode);
        let before = Stamp::of(&std::fs::metadata(root.leaf()).unwrap());
        assert!(root.acquire().is_err());
        assert_eq!(std::fs::read(root.leaf()).unwrap(), bytes);
        assert!(before == Stamp::of(&std::fs::metadata(root.leaf()).unwrap()));
    }
}

#[test]
fn symlink_hardlink_directory_and_fifo_locks_refuse_without_repair() {
    for kind in ["symlink", "hardlink", "directory", "fifo"] {
        let root = Root::new();
        let other = root.parent().join("other");
        std::fs::write(&other, b"preserve").unwrap();
        match kind {
            "symlink" => symlink(&other, root.leaf()).unwrap(),
            "hardlink" => std::fs::hard_link(&other, root.leaf()).unwrap(),
            "directory" => std::fs::create_dir(root.leaf()).unwrap(),
            "fifo" => {
                let leaf = name(root.leaf().as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(leaf.as_ptr(), 0o600) }, 0);
            }
            _ => unreachable!(),
        }
        let before = std::fs::symlink_metadata(root.leaf()).unwrap();
        assert!(root.acquire().is_err(), "{kind}");
        assert!(same_inode(
            &before,
            &std::fs::symlink_metadata(root.leaf()).unwrap()
        ));
        assert_eq!(std::fs::read(&other).unwrap(), b"preserve");
    }
}

#[test]
fn nonblocking_separate_open_contention_and_drop_release_keep_one_inode() {
    let root = Root::new();
    let first = root.acquire().unwrap();
    let before = stat(&first.file).unwrap();
    assert!(root.acquire().err().unwrap().is("MAINTENANCE_BUSY"));
    drop(first);
    let second = root.acquire().unwrap();
    assert!(same_inode(&before, &stat(&second.file).unwrap()));
}

#[test]
fn flock_excludes_another_process_using_a_fresh_open_file_description() {
    let root = Root::new();
    let guard = root.acquire().unwrap();
    let path = name(root.leaf().as_os_str().as_bytes()).unwrap();
    let inherited = guard.file.as_raw_fd();
    // Child performs only direct descriptor syscalls and _exit; it does not
    // run Rust destructors or use the allocator after a multithreaded fork.
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        unsafe {
            libc::close(inherited);
            let fd = libc::open(
                path.as_ptr(),
                libc::O_RDWR | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            );
            if fd < 0 {
                libc::_exit(2);
            }
            let status = libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB);
            #[cfg(target_os = "macos")]
            let lock_errno = *libc::__error();
            #[cfg(target_os = "linux")]
            let lock_errno = *libc::__errno_location();
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            let lock_errno = 0;
            // Only exact contention proves the other process was excluded. An
            // unrelated syscall failure must fail the fixture, never become PASS.
            libc::close(fd);
            libc::_exit(if status == -1 && lock_errno == libc::EWOULDBLOCK {
                0
            } else {
                1
            });
        }
    }
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(child, &mut status, 0) };
        if waited == child {
            break;
        }
        assert!(waited < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted);
    }
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
}

#[test]
fn concurrent_creators_never_replace_winner_or_acquire_two_guards() {
    let root = Root::new();
    let barrier = Arc::new(Barrier::new(8));
    let mut workers = Vec::new();
    for _ in 0..8 {
        let path = root.path.clone();
        let owner = root.owner;
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            HostMaintenanceGuard::acquire_ancestry(
                Ancestry::fixture(&path, &["a", "b"], owner).unwrap(),
            )
        }));
    }
    // Successful result remains alive in its JoinHandle/results while others
    // contend. A loser observing transient nlink2 may conservatively refuse.
    let results = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|value| value.is_ok()).count(), 1);
    let named = std::fs::metadata(root.leaf()).unwrap();
    assert!(protected_lock(&named, root.owner));
    for guard in results.iter().filter_map(|value| value.as_ref().ok()) {
        assert!(same_inode(&stat(&guard.file).unwrap(), &named));
    }
    drop(results);
    root.acquire().unwrap();
}

#[test]
fn interrupted_two_link_publication_refuses_without_automatic_repair() {
    let root = Root::new();
    let temporary = root.parent().join(".interrupted-own-temporary");
    std::fs::write(&temporary, b"").unwrap();
    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::hard_link(&temporary, root.leaf()).unwrap();
    let before = Stamp::of(&std::fs::metadata(root.leaf()).unwrap());
    assert_eq!(before.nlink, 2);
    assert!(root.acquire().is_err());
    assert!(before == Stamp::of(&std::fs::metadata(root.leaf()).unwrap()));
    assert!(temporary.exists());
}

#[test]
fn changed_named_lock_or_metadata_poison_guard_without_restoring_prior_state() {
    for change in ["replacement", "unlink", "mode", "bytes", "extra-link"] {
        let root = Root::new();
        let mut guard = root.acquire().unwrap();
        let held = root.parent().join("held-old");
        match change {
            "replacement" => {
                std::fs::rename(root.leaf(), &held).unwrap();
                root.write(b"replacement", 0o600);
            }
            "unlink" => std::fs::remove_file(root.leaf()).unwrap(),
            "mode" => std::fs::set_permissions(root.leaf(), std::fs::Permissions::from_mode(0o644))
                .unwrap(),
            "bytes" => std::fs::write(root.leaf(), b"changed").unwrap(),
            "extra-link" => std::fs::hard_link(root.leaf(), &held).unwrap(),
            _ => unreachable!(),
        }
        assert!(guard.assert_held().is_err(), "{change}");
        assert!(guard
            .assert_held()
            .unwrap_err()
            .is("MAINTENANCE_GUARD_POISONED"));
        if change == "replacement" {
            assert_eq!(std::fs::read(root.leaf()).unwrap(), b"replacement");
        }
    }
}

#[test]
fn ancestor_symlink_writability_or_replacement_refuses_before_or_during_hold() {
    for change in ["writable", "symlink"] {
        let root = Root::new();
        let parent = root.path.join("a");
        if change == "writable" {
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
        } else {
            std::fs::rename(&parent, root.path.join("original")).unwrap();
            symlink(root.path.join("original"), &parent).unwrap();
        }
        assert!(root.acquire().is_err());
        assert!(!root.leaf().exists());
    }
    let root = Root::new();
    let mut guard = root.acquire().unwrap();
    std::fs::rename(root.path.join("a"), root.path.join("original")).unwrap();
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(root.parent())
        .unwrap();
    assert!(guard.assert_held().is_err());
    assert!(!root.leaf().exists());
    assert!(root.path.join("original/b").join(LOCK_LEAF).exists());
    let root = Root::new();
    let mut guard = root.acquire().unwrap();
    std::fs::set_permissions(root.path.join("a"), std::fs::Permissions::from_mode(0o755)).unwrap();
    // Even a still-protected mode change invalidates the held ancestor stamp.
    assert!(guard.assert_held().is_err());
}

#[test]
fn failed_temporary_cleanup_never_unlinks_a_replacement_name() {
    let root = Root::new();
    let ancestry = root.ancestry().unwrap();
    let mut temporary = prepare(ancestry.parent(), root.owner).unwrap();
    let leaf = std::ffi::OsStr::from_bytes(temporary.leaf.as_bytes());
    let path = root.parent().join(leaf);
    let original = root.parent().join("held-private");
    std::fs::rename(&path, &original).unwrap();
    std::fs::write(&path, b"replacement").unwrap();
    assert!(temporary
        .unlink_own_temporary()
        .unwrap_err()
        .is("MAINTENANCE_TEMP_CHANGED"));
    drop(temporary);
    assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
    assert!(original.exists());
}
