//! Actual OS-lock SOFTWARE fixtures in repository-private roots. Child stdio
//! pipes carry only fixed synthetic commands/status. No native/root/checked
//! deployment, host-guard, inactivity or installation capability is fabricated.
use super::*;
use std::{
    cell::Cell,
    io::{Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{symlink, PermissionsExt},
    },
    path::PathBuf,
    process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

struct Fixture {
    root: PathBuf,
    parent: File,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::current_dir().unwrap().join(format!(
            ".startup-lease-{}",
            hex::encode(crate::rng::bytes32())
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let parent = File::open(&root).unwrap();
        let result = Self { root, parent };
        result.provision_fixture();
        result
    }
    fn leaf(&self) -> PathBuf {
        self.root.join(STARTUP_LIFETIME_LEAF)
    }
    fn marker(&self) -> PathBuf {
        self.root.join(UPGRADE_INHIBITION_LEAF)
    }
    fn owner(&self) -> Owner {
        Owner {
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        }
    }
    fn provision_fixture(&self) {
        // Synthetic test provisioning only. Product never creates this leaf.
        let file = File::options()
            .write(true)
            .create_new(true)
            .open(self.leaf())
            .unwrap();
        file.set_permissions(std::fs::Permissions::from_mode(0o644))
            .unwrap();
        let m = file.metadata().unwrap();
        assert_eq!((m.uid(), m.gid()), (self.owner().uid, self.owner().gid));
    }
    fn inhibit(&self) {
        std::fs::write(self.marker(), b"SYNTHETIC DENIAL ONLY\n").unwrap();
    }
    fn acquire(&self, lock: Lock) -> EnclaveResult<LeaseFile> {
        acquire(&self.parent, self.owner(), lock, &mut || Ok(()))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct Process {
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
    finished: bool,
}
impl Process {
    fn spawn(fixture: &Fixture, role: &str) -> Self {
        let name = format!(
            "{}::lease_subprocess",
            module_path!().split_once("::").unwrap().1
        );
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &name,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("MCPMAC_STARTUP_LEASE_TEST_ROLE", role)
            .env("MCPMAC_STARTUP_LEASE_TEST_ROOT", &fixture.root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        Self {
            child,
            input,
            output,
            finished: false,
        }
    }
    fn send(&mut self, value: &str) {
        self.input.write_all(value.as_bytes()).unwrap();
        self.input.flush().unwrap();
    }
    fn expect(&mut self, want: &str) {
        let until = Instant::now() + Duration::from_secs(5);
        let mut line = Vec::new();
        let mut total = 0;
        loop {
            assert!(Instant::now() < until, "synthetic child status timeout");
            let mut poll = libc::pollfd {
                fd: self.output.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let n = unsafe { libc::poll(&mut poll, 1, 20) };
            assert!(n >= 0, "synthetic child poll failure");
            if n == 0 {
                continue;
            }
            let mut byte = [0u8; 1];
            let n = self.output.read(&mut byte).unwrap();
            assert_ne!(n, 0, "synthetic child ended before expected status");
            total += n;
            assert!(total < 16 * 1024, "synthetic child output bound");
            if byte[0] == b'\n' {
                let value = String::from_utf8(std::mem::take(&mut line)).unwrap();
                if value.ends_with(want) {
                    return;
                }
            } else {
                line.push(byte[0]);
            }
        }
    }
    fn finish(&mut self) -> ExitStatus {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                self.finished = true;
                return status;
            }
            assert!(
                Instant::now() < until,
                "synthetic child did not exit; Drop attempts bounded cleanup"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let _ = self.child.kill();
        let until = Instant::now() + Duration::from_secs(2);
        while Instant::now() < until {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        eprintln!("synthetic startup child cleanup unconfirmed");
    }
}
fn command() -> String {
    let mut value = String::new();
    std::io::stdin().read_line(&mut value).unwrap();
    value
}
fn status(value: &str) {
    println!("LEASE_STATUS:{value}");
    std::io::stdout().flush().unwrap();
}

#[test]
fn retained_observation_uses_same_lock_and_poison_survives_restored_marker() {
    let fixture = Fixture::new();
    let mut retained = Retained {
        owner: fixture.acquire(Lock::Shared).unwrap(),
        poisoned: false,
    };
    let original = retained.owner.file.as_raw_fd();
    retained
        .check_deadline(Instant::now() + Duration::from_secs(2), |file| {
            file.assert_current(&fixture.parent)?;
            marker(&fixture.parent, false)
        })
        .unwrap();
    assert_eq!(retained.owner.file.as_raw_fd(), original);
    fixture.inhibit();
    assert!(retained
        .check_deadline(Instant::now() + Duration::from_secs(2), |file| {
            file.assert_current(&fixture.parent)?;
            marker(&fixture.parent, false)
        })
        .is_err());
    std::fs::remove_file(fixture.marker()).unwrap();
    assert!(retained
        .check_deadline(Instant::now() + Duration::from_secs(2), |_| Ok(()))
        .is_err());
    assert_eq!(retained.owner.file.as_raw_fd(), original);
    assert!(
        fixture.acquire(Lock::DedicatedExclusive).is_err(),
        "poison must retain the actual SH lock"
    );
}

#[test]
fn retained_observation_expired_endpoint_never_invokes_check_or_revives() {
    let fixture = Fixture::new();
    let mut retained = Retained {
        owner: fixture.acquire(Lock::Shared).unwrap(),
        poisoned: false,
    };
    let called = Cell::new(false);
    assert!(retained
        .check_deadline(Instant::now(), |_| {
            called.set(true);
            Ok(())
        })
        .is_err());
    assert!(!called.get());
    assert!(retained
        .check_deadline(Instant::now() + Duration::from_secs(2), |_| {
            called.set(true);
            Ok(())
        })
        .is_err());
    assert!(!called.get());
    assert!(fixture.acquire(Lock::DedicatedExclusive).is_err());
}

#[test]
fn retained_observation_late_success_poison_keeps_original_lock() {
    let fixture = Fixture::new();
    let mut retained = Retained {
        owner: fixture.acquire(Lock::Shared).unwrap(),
        poisoned: false,
    };
    let deadline = Instant::now() + Duration::from_millis(10);
    assert!(retained
        .check_deadline(deadline, |_| {
            while Instant::now() < deadline {
                std::thread::yield_now();
            }
            Ok(())
        })
        .unwrap_err()
        .is("STARTUP_LEASE_OBSERVATION_DEADLINE"));
    assert!(retained.poisoned);
    assert!(fixture.acquire(Lock::DedicatedExclusive).is_err());
}

// Invoked only as an exact subprocess with explicit synthetic fixture args.
#[test]
#[ignore = "private subprocess helper; coordinator runs parent tests"]
fn lease_subprocess() {
    let role = std::env::var("MCPMAC_STARTUP_LEASE_TEST_ROLE").expect("explicit synthetic role");
    let root = PathBuf::from(
        std::env::var_os("MCPMAC_STARTUP_LEASE_TEST_ROOT").expect("explicit synthetic root"),
    );
    let parent = File::open(&root).unwrap();
    let owner = Owner {
        uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getegid() },
    };
    match role.as_str() {
        "shared" | "poison" => {
            let file = acquire(&parent, owner, Lock::Shared, &mut || Ok(())).unwrap();
            let mut retained = Retained {
                owner: file,
                poisoned: false,
            };
            status("READY");
            if role == "poison" {
                assert_eq!(command(), "POISON\n");
                assert!(retained
                    .check(|file| {
                        file.assert_current(&parent)?;
                        marker(&parent, false)
                    })
                    .is_err());
                assert!(retained.poisoned);
                status("POISONED");
                // Later marker disappearance must not revive the owner.
                assert_eq!(command(), "RECHECK\n");
                assert!(retained
                    .check(|_| Ok(()))
                    .unwrap_err()
                    .is("STARTUP_LEASE_POISONED"));
                status("STILL_POISONED");
            }
            assert_eq!(command(), "EXIT\n");
            // Actual field stays owned through final child effects, not just
            // the successful startup method's stack frame.
            assert!(retained.owner.file.metadata().is_ok());
            status("EXITING");
        }
        "delayed" => {
            marker(&parent, false).unwrap();
            status("OLD_ADMISSION");
            assert_eq!(command(), "CONTINUE\n");
            assert!(acquire(&parent, owner, Lock::Shared, &mut || Ok(())).is_err());
            status("DENIED_BEFORE_EFFECT");
        }
        "retained-exclusive-refusal" => {
            let calls = Cell::new(0);
            let failure = acquire_retained(&parent, owner, Lock::Exclusive, &mut || {
                calls.set(calls.get() + 1);
                if calls.get() == 3 {
                    Err(err!(ESTALE, "SYNTHETIC_POST_LOCK_REFUSAL"))
                } else {
                    Ok(())
                }
            })
            .err()
            .expect("actual post-lock refusal");
            assert!(failure.acquired && failure.file.is_some());
            assert!(failure.error.is("SYNTHETIC_POST_LOCK_REFUSAL"));
            status("REFUSED_EX_HELD");
            assert_eq!(command(), "RECHECK\n");
            failure
                .file
                .as_ref()
                .unwrap()
                .assert_current(&parent)
                .unwrap();
            assert!(failure.error.is("SYNTHETIC_POST_LOCK_REFUSAL"));
            status("REFUSAL_STILL_HELD");
            assert_eq!(command(), "EXIT\n");
            // The actual refusal owner, not a replacement lease or success
            // receipt, stays alive through all remaining subprocess effects.
            assert!(failure.file.as_ref().unwrap().file.metadata().is_ok());
            status("EXITING");
        }
        "unleased" => {
            status("READY_UNLEASED");
            assert_eq!(command(), "EXIT\n");
        }
        _ => panic!("unknown synthetic role"),
    }
}

#[test]
fn shared_actor_blocks_other_process_exclusion_until_actual_child_exit() {
    let fixture = Fixture::new();
    let mut child = Process::spawn(&fixture, "shared");
    child.expect("LEASE_STATUS:READY");
    fixture.inhibit();
    assert!(fixture
        .acquire(Lock::Exclusive)
        .err()
        .unwrap()
        .is("STARTUP_LEASE_BUSY"));
    child.send("EXIT\n");
    assert!(child.finish().success());
    let exclusive = fixture.acquire(Lock::Exclusive).unwrap();
    exclusive.assert_current(&fixture.parent).unwrap();
    assert!(fixture.marker().exists());
    assert_eq!(std::fs::metadata(fixture.leaf()).unwrap().len(), 0);
}
#[test]
fn delayed_old_absence_admission_cannot_initialize_after_marker_and_exclusion() {
    let fixture = Fixture::new();
    let mut child = Process::spawn(&fixture, "delayed");
    child.expect("LEASE_STATUS:OLD_ADMISSION");
    fixture.inhibit();
    let exclusive = fixture.acquire(Lock::Exclusive).unwrap();
    child.send("CONTINUE\n");
    child.expect("LEASE_STATUS:DENIED_BEFORE_EFFECT");
    assert!(child.finish().success());
    exclusive.assert_current(&fixture.parent).unwrap();
    assert!(fixture.marker().exists());
}
#[test]
fn poisoned_retained_shared_owner_blocks_exclusion_until_process_exit_and_cannot_revive() {
    let fixture = Fixture::new();
    let mut child = Process::spawn(&fixture, "poison");
    child.expect("LEASE_STATUS:READY");
    fixture.inhibit();
    child.send("POISON\n");
    child.expect("LEASE_STATUS:POISONED");
    assert!(fixture
        .acquire(Lock::Exclusive)
        .err()
        .unwrap()
        .is("STARTUP_LEASE_BUSY"));
    std::fs::remove_file(fixture.marker()).unwrap();
    child.send("RECHECK\n");
    child.expect("LEASE_STATUS:STILL_POISONED");
    fixture.inhibit();
    assert!(fixture
        .acquire(Lock::Exclusive)
        .err()
        .unwrap()
        .is("STARTUP_LEASE_BUSY"));
    child.send("EXIT\n");
    assert!(child.finish().success());
    assert!(fixture.acquire(Lock::Exclusive).is_ok());
}
#[test]
fn two_cooperating_processes_hold_independent_shared_leases() {
    let fixture = Fixture::new();
    let mut first = Process::spawn(&fixture, "shared");
    first.expect("LEASE_STATUS:READY");
    let mut second = Process::spawn(&fixture, "shared");
    second.expect("LEASE_STATUS:READY");
    fixture.inhibit();
    assert!(fixture.acquire(Lock::Exclusive).is_err());
    first.send("EXIT\n");
    assert!(first.finish().success());
    assert!(fixture.acquire(Lock::Exclusive).is_err());
    second.send("EXIT\n");
    assert!(second.finish().success());
    assert!(fixture.acquire(Lock::Exclusive).is_ok());
}
#[test]
fn cloexec_does_not_leak_the_lease_into_unrelated_exec_child() {
    let fixture = Fixture::new();
    let actor = fixture.acquire(Lock::Shared).unwrap();
    let flags = unsafe { libc::fcntl(actor.file.as_raw_fd(), libc::F_GETFD) };
    assert_ne!(flags & libc::FD_CLOEXEC, 0);
    let mut child = Process::spawn(&fixture, "unleased");
    child.expect("LEASE_STATUS:READY_UNLEASED");
    drop(actor);
    fixture.inhibit();
    let exclusive = fixture.acquire(Lock::Exclusive).unwrap();
    child.send("EXIT\n");
    assert!(child.finish().success());
    exclusive.assert_current(&fixture.parent).unwrap();
}
#[test]
fn duplicate_os_descriptor_keeps_shared_lock_until_last_private_fixture_owner_closes() {
    let fixture = Fixture::new();
    let actor = fixture.acquire(Lock::Shared).unwrap();
    let duplicate = actor.file.try_clone().unwrap();
    drop(actor);
    fixture.inhibit();
    assert!(fixture.acquire(Lock::Exclusive).is_err());
    drop(duplicate);
    assert!(fixture.acquire(Lock::Exclusive).is_ok());
}
#[test]
fn marker_publication_at_every_shared_acquisition_boundary_refuses_before_actor_effect() {
    for publish_at in 1..=4 {
        let fixture = Fixture::new();
        let calls = Cell::new(0);
        let result = acquire(&fixture.parent, fixture.owner(), Lock::Shared, &mut || {
            calls.set(calls.get() + 1);
            if calls.get() == publish_at {
                fixture.inhibit();
            }
            Ok(())
        });
        assert!(result.is_err());
        assert!(calls.get() >= publish_at);
        assert!(fixture.marker().exists());
        // Failed initial admission owns no lifetime service effect or stale SH.
        assert!(fixture.acquire(Lock::Exclusive).is_ok());
    }
}
#[test]
fn exclusive_requires_existing_marker_and_refuses_marker_loss_after_lock() {
    let fixture = Fixture::new();
    assert!(fixture
        .acquire(Lock::Exclusive)
        .err()
        .unwrap()
        .is("STARTUP_LEASE_INHIBITION_REQUIRED"));
    fixture.inhibit();
    let calls = Cell::new(0);
    assert!(acquire(
        &fixture.parent,
        fixture.owner(),
        Lock::Exclusive,
        &mut || {
            calls.set(calls.get() + 1);
            if calls.get() == 3 {
                std::fs::remove_file(fixture.marker()).unwrap();
            }
            Ok(())
        }
    )
    .is_err());
    assert!(fixture.acquire(Lock::Shared).is_ok());
}
#[test]
fn all_named_marker_types_deny_shared_without_opening_or_repairing_them() {
    for kind in ["empty", "partial", "directory", "symlink", "fifo"] {
        let fixture = Fixture::new();
        match kind {
            "empty" => std::fs::write(fixture.marker(), b"").unwrap(),
            "partial" => std::fs::write(fixture.marker(), b"{").unwrap(),
            "directory" => std::fs::create_dir(fixture.marker()).unwrap(),
            "symlink" => symlink(fixture.root.join("missing"), fixture.marker()).unwrap(),
            _ => {
                let name = CString::new(fixture.marker().as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
        }
        let before = std::fs::symlink_metadata(fixture.marker()).unwrap();
        assert!(fixture.acquire(Lock::Shared).is_err());
        // Core EX only observes denial presence. Foreign bytes are never native
        // transaction authority, and are not opened/adopted/repaired here.
        assert!(fixture.acquire(Lock::Exclusive).is_ok());
        let after = std::fs::symlink_metadata(fixture.marker()).unwrap();
        assert_eq!(
            (before.dev(), before.ino(), before.mode()),
            (after.dev(), after.ino(), after.mode())
        );
    }
}
#[test]
fn missing_and_unsafe_permanent_lease_names_refuse_without_creation_or_repair() {
    for kind in [
        "missing",
        "symlink",
        "fifo",
        "directory",
        "hardlink",
        "mode",
        "size",
    ] {
        let fixture = Fixture::new();
        std::fs::remove_file(fixture.leaf()).unwrap();
        match kind {
            "missing" => (),
            "symlink" => symlink(fixture.root.join("missing"), fixture.leaf()).unwrap(),
            "fifo" => {
                let name = CString::new(fixture.leaf().as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o644) }, 0);
            }
            "directory" => std::fs::create_dir(fixture.leaf()).unwrap(),
            _ => {
                fixture.provision_fixture();
                match kind {
                    "hardlink" => {
                        std::fs::hard_link(fixture.leaf(), fixture.root.join("alias")).unwrap()
                    }
                    "mode" => std::fs::set_permissions(
                        fixture.leaf(),
                        std::fs::Permissions::from_mode(0o666),
                    )
                    .unwrap(),
                    _ => std::fs::write(fixture.leaf(), b"not zero").unwrap(),
                }
            }
        }
        let before = std::fs::symlink_metadata(fixture.leaf()).ok();
        assert!(fixture.acquire(Lock::Shared).is_err());
        let after = std::fs::symlink_metadata(fixture.leaf()).ok();
        assert_eq!(
            before
                .as_ref()
                .map(|m| (m.dev(), m.ino(), m.mode(), m.len(), m.nlink())),
            after
                .as_ref()
                .map(|m| (m.dev(), m.ino(), m.mode(), m.len(), m.nlink()))
        );
    }
}
#[test]
fn named_inode_replacement_or_protection_drift_invalidates_retained_file() {
    for change in ["replacement", "symlink", "mode", "size", "hardlink"] {
        let fixture = Fixture::new();
        let actor = fixture.acquire(Lock::Shared).unwrap();
        match change {
            "replacement" | "symlink" => {
                std::fs::rename(fixture.leaf(), fixture.root.join("original")).unwrap();
                if change == "replacement" {
                    fixture.provision_fixture();
                } else {
                    symlink(fixture.root.join("original"), fixture.leaf()).unwrap();
                }
            }
            "mode" => {
                std::fs::set_permissions(fixture.leaf(), std::fs::Permissions::from_mode(0o600))
                    .unwrap()
            }
            "size" => std::fs::write(fixture.leaf(), b"changed").unwrap(),
            _ => std::fs::hard_link(fixture.leaf(), fixture.root.join("alias")).unwrap(),
        }
        assert!(actor.assert_current(&fixture.parent).is_err());
        // No automatic name repair or unlink occurs on observation refusal.
        assert!(std::fs::symlink_metadata(fixture.leaf()).is_ok());
    }
}
#[test]
fn changed_access_and_cloexec_flags_invalidate_the_private_fixture_owner() {
    for close_on_exec in [false, true] {
        let fixture = Fixture::new();
        let actor = fixture.acquire(Lock::Shared).unwrap();
        if close_on_exec {
            assert_eq!(
                unsafe { libc::fcntl(actor.file.as_raw_fd(), libc::F_SETFD, 0) },
                0
            );
        } else {
            assert_eq!(
                unsafe { libc::fcntl(actor.file.as_raw_fd(), libc::F_SETFL, 0) },
                0
            );
        }
        assert!(actor.assert_current(&fixture.parent).is_err());
    }
}
#[test]
fn binding_refusal_after_actual_lock_closes_only_unadmitted_owner() {
    let fixture = Fixture::new();
    let calls = Cell::new(0);
    let result = acquire(&fixture.parent, fixture.owner(), Lock::Shared, &mut || {
        calls.set(calls.get() + 1);
        if calls.get() == 3 {
            Err(err!(ESTALE, "SYNTHETIC_DESCRIPTOR_CHANGED"))
        } else {
            Ok(())
        }
    });
    assert!(result.err().unwrap().is("SYNTHETIC_DESCRIPTOR_CHANGED"));
    fixture.inhibit();
    assert!(fixture.acquire(Lock::Exclusive).is_ok());
}
#[test]
fn named_lease_swap_after_actual_shared_lock_refuses_without_adopting_new_inode() {
    let fixture = Fixture::new();
    let calls = Cell::new(0);
    let result = acquire(&fixture.parent, fixture.owner(), Lock::Shared, &mut || {
        calls.set(calls.get() + 1);
        if calls.get() == 3 {
            std::fs::rename(fixture.leaf(), fixture.root.join("original")).unwrap();
            fixture.provision_fixture();
        }
        Ok(())
    });
    assert!(result.is_err());
    assert_eq!(calls.get(), 3);
    let original = File::open(fixture.root.join("original")).unwrap();
    assert_eq!(
        unsafe { libc::flock(original.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0,
        "failed initial admission must not leak a lock on the detached inode"
    );
    assert_ne!(
        original.metadata().unwrap().ino(),
        std::fs::metadata(fixture.leaf()).unwrap().ino()
    );
}
#[test]
fn marker_status_and_foreign_ownership_unknowns_cannot_become_admission() {
    let fixture = Fixture::new();
    let regular = File::open(fixture.leaf()).unwrap();
    assert!(marker(&regular, false)
        .unwrap_err()
        .is("STARTUP_LEASE_MARKER_UNKNOWN"));
    let different = Owner {
        uid: fixture.owner().uid.wrapping_add(1),
        gid: fixture.owner().gid,
    };
    assert!(LeaseFile::open(&fixture.parent, different).is_err());
    assert_eq!(std::fs::metadata(fixture.leaf()).unwrap().len(), 0);
}
#[test]
fn unleased_old_actor_demonstrates_exclusion_is_not_whole_target_inactivity() {
    let fixture = Fixture::new();
    let mut old = Process::spawn(&fixture, "unleased");
    old.expect("LEASE_STATUS:READY_UNLEASED");
    fixture.inhibit();
    let exclusive = fixture.acquire(Lock::Exclusive).unwrap();
    assert!(
        old.child.try_wait().unwrap().is_none(),
        "ungated actor is still alive while EX succeeds"
    );
    exclusive.assert_current(&fixture.parent).unwrap();
    old.send("EXIT\n");
    assert!(old.finish().success());
}
#[test]
fn unsupported_or_unselected_production_constructors_have_no_fixture_fallback() {
    #[cfg(not(target_os = "macos"))]
    assert!(native_root()
        .unwrap_err()
        .is("STARTUP_EXCLUSION_NATIVE_ROOT_REQUIRED"));
    // Do not mutate the global selector to manufacture a checked capability.
    assert!(
        super::super::selected().is_none(),
        "requires an unselected test process"
    );
    assert!(retain_selected_startup_lease()
        .unwrap_err()
        .is("DEPLOYMENT_CONTEXT_REQUIRED"));
}

#[test]
fn dedicated_exclusion_blocks_delayed_admission_without_creating_an_inhibition_marker() {
    let fixture = Fixture::new();
    let mut child = Process::spawn(&fixture, "delayed");
    child.expect("LEASE_STATUS:OLD_ADMISSION");
    let exclusive = fixture.acquire(Lock::DedicatedExclusive).unwrap();
    assert!(!fixture.marker().exists());
    child.send("CONTINUE\n");
    child.expect("LEASE_STATUS:DENIED_BEFORE_EFFECT");
    assert!(child.finish().success());
    exclusive.assert_current(&fixture.parent).unwrap();
    assert!(fixture
        .acquire(Lock::Shared)
        .err()
        .unwrap()
        .is("STARTUP_LEASE_BUSY"));
    assert!(fixture
        .acquire(Lock::DedicatedExclusive)
        .err()
        .unwrap()
        .is("STARTUP_LEASE_BUSY"));
    drop(exclusive);
    assert!(fixture.acquire(Lock::Shared).is_ok());
    assert!(!fixture.marker().exists());
}

#[test]
fn dedicated_exclusion_refuses_an_already_running_cooperating_actor() {
    let fixture = Fixture::new();
    let mut actor = Process::spawn(&fixture, "shared");
    actor.expect("LEASE_STATUS:READY");
    assert!(fixture
        .acquire(Lock::DedicatedExclusive)
        .err()
        .unwrap()
        .is("STARTUP_LEASE_BUSY"));
    assert!(!fixture.marker().exists());
    actor.send("EXIT\n");
    assert!(actor.finish().success());
    assert!(fixture.acquire(Lock::DedicatedExclusive).is_ok());
}

#[test]
fn dedicated_exclusion_marker_races_refuse_without_clearing_denial_or_leaking_ex() {
    for publish_at in 1..=4 {
        let fixture = Fixture::new();
        let calls = Cell::new(0);
        let result = acquire(
            &fixture.parent,
            fixture.owner(),
            Lock::DedicatedExclusive,
            &mut || {
                calls.set(calls.get() + 1);
                if calls.get() == publish_at {
                    fixture.inhibit();
                }
                Ok(())
            },
        );
        assert!(result.err().unwrap().is("DEPLOYMENT_UPGRADE_INHIBITED"));
        assert!(fixture.marker().exists());
        assert!(calls.get() >= publish_at);
        assert!(fixture.acquire(Lock::Exclusive).is_ok());
    }
}

#[test]
fn poisoned_dedicated_fixture_owner_retains_ex_until_drop_and_never_revives() {
    let fixture = Fixture::new();
    let mut retained = Retained {
        owner: fixture.acquire(Lock::DedicatedExclusive).unwrap(),
        poisoned: false,
    };
    fixture.inhibit();
    assert!(retained
        .check(|file| {
            file.assert_current(&fixture.parent)?;
            marker(&fixture.parent, false)
        })
        .is_err());
    std::fs::remove_file(fixture.marker()).unwrap();
    assert!(retained
        .check(|_| Ok(()))
        .unwrap_err()
        .is("STARTUP_LEASE_POISONED"));
    assert!(fixture
        .acquire(Lock::Shared)
        .err()
        .unwrap()
        .is("STARTUP_LEASE_BUSY"));
    drop(retained);
    assert!(fixture.acquire(Lock::Shared).is_ok());
}

#[test]
fn dedicated_mode_cannot_bypass_existing_upgrade_role_or_adopt_a_missing_leaf() {
    exclusive_role(DeploymentRole::DedicatedTest, Lock::DedicatedExclusive).unwrap();
    assert!(
        exclusive_role(DeploymentRole::ExistingUpgrade, Lock::DedicatedExclusive)
            .unwrap_err()
            .is("STARTUP_LEASE_DEDICATED_REQUIRED")
    );
    for role in [
        DeploymentRole::DedicatedTest,
        DeploymentRole::ExistingUpgrade,
    ] {
        exclusive_role(role, Lock::Exclusive).unwrap();
        assert!(exclusive_role(role, Lock::Shared).is_err());
    }
    let fixture = Fixture::new();
    std::fs::remove_file(fixture.leaf()).unwrap();
    assert!(fixture
        .acquire(Lock::DedicatedExclusive)
        .err()
        .unwrap()
        .is("STARTUP_LEASE_MISSING_OR_UNKNOWN"));
    assert!(!fixture.leaf().exists());
    assert!(!fixture.marker().exists());
}

#[test]
fn dedicated_exclusion_still_does_not_prove_ungated_actor_inactivity() {
    let fixture = Fixture::new();
    let mut old = Process::spawn(&fixture, "unleased");
    old.expect("LEASE_STATUS:READY_UNLEASED");
    let exclusive = fixture.acquire(Lock::DedicatedExclusive).unwrap();
    assert!(old.child.try_wait().unwrap().is_none());
    exclusive.assert_current(&fixture.parent).unwrap();
    assert!(!fixture.marker().exists());
    old.send("EXIT\n");
    assert!(old.finish().success());
}

#[test]
fn final_dedicated_absence_observation_retains_same_ex_without_unlock_or_reopen() {
    let fixture = Fixture::new();
    fixture.inhibit();
    let exclusive = fixture.acquire(Lock::Exclusive).unwrap();
    let original = exclusive.file.metadata().unwrap();
    std::fs::remove_file(fixture.marker()).unwrap();
    observe_dedicated_clear(
        &fixture.parent,
        &exclusive,
        Lock::Exclusive,
        DeploymentRole::DedicatedTest,
        &mut || Ok(()),
    )
    .unwrap();
    let after = exclusive.file.metadata().unwrap();
    assert_eq!((after.dev(), after.ino()), (original.dev(), original.ino()));
    assert!(fixture
        .acquire(Lock::Shared)
        .err()
        .unwrap()
        .is("STARTUP_LEASE_BUSY"));
    assert!(!fixture.marker().exists());
    drop(exclusive);
    assert!(fixture.acquire(Lock::Shared).is_ok());
}

#[test]
fn final_absence_refuses_upgrade_roles_wrong_modes_and_any_remaining_marker() {
    let fixture = Fixture::new();
    fixture.inhibit();
    let exclusive = fixture.acquire(Lock::Exclusive).unwrap();
    assert!(observe_dedicated_clear(
        &fixture.parent,
        &exclusive,
        Lock::Exclusive,
        DeploymentRole::DedicatedTest,
        &mut || Ok(())
    )
    .unwrap_err()
    .is("DEPLOYMENT_UPGRADE_INHIBITED"));
    std::fs::remove_file(fixture.marker()).unwrap();
    assert!(observe_dedicated_clear(
        &fixture.parent,
        &exclusive,
        Lock::Exclusive,
        DeploymentRole::ExistingUpgrade,
        &mut || Ok(())
    )
    .unwrap_err()
    .is("STARTUP_LEASE_DEDICATED_REQUIRED"));
    for previous in [Lock::Shared, Lock::DedicatedExclusive] {
        assert!(observe_dedicated_clear(
            &fixture.parent,
            &exclusive,
            previous,
            DeploymentRole::DedicatedTest,
            &mut || Ok(())
        )
        .unwrap_err()
        .is("STARTUP_LEASE_TRANSITION_REQUIRES_INHIBITED_EX"));
    }
    assert!(fixture
        .acquire(Lock::Shared)
        .err()
        .unwrap()
        .is("STARTUP_LEASE_BUSY"));
}

#[test]
fn final_absence_rechecks_context_marker_and_original_inode_without_repair() {
    for fail_at in [1, 2] {
        let fixture = Fixture::new();
        fixture.inhibit();
        let exclusive = fixture.acquire(Lock::Exclusive).unwrap();
        std::fs::remove_file(fixture.marker()).unwrap();
        let calls = Cell::new(0);
        let error = observe_dedicated_clear(
            &fixture.parent,
            &exclusive,
            Lock::Exclusive,
            DeploymentRole::DedicatedTest,
            &mut || {
                calls.set(calls.get() + 1);
                if calls.get() == fail_at {
                    fixture.inhibit();
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.is("DEPLOYMENT_UPGRADE_INHIBITED"));
        assert!(fixture.marker().exists());
        assert!(fixture
            .acquire(Lock::Exclusive)
            .err()
            .unwrap()
            .is("STARTUP_LEASE_BUSY"));
    }
    let fixture = Fixture::new();
    fixture.inhibit();
    let exclusive = fixture.acquire(Lock::Exclusive).unwrap();
    std::fs::remove_file(fixture.marker()).unwrap();
    let moved = fixture.root.join("original.lock");
    std::fs::rename(fixture.leaf(), &moved).unwrap();
    std::fs::write(fixture.leaf(), b"").unwrap();
    std::fs::set_permissions(fixture.leaf(), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(observe_dedicated_clear(
        &fixture.parent,
        &exclusive,
        Lock::Exclusive,
        DeploymentRole::DedicatedTest,
        &mut || Ok(())
    )
    .unwrap_err()
    .is("STARTUP_LEASE_CHANGED"));
    assert!(std::fs::metadata(moved).is_ok());
    assert!(!fixture.marker().exists());
}

#[test]
fn failed_final_absence_check_retains_poisoned_ex_until_owner_drop() {
    let fixture = Fixture::new();
    fixture.inhibit();
    let mut retained = Retained {
        owner: fixture.acquire(Lock::Exclusive).unwrap(),
        poisoned: false,
    };
    std::fs::remove_file(fixture.marker()).unwrap();
    let error = retained
        .check(|file| {
            observe_dedicated_clear(
                &fixture.parent,
                file,
                Lock::Exclusive,
                DeploymentRole::DedicatedTest,
                &mut || Err(err!(ESTALE, "FIXTURE_FINAL_CONTEXT_CHANGED")),
            )
        })
        .unwrap_err();
    assert!(error.is("FIXTURE_FINAL_CONTEXT_CHANGED"));
    assert!(retained
        .check(|_| Ok(()))
        .unwrap_err()
        .is("STARTUP_LEASE_POISONED"));
    assert!(fixture
        .acquire(Lock::Shared)
        .err()
        .unwrap()
        .is("STARTUP_LEASE_BUSY"));
    assert!(!fixture.marker().exists());
    drop(retained);
    assert!(fixture.acquire(Lock::Shared).is_ok());
}

// Direct synthetic probes distinguish actual kernel contention from marker or
// namespace refusal. They never supply authority to a product constructor.
fn kernel_contended(path: &std::path::Path, lock: i32) -> bool {
    let file = File::open(path).unwrap();
    if unsafe { libc::flock(file.as_raw_fd(), lock | libc::LOCK_NB) } == 0 {
        return false;
    }
    let error = std::io::Error::last_os_error().raw_os_error();
    assert!(
        error == Some(libc::EAGAIN) || error == Some(libc::EWOULDBLOCK),
        "unexpected synthetic flock failure"
    );
    true
}

#[test]
fn retained_inhibited_post_lock_binding_faults_keep_actual_ex_until_failure_drop() {
    for fail_at in [3, 4] {
        let fixture = Fixture::new();
        fixture.inhibit();
        let calls = Cell::new(0);
        let failure = acquire_retained(
            &fixture.parent,
            fixture.owner(),
            Lock::Exclusive,
            &mut || {
                calls.set(calls.get() + 1);
                if calls.get() == fail_at {
                    Err(err!(ESTALE, "SYNTHETIC_POST_LOCK_REFUSAL"))
                } else {
                    Ok(())
                }
            },
        )
        .err()
        .expect("post-flock check must refuse");
        assert_eq!(calls.get(), fail_at);
        assert!(failure.acquired && failure.file.is_some());
        assert!(failure.error.is("SYNTHETIC_POST_LOCK_REFUSAL"));
        assert!(kernel_contended(&fixture.leaf(), libc::LOCK_SH));
        assert!(kernel_contended(&fixture.leaf(), libc::LOCK_EX));
        // Matching later public observations cannot convert the error into an
        // admitted lease. The exact failed owner still owns the actual lock.
        failure
            .file
            .as_ref()
            .unwrap()
            .assert_current(&fixture.parent)
            .unwrap();
        assert!(failure.error.is("SYNTHETIC_POST_LOCK_REFUSAL"));
        drop(failure);
        assert!(!kernel_contended(&fixture.leaf(), libc::LOCK_EX));
        assert!(fixture.marker().exists());
        assert_eq!(std::fs::metadata(fixture.leaf()).unwrap().len(), 0);
    }
}

#[test]
fn retained_inhibited_marker_loss_keeps_ex_without_restoring_denial_or_reacquiring() {
    for remove_at in [3, 4] {
        let fixture = Fixture::new();
        fixture.inhibit();
        let calls = Cell::new(0);
        let failure = acquire_retained(
            &fixture.parent,
            fixture.owner(),
            Lock::Exclusive,
            &mut || {
                calls.set(calls.get() + 1);
                if calls.get() == remove_at {
                    std::fs::remove_file(fixture.marker()).unwrap();
                }
                Ok(())
            },
        )
        .err()
        .expect("marker loss must refuse");
        assert!(failure.acquired);
        assert!(failure.error.is("STARTUP_LEASE_INHIBITION_REQUIRED"));
        assert!(!fixture.marker().exists());
        assert!(kernel_contended(&fixture.leaf(), libc::LOCK_SH));
        assert!(fixture
            .acquire(Lock::Shared)
            .err()
            .unwrap()
            .is("STARTUP_LEASE_BUSY"));
        drop(failure);
        assert!(!kernel_contended(&fixture.leaf(), libc::LOCK_EX));
        assert!(!fixture.marker().exists());
    }
}

#[test]
fn retained_inhibited_all_post_lock_failures_preserve_order_and_detached_original_lock() {
    let fixture = Fixture::new();
    fixture.inhibit();
    let calls = Cell::new(0);
    let original = std::fs::metadata(fixture.leaf()).unwrap();
    let moved = fixture.root.join("original-held.lock");
    let failure = acquire_retained(
        &fixture.parent,
        fixture.owner(),
        Lock::Exclusive,
        &mut || {
            calls.set(calls.get() + 1);
            if calls.get() == 3 {
                std::fs::rename(fixture.leaf(), &moved).unwrap();
                fixture.provision_fixture();
                std::fs::remove_file(fixture.marker()).unwrap();
                return Err(err!(ESTALE, "SYNTHETIC_POST_LOCK_REFUSAL"));
            }
            Ok(())
        },
    )
    .err()
    .expect("independent post-lock faults must refuse");
    assert!(failure.acquired);
    assert!(failure.error.is("SYNTHETIC_POST_LOCK_REFUSAL"));
    assert_eq!(
        failure
            .final_errors
            .iter()
            .map(|e| e.reason.as_str())
            .collect::<Vec<_>>(),
        [
            "SYNTHETIC_POST_LOCK_REFUSAL",
            "STARTUP_LEASE_CHANGED",
            "STARTUP_LEASE_INHIBITION_REQUIRED"
        ]
    );
    let held = failure.file.as_ref().unwrap().file.metadata().unwrap();
    assert_eq!((held.dev(), held.ino()), (original.dev(), original.ino()));
    assert!(kernel_contended(&moved, libc::LOCK_EX));
    assert!(
        !kernel_contended(&fixture.leaf(), libc::LOCK_EX),
        "replacement is not the locked inode"
    );
    assert!(failure
        .file
        .as_ref()
        .unwrap()
        .assert_current(&fixture.parent)
        .is_err());
    drop(failure);
    assert!(!kernel_contended(&moved, libc::LOCK_EX));
    assert!(!fixture.marker().exists());
    assert!(moved.exists() && fixture.leaf().exists());
}

#[test]
fn retained_pre_lock_faults_report_only_the_partial_owner_actually_opened() {
    for fail_at in [1, 2] {
        let fixture = Fixture::new();
        fixture.inhibit();
        let calls = Cell::new(0);
        let failure = acquire_retained(
            &fixture.parent,
            fixture.owner(),
            Lock::Exclusive,
            &mut || {
                calls.set(calls.get() + 1);
                if calls.get() == fail_at {
                    Err(err!(ESTALE, "SYNTHETIC_PRE_LOCK_REFUSAL"))
                } else {
                    Ok(())
                }
            },
        )
        .err()
        .expect("pre-lock check must refuse");
        assert!(!failure.acquired);
        assert_eq!(failure.file.is_some(), fail_at == 2);
        assert!(failure.final_errors.is_empty());
        assert!(failure.error.is("SYNTHETIC_PRE_LOCK_REFUSAL"));
        assert!(!kernel_contended(&fixture.leaf(), libc::LOCK_EX));
        drop(failure);
        assert!(fixture.marker().exists());
    }
}

#[test]
fn retained_actual_contention_never_reports_acquisition_or_adopts_the_other_actor() {
    let fixture = Fixture::new();
    let actor = fixture.acquire(Lock::Shared).unwrap();
    fixture.inhibit();
    let failure = acquire_retained(
        &fixture.parent,
        fixture.owner(),
        Lock::Exclusive,
        &mut || Ok(()),
    )
    .err()
    .expect("actual shared flock must deny EX");
    assert!(failure.error.is("STARTUP_LEASE_BUSY"));
    assert!(!failure.acquired && failure.file.is_some());
    assert!(kernel_contended(&fixture.leaf(), libc::LOCK_EX));
    drop(actor);
    // Keeping an opened-but-unlocked refusal does not retain someone else's
    // SH or pretend that this failed attempt acquired EX after their exit.
    assert!(!kernel_contended(&fixture.leaf(), libc::LOCK_EX));
    assert!(!failure.acquired);
    drop(failure);
    assert!(fixture.marker().exists());
}

#[test]
fn retained_acquisition_success_uses_original_inode_and_keeps_existing_four_checks() {
    let fixture = Fixture::new();
    fixture.inhibit();
    let calls = Cell::new(0);
    let file = acquire_retained(
        &fixture.parent,
        fixture.owner(),
        Lock::Exclusive,
        &mut || {
            calls.set(calls.get() + 1);
            Ok(())
        },
    )
    .ok()
    .expect("actual fixture acquisition must pass");
    assert_eq!(calls.get(), 4);
    file.assert_current(&fixture.parent).unwrap();
    assert!(kernel_contended(&fixture.leaf(), libc::LOCK_SH));
    drop(file);
    assert!(!kernel_contended(&fixture.leaf(), libc::LOCK_EX));
    assert!(fixture.marker().exists());
}

#[test]
fn retained_failed_exclusive_child_blocks_until_actual_failure_owner_process_exit() {
    let fixture = Fixture::new();
    fixture.inhibit();
    let mut child = Process::spawn(&fixture, "retained-exclusive-refusal");
    child.expect("LEASE_STATUS:REFUSED_EX_HELD");
    assert!(fixture
        .acquire(Lock::Exclusive)
        .err()
        .unwrap()
        .is("STARTUP_LEASE_BUSY"));
    assert!(kernel_contended(&fixture.leaf(), libc::LOCK_SH));
    child.send("RECHECK\n");
    child.expect("LEASE_STATUS:REFUSAL_STILL_HELD");
    assert!(kernel_contended(&fixture.leaf(), libc::LOCK_EX));
    child.send("EXIT\n");
    assert!(child.finish().success());
    assert!(!kernel_contended(&fixture.leaf(), libc::LOCK_EX));
    assert!(fixture.acquire(Lock::Exclusive).is_ok());
    assert!(fixture.marker().exists());
}

fn inert_private_birth_target() -> (super::super::DeploymentTarget, PathBuf) {
    let root = PathBuf::from("/private-birth/00112233445566778899aabbccddeeff");
    let path = |name: &str| root.join(name);
    let raw=serde_json::to_vec(&serde_json::json!({"version":1,"target_id":"ykft-00112233445566778899aabbccddeeff",
        "role":"dedicated-test","profile":"L2","signing_identity_mode":"local-pins",
        "authority_config":path("support/custody.json"),"expected_artifacts_manifest":path("config/inventory.json"),
        "codesign_pins_file":path("support/pins.json"),"broker":null,"shared_read_only_inputs":[],
        "layout":{"binary_dir":path("bin"),"custody_bundle":path("support/Custody.app"),"sandbox_dir":path("sandbox"),
            "socket_root":path("run"),"state_root":path("state"),"audit_root":path("audit"),"cas_store_root":path("cas"),
            "staging_root":path("stage"),"support_root":path("support"),"launchd_namespace":"com.mcpmac.modefixture",
            "mach_service":"com.mcpmac.modefixture.exception"}})).unwrap();
    (
        super::super::DeploymentTarget::parse(&raw).unwrap(),
        path("config/deployment.json"),
    )
}

#[test]
fn private_birth_mode_scope_derives_one_exact_nonce_and_all_thirteen_inert_references() {
    let (target, config) = inert_private_birth_target();
    let root = private_birth_root_for(&target, &config).unwrap();
    assert_eq!(
        root,
        Path::new("/private-birth/00112233445566778899aabbccddeeff")
    );
    for index in 0..13 {
        let (mut target, mut config) = inert_private_birth_target();
        let l = &mut target.layout;
        let references: [&mut PathBuf; 13] = [
            &mut l.binary_dir,
            &mut l.custody_bundle,
            &mut l.sandbox_dir,
            &mut l.socket_root,
            &mut l.state_root,
            &mut l.audit_root,
            &mut l.cas_store_root,
            &mut l.staging_root,
            &mut l.support_root,
            &mut target.authority_config,
            &mut target.expected_artifacts_manifest,
            &mut target.codesign_pins_file,
            &mut config,
        ];
        *references.into_iter().nth(index).unwrap() = PathBuf::from("/outside/one-reference");
        assert!(
            private_birth_root_for(&target, &config).is_err(),
            "reference {index}"
        );
    }
    for variant in [
        "id",
        "upper",
        "duplicate",
        "outside",
        "root-ref",
        "config",
        "profile",
        "role",
    ] {
        let (mut target, mut config) = inert_private_birth_target();
        match variant {
            "id" => target.target_id = "ykft-not-a-nonce".into(),
            "upper" => target.target_id = "ykft-00112233445566778899AABBCCDDEEFF".into(),
            "duplicate" => {
                target.layout.support_root = target
                    .layout
                    .support_root
                    .join("00112233445566778899aabbccddeeff/support")
            }
            "outside" => target.codesign_pins_file = "/outside/pins.json".into(),
            "root-ref" => target.authority_config = root.clone(),
            "config" => config = "/outside/config.json".into(),
            "profile" => target.profile = crate::profile::Profile::L3,
            _ => target.role = DeploymentRole::ExistingUpgrade,
        }
        assert!(
            private_birth_root_for(&target, &config).is_err(),
            "{variant}"
        );
    }
}

#[test]
fn metadata_retention_resolver_keeps_original_primary_and_all_final_errors_without_fabricated_capability(
) {
    let fixture = Fixture::new();
    fixture.inhibit();
    let file = fixture.acquire(Lock::Exclusive).unwrap();
    let original = file.file.as_raw_fd();
    let refusal = super::super::upgrade::directory_mode::resolve_retained::<_, ()>(
        file,
        Err(err!(EIO, "SYNTHETIC_MODE_RESOLVER_PRIMARY")),
        vec![err!(EACCES, "SYNTHETIC_MODE_RESOLVER_BOUNDARY")],
        vec![err!(ESTALE, "SYNTHETIC_MODE_RESOLVER_FINAL")],
        None,
        None,
    )
    .err()
    .expect("original operation refuses");
    assert!(refusal.error.is("SYNTHETIC_MODE_RESOLVER_PRIMARY"));
    assert_eq!(refusal.boundary_errors.len(), 1);
    assert_eq!(refusal.final_errors.len(), 1);
    assert_eq!(refusal.owner.file.as_raw_fd(), original);
    assert!(kernel_contended(&fixture.leaf(), libc::LOCK_SH));
    assert!(refusal.change.is_none() && refusal.effect.is_none());
    drop(refusal);
    assert!(!kernel_contended(&fixture.leaf(), libc::LOCK_EX));
    assert!(fixture.marker().exists());
}
