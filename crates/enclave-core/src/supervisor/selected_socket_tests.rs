//! Actual private socket ownership logic with repository-local software roots.
//! No selected native/root/PF/installed service capability is fabricated.
use super::*;
use std::{
    io::{Read, Write},
    os::unix::{
        fs::{symlink, OpenOptionsExt, PermissionsExt},
        net::UnixStream,
    },
    time::Duration,
};

struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        // Relative AF_UNIX names keep the same fixture usable in long native
        // checkout paths without changing cwd or writing outside the checkout.
        let root = PathBuf::from("target")
            .join(format!("ss-{}", hex::encode(&crate::rng::bytes32()[..8])));
        std::fs::create_dir_all("target").unwrap();
        std::fs::create_dir(&root).unwrap();
        mode(&root, 0o700);
        std::fs::create_dir(root.join(super::super::SOCKET_DIR)).unwrap();
        mode(&root.join(super::super::SOCKET_DIR), 0o2750);
        Self { root }
    }
    fn parent(&self) -> PathBuf {
        self.root.join(super::super::SOCKET_DIR)
    }
    fn prepared(&self, role: Role) -> Owner {
        let file = open(&self.root);
        let identity = Identity::of(&file.metadata().unwrap());
        let mut owner = Owner::empty(role);
        let gid = std::fs::metadata(self.parent()).unwrap().gid();
        owner.context = Some(Context::Fixture {
            root: self.root.clone(),
            file,
            identity,
            gid,
        });
        owner.path = Some(role.path(&self.root));
        owner.parent = Some(open(&self.parent()));
        owner
    }
    fn bind(&self, role: Role) -> Owner {
        self.bind_with(role, until(), None)
    }
    fn bind_with(
        &self,
        role: Role,
        end: Instant,
        hook: Option<Box<dyn FnMut(Point, &Path)>>,
    ) -> Owner {
        let mut owner = self.prepared(role);
        owner.hook = hook;
        if let Err(reason) = owner.prepare(&mut None, end) {
            owner.retain(reason);
        }
        owner
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.root, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::set_permissions(self.parent(), std::fs::Permissions::from_mode(0o750));
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn open(path: &Path) -> File {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .unwrap()
}
fn mode(path: &Path, bits: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits)).unwrap();
}
fn until() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn current(owner: &mut Owner) -> Check<()> {
    owner.require_current(&mut None, until())
}
fn inode(path: &Path) -> (u64, u64) {
    Identity::of(&std::fs::symlink_metadata(path).unwrap()).inode()
}

#[test]
fn both_fixed_roles_bind_exact_names_dac_and_actual_original_listener() {
    let fixture = Fixture::new();
    for role in [Role::Primary, Role::Held] {
        let mut owner = fixture.bind(role);
        current(&mut owner).unwrap();
        let path = role.path(&fixture.root);
        assert_eq!(owner.path.as_ref(), Some(&path));
        assert_eq!(owner.role, role);
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(
            metadata.gid(),
            std::fs::metadata(fixture.parent()).unwrap().gid()
        );
        assert_eq!(metadata.mode() & 0o7777, 0o660);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(owner.created, Some(inode(&path)));
        assert!(owner.listen_succeeded && !owner.taken);
        let expected = listener_identity(owner.listener.as_ref().unwrap(), Some(&path)).unwrap();
        assert_eq!(owner.listener_identity, Some(expected));
        // A successful observation does not unlink the name on Drop.
        drop(owner);
        assert!(path.exists());
    }
    assert_ne!(
        Role::Primary.path(&fixture.root),
        Role::Held.path(&fixture.root)
    );
}

#[test]
fn one_checked_dup_is_the_same_open_listener_and_can_accept_real_fixture_bytes() {
    let fixture = Fixture::new();
    let mut owner = fixture.bind(Role::Primary);
    current(&mut owner).unwrap();
    let original_fd = owner.listener.as_ref().unwrap().as_raw_fd();
    let duplicate = owner.take_listener(&mut None, until()).unwrap();
    assert_ne!(duplicate.as_raw_fd(), original_fd);
    assert_eq!(
        listener_identity(&duplicate, owner.path.as_deref()).unwrap(),
        owner.listener_identity.unwrap()
    );
    let mut client = UnixStream::connect(owner.path.as_ref().unwrap()).unwrap();
    let (mut server, _) = duplicate.accept().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    client.write_all(b"fixture").unwrap();
    let mut bytes = [0; 7];
    server.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"fixture");
    server.write_all(b"ok").unwrap();
    let mut bytes = [0; 2];
    client.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"ok");
    assert!(owner.take_listener(&mut None, until()).is_err());
    assert!(owner.failures.contains(&Reason::AlreadyTaken));
    assert!(current(&mut owner).is_err()); // Duplicate issuance cannot be retried or revive this allocation.
    assert_eq!(owner.listener.as_ref().unwrap().as_raw_fd(), original_fd);
    drop(duplicate);
    assert!(unsafe { libc::fcntl(original_fd, libc::F_GETFD) } >= 0);
}

#[test]
fn supported_object_checks_refuse_wrong_type_and_an_unbound_route_without_fabricating_acceptance() {
    let fixture = Fixture::new();
    for kind in [libc::SOCK_STREAM, libc::SOCK_DGRAM] {
        let raw = unsafe { libc::socket(libc::AF_UNIX, kind, 0) };
        assert!(raw >= 0);
        // This private negative owns a real socket descriptor. Only descriptor
        // queries and Drop run for the datagram; it never reaches accept.
        let socket = unsafe { UnixListener::from_raw_fd(raw) };
        assert_eq!(
            unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) },
            0
        );
        socket.set_nonblocking(true).unwrap();
        if kind == libc::SOCK_DGRAM {
            assert_eq!(
                listener_identity(&socket, None),
                Err(Reason::ListenerChanged)
            );
        } else {
            // A stream FD passes object checks before listen. That says
            // nothing about acceptance; an exact bound route is still absent.
            let identity = listener_identity(&socket, None).unwrap();
            assert_eq!(
                listener_identity(&socket, Some(&Role::Primary.path(&fixture.root))),
                Err(Reason::ListenerChanged)
            );
            let mut owner = fixture.prepared(Role::Primary);
            owner.listener_identity = Some(identity);
            owner.listener = Some(socket);
            assert_eq!(current(&mut owner), Err(Reason::Incomplete));
            assert!(!owner.listen_succeeded && owner.created.is_none());
            assert!(owner.take_listener(&mut None, until()).is_err());
            assert!(!owner.taken);
        }
    }
}

#[test]
fn every_preexisting_leaf_refuses_without_unlink_chmod_or_adoption() {
    for variant in 0..6 {
        let fixture = Fixture::new();
        let path = Role::Primary.path(&fixture.root);
        let mut foreign = None;
        match variant {
            0 => {
                std::fs::write(&path, b"foreign").unwrap();
                mode(&path, 0o640);
            }
            1 => symlink("missing-target", &path).unwrap(),
            2 => {
                let name = CString::new(path.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o640) }, 0);
            }
            3 => {
                std::fs::create_dir(&path).unwrap();
                mode(&path, 0o700);
            }
            4 => {
                foreign = Some(UnixListener::bind(&path).unwrap());
                mode(&path, 0o600);
            }
            _ => {
                std::fs::write(fixture.root.join("target"), b"untouched").unwrap();
                symlink("../target", &path).unwrap();
            }
        }
        let before = Identity::of(&std::fs::symlink_metadata(&path).unwrap());
        let mut owner = fixture.bind(Role::Primary);
        assert_eq!(owner.failures, vec![Reason::Occupied]);
        assert!(owner.listener.is_none() && owner.created.is_none());
        assert!(owner.parent.is_some());
        assert!(current(&mut owner).is_err());
        drop(owner);
        assert_eq!(
            Identity::of(&std::fs::symlink_metadata(&path).unwrap()),
            before
        );
        if variant == 0 {
            assert_eq!(std::fs::read(&path).unwrap(), b"foreign");
        }
        if variant == 5 {
            assert_eq!(
                std::fs::read(fixture.root.join("target")).unwrap(),
                b"untouched"
            );
        }
        drop(foreign);
    }
}

#[test]
fn parent_mode_or_named_replacement_is_never_repaired_and_original_fd_survives() {
    for replacement in [false, true] {
        let fixture = Fixture::new();
        let mut owner = fixture.bind(Role::Held);
        current(&mut owner).unwrap();
        let original = owner.parent.as_ref().unwrap().as_raw_fd();
        let identity = owner.parent_identity.unwrap();
        if replacement {
            std::fs::rename(fixture.parent(), fixture.root.join("saved")).unwrap();
            std::fs::create_dir(fixture.parent()).unwrap();
            mode(&fixture.parent(), 0o2750);
        } else {
            mode(&fixture.parent(), 0o2770);
        }
        assert!(current(&mut owner).is_err());
        assert!(owner.failures.contains(&Reason::ParentChanged));
        assert_eq!(owner.parent.as_ref().unwrap().as_raw_fd(), original);
        assert_eq!(
            Identity::of(&owner.parent.as_ref().unwrap().metadata().unwrap()).inode(),
            identity.inode()
        );
        if replacement {
            std::fs::remove_dir(fixture.parent()).unwrap();
            std::fs::rename(fixture.root.join("saved"), fixture.parent()).unwrap();
        } else {
            assert_eq!(
                std::fs::metadata(fixture.parent()).unwrap().mode() & 0o7777,
                0o2770
            );
            mode(&fixture.parent(), 0o2750);
        }
        assert!(current(&mut owner).is_err());
        assert!(owner.failures.contains(&Reason::Poisoned));
    }
}

#[test]
fn unsafe_or_symlinked_parent_refuses_before_allocating_a_socket() {
    for link in [false, true] {
        let fixture = Fixture::new();
        let mut owner = fixture.prepared(Role::Primary);
        if link {
            std::fs::rename(fixture.parent(), fixture.root.join("saved")).unwrap();
            symlink("saved", fixture.parent()).unwrap();
        } else {
            mode(&fixture.parent(), 0o2770);
        }
        let before = Identity::of(&std::fs::symlink_metadata(fixture.parent()).unwrap());
        if let Err(reason) = owner.prepare(&mut None, until()) {
            owner.retain(reason);
        }
        assert!(owner.poisoned && owner.listener.is_none() && owner.created.is_none());
        assert_eq!(
            Identity::of(&std::fs::symlink_metadata(fixture.parent()).unwrap()),
            before
        );
        assert!(!Role::Primary.path(&fixture.root).exists());
        if link {
            std::fs::remove_file(fixture.parent()).unwrap();
            std::fs::rename(fixture.root.join("saved"), fixture.parent()).unwrap();
        }
    }
}

#[test]
fn replaced_socket_and_restored_mode_never_revive_or_create_another_duplicate() {
    for replacement in [false, true] {
        let fixture = Fixture::new();
        let mut owner = fixture.bind(Role::Primary);
        current(&mut owner).unwrap();
        let path = owner.path.clone().unwrap();
        let original = owner.created.unwrap();
        if replacement {
            std::fs::rename(&path, fixture.root.join("saved.sock")).unwrap();
            std::fs::write(&path, b"foreign").unwrap();
        } else {
            mode(&path, 0o600);
        }
        assert!(current(&mut owner).is_err());
        assert_eq!(owner.created, Some(original));
        if replacement {
            assert_eq!(std::fs::read(&path).unwrap(), b"foreign");
            std::fs::remove_file(&path).unwrap();
            std::fs::rename(fixture.root.join("saved.sock"), &path).unwrap();
        } else {
            mode(&path, 0o660);
        }
        assert!(owner.take_listener(&mut None, until()).is_err());
        assert!(!owner.taken);
        assert!(owner.listener.is_some() && owner.parent.is_some());
    }
}

#[test]
fn original_fixture_ancestor_replacement_and_writability_are_detected() {
    for replacement in [false, true] {
        let fixture = Fixture::new();
        let mut owner = fixture.bind(Role::Held);
        current(&mut owner).unwrap();
        let saved = fixture.root.with_extension("saved");
        if replacement {
            std::fs::rename(&fixture.root, &saved).unwrap();
            std::fs::create_dir(&fixture.root).unwrap();
            mode(&fixture.root, 0o700);
        } else {
            mode(&fixture.root, 0o770);
        }
        assert!(current(&mut owner).is_err());
        assert!(owner.failures.contains(&Reason::ParentChanged));
        if replacement {
            std::fs::remove_dir(&fixture.root).unwrap();
            std::fs::rename(saved, &fixture.root).unwrap();
        } else {
            mode(&fixture.root, 0o700);
        }
        assert!(current(&mut owner).is_err());
    }
}

#[test]
fn after_bind_replacement_refuses_before_dac_and_listen_retaining_partial_owner() {
    let fixture = Fixture::new();
    let hook = Box::new(|point, path: &Path| {
        if point == Point::AfterBind {
            std::fs::rename(path, path.with_extension("original")).unwrap();
            std::fs::write(path, b"foreign").unwrap();
            mode(path, 0o640);
        }
    });
    let mut owner = fixture.bind_with(Role::Primary, until(), Some(hook));
    assert!(owner.poisoned && !owner.listen_succeeded && !owner.taken && owner.protected.is_none());
    assert!(owner.listener.is_some() && owner.parent.is_some() && owner.created.is_some());
    assert!(owner.failures.contains(&Reason::NameChanged));
    let path = owner.path.as_ref().unwrap();
    assert_eq!(std::fs::read(path).unwrap(), b"foreign");
    assert_eq!(
        std::fs::symlink_metadata(path).unwrap().mode() & 0o7777,
        0o640
    );
    assert!(owner.take_listener(&mut None, until()).is_err());
}

#[test]
fn after_dac_protection_loss_and_after_listen_name_loss_are_sticky() {
    for point in [Point::AfterDac, Point::AfterListen] {
        let fixture = Fixture::new();
        let hook = Box::new(move |actual, path: &Path| {
            if actual == point {
                if actual == Point::AfterDac {
                    mode(path, 0o666);
                } else {
                    std::fs::rename(path, path.with_extension("saved")).unwrap();
                }
            }
        });
        let mut owner = fixture.bind_with(Role::Held, until(), Some(hook));
        assert!(owner.poisoned && owner.listener.is_some() && owner.parent.is_some());
        assert_eq!(owner.listen_succeeded, point == Point::AfterListen);
        assert!(owner.take_listener(&mut None, until()).is_err());
        assert!(!owner.taken);
    }
}

#[test]
fn expiry_before_bind_has_no_socket_effect_and_late_bind_keeps_its_original() {
    let fixture = Fixture::new();
    let mut owner = fixture.bind_with(Role::Primary, Instant::now(), None);
    assert!(owner.poisoned && owner.listener.is_none() && owner.created.is_none());
    assert!(!Role::Primary.path(&fixture.root).exists());
    assert!(current(&mut owner).is_err());
    let end = Instant::now() + Duration::from_secs(1);
    let hook = Box::new(move |point, _: &Path| {
        if point == Point::AfterBind {
            std::thread::sleep(end.saturating_duration_since(Instant::now()));
        }
    });
    let mut owner = fixture.bind_with(Role::Held, end, Some(hook));
    assert!(owner.failures.contains(&Reason::Deadline));
    assert!(owner.listener.is_some() && owner.created.is_some());
    assert!(!owner.listen_succeeded && owner.protected.is_none());
    assert!(current(&mut owner).is_err());
}

#[test]
fn late_duplicate_is_withheld_and_original_cannot_be_replaced_or_reissued() {
    let fixture = Fixture::new();
    let mut owner = fixture.bind(Role::Primary);
    current(&mut owner).unwrap();
    let original = owner.listener.as_ref().unwrap().as_raw_fd();
    let end = Instant::now() + Duration::from_secs(1);
    owner.hook = Some(Box::new(move |point, _| {
        if point == Point::AfterDuplicate {
            std::thread::sleep(end.saturating_duration_since(Instant::now()));
        }
    }));
    assert!(owner.take_listener(&mut None, end).is_err());
    assert!(owner.taken && owner.poisoned);
    assert_eq!(owner.listener.as_ref().unwrap().as_raw_fd(), original);
    assert!(unsafe { libc::fcntl(original, libc::F_GETFD) } >= 0);
    assert!(owner.take_listener(&mut None, until()).is_err());
}

#[test]
fn changed_listener_flags_refuse_even_after_flags_are_restored() {
    for descriptor in [false, true] {
        let fixture = Fixture::new();
        let mut owner = fixture.bind(Role::Primary);
        current(&mut owner).unwrap();
        let raw = owner.listener.as_ref().unwrap().as_raw_fd();
        let (get, set, bit) = if descriptor {
            (libc::F_GETFD, libc::F_SETFD, libc::FD_CLOEXEC)
        } else {
            (libc::F_GETFL, libc::F_SETFL, libc::O_NONBLOCK)
        };
        let flags = unsafe { libc::fcntl(raw, get) };
        assert!(flags >= 0);
        assert_eq!(unsafe { libc::fcntl(raw, set, flags & !bit) }, 0);
        assert!(current(&mut owner).is_err());
        assert!(owner.failures.contains(&Reason::Flags));
        assert_eq!(unsafe { libc::fcntl(raw, set, flags) }, 0);
        assert!(current(&mut owner).is_err());
        assert!(owner.take_listener(&mut None, until()).is_err());
    }
}

#[test]
fn unrelated_entries_do_not_invalidate_original_identity_or_rewrite_existing_names() {
    let fixture = Fixture::new();
    let mut owner = fixture.bind(Role::Primary);
    current(&mut owner).unwrap();
    std::fs::write(fixture.parent().join("other"), b"unrelated").unwrap();
    current(&mut owner).unwrap();
    let original = owner.created;
    let second = fixture.bind(Role::Primary);
    assert_eq!(second.failures, vec![Reason::Occupied]);
    assert_eq!(owner.created, original);
    current(&mut owner).unwrap();
}

#[test]
fn incomplete_or_unadmitted_native_owner_never_manufactures_socket_authority() {
    let mut empty = Owner::empty(Role::Primary);
    assert!(current(&mut empty).is_err());
    assert!(empty.poisoned);
    if native().is_err() {
        let mut originals = SelectedRuntime::acquire_selected(
            Path::new("/unopened-selected-socket"),
            Profile::L2,
            until(),
        );
        let primary = PrimarySocket::bind(&mut originals, until());
        let held = HeldSocket::bind(&mut originals, until());
        for owner in [&primary.inner, &held.inner] {
            assert_eq!(owner.failures, vec![Reason::Native]);
            assert!(
                owner.context.is_none()
                    && owner.parent.is_none()
                    && owner.listener.is_none()
                    && owner.path.is_none()
            );
            assert!(!format!("{}", owner.error()).contains("/unopened-selected-socket"));
        }
    }
}
