//! SOFTWARE fixtures use real held descriptors under a fresh private root.
//! No native selection, service, monitor, IPC, PF or external command runs.
use super::*;
use std::{
    cell::Cell,
    os::unix::fs::{symlink, PermissionsExt},
    rc::Rc,
};

const DESCRIPTOR: &[u8] = b"SYNTHETIC_DESCRIPTOR_CONTENT_NEVER_A_NATIVE_CAPABILITY";
struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let parent = std::env::current_dir().unwrap().join("target");
        std::fs::create_dir_all(&parent).unwrap();
        let root = parent.join(format!(
            "selected-runtime-{}",
            hex::encode(crate::rng::bytes32())
        ));
        std::fs::create_dir(&root).unwrap();
        mode(&root, 0o700);
        std::fs::write(root.join("descriptor.json"), DESCRIPTOR).unwrap();
        mode(&root.join("descriptor.json"), 0o644);
        std::fs::create_dir(root.join("mesh")).unwrap();
        mode(&root.join("mesh"), 0o755);
        std::fs::create_dir(root.join("mesh/supervisor")).unwrap();
        mode(&root.join("mesh/supervisor"), 0o2750);
        Self { root }
    }
    fn target(&self) -> DeploymentTarget {
        DeploymentTarget {
            version: 1,
            target_id: "selected-runtime-fixture".into(),
            role: DeploymentRole::DedicatedTest,
            profile: Profile::L2,
            authority_config: self.root.join("support/authority.json"),
            expected_artifacts_manifest: self.root.join("support/inventory.json"),
            codesign_pins_file: self.root.join("support/pins.json"),
            signing_identity_mode: DeploymentSigningMode::LocalPins,
            layout: deployment::DeploymentLayout {
                binary_dir: self.root.join("bin"),
                custody_bundle: self.root.join("support/Custody.app"),
                sandbox_dir: self.root.join("sandbox"),
                socket_root: self.root.join("mesh"),
                state_root: self.root.join("state"),
                audit_root: self.root.join("audit"),
                cas_store_root: self.root.join("cas"),
                staging_root: self.root.join("stage"),
                support_root: self.root.join("support"),
                launchd_namespace: "com.enterprise.selected-runtime.fixture".into(),
                mach_service: "com.enterprise.selected-runtime.fixture.exception".into(),
            },
            broker: None,
            shared_read_only_inputs: Vec::new(),
        }
    }
    fn specs(&self) -> Vec<Spec> {
        let mut specs = runtime_specs(
            &self.target(),
            &self.root.join("descriptor.json"),
            &hex::encode(Sha256::digest(DESCRIPTOR)),
        )
        .unwrap();
        for spec in &mut specs {
            if let Expected::Directory { gid, .. } = &mut spec.expected {
                *gid = unsafe { libc::getegid() };
            }
        }
        specs
    }
    fn open(&self) -> SelectedRuntime {
        self.open_with(|| Ok(()))
    }
    fn open_with(&self, check: impl FnMut() -> Check<()> + 'static) -> SelectedRuntime {
        let mut owner = SelectedRuntime::empty();
        owner.context = Some(Context::Fixture(Box::new(check)));
        owner.open(
            self.specs(),
            Protection::Fixture {
                root: self.root.clone(),
                uid: unsafe { libc::geteuid() },
            },
            until(),
        );
        owner.revalidate(until());
        owner
    }
    fn path(&self, role: Role) -> PathBuf {
        self.root.join(match role {
            Role::Descriptor => "descriptor.json",
            Role::Mesh => "mesh",
            Role::Supervisor => "mesh/supervisor",
        })
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Only software fixture paths, including unsafe-mode negative cases.
        let _ = std::fs::set_permissions(
            self.root.join("mesh"),
            std::fs::Permissions::from_mode(0o755),
        );
        let _ = std::fs::set_permissions(
            self.root.join("mesh/supervisor"),
            std::fs::Permissions::from_mode(0o750),
        );
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn mode(path: &Path, bits: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits)).unwrap();
}
fn until() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
#[test]
fn sibling_borrow_is_same_admitted_mesh_and_refuses_after_original_replacement() {
    let fixture = Fixture::new();
    let mut owner = fixture.open();
    owner.require_current(until()).unwrap();
    let original = owner.mesh_parent().unwrap().as_raw_fd();
    assert_eq!(
        original,
        route(&owner, Role::Mesh)
            .nodes
            .last()
            .unwrap()
            .file
            .as_raw_fd()
    );
    let old = fixture.root.join("mesh-original");
    std::fs::rename(fixture.path(Role::Mesh), &old).unwrap();
    std::fs::create_dir(fixture.path(Role::Mesh)).unwrap();
    mode(&fixture.path(Role::Mesh), 0o755);
    assert!(owner.require_current(until()).is_err());
    assert!(owner.mesh_parent().is_err());
    std::fs::remove_dir(fixture.path(Role::Mesh)).unwrap();
    std::fs::rename(old, fixture.path(Role::Mesh)).unwrap();
    assert!(owner.require_current(until()).is_err());
    assert!(owner.mesh_parent().is_err());
}
#[test]
fn sibling_api_rejects_empty_owner_and_expired_endpoint() {
    let mut empty = SelectedRuntime::empty();
    assert!(empty.mesh_parent().is_err());
    assert!(empty.supervisor_parent().is_err());
    assert!(empty.require_current(until()).is_err());
    let fixture = Fixture::new();
    let mut owner = fixture.open();
    assert!(owner.require_current(Instant::now()).is_err());
    assert!(owner.mesh_parent().is_err());
    assert!(owner.supervisor_parent().is_err());
}

#[test]
fn mesh_parent_lease_shares_same_file_and_retains_it_after_runtime_drop() {
    let fixture = Fixture::new();
    let mut owner = fixture.open();
    let first = owner.mesh_parent_lease(until()).unwrap();
    let second = owner.mesh_parent_lease(until()).unwrap();
    let held = &route(&owner, Role::Mesh).nodes.last().unwrap().file;
    assert!(Arc::ptr_eq(&first, held));
    assert!(Arc::ptr_eq(&first, &second));
    let fd = first.as_raw_fd();
    let inode = first.metadata().unwrap().ino();
    assert_eq!(fd, owner.mesh_parent().unwrap().as_raw_fd());
    drop(owner);
    assert_eq!(first.as_raw_fd(), fd);
    assert_eq!(first.metadata().unwrap().ino(), inode);
    drop(first);
    assert_eq!(second.as_raw_fd(), fd);
    assert_eq!(second.metadata().unwrap().ino(), inode);
    assert!(unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0);
}

#[test]
fn mesh_parent_lease_revalidates_and_cannot_adopt_or_revive_replaced_original() {
    let fixture = Fixture::new();
    let mut owner = fixture.open();
    let original = owner.mesh_parent_lease(until()).unwrap();
    let inode = original.metadata().unwrap().ino();
    let saved = fixture.root.join("mesh-before-lease-replacement");
    std::fs::rename(fixture.path(Role::Mesh), &saved).unwrap();
    std::fs::create_dir(fixture.path(Role::Mesh)).unwrap();
    mode(&fixture.path(Role::Mesh), 0o755);
    assert!(owner.mesh_parent_lease(until()).is_err());
    assert_eq!(original.metadata().unwrap().ino(), inode);
    assert!(Arc::ptr_eq(
        &original,
        &route(&owner, Role::Mesh).nodes.last().unwrap().file
    ));
    std::fs::remove_dir(fixture.path(Role::Mesh)).unwrap();
    std::fs::rename(saved, fixture.path(Role::Mesh)).unwrap();
    assert!(owner.mesh_parent_lease(until()).is_err());
    assert_eq!(original.metadata().unwrap().ino(), inode);
}

#[test]
fn mesh_parent_lease_expiry_is_terminal_and_never_reopens_original() {
    let fixture = Fixture::new();
    let mut owner = fixture.open();
    let original = owner.mesh_parent_lease(until()).unwrap();
    let fd = original.as_raw_fd();
    assert!(owner.mesh_parent_lease(Instant::now()).is_err());
    assert!(owner.mesh_parent_lease(until()).is_err());
    assert_eq!(
        route(&owner, Role::Mesh)
            .nodes
            .last()
            .unwrap()
            .file
            .as_raw_fd(),
        fd
    );
    assert!(original.metadata().is_ok());
}
#[test]
fn supervisor_borrow_retains_exact_original_and_refuses_replacement_without_revival() {
    let fixture = Fixture::new();
    let mut owner = fixture.open();
    owner.require_current(until()).unwrap();
    let original = owner.supervisor_parent().unwrap().as_raw_fd();
    assert_eq!(
        original,
        route(&owner, Role::Supervisor)
            .nodes
            .last()
            .unwrap()
            .file
            .as_raw_fd()
    );
    assert_ne!(original, owner.mesh_parent().unwrap().as_raw_fd());
    let saved = fixture.root.join("supervisor-original");
    std::fs::rename(fixture.path(Role::Supervisor), &saved).unwrap();
    std::fs::create_dir(fixture.path(Role::Supervisor)).unwrap();
    mode(&fixture.path(Role::Supervisor), 0o750);
    assert!(owner.require_current(until()).is_err());
    assert!(owner.supervisor_parent().is_err());
    assert_eq!(
        route(&owner, Role::Supervisor)
            .nodes
            .last()
            .unwrap()
            .file
            .as_raw_fd(),
        original
    );
    std::fs::remove_dir(fixture.path(Role::Supervisor)).unwrap();
    std::fs::rename(saved, fixture.path(Role::Supervisor)).unwrap();
    assert!(owner.require_current(until()).is_err());
    assert!(owner.supervisor_parent().is_err());
}
fn has(owner: &SelectedRuntime, role: Role, reason: Reason) -> bool {
    owner
        .refusals
        .iter()
        .any(|error| error.role == Some(role) && error.reason == reason)
}
fn route(owner: &SelectedRuntime, role: Role) -> &HeldRoute {
    owner
        .routes
        .iter()
        .find(|route| route.spec.role == role)
        .unwrap()
}

#[test]
fn production_contract_keeps_exact_mesh_supervisor_modes_groups_and_descriptor_digest() {
    let fixture = Fixture::new();
    let target = fixture.target();
    target.validate().unwrap();
    let specs = runtime_specs(&target, &fixture.path(Role::Descriptor), &"a".repeat(64)).unwrap();
    assert_eq!(specs.len(), 3);
    assert!(matches!(&specs[0].expected, Expected::Descriptor(hash) if hash == &"a".repeat(64)));
    assert!(matches!(
        &specs[1].expected,
        Expected::Directory {
            gid: 0,
            mode: 0o755
        }
    ));
    assert!(matches!(
        &specs[2].expected,
        Expected::Directory {
            gid: 8716,
            mode: 0o2750
        }
    ));
    assert_eq!(specs[2].path, target.layout.socket_root.join("supervisor"));
}

#[test]
fn exact_target_shape_and_runtime_route_cannot_widen() {
    let fixture = Fixture::new();
    let target = fixture.target();
    assert!(target_scope(&target));
    for variant in 0..7 {
        let mut changed = target.clone();
        match variant {
            0 => changed.role = DeploymentRole::ExistingUpgrade,
            1 => changed.profile = Profile::L1,
            2 => changed.profile = Profile::L3,
            3 => changed.signing_identity_mode = DeploymentSigningMode::TeamId,
            4 => {
                changed.broker = Some(deployment::DeploymentBroker {
                    base_dir: fixture.root.join("broker"),
                    tuf_root_file: fixture.root.join("tuf"),
                })
            }
            5 => changed
                .shared_read_only_inputs
                .push(changed.authority_config.clone()),
            _ => {
                changed.role = DeploymentRole::ExistingUpgrade;
                changed.profile = Profile::L3;
            }
        }
        assert!(!target_scope(&changed));
    }
    assert_eq!(
        binding(&target.layout.socket_root, Profile::L2, &target),
        Ok(())
    );
    for profile in [Profile::L1, Profile::L3] {
        assert_eq!(
            binding(&target.layout.socket_root, profile, &target),
            Err(Reason::ProfileMismatch)
        );
    }
    assert_eq!(
        binding(&fixture.root.join("other"), Profile::L2, &target),
        Err(Reason::RouteMismatch)
    );
}

#[test]
fn production_non_native_or_nonroot_refusal_has_no_original_or_service_effect() {
    if !cfg!(target_os = "macos") || unsafe { libc::geteuid() } != 0 {
        let owner = SelectedRuntime::acquire_selected(
            Path::new("/unopened-selected-runtime"),
            Profile::L2,
            until(),
        );
        assert!(owner.poisoned && owner.routes.is_empty() && owner.context.is_none());
        let expected = if cfg!(target_os = "macos") {
            Reason::RootRequired
        } else {
            Reason::NativeRequired
        };
        assert_eq!(owner.refusals[0].reason, expected);
        assert!(
            refuse_selected_start(Path::new("/unopened-selected-runtime"), Profile::L2).is_err()
        );
    } else {
        assert_eq!(native_root(), Ok(()));
    }
}

#[test]
fn actual_software_originals_remain_read_only_and_unchanged_across_revalidation() {
    let fixture = Fixture::new();
    let before = [Role::Descriptor, Role::Mesh, Role::Supervisor].map(|role| {
        let metadata = std::fs::metadata(fixture.path(role)).unwrap();
        (role, Stamp::of(&metadata, role == Role::Descriptor))
    });
    let mut owner = fixture.open();
    assert!(!owner.poisoned);
    assert!(owner.revalidate(until()));
    assert!(owner.refusals.is_empty());
    for held in &owner.routes {
        assert!(held.admitted);
        for node in &held.nodes {
            held.protection.inspect(&node.file).unwrap();
        }
    }
    for (role, old) in before {
        assert!(
            Stamp::of(
                &std::fs::metadata(fixture.path(role)).unwrap(),
                role == Role::Descriptor
            ) == old
        );
    }
    assert_eq!(
        std::fs::read(fixture.path(Role::Descriptor)).unwrap(),
        DESCRIPTOR
    );
}

#[test]
fn missing_runtime_leaf_never_gets_created_and_other_originals_survive() {
    let fixture = Fixture::new();
    std::fs::remove_dir(fixture.path(Role::Supervisor)).unwrap();
    let owner = fixture.open();
    assert!(has(&owner, Role::Supervisor, Reason::Metadata));
    assert!(!fixture.path(Role::Supervisor).exists());
    assert!(route(&owner, Role::Descriptor).admitted && route(&owner, Role::Mesh).admitted);
    assert!(!route(&owner, Role::Supervisor).nodes.is_empty());
}

#[test]
fn every_runtime_mode_must_be_exact_and_is_never_repaired() {
    for (role, modes) in [
        (Role::Mesh, vec![0o700, 0o750, 0o775, 0o2755]),
        (Role::Supervisor, vec![0o750, 0o2755, 0o2770, 0o777]),
    ] {
        for bits in modes {
            let fixture = Fixture::new();
            mode(&fixture.path(role), bits);
            let owner = fixture.open();
            assert!(has(&owner, role, Reason::Protection));
            assert_eq!(
                std::fs::metadata(fixture.path(role)).unwrap().mode() & 0o7777,
                bits
            );
        }
    }
}

#[test]
fn incorrect_runtime_group_and_ancestry_owner_are_refused_without_chown() {
    let fixture = Fixture::new();
    let mut specs = fixture.specs();
    if let Expected::Directory { gid, .. } = &mut specs[2].expected {
        *gid = gid.wrapping_add(1);
    }
    let mut owner = SelectedRuntime::empty();
    owner.open(
        specs,
        Protection::Fixture {
            root: fixture.root.clone(),
            uid: unsafe { libc::geteuid() },
        },
        until(),
    );
    assert!(has(&owner, Role::Supervisor, Reason::Protection));
    let mut owner = SelectedRuntime::empty();
    owner.open(
        fixture.specs(),
        Protection::Fixture {
            root: fixture.root.clone(),
            uid: unsafe { libc::geteuid() }.wrapping_add(1),
        },
        until(),
    );
    assert!(owner
        .routes
        .iter()
        .all(|route| !route.admitted && route.nodes.len() == 1));
    assert_eq!(
        std::fs::metadata(fixture.path(Role::Supervisor))
            .unwrap()
            .gid(),
        unsafe { libc::getegid() }
    );
}

#[test]
fn writable_ancestry_refuses_all_routes_and_preserves_that_ancestry() {
    let fixture = Fixture::new();
    mode(&fixture.root, 0o777);
    let owner = fixture.open();
    for role in [Role::Descriptor, Role::Mesh, Role::Supervisor] {
        assert!(has(&owner, role, Reason::Protection));
    }
    assert_eq!(
        std::fs::metadata(&fixture.root).unwrap().mode() & 0o7777,
        0o777
    );
    mode(&fixture.root, 0o700);
}

#[test]
fn symbolic_link_leaf_and_ancestor_are_not_followed_or_adopted() {
    for role in [Role::Descriptor, Role::Supervisor, Role::Mesh] {
        let fixture = Fixture::new();
        let path = fixture.path(role);
        let saved = fixture.root.join("saved");
        std::fs::rename(&path, &saved).unwrap();
        symlink(&saved, &path).unwrap();
        let owner = fixture.open();
        assert!(has(&owner, role, Reason::Type));
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(&saved, &path).unwrap();
    }
}

#[test]
fn fifo_and_regular_file_runtime_names_refuse_without_opening_or_repairing() {
    for fifo in [false, true] {
        let fixture = Fixture::new();
        let path = fixture.path(Role::Supervisor);
        std::fs::remove_dir(&path).unwrap();
        if fifo {
            let name = CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        } else {
            std::fs::write(&path, b"foreign node").unwrap();
        }
        let before = Identity::of(&std::fs::symlink_metadata(&path).unwrap());
        let owner = fixture.open();
        assert!(has(&owner, Role::Supervisor, Reason::Type));
        assert_eq!(
            Identity::of(&std::fs::symlink_metadata(&path).unwrap()),
            before
        );
        std::fs::remove_file(&path).unwrap();
    }
}

#[test]
fn descriptor_hash_links_and_size_are_independent_required_original_properties() {
    for variant in 0..4 {
        let fixture = Fixture::new();
        let path = fixture.path(Role::Descriptor);
        let expected = match variant {
            0 => {
                std::fs::write(&path, b"changed descriptor").unwrap();
                Reason::DescriptorMismatch
            }
            1 => {
                std::fs::hard_link(&path, fixture.root.join("descriptor-alias")).unwrap();
                Reason::Links
            }
            2 => {
                std::fs::write(&path, b"").unwrap();
                Reason::Size
            }
            _ => {
                std::fs::write(&path, vec![b'x'; deployment::MAX_DESCRIPTOR_BYTES + 1]).unwrap();
                Reason::Size
            }
        };
        let before = std::fs::read(&path).unwrap();
        let owner = fixture.open();
        assert!(has(&owner, Role::Descriptor, expected));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(route(&owner, Role::Mesh).admitted && route(&owner, Role::Supervisor).admitted);
    }
}

#[test]
fn failed_open_keeps_actual_partial_descriptors_for_owner_lifetime() {
    let fixture = Fixture::new();
    mode(&fixture.path(Role::Supervisor), 0o777);
    let mut owner = fixture.open();
    let held = route(&owner, Role::Supervisor);
    assert!(!held.admitted && held.nodes.last().unwrap().leaf);
    let descriptors = owner
        .routes
        .iter()
        .flat_map(|route| route.nodes.iter().map(|node| node.file.as_raw_fd()))
        .collect::<Vec<_>>();
    for descriptor in &descriptors {
        assert!(unsafe { libc::fcntl(*descriptor, libc::F_GETFD) } >= 0);
    }
    assert!(!owner.revalidate(until()));
    let retained = owner
        .routes
        .iter()
        .flat_map(|route| route.nodes.iter().map(|node| node.file.as_raw_fd()))
        .collect::<Vec<_>>();
    assert_eq!(retained, descriptors);
}

#[test]
fn descriptor_replacement_with_identical_bytes_does_not_replace_the_original() {
    let fixture = Fixture::new();
    let mut owner = fixture.open();
    let path = fixture.path(Role::Descriptor);
    let original = route(&owner, Role::Descriptor)
        .nodes
        .last()
        .unwrap()
        .file
        .metadata()
        .unwrap()
        .ino();
    std::fs::rename(&path, fixture.root.join("old-descriptor")).unwrap();
    std::fs::write(&path, DESCRIPTOR).unwrap();
    mode(&path, 0o644);
    assert!(!owner.revalidate(until()));
    assert!(has(&owner, Role::Descriptor, Reason::Changed));
    assert_eq!(
        route(&owner, Role::Descriptor)
            .nodes
            .last()
            .unwrap()
            .file
            .metadata()
            .unwrap()
            .ino(),
        original
    );
}

#[test]
fn renamed_runtime_directory_and_recreated_exact_modes_revoke_the_same_owner() {
    let fixture = Fixture::new();
    let mut owner = fixture.open();
    let original = route(&owner, Role::Mesh)
        .nodes
        .last()
        .unwrap()
        .file
        .metadata()
        .unwrap()
        .ino();
    std::fs::rename(fixture.path(Role::Mesh), fixture.root.join("old-mesh")).unwrap();
    std::fs::create_dir(fixture.path(Role::Mesh)).unwrap();
    mode(&fixture.path(Role::Mesh), 0o755);
    std::fs::create_dir(fixture.path(Role::Supervisor)).unwrap();
    mode(&fixture.path(Role::Supervisor), 0o2750);
    assert!(!owner.revalidate(until()));
    assert!(
        has(&owner, Role::Mesh, Reason::Changed) && has(&owner, Role::Supervisor, Reason::Changed)
    );
    assert_eq!(
        route(&owner, Role::Mesh)
            .nodes
            .last()
            .unwrap()
            .file
            .metadata()
            .unwrap()
            .ino(),
        original
    );
}

#[test]
fn in_place_descriptor_and_mode_changes_are_both_retained_without_short_circuit() {
    let fixture = Fixture::new();
    let mut owner = fixture.open();
    std::fs::write(fixture.path(Role::Descriptor), b"changed in place").unwrap();
    mode(&fixture.path(Role::Mesh), 0o775);
    mode(&fixture.path(Role::Supervisor), 0o2770);
    assert!(!owner.revalidate(until()));
    assert!(has(&owner, Role::Descriptor, Reason::DescriptorMismatch));
    assert!(
        has(&owner, Role::Mesh, Reason::Protection)
            && has(&owner, Role::Supervisor, Reason::Protection)
    );
    assert_eq!(
        std::fs::read(fixture.path(Role::Descriptor)).unwrap(),
        b"changed in place"
    );
}

#[test]
fn permanent_poison_prevents_a_restored_mode_from_reviving_the_original_owner() {
    let fixture = Fixture::new();
    let mut owner = fixture.open();
    mode(&fixture.path(Role::Supervisor), 0o2770);
    assert!(!owner.revalidate(until()));
    let before = owner.refusals.clone();
    mode(&fixture.path(Role::Supervisor), 0o2750);
    assert!(!owner.revalidate(until()));
    assert!(owner.refusals.starts_with(&before));
    assert_eq!(owner.refusals.last().unwrap().reason, Reason::Poisoned);
    assert!(route(&owner, Role::Supervisor).admitted);
}

#[test]
fn context_loss_and_original_loss_are_independent_retained_boundary_failures() {
    let fixture = Fixture::new();
    let valid = Rc::new(Cell::new(true));
    let check = valid.clone();
    let mut owner = fixture.open_with(move || {
        if check.get() {
            Ok(())
        } else {
            Err(Reason::ContextChanged)
        }
    });
    assert!(!owner.poisoned);
    valid.set(false);
    std::fs::remove_file(fixture.path(Role::Descriptor)).unwrap();
    assert!(!owner.revalidate(until()));
    assert!(owner
        .refusals
        .iter()
        .any(|error| error.reason == Reason::ContextChanged));
    assert!(has(&owner, Role::Descriptor, Reason::Metadata));
    assert!(route(&owner, Role::Mesh).admitted && route(&owner, Role::Supervisor).admitted);
}

#[test]
fn expiry_cannot_admit_or_revalidate_an_owner_and_never_drops_held_originals() {
    let fixture = Fixture::new();
    let mut owner = fixture.open();
    let count = owner
        .routes
        .iter()
        .map(|route| route.nodes.len())
        .sum::<usize>();
    assert!(!owner.revalidate(Instant::now()));
    assert!(owner
        .refusals
        .iter()
        .any(|error| error.reason == Reason::Deadline));
    assert_eq!(
        owner
            .routes
            .iter()
            .map(|route| route.nodes.len())
            .sum::<usize>(),
        count
    );
    let mut empty = SelectedRuntime::empty();
    empty.open(
        fixture.specs(),
        Protection::Fixture {
            root: fixture.root.clone(),
            uid: unsafe { libc::geteuid() },
        },
        Instant::now(),
    );
    assert!(
        empty.poisoned
            && empty
                .routes
                .iter()
                .all(|route| route.nodes.is_empty() && !route.admitted)
    );
}

#[test]
fn lexical_invalid_paths_and_fixture_root_escape_refuse_without_opening() {
    let fixture = Fixture::new();
    for path in [
        fixture.root.join("mesh/../mesh/supervisor"),
        PathBuf::from("relative/runtime"),
        PathBuf::from("/outside-fixture/runtime"),
    ] {
        let mut held = HeldRoute::new(
            Spec {
                role: Role::Supervisor,
                path,
                expected: Expected::Directory {
                    gid: unsafe { libc::getegid() },
                    mode: 0o2750,
                },
            },
            Protection::Fixture {
                root: fixture.root.clone(),
                uid: unsafe { libc::geteuid() },
            },
        );
        assert_eq!(held.open(until()), Err(Reason::InvalidPath));
        assert!(held.nodes.is_empty());
    }
}

#[test]
fn unrelated_directory_entries_do_not_replace_protected_original_identity() {
    let fixture = Fixture::new();
    let mut owner = fixture.open();
    std::fs::write(
        fixture.path(Role::Mesh).join("unrelated"),
        b"fixture-only other entry",
    )
    .unwrap();
    assert!(owner.revalidate(until()));
    assert!(owner.refusals.is_empty());
}

#[test]
fn retained_refusals_do_not_disclose_synthetic_descriptor_bytes_or_claim_dependencies() {
    let fixture = Fixture::new();
    let mut owner = fixture.open();
    owner.context = None;
    assert!(!owner.revalidate(until()));
    assert!(!format!("{:?}", owner.refusals).contains(std::str::from_utf8(DESCRIPTOR).unwrap()));
    for requirement in [
        "power/USB",
        "primary/held",
        "Mach",
        "custody",
        "BOTH-anchor",
        "kqueue/SCDynamicStore",
        "Begin",
    ] {
        assert!(MISSING_DEPENDENCIES.contains(requirement));
    }
}

struct BindingSession(std::sync::atomic::AtomicBool);
impl SelectedSessionVeto for BindingSession {
    fn veto_atomic(&self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}
fn binding_session() -> Arc<BindingSession> {
    Arc::new(BindingSession(std::sync::atomic::AtomicBool::new(false)))
}

#[test]
fn original_input_binding_checks_both_arc_identities_and_preserves_cap_without_observing_health() {
    use std::sync::atomic::Ordering;
    for changed in 0..4 {
        let monitor = Arc::new(());
        let session = binding_session();
        let offered_monitor = if changed & 1 != 0 {
            Arc::new(())
        } else {
            monitor.clone()
        };
        let offered_session = if changed & 2 != 0 {
            binding_session()
        } else {
            session.clone()
        };
        // Even a past cap is returned verbatim by this identity-only check;
        // mandatory full revalidation separately refuses expired authority.
        let end = Instant::now();
        let result = original_input_binding(
            Some((&monitor, &session, end)),
            &offered_monitor,
            &offered_session,
        );
        if changed == 0 {
            assert_eq!(result, Ok(end));
            assert!(!session.0.load(Ordering::SeqCst));
        } else {
            assert_eq!(result, Err(InputBindingFailure::Mismatch));
            assert!(session.0.load(Ordering::SeqCst) && offered_session.0.load(Ordering::SeqCst));
        }
    }
}

#[test]
fn missing_or_mismatched_input_vetoes_originals_before_any_caller_owner_cleanup() {
    use std::sync::atomic::Ordering;
    struct OtherOwner(Arc<BindingSession>, Arc<BindingSession>);
    impl Drop for OtherOwner {
        fn drop(&mut self) {
            assert!(
                self.0 .0.load(Ordering::SeqCst) && self.1 .0.load(Ordering::SeqCst),
                "all original sessions must be negative before caller native cleanup"
            );
        }
    }
    let monitor = Arc::new(());
    let session = binding_session();
    let offered = binding_session();
    let cleanup = OtherOwner(session.clone(), offered.clone());
    assert_eq!(
        original_input_binding(Some((&monitor, &session, until())), &monitor, &offered),
        Err(InputBindingFailure::Mismatch)
    );
    drop(cleanup);
    let offered = binding_session();
    assert_eq!(
        original_input_binding::<(), _>(None, &monitor, &offered),
        Err(InputBindingFailure::Missing)
    );
    assert!(offered.0.load(Ordering::SeqCst));
}
