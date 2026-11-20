//! Ordinary actual original-FD/closed-mapping scope ONLY. No native live scope,
//! cleared birth/guard/approval/EX/release record or phase capability is faked.
//! Portable modeled-link cases change fixture cache expectations explicitly;
//! they do NOT claim the filesystem exhibited actual link-count variation.
use super::*;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

fn template() -> DeploymentTarget {
    DeploymentTarget::parse(&serde_json::to_vec(&serde_json::json!({"version":1,"target_id":"live-directory-fixture",
        "role":"dedicated-test","profile":"L2","signing_identity_mode":"local-pins",
        "authority_config":"/template/support/custody.json","expected_artifacts_manifest":"/template/config/inventory.json",
        "codesign_pins_file":"/template/support/pins.json","broker":null,"shared_read_only_inputs":[],
        "layout":{"binary_dir":"/template/bin","custody_bundle":"/template/support/Custody.app","sandbox_dir":"/template/sandbox",
        "socket_root":"/template/run","state_root":"/template/state","audit_root":"/template/audit","cas_store_root":"/template/cas",
        "staging_root":"/template/stage","support_root":"/template/support","launchd_namespace":"com.mcpmac.livefixture",
        "mach_service":"com.mcpmac.livefixture.exception"}})).unwrap()).unwrap()
}
#[test]
fn closed_output_mapping_is_exact_audit_five_and_total_seventeen_without_auxiliary_inheritance() {
    let target = template();
    let specs = fixed_outputs(&target).unwrap();
    assert_eq!(specs.len(), 17);
    let audit = specs
        .iter()
        .filter(|spec| spec.role == OutputRole::Audit)
        .collect::<Vec<_>>();
    assert_eq!(audit.len(), 5);
    for daemon in crate::ctl::START_ORDER {
        let spec = audit
            .iter()
            .find(|spec| spec.path == target.layout.audit_root.join(daemon.dir_name()))
            .unwrap();
        assert_eq!(
            (spec.uid, spec.gid, spec.mode),
            (daemon.uid(), 8720, 0o2750)
        );
    }
    for path in [
        target.layout.socket_root.join("jobs"),
        target.layout.socket_root.join("supervisor"),
        target.layout.socket_root.join("browser"),
        target.layout.state_root.join("cas/tuf"),
        target.layout.state_root.join("cas/tuf/repo"),
        target.layout.audit_root.clone(),
        target.layout.support_root.clone(),
    ] {
        assert!(!specs.iter().any(|spec| spec.path == path));
    }
}
#[test]
fn duplicate_canonical_output_roles_are_refused_instead_of_merged() {
    let mut target = template();
    target.layout.cas_store_root = target.layout.state_root.join("cas");
    assert!(fixed_outputs(&target)
        .err()
        .unwrap()
        .is("BIRTH_LIVE_DIRECTORY_ROLE_ALIAS"));
}

struct Fixture {
    path: PathBuf,
    directory: Directory,
    original: OriginalOutput,
    protection: Protection,
}
impl Fixture {
    fn new() -> Self {
        let path = std::env::current_dir().unwrap().join(format!(
            ".birth-live-directory-{}",
            hex::encode(enclave_core::rng::bytes32())
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        let fd = unsafe {
            libc::open(
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC,
            )
        };
        assert!(fd >= 0);
        let protection = Protection {
            owner: (unsafe { libc::geteuid() }, unsafe { libc::getegid() }),
            native_acl: false,
        };
        let directory =
            Directory::capture(unsafe { File::from_raw_fd(fd) }, None, true, protection).unwrap();
        let original = OriginalOutput {
            path: path.clone(),
            stamp: directory.stamp.clone(),
            links: directory.links,
            fd: directory.file.as_raw_fd(),
            role: OutputRole::Audit,
        };
        Self {
            path,
            directory,
            original,
            protection,
        }
    }
    fn named(&self) -> File {
        let name = CString::new(self.path.as_os_str().as_bytes()).unwrap();
        let fd = unsafe {
            libc::open(
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC,
            )
        };
        assert!(fd >= 0);
        unsafe { File::from_raw_fd(fd) }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
        let _ = std::fs::remove_dir_all(self.path.with_extension("moved"));
    }
}

#[test]
#[cfg(not(target_os = "macos"))]
fn modeled_cached_link_mismatch_preserves_cache_under_original_fd_primitive() {
    let mut fixture = Fixture::new();
    // Model ONLY the cached prior link count on the actual original FD. Some
    // shared filesystems report constant directory nlink=1 even after unlink.
    // No native phase, real temporal link drift or provenance is fabricated.
    let actual = stat(&fixture.directory.file).unwrap().nlink();
    assert!(actual > 0);
    let old = actual.checked_add(1).unwrap();
    fixture.directory.links = old;
    fixture.original.links = old;
    assert!(fixture
        .directory
        .current(&fixture.directory.file, fixture.protection, true)
        .is_err());
    fixture
        .original
        .current_inode(
            &fixture.directory,
            &fixture.directory.file,
            fixture.protection,
        )
        .unwrap();
    fixture
        .original
        .current_inode(&fixture.directory, &fixture.named(), fixture.protection)
        .unwrap();
    assert_eq!(fixture.directory.links, old);
    assert_eq!(fixture.original.links, old);
}
#[test]
fn same_mode_named_replacement_is_never_live_original() {
    let fixture = Fixture::new();
    std::fs::rename(&fixture.path, fixture.path.with_extension("moved")).unwrap();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&fixture.path)
        .unwrap();
    assert!(fixture
        .original
        .current_inode(&fixture.directory, &fixture.named(), fixture.protection)
        .is_err());
}
#[test]
fn changed_mode_or_descriptor_flags_refuse_without_cached_stamp_update() {
    let fixture = Fixture::new();
    std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(0o750)).unwrap();
    assert!(fixture
        .original
        .current_inode(
            &fixture.directory,
            &fixture.directory.file,
            fixture.protection
        )
        .is_err());
    std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let old = unsafe { libc::fcntl(fixture.directory.file.as_raw_fd(), libc::F_GETFL) };
    assert!(old >= 0);
    assert_eq!(
        unsafe {
            libc::fcntl(
                fixture.directory.file.as_raw_fd(),
                libc::F_SETFL,
                old & !libc::O_NONBLOCK,
            )
        },
        0
    );
    assert!(fixture
        .original
        .current_inode(
            &fixture.directory,
            &fixture.directory.file,
            fixture.protection
        )
        .is_err());
    assert_eq!(fixture.directory.stamp.mode & 0o7777, 0o700);
}
#[test]
fn removed_original_name_cannot_supply_required_named_descriptor() {
    let fixture = Fixture::new();
    std::fs::remove_dir(&fixture.path).unwrap();
    let parent = File::open(fixture.path.parent().unwrap()).unwrap();
    // Full production observation requires BOTH held and original named FDs.
    // Name removal refuses even on a filesystem whose detached FD reports1.
    assert!(open_at(&parent, &fixture.path, true).is_err());
}
#[test]
#[cfg(not(target_os = "macos"))]
fn modeled_child_link_mismatch_stays_strict_beside_actual_live_parent_primitive() {
    let parent = Fixture::new();
    let child = parent.path.join("strict-original-child");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&child)
        .unwrap();
    let child_file = open_at(&parent.directory.file, &child, true).unwrap();
    let mut child_directory =
        Directory::capture(child_file, None, true, parent.protection).unwrap();
    // Explicit fixture-only cache model; no real child link drift is claimed.
    child_directory.links = stat(&child_directory.file)
        .unwrap()
        .nlink()
        .checked_add(1)
        .unwrap();
    parent
        .original
        .current_inode(&parent.directory, &parent.directory.file, parent.protection)
        .unwrap();
    assert!(child_directory
        .current(&child_directory.file, parent.protection, true)
        .is_err());
}

// Coordinator measured actual positive nlink drift on the configured Mac
// runner: both native cases below passed SOURCE1. Retain those real checks;
// portable modeled counterparts above do not replace the native evidence.
#[test]
#[cfg(target_os = "macos")]
fn original_fd_primitive_allows_live_positive_links_without_replacing_cached_baseline() {
    let fixture = Fixture::new();
    let old = fixture.directory.links;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(fixture.path.join("actual-new-output-directory"))
        .unwrap();
    assert_ne!(
        stat(&fixture.directory.file).unwrap().nlink(),
        old,
        "actual link variation capability unavailable"
    );
    assert!(fixture
        .directory
        .current(&fixture.directory.file, fixture.protection, true)
        .is_err());
    fixture
        .original
        .current_inode(
            &fixture.directory,
            &fixture.directory.file,
            fixture.protection,
        )
        .unwrap();
    fixture
        .original
        .current_inode(&fixture.directory, &fixture.named(), fixture.protection)
        .unwrap();
    assert_eq!(fixture.directory.links, old);
    assert_eq!(fixture.original.links, old);
}
#[test]
#[cfg(target_os = "macos")]
fn live_parent_does_not_relax_exact_original_child_directory() {
    let parent = Fixture::new();
    let child = parent.path.join("strict-original-child");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&child)
        .unwrap();
    let child_file = open_at(&parent.directory.file, &child, true).unwrap();
    let child_directory = Directory::capture(child_file, None, true, parent.protection).unwrap();
    let old = child_directory.links;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(child.join("unapproved-child-entry"))
        .unwrap();
    assert_ne!(
        stat(&child_directory.file).unwrap().nlink(),
        old,
        "actual child link variation capability unavailable"
    );
    parent
        .original
        .current_inode(&parent.directory, &parent.directory.file, parent.protection)
        .unwrap();
    assert!(child_directory
        .current(&child_directory.file, parent.protection, true)
        .is_err());
}

// Actual native audit5 admission and postdrop17 promotion, original metadata/
// SOFTWARE exclusion rejection, actual phase mismatch and late-error/expiry
// retention require genuine selected native owners. They remain UNEXERCISED.
// Native coordinator must verify exact path tables and excluded aux/TUF/root
// dirs, real bootstrap log timing, actor socket/state/journal/CAS creation,
// same named/held identity and positive nlinks without any cache/history
// restamp. Portable primitive software cases above cannot establish those capabilities.
// SOURCE1 Linux /workspace measured constant directory nlink1: three
// filesystem-assumption fixtures FAILED. SOURCE1 Mac measured positive link
// drift (two actual cases PASS) but held removed directory nlink2 (zero-link
// fixture FAILED). Both retained failures remain historical evidence.
// Mandatory original named reopening refuses unlink on BOTH filesystems.
// Neither observed detached0, and no numerical-zero coverage is claimed.
// SOURCE2 with three ignored capability cases is preserved but superseded.
// SOURCE3 compiles seven default cases per platform, with two explicitly
// modeled cases on nonMac and two real link-variation cases on the Mac runner.
