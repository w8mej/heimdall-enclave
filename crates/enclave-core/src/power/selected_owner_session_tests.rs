//! Private repository-local records exercise the same parser/retained-source
//! implementation. They never construct native identity or startup authority.
use super::*;
use std::{
    os::unix::fs::{symlink, PermissionsExt},
    sync::{atomic::AtomicU64, Arc},
};

const START: u64 = 1_000_000_000;
const NOW: u64 = 2_000_000_000;
const END: u64 = 62_000_000_000;
fn binding() -> Binding {
    Binding {
        target: "dedicated-test".into(),
        descriptor: "ab".repeat(32),
    }
}
fn boot() -> [u8; 16] {
    *uuid::Uuid::parse_str("c7939a56-427f-48c3-a715-2e32f590687a")
        .unwrap()
        .as_bytes()
}
fn value() -> serde_json::Value {
    serde_json::json!({
        "v":1,"target_id":"dedicated-test","descriptor_sha256":"ab".repeat(32),
        "profile":"L2","signing":"local-pins","boot_session_uuid":"c7939a56-427f-48c3-a715-2e32f590687a",
        "policy_session_id":"cd".repeat(32),"not_before_boot_ns_hex":format!("{START:016x}"),
        "not_after_boot_ns_hex":format!("{END:016x}")
    })
}
fn bytes() -> Vec<u8> {
    serde_json::to_vec(&value()).unwrap()
}
fn mode(path: &Path, bits: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits)).unwrap();
}
struct Fixture {
    root: PathBuf,
    clock: Arc<AtomicU64>,
}
impl Fixture {
    fn new() -> Self {
        let target = std::env::current_dir().unwrap().join("target");
        std::fs::create_dir_all(&target).unwrap();
        let root = target.join(format!(
            "selected-session-{}",
            hex::encode(&crate::rng::bytes32()[..8])
        ));
        std::fs::create_dir(&root).unwrap();
        mode(&root, 0o700);
        std::fs::create_dir(root.join("mesh")).unwrap();
        mode(&root.join("mesh"), 0o755);
        let fixture = Self {
            root,
            clock: Arc::new(AtomicU64::new(NOW)),
        };
        std::fs::write(fixture.path(), bytes()).unwrap();
        mode(&fixture.path(), 0o644);
        fixture
    }
    fn parent(&self) -> PathBuf {
        self.root.join("mesh")
    }
    fn path(&self) -> PathBuf {
        self.parent().join(SESSION_LEAF)
    }
    fn context(&self) -> Context {
        let metadata = std::fs::metadata(&self.root).unwrap();
        Context::Fixture {
            root: self.root.clone(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            binding: binding(),
            clock: self.clock.clone(),
            boot: boot(),
        }
    }
    fn open(&self) -> SelectedOwnerSession {
        SelectedOwnerSession::open(self.context()).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.root, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::set_permissions(self.parent(), std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn session_closed_record_accepts_exact_bound_public_values() {
    let parsed = parse(&bytes(), &binding()).unwrap();
    assert_eq!(parsed.session, [0xcd; 32]);
    assert_eq!(parsed.boot, boot());
    assert_eq!((parsed.start, parsed.end), (START, END));
    let mut other = binding();
    other.target = "other-target".into();
    assert!(parse(&bytes(), &other).is_err());
    other = binding();
    other.descriptor = "ef".repeat(32);
    assert!(parse(&bytes(), &other).is_err());
}

#[test]
fn session_schema_refuses_unknown_duplicate_missing_trailing_and_size() {
    let mut bad = value();
    bad["unexpected"] = serde_json::json!(true);
    assert!(parse(&serde_json::to_vec(&bad).unwrap(), &binding()).is_err());
    for key in value().as_object().unwrap().keys() {
        let mut missing = value();
        missing.as_object_mut().unwrap().remove(key);
        assert!(
            parse(&serde_json::to_vec(&missing).unwrap(), &binding()).is_err(),
            "missing {key}"
        );
        let mut duplicate = bytes();
        duplicate.pop();
        duplicate.extend_from_slice(
            format!(
                ",{}:{} }}",
                serde_json::to_string(key).unwrap(),
                value()[key]
            )
            .as_bytes(),
        );
        assert!(parse(&duplicate, &binding()).is_err(), "duplicate {key}");
    }
    let mut trailing = bytes();
    trailing.extend_from_slice(b" {}");
    for raw in [
        Vec::new(),
        vec![b' '; MAX_RECORD + 1],
        trailing,
        b"null".to_vec(),
        b"[]".to_vec(),
    ] {
        assert!(parse(&raw, &binding()).is_err());
    }
    let mut bounded = bytes();
    bounded.resize(MAX_RECORD, b' ');
    assert!(parse(&bounded, &binding()).is_ok());
    bounded.push(b' ');
    assert!(parse(&bounded, &binding()).is_err());
}

#[test]
fn session_record_refuses_scope_type_hex_uuid_and_interval_substitution() {
    let cases: Vec<(&str, serde_json::Value)> = vec![
        ("v", serde_json::json!(0)),
        ("v", serde_json::json!(2)),
        ("v", serde_json::json!(256)),
        ("v", serde_json::json!("1")),
        ("target_id", serde_json::json!("other")),
        ("profile", serde_json::json!("L1")),
        ("profile", serde_json::json!("L3")),
        ("signing", serde_json::json!("team-id")),
        ("signing", serde_json::json!("LocalPins")),
        ("descriptor_sha256", serde_json::json!("AB".repeat(32))),
        ("descriptor_sha256", serde_json::json!("ab".repeat(31))),
        ("descriptor_sha256", serde_json::json!("ag".repeat(32))),
        ("policy_session_id", serde_json::json!("00".repeat(32))),
        ("policy_session_id", serde_json::json!("CD".repeat(32))),
        ("policy_session_id", serde_json::json!("cd".repeat(33))),
        (
            "boot_session_uuid",
            serde_json::json!("00000000-0000-0000-0000-000000000000"),
        ),
        (
            "boot_session_uuid",
            serde_json::json!("C7939A56-427F-48C3-A715-2E32F590687A"),
        ),
        (
            "boot_session_uuid",
            serde_json::json!("c7939a56427f48c3a7152e32f590687a"),
        ),
        (
            "boot_session_uuid",
            serde_json::json!("c7939a56-427f-48c3-a715-2e32f590687z"),
        ),
        (
            "not_before_boot_ns_hex",
            serde_json::json!("0000000000000000"),
        ),
        (
            "not_before_boot_ns_hex",
            serde_json::json!(format!("{END:016x}")),
        ),
        (
            "not_after_boot_ns_hex",
            serde_json::json!(format!("{START:016x}")),
        ),
        (
            "not_after_boot_ns_hex",
            serde_json::json!("ffffffffffffffff"),
        ),
        (
            "not_after_boot_ns_hex",
            serde_json::json!("0000000e6f7cec0"),
        ),
        (
            "not_after_boot_ns_hex",
            serde_json::json!("0000000E6F7CEC00"),
        ),
        ("not_after_boot_ns_hex", serde_json::json!(END)),
    ];
    for (key, replacement) in cases {
        let mut bad = value();
        bad[key] = replacement;
        assert!(
            parse(&serde_json::to_vec(&bad).unwrap(), &binding()).is_err(),
            "{key}"
        );
    }
}

#[test]
fn session_time_has_exclusive_original_end_and_no_sentinel_or_other_boot() {
    let parsed = parse(&bytes(), &binding()).unwrap();
    let now = Instant::now();
    let end = now + Duration::from_secs(1);
    for current in [START, NOW, END - 1] {
        assert!(time_current(&parsed, current, boot(), now, end).is_ok());
    }
    for current in [0, START - 1, END, u64::MAX] {
        assert!(time_current(&parsed, current, boot(), now, end).is_err());
    }
    assert!(time_current(&parsed, NOW, [0; 16], now, end).is_err());
    assert!(time_current(&parsed, NOW, boot(), end, end).is_err());
    assert!(time_current(&parsed, NOW, boot(), end + Duration::from_nanos(1), end).is_err());
}

#[test]
fn session_boot_conversion_uses_earlier_instant_and_later_boot_without_rounding() {
    let earlier = Instant::now();
    let sampled = earlier + Duration::from_nanos(600);
    let end = conservative_end(earlier, NOW, END).unwrap();
    assert_eq!(end, earlier + Duration::from_nanos(END - NOW));
    assert!(end < sampled + Duration::from_nanos(END - NOW));
    assert_eq!(
        conservative_end(earlier, END - 1, END).unwrap(),
        earlier + Duration::from_nanos(1)
    );
    for (current, limit) in [
        (0, END),
        (u64::MAX, END),
        (NOW, u64::MAX),
        (END, END),
        (END + 1, END),
    ] {
        assert!(conservative_end(earlier, current, limit).is_err());
    }
}

#[test]
fn session_retains_exact_original_files_bytes_hash_and_fixed_instant() {
    let fixture = Fixture::new();
    let owner = fixture.open();
    let until = owner.original_instant_end();
    assert_eq!(owner.source.raw, bytes());
    assert_eq!(
        owner.record_sha256(),
        <[u8; 32]>::from(Sha256::digest(bytes()))
    );
    assert_eq!(owner.policy_session_id(), [0xcd; 32]);
    assert_eq!(owner.expires_boot_ns(), END);
    assert_eq!(owner.source.nodes.len(), 2);
    for _ in 0..3 {
        owner.require_current().unwrap();
        assert_eq!(owner.original_instant_end(), until);
    }
    assert_eq!(format!("{owner:?}"), "SelectedOwnerSession { .. }");
    let before = Stamp::of(&std::fs::metadata(fixture.path()).unwrap());
    drop(owner);
    assert_eq!(
        Stamp::of(&std::fs::metadata(fixture.path()).unwrap()) == before,
        true
    );
    assert_eq!(std::fs::read(fixture.path()).unwrap(), bytes());
}

#[test]
fn session_raw_end_must_match_and_shortening_preserves_every_earlier_cap() {
    let fixture = Fixture::new();
    let owner = fixture.open();
    let original = owner.original_instant_end();
    let cap10 = Instant::now() + Duration::from_secs(10);
    assert_eq!(
        owner.shorten_before(END, cap10).unwrap(),
        cap10.min(original)
    );
    assert_eq!(
        owner
            .shorten_before(END, original + Duration::from_secs(30))
            .unwrap(),
        original
    );
    assert_eq!(owner.original_instant_end(), original);
    assert!(owner.shorten_before(END - 1, cap10).is_err());
    assert!(
        owner.shorten_before(END, cap10).is_err(),
        "a later exact end cannot revive mismatch"
    );
    let owner = fixture.open();
    assert!(owner.shorten_before(END, Instant::now()).is_err());
    assert!(owner.require_current().is_err());
}

#[test]
fn session_initial_interval_boot_and_actual_instant_expiry_refuse() {
    for current in [0, START - 1, END, u64::MAX] {
        let fixture = Fixture::new();
        fixture.clock.store(current, Ordering::SeqCst);
        assert!(SelectedOwnerSession::open(fixture.context()).is_err());
    }
    let fixture = Fixture::new();
    let mut context = fixture.context();
    if let Context::Fixture { boot, .. } = &mut context {
        *boot = [1; 16];
    }
    assert!(SelectedOwnerSession::open(context).is_err());
    let mut owner = fixture.open();
    owner.end = Instant::now();
    assert!(owner.require_current().is_err());
    owner.end = Instant::now() + Duration::from_secs(60);
    assert!(owner.require_current().is_err());
}

#[test]
fn session_initial_record_kinds_links_and_modes_refuse_without_mutation() {
    for variant in 0..8 {
        let fixture = Fixture::new();
        let path = fixture.path();
        match variant {
            0 => mode(&path, 0o666),
            1 => mode(&path, 0o600),
            2 => mode(&path, 0o4644),
            3 => std::fs::hard_link(&path, fixture.root.join("other-link")).unwrap(),
            4 => {
                std::fs::remove_file(&path).unwrap();
                symlink("missing", &path).unwrap();
            }
            5 => {
                std::fs::remove_file(&path).unwrap();
                std::fs::create_dir(&path).unwrap();
                mode(&path, 0o644);
            }
            6 => {
                std::fs::remove_file(&path).unwrap();
                let name = CString::new(path.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o644) }, 0);
                mode(&path, 0o644);
            }
            _ => std::fs::write(&path, vec![b' '; MAX_RECORD + 1]).unwrap(),
        }
        let before = Stamp::of(&std::fs::symlink_metadata(&path).unwrap());
        assert!(
            SelectedOwnerSession::open(fixture.context()).is_err(),
            "variant {variant}"
        );
        assert!(Stamp::of(&std::fs::symlink_metadata(&path).unwrap()) == before);
        if variant == 5 {
            mode(&path, 0o755);
        }
    }
}

#[test]
fn session_wrong_expected_owner_and_group_refuse_in_private_fixture() {
    for owner in [false, true] {
        let fixture = Fixture::new();
        let mut context = fixture.context();
        if let Context::Fixture { uid, gid, .. } = &mut context {
            if owner {
                *uid = uid.wrapping_add(1);
            } else {
                *gid = gid.wrapping_add(1);
            }
        }
        assert!(SelectedOwnerSession::open(context).is_err());
    }
}

#[test]
fn session_unsafe_ancestor_mesh_mode_and_symlink_refuse() {
    for variant in 0..4 {
        let fixture = Fixture::new();
        match variant {
            0 => mode(&fixture.root, 0o770),
            1 => mode(&fixture.parent(), 0o775),
            2 => mode(&fixture.parent(), 0o700),
            _ => {
                std::fs::rename(fixture.parent(), fixture.root.join("saved")).unwrap();
                symlink("saved", fixture.parent()).unwrap();
            }
        }
        assert!(SelectedOwnerSession::open(fixture.context()).is_err());
        if variant == 3 {
            std::fs::remove_file(fixture.parent()).unwrap();
            std::fs::rename(fixture.root.join("saved"), fixture.parent()).unwrap();
        }
    }
}

#[test]
fn session_same_bytes_leaf_replacement_and_unlink_are_terminal() {
    for replace in [false, true] {
        let fixture = Fixture::new();
        let owner = fixture.open();
        std::fs::rename(fixture.path(), fixture.root.join("original")).unwrap();
        if replace {
            std::fs::write(fixture.path(), bytes()).unwrap();
            mode(&fixture.path(), 0o644);
        }
        assert!(owner.require_current().is_err());
        if replace {
            std::fs::remove_file(fixture.path()).unwrap();
        }
        std::fs::rename(fixture.root.join("original"), fixture.path()).unwrap();
        assert!(owner.require_current().is_err());
        assert_eq!(owner.source.raw, bytes());
    }
}

#[test]
fn session_parent_replacement_and_observed_protection_loss_never_revive() {
    for variant in 0..4 {
        let fixture = Fixture::new();
        let owner = fixture.open();
        match variant {
            0 => mode(&fixture.parent(), 0o775),
            1 => mode(&fixture.root, 0o770),
            2 => mode(&fixture.path(), 0o600),
            _ => {
                std::fs::rename(fixture.parent(), fixture.root.join("saved")).unwrap();
                std::fs::create_dir(fixture.parent()).unwrap();
                mode(&fixture.parent(), 0o755);
                std::fs::write(fixture.path(), bytes()).unwrap();
                mode(&fixture.path(), 0o644);
            }
        }
        assert!(owner.require_current().is_err());
        match variant {
            0 => mode(&fixture.parent(), 0o755),
            1 => mode(&fixture.root, 0o700),
            2 => mode(&fixture.path(), 0o644),
            _ => {
                std::fs::remove_file(fixture.path()).unwrap();
                std::fs::remove_dir(fixture.parent()).unwrap();
                std::fs::rename(fixture.root.join("saved"), fixture.parent()).unwrap();
            }
        }
        assert!(owner.require_current().is_err());
    }
}

#[test]
fn session_retained_fixture_root_replacement_refuses_even_same_descendant_names() {
    let fixture = Fixture::new();
    let owner = fixture.open();
    let saved = fixture.root.with_extension("original");
    std::fs::rename(&fixture.root, &saved).unwrap();
    std::fs::create_dir(&fixture.root).unwrap();
    mode(&fixture.root, 0o700);
    assert!(owner.require_current().is_err());
    std::fs::remove_dir(&fixture.root).unwrap();
    std::fs::rename(&saved, &fixture.root).unwrap();
    assert!(owner.require_current().is_err());
}

#[test]
fn session_content_and_link_changes_refuse_then_restoration_cannot_reauthorize() {
    for variant in 0..3 {
        let fixture = Fixture::new();
        let owner = fixture.open();
        match variant {
            0 => std::fs::write(fixture.path(), b"changed").unwrap(),
            1 => {
                let mut changed = bytes();
                changed.push(b' ');
                std::fs::write(fixture.path(), changed).unwrap();
            }
            _ => std::fs::hard_link(fixture.path(), fixture.root.join("other")).unwrap(),
        }
        assert!(owner.require_current().is_err());
        if variant == 2 {
            std::fs::remove_file(fixture.root.join("other")).unwrap();
        } else {
            std::fs::write(fixture.path(), bytes()).unwrap();
        }
        assert!(owner.require_current().is_err());
        assert_eq!(
            owner.record_sha256(),
            <[u8; 32]>::from(Sha256::digest(bytes()))
        );
    }
}

#[test]
fn session_original_bytes_are_checked_independently_of_metadata() {
    let fixture = Fixture::new();
    let mut owner = fixture.open();
    let mut changed = bytes();
    let index = changed.iter().position(|byte| *byte == b'c').unwrap();
    changed[index] = b'd';
    std::fs::write(fixture.path(), changed).unwrap();
    // Private fault injection removes the independent timestamp detector to
    // exercise byte retention itself; production cannot replace this stamp.
    owner.source.stamp = Stamp::of(&std::fs::metadata(fixture.path()).unwrap());
    assert!(owner.require_current().is_err());
    std::fs::write(fixture.path(), bytes()).unwrap();
    assert!(owner.require_current().is_err());
    assert_eq!(owner.source.raw, bytes());
}

#[test]
fn session_original_descriptor_flag_loss_is_terminal_for_leaf_and_parents() {
    for which in 0..3 {
        let fixture = Fixture::new();
        let owner = fixture.open();
        let fd = match which {
            0 => owner.source.file.as_raw_fd(),
            1 => owner.source.nodes[0].file.as_raw_fd(),
            _ => owner.source.nodes[1].file.as_raw_fd(),
        };
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) },
            0
        );
        assert!(owner.require_current().is_err());
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFL, flags) }, 0);
        assert!(owner.require_current().is_err());
    }
    let fixture = Fixture::new();
    let owner = fixture.open();
    let fd = owner.source.file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert!(flags >= 0);
    assert_eq!(
        unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
        0
    );
    assert!(owner.require_current().is_err());
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, flags) }, 0);
    assert!(owner.require_current().is_err());
}

#[test]
fn session_observed_boot_expiry_is_terminal_after_fixture_clock_rollback() {
    let fixture = Fixture::new();
    let owner = fixture.open();
    fixture.clock.store(END, Ordering::SeqCst);
    assert!(owner.require_current().is_err());
    fixture.clock.store(NOW, Ordering::SeqCst);
    assert!(owner.require_current().is_err());
    assert!(owner.shorten_before(END, owner.end).is_err());
}

#[test]
fn session_revoke_error_and_caught_unwind_are_terminal() {
    let fixture = Fixture::new();
    let owner = fixture.open();
    owner.revoke();
    owner.revoke();
    assert!(owner.require_current().is_err());
    let owner = fixture.open();
    assert!(owner
        .checked::<()>(|| Err(err!(EIO, "PRIVATE_FIXTURE")))
        .is_err());
    assert!(owner.require_current().is_err());
    let owner = fixture.open();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = owner.checked::<()>(|| panic!("private fixture unwind"));
    }));
    assert!(result.is_err());
    assert!(owner.require_current().is_err());
}

#[test]
fn session_revocation_during_in_progress_check_prevents_late_success() {
    let fixture = Fixture::new();
    let owner = fixture.open();
    let entered = std::sync::Barrier::new(2);
    let resume = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let waiter = scope.spawn(|| {
            owner.checked(|| {
                entered.wait();
                resume.wait();
                Ok(())
            })
        });
        entered.wait();
        owner.revoke();
        resume.wait();
        assert!(waiter.join().unwrap().is_err());
    });
    assert!(owner.require_current().is_err());
}

#[cfg(not(target_os = "macos"))]
#[test]
fn session_public_native_capture_refuses_linux_before_fixture_authority() {
    assert!(SelectedOwnerSession::capture().is_err());
    assert!(native_boot_id().is_err());
}

#[test]
fn session_negative_observer_reports_same_terminal_failure_without_rechecking_files() {
    let fixture = Fixture::new();
    let session = fixture.open();
    session.require_not_revoked().unwrap();
    let moved = fixture.root.join("temporarily-moved-session");
    std::fs::rename(fixture.path(), &moved).unwrap();
    // A negative-only observation supplies no fresh file or readiness proof.
    session.require_not_revoked().unwrap();
    assert!(session.require_current().is_err());
    std::fs::rename(moved, fixture.path()).unwrap();
    assert!(session.require_not_revoked().is_err());
    assert!(session.require_current().is_err());
}
