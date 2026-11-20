//! Pure source-plan checks plus explicit protected-root filesystem fixtures.
//! Linux engine cases use the genuine existing walker in its mode-only
//! software scope. They never construct the native ACL-protected entry owner.
use super::*;
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::OpenOptions,
    os::{
        fd::AsRawFd,
        unix::fs::{symlink, OpenOptionsExt, PermissionsExt},
    },
};

fn spec(role: BirthSourceRole, path: &str, size: u64) -> BirthSourceSpec {
    BirthSourceSpec {
        role,
        path: path.into(),
        sha256: "a".repeat(64),
        size,
    }
}
fn staged(label: &str, path: &str, size: u64) -> BirthSourceSpec {
    spec(BirthSourceRole::Staged(label.into()), path, size)
}
fn plan(specs: &[BirthSourceSpec]) -> EnclaveResult<SourcePlan> {
    SourcePlan::build(Path::new("/source-package"), specs)
}
fn denied<T>(result: EnclaveResult<T>, expected: &str) {
    let error = result
        .err()
        .expect("source operation unexpectedly accepted");
    assert!(
        error.is(expected),
        "unexpected source error: {}",
        error.reason
    );
    assert!(error.detail.is_empty());
}

#[test]
fn pure_plan_retains_exact_roles_routes_and_inert_expectations_without_opening_files() {
    let specs = [
        spec(
            BirthSourceRole::Inventory,
            "/source-package/inventory.json",
            1,
        ),
        spec(
            BirthSourceRole::CustodyManifest,
            "/source-package/custody.json",
            2,
        ),
        staged(
            "codesign-pins.json",
            "/source-package/stage/codesign-pins.json",
            3,
        ),
    ];
    let result = plan(&specs).unwrap();
    assert_eq!(result.package, Path::new("/source-package"));
    assert_eq!(result.specs.len(), 3);
    for (actual, expected) in result.specs.iter().zip(&specs) {
        assert!(actual.role == expected.role);
        assert_eq!(actual.path, expected.path);
        assert_eq!(
            (&actual.sha256, actual.size),
            (&expected.sha256, expected.size)
        );
    }
}

#[test]
fn source_count_and_aggregate_byte_admission_are_bounded_without_allocation_or_io() {
    denied(plan(&[]), "BIRTH_INPUT_COUNT");
    let specs: Vec<_> = (0..MAX_FILES)
        .map(|i| {
            staged(
                &format!("file-{i}"),
                &format!("/source-package/file-{i}"),
                1,
            )
        })
        .collect();
    assert!(plan(&specs).is_ok());
    let mut too_many = specs;
    too_many.push(staged("last", "/source-package/last", 1));
    denied(plan(&too_many), "BIRTH_INPUT_COUNT");
    let mut bytes: Vec<_> = (0..4)
        .map(|i| {
            staged(
                &format!("large-{i}"),
                &format!("/source-package/large-{i}"),
                MAX_FILE_BYTES,
            )
        })
        .collect();
    assert!(plan(&bytes).is_ok());
    bytes.push(staged("overflow", "/source-package/overflow", 1));
    denied(plan(&bytes), "BIRTH_INPUT_TOTAL");
}

#[test]
fn every_role_uses_existing_file_size_contract_and_nonempty_sources() {
    for role in [
        BirthSourceRole::Inventory,
        BirthSourceRole::CustodyManifest,
        BirthSourceRole::CustodyPolicy,
        BirthSourceRole::PolicyIssuerKey,
        BirthSourceRole::InventoryIssuerKey,
        BirthSourceRole::EnvelopeIssuerKey,
        BirthSourceRole::Staged("binary".into()),
    ] {
        let cap = role.maximum().unwrap();
        assert!(plan(&[spec(role.clone(), "/source-package/input", cap)]).is_ok());
        denied(
            plan(&[spec(role.clone(), "/source-package/input", cap + 1)]),
            "BIRTH_INPUT_SIZE",
        );
        denied(
            plan(&[spec(role, "/source-package/input", 0)]),
            "BIRTH_INPUT_SIZE",
        );
    }
}

#[test]
fn digest_syntax_and_source_name_role_aliases_refuse_before_opening_anything() {
    for digest in ["".into(), "A".repeat(64), "a".repeat(63), "g".repeat(64)] {
        let mut s = staged("one", "/source-package/one", 1);
        s.sha256 = digest;
        denied(plan(&[s]), "BIRTH_INPUT_DIGEST");
    }
    for pair in [
        [
            staged("one", "/source-package/A", 1),
            staged("two", "/source-package/a", 1),
        ],
        [
            staged("one", "/source-package/a", 1),
            staged("two", "/source-package/a/child", 1),
        ],
        [
            staged("A", "/source-package/one", 1),
            staged("a", "/source-package/two", 1),
        ],
        [
            spec(BirthSourceRole::Inventory, "/source-package/one", 1),
            spec(BirthSourceRole::Inventory, "/source-package/two", 1),
        ],
    ] {
        denied(plan(&pair), "BIRTH_INPUT_ALIAS");
    }
}

#[test]
fn every_source_must_be_a_strict_canonical_package_descendant() {
    for path in [
        "/foreign/input",
        "/source-package",
        "/source-package-other/input",
        "relative/input",
        "/source-package/../input",
        "/source-package/./input",
        "/source-package//input",
        "/source-package/input/",
        "/source-package/$input",
        "/source-package/input\n",
    ] {
        assert!(
            plan(&[staged("input", path, 1)]).is_err(),
            "unsafe route accepted"
        );
    }
    assert!(SourcePlan::build(Path::new("/"), &[staged("input", "/input", 1)]).is_err());
    assert!(SourcePlan::build(Path::new("relative"), &[staged("input", "/input", 1)]).is_err());
}

#[test]
fn source_and_stage_labels_have_component_depth_and_closed_relative_syntax_bounds() {
    denied(
        plan(&[staged(
            "input",
            &format!("/source-package/{}", "x".repeat(256)),
            1,
        )]),
        "BIRTH_INPUT_PATH_BOUND",
    );
    let path = format!(
        "/source-package/{}",
        "part/".repeat(MAX_COMPONENTS) + "leaf"
    );
    denied(plan(&[staged("input", &path, 1)]), "BIRTH_INPUT_PATH_BOUND");
    for label in [
        "",
        "/absolute",
        "../outside",
        "a/../b",
        "a/./b",
        "a//b",
        "a/",
        "$input",
        "é",
    ] {
        denied(
            plan(&[staged(label, "/source-package/input", 1)]),
            "BIRTH_INPUT_ROLE",
        );
    }
    denied(
        plan(&[staged(&"x".repeat(256), "/source-package/input", 1)]),
        "BIRTH_INPUT_PATH_BOUND",
    );
}

#[test]
fn fixed_os_aliases_share_the_exact_existing_normalization() {
    let specs = [staged("input", "/var/package/input", 1)];
    let result = SourcePlan::build(Path::new("/private/var/package"), &specs).unwrap();
    assert_eq!(
        result.specs[0].path,
        Path::new("/private/var/package/input")
    );
    assert!(SourcePlan::build(Path::new("/VAR/package"), &specs).is_err());
}

#[cfg(not(target_os = "macos"))]
#[test]
fn native_source_entry_has_no_nonmacos_mode_only_fallback() {
    assert!(UnadmittedBirthSources::open(
        Path::new("/source-package"),
        &[staged("input", "/source-package/input", 1)]
    )
    .is_err());
}

struct RootFixture {
    base: PathBuf,
}
impl RootFixture {
    fn new() -> Self {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "actual protected-root fixture requires root"
        );
        let parent = std::env::var_os("ENCLAVE_TEST_STATE_ROOT")
            .expect("explicit protected fixture root required");
        let parent = normalized_path(Path::new(&parent)).unwrap();
        let base = parent.join(format!(
            "birth-source-{}",
            hex::encode(enclave_core::rng::bytes32())
        ));
        std::fs::create_dir(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self { base }
    }
    fn file(&self, name: &str, bytes: &[u8]) -> BirthSourceSpec {
        use std::io::Write;
        let path = self.base.join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        BirthSourceSpec {
            role: BirthSourceRole::Staged(name.into()),
            path,
            sha256: hex::encode(Sha256::digest(bytes)),
            size: bytes.len() as u64,
        }
    }
    fn software(&self, specs: &[BirthSourceSpec]) -> EnclaveResult<UnadmittedBirthSources> {
        // Genuine held-FD walker, explicitly software/mode-only on Linux.
        // This private seam cannot be called through native public entry.
        UnadmittedBirthSources::open_plan(SourcePlan::build(&self.base, specs)?, HeldPaths::new()?)
    }
}
impl Drop for RootFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

#[test]
#[ignore = "requires explicit protected private-root filesystem"]
fn checked_chunks_cover_exact_bytes_offsets_eof_and_do_not_change_source_names_or_modes() {
    let f = RootFixture::new();
    let bytes: Vec<_> = (0..MAX_CHUNK + 37).map(|i| (i % 251) as u8).collect();
    let s = f.file("candidate", &bytes);
    let before = std::fs::metadata(&s.path).unwrap();
    let mut owner = f
        .software(&[s])
        .ok()
        .expect("genuine source walker admission");
    assert_eq!(owner.source_count(), 1);
    assert!(matches!(owner.role(0), Some(BirthSourceRole::Staged(_))));
    assert_eq!(
        owner.sha256(0),
        Some(hex::encode(Sha256::digest(&bytes)).as_str())
    );
    assert_eq!(owner.sha256(1), None);
    assert_eq!(owner.size(0), Some(bytes.len() as u64));
    let mut buffer = vec![0xee; MAX_CHUNK];
    assert_eq!(owner.read_chunk(0, 0, &mut buffer).unwrap(), MAX_CHUNK);
    assert_eq!(buffer, bytes[..MAX_CHUNK]);
    assert_eq!(
        owner.read_chunk(0, MAX_CHUNK as u64, &mut buffer).unwrap(),
        37
    );
    assert_eq!(buffer[..37], bytes[MAX_CHUNK..]);
    assert!(buffer[37..].iter().all(|b| *b == 0));
    assert_eq!(
        owner
            .read_chunk(0, bytes.len() as u64, &mut buffer)
            .unwrap(),
        0
    );
    assert!(buffer.iter().all(|b| *b == 0));
    owner.assert_current().unwrap();
    let member = &owner.members[0].held;
    let after = std::fs::metadata(member.path()).unwrap();
    assert_eq!(
        (
            before.dev(),
            before.ino(),
            before.mode(),
            before.nlink(),
            before.len()
        ),
        (
            after.dev(),
            after.ino(),
            after.mode(),
            after.nlink(),
            after.len()
        )
    );
    assert_eq!(std::fs::read_dir(&f.base).unwrap().count(), 1);
}

#[test]
#[ignore = "requires explicit protected private-root filesystem"]
fn wrong_digest_size_and_every_preexisting_nonregular_or_link_source_are_refused() {
    for variant in [
        "digest",
        "size",
        "symlink",
        "hardlink",
        "directory",
        "fifo",
        "writable",
    ] {
        let f = RootFixture::new();
        let mut s = f.file("input", b"original");
        match variant {
            "digest" => s.sha256 = "0".repeat(64),
            "size" => s.size += 1,
            "symlink" => {
                let old = f.base.join("old");
                std::fs::rename(&s.path, &old).unwrap();
                symlink(&old, &s.path).unwrap();
            }
            "hardlink" => std::fs::hard_link(&s.path, f.base.join("alias")).unwrap(),
            "directory" => {
                std::fs::remove_file(&s.path).unwrap();
                std::fs::create_dir(&s.path).unwrap();
            }
            "fifo" => {
                std::fs::remove_file(&s.path).unwrap();
                let path = CString::new(s.path.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
            _ => std::fs::set_permissions(&s.path, std::fs::Permissions::from_mode(0o666)).unwrap(),
        }
        assert!(f.software(&[s]).is_err());
    }
}

#[test]
#[ignore = "requires explicit protected private-root filesystem"]
fn in_place_changes_and_exact_byte_replacements_poison_all_later_reads_without_adoption() {
    for replace in [false, true] {
        let f = RootFixture::new();
        let s = f.file("input", b"original");
        let path = s.path.clone();
        let mut owner = f.software(&[s]).ok().expect("source admission");
        let original = owner.members[0].held.file().metadata().unwrap().ino();
        if replace {
            std::fs::rename(&path, f.base.join("old")).unwrap();
            f.file("input", b"original");
        } else {
            std::fs::write(&path, b"modified").unwrap();
        }
        let mut buffer = [0xee; 32];
        assert!(owner.read_chunk(0, 0, &mut buffer).is_err());
        assert!(buffer.iter().all(|b| *b == 0));
        assert!(owner.poisoned);
        assert_eq!(
            owner.members[0].held.file().metadata().unwrap().ino(),
            original
        );
        if replace {
            std::fs::remove_file(&path).unwrap();
            std::fs::rename(f.base.join("old"), &path).unwrap();
        } else {
            std::fs::write(&path, b"original").unwrap();
        }
        denied(owner.assert_current(), "BIRTH_INPUT_OWNER_POISONED");
        denied(
            owner.read_chunk(0, 0, &mut buffer),
            "BIRTH_INPUT_OWNER_POISONED",
        );
    }
}

#[test]
#[ignore = "requires explicit protected private-root filesystem"]
fn a_changed_unrequested_member_refuses_delivery_and_invalid_requests_poison() {
    for variant in ["peer", "index", "offset", "empty", "large"] {
        let f = RootFixture::new();
        let first = f.file("first", b"first");
        let second = f.file("second", b"second");
        let peer = second.path.clone();
        let mut owner = f.software(&[first, second]).ok().expect("source admission");
        let mut buffer = vec![
            0xee;
            if variant == "large" {
                MAX_CHUNK + 1
            } else if variant == "empty" {
                0
            } else {
                32
            }
        ];
        if variant == "peer" {
            std::fs::write(&peer, b"change").unwrap();
        }
        assert!(owner
            .read_chunk(
                if variant == "index" { 2 } else { 0 },
                if variant == "offset" { 6 } else { 0 },
                &mut buffer
            )
            .is_err());
        assert!(buffer.iter().all(|b| *b == 0));
        denied(owner.assert_current(), "BIRTH_INPUT_OWNER_POISONED");
    }
}

#[test]
#[ignore = "requires explicit protected private-root filesystem"]
fn final_full_digest_gate_is_required_after_streaming_and_prior_chunks_cannot_be_recalled() {
    let f = RootFixture::new();
    let s = f.file("input", b"original");
    let path = s.path.clone();
    let mut owner = f.software(&[s]).ok().expect("source admission");
    owner.assert_current().unwrap();
    let mut delivered = [0xee; 8];
    assert_eq!(owner.read_chunk(0, 0, &mut delivered).unwrap(), 8);
    assert_eq!(&delivered, b"original");
    std::fs::write(&path, b"modified").unwrap();
    assert!(owner.assert_current().is_err());
    assert_eq!(
        &delivered, b"original",
        "already returned bytes cannot be recalled or become import authority"
    );
    denied(owner.assert_current(), "BIRTH_INPUT_OWNER_POISONED");
}

#[test]
#[ignore = "requires explicit protected private-root filesystem"]
fn ancestor_replacement_or_permission_and_descriptor_flag_drift_are_terminal() {
    for variant in ["ancestor", "mode", "flags"] {
        let f = RootFixture::new();
        let s = f.file("input", b"original");
        let mut owner = f.software(&[s]).ok().expect("source admission");
        match variant {
            "ancestor" => {
                let moved = f.base.with_extension("original");
                std::fs::rename(&f.base, &moved).unwrap();
                std::fs::create_dir(&f.base).unwrap();
                std::fs::set_permissions(&f.base, std::fs::Permissions::from_mode(0o755)).unwrap();
                assert!(owner.assert_current().is_err());
                std::fs::remove_dir(&f.base).unwrap();
                std::fs::rename(&moved, &f.base).unwrap();
            }
            "mode" => {
                std::fs::set_permissions(&f.base, std::fs::Permissions::from_mode(0o777)).unwrap();
                assert!(owner.assert_current().is_err());
                std::fs::set_permissions(&f.base, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            _ => {
                let fd = owner.members[0].held.file().as_raw_fd();
                let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
                assert!(flags >= 0);
                assert_eq!(
                    unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
                    0
                );
                denied(owner.assert_current(), "BIRTH_INPUT_DESCRIPTOR_FLAGS");
                assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, flags) }, 0);
            }
        }
        denied(owner.assert_current(), "BIRTH_INPUT_OWNER_POISONED");
    }
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires actual macOS root and explicit protected private-root filesystem"]
fn actual_native_constructor_reads_only_original_sources_and_retains_no_write_authority() {
    let f = RootFixture::new();
    let s = f.file("input", b"native source");
    let path = s.path.clone();
    let mut owner = UnadmittedBirthSources::open(&f.base, &[s])
        .ok()
        .expect("actual native ACL-protected source admission");
    let mut buffer = [0xee; 32];
    assert_eq!(owner.read_chunk(0, 0, &mut buffer).unwrap(), 13);
    assert_eq!(&buffer[..13], b"native source");
    owner.assert_current().unwrap();
    drop(owner);
    assert_eq!(std::fs::read(path).unwrap(), b"native source");
    assert_eq!(std::fs::read_dir(&f.base).unwrap().count(), 1);
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires actual macOS root and explicit protected private-root filesystem"]
fn native_acl_on_original_source_or_package_refuses_chunks_and_restoration_cannot_revive_owner() {
    use crate::native_fs::acl_fixture;
    for directory in [false, true] {
        let f = RootFixture::new();
        let s = f.file("input", b"native source");
        let mut owner = UnadmittedBirthSources::open(&f.base, &[s])
            .ok()
            .expect("native strict source admission");
        let ancestor = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&f.base)
            .unwrap();
        let held = if directory {
            &ancestor
        } else {
            owner.members[0].held.file()
        };
        acl_fixture::set_allow(held);
        let mut buffer = [0xee; 32];
        assert!(owner.read_chunk(0, 0, &mut buffer).is_err());
        assert!(buffer.iter().all(|b| *b == 0));
        let held = if directory {
            &ancestor
        } else {
            owner.members[0].held.file()
        };
        acl_fixture::set_empty(held);
        denied(owner.assert_current(), "BIRTH_INPUT_OWNER_POISONED");
    }
}
