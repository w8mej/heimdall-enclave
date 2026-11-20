//! Synthetic policy/path orchestration tests. Fake observations cannot establish
//! native signatures, root ownership, issuer approval or installed readiness.
use super::*;
use std::{
    fs,
    os::unix::fs::{symlink, DirBuilderExt, PermissionsExt},
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Root {
    path: PathBuf,
}
impl Root {
    fn new() -> Self {
        let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
        // Isolated captures use an external CARGO_TARGET_DIR; their own
        // checkout-local target need not have been created by Cargo.
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&parent)
            .unwrap();
        let path = parent.join(format!(
            "native-code-fixture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self {
            path: path.canonicalize().unwrap(),
        }
    }
    fn write(&self, relative: &str, bytes: &[u8]) -> PathBuf {
        let path = self.path.join(relative);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path.parent().unwrap())
            .unwrap();
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }
    fn dirs(&self) -> Directories {
        Directories::fixture(&self.path, unsafe { libc::geteuid() }).unwrap()
    }
    fn executable(&self) -> PathBuf {
        self.write("mcp-enclave", &macho(2))
    }
    fn bundle(&self) -> PathBuf {
        for (path, bytes) in [
            ("EnclaveOIDC.app/Contents/MacOS/enclave-oidc", macho(2)),
            (
                "EnclaveOIDC.app/Contents/Info.plist",
                b"SYNTHETIC INFO; fake backend only".to_vec(),
            ),
            (
                "EnclaveOIDC.app/Contents/_CodeSignature/CodeResources",
                b"SYNTHETIC RESOURCES".to_vec(),
            ),
        ] {
            self.write(path, &bytes);
        }
        self.path.join("EnclaveOIDC.app")
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
fn macho(filetype: u32) -> Vec<u8> {
    let mut result = vec![0u8; 64];
    result[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    result[12..16].copy_from_slice(&filetype.to_le_bytes());
    result
}
fn req(identifier: &str) -> CodeRequirement {
    CodeRequirement {
        identifier: identifier.into(),
        team_id: TEAM_ID.into(),
        cdhash_allowlist: vec!["ab".repeat(20)],
    }
}
fn observation(
    req: &CodeRequirement,
    policy: NativeEntitlementPolicy,
    code: &Path,
    exe: &Path,
) -> SigningObservation {
    let bundle_info = role(&req.identifier).unwrap().1.then(|| {
        (
            req.identifier.clone(),
            role(&req.identifier).unwrap().0.into(),
        )
    });
    SigningObservation {
        identity: CodeIdentity {
            identifier: req.identifier.clone(),
            team_id: TEAM_ID.into(),
            cdhash: "ab".repeat(20),
        },
        flags: RUNTIME,
        entitlements: expected_entitlements(policy),
        code_path: code.to_owned(),
        executable_path: exe.to_owned(),
        bundle_info,
    }
}
struct Fake {
    observed: Option<SigningObservation>,
    action: Option<Box<dyn FnOnce()>>,
    calls: usize,
    fail: bool,
}
impl Fake {
    fn new(observed: SigningObservation) -> Self {
        Self {
            observed: Some(observed),
            action: None,
            calls: 0,
            fail: false,
        }
    }
}
impl StaticBackend for Fake {
    fn inspect(
        &mut self,
        _path: &Path,
        _bundle: bool,
        requirement: &str,
    ) -> EnclaveResult<SigningObservation> {
        assert!(requirement.contains("cdhash H\"abab"));
        self.calls += 1;
        if let Some(action) = self.action.take() {
            action();
        }
        if self.fail {
            fail!(EACCES, "SYNTHETIC_SIGNATURE_REFUSAL");
        }
        Ok(self.observed.take().unwrap())
    }
}
fn run_executable(
    root: &Root,
    req: &CodeRequirement,
    backend: &mut dyn StaticBackend,
) -> EnclaveResult<NativeCodeObservation> {
    let path = root.path.join("mcp-enclave");
    let file = File::open(&path).unwrap();
    let size = file.metadata().unwrap().len();
    let hash = hex::encode(Sha256::digest(fs::read(&path).unwrap()));
    verify_with(
        NativeCodeShape::Executable(ProtectedNativeFile {
            path: &path,
            file: &file,
            sha256: &hash,
            size,
        }),
        req,
        NativeEntitlementPolicy::DaemonBaseline,
        backend,
        root.dirs(),
    )
}
fn run_bundle(
    root: &Root,
    backend: &mut dyn StaticBackend,
    extra_member: bool,
) -> EnclaveResult<NativeCodeObservation> {
    run_bundle_req(
        root,
        backend,
        extra_member,
        &req("com.enterprise.enclave.oidc-broker"),
    )
}
fn run_bundle_req(
    root: &Root,
    backend: &mut dyn StaticBackend,
    extra_member: bool,
    requirement: &CodeRequirement,
) -> EnclaveResult<NativeCodeObservation> {
    let bundle = root.path.join("EnclaveOIDC.app");
    let mut names = vec![
        "Contents/MacOS/enclave-oidc",
        "Contents/Info.plist",
        "Contents/_CodeSignature/CodeResources",
    ];
    if extra_member {
        names.push("Contents/unapproved");
    }
    let owned = names
        .into_iter()
        .map(|n| {
            let path = bundle.join(n);
            let file = File::open(&path).unwrap();
            let bytes = fs::read(&path).unwrap();
            let hash = hex::encode(Sha256::digest(&bytes));
            (path, file, hash, bytes.len() as u64)
        })
        .collect::<Vec<_>>();
    let views = owned
        .iter()
        .map(|(path, file, hash, size)| ProtectedNativeFile {
            path,
            file,
            sha256: hash,
            size: *size,
        })
        .collect::<Vec<_>>();
    verify_with(
        NativeCodeShape::Bundle {
            root: &bundle,
            executable: views[0],
            members: &views[1..],
        },
        requirement,
        NativeEntitlementPolicy::DaemonBaseline,
        backend,
        root.dirs(),
    )
}

#[test]
fn exact_compiled_team_and_pins_are_mandatory_without_global_context() {
    let good = req("com.enterprise.enclave.ctl");
    let text = requirement_text(&good, NativeEntitlementPolicy::DaemonBaseline).unwrap();
    assert!(text.contains("identifier \"com.enterprise.enclave.ctl\""));
    assert!(text.contains("cdhash H\"abab"));
    assert_eq!(text.contains("anchor apple generic"), !TEAM_ID.is_empty());
    for bad in [
        CodeRequirement {
            team_id: format!("{TEAM_ID}X"),
            ..good.clone()
        },
        CodeRequirement {
            cdhash_allowlist: vec![],
            ..good.clone()
        },
        CodeRequirement {
            cdhash_allowlist: vec!["aa".repeat(19)],
            ..good.clone()
        },
        CodeRequirement {
            cdhash_allowlist: vec!["zz".repeat(20)],
            ..good.clone()
        },
        CodeRequirement {
            cdhash_allowlist: vec!["ab".repeat(20), "AB".repeat(20)],
            ..good.clone()
        },
        CodeRequirement {
            identifier: "com.foreign.ctl\" or true".into(),
            ..good.clone()
        },
    ] {
        assert!(requirement_text(&bad, NativeEntitlementPolicy::DaemonBaseline).is_err());
    }
    assert!(requirement_text(
        &good,
        NativeEntitlementPolicy::CustodyForCompiledSigningMode
    )
    .is_err());
    assert!(requirement_text(
        &req("com.enterprise.enclave.custody"),
        NativeEntitlementPolicy::DaemonBaseline
    )
    .is_err());
}

#[test]
fn original_identity_exact_hash_runtime_and_exact_typed_entitlements_are_enforced() {
    let requirement = req("com.enterprise.enclave.ctl");
    let path = Path::new("/synthetic/mcp-enclave");
    let good = observation(
        &requirement,
        NativeEntitlementPolicy::DaemonBaseline,
        path,
        path,
    );
    verify_observation(&good, &requirement, NativeEntitlementPolicy::DaemonBaseline).unwrap();
    for change in [
        "identifier",
        "team",
        "hash",
        "runtime",
        "missing",
        "extra",
        "true",
        "type",
    ] {
        let mut value = observation(
            &requirement,
            NativeEntitlementPolicy::DaemonBaseline,
            path,
            path,
        );
        match change {
            "identifier" => value.identity.identifier = "com.foreign.ctl".into(),
            "team" => value.identity.team_id.push('X'),
            "hash" => value.identity.cdhash = "ff".repeat(20),
            "runtime" => value.flags = 0,
            "missing" => {
                value.entitlements.remove(BASELINE[0]);
            }
            "extra" => {
                value
                    .entitlements
                    .insert("com.apple.unapproved".into(), Entitlement::Boolean(false));
            }
            "true" => {
                value
                    .entitlements
                    .insert(BASELINE[0].into(), Entitlement::Boolean(true));
            }
            "type" => {
                value
                    .entitlements
                    .insert(BASELINE[0].into(), Entitlement::Text("false".into()));
            }
            _ => unreachable!(),
        }
        assert!(
            verify_observation(
                &value,
                &requirement,
                NativeEntitlementPolicy::DaemonBaseline
            )
            .is_err(),
            "{change}"
        );
    }
}

#[test]
fn selected_cdhash_requires_exact_corresponding_digest_and_bounded_unambiguous_metadata() {
    let first = vec![0xabu8; 20];
    let second = vec![0xcdu8; 20];
    let hashes = vec![first.clone(), second.clone()];
    assert_eq!(
        consistent_selected_cdhash(&second, 2, &[1, 2], &hashes).unwrap(),
        "cd".repeat(20)
    );
    assert_eq!(
        consistent_selected_cdhash(&first, 1, &[1, 2], &hashes).unwrap(),
        "ab".repeat(20)
    );
    for (unique, selected, algorithms, hashes) in [
        (first.clone(), 2, vec![1, 2], hashes.clone()),
        (first.clone(), 3, vec![1, 2], hashes.clone()),
        (first.clone(), 1, vec![1, 1], hashes.clone()),
        (first.clone(), 1, vec![0, 1], hashes.clone()),
        (first.clone(), 1, vec![-1, 1], hashes.clone()),
        (
            first.clone(),
            1,
            vec![i64::from(u32::MAX) + 1, 1],
            hashes.clone(),
        ),
        (first.clone(), 1, vec![1], hashes.clone()),
        (first.clone(), 1, vec![], vec![]),
        (first[..19].to_vec(), 1, vec![1], vec![first.clone()]),
        (first.clone(), 1, vec![1], vec![first[..19].to_vec()]),
        (
            first.clone(),
            1,
            (1..=17).collect(),
            vec![first.clone(); 17],
        ),
    ] {
        assert!(consistent_selected_cdhash(&unique, selected, &algorithms, &hashes).is_err());
    }
}

#[test]
fn custody_policy_uses_only_compiled_mode_and_baseline_has_no_snapshot_grant() {
    let base = expected_entitlements(NativeEntitlementPolicy::DaemonBaseline);
    assert_eq!(base.len(), 7);
    assert!(!base.contains_key("com.apple.developer.vfs.snapshot"));
    let custody = expected_entitlements(NativeEntitlementPolicy::CustodyForCompiledSigningMode);
    assert_eq!(custody.len(), if TEAM_ID.is_empty() { 7 } else { 10 });
    if !TEAM_ID.is_empty() {
        assert_eq!(
            custody["com.apple.developer.team-identifier"],
            Entitlement::Text(TEAM_ID.into())
        );
        assert_eq!(
            custody["keychain-access-groups"],
            Entitlement::TextArray(vec![format!("{TEAM_ID}.com.enterprise.enclave.custody")])
        );
    }
}

#[test]
fn held_executable_success_preserves_bytes_metadata_and_file_offset() {
    use std::io::{Seek, SeekFrom};
    let root = Root::new();
    let path = root.executable();
    let requirement = req("com.enterprise.enclave.ctl");
    let mut backend = Fake::new(observation(
        &requirement,
        NativeEntitlementPolicy::DaemonBaseline,
        &path,
        &path,
    ));
    let mut file = File::open(&path).unwrap();
    file.seek(SeekFrom::Start(9)).unwrap();
    let before = Stamp::of(&file.metadata().unwrap());
    let bytes = fs::read(&path).unwrap();
    let hash = hex::encode(Sha256::digest(&bytes));
    let value = verify_with(
        NativeCodeShape::Executable(ProtectedNativeFile {
            path: &path,
            file: &file,
            sha256: &hash,
            size: bytes.len() as u64,
        }),
        &requirement,
        NativeEntitlementPolicy::DaemonBaseline,
        &mut backend,
        root.dirs(),
    )
    .unwrap();
    assert_eq!(backend.calls, 1);
    assert_eq!(value.identity.identifier, requirement.identifier);
    assert_eq!(value.flags, RUNTIME);
    assert_eq!(value.executable_sha256, hash);
    assert_eq!(value.member_sha256.len(), 1);
    assert_eq!(
        value.entitlement_policy,
        NativeEntitlementPolicy::DaemonBaseline
    );
    assert_eq!(file.stream_position().unwrap(), 9);
    assert_eq!(Stamp::of(&file.metadata().unwrap()), before);
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[test]
fn writable_ancestor_and_symlink_or_hardlink_executable_refuse_before_backend() {
    for change in ["writable", "symlink", "hardlink"] {
        let root = Root::new();
        let path = root.executable();
        match change {
            "writable" => {
                fs::set_permissions(&root.path, fs::Permissions::from_mode(0o777)).unwrap()
            }
            "symlink" => {
                let other = root.path.join("other");
                fs::rename(&path, &other).unwrap();
                symlink(&other, &path).unwrap();
            }
            "hardlink" => fs::hard_link(&path, root.path.join("extra")).unwrap(),
            _ => unreachable!(),
        }
        let requirement = req("com.enterprise.enclave.ctl");
        let mut backend = Fake::new(observation(
            &requirement,
            NativeEntitlementPolicy::DaemonBaseline,
            &path,
            &path,
        ));
        // Writable fixture root is itself rejected while constructing ancestry.
        if change == "writable" {
            assert!(Directories::fixture(&root.path, unsafe { libc::geteuid() }).is_err());
        } else {
            assert!(run_executable(&root, &requirement, &mut backend).is_err());
        }
        assert_eq!(backend.calls, 0);
    }
}

#[test]
fn writable_fd_bad_digest_length_and_special_mode_refuse_before_backend() {
    let root = Root::new();
    let path = root.executable();
    let requirement = req("com.enterprise.enclave.ctl");
    let bytes = fs::read(&path).unwrap();
    let hash = hex::encode(Sha256::digest(&bytes));
    for change in ["writable-fd", "digest", "length", "setuid"] {
        let file = if change == "writable-fd" {
            File::options().read(true).write(true).open(&path).unwrap()
        } else {
            File::open(&path).unwrap()
        };
        if change == "setuid" {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o4600)).unwrap();
        }
        let wrong = "ff".repeat(32);
        let input = ProtectedNativeFile {
            path: &path,
            file: &file,
            sha256: if change == "digest" { &wrong } else { &hash },
            size: if change == "length" {
                bytes.len() as u64 + 1
            } else {
                bytes.len() as u64
            },
        };
        let mut backend = Fake::new(observation(
            &requirement,
            NativeEntitlementPolicy::DaemonBaseline,
            &path,
            &path,
        ));
        assert!(verify_with(
            NativeCodeShape::Executable(input),
            &requirement,
            NativeEntitlementPolicy::DaemonBaseline,
            &mut backend,
            root.dirs()
        )
        .is_err());
        assert_eq!(backend.calls, 0);
    }
}

#[test]
fn non_macho_dylib_and_universal_code_refuse_without_native_observation() {
    for kind in ["script", "dylib", "fat32", "fat64"] {
        let root = Root::new();
        let mut bytes = macho(if kind == "dylib" { 6 } else { 2 });
        match kind {
            "script" => bytes[..4].copy_from_slice(b"#!/b"),
            "fat32" => bytes[..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]),
            "fat64" => bytes[..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbf]),
            _ => (),
        }
        let path = root.write("mcp-enclave", &bytes);
        let requirement = req("com.enterprise.enclave.ctl");
        let mut backend = Fake::new(observation(
            &requirement,
            NativeEntitlementPolicy::DaemonBaseline,
            &path,
            &path,
        ));
        let error = run_executable(&root, &requirement, &mut backend).unwrap_err();
        if kind.starts_with("fat") {
            assert!(error.is("NATIVE_CODE_UNIVERSAL_UNSUPPORTED"));
        }
        assert_eq!(backend.calls, 0);
    }
}

#[test]
fn substitution_during_backend_refuses_even_if_backend_originally_succeeded() {
    for change in ["replacement", "bytes", "extra-link", "mode"] {
        let root = Root::new();
        let path = root.executable();
        let requirement = req("com.enterprise.enclave.ctl");
        let mut backend = Fake::new(observation(
            &requirement,
            NativeEntitlementPolicy::DaemonBaseline,
            &path,
            &path,
        ));
        let target = path.clone();
        let extra = root.path.join("held-old");
        let change = change.to_owned();
        backend.action = Some(Box::new(move || match change.as_str() {
            "replacement" => {
                fs::rename(&target, &extra).unwrap();
                fs::write(&target, macho(2)).unwrap();
            }
            "bytes" => {
                fs::write(&target, b"changed even when backend says valid").unwrap();
            }
            "extra-link" => {
                fs::hard_link(&target, &extra).unwrap();
            }
            "mode" => {
                fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
            }
            _ => unreachable!(),
        }));
        assert!(run_executable(&root, &requirement, &mut backend).is_err());
        assert_eq!(backend.calls, 1);
    }
}

#[test]
fn native_error_still_revalidates_files_and_success_cannot_substitute_returned_path() {
    let root = Root::new();
    let path = root.executable();
    let requirement = req("com.enterprise.enclave.ctl");
    let mut backend = Fake::new(observation(
        &requirement,
        NativeEntitlementPolicy::DaemonBaseline,
        &path,
        &path,
    ));
    backend.fail = true;
    let changed = path.clone();
    backend.action = Some(Box::new(move || fs::write(changed, b"changed").unwrap()));
    assert!(run_executable(&root, &requirement, &mut backend)
        .unwrap_err()
        .is("NATIVE_CODE_FILE_CHANGED"));
    root.executable();
    let mut obs = observation(
        &requirement,
        NativeEntitlementPolicy::DaemonBaseline,
        &path,
        &path,
    );
    obs.executable_path = PathBuf::from("/foreign/mcp-enclave");
    assert!(run_executable(&root, &requirement, &mut Fake::new(obs))
        .unwrap_err()
        .is("NATIVE_CODE_RESOLVED_PATH"));
}

#[test]
fn bundle_closed_members_signed_info_and_resource_binding_are_required() {
    let root = Root::new();
    let bundle = root.bundle();
    let exe = bundle.join("Contents/MacOS/enclave-oidc");
    let requirement = req("com.enterprise.enclave.oidc-broker");
    let mut backend = Fake::new(observation(
        &requirement,
        NativeEntitlementPolicy::DaemonBaseline,
        &bundle,
        &exe,
    ));
    let value = run_bundle(&root, &mut backend, false).unwrap();
    assert_eq!(value.member_sha256.len(), 3);
    assert_eq!(backend.calls, 1);
    let mut obs = observation(
        &requirement,
        NativeEntitlementPolicy::DaemonBaseline,
        &bundle,
        &exe,
    );
    obs.bundle_info = Some((requirement.identifier.clone(), "foreign-executable".into()));
    assert!(run_bundle(&root, &mut Fake::new(obs), false)
        .unwrap_err()
        .is("NATIVE_CODE_BUNDLE_INFO"));
    let mut backend = Fake::new(observation(
        &requirement,
        NativeEntitlementPolicy::DaemonBaseline,
        &bundle,
        &exe,
    ));
    let resource = bundle.join("Contents/_CodeSignature/CodeResources");
    backend.action = Some(Box::new(move || fs::write(resource, b"changed").unwrap()));
    assert!(run_bundle(&root, &mut backend, false).is_err());
}

#[test]
fn unlisted_or_unapproved_bundle_members_and_late_additions_refuse() {
    for change in [
        "extra-unlisted",
        "extra-listed",
        "extra-directory",
        "late-extra",
    ] {
        let root = Root::new();
        let bundle = root.bundle();
        let exe = bundle.join("Contents/MacOS/enclave-oidc");
        let requirement = req("com.enterprise.enclave.oidc-broker");
        let mut backend = Fake::new(observation(
            &requirement,
            NativeEntitlementPolicy::DaemonBaseline,
            &bundle,
            &exe,
        ));
        match change {
            "extra-unlisted" | "extra-listed" => {
                root.write("EnclaveOIDC.app/Contents/unapproved", b"unapproved");
            }
            "extra-directory" => fs::create_dir(bundle.join("Contents/Nested.app")).unwrap(),
            "late-extra" => {
                let extra = bundle.join("Contents/unapproved");
                backend.action = Some(Box::new(move || fs::write(extra, b"late").unwrap()));
            }
            _ => unreachable!(),
        }
        assert!(run_bundle(&root, &mut backend, change == "extra-listed").is_err());
        assert_eq!(backend.calls, usize::from(change == "late-extra"));
    }
}

#[test]
fn missing_bundle_seal_and_resource_symlink_refuse_before_native_backend() {
    let root = Root::new();
    let bundle = root.bundle();
    let exe = bundle.join("Contents/MacOS/enclave-oidc");
    let requirement = req("com.enterprise.enclave.oidc-broker");
    let mut backend = Fake::new(observation(
        &requirement,
        NativeEntitlementPolicy::DaemonBaseline,
        &bundle,
        &exe,
    ));
    let path = bundle.join("Contents/_CodeSignature/CodeResources");
    let outside = root.write("foreign-resource", b"foreign");
    fs::remove_file(&path).unwrap();
    symlink(&outside, &path).unwrap();
    assert!(run_bundle(&root, &mut backend, false).is_err());
    assert_eq!(backend.calls, 0);
    fs::remove_file(&path).unwrap();
    let exe_file = File::open(&exe).unwrap();
    let hash = hex::encode(Sha256::digest(fs::read(&exe).unwrap()));
    let info_path = bundle.join("Contents/Info.plist");
    let info_file = File::open(&info_path).unwrap();
    let info_size = info_file.metadata().unwrap().len();
    let info_hash = hex::encode(Sha256::digest(fs::read(&info_path).unwrap()));
    let members = [ProtectedNativeFile {
        path: &info_path,
        file: &info_file,
        sha256: &info_hash,
        size: info_size,
    }];
    assert!(verify_with(
        NativeCodeShape::Bundle {
            root: &bundle,
            executable: ProtectedNativeFile {
                path: &exe,
                file: &exe_file,
                sha256: &hash,
                size: exe_file.metadata().unwrap().len()
            },
            members: &members
        },
        &requirement,
        NativeEntitlementPolicy::DaemonBaseline,
        &mut backend,
        root.dirs()
    )
    .unwrap_err()
    .is("NATIVE_CODE_BUNDLE_INCOMPLETE"));
}

#[cfg(not(target_os = "macos"))]
#[test]
fn nonnative_public_entry_has_no_fixture_or_candidate_authority_fallback() {
    let root = Root::new();
    let path = root.executable();
    let file = File::open(&path).unwrap();
    let hash = hex::encode(Sha256::digest(fs::read(&path).unwrap()));
    assert!(verify_static_code(
        NativeCodeShape::Executable(ProtectedNativeFile {
            path: &path,
            file: &file,
            sha256: &hash,
            size: file.metadata().unwrap().len()
        }),
        &req("com.enterprise.enclave.ctl"),
        NativeEntitlementPolicy::DaemonBaseline
    )
    .unwrap_err()
    .is("NATIVE_CODE_VERIFICATION_UNAVAILABLE"));
}

#[cfg(target_os = "macos")]
#[test]
fn native_corefoundation_type_and_embedded_nul_checks_refuse_lossy_observations() {
    darwin::test_cf_boundaries();
}

#[cfg(target_os = "macos")]
#[test]
fn native_selected_cdhash_rejects_missing_and_wrong_typed_digest_metadata() {
    darwin::test_selected_hash_boundaries();
}

/// Coordinator prepares disposable ad-hoc fixtures under this checkout's
/// target directory. No fixture program is executed. Pins are self-derived
/// ONLY inside this explicitly synthetic test, never a production authorizer.
#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires coordinator-generated disposable signed native fixtures"]
fn native_security_framework_generated_executable_and_bundle_fixtures() {
    let supplied = PathBuf::from(
        std::env::var_os("ENCLAVE_NATIVE_STATIC_FIXTURE_ROOT")
            .expect("explicit generated fixture root"),
    );
    let supplied = supplied.canonicalize().unwrap();
    let target = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .canonicalize()
        .unwrap();
    assert!(supplied.starts_with(&target) && supplied != target);
    assert_eq!(
        fs::read(supplied.join("FIXTURE-ONLY")).unwrap(),
        b"SYNTHETIC-NATIVE-CODE-FIXTURE\n"
    );
    let identifier = "com.enterprise.enclave.ctl";
    let raw_requirement = format!("identifier \"{identifier}\"");
    for (kind, expected_error) in [
        ("valid", None),
        ("no-runtime", Some("NATIVE_CODE_RUNTIME")),
        ("extra-entitlement", Some("NATIVE_CODE_ENTITLEMENTS")),
    ] {
        let root = Root::new();
        let path = root.write(
            "mcp-enclave",
            &fs::read(supplied.join(kind).join("mcp-enclave")).unwrap(),
        );
        let mut native = darwin::SecurityBackend;
        let observed = native.inspect(&path, false, &raw_requirement).unwrap();
        let mut requirement = req(identifier);
        requirement.cdhash_allowlist = vec![observed.identity.cdhash];
        let result = run_executable(&root, &requirement, &mut native);
        if let Some(error) = expected_error {
            assert!(result.unwrap_err().is(error), "{kind}");
        } else {
            result.unwrap();
            assert!(native
                .inspect(&path, false, "identifier \"com.foreign.ctl\"")
                .is_err());
            let mut wrong = requirement.clone();
            wrong.cdhash_allowlist = vec!["ff".repeat(20)];
            assert!(run_executable(&root, &wrong, &mut native).is_err());
            // Corrupt the reserved Mach-O header word inside the signed first
            // page, leaving the thin/executable shape check intact.
            let mut bytes = fs::read(&path).unwrap();
            bytes[28] ^= 1;
            fs::write(&path, bytes).unwrap();
            assert!(run_executable(&root, &requirement, &mut native).is_err());
        }
    }
    let root = Root::new();
    let source = supplied.join("EnclaveOIDC.app");
    for relative in [
        "Contents/MacOS/enclave-oidc",
        "Contents/Info.plist",
        "Contents/_CodeSignature/CodeResources",
    ] {
        root.write(
            &format!("EnclaveOIDC.app/{relative}"),
            &fs::read(source.join(relative)).unwrap(),
        );
    }
    let bundle = root.path.join("EnclaveOIDC.app");
    let mut native = darwin::SecurityBackend;
    let observed = native
        .inspect(
            &bundle,
            true,
            "identifier \"com.enterprise.enclave.oidc-broker\"",
        )
        .unwrap();
    let mut requirement = req("com.enterprise.enclave.oidc-broker");
    requirement.cdhash_allowlist = vec![observed.identity.cdhash];
    run_bundle_req(&root, &mut native, false, &requirement).unwrap();
    let resources = bundle.join("Contents/_CodeSignature/CodeResources");
    let mut bytes = fs::read(&resources).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(resources, bytes).unwrap();
    assert!(run_bundle_req(&root, &mut native, false, &requirement).is_err());
}
