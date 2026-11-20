//! SOFTWARE fixtures. Ordinary cases use the actual private create-only parent
//! engine and original file bindings, without protected load or native guard.
//! Ignored /state cases use the REAL protected loader/Layout and test-signed
//! policy. They never construct NativeDedicatedBirth, an actual host guard,
//! software approval, runtime trust, installed state or physical authority.

use super::*;
use ed25519_dalek::{Signer, SigningKey};
use enclave_custody_vaultd::ctap::asset_enrollment::{
    AssetEnrollmentPolicy, AttestationMode, SignedAssetEnrollmentPolicy,
};
use serde_json::{json, Value};
use std::{cell::Cell, os::unix::fs::PermissionsExt, sync::Mutex};

fn bytes(value: Value) -> Vec<u8> {
    serde_json::to_vec(&value).unwrap()
}
fn sync(file: &File) -> EnclaveResult<()> {
    file.sync_all().map_err(|_| err!(EIO, "FIXTURE_LOAD_SYNC"))
}
fn denied<T>(result: EnclaveResult<T>, reason: &str) {
    let error = result.err().expect("must refuse");
    assert!(error.is(reason), "{} != {reason}", error.reason);
}
fn no_authority(progress: &BirthProgress) {
    assert!(
        !progress.mutation_allowed
            && !progress.inactivity_proven
            && !progress.activation_allowed
            && !progress.installation_supported
            && !progress.qualified
    );
}
fn template() -> DeploymentTarget {
    DeploymentTarget::parse(&bytes(json!({"version":1,"target_id":"load-fixture",
        "role":"dedicated-test","profile":"L2","signing_identity_mode":"local-pins",
        "authority_config":"/template/support/custody.json","expected_artifacts_manifest":"/template/config/inventory.json",
        "codesign_pins_file":"/template/support/pins.json","broker":null,"shared_read_only_inputs":[],
        "layout":{"binary_dir":"/template/bin","custody_bundle":"/template/support/Custody.app",
            "sandbox_dir":"/template/sandbox","socket_root":"/template/run","state_root":"/template/state",
            "audit_root":"/template/audit","cas_store_root":"/template/cas","staging_root":"/template/stage",
            "support_root":"/template/support","launchd_namespace":"com.mcpmac.loadfixture",
            "mach_service":"com.mcpmac.loadfixture.exception"}}))).unwrap()
}
fn signed_policy(expired: bool) -> Vec<u8> {
    let now = enclave_crypto::time::now_unix();
    let policy = AssetEnrollmentPolicy {
        version: 1,
        revision: 1,
        host_id: "software-host".into(),
        asset_id: "software-asset".into(),
        custodian_id: "software-custodian".into(),
        aaguid: [0x42; 16],
        mode: AttestationMode::BasicWithIndependentAsset,
        enterprise_leaf_sha256: None,
        rationale: "SOFTWARE fixture only".into(),
        issued_unix: now - 100,
        expires_unix: if expired { now - 1 } else { now + 3600 },
    };
    let signature = SigningKey::from_bytes(&[11; 32])
        .sign(&policy.signing_message().unwrap())
        .to_bytes()
        .to_vec();
    serde_json::to_vec(&SignedAssetEnrollmentPolicy { policy, signature }).unwrap()
}

struct Fixture {
    anchor: PathBuf,
    state: BirthState,
}
impl Fixture {
    fn new() -> Self {
        Self::edited(|_| {})
    }
    fn edited(edit: impl FnOnce(&mut Value)) -> Self {
        Self::edited_mode(edit, None)
    }
    fn edited_mode(edit: impl FnOnce(&mut Value), mode: Option<(InputRole, u32)>) -> Self {
        let anchor = std::env::current_dir().unwrap().join(format!(
            ".birth-load-fixture-{}",
            hex::encode(enclave_core::rng::bytes32())
        ));
        Self::at_mode(anchor, false, edit, mode)
    }
    fn at(anchor: PathBuf, expired: bool, edit: impl FnOnce(&mut Value)) -> Self {
        Self::at_mode(anchor, expired, edit, None)
    }
    fn at_mode(
        anchor: PathBuf,
        expired: bool,
        edit: impl FnOnce(&mut Value),
        mode: Option<(InputRole, u32)>,
    ) -> Self {
        std::fs::create_dir(&anchor).unwrap();
        std::fs::set_permissions(&anchor, std::fs::Permissions::from_mode(0o700)).unwrap();
        let original = BirthPlan::build(
            &template(),
            Path::new("/template"),
            Path::new("/birth-load"),
            &[0x51; 16],
        )
        .unwrap();
        let root = anchor.join(original.root.file_name().unwrap());
        let map = |p: &Path| root.join(p.strip_prefix(&original.root).unwrap());
        // Test-only rebase, never a production constructor or socket-bound
        // exemption. The actual native constructor is not called by tests.
        let raw = String::from_utf8(original.bytes.clone())
            .unwrap()
            .replace(original.root.to_str().unwrap(), root.to_str().unwrap())
            .into_bytes();
        let plan = BirthPlan {
            root: root.clone(),
            target: DeploymentTarget::parse(&raw).unwrap(),
            descriptor: map(&original.descriptor),
            bytes: raw,
            seed_dirs: original.seed_dirs.iter().map(|p| map(p)).collect(),
        };
        let protection = Protection {
            owner: (unsafe { libc::geteuid() }, unsafe { libc::getegid() }),
            native_acl: false,
        };
        let path = CString::new(anchor.as_os_str().as_bytes()).unwrap();
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC,
            )
        };
        assert!(fd >= 0);
        let directory =
            Directory::capture(unsafe { File::from_raw_fd(fd) }, None, false, protection).unwrap();
        let mut progress = BirthProgress::new();
        progress.root = Some(root.clone());
        progress.descriptor = Some(plan.descriptor.clone());
        progress.target_id = Some(plan.target.target_id.clone());
        let mut state = BirthState {
            plan,
            dirs: BTreeMap::from([(anchor.clone(), directory)]),
            files: BTreeMap::new(),
            protection,
            progress,
            poisoned: false,
            pending: None,
            private_load: None,
        };
        state
            .create_directory(&root, &mut || Vec::new(), &mut Vec::new(), &mut sync)
            .unwrap();
        state.prepare_seeds(&mut || Vec::new(), &mut sync).unwrap();
        let target = &state.plan.target;
        let support = &target.layout.support_root;
        let pins = bytes(
            json!({"v":1,"pins":{"com.enterprise.enclave.custody":["ab".repeat(20)],
            "com.enterprise.enclave.cas":["ab".repeat(20)]}}),
        );
        let hash = hex::encode(Sha256::digest(&pins));
        let inventory = bytes(
            json!({"version":1,"kind":"mcpmac-first-touch-artifact-inventory",
            "target_id":target.target_id,"profile":"L2","signing_identity_mode":"local-pins",
            "deployment_config_sha256":hex::encode(Sha256::digest(&state.plan.bytes)),
            "source_git_commit":"a".repeat(40),"source_manifest_sha256":"b".repeat(64),"source_input_count":1,
            "codesign_pins_sha256":hash,"staging_root":target.layout.staging_root,"external_provenance":"UNKNOWN",
            "files":[{"path":"bin/mcp-enclave","sha256":"c".repeat(64),"size":1},
                {"path":"codesign-pins.json","sha256":hash,"size":pins.len()}]}),
        );
        let policy = support.join("public/policy.json");
        let policy_key = support.join("public/policy.key");
        let inventory_key = support.join("public/inventory.key");
        let envelope_key = support.join("public/envelope.key");
        let mut manifest = json!({"v":1,"profile":"L2","asset_policy_file":policy,
            "asset_policy_key_file":policy_key,"asset_inventory_key_file":inventory_key,
            "envelope_policy_key_file":envelope_key,"asset_host_id":"software-host",
            "asset_id":"software-asset","asset_custodian_id":"software-custodian",
            "envelope_policy_subject":"software-host","envelope_policy_namespace":"software-fixture"});
        edit(&mut manifest);
        use InputRole::*;
        let inputs = vec![
            (
                Inventory,
                target.expected_artifacts_manifest.clone(),
                inventory.clone(),
            ),
            (Manifest, target.authority_config.clone(), bytes(manifest)),
            (Policy, policy, signed_policy(expired)),
            (
                PolicyIssuer,
                policy_key,
                hex::encode(SigningKey::from_bytes(&[11; 32]).verifying_key().to_bytes())
                    .into_bytes(),
            ),
            (
                InventoryIssuer,
                inventory_key,
                hex::encode(SigningKey::from_bytes(&[12; 32]).verifying_key().to_bytes())
                    .into_bytes(),
            ),
            (
                EnvelopeIssuer,
                envelope_key,
                hex::encode(SigningKey::from_bytes(&[13; 32]).verifying_key().to_bytes())
                    .into_bytes(),
            ),
            (
                StagedPins,
                target.layout.staging_root.join(STAGED_PINS),
                pins.clone(),
            ),
            (SelectedPins, target.codesign_pins_file.clone(), pins),
        ];
        state
            .prepare_denial(&inventory, &mut || Vec::new(), &mut sync)
            .unwrap();
        // This fixture directly seeds the actual original parent engine. It
        // does not exercise or impersonate the native source owner/importer.
        for (role, path, payload) in inputs {
            let mut parents = Vec::new();
            let mut parent = path.parent().unwrap();
            while !state.dirs.contains_key(parent) {
                parents.push(parent.to_owned());
                parent = parent.parent().unwrap();
            }
            for parent in parents.into_iter().rev() {
                state
                    .create_directory(&parent, &mut || Vec::new(), &mut Vec::new(), &mut sync)
                    .unwrap();
            }
            let initial_mode = mode
                .filter(|(selected, _)| *selected == role)
                .map_or(role.mode(), |(_, mode)| mode);
            state
                .create_file(
                    &path,
                    &payload,
                    initial_mode,
                    &mut || Vec::new(),
                    &mut Vec::new(),
                    &mut sync,
                )
                .unwrap();
        }
        Self { anchor, state }
    }
    fn original(&self) -> EnclaveResult<OriginalInputs> {
        OriginalInputs::capture(&self.state)
    }
    fn load(&mut self) -> Result<BirthProgress, BirthFailure> {
        self.state.load_private_inputs(&mut || Vec::new())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.anchor);
    }
}

#[test]
fn original_bindings_cover_all_eleven_roles_without_effects_or_authority() {
    let f = Fixture::new();
    let before = f.state.progress.attempted.clone();
    let originals = f.original().unwrap();
    assert_eq!(originals.files.len(), 11);
    for file in &originals.files {
        let expected = if matches!(file.role, InputRole::Denial | InputRole::StagedPins) {
            0o600
        } else {
            0o644
        };
        let seed = &f.state.files[&file.path];
        let metadata = seed.file.metadata().unwrap();
        assert_eq!(metadata.mode() & 0o7777, expected);
        assert!(seed.stamp == file.stamp);
        assert_eq!(seed.access, libc::O_RDONLY);
        assert_eq!(metadata.nlink(), 1);
    }
    for (path, directory) in &f.state.dirs {
        if path.starts_with(&f.state.plan.root) {
            assert!(directory.private);
            assert_eq!(directory.file.metadata().unwrap().mode() & 0o7777, 0o700);
        }
    }
    originals.current(&f.state).unwrap();
    assert_eq!(before, f.state.progress.attempted);
    assert!(f.state.private_load.is_none());
    assert!(f.state.progress.denial_prepared);
    for path in [
        &f.state.plan.target.layout.binary_dir,
        &f.state.plan.target.layout.custody_bundle,
        &f.state.plan.target.layout.sandbox_dir,
        &f.state.plan.target.layout.socket_root,
        &f.state.plan.target.layout.state_root,
        &f.state.plan.target.layout.audit_root,
        &f.state.plan.target.layout.cas_store_root,
    ] {
        assert!(!path.exists());
    }
    no_authority(&f.state.progress);
}

#[test]
fn wrong_initial_destination_mode_cannot_be_admitted_from_an_original_engine_inode() {
    use InputRole::*;
    for role in [
        Inventory,
        Manifest,
        Policy,
        PolicyIssuer,
        InventoryIssuer,
        EnvelopeIssuer,
        StagedPins,
        SelectedPins,
    ] {
        let wrong = if role == StagedPins { 0o644 } else { 0o600 };
        // Wrong at original O_EXCL creation, with its original matching stamp.
        // This never refreshes a previously admitted file to make it pass.
        let f = Fixture::edited_mode(|_| {}, Some((role, wrong)));
        denied(f.original(), "BIRTH_LOAD_INPUT_PROTECTION");
        assert!(f.state.private_load.is_none());
        no_authority(&f.state.progress);
    }
}

#[test]
fn seeds_denial_and_every_original_nested_input_are_mandatory_before_protected_reads() {
    let mut f = Fixture::new();
    f.state.progress.seeds_complete = false;
    denied(f.original(), "BIRTH_LOAD_DENIAL_REQUIRED");
    let mut f = Fixture::new();
    f.state.progress.denial_prepared = false;
    denied(f.original(), "BIRTH_LOAD_DENIAL_REQUIRED");
    let mut f = Fixture::new();
    f.state.pending = None;
    denied(f.original(), "BIRTH_LOAD_DENIAL_REQUIRED");
    for leaf in ["policy.json", "policy.key", "inventory.key", "envelope.key"] {
        let mut f = Fixture::new();
        let path = f
            .state
            .plan
            .target
            .layout
            .support_root
            .join("public")
            .join(leaf);
        f.state.files.remove(&path);
        assert!(
            path.exists(),
            "existence cannot supply an original held input"
        );
        denied(f.original(), "BIRTH_LOAD_ORIGINAL_INPUT_REQUIRED");
    }
}

#[test]
fn streamed_content_sentinels_cannot_supply_any_of_the_eleven_original_input_roles() {
    for index in 0..11 {
        let mut f = Fixture::new();
        let path = f
            .original()
            .unwrap()
            .files
            .into_iter()
            .nth(index)
            .unwrap()
            .path;
        // Test-only content-tag substitution, never native authority or an
        // original-file refresh. Streamed .bytes is an empty sentinel and may
        // not stand for either the empty lifetime seed or a nested input.
        let seed = f.state.files.get_mut(&path).unwrap();
        seed.streamed = Some(StreamedContent {
            length: seed.stamp.len,
            sha256: hex::encode(Sha256::digest(&seed.bytes)),
        });
        seed.bytes.clear();
        let before = f.state.progress.attempted.clone();
        denied(f.original(), "BIRTH_LOAD_ORIGINAL_INPUT_REQUIRED");
        assert_eq!(before, f.state.progress.attempted);
        assert!(f.state.private_load.is_none());
    }
}

#[test]
fn manifest_schema_profile_strict_root_and_distinct_control_roles_precede_reads() {
    let f = Fixture::edited(|m| m["profile"] = json!("L3"));
    assert!(f.original().is_err());
    let f = Fixture::edited(|m| m["asset_policy_file"] = json!("/outside/policy.json"));
    denied(f.original(), "BIRTH_PATH_OUTSIDE_TEMPLATE");
    let f = Fixture::edited(|m| m["asset_policy_key_file"] = m["asset_policy_file"].clone());
    denied(f.original(), "BIRTH_LOAD_INPUT_ROLE_ALIAS");
    let f = Fixture::edited(|m| {
        let policy: PathBuf = serde_json::from_value(m["asset_policy_file"].clone()).unwrap();
        let root = policy.parent().unwrap().parent().unwrap().parent().unwrap();
        m["asset_policy_key_file"] = json!(root.join(DESCRIPTOR));
    });
    denied(f.original(), "BIRTH_LOAD_INPUT_ROLE_ALIAS");
}

#[test]
fn pending_inventory_descriptor_and_both_pin_byte_bindings_are_exact() {
    let mut f = Fixture::new();
    let p = f.state.plan.descriptor.clone();
    f.state.files.get_mut(&p).unwrap().bytes.push(b' ');
    denied(f.original(), "BIRTH_LOAD_DESCRIPTOR_BINDING");
    let mut f = Fixture::new();
    let p = f.state.plan.target.expected_artifacts_manifest.clone();
    f.state.files.get_mut(&p).unwrap().bytes.push(b' ');
    denied(f.original(), "BIRTH_LOAD_PENDING_INVENTORY");
    let mut f = Fixture::new();
    f.state.pending.as_mut().unwrap().inventory_sha256 = "00".repeat(32);
    denied(f.original(), "BIRTH_PENDING_BINDING_CHANGED");
    for staged in [false, true] {
        let mut f = Fixture::new();
        let p = if staged {
            f.state.plan.target.layout.staging_root.join(STAGED_PINS)
        } else {
            f.state.plan.target.codesign_pins_file.clone()
        };
        f.state.files.get_mut(&p).unwrap().bytes.push(b' ');
        denied(f.original(), "BIRTH_LOAD_PINS_BINDING");
    }
}

#[test]
fn identical_named_replacement_is_refused_by_original_inode_binding() {
    let f = Fixture::new();
    let originals = f.original().unwrap();
    let path = f
        .state
        .plan
        .target
        .layout
        .support_root
        .join("public/policy.key");
    let old = std::fs::symlink_metadata(&path).unwrap();
    let payload = std::fs::read(&path).unwrap();
    let replacement = path.with_extension("replacement");
    std::fs::write(&replacement, &payload).unwrap();
    std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::rename(replacement, &path).unwrap();
    let new = std::fs::symlink_metadata(&path).unwrap();
    assert_ne!((old.dev(), old.ino()), (new.dev(), new.ino()));
    assert_eq!(std::fs::read(&path).unwrap(), payload);
    denied(originals.current(&f.state), "BIRTH_SEED_CHANGED");
}

#[test]
fn retained_role_hash_and_original_modes_cannot_be_refreshed_or_adopted() {
    let f = Fixture::new();
    let mut originals = f.original().unwrap();
    originals
        .files
        .iter_mut()
        .find(|file| file.role == InputRole::PolicyIssuer)
        .unwrap()
        .sha256 = "00".repeat(32);
    denied(
        originals.current(&f.state),
        "BIRTH_LOAD_ORIGINAL_BINDING_CHANGED",
    );
    for index in 0..11 {
        let f = Fixture::new();
        let originals = f.original().unwrap();
        let original = &originals.files[index];
        let wrong = if original.stamp.directory.mode & 0o7777 == 0o644 {
            0o600
        } else {
            0o644
        };
        std::fs::set_permissions(&original.path, std::fs::Permissions::from_mode(wrong)).unwrap();
        denied(originals.current(&f.state), "BIRTH_SEED_CHANGED");
        assert!(f.state.files[&original.path].stamp == original.stamp);
    }
}

#[test]
fn original_input_refusal_preserves_all_final_guard_errors_and_sticky_poison() {
    let mut f = Fixture::new();
    let path = f
        .state
        .plan
        .target
        .layout
        .support_root
        .join("public/policy.key");
    f.state.files.remove(&path);
    let files = f.state.progress.created_files.clone();
    let calls = Cell::new(0);
    let mut check = || {
        calls.set(calls.get() + 1);
        if calls.get() > 2 {
            vec![err!(ESTALE, "FIXTURE_LOAD_FINAL_GUARD")]
        } else {
            Vec::new()
        }
    };
    let failure = f.state.load_private_inputs(&mut check).unwrap_err();
    assert!(failure.error.is("BIRTH_LOAD_ORIGINAL_INPUT_REQUIRED"));
    assert!(
        failure
            .final_errors
            .iter()
            .filter(|e| e.is("FIXTURE_LOAD_FINAL_GUARD"))
            .count()
            >= 4
    );
    assert!(calls.get() >= 6);
    assert!(f.state.poisoned);
    assert!(f.state.private_load.is_none());
    assert_eq!(files, f.state.progress.created_files);
    for path in files {
        assert!(path.exists());
    }
    assert!(f.load().unwrap_err().error.is("BIRTH_OWNER_POISONED"));
    no_authority(&f.state.progress);
}

#[test]
fn initial_guard_refusal_keeps_original_files_and_runs_all_final_gates() {
    let mut f = Fixture::new();
    let before = f.state.progress.attempted.clone();
    let calls = Cell::new(0);
    let failure = f
        .state
        .load_private_inputs(&mut || {
            calls.set(calls.get() + 1);
            vec![err!(ESTALE, "FIXTURE_LOAD_GUARD")]
        })
        .unwrap_err();
    assert!(failure.error.is("FIXTURE_LOAD_GUARD"));
    assert!(!failure.boundary_errors.is_empty());
    assert!(!failure.final_errors.is_empty());
    assert!(calls.get() >= 6);
    assert_eq!(before, f.state.progress.attempted);
    assert!(f.state.private_load.is_none());
    assert!(f.state.poisoned);
    no_authority(&f.state.progress);
}

static PROTECTED_LOCK: Mutex<()> = Mutex::new(());
fn protected(expired: bool) -> Fixture {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "requires actual private-root root"
    );
    assert_eq!(
        std::env::var("ENCLAVE_TEST_STATE_ROOT").as_deref(),
        Ok("/state"),
        "coordinator private /state harness required; never run against the host root"
    );
    assert!(
        matches!(
            enclave_core::codesign::signing_mode(),
            enclave_core::codesign::SigningMode::LocalPins
        ),
        "dedicated birth supports actual local-pins build only"
    );
    assert!(
        deployment::selected().is_none(),
        "fresh private-root process required"
    );
    Fixture::at(PathBuf::from("/state/birth-admit-fixture"), expired, |_| {})
}

#[test]
#[ignore = "requires coordinator private-root /state, actual protected loaders; SOFTWARE signed fixture only"]
fn protected_real_load_is_retained_private_and_one_shot_without_selection_or_effects() {
    let _serial = PROTECTED_LOCK.lock().unwrap();
    let mut f = protected(false);
    let before = f.state.progress.attempted.clone();
    let originals = f.original().unwrap();
    let original_fds = f
        .state
        .files
        .iter()
        .map(|(path, seed)| (path.clone(), seed.file.as_raw_fd()))
        .collect::<Vec<_>>();
    f.load().unwrap();
    assert!(deployment::selected().is_none());
    let loaded = f.state.private_load.as_ref().unwrap();
    loaded.current(&f.state).unwrap();
    assert!(originals == loaded.originals);
    assert!(originals == f.original().unwrap());
    for (path, fd) in original_fds {
        assert_eq!(f.state.files[&path].file.as_raw_fd(), fd);
    }
    originals.checked(&loaded.checked).unwrap();
    originals.layout(&loaded.layout).unwrap();
    assert_eq!(
        loaded.checked.config_path(),
        f.state.plan.descriptor.as_path()
    );
    assert_eq!(
        loaded.checked.descriptor_sha256(),
        hex::encode(Sha256::digest(&f.state.plan.bytes))
    );
    // Actual independent asset-policy expiry verifier retained by the real
    // Layout. This explicit future-time probe is not a wall-clock measurement.
    let authority = loaded.layout.custody_authority.as_ref().unwrap();
    denied(
        authority.revalidate(Profile::L2, authority.receipt().asset_policy_expires_unix),
        "CUSTODY_PROVISIONING_POLICY",
    );
    f.state.revalidate(&mut || Vec::new()).unwrap();
    assert_eq!(before, f.state.progress.attempted);
    let failure = f.load().unwrap_err();
    assert!(failure.error.is("BIRTH_LOAD_ALREADY_PREPARED"));
    assert!(f.state.private_load.is_some());
    assert!(f.state.poisoned);
    assert_eq!(before, f.state.progress.attempted);
    assert!(deployment::selected().is_none());
    assert!(f
        .state
        .plan
        .target
        .layout
        .support_root
        .join(UPGRADE_INHIBITION_LEAF)
        .exists());
    no_authority(&f.state.progress);
}

#[test]
#[ignore = "requires coordinator private-root /state, real Layout hook and actual signed-policy failures; SOFTWARE only"]
fn protected_retained_layout_hook_and_expired_signed_policy_fail_closed() {
    let _serial = PROTECTED_LOCK.lock().unwrap();
    {
        let mut f = protected(false);
        f.load().unwrap();
        f.original().unwrap().current(&f.state).unwrap();
        // Synthetic corruption of an already REAL loaded private Layout proves
        // later parent boundaries validate it independently of original bytes.
        // No checked/issuer capability is fabricated for this negative case.
        f.state.private_load.as_mut().unwrap().layout.fido_emulator = true;
        f.original().unwrap().current(&f.state).unwrap();
        let failure = f.state.revalidate(&mut || Vec::new()).unwrap_err();
        assert!(failure
            .final_errors
            .iter()
            .any(|e| e.is("DEPLOYMENT_LAYOUT_MISMATCH")));
        assert!(f.state.poisoned);
        assert!(deployment::selected().is_none());
        no_authority(&f.state.progress);
    }
    {
        let mut f = protected(true);
        let before = f.state.progress.attempted.clone();
        let failure = f.load().unwrap_err();
        assert!(failure.error.is("CUSTODY_PROVISIONING_POLICY"));
        assert!(f.state.private_load.is_none());
        assert!(f.state.poisoned);
        assert_eq!(before, f.state.progress.attempted);
        assert!(deployment::selected().is_none());
        assert!(f
            .state
            .plan
            .target
            .layout
            .support_root
            .join(UPGRADE_INHIBITION_LEAF)
            .exists());
        no_authority(&f.state.progress);
    }
}
