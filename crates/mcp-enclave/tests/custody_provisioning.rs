//! Configuration-only qualification. No SEP, HID, IPC or sealed-state opening.
//! Protection cases require the coordinator's repository-local private-root
//! runner with ENCLAVE_TEST_STATE_ROOT=/state; no test changes the host root.

use enclave_core::{profile::Profile, runtime::DaemonArgs};
use enclave_custody_vaultd::provisioning::{CustodyProvisioning, LEGACY_AUTHORITY_ARGUMENTS};

fn args(extra: &[&str]) -> DaemonArgs {
    DaemonArgs::parse(["custody", "--profile", "L3"].into_iter().chain(extra.iter().copied())
        .map(str::to_owned)).unwrap()
}

#[test]
fn native_argument_guards_precede_protected_file_reads() {
    let missing = "/missing-public-authority-manifest";
    for legacy in LEGACY_AUTHORITY_ARGUMENTS {
        let mut parsed = args(&["--custody-authority-config", missing]);
        parsed.extra.push((legacy.into(), "fixture-only".into()));
        let error = CustodyProvisioning::from_daemon_args(&parsed, 1).unwrap_err();
        assert!(error.is("CUSTODY_PROVISIONING_MIXED_ARGUMENTS"));
        assert!(error.detail.is_empty());
    }
    let duplicate = args(&["--custody-authority-config", missing,
        "--custody-authority-config", missing]);
    assert!(CustodyProvisioning::from_daemon_args(&duplicate, 1).unwrap_err()
        .is("CUSTODY_PROVISIONING_MIXED_ARGUMENTS"));
    for extra in [
        vec!["--dev-same-uid"],
        vec!["--dev-same-uid", "--simulated-hardware"],
        vec!["--yubikey-transport", "emulator"],
        vec!["--yubikey-transport", "unknown"],
    ] {
        let mut options = vec!["--custody-authority-config", missing];
        options.extend(extra);
        let error = CustodyProvisioning::from_daemon_args(&args(&options), 1).unwrap_err();
        assert!(error.is("CUSTODY_PROVISIONING_NATIVE_REQUIRED"));
        assert!(error.detail.is_empty());
    }
    let legacy = args(&["--asset-policy-file", missing]);
    assert!(CustodyProvisioning::from_daemon_args(&legacy, 1).unwrap().is_none());
}

#[test]
fn unconfigured_layout_keeps_authority_out_of_every_daemon() {
    use enclave_core::daemon::DaemonId;
    use depot_enclave::launchd::{self, Layout};
    let layout = Layout::default();
    assert!(layout.custody_authority.is_none());
    for daemon in DaemonId::ALL {
        let argv = launchd::daemon_args(daemon, &layout);
        assert!(!argv.iter().any(|v| v == "--custody-authority-config"));
        assert!(!launchd::sandbox_profile(daemon, &layout)
            .contains("Complete root-protected public custody authority"));
        let parsed = DaemonArgs::parse(std::iter::once("daemon".into()).chain(argv)).unwrap();
        assert_eq!(parsed.profile, Profile::L2);
        assert!(CustodyProvisioning::from_daemon_args(&parsed, 1).unwrap().is_none());
    }
}

#[cfg(unix)]
mod protected {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use enclave_core::daemon::DaemonId;
    use enclave_custody_vaultd::ctap::asset_enrollment::{
        AssetEnrollmentPolicy, AttestationMode, SignedAssetEnrollmentPolicy,
    };
    use depot_enclave::launchd::{self, Layout};
    use serde_json::{json, Value};
    use std::{ffi::CString, fs, os::unix::fs::{symlink, MetadataExt, PermissionsExt},
        path::{Path, PathBuf}, sync::Mutex};

    const CONFIG: &str = "/state/custody-provisioning/authority/custody.json";
    const HOST: &str = "fixture-private-host-marker";
    const ASSET: &str = "fixture-private-asset-marker";
    const CUSTODIAN: &str = "fixture-private-custodian-marker";
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());
    const FIXTURE: &str = "/state/custody-provisioning";

    struct LocalRoot(PathBuf);
    impl Drop for LocalRoot {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }

    fn run_case(case: &str) {
        let _serial = FIXTURE_LOCK.lock().unwrap();
        assert_eq!(unsafe { libc::geteuid() }, 0, "private-root fixture requires root");
        assert_eq!(std::env::var("ENCLAVE_TEST_STATE_ROOT").as_deref(), Ok("/state"),
            "use coordinator run_private_fixture.py; never run these cases on the host root");
        fs::create_dir(FIXTURE).unwrap();
        fs::set_permissions(FIXTURE, fs::Permissions::from_mode(0o700)).unwrap();
        let _fixture = LocalRoot(PathBuf::from(FIXTURE));
        let now = enclave_crypto::time::now_unix();
        eprintln!("provisioning fixture case: {case}");
        setup(now);
        match case {
            "roundtrip" => roundtrip(now),
            "schema" => schema(now),
            "policy" => policy_failures(now),
            "protection" => protection(now),
            "owner-path" => owner_paths(now),
            "paths" => paths(now),
            "stale" => stale(now),
            "preselection-l2" => preselection(now, Profile::L2, false),
            "preselection-l3" => preselection(now, Profile::L3, false),
            "preselection-frozen-control" => preselection(now, Profile::L2, true),
            _ => panic!("unknown fixture case"),
        }
    }

    fn put(path: &str, bytes: impl AsRef<[u8]>) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
    }
    fn policy(now: i64) -> SignedAssetEnrollmentPolicy {
        let policy = AssetEnrollmentPolicy { version: 1, revision: 7,
            host_id: HOST.into(), asset_id: ASSET.into(), custodian_id: CUSTODIAN.into(),
            aaguid: [0x31; 16], mode: AttestationMode::BasicWithIndependentAsset,
            enterprise_leaf_sha256: None, rationale: "offline fixture only".into(),
            issued_unix: now - 10, expires_unix: now + 3600 };
        let signature = SigningKey::from_bytes(&[11; 32]).sign(&policy.signing_message().unwrap())
            .to_bytes().to_vec();
        SignedAssetEnrollmentPolicy { policy, signature }
    }
    fn manifest() -> Value {
        json!({"v":1,"profile":"L3", "asset_policy_file":"/state/custody-provisioning/authority/policy.json",
            "asset_policy_key_file":"/state/custody-provisioning/authority/policy.pub",
            "asset_inventory_key_file":"/state/custody-provisioning/authority/inventory.pub", "asset_host_id":HOST,
            "asset_id":ASSET,"asset_custodian_id":CUSTODIAN,
            "envelope_policy_key_file":"/state/custody-provisioning/authority/envelope.pub",
            "envelope_policy_subject":"fixture-private-subject-marker",
            "envelope_policy_namespace":"fixture-private-namespace-marker"})
    }
    fn setup(now: i64) {
        fs::create_dir("/state/custody-provisioning/authority").unwrap();
        fs::set_permissions("/state/custody-provisioning/authority", fs::Permissions::from_mode(0o755)).unwrap();
        put(CONFIG, serde_json::to_vec(&manifest()).unwrap());
        put("/state/custody-provisioning/authority/policy.json", serde_json::to_vec(&policy(now)).unwrap());
        for (name, seed) in [("policy", 11), ("inventory", 12), ("envelope", 13)] {
            put(&format!("/state/custody-provisioning/authority/{name}.pub"),
                hex::encode(SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes()));
        }
    }
    fn load(now: i64) -> CustodyProvisioning {
        CustodyProvisioning::load(Path::new(CONFIG), Profile::L3, now).unwrap()
    }
    #[track_caller]
    fn denied(path: &str, profile: Profile, now: i64, reason: &str) {
        let error = CustodyProvisioning::load(Path::new(path), profile, now).unwrap_err();
        assert!(error.is(reason), "unexpected category: {}", error.reason);
        assert!(error.detail.is_empty());
        for marker in [HOST, ASSET, CUSTODIAN, "/state/custody-provisioning/authority", "fixture-private-subject-marker"] {
            assert!(!format!("{error:?}").contains(marker));
        }
    }

    #[test]
    #[ignore = "requires coordinator private-root fixture with /state; native compile only"]
    fn protected_authorities_render_and_native_argument_pickup() { run_case("roundtrip"); }
    #[test]
    #[ignore = "requires coordinator private-root fixture with /state; native compile only"]
    fn closed_manifest_schema_and_exact_profile_are_required() { run_case("schema"); }
    #[test]
    #[ignore = "requires coordinator private-root fixture with /state; native compile only"]
    fn signed_policy_and_public_key_failures_are_redacted() { run_case("policy"); }
    #[test]
    #[ignore = "requires coordinator private-root fixture with /state; native compile only"]
    fn protected_reader_refuses_links_fifo_writable_and_oversize() { run_case("protection"); }
    #[test]
    #[ignore = "requires private-root filesystem with real chown; shared workspace chown is a no-op, so full-path owner cases are UNEXERCISED"]
    fn full_path_nonroot_ownership_requires_real_chown() { run_case("owner-path"); }
    #[test]
    #[ignore = "requires coordinator private-root fixture with /state; native compile only"]
    fn unsafe_paths_and_scope_values_are_refused() { run_case("paths"); }
    #[test]
    #[ignore = "requires coordinator private-root fixture with /state; native compile only"]
    fn changed_sources_and_emulator_refuse_before_render_writes() { run_case("stale"); }

    #[test]
    #[ignore = "requires coordinator private-root fixture with /state; isolated real process selection/cache only"]
    fn private_target_loading_preserves_one_later_selection_and_unprimed_pins() {
        const CHILD: &str = "depot_CUSTODY_PRESELECTION_CHILD";
        const SELECTOR: &str = "protected::private_target_loading_preserves_one_later_selection_and_unprimed_pins";
        if let Some(case) = std::env::var_os(CHILD) {
            let case = case.to_str().expect("closed fixture child mode");
            assert!(matches!(case, "preselection-l2" | "preselection-l3" | "preselection-frozen-control"));
            run_case(case);
            return;
        }
        // The existing protected tests share a fixed private fixture path.
        // Serialize the parent against them while each fresh child owns its
        // own immutable global selection/cache and independently cleans up.
        let _serial = FIXTURE_LOCK.lock().unwrap();
        assert_eq!(unsafe { libc::geteuid() }, 0, "private-root fixture requires root");
        assert_eq!(std::env::var("ENCLAVE_TEST_STATE_ROOT").as_deref(), Ok("/state"),
            "use coordinator run_private_fixture.py; never run on the host root");
        let executable = std::env::current_exe().or_else(|error| {
            // The declared private chroot has no /proc. Match the existing
            // core fixture fallback to its exact coordinator-copied binary;
            // never choose a host binary or create another runner.
            if std::env::var("ENCLAVE_TEST_STATE_ROOT").as_deref() == Ok("/state")
                && fs::symlink_metadata("/test-binary").is_ok_and(|m| m.is_file()) {
                Ok(PathBuf::from("/test-binary"))
            } else { Err(error) }
        }).unwrap();
        for case in ["preselection-l2", "preselection-l3", "preselection-frozen-control"] {
            let output = std::process::Command::new(&executable)
                .args(["--exact", SELECTOR, "--ignored", "--nocapture", "--test-threads=1"])
                .env(CHILD, case)
                // Inherit existing handles: the minimal private root need
                // not fabricate /dev/null for child stdin.
                .stdin(std::process::Stdio::inherit())
                .output().unwrap();
            assert!(output.status.success(), "preselection child {case} failed:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert!(stdout.contains("1 passed; 0 failed"), "child must run its exact selector: {stdout}");
            assert!(!Path::new(FIXTURE).exists(), "child must remove only its own private fixture");
        }
    }

    fn preselection(now: i64, profile: Profile, frozen_control: bool) {
        use enclave_core::{codesign::{self, CodeRequirement, SigningMode}, deployment};
        const ROOT: &str = "/state/custody-provisioning/private-target";
        const DESCRIPTOR: &str = "/state/custody-provisioning/private-target/config/deployment.json";
        const AUTHORITY: &str = "/state/custody-provisioning/private-target/support/custody.json";
        const PINS: &str = "/state/custody-provisioning/private-target/support/codesign-pins.json";
        const PIN_A: &str = "1919191919191919191919191919191919191919";
        const PIN_B: &str = "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a";
        let write_pins = |hash: &str| put(PINS, serde_json::to_vec(&json!({"v":1,"pins":{
            "com.enterprise.enclave.custody":[hash],"com.enterprise.enclave.cas":[hash]
        }})).unwrap());
        assert!(deployment::selected().is_none(), "fresh subprocess must have no selected target");
        for path in [ROOT, "/state/custody-provisioning/private-target/config",
            "/state/custody-provisioning/private-target/support"] {
            fs::create_dir(path).unwrap();fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut authority = manifest();authority["profile"] = json!(profile);
        put(AUTHORITY, serde_json::to_vec(&authority).unwrap());
        // These bounded placeholders are public parser inputs only. The real
        // protected loader does not approve an inventory or bootstrap TUF;
        // this test constructs no software/runtime/native authority from them.
        put("/state/custody-provisioning/private-target/config/inventory.json", b"{}");
        if profile == Profile::L3 {
            put("/state/custody-provisioning/private-target/support/independent-runtime-root.json", b"{}");
        }
        write_pins(PIN_A);
        let root = Path::new(ROOT);
        let target = json!({"version":1,"target_id":"preselection-fixture","role":"dedicated-test",
            "profile":profile,"authority_config":AUTHORITY,
            "expected_artifacts_manifest":root.join("config/inventory.json"),
            "codesign_pins_file":PINS,
            "signing_identity_mode":match codesign::signing_mode() {
                SigningMode::LocalPins=>"local-pins",SigningMode::TeamId=>"team-id"},
            "broker":if profile==Profile::L3 {json!({"base_dir":root.join("state/apfs-broker"),
                "tuf_root_file":root.join("support/independent-runtime-root.json")})}else{Value::Null},
            "shared_read_only_inputs":[],"layout":{
                "binary_dir":root.join("bin"),"custody_bundle":root.join("support/EnclaveCustody.app"),
                "sandbox_dir":root.join("sandbox"),"socket_root":root.join("run"),
                "state_root":root.join("state"),"audit_root":root.join("audit"),
                "cas_store_root":root.join("cas"),"staging_root":root.join("stage"),
                "support_root":root.join("support"),"launchd_namespace":"com.depot.preselection",
                "mach_service":"com.depot.preselection.exception"}});
        put(DESCRIPTOR, serde_json::to_vec(&target).unwrap());
        if frozen_control {
            // This accessor freezes the legacy context WITHOUT opening its
            // global pin file. selected()==None alone cannot detect a freeze.
            let _legacy_route = deployment::selected_pin_file();
            assert!(deployment::selected().is_none());
        }
        let checked = deployment::load(Path::new(DESCRIPTOR)).unwrap();
        assert!(deployment::selected().is_none(), "protected loading must not select");
        let layout = Layout::for_target(checked.clone()).unwrap();
        assert!(deployment::selected().is_none(), "private Layout loading must not select");
        assert_eq!(layout.custody_authority.as_ref().unwrap().receipt().profile, profile);
        assert_eq!(layout.custody_authority.as_ref().unwrap().receipt().asset_policy_sha256,
            load(now).receipt().asset_policy_sha256);
        assert!(layout.deployment.as_ref().unwrap().target() == checked.target());
        layout.validate().unwrap();
        write_pins(PIN_B);
        // Repeated private validation must neither cache A nor freeze the
        // legacy pin route. Only the later ONE real selection may bind B.
        layout.validate().unwrap();
        assert!(deployment::selected().is_none());
        if frozen_control {
            assert!(deployment::select(checked).unwrap_err().is("DEPLOYMENT_CONTEXT_FROZEN"));
            assert!(deployment::selected().is_none());
            return;
        }
        let descriptor_hash = checked.descriptor_sha256().to_owned();
        deployment::select(checked).unwrap();
        let selected = deployment::selected().unwrap();
        assert_eq!(selected.config_path(), Path::new(DESCRIPTOR));
        assert_eq!(selected.descriptor_sha256(), descriptor_hash);
        assert_eq!(deployment::selected_pin_file(), Path::new(PINS));
        let requirement = CodeRequirement::daemon(DaemonId::CustodyVault);
        assert_eq!(requirement.cdhash_allowlist, vec![PIN_B.to_owned()]);
        assert_eq!(codesign::pins::pinned("com.enterprise.enclave.cas"), vec![PIN_B.to_owned()]);
        assert!(!requirement.cdhash_allowlist.iter().any(|hash|hash == PIN_A));
        // Global immutable selection/cache dies with this child; no reset or
        // substitute authority is introduced to make another case pass.
    }

    fn roundtrip(now: i64) {
        let checked = load(now);
        let (asset, envelope) = checked.authorities();
        assert_eq!((asset.host.as_str(), asset.asset.as_str(), asset.custodian.as_str()),
            (HOST, ASSET, CUSTODIAN));
        assert_eq!(asset.policy_file, Path::new("/state/custody-provisioning/authority/policy.json"));
        assert_eq!(asset.policy_issuer, SigningKey::from_bytes(&[11; 32]).verifying_key());
        assert_eq!(asset.inventory_issuer, SigningKey::from_bytes(&[12; 32]).verifying_key());
        assert_eq!(envelope.issuer, SigningKey::from_bytes(&[13; 32]).verifying_key());
        assert_eq!(envelope.subject, "fixture-private-subject-marker");
        assert_eq!(envelope.namespace, "fixture-private-namespace-marker");
        let exported = format!("{checked:?} {}", serde_json::to_string(checked.receipt()).unwrap());
        let raw_policy_key = hex::encode(asset.policy_issuer.to_bytes());
        for value in [HOST, ASSET, CUSTODIAN, "/state/custody-provisioning/authority", "fixture-private-subject-marker",
            "fixture-private-namespace-marker", raw_policy_key.as_str()] {
            assert!(!exported.contains(value));
        }
        let layout = Layout { profile: "L3".into(), custody_authority: Some(checked.clone()),
            ..Default::default() };
        launchd::render_all(Path::new("/state/custody-provisioning/rendered"), &layout).unwrap();
        let argv = launchd::daemon_args(DaemonId::CustodyVault, &layout);
        assert!(argv.windows(2).any(|pair| pair == ["--custody-authority-config", CONFIG]));
        assert!(!argv.iter().any(|v| v.contains(HOST) || v.contains(ASSET) || v.contains(CUSTODIAN)));
        for legacy in LEGACY_AUTHORITY_ARGUMENTS {
            assert!(!argv.iter().any(|v| v == &format!("--{legacy}")));
        }
        let parsed = DaemonArgs::parse(std::iter::once("custody".into()).chain(argv)).unwrap();
        let from_entry = CustodyProvisioning::from_daemon_args(&parsed, now).unwrap().unwrap();
        assert_eq!(from_entry.receipt(), checked.receipt());
        assert_eq!(from_entry.authorities().0.policy_issuer, asset.policy_issuer);
        let sandbox = launchd::sandbox_profile(DaemonId::CustodyVault, &layout);
        for path in checked.read_paths() {
            assert!(sandbox.contains(&format!("(allow file-read* (literal \"{}\"))", path.display())));
        }
        for parent in checked.ancestor_paths() {
            assert!(sandbox.contains(&format!("(allow file-read-data file-read-metadata (literal \"{}\"))", parent.display())));
        }
        assert!(!sandbox.contains("(subpath \"/state/custody-provisioning/authority"));
        for daemon in DaemonId::ALL.into_iter().filter(|d| *d != DaemonId::CustodyVault) {
            assert!(!launchd::daemon_args(daemon, &layout).iter().any(|v| v == "--custody-authority-config"));
            assert!(!launchd::sandbox_profile(daemon, &layout).contains("/state/custody-provisioning/authority"));
        }
        let spaced_key = "/state/custody-provisioning/authority/policy issuer.pub";
        fs::rename("/state/custody-provisioning/authority/policy.pub", spaced_key).unwrap();
        let mut spaced_manifest = manifest(); spaced_manifest["asset_policy_key_file"] = json!(spaced_key);
        let spaced_path = "/state/custody-provisioning/authority/custody authority.json";
        put(spaced_path, serde_json::to_vec(&spaced_manifest).unwrap());
        let spaced = CustodyProvisioning::load(Path::new(spaced_path), Profile::L3, now).unwrap();
        let spaced_layout = Layout { custody_authority: Some(spaced.clone()), ..layout };
        let spaced_argv = launchd::daemon_args(DaemonId::CustodyVault, &spaced_layout);
        assert!(spaced_argv.windows(2).any(|pair| pair == ["--custody-authority-config", spaced_path]));
        let parsed = DaemonArgs::parse(std::iter::once("custody".into()).chain(spaced_argv)).unwrap();
        assert_eq!(CustodyProvisioning::from_daemon_args(&parsed, now).unwrap().unwrap().receipt(), spaced.receipt());
        assert!(launchd::sandbox_profile(DaemonId::CustodyVault, &spaced_layout)
            .contains(&format!("(allow file-read* (literal \"{spaced_key}\"))")));
    }

    fn schema(now: i64) {
        let complete = manifest();
        for field in complete.as_object().unwrap().keys() {
            let mut partial = complete.clone();
            partial.as_object_mut().unwrap().remove(field);
            put(CONFIG, serde_json::to_vec(&partial).unwrap());
            denied(CONFIG, Profile::L3, now, "CUSTODY_PROVISIONING_SCHEMA");
        }
        let mut unknown = complete.clone(); unknown["private_issuer_seed"] = json!("must-refuse");
        put(CONFIG, serde_json::to_vec(&unknown).unwrap());
        denied(CONFIG, Profile::L3, now, "CUSTODY_PROVISIONING_SCHEMA");
        let serialized = serde_json::to_string(&complete).unwrap();
        put(CONFIG, serialized.replacen('{', "{\"v\":1,", 1));
        denied(CONFIG, Profile::L3, now, "CUSTODY_PROVISIONING_SCHEMA");
        put(CONFIG, serde_json::to_vec(&complete).unwrap());
        denied(CONFIG, Profile::L2, now, "CUSTODY_PROVISIONING_PROFILE");
        let mut l1 = complete.clone(); l1["profile"] = json!("L1");
        put(CONFIG, serde_json::to_vec(&l1).unwrap());
        denied(CONFIG, Profile::L1, now, "CUSTODY_PROVISIONING_PROFILE");
        let mut version = complete; version["v"] = json!(2);
        put(CONFIG, serde_json::to_vec(&version).unwrap());
        denied(CONFIG, Profile::L3, now, "CUSTODY_PROVISIONING_PROFILE");
    }

    fn policy_failures(now: i64) {
        let invalid_point = (0..=255).map(|byte| [byte; 32])
            .find(|bytes| VerifyingKey::from_bytes(bytes).is_err()).unwrap();
        for field in ["asset_policy_key_file", "asset_inventory_key_file", "envelope_policy_key_file"] {
            let path = manifest()[field].as_str().unwrap().to_owned();
            let original = fs::read(&path).unwrap();
            for invalid in ["not-a-key".to_owned(), "aa".repeat(31), "ff".repeat(33), hex::encode(invalid_point)] {
                put(&path, invalid);
                denied(CONFIG, Profile::L3, now, "CUSTODY_PROVISIONING_PUBLIC_KEY");
            }
            let mut identity = [0; 32]; identity[0] = 1;
            for weak in [[0; 32], identity] {
                // Both points have valid encodings, but cannot be issuer pins.
                assert!(VerifyingKey::from_bytes(&weak).unwrap().is_weak());
                put(&path, hex::encode(weak));
                denied(CONFIG, Profile::L3, now, "CUSTODY_PROVISIONING_PUBLIC_KEY");
            }
            put(&path, original);
        }
        let pin = fs::read("/state/custody-provisioning/authority/policy.pub").unwrap();
        put("/state/custody-provisioning/authority/policy.pub",
            hex::encode(SigningKey::from_bytes(&[99; 32]).verifying_key().to_bytes()));
        denied(CONFIG, Profile::L3, now, "CUSTODY_PROVISIONING_POLICY");
        put("/state/custody-provisioning/authority/policy.pub", pin);
        let mut invalid = policy(now); invalid.signature[0] ^= 1;
        put("/state/custody-provisioning/authority/policy.json", serde_json::to_vec(&invalid).unwrap());
        denied(CONFIG, Profile::L3, now, "CUSTODY_PROVISIONING_POLICY");
        put("/state/custody-provisioning/authority/policy.json", serde_json::to_vec(&policy(now)).unwrap());
        denied(CONFIG, Profile::L3, now + 3600, "CUSTODY_PROVISIONING_POLICY");
        denied(CONFIG, Profile::L3, now - 11, "CUSTODY_PROVISIONING_POLICY");
        let mut wrong_scope = manifest(); wrong_scope["asset_host_id"] = json!("other-host");
        put(CONFIG, serde_json::to_vec(&wrong_scope).unwrap());
        denied(CONFIG, Profile::L3, now, "CUSTODY_PROVISIONING_POLICY");
    }

    #[track_caller]
    fn fixture_metadata(path: &str, uid: u32, mode: u32, stage: &str) {
        let observed = fs::symlink_metadata(path).unwrap();
        assert_eq!(observed.uid(), uid, "fixture ownership did not apply at {stage}");
        assert_eq!(observed.mode() & 0o7777, mode, "fixture mode did not apply at {stage}");
    }

    fn protection(now: i64) {
        eprintln!("protection stage: manifest symlink");
        symlink(CONFIG, "/state/custody-provisioning/manifest-link").unwrap();
        denied("/state/custody-provisioning/manifest-link", Profile::L3, now, "CUSTODY_PROVISIONING_PROTECTED_FILE");
        eprintln!("protection stage: ancestor symlink");
        symlink("/state/custody-provisioning/authority", "/state/custody-provisioning/ancestor-link").unwrap();
        denied("/state/custody-provisioning/ancestor-link/custody.json", Profile::L3, now, "CUSTODY_PROVISIONING_PROTECTED_FILE");
        let original = fs::read("/state/custody-provisioning/authority/inventory.pub").unwrap();
        fs::rename("/state/custody-provisioning/authority/inventory.pub", "/state/custody-provisioning/authority/original.pub").unwrap();
        eprintln!("protection stage: referenced pin symlink");
        symlink("/state/custody-provisioning/authority/original.pub", "/state/custody-provisioning/authority/inventory.pub").unwrap();
        denied(CONFIG, Profile::L3, now, "CUSTODY_PROVISIONING_PROTECTED_FILE");
        fs::remove_file("/state/custody-provisioning/authority/inventory.pub").unwrap();
        eprintln!("protection stage: referenced pin FIFO");
        let fifo = CString::new("/state/custody-provisioning/authority/inventory.pub").unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        denied(CONFIG, Profile::L3, now, "CUSTODY_PROVISIONING_PROTECTED_FILE");
        fs::remove_file("/state/custody-provisioning/authority/inventory.pub").unwrap();
        put("/state/custody-provisioning/authority/inventory.pub", &original);
        for mode in [0o664, 0o646] {
            eprintln!("protection stage: writable pin mode {mode:o}");
            fs::set_permissions("/state/custody-provisioning/authority/inventory.pub", fs::Permissions::from_mode(mode)).unwrap();
            fixture_metadata("/state/custody-provisioning/authority/inventory.pub", 0, mode, "writable pin");
            denied(CONFIG, Profile::L3, now, "CUSTODY_PROVISIONING_PROTECTED_FILE");
        }
        put("/state/custody-provisioning/authority/inventory.pub", &original);
        fixture_metadata("/state/custody-provisioning/authority/inventory.pub", 0, 0o644, "restored pin after mode cases");
        eprintln!("protection stage: writable ancestor");
        fs::set_permissions("/state/custody-provisioning/authority", fs::Permissions::from_mode(0o775)).unwrap();
        fixture_metadata("/state/custody-provisioning/authority", 0, 0o775, "writable ancestor");
        denied(CONFIG, Profile::L3, now, "CUSTODY_PROVISIONING_PROTECTED_PATH");
        fs::set_permissions("/state/custody-provisioning/authority", fs::Permissions::from_mode(0o755)).unwrap();
        fixture_metadata("/state/custody-provisioning/authority", 0, 0o755, "restored ancestor after mode case");
        eprintln!("protection stage: unprotected tmp ancestor");
        denied("/tmp/not-a-protected-manifest", Profile::L3, now, "CUSTODY_PROVISIONING_PROTECTED_PATH");
        for bytes in [vec![], vec![b'a'; 129]] {
            eprintln!("protection stage: pin length {}", bytes.len());
            put("/state/custody-provisioning/authority/inventory.pub", bytes);
            denied(CONFIG, Profile::L3, now, "CUSTODY_PROVISIONING_PROTECTED_FILE");
        }
        put("/state/custody-provisioning/authority/inventory.pub", original);
        eprintln!("protection stage: manifest oversize");
        put(CONFIG, vec![b' '; 16 * 1024 + 1]);
        denied(CONFIG, Profile::L3, now, "CUSTODY_PROVISIONING_PROTECTED_FILE");
    }

    fn owner_paths(now: i64) {
        eprintln!("protection stage: actual nonroot pathname pin");
        let pin = CString::new("/state/custody-provisioning/authority/inventory.pub").unwrap();
        assert_eq!(unsafe { libc::chown(pin.as_ptr(), 12345, 0) }, 0);
        fixture_metadata("/state/custody-provisioning/authority/inventory.pub", 12345, 0o644, "actual nonroot pin");
        denied(CONFIG, Profile::L3, now, "CUSTODY_PROVISIONING_PROTECTED_FILE");
        assert_eq!(unsafe { libc::chown(pin.as_ptr(), 0, 0) }, 0);
        fixture_metadata("/state/custody-provisioning/authority/inventory.pub", 0, 0o644, "actual restored pin");

        eprintln!("protection stage: actual nonroot pathname ancestor");
        let ancestor = CString::new("/state/custody-provisioning/authority").unwrap();
        assert_eq!(unsafe { libc::chown(ancestor.as_ptr(), 12345, 0) }, 0);
        fixture_metadata("/state/custody-provisioning/authority", 12345, 0o755, "actual nonroot ancestor");
        denied(CONFIG, Profile::L3, now, "CUSTODY_PROVISIONING_PROTECTED_PATH");
        assert_eq!(unsafe { libc::chown(ancestor.as_ptr(), 0, 0) }, 0);
        fixture_metadata("/state/custody-provisioning/authority", 0, 0o755, "actual restored ancestor");
    }

    fn paths(now: i64) {
        for path in ["relative.json", "/state/custody-provisioning/authority/../authority/custody.json",
            "/state/custody-provisioning/authority/./custody.json", "/state/custody-provisioning/authority//custody.json", "/state/custody-provisioning/authority/custody.json/",
            "/state/custody-provisioning/authority/evil\"name", "/state/custody-provisioning/authority/evil\nname", "/state/custody-provisioning/authority/$(name)"] {
            denied(path, Profile::L3, now, "CUSTODY_PROVISIONING_PATH");
        }
        for field in ["asset_policy_file", "asset_policy_key_file", "asset_inventory_key_file",
            "envelope_policy_key_file"] {
            let mut changed = manifest(); changed[field] = json!("/state/custody-provisioning/authority/../policy");
            put(CONFIG, serde_json::to_vec(&changed).unwrap());
            denied(CONFIG, Profile::L3, now, "CUSTODY_PROVISIONING_PATH");
        }
        for field in ["asset_host_id", "asset_id", "asset_custodian_id",
            "envelope_policy_subject", "envelope_policy_namespace"] {
            for value in ["".to_owned(), "x".repeat(257), "control\nmarker".into()] {
                let mut changed = manifest(); changed[field] = json!(value);
                put(CONFIG, serde_json::to_vec(&changed).unwrap());
                denied(CONFIG, Profile::L3, now, "CUSTODY_PROVISIONING_SCOPE");
            }
        }
    }

    fn stale(now: i64) {
        let original = load(now);
        let layout = Layout { profile: "L3".into(), custody_authority: Some(original.clone()),
            ..Default::default() };
        for path in [CONFIG, "/state/custody-provisioning/authority/policy.json", "/state/custody-provisioning/authority/policy.pub",
            "/state/custody-provisioning/authority/inventory.pub", "/state/custody-provisioning/authority/envelope.pub"] {
            let bytes = fs::read(path).unwrap();
            let mut changed = bytes.clone(); changed.push(b'\n'); put(path, changed);
            assert!(original.revalidate(Profile::L3, now).unwrap_err().is("CUSTODY_PROVISIONING_CHANGED"));
            assert!(launchd::render_all(Path::new("/state/custody-provisioning/must-not-exist"), &layout).is_err());
            assert!(!Path::new("/state/custody-provisioning/must-not-exist").exists());
            put(path, bytes);
        }
        let emulator = Layout { fido_emulator: true, ..layout.clone() };
        assert!(launchd::render_all(Path::new("/state/custody-provisioning/must-not-exist"), &emulator).unwrap_err()
            .is("CUSTODY_PROVISIONING_NATIVE_REQUIRED"));
        assert!(!Path::new("/state/custody-provisioning/must-not-exist").exists());
        let wrong_profile = Layout { profile: "L2".into(), ..layout.clone() };
        assert!(launchd::render_all(Path::new("/state/custody-provisioning/must-not-exist"), &wrong_profile).is_err());
        assert!(!Path::new("/state/custody-provisioning/must-not-exist").exists());
        assert!(original.revalidate(Profile::L3, now + 3600).is_err());
        original.revalidate(Profile::L3, now).unwrap();
    }
}
