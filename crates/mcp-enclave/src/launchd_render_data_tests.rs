//! Public-data renderer tests. No native code/guard/birth/approval is forged.
use super::*;
use serde_json::json;
fn raw(root: &Path) -> DeploymentTarget {
    let token = root.file_name().unwrap().to_str().unwrap();
    let support = root.join("support");
    DeploymentTarget {
        version: 1,
        target_id: format!("ykft-{token}"),
        role: DeploymentRole::DedicatedTest,
        profile: Profile::L2,
        authority_config: support.join("authority.json"),
        expected_artifacts_manifest: root.join("control/inventory.json"),
        codesign_pins_file: support.join("codesign-pins.json"),
        signing_identity_mode: DeploymentSigningMode::LocalPins,
        layout: enclave_core::deployment::DeploymentLayout {
            binary_dir: root.join("bin"),
            custody_bundle: support.join("Custody.app"),
            sandbox_dir: root.join("sandbox"),
            socket_root: root.join("run"),
            state_root: root.join("state"),
            audit_root: root.join("audit"),
            cas_store_root: root.join("cas"),
            staging_root: root.join("stage"),
            support_root: support,
            launchd_namespace: format!("com.enterprise.enclave.ykft.n{token}"),
            mach_service: format!("com.enterprise.enclave.ykft.n{token}.exception"),
        },
        broker: None,
        shared_read_only_inputs: vec![],
    }
}
fn manifest(target: &DeploymentTarget) -> Vec<u8> {
    let support = &target.layout.support_root;
    serde_json::to_vec(&json!({"v":1,"profile":"L2","asset_policy_file":support.join("policy.json"),
        "asset_policy_key_file":support.join("policy.pub"),"asset_inventory_key_file":support.join("inventory.pub"),
        "envelope_policy_key_file":support.join("envelope.pub"),"asset_host_id":"PUBLIC-SYNTHETIC-HOST-NOT-OUTPUT",
        "asset_id":"PUBLIC-SYNTHETIC-ASSET-NOT-OUTPUT","asset_custodian_id":"PUBLIC-SYNTHETIC-CUSTODIAN-NOT-OUTPUT",
        "envelope_policy_subject":"PUBLIC-SYNTHETIC-SUBJECT-NOT-OUTPUT","envelope_policy_namespace":"PUBLIC-SYNTHETIC-NAMESPACE-NOT-OUTPUT"})).unwrap()
}
fn inert() -> (DeploymentTarget, PathBuf) {
    let root = Path::new("/unopened-render-data/0123456789abcdef0123456789abcdef");
    (raw(root), root.join("config/deployment.json"))
}
#[test]
fn pure_export_is_exact_twenty_closed_public_paths_with_no_input_scope_identifiers() {
    let (target, descriptor) = inert();
    let bytes = serde_json::to_vec(&target).unwrap();
    let controls = manifest(&target);
    let files = public_artifacts(&bytes, &descriptor, &controls).unwrap();
    assert_eq!(files.len(), 20);
    assert_eq!(
        files,
        public_artifacts(&bytes, &descriptor, &controls).unwrap()
    );
    for (path, body) in &files {
        assert!(path.starts_with("launchd/"));
        assert!(!body.contains("PUBLIC-SYNTHETIC-"));
        assert!(!body.contains("com.enterprise.enclave.ykft.nffffffff"));
    }
    for daemon in DaemonId::ALL {
        let path = format!(
            "launchd/{}.{}.plist",
            target.layout.launchd_namespace,
            daemon.plist_suffix()
        );
        let plist = &files[&path];
        assert!(plist.contains(descriptor.to_str().unwrap()));
        assert!(plist.contains(target.layout.state_root.to_str().unwrap()));
    }
    assert!(
        !descriptor.exists(),
        "pure export must not need or create final descriptor"
    );
}
#[test]
fn public_export_refuses_nonallocated_scope_aliases_and_oversized_input_before_output() {
    let (target, descriptor) = inert();
    let controls = manifest(&target);
    for case in 0..7 {
        let mut changed = target.clone();
        let mut path = descriptor.clone();
        match case {
            0 => changed.role = DeploymentRole::ExistingUpgrade,
            1 => changed.profile = Profile::L3,
            2 => changed.target_id = "ykft-wrong".into(),
            3 => changed.layout.launchd_namespace = "com.depot.foreign".into(),
            4 => changed.layout.mach_service = "com.depot.foreign.exception".into(),
            5 => path = descriptor.with_file_name("other.json"),
            _ => changed.layout.state_root = "/outside/state".into(),
        }
        assert!(
            public_artifacts(&serde_json::to_vec(&changed).unwrap(), &path, &controls).is_err()
        );
    }
    assert!(public_artifacts(&vec![b' '; 65537], &descriptor, &controls)
        .unwrap_err()
        .is("BIRTH_PUBLIC_RENDER_INPUT_BOUND"));
    let mut aliases: serde_json::Value = serde_json::from_slice(&controls).unwrap();
    aliases["asset_inventory_key_file"] = aliases["asset_policy_key_file"].clone();
    assert!(public_artifacts(
        &serde_json::to_vec(&target).unwrap(),
        &descriptor,
        &serde_json::to_vec(&aliases).unwrap()
    )
    .is_err());
}

#[test]
#[ignore = "requires coordinator actual protected private-root fixture with /state"]
fn actual_protected_layout_and_public_data_projection_render_identical_bytes() {
    use ed25519_dalek::{Signer, SigningKey};
    use enclave_custody_vaultd::ctap::asset_enrollment::{
        AssetEnrollmentPolicy, AttestationMode, SignedAssetEnrollmentPolicy,
    };
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, PermissionsExt},
    };
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert_eq!(
        std::env::var("ENCLAVE_TEST_STATE_ROOT").as_deref(),
        Ok("/state")
    );
    let parent = Path::new("/state/public-render-data");
    fs::DirBuilder::new().mode(0o700).create(parent).unwrap();
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(parent.to_owned());
    let root = parent.join("0123456789abcdef0123456789abcdef");
    let target = raw(&root);
    let descriptor = root.join("config/deployment.json");
    for path in [
        &target.layout.support_root,
        descriptor.parent().unwrap(),
        target.expected_artifacts_manifest.parent().unwrap(),
    ] {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .unwrap();
    }
    let put = |path: &Path, bytes: &[u8]| {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
    };
    let now = enclave_crypto::time::now_unix();
    let policy = AssetEnrollmentPolicy {
        version: 1,
        revision: 7,
        host_id: "PUBLIC-SYNTHETIC-HOST-NOT-OUTPUT".into(),
        asset_id: "PUBLIC-SYNTHETIC-ASSET-NOT-OUTPUT".into(),
        custodian_id: "PUBLIC-SYNTHETIC-CUSTODIAN-NOT-OUTPUT".into(),
        aaguid: [0x31; 16],
        mode: AttestationMode::BasicWithIndependentAsset,
        enterprise_leaf_sha256: None,
        rationale: "public renderer isolated software fixture".into(),
        issued_unix: now - 10,
        expires_unix: now + 3600,
    };
    let signature = SigningKey::from_bytes(&[11; 32])
        .sign(&policy.signing_message().unwrap())
        .to_bytes()
        .to_vec();
    put(
        &target.layout.support_root.join("policy.json"),
        &serde_json::to_vec(&SignedAssetEnrollmentPolicy { policy, signature }).unwrap(),
    );
    for (name, seed) in [("policy", 11), ("inventory", 12), ("envelope", 13)] {
        put(
            &target.layout.support_root.join(format!("{name}.pub")),
            hex::encode(
                SigningKey::from_bytes(&[seed; 32])
                    .verifying_key()
                    .to_bytes(),
            )
            .as_bytes(),
        );
    }
    let controls = manifest(&target);
    put(&target.authority_config, &controls);
    let mut pins = serde_json::Map::new();
    for daemon in DaemonId::ALL {
        pins.insert(daemon.launchd_label(), json!(["ab".repeat(20)]));
    }
    for label in [
        enclave_core::codesign::CTL_IDENTIFIER,
        enclave_core::codesign::INTENT_IDENTIFIER,
        enclave_core::supervisor::LAUNCHD_LABEL,
        OIDC_LABEL,
        "com.enterprise.enclave.apfs-broker",
    ] {
        pins.insert(label.into(), json!(["ab".repeat(20)]));
    }
    put(
        &target.codesign_pins_file,
        &serde_json::to_vec(&json!({"v":1,"pins":pins})).unwrap(),
    );
    put(
        &target.expected_artifacts_manifest,
        b"{\"fixture_only\":true}",
    );
    let bytes = serde_json::to_vec(&target).unwrap();
    put(&descriptor, &bytes);
    let checked = enclave_core::deployment::load(&descriptor).unwrap();
    let actual = super::super::Layout::for_target(checked).unwrap();
    let original = artifacts(&Layout::from_protected(&actual));
    assert_eq!(
        public_artifacts(&bytes, &descriptor, &controls).unwrap(),
        original
    );
    let out = target.layout.staging_root.join("launchd");
    for name in super::super::render_all(&out, &actual).unwrap() {
        let path = Path::new(&name);
        let relative = format!("launchd/{}", path.file_name().unwrap().to_str().unwrap());
        assert_eq!(fs::read(path).unwrap(), original[&relative].as_bytes());
    }
}
