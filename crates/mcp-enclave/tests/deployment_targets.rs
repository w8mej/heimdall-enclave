//! Public configuration and routing checks only. No native APIs, IPC, service
//! startup, sealed state, hardware or issuer production authority is exercised.
use enclave_core::{daemon::DaemonId, deployment::*, Profile, runtime::DaemonArgs};
use depot_enclave::launchd::{self, Layout};
use std::path::{Path, PathBuf};

fn descriptor(id: &str, role: DeploymentRole, profile: Profile) -> DeploymentTarget {
    let root = Path::new("/state/deployment-target-routing").join(id);
    DeploymentTarget {
        version: 1, target_id: id.into(), role, profile,
        authority_config: root.join("support/authority.json"),
        expected_artifacts_manifest: root.join("support/artifacts.json"),
        codesign_pins_file: root.join("support/pins.json"),
        signing_identity_mode: match enclave_core::codesign::signing_mode() {
            enclave_core::codesign::SigningMode::LocalPins => DeploymentSigningMode::LocalPins,
            enclave_core::codesign::SigningMode::TeamId => DeploymentSigningMode::TeamId,
        },
        layout: DeploymentLayout { binary_dir: root.join("bin"),
            custody_bundle: root.join("support/Custody.app"), sandbox_dir: root.join("sandbox"),
            socket_root: root.join("run"), state_root: root.join("state"), audit_root: root.join("audit"),
            cas_store_root: root.join("cas"), staging_root: root.join("stage"), support_root: root.join("support"),
            launchd_namespace: format!("com.depot.{id}"), mach_service: format!("com.depot.{id}.exception") },
        broker: (profile == Profile::L3).then(|| DeploymentBroker {
            base_dir: root.join("state/apfs-broker"), tuf_root_file: root.join("support/tuf-root.json") }),
        shared_read_only_inputs: vec![],
    }
}

#[test]
fn target_pair_refuses_installed_and_cross_target_routes() {
    let a = descriptor("dedicated", DeploymentRole::DedicatedTest, Profile::L3);
    let b = descriptor("upgrade", DeploymentRole::ExistingUpgrade, Profile::L2);
    a.validate_pair(&b).unwrap();
    assert_eq!(DeploymentTarget::parse(&serde_json::to_vec(&a).unwrap()).unwrap(), a);
    let mut wrong = b.clone(); wrong.layout.socket_root = a.layout.socket_root.clone();
    assert!(a.validate_pair(&wrong).is_err());
    let mut wrong = b.clone(); wrong.codesign_pins_file = a.codesign_pins_file.clone();
    assert!(a.validate_pair(&wrong).is_err());
    let mut wrong = a.clone(); wrong.layout.socket_root = "/var/run/enclave".into();
    assert!(wrong.validate().is_err());
    let mut wrong = a.clone(); wrong.broker.as_mut().unwrap().base_dir = "/some-other-broker".into();
    assert!(wrong.validate().is_err());
    let mut wrong = b.clone(); wrong.layout.mach_service = a.layout.mach_service.clone();
    assert!(a.validate_pair(&wrong).is_err());
}

#[test]
fn unconfigured_render_arguments_keep_installed_defaults() {
    let l = Layout::default();
    assert!(l.deployment.is_none());
    for d in DaemonId::ALL {
        let args = launchd::daemon_args(d, &l);
        assert!(!args.iter().any(|s| s == "--deployment-target"));
        let parsed = DaemonArgs::parse(std::iter::once("daemon".into()).chain(args)).unwrap();
        assert_eq!(parsed.profile, Profile::L2);
        assert_eq!(parsed.socket_dir, Path::new("/var/run/enclave"));
        assert_eq!(parsed.audit_dir.as_deref(), Some(Path::new("/var/log/enclave")));
        assert!(launchd::plist(d, &l).contains(&d.launchd_label()));
    }
    for plist in [launchd::supervisor_plist(&l), launchd::browser_plist(&l),
        launchd::intent_plist(&l), launchd::gateway_plist(&l), launchd::hydrate_plist(&l)] {
        assert!(!plist.contains("--deployment-target"));
        assert!(!plist.contains("--deployment-config"));
    }
    assert_eq!(launchd::oidc_plist_for_layout(&l), launchd::oidc_plist());
}

#[cfg(unix)]
mod protected {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use enclave_custody_vaultd::ctap::asset_enrollment::{AssetEnrollmentPolicy,
        SignedAssetEnrollmentPolicy, AttestationMode};
    use serde_json::json;
    use std::{fs, os::unix::fs::PermissionsExt};
    const ROOT: &str = "/state/deployment-target-routing";
    const HOST: &str = "routing-fixture-host";
    const ASSET: &str = "routing-fixture-asset";
    const CUSTODIAN: &str = "routing-fixture-custodian";

    fn put(path: &Path, bytes: impl AsRef<[u8]>) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
    }
    fn config_path(t: &DeploymentTarget) -> PathBuf { t.layout.support_root.join("target.json") }
    fn setup(t: &DeploymentTarget, now: i64, hash: &str) {
        let support = &t.layout.support_root;
        fs::create_dir_all(support).unwrap();
        fs::set_permissions(support, fs::Permissions::from_mode(0o755)).unwrap();
        let policy = AssetEnrollmentPolicy { version: 1, revision: 7,
            host_id: HOST.into(), asset_id: ASSET.into(), custodian_id: CUSTODIAN.into(),
            aaguid: [0x31; 16], mode: AttestationMode::BasicWithIndependentAsset,
            enterprise_leaf_sha256: None, rationale: "isolated routing fixture".into(),
            issued_unix: now - 10, expires_unix: now + 3600 };
        let signature = SigningKey::from_bytes(&[11; 32])
            .sign(&policy.signing_message().unwrap()).to_bytes().to_vec();
        put(&support.join("policy.json"), serde_json::to_vec(&SignedAssetEnrollmentPolicy { policy, signature }).unwrap());
        for (name, seed) in [("policy",11), ("inventory",12), ("envelope",13)] {
            put(&support.join(format!("{name}.pub")),
                hex::encode(SigningKey::from_bytes(&[seed;32]).verifying_key().to_bytes()));
        }
        put(&t.authority_config, serde_json::to_vec(&json!({"v":1,"profile":t.profile,
            "asset_policy_file":support.join("policy.json"), "asset_policy_key_file":support.join("policy.pub"),
            "asset_inventory_key_file":support.join("inventory.pub"), "asset_host_id":HOST,
            "asset_id":ASSET, "asset_custodian_id":CUSTODIAN,
            "envelope_policy_key_file":support.join("envelope.pub"),
            "envelope_policy_subject":"routing-fixture-subject", "envelope_policy_namespace":"routing-fixture-namespace"})).unwrap());
        let mut pins = serde_json::Map::new();
        for d in DaemonId::ALL { pins.insert(d.launchd_label(), json!([hash.repeat(20)])); }
        for id in [enclave_core::codesign::CTL_IDENTIFIER, enclave_core::codesign::INTENT_IDENTIFIER,
            enclave_core::supervisor::LAUNCHD_LABEL, launchd::OIDC_LABEL,
            "com.enterprise.enclave.apfs-broker"] { pins.insert(id.into(), json!([hash.repeat(20)])); }
        put(&t.codesign_pins_file, serde_json::to_vec(&json!({"v":1,"pins":pins})).unwrap());
        put(&t.expected_artifacts_manifest, b"{\"fixture_only\":true}");
        if let Some(broker) = &t.broker { put(&broker.tuf_root_file, b"{\"fixture_only\":true}"); }
        put(&config_path(t), serde_json::to_vec(t).unwrap());
    }

    fn has_pair(args: &[String], key: &str, value: &Path) {
        assert!(args.windows(2).any(|p| p[0] == key && Path::new(&p[1]) == value), "missing {key}");
    }
    fn check_render(l: &Layout, other: &DeploymentTarget, bind: bool) {
        let checked = l.deployment.as_ref().unwrap(); let t = checked.target();
        for d in DaemonId::ALL {
            let args = launchd::daemon_args(d, l);
            has_pair(&args, "--deployment-target", checked.config_path());
            has_pair(&args, "--state-dir", &t.layout.state_root.join(d.dir_name()));
            has_pair(&args, "--sandbox-profile", &t.layout.sandbox_dir.join(format!("{}.sb",d.plist_suffix())));
            for marker in [HOST, ASSET, CUSTODIAN, "routing-fixture-subject", "routing-fixture-namespace"] {
                assert!(!args.iter().any(|a| a.contains(marker)));
            }
            let parsed = DaemonArgs::parse(std::iter::once("daemon".into()).chain(args)).unwrap();
            assert_eq!(parsed.profile, t.profile); assert_eq!(parsed.socket_dir, t.layout.socket_root);
            assert_eq!(parsed.audit_dir.as_deref(), Some(t.layout.audit_root.as_path()));
            if bind {
                // Render-only fixture: manual selection never provisions or retains
                // the real actor startup lease, so binding must refuse it absent.
                assert!(parsed.bind_deployment_context().unwrap_err().is("STARTUP_LEASE_MISSING_OR_UNKNOWN"));
            }
            let plist = launchd::plist(d,l); assert!(plist.contains(&l.job_label(&d.launchd_label())));
            assert!(plist.contains(d.account()));
            let sb = launchd::sandbox_profile(d,l);
            for path in [checked.config_path(), &t.authority_config, &t.expected_artifacts_manifest, &t.codesign_pins_file] {
                assert!(sb.contains(&format!("(literal \"{}\")",path.display())));
            }
            assert!(!sb.contains(&other.codesign_pins_file.display().to_string()));
            assert!(!sb.contains(enclave_core::codesign::PIN_FILE));
            assert!(sb.contains(&t.layout.mach_service));
        }
        let cas = launchd::daemon_args(DaemonId::SwarmSync,l);
        has_pair(&cas,"--store-dir",&t.layout.cas_store_root);
        let custody = launchd::daemon_args(DaemonId::CustodyVault,l);
        has_pair(&custody,"--custody-authority-config",&t.authority_config);
        has_pair(&custody,"--oidc-broker-config",&t.layout.support_root.join("oidc-broker-identity.json"));
        let intent = launchd::intent_plist(l);
        assert!(intent.contains(&t.layout.socket_root.join("supervisor/supervisor.sock").display().to_string()));
        let sup = launchd::supervisor_plist(l); assert!(sup.contains(&t.layout.mach_service));
        for plist in [intent, sup, launchd::hydrate_plist(l), launchd::browser_plist(l), launchd::gateway_plist(l)] {
            assert!(plist.contains(&checked.config_path().display().to_string()));
            assert!(!plist.contains(&other.layout.socket_root.display().to_string()));
        }
        let oidc = launchd::oidc_plist_for_layout(l);
        for name in ["EnclaveOIDC.app", "oidc-broker-identity.json", "oidc-oauth.json"] {
            assert!(oidc.contains(&t.layout.support_root.join(name).display().to_string()));
        }
        assert!(oidc.contains("<string>--deployment-target</string>"));
        assert!(oidc.contains(&checked.config_path().display().to_string()));
        assert!(!oidc.contains(&other.codesign_pins_file.display().to_string()));
        if t.profile == Profile::L3 {
            assert!(launchd::apfs_broker_plist(l).contains(&checked.config_path().display().to_string()));
        }
        let out = t.layout.staging_root.join("launchd");
        let files = launchd::render_all(&out,l).unwrap();
        for d in DaemonId::ALL { assert!(out.join(format!("{}.plist",l.job_label(&d.launchd_label()))).is_file()); }
        assert!(files.iter().all(|p| Path::new(p).starts_with(&out)));
        assert!(!out.join(format!("{}.plist",DaemonId::CustodyVault.launchd_label())).exists());
    }

    #[test]
    #[ignore = "requires coordinator private-root fixture with /state; no host-root execution"]
    fn protected_two_target_routes_refuse_mixed_context_and_changed_descriptor() {
        assert_eq!(unsafe {libc::geteuid()},0);
        assert_eq!(std::env::var("ENCLAVE_TEST_STATE_ROOT").as_deref(),Ok("/state"));
        fs::create_dir(ROOT).unwrap();
        fs::set_permissions(ROOT,fs::Permissions::from_mode(0o700)).unwrap();
        struct Cleanup; impl Drop for Cleanup { fn drop(&mut self) {let _ = fs::remove_dir_all(ROOT);} }
        let _cleanup = Cleanup;
        let a = descriptor("dedicated",DeploymentRole::DedicatedTest,Profile::L3);
        let b = descriptor("upgrade",DeploymentRole::ExistingUpgrade,Profile::L2);
        let now = enclave_crypto::time::now_unix(); setup(&a,now,"ab"); setup(&b,now,"cd");
        let ca = load(&config_path(&a)).unwrap(); let cb = load(&config_path(&b)).unwrap();
        select(ca.clone()).unwrap();
        let la = Layout::for_target(ca.clone()).unwrap(); let lb = Layout::for_target(cb.clone()).unwrap();
        check_render(&la,&b,true); check_render(&lb,&a,false);
        let env = depot_enclave::ctl::Env::production_for_target(&ca).unwrap();
        assert_eq!(env.uid_of(DaemonId::CustodyVault),703); assert!(!env.dev);
        assert_eq!(env.socket_dir,a.layout.socket_root); assert_eq!(env.state_dir,a.layout.state_root);
        assert!(depot_enclave::ctl::Env::production_for_target(&cb).is_err());
        assert!(select(cb).is_err()); assert_eq!(selected_pin_file(),a.codesign_pins_file);
        let foreign = DaemonArgs::parse(std::iter::once("daemon".into()).chain(launchd::daemon_args(DaemonId::CustodyVault,&lb))).unwrap();
        assert!(foreign.bind_deployment_context().is_err());
        let mut mixed = la.clone(); mixed.socket_dir = b.layout.socket_root.display().to_string();
        assert!(mixed.validate().is_err());
        let mut mixed = la.clone(); mixed.profile = "L2".into(); assert!(mixed.validate().is_err());
        let mut mixed = la.clone(); mixed.fido_emulator = true; assert!(mixed.validate().is_err());
        let outside = Path::new(ROOT).join("wrong-stage");
        assert!(launchd::render_all(&outside,&la).unwrap_err().is("DEPLOYMENT_STAGING_MISMATCH"));
        assert!(!outside.exists());
        let mut changed = a.clone(); changed.layout.mach_service = "com.depot.changed.exception".into();
        put(&config_path(&a),serde_json::to_vec(&changed).unwrap());
        assert!(la.validate().is_err());
        put(&config_path(&a),serde_json::to_vec(&a).unwrap());
        fs::remove_file(&a.codesign_pins_file).unwrap();
        assert!(load(&config_path(&a)).is_err());
        assert!(enclave_core::codesign::CodeRequirement::pinned_boundary(enclave_core::codesign::CTL_IDENTIFIER).is_err());
        assert!(b.codesign_pins_file.is_file());
    }
}

#[cfg(unix)]
mod packaging_guard {
    use std::{fs, os::unix::fs::PermissionsExt, path::{Path, PathBuf}, process::Command};

    struct Fixture(PathBuf);
    impl Drop for Fixture { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
    fn executable(path: &Path, body: &str) {
        fs::write(path,body).unwrap(); fs::set_permissions(path,fs::Permissions::from_mode(0o700)).unwrap();
    }
    fn fixture() -> Fixture {
        let root = std::env::temp_dir().join(format!("depot-build-guard-{}-{}",std::process::id(),enclave_core::rng::u64()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root,fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir_all(root.join("packaging/macos")).unwrap();
        fs::create_dir(root.join("tools")).unwrap(); fs::create_dir(root.join("home")).unwrap();
        fs::write(root.join("packaging/macos/build.sh"), include_str!("../../../packaging/macos/build.sh")).unwrap();
        executable(&root.join("tools/uname"),"#!/bin/sh\nprintf 'Darwin\\n'\n");
        executable(&root.join("tools/id"),"#!/bin/sh\nprintf '501\\n'\n");
        // Deliberately stop at the first build boundary. No Cargo/build or
        // cleanup tool is ever executed; stubs only mark reachability.
        executable(&root.join("tools/cargo"),"#!/bin/sh\nprintf 'reached\\n' > cargo-reached\nexit 79\n");
        executable(&root.join("tools/rm"),"#!/bin/sh\nprintf 'reached\\n' > cleanup-reached\nexit 80\n");
        executable(&root.join("tools/validator"),"#!/bin/sh\nprintf '%s\\n' \"$@\" > validator-arguments\nexit 73\n");
        Fixture(root)
    }
    fn command(f: &Fixture) -> Command {
        let mut command = Command::new("/bin/sh");
        command.arg(f.0.join("packaging/macos/build.sh")).env_clear()
            .env("PATH",format!("{}:/usr/bin:/bin",f.0.join("tools").display()))
            .env("HOME",f.0.join("home"))
            .env("depot_IFC_GRANT_PUBLIC_KEY","ab".repeat(32))
            .env("depot_DIST",f.0.join("undeclared-output"))
            .env("depot_BUILD_PROFILE","L3");
        command
    }
    #[test]
    fn configured_packaging_refusal_precedes_environment_build_and_cleanup() {
        let f = fixture();
        fs::create_dir(f.0.join("home/.cargo")).unwrap();
        fs::write(f.0.join("home/.cargo/env"),"printf 'reached\\n' > environment-reached\n").unwrap();
        let output = command(&f).env("depot_DEPLOYMENT_CONFIG","/protected/target.json")
            .env("depot_DEPLOYMENT_VALIDATOR",f.0.join("tools/validator")).output().unwrap();
        assert_eq!(output.status.code(),Some(73));
        let args = fs::read_to_string(f.0.join("validator-arguments")).unwrap();
        let expected = vec!["--profile".to_owned(),"L3".into(),"--json".into(),"--deployment-config".into(),
            "/protected/target.json".into(),"launchd".into(),"deployment-check".into(),"--dist".into(),
            f.0.join("undeclared-output").display().to_string(),"--signing-mode".into(),"local-pins".into()];
        assert_eq!(args.lines().collect::<Vec<_>>(),expected.iter().map(String::as_str).collect::<Vec<_>>());
        for marker in ["environment-reached","cargo-reached","cleanup-reached","undeclared-output"] {
            assert!(!f.0.join(marker).exists(),"unexpected {marker}");
        }
    }
    #[test]
    fn configured_packaging_missing_validator_refuses_before_build() {
        let f = fixture();
        let output = command(&f).env("depot_DEPLOYMENT_CONFIG","/protected/target.json")
            .env("depot_DEPLOYMENT_VALIDATOR",f.0.join("missing-validator")).output().unwrap();
        assert_eq!(output.status.code(),Some(2));
        for marker in ["validator-arguments","cargo-reached","cleanup-reached","undeclared-output"] {
            assert!(!f.0.join(marker).exists());
        }
    }
    #[test]
    fn default_packaging_preserves_build_boundary_without_validator() {
        let f = fixture();
        let output = command(&f).env("depot_DEPLOYMENT_VALIDATOR",f.0.join("tools/validator"))
            .output().unwrap();
        assert_eq!(output.status.code(),Some(79));
        assert!(f.0.join("cargo-reached").is_file());
        assert!(!f.0.join("validator-arguments").exists());
        assert!(!f.0.join("cleanup-reached").exists());
        assert!(!f.0.join("undeclared-output").exists());
    }
}
