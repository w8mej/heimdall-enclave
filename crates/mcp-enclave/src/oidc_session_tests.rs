use super::*;
use std::{cell::Cell, os::unix::fs::{DirBuilderExt, PermissionsExt}};

struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        // The coordinated private-root harness materializes this compile-time
        // target directory with protected ancestors. No host /Library path.
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target")
            .join(format!("oidc-session-{:x}", enclave_core::rng::u64()));
        std::fs::DirBuilder::new().recursive(true).mode(0o755).create(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let root = Self(path.canonicalize().unwrap()); root.config(); root
    }
    fn config(&self) {
        self.write(OAUTH, &canonical(&serde_json::json!({"v":1,"issuer":"https://idp.example", "audience":"mcpmac",
            "client_id":"client", "authorization_endpoint":"https://idp.example/auth", "token_endpoint":"https://idp.example/token",
            "redirect_uri":"com.enterprise.enclave.oidc://callback/login", "callback_scheme":"com.enterprise.enclave.oidc", "expires_unix":300})).unwrap());
        self.write(PINS, &serde_json::to_vec(&serde_json::json!({"v":1,"pins":{
            crate::launchd::OIDC_LABEL:["11".repeat(20)], codesign::INTENT_IDENTIFIER:["22".repeat(20)],
            codesign::CTL_IDENTIFIER:["33".repeat(20)], DaemonId::CustodyVault.launchd_label():["44".repeat(20)]}})).unwrap());
    }
    fn write(&self, leaf: &str, raw: &[u8]) {
        let path = self.0.join(leaf); std::fs::write(&path, raw).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    fn write_marker(&self, raw: &[u8]) {
        self.write(HIGH_WATER, raw);
        std::fs::set_permissions(self.0.join(HIGH_WATER), std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn floor(&self) -> i64 { HighWater::floor(&std::fs::read(self.0.join(HIGH_WATER)).unwrap()).unwrap() }
    fn directory(&self) -> Directory { Directory::open(&self.0).unwrap() }
}
impl Drop for Root { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
fn session() -> EnclaveResult<(u32,u32,i64)> { Ok((501,777,100)) }

#[test]
fn exact_json_replacement_changes_digest_and_never_extends_captured_identity() {
    let root = Root::new(); let directory = root.directory();
    let first = renew_in(&directory, 200, &mut session).unwrap();
    let bytes = std::fs::read(root.0.join(IDENTITY)).unwrap();
    assert_eq!(String::from_utf8(bytes.clone()).unwrap(), "{\"audit_session_id\":777,\"console_uid\":501,\"expires_unix\":200,\"identifier\":\"com.enterprise.enclave.oidc-broker\",\"socket\":\"/var/run/enclave/oidc/501/broker.sock\",\"v\":1}");
    assert_eq!(first.identity_sha256, hex::encode(Sha256::digest(&bytes)));
    assert_eq!(std::fs::metadata(root.0.join(IDENTITY)).unwrap().mode() & 0o777, 0o644);
    assert!(renew_in(&directory, 200, &mut session).unwrap_err().is("OIDC_SESSION_EXPIRY_FLOOR"));
    let second = renew_in(&directory, 201, &mut session).unwrap();
    assert_ne!(first.identity_sha256, second.identity_sha256);
    assert!(renew_in(&directory,200,&mut session).unwrap_err().is("OIDC_SESSION_EXPIRY_FLOOR"));
    assert!(renew_in(&directory,200,&mut ||Ok((502,888,101))).unwrap_err().is("OIDC_SESSION_EXPIRY_FLOOR"));
    let next_session=renew_in(&directory,202,&mut ||Ok((502,888,101))).unwrap();
    assert_ne!(next_session.identity_sha256, first.identity_sha256);
    assert!(renew_in(&directory,201,&mut session).unwrap_err().is("OIDC_SESSION_EXPIRY_FLOOR"));
    // Existing consumers retain this old digest and expiry; successful renewal
    // changes their comparison input, never mutates their captured scope.
    assert_ne!(bytes, std::fs::read(root.0.join(IDENTITY)).unwrap());
    assert_eq!(first.expires_unix, 200);
    assert!(!format!("{second:?}").contains("audit_session_id"));
}

#[test]
fn unavailable_session_expiry_and_missing_exact_pins_refuse_without_publication() {
    let root = Root::new(); let directory = root.directory();
    for expires in [i64::MIN,100,301,i64::MAX] { assert!(renew_in(&directory, expires, &mut session).unwrap_err().is("OIDC_SESSION_EXPIRY")); }
    for (uid,audit) in [(0,777),(501,0),(501,u32::MAX)] {
        assert!(renew_in(&directory,200,&mut ||Ok((uid,audit,100))).unwrap_err().is("OIDC_SESSION_UNAVAILABLE"));
    }
    assert!(renew_in(&directory,200,&mut ||Err(err!(EACCES,"TEST_NO_SESSION"))).is_err());
    root.write(PINS, br#"{"v":1,"pins":{"com.enterprise.enclave.oidc-broker":["1111111111111111111111111111111111111111"]}}"#);
    assert!(renew_in(&directory,200,&mut session).unwrap_err().is("CODESIGN_PINS_MISSING"));
    assert!(!root.0.join(IDENTITY).exists());
}

#[test]
fn session_config_or_expiry_change_at_each_commit_boundary_cannot_succeed() {
    for cut in [2,3] {
        for change in ["session","oauth","pins","expiry"] {
            let root = Root::new(); let directory = root.directory(); let calls = Cell::new(0);
            let result = renew_in(&directory,200,&mut || {
                let call = calls.get()+1; calls.set(call);
                if call >= cut {
                    match change {
                        "session" => return Ok((501,778,100)),
                        "oauth" => { let mut oauth: serde_json::Value = serde_json::from_slice(&std::fs::read(root.0.join(OAUTH)).unwrap()).unwrap(); oauth["client_id"]="different-client".into(); root.write(OAUTH,&canonical(&oauth).unwrap()); },
                        "pins" => { let raw=std::fs::read(root.0.join(PINS)).unwrap(); let mut pins:serde_json::Value=serde_json::from_slice(&raw).unwrap();pins["pins"][crate::launchd::OIDC_LABEL]=serde_json::json!(["55".repeat(20)]);root.write(PINS,&serde_json::to_vec(&pins).unwrap()); },
                        "expiry" => return Ok((501,777,200)),
                        _ => unreachable!(),
                    }
                }
                session()
            });
            assert!(result.is_err(), "{cut}/{change}");
            assert_eq!(root.floor(), 200, "burned floor survives every later failure");
            if cut == 3 {
                let raw=std::fs::read(root.0.join(IDENTITY)).unwrap();
                let tombstone:Tombstone=serde_json::from_slice(&raw).unwrap();assert!(tombstone.invalid);
                assert_eq!(Identity::expiry_floor(&raw).unwrap(),200);
                root.config();
                assert!(renew_in(&directory,200,&mut session).unwrap_err().is("OIDC_SESSION_EXPIRY_FLOOR"));
            } else { assert!(!root.0.join(IDENTITY).exists(), "{cut}/{change}"); }
        }
    }
}

#[test]
fn held_directory_lease_nofollow_and_hardlink_checks_protect_publication() {
    let root = Root::new(); let directory = root.directory();
    let lease = directory.lock().unwrap();
    assert!(renew_in(&directory,200,&mut session).unwrap_err().is("OIDC_SESSION_BUSY")); drop(lease);
    let unrelated = root.0.join("other.json"); root.write("other.json", b"unrelated-root-fixture");
    std::os::unix::fs::symlink(&unrelated,root.0.join(IDENTITY)).unwrap();
    assert!(renew_in(&directory,200,&mut session).is_err());
    assert_eq!(std::fs::read(&unrelated).unwrap(),b"unrelated-root-fixture");
    std::fs::remove_file(root.0.join(IDENTITY)).unwrap();
    std::fs::hard_link(&unrelated,root.0.join(IDENTITY)).unwrap();
    assert!(renew_in(&directory,200,&mut session).is_err());
    std::fs::remove_file(root.0.join(IDENTITY)).unwrap();
    let linked = root.0.with_extension("link"); std::os::unix::fs::symlink(&root.0,&linked).unwrap();
    assert!(Directory::open(&linked).is_err()); std::fs::remove_file(linked).unwrap();
    std::fs::set_permissions(&root.0,std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(renew_in(&directory,200,&mut session).is_err());
    assert!(!root.0.join(IDENTITY).exists());
}

#[test]
fn directory_replacement_during_publication_refuses_and_preserves_replacement() {
    for cut in [2,3] {
        let root = Root::new(); let directory = root.directory(); let calls=Cell::new(0);
        let held = root.0.with_extension("held");
        let result=renew_in(&directory,200,&mut ||{
            let call=calls.get()+1;calls.set(call);
            if call==cut {
                std::fs::rename(&root.0,&held).unwrap();
                std::fs::DirBuilder::new().mode(0o755).create(&root.0).unwrap();
                root.write("replacement.fixture",b"preserve");
            }
            session()
        });
        assert!(result.is_err());assert_eq!(std::fs::read(root.0.join("replacement.fixture")).unwrap(),b"preserve");
        if cut==3 { let raw=std::fs::read(held.join(IDENTITY)).unwrap();assert!(serde_json::from_slice::<Tombstone>(&raw).unwrap().invalid); }
        else { assert!(!held.join(IDENTITY).exists()); }
        std::fs::remove_dir_all(held).unwrap();
    }
}

#[test]
fn closed_canonical_oauth_rejects_ambiguous_or_ambient_authority() {
    let valid=canonical(&serde_json::json!({"v":1,"issuer":"https://idp.example", "audience":"mcpmac", "client_id":"client",
        "authorization_endpoint":"https://idp.example/auth", "token_endpoint":"https://idp.example/token",
        "redirect_uri":"com.enterprise.enclave.oidc://callback", "callback_scheme":"com.enterprise.enclave.oidc", "expires_unix":300})).unwrap();
    assert!(OAuth::parse(&valid,100).is_ok());
    let mut newline=valid.clone();newline.push(b'\n');assert!(OAuth::parse(&newline,100).is_err());
    for endpoint in ["http://idp.example","https://user@idp.example","https://idp.example?q=1","https://idp.example:444/token","https://idp.example\\other/token"] {
        let mut value:serde_json::Value=serde_json::from_slice(&valid).unwrap();value["token_endpoint"]=endpoint.into();assert!(OAuth::parse(&canonical(&value).unwrap(),100).is_err());
    }
    assert!(OAuth::parse(br#"{"v":1,"v":1}"#,100).is_err());
    assert!(Identity::expiry_floor(br#"{"v":1,"expires_unix":200,"invalid":false}"#).is_err());
    assert!(Identity::expiry_floor(br#"{"expires_unix":200,"invalid":true,"v":1,"reset":true}"#).is_err());
    assert!(Identity::expiry_floor(br#"{"expires_unix":200,"invalid":true,"v":1}\n"#).is_err());
    let mut value:serde_json::Value=serde_json::from_slice(&valid).unwrap();value["client_secret"]="forbidden".into();assert!(OAuth::parse(&canonical(&value).unwrap(),100).is_err());
}

#[test]
fn uncertain_renewal_tombstone_keeps_high_water_floor_and_never_revives_old_digest() {
    let root=Root::new();let directory=root.directory();
    let old=renew_in(&directory,200,&mut session).unwrap();let calls=Cell::new(0);
    assert!(renew_in(&directory,201,&mut || {let call=calls.get()+1;calls.set(call);Ok((501,if call==3 {778}else{777},100))}).is_err());
    let raw=std::fs::read(root.0.join(IDENTITY)).unwrap();
    assert!(serde_json::from_slice::<Tombstone>(&raw).unwrap().invalid);
    assert_eq!(Identity::expiry_floor(&raw).unwrap(),201);
    for expires in [200,201] {assert!(renew_in(&directory,expires,&mut session).unwrap_err().is("OIDC_SESSION_EXPIRY_FLOOR"));}
    std::fs::remove_file(root.0.join(IDENTITY)).unwrap();
    assert_eq!(root.floor(), 201, "deleting the refusal tombstone cannot reset the separate marker");
    for expires in [200,201] {assert!(renew_in(&directory,expires,&mut session).unwrap_err().is("OIDC_SESSION_EXPIRY_FLOOR"));}
    let fresh=renew_in(&directory,202,&mut session).unwrap();assert_ne!(old.identity_sha256,fresh.identity_sha256);
}

#[test]
fn deleting_public_identity_never_reissues_a_still_live_digest() {
    let root = Root::new(); let directory = root.directory();
    assert!(!root.0.join(IDENTITY).exists() && !root.0.join(HIGH_WATER).exists());
    let first = renew_in(&directory, 200, &mut session).unwrap();
    assert_eq!(root.floor(), 200);
    assert_eq!(std::fs::metadata(root.0.join(HIGH_WATER)).unwrap().mode() & 0o777, 0o600);
    std::fs::remove_file(root.0.join(IDENTITY)).unwrap();
    assert!(renew_in(&directory, 200, &mut session).unwrap_err().is("OIDC_SESSION_EXPIRY_FLOOR"));
    let second = renew_in(&directory, 201, &mut session).unwrap();
    assert_ne!(first.identity_sha256, second.identity_sha256);
    std::fs::remove_file(root.0.join(IDENTITY)).unwrap();
    for expiry in [200, 201] {
        assert!(renew_in(&directory, expiry, &mut session).unwrap_err().is("OIDC_SESSION_EXPIRY_FLOOR"));
        assert!(!root.0.join(IDENTITY).exists());
    }
    let third = renew_in(&directory, 202, &mut session).unwrap();
    assert_eq!(root.floor(), 202);
    assert_ne!(third.identity_sha256, first.identity_sha256);
    assert_ne!(third.identity_sha256, second.identity_sha256);
}

#[test]
fn failure_after_marker_burn_before_identity_publish_retains_strict_floor() {
    let root = Root::new(); let directory = root.directory();
    renew_in(&directory, 200, &mut session).unwrap();
    let old_identity = std::fs::read(root.0.join(IDENTITY)).unwrap();
    let calls = Cell::new(0);
    assert!(renew_in(&directory, 201, &mut || {
        let call = calls.get() + 1; calls.set(call);
        if call == 2 {
            assert_eq!(root.floor(), 201, "marker is persisted before public identity rename");
            assert_eq!(std::fs::read(root.0.join(IDENTITY)).unwrap(), old_identity);
            return Err(err!(EIO, "TEST_AFTER_MARKER_BEFORE_IDENTITY"));
        }
        session()
    }).unwrap_err().is("TEST_AFTER_MARKER_BEFORE_IDENTITY"));
    assert_eq!(root.floor(), 201);
    assert_eq!(std::fs::read(root.0.join(IDENTITY)).unwrap(), old_identity);
    std::fs::remove_file(root.0.join(IDENTITY)).unwrap();
    for expiry in [200, 201] { assert!(renew_in(&directory, expiry, &mut session).unwrap_err().is("OIDC_SESSION_EXPIRY_FLOOR")); }
    renew_in(&directory, 202, &mut session).unwrap();
}

#[test]
fn legacy_identity_migration_retains_observed_floor_even_on_refused_renewal() {
    let root = Root::new(); let directory = root.directory();
    root.write(IDENTITY, &canonical(&Identity { v: 1, socket: "/var/run/enclave/oidc/501/broker.sock".into(),
        identifier: crate::launchd::OIDC_LABEL.into(), console_uid: 501, audit_session_id: 777, expires_unix: 200 }).unwrap());
    assert!(!root.0.join(HIGH_WATER).exists());
    assert!(renew_in(&directory, 200, &mut session).unwrap_err().is("OIDC_SESSION_EXPIRY_FLOOR"));
    assert_eq!(root.floor(), 200, "a refused migration must retain the validated old record floor");
    std::fs::remove_file(root.0.join(IDENTITY)).unwrap();
    assert!(renew_in(&directory, 200, &mut session).unwrap_err().is("OIDC_SESSION_EXPIRY_FLOOR"));
    renew_in(&directory, 201, &mut session).unwrap();
    // If a legacy marker lags a surviving higher identity, use their maximum.
    root.write_marker(&canonical(&HighWater { v: 1, max_expires_unix: 199 }).unwrap());
    assert!(renew_in(&directory, 201, &mut session).unwrap_err().is("OIDC_SESSION_EXPIRY_FLOOR"));
    assert_eq!(root.floor(), 201);
    std::fs::remove_file(root.0.join(IDENTITY)).unwrap();
    assert!(renew_in(&directory, 201, &mut session).unwrap_err().is("OIDC_SESSION_EXPIRY_FLOOR"));
    renew_in(&directory, 202, &mut session).unwrap();
}

#[test]
fn malformed_or_unprotected_highwater_never_becomes_fresh_state() {
    let root = Root::new(); let directory = root.directory();
    for raw in [br#"{"max_expires_unix":200,"v":1,"v":1}"#.as_slice(),
        br#"{"max_expires_unix":200,"reset":true,"v":1}"#,
        br#"{"max_expires_unix":-1,"v":1}"#, br#"{"max_expires_unix":200,"v":2}"#,
        b"{\"max_expires_unix\":200,\"v\":1}\n"] {
        root.write_marker(raw);
        assert!(renew_in(&directory, 201, &mut session).unwrap_err().is("OIDC_SESSION_HIGHWATER_INVALID"));
        assert_eq!(std::fs::read(root.0.join(HIGH_WATER)).unwrap(), raw);
        assert!(!root.0.join(IDENTITY).exists());
    }
    root.write(HIGH_WATER, &canonical(&HighWater { v: 1, max_expires_unix: 200 }).unwrap());
    assert!(renew_in(&directory, 201, &mut session).unwrap_err().is("OIDC_SESSION_PROTECTION"));
    std::fs::remove_file(root.0.join(HIGH_WATER)).unwrap();
    root.write("unrelated.fixture", b"preserve");
    std::os::unix::fs::symlink(root.0.join("unrelated.fixture"), root.0.join(HIGH_WATER)).unwrap();
    assert!(renew_in(&directory, 201, &mut session).is_err());
    assert_eq!(std::fs::read(root.0.join("unrelated.fixture")).unwrap(), b"preserve");
    std::fs::remove_file(root.0.join(HIGH_WATER)).unwrap();
    std::fs::hard_link(root.0.join("unrelated.fixture"), root.0.join(HIGH_WATER)).unwrap();
    assert!(renew_in(&directory, 201, &mut session).unwrap_err().is("OIDC_SESSION_PROTECTION"));
    assert!(!root.0.join(IDENTITY).exists());
}


struct SelectedRoot {
    root: Root,
    checked: enclave_core::deployment::CheckedDeploymentTarget,
    directory: Directory,
    pin_directory: Directory,
    pin_leaf: String,
}
impl SelectedRoot {
    fn new(role: enclave_core::deployment::DeploymentRole) -> Self {
        Self::with_pins(role, "selected-custom-pins.json", false)
    }
    fn with_pins(role: enclave_core::deployment::DeploymentRole, leaf: &str, in_support: bool) -> Self {
        use enclave_core::{deployment::{self, DeploymentLayout, DeploymentSigningMode, DeploymentTarget}, profile::Profile};
        let root = Root::new();
        let support = root.0.join("support");
        let pin_parent = if in_support { support.clone() } else { root.0.join("independent-pin-input") };
        std::fs::DirBuilder::new().mode(0o755).create(&support).unwrap();
        if pin_parent != support { std::fs::DirBuilder::new().mode(0o755).create(&pin_parent).unwrap(); }
        let pin_leaf = leaf.to_owned();
        let target = DeploymentTarget { version: 1, target_id: "oidc-selected".into(), role,
            profile: Profile::L2, authority_config: support.join("authority.json"),
            expected_artifacts_manifest: support.join("artifacts.json"), codesign_pins_file: pin_parent.join(&pin_leaf),
            signing_identity_mode: match codesign::signing_mode() {
                codesign::SigningMode::LocalPins => DeploymentSigningMode::LocalPins,
                codesign::SigningMode::TeamId => DeploymentSigningMode::TeamId,
            },
            layout: DeploymentLayout { binary_dir: root.0.join("bin"), custody_bundle: support.join("Custody.app"),
                sandbox_dir: root.0.join("sandbox"), socket_root: root.0.join("run"), state_root: root.0.join("state"),
                audit_root: root.0.join("audit"), cas_store_root: root.0.join("cas"), staging_root: root.0.join("stage"),
                support_root: support.clone(), launchd_namespace: "com.mcpmac.oidc-selected".into(),
                mach_service: "com.mcpmac.oidc-selected.exception".into() }, broker: None, shared_read_only_inputs: vec![] };
        target.validate().unwrap();
        let config = support.join("deployment.json");
        for (path, raw) in [(&config, serde_json::to_vec(&target).unwrap()),
            (&target.authority_config, b"{}".to_vec()), (&target.expected_artifacts_manifest, b"{}".to_vec()),
            (&support.join(OAUTH), std::fs::read(root.0.join(OAUTH)).unwrap()),
            (&target.codesign_pins_file, std::fs::read(root.0.join(PINS)).unwrap())] {
            std::fs::write(path, raw).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        // A valid default-named pin file in support is deliberately a decoy.
        std::fs::copy(root.0.join(PINS), support.join(PINS)).unwrap();
        let checked = deployment::load(&config).unwrap();
        let directory = Directory::open(&support).unwrap();
        let pin_directory = Directory::open(&pin_parent).unwrap();
        Self { root, checked, directory, pin_directory, pin_leaf }
    }
    fn scope(&self) -> Renewal<'_> {
        Renewal { directory: &self.directory, pin_directory: &self.pin_directory, pin_leaf: &self.pin_leaf,
            socket_root: &self.checked.target().layout.socket_root, checked: Some(&self.checked) }
    }
    fn call(&self, expiry: i64, session: &mut impl FnMut() -> EnclaveResult<(u32,u32,i64)>) -> EnclaveResult<SessionReceipt> {
        renew_scoped(&self.scope(), expiry, session)
    }
    fn floor(&self) -> i64 {
        HighWater::floor(&std::fs::read(self.directory.path.join(HIGH_WATER)).unwrap()).unwrap()
    }
    fn drift_descriptor(&self) {
        let mut bytes = std::fs::read(self.checked.config_path()).unwrap(); bytes.push(b' ');
        std::fs::write(self.checked.config_path(), bytes).unwrap();
    }
}

#[test]
fn selected_dedicated_and_upgrade_keep_all_mutable_state_and_sockets_isolated() {
    use enclave_core::deployment::DeploymentRole;
    let a = SelectedRoot::new(DeploymentRole::DedicatedTest);
    let b = SelectedRoot::new(DeploymentRole::ExistingUpgrade);
    let decoys = [a.root.0.join(OAUTH), a.root.0.join(PINS), a.directory.path.join(PINS)];
    let before: Vec<_> = decoys.iter().map(|p| std::fs::read(p).unwrap()).collect();
    let first = a.call(200, &mut session).unwrap();
    assert_eq!(first.identity_path, a.directory.path.join(IDENTITY).to_str().unwrap());
    let identity: Identity = serde_json::from_slice(&std::fs::read(&first.identity_path).unwrap()).unwrap();
    assert_eq!(identity.socket, socket_path(&a.checked.target().layout.socket_root, 501));
    assert_eq!(identity.identifier, crate::launchd::OIDC_LABEL);
    assert_eq!((identity.console_uid, identity.audit_session_id), (501,777));
    assert_eq!(a.floor(), 200);
    for leaf in [IDENTITY, HIGH_WATER, LOCK] {
        assert!(a.directory.path.join(leaf).exists());
        assert!(!a.root.0.join(leaf).exists());
        assert!(!b.directory.path.join(leaf).exists());
    }
    let second = b.call(200, &mut session).unwrap();
    assert_ne!(first.identity_sha256, second.identity_sha256);
    assert_eq!(b.floor(), 200);
    assert!(a.call(200, &mut || Ok((502,888,101))).unwrap_err().is("OIDC_SESSION_EXPIRY_FLOOR"));
    a.call(201, &mut || Ok((502,888,101))).unwrap();
    assert!(a.call(200, &mut session).unwrap_err().is("OIDC_SESSION_EXPIRY_FLOOR"));
    assert_eq!(b.floor(), 200);
    for (path, raw) in decoys.iter().zip(before) { assert_eq!(std::fs::read(path).unwrap(), raw); }
}

#[test]
fn selected_missing_foreign_unsafe_or_drifting_pins_never_fall_back_to_default() {
    use enclave_core::deployment::DeploymentRole;
    for case in ["missing", "foreign-schema", "symlink", "hardlink", "parent-mode"] {
        let f = SelectedRoot::new(DeploymentRole::DedicatedTest);
        let pins = &f.checked.target().codesign_pins_file;
        match case {
            "missing" => std::fs::remove_file(pins).unwrap(),
            "foreign-schema" => std::fs::write(pins, br#"{"v":1,"pins":{"other.target":["1111111111111111111111111111111111111111"]}}"#).unwrap(),
            "symlink" => { std::fs::remove_file(pins).unwrap(); std::os::unix::fs::symlink(f.directory.path.join(PINS), pins).unwrap(); },
            "hardlink" => { std::fs::remove_file(pins).unwrap(); std::fs::hard_link(f.directory.path.join(PINS), pins).unwrap(); },
            "parent-mode" => std::fs::set_permissions(&f.pin_directory.path, std::fs::Permissions::from_mode(0o777)).unwrap(),
            _ => unreachable!(),
        }
        assert!(f.call(200, &mut session).is_err(), "{case}");
        assert!(!f.directory.path.join(IDENTITY).exists(), "{case}");
        assert!(!f.directory.path.join(HIGH_WATER).exists(), "{case}");
    }
    for cut in [2,3] {
        let f = SelectedRoot::new(DeploymentRole::ExistingUpgrade); let calls = Cell::new(0);
        assert!(f.call(200, &mut || {
            let n = calls.get()+1; calls.set(n);
            if n==cut { std::fs::write(&f.checked.target().codesign_pins_file,
                std::fs::read(f.directory.path.join(PINS)).unwrap().into_iter().chain([b' ']).collect::<Vec<_>>()).unwrap(); }
            session()
        }).is_err());
        assert_eq!(f.floor(), 200);
        if cut==3 { assert!(serde_json::from_slice::<Tombstone>(&std::fs::read(f.directory.path.join(IDENTITY)).unwrap()).unwrap().invalid); }
        else { assert!(!f.directory.path.join(IDENTITY).exists()); }
    }
}

#[test]
fn selected_mixed_support_pins_socket_or_checked_context_refuses_before_lock() {
    use enclave_core::deployment::DeploymentRole;
    let a = SelectedRoot::new(DeploymentRole::DedicatedTest);
    let b = SelectedRoot::new(DeploymentRole::ExistingUpgrade);
    for slot in 0..5 {
        let mut scope = a.scope();
        match slot { 0=>scope.directory=&b.directory, 1=>scope.pin_directory=&b.pin_directory,
            2=>scope.pin_leaf=PINS, 3=>scope.socket_root=&b.checked.target().layout.socket_root,
            _=>scope.checked=Some(&b.checked) }
        assert!(renew_scoped(&scope,200,&mut session).unwrap_err().is("DEPLOYMENT_OIDC_CONTEXT_MISMATCH"));
        assert!(!a.directory.path.join(LOCK).exists()); assert!(!b.directory.path.join(LOCK).exists());
    }
}

#[test]
fn selected_descriptor_drift_before_and_through_publication_never_returns_receipt() {
    use enclave_core::deployment::DeploymentRole;
    let initial = SelectedRoot::new(DeploymentRole::DedicatedTest); initial.drift_descriptor();
    assert!(initial.call(200,&mut session).unwrap_err().is("DEPLOYMENT_CHANGED"));
    assert!(!initial.directory.path.join(LOCK).exists());
    for cut in [1,2,3] {
        let f = SelectedRoot::new(DeploymentRole::ExistingUpgrade); let calls = Cell::new(0);
        let original = std::fs::read(f.checked.config_path()).unwrap();
        assert!(f.call(200,&mut || {let n=calls.get()+1;calls.set(n);if n==cut {f.drift_descriptor();} session()})
            .unwrap_err().is("DEPLOYMENT_CHANGED"));
        if cut==1 { assert!(!f.directory.path.join(HIGH_WATER).exists()); }
        else { assert_eq!(f.floor(),200); }
        if cut==3 { assert!(serde_json::from_slice::<Tombstone>(&std::fs::read(f.directory.path.join(IDENTITY)).unwrap()).unwrap().invalid); }
        else { assert!(!f.directory.path.join(IDENTITY).exists()); }
        std::fs::write(f.checked.config_path(), original).unwrap();
        if cut>1 { assert!(f.call(200,&mut session).unwrap_err().is("OIDC_SESSION_EXPIRY_FLOOR")); }
        f.call(201,&mut session).unwrap();
    }
}

#[test]
fn selected_floors_migration_cancellation_tombstones_and_session_changes_stay_monotonic() {
    use enclave_core::deployment::DeploymentRole;
    let f = SelectedRoot::new(DeploymentRole::ExistingUpgrade);
    let old = canonical(&Identity { v:1, socket:socket_path(&f.checked.target().layout.socket_root,501),
        identifier:crate::launchd::OIDC_LABEL.into(), console_uid:501, audit_session_id:777, expires_unix:200 }).unwrap();
    std::fs::write(f.directory.path.join(IDENTITY),&old).unwrap();
    assert!(f.call(200,&mut session).unwrap_err().is("OIDC_SESSION_EXPIRY_FLOOR")); assert_eq!(f.floor(),200);
    std::fs::remove_file(f.directory.path.join(IDENTITY)).unwrap();
    let calls=Cell::new(0);
    assert!(f.call(201,&mut || {let n=calls.get()+1;calls.set(n);if n==2 {return Err(err!(EAGAIN,"TEST_SELECTED_CANCELLED"));} session()})
        .unwrap_err().is("TEST_SELECTED_CANCELLED"));
    assert_eq!(f.floor(),201);assert!(!f.directory.path.join(IDENTITY).exists());
    let calls=Cell::new(0);
    assert!(f.call(202,&mut || {let n=calls.get()+1;calls.set(n);Ok((501,if n==3 {778} else {777},100))}).is_err());
    let tombstone=std::fs::read(f.directory.path.join(IDENTITY)).unwrap();
    assert_eq!(Identity::expiry_floor_at(&tombstone,&f.checked.target().layout.socket_root).unwrap(),202);
    std::fs::remove_file(f.directory.path.join(IDENTITY)).unwrap();
    for expiry in [200,201,202] {assert!(f.call(expiry,&mut session).unwrap_err().is("OIDC_SESSION_EXPIRY_FLOOR"));}
    f.call(203,&mut || Ok((502,888,101))).unwrap();
    assert!(f.call(202,&mut session).unwrap_err().is("OIDC_SESSION_EXPIRY_FLOOR"));
    // An identity for the other socket namespace is never accepted as legacy.
    std::fs::write(f.directory.path.join(IDENTITY),canonical(&Identity {v:1,socket:"/var/run/enclave/oidc/501/broker.sock".into(),
        identifier:crate::launchd::OIDC_LABEL.into(),console_uid:501,audit_session_id:777,expires_unix:250}).unwrap()).unwrap();
    assert!(f.call(251,&mut session).unwrap_err().is("OIDC_SESSION_PREVIOUS_INVALID"));assert_eq!(f.floor(),203);
}

#[test]
fn selected_external_marker_named_public_pins_are_valid_without_weakening_marker_mode() {
    use enclave_core::deployment::DeploymentRole;
    let f = SelectedRoot::with_pins(DeploymentRole::DedicatedTest,HIGH_WATER,false);
    assert_eq!(std::fs::metadata(&f.checked.target().codesign_pins_file).unwrap().mode() & 0o777,0o644);
    f.call(200,&mut session).unwrap();
    assert_eq!(f.floor(),200);
    assert_eq!(std::fs::metadata(f.directory.path.join(HIGH_WATER)).unwrap().mode() & 0o777,0o600);
    std::fs::set_permissions(f.directory.path.join(HIGH_WATER),std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(f.call(201,&mut session).unwrap_err().is("OIDC_SESSION_PROTECTION"));
}

#[test]
fn selected_reserved_public_pin_destinations_refuse_before_lock_or_writes() {
    use enclave_core::deployment::DeploymentRole;
    for leaf in [IDENTITY,OAUTH,HIGH_WATER,LOCK] {
      for spelling in [leaf.to_owned(),leaf.to_ascii_uppercase()] {
        let f=SelectedRoot::with_pins(DeploymentRole::ExistingUpgrade,&spelling,true);
        let before=std::fs::read(&f.checked.target().codesign_pins_file).unwrap();
        assert!(f.call(200,&mut session).unwrap_err().is("DEPLOYMENT_OIDC_RESERVED_INPUT_PATH"),"{leaf}");
        assert_eq!(std::fs::read(&f.checked.target().codesign_pins_file).unwrap(),before);
        for other in [IDENTITY,HIGH_WATER,LOCK] {if !other.eq_ignore_ascii_case(&spelling) {assert!(!f.directory.path.join(other).exists(),"{spelling}/{other}");}}
      }
    }
}

#[test]
fn selected_declared_readonly_inputs_cannot_alias_mutable_renewal_destinations() {
    use enclave_core::deployment::{self,DeploymentRole};
    for input in ["authority","inventory","descriptor","broker-root"] {
        for leaf in [IDENTITY,HIGH_WATER,LOCK] {
          for spelling in [leaf.to_owned(),leaf.to_ascii_uppercase()] {
            let mut f=SelectedRoot::new(DeploymentRole::ExistingUpgrade);
            let mut target=f.checked.target().clone();
            let destination=f.directory.path.join(&spelling);
            let marker=canonical(&HighWater {v:1,max_expires_unix:150}).unwrap();
            std::fs::write(&destination,&marker).unwrap();
            std::fs::set_permissions(&destination,std::fs::Permissions::from_mode(0o600)).unwrap();
            let mut config=f.checked.config_path().to_owned();
            match input {
                "authority"=>target.authority_config=destination.clone(),
                "inventory"=>target.expected_artifacts_manifest=destination.clone(),
                "descriptor"=>config=destination.clone(),
                "broker-root"=>{
                    target.profile=enclave_core::Profile::L3;
                    target.broker=Some(deployment::DeploymentBroker {base_dir:target.layout.state_root.join("apfs-broker"),tuf_root_file:destination.clone()});
                },
                _=>unreachable!(),
            }
            std::fs::write(&config,serde_json::to_vec(&target).unwrap()).unwrap();
            // Descriptor protection accepts an arbitrary filename. Other
            // authority references retain marker bytes to reproduce the prior
            // accidental overwrite without inventing semantic authority.
            f.checked=deployment::load(&config).unwrap();
            let before=std::fs::read(&destination).unwrap();
            assert!(f.call(200,&mut session).unwrap_err().is("DEPLOYMENT_OIDC_RESERVED_INPUT_PATH"),"{input}/{leaf}");
            assert_eq!(std::fs::read(&destination).unwrap(),before,"{input}/{leaf}");
            for other in [IDENTITY,HIGH_WATER,LOCK] {if !other.eq_ignore_ascii_case(&spelling) {assert!(!f.directory.path.join(other).exists(),"{input}/{spelling}/{other}");}}
          }
        }
    }
}

#[test]
fn selected_descriptor_rebind_at_marker_boundaries_never_rolls_back_published_floor() {
    use enclave_core::deployment::DeploymentRole;
    for cut in [1,2,3] {
        let f=SelectedRoot::new(DeploymentRole::DedicatedTest);let calls=Cell::new(0);
        let result=f.directory.burn_highwater(200,None,&|| {
            let n=calls.get()+1;calls.set(n);if n==cut {f.drift_descriptor();}f.scope().rebind()
        });
        assert!(result.unwrap_err().is("DEPLOYMENT_CHANGED"));
        assert_eq!(calls.get(),cut);
        if cut==3 {assert_eq!(f.floor(),200);}else {assert!(!f.directory.path.join(HIGH_WATER).exists());}
        assert!(!f.directory.path.join(IDENTITY).exists());
        assert!(!std::fs::read_dir(&f.directory.path).unwrap().any(|e|e.unwrap().file_name().to_string_lossy().ends_with(".tmp")));
    }
}

#[test]
fn selected_pin_parent_replacement_preserves_replacement_and_never_returns_receipt() {
    use enclave_core::deployment::DeploymentRole;
    for cut in [2,3] {
        let f=SelectedRoot::new(DeploymentRole::DedicatedTest);let calls=Cell::new(0);
        let held=f.pin_directory.path.with_extension("held");
        assert!(f.call(200,&mut || {
            let n=calls.get()+1;calls.set(n);
            if n==cut {
                std::fs::rename(&f.pin_directory.path,&held).unwrap();
                std::fs::DirBuilder::new().mode(0o755).create(&f.pin_directory.path).unwrap();
                std::fs::write(f.pin_directory.path.join(&f.pin_leaf),std::fs::read(f.directory.path.join(PINS)).unwrap()).unwrap();
                std::fs::write(f.pin_directory.path.join("replacement.fixture"),b"preserve").unwrap();
            }
            session()
        }).is_err());
        assert_eq!(f.floor(),200);
        assert_eq!(std::fs::read(f.pin_directory.path.join("replacement.fixture")).unwrap(),b"preserve");
        if cut==3 {assert!(serde_json::from_slice::<Tombstone>(&std::fs::read(f.directory.path.join(IDENTITY)).unwrap()).unwrap().invalid);}
        else {assert!(!f.directory.path.join(IDENTITY).exists());}
    }
}
