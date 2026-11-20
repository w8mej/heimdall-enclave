//! Synthetic public bytes and an explicitly fake authority provider only.
//! Ignored filesystem tests require the coordinator's actual private /state
//! root fixture; they never infer native signature or installed acceptance.
use super::*;
use enclave_core::{
    deployment::{
        load, DeploymentBroker, DeploymentLayout, DeploymentSigningMode, DeploymentTarget,
    },
    Profile,
};
use serde_json::json;
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
fn mkdir_public(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}
fn write_public(path: impl AsRef<Path>, bytes: impl AsRef<[u8]>) -> std::io::Result<()> {
    fs::write(&path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o644))
}
struct Fixture {
    base: PathBuf,
    target: DeploymentTarget,
    config: PathBuf,
    inventory: Vec<u8>,
    old_pins: Vec<u8>,
}
impl Fixture {
    fn new() -> Self {
        let parent = PathBuf::from(
            std::env::var_os("ENCLAVE_TEST_STATE_ROOT").expect("explicit private root fixture"),
        );
        assert_eq!(
            parent,
            Path::new("/state"),
            "do not run synthetic payload application on a host layout"
        );
        let metadata = fs::symlink_metadata(&parent).unwrap();
        assert_eq!(metadata.uid(), 0);
        assert_eq!(metadata.mode() & 0o022, 0);
        assert!(metadata.is_dir());
        let id = format!(
            "payload-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        );
        let base = parent.join(&id);
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let support = base.join("support");
        let stage = base.join("stage");
        mkdir_public(&support);
        mkdir_public(&stage);
        let target = DeploymentTarget {
            version: 1,
            target_id: id.clone(),
            role: DeploymentRole::DedicatedTest,
            profile: Profile::L2,
            authority_config: support.join("authority.json"),
            expected_artifacts_manifest: support.join("inventory.json"),
            codesign_pins_file: support.join("installed-pins.json"),
            signing_identity_mode: match enclave_core::codesign::signing_mode() {
                enclave_core::codesign::SigningMode::LocalPins => DeploymentSigningMode::LocalPins,
                enclave_core::codesign::SigningMode::TeamId => DeploymentSigningMode::TeamId,
            },
            layout: DeploymentLayout {
                binary_dir: base.join("bin"),
                custody_bundle: support.join("Custody.app"),
                sandbox_dir: base.join("sandbox"),
                socket_root: base.join("run"),
                state_root: base.join("state"),
                audit_root: base.join("audit"),
                cas_store_root: base.join("cas-store"),
                staging_root: stage,
                support_root: support,
                launchd_namespace: format!("com.mcpmac.{id}"),
                mach_service: format!("com.mcpmac.{id}.exception"),
            },
            broker: None,
            shared_read_only_inputs: vec![],
        };
        let config = base.join("target.json");
        let old_pins=br#"{"v":1,"pins":{"com.enterprise.enclave.ctl":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}}"#.to_vec();
        write_public(&target.authority_config, b"{}").unwrap();
        write_public(&target.codesign_pins_file, &old_pins).unwrap();
        let mut f = Self {
            base,
            target,
            config,
            inventory: Vec::new(),
            old_pins,
        };
        f.populate();
        f
    }
    fn l3() -> Self {
        let mut f = Self::new();
        f.target.profile = Profile::L3;
        f.target.broker = Some(DeploymentBroker {
            base_dir: f.target.layout.state_root.join("apfs-broker"),
            tuf_root_file: f.target.layout.support_root.join("tuf-root.json"),
        });
        write_public(
            &f.target.broker.as_ref().unwrap().tuf_root_file,
            b"SYNTHETIC L3 PUBLIC TRUST REFERENCE ONLY\n",
        )
        .unwrap();
        f.populate();
        f
    }
    fn paths(&self) -> Vec<String> {
        let mut paths = vec!["codesign-pins.json".into()];
        for binary in [
            "mcp-enclave",
            "enclave-model-runnerd",
            "enclave-swarm-syncd",
            "enclave-apfs-broker",
            "enclave-agent-runtime",
            "enclave-zk-auditor",
            "enclave-cdp-browser",
            "enclave-client-gateway",
            "enclave-intent",
        ] {
            paths.push(format!("bin/{binary}"));
        }
        for (bundle, binary) in [
            ("EnclaveCustody.app", "enclave-custody-vaultd"),
            ("EnclaveOIDC.app", "enclave-oidc"),
        ] {
            for member in [
                "Contents/Info.plist".to_owned(),
                "Contents/_CodeSignature/CodeResources".into(),
                format!("Contents/MacOS/{binary}"),
            ] {
                paths.push(format!("{bundle}/{member}"));
            }
        }
        for name in [
            "adapter", "cas", "custody", "ifc", "zk", "browser", "gateway",
        ] {
            paths.push(format!("launchd/{name}.sb"));
        }
        for job in [
            "adapter",
            "cas",
            "custody",
            "ifc",
            "zk",
            "supervisor",
            "intent",
            "oidc-broker",
            "hydrate",
            "browser",
            "gateway",
        ] {
            paths.push(format!(
                "launchd/{}.{job}.plist",
                self.target.layout.launchd_namespace
            ));
        }
        if self.target.profile == Profile::L3 {
            paths.push(format!(
                "launchd/{}.apfs-broker.plist",
                self.target.layout.launchd_namespace
            ));
        }
        for member in [
            "SHA256SUMS",
            "custody.entitlements",
            "yubikey-transport",
            "install.sh",
            "uninstall.sh",
            "public-trust.sh",
            "fido-mds/yubico.json",
            "launchd/provision-accounts.sh",
            "launchd/enclave-daemon.entitlements",
        ] {
            paths.push(member.into());
        }
        for member in [
            "root.json",
            "timestamp.json",
            "snapshot.json",
            "targets.json",
            "enclave-host-config.json",
            "enclave-policy.cedar.v1.json",
            "vk_manifest.json",
            "enclave-distribution-v1.json",
        ] {
            paths.push(format!("tuf/repo/{member}"));
        }
        paths.sort();
        paths
    }
    fn populate(&mut self) {
        for relative in self.paths() {
            let path = self.target.layout.staging_root.join(&relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            for directory in path
                .parent()
                .unwrap()
                .ancestors()
                .take_while(|p| p.starts_with(&self.base) && *p != self.base.as_path())
            {
                fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
            }
            let bytes = if relative == "codesign-pins.json" {
                br#"{"v":1,"pins":{"com.enterprise.enclave.ctl":["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]}}"#.to_vec()
            } else {
                format!("SYNTHETIC PUBLIC FIXTURE ONLY: {relative}\n").into_bytes()
            };
            write_public(path, bytes).unwrap();
        }
        self.write_context();
    }
    fn write_context(&mut self) {
        let raw = serde_json::to_vec(&self.target).unwrap();
        write_public(&self.config, &raw).unwrap();
        let files = self
            .paths()
            .into_iter()
            .map(|p| {
                let bytes = fs::read(self.target.layout.staging_root.join(&p)).unwrap();
                json!({"path":p,"sha256":hex::encode(Sha256::digest(&bytes)),"size":bytes.len()})
            })
            .collect::<Vec<_>>();
        let pins = fs::read(self.target.layout.staging_root.join("codesign-pins.json")).unwrap();
        self.inventory=serde_json::to_vec(&json!({"version":1,"kind":"mcpmac-first-touch-artifact-inventory",
            "target_id":self.target.target_id,"profile":self.target.profile,"signing_identity_mode":self.target.signing_identity_mode,
            "deployment_config_sha256":hex::encode(Sha256::digest(&raw)),"source_git_commit":"a".repeat(40),
            "source_manifest_sha256":"b".repeat(64),"source_input_count":1,"codesign_pins_sha256":hex::encode(Sha256::digest(pins)),
            "staging_root":normalized_path(&self.target.layout.staging_root).unwrap(),"external_provenance":"UNKNOWN","files":files})).unwrap();
        write_public(&self.target.expected_artifacts_manifest, &self.inventory).unwrap();
    }
    fn checked(&self) -> CheckedDeploymentTarget {
        load(&self.config).unwrap()
    }
    fn cli_source(&self) -> PathBuf {
        self.target.layout.staging_root.join("bin/mcp-enclave")
    }
    fn cli_destination(&self) -> PathBuf {
        self.target.layout.binary_dir.join("mcp-enclave")
    }
    fn preserved(&self) {
        assert_eq!(
            fs::read(&self.target.codesign_pins_file).unwrap(),
            self.old_pins
        );
        for root in [
            &self.target.layout.socket_root,
            &self.target.layout.state_root,
            &self.target.layout.audit_root,
            &self.target.layout.cas_store_root,
        ] {
            assert!(
                !root.exists(),
                "public payload does not create runtime/state stores"
            );
        }
        if let Some(b) = &self.target.broker {
            assert!(
                !b.base_dir.exists(),
                "public payload never creates or activates the broker"
            );
            assert!(!Path::new("/Library/LaunchDaemons")
                .join(format!(
                    "{}.apfs-broker.plist",
                    self.target.layout.launchd_namespace
                ))
                .exists());
        }
        for job in [
            "adapter",
            "cas",
            "custody",
            "ifc",
            "zk",
            "supervisor",
            "intent",
            "oidc-broker",
            "hydrate",
            "browser",
            "gateway",
        ] {
            let directory = if ["intent", "oidc-broker"].contains(&job) {
                "/Library/LaunchAgents"
            } else {
                "/Library/LaunchDaemons"
            };
            assert!(!Path::new(directory)
                .join(format!(
                    "{}.{job}.plist",
                    self.target.layout.launchd_namespace
                ))
                .exists());
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

/// This test-only adapter exercises the private filesystem engine. It cannot
/// construct native guard/account capabilities or enter the production API.
fn fixture_payload(
    checked: &CheckedDeploymentTarget,
    authority: &mut dyn SyntheticPayloadAuthority,
) -> Result<PublicPayloadReceipt, PublicPayloadFailure> {
    run_payload(checked, authority, &mut |_| Ok(()))
}

/// This provider is synthetic test infrastructure, not production authority.
#[derive(Default)]
struct FixtureAuthority {
    deny_release: bool,
    deny_inactive: bool,
    calls: usize,
    mutate: Option<Box<dyn FnMut()>>,
}
impl SyntheticPayloadAuthority for FixtureAuthority {
    fn verify_release_and_native_code(
        &mut self,
        _: &CheckedDeploymentTarget,
        plan: &TargetInstallPlan,
        files: &[HeldPublicFile],
    ) -> EnclaveResult<()> {
        self.calls += 1;
        assert!(files.len() >= plan.copies.len());
        for file in files {
            assert!(file.path().is_absolute());
            assert_eq!(file.file().metadata().unwrap().len(), file.size());
            assert_eq!(file.sha256().len(), 64);
        }
        if self.deny_release {
            fail!(EACCES, "TEST_RELEASE_NOT_APPROVED");
        }
        if let Some(action) = &mut self.mutate {
            action();
        }
        Ok(())
    }
    fn verify_target_inactive(&mut self, _: &CheckedDeploymentTarget) -> EnclaveResult<()> {
        self.calls += 1;
        if self.deny_inactive {
            fail!(EACCES, "TEST_TARGET_ACTIVE");
        }
        Ok(())
    }
}

#[test]
fn publication_subset_never_includes_pins_or_launchd_jobs() {
    let pins = Path::new("/protected/pins.json");
    for (path, allowed) in [
        ("/protected/pins.json", false),
        ("/Library/LaunchDaemons/com.test.plist", false),
        ("/Library/LaunchAgents/com.test.plist", false),
        ("/dedicated/bin/mcp-enclave", true),
    ] {
        let entry = target_plan::CopyEntry {
            source: "/stage/file".into(),
            destination: path.into(),
            sha256: "a".repeat(64),
            size: 1,
            uid: 0,
            gid: 0,
            mode: "0644".into(),
            condition: "test",
        };
        assert_eq!(payload_copy(&entry, pins), allowed);
    }
}

#[test]
#[ignore = "requires coordinator private root /state fixture"]
fn dedicated_public_payload_is_exact_create_only_and_leaves_authority_state_jobs_untouched() {
    let f = Fixture::new();
    let checked = f.checked();
    let plan = target_plan::prepare(&checked).unwrap();
    let result = fixture_payload(&checked, &mut FixtureAuthority::default()).unwrap();
    assert!(!result.installation_supported && !result.qualified);
    assert_eq!(result.target_id, f.target.target_id);
    assert_eq!(result.descriptor_sha256, checked.descriptor_sha256());
    assert_eq!(
        result.artifact_inventory_sha256,
        plan.artifact_inventory_sha256
    );
    assert_eq!(
        result.selected_pins_sha256_unchanged,
        hex::encode(Sha256::digest(&f.old_pins))
    );
    let expected = plan
        .copies
        .iter()
        .filter(|c| payload_copy(c, &plan.selected_pins_file))
        .collect::<Vec<_>>();
    assert_eq!(result.published.len(), expected.len());
    assert!(!result.published.is_empty());
    for copy in expected {
        assert_eq!(
            fs::read(&copy.destination).unwrap(),
            fs::read(&copy.source).unwrap()
        );
        let m = fs::symlink_metadata(&copy.destination).unwrap();
        assert!(m.is_file());
        assert_eq!(m.nlink(), 1);
        assert_eq!(m.uid(), 0);
        assert_eq!(m.gid(), 0);
        assert_eq!(
            m.mode() & 0o7777,
            u32::from_str_radix(&copy.mode, 8).unwrap()
        );
    }
    f.preserved();
    let old = fs::read(f.cli_destination()).unwrap();
    assert!(fixture_payload(&checked, &mut FixtureAuthority::default())
        .unwrap_err()
        .error
        .is("PAYLOAD_REPLACEMENT_UNAVAILABLE"));
    assert_eq!(fs::read(f.cli_destination()).unwrap(), old);
    f.preserved();
}

#[test]
#[ignore = "requires coordinator private root /state fixture"]
fn independent_authority_and_inactive_checks_refuse_before_any_payload_effect() {
    for deny_release in [true, false] {
        let f = Fixture::new();
        let mut authority = FixtureAuthority {
            deny_release,
            deny_inactive: !deny_release,
            ..Default::default()
        };
        assert!(fixture_payload(&f.checked(), &mut authority).is_err());
        assert_eq!(authority.calls, if deny_release { 1 } else { 2 });
        assert!(!f.cli_destination().exists());
        assert!(!f.target.layout.binary_dir.exists());
        f.preserved();
    }
}

#[test]
#[ignore = "requires coordinator private root /state fixture"]
fn upgrade_or_existing_runtime_roots_refuse_without_replacement() {
    let mut f = Fixture::new();
    f.target.role = DeploymentRole::ExistingUpgrade;
    f.write_context();
    let mut authority = FixtureAuthority::default();
    assert!(fixture_payload(&f.checked(), &mut authority)
        .unwrap_err()
        .error
        .is("PAYLOAD_UPGRADE_UNAVAILABLE"));
    assert_eq!(authority.calls, 0);
    for index in 0..4 {
        let f = Fixture::new();
        let roots = [
            &f.target.layout.socket_root,
            &f.target.layout.state_root,
            &f.target.layout.audit_root,
            &f.target.layout.cas_store_root,
        ];
        mkdir_public(roots[index]);
        write_public(
            roots[index].join("preserved"),
            b"state-counter-floor-wrapper",
        )
        .unwrap();
        let mut authority = FixtureAuthority::default();
        assert!(fixture_payload(&f.checked(), &mut authority)
            .unwrap_err()
            .error
            .is("PAYLOAD_TARGET_NOT_PRISTINE"));
        assert_eq!(authority.calls, 0);
        assert_eq!(
            fs::read(roots[index].join("preserved")).unwrap(),
            b"state-counter-floor-wrapper"
        );
        assert!(!f.cli_destination().exists());
    }
}

#[test]
#[ignore = "requires coordinator private root /state fixture"]
fn source_digest_size_and_metadata_mutation_refuse_before_publication() {
    for mutation in ["bytes", "size", "mode", "during-authority"] {
        let f = Fixture::new();
        let checked = f.checked();
        let source = f.cli_source();
        let mut authority = FixtureAuthority::default();
        match mutation {
            "bytes" => {
                let mut b = fs::read(&source).unwrap();
                b[0] ^= 1;
                write_public(&source, b).unwrap();
            }
            "size" => {
                write_public(&source, b"wrong size").unwrap();
            }
            "mode" => {
                fs::set_permissions(&source, fs::Permissions::from_mode(0o666)).unwrap();
            }
            _ => {
                authority.mutate = Some(Box::new(move || {
                    write_public(&source, b"changed during native fixture verification").unwrap();
                }));
            }
        }
        assert!(fixture_payload(&checked, &mut authority).is_err());
        assert!(!f.cli_destination().exists());
        assert!(!f.target.layout.binary_dir.exists());
        f.preserved();
    }
}

#[test]
#[ignore = "requires coordinator private root /state fixture"]
fn source_symlink_hardlink_and_special_files_are_refused() {
    for attack in ["symlink", "hardlink", "fifo"] {
        let f = Fixture::new();
        let source = f.cli_source();
        if attack == "hardlink" {
            fs::hard_link(&source, f.base.join("source-alias")).unwrap();
        } else {
            fs::remove_file(&source).unwrap();
            if attack == "symlink" {
                symlink(&f.target.authority_config, &source).unwrap();
            } else {
                let path = CString::new(source.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
        }
        let mut authority = FixtureAuthority::default();
        assert!(fixture_payload(&f.checked(), &mut authority).is_err());
        assert_eq!(authority.calls, 0);
        assert!(!f.cli_destination().exists());
        f.preserved();
    }
}

#[test]
#[ignore = "requires coordinator private root /state fixture"]
fn destination_symlink_or_ancestor_link_never_redirects_a_copy() {
    let f = Fixture::new();
    mkdir_public(&f.target.layout.binary_dir);
    let victim = f.base.join("victim");
    write_public(&victim, b"untouched").unwrap();
    symlink(&victim, f.cli_destination()).unwrap();
    assert!(fixture_payload(&f.checked(), &mut FixtureAuthority::default()).is_err());
    assert_eq!(fs::read(&victim).unwrap(), b"untouched");
    let f = Fixture::new();
    let alternate = f.base.join("alternate");
    mkdir_public(&alternate);
    symlink(&alternate, &f.target.layout.binary_dir).unwrap();
    assert!(fixture_payload(&f.checked(), &mut FixtureAuthority::default()).is_err());
    assert_eq!(fs::read_dir(&alternate).unwrap().count(), 0);
}

#[test]
#[ignore = "requires coordinator private root /state fixture"]
fn raw_context_or_old_pins_drift_during_approval_refuses_before_writes() {
    for which in ["descriptor", "inventory", "pins"] {
        let f = Fixture::new();
        let checked = f.checked();
        let path = match which {
            "descriptor" => f.config.clone(),
            "inventory" => f.target.expected_artifacts_manifest.clone(),
            _ => f.target.codesign_pins_file.clone(),
        };
        let mut authority = FixtureAuthority {
            mutate: Some(Box::new(move || {
                let mut b = fs::read(&path).unwrap();
                b.push(b'\n');
                write_public(&path, b).unwrap();
            })),
            ..Default::default()
        };
        assert!(fixture_payload(&checked, &mut authority).is_err());
        assert!(!f.target.layout.binary_dir.exists());
    }
}

#[test]
#[ignore = "requires coordinator private root /state fixture"]
fn exclusive_atomic_publication_preserves_existing_name_and_cleans_own_temporary() {
    let f = Fixture::new();
    let mut dirs = Directories::new().unwrap();
    let source = HeldPublicFile::open(&mut dirs, &f.cli_source(), None, MAX_FILE_BYTES).unwrap();
    dirs.ensure(&f.target.layout.binary_dir, true).unwrap();
    let destination = f.cli_destination();
    write_public(&destination, b"existing-payload-sentinel").unwrap();
    assert!(publish_one(&dirs, &source, &destination, 0o755)
        .unwrap_err()
        .is("PAYLOAD_REPLACEMENT_UNAVAILABLE"));
    assert_eq!(
        fs::read(&destination).unwrap(),
        b"existing-payload-sentinel"
    );
    assert_eq!(
        fs::read_dir(&f.target.layout.binary_dir).unwrap().count(),
        1
    );
    assert_eq!(fs::metadata(&destination).unwrap().nlink(), 1);
    f.preserved();
}

#[test]
#[ignore = "requires coordinator private root /state fixture"]
fn directory_replacement_after_held_open_refuses_and_never_follows_new_path() {
    let f = Fixture::new();
    let mut dirs = Directories::new().unwrap();
    dirs.ensure(&f.target.layout.binary_dir, true).unwrap();
    let retained = f.base.join("original-bin");
    fs::rename(&f.target.layout.binary_dir, &retained).unwrap();
    mkdir_public(&f.target.layout.binary_dir);
    assert!(dirs.validate().unwrap_err().is("PAYLOAD_DIRECTORY_CHANGED"));
    assert_eq!(fs::read_dir(&retained).unwrap().count(), 0);
}

#[test]
#[ignore = "requires coordinator private root /state fixture"]
fn bounded_complete_plan_and_deep_directory_limits_refuse() {
    let mut f = Fixture::new();
    let mut inventory: serde_json::Value = serde_json::from_slice(&f.inventory).unwrap();
    inventory["files"]
        .as_array_mut()
        .unwrap()
        .retain(|v| v["path"] != "install.sh");
    write_public(
        &f.target.expected_artifacts_manifest,
        serde_json::to_vec(&inventory).unwrap(),
    )
    .unwrap();
    assert!(
        fixture_payload(&f.checked(), &mut FixtureAuthority::default())
            .unwrap_err()
            .error
            .is("PAYLOAD_INCOMPLETE")
    );
    f.write_context();
    let mut dirs = Directories::new().unwrap();
    let first = f.base.join("not-created");
    let mut path = first.clone();
    for _ in 0..MAX_DIRECTORIES {
        path.push("a");
    }
    assert!(dirs
        .ensure(&path, true)
        .unwrap_err()
        .is("PAYLOAD_DIRECTORY_LIMIT"));
    assert!(!first.exists());
}

#[test]
#[ignore = "requires coordinator private root /state fixture"]
fn cumulative_directory_budget_is_rechecked_after_recursive_parent_insertion() {
    let f = Fixture::new();
    let mut dirs = Directories::new().unwrap();
    let mut index = 0;
    while dirs.held.len() < MAX_DIRECTORIES - 1 {
        dirs.ensure(&f.base.join(format!("held-{index}")), true)
            .unwrap();
        index += 1;
    }
    assert_eq!(dirs.held.len(), MAX_DIRECTORIES - 1);
    let parent = f.base.join("last-parent");
    let child = parent.join("must-not-create");
    assert!(dirs
        .ensure(&child, true)
        .unwrap_err()
        .is("PAYLOAD_DIRECTORY_LIMIT"));
    assert_eq!(dirs.held.len(), MAX_DIRECTORIES);
    assert!(parent.is_dir());
    assert!(!child.exists());
}

#[test]
#[ignore = "requires coordinator private root /state fixture; synthetic L3, no broker activation"]
fn l3_public_payload_preserves_broker_trust_and_retains_tuf_without_publishing_jobs() {
    let f = Fixture::l3();
    let checked = f.checked();
    let plan = target_plan::prepare(&checked).unwrap();
    assert!(plan.missing_required_files.is_empty());
    assert!(plan.copies.iter().any(|c| c.destination
        == Path::new("/Library/LaunchDaemons").join(format!(
            "{}.apfs-broker.plist",
            f.target.layout.launchd_namespace
        ))));
    let broker = f.target.broker.as_ref().unwrap();
    let refs = [
        &f.config,
        &f.target.authority_config,
        &f.target.expected_artifacts_manifest,
        &f.target.codesign_pins_file,
        &broker.tuf_root_file,
    ];
    let observed = refs
        .iter()
        .map(|p| {
            (
                fs::read(p).unwrap(),
                stamp(&fs::symlink_metadata(p).unwrap()),
            )
        })
        .collect::<Vec<_>>();
    let tuf = plan
        .retained_in_staging
        .iter()
        .filter(|c| {
            c.source
                .starts_with(f.target.layout.staging_root.join("tuf"))
        })
        .map(|c| (c.source.clone(), fs::read(&c.source).unwrap()))
        .collect::<Vec<_>>();
    assert_eq!(tuf.len(), 8);
    let mut authority = FixtureAuthority::default();
    let result = fixture_payload(&checked, &mut authority).unwrap();
    assert_eq!(authority.calls, 2);
    assert!(!result.installation_supported && !result.qualified);
    let expected = plan
        .copies
        .iter()
        .filter(|c| payload_copy(c, &plan.selected_pins_file))
        .collect::<Vec<_>>();
    assert_eq!(result.published.len(), expected.len());
    for copy in expected {
        assert!(result
            .published
            .contains(&route(&copy.destination).unwrap()));
        assert_eq!(
            fs::read(&copy.destination).unwrap(),
            fs::read(&copy.source).unwrap()
        );
    }
    for (path, (bytes, metadata)) in refs.iter().zip(observed) {
        assert_eq!(fs::read(path).unwrap(), bytes);
        assert_eq!(stamp(&fs::symlink_metadata(path).unwrap()), metadata);
    }
    for (path, bytes) in tuf {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
    assert_eq!(
        result.selected_pins_sha256_unchanged,
        hex::encode(Sha256::digest(&f.old_pins))
    );
    f.preserved();
}

#[test]
#[ignore = "requires coordinator private root /state fixture; synthetic L3 trust negatives"]
fn l3_missing_or_unprotected_broker_root_refuses_before_authority_and_payload_effects() {
    for attack in ["missing", "writable", "symlink", "hardlink", "empty"] {
        let f = Fixture::l3();
        let checked = f.checked();
        let root = f.target.broker.as_ref().unwrap().tuf_root_file.clone();
        match attack {
            "missing" => fs::remove_file(&root).unwrap(),
            "writable" => fs::set_permissions(&root, fs::Permissions::from_mode(0o666)).unwrap(),
            "symlink" => {
                fs::remove_file(&root).unwrap();
                symlink(&f.target.authority_config, &root).unwrap();
            }
            "hardlink" => fs::hard_link(&root, f.base.join("broker-root-alias")).unwrap(),
            _ => write_public(&root, b"").unwrap(),
        }
        let mut authority = FixtureAuthority::default();
        assert!(fixture_payload(&checked, &mut authority).is_err());
        assert_eq!(authority.calls, 0);
        assert!(!f.target.layout.binary_dir.exists());
        f.preserved();
    }
}

#[test]
#[ignore = "requires coordinator private root /state fixture; synthetic L3 held-trust mutation"]
fn l3_broker_root_bytes_or_named_inode_drift_during_authority_refuses_before_publication() {
    for replace in [false, true] {
        let f = Fixture::l3();
        let checked = f.checked();
        let root = f.target.broker.as_ref().unwrap().tuf_root_file.clone();
        let mut authority = FixtureAuthority {
            mutate: Some(Box::new(move || {
                let mut bytes = fs::read(&root).unwrap();
                if replace {
                    let replacement = root.with_extension("replacement");
                    write_public(&replacement, &bytes).unwrap();
                    fs::rename(replacement, &root).unwrap();
                } else {
                    bytes.push(b'\n');
                    write_public(&root, bytes).unwrap();
                }
            })),
            ..Default::default()
        };
        assert!(fixture_payload(&checked, &mut authority).is_err());
        assert_eq!(authority.calls, 2);
        assert!(!f.target.layout.binary_dir.exists());
        f.preserved();
    }
}

#[test]
#[ignore = "requires coordinator private root /state fixture; synthetic admission boundaries"]
fn account_refusal_precedes_authority_and_mutation_and_still_receives_postcheck() {
    let f = Fixture::new();
    let mut accounts = 0;
    let mut authority = FixtureAuthority::default();
    let failure = run_payload(&f.checked(), &mut authority, &mut |phase| {
        if phase == CheckPhase::Accounts {
            accounts += 1;
            fail!(EACCES, "TEST_ACCOUNTS_REFUSED");
        }
        panic!("no prepared context after initial account refusal")
    })
    .unwrap_err();
    assert_eq!(accounts, 2);
    assert_eq!(authority.calls, 0);
    assert!(failure.error.is("TEST_ACCOUNTS_REFUSED"));
    assert!(failure.operation_error.unwrap().is("TEST_ACCOUNTS_REFUSED"));
    assert!(failure.receipt.artifact_inventory_sha256.is_none());
    assert!(failure.receipt.published.is_empty() && failure.receipt.created_directories.is_empty());
    assert!(failure.receipt.incomplete.is_none() && failure.receipt.temporary.is_none());
    assert!(!f.target.layout.binary_dir.exists());
    f.preserved();
}

#[test]
#[ignore = "requires coordinator private root /state fixture; synthetic authority/postcheck failures"]
fn authority_error_preserves_original_when_account_postcheck_also_refuses() {
    let f = Fixture::new();
    let mut accounts = 0;
    let mut authority = FixtureAuthority {
        deny_release: true,
        ..Default::default()
    };
    let failure = run_payload(&f.checked(), &mut authority, &mut |phase| {
        if phase == CheckPhase::Accounts {
            accounts += 1;
            if accounts == 2 {
                fail!(ESTALE, "TEST_ACCOUNTS_CHANGED");
            }
        }
        Ok(())
    })
    .unwrap_err();
    assert_eq!(accounts, 2);
    assert_eq!(authority.calls, 1);
    assert!(failure.error.is("TEST_ACCOUNTS_CHANGED"));
    assert!(failure
        .operation_error
        .unwrap()
        .is("TEST_RELEASE_NOT_APPROVED"));
    assert!(failure.receipt.published.is_empty() && failure.receipt.created_directories.is_empty());
    assert!(!f.target.layout.binary_dir.exists());
    f.preserved();
}

#[test]
#[ignore = "requires coordinator private root /state fixture; synthetic final account refusal"]
fn final_account_refusal_cannot_return_success_and_retains_complete_verified_prefix() {
    let f = Fixture::new();
    let checked = f.checked();
    let plan = target_plan::prepare(&checked).unwrap();
    let mut accounts = 0;
    let failure = run_payload(&checked, &mut FixtureAuthority::default(), &mut |phase| {
        if phase == CheckPhase::Accounts {
            accounts += 1;
            if accounts == 2 {
                fail!(ESTALE, "TEST_ACCOUNTS_CHANGED");
            }
        }
        Ok(())
    })
    .unwrap_err();
    assert_eq!(accounts, 2);
    assert!(failure.error.is("TEST_ACCOUNTS_CHANGED"));
    assert!(failure.operation_error.is_none());
    let expected = plan
        .copies
        .iter()
        .filter(|c| payload_copy(c, &plan.selected_pins_file))
        .collect::<Vec<_>>();
    assert_eq!(failure.receipt.published.len(), expected.len());
    assert!(!expected.is_empty());
    for copy in expected {
        assert!(failure
            .receipt
            .published
            .contains(&route(&copy.destination).unwrap()));
        assert_eq!(
            fs::read(&copy.destination).unwrap(),
            fs::read(&copy.source).unwrap()
        );
    }
    assert!(!failure.receipt.created_directories.is_empty());
    assert!(failure.receipt.incomplete.is_none() && failure.receipt.temporary.is_none());
    f.preserved();
}

#[test]
#[ignore = "requires coordinator private root /state fixture; synthetic exclusion loss during mkdir"]
fn directory_boundary_loss_retains_created_inode_without_later_metadata_or_payload_writes() {
    let f = Fixture::new();
    let checked = f.checked();
    let plan = target_plan::prepare(&checked).unwrap();
    let first = plan
        .copies
        .iter()
        .find(|c| payload_copy(c, &plan.selected_pins_file))
        .unwrap();
    let planned_parent = route(first.destination.parent().unwrap()).unwrap();
    let parent = planned_parent
        .ancestors()
        .filter(|p| !p.exists())
        .last()
        .unwrap()
        .to_owned();
    let mut accounts = 0;
    let failure = run_payload(&checked, &mut FixtureAuthority::default(), &mut |phase| {
        if phase == CheckPhase::Accounts {
            accounts += 1;
        }
        if phase == CheckPhase::Context && parent.exists() {
            fail!(ESTALE, "TEST_EXCLUSION_LOST");
        }
        Ok(())
    })
    .unwrap_err();
    assert_eq!(accounts, 2);
    assert!(failure.error.is("TEST_EXCLUSION_LOST"));
    assert_eq!(failure.receipt.created_directories, vec![parent.clone()]);
    assert_eq!(failure.receipt.incomplete, Some(parent.clone()));
    assert_eq!(fs::symlink_metadata(parent).unwrap().mode() & 0o7777, 0o700);
    assert!(failure.receipt.published.is_empty() && failure.receipt.temporary.is_none());
    f.preserved();
}

#[test]
#[ignore = "requires coordinator private root /state fixture; synthetic exclusion loss during temp/link"]
fn exclusion_loss_leaves_uncertain_temporary_or_link_and_still_rechecks_accounts() {
    for after_link in [false, true] {
        let f = Fixture::new();
        let checked = f.checked();
        let plan = target_plan::prepare(&checked).unwrap();
        let first = plan
            .copies
            .iter()
            .find(|c| payload_copy(c, &plan.selected_pins_file))
            .unwrap();
        let destination = route(&first.destination).unwrap();
        let parent = destination.parent().unwrap();
        let mut accounts = 0;
        let failure = run_payload(&checked, &mut FixtureAuthority::default(), &mut |phase| {
            if phase == CheckPhase::Accounts {
                accounts += 1;
            }
            let temporary = fs::read_dir(parent)
                .ok()
                .into_iter()
                .flatten()
                .filter_map(Result::ok)
                .any(|e| e.file_name().as_bytes().starts_with(b".mcpmac-payload-"));
            if phase == CheckPhase::Context
                && if after_link {
                    destination.exists()
                } else {
                    temporary
                }
            {
                fail!(ESTALE, "TEST_EXCLUSION_LOST");
            }
            Ok(())
        })
        .unwrap_err();
        assert_eq!(accounts, 2);
        assert!(failure.error.is("TEST_EXCLUSION_LOST"));
        assert!(failure.operation_error.unwrap().is("TEST_EXCLUSION_LOST"));
        assert_eq!(failure.receipt.incomplete, Some(destination.clone()));
        assert!(failure.receipt.published.is_empty());
        let temporary = failure.receipt.temporary.unwrap();
        let metadata = fs::symlink_metadata(&temporary).unwrap();
        assert_eq!(metadata.nlink(), if after_link { 2 } else { 1 });
        if after_link {
            assert_eq!(
                metadata.ino(),
                fs::symlink_metadata(&destination).unwrap().ino()
            );
            assert_eq!(
                fs::read(destination).unwrap(),
                fs::read(&first.source).unwrap()
            );
        } else {
            assert_eq!(metadata.len(), 0);
            assert!(!destination.exists());
        }
        f.preserved();
    }
}

#[test]
#[ignore = "requires coordinator private root /state fixture; synthetic operation and named-binding failures"]
fn held_named_binding_postcheck_runs_even_after_operation_and_account_failures() {
    let f = Fixture::new();
    let checked = f.checked();
    let source = f.cli_source();
    let original = source.clone();
    let mut accounts = 0;
    let mut authority = FixtureAuthority {
        mutate: Some(Box::new(move || {
            let bytes = fs::read(&source).unwrap();
            let replacement = source.with_extension("replaced");
            write_public(&replacement, bytes).unwrap();
            fs::rename(replacement, &source).unwrap();
        })),
        ..Default::default()
    };
    let failure = run_payload(&checked, &mut authority, &mut |phase| {
        if phase == CheckPhase::Accounts {
            accounts += 1;
            if accounts == 2 {
                fail!(ESTALE, "TEST_ACCOUNTS_CHANGED");
            }
        }
        Ok(())
    })
    .unwrap_err();
    assert_eq!(accounts, 2);
    assert!(failure.error.is("PAYLOAD_SOURCE_CHANGED"));
    assert!(failure
        .operation_error
        .unwrap()
        .is("PAYLOAD_SOURCE_CHANGED"));
    assert!(original.exists());
    assert!(failure.receipt.published.is_empty());
    assert!(!f.target.layout.binary_dir.exists());
    f.preserved();
}
