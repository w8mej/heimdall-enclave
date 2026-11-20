//! Private SOFTWARE fixtures only. These tests do not call the native production
//! entry or create any actual selected target, host lock, account or service.
//! Neutral fixture UID/GID exercise the same private directory algorithm; fixed
//! production metadata is checked separately against the actual planner map.
use super::*;
use enclave_core::{
    deployment::{DeploymentBroker, DeploymentLayout, DeploymentSigningMode},
    Profile,
};
use std::{
    fs,
    os::unix::fs::{symlink, DirBuilderExt, PermissionsExt},
};

fn target(profile: Profile) -> DeploymentTarget {
    let base = Path::new("/opt/mcpmac-runtime-fixture");
    let support = base.join("support");
    DeploymentTarget {
        version: 1,
        target_id: "runtime-fixture".into(),
        role: DeploymentRole::DedicatedTest,
        profile,
        authority_config: support.join("authority.json"),
        expected_artifacts_manifest: support.join("inventory.json"),
        codesign_pins_file: support.join("pins.json"),
        signing_identity_mode: DeploymentSigningMode::LocalPins,
        layout: DeploymentLayout {
            binary_dir: base.join("bin"),
            custody_bundle: support.join("Custody.app"),
            sandbox_dir: base.join("sandbox"),
            socket_root: base.join("run"),
            state_root: base.join("state"),
            audit_root: base.join("audit"),
            cas_store_root: base.join("cas-store"),
            staging_root: base.join("stage"),
            support_root: support.clone(),
            launchd_namespace: "com.mcpmac.runtime-fixture".into(),
            mach_service: "com.mcpmac.runtime-fixture.exception".into(),
        },
        broker: if profile == Profile::L3 {
            Some(DeploymentBroker {
                base_dir: base.join("state/apfs-broker"),
                tuf_root_file: support.join("root.json"),
            })
        } else {
            None
        },
        shared_read_only_inputs: vec![],
    }
}
fn plan(t: &DeploymentTarget) -> TargetInstallPlan {
    let raw=serde_json::to_vec(&serde_json::json!({"version":1,"kind":"mcpmac-first-touch-artifact-inventory",
        "target_id":t.target_id,"profile":t.profile,"signing_identity_mode":t.signing_identity_mode,
        "deployment_config_sha256":"a".repeat(64),"source_git_commit":"b".repeat(40),
        "source_manifest_sha256":"c".repeat(64),"source_input_count":1,"codesign_pins_sha256":"d".repeat(64),
        "staging_root":t.layout.staging_root,"external_provenance":"UNKNOWN","files":[
            {"path":"bin/mcp-enclave","sha256":"e".repeat(64),"size":1},
            {"path":"codesign-pins.json","sha256":"d".repeat(64),"size":1}]})).unwrap();
    target_plan::describe(t, &"a".repeat(64), &raw).unwrap()
}
fn receipt() -> RuntimeDirectoryReceipt {
    RuntimeDirectoryReceipt {
        target_id: "private-software-fixture".into(),
        descriptor_sha256: "a".repeat(64),
        artifact_inventory_sha256: "b".repeat(64),
        created: vec![],
        verified_existing: vec![],
        incomplete: None,
        complete: false,
        inactivity_proven: false,
        installation_supported: false,
        qualified: false,
    }
}
fn flags_false(r: &RuntimeDirectoryReceipt) {
    assert!(!r.inactivity_proven && !r.installation_supported && !r.qualified);
}

struct Root {
    path: PathBuf,
    uid: u32,
    gid: u32,
}
impl Root {
    fn new() -> Self {
        let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
        fs::create_dir_all(&parent).unwrap();
        let path = parent.join(format!(
            "runtime-directories-{:x}",
            enclave_core::rng::u64()
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let path = path.canonicalize().unwrap();
        let metadata = fs::metadata(&path).unwrap();
        Self {
            path,
            uid: metadata.uid(),
            gid: metadata.gid(),
        }
    }
    fn directories(&self) -> Directories {
        // Explicit private fixture anchor: ancestors outside this newly-created
        // repository-local fixture are not accepted as native protected paths.
        let path = name(self.path.as_os_str()).unwrap();
        let file = from_fd(unsafe { libc::open(path.as_ptr(), OPEN_DIRECTORY) }).unwrap();
        Directories {
            anchor: self.path.clone(),
            held: BTreeMap::from([(self.path.clone(), Held::new(file).unwrap())]),
            creator_uid: self.uid,
        }
    }
    fn spec(&self, path: &str, mode: u32) -> Spec {
        Spec {
            path: self.path.join(path),
            uid: self.uid,
            gid: self.gid,
            mode,
        }
    }
    fn mkdir(&self, path: &str, mode: u32) {
        fs::DirBuilder::new()
            .mode(mode)
            .create(self.path.join(path))
            .unwrap();
        fs::set_permissions(self.path.join(path), fs::Permissions::from_mode(mode)).unwrap();
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn derives_exact_planner_metadata_for_l2_l3_without_public_or_per_console_outputs() {
    use enclave_core::daemon::{self, DaemonId};
    for profile in [Profile::L2, Profile::L3] {
        let t = target(profile);
        let p = plan(&t);
        let desired = specs(&t, &p).unwrap();
        assert_eq!(desired.len(), if profile == Profile::L3 { 35 } else { 29 });
        let metadata = desired
            .iter()
            .map(|s| (s.path.clone(), (s.uid, s.gid, s.mode)))
            .collect::<BTreeMap<_, _>>();
        for root in [
            &t.layout.socket_root,
            &t.layout.state_root,
            &t.layout.audit_root,
        ] {
            assert_eq!(metadata[root], (0, 0, 0o755));
        }
        for d in DaemonId::ALL {
            assert_eq!(
                metadata[&t.layout.socket_root.join(d.dir_name())],
                (d.uid(), d.client_gid(), 0o2750)
            );
            assert_eq!(
                metadata[&t.layout.state_root.join(d.dir_name())],
                (d.uid(), d.gid(), 0o700)
            );
            assert_eq!(
                metadata[&t.layout.audit_root.join(d.dir_name())],
                (d.uid(), crate::launchd::JOURNAL_READ_GID, 0o2750)
            );
        }
        assert_eq!(metadata[&t.layout.cas_store_root], (702, 8702, 0o700));
        for (suffix, uid, gid, mode) in [
            (
                "supervisor",
                0,
                enclave_core::supervisor::CLIENT_GID,
                0o2750,
            ),
            ("intent", 0, 0, 0o755),
            ("oidc", 0, 0, 0o755),
            (
                crate::launchd::BROWSER_SOCKET_DIR,
                daemon::BROWSER_UID,
                daemon::BROWSER_CLIENT_GID,
                0o2750,
            ),
            (
                daemon::GATEWAY_SOCKET_DIR,
                daemon::GATEWAY_UID,
                daemon::GATEWAY_GID,
                0o755,
            ),
            (
                daemon::WITNESS_SOCKET_DIR,
                705,
                daemon::WITNESS_CLIENT_GID,
                0o2750,
            ),
            ("jobs", 702, 8702, 0o700),
        ] {
            assert_eq!(
                metadata[&t.layout.socket_root.join(suffix)],
                (uid, gid, mode)
            );
        }
        assert!(desired
            .iter()
            .all(|s| !s.path.starts_with(&t.layout.binary_dir)
                && !s.path.starts_with(&t.layout.support_root)
                && !s.path.starts_with(&t.layout.staging_root)
                && !s.path.starts_with("/Library")
                && !s.path.ends_with("501")));
        if let Some(b) = &t.broker {
            for root in [
                &b.base_dir,
                &b.base_dir.join("state"),
                &b.base_dir.join("tuf"),
                &b.base_dir.join("tuf/repo"),
                &t.layout.audit_root.join("apfs-broker"),
            ] {
                assert_eq!(metadata[root], (0, 0, 0o700));
            }
            assert_eq!(
                metadata[&t.layout.socket_root.join("apfs-broker")],
                (0, 8702, 0o2750)
            );
        }
    }
}

#[test]
fn rejects_duplicate_missing_root_unknown_mode_and_daemon_writable_parent_plans() {
    let t = target(Profile::L2);
    for kind in ["duplicate", "missing-root", "mode", "daemon-child"] {
        let mut p = plan(&t);
        match kind {
            "duplicate" => p.directories.push(target_plan::DirectoryEntry {
                path: t.layout.socket_root.clone(),
                uid: 0,
                gid: 0,
                mode: "0755".into(),
                condition: "test",
            }),
            "missing-root" => p.directories.retain(|d| d.path != t.layout.cas_store_root),
            "mode" => {
                p.directories
                    .iter_mut()
                    .find(|d| d.path == t.layout.socket_root)
                    .unwrap()
                    .mode = "0777".into()
            }
            "daemon-child" => p.directories.push(target_plan::DirectoryEntry {
                path: t.layout.state_root.join("custody/new"),
                uid: 0,
                gid: 0,
                mode: "0700".into(),
                condition: "test",
            }),
            _ => unreachable!(),
        }
        assert!(specs(&t, &p).is_err(), "{kind}");
    }
}

#[test]
fn payload_sequence_requires_exact_complete_target_descriptor_inventory_and_public_prefix() {
    let mut t = target(Profile::L2);
    let mut p = plan(&t);
    // This is a synthetic in-process receipt/binding test, not release approval.
    p.missing_required_files.clear();
    let make = || PublicPayloadReceipt {
        target_id: p.target_id.clone(),
        descriptor_sha256: "a".repeat(64),
        artifact_inventory_sha256: p.artifact_inventory_sha256.clone(),
        published: vec![t.layout.binary_dir.join("mcp-enclave")],
        selected_pins_sha256_unchanged: "f".repeat(64),
        installation_supported: false,
        qualified: false,
    };
    assert!(payload_binding(&t, &"a".repeat(64), &p, &make()).is_ok());
    for kind in [
        "target",
        "descriptor",
        "inventory",
        "prefix",
        "duplicate",
        "qualification",
    ] {
        let mut value = make();
        match kind {
            "target" => value.target_id = "other-target".into(),
            "descriptor" => value.descriptor_sha256 = "b".repeat(64),
            "inventory" => value.artifact_inventory_sha256 = "b".repeat(64),
            "prefix" => value.published.clear(),
            "duplicate" => value.published.push(value.published[0].clone()),
            "qualification" => value.qualified = true,
            _ => unreachable!(),
        }
        assert!(
            payload_binding(&t, &"a".repeat(64), &p, &value).is_err(),
            "{kind}"
        );
    }
    let value = make();
    t.role = DeploymentRole::ExistingUpgrade;
    assert!(payload_binding(&t, &"a".repeat(64), &p, &value)
        .unwrap_err()
        .is("RUNTIME_UPGRADE_SEQUENCE_UNAVAILABLE"));
    assert!(require_root(0).is_ok());
    assert!(require_root(501).unwrap_err().is("RUNTIME_ROOT_REQUIRED"));
}

#[test]
fn creates_only_fixed_absent_directories_with_exact_metadata_and_cloexec_then_verifies_retry() {
    let root = Root::new();
    let desired = [
        root.spec("run", 0o755),
        root.spec("run/daemon", 0o2750),
        root.spec("state", 0o700),
    ];
    let mut directories = root.directories();
    let mut r = receipt();
    apply(&mut directories, &desired, &mut r, || Ok(())).unwrap();
    assert!(r.complete);
    flags_false(&r);
    assert_eq!(r.created.len(), 3);
    assert!(r.verified_existing.is_empty() && r.incomplete.is_none());
    for spec in &desired {
        let held = directories.get(&spec.path).unwrap();
        assert!(exact(&stat(&held.file).unwrap(), spec));
        assert_eq!(
            unsafe { libc::fcntl(held.file.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            libc::FD_CLOEXEC
        );
    }
    let mut retry = receipt();
    apply(&mut root.directories(), &desired, &mut retry, || Ok(())).unwrap();
    assert!(retry.complete);
    assert!(retry.created.is_empty());
    assert_eq!(retry.verified_existing.len(), 3);
    flags_false(&retry);
}

#[test]
fn existing_exact_state_with_counter_and_symlink_contents_is_metadata_only_and_never_repaired() {
    let root = Root::new();
    root.mkdir("state", 0o700);
    fs::write(
        root.path.join("state/counter"),
        b"retained monotonic fixture counter: 19",
    )
    .unwrap();
    symlink(
        "/nonexistent-untrusted-content",
        root.path.join("state/do-not-follow"),
    )
    .unwrap();
    let before = fs::symlink_metadata(root.path.join("state/counter")).unwrap();
    let dir_before = fs::metadata(root.path.join("state")).unwrap();
    let mut r = receipt();
    apply(
        &mut root.directories(),
        &[root.spec("state", 0o700)],
        &mut r,
        || Ok(()),
    )
    .unwrap();
    let after = fs::symlink_metadata(root.path.join("state/counter")).unwrap();
    assert!(same_inode(&before, &after));
    assert_eq!(before.mtime_nsec(), after.mtime_nsec());
    assert_eq!(
        fs::read(root.path.join("state/counter")).unwrap(),
        b"retained monotonic fixture counter: 19"
    );
    assert_eq!(
        fs::read_link(root.path.join("state/do-not-follow")).unwrap(),
        Path::new("/nonexistent-untrusted-content")
    );
    assert!(Stamp::of(&dir_before) == Stamp::of(&fs::metadata(root.path.join("state")).unwrap()));
    assert!(r.created.is_empty());
    assert_eq!(r.verified_existing, vec![root.path.join("state")]);
    flags_false(&r);
}

#[test]
fn missing_unplanned_ancestor_refuses_without_mkdir_or_partial_claim() {
    let root = Root::new();
    let mut r = receipt();
    let error = apply(
        &mut root.directories(),
        &[root.spec("not-planned/leaf", 0o700)],
        &mut r,
        || Ok(()),
    )
    .unwrap_err();
    assert!(error.is("RUNTIME_ANCESTOR_MISSING"));
    assert!(!root.path.join("not-planned").exists());
    assert!(
        r.created.is_empty()
            && r.verified_existing.is_empty()
            && r.incomplete.is_none()
            && !r.complete
    );
    flags_false(&r);
}

#[test]
fn wrong_owner_group_mode_or_special_bits_refuse_existing_inode_without_mutation() {
    for kind in ["owner", "group", "mode", "special"] {
        let root = Root::new();
        root.mkdir("state", if kind == "special" { 0o1700 } else { 0o700 });
        let before = fs::metadata(root.path.join("state")).unwrap();
        let mut desired = root.spec("state", 0o700);
        match kind {
            "owner" => desired.uid = root.uid.checked_add(1).unwrap(),
            "group" => desired.gid = root.gid.checked_add(1).unwrap(),
            "mode" => desired.mode = 0o755,
            "special" => (),
            _ => unreachable!(),
        }
        assert!(!exact(&before, &desired));
        let mut r = receipt();
        assert!(
            apply(&mut root.directories(), &[desired], &mut r, || Ok(()))
                .unwrap_err()
                .is("RUNTIME_EXISTING_DIRECTORY_METADATA")
        );
        assert!(Stamp::of(&before) == Stamp::of(&fs::metadata(root.path.join("state")).unwrap()));
        assert!(r.created.is_empty() && r.verified_existing.is_empty() && r.incomplete.is_none());
        flags_false(&r);
    }
}

#[test]
fn symlink_file_hardlink_fifo_and_symlink_or_writable_ancestor_are_refused() {
    for kind in [
        "symlink",
        "file",
        "hardlink",
        "fifo",
        "ancestor-symlink",
        "ancestor-writable",
    ] {
        let root = Root::new();
        fs::write(root.path.join("preserve"), b"retained fixture bytes").unwrap();
        let desired = if kind.starts_with("ancestor-") {
            root.mkdir("original", 0o700);
            if kind == "ancestor-symlink" {
                symlink(root.path.join("original"), root.path.join("bad")).unwrap();
            } else {
                root.mkdir("bad", 0o777);
            }
            root.spec("bad/leaf", 0o700)
        } else {
            let path = root.path.join("bad");
            match kind {
                "symlink" => symlink(root.path.join("preserve"), &path).unwrap(),
                "file" => fs::write(&path, b"do not truncate").unwrap(),
                "hardlink" => fs::hard_link(root.path.join("preserve"), &path).unwrap(),
                "fifo" => {
                    let value = name(path.as_os_str()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(value.as_ptr(), 0o600) }, 0);
                }
                _ => unreachable!(),
            }
            root.spec("bad", 0o700)
        };
        let before = fs::symlink_metadata(root.path.join("bad")).unwrap();
        let mut r = receipt();
        assert!(
            apply(&mut root.directories(), &[desired], &mut r, || Ok(())).is_err(),
            "{kind}"
        );
        assert!(same_inode(
            &before,
            &fs::symlink_metadata(root.path.join("bad")).unwrap()
        ));
        assert_eq!(
            fs::read(root.path.join("preserve")).unwrap(),
            b"retained fixture bytes"
        );
        assert!(!root.path.join("original/leaf").exists());
        assert!(r.created.is_empty());
        flags_false(&r);
    }
}

#[test]
fn named_ancestor_substitution_after_first_directory_aborts_without_following_replacement() {
    let root = Root::new();
    let desired = [root.spec("run", 0o755), root.spec("run/leaf", 0o700)];
    let mut r = receipt();
    let mut calls = 0;
    let error = apply(&mut root.directories(), &desired, &mut r, || {
        calls += 1;
        if calls == 3 {
            fs::rename(root.path.join("run"), root.path.join("retained-original")).unwrap();
            root.mkdir("run", 0o755);
        }
        Ok(())
    })
    .unwrap_err();
    assert!(error.is("RUNTIME_DIRECTORY_CHANGED"));
    assert_eq!(calls, 3);
    assert_eq!(r.created, vec![root.path.join("run")]);
    assert!(!r.complete && r.incomplete.is_none());
    assert!(
        !root.path.join("run/leaf").exists() && !root.path.join("retained-original/leaf").exists()
    );
    flags_false(&r);
}

#[test]
fn exclusion_or_context_failure_keeps_completed_prefix_and_never_runs_later_creation() {
    for fail_at in [1, 3, 4] {
        let root = Root::new();
        let mut calls = 0;
        let mut r = receipt();
        let desired = [root.spec("run", 0o755), root.spec("state", 0o700)];
        let error = apply(&mut root.directories(), &desired, &mut r, || {
            calls += 1;
            if calls == fail_at {
                Err(err!(ESTALE, "TEST_CONTEXT_OR_EXCLUSION_CHANGED"))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert!(error.is("TEST_CONTEXT_OR_EXCLUSION_CHANGED"));
        assert!(!r.complete);
        assert_eq!(r.created.len(), if fail_at == 1 { 0 } else { 1 });
        assert!(!root.path.join("state").exists());
        flags_false(&r);
    }
}

#[test]
fn failed_observed_new_metadata_leaves_incomplete_directory_and_never_claims_or_repairs_it() {
    let root = Root::new();
    let mut desired = root.spec("state", 0o700);
    // POSIX uid_t(-1) makes fchown retain its current UID. The observed exact
    // metadata check must refuse this synthetic mismatch even if syscall is0.
    desired.uid = u32::MAX;
    let mut r = receipt();
    assert!(
        apply(&mut root.directories(), &[desired], &mut r, || Ok(()))
            .unwrap_err()
            .is("RUNTIME_NEW_DIRECTORY_METADATA")
    );
    assert!(root.path.join("state").is_dir());
    assert_eq!(
        fs::metadata(root.path.join("state")).unwrap().uid(),
        root.uid
    );
    assert_eq!(r.incomplete, Some(root.path.join("state")));
    assert!(r.created.is_empty() && !r.complete);
    flags_false(&r);
}

#[test]
fn operation_error_still_rechecks_and_postcheck_refusal_preserves_prefix_and_incomplete_name() {
    for postcheck_refuses in [false, true] {
        let root = Root::new();
        let mut broken = root.spec("state", 0o700);
        broken.uid = u32::MAX;
        let desired = [
            root.spec("run", 0o755),
            broken,
            root.spec("never-created", 0o700),
        ];
        let mut calls = 0;
        let mut r = receipt();
        let error = apply(&mut root.directories(), &desired, &mut r, || {
            calls += 1;
            if calls == 5 && postcheck_refuses {
                Err(err!(ESTALE, "TEST_POSTCHECK_REFUSED"))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(
            calls, 5,
            "postcheck must execute even after actual new-owner metadata refusal"
        );
        assert!(error.is(if postcheck_refuses {
            "TEST_POSTCHECK_REFUSED"
        } else {
            "RUNTIME_NEW_DIRECTORY_METADATA"
        }));
        assert_eq!(r.created, vec![root.path.join("run")]);
        assert_eq!(r.incomplete, Some(root.path.join("state")));
        assert!(root.path.join("run").is_dir() && root.path.join("state").is_dir());
        assert!(!root.path.join("never-created").exists());
        assert!(!r.complete);
        flags_false(&r);
    }
}

#[test]
fn binding_validation_runs_even_when_context_postcheck_refuses() {
    let root = Root::new();
    let mut calls = 0;
    let mut r = receipt();
    let error = apply(
        &mut root.directories(),
        &[root.spec("run", 0o755)],
        &mut r,
        || {
            calls += 1;
            if calls == 3 {
                fs::rename(root.path.join("run"), root.path.join("retained-original")).unwrap();
                root.mkdir("run", 0o755);
                return Err(err!(ESTALE, "TEST_CONTEXT_REFUSED"));
            }
            Ok(())
        },
    )
    .unwrap_err();
    assert!(error.is("RUNTIME_DIRECTORY_CHANGED"));
    assert_eq!(calls, 3);
    assert_eq!(r.created, vec![root.path.join("run")]);
    assert!(!r.complete);
    flags_false(&r);
}

#[test]
fn held_directory_metadata_change_and_fixture_anchor_replacement_are_detected() {
    let root = Root::new();
    root.mkdir("state", 0o700);
    let mut directories = root.directories();
    let mut r = receipt();
    directories.one(&root.spec("state", 0o700), &mut r).unwrap();
    fs::set_permissions(root.path.join("state"), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(directories
        .validate()
        .unwrap_err()
        .is("RUNTIME_DIRECTORY_CHANGED"));
    let root = Root::new();
    let directories = root.directories();
    let moved = root.path.with_extension("retained-original");
    fs::rename(&root.path, &moved).unwrap();
    fs::create_dir(&root.path).unwrap();
    fs::set_permissions(&root.path, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(directories
        .validate()
        .unwrap_err()
        .is("RUNTIME_DIRECTORY_CHANGED"));
    fs::remove_dir(&root.path).unwrap();
    fs::rename(&moved, &root.path).unwrap();
}
