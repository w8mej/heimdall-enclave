//! Private engine fixtures; native birth/guard, authority and installation are
//! never constructed here. Ignored source cases use the genuine held-file
//! reader's explicit root /state software fixture, not native ACL admission.
use super::*;
use crate::deploy::target_birth_inputs::BirthSourceSpec;
use serde_json::{json, Value};
use std::{
    cell::Cell,
    os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt},
};
fn encode(v: Value) -> Vec<u8> {
    serde_json::to_vec(&v).unwrap()
}
fn sync(file: &File) -> EnclaveResult<()> {
    file.sync_all().map_err(|_| err!(EIO, "FIXTURE_SYNC"))
}
fn template() -> DeploymentTarget {
    DeploymentTarget::parse(&encode(json!({"version":1,"target_id":"stage-fixture","role":"dedicated-test",
        "profile":"L2","signing_identity_mode":"local-pins","authority_config":"/template/support/custody.json",
        "expected_artifacts_manifest":"/template/config/inventory.json","codesign_pins_file":"/template/support/pins.json",
        "broker":null,"shared_read_only_inputs":[],"layout":{"binary_dir":"/template/bin",
            "custody_bundle":"/template/support/Custody.app","sandbox_dir":"/template/sandbox","socket_root":"/template/run",
            "state_root":"/template/state","audit_root":"/template/audit","cas_store_root":"/template/cas",
            "staging_root":"/template/stage","support_root":"/template/support",
            "launchd_namespace":"com.mcpmac.stagefixture","mach_service":"com.mcpmac.stagefixture.exception"}}))).unwrap()
}
fn no_authority(p: &BirthProgress) {
    assert!(
        !p.activation_allowed
            && !p.mutation_allowed
            && !p.inactivity_proven
            && !p.installation_supported
            && !p.qualified
    );
}
fn denied<T>(r: EnclaveResult<T>, reason: &str) {
    assert!(
        r.err().expect("must refuse").is(reason),
        "expected {reason}"
    );
}
struct Fixture {
    anchor: PathBuf,
    state: BirthState,
    payloads: BTreeMap<PathBuf, Vec<u8>>,
}
impl Fixture {
    fn new() -> Self {
        let parent = std::env::var_os("ENCLAVE_TEST_STATE_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::current_dir().unwrap());
        let anchor = parent.join(format!(
            "birth-stage-{}",
            hex::encode(enclave_core::rng::bytes32())
        ));
        std::fs::create_dir(&anchor).unwrap();
        std::fs::set_permissions(&anchor, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Source namespace setup precedes capturing the original birth parent
        // nlinks. It is never adopted or refreshed by the product importer.
        let package = anchor.join("sources");
        std::fs::create_dir(&package).unwrap();
        std::fs::set_permissions(&package, std::fs::Permissions::from_mode(0o700)).unwrap();
        let original = BirthPlan::build(
            &template(),
            Path::new("/template"),
            Path::new("/birth-stage"),
            &[0x43; 16],
        )
        .unwrap();
        let root = anchor.join(original.root.file_name().unwrap());
        let map = |p: &Path| root.join(p.strip_prefix(&original.root).unwrap());
        // Private test rebase, not a native socket-qualified birth constructor.
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
        let mut payloads = BTreeMap::from([
            (
                PathBuf::from("bin/mcp-enclave"),
                (0..(2 * 64 * 1024 + 37)).map(|i| (i % 251) as u8).collect(),
            ),
            (
                PathBuf::from("SHA256SUMS"),
                b"unadmitted checksums".to_vec(),
            ),
            (
                PathBuf::from("EnclaveCustody.app/Contents/MacOS/enclave-custody-vaultd"),
                b"unadmitted code".to_vec(),
            ),
            (
                PathBuf::from("launchd/adapter.sb"),
                b"unadmitted sandbox".to_vec(),
            ),
            (
                PathBuf::from("tuf/repo/root.json"),
                b"unadmitted root".to_vec(),
            ),
            (
                PathBuf::from("tuf/repo/enclave-host-config.json"),
                b"unadmitted hostconfig".to_vec(),
            ),
            (
                PathBuf::from("fido-mds/yubico.json"),
                b"unadmitted diagnostic metadata".to_vec(),
            ),
            (PathBuf::from("public-trust.sh"), b"never execute".to_vec()),
        ]);
        payloads.insert(
            PathBuf::from(format!(
                "launchd/{}.adapter.plist",
                state.plan.target.layout.launchd_namespace
            )),
            b"unadmitted job".to_vec(),
        );
        let pins = encode(
            json!({"v":1,"mode":"local-pins","pins":{"com.enterprise.enclave.ctl":["ab".repeat(20)]}}),
        );
        let mut inventory_payloads = payloads.clone();
        inventory_payloads.insert(PINS.into(), pins.clone());
        let files = inventory_payloads
            .iter()
            .map(|(p, b)| json!({"path":p,"sha256":hex::encode(Sha256::digest(b)),"size":b.len()}))
            .collect::<Vec<_>>();
        let raw = encode(
            json!({"version":1,"kind":"mcpmac-first-touch-artifact-inventory","target_id":state.plan.target.target_id,
            "profile":"L2","signing_identity_mode":"local-pins","deployment_config_sha256":hex::encode(Sha256::digest(&state.plan.bytes)),
            "source_git_commit":"a".repeat(40),"source_manifest_sha256":"b".repeat(64),"source_input_count":1,
            "codesign_pins_sha256":hex::encode(Sha256::digest(&pins)),"staging_root":state.plan.target.layout.staging_root,
            "external_provenance":"UNKNOWN","files":files}),
        );
        state
            .prepare_denial(&raw, &mut || Vec::new(), &mut sync)
            .unwrap();
        let support = &state.plan.target.layout.support_root;
        let manifest = encode(
            json!({"v":1,"profile":"L2","asset_policy_file":support.join("public/policy.json"),
            "asset_policy_key_file":support.join("public/policy.key"),"asset_inventory_key_file":support.join("public/inventory.key"),
            "envelope_policy_key_file":support.join("public/envelope.key"),"asset_host_id":"fixture-host",
            "asset_id":"fixture-asset","asset_custodian_id":"fixture-custodian","envelope_policy_subject":"fixture-host",
            "envelope_policy_namespace":"fixture-namespace"}),
        );
        let public = support.join("public");
        state
            .create_directory(&public, &mut || Vec::new(), &mut Vec::new(), &mut sync)
            .unwrap();
        let initial = vec![
            (state.plan.target.expected_artifacts_manifest.clone(), raw),
            (state.plan.target.authority_config.clone(), manifest),
            (public.join("policy.json"), b"{}".to_vec()),
            (public.join("policy.key"), "01".repeat(32).into_bytes()),
            (public.join("inventory.key"), "02".repeat(32).into_bytes()),
            (public.join("envelope.key"), "03".repeat(32).into_bytes()),
            (
                state.plan.target.layout.staging_root.join(PINS),
                pins.clone(),
            ),
            (state.plan.target.codesign_pins_file.clone(), pins),
        ];
        for (path, bytes) in initial {
            let mode = if path == state.plan.target.layout.staging_root.join(PINS) {
                0o600
            } else {
                0o644
            };
            state
                .create_file(
                    &path,
                    &bytes,
                    mode,
                    &mut || Vec::new(),
                    &mut Vec::new(),
                    &mut sync,
                )
                .unwrap();
        }
        Self {
            anchor,
            state,
            payloads,
        }
    }
    fn observed(&self) -> Vec<StagedSource> {
        self.payloads
            .iter()
            .enumerate()
            .map(|(index, (p, b))| StagedSource {
                index,
                relative: p.clone(),
                sha256: hex::encode(Sha256::digest(b)),
                size: b.len() as u64,
            })
            .collect()
    }
    fn source_package(&self) -> (PathBuf, Vec<BirthSourceSpec>) {
        let package = self.anchor.join("sources");
        let mut specs = Vec::new();
        for (index, (relative, bytes)) in self.payloads.iter().enumerate() {
            // Different source names demonstrate roles, not path coincidences,
            // bind actual original-source bytes to selected staging routes.
            let path = package.join(format!("source-{index}"));
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            f.write_all(bytes).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            specs.push(BirthSourceSpec {
                role: BirthSourceRole::Staged(relative.clone()),
                path,
                sha256: hex::encode(Sha256::digest(bytes)),
                size: bytes.len() as u64,
            });
        }
        (package, specs)
    }
    fn sources(&self) -> (UnadmittedBirthSources, Vec<BirthSourceSpec>) {
        let (package, specs) = self.source_package();
        (
            UnadmittedBirthSources::open_software_fixture(&package, &specs).unwrap(),
            specs,
        )
    }
    fn replace_inventory(&mut self, edit: impl FnOnce(&mut Value)) {
        // Pure-plan fixture alteration, never a production owner repair path.
        let mut value: Value =
            serde_json::from_slice(&self.state.pending.as_ref().unwrap().bytes).unwrap();
        edit(&mut value);
        let raw = encode(value);
        let pending = PendingInventory::new(&self.state.plan, &raw).unwrap();
        self.state
            .files
            .get_mut(&self.state.plan.target.expected_artifacts_manifest)
            .unwrap()
            .bytes = raw;
        self.state
            .files
            .get_mut(
                &self
                    .state
                    .plan
                    .target
                    .layout
                    .support_root
                    .join(UPGRADE_INHIBITION_LEAF),
            )
            .unwrap()
            .bytes = pending.marker_bytes(&self.state.plan).unwrap();
        self.state.pending = Some(pending);
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.anchor);
    }
}

#[test]
fn plan_closes_remaining_actual_copy_and_retained_sources_before_effects() {
    let f = Fixture::new();
    let before = (
        f.state.files.len(),
        f.state.dirs.len(),
        f.state.progress.attempted.clone(),
    );
    let plan = StagePlan::build(&f.state, &f.observed()).unwrap();
    assert_eq!(plan.files.len(), f.payloads.len());
    for file in &plan.files {
        let relative = file
            .destination
            .strip_prefix(&f.state.plan.target.layout.staging_root)
            .unwrap();
        assert_eq!(file.size, f.payloads[relative].len() as u64);
        assert!(!file.destination.exists());
    }
    assert_eq!(
        before,
        (
            f.state.files.len(),
            f.state.dirs.len(),
            f.state.progress.attempted.clone()
        )
    );
    assert!(plan
        .directories
        .iter()
        .all(|p| p.starts_with(&f.state.plan.target.layout.staging_root)));
    assert!(!plan
        .files
        .iter()
        .any(|f| f.destination.starts_with("/Library")));
    no_authority(&f.state.progress);
}
#[test]
fn exact_source_set_hash_size_case_and_initial_ownership_are_required() {
    let f = Fixture::new();
    let mut source = f.observed();
    source.pop();
    denied(
        StagePlan::build(&f.state, &source),
        "BIRTH_STAGE_SOURCE_SET",
    );
    let mut source = f.observed();
    source[0].relative = "SHA256sums".into();
    denied(
        StagePlan::build(&f.state, &source),
        "BIRTH_STAGE_SOURCE_SET",
    );
    let mut source = f.observed();
    source[0].sha256 = "0".repeat(64);
    denied(
        StagePlan::build(&f.state, &source),
        "BIRTH_STAGE_SOURCE_BINDING",
    );
    let mut source = f.observed();
    source[0].size += 1;
    denied(
        StagePlan::build(&f.state, &source),
        "BIRTH_STAGE_SOURCE_BINDING",
    );
    let mut f = Fixture::new();
    let pins = f.state.plan.target.layout.staging_root.join(PINS);
    f.state.files.remove(&pins);
    denied(
        StagePlan::build(&f.state, &f.observed()),
        "BIRTH_STAGE_INITIAL_INPUTS_REQUIRED",
    );
    let mut f = Fixture::new();
    f.state.progress.denial_prepared = false;
    denied(
        StagePlan::build(&f.state, &f.observed()),
        "BIRTH_STAGE_INITIAL_INPUTS_REQUIRED",
    );
}
#[test]
fn cached_case_directory_alias_and_total_node_budget_refuse_before_effects() {
    let mut f = Fixture::new();
    let stage = f.state.plan.target.layout.staging_root.clone();
    let alias = stage.join("BIN");
    f.state
        .create_directory(&alias, &mut || Vec::new(), &mut Vec::new(), &mut sync)
        .unwrap();
    let before = f.state.progress.attempted.clone();
    denied(
        StagePlan::build(&f.state, &f.observed()),
        "BIRTH_STAGE_DIRECTORY_ALIAS",
    );
    assert_eq!(before, f.state.progress.attempted);
    let mut f = Fixture::new();
    let directory = f.state.dirs.values().next().unwrap();
    let original = directory.file.try_clone().unwrap();
    let stamp = directory.stamp.clone();
    let links = directory.links;
    while f.state.dirs.len() < MAX_NODES {
        let p = f.anchor.join(format!("cached{}", f.state.dirs.len()));
        f.state.dirs.insert(
            p,
            Directory {
                file: original.try_clone().unwrap(),
                parent: None,
                stamp: stamp.clone(),
                links,
                private: true,
            },
        );
    }
    denied(
        StagePlan::build(&f.state, &f.observed()),
        "BIRTH_DIRECTORY_LIMIT",
    );
}
#[test]
fn exact_pins_and_nonstreamed_original_initial_bytes_remain_required() {
    let mut f = Fixture::new();
    let pins = f.state.plan.target.codesign_pins_file.clone();
    f.state.files.get_mut(&pins).unwrap().bytes.push(b' ');
    denied(
        StagePlan::build(&f.state, &f.observed()),
        "BIRTH_STAGE_PINS_BINDING",
    );
    let mut f = Fixture::new();
    let manifest = f.state.plan.target.authority_config.clone();
    f.state.files.get_mut(&manifest).unwrap().streamed = Some(StreamedContent {
        length: 1,
        sha256: "a".repeat(64),
    });
    denied(
        StagePlan::build(&f.state, &f.observed()),
        "BIRTH_STAGE_INITIAL_INPUTS_REQUIRED",
    );
}
#[test]
fn zero_retained_bytes_are_refused_in_pure_plan_without_weakening_source_owner() {
    let mut f = Fixture::new();
    f.payloads.insert("SHA256SUMS".into(), Vec::new());
    f.replace_inventory(|v| {
        for item in v["files"].as_array_mut().unwrap() {
            if item["path"] == "SHA256SUMS" {
                item["size"] = json!(0);
                item["sha256"] = json!(hex::encode(Sha256::digest([])));
            }
        }
    });
    denied(
        StagePlan::build(&f.state, &f.observed()),
        "BIRTH_STAGE_SOURCE_BOUND",
    );
}

#[test]
#[ignore = "requires actual root and explicit protected /state software source fixture"]
fn genuine_source_reader_streams_multiple_chunks_preserves_initial_inodes_and_private_modes() {
    let mut f = Fixture::new();
    let before = f
        .state
        .files
        .iter()
        .map(|(p, s)| (p.clone(), s.stamp.directory.ino, s.bytes.clone()))
        .collect::<Vec<_>>();
    let (mut sources, _) = f.sources();
    let progress = f
        .state
        .import_remaining_staging_sources(&mut sources, &mut || Vec::new(), &mut sync)
        .unwrap();
    for (path, inode, bytes) in before {
        let held = &f.state.files[&path];
        assert_eq!(held.stamp.directory.ino, inode);
        assert_eq!(held.exact_bytes(), Some(bytes.as_slice()));
    }
    for (relative, bytes) in &f.payloads {
        let path = f.state.plan.target.layout.staging_root.join(relative);
        let held = &f.state.files[&path];
        assert_eq!(std::fs::read(&path).unwrap(), *bytes);
        assert!(held.bytes.is_empty() && held.streamed.is_some());
        assert!(held.exact_bytes().is_none());
        let m = held.file.metadata().unwrap();
        assert_eq!((m.mode() & 0o7777, m.nlink()), (0o600, 1));
    }
    for d in f.state.dirs.values().filter(|d| d.private) {
        assert_eq!(d.file.metadata().unwrap().mode() & 0o7777, 0o700);
    }
    no_authority(&progress);
    assert!(progress.denial_prepared);
    f.state.revalidate(&mut || Vec::new()).unwrap();
    assert!(!f.state.plan.target.layout.binary_dir.exists());
    assert!(!f.state.plan.target.layout.state_root.exists());
    let failure = f
        .state
        .import_remaining_staging_sources(&mut sources, &mut || Vec::new(), &mut sync)
        .unwrap_err();
    assert!(failure.error.is("BIRTH_STAGE_ALREADY_PREPARED"));
    assert!(f.state.poisoned);
}
#[test]
#[ignore = "requires actual root and explicit protected /state software source fixture"]
fn same_original_destination_full_digest_and_named_identity_revalidation_is_sticky() {
    for replace in [false, true] {
        let mut f = Fixture::new();
        let (mut sources, _) = f.sources();
        f.state
            .import_remaining_staging_sources(&mut sources, &mut || Vec::new(), &mut sync)
            .unwrap();
        let path = f
            .state
            .plan
            .target
            .layout
            .staging_root
            .join("bin/mcp-enclave");
        let bytes = std::fs::read(&path).unwrap();
        let held = &f.state.files[&path];
        let expected = held.streamed.as_ref().unwrap().sha256.clone();
        assert_eq!(
            file_sha256(&held.file, bytes.len() as u64).unwrap(),
            expected
        );
        if replace {
            std::fs::rename(&path, path.with_extension("original")).unwrap();
            std::fs::write(&path, &bytes).unwrap();
        } else {
            let mut changed = bytes.clone();
            changed[0] ^= 1;
            std::fs::write(&path, changed).unwrap();
        }
        assert!(f.state.revalidate(&mut || Vec::new()).is_err());
        std::fs::write(&path, &bytes).unwrap();
        assert!(f.state.revalidate(&mut || Vec::new()).is_err());
        assert!(f.state.poisoned);
    }
}
#[test]
#[ignore = "requires actual root and explicit protected /state software source fixture"]
fn guard_loss_midstream_retains_partial_file_and_all_final_errors() {
    let mut f = Fixture::new();
    let (mut sources, _) = f.sources();
    let path = f
        .state
        .plan
        .target
        .layout
        .staging_root
        .join("bin/mcp-enclave");
    let lost = Cell::new(false);
    let failure = f
        .state
        .import_remaining_staging_sources(
            &mut sources,
            &mut || {
                if std::fs::metadata(&path).is_ok_and(|m| m.len() >= 64 * 1024) {
                    lost.set(true);
                }
                if lost.get() {
                    vec![err!(EACCES, "FIXTURE_GUARD_LOST")]
                } else {
                    Vec::new()
                }
            },
            &mut sync,
        )
        .unwrap_err();
    assert!(failure.error.is("FIXTURE_GUARD_LOST"));
    assert!(!failure.boundary_errors.is_empty() && !failure.final_errors.is_empty());
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 64 * 1024);
    assert!(f.state.poisoned);
    no_authority(&failure.progress);
}
#[test]
#[ignore = "requires actual root and explicit protected /state software source fixture"]
fn original_source_mutation_stops_before_next_effect_and_poison_cannot_be_restored() {
    let mut f = Fixture::new();
    let (mut sources, specs) = f.sources();
    let source = specs
        .iter()
        .find(|s| matches!(&s.role,BirthSourceRole::Staged(p)if p==Path::new("bin/mcp-enclave")))
        .unwrap();
    let original = std::fs::read(&source.path).unwrap();
    let destination = f
        .state
        .plan
        .target
        .layout
        .staging_root
        .join("bin/mcp-enclave");
    let changed = Cell::new(false);
    let failure = f
        .state
        .import_remaining_staging_sources(
            &mut sources,
            &mut || {
                if !changed.get()
                    && std::fs::metadata(&destination).is_ok_and(|m| m.len() >= 64 * 1024)
                {
                    let mut bytes = original.clone();
                    bytes[0] ^= 1;
                    std::fs::write(&source.path, bytes).unwrap();
                    changed.set(true);
                }
                Vec::new()
            },
            &mut sync,
        )
        .unwrap_err();
    assert!(changed.get());
    assert_eq!(std::fs::metadata(&destination).unwrap().len(), 64 * 1024);
    assert!(f.state.poisoned && !failure.final_errors.is_empty());
    std::fs::write(&source.path, original).unwrap();
    assert!(sources.assert_current().is_err());
    no_authority(&failure.progress);
}
#[test]
#[ignore = "requires actual root and explicit protected /state software source fixture"]
fn foreign_file_symlink_fifo_and_directory_are_never_adopted_or_repaired() {
    for kind in ["file", "symlink", "fifo", "directory"] {
        let mut f = Fixture::new();
        let (mut sources, _) = f.sources();
        let directory = f.state.plan.target.layout.staging_root.join("bin");
        f.state
            .create_directory(&directory, &mut || Vec::new(), &mut Vec::new(), &mut sync)
            .unwrap();
        let path = directory.join("mcp-enclave");
        match kind {
            "file" => std::fs::write(&path, b"foreign").unwrap(),
            "symlink" => symlink("/nonexistent-foreign", &path).unwrap(),
            "fifo" => {
                let name = CString::new(path.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
            _ => std::fs::create_dir(&path).unwrap(),
        }
        // Fixture-only setup observes own external injection's parent link
        // count so the test reaches O_EXCL. Product never refreshes on EEXIST.
        for d in f.state.dirs.values_mut() {
            d.links = d.file.metadata().unwrap().nlink();
        }
        let before = std::fs::symlink_metadata(&path).unwrap();
        let failure = f
            .state
            .import_remaining_staging_sources(&mut sources, &mut || Vec::new(), &mut sync)
            .unwrap_err();
        assert!(failure.error.is("BIRTH_ALREADY_EXISTS"));
        let after = std::fs::symlink_metadata(&path).unwrap();
        assert_eq!(
            (before.dev(), before.ino(), before.mode(), before.len()),
            (after.dev(), after.ino(), after.mode(), after.len())
        );
        assert!(!f.state.files.contains_key(&path));
        assert!(f.state.poisoned);
    }
}
#[test]
#[ignore = "requires actual root and explicit protected /state software source fixture"]
fn file_sync_failure_preserves_created_original_names_and_denial() {
    let mut f = Fixture::new();
    let (mut sources, _) = f.sources();
    let failed = Cell::new(false);
    let failure = f
        .state
        .import_remaining_staging_sources(&mut sources, &mut || Vec::new(), &mut |file| {
            let m = file.metadata().unwrap();
            if m.is_file() && m.len() > 64 * 1024 {
                failed.set(true);
                Err(err!(EIO, "FIXTURE_SYNC_FAIL"))
            } else {
                sync(file)
            }
        })
        .unwrap_err();
    assert!(failed.get() && failure.error.is("FIXTURE_SYNC_FAIL"));
    let path = f
        .state
        .plan
        .target
        .layout
        .staging_root
        .join("bin/mcp-enclave");
    assert!(path.exists() && f.state.files.contains_key(&path));
    assert!(f.state.progress.denial_prepared);
    assert!(f.state.poisoned);
    assert!(f
        .state
        .plan
        .target
        .layout
        .support_root
        .join(UPGRADE_INHIBITION_LEAF)
        .exists());
    no_authority(&failure.progress);
}

#[test]
#[ignore = "requires actual root and explicit protected /state software source fixture"]
fn full_digest_gate_is_distinct_from_metadata_only_streaming_boundary() {
    let mut f = Fixture::new();
    let (mut sources, _) = f.sources();
    f.state
        .import_remaining_staging_sources(&mut sources, &mut || Vec::new(), &mut sync)
        .unwrap();
    let path = f
        .state
        .plan
        .target
        .layout
        .staging_root
        .join("bin/mcp-enclave");
    let original = std::fs::read(&path).unwrap();
    let mut changed = original.clone();
    changed[0] ^= 1;
    std::fs::write(&path, &changed).unwrap();
    // Test-only stable-metadata simulation demonstrates digest enforcement
    // separately from ordinary mtime/ctime drift; product never repairs stamps.
    let held = f.state.files.get_mut(&path).unwrap();
    held.stamp = FileStamp::of(&held.file.metadata().unwrap());
    assert!(f.state.metadata_checks(&mut || Vec::new()).is_empty());
    let errors = f.state.checks(&mut || Vec::new());
    assert!(errors.iter().any(|e| e.is("BIRTH_STREAM_DIGEST_CHANGED")));
    assert!(f.state.revalidate(&mut || Vec::new()).is_err());
    std::fs::write(&path, original).unwrap();
    assert!(f.state.revalidate(&mut || Vec::new()).is_err());
}
