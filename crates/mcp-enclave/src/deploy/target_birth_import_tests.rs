//! Synthetic public-byte/private-engine software fixtures only. These do NOT
//! construct UnadmittedBirthSources, a native birth owner, actual guard, checked
//! target, issuer authority or installed state. Source-owner/full-hash/guard
//! construction remains separate native acceptance; no callbacks are added to
//! the production source interface for these tests.
use super::*;
use std::{cell::Cell, os::unix::fs::{PermissionsExt, symlink}};
use serde_json::{json, Value};

fn sync(file: &File) -> EnclaveResult<()> { file.sync_all().map_err(|_|err!(EIO,"FIXTURE_SYNC")) }
fn json_bytes(value: Value) -> Vec<u8> { serde_json::to_vec(&value).unwrap() }
fn template() -> DeploymentTarget {
    DeploymentTarget::parse(&json_bytes(json!({"version":1,"target_id":"import-fixture",
        "role":"dedicated-test","profile":"L2","signing_identity_mode":"local-pins",
        "authority_config":"/template/support/custody.json","expected_artifacts_manifest":"/template/config/inventory.json",
        "codesign_pins_file":"/template/support/pins.json","broker":null,"shared_read_only_inputs":[],
        "layout":{"binary_dir":"/template/bin","custody_bundle":"/template/support/Custody.app",
            "sandbox_dir":"/template/sandbox","socket_root":"/template/run","state_root":"/template/state",
            "audit_root":"/template/audit","cas_store_root":"/template/cas","staging_root":"/template/stage",
            "support_root":"/template/support","launchd_namespace":"com.depot.importfixture",
            "mach_service":"com.depot.importfixture.exception"}}))).unwrap()
}
fn inventory(plan: &BirthPlan, pins: &[u8]) -> Vec<u8> {
    let hash = hex::encode(Sha256::digest(pins));
    json_bytes(json!({"version":1,"kind":"depot-first-touch-artifact-inventory",
        "target_id":plan.target.target_id,"profile":plan.target.profile,"signing_identity_mode":plan.target.signing_identity_mode,
        "deployment_config_sha256":hex::encode(Sha256::digest(&plan.bytes)),"source_git_commit":"a".repeat(40),
        "source_manifest_sha256":"b".repeat(64),"source_input_count":1,"codesign_pins_sha256":hash,
        "staging_root":plan.target.layout.staging_root,"external_provenance":"UNKNOWN",
        "files":[{"path":"bin/depot-enclave","sha256":"c".repeat(64),"size":100},
            {"path":"codesign-pins.json","sha256":hash,"size":pins.len()}]}))
}
fn public_inputs(plan: &BirthPlan) -> PublicInputs {
    let support = &plan.target.layout.support_root;
    let pins = json_bytes(json!({"v":1,"mode":"local-pins","pins":{"com.enterprise.enclave.ctl":["ab".repeat(20)]}}));
    let manifest = json_bytes(json!({"v":1,"profile":"L2",
        "asset_policy_file":support.join("public/policy.json"),
        "asset_policy_key_file":support.join("public/keys/policy.key"),
        "asset_inventory_key_file":support.join("public/keys/inventory.key"),
        "envelope_policy_key_file":support.join("public/keys/envelope.key"),
        "asset_host_id":"synthetic-host","asset_id":"synthetic-asset","asset_custodian_id":"synthetic-custodian",
        "envelope_policy_subject":"synthetic-host","envelope_policy_namespace":"synthetic-namespace"}));
    PublicInputs { bytes: BTreeMap::from([
        (BirthSourceRole::Inventory,inventory(plan,&pins)),
        (BirthSourceRole::CustodyManifest,manifest),
        (BirthSourceRole::CustodyPolicy,b"{\"unadmitted_public_policy_fixture\":true}".to_vec()),
        (BirthSourceRole::PolicyIssuerKey,"01".repeat(32).into_bytes()),
        (BirthSourceRole::InventoryIssuerKey,"02".repeat(32).into_bytes()),
        (BirthSourceRole::EnvelopeIssuerKey,"03".repeat(32).into_bytes()),
        (BirthSourceRole::Staged(STAGED_PINS.into()),pins),
    ]) }
}
fn edit_manifest(inputs: &mut PublicInputs, field: &str, value: Value) {
    let bytes = inputs.bytes.get_mut(&BirthSourceRole::CustodyManifest).unwrap();
    let mut manifest: Value = serde_json::from_slice(bytes).unwrap();
    manifest[field] = value; *bytes = json_bytes(manifest);
}
fn denied<T>(value: EnclaveResult<T>, code: &str) {
    assert!(value.err().expect("must refuse").is(code),"expected {code}");
}
fn no_authority(progress: &BirthProgress) {
    assert!(!progress.mutation_allowed && !progress.inactivity_proven && !progress.activation_allowed
        && !progress.installation_supported && !progress.qualified);
}
struct Fixture {anchor: PathBuf, state: BirthState, inputs: PublicInputs}
impl Fixture {
    fn new() -> Self {
        let anchor = std::env::current_dir().unwrap().join(format!(".birth-import-fixture-{}",hex::encode(enclave_core::rng::bytes32())));
        std::fs::create_dir(&anchor).unwrap();
        std::fs::set_permissions(&anchor,std::fs::Permissions::from_mode(0o700)).unwrap();
        let original = BirthPlan::build(&template(),Path::new("/template"),Path::new("/birth-import"),&[0x41;16]).unwrap();
        let root = anchor.join(original.root.file_name().unwrap());
        let map = |p: &Path|root.join(p.strip_prefix(&original.root).unwrap());
        // Test-only rebase avoids treating a long checkout path as a native
        // Darwin socket-qualified birth constructor. No native owner exists.
        let raw = String::from_utf8(original.bytes.clone()).unwrap()
            .replace(original.root.to_str().unwrap(),root.to_str().unwrap()).into_bytes();
        let plan = BirthPlan {root:root.clone(),target:DeploymentTarget::parse(&raw).unwrap(),
            descriptor:map(&original.descriptor),bytes:raw,seed_dirs:original.seed_dirs.iter().map(|p|map(p)).collect()};
        let inputs = public_inputs(&plan);
        let protection = Protection {owner:(unsafe{libc::geteuid()},unsafe{libc::getegid()}),native_acl:false};
        let path = CString::new(anchor.as_os_str().as_bytes()).unwrap();
        let fd = unsafe{libc::open(path.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)};
        assert!(fd>=0);
        let directory = Directory::capture(unsafe{File::from_raw_fd(fd)},None,false,protection).unwrap();
        let mut progress = BirthProgress::new(); progress.root=Some(root.clone());
        progress.descriptor=Some(plan.descriptor.clone());progress.target_id=Some(plan.target.target_id.clone());
        let mut state = BirthState {plan,dirs:BTreeMap::from([(anchor.clone(),directory)]),files:BTreeMap::new(),
            protection,progress,poisoned:false,pending:None,private_load:None};
        state.create_directory(&root,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();
        state.prepare_seeds(&mut||Vec::new(),&mut sync).unwrap();
        state.prepare_denial(inputs.get(&BirthSourceRole::Inventory).unwrap(),&mut||Vec::new(),&mut sync).unwrap();
        Self {anchor,state,inputs}
    }
    fn plan(&self) -> EnclaveResult<InitialInputPlan> { InitialInputPlan::build(&self.state,&self.inputs) }
    fn apply(&mut self) -> EnclaveResult<()> {
        let plan = self.plan()?;
        self.state.create_initial_inputs(&plan,&self.inputs,&mut||Vec::new(),&mut Vec::new(),&mut sync)
    }
    fn observe_fixture_setup_links(&mut self) {
        // Only synthetic fixture setup, never a production adoption path.
        for directory in self.state.dirs.values_mut() { directory.links=directory.file.metadata().unwrap().nlink(); }
    }
}
impl Drop for Fixture { fn drop(&mut self) { let _=std::fs::remove_dir_all(&self.anchor); } }

#[test]
fn pure_plan_closes_exact_eight_destinations_without_touching_files_or_granting_authority() {
    let f=Fixture::new();let before=(f.state.dirs.len(),f.state.files.len(),f.state.progress.created_files.clone());
    let plan=f.plan().unwrap();assert_eq!(plan.files.len(),8);
    assert_eq!(before,(f.state.dirs.len(),f.state.files.len(),f.state.progress.created_files.clone()));
    let target=&f.state.plan.target;
    assert_eq!(plan.files.iter().filter(|p|p.role==BirthSourceRole::Staged(STAGED_PINS.into())).count(),2);
    for file in &plan.files {
        let expected=if file.destination==target.layout.staging_root.join(STAGED_PINS){0o600}else{0o644};
        assert_eq!(file.destination_role.mode(),expected);
    }
    let pins=plan.files.iter().filter(|p|p.role==BirthSourceRole::Staged(STAGED_PINS.into())).collect::<Vec<_>>();
    assert!(pins.iter().any(|p|p.destination_role==InitialControlRole::StagedPins));
    assert!(pins.iter().any(|p|p.destination_role==InitialControlRole::SelectedPins));
    for path in [&target.expected_artifacts_manifest,&target.authority_config,&target.codesign_pins_file,
        &target.layout.staging_root.join(STAGED_PINS)] {
        assert_eq!(plan.files.iter().filter(|p|&p.destination==path).count(),1);
        assert!(!path.exists());
    }
    for directory in &plan.directories { below(directory,&f.state.plan.root).unwrap(); }
    assert!(f.state.progress.denial_prepared);no_authority(&f.state.progress);
}

#[test]
fn exact_pending_inventory_pin_bytes_role_set_and_small_public_bounds_are_mandatory() {
    let mut f=Fixture::new();
    f.inputs.bytes.get_mut(&BirthSourceRole::Inventory).unwrap().push(b' ');
    denied(f.plan(),"BIRTH_IMPORT_PENDING_INVENTORY");
    let mut f=Fixture::new();f.inputs.bytes.get_mut(&BirthSourceRole::Staged(STAGED_PINS.into())).unwrap().push(b' ');
    denied(f.plan(),"BIRTH_IMPORT_PINS_BINDING");
    let mut f=Fixture::new();f.inputs.bytes.remove(&BirthSourceRole::InventoryIssuerKey);
    denied(f.plan(),"BIRTH_IMPORT_SOURCE_SET");
    let mut f=Fixture::new();f.inputs.bytes.insert(BirthSourceRole::Staged("bin/depot-enclave".into()),b"never import code".to_vec());
    denied(f.plan(),"BIRTH_IMPORT_SOURCE_SET");
    for bytes in [Vec::new(),vec![0;MAX_INPUT_BYTES+1]] {
        let mut f=Fixture::new();f.inputs.bytes.insert(BirthSourceRole::CustodyPolicy,bytes);
        denied(f.plan(),"BIRTH_IMPORT_SOURCE_BOUND");
    }
}

#[test]
fn real_manifest_schema_profile_and_all_destination_boundaries_precede_effects() {
    let mut f=Fixture::new();edit_manifest(&mut f.inputs,"profile",json!("L3"));
    assert!(f.plan().is_err());
    let f=Fixture::new();let root=f.state.plan.root.clone();let support=f.state.plan.target.layout.support_root.clone();
    let mut prohibited=vec![PathBuf::from("/outside/issuer.key"),root.clone(),f.state.plan.descriptor.clone(),
        f.state.plan.target.expected_artifacts_manifest.clone(),f.state.plan.target.authority_config.clone(),
        f.state.plan.target.codesign_pins_file.clone(),f.state.plan.target.layout.staging_root.join("issuer.key")];
    prohibited.extend(fixed_support_roles(&f.state.plan.target).into_iter());
    prohibited.extend([&f.state.plan.target.layout.binary_dir,&f.state.plan.target.layout.custody_bundle,
        &f.state.plan.target.layout.sandbox_dir,&f.state.plan.target.layout.socket_root,&f.state.plan.target.layout.state_root,
        &f.state.plan.target.layout.audit_root,&f.state.plan.target.layout.cas_store_root].into_iter().map(|p|p.join("issuer.key")));
    for path in prohibited {
        let mut inputs=public_inputs(&f.state.plan);edit_manifest(&mut inputs,"asset_policy_key_file",json!(path));
        assert!(InitialInputPlan::build(&f.state,&inputs).is_err(),"{}",path.display());
    }
    let mut inputs=public_inputs(&f.state.plan);
    edit_manifest(&mut inputs,"asset_policy_key_file",json!(support.join("public/../issuer.key")));
    assert!(InitialInputPlan::build(&f.state,&inputs).is_err());
    assert_eq!(f.state.files.len(),3,"only descriptor, lifetime and denial seeds exist");
}

#[test]
fn case_aliases_ancestor_roles_and_future_payload_parent_directories_are_refused() {
    let f=Fixture::new();let support=&f.state.plan.target.layout.support_root;
    for (a,b) in [(support.join("public/SAME.key"),support.join("public/same.key")),
        (support.join("public/issuer"),support.join("public/issuer/child.key"))] {
        let mut inputs=public_inputs(&f.state.plan);
        edit_manifest(&mut inputs,"asset_policy_key_file",json!(a));
        edit_manifest(&mut inputs,"asset_inventory_key_file",json!(b));
        denied(InitialInputPlan::build(&f.state,&inputs),"BIRTH_IMPORT_DESTINATION_ALIAS");
    }
    // Distinct leaf names cannot conceal case-aliased new parent directories.
    let mut inputs=public_inputs(&f.state.plan);
    edit_manifest(&mut inputs,"asset_policy_key_file",json!(support.join("public/Keys/policy.key")));
    edit_manifest(&mut inputs,"asset_inventory_key_file",json!(support.join("public/keys/inventory.key")));
    denied(InitialInputPlan::build(&f.state,&inputs),"BIRTH_IMPORT_DIRECTORY_ALIAS");
    let mut inputs=public_inputs(&f.state.plan);
    edit_manifest(&mut inputs,"asset_policy_file",json!(support.join("Public/policy.json")));
    denied(InitialInputPlan::build(&f.state,&inputs),"BIRTH_IMPORT_DIRECTORY_ALIAS");
    // Match every original cached directory's exact spelling too; a new CONFIG
    // path must never become a second name for the retained config parent.
    let mut inputs=public_inputs(&f.state.plan);
    edit_manifest(&mut inputs,"asset_policy_key_file",json!(f.state.plan.root.join("CONFIG/policy.key")));
    denied(InitialInputPlan::build(&f.state,&inputs),"BIRTH_IMPORT_DIRECTORY_ALIAS");
    // A new common parent of future browser code cannot be prepared through a
    // seemingly disjoint sibling policy file in the same directory.
    let mut inputs=public_inputs(&f.state.plan);
    edit_manifest(&mut inputs,"asset_policy_key_file",json!(support.join("browser/issuer.key")));
    denied(InitialInputPlan::build(&f.state,&inputs),"BIRTH_IMPORT_RESERVED_DIRECTORY");
}

#[test]
fn real_root_ancestry_key_is_not_a_false_alias_of_strict_nonce_parents() {
    let mut f=Fixture::new();
    // Production caches the real read-only "/" ancestry descriptor. This pure
    // plan test adds that actual root entry without constructing a native
    // birth owner/guard or running the filesystem mutation engine against it.
    let fd=unsafe{libc::open(c"/".as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)};
    assert!(fd>=0);
    let directory=Directory::capture(unsafe{File::from_raw_fd(fd)},None,false,
        Protection {owner:(0,0),native_acl:false}).unwrap();
    f.state.dirs.insert(PathBuf::from("/"),directory);
    f.plan().unwrap();
}

#[test]
fn missing_denial_pending_drift_and_total_directory_budget_refuse_before_mutation() {
    let mut f=Fixture::new();f.state.progress.denial_prepared=false;
    denied(f.plan(),"BIRTH_IMPORT_DENIAL_REQUIRED");
    let mut f=Fixture::new();f.state.pending.as_mut().unwrap().inventory_sha256="00".repeat(32);
    denied(f.plan(),"BIRTH_PENDING_BINDING_CHANGED");
    let mut f=Fixture::new();let support=f.state.plan.target.layout.support_root.clone();
    let mut policy=support.clone();let mut key=support;
    for index in 0..48 {policy.push(format!("p{index}"));key.push(format!("k{index}"));}
    edit_manifest(&mut f.inputs,"asset_policy_file",json!(policy.join("policy.json")));
    edit_manifest(&mut f.inputs,"asset_policy_key_file",json!(key.join("key")));
    let before=f.state.progress.attempted.clone();
    denied(f.plan(),"BIRTH_DIRECTORY_LIMIT");assert_eq!(f.state.progress.attempted,before);
}

#[test]
fn same_parent_engine_creates_exact_control_modes_and_two_distinct_pin_inodes_then_refuses_repeat() {
    let mut f=Fixture::new();let plan=f.plan().unwrap();
    let original=f.state.files.iter().map(|(p,s)|(p.clone(),FileStamp::of(&s.file.metadata().unwrap()),
        s.file.as_raw_fd(),s.bytes.clone())).collect::<Vec<_>>();
    f.apply().unwrap();
    for file in &plan.files {
        let bytes=std::fs::read(&file.destination).unwrap();assert_eq!(bytes,f.inputs.get(&file.role).unwrap());
        let metadata=std::fs::symlink_metadata(&file.destination).unwrap();
        let expected=if file.destination==f.state.plan.target.layout.staging_root.join(STAGED_PINS){0o600}else{0o644};
        assert_eq!(metadata.mode()&0o7777,expected);assert_eq!(metadata.nlink(),1);
        assert_eq!((metadata.uid(),metadata.gid()),f.state.protection.owner);
        assert!(f.state.progress.synced.contains(&file.destination));
        assert!(f.state.progress.synced.contains(&file.destination.parent().unwrap().to_owned()));
    }
    let staged=std::fs::metadata(f.state.plan.target.layout.staging_root.join(STAGED_PINS)).unwrap();
    let selected=std::fs::metadata(&f.state.plan.target.codesign_pins_file).unwrap();
    assert_ne!((staged.dev(),staged.ino()),(selected.dev(),selected.ino()));
    assert_eq!(std::fs::read(f.state.plan.target.layout.staging_root.join(STAGED_PINS)).unwrap(),
        std::fs::read(&f.state.plan.target.codesign_pins_file).unwrap());
    assert_eq!(f.state.files.len(),11);
    for (path,seed) in &f.state.files {
        let expected=if path==&f.state.plan.target.layout.support_root.join(UPGRADE_INHIBITION_LEAF)
            ||path==&f.state.plan.target.layout.staging_root.join(STAGED_PINS){0o600}else{0o644};
        assert_eq!(seed.file.metadata().unwrap().mode()&0o7777,expected);assert_eq!(seed.access,libc::O_RDONLY);
        assert!(seed.stamp==FileStamp::of(&seed.file.metadata().unwrap()));
    }
    for (path,directory) in &f.state.dirs {if path.starts_with(&f.state.plan.root){
        assert!(directory.private);assert_eq!(directory.file.metadata().unwrap().mode()&0o7777,0o700);
    }}
    for (path,stamp,fd,bytes) in original {
        let seed=&f.state.files[&path];assert!(FileStamp::of(&std::fs::symlink_metadata(&path).unwrap())==stamp);
        assert!(seed.stamp==stamp);assert_eq!(seed.file.as_raw_fd(),fd);
        assert_eq!(std::fs::read(&path).unwrap(),bytes);
    }
    for root in [&f.state.plan.target.layout.binary_dir,&f.state.plan.target.layout.custody_bundle,
        &f.state.plan.target.layout.sandbox_dir,&f.state.plan.target.layout.socket_root,&f.state.plan.target.layout.state_root,
        &f.state.plan.target.layout.audit_root,&f.state.plan.target.layout.cas_store_root] {assert!(!root.exists());}
    denied(f.plan(),"BIRTH_IMPORT_ALREADY_PREPARED");
    f.state.revalidate(&mut||Vec::new()).unwrap();no_authority(&f.state.progress);
}

#[test]
fn preexisting_foreign_file_symlink_fifo_and_input_parent_are_never_adopted_or_repaired() {
    for kind in ["file","symlink","fifo","parent"] {
        let mut f=Fixture::new();let target=&f.state.plan.target;
        let collision=if kind=="parent"{target.layout.support_root.join("public")}else{target.codesign_pins_file.clone()};
        let sentinel=f.anchor.join("sentinel");std::fs::write(&sentinel,b"untouched").unwrap();
        match kind {
            "symlink"=>symlink(&sentinel,&collision).unwrap(),
            "fifo"=>{let path=CString::new(collision.as_os_str().as_bytes()).unwrap();assert_eq!(unsafe{libc::mkfifo(path.as_ptr(),0o600)},0);},
            "parent"=>std::fs::create_dir(&collision).unwrap(),
            _=>std::fs::write(&collision,b"foreign").unwrap(),
        }
        f.observe_fixture_setup_links();
        let before=std::fs::symlink_metadata(&collision).unwrap();
        denied(f.apply(),"BIRTH_ALREADY_EXISTS");
        let after=std::fs::symlink_metadata(&collision).unwrap();
        assert_eq!((before.dev(),before.ino(),before.mode(),before.len()),(after.dev(),after.ino(),after.mode(),after.len()));
        assert_eq!(std::fs::read(sentinel).unwrap(),b"untouched");
        assert!(f.state.progress.existing_names.contains(&collision));no_authority(&f.state.progress);
    }
}

#[test]
fn sync_refusal_retains_original_partial_names_without_creating_later_inputs() {
    let mut f=Fixture::new();let plan=f.plan().unwrap();let prior=f.state.progress.created_files.clone();
    let mut observed=Vec::new();let calls=Cell::new(0);
    let result=f.state.create_initial_inputs(&plan,&f.inputs,&mut||Vec::new(),&mut observed,
        &mut|_|{calls.set(calls.get()+1);Err(err!(EIO,"FIXTURE_IMPORT_SYNC"))});
    denied(result,"FIXTURE_IMPORT_SYNC");assert_eq!(calls.get(),1);
    assert_eq!(f.state.progress.created_files,prior);
    assert!(f.state.progress.uncertain_effects);
    assert!(f.state.progress.created_directories.iter().all(|p|p.exists()));
    assert!(plan.files.iter().all(|f|!f.destination.exists()));no_authority(&f.state.progress);
}

#[test]
fn guard_loss_after_exclusive_creation_stops_before_writes_and_preserves_all_observed_errors() {
    let mut f=Fixture::new();let plan=f.plan().unwrap();let inventory=f.state.plan.target.expected_artifacts_manifest.clone();
    let mut observed=Vec::new();let finals_called=Cell::new(0);
    let mut check=||{if inventory.exists(){finals_called.set(finals_called.get()+1);vec![err!(ESTALE,"FIXTURE_IMPORT_GUARD_LOST")]}else{Vec::new()}};
    let result=f.state.create_initial_inputs(&plan,&f.inputs,&mut check,&mut observed,&mut sync);
    denied(result,"FIXTURE_IMPORT_GUARD_LOST");
    let finals=f.state.checks(&mut check);
    assert!(observed.iter().any(|e|e.is("FIXTURE_IMPORT_GUARD_LOST")));
    assert!(finals.iter().filter(|e|e.is("FIXTURE_IMPORT_GUARD_LOST")).count()>=2);
    assert!(finals_called.get()>=3);assert_eq!(std::fs::metadata(&inventory).unwrap().len(),0);
    assert!(plan.files.iter().filter(|p|p.destination!=inventory).all(|p|!p.destination.exists()));
    assert!(f.state.progress.created_files.contains(&inventory));no_authority(&f.state.progress);
}

#[test]
fn retained_imported_content_replacement_is_terminal_even_after_original_bytes_are_restored() {
    let mut f=Fixture::new();f.apply().unwrap();let path=f.state.plan.target.codesign_pins_file.clone();
    let original=std::fs::read(&path).unwrap();std::fs::write(&path,b"substituted").unwrap();
    assert!(f.state.revalidate(&mut||Vec::new()).is_err());assert!(f.state.poisoned);
    std::fs::write(&path,original).unwrap();
    let failure=f.state.revalidate(&mut||Vec::new()).unwrap_err();assert!(failure.error.is("BIRTH_OWNER_POISONED"));
    assert!(f.state.progress.denial_prepared);no_authority(&failure.progress);
}
