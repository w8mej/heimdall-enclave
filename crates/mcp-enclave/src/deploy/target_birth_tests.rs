//! SOFTWARE fixtures only. These construct private filesystem engines with a
//! synthetic trust anchor/owner and exclusion callback, never a native owner,
//! checked deployment, actual guard, provider, EX or installation authority.
//! Real runner checkout paths may exceed Darwin socket bounds; pure plan tests
//! validate actual routing independently from the rebased filesystem fixtures.
use super::*;
use std::{cell::Cell,os::unix::fs::{PermissionsExt,symlink}};

fn template()->DeploymentTarget {
    DeploymentTarget::parse(&serde_json::to_vec(&serde_json::json!({
        "version":1,"target_id":"birth-fixture","role":"dedicated-test","profile":"L2",
        "authority_config":"/template/support/custody-authority.json",
        "expected_artifacts_manifest":"/template/config/inventory.json",
        "codesign_pins_file":"/template/support/pins.json","signing_identity_mode":"local-pins",
        "broker":null,"shared_read_only_inputs":[],
        "layout":{"binary_dir":"/template/bin","custody_bundle":"/template/support/EnclaveCustody.app",
            "sandbox_dir":"/template/sandbox","socket_root":"/template/run","state_root":"/template/state",
            "audit_root":"/template/audit","cas_store_root":"/template/cas","staging_root":"/template/stage",
            "support_root":"/template/support","launchd_namespace":"com.enterprise.enclave.fixture",
            "mach_service":"com.enterprise.enclave.fixture.exception"}
    })).unwrap()).unwrap()
}
fn plan(target:&DeploymentTarget)->EnclaveResult<BirthPlan> {
    BirthPlan::build(target,Path::new("/template"),Path::new("/opt/enterprise/depot-firsttouch"),&[0x19;16])
}
fn no_authority(p:&BirthProgress) {
    assert!(!p.mutation_allowed&&!p.inactivity_proven&&!p.activation_allowed&&!p.installation_supported&&!p.qualified);
}
fn sync(file:&File)->EnclaveResult<()> {file.sync_all().map_err(|_|err!(EIO,"FIXTURE_SYNC"))}

struct Fixture {anchor:PathBuf,state:BirthState}
impl Fixture {
    fn new()->Self {
        let anchor=std::env::current_dir().unwrap().join(format!(".birth-fixture-{}",hex::encode(enclave_core::rng::bytes32())));
        std::fs::create_dir(&anchor).unwrap();
        std::fs::set_permissions(&anchor,std::fs::Permissions::from_mode(0o700)).unwrap();
        let original=plan(&template()).unwrap();
        let root=anchor.join(original.root.file_name().unwrap());
        // PRIVATE synthetic engine layout only: this is not another plan
        // constructor or a way to obtain the native capability. A runner's
        // arbitrarily long checkout must not force an out-of-repo trust anchor.
        let map=|p:&Path|root.join(p.strip_prefix(&original.root).unwrap());
        let target_bytes=String::from_utf8(original.bytes.clone()).unwrap()
            .replace(original.root.to_str().unwrap(),root.to_str().unwrap());
        let target=DeploymentTarget::parse(target_bytes.as_bytes()).unwrap();
        let planned=BirthPlan {root:root.clone(),target,descriptor:map(&original.descriptor),
            bytes:target_bytes.into_bytes(),seed_dirs:original.seed_dirs.iter().map(|p|map(p)).collect()};
        let owner=(unsafe {libc::geteuid()},unsafe {libc::getegid()});
        let protection=Protection {owner,native_acl:false};
        let path=CString::new(anchor.as_os_str().as_bytes()).unwrap();
        let fd=unsafe {libc::open(path.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)};
        assert!(fd>=0);
        let directory=Directory::capture(unsafe {File::from_raw_fd(fd)},None,false,protection).unwrap();
        let mut progress=BirthProgress::new();progress.root=Some(root);progress.descriptor=Some(planned.descriptor.clone());
        progress.target_id=Some(planned.target.target_id.clone());
        let state=BirthState {plan:planned,dirs:BTreeMap::from([(anchor.clone(),directory)]),files:BTreeMap::new(),
            protection,progress,poisoned:false,pending:None,private_load:None};
        Self {anchor,state}
    }
    fn root(&self)->PathBuf {self.state.plan.root.clone()}
    fn birth(&mut self)->Result<(),BirthFailure> {self.birth_with(&mut ||Vec::new(),&mut sync)}
    fn birth_with(&mut self,check:&mut impl FnMut()->Vec<EnclaveError>,
        sync:&mut impl FnMut(&File)->EnclaveResult<()>)->Result<(),BirthFailure> {
        let mut boundary=Vec::new();let root=self.root();
        let operation=self.state.create_directory(&root,check,&mut boundary,sync);
        let finals=self.state.checks(check);
        outcome(&mut self.state.progress,operation,boundary,finals)
    }
    fn seeds(&mut self)->Result<BirthProgress,BirthFailure> {self.state.prepare_seeds(&mut ||Vec::new(),&mut sync)}
}
impl Drop for Fixture {fn drop(&mut self){let _=std::fs::remove_dir_all(&self.anchor);}}

#[test]
fn plan_rebases_every_path_and_derives_valid_identities_from_nonce() {
    let source=template();let first=plan(&source).unwrap();
    let second=BirthPlan::build(&source,Path::new("/template"),Path::new("/opt/enterprise/depot-firsttouch"),&[0x92;16]).unwrap();
    assert_ne!(first.root,second.root);assert_ne!(first.target.target_id,second.target.target_id);
    assert_ne!(first.target.layout.launchd_namespace,second.target.layout.launchd_namespace);
    assert_ne!(first.target.layout.mach_service,second.target.layout.mach_service);
    assert_eq!(first.root.file_name().unwrap(),"19191919191919191919191919191919");
    assert_eq!(first.target.target_id,"ykft-19191919191919191919191919191919");
    assert!(first.target.layout.launchd_namespace.ends_with(".n19191919191919191919191919191919"));
    for path in roots(&first.target).into_iter().chain([first.target.authority_config.as_path(),
        first.target.expected_artifacts_manifest.as_path(),first.target.codesign_pins_file.as_path(),first.descriptor.as_path()]) {
        assert!(!below(path,&first.root).unwrap().as_os_str().is_empty());
    }
    assert!(DeploymentTarget::parse(&first.bytes).unwrap()==first.target);
    assert_eq!(first.descriptor,first.root.join(DESCRIPTOR));
    assert!(template()==source,"pure rebasing never changes caller template");
}
#[test]
fn every_raw_reference_must_be_a_strict_template_descendant() {
    for field in ["authority_config","expected_artifacts_manifest","codesign_pins_file","binary_dir",
        "custody_bundle","sandbox_dir","socket_root","state_root","audit_root","cas_store_root",
        "staging_root","support_root"] {
        for replacement in ["/foreign/unrelated","/template"] {
            let mut value=serde_json::to_value(template()).unwrap();
            if value.get(field).is_some(){value[field]=replacement.into();}else{value["layout"][field]=replacement.into();}
            let t:DeploymentTarget=serde_json::from_value(value).unwrap();
            assert!(plan(&t).is_err(),"{field}: {replacement}");
        }
    }
}
#[test]
fn role_profile_signing_broker_and_shared_input_scope_cannot_expand() {
    for variant in ["upgrade","l1","l3","team","shared"] {
        let mut t=template();
        match variant {
            "upgrade"=>t.role=DeploymentRole::ExistingUpgrade,
            "l1"=>t.profile=Profile::L1,
            "l3"=>t.profile=Profile::L3,
            "team"=>t.signing_identity_mode=DeploymentSigningMode::TeamId,
            _=>t.shared_read_only_inputs.push(t.authority_config.clone()),
        }
        assert!(plan(&t).is_err(),"{variant}");
    }
}
#[test]
fn descriptor_and_inventory_are_outside_every_release_mutation_domain() {
    for location in ["/template/support/inventory.json","/template/stage/inventory.json",
        "/template/config/deployment.json","/template/config"] {
        let mut t=template();t.expected_artifacts_manifest=location.into();assert!(plan(&t).is_err(),"{location}");
    }
    let mut t=template();t.layout.support_root="/template/config".into();
    t.layout.custody_bundle="/template/config/EnclaveCustody.app".into();
    assert!(plan(&t).is_err());
    let t=plan(&template()).unwrap();
    for path in roots(&t.target) {
        assert!(!overlaps(&t.descriptor,path).unwrap());
        assert!(!overlaps(&t.target.expected_artifacts_manifest,path).unwrap());
    }
}
#[test]
fn reserved_lock_and_seed_aliases_are_refused_case_insensitively() {
    let mut t=template();t.authority_config=Path::new("/template/support").join(STARTUP_LIFETIME_LEAF);
    assert!(plan(&t).is_err());
    t=template();t.authority_config="/template/CONFIG".into();assert!(plan(&t).is_err());
    t=template();t.layout.socket_root="/template/config/runtime".into();assert!(plan(&t).is_err());
}
#[test]
fn support_seed_may_parent_future_custody_bundle_but_cannot_prepare_payload_or_runtime() {
    let admitted=plan(&template()).unwrap();
    assert!(admitted.seed_dirs.contains(&admitted.target.layout.support_root));
    assert!(!admitted.seed_dirs.contains(&admitted.target.layout.custody_bundle));
    for field in ["binary_dir","sandbox_dir","socket_root","state_root","audit_root","cas_store_root"] {
        let mut value=serde_json::to_value(template()).unwrap();value["layout"][field]="/template/config/future".into();
        let t:DeploymentTarget=serde_json::from_value(value).unwrap();assert!(plan(&t).is_err(),"{field}");
    }
    let mut t=template();t.layout.support_root="/template/support/EnclaveCustody.app".into();
    assert!(plan(&t).is_err(),"support seed cannot itself be the custody bundle");
}
#[test]
fn darwin_socket_capacity_is_checked_even_on_linux_and_before_effects() {
    let t=template();let admitted=plan(&t).unwrap();
    assert!(admitted.target.intent_socket(u32::MAX-1).unwrap().as_os_str().as_bytes().len()<104);
    let error=BirthPlan::build(&t,Path::new("/template"),
        &PathBuf::from(format!("/{}","x".repeat(100))),&[0;16]).err().unwrap();
    assert!(error.is("BIRTH_DARWIN_SOCKET_PATH"));
}
#[test]
fn actual_created_root_is_private_original_inode_and_syncs_root_then_allocator() {
    let mut f=Fixture::new();let mut synced=Vec::new();
    f.birth_with(&mut ||Vec::new(),&mut |file|{synced.push(file.metadata().unwrap().ino());sync(file)}).unwrap();
    let m=std::fs::symlink_metadata(f.root()).unwrap();let ancestor=std::fs::metadata(&f.anchor).unwrap();
    assert_eq!(m.mode()&0o7777,0o700);assert_eq!((m.uid(),m.gid()),f.state.protection.owner);
    assert_eq!(synced,vec![m.ino(),ancestor.ino()]);
    assert_eq!(f.state.dirs[&f.root()].stamp.ino,m.ino());
    assert_eq!(f.state.dirs[&f.root()].links,m.nlink());
    assert_eq!(f.state.dirs[&f.anchor].links,ancestor.nlink());
    assert!(f.state.revalidate(&mut ||Vec::new()).unwrap().complete);no_authority(&f.state.progress);
}
#[test]
fn preexisting_directory_symlink_file_and_fifo_are_never_adopted_or_repaired() {
    for kind in ["directory","symlink","file","fifo"] {
        let mut f=Fixture::new();let root=f.root();let sentinel=f.anchor.join("sentinel");
        std::fs::write(&sentinel,b"keep").unwrap();
        match kind {
            "directory"=>std::fs::create_dir(&root).unwrap(),
            "symlink"=>symlink(&sentinel,&root).unwrap(),
            "fifo"=>{let path=CString::new(root.as_os_str().as_bytes()).unwrap();assert_eq!(unsafe{libc::mkfifo(path.as_ptr(),0o600)},0);},
            _=>std::fs::write(&root,b"foreign").unwrap(),
        }
        // Parent link count changes from fixture setup, not from production
        // adoption. Re-anchor only the explicit synthetic fixture observation.
        f.state.dirs.get_mut(&f.anchor).unwrap().links=std::fs::metadata(&f.anchor).unwrap().nlink();
        let before=std::fs::symlink_metadata(&root).unwrap();
        let error=f.birth_with(&mut ||Vec::new(),&mut |_|panic!("must not sync existing name")).unwrap_err();
        assert!(error.error.is("BIRTH_ALREADY_EXISTS"));assert_eq!(error.progress.existing_names,vec![root.clone()]);
        assert!(error.progress.created_directories.is_empty());
        let after=std::fs::symlink_metadata(root).unwrap();assert_eq!(FileStamp::of(&before).directory.ino,after.ino());
        assert_eq!((before.mode(),before.nlink(),before.len()),(after.mode(),after.nlink(),after.len()));
        assert_eq!(std::fs::read(&sentinel).unwrap(),b"keep");no_authority(&error.progress);
    }
}
#[test]
fn all_creation_boundaries_refuse_and_preserve_created_private_root() {
    let mut baseline=Fixture::new();let total=Cell::new(0);
    baseline.birth_with(&mut ||{total.set(total.get()+1);Vec::new()},&mut sync).unwrap();
    for fail_at in 1..=total.get() {
        let mut f=Fixture::new();let calls=Cell::new(0);
        let error=f.birth_with(&mut ||{calls.set(calls.get()+1);
            if calls.get()==fail_at {vec![err!(ESTALE,"FIXTURE_BOUNDARY")]}else{Vec::new()}},&mut sync).unwrap_err();
        assert!(!error.progress.complete);no_authority(&error.progress);
        if f.root().exists(){assert_eq!(std::fs::metadata(f.root()).unwrap().mode()&0o7777,0o700);}
        assert!(error.error.is("FIXTURE_BOUNDARY"));
    }
}
#[test]
fn root_and_allocator_sync_errors_preserve_original_error_and_all_final_failures() {
    for fail_at in [1,2] {
        let mut f=Fixture::new();let calls=Cell::new(0);let lost=Cell::new(false);
        let error=f.birth_with(&mut ||if lost.get(){vec![err!(ESTALE,"FIXTURE_GUARD"),err!(ESTALE,"FIXTURE_BINDING")]}else{Vec::new()},
            &mut |file| {calls.set(calls.get()+1);if calls.get()==fail_at {lost.set(true);Err(err!(EIO,"FIXTURE_ORIGINAL_SYNC"))}else{sync(file)}}).unwrap_err();
        assert!(error.error.is("FIXTURE_ORIGINAL_SYNC"));assert!(error.progress.uncertain_effects);
        assert!(error.boundary_errors.iter().any(|e|e.is("FIXTURE_GUARD")));
        assert!(error.final_errors.iter().any(|e|e.is("FIXTURE_BINDING")));
        assert_eq!(error.progress.synced.len(),fail_at-1);assert!(f.root().is_dir());no_authority(&error.progress);
    }
}
#[test]
fn exact_mode_root_replacement_is_rejected_and_owner_cannot_revive_after_restoration() {
    let mut f=Fixture::new();f.birth().unwrap();let original=f.state.dirs[&f.root()].stamp.ino;
    let moved=f.anchor.join("original");std::fs::rename(f.root(),&moved).unwrap();
    std::fs::create_dir(f.root()).unwrap();std::fs::set_permissions(f.root(),std::fs::Permissions::from_mode(0o700)).unwrap();
    let replacement=std::fs::metadata(f.root()).unwrap().ino();assert_ne!(original,replacement);
    assert!(f.state.revalidate(&mut ||Vec::new()).is_err());
    assert_eq!(f.state.dirs[&f.root()].file.metadata().unwrap().ino(),original);
    std::fs::remove_dir(f.root()).unwrap();std::fs::rename(moved,f.root()).unwrap();
    assert!(f.state.revalidate(&mut ||Vec::new()).unwrap_err().error.is("BIRTH_OWNER_POISONED"));
    assert!(f.state.prepare_seeds(&mut ||Vec::new(),&mut |_|panic!("poisoned owner cannot sync")).is_err());
    assert!(!f.state.plan.descriptor.exists());
}
#[test]
fn protection_link_count_and_descriptor_flag_drift_poison_without_repair() {
    for change in ["mode","links","cloexec","nonblock"] {
        let mut f=Fixture::new();f.birth().unwrap();let root=f.root();
        match change {
            "mode"=>std::fs::set_permissions(f.root(),std::fs::Permissions::from_mode(0o755)).unwrap(),
            "links"=>{f.state.dirs.get_mut(&root).unwrap().links+=1;}, // APFS-independent observed-count mismatch.
            "cloexec"=>assert_eq!(unsafe{libc::fcntl(f.state.dirs[&f.root()].file.as_raw_fd(),libc::F_SETFD,0)},0),
            _=>assert_eq!(unsafe{libc::fcntl(f.state.dirs[&f.root()].file.as_raw_fd(),libc::F_SETFL,0)},0),
        }
        let before=std::fs::metadata(f.root()).unwrap();assert!(f.state.revalidate(&mut ||Vec::new()).is_err());
        let after=std::fs::metadata(f.root()).unwrap();assert_eq!((before.ino(),before.mode(),before.nlink()),(after.ino(),after.mode(),after.nlink()));
        assert!(f.state.poisoned);no_authority(&f.state.progress);
    }
}
#[cfg(target_os="macos")]
#[test]
fn unrelated_child_creation_is_not_adopted_as_an_own_file_link_count_change() {
    let mut f=Fixture::new();f.birth().unwrap();let foreign=f.root().join("foreign-child");
    std::fs::create_dir(&foreign).unwrap();let before=std::fs::metadata(&foreign).unwrap();
    let error=f.seeds().unwrap_err();assert!(error.error.is("BIRTH_DIRECTORY_CHANGED"));
    assert!(error.progress.created_files.is_empty());assert!(!f.state.plan.descriptor.exists());
    let after=std::fs::metadata(foreign).unwrap();assert_eq!((before.dev(),before.ino(),before.mode()),(after.dev(),after.ino(),after.mode()));
    assert!(f.state.poisoned);no_authority(&error.progress);
}
#[test]
fn seed_preparation_creates_only_exact_inert_names_and_no_authority_or_runtime() {
    let mut f=Fixture::new();f.birth().unwrap();let p=f.seeds().unwrap();
    assert!(p.complete&&p.seeds_complete&&!p.uncertain_effects);no_authority(&p);
    let descriptor=&f.state.plan.descriptor;assert_eq!(std::fs::read(descriptor).unwrap(),f.state.plan.bytes);
    let dm=std::fs::metadata(descriptor).unwrap();assert_eq!((dm.mode()&0o7777,dm.nlink()),(0o644,1));
    let lease=f.state.plan.target.layout.support_root.join(STARTUP_LIFETIME_LEAF);let lm=std::fs::metadata(lease).unwrap();
    assert_eq!((lm.mode()&0o7777,lm.nlink(),lm.len()),(0o644,1,0));
    assert!(!f.root().join(STARTUP_LIFETIME_LEAF).exists(),"actors use the selected support directory, not the hidden ancestor");
    assert_eq!(p.created_files.len(),2);assert_eq!(p.created_directories.len(),4);
    for input in [&f.state.plan.target.authority_config,&f.state.plan.target.expected_artifacts_manifest,&f.state.plan.target.codesign_pins_file] {
        assert!(!input.exists());
    }
    let l=&f.state.plan.target.layout;
    for path in [&l.binary_dir,&l.custody_bundle,&l.sandbox_dir,&l.socket_root,&l.state_root,&l.audit_root,&l.cas_store_root] {assert!(!path.exists());}
    assert_eq!(std::fs::metadata(f.root()).unwrap().mode()&0o7777,0o700);
    f.state.revalidate(&mut ||Vec::new()).unwrap();
}
#[test]
fn preexisting_seed_is_refused_and_partial_names_survive_without_retry_or_cleanup() {
    let mut f=Fixture::new();f.birth().unwrap();let stage=f.state.plan.target.layout.staging_root.clone();
    std::fs::create_dir(&stage).unwrap();std::fs::set_permissions(&stage,std::fs::Permissions::from_mode(0o700)).unwrap();
    // Explicit fixture-only arrangement, before the actual seed transaction.
    let root=f.root();f.state.dirs.get_mut(&root).unwrap().links=std::fs::metadata(&root).unwrap().nlink();
    let original=std::fs::metadata(&stage).unwrap().ino();let error=f.seeds().unwrap_err();
    assert!(error.error.is("BIRTH_ALREADY_EXISTS"));assert!(error.progress.uncertain_effects&&!error.progress.complete);
    assert_eq!(std::fs::metadata(stage).unwrap().ino(),original);assert!(f.state.poisoned);
    assert!(!f.state.plan.descriptor.exists());assert!(root.join("config").is_dir());
}
#[test]
fn seed_sync_failure_preserves_completed_prefix_and_never_fabricates_inputs() {
    for fail_at in 1..=10 {
        let mut f=Fixture::new();f.birth().unwrap();let baseline=f.state.progress.synced.len();let calls=Cell::new(0);
        let error=f.state.prepare_seeds(&mut ||Vec::new(),&mut |file| {
            calls.set(calls.get()+1);if calls.get()==fail_at{Err(err!(EIO,"FIXTURE_SEED_SYNC"))}else{sync(file)}
        }).unwrap_err();
        assert!(error.error.is("FIXTURE_SEED_SYNC"));assert_eq!(error.progress.synced.len()-baseline,fail_at-1);
        assert!(error.progress.uncertain_effects&&!error.progress.complete);no_authority(&error.progress);
        assert!(!f.state.plan.target.authority_config.exists());assert!(!f.state.plan.target.expected_artifacts_manifest.exists());
        assert!(!f.state.plan.target.codesign_pins_file.exists());assert_eq!(std::fs::metadata(f.root()).unwrap().mode()&0o7777,0o700);
    }
}
#[test]
fn held_descriptor_and_zero_lease_replacements_are_not_adopted() {
    for seed in ["descriptor","lease"] {
        let mut f=Fixture::new();f.birth().unwrap();f.seeds().unwrap();
        let path=if seed=="descriptor"{f.state.plan.descriptor.clone()}else{f.state.plan.target.layout.support_root.join(STARTUP_LIFETIME_LEAF)};
        let held=f.state.files[&path].file.metadata().unwrap().ino();let backup=path.with_extension("original");
        let bytes=std::fs::read(&path).unwrap();let mode=std::fs::metadata(&path).unwrap().mode()&0o7777;
        std::fs::rename(&path,&backup).unwrap();std::fs::write(&path,&bytes).unwrap();
        std::fs::set_permissions(&path,std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(f.state.revalidate(&mut ||Vec::new()).is_err());assert_eq!(f.state.files[&path].file.metadata().unwrap().ino(),held);
        assert_ne!(std::fs::metadata(&path).unwrap().ino(),held);assert_eq!(std::fs::read(&path).unwrap(),bytes);assert!(backup.exists());
    }
}
#[test]
fn original_seed_descriptor_binding_is_checked_before_subsequent_effects() {
    let mut f=Fixture::new();f.birth().unwrap();let path=f.state.plan.descriptor.clone();let moved=path.with_extension("original");
    let changed=Cell::new(false);
    let error=f.state.prepare_seeds(&mut || {
        if path.exists()&&!changed.get() {
            changed.set(true);std::fs::rename(&path,&moved).unwrap();std::fs::write(&path,b"foreign").unwrap();
            std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o600)).unwrap();
        }Vec::new()
    },&mut sync).unwrap_err();
    assert!(changed.get());assert!(!error.progress.complete&&error.progress.uncertain_effects);
    assert_eq!(std::fs::read(path).unwrap(),b"foreign");assert_eq!(std::fs::read(moved).unwrap(),b"");
    assert!(!f.state.plan.target.layout.support_root.join(STARTUP_LIFETIME_LEAF).exists());
}
#[test]
fn drop_does_not_remove_or_expose_completed_or_partial_private_names() {
    let mut f=Fixture::new();f.birth().unwrap();f.seeds().unwrap();let root=f.root();
    let empty=BirthState {plan:plan(&template()).unwrap(),dirs:BTreeMap::new(),files:BTreeMap::new(),
        protection:Protection{owner:(0,0),native_acl:false},progress:BirthProgress::new(),poisoned:true,pending:None,private_load:None};
    let previous=std::mem::replace(&mut f.state,empty);
    drop(previous);assert!(root.join(DESCRIPTOR).is_file());assert_eq!(std::fs::metadata(root).unwrap().mode()&0o7777,0o700);
}
#[test]
fn native_entry_and_acl_inspection_have_no_nonmacos_fallback() {
    #[cfg(not(target_os="macos"))]
    {
        assert!(require_native_root().unwrap_err().is("BIRTH_NATIVE_ROOT_REQUIRED"));
        let f=Fixture::new();let file=&f.state.dirs[&f.anchor].file;
        assert!(no_extended_acl(file,Protection {owner:f.state.protection.owner,native_acl:true})
            .unwrap_err().is("BIRTH_NATIVE_ACL_REQUIRED"));
    }
    #[cfg(target_os="macos")]
    if unsafe{libc::geteuid()}!=0 {assert!(require_native_root().is_err());}
}

/// Actual Darwin ACL calls on ONLY this test's owned synthetic directory.
/// This neither constructs a native birth nor observes any production path.
#[cfg(target_os="macos")]
#[test]
fn darwin_acl_absence_and_presence_are_observed_on_own_synthetic_directory() {
    let f=Fixture::new();let file=&f.state.dirs[&f.anchor].file;
    let original=file.metadata().unwrap();let named=std::fs::symlink_metadata(&f.anchor).unwrap();
    assert!(named.is_dir());assert_eq!((named.dev(),named.ino(),named.uid()),
        (original.dev(),original.ino(),unsafe{libc::geteuid()}));
    let protection=Protection {owner:f.state.protection.owner,native_acl:true};
    use std::ffi::c_void;
    unsafe extern "C" {
        fn acl_init(count:libc::c_int)->*mut c_void;
        fn acl_create_entry(acl:*mut *mut c_void,entry:*mut *mut c_void)->libc::c_int;
        fn acl_set_tag_type(entry:*mut c_void,tag:libc::c_int)->libc::c_int;
        fn acl_set_qualifier(entry:*mut c_void,qualifier:*const c_void)->libc::c_int;
        fn acl_get_permset(entry:*mut c_void,perms:*mut *mut c_void)->libc::c_int;
        fn acl_add_perm(perms:*mut c_void,permission:libc::c_int)->libc::c_int;
        fn acl_set_fd_np(fd:libc::c_int,acl:*mut c_void,kind:libc::c_int)->libc::c_int;
        fn acl_free(object:*mut c_void)->libc::c_int;
        fn mbr_uid_to_uuid(uid:libc::uid_t,uuid:*mut u8)->libc::c_int;
    }
    struct FixtureAcl(*mut c_void);
    impl Drop for FixtureAcl {fn drop(&mut self){if !self.0.is_null(){unsafe{acl_free(self.0);}}}}
    let empty=FixtureAcl(unsafe{acl_init(0)});assert!(!empty.0.is_null());
    // Test-only empty ACL on the ORIGINAL owned fixture FD. Production has no
    // ACL repair/removal. Actual SDK: TYPE_EXTENDED=0x100, ENTRY_ALLOW=1,
    // READ_DATA/LIST_DIRECTORY=2; these are three different enum families.
    assert_eq!(unsafe{acl_set_fd_np(file.as_raw_fd(),empty.0,0x100)},0,
        "fixture empty ACL installation failed; no native ACL PASS");
    no_extended_acl(file,protection).unwrap();
    let mut uuid=[0u8;16];assert_eq!(unsafe {mbr_uid_to_uuid(libc::geteuid(),uuid.as_mut_ptr())},0,
        "fixture owner UUID resolution failed; no native ACL PASS");
    let mut allow=FixtureAcl(unsafe{acl_init(1)});assert!(!allow.0.is_null());
    let mut entry=std::ptr::null_mut();
    assert_eq!(unsafe{acl_create_entry(&mut allow.0,&mut entry)},0);assert!(!entry.is_null());
    assert_eq!(unsafe{acl_set_tag_type(entry,1)},0);
    assert_eq!(unsafe{acl_set_qualifier(entry,uuid.as_ptr().cast())},0);
    let mut perms=std::ptr::null_mut();assert_eq!(unsafe{acl_get_permset(entry,&mut perms)},0);assert!(!perms.is_null());
    assert_eq!(unsafe{acl_add_perm(perms,2)},0);
    assert_eq!(unsafe{acl_set_fd_np(file.as_raw_fd(),allow.0,0x100)},0,
        "fixture owner ACL installation failed; no native ACL PASS");
    assert!(no_extended_acl(file,protection).unwrap_err().is("BIRTH_EXTENDED_ACL_REFUSED"));
    let named=std::fs::symlink_metadata(&f.anchor).unwrap();assert_eq!((named.dev(),named.ino()),(original.dev(),original.ino()));
    assert_eq!(unsafe{acl_set_fd_np(file.as_raw_fd(),empty.0,0x100)},0);no_extended_acl(file,protection).unwrap();
}

fn pending_inventory(state:&BirthState)->Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "version":1,"kind":"depot-first-touch-artifact-inventory",
        "target_id":state.plan.target.target_id,"profile":"L2","signing_identity_mode":"local-pins",
        "deployment_config_sha256":hex::encode(Sha256::digest(&state.plan.bytes)),
        "source_git_commit":"a".repeat(40),"source_manifest_sha256":"b".repeat(64),
        "source_input_count":1,"external_provenance":"UNKNOWN",
        "staging_root":state.plan.target.layout.staging_root,"codesign_pins_sha256":"c".repeat(64),
        "files":[{"path":"bin/depot-enclave","sha256":"d".repeat(64),"size":1},
            {"path":"codesign-pins.json","sha256":"c".repeat(64),"size":1}]
    })).unwrap()
}
fn denial_path(state:&BirthState)->PathBuf {state.plan.target.layout.support_root.join(UPGRADE_INHIBITION_LEAF)}
#[test]
fn pending_denial_uses_exact_support_name_original_hashes_and_file_then_parent_sync() {
    let mut f=Fixture::new();f.birth().unwrap();f.seeds().unwrap();let raw=pending_inventory(&f.state);
    let path=denial_path(&f.state);let lease=f.state.plan.target.layout.support_root.join(STARTUP_LIFETIME_LEAF);
    let original_lease=std::fs::metadata(&lease).unwrap();let mut synced=Vec::new();
    let progress=f.state.prepare_denial(&raw,&mut ||Vec::new(),&mut |file|{
        synced.push(file.metadata().unwrap().is_dir());sync(file)
    }).unwrap();
    assert_eq!(synced,vec![false,true]);assert!(progress.denial_prepared&&progress.complete&&!progress.uncertain_effects);
    let bytes=std::fs::read(&path).unwrap();let value:serde_json::Value=serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value.as_object().unwrap().len(),5);assert_eq!(value["version"],1);
    assert_eq!(value["kind"],"depot-upgrade-start-inhibition");assert_eq!(value["target_id"],f.state.plan.target.target_id);
    assert_eq!(value["descriptor_sha256"],hex::encode(Sha256::digest(&f.state.plan.bytes)));
    assert_eq!(value["artifact_inventory_sha256"],hex::encode(Sha256::digest(&raw)));
    let m=std::fs::metadata(&path).unwrap();assert_eq!((m.uid(),m.gid()),f.state.protection.owner);
    assert_eq!((m.mode()&0o7777,m.nlink()),(0o600,1));assert_eq!(f.state.files[&path].file.metadata().unwrap().ino(),m.ino());
    let current_lease=std::fs::metadata(&lease).unwrap();assert_eq!(FileStamp::of(&original_lease).directory.ino,current_lease.ino());
    assert_eq!((current_lease.mode()&0o7777,current_lease.len(),current_lease.nlink()),(0o644,0,1));
    assert!(!f.root().join(UPGRADE_INHIBITION_LEAF).exists());no_authority(&progress);
    assert!(!f.state.plan.target.expected_artifacts_manifest.exists());assert!(!f.state.plan.target.codesign_pins_file.exists());
}
#[test]
fn pending_inventory_is_copied_once_and_cannot_rebind_or_import_as_authority() {
    let mut f=Fixture::new();f.birth().unwrap();f.seeds().unwrap();let mut raw=pending_inventory(&f.state);
    f.state.prepare_denial(&raw,&mut ||Vec::new(),&mut sync).unwrap();let original=raw.clone();raw.push(b' ');
    assert_eq!(f.state.pending.as_ref().unwrap().bytes,original);f.state.revalidate(&mut ||Vec::new()).unwrap();
    let path=denial_path(&f.state);let before=std::fs::read(&path).unwrap();
    let failure=f.state.prepare_denial(&raw,&mut ||Vec::new(),&mut |_|panic!("no repeated denial sync")).unwrap_err();
    assert!(failure.error.is("BIRTH_PENDING_ALREADY_PREPARED"));assert!(f.state.poisoned);
    assert_eq!(std::fs::read(path).unwrap(),before);no_authority(&failure.progress);
}
#[test]
fn pending_denial_requires_actual_seed_state_and_poisoned_refusal_cannot_resume() {
    let mut f=Fixture::new();f.birth().unwrap();let raw=pending_inventory(&f.state);
    let failure=f.state.prepare_denial(&raw,&mut ||Vec::new(),&mut sync).unwrap_err();
    assert!(failure.error.is("BIRTH_PENDING_SEEDS_REQUIRED"));assert!(!denial_path(&f.state).exists());
    assert!(f.state.poisoned);assert!(f.state.prepare_seeds(&mut ||Vec::new(),&mut sync).unwrap_err().error.is("BIRTH_OWNER_POISONED"));
}
#[test]
fn malformed_oversize_or_wrong_nonce_descriptor_and_staging_inventory_cannot_create_denial() {
    for variant in ["empty","oversize","schema","target","descriptor","stage"] {
        let mut f=Fixture::new();f.birth().unwrap();f.seeds().unwrap();let mut raw=pending_inventory(&f.state);
        match variant {
            "empty"=>raw.clear(),"oversize"=>raw=vec![b'x';1024*1024+1],"schema"=>raw=b"{}".to_vec(),
            field=>{let mut value:serde_json::Value=serde_json::from_slice(&raw).unwrap();
                match field {"target"=>value["target_id"]="foreign-target".into(),
                    "descriptor"=>value["deployment_config_sha256"]="0".repeat(64).into(),
                    _=>value["staging_root"]="/foreign/stage".into()}
                raw=serde_json::to_vec(&value).unwrap();},
        }
        let failure=f.state.prepare_denial(&raw,&mut ||Vec::new(),&mut |_|panic!("bad inventory cannot sync")).unwrap_err();
        assert!(!failure.progress.denial_prepared&&!denial_path(&f.state).exists());assert!(f.state.poisoned);
        no_authority(&failure.progress);
    }
}
#[test]
fn pending_marker_name_is_reserved_against_all_raw_template_input_aliases() {
    let mut t=template();t.authority_config=t.layout.support_root.join(UPGRADE_INHIBITION_LEAF);
    assert!(plan(&t).err().unwrap().is("BIRTH_RESERVED_NAME"));
    t=template();t.codesign_pins_file=t.layout.support_root.join(UPGRADE_INHIBITION_LEAF);
    assert!(plan(&t).err().unwrap().is("BIRTH_RESERVED_NAME"));
}
#[test]
fn every_preexisting_pending_name_type_is_refused_without_adoption_repair_or_sync() {
    for kind in ["exact","partial","directory","symlink","fifo"] {
        let mut f=Fixture::new();f.birth().unwrap();f.seeds().unwrap();let raw=pending_inventory(&f.state);
        let path=denial_path(&f.state);
        match kind {
            "exact"=>std::fs::write(&path,PendingInventory::new(&f.state.plan,&raw).unwrap().marker_bytes(&f.state.plan).unwrap()).unwrap(),
            "partial"=>std::fs::write(&path,b"{").unwrap(),"directory"=>std::fs::create_dir(&path).unwrap(),
            "symlink"=>symlink(f.root().join("missing"),&path).unwrap(),
            _=>{let leaf=CString::new(path.as_os_str().as_bytes()).unwrap();assert_eq!(unsafe{libc::mkfifo(leaf.as_ptr(),0o600)},0);},
        }
        // Explicit synthetic preexisting-name setup, not production adoption.
        let parent=path.parent().unwrap();f.state.dirs.get_mut(parent).unwrap().links=std::fs::metadata(parent).unwrap().nlink();
        let before=std::fs::symlink_metadata(&path).unwrap();
        let failure=f.state.prepare_denial(&raw,&mut ||Vec::new(),&mut |_|panic!("foreign denial cannot sync")).unwrap_err();
        assert!(failure.error.is("BIRTH_ALREADY_EXISTS"));let after=std::fs::symlink_metadata(&path).unwrap();
        assert_eq!((before.ino(),before.mode(),before.nlink(),before.len()),(after.ino(),after.mode(),after.nlink(),after.len()));
        assert!(!failure.progress.denial_prepared&&f.state.poisoned);no_authority(&failure.progress);
    }
}
#[test]
fn pending_creation_refuses_at_every_boundary_and_preserves_any_partial_denial() {
    let mut baseline=Fixture::new();baseline.birth().unwrap();baseline.seeds().unwrap();let raw=pending_inventory(&baseline.state);
    let count=Cell::new(0);baseline.state.prepare_denial(&raw,&mut ||{count.set(count.get()+1);Vec::new()},&mut sync).unwrap();
    for fail_at in 1..=count.get() {
        let mut f=Fixture::new();f.birth().unwrap();f.seeds().unwrap();let raw=pending_inventory(&f.state);let calls=Cell::new(0);
        let failure=f.state.prepare_denial(&raw,&mut ||{calls.set(calls.get()+1);
            if calls.get()==fail_at{vec![err!(ESTALE,"FIXTURE_PENDING_BOUNDARY")]}else{Vec::new()}},&mut sync).unwrap_err();
        assert!(failure.error.is("FIXTURE_PENDING_BOUNDARY"));assert!(!failure.progress.complete&&f.state.poisoned);
        if let Ok(m)=std::fs::symlink_metadata(denial_path(&f.state)){assert!(m.is_file());assert_eq!(m.mode()&0o077,0);}
        assert_eq!(std::fs::metadata(f.root()).unwrap().mode()&0o7777,0o700);no_authority(&failure.progress);
    }
}
#[test]
fn pending_sync_failure_retains_original_and_all_final_errors_with_durable_prefix() {
    for fail_at in [1,2] {
        let mut f=Fixture::new();f.birth().unwrap();f.seeds().unwrap();let raw=pending_inventory(&f.state);
        let old_synced=f.state.progress.synced.len();let calls=Cell::new(0);let lost=Cell::new(false);
        let failure=f.state.prepare_denial(&raw,&mut ||if lost.get(){vec![err!(ESTALE,"FIXTURE_PENDING_GUARD"),err!(ESTALE,"FIXTURE_PENDING_CONTEXT")]}else{Vec::new()},
            &mut |file|{calls.set(calls.get()+1);if calls.get()==fail_at{lost.set(true);Err(err!(EIO,"FIXTURE_PENDING_SYNC"))}else{sync(file)}}).unwrap_err();
        assert!(failure.error.is("FIXTURE_PENDING_SYNC"));assert_eq!(failure.progress.synced.len()-old_synced,fail_at-1);
        assert!(failure.boundary_errors.iter().any(|e|e.is("FIXTURE_PENDING_GUARD")));
        assert!(failure.final_errors.iter().any(|e|e.is("FIXTURE_PENDING_CONTEXT")));
        assert!(!failure.progress.denial_prepared&&failure.progress.uncertain_effects);
        let path=denial_path(&f.state);assert_eq!(std::fs::read(&path).unwrap(),f.state.pending.as_ref().unwrap().marker_bytes(&f.state.plan).unwrap());
        assert!(f.state.files.contains_key(&path));no_authority(&failure.progress);
    }
}
#[test]
fn exact_pending_marker_replacement_is_not_adopted_and_poison_cannot_revive() {
    let mut f=Fixture::new();f.birth().unwrap();f.seeds().unwrap();let raw=pending_inventory(&f.state);
    f.state.prepare_denial(&raw,&mut ||Vec::new(),&mut sync).unwrap();let path=denial_path(&f.state);let moved=path.with_extension("original");
    let original=f.state.files[&path].file.metadata().unwrap().ino();let bytes=std::fs::read(&path).unwrap();
    std::fs::rename(&path,&moved).unwrap();std::fs::write(&path,&bytes).unwrap();
    std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(f.state.revalidate(&mut ||Vec::new()).is_err());assert_eq!(f.state.files[&path].file.metadata().unwrap().ino(),original);
    assert_ne!(std::fs::metadata(&path).unwrap().ino(),original);assert_eq!(std::fs::read(&path).unwrap(),bytes);
    std::fs::remove_file(&path).unwrap();std::fs::rename(&moved,&path).unwrap();
    assert!(f.state.revalidate(&mut ||Vec::new()).unwrap_err().error.is("BIRTH_OWNER_POISONED"));
}
