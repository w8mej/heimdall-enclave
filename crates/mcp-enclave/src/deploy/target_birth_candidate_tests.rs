//! Tests for the nonauthority original-readonly-view seam only. No fake
//! HostMaintenanceGuard, NativeDedicatedBirth, checked target, accounts,
//! SoftwareApproval, native verifier or successful candidate is constructed.
//! Full consuming-owner acceptance requires genuine native authority/payload.
use super::*;
use serde_json::{json,Value};
use std::os::unix::fs::{OpenOptionsExt,PermissionsExt};
fn bytes(v:Value)->Vec<u8>{serde_json::to_vec(&v).unwrap()}
fn sync(f:&File)->EnclaveResult<()>{f.sync_all().map_err(|_|err!(EIO,"CANDIDATE_FIXTURE_SYNC"))}
fn denied<T>(value:EnclaveResult<T>,reason:&str){let error=value.err().expect("must refuse");assert!(error.is(reason),"expected {reason}, got {}",error.reason);}
fn template()->DeploymentTarget {
    DeploymentTarget::parse(&bytes(json!({"version":1,"target_id":"candidate-view-fixture","role":"dedicated-test",
        "profile":"L2","signing_identity_mode":"local-pins","authority_config":"/template/support/custody.json",
        "expected_artifacts_manifest":"/template/config/inventory.json","codesign_pins_file":"/template/support/pins.json",
        "broker":null,"shared_read_only_inputs":[],"layout":{"binary_dir":"/template/bin",
            "custody_bundle":"/template/support/Custody.app","sandbox_dir":"/template/sandbox","socket_root":"/template/run",
            "state_root":"/template/state","audit_root":"/template/audit","cas_store_root":"/template/cas",
            "staging_root":"/template/stage","support_root":"/template/support",
            "launchd_namespace":"com.depot.candidatefixture","mach_service":"com.depot.candidatefixture.exception"}}))).unwrap()
}
fn inventory(plan:&BirthPlan,payloads:&BTreeMap<PathBuf,Vec<u8>>)->Vec<u8> {
    let pins=&payloads[Path::new("codesign-pins.json")];
    let files=payloads.iter().map(|(path,content)|json!({"path":path,"sha256":hex::encode(Sha256::digest(content)),"size":content.len()})).collect::<Vec<_>>();
    bytes(json!({"version":1,"kind":"depot-first-touch-artifact-inventory","target_id":plan.target.target_id,
        "profile":"L2","signing_identity_mode":"local-pins","deployment_config_sha256":hex::encode(Sha256::digest(&plan.bytes)),
        "source_git_commit":"a".repeat(40),"source_manifest_sha256":"b".repeat(64),"source_input_count":payloads.len(),
        "codesign_pins_sha256":hex::encode(Sha256::digest(pins)),"staging_root":plan.target.layout.staging_root,
        "external_provenance":"UNKNOWN","files":files}))
}
struct Fixture {anchor:PathBuf,state:BirthState,plan:TargetInstallPlan}
impl Fixture {
    fn new()->Self {
        let anchor=std::env::current_dir().unwrap().join(format!(".birth-candidate-views-{}",hex::encode(enclave_core::rng::bytes32())));
        std::fs::create_dir(&anchor).unwrap();std::fs::set_permissions(&anchor,std::fs::Permissions::from_mode(0o700)).unwrap();
        let original=BirthPlan::build(&template(),Path::new("/template"),Path::new("/birth-views"),&[0x45;16]).unwrap();
        let root=anchor.join(original.root.file_name().unwrap());let map=|path:&Path|root.join(path.strip_prefix(&original.root).unwrap());
        // Explicit private-engine rebase; never a native birth construction.
        let raw=String::from_utf8(original.bytes.clone()).unwrap().replace(original.root.to_str().unwrap(),root.to_str().unwrap()).into_bytes();
        let planned=BirthPlan {root:root.clone(),target:DeploymentTarget::parse(&raw).unwrap(),descriptor:map(&original.descriptor),
            bytes:raw,seed_dirs:original.seed_dirs.iter().map(|p|map(p)).collect()};
        let protection=Protection {owner:(unsafe{libc::geteuid()},unsafe{libc::getegid()}),native_acl:false};
        let name=CString::new(anchor.as_os_str().as_bytes()).unwrap();
        let fd=unsafe{libc::open(name.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)};
        assert!(fd>=0);let directory=Directory::capture(unsafe{File::from_raw_fd(fd)},None,false,protection).unwrap();
        let mut progress=BirthProgress::new();progress.root=Some(root.clone());progress.descriptor=Some(planned.descriptor.clone());
        progress.target_id=Some(planned.target.target_id.clone());
        let mut state=BirthState {plan:planned,dirs:BTreeMap::from([(anchor.clone(),directory)]),files:BTreeMap::new(),
            protection,progress,poisoned:false,pending:None,private_load:None};
        state.create_directory(&root,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();
        state.prepare_seeds(&mut||Vec::new(),&mut sync).unwrap();
        let mut payloads=BTreeMap::from([(PathBuf::from("bin/depot-enclave"),b"software byte fixture".to_vec()),
            (PathBuf::from("codesign-pins.json"),b"unadmitted pin byte fixture".to_vec())]);
        // Discover the actual production required set through its real parser,
        // rather than reproducing the packaging map in a test.
        let initial=target_plan::describe(&state.plan.target,&hex::encode(Sha256::digest(&state.plan.bytes)),&inventory(&state.plan,&payloads)).unwrap();
        for name in initial.missing_required_files {payloads.insert(name.into(),b"unadmitted public byte fixture".to_vec());}
        let raw=inventory(&state.plan,&payloads);
        let plan=target_plan::describe(&state.plan.target,&hex::encode(Sha256::digest(&state.plan.bytes)),&raw).unwrap();
        assert!(plan.missing_required_files.is_empty());state.prepare_denial(&raw,&mut||Vec::new(),&mut sync).unwrap();
        let inventory_path=state.plan.target.expected_artifacts_manifest.clone();
        state.create_file(&inventory_path,&raw,0o600,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();
        let staging=state.plan.target.layout.staging_root.clone();let mut directories=BTreeSet::new();
        for path in payloads.keys(){let mut parent=staging.join(path).parent().unwrap().to_owned();
            while parent!=staging {directories.insert(parent.clone());parent=parent.parent().unwrap().to_owned();}}
        let mut directories=directories.into_iter().collect::<Vec<_>>();directories.sort_by_key(|p|(p.components().count(),p.clone()));
        for directory in directories {state.create_directory(&directory,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();}
        for (relative,content) in payloads {state.create_file(&staging.join(relative),&content,0o600,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();}
        Self {anchor,state,plan}
    }
}
impl Drop for Fixture {fn drop(&mut self){let _=std::fs::remove_dir_all(&self.anchor);}}

#[test]
fn complete_actual_plan_yields_only_borrowed_original_readonly_views_without_authority() {
    let f=Fixture::new();let before=f.state.progress.attempted.clone();let views=staged_views(&f.state,&f.plan).unwrap();
    assert_eq!(views.len(),f.plan.copies.len()+f.plan.retained_in_staging.len());
    for view in views {let held=&f.state.files[view.path];assert_eq!(view.file.as_raw_fd(),held.file.as_raw_fd());
        assert!(view.path.starts_with(&f.state.plan.target.layout.staging_root));assert_eq!(held.access,libc::O_RDONLY);}
    assert_eq!(before,f.state.progress.attempted);assert!(f.state.private_load.is_none());
    assert!(!f.state.progress.mutation_allowed&&!f.state.progress.inactivity_proven&&!f.state.progress.activation_allowed
        &&!f.state.progress.installation_supported&&!f.state.progress.qualified);
    denied(checked(&f.state),"BIRTH_CANDIDATE_PRIVATE_LOAD_REQUIRED");
}
#[test]
fn required_package_and_exact_descriptor_inventory_target_bindings_precede_views() {
    // Drop each complete fixture before the next case: shadowing six owners
    // retains hundreds of original descriptors until the enclosing scope ends
    // and can exceed the real native user-session descriptor limit.
    for case in 0..6 {
        let mut f=Fixture::new();
        let expected=match case {
            0=>{f.plan.missing_required_files.push("bin/actually-missing".into());"BIRTH_CANDIDATE_PACKAGE_INCOMPLETE"},
            1=>{f.plan.artifact_inventory_sha256="00".repeat(32);"BIRTH_CANDIDATE_PLAN_BINDING"},
            2=>{f.plan.deployment_config_sha256="00".repeat(32);"BIRTH_CANDIDATE_PLAN_BINDING"},
            3=>{f.plan.target_id="different-target".into();"BIRTH_CANDIDATE_PLAN_BINDING"},
            4=>{f.state.progress.denial_prepared=false;"BIRTH_CANDIDATE_PLAN_BINDING"},
            _=>{f.state.plan.target.role=DeploymentRole::ExistingUpgrade;"BIRTH_CANDIDATE_DEDICATED_L2_REQUIRED"},
        };
        denied(staged_views(&f.state,&f.plan),expected);
    }
}
#[test]
fn missing_held_original_and_extra_staged_inode_cannot_be_adopted_from_paths() {
    let mut f=Fixture::new();let path=f.state.plan.target.layout.staging_root.join("bin/depot-enclave");
    f.state.files.remove(&path);assert!(path.exists());
    denied(staged_views(&f.state,&f.plan),"BIRTH_CANDIDATE_ORIGINAL_SOURCE_REQUIRED");
    let mut f=Fixture::new();let path=f.state.plan.target.layout.staging_root.join("unrequested-extra");
    f.state.create_file(&path,b"extra",0o600,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();
    denied(staged_views(&f.state,&f.plan),"BIRTH_CANDIDATE_SOURCE_SET");
}
#[test]
fn exact_size_digest_and_actual_readonly_descriptor_flags_are_required() {
    let mut f=Fixture::new();f.plan.copies[0].size+=1;
    denied(staged_views(&f.state,&f.plan),"BIRTH_CANDIDATE_READONLY_SOURCE_REQUIRED");
    let mut f=Fixture::new();f.plan.copies[0].sha256="00".repeat(32);
    denied(staged_views(&f.state,&f.plan),"BIRTH_CANDIDATE_SOURCE_BINDING");
    for lie_about_flags in [false,true] {
        let mut f=Fixture::new();let path=f.state.plan.target.layout.staging_root.join("bin/depot-enclave");
        // Negative private fixture only: reopen same own inode writable to
        // prove metadata/content equality cannot replace readonly admission.
        let writable=std::fs::OpenOptions::new().read(true).write(true)
            .custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC).open(&path).unwrap();
        let held=f.state.files.get_mut(&path).unwrap();held.file=writable;
        held.access=if lie_about_flags{libc::O_RDONLY}else{libc::O_RDWR};
        denied(staged_views(&f.state,&f.plan),if lie_about_flags{"BIRTH_DESCRIPTOR_FLAGS"}else{"BIRTH_CANDIDATE_READONLY_SOURCE_REQUIRED"});
    }
}
#[test]
fn same_content_named_replacement_never_replaces_retained_original_identity() {
    let f=Fixture::new();let path=f.state.plan.target.layout.staging_root.join("bin/depot-enclave");
    let bytes=std::fs::read(&path).unwrap();let original=f.state.files[&path].file.metadata().unwrap();
    let replacement=path.with_extension("replacement");std::fs::write(&replacement,&bytes).unwrap();
    std::fs::set_permissions(&replacement,std::fs::Permissions::from_mode(0o600)).unwrap();std::fs::rename(&replacement,&path).unwrap();
    assert_ne!(std::fs::metadata(&path).unwrap().ino(),original.ino());assert_eq!(std::fs::read(&path).unwrap(),bytes);
    denied(staged_views(&f.state,&f.plan),"BIRTH_SEED_CHANGED");
}
#[test]
fn current_parent_and_complete_original_stage_set_are_required_without_installation() {
    let mut f=Fixture::new();let directory=f.state.plan.target.layout.staging_root.join("bin");
    f.state.dirs.get_mut(&directory).unwrap().private=false;
    denied(staged_views(&f.state,&f.plan),"BIRTH_CANDIDATE_ORIGINAL_PARENT_REQUIRED");
    let mut f=Fixture::new();let source=f.plan.copies[0].source.clone();let unpublished=f.anchor.join("never-published/duplicate");
    f.plan.copies.push(target_plan::CopyEntry {
        source,destination:unpublished.clone(),sha256:"00".repeat(32),size:1,uid:0,gid:0,
        mode:"0644".into(),condition:"synthetic duplicate refusal only"});
    denied(staged_views(&f.state,&f.plan),"BIRTH_CANDIDATE_SOURCE_SET");
    assert!(!unpublished.exists());assert!(!f.state.plan.target.layout.binary_dir.exists());
}
