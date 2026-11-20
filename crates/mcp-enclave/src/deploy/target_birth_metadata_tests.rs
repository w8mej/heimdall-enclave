//! Private SOFTWARE planner/kernel fixtures only. No native wrapper, checked
//! target, accounts, SoftwareApproval, HostMaintenanceGuard, startup EX or
//! genuine owner-exclusion capability is constructed. Synthetic denial sets
//! deny fixture identities only. Kernel-only steps use actual fixture UID/GID;
//! the separate real-plan checks inspect unmodified production UID/GID values.

use super::*;
use serde_json::{json,Value};
use std::{cell::Cell,os::unix::fs::{PermissionsExt,symlink},sync::Mutex};

static SERIAL:Mutex<()>=Mutex::new(());
#[path="target_birth_metadata_native_tests.rs"]
mod native_boundaries;
fn encoded(value:Value)->Vec<u8>{serde_json::to_vec(&value).unwrap()}
fn sync(file:&File)->EnclaveResult<()> {file.sync_all().map_err(|_|err!(EIO,"METADATA_FIXTURE_SYNC"))}
fn template()->DeploymentTarget {
    DeploymentTarget::parse(&encoded(json!({"version":1,"target_id":"metadata-fixture","role":"dedicated-test","profile":"L2",
        "signing_identity_mode":"local-pins","authority_config":"/template/support/custody.json",
        "expected_artifacts_manifest":"/template/config/inventory.json","codesign_pins_file":"/template/support/pins.json",
        "broker":null,"shared_read_only_inputs":[],"layout":{"binary_dir":"/template/bin","custody_bundle":"/template/support/Custody.app",
            "sandbox_dir":"/template/sandbox","socket_root":"/template/run","state_root":"/template/state","audit_root":"/template/audit",
            "cas_store_root":"/template/cas","staging_root":"/template/stage","support_root":"/template/support",
            "launchd_namespace":"com.depot.metadatafixture","mach_service":"com.depot.metadatafixture.exception"}}))).unwrap()
}
struct Fixture { anchor:PathBuf,state:BirthState }
impl Fixture {
    fn new()->Self {
        let anchor=std::env::current_dir().unwrap().join(format!(".birth-metadata-{}",hex::encode(enclave_core::rng::bytes32())));
        std::fs::create_dir(&anchor).unwrap();std::fs::set_permissions(&anchor,std::fs::Permissions::from_mode(0o700)).unwrap();
        let original=BirthPlan::build(&template(),Path::new("/template"),Path::new("/birth-metadata"),&[0x29;16]).unwrap();
        let root=anchor.join(original.root.file_name().unwrap());let map=|path:&Path|root.join(path.strip_prefix(&original.root).unwrap());
        let bytes=String::from_utf8(original.bytes.clone()).unwrap().replace(original.root.to_str().unwrap(),root.to_str().unwrap()).into_bytes();
        let plan=BirthPlan {root:root.clone(),target:DeploymentTarget::parse(&bytes).unwrap(),descriptor:map(&original.descriptor),
            bytes,seed_dirs:original.seed_dirs.iter().map(|path|map(path)).collect()};
        let protection=Protection {owner:(unsafe{libc::geteuid()},unsafe{libc::getegid()}),native_acl:false};
        let name=CString::new(anchor.as_os_str().as_bytes()).unwrap();
        let fd=unsafe{libc::open(name.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)};
        assert!(fd>=0);let directory=Directory::capture(unsafe{File::from_raw_fd(fd)},None,false,protection).unwrap();
        let mut progress=BirthProgress::new();progress.root=Some(root.clone());progress.descriptor=Some(plan.descriptor.clone());
        progress.target_id=Some(plan.target.target_id.clone());
        let mut state=BirthState {plan,dirs:BTreeMap::from([(anchor.clone(),directory)]),files:BTreeMap::new(),protection,
            progress,poisoned:false,pending:None,private_load:None};
        state.create_directory(&root,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();
        state.prepare_seeds(&mut||Vec::new(),&mut sync).unwrap();Self {anchor,state}
    }
    fn directory(&mut self,relative:&str)->PathBuf {
        let path=self.state.plan.root.join(relative);let mut missing=Vec::new();let mut parent=path.as_path();
        while !self.state.dirs.contains_key(parent) {missing.push(parent.to_owned());parent=parent.parent().unwrap();}
        for path in missing.into_iter().rev(){self.state.create_directory(&path,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();}
        path
    }
    fn kernel(&mut self,relative:&str,mode:u32)->KernelMetadataAttempt {
        let path=self.directory(relative);let (uid,gid)=self.state.protection.owner;
        let denied=RetainedDirectoryExclusions {identities:BTreeSet::from([Identity::of(&self.state.dirs[&self.state.plan.root].stamp)])};
        let step=OwnMetadataStep::capture(&self.state,&path,Desired {uid,gid,mode},&denied).unwrap();
        KernelMetadataAttempt::new(vec![step],denied)
    }
    fn controls(&mut self) {
        let payloads=|files:&BTreeMap<String,Vec<u8>>| {
            let pins=&files["codesign-pins.json"];
            encoded(json!({"version":1,"kind":"depot-first-touch-artifact-inventory","target_id":self.state.plan.target.target_id,
                "profile":"L2","signing_identity_mode":"local-pins","deployment_config_sha256":hex::encode(Sha256::digest(&self.state.plan.bytes)),
                "source_git_commit":"a".repeat(40),"source_manifest_sha256":"b".repeat(64),"source_input_count":files.len(),
                "codesign_pins_sha256":hex::encode(Sha256::digest(pins)),"staging_root":self.state.plan.target.layout.staging_root,
                "external_provenance":"UNKNOWN","files":files.iter().map(|(path,bytes)|json!({"path":path,
                    "sha256":hex::encode(Sha256::digest(bytes)),"size":bytes.len()})).collect::<Vec<_>>()}))
        };
        let mut files=BTreeMap::from([("bin/depot-enclave".to_owned(),b"inert SOFTWARE payload".to_vec()),
            ("codesign-pins.json".to_owned(),b"inert SOFTWARE pins".to_vec())]);
        let first=target_plan::describe(&self.state.plan.target,&hex::encode(Sha256::digest(&self.state.plan.bytes)),&payloads(&files)).unwrap();
        for path in first.missing_required_files {files.insert(path,b"inert SOFTWARE bytes".to_vec());}
        let raw=payloads(&files);
        self.state.prepare_denial(&raw,&mut||Vec::new(),&mut sync).unwrap();
        let inventory=self.state.plan.target.expected_artifacts_manifest.clone();
        self.state.create_file(&inventory,&raw,0o644,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();
        let support=self.state.plan.target.layout.support_root.clone();let public=support.join("public");
        self.state.create_directory(&public,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();
        let manifest=encoded(json!({"v":1,"profile":"L2","asset_policy_file":public.join("policy.json"),
            "asset_policy_key_file":public.join("policy.key"),"asset_inventory_key_file":public.join("inventory.key"),
            "envelope_policy_key_file":public.join("envelope.key"),"asset_host_id":"fixture-host","asset_id":"fixture-asset",
            "asset_custodian_id":"fixture-custodian","envelope_policy_subject":"fixture-host","envelope_policy_namespace":"fixture-space"}));
        let pins=files["codesign-pins.json"].clone();
        for (path,bytes) in [(self.state.plan.target.authority_config.clone(),manifest),
            (public.join("policy.json"),b"{}".to_vec()),(public.join("policy.key"),"01".repeat(32).into_bytes()),
            (public.join("inventory.key"),"02".repeat(32).into_bytes()),(public.join("envelope.key"),"03".repeat(32).into_bytes()),
            (self.state.plan.target.codesign_pins_file.clone(),pins.clone())] {
            self.state.create_file(&path,&bytes,0o644,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();
        }
        let staged=self.state.plan.target.layout.staging_root.join("codesign-pins.json");
        self.state.create_file(&staged,&pins,0o600,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();
        assert_eq!(admit::original_modes(&self.state).unwrap().len(),11);
    }
}
impl Drop for Fixture {fn drop(&mut self){let _=std::fs::remove_dir_all(&self.anchor);}}
fn flags_false(state:&BirthState) {
    assert!(!state.progress.inactivity_proven&&!state.progress.mutation_allowed&&!state.progress.activation_allowed
        &&!state.progress.installation_supported&&!state.progress.qualified);
}

#[test]
fn real_plan_declares_fixed_payload_runtime_transport_and_excludes_original_ancestors() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);let mut f=Fixture::new();f.controls();
    let before=f.state.progress.attempted.clone();let payload=OwnMetadataPlan::build(&f.state,Scope::Payload).unwrap();
    assert!(!payload.declarations.is_empty());
    for (path,(desired,role)) in &payload.declarations {
        assert!(!payload.excluded_paths.contains(path));assert!(!path.starts_with(&f.state.plan.target.layout.staging_root));
        assert!(*role==Role::Payload);assert_eq!((desired.uid,desired.gid,desired.mode),(0,0,0o755));
    }
    let runtime=OwnMetadataPlan::build(&f.state,Scope::Runtime).unwrap();let l=&f.state.plan.target.layout;
    for d in enclave_core::daemon::DaemonId::ALL {
        let socket=runtime.declarations[&l.socket_root.join(d.dir_name())].0;
        let state=runtime.declarations[&l.state_root.join(d.dir_name())].0;
        let audit=runtime.declarations[&l.audit_root.join(d.dir_name())].0;
        assert_eq!((socket.uid,socket.gid,socket.mode),(d.uid(),d.client_gid(),0o2750));
        assert_eq!((state.uid,state.gid,state.mode),(d.uid(),d.gid(),0o700));
        assert_eq!((audit.uid,audit.gid,audit.mode),(d.uid(),crate::launchd::JOURNAL_READ_GID,0o2750));
    }
    let transport=runtime.declarations.iter().filter(|(_,(_,role))|*role==Role::Transport).map(|(p,_)|p.clone()).collect::<BTreeSet<_>>();
    assert_eq!(transport,BTreeSet::from([l.support_root.join("tuf"),l.state_root.join("cas/tuf"),l.state_root.join("cas/tuf/repo")]));
    for path in transport {let desired=runtime.declarations[&path].0;assert_eq!((desired.uid,desired.gid,desired.mode),(0,0,0o755));}
    assert_eq!(before,f.state.progress.attempted);hidden_root(&f.state).unwrap();flags_false(&f.state);
    // A real plan alone cannot manufacture missing original-created nodes.
    let denied=RetainedDirectoryExclusions {identities:BTreeSet::new()};
    assert!(OwnMetadataAttempt::prepare(&f.state,Scope::Payload,denied).is_err());
}

#[test]
fn real_readonly_root_ancestry_does_not_refuse_closed_metadata_plans() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);let mut f=Fixture::new();f.controls();
    let payload=OwnMetadataPlan::build(&f.state,Scope::Payload).unwrap();
    let runtime=OwnMetadataPlan::build(&f.state,Scope::Runtime).unwrap();
    // Observe the genuine readonly root, as native ancestry does, without
    // constructing native birth/guard/EX authority or mutating that directory.
    let fd=unsafe{libc::open(c"/".as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)};
    assert!(fd>=0);
    let directory=Directory::capture(unsafe{File::from_raw_fd(fd)},None,false,
        Protection {owner:(0,0),native_acl:false}).unwrap();
    let original=Snapshot::of(&directory.file).unwrap();let root_fd=directory.file.as_raw_fd();
    f.state.dirs.insert(PathBuf::from("/"),directory);
    let before=f.state.progress.attempted.clone();
    let actual_payload=OwnMetadataPlan::build(&f.state,Scope::Payload).unwrap();
    let actual_runtime=OwnMetadataPlan::build(&f.state,Scope::Runtime).unwrap();
    assert!(payload.declarations==actual_payload.declarations&&runtime.declarations==actual_runtime.declarations);
    assert!(payload.excluded_paths==actual_payload.excluded_paths&&runtime.excluded_paths==actual_runtime.excluded_paths);
    for plan in [&actual_payload,&actual_runtime] {assert!(!plan.declarations.contains_key(Path::new("/")));}
    let root=&f.state.dirs[Path::new("/")];let after=Snapshot::of(&root.file).unwrap();
    assert!(original.stamp==after.stamp&&original.links==after.links);
    assert!(original.modified==after.modified&&original.changed==after.changed);
    assert_eq!(root.file.as_raw_fd(),root_fd);assert!(!root.private);flags(&root.file,libc::O_RDONLY).unwrap();
    assert_eq!(f.state.progress.attempted,before);hidden_root(&f.state).unwrap();flags_false(&f.state);
}

#[test]
fn real_closed_plan_steps_are_original_bound_deepest_first_and_actual_denials_refuse() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);let mut f=Fixture::new();f.controls();
    let plan=OwnMetadataPlan::build(&f.state,Scope::Runtime).unwrap();
    let mut paths=plan.declarations.keys().cloned().collect::<Vec<_>>();paths.sort_by_key(|p|(p.components().count(),p.clone()));
    for path in &paths {let relative=path.strip_prefix(&f.state.plan.root).unwrap().to_str().unwrap().to_owned();f.directory(&relative);}
    let denied=RetainedDirectoryExclusions {identities:BTreeSet::new()};
    let prepared=OwnMetadataAttempt::prepare(&f.state,Scope::Runtime,denied).unwrap();
    assert_eq!(prepared.kernel.steps.len(),plan.declarations.len());
    for pair in prepared.kernel.steps.windows(2){assert!(pair[0].origin.path.components().count()>=pair[1].origin.path.components().count());}
    let mut ids=BTreeSet::new();for step in &prepared.kernel.steps {
        assert!(ids.insert(Identity::of(&step.origin.stamp)));assert_eq!(step.origin.fd,f.state.dirs[&step.origin.path].file.as_raw_fd());
        assert_eq!(step.origin.stamp.mode&0o7777,0o700);assert!(step.desired==plan.declarations[&step.origin.path].0);
    }
    let blocked=Identity::of(&prepared.kernel.steps[0].origin.stamp);
    assert!(OwnMetadataAttempt::prepare(&f.state,Scope::Runtime,RetainedDirectoryExclusions {identities:BTreeSet::from([blocked])}).is_err());
    hidden_root(&f.state).unwrap();flags_false(&f.state);
}

#[test]
fn original_readonly_mode_change_preserves_identity_provenance_files_and_exact_expected_metadata() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);let mut f=Fixture::new();let mut a=f.kernel("payload/leaf",0o755);
    let path=a.steps[0].origin.path.clone();let identity=Identity::of(&a.steps[0].origin.stamp);let fd=a.steps[0].origin.fd;
    let files=f.state.files.iter().map(|(p,s)|(p.clone(),FileStamp::of(&s.file.metadata().unwrap()),s.file.as_raw_fd())).collect::<Vec<_>>();
    a.apply(&mut f.state,None,&mut||Vec::new(),&mut sync).unwrap();
    let d=&f.state.dirs[&path];assert!(d.private);assert!(Identity::of(&d.stamp)==identity);assert_eq!(d.file.as_raw_fd(),fd);
    assert_eq!(d.stamp.mode&0o7777,0o755);assert_eq!(a.steps[0].origin.stamp.mode&0o7777,0o700);
    assert_eq!(a.history[0].calls.len(),1);assert!(a.history[0].calls[0].operation==Operation::Chmod);
    assert!(a.history[0].calls[0].result==Some(Ok(()))&&a.history[0].calls[0].expected_committed);
    assert_eq!(a.history[0].syncs.len(),2);assert!(a.history[0].syncs.iter().all(|s|s.error.is_none()));
    flags(&d.file,libc::O_RDONLY).unwrap();hidden_root(&f.state).unwrap();
    for (path,stamp,fd) in files {let seed=&f.state.files[&path];assert!(seed.stamp==stamp);assert_eq!(seed.file.as_raw_fd(),fd);}
    assert!(a.complete&&!a.poisoned&&!f.state.poisoned);assert!(!f.state.progress.complete);flags_false(&f.state);
}

#[test]
fn exact_noop_does_not_call_metadata_syscalls_or_rewrite_original_stamps() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);let mut f=Fixture::new();let mut a=f.kernel("payload/leaf",0o700);
    let path=a.steps[0].origin.path.clone();let before=Snapshot::of(&f.state.dirs[&path].file).unwrap();
    a.apply(&mut f.state,None,&mut||Vec::new(),&mut sync).unwrap();let after=Snapshot::of(&f.state.dirs[&path].file).unwrap();
    assert!(a.history[0].calls.is_empty()&&a.history[0].chown_noop&&a.history[0].chmod_noop);
    assert!(before.stamp==after.stamp);assert_eq!(before.changed,after.changed);assert_eq!(before.modified,after.modified);
    assert_eq!(before.links,after.links);hidden_root(&f.state).unwrap();
}

#[test]
fn own_chown_is_verified_before_setgid_and_failed_chmod_retains_first_effect() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);let mut f=Fixture::new();let mut a=f.kernel("payload/leaf",0o2750);
    let mut observed=Vec::new();
    // The private kernel seam forces a genuine same-owner chown even when
    // normal planning would skip it. This tests ordering/effect history without
    // changing a host account or requiring a fabricated native authority.
    a.syscall(0,Operation::Chown,&mut f.state,None,&mut||Vec::new(),&mut observed).unwrap();
    let path=a.steps[0].origin.path.clone();assert_eq!(f.state.dirs[&path].stamp.mode&0o7777,0o700);
    a.fault=Some(TestSyscallFault::Before(Operation::Chmod));
    assert!(a.apply(&mut f.state,None,&mut||Vec::new(),&mut sync).unwrap_err().is("BIRTH_METADATA_SYSCALL_FAILED"));
    assert_eq!(a.history[0].calls.len(),2);assert!(a.history[0].calls[0].operation==Operation::Chown);
    assert!(a.history[0].calls[0].expected_committed);assert!(a.history[0].calls[1].operation==Operation::Chmod);
    assert!(!a.history[0].calls[1].expected_committed);assert_eq!(f.state.dirs[&path].file.metadata().unwrap().mode()&0o7777,0o700);
    assert!(a.poisoned&&f.state.poisoned);assert!(a.failure.as_ref().unwrap().error.is("BIRTH_METADATA_SYSCALL_FAILED"));
    assert_eq!(a.steps[0].origin.fd,f.state.dirs[&path].file.as_raw_fd());
}

#[test]
fn genuine_fixture_chown_then_setgid_mode_keeps_each_exact_prediction_and_readonly_fd() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);let mut f=Fixture::new();let mut a=f.kernel("payload/leaf",0o2750);
    let mut observed=Vec::new();let path=a.steps[0].origin.path.clone();let fd=a.steps[0].origin.fd;
    a.syscall(0,Operation::Chown,&mut f.state,None,&mut||Vec::new(),&mut observed).unwrap();
    a.apply(&mut f.state,None,&mut||Vec::new(),&mut sync).unwrap();
    assert_eq!(a.history[0].calls.len(),2);
    let chown=&a.history[0].calls[0];let chmod=&a.history[0].calls[1];
    assert!(chown.operation==Operation::Chown&&chmod.operation==Operation::Chmod);
    assert_eq!(chown.predicted.mode&0o7777,0o700);assert_eq!(chmod.before.stamp.mode&0o7777,0o700);
    assert_eq!(chmod.predicted.mode&0o7777,0o2750);assert!(chown.expected_committed&&chmod.expected_committed);
    let d=&f.state.dirs[&path];assert_eq!(d.file.metadata().unwrap().mode()&0o7777,0o2750);
    assert_eq!(d.file.as_raw_fd(),fd);flags(&d.file,libc::O_RDONLY).unwrap();hidden_root(&f.state).unwrap();flags_false(&f.state);
}

#[test]
fn ambiguous_actual_mode_effect_is_retained_but_never_adopted_or_retried() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);let mut f=Fixture::new();let mut a=f.kernel("payload/leaf",0o755);
    a.fault=Some(TestSyscallFault::AmbiguousAfterSuccess(Operation::Chmod));let path=a.steps[0].origin.path.clone();
    assert!(a.apply(&mut f.state,None,&mut||Vec::new(),&mut sync).is_err());
    let call=&a.history[0].calls[0];assert!(call.result==Some(Err(libc::EIO)));assert!(!call.expected_committed);
    assert_eq!(call.held_after.as_ref().unwrap().stamp.mode&0o7777,0o755);
    assert_eq!(call.named_after.as_ref().unwrap().stamp.mode&0o7777,0o755);
    assert_eq!(f.state.dirs[&path].stamp.mode&0o7777,0o700);assert_eq!(f.state.dirs[&path].file.metadata().unwrap().mode()&0o7777,0o755);
    assert!(!a.failure.as_ref().unwrap().final_errors.is_empty());let old_errors=a.failure.as_ref().unwrap().final_errors.len();
    assert!(a.apply(&mut f.state,None,&mut||Vec::new(),&mut sync).unwrap_err().is("BIRTH_METADATA_OWNER_POISONED"));
    assert_eq!(a.history[0].calls.len(),1);assert!(a.failure.as_ref().unwrap().error.is("BIRTH_METADATA_SYSCALL_FAILED"));
    assert!(a.failure.as_ref().unwrap().final_errors.len()>=old_errors);flags_false(&f.state);
}

#[test]
fn sync_and_final_guard_refusals_retain_applied_metadata_and_all_available_errors() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);let mut f=Fixture::new();let mut a=f.kernel("payload/leaf",0o755);
    let synced=Cell::new(false);let path=a.steps[0].origin.path.clone();
    let error=a.apply(&mut f.state,None,&mut||if synced.get(){vec![err!(EACCES,"FIXTURE_METADATA_GUARD_LOST")]}else{Vec::new()},
        &mut|_|{synced.set(true);Err(err!(EIO,"FIXTURE_METADATA_SYNC_FAIL"))}).unwrap_err();
    assert!(error.is("FIXTURE_METADATA_SYNC_FAIL"));let failure=a.failure.as_ref().unwrap();
    assert!(failure.boundary_errors.iter().any(|e|e.is("FIXTURE_METADATA_GUARD_LOST")));
    assert!(failure.final_errors.iter().any(|e|e.is("FIXTURE_METADATA_GUARD_LOST")));
    assert!(a.history[0].calls[0].expected_committed);assert!(a.history[0].syncs[0].error.as_ref().unwrap().is("FIXTURE_METADATA_SYNC_FAIL"));
    assert_eq!(f.state.dirs[&path].stamp.mode&0o7777,0o755);assert_eq!(f.state.dirs[&path].file.metadata().unwrap().mode()&0o7777,0o755);
    assert!(f.state.poisoned&&a.poisoned);hidden_root(&f.state).unwrap();
}

#[test]
fn root_visibility_loss_or_original_name_replacement_refuses_without_own_metadata_effect() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    for variant in ["root","replace","symlink","flags"] {
        let mut f=Fixture::new();let mut a=f.kernel("payload/leaf",0o755);let path=a.steps[0].origin.path.clone();
        let original=Snapshot::of(&f.state.dirs[&path].file).unwrap();
        match variant {
            "root"=>std::fs::set_permissions(&f.state.plan.root,std::fs::Permissions::from_mode(0o755)).unwrap(),
            "flags"=>{let fd=f.state.dirs[&path].file.as_raw_fd();let flags=unsafe{libc::fcntl(fd,libc::F_GETFL)};
                assert_eq!(unsafe{libc::fcntl(fd,libc::F_SETFL,flags&!libc::O_NONBLOCK)},0);},
            _=>{std::fs::rename(&path,f.anchor.join("saved-original")).unwrap();
                if variant=="symlink" {symlink(f.anchor.join("saved-original"),&path).unwrap();}
                else {std::fs::create_dir(&path).unwrap();std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o700)).unwrap();}},
        }
        assert!(a.apply(&mut f.state,None,&mut||Vec::new(),&mut sync).is_err());assert!(a.history[0].calls.is_empty());
        let held=Snapshot::of(&f.state.dirs[&path].file).unwrap();assert!(held.stamp==original.stamp);
        assert_eq!(held.stamp.mode&0o7777,0o700);assert_eq!(a.steps[0].origin.fd,f.state.dirs[&path].file.as_raw_fd());flags_false(&f.state);
    }
}

#[test]
fn missing_creation_provenance_and_denied_original_identity_never_gain_metadata_steps() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);let mut f=Fixture::new();let path=f.directory("payload/leaf");
    let d=&f.state.dirs[&path];let desired=Desired {uid:d.stamp.uid,gid:d.stamp.gid,mode:0o755};
    let denied=RetainedDirectoryExclusions {identities:BTreeSet::from([Identity::of(&d.stamp)])};
    assert!(OwnMetadataStep::capture(&f.state,&path,desired,&denied).is_err());
    let denied=RetainedDirectoryExclusions {identities:BTreeSet::new()};
    f.state.progress.created_directories.retain(|p|p!=&path);
    assert!(OwnMetadataStep::capture(&f.state,&path,desired,&denied).is_err());
    assert_eq!(f.state.dirs[&path].file.metadata().unwrap().mode()&0o7777,0o700);hidden_root(&f.state).unwrap();
}
