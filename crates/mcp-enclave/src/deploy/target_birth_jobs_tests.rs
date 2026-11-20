//! Ordinary parser/original-FD/kernel fixtures only. No native birth, EX,
//! host guard, provisioning, account or SOFTWARE authority is constructed.
//! Fixture namespace effects are confined to a unique test directory.
use super::*;
use serde_json::{json,Value};
use std::{cell::Cell,os::unix::fs::{OpenOptionsExt,PermissionsExt,symlink}};
fn encode(value:Value)->Vec<u8>{serde_json::to_vec(&value).unwrap()}
fn sync(file:&File)->EnclaveResult<()>{file.sync_all().map_err(|_|err!(EIO,"JOBS_FIXTURE_SYNC"))}
fn open_dir(path:&Path)->File {
    let name=CString::new(path.as_os_str().as_bytes()).unwrap();
    let fd=unsafe{libc::open(name.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)};
    assert!(fd>=0);unsafe{File::from_raw_fd(fd)}
}
fn template()->DeploymentTarget {
    DeploymentTarget::parse(&encode(json!({"version":1,"target_id":"job-fixture","role":"dedicated-test","profile":"L2",
        "signing_identity_mode":"local-pins","authority_config":"/template/support/custody.json",
        "expected_artifacts_manifest":"/template/config/inventory.json","codesign_pins_file":"/template/support/pins.json",
        "broker":null,"shared_read_only_inputs":[],"layout":{"binary_dir":"/template/bin","custody_bundle":"/template/support/Custody.app",
        "sandbox_dir":"/template/sandbox","socket_root":"/template/run","state_root":"/template/state","audit_root":"/template/audit",
        "cas_store_root":"/template/cas","staging_root":"/template/stage","support_root":"/template/support",
        "launchd_namespace":"com.mcpmac.jobfixture","mach_service":"com.mcpmac.jobfixture.exception"}}))).unwrap()
}
fn inventory(plan:&BirthPlan,files:&BTreeMap<PathBuf,Vec<u8>>)->Vec<u8> {
    encode(json!({"version":1,"kind":"mcpmac-first-touch-artifact-inventory","target_id":plan.target.target_id,"profile":"L2",
        "signing_identity_mode":"local-pins","deployment_config_sha256":hex::encode(Sha256::digest(&plan.bytes)),
        "source_git_commit":"a".repeat(40),"source_manifest_sha256":"b".repeat(64),"source_input_count":files.len(),
        "codesign_pins_sha256":hex::encode(Sha256::digest(&files[Path::new("codesign-pins.json")])),
        "staging_root":plan.target.layout.staging_root,"external_provenance":"UNKNOWN",
        "files":files.iter().map(|(path,bytes)|json!({"path":path,"sha256":hex::encode(Sha256::digest(bytes)),"size":bytes.len()})).collect::<Vec<_>>()}))
}
struct PlanFixture {anchor:PathBuf,state:BirthState,approved:TargetInstallPlan}
impl PlanFixture {
    fn new(size:usize)->Self {
        let anchor=std::env::current_dir().unwrap().join(format!(".birth-jobs-{}",hex::encode(enclave_core::rng::bytes32())));
        std::fs::create_dir(&anchor).unwrap();std::fs::set_permissions(&anchor,std::fs::Permissions::from_mode(0o700)).unwrap();
        let original=BirthPlan::build(&template(),Path::new("/template"),Path::new("/jobs-birth"),&[0x71;16]).unwrap();
        let root=anchor.join(original.root.file_name().unwrap());let map=|p:&Path|root.join(p.strip_prefix(&original.root).unwrap());
        let raw=String::from_utf8(original.bytes.clone()).unwrap().replace(original.root.to_str().unwrap(),root.to_str().unwrap()).into_bytes();
        let plan=BirthPlan {root:root.clone(),target:DeploymentTarget::parse(&raw).unwrap(),descriptor:map(&original.descriptor),bytes:raw,
            seed_dirs:original.seed_dirs.iter().map(|p|map(p)).collect()};
        let protection=Protection {owner:(unsafe{libc::geteuid()},unsafe{libc::getegid()}),native_acl:false};
        let directory=Directory::capture(open_dir(&anchor),None,false,protection).unwrap();
        let mut progress=BirthProgress::new();progress.root=Some(root.clone());progress.descriptor=Some(plan.descriptor.clone());
        progress.target_id=Some(plan.target.target_id.clone());
        let mut state=BirthState {plan,dirs:BTreeMap::from([(anchor.clone(),directory)]),files:BTreeMap::new(),protection,
            progress,poisoned:false,pending:None,private_load:None};
        state.create_directory(&root,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();state.prepare_seeds(&mut||Vec::new(),&mut sync).unwrap();
        // Both roles are mandatory even for the parser's incomplete report.
        let mut files=BTreeMap::from([(PathBuf::from("codesign-pins.json"),b"SOFTWARE unadmitted pins".to_vec()),
            (PathBuf::from("bin/mcp-enclave"),b"SOFTWARE inert binary".to_vec())]);
        let first=target_plan::describe(&state.plan.target,&hex::encode(Sha256::digest(&state.plan.bytes)),&inventory(&state.plan,&files)).unwrap();
        for name in first.missing_required_files {files.insert(name.into(),b"SOFTWARE unadmitted required body".to_vec());}
        for role in JOB_ROLES {files.insert(PathBuf::from(format!("launchd/{}.{role}.plist",state.plan.target.layout.launchd_namespace)),
            (0..size).map(|n|(n%251)as u8).collect());}
        let raw=inventory(&state.plan,&files);let approved=target_plan::describe(&state.plan.target,&hex::encode(Sha256::digest(&state.plan.bytes)),&raw).unwrap();
        assert!(approved.missing_required_files.is_empty());state.prepare_denial(&raw,&mut||Vec::new(),&mut sync).unwrap();
        let stage=state.plan.target.layout.staging_root.clone();state.create_directory(&stage.join("launchd"),&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();
        for copy in &approved.copies {if copy.source.parent()==Some(stage.join("launchd").as_path())&&copy.source.extension().is_some_and(|s|s=="plist") {
            let body=&files[copy.source.strip_prefix(&stage).unwrap()];state.create_file(&copy.source,body,0o600,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();
            let file=state.files.get_mut(&copy.source).unwrap();file.bytes.clear();file.streamed=Some(StreamedContent {length:body.len()as u64,sha256:hex::encode(Sha256::digest(body))});
        }}Self {anchor,state,approved}
    }
    fn plan(&self)->EnclaveResult<JobsPlan>{JobsPlan::build(&self.state,&self.approved)}
}
impl Drop for PlanFixture {fn drop(&mut self){let _=std::fs::remove_dir_all(&self.anchor);}}
struct KernelFixture {base:PlanFixture,owner:ExternalJobs,spec:JobSpec,parent:PathBuf}
impl KernelFixture {
    fn new(size:usize)->Self {
        let base=PlanFixture::new(size);let mut spec=base.plan().unwrap().copies.remove(0);
        let parent=base.anchor.join("external");std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent,std::fs::Permissions::from_mode(0o700)).unwrap();
        spec.destination=parent.join(spec.destination.file_name().unwrap());spec.pending=parent.join(spec.pending.file_name().unwrap());
        let mut owner=ExternalJobs::new(&[spec.clone()],base.state.protection);
        for path in [&base.anchor,&parent] {owner.parents.insert(path.clone(),ExternalParent {file:open_dir(path),original:None});owner.admit_parent(path).unwrap();}
        owner.all_absent().unwrap();Self {base,owner,spec,parent}
    }
    fn run(&mut self,check:&mut impl FnMut()->Vec<EnclaveError>,sync:&mut impl FnMut(&File)->EnclaveResult<()>,observed:&mut Vec<EnclaveError>)->EnclaveResult<()> {
        let source=job_source(&self.base.state,&self.spec)?;self.owner.copy_one(0,&source,check,observed,sync)
    }
    fn copied(&mut self){self.run(&mut||Vec::new(),&mut sync,&mut Vec::new()).unwrap();}
}
fn no_authority(state:&BirthState){assert!(state.private_load.is_none());assert!(!state.progress.activation_allowed&&!state.progress.mutation_allowed
    &&!state.progress.inactivity_proven&&!state.progress.installation_supported&&!state.progress.qualified);metadata::hidden_root(state).unwrap();}

#[test]
fn real_l2_plan_has_exact_allocated_nine_daemons_two_agents_and_original_sources() {
    let f=PlanFixture::new(17);let before=f.state.progress.attempted.clone();let plan=f.plan().unwrap();assert_eq!(plan.copies.len(),11);
    assert_eq!(plan.copies.iter().filter(|s|s.destination.parent()==Some(Path::new(DAEMONS))).count(),9);
    assert_eq!(plan.copies.iter().filter(|s|s.destination.parent()==Some(Path::new(AGENTS))).count(),2);
    for spec in &plan.copies {assert!(!spec.pending.ends_with(".plist"));assert_eq!(spec.pending.extension().unwrap(),"pending");
        assert!(spec.destination.file_name().unwrap().as_bytes().starts_with(f.state.plan.target.layout.launchd_namespace.as_bytes()));
        assert_eq!(f.state.files[&spec.source].access,libc::O_RDONLY);job_source(&f.state,spec).unwrap().current(spec,true).unwrap();}
    assert_eq!(before,f.state.progress.attempted);no_authority(&f.state);
}
#[test]
fn missing_unknown_duplicate_wrong_owner_mode_bound_and_case_alias_refuse_before_effects() {
    for kind in 0..9 {let mut f=PlanFixture::new(17);let before=f.state.progress.attempted.clone();
        let index=f.approved.copies.iter().position(|c|c.destination.parent()==Some(Path::new(DAEMONS))).unwrap();
        match kind {
            0=>{f.approved.copies.remove(index);},
            1|2|8=>{let c=&f.approved.copies[index];let mut extra=target_plan::CopyEntry {source:c.source.clone(),destination:c.destination.clone(),sha256:c.sha256.clone(),size:c.size,uid:c.uid,gid:c.gid,mode:c.mode.clone(),condition:c.condition};
                if kind==1 {extra.source=f.state.plan.target.layout.staging_root.join("launchd/unknown.plist");extra.destination=Path::new(DAEMONS).join("unknown.plist");}
                if kind==8 {extra.source=f.state.plan.target.layout.staging_root.join("launchd/case.plist");extra.destination=PathBuf::from("/library/launchdaemons/unknown.plist");}
                f.approved.copies.push(extra);},
            3=>f.approved.copies[index].uid=1,4=>f.approved.copies[index].mode="0600".into(),
            5=>f.approved.copies[index].size=MAX_JOB_BYTES+1,6=>f.approved.copies[index].sha256="AB".repeat(32),
            _=>f.approved.copies[index].gid=1,
        }
        assert!(f.plan().is_err(),"kind {kind}");assert_eq!(before,f.state.progress.attempted);no_authority(&f.state);
    }
}
#[test]
fn original_external_ancestor_is_allowed_but_cached_file_or_child_alias_refuses() {
    let mut f=PlanFixture::new(17);let plan=f.plan().unwrap();let path=plan.copies[0].destination.clone();
    let file=open_dir(Path::new("/"));let m=file.metadata().unwrap();let protection=Protection {owner:(m.uid(),m.gid()),native_acl:false};
    let root_fd=file.as_raw_fd();let root_identity=(m.dev(),m.ino());
    f.state.dirs.insert(PathBuf::from("/"),Directory::capture(file,None,false,protection).unwrap());
    let after=f.plan().unwrap();assert_eq!(plan.copies.len(),after.copies.len());
    for (before,after) in plan.copies.iter().zip(&after.copies) {
        assert_eq!((&before.source,&before.destination,&before.pending),(&after.source,&after.destination,&after.pending));
    }
    let held=&f.state.dirs[Path::new("/")].file;let current=held.metadata().unwrap();
    assert_eq!(held.as_raw_fd(),root_fd);assert_eq!((current.dev(),current.ino()),root_identity);flags(held,libc::O_RDONLY).unwrap();
    // Selectable normalization remains strict. This regression permits only
    // the exact genuine cached root as an external shared ancestor.
    assert!(folded(Path::new("/")).is_err());
    let file=open_dir(&f.anchor);let d=Directory::capture(file,None,false,f.state.protection).unwrap();
    f.state.dirs.insert(path.join("child"),d);assert!(f.plan().err().unwrap().is("BIRTH_JOBS_ORIGINAL_ALIAS"));no_authority(&f.state);
}
#[test]
fn complete_bytes_are_read_back_and_sealed_before_create_only_final_publication() {
    let mut f=KernelFixture::new(64*1024+37);let source_fd=f.base.state.files[&f.spec.source].file.as_raw_fd();f.copied();
    let o=&f.owner.outputs[0];assert!(o.writer.is_none()&&o.readonly.is_some()&&o.durable&&o.content_complete);
    assert!(!f.spec.pending.exists());assert_eq!(std::fs::read(&f.spec.destination).unwrap(),std::fs::read(&f.spec.source).unwrap());
    let m=std::fs::metadata(&f.spec.destination).unwrap();assert_eq!(m.mode()&0o7777,0o644);assert_eq!(m.nlink(),1);
    assert_eq!(o.initial.as_ref().unwrap().mode&0o7777,0o600);assert!(o.effects.iter().all(|e|e.verified&&e.result==Some(Ok(()))));
    assert!(o.effects.iter().filter(|e|matches!(e.action,JobAction::Write)).count()>1);
    assert!(f.owner.observations(true).is_empty());assert_eq!(f.base.state.files[&f.spec.source].file.as_raw_fd(),source_fd);no_authority(&f.base.state);
}
#[test]
fn every_existing_final_or_pending_type_refuses_untouched_without_creating_outputs() {
    for final_name in [false,true] {for kind in 0..4 {let f=KernelFixture::new(17);let path=if final_name{&f.spec.destination}else{&f.spec.pending};
        match kind {0=>std::fs::write(path,b"preexisting").unwrap(),1=>std::fs::create_dir(path).unwrap(),
            2=>symlink(&f.spec.source,path).unwrap(),_=>{let name=CString::new(path.as_os_str().as_bytes()).unwrap();assert_eq!(unsafe{libc::mkfifo(name.as_ptr(),0o600)},0);}}
        let before=std::fs::symlink_metadata(path).unwrap();assert!(f.owner.all_absent().unwrap_err().is("BIRTH_JOBS_EXISTING_NAME"));
        let after=std::fs::symlink_metadata(path).unwrap();assert_eq!((before.dev(),before.ino(),before.mode()),(after.dev(),after.ino(),after.mode()));
        assert!(f.owner.outputs[0].writer.is_none()&&f.owner.outputs[0].effects.is_empty());no_authority(&f.base.state);
    }}
}
#[test]
fn original_source_content_name_flags_and_length_drift_refuse() {
    for kind in 0..5 {let f=KernelFixture::new(17);let seed=&f.base.state.files[&f.spec.source];
        match kind {0=>std::fs::write(&f.spec.source,b"changed bytes!!!!").unwrap(),
            1=>{std::fs::rename(&f.spec.source,f.spec.source.with_extension("held")).unwrap();std::fs::write(&f.spec.source,[0u8;17]).unwrap();},
            2=>std::fs::set_permissions(&f.spec.source,std::fs::Permissions::from_mode(0o644)).unwrap(),
            3=>{let status=unsafe{libc::fcntl(seed.file.as_raw_fd(),libc::F_GETFL)};assert_eq!(unsafe{libc::fcntl(seed.file.as_raw_fd(),libc::F_SETFL,status&!libc::O_NONBLOCK)},0);},
            _=>{std::fs::OpenOptions::new().write(true).open(&f.spec.source).unwrap().set_len(18).unwrap();}}
        assert!(job_source(&f.base.state,&f.spec).unwrap().current(&f.spec,true).is_err());assert!(f.owner.outputs[0].writer.is_none());
    }
}
#[test]
fn parent_replacement_mode_or_descriptor_flags_refuse_without_new_output() {
    for kind in 0..3 {let mut f=KernelFixture::new(17);let original=f.owner.parents[&f.parent].file.as_raw_fd();
        match kind {0=>{std::fs::rename(&f.parent,f.parent.with_extension("held")).unwrap();std::fs::create_dir(&f.parent).unwrap();},
            1=>std::fs::set_permissions(&f.parent,std::fs::Permissions::from_mode(0o777)).unwrap(),
            _=>{let status=unsafe{libc::fcntl(original,libc::F_GETFD)};assert_eq!(unsafe{libc::fcntl(original,libc::F_SETFD,status&!libc::FD_CLOEXEC)},0);}}
        assert!(f.run(&mut||Vec::new(),&mut sync,&mut Vec::new()).is_err());assert!(f.owner.poisoned);
        assert_eq!(f.owner.parents[&f.parent].file.as_raw_fd(),original);assert!(f.owner.outputs[0].writer.is_none());
    }
}
#[test]
fn refusal_at_each_effect_boundary_keeps_original_descriptors_and_partial_names() {
    for stop in 0..6 {let mut f=KernelFixture::new(64*1024+37);let pending=f.spec.pending.clone();let final_name=f.spec.destination.clone();
        let syncs=Cell::new(0);let mut observed=Vec::new();let mut check=|| {
            let p=std::fs::metadata(&pending).ok();let q=std::fs::metadata(&final_name).ok();
            let refuse=match stop {0=>true,1=>p.is_some(),2=>p.as_ref().is_some_and(|m|m.len()>0),
                3=>p.as_ref().is_some_and(|m|m.mode()&0o7777==0o644),4=>q.is_some(),_=>q.is_some()&&p.is_none()};
            if refuse{vec![err!(EACCES,"JOBS_FIXTURE_GUARD_LOST")]}else{Vec::new()}
        };
        assert!(f.run(&mut check,&mut|file|{syncs.set(syncs.get()+1);sync(file)},&mut observed).unwrap_err().is("JOBS_FIXTURE_GUARD_LOST"));
        assert!(f.owner.poisoned&&observed.iter().any(|e|e.is("JOBS_FIXTURE_GUARD_LOST")));
        let o=&f.owner.outputs[0];if stop==0{assert!(o.writer.is_none()&&o.readonly.is_none());}else{
            let held=o.file().unwrap().metadata().unwrap();let initial=o.initial.as_ref().unwrap();assert_eq!((held.dev(),held.ino()),(initial.dev,initial.ino));
            assert_eq!(pending.exists(),o.pending_present);assert_eq!(final_name.exists(),o.final_present);assert!(!o.durable);
        }
        let effects=o.effects.len();assert!(f.run(&mut||Vec::new(),&mut sync,&mut Vec::new()).is_err());assert_eq!(f.owner.outputs[0].effects.len(),effects);
        no_authority(&f.base.state);
    }
}
#[test]
fn failed_file_or_parent_sync_retains_same_output_and_exact_no_retry_history() {
    for failed in 0..3 {let mut f=KernelFixture::new(17);let calls=Cell::new(0);let mut observed=Vec::new();
        let error=f.run(&mut||Vec::new(),&mut|file|{let n=calls.get();calls.set(n+1);if n==failed {Err(err!(EIO,"JOBS_FIXTURE_SYNC_LOST"))}else{sync(file)}},&mut observed).unwrap_err();
        assert!(error.is("JOBS_FIXTURE_SYNC_LOST"));assert_eq!(calls.get(),failed+1);assert!(f.owner.poisoned);
        let o=&f.owner.outputs[0];assert!(!o.durable);assert!(o.file().is_ok());assert!(observed.iter().any(|e|e.is("JOBS_FIXTURE_SYNC_LOST")));
        assert!(o.effects.last().unwrap().result==Some(Err(libc::EIO)));assert!(!o.effects.last().unwrap().verified);
        if failed==0 {assert!(o.writer.is_some()&&f.spec.pending.exists()&&!f.spec.destination.exists());}
        else{assert!(o.readonly.is_some()&&o.writer.is_none()&&!f.spec.pending.exists()&&f.spec.destination.exists());}
        no_authority(&f.base.state);
    }
}
#[test]
fn ambiguous_reported_link_or_unlink_failure_never_adopts_observed_real_success() {
    for fault in [JobFault::AmbiguousLink,JobFault::AmbiguousUnlink] {let mut f=KernelFixture::new(17);f.owner.fault=Some(fault);
        assert!(f.run(&mut||Vec::new(),&mut sync,&mut Vec::new()).unwrap_err().is("BIRTH_JOBS_SYSCALL_REFUSED"));
        let o=&f.owner.outputs[0];let effect=o.effects.last().unwrap();assert_eq!(effect.result,Some(Err(libc::EIO)));assert!(!effect.verified);
        assert_eq!(o.expected.as_ref(),effect.before.as_ref());assert_ne!(effect.before,effect.after);assert!(f.owner.poisoned&&!o.durable);
        match fault {JobFault::AmbiguousLink=>{assert!(f.spec.destination.exists()&&f.spec.pending.exists());assert_eq!(o.expected.as_ref().unwrap().links,1);assert_eq!(effect.after.as_ref().unwrap().links,2);},
            JobFault::AmbiguousUnlink=>{assert!(f.spec.destination.exists()&&!f.spec.pending.exists());assert_eq!(o.expected.as_ref().unwrap().links,2);assert_eq!(effect.after.as_ref().unwrap().links,1);}}
        assert!(o.readonly.is_some()&&o.writer.is_none());no_authority(&f.base.state);
    }
}
#[test]
fn completed_output_name_content_mode_flags_and_reintroduced_pending_drift_refuse() {
    for kind in 0..5 {let mut f=KernelFixture::new(17);f.copied();let o=&f.owner.outputs[0];let held=o.readonly.as_ref().unwrap().as_raw_fd();
        match kind {0=>{std::fs::rename(&f.spec.destination,f.spec.destination.with_extension("held")).unwrap();std::fs::write(&f.spec.destination,[0u8;17]).unwrap();},
            1=>std::fs::OpenOptions::new().write(true).custom_flags(libc::O_NOFOLLOW).open(&f.spec.destination).unwrap().write_all(&[3u8;17]).unwrap(),
            2=>std::fs::set_permissions(&f.spec.destination,std::fs::Permissions::from_mode(0o600)).unwrap(),
            3=>{let status=unsafe{libc::fcntl(held,libc::F_GETFL)};assert_eq!(unsafe{libc::fcntl(held,libc::F_SETFL,status&!libc::O_NONBLOCK)},0);},
            _=>{std::fs::write(&f.spec.pending,b"reintroduced").unwrap();}}
        assert!(!f.owner.observations(true).is_empty());assert_eq!(f.owner.outputs[0].readonly.as_ref().unwrap().as_raw_fd(),held);no_authority(&f.base.state);
    }
}
#[test]
fn completion_requires_retained_successful_effect_history_as_well_as_current_inode() {
    let mut f=KernelFixture::new(17);f.copied();
    let last=f.owner.outputs[0].effects.len()-1;
    f.owner.outputs[0].effects[last].verified=false;
    assert!(f.owner.observations(true).iter().any(|error|error.is("BIRTH_JOBS_INCOMPLETE_HISTORY")));
    f.owner.outputs[0].effects[last].verified=true;f.owner.outputs[0].effects[last].result=Some(Err(libc::EIO));
    assert!(f.owner.observations(true).iter().any(|error|error.is("BIRTH_JOBS_INCOMPLETE_HISTORY")));
    no_authority(&f.base.state);
}
