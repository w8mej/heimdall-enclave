//! Private original-created DIRECTORY metadata mechanics, with retained history.
//!
//! Native mechanics are reachable only with actual SOFTWARE and startup EX
//! owners. The consuming native child must keep genuine account/native gates,
//! SAME borrowed host guard and actual inhibited EX throughout the operation.
//! Both real retained owners supply immutable denial-only directory identities;
//! no caller report, empty set or fixture can authorize native preparation.
//! This child cannot construct a native birth or inactivity token.
//!
//! Original controls/staging/lease/denial, nonce/support/input ancestry and every
//! actual retained-owner directory identity are excluded. Root stays0700. Only
//! directories declared by the real original plan (plus three exact transport
//! parents) are eligible; no regular-file metadata transition exists here.
//! A future wrapper must retain BOTH its actual birth owner and this attempt
//! after every refusal. Neither success nor failure restores/removes any name.

use super::*;
use crate::deploy::target_plan;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Identity { dev:u64, ino:u64 }
impl Identity { fn of(s:&DirStamp)->Self { Self {dev:s.dev,ino:s.ino} } }

// An immutable DENIAL observation, never authority/currentness. Native creation
// queries both actual retained owners; no set/boolean/provider is accepted.
struct RetainedDirectoryExclusions { identities:BTreeSet<Identity> }
impl RetainedDirectoryExclusions {
    fn collect_actual(state:&BirthState,approval:&crate::deploy::target_release::SoftwareApproval,
        lease:&enclave_core::deployment::startup_lease::ExclusiveStartupLease)->Self {
        let identities=state.dirs.values().filter_map(|directory| {
            let identity=Identity::of(&directory.stamp);
            let software=approval.retains_directory_identity(identity.dev,identity.ino);
            let exclusion=lease.retains_directory_identity(identity.dev,identity.ino);
            (software||exclusion).then_some(identity)
        }).collect();
        Self {identities}
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::deploy::target_birth) enum Scope { Payload, Runtime }
#[derive(Clone, Copy, PartialEq, Eq)]
struct Desired { uid:u32, gid:u32, mode:u32 }
impl Desired {
    fn declared(uid:u32,gid:u32,mode:&str)->EnclaveResult<Self> {
        let mode=match mode {"0700"=>0o700,"0755"=>0o755,"2750"=>0o2750,
            _=>fail!(EINVAL,"BIRTH_METADATA_DECLARED_MODE")};
        if uid==u32::MAX||gid==u32::MAX {fail!(EINVAL,"BIRTH_METADATA_DECLARED_OWNER");}
        Ok(Self {uid,gid,mode})
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role { Payload, Runtime, Transport }

struct OwnMetadataPlan {
    target_id:String,descriptor_sha256:String,inventory_sha256:String,plan_sha256:String,
    declarations:BTreeMap<PathBuf,(Desired,Role)>,excluded_paths:BTreeSet<PathBuf>,
}
fn original_plan(state:&BirthState)->EnclaveResult<target_plan::TargetInstallPlan> {
    if state.plan.target.role!=DeploymentRole::DedicatedTest||state.plan.target.profile!=Profile::L2 {
        fail!(EACCES,"BIRTH_METADATA_DEDICATED_L2_REQUIRED");
    }
    let pending=state.pending.as_ref().ok_or_else(||err!(EACCES,"BIRTH_METADATA_DENIAL_REQUIRED"))?;
    if !state.progress.seeds_complete||!state.progress.denial_prepared {
        fail!(EACCES,"BIRTH_METADATA_DENIAL_REQUIRED");
    }
    pending.current(&state.plan)?;
    let plan=target_plan::describe(&state.plan.target,&pending.descriptor_sha256,&pending.bytes)?;
    if !plan.missing_required_files.is_empty() {fail!(EACCES,"BIRTH_METADATA_PACKAGE_INCOMPLETE");}
    Ok(plan)
}
fn plan_hash(plan:&target_plan::TargetInstallPlan)->EnclaveResult<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(plan)
        .map_err(|_|err!(EIO,"BIRTH_METADATA_PLAN_ENCODING"))?)))
}
fn exclusion_paths(state:&BirthState)->EnclaveResult<BTreeSet<PathBuf>> {exclusion_paths_with_owned_removal(state,None)}
fn exclusion_paths_with_owned_removal(state:&BirthState,removal:Option<&denial_handoff::OwnedDenialRemoval>)
    ->EnclaveResult<BTreeSet<PathBuf>> {
    // The actual closed eleven-role parser observes exact original inputs;
    // merely guessing filenames cannot grant a public-mode exception.
    let mut result=BTreeSet::from([state.plan.root.clone()]);
    for path in admit::original_modes_with_owned_removal(state,removal)?.keys().chain([
        &state.plan.target.layout.staging_root,&state.plan.target.layout.support_root]) {
        let mut path=path.as_path();
        loop {
            if !path.starts_with(&state.plan.root) {break;}
            result.insert(path.to_owned());
            if path==state.plan.root {break;}
            path=path.parent().ok_or_else(||err!(EINVAL,"BIRTH_METADATA_PATH"))?;
        }
    }
    Ok(result)
}
fn payload_copy(copy:&target_plan::CopyEntry,plan:&target_plan::TargetInstallPlan)->bool {
    copy.destination!=plan.selected_pins_file&&!copy.destination.starts_with("/Library/LaunchDaemons")
        &&!copy.destination.starts_with("/Library/LaunchAgents")
}
impl OwnMetadataPlan {
    fn build(state:&BirthState,scope:Scope)->EnclaveResult<Self> {
        hidden_root(state)?;
        let plan=original_plan(state)?;let excluded_paths=exclusion_paths(state)?;
        let l=&state.plan.target.layout;let runtime=[&l.socket_root,&l.state_root,&l.audit_root,&l.cas_store_root];
        let mut payload_parents=BTreeSet::new();
        for copy in plan.copies.iter().filter(|copy|payload_copy(copy,&plan)) {
            below(&copy.destination,&state.plan.root)?;
            let mut parent=copy.destination.parent().ok_or_else(||err!(EINVAL,"BIRTH_METADATA_PATH"))?;
            while parent!=state.plan.root {
                payload_parents.insert(parent.to_owned());
                parent=parent.parent().ok_or_else(||err!(EINVAL,"BIRTH_METADATA_PATH"))?;
            }
        }
        let mut declarations=BTreeMap::new();
        for entry in &plan.directories {
            let included=match scope {
                Scope::Payload=>payload_parents.contains(&entry.path),
                Scope::Runtime=>runtime.iter().any(|root|entry.path.starts_with(root)),
            };
            if !included||excluded_paths.contains(&entry.path) {continue;}
            below(&entry.path,&state.plan.root)?;
            let role=match scope {Scope::Payload=>Role::Payload,Scope::Runtime=>Role::Runtime};
            declarations.insert(entry.path.clone(),(Desired::declared(entry.uid,entry.gid,&entry.mode)?,role));
        }
        if scope==Scope::Runtime {
            // Closed transport mapping agreed with runtime-import-next design.
            // Root ownership below future UID702 parents conveys no trust.
            for path in [l.support_root.join("tuf"),l.state_root.join("cas/tuf"),l.state_root.join("cas/tuf/repo")] {
                below(&path,&state.plan.root)?;
                if excluded_paths.contains(&path)||declarations.contains_key(&path) {
                    fail!(EACCES,"BIRTH_METADATA_TRANSPORT_COLLISION");
                }
                declarations.insert(path,(Desired {uid:0,gid:0,mode:0o755},Role::Transport));
            }
        }
        if declarations.is_empty()||declarations.len()>MAX_NODES {fail!(E2BIG,"BIRTH_METADATA_DIRECTORY_BOUND");}
        let mut folded_paths=BTreeSet::new();
        for path in declarations.keys() {
            if normalized_path(path)?!=*path||!folded_paths.insert(folded(path)?)
                ||overlaps(path,&l.staging_root)? {fail!(EACCES,"BIRTH_METADATA_PATH_ALIAS");}
            let key=folded(path)?;
            for cached in state.dirs.keys() {
                // The retained filesystem root cannot alias a strict nonce child.
                if cached.as_path()==Path::new("/") {continue;}
                if cached!=path&&folded(cached)?==key {fail!(EACCES,"BIRTH_METADATA_PATH_ALIAS");}
            }
            for file in state.files.keys() {
                let file=folded(file)?;
                if key==file||key.starts_with(file) {fail!(EACCES,"BIRTH_METADATA_FILE_COLLISION");}
            }
        }
        Ok(Self {target_id:plan.target_id.clone(),descriptor_sha256:plan.deployment_config_sha256.clone(),
            inventory_sha256:plan.artifact_inventory_sha256.clone(),plan_sha256:plan_hash(&plan)?,
            declarations,excluded_paths})
    }
    fn current(&self,state:&BirthState)->EnclaveResult<()> {
        self.binding_current(state)?;hidden_root(state)
    }
    fn binding_current(&self,state:&BirthState)->EnclaveResult<()> {self.binding_current_with_owned_removal(state,None)}
    fn binding_current_with_owned_removal(&self,state:&BirthState,removal:Option<&denial_handoff::OwnedDenialRemoval>)->EnclaveResult<()> {
        let plan=original_plan(state)?;
        if plan.target_id!=self.target_id||plan.deployment_config_sha256!=self.descriptor_sha256
            ||plan.artifact_inventory_sha256!=self.inventory_sha256||plan_hash(&plan)?!=self.plan_sha256
            ||exclusion_paths_with_owned_removal(state,removal)?!=self.excluded_paths {fail!(ESTALE,"BIRTH_METADATA_PLAN_CHANGED");}
        Ok(())
    }
}

// Legacy `private` remains immutable CreatedHere provenance. Capture still
// requires initial root0700; the only production expected-field writer in this
// increment is the closed, currently unexposed, own-syscall path below. Exact
// expected ownership is never inferred from later observed metadata.
pub(super) fn current_created_directory(directory:&Directory,file:&File,p:Protection,links:bool)
    ->EnclaveResult<()> {
    let m=stat(file)?;
    if !directory.private||!m.is_dir()||m.nlink()==0||m.mode()&0o022!=0
        ||!matches!(directory.stamp.mode&0o7777,0o700|0o755|0o2750)
        ||DirStamp::of(&m)!=directory.stamp||(links&&m.nlink()!=directory.links) {
        fail!(ESTALE,"BIRTH_DIRECTORY_CHANGED");
    }
    flags(file,libc::O_RDONLY)?;no_extended_acl(file,p)
}
pub(in crate::deploy::target_birth) fn hidden_root(state:&BirthState)->EnclaveResult<()> {
    let d=state.dirs.get(&state.plan.root).ok_or_else(||err!(EACCES,"BIRTH_METADATA_PRIVATE_ROOT_REQUIRED"))?;
    if !d.private||d.stamp.uid!=state.protection.owner.0||d.stamp.gid!=state.protection.owner.1
        ||d.stamp.mode&0o7777!=0o700 {fail!(EACCES,"BIRTH_METADATA_PRIVATE_ROOT_REQUIRED");}
    d.current(&d.file,state.protection,true)?;
    if let Some(parent)=&d.parent {
        let named=open_at(&state.dirs.get(parent).ok_or_else(||err!(EACCES,"BIRTH_PARENT_NOT_HELD"))?.file,
            &state.plan.root,true)?;d.current(&named,state.protection,true)?;
    }
    Ok(())
}

#[derive(Clone)]
struct Snapshot { stamp:DirStamp,links:u64,modified:(i64,i64),changed:(i64,i64) }
impl Snapshot {
    fn of(file:&File)->EnclaveResult<Self> {
        let m=stat(file)?;
        if !m.is_dir(){fail!(ESTALE,"BIRTH_METADATA_DIRECTORY_CHANGED");}
        Ok(Self {stamp:DirStamp::of(&m),links:m.nlink(),modified:(m.mtime(),m.mtime_nsec()),
            changed:(m.ctime(),m.ctime_nsec())})
    }
}
struct OriginalDirectory { path:PathBuf,stamp:DirStamp,links:u64,fd:i32 }
struct OwnMetadataStep { origin:OriginalDirectory,desired:Desired,expected:DirStamp }
impl OwnMetadataStep {
    fn capture(state:&BirthState,path:&Path,desired:Desired,denied:&RetainedDirectoryExclusions)->EnclaveResult<Self> {
        below(path,&state.plan.root)?;
        let layout=&state.plan.target.layout;
        if layout.support_root.starts_with(path)||overlaps(path,&layout.staging_root)? {
            fail!(EACCES,"BIRTH_METADATA_ORIGINAL_ANCESTRY_EXCLUDED");
        }
        let d=state.dirs.get(path).ok_or_else(||err!(EACCES,"BIRTH_METADATA_OWN_DIRECTORY_REQUIRED"))?;
        if !d.private||!state.progress.created_directories.iter().any(|created|created==path)
            ||d.stamp.uid!=state.protection.owner.0||d.stamp.gid!=state.protection.owner.1
            ||d.stamp.mode&0o7777!=0o700||denied.identities.contains(&Identity::of(&d.stamp)) {
            fail!(EACCES,"BIRTH_METADATA_RETAINED_OR_FOREIGN_DIRECTORY");
        }
        if state.dirs.iter().any(|(other,node)|other!=path&&Identity::of(&node.stamp)==Identity::of(&d.stamp)) {
            fail!(ESTALE,"BIRTH_METADATA_INODE_ALIAS");
        }
        let origin=OriginalDirectory {path:path.to_owned(),stamp:d.stamp.clone(),links:d.links,fd:d.file.as_raw_fd()};
        let result=Self {expected:origin.stamp.clone(),origin,desired};result.current(state,denied)?;Ok(result)
    }
    fn current(&self,state:&BirthState,denied:&RetainedDirectoryExclusions)->EnclaveResult<()> {
        self.current_with_live_directories(state,denied,None,None)
    }
    fn original_binding_current(&self,state:&BirthState,denied:&RetainedDirectoryExclusions)->EnclaveResult<()> {
        let path=&self.origin.path;
        let d=state.dirs.get(path).ok_or_else(||err!(ESTALE,"BIRTH_METADATA_OWN_DIRECTORY_LOST"))?;
        if !d.private||d.file.as_raw_fd()!=self.origin.fd||Identity::of(&d.stamp)!=Identity::of(&self.origin.stamp)
            ||d.stamp!=self.expected||d.links!=self.origin.links
            ||denied.identities.contains(&Identity::of(&self.origin.stamp)) {
            fail!(ESTALE,"BIRTH_METADATA_ORIGIN_CHANGED");
        }
        Ok(())
    }
    fn current_with_live_directories(&self,state:&BirthState,denied:&RetainedDirectoryExclusions,
        removal:Option<&denial_handoff::OwnedDenialRemoval>,live:Option<&live_directories::LiveDirectoryScope>)->EnclaveResult<()> {
        self.original_binding_current(state,denied)?;
        let path=&self.origin.path;let d=&state.dirs[path];
        live_directories::current_directory(state,path,d,&d.file,removal,live)?;
        let parent_path=path.parent().ok_or_else(||err!(EINVAL,"BIRTH_METADATA_PATH"))?;
        let parent=state.dirs.get(parent_path).ok_or_else(||err!(EACCES,"BIRTH_PARENT_NOT_HELD"))?;
        live_directories::current_directory(state,parent_path,parent,&parent.file,removal,live)?;
        let named=open_at(&parent.file,path,true)?;
        live_directories::current_directory(state,path,d,&named,removal,live)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation { Chown, Chmod }
struct SyscallRecord {
    operation:Operation,before:Snapshot,predicted:DirStamp,result:Option<Result<(),i32>>,
    held_after:Option<Snapshot>,named_after:Option<Snapshot>,observation_errors:Vec<EnclaveError>,
    held_confirmed:Option<Snapshot>,named_confirmed:Option<Snapshot>,
    expected_committed:bool,
}
struct SyncRecord { path:PathBuf,error:Option<EnclaveError> }
struct NodeHistory { calls:Vec<SyscallRecord>,syncs:Vec<SyncRecord>,chown_noop:bool,chmod_noop:bool }
struct MetadataFailure { error:EnclaveError,boundary_errors:Vec<EnclaveError>,final_errors:Vec<EnclaveError> }

// These test-only fault choices exercise retention around actual kernel calls;
// they are not callbacks, authority providers or a native-positive test seam.
#[cfg(test)]
#[derive(Clone, Copy)]
enum TestSyscallFault { Before(Operation), AmbiguousAfterSuccess(Operation) }

#[must_use="retain the original birth owner AND this metadata attempt on refusal"]
struct KernelMetadataAttempt {
    steps:Vec<OwnMetadataStep>,denied:RetainedDirectoryExclusions,history:Vec<NodeHistory>,
    complete:bool,poisoned:bool,failure:Option<MetadataFailure>,
    #[cfg(test)] fault:Option<TestSyscallFault>,
}
impl KernelMetadataAttempt {
    fn new(steps:Vec<OwnMetadataStep>,denied:RetainedDirectoryExclusions)->Self {
        let history=steps.iter().map(|_|NodeHistory {calls:Vec::new(),syncs:Vec::new(),chown_noop:false,chmod_noop:false}).collect();
        Self {steps,denied,history,complete:false,poisoned:false,failure:None,#[cfg(test)] fault:None}
    }
    fn completed_history(&self)->EnclaveResult<()> {
        if !self.complete||self.poisoned||self.failure.is_some()||self.steps.is_empty()||self.steps.len()!=self.history.len() {
            fail!(EACCES,"BIRTH_METADATA_NOT_COMPLETE");
        }
        for (step,history) in self.steps.iter().zip(&self.history) {
            let chown=(step.origin.stamp.uid,step.origin.stamp.gid)!=(step.desired.uid,step.desired.gid);
            let chmod=step.origin.stamp.mode&0o7777!=step.desired.mode;
            let operations=[chown.then_some(Operation::Chown),chmod.then_some(Operation::Chmod)]
                .into_iter().flatten().collect::<Vec<_>>();
            if history.chown_noop==chown||history.chmod_noop==chmod||history.calls.len()!=operations.len()
                ||history.syncs.len()!=2 {fail!(ESTALE,"BIRTH_METADATA_COMPLETION_HISTORY");}
            let mut expected=step.origin.stamp.clone();
            for (record,operation) in history.calls.iter().zip(operations) {
                let before=expected.clone();
                match operation {Operation::Chown=>{expected.uid=step.desired.uid;expected.gid=step.desired.gid;},
                    Operation::Chmod=>expected.mode=(expected.mode&!0o7777)|step.desired.mode,}
                if record.operation!=operation||record.before.stamp!=before||record.before.links!=step.origin.links
                    ||record.predicted!=expected||record.result!=Some(Ok(()))||!record.expected_committed
                    ||!record.observation_errors.is_empty() {fail!(ESTALE,"BIRTH_METADATA_COMPLETION_HISTORY");}
                let snapshots=[&record.held_after,&record.named_after,&record.held_confirmed,&record.named_confirmed];
                let mut changed=None;
                for snapshot in snapshots {
                    let snapshot=snapshot.as_ref().ok_or_else(||err!(ESTALE,"BIRTH_METADATA_COMPLETION_HISTORY"))?;
                    if snapshot.stamp!=expected||snapshot.links!=step.origin.links||snapshot.modified!=record.before.modified
                        ||changed.is_some_and(|old|old!=snapshot.changed) {fail!(ESTALE,"BIRTH_METADATA_COMPLETION_HISTORY");}
                    changed=Some(snapshot.changed);
                }
            }
            let parent=step.origin.path.parent().ok_or_else(||err!(ESTALE,"BIRTH_METADATA_COMPLETION_HISTORY"))?;
            if expected!=step.expected||history.syncs[0].path!=step.origin.path||history.syncs[1].path!=parent
                ||history.syncs.iter().any(|sync|sync.error.is_some()) {fail!(ESTALE,"BIRTH_METADATA_COMPLETION_HISTORY");}
        }
        Ok(())
    }
    fn observations(&self,state:&BirthState,plan:Option<&OwnMetadataPlan>,check:&mut impl FnMut()->Vec<EnclaveError>)
        ->Vec<EnclaveError> {
        let mut observed=state.checks(check);
        observed.extend(errors([hidden_root(state)]));
        if let Some(plan)=plan {observed.extend(errors([plan.current(state)]));}
        for step in &self.steps {observed.extend(errors([step.current(state,&self.denied)]));}
        observed.extend(state.checks(check));observed
    }
    fn gate(&self,state:&BirthState,plan:Option<&OwnMetadataPlan>,check:&mut impl FnMut()->Vec<EnclaveError>,
        observed:&mut Vec<EnclaveError>)->EnclaveResult<()> {
        let checks=self.observations(state,plan,check);let result=first(&checks);observed.extend(checks);result
    }
    fn syscall(&mut self,index:usize,operation:Operation,state:&mut BirthState,plan:Option<&OwnMetadataPlan>,
        check:&mut impl FnMut()->Vec<EnclaveError>,observed:&mut Vec<EnclaveError>)->EnclaveResult<()> {
        self.gate(state,plan,check,observed)?;
        let step=&self.steps[index];let path=step.origin.path.clone();let desired=step.desired;
        // Exact last direct checks AFTER all callbacks, immediately before own
        // syscall. No generic snapshot refresh or pathname adoption follows.
        hidden_root(state)?;step.current(state,&self.denied)?;
        let before=Snapshot::of(&state.dirs[&path].file)?;
        if before.stamp!=step.expected||before.links!=step.origin.links {
            fail!(ESTALE,"BIRTH_METADATA_OLD_STAMP_CHANGED");
        }
        let mut predicted=step.expected.clone();
        match operation {Operation::Chown=>{predicted.uid=desired.uid;predicted.gid=desired.gid;},
            Operation::Chmod=>predicted.mode=(predicted.mode&!0o7777)|desired.mode,}
        self.history[index].calls.push(SyscallRecord {operation,before,predicted:predicted.clone(),result:None,
            held_after:None,named_after:None,observation_errors:Vec::new(),held_confirmed:None,named_confirmed:None,
            expected_committed:false});
        state.progress.uncertain_effects=true;
        let fd=state.dirs[&path].file.as_raw_fd();
        #[cfg(test)]
        let fail_before=matches!(self.fault,Some(TestSyscallFault::Before(kind))if kind==operation);
        #[cfg(not(test))]
        let fail_before=false;
        let mut result=if fail_before {Err(libc::EIO)}else {
            let status=match operation {
                Operation::Chown=>unsafe {libc::fchown(fd,desired.uid,desired.gid)},
                Operation::Chmod=>unsafe {libc::fchmod(fd,desired.mode as libc::mode_t)},
            };
            if status==0 {Ok(())}else {Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO))}
        };
        #[cfg(test)]
        if result.is_ok()&&matches!(self.fault,Some(TestSyscallFault::AmbiguousAfterSuccess(kind))if kind==operation) {
            result=Err(libc::EIO);
        }
        let record=self.history[index].calls.last_mut().expect("installed before effect");record.result=Some(result);
        let held=Snapshot::of(&state.dirs[&path].file);
        let parent=path.parent().and_then(|p|state.dirs.get(p));
        let named=parent.ok_or_else(||err!(EACCES,"BIRTH_PARENT_NOT_HELD"))
            .and_then(|parent|open_at(&parent.file,&path,true));
        let named_snapshot=named.as_ref().map_err(Clone::clone).and_then(Snapshot::of);
        for value in [&held,&named_snapshot] {if let Err(error)=value {record.observation_errors.push(error.clone());}}
        record.held_after=held.ok();record.named_after=named_snapshot.ok();
        let exact=|s:&Snapshot|s.stamp==predicted&&s.links==record.before.links
            &&s.modified==record.before.modified;
        if record.held_after.as_ref().is_some_and(|s|!exact(s))||record.named_after.as_ref().is_some_and(|s|!exact(s)) {
            record.observation_errors.push(err!(ESTALE,"BIRTH_METADATA_PREDICTED_DELTA_MISMATCH"));
        }
        record.observation_errors.extend(errors([flags(&state.dirs[&path].file,libc::O_RDONLY),
            no_extended_acl(&state.dirs[&path].file,state.protection)]));
        if let Ok(named)=&named {record.observation_errors.extend(errors([flags(named,libc::O_RDONLY),no_extended_acl(named,state.protection)]));}
        // Attribute/flag observations cannot hide a later metadata change.
        // Retain both observations, requiring even post-own-call ctime stable
        // across the read-only validation interval before any expected update.
        let held_confirmed=Snapshot::of(&state.dirs[&path].file);
        let named_confirmed=named.as_ref().map_err(Clone::clone).and_then(Snapshot::of);
        for value in [&held_confirmed,&named_confirmed] {if let Err(error)=value {record.observation_errors.push(error.clone());}}
        record.held_confirmed=held_confirmed.ok();record.named_confirmed=named_confirmed.ok();
        let stable=|a:&Snapshot,b:&Snapshot|a.stamp==b.stamp&&a.links==b.links&&a.modified==b.modified&&a.changed==b.changed;
        let held_stable=record.held_after.as_ref().zip(record.held_confirmed.as_ref()).is_some_and(|(a,b)|stable(a,b));
        let named_stable=record.named_after.as_ref().zip(record.named_confirmed.as_ref()).is_some_and(|(a,b)|stable(a,b));
        if !held_stable||!named_stable {record.observation_errors.push(err!(ESTALE,"BIRTH_METADATA_POST_STAMP_CHANGED"));}
        let verified=result.is_ok()&&held_stable&&named_stable&&record.observation_errors.is_empty();
        if verified {
            // Only predicted fields from this successful own syscall. Dev/ino,
            // private provenance and nlink are NEVER copied from a later stat.
            let d=state.dirs.get_mut(&path).expect("retained original");
            d.stamp.uid=predicted.uid;d.stamp.gid=predicted.gid;d.stamp.mode=predicted.mode;
            let expected=&mut self.steps[index].expected;
            expected.uid=predicted.uid;expected.gid=predicted.gid;expected.mode=predicted.mode;
            record.expected_committed=true;
        }
        observed.extend(record.observation_errors.iter().cloned());
        let syscall=result.map_err(|_|err!(EACCES,"BIRTH_METADATA_SYSCALL_FAILED"));
        let verification=first(&record.observation_errors);
        let post=self.gate(state,plan,check,observed);
        syscall?;verification?;post
    }
    fn one(&mut self,index:usize,state:&mut BirthState,plan:Option<&OwnMetadataPlan>,
        check:&mut impl FnMut()->Vec<EnclaveError>,observed:&mut Vec<EnclaveError>,
        sync:&mut impl FnMut(&File)->EnclaveResult<()>)->EnclaveResult<()> {
        self.gate(state,plan,check,observed)?;
        let desired=self.steps[index].desired;let expected=&self.steps[index].expected;
        if (expected.uid,expected.gid)!=(desired.uid,desired.gid) {
            // Original entry is root0700; no set-ID bits may be installed
            // before chown. Children must already be complete before apply.
            if expected.mode&0o7777!=0o700 {fail!(EACCES,"BIRTH_METADATA_CHOWN_ORDER");}
            self.syscall(index,Operation::Chown,state,plan,check,observed)?;
        }else {self.history[index].chown_noop=true;}
        if self.steps[index].expected.mode&0o7777!=desired.mode {
            self.syscall(index,Operation::Chmod,state,plan,check,observed)?;
        }else {self.history[index].chmod_noop=true;}
        let path=self.steps[index].origin.path.clone();
        let parent=path.parent().ok_or_else(||err!(EINVAL,"BIRTH_METADATA_PATH"))?.to_owned();
        for path in [path,parent] {
            self.gate(state,plan,check,observed)?;
            let result=sync(&state.dirs[&path].file);
            self.history[index].syncs.push(SyncRecord {path:path.clone(),error:result.as_ref().err().cloned()});
            if result.is_ok(){state.progress.synced.push(path);}
            let post=self.gate(state,plan,check,observed);result?;post?;
        }
        Ok(())
    }
    fn apply(&mut self,state:&mut BirthState,plan:Option<&OwnMetadataPlan>,check:&mut impl FnMut()->Vec<EnclaveError>,
        sync:&mut impl FnMut(&File)->EnclaveResult<()>)->EnclaveResult<()> {
        let mut boundary_errors=Vec::new();state.progress.operation="prepare_private_directory_metadata";state.progress.complete=false;
        let operation=(|| {
            if self.poisoned||state.poisoned {fail!(EACCES,"BIRTH_METADATA_OWNER_POISONED");}
            if self.complete {fail!(EALREADY,"BIRTH_METADATA_ALREADY_APPLIED");}
            self.gate(state,plan,check,&mut boundary_errors)?;
            for index in 0..self.steps.len(){self.one(index,state,plan,check,&mut boundary_errors,sync)?;}
            Ok(())
        })();
        let mut final_errors=self.observations(state,plan,check);
        final_errors.extend(self.observations(state,plan,check));
        match operation.err().or_else(||final_errors.first().cloned()) {
            Some(error)=>{
                self.poisoned=true;state.poisoned=true;state.progress.uncertain_effects=true;
                if let Some(original)=&mut self.failure {
                    // A private accidental second call cannot erase the first
                    // refusal or its available effect/error history.
                    original.boundary_errors.push(error.clone());
                    original.boundary_errors.extend(boundary_errors);
                    original.final_errors.extend(final_errors);
                }else {self.failure=Some(MetadataFailure {error:error.clone(),boundary_errors,final_errors});}
                Err(error)
            },
            None=>{self.complete=true;state.progress.uncertain_effects=false;Ok(())},
        }
    }
}

#[must_use="retain actual original birth owner with this immutable origin/syscall ledger"]
pub(in crate::deploy::target_birth) struct OwnMetadataAttempt { plan:OwnMetadataPlan,kernel:KernelMetadataAttempt }
impl OwnMetadataAttempt {
    // Private software mechanics only; the native subtree can obtain an
    // attempt exclusively through prepare_actual with BOTH genuine owners.
    fn prepare(state:&BirthState,scope:Scope,denied:RetainedDirectoryExclusions)->EnclaveResult<Self> {
        let plan=OwnMetadataPlan::build(state,scope)?;
        let mut paths=plan.declarations.keys().cloned().collect::<Vec<_>>();
        paths.sort_by(|a,b|b.components().count().cmp(&a.components().count()).then(a.cmp(b)));
        let steps=paths.iter().map(|path|OwnMetadataStep::capture(state,path,plan.declarations[path].0,&denied))
            .collect::<EnclaveResult<Vec<_>>>()?;
        Ok(Self {plan,kernel:KernelMetadataAttempt::new(steps,denied)})
    }
    pub(in crate::deploy::target_birth) fn prepare_actual(state:&BirthState,scope:Scope,
        approval:&crate::deploy::target_release::SoftwareApproval,
        lease:&enclave_core::deployment::startup_lease::ExclusiveStartupLease)->EnclaveResult<Self> {
        require_native_root()?;
        if state.protection.owner!=(0,0)||!state.protection.native_acl {
            fail!(EACCES,"BIRTH_METADATA_ACTUAL_PROTECTION_REQUIRED");
        }
        Self::prepare(state,scope,RetainedDirectoryExclusions::collect_actual(state,approval,lease))
    }
    // The concrete consuming child alone supplies real guard/accounts/software/
    // EX and retained runtime inputs here. The callback is an additional check,
    // never a native constructor; no external caller can construct an attempt.
    pub(in crate::deploy::target_birth) fn apply(&mut self,state:&mut BirthState,check:&mut impl FnMut()->Vec<EnclaveError>,
        sync:&mut impl FnMut(&File)->EnclaveResult<()>)->EnclaveResult<()> {
        self.kernel.apply(state,Some(&self.plan),check,sync)
    }
    /// Read-only original/predicted metadata and source checks. No change,
    /// completion conversion, owner replacement or poison reset is possible.
    pub(in crate::deploy::target_birth) fn observations(&self,state:&BirthState)->Vec<EnclaveError> {
        self.kernel.observations(state,Some(&self.plan),&mut||Vec::new())
    }
    /// Denial-only checks for a later actual event-bearing visibility phase.
    /// The caller separately proves its accepted original root using the real
    /// birth ledger and SAME EX. No caller mode/report replaces that proof.
    /// Existing mutable/apply/observations entry points still require root700.
    pub(in crate::deploy::target_birth) fn retained_completed_observations(&self,state:&BirthState)->Vec<EnclaveError> {
        self.retained_completed_observations_with_owned_removal(state,None)
    }
    pub(in crate::deploy::target_birth) fn retained_completed_observations_with_owned_removal(&self,state:&BirthState,
        removal:Option<&denial_handoff::OwnedDenialRemoval>)->Vec<EnclaveError> {
        self.retained_completed_observations_with_live_directories(state,removal,None)
    }
    pub(in crate::deploy::target_birth) fn retains_excluded_directory_identity(&self,dev:u64,ino:u64)->bool {
        self.kernel.denied.identities.contains(&Identity {dev,ino})
    }
    pub(in crate::deploy::target_birth) fn retained_directory_origin_current(&self,state:&BirthState,path:&Path)->EnclaveResult<bool> {
        self.kernel.completed_history()?;
        match self.kernel.steps.iter().find(|step|step.origin.path==path) {
            Some(step)=>{step.original_binding_current(state,&self.kernel.denied)?;Ok(true)},None=>Ok(false),
        }
    }
    pub(in crate::deploy::target_birth) fn retained_completed_observations_with_live_directories(&self,state:&BirthState,
        removal:Option<&denial_handoff::OwnedDenialRemoval>,live:Option<&live_directories::LiveDirectoryScope>)->Vec<EnclaveError> {
        let mut observed=state.checks_with_content_live_directories(&mut||Vec::new(),true,removal,live);
        observed.extend(errors([self.plan.binding_current_with_owned_removal(state,removal),self.kernel.completed_history()]));
        if self.kernel.steps.len()!=self.plan.declarations.len()||self.kernel.steps.iter().any(|step|
            self.plan.declarations.get(&step.origin.path).is_none_or(|(desired,_)|*desired!=step.desired)) {
            observed.push(err!(ESTALE,"BIRTH_METADATA_COMPLETION_PLAN"));
        }
        for step in &self.kernel.steps {observed.extend(errors([step.current_with_live_directories(state,&self.kernel.denied,removal,live)]));}
        observed.extend(state.checks_with_content_live_directories(&mut||Vec::new(),true,removal,live));observed
    }
    /// Both fixed scopes must be independent before either can change metadata.
    pub(in crate::deploy::target_birth) fn assert_disjoint(&self,other:&Self)->EnclaveResult<()> {
        if self.kernel.steps.iter().any(|step|other.kernel.steps.iter().any(|second|
            step.origin.path==second.origin.path||Identity::of(&step.origin.stamp)==Identity::of(&second.origin.stamp))) {
            fail!(EACCES,"BIRTH_METADATA_SCOPE_ALIAS");
        }
        Ok(())
    }
    /// Borrow retained diagnostics; the actual attempt/history stays owned.
    pub(in crate::deploy::target_birth) fn retained_errors(&self)->Option<(&[EnclaveError],&[EnclaveError])> {
        self.kernel.failure.as_ref().map(|failure|(failure.boundary_errors.as_slice(),failure.final_errors.as_slice()))
    }
}

#[cfg(test)]
#[path="target_birth_metadata_tests.rs"]
mod tests;
