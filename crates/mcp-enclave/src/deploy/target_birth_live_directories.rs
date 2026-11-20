//! Native original-directory observations for actual core output phases.
//! Closed audit5 admission requires actual cleared registration ownership;
//! released17 promotion requires the SAME ledger's actual Dedicated drop.
//! No cache/provenance/history is restamped and no runtime health is proved.
use super::*;
use std::sync::Arc;
use enclave_core::deployment::{CheckedDeploymentTarget,startup_lease::{DirectoryModeChange,PrivateBirthAncestor}};
use crate::deploy::{target_accounts::FixedAccountAdmission,target_release::SoftwareApproval};
use super::{metadata::OwnMetadataAttempt,denial_handoff::OwnedDenialRemoval};

#[derive(Clone,Copy,PartialEq,Eq)]
enum OutputRole { Audit, Socket, State, CasStore, Witness }
struct OutputSpec {path:PathBuf,uid:u32,gid:u32,mode:u32,role:OutputRole}
fn fixed_outputs(target:&DeploymentTarget)->EnclaveResult<Vec<OutputSpec>> {
    let l=&target.layout;let mut result=Vec::new();
    for daemon in crate::ctl::START_ORDER {
        result.push(OutputSpec {path:l.audit_root.join(daemon.dir_name()),uid:daemon.uid(),gid:crate::launchd::JOURNAL_READ_GID,mode:0o2750,role:OutputRole::Audit});
        result.push(OutputSpec {path:l.socket_root.join(daemon.dir_name()),uid:daemon.uid(),gid:daemon.client_gid(),mode:0o2750,role:OutputRole::Socket});
        result.push(OutputSpec {path:l.state_root.join(daemon.dir_name()),uid:daemon.uid(),gid:daemon.gid(),mode:0o700,role:OutputRole::State});
    }
    result.push(OutputSpec {path:l.cas_store_root.clone(),uid:702,gid:8702,mode:0o700,role:OutputRole::CasStore});
    result.push(OutputSpec {path:l.socket_root.join(enclave_core::daemon::WITNESS_SOCKET_DIR),uid:705,
        gid:enclave_core::daemon::WITNESS_CLIENT_GID,mode:0o2750,role:OutputRole::Witness});
    let mut paths=BTreeSet::new();
    for spec in &result {
        if normalized_path(&spec.path)?!=spec.path||!paths.insert(spec.path.clone()) {fail!(EINVAL,"BIRTH_LIVE_DIRECTORY_ROLE_ALIAS");}
    }
    if result.len()!=17 {fail!(EINVAL,"BIRTH_LIVE_DIRECTORY_ROLE_SET");}Ok(result)
}
#[derive(Clone)]
struct OriginalOutput {path:PathBuf,stamp:DirStamp,links:u64,fd:i32,role:OutputRole}
impl OriginalOutput {
    fn current_inode(&self,directory:&Directory,file:&File,protection:Protection)->EnclaveResult<()> {
        if !directory.private||directory.file.as_raw_fd()!=self.fd||directory.stamp!=self.stamp||directory.links!=self.links {
            fail!(ESTALE,"BIRTH_LIVE_DIRECTORY_ORIGINAL_CHANGED");
        }
        directory.current(file,protection,false)
    }
    fn cache_current(&self,state:&BirthState,directory:&Directory)->EnclaveResult<()> {
        if !directory.private||directory.file.as_raw_fd()!=self.fd||directory.stamp!=self.stamp||directory.links!=self.links
            ||!state.progress.created_directories.iter().any(|path|path==&self.path) {
            fail!(ESTALE,"BIRTH_LIVE_DIRECTORY_ORIGINAL_CHANGED");
        }Ok(())
    }
    fn current(&self,state:&BirthState,directory:&Directory,file:&File)->EnclaveResult<()> {
        self.cache_current(state,directory)?;
        // current_created_directory still enforces exact original inode,
        // full owner/mode, positive links, native ACL and readonly FD flags.
        // ONLY live stat.nlink equality is omitted. Cached links stay original.
        self.current_inode(directory,file,state.protection)
    }
}
#[derive(Clone,Copy,PartialEq,Eq)]
enum Phase { Audit, Released }
pub(super) struct LiveDirectoryScope {
    root:PathBuf,target_id:String,descriptor_sha256:String,inventory_sha256:String,
    support_event:Arc<DirectoryModeChange>,nonce_event:Arc<DirectoryModeChange>,
    originals:Vec<OriginalOutput>,phase:Phase,
}
impl LiveDirectoryScope {
    fn binding(&self,state:&BirthState,removal:&OwnedDenialRemoval)->EnclaveResult<()> {
        let pending=state.pending.as_ref().ok_or_else(||err!(EACCES,"BIRTH_LIVE_DIRECTORY_PENDING_REQUIRED"))?;
        if self.root!=state.plan.root||self.target_id!=state.plan.target.target_id
            ||self.descriptor_sha256!=pending.descriptor_sha256||self.inventory_sha256!=pending.inventory_sha256
            ||self.originals.len()!=17||state.plan.target.role!=DeploymentRole::DedicatedTest||state.plan.target.profile!=Profile::L2
            ||!Arc::ptr_eq(&self.support_event,removal.event(PrivateBirthAncestor::SupportRoot))
            ||!Arc::ptr_eq(&self.nonce_event,removal.event(PrivateBirthAncestor::NonceRoot)) {
            fail!(ESTALE,"BIRTH_LIVE_DIRECTORY_PHASE_BINDING");
        }
        let path=state.plan.target.layout.support_root.join(UPGRADE_INHIBITION_LEAF);
        let marker=state.files.get(&path).ok_or_else(||err!(EACCES,"BIRTH_LIVE_DIRECTORY_ORIGINAL_MARKER_REQUIRED"))?;
        removal.current_marker(state,&path,marker)
    }
    fn targets(&self,path:&Path)->bool {
        self.originals.iter().any(|original|original.path==path&&(self.phase==Phase::Released||original.role==OutputRole::Audit))
    }
    fn current(&self,state:&BirthState,path:&Path,directory:&Directory,file:&File,removal:&OwnedDenialRemoval)->EnclaveResult<()> {
        self.binding(state,removal)?;
        let original=self.originals.iter().find(|original|original.path==path&&self.targets(path))
            .ok_or_else(||err!(EACCES,"BIRTH_LIVE_DIRECTORY_EXACT_ROLE_REQUIRED"))?;
        original.current(state,directory,file)
    }
    fn projection_after_actual_release(&self)->Self {
        Self {root:self.root.clone(),target_id:self.target_id.clone(),descriptor_sha256:self.descriptor_sha256.clone(),
            inventory_sha256:self.inventory_sha256.clone(),support_event:Arc::clone(&self.support_event),
            nonce_event:Arc::clone(&self.nonce_event),originals:self.originals.clone(),phase:Phase::Released}
    }
}
// Denial-only live directory hook. None is byte-equivalent to the original
// strict currentness path. A scope never affects an unknown path/descendant.
pub(super) fn current_directory(state:&BirthState,path:&Path,directory:&Directory,file:&File,
    removal:Option<&OwnedDenialRemoval>,scope:Option<&LiveDirectoryScope>)->EnclaveResult<()> {
    match scope.filter(|scope|scope.targets(path)) {
        Some(scope)=>scope.current(state,path,directory,file,
            removal.ok_or_else(||err!(EACCES,"BIRTH_LIVE_DIRECTORY_ACTUAL_REMOVAL_REQUIRED"))?),
        None=>directory.current(file,state.protection,true),
    }
}
struct Refusal {error:EnclaveError,observed:Vec<EnclaveError>}
pub(super) struct LiveDirectoryLedger {
    audit:Option<LiveDirectoryScope>,released:Option<LiveDirectoryScope>,
    pending_audit:Option<LiveDirectoryScope>,pending_released:Option<LiveDirectoryScope>,failures:Vec<Refusal>,poisoned:bool,
}
impl LiveDirectoryLedger {
    pub(super) fn new()->Self {Self {audit:None,released:None,pending_audit:None,pending_released:None,failures:Vec::new(),poisoned:false}}
    pub(super) fn scope(&self)->Option<&LiveDirectoryScope> {self.released.as_ref().or(self.audit.as_ref())}
    pub(super) fn registration_observations(&self,state:&BirthState,removal:Option<&OwnedDenialRemoval>)->Vec<EnclaveError> {
        let mut observed=Vec::new();
        if self.poisoned||self.pending_audit.is_some()||self.pending_released.is_some(){observed.push(err!(EACCES,"BIRTH_LIVE_DIRECTORY_OWNER_POISONED"));}
        if self.audit.is_none(){observed.push(err!(EACCES,"BIRTH_LIVE_DIRECTORY_ACTUAL_AUDIT_ADMISSION_REQUIRED"));}
        match (self.scope(),removal) {
            (Some(scope),Some(removal))=>observed.extend(errors([scope.binding(state,removal)])),
            _=>observed.push(err!(EACCES,"BIRTH_LIVE_DIRECTORY_ACTUAL_PHASE_REQUIRED")),
        }
        for failure in &self.failures {observed.push(failure.error.clone());observed.extend(failure.observed.iter().cloned());}observed
    }
    pub(super) fn released_observations(&self,state:&BirthState,removal:Option<&OwnedDenialRemoval>)->Vec<EnclaveError> {
        let mut observed=self.registration_observations(state,removal);
        if !self.released.as_ref().is_some_and(|scope|scope.phase==Phase::Released) {
            observed.push(err!(EACCES,"BIRTH_LIVE_DIRECTORY_ACTUAL_RELEASE_ADMISSION_REQUIRED"));
        }observed
    }
}
fn context(state:&BirthState)->EnclaveResult<CheckedDeploymentTarget> {
    let checked=state.private_load.as_ref().ok_or_else(||err!(EACCES,"BIRTH_LIVE_DIRECTORY_PRIVATE_LOAD_REQUIRED"))?.checked();
    if state.poisoned||state.protection.owner!=(0,0)||!state.protection.native_acl
        ||checked.target()!=&state.plan.target||checked.config_path()!=state.plan.descriptor
        ||checked.descriptor_sha256()!=hex::encode(Sha256::digest(&state.plan.bytes))
        ||checked.target().role!=DeploymentRole::DedicatedTest||checked.target().profile!=Profile::L2
        ||!enclave_core::deployment::selected().is_some_and(|selected|selected.target()==checked.target()
            &&selected.config_path()==checked.config_path()&&selected.descriptor_sha256()==checked.descriptor_sha256()) {
        fail!(EACCES,"BIRTH_LIVE_DIRECTORY_ACTUAL_CONTEXT_REQUIRED");
    }Ok(checked.clone())
}
fn excluded(state:&BirthState,scope:&LiveDirectoryScope,approval:&SoftwareApproval,metadata:[&OwnMetadataAttempt;2])->Vec<EnclaveError> {
    let mut observed=Vec::new();
    for original in &scope.originals {
        let identity=(original.stamp.dev,original.stamp.ino);
        if approval.retains_directory_identity(identity.0,identity.1)
            ||metadata.iter().any(|attempt|attempt.retains_excluded_directory_identity(identity.0,identity.1)) {
            observed.push(err!(EACCES,"BIRTH_LIVE_DIRECTORY_RETAINED_OWNER_EXCLUSION"));
        }
        let mut origins=0;
        for attempt in metadata {
            match attempt.retained_directory_origin_current(state,&original.path) {
                Ok(true)=>origins+=1,Ok(false)=>(),Err(error)=>observed.push(error),
            }
        }
        if origins!=1 {observed.push(err!(EACCES,"BIRTH_LIVE_DIRECTORY_COMPLETED_ORIGIN_REQUIRED"));}
        match state.dirs.get(&original.path) {
            Some(directory)=>observed.extend(errors([original.cache_current(state,directory)])),
            None=>observed.push(err!(ESTALE,"BIRTH_LIVE_DIRECTORY_ORIGINAL_LOST")),
        }
    }observed
}
fn capture(state:&BirthState,removal:&OwnedDenialRemoval)->EnclaveResult<LiveDirectoryScope> {
    let pending=state.pending.as_ref().ok_or_else(||err!(EACCES,"BIRTH_LIVE_DIRECTORY_PENDING_REQUIRED"))?;
    let plan=crate::deploy::target_plan::describe(&state.plan.target,&pending.descriptor_sha256,&pending.bytes)?;
    let mut originals=Vec::new();let mut inodes=BTreeSet::new();
    for spec in fixed_outputs(&state.plan.target)? {
        let directory=state.dirs.get(&spec.path).ok_or_else(||err!(EACCES,"BIRTH_LIVE_DIRECTORY_ORIGINAL_REQUIRED"))?;
        let mut declarations=plan.directories.iter().filter(|entry|entry.path==spec.path);
        let declaration=declarations.next().ok_or_else(||err!(EACCES,"BIRTH_LIVE_DIRECTORY_DECLARATION_REQUIRED"))?;
        let mode=match declaration.mode.as_str(){"0700"=>0o700,"2750"=>0o2750,_=>fail!(EACCES,"BIRTH_LIVE_DIRECTORY_DECLARED_MODE")};
        if declarations.next().is_some()||(declaration.uid,declaration.gid,mode)!=(spec.uid,spec.gid,spec.mode)
            ||(directory.stamp.uid,directory.stamp.gid,directory.stamp.mode&0o7777)!=(spec.uid,spec.gid,spec.mode)
            ||!directory.private||!state.progress.created_directories.iter().any(|path|path==&spec.path)
            ||!inodes.insert((directory.stamp.dev,directory.stamp.ino))
            ||state.dirs.iter().any(|(path,other)|path!=&spec.path&&(other.stamp.dev,other.stamp.ino)==(directory.stamp.dev,directory.stamp.ino)) {
            fail!(ESTALE,"BIRTH_LIVE_DIRECTORY_ORIGINAL_ROLE_BINDING");
        }
        originals.push(OriginalOutput {path:spec.path,stamp:directory.stamp.clone(),links:directory.links,fd:directory.file.as_raw_fd(),role:spec.role});
    }
    Ok(LiveDirectoryScope {root:state.plan.root.clone(),target_id:state.plan.target.target_id.clone(),
        descriptor_sha256:pending.descriptor_sha256.clone(),inventory_sha256:pending.inventory_sha256.clone(),
        support_event:Arc::clone(removal.event(PrivateBirthAncestor::SupportRoot)),nonce_event:Arc::clone(removal.event(PrivateBirthAncestor::NonceRoot)),
        originals,phase:Phase::Audit})
}
impl NativeDedicatedBirth<'_> {
    // Sole caller: actual cleared-consuming registration, after strict Clear
    // gate and before any real adapter call. All17 snapshots use ORIGINAL
    // cache and completed own metadata; only audit5 initially become live.
    pub(in crate::deploy::target_birth) fn begin_registration_live_directories(&mut self,accounts:&FixedAccountAdmission,
        approval:&mut SoftwareApproval,payload:&OwnMetadataAttempt,runtime:&OwnMetadataAttempt,expiry:&CryptoExpiryObservation)->EnclaveResult<()> {
        let mut observed=Vec::new();let operation=(|| {
            if self.live_directories.audit.is_some()||self.live_directories.pending_audit.is_some()||self.live_directories.poisoned {
                fail!(EALREADY,"BIRTH_LIVE_DIRECTORY_NO_RETRY");
            }
            let checked=context(&self.state)?;let proof=self.denial_removal.proof().ok_or_else(||err!(EACCES,"BIRTH_LIVE_DIRECTORY_ACTUAL_REMOVAL_REQUIRED"))?;
            self.live_directories.pending_audit=Some(capture(&self.state,proof)?);
            let scope=self.live_directories.pending_audit.as_ref().expect("original snapshot retained before later gates");
            observed.extend(errors([require_native_root(),self.guard.assert_held(),accounts.assert_current(&checked,self.guard),approval.assert_current(&checked,self.guard)]));
            observed.extend(excluded(&self.state,scope,approval,[payload,runtime]));
            observed.extend(self.state.checks_with_content_owned_removal(&mut||errors([require_native_root(),self.guard.assert_held()]),true,Some(proof)));
            for attempt in [payload,runtime] {observed.extend(attempt.retained_completed_observations_with_owned_removal(&self.state,Some(proof)));}
            observed.extend(self.directory_events.current_with_owned_removal(&self.state,Some(proof)));
            observed.extend(self.denial_removal.current(&self.state,&checked));
            observed.extend(errors([context(&self.state).map(|_|()),accounts.assert_current(&checked,self.guard),approval.assert_current(&checked,self.guard),self.guard.assert_held(),require_native_root()]));
            let current=first(&observed);current?;expiry.current()?;
            self.live_directories.audit=self.live_directories.pending_audit.take();Ok(())
        })();
        if let Err(error)=&operation {self.live_directories.poisoned=true;self.state.poisoned=true;
            self.live_directories.failures.push(Refusal {error:error.clone(),observed});}operation
    }
    // Sole caller: actual terminal release child AFTER native take/drop. No
    // strict runtime nlink gate runs here; originals/exclusions stay immutable.
    pub(in crate::deploy::target_birth) fn observe_released_live_directories(&mut self,accounts:&FixedAccountAdmission,
        approval:&mut SoftwareApproval,payload:&OwnMetadataAttempt,runtime:&OwnMetadataAttempt,expiry:&CryptoExpiryObservation)->EnclaveResult<()> {
        let mut observed=Vec::new();let operation=(|| {
            if self.live_directories.released.is_some()||self.live_directories.pending_released.is_some()||self.live_directories.poisoned {
                fail!(EALREADY,"BIRTH_LIVE_DIRECTORY_NO_RETRY");
            }
            let checked=context(&self.state)?;
            observed.extend(self.denial_removal.current_after_release(&self.state,&checked));
            let proof=self.denial_removal.proof().ok_or_else(||err!(EACCES,"BIRTH_LIVE_DIRECTORY_ACTUAL_REMOVAL_REQUIRED"))?;
            observed.extend(self.live_directories.registration_observations(&self.state,Some(proof)));
            let audit=self.live_directories.audit.as_ref().ok_or_else(||err!(EACCES,"BIRTH_LIVE_DIRECTORY_ACTUAL_AUDIT_ADMISSION_REQUIRED"))?;
            self.live_directories.pending_released=Some(audit.projection_after_actual_release());
            let scope=self.live_directories.pending_released.as_ref().expect("original projection retained before later gates");
            observed.extend(excluded(&self.state,scope,approval,[payload,runtime]));
            observed.extend(self.state.checks_with_content_live_directories(&mut||errors([require_native_root(),self.guard.assert_held()]),true,Some(proof),Some(scope)));
            for attempt in [payload,runtime] {observed.extend(attempt.retained_completed_observations_with_live_directories(&self.state,Some(proof),Some(scope)));}
            observed.extend(self.directory_events.current_with_owned_removal(&self.state,Some(proof)));
            observed.extend(errors([require_native_root(),self.guard.assert_held(),context(&self.state).map(|_|()),
                accounts.assert_current(&checked,self.guard),approval.assert_current(&checked,self.guard)]));
            observed.extend(self.denial_removal.current_after_release(&self.state,&checked));
            let current=first(&observed);current?;expiry.current()?;
            self.live_directories.released=self.live_directories.pending_released.take();Ok(())
        })();
        if let Err(error)=&operation {self.live_directories.poisoned=true;self.state.poisoned=true;
            self.live_directories.failures.push(Refusal {error:error.clone(),observed});}operation
    }
}

#[cfg(test)]
#[path="target_birth_live_directories_tests.rs"]
mod tests;
