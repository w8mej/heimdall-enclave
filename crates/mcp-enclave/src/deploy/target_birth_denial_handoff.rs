//! Private original-marker unlink mechanics and native-only phase vocabulary.
//! The sole production caller is the concrete consuming NativeVisibleBirth
//! child, after its full durable-jobs/accepted-events readiness gate. This
//! private bridge retains actual EX immediately and independently binds the
//! original birth, both actual accepted events and real native owners.
//! Generic real-kernel SOFTWARE observations cannot construct that native proof.
//! Original SeedFile/stamp/bytes stay cached; no disappearance becomes success.
use super::*;
use std::sync::Arc;
use enclave_core::deployment::{self,CheckedDeploymentTarget,startup_lease::{DirectoryModeChange,
    DedicatedStartupLease,DedicatedLeaseTransitionFailure,ExclusiveStartupLease,PrivateBirthAncestor}};
use crate::deploy::{target_accounts::FixedAccountAdmission,target_release::SoftwareApproval};
use crate::ctl::{HeldPaths,HeldFile};

const MAX_MARKER_BYTES:usize=64*1024;
fn copy_stamp(s:&FileStamp)->FileStamp {FileStamp {directory:s.directory.clone(),links:s.links,len:s.len,
    modified:s.modified,changed:s.changed}}
fn exact_bytes(file:&File,expected:&[u8])->EnclaveResult<()> {
    if expected.is_empty()||expected.len()>MAX_MARKER_BYTES {fail!(E2BIG,"BIRTH_DENIAL_BYTES_BOUND");}
    let mut bytes=vec![0;expected.len()];let mut offset=0;
    while offset<bytes.len() {
        let count=loop {match file.read_at(&mut bytes[offset..],offset as u64) {
            Err(error) if error.kind()==std::io::ErrorKind::Interrupted=>continue,
            result=>break result.map_err(|_|err!(EIO,"BIRTH_DENIAL_READ"))?,
        }};
        if count==0 {fail!(ESTALE,"BIRTH_DENIAL_TRUNCATED");}offset+=count;
    }
    let mut extra=[0];
    if file.read_at(&mut extra,expected.len()as u64).map_err(|_|err!(EIO,"BIRTH_DENIAL_READ"))?!=0||bytes!=expected {
        fail!(ESTALE,"BIRTH_DENIAL_BYTES_CHANGED");
    }Ok(())
}
fn absent(parent:&File,path:&Path)->EnclaveResult<()> {
    let leaf=name(path)?;let mut metadata=std::mem::MaybeUninit::<libc::stat>::uninit();
    let result=unsafe{libc::fstatat(parent.as_raw_fd(),leaf.as_ptr(),metadata.as_mut_ptr(),libc::AT_SYMLINK_NOFOLLOW)};
    if result==0 {fail!(EALREADY,"BIRTH_DENIAL_NAME_PRESENT");}
    if std::io::Error::last_os_error().raw_os_error()!=Some(libc::ENOENT) {fail!(EACCES,"BIRTH_DENIAL_ABSENCE_UNCERTAIN");}
    Ok(())
}
fn parent_links_after(before:u64,after:u64)->EnclaveResult<()> {
    // APFS can count a regular entry in directory nlink; other supported
    // filesystems leave directory nlink unchanged. No larger drift is adopted.
    if before==0||after==0||!(after==before||before.checked_sub(1)==Some(after)) {
        fail!(ESTALE,"BIRTH_DENIAL_PARENT_LINK_DELTA");
    }Ok(())
}
struct ParentSnapshot {stamp:DirStamp,links:u64,modified:(i64,i64),changed:(i64,i64)}
impl ParentSnapshot {
    fn of(file:&File)->EnclaveResult<Self> {
        let m=stat(file)?;if !m.is_dir(){fail!(ESTALE,"BIRTH_DENIAL_PARENT_CHANGED");}
        Ok(Self {stamp:DirStamp::of(&m),links:m.nlink(),modified:(m.mtime(),m.mtime_nsec()),changed:(m.ctime(),m.ctime_nsec())})
    }
    fn same(&self,other:&Self)->bool {self.stamp==other.stamp&&self.links==other.links
        &&self.modified==other.modified&&self.changed==other.changed}
}
struct RemovalOriginal {
    path:PathBuf,fd:i32,parent_fd:i32,stamp:FileStamp,parent:ParentSnapshot,bytes:Vec<u8>,protection:Protection,
}
impl RemovalOriginal {
    fn capture(parent:&File,file:&File,path:&Path,bytes:&[u8],protection:Protection)->EnclaveResult<Self> {
        if bytes.is_empty()||bytes.len()>MAX_MARKER_BYTES {fail!(E2BIG,"BIRTH_DENIAL_BYTES_BOUND");}
        if path.file_name()!=Some(std::ffi::OsStr::new(UPGRADE_INHIBITION_LEAF)) {
            fail!(EACCES,"BIRTH_DENIAL_FIXED_LEAF_REQUIRED");
        }
        let stamp=FileStamp::of(&stat(file)?);let parent_stamp=ParentSnapshot::of(parent)?;
        let original=Self {path:path.to_owned(),fd:file.as_raw_fd(),parent_fd:parent.as_raw_fd(),stamp,parent:parent_stamp,
            bytes:bytes.to_owned(),protection};original.linked(parent,file)?;Ok(original)
    }
    fn parent_identity(&self,parent:&File)->EnclaveResult<()> {
        let m=stat(parent)?;
        if parent.as_raw_fd()!=self.parent_fd||DirStamp::of(&m)!=self.parent.stamp
            ||!m.is_dir()||m.uid()!=self.protection.owner.0||m.gid()!=self.protection.owner.1||m.mode()&0o022!=0 {
            fail!(ESTALE,"BIRTH_DENIAL_PARENT_CHANGED");
        }
        flags(parent,libc::O_RDONLY)?;no_extended_acl(parent,self.protection)
    }
    fn linked(&self,parent:&File,file:&File)->EnclaveResult<()> {
        self.parent_identity(parent)?;
        if !ParentSnapshot::of(parent)?.same(&self.parent) {fail!(ESTALE,"BIRTH_DENIAL_PARENT_CHANGED");}
        if file.as_raw_fd()!=self.fd||self.stamp.links!=1||self.stamp.directory.uid!=self.protection.owner.0
            ||self.stamp.directory.gid!=self.protection.owner.1||self.stamp.directory.mode!=(libc::S_IFREG as u32|0o600)
            ||self.stamp.len!=self.bytes.len()as u64||FileStamp::of(&stat(file)?)!=self.stamp {
            fail!(ESTALE,"BIRTH_DENIAL_ORIGINAL_CHANGED");
        }
        flags(file,libc::O_RDONLY)?;no_extended_acl(file,self.protection)?;
        let named=open_at(parent,&self.path,false)?;
        if FileStamp::of(&stat(&named)?)!=self.stamp {fail!(ESTALE,"BIRTH_DENIAL_NAMED_CHANGED");}
        flags(&named,libc::O_RDONLY)?;no_extended_acl(&named,self.protection)?;
        exact_bytes(file,&self.bytes)?;exact_bytes(&named,&self.bytes)?;
        if FileStamp::of(&stat(file)?)!=self.stamp||FileStamp::of(&stat(&named)?)!=self.stamp {
            fail!(ESTALE,"BIRTH_DENIAL_ORIGINAL_CHANGED");
        }Ok(())
    }
}
// Actual kernel observations only. This is deliberately NOT OwnedDenialRemoval
// and cannot authorize a protected birth phase, visibility or lease handoff.
struct RemovedObservation {stamp:FileStamp,parent:ParentSnapshot}
struct UnlinkRecord {
    attempted:bool,result:Option<Result<(),i32>>,held_after:Option<FileStamp>,parent_after:Option<ParentSnapshot>,
    observation_errors:Vec<EnclaveError>,verified:bool,
}
struct RemovalSync {parent:bool,error:Option<EnclaveError>}
struct KernelRemovalFailure {error:EnclaveError,boundary_errors:Vec<EnclaveError>,final_errors:Vec<EnclaveError>}
struct KernelRemovalAttempt {
    original:RemovalOriginal,record:UnlinkRecord,removed:Option<RemovedObservation>,syncs:Vec<RemovalSync>,
    complete:bool,poisoned:bool,failure:Option<KernelRemovalFailure>,
    #[cfg(test)] ambiguous_unlink:bool,
}
impl KernelRemovalAttempt {
    fn new(original:RemovalOriginal)->Self {Self {original,record:UnlinkRecord {attempted:false,result:None,
        held_after:None,parent_after:None,observation_errors:Vec::new(),verified:false},removed:None,syncs:Vec::new(),
        complete:false,poisoned:false,failure:None,#[cfg(test)] ambiguous_unlink:false}}
    fn removed_current(&self,parent:&File,file:&File)->EnclaveResult<()> {
        let removed=self.removed.as_ref().ok_or_else(||err!(ESTALE,"BIRTH_DENIAL_REMOVAL_UNVERIFIED"))?;
        self.original.parent_identity(parent)?;
        if file.as_raw_fd()!=self.original.fd||FileStamp::of(&stat(file)?)!=removed.stamp
            ||!ParentSnapshot::of(parent)?.same(&removed.parent) {fail!(ESTALE,"BIRTH_DENIAL_REMOVED_CHANGED");}
        flags(file,libc::O_RDONLY)?;no_extended_acl(file,self.original.protection)?;
        exact_bytes(file,&self.original.bytes)?;absent(parent,&self.original.path)?;
        if FileStamp::of(&stat(file)?)!=removed.stamp||!ParentSnapshot::of(parent)?.same(&removed.parent) {
            fail!(ESTALE,"BIRTH_DENIAL_REMOVED_CHANGED");
        }Ok(())
    }
    fn observations(&self,parent:&File,file:&File,check:&mut impl FnMut()->Vec<EnclaveError>)->Vec<EnclaveError> {
        let mut observed=check();
        let current=if self.record.result==Some(Ok(())){self.removed_current(parent,file)}else{self.original.linked(parent,file)};
        observed.extend(errors([current,self.original.parent_identity(parent),flags(file,libc::O_RDONLY),
            no_extended_acl(file,self.original.protection),exact_bytes(file,&self.original.bytes)]));
        if self.record.result==Some(Ok(())){observed.extend(errors([absent(parent,&self.original.path)]));}
        observed.extend(check());observed
    }
    fn gate(&self,parent:&File,file:&File,check:&mut impl FnMut()->Vec<EnclaveError>,observed:&mut Vec<EnclaveError>)->EnclaveResult<()> {
        let checks=self.observations(parent,file,check);let current=first(&checks);observed.extend(checks);current
    }
    fn observe_unlink(&mut self,parent:&File,file:&File)->EnclaveResult<()> {
        let held=FileStamp::of(&stat(file)?);self.record.held_after=Some(copy_stamp(&held));
        let after=ParentSnapshot::of(parent)?;
        self.record.parent_after=Some(ParentSnapshot {stamp:after.stamp.clone(),links:after.links,modified:after.modified,changed:after.changed});
        let original=&self.original;
        original.parent_identity(parent)?;
        if file.as_raw_fd()!=original.fd||held.directory!=original.stamp.directory||held.len!=original.stamp.len
            ||held.modified!=original.stamp.modified||held.links!=0 {fail!(ESTALE,"BIRTH_DENIAL_UNLINK_DELTA");}
        parent_links_after(original.parent.links,after.links)?;
        flags(file,libc::O_RDONLY)?;no_extended_acl(file,original.protection)?;exact_bytes(file,&original.bytes)?;
        absent(parent,&original.path)?;
        if FileStamp::of(&stat(file)?)!=held||!ParentSnapshot::of(parent)?.same(&after) {fail!(ESTALE,"BIRTH_DENIAL_UNLINK_UNSTABLE");}
        self.removed=Some(RemovedObservation {stamp:held,parent:after});self.record.verified=true;Ok(())
    }
    fn apply(&mut self,parent:&File,file:&File,check:&mut impl FnMut()->Vec<EnclaveError>,
        sync:&mut impl FnMut(&File)->EnclaveResult<()>)->EnclaveResult<()> {
        self.apply_with_endpoint(parent,file,check,sync,&mut||Ok(()))
    }
    fn apply_with_endpoint(&mut self,parent:&File,file:&File,check:&mut impl FnMut()->Vec<EnclaveError>,
        sync:&mut impl FnMut(&File)->EnclaveResult<()>,endpoint:&mut impl FnMut()->EnclaveResult<()>)->EnclaveResult<()> {
        let mut boundary_errors=Vec::new();
        let operation=(|| {
            if self.poisoned {fail!(EACCES,"BIRTH_DENIAL_REMOVAL_POISONED");}
            if self.record.attempted||self.complete {fail!(EALREADY,"BIRTH_DENIAL_REMOVAL_NO_RETRY");}
            self.gate(parent,file,check,&mut boundary_errors)?;
            self.gate(parent,file,check,&mut boundary_errors)?;
            // Last original held+named/parent/bytes check after callbacks.
            self.original.linked(parent,file)?;let leaf=name(&self.original.path)?;endpoint()?;
            self.record.attempted=true;
            let status=unsafe{libc::unlinkat(parent.as_raw_fd(),leaf.as_ptr(),0)};
            let result=if status==0 {Ok(())}else{Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO))};
            #[cfg(test)]
            let result=if result.is_ok()&&self.ambiguous_unlink {Err(libc::EIO)}else{result};
            self.record.result=Some(result);
            // Observe both original inode and name even when syscall refused.
            // Only actual successful unlink with exact delta installs a
            // SOFTWARE observation, never a native ownership/absence proof.
            match stat(file) {Ok(m)=>self.record.held_after=Some(FileStamp::of(&m)),Err(error)=>self.record.observation_errors.push(error)}
            match ParentSnapshot::of(parent) {Ok(m)=>self.record.parent_after=Some(m),Err(error)=>self.record.observation_errors.push(error)}
            if result.is_ok() {let observation=self.observe_unlink(parent,file);
                if let Err(error)=&observation {self.record.observation_errors.push(error.clone());}
                observation?;
            }
            result.map_err(|_|err!(EIO,"BIRTH_DENIAL_UNLINK_FAILED"))?;
            self.gate(parent,file,check,&mut boundary_errors)?;
            for is_parent in [false,true] {
                self.gate(parent,file,check,&mut boundary_errors)?;
                endpoint()?;let result=sync(if is_parent{parent}else{file});
                self.syncs.push(RemovalSync {parent:is_parent,error:result.as_ref().err().cloned()});
                let post=self.gate(parent,file,check,&mut boundary_errors);result?;post?;
            }
            Ok(())
        })();
        let mut final_errors=self.observations(parent,file,check);final_errors.extend(self.observations(parent,file,check));
        final_errors.extend(errors([endpoint()]));
        match operation.err().or_else(||final_errors.first().cloned()) {
            Some(error)=>{self.poisoned=true;
                if let Some(failure)=&mut self.failure {failure.boundary_errors.push(error.clone());
                    failure.boundary_errors.extend(boundary_errors);failure.final_errors.extend(final_errors);}
                else{self.failure=Some(KernelRemovalFailure {error:error.clone(),boundary_errors,final_errors});}Err(error)},
            None=>{self.complete=true;Ok(())},
        }
    }
}

// Native phase proof. Only the concrete native bridge below constructs this,
// after complete own kernel history AND actual birth/event/SAME EX binding.
pub(super) struct OwnedDenialRemoval {
    path:PathBuf,root:PathBuf,target_id:String,descriptor_sha256:String,inventory_sha256:String,
    fd:i32,parent_fd:i32,linked:FileStamp,removed:FileStamp,bytes:Vec<u8>,parent_stamp:DirStamp,
    parent_links_before:u64,parent_links_after:u64,durable:bool,
    support_event:Arc<DirectoryModeChange>,nonce_event:Arc<DirectoryModeChange>,
}
impl OwnedDenialRemoval {
    pub(super) fn targets(&self,path:&Path)->bool {self.path==path}
    pub(super) fn event(&self,role:PrivateBirthAncestor)->&Arc<DirectoryModeChange> {
        match role {PrivateBirthAncestor::SupportRoot=>&self.support_event,PrivateBirthAncestor::NonceRoot=>&self.nonce_event}
    }
    pub(super) fn current_marker(&self,state:&BirthState,path:&Path,marker:&SeedFile)->EnclaveResult<()> {
        let pending=state.pending.as_ref().ok_or_else(||err!(EACCES,"BIRTH_DENIAL_PENDING_REQUIRED"))?;
        let expected=state.plan.target.layout.support_root.join(UPGRADE_INHIBITION_LEAF);
        if !self.durable||state.protection.owner!=(0,0)||!state.protection.native_acl
            ||self.path!=expected||path!=expected||self.root!=state.plan.root||self.target_id!=state.plan.target.target_id
            ||self.descriptor_sha256!=pending.descriptor_sha256||self.inventory_sha256!=pending.inventory_sha256
            ||state.plan.target.role!=DeploymentRole::DedicatedTest||state.plan.target.profile!=Profile::L2
            ||self.bytes!=pending.marker_bytes(&state.plan)?||marker.stamp!=self.linked||marker.access!=libc::O_RDONLY
            ||marker.file.as_raw_fd()!=self.fd||marker.exact_bytes()!=Some(self.bytes.as_slice())
            ||self.linked.links!=1||self.removed.links!=0||self.linked.directory!=self.removed.directory
            ||self.linked.len!=self.removed.len||self.linked.modified!=self.removed.modified
            ||self.linked.directory.mode!=(libc::S_IFREG as u32|0o600)||self.linked.directory.uid!=0||self.linked.directory.gid!=0 {
            fail!(ESTALE,"BIRTH_DENIAL_OWNED_REMOVAL_BINDING");
        }
        let parent=state.dirs.get(expected.parent().expect("fixed support parent"))
            .ok_or_else(||err!(EACCES,"BIRTH_DENIAL_ORIGINAL_PARENT_REQUIRED"))?;
        if parent.file.as_raw_fd()!=self.parent_fd||parent.stamp!=self.parent_stamp||parent.links!=self.parent_links_after
            ||self.support_event.path()!=state.plan.target.layout.support_root||self.nonce_event.path()!=state.plan.root
            ||self.support_event.ancestor()!=PrivateBirthAncestor::SupportRoot||self.nonce_event.ancestor()!=PrivateBirthAncestor::NonceRoot
            ||!self.support_event.durability_completed()||!self.nonce_event.durability_completed() {
            fail!(ESTALE,"BIRTH_DENIAL_OWNED_PARENT_BINDING");
        }
        parent_links_after(self.parent_links_before,self.parent_links_after)?;
        parent.current(&parent.file,state.protection,true)?;
        let ancestor=parent.parent.as_ref().and_then(|path|state.dirs.get(path))
            .ok_or_else(||err!(EACCES,"BIRTH_DENIAL_ORIGINAL_ANCESTRY_REQUIRED"))?;
        let named=open_at(&ancestor.file,expected.parent().expect("fixed support parent"),true)?;
        parent.current(&named,state.protection,true)?;
        if FileStamp::of(&stat(&marker.file)?)!=self.removed {fail!(ESTALE,"BIRTH_DENIAL_REMOVED_CHANGED");}
        flags(&marker.file,libc::O_RDONLY)?;no_extended_acl(&marker.file,state.protection)?;
        exact_bytes(&marker.file,&self.bytes)?;absent(&parent.file,path)?;
        if FileStamp::of(&stat(&marker.file)?)!=self.removed {fail!(ESTALE,"BIRTH_DENIAL_REMOVED_CHANGED");}Ok(())
    }
    pub(super) fn original_stamp(&self,state:&BirthState,path:&Path,marker:&SeedFile)->EnclaveResult<FileStamp> {
        self.current_marker(state,path,marker)?;Ok(copy_stamp(&self.linked))
    }
    // Typed APFS overlay for an accepted ORIGINAL support event. Its
    // immutable historical original.links never changes; no current stat is
    // accepted as a new expected baseline by this method.
    pub(super) fn expected_parent_links(&self,path:&Path,dev:u64,ino:u64,original_links:u64)->EnclaveResult<Option<u64>> {
        if self.path.parent()!=Some(path){return Ok(None);}
        if !self.durable||self.parent_stamp.dev!=dev||self.parent_stamp.ino!=ino||self.parent_links_before!=original_links {
            fail!(ESTALE,"BIRTH_DENIAL_PARENT_OVERLAY_BINDING");
        }
        parent_links_after(original_links,self.parent_links_after)?;Ok(Some(self.parent_links_after))
    }
}
// Fixed native-only ledger; empty construction is not an effect/readiness
// capability. The concrete Visible consumer and native bridge keep SAME actual
// EX, complete kernel history, proof and dedicated transition in this owner.
pub(super) struct DenialRemovalLedger {
    proof:Option<OwnedDenialRemoval>,attempt:Option<KernelRemovalAttempt>,
    exclusive:Option<ExclusiveStartupLease>,dedicated:Option<DedicatedStartupLease>,
    transition_failure:Option<DedicatedLeaseTransitionFailure>,poisoned:bool,
    release:Option<DedicatedReleaseRecord>,release_failure:Option<DedicatedReleaseFailure>,
}
impl DenialRemovalLedger {
    pub(super) fn new()->Self {Self {proof:None,attempt:None,exclusive:None,dedicated:None,transition_failure:None,poisoned:false,
        release:None,release_failure:None}}
    pub(super) fn proof(&self)->Option<&OwnedDenialRemoval> {self.proof.as_ref()}
    pub(super) fn denial_may_have_been_removed(&self)->bool {
        self.attempt.as_ref().is_some_and(|attempt|attempt.record.attempted)
    }
    pub(super) fn current(&mut self,state:&BirthState,checked:&CheckedDeploymentTarget)->Vec<EnclaveError> {
        let mut observed=Vec::new();
        if self.poisoned {observed.push(err!(EACCES,"BIRTH_DENIAL_NATIVE_PHASE_POISONED"));}
        if self.release.is_some(){observed.push(err!(EACCES,"BIRTH_DENIAL_DEDICATED_ALREADY_RELEASED"));}
        if let Some(attempt)=&self.attempt {
            if let Some(failure)=&attempt.failure {
                observed.push(failure.error.clone());observed.extend(failure.boundary_errors.iter().cloned());
                observed.extend(failure.final_errors.iter().cloned());
            }
            observed.extend(attempt.record.observation_errors.iter().cloned());
        }
        if let Some(failure)=&self.transition_failure {observed.push(failure.error.clone());}
        match &self.proof {
            Some(proof)=>{
                let current=state.files.get(&proof.path).ok_or_else(||err!(ESTALE,"BIRTH_DENIAL_ORIGINAL_LOST"))
                    .and_then(|marker|proof.current_marker(state,&proof.path,marker));
                observed.extend(errors([current]));
            },
            None=>observed.push(err!(EACCES,"BIRTH_DENIAL_ACTUAL_REMOVAL_REQUIRED")),
        }
        // NEVER re-enter an inhibited EX observation after an attempted unlink.
        // On refusal its owner remains held, but supplies no current success.
        if self.exclusive.is_some() {observed.push(err!(EACCES,"BIRTH_DENIAL_EX_TRANSITION_INCOMPLETE"));}
        match &mut self.dedicated {
            Some(lease)=>observed.extend(errors([lease.assert_current(checked)])),
            None=>observed.push(err!(EACCES,"BIRTH_DENIAL_SAME_DEDICATED_REQUIRED")),
        }
        if !observed.is_empty(){self.poisoned=true;}observed
    }
}

// Native history only, constructed immediately AFTER actual original
// Dedicated.take and BEFORE intentional drop. `drop_returned` records the
// actual synchronous destructor returning; it is no runtime/health proof or
// independent kernel acknowledgement, and cannot recall delivered startup.
struct DedicatedReleaseRecord {
    path:PathBuf,root:PathBuf,target_id:String,descriptor_sha256:String,inventory_sha256:String,
    marker_fd:i32,parent_fd:i32,support_event:Arc<DirectoryModeChange>,nonce_event:Arc<DirectoryModeChange>,
    drop_returned:bool,
}
struct DedicatedReleaseFailure {error:EnclaveError,boundary_errors:Vec<EnclaveError>,final_errors:Vec<EnclaveError>}
impl DedicatedReleaseRecord {
    fn matches(&self,proof:&OwnedDenialRemoval)->EnclaveResult<()> {
        if !self.drop_returned||self.path!=proof.path||self.root!=proof.root||self.target_id!=proof.target_id
            ||self.descriptor_sha256!=proof.descriptor_sha256||self.inventory_sha256!=proof.inventory_sha256
            ||self.marker_fd!=proof.fd||self.parent_fd!=proof.parent_fd
            ||!Arc::ptr_eq(&self.support_event,&proof.support_event)||!Arc::ptr_eq(&self.nonce_event,&proof.nonce_event) {
            fail!(ESTALE,"BIRTH_DENIAL_ACTUAL_RELEASE_HISTORY_REQUIRED");
        }Ok(())
    }
}
fn release_context(state:&BirthState,checked:&CheckedDeploymentTarget)->EnclaveResult<()> {
    if state.poisoned {fail!(EACCES,"BIRTH_OWNER_POISONED");}
    let actual=native_context(state)?;
    if actual.target()!=checked.target()||actual.config_path()!=checked.config_path()
        ||actual.descriptor_sha256()!=checked.descriptor_sha256() {
        fail!(ESTALE,"BIRTH_DENIAL_RELEASE_CONTEXT_CHANGED");
    }Ok(())
}
impl DenialRemovalLedger {
    pub(super) fn dedicated_release_may_have_occurred(&self)->bool {
        // The record exists only AFTER an actual original-owner take. A mere
        // endpoint entry or precheck failure cannot manufacture this history.
        self.release.is_some()
    }
    /// Read-only proof/history phase after explicit original-owner release.
    /// NEVER calls Dedicated or inhibited EX currentness or reacquires either.
    pub(super) fn current_after_release(&mut self,state:&BirthState,checked:&CheckedDeploymentTarget)->Vec<EnclaveError> {
        let mut observed=errors([require_native_root(),release_context(state,checked)]);
        if self.poisoned {observed.push(err!(EACCES,"BIRTH_DENIAL_NATIVE_PHASE_POISONED"));}
        if self.exclusive.is_some()||self.dedicated.is_some()||self.transition_failure.is_some() {
            observed.push(err!(EACCES,"BIRTH_DENIAL_RELEASE_OWNER_STATE"));
        }
        match (&self.release,&self.proof) {
            (Some(record),Some(proof))=>{
                observed.extend(errors([record.matches(proof)]));
                let current=state.files.get(&proof.path).ok_or_else(||err!(ESTALE,"BIRTH_DENIAL_ORIGINAL_LOST"))
                    .and_then(|marker|proof.current_marker(state,&proof.path,marker));
                observed.extend(errors([current]));
            },
            _=>observed.push(err!(EACCES,"BIRTH_DENIAL_ACTUAL_RELEASE_HISTORY_REQUIRED")),
        }
        if let Some(attempt)=&self.attempt {
            if !attempt.complete||attempt.poisoned||attempt.failure.is_some() {
                observed.push(err!(EACCES,"BIRTH_DENIAL_DURABLE_OWN_HISTORY_REQUIRED"));
            }
            if let Some(failure)=&attempt.failure {
                observed.push(failure.error.clone());observed.extend(failure.boundary_errors.iter().cloned());
                observed.extend(failure.final_errors.iter().cloned());
            }
            observed.extend(attempt.record.observation_errors.iter().cloned());
        }else{observed.push(err!(EACCES,"BIRTH_DENIAL_OWN_UNLINK_REQUIRED"));}
        if let Some(failure)=&self.transition_failure {observed.push(failure.error.clone());}
        if let Some(failure)=&self.release_failure {
            observed.push(failure.error.clone());observed.extend(failure.boundary_errors.iter().cloned());
            observed.extend(failure.final_errors.iter().cloned());
        }
        if !observed.is_empty(){self.poisoned=true;}observed
    }
    /// Sole caller is the concrete actual Registered-consuming terminal child
    /// after its full source/jobs/authority/native/expiry gate. The ledger does
    /// its own actual native proof/guard/context/SAME Dedicated check, then
    /// checks the genuine captured expiry LAST before the one intentional drop.
    pub(super) fn release_same_dedicated(&mut self,state:&BirthState,checked:&CheckedDeploymentTarget,
        guard:&mut HostMaintenanceGuard,expiry:&CryptoExpiryObservation)->EnclaveResult<()> {
        let mut boundary_errors=Vec::new();
        let operation=(|| {
            if self.release.is_some()||self.release_failure.is_some()||self.poisoned {
                fail!(EALREADY,"BIRTH_DENIAL_DEDICATED_RELEASE_NO_RETRY");
            }
            let checks=errors([require_native_root(),guard.assert_held(),release_context(state,checked)]);
            let current=first(&checks);boundary_errors.extend(checks);current?;
            let checks=self.current(state,checked);let current=first(&checks);boundary_errors.extend(checks);current?;
            let proof=self.proof.as_ref().ok_or_else(||err!(EACCES,"BIRTH_DENIAL_ACTUAL_REMOVAL_REQUIRED"))?;
            // Prepare owned historical binding BEFORE the final actual clock.
            // No allocation, native operation or slow observation follows that
            // endpoint before taking the exact original Dedicated owner.
            let record=DedicatedReleaseRecord {path:proof.path.clone(),root:proof.root.clone(),target_id:proof.target_id.clone(),
                descriptor_sha256:proof.descriptor_sha256.clone(),inventory_sha256:proof.inventory_sha256.clone(),
                marker_fd:proof.fd,parent_fd:proof.parent_fd,support_event:Arc::clone(&proof.support_event),
                nonce_event:Arc::clone(&proof.nonce_event),drop_returned:false};
            let checks=errors([require_native_root(),guard.assert_held(),release_context(state,checked),expiry.current()]);
            let current=first(&checks);boundary_errors.extend(checks);current?;
            let lease=self.dedicated.take().expect("same actual Dedicated validated immediately before release");
            self.release=Some(record); // record actual take before intentional drop
            drop(lease);
            self.release.as_mut().expect("actual take recorded before drop").drop_returned=true;
            Ok(())
        })();
        // The original owner is never rechecked/reacquired after drop. A late
        // refusal retains actual release history and cannot undo startup.
        let mut final_errors=errors([require_native_root(),guard.assert_held(),release_context(state,checked)]);
        final_errors.extend(self.current_after_release(state,checked));
        final_errors.extend(errors([guard.assert_held(),require_native_root(),expiry.current()]));
        match operation.err().or_else(||final_errors.first().cloned()) {
            Some(error)=>{
                self.poisoned=true;
                if let Some(failure)=&mut self.release_failure {
                    failure.boundary_errors.push(error.clone());failure.boundary_errors.extend(boundary_errors);
                    failure.final_errors.extend(final_errors);
                }else{self.release_failure=Some(DedicatedReleaseFailure {error:error.clone(),boundary_errors,final_errors});}
                Err(error)
            },
            None=>Ok(()),
        }
    }
}

/// Terminal native refusal. Even an unexpected second incoming owner remains
/// owned here rather than replacing/dropping the original fixed ledger owner.
#[must_use="retain actual denial refusal and any original incoming EX"]
pub(super) struct NativeDenialPhaseFailure {
    pub(super) error:EnclaveError,pub(super) boundary_errors:Vec<EnclaveError>,
    pub(super) final_errors:Vec<EnclaveError>,_incoming:Option<ExclusiveStartupLease>,
}
impl NativeDenialPhaseFailure {
    pub(super) fn retained_checks(&self,_checked:&CheckedDeploymentTarget)->Vec<EnclaveError> {
        // No lease observation: marker absence can be legitimate here. These
        // are retained actual refusals, never a fabricated currentness result.
        let mut observed=vec![self.error.clone()];observed.extend(self.boundary_errors.iter().cloned());
        observed.extend(self.final_errors.iter().cloned());observed
    }
}

fn native_context(state:&BirthState)->EnclaveResult<CheckedDeploymentTarget> {
    if state.protection.owner!=(0,0)||!state.protection.native_acl
        ||state.plan.target.role!=DeploymentRole::DedicatedTest||state.plan.target.profile!=Profile::L2 {
        fail!(EACCES,"BIRTH_DENIAL_NATIVE_DEDICATED_L2_REQUIRED");
    }
    let checked=state.private_load.as_ref().ok_or_else(||err!(EACCES,"BIRTH_DENIAL_PRIVATE_LOAD_REQUIRED"))?.checked();
    if checked.target()!=&state.plan.target||checked.config_path()!=state.plan.descriptor
        ||checked.descriptor_sha256()!=hex::encode(Sha256::digest(&state.plan.bytes))
        ||!deployment::selected().is_some_and(|selected|selected.target()==checked.target()
            &&selected.config_path()==checked.config_path()&&selected.descriptor_sha256()==checked.descriptor_sha256()) {
        fail!(ESTALE,"BIRTH_DENIAL_SELECTED_CONTEXT_CHANGED");
    }Ok(checked.clone())
}
struct NativeExternalInputs<'a> {paths:&'a HeldPaths,record:&'a HeldFile,pin:&'a HeldFile,expiry:&'a CryptoExpiryObservation}
impl NativeExternalInputs<'_> {
    fn observations(&self,state:&BirthState,approval:&SoftwareApproval)->Vec<EnclaveError> {
        let mut observed=errors([self.paths.revalidate()]);let mut identities=BTreeSet::new();
        for held in [self.record,self.pin] {
            let current=(|| {
                let m=stat(held.file())?;
                if !m.is_file()||m.uid()!=0||m.gid()!=0||m.mode()&0o7777!=0o600||m.nlink()!=1||m.len()!=held.size()
                    ||held.path().starts_with(&state.plan.root)||!identities.insert((m.dev(),m.ino()))
                    ||state.files.values().any(|f|(f.stamp.directory.dev,f.stamp.directory.ino)==(m.dev(),m.ino()))
                    ||state.dirs.values().any(|d|(d.stamp.dev,d.stamp.ino)==(m.dev(),m.ino())) {
                    fail!(EACCES,"BIRTH_DENIAL_EXTERNAL_ORIGINAL_BINDING");
                }
                flags(held.file(),libc::O_RDONLY)?;held.revalidate(self.paths)
            })();observed.extend(errors([current]));
        }
        observed.extend(errors([approval.assert_external_runtime_sources_separate(
            &[(self.record.path(),self.record.file()),(self.pin.path(),self.pin.file())]),self.paths.revalidate()]));
        observed.extend(errors([self.expiry.current()]));observed
    }
}
fn native_boundary(state:&BirthState,guard:&mut HostMaintenanceGuard,checked:&CheckedDeploymentTarget,
    accounts:&FixedAccountAdmission,approval:&mut SoftwareApproval,external:&NativeExternalInputs<'_>)->Vec<EnclaveError> {
    let mut observed=errors([require_native_root(),guard.assert_held(),native_context(state).map(|_|()),
        accounts.assert_current(checked,guard),approval.assert_current(checked,guard),guard.assert_held(),require_native_root()]);
    observed.extend(external.observations(state,approval));observed
}
// During the narrow real kernel unlink/sync interval the kernel itself checks
// the exact original marker and its original parent. All DISJOINT original
// files/directories, actual protected Layout, accounts/SOFTWARE and guard still
// receive concrete checks here. No callback/provider supplied by the caller.
fn disjoint_observations(state:&BirthState,guard:&mut HostMaintenanceGuard,checked:&CheckedDeploymentTarget,
    accounts:&FixedAccountAdmission,approval:&mut SoftwareApproval,path:&Path,external:&NativeExternalInputs<'_>)->Vec<EnclaveError> {
    let mut observed=native_boundary(state,guard,checked,accounts,approval,external);
    for (name,directory) in &state.dirs {
        if Some(name.as_path())==path.parent(){continue;}
        observed.extend(errors([directory.current(&directory.file,state.protection,true)]));
        if let Some(parent)=directory.parent.as_ref().and_then(|p|state.dirs.get(p)) {
            observed.extend(errors([open_at(&parent.file,name,true).and_then(|named|directory.current(&named,state.protection,true))]));
        }
    }
    for (name,file) in &state.files {
        if name==path {continue;}
        let current=name.parent().and_then(|p|state.dirs.get(p)).ok_or_else(||err!(EACCES,"BIRTH_DENIAL_ORIGINAL_PARENT_REQUIRED"))
            .and_then(|parent|file.current_with_content(&parent.file,name,state.protection,true));
        observed.extend(errors([current]));
    }
    if let Some(pending)=&state.pending {observed.extend(errors([pending.current(&state.plan)]));}
    match &state.private_load {Some(loaded)=>observed.extend(errors([loaded.layout_current()])),
        None=>observed.push(err!(EACCES,"BIRTH_DENIAL_PRIVATE_LOAD_REQUIRED")),}
    observed.extend(native_boundary(state,guard,checked,accounts,approval,external));observed
}

impl NativeDedicatedBirth<'_> {
    /// Private bridge used ONLY by the concrete consuming NativeVisibleBirth
    /// child after its complete real jobs/both-recipient ready_gate. No caller
    /// report, readiness boolean, path, event or check callback is accepted.
    pub(in crate::deploy::target_birth) fn remove_owned_startup_denial(&mut self,lease:ExclusiveStartupLease,
        accounts:&FixedAccountAdmission,approval:&mut SoftwareApproval,paths:&HeldPaths,record:&HeldFile,pin:&HeldFile,
        expiry:&CryptoExpiryObservation)
        ->Result<(),NativeDenialPhaseFailure> {
        if self.denial_removal.exclusive.is_some()||self.denial_removal.attempt.is_some()
            ||self.denial_removal.proof.is_some()||self.denial_removal.dedicated.is_some()
            ||self.denial_removal.transition_failure.is_some()||self.denial_removal.poisoned {
            let error=err!(EALREADY,"BIRTH_DENIAL_NATIVE_NO_RETRY");
            self.denial_removal.poisoned=true;self.state.poisoned=true;
            return Err(NativeDenialPhaseFailure {error,boundary_errors:Vec::new(),final_errors:Vec::new(),_incoming:Some(lease)});
        }
        self.denial_removal.exclusive=Some(lease); // retain before ANY fallible observation
        self.state.progress.operation="remove_owned_startup_denial";self.state.progress.complete=false;
        let mut boundary_errors=Vec::new();let external=NativeExternalInputs {paths,record,pin,expiry};
        let operation=(|| {
            if self.state.poisoned {fail!(EACCES,"BIRTH_OWNER_POISONED");}
            let checked=native_context(&self.state)?;
            let support=Arc::clone(self.accepted_directory_event(PrivateBirthAncestor::SupportRoot)
                .ok_or_else(||err!(EACCES,"BIRTH_DENIAL_ACCEPTED_SUPPORT_REQUIRED"))?);
            let nonce=Arc::clone(self.accepted_directory_event(PrivateBirthAncestor::NonceRoot)
                .ok_or_else(||err!(EACCES,"BIRTH_DENIAL_ACCEPTED_NONCE_REQUIRED"))?);
            if support.path()!=self.state.plan.target.layout.support_root||nonce.path()!=self.state.plan.root
                ||support.ancestor()!=PrivateBirthAncestor::SupportRoot||nonce.ancestor()!=PrivateBirthAncestor::NonceRoot
                ||!support.durability_completed()||!nonce.durability_completed() {
                fail!(ESTALE,"BIRTH_DENIAL_REAL_EVENTS_REQUIRED");
            }
            boundary_errors.extend(self.accepted_directory_events_current_with_owned_removal(None));
            {
                let lease=self.denial_removal.exclusive.as_mut().expect("retained original incoming EX");
                for event in [&support,&nonce] {
                    boundary_errors.extend(errors([lease.assert_directory_change(&checked,event),
                        approval.assert_accepted_directory_change(&checked,lease,event)]));
                }
                boundary_errors.extend(self.state.checks(&mut|| {
                    let mut values=native_boundary(&self.state,self.guard,&checked,accounts,approval,&external);
                    values.extend(errors([lease.assert_current(&checked)]));values
                }));
            }
            first(&boundary_errors)?;
            let path=self.state.plan.target.layout.support_root.join(UPGRADE_INHIBITION_LEAF);
            let marker=self.state.files.get(&path).ok_or_else(||err!(EACCES,"BIRTH_DENIAL_ORIGINAL_REQUIRED"))?;
            let parent=self.state.dirs.get(path.parent().expect("fixed support parent"))
                .ok_or_else(||err!(EACCES,"BIRTH_DENIAL_ORIGINAL_PARENT_REQUIRED"))?;
            let pending=self.state.pending.as_ref().ok_or_else(||err!(EACCES,"BIRTH_DENIAL_PENDING_REQUIRED"))?;
            let bytes=pending.marker_bytes(&self.state.plan)?;
            if marker.exact_bytes()!=Some(bytes.as_slice())||marker.access!=libc::O_RDONLY||!parent.private
                ||!self.state.progress.created_files.iter().any(|created|created==&path) {
                fail!(ESTALE,"BIRTH_DENIAL_ORIGINAL_BINDING");
            }
            let original=RemovalOriginal::capture(&parent.file,&marker.file,&path,&bytes,self.state.protection)?;
            if original.stamp!=marker.stamp||original.parent.stamp!=parent.stamp||original.parent.links!=parent.links {
                fail!(ESTALE,"BIRTH_DENIAL_ORIGINAL_CACHE_CHANGED");
            }
            self.denial_removal.attempt=Some(KernelRemovalAttempt::new(original));
            let state=&self.state;let guard=&mut self.guard;
            let attempt=self.denial_removal.attempt.as_mut().expect("original kernel retained before effect");
            attempt.apply_with_endpoint(&parent.file,&marker.file,
                &mut||disjoint_observations(state,guard,&checked,accounts,approval,&path,&external),
                &mut enclave_core::fsutil::full_fsync,&mut||expiry.current())?;
            // Native proof requires BOTH successful original syncs, complete
            // real unlink history and actual events bound above to SAME EX.
            if !attempt.complete||attempt.poisoned||attempt.failure.is_some()||!attempt.record.attempted
                ||attempt.record.result!=Some(Ok(()))||!attempt.record.verified||!attempt.record.observation_errors.is_empty()
                ||attempt.syncs.len()!=2||attempt.syncs[0].parent||!attempt.syncs[1].parent
                ||attempt.syncs.iter().any(|sync|sync.error.is_some()) {
                fail!(EACCES,"BIRTH_DENIAL_DURABLE_OWN_HISTORY_REQUIRED");
            }
            let removed=attempt.removed.as_ref().ok_or_else(||err!(EACCES,"BIRTH_DENIAL_OWN_UNLINK_REQUIRED"))?;
            let proof=OwnedDenialRemoval {path:path.clone(),root:state.plan.root.clone(),target_id:state.plan.target.target_id.clone(),
                descriptor_sha256:pending.descriptor_sha256.clone(),inventory_sha256:pending.inventory_sha256.clone(),
                fd:attempt.original.fd,parent_fd:attempt.original.parent_fd,linked:copy_stamp(&attempt.original.stamp),
                removed:copy_stamp(&removed.stamp),bytes:attempt.original.bytes.clone(),parent_stamp:attempt.original.parent.stamp.clone(),
                parent_links_before:attempt.original.parent.links,parent_links_after:removed.parent.links,durable:true,
                support_event:support,nonce_event:nonce};
            // Last full actual observations precede a DIRECT kernel check;
            // then only the bounded own nlink prediction and proof are stored.
            let checks=disjoint_observations(state,guard,&checked,accounts,approval,&path,&external);
            let current=first(&checks);boundary_errors.extend(checks);current?;
            attempt.removed_current(&parent.file,&marker.file)?;expiry.current()?;
            self.state.dirs.get_mut(path.parent().expect("fixed support parent")).expect("original parent retained").links=proof.parent_links_after;
            self.denial_removal.proof=Some(proof);
            let proof=self.denial_removal.proof.as_ref().expect("actual native proof retained");
            let checks=self.state.checks_with_content_owned_removal(
                &mut||native_boundary(&self.state,self.guard,&checked,accounts,approval,&external),true,Some(proof));
            let current=first(&checks);boundary_errors.extend(checks);current?;
            boundary_errors.extend(self.accepted_directory_events_current_with_owned_removal(Some(proof)));
            first(&boundary_errors)?;expiry.current()?;
            // No inhibited EX currentness from the first own unlink onward.
            // This takes the SAME retained owner ONCE and immediately keeps
            // either actual Dedicated success or original transition refusal.
            let lease=self.denial_removal.exclusive.take().expect("same original EX retained until transition");
            match lease.observe_dedicated_after_clear(&checked) {
                Ok(dedicated)=>self.denial_removal.dedicated=Some(dedicated),
                Err(failure)=>{let error=failure.error.clone();self.denial_removal.transition_failure=Some(failure);return Err(error);},
            }
            Ok(())
        })();
        let mut final_errors=Vec::new();
        match native_context(&self.state) {
            Ok(checked)=>{
                final_errors.extend(native_boundary(&self.state,self.guard,&checked,accounts,approval,&external));
                final_errors.extend(self.denial_removal.current(&self.state,&checked));
                if let Some(proof)=self.denial_removal.proof() {
                    final_errors.extend(self.state.checks_with_content_owned_removal(&mut||Vec::new(),true,Some(proof)));
                    final_errors.extend(self.accepted_directory_events_current_with_owned_removal(Some(proof)));
                }
            },
            Err(error)=>final_errors.push(error),
        }
        final_errors.extend(errors([expiry.current()]));
        match operation.err().or_else(||final_errors.first().cloned()) {
            Some(error)=>{
                self.denial_removal.poisoned=true;self.state.poisoned=true;
                self.state.progress.complete=false;self.state.progress.uncertain_effects=true;
                Err(NativeDenialPhaseFailure {error,boundary_errors,final_errors,_incoming:None})
            },
            None=>Ok(()),
        }
    }
}

#[cfg(test)]
#[path="target_birth_denial_handoff_tests.rs"]
mod tests;
