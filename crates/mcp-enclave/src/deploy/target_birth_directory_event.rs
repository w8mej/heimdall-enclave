//! One-way recipient of an ACTUAL core own-directory mode event.
//! No chmod, original-owner replacement, inactivity/visibility/publication or
//! start authority exists here. The SAME actual birth guard, checked load and
//! mutable inhibited EX bind the opaque event before predicted expectations
//! advance. An actual nonce event may already have changed visibility even
//! when this recipient refuses. All proofs and original stamps stay retained.
use super::*;
use std::sync::Arc;
use enclave_core::deployment::{self,CheckedDeploymentTarget,startup_lease::{
    DirectoryModeChange,DirectoryModeIdentity,ExclusiveStartupLease,PrivateBirthAncestor}};

fn identity(stamp:&DirStamp)->DirectoryModeIdentity {
    DirectoryModeIdentity {dev:stamp.dev,ino:stamp.ino,uid:stamp.uid,gid:stamp.gid,mode:stamp.mode}
}
fn predicted(old:&DirStamp,before:DirectoryModeIdentity,after:DirectoryModeIdentity)->EnclaveResult<DirStamp> {
    if old.uid!=0||old.gid!=0||old.mode&0o7777!=0o700||old.mode&libc::S_IFMT as u32!=libc::S_IFDIR as u32
        ||before!=identity(old) {fail!(EACCES,"BIRTH_DIRECTORY_EVENT_ORIGINAL_IDENTITY");}
    let mut expected=old.clone();expected.mode=(expected.mode&!0o7777)|0o755;
    if after!=identity(&expected) {fail!(ESTALE,"BIRTH_DIRECTORY_EVENT_PREDICTED_DELTA");}Ok(expected)
}
fn fixed_path(root:&Path,support:&Path,role:PrivateBirthAncestor,path:&Path)->EnclaveResult<()> {
    if normalized_path(root)?!=root||normalized_path(support)?!=support||support==root||!support.starts_with(root) {
        fail!(EACCES,"BIRTH_DIRECTORY_EVENT_ROLE_SCOPE");
    }
    let expected=match role {PrivateBirthAncestor::SupportRoot=>support,PrivateBirthAncestor::NonceRoot=>root};
    if path!=expected {fail!(EACCES,"BIRTH_DIRECTORY_EVENT_FIXED_PATH");}Ok(())
}
fn actual_checked(state:&BirthState)->EnclaveResult<CheckedDeploymentTarget> {
    let checked=state.private_load.as_ref().ok_or_else(||err!(EACCES,"BIRTH_DIRECTORY_EVENT_PRIVATE_LOAD_REQUIRED"))?.checked();
    if checked.target()!=&state.plan.target||checked.config_path()!=state.plan.descriptor
        ||checked.descriptor_sha256()!=hex::encode(Sha256::digest(&state.plan.bytes))
        ||checked.target().role!=DeploymentRole::DedicatedTest||checked.target().profile!=Profile::L2 {
        fail!(ESTALE,"BIRTH_DIRECTORY_EVENT_CHECKED_BINDING");
    }Ok(checked.clone())
}
fn selected(checked:&CheckedDeploymentTarget)->EnclaveResult<()> {
    if !deployment::selected().is_some_and(|current|current.target()==checked.target()
        &&current.config_path()==checked.config_path()&&current.descriptor_sha256()==checked.descriptor_sha256()) {
        fail!(ESTALE,"BIRTH_DIRECTORY_EVENT_SELECTED_BINDING");
    }Ok(())
}
fn actual_boundary(guard:&mut HostMaintenanceGuard,lease:&mut ExclusiveStartupLease,
    checked:&CheckedDeploymentTarget,event:&DirectoryModeChange)->Vec<EnclaveError> {
    errors([require_native_root(),guard.assert_held(),selected(checked),lease.assert_directory_change(checked,event),
        guard.assert_held(),require_native_root()])
}

#[derive(Clone)]
struct OriginalDirectory {stamp:DirStamp,links:u64,fd:i32,created_here:bool}
impl OriginalDirectory {
    fn capture(directory:&Directory)->Self {Self {stamp:directory.stamp.clone(),links:directory.links,
        fd:directory.file.as_raw_fd(),created_here:directory.private}}
}
// No external constructor: parent optional hook accepts only this bounded
// actual event phase. It cannot be used to relax an unrelated directory.
pub(super) struct PendingDirectoryEvent {
    event:Arc<DirectoryModeChange>,original:Option<OriginalDirectory>,
}
impl PendingDirectoryEvent {
    fn capture(state:&BirthState,event:DirectoryModeChange)->Self {
        let event=Arc::new(event);let original=state.dirs.get(event.path()).map(OriginalDirectory::capture);Self {event,original}
    }
    pub(super) fn targets(&self,path:&Path)->bool {self.event.path()==path}
    pub(super) fn verify_directory(&self,state:&BirthState,path:&Path,directory:&Directory)->EnclaveResult<()> {
        let original=self.original.as_ref().ok_or_else(||err!(EACCES,"BIRTH_DIRECTORY_EVENT_ORIGINAL_REQUIRED"))?;
        if !self.targets(path)||!original.created_here||!directory.private
            ||!state.progress.created_directories.iter().any(|created|created==path)
            ||directory.stamp!=original.stamp||directory.links!=original.links||directory.file.as_raw_fd()!=original.fd {
            fail!(ESTALE,"BIRTH_DIRECTORY_EVENT_ORIGINAL_CHANGED");
        }
        let _expected=predicted(&original.stamp,self.event.before(),self.event.after())?;
        fixed_path(&state.plan.root,&state.plan.target.layout.support_root,self.event.ancestor(),path)?;
        let parent=directory.parent.as_ref().and_then(|parent|state.dirs.get(parent))
            .ok_or_else(||err!(EACCES,"BIRTH_DIRECTORY_EVENT_ORIGINAL_PARENT_REQUIRED"))?;
        let named=open_at(&parent.file,path,true)?;
        // Old nlink remains the birth's original expectation, never a stat
        // refresh. Core verifies both held/named complete event snapshots,
        // native ACL and readonly flags against its actual own syscall.
        if stat(&directory.file)?.nlink()!=original.links||stat(&named)?.nlink()!=original.links {
            fail!(ESTALE,"BIRTH_DIRECTORY_EVENT_ORIGINAL_LINKS_CHANGED");
        }
        self.event.verify_recipient(&actual_checked(state)?,path,&directory.file,&named,identity(&original.stamp))
    }
}

struct AcceptedDirectoryEvent {event:Arc<DirectoryModeChange>,original:OriginalDirectory,expected:DirStamp}
impl AcceptedDirectoryEvent {
    fn current(&self,state:&BirthState)->EnclaveResult<()> {self.current_with_owned_removal(state,None)}
    fn current_with_owned_removal(&self,state:&BirthState,removal:Option<&denial_handoff::OwnedDenialRemoval>)->EnclaveResult<()> {
        let expected_links=match removal {
            Some(proof)=>{
                if !Arc::ptr_eq(proof.event(self.event.ancestor()),&self.event) {
                    fail!(ESTALE,"BIRTH_DENIAL_ACCEPTED_EVENT_CHANGED");
                }
                proof.expected_parent_links(self.event.path(),self.original.stamp.dev,self.original.stamp.ino,self.original.links)?
                    .unwrap_or(self.original.links)
            },
            None=>self.original.links,
        };
        let directory=state.dirs.get(self.event.path()).ok_or_else(||err!(ESTALE,"BIRTH_DIRECTORY_EVENT_ACCEPTED_LOST"))?;
        if !directory.private||!self.original.created_here||directory.stamp!=self.expected
            ||directory.file.as_raw_fd()!=self.original.fd||directory.links!=expected_links {
            fail!(ESTALE,"BIRTH_DIRECTORY_EVENT_ACCEPTED_CHANGED");
        }
        // After one-way acceptance, ordinary exact predicted identity/current
        // checks apply. The historical event's ctime/mtime is not re-frozen.
        directory.current(&directory.file,state.protection,true)?;
        let parent=directory.parent.as_ref().and_then(|p|state.dirs.get(p))
            .ok_or_else(||err!(EACCES,"BIRTH_DIRECTORY_EVENT_ORIGINAL_PARENT_REQUIRED"))?;
        let named=open_at(&parent.file,self.event.path(),true)?;directory.current(&named,state.protection,true)
    }
}
struct RefusedDirectoryEvent {
    pending:PendingDirectoryEvent,expected_updated:bool,error:EnclaveError,
    boundary_errors:Vec<EnclaveError>,final_errors:Vec<EnclaveError>,
}
// Exactly two accepted roles. Failed attempts remain separately retained and
// never replace an accepted proof or supply a retry/poison-clear capability.
pub(super) struct DirectoryEventLedger {
    support:Option<Arc<AcceptedDirectoryEvent>>,nonce:Option<Arc<AcceptedDirectoryEvent>>,
    refusals:Vec<Arc<RefusedDirectoryEvent>>,
}
impl DirectoryEventLedger {
    pub(super) fn new()->Self {Self {support:None,nonce:None,refusals:Vec::new()}}
    pub(super) fn current_with_owned_removal(&self,state:&BirthState,removal:Option<&denial_handoff::OwnedDenialRemoval>)
        ->Vec<EnclaveError> {
        let mut observed=Vec::new();
        for role in [PrivateBirthAncestor::SupportRoot,PrivateBirthAncestor::NonceRoot] {
            match self.accepted(role) {
                Some(event)=>observed.extend(errors([event.current_with_owned_removal(state,removal)])),
                None=>observed.push(err!(EACCES,"BIRTH_DENIAL_BOTH_ACCEPTED_EVENTS_REQUIRED")),
            }
        }observed
    }
    pub(super) fn accepted_event(&self,role:PrivateBirthAncestor)->Option<&Arc<DirectoryModeChange>> {
        self.accepted(role).map(|proof|&proof.event)
    }
    fn accepted(&self,role:PrivateBirthAncestor)->Option<&Arc<AcceptedDirectoryEvent>> {
        match role {PrivateBirthAncestor::SupportRoot=>self.support.as_ref(),PrivateBirthAncestor::NonceRoot=>self.nonce.as_ref()}
    }
    fn store(&mut self,role:PrivateBirthAncestor,proof:Arc<AcceptedDirectoryEvent>) {
        match role {PrivateBirthAncestor::SupportRoot=>self.support=Some(proof),PrivateBirthAncestor::NonceRoot=>self.nonce=Some(proof)}
    }
}

/// Historical acceptance only; same actual birth also retains this proof.
#[must_use="retain actual event acceptance with same original owners"]
pub(crate) struct BirthDirectoryAcceptance {proof:Arc<AcceptedDirectoryEvent>}
impl BirthDirectoryAcceptance {
    /// Borrow only the opaque actual core event for the next genuine recipient.
    /// This neither exports an owner nor supplies SOFTWARE/currentness approval.
    pub(in crate::deploy::target_birth) fn event(&self)->&Arc<DirectoryModeChange> {&self.proof.event}
    pub(crate) fn namespace_visibility_may_have_changed(&self)->bool {self.proof.event.ancestor()==PrivateBirthAncestor::NonceRoot}
}
impl std::fmt::Debug for BirthDirectoryAcceptance {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        f.debug_struct("BirthDirectoryAcceptance").field("observations",&"<redacted>").finish_non_exhaustive()
    }
}
/// Terminal refusal. Original birth internally retains the same proof/errors.
#[must_use="retain same poisoned birth, actual EX and refused actual event"]
pub(crate) struct BirthDirectoryRefusal {
    pub(crate) error:EnclaveError,pub(crate) boundary_errors:Vec<EnclaveError>,pub(crate) final_errors:Vec<EnclaveError>,
    pub(crate) progress:BirthProgress,proof:Arc<RefusedDirectoryEvent>,
}
impl BirthDirectoryRefusal {
    pub(crate) fn namespace_visibility_may_have_changed(&self)->bool {
        self.proof.pending.event.ancestor()==PrivateBirthAncestor::NonceRoot
    }
    pub(crate) fn expected_stamp_was_updated(&self)->bool {self.proof.expected_updated}
}
impl std::fmt::Debug for BirthDirectoryRefusal {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        f.debug_struct("BirthDirectoryRefusal").field("reason",&self.error.reason)
            .field("boundary_error_count",&self.boundary_errors.len()).field("final_error_count",&self.final_errors.len())
            .field("expected_stamp_was_updated",&self.expected_stamp_was_updated())
            .field("namespace_visibility_may_have_changed",&self.namespace_visibility_may_have_changed())
            .field("observations",&"<redacted>").finish_non_exhaustive()
    }
}

impl NativeDedicatedBirth<'_> {
    // The original event/links remain immutable historical evidence. ONLY the
    // actual native owned-unlink proof can project this exact support nlink.
    pub(in crate::deploy::target_birth) fn accepted_directory_events_current_with_owned_removal(
        &self,removal:Option<&denial_handoff::OwnedDenialRemoval>)->Vec<EnclaveError> {
        self.directory_events.current_with_owned_removal(&self.state,removal)
    }
    /// Accept an already actual own syscall event under the SAME EX and guard.
    /// The caller must coordinate the SOFTWARE recipient before re-entering
    /// normal full candidate gates; this phase supplies no SOFTWARE transition.
    pub(in crate::deploy::target_birth) fn accept_own_directory_event(&mut self,lease:&mut ExclusiveStartupLease,
        event:DirectoryModeChange)->Result<BirthDirectoryAcceptance,BirthDirectoryRefusal> {
        let pending=PendingDirectoryEvent::capture(&self.state,event);let role=pending.event.ancestor();
        let mut boundary_errors=Vec::new();let expected_updated=false;
        self.state.progress.operation="accept_own_directory_event";self.state.progress.complete=false;
        let operation=(|| {
            if self.state.poisoned {fail!(EACCES,"BIRTH_OWNER_POISONED");}
            if self.state.protection.owner!=(0,0)||!self.state.protection.native_acl {
                fail!(EACCES,"BIRTH_DIRECTORY_EVENT_NATIVE_PROTECTION_REQUIRED");
            }
            let checked=actual_checked(&self.state)?;
            let checks=actual_boundary(self.guard,lease,&checked,&pending.event);let current=first(&checks);boundary_errors.extend(checks);current?;
            if self.directory_events.accepted(role).is_some() {fail!(EALREADY,"BIRTH_DIRECTORY_EVENT_NO_REPLAY");}
            fixed_path(&self.state.plan.root,&self.state.plan.target.layout.support_root,role,pending.event.path())?;
            if !pending.event.durability_completed() {fail!(EACCES,"BIRTH_DIRECTORY_EVENT_DURABILITY_REQUIRED");}
            if role==PrivateBirthAncestor::NonceRoot {
                let support=self.directory_events.support.as_ref().ok_or_else(||err!(EACCES,"BIRTH_DIRECTORY_EVENT_SUPPORT_FIRST_REQUIRED"))?;
                // Both events must belong to this SAME acquisition; a receipt
                // from another real lease cannot authorize root-last ordering.
                let checks=errors([lease.assert_directory_change(&checked,&support.event),support.current(&self.state)]);
                let current=first(&checks);boundary_errors.extend(checks);current?;
            }
            for _ in 0..2 {
                let checks=self.state.checks_with_content_event(
                    &mut||actual_boundary(self.guard,lease,&checked,&pending.event),true,Some(&pending));
                let current=first(&checks);boundary_errors.extend(checks);current?;
            }
            let original=pending.original.as_ref().ok_or_else(||err!(EACCES,"BIRTH_DIRECTORY_EVENT_ORIGINAL_REQUIRED"))?;
            let _expected=predicted(&original.stamp,pending.event.before(),pending.event.after())?;
            Ok(())
        })();
        // Even a refused actual event may already have widened the namespace.
        // Keep its actual proof while collecting all available independent
        // final observations. Failed acceptance never restores metadata.
        let mut final_errors=Vec::new();
        for _ in 0..2 {
            match actual_checked(&self.state) {
                Ok(checked)=>{
                    let mut check=||actual_boundary(self.guard,lease,&checked,&pending.event);
                    final_errors.extend(self.state.checks_with_content_event(&mut check,true,Some(&pending)));
                },
                Err(error)=>{final_errors.push(error);final_errors.extend(errors([require_native_root(),self.guard.assert_held()]));},
            }
        }
        if operation.is_ok()&&final_errors.is_empty() {
            // Last direct actual binding follows every expensive independent
            // check. No callback or fallible read follows before the atomic
            // predicted cache update and acceptance-ledger insertion below.
            match actual_checked(&self.state) {
                Ok(checked)=>final_errors.extend(actual_boundary(self.guard,lease,&checked,&pending.event)),
                Err(error)=>final_errors.push(error),
            }
            let direct=self.state.dirs.get(pending.event.path()).ok_or_else(||err!(EACCES,"BIRTH_DIRECTORY_EVENT_ORIGINAL_REQUIRED"))
                .and_then(|directory|pending.verify_directory(&self.state,pending.event.path(),directory));
            final_errors.extend(errors([direct]));
        }
        match operation.err().or_else(||final_errors.first().cloned()) {
            Some(error)=>{
                self.state.poisoned=true;self.state.progress.uncertain_effects=true;
                let proof=Arc::new(RefusedDirectoryEvent {pending,expected_updated,error:error.clone(),
                    boundary_errors:boundary_errors.clone(),final_errors:final_errors.clone()});
                self.directory_events.refusals.push(Arc::clone(&proof));
                Err(BirthDirectoryRefusal {error,boundary_errors,final_errors,progress:self.state.progress.clone(),proof})
            },
            None=>{
                let original=pending.original.expect("successful exact original event");
                let expected=predicted(&original.stamp,pending.event.before(),pending.event.after()).expect("verified fixed predicted delta");
                // Only own-event predicted fields advance after ALL checks.
                // No stat-derived stamp or immutable provenance is adopted.
                let directory=self.state.dirs.get_mut(pending.event.path()).expect("last verified original event target");
                directory.stamp.uid=expected.uid;directory.stamp.gid=expected.gid;directory.stamp.mode=expected.mode;
                let proof=Arc::new(AcceptedDirectoryEvent {event:pending.event,original,expected});
                self.directory_events.store(role,Arc::clone(&proof));
                self.state.progress.complete=true;self.state.progress.uncertain_effects=false;
                Ok(BirthDirectoryAcceptance {proof})
            },
        }
    }
    /// Borrow the ledger's original accepted event without constructing a new
    /// recipient proof. Historical evidence cannot reset any owner's poison.
    pub(in crate::deploy::target_birth) fn accepted_directory_event(&self,role:PrivateBirthAncestor)->Option<&Arc<DirectoryModeChange>> {
        self.directory_events.accepted_event(role)
    }
}

#[cfg(test)]
#[path="target_birth_directory_event_tests.rs"]
mod tests;
