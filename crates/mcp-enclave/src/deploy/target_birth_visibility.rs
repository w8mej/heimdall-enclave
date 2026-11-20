//! Concrete root-LAST same-owner original-ancestor compositor.
//! Only complete actual NativeJobsBirth enters. Core owns each original-FD
//! syscall; birth and SOFTWARE recipients must both accept that same event
//! before normal owner gates resume. Every failure retains original owners,
//! proofs, partial recipients and actual core refusal; nothing is reacquired.
use super::*;

#[path="target_birth_clear.rs"]
mod clear;
use std::sync::Arc;
use enclave_core::deployment::startup_lease::{DirectoryModeChange,DirectoryModeChangeFailure,PrivateBirthAncestor};
use crate::deploy::{target_birth::directory_event::{BirthDirectoryAcceptance,BirthDirectoryRefusal},
    target_release::DirectoryModeAcceptanceFailure};

struct VisibilityAttempt<'guard> {
    jobs:NativeJobsBirth<'guard>,pending:Option<DirectoryModeChange>,core_failure:Option<DirectoryModeChangeFailure>,
    birth:[Option<BirthDirectoryAcceptance>;2],birth_failures:[Option<BirthDirectoryRefusal>;2],
    software:[Option<Arc<DirectoryModeChange>>;2],software_failures:[Option<DirectoryModeAcceptanceFailure>;2],
}
fn slot(role:PrivateBirthAncestor)->usize {match role {PrivateBirthAncestor::SupportRoot=>0,PrivateBirthAncestor::NonceRoot=>1}}
impl VisibilityAttempt<'_> {
    fn poison(&mut self) {self.jobs.owner.metadata.owner.transport.owner.pin.owner.poison();}
    fn visibility_may_have_changed(&self)->bool {
        self.pending.as_ref().is_some_and(|event|event.ancestor()==PrivateBirthAncestor::NonceRoot)
            ||self.birth[1].is_some()||self.birth_failures[1].as_ref().is_some_and(|failure|failure.namespace_visibility_may_have_changed())
            ||self.software[1].is_some()||self.software_failures[1].is_some()
            ||self.core_failure.as_ref().is_some_and(|failure|failure.namespace_visibility_may_have_changed())
    }
    fn observations(&mut self)->Vec<EnclaveError> {
        // Existing jobs/metadata creator gates remain root700. This concrete
        // phase instead uses actual birth-ledger proofs for only the two
        // original ancestors, and completed own metadata for every other node.
        let mut observed=Vec::new();
        {
            let jobs=&mut self.jobs.owner;let metadata=&mut jobs.metadata.owner;
            let original=&mut metadata.transport.owner.pin.owner;
            observed.extend(errors([require_native_root(),original.scope().map(|_|())]));
            observed.extend(original.payload.owner.observations());
            let birth=&original.payload.owner.candidate.birth;let state=&birth.state;
            observed.extend(errors([original.payload.plan.assert_retained_copies(state)]));
            observed.extend(original.inputs.observations());observed.extend(original.source_separation());
            observed.extend(errors([original.scope().and_then(|scope|original.inputs.complete(&scope))]));
            for source in &metadata.transport.owner.sources {observed.extend(errors([source_current(state,&source.spec,true)]));}
            match &metadata.transport.owner.plan {
                Some(plan)=>observed.extend(plan.contents_current(state,&original.inputs.pin_bytes,true)),
                None=>observed.push(err!(EACCES,"BIRTH_VISIBILITY_RUNTIME_REQUIRED")),
            }
            for attempt in [&metadata.payload,&metadata.runtime] {
                match attempt {Some(attempt)=>observed.extend(attempt.retained_completed_observations(state)),
                    None=>observed.push(err!(EACCES,"BIRTH_VISIBILITY_COMPLETED_METADATA_REQUIRED")),}
            }
            match &jobs.plan {Some(plan)=>observed.extend(plan.sources_current(state,true)),
                None=>observed.push(err!(EACCES,"BIRTH_VISIBILITY_JOBS_PLAN_REQUIRED")),}
            match &jobs.external {Some(external)=>observed.extend(external.observations(true)),
                None=>observed.push(err!(EACCES,"BIRTH_VISIBILITY_COMPLETE_JOBS_REQUIRED")),}
            for role in [PrivateBirthAncestor::SupportRoot,PrivateBirthAncestor::NonceRoot] {
                let index=slot(role);let path=match role {PrivateBirthAncestor::SupportRoot=>&state.plan.target.layout.support_root,
                    PrivateBirthAncestor::NonceRoot=>&state.plan.root};
                let directory=state.dirs.get(path);
                match (&self.birth[index],birth.accepted_directory_event(role),&self.software[index],directory) {
                    (Some(receipt),Some(recorded),Some(software),Some(directory))=>{
                        let event=receipt.event();let after=event.after();
                        if !Arc::ptr_eq(event,recorded)||!Arc::ptr_eq(event,software)||event.path()!=path
                            ||event.ancestor()!=role||!event.durability_completed()||!directory.private
                            ||(directory.stamp.dev,directory.stamp.ino,directory.stamp.uid,directory.stamp.gid,directory.stamp.mode)
                                !=(after.dev,after.ino,after.uid,after.gid,after.mode) {
                            observed.push(err!(ESTALE,"BIRTH_VISIBILITY_ORIGINAL_EVENT_BINDING"));
                        }
                    },
                    (None,None,None,Some(directory))=>{
                        if !directory.private||directory.stamp.uid!=0||directory.stamp.gid!=0||directory.stamp.mode&0o7777!=0o700 {
                            observed.push(err!(EACCES,"BIRTH_VISIBILITY_ORIGINAL_PRIVATE_REQUIRED"));
                        }
                    },
                    _=>observed.push(err!(EACCES,"BIRTH_VISIBILITY_RECIPIENTS_INCOMPLETE")),
                }
            }
            if original.payload.owner.lease.is_none()||original.payload.owner.acquisition_failure.is_some() {
                observed.push(err!(EACCES,"BIRTH_VISIBILITY_SAME_EX_REQUIRED"));
            }
        }
        // Actual recipient assertions include zero-node SOFTWARE recipients.
        // They bind pointer-identical opaque proof, not metadata equality or a
        // report. Full actual freshness/save checks still run independently.
        let checked=checked(&self.jobs.owner.metadata.owner.transport.owner.pin.owner.payload.owner.candidate.birth.state).cloned();
        match checked {
            Ok(checked)=>{
                let owner=&mut self.jobs.owner.metadata.owner.transport.owner.pin.owner.payload.owner;
                if let Some(failure)=&self.core_failure {observed.extend(failure.retained_checks(&checked));}
                if let Some(lease)=&mut owner.lease {
                    for event in self.software.iter().flatten() {
                        observed.extend(errors([lease.assert_directory_change(&checked,event)]));
                        match &mut owner.candidate.approval {
                            Some(approval)=>observed.extend(errors([approval.assert_accepted_directory_change(&checked,lease,event)])),
                            None=>observed.push(err!(EACCES,"BIRTH_VISIBILITY_ACTUAL_SOFTWARE_REQUIRED")),
                        }
                    }
                }
            },
            Err(error)=>observed.push(error),
        }
        let original=&mut self.jobs.owner.metadata.owner.transport.owner.pin.owner;
        observed.extend(errors([original.payload.owner.candidate.verify_candidate()]));
        observed.extend(original.payload.owner.observations());
        observed.extend(errors([self.jobs.owner.metadata.owner.transport.owner.crypto()]));observed
    }
    fn gate(&mut self,observed:&mut Vec<EnclaveError>)->EnclaveResult<()> {
        let checks=self.observations();let current=first(&checks);observed.extend(checks);if current.is_err(){self.poison();}current
    }
    fn ready_observations(&mut self)->Vec<EnclaveError> {
        let mut observed=self.observations();
        if self.pending.is_some()||self.core_failure.is_some()||self.birth_failures.iter().any(Option::is_some)
            ||self.software_failures.iter().any(Option::is_some)||self.birth.iter().any(Option::is_none)
            ||self.software.iter().any(Option::is_none) {
            observed.push(err!(EACCES,"BIRTH_VISIBILITY_BOTH_REAL_RECIPIENTS_REQUIRED"));
        }observed
    }
    fn ready_gate(&mut self,observed:&mut Vec<EnclaveError>)->EnclaveResult<()> {
        let expiry=self.jobs.owner.metadata.owner.transport.owner.crypto_expiry();
        let checks=self.ready_observations();let current=first(&checks);observed.extend(checks);
        let last=match expiry {Ok(expiry)=>expiry.current(),Err(error)=>Err(error)};
        if let Err(error)=&last {observed.push(error.clone());}
        if current.is_err()||last.is_err(){self.poison();}current?;last
    }
    fn change(&mut self,role:PrivateBirthAncestor,observed:&mut Vec<EnclaveError>)->EnclaveResult<()> {
        self.gate(observed)?;let index=slot(role);
        if self.pending.is_some()||self.core_failure.is_some()||self.birth[index].is_some()
            ||self.birth_failures[index].is_some()||self.software[index].is_some()||self.software_failures[index].is_some() {
            fail!(EALREADY,"BIRTH_VISIBILITY_NO_RETRY");
        }
        if role==PrivateBirthAncestor::NonceRoot&&(self.birth[0].is_none()||self.software[0].is_none()) {
            fail!(EACCES,"BIRTH_VISIBILITY_SUPPORT_FIRST_REQUIRED");
        }
        let checked=checked(&self.jobs.owner.metadata.owner.transport.owner.pin.owner.payload.owner.candidate.birth.state)?.clone();
        let result={
            let owner=&mut self.jobs.owner.metadata.owner.transport.owner.pin.owner.payload.owner;
            let checks=errors([require_native_root(),owner.candidate.birth.guard.assert_held()]);
            let current=first(&checks);observed.extend(checks);current?;
            let lease=owner.lease.take().ok_or_else(||err!(EACCES,"BIRTH_VISIBILITY_SAME_EX_REQUIRED"))?;
            lease.prepare_private_birth_ancestor(&checked,role)
        };
        match result {
            Ok((lease,event))=>{
                self.jobs.owner.metadata.owner.transport.owner.pin.owner.payload.owner.lease=Some(lease);
                self.pending=Some(event);
            },
            Err(failure)=>{let error=failure.error.clone();self.core_failure=Some(failure);return Err(error);},
        }
        // No full old-mode SOFTWARE/candidate gate between the actual syscall
        // and BOTH recipients. Each borrowed same owner stays in this aggregate.
        let event=self.pending.take().expect("retained actual core success");
        let birth={
            let owner=&mut self.jobs.owner.metadata.owner.transport.owner.pin.owner.payload.owner;
            owner.candidate.birth.accept_own_directory_event(owner.lease.as_mut().expect("same returned EX"),event)
        };
        match birth {
            Ok(receipt)=>self.birth[index]=Some(receipt),
            Err(failure)=>{let error=failure.error.clone();self.birth_failures[index]=Some(failure);return Err(error);},
        }
        let event=self.birth[index].as_ref().expect("actual accepted birth event retained").event();
        let software={
            let owner=&mut self.jobs.owner.metadata.owner.transport.owner.pin.owner.payload.owner;
            let lease=owner.lease.as_mut().expect("same returned EX");let candidate=&mut owner.candidate;
            let approval=candidate.approval.as_mut().ok_or_else(||err!(EACCES,"BIRTH_VISIBILITY_ACTUAL_SOFTWARE_REQUIRED"))?;
            approval.accept_directory_change(&checked,candidate.birth.guard,lease,event)
        };
        match software {
            Ok(())=>self.software[index]=Some(Arc::clone(event)),
            Err(failure)=>{let error=failure.error.clone();self.software_failures[index]=Some(failure);return Err(error);},
        }
        self.gate(observed)
    }
}

/// Actual complete jobs with both original ancestor events accepted by every
/// retained recipient. This does not clear denial, start jobs or qualify tiers.
#[must_use="retain actual visible namespace and every same-invocation owner"]
pub(crate) struct NativeVisibleBirth<'guard> {owner:VisibilityAttempt<'guard>}
impl std::fmt::Debug for NativeVisibleBirth<'_> {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        f.debug_struct("NativeVisibleBirth").field("observations",&"<redacted>").finish_non_exhaustive()
    }
}
#[must_use="retain all actual partial effects, event refusals and SAME EX"]
pub(crate) struct NativeVisibilityFailure<'guard> {
    pub(crate) error:EnclaveError,pub(crate) boundary_errors:Vec<EnclaveError>,pub(crate) final_errors:Vec<EnclaveError>,
    pub(crate) progress:BirthProgress,owner:VisibilityAttempt<'guard>,
}
impl NativeVisibilityFailure<'_> {
    pub(crate) fn namespace_visibility_may_have_changed(&self)->bool {self.owner.visibility_may_have_changed()}
}
impl std::fmt::Debug for NativeVisibilityFailure<'_> {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        f.debug_struct("NativeVisibilityFailure").field("reason",&self.error.reason)
            .field("boundary_error_count",&self.boundary_errors.len()).field("final_error_count",&self.final_errors.len())
            .field("namespace_visibility_may_have_changed",&self.namespace_visibility_may_have_changed())
            .field("observations",&"<redacted>").finish_non_exhaustive()
    }
}
impl<'guard> NativeJobsBirth<'guard> {
    pub(crate) fn prepare_original_ancestor_visibility(self)->Result<NativeVisibleBirth<'guard>,NativeVisibilityFailure<'guard>> {
        let mut owner=VisibilityAttempt {jobs:self,pending:None,core_failure:None,birth:[None,None],birth_failures:[None,None],
            software:[None,None],software_failures:[None,None]};let mut boundary_errors=Vec::new();
        owner.jobs.owner.metadata.owner.transport.owner.pin.owner.payload.owner.candidate.birth.state.progress.operation="prepare_original_ancestor_visibility";
        let operation=(|| {
            // Complete actual jobs/root700 phase, before any original ancestor
            // syscall. Existing creator checkers are never relaxed or re-used
            // after nonce755; later observations use real accepted ledgers.
            owner.jobs.owner.gate(true,&mut boundary_errors)?;owner.gate(&mut boundary_errors)?;
            owner.change(PrivateBirthAncestor::SupportRoot,&mut boundary_errors)?;
            owner.change(PrivateBirthAncestor::NonceRoot,&mut boundary_errors)?;
            owner.ready_gate(&mut boundary_errors)
        })();
        let expiry=owner.jobs.owner.metadata.owner.transport.owner.crypto_expiry();
        let mut final_errors=owner.ready_observations();final_errors.extend(owner.ready_observations());
        match expiry {Ok(expiry)=>final_errors.extend(errors([expiry.current()])),Err(error)=>final_errors.push(error)}
        match resolve_owned(owner,operation,boundary_errors,final_errors) {
            Ok(mut owner)=>{
                let progress=&mut owner.jobs.owner.metadata.owner.transport.owner.pin.owner.payload.owner.candidate.birth.state.progress;
                progress.complete=true;progress.uncertain_effects=false;Ok(NativeVisibleBirth {owner})
            },
            Err(mut refusal)=>{
                refusal.owner.poison();Err(NativeVisibilityFailure {error:refusal.error,boundary_errors:refusal.boundary_errors,
                    final_errors:refusal.final_errors,
                    progress:refusal.owner.jobs.owner.metadata.owner.transport.owner.pin.owner.payload.owner.candidate.birth.state.progress.clone(),owner:refusal.owner})
            },
        }
    }
}

#[cfg(test)]
#[path="target_birth_visibility_tests.rs"]
mod tests;
