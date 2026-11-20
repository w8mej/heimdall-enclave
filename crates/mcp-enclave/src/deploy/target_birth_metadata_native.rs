//! Consume actual complete runtime transport before original directory handoff.
//! This private child of runtime_transport keeps the same birth, actual guard,
//! accounts, SOFTWARE approval, inhibited EX, operator pin and runtime sources.
//! Only real own-syscall predicted directory stamps may advance. Root remains
//! 0700; no original-control, staging, support/root, job, visibility or start
//! transition occurs. Reports and callbacks cannot construct this owner.
use super::*;
use crate::deploy::target_birth::metadata::{self,OwnMetadataAttempt,Scope};

#[path="target_birth_jobs.rs"]
mod jobs;

struct MetadataAttempt<'guard> {
    transport:NativeRuntimeTransportBirth<'guard>,
    payload:Option<OwnMetadataAttempt>,runtime:Option<OwnMetadataAttempt>,
}
impl MetadataAttempt<'_> {
    fn observations(&mut self)->Vec<EnclaveError> {
        // RuntimeTransportAttempt::gate deliberately remains the all700
        // creator gate. This phase instead checks original immutable files
        // plus exact original/own-predicted directory expectations.
        let transport=&mut self.transport.owner;let original=&mut transport.pin.owner;
        let mut observed=errors([require_native_root(),original.scope().map(|_|())]);
        observed.extend(original.payload.owner.observations());
        let state=&original.payload.owner.candidate.birth.state;
        observed.extend(errors([metadata::hidden_root(state),original.payload.plan.assert_retained_copies(state)]));
        if original.payload.owner.lease.is_none()||original.payload.owner.acquisition_failure.is_some() {
            observed.push(err!(EACCES,"BIRTH_METADATA_ACTUAL_EX_REQUIRED"));
        }
        observed.extend(original.inputs.observations());observed.extend(original.source_separation());
        observed.extend(errors([original.scope().and_then(|scope|original.inputs.complete(&scope))]));
        for source in &transport.sources {observed.extend(errors([source_current(state,&source.spec,true)]));}
        match &transport.plan {
            Some(plan)=>observed.extend(plan.contents_current(state,&original.inputs.pin_bytes,true)),
            None=>observed.push(err!(EACCES,"BIRTH_METADATA_COMPLETE_RUNTIME_REQUIRED")),
        }
        for attempt in [&self.payload,&self.runtime].into_iter().flatten() {
            observed.extend(attempt.observations(state));
        }
        // Concrete original-code verification is still attempted when another
        // independent source or owner gate refused. Retain its actual error.
        observed.extend(errors([original.payload.owner.candidate.verify_candidate()]));
        observed.extend(original.payload.owner.observations());
        // Re-run genuine provisioning/current original pin/source crypto at an
        // actual current wall time. The report remains diagnostic only.
        observed.extend(errors([transport.crypto()]));
        observed.extend(errors([metadata::hidden_root(&transport.pin.owner.payload.owner.candidate.birth.state)]));
        observed
    }
    fn gate(&mut self,observed:&mut Vec<EnclaveError>)->EnclaveResult<()> {
        let checks=self.observations();let current=first(&checks);observed.extend(checks);
        if current.is_err(){self.transport.owner.pin.owner.poison();}current
    }
    fn prepare(&mut self,scope:Scope)->EnclaveResult<()> {
        if match scope {Scope::Payload=>self.payload.is_some(),Scope::Runtime=>self.runtime.is_some()} {
            fail!(EALREADY,"BIRTH_METADATA_NO_ATTEMPT_REPLACEMENT");
        }
        let original=&self.transport.owner.pin.owner;let owner=&original.payload.owner;
        let approval=owner.candidate.approval.as_ref().ok_or_else(||err!(EACCES,"BIRTH_METADATA_ACTUAL_SOFTWARE_REQUIRED"))?;
        let lease=owner.lease.as_ref().ok_or_else(||err!(EACCES,"BIRTH_METADATA_ACTUAL_EX_REQUIRED"))?;
        let attempt=OwnMetadataAttempt::prepare_actual(&owner.candidate.birth.state,scope,approval,lease)?;
        // Store each actual plan/origin/denial owner BEFORE the next gate or
        // effect. Refusals keep every previously prepared/applied attempt.
        match scope {Scope::Payload=>self.payload=Some(attempt),Scope::Runtime=>self.runtime=Some(attempt)}
        Ok(())
    }
    fn apply(&mut self,scope:Scope,observed:&mut Vec<EnclaveError>)->EnclaveResult<()> {
        self.gate(observed)?;
        let original=&mut self.transport.owner.pin.owner;let pin_scope=original.scope()?;
        let checked=checked(&original.payload.owner.candidate.birth.state)?.clone();
        let inputs=&original.inputs;let owner=&mut original.payload.owner;
        let lease=owner.lease.as_mut().ok_or_else(||err!(EACCES,"BIRTH_METADATA_ACTUAL_EX_REQUIRED"))?;
        let candidate=&mut owner.candidate;
        let accounts=candidate.accounts.as_ref().ok_or_else(||err!(EACCES,"BIRTH_METADATA_ACTUAL_ACCOUNTS_REQUIRED"))?;
        let approval=candidate.approval.as_mut().ok_or_else(||err!(EACCES,"BIRTH_METADATA_ACTUAL_SOFTWARE_REQUIRED"))?;
        let birth=&mut candidate.birth;
        let attempt=match scope {Scope::Payload=>self.payload.as_mut(),Scope::Runtime=>self.runtime.as_mut()}
            .ok_or_else(||err!(EACCES,"BIRTH_METADATA_ACTUAL_PLAN_REQUIRED"))?;
        // The kernel independently rechecks complete original BirthState
        // content, actual Layout/provisioning and root700 around every syscall
        // and sync. This closure borrows ONLY real disjoint authority/input
        // fields; it cannot manufacture native authority or replace state.
        let operation=attempt.apply(&mut birth.state,
            &mut||authority_boundary(&checked,birth.guard,lease,accounts,approval,inputs,&pin_scope),
            &mut enclave_core::fsutil::full_fsync);
        if let Some((boundary,finals))=attempt.retained_errors() {
            observed.extend(boundary.iter().cloned());observed.extend(finals.iter().cloned());
        }
        let post=self.gate(observed);
        if let Err(error)=&post {observed.push(error.clone());}
        operation?;post
    }
}

/// Same original complete transport with retained own directory syscall ledgers.
/// This is preparation behind root0700, never publication/start authority.
#[must_use="retain actual birth, guard, EX, approval, inputs and metadata history"]
pub(crate) struct NativeMetadataBirth<'guard> {owner:MetadataAttempt<'guard>}
impl std::fmt::Debug for NativeMetadataBirth<'_> {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        f.debug_struct("NativeMetadataBirth").field("observations",&"<redacted>").finish_non_exhaustive()
    }
}

/// Terminal refusal keeps original owners and every verified or uncertain effect.
#[must_use="retain all original owners and metadata history through refusal"]
pub(crate) struct NativeMetadataFailure<'guard> {
    pub(crate) error:EnclaveError,pub(crate) boundary_errors:Vec<EnclaveError>,pub(crate) final_errors:Vec<EnclaveError>,
    pub(crate) progress:BirthProgress,owner:MetadataAttempt<'guard>,
}
impl std::fmt::Debug for NativeMetadataFailure<'_> {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        f.debug_struct("NativeMetadataFailure").field("reason",&self.error.reason)
            .field("boundary_error_count",&self.boundary_errors.len()).field("final_error_count",&self.final_errors.len())
            .field("observations",&"<redacted>").finish_non_exhaustive()
    }
}
impl<'guard> NativeRuntimeTransportBirth<'guard> {
    /// Complete both fixed directory scopes with the same actual owner chain.
    /// Actual runtime transport and cryptographic input checks precede effects;
    /// no caller-selected paths, modes, providers or exclusion reports exist.
    pub(crate) fn prepare_private_directory_metadata(self)
        ->Result<NativeMetadataBirth<'guard>,NativeMetadataFailure<'guard>> {
        let mut owner=MetadataAttempt {transport:self,payload:None,runtime:None};let mut boundary_errors=Vec::new();
        owner.transport.owner.pin.owner.payload.owner.candidate.birth.state.progress.operation="prepare_private_directory_metadata";
        let operation=(|| {
            // The actual complete create-only transport must still be private
            // and700 at this one-time entry. Never relax or re-enter that gate.
            owner.transport.owner.gate(true,&mut boundary_errors)?;
            owner.gate(&mut boundary_errors)?;
            // Prepare both actual closed scopes before any mutation: all
            // original metadata/provenance starts at the creation boundary.
            owner.prepare(Scope::Payload)?;owner.gate(&mut boundary_errors)?;
            owner.prepare(Scope::Runtime)?;owner.gate(&mut boundary_errors)?;
            owner.payload.as_ref().expect("prepared actual payload scope")
                .assert_disjoint(owner.runtime.as_ref().expect("prepared actual runtime scope"))?;
            owner.apply(Scope::Payload,&mut boundary_errors)?;
            owner.apply(Scope::Runtime,&mut boundary_errors)?;
            owner.gate(&mut boundary_errors)
        })();
        // This observation is constructed only by genuine current crypto and
        // provisioning verification. Retain its original minimum expiry across
        // every expensive final native/owner/hash/save gate below.
        let expiry=owner.transport.owner.crypto_expiry();
        let mut final_errors=owner.observations();final_errors.extend(owner.observations());
        // Last practical acceptance endpoint: a new actual clock observation
        // rejects equality, expiry and rollback relative to that verification.
        match expiry {
            Ok(expiry)=>final_errors.extend(errors([expiry.current()])),
            Err(error)=>final_errors.push(error),
        }
        match resolve_owned(owner,operation,boundary_errors,final_errors) {
            Ok(mut owner)=>{
                let progress=&mut owner.transport.owner.pin.owner.payload.owner.candidate.birth.state.progress;
                progress.complete=true;progress.uncertain_effects=false;Ok(NativeMetadataBirth {owner})
            },
            Err(mut refusal)=>{
                refusal.owner.transport.owner.pin.owner.poison();
                Err(NativeMetadataFailure {error:refusal.error,boundary_errors:refusal.boundary_errors,
                    final_errors:refusal.final_errors,
                    progress:refusal.owner.transport.owner.pin.owner.payload.owner.candidate.birth.state.progress.clone(),owner:refusal.owner})
            },
        }
    }
}
