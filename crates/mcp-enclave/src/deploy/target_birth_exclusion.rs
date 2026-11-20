//! Retain actual inhibited startup EX with the SAME selected private candidate.
//!
//! A kernel lock on cooperating actors is not complete inactivity or authority
//! to publish, install, change modes, start jobs, clear denial or activate.
//! All real owners, including post-acquisition refusal owners, remain private.
use super::*;
use enclave_core::deployment::startup_lease::{self,ExclusiveStartupLease,ExclusiveStartupLeaseFailure};

#[path="target_birth_payload.rs"]
mod payload;

// Private owned-outcome seam, not a provider or authority constructor. Both
// success and refusal keep the SAME owned value; tests can use real synthetic
// OS-lock files without constructing any native candidate/guard/EX authority.
struct RetainedRefusal<T> {
    error:EnclaveError,boundary_errors:Vec<EnclaveError>,final_errors:Vec<EnclaveError>,owner:T,
}
fn resolve_owned<T>(owner:T,operation:EnclaveResult<()>,boundary_errors:Vec<EnclaveError>,
    final_errors:Vec<EnclaveError>)->Result<T,RetainedRefusal<T>> {
    let error=operation.err().or_else(||final_errors.first().cloned());
    match error {
        Some(error)=>Err(RetainedRefusal {error,boundary_errors,final_errors,owner}),
        None=>Ok(owner),
    }
}

struct ExclusionAttempt<'guard> {
    candidate:CandidateAttempt<'guard>,
    lease:Option<ExclusiveStartupLease>,
    acquisition_failure:Option<ExclusiveStartupLeaseFailure>,
}
impl ExclusionAttempt<'_> {
    fn observations(&mut self)->Vec<EnclaveError> {
        let mut observed=self.candidate.observations(Selection::After);
        // Observe acquired EX independently even when a source/account/release
        // or original guard gate above refused. Neither failure path reacquires.
        match checked(&self.candidate.birth.state).cloned() {
            Ok(checked)=>{
                if let Some(lease)=&mut self.lease {observed.extend(errors([lease.assert_current(&checked)]));}
                if let Some(failure)=&self.acquisition_failure {observed.extend(failure.retained_checks(&checked));}
            },
            Err(error)=>observed.push(error),
        }
        observed.extend(self.candidate.observations(Selection::After));observed
    }
    fn gate(&mut self,observed:&mut Vec<EnclaveError>)->EnclaveResult<()> {
        let checks=self.observations();let result=first(&checks);observed.extend(checks);result
    }
    fn native_gate(&mut self,observed:&mut Vec<EnclaveError>)->EnclaveResult<()> {
        let verified=self.candidate.verify_candidate();
        let current=self.gate(observed);
        // The original concrete native/renderer error stays primary. The
        // independent full owner/EX gates are evaluated and retained as well.
        verified?;current
    }
}

/// Retains every original owner and any actual acquired EX after refusal.
/// No extraction, retry, resume, lock release/reacquisition or repair exists.
#[must_use="retain selected candidate, guard and acquired EX through refusal"]
pub(crate) struct NativeExclusionFailure<'guard> {
    pub(crate) error:EnclaveError,
    pub(crate) boundary_errors:Vec<EnclaveError>,pub(crate) final_errors:Vec<EnclaveError>,
    pub(crate) progress:BirthProgress,
    pub(crate) selected_context_observed:bool,
    owner:ExclusionAttempt<'guard>,
}
impl std::fmt::Debug for NativeExclusionFailure<'_> {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        f.debug_struct("NativeExclusionFailure").field("error",&self.error)
            .field("boundary_errors",&self.boundary_errors).field("final_errors",&self.final_errors)
            .field("progress",&self.progress).field("selected_context_observed",&self.selected_context_observed)
            .field("acquisition_failure",&self.owner.acquisition_failure).finish_non_exhaustive()
    }
}

/// Original selected candidate and actual inhibited EX, retained together.
/// No inactivity, filesystem mutation or installation authority is exported.
pub(crate) struct NativeExcludedCandidateBirth<'guard> {owner:ExclusionAttempt<'guard>}
impl std::fmt::Debug for NativeExcludedCandidateBirth<'_> {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        f.debug_struct("NativeExcludedCandidateBirth").finish_non_exhaustive()
    }
}
impl<'guard> NativeSelectedCandidateBirth<'guard> {
    /// Acquire once under the original denial and original selected candidate.
    /// Core failures retain even an EX acquired before a later core postcheck
    /// refused; the older dropping acquisition adapter is never used here.
    pub(crate) fn retain_inhibited_exclusion(self)
        ->Result<NativeExcludedCandidateBirth<'guard>,NativeExclusionFailure<'guard>> {
        let candidate=self.owner;
        let mut owner=ExclusionAttempt {candidate:CandidateAttempt {birth:candidate.birth,
            plan:Some(candidate.plan),accounts:Some(candidate.accounts),approval:Some(candidate.approval),
            release_failure:None},lease:None,acquisition_failure:None};
        owner.candidate.birth.state.progress.operation="retain_inhibited_startup_exclusion";
        let mut boundary_errors=Vec::new();
        let operation=(|| {
            owner.gate(&mut boundary_errors)?;
            owner.native_gate(&mut boundary_errors)?;
            let checked=checked(&owner.candidate.birth.state)?.clone();
            match startup_lease::try_exclusive_inhibited_retained(&checked) {
                Ok(lease)=>owner.lease=Some(lease),
                Err(failure)=>{
                    let original=failure.error.clone();
                    boundary_errors.extend(failure.final_errors.iter().cloned());
                    owner.acquisition_failure=Some(failure);return Err(original);
                },
            }
            owner.gate(&mut boundary_errors)?;
            owner.native_gate(&mut boundary_errors)
        })();
        // Every final available source/Layout/account/software/native/guard/EX
        // gate is attempted even on an earlier refusal. The actual native
        // verifier retains its own exported error precedence and limits.
        let mut final_errors=owner.observations();
        final_errors.extend(errors([owner.candidate.verify_candidate()]));
        final_errors.extend(owner.observations());
        match resolve_owned(owner,operation,boundary_errors,final_errors) {
            Ok(mut owner)=>{
                debug_assert!(owner.lease.is_some()&&owner.acquisition_failure.is_none());
                owner.candidate.birth.state.progress.complete=true;
                owner.candidate.birth.state.progress.uncertain_effects=false;
                Ok(NativeExcludedCandidateBirth {owner})
            },
            Err(mut refusal)=>{
                refusal.owner.candidate.birth.state.poisoned=true;
                refusal.owner.candidate.birth.state.progress.complete=false;
                refusal.owner.candidate.birth.state.progress.uncertain_effects=true;
                Err(NativeExclusionFailure {error:refusal.error,boundary_errors:refusal.boundary_errors,
                    final_errors:refusal.final_errors,progress:refusal.owner.candidate.birth.state.progress.clone(),
                    selected_context_observed:deployment::selected().is_some(),owner:refusal.owner})
            },
        }
    }
}

#[cfg(test)]
#[path="target_birth_exclusion_tests.rs"]
mod tests;
