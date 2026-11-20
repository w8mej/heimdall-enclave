//! Explicitly relinquish startup EX only from the actual registered owner.
//! All original authorities/currentness and earliest crypto expiry precede
//! the actual ledger's one consuming Dedicated drop. Keep every remaining
//! owner/outcome and actual release history even after a late refusal. No
//! actor health, auxiliary startup or full installation readiness is inferred.
use super::*;

// Routing state cannot create release history or replace its native producer.
// Switch BEFORE the endpoint, so even its late refusal never re-enters a
// former Dedicated-currentness gate after intentionally relinquishing EX.
enum StartupReleasePhase {
    BeforeEndpoint,
    EndpointEntered,
}
struct StartupReleaseAttempt<'guard> {
    registered: NativeRegisteredBirth<'guard>,
    phase: StartupReleasePhase,
}

fn original_fields<'a, 'guard>(
    registered: &'a mut NativeRegisteredBirth<'guard>,
) -> EnclaveResult<RegistrationOriginals<'a>> {
    original_registration_fields(&mut registered.owner.cleared)
}
impl StartupReleaseAttempt<'_> {
    fn poison(&mut self) {
        self.registered.owner.poison();
    }
    fn startup_exclusion_may_have_been_released(&self) -> bool {
        self.registered
            .owner
            .cleared
            .owner
            .visible
            .owner
            .jobs
            .owner
            .metadata
            .owner
            .transport
            .owner
            .pin
            .owner
            .payload
            .owner
            .candidate
            .birth
            .denial_removal
            .dedicated_release_may_have_occurred()
    }
    fn crypto_expiry(&self) -> EnclaveResult<CryptoExpiryObservation> {
        // This actual verifier reads only original sources and typed own-unlink
        // proof. It has no old Dedicated or inhibited-EX currentness gate.
        self.registered.owner.cleared.owner.crypto_expiry()
    }
    fn retained_registration_errors(&self) -> Vec<EnclaveError> {
        let mut observed = Vec::new();
        if !self.registered.owner.adapter_entered {
            observed.push(err!(
                EACCES,
                "BIRTH_STARTUP_RELEASE_ACTUAL_REGISTRATION_REQUIRED"
            ));
        }
        match &self.registered.owner.outcome {
            Some(outcome) => {
                observed.extend(outcome.currentness_errors.iter().cloned());
                observed.extend(outcome.lifecycle.error.iter().cloned());
                observed.extend(outcome.lifecycle.maintenance_error.iter().cloned());
                if !outcome.lifecycle.successful {
                    observed.push(err!(EACCES, "BIRTH_STARTUP_RELEASE_REGISTRATION_REFUSED"));
                }
            }
            None => observed.push(err!(
                EACCES,
                "BIRTH_STARTUP_RELEASE_NATIVE_OUTCOME_REQUIRED"
            )),
        }
        observed
    }
    fn observations_after_endpoint(&mut self) -> Vec<EnclaveError> {
        let mut observed = self.retained_registration_errors();
        match original_fields(&mut self.registered) {
            Ok(mut originals) => {
                // Requires actual native release history. Missing/failed
                // release cannot substitute a caller flag or mere absence.
                let result = originals
                    .boundary
                    .gate_after_release(originals.guard, &mut observed);
                if let Err(error) = result {
                    observed.push(error);
                }
            }
            Err(error) => observed.push(error),
        }
        observed
    }
    fn observations(&mut self) -> Vec<EnclaveError> {
        match self.phase {
            StartupReleasePhase::BeforeEndpoint => self.registered.owner.observations(),
            StartupReleasePhase::EndpointEntered => self.observations_after_endpoint(),
        }
    }
    fn release(&mut self, observed: &mut Vec<EnclaveError>) -> EnclaveResult<()> {
        if !matches!(self.phase, StartupReleasePhase::BeforeEndpoint) {
            fail!(EALREADY, "BIRTH_STARTUP_RELEASE_NO_RETRY");
        }
        let expiry = self.crypto_expiry();
        let checks = self.registered.owner.observations();
        let current = first(&checks);
        observed.extend(checks);
        let repeated = self.registered.owner.observations();
        let final_current = first(&repeated);
        observed.extend(repeated);
        let history = self.retained_registration_errors();
        let actual_history = first(&history);
        observed.extend(history);
        // Earliest actual verifier expiry spans both expensive original-owner
        // passes. Never recompute a deadline from a report or reset a floor.
        let expiry = expiry?;
        current?;
        final_current?;
        actual_history?;
        let RegistrationOriginals {
            boundary,
            guard,
            checked,
        } = original_fields(&mut self.registered)?;
        expiry.current()?;
        self.phase = StartupReleasePhase::EndpointEntered;
        // Actual native endpoint separately verifies SAME guard, original
        // proof/context and SAME held Dedicated, then expiry LAST before taking
        // that exact owner and intentionally dropping it ONCE. All effect
        // history remains inside the original ledger, including late refusal.
        let operation =
            boundary
                .denial
                .release_same_dedicated(boundary.state, &checked, guard, &expiry);
        // Promotion is bound to actual native SAME-ledger drop history. It
        // derives only from the immutable prebootstrap17 snapshots, never
        // sampling a replacement nlink baseline after actors can begin work.
        let promotion =
            if self.startup_exclusion_may_have_been_released() {
                let metadata = &mut self
                    .registered
                    .owner
                    .cleared
                    .owner
                    .visible
                    .owner
                    .jobs
                    .owner
                    .metadata
                    .owner;
                let candidate = &mut metadata.transport.owner.pin.owner.payload.owner.candidate;
                let accounts = candidate.accounts.as_ref().ok_or_else(|| {
                    err!(EACCES, "BIRTH_STARTUP_RELEASE_ACTUAL_ACCOUNTS_REQUIRED")
                })?;
                let approval = candidate.approval.as_mut().ok_or_else(|| {
                    err!(EACCES, "BIRTH_STARTUP_RELEASE_ACTUAL_SOFTWARE_REQUIRED")
                })?;
                let payload = metadata.payload.as_ref().ok_or_else(|| {
                    err!(EACCES, "BIRTH_STARTUP_RELEASE_PAYLOAD_METADATA_REQUIRED")
                })?;
                let runtime = metadata.runtime.as_ref().ok_or_else(|| {
                    err!(EACCES, "BIRTH_STARTUP_RELEASE_RUNTIME_METADATA_REQUIRED")
                })?;
                candidate.birth.observe_released_live_directories(
                    accounts, approval, payload, runtime, &expiry,
                )
            } else {
                Err(err!(EACCES, "BIRTH_STARTUP_RELEASE_ACTUAL_DROP_REQUIRED"))
            };
        if let Err(error) = &promotion {
            observed.push(error.clone());
        }
        operation?;
        promotion
    }
}

/// Actual retained startup-EX owner intentionally relinquished once, with all
/// remaining original owners/proofs/outcomes retained. Runtime readiness is
/// UNKNOWN; this type grants no actor, auxiliary or profile qualification.
#[must_use = "retain all remaining original owners and actual startup-release history"]
pub(crate) struct NativeStartupReleasedBirth<'guard> {
    owner: StartupReleaseAttempt<'guard>,
}
impl std::fmt::Debug for NativeStartupReleasedBirth<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeStartupReleasedBirth")
            .field("runtime_readiness", &"UNKNOWN")
            .field("observations", &"<redacted>")
            .finish_non_exhaustive()
    }
}
#[must_use = "retain actual release history, remaining owners and every late refusal"]
pub(crate) struct NativeStartupReleaseFailure<'guard> {
    pub(crate) error: EnclaveError,
    pub(crate) boundary_errors: Vec<EnclaveError>,
    pub(crate) final_errors: Vec<EnclaveError>,
    pub(crate) progress: BirthProgress,
    owner: StartupReleaseAttempt<'guard>,
}
impl NativeStartupReleaseFailure<'_> {
    pub(crate) fn startup_exclusion_may_have_been_released(&self) -> bool {
        self.owner.startup_exclusion_may_have_been_released()
    }
}
impl std::fmt::Debug for NativeStartupReleaseFailure<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeStartupReleaseFailure")
            .field("reason", &self.error.reason)
            .field("boundary_error_count", &self.boundary_errors.len())
            .field("final_error_count", &self.final_errors.len())
            .field(
                "startup_exclusion_may_have_been_released",
                &self.startup_exclusion_may_have_been_released(),
            )
            .field("observations", &"<redacted>")
            .finish_non_exhaustive()
    }
}
impl<'guard> NativeRegisteredBirth<'guard> {
    pub(crate) fn release_startup_exclusion(
        self,
    ) -> Result<NativeStartupReleasedBirth<'guard>, NativeStartupReleaseFailure<'guard>> {
        let mut owner = StartupReleaseAttempt {
            registered: self,
            phase: StartupReleasePhase::BeforeEndpoint,
        };
        owner
            .registered
            .owner
            .cleared
            .owner
            .visible
            .owner
            .jobs
            .owner
            .metadata
            .owner
            .transport
            .owner
            .pin
            .owner
            .payload
            .owner
            .candidate
            .birth
            .state
            .progress
            .operation = "release_startup_exclusion";
        let mut boundary_errors = Vec::new();
        let operation = owner.release(&mut boundary_errors);
        let expiry = owner.crypto_expiry();
        let mut final_errors = owner.observations();
        final_errors.extend(owner.observations());
        match expiry {
            Ok(expiry) => final_errors.extend(errors([expiry.current()])),
            Err(error) => final_errors.push(error),
        }
        match resolve_owned(owner, operation, boundary_errors, final_errors) {
            Ok(mut owner) => {
                let progress = &mut owner
                    .registered
                    .owner
                    .cleared
                    .owner
                    .visible
                    .owner
                    .jobs
                    .owner
                    .metadata
                    .owner
                    .transport
                    .owner
                    .pin
                    .owner
                    .payload
                    .owner
                    .candidate
                    .birth
                    .state
                    .progress;
                progress.complete = true;
                progress.uncertain_effects = false;
                Ok(NativeStartupReleasedBirth { owner })
            }
            Err(mut refusal) => {
                refusal.owner.poison();
                Err(NativeStartupReleaseFailure {
                    error: refusal.error,
                    boundary_errors: refusal.boundary_errors,
                    final_errors: refusal.final_errors,
                    progress: refusal
                        .owner
                        .registered
                        .owner
                        .cleared
                        .owner
                        .visible
                        .owner
                        .jobs
                        .owner
                        .metadata
                        .owner
                        .transport
                        .owner
                        .pin
                        .owner
                        .payload
                        .owner
                        .candidate
                        .birth
                        .state
                        .progress
                        .clone(),
                    owner: refusal.owner,
                })
            }
        }
    }
}

#[cfg(test)]
#[path = "target_birth_startup_release_tests.rs"]
mod tests;
