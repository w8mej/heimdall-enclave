//! Consume the actual fully visible birth before removing its OWN denial.
//! The native birth bridge retains the original kernel attempt and SAME EX,
//! mints only actual durable own-removal proof, and consumes that same EX into
//! Dedicated. No old inhibition-present observer runs after bridge entry.
//! Every outcome retains the entire original visibility/authority owner chain.
use super::*;

#[path = "target_birth_registration.rs"]
mod registration;
use crate::deploy::target_birth::denial_handoff::NativeDenialPhaseFailure;

// Routing state only; this cannot create removal proof or a native owner.
// Switch BEFORE passing EX to the bridge, including all refused handoffs.
enum ClearPhase {
    BeforeHandoff,
    HandedOff,
}
struct ClearAttempt<'guard> {
    visible: NativeVisibleBirth<'guard>,
    phase: ClearPhase,
    native_failure: Option<NativeDenialPhaseFailure>,
}
impl ClearAttempt<'_> {
    fn poison(&mut self) {
        self.visible.owner.poison();
    }
    fn denial_may_have_been_removed(&self) -> bool {
        self.visible
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
            .denial_may_have_been_removed()
    }
    fn postclear_observations(&mut self) -> Vec<EnclaveError> {
        let visibility = &mut self.visible.owner;
        let mut observed = Vec::new();
        // A bool, report, namespace absence or successful ordinary fixture
        // cannot satisfy either actual proof or the dedicated lease ledger.
        if visibility.pending.is_some()
            || visibility.core_failure.is_some()
            || visibility.birth_failures.iter().any(Option::is_some)
            || visibility.software_failures.iter().any(Option::is_some)
            || visibility.birth.iter().any(Option::is_none)
            || visibility.software.iter().any(Option::is_none)
        {
            observed.push(err!(EACCES, "BIRTH_CLEAR_COMPLETE_VISIBLE_OWNER_REQUIRED"));
        }
        {
            let jobs = &mut visibility.jobs.owner;
            let metadata = &mut jobs.metadata.owner;
            let original = &mut metadata.transport.owner.pin.owner;
            observed.extend(errors([
                require_native_root(),
                original.scope().map(|_| ()),
            ]));
            observed.extend(original.inputs.observations());
            observed.extend(original.source_separation());
            observed.extend(errors([original
                .scope()
                .and_then(|scope| original.inputs.complete(&scope))]));
            let exclusion = &mut original.payload.owner;
            if exclusion.lease.is_some() || exclusion.acquisition_failure.is_some() {
                observed.push(err!(EACCES, "BIRTH_CLEAR_ORIGINAL_EX_HANDOFF_REQUIRED"));
            }
            let candidate = &mut exclusion.candidate;
            let birth = &mut candidate.birth;
            let state = &birth.state;
            let removal = birth.denial_removal.proof();
            if removal.is_none() {
                observed.push(err!(EACCES, "BIRTH_CLEAR_ACTUAL_OWNED_REMOVAL_REQUIRED"));
            }
            if state.poisoned {
                observed.push(err!(EACCES, "BIRTH_OWNER_POISONED"));
            }
            observed.extend(state.checks_with_content_owned_removal(
                &mut || errors([require_native_root(), birth.guard.assert_held()]),
                true,
                removal,
            ));
            observed.extend(birth.accepted_directory_events_current_with_owned_removal(removal));
            if state
                .files
                .values()
                .any(|file| file.access != libc::O_RDONLY)
            {
                observed.push(err!(EACCES, "BIRTH_CLEAR_ORIGINAL_READONLY_REQUIRED"));
            }
            observed.extend(errors([original
                .payload
                .plan
                .assert_retained_copies(state)]));
            for source in &metadata.transport.owner.sources {
                observed.extend(errors([source_current(state, &source.spec, true)]));
            }
            match &metadata.transport.owner.plan {
                Some(plan) => {
                    observed.extend(plan.contents_current(state, &original.inputs.pin_bytes, true))
                }
                None => observed.push(err!(EACCES, "BIRTH_CLEAR_RUNTIME_REQUIRED")),
            }
            for attempt in [&metadata.payload, &metadata.runtime] {
                match attempt {
                    Some(attempt) => observed.extend(
                        attempt.retained_completed_observations_with_owned_removal(state, removal),
                    ),
                    None => observed.push(err!(EACCES, "BIRTH_CLEAR_COMPLETED_METADATA_REQUIRED")),
                }
            }
            match &jobs.plan {
                Some(plan) => observed.extend(plan.sources_current(state, true)),
                None => observed.push(err!(EACCES, "BIRTH_CLEAR_JOBS_PLAN_REQUIRED")),
            }
            match &jobs.external {
                Some(external) => observed.extend(external.observations(true)),
                None => observed.push(err!(EACCES, "BIRTH_CLEAR_COMPLETE_JOBS_REQUIRED")),
            }
            match checked(state).cloned() {
                Ok(checked) => {
                    if !deployment::selected().is_some_and(|selected| {
                        selected.target() == checked.target()
                            && selected.config_path() == checked.config_path()
                            && selected.descriptor_sha256() == checked.descriptor_sha256()
                    }) {
                        observed.push(err!(ESTALE, "BIRTH_CLEAR_SELECTED_BINDING"));
                    }
                    match &candidate.accounts {
                        Some(accounts) => observed
                            .extend(errors([accounts.assert_current(&checked, birth.guard)])),
                        None => observed.push(err!(EACCES, "BIRTH_CLEAR_ACTUAL_ACCOUNTS_REQUIRED")),
                    }
                    for role in [
                        PrivateBirthAncestor::SupportRoot,
                        PrivateBirthAncestor::NonceRoot,
                    ] {
                        let index = slot(role);
                        let path = match role {
                            PrivateBirthAncestor::SupportRoot => {
                                &state.plan.target.layout.support_root
                            }
                            PrivateBirthAncestor::NonceRoot => &state.plan.root,
                        };
                        match (
                            &visibility.birth[index],
                            birth.accepted_directory_event(role),
                            &visibility.software[index],
                            state.dirs.get(path),
                        ) {
                            (Some(receipt), Some(recorded), Some(software), Some(directory)) => {
                                let event = receipt.event();
                                let after = event.after();
                                if !Arc::ptr_eq(event, recorded)
                                    || !Arc::ptr_eq(event, software)
                                    || event.ancestor() != role
                                    || event.path() != path
                                    || !event.durability_completed()
                                    || !directory.private
                                    || after.mode & 0o7777 != 0o755
                                    || (
                                        directory.stamp.dev,
                                        directory.stamp.ino,
                                        directory.stamp.uid,
                                        directory.stamp.gid,
                                        directory.stamp.mode,
                                    ) != (after.dev, after.ino, after.uid, after.gid, after.mode)
                                {
                                    observed
                                        .push(err!(ESTALE, "BIRTH_CLEAR_ORIGINAL_EVENT_BINDING"));
                                }
                                match &mut candidate.approval {
                                    Some(approval) => observed.extend(errors([approval
                                        .assert_accepted_directory_change_history(
                                            &checked, event,
                                        )])),
                                    None => observed
                                        .push(err!(EACCES, "BIRTH_CLEAR_ACTUAL_SOFTWARE_REQUIRED")),
                                }
                            }
                            _ => {
                                observed.push(err!(EACCES, "BIRTH_CLEAR_BOTH_RECIPIENTS_REQUIRED"))
                            }
                        }
                    }
                    match &mut candidate.approval {
                        Some(approval) => observed
                            .extend(errors([approval.assert_current(&checked, birth.guard)])),
                        None => observed.push(err!(EACCES, "BIRTH_CLEAR_ACTUAL_SOFTWARE_REQUIRED")),
                    }
                    // This gate alone checks the postclear Dedicated lease.
                    // It never calls the old inhibited EX marker-present gate.
                    observed.extend(birth.denial_removal.current(state, &checked));
                    if let Some(failure) = &self.native_failure {
                        observed.extend(failure.retained_checks(&checked));
                    }
                }
                Err(error) => observed.push(error),
            }
            if let Some(failure) = &candidate.release_failure {
                observed.extend(failure.retained_checks());
            }
            if self.native_failure.is_some() {
                observed.push(err!(EACCES, "BIRTH_CLEAR_NATIVE_HANDOFF_REFUSED"));
            }
            observed.extend(errors([require_native_root(), birth.guard.assert_held()]));
        }
        // Actual code/renderer verification remains mandatory. It uses the
        // original staged files/plan and approval, and has no inhibited EX gate.
        observed.extend(errors([visibility
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
            .verify_candidate()]));
        let transport = &visibility.jobs.owner.metadata.owner.transport.owner;
        let birth = &transport.pin.owner.payload.owner.candidate.birth;
        observed.extend(errors([transport
            .crypto_expiry_with_owned_removal(birth.denial_removal.proof())
            .map(|_| ())]));
        observed
    }
    fn observations(&mut self) -> Vec<EnclaveError> {
        match self.phase {
            ClearPhase::BeforeHandoff => self.visible.owner.ready_observations(),
            ClearPhase::HandedOff => self.postclear_observations(),
        }
    }
    fn crypto_expiry(&self) -> EnclaveResult<CryptoExpiryObservation> {
        let transport = &self.visible.owner.jobs.owner.metadata.owner.transport.owner;
        match self.phase {
            ClearPhase::BeforeHandoff => transport.crypto_expiry(),
            ClearPhase::HandedOff => transport.crypto_expiry_with_owned_removal(
                transport
                    .pin
                    .owner
                    .payload
                    .owner
                    .candidate
                    .birth
                    .denial_removal
                    .proof(),
            ),
        }
    }
    fn gate(&mut self, observed: &mut Vec<EnclaveError>) -> EnclaveResult<()> {
        let expiry = self.crypto_expiry();
        let checks = self.observations();
        let current = first(&checks);
        observed.extend(checks);
        let last = match expiry {
            Ok(expiry) => expiry.current(),
            Err(error) => Err(error),
        };
        if let Err(error) = &last {
            observed.push(error.clone());
        }
        if current.is_err() || last.is_err() {
            self.poison();
        }
        current?;
        last
    }
    fn clear(&mut self, observed: &mut Vec<EnclaveError>) -> EnclaveResult<()> {
        if !matches!(self.phase, ClearPhase::BeforeHandoff) {
            fail!(EALREADY, "BIRTH_CLEAR_NO_RETRY");
        }
        self.visible.owner.ready_gate(observed)?;
        // This private observation can only come from the actual successful
        // verifier. The native kernel checks its same expiry after each slow
        // boundary, including immediately before the irreversible unlink.
        let expiry = self.crypto_expiry()?;
        // Validate every required borrowed actual input BEFORE taking EX. Once
        // the phase changes, even a refused bridge uses only postclear gates.
        let original = &mut self
            .visible
            .owner
            .jobs
            .owner
            .metadata
            .owner
            .transport
            .owner
            .pin
            .owner;
        let paths = original
            .inputs
            .paths
            .as_ref()
            .ok_or_else(|| err!(EACCES, "BIRTH_CLEAR_ORIGINAL_OPERATOR_PATHS_REQUIRED"))?;
        let record = original
            .inputs
            .record
            .as_ref()
            .ok_or_else(|| err!(EACCES, "BIRTH_CLEAR_ORIGINAL_OPERATOR_RECORD_REQUIRED"))?;
        let pin = original
            .inputs
            .pin
            .as_ref()
            .ok_or_else(|| err!(EACCES, "BIRTH_CLEAR_ORIGINAL_OPERATOR_PIN_REQUIRED"))?;
        let exclusion = &mut original.payload.owner;
        let candidate = &mut exclusion.candidate;
        let accounts = candidate
            .accounts
            .as_ref()
            .ok_or_else(|| err!(EACCES, "BIRTH_CLEAR_ACTUAL_ACCOUNTS_REQUIRED"))?;
        let approval = candidate
            .approval
            .as_mut()
            .ok_or_else(|| err!(EACCES, "BIRTH_CLEAR_ACTUAL_SOFTWARE_REQUIRED"))?;
        let lease = exclusion
            .lease
            .take()
            .ok_or_else(|| err!(EACCES, "BIRTH_CLEAR_SAME_EX_REQUIRED"))?;
        self.phase = ClearPhase::HandedOff;
        match candidate
            .birth
            .remove_owned_startup_denial(lease, accounts, approval, paths, record, pin, &expiry)
        {
            Ok(()) => (),
            Err(failure) => {
                let error = failure.error.clone();
                observed.extend(failure.boundary_errors.iter().cloned());
                observed.extend(failure.final_errors.iter().cloned());
                self.native_failure = Some(failure);
                return Err(error);
            }
        }
        self.gate(observed)
    }
}

/// Actual own denial removed durably, with the SAME EX now held as Dedicated.
/// No job start, owner release, activation or profile qualification is implied.
#[must_use = "retain the actual visible owner, removal proof and SAME Dedicated lease"]
pub(crate) struct NativeClearedBirth<'guard> {
    owner: ClearAttempt<'guard>,
}
impl std::fmt::Debug for NativeClearedBirth<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeClearedBirth")
            .field("observations", &"<redacted>")
            .finish_non_exhaustive()
    }
}
#[must_use = "retain every original owner, removal/transition attempt and refusal"]
pub(crate) struct NativeClearFailure<'guard> {
    pub(crate) error: EnclaveError,
    pub(crate) boundary_errors: Vec<EnclaveError>,
    pub(crate) final_errors: Vec<EnclaveError>,
    pub(crate) progress: BirthProgress,
    owner: ClearAttempt<'guard>,
}
impl NativeClearFailure<'_> {
    pub(crate) fn denial_may_have_been_removed(&self) -> bool {
        self.owner.denial_may_have_been_removed()
    }
}
impl std::fmt::Debug for NativeClearFailure<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeClearFailure")
            .field("reason", &self.error.reason)
            .field("boundary_error_count", &self.boundary_errors.len())
            .field("final_error_count", &self.final_errors.len())
            .field(
                "denial_may_have_been_removed",
                &self.denial_may_have_been_removed(),
            )
            .field("observations", &"<redacted>")
            .finish_non_exhaustive()
    }
}
impl<'guard> NativeVisibleBirth<'guard> {
    pub(crate) fn clear_owned_startup_denial(
        self,
    ) -> Result<NativeClearedBirth<'guard>, NativeClearFailure<'guard>> {
        let mut owner = ClearAttempt {
            visible: self,
            phase: ClearPhase::BeforeHandoff,
            native_failure: None,
        };
        owner
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
            .operation = "clear_owned_startup_denial";
        let mut boundary_errors = Vec::new();
        let operation = owner.clear(&mut boundary_errors);
        // Capture expiry BEFORE both expensive final passes. current() is the
        // last practical acceptance endpoint, including genuine save/native
        // work. Expiry or rollback can never be refreshed into acceptance.
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
                Ok(NativeClearedBirth { owner })
            }
            Err(mut refusal) => {
                refusal.owner.poison();
                Err(NativeClearFailure {
                    error: refusal.error,
                    boundary_errors: refusal.boundary_errors,
                    final_errors: refusal.final_errors,
                    progress: refusal
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
#[path = "target_birth_clear_tests.rs"]
mod tests;
