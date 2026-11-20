//! Register core jobs while retaining the actual SAME Dedicated startup EX.
//! Only an actual NativeClearedBirth enters. The concrete native adapter
//! borrows its original guard and calls full original-owner denial gates at
//! every native verifier/launchctl boundary. No lease release or readiness.
use super::*;

#[path = "target_birth_startup_release.rs"]
mod startup_release;
use crate::ctl::{selected_core_start_with_retained_guard, Env, RetainedGuardCoreStartOutcome};
use crate::deploy::target_birth::{
    denial_handoff::DenialRemovalLedger, directory_event::DirectoryEventLedger,
    live_directories::LiveDirectoryLedger, metadata::OwnMetadataAttempt,
};

// Borrows actual disjoint fields from the one retained owner. No constructor
// accepts a report, flags, replacement guard, original owners or fake proof.
struct RegistrationBoundary<'a> {
    state: &'a BirthState,
    denial: &'a mut DenialRemovalLedger,
    events: &'a DirectoryEventLedger,
    live: &'a LiveDirectoryLedger,
    scope: PinScope,
    inputs: &'a OperatorPinInputs,
    payload: &'a PrivatePayloadPlan,
    candidate: &'a TargetInstallPlan,
    accounts: &'a FixedAccountAdmission,
    approval: &'a mut SoftwareApproval,
    metadata: [&'a OwnMetadataAttempt; 2],
    sources: &'a [RuntimeSource],
    transport: &'a RuntimeTransportPlan,
    jobs: &'a JobsPlan,
    external: &'a ExternalJobs,
    birth_receipts: &'a [Option<BirthDirectoryAcceptance>; 2],
    software_events: &'a [Option<Arc<DirectoryModeChange>>; 2],
}
impl RegistrationBoundary<'_> {
    fn originals_observations(&mut self, guard: &mut HostMaintenanceGuard) -> Vec<EnclaveError> {
        let state = self.state;
        let mut observed = errors([require_native_root(), guard.assert_held()]);
        let removal = self.denial.proof();
        if removal.is_none() {
            observed.push(err!(EACCES, "BIRTH_REGISTRATION_ACTUAL_REMOVAL_REQUIRED"));
        }
        if state.poisoned {
            observed.push(err!(EACCES, "BIRTH_OWNER_POISONED"));
        }
        observed.extend(state.checks_with_content_live_directories(
            &mut || errors([require_native_root(), guard.assert_held()]),
            true,
            removal,
            self.live.scope(),
        ));
        observed.extend(self.events.current_with_owned_removal(state, removal));
        if state
            .files
            .values()
            .any(|file| file.access != libc::O_RDONLY)
        {
            observed.push(err!(
                EACCES,
                "BIRTH_REGISTRATION_ORIGINAL_READONLY_REQUIRED"
            ));
        }
        observed.extend(self.inputs.observations());
        observed.extend(errors([self.inputs.complete(&self.scope)]));
        let originals = state
            .files
            .values()
            .map(|file| (file.stamp.directory.dev, file.stamp.directory.ino))
            .chain(
                state
                    .dirs
                    .values()
                    .map(|directory| (directory.stamp.dev, directory.stamp.ino)),
            )
            .collect::<BTreeSet<_>>();
        let held = [&self.inputs.record, &self.inputs.pin]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        observed.extend(errors([independent_inodes(&held, &originals)]));
        let external_sources = held
            .into_iter()
            .map(|file| (file.path(), file.file()))
            .collect::<Vec<_>>();
        observed.extend(errors([
            self.approval
                .assert_external_runtime_sources_separate(&external_sources),
            self.payload.assert_retained_copies(state),
        ]));
        for source in self.sources {
            observed.extend(errors([source_current(state, &source.spec, true)]));
        }
        observed.extend(
            self.transport
                .contents_current(state, &self.inputs.pin_bytes, true),
        );
        for attempt in self.metadata {
            observed.extend(
                attempt.retained_completed_observations_with_live_directories(
                    state,
                    removal,
                    self.live.scope(),
                ),
            );
        }
        observed.extend(self.jobs.sources_current(state, true));
        observed.extend(self.external.observations(true));
        match checked(state).cloned() {
            Ok(checked) => {
                if !deployment::selected().is_some_and(|selected| {
                    selected.target() == checked.target()
                        && selected.config_path() == checked.config_path()
                        && selected.descriptor_sha256() == checked.descriptor_sha256()
                }) {
                    observed.push(err!(ESTALE, "BIRTH_REGISTRATION_SELECTED_BINDING"));
                }
                observed.extend(errors([
                    self.accounts.assert_current(&checked, guard),
                    self.approval.assert_current(&checked, guard),
                ]));
                for role in [
                    PrivateBirthAncestor::SupportRoot,
                    PrivateBirthAncestor::NonceRoot,
                ] {
                    let index = slot(role);
                    let path = match role {
                        PrivateBirthAncestor::SupportRoot => &state.plan.target.layout.support_root,
                        PrivateBirthAncestor::NonceRoot => &state.plan.root,
                    };
                    match (
                        &self.birth_receipts[index],
                        self.events.accepted_event(role),
                        &self.software_events[index],
                        state.dirs.get(path),
                    ) {
                        (Some(receipt), Some(recorded), Some(software), Some(directory)) => {
                            let event = receipt.event();
                            let after = event.after();
                            if !Arc::ptr_eq(event, recorded)
                                || !Arc::ptr_eq(event, software)
                                || event.path() != path
                                || event.ancestor() != role
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
                                observed.push(err!(
                                    ESTALE,
                                    "BIRTH_REGISTRATION_ORIGINAL_EVENT_BINDING"
                                ));
                            }
                            observed.extend(errors([self
                                .approval
                                .assert_accepted_directory_change_history(&checked, event)]));
                        }
                        _ => observed
                            .push(err!(EACCES, "BIRTH_REGISTRATION_BOTH_RECIPIENTS_REQUIRED")),
                    }
                }
                let native = staged_views(state, self.candidate).and_then(|files| {
                    target_candidate::verify_candidate_native_and_rendered(
                        &checked,
                        self.candidate,
                        &files,
                        self.approval,
                        guard,
                    )
                });
                observed.extend(errors([
                    native,
                    self.accounts.assert_current(&checked, guard),
                    self.approval.assert_current(&checked, guard),
                ]));
            }
            Err(error) => observed.push(error),
        }
        observed.extend(self.inputs.observations());
        observed.extend(errors([self.inputs.complete(&self.scope)]));
        observed.extend(errors([require_native_root(), guard.assert_held()]));
        observed
    }
    // Both routes check the actual native ledger before AND after every
    // original-source/native/save gate. No caller phase flag supplies proof.
    fn held_lease_observations(&mut self) -> Vec<EnclaveError> {
        match checked(self.state).cloned() {
            Ok(checked) => {
                let mut observed = self.denial.current(self.state, &checked);
                observed.extend(
                    self.live
                        .registration_observations(self.state, self.denial.proof()),
                );
                observed
            }
            Err(error) => vec![error],
        }
    }
    fn released_lease_observations(&mut self) -> Vec<EnclaveError> {
        match checked(self.state).cloned() {
            Ok(checked) => {
                let mut observed = self.denial.current_after_release(self.state, &checked);
                observed.extend(
                    self.live
                        .released_observations(self.state, self.denial.proof()),
                );
                observed
            }
            Err(error) => vec![error],
        }
    }
    fn observations(&mut self, guard: &mut HostMaintenanceGuard) -> Vec<EnclaveError> {
        let mut observed = self.held_lease_observations();
        observed.extend(self.originals_observations(guard));
        observed.extend(self.held_lease_observations());
        observed
    }
    fn observations_after_release(
        &mut self,
        guard: &mut HostMaintenanceGuard,
    ) -> Vec<EnclaveError> {
        let mut observed = self.released_lease_observations();
        observed.extend(self.originals_observations(guard));
        observed.extend(self.released_lease_observations());
        observed
    }
    fn gate_after_release(
        &mut self,
        guard: &mut HostMaintenanceGuard,
        observed: &mut Vec<EnclaveError>,
    ) -> EnclaveResult<()> {
        let expiry = crypto_expiry_from_originals(
            self.state,
            self.inputs,
            self.sources,
            &self.scope,
            self.denial.proof(),
        );
        let checks = self.observations_after_release(guard);
        let current = first(&checks);
        observed.extend(checks);
        let last = match expiry {
            Ok(expiry) => expiry.current(),
            Err(error) => Err(error),
        };
        if let Err(error) = &last {
            observed.push(error.clone());
        }
        current?;
        last
    }
    fn gate(
        &mut self,
        guard: &mut HostMaintenanceGuard,
        observed: &mut Vec<EnclaveError>,
    ) -> EnclaveResult<()> {
        // Genuine verifier construction remains centralized in the original
        // runtime transport helper. Its minimum expiry spans all expensive
        // original-file/native/save checks and is checked LAST before effects.
        let expiry = crypto_expiry_from_originals(
            self.state,
            self.inputs,
            self.sources,
            &self.scope,
            self.denial.proof(),
        );
        let checks = self.observations(guard);
        let current = first(&checks);
        observed.extend(checks);
        let last = match expiry {
            Ok(expiry) => expiry.current(),
            Err(error) => Err(error),
        };
        if let Err(error) = &last {
            observed.push(error.clone());
        }
        current?;
        last
    }
}

struct RegistrationOriginals<'a> {
    boundary: RegistrationBoundary<'a>,
    guard: &'a mut HostMaintenanceGuard,
    checked: CheckedDeploymentTarget,
}
// Borrow only this concrete complete same-invocation predecessor's disjoint
// fields. No caller guard/plan/report/receipt/EX/proof constructor is accepted.
fn original_registration_fields<'a, 'guard>(
    cleared: &'a mut NativeClearedBirth<'guard>,
) -> EnclaveResult<RegistrationOriginals<'a>> {
    let clear = &mut cleared.owner;
    if !matches!(clear.phase, ClearPhase::HandedOff) || clear.native_failure.is_some() {
        fail!(EACCES, "BIRTH_STARTUP_RELEASE_ACTUAL_CLEAR_REQUIRED");
    }
    let visibility = &mut clear.visible.owner;
    if visibility.pending.is_some()
        || visibility.core_failure.is_some()
        || visibility.birth_failures.iter().any(Option::is_some)
        || visibility.software_failures.iter().any(Option::is_some)
        || visibility.birth.iter().any(Option::is_none)
        || visibility.software.iter().any(Option::is_none)
    {
        fail!(EACCES, "BIRTH_STARTUP_RELEASE_COMPLETE_VISIBILITY_REQUIRED");
    }
    let jobs = &mut visibility.jobs.owner;
    let metadata = &mut jobs.metadata.owner;
    let transport = &mut metadata.transport.owner;
    let original = &mut transport.pin.owner;
    let scope = original.scope()?;
    let exclusion = &mut original.payload.owner;
    if exclusion.lease.is_some() || exclusion.acquisition_failure.is_some() {
        fail!(EACCES, "BIRTH_STARTUP_RELEASE_ORIGINAL_HANDOFF_REQUIRED");
    }
    let candidate = &mut exclusion.candidate;
    if candidate.release_failure.is_some() {
        fail!(EACCES, "BIRTH_STARTUP_RELEASE_NO_PRIOR_SOFTWARE_REFUSAL");
    }
    let NativeDedicatedBirth {
        state,
        guard,
        directory_events,
        denial_removal,
        live_directories,
    } = &mut candidate.birth;
    let checked = checked(state)?.clone();
    let boundary =
        RegistrationBoundary {
            state,
            denial: denial_removal,
            events: directory_events,
            live: live_directories,
            scope,
            inputs: &original.inputs,
            payload: &original.payload.plan,
            candidate: candidate
                .plan
                .as_ref()
                .ok_or_else(|| err!(EACCES, "BIRTH_STARTUP_RELEASE_ORIGINAL_PLAN_REQUIRED"))?,
            accounts: candidate
                .accounts
                .as_ref()
                .ok_or_else(|| err!(EACCES, "BIRTH_STARTUP_RELEASE_ACTUAL_ACCOUNTS_REQUIRED"))?,
            approval: candidate
                .approval
                .as_mut()
                .ok_or_else(|| err!(EACCES, "BIRTH_STARTUP_RELEASE_ACTUAL_SOFTWARE_REQUIRED"))?,
            metadata: [
                metadata.payload.as_ref().ok_or_else(|| {
                    err!(EACCES, "BIRTH_STARTUP_RELEASE_PAYLOAD_METADATA_REQUIRED")
                })?,
                metadata.runtime.as_ref().ok_or_else(|| {
                    err!(EACCES, "BIRTH_STARTUP_RELEASE_RUNTIME_METADATA_REQUIRED")
                })?,
            ],
            sources: &transport.sources,
            transport: transport
                .plan
                .as_ref()
                .ok_or_else(|| err!(EACCES, "BIRTH_STARTUP_RELEASE_RUNTIME_REQUIRED"))?,
            jobs: jobs
                .plan
                .as_ref()
                .ok_or_else(|| err!(EACCES, "BIRTH_STARTUP_RELEASE_JOBS_REQUIRED"))?,
            external: jobs
                .external
                .as_ref()
                .ok_or_else(|| err!(EACCES, "BIRTH_STARTUP_RELEASE_EXTERNAL_JOBS_REQUIRED"))?,
            birth_receipts: &visibility.birth,
            software_events: &visibility.software,
        };
    Ok(RegistrationOriginals {
        boundary,
        guard,
        checked,
    })
}

struct RegistrationAttempt<'guard> {
    cleared: NativeClearedBirth<'guard>,
    outcome: Option<RetainedGuardCoreStartOutcome>,
    adapter_entered: bool,
}
impl RegistrationAttempt<'_> {
    fn poison(&mut self) {
        self.cleared.owner.poison();
    }
    fn registration_may_have_changed(&self) -> bool {
        // Missing/unknown receipt after an entered adapter is conservative;
        // actual reported completed-prefix/uncertain command evidence wins.
        self.adapter_entered
            && self.outcome.as_ref().is_none_or(|outcome| {
                outcome
                    .lifecycle
                    .receipt
                    .get("uncertain_command_effects")
                    .and_then(serde_json::Value::as_bool)
                    != Some(false)
                    || outcome
                        .lifecycle
                        .receipt
                        .get("completed_labels")
                        .and_then(serde_json::Value::as_array)
                        .is_none_or(|labels| !labels.is_empty())
            })
    }
    fn observations(&mut self) -> Vec<EnclaveError> {
        let mut observed = Vec::new();
        match original_registration_fields(&mut self.cleared) {
            Ok(mut originals) => observed.extend(originals.boundary.observations(originals.guard)),
            Err(error) => observed.push(error),
        }
        match &self.outcome {
            Some(outcome) => {
                observed.extend(outcome.currentness_errors.iter().cloned());
                observed.extend(outcome.lifecycle.error.iter().cloned());
                observed.extend(outcome.lifecycle.maintenance_error.iter().cloned());
                if !outcome.lifecycle.successful {
                    observed.push(err!(EACCES, "BIRTH_REGISTRATION_NATIVE_REFUSED"));
                }
            }
            None => observed.push(err!(EACCES, "BIRTH_REGISTRATION_NATIVE_OUTCOME_REQUIRED")),
        }
        observed
    }
    fn register(&mut self, observed: &mut Vec<EnclaveError>) -> EnclaveResult<()> {
        if self.adapter_entered || self.outcome.is_some() {
            fail!(EALREADY, "BIRTH_REGISTRATION_NO_RETRY");
        }
        self.cleared.owner.gate(observed)?;
        // Admit original audit5 scope from actual completed Clear, before
        // any native bootstrap output. Both actual metadata owners and real
        // SOFTWARE independently deny retained identities across all17 roles.
        let expiry = self.cleared.owner.crypto_expiry()?;
        {
            let metadata = &mut self.cleared.owner.visible.owner.jobs.owner.metadata.owner;
            let candidate = &mut metadata.transport.owner.pin.owner.payload.owner.candidate;
            let accounts = candidate
                .accounts
                .as_ref()
                .ok_or_else(|| err!(EACCES, "BIRTH_REGISTRATION_ACTUAL_ACCOUNTS_REQUIRED"))?;
            let approval = candidate
                .approval
                .as_mut()
                .ok_or_else(|| err!(EACCES, "BIRTH_REGISTRATION_ACTUAL_SOFTWARE_REQUIRED"))?;
            let payload = metadata
                .payload
                .as_ref()
                .ok_or_else(|| err!(EACCES, "BIRTH_REGISTRATION_PAYLOAD_METADATA_REQUIRED"))?;
            let runtime = metadata
                .runtime
                .as_ref()
                .ok_or_else(|| err!(EACCES, "BIRTH_REGISTRATION_RUNTIME_METADATA_REQUIRED"))?;
            candidate.birth.begin_registration_live_directories(
                accounts, approval, payload, runtime, &expiry,
            )?;
        }
        let RegistrationOriginals {
            mut boundary,
            guard,
            checked,
        } = original_registration_fields(&mut self.cleared)?;
        let env = Env::production_for_target(&checked)?;
        // Only this concrete fixed adapter can issue commands. Its callback
        // receives a temporary borrow of the SAME original guard; all other
        // fields stay disjoint and remain in this original owning aggregate.
        self.adapter_entered = true;
        let result =
            selected_core_start_with_retained_guard(&env, &checked, guard, &mut |same_guard| {
                boundary.gate(same_guard, observed)
            });
        match result {
            Ok(outcome) => self.outcome = Some(outcome),
            Err(error) => return Err(error),
        }
        let checks = self.observations();
        let current = first(&checks);
        observed.extend(checks);
        current
    }
}

/// Five actual core registration commands accepted with SAME Dedicated EX
/// still held. Runtime/full-installation readiness and auxiliary jobs excluded.
#[must_use = "retain original cleared birth, registration outcome and SAME Dedicated EX"]
pub(crate) struct NativeRegisteredBirth<'guard> {
    owner: RegistrationAttempt<'guard>,
}
impl std::fmt::Debug for NativeRegisteredBirth<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeRegisteredBirth")
            .field("observations", &"<redacted>")
            .finish_non_exhaustive()
    }
}
#[must_use = "retain every original owner and actual partial registration outcome"]
pub(crate) struct NativeRegistrationFailure<'guard> {
    pub(crate) error: EnclaveError,
    pub(crate) boundary_errors: Vec<EnclaveError>,
    pub(crate) final_errors: Vec<EnclaveError>,
    pub(crate) progress: BirthProgress,
    owner: RegistrationAttempt<'guard>,
}
impl NativeRegistrationFailure<'_> {
    pub(crate) fn registration_may_have_changed(&self) -> bool {
        self.owner.registration_may_have_changed()
    }
}
impl std::fmt::Debug for NativeRegistrationFailure<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeRegistrationFailure")
            .field("reason", &self.error.reason)
            .field("boundary_error_count", &self.boundary_errors.len())
            .field("final_error_count", &self.final_errors.len())
            .field(
                "registration_may_have_changed",
                &self.registration_may_have_changed(),
            )
            .field("observations", &"<redacted>")
            .finish_non_exhaustive()
    }
}
impl<'guard> NativeClearedBirth<'guard> {
    pub(crate) fn register_core_jobs(
        self,
    ) -> Result<NativeRegisteredBirth<'guard>, NativeRegistrationFailure<'guard>> {
        let mut owner = RegistrationAttempt {
            cleared: self,
            outcome: None,
            adapter_entered: false,
        };
        owner
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
            .operation = "register_core_jobs";
        let mut boundary_errors = Vec::new();
        let operation = owner.register(&mut boundary_errors);
        let expiry = owner.cleared.owner.crypto_expiry();
        let mut final_errors = owner.observations();
        final_errors.extend(owner.observations());
        match expiry {
            Ok(expiry) => final_errors.extend(errors([expiry.current()])),
            Err(error) => final_errors.push(error),
        }
        match resolve_owned(owner, operation, boundary_errors, final_errors) {
            Ok(mut owner) => {
                let progress = &mut owner
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
                Ok(NativeRegisteredBirth { owner })
            }
            Err(mut refusal) => {
                refusal.owner.poison();
                Err(NativeRegistrationFailure {
                    error: refusal.error,
                    boundary_errors: refusal.boundary_errors,
                    final_errors: refusal.final_errors,
                    progress: refusal
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
#[path = "target_birth_registration_tests.rs"]
mod tests;
