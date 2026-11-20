//! Restrictive selected non-broker auxiliary registration teardown.
//!
//! This module never starts jobs, removes payload/state, invokes a broker, or
//! proves inactivity. The caller retains one genuine host maintenance guard.
//! The original core-five stop operation remains separate. An explicit future
//! `daemon stop-auxiliary` route can use this module; it is not a complete stop.

use crate::deploy::{self, CommandFailure, HostMaintenanceGuard,
    JobObservation, MaintenanceExclusion, NativeLaunchctlRunner};
use enclave_core::{deployment::{DeploymentTarget, teardown::TeardownDeploymentTarget},
    error::{EnclaveError, EnclaveResult}, err, fail};
use serde::Serialize;
use std::{collections::BTreeSet, process::Command, time::{Duration, Instant}};

const OPERATION_LIMIT: Duration = Duration::from_secs(30);
const COMMAND_LIMIT: Duration = Duration::from_secs(5);
const AGENTS: [&str; 2] = ["intent", "oidc-broker"];
const SCOPE: &str = "SELECTED_NONBROKER_AUXILIARY_REGISTRATIONS";

/// Closed bootout target. No PID, arbitrary command, or plist is accepted.
struct AuxiliaryJob { domain: String, label: String }
impl AuxiliaryJob {
    fn target(&self) -> String { format!("{}/{}", self.domain, self.label) }
    fn command(&self) -> Command {
        let mut command = crate::syscmd::command(crate::syscmd::Tool::Launchctl);
        command.args(["bootout", &self.target()]).current_dir("/");
        command
    }
}

/// A registration outcome, never a certificate of process or broker inactivity.
#[derive(Debug, Serialize)]
pub(crate) struct AuxiliaryStopReceipt {
    pub(crate) target_id: String,
    pub(crate) descriptor_sha256: String,
    pub(crate) scope: &'static str,
    pub(crate) gui_candidate_uids: Vec<u32>,
    /// These commands returned success, even if a later observation failed.
    pub(crate) bootout_succeeded: Vec<String>,
    /// Loaded jobs whose bootout and subsequent absence/binding checks passed.
    pub(crate) completed_jobs: Vec<String>,
    pub(crate) already_absent_jobs: Vec<String>,
    pub(crate) boundary_job: Option<String>,
    pub(crate) uncertain_command_effects: bool,
    pub(crate) complete: bool,
    pub(crate) core_jobs: &'static str,
    pub(crate) broker_quiescence: &'static str,
    pub(crate) inactivity_proven: bool,
    pub(crate) installation_supported: bool,
    pub(crate) qualified: bool,
}

#[derive(Debug)]
pub(crate) struct AuxiliaryStopFailure {
    pub(crate) receipt: AuxiliaryStopReceipt,
    pub(crate) error: EnclaveError,
    /// A final descriptor/exclusion failure never erases the original error.
    pub(crate) final_binding_error: Option<EnclaveError>,
}
type StopResult = Result<AuxiliaryStopReceipt, AuxiliaryStopFailure>;

trait Observer {
    fn gui_candidates(&mut self, until: Instant) -> EnclaveResult<BTreeSet<u32>>;
    fn job(&mut self, job: &AuxiliaryJob, until: Instant) -> EnclaveResult<JobObservation>;
}
struct NativeObserver { runner: NativeLaunchctlRunner }
impl Observer for NativeObserver {
    fn gui_candidates(&mut self, until: Instant) -> EnclaveResult<BTreeSet<u32>> {
        deploy::observe_live_gui_candidates(&mut self.runner, until)
    }
    fn job(&mut self, job: &AuxiliaryJob, until: Instant) -> EnclaveResult<JobObservation> {
        deploy::observe_fixed_job(&mut self.runner, &job.domain, &job.label, until)
    }
}
trait StopRunner {
    fn bootout(&mut self, job: &AuxiliaryJob, until: Instant) -> EnclaveResult<()>;
}
struct NativeStopRunner;
impl StopRunner for NativeStopRunner {
    fn bootout(&mut self, job: &AuxiliaryJob, until: Instant) -> EnclaveResult<()> {
        match deploy::run_owned_command(job.command(), until) {
            Ok(output) if output.code == Some(0) => Ok(()),
            Ok(_) => Err(err!(EIO, "AUXILIARY_BOOTOUT_FAILED")),
            Err(CommandFailure::Timeout) => Err(err!(ETIMEDOUT, "AUXILIARY_BOOTOUT_TIMEOUT")),
            Err(CommandFailure::OutputLimit) => Err(err!(E2BIG, "AUXILIARY_BOOTOUT_OUTPUT_LIMIT")),
            Err(CommandFailure::OwnershipUnknown) => Err(err!(EIO, "AUXILIARY_BOOTOUT_CLEANUP_UNCERTAIN")),
            Err(CommandFailure::Unavailable | CommandFailure::Io) => Err(err!(EIO, "AUXILIARY_BOOTOUT_UNAVAILABLE")),
        }
    }
}

fn deadline(until: Instant) -> EnclaveResult<()> {
    if Instant::now() >= until { fail!(ETIMEDOUT, "AUXILIARY_STOP_TIMEOUT"); }
    Ok(())
}
fn receipt(target: &DeploymentTarget, descriptor: &str) -> AuxiliaryStopReceipt {
    AuxiliaryStopReceipt {
        target_id: target.target_id.clone(), descriptor_sha256: descriptor.into(), scope: SCOPE,
        gui_candidate_uids: vec![], bootout_succeeded: vec![], completed_jobs: vec![],
        already_absent_jobs: vec![], boundary_job: None, uncertain_command_effects: false,
        complete: false, core_jobs: "NOT_OPERATED_BY_THIS_SCOPE",
        broker_quiescence: "UNKNOWN_NOT_PERFORMED", inactivity_proven: false,
        installation_supported: false, qualified: false,
    }
}
fn jobs(target: &DeploymentTarget, uids: &BTreeSet<u32>) -> Vec<AuxiliaryJob> {
    let namespace = &target.layout.launchd_namespace;
    let system = |suffix: &str| AuxiliaryJob { domain: "system".into(), label: format!("{namespace}.{suffix}") };
    // Stop the worker before the remaining auxiliaries. Keep the revocation
    // supervisor until last. Broker and core registration teardown are separate.
    let mut result = vec![system("hydrate")];
    for uid in uids { for suffix in AGENTS {
        result.push(AuxiliaryJob { domain: format!("gui/{uid}"), label: format!("{namespace}.{suffix}") });
    }}
    result.extend([system("gateway"), system("browser"), system("supervisor")]);
    result
}
fn observed<T>(until: Instant, revalidate: &mut impl FnMut() -> EnclaveResult<()>,
    observe: impl FnOnce() -> EnclaveResult<T>) -> EnclaveResult<T> {
    deadline(until)?; revalidate()?; deadline(until)?;
    let result = observe();
    // Always recheck the held descriptor/exclusion after an observation error.
    let binding = revalidate();
    deadline(until)?; binding?; result
}
fn stable_domains(observer: &mut dyn Observer, expected: &BTreeSet<u32>, until: Instant,
    revalidate: &mut impl FnMut() -> EnclaveResult<()>) -> EnclaveResult<()> {
    let current = observed(until, revalidate, || observer.gui_candidates(until))?;
    if &current != expected { fail!(ESTALE, "AUXILIARY_GUI_DOMAINS_CHANGED"); }
    Ok(())
}
fn absent(status: &JobObservation, job: &AuxiliaryJob) -> bool {
    *status == JobObservation::ObservedServiceAbsent
        || (*status == JobObservation::ObservedGuiDomainAbsent && job.domain.starts_with("gui/"))
}

fn operate(target: &DeploymentTarget, descriptor: &str, observer: &mut dyn Observer,
    runner: &mut dyn StopRunner, revalidate: &mut impl FnMut() -> EnclaveResult<()>, until: Instant) -> StopResult {
    let mut result = receipt(target, descriptor);
    let operation = (|| {
        target.validate()?;
        if descriptor.len() != 64 || !descriptor.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
            fail!(EINVAL, "AUXILIARY_CHECKED_DESCRIPTOR_REQUIRED");
        }
        let uids = observed(until, revalidate, || observer.gui_candidates(until))?;
        // Enforce the native observer's bounds in the injected model as well.
        if uids.len() > 64 || uids.iter().any(|uid| *uid < 500 || *uid == u32::MAX) {
            fail!(EACCES, "AUXILIARY_GUI_INVENTORY_INVALID");
        }
        result.gui_candidate_uids = uids.iter().copied().collect();
        for job in jobs(target, &uids) {
            result.boundary_job = Some(job.target());
            stable_domains(observer, &uids, until, revalidate)?;
            let status = observed(until, revalidate, || observer.job(&job, until))?;
            if absent(&status, &job) {
                stable_domains(observer, &uids, until, revalidate)?;
                result.already_absent_jobs.push(job.target());
                continue;
            }
            if status != JobObservation::ObservedLoaded { fail!(EACCES, "AUXILIARY_JOB_OBSERVATION_UNKNOWN"); }
            deadline(until)?; revalidate()?; deadline(until)?;
            let command_until = until.min(Instant::now() + COMMAND_LIMIT);
            result.uncertain_command_effects = true;
            let command_result = runner.bootout(&job, command_until);
            if command_result.is_ok() { result.bootout_succeeded.push(job.target()); }
            let binding = revalidate();
            // Never spawn another observer after command/owned-child uncertainty.
            binding?; deadline(command_until)?; command_result?;
            let status = observed(until, revalidate, || observer.job(&job, until))?;
            if !absent(&status, &job) {
                if status == JobObservation::ObservedLoaded { fail!(EAGAIN, "AUXILIARY_JOB_STILL_LOADED"); }
                fail!(EACCES, "AUXILIARY_JOB_OBSERVATION_UNKNOWN");
            }
            stable_domains(observer, &uids, until, revalidate)?;
            result.completed_jobs.push(job.target());
            result.uncertain_command_effects = false;
        }
        stable_domains(observer, &uids, until, revalidate)?;
        result.boundary_job = None;
        result.complete = true;
        Ok(())
    })();
    let final_binding = revalidate().and_then(|()| deadline(until));
    if operation.is_err() || final_binding.is_err() { result.complete = false; }
    match (operation, final_binding) {
        (Ok(()), Ok(())) => Ok(result),
        (Err(error), final_binding) => Err(AuxiliaryStopFailure { receipt: result, error,
            final_binding_error: final_binding.err() }),
        (Ok(()), Err(error)) => Err(AuxiliaryStopFailure { receipt: result, error,
            final_binding_error: None }),
    }
}

/// Stop only non-broker auxiliary registrations for an explicit teardown cap.
/// Root must expose this through a separately named route, retain the original
/// core-five behavior, and never use its receipt as installer quiescence.
pub(crate) fn stop_auxiliary(target: &TeardownDeploymentTarget, guard: &mut HostMaintenanceGuard) -> StopResult {
    // This native capability recheck cannot be supplied by a JSON/test adapter.
    let mut revalidate = || {
        let descriptor = target.recheck();
        let exclusion = guard.assert_held();
        descriptor?; exclusion
    };
    operate(target.target(), target.descriptor_sha256(),
        &mut NativeObserver { runner: NativeLaunchctlRunner }, &mut NativeStopRunner,
        &mut revalidate, Instant::now() + OPERATION_LIMIT)
}

#[cfg(test)]
#[path = "ctl_target_aux_stop_tests.rs"]
mod tests;
