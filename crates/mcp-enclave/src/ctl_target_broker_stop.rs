//! Restrictive selected live-broker quiescence followed by registration stop.
//!
//! A genuine authenticated live reply must precede every observation/bootout.
//! Neither an absent registration nor an installed executable replaces it.
//! Private publication state stays in the broker. The caller owns the real
//! host guard throughout; whole-host inactivity and installation remain open.

use crate::deploy::{self, CommandFailure, HostMaintenanceGuard, JobObservation,
    MaintenanceExclusion, NativeLaunchctlRunner};
use enclave_core::{deployment::{self, CheckedDeploymentTarget, DeploymentTarget},
    error::{EnclaveError, EnclaveResult}, err, fail, Profile};
use serde::Serialize;
use std::{process::Command, time::{Duration, Instant}};

const OPERATION_LIMIT: Duration = Duration::from_secs(30);
const COMMAND_LIMIT: Duration = Duration::from_secs(5);
const SCOPE: &str = "SELECTED_AUTHENTICATED_LIVE_BROKER_BARRIER_AND_REGISTRATION_ONLY";

struct BrokerJob { label: String }
impl BrokerJob {
    fn for_target(target: &DeploymentTarget) -> Self {
        Self { label: format!("{}.apfs-broker", target.layout.launchd_namespace) }
    }
    fn target(&self) -> String { format!("system/{}", self.label) }
    fn command(&self) -> Command {
        let mut command = crate::syscmd::command(crate::syscmd::Tool::Launchctl);
        command.args(["bootout", &self.target()]).current_dir("/"); command
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct BrokerStopReceipt {
    pub(crate) target_id: String,
    pub(crate) descriptor_sha256: String,
    pub(crate) scope: &'static str,
    pub(crate) job: String,
    pub(crate) quiescence_attempted: bool,
    pub(crate) authenticated_quiescence_confirmed: bool,
    /// A failed/lost reply can leave a restrictive marker behind; never undo it.
    pub(crate) uncertain_quiescence_effects: bool,
    pub(crate) bootout_succeeded: bool,
    pub(crate) already_absent: bool,
    pub(crate) registration_absence_observed: bool,
    pub(crate) uncertain_command_effects: bool,
    pub(crate) complete: bool,
    pub(crate) inactivity_proven: bool,
    pub(crate) installation_supported: bool,
    pub(crate) qualified: bool,
}
#[derive(Debug)]
pub(crate) struct BrokerStopFailure {
    pub(crate) receipt: BrokerStopReceipt,
    pub(crate) error: EnclaveError,
    pub(crate) final_binding_error: Option<EnclaveError>,
}
type StopResult = Result<BrokerStopReceipt, BrokerStopFailure>;

// Private injection seams exercise ordering/fault handling only. The sole
// production constructor below binds the genuine checked target and guard.
trait Quiescence { fn request(&mut self, until: Instant) -> EnclaveResult<()>; }
struct NativeQuiescence<'a> { checked: &'a CheckedDeploymentTarget }
impl Quiescence for NativeQuiescence<'_> {
    fn request(&mut self, until: Instant) -> EnclaveResult<()> {
        enclave_swarm_syncd::snapshot_broker::request_selected_quiescence(self.checked, until)
    }
}
trait Observer { fn job(&mut self, job: &BrokerJob, until: Instant) -> EnclaveResult<JobObservation>; }
struct NativeObserver { runner: NativeLaunchctlRunner }
impl Observer for NativeObserver {
    fn job(&mut self, job: &BrokerJob, until: Instant) -> EnclaveResult<JobObservation> {
        deploy::observe_fixed_job(&mut self.runner, "system", &job.label, until)
    }
}
trait StopRunner { fn bootout(&mut self, job: &BrokerJob, until: Instant) -> EnclaveResult<()>; }
struct NativeStopRunner;
impl StopRunner for NativeStopRunner {
    fn bootout(&mut self, job: &BrokerJob, until: Instant) -> EnclaveResult<()> {
        match deploy::run_owned_command(job.command(), until) {
            Ok(output) if output.code == Some(0) => Ok(()),
            Ok(_) => Err(err!(EIO, "BROKER_STOP_BOOTOUT_FAILED")),
            Err(CommandFailure::Timeout) => Err(err!(ETIMEDOUT, "BROKER_STOP_BOOTOUT_TIMEOUT")),
            Err(CommandFailure::OutputLimit) => Err(err!(E2BIG, "BROKER_STOP_BOOTOUT_OUTPUT_LIMIT")),
            Err(CommandFailure::OwnershipUnknown) => Err(err!(EIO, "BROKER_STOP_BOOTOUT_CLEANUP_UNCERTAIN")),
            Err(CommandFailure::Unavailable | CommandFailure::Io) => Err(err!(EIO, "BROKER_STOP_BOOTOUT_UNAVAILABLE")),
        }
    }
}
fn deadline(until: Instant) -> EnclaveResult<()> {
    if Instant::now() >= until { fail!(ETIMEDOUT, "BROKER_STOP_TIMEOUT"); } Ok(())
}
fn operate(target: &DeploymentTarget, descriptor: &str, quiescence: &mut dyn Quiescence,
    observer: &mut dyn Observer, runner: &mut dyn StopRunner,
    revalidate: &mut impl FnMut() -> EnclaveResult<()>, until: Instant) -> StopResult {
    let job = BrokerJob::for_target(target);
    let mut result = BrokerStopReceipt { target_id: target.target_id.clone(), descriptor_sha256: descriptor.into(),
        scope: SCOPE, job: job.target(), quiescence_attempted: false, authenticated_quiescence_confirmed: false,
        uncertain_quiescence_effects: false, bootout_succeeded: false, already_absent: false,
        registration_absence_observed: false, uncertain_command_effects: false, complete: false,
        inactivity_proven: false, installation_supported: false, qualified: false };
    let operation = (|| {
        target.validate()?;
        if target.profile != Profile::L3 || target.broker.is_none() { fail!(EACCES, "BROKER_STOP_L3_REQUIRED"); }
        if descriptor.len() != 64 || !descriptor.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
            fail!(EINVAL, "BROKER_STOP_CHECKED_DESCRIPTOR_REQUIRED");
        }
        deadline(until)?; revalidate()?; deadline(until)?;
        result.quiescence_attempted = true; result.uncertain_quiescence_effects = true;
        let admitted = quiescence.request(until.min(Instant::now() + COMMAND_LIMIT));
        let binding = revalidate(); let time = deadline(until);
        admitted?; binding?; time?;
        result.authenticated_quiescence_confirmed = true; result.uncertain_quiescence_effects = false;
        // Registration absence is considered only AFTER the real live barrier.
        let observation = observer.job(&job, until);
        let binding = revalidate(); let time = deadline(until);
        let observation = observation?; binding?; time?;
        match observation {
            JobObservation::ObservedServiceAbsent => {
                result.already_absent = true; result.registration_absence_observed = true;
            },
            JobObservation::ObservedLoaded => {
                deadline(until)?; revalidate()?; deadline(until)?;
                let command_until = until.min(Instant::now() + COMMAND_LIMIT);
                result.uncertain_command_effects = true;
                let command = runner.bootout(&job, command_until);
                if command.is_ok() { result.bootout_succeeded = true; }
                let binding = revalidate(); let time = deadline(command_until);
                command?; binding?; time?;
                let observation = observer.job(&job, until);
                let binding = revalidate(); let time = deadline(until);
                let observation = observation?; binding?; time?;
                if observation != JobObservation::ObservedServiceAbsent { fail!(EACCES, "BROKER_STOP_ABSENCE_UNKNOWN"); }
                result.registration_absence_observed = true; result.uncertain_command_effects = false;
            },
            _ => fail!(EACCES, "BROKER_STOP_OBSERVATION_UNKNOWN"),
        }
        result.complete = true; Ok(())
    })();
    let final_binding = revalidate().and_then(|()| deadline(until));
    if operation.is_err() || final_binding.is_err() { result.complete = false; }
    match (operation, final_binding) {
        (Ok(()), Ok(())) => Ok(result),
        (Err(error), final_binding) => Err(BrokerStopFailure { receipt: result, error,
            final_binding_error: final_binding.err() }),
        (Ok(()), Err(error)) => Err(BrokerStopFailure { receipt: result, error, final_binding_error: None }),
    }
}

/// Actual selected native root operation, with no parsed/serialized authority
/// constructor and no production runner/verifier provider. Both dedicated and
/// existing-upgrade roles require the same live reciprocal pinned protocol.
pub(crate) fn stop_selected_broker(checked: &CheckedDeploymentTarget, guard: &mut HostMaintenanceGuard) -> StopResult {
    let mut revalidate = || {
        let context = (|| {
            if !cfg!(target_os = "macos") || unsafe { libc::geteuid() } != 0 { fail!(EACCES, "BROKER_STOP_NATIVE_ROOT_REQUIRED"); }
            let selected = deployment::selected().ok_or_else(|| err!(EACCES, "DEPLOYMENT_CONTEXT_REQUIRED"))?;
            let fresh = deployment::load(checked.config_path())?;
            if selected.config_path() != checked.config_path() || selected.target() != checked.target()
                || selected.descriptor_sha256() != checked.descriptor_sha256()
                || fresh.target() != checked.target() || fresh.descriptor_sha256() != checked.descriptor_sha256() {
                fail!(ESTALE, "BROKER_STOP_CONTEXT_CHANGED");
            } Ok(())
        })();
        let exclusion = guard.assert_held(); context?; exclusion
    };
    operate(checked.target(), checked.descriptor_sha256(), &mut NativeQuiescence { checked },
        &mut NativeObserver { runner: NativeLaunchctlRunner }, &mut NativeStopRunner,
        &mut revalidate, Instant::now() + OPERATION_LIMIT)
}

#[cfg(test)]
#[path = "ctl_target_broker_stop_tests.rs"]
mod tests;
