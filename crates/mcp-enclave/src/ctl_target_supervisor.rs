//! One selected administrative registration, never service/Begin readiness.
//!
//! The existing installed plist enters a repairing runtime and legacy global
//! PF-restoring watcher. A private mandatory refusal prevents this new route
//! from bootstrapping it. A real verify-only selected runtime contract must be
//! implemented and reviewed before this gate can admit any production command.
use super::{Env, HeldFile, HeldPaths};
use crate::deploy::{self, HostMaintenanceGuard, MaintenanceExclusion, NativeCodeShape,
    NativeEntitlementPolicy, ProtectedNativeFile};
use enclave_core::{codesign::{self, CodeRequirement}, deployment::{self, CheckedDeploymentTarget,
    DeploymentRole, DeploymentSigningMode, DeploymentTarget, normalized_path},
    error::{EnclaveError, EnclaveResult}, err, fail,
    native_command::{self, CommandFailure, CommandOutput}, Profile};
use serde::Serialize;
use std::{collections::BTreeMap, path::{Path, PathBuf}, process::Command, time::{Duration, Instant}};

const MAX_PUBLIC: u64 = 1024 * 1024;
const MAX_CODE: u64 = 512 * 1024 * 1024;
const COMMAND_LIMIT: Duration = Duration::from_secs(5);
const OPERATION_LIMIT: Duration = Duration::from_secs(30);
const RUNTIME_UNAVAILABLE: &str = "DEPLOYMENT_SUPERVISOR_SELECTED_RUNTIME_UNAVAILABLE";

/// Public progress only. No deserializer or startup/readiness capability exists.
#[derive(Debug, Serialize)]
pub struct TargetSupervisorStartReport {
    /// Only the one registration and all terminal checks succeeded.
    pub successful: bool,
    /// Actual progress survives later refusals and uncertain command effects.
    pub receipt: SupervisorStartReceipt,
    /// Original refusal, without native child stdout/stderr.
    pub error: Option<EnclaveError>,
    /// Every independent terminal context/original/guard/deadline refusal.
    pub final_errors: Vec<EnclaveError>,
    /// All observed failures, including distinct intermediate boundaries.
    pub retained_errors: Vec<EnclaveError>,
}
/// Descriptive data, never accepted by any privileged producer or Begin gate.
#[derive(Debug, Serialize)]
pub struct SupervisorStartReceipt {
    /// Actual selected target identifier.
    pub target_id: String,
    /// Exact checked selected descriptor bytes.
    pub descriptor_sha256: String,
    /// Only the selected system supervisor registration is in scope.
    pub scope: &'static str,
    /// Internally derived target label.
    pub label: String,
    /// Fixed LaunchDaemons parent plus the internally derived target label.
    pub plist: PathBuf,
    /// Native original-owner/code preflight completed.
    pub preflight_complete: bool,
    /// The native command was entered; effects may be uncertain.
    pub bootstrap_attempted: bool,
    /// The executor returned exit0 before terminal rechecks.
    pub bootstrap_succeeded: bool,
    /// The registration command and all terminal checks succeeded.
    pub registration_complete: bool,
    /// An attempted command is not called rolled back on any later refusal.
    pub uncertain_command_effects: bool,
    /// The actual verify-only runtime contract has not been implemented yet.
    pub selected_runtime: &'static str,
    /// All mandatory effective PF/watcher/restoration terms remain unproven.
    pub pf_prerequisites: &'static str,
    /// Registration alone cannot establish resource or service readiness.
    pub readiness: &'static str,
    /// Always false in this administrative increment.
    pub first_begin_prerequisites_met: bool,
    /// Always false; no full profile or physical qualification is inferred.
    pub qualified: bool,
}

/// No caller/report/environment/CLI boolean can enable this contract. Replacing
/// this refusal requires the actual selected runtime's reviewed native owner
/// integration, with no legacy repair/global-PF entry and with mandatory PF
/// readiness kept fail closed. Registration alone never establishes those PF
/// prerequisites. No enrollment exception or runtime capability exists here.
fn require_selected_runtime() -> EnclaveResult<()> { fail!(ENOSYS, RUNTIME_UNAVAILABLE); }
fn deadline(until: Instant) -> EnclaveResult<()> {
    if Instant::now() >= until { fail!(ETIMEDOUT, "DEPLOYMENT_SUPERVISOR_TIMEOUT"); }
    Ok(())
}
fn scope(target: &DeploymentTarget) -> EnclaveResult<()> {
    if target.role != DeploymentRole::DedicatedTest || target.profile != Profile::L2
        || target.signing_identity_mode != DeploymentSigningMode::LocalPins
        || codesign::signing_mode() != codesign::SigningMode::LocalPins
        || target.broker.is_some() || !target.shared_read_only_inputs.is_empty() {
        fail!(EACCES, "DEPLOYMENT_SUPERVISOR_SCOPE_UNSUPPORTED");
    }
    Ok(())
}
fn bind(env: &Env, target: &DeploymentTarget) -> EnclaveResult<()> {
    if env.dev || env.profile != target.profile || env.socket_dir != target.layout.socket_root
        || env.audit_dir != target.layout.audit_root || env.state_dir != target.layout.state_root {
        fail!(EACCES, "DEPLOYMENT_SUPERVISOR_CONTEXT_MISMATCH");
    }
    scope(target)
}
fn native_selection(env: &Env, checked: &CheckedDeploymentTarget) -> EnclaveResult<()> {
    if !cfg!(target_os = "macos") { fail!(ENOSYS, "DEPLOYMENT_SUPERVISOR_NATIVE_REQUIRED"); }
    if unsafe { libc::geteuid() } != 0 { fail!(EPERM, "DEPLOYMENT_SUPERVISOR_ROOT_REQUIRED"); }
    let actual = deployment::selected().ok_or_else(|| err!(EACCES, "DEPLOYMENT_CONTEXT_REQUIRED"))?;
    if !std::ptr::eq(actual, checked) { fail!(ESTALE, "DEPLOYMENT_SUPERVISOR_CONTEXT_MISMATCH"); }
    bind(env, actual.target())
}

// Fields/constructors stay private; production derives the only label/path
// from its actual checked selection. No arbitrary argv or action can enter.
struct SupervisorCommand { label: String, plist: PathBuf }
impl SupervisorCommand {
    fn for_target(target: &DeploymentTarget) -> Self {
        let label = format!("{}.supervisor", target.layout.launchd_namespace);
        Self { plist: Path::new("/Library/LaunchDaemons").join(format!("{label}.plist")), label }
    }
    fn command(&self) -> Command {
        let mut command = crate::syscmd::command(crate::syscmd::Tool::Launchctl);
        command.current_dir("/").args(["bootstrap", "system"]).arg(&self.plist);
        command
    }
}
fn new_receipt(target: &DeploymentTarget, descriptor: &str) -> SupervisorStartReceipt {
    let command = SupervisorCommand::for_target(target);
    SupervisorStartReceipt { target_id: target.target_id.clone(), descriptor_sha256: descriptor.into(),
        scope: "ONE_SELECTED_SYSTEM_SUPERVISOR_REGISTRATION_ONLY", label: command.label, plist: command.plist,
        preflight_complete: false, bootstrap_attempted: false, bootstrap_succeeded: false,
        registration_complete: false, uncertain_command_effects: false,
        selected_runtime: "UNAVAILABLE_VERIFY_ONLY_SELECTED_RUNTIME", pf_prerequisites: "UNKNOWN_REQUIRED_ENFORCEMENT_WATCHER_AND_RESTORATION",
        readiness: "UNKNOWN_RESOURCE_SERVICE_AND_FULL_PROFILE_READINESS", first_begin_prerequisites_met: false, qualified: false }
}
fn command_result(result: Result<CommandOutput, CommandFailure>) -> EnclaveResult<()> {
    match result {
        Ok(output) if output.stdout.len().checked_add(output.stderr.len()).is_none_or(|size| size > native_command::MAX_OUTPUT) =>
            Err(err!(E2BIG, "DEPLOYMENT_SUPERVISOR_BOOTSTRAP_OUTPUT_LIMIT")),
        Ok(output) if output.code == Some(0) => Ok(()),
        Ok(_) => Err(err!(EIO, "DEPLOYMENT_SUPERVISOR_BOOTSTRAP_FAILED")),
        Err(CommandFailure::Timeout) => Err(err!(ETIMEDOUT, "DEPLOYMENT_SUPERVISOR_BOOTSTRAP_TIMEOUT")),
        Err(CommandFailure::OutputLimit) => Err(err!(E2BIG, "DEPLOYMENT_SUPERVISOR_BOOTSTRAP_OUTPUT_LIMIT")),
        Err(CommandFailure::OwnershipUnknown) => Err(err!(EIO, "DEPLOYMENT_SUPERVISOR_BOOTSTRAP_CLEANUP_UNCERTAIN")),
        Err(CommandFailure::Unavailable | CommandFailure::Io) => Err(err!(EIO, "DEPLOYMENT_SUPERVISOR_BOOTSTRAP_UNAVAILABLE")),
    }
}
fn retain(errors: &mut Vec<EnclaveError>, results: &[&EnclaveResult<()>]) {
    errors.extend(results.iter().filter_map(|result| result.as_ref().err().cloned()));
}
fn first_error(errors: Vec<EnclaveError>, retained: &mut Vec<EnclaveError>) -> EnclaveResult<()> {
    let first = errors.first().cloned(); retained.extend(errors);
    first.map_or(Ok(()), Err)
}
fn finish(mut receipt: SupervisorStartReceipt, operation: EnclaveResult<()>,
    final_errors: Vec<EnclaveError>, mut retained_errors: Vec<EnclaveError>) -> TargetSupervisorStartReport {
    let successful = operation.is_ok() && final_errors.is_empty() && receipt.preflight_complete
        && receipt.bootstrap_attempted && receipt.bootstrap_succeeded;
    receipt.registration_complete = successful;
    receipt.uncertain_command_effects = receipt.bootstrap_attempted && !successful;
    receipt.first_begin_prerequisites_met = false; receipt.qualified = false;
    if let Err(error) = &operation { retained_errors.push(error.clone()); }
    retained_errors.extend(final_errors.iter().cloned());
    TargetSupervisorStartReport { successful, receipt, error: operation.err(), final_errors, retained_errors }
}

fn selected_requirement(bytes: &[u8]) -> EnclaveResult<CodeRequirement> {
    let pins = codesign::pins::parse(bytes)?;
    let hashes = pins.get(codesign::CTL_IDENTIFIER).filter(|hashes| !hashes.is_empty())
        .ok_or_else(|| err!(EACCES, "CODESIGN_PINS_MISSING"))?.clone();
    Ok(CodeRequirement { identifier: codesign::CTL_IDENTIFIER.into(), team_id: codesign::TEAM_ID.into(), cdhash_allowlist: hashes })
}
fn copy_contract(copy: &deploy::target_plan::CopyEntry, mode: u32) -> EnclaveResult<()> {
    let actual = u32::from_str_radix(&copy.mode, 8).map_err(|_| err!(EINVAL, "DEPLOYMENT_SUPERVISOR_INVENTORY_MODE"))?;
    if copy.uid != 0 || copy.gid != 0 || actual != mode {
        fail!(EACCES, "DEPLOYMENT_SUPERVISOR_INVENTORY_MODE");
    }
    Ok(())
}
fn installed_copy(paths: &mut HeldPaths, files: &mut BTreeMap<PathBuf, HeldFile>,
    plan: &deploy::target_plan::TargetInstallPlan, destination: &Path, mode: u32, maximum: u64) -> EnclaveResult<Vec<u8>> {
    let path = normalized_path(destination)?;
    let copy = plan.copies.iter().find(|copy| normalized_path(&copy.destination).ok().as_ref() == Some(&path))
        .ok_or_else(|| err!(EACCES, "DEPLOYMENT_SUPERVISOR_INVENTORY_MISSING"))?;
    copy_contract(copy, mode)?;
    let (file, bytes) = HeldFile::open(paths, &path, maximum, Some(mode))?;
    let matches = file.sha256() == copy.sha256 && file.size() == copy.size;
    files.insert(path, file); // Keep the actual opened owner before later refusal.
    if !matches { fail!(ESTALE, "DEPLOYMENT_SUPERVISOR_INSTALLED_HASH"); }
    Ok(bytes)
}
fn exact_plist(actual: &[u8], expected: &[u8]) -> EnclaveResult<()> {
    if actual != expected { fail!(EACCES, "DEPLOYMENT_SUPERVISOR_RENDERER_MISMATCH"); }
    Ok(())
}

// Successful original owners are installed immediately and survive all later
// refused preflight/command/final checks. Existing HeldFile/HeldPaths internals
// may close a temporary descriptor before returning an error; this code does
// not claim ownership of a value those existing readers never returned.
struct PreparedSupervisor {
    paths: HeldPaths, descriptor: Option<HeldFile>, inventory: Option<HeldFile>, pins: Option<HeldFile>,
    files: BTreeMap<PathBuf, HeldFile>, executable: PathBuf,
    requirement: Option<CodeRequirement>, layout: Option<crate::launchd::Layout>,
}
impl PreparedSupervisor {
    fn new(checked: &CheckedDeploymentTarget) -> EnclaveResult<Self> {
        Ok(Self { paths: HeldPaths::new_native_acl_protected()?, descriptor: None, inventory: None, pins: None,
            files: BTreeMap::new(), executable: normalized_path(&checked.target().layout.binary_dir.join("mcp-enclave"))?,
            requirement: None, layout: None })
    }
    fn populate(&mut self, checked: &CheckedDeploymentTarget, command: &SupervisorCommand) -> EnclaveResult<()> {
        let target = checked.target();
        let (descriptor, _) = HeldFile::open(&mut self.paths, checked.config_path(), deployment::MAX_DESCRIPTOR_BYTES as u64, None)?;
        self.descriptor = Some(descriptor);
        if self.descriptor.as_ref().expect("held descriptor").sha256() != checked.descriptor_sha256() { fail!(ESTALE, "DEPLOYMENT_CHANGED"); }
        let (inventory, bytes) = HeldFile::open(&mut self.paths, &target.expected_artifacts_manifest, MAX_PUBLIC, None)?;
        self.inventory = Some(inventory);
        let plan = deploy::target_plan::describe(target, checked.descriptor_sha256(), &bytes)?;
        let (pins, bytes) = HeldFile::open(&mut self.paths, &target.codesign_pins_file, MAX_PUBLIC, None)?;
        self.pins = Some(pins);
        if self.pins.as_ref().expect("held pins").sha256() != plan.candidate_codesign_pins_sha256 {
            fail!(ESTALE, "DEPLOYMENT_SUPERVISOR_PIN_CUTOVER_REQUIRED");
        }
        self.requirement = Some(selected_requirement(&bytes)?);
        let (authority, _) = HeldFile::open(&mut self.paths, &target.authority_config, MAX_PUBLIC, None)?;
        self.files.insert(authority.path().to_owned(), authority);
        self.layout = Some(crate::launchd::Layout::for_target(checked.clone())?);
        let bytes = installed_copy(&mut self.paths, &mut self.files, &plan, &command.plist, 0o644, MAX_PUBLIC)?;
        exact_plist(&bytes, crate::launchd::supervisor_plist(self.layout.as_ref().expect("held layout")).as_bytes())?;
        installed_copy(&mut self.paths, &mut self.files, &plan, &self.executable, 0o755, MAX_CODE)?;
        self.paths.hold_directory(&target.layout.socket_root, Some((0, 0, 0o755)))?;
        self.paths.hold_directory(&target.layout.audit_root, Some((0, 0, 0o755)))?;
        self.paths.hold_directory(&target.layout.socket_root.join("supervisor"), Some((0, enclave_core::supervisor::CLIENT_GID, 0o2750)))?;
        Ok(())
    }
    fn originals(&self, checked: &CheckedDeploymentTarget) -> Vec<EnclaveError> {
        let mut errors = Vec::new();
        for file in [self.descriptor.as_ref(), self.inventory.as_ref(), self.pins.as_ref()].into_iter().flatten()
            .chain(self.files.values()) {
            if let Err(error) = file.revalidate(&self.paths) { errors.push(error); }
        }
        if self.descriptor.as_ref().is_some_and(|file| file.sha256() != checked.descriptor_sha256()) { errors.push(err!(ESTALE, "DEPLOYMENT_CHANGED")); }
        if let Some(layout) = &self.layout { if let Err(error) = layout.validate() { errors.push(error); } }
        if let Err(error) = self.paths.revalidate() { errors.push(error); }
        errors
    }
    fn observations(&self, env: &Env, checked: &CheckedDeploymentTarget,
        guard: &mut HostMaintenanceGuard, until: Instant) -> Vec<EnclaveError> {
        let mut errors = self.originals(checked);
        for result in [native_selection(env, checked), deployment::upgrade::assert_start_allowed(checked),
            guard.assert_held(), require_selected_runtime(), deadline(until)] {
            if let Err(error) = result { errors.push(error); }
        }
        errors
    }
    fn verify_code(&self, env: &Env, checked: &CheckedDeploymentTarget, guard: &mut HostMaintenanceGuard,
        until: Instant, retained: &mut Vec<EnclaveError>) -> EnclaveResult<()> {
        first_error(self.observations(env, checked, guard, until), retained)?;
        let code = self.files.get(&self.executable).ok_or_else(|| err!(EACCES, "DEPLOYMENT_SUPERVISOR_CODE_REQUIRED"))?;
        let view = ProtectedNativeFile { path: &self.executable, file: code.file(), sha256: code.sha256(), size: code.size() };
        let requirement = self.requirement.as_ref().ok_or_else(|| err!(EACCES, "DEPLOYMENT_SUPERVISOR_CODE_REQUIRED"))?;
        let native = deploy::verify_static_code(NativeCodeShape::Executable(view), requirement, NativeEntitlementPolicy::DaemonBaseline).map(|_| ());
        let after = self.observations(env, checked, guard, until);
        retain(retained, &[&native]);
        let current = first_error(after, retained);
        native?; current
    }
}

// Private orchestration accepts only the closed command. Production supplies
// concrete owner/guard observations and the shared executor; only cfg(test)
// code below supplies synthetic callbacks. No callback is exported to callers.
fn register_one(command: &SupervisorCommand, receipt: &mut SupervisorStartReceipt, until: Instant,
    observe: &mut impl FnMut(Instant) -> Vec<EnclaveError>,
    run: &mut impl FnMut(&SupervisorCommand, Instant) -> Result<CommandOutput, CommandFailure>,
    retained: &mut Vec<EnclaveError>) -> EnclaveResult<()> {
    let current = first_error(observe(until), retained);
    let time = deadline(until); retain(retained, &[&time]); current?; time?;
    let command_until = until.min(Instant::now() + COMMAND_LIMIT);
    receipt.bootstrap_attempted = true; receipt.uncertain_command_effects = true;
    let operation = command_result(run(command, command_until));
    receipt.bootstrap_succeeded = operation.is_ok();
    let time = deadline(command_until);
    retain(retained, &[&operation, &time]);
    // Always collect every post observation, even after unknown cleanup; there
    // is no next command or retry. Original command failure remains primary.
    let current = first_error(observe(until), retained);
    operation?; time?; current
}

/// Selected-only native administrative adapter. The required private runtime
/// refusal currently precedes maintenance-lock acquisition and every bootstrap,
/// preventing entry into the unchanged repairing/global-PF runtime. No caller
/// can supply an alternative runtime, command, verifier, guard or ready proof.
pub fn selected_supervisor_start(env: &Env) -> EnclaveResult<TargetSupervisorStartReport> {
    let checked = deployment::selected().ok_or_else(|| err!(EACCES, "DEPLOYMENT_CONTEXT_REQUIRED"))?;
    native_selection(env, checked)?;
    let until = Instant::now() + OPERATION_LIMIT;
    let command = SupervisorCommand::for_target(checked.target());
    let mut receipt = new_receipt(checked.target(), checked.descriptor_sha256());
    let mut guard = None;
    let mut owner = None;
    let mut retained = Vec::new();
    let operation = (|| {
        deadline(until)?;
        require_selected_runtime()?; // Mandatory before any maintenance effect.
        guard = Some(HostMaintenanceGuard::acquire()?);
        let guard = guard.as_mut().expect("actual retained maintenance guard");
        guard.assert_held()?;
        deployment::upgrade::assert_start_allowed(checked)?;
        owner = Some(PreparedSupervisor::new(checked)?);
        let owner = owner.as_mut().expect("actual retained selected originals");
        owner.populate(checked, &command)?;
        owner.verify_code(env, checked, guard, until, &mut retained)?;
        receipt.preflight_complete = true;
        register_one(&command, &mut receipt, until, &mut |end| owner.observations(env, checked, guard, end),
            &mut |command, end| native_command::run_owned_command(command.command(), end), &mut retained)
    })();
    let mut final_errors = owner.as_ref().map_or_else(Vec::new, |owner| owner.originals(checked));
    for result in [native_selection(env, checked), deployment::upgrade::assert_start_allowed(checked), require_selected_runtime(), deadline(until)] {
        if let Err(error) = result { final_errors.push(error); }
    }
    if let Some(guard) = &mut guard { if let Err(error) = guard.assert_held() { final_errors.push(error); } }
    // Hold the same successful original owners/guard through all final checks.
    Ok(finish(receipt, operation, final_errors, retained))
}

#[cfg(test)]
#[path = "ctl_target_supervisor_tests.rs"]
mod tests;
