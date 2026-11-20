//! Concrete selected lifecycle adapters. Only fixed core commands enter the
//! owned-child executor. Public output carries bounded receipts and stable
//! errors, never launchctl stdout/stderr or a claim of installation readiness.

use super::{target_lifecycle::{self, CoreCodeVerifier, CoreCodeView, CoreCommand,
    CoreLifecycleFailure, CoreLifecycleReceipt, CoreRunner}, Env};
use crate::deploy::{self, CommandFailure, HostMaintenanceGuard, MaintenanceExclusion,
    NativeCodeShape, NativeEntitlementPolicy, NativeOutput, ProtectedNativeFile};
use enclave_core::{codesign::CodeRequirement, daemon::DaemonId, deployment,
    error::{EnclaveError, EnclaveResult}, err, fail};
use serde::Serialize;
use std::{cell::RefCell, time::Instant};

/// Selected core-five registration outcome. Runtime and full-installation
/// readiness remain unknown even when all five commands complete.
#[derive(Debug, Serialize)]
pub struct TargetLifecycleReport {
    /// All commands and final maintenance recheck succeeded.
    pub successful:bool,
    /// Exact lifecycle receipt, including a completed prefix on failure.
    pub receipt:serde_json::Value,
    /// Stable operation failure without child output.
    pub error:Option<EnclaveError>,
    /// A separate final exclusion failure never erases the operation receipt.
    pub maintenance_error:Option<EnclaveError>,
}

/// Selected non-broker auxiliary registration outcome. This does not certify
/// core/broker shutdown, process inactivity or readiness for installation.
#[derive(Debug, Serialize)]
pub struct TargetAuxiliaryStopReport {
    /// The complete scoped operation and final maintenance check succeeded.
    pub successful:bool,
    /// Exact public registration receipt, including partial/uncertain progress.
    pub receipt:serde_json::Value,
    /// Original operation error, with no raw child output.
    pub error:Option<EnclaveError>,
    /// A separately retained final descriptor/exclusion failure.
    pub final_binding_error:Option<EnclaveError>,
    /// Adapter's final real maintenance-guard check failure.
    pub maintenance_error:Option<EnclaveError>,
}

/// Live authenticated selected broker barrier and registration-stop outcome.
/// This never proves complete target inactivity or installation readiness.
#[derive(Debug, Serialize)]
pub struct TargetBrokerStopReport {
    /// The scoped operation and every final binding/exclusion check passed.
    pub successful:bool,
    /// Public progress, including uncertain barrier or bootout effects.
    pub receipt:serde_json::Value,
    /// Original operation refusal, without raw process or IPC output.
    pub error:Option<EnclaveError>,
    /// Separately retained final target/exclusion refusal.
    pub final_binding_error:Option<EnclaveError>,
    /// Adapter's final actual maintenance-guard refusal.
    pub maintenance_error:Option<EnclaveError>,
}

fn broker_report(result:Result<super::target_broker_stop::BrokerStopReceipt,
    super::target_broker_stop::BrokerStopFailure>,maintenance:EnclaveResult<()>)
    ->EnclaveResult<TargetBrokerStopReport> {
    let (receipt,error,final_binding_error)=match result {
        Ok(receipt)=>(receipt,None,None),
        Err(failure)=>(failure.receipt,Some(failure.error),failure.final_binding_error),
    };
    let maintenance_error=maintenance.err();
    Ok(TargetBrokerStopReport {
        successful:error.is_none() && final_binding_error.is_none()
            && maintenance_error.is_none() && receipt.complete,
        receipt:serde_json::to_value(receipt).map_err(|_|err!(EIO,"DEPLOYMENT_LIFECYCLE_SERIALIZE"))?,
        error,final_binding_error,maintenance_error,
    })
}

fn auxiliary_report(result:Result<super::target_aux_stop::AuxiliaryStopReceipt,
    super::target_aux_stop::AuxiliaryStopFailure>,maintenance:EnclaveResult<()>)
    ->EnclaveResult<TargetAuxiliaryStopReport> {
    let (receipt,error,final_binding_error)=match result {
        Ok(receipt)=>(receipt,None,None),
        Err(failure)=>(failure.receipt,Some(failure.error),failure.final_binding_error),
    };
    let maintenance_error=maintenance.err();
    Ok(TargetAuxiliaryStopReport {
        successful:error.is_none() && final_binding_error.is_none()
            && maintenance_error.is_none() && receipt.complete,
        receipt:serde_json::to_value(receipt).map_err(|_|err!(EIO,"DEPLOYMENT_LIFECYCLE_SERIALIZE"))?,
        error,final_binding_error,maintenance_error,
    })
}

fn report(result:Result<CoreLifecycleReceipt,CoreLifecycleFailure>,maintenance:EnclaveResult<()>)
    ->EnclaveResult<TargetLifecycleReport> {
    let (receipt,error)=match result {Ok(receipt)=>(receipt,None),Err(failure)=>(failure.receipt,Some(failure.error))};
    let maintenance_error=maintenance.err();
    Ok(TargetLifecycleReport {successful:error.is_none() && maintenance_error.is_none() && receipt.complete,
        receipt:serde_json::to_value(receipt).map_err(|_|err!(EIO,"DEPLOYMENT_LIFECYCLE_SERIALIZE"))?,
        error,maintenance_error})
}
fn held(guard:&RefCell<&mut HostMaintenanceGuard>)->EnclaveResult<()> {
    guard.try_borrow_mut().map_err(|_|err!(EACCES,"MAINTENANCE_GUARD_BORROWED"))?.assert_held()
}
fn deadline(until:Instant)->EnclaveResult<()> {
    if Instant::now()>=until {fail!(ETIMEDOUT,"DEPLOYMENT_LIFECYCLE_TIMEOUT");}Ok(())
}

fn command_result(result:Result<NativeOutput,CommandFailure>)->EnclaveResult<()> {
    match result {
        Ok(output) if output.code==Some(0)=>Ok(()),
        Ok(_)=>Err(err!(EIO,"DEPLOYMENT_LAUNCHCTL_FAILED")),
        Err(CommandFailure::Timeout)=>Err(err!(ETIMEDOUT,"DEPLOYMENT_LAUNCHCTL_TIMEOUT")),
        Err(CommandFailure::OutputLimit)=>Err(err!(E2BIG,"DEPLOYMENT_LAUNCHCTL_OUTPUT_LIMIT")),
        Err(CommandFailure::OwnershipUnknown)=>Err(err!(EIO,"DEPLOYMENT_LAUNCHCTL_CLEANUP_UNCERTAIN")),
        Err(CommandFailure::Unavailable|CommandFailure::Io)=>Err(err!(EIO,"DEPLOYMENT_LAUNCHCTL_UNAVAILABLE")),
    }
}
/// A concrete caller's extra currentness can only refuse. The mandatory
/// selected installed-input/native verifier and real guard remain independent.
struct AdditionalCurrentness<'observer> {
    checked:&'observer deployment::CheckedDeploymentTarget,
    callback:&'observer mut dyn FnMut(&mut HostMaintenanceGuard)->EnclaveResult<()>,
    operation_deadline:Option<Instant>,errors:Vec<EnclaveError>,
}
// Retain every observed stable error before primary-error precedence consumes
// results. This primitive never converts a failure to success or stores native
// child output. Equal errors at distinct boundaries remain separate evidence.
fn retain_result_errors(errors:&mut Vec<EnclaveError>,results:&[&EnclaveResult<()>]) {
    for result in results {if let Err(error)=result {errors.push(error.clone());}}
}
fn retain_observed_results(observer:Option<&RefCell<AdditionalCurrentness<'_>>>,
    results:&[&EnclaveResult<()>])->EnclaveResult<()> {
    if let Some(observer)=observer {
        let mut observer=observer.try_borrow_mut().map_err(|_|err!(EACCES,"DEPLOYMENT_CURRENTNESS_BORROWED"))?;
        retain_result_errors(&mut observer.errors,results);
    }
    Ok(())
}
fn observer_context(checked:&deployment::CheckedDeploymentTarget)->EnclaveResult<()> {
    if !cfg!(target_os="macos") {fail!(ENOSYS,"DEPLOYMENT_LIFECYCLE_NATIVE_REQUIRED");}
    if unsafe{libc::geteuid()}!=0 {fail!(EPERM,"DEPLOYMENT_LIFECYCLE_ROOT_REQUIRED");}
    let selected=deployment::selected().ok_or_else(||err!(EACCES,"DEPLOYMENT_CONTEXT_REQUIRED"))?;
    if selected.config_path()!=checked.config_path()||selected.descriptor_sha256()!=checked.descriptor_sha256()
        ||selected.target()!=checked.target() {fail!(EACCES,"DEPLOYMENT_LIFECYCLE_CONTEXT_MISMATCH");}
    Ok(())
}
fn observer_boundary(guard:&RefCell<&mut HostMaintenanceGuard>,
    observer:Option<&RefCell<AdditionalCurrentness<'_>>>,until:Option<Instant>)->EnclaveResult<()> {
    let Some(observer)=observer else{return Ok(());};
    let mut errors=Vec::new();
    let context=||observer.try_borrow().map_err(|_|err!(EACCES,"DEPLOYMENT_CURRENTNESS_BORROWED"))
        .and_then(|owner|observer_context(owner.checked));
    for result in [held(guard),until.map_or(Ok(()),deadline),context()] {
        if let Err(error)=result{errors.push(error);}
    }
    if errors.is_empty() {
        // This synchronous reborrow is exactly the already-retained guard.
        // No owner/FD export or reacquisition occurs; callback success cannot
        // replace any native/context/code/guard check in the real lifecycle.
        let result=(|| {
            let mut observer=observer.try_borrow_mut().map_err(|_|err!(EACCES,"DEPLOYMENT_CURRENTNESS_BORROWED"))?;
            let mut same_guard=guard.try_borrow_mut().map_err(|_|err!(EACCES,"MAINTENANCE_GUARD_BORROWED"))?;
            (observer.callback)(&mut **same_guard)
        })();
        if let Err(error)=result{errors.push(error);}
    }
    // Actual post context/guard/deadline checks still execute when callback or
    // prechecks refused. No slow callback result may skip these boundaries.
    for result in [context(),held(guard),until.map_or(Ok(()),deadline)] {
        if let Err(error)=result{errors.push(error);}
    }
    let result=errors.first().cloned().map_or(Ok(()),Err);
    observer.try_borrow_mut().map_err(|_|err!(EACCES,"DEPLOYMENT_CURRENTNESS_BORROWED"))?.errors.extend(errors);
    result
}
struct NativeCoreRunner<'a,'guard,'observer> {
    guard:&'a RefCell<&'guard mut HostMaintenanceGuard>,
    observer:Option<&'a RefCell<AdditionalCurrentness<'observer>>>,
}
impl CoreRunner for NativeCoreRunner<'_,'_,'_> {
    fn run(&mut self,command:&CoreCommand,until:Instant)->EnclaveResult<()> {
        held(self.guard)?;deadline(until)?;
        observer_boundary(self.guard,self.observer,Some(until))?;
        let result=command_result(deploy::run_owned_command(command.command(),until));
        // Recheck even on command/cleanup error. A failed postcheck conservatively
        // marks this boundary uncertain, preserving all earlier completed jobs.
        let current=observer_boundary(self.guard,self.observer,Some(until));
        let maintenance=held(self.guard);let bounded=deadline(until);
        // The actual operation and each independently observed post failure
        // survive even when the unchanged primary precedence selects another.
        let retained=retain_observed_results(self.observer,&[&result,&maintenance,&bounded]);
        maintenance?;bounded?;current?;retained?;result
    }
}

fn verify_view(daemon:DaemonId,view:&CoreCodeView<'_>,requirement:&CodeRequirement,until:Instant,
    mut native:impl FnMut(NativeCodeShape<'_>,&CodeRequirement,NativeEntitlementPolicy)->EnclaveResult<()>)
    ->EnclaveResult<()> {
    verify_view_retaining(daemon,view,requirement,until,&mut native,|_|Ok(()))
}
fn verify_view_retaining(daemon:DaemonId,view:&CoreCodeView<'_>,requirement:&CodeRequirement,until:Instant,
    mut native:impl FnMut(NativeCodeShape<'_>,&CodeRequirement,NativeEntitlementPolicy)->EnclaveResult<()>,
    mut retain:impl FnMut(&[&EnclaveResult<()>])->EnclaveResult<()>)->EnclaveResult<()> {
    if !super::START_ORDER.contains(&daemon) || requirement.identifier!=daemon.launchd_label() {
        fail!(EACCES,"DEPLOYMENT_NATIVE_CODE_ROLE");
    }
    deadline(until)?;(view.revalidate)()?;deadline(until)?;
    let executable=ProtectedNativeFile {path:view.executable_path,file:view.executable,
        sha256:view.executable_sha256,size:view.executable_size};
    let members=view.members.iter().map(|member|ProtectedNativeFile {path:member.path,
        file:member.file,sha256:member.sha256,size:member.size}).collect::<Vec<_>>();
    let (shape,policy)=if daemon==DaemonId::CustodyVault {
        (NativeCodeShape::Bundle {root:view.code_path,executable,members:&members},
            NativeEntitlementPolicy::CustodyForCompiledSigningMode)
    } else {
        if view.code_path!=view.executable_path || !members.is_empty() {
            fail!(EACCES,"DEPLOYMENT_NATIVE_CODE_SHAPE");
        }
        (NativeCodeShape::Executable(executable),NativeEntitlementPolicy::DaemonBaseline)
    };
    let result=native(shape,requirement,policy);
    // Even a native refusal must be followed by the held binding recheck.
    let after=(view.revalidate)();
    let bounded=deadline(until);
    // Capture the actual native refusal and actual original-view/deadline
    // refusals together before the established primary precedence consumes any.
    let retained=retain(&[&result,&after,&bounded]);
    bounded?;after?;retained?;result
}
struct NativeCoreVerifier<'a,'guard,'observer> {
    guard:&'a RefCell<&'guard mut HostMaintenanceGuard>,
    observer:Option<&'a RefCell<AdditionalCurrentness<'observer>>>,
}
impl CoreCodeVerifier for NativeCoreVerifier<'_,'_,'_> {
    fn verify(&mut self,daemon:DaemonId,view:&CoreCodeView<'_>,requirement:&CodeRequirement,until:Instant)->EnclaveResult<()> {
        held(self.guard)?;
        if let Some(observer)=self.observer {
            // This is the existing lifecycle's actual overall deadline, not a
            // new/extended callback budget or a per-command deadline.
            observer.try_borrow_mut().map_err(|_|err!(EACCES,"DEPLOYMENT_CURRENTNESS_BORROWED"))?.operation_deadline=Some(until);
        }
        observer_boundary(self.guard,self.observer,Some(until))?;
        let native=|shape:NativeCodeShape<'_>,req:&CodeRequirement,policy:NativeEntitlementPolicy|deploy::verify_static_code(shape,req,policy).map(|_|());
        let result=if self.observer.is_some() {
            verify_view_retaining(daemon,view,requirement,until,native,
                |results|retain_observed_results(self.observer,results))
        } else {verify_view(daemon,view,requirement,until,native)};
        let current=observer_boundary(self.guard,self.observer,Some(until));
        let maintenance=held(self.guard);let bounded=deadline(until);
        // The actual operation and each independently observed post failure
        // survive even when the unchanged primary precedence selects another.
        let retained=retain_observed_results(self.observer,&[&result,&maintenance,&bounded]);
        maintenance?;bounded?;current?;retained?;result
    }
}

/// Start only the selected core-five jobs under host maintenance exclusion.
/// This invokes no installer, provisioning, authority repair or rollback.
pub fn selected_core_start(env:&Env)->EnclaveResult<TargetLifecycleReport> {
    let selected=deployment::selected().ok_or_else(||err!(EACCES,"DEPLOYMENT_CONTEXT_REQUIRED"))?;
    crate::custody_notice::show_for_profile(&env.profile.to_string());
    let mut guard=HostMaintenanceGuard::acquire()?;
    let guard=RefCell::new(&mut guard);
    held(&guard)?;
    let result=target_lifecycle::start_core(env,selected,&mut NativeCoreVerifier {guard:&guard,observer:None},
        &mut NativeCoreRunner {guard:&guard,observer:None});
    let maintenance=held(&guard);
    report(result,maintenance)
}
/// Registration outcome plus every observed operation/currentness refusal.
/// Public lifecycle receipt/error semantics remain unchanged. These diagnostic
/// errors never construct any native readiness or startup authority.
pub(crate) struct RetainedGuardCoreStartOutcome {
    pub(crate) lifecycle:TargetLifecycleReport,
    // Includes actual command/native failures and independent postchecks,
    // including errors hidden by the original primary-error precedence.
    pub(crate) currentness_errors:Vec<EnclaveError>,
}
/// Borrow the SAME already-held guard through every concrete core registration.
/// The synchronous callback receives only that original mutable guard reborrow;
/// an actual birth caller splits its other original owners away from that guard
/// and retains its own detailed errors. Callback success is denial-only: exact
/// installed inputs, selected context, native code and guard remain mandatory.
/// No guard/EX acquisition, lease release, selection, installation or readiness
/// proof occurs. A consuming caller separately proves its actual own-clear and
/// SAME acquisition's Dedicated transition and retains EX during registration.
/// Runtime startup can succeed only after a later explicit release boundary;
/// command registration is never authenticated process/policy health.
pub(crate) fn selected_core_start_with_retained_guard(env:&Env,
    checked:&deployment::CheckedDeploymentTarget,guard:&mut HostMaintenanceGuard,
    additional:&mut dyn FnMut(&mut HostMaintenanceGuard)->EnclaveResult<()>)->EnclaveResult<RetainedGuardCoreStartOutcome> {
    let guard=RefCell::new(guard);held(&guard)?;
    let observer=RefCell::new(AdditionalCurrentness {checked,callback:additional,operation_deadline:None,errors:Vec::new()});
    let result=target_lifecycle::start_core(env,checked,&mut NativeCoreVerifier {guard:&guard,observer:Some(&observer)},
        &mut NativeCoreRunner {guard:&guard,observer:Some(&observer)});
    // If preparation failed before first code verification, no command was
    // possible and the lifecycle is already a refusal. Otherwise preserve its
    // actual original overall deadline for terminal observer completion.
    let until=observer.borrow().operation_deadline;
    let terminal=observer_boundary(&guard,Some(&observer),until);
    let maintenance=held(&guard);
    let mut lifecycle=report(result,maintenance)?;
    let mut currentness_errors=std::mem::take(&mut observer.borrow_mut().errors);
    // Preserve even an internal observer-ledger borrow failure separately from
    // an existing lifecycle failure; never erase partial command receipts.
    if let Err(error)=terminal {if currentness_errors.is_empty(){currentness_errors.push(error);}}
    lifecycle.successful&=currentness_errors.is_empty();
    Ok(RetainedGuardCoreStartOutcome {lifecycle,currentness_errors})
}
/// Restrictively stop the descriptor's closed core labels without loading any
/// admission reference or selecting a general production context.
pub fn selected_core_stop(env:&Env,target:&deployment::teardown::TeardownDeploymentTarget)->EnclaveResult<TargetLifecycleReport> {
    let mut guard=HostMaintenanceGuard::acquire()?;
    let guard=RefCell::new(&mut guard);
    held(&guard)?;
    let result=target_lifecycle::stop_core(env,target,&mut NativeCoreRunner {guard:&guard,observer:None});
    let maintenance=held(&guard);
    report(result,maintenance)
}

/// Restrictively stop selected non-broker auxiliaries in native live GUI
/// domains and the fixed system namespace, retaining one real guard throughout.
pub fn selected_auxiliary_stop(target:&deployment::teardown::TeardownDeploymentTarget)
    ->EnclaveResult<TargetAuxiliaryStopReport> {
    let mut guard=HostMaintenanceGuard::acquire()?;
    guard.assert_held()?;
    let result=super::target_aux_stop::stop_auxiliary(target,&mut guard);
    let maintenance=guard.assert_held();
    auxiliary_report(result,maintenance)
}

/// Require a fully checked selected target and authenticated live broker idle
/// before stopping its registration. There is no descriptor-only fallback.
pub fn selected_broker_stop()->EnclaveResult<TargetBrokerStopReport> {
    let checked=deployment::selected().ok_or_else(||err!(EACCES,"DEPLOYMENT_CONTEXT_REQUIRED"))?;
    let mut guard=HostMaintenanceGuard::acquire()?;
    guard.assert_held()?;
    let result=super::target_broker_stop::stop_selected_broker(checked,&mut guard);
    let maintenance=guard.assert_held();
    broker_report(result,maintenance)
}

#[cfg(test)]
#[path="ctl_target_native_tests.rs"]
mod tests;
