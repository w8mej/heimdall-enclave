//! Selected intent registration only, with real native/root/session authority.
//! After full native code preflight, the actual current-console directory may
//! be created only when absent, with the same maintenance guard retained through
//! the fixed selected launchctl bootstrap. Core-five/session wiring stays separate.

use super::{Env,target_lifecycle::{HeldPaths,HeldFile,intent_directory::IntentConsoleDirectoryAttempt}};
pub use super::target_lifecycle::intent_directory::IntentConsoleDirectoryReceipt;
use crate::deploy::{self, CommandFailure, HostMaintenanceGuard, MaintenanceExclusion,
    NativeCodeShape, NativeEntitlementPolicy, NativeOutput, ProtectedNativeFile};
use enclave_core::{codesign::{self, CodeRequirement},
    deployment::{self, CheckedDeploymentTarget, normalized_path},
    error::{EnclaveError, EnclaveResult}, err, fail, Profile};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::{Path, PathBuf}, process::Command, time::{Duration, Instant}};

const MAX_PUBLIC:u64=1024*1024;
const MAX_CODE:u64=512*1024*1024;
const COMMAND_LIMIT:Duration=Duration::from_secs(5);
const OPERATION_LIMIT:Duration=Duration::from_secs(30);
const INTENT_ID:&str="com.enterprise.enclave.intent";

/// A single selected GUI registration outcome, never helper/ceremony readiness.
#[derive(Debug, Serialize)]
pub struct TargetIntentStartReport {
    /// Exact native registration and every final binding/exclusion check passed.
    pub successful:bool,
    /// Bounded public progress, preserved even after a failed final recheck.
    pub receipt:IntentStartReceipt,
    /// Stable operation refusal, without child stdout/stderr.
    pub error:Option<EnclaveError>,
    /// Separate final target/session/deadline refusal.
    pub final_binding_error:Option<EnclaveError>,
    /// Separate final actual maintenance-guard refusal.
    pub maintenance_error:Option<EnclaveError>,
    /// Actual original console-directory history, including partial own effects.
    pub directory:Option<IntentConsoleDirectoryReceipt>,
    /// All independently observed operation/native/command/final refusals.
    pub retained_errors:Vec<EnclaveError>,
}
/// Progress is descriptive; it cannot be replayed as startup/install authority.
#[derive(Debug, Serialize)]
pub struct IntentStartReceipt {
    /// Selected deployment identifier.
    pub target_id:String,
    /// Exact protected descriptor bytes accepted by the real selected context.
    pub descriptor_sha256:String,
    /// One selected intent registration, with every other auxiliary excluded.
    pub scope:&'static str,
    /// Actual native on-console UID, if observation succeeded.
    pub console_uid:Option<u32>,
    /// Actual native audit session, if observation succeeded.
    pub audit_session_id:Option<u32>,
    /// Exact selected launchd label.
    pub label:String,
    /// Exact selected installed LaunchAgent.
    pub plist:PathBuf,
    /// Every protected input and native signature/session precheck passed.
    pub preflight_complete:bool,
    /// The bounded bootstrap command was entered; effects may be uncertain.
    pub bootstrap_attempted:bool,
    /// The bounded executor observed bootstrap exit0, before final rechecks.
    pub bootstrap_succeeded:bool,
    /// Failed command/cleanup/final checks may leave the registration changed.
    pub uncertain_command_effects:bool,
    /// Registration command and all final checks succeeded.
    pub complete:bool,
    /// Process/IPC/biometric/YubiKey/install readiness is never inferred.
    pub readiness:&'static str,
    /// Always false; native registration is not profile qualification.
    pub qualified:bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ConsoleSession {uid:u32,audit:u32}
#[cfg(any(target_os="macos",test))]
fn session_value(value:Option<(u32,u32)>)->EnclaveResult<ConsoleSession> {
    match value {
        Some((uid,audit)) if uid>=500 && uid<u32::MAX && audit>0 && audit<u32::MAX=>Ok(ConsoleSession {uid,audit}),
        _=>Err(err!(EACCES,"DEPLOYMENT_INTENT_CONSOLE_SESSION_UNAVAILABLE")),
    }
}
fn current_session()->EnclaveResult<ConsoleSession> {
    #[cfg(target_os="macos")]
    {session_value(enclave_custody_vaultd::oidc_acquisition::current_console_session())}
    #[cfg(not(target_os="macos"))]
    {fail!(ENOSYS,"DEPLOYMENT_INTENT_NATIVE_REQUIRED");}
}
fn same_session(expected:ConsoleSession,actual:ConsoleSession)->EnclaveResult<()> {
    if expected!=actual {fail!(ESTALE,"DEPLOYMENT_INTENT_CONSOLE_SESSION_CHANGED");}Ok(())
}
fn deadline(until:Instant)->EnclaveResult<()> {
    if Instant::now()>=until {fail!(ETIMEDOUT,"DEPLOYMENT_INTENT_TIMEOUT");}Ok(())
}
fn native_selection(env:&Env,checked:&CheckedDeploymentTarget)->EnclaveResult<()> {
    if !cfg!(target_os="macos") {fail!(ENOSYS,"DEPLOYMENT_INTENT_NATIVE_REQUIRED");}
    if unsafe {libc::geteuid()}!=0 {fail!(EPERM,"DEPLOYMENT_INTENT_ROOT_REQUIRED");}
    let selected=deployment::selected().ok_or_else(||err!(EACCES,"DEPLOYMENT_CONTEXT_REQUIRED"))?;
    if selected.config_path()!=checked.config_path() || selected.descriptor_sha256()!=checked.descriptor_sha256()
        || selected.target()!=checked.target() || env.dev || env.profile!=checked.target().profile
        || env.socket_dir!=checked.target().layout.socket_root || env.state_dir!=checked.target().layout.state_root
        || env.audit_dir!=checked.target().layout.audit_root {
        fail!(EACCES,"DEPLOYMENT_INTENT_CONTEXT_MISMATCH");
    }
    if env.profile==Profile::L3 && codesign::TEAM_ID.is_empty() {fail!(EACCES,"L3_REQUIRES_TEAM_ID");}
    Ok(())
}
// Private closed command: domain, UID, label and plist are derived internally.
struct IntentCommand {uid:u32,label:String,plist:PathBuf}
impl IntentCommand {
    fn for_target(checked:&CheckedDeploymentTarget,session:ConsoleSession)->Self {
        Self::from_namespace(&checked.target().layout.launchd_namespace,session)
    }
    fn from_namespace(namespace:&str,session:ConsoleSession)->Self {
        let label=format!("{namespace}.intent");
        Self {uid:session.uid,plist:Path::new("/Library/LaunchAgents").join(format!("{label}.plist")),label}
    }
    fn command(&self)->Command {
        let mut command=crate::syscmd::command(crate::syscmd::Tool::Launchctl);
        command.current_dir("/").arg("bootstrap").arg(format!("gui/{}",self.uid)).arg(&self.plist);
        command
    }
}
fn command_result(result:Result<NativeOutput,CommandFailure>)->EnclaveResult<()> {
    match result {
        Ok(value) if value.code==Some(0)=>Ok(()),
        Ok(_)=>Err(err!(EIO,"DEPLOYMENT_INTENT_BOOTSTRAP_FAILED")),
        Err(CommandFailure::Timeout)=>Err(err!(ETIMEDOUT,"DEPLOYMENT_INTENT_BOOTSTRAP_TIMEOUT")),
        Err(CommandFailure::OutputLimit)=>Err(err!(E2BIG,"DEPLOYMENT_INTENT_BOOTSTRAP_OUTPUT_LIMIT")),
        Err(CommandFailure::OwnershipUnknown)=>Err(err!(EIO,"DEPLOYMENT_INTENT_BOOTSTRAP_CLEANUP_UNCERTAIN")),
        Err(CommandFailure::Unavailable|CommandFailure::Io)=>Err(err!(EIO,"DEPLOYMENT_INTENT_BOOTSTRAP_UNAVAILABLE")),
    }
}

pub(in crate::ctl) struct PreparedIntent {
    paths:HeldPaths,descriptor:HeldFile,inventory:HeldFile,pins:HeldFile,
    files:BTreeMap<PathBuf,HeldFile>,executable:PathBuf,requirement:CodeRequirement,
    session:ConsoleSession,command:IntentCommand,layout:crate::launchd::Layout,
}
fn installed_copy(paths:&mut HeldPaths,plan:&deploy::target_plan::TargetInstallPlan,
    path:&Path,mode:u32,maximum:u64)->EnclaveResult<(HeldFile,Vec<u8>)> {
    let path=normalized_path(path)?;
    let copy=plan.copies.iter().find(|copy|normalized_path(&copy.destination).ok().as_ref()==Some(&path))
        .ok_or_else(||err!(EACCES,"DEPLOYMENT_INTENT_INVENTORY_MISSING"))?;
    let expected_mode=u32::from_str_radix(&copy.mode,8).map_err(|_|err!(EINVAL,"DEPLOYMENT_INTENT_INVENTORY_MODE"))?;
    if copy.uid!=0 || copy.gid!=0 || expected_mode!=mode {fail!(EACCES,"DEPLOYMENT_INTENT_INVENTORY_MODE");}
    let (file,bytes)=HeldFile::open(paths,&path,maximum,Some(mode))?;
    if file.sha256()!=copy.sha256 || file.size()!=copy.size {fail!(ESTALE,"DEPLOYMENT_INTENT_INSTALLED_HASH");}
    Ok((file,bytes))
}
fn intent_requirement(pin_bytes:&[u8])->EnclaveResult<CodeRequirement> {
    let pins=codesign::pins::parse(pin_bytes)?;
    let hashes=pins.get(INTENT_ID).filter(|v|!v.is_empty())
        .ok_or_else(||err!(EACCES,"CODESIGN_PINS_MISSING"))?.clone();
    Ok(CodeRequirement {identifier:INTENT_ID.into(),team_id:codesign::TEAM_ID.into(),cdhash_allowlist:hashes})
}
impl PreparedIntent {
    fn open(env:&Env,checked:&CheckedDeploymentTarget)->EnclaveResult<Self> {
        let mut result=Self::open_originals(env,checked)?;
        let child=checked.target().layout.socket_root.join("intent").join(result.session.uid.to_string());
        result.paths.hold_directory(&child,Some((result.session.uid,8703,0o2710)))?;
        result.revalidate(checked)?;Ok(result)
    }
    // Sole deferred leaf route: requires the actual native creator, never a
    // caller boolean, UID/session/path or reconstructed directory receipt.
    fn open_for_console_creation(env:&Env,checked:&CheckedDeploymentTarget,
        creator:&IntentConsoleDirectoryAttempt)->EnclaveResult<Self> {
        let result=Self::open_originals(env,checked)?;
        creator.session_matches(result.session.uid,result.session.audit)?;Ok(result)
    }
    fn open_originals(env:&Env,checked:&CheckedDeploymentTarget)->EnclaveResult<Self> {
        native_selection(env,checked)?;
        deployment::upgrade::assert_start_allowed(checked)?;
        let session=current_session()?;
        let target=checked.target();
        let mut paths=HeldPaths::new()?;
        let (descriptor,_)=HeldFile::open(&mut paths,checked.config_path(),65536,None)?;
        if descriptor.sha256()!=checked.descriptor_sha256() {fail!(ESTALE,"DEPLOYMENT_CHANGED");}
        let (inventory,inventory_bytes)=HeldFile::open(&mut paths,&target.expected_artifacts_manifest,MAX_PUBLIC,None)?;
        let plan=deploy::target_plan::describe(target,checked.descriptor_sha256(),&inventory_bytes)?;
        let (pins,pin_bytes)=HeldFile::open(&mut paths,&target.codesign_pins_file,MAX_PUBLIC,None)?;
        if pins.sha256()!=plan.candidate_codesign_pins_sha256 {fail!(ESTALE,"DEPLOYMENT_INTENT_PIN_CUTOVER_REQUIRED");}
        let requirement=intent_requirement(&pin_bytes)?;
        let layout=crate::launchd::Layout::for_target(checked.clone())?;
        let command=IntentCommand::for_target(checked,session);
        let (plist,bytes)=installed_copy(&mut paths,&plan,&command.plist,0o644,MAX_PUBLIC)?;
        if bytes!=crate::launchd::intent_plist(&layout).as_bytes() {fail!(EACCES,"DEPLOYMENT_INTENT_RENDERER_MISMATCH");}
        let executable=normalized_path(&target.layout.binary_dir.join(crate::launchd::INTENT_BINARY))?;
        let (code,_)=installed_copy(&mut paths,&plan,&executable,0o755,MAX_CODE)?;
        let mut files=BTreeMap::from([(plist.path().to_owned(),plist),(executable.clone(),code)]);
        let authority=normalized_path(&target.authority_config)?;
        let (authority_file,_)=HeldFile::open(&mut paths,&authority,MAX_PUBLIC,None)?;
        files.insert(authority,authority_file);
        if let Some(broker)=&target.broker {
            let (file,_)=HeldFile::open(&mut paths,&broker.tuf_root_file,4*MAX_PUBLIC,None)?;
            files.insert(file.path().to_owned(),file);
        }
        paths.hold_directory(&target.layout.socket_root,Some((0,0,0o755)))?;
        paths.hold_directory(&target.layout.audit_root,Some((0,0,0o755)))?;
        let parent=target.layout.socket_root.join("intent");
        paths.hold_directory(&parent,Some((0,0,0o755)))?;
        let result=Self {paths,descriptor,inventory,pins,files,executable,requirement,session,command,layout};
        result.revalidate(checked)?;Ok(result)
    }
    pub(in crate::ctl) fn revalidate(&self,checked:&CheckedDeploymentTarget)->EnclaveResult<()> {
        deployment::upgrade::assert_start_allowed(checked)?;
        self.descriptor.revalidate(&self.paths)?;
        if self.descriptor.sha256()!=checked.descriptor_sha256() {fail!(ESTALE,"DEPLOYMENT_CHANGED");}
        self.inventory.revalidate(&self.paths)?;self.pins.revalidate(&self.paths)?;
        if hex::encode(Sha256::digest(checked.read_artifact_inventory()?))!=self.inventory.sha256() {
            fail!(ESTALE,"DEPLOYMENT_INTENT_INVENTORY_CHANGED");
        }
        self.layout.validate()?;
        for file in self.files.values() {file.revalidate(&self.paths)?;}
        self.paths.revalidate()?;same_session(self.session,current_session()?)
    }
    fn verify_code(&self,checked:&CheckedDeploymentTarget,guard:&mut HostMaintenanceGuard,until:Instant)->EnclaveResult<()> {
        self.check(checked,guard,until)?;
        let executable=&self.files[&self.executable];
        let view=ProtectedNativeFile {path:&self.executable,file:executable.file(),sha256:executable.sha256(),size:executable.size()};
        let result=deploy::verify_static_code(NativeCodeShape::Executable(view),&self.requirement,NativeEntitlementPolicy::DaemonBaseline);
        let after=self.check(checked,guard,until);
        // Always make the post-native observation, including a native refusal.
        result?;after
    }
    fn verify_code_retaining(&self,checked:&CheckedDeploymentTarget,guard:&mut HostMaintenanceGuard,
        until:Instant,retained:&mut Vec<EnclaveError>)->EnclaveResult<()> {
        self.check_retaining(checked,guard,until,retained)?;
        let executable=&self.files[&self.executable];
        let view=ProtectedNativeFile {path:&self.executable,file:executable.file(),sha256:executable.sha256(),size:executable.size()};
        let native=deploy::verify_static_code(NativeCodeShape::Executable(view),&self.requirement,NativeEntitlementPolicy::DaemonBaseline);
        let binding=self.revalidate(checked);let maintenance=guard.assert_held();let time=deadline(until);
        for error in [native.as_ref().err(),binding.as_ref().err(),maintenance.as_ref().err(),time.as_ref().err()].into_iter().flatten() {retained.push(error.clone());}
        native?;binding?;maintenance?;time
    }
    fn check_retaining(&self,checked:&CheckedDeploymentTarget,guard:&mut HostMaintenanceGuard,
        until:Instant,retained:&mut Vec<EnclaveError>)->EnclaveResult<()> {
        let binding=self.revalidate(checked);let exclusion=guard.assert_held();let time=deadline(until);
        for result in [&binding,&exclusion,&time] {if let Err(error)=result {retained.push(error.clone());}}
        binding?;exclusion?;time
    }
    fn check(&self,checked:&CheckedDeploymentTarget,guard:&mut HostMaintenanceGuard,until:Instant)->EnclaveResult<()> {
        let binding=self.revalidate(checked);let exclusion=guard.assert_held();let time=deadline(until);
        binding?;exclusion?;time
    }
}
fn new_receipt(checked:&CheckedDeploymentTarget)->IntentStartReceipt {
    let label=format!("{}.intent",checked.target().layout.launchd_namespace);
    IntentStartReceipt {target_id:checked.target().target_id.clone(),descriptor_sha256:checked.descriptor_sha256().into(),
        scope:"SELECTED_CURRENT_CONSOLE_INTENT_REGISTRATION_ONLY",console_uid:None,audit_session_id:None,
        plist:Path::new("/Library/LaunchAgents").join(format!("{label}.plist")),label,preflight_complete:false,
        bootstrap_attempted:false,bootstrap_succeeded:false,uncertain_command_effects:false,complete:false,
        readiness:"UNKNOWN_HELPER_IPC_BIOMETRIC_YUBIKEY_AND_INSTALLATION_READINESS",qualified:false}
}
fn finish(mut receipt:IntentStartReceipt,operation:EnclaveResult<()>,binding:EnclaveResult<()>,maintenance:EnclaveResult<()>)
    ->TargetIntentStartReport {
    let successful=operation.is_ok() && binding.is_ok() && maintenance.is_ok() && receipt.bootstrap_succeeded;
    receipt.complete=successful;receipt.uncertain_command_effects=receipt.bootstrap_attempted && !successful;
    let retained_errors=[operation.as_ref().err(),binding.as_ref().err(),maintenance.as_ref().err()]
        .into_iter().flatten().cloned().collect();
    TargetIntentStartReport {successful,receipt,error:operation.err(),final_binding_error:binding.err(),maintenance_error:maintenance.err(),
        directory:None,retained_errors}
}
/// Bootstrap only the actual selected current-console intent registration.
/// Requires native root authority; observes an existing exact console child or
/// creates only the absent actual-console child after native code preflight;
/// no caller supplies a UID, session, verifier, command, guard or configuration.
pub fn selected_intent_start(env:&Env)->EnclaveResult<TargetIntentStartReport> {
    let checked=deployment::selected().ok_or_else(||err!(EACCES,"DEPLOYMENT_CONTEXT_REQUIRED"))?;
    native_selection(env,checked)?;
    crate::custody_notice::show_for_profile(&env.profile.to_string());
    let mut guard=HostMaintenanceGuard::acquire()?;
    guard.assert_held()?;
    let until=Instant::now()+OPERATION_LIMIT;
    let mut receipt=new_receipt(checked);
    let mut prepared=None;
    let mut directory=None;
    let mut retained=Vec::new();
    let operation=(|| {
        deadline(until)?;guard.assert_held()?;
        directory=match IntentConsoleDirectoryAttempt::open(checked,&mut guard,until) {
            Ok(owner)=>Some(owner),
            Err(failure)=>{
                // Adopt the ACTUAL constructed refusal owner before returning;
                // its original descriptors and all gate errors reach final checks.
                directory=failure.owner;return Err(failure.error);
            },
        };
        prepared=Some(PreparedIntent::open_for_console_creation(env,checked,directory.as_ref().expect("native creator"))?);
        let state=prepared.as_mut().expect("successful intent preflight allocation");
        receipt.console_uid=Some(state.session.uid);receipt.audit_session_id=Some(state.session.audit);
        receipt.label=state.command.label.clone();receipt.plist=state.command.plist.clone();
        state.verify_code_retaining(checked,&mut guard,until,&mut retained)?;
        let creator=directory.as_mut().expect("retained native creator");
        creator.prepare(checked,&mut guard,state,until)?;
        creator.admit_same_child(&mut state.paths)?;
        state.check_retaining(checked,&mut guard,until,&mut retained)?;
        creator.finish(checked,&mut guard,until)?;receipt.preflight_complete=true;
        let command_until=until.min(Instant::now()+COMMAND_LIMIT);
        receipt.bootstrap_attempted=true;receipt.uncertain_command_effects=true;
        let result=command_result(deploy::run_owned_command(state.command.command(),command_until));
        receipt.bootstrap_succeeded=result.is_ok();
        // Keep actual command refusal before independently observed late time.
        let time=deadline(command_until);
        for observed in [&result,&time] {if let Err(error)=observed {retained.push(error.clone());}}
        result?;time
    })();
    let binding=match &prepared {Some(state)=>{
        let original=state.revalidate(checked);let time=deadline(until);
        for observed in [&original,&time] {if let Err(error)=observed {retained.push(error.clone());}}
        original.and(time)
    },None=>Ok(())};
    // Final real originals remain retained through all terminal observations;
    // no cleanup/retry follows a partial creation or uncertain bootstrap.
    let directory_final=match directory.as_mut() {Some(owner)=>owner.finish(checked,&mut guard,until),None=>Ok(())};
    let maintenance=guard.assert_held();
    let mut report=finish(receipt,operation,binding,maintenance);
    if let Err(error)=directory_final {report.successful=false;report.receipt.complete=false;
        report.receipt.uncertain_command_effects=report.receipt.bootstrap_attempted;
        retained.push(error);}
    if let Some(owner)=directory.as_ref() {
        let progress=owner.receipt();retained.extend(progress.errors.iter().cloned());
        report.directory=Some(progress);
    }
    report.retained_errors.extend(retained);
    Ok(report)
}

#[cfg(test)]
#[path="ctl_target_intent_tests.rs"]
mod tests;
