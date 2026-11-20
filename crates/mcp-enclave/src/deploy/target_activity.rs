//! Read-only selected-target launchd observations, never installation authority.
//!
//! The trusted caller must hold maintenance exclusion over the ENTIRE call and
//! any later action. The guard is an in-process integration requirement, not an
//! assertion supplied by a CLI/JSON caller. No production guard/provider or CLI
//! is supplied here. Even exact absence of every observed job cannot prove the
//! absence of unmanaged processes: shared UID/code identity is not an instance
//! credential. Consequently inactivity_proven and installation_supported remain
//! false, including when every selected registration is observed absent.
//!
//! GUI candidates use the existing packaging/macos/install.sh:249-263 (and
//! uninstall.sh) subdomains grammar: user|gui/UID with optional numeric [id].
//! Directory-backed and non-current login users are included; no dscl fallback.
//! Native absence diagnostics are exact macOS26.6.2/C-locale observations from
//! coordinator/native-absent-target-launchd-attempt1.stdout. Other versions and
//! unknown/changed/error outputs remain UNKNOWN. No user/UID query is inferred
//! from a gui/UID query. Only fixed launchctl print requests can be constructed.

use std::{collections::BTreeSet, process::Command, time::{Duration, Instant}};
use enclave_core::{deployment::{CheckedDeploymentTarget, DeploymentTarget},
    error::EnclaveResult, fail, Profile};
use serde::Serialize;
use enclave_core::native_command::{self,MAX_OUTPUT};
pub(crate) use enclave_core::native_command::CommandFailure;

const MAX_GUI_DOMAINS:usize=64;
const COMMAND_LIMIT:Duration=Duration::from_secs(2);
const OBSERVATION_LIMIT:Duration=Duration::from_secs(10);
const SYSTEM_SUFFIXES:&[&str]=&["adapter","cas","custody","ifc","zk","supervisor","hydrate","browser","gateway"];
const AGENT_SUFFIXES:&[&str]=&["intent","oidc-broker"];

/// Trusted maintenance exclusion must survive this entire observation interval.
/// There is deliberately no system/default implementation or boolean adapter.
pub(crate) trait MaintenanceExclusion {
    fn assert_held(&mut self)->EnclaveResult<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeContract { MacOs26_6_2 }

/// Raw output never implements Serialize or a content-bearing Debug formatter.
#[derive(Clone)]
pub(crate) struct NativeOutput {
    pub(crate) code:Option<i32>,
    pub(crate) stdout:Vec<u8>,
    pub(crate) stderr:Vec<u8>,
    pub(crate) contract:Option<NativeContract>,
}
impl std::fmt::Debug for NativeOutput {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        f.debug_struct("NativeOutput").field("code",&self.code)
            .field("stdout_bytes",&self.stdout.len()).field("stderr_bytes",&self.stderr.len()).finish()
    }
}

/// Private fields prevent callers from supplying arbitrary argv to this runner.
#[derive(Clone, Debug)]
pub(crate) struct LaunchQuery {domain:String,label:Option<String>}
impl LaunchQuery {
    fn system()->Self {Self {domain:"system".into(),label:None}}
    fn job(domain:String,label:String)->Self {Self {domain,label:Some(label)}}
    fn target(&self)->String {match &self.label {Some(label)=>format!("{}/{label}",self.domain),None=>self.domain.clone()}}
    fn allowed(&self)->bool {
        let domain=self.domain=="system" || self.domain.strip_prefix("gui/").is_some_and(|s|
            s.parse::<u32>().is_ok_and(|uid|uid>=500 && uid<u32::MAX && uid.to_string()==s));
        domain && match &self.label {
            None=>self.domain=="system",
            Some(label)=>label.rsplit_once('.').is_some_and(|(namespace,suffix)|
                valid_namespace(namespace) && if self.domain=="system" {
                    SYSTEM_SUFFIXES.contains(&suffix) || suffix=="apfs-broker"
                } else {AGENT_SUFFIXES.contains(&suffix)})
        }
    }
}
fn valid_namespace(value:&str)->bool {
    value.len()<=112 && value.contains('.') && value.split('.').all(|part| {
        !part.is_empty() && part.len()<=63 && part.as_bytes()[0].is_ascii_lowercase()
            && part.as_bytes().last().is_some_and(|b|b.is_ascii_lowercase() || b.is_ascii_digit())
            && part.bytes().all(|b|b.is_ascii_lowercase() || b.is_ascii_digit() || b==b'-')
    })
}

pub(crate) trait ActivityRunner {
    /// Must honor the absolute deadline and output bound, including descendants.
    fn print(&mut self,query:&LaunchQuery,deadline:Instant)->Result<NativeOutput,CommandFailure>;
}

/// Real read-only runner, with no authority hook or CLI wiring. Its only child
/// is fixed syscmd::Tool::Launchctl with exactly [print, closed_query].
pub(crate) struct NativeLaunchctlRunner;
/// Shared bounded executor for trusted, internally constructed native commands.
/// This is plumbing, not the closed read-only ActivityRunner query interface or
/// permission to expose raw argv/commands to CLI callers. The lifecycle adapter
/// must supply only its closed CoreCommand.command(), accept only exit0 and
/// map all other outcomes to redacted errors. Raw output must never be logged,
/// serialized or exported by that adapter. No production platform fallback.
pub(crate) fn run_owned_command(command:Command,deadline:Instant)->Result<NativeOutput,CommandFailure> {
    command_output(native_command::run_owned_command(command,deadline),None)
}
// Keep platform-specific launchd absence evidence in this adapter. Moving raw
// fields adds no output copy, authority or default successful native contract.
fn command_output(result:Result<native_command::CommandOutput,CommandFailure>,contract:Option<NativeContract>)
    ->Result<NativeOutput,CommandFailure> {
    result.map(|output|NativeOutput {code:output.code,stdout:output.stdout,stderr:output.stderr,contract})
}
impl ActivityRunner for NativeLaunchctlRunner {
    fn print(&mut self,query:&LaunchQuery,deadline:Instant)->Result<NativeOutput,CommandFailure> {
        if !query.allowed() {return Err(CommandFailure::Unavailable);}
        #[cfg(target_os="macos")]
        {
            let mut command=crate::syscmd::command(crate::syscmd::Tool::Launchctl);
            command.args(["print",&query.target()]).current_dir("/");
            let contract=native_contract();
            command_output(native_command::run_owned_command(command,deadline),contract)
        }
        #[cfg(not(target_os="macos"))]
        {let _=deadline;Err(CommandFailure::Unavailable)}
    }
}
#[cfg(target_os="macos")]
fn native_contract()->Option<NativeContract> {
    let mut bytes=[0u8;64];let mut length=bytes.len();
    // Read-only native metadata; neither environment nor a caller boolean may
    // substitute for the exact version whose absence contract was observed.
    let result=unsafe {libc::sysctlbyname(b"kern.osproductversion\0".as_ptr().cast(),
        bytes.as_mut_ptr().cast(),&mut length,std::ptr::null_mut(),0)};
    if result==0 && length==b"26.6.2\0".len() && &bytes[..length]==b"26.6.2\0" {
        Some(NativeContract::MacOs26_6_2)
    } else {None}
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) enum JobObservation { ObservedLoaded, ObservedServiceAbsent, ObservedGuiDomainAbsent,
    UnknownResponse, UnknownPlatform, UnknownUnavailable, UnknownTimeout, UnknownOutputLimit }
#[derive(Debug, Serialize)]
pub(crate) struct JobRecord {pub(crate) target:String,pub(crate) status:JobObservation}
#[derive(Debug, Serialize)]
pub(crate) struct TargetActivityObservation {
    pub(crate) target_id:String,
    pub(crate) descriptor_sha256:String,
    pub(crate) gui_candidate_uids:Vec<u32>,
    pub(crate) jobs:Vec<JobRecord>,
    pub(crate) domain_inventory_status:&'static str,
    pub(crate) selected_jobs_status:&'static str,
    pub(crate) process_instance_status:&'static str,
    pub(crate) inactivity_proven:bool,
    pub(crate) installation_supported:bool,
    pub(crate) qualified:bool,
}

// This is the existing installer AWK grammar, expressed without invoking a
// shell or adding an alternative local-directory/console-only inventory path.
fn gui_candidates(raw:&[u8])->Result<BTreeSet<u32>,()> {
    let text=std::str::from_utf8(raw).map_err(|_|())?;
    if text.lines().next().map(str::trim)!=Some("system = {") {return Err(());}
    let (mut seen,mut inside,mut closed)=(false,false,false);
    let mut result=BTreeSet::new();
    for line in text.lines() {
        let line=line.trim_matches(|c:char|c.is_ascii_whitespace());
        if line=="subdomains = {" {
            if seen {return Err(());}seen=true;inside=true;continue;
        }
        if inside && line=="}" {inside=false;closed=true;continue;}
        if !inside || line.is_empty() {continue;}
        let mut fields=line.split_ascii_whitespace();
        let first=fields.next().ok_or(())?;
        let (kind,uid)=first.split_once('/').ok_or(())?;
        if !["user","gui"].contains(&kind) || uid.is_empty() || !uid.bytes().all(|b|b.is_ascii_digit()) {return Err(());}
        if let Some(identifier)=fields.next() {
            let digits=identifier.strip_prefix('[').and_then(|s|s.strip_suffix(']')).ok_or(())?;
            if digits.is_empty() || !digits.bytes().all(|b|b.is_ascii_digit()) {return Err(());}
        }
        if fields.next().is_some() {return Err(());}
        let uid=uid.parse::<u64>().map_err(|_|())?;
        if (500..u32::MAX as u64).contains(&uid) {result.insert(uid as u32);}
        if result.len()>MAX_GUI_DOMAINS {return Err(());}
    }
    if !seen || !closed || inside || text.lines().rev().find(|l|!l.trim().is_empty()).map(str::trim)!=Some("}") {
        return Err(());
    }
    Ok(result)
}
fn exact_header(raw:&[u8],target:&str)->bool {
    let Ok(text)=std::str::from_utf8(raw) else {return false};
    text.lines().next().map(str::trim)==Some(format!("{target} = {{").as_str())
        && text.lines().rev().find(|line|!line.trim().is_empty()).map(str::trim)==Some("}")
}
fn classify(query:&LaunchQuery,output:&NativeOutput)->JobObservation {
    if output.contract!=Some(NativeContract::MacOs26_6_2) {return JobObservation::UnknownPlatform;}
    if output.code==Some(0) && output.stderr.is_empty() && exact_header(&output.stdout,&query.target()) {
        return JobObservation::ObservedLoaded;
    }
    if !output.stdout.is_empty() {return JobObservation::UnknownResponse;}
    let Some(label)=&query.label else {return JobObservation::UnknownResponse};
    let domain=if query.domain=="system" {"system".to_owned()}
        else {format!("user gui: {}",query.domain.strip_prefix("gui/").unwrap_or("INVALID"))};
    if output.code==Some(113) && output.stderr==format!("Bad request.\nCould not find service \"{label}\" in domain for {domain}\n").as_bytes() {
        return JobObservation::ObservedServiceAbsent;
    }
    if query.domain.starts_with("gui/") && output.code==Some(112)
        && output.stderr==format!("Bad request.\nCould not find domain for {domain}\n").as_bytes() {
        return JobObservation::ObservedGuiDomainAbsent;
    }
    JobObservation::UnknownResponse
}
fn failure(error:CommandFailure)->JobObservation {match error {
    CommandFailure::Timeout=>JobObservation::UnknownTimeout,
    CommandFailure::OutputLimit=>JobObservation::UnknownOutputLimit,
    CommandFailure::Unavailable|CommandFailure::Io=>JobObservation::UnknownUnavailable,
    CommandFailure::OwnershipUnknown=>JobObservation::UnknownUnavailable,
}}
fn run(runner:&mut dyn ActivityRunner,query:&LaunchQuery,until:Instant)->Result<NativeOutput,CommandFailure> {
    if !query.allowed() {return Err(CommandFailure::Unavailable);}
    if Instant::now()>=until {return Err(CommandFailure::Timeout);}
    let deadline=until.min(Instant::now()+COMMAND_LIMIT);
    let output=runner.print(query,deadline)?;
    if Instant::now()>deadline {return Err(CommandFailure::Timeout);}
    if output.stdout.len().checked_add(output.stderr.len()).is_none_or(|n|n>MAX_OUTPUT) {
        return Err(CommandFailure::OutputLimit);
    }
    Ok(output)
}
fn observed_run(runner:&mut dyn ActivityRunner,query:&LaunchQuery,until:Instant)
    ->EnclaveResult<Result<NativeOutput,CommandFailure>> {
    let result=run(runner,query,until);
    if let Err(CommandFailure::OwnershipUnknown)=&result {
        // Stop spawning observers after uncertain owned-child cleanup; this is
        // not an observation of target inactivity and cannot yield a receipt.
        fail!(EIO,"UNKNOWN_ACTIVITY_OBSERVER_OWNERSHIP");
    }
    Ok(result)
}

/// A bounded public launchd-domain snapshot, never proof of process inactivity.
/// The caller owns descriptor/exclusion checks across observation and use.
/// Unknown inventory refuses rather than becoming an empty candidate set.
pub(crate) fn observe_live_gui_candidates(runner:&mut dyn ActivityRunner,until:Instant)
    ->EnclaveResult<BTreeSet<u32>> {
    if let Ok(output)=observed_run(runner,&LaunchQuery::system(),until)? {
        if output.contract==Some(NativeContract::MacOs26_6_2)
            && output.code==Some(0) && output.stderr.is_empty() {
            if let Ok(candidates)=gui_candidates(&output.stdout) {return Ok(candidates);}
        }
    }
    fail!(EIO,"UNKNOWN_ACTIVITY_LIVE_GUI_INVENTORY");
}

/// Closed read-only job observation. This exposes neither raw native output nor
/// parser authority; invalid domain/label grammar never reaches the runner.
pub(crate) fn observe_fixed_job(runner:&mut dyn ActivityRunner,domain:&str,label:&str,until:Instant)
    ->EnclaveResult<JobObservation> {
    let query=LaunchQuery::job(domain.to_owned(),label.to_owned());
    Ok(match observed_run(runner,&query,until)? {
        Ok(output)=>classify(&query,&output),Err(error)=>failure(error),
    })
}

/// No boolean returned by this function can approve PublicPayloadAuthority.
pub(crate) fn observe_selected_target(checked:&CheckedDeploymentTarget,
    maintenance:&mut dyn MaintenanceExclusion,runner:&mut dyn ActivityRunner)->EnclaveResult<TargetActivityObservation> {
    observe_rebound(checked.target(),checked.descriptor_sha256(),maintenance,runner,
        &mut ||checked.read_artifact_inventory().map(|_|()))
}
fn observe_rebound(target:&DeploymentTarget,descriptor_sha256:&str,maintenance:&mut dyn MaintenanceExclusion,
    runner:&mut dyn ActivityRunner,rebind:&mut impl FnMut()->EnclaveResult<()>)->EnclaveResult<TargetActivityObservation> {
    maintenance.assert_held()?;
    rebind()?;
    let report=observe(target,descriptor_sha256,maintenance,runner)?;
    rebind()?;
    maintenance.assert_held()?;
    Ok(report)
}
fn observe(target:&DeploymentTarget,descriptor_sha256:&str,
    maintenance:&mut dyn MaintenanceExclusion,runner:&mut dyn ActivityRunner)->EnclaveResult<TargetActivityObservation> {
    target.validate()?;
    if descriptor_sha256.len()!=64 || !descriptor_sha256.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        fail!(EINVAL,"ACTIVITY_CHECKED_DESCRIPTOR_REQUIRED");
    }
    maintenance.assert_held()?;
    let until=Instant::now()+OBSERVATION_LIMIT;
    let inventory_query=LaunchQuery::system();
    let initial=observed_run(runner,&inventory_query,until)?.ok().and_then(|out|
        if out.contract==Some(NativeContract::MacOs26_6_2) && out.code==Some(0) && out.stderr.is_empty() {
            gui_candidates(&out.stdout).ok()
        } else {None});
    let mut report=TargetActivityObservation {target_id:target.target_id.clone(),descriptor_sha256:descriptor_sha256.into(),
        gui_candidate_uids:initial.as_ref().map(|u|u.iter().copied().collect()).unwrap_or_default(),jobs:Vec::new(),
        domain_inventory_status:if initial.is_some(){"OBSERVED_LIVE_DOMAIN_CANDIDATE_SNAPSHOT"}else{"UNKNOWN_LIVE_DOMAIN_INVENTORY"},
        selected_jobs_status:"UNKNOWN_INCOMPLETE_JOB_OBSERVATIONS",process_instance_status:"UNKNOWN_UNMANAGED_PROCESS_INSTANCES_SHARED_UID_CODE_IS_NOT_INSTANCE_AUTHORITY",
        inactivity_proven:false,installation_supported:false,qualified:false};
    let mut queries=Vec::new();
    for suffix in SYSTEM_SUFFIXES.iter().copied().chain((target.profile==Profile::L3).then_some("apfs-broker")) {
        queries.push(LaunchQuery::job("system".into(),format!("{}.{suffix}",target.layout.launchd_namespace)));
    }
    if let Some(uids)=&initial {for uid in uids {for suffix in AGENT_SUFFIXES {
        queries.push(LaunchQuery::job(format!("gui/{uid}"),format!("{}.{suffix}",target.layout.launchd_namespace)));
    }}}
    for query in queries {
        maintenance.assert_held()?;
        let status=match observed_run(runner,&query,until)? {Ok(output)=>classify(&query,&output),Err(error)=>failure(error)};
        report.jobs.push(JobRecord {target:query.target(),status});
    }
    maintenance.assert_held()?;
    let final_inventory=observed_run(runner,&inventory_query,until)?.ok().and_then(|out|
        if out.contract==Some(NativeContract::MacOs26_6_2) && out.code==Some(0) && out.stderr.is_empty() {
            gui_candidates(&out.stdout).ok()
        } else {None});
    if initial.is_none() || final_inventory.is_none() {report.domain_inventory_status="UNKNOWN_LIVE_DOMAIN_INVENTORY";}
    else if initial!=final_inventory {report.domain_inventory_status="UNKNOWN_LIVE_DOMAIN_INVENTORY_CHANGED";}
    for uid in &report.gui_candidate_uids {
        let domain=format!("gui/{uid}/");
        let states=report.jobs.iter().filter(|j|j.target.starts_with(&domain)).map(|j|&j.status).collect::<Vec<_>>();
        if states.contains(&&JobObservation::ObservedGuiDomainAbsent)
            && states.iter().any(|s|**s==JobObservation::ObservedLoaded || **s==JobObservation::ObservedServiceAbsent) {
            report.domain_inventory_status="UNKNOWN_GUI_DOMAIN_CHANGED_DURING_OBSERVATION";
        }
    }
    report.selected_jobs_status=if report.jobs.iter().any(|j|j.status==JobObservation::ObservedLoaded) {
        "OBSERVED_SELECTED_JOB_LOADED"
    } else if report.domain_inventory_status=="OBSERVED_LIVE_DOMAIN_CANDIDATE_SNAPSHOT"
        && report.jobs.iter().all(|j|matches!(j.status,JobObservation::ObservedServiceAbsent|JobObservation::ObservedGuiDomainAbsent)) {
        "OBSERVED_SELECTED_REGISTRATIONS_ABSENT_PROCESS_PROOF_UNKNOWN"
    } else {"UNKNOWN_INCOMPLETE_JOB_OBSERVATIONS"};
    maintenance.assert_held()?;
    Ok(report)
}

#[cfg(test)]
#[path="target_activity_tests.rs"]
mod tests;
