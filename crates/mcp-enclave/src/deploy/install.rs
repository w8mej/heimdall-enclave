//! System installation and launchd bootstrap orchestration (FS-706 §2, D-R5, D-R6).

use super::scripts::{resolve_dist, run_script, DeployCtx, Script};
use super::{HostMaintenanceGuard,MaintenanceExclusion};
use crate::syscmd::{self, Tool};
use enclave_core::error::{EnclaveError,EnclaveResult};
use serde_json::json;

pub(super) type DeployOutcome=(i32,String,serde_json::Value);
pub(super) type MaintenanceCheck<'a>=dyn FnMut()->EnclaveResult<()>+'a;

fn maintenance_failure(stage:&str,phase:&str,error:EnclaveError,original:Option<DeployOutcome>)->DeployOutcome {
    let returned_ok=phase=="after" && original.as_ref().is_none_or(|(code,_,_)|*code==0);
    (20,format!("Deployment maintenance exclusion refused at {stage}: {}",error.reason),
        json!({"error":"DEPLOYMENT_MAINTENANCE_FAILED","stage":stage,"boundary_phase":phase,
            "operation_returned_ok":returned_ok,
            "maintenance_error":{"errno":error.errno,"reason":error.reason},
            "operation_outcome":original.map(|(code,summary,details)|json!({"exit_code":code,"summary":summary,"details":details})),
            "rollback_performed":false,"scope":"COOPERATING_RUST_DEPLOY_WRAPPERS_ONLY",
            "inactivity_proven":false,"installation_qualified":false}))
}

/// Bracket one synchronous boundary, including failed checks/child outcomes.
/// The operation's original refusal remains visible if the postcheck fails.
pub(super) fn maintenance_step<T>(check:&mut MaintenanceCheck<'_>,stage:&str,
    operation:impl FnOnce()->Result<T,DeployOutcome>)->Result<T,DeployOutcome> {
    check().map_err(|error|maintenance_failure(stage,"before",error,None))?;
    let result=operation();
    match check() {
        Ok(())=>result,
        Err(error)=>Err(maintenance_failure(stage,"after",error,result.err())),
    }
}
fn maintenance_session(check:&mut MaintenanceCheck<'_>,
    operation:impl FnOnce(&mut MaintenanceCheck<'_>)->DeployOutcome)->DeployOutcome {
    let result=match check() {
        Ok(())=>operation(check),
        Err(error)=>maintenance_failure("initial","before",error,None),
    };
    // Always attempt the final check, including errors before an embedded child.
    match check() {Ok(())=>result,Err(error)=>maintenance_failure("final","after",error,Some(result))}
}
/// Exactly one real guard per actual wrapper invocation. Embedded scripts run
/// synchronously while its owner remains alive. There is no nested acquisition,
/// transferred FD, child supervision/crash guarantee or whole-fleet exclusion.
pub(super) fn with_native_maintenance(
    operation:impl FnOnce(&mut MaintenanceCheck<'_>)->DeployOutcome)->DeployOutcome {
    let mut guard=match HostMaintenanceGuard::acquire() {
        Ok(guard)=>guard,Err(error)=>return maintenance_failure("acquire","before",error,None),
    };
    maintenance_session(&mut ||guard.assert_held(),operation)
}

/// Profile floor order: L1 < L2 < L3.
fn profile_level(p: &str) -> Option<u32> {
    match p.to_ascii_uppercase().as_str() {
        "L1" => Some(1),
        "L2" => Some(2),
        "L3" => Some(3),
        _ => None,
    }
}

/// Enforce profile floor compatibility per D-R5.
pub fn check_profile_floor(requested_profile: &str) -> Result<(), (i32, String)> {
    let req_lvl = match profile_level(requested_profile) {
        Some(l) => l,
        None => return Err((64, format!("Unknown profile tier: {requested_profile}"))),
    };

    // Check signed host config if installed
    for path in [
        "/opt/enterprise/enclave/cas/enclave-host-config.json",
        "/var/db/enclave/cas/tuf/repo/enclave-host-config.json",
    ] {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(floor_str) = val.get("profile_floor").and_then(|v| v.as_str()) {
                    if let Some(floor_lvl) = profile_level(floor_str) {
                        if req_lvl < floor_lvl {
                            return Err((
                                20,
                                format!(
                                    "PROFILE_MISMATCH: requested profile {requested_profile} is below signed host config floor {floor_str}"
                                ),
                            ));
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Enforce Mode B (Team ID) code signing requirement for Profile L3 per D-R6.
pub fn check_l3_signing_mode(requested_profile: &str) -> Result<(), (i32, String)> {
    if requested_profile.eq_ignore_ascii_case("L3") {
        let is_team_id_mode =
            enclave_core::codesign::signing_mode() == enclave_core::codesign::SigningMode::TeamId;
        let adhoc_dev =
            cfg!(debug_assertions) && std::env::var("MCPMAC_L3_ADHOC_DEV").as_deref() == Ok("1");

        if !is_team_id_mode && !adhoc_dev {
            return Err((
                20,
                "L3_REQUIRES_TEAM_ID: Profile L3 strictly mandates Mode B (Apple Developer Team ID). Bare-metal trust chain requires Team ID. LocalPins / ad-hoc builds cannot run L3 in production.".into(),
            ));
        }
    }
    Ok(())
}

/// Execute system installation on the real host.
///
/// `dist`: see [`crate::deploy::DeployArgs::dist`].
pub fn run_install(
    profile: &str,
    dry_run: bool,
    dist: Option<&str>,
) -> (i32, String, serde_json::Value) {
    if dry_run {return install_with_checks(profile,true,dist,&DeployCtx::system(),&mut ||Ok(()));}
    with_native_maintenance(|check| {
        let preflight=maintenance_step(check,"install_preflight",|| {
        let preflight = crate::deploy::preflight::evaluate_preflight(profile, None);
        if !preflight.passed {
            crate::custody_notice::show_for_profile(profile);
            return Err((
                10,
                preflight.message,
                json!({"error": "PREFLIGHT_REQUIRED", "preflight": preflight.preflight}),
            ));
        }
        Ok(())
        });
        if let Err(failure)=preflight {return failure;}
        install_with_checks(profile,false,dist,&DeployCtx::system(),check)
    })
}

fn install_plan(profile: &str, dist: Option<&str>) -> (i32, String, serde_json::Value) {
    let mode = if dist.is_some() { "dist" } else { "payload" };
    (
        0,
        format!("[dry-run] Planned installation for Profile {profile} ({mode} mode): accounts 8701-8720, /opt/enterprise/enclave hierarchy, launchd plists, and pf anchors."),
        json!({
            "dry_run": true,
            "profile": profile,
            "mode": mode,
            "dist": dist,
            "script": dist.map(|_| Script::Install.argv0()),
            "actions": [
                "provision accounts (8701-8705 primary, 8711-8720 client)",
                "deploy binaries to /opt/enterprise/enclave/bin",
                "install EnclaveCustody.app to /Library/Application Support/EnterpriseEnclave",
                "render and deploy Seatbelt sandbox profiles to /opt/enterprise/enclave/sandbox",
                "install and bootstrap system LaunchDaemons in /Library/LaunchDaemons",
                "install com.enterprise.enclave.intent LaunchAgent in /Library/LaunchAgents",
                "install and load Darwin pf anchors com.enterprise.llm.isolation and com.enterprise.cas.swarm"
            ]
        }),
    )
}

fn install_fail(code: &str, msg: String) -> (i32, String, serde_json::Value) {
    (20, msg.clone(), json!({ "error": code, "details": msg }))
}

/// Run the embedded install.sh against a resolved dist.
fn run_dist_install(
    ctx: &DeployCtx<'_>,
    dist: &str,
    profile: &str,
    check:&mut MaintenanceCheck<'_>,
) -> Result<String, (i32, String, serde_json::Value)> {
    let dist_abs = maintenance_step(check,"install_dist_resolution",||
        resolve_dist(dist).map_err(|m| install_fail("INSTALL_DIST_MISSING", m)))?;
    let dist_str = dist_abs.display().to_string();
    maintenance_step(check,"embedded_install_child",|| {
    match run_script(ctx, Script::Install, &[], &[("MCPMAC_DIST", &dist_str), ("MCPMAC_PROFILE", profile)]) {
        Ok(s) if s.success() => Ok(dist_str),
        Ok(s) => Err((
            20,
            format!("install.sh failed with exit status: {s}"),
            json!({ "error": "INSTALL_SCRIPT_FAILED", "exit_status": s.to_string() }),
        )),
        Err(e) => Err(install_fail(
            "SPAWN_ERROR",
            format!("Failed to execute install.sh: {e}"),
        )),
    }
    })
}

/// [`run_install`] against an explicit host context.
///
/// DEFECT-F-90: the install script is the copy embedded in this binary
/// ([`Script::Install`]), never `packaging/macos/install.sh` in the current
/// directory; the mode is chosen by `--dist`, not by where the command runs.
/// This compatibility API is a trusted in-process dependency-injection seam.
/// It does not acquire host exclusion. Actual CLI operations use `run_install`,
/// whose real guard covers native preflight and this engine without nesting.
pub fn run_install_with(
    profile: &str,
    dry_run: bool,
    dist: Option<&str>,
    ctx: &DeployCtx<'_>,
) -> (i32, String, serde_json::Value) {
    install_with_checks(profile,dry_run,dist,ctx,&mut ||Ok(()))
}
fn install_with_checks(profile:&str,dry_run:bool,dist:Option<&str>,ctx:&DeployCtx<'_>,
    check:&mut MaintenanceCheck<'_>)->DeployOutcome {
    let policy=maintenance_step(check,"install_policy_checks",|| {
    crate::custody_notice::show_for_profile(profile);
    if let Err((code, msg)) = check_profile_floor(profile) {
        return Err((code, msg.clone(), json!({ "error": msg })));
    }
    if let Err((code, msg)) = check_l3_signing_mode(profile) {
        return Err((code, msg.clone(), json!({ "error": msg })));
    }
    Ok(())
    });
    if let Err(failure)=policy {return failure;}
    if dry_run {
        return install_plan(profile, dist);
    }
    if !ctx.is_root {
        return (
            20,
            "install requires root privileges; re-run with sudo".into(),
            json!({ "error": "ROOT_REQUIRED" }),
        );
    }
    // Every entry point performs the same verified distribution installation.
    // Packages preserve the entire distribution at this root-installed path.
    let input = dist.unwrap_or("/opt/enterprise/enclave/dist");
    let dist_used = match run_dist_install(ctx, input, profile, check) {
        Ok(d) => d,
        Err(fail) => return fail,
    };
    // The embedded installer activates PF before starting any new daemon and
    // propagates those failures itself. A second activation here could fail
    // after its successful bootstrap and leave an ambiguous live deployment.
    let mode = if dist.is_some() { "dist" } else { "payload" };
    (
        0,
        format!("Enclave installation complete for Profile {profile} ({mode} mode)"),
        json!({ "status": "ok", "profile": profile, "mode": mode, "dist": dist_used }),
    )
}

/// Target for console UID resolution (Prompt 5, D2).
pub trait ConsoleUidProvider {
    /// Return the active console UID, if any.
    fn console_uid(&self) -> Option<u32>;
}

/// System-based console UID provider reading /dev/console.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemConsoleUidProvider;

impl ConsoleUidProvider for SystemConsoleUidProvider {
    fn console_uid(&self) -> Option<u32> {
        crate::deploy::preflight::get_console_uid()
    }
}

/// Intent agent bootstrap action result (FS-706 §4.1, Design D2).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IntentBootstrapOutcome {
    /// Active console UID, if detected.
    pub console_uid: Option<u32>,
    /// Whether bootstrap into an active GUI session was executed.
    pub bootstrapped: bool,
    /// Whether bootstrap was deferred because no non-root console user is logged in.
    pub deferred: bool,
    /// Diagnostic summary.
    pub message: String,
}

/// Evaluate console user and conditionally bootstrap intent agent into `gui/$CONSOLE_UID`.
pub fn evaluate_intent_bootstrap(provider: &impl ConsoleUidProvider) -> IntentBootstrapOutcome {
    let uid = provider.console_uid();
    match uid {
        Some(0) => IntentBootstrapOutcome {
            console_uid: Some(0),
            bootstrapped: false,
            deferred: true,
            message: "Console user is root (loginwindow active); intent agent deferred to user login via RunAtLoad".into(),
        },
        None => IntentBootstrapOutcome {
            console_uid: None,
            bootstrapped: false,
            deferred: true,
            message: "No active Aqua console session detected; intent agent deferred to user login via RunAtLoad".into(),
        },
        Some(u) => {
            #[cfg(target_os = "macos")]
            {
                // Attempt bootstrap into gui/$CONSOLE_UID
                let _ = syscmd::command(Tool::Launchctl)
                    .args(["bootout", &format!("gui/{u}/com.enterprise.enclave.intent")])
                    .output();
                let status = syscmd::command(Tool::Launchctl)
                    .args([
                        "bootstrap",
                        &format!("gui/{u}"),
                        "/Library/LaunchAgents/com.enterprise.enclave.intent.plist",
                    ])
                    .status();
                let bootstrapped = status.map(|s| s.success()).unwrap_or(false);
                IntentBootstrapOutcome {
                    console_uid: Some(u),
                    bootstrapped,
                    deferred: false,
                    message: format!("Intent agent bootstrapped into Aqua session gui/{u}"),
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                IntentBootstrapOutcome {
                    console_uid: Some(u),
                    bootstrapped: true,
                    deferred: false,
                    message: format!("Mock intent agent bootstrapped into gui/{u}"),
                }
            }
        }
    }
}

#[cfg(test)]
#[path="installer_maintenance_tests.rs"]
mod maintenance_tests;
