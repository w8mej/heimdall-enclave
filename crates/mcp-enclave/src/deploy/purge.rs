//! Decommissioning, teardown, and state purge orchestration (FS-706 §1.2, D-R1).

use super::scripts::{run_script, DeployCtx, Script};
use super::install::{maintenance_step,with_native_maintenance,DeployOutcome,MaintenanceCheck};
use serde_json::json;

/// Execute enclave decommissioning and purge on the real host.
pub fn run_purge(
    profile: &str,
    yes: bool,
    purge_state: bool,
    remove_accounts: bool,
) -> (i32, String, serde_json::Value) {
    // Missing explicit destructive confirmation must not even create the
    // persistent host maintenance name. The injected engine preserves refusal.
    if !yes {return run_purge_with(profile,false,purge_state,remove_accounts,&DeployCtx::system());}
    with_native_maintenance(|check|
        purge_with_checks(profile,true,purge_state,remove_accounts,&DeployCtx::system(),check))
}

/// [`run_purge`] against an explicit host context.
///
/// DEFECT-F-90: always runs the uninstall script embedded in this binary
/// ([`Script::Uninstall`]); `packaging/macos/uninstall.sh` in the current
/// directory is never read, and the outcome no longer depends on where the
/// command is run from.
/// This compatibility dependency-injection seam does not acquire exclusion;
/// actual CLI callers use `run_purge`, which owns one real native guard.
pub fn run_purge_with(
    profile: &str,
    yes: bool,
    purge_state: bool,
    remove_accounts: bool,
    ctx: &DeployCtx<'_>,
) -> (i32, String, serde_json::Value) {
    purge_with_checks(profile,yes,purge_state,remove_accounts,ctx,&mut ||Ok(()))
}
fn purge_with_checks(_profile:&str,yes:bool,purge_state:bool,remove_accounts:bool,
    ctx:&DeployCtx<'_>,check:&mut MaintenanceCheck<'_>)->DeployOutcome {
    if !yes {
        return (
            60,
            "PURGE_REFUSED: destructive purge operation requires explicit --yes confirmation"
                .into(),
            json!({ "error": "CONFIRMATION_REQUIRED", "exit_code": 60 }),
        );
    }
    if !ctx.is_root {
        return (
            20,
            "purge requires root privileges (run with sudo)".into(),
            json!({ "error": "ROOT_REQUIRED" }),
        );
    }
    let flags: Vec<&str> = [
        purge_state.then_some("--purge-state"),
        remove_accounts.then_some("--remove-accounts"),
    ]
    .into_iter()
    .flatten()
    .collect();
    let result=maintenance_step(check,"embedded_uninstall_child",|| {
    match run_script(ctx, Script::Uninstall, &flags, &[]) {
        Ok(s) if s.success() => Ok((
            0,
            "Enclave fleet deployment, daemons, and state successfully purged".into(),
            json!({ "status": "ok", "purge_state": purge_state, "remove_accounts": remove_accounts }),
        )),
        Ok(s) => Err((
            20,
            format!("uninstall.sh failed with exit code: {s}"),
            json!({ "error": "UNINSTALL_SCRIPT_FAILED", "exit_status": s.to_string() }),
        )),
        Err(e) => Err((
            20,
            format!("Failed to execute uninstall.sh: {e}"),
            json!({ "error": "SPAWN_ERROR", "details": e.to_string() }),
        )),
    }
    });
    match result {Ok(success)=>success,Err(failure)=>failure}
}

#[cfg(test)]
#[path="purge_maintenance_tests.rs"]
mod maintenance_tests;
