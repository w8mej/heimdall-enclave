//! Enterprise MDM fleet deployment and orchestration framework (FS-706, D-R1).

pub mod health;
pub mod hydrate;
pub mod install;
pub mod preflight;
pub mod purge;
pub mod scripts;
pub mod security_probe;
mod target_accounts;
mod target_activity;
mod target_candidate;
mod target_birth;
mod target_birth_inputs;
mod target_maintenance;
mod target_native_code;
mod target_payload;
mod target_release;
mod target_release_json;
pub mod target_plan;
mod target_runtime;
mod target_runtime_trust;
mod target_runtime_preflight;
mod target_upgrade;
mod target_upgrade_inhibition;
mod target_startup_lease;
pub mod verify;

pub(crate) use target_activity::{observe_fixed_job, observe_live_gui_candidates, run_owned_command,
    CommandFailure, JobObservation, MaintenanceExclusion, NativeLaunchctlRunner, NativeOutput};
pub(crate) use target_maintenance::HostMaintenanceGuard;
pub use target_birth::{DedicatedBirthSessionArgs,DedicatedBirthSessionExit,DedicatedBirthRenderArgs,
    run_dedicated_birth_session,render_dedicated_birth_public_data};
pub(crate) use target_native_code::{verify_static_code, NativeCodeShape, NativeEntitlementPolicy, ProtectedNativeFile};

use clap::Subcommand;
use serde::{Deserialize, Serialize};

pub use install::{
    evaluate_intent_bootstrap, ConsoleUidProvider, IntentBootstrapOutcome, SystemConsoleUidProvider,
};
pub use preflight::{classify_hw_tier, evaluate_preflight, DarwinPreflight};

/// Stable exit codes per D-R1.
pub const EXIT_SUCCESS: i32 = 0;
/// Pre-flight hardware or security gates failed.
pub const EXIT_PREFLIGHT_FAILED: i32 = 10;
/// System installation or account provisioning failed.
pub const EXIT_INSTALL_FAILED: i32 = 20;
/// Post-install socket or verification probes failed.
pub const EXIT_VERIFY_FAILED: i32 = 30;
/// Asynchronous hydration job dispatched (< 5s APNs detachment).
pub const EXIT_HYDRATION_PENDING: i32 = 40;
/// Model weight transfer or Merkle verification failed.
pub const EXIT_HYDRATION_FAILED: i32 = 41;
/// Fleet telemetry indicates stopped daemons, memory breach, or exposed pf.
pub const EXIT_UNHEALTHY: i32 = 50;
/// Destructive purge rejected due to missing confirmation.
pub const EXIT_PURGE_REFUSED: i32 = 60;
/// Invalid CLI usage, unknown profile, or bad arguments.
pub const EXIT_USAGE_ERROR: i32 = 64;

/// Deployment verbs for the operator CLI.
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DeployVerb {
    /// Evaluate host hardware, memory tier, disk space, and Darwin security baseline.
    Preflight,
    /// Idempotently provision accounts, file hierarchy, Seatbelt sandboxes, and launchd plists.
    Install,
    /// Execute full post-install verification and socket health probes.
    Verify,
    /// Initiate model weight synchronization via UID 702 content-addressed transport.
    Hydrate,
    /// Detached background hydration worker consuming /var/run/enclave/jobs.
    HydrateWorker,
    /// Emit real-time fleet health, memory phys_footprint, and pf anchor telemetry.
    Healthcheck,
    /// Tear down daemons, unmount volumes, and optionally wipe state and accounts.
    Purge,
}

/// Optional arguments for deployment operations.
#[derive(Debug, Clone, Default)]
pub struct DeployArgs {
    /// Model target slug for hydration.
    pub target: Option<String>,
    /// Pre-staged DMG image path for Profile L3.
    pub dmg: Option<String>,
    /// Asynchronous execution mode.
    pub r#async: bool,
    /// Synchronous execution mode.
    pub sync: bool,
    /// Dry-run simulation mode without mutating state.
    pub dry_run: bool,
    /// Bypass confirmation prompts for destructive actions.
    pub yes: bool,
    /// Remove user accounts during purge.
    pub remove_accounts: bool,
    /// Wipe all persistent state directories during purge.
    pub purge_state: bool,
    /// Override jobs directory for testing or custom layouts.
    pub jobs_dir: Option<String>,
    /// Override CAS directory for testing or custom layouts.
    pub cas_dir: Option<String>,
    /// Build distribution for `install` (DEFECT-F-90). With it, `install`
    /// runs the embedded install.sh against this dist; without it, `install`
    /// only installs and loads the pf anchors over an already-laid payload
    /// (the `.pkg` flow). The current directory is never consulted.
    pub dist: Option<String>,
}

/// Deployment execution result conforming to `schemas/deploy-result.schema.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployResult {
    /// Verb executed.
    pub verb: String,
    /// Profile tier (L1, L2, L3).
    pub profile: String,
    /// Deterministic exit code.
    pub exit_code: i32,
    /// Status category ("ok", "pending", "failed", "unhealthy", "refused", "usage_error").
    pub status: String,
    /// Human-readable summary message.
    pub summary: String,
    /// Optional structured diagnostics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    /// Unix timestamp in seconds.
    pub timestamp: u64,
    /// Pre-flight platform report.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub darwin_preflight: Option<DarwinPreflight>,
}

/// Execute a deployment command and return structured result plus exit code.
pub fn execute(verb: DeployVerb, profile_str: &str, args: &DeployArgs) -> (DeployResult, i32) {
    let profile = profile_str.to_ascii_uppercase();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Validate profile tier
    if !matches!(profile.as_str(), "L1" | "L2" | "L3") {
        let res = DeployResult {
            verb: format!("{verb:?}").to_lowercase(),
            profile: profile.clone(),
            exit_code: EXIT_USAGE_ERROR,
            status: "usage_error".into(),
            summary: format!("Unknown profile tier '{profile}'; must be L1, L2, or L3"),
            details: None,
            timestamp,
            darwin_preflight: None,
        };
        return (res, EXIT_USAGE_ERROR);
    }

    if matches!(&verb, DeployVerb::Preflight) {
        crate::custody_notice::show_for_profile(&profile);
    }
    match verb {
        DeployVerb::Preflight => {
            let pf = preflight::evaluate_preflight(&profile, None);
            let exit_code = if pf.passed {
                EXIT_SUCCESS
            } else {
                EXIT_PREFLIGHT_FAILED
            };
            let status = if pf.passed { "ok" } else { "failed" };
            let res = DeployResult {
                verb: "preflight".into(),
                profile,
                exit_code,
                status: status.into(),
                summary: pf.message,
                details: None,
                timestamp,
                darwin_preflight: Some(pf.preflight),
            };
            (res, exit_code)
        }
        DeployVerb::Install => {
            let (code, msg, details) =
                install::run_install(&profile, args.dry_run, args.dist.as_deref());
            let status = if code == 0 { "ok" } else { "failed" };
            let res = DeployResult {
                verb: "install".into(),
                profile,
                exit_code: code,
                status: status.into(),
                summary: msg,
                details: Some(details),
                timestamp,
                darwin_preflight: None,
            };
            (res, code)
        }
        DeployVerb::Verify => {
            let (code, msg, details) = verify::run_verify(&profile);
            let status = details["status"].as_str().unwrap_or("failed").to_owned();
            let res = DeployResult {
                verb: "verify".into(),
                profile,
                exit_code: code,
                status: status.into(),
                summary: msg,
                details: Some(details),
                timestamp,
                darwin_preflight: None,
            };
            (res, code)
        }
        DeployVerb::Hydrate => {
            let is_async = args.r#async || !args.sync;
            let (code, msg, details) = hydrate::run_hydrate(
                &profile,
                args.target.as_deref(),
                args.dmg.as_deref(),
                is_async,
                args.jobs_dir.as_deref().map(std::path::Path::new),
                args.cas_dir.as_deref().map(std::path::Path::new),
            );
            let status = if code == EXIT_SUCCESS {
                "ok"
            } else if code == EXIT_HYDRATION_PENDING {
                "pending"
            } else {
                "failed"
            };
            let res = DeployResult {
                verb: "hydrate".into(),
                profile,
                exit_code: code,
                status: status.into(),
                summary: msg,
                details: Some(details),
                timestamp,
                darwin_preflight: None,
            };
            (res, code)
        }
        DeployVerb::HydrateWorker => {
            let (code, msg, details) = hydrate::run_hydrate_worker(
                args.jobs_dir.as_deref().map(std::path::Path::new),
                args.cas_dir.as_deref().map(std::path::Path::new),
            );
            let status = if code == EXIT_SUCCESS {
                "ok"
            } else if code == EXIT_HYDRATION_PENDING {
                "pending"
            } else {
                "failed"
            };
            let res = DeployResult {
                verb: "hydrate-worker".into(),
                profile,
                exit_code: code,
                status: status.into(),
                summary: msg,
                details: Some(details),
                timestamp,
                darwin_preflight: None,
            };
            (res, code)
        }
        DeployVerb::Healthcheck => {
            let (code, msg, details) = health::run_healthcheck(&profile);
            let status = if code == EXIT_SUCCESS {
                "ok"
            } else {
                "unhealthy"
            };
            let res = DeployResult {
                verb: "healthcheck".into(),
                profile,
                exit_code: code,
                status: status.into(),
                summary: msg,
                details: Some(details),
                timestamp,
                darwin_preflight: None,
            };
            (res, code)
        }
        DeployVerb::Purge => {
            let (code, msg, details) =
                purge::run_purge(&profile, args.yes, args.purge_state, args.remove_accounts);
            let status = if code == EXIT_SUCCESS {
                "ok"
            } else if code == EXIT_PURGE_REFUSED {
                "refused"
            } else {
                "failed"
            };
            let res = DeployResult {
                verb: "purge".into(),
                profile,
                exit_code: code,
                status: status.into(),
                summary: msg,
                details: Some(details),
                timestamp,
                darwin_preflight: None,
            };
            (res, code)
        }
    }
}
