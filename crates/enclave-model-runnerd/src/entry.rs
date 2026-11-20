//! Daemon entry point (UID 701 `_llmagent`): argument handling, peer wiring and the
//! service loop, shared by the dedicated binary and `mcp-enclave __daemon`.

use std::path::PathBuf;
use std::sync::Mutex;

use crate::arena::WeightBytes;
use crate::classes::speculative::ThermalProvider;
#[cfg(not(target_os = "macos"))]
use crate::classes::speculative::{FixedThermal, PowerSource, ThermalState};
use crate::service::{
    ResolvedWeights, RunnerConfig, RunnerRequest, RunnerResponse, RunnerService, WeightSource,
};
use enclave_core::daemon::DaemonId;
use enclave_core::error::EnclaveResult;
use enclave_core::profile::Profile;
use enclave_core::runtime::{run_service, DaemonArgs};
use serde::{Deserialize, Serialize};

/// Wire-compatible subset of the UID 702 API (externally tagged CBOR).
#[derive(Serialize)]
enum CasRequest<'a> {
    Resolve { cas_uri: &'a str },
}

#[derive(Deserialize)]
#[allow(dead_code)]
enum CasResponse {
    Resolved {
        effective_profile: Profile,
        sha256: String,
        fds: usize,
    },
    Fetched(serde_bytes::ByteBuf),
}

/// Upper bound on one artifact resolution by UID 702.
const RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

struct CasWeights {
    args: DaemonArgs,
    lock: Mutex<()>,
}

impl WeightSource for CasWeights {
    fn resolve(&self, cas_uri: &str) -> EnclaveResult<ResolvedWeights> {
        let _g = self
            .lock
            .lock()
            .map_err(|_| enclave_core::err!(EIO, "LOCK"))?;
        // `connect` verifies the server is UID 702 before any byte is sent.
        let mut c = self.args.connect(DaemonId::SwarmSync)?;
        // UID 702 reassembles and re-verifies the whole artifact before it
        // passes the descriptor; GB-sized models outlast the 30 s I/O bound.
        c.set_timeout(Some(RESOLVE_TIMEOUT))?;
        let CasResponse::Resolved { fds, .. } = c.call(&CasRequest::Resolve { cas_uri })? else {
            enclave_core::fail!(EIO, "CAS_NOT_RESOLVED");
        };
        if fds == 0 {
            enclave_core::fail!(EIO, "CAS_NO_FD");
        }
        let got = c.recv_fds(fds.min(8))?;
        let mut it = got.into_iter();
        let primary_fd = it
            .next()
            .ok_or_else(|| enclave_core::err!(EIO, "CAS_NO_FD"))?;
        let primary = WeightBytes::map_fd(&primary_fd)?;
        let mut companions = Vec::new();
        for companion_fd in it {
            companions.push(WeightBytes::map_fd(&companion_fd)?);
        }
        Ok(ResolvedWeights {
            primary,
            companions,
        })
    }

    fn fetch_manifest(&self, model_id: &str) -> EnclaveResult<Vec<u8>> {
        let target = crate::service::model_manifest_target(model_id)?;
        enclave_core::host_config::fetch_tuf_target(
            &self.args.socket_dir,
            &target,
            self.args.dev_same_uid,
        )
    }

    fn fetch_corpus(&self, digest: &str) -> EnclaveResult<Vec<u8>> {
        let bytes = enclave_core::host_config::fetch_tuf_target(
            &self.args.socket_dir,
            enclave_core::host_config::CALIBRATION_CORPUS_TARGET,
            self.args.dev_same_uid,
        )?;
        if blake3::hash(&bytes).to_hex().as_str() != digest {
            enclave_core::fail!(EACCES, "CALIBRATION_CORPUS_DIGEST");
        }
        Ok(bytes)
    }
}

fn thermal() -> Box<dyn ThermalProvider> {
    #[cfg(target_os = "macos")]
    {
        Box::new(crate::classes::speculative::DarwinThermal::new())
    }
    #[cfg(not(target_os = "macos"))]
    {
        // No thermal telemetry off macOS: assume battery + fair (r_max <= 8).
        Box::new(FixedThermal(ThermalState::Fair, PowerSource::Battery))
    }
}

/// Run the daemon until SIGTERM / SIGINT.
pub fn run(args: DaemonArgs) -> EnclaveResult<()> {
    args.bind_deployment_for_daemon(DaemonId::ModelRunner)?;
    // Both binary entry points pass here. Missing production persistence must
    // refuse before loading a model, publishing IPC or accepting a release.
    // Explicit development mode retains the ephemeral fixture configuration.
    if !args.dev_same_uid && args.state_dir.is_none() {
        enclave_core::fail!(EACCES, "RUNNER_STATE_DIR_REQUIRED");
    }
    enclave_core::host_config::require_profile_floor(
        &args.socket_dir, args.profile, args.dev_same_uid,
    )?;
    // Crash-dump lock-down before any model descriptor is accepted.
    enclave_core::resource::harden_process();
    // Production always wires the sandboxed browser actuator. The development
    // fleet runs no browser daemon, so there the actuator is attached only
    // when a browser socket is named explicitly; plans then report
    // `actuated: false` and keep their observation obligation.
    let explicit_browser = args.get("browser-socket").map(PathBuf::from);
    let attach_actuator = !args.dev_same_uid || explicit_browser.is_some();
    let browser_sock = explicit_browser
        .unwrap_or_else(|| PathBuf::from("/var/run/enclave/browser/browser.sock"));
    let cfg = RunnerConfig {
        dev_same_uid: args.dev_same_uid,
        profile: args.profile,
        audit_path: args.audit_path(DaemonId::ModelRunner),
        calib_corpus_blake3: args.get("calib-corpus-blake3").map(str::to_owned),
        thermal: Box::new(thermal),
        actuator: attach_actuator.then(|| -> Box<dyn crate::classes::world::Actuator + Send> {
            Box::new(
                crate::classes::world::CdpSocketActuator::new(browser_sock).with_expected_uid(
                    if args.dev_same_uid {
                        enclave_core::ipc::geteuid()
                    } else {
                        enclave_core::daemon::BROWSER_UID
                    },
                ),
            )
        }),
        state_dir: args.state_dir.clone(),
    };
    let svc = RunnerService::start(
        cfg,
        Box::new(CasWeights {
            args: args.clone(),
            lock: Mutex::new(()),
        }),
    )?;
    // GAP-16: power / sleep / lock / yank wipe hook
    let svc_wipe = std::sync::Arc::downgrade(&svc);
    enclave_core::power::registry().register("701_model_wipe", move |trigger| {
        let Some(svc_wipe) = svc_wipe.upgrade() else { return Ok(()); };
        let op = enclave_core::ipc::PeerCredentials::local(0, 0);
        let trigger = runner_wipe_trigger(trigger);
        match svc_wipe.handle(&op, RunnerRequest::Zeroize(trigger))? {
            RunnerResponse::Wiped(_) => Ok(()),
            _ => enclave_core::fail!(EIO, "WIPE_RESPONSE_INVALID"),
        }
    });
    let _power_mon = enclave_core::power::start_for_profile(
        args.profile, enclave_core::power::darwin::PowerMonitor::start,
    )?;
    let h = svc.clone();
    let admission = args.clone();
    run_service::<RunnerRequest, RunnerResponse, _>(
        DaemonId::ModelRunner,
        &args,
        move |p, r| {
            // Safety cleanup remains available even when trust/config expires.
            if !matches!(&r, RunnerRequest::Zeroize(_) | RunnerRequest::SsmExit { .. } | RunnerRequest::SsmExitOwned { .. }) {
                enclave_core::host_config::require_profile_floor(
                    &admission.socket_dir, admission.profile, admission.dev_same_uid,
                )?;
            }
            h.handle(p, r)
        },
        || {},
    )
}

/// Preserve the power event's cause in the runner's own trigger vocabulary.
pub fn runner_wipe_trigger(t: enclave_core::power::WipeTrigger) -> crate::arena::ZeroizeTrigger {
    use crate::arena::ZeroizeTrigger;
    use enclave_core::power::WipeTrigger;
    match t {
        WipeTrigger::SystemSleep => ZeroizeTrigger::SystemWillSleep,
        WipeTrigger::SessionLocked => ZeroizeTrigger::ScreenLocked,
        WipeTrigger::AuthenticatorYank => ZeroizeTrigger::YubiKeyRemoved,
        WipeTrigger::ThunderboltHotPlugLocked => ZeroizeTrigger::TaintExit,
    }
}
