//! Daemon entry point (UID 703 `_piivault`): argument handling, peer wiring and the
//! service loop, shared by the dedicated binary and `mcp-enclave __daemon`.

use crate::service::{VaultConfig, VaultHardware, VaultRequest, VaultResponse, VaultService};
use enclave_core::daemon::DaemonId;
use enclave_core::error::EnclaveResult;
use enclave_core::runtime::{run_service, run_service_with_startup, DaemonArgs};

/// Run the daemon until SIGTERM / SIGINT.
pub fn run(args: DaemonArgs) -> EnclaveResult<()> {
    if args.get("travel-recovery-mode").is_some() {
        return Err(enclave_core::err!(EACCES,"TRAVEL_INDEPENDENT_ANCHOR_REQUIRED",
            "travel startup requires independently provisioned anchored and audited typed admission"));
    }
    run_inner(args,None)
}

/// Run through already verified independently anchored/audited keyless travel
/// admission. This is an embedding integration point, never a command-line
/// boolean or an RPC. Missing real installed anchor/provider remains refused.
pub fn run_with_travel(args:DaemonArgs,travel:crate::service::ValidatedTravelStartup)->EnclaveResult<()> {
    run_inner(args,Some(travel))
}

fn run_inner(args:DaemonArgs,travel:Option<crate::service::ValidatedTravelStartup>)->EnclaveResult<()> {
    args.bind_deployment_for_daemon(DaemonId::CustodyVault)?;
    let keyless_travel=travel.is_some();
    if keyless_travel&&args.profile!=enclave_core::Profile::L3 {
        return Err(enclave_core::err!(EACCES,"TRAVEL_PERMANENT_L3_REQUIRED"));
    }
    // Public configuration refusal precedes monitors, SEP/HID and sealed state.
    let provisioned = crate::provisioning::CustodyProvisioning::from_daemon_args(
        &args, enclave_crypto::time::now_unix(),
    )?;
    let provisioned = if let Some(target) = enclave_core::deployment::selected() {
        if args.extra.iter().any(|(key, _)| crate::provisioning::LEGACY_AUTHORITY_ARGUMENTS.contains(&key.as_str())) {
            return Err(enclave_core::err!(EACCES, "DEPLOYMENT_MIXED_ARGUMENTS"));
        }
        Some(match provisioned {
            Some(config) => config,
            None => crate::provisioning::CustodyProvisioning::load(
                &target.target().authority_config, args.profile, enclave_crypto::time::now_unix(),
            )?,
        })
    } else { provisioned };
    enclave_core::host_config::require_profile_floor(
        &args.socket_dir, args.profile, args.dev_same_uid,
    )?;
    if let Some(checked) = enclave_core::deployment::selected() {
        // Public scope validation is effect-free. All selected native owners
        // are constructed only inside the already confined initializer below.
        selected_entry_scope(checked.target(), &args, keyless_travel)?;
        return run_service_with_startup::<VaultRequest, VaultResponse, _, _, _>(
            DaemonId::CustodyVault, &args,
            || {
                let session = selected_entry_session(&args, keyless_travel)?
                    .ok_or_else(|| enclave_core::err!(EACCES, "SELECTED_OWNER_ENTRY_SESSION_REQUIRED"))?;
                let owners = initialize_custody(&args, travel, provisioned, Some(session))?
                    .ok_or_else(|| enclave_core::err!(EACCES, "SELECTED_OWNER_ENTRY_NATIVE_SINGLETON_REQUIRED"))?;
                let handler = custody_handler(owners.service.clone(), args.clone());
                Ok((handler, owners))
            }, custody_rss_breach,
        );
    }
    // Preserve ordinary unselected startup, including standalone probes and
    // travel, while sharing service construction and request behavior.
    let Some(owners) = initialize_custody(&args, travel, provisioned, None)? else { return Ok(()); };
    let result = run_service::<VaultRequest, VaultResponse, _>(DaemonId::CustodyVault, &args,
        custody_handler(owners.service.clone(), args.clone()), custody_rss_breach);
    drop(owners); // Ordinary checkpoint stays after serving, as before.
    result
}

// This guard is returned to run_service_with_startup and retained even when
// IPC binding fails. Drop body runs while every original owner remains alive.
struct CustodyStartupOwners {
    service: std::sync::Arc<VaultService>,
    runtime: Option<crate::ctap::selected_owner_runtime::SelectedOwnerRuntime>,
    _monitor: Option<std::sync::Arc<enclave_core::power::darwin::PowerMonitor>>,
    session: Option<std::sync::Arc<enclave_core::power::selected_owner_session::SelectedOwnerSession>>,
    checkpoint_on_drop: bool,
}
impl Drop for CustodyStartupOwners {
    fn drop(&mut self) {
        // Revoke SAME session before checkpointing can block. Every original
        // owner remains held through shutdown and then drops normally.
        if let Some(session) = &self.session { session.revoke(); }
        if self.checkpoint_on_drop {
            // ADR-010/GAP-27: checkpoint before runtime/monitor/session fields
            // drop. Completion may still fail or block.
            let _ = self.service.shutdown();
        }
    }
}
fn custody_handler(service: std::sync::Arc<VaultService>, admission: DaemonArgs)
    -> impl Fn(&enclave_core::ipc::PeerCredentials, VaultRequest) -> EnclaveResult<VaultResponse> + Send + Sync + 'static {
    move |peer, request| {
        if !matches!(&request, VaultRequest::Tamper(_)) {
            enclave_core::host_config::require_profile_floor(
                &admission.socket_dir, admission.profile, admission.dev_same_uid,
            )?;
        }
        service.handle(peer, request)
    }
}
fn custody_rss_breach() {
    // The process exits; secrets remain in zeroize-on-drop/mlock containers,
    // and RLIMIT_CORE = 0 prevents dumps. No new cleanup completion is inferred.
}
fn initialize_custody(args: &DaemonArgs, travel: Option<crate::service::ValidatedTravelStartup>,
    provisioned: Option<crate::provisioning::CustodyProvisioning>,
    selected_session: Option<std::sync::Arc<enclave_core::power::selected_owner_session::SelectedOwnerSession>>,
) -> EnclaveResult<Option<CustodyStartupOwners>> {
    let keyless_travel = travel.is_some();
    if selected_session.is_none() && enclave_core::deployment::selected().is_some() {
        return Err(enclave_core::err!(EACCES, "SELECTED_OWNER_ENTRY_SESSION_REQUIRED"));
    }
    // Arm native event observation before hardware discovery/enrollment. A
    // selected-instance generation invalidated during setup must never serve.
    let power_mon = enclave_core::power::start_for_profile(
        args.profile, enclave_core::power::darwin::PowerMonitor::start,
    )?.map(std::sync::Arc::new);
    if let Some(session) = &selected_session { session.require_current()?; }
    let now = enclave_crypto::time::now_unix();
    let hw = if args.simulated_hardware {
        simulated_hardware(args, now)?
    } else {
        match production_hardware(args,keyless_travel,provisioned.as_ref())? {
            Some(hw) => hw,
            None => return Ok(None), // ordinary --sep-probe finished
        }
    };
    // Capture the actual original singleton handle before moving hardware to
    // the service. No software/paired/missing handle can supply this token.
    let selected_runtime = if let Some(session) = &selected_session {
        let token = selected_entry_transport(&hw)?;
        let monitor = power_mon.as_ref().ok_or_else(|| enclave_core::err!(EACCES, "SELECTED_OWNER_ENTRY_MONITOR_REQUIRED"))?.clone();
        let end = session.original_instant_end();
        Some(crate::ctap::selected_owner_runtime::SelectedOwnerRuntime::start(token, monitor,
            end, end, crate::service::SelectedOwnerFailure::new(), session.clone())?)
    } else { None };
    let grant_key = load_grant_key(args)?;
    let cfg=VaultConfig {
            profile: args.profile,
            audit_path: args.audit_path(DaemonId::CustodyVault),
            grant_key,
            state_dir: args.state_dir.clone(),
            socket_dir: Some(args.socket_dir.clone()),
            dev_same_uid: args.dev_same_uid,
        };
    let svc=match travel {
        Some(travel)=>VaultService::start_with_travel(cfg,hw,travel)?,
        None=>VaultService::start(cfg,hw)?,
    };
    let selected = selected_session.is_some();
    let mut owners = CustodyStartupOwners { service: svc, runtime: selected_runtime,
        _monitor: power_mon, session: selected_session, checkpoint_on_drop: selected };
    let svc = &owners.service;
    if let Some(runtime) = &mut owners.runtime {
        // Bind SAME service before any public accepting loop. Failure drops
        // this original runtime and never falls through to ordinary serving.
        let end = owners.session.as_ref().ok_or_else(|| enclave_core::err!(EACCES, "SELECTED_OWNER_ENTRY_SESSION_REQUIRED"))?.original_instant_end();
        runtime.bind_service(svc, end)?;
    }
    // Independent administrator-provisioned pins, never learned from CAS or an
    // engineer request. Missing authority keeps namespace release unavailable.
    match (args.get("enterprise-issuer-key-file"),args.get("enterprise-policy-file")) {
        (Some(issuer),Some(policy))=>{
            use enclave_core::enterprise_authority::{AuthorityConfig,EnterpriseAuthority,read_public_file};
            let key=read_public_file(std::path::Path::new(issuer),128)?;
            let key=std::str::from_utf8(&key).map_err(|_|enclave_core::err!(EACCES,"ENTERPRISE_KEY"))?.trim().to_owned();
            let state=args.state_dir.as_deref().ok_or_else(||enclave_core::err!(EACCES,"ENTERPRISE_STATE_REQUIRED"))?;
            let authority=EnterpriseAuthority::open_with_release_serial(AuthorityConfig{issuer_public_key_hex:key,policy_path:policy.into()},&state.join("enterprise"),svc.namespace_release_serial())?;
            authority.refresh(now)?;svc.set_enterprise_authority(authority)?;
        },
        (None,None)=>{},
        _=>return Err(enclave_core::err!(EACCES,"ENTERPRISE_AUTHORITY_CONFIG")),
    }
    // GAP-16: power / sleep / lock / yank wipe hook
    register_vault_wipe(enclave_core::power::registry(), svc);
    if !keyless_travel && !args.simulated_hardware && args.profile == enclave_core::profile::Profile::L3 {
        enclave_core::power::require_selected_usb_instance()?;
    }
    if let Some(runtime) = &mut owners.runtime {
        // Recheck after intervening startup work, under the SAME original cap.
        let end = owners.session.as_ref().ok_or_else(|| enclave_core::err!(EACCES, "SELECTED_OWNER_ENTRY_SESSION_REQUIRED"))?.original_instant_end();
        runtime.observe_health(end)?;
    }
    // Ordinary initialization failures retain their former drop-only behavior;
    // successful ordinary serving and every constructed selected service keep
    // the original checkpoint-before-owner-drop ordering.
    owners.checkpoint_on_drop = true;
    Ok(Some(owners))
}

// Public descriptor data is only a closed-scope refusal predicate. Passing
// this private function does not mint a checked target or a native session.
fn selected_entry_scope(target: &enclave_core::deployment::DeploymentTarget,
    args: &DaemonArgs, keyless_travel: bool) -> EnclaveResult<()> {
    use enclave_core::deployment::{DeploymentRole, DeploymentSigningMode};
    use enclave_core::Profile;
    if target.version != 1 || target.role != DeploymentRole::DedicatedTest || target.profile != Profile::L2
        || target.signing_identity_mode != DeploymentSigningMode::LocalPins
        || target.broker.is_some() || !target.shared_read_only_inputs.is_empty()
        || args.profile != target.profile || args.dev_same_uid || args.simulated_hardware || keyless_travel
        || args.get("yubikey-transport").is_some_and(|transport| transport != "hid")
        || args.get("yubikey-membership-pair").is_some()
        || args.get("asset-member").is_some_and(|member| member != "0")
        || args.get("bio-probe").is_some() || args.get("sep-probe").is_some() {
        return Err(enclave_core::err!(EACCES, "SELECTED_OWNER_ENTRY_UNSUPPORTED_SCOPE"));
    }
    let path = enclave_core::deployment::normalized_path;
    if path(&args.socket_dir)? != path(&target.layout.socket_root)?
        || args.state_dir.as_deref().map(path).transpose()?
            != Some(path(&target.layout.state_root.join(DaemonId::CustodyVault.dir_name()))?) {
        return Err(enclave_core::err!(EACCES, "SELECTED_OWNER_ENTRY_CONTEXT_MISMATCH"));
    }
    Ok(())
}
fn selected_entry_process() -> EnclaveResult<()> {
    if !cfg!(target_os = "macos") || !enclave_core::codesign::enforced() {
        return Err(enclave_core::err!(ENOSYS, "SELECTED_OWNER_ENTRY_NATIVE_REQUIRED"));
    }
    if enclave_core::ipc::geteuid() != DaemonId::CustodyVault.uid()
        || enclave_core::codesign::signing_mode() != enclave_core::codesign::SigningMode::LocalPins {
        return Err(enclave_core::err!(EPERM, "SELECTED_OWNER_ENTRY_PROCESS"));
    }
    Ok(())
}
fn selected_entry_session(args: &DaemonArgs, keyless_travel: bool)
    -> EnclaveResult<Option<std::sync::Arc<enclave_core::power::selected_owner_session::SelectedOwnerSession>>> {
    let Some(checked) = enclave_core::deployment::selected() else { return Ok(None); };
    selected_entry_scope(checked.target(), args, keyless_travel)?;
    selected_entry_process()?;
    // Actual protected capture only: no provider/path/clock/record injection.
    let session = std::sync::Arc::new(enclave_core::power::selected_owner_session::SelectedOwnerSession::capture()?);
    session.require_current()?;
    Ok(Some(session))
}
fn selected_entry_transport(hw: &VaultHardware) -> EnclaveResult<crate::ctap::selected_transport_lifetime::SelectedTransportLifetime> {
    if hw.simulated || hw.membership_devices.is_some() {
        return Err(enclave_core::err!(EACCES, "SELECTED_OWNER_ENTRY_NATIVE_SINGLETON_REQUIRED"));
    }
    let token = hw.yubikey.as_ref().ok_or_else(|| enclave_core::err!(EACCES, "SELECTED_OWNER_ENTRY_YUBIKEY_REQUIRED"))?
        .selected_transport_lifetime()?;
    token.require_current()?;
    Ok(token)
}

fn register_vault_wipe(registry: &enclave_core::power::WipeRegistry, service: &std::sync::Arc<VaultService>) {
    let service = std::sync::Arc::downgrade(service);
    registry.register("703_custody_wipe", move |trigger| {
        let Some(service) = service.upgrade() else { return Ok(()); };
        let op = enclave_core::ipc::PeerCredentials::local(0, 0);
        let ev = match trigger {
            enclave_core::power::WipeTrigger::SystemSleep => crate::zeroizer::TamperEvent::LidSleep,
            enclave_core::power::WipeTrigger::SessionLocked => {
                crate::zeroizer::TamperEvent::ScreenLock
            }
            enclave_core::power::WipeTrigger::AuthenticatorYank => {
                crate::zeroizer::TamperEvent::UsbYank { docked: false }
            }
            enclave_core::power::WipeTrigger::ThunderboltHotPlugLocked => {
                crate::zeroizer::TamperEvent::ScreenLock
            }
        };
        service.handle(&op, VaultRequest::Tamper(ev))?;
        Ok(())
    });
}

#[cfg(test)]
mod monitor_startup_tests {
    use super::*;
    // Inert public descriptor/argument data only. Passing a refusal predicate
    // cannot construct checked deployment selection, native session or HID.
    fn selected_entry_fixture() -> (enclave_core::deployment::DeploymentTarget, DaemonArgs) {
        use enclave_core::deployment::{DeploymentTarget, DeploymentLayout, DeploymentRole, DeploymentSigningMode};
        let root = std::path::PathBuf::from("/inert-selected-entry-fixture");
        let target = DeploymentTarget { version: 1, target_id: "selected-entry-fixture".into(),
            role: DeploymentRole::DedicatedTest, profile: enclave_core::Profile::L2,
            authority_config: root.join("support/authority.json"),
            expected_artifacts_manifest: root.join("support/artifacts.json"),
            codesign_pins_file: root.join("support/pins.json"),
            signing_identity_mode: DeploymentSigningMode::LocalPins,
            layout: DeploymentLayout { binary_dir: root.join("bin"), custody_bundle: root.join("Custody.app"),
                sandbox_dir: root.join("sandbox"), socket_root: root.join("mesh"), state_root: root.join("state"),
                audit_root: root.join("audit"), cas_store_root: root.join("cas"), staging_root: root.join("stage"),
                support_root: root.join("support"), launchd_namespace: "com.enterprise.selected-entry.fixture".into(),
                mach_service: "com.enterprise.selected-entry.fixture.exception".into() },
            broker: None, shared_read_only_inputs: Vec::new() };
        let args = DaemonArgs { socket_dir: target.layout.socket_root.clone(), audit_dir: Some(target.layout.audit_root.clone()),
            profile: target.profile, dev_same_uid: false, simulated_hardware: false,
            state_dir: Some(target.layout.state_root.join(DaemonId::CustodyVault.dir_name())),
            sandbox_profile: Some(target.layout.sandbox_dir.join("custody-vaultd.sb")),
            inherit_listener_fd: None, extra: Vec::new() };
        (target, args)
    }
    #[test]
    fn selected_entry_real_runtime_precondition_refusal_never_calls_initializer_or_binds() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let (_, mut args) = selected_entry_fixture();
        // Use the actual shared boundary selected entry now calls. Refuse
        // before hardening/sandbox work on every possible test process UID.
        let expected = if enclave_core::ipc::geteuid() == DaemonId::CustodyVault.uid() {
            args.simulated_hardware = true; "SIMULATION_REQUIRES_DEV_MODE"
        } else { "WRONG_DAEMON_UID" };
        args.socket_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target")
            .join(format!("selected-entry-refused-{:x}", enclave_core::rng::u64()));
        let path = args.socket_path(DaemonId::CustodyVault);
        assert!(!path.exists());
        let initialized = AtomicBool::new(false);
        let error = run_service_with_startup::<VaultRequest, VaultResponse, _, _, _>(
            DaemonId::CustodyVault, &args,
            || {
                initialized.store(true, Ordering::SeqCst);
                Ok((|_: &enclave_core::ipc::PeerCredentials, _: VaultRequest|
                    Err::<VaultResponse, _>(enclave_core::err!(EACCES, "UNREACHABLE_INITIALIZER")), ()))
            }, custody_rss_breach,
        ).unwrap_err();
        assert!(error.is(expected), "{error:?}");
        assert!(!initialized.load(Ordering::SeqCst));
        assert!(!path.exists(), "no listener may bind after failed native startup preconditions");
    }
    #[test]
    fn selected_entry_ownership_guard_shutdown_reaches_actual_service_before_drop() {
        let service = VaultService::start(VaultConfig { profile: enclave_core::Profile::L1, ..Default::default() },
            VaultHardware::simulated(enclave_core::Profile::L1, enclave_crypto::time::now_unix()).unwrap()).unwrap();
        let (_, enabled, cancelled) = service.selected_owner_test_state();
        assert!(enabled && !cancelled);
        drop(CustodyStartupOwners { service: service.clone(), runtime: None, _monitor: None,
            session: None, checkpoint_on_drop: true });
        let (_, enabled, cancelled) = service.selected_owner_test_state();
        assert!(!enabled && cancelled, "actual service shutdown must revoke while guard owns service");
    }
    #[test]
    fn selected_entry_closed_scope_refuses_unsupported_targets_and_mode_downgrades() {
        use enclave_core::deployment::{DeploymentBroker, DeploymentRole, DeploymentSigningMode};
        let (original, args) = selected_entry_fixture();
        selected_entry_scope(&original, &args, false).unwrap();
        for variant in 0..7 {
            let mut target = original.clone();
            match variant {
                0 => target.version = 2,
                1 => target.role = DeploymentRole::ExistingUpgrade,
                2 => target.profile = enclave_core::Profile::L1,
                3 => target.profile = enclave_core::Profile::L3,
                4 => target.signing_identity_mode = DeploymentSigningMode::TeamId,
                5 => target.broker = Some(DeploymentBroker { base_dir: "/inert-broker".into(), tuf_root_file: "/inert-broker/root.json".into() }),
                _ => target.shared_read_only_inputs.push("/inert-shared-input".into()),
            }
            assert!(selected_entry_scope(&target, &args, false).unwrap_err().is("SELECTED_OWNER_ENTRY_UNSUPPORTED_SCOPE"));
        }
        for variant in 0..3 {
            let mut altered = args.clone();
            match variant { 0 => altered.dev_same_uid = true, 1 => altered.simulated_hardware = true,
                _ => altered.profile = enclave_core::Profile::L3 }
            assert!(selected_entry_scope(&original, &altered, false).unwrap_err().is("SELECTED_OWNER_ENTRY_UNSUPPORTED_SCOPE"));
        }
        assert!(selected_entry_scope(&original, &args, true).unwrap_err().is("SELECTED_OWNER_ENTRY_UNSUPPORTED_SCOPE"));
        for (key, value) in [("yubikey-transport", "emulated:/inert.sock"), ("yubikey-membership-pair", "0"),
            ("asset-member", "1"), ("bio-probe", "/inert-probe"), ("sep-probe", "1")] {
            let mut altered = args.clone(); altered.extra.push((key.into(), value.into()));
            assert!(selected_entry_scope(&original, &altered, false).unwrap_err().is("SELECTED_OWNER_ENTRY_UNSUPPORTED_SCOPE"));
        }
        let mut wrong_socket = args.clone(); wrong_socket.socket_dir = "/other-inert-mesh".into();
        assert!(selected_entry_scope(&original, &wrong_socket, false).unwrap_err().is("SELECTED_OWNER_ENTRY_CONTEXT_MISMATCH"));
        let mut missing_state = args; missing_state.state_dir = None;
        assert!(selected_entry_scope(&original, &missing_state, false).unwrap_err().is("SELECTED_OWNER_ENTRY_CONTEXT_MISMATCH"));
    }
    #[test]
    fn selected_entry_actual_software_hardware_cannot_mint_native_transport_by_clearing_flag() {
        let mut hw = VaultHardware::simulated(enclave_core::Profile::L2, enclave_crypto::time::now_unix()).unwrap();
        assert!(selected_entry_transport(&hw).unwrap_err().is("SELECTED_OWNER_ENTRY_NATIVE_SINGLETON_REQUIRED"));
        hw.simulated = false;
        assert!(selected_entry_transport(&hw).unwrap_err().is("HID_SELECTED_TRANSPORT_UNAVAILABLE"));
        hw.yubikey = None;
        assert!(selected_entry_transport(&hw).unwrap_err().is("SELECTED_OWNER_ENTRY_YUBIKEY_REQUIRED"));
    }
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn selected_entry_native_process_gate_refuses_linux_without_capture_or_owners() {
        assert!(selected_entry_process().unwrap_err().is("SELECTED_OWNER_ENTRY_NATIVE_REQUIRED"));
    }
    #[test]
    fn yk03_actual_local_registry_scrubs_owned_synthetic_region_on_every_native_trigger_route() {
        use enclave_core::{profile::Profile, power::{WipeRegistry, WipeTrigger}};
        for trigger in [WipeTrigger::AuthenticatorYank, WipeTrigger::SessionLocked,
            WipeTrigger::SystemSleep, WipeTrigger::ThunderboltHotPlugLocked] {
            let service = VaultService::start(
                VaultConfig { profile: Profile::L1, ..VaultConfig::default() },
                VaultHardware::simulated(Profile::L1, enclave_crypto::time::now_unix()).unwrap(),
            ).unwrap();
            let mut region = enclave_core::guarded::GuardedRegion::new(64).unwrap();
            region.as_mut_slice().unwrap().fill(0xa7);
            let region = std::sync::Arc::new(region);
            service.register_synthetic_region(region.clone()).unwrap();
            let registry = WipeRegistry::default();
            register_vault_wipe(&registry, &service);
            let receipt = registry.execute(trigger);
            assert!(receipt.success, "actual service cleanup failed: {receipt:?}");
            assert!(region.is_scrubbed());
            assert!(region.verify_zeroed(), "synthetic canary remains after service cleanup");
            assert!(region.as_slice().is_err(), "completed scrub cannot reopen old region");
            assert!(registry.execute(trigger).success, "repeat cleanup must retain ownership safely");
        }
    }
    #[test]
    fn f38_failed_required_monitor_does_not_keep_custody_alive_through_wipe_registry() {
        use enclave_core::{profile::Profile, power::{WipeRegistry, WipeTrigger}};
        let service = VaultService::start(
            VaultConfig { profile: Profile::L1, ..VaultConfig::default() },
            VaultHardware::simulated(Profile::L1, enclave_crypto::time::now_unix()).unwrap(),
        ).unwrap();
        let weak = std::sync::Arc::downgrade(&service);
        let registry = WipeRegistry::default();
        register_vault_wipe(&registry, &service);
        assert!(registry.execute(WipeTrigger::SessionLocked).success);
        assert!(enclave_core::power::start_for_profile::<()>(Profile::L2, || Err(enclave_core::err!(EIO, "FIXTURE_MONITOR_REQUIRED"))).is_err());
        drop(service);
        assert!(weak.upgrade().is_none());
        assert!(registry.execute(WipeTrigger::SessionLocked).success);
    }
}

/// UID 704's custody-grant verifying key (`Custody::ReversibleTokenize`).
/// `--grant-key-file` (provisioned by `mcp-enclave launchd grant-key`) must
/// hold a valid Ed25519 key if given; without either option no grant is
/// ever accepted (fail closed).
fn load_grant_key(args: &DaemonArgs) -> EnclaveResult<Option<ed25519_dalek::VerifyingKey>> {
    let hex_src = match (args.get("grant-key-file"), args.get("grant-key-hex")) {
        (Some(p), _) => std::fs::read_to_string(p)
            .map_err(|e| enclave_core::err!(EIO, "GRANT_KEY_FILE", "{p}: {e}"))?,
        (None, Some(h)) => h.to_owned(),
        (None, None) => {
            match enclave_core::host_config::fetch_host_config(&args.socket_dir, args.dev_same_uid)
            {
                Ok(cfg) => cfg.ifc_grant_public_key,
                Err(_) => return Ok(None),
            }
        }
    };
    hex::decode(hex_src.trim())
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .and_then(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).ok())
        .map(Some)
        .ok_or_else(|| {
            enclave_core::err!(
                EINVAL,
                "GRANT_KEY_INVALID",
                "expected a 64-hex Ed25519 public key"
            )
        })
}

/// Production hardware (GAP-15). The Secure Enclave epoch key is opened (or
/// created) first, as UID 703 under its Seatbelt profile, so the launchd
/// bring-up proves SEP access in the real context. The vault then still
/// refuses to serve until the biometric tier keys (`_enclaveintent` helper,
/// GAP-14) and the YubiKey transport (GAP-13) exist — it never falls back to
/// software keys.
///
/// `--sep-probe 1` signs and verifies one boot epoch with the SEP key, prints
/// a JSON report and exits 0 (the GAP-15 exit criterion check).
#[cfg(target_os = "macos")]
fn production_hardware(args: &DaemonArgs,keyless_travel:bool,provisioned:Option<&crate::provisioning::CustodyProvisioning>) -> EnclaveResult<Option<VaultHardware>> {
    use crate::sep::SepAgent;
    enclave_core::runtime::check_identity(DaemonId::CustodyVault, args)?;
    if !enclave_core::resource::harden_process() && !args.dev_same_uid {
        enclave_core::fail!(
            EPERM,
            "HARDENING_FAILED",
            "RLIMIT_CORE / PT_DENY_ATTACH / exception ports"
        );
    }
    let state = args.state_dir.as_deref().ok_or_else(|| {
        enclave_core::err!(
            EINVAL,
            "STATE_DIR_REQUIRED",
            "production custody needs --state-dir"
        )
    })?;
    let sep = crate::darwin_sep::DarwinSep::open(&state.join("sep"))?;
    let pk = sep.epoch_public_key();
    if let Some(bio_path) = args.get("bio-probe") {
        let v = crate::darwin_sep::bio_probe(std::path::Path::new(bio_path))?;
        println!("{}", v);
        return Ok(None);
    }
    if args.get("sep-probe").is_some() {
        let id = enclave_core::seq::new_boot_epoch_id();
        let be = enclave_core::seq::BootEpoch {
            boot_epoch_id: id.clone(),
            signature: sep.sign_epoch(&enclave_core::seq::epoch_signing_message(&id))?,
            signer_public_key: pk.clone(),
        };
        let verified = enclave_crypto::epoch::verify(&be).is_ok();
        println!(
            "{}",
            serde_json::json!({
                "probe": "sep", "uid": enclave_core::ipc::geteuid(), "storage": "sep-wrapped-token-object",
                "epoch_public_key": hex::encode(&pk), "boot_epoch_signature_verified": verified,
                "errSecMissingEntitlement_count": 0,
            })
        );
        return if verified {
            Ok(None)
        } else {
            Err(enclave_core::err!(
                EIO,
                "SEP_PROBE_FAILED",
                "boot epoch signature did not verify"
            ))
        };
    }
    eprintln!(
        "{}",
        serde_json::json!({"event": "SEP_EPOCH_KEY_READY", "epoch_public_key": hex::encode(&pk)})
    );
    // Probe configured authenticator transport (IOKit HID, or CTAPHID emulator)
    if !keyless_travel {eprintln!("{}",probe_yubikey(args));}

    let intent_sock = args.socket_dir.join("intent/intent.sock");

    let asset_enrollment_authority = match provisioned {
        Some(config) => Some(config.authorities().0),
        None => load_asset_enrollment_authority(args)?,
    };
    let selected_member=match args.get("asset-member") {
        None|Some("0")=>0,
        Some("1")=>1,
        _=>return Err(enclave_core::err!(EINVAL,"ASSET_MEMBER_SELECTION")),
    };
    let now=enclave_crypto::time::now_unix();
    let membership=crate::service::load_native_membership(state,asset_enrollment_authority.as_ref(),args.profile,now)?;
    // The explicit v3 reader authenticates both inventory receipts and the
    // exact authoritative content reference. Selecting a record is no proof
    // that an attached USB device owns it; every live assertion still verifies
    // that record's credential before any tier-key use.
    let admitted=match membership.as_ref() {
        Some(membership)=>Some((membership.enrolled(selected_member)?,membership.source_binding())),
        None=>{
            if selected_member!=0 {return Err(enclave_core::err!(EACCES,"ASSET_MEMBER_NOT_ADMITTED"));}
            match crate::service::load_native_enrollment(state,asset_enrollment_authority.as_ref(),args.profile,now)? {
                Some(enrolled)=>Some(enrolled),
                None=>crate::service::load_native_membership_setup(state,asset_enrollment_authority.as_ref(),args.profile,now)?
                    .map(|setup|(setup.enrolled(),setup.source_binding())),
            }
        },
    };
    let asset_activation_binding=admitted.as_ref().map(|(_,binding)|*binding);
    // Check for persisted custodian enrollment in <state>/custody/enrollment.sealed
    let custody_dir = state.join("custody");
    let (_enrollment_store, enrollment) = enclave_core::sealed::SealedStore::open(&custody_dir, "enrollment")
        .map_err(|_| enclave_core::err!(EACCES, "CUSTODY_ENROLLMENT_STATE"))?;
    let (cred, bio_pk, bio_blob) = match enrollment {
        enclave_core::sealed::Loaded::State(bytes) => {
            if args.profile>=enclave_core::profile::Profile::L2 {return Err(enclave_core::err!(EACCES,"ASSET_ENROLLMENT_MIGRATION_REQUIRED"));}
            let enrolled: crate::service::EnrolledCustodyState = enclave_core::sealed::decode(&bytes)
                .map_err(|_| enclave_core::err!(EACCES, "CUSTODY_ENROLLMENT_STATE"))?;
            (Some(enrolled.credential), enrolled.bio_public_key, Some(enrolled.bio_key_blob))
        },
        enclave_core::sealed::Loaded::Fresh => match admitted {
            Some((enrolled,_))=>(Some(enrolled.credential),enrolled.bio_public_key,Some(enrolled.bio_key_blob)),
            // L1 has no custodian credential: its Touch ID key, if registered
            // (`vault enroll-biometric`), lives in its own sealed record.
            None if args.profile==enclave_core::profile::Profile::L1 => {
                let (_store, loaded) = enclave_core::sealed::SealedStore::open(&custody_dir, crate::service::BIOMETRIC_L1_STORE)
                    .map_err(|_| enclave_core::err!(EACCES, "CUSTODY_ENROLLMENT_STATE"))?;
                match loaded {
                    enclave_core::sealed::Loaded::State(bytes) => {
                        let enrolled: crate::service::EnrolledBiometricL1 = enclave_core::sealed::decode(&bytes)
                            .map_err(|_| enclave_core::err!(EACCES, "CUSTODY_ENROLLMENT_STATE"))?;
                        (None, enrolled.bio_public_key, Some(enrolled.bio_key_blob))
                    }
                    enclave_core::sealed::Loaded::Fresh => (None,pk.clone(),None),
                }
            }
            None=>(None,pk.clone(),None),
        },
    };
    // A malformed enrolled identity cannot silently become an unrelated key.
    let bio_verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&bio_pk)
        .map_err(|_| enclave_core::err!(EACCES, "CUSTODY_BIOMETRIC_IDENTITY"))?;

    let membership_devices=if keyless_travel {None}else{open_membership_devices(args)?};
    let yubikey_dev: Option<Box<dyn crate::ctap::hid::HidDevice + Send>> = if keyless_travel||membership_devices.is_some() {None} else {
        use crate::ctap::transport::{Transport, EMULATOR_UID};
        let spec = args.get("yubikey-transport").unwrap_or("hid").to_owned();
        match Transport::parse(&spec).and_then(|t| {
            let server_uid = if args.dev_same_uid {
                enclave_core::ipc::geteuid()
            } else {
                EMULATOR_UID
            };
            match cred.as_ref() {
                Some(c) => t.open_enrolled(server_uid, &c.aaguid),
                None => t.open(server_uid),
            }
        }) {
            Ok(dev) => Some(dev),
            Err(e) => {
                eprintln!("production_hardware: transport open failed ({spec}): {e}");
                None
            }
        }
    };

    // The local allowlist file is diagnostic input only. Critical operations
    // obtain bytes and freshness from authenticated, currently verified CAS.
    // Construct lazily so a public L2 startup does not require a present key or
    // a metadata transaction until an authenticator operation is requested.
    let metadata_source = Some(crate::metadata_source::CustodyMetadataSource::new(args.socket_dir.clone(), args.dev_same_uid));
    let envelope_authority = if let Some(config) = provisioned {
        Some(config.authorities().1)
    } else { match (args.get("envelope-policy-key-file"), args.get("envelope-policy-subject"), args.get("envelope-policy-namespace")) {
        (Some(key), Some(subject), Some(namespace)) => {
            let raw = enclave_core::enterprise_authority::read_public_file(std::path::Path::new(key), 128)?;
            let raw = std::str::from_utf8(&raw).map_err(|_| enclave_core::err!(EINVAL, "ENVELOPE_POLICY_KEY"))?;
            let bytes: [u8;32] = hex::decode(raw.trim()).ok().and_then(|v| v.try_into().ok())
                .ok_or_else(|| enclave_core::err!(EINVAL, "ENVELOPE_POLICY_KEY"))?;
            Some(crate::metadata_source::EnvelopeAuthorityConfig {
                issuer: ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| enclave_core::err!(EINVAL, "ENVELOPE_POLICY_KEY"))?,
                subject: subject.into(), namespace: namespace.into(),
            })
        },
        (None, None, None) => None,
        _ => return Err(enclave_core::err!(EINVAL, "ENVELOPE_POLICY_CONFIG")),
    }};

    let egress: Option<Box<dyn crate::ceremony::EgressGate + Send>> =
        if args.profile == enclave_core::Profile::L3 {
            let zk_sock = args
                .state_dir
                .as_ref()
                .map(|d| d.join("zk/zk.sock"))
                .unwrap_or_else(|| std::path::PathBuf::from("/var/run/enclave/zk/zk.sock"));
            Some(Box::new(crate::egress_uds::UdsEgressGate::new(zk_sock)))
        } else {
            None
        };

    Ok(Some(VaultHardware {
        sep: Box::new(sep),
        biometric: Box::new(crate::biometric::IntentHelperProvider::new(intent_sock.clone())),
        sep_bio_key: bio_verifying_key,
        sep_bio_blob: bio_blob,
        yubikey: yubikey_dev,
        membership_devices,
        credential: cred,
        mds: None,
        metadata_source,
        envelope_authority,
        asset_enrollment_authority,
        asset_activation_binding,
        active_asset_guard:None,
        oidc_provider: args.get("oidc-broker-config").map(|path| Box::new(
            crate::oidc_acquisition::NativeIntentOidcProvider::new(args.socket_dir.clone(), std::path::PathBuf::from(path)))
            as Box<dyn crate::oidc_acquisition::IntentOidcProvider>),
        existing_pin: Some(Box::new(crate::pin::NativeExistingPinProvider::new(intent_sock.clone()))),
        egress,
        display: Box::new(crate::display::NativeHelperDisplay::new(intent_sock)),
        simulated: false,
    }))
}

/// An explicit setup mode owns two concrete handles from one enumeration.
/// The index only chooses an untrusted candidate order; the live producer must
/// authenticate both credentials. Ordinary committed-member startup needs only
/// the selected member, so losing the primary does not require its presence to
/// use an independently admitted backup.
#[cfg(target_os="macos")]
fn open_membership_devices(args:&DaemonArgs)->EnclaveResult<Option<crate::service::MembershipDevices>> {
    let primary_index=match args.get("yubikey-membership-pair") {
        None=>return Ok(None),
        Some("0")=>0,
        Some("1")=>1,
        _=>return Err(enclave_core::err!(EINVAL,"MEMBERSHIP_PAIR_SELECTION")),
    };
    if args.get("yubikey-transport").is_some_and(|transport|transport!="hid") {
        return Err(enclave_core::err!(EACCES,"MEMBERSHIP_NATIVE_PAIR_REQUIRED"));
    }
    #[cfg(feature="macos-hid")]
    {
        let devices=crate::ctap::macos_hid::MacHidDevice::enumerate()?;
        let [mut first,mut second]:[_;2]=devices.try_into()
            .map_err(|_|enclave_core::err!(EACCES,"MEMBERSHIP_EXACT_TWO_DEVICES_REQUIRED"))?;
        if args.profile==enclave_core::Profile::L3 && (first.hub_depth()!=1 || second.hub_depth()!=1) {
            return Err(enclave_core::err!(EACCES,"USB_HUB_FORBIDDEN_L3"));
        }
        if primary_index==1 {std::mem::swap(&mut first,&mut second);}
        Ok(Some(crate::service::MembershipDevices::from_native(first,second)?))
    }
    #[cfg(not(feature="macos-hid"))]
    {
        let _=primary_index;
        Err(enclave_core::err!(EPERM,"HID_TRANSPORT_NOT_COMPILED"))
    }
}

/// Open the configured authenticator, run `getInfo`, and check it against
/// `--mds-file`. Returns a journal event (`YUBIKEY_READY` or
/// `YUBIKEY_UNAVAILABLE`); errors are reported, never swallowed into success.
pub fn probe_yubikey(args: &DaemonArgs) -> serde_json::Value {
    use crate::ctap::transport::{Transport, EMULATOR_UID};
    let spec = args.get("yubikey-transport").unwrap_or("hid").to_owned();
    let r = (|| -> EnclaveResult<serde_json::Value> {
        let t = Transport::parse(&spec)?;
        let server_uid = if args.dev_same_uid {
            enclave_core::ipc::geteuid()
        } else {
            EMULATOR_UID
        };
        let mut dev = t.open(server_uid)?;
        let mut c = crate::ctap::client::CtapClient::open(&mut *dev)?;
        let info = c.get_info()?;
        let hub_depth = c.hub_depth();
        let mds = match args.get("mds-file") {
            Some(p) => {
                let m = load_mds(std::path::Path::new(p))?;
                let check = m.check(
                    &info.aaguid,
                    info.firmware_version,
                    crate::ctap::alg::EDDSA,
                    args.profile,
                    enclave_core::profile::ActionClass::A3,
                    enclave_crypto::time::now_unix(),
                );
                serde_json::json!({"file": p, "allowed": check.is_ok(), "reason": check.err().map(|e| e.to_string())})
            }
            None => {
                serde_json::json!({"file": null, "allowed": false, "reason": "no --mds-file installed"})
            }
        };
        Ok(serde_json::json!({
            "event": "YUBIKEY_READY", "transport": spec, "aaguid": hex::encode(info.aaguid),
            "firmware": format!("{}.{}.{}", info.firmware_version >> 16, (info.firmware_version >> 8) & 0xff, info.firmware_version & 0xff),
            "versions": info.versions, "extensions": info.extensions, "pin_uv_protocols": info.pin_uv_protocols,
            "hub_depth": hub_depth, "mds": mds,
        }))
    })();
    r.unwrap_or_else(|e| serde_json::json!({"event": "YUBIKEY_UNAVAILABLE", "transport": spec, "error": e.to_string()}))
}

/// Parse provisioned allowlist bytes without inventing authenticated freshness.
/// Native custody replaces this with the live verified CAS receipt below; a
/// local file mtime is never metadata freshness authority.
fn load_mds(p: &std::path::Path) -> EnclaveResult<crate::ctap::mds::MdsState> {
    let raw = std::fs::read(p)
        .map_err(|error| enclave_core::err!(EIO, "MDS_FILE_READ", "{}: {error}", p.display()))?;
    crate::ctap::mds::MdsState::from_verified_target(&raw, -1)
}

#[cfg(not(target_os = "macos"))]
fn production_hardware(args: &DaemonArgs,keyless_travel:bool,provisioned:Option<&crate::provisioning::CustodyProvisioning>) -> EnclaveResult<Option<VaultHardware>> {
    let _ = provisioned;
    if let Some(bio_path) = args.get("bio-probe") {
        let v = crate::darwin_sep::bio_probe(std::path::Path::new(bio_path))?;
        println!("{}", v);
        return Ok(None);
    }
    // The authenticator transport is platform-neutral; report it anyway.
    if !keyless_travel {eprintln!("{}", probe_yubikey(args));}
    Err(enclave_core::err!(EPERM, "HARDWARE_PROVIDERS_UNAVAILABLE", "production custody requires an Apple-silicon Secure Enclave; refusing to start (fail closed)"))
}

/// GAP-03: simulated custody hardware exists only in a build compiled with the
/// `simulation` feature, only in development mode, and never under a
/// production identity or on the production socket directory — so a plist
/// edit alone can never turn UID 703 into an auto-approving vault.
#[cfg(feature = "simulation")]
fn simulated_hardware(args: &DaemonArgs, now: i64) -> EnclaveResult<VaultHardware> {
    args.check_simulation_allowed()?;
    VaultHardware::simulated_in(args.profile, now, args.state_dir.as_deref())
}

#[cfg(not(feature = "simulation"))]
fn simulated_hardware(_args: &DaemonArgs, _now: i64) -> EnclaveResult<VaultHardware> {
    Err(enclave_core::err!(
        EPERM,
        "SIMULATION_NOT_COMPILED",
        "this build has no simulated custody hardware; rebuild with --features simulation for development"
    ))
}

/// Operator config supplies independent trust; no setup RPC supplies issuer keys.
#[cfg(target_os="macos")]
fn load_asset_enrollment_authority(args:&DaemonArgs)->EnclaveResult<Option<crate::service::AssetEnrollmentAuthority>> {
    let names=["asset-policy-file","asset-policy-key-file","asset-inventory-key-file","asset-host-id","asset-id","asset-custodian-id"];
    let values:Vec<_>=names.iter().map(|name|args.get(name)).collect();
    if values.iter().all(|v|v.is_none()) {return Ok(None)}
    if values.iter().any(|v|v.is_none()) {return Err(enclave_core::err!(EINVAL,"ASSET_AUTHORITY_CONFIG"));}
    let key=|path:&str|->EnclaveResult<ed25519_dalek::VerifyingKey> {
        let bytes=crate::service::read_asset_authority_file(std::path::Path::new(path),128)?;
        let text=std::str::from_utf8(&bytes).map_err(|_|enclave_core::err!(EINVAL,"ASSET_AUTHORITY_KEY"))?;
        let raw:[u8;32]=hex::decode(text.trim()).ok().and_then(|b|b.try_into().ok()).ok_or_else(||enclave_core::err!(EINVAL,"ASSET_AUTHORITY_KEY"))?;
        ed25519_dalek::VerifyingKey::from_bytes(&raw).map_err(|_|enclave_core::err!(EINVAL,"ASSET_AUTHORITY_KEY"))
    };
    Ok(Some(crate::service::AssetEnrollmentAuthority {policy_file:values[0].unwrap().into(),policy_issuer:key(values[1].unwrap())?,
        inventory_issuer:key(values[2].unwrap())?,host:values[3].unwrap().into(),asset:values[4].unwrap().into(),custodian:values[5].unwrap().into()}))
}
