//! SOFTWARE only: inert public targets and private orchestration callbacks.
//! No native context/guard/code/runtime authority is minted; no process runs.
use super::*;
use std::cell::{Cell, RefCell};

fn target() -> DeploymentTarget {
    let root = Path::new("/unopened-supervisor-software-fixture");
    DeploymentTarget {
        version: 1,
        target_id: "supervisor-fixture".into(),
        role: DeploymentRole::DedicatedTest,
        profile: Profile::L2,
        authority_config: root.join("support/authority.json"),
        expected_artifacts_manifest: root.join("support/inventory.json"),
        codesign_pins_file: root.join("support/pins.json"),
        signing_identity_mode: DeploymentSigningMode::LocalPins,
        layout: deployment::DeploymentLayout {
            binary_dir: root.join("bin"),
            custody_bundle: root.join("support/Custody.app"),
            sandbox_dir: root.join("sandbox"),
            socket_root: root.join("run"),
            state_root: root.join("state"),
            audit_root: root.join("audit"),
            cas_store_root: root.join("cas"),
            staging_root: root.join("stage"),
            support_root: root.join("support"),
            launchd_namespace: "com.enterprise.enclave.supervisor-fixture".into(),
            mach_service: "com.enterprise.enclave.supervisor-fixture.exception".into(),
        },
        broker: None,
        shared_read_only_inputs: Vec::new(),
    }
}
fn env(target: &DeploymentTarget) -> Env {
    Env {
        dev: false,
        profile: target.profile,
        state_dir: target.layout.state_root.clone(),
        socket_dir: target.layout.socket_root.clone(),
        audit_dir: target.layout.audit_root.clone(),
    }
}
fn receipt() -> SupervisorStartReceipt {
    new_receipt(&target(), &"a".repeat(64))
}
fn until() -> Instant {
    Instant::now() + Duration::from_secs(2)
}
fn output(code: Option<i32>) -> CommandOutput {
    CommandOutput {
        code,
        stdout: b"RAW_CHILD_STDOUT_SENTINEL".to_vec(),
        stderr: b"RAW_CHILD_STDERR_SENTINEL".to_vec(),
    }
}
fn no_readiness(report: &TargetSupervisorStartReport) {
    assert!(!report.receipt.first_begin_prerequisites_met && !report.receipt.qualified);
    assert_eq!(
        report.receipt.pf_prerequisites,
        "UNKNOWN_REQUIRED_ENFORCEMENT_WATCHER_AND_RESTORATION"
    );
    assert!(report.receipt.readiness.starts_with("UNKNOWN"));
}
fn copy() -> deploy::target_plan::CopyEntry {
    deploy::target_plan::CopyEntry {
        source: "/unopened-stage/supervisor.plist".into(),
        destination:
            "/Library/LaunchDaemons/com.enterprise.enclave.supervisor-fixture.supervisor.plist"
                .into(),
        sha256: "b".repeat(64),
        size: 42,
        uid: 0,
        gid: 0,
        mode: "0644".into(),
        condition: "SOFTWARE_ONLY",
    }
}

#[test]
fn production_runtime_refusal_prevents_even_a_private_fixture_executor() {
    let calls = Cell::new(0);
    let mut progress = receipt();
    let mut retained = Vec::new();
    let result = register_one(
        &SupervisorCommand::for_target(&target()),
        &mut progress,
        until(),
        &mut |_| vec![require_selected_runtime().unwrap_err()],
        &mut |_, _| {
            calls.set(calls.get() + 1);
            Ok(output(Some(0)))
        },
        &mut retained,
    );
    assert!(result.unwrap_err().is(RUNTIME_UNAVAILABLE));
    assert_eq!(calls.get(), 0);
    assert!(!progress.bootstrap_attempted && !progress.bootstrap_succeeded);
    assert!(retained.iter().any(|error| error.is(RUNTIME_UNAVAILABLE)));
    assert!(require_selected_runtime()
        .unwrap_err()
        .is(RUNTIME_UNAVAILABLE));
}

#[test]
fn closed_command_bootstraps_exactly_one_selected_system_supervisor_with_scrubbed_environment() {
    let command = SupervisorCommand::for_target(&target());
    assert_eq!(
        command.label,
        "com.enterprise.enclave.supervisor-fixture.supervisor"
    );
    let actual = command.command();
    assert_eq!(actual.get_program(), "/bin/launchctl");
    assert_eq!(actual.get_current_dir(), Some(Path::new("/")));
    let args = actual
        .get_args()
        .map(|value| value.to_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        args,
        [
            "bootstrap",
            "system",
            "/Library/LaunchDaemons/com.enterprise.enclave.supervisor-fixture.supervisor.plist"
        ]
    );
    let environment = actual
        .get_envs()
        .map(|(name, value)| (name.to_str().unwrap(), value.unwrap().to_str().unwrap()))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        environment,
        BTreeMap::from([("LC_ALL", "C"), ("PATH", crate::syscmd::SAFE_PATH)])
    );
    assert!(format!("{actual:?}").contains("env -i"));
    assert!(!args
        .iter()
        .any(|argument| ["bootout", "kickstart", "enable", "disable"].contains(argument)));
}

#[test]
fn exact_supported_scope_refuses_every_other_role_profile_signing_broker_or_shared_shape() {
    let baseline = target();
    baseline.validate().unwrap();
    if codesign::signing_mode() == codesign::SigningMode::LocalPins {
        scope(&baseline).unwrap();
    } else {
        assert!(scope(&baseline)
            .unwrap_err()
            .is("DEPLOYMENT_SUPERVISOR_SCOPE_UNSUPPORTED"));
    }
    for variant in 0..7 {
        let mut changed = baseline.clone();
        match variant {
            0 => changed.role = DeploymentRole::ExistingUpgrade,
            1 => changed.profile = Profile::L1,
            2 => changed.profile = Profile::L3,
            3 => changed.signing_identity_mode = DeploymentSigningMode::TeamId,
            4 => {
                changed.broker = Some(deployment::DeploymentBroker {
                    base_dir: changed.layout.state_root.join("apfs-broker"),
                    tuf_root_file: changed.layout.support_root.join("tuf.json"),
                })
            }
            5 => changed
                .shared_read_only_inputs
                .push(changed.authority_config.clone()),
            _ => {
                changed.profile = Profile::L3;
                changed.broker = Some(deployment::DeploymentBroker {
                    base_dir: changed.layout.state_root.join("apfs-broker"),
                    tuf_root_file: changed.layout.support_root.join("tuf.json"),
                });
            }
        }
        assert!(scope(&changed)
            .unwrap_err()
            .is("DEPLOYMENT_SUPERVISOR_SCOPE_UNSUPPORTED"));
    }
}

#[test]
fn development_or_wrong_profile_state_socket_or_audit_routes_cannot_bind_to_target() {
    let target = target();
    for variant in 0..5 {
        let mut changed = env(&target);
        match variant {
            0 => changed.dev = true,
            1 => changed.profile = Profile::L3,
            2 => changed.state_dir = "/unopened-other-state".into(),
            3 => changed.socket_dir = "/unopened-other-run".into(),
            _ => changed.audit_dir = "/unopened-other-audit".into(),
        }
        assert!(bind(&changed, &target)
            .unwrap_err()
            .is("DEPLOYMENT_SUPERVISOR_CONTEXT_MISMATCH"));
    }
}

#[test]
fn native_code_requirement_uses_only_original_ctl_identifier_selected_pins_and_compiled_team() {
    let bytes = serde_json::to_vec(&serde_json::json!({"v":1,"pins":{
        "com.enterprise.enclave.ctl":["1".repeat(40)],"com.enterprise.enclave.supervisor":["2".repeat(40)],
        "com.enterprise.enclave.intent":["3".repeat(40)]}})).unwrap();
    let requirement = selected_requirement(&bytes).unwrap();
    assert_eq!(requirement.identifier, codesign::CTL_IDENTIFIER);
    assert_eq!(requirement.team_id, codesign::TEAM_ID);
    assert_eq!(requirement.cdhash_allowlist, vec!["1".repeat(40)]);
    for value in [
        serde_json::json!({"v":1,"pins":{"com.enterprise.enclave.supervisor":["2".repeat(40)]}}),
        serde_json::json!({"v":1,"pins":{"com.enterprise.enclave.ctl":[]}}),
        serde_json::json!({"v":1,"pins":{"com.enterprise.enclave.ctl":["invalid"]}}),
    ] {
        assert!(selected_requirement(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}

#[test]
fn inventory_contract_refuses_wrong_owner_group_or_fixed_plist_and_code_modes() {
    copy_contract(&copy(), 0o644).unwrap();
    for variant in 0..5 {
        let mut changed = copy();
        match variant {
            0 => changed.uid = 501,
            1 => changed.gid = 8703,
            2 => changed.mode = "0600".into(),
            3 => changed.mode = "0664".into(),
            _ => changed.mode = "invalid".into(),
        }
        assert!(copy_contract(&changed, 0o644).is_err());
    }
    assert!(copy_contract(&copy(), 0o755).is_err());
    let mut code = copy();
    code.mode = "0755".into();
    copy_contract(&code, 0o755).unwrap();
}

#[test]
fn renderer_comparison_keeps_all_bytes_order_and_program_arguments_exact() {
    let expected = b"<array><string>supervise</string><string>--deployment-config</string><string>/selected.json</string></array>\n";
    exact_plist(expected, expected).unwrap();
    for changed in [b"<array><string>--dev</string></array>".as_slice(),
        b"<array><string>supervise</string><string>--deployment-config</string><string>/other.json</string></array>\n",
        b"<array><string>supervise</string><string>--deployment-config</string><string>/selected.json</string></array>"] {
        assert!(exact_plist(changed, expected).unwrap_err().is("DEPLOYMENT_SUPERVISOR_RENDERER_MISMATCH"));
    }
}

#[test]
fn all_engine_failures_and_nonzero_or_missing_exits_remain_redacted_refusals() {
    for (failure, reason) in [
        (
            CommandFailure::Timeout,
            "DEPLOYMENT_SUPERVISOR_BOOTSTRAP_TIMEOUT",
        ),
        (
            CommandFailure::OutputLimit,
            "DEPLOYMENT_SUPERVISOR_BOOTSTRAP_OUTPUT_LIMIT",
        ),
        (
            CommandFailure::OwnershipUnknown,
            "DEPLOYMENT_SUPERVISOR_BOOTSTRAP_CLEANUP_UNCERTAIN",
        ),
        (
            CommandFailure::Unavailable,
            "DEPLOYMENT_SUPERVISOR_BOOTSTRAP_UNAVAILABLE",
        ),
        (
            CommandFailure::Io,
            "DEPLOYMENT_SUPERVISOR_BOOTSTRAP_UNAVAILABLE",
        ),
    ] {
        assert!(command_result(Err(failure)).unwrap_err().is(reason));
    }
    for code in [None, Some(1), Some(64)] {
        let error = command_result(Ok(output(code))).unwrap_err();
        assert!(error.is("DEPLOYMENT_SUPERVISOR_BOOTSTRAP_FAILED"));
        assert!(!format!("{error:?}").contains("RAW_CHILD"));
    }
    command_result(Ok(output(Some(0)))).unwrap();
}

#[test]
fn command_adapter_refuses_combined_output_above_the_shared_cap() {
    assert!(command_result(Ok(CommandOutput {
        code: Some(0),
        stdout: vec![b'a'; native_command::MAX_OUTPUT],
        stderr: vec![b'b']
    }))
    .unwrap_err()
    .is("DEPLOYMENT_SUPERVISOR_BOOTSTRAP_OUTPUT_LIMIT"));
}

#[test]
fn one_synthetic_registration_preserves_progress_but_never_establishes_readiness() {
    let mut progress = receipt();
    progress.preflight_complete = true;
    let calls = Cell::new(0);
    let observations = Cell::new(0);
    let mut retained = Vec::new();
    let operation = register_one(
        &SupervisorCommand::for_target(&target()),
        &mut progress,
        until(),
        &mut |_| {
            observations.set(observations.get() + 1);
            Vec::new()
        },
        &mut |command, _| {
            calls.set(calls.get() + 1);
            assert!(command.label.ends_with(".supervisor"));
            Ok(output(Some(0)))
        },
        &mut retained,
    );
    let report = finish(progress, operation, Vec::new(), retained);
    assert_eq!(calls.get(), 1);
    assert_eq!(observations.get(), 2);
    assert!(
        report.successful
            && report.receipt.registration_complete
            && report.receipt.bootstrap_succeeded
    );
    assert!(!report.receipt.uncertain_command_effects);
    no_readiness(&report);
}

#[test]
fn every_precommand_refusal_is_retained_and_prevents_registration() {
    let mut progress = receipt();
    let mut retained = Vec::new();
    let operation = register_one(
        &SupervisorCommand::for_target(&target()),
        &mut progress,
        until(),
        &mut |_| {
            vec![
                err!(ESTALE, "SOFTWARE_DESCRIPTOR_CHANGED"),
                err!(EACCES, "SOFTWARE_GUARD_LOST"),
                err!(EIO, "SOFTWARE_CODE_REFUSED"),
            ]
        },
        &mut |_, _| panic!("precommand refusal must not enter any executor"),
        &mut retained,
    );
    assert!(operation.unwrap_err().is("SOFTWARE_DESCRIPTOR_CHANGED"));
    assert_eq!(retained.len(), 3);
    assert!(!progress.bootstrap_attempted);
}

#[test]
fn every_command_failure_stops_after_one_attempt_without_retry() {
    for failure in [
        CommandFailure::Timeout,
        CommandFailure::OutputLimit,
        CommandFailure::Io,
        CommandFailure::Unavailable,
        CommandFailure::OwnershipUnknown,
    ] {
        let mut progress = receipt();
        progress.preflight_complete = true;
        let calls = Cell::new(0);
        let mut retained = Vec::new();
        let operation = register_one(
            &SupervisorCommand::for_target(&target()),
            &mut progress,
            until(),
            &mut |_| Vec::new(),
            &mut |_, _| {
                calls.set(calls.get() + 1);
                Err(failure)
            },
            &mut retained,
        );
        let report = finish(progress, operation, Vec::new(), retained);
        assert_eq!(calls.get(), 1);
        assert!(!report.successful && report.receipt.uncertain_command_effects);
        assert!(!report.receipt.bootstrap_succeeded);
        no_readiness(&report);
    }
}

#[test]
fn unknown_cleanup_remains_primary_while_all_postcommand_and_terminal_errors_survive() {
    let mut progress = receipt();
    progress.preflight_complete = true;
    let checks = Cell::new(0);
    let mut retained = Vec::new();
    let operation = register_one(
        &SupervisorCommand::for_target(&target()),
        &mut progress,
        until(),
        &mut |_| {
            checks.set(checks.get() + 1);
            if checks.get() == 1 {
                Vec::new()
            } else {
                vec![
                    err!(ESTALE, "SOFTWARE_DESCRIPTOR_CHANGED"),
                    err!(ESTALE, "SOFTWARE_PIN_CHANGED"),
                    err!(EACCES, "SOFTWARE_GUARD_LOST"),
                ]
            }
        },
        &mut |_, _| Err(CommandFailure::OwnershipUnknown),
        &mut retained,
    );
    let report = finish(
        progress,
        operation,
        vec![
            err!(EIO, "SOFTWARE_FINAL_ORIGINAL_LOST"),
            err!(ETIMEDOUT, "SOFTWARE_FINAL_LATE"),
        ],
        retained,
    );
    assert!(report
        .error
        .as_ref()
        .unwrap()
        .is("DEPLOYMENT_SUPERVISOR_BOOTSTRAP_CLEANUP_UNCERTAIN"));
    for reason in [
        "SOFTWARE_DESCRIPTOR_CHANGED",
        "SOFTWARE_PIN_CHANGED",
        "SOFTWARE_GUARD_LOST",
        "SOFTWARE_FINAL_ORIGINAL_LOST",
        "SOFTWARE_FINAL_LATE",
    ] {
        assert!(report.retained_errors.iter().any(|error| error.is(reason)));
    }
    assert_eq!(report.final_errors.len(), 2);
    assert!(report.receipt.uncertain_command_effects);
    no_readiness(&report);
}

#[test]
fn a_successful_command_and_later_original_failure_keep_the_successful_effect_observation() {
    let mut progress = receipt();
    progress.preflight_complete = true;
    let mut retained = Vec::new();
    let operation = register_one(
        &SupervisorCommand::for_target(&target()),
        &mut progress,
        until(),
        &mut |_| Vec::new(),
        &mut |_, _| Ok(output(Some(0))),
        &mut retained,
    );
    let report = finish(
        progress,
        operation,
        vec![err!(ESTALE, "SOFTWARE_FINAL_REPLACEMENT")],
        retained,
    );
    assert!(report.receipt.bootstrap_succeeded && report.receipt.bootstrap_attempted);
    assert!(
        !report.successful
            && !report.receipt.registration_complete
            && report.receipt.uncertain_command_effects
    );
    assert!(report.error.is_none());
    assert_eq!(report.final_errors.len(), 1);
    no_readiness(&report);
}

#[test]
fn each_command_deadline_only_shortens_the_original_operation_endpoint() {
    let mut progress = receipt();
    let mut retained = Vec::new();
    let original = until();
    let seen = RefCell::new(None);
    register_one(
        &SupervisorCommand::for_target(&target()),
        &mut progress,
        original,
        &mut |_| Vec::new(),
        &mut |_, end| {
            assert!(end <= original && end <= Instant::now() + COMMAND_LIMIT);
            *seen.borrow_mut() = Some(end);
            Ok(output(Some(0)))
        },
        &mut retained,
    )
    .unwrap();
    assert!(seen.borrow().is_some());
}

#[test]
fn expired_endpoint_prevents_registration_and_late_exit_zero_is_refused() {
    let mut progress = receipt();
    let mut retained = Vec::new();
    let result = register_one(
        &SupervisorCommand::for_target(&target()),
        &mut progress,
        Instant::now(),
        &mut |_| Vec::new(),
        &mut |_, _| panic!("expired endpoint must not enter executor"),
        &mut retained,
    );
    assert!(result.unwrap_err().is("DEPLOYMENT_SUPERVISOR_TIMEOUT"));
    assert!(!progress.bootstrap_attempted);
    let mut progress = receipt();
    progress.preflight_complete = true;
    let mut retained = Vec::new();
    let result = register_one(
        &SupervisorCommand::for_target(&target()),
        &mut progress,
        Instant::now() + Duration::from_millis(100),
        &mut |_| Vec::new(),
        &mut |_, end| {
            std::thread::sleep(
                end.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
            );
            Ok(output(Some(0)))
        },
        &mut retained,
    );
    let report = finish(progress, result, Vec::new(), retained);
    assert!(report
        .error
        .as_ref()
        .unwrap()
        .is("DEPLOYMENT_SUPERVISOR_TIMEOUT"));
    assert!(report.receipt.bootstrap_succeeded && report.receipt.uncertain_command_effects);
    no_readiness(&report);
}

#[test]
fn command_failure_precedes_late_endpoint_and_all_following_observations_still_run() {
    let mut progress = receipt();
    let mut retained = Vec::new();
    let checks = Cell::new(0);
    let result = register_one(
        &SupervisorCommand::for_target(&target()),
        &mut progress,
        Instant::now() + Duration::from_millis(100),
        &mut |_| {
            checks.set(checks.get() + 1);
            Vec::new()
        },
        &mut |_, end| {
            std::thread::sleep(
                end.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
            );
            Err(CommandFailure::OwnershipUnknown)
        },
        &mut retained,
    );
    assert!(result
        .unwrap_err()
        .is("DEPLOYMENT_SUPERVISOR_BOOTSTRAP_CLEANUP_UNCERTAIN"));
    assert!(retained
        .iter()
        .any(|error| error.is("DEPLOYMENT_SUPERVISOR_TIMEOUT")));
    assert_eq!(checks.get(), 2);
}

#[test]
fn a_report_or_invented_preflight_flag_cannot_override_the_private_production_runtime_gate() {
    let mut progress = receipt();
    progress.preflight_complete = true;
    progress.bootstrap_attempted = true;
    progress.bootstrap_succeeded = true;
    progress.first_begin_prerequisites_met = true;
    progress.qualified = true;
    let report = finish(progress, Ok(()), Vec::new(), Vec::new());
    assert!(report.successful);
    no_readiness(&report);
    assert!(require_selected_runtime()
        .unwrap_err()
        .is(RUNTIME_UNAVAILABLE));
    assert_eq!(
        report.receipt.selected_runtime,
        "UNAVAILABLE_VERIFY_ONLY_SELECTED_RUNTIME"
    );
}

#[test]
fn no_public_progress_or_error_serialization_exposes_raw_native_streams() {
    for code in [Some(0), Some(1), None] {
        let mut progress = receipt();
        progress.preflight_complete = true;
        let mut retained = Vec::new();
        let operation = register_one(
            &SupervisorCommand::for_target(&target()),
            &mut progress,
            until(),
            &mut |_| Vec::new(),
            &mut |_, _| Ok(output(code)),
            &mut retained,
        );
        let report = finish(progress, operation, Vec::new(), retained);
        assert!(!format!("{report:?}").contains("RAW_CHILD"));
        assert!(!serde_json::to_string(&report)
            .unwrap()
            .contains("RAW_CHILD"));
        no_readiness(&report);
    }
}
