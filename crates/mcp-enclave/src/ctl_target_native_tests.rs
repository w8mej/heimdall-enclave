//! SOFTWARE adapter tests with injected native results and public fixture data.
//! No native verifier, launchctl, maintenance guard or production deployment
//! capability is constructed. /dev/null supplies only a borrowed inert FD.
use super::target_lifecycle::{CoreAction, CoreResourceView};
use super::*;
use enclave_core::{codesign::TEAM_ID, error::Errno};
use std::{
    cell::Cell,
    fs::File,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    time::Duration,
};

const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const RAW_STDOUT: &[u8] = b"SYNTHETIC-CHILD-STDOUT-MUST-NOT-ESCAPE\x00\xff";
const RAW_STDERR: &[u8] = b"SYNTHETIC-CHILD-STDERR-MUST-NOT-ESCAPE\n\xfe";

struct ViewFixture {
    file: File,
    executable: PathBuf,
    code: PathBuf,
    resource: PathBuf,
}
impl ViewFixture {
    fn new(daemon: DaemonId) -> Self {
        let code = PathBuf::from("/synthetic-adapter-fixture/Custody.app");
        let executable = if daemon == DaemonId::CustodyVault {
            code.join("Contents/MacOS").join(daemon.binary())
        } else {
            Path::new("/synthetic-adapter-fixture/bin").join(daemon.binary())
        };
        let resource = code.join("Contents/Info.plist");
        Self {
            file: File::open("/dev/null").unwrap(),
            code: if daemon == DaemonId::CustodyVault {
                code
            } else {
                executable.clone()
            },
            executable,
            resource,
        }
    }
    fn view<'a>(
        &'a self,
        daemon: DaemonId,
        revalidate: &'a dyn Fn() -> EnclaveResult<()>,
    ) -> CoreCodeView<'a> {
        let members = if daemon == DaemonId::CustodyVault {
            vec![CoreResourceView {
                path: &self.resource,
                file: &self.file,
                sha256: HASH,
                size: 23,
            }]
        } else {
            vec![]
        };
        CoreCodeView {
            code_path: &self.code,
            executable_path: &self.executable,
            executable: &self.file,
            executable_sha256: HASH,
            executable_size: 47,
            members,
            revalidate,
        }
    }
}
fn requirement(daemon: DaemonId) -> CodeRequirement {
    CodeRequirement {
        identifier: daemon.launchd_label(),
        team_id: TEAM_ID.into(),
        cdhash_allowlist: vec!["ab".repeat(20)],
    }
}
fn future() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

#[test]
fn native_success_and_refusal_preserve_all_five_exact_views_and_binding_brackets() {
    for daemon in DaemonId::ALL {
        for native_fails in [false, true] {
            let fixture = ViewFixture::new(daemon);
            let events = RefCell::new(Vec::new());
            let binding = || {
                events.borrow_mut().push("binding");
                Ok(())
            };
            let view = fixture.view(daemon, &binding);
            let req = requirement(daemon);
            let result = verify_view(daemon, &view, &req, future(), |shape, observed, policy| {
                events.borrow_mut().push("native");
                assert!(std::ptr::eq(observed, &req));
                let executable = match shape {
                    NativeCodeShape::Executable(executable) => {
                        assert_ne!(daemon, DaemonId::CustodyVault);
                        assert_eq!(policy, NativeEntitlementPolicy::DaemonBaseline);
                        executable
                    }
                    NativeCodeShape::Bundle {
                        root,
                        executable,
                        members,
                    } => {
                        assert_eq!(daemon, DaemonId::CustodyVault);
                        assert_eq!(root, fixture.code.as_path());
                        assert_eq!(
                            policy,
                            NativeEntitlementPolicy::CustodyForCompiledSigningMode
                        );
                        assert_eq!(members.len(), 1);
                        assert_eq!(members[0].path, fixture.resource.as_path());
                        assert_eq!(members[0].file.as_raw_fd(), fixture.file.as_raw_fd());
                        assert_eq!(members[0].sha256, HASH);
                        assert_eq!(members[0].size, 23);
                        executable
                    }
                };
                assert_eq!(executable.path, fixture.executable.as_path());
                assert_eq!(executable.file.as_raw_fd(), fixture.file.as_raw_fd());
                assert_eq!(executable.sha256, HASH);
                assert_eq!(executable.size, 47);
                if native_fails {
                    Err(err!(EACCES, "SYNTHETIC_NATIVE_REFUSAL"))
                } else {
                    Ok(())
                }
            });
            if native_fails {
                assert!(result.unwrap_err().is("SYNTHETIC_NATIVE_REFUSAL"));
            } else {
                result.unwrap();
            }
            assert_eq!(*events.borrow(), ["binding", "native", "binding"]);
        }
    }
}

#[test]
fn initial_binding_refusal_never_enters_native_and_postcheck_refusal_overrides_native_result() {
    for failed_check in [1, 2] {
        for native_fails in [false, true] {
            let daemon = DaemonId::CustodyVault;
            let fixture = ViewFixture::new(daemon);
            let checks = Cell::new(0);
            let native_calls = Cell::new(0);
            let binding = || {
                checks.set(checks.get() + 1);
                if checks.get() == failed_check {
                    Err(err!(ESTALE, "SYNTHETIC_BINDING_CHANGED"))
                } else {
                    Ok(())
                }
            };
            let error = verify_view(
                daemon,
                &fixture.view(daemon, &binding),
                &requirement(daemon),
                future(),
                |_, _, _| {
                    native_calls.set(native_calls.get() + 1);
                    if native_fails {
                        Err(err!(EACCES, "SYNTHETIC_NATIVE_REFUSAL"))
                    } else {
                        Ok(())
                    }
                },
            )
            .unwrap_err();
            assert!(error.is("SYNTHETIC_BINDING_CHANGED"));
            assert_eq!(checks.get(), failed_check);
            assert_eq!(native_calls.get(), failed_check - 1);
        }
    }
}

#[test]
fn mismatched_original_daemon_identifier_refuses_before_binding_or_native() {
    for daemon in DaemonId::ALL {
        for foreign in DaemonId::ALL {
            if daemon == foreign {
                continue;
            }
            let fixture = ViewFixture::new(daemon);
            let binding = || panic!("wrong role must refuse before protected binding inspection");
            let error = verify_view(
                daemon,
                &fixture.view(daemon, &binding),
                &requirement(foreign),
                future(),
                |_, _, _| panic!("wrong role must not enter native verifier"),
            )
            .unwrap_err();
            assert!(error.is("DEPLOYMENT_NATIVE_CODE_ROLE"));
        }
    }
}

#[test]
fn noncustody_bundle_root_or_resource_members_refuse_before_native() {
    for daemon in DaemonId::ALL {
        if daemon == DaemonId::CustodyVault {
            continue;
        }
        for extra_member in [false, true] {
            let fixture = ViewFixture::new(daemon);
            let checks = Cell::new(0);
            let binding = || {
                checks.set(checks.get() + 1);
                Ok(())
            };
            let mut view = fixture.view(daemon, &binding);
            if extra_member {
                view.members.push(CoreResourceView {
                    path: &fixture.resource,
                    file: &fixture.file,
                    sha256: HASH,
                    size: 23,
                });
            } else {
                view.code_path = Path::new("/synthetic-adapter-fixture/Foreign.app");
            }
            let error = verify_view(daemon, &view, &requirement(daemon), future(), |_, _, _| {
                panic!("invalid executable shape must not enter native verifier")
            })
            .unwrap_err();
            assert!(error.is("DEPLOYMENT_NATIVE_CODE_SHAPE"));
            assert_eq!(checks.get(), 1);
        }
    }
}

#[test]
fn expired_deadline_refuses_before_binding_or_native() {
    deadline(future()).unwrap();
    let daemon = DaemonId::SwarmSync;
    let fixture = ViewFixture::new(daemon);
    let binding = || panic!("expired admission must not inspect binding");
    let error = verify_view(
        daemon,
        &fixture.view(daemon, &binding),
        &requirement(daemon),
        Instant::now(),
        |_, _, _| panic!("expired admission must not enter native verifier"),
    )
    .unwrap_err();
    assert_eq!(error.errno, Errno::ETIMEDOUT);
    assert!(error.is("DEPLOYMENT_LIFECYCLE_TIMEOUT"));
}

fn wait_until(until: Instant) {
    // Force the injected callback's completion past its actual monotonic cutoff.
    // This checks admission behavior, not a performance/ceremony timing budget.
    while Instant::now() < until {
        std::thread::sleep(until.saturating_duration_since(Instant::now()));
    }
}
#[test]
fn precheck_finishing_after_deadline_refuses_before_native() {
    let daemon = DaemonId::SwarmSync;
    let fixture = ViewFixture::new(daemon);
    let checks = Cell::new(0);
    let until = Instant::now() + Duration::from_millis(100);
    let binding = || {
        checks.set(checks.get() + 1);
        wait_until(until);
        Ok(())
    };
    let error = verify_view(
        daemon,
        &fixture.view(daemon, &binding),
        &requirement(daemon),
        until,
        |_, _, _| panic!("late protected precheck must not enter native verifier"),
    )
    .unwrap_err();
    assert!(error.is("DEPLOYMENT_LIFECYCLE_TIMEOUT"));
    assert_eq!(checks.get(), 1);
}

#[test]
fn late_native_completion_still_rechecks_binding_and_cannot_return_success_or_native_error() {
    for native_fails in [false, true] {
        let daemon = DaemonId::CustodyVault;
        let fixture = ViewFixture::new(daemon);
        let checks = Cell::new(0);
        let binding = || {
            checks.set(checks.get() + 1);
            Ok(())
        };
        let until = Instant::now() + Duration::from_millis(100);
        let native_calls = Cell::new(0);
        let error = verify_view(
            daemon,
            &fixture.view(daemon, &binding),
            &requirement(daemon),
            until,
            |_, _, _| {
                native_calls.set(native_calls.get() + 1);
                wait_until(until);
                if native_fails {
                    Err(err!(EACCES, "SYNTHETIC_NATIVE_REFUSAL"))
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
        assert!(error.is("DEPLOYMENT_LIFECYCLE_TIMEOUT"));
        assert_eq!(checks.get(), 2);
        assert_eq!(native_calls.get(), 1);
    }
}

fn output(code: Option<i32>) -> NativeOutput {
    NativeOutput {
        code,
        stdout: RAW_STDOUT.to_vec(),
        stderr: RAW_STDERR.to_vec(),
        contract: None,
    }
}
fn assert_no_child_output(value: &impl std::fmt::Debug) {
    let text = format!("{value:?}");
    assert!(!text.contains("SYNTHETIC-CHILD-STDOUT"));
    assert!(!text.contains("SYNTHETIC-CHILD-STDERR"));
}
#[test]
fn command_result_accepts_only_zero_and_redacts_nonzero_missing_and_each_executor_failure() {
    command_result(Ok(output(Some(0)))).unwrap();
    for code in [None, Some(-1), Some(1), Some(3), Some(i32::MAX)] {
        let error = command_result(Ok(output(code))).unwrap_err();
        assert_eq!(error.errno, Errno::EIO);
        assert!(error.is("DEPLOYMENT_LAUNCHCTL_FAILED"));
        assert!(error.detail.is_empty());
        assert_no_child_output(&error);
        assert_no_child_output(&serde_json::to_value(&error).unwrap());
    }
    for (failure, errno, reason) in [
        (
            CommandFailure::Timeout,
            Errno::ETIMEDOUT,
            "DEPLOYMENT_LAUNCHCTL_TIMEOUT",
        ),
        (
            CommandFailure::OutputLimit,
            Errno::E2BIG,
            "DEPLOYMENT_LAUNCHCTL_OUTPUT_LIMIT",
        ),
        (
            CommandFailure::OwnershipUnknown,
            Errno::EIO,
            "DEPLOYMENT_LAUNCHCTL_CLEANUP_UNCERTAIN",
        ),
        (
            CommandFailure::Unavailable,
            Errno::EIO,
            "DEPLOYMENT_LAUNCHCTL_UNAVAILABLE",
        ),
        (
            CommandFailure::Io,
            Errno::EIO,
            "DEPLOYMENT_LAUNCHCTL_UNAVAILABLE",
        ),
    ] {
        let error = command_result(Err(failure)).unwrap_err();
        assert_eq!(error.errno, errno);
        assert!(error.is(reason));
        assert!(error.detail.is_empty());
        assert_no_child_output(&error);
    }
}

fn receipt(action: CoreAction, completed: usize, uncertain: bool) -> CoreLifecycleReceipt {
    let mut labels = vec!["cas", "custody", "adapter", "ifc", "zk"];
    if action == CoreAction::Stop {
        labels.reverse();
    }
    let labels = labels
        .into_iter()
        .map(|suffix| format!("com.mcpmac.synthetic.{suffix}"))
        .collect::<Vec<_>>();
    CoreLifecycleReceipt {
        target_id: "synthetic-adapter-target".into(),
        descriptor_sha256: HASH.into(),
        action,
        scope: "CORE_FIVE_LAUNCHD_REGISTRATIONS_ONLY_AUXILIARY_JOBS_EXCLUDED",
        completed_labels: labels[..completed].to_vec(),
        boundary_label: labels.get(completed).cloned(),
        uncertain_command_effects: uncertain,
        complete: completed == 5,
        readiness: "UNKNOWN_RUNTIME_AND_FULL_INSTALLATION_READINESS",
        qualified: false,
    }
}
#[test]
fn operation_and_final_maintenance_failures_preserve_each_exact_completed_prefix() {
    for action in [CoreAction::Start, CoreAction::Stop] {
        for completed in 0..5 {
            for uncertain in [false, true] {
                for maintenance_fails in [false, true] {
                    let receipt = receipt(action, completed, uncertain);
                    let expected = serde_json::to_value(&receipt).unwrap();
                    let maintenance = if maintenance_fails {
                        Err(err!(ESTALE, "SYNTHETIC_FINAL_EXCLUSION_FAILURE"))
                    } else {
                        Ok(())
                    };
                    let report = report(
                        Err(CoreLifecycleFailure {
                            error: err!(EIO, "SYNTHETIC_OPERATION_FAILURE"),
                            receipt,
                        }),
                        maintenance,
                    )
                    .unwrap();
                    assert!(!report.successful);
                    assert_eq!(report.receipt, expected);
                    assert!(report
                        .error
                        .as_ref()
                        .unwrap()
                        .is("SYNTHETIC_OPERATION_FAILURE"));
                    assert_eq!(report.maintenance_error.is_some(), maintenance_fails);
                    if maintenance_fails {
                        assert!(report
                            .maintenance_error
                            .as_ref()
                            .unwrap()
                            .is("SYNTHETIC_FINAL_EXCLUSION_FAILURE"));
                    }
                    assert_eq!(
                        report.receipt["completed_labels"].as_array().unwrap().len(),
                        completed
                    );
                    assert_eq!(report.receipt["uncertain_command_effects"], uncertain);
                    assert_eq!(report.receipt["complete"], false);
                    assert_eq!(report.receipt["qualified"], false);
                }
            }
        }
    }
}

#[test]
fn final_exclusion_failure_retains_complete_receipt_and_success_requires_complete_operation() {
    for action in [CoreAction::Start, CoreAction::Stop] {
        for maintenance_fails in [false, true] {
            let receipt = receipt(action, 5, false);
            let expected = serde_json::to_value(&receipt).unwrap();
            let maintenance = if maintenance_fails {
                Err(err!(ESTALE, "SYNTHETIC_FINAL_EXCLUSION_FAILURE"))
            } else {
                Ok(())
            };
            let report = report(Ok(receipt), maintenance).unwrap();
            assert_eq!(report.successful, !maintenance_fails);
            assert!(report.error.is_none());
            assert_eq!(report.maintenance_error.is_some(), maintenance_fails);
            assert_eq!(report.receipt, expected);
            assert_eq!(report.receipt["complete"], true);
            assert_eq!(report.receipt["qualified"], false);
            assert!(report.receipt["readiness"]
                .as_str()
                .unwrap()
                .starts_with("UNKNOWN"));
        }
    }
    let report = report(Ok(receipt(CoreAction::Start, 2, false)), Ok(())).unwrap();
    assert!(!report.successful);
    assert!(report.error.is_none());
    assert!(report.maintenance_error.is_none());
}

#[test]
fn serialized_failure_report_cannot_export_launchctl_stdout_or_stderr() {
    for code in [None, Some(1)] {
        let error = command_result(Ok(output(code))).unwrap_err();
        let report = report(
            Err(CoreLifecycleFailure {
                error,
                receipt: receipt(CoreAction::Stop, 2, true),
            }),
            Ok(()),
        )
        .unwrap();
        assert!(!report.successful);
        assert_no_child_output(&report);
        let encoded = serde_json::to_string(&report).unwrap();
        assert_no_child_output(&encoded);
        assert!(encoded.contains("DEPLOYMENT_LAUNCHCTL_FAILED"));
        assert_eq!(
            report.receipt["completed_labels"].as_array().unwrap().len(),
            2
        );
        assert_eq!(report.receipt["uncertain_command_effects"], true);
    }
}

fn auxiliary_receipt(complete: bool) -> crate::ctl::target_aux_stop::AuxiliaryStopReceipt {
    crate::ctl::target_aux_stop::AuxiliaryStopReceipt {
        target_id: "synthetic-auxiliary-target".into(),
        descriptor_sha256: HASH.into(),
        scope: "SELECTED_NONBROKER_AUXILIARY_REGISTRATIONS",
        gui_candidate_uids: vec![501, 502],
        bootout_succeeded: vec!["system/com.mcpmac.synthetic.hydrate".into()],
        completed_jobs: vec![],
        already_absent_jobs: vec![],
        boundary_job: Some("system/com.mcpmac.synthetic.hydrate".into()),
        uncertain_command_effects: !complete,
        complete,
        core_jobs: "NOT_OPERATED_BY_THIS_SCOPE",
        broker_quiescence: "UNKNOWN_NOT_PERFORMED",
        inactivity_proven: false,
        installation_supported: false,
        qualified: false,
    }
}

#[test]
fn auxiliary_report_preserves_progress_and_all_three_independent_failure_categories() {
    for final_fails in [false, true] {
        for maintenance_fails in [false, true] {
            let receipt = auxiliary_receipt(false);
            let expected = serde_json::to_value(&receipt).unwrap();
            let final_binding_error =
                final_fails.then(|| err!(ESTALE, "SYNTHETIC_DESCRIPTOR_CHANGED"));
            let maintenance = if maintenance_fails {
                Err(err!(ESTALE, "SYNTHETIC_FINAL_EXCLUSION_FAILURE"))
            } else {
                Ok(())
            };
            let report = auxiliary_report(
                Err(crate::ctl::target_aux_stop::AuxiliaryStopFailure {
                    receipt,
                    error: err!(EIO, "SYNTHETIC_OPERATION_FAILURE"),
                    final_binding_error,
                }),
                maintenance,
            )
            .unwrap();
            assert!(!report.successful);
            assert_eq!(report.receipt, expected);
            assert!(report.error.unwrap().is("SYNTHETIC_OPERATION_FAILURE"));
            assert_eq!(report.final_binding_error.is_some(), final_fails);
            assert_eq!(report.maintenance_error.is_some(), maintenance_fails);
            assert_eq!(report.receipt["uncertain_command_effects"], true);
            assert_eq!(report.receipt["broker_quiescence"], "UNKNOWN_NOT_PERFORMED");
            assert_eq!(report.receipt["inactivity_proven"], false);
        }
    }
}

#[test]
fn auxiliary_report_requires_completed_scope_and_final_guard_without_claiming_installation() {
    for complete in [false, true] {
        for maintenance_fails in [false, true] {
            let maintenance = if maintenance_fails {
                Err(err!(ESTALE, "SYNTHETIC_FINAL_EXCLUSION_FAILURE"))
            } else {
                Ok(())
            };
            let report = auxiliary_report(Ok(auxiliary_receipt(complete)), maintenance).unwrap();
            assert_eq!(report.successful, complete && !maintenance_fails);
            assert_eq!(report.receipt["complete"], complete);
            assert_eq!(report.receipt["qualified"], false);
            assert_eq!(report.receipt["installation_supported"], false);
            assert_eq!(report.receipt["core_jobs"], "NOT_OPERATED_BY_THIS_SCOPE");
            assert!(report.error.is_none() && report.final_binding_error.is_none());
        }
    }
}

fn broker_receipt(complete: bool) -> crate::ctl::target_broker_stop::BrokerStopReceipt {
    crate::ctl::target_broker_stop::BrokerStopReceipt {
        target_id: "synthetic-broker-target".into(),
        descriptor_sha256: HASH.into(),
        scope: "SELECTED_AUTHENTICATED_LIVE_BROKER_BARRIER_AND_REGISTRATION_ONLY",
        job: "system/com.mcpmac.synthetic.apfs-broker".into(),
        quiescence_attempted: true,
        authenticated_quiescence_confirmed: complete,
        uncertain_quiescence_effects: !complete,
        bootout_succeeded: complete,
        already_absent: false,
        registration_absence_observed: complete,
        uncertain_command_effects: !complete,
        complete,
        inactivity_proven: false,
        installation_supported: false,
        qualified: false,
    }
}

#[test]
fn broker_report_preserves_uncertainty_and_every_independent_failure_category() {
    for final_fails in [false, true] {
        for maintenance_fails in [false, true] {
            let receipt = broker_receipt(false);
            let expected = serde_json::to_value(&receipt).unwrap();
            let final_binding_error =
                final_fails.then(|| err!(ESTALE, "SYNTHETIC_DESCRIPTOR_CHANGED"));
            let maintenance = if maintenance_fails {
                Err(err!(ESTALE, "SYNTHETIC_FINAL_EXCLUSION_FAILURE"))
            } else {
                Ok(())
            };
            let report = broker_report(
                Err(crate::ctl::target_broker_stop::BrokerStopFailure {
                    receipt,
                    error: err!(EIO, "SYNTHETIC_BARRIER_FAILURE"),
                    final_binding_error,
                }),
                maintenance,
            )
            .unwrap();
            assert!(!report.successful);
            assert_eq!(report.receipt, expected);
            assert!(report.error.unwrap().is("SYNTHETIC_BARRIER_FAILURE"));
            assert_eq!(report.final_binding_error.is_some(), final_fails);
            assert_eq!(report.maintenance_error.is_some(), maintenance_fails);
            assert_eq!(report.receipt["uncertain_quiescence_effects"], true);
        }
    }
}

#[test]
fn broker_report_requires_completion_and_guard_without_installation_authority() {
    for complete in [false, true] {
        for maintenance_fails in [false, true] {
            let maintenance = if maintenance_fails {
                Err(err!(ESTALE, "SYNTHETIC_FINAL_EXCLUSION_FAILURE"))
            } else {
                Ok(())
            };
            let report = broker_report(Ok(broker_receipt(complete)), maintenance).unwrap();
            assert_eq!(report.successful, complete && !maintenance_fails);
            assert_eq!(report.receipt["complete"], complete);
            for field in ["qualified", "installation_supported", "inactivity_proven"] {
                assert_eq!(report.receipt[field], false);
            }
            assert!(report.error.is_none() && report.final_binding_error.is_none());
        }
    }
}

#[test]
#[ignore = "requires actual protected private-root filesystem"]
fn actual_original_file_change_and_native_refusal_both_survive_primary_postcheck_error() {
    use super::target_lifecycle::{HeldFile, HeldPaths};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "actual private root required"
    );
    let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&parent)
        .unwrap();
    let base = parent.join(format!(
        "native-adapter-errors-{}",
        hex::encode(enclave_core::rng::bytes32())
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&base)
        .unwrap();
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let cleanup = Cleanup(base.canonicalize().unwrap());
    let path = cleanup.0.join("original-public-executable");
    for retained_path in [false, true] {
        std::fs::write(&path, b"ordinary-public-original").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut paths = HeldPaths::new().unwrap();
        let (held, _) = HeldFile::open(&mut paths, &path, 4096, Some(0o644)).unwrap();
        let original_fd = held.file().as_raw_fd();
        let revalidate = || held.revalidate(&paths);
        let view = CoreCodeView {
            code_path: held.path(),
            executable_path: held.path(),
            executable: held.file(),
            executable_sha256: held.sha256(),
            executable_size: held.size(),
            members: vec![],
            revalidate: &revalidate,
        };
        let daemon = DaemonId::SwarmSync;
        let req = requirement(daemon);
        let calls = Cell::new(0);
        let native = |shape: NativeCodeShape<'_>,
                      req_seen: &CodeRequirement,
                      _: NativeEntitlementPolicy| {
            calls.set(calls.get() + 1);
            assert!(std::ptr::eq(req_seen, &req));
            let NativeCodeShape::Executable(original)=shape else {panic!("CAS executable required");};
            assert_eq!(original.file.as_raw_fd(), original_fd);
            // Change the actual retained original inode through its existing
            // name. The ensuing refusal comes from production HeldFile checks.
            std::fs::write(&path, b"ordinary-public-mutated-different-size").unwrap();
            Err(err!(EACCES, "SYNTHETIC_NATIVE_REFUSAL"))
        };
        let mut errors = Vec::new();
        let result = if retained_path {
            verify_view_retaining(daemon, &view, &req, future(), native, |results| {
                retain_result_errors(&mut errors, results);
                Ok(())
            })
        } else {
            verify_view(daemon, &view, &req, future(), native)
        };
        assert!(result.unwrap_err().is("DEPLOYMENT_LIFECYCLE_FILE_CHANGED"));
        assert_eq!(calls.get(), 1);
        assert!(held
            .revalidate(&paths)
            .unwrap_err()
            .is("DEPLOYMENT_LIFECYCLE_FILE_CHANGED"));
        if retained_path {
            assert_eq!(errors.len(), 2);
            assert_eq!(errors[0], err!(EACCES, "SYNTHETIC_NATIVE_REFUSAL"));
            assert_eq!(errors[1], err!(ESTALE, "DEPLOYMENT_LIFECYCLE_FILE_CHANGED"));
        } else {
            assert!(errors.is_empty());
        }
    }
}
