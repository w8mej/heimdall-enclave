//! SOFTWARE boundary injection only. No real guard/root constructor, child,
//! install or purge executes. Public dry-run/confirmation refusal stays inert.
use super::*;
use crate::syscmd::Runner;
use enclave_core::err;
use std::{
    cell::Cell,
    os::unix::process::ExitStatusExt,
    path::PathBuf,
    process::{Command, ExitStatus, Output},
    rc::Rc,
};

struct FakeChild {
    calls: Rc<Cell<usize>>,
    exit: i32,
    spawn_error: bool,
}
impl Runner for FakeChild {
    fn status(&self, command: Command) -> std::io::Result<ExitStatus> {
        self.calls.set(self.calls.get() + 1);
        assert_eq!(command.get_program(), "/bin/sh");
        assert_eq!(command.get_args().nth(1).unwrap(), Script::Install.body());
        if self.spawn_error {
            return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        }
        Ok(ExitStatus::from_raw(self.exit << 8))
    }
    fn output(&self, _: Command) -> std::io::Result<Output> {
        panic!("installation does not spawn another checker")
    }
}
struct Fixture {
    base: PathBuf,
    calls: Rc<Cell<usize>>,
}
impl Fixture {
    fn new() -> Self {
        let parent = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target");
        std::fs::create_dir_all(&parent).unwrap();
        let base = parent.join(format!(
            "installer-boundary-{}-{}",
            std::process::id(),
            enclave_core::rng::u64()
        ));
        std::fs::create_dir(&base).unwrap();
        std::fs::write(base.join("codesign-pins.json"), b"{}").unwrap();
        Self {
            base,
            calls: Rc::new(Cell::new(0)),
        }
    }
    fn context<'a>(&self, runner: &'a dyn Runner) -> DeployCtx<'a> {
        DeployCtx {
            is_root: true,
            runner,
            anchors_dir: self.base.join("no-anchor-effects"),
            pf_conf: self.base.join("no-pf-effects"),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

#[test]
fn real_dry_run_path_and_unconfirmed_purge_do_not_require_native_guard() {
    // Invalid profile returns the existing policy error, not native/root lock
    // admission. No dist resolution or real process can occur on this branch.
    let (code, _, details) = run_install("invalid-profile", true, Some("/does-not-exist"));
    assert_eq!(code, 64);
    assert!(details["error"]
        .as_str()
        .unwrap()
        .contains("Unknown profile"));
    let (code, _, details) = crate::deploy::purge::run_purge("L2", false, true, true);
    assert_eq!(code, 60);
    assert_eq!(details["error"], "CONFIRMATION_REQUIRED");
}

#[test]
fn initial_guard_refusal_prevents_preflight_or_child_and_attempts_final_check() {
    let mut checks = 0;
    let mut entered = false;
    let (code, _, details) = maintenance_session(
        &mut || {
            checks += 1;
            Err(err!(ESTALE, "SYNTHETIC_GUARD_LOST"))
        },
        |_| {
            entered = true;
            panic!("preflight/operation cannot begin")
        },
    );
    assert!(!entered);
    assert_eq!(checks, 2);
    assert_eq!(code, 20);
    assert_eq!(details["error"], "DEPLOYMENT_MAINTENANCE_FAILED");
    assert_eq!(details["operation_outcome"]["details"]["stage"], "initial");
}

#[test]
fn failing_policy_and_missing_dist_still_receive_final_guard_check_without_child() {
    for invalid_profile in [true, false] {
        let fixture = Fixture::new();
        let runner = FakeChild {
            calls: fixture.calls.clone(),
            exit: 0,
            spawn_error: false,
        };
        let mut checks = 0;
        let (code, _, details) = maintenance_session(
            &mut || {
                checks += 1;
                Ok(())
            },
            |check| {
                install_with_checks(
                    if invalid_profile {
                        "invalid-profile"
                    } else {
                        "L2"
                    },
                    false,
                    fixture.base.join("missing").to_str(),
                    &fixture.context(&runner),
                    check,
                )
            },
        );
        assert_eq!(code, if invalid_profile { 64 } else { 20 });
        assert!(checks >= 4);
        assert_eq!(fixture.calls.get(), 0);
        if !invalid_profile {
            assert_eq!(details["error"], "INSTALL_DIST_MISSING");
        }
    }
}

#[test]
fn child_error_with_lost_guard_preserves_original_failure_and_no_further_child() {
    let fixture = Fixture::new();
    let runner = FakeChild {
        calls: fixture.calls.clone(),
        exit: 7,
        spawn_error: false,
    };
    let checks_after = Cell::new(0);
    let (code, _, details) = maintenance_session(
        &mut || {
            if fixture.calls.get() != 0 {
                checks_after.set(checks_after.get() + 1);
                return Err(err!(ESTALE, "SYNTHETIC_GUARD_LOST"));
            }
            Ok(())
        },
        |check| {
            install_with_checks(
                "L2",
                false,
                fixture.base.to_str(),
                &fixture.context(&runner),
                check,
            )
        },
    );
    assert_eq!(code, 20);
    assert_eq!(fixture.calls.get(), 1);
    assert_eq!(checks_after.get(), 2);
    assert_eq!(details["stage"], "final");
    let child = &details["operation_outcome"]["details"];
    assert_eq!(child["stage"], "embedded_install_child");
    assert_eq!(child["boundary_phase"], "after");
    assert_eq!(
        child["operation_outcome"]["details"]["error"],
        "INSTALL_SCRIPT_FAILED"
    );
    assert_eq!(details["rollback_performed"], false);
    assert!(!fixture.base.join("no-pf-effects").exists());
}

#[test]
fn successful_child_cannot_report_success_after_guard_loss() {
    let fixture = Fixture::new();
    let runner = FakeChild {
        calls: fixture.calls.clone(),
        exit: 0,
        spawn_error: false,
    };
    let (code, _, details) = maintenance_session(
        &mut || {
            if fixture.calls.get() != 0 {
                Err(err!(ESTALE, "SYNTHETIC_GUARD_LOST"))
            } else {
                Ok(())
            }
        },
        |check| {
            install_with_checks(
                "L2",
                false,
                fixture.base.to_str(),
                &fixture.context(&runner),
                check,
            )
        },
    );
    assert_eq!(code, 20);
    assert_eq!(fixture.calls.get(), 1);
    assert_eq!(details["stage"], "final");
    assert_eq!(
        details["operation_outcome"]["details"]["stage"],
        "embedded_install_child"
    );
    assert_eq!(
        details["operation_outcome"]["details"]["operation_returned_ok"],
        true
    );
    assert_eq!(details["inactivity_proven"], false);
    assert_eq!(details["installation_qualified"], false);
}

#[test]
fn spawn_failure_receives_both_postchecks_and_preserves_existing_error_when_guard_stays_current() {
    let fixture = Fixture::new();
    let runner = FakeChild {
        calls: fixture.calls.clone(),
        exit: 0,
        spawn_error: true,
    };
    let checks_after = Cell::new(0);
    let (code, _, details) = maintenance_session(
        &mut || {
            if fixture.calls.get() != 0 {
                checks_after.set(checks_after.get() + 1);
            }
            Ok(())
        },
        |check| {
            install_with_checks(
                "L2",
                false,
                fixture.base.to_str(),
                &fixture.context(&runner),
                check,
            )
        },
    );
    assert_eq!(code, 20);
    assert_eq!(fixture.calls.get(), 1);
    assert_eq!(checks_after.get(), 2);
    assert_eq!(details["error"], "SPAWN_ERROR");
}

#[test]
fn final_guard_refusal_retains_prior_successful_installer_outcome() {
    let fixture = Fixture::new();
    let runner = FakeChild {
        calls: fixture.calls.clone(),
        exit: 0,
        spawn_error: false,
    };
    let checks_after = Cell::new(0);
    let (code, _, details) = maintenance_session(
        &mut || {
            if fixture.calls.get() != 0 {
                checks_after.set(checks_after.get() + 1);
                if checks_after.get() == 2 {
                    return Err(err!(ESTALE, "SYNTHETIC_FINAL_GUARD_LOST"));
                }
            }
            Ok(())
        },
        |check| {
            install_with_checks(
                "L2",
                false,
                fixture.base.to_str(),
                &fixture.context(&runner),
                check,
            )
        },
    );
    assert_eq!(code, 20);
    assert_eq!(fixture.calls.get(), 1);
    assert_eq!(details["stage"], "final");
    assert_eq!(details["operation_outcome"]["exit_code"], 0);
    assert_eq!(details["operation_outcome"]["details"]["status"], "ok");
}
