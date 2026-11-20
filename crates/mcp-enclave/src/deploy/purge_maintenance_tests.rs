//! Injected SOFTWARE child/boundary tests only; no native lock or purge.
use super::*;
use crate::syscmd::Runner;
use enclave_core::err;
use std::{
    cell::Cell,
    os::unix::process::ExitStatusExt,
    path::PathBuf,
    process::{Command, ExitStatus, Output},
};
struct Child {
    calls: Cell<usize>,
    exit: i32,
}
impl Runner for Child {
    fn status(&self, command: Command) -> std::io::Result<ExitStatus> {
        self.calls.set(self.calls.get() + 1);
        let args = command
            .get_args()
            .map(|a| a.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            args,
            [
                "-c",
                Script::Uninstall.body(),
                Script::Uninstall.argv0(),
                "--purge-state",
                "--remove-accounts"
            ]
        );
        Ok(ExitStatus::from_raw(self.exit << 8))
    }
    fn output(&self, _: Command) -> std::io::Result<Output> {
        panic!("no additional child")
    }
}
fn context(child: &Child) -> DeployCtx<'_> {
    DeployCtx {
        is_root: true,
        runner: child,
        anchors_dir: PathBuf::from("/unused-purge-fixture"),
        pf_conf: PathBuf::from("/unused-purge-fixture/pf.conf"),
    }
}
#[test]
fn missing_confirmation_precedes_every_boundary_or_child() {
    let child = Child {
        calls: Cell::new(0),
        exit: 0,
    };
    let (code, _, details) =
        purge_with_checks("L2", false, true, true, &context(&child), &mut || {
            panic!("no guard on unconfirmed purge")
        });
    assert_eq!(code, 60);
    assert_eq!(details["error"], "CONFIRMATION_REQUIRED");
    assert_eq!(child.calls.get(), 0);
}
#[test]
fn prechild_boundary_refusal_prevents_destructive_command() {
    let child = Child {
        calls: Cell::new(0),
        exit: 0,
    };
    let (code, _, details) =
        purge_with_checks("L2", true, true, true, &context(&child), &mut || {
            Err(err!(ESTALE, "SYNTHETIC_GUARD_LOST"))
        });
    assert_eq!(code, 20);
    assert_eq!(child.calls.get(), 0);
    assert_eq!(details["stage"], "embedded_uninstall_child");
    assert_eq!(details["boundary_phase"], "before");
}
#[test]
fn failed_destructive_child_with_lost_boundary_retains_original_error() {
    let child = Child {
        calls: Cell::new(0),
        exit: 5,
    };
    let mut checks_after = 0;
    let (code, _, details) =
        purge_with_checks("L2", true, true, true, &context(&child), &mut || {
            if child.calls.get() != 0 {
                checks_after += 1;
                Err(err!(ESTALE, "SYNTHETIC_GUARD_LOST"))
            } else {
                Ok(())
            }
        });
    assert_eq!(code, 20);
    assert_eq!(child.calls.get(), 1);
    assert_eq!(checks_after, 1);
    assert_eq!(details["boundary_phase"], "after");
    assert_eq!(
        details["operation_outcome"]["details"]["error"],
        "UNINSTALL_SCRIPT_FAILED"
    );
    assert_eq!(details["rollback_performed"], false);
}
#[test]
fn successful_destructive_child_with_lost_boundary_refuses_success() {
    let child = Child {
        calls: Cell::new(0),
        exit: 0,
    };
    let (code, _, details) =
        purge_with_checks("L2", true, true, true, &context(&child), &mut || {
            if child.calls.get() != 0 {
                Err(err!(ESTALE, "SYNTHETIC_GUARD_LOST"))
            } else {
                Ok(())
            }
        });
    assert_eq!(code, 20);
    assert_eq!(child.calls.get(), 1);
    assert_eq!(details["boundary_phase"], "after");
    assert_eq!(details["error"], "DEPLOYMENT_MAINTENANCE_FAILED");
    assert_eq!(details["inactivity_proven"], false);
    assert_eq!(details["operation_returned_ok"], true);
}
