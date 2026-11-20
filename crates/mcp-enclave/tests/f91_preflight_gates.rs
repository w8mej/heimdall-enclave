//! DEFECT-F-91: FileVault and SIP preflight gates fail closed and match
//! exact status lines. The probes are fed canned `fdesetup` / `csrutil`
//! outputs through a fake runner; nothing on the host is changed.
#![cfg(target_os = "macos")]

use depot_enclave::deploy::preflight::evaluate_preflight_with;
use depot_enclave::syscmd::Runner;
use std::cell::RefCell;
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus, Output};

/// Canned answer for one tool: `Ok((exit, stdout))` or a spawn error.
type Answer = Result<(i32, &'static str), ()>;

struct Fake {
    fdesetup: Answer,
    csrutil: Answer,
    seen: RefCell<Vec<(String, Vec<String>)>>,
}

impl Fake {
    fn new(fdesetup: Answer, csrutil: Answer) -> Self {
        Self {
            fdesetup,
            csrutil,
            seen: RefCell::new(Vec::new()),
        }
    }
}

impl Runner for Fake {
    fn status(&self, cmd: Command) -> io::Result<ExitStatus> {
        self.output(cmd).map(|o| o.status)
    }
    fn output(&self, cmd: Command) -> io::Result<Output> {
        let prog = cmd.get_program().to_string_lossy().into_owned();
        let args = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        self.seen.borrow_mut().push((prog.clone(), args));
        let answer = match prog.as_str() {
            "/usr/bin/fdesetup" => self.fdesetup,
            "/usr/bin/csrutil" => self.csrutil,
            other => panic!("unexpected program {other}"),
        };
        match answer {
            Ok((code, out)) => Ok(Output {
                status: ExitStatus::from_raw(code << 8),
                stdout: out.as_bytes().to_vec(),
                stderr: Vec::new(),
            }),
            Err(()) => Err(io::Error::new(io::ErrorKind::NotFound, "no such tool")),
        }
    }
}

const FV_ON: Answer = Ok((0, "FileVault is On.\n"));
const SIP_ON: Answer = Ok((0, "System Integrity Protection status: enabled.\n"));
/// `csrutil status` after `csrutil enable --without debug` (the review's VM).
const SIP_WITHOUT_DEBUG: Answer = Ok((
    0,
    "System Integrity Protection status: unknown (Custom Configuration).\n\nConfiguration:\n\tApple Internal: disabled\n\tKext Signing: enabled\n\tFilesystem Protections: enabled\n\tDebugging Restrictions: disabled\n\tDTrace Restrictions: enabled\n\tNVRAM Protections: enabled\n\tBaseSystem Verification: enabled\n\nThis is an unsupported configuration, likely to break in the future and leave your machine in an unknown state.\n",
));

const SMALL_FOOTPRINT: Option<u64> = Some(1);

fn run(fv: Answer, sip: Answer) -> (depot_enclave::deploy::preflight::PreflightResult, Fake) {
    let fake = Fake::new(fv, sip);
    let r = evaluate_preflight_with("L2", SMALL_FOOTPRINT, &fake);
    (r, fake)
}

#[test]
fn non_vacuity_both_on_passes() {
    let (r, fake) = run(FV_ON, SIP_ON);
    assert!(r.passed, "{}", r.message);
    assert!(r.preflight.filevault && r.preflight.sip);
    let seen = fake.seen.borrow();
    assert!(seen.contains(&("/usr/bin/fdesetup".into(), vec!["status".into()])));
    assert!(seen.contains(&("/usr/bin/csrutil".into(), vec!["status".into()])));
}

/// Review validation step: SIP partly disabled must not be reported as on.
#[test]
fn review_validation_sip_custom_configuration_fails() {
    let (r, _) = run(FV_ON, SIP_WITHOUT_DEBUG);
    assert!(!r.passed);
    assert!(
        !r.preflight.sip,
        "SIP reported on for a custom configuration"
    );
    assert!(r.message.contains("not fully enabled"), "{}", r.message);
}

#[test]
fn sip_enabled_custom_configuration_fails() {
    let (r, _) = run(
        FV_ON,
        Ok((
            0,
            "System Integrity Protection status: enabled (Custom Configuration).\n",
        )),
    );
    assert!(!r.passed && !r.preflight.sip);
}

#[test]
fn csrutil_that_cannot_run_fails_closed() {
    let (r, _) = run(FV_ON, Err(()));
    assert!(!r.passed && !r.preflight.sip);
    assert!(r.message.contains("could not be verified"), "{}", r.message);
}

#[test]
fn fdesetup_that_cannot_run_fails_closed() {
    let (r, _) = run(Err(()), SIP_ON);
    assert!(!r.passed && !r.preflight.filevault);
    assert!(r.message.contains("failing closed"), "{}", r.message);
}

#[test]
fn nonzero_exit_fails_closed_even_with_on_text() {
    let (r, _) = run(Ok((1, "FileVault is On.\n")), SIP_ON);
    assert!(!r.passed, "a failing fdesetup must not pass on its stdout");
    let (r2, _) = run(
        FV_ON,
        Ok((1, "System Integrity Protection status: enabled.\n")),
    );
    assert!(!r2.passed);
}

#[test]
fn filevault_off_and_restart_pending_fail() {
    assert!(!run(Ok((0, "FileVault is Off.\n")), SIP_ON).0.passed);
    assert!(
        !run(
            Ok((0, "FileVault is On, but needs to be restarted to finish.\n")),
            SIP_ON
        )
        .0
        .passed
    );
}

/// Real read-only probes on this Mac (SIP enabled, FileVault on).
#[test]
fn host_probes_report_on() {
    assert!(
        depot_enclave::deploy::preflight::get_sip_status(),
        "csrutil status on this host"
    );
    assert!(
        depot_enclave::deploy::preflight::get_filevault_status(),
        "fdesetup status on this host"
    );
}
