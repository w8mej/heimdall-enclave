//! Original command-owner lifecycle/cap fixtures, moved with their engine.
//! These execute synthetic subprocesses only when the coordinator runs tests;
//! they establish neither installed authority nor native profile qualification.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

const COMMAND_LIMIT: Duration = Duration::from_secs(2);
static NEXT: AtomicUsize = AtomicUsize::new(0);

#[test]
fn owned_leader_remains_unreaped_until_group_cleanup_and_cannot_recycle_before_signal() {
    for (terminal, result, error, expected) in [
        (true, 0, None, Ok(false)),
        (false, 0, Some(libc::EPERM), Ok(false)),
        (false, -1, Some(libc::ESRCH), Ok(false)),
        (true, -1, Some(libc::EPERM), Ok(true)),
        (
            false,
            -1,
            Some(libc::EPERM),
            Err(CommandFailure::OwnershipUnknown),
        ),
        (
            true,
            -1,
            Some(libc::EACCES),
            Err(CommandFailure::OwnershipUnknown),
        ),
        (true, -1, None, Err(CommandFailure::OwnershipUnknown)),
        (
            true,
            -2,
            Some(libc::EPERM),
            Err(CommandFailure::OwnershipUnknown),
        ),
    ] {
        assert_eq!(cleanup_signal_decision(terminal, result, error), expected);
    }
    assert!(group_gone_after_reap(-1, Some(libc::ESRCH)));
    for (result, error) in [
        (0, None),
        (0, Some(libc::ESRCH)),
        (-1, Some(libc::EPERM)),
        (-1, Some(libc::EACCES)),
        (-1, None),
        (-2, Some(libc::ESRCH)),
    ] {
        assert!(!group_gone_after_reap(result, error));
    }
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "exit 7"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    let child = command.spawn().unwrap();
    let group = child.id() as libc::pid_t;
    let mut owned = OwnedObserver {
        child,
        group,
        cleaned: false,
    };
    let until = Instant::now() + COMMAND_LIMIT;
    while !owned.terminal().unwrap() {
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(2));
    }
    // A repeated WNOWAIT must still observe the same terminal event; no wait
    // has reaped it and freed the numeric process/group identity for reuse.
    assert!(owned.terminal().unwrap());
    assert!(!owned.cleaned);
    // On the observed Darwin26.6.2, group SIGKILL returns EPERM when only this
    // zombie leader remains; cleanup must reap then require exact signal0
    // ESRCH. On Linux the normal successful group signal follows the same pin.
    assert_eq!(owned.cleanup().unwrap(), Some(7));
    assert!(owned.cleaned);
    assert_eq!(owned.cleanup().unwrap_err(), CommandFailure::Io);
}

#[test]
fn auto_reap_policy_or_lost_child_pin_refuses_signalling_and_no_second_cleanup_signal_occurs() {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = libc::SIG_DFL;
    action.sa_flags = 0;
    assert!(safe_child_policy(&action));
    action.sa_sigaction = libc::SIG_IGN;
    assert!(!safe_child_policy(&action));
    action.sa_sigaction = libc::SIG_DFL;
    action.sa_flags = libc::SA_NOCLDWAIT;
    assert!(!safe_child_policy(&action));
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "exit 0"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    let child = command.spawn().unwrap();
    let group = child.id() as libc::pid_t;
    let mut owned = OwnedObserver {
        child,
        group,
        cleaned: false,
    };
    // Deliberately violate the production no-competing-reaper contract. The
    // cleanup must observe ECHILD and refuse to signal a now-unpinned group.
    owned.child.wait().unwrap();
    assert_eq!(
        owned.cleanup().unwrap_err(),
        CommandFailure::OwnershipUnknown
    );
    assert!(owned.cleaned);
    assert_eq!(owned.cleanup().unwrap_err(), CommandFailure::Io);
}

#[test]
fn every_postspawn_result_is_cleaned_and_lost_ownership_overrides_original_errors() {
    for original in [
        Ok(()),
        Err(CommandFailure::Timeout),
        Err(CommandFailure::OutputLimit),
        Err(CommandFailure::Io),
    ] {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "exit 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let child = command.spawn().unwrap();
        let group = child.id() as libc::pid_t;
        let mut owned = OwnedObserver {
            child,
            group,
            cleaned: false,
        };
        let result = with_observer_cleanup(&mut owned, |owned| {
            // Model the former early-return path while also consuming the
            // child's lifetime pin. Explicit finalization must notice ECHILD
            // and override even a prior timeout/output/read failure.
            owned.child.wait().unwrap();
            original
        });
        assert_eq!(result.unwrap_err(), CommandFailure::OwnershipUnknown);
        assert!(owned.cleaned);
        assert_eq!(owned.cleanup().unwrap_err(), CommandFailure::Io);
    }
}

#[test]
fn real_owned_observer_subprocess_has_combined_output_and_deadline_caps() {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "printf public; printf diagnostic >&2"]);
    let result = bounded_output(command, Instant::now() + COMMAND_LIMIT).unwrap();
    assert_eq!(result.code, Some(0));
    assert_eq!(result.stdout, b"public");
    assert_eq!(result.stderr, b"diagnostic");
    let mut command = Command::new("/bin/sh");
    command.args([
        "-c",
        "while :; do printf '1234567890123456789012345678901234567890'; done",
    ]);
    assert_eq!(
        bounded_output(command, Instant::now() + COMMAND_LIMIT).unwrap_err(),
        CommandFailure::OutputLimit
    );
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "sleep 30"]);
    assert_eq!(
        bounded_output(command, Instant::now() + Duration::from_millis(50)).unwrap_err(),
        CommandFailure::Timeout
    );
}

#[test]
fn exited_leader_pipe_holding_descendant_is_terminated_with_only_owned_group_cleanup() {
    let directory = std::env::temp_dir().join(format!(
        "activity-observer-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("child.pid");
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "sleep 30 & printf '%s' \"$!\" > \"$1\"; exit 0",
            "owned-observer-fixture",
        ])
        .arg(&path);
    assert_eq!(
        bounded_output(command, Instant::now() + Duration::from_millis(250)).unwrap_err(),
        CommandFailure::Timeout
    );
    let pid = std::fs::read_to_string(&path)
        .unwrap()
        .parse::<i32>()
        .unwrap();
    let until = Instant::now() + Duration::from_secs(1);
    loop {
        let exists = unsafe { libc::kill(pid, 0) } == 0;
        let zombie = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|s| {
                s.rsplit_once(')')
                    .map(|(_, v)| v.trim_start().starts_with('Z'))
            })
            .unwrap_or(false);
        if !exists || zombie {
            break;
        }
        assert!(
            Instant::now() < until,
            "owned synthetic descendant survived observer cleanup"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    std::fs::remove_dir_all(directory).unwrap();
}

// BEGIN CLEANUP_DIAGNOSTIC_TESTS_ONLY
// Private cfg(test) recorder: diagnostic collection is not cleanup success.
// Root runs these exact functions with --nocapture in isolated serial harnesses.
#[derive(Clone, Copy, Debug)]
enum DiagnosticEvent {
    Operation(Option<CommandFailure>),
    CleanupStart(bool),
    Terminal {
        result: i32,
        error: Option<i32>,
        terminal: bool,
    },
    Initial(bool),
    ScheduledTerminal {
        result: i32,
        error: Option<i32>,
        terminal: bool,
    },
    Signal {
        result: i32,
        error: Option<i32>,
        decision: Result<bool, CommandFailure>,
    },
    Reaped(Option<i32>),
    Probe {
        result: i32,
        error: Option<i32>,
    },
    RemovedPin {
        reaped: bool,
        error: Option<i32>,
    },
}
struct DiagnosticTrace {
    start: Instant,
    events: Vec<(u128, DiagnosticEvent)>,
    overflow: bool,
    release: Option<std::process::ChildStdin>,
    scheduling_error: Option<&'static str>,
    owned_pid: Option<u32>,
    remove_pin_after_denial: bool,
}
impl DiagnosticTrace {
    fn new(release: Option<std::process::ChildStdin>) -> Self {
        Self {
            start: Instant::now(),
            events: Vec::with_capacity(4096),
            overflow: false,
            release,
            scheduling_error: None,
            owned_pid: None,
            remove_pin_after_denial: false,
        }
    }
    fn record(&mut self, event: DiagnosticEvent) {
        if self.events.len() == self.events.capacity() {
            self.overflow = true;
            return;
        }
        self.events.push((self.start.elapsed().as_nanos(), event));
    }
}
thread_local! {
    static DIAGNOSTIC_TRACE:std::cell::RefCell<Option<DiagnosticTrace>>=const {std::cell::RefCell::new(None)};
}
fn diagnostic_record(event: DiagnosticEvent) {
    DIAGNOSTIC_TRACE.with(|slot| {
        if let Some(trace) = slot.borrow_mut().as_mut() {
            trace.record(event);
        }
    });
}
pub(super) fn diagnostic_operation(error: Option<CommandFailure>) {
    diagnostic_record(DiagnosticEvent::Operation(error));
}
pub(super) fn diagnostic_cleanup_start(cleaned: bool) {
    diagnostic_record(DiagnosticEvent::CleanupStart(cleaned));
}
pub(super) fn diagnostic_terminal(result: i32, error: Option<i32>, terminal: bool) {
    diagnostic_record(DiagnosticEvent::Terminal {
        result,
        error,
        terminal,
    });
}
pub(super) fn diagnostic_signal(
    result: i32,
    error: Option<i32>,
    decision: Result<bool, CommandFailure>,
) {
    diagnostic_record(DiagnosticEvent::Signal {
        result,
        error,
        decision,
    });
    let pid = DIAGNOSTIC_TRACE.with(|slot| {
        let mut slot = slot.borrow_mut();
        let trace = slot.as_mut()?;
        if result == -1 && error == Some(libc::EPERM) && trace.remove_pin_after_denial {
            trace.remove_pin_after_denial = false;
            trace.owned_pid
        } else {
            None
        }
    });
    if let Some(pid) = pid {
        // Synthetic fault only: intentionally violate exclusive reaper
        // ownership AFTER the original denied signal. Never signal or retry.
        let mut status = 0;
        let result = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
        let error = if result < 0 {
            std::io::Error::last_os_error().raw_os_error()
        } else {
            None
        };
        let reaped = result == pid as libc::pid_t;
        diagnostic_record(DiagnosticEvent::RemovedPin { reaped, error });
        if !reaped {
            DIAGNOSTIC_TRACE.with(|slot| {
                slot.borrow_mut().as_mut().unwrap().scheduling_error =
                    Some("fault failed to remove original child pin")
            });
        }
    }
}
pub(super) fn diagnostic_reaped(code: Option<i32>) {
    diagnostic_record(DiagnosticEvent::Reaped(code));
}
pub(super) fn diagnostic_probe(result: i32, error: Option<i32>) {
    diagnostic_record(DiagnosticEvent::Probe { result, error });
}
pub(super) fn diagnostic_after_initial(pid: u32, terminal: bool) {
    diagnostic_record(DiagnosticEvent::Initial(terminal));
    DIAGNOSTIC_TRACE.with(|slot| {
        if let Some(trace) = slot.borrow_mut().as_mut() {
            trace.owned_pid = Some(pid);
        }
    });
    let release = DIAGNOSTIC_TRACE.with(|slot| {
        slot.borrow_mut()
            .as_mut()
            .and_then(|trace| trace.release.take())
    });
    let Some(mut release)=release else {return;};
    // Deliberate test-only scheduling: release this originally owned shell,
    // observe terminal without reaping, then let the UNCHANGED cleanup signal.
    let mut failure = None;
    if terminal {
        failure = Some("scheduled child was already terminal");
    }
    use std::io::Write;
    if release.write_all(b"\n").is_err() {
        failure = Some("scheduled child release failed");
    }
    drop(release);
    let until = Instant::now() + Duration::from_millis(250);
    let (result, error, terminal) = loop {
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        // Read errno before timestamps, trace calls or further syscalls.
        let error = if result < 0 {
            std::io::Error::last_os_error().raw_os_error()
        } else {
            None
        };
        let terminal = result == 0 && unsafe { info.assume_init() }.si_signo != 0;
        if result < 0 || terminal || Instant::now() >= until {
            break (result, error, terminal);
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    if result != 0 || !terminal {
        failure = Some("scheduled owned terminal event not observed within bound");
    }
    DIAGNOSTIC_TRACE.with(|slot| {
        let mut slot = slot.borrow_mut();
        let trace = slot.as_mut().expect("active diagnostic");
        trace.scheduling_error = failure;
        trace.record(DiagnosticEvent::ScheduledTerminal {
            result,
            error,
            terminal,
        });
    });
}
fn diagnostic_begin(release: Option<std::process::ChildStdin>) {
    DIAGNOSTIC_TRACE.with(|slot| {
        let mut slot = slot.borrow_mut();
        assert!(slot.is_none());
        *slot = Some(DiagnosticTrace::new(release));
    });
}
fn diagnostic_finish(
    label: &str,
    result: Result<Option<i32>, CommandFailure>,
) -> Vec<DiagnosticEvent> {
    let trace = DIAGNOSTIC_TRACE.with(|slot| slot.borrow_mut().take().expect("active diagnostic"));
    println!("NATIVE_COMMAND_DIAGNOSTIC label={label} outcome={result:?} elapsed_ns={} overflow={} scheduling_error={:?} events={:?}",
        trace.start.elapsed().as_nanos(),trace.overflow,trace.scheduling_error,trace.events);
    assert!(!trace.overflow, "diagnostic recorder overflow");
    assert_eq!(
        trace.scheduling_error, None,
        "controlled schedule incomplete"
    );
    let events = trace
        .events
        .into_iter()
        .map(|(_, event)| event)
        .collect::<Vec<_>>();
    assert!(
        events
            .iter()
            .filter(|event| matches!(event, DiagnosticEvent::Signal { .. }))
            .count()
            <= 1,
        "diagnostic observed more than one mutating group signal"
    );
    events
}
fn diagnostic_owned_blocked_shell() -> (OwnedObserver, std::process::ChildStdin) {
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "IFS= read -r value; exit 7"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    let mut child = command.spawn().unwrap();
    let group = child.id() as libc::pid_t;
    let release = child.stdin.take().unwrap();
    (
        OwnedObserver {
            child,
            group,
            cleaned: false,
        },
        release,
    )
}

#[test]
fn diagnostic_cap_records_actual_errno_and_timestamps_without_cleanup_success_claim() {
    let mut command = Command::new("/bin/sh");
    command.args([
        "-c",
        "while :; do printf '1234567890123456789012345678901234567890'; done",
    ]);
    diagnostic_begin(None);
    let result = bounded_output(command, Instant::now() + COMMAND_LIMIT).map(|output| output.code);
    let events = diagnostic_finish("passive-original-cap", result);
    assert!(events.iter().any(|event| matches!(
        event,
        DiagnosticEvent::Operation(Some(CommandFailure::OutputLimit))
    )));
    // Record the real result, including OwnershipUnknown. Do not reinterpret
    // this diagnostic's completed recording as the original cap assertion PASS.
}

#[test]
fn diagnostic_scheduled_live_to_terminal_records_stale_snapshot_without_reaping() {
    let (mut owned, release) = diagnostic_owned_blocked_shell();
    diagnostic_begin(Some(release));
    let result = owned.cleanup();
    let events = diagnostic_finish("scheduled-live-to-terminal-baseline", result);
    assert!(events
        .iter()
        .any(|event| matches!(event, DiagnosticEvent::Initial(false))));
    assert!(events.iter().any(|event| matches!(
        event,
        DiagnosticEvent::ScheduledTerminal {
            result: 0,
            terminal: true,
            ..
        }
    )));
    assert!(owned.cleaned);
    // EPERM is not injected or assumed; the actual sole signal result is kept.
}

#[test]
fn diagnostic_already_terminal_records_native_signal_and_absence_probe() {
    let (mut owned, mut release) = diagnostic_owned_blocked_shell();
    use std::io::Write;
    release.write_all(b"\n").unwrap();
    drop(release);
    let until = Instant::now() + COMMAND_LIMIT;
    while !owned.terminal().unwrap() {
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(1));
    }
    diagnostic_begin(None);
    let result = owned.cleanup();
    let events = diagnostic_finish("already-terminal-control", result);
    assert!(events
        .iter()
        .any(|event| matches!(event, DiagnosticEvent::Initial(true))));
    assert!(owned.cleaned);
}

#[test]
fn diagnostic_live_leader_records_one_original_group_signal() {
    let (mut owned, release) = diagnostic_owned_blocked_shell();
    diagnostic_begin(None);
    let result = owned.cleanup();
    let events = diagnostic_finish("live-leader-control", result);
    assert!(events
        .iter()
        .any(|event| matches!(event, DiagnosticEvent::Initial(false))));
    assert!(owned.cleaned);
    drop(release);
}

#[test]
fn diagnostic_lost_pin_records_refusal_without_group_signal() {
    let (mut owned, release) = diagnostic_owned_blocked_shell();
    drop(release);
    owned.child.wait().unwrap();
    diagnostic_begin(None);
    let result = owned.cleanup();
    let events = diagnostic_finish("lost-pin-control", result);
    assert_eq!(result, Err(CommandFailure::OwnershipUnknown));
    assert!(!events
        .iter()
        .any(|event| matches!(event, DiagnosticEvent::Signal { .. })));
    assert!(owned.cleaned);
}
// END CLEANUP_DIAGNOSTIC_TESTS_ONLY

// BEGIN CLEANUP_CANDIDATE_REGRESSION_TESTS_ONLY
#[test]
fn denied_signal_reobserves_original_terminal_before_reap_and_preserves_output_limit() {
    let (mut owned, release) = diagnostic_owned_blocked_shell();
    diagnostic_begin(Some(release));
    let result: Result<((), Option<i32>), CommandFailure> =
        with_observer_cleanup(&mut owned, |_| Err(CommandFailure::OutputLimit));
    let result = result.map(|(_, code)| code);
    let events = diagnostic_finish("candidate-stale-snapshot-original-cap-error", result);
    assert_eq!(result, Err(CommandFailure::OutputLimit));
    assert!(events
        .iter()
        .any(|event| matches!(event, DiagnosticEvent::Initial(false))));
    assert!(events.iter().any(|event| matches!(
        event,
        DiagnosticEvent::ScheduledTerminal {
            result: 0,
            terminal: true,
            ..
        }
    )));
    let signal = events
        .iter()
        .position(|event| matches!(event, DiagnosticEvent::Signal { .. }))
        .unwrap();
    let denied = matches!(
        events[signal],
        DiagnosticEvent::Signal {
            result: -1,
            error: Some(libc::EPERM),
            ..
        }
    );
    // Linux normally permits signalling a zombie. The actual Darwin baseline
    // must demonstrate EPERM; this native regression requires that real branch.
    #[cfg(target_os = "macos")]
    assert!(
        denied,
        "native denied-signal regression did not reach the observed EPERM branch"
    );
    if denied {
        let fresh = events
            .iter()
            .enumerate()
            .skip(signal + 1)
            .find_map(|(index, event)| {
                matches!(
                    event,
                    DiagnosticEvent::Terminal {
                        result: 0,
                        error: None,
                        terminal: true
                    }
                )
                .then_some(index)
            })
            .unwrap();
        let reaped = events
            .iter()
            .position(|event| matches!(event, DiagnosticEvent::Reaped(Some(7))))
            .unwrap();
        let absent = events
            .iter()
            .position(|event| {
                matches!(
                    event,
                    DiagnosticEvent::Probe {
                        result: -1,
                        error: Some(libc::ESRCH)
                    }
                )
            })
            .unwrap();
        assert!(signal < fresh && fresh < reaped && reaped < absent);
    }
    assert!(owned.cleaned);
    // Original pure decision coverage still refuses EPERM+freshfalse and every
    // unknown/non-ESRCH post-reap tuple; no predicate or assertion is relaxed.
}

#[cfg(target_os = "macos")]
#[test]
fn lost_pin_after_denied_signal_overrides_original_output_limit_without_a_second_signal() {
    let (mut owned, release) = diagnostic_owned_blocked_shell();
    diagnostic_begin(Some(release));
    DIAGNOSTIC_TRACE
        .with(|slot| slot.borrow_mut().as_mut().unwrap().remove_pin_after_denial = true);
    let result: Result<((), Option<i32>), CommandFailure> =
        with_observer_cleanup(&mut owned, |_| Err(CommandFailure::OutputLimit));
    let result = result.map(|(_, code)| code);
    assert!(owned.cleaned);
    assert_eq!(owned.cleanup(), Err(CommandFailure::Io));
    let events = diagnostic_finish("candidate-denied-signal-competing-reaper-fault", result);
    assert_eq!(result, Err(CommandFailure::OwnershipUnknown));
    assert!(events.iter().any(|event| matches!(
        event,
        DiagnosticEvent::Signal {
            result: -1,
            error: Some(libc::EPERM),
            ..
        }
    )));
    let lost = events
        .iter()
        .position(|event| {
            matches!(
                event,
                DiagnosticEvent::RemovedPin {
                    reaped: true,
                    error: None
                }
            )
        })
        .unwrap();
    let refused = events
        .iter()
        .enumerate()
        .skip(lost + 1)
        .find_map(|(index, event)| {
            matches!(
                event,
                DiagnosticEvent::Terminal {
                    result: -1,
                    error: Some(libc::ECHILD),
                    terminal: false
                }
            )
            .then_some(index)
        })
        .unwrap();
    assert!(lost < refused);
    assert!(!events.iter().any(|event| matches!(
        event,
        DiagnosticEvent::Reaped(_) | DiagnosticEvent::Probe { .. }
    )));
}
// END CLEANUP_CANDIDATE_REGRESSION_TESTS_ONLY

// BEGIN RETAINED_STRICT_ENGINE_TESTS_ONLY
fn strict_fixture_scope() -> ExclusiveCommandWaitScope {
    ExclusiveCommandWaitScope {
        _seal: wait_discipline::fixture_seal(),
        _thread: std::marker::PhantomData,
    }
}
fn strict_fixture_attempt<'a>(
    retention: &'a StrictRetention,
    end: Instant,
) -> StrictCommandAttempt<'a> {
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "printf public; printf diagnostic >&2; exit 7"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut attempt = StrictCommandAttempt::before_spawn(end, retention);
    let child = command.spawn().unwrap();
    let original = attempt.original.as_mut().unwrap();
    original.child = Some(child);
    original.group = Some(original.child.as_ref().unwrap().id() as libc::pid_t);
    attempt
}
fn strict_fixture_terminal(attempt: &StrictCommandAttempt<'_>) {
    let until = Instant::now() + COMMAND_LIMIT;
    let child = attempt.original.as_ref().unwrap().child.as_ref().unwrap();
    loop {
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                child.id() as libc::id_t,
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        assert_eq!(result, 0);
        if unsafe { info.assume_init() }.si_signo != 0 {
            return;
        }
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(1));
    }
}
// Fixture teardown only: reap the SAME already-terminal original Child, never
// signal a numeric PID/group, retry a production attempt or adopt another child.
fn strict_fixture_reap(mut original: Box<StrictCommandResources>) {
    assert_eq!(
        original.child.as_mut().unwrap().wait().unwrap().code(),
        Some(7)
    );
}

#[test]
fn strict_engine_preserves_original_numeric_exit_and_combined_output_with_no_compatibility_change()
{
    let retention = StrictRetention::new();
    let mut scope = strict_fixture_scope();
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "printf public; printf diagnostic >&2; exit 7"]);
    let output = strict_output_inner(
        command,
        Instant::now() + COMMAND_LIMIT,
        &mut scope,
        &retention,
    )
    .unwrap();
    assert_eq!(output.code, Some(7));
    assert_eq!(output.stdout, b"public");
    assert_eq!(output.stderr, b"diagnostic");
    assert!(!retention.refused());
    assert!(retention.original.lock().unwrap().is_none());
}

#[test]
fn strict_output_limit_preserves_operation_failure_after_confirmed_single_group_cleanup() {
    let retention = StrictRetention::new();
    let mut scope = strict_fixture_scope();
    let mut command = Command::new("/bin/sh");
    command.args([
        "-c",
        "while :; do printf '1234567890123456789012345678901234567890'; done",
    ]);
    let failure = strict_output_inner(
        command,
        Instant::now() + COMMAND_LIMIT,
        &mut scope,
        &retention,
    )
    .unwrap_err();
    assert_eq!(failure.operation, Some(CommandFailure::OutputLimit));
    assert_eq!(failure.cleanup, None);
    assert_eq!(failure.exit_code, Some(None));
    assert!(!failure.original_retained);
    assert!(!retention.refused());
}

#[test]
fn expired_strict_endpoint_retains_same_child_pipes_and_frame_without_any_cleanup_grace() {
    let retention = StrictRetention::new();
    let mut attempt = strict_fixture_attempt(&retention, Instant::now() + COMMAND_LIMIT);
    strict_fixture_terminal(&attempt);
    let original = attempt.original.as_mut().unwrap();
    let end = Instant::now() - Duration::from_millis(1);
    original.end = end;
    let address = (&**original) as *const StrictCommandResources;
    let child = original.child.as_ref().unwrap();
    let id = child.id();
    let pipes = (
        child.stdout.as_ref().unwrap().as_raw_fd(),
        child.stderr.as_ref().unwrap().as_raw_fd(),
    );
    let failure = attempt.complete(Err(CommandFailure::Io)).unwrap_err();
    assert_eq!(
        failure,
        StrictCommandFailure {
            operation: Some(CommandFailure::Io),
            cleanup: Some(CommandFailure::Timeout),
            exit_code: None,
            original_retained: true
        }
    );
    let original = retention.original.lock().unwrap().take().unwrap();
    assert_eq!((&*original) as *const StrictCommandResources, address);
    assert_eq!(original.end, end);
    assert_eq!(original.signal_calls, 0);
    let child = original.child.as_ref().unwrap();
    assert_eq!(child.id(), id);
    assert_eq!(
        (
            child.stdout.as_ref().unwrap().as_raw_fd(),
            child.stderr.as_ref().unwrap().as_raw_fd()
        ),
        pipes
    );
    assert!(retention.refused());
    strict_fixture_reap(original);
}

#[test]
fn strict_unwind_parks_intact_original_without_drop_cleanup_or_a_new_timer() {
    let retention = StrictRetention::new();
    let attempt = strict_fixture_attempt(&retention, Instant::now() + COMMAND_LIMIT);
    strict_fixture_terminal(&attempt);
    let original = attempt.original.as_ref().unwrap();
    let address = (&**original) as *const StrictCommandResources;
    let end = original.end;
    let stdout = original
        .child
        .as_ref()
        .unwrap()
        .stdout
        .as_ref()
        .unwrap()
        .as_raw_fd();
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _owned = attempt;
        panic!("synthetic retained command unwind");
    }));
    assert!(caught.is_err());
    let original = retention.original.lock().unwrap().take().unwrap();
    assert_eq!((&*original) as *const StrictCommandResources, address);
    assert_eq!(original.end, end);
    assert_eq!(original.phase, StrictCleanupPhase::Unstarted);
    assert_eq!(original.signal_calls, 0);
    assert_eq!(
        original
            .child
            .as_ref()
            .unwrap()
            .stdout
            .as_ref()
            .unwrap()
            .as_raw_fd(),
        stdout
    );
    assert!(retention.refused());
    strict_fixture_reap(original);
}

#[test]
fn strict_lost_wait_pin_retains_original_error_and_cleanup_uncertainty_without_signalling() {
    let retention = StrictRetention::new();
    let mut attempt = strict_fixture_attempt(&retention, Instant::now() + COMMAND_LIMIT);
    strict_fixture_terminal(&attempt);
    // Deliberately reap only this original fixture's leader to model unsupported
    // competing wait ownership. No signal is sent after the lost lifetime pin.
    attempt
        .original
        .as_mut()
        .unwrap()
        .child
        .as_mut()
        .unwrap()
        .wait()
        .unwrap();
    let failure = attempt
        .complete(Err(CommandFailure::OutputLimit))
        .unwrap_err();
    assert_eq!(failure.operation, Some(CommandFailure::OutputLimit));
    assert_eq!(failure.cleanup, Some(CommandFailure::OwnershipUnknown));
    assert!(failure.original_retained);
    let original = retention.original.lock().unwrap().take().unwrap();
    assert_eq!(original.signal_calls, 0);
    assert!(original.child.as_ref().unwrap().stdout.is_some());
    strict_fixture_reap(original);
}

#[test]
fn strict_confirmed_reap_cannot_signal_twice_or_extend_the_original_endpoint() {
    let retention = StrictRetention::new();
    let mut attempt = strict_fixture_attempt(&retention, Instant::now() + COMMAND_LIMIT);
    strict_fixture_terminal(&attempt);
    let original = attempt.original.as_mut().unwrap();
    let end = original.end;
    original.cleanup().unwrap();
    assert_eq!(original.phase, StrictCleanupPhase::Confirmed);
    assert_eq!(original.exit_code, Some(Some(7)));
    assert_eq!(original.signal_calls, 1);
    assert_eq!(original.cleanup(), Err(CommandFailure::OwnershipUnknown));
    assert_eq!(original.signal_calls, 1);
    assert_eq!(original.end, end);
    // Confirmed original may drop normally; no strict or legacy Drop signals.
}

#[test]
fn strict_reaped_uncertainty_keeps_observed_exit_and_never_reenters_signalling() {
    let retention = StrictRetention::new();
    let mut attempt = strict_fixture_attempt(&retention, Instant::now() + COMMAND_LIMIT);
    strict_fixture_terminal(&attempt);
    let original = attempt.original.as_mut().unwrap();
    original.exit_code = Some(original.child.as_mut().unwrap().wait().unwrap().code());
    original.phase = StrictCleanupPhase::Reaped;
    let failure = attempt.complete(Err(CommandFailure::Io)).unwrap_err();
    assert_eq!(failure.exit_code, Some(Some(7)));
    assert_eq!(failure.operation, Some(CommandFailure::Io));
    assert_eq!(failure.cleanup, Some(CommandFailure::OwnershipUnknown));
    let original = retention.original.lock().unwrap().take().unwrap();
    assert_eq!(original.signal_calls, 0);
    strict_fixture_reap(original);
}

#[test]
fn strict_parking_contention_collision_and_poison_preserve_intact_extra_boxes_without_blocking() {
    for mode in 0..3 {
        let retention = StrictRetention::new();
        let mut attempt = strict_fixture_attempt(&retention, Instant::now() + COMMAND_LIMIT);
        strict_fixture_terminal(&attempt);
        let mut bundle = attempt.original.take().unwrap();
        let address = (&mut *bundle) as *mut StrictCommandResources;
        let stdout = bundle
            .child
            .as_ref()
            .unwrap()
            .stdout
            .as_ref()
            .unwrap()
            .as_raw_fd();
        let first = if mode == 0 {
            let mut first = strict_fixture_attempt(&retention, Instant::now() + COMMAND_LIMIT);
            strict_fixture_terminal(&first);
            Some(first.original.take().unwrap())
        } else {
            None
        };
        if let Some(first) = first {
            *retention.original.lock().unwrap() = Some(first);
        }
        if mode == 1 {
            let _held = retention.original.lock().unwrap();
            retention.retain(bundle);
        } else if mode == 2 {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _held = retention.original.lock().unwrap();
                panic!("synthetic parking poison");
            }));
            retention.retain(bundle);
        } else {
            retention.retain(bundle);
        }
        assert!(retention.refused());
        assert!(
            unsafe { libc::fcntl(stdout, libc::F_GETFD) } >= 0,
            "collision dropped original pipe"
        );
        // Test-only recovery of the exact forgotten allocation, known to be on
        // a forced collision/contention/poison branch. Never reconstruct from
        // PID/PGID, signal, retry or adopt; reap only the terminal fixture Child.
        let original = unsafe { Box::from_raw(address) };
        assert_eq!(original.signal_calls, 0);
        strict_fixture_reap(original);
        let mut slot = retention
            .original
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(original) = slot.take() {
            strict_fixture_reap(original);
        }
    }
}

#[test]
fn retained_uncertainty_permanently_refuses_later_strict_spawn_even_after_slot_inspection() {
    let retention = StrictRetention::new();
    let mut scope = strict_fixture_scope();
    let mut attempt = strict_fixture_attempt(&retention, Instant::now() + COMMAND_LIMIT);
    strict_fixture_terminal(&attempt);
    attempt.retain_original();
    let original = retention.original.lock().unwrap().take().unwrap();
    strict_fixture_reap(original);
    // Missing executable would report Unavailable if spawn were reached.
    let failure = strict_output_inner(
        Command::new("/no-such-strict-fixture-executable"),
        Instant::now() + COMMAND_LIMIT,
        &mut scope,
        &retention,
    )
    .unwrap_err();
    assert_eq!(
        failure,
        StrictCommandFailure::before_spawn(CommandFailure::OwnershipUnknown)
    );
    assert!(retention.refused());
}
// END RETAINED_STRICT_ENGINE_TESTS_ONLY
