//! Unchanged existing strict fixtures, relocated into the proposed small binary.
//! No source-only fixture is native/root/installed acceptance.
use super::*;
const COMMAND_LIMIT: Duration = Duration::from_secs(2);

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

// Separate-process boundary fixtures are test-only and have no production protocol.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[path = "process_boundary_tests.rs"]
mod process_boundary;
