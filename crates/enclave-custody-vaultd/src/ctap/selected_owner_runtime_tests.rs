//! Software metadata/actor scheduling only; native connection authenticity and
//! service final-release paths have separate concrete qualification.
use super::*;
use crate::ctap::selected_transport_lifetime::{
    OwnerThreadGuard, OwnerThreadState, TransportLifetimeState,
};
fn end() -> Instant {
    Instant::now() + Duration::from_secs(3)
}
fn fixture() -> (Arc<Control>, TransportLifetimeState, OwnerThreadGuard) {
    let owner = OwnerThreadState::new();
    let guard = owner.enter().unwrap();
    let state = TransportLifetimeState::new(owner, Arc::new(AtomicBool::new(false)));
    state.singleton_bound();
    let until = end();
    let control = Arc::new(Control {
        token: state.capture().unwrap(),
        stop: CustodySelectedOwnerStop::new(until),
        session: Session::Fixture,
        failed: SelectedOwnerFailure::new(),
        ended: AtomicBool::new(false),
        fence_started: AtomicBool::new(false),
        service: Mutex::new(None),
        end: until,
    });
    (control, state, guard)
}

#[test]
fn runtime_watchdog_revokes_while_original_actor_is_blocked_without_actor_queue() {
    let (control, state, _guard) = fixture();
    let (entered, waiting) = mpsc::sync_channel(0);
    let (resume, blocked) = mpsc::sync_channel(0);
    let actor = std::thread::spawn(move || {
        entered.send(()).unwrap();
        blocked.recv_timeout(Duration::from_secs(3)).unwrap();
    });
    waiting.recv_timeout(Duration::from_secs(1)).unwrap();
    let watching = control.clone();
    let (done, observed) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        watchdog(watching);
        done.send(()).unwrap();
    });
    state.close();
    observed.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(control.failed.require_current().is_err());
    assert!(control.current().is_err());
    // Actor has not resumed; cancellation did not require its progress.
    resume.send(()).unwrap();
    actor.join().unwrap();
    worker.join().unwrap();
}

#[test]
fn runtime_original_owner_exit_and_expiry_are_terminal_without_replacement() {
    for expire in [false, true] {
        let (mut control, _state, guard) = fixture();
        if expire {
            Arc::get_mut(&mut control).unwrap().end = Instant::now();
        } else {
            drop(guard);
        }
        watchdog(control.clone());
        assert!(control.current().is_err());
        assert!(control.failed.require_current().is_err());
        assert!(control.ended.load(Ordering::SeqCst));
    }
}

#[test]
fn runtime_service_session_expiry_denies_while_actual_watchdog_is_blocked() {
    let (mut control, _state, _guard) = fixture();
    let (entered, waiting) = mpsc::sync_channel(1);
    let (resume, resumed) = mpsc::channel();
    Arc::get_mut(&mut control).unwrap().session = Session::BlockedFixture {
        entered,
        resume: Mutex::new(resumed),
    };
    let service = VaultService::selected_owner_test_fixture(control.failed.clone()).unwrap();
    *control.service.lock().unwrap() = Some(Arc::downgrade(&service));
    let watching = control.clone();
    let (done, finished) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        watchdog(watching);
        done.send(()).unwrap();
    });
    waiting.recv_timeout(Duration::from_secs(1)).unwrap();
    // The actual watchdog is now in its private session-check boundary. Bind
    // the shared cap while it is blocked, without changing the live HID token.
    let instant = Instant::now();
    let boot = enclave_core::clock::boot_clock_ns();
    let until = control
        .failed
        .bind_fixture_original(instant + Duration::from_millis(40), boot + 5_000_000_000)
        .unwrap();
    std::thread::sleep(until.saturating_duration_since(Instant::now()));
    control.token.require_current().unwrap();
    assert!(matches!(
        finished.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    let error = service
        .handle(
            &enclave_core::ipc::PeerCredentials::local(enclave_core::ipc::geteuid(), 0),
            crate::service::VaultRequest::AllocateSlot,
        )
        .unwrap_err();
    assert!(error.is("SELECTED_OWNER_DEPENDENCY_FAILED"));
    // Service denial comes from its immutable cap, before watchdog progress or
    // its later generation fence/cleanup. No native kernel hang is induced.
    assert!(matches!(
        finished.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    resume.send(()).unwrap();
    finished.recv_timeout(Duration::from_secs(3)).unwrap();
    worker.join().unwrap();
    assert!(control.failed.require_current().is_err());
}

#[test]
fn runtime_fresh_probe_ack_requires_original_sequence_and_post_probe_transport() {
    for mode in 0..3 {
        let (control, state, _guard) = fixture();
        let (send, receive) = mpsc::sync_channel::<Probe>(1);
        let worker = std::thread::spawn(move || {
            let request = receive.recv_timeout(Duration::from_secs(1)).unwrap();
            if mode == 2 {
                state.close();
            }
            request
                .reply
                .send(request.sequence + u64::from(mode == 1))
                .unwrap();
        });
        let mut sequence = 0;
        let result = control.observe(&send, &mut sequence, end());
        assert_eq!(result.is_ok(), mode == 0);
        assert_eq!(sequence, 1);
        assert_eq!(control.failed.require_current().is_ok(), mode == 0);
        worker.join().unwrap();
        control.signal_failure();
    }
}

#[test]
fn runtime_probe_timeout_backpressure_disconnect_and_sequence_exhaustion_fail_closed() {
    for mode in 0..4 {
        let (control, _state, _guard) = fixture();
        let (send, receive) = mpsc::sync_channel(1);
        let mut receiver = Some(receive);
        let mut sequence = if mode == 3 { u64::MAX } else { 0 };
        if mode == 1 {
            let (reply, _receive) = mpsc::sync_channel(1);
            assert!(send
                .try_send(Probe {
                    sequence: 999,
                    end: end(),
                    reply
                })
                .is_ok());
        }
        if mode == 2 {
            drop(receiver.take());
        }
        let deadline = Instant::now() + Duration::from_millis(20);
        assert!(control.observe(&send, &mut sequence, deadline).is_err());
        assert!(control.failed.require_current().is_err());
        assert!(control.current().is_err());
    }
}

#[test]
fn runtime_caught_worker_or_pending_startup_unwind_latches_failure() {
    let (control, _state, _guard) = fixture();
    let failed = control.failed.clone();
    let worker = control.clone();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _exit = ActorExit(worker);
        panic!("fixture actor panic");
    }))
    .is_err());
    assert!(failed.require_current().is_err());
    let failed = SelectedOwnerFailure::new();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _attempt = PendingFailure {
            failure: failed.clone(),
            armed: true,
        };
        panic!("fixture pending construction panic");
    }))
    .is_err());
    assert!(failed.require_current().is_err());
}

#[test]
fn runtime_same_channel_stop_fences_real_service_before_blocked_actor_resumes() {
    let (control, _state, _guard) = fixture();
    let service = VaultService::selected_owner_test_fixture(control.failed.clone()).unwrap();
    *control.service.lock().unwrap() = Some(Arc::downgrade(&service));
    let before = service.selected_owner_test_state().0;
    let (entered, waiting) = mpsc::sync_channel(0);
    let (resume, blocked) = mpsc::sync_channel(0);
    let actor = std::thread::spawn(move || {
        entered.send(()).unwrap();
        blocked.recv_timeout(Duration::from_secs(3)).unwrap();
    });
    waiting.recv_timeout(Duration::from_secs(1)).unwrap();
    let watching = control.clone();
    let (done, observed) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        watchdog(watching);
        done.send(()).unwrap();
    });
    // The original HID remains live. The SAME channel's terminal control must
    // independently reach the latch and direct service fence before actor work.
    control.token.require_current().unwrap();
    control.stop.clone().stop();
    observed.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(control.failed.require_current().is_err());
    let (after, enabled, cancelled) = service.selected_owner_test_state();
    assert!(after > before && !enabled && cancelled);
    control.token.require_current().unwrap();
    resume.send(()).unwrap();
    actor.join().unwrap();
    worker.join().unwrap();
}

#[test]
fn runtime_poisoned_service_binding_still_fences_original_real_service() {
    let (control, _state, _guard) = fixture();
    let service = VaultService::selected_owner_test_fixture(control.failed.clone()).unwrap();
    *control.service.lock().unwrap() = Some(Arc::downgrade(&service));
    let before = service.selected_owner_test_state().0;
    let poisoning = control.clone();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _binding = poisoning.service.lock().unwrap();
            panic!("runtime weak service metadata poison");
        }))
        .is_err()
    );
    assert!(control.service.is_poisoned());
    control.signal_failure();
    control.fence_service();
    assert!(control.failed.require_current().is_err());
    let (after, enabled, cancelled) = service.selected_owner_test_state();
    assert!(after > before && !enabled && cancelled);
    control.fence_service();
    assert_eq!(service.selected_owner_test_state().0, after);
}

#[cfg(not(target_os = "macos"))]
#[test]
fn runtime_linux_refusal_consumes_original_negative_gate_without_threads() {
    let (control, _state, _guard) = fixture();
    let failed = control.failed.clone();
    // SAME extracted native-process admission used by actual start, under its
    // same pending-failure guard. No public/native Session constructor exists
    // for software fixtures merely to make the later start signature callable.
    {
        let _attempt = PendingFailure {
            failure: failed.clone(),
            armed: true,
        };
        assert!(native_process()
            .err()
            .unwrap()
            .is("SELECTED_OWNER_RUNTIME_NATIVE_REQUIRED"));
    }
    assert!(failed.require_current().is_err());
}
