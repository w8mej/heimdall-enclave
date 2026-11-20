use super::*;

// Private metadata fixtures do not enumerate hardware or establish native
// singleton binding. Native integration tests separately exercise its caller.
fn fixture() -> (
    Arc<OwnerThreadState>,
    TransportLifetimeState,
    Arc<AtomicBool>,
) {
    let owner = OwnerThreadState::new();
    let poisoned = Arc::new(AtomicBool::new(false));
    let handle = TransportLifetimeState::new(owner.clone(), poisoned.clone());
    (owner, handle, poisoned)
}

#[test]
fn software_hid_default_cannot_supply_native_lifetime() {
    #[derive(Debug)]
    struct Software;
    impl crate::ctap::hid::HidDevice for Software {
        fn write_report(&mut self, _: &[u8; 64]) -> EnclaveResult<()> {
            Ok(())
        }
        fn read_report(&mut self) -> EnclaveResult<[u8; 64]> {
            Ok([0; 64])
        }
        fn hub_depth(&self) -> u8 {
            1
        }
    }
    use crate::ctap::hid::HidDevice;
    assert!(Software
        .selected_transport_lifetime()
        .unwrap_err()
        .is("HID_SELECTED_TRANSPORT_UNAVAILABLE"));
}

#[test]
fn candidates_and_handles_without_an_entered_owner_refuse() {
    let (owner, state, _) = fixture();
    assert!(state
        .capture()
        .unwrap_err()
        .is("HID_SELECTED_TRANSPORT_UNBOUND"));
    state.singleton_bound();
    assert!(state.capture().unwrap_err().is("HID_OWNER_LIFETIME_ENDED"));
    let _guard = owner.enter().unwrap();
    assert!(state
        .capture()
        .unwrap_err()
        .is("HID_SELECTED_TRANSPORT_FAILED"));
}

#[test]
fn selected_capability_clones_pin_original_handle_and_owner() {
    let (owner, state, _) = fixture();
    let _guard = owner.enter().unwrap();
    state.singleton_bound();
    let original = state.capture().unwrap();
    let cloned = original.clone();
    original.require_current().unwrap();
    cloned.require_current().unwrap();
    state.close();
    assert!(original
        .require_current()
        .unwrap_err()
        .is("HID_SELECTED_TRANSPORT_CLOSED"));
    assert!(cloned.require_current().is_err());
    let replacement = TransportLifetimeState::new(owner.clone(), Arc::new(AtomicBool::new(false)));
    replacement.singleton_bound();
    replacement.capture().unwrap().require_current().unwrap();
    assert!(original.require_current().is_err());
}

#[test]
fn failure_and_original_poison_are_irreversible_for_captured_capability() {
    for explicit_failure in [false, true] {
        let (owner, state, poisoned) = fixture();
        let _guard = owner.enter().unwrap();
        state.singleton_bound();
        let lifetime = state.capture().unwrap();
        if explicit_failure {
            state.fail();
        } else {
            poisoned.store(true, Ordering::SeqCst);
        }
        assert!(lifetime.require_current().is_err());
        poisoned.store(false, Ordering::SeqCst);
        state.singleton_bound();
        assert!(lifetime.require_current().is_err());
        assert!(state.capture().is_err());
    }
}

#[test]
fn actual_thread_entry_exit_and_unwind_never_rearm_original_owner() {
    for unwind in [false, true] {
        let (owner, state, _) = fixture();
        let thread_owner = owner.clone();
        let thread_state = state.clone();
        let (ready, receiver) = std::sync::mpsc::sync_channel(1);
        let (finish, finished) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let _guard = thread_owner.enter().unwrap();
            thread_state.singleton_bound();
            ready.send(thread_state.capture().unwrap()).unwrap();
            finished.recv().unwrap();
            if unwind {
                panic!("synthetic native owner unwind");
            }
        });
        let lifetime = receiver.recv().unwrap();
        lifetime.require_current().unwrap();
        finish.send(()).unwrap();
        assert_eq!(worker.join().is_err(), unwind);
        assert!(lifetime.require_current().is_err());
        assert!(owner.enter().is_err());
    }
}

#[test]
fn abandoned_startup_cannot_be_armed_by_a_late_thread_entry() {
    let (owner, state, _) = fixture();
    owner.abandon();
    let thread_owner = owner.clone();
    assert!(std::thread::spawn(move || thread_owner.enter().is_err())
        .join()
        .unwrap());
    state.singleton_bound();
    assert!(state.capture().is_err());
}

#[test]
fn live_thread_abandonment_refuses_even_before_the_blocked_owner_exits() {
    let (owner, state, _) = fixture();
    let thread_owner = owner.clone();
    let (ready, receiver) = std::sync::mpsc::sync_channel(1);
    let (finish, finished) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let _guard = thread_owner.enter().unwrap();
        state.singleton_bound();
        ready.send(state.capture().unwrap()).unwrap();
        finished.recv().unwrap();
    });
    let lifetime = receiver.recv().unwrap();
    lifetime.require_current().unwrap();
    owner.abandon();
    assert!(lifetime.require_current().is_err());
    finish.send(()).unwrap();
    worker.join().unwrap();
    assert!(owner.enter().is_err());
}
