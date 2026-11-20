//! GAP-16: System sleep, screen-lock, and authenticator-yank wipe tests.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use enclave_core::power::{registry, WipeReceipt, WipeTrigger};
use enclave_core::supervisor::{fanout_wipe, SupervisorRequest};

#[test]
fn power_wipe_registry_records_execution_and_budget() {
    let count = Arc::new(AtomicUsize::new(0));
    let count_cl = count.clone();

    registry().register("unit_test_wipe_hook", move |trigger| match trigger {
        WipeTrigger::SystemSleep
        | WipeTrigger::SessionLocked
        | WipeTrigger::AuthenticatorYank
        | WipeTrigger::ThunderboltHotPlugLocked => {
            count_cl.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    });

    let receipt: WipeReceipt = registry().execute(WipeTrigger::SystemSleep);
    assert_eq!(receipt.trigger, WipeTrigger::SystemSleep);
    assert!(receipt.success);
    assert!(receipt.duration_ns > 0);
    // Under 1 ms CPU time
    assert!(receipt.cpu_us <= 1000);
    assert!(count.load(Ordering::SeqCst) >= 1);

    let receipt_lock = registry().execute(WipeTrigger::SessionLocked);
    assert_eq!(receipt_lock.trigger, WipeTrigger::SessionLocked);
    assert!(receipt_lock.success);

    let receipt_yank = registry().execute(WipeTrigger::AuthenticatorYank);
    assert_eq!(receipt_yank.trigger, WipeTrigger::AuthenticatorYank);
    assert!(receipt_yank.success);
}

#[test]
fn supervisor_cbor_session_locked_encoding() {
    let req = SupervisorRequest::SessionLocked;
    let mut buf = Vec::new();
    ciborium::into_writer(&req, &mut buf).unwrap();

    // Must decode back to SessionLocked
    let decoded: SupervisorRequest = ciborium::from_reader(&buf[..]).unwrap();
    match decoded {
        SupervisorRequest::SessionLocked => {}
        _ => panic!("expected SessionLocked variant"),
    }
}

#[test]
fn supervisor_fanout_returns_receipts_for_all_daemons() {
    let temp_mesh = std::env::temp_dir().join(format!("depot-mesh-{}", enclave_core::rng::u64()));
    std::fs::create_dir_all(&temp_mesh).unwrap();

    let receipts = fanout_wipe(&temp_mesh, true, WipeTrigger::SessionLocked);
    assert_eq!(receipts.len(), 5);
    for r in &receipts {
        assert_eq!(r.trigger, WipeTrigger::SessionLocked);
        assert!(r.duration_ns > 0);
    }

    let _ = std::fs::remove_dir_all(temp_mesh);
}

#[test]
#[cfg(target_os = "macos")]
fn macos_hardware_power_pmset_sleepnow() {
    if std::env::var("depot_HW").as_deref() != Ok("1") {
        eprintln!("skipping macOS hardware sleep wipe test (depot_HW != 1)");
        return;
    }

    // Hardware verification: ensures PowerMonitor starts and can register
    let mut monitor = enclave_core::power::darwin::PowerMonitor::start()
        .expect("PowerMonitor::start must succeed on macOS hardware");
    monitor.stop();
}
