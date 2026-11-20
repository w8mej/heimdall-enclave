//! Synthetic original-worker tests only. Never call check-in, Mach, a daemon,
//! native listener constructor, PF, hardware or the global wipe registry.
use super::{mach_readiness::*, *};
use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}, mpsc};

fn endpoint() -> Instant { Instant::now() + Duration::from_secs(2) }
fn fixture(body: impl FnOnce(Worker, Armed, Arc<AtomicBool>, Arc<AtomicBool>) + Send + 'static) -> Owner {
    let (health, worker_health) = Health::pair();
    let running = Arc::new(AtomicBool::new(true));
    let stop = Arc::new(AtomicBool::new(false));
    let worker_running = running.clone();
    let worker_stop = stop.clone();
    let (started, receive) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let armed = worker_health.arm(&worker_running, &worker_stop).unwrap();
        started.send(()).unwrap();
        body(worker_health, armed, worker_running, worker_stop);
    });
    receive.recv_timeout(Duration::from_secs(2)).unwrap();
    Owner { health, running, stop, worker: Some(worker) }
}
fn live_loop(worker: &Worker, running: &AtomicBool, stop: &AtomicBool) {
    while running.load(Ordering::Acquire) && !stop.load(Ordering::Acquire) {
        if let Some(challenge) = worker.next_challenge() {
            assert!(worker.receive_outcome(RECEIVE_TIMED_OUT));
            worker.acknowledge(challenge, running, stop);
        }
        std::thread::park_timeout(Duration::from_millis(1));
    }
}
fn finished(owner: &Owner) {
    let deadline = endpoint();
    while !owner.worker.as_ref().unwrap().is_finished() {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
}

#[test]
fn mach_health_only_success_or_documented_receive_timeout_is_progress() {
    let accepted = (-128..=127).filter(|result| receive_progress(*result)).collect::<Vec<_>>();
    assert_eq!(accepted, vec![0]);
    assert!(receive_progress(RECEIVE_TIMED_OUT));
    for result in [i32::MIN, -1, 1, 3, 4, 0x1000_4001, 0x1000_4002, 0x1000_4004, i32::MAX] {
        assert!(!receive_progress(result));
        let (_, worker) = Health::pair();
        assert!(!worker.receive_outcome(result));
        let error = worker.shared.error("TEST_RECEIVE_REFUSAL");
        assert!(error.detail.contains("Receive"));
        assert!(error.detail.contains(&format!("Some({result})")));
    }
}

#[test]
fn mach_health_each_positive_observation_uses_the_actual_original_worker() {
    let replies = Arc::new(AtomicUsize::new(0));
    let counted = replies.clone();
    let mut owner = fixture(move |worker, _armed, running, stop| {
        while running.load(Ordering::Acquire) && !stop.load(Ordering::Acquire) {
            if let Some(challenge) = worker.next_challenge() {
                assert!(worker.receive_outcome(0));
                counted.fetch_add(1, Ordering::AcqRel);
                worker.acknowledge(challenge, &running, &stop);
            }
            std::thread::park_timeout(Duration::from_millis(1));
        }
    });
    owner.observe(endpoint()).unwrap();
    owner.observe(endpoint()).unwrap();
    assert_eq!(replies.load(Ordering::Acquire), 2);
    owner.stop(endpoint()).unwrap();
    assert!(owner.worker.is_none());
    assert!(!owner.stop.load(Ordering::Acquire));
    assert!(owner.observe(endpoint()).unwrap_err().is("SUPERVISOR_MACH_HEALTH_UNAVAILABLE"));
    owner.stop(endpoint()).unwrap();
}

#[test]
fn mach_health_unarmed_absent_original_handle_and_external_stop_refuse() {
    let (health, worker) = Health::pair();
    let running = AtomicBool::new(true);
    let stop = AtomicBool::new(false);
    assert!(health.observe(&running, &stop, None, endpoint()).unwrap_err().is("SUPERVISOR_MACH_HEALTH_UNAVAILABLE"));
    health.shared.refuse(FailureStage::Stop, None);
    assert!(worker.arm(&running, &stop).is_err());

    let mut owner = fixture(|worker, _armed, running, stop| live_loop(&worker, &running, &stop));
    assert!(owner.health.observe(&owner.running, &owner.stop, None, endpoint()).is_err());
    owner.stop.store(true, Ordering::Release);
    assert!(owner.observe(endpoint()).is_err());
    owner.stop(endpoint()).unwrap();
}

#[test]
fn mach_health_stalled_worker_timeout_busy_queue_and_old_reply_never_reuse_success() {
    let (release, held) = mpsc::sync_channel(1);
    let (drained, old_drained) = mpsc::sync_channel(1);
    let mut owner = fixture(move |worker, _armed, running, stop| {
        held.recv_timeout(Duration::from_secs(2)).unwrap();
        let until = endpoint();
        loop {
            if let Some(old) = worker.next_challenge() {
                worker.acknowledge(old, &running, &stop);
                drained.send(()).unwrap();
                break;
            }
            assert!(Instant::now() < until);
            std::thread::yield_now();
        }
        live_loop(&worker, &running, &stop);
    });
    assert!(owner.observe(Instant::now() + Duration::from_millis(25)).unwrap_err().is("SUPERVISOR_MACH_HEALTH_DEADLINE"));
    assert!(owner.observe(endpoint()).unwrap_err().is("SUPERVISOR_MACH_HEALTH_BUSY"));
    assert!(!owner.worker.as_ref().unwrap().is_finished());
    release.send(()).unwrap();
    old_drained.recv_timeout(Duration::from_secs(2)).unwrap();
    owner.observe(endpoint()).unwrap();
    owner.stop(endpoint()).unwrap();
}

#[test]
fn mach_health_revoke_during_probe_prevents_ack_and_late_rearm() {
    let (received, pending) = mpsc::sync_channel(1);
    let (release, held) = mpsc::sync_channel(1);
    let mut owner = fixture(move |worker, armed, running, stop| {
        let until = endpoint();
        let challenge = loop {
            if let Some(challenge) = worker.next_challenge() { break challenge; }
            assert!(Instant::now() < until);
            std::thread::yield_now();
        };
        received.send(()).unwrap();
        held.recv_timeout(Duration::from_secs(2)).unwrap();
        drop(armed);
        assert!(worker.arm(&running, &stop).is_err());
        worker.acknowledge(challenge, &running, &stop);
    });
    std::thread::scope(|scope| {
        let observing = scope.spawn(|| owner.observe(endpoint()));
        pending.recv_timeout(Duration::from_secs(2)).unwrap();
        owner.health.shared.refuse(FailureStage::RightType, Some(17));
        release.send(()).unwrap();
        assert!(observing.join().unwrap().unwrap_err().is("SUPERVISOR_MACH_HEALTH_UNAVAILABLE"));
    });
    finished(&owner);
    assert!(owner.stop(endpoint()).unwrap_err().detail.contains("RightType"));
}

#[test]
fn mach_health_unknown_receive_and_all_subsequent_cleanup_failures_are_retained() {
    let mut owner = fixture(|worker, _armed, _, _| {
        assert!(!worker.receive_outcome(0x1000_4004));
        worker.shared.refuse(FailureStage::Reply, Some(0x1000_0004));
        worker.shared.refuse(FailureStage::ReleaseThread, Some(15));
        worker.shared.refuse(FailureStage::ReleaseTask, Some(16));
        worker.shared.refuse(FailureStage::ReleaseReceive, Some(17));
    });
    finished(&owner);
    let error = owner.observe(endpoint()).unwrap_err();
    let mut previous = 0;
    for stage in ["Receive,", "Reply,", "ReleaseThread,", "ReleaseTask,", "ReleaseReceive,"] {
        let index = error.detail.find(stage).unwrap();
        assert!(index >= previous);
        previous = index;
    }
    assert!(owner.stop(endpoint()).is_err());
    assert!(owner.worker.is_none());
    assert!(owner.observe(endpoint()).is_err());
}

#[test]
fn mach_health_worker_exit_or_unwind_revokes_even_if_running_still_true() {
    for unwind in [false, true] {
        let mut owner = fixture(move |_, _armed, _, _| {
            if unwind { panic!("synthetic Mach worker unwind"); }
        });
        finished(&owner);
        assert!(owner.running.load(Ordering::Acquire));
        let error = owner.observe(endpoint()).unwrap_err();
        assert!(error.detail.contains(if unwind { "WorkerUnwind" } else { "WorkerExit" }));
        assert_eq!(owner.stop(endpoint()).is_err(), unwind);
        assert!(owner.worker.is_none());
    }
}

#[test]
fn mach_health_expired_endpoint_enqueues_no_request() {
    let replies = Arc::new(AtomicUsize::new(0));
    let counted = replies.clone();
    let mut owner = fixture(move |worker, _armed, running, stop| {
        while running.load(Ordering::Acquire) && !stop.load(Ordering::Acquire) {
            if let Some(challenge) = worker.next_challenge() {
                counted.fetch_add(1, Ordering::AcqRel);
                worker.acknowledge(challenge, &running, &stop);
            }
            std::thread::park_timeout(Duration::from_millis(1));
        }
    });
    assert!(owner.observe(Instant::now()).unwrap_err().is("SUPERVISOR_MACH_HEALTH_DEADLINE"));
    owner.observe(endpoint()).unwrap();
    assert_eq!(replies.load(Ordering::Acquire), 1);
    owner.stop(endpoint()).unwrap();
}

#[test]
fn mach_health_old_owner_stop_cannot_revoke_a_different_instance_generation() {
    let mut old = fixture(|worker, _armed, running, stop| live_loop(&worker, &running, &stop));
    let mut current = fixture(|worker, _armed, running, stop| live_loop(&worker, &running, &stop));
    assert!(!Arc::ptr_eq(&old.health.shared, &current.health.shared));
    old.stop(endpoint()).unwrap();
    drop(old);
    current.observe(endpoint()).unwrap();
    current.stop(endpoint()).unwrap();
}

#[test]
fn mach_health_stop_deadline_keeps_original_worker_until_actual_exit() {
    let (release, held) = mpsc::sync_channel(1);
    let mut owner = fixture(move |_, _armed, _, _| {
        held.recv_timeout(Duration::from_secs(2)).unwrap();
    });
    assert!(owner.stop(Instant::now()).unwrap_err().is("SUPERVISOR_MACH_STOP_PENDING"));
    assert!(owner.worker.is_some());
    assert!(!owner.running.load(Ordering::Acquire));
    assert!(!owner.stop.load(Ordering::Acquire));
    assert!(owner.observe(endpoint()).is_err());
    release.send(()).unwrap();
    finished(&owner);
    let error = owner.stop(endpoint()).unwrap_err();
    assert!(error.detail.contains("StopPending"));
    assert!(owner.worker.is_none());
}

#[test]
fn mach_health_drop_requests_stop_without_freeing_a_resource_still_on_worker() {
    struct SyntheticResource(Arc<AtomicUsize>, mpsc::SyncSender<()>);
    impl Drop for SyntheticResource {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::AcqRel);
            self.1.send(()).unwrap();
        }
    }
    let (release, held) = mpsc::sync_channel(1);
    let (cleaned, received) = mpsc::sync_channel(1);
    let drops = Arc::new(AtomicUsize::new(0));
    let counted = drops.clone();
    let owner = fixture(move |_, _armed, running, _| {
        let _resource = SyntheticResource(counted, cleaned);
        held.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(!running.load(Ordering::Acquire));
    });
    drop(owner);
    assert_eq!(drops.load(Ordering::Acquire), 0);
    assert!(matches!(received.try_recv(), Err(mpsc::TryRecvError::Empty)));
    release.send(()).unwrap();
    received.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(drops.load(Ordering::Acquire), 1);
}

#[test]
fn mach_health_failure_report_contains_only_fixed_stage_and_numeric_codes() {
    let (health, _) = Health::pair();
    for stage in [FailureStage::ServiceName, FailureStage::CheckIn, FailureStage::WorkerStart,
        FailureStage::StartupWait, FailureStage::Forwarding, FailureStage::TaskIdentity,
        FailureStage::ProcessIdentity, FailureStage::ServiceChanged, FailureStage::Join] {
        health.shared.refuse(stage, Some(-777));
    }
    let error = health.shared.error("SUPERVISOR_MACH_HEALTH_UNAVAILABLE");
    assert!(error.detail.contains("Some(-777)"));
    for secret in ["synthetic-pin", "private-descriptor", "/Library/", "raw-fault-address"] {
        assert!(!error.detail.contains(secret));
    }
    assert!(health.shared.stop_failed());
}

#[test]
fn mach_health_forwarding_failure_preserves_typed_reason_and_redacts_free_form_detail() {
    let (health, _) = Health::pair();
    health.shared.refuse_forwarding(err!(EACCES, "IPC_READ", "synthetic-pin raw-fault-address /Library/private"));
    health.shared.refuse_forwarding(err!(EIO, "raw private reason", "private-descriptor"));
    health.shared.refuse_forwarding(err!(EIO, "RAW_PRIVATE_SECRET", "private-descriptor"));
    let error = health.shared.error("SUPERVISOR_MACH_HEALTH_UNAVAILABLE");
    for retained in ["Forwarding", "EACCES", "IPC_READ", "EIO", "UNSTRUCTURED_REASON_REDACTED"] {
        assert!(error.detail.contains(retained));
    }
    for hidden in ["synthetic-pin", "raw-fault-address", "/Library/private", "raw private reason", "private-descriptor", "RAW_PRIVATE_SECRET"] {
        assert!(!error.detail.contains(hidden));
    }
    assert!(health.shared.stop_failed());
}
