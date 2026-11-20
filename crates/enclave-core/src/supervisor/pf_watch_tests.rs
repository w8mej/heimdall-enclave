//! Software fixtures test the production private owners/classifiers/channels.
//! They cannot establish native registration, ACL, SC continuity or PF readiness.
use super::*;
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    sync::atomic::AtomicUsize,
    time::Duration,
};

fn endpoint() -> Instant {
    Instant::now() + Duration::from_secs(2)
}
fn arm(shared: &Shared, source: Source) {
    shared.running[source.slot()].store(true, Ordering::SeqCst);
    shared.phase[source.slot()].store(ARMED, Ordering::SeqCst);
}
fn timer() -> Event {
    Event {
        ident: TIMER_ID,
        filter: FILTER_TIMER,
        flags: REGISTER_FLAGS | RECEIPT,
        fflags: 0,
        data: 1,
        udata_null: true,
    }
}
fn vnode() -> Event {
    Event {
        ident: 123,
        filter: FILTER_VNODE,
        flags: REGISTER_FLAGS | RECEIPT,
        fflags: NOTE_WRITE_,
        data: 0,
        udata_null: true,
    }
}

#[test]
fn ordinary_events_invalidate_while_ticks_have_separate_sequence() {
    let shared = Shared::new();
    assert_eq!(shared.tick().unwrap(), 1);
    assert_eq!(shared.generation.load(Ordering::SeqCst), 0);
    assert_eq!(shared.invalidate(Source::Kqueue).unwrap(), 1);
    assert_eq!(shared.invalidate(Source::DynamicStore).unwrap(), 2);
    assert_eq!(shared.ticks.load(Ordering::SeqCst), 1);
    assert_eq!(shared.source_bits.load(Ordering::SeqCst), 3);
    assert!(shared.usable(Source::Owner).is_ok());
}
#[test]
fn generation_overflow_is_irreversible_and_not_wrapped() {
    let shared = Shared::new();
    shared.generation.store(u64::MAX, Ordering::SeqCst);
    assert_eq!(
        shared.invalidate(Source::DynamicStore).unwrap_err().reason,
        Reason::CounterOverflow
    );
    assert_eq!(shared.generation.load(Ordering::SeqCst), u64::MAX);
    assert!(shared.usable(Source::Kqueue).is_err());
}
#[test]
fn tick_overflow_also_revokes_without_advancing_policy_generation() {
    let shared = Shared::new();
    shared.ticks.store(u64::MAX, Ordering::SeqCst);
    assert!(shared.tick().is_err());
    assert!(shared.revoked.load(Ordering::SeqCst));
    assert_eq!(shared.generation.load(Ordering::SeqCst), 0);
}
#[test]
fn failure_bound_preserves_first_and_independent_cleanup() {
    let shared = Shared::new();
    let first = Failure::code(Source::DynamicStore, Reason::ScQuery, 2002);
    shared.record(first, false);
    for code in 0..MAX_FAILURES + 4 {
        shared.record(
            Failure::code(Source::Kqueue, Reason::NativeCall, code as i32),
            false,
        );
    }
    let close = Failure {
        source: Source::Kqueue,
        reason: Reason::Close,
        code: Some(9),
        resource: Some(7),
    };
    shared.record(close, true);
    let journal = shared.journal.lock().unwrap();
    assert_eq!(journal.first, Some(first));
    assert_eq!(journal.failures.len(), MAX_FAILURES);
    assert!(journal.overflow);
    assert_eq!(journal.cleanup, vec![close]);
}
#[test]
fn poison_cannot_look_healthy_or_erase_later_failure() {
    let shared = Shared::new();
    let worker = shared.clone();
    assert!(thread::spawn(move || {
        let _guard = worker.journal.lock().unwrap();
        panic!("fixture poison");
    })
    .join()
    .is_err());
    assert_eq!(
        shared.usable(Source::Owner).unwrap_err().reason,
        Reason::Poisoned
    );
    shared.record(Failure::code(Source::Kqueue, Reason::Close, 9), true);
    let journal = shared.journal.lock().unwrap_err().into_inner();
    assert_eq!(journal.first.unwrap().reason, Reason::Poisoned);
    assert_eq!(journal.cleanup.len(), 1);
}
#[test]
fn exact_receipt_echo_accepts_submitted_bits_and_no_others() {
    let event = Event {
        flags: REGISTER_FLAGS | RECEIPT | ERROR,
        data: 0,
        ..timer()
    };
    assert!(receipt_valid(
        event,
        TIMER_ID,
        FILTER_TIMER,
        REGISTER_FLAGS,
        0
    ));
    assert!(!receipt_valid(
        Event {
            flags: ERROR,
            ..event
        },
        TIMER_ID,
        FILTER_TIMER,
        REGISTER_FLAGS,
        0
    ));
    assert!(!receipt_valid(
        Event {
            flags: event.flags | EOF,
            ..event
        },
        TIMER_ID,
        FILTER_TIMER,
        REGISTER_FLAGS,
        0
    ));
    assert!(!receipt_valid(
        Event { data: 9, ..event },
        TIMER_ID,
        FILTER_TIMER,
        REGISTER_FLAGS,
        0
    ));
    assert!(!receipt_valid(
        Event { ident: 7, ..event },
        TIMER_ID,
        FILTER_TIMER,
        REGISTER_FLAGS,
        0
    ));
    assert!(!receipt_valid(
        Event {
            filter: FILTER_VNODE,
            ..event
        },
        TIMER_ID,
        FILTER_TIMER,
        REGISTER_FLAGS,
        0
    ));
    assert!(!receipt_valid(
        Event {
            udata_null: false,
            ..event
        },
        TIMER_ID,
        FILTER_TIMER,
        REGISTER_FLAGS,
        0
    ));
}
#[test]
fn vnode_receipt_must_echo_exact_requested_notes() {
    let event = Event {
        flags: REGISTER_FLAGS | RECEIPT | ERROR,
        fflags: VNODE_NOTES,
        ..vnode()
    };
    assert!(receipt_valid(
        event,
        123,
        FILTER_VNODE,
        REGISTER_FLAGS,
        VNODE_NOTES
    ));
    assert!(!receipt_valid(
        Event { fflags: 0, ..event },
        123,
        FILTER_VNODE,
        REGISTER_FLAGS,
        VNODE_NOTES
    ));
    let deleted = Event {
        flags: DELETE | RECEIPT | ERROR,
        fflags: 0,
        ..event
    };
    assert!(receipt_valid(deleted, 123, FILTER_VNODE, DELETE, 0));
}
#[test]
fn actual_event_classifier_is_closed_over_identity_filter_flags_data() {
    assert_eq!(classify_event(timer(), &[]).unwrap(), EventKind::Timer);
    assert_eq!(classify_event(vnode(), &[123]).unwrap(), EventKind::Vnode);
    assert_eq!(
        classify_event(
            Event {
                fflags: NOTE_REVOKE_,
                ..vnode()
            },
            &[123]
        )
        .unwrap(),
        EventKind::RevokedVnode
    );
    for bad in [
        Event {
            ident: 7,
            ..timer()
        },
        Event {
            filter: -1,
            ..timer()
        },
        Event { data: 0, ..timer() },
        Event {
            fflags: 1,
            ..timer()
        },
        Event {
            flags: ERROR,
            ..timer()
        },
        Event {
            flags: EOF,
            ..timer()
        },
        Event {
            udata_null: false,
            ..timer()
        },
        Event {
            flags: 0,
            ..timer()
        },
        Event {
            fflags: 0x8000,
            ..vnode()
        },
        Event { data: 1, ..vnode() },
        Event {
            fflags: 0,
            ..vnode()
        },
    ] {
        assert_eq!(
            classify_event(bad, &[123]).unwrap_err().reason,
            Reason::UnknownEvent
        );
    }
    assert!(classify_event(vnode(), &[124]).is_err());
}
#[test]
fn only_documented_live_runloop_outcomes_progress() {
    for result in [-1, 0, 1, 2, 5, i32::MAX] {
        assert!(!runloop_progress(result));
    }
    assert!(runloop_progress(3));
    assert!(runloop_progress(4));
}
#[test]
fn callback_classification_refuses_restart_unknown_array_context_and_thread() {
    assert!(callback_kind(true, true, Some(1)).is_ok());
    assert!(callback_kind(true, true, Some(4096)).is_ok());
    assert_eq!(
        callback_kind(true, true, Some(0)).unwrap_err().reason,
        Reason::ServerRestart
    );
    for (store, thread, count) in [
        (false, true, Some(1)),
        (true, false, Some(1)),
        (true, true, None),
        (true, true, Some(4097)),
    ] {
        assert_eq!(
            callback_kind(store, thread, count).unwrap_err().reason,
            Reason::MalformedCallback
        );
    }
}
#[test]
fn independent_fresh_challenges_need_both_original_endpoints() {
    let shared = Shared::new();
    arm(&shared, Source::Kqueue);
    arm(&shared, Source::DynamicStore);
    let (one, flow_one) = WorkerEndpoint::pair(Source::Kqueue, shared.clone());
    let (two, flow_two) = WorkerEndpoint::pair(Source::DynamicStore, shared.clone());
    let deadline = endpoint();
    let reply_one = one.request(&shared, deadline).unwrap();
    let reply_two = two.request(&shared, deadline).unwrap();
    let worker_one = thread::spawn(move || {
        flow_one
            .acknowledge(flow_one.next().unwrap().unwrap())
            .unwrap();
    });
    let worker_two = thread::spawn(move || {
        flow_two
            .acknowledge(flow_two.next().unwrap().unwrap())
            .unwrap();
    });
    assert_eq!(
        one.receive(&shared, reply_one, deadline).unwrap().source,
        Source::Kqueue
    );
    assert_eq!(
        two.receive(&shared, reply_two, deadline).unwrap().source,
        Source::DynamicStore
    );
    worker_one.join().unwrap();
    worker_two.join().unwrap();
}
#[test]
fn unarmed_missing_and_full_channel_are_refused() {
    let shared = Shared::new();
    let (endpoint_one, flow) = WorkerEndpoint::pair(Source::Kqueue, shared.clone());
    assert_eq!(
        endpoint_one
            .request(&shared, endpoint())
            .unwrap_err()
            .reason,
        Reason::Unarmed
    );
    arm(&shared, Source::Kqueue);
    let _pending = endpoint_one.request(&shared, endpoint()).unwrap();
    assert_eq!(
        endpoint_one
            .request(&shared, endpoint())
            .unwrap_err()
            .reason,
        Reason::ChannelBusy
    );
    drop(flow);
    assert_eq!(
        endpoint_one
            .request(&shared, endpoint())
            .unwrap_err()
            .reason,
        Reason::ChannelClosed
    );
}
#[test]
fn expired_challenge_never_acknowledges() {
    let shared = Shared::new();
    arm(&shared, Source::Kqueue);
    let (_end, flow) = WorkerEndpoint::pair(Source::Kqueue, shared);
    let (reply, receiver) = mpsc::sync_channel(1);
    assert_eq!(
        flow.acknowledge(Challenge {
            deadline: Instant::now(),
            reply
        })
        .unwrap_err()
        .reason,
        Reason::Deadline
    );
    assert!(receiver.try_recv().is_err());
}
#[test]
fn reply_channel_is_fresh_and_late_ack_cannot_satisfy_next_request() {
    let shared = Shared::new();
    arm(&shared, Source::Kqueue);
    let (end, flow) = WorkerEndpoint::pair(Source::Kqueue, shared.clone());
    let old = end.request(&shared, endpoint()).unwrap();
    let challenge = flow.next().unwrap().unwrap();
    drop(old);
    let current = end.request(&shared, endpoint()).unwrap();
    assert_eq!(
        flow.acknowledge(challenge).unwrap_err().reason,
        Reason::ReplyClosed
    );
    assert!(matches!(current.try_recv(), Err(mpsc::TryRecvError::Empty)));
    flow.acknowledge(flow.next().unwrap().unwrap()).unwrap();
    assert_eq!(
        end.receive(&shared, current, endpoint()).unwrap().source,
        Source::Kqueue
    );
}
#[test]
fn revocation_between_native_iteration_and_ack_refuses() {
    let shared = Shared::new();
    arm(&shared, Source::DynamicStore);
    let (end, flow) = WorkerEndpoint::pair(Source::DynamicStore, shared.clone());
    let receiver = end.request(&shared, endpoint()).unwrap();
    let request = flow.next().unwrap().unwrap();
    shared.record(
        Failure::new(Source::DynamicStore, Reason::ServerRestart),
        false,
    );
    assert!(flow.acknowledge(request).is_err());
    assert!(receiver.try_recv().is_err());
}
#[test]
fn worker_exit_revokes_and_preserves_stopped_phase() {
    let shared = Shared::new();
    arm(&shared, Source::Kqueue);
    drop(WorkerExit {
        shared: shared.clone(),
        source: Source::Kqueue,
    });
    assert!(shared.revoked.load(Ordering::SeqCst));
    assert!(!shared.running[0].load(Ordering::SeqCst));
    assert_eq!(shared.phase[0].load(Ordering::SeqCst), STOPPED);
    assert!(shared.phase_current(Source::Kqueue).is_err());
}

struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let parent = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("target/yubikey-pf-watch-software-fixtures");
        fs::create_dir_all(&parent).unwrap();
        let root = parent.join(format!(
            "{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        Self { root }
    }
    fn protection(&self) -> Protection {
        Protection::Fixture {
            uid: unsafe { libc::geteuid() },
            root: self.root.clone(),
        }
    }
    fn spec(&self, role: Role, leaf: &str, bytes: &'static [u8]) -> InputSpec {
        let path = self.root.join(leaf);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        InputSpec {
            role,
            path,
            maximum: MAX_INPUT,
            expected: Expected::Canonical(bytes),
        }
    }
    fn originals(&self, shared: Arc<Shared>) -> Originals {
        let specs = vec![
            self.spec(Role::Descriptor, "descriptor", b"descriptor"),
            self.spec(Role::RootPolicy, "root-policy", b"root policy"),
            self.spec(Role::LlmPolicy, "llm-policy", LLM_POLICY),
            self.spec(Role::CasPolicy, "cas-policy", CAS_POLICY),
        ];
        let mut originals = Originals {
            routes: Vec::new(),
            shared,
        };
        originals
            .open(specs, self.protection(), endpoint())
            .unwrap();
        originals
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
#[test]
fn retained_fixture_originals_are_current_and_close_on_drop() {
    let fixture = Fixture::new();
    let shared = Shared::new();
    let originals = fixture.originals(shared.clone());
    assert!(originals.current(endpoint()).is_ok());
    assert_eq!(originals.routes.len(), 4);
    assert!(originals
        .routes
        .iter()
        .all(|route| route.admitted && route.nodes.len() == 2));
    assert_eq!(shared.resources[0].load(Ordering::SeqCst), 8);
    drop(originals);
    assert!(shared.revoked.load(Ordering::SeqCst));
    assert!(shared.journal.lock().unwrap().cleanup.is_empty());
    assert_eq!(shared.resources[0].load(Ordering::SeqCst), 0);
}
#[test]
fn named_replacement_and_same_original_content_change_are_both_refused() {
    let fixture = Fixture::new();
    let shared = Shared::new();
    let originals = fixture.originals(shared);
    fs::write(fixture.root.join("root-policy"), b"changed policy").unwrap();
    assert_eq!(
        originals.routes[1].current(endpoint()).unwrap_err().reason,
        Reason::InputChanged
    );
    let held = originals.routes[2].nodes.last().unwrap().owned.file();
    let original_inode = held.metadata().unwrap().ino();
    let replacement = fixture.root.join("replacement");
    fs::write(&replacement, LLM_POLICY).unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o644)).unwrap();
    fs::rename(replacement, fixture.root.join("llm-policy")).unwrap();
    // The old original is retained after rename but now has nlink0, which is
    // the precise earlier metadata refusal. Never adopt the new named inode.
    assert_eq!(held.metadata().unwrap().ino(), original_inode);
    assert_eq!(held.metadata().unwrap().nlink(), 0);
    assert_ne!(
        fs::metadata(fixture.root.join("llm-policy")).unwrap().ino(),
        original_inode
    );
    assert_eq!(
        originals.routes[2].current(endpoint()).unwrap_err().reason,
        Reason::InputLinks
    );
}
#[test]
fn hardlink_protection_and_descriptor_flags_are_rechecked_on_originals() {
    let fixture = Fixture::new();
    let originals = fixture.originals(Shared::new());
    fs::hard_link(
        fixture.root.join("root-policy"),
        fixture.root.join("extra-link"),
    )
    .unwrap();
    assert_eq!(
        originals.routes[1].current(endpoint()).unwrap_err().reason,
        Reason::InputLinks
    );
    let fd = originals.routes[2].nodes.last().unwrap().owned.fd();
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, 0) }, 0);
    assert_eq!(
        originals.routes[2].current(endpoint()).unwrap_err().reason,
        Reason::DescriptorFlags
    );
    fs::set_permissions(
        fixture.root.join("cas-policy"),
        fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    assert_eq!(
        originals.routes[3].current(endpoint()).unwrap_err().reason,
        Reason::InputProtection
    );
}
#[test]
fn refused_symlink_retains_partial_original_and_never_adopts_target() {
    let fixture = Fixture::new();
    let target = fixture.spec(Role::RootPolicy, "target", b"root policy");
    let path = fixture.root.join("symlink");
    symlink(&target.path, &path).unwrap();
    let mut route = HeldRoute::new(InputSpec { path, ..target }, fixture.protection());
    assert_eq!(
        route.open(&Shared::new(), endpoint()).unwrap_err().reason,
        Reason::InputType
    );
    assert_eq!(route.nodes.len(), 1);
    assert!(!route.admitted);
}
#[test]
fn fixture_canonical_mismatch_retains_open_leaf() {
    let fixture = Fixture::new();
    let mut spec = fixture.spec(Role::LlmPolicy, "policy", b"unexpected");
    spec.expected = Expected::Canonical(LLM_POLICY);
    let mut route = HeldRoute::new(spec, fixture.protection());
    assert_eq!(
        route.open(&Shared::new(), endpoint()).unwrap_err().reason,
        Reason::CanonicalMismatch
    );
    assert_eq!(route.nodes.len(), 2);
    assert!(!route.admitted);
}
#[test]
fn deadline_prevents_opening_any_fixture_original() {
    let fixture = Fixture::new();
    let mut route = HeldRoute::new(
        fixture.spec(Role::RootPolicy, "policy", b"policy"),
        fixture.protection(),
    );
    assert_eq!(
        route
            .open(&Shared::new(), Instant::now())
            .unwrap_err()
            .reason,
        Reason::Deadline
    );
    assert!(route.nodes.is_empty());
}
#[cfg(not(target_os = "macos"))]
#[test]
fn native_acl_is_unavailable_on_software_host() {
    let fixture = Fixture::new();
    let spec = fixture.spec(Role::RootPolicy, "policy", b"policy");
    let file = File::open(spec.path).unwrap();
    assert_eq!(
        native_empty_acl(&file).unwrap_err().reason,
        Reason::AclUnavailable
    );
}

fn owner_with_held_original_thread(
    shared: Arc<Shared>,
) -> (PfNotifications, mpsc::SyncSender<()>, Arc<AtomicUsize>) {
    let (one, _flow_one) = WorkerEndpoint::pair(Source::Kqueue, shared.clone());
    let (two, _flow_two) = WorkerEndpoint::pair(Source::DynamicStore, shared.clone());
    let (release, wait) = mpsc::sync_channel(1);
    let (started, ready) = mpsc::sync_channel(1);
    let dropped = Arc::new(AtomicUsize::new(0));
    let resource = dropped.clone();
    let state = shared.clone();
    let worker = thread::spawn(move || {
        struct Resource(Arc<AtomicUsize>, Arc<Shared>);
        impl Drop for Resource {
            fn drop(&mut self) {
                self.1.resource_released(Source::Kqueue);
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        state.resource_acquired(Source::Kqueue);
        let _resource = Resource(resource, state.clone());
        arm(&state, Source::Kqueue);
        let _exit = WorkerExit {
            shared: state,
            source: Source::Kqueue,
        };
        started.send(()).unwrap();
        let _ = wait.recv();
    });
    ready.recv_timeout(Duration::from_secs(2)).unwrap();
    (
        PfNotifications {
            resources: Some(Box::new(Resources {
                shared,
                checked: None,
                endpoints: [one, two],
                workers: [Some(worker), None],
            })),
        },
        release,
        dropped,
    )
}
#[test]
fn expired_stop_retains_original_handle_and_resource_and_sticky_uncertainty() {
    let (mut owner, release, dropped) = owner_with_held_original_thread(Shared::new());
    assert!(owner.stop(Instant::now()).is_err());
    assert!(owner.workers[0].is_some());
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    assert!(owner.shared.revoked.load(Ordering::SeqCst));
    assert_eq!(owner.accounting().retained_thread_handles, 1);
    release.send(()).unwrap();
    assert!(owner.stop(endpoint()).is_err()); // Earlier stop uncertainty survives later cleanup.
    assert!(owner.workers.iter().all(Option::is_none));
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert_eq!(
        owner.shared.journal.lock().unwrap().first.unwrap().reason,
        Reason::StopPending
    );
    // Software fixture has joined its exact original; avoid the process-wide
    // native retention slot while preserving the already asserted uncertainty.
    drop(owner.resources.take());
}
#[test]
fn owner_drop_does_not_release_original_resource_while_thread_is_stalled() {
    let (mut owner, release, dropped) = owner_with_held_original_thread(Shared::new());
    let shared = owner.shared.clone();
    let mut retained = OnceLock::new();
    retire_bundle(&retained, owner.resources.take().unwrap());
    drop(owner);
    assert!(shared.revoked.load(Ordering::SeqCst));
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    assert!(retained.get().unwrap().workers[0].is_some());
    release.send(()).unwrap();
    let mut original = retained.take().unwrap();
    original.workers[0].take().unwrap().join().unwrap();
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}
#[test]
fn bounded_registration_receipts_and_latest_loop_codes_keep_numeric_evidence() {
    let shared = Shared::new();
    let receipt = Event {
        flags: REGISTER_FLAGS | RECEIPT | ERROR,
        data: 0,
        ..timer()
    };
    shared.note_receipt(receipt).unwrap();
    shared.note_loop(Source::Kqueue, 0).unwrap();
    shared.note_loop(Source::DynamicStore, 3).unwrap();
    assert!(shared.last_loop_ns[0].load(Ordering::SeqCst) > 0);
    let journal = shared.journal.lock().unwrap();
    assert_eq!(journal.receipts.len(), 1);
    assert_eq!(journal.receipts[0].0.flags, 0x4065);
    assert_eq!(journal.last_loop_result, [Some(0), Some(3)]);
}
#[test]
fn internal_allocation_identity_is_not_a_reusable_generation_number() {
    let first = Shared::new();
    let second = Shared::new();
    first.invalidate(Source::Kqueue).unwrap();
    second.invalidate(Source::Kqueue).unwrap();
    assert_eq!(
        first.generation.load(Ordering::SeqCst),
        second.generation.load(Ordering::SeqCst)
    );
    assert!(!Arc::ptr_eq(&first, &second));
}
#[cfg(not(target_os = "macos"))]
#[test]
fn production_nonnative_constructor_refuses_with_zero_workers_or_resources() {
    let owner = PfNotifications::start_bound(OriginalNegativeBinding::fixture(endpoint()));
    assert!(owner.workers.iter().all(Option::is_none));
    let accounting = owner.accounting();
    assert_eq!(accounting.owned_fds_live_or_close_uncertain, 0);
    assert_eq!(accounting.owned_cf_references_not_yet_released, 0);
    assert_eq!(
        accounting.first_failure.unwrap().reason,
        Reason::NativeRequired
    );
    assert!(owner.observe_current(endpoint()).is_err());
}

fn fixture_session(binding: &OriginalNegativeBinding) -> &AtomicBool {
    match &binding.session {
        BoundSession::Fixture(session) => session,
        BoundSession::Native(_) => panic!("software fixture cannot construct native authority"),
    }
}
fn empty_owner(shared: Arc<Shared>) -> PfNotifications {
    let (one, _flow_one) = WorkerEndpoint::pair(Source::Kqueue, shared.clone());
    let (two, _flow_two) = WorkerEndpoint::pair(Source::DynamicStore, shared.clone());
    PfNotifications {
        resources: Some(Box::new(Resources {
            shared,
            checked: None,
            endpoints: [one, two],
            workers: [None, None],
        })),
    }
}
fn assert_original_negative(shared: &Shared) {
    assert!(fixture_session(&shared.binding).load(Ordering::SeqCst));
    assert!(shared.binding.supervisor_stop.load(Ordering::SeqCst));
    assert!(shared.revoked.load(Ordering::SeqCst));
    assert!(shared.stop.load(Ordering::SeqCst));
}
#[test]
fn bound_failure_vetoes_original_session_before_journal_lock() {
    let shared = Shared::new();
    let guard = shared.journal.lock().unwrap();
    let worker_shared = shared.clone();
    let recorder = thread::spawn(move || {
        worker_shared.record(Failure::new(Source::Kqueue, Reason::NativeCall), false)
    });
    let end = endpoint();
    while !shared.stop.load(Ordering::SeqCst) && Instant::now() < end {
        thread::yield_now();
    }
    assert_original_negative(&shared);
    assert!(!recorder.is_finished());
    assert!(guard.first.is_none());
    drop(guard);
    recorder.join().unwrap();
    assert_eq!(
        shared.journal.lock().unwrap().first.unwrap().reason,
        Reason::NativeCall
    );
}
#[test]
fn vnode_and_callback_veto_before_parsing_but_timer_and_query_epoch_do_not() {
    let quiet = Shared::new();
    quiet.dispatch_event(timer(), &[]).unwrap();
    quiet.invalidate(Source::DynamicStore).unwrap(); // Actual query epoch-only helper.
    assert!(!fixture_session(&quiet.binding).load(Ordering::SeqCst));
    assert!(!quiet.binding.supervisor_stop.load(Ordering::SeqCst));
    assert_eq!(quiet.ticks.load(Ordering::SeqCst), 1);
    assert_eq!(quiet.generation.load(Ordering::SeqCst), 1);
    for event in [
        vnode(),
        Event {
            filter: -1,
            ..vnode()
        },
        Event {
            ident: 999,
            ..vnode()
        },
    ] {
        let shared = Shared::new();
        let _ = shared.dispatch_event(event, &[123]);
        assert_original_negative(&shared);
        assert_eq!(shared.generation.load(Ordering::SeqCst), 1);
    }
    let malformed_tick = Shared::new();
    assert!(malformed_tick
        .dispatch_event(Event { data: 0, ..timer() }, &[])
        .is_err());
    assert_original_negative(&malformed_tick);
    assert_eq!(malformed_tick.ticks.load(Ordering::SeqCst), 0);
    for count in [Some(1), Some(0), None] {
        let shared = Shared::new();
        let _ = shared.dispatch_callback(|| {
            assert_original_negative(&shared); // Before parser/context checks.
            callback_kind(true, true, count)
        });
        assert_original_negative(&shared);
        assert_eq!(shared.generation.load(Ordering::SeqCst), 1);
    }
}
#[test]
fn worker_and_native_owner_drop_veto_before_blocked_cleanup() {
    for native_owner in [false, true] {
        let shared = Shared::new();
        let state = shared.clone();
        let (entered, ready) = mpsc::sync_channel(1);
        let (release, wait) = mpsc::sync_channel(1);
        // An ordinary file exercises the same private OwnedFile Drop; it
        // makes no native PF registration or cleanup-completion claim.
        let file = native_owner.then(|| File::open("/dev/null").unwrap());
        let worker = thread::spawn(move || {
            if let Some(file) = file {
                let owned = unsafe { OwnedFile::take(file.into_raw_fd(), state.clone(), 0) };
                drop(owned);
            } else {
                drop(WorkerExit {
                    shared: state,
                    source: Source::Kqueue,
                });
            }
            entered.send(()).unwrap();
            wait.recv().unwrap(); // Synthetic later cleanup remains blocked.
        });
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_original_negative(&shared);
        assert!(!worker.is_finished());
        release.send(()).unwrap();
        worker.join().unwrap();
    }
}
#[test]
fn orphan_callback_uses_published_original_domain_without_rebinding() {
    let domain = OnceLock::new();
    veto_orphan(&domain); // No NULL dereference, allocation or fallback owner.
    let original = OriginalNegativeBinding::fixture(endpoint());
    publish_domain(&domain, original.clone()).unwrap();
    veto_orphan(&domain);
    assert!(fixture_session(&original).load(Ordering::SeqCst));
    assert!(original.supervisor_stop.load(Ordering::SeqCst));
    assert!(Arc::ptr_eq(domain.get().unwrap(), &original));
    original.supervisor_stop.store(false, Ordering::SeqCst);
    veto_orphan(&domain);
    assert!(original.supervisor_stop.load(Ordering::SeqCst));
}
#[test]
fn second_binding_revokes_offered_and_original_before_worker_effects() {
    let domain = OnceLock::new();
    let original = OriginalNegativeBinding::fixture(endpoint());
    let offered = OriginalNegativeBinding::fixture(endpoint());
    let effects = AtomicUsize::new(0);
    publish_domain(&domain, original.clone()).unwrap();
    let result = publish_domain(&domain, offered.clone()).map(|()| {
        effects.fetch_add(1, Ordering::SeqCst);
    });
    assert_eq!(result.unwrap_err().reason, Reason::AlreadyAttempted);
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    for binding in [&original, &offered] {
        assert!(fixture_session(binding).load(Ordering::SeqCst));
        assert!(binding.supervisor_stop.load(Ordering::SeqCst));
    }
    assert!(Arc::ptr_eq(domain.get().unwrap(), &original));
}
#[test]
fn requested_end_only_shortens_and_stop_reset_cannot_revive_original() {
    let end = endpoint();
    let binding = OriginalNegativeBinding::fixture(end);
    let shorter = end - Duration::from_millis(500);
    assert_eq!(
        binding.endpoint(end + Duration::from_secs(99)).unwrap(),
        end
    );
    assert_eq!(binding.endpoint(shorter).unwrap(), shorter);
    assert_eq!(binding.end, end);
    assert_eq!(
        binding.endpoint(Instant::now()).unwrap_err().reason,
        Reason::Deadline
    );
    binding.supervisor_stop.store(false, Ordering::SeqCst);
    assert!(fixture_session(&binding).load(Ordering::SeqCst));
    assert!(binding.current().is_err());
    assert!(binding.supervisor_stop.load(Ordering::SeqCst));
    assert_eq!(binding.end, end);
}
#[test]
fn partial_spawn_and_postcheck_failure_retain_same_original_bundle() {
    for count in 0..=2 {
        let shared = Shared::new();
        let mut owner = empty_owner(shared.clone());
        let mut releases = Vec::new();
        let mut identities = Vec::new();
        for index in 0..count {
            let (release, wait) = mpsc::sync_channel(1);
            let handle = thread::spawn(move || {
                let _ = wait.recv();
            });
            identities.push(handle.thread().id());
            owner.workers[index] = Some(handle);
            releases.push(release);
        }
        let pointer = &**owner.resources.as_ref().unwrap() as *const Resources;
        shared.record(
            Failure::new(
                Source::Owner,
                if count < 2 {
                    Reason::Spawn
                } else {
                    Reason::ContextChanged
                },
            ),
            false,
        );
        let mut retained = OnceLock::new();
        retire_bundle(&retained, owner.resources.take().unwrap());
        assert_original_negative(&shared);
        if count == 0 {
            assert!(retained.get().is_none());
            continue;
        }
        let original = retained.get().unwrap();
        assert_eq!(&**original as *const Resources, pointer);
        assert!(Arc::ptr_eq(&original.shared, &shared));
        for (index, identity) in identities.iter().enumerate() {
            assert_eq!(
                original.workers[index].as_ref().unwrap().thread().id(),
                *identity
            );
        }
        for release in releases {
            release.send(()).unwrap();
        }
        let mut original = retained.take().unwrap();
        for handle in &mut original.workers {
            if let Some(handle) = handle.take() {
                handle.join().unwrap();
            }
        }
    }
}
#[test]
fn expired_drop_retains_live_handles_and_unknown_charge_until_original_join() {
    let shared = Shared::new();
    shared.registrations[1].store(1, Ordering::SeqCst); // Remote cleanup remains unknown.
    let (mut owner, release, dropped) = owner_with_held_original_thread(shared.clone());
    let pointer = &**owner.resources.as_ref().unwrap() as *const Resources;
    let identity = owner.workers[0].as_ref().unwrap().thread().id();
    assert!(owner.stop(Instant::now()).is_err());
    let mut retained = OnceLock::new();
    retire_bundle(&retained, owner.resources.take().unwrap());
    drop(owner);
    assert_original_negative(&shared);
    let original = retained.get().unwrap();
    assert_eq!(&**original as *const Resources, pointer);
    assert_eq!(
        original.workers[0].as_ref().unwrap().thread().id(),
        identity
    );
    assert_eq!(shared.resources[0].load(Ordering::SeqCst), 1);
    assert_eq!(shared.registrations[1].load(Ordering::SeqCst), 1);
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    release.send(()).unwrap();
    let mut original = retained.take().unwrap();
    original.workers[0].take().unwrap().join().unwrap();
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert_eq!(shared.resources[0].load(Ordering::SeqCst), 0);
    assert_eq!(shared.registrations[1].load(Ordering::SeqCst), 1);
    assert!(original.needs_retention());
    assert_eq!(
        shared.journal.lock().unwrap().first.unwrap().reason,
        Reason::StopPending
    );
}
#[test]
fn cleanup_uncertainty_and_retention_collision_never_clear_original_charge() {
    let original = Shared::new();
    original.registrations[1].store(3, Ordering::SeqCst);
    original.record(Failure::new(Source::DynamicStore, Reason::ScQuery), false);
    for _ in 0..MAX_CLEANUP_FAILURES + 2 {
        original.record(
            Failure::new(Source::DynamicStore, Reason::CleanupUncertain),
            true,
        );
    }
    let journal = original.journal.lock().unwrap();
    assert_eq!(journal.first.unwrap().reason, Reason::ScQuery);
    assert_eq!(journal.failures.len(), 1);
    assert_eq!(journal.cleanup.len(), MAX_CLEANUP_FAILURES);
    assert!(journal.overflow);
    drop(journal);
    let mut first = empty_owner(original.clone());
    let mut slot = OnceLock::new();
    retire_bundle(&slot, first.resources.take().unwrap());
    let offered = Shared::new();
    offered.resources[0].store(2, Ordering::SeqCst);
    let weak = Arc::downgrade(&offered);
    let mut second = empty_owner(offered.clone());
    let before = RETENTION_COLLISIONS.load(Ordering::SeqCst);
    retire_bundle(&slot, second.resources.take().unwrap());
    assert_original_negative(&offered);
    assert!(RETENTION_COLLISIONS.load(Ordering::SeqCst) > before);
    assert!(Arc::ptr_eq(&slot.get().unwrap().shared, &original));
    assert_eq!(original.registrations[1].load(Ordering::SeqCst), 3);
    assert_eq!(offered.resources[0].load(Ordering::SeqCst), 2);
    drop(offered);
    assert!(weak.upgrade().is_some()); // Rejected exact bundle was preserved.
    assert!(slot.take().unwrap().needs_retention());
}
#[test]
fn root_policy_canonical_bytes_admit_actual_protected_original() {
    let fixture = Fixture::new();
    let mut spec = fixture.spec(
        Role::RootPolicy,
        "root-policy",
        super::super::pf_restore_input::render_root_filter(),
    );
    spec.expected = Expected::RootPolicy;
    let shared = Shared::new();
    let mut route = HeldRoute::new(spec, fixture.protection());
    route.open(&shared, endpoint()).unwrap();
    assert!(route.admitted);
    assert_eq!(route.nodes.len(), 2);
    assert!(route.current(endpoint()).is_ok());
}
#[test]
fn root_policy_mutation_and_extra_rule_refuse_but_retain_actual_original() {
    let canonical = super::super::pf_restore_input::render_root_filter();
    let mut changed = canonical.to_vec();
    changed[0] ^= 1;
    let mut extra = canonical.to_vec();
    extra.extend_from_slice(b"\npass out all\n");
    for bytes in [changed, extra, b"pass all\n".to_vec()] {
        let fixture = Fixture::new();
        let mut spec = fixture.spec(Role::RootPolicy, "root-policy", canonical);
        fs::write(&spec.path, bytes).unwrap();
        spec.expected = Expected::RootPolicy;
        let shared = Shared::new();
        let mut route = HeldRoute::new(spec, fixture.protection());
        assert_eq!(
            route.open(&shared, endpoint()).unwrap_err().reason,
            Reason::CanonicalMismatch
        );
        assert!(!route.admitted);
        assert_eq!(route.nodes.len(), 2);
        assert_eq!(shared.resources[0].load(Ordering::SeqCst), 2);
    }
}

#[test]
fn invalid_or_late_runloop_vetoes_original_before_evidence_journal_lock() {
    for (result, late) in [(1, false), (3, true)] {
        let shared = Shared::new();
        let guard = shared.journal.lock().unwrap();
        let state = shared.clone();
        let end = if late { Instant::now() } else { endpoint() };
        let worker = thread::spawn(move || state.complete_runloop(result, end));
        let end = endpoint();
        while !shared.stop.load(Ordering::SeqCst) && Instant::now() < end {
            thread::yield_now();
        }
        assert_original_negative(&shared);
        assert!(!worker.is_finished());
        assert_eq!(guard.last_loop_result, [None, None]);
        drop(guard);
        let failure = worker.join().unwrap().unwrap_err();
        assert_eq!(
            failure.reason,
            if late {
                Reason::Deadline
            } else {
                Reason::RunLoopResult
            }
        );
        assert_eq!(
            shared.journal.lock().unwrap().last_loop_result[1],
            Some(result)
        );
    }
    let current = Shared::new();
    current.complete_runloop(3, endpoint()).unwrap();
    assert!(!fixture_session(&current.binding).load(Ordering::SeqCst));
}
#[test]
fn malformed_late_or_revoked_query_vetoes_before_blocked_original_release() {
    for mode in 0..4 {
        let shared = Shared::new();
        shared.resource_acquired(Source::DynamicStore);
        let state = shared.clone();
        let (entered, ready) = mpsc::sync_channel(1);
        let (release, wait) = mpsc::sync_channel(1);
        let inspected = Arc::new(AtomicUsize::new(0));
        let calls = inspected.clone();
        let end = if mode == 1 {
            Instant::now()
        } else {
            endpoint()
        };
        if mode == 3 {
            shared.binding.revoke();
        }
        let worker = thread::spawn(move || {
            state.complete_query(
                end,
                || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    if mode == 2 {
                        state.binding.revoke();
                        return Ok(());
                    }
                    Err(Failure::new(Source::DynamicStore, Reason::ScQuery))
                },
                || {
                    entered.send(()).unwrap();
                    wait.recv().unwrap();
                    state.resource_released(Source::DynamicStore);
                },
            )
        });
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_original_negative(&shared);
        assert_eq!(
            inspected.load(Ordering::SeqCst),
            usize::from(mode == 0 || mode == 2)
        );
        assert_eq!(shared.resources[1].load(Ordering::SeqCst), 1);
        assert!(!worker.is_finished());
        release.send(()).unwrap();
        assert!(worker.join().unwrap().is_err());
        assert_eq!(shared.resources[1].load(Ordering::SeqCst), 0);
    }
    let quiet = Shared::new();
    quiet.invalidate(Source::DynamicStore).unwrap();
    let mut released = false;
    assert_eq!(
        quiet
            .complete_query(
                endpoint(),
                || Ok(7),
                || {
                    released = true;
                }
            )
            .unwrap(),
        7
    );
    assert!(released);
    assert!(!fixture_session(&quiet.binding).load(Ordering::SeqCst));
    assert_eq!(quiet.generation.load(Ordering::SeqCst), 1);
}
#[test]
fn invalid_registration_receipt_vetoes_original_before_evidence_journal_lock() {
    for mode in 0..3 {
        let shared = Shared::new();
        let event = Event {
            flags: REGISTER_FLAGS | RECEIPT | ERROR,
            data: if mode == 0 { 9 } else { 0 },
            ..timer()
        };
        let deadline = if mode == 1 {
            Instant::now()
        } else {
            endpoint()
        };
        if mode == 2 {
            shared.binding.revoke();
        }
        let guard = shared.journal.lock().unwrap();
        let state = shared.clone();
        let worker = thread::spawn(move || {
            state.complete_registration_receipt(1, event, TIMER_ID, FILTER_TIMER, 0, deadline)
        });
        let end = endpoint();
        while !shared.stop.load(Ordering::SeqCst) && Instant::now() < end {
            thread::yield_now();
        }
        assert_original_negative(&shared);
        assert!(!worker.is_finished());
        assert!(guard.receipts.is_empty());
        drop(guard);
        let failure = worker.join().unwrap().unwrap_err();
        assert_eq!(
            failure.reason,
            match mode {
                0 => Reason::RegistrationReceipt,
                1 => Reason::Deadline,
                _ => Reason::Stopped,
            }
        );
        if mode == 0 {
            assert_eq!(failure.code, Some(9));
        }
        let observed = shared.journal.lock().unwrap().receipts[0].0;
        assert_eq!(
            (
                observed.ident,
                observed.filter,
                observed.flags,
                observed.fflags,
                observed.data,
                observed.udata_null
            ),
            (
                event.ident,
                event.filter,
                event.flags,
                event.fflags,
                event.data,
                event.udata_null
            )
        );
    }
    let quiet = Shared::new();
    quiet
        .complete_registration_receipt(
            1,
            Event {
                flags: REGISTER_FLAGS | RECEIPT | ERROR,
                data: 0,
                ..timer()
            },
            TIMER_ID,
            FILTER_TIMER,
            0,
            endpoint(),
        )
        .unwrap();
    assert!(!fixture_session(&quiet.binding).load(Ordering::SeqCst));
    let absent = Shared::new();
    assert!(absent
        .complete_registration_receipt(0, timer(), TIMER_ID, FILTER_TIMER, 0, endpoint())
        .is_err());
    assert_original_negative(&absent);
    assert!(absent.journal.lock().unwrap().receipts.is_empty());
}
#[test]
fn expired_stop_and_finished_unwind_never_wait_for_journal_and_keep_unknown_charge() {
    for mode in 0..3 {
        let shared = Shared::new();
        let (mut owner, release) = if mode == 1 {
            let (owner, release, _) = owner_with_held_original_thread(shared.clone());
            (owner, Some(release))
        } else {
            (empty_owner(shared.clone()), None)
        };
        if mode == 2 {
            let worker = thread::spawn(|| panic!("fixture finished original unwind"));
            let end = endpoint();
            while !worker.is_finished() && Instant::now() < end {
                thread::yield_now();
            }
            assert!(worker.is_finished());
            owner.workers[0] = Some(worker);
        }
        let guard = shared.journal.lock().unwrap();
        let (done, result) = mpsc::sync_channel(1);
        let stopper = thread::spawn(move || {
            let refused = owner.stop(Instant::now()).is_err();
            done.send((owner, refused))
                .unwrap_or_else(|_| panic!("fixture stop receiver disappeared"));
        });
        let returned = result.recv_timeout(Duration::from_secs(2));
        let timely = returned.is_ok();
        assert_original_negative(&shared);
        assert!(guard.first.is_none());
        drop(guard); // Release even on regression, so the fixture cannot hang.
        let (mut owner, refused) =
            returned.unwrap_or_else(|_| result.recv_timeout(Duration::from_secs(2)).unwrap());
        stopper.join().unwrap();
        let evidence_unknown = shared.stop_evidence_unknown.load(Ordering::SeqCst);
        let pending = shared.stop_pending.load(Ordering::SeqCst);
        let unwound = shared.joined_unwind_sources.load(Ordering::SeqCst);
        let retained = owner.resources.as_ref().unwrap().needs_retention();
        if let Some(release) = release {
            release.send(()).unwrap();
            assert!(owner.stop(endpoint()).is_err());
            assert!(owner.workers.iter().all(Option::is_none));
        }
        // Exact software fixtures are joined; preserve production globals.
        drop(owner.resources.take());
        assert!(timely && refused);
        assert!(evidence_unknown && retained);
        assert_eq!(pending, mode == 1);
        assert_eq!(unwound, if mode == 2 { 1 } else { 0 });
        assert!(shared.stop_uncertain());
    }
    let mut clean = empty_owner(Shared::new());
    assert!(clean.stop(endpoint()).is_ok());
    assert!(!clean.resources.as_ref().unwrap().needs_retention());
}
#[test]
fn administrative_operation_window_preserves_immutable_original_lifetime() {
    let before = Instant::now();
    let original_end = before + Duration::from_secs(60);
    let binding = OriginalNegativeBinding::fixture(original_end);
    let admission = binding.operation_end(original_end);
    assert!(admission >= before + ADMIN_LIMIT);
    assert!(admission <= Instant::now() + ADMIN_LIMIT);
    assert!(admission < original_end);
    assert_eq!(binding.end, original_end);
    let shorter = before + Duration::from_millis(100);
    assert_eq!(binding.operation_end(shorter), shorter);
    assert!(binding.operation_end(original_end + Duration::from_secs(60)) <= original_end);
    assert_eq!(binding.end, original_end);
    assert!(!fixture_session(&binding).load(Ordering::SeqCst));
}

// Synthetic intervals exercise the SAME core admission/dispatch/handoff logic.
// No fixture enters native PF/SC/kqueue or supplies root mutation authority.
#[test]
fn repair_request_uses_original_pre_native_cap_and_same_bundle_without_reviving_old_session() {
    let shared = Shared::new();
    let owner = empty_owner(shared.clone());
    let allocation = owner.resources.as_deref().unwrap() as *const Resources;
    let cap = Instant::now() + Duration::from_millis(700);
    let observation = shared
        .begin_repair_observation(Source::Kqueue, cap)
        .unwrap();
    let window = observation.window();
    assert!(window.end <= cap && window.end <= window.started + REPAIR_LIMIT);
    shared
        .dispatch_observed_event(window, vnode(), &[123])
        .unwrap();
    assert_original_negative(&shared);
    observation.complete();
    let mut request = owner.into_repair_request();
    assert_eq!(
        request.owner.resources.as_deref().unwrap() as *const Resources,
        allocation
    );
    assert_eq!(
        request.execution_gap(),
        RepairExecutionGap::IndependentRootMutationAuthorityAndInstalledTransaction
    );
    assert_eq!(
        request.require_pending_until(endpoint()).unwrap(),
        window.end
    );
    assert!(shared.binding.current().is_err()); // Deliberately revoked forever.
    assert_eq!(
        request.require_pending_until(endpoint()).unwrap(),
        window.end
    );
    assert_original_negative(&shared);
}
#[test]
fn repair_handoff_refuses_earlier_revoked_unpublished_native_window_even_after_later_trigger() {
    let shared = Shared::new();
    let (ready, first_window) = mpsc::sync_channel(1);
    let (revoke, revocation) = mpsc::sync_channel(1);
    let (revoked, revocation_seen) = mpsc::sync_channel(1);
    let (release, stalled) = mpsc::sync_channel(1);
    let original = shared.clone();
    let earlier = thread::spawn(move || {
        let observation = original
            .begin_repair_observation(Source::Kqueue, endpoint())
            .unwrap();
        ready.send(observation.window()).unwrap();
        revocation.recv().unwrap();
        // Stall at the exact earlier-event gap: veto happened, publication has not.
        original.terminal_veto();
        revoked.send(()).unwrap();
        stalled.recv().unwrap();
        original
            .dispatch_observed_event(observation.window(), vnode(), &[123])
            .unwrap();
        observation.complete();
    });
    let first = first_window.recv_timeout(Duration::from_secs(2)).unwrap();
    let later = shared
        .begin_repair_observation(Source::DynamicStore, endpoint())
        .unwrap();
    revoke.send(()).unwrap();
    revocation_seen
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    shared
        .dispatch_observed_callback(Some(later.window()), || Ok(()))
        .unwrap();
    later.complete();
    let mut request = empty_owner(shared.clone()).into_repair_request();
    let refused = request.require_pending_until(endpoint());
    release.send(()).unwrap();
    earlier.join().unwrap();
    assert_eq!(refused, Err(RepairRequestRefusal::NativeObservationPending));
    assert_eq!(shared.repair_native_active.load(Ordering::SeqCst), 0);
    assert!(shared.repair_bounds.lock().unwrap().unwrap().end <= first.end);
    assert_eq!(
        request.require_pending_until(endpoint()),
        Err(RepairRequestRefusal::NativeObservationPending)
    );
    assert_original_negative(&shared);
}
#[test]
fn repair_close_precedes_later_registration_and_refused_request_never_retries_native_entry() {
    let shared = Shared::new();
    let mut request = empty_owner(shared.clone()).into_repair_request();
    let mut native_entries = 0;
    let refused = match shared.begin_repair_observation(Source::Kqueue, endpoint()) {
        Ok(observation) => {
            native_entries += 1;
            observation.complete();
            None
        }
        Err(error) => Some(error.reason),
    };
    assert_eq!(refused, Some(Reason::RepairObservationClosed));
    assert_eq!(native_entries, 0);
    assert_eq!(shared.repair_native_active.load(Ordering::SeqCst), 0);
    assert!(shared.repair_unknown.load(Ordering::SeqCst));
    assert_eq!(
        request.require_pending_until(endpoint()),
        Err(RepairRequestRefusal::MissingTrigger)
    );
    assert_original_negative(&shared);
}
#[test]
fn repair_reverse_publication_preserves_earliest_window_and_deadline_only_shortens() {
    let shared = Shared::new();
    let earlier = shared
        .begin_repair_observation(Source::Kqueue, Instant::now() + Duration::from_millis(700))
        .unwrap();
    let original = earlier.window();
    let later = shared
        .begin_repair_observation(Source::DynamicStore, endpoint())
        .unwrap();
    shared
        .dispatch_observed_callback(Some(later.window()), || Ok(()))
        .unwrap();
    later.complete();
    shared
        .dispatch_observed_event(original, vnode(), &[123])
        .unwrap();
    earlier.complete();
    let bounds = shared.repair_bounds.lock().unwrap().unwrap();
    assert_eq!(bounds.started, original.started);
    assert_eq!(bounds.end, original.end);
    let mut request = empty_owner(shared.clone()).into_repair_request();
    assert_eq!(
        request.require_pending_until(endpoint()).unwrap(),
        original.end
    );
    let shorter = original.end - Duration::from_millis(10);
    assert_eq!(request.require_pending_until(shorter).unwrap(), shorter);
    assert_eq!(request.require_pending_until(endpoint()).unwrap(), shorter);
    assert_original_negative(&shared);
}
#[test]
fn repair_unwind_failed_admission_and_counter_overflow_leave_no_successful_handoff() {
    let shared = Shared::new();
    let state = shared.clone();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _observation = state
                .begin_repair_observation(Source::Kqueue, endpoint())
                .unwrap();
            panic!("fixture observation unwind");
        }))
        .is_err()
    );
    assert_eq!(shared.repair_native_active.load(Ordering::SeqCst), 0);
    assert!(shared.repair_unknown.load(Ordering::SeqCst));
    assert_original_negative(&shared);
    let mut request = empty_owner(shared).into_repair_request();
    assert_eq!(
        request.require_pending_until(endpoint()),
        Err(RepairRequestRefusal::TriggerUnknown)
    );
    let expired = Shared::new();
    assert_eq!(
        expired
            .begin_repair_observation(Source::Kqueue, Instant::now())
            .err()
            .unwrap()
            .reason,
        Reason::Deadline
    );
    assert_eq!(expired.repair_native_active.load(Ordering::SeqCst), 0);
    assert_original_negative(&expired);
    let overflow = Shared::new();
    overflow
        .repair_native_active
        .store(u64::MAX, Ordering::SeqCst);
    assert_eq!(
        overflow
            .begin_repair_observation(Source::Kqueue, endpoint())
            .err()
            .unwrap()
            .reason,
        Reason::RepairObservationUnknown
    );
    assert_eq!(
        overflow.repair_native_active.load(Ordering::SeqCst),
        u64::MAX
    );
    assert!(overflow.repair_unknown.load(Ordering::SeqCst));
    assert_original_negative(&overflow);
}
#[test]
fn repair_foreign_missing_expired_or_busy_windows_remain_unknown_after_later_good_dispatch() {
    for case in 0..4 {
        let shared = Shared::new();
        let observation = shared
            .begin_repair_observation(Source::DynamicStore, endpoint())
            .unwrap();
        let mut window = observation.window();
        let held = (case == 3).then(|| shared.repair_bounds.lock().unwrap());
        let supplied = match case {
            0 => {
                window.allocation ^= 1;
                Some(window)
            }
            1 => None,
            2 => {
                window.end = Instant::now();
                Some(window)
            }
            _ => Some(window),
        };
        shared
            .dispatch_observed_callback(supplied, || {
                assert_original_negative(&shared);
                Ok(())
            })
            .unwrap();
        drop(held);
        shared
            .dispatch_observed_callback(Some(observation.window()), || Ok(()))
            .unwrap();
        observation.complete();
        assert!(shared.repair_unknown.load(Ordering::SeqCst));
        let mut request = empty_owner(shared.clone()).into_repair_request();
        assert_eq!(
            request.require_pending_until(endpoint()),
            Err(RepairRequestRefusal::TriggerUnknown)
        );
        assert_original_negative(&shared);
    }
}
#[test]
fn repair_callback_parse_unwind_poison_and_late_trigger_cannot_be_normalized_into_a_request() {
    let shared = Shared::new();
    let observation = shared
        .begin_repair_observation(Source::DynamicStore, endpoint())
        .unwrap();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = shared.dispatch_observed_callback(Some(observation.window()), || -> Check<()> {
            assert_original_negative(&shared);
            panic!("fixture callback parse unwind");
        });
    }))
    .is_err());
    observation.complete();
    let mut request = empty_owner(shared.clone()).into_repair_request();
    assert_eq!(
        request.require_pending_until(endpoint()),
        Err(RepairRequestRefusal::TriggerUnknown)
    );
    let poisoned = Shared::new();
    let other = poisoned.clone();
    assert!(thread::spawn(move || {
        let _guard = other.repair_bounds.lock().unwrap();
        panic!("fixture bounds poison");
    })
    .join()
    .is_err());
    let observation = poisoned
        .begin_repair_observation(Source::Kqueue, endpoint())
        .unwrap();
    poisoned
        .dispatch_observed_event(observation.window(), vnode(), &[123])
        .unwrap();
    observation.complete();
    let mut request = empty_owner(poisoned).into_repair_request();
    assert_eq!(
        request.require_pending_until(endpoint()),
        Err(RepairRequestRefusal::TriggerUnknown)
    );
    let late = Shared::new();
    let observation = late
        .begin_repair_observation(Source::Kqueue, endpoint())
        .unwrap();
    late.dispatch_observed_event(observation.window(), vnode(), &[123])
        .unwrap();
    observation.complete();
    let mut request = empty_owner(late.clone()).into_repair_request();
    late.repair_bounds.lock().unwrap().as_mut().unwrap().end = Instant::now();
    assert_eq!(
        request.require_pending_until(endpoint()),
        Err(RepairRequestRefusal::Deadline)
    );
    late.repair_bounds.lock().unwrap().as_mut().unwrap().end = endpoint();
    assert_eq!(
        request.require_pending_until(endpoint()),
        Err(RepairRequestRefusal::Deadline)
    );
    assert_original_negative(&late);
}
#[test]
fn repair_timers_and_query_epochs_do_not_trigger_and_restored_fixture_bits_never_revive_refusal() {
    let shared = Shared::new();
    let observation = shared
        .begin_repair_observation(Source::Kqueue, endpoint())
        .unwrap();
    shared
        .dispatch_observed_event(observation.window(), timer(), &[])
        .unwrap();
    shared.invalidate(Source::DynamicStore).unwrap();
    observation.complete();
    assert!(shared.repair_bounds.lock().unwrap().is_none());
    let mut request = empty_owner(shared.clone()).into_repair_request();
    assert_eq!(
        request.require_pending_until(endpoint()),
        Err(RepairRequestRefusal::MissingTrigger)
    );
    *shared.repair_bounds.lock().unwrap() = Some(RepairBounds {
        started: Instant::now(),
        end: endpoint(),
    });
    shared.repair_unknown.store(false, Ordering::SeqCst);
    assert_eq!(
        request.require_pending_until(endpoint()),
        Err(RepairRequestRefusal::MissingTrigger)
    );
    assert_original_negative(&shared);
}
#[test]
fn repair_request_retains_exact_original_worker_and_unknown_resource_bundle_until_original_join() {
    let shared = Shared::new();
    let (owner, release, dropped) = owner_with_held_original_thread(shared.clone());
    let allocation = owner.resources.as_deref().unwrap() as *const Resources;
    let observation = shared
        .begin_repair_observation(Source::Kqueue, endpoint())
        .unwrap();
    shared
        .dispatch_observed_event(observation.window(), vnode(), &[123])
        .unwrap();
    observation.complete();
    let mut request = owner.into_repair_request();
    assert_eq!(
        request.owner.resources.as_deref().unwrap() as *const Resources,
        allocation
    );
    assert!(request.require_pending_until(endpoint()).is_ok());
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    assert!(request.owner.workers[0].is_some());
    assert_original_negative(&shared);
    let mut retained = OnceLock::new();
    retire_bundle(&retained, request.owner.resources.take().unwrap());
    drop(request); // Same retirement path as production Drop, local fixture slot.
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    assert_eq!(
        retained.get().unwrap().as_ref() as *const Resources,
        allocation
    );
    release.send(()).unwrap();
    let mut original = retained.take().unwrap();
    original.workers[0].take().unwrap().join().unwrap();
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert_original_negative(&shared);
}

#[test]
fn repair_request_requires_old_session_veto_and_later_fixture_restoration_never_clears_refusal() {
    let shared = Shared::new();
    let observation = shared
        .begin_repair_observation(Source::Kqueue, endpoint())
        .unwrap();
    shared
        .dispatch_observed_event(observation.window(), vnode(), &[123])
        .unwrap();
    observation.complete();
    let mut request = empty_owner(shared.clone()).into_repair_request();
    fixture_session(&shared.binding).store(false, Ordering::SeqCst);
    assert_eq!(
        request.require_pending_until(endpoint()),
        Err(RepairRequestRefusal::OriginalVetoRequired)
    );
    assert_original_negative(&shared); // Refusal re-veto precedes cleanup.
    assert_eq!(
        request.require_pending_until(endpoint()),
        Err(RepairRequestRefusal::OriginalVetoRequired)
    );
}

// SOFTWARE ONLY: these owners retain real fixture JoinHandles, but never
// register native sources or establish configd continuity/PF enforcement.
struct CollectionOwnerFixture {
    owner: PfNotifications,
    release: Vec<mpsc::SyncSender<()>>,
}
impl CollectionOwnerFixture {
    fn new() -> Self {
        let shared = Shared::new();
        let mut owner = empty_owner(shared.clone());
        let mut release = Vec::new();
        for source in [Source::Kqueue, Source::DynamicStore] {
            let (send, receive) = mpsc::sync_channel(1);
            let (started, ready) = mpsc::sync_channel(1);
            let state = shared.clone();
            owner.workers[source.slot()] = Some(thread::spawn(move || {
                arm(&state, source);
                started.send(()).unwrap();
                let _exit = WorkerExit {
                    shared: state,
                    source,
                };
                let _ = receive.recv();
            }));
            ready.recv_timeout(Duration::from_secs(2)).unwrap();
            release.push(send);
        }
        Self { owner, release }
    }
    fn progress(&self) -> NotificationProgress {
        NotificationProgress {
            allocation: self.owner.shared.clone(),
            generation: self.owner.shared.generation.load(Ordering::SeqCst),
            ticks: 0,
            source_bits: 0,
            unstable: false,
            started_boot_ns: 0,
            ended_boot_ns: 0,
            worker_boot_ns: [0; 2],
            session_continuity: SessionContinuity::UnavailablePublicContract,
        }
    }
    fn window(&self, end: Instant) -> NegativeCollectionWindow<'_> {
        NegativeCollectionWindow::from_progress(&self.owner, self.progress(), end).unwrap()
    }
}
impl Drop for CollectionOwnerFixture {
    fn drop(&mut self) {
        self.owner.request_stop();
        for release in self.release.drain(..) {
            let _ = release.send(());
        }
        // Join only our synthetic fixture handles; never use production globals.
        if let Some(mut bundle) = self.owner.resources.take() {
            for worker in &mut bundle.workers {
                if let Some(worker) = worker.take() {
                    let _ = worker.join();
                }
            }
        }
    }
}
#[test]
fn collection_window_retains_exact_owner_allocation_postchallenge_generation_and_fixed_cap() {
    let fixture = CollectionOwnerFixture::new();
    fixture
        .owner
        .shared
        .invalidate(Source::DynamicStore)
        .unwrap();
    let end = endpoint();
    let window = fixture.window(end);
    assert!(std::ptr::eq(window.owner, &fixture.owner));
    assert!(Arc::ptr_eq(&window.allocation, &fixture.owner.shared));
    assert_eq!(window.generation, 1);
    assert_eq!(window.end, end);
    fixture.owner.shared.tick().unwrap();
    window
        .require_current(end + Duration::from_secs(30))
        .unwrap();
    assert_eq!(window.end, end);
    assert_eq!(window.generation, 1);
    window.complete(end).unwrap();
    assert!(!fixture.owner.shared.revoked.load(Ordering::SeqCst));
}
#[test]
fn collection_window_generation_change_refuses_and_cannot_be_revived_by_counter_reset() {
    let fixture = CollectionOwnerFixture::new();
    let end = endpoint();
    let window = fixture.window(end);
    fixture
        .owner
        .shared
        .invalidate(Source::DynamicStore)
        .unwrap();
    assert_eq!(
        window.check(end).unwrap_err().reason,
        Reason::CollectionChanged
    );
    assert_original_negative(&fixture.owner.shared);
    fixture
        .owner
        .shared
        .generation
        .store(window.generation, Ordering::SeqCst);
    assert!(window.check(end).is_err());
}
#[test]
fn collection_window_equal_generation_from_foreign_allocation_vetoes_both_domains() {
    let original = CollectionOwnerFixture::new();
    let foreign = CollectionOwnerFixture::new();
    assert_eq!(
        original.owner.shared.generation.load(Ordering::SeqCst),
        foreign.owner.shared.generation.load(Ordering::SeqCst)
    );
    assert!(NegativeCollectionWindow::from_progress(
        &original.owner,
        foreign.progress(),
        endpoint()
    )
    .is_err());
    assert_original_negative(&original.owner.shared);
    assert_original_negative(&foreign.owner.shared);
}
#[test]
fn collection_window_refuses_original_stop_phase_and_cleanup_uncertainty_without_generation_change()
{
    for mode in 0..5 {
        let fixture = CollectionOwnerFixture::new();
        let end = endpoint();
        let window = fixture.window(end);
        match mode {
            0 => fixture
                .owner
                .shared
                .binding
                .supervisor_stop
                .store(true, Ordering::SeqCst),
            1 => fixture.owner.shared.running[1].store(false, Ordering::SeqCst),
            2 => fixture.owner.shared.phase[0].store(STOPPED, Ordering::SeqCst),
            3 => fixture
                .owner
                .shared
                .stop_pending
                .store(true, Ordering::SeqCst),
            _ => fixture
                .owner
                .shared
                .stop_evidence_unknown
                .store(true, Ordering::SeqCst),
        }
        assert!(window.check(end).is_err());
        assert_original_negative(&fixture.owner.shared);
        assert_eq!(window.generation, 0);
    }
}
#[test]
fn collection_window_drop_or_caught_unwind_revokes_before_later_work() {
    for unwind in [false, true] {
        let fixture = CollectionOwnerFixture::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _window = fixture.window(endpoint());
            assert!(!unwind, "software collection body unwind");
        }));
        assert_eq!(result.is_err(), unwind);
        assert_original_negative(&fixture.owner.shared);
    }
}
#[test]
fn collection_window_shorter_or_original_expiry_cannot_be_renewed() {
    let fixture = CollectionOwnerFixture::new();
    let end = endpoint();
    let window = fixture.window(end);
    assert_eq!(
        window.check(Instant::now()).unwrap_err().reason,
        Reason::Deadline
    );
    assert_original_negative(&fixture.owner.shared);
    assert!(window.complete(end + Duration::from_secs(30)).is_err());
    let fixture = CollectionOwnerFixture::new();
    assert!(NegativeCollectionWindow::from_progress(
        &fixture.owner,
        fixture.progress(),
        Instant::now()
    )
    .is_err());
    assert_original_negative(&fixture.owner.shared);
}
#[test]
fn collection_window_finished_original_handle_refuses_even_with_forged_armed_phase() {
    let mut fixture = CollectionOwnerFixture::new();
    fixture.release.remove(0).send(()).unwrap();
    let end = endpoint();
    while !fixture.owner.workers[0].as_ref().unwrap().is_finished() && Instant::now() < end {
        thread::yield_now();
    }
    assert!(fixture.owner.workers[0].as_ref().unwrap().is_finished());
    // Remove fixture WorkerExit's visible veto to isolate actual handle check.
    fixture_session(&fixture.owner.shared.binding).store(false, Ordering::SeqCst);
    fixture
        .owner
        .shared
        .binding
        .supervisor_stop
        .store(false, Ordering::SeqCst);
    fixture.owner.shared.revoked.store(false, Ordering::SeqCst);
    fixture.owner.shared.stop.store(false, Ordering::SeqCst);
    arm(&fixture.owner.shared, Source::Kqueue);
    assert!(
        NegativeCollectionWindow::from_progress(&fixture.owner, fixture.progress(), end).is_err()
    );
    assert_original_negative(&fixture.owner.shared);
}
#[test]
fn collection_window_known_invalidation_vetoes_before_blocked_journal_reporting() {
    let fixture = CollectionOwnerFixture::new();
    let end = endpoint();
    let window = fixture.window(end);
    fixture
        .owner
        .shared
        .invalidate(Source::DynamicStore)
        .unwrap();
    let guard = fixture.owner.shared.journal.lock().unwrap();
    // Private negative checks never acquire the journal; reporting may wait
    // only after the SAME session/stop domain has already been revoked.
    assert_eq!(
        window.check(end).unwrap_err().reason,
        Reason::CollectionChanged
    );
    assert_original_negative(&fixture.owner.shared);
    assert!(guard.first.is_none());
    drop(guard);
}
