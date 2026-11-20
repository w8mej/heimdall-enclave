//! Repository-local socket/FD/lifecycle fixtures. No fixture constructs native
//! root identity, real PowerMonitor, selected context or root channel authority.
use super::*;
use std::{
    io::{Read, Write},
    os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt},
    sync::atomic::AtomicUsize,
    thread,
};

// Private synthetic capabilities test only the real mailbox state machine.
// They cannot create a production CertifiedReceivedTaskAudit or native handle.
struct ActorFixtureSession {
    end: Instant,
    revoked: AtomicBool,
}
impl ActorSession for ActorFixtureSession {
    fn check_atomic(&self) -> EnclaveResult<()> {
        if self.revoked.load(Ordering::SeqCst) {
            Err(err!(EACCES, "FIXTURE_ACTOR_REVOKED"))
        } else {
            Ok(())
        }
    }
    fn check_current(&self) -> EnclaveResult<()> {
        self.check_atomic()?;
        if Instant::now() >= self.end {
            Err(err!(ETIMEDOUT, "FIXTURE_ACTOR_EXPIRED"))
        } else {
            Ok(())
        }
    }
    fn revoke_atomic(&self) {
        self.revoked.store(true, Ordering::SeqCst);
    }
    fn original_end(&self) -> Instant {
        self.end
    }
}
struct ActorFixtureAudit {
    session: Arc<ActorFixtureSession>,
    end: Instant,
    active: AtomicBool,
    calls: AtomicUsize,
}
impl ActorAudit<ActorFixtureSession> for ActorFixtureAudit {
    fn check_original(
        &self,
        session: &Arc<ActorFixtureSession>,
        end: Instant,
    ) -> EnclaveResult<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if !Arc::ptr_eq(session, &self.session)
            || !self.active.load(Ordering::SeqCst)
            || Instant::now() >= self.end.min(end)
        {
            return Err(err!(EACCES, "FIXTURE_ACTOR_AUDIT"));
        }
        session.check_current()
    }
    fn original_end(&self) -> Instant {
        self.end
    }
}
type FixtureMailbox = ActorMailbox<ActorFixtureAudit, ActorFixtureSession>;
fn actor_fixture() -> (
    Arc<FixtureMailbox>,
    Arc<ActorFixtureSession>,
    Arc<ActorFixtureAudit>,
) {
    let session = Arc::new(ActorFixtureSession {
        end: end(),
        revoked: AtomicBool::new(false),
    });
    let audit = Arc::new(ActorFixtureAudit {
        session: session.clone(),
        end: session.end,
        active: AtomicBool::new(true),
        calls: AtomicUsize::new(0),
    });
    let mailbox = ActorMailbox::new(
        session.clone(),
        session.end,
        Arc::new(AtomicBool::new(false)),
    );
    (mailbox, session, audit)
}
fn actor_waiter(
    mailbox: &Arc<FixtureMailbox>,
    session: &Arc<ActorFixtureSession>,
    audit: &Arc<ActorFixtureAudit>,
    until: Instant,
) -> thread::JoinHandle<EnclaveResult<ActorReceipt<ActorFixtureAudit, ActorFixtureSession>>> {
    let mailbox = mailbox.clone();
    let session = session.clone();
    let audit = audit.clone();
    thread::spawn(move || mailbox.compare(audit, &session, until))
}
fn actor_request(mailbox: &Arc<FixtureMailbox>) -> ActorRequest<ActorFixtureAudit> {
    let until = end();
    loop {
        if let Some(request) = mailbox.take().unwrap() {
            return request;
        }
        assert!(Instant::now() < until, "fixture request never queued");
        thread::yield_now();
    }
}

#[test]
fn listener_actor_mailbox_unpublished_sender_slot_never_contends_with_original_actor_poll() {
    let (mailbox, session, audit) = actor_fixture();
    let _presence = mailbox.enter_actor().unwrap();
    // Hold the exact metadata lock as the sender does before publication. A
    // normal actor poll has no request yet and must never touch this lock.
    let key = Arc::new(ActorKey {
        actor: mailbox.actor.clone(),
        serial: 1,
        challenge: [0x7b; 32],
    });
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let until = end().min(session.end);
    let mut held = mailbox.state.lock().unwrap();
    held.next = 1;
    held.inflight = Some(key.clone());
    held.pending = Some(ActorRequest {
        key: key.clone(),
        audit: audit.clone(),
        end: until,
        response: send,
    });
    mailbox.busy.store(true, Ordering::SeqCst);
    mailbox.serial.store(1, Ordering::SeqCst);
    assert!(mailbox.take().unwrap().is_none());
    assert!(!session.revoked.load(Ordering::SeqCst));
    assert!(!mailbox.veto.load(Ordering::SeqCst));
    assert!(Arc::ptr_eq(&held.pending.as_ref().unwrap().key, &key));
    drop(held);
    mailbox.pending_published.store(true, Ordering::SeqCst);
    let request = mailbox.take().unwrap().unwrap();
    assert!(Arc::ptr_eq(&request.key, &key) && Arc::ptr_eq(&request.audit, &audit));
    assert_eq!(request.end, until);
    assert!(!mailbox.pending_published.load(Ordering::SeqCst));
    mailbox
        .process(request, |actual, end| {
            assert!(std::ptr::eq(actual, audit.as_ref()));
            assert_eq!(end, until);
            assert!(mailbox.state.try_lock().is_ok());
            Ok(())
        })
        .unwrap();
    assert!(Arc::ptr_eq(&receive.try_recv().unwrap(), &key));
    assert!(!session.revoked.load(Ordering::SeqCst));
    // A published request still refuses actual contention rather than waiting
    // or retrying. This cannot arise from the production sender's publication.
    let (mailbox, session, _) = actor_fixture();
    let _presence = mailbox.enter_actor().unwrap();
    mailbox.pending_published.store(true, Ordering::SeqCst);
    let held = mailbox.state.lock().unwrap();
    assert!(mailbox.take().is_err());
    assert!(session.revoked.load(Ordering::SeqCst));
    drop(held);
}

#[test]
fn listener_actor_mailbox_exact_original_session_audit_and_request_succeed_without_queue_lock_callbacks(
) {
    let (mailbox, session, audit) = actor_fixture();
    let presence = mailbox.enter_actor().unwrap();
    let waiter = actor_waiter(&mailbox, &session, &audit, end());
    let request = actor_request(&mailbox);
    let key = request.key.clone();
    assert_ne!(key.challenge, [0; 32]);
    assert_eq!(key.serial, 1);
    mailbox
        .process(request, |actual, until| {
            assert!(std::ptr::eq(actual, audit.as_ref()));
            assert!(until <= session.end);
            assert!(
                mailbox.state.try_lock().is_ok(),
                "no queue lock during native/peer/owner work"
            );
            Ok(())
        })
        .unwrap();
    let receipt = waiter.join().unwrap().unwrap();
    receipt.require(&audit, &session, end()).unwrap();
    assert!(Arc::ptr_eq(&receipt.key, &key));
    assert!(!session.revoked.load(Ordering::SeqCst));
    assert!(!mailbox.busy.load(Ordering::SeqCst));
    assert!(mailbox.state.lock().unwrap().inflight.is_none());
    drop(presence);
    assert!(session.revoked.load(Ordering::SeqCst));
    assert!(receipt.require(&audit, &session, end()).is_err());
}

#[test]
fn listener_actor_mailbox_serial_and_fresh_challenge_prevent_previous_success_reuse() {
    let (mailbox, session, audit) = actor_fixture();
    let _presence = mailbox.enter_actor().unwrap();
    let mut receipts = Vec::new();
    for _ in 0..2 {
        let waiter = actor_waiter(&mailbox, &session, &audit, end());
        let request = actor_request(&mailbox);
        mailbox.process(request, |_, _| Ok(())).unwrap();
        receipts.push(waiter.join().unwrap().unwrap());
    }
    assert_eq!(receipts[0].key.serial, 1);
    assert_eq!(receipts[1].key.serial, 2);
    assert_ne!(receipts[0].key.challenge, receipts[1].key.challenge);
    assert!(!Arc::ptr_eq(&receipts[0].key, &receipts[1].key));
    receipts[1].require(&audit, &session, end()).unwrap();
    assert!(receipts[0].require(&audit, &session, end()).is_err());
    assert!(session.revoked.load(Ordering::SeqCst));
}

#[test]
fn listener_actor_mailbox_busy_vetoes_same_session_before_any_queue_lock_or_second_callback() {
    let (mailbox, session, audit) = actor_fixture();
    let _presence = mailbox.enter_actor().unwrap();
    let waiter = actor_waiter(&mailbox, &session, &audit, end());
    let request = actor_request(&mailbox);
    let calls = audit.calls.load(Ordering::SeqCst);
    let queue = mailbox.state.lock().unwrap();
    assert!(mailbox.compare(audit.clone(), &session, end()).is_err());
    assert_eq!(
        audit.calls.load(Ordering::SeqCst),
        calls,
        "busy refusal precedes callbacks"
    );
    assert!(session.revoked.load(Ordering::SeqCst));
    assert!(mailbox.veto.load(Ordering::SeqCst));
    drop(queue);
    drop(request);
    assert!(waiter.join().unwrap().is_err());
}

#[test]
fn listener_actor_mailbox_blocked_original_actor_times_out_vetoes_without_shutdown_and_withholds_late_reply(
) {
    let (mailbox, session, audit) = actor_fixture();
    let _presence = mailbox.enter_actor().unwrap();
    let waiter = actor_waiter(
        &mailbox,
        &session,
        &audit,
        Instant::now() + Duration::from_secs(1),
    );
    let request = actor_request(&mailbox);
    let worker_mailbox = mailbox.clone();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let actor = thread::spawn(move || {
        worker_mailbox.process(request, |_, _| {
            assert!(worker_mailbox.state.try_lock().is_ok());
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            Ok(())
        })
    });
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(waiter.join().unwrap().is_err());
    assert!(session.revoked.load(Ordering::SeqCst));
    assert!(mailbox.veto.load(Ordering::SeqCst));
    assert!(!actor.is_finished(), "actual actor remains charged/blocked");
    assert!(mailbox.state.try_lock().is_ok());
    release_tx.send(()).unwrap();
    assert!(actor.join().unwrap().is_err());
}

#[test]
fn listener_actor_mailbox_wrong_session_and_wrong_audit_arc_never_become_original_match() {
    let (mailbox, session, audit) = actor_fixture();
    let _presence = mailbox.enter_actor().unwrap();
    let other = Arc::new(ActorFixtureSession {
        end: session.end,
        revoked: AtomicBool::new(false),
    });
    assert!(mailbox.compare(audit.clone(), &other, end()).is_err());
    assert!(session.revoked.load(Ordering::SeqCst) && other.revoked.load(Ordering::SeqCst));
    let (mailbox, session, audit) = actor_fixture();
    let _presence = mailbox.enter_actor().unwrap();
    let waiter = actor_waiter(&mailbox, &session, &audit, end());
    let request = actor_request(&mailbox);
    mailbox.process(request, |_, _| Ok(())).unwrap();
    let receipt = waiter.join().unwrap().unwrap();
    let copied = Arc::new(ActorFixtureAudit {
        session: session.clone(),
        end: audit.end,
        active: AtomicBool::new(true),
        calls: AtomicUsize::new(0),
    });
    assert!(receipt.require(&copied, &session, end()).is_err());
    assert!(session.revoked.load(Ordering::SeqCst));
}

#[test]
fn listener_actor_mailbox_stale_or_copied_reply_key_cannot_match_original_request_allocation() {
    for changed in 0..4 {
        let (mailbox, session, audit) = actor_fixture();
        let _presence = mailbox.enter_actor().unwrap();
        let waiter = actor_waiter(&mailbox, &session, &audit, end());
        let request = actor_request(&mailbox);
        let mut challenge = request.key.challenge;
        if changed == 2 {
            challenge[0] ^= 1;
        }
        let key = Arc::new(ActorKey {
            actor: if changed == 0 {
                Arc::new(())
            } else {
                request.key.actor.clone()
            },
            serial: request.key.serial + if changed == 1 { 1 } else { 0 },
            challenge,
        });
        assert!(request.response.try_send(key).is_ok());
        drop(request);
        assert!(waiter.join().unwrap().is_err());
        assert!(session.revoked.load(Ordering::SeqCst));
    }
}

#[test]
fn listener_actor_mailbox_missing_actor_expired_audit_or_actor_exit_refuse_without_enqueue_or_rearm(
) {
    for variant in 0..3 {
        let (mailbox, session, audit) = actor_fixture();
        let mut presence = if variant == 0 {
            None
        } else {
            Some(mailbox.enter_actor().unwrap())
        };
        if variant == 1 {
            audit.active.store(false, Ordering::SeqCst);
        }
        if variant == 2 {
            drop(presence.take());
        }
        assert!(mailbox.compare(audit.clone(), &session, end()).is_err());
        assert!(session.revoked.load(Ordering::SeqCst));
        assert!(mailbox.state.lock().unwrap().pending.is_none());
        assert!(mailbox.enter_actor().is_err());
    }
}

#[test]
fn listener_actor_mailbox_lease_loss_error_and_unwind_veto_before_original_owner_outer_cleanup() {
    for variant in 0..3 {
        let (mailbox, session, audit) = actor_fixture();
        let _presence = mailbox.enter_actor().unwrap();
        let waiter = actor_waiter(&mailbox, &session, &audit, end());
        let request = actor_request(&mailbox);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            mailbox.process(request, |_, _| {
                assert!(mailbox.state.try_lock().is_ok());
                match variant {
                    0 => {
                        audit.active.store(false, Ordering::SeqCst);
                        Ok(())
                    }
                    1 => Err(err!(EACCES, "FIXTURE_ACTOR_PEER_CHANGED")),
                    _ => panic!("actor native boundary unwind"),
                }
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        // This boundary is before the surrounding actor/channel/resource Drop.
        assert!(session.revoked.load(Ordering::SeqCst));
        assert!(mailbox.veto.load(Ordering::SeqCst));
        assert!(mailbox.state.try_lock().is_ok());
        assert!(waiter.join().unwrap().is_err());
    }
}

#[test]
fn listener_actor_mailbox_queue_contention_poison_and_serial_overflow_have_atomic_negative_exit() {
    let (mailbox, session, audit) = actor_fixture();
    let _presence = mailbox.enter_actor().unwrap();
    let held = mailbox.state.lock().unwrap();
    assert!(mailbox.compare(audit, &session, end()).is_err());
    assert!(session.revoked.load(Ordering::SeqCst));
    drop(held);
    let (mailbox, session, audit) = actor_fixture();
    let _presence = mailbox.enter_actor().unwrap();
    let poisoned = mailbox.clone();
    assert!(thread::spawn(move || {
        let _held = poisoned.state.lock().unwrap();
        panic!("queue poison");
    })
    .join()
    .is_err());
    assert!(mailbox.compare(audit, &session, end()).is_err());
    assert!(session.revoked.load(Ordering::SeqCst));
    let (mailbox, session, audit) = actor_fixture();
    let _presence = mailbox.enter_actor().unwrap();
    mailbox.state.lock().unwrap().next = u64::MAX;
    assert!(mailbox.compare(audit, &session, end()).is_err());
    assert!(session.revoked.load(Ordering::SeqCst));
    assert_eq!(mailbox.state.lock().unwrap().next, u64::MAX);
    assert!(mailbox.state.lock().unwrap().pending.is_none());
}

#[test]
fn listener_actor_mailbox_original_caps_and_pending_request_cannot_be_extended_or_replaced() {
    let (mailbox, session, _) = actor_fixture();
    let _presence = mailbox.enter_actor().unwrap();
    let audit = Arc::new(ActorFixtureAudit {
        session: session.clone(),
        end: Instant::now() + Duration::from_secs(1),
        active: AtomicBool::new(true),
        calls: AtomicUsize::new(0),
    });
    let waiter = actor_waiter(&mailbox, &session, &audit, end());
    let request = actor_request(&mailbox);
    assert!(
        request.end <= audit.end && request.end <= session.end && request.end <= mailbox.original
    );
    let old = request.key.clone();
    let (tx, _rx) = std::sync::mpsc::sync_channel(1);
    mailbox.state.lock().unwrap().pending = Some(ActorRequest {
        key: old,
        audit: audit.clone(),
        end: request.end,
        response: tx,
    });
    // An unexpected pending slot cannot start native work or yield a response,
    // even when an injected private fixture copies the exact original key.
    let calls = std::cell::Cell::new(0);
    assert!(mailbox
        .process(request, |_, _| {
            calls.set(calls.get() + 1);
            Ok(())
        })
        .is_err());
    assert_eq!(calls.get(), 0);
    assert!(waiter.join().unwrap().is_err());
    assert!(session.revoked.load(Ordering::SeqCst));
}
fn end() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn mode(path: &Path, bits: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits)).unwrap();
}
fn open(path: &Path) -> File {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .unwrap()
}
#[derive(Clone)]
struct Signal {
    calls: Arc<AtomicUsize>,
}
impl StopOriginal for Signal {
    fn stop_original(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}
fn new_control() -> Control<Signal> {
    Control::new(
        end(),
        Signal {
            calls: Arc::new(AtomicUsize::new(0)),
        },
    )
}
struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = PathBuf::from("target")
            .join(format!("ol-{}", hex::encode(&crate::rng::bytes32()[..6])));
        std::fs::create_dir_all("target").unwrap();
        std::fs::create_dir(&root).unwrap();
        mode(&root, 0o700);
        std::fs::create_dir(root.join("mesh")).unwrap();
        mode(&root.join("mesh"), 0o755);
        Self { root }
    }
    fn parent(&self) -> PathBuf {
        self.root.join("mesh")
    }
    fn path(&self) -> PathBuf {
        self.parent().join(SOCKET_LEAF)
    }
    fn empty(&self) -> Bound {
        let parent = Arc::new(open(&self.parent()));
        let metadata = parent.metadata().unwrap();
        Bound::new(
            Context::Fixture {
                root: self.root.clone(),
                uid: metadata.uid(),
                gid: metadata.gid(),
            },
            self.parent(),
            parent,
        )
        .unwrap()
    }
    fn bind(&self) -> (Bound, Control<Signal>) {
        self.bind_hook(&mut |_, _| {})
    }
    fn bind_hook(&self, hook: &mut impl FnMut(Point, &Path)) -> (Bound, Control<Signal>) {
        let mut bound = self.empty();
        let control = new_control();
        control
            .advance(Phase::Fresh, Phase::Binding, end())
            .unwrap();
        let result = bound.prepare(&control, end(), hook);
        if result.is_ok() {
            control
                .advance(Phase::Binding, Phase::Bound, end())
                .unwrap();
        } else {
            control.stop();
        }
        result.unwrap();
        (bound, control)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.root, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::set_permissions(self.parent(), std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn run(control: &Control<Signal>) {
    control
        .advance(Phase::Bound, Phase::Running, end())
        .unwrap();
}
fn prepare_failure(
    fixture: &Fixture,
    hook: &mut impl FnMut(Point, &Path),
) -> (Bound, Control<Signal>, Reason) {
    let mut bound = fixture.empty();
    let control = new_control();
    control
        .advance(Phase::Fresh, Phase::Binding, end())
        .unwrap();
    let reason = bound.prepare(&control, end(), hook).unwrap_err();
    control.stop();
    (bound, control, reason)
}

#[test]
fn listener_fixed_leaf_final_dac_original_route_and_real_single_exchange() {
    let fixture = Fixture::new();
    let (bound, control) = fixture.bind();
    bound.current(&control, end()).unwrap();
    assert_eq!(bound.path, fixture.path());
    assert_eq!(bound.path.file_name().unwrap(), SOCKET_LEAF);
    let metadata = std::fs::symlink_metadata(&bound.path).unwrap();
    assert_eq!(metadata.mode() & 0o7777, 0o660);
    assert_eq!((metadata.uid(), metadata.gid()), bound.context.ids());
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(Some((metadata.dev(), metadata.ino())), bound.created);
    assert!(bound.listened);
    run(&control);
    let mut client = UnixStream::connect(&bound.path).unwrap();
    let mut server = bound.accept_one(&control, end(), &mut |_, _| {}).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    client.write_all(b"fixture").unwrap();
    let mut bytes = [0; 7];
    server.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"fixture");
    server.write_all(b"ok").unwrap();
    let mut bytes = [0; 2];
    client.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"ok");
    assert_eq!(control.life.lock().unwrap().phase, Phase::Accepted);
    control.stop();
    drop(bound);
    assert!(
        fixture.path().exists(),
        "production teardown must never unlink"
    );
}

#[test]
fn listener_every_preexisting_leaf_refuses_without_mutation_or_adoption() {
    for variant in 0..6 {
        let fixture = Fixture::new();
        let path = fixture.path();
        let mut socket = None;
        match variant {
            0 => {
                std::fs::write(&path, b"foreign").unwrap();
                mode(&path, 0o640);
            }
            1 => symlink("missing", &path).unwrap(),
            2 => {
                let name = CString::new(path.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o640) }, 0);
            }
            3 => {
                std::fs::create_dir(&path).unwrap();
                mode(&path, 0o700);
            }
            4 => {
                socket = Some(UnixListener::bind(&path).unwrap());
                mode(&path, 0o600);
            }
            _ => {
                std::fs::write(fixture.root.join("target"), b"untouched").unwrap();
                symlink("../target", &path).unwrap();
            }
        }
        let before = Identity::of(&std::fs::symlink_metadata(&path).unwrap());
        let (bound, control, reason) = prepare_failure(&fixture, &mut |_, _| {});
        assert_eq!(reason, Reason::Occupied);
        assert!(bound.listener.is_none() && bound.created.is_none());
        assert!(!bound.listened);
        assert!(bound.current(&control, end()).is_err());
        drop(bound);
        assert_eq!(
            Identity::of(&std::fs::symlink_metadata(&path).unwrap()),
            before
        );
        if variant == 0 {
            assert_eq!(std::fs::read(&path).unwrap(), b"foreign");
        }
        if variant == 5 {
            assert_eq!(
                std::fs::read(fixture.root.join("target")).unwrap(),
                b"untouched"
            );
        }
        drop(socket);
    }
}

#[test]
fn listener_unsafe_symlinked_or_wrong_provided_parent_never_binds() {
    for variant in 0..3 {
        let fixture = Fixture::new();
        let mut bound = fixture.empty();
        let control = new_control();
        control
            .advance(Phase::Fresh, Phase::Binding, end())
            .unwrap();
        match variant {
            0 => mode(&fixture.parent(), 0o775),
            1 => {
                std::fs::rename(fixture.parent(), fixture.root.join("saved")).unwrap();
                symlink("saved", fixture.parent()).unwrap();
            }
            _ => {
                std::fs::create_dir(fixture.root.join("other")).unwrap();
                mode(&fixture.root.join("other"), 0o755);
                bound.route.provided = Arc::new(open(&fixture.root.join("other")));
                bound.route.provided_fd = bound.route.provided.as_raw_fd();
            }
        }
        assert!(bound.prepare(&control, end(), &mut |_, _| {}).is_err());
        control.stop();
        assert!(bound.listener.is_none());
        assert!(!fixture.path().exists());
        if variant == 1 {
            std::fs::remove_file(fixture.parent()).unwrap();
            std::fs::rename(fixture.root.join("saved"), fixture.parent()).unwrap();
        }
    }
}

#[test]
fn listener_parent_and_ancestor_replacement_or_mode_loss_are_sticky() {
    for variant in 0..4 {
        let fixture = Fixture::new();
        let (bound, control) = fixture.bind();
        match variant {
            0 => mode(&fixture.parent(), 0o775),
            1 => {
                std::fs::rename(fixture.parent(), fixture.root.join("saved")).unwrap();
                std::fs::create_dir(fixture.parent()).unwrap();
                mode(&fixture.parent(), 0o755);
            }
            2 => mode(&fixture.root, 0o770),
            _ => {
                std::fs::rename(&fixture.root, fixture.root.with_extension("saved")).unwrap();
                std::fs::create_dir(&fixture.root).unwrap();
                mode(&fixture.root, 0o700);
            }
        }
        assert!(bound.current(&control, end()).is_err());
        assert!(control.flag.load(Ordering::Acquire));
        match variant {
            0 => mode(&fixture.parent(), 0o755),
            1 => {
                std::fs::remove_dir(fixture.parent()).unwrap();
                std::fs::rename(fixture.root.join("saved"), fixture.parent()).unwrap();
            }
            2 => mode(&fixture.root, 0o700),
            _ => {
                std::fs::remove_dir(&fixture.root).unwrap();
                std::fs::rename(fixture.root.with_extension("saved"), &fixture.root).unwrap();
            }
        }
        assert!(bound.current(&control, end()).is_err());
        assert!(!bound.listener.as_ref().unwrap().0.lock().unwrap().is_some());
    }
}

#[test]
fn listener_socket_replacement_mode_or_link_change_never_revives_original() {
    for variant in 0..3 {
        let fixture = Fixture::new();
        let (bound, control) = fixture.bind();
        let original = bound.created;
        match variant {
            0 => {
                std::fs::rename(&bound.path, bound.path.with_extension("saved")).unwrap();
                std::fs::write(&bound.path, b"foreign").unwrap();
            }
            1 => mode(&bound.path, 0o600),
            _ => std::fs::hard_link(&bound.path, bound.path.with_extension("other")).unwrap(),
        }
        assert!(bound.current(&control, end()).is_err());
        assert_eq!(bound.created, original);
        if variant == 0 {
            assert_eq!(std::fs::read(&bound.path).unwrap(), b"foreign");
            std::fs::remove_file(&bound.path).unwrap();
            std::fs::rename(bound.path.with_extension("saved"), &bound.path).unwrap();
        }
        if variant == 1 {
            mode(&bound.path, 0o660);
        }
        assert!(bound.current(&control, end()).is_err());
    }
}

#[test]
fn listener_substitution_after_bind_never_chmods_or_listens_on_replacement() {
    let fixture = Fixture::new();
    let (bound, control, reason) = prepare_failure(&fixture, &mut |point, path| {
        if point == Point::AfterBind {
            std::fs::rename(path, path.with_extension("saved")).unwrap();
            std::fs::write(path, b"foreign").unwrap();
            mode(path, 0o640);
        }
    });
    assert_eq!(reason, Reason::Changed);
    assert!(bound.created.is_some());
    assert!(!bound.listened && bound.protected.is_none());
    assert_eq!(std::fs::read(&bound.path).unwrap(), b"foreign");
    assert_eq!(
        std::fs::symlink_metadata(&bound.path).unwrap().mode() & 0o7777,
        0o640
    );
    assert!(bound.current(&control, end()).is_err());
}

#[test]
fn listener_protection_or_name_loss_after_dac_and_listen_is_terminal() {
    for checkpoint in [Point::AfterDac, Point::AfterListen] {
        let fixture = Fixture::new();
        let (bound, control, _) = prepare_failure(&fixture, &mut |point, path| {
            if point == checkpoint {
                if point == Point::AfterDac {
                    mode(path, 0o666);
                } else {
                    std::fs::rename(path, path.with_extension("saved")).unwrap();
                }
            }
        });
        assert_eq!(bound.listened, checkpoint == Point::AfterListen);
        assert!(bound.protected.is_some());
        assert!(control.flag.load(Ordering::Acquire));
        assert!(bound.current(&control, end()).is_err());
        assert!(control
            .advance(Phase::Terminal, Phase::Running, end())
            .is_err());
    }
}

#[test]
fn listener_external_stop_before_bind_and_at_each_socket_checkpoint_cannot_late_listen() {
    let fixture = Fixture::new();
    let mut bound = fixture.empty();
    let control = new_control();
    control.stop();
    assert!(control
        .advance(Phase::Fresh, Phase::Binding, end())
        .is_err());
    assert!(bound.prepare(&control, end(), &mut |_, _| {}).is_err());
    assert!(bound.listener.is_none());
    assert!(!fixture.path().exists());
    for checkpoint in [
        Point::AfterSocket,
        Point::AfterBind,
        Point::AfterDac,
        Point::AfterListen,
    ] {
        let fixture = Fixture::new();
        let mut bound = fixture.empty();
        let control = new_control();
        control
            .advance(Phase::Fresh, Phase::Binding, end())
            .unwrap();
        assert!(bound
            .prepare(&control, end(), &mut |point, _| if point == checkpoint {
                control.stop();
            })
            .is_err());
        assert_eq!(bound.listened, checkpoint == Point::AfterListen);
        assert!(bound.listener.as_ref().unwrap().0.lock().unwrap().is_none());
        assert!(bound.current(&control, end()).is_err());
    }
}

#[test]
fn listener_changed_original_descriptor_flags_poison_even_if_restored() {
    for parent in [false, true] {
        let fixture = Fixture::new();
        let (bound, control) = fixture.bind();
        if parent {
            let raw = bound.route.provided.as_raw_fd();
            let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
            assert_eq!(
                unsafe { libc::fcntl(raw, libc::F_SETFL, flags & !libc::O_NONBLOCK) },
                0
            );
            assert!(bound.current(&control, end()).is_err());
            assert_eq!(unsafe { libc::fcntl(raw, libc::F_SETFL, flags) }, 0);
        } else {
            let listener = bound.listener.as_ref().unwrap().lease().unwrap();
            let raw = listener.as_raw_fd();
            let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
            assert_eq!(
                unsafe { libc::fcntl(raw, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
                0
            );
            assert!(bound.current(&control, end()).is_err());
        }
        assert!(bound.current(&control, end()).is_err());
    }
}

#[test]
fn listener_expiry_before_bind_or_after_side_effect_keeps_exact_partial_name_without_listen() {
    let fixture = Fixture::new();
    let mut bound = fixture.empty();
    let control = new_control();
    control
        .advance(Phase::Fresh, Phase::Binding, end())
        .unwrap();
    assert_eq!(
        bound.prepare(&control, Instant::now(), &mut |_, _| {}),
        Err(Reason::Deadline)
    );
    control.stop();
    assert!(bound.listener.is_none());
    assert!(!fixture.path().exists());
    let fixture = Fixture::new();
    let mut bound = fixture.empty();
    let control = new_control();
    control
        .advance(Phase::Fresh, Phase::Binding, end())
        .unwrap();
    let until = Instant::now() + Duration::from_millis(30);
    let result = bound.prepare(&control, until, &mut |point, _| {
        if point == Point::AfterBind {
            thread::sleep(until.saturating_duration_since(Instant::now()));
        }
    });
    assert_eq!(result, Err(Reason::Deadline));
    control.stop();
    assert!(bound.created.is_some());
    assert!(!bound.listened);
    assert!(fixture.path().exists());
}

#[test]
fn listener_one_accept_is_serialized_and_another_private_accept_cannot_reach_kernel() {
    let fixture = Fixture::new();
    let (bound, control) = fixture.bind();
    run(&control);
    let _first = UnixStream::connect(&bound.path).unwrap();
    let first = bound.accept_one(&control, end(), &mut |_, _| {}).unwrap();
    let _second = UnixStream::connect(&bound.path).unwrap();
    assert!(control
        .accept(bound.listener.as_ref().unwrap(), end())
        .is_err());
    assert_eq!(control.life.lock().unwrap().phase, Phase::Terminal);
    drop(first);
    assert!(bound.accept_one(&control, end(), &mut |_, _| {}).is_err());
}

#[test]
fn listener_stop_while_waiting_accept_needs_no_connection_or_actor_command() {
    let fixture = Fixture::new();
    let (bound, control) = fixture.bind();
    run(&control);
    let bound = Arc::new(bound);
    let actor_bound = bound.clone();
    let actor_control = control.clone();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let actor = thread::spawn(move || {
        entered_tx.send(()).unwrap();
        actor_bound
            .accept_one(&actor_control, end(), &mut |_, _| {})
            .is_err()
    });
    entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    control.stop();
    assert!(actor.join().unwrap());
    assert!(bound.listener.as_ref().unwrap().0.lock().unwrap().is_none());
    assert!(fixture.path().exists());
}

#[test]
fn listener_stop_or_name_substitution_immediately_after_accept_withholds_and_shuts_stream() {
    for stop_after in [false, true] {
        let fixture = Fixture::new();
        let (bound, control) = fixture.bind();
        run(&control);
        let mut client = UnixStream::connect(&bound.path).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let result = bound.accept_one(&control, end(), &mut |point, path| {
            if point == Point::AfterAccept {
                if stop_after {
                    control.stop();
                } else {
                    std::fs::rename(path, path.with_extension("saved")).unwrap();
                }
            }
        });
        assert!(result.is_err());
        assert_eq!(client.read(&mut [0; 1]).unwrap(), 0);
        assert!(control
            .advance(Phase::Accepted, Phase::Running, end())
            .is_err());
    }
}

#[test]
fn listener_independent_original_guard_revokes_while_session_actor_is_blocked() {
    let fixture = Fixture::new();
    let (bound, control) = fixture.bind();
    run(&control);
    let bound = Arc::new(bound);
    let _client = UnixStream::connect(&bound.path).unwrap();
    let stream = bound.accept_one(&control, end(), &mut |_, _| {}).unwrap();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let actor_control = control.clone();
    let actor_bound = bound.clone();
    let actor = thread::spawn(move || {
        let _exit = StopOnExit(actor_control.clone());
        let _stream = stream;
        entered_tx.send(()).unwrap();
        resume_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        actor_bound.current(&actor_control, end()).is_err()
    });
    entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    mode(&fixture.parent(), 0o775);
    // Same original-check path as production guard, without actor progress.
    assert!(bound.current(&control, end()).is_err());
    assert!(control.signal.calls.load(Ordering::SeqCst) > 0);
    assert!(bound.listener.as_ref().unwrap().0.lock().unwrap().is_none());
    resume_tx.send(()).unwrap();
    assert!(actor.join().unwrap());
}

#[test]
fn listener_metadata_poison_and_actor_caught_unwind_are_terminal() {
    for poison in [false, true] {
        let fixture = Fixture::new();
        let (bound, control) = fixture.bind();
        run(&control);
        if poison {
            let life = control.life.clone();
            assert!(thread::spawn(move || {
                let _lock = life.lock().unwrap();
                panic!("fixture life poison");
            })
            .join()
            .is_err());
            assert!(control.check(end()).is_err());
        } else {
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _exit = StopOnExit(control.clone());
                panic!("fixture actor unwind");
            }))
            .is_err());
        }
        assert!(control.check(end()).is_err());
        assert!(bound.current(&control, end()).is_err());
        assert!(bound.listener.as_ref().unwrap().0.lock().unwrap().is_none());
    }
}

#[test]
fn listener_thread_accounting_retains_blocked_actor_and_guard_until_actual_joins() {
    let (actor_tx, actor_rx) = std::sync::mpsc::channel();
    let (guard_tx, guard_rx) = std::sync::mpsc::channel();
    let owner = Arc::new(());
    let weak = Arc::downgrade(&owner);
    let actor_owner = owner.clone();
    let guard_owner = owner.clone();
    drop(owner);
    let mut threads = Threads::new();
    threads.actor = Some(thread::spawn(move || {
        let _owner = actor_owner;
        actor_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        Ok(())
    }));
    threads.guardian = Some(thread::spawn(move || {
        let _owner = guard_owner;
        guard_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    }));
    let mut failures = Vec::new();
    threads.join_finished(&mut failures);
    assert!(!threads.complete());
    assert!(threads.actor.is_some() && threads.guardian.is_some());
    assert!(weak.upgrade().is_some());
    actor_tx.send(()).unwrap();
    guard_tx.send(()).unwrap();
    let until = Instant::now() + Duration::from_secs(1);
    while !threads.complete() && Instant::now() < until {
        threads.join_finished(&mut failures);
        thread::sleep(Duration::from_millis(1));
    }
    assert!(threads.complete());
    assert!(failures.is_empty());
    assert!(weak.upgrade().is_none());
}

#[test]
fn listener_thread_accounting_records_failed_or_unwound_actor_and_guard() {
    for unwind in [false, true] {
        let mut threads = Threads::new();
        threads.actor = Some(thread::spawn(move || {
            if unwind {
                panic!("actor fixture");
            }
            Err(error(Reason::Actor))
        }));
        threads.guardian = Some(thread::spawn(move || {
            if unwind {
                panic!("guard fixture");
            }
        }));
        let mut failures = Vec::new();
        let until = Instant::now() + Duration::from_secs(1);
        while !threads.complete() && Instant::now() < until {
            threads.join_finished(&mut failures);
            thread::sleep(Duration::from_millis(1));
        }
        assert!(threads.complete());
        assert!(failures.contains(if unwind {
            &Reason::Unwound
        } else {
            &Reason::Actor
        }));
        if unwind {
            assert!(failures.contains(&Reason::Guardian));
        }
    }
}

#[test]
fn listener_unrelated_sibling_entry_does_not_change_original_directory_identity() {
    let fixture = Fixture::new();
    let (bound, control) = fixture.bind();
    std::fs::write(fixture.parent().join("unrelated"), b"data").unwrap();
    bound.current(&control, end()).unwrap();
    control.stop();
}

#[test]
fn listener_native_gate_never_turns_linux_or_unselected_context_into_authority() {
    if native().is_err() {
        assert!(Context::capture(end()).is_err());
    }
    assert!(Context::capture(Instant::now()).is_err());
}

#[test]
fn listener_guard_preserves_exact_original_accept_cap_without_actor_progress() {
    let fixture = Fixture::new();
    let mut bound = fixture.empty();
    let control = new_control();
    let until = Instant::now() + Duration::from_millis(100);
    control
        .advance(Phase::Fresh, Phase::Binding, until)
        .unwrap();
    bound.prepare(&control, until, &mut |_, _| {}).unwrap();
    control
        .advance(Phase::Binding, Phase::Bound, until)
        .unwrap();
    control
        .advance(Phase::Bound, Phase::Running, until)
        .unwrap();
    thread::sleep(until.saturating_duration_since(Instant::now()));
    assert_eq!(control.check(control.original), Err(Reason::Deadline));
    assert!(bound.current(&control, control.original).is_err());
    assert!(bound.listener.as_ref().unwrap().0.lock().unwrap().is_none());
}

#[test]
fn listener_successful_first_accept_cannot_be_rearmed_even_before_stop() {
    let fixture = Fixture::new();
    let (bound, control) = fixture.bind();
    run(&control);
    let _client = UnixStream::connect(&bound.path).unwrap();
    let _server = bound.accept_one(&control, end(), &mut |_, _| {}).unwrap();
    assert_eq!(
        control.advance(Phase::Accepted, Phase::Running, end()),
        Err(Reason::Reused)
    );
    assert_eq!(control.life.lock().unwrap().phase, Phase::Terminal);
}

#[test]
fn listener_actor_completion_or_terminal_phase_cannot_erase_ever_accepted_charge() {
    let fixture = Fixture::new();
    let (bound, control) = fixture.bind();
    assert!(!control.ever_accepted());
    run(&control);
    let _client = UnixStream::connect(&bound.path).unwrap();
    let _server = bound.accept_one(&control, end(), &mut |_, _| {}).unwrap();
    control.stop();
    assert!(control.ever_accepted());
    assert_eq!(control.life.lock().unwrap().phase, Phase::Terminal);
    assert!(control
        .advance(Phase::Terminal, Phase::Fresh, end())
        .is_err());
    assert!(control.ever_accepted());
    // Joined listener threads alone intentionally cannot certify the channel's
    // private detached watcher/wipe owner. Native Resources enforces this gap.
}

#[test]
fn listener_stop_cancels_before_gated_bind_or_listen_lease_resumes_and_late_success_is_withheld() {
    // These gates model a stalled native-call boundary with the actual original
    // descriptor leased. They do not claim to force a blocked kernel syscall.
    for checkpoint in [
        Point::BeforeBindCall,
        Point::AfterBindCall,
        Point::BeforeListenCall,
        Point::AfterListenCall,
    ] {
        let fixture = Fixture::new();
        let mut bound = fixture.empty();
        let control = new_control();
        control
            .advance(Phase::Fresh, Phase::Binding, end())
            .unwrap();
        let actor_control = control.clone();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let actor = thread::spawn(move || {
            let result = bound.prepare(&actor_control, end(), &mut |point, _| {
                if point == checkpoint {
                    entered_tx.send(()).unwrap();
                    resume_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                }
            });
            (result, bound)
        });
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let cell = control
            .life
            .lock()
            .unwrap()
            .listener
            .as_ref()
            .unwrap()
            .clone();
        let weak = {
            let lease = cell.lease().unwrap();
            Arc::downgrade(&lease)
        };
        control.stop();
        assert!(control.signal.calls.load(Ordering::SeqCst) > 0);
        assert!(control.life.try_lock().is_ok());
        assert!(cell.0.try_lock().is_ok());
        assert!(cell.lease().is_err());
        // Retired numeric FD is still owned by the blocked call's exact Arc.
        assert!(weak.upgrade().is_some());
        resume_tx.send(()).unwrap();
        let (result, bound) = actor.join().unwrap();
        assert!(result.is_err());
        assert!(control.check(end()).is_err());
        assert!(bound.created.is_some());
        assert!(fixture.path().exists());
        assert!(weak.upgrade().is_none());
        assert_eq!(
            bound.listened,
            checkpoint == Point::BeforeListenCall || checkpoint == Point::AfterListenCall
        );
        assert!(bound.current(&control, end()).is_err());
    }
}

#[test]
fn listener_native_descriptor_query_lease_never_holds_a_stop_metadata_mutex() {
    let fixture = Fixture::new();
    let (bound, control) = fixture.bind();
    let bound = Arc::new(bound);
    let actor_bound = bound.clone();
    let actor_control = control.clone();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let actor = thread::spawn(move || {
        let lease = actor_bound.listener.as_ref().unwrap().lease().unwrap();
        entered_tx.send(()).unwrap();
        resume_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        // Actual shared native query helper still observes the original socket,
        // but its late positive metadata cannot pass the terminal outer gate.
        assert!(listener_identity(&lease, Some(&actor_bound.path)).is_ok());
        actor_bound.current(&actor_control, end()).is_err()
    });
    entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    let cell = bound.listener.as_ref().unwrap();
    control.stop();
    assert!(control.signal.calls.load(Ordering::SeqCst) > 0);
    assert!(cell.0.try_lock().is_ok());
    assert!(control.life.try_lock().is_ok());
    assert!(cell.lease().is_err());
    resume_tx.send(()).unwrap();
    assert!(actor.join().unwrap());
}

#[test]
fn listener_stop_cancels_before_gated_accept_resumes_and_closes_late_real_stream() {
    for checkpoint in [Point::BeforeAcceptCall, Point::AfterAcceptCall] {
        let fixture = Fixture::new();
        let (bound, control) = fixture.bind();
        run(&control);
        let bound = Arc::new(bound);
        let mut client = UnixStream::connect(&bound.path).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let actor_bound = bound.clone();
        let actor_control = control.clone();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let actor = thread::spawn(move || {
            actor_bound
                .accept_one(&actor_control, end(), &mut |point, _| {
                    if point == checkpoint {
                        entered_tx.send(()).unwrap();
                        resume_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                    }
                })
                .is_err()
        });
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let cell = bound.listener.as_ref().unwrap();
        let weak = {
            let lease = cell.lease().unwrap();
            Arc::downgrade(&lease)
        };
        assert_eq!(control.life.lock().unwrap().phase, Phase::Accepting);
        control.stop();
        assert!(control.signal.calls.load(Ordering::SeqCst) > 0);
        assert!(control.life.try_lock().is_ok());
        assert!(cell.lease().is_err());
        assert!(weak.upgrade().is_some());
        resume_tx.send(()).unwrap();
        assert!(actor.join().unwrap());
        assert_eq!(client.read(&mut [0; 1]).unwrap(), 0);
        assert!(control.ever_accepted());
        assert!(weak.upgrade().is_none());
        assert_eq!(control.life.lock().unwrap().phase, Phase::Terminal);
    }
}

#[test]
fn listener_late_wouldblock_cannot_restore_running_after_stop() {
    let fixture = Fixture::new();
    let (bound, control) = fixture.bind();
    run(&control);
    let bound = Arc::new(bound);
    let actor_bound = bound.clone();
    let actor_control = control.clone();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let actor = thread::spawn(move || {
        actor_bound
            .accept_one(&actor_control, end(), &mut |point, _| {
                if point == Point::AfterAcceptCall {
                    entered_tx.send(()).unwrap();
                    resume_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                }
            })
            .is_err()
    });
    entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    control.stop();
    assert!(control.signal.calls.load(Ordering::SeqCst) > 0);
    resume_tx.send(()).unwrap();
    assert!(actor.join().unwrap());
    assert!(!control.ever_accepted());
    assert_eq!(control.life.lock().unwrap().phase, Phase::Terminal);
    assert!(control
        .advance(Phase::Bound, Phase::Running, end())
        .is_err());
}

#[test]
fn listener_concurrent_second_accept_cannot_enter_native_call_or_rearm_reserved_original() {
    let fixture = Fixture::new();
    let (bound, control) = fixture.bind();
    run(&control);
    let bound = Arc::new(bound);
    let mut client = UnixStream::connect(&bound.path).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let actor_bound = bound.clone();
    let actor_control = control.clone();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let actor = thread::spawn(move || {
        actor_bound
            .accept_one(&actor_control, end(), &mut |point, _| {
                if point == Point::BeforeAcceptCall {
                    entered_tx.send(()).unwrap();
                    resume_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                }
            })
            .is_err()
    });
    entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    let mut native_calls = 0;
    assert!(control
        .accept_with(bound.listener.as_ref().unwrap(), end(), &mut |_| {
            native_calls += 1
        })
        .is_err());
    assert_eq!(native_calls, 0);
    assert!(control.signal.calls.load(Ordering::SeqCst) > 0);
    resume_tx.send(()).unwrap();
    assert!(actor.join().unwrap());
    assert_eq!(client.read(&mut [0; 1]).unwrap(), 0);
    assert_eq!(control.life.lock().unwrap().phase, Phase::Terminal);
}

#[test]
fn listener_gated_preparation_or_accept_unwind_cancels_without_native_owner_escape() {
    for checkpoint in [Point::BeforeBindCall, Point::BeforeListenCall] {
        let fixture = Fixture::new();
        let mut bound = fixture.empty();
        let control = new_control();
        control
            .advance(Phase::Fresh, Phase::Binding, end())
            .unwrap();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| bound.prepare(
                &control,
                end(),
                &mut |point, _| if point == checkpoint {
                    panic!("leased preparation unwind");
                }
            )))
            .is_err()
        );
        assert!(control.signal.calls.load(Ordering::SeqCst) > 0);
        assert!(bound.listener.as_ref().unwrap().lease().is_err());
        assert!(control.check(end()).is_err());
    }
    for checkpoint in [Point::BeforeAcceptCall, Point::AfterAcceptCall] {
        let fixture = Fixture::new();
        let (bound, control) = fixture.bind();
        run(&control);
        let mut client = UnixStream::connect(&bound.path).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| bound.accept_one(
                &control,
                end(),
                &mut |point, _| if point == checkpoint {
                    panic!("leased accept unwind");
                }
            )))
            .is_err()
        );
        assert!(control.signal.calls.load(Ordering::SeqCst) > 0);
        assert!(bound.listener.as_ref().unwrap().lease().is_err());
        assert!(control.check(end()).is_err());
        // Before the actual accept, the queued peer can observe reset/refusal;
        // after it, the actual retained stream is explicitly shutdown on unwind.
        if checkpoint == Point::AfterAcceptCall {
            assert_eq!(client.read(&mut [0; 1]).unwrap(), 0);
        }
    }
}

#[test]
fn listener_poisoned_socket_cell_refuses_new_lease_and_cancels_without_guarded_native_calls() {
    let fixture = Fixture::new();
    let (bound, control) = fixture.bind();
    let cell = bound.listener.as_ref().unwrap().clone();
    let poisoned = cell.clone();
    assert!(thread::spawn(move || {
        let _state = poisoned.0.lock().unwrap();
        panic!("original socket cell poison");
    })
    .join()
    .is_err());
    assert!(cell.lease().is_err());
    assert!(bound.current(&control, end()).is_err());
    assert!(control.signal.calls.load(Ordering::SeqCst) > 0);
    assert!(cell
        .0
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .is_none());
    assert!(control.check(end()).is_err());
}

#[test]
fn listener_same_root_cancellation_runs_before_retired_original_native_close_outside_both_mutexes()
{
    #[derive(Clone)]
    struct InspectSignal {
        life: Arc<Mutex<Option<std::sync::Weak<Mutex<Life>>>>>,
        cell: Arc<Mutex<Option<Arc<ListenerCell>>>>,
        socket: Arc<Mutex<Option<std::sync::Weak<UnixListener>>>>,
        seen: Arc<AtomicUsize>,
    }
    impl StopOriginal for InspectSignal {
        fn stop_original(&self) {
            let life = self
                .life
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .upgrade()
                .unwrap();
            assert!(life.try_lock().is_ok());
            let cell = self.cell.lock().unwrap().clone();
            if let Some(cell) = cell {
                assert!(cell.0.try_lock().is_ok());
            }
            let socket = self.socket.lock().unwrap().clone();
            if let Some(socket) = socket {
                assert!(
                    socket.upgrade().is_some(),
                    "same original must remain owned until cancellation runs"
                );
            }
            self.seen.fetch_add(1, Ordering::SeqCst);
        }
    }
    let fixture = Fixture::new();
    let mut bound = fixture.empty();
    let signal = InspectSignal {
        life: Arc::new(Mutex::new(None)),
        cell: Arc::new(Mutex::new(None)),
        socket: Arc::new(Mutex::new(None)),
        seen: Arc::new(AtomicUsize::new(0)),
    };
    let control = Control::new(end(), signal.clone());
    *signal.life.lock().unwrap() = Some(Arc::downgrade(&control.life));
    control
        .advance(Phase::Fresh, Phase::Binding, end())
        .unwrap();
    bound.prepare(&control, end(), &mut |_, _| {}).unwrap();
    control
        .advance(Phase::Binding, Phase::Bound, end())
        .unwrap();
    let cell = bound.listener.as_ref().unwrap().clone();
    let weak = {
        let lease = cell.lease().unwrap();
        Arc::downgrade(&lease)
    };
    *signal.socket.lock().unwrap() = Some(weak.clone());
    *signal.cell.lock().unwrap() = Some(cell.clone());
    control.stop();
    assert_eq!(signal.seen.load(Ordering::SeqCst), 1);
    assert!(weak.upgrade().is_none());
    assert!(cell.0.try_lock().is_ok());
}
