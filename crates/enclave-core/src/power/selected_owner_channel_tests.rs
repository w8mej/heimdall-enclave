//! Private software fixtures for the production framing/session machinery and
//! real UsbSelection transitions. No fixture creates native authentication.
use super::super::{SelectedUsbInstance, UsbObservationEpoch, UsbSelection};
use super::*;
use std::{
    io::Write,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
};

fn end() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn hint() -> AttachmentHint {
    serde_json::from_str(r#"{"version":1,"service_registry_id":10}"#).unwrap()
}
fn binding() -> Binding {
    Binding {
        target_id: "fixture-target".into(),
        descriptor_sha256: "ab".repeat(32),
        profile: Profile::L2,
        signing: DeploymentSigningMode::LocalPins,
    }
}
// Private software wire metadata only. Native entry points require an opaque
// Arc<SelectedOwnerSession>; these values cannot construct that capability.
fn policy() -> PolicySession {
    static POLICY: std::sync::OnceLock<PolicySession> = std::sync::OnceLock::new();
    *POLICY.get_or_init(|| PolicySession {
        record_sha256: [0x31; 32],
        policy_session_id: [0x41; 32],
        expires_boot_ns: boot_now().unwrap().checked_add(3_600_000_000_000).unwrap(),
    })
}

#[test]
fn selected_owner_channel_actor_compare_rechecks_same_stream_owner_peer_without_wire_or_timeout_changes(
) {
    use std::os::fd::AsRawFd;
    let mut connected = Connected::new();
    let peer = verified_peer();
    let stream = connected.root.connection.0.as_raw_fd();
    let read_timeout = connected.root.connection.0.read_timeout().unwrap();
    let write_timeout = connected.root.connection.0.write_timeout().unwrap();
    let sequence = connected.root.book.as_ref().unwrap().next;
    let events = std::cell::RefCell::new(Vec::new());
    connected
        .root
        .compare_peer_with(
            end(),
            |actual, until| {
                assert_eq!(actual.as_raw_fd(), stream);
                same_peer(&peer, &peer)?;
                events.borrow_mut().push("peer");
                within(until)
            },
            |owner, hint, until| {
                events.borrow_mut().push("owner");
                owner.require(hint, until)
            },
            || {
                events.borrow_mut().push("compare");
                same_peer(&peer, &peer)
            },
        )
        .unwrap();
    assert_eq!(
        *events.borrow(),
        vec!["peer", "owner", "compare", "owner", "peer"]
    );
    assert_eq!(connected.root.book.as_ref().unwrap().next, sequence);
    assert_eq!(
        connected.root.connection.0.read_timeout().unwrap(),
        read_timeout
    );
    assert_eq!(
        connected.root.connection.0.write_timeout().unwrap(),
        write_timeout
    );
    assert!(connected.store.live());
    assert_eq!(connected.store.drops.load(Ordering::SeqCst), 0);
    // A subsequent original framed probe still has exactly the old sequence.
    let probe = connected.probe();
    send(&mut connected.client, &probe);
    step(&mut connected.root).unwrap();
    assert_eq!(receive(&mut connected.client).sequence, 1);
}

#[test]
fn selected_owner_channel_actor_compare_refuses_every_changed_audit_word_and_reauthenticated_code()
{
    let peer = verified_peer();
    for field in 0..10 {
        let mut connected = Connected::new();
        let mut changed = peer.clone();
        if field < 8 {
            changed.audit_token.as_mut().unwrap()[field] ^= 1;
        } else if field == 8 {
            changed.code_identity.as_mut().unwrap().cdhash = "ef".repeat(20);
        } else {
            changed.uid = 0;
        }
        let result = connected.root.compare_peer_with(
            end(),
            |_, until| within(until),
            |owner, hint, until| owner.require(hint, until),
            || same_peer(&peer, &changed),
        );
        assert!(result.is_err());
        // The mailbox's atomic negative guard owns refusal. This observation
        // does not release/cancel native ownership from inside the comparison.
        assert!(connected.root.owner.is_some());
        assert!(connected.store.live());
        assert_eq!(connected.store.drops.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn selected_owner_channel_actor_compare_pre_and_post_failures_leave_cleanup_to_atomic_outer_guard()
{
    for refused in 1..=5 {
        let mut connected = Connected::new();
        let point = std::cell::Cell::new(0);
        let check = || {
            point.set(point.get() + 1);
            if point.get() == refused {
                Err(err!(EACCES, "FIXTURE_ACTOR_REFUSED"))
            } else {
                Ok(())
            }
        };
        assert!(connected
            .root
            .compare_peer_with(
                end(),
                |_, _| check(),
                |owner, hint, until| {
                    check()?;
                    owner.require(hint, until)
                },
                || check()
            )
            .is_err());
        assert_eq!(point.get(), refused);
        assert!(connected.root.owner.is_some());
        assert_eq!(connected.store.drops.load(Ordering::SeqCst), 0);
        let store = connected.store.clone();
        drop(connected);
        assert_eq!(store.drops.load(Ordering::SeqCst), 1);
        assert_eq!(store.releases(), 1);
    }
}

#[test]
fn selected_owner_channel_actor_compare_unwind_and_expired_original_do_not_touch_or_replace_owner()
{
    let mut connected = Connected::new();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = connected.root.compare_peer_with(
            end(),
            |_, until| within(until),
            |owner, hint, until| owner.require(hint, until),
            || panic!("actor compare unwind"),
        );
    }))
    .is_err());
    assert!(connected.root.owner.is_some());
    assert!(connected.store.live());
    let calls = std::cell::Cell::new(0);
    connected.root.end = Instant::now();
    assert!(connected
        .root
        .compare_peer_with(
            end(),
            |_, _| {
                calls.set(calls.get() + 1);
                Ok(())
            },
            |_, _, _| {
                calls.set(calls.get() + 1);
                Ok(())
            },
            || {
                calls.set(calls.get() + 1);
                Ok(())
            }
        )
        .is_err());
    assert_eq!(calls.get(), 0);
    assert_eq!(connected.store.drops.load(Ordering::SeqCst), 0);
}
fn request() -> Request {
    Request {
        version: 2,
        kind: Kind::Bind,
        binding: binding(),
        hint: hint(),
        client: [1; 32],
        session: [0; 32],
        sequence: 0,
        challenge: [2; 32],
        expires_boot_ns: policy().expires_boot_ns,
        record_sha256: policy().record_sha256,
        policy_session_id: policy().policy_session_id,
    }
}
fn send(stream: &mut UnixStream, value: &impl Serialize) {
    ipc::write_frame_timed(
        stream,
        &ipc::to_cbor(value).unwrap(),
        &limits(end()).unwrap(),
    )
    .unwrap();
}
fn receive(stream: &mut UnixStream) -> Response {
    decode(&ipc::read_frame_timed(stream, &limits(end()).unwrap()).unwrap()).unwrap()
}

#[derive(Clone)]
struct Store {
    state: Arc<Mutex<UsbSelection>>,
    releases: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}
impl Store {
    fn new() -> Self {
        let mut state = UsbSelection::default();
        state.monitor_started().unwrap();
        Self {
            state: Arc::new(Mutex::new(state)),
            releases: Arc::new(AtomicUsize::new(0)),
            drops: Arc::new(AtomicUsize::new(0)),
        }
    }
    fn bind(&self, observed: AttachmentHint, until: Instant) -> EnclaveResult<Original> {
        within(until)?;
        if observed != hint() {
            fail!(ESTALE, "FIXTURE_ATTACHMENT_CHANGED");
        }
        let mut state = self.state.lock().unwrap();
        let monitor = state.monitor_generation;
        let instance = SelectedUsbInstance::new_observed(
            10,
            vec![20, 1],
            UsbObservationEpoch(state.event_epoch),
        )?;
        let generation = state.bind(instance)?;
        Ok(Original {
            store: self.clone(),
            generation,
            monitor,
        })
    }
    fn live(&self) -> bool {
        self.state.lock().unwrap().selected.is_some()
    }
    fn releases(&self) -> usize {
        self.releases.load(Ordering::SeqCst)
    }
}
struct Original {
    store: Store,
    generation: u64,
    monitor: u64,
}
impl Original {
    fn require(&mut self, observed: AttachmentHint, until: Instant) -> EnclaveResult<()> {
        within(until)?;
        if observed != hint() {
            fail!(ESTALE, "FIXTURE_ATTACHMENT_CHANGED");
        }
        let state = self.store.state.lock().unwrap();
        if !state.monitor_active || state.monitor_generation != self.monitor {
            fail!(EIO, "FIXTURE_MONITOR_LOST");
        }
        state.require(Some(self.generation), 1)
    }
}
impl Drop for Original {
    fn drop(&mut self) {
        let released = self.store.state.lock().unwrap().release(self.generation);
        if released {
            assert!(
                self.store.state.try_lock().is_ok(),
                "wipe callback must run outside topology mutex"
            );
            self.store.releases.fetch_add(1, Ordering::SeqCst);
        }
        self.store.drops.fetch_add(1, Ordering::SeqCst);
    }
}
fn accept(server: UnixStream, store: &Store) -> EnclaveResult<RootSession<Original>> {
    RootSession::accept_with(
        server,
        &binding(),
        end(),
        end(),
        |_, until| within(until),
        |observed, until| store.bind(observed, until),
        |owner, observed, until| owner.require(observed, until),
        policy(),
    )
}
fn step(root: &mut RootSession<Original>) -> EnclaveResult<()> {
    root.step_with(
        end(),
        |_, until| within(until),
        |owner, observed, until| owner.require(observed, until),
    )
}
struct Connected {
    client: UnixStream,
    root: RootSession<Original>,
    store: Store,
    original: Request,
    response: Response,
}
impl Connected {
    fn new() -> Self {
        let (mut client, server) = UnixStream::pair().unwrap();
        let store = Store::new();
        let original = request();
        send(&mut client, &original);
        let root = accept(server, &store).unwrap();
        let response = receive(&mut client);
        Self {
            client,
            root,
            store,
            original,
            response,
        }
    }
    fn probe(&self) -> Request {
        Request {
            kind: Kind::Probe,
            session: self.response.session,
            sequence: 1,
            challenge: [3; 32],
            ..self.original.clone()
        }
    }
}

#[test]
fn selected_owner_channel_real_framing_retains_same_original_across_bind_probe_and_drop() {
    let mut connected = Connected::new();
    assert!(connected.store.live());
    assert_eq!(connected.store.releases(), 0);
    assert_eq!(connected.response.client, connected.original.client);
    assert_ne!(connected.response.session, [0; 32]);
    let original_end = connected.root.end;
    let probe = connected.probe();
    send(&mut connected.client, &probe);
    step(&mut connected.root).unwrap();
    let response = receive(&mut connected.client);
    assert_eq!(response.session, connected.response.session);
    assert_eq!(response.expires_boot_ns, connected.original.expires_boot_ns);
    assert_eq!(response.sequence, 1);
    assert_eq!(response.challenge, probe.challenge);
    assert_eq!(connected.root.end, original_end);
    assert!(connected.store.live());
    assert_eq!(connected.store.releases(), 0);
    drop(connected.root);
    assert!(!connected.store.live());
    assert_eq!(connected.store.releases(), 1);
}

#[test]
fn selected_owner_channel_client_and_root_share_production_bind_and_probe_without_reconnect() {
    let (client, server) = UnixStream::pair().unwrap();
    let store = Store::new();
    let root_store = store.clone();
    let worker = thread::spawn(move || {
        let mut root = accept(server, &root_store).unwrap();
        step(&mut root).unwrap();
    });
    let original_end = end();
    let mut client = ClientWire::open(
        client,
        binding(),
        hint(),
        original_end,
        end(),
        |_, until| within(until),
        policy(),
    )
    .unwrap();
    let session = client.session;
    let expires = client.policy.expires_boot_ns;
    client
        .exchange(Kind::Probe, end(), |_, until| within(until))
        .unwrap();
    assert_eq!(client.session, session);
    assert_eq!(client.policy.expires_boot_ns, expires);
    assert_eq!(
        expires,
        policy().expires_boot_ns,
        "shorter local Instant must not rewrite raw policy identity"
    );
    assert_eq!(client.end, original_end);
    assert_eq!(client.next, 2);
    worker.join().unwrap();
    assert_eq!(store.releases(), 1);
}

#[test]
fn selected_owner_channel_bind_refuses_wrong_version_role_context_sequence_nonce_or_expiry_before_owner(
) {
    for mode in 0..9 {
        let (mut client, server) = UnixStream::pair().unwrap();
        let store = Store::new();
        let mut value = request();
        match mode {
            0 => value.version = 1,
            1 => value.kind = Kind::Probe,
            2 => value.binding.target_id = "foreign-target".into(),
            3 => value.sequence = 1,
            4 => value.client = [0; 32],
            5 => value.session = [4; 32],
            6 => value.challenge = [0; 32],
            7 => value.expires_boot_ns = 0,
            _ => value.expires_boot_ns = u64::MAX,
        }
        send(&mut client, &value);
        assert!(accept(server, &store).is_err());
        assert!(!store.live());
        assert_eq!(store.drops.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn selected_owner_channel_probe_rejects_splice_replay_rebind_and_lifetime_change_then_never_revives(
) {
    for mode in 0..10 {
        let mut connected = Connected::new();
        let mut value = connected.probe();
        match mode {
            0 => value.client = [5; 32],
            1 => value.session = [5; 32],
            2 => value.sequence = 0,
            3 => value.sequence = 2,
            4 => value.kind = Kind::Bind,
            5 => value.binding.descriptor_sha256 = "ff".repeat(32),
            6 => {
                value.hint =
                    serde_json::from_str(r#"{"version":1,"service_registry_id":11}"#).unwrap()
            }
            7 => value.challenge = [0; 32],
            8 => value.expires_boot_ns += 1,
            _ => value.version = 1,
        }
        send(&mut connected.client, &value);
        assert!(step(&mut connected.root).is_err());
        assert!(!connected.store.live());
        assert_eq!(connected.store.releases(), 1);
        assert!(step(&mut connected.root)
            .unwrap_err()
            .is("SELECTED_OWNER_POISONED"));
        assert_eq!(connected.store.releases(), 1);
    }
}

#[test]
fn selected_owner_channel_eof_stop_and_original_deadline_revoke_once() {
    for mode in 0..3 {
        let mut connected = Connected::new();
        match mode {
            0 => {
                connected.client.shutdown(Shutdown::Both).unwrap();
                assert!(step(&mut connected.root).is_err());
            }
            1 => connected.root.stop(),
            _ => {
                connected.root.end = Instant::now();
                assert!(step(&mut connected.root).is_err());
            }
        }
        assert!(connected.root.poisoned);
        assert!(connected.root.owner.is_none());
        assert!(!connected.store.live());
        assert_eq!(connected.store.releases(), 1);
        connected.root.stop();
        drop(connected.root);
        assert_eq!(connected.store.releases(), 1);
    }
}

#[test]
fn selected_owner_channel_partial_frame_timeout_does_not_postpone_or_keep_original_guard() {
    let mut connected = Connected::new();
    connected.client.set_nonblocking(false).unwrap();
    connected.client.write_all(&[0]).unwrap();
    let result = connected.root.step_with(
        Instant::now() + Duration::from_millis(20),
        |_, until| within(until),
        |owner, observed, until| owner.require(observed, until),
    );
    assert!(result.is_err());
    assert!(connected.root.poisoned);
    assert!(!connected.store.live());
    assert_eq!(connected.store.releases(), 1);
}

#[test]
fn selected_owner_channel_failed_reply_releases_actual_guard_without_cleanup_message() {
    let mut connected = Connected::new();
    let probe = connected.probe();
    send(&mut connected.client, &probe);
    // Stop this exact writer at the final observation. Peer read shutdown can
    // still admit a buffered write on Darwin, so it is not a portable way to
    // force the production reply-write failure under test.
    let closed = connected.root.connection.0.try_clone().unwrap();
    let mut calls = 0;
    let result = connected.root.step_with(
        end(),
        |_, until| within(until),
        |owner, observed, until| {
            calls += 1;
            owner.require(observed, until)?;
            if calls == 2 {
                closed.shutdown(Shutdown::Write).unwrap();
            }
            Ok(())
        },
    );
    assert!(result.is_err());
    assert_eq!(calls, 2);
    assert!(!connected.store.live());
    assert_eq!(connected.store.releases(), 1);
}

#[test]
fn selected_owner_channel_post_observation_failure_and_caught_unwind_poison_retained_session() {
    for unwind in [false, true] {
        let mut connected = Connected::new();
        let probe = connected.probe();
        send(&mut connected.client, &probe);
        let mut calls = 0;
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            connected.root.step_with(
                end(),
                |_, until| {
                    calls += 1;
                    within(until)?;
                    if calls == 2 {
                        if unwind {
                            panic!("private fixture verifier unwind");
                        }
                        fail!(EACCES, "FIXTURE_PEER_CHANGED");
                    }
                    Ok(())
                },
                |owner, observed, until| owner.require(observed, until),
            )
        }));
        if unwind {
            assert!(caught.is_err());
        } else {
            assert!(caught.unwrap().is_err());
        }
        assert!(connected.root.poisoned);
        assert!(connected.root.owner.is_none());
        assert!(!connected.store.live());
        assert_eq!(connected.store.releases(), 1);
        assert!(step(&mut connected.root).is_err());
    }
}

#[test]
fn selected_owner_channel_failed_initial_observation_never_leaves_bound_guard() {
    for mode in 0..3 {
        let (mut client, server) = UnixStream::pair().unwrap();
        let store = Store::new();
        send(&mut client, &request());
        let mut calls = 0;
        let result = RootSession::accept_with(
            server,
            &binding(),
            end(),
            end(),
            |_, until| within(until),
            |observed, until| {
                let owner = store.bind(observed, until)?;
                if mode == 0 {
                    drop(owner);
                    fail!(EIO, "FIXTURE_CONSTRUCTOR_FAILED_AFTER_OWNERSHIP");
                }
                Ok(owner)
            },
            |owner: &mut Original, observed, until| {
                calls += 1;
                if (mode == 1 && calls == 1) || (mode == 2 && calls == 2) {
                    fail!(EIO, "FIXTURE_MONITOR_LOST");
                }
                owner.require(observed, until)
            },
            policy(),
        );
        assert!(result.is_err());
        assert!(!store.live());
        assert_eq!(store.releases(), 1);
    }
}

#[test]
fn selected_owner_channel_obsolete_root_drop_cannot_revoke_rebound_generation_or_monitor() {
    for replace_monitor in [false, true] {
        let mut connected = Connected::new();
        {
            let mut state = connected.store.state.lock().unwrap();
            if replace_monitor {
                let monitor = state.monitor_generation;
                assert!(state.monitor_lost(monitor));
                state.monitor_started().unwrap();
            } else {
                let generation = state.selected.as_ref().unwrap().0;
                assert!(state.release(generation));
            }
        }
        let replacement = connected.store.bind(hint(), end()).unwrap();
        assert!(step(&mut connected.root).is_err());
        assert!(connected.store.live());
        assert_eq!(connected.store.releases(), 0);
        drop(connected.root);
        assert!(connected.store.live());
        assert_eq!(connected.store.releases(), 0);
        drop(replacement);
        assert!(!connected.store.live());
        assert_eq!(connected.store.releases(), 1);
    }
}

#[test]
fn selected_owner_channel_strict_schema_refuses_duplicate_unknown_tag_and_trailing_data() {
    let encoded = ipc::to_cbor(&request()).unwrap();
    let original: ciborium::value::Value = ciborium::from_reader(encoded.as_slice()).unwrap();
    for mode in 0..4 {
        let mut value = original.clone();
        if let ciborium::value::Value::Map(ref mut entries) = value {
            match mode {
                0 => entries.push(entries[0].clone()),
                1 => entries.push((
                    ciborium::value::Value::Text("foreign_generation".into()),
                    ciborium::value::Value::Integer(7.into()),
                )),
                2 => entries[0].1 = ciborium::value::Value::Tag(1, Box::new(entries[0].1.clone())),
                _ => (),
            }
        }
        let mut bytes = ipc::to_cbor(&value).unwrap();
        if mode == 3 {
            bytes.push(0);
        }
        assert!(decode::<Request>(&bytes).is_err());
    }
}

fn verified_peer() -> PeerCredentials {
    let mut peer = PeerCredentials::local(703, 8703);
    peer.audit_token = Some([7; 8]);
    peer.code_identity = Some(codesign::CodeIdentity {
        identifier: "fixture-custody".into(),
        team_id: "fixture-team".into(),
        cdhash: "ab".repeat(20),
    });
    peer
}
#[test]
fn selected_owner_channel_peer_comparison_requires_original_full_audit_code_and_uid() {
    let original = verified_peer();
    same_peer(&original, &original).unwrap();
    for mode in 0..6 {
        let mut current = original.clone();
        match mode {
            0 => current.uid = 0,
            1 => current.gid += 1,
            2 => current.audit_token = Some([8; 8]),
            3 => current.audit_token = None,
            4 => current.code_identity = None,
            _ => current.code_identity.as_mut().unwrap().cdhash = "cd".repeat(20),
        }
        assert!(same_peer(&original, &current).is_err());
    }
}

#[test]
fn selected_owner_channel_sequence_exhaustion_fails_without_wrapping() {
    let mut connected = Connected::new();
    connected.root.book.as_mut().unwrap().next = u64::MAX;
    let mut probe = connected.probe();
    probe.sequence = u64::MAX;
    send(&mut connected.client, &probe);
    assert!(step(&mut connected.root).is_err());
    assert!(!connected.store.live());
    assert_eq!(connected.store.releases(), 1);
}

#[test]
fn selected_owner_channel_client_wrong_reply_and_caught_unwind_permanently_close_same_stream() {
    for unwind in [false, true] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            let bytes = ipc::read_frame_timed(&mut server, &limits(end()).unwrap()).unwrap();
            let request: Request = decode(&bytes).unwrap();
            let now = boot_now().unwrap();
            let mut book = Book::bind(&request, &binding(), policy()).unwrap();
            if !unwind {
                book.client = [9; 32];
            }
            send(&mut server, &book.response(&request, now).unwrap());
            if unwind {
                // Client's caught unwind must shutdown the retained connection.
                assert!(ipc::read_frame_timed(&mut server, &limits(end()).unwrap()).is_err());
            }
        });
        let mut calls = 0;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ClientWire::open(
                client,
                binding(),
                hint(),
                end(),
                end(),
                |_, until| {
                    calls += 1;
                    if unwind && calls == 3 {
                        panic!("private fixture client unwind");
                    }
                    within(until)
                },
                policy(),
            )
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        worker.join().unwrap();
    }
}

#[test]
fn selected_owner_channel_caught_client_probe_unwind_poison_retained_client_and_root_guard() {
    let (client, server) = UnixStream::pair().unwrap();
    let store = Store::new();
    let root_store = store.clone();
    let worker = thread::spawn(move || {
        let mut root = accept(server, &root_store).unwrap();
        assert!(step(&mut root).is_err());
    });
    let mut client = ClientWire::open(
        client,
        binding(),
        hint(),
        end(),
        end(),
        |_, until| within(until),
        policy(),
    )
    .unwrap();
    let original_session = client.session;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.exchange(Kind::Probe, end(), |_, _| {
            panic!("retained client verifier unwind")
        })
    }));
    assert!(result.is_err());
    assert!(client.poisoned);
    assert_eq!(client.session, original_session);
    assert!(client
        .exchange(Kind::Probe, end(), |_, _| panic!(
            "poisoned client must not call verifier"
        ))
        .is_err());
    worker.join().unwrap();
    assert_eq!(store.releases(), 1);
}

#[test]
fn selected_owner_channel_client_refuses_bad_reply_schema_bindings_clocks_and_lifetime() {
    for mode in 0..11 {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            let bytes = ipc::read_frame_timed(&mut server, &limits(end()).unwrap()).unwrap();
            let request: Request = decode(&bytes).unwrap();
            let book = Book::bind(&request, &binding(), policy()).unwrap();
            let mut response = book.response(&request, boot_now().unwrap()).unwrap();
            match mode {
                0 => response.version = 1,
                1 => response.binding.target_id = "foreign-target".into(),
                2 => {
                    response.hint =
                        serde_json::from_str(r#"{"version":1,"service_registry_id":11}"#).unwrap()
                }
                3 => response.client = [8; 32],
                4 => response.session = [0; 32],
                5 => response.sequence += 1,
                6 => response.challenge = [0; 32],
                7 => response.expires_boot_ns += 1,
                8 => response.started_boot_ns = u64::MAX,
                9 => response.ended_boot_ns = 0,
                _ => response.ended_boot_ns = u64::MAX,
            }
            send(&mut server, &response);
        });
        assert!(ClientWire::open(
            client,
            binding(),
            hint(),
            end(),
            end(),
            |_, until| within(until),
            policy()
        )
        .is_err());
        worker.join().unwrap();
    }
}

#[cfg(not(target_os = "macos"))]
#[test]
fn selected_owner_channel_native_constructor_never_uses_linux_uid_only_authentication() {
    // The constructor's opaque mandatory input has no successful Linux
    // production factory. Pin its signature without minting a fake session.
    let _constructor: fn(
        &super::super::darwin::PowerMonitor,
        Instant,
        Instant,
        Arc<SelectedOwnerSession>,
    ) -> EnclaveResult<CustodySelectedOwnerChannel> = CustodySelectedOwnerChannel::connect_custody;
    assert!(SelectedOwnerSession::capture()
        .unwrap_err()
        .is("SELECTED_SESSION_NATIVE_REQUIRED"));
    assert!(process(DaemonId::CustodyVault.uid())
        .unwrap_err()
        .is("SELECTED_OWNER_NATIVE_REQUIRED"));
}

#[test]
fn selected_owner_v2_bind_requires_independent_exact_record_policy_and_raw_end_before_owner() {
    for mode in 0..7 {
        let (mut client, server) = UnixStream::pair().unwrap();
        let store = Store::new();
        let mut bind = request();
        match mode {
            0 => bind.record_sha256[0] ^= 1,
            1 => bind.policy_session_id[0] ^= 1,
            2 => bind.policy_session_id = [0; 32],
            3 => bind.expires_boot_ns -= 1, // Earlier peer end is not exact policy admission.
            4 => bind.expires_boot_ns += 1,
            5 => bind.version = 1,
            _ => bind.binding.descriptor_sha256 = "cd".repeat(32),
        }
        send(&mut client, &bind);
        assert!(accept(server, &store).is_err(), "mode {mode}");
        assert!(!store.live());
        assert_eq!(store.drops.load(Ordering::SeqCst), 0);
    }
    // An invalid locally supplied private fixture cannot derive admission from
    // a valid peer. Native callers derive this tuple only from opaque session.
    for mode in 0..3 {
        let (mut client, server) = UnixStream::pair().unwrap();
        let store = Store::new();
        send(&mut client, &request());
        let mut local = policy();
        match mode {
            0 => local.policy_session_id = [0; 32],
            1 => local.expires_boot_ns = 0,
            _ => local.expires_boot_ns = boot_now().unwrap().saturating_sub(1),
        }
        assert!(RootSession::accept_with(
            server,
            &binding(),
            end(),
            end(),
            |_, until| within(until),
            |observed, until| store.bind(observed, until),
            |owner, observed, until| owner.require(observed, until),
            local
        )
        .is_err());
        assert_eq!(store.drops.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn selected_owner_v2_probe_tuple_changes_cannot_replace_original_or_replay_after_failure() {
    for mode in 0..4 {
        let mut connected = Connected::new();
        let mut probe = connected.probe();
        match mode {
            0 => probe.record_sha256[0] ^= 1,
            1 => probe.policy_session_id[0] ^= 1,
            2 => probe.expires_boot_ns -= 1,
            _ => probe.expires_boot_ns += 1,
        }
        send(&mut connected.client, &probe);
        assert!(step(&mut connected.root).is_err());
        assert_eq!(connected.store.releases(), 1);
        assert!(!connected.store.live());
        assert!(connected.root.owner.is_none());
        assert!(step(&mut connected.root)
            .unwrap_err()
            .is("SELECTED_OWNER_POISONED"));
    }
}

#[test]
fn selected_owner_v2_client_rejects_cross_record_policy_and_raw_end_responses() {
    for mode in 0..4 {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            let request: Request =
                decode(&ipc::read_frame_timed(&mut server, &limits(end()).unwrap()).unwrap())
                    .unwrap();
            let book = Book::bind(&request, &binding(), policy()).unwrap();
            let mut response = book.response(&request, boot_now().unwrap()).unwrap();
            match mode {
                0 => response.record_sha256[0] ^= 1,
                1 => response.policy_session_id[0] ^= 1,
                2 => response.policy_session_id = [0; 32],
                _ => response.expires_boot_ns -= 1,
            }
            send(&mut server, &response);
            assert!(ipc::read_frame_timed(&mut server, &limits(end()).unwrap()).is_err());
        });
        assert!(ClientWire::open(
            client,
            binding(),
            hint(),
            end(),
            end(),
            |_, until| within(until),
            policy()
        )
        .is_err());
        worker.join().unwrap();
    }
}

#[test]
fn selected_owner_v2_closed_schema_has_no_v1_or_missing_policy_compatibility() {
    assert_eq!(SOCKET_LEAF, "selected-owner-v2.sock");
    let bind = request();
    let book = Book::bind(&bind, &binding(), policy()).unwrap();
    let response = book.response(&bind, boot_now().unwrap()).unwrap();
    for response_side in [false, true] {
        let encoded = if response_side {
            ipc::to_cbor(&response).unwrap()
        } else {
            ipc::to_cbor(&bind).unwrap()
        };
        let original: ciborium::value::Value = ciborium::from_reader(encoded.as_slice()).unwrap();
        for field in ["record_sha256", "policy_session_id", "expires_boot_ns"] {
            let mut value = original.clone();
            let ciborium::value::Value::Map(ref mut entries) = value else { panic!("map required") };
            entries.retain(|(key, _)| key != &ciborium::value::Value::Text(field.into()));
            let raw = ipc::to_cbor(&value).unwrap();
            if response_side {
                assert!(decode::<Response>(&raw).is_err());
            } else {
                assert!(decode::<Request>(&raw).is_err());
            }
        }
    }
}

#[test]
fn selected_owner_v2_connection_nonce_challenge_and_sequence_stop_replay_inside_same_policy() {
    let mut connected = Connected::new();
    let old_reply = ipc::to_cbor(&connected.response).unwrap();
    let probe = connected.probe();
    send(&mut connected.client, &probe);
    step(&mut connected.root).unwrap();
    let response = receive(&mut connected.client);
    assert_eq!(
        response.policy_session_id,
        connected.response.policy_session_id
    );
    assert_eq!(response.record_sha256, connected.response.record_sha256);
    assert_ne!(ipc::to_cbor(&response).unwrap(), old_reply);
    send(&mut connected.client, &probe); // Already consumed sequence/challenge.
    assert!(step(&mut connected.root).is_err());
    assert_eq!(connected.store.releases(), 1);
}

#[test]
fn selected_owner_v2_expired_original_raw_end_refuses_even_with_live_instant_cap() {
    let mut connected = Connected::new();
    connected.root.book.as_mut().unwrap().policy.expires_boot_ns =
        boot_now().unwrap().saturating_sub(1);
    assert!(Instant::now() < connected.root.end);
    assert!(step(&mut connected.root).is_err());
    assert_eq!(connected.store.releases(), 1);
    // Only private fault injection changes the tuple here. Native owners never
    // replace an admitted endpoint, and a later restoration cannot revive it.
    connected.root.book.as_mut().unwrap().policy = policy();
    assert!(step(&mut connected.root).is_err());
    assert_eq!(connected.store.releases(), 1);
}

#[test]
fn selected_owner_v2_retained_source_verifier_failure_after_bind_read_prevents_owner_creation() {
    // Actual retained-record replacement/protection/bytes coverage lives in
    // selected_owner_session's real filesystem suite. This composes its
    // negative require_current result with the real channel read boundary.
    let (mut client, server) = UnixStream::pair().unwrap();
    let store = Store::new();
    let (entered, observed) = std::sync::mpsc::channel();
    let (resume, resumed) = std::sync::mpsc::channel();
    let rejected = Arc::new(AtomicBool::new(false));
    let actual = rejected.clone();
    let worker_store = store.clone();
    let worker = thread::spawn(move || {
        let mut checks = 0;
        RootSession::accept_with(
            server,
            &binding(),
            end(),
            end(),
            |_, until| {
                checks += 1;
                within(until)?;
                if checks == 1 {
                    entered.send(()).unwrap();
                    resumed.recv_timeout(Duration::from_secs(2)).unwrap();
                }
                if checks > 1 && actual.load(Ordering::SeqCst) {
                    fail!(ESTALE, "FIXTURE_ORIGINAL_POLICY_SOURCE_CHANGED");
                }
                Ok(())
            },
            |observed, until| worker_store.bind(observed, until),
            |owner, observed, until| owner.require(observed, until),
            policy(),
        )
        .is_err()
    });
    observed.recv_timeout(Duration::from_secs(2)).unwrap();
    rejected.store(true, Ordering::SeqCst);
    send(&mut client, &request());
    resume.send(()).unwrap();
    assert!(worker.join().unwrap());
    assert_eq!(store.drops.load(Ordering::SeqCst), 0);
    assert!(!store.live());
}

#[test]
fn selected_owner_v2_retained_policy_failure_during_probe_closes_original_once() {
    let mut connected = Connected::new();
    let probe = connected.probe();
    send(&mut connected.client, &probe);
    let mut checks = 0;
    let result = connected.root.step_with(
        end(),
        |_, until| {
            checks += 1;
            within(until)?;
            if checks == 2 {
                fail!(ESTALE, "FIXTURE_ORIGINAL_POLICY_SOURCE_CHANGED");
            }
            Ok(())
        },
        |owner, observed, until| owner.require(observed, until),
    );
    assert!(result.is_err());
    assert_eq!(connected.store.releases(), 1);
    assert!(step(&mut connected.root).is_err());
    assert_eq!(connected.store.releases(), 1);
}

#[test]
fn selected_owner_v2_pending_control_retains_local_raw_end_and_refuses_rebinding() {
    let stop = CustodySelectedOwnerStop::new(end());
    let raw = policy().expires_boot_ns;
    stop.control.bind_boot(raw).unwrap();
    stop.control.require_boot(raw).unwrap();
    assert!(stop.control.require_boot(raw - 1).is_err());
    assert_eq!(stop.control.state.lock().unwrap().boot_limit, Some(raw));
    assert!(stop.control.bind_boot(raw + 1).is_err());
    assert!(stop.require_not_stopped().is_err());
    let not_bound = CustodySelectedOwnerStop::new(end());
    assert!(not_bound.control.require_boot(raw).is_err());
    assert!(not_bound.control.bind_boot(raw).is_err());
}

// Private cancellation fixture uses actual UsbSelection generations. It never
// supplies native authentication or a public replacement selection provider.
#[derive(Clone)]
struct FixtureCancellation {
    store: Store,
    state: Arc<Mutex<(bool, Option<u64>)>>,
}
impl FixtureCancellation {
    fn new(store: Store) -> Self {
        Self {
            store,
            state: Arc::new(Mutex::new((false, None))),
        }
    }
    fn bind(&self) -> EnclaveResult<Original> {
        let mut state = self.state.lock().unwrap();
        if state.0 || state.1.is_some() {
            fail!(EACCES, "FIXTURE_CANCELLED");
        }
        let owner = self.store.bind(hint(), end())?;
        state.1 = Some(owner.generation);
        Ok(owner)
    }
}
impl CancelOriginal for FixtureCancellation {
    fn cancel_original(&self) {
        let generation = {
            let mut state = self.state.lock().unwrap();
            state.0 = true;
            state.1.take()
        };
        if let Some(generation) = generation {
            let released = self.store.state.lock().unwrap().release(generation);
            if released {
                assert!(self.store.state.try_lock().is_ok());
                assert!(self.state.try_lock().is_ok());
                self.store.releases.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}
fn watch_fixture() -> (WatchControl<FixtureCancellation>, Store) {
    let store = Store::new();
    (
        WatchControl::new(end(), FixtureCancellation::new(store.clone())),
        store,
    )
}

#[test]
fn selected_owner_watch_late_completion_and_expired_begin_never_renew_active_deadline() {
    for late_finish in [false, true] {
        let (control, store) = watch_fixture();
        let now = Instant::now();
        let boot = boot_now().unwrap();
        let phase = control
            .begin_at(now + Duration::from_millis(20), now, boot)
            .unwrap();
        let owner = control.cancellation.bind().unwrap();
        assert!(store.live());
        if late_finish {
            assert!(control.finish_at(phase, phase.end, boot).is_err());
        } else {
            assert!(control.begin_at(end(), phase.end, boot).is_err());
        }
        assert!(!store.live());
        assert_eq!(store.releases(), 1);
        assert!(control.finish_at(phase, now, boot).is_err());
        assert!(control.begin_at(end(), now, boot).is_err());
        drop(owner);
        assert_eq!(store.releases(), 1);
    }
}

#[test]
fn selected_owner_watch_original_lifetime_and_peer_boot_expiry_are_independent_sticky_caps() {
    for boot_expiry in [false, true] {
        let (control, store) = watch_fixture();
        let now = Instant::now();
        let boot = boot_now().unwrap();
        let phase = control.begin_at(end(), now, boot).unwrap();
        let owner = control.cancellation.bind().unwrap();
        control.finish_at(phase, now, boot).unwrap();
        let limit = boot_now().unwrap() + 1_000_000_000;
        control.bind_boot(limit).unwrap();
        let result = if boot_expiry {
            control.apply_at(now, limit, |_| Ok(()))
        } else {
            control.apply_at(control.original, boot, |_| Ok(()))
        };
        assert!(result.is_err());
        assert!(!store.live());
        assert!(control.begin_at(end(), now, boot).is_err());
        drop(owner);
        assert_eq!(store.releases(), 1);
    }
}

#[test]
fn selected_owner_watch_finished_exchange_cannot_extend_original_or_complete_newer_phase() {
    let (control, store) = watch_fixture();
    let now = Instant::now();
    let boot = boot_now().unwrap();
    let first = control.begin_at(end(), now, boot).unwrap();
    let owner = control.cancellation.bind().unwrap();
    control.finish_at(first, now, boot).unwrap();
    assert_eq!(control.poll_end().unwrap(), control.original);
    let second = control.begin_at(end(), now, boot).unwrap();
    assert_ne!(first.serial, second.serial);
    assert!(second.end <= control.original);
    assert!(control.finish_at(first, now, boot).is_err());
    assert!(!store.live());
    assert!(control.finish_at(second, now, boot).is_err());
    drop(owner);
    assert_eq!(store.releases(), 1);
}

#[test]
fn selected_owner_watch_cancel_before_bind_and_pre_stopped_socket_remain_terminal() {
    let (control, store) = watch_fixture();
    control.stop();
    assert!(control.cancellation.bind().is_err());
    assert!(!store.live());
    let (server, mut client) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    assert!(control.attach(Arc::new(server)).is_err());
    use std::io::Read;
    assert_eq!(client.read(&mut [0; 1]).unwrap(), 0);
    assert!(control.begin(end()).is_err());
    assert_eq!(store.releases(), 0);
}

#[test]
fn selected_owner_watch_cancellation_while_actor_blocked_revokes_original_without_actor_cleanup() {
    let (control, store) = watch_fixture();
    let phase = control.begin(end()).unwrap();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let actor_control = control.clone();
    let actor = thread::spawn(move || {
        let owner = actor_control.cancellation.bind().unwrap();
        entered_tx.send(()).unwrap();
        resume_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(actor_control.finish(phase).is_err());
        drop(owner);
    });
    entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(store.live());
    control.stop();
    assert!(!store.live());
    assert_eq!(store.releases(), 1);
    resume_tx.send(()).unwrap();
    actor.join().unwrap();
    assert_eq!(store.releases(), 1);
}

#[test]
fn selected_owner_watch_stale_original_cancel_cannot_revoke_replacement_generation() {
    let (control, store) = watch_fixture();
    let owner = control.cancellation.bind().unwrap();
    // An earlier external fence removed the original selection. Keep its
    // obsolete owner alive; replacement cannot bind over a current selection.
    assert!(store.state.lock().unwrap().release(owner.generation));
    let replacement = store.bind(hint(), end()).unwrap();
    control.stop();
    assert!(store.live());
    assert_eq!(store.releases(), 0);
    drop(owner);
    assert!(store.live());
    drop(replacement);
    assert_eq!(store.releases(), 1);
}

#[test]
fn selected_owner_watch_shared_stop_flag_and_metadata_poison_refuse_further_authority() {
    for poison in [false, true] {
        let (control, store) = watch_fixture();
        let owner = control.cancellation.bind().unwrap();
        if poison {
            let state = control.state.clone();
            assert!(thread::spawn(move || {
                let _guard = state.lock().unwrap();
                panic!("metadata poison");
            })
            .join()
            .is_err());
        } else {
            let stopped = Arc::new(AtomicBool::new(false));
            control.observe_stop(stopped.clone()).unwrap();
            stopped.store(true, Ordering::Release);
        }
        assert!(control.check().is_err());
        assert!(!store.live());
        assert!(control.begin(end()).is_err());
        drop(owner);
        assert_eq!(store.releases(), 1);
    }
}

#[test]
fn selected_owner_session_shuts_down_before_blocked_original_owner_drop_finishes() {
    use std::io::Read;
    struct BlockedDrop {
        entered: std::sync::mpsc::Sender<()>,
        resume: std::sync::mpsc::Receiver<()>,
    }
    impl Drop for BlockedDrop {
        fn drop(&mut self) {
            self.entered.send(()).unwrap();
            self.resume.recv_timeout(Duration::from_secs(2)).unwrap();
        }
    }
    let (server, mut client) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let worker = thread::spawn(move || {
        let mut session = RootSession {
            connection: Connection(server, None),
            owner: Some(BlockedDrop {
                entered: entered_tx,
                resume: resume_rx,
            }),
            book: None,
            end: end(),
            poisoned: false,
        };
        session.stop();
    });
    entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(client.read(&mut [0; 1]).unwrap(), 0);
    resume_tx.send(()).unwrap();
    worker.join().unwrap();
}

#[test]
fn selected_owner_watch_shuts_down_before_blocked_generation_cancellation_finishes() {
    use std::io::Read;
    #[derive(Clone)]
    struct BlockingCancel {
        entered: std::sync::mpsc::Sender<()>,
        resume: Arc<Mutex<std::sync::mpsc::Receiver<()>>>,
    }
    impl CancelOriginal for BlockingCancel {
        fn cancel_original(&self) {
            self.entered.send(()).unwrap();
            self.resume
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(2))
                .unwrap();
        }
    }
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let control = WatchControl::new(
        end(),
        BlockingCancel {
            entered: entered_tx,
            resume: Arc::new(Mutex::new(resume_rx)),
        },
    );
    let (server, mut client) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    control.attach(Arc::new(server)).unwrap();
    let stopped = control.clone();
    let worker = thread::spawn(move || stopped.stop());
    entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(client.read(&mut [0; 1]).unwrap(), 0);
    assert!(control.check().is_err());
    resume_tx.send(()).unwrap();
    worker.join().unwrap();
}

#[test]
fn selected_owner_channel_deep_or_oversized_schema_refuses_without_owner_creation() {
    let mut nested = ciborium::value::Value::Null;
    for _ in 0..16 {
        nested = ciborium::value::Value::Array(vec![nested]);
    }
    let map = ciborium::value::Value::Map(vec![(
        ciborium::value::Value::Text("nested".into()),
        nested,
    )]);
    assert!(decode::<Request>(&ipc::to_cbor(&map).unwrap()).is_err());
    assert!(decode::<Request>(&vec![0; FRAME + 1]).is_err());
    // Decoder recursion is independently bounded even before our schema walk.
    let mut excessive = vec![0x81; FRAME - 2];
    excessive.push(0xf6);
    assert!(decode::<Request>(&excessive).is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn selected_owner_native_watch_buffered_eof_cancels_while_actor_does_not_read() {
    let (control, store) = watch_fixture();
    control.begin(end()).unwrap();
    let owner = control.cancellation.bind().unwrap();
    let (server, mut client) = UnixStream::pair().unwrap();
    let watcher = WatchWorker::start(&server, control.clone()).unwrap();
    client.write_all(&[0, 0, 0, 4, 1, 2, 3, 4]).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    // Poll only test metadata: no actor step, channel read or cleanup message.
    let until = Instant::now() + Duration::from_secs(1);
    while store.live() && Instant::now() < until {
        thread::sleep(Duration::from_millis(1));
    }
    assert!(!store.live());
    assert!(control.check().is_err());
    drop(owner);
    drop(watcher);
    assert_eq!(store.releases(), 1);
}

#[cfg(target_os = "macos")]
#[test]
fn selected_owner_native_watch_active_deadline_and_shared_stop_need_no_actor_progress() {
    for stopped in [false, true] {
        let (control, store) = watch_fixture();
        control
            .begin(Instant::now() + Duration::from_millis(100))
            .unwrap();
        let owner = control.cancellation.bind().unwrap();
        let (server, _client) = UnixStream::pair().unwrap();
        let flag = Arc::new(AtomicBool::new(false));
        control.observe_stop(flag.clone()).unwrap();
        let watcher = WatchWorker::start(&server, control.clone()).unwrap();
        if stopped {
            flag.store(true, Ordering::Release);
        }
        let until = Instant::now() + Duration::from_secs(1);
        while store.live() && Instant::now() < until {
            thread::sleep(Duration::from_millis(1));
        }
        assert!(!store.live());
        drop(owner);
        drop(watcher);
        assert_eq!(store.releases(), 1);
    }
}

#[test]
fn selected_owner_watch_real_bind_frame_cannot_late_bind_after_pending_cancellation() {
    let (control, store) = watch_fixture();
    let phase = control.begin(end()).unwrap();
    let (mut client, server) = UnixStream::pair().unwrap();
    send(&mut client, &request());
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let actor_control = control.clone();
    let actor = thread::spawn(move || {
        let verify_control = actor_control.clone();
        let bind_control = actor_control.clone();
        RootSession::accept_inner(
            Connection(server, None),
            &binding(),
            actor_control.original,
            phase.end,
            |_, until| {
                within(until)?;
                verify_control.check()
            },
            |_, _| {
                // Models a synchronous native observation that cannot be
                // interrupted: return only after cancellation has occurred.
                entered_tx.send(()).unwrap();
                resume_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                bind_control.cancellation.bind()
            },
            |owner, observed, until| owner.require(observed, until),
            |limit| actor_control.bind_boot(limit),
            policy(),
        )
        .is_err()
    });
    entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    control.stop();
    resume_tx.send(()).unwrap();
    assert!(actor.join().unwrap());
    assert!(!store.live());
    assert_eq!(store.releases(), 0);
    assert_eq!(store.drops.load(Ordering::SeqCst), 0);
    assert!(control.finish(phase).is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn selected_owner_native_watch_idle_original_and_peer_boot_lifetimes_need_no_actor_progress() {
    for peer_boot in [false, true] {
        let store = Store::new();
        let original = if peer_boot {
            end()
        } else {
            Instant::now() + Duration::from_millis(100)
        };
        let control = WatchControl::new(original, FixtureCancellation::new(store.clone()));
        if peer_boot {
            control
                .bind_boot(boot_now().unwrap() + 100_000_000)
                .unwrap();
        }
        let owner = control.cancellation.bind().unwrap();
        let (server, _client) = UnixStream::pair().unwrap();
        let watcher = WatchWorker::start(&server, control.clone()).unwrap();
        let until = Instant::now() + Duration::from_secs(1);
        while store.live() && Instant::now() < until {
            thread::sleep(Duration::from_millis(1));
        }
        assert!(!store.live());
        assert!(control.check().is_err());
        drop(owner);
        drop(watcher);
        assert_eq!(store.releases(), 1);
    }
}

#[test]
fn selected_owner_custody_stop_is_terminal_before_socket_and_refuses_late_attach() {
    use std::io::Read;
    let stop = CustodySelectedOwnerStop::new(end());
    stop.stop();
    let (server, mut client) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    assert!(stop.control.attach(Arc::new(server)).is_err());
    assert_eq!(client.read(&mut [0; 1]).unwrap(), 0);
    assert!(stop.control.begin(end()).is_err());
    assert!(stop.control.check().is_err());
}

#[test]
fn selected_owner_custody_external_stop_closes_socket_while_connect_verifier_actor_blocks() {
    use std::io::Read;
    let stop = CustodySelectedOwnerStop::new(end());
    let phase = stop.control.begin(end()).unwrap();
    let (client, mut server) = UnixStream::pair().unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    stop.control
        .attach(Arc::new(client.try_clone().unwrap()))
        .unwrap();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let actor_stop = stop.clone();
    let actor = thread::spawn(move || {
        let _attempt = StopAttempt {
            control: actor_stop.control.clone(),
            armed: true,
        };
        ClientWire::open_inner(
            Connection(client, None),
            binding(),
            hint(),
            actor_stop.control.original,
            phase.end,
            |_, _| {
                entered_tx.send(()).unwrap();
                resume_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                actor_stop.control.check()
            },
            |limit| actor_stop.control.bind_boot(limit),
            policy(),
        )
        .is_err()
    });
    entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    stop.stop();
    // The verifier is still blocked: shutdown is directly observable now.
    assert_eq!(server.read(&mut [0; 1]).unwrap(), 0);
    resume_tx.send(()).unwrap();
    assert!(actor.join().unwrap());
    assert!(stop.control.finish(phase).is_err());
}

#[test]
fn selected_owner_custody_external_stop_closes_retained_probe_without_actor_progress() {
    let stop = CustodySelectedOwnerStop::new(end());
    let first = stop.control.begin(end()).unwrap();
    let (client, server) = UnixStream::pair().unwrap();
    stop.control
        .attach(Arc::new(client.try_clone().unwrap()))
        .unwrap();
    let store = Store::new();
    let root_store = store.clone();
    let server_actor = thread::spawn(move || {
        let mut root = accept(server, &root_store).unwrap();
        assert!(step(&mut root).is_err());
    });
    let mut wire = ClientWire::open_inner(
        Connection(client, None),
        binding(),
        hint(),
        stop.control.original,
        first.end,
        |_, _| stop.control.check(),
        |limit| stop.control.bind_boot(limit),
        policy(),
    )
    .unwrap();
    stop.control.finish(first).unwrap();
    let phase = stop.control.begin(end()).unwrap();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let actor_stop = stop.clone();
    let client_actor = thread::spawn(move || {
        let _attempt = StopAttempt {
            control: actor_stop.control.clone(),
            armed: true,
        };
        let result = wire.exchange(Kind::Probe, phase.end, |_, _| {
            entered_tx.send(()).unwrap();
            resume_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            actor_stop.control.check()
        });
        assert!(result.is_err());
        assert!(wire.poisoned);
    });
    entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    stop.stop();
    server_actor.join().unwrap();
    assert!(!store.live());
    assert_eq!(store.releases(), 1);
    resume_tx.send(()).unwrap();
    client_actor.join().unwrap();
    assert!(stop.control.finish(phase).is_err());
}

#[test]
fn selected_owner_custody_attempt_error_or_caught_unwind_poison_pending_handle() {
    for unwind in [false, true] {
        let stop = CustodySelectedOwnerStop::new(end());
        let phase = stop.control.begin(end()).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _attempt = StopAttempt {
                control: stop.control.clone(),
                armed: true,
            };
            if unwind {
                panic!("pending custody constructor unwind");
            }
        }));
        assert_eq!(result.is_err(), unwind);
        assert!(stop.control.finish(phase).is_err());
        assert!(stop.control.begin(end()).is_err());
    }
}

#[cfg(target_os = "macos")]
#[test]
fn selected_owner_native_custody_original_socket_is_bound_before_authentication_and_pending_stop() {
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;
    let mut parent = std::env::temp_dir();
    if parent
        .join("yk1234567890-1/owner.sock")
        .as_os_str()
        .as_bytes()
        .len()
        >= 104
    {
        // The configured repository-local TMPDIR is too long for Darwin's
        // sockaddr_un. Its repository-local target parent keeps this fixture
        // within the real socket ABI without changing production admission.
        parent = parent.parent().expect("temporary parent").to_path_buf();
    }
    // Core has no tempfile dependency. Atomically create a private fixture
    // directory and remove only this successfully created original on Drop.
    use std::os::unix::fs::DirBuilderExt;
    struct Directory(std::path::PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let directory_path = parent.join(format!(
        "yk{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory_path)
        .unwrap();
    let directory = Directory(directory_path);
    let path = directory.0.join("owner.sock");
    assert!(path.as_os_str().as_bytes().len() < 104);
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let stop = CustodySelectedOwnerStop::new(end());
    let phase = stop.control.begin(end()).unwrap();
    let stream = connect_pending_inner(&path, &stop.control, phase.end, None).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    // No authentication/framing has occurred; stop already owns shutdown.
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    stop.stop();
    assert_eq!(server.read(&mut [0; 1]).unwrap(), 0);
    drop(stream);
    assert!(connect_pending_inner(&path, &stop.control, phase.end, None).is_err());
}

#[test]
fn selected_owner_custody_negative_observer_uses_same_terminal_pending_and_poisoned_state() {
    let stop = CustodySelectedOwnerStop::new(end());
    // Pending success is deliberately no evidence that a channel exists.
    stop.require_not_stopped().unwrap();
    stop.clone().stop();
    assert!(stop.require_not_stopped().is_err());
    assert!(stop.control.begin(end()).is_err());
    let expired = CustodySelectedOwnerStop::new(Instant::now());
    assert!(expired.require_not_stopped().is_err());
    let poisoned = CustodySelectedOwnerStop::new(end());
    let retained = poisoned.clone();
    assert!(std::panic::catch_unwind(move || {
        let _state = retained.control.state.lock().unwrap();
        panic!("negative observer metadata poison");
    })
    .is_err());
    assert!(poisoned.require_not_stopped().is_err());
    assert!(poisoned.control.state.is_poisoned());
    assert!(
        poisoned
            .control
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .terminal
    );
}

#[cfg(target_os = "macos")]
#[test]
fn selected_owner_native_custody_negative_observer_sees_eof_phase_and_boot_without_actor() {
    for mode in 0..3 {
        let stop = CustodySelectedOwnerStop::new(end());
        let (server, mut peer) = UnixStream::pair().unwrap();
        let watcher = WatchWorker::start(&server, stop.control.clone()).unwrap();
        if mode == 0 {
            peer.write_all(&[0, 0, 0, 1, 0]).unwrap();
            peer.shutdown(Shutdown::Write).unwrap();
        } else if mode == 1 {
            stop.control
                .begin(Instant::now() + Duration::from_millis(30))
                .unwrap();
        } else {
            stop.control
                .bind_boot(boot_now().unwrap() + 30_000_000)
                .unwrap();
        }
        let until = Instant::now() + Duration::from_secs(1);
        while stop.require_not_stopped().is_ok() && Instant::now() < until {
            thread::sleep(Duration::from_millis(1));
        }
        assert!(stop.require_not_stopped().is_err());
        assert!(stop.control.begin(end()).is_err());
        drop(watcher);
    }
}
