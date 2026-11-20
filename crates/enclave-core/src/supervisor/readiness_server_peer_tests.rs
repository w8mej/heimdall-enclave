//! Private sequencing fixtures do not authenticate a native server peer or
//! construct ServerPeer. Real local framing below is software I/O evidence only.
use super::*;
use std::{cell::Cell, io::Write, time::Duration};

fn endpoint() -> Instant {
    Instant::now() + Duration::from_secs(30)
}
fn peer(uid: u32) -> PeerCredentials {
    let mut peer = PeerCredentials::local(uid, uid);
    peer.pid = Some(123);
    peer.audit_token = Some([7; 8]);
    peer.code_identity = Some(codesign::CodeIdentity {
        identifier: "fixture.original".into(),
        team_id: "fixture-team".into(),
        cdhash: "a".repeat(40),
    });
    peer
}
#[derive(Default)]
struct Stream {
    counts: [usize; 3],
    events: Vec<&'static str>,
}
fn run(
    exchange: &mut Exchange<'_, Stream>,
    verify: &mut impl FnMut(&Stream, Instant) -> EnclaveResult<PeerCredentials>,
) -> EnclaveResult<Instant> {
    exchange.read_with(&mut *verify, |stream, _| {
        stream.counts[0] += 1;
        stream.events.push("read");
        Ok(())
    })?;
    let (end, ()) = exchange.publish_with(&mut *verify, |_| ())?;
    // Publication carries no stream reference; count its actual callback here
    // through this private fixture's event. Other tests count the closure itself.
    exchange.stream.counts[1] += 1;
    exchange.stream.events.push("published");
    exchange.reply_with(&mut *verify, |stream, _| {
        stream.counts[2] += 1;
        stream.events.push("reply");
        Ok(())
    })?;
    Ok(end)
}

#[test]
fn server_peer_same_original_stream_and_verified_snapshot_bracket_every_boundary() {
    for uid in [0, DaemonId::CustodyVault.uid()] {
        let original = peer(uid);
        let original_end = endpoint();
        let mut pin = OriginalPeer::new(original.clone(), uid, original_end).unwrap();
        let mut stream = Stream::default();
        let address = &stream as *const Stream as usize;
        let stopped = AtomicBool::new(false);
        let reads = Cell::new(0);
        for _ in 0..2 {
            let mut exchange = pin.begin(&mut stream, &stopped).unwrap();
            let request_started = Instant::now();
            let end = run(&mut exchange, &mut |actual, end| {
                reads.set(reads.get() + 1);
                assert_eq!(actual as *const Stream as usize, address);
                assert!(end <= original_end);
                Ok(original.clone())
            })
            .unwrap();
            assert!(end <= original_end && end <= Instant::now() + super::super::PROBE);
            assert!(end >= request_started);
            assert!(exchange.completed);
        }
        assert_eq!(reads.get(), 12);
        assert_eq!(stream.counts, [2, 2, 2]);
        assert_eq!(
            stream.events,
            ["read", "published", "reply", "read", "published", "reply"]
        );
        assert!(!pin.consumed);
        assert_eq!(pin.original, original);
        assert_eq!(pin.end, original_end);
    }
}

#[test]
fn server_peer_every_opaque_audit_word_change_at_each_boundary_terminally_refuses() {
    for word in 0..8 {
        for boundary in 0..6 {
            let original = peer(703);
            let mut pin = OriginalPeer::new(original.clone(), 703, endpoint()).unwrap();
            let mut stream = Stream::default();
            let stopped = AtomicBool::new(false);
            let reads = Cell::new(0);
            let published = Cell::new(0);
            let replies = Cell::new(0);
            {
                let mut exchange = pin.begin(&mut stream, &stopped).unwrap();
                let mut verify = |_: &Stream, _: Instant| {
                    let at = reads.get();
                    reads.set(at + 1);
                    let mut value = original.clone();
                    if at == boundary {
                        value.audit_token.as_mut().unwrap()[word] ^= 1;
                    }
                    Ok(value)
                };
                let result = (|| {
                    exchange.read_with(&mut verify, |stream, _| {
                        stream.counts[0] += 1;
                        Ok(())
                    })?;
                    exchange.publish_with(&mut verify, |_| published.set(published.get() + 1))?;
                    exchange.reply_with(&mut verify, |_, _| {
                        replies.set(replies.get() + 1);
                        Ok(())
                    })
                })();
                assert!(result.is_err());
                assert!(exchange.failed);
                assert!(exchange.pin.consumed);
                assert_eq!(reads.get(), boundary + 1);
                assert_eq!(exchange.stream.counts[0], usize::from(boundary > 0));
                assert_eq!(published.get(), usize::from(boundary >= 3));
                assert_eq!(replies.get(), usize::from(boundary >= 5));
                assert!(exchange
                    .read_with(
                        |_, _| panic!("retired peer reauthenticated"),
                        |_, _| -> EnclaveResult<()> { panic!("retired peer read") }
                    )
                    .is_err());
            }
            assert_eq!(pin.original, original);
            assert!(pin.begin(&mut stream, &stopped).is_err());
        }
    }
}

#[test]
fn server_peer_uid_gid_code_missing_identity_and_network_substitution_never_rebind() {
    for variant in 0..9 {
        for boundary in 0..6 {
            let original = peer(703);
            let mut pin = OriginalPeer::new(original.clone(), 703, endpoint()).unwrap();
            let mut stream = Stream::default();
            let stopped = AtomicBool::new(false);
            let reads = Cell::new(0);
            {
                let mut exchange = pin.begin(&mut stream, &stopped).unwrap();
                let result = run(&mut exchange, &mut |_, _| {
                    let at = reads.get();
                    reads.set(at + 1);
                    let mut value = original.clone();
                    if at == boundary {
                        match variant {
                            0 => value.uid = 0,
                            1 => value.gid ^= 1,
                            2 => value.code_identity.as_mut().unwrap().identifier.push('x'),
                            3 => value.code_identity.as_mut().unwrap().team_id.push('x'),
                            4 => value.code_identity.as_mut().unwrap().cdhash = "b".repeat(40),
                            5 => value.audit_token = None,
                            6 => value.code_identity = None,
                            7 => value.tls_channel_binding = Some([1; 32]),
                            _ => value.uid = 501,
                        }
                    }
                    Ok(value)
                });
                assert!(result.is_err());
                assert!(exchange.pin.consumed);
                assert!(exchange.failed);
            }
            assert_eq!(pin.original, original);
            assert!(pin.begin(&mut stream, &stopped).is_err());
        }
    }
}

#[test]
fn server_peer_initial_snapshot_requires_native_identity_shape_and_same_quota_uid() {
    for variant in 0..5 {
        let mut original = peer(703);
        match variant {
            0 => original.uid = 501,
            1 => original.audit_token = None,
            2 => original.code_identity = None,
            3 => original.tls_channel_binding = Some([1; 32]),
            _ => (),
        }
        let admitted = if variant == 4 { 0 } else { original.uid };
        assert!(OriginalPeer::new(original, admitted, endpoint()).is_err());
    }
}

#[test]
fn server_peer_pid_telemetry_cannot_replace_whole_audit_identity() {
    let original = peer(703);
    let mut pin = OriginalPeer::new(original.clone(), 703, endpoint()).unwrap();
    let mut stream = Stream::default();
    let stopped = AtomicBool::new(false);
    {
        let mut exchange = pin.begin(&mut stream, &stopped).unwrap();
        run(&mut exchange, &mut |_, _| {
            let mut value = original.clone();
            value.pid = Some(999);
            Ok(value)
        })
        .unwrap();
    }
    let mut absent = original.clone();
    absent.audit_token = None;
    assert!(pin.same(&absent).is_err());
    let mut changed = original.clone();
    changed.audit_token.as_mut().unwrap()[5] ^= 1;
    assert!(pin.same(&changed).is_err());
    assert_eq!(pin.original, original);
}

#[test]
fn server_peer_stop_at_each_auth_boundary_is_terminal_even_after_external_reset() {
    for boundary in 0..6 {
        let original = peer(703);
        let mut pin = OriginalPeer::new(original.clone(), 703, endpoint()).unwrap();
        let mut stream = Stream::default();
        let stopped = AtomicBool::new(false);
        let reads = Cell::new(0);
        {
            let mut exchange = pin.begin(&mut stream, &stopped).unwrap();
            assert!(run(&mut exchange, &mut |_, _| {
                let at = reads.get();
                reads.set(at + 1);
                if at == boundary {
                    stopped.store(true, Ordering::Release);
                }
                Ok(original.clone())
            })
            .is_err());
            stopped.store(false, Ordering::Release);
            assert!(exchange.failed);
            assert!(exchange.pin.consumed);
            assert!(exchange
                .read_with(
                    |_, _| panic!("reset stop reauthenticated"),
                    |_, _| -> EnclaveResult<()> { panic!() }
                )
                .is_err());
        }
        assert!(pin.begin(&mut stream, &stopped).is_err());
    }
    let mut pin = OriginalPeer::new(peer(703), 703, endpoint()).unwrap();
    let mut stream = ();
    let stopped = AtomicBool::new(true);
    assert!(pin.begin(&mut stream, &stopped).is_err());
    stopped.store(false, Ordering::Release);
    assert!(pin.begin(&mut stream, &stopped).is_err());
}

#[test]
fn server_peer_original_and_request_endpoints_never_renew_or_expand() {
    let original = peer(703);
    let original_end = endpoint();
    let mut pin = OriginalPeer::new(original.clone(), 703, original_end).unwrap();
    let mut stream = Stream::default();
    let stopped = AtomicBool::new(false);
    {
        let mut exchange = pin.begin(&mut stream, &stopped).unwrap();
        exchange
            .read_with(
                |_, end| {
                    assert_eq!(end, original_end);
                    Ok(original.clone())
                },
                |_, _| Ok(()),
            )
            .unwrap();
        let before = Instant::now();
        let (end, seen) = exchange
            .publish_with(
                |_, end| {
                    assert!(end <= original_end);
                    Ok(original.clone())
                },
                |end| end,
            )
            .unwrap();
        assert_eq!(end, seen);
        assert!(end <= Instant::now() + super::super::PROBE);
        assert!(end >= before && end <= original_end);
        exchange
            .reply_with(
                |_, until| {
                    assert_eq!(until, end);
                    Ok(original.clone())
                },
                |_, until| {
                    assert_eq!(until, end);
                    Ok(())
                },
            )
            .unwrap();
    }
    assert_eq!(pin.end, original_end);
    let mut expired = OriginalPeer::new(original, 703, Instant::now()).unwrap();
    assert!(expired.begin(&mut stream, &stopped).is_err());
    assert!(expired.consumed);
}

#[test]
fn server_peer_late_authentication_withholds_later_io_queue_or_reply() {
    for boundary in 0..6 {
        let original = peer(703);
        let end = Instant::now() + Duration::from_millis(100);
        let mut pin = OriginalPeer::new(original.clone(), 703, end).unwrap();
        let mut stream = Stream::default();
        let stopped = AtomicBool::new(false);
        let reads = Cell::new(0);
        {
            let mut exchange = pin.begin(&mut stream, &stopped).unwrap();
            assert!(run(&mut exchange, &mut |_, _| {
                let at = reads.get();
                reads.set(at + 1);
                if at == boundary {
                    while Instant::now() < end {
                        std::thread::yield_now();
                    }
                }
                Ok(original.clone())
            })
            .is_err());
            assert!(exchange.failed);
            assert!(exchange.pin.consumed);
            assert_eq!(reads.get(), boundary + 1);
        }
        assert!(pin.begin(&mut stream, &stopped).is_err());
    }
}

#[test]
fn server_peer_authentication_error_and_caught_unwind_consume_before_callbacks() {
    for boundary in 0..6 {
        for panic_instead in [false, true] {
            let original = peer(703);
            let mut pin = OriginalPeer::new(original.clone(), 703, endpoint()).unwrap();
            let mut stream = Stream::default();
            let stopped = AtomicBool::new(false);
            let reads = Cell::new(0);
            {
                let mut exchange = pin.begin(&mut stream, &stopped).unwrap();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run(&mut exchange, &mut |_, _| {
                        let at = reads.get();
                        reads.set(at + 1);
                        if at == boundary {
                            if panic_instead {
                                panic!("fixture authentication unwind");
                            }
                            fail!(EIO, "FIXTURE_SERVER_AUTHENTICATION_ERROR");
                        }
                        Ok(original.clone())
                    })
                }));
                assert!(result.is_err() || result.unwrap().is_err());
                assert!(exchange.failed);
                assert!(exchange.pin.consumed);
                assert!(exchange
                    .read_with(
                        |_, _| panic!("caught unwind recaptured"),
                        |_, _| -> EnclaveResult<()> { panic!() }
                    )
                    .is_err());
            }
            assert!(pin.begin(&mut stream, &stopped).is_err());
        }
    }
}

#[test]
fn server_peer_io_or_publication_unwind_and_error_never_replay_original_operation() {
    for phase in 0..3 {
        for panic_instead in [false, true] {
            // Publication has no I/O error channel: a full mailbox is a typed
            // negative response. Its callback unwind must still retire the stream.
            if phase == 1 && !panic_instead {
                continue;
            }
            let original = peer(703);
            let mut pin = OriginalPeer::new(original.clone(), 703, endpoint()).unwrap();
            let mut stream = ();
            let stopped = AtomicBool::new(false);
            let calls = Cell::new(0);
            {
                let mut exchange = pin.begin(&mut stream, &stopped).unwrap();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                    || -> EnclaveResult<()> {
                        exchange.read_with(
                            |_, _| Ok(original.clone()),
                            |_, _| {
                                if phase == 0 {
                                    calls.set(calls.get() + 1);
                                    if panic_instead {
                                        panic!("fixture read unwind");
                                    }
                                    fail!(EIO, "FIXTURE_READ");
                                }
                                Ok(())
                            },
                        )?;
                        exchange.publish_with(
                            |_, _| Ok(original.clone()),
                            |_| {
                                if phase == 1 {
                                    calls.set(calls.get() + 1);
                                    panic!("fixture publish unwind");
                                }
                            },
                        )?;
                        exchange.reply_with(
                            |_, _| Ok(original.clone()),
                            |_, _| {
                                calls.set(calls.get() + 1);
                                if panic_instead {
                                    panic!("fixture reply unwind");
                                }
                                fail!(EIO, "FIXTURE_REPLY");
                            },
                        )
                    },
                ));
                assert!(result.is_err() || result.unwrap().is_err());
                assert_eq!(calls.get(), 1);
                assert!(exchange.failed && exchange.pin.consumed);
            }
            assert!(pin.begin(&mut stream, &stopped).is_err());
        }
    }
}

#[test]
fn server_peer_abandoned_or_out_of_order_exchange_retires_without_authentication_retry() {
    for phase in 0..5 {
        let original = peer(703);
        let mut pin = OriginalPeer::new(original.clone(), 703, endpoint()).unwrap();
        let mut stream = ();
        let stopped = AtomicBool::new(false);
        {
            let mut exchange = pin.begin(&mut stream, &stopped).unwrap();
            if phase == 0 { /* Drop the unread request. */ }
            if phase == 1 {
                exchange
                    .read_with(|_, _| Ok(original.clone()), |_, _| Ok(()))
                    .unwrap();
            }
            if phase == 2 {
                assert!(exchange
                    .publish_with(|_, _| panic!("out of order auth"), |_| ())
                    .is_err());
            }
            if phase == 3 {
                assert!(exchange
                    .reply_with(|_, _| panic!("out of order auth"), |_, _| Ok(()))
                    .is_err());
            }
            if phase == 4 {
                exchange
                    .read_with(|_, _| Ok(original.clone()), |_, _| Ok(()))
                    .unwrap();
                exchange
                    .publish_with(|_, _| Ok(original.clone()), |_| ())
                    .unwrap();
                assert!(exchange
                    .publish_with(|_, _| panic!("duplicate publish auth"), |_| ())
                    .is_err());
            }
            assert!(exchange.pin.consumed);
        }
        assert!(pin.begin(&mut stream, &stopped).is_err());
    }
}

#[test]
fn server_peer_busy_queue_negative_reply_preserves_same_identity_and_original_lifetime() {
    let original = peer(703);
    let end = endpoint();
    let mut pin = OriginalPeer::new(original.clone(), 703, end).unwrap();
    let mut stream = ();
    let stopped = AtomicBool::new(false);
    {
        let mut exchange = pin.begin(&mut stream, &stopped).unwrap();
        exchange
            .read_with(|_, _| Ok(original.clone()), |_, _| Ok(()))
            .unwrap();
        let (_, response) = exchange
            .publish_with(|_, _| Ok(original.clone()), |_| Err::<(), _>("busy"))
            .unwrap();
        assert_eq!(response, Err("busy"));
        exchange
            .reply_with(|_, _| Ok(original.clone()), |_, _| Ok(()))
            .unwrap();
    }
    assert!(!pin.consumed);
    assert_eq!(pin.end, end);
    assert_eq!(pin.original, original);
}

#[test]
fn server_peer_real_local_framing_uses_one_original_stream_through_read_and_reply() {
    let (mut client, mut stream) = UnixStream::pair().unwrap();
    let end = endpoint();
    let limits = FrameIoLimits {
        max_frame: super::super::FRAME,
        frame_deadline: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(2),
    };
    ipc::write_frame_timed(&mut client, b"fixture-request", &limits).unwrap();
    let original = peer(703);
    let mut pin = OriginalPeer::new(original.clone(), 703, end).unwrap();
    let stopped = AtomicBool::new(false);
    {
        let mut exchange = pin.begin(&mut stream, &stopped).unwrap();
        let bytes = exchange
            .read_with(
                |_, _| Ok(original.clone()),
                |stream, _| ipc::read_frame_timed(stream, &limits),
            )
            .unwrap();
        assert_eq!(bytes.as_slice(), b"fixture-request");
        exchange
            .publish_with(|_, _| Ok(original.clone()), |_| ())
            .unwrap();
        exchange
            .reply_with(
                |_, _| Ok(original.clone()),
                |stream, _| ipc::write_frame_timed(stream, b"fixture-reply", &limits),
            )
            .unwrap();
    }
    assert_eq!(
        ipc::read_frame_timed(&mut client, &limits)
            .unwrap()
            .as_slice(),
        b"fixture-reply"
    );
    assert!(!pin.consumed);
}

#[test]
fn server_peer_real_oversized_frame_refuses_without_publication_and_retires_original() {
    let (mut client, mut stream) = UnixStream::pair().unwrap();
    let end = endpoint();
    client
        .write_all(&((super::super::FRAME + 1) as u32).to_be_bytes())
        .unwrap();
    let original = peer(703);
    let mut pin = OriginalPeer::new(original.clone(), 703, end).unwrap();
    let stopped = AtomicBool::new(false);
    {
        let mut exchange = pin.begin(&mut stream, &stopped).unwrap();
        let limits = FrameIoLimits {
            max_frame: super::super::FRAME,
            frame_deadline: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(2),
        };
        assert!(exchange
            .read_with(
                |_, _| Ok(original.clone()),
                |stream, _| ipc::read_frame_timed(stream, &limits)
            )
            .is_err());
        assert!(exchange
            .publish_with(
                |_, _| panic!("bad frame reauthenticated"),
                |_| panic!("bad frame published")
            )
            .is_err());
    }
    assert!(pin.begin(&mut stream, &stopped).is_err());
}

#[cfg(not(target_os = "macos"))]
#[test]
fn server_peer_native_wrapper_never_authenticates_linux_uid_only_socket() {
    let (_client, stream) = UnixStream::pair().unwrap();
    let policy = PeerPolicy::allow([0, 703]);
    assert!(ServerPeer::authenticate(stream, policy, 703, auth_shutdown(), endpoint()).is_err());
}

fn auth_shutdown() -> Arc<super::super::IpcShutdown> {
    super::super::IpcShutdown::new(
        super::super::IpcSession::Fixture {
            revoked: Arc::new(AtomicBool::new(false)),
            process_unknown: Arc::new(AtomicBool::new(false)),
        },
        Arc::new(AtomicBool::new(false)),
    )
}
fn auth_revoked(shutdown: &super::super::IpcShutdown) -> bool {
    match &shutdown.session {
        super::super::IpcSession::Fixture { revoked, .. } => revoked.load(Ordering::SeqCst),
        super::super::IpcSession::Native(_) => {
            panic!("software authentication obtained native authority")
        }
    }
}
// This owns a real local stream. Its Drop observes/holds the actual cleanup
// boundary, AFTER Authentication's Drop body but BEFORE its OS stream closes.
struct AuthCleanupStream {
    stream: UnixStream,
    shutdown: Arc<super::super::IpcShutdown>,
    cleanup: Arc<std::sync::Mutex<()>>,
    entered: Arc<AtomicBool>,
    veto_seen: Arc<AtomicBool>,
}
impl Drop for AuthCleanupStream {
    fn drop(&mut self) {
        self.veto_seen.store(
            auth_revoked(&self.shutdown) && self.shutdown.stop.load(Ordering::SeqCst),
            Ordering::SeqCst,
        );
        self.entered.store(true, Ordering::SeqCst);
        let _cleanup = self
            .cleanup
            .lock()
            .unwrap_or_else(|error| error.into_inner());
    }
}

#[test]
fn authentication_initial_and_postconstruction_unwind_veto_before_owned_stream_cleanup() {
    for boundary in 0..2 {
        let shutdown = auth_shutdown();
        let (_client, stream) = UnixStream::pair().unwrap();
        let cleanup = Arc::new(std::sync::Mutex::new(()));
        let held = cleanup.lock().unwrap();
        let entered = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(AtomicBool::new(false));
        let stream = AuthCleanupStream {
            stream,
            shutdown: shutdown.clone(),
            cleanup: cleanup.clone(),
            entered: entered.clone(),
            veto_seen: seen.clone(),
        };
        let worker_shutdown = shutdown.clone();
        let worker = std::thread::spawn(move || {
            let mut count = 0;
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _owner =
                    authenticate_owned(stream, 703, worker_shutdown, endpoint(), |_, _| {
                        let at = count;
                        count += 1;
                        if at == boundary {
                            panic!("software actual-callee verification unwind");
                        }
                        Ok(peer(703))
                    });
            }))
            .is_err()
        });
        let end = Instant::now() + Duration::from_secs(5);
        while !entered.load(Ordering::SeqCst) && Instant::now() < end {
            std::thread::yield_now();
        }
        assert!(
            entered.load(Ordering::SeqCst),
            "actual cleanup observer never reached"
        );
        assert!(
            seen.load(Ordering::SeqCst) && auth_revoked(&shutdown),
            "callee-owned stream cleanup preceded original veto"
        );
        assert!(
            !worker.is_finished(),
            "fixture cleanup boundary must still be held"
        );
        drop(held);
        assert!(worker.join().unwrap());
    }
}

#[test]
fn authentication_normal_refusal_stays_connection_local_at_both_native_check_positions() {
    for boundary in 0..2 {
        let shutdown = auth_shutdown();
        let (_client, stream) = UnixStream::pair().unwrap();
        let entered = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(AtomicBool::new(false));
        let stream = AuthCleanupStream {
            stream,
            shutdown: shutdown.clone(),
            cleanup: Arc::new(std::sync::Mutex::new(())),
            entered: entered.clone(),
            veto_seen: seen.clone(),
        };
        let mut count = 0;
        let result = authenticate_owned(stream, 703, shutdown.clone(), endpoint(), |_, _| {
            let at = count;
            count += 1;
            if at == boundary {
                fail!(EACCES, "FIXTURE_NORMAL_AUTH_REFUSAL");
            }
            Ok(peer(703))
        });
        assert!(matches!(result,Err(ref error) if error.is("FIXTURE_NORMAL_AUTH_REFUSAL")));
        assert!(entered.load(Ordering::SeqCst) && !seen.load(Ordering::SeqCst));
        assert!(!auth_revoked(&shutdown) && !shutdown.stop.load(Ordering::SeqCst));
    }
}

#[test]
fn authentication_owned_positive_keeps_same_real_stream_and_original_pin_without_root_veto() {
    use std::io::Read;
    let shutdown = auth_shutdown();
    let (mut client, stream) = UnixStream::pair().unwrap();
    client.write_all(b"owned").unwrap();
    let entered = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(AtomicBool::new(false));
    let stream = AuthCleanupStream {
        stream,
        shutdown: shutdown.clone(),
        cleanup: Arc::new(std::sync::Mutex::new(())),
        entered: entered.clone(),
        veto_seen: seen.clone(),
    };
    let identity = std::os::fd::AsRawFd::as_raw_fd(&stream.stream);
    let original = peer(703);
    let mut calls = 0;
    let mut owner = authenticate_owned(stream, 703, shutdown.clone(), endpoint(), |stream, _| {
        assert_eq!(std::os::fd::AsRawFd::as_raw_fd(&stream.stream), identity);
        calls += 1;
        Ok(original.clone())
    })
    .unwrap_or_else(|error| panic!("software owned authentication failed: {error:?}"));
    assert_eq!(calls, 2);
    assert_eq!(owner.pin.as_ref().unwrap().original, original);
    let mut bytes = [0; 5];
    owner.stream.stream.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"owned");
    drop(owner);
    assert!(entered.load(Ordering::SeqCst) && !seen.load(Ordering::SeqCst));
    assert!(!auth_revoked(&shutdown));
}
