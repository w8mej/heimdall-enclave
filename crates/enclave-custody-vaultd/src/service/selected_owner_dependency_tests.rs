//! Software-only service/real-UDS release tests. Installing the private slot in
//! these fixtures supplies no native identity, channel, HID or readiness claim.
use super::*;
use enclave_core::ipc::{self, PeerPolicy, SocketAccess};
use std::{
    os::unix::fs::PermissionsExt,
    sync::mpsc,
    time::{Duration, Instant},
};

// Fixture scheduling endpoints, not measured YKD02/native lifecycle budgets.
fn after(delay: Duration) -> (Instant, u64) {
    let instant = Instant::now();
    let boot = enclave_core::clock::boot_clock_ns();
    assert!(boot != 0 && boot != u64::MAX);
    (
        instant + delay,
        boot.checked_add(u64::try_from(delay.as_nanos()).unwrap())
            .unwrap(),
    )
}
fn past(end: Instant) {
    std::thread::sleep(end.saturating_duration_since(Instant::now()));
}

fn service(profile: Profile) -> Arc<VaultService> {
    VaultService::start(
        VaultConfig {
            profile,
            ..Default::default()
        },
        VaultHardware::simulated(profile, enclave_crypto::time::now_unix()).unwrap(),
    )
    .unwrap()
}

fn install_fixture(service: &VaultService) -> SelectedOwnerFailure {
    let failure = SelectedOwnerFailure::new();
    assert!(service.selected_owner_failure.set(failure.clone()).is_ok());
    failure
}

fn wait_until(mut predicate: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + Duration::from_secs(3);
    while Instant::now() < end {
        if predicate() {
            return true;
        }
        std::thread::yield_now();
    }
    predicate()
}

// Exercise the actual private ReleasePermit::release via serve, rather than a
// copied validator. Every wait has a deadline, and the socket is repo-local.
fn socket_fixture() -> (
    std::path::PathBuf,
    std::path::PathBuf,
    std::os::unix::net::UnixListener,
) {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!("selected-dep-{:x}", enclave_core::rng::u64()));
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let directory = directory.canonicalize().unwrap();
    // Relative spelling keeps the real AF_UNIX address below macOS's limit.
    let current = std::env::current_dir().unwrap();
    let from: Vec<_> = current.components().collect();
    let to: Vec<_> = directory.components().collect();
    let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
    let mut relative = std::path::PathBuf::new();
    for _ in common..from.len() {
        relative.push("..");
    }
    for component in &to[common..] {
        relative.push(component.as_os_str());
    }
    let socket = relative.join("vault.sock");
    let listener = ipc::bind(&socket, SocketAccess::OwnerOnly).unwrap();
    (directory, socket, listener)
}
fn ipc_bool(
    handler: impl Fn() -> EnclaveResult<bool> + Send + Sync + 'static,
    while_pending: impl FnOnce(),
) -> EnclaveResult<bool> {
    let (directory, socket, listener) = socket_fixture();
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let server = std::thread::spawn(move || {
        ipc::serve(
            listener,
            PeerPolicy::allow([ipc::geteuid()]),
            Arc::new(move |_: &PeerCredentials, _: ()| handler()),
            stopped,
        )
    });
    let client = std::thread::spawn(move || {
        let mut client = ipc::Client::connect(&socket, ipc::geteuid())?;
        client.set_timeout(Some(Duration::from_secs(5)))?;
        client.call::<_, bool>(&())
    });
    while_pending();
    let result = client.join().unwrap();
    stop.store(true, Ordering::SeqCst);
    server.join().unwrap().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    result
}

#[test]
fn original_failure_clones_and_slot_are_terminal() {
    let service = service(Profile::L2);
    let original = install_fixture(&service);
    let retained = original.clone();
    original.require_current().unwrap();
    retained.fail();
    original.fail();
    assert!(original
        .require_current()
        .unwrap_err()
        .is("SELECTED_OWNER_DEPENDENCY_FAILED"));
    let replacement = SelectedOwnerFailure::new();
    assert!(service
        .selected_owner_failure
        .set(replacement.clone())
        .is_err());
    replacement.require_current().unwrap();
    assert!(service
        .require_selected_owner()
        .unwrap_err()
        .is("SELECTED_OWNER_DEPENDENCY_FAILED"));
}

#[test]
fn session_cap_is_one_shot_shared_and_future_end_cannot_extend_original() {
    for earlier in [false, true] {
        let failure = SelectedOwnerFailure::new();
        let (instant, raw) = after(Duration::from_secs(5));
        let end = failure.bind_fixture_original(instant, raw).unwrap();
        assert!(end <= instant);
        let clone = failure.clone();
        clone.require_current().unwrap();
        let replacement = if earlier {
            end - Duration::from_millis(1)
        } else {
            end + Duration::from_secs(50)
        };
        assert!(clone
            .bind_fixture_original(replacement, raw + 1)
            .unwrap_err()
            .is("SELECTED_OWNER_DEPENDENCY_END_ALREADY_BOUND"));
        let retained = failure.0.original.get().unwrap();
        assert_eq!((retained.instant, retained.boot_end), (end, raw));
        assert!(failure.require_current().is_err());
        assert!(clone.require_current().is_err());
    }
}

#[test]
fn concurrent_original_cap_bind_cannot_replace_or_revive_the_winner() {
    let failure = SelectedOwnerFailure::new();
    let one = after(Duration::from_secs(5));
    let two = after(Duration::from_secs(10));
    let start = Arc::new(std::sync::Barrier::new(3));
    let mut workers = Vec::new();
    for (instant, raw) in [one, two] {
        let gate = failure.clone();
        let start = start.clone();
        workers.push(std::thread::spawn(move || {
            start.wait();
            gate.bind_fixture_original(instant, raw).is_ok()
        }));
    }
    start.wait();
    let successful = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .filter(|success| *success)
        .count();
    assert!(successful <= 1);
    let original = failure.0.original.get().unwrap();
    assert!(original.boot_end == one.1 || original.boot_end == two.1);
    assert!(
        original.instant
            <= if original.boot_end == one.1 {
                one.0
            } else {
                two.0
            }
    );
    assert!(failure.require_current().is_err());
}

#[test]
fn invalid_expired_missing_or_fault_clock_cap_is_terminal() {
    let (instant, raw) = after(Duration::from_secs(5));
    let boot = enclave_core::clock::boot_clock_ns();
    for (end, limit) in [
        (instant, 0),
        (instant, u64::MAX),
        (instant, boot),
        (Instant::now(), raw),
    ] {
        let failure = SelectedOwnerFailure::new();
        assert!(failure.bind_fixture_original(end, limit).is_err());
        assert!(failure.bind_fixture_original(instant, raw).is_err());
        assert!(failure.require_current().is_err());
    }
    for clock in [0, u64::MAX] {
        assert!(Original::admit(Instant::now(), clock, instant, raw).is_err());
    }
    let failure = SelectedOwnerFailure::new();
    failure.require_current().unwrap();
    assert!(failure
        .require_original()
        .unwrap_err()
        .is("SELECTED_OWNER_DEPENDENCY_END_REQUIRED"));
    assert!(failure.require_current().is_err());
}

#[test]
fn private_fixture_cap_and_negative_flag_never_satisfy_native_original_requirement() {
    for with_flag in [false, true] {
        let failure = SelectedOwnerFailure::new();
        let (instant, raw) = after(Duration::from_secs(5));
        let session =
            with_flag.then(|| OriginalSession::FixtureRevoked(Arc::new(AtomicBool::new(false))));
        failure.bind_cap(instant, raw, session).unwrap();
        failure.require_current().unwrap();
        assert!(failure
            .require_original()
            .unwrap_err()
            .is("SELECTED_OWNER_DEPENDENCY_END_REQUIRED"));
        assert!(failure.require_current().is_err());
    }
}

#[test]
fn session_cap_uses_each_exclusive_clock_and_conservative_raw_shortening() {
    let start = Instant::now();
    let original = Original::admit(start, 10, start + Duration::from_secs(10), 11).unwrap();
    assert_eq!(original.instant, start + Duration::from_nanos(1));
    assert_eq!(original.boot_end, 11);
    assert!(original.current(start, 10).is_ok());
    assert!(original.current(start, 11).is_err());
    assert!(original.current(original.instant, 10).is_err());
    for clock in [0, u64::MAX] {
        assert!(original.current(start, clock).is_err());
    }
    // Isolate actual raw-clock refusal from a still-future Instant using only
    // the private test seam; production binds only through the admitted record.
    let failure = SelectedOwnerFailure::new();
    let (future, _) = after(Duration::from_secs(5));
    assert!(failure
        .0
        .original
        .set(Original {
            instant: future,
            boot_end: enclave_core::clock::boot_clock_ns(),
            session: None
        })
        .is_ok());
    assert!(failure.require_current().is_err());
    assert!(failure.0.failed.load(Ordering::SeqCst));
}

#[test]
fn finite_session_positive_uses_actual_private_service_and_ipc_permit() {
    let failure = SelectedOwnerFailure::new();
    let service = VaultService::selected_owner_test_fixture(failure.clone()).unwrap();
    let worker = service.clone();
    let bound = failure.clone();
    assert!(ipc_bool(
        move || {
            let (instant, raw) = after(Duration::from_secs(5));
            bound.bind_fixture_original(instant, raw)?;
            let response = worker.handle(
                &PeerCredentials::local(ipc::geteuid(), 0),
                VaultRequest::AllocateSlot,
            )?;
            Ok(matches!(response, VaultResponse::Slot { .. }))
        },
        || {}
    )
    .unwrap());
    failure.require_current().unwrap();
}

#[test]
fn finite_session_never_extends_an_earlier_actual_action_handoff_end() {
    let failure = SelectedOwnerFailure::new();
    let service = VaultService::selected_owner_test_fixture(failure.clone()).unwrap();
    let worker = service.clone();
    let bound = failure.clone();
    assert!(ipc_bool(
        move || {
            let (instant, raw) = after(Duration::from_secs(5));
            bound.bind_fixture_original(instant, raw)?;
            ipc::attach_release_permit(
                worker
                    .selected_release_permit(
                        worker.cas_key_release.clone(),
                        Arc::new(|| Ok(())),
                        SelectedOwnerReply::Authority,
                    )
                    .with_handoff_deadline(Instant::now()),
            );
            Ok(true)
        },
        || {}
    )
    .is_err());
    failure.require_current().unwrap();
}

#[test]
fn finite_session_never_extends_an_earlier_actual_action_raw_handoff_end() {
    let failure = SelectedOwnerFailure::new();
    let service = VaultService::selected_owner_test_fixture(failure.clone()).unwrap();
    let worker = service.clone();
    let bound = failure.clone();
    assert!(ipc_bool(
        move || {
            let (instant, raw) = after(Duration::from_secs(5));
            bound.bind_fixture_original(instant, raw)?;
            ipc::attach_release_permit(
                worker
                    .selected_release_permit(
                        worker.cas_key_release.clone(),
                        Arc::new(|| Ok(())),
                        SelectedOwnerReply::Authority,
                    )
                    .with_handoff_boot_deadline(enclave_core::clock::boot_clock_ns()),
            );
            Ok(true)
        },
        || {}
    )
    .is_err());
    assert!(
        failure.0.original.get().is_some(),
        "handler must reach original binding before IPC refusal counts"
    );
    // The service original remains current: the distinct earlier action end
    // caused IPC refusal rather than a watchdog/dependency failure.
    failure.require_current().unwrap();
}

#[test]
fn final_ipc_session_expiry_while_waiting_serial_needs_no_watchdog_progress() {
    let failure = SelectedOwnerFailure::new();
    let service = VaultService::selected_owner_test_fixture(failure.clone()).unwrap();
    let serial = service.cas_key_release.lock().unwrap();
    let worker = service.clone();
    let bound = failure.clone();
    let (ready, prepared) = mpsc::channel();
    let result = ipc_bool(
        move || {
            let (instant, raw) = after(Duration::from_millis(100));
            let end = bound.bind_fixture_original(instant, raw)?;
            let ready = ready.clone();
            ipc::attach_release_permit(
                worker
                    .selected_release_permit(
                        worker.cas_key_release.clone(),
                        Arc::new(|| Ok(())),
                        SelectedOwnerReply::Authority,
                    )
                    .with_preflight(Arc::new(move || {
                        ready.send(end).unwrap();
                        Ok(())
                    }))
                    .with_handoff_deadline(Instant::now() + Duration::from_secs(10)),
            );
            Ok(true)
        },
        || {
            let end = prepared.recv_timeout(Duration::from_secs(3)).unwrap();
            past(end);
            assert!(
                !failure.0.failed.load(Ordering::SeqCst),
                "no watchdog sampled expiry while final validation waited"
            );
            drop(serial);
        },
    );
    assert!(result.is_err());
    assert!(failure.0.failed.load(Ordering::SeqCst));
    assert!(service.cas_key_release.try_lock().is_ok());
}

#[test]
fn final_ipc_original_policy_stop_is_observed_with_future_clocks_and_no_watchdog() {
    let failure = SelectedOwnerFailure::new();
    let service = VaultService::selected_owner_test_fixture(failure.clone()).unwrap();
    let revoked = Arc::new(AtomicBool::new(false));
    let negative = revoked.clone();
    let serial = service.cas_key_release.lock().unwrap();
    let worker = service.clone();
    let bound = failure.clone();
    let (ready, prepared) = mpsc::channel();
    let result = ipc_bool(
        move || {
            let (instant, raw) = after(Duration::from_secs(5));
            bound.bind_cap(
                instant,
                raw,
                Some(OriginalSession::FixtureRevoked(negative.clone())),
            )?;
            let ready = ready.clone();
            ipc::attach_release_permit(
                worker
                    .selected_release_permit(
                        worker.cas_key_release.clone(),
                        Arc::new(|| Ok(())),
                        SelectedOwnerReply::Authority,
                    )
                    .with_preflight(Arc::new(move || {
                        ready.send(()).unwrap();
                        Ok(())
                    })),
            );
            Ok(true)
        },
        || {
            prepared.recv_timeout(Duration::from_secs(3)).unwrap();
            let original = failure.0.original.get().unwrap();
            assert!(original
                .current(Instant::now(), enclave_core::clock::boot_clock_ns())
                .is_ok());
            assert!(!failure.0.failed.load(Ordering::SeqCst));
            // Private negative-only model of the SAME original session's atomic
            // veto. Root's loader test exercises its actual AtomicBool getter.
            revoked.store(true, Ordering::SeqCst);
            drop(serial);
        },
    );
    assert!(result.is_err());
    assert!(failure.0.failed.load(Ordering::SeqCst));
    assert!(service.cas_key_release.try_lock().is_ok());
}

#[test]
fn bound_session_expiry_before_handler_prevents_actual_fresh_action() {
    let failure = SelectedOwnerFailure::new();
    let service = VaultService::selected_owner_test_fixture(failure.clone()).unwrap();
    let (instant, raw) = after(Duration::from_millis(30));
    let end = failure.bind_fixture_original(instant, raw).unwrap();
    let before = service.lock_state().unwrap().seq.current();
    past(end);
    let worker = service.clone();
    assert!(ipc_bool(
        move || worker
            .handle(
                &PeerCredentials::local(ipc::geteuid(), 0),
                VaultRequest::AllocateSlot
            )
            .map(|_| true),
        || {}
    )
    .is_err());
    // lock_state itself is now refused; inspect only the private fixture's
    // unchanged metadata after observing the actual denied action.
    assert_eq!(service.state.lock().unwrap().seq.current(), before);
    assert!(failure.require_current().is_err());
}

#[test]
fn actual_ipc_backpressure_keeps_session_end_when_later_deadline_is_appended() {
    use std::{io::Read, os::fd::AsRawFd, os::unix::net::UnixStream};
    let failure = SelectedOwnerFailure::new();
    let service = VaultService::selected_owner_test_fixture(failure.clone()).unwrap();
    let (directory, socket, listener) = socket_fixture();
    let small: libc::c_int = 4096;
    assert_eq!(
        unsafe {
            libc::setsockopt(
                listener.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                std::ptr::addr_of!(small).cast(),
                std::mem::size_of_val(&small) as libc::socklen_t,
            )
        },
        0
    );
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let worker = service.clone();
    let bound = failure.clone();
    let (ready, prepared) = mpsc::channel();
    let server = std::thread::spawn(move || {
        ipc::serve(
            listener,
            PeerPolicy::allow([ipc::geteuid()]),
            Arc::new(move |_: &PeerCredentials, _: ()| {
                let (instant, raw) = after(Duration::from_millis(500));
                let end = bound.bind_fixture_original(instant, raw)?;
                let ready = ready.clone();
                ipc::attach_release_permit(
                    worker
                        .selected_release_permit(
                            worker.cas_key_release.clone(),
                            Arc::new(|| Ok(())),
                            SelectedOwnerReply::Authority,
                        )
                        .with_preflight(Arc::new(move || {
                            ready.send(end).unwrap();
                            Ok(())
                        }))
                        .with_handoff_deadline(Instant::now() + Duration::from_secs(10)),
                );
                Ok(serde_bytes::ByteBuf::from(vec![0x5au8; ipc::MAX_FRAME / 2]))
            }),
            stopped,
        )
    });
    let mut client = UnixStream::connect(socket).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    assert_eq!(
        unsafe {
            libc::setsockopt(
                client.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                std::ptr::addr_of!(small).cast(),
                std::mem::size_of_val(&small) as libc::socklen_t,
            )
        },
        0
    );
    ipc::write_frame(&mut client, &ipc::to_cbor(&()).unwrap()).unwrap();
    let end = prepared.recv_timeout(Duration::from_secs(3)).unwrap();
    // Observe a real queued prefix without draining socket backpressure.
    assert!(wait_until(|| {
        let mut byte = 0u8;
        (unsafe {
            libc::recv(
                client.as_raw_fd(),
                std::ptr::addr_of_mut!(byte).cast(),
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        }) == 1
    }));
    past(end);
    // Starting reads after expiry would let an incorrectly extended2s writer
    // finish. The retained session deadline instead closes its partial frame.
    let mut received = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut complete = false;
    loop {
        let count = client.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        received.extend_from_slice(&buffer[..count]);
        if received.len() >= 4 {
            let declared = u32::from_be_bytes(received[..4].try_into().unwrap()) as usize;
            if received.len() >= 4 + declared {
                complete = true;
                break;
            }
        }
    }
    drop(client);
    stop.store(true, Ordering::SeqCst);
    server.join().unwrap().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        !received.is_empty(),
        "fixture must establish an actual pre-expiry prefix"
    );
    assert!(
        !complete,
        "a backpressured success cannot complete after original session expiry"
    );
    assert!(service.cas_key_release.try_lock().is_ok());
    assert!(failure.require_current().is_err());
    // The already queued prefix stands; it is neither retried nor recalled.
}

#[test]
fn actual_ipc_backpressure_keeps_original_raw_end_with_live_instant_and_later_decorators() {
    use std::{io::Read, os::fd::AsRawFd, os::unix::net::UnixStream};
    let failure = SelectedOwnerFailure::new();
    let service = VaultService::selected_owner_test_fixture(failure.clone()).unwrap();
    let (directory, socket, listener) = socket_fixture();
    let small: libc::c_int = 4096;
    assert_eq!(
        unsafe {
            libc::setsockopt(
                listener.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                std::ptr::addr_of!(small).cast(),
                std::mem::size_of_val(&small) as libc::socklen_t,
            )
        },
        0
    );
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let validations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let checked = validations.clone();
    let worker = service.clone();
    let bound = failure.clone();
    let (ready, prepared) = mpsc::channel();
    let server = std::thread::spawn(move || {
        ipc::serve(
            listener,
            PeerPolicy::allow([ipc::geteuid()]),
            Arc::new(move |_: &PeerCredentials, _: ()| {
                let admitted = Instant::now();
                let raw = enclave_core::clock::boot_clock_ns()
                    .checked_add(500_000_000)
                    .unwrap();
                // Private fault fixture separates clock domains to model a raw
                // expiry while Instant remains live. Production admits only the
                // original native session and conservative conversion; no public
                // API can mint/replace this metadata or create native authority.
                let instant = admitted + Duration::from_secs(30);
                assert!(bound
                    .0
                    .original
                    .set(Original {
                        instant,
                        boot_end: raw,
                        session: None
                    })
                    .is_ok());
                bound.require_current()?;
                let ready = ready.clone();
                let checked = checked.clone();
                ipc::attach_release_permit(
                    worker
                        .selected_release_permit(
                            worker.cas_key_release.clone(),
                            Arc::new(move || {
                                checked.fetch_add(1, Ordering::SeqCst);
                                Ok(())
                            }),
                            SelectedOwnerReply::Authority,
                        )
                        .with_preflight(Arc::new(move || {
                            ready.send((admitted, instant, raw)).unwrap();
                            Ok(())
                        }))
                        .with_handoff_deadline(instant + Duration::from_secs(30))
                        .with_handoff_boot_deadline(raw + 30_000_000_000),
                );
                Ok(serde_bytes::ByteBuf::from(vec![0x6bu8; ipc::MAX_FRAME / 2]))
            }),
            stopped,
        )
    });
    let mut client = UnixStream::connect(socket).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    assert_eq!(
        unsafe {
            libc::setsockopt(
                client.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                std::ptr::addr_of!(small).cast(),
                std::mem::size_of_val(&small) as libc::socklen_t,
            )
        },
        0
    );
    ipc::write_frame(&mut client, &ipc::to_cbor(&()).unwrap()).unwrap();
    let (admitted, instant, raw) = prepared.recv_timeout(Duration::from_secs(3)).unwrap();
    assert!(wait_until(|| {
        let mut byte = 0u8;
        (unsafe {
            libc::recv(
                client.as_raw_fd(),
                std::ptr::addr_of_mut!(byte).cast(),
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        }) == 1
    }));
    assert_eq!(
        validations.load(Ordering::SeqCst),
        2,
        "validation before preflight and after serial preceded the queued prefix"
    );
    assert!(wait_until(|| enclave_core::clock::boot_clock_ns() >= raw));
    // Scheduling precondition isolates the new raw cap from the generic 2s
    // write bound. A stalled fixture fails instead of claiming causal coverage.
    assert!(
        Instant::now() < admitted + Duration::from_secs(1),
        "fixture stalled before raw-only drain"
    );
    assert!(Instant::now() < instant);
    assert!(
        !failure.0.failed.load(Ordering::SeqCst),
        "no watchdog or later validator sampled expiry"
    );
    let mut received = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut complete = false;
    loop {
        let count = client.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        received.extend_from_slice(&buffer[..count]);
        if received.len() >= 4 {
            let declared = u32::from_be_bytes(received[..4].try_into().unwrap()) as usize;
            if received.len() >= 4 + declared {
                complete = true;
                break;
            }
        }
    }
    drop(client);
    stop.store(true, Ordering::SeqCst);
    server.join().unwrap().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(!received.is_empty(), "actual pre-expiry prefix must stand");
    assert!(
        !complete,
        "later decorators cannot extend the original raw end during a started send"
    );
    assert_eq!(
        validations.load(Ordering::SeqCst),
        2,
        "writer performs raw checks without further validator callbacks"
    );
    assert!(Instant::now() < instant);
    assert!(service.cas_key_release.try_lock().is_ok());
    assert!(failure.require_current().is_err());
}

#[cfg(not(target_os = "macos"))]
#[test]
fn production_installer_refuses_non_native_without_installing_test_authority() {
    let service = service(Profile::L2);
    assert!(service
        .install_selected_owner_failure(SelectedOwnerFailure::new())
        .unwrap_err()
        .is("SELECTED_OWNER_DEPENDENCY_NATIVE_REQUIRED"));
    assert!(service.selected_owner_failure.get().is_none());
}

#[test]
fn absent_dependency_preserves_ordinary_software_profiles() {
    for profile in [Profile::L1, Profile::L2, Profile::L3] {
        let service = service(profile);
        assert!(service.selected_owner_failure.get().is_none());
        let worker = service.clone();
        assert!(ipc_bool(
            move || {
                let response = worker.handle(
                    &PeerCredentials::local(ipc::geteuid(), 0),
                    VaultRequest::AllocateSlot,
                )?;
                Ok(matches!(response, VaultResponse::Slot { .. }))
            },
            || {}
        )
        .unwrap());
    }
}

#[test]
fn direct_failure_fences_before_blocked_state_and_drops_serial_before_cleanup() {
    let service = service(Profile::L2);
    let failure = install_fixture(&service);
    let generation = service.cas_key_generation.load(Ordering::SeqCst);
    let state = service.lock_state().unwrap();
    let worker = service.clone();
    let (done, outcome) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let result = worker.fail_selected_owner();
        done.send(result).unwrap();
    });
    let fenced = wait_until(|| service.cas_key_generation.load(Ordering::SeqCst) != generation);
    let failed = failure.require_current().is_err();
    let cancelled = service.ceremony_cancelled.load(Ordering::SeqCst);
    let disabled = !service.cas_keys_enabled.load(Ordering::SeqCst);
    let serial_free = service.cas_key_release.try_lock().is_ok();
    let still_cleaning = matches!(outcome.try_recv(), Err(mpsc::TryRecvError::Empty));
    drop(state);
    outcome
        .recv_timeout(Duration::from_secs(3))
        .unwrap()
        .unwrap();
    thread.join().unwrap();
    assert!(fenced && failed && cancelled && disabled && serial_free && still_cleaning);
}

#[test]
fn direct_failure_latches_before_waiting_for_existing_release() {
    let service = service(Profile::L2);
    let failure = install_fixture(&service);
    let serial = service.cas_key_release.lock().unwrap();
    let generation = service.cas_key_generation.load(Ordering::SeqCst);
    let worker = service.clone();
    let (done, outcome) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let result = worker.fail_selected_owner();
        done.send(result).unwrap();
    });
    let failed = wait_until(|| failure.require_current().is_err());
    let cancelling = wait_until(|| service.ceremony_cancelled.load(Ordering::SeqCst));
    let old_generation = service.cas_key_generation.load(Ordering::SeqCst) == generation;
    let still_waiting = matches!(outcome.try_recv(), Err(mpsc::TryRecvError::Empty));
    drop(serial);
    outcome
        .recv_timeout(Duration::from_secs(3))
        .unwrap()
        .unwrap();
    thread.join().unwrap();
    assert!(failed && cancelling && old_generation && still_waiting);
    assert!(service.cas_key_generation.load(Ordering::SeqCst) > generation);
    assert!(!service.cas_keys_enabled.load(Ordering::SeqCst));
}

#[test]
fn failed_dependency_refuses_fresh_authorization_and_enrollment_before_state_wait() {
    let service = service(Profile::L2);
    install_fixture(&service).fail();
    let generation = service.cas_key_generation.load(Ordering::SeqCst);
    service.ceremony_cancelled.store(true, Ordering::SeqCst);
    service.cas_keys_enabled.store(false, Ordering::SeqCst);
    let state = service.lock_state().unwrap();
    let worker = service.clone();
    let (done, outcome) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let peer = PeerCredentials::local(ipc::geteuid(), 0);
        let results = [
            worker.prepare_fresh_authorization(generation),
            worker.finish_fresh_authorization(generation, Profile::L2, ActionClass::A3),
            worker.prepare_sterile_replacement_enrollment(generation, Profile::L2),
            worker.enroll(&peer).map(|_| ()),
            worker.handle(&peer, VaultRequest::AllocateSlot).map(|_| ()),
        ];
        done.send(results.map(|r| r.is_err_and(|e| e.is("SELECTED_OWNER_DEPENDENCY_FAILED"))))
            .unwrap();
    });
    let early = outcome.recv_timeout(Duration::from_secs(3));
    drop(state);
    thread.join().unwrap();
    assert_eq!(early.unwrap(), [true; 5]);
    assert!(service.ceremony_cancelled.load(Ordering::SeqCst));
    assert!(!service.cas_keys_authorized());
    assert!(!service.cas_keys_enabled.load(Ordering::SeqCst));
    assert!(service
        .check_lifecycle_generation(generation)
        .unwrap_err()
        .is("SELECTED_OWNER_DEPENDENCY_FAILED"));
}

#[test]
fn actual_state_acquisition_rechecks_failure_before_consuming_ingress_slot() {
    let service = service(Profile::L2);
    let failure = install_fixture(&service);
    let sequence = service.lock_state().unwrap().seq.current();
    let worker = service.clone();
    let (snapshot, observed) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    let (done, outcome) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        INGRESS_PAIR_SNAPSHOT_FOR_TEST.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move |required| {
                assert!(!required);
                snapshot.send(()).unwrap();
                resumed.recv_timeout(Duration::from_secs(3)).unwrap();
            }))
        });
        done.send(worker.handle(
            &PeerCredentials::local(ipc::geteuid(), 0),
            VaultRequest::AllocateSlot,
        ))
        .unwrap();
    });
    observed.recv_timeout(Duration::from_secs(3)).unwrap();
    let state = service.lock_state().unwrap();
    failure.fail();
    resume.send(()).unwrap();
    drop(state);
    assert!(outcome
        .recv_timeout(Duration::from_secs(3))
        .unwrap()
        .unwrap_err()
        .is("SELECTED_OWNER_DEPENDENCY_FAILED"));
    thread.join().unwrap();
    assert_eq!(service.lock_state().unwrap().seq.current(), sequence);
}

#[test]
fn final_ipc_validator_observes_failure_after_preflight_while_serial_is_busy() {
    let service = service(Profile::L2);
    let failure = install_fixture(&service);
    let serial = service.cas_key_release.lock().unwrap();
    let worker = service.clone();
    let (prepared, ready) = mpsc::channel();
    let result = ipc_bool(
        move || {
            let prepared = prepared.clone();
            let permit = worker
                .selected_release_permit(
                    worker.cas_key_release.clone(),
                    Arc::new(|| Ok(())),
                    SelectedOwnerReply::Authority,
                )
                .with_preflight(Arc::new(move || {
                    prepared.send(()).unwrap();
                    Ok(())
                }));
            ipc::attach_release_permit(permit);
            Ok(true)
        },
        || {
            ready.recv_timeout(Duration::from_secs(3)).unwrap();
            failure.fail();
            drop(serial);
        },
    );
    assert!(
        result.is_err(),
        "a prepared successful handler must not hand off after terminal failure"
    );
}

#[test]
fn permit_prepared_before_slot_install_observes_original_later_failure() {
    let service = service(Profile::L2);
    let worker = service.clone();
    let (prepared, ready) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    let resumed = Mutex::new(resumed);
    let result = ipc_bool(
        move || {
            ipc::attach_release_permit(worker.selected_release_permit(
                worker.cas_key_release.clone(),
                Arc::new(|| Ok(())),
                SelectedOwnerReply::Authority,
            ));
            prepared.send(()).unwrap();
            resumed
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(3))
                .unwrap();
            Ok(true)
        },
        || {
            ready.recv_timeout(Duration::from_secs(3)).unwrap();
            install_fixture(&service).fail();
            resume.send(()).unwrap();
        },
    );
    assert!(result.is_err());
}

#[test]
fn l2_pre_asset_reply_gets_actual_final_dependency_permit() {
    let service = service(Profile::L2);
    let failure = install_fixture(&service);
    assert!(service.lock_state().unwrap().active_asset_guard.is_none());
    // Existing L2 ingress does not demand key authorization. The new negative
    // fallback must not silently turn that into an enrollment prerequisite.
    service.cas_keys_enabled.store(false, Ordering::SeqCst);
    let worker = service.clone();
    let (prepared, ready) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    let resumed = Mutex::new(resumed);
    let result = ipc_bool(
        move || {
            assert!(matches!(
                worker.handle(
                    &PeerCredentials::local(ipc::geteuid(), 0),
                    VaultRequest::AllocateSlot
                )?,
                VaultResponse::Slot { .. }
            ));
            prepared.send(()).unwrap();
            resumed
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(3))
                .unwrap();
            Ok(true)
        },
        || {
            ready.recv_timeout(Duration::from_secs(3)).unwrap();
            failure.fail();
            resume.send(()).unwrap();
        },
    );
    assert!(
        result.is_err(),
        "the actual L2 handler must retain a dependency permit without an asset guard"
    );
}

#[test]
fn selected_only_fallback_preserves_captured_generation_and_time_bounds() {
    for stage in 0..4 {
        let service = service(Profile::L2);
        install_fixture(&service);
        service.cas_keys_enabled.store(false, Ordering::SeqCst);
        let generation = service.cas_key_generation.load(Ordering::SeqCst);
        let worker = service.clone();
        let result = ipc_bool(
            move || {
                worker.attach_selected_dependency_release(
                    if stage == 0 {
                        generation.saturating_add(1)
                    } else {
                        generation
                    },
                    if stage == 1 { Some(0) } else { None },
                    if stage == 2 {
                        Some(enclave_crypto::time::now_unix() - 1)
                    } else {
                        None
                    },
                )?;
                Ok(true)
            },
            || {},
        );
        if stage == 3 {
            assert!(
                result.unwrap(),
                "negative dependency preserves ordinary L2 ingress without keys"
            );
        } else {
            assert!(result.is_err());
        }
    }
}

#[test]
fn l3_original_lifecycle_validator_is_not_replaced_by_dependency_fallback() {
    let service = service(Profile::L3);
    install_fixture(&service);
    let worker = service.clone();
    let (prepared, ready) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    let resumed = Mutex::new(resumed);
    let result = ipc_bool(
        move || {
            worker.handle(
                &PeerCredentials::local(ipc::geteuid(), 0),
                VaultRequest::AllocateSlot,
            )?;
            prepared.send(()).unwrap();
            resumed
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(3))
                .unwrap();
            Ok(true)
        },
        || {
            ready.recv_timeout(Duration::from_secs(3)).unwrap();
            // The selected-only fallback checks generation, not enabled. Only the
            // original stronger lifecycle validator can reject this transition.
            service.cas_keys_enabled.store(false, Ordering::SeqCst);
            resume.send(()).unwrap();
        },
    );
    assert!(result.is_err());
}

#[test]
fn original_validator_preflight_and_handoff_deadline_remain_effective() {
    for stage in 0..3 {
        let service = service(Profile::L2);
        install_fixture(&service);
        let worker = service.clone();
        let validated = Arc::new(AtomicBool::new(false));
        let preflighted = Arc::new(AtomicBool::new(false));
        let seen_validator = validated.clone();
        let seen_preflight = preflighted.clone();
        let result = ipc_bool(
            move || {
                let validated = seen_validator.clone();
                let preflighted = seen_preflight.clone();
                let permit = worker
                    .selected_release_permit(
                        worker.cas_key_release.clone(),
                        Arc::new(move || {
                            validated.store(true, Ordering::SeqCst);
                            if stage == 0 {
                                fail!(EACCES, "ORIGINAL_VALIDATOR_REFUSED");
                            }
                            Ok(())
                        }),
                        SelectedOwnerReply::Authority,
                    )
                    .with_preflight(Arc::new(move || {
                        preflighted.store(true, Ordering::SeqCst);
                        if stage == 1 {
                            fail!(EACCES, "ORIGINAL_PREFLIGHT_REFUSED");
                        }
                        Ok(())
                    }))
                    .with_handoff_deadline(Instant::now());
                ipc::attach_release_permit(permit);
                Ok(true)
            },
            || {},
        );
        assert!(result.is_err());
        assert!(validated.load(Ordering::SeqCst));
        assert_eq!(preflighted.load(Ordering::SeqCst), stage != 0);
    }
}

#[test]
fn failure_keeps_only_status_and_tamper_acknowledgments_available() {
    let service = service(Profile::L2);
    install_fixture(&service);
    service.fail_selected_owner().unwrap();
    for tamper in [false, true] {
        let worker = service.clone();
        assert!(ipc_bool(
            move || {
                let request = if tamper {
                    VaultRequest::Tamper(TamperEvent::ScreenLock)
                } else {
                    VaultRequest::Status
                };
                let response =
                    worker.handle(&PeerCredentials::local(ipc::geteuid(), 0), request)?;
                Ok(matches!(
                    response,
                    VaultResponse::Status(_) | VaultResponse::Zeroized(_)
                ))
            },
            || {}
        )
        .unwrap());
    }
    let worker = service.clone();
    assert!(ipc_bool(
        move || worker
            .handle(
                &PeerCredentials::local(ipc::geteuid(), 0),
                VaultRequest::BootEpoch
            )
            .map(|_| true),
        || {}
    )
    .is_err());
}

#[test]
fn cleanup_error_cannot_clear_terminal_failure_or_revive_generation() {
    let service = service(Profile::L2);
    let failure = install_fixture(&service);
    let generation = service.cas_key_generation.load(Ordering::SeqCst);
    let poisoned = service.state.clone();
    assert!(std::thread::spawn(move || {
        let _state = poisoned.lock().unwrap();
        panic!("software fixture State poison");
    })
    .join()
    .is_err());
    assert!(service
        .fail_selected_owner()
        .unwrap_err()
        .is("STATE_POISONED"));
    assert!(failure
        .require_current()
        .unwrap_err()
        .is("SELECTED_OWNER_DEPENDENCY_FAILED"));
    assert!(service.cas_key_generation.load(Ordering::SeqCst) > generation);
    assert!(service.ceremony_cancelled.load(Ordering::SeqCst));
    assert!(!service.cas_keys_enabled.load(Ordering::SeqCst));
}

#[derive(Debug)]
struct ObservedDisplay {
    shown: Arc<std::sync::atomic::AtomicUsize>,
    prepare: Option<(mpsc::SyncSender<()>, mpsc::Receiver<()>)>,
}
impl HumanDisplay for ObservedDisplay {
    fn prepare(&mut self) -> EnclaveResult<()> {
        if let Some((entered, resume)) = self.prepare.take() {
            entered.send(()).unwrap();
            resume.recv_timeout(Duration::from_secs(3)).unwrap();
        }
        Ok(())
    }
    fn show(&mut self, values: &[SecretBytes]) -> EnclaveResult<()> {
        assert_eq!(values.len(), 1);
        self.shown.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn detokenize_fixture(
    prepare: Option<(mpsc::SyncSender<()>, mpsc::Receiver<()>)>,
) -> (
    Arc<VaultService>,
    SelectedOwnerFailure,
    Arc<std::sync::atomic::AtomicUsize>,
    VaultRequest,
) {
    let shown = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut hardware =
        VaultHardware::simulated(Profile::L2, enclave_crypto::time::now_unix()).unwrap();
    hardware.display = Box::new(ObservedDisplay {
        shown: shown.clone(),
        prepare,
    });
    let service = VaultService::start(
        VaultConfig {
            profile: Profile::L2,
            ..Default::default()
        },
        hardware,
    )
    .unwrap();
    let failure = install_fixture(&service);
    let response = service
        .handle(
            &PeerCredentials::local(ipc::geteuid(), 0),
            VaultRequest::Tokenize {
                items: vec![TokenizeItem {
                    value: "selected-dependency@example.invalid".into(),
                    declared: Some(PiiKind::Email),
                }],
                bulk_set: false,
                grant: None,
            },
        )
        .unwrap();
    let VaultResponse::Tokens(tokens) = response else { panic!("expected actual tokens"); };
    let draft = enclave_core::intent_draft::IntentDraftV1 {
        action_class: ActionClass::A3,
        profile: Profile::L2,
        data_class: enclave_core::label::Conf::C3,
        tool_name: "detokenize_row".into(),
        target_namespace: "data".into(),
        canonical_verb: "Reveal".into(),
        row_count_bound: 1,
        arguments_jcs_sha256: "ab".repeat(32),
        canonical_arguments_blake3: "cd".repeat(32),
        policy_blake3: "ef".repeat(32),
        qif_millibits_delta: 0,
        org_root_mutation: false,
    };
    let request = VaultRequest::Detokenize {
        surrogates: vec![tokens[0].token.clone()],
        draft: Box::new(draft),
    };
    (service, failure, shown, request)
}

#[test]
fn actual_detokenize_receipt_is_fenced_without_recalling_completed_display() {
    for mode in 0..4 {
        let (service, failure, shown, request) = detokenize_fixture(None);
        let worker = service.clone();
        let (prepared, ready) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        let resumed = Mutex::new(resumed);
        let result = ipc_bool(
            move || {
                let response =
                    worker.handle(&PeerCredentials::local(ipc::geteuid(), 0), request.clone())?;
                assert!(matches!(response, VaultResponse::Delivered { rows: 1, .. }));
                prepared.send(()).unwrap();
                resumed
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(3))
                    .unwrap();
                Ok(true)
            },
            || {
                ready.recv_timeout(Duration::from_secs(3)).unwrap();
                assert_eq!(
                    shown.load(Ordering::SeqCst),
                    1,
                    "the real display path has already completed"
                );
                match mode {
                    1 => failure.fail(), // Unchanged generation proves the added dependency is retained.
                    2 => service.fail_selected_owner().unwrap(),
                    3 => service.revoke_cas_keys().unwrap(), // Original lifecycle authority is retained too.
                    _ => (),
                }
                resume.send(()).unwrap();
            },
        );
        if mode == 0 {
            assert!(result.unwrap());
        } else {
            assert!(
                result.is_err(),
                "a prepared Delivered receipt cannot cross either fence"
            );
        }
        assert_eq!(
            shown.load(Ordering::SeqCst),
            1,
            "failed receipt never replays or recalls a pre-fence effect"
        );
    }
}

#[test]
fn actual_display_handoff_refuses_dependency_loss_after_preparation() {
    let (entered, prepared) = mpsc::sync_channel(1);
    let (resume, resumed) = mpsc::sync_channel(1);
    let (service, failure, shown, request) = detokenize_fixture(Some((entered, resumed)));
    let worker = std::thread::spawn(move || {
        service.handle(&PeerCredentials::local(ipc::geteuid(), 0), request)
    });
    prepared.recv_timeout(Duration::from_secs(3)).unwrap();
    failure.fail();
    resume.send(()).unwrap();
    assert!(worker
        .join()
        .unwrap()
        .unwrap_err()
        .is("SELECTED_OWNER_DEPENDENCY_FAILED"));
    assert_eq!(shown.load(Ordering::SeqCst), 0);
}
