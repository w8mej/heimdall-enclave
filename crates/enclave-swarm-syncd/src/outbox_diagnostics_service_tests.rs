// Included inside service::sync_diagnostics_service_tests.
// Reuses that module's Fixture, wall/NOW/EXP, NoBackend and imported types.
// Successor v3 also defers immutable-observation unwinds until locks are
// released and the worker joined; v2 corrected the L3 missing-journal fixture.
// Synthetic PeerCredentials test the INNER policy;
// they do not establish kernel identity or installed authorization acceptance.

fn outbox_fixture(dev: bool, profile: Profile, rooted: bool, durable: bool) -> Fixture {
    let base = std::env::temp_dir().canonicalize().unwrap()
        .join(format!("mc-ob-state-{:016x}", enclave_core::rng::u64()));
    std::fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
    let repo = enclave_crypto::tuf::RepoBuilder::new(3, 2);
    let service = CasService::start_with_wall_clock(CasConfig {
        dev_same_uid: dev, profile, store_dir: base.join("store"),
        audit_path: Some(base.join("audit.jsonl")),
        tuf_root: rooted.then(|| repo.root(EXP).unwrap()), ohttp_gateway: None,
        state_dir: durable.then(|| base.join("sealed")), revocation: Enforcement::Unavailable,
    }, wall).unwrap();
    Fixture {base, service, peer: PeerCredentials::local(enclave_core::ipc::geteuid(), 0), repo}
}

fn outbox_snapshot(f: &Fixture) -> crate::outbox::OutboxDiagnosticsSnapshot {
    let CasResponse::OutboxDiagnostics(snapshot) = f.service.handle(&f.peer, CasRequest::OutboxDiagnostics).unwrap()
        else {panic!("actual outbox response variant");};
    assert!(snapshot.valid());
    assert_eq!(snapshot.process_uid, enclave_core::ipc::geteuid());
    assert_eq!(snapshot.process_pid, std::process::id());
    snapshot
}

fn outbox_sealed_bytes(base: &std::path::Path) -> BTreeMap<PathBuf, Vec<u8>> {
    // The fixture compares its own small sealed files in memory. Never print
    // sealing seeds, MACs, sealed bodies or any other private fixture bytes.
    let mut result = BTreeMap::new();
    for entry in std::fs::read_dir(base.join("sealed")).unwrap() {
        let entry = entry.unwrap();
        assert!(entry.file_type().unwrap().is_file());
        result.insert(entry.file_name().into(), std::fs::read(entry.path()).unwrap());
    }
    result
}

fn outbox_advanced_wall() -> i64 { NOW + 100_000 }

#[test]
fn outbox_diagnostics_actual_held_exhausted_state_preserves_clock_sealed_journal_and_cancellation() {
    use std::sync::atomic::Ordering::SeqCst;
    let f = outbox_fixture(true, Profile::L1, true, true);
    f.service.handle(&f.peer, f.request(1, EXP)).unwrap();
    let expected = outbox_snapshot(&f);
    assert_eq!(expected.observation, crate::outbox::OutboxObservation::Current {
        counts: crate::outbox::OutboxCounts {pending_frames: 0, dead_frames: 0, retained_bytes: 0},
    });
    let audit = std::fs::read(f.base.join("audit.jsonl")).unwrap();
    let sealed = outbox_sealed_bytes(&f.base);
    assert!(sealed.keys().any(|path| path == std::path::Path::new("tuf.sealed")));
    let mut state = f.service.state.lock().unwrap();
    let epoch = state.seq.boot_epoch_id().to_owned();
    state.seq = RpcSequencer::new(epoch, u64::MAX);
    state.wall = outbox_advanced_wall;
    let (clock, persisted, refreshed) = (state.clock.high_water(), state.persisted_high_water, state.refreshed_at);
    let reserved = state.sessions.staging_reserved().unwrap();
    f.service.cancellation.generation.store(17, SeqCst);
    f.service.cancellation.pending.store(1, SeqCst);
    f.service.cancellation.blocked.store(true, SeqCst);
    let release = f.service.cancellation.release.lock().unwrap();
    let foreign_uid = if f.peer.uid == 70_000 {70_001} else {70_000};
    let foreign = PeerCredentials::local(foreign_uid, 0);
    let peer = f.peer.clone();
    let service = f.service.clone();
    let (send, receive) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let allowed = service.handle(&peer, CasRequest::OutboxDiagnostics);
        let refused = service.handle(&foreign, CasRequest::OutboxDiagnostics);
        send.send((allowed, refused)).unwrap();
    });
    // If a regression takes either lock, release both before joining so this
    // fixture fails its bounded oracle without leaving a detached worker.
    let reply = receive.recv_timeout(std::time::Duration::from_secs(2));
    let immutable = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state.seq.current() == u64::MAX
        && (state.clock.high_water(), state.persisted_high_water, state.refreshed_at) == (clock, persisted, refreshed)
        && state.sessions.staging_reserved().unwrap() == reserved
        && f.service.cancellation.generation.load(SeqCst) == 17
        && f.service.cancellation.pending.load(SeqCst) == 1
        && f.service.cancellation.blocked.load(SeqCst)
        && std::fs::read(f.base.join("audit.jsonl")).unwrap() == audit
        && outbox_sealed_bytes(&f.base) == sealed
    }));
    drop(release);
    drop(state);
    let joined = worker.join();
    let immutable = match immutable {
        Ok(immutable) => immutable,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    joined.unwrap();
    let (allowed, refused) = reply.expect("diagnostics waited for State or final-release lock");
    let CasResponse::OutboxDiagnostics(actual) = allowed.unwrap() else {panic!("actual response");};
    assert_eq!(actual, expected);
    assert!(refused.unwrap_err().is("OUTBOX_DIAGNOSTICS_PEER_REJECTED"));
    assert!(immutable, "diagnostic mutated established trust, clock, staging, journal or cancellation");
    // Explicitly exercise the internal locked dispatcher with exhausted State.
    let mut state = f.service.state.lock().unwrap();
    assert!(matches!(f.service.handle_locked(&mut state, &f.peer, CasRequest::OutboxDiagnostics).unwrap(),
        CasResponse::OutboxDiagnostics(value) if value == expected));
    assert_eq!(state.seq.current(), u64::MAX);
    drop(state);
    assert!(f.service.handle(&f.peer, CasRequest::Status).unwrap_err().is("RPC_SEQ_EXHAUSTED"));
}

#[test]
fn outbox_diagnostics_actual_initialized_l3_state_poison_avoids_backends_and_preserves_startup_gate() {
    let f = outbox_fixture(true, Profile::L3, false, false);
    f.service.set_snapshot_publisher(Arc::new(NoBackend)).unwrap();
    f.service.set_namespace_custody(Arc::new(NoBackend)).unwrap();
    f.service.enable_host_profile_floor(Profile::L3).unwrap();
    assert!(f.service.handle(&f.peer, CasRequest::Status).unwrap_err().is("HOST_CONFIG_REQUIRED"));
    let expected = outbox_snapshot(&f);
    // AuditJournal::open creates no file before its first actual event.
    // This unrooted L3 fixture has only refused Status and diagnostic reads.
    assert_eq!(std::fs::symlink_metadata(f.base.join("audit.jsonl")).unwrap_err().kind(), std::io::ErrorKind::NotFound);
    let service = f.service.clone();
    let poisoned = std::thread::spawn(move || {
        let _state = service.state.lock().unwrap();
        panic!("owned State poison proves outbox diagnostics do not recover mutable authority state");
    });
    assert!(poisoned.join().is_err());
    for _ in 0..3 {assert_eq!(outbox_snapshot(&f), expected);}
    let foreign = PeerCredentials::local(if f.peer.uid == 70_000 {70_001} else {70_000}, 0);
    assert!(f.service.handle(&foreign, CasRequest::OutboxDiagnostics).unwrap_err().is("OUTBOX_DIAGNOSTICS_PEER_REJECTED"));
    assert!(f.service.handle(&f.peer, CasRequest::Status).unwrap_err().is("STATE_POISONED"));
    assert_eq!(std::fs::symlink_metadata(f.base.join("audit.jsonl")).unwrap_err().kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn outbox_diagnostics_actual_inner_policy_allows_root_only_in_production_and_actual_uid_only_in_development() {
    // Raw service initialization deliberately skips production entry/signing.
    // Peer credentials here are explicit synthetic inner-policy fixtures.
    let production = outbox_fixture(false, Profile::L1, false, false);
    let root = PeerCredentials::local(0, 0);
    let CasResponse::OutboxDiagnostics(snapshot) = production.service.handle(&root, CasRequest::OutboxDiagnostics).unwrap()
        else {panic!("actual production-mode response");};
    assert!(!snapshot.dev_same_uid && snapshot.valid());
    let mut rejected = std::collections::BTreeSet::from([700, 701, 702, 703, 704, 705, 70_000]);
    if enclave_core::ipc::geteuid() != 0 {rejected.insert(enclave_core::ipc::geteuid());}
    for uid in rejected {
        assert!(production.service.handle(&PeerCredentials::local(uid, 0), CasRequest::OutboxDiagnostics)
            .unwrap_err().is("OUTBOX_DIAGNOSTICS_PEER_REJECTED"), "production admitted nonroot uid {uid}");
    }
    let development = outbox_fixture(true, Profile::L1, false, false);
    assert!(outbox_snapshot(&development).dev_same_uid);
    if enclave_core::ipc::geteuid() != 0 {
        assert!(development.service.handle(&root, CasRequest::OutboxDiagnostics)
            .unwrap_err().is("OUTBOX_DIAGNOSTICS_PEER_REJECTED"));
    }
    let foreign_uid = if development.peer.uid == 70_000 {70_001} else {70_000};
    assert!(development.service.handle(&PeerCredentials::local(foreign_uid, 0), CasRequest::OutboxDiagnostics)
        .unwrap_err().is("OUTBOX_DIAGNOSTICS_PEER_REJECTED"));
}
