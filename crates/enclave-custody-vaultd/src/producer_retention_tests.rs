//! Private actual-service admission boundaries; no public/physical transaction claim.
use super::*;

fn fixture_service() -> Arc<VaultService> {
    VaultService::start(
        VaultConfig {
            profile: Profile::L1,
            state_dir: None,
            audit_path: None,
            socket_dir: None,
            dev_same_uid: false,
            grant_key: None,
        },
        VaultHardware::simulated(Profile::L1, enclave_crypto::time::now_unix()).unwrap(),
    )
    .unwrap()
}

fn assert_local_full<T>(result: EnclaveResult<T>) {
    match result {
        Err(error) => assert!(
            error.is("WITNESS_RETENTION_CAPACITY"),
            "unexpected refusal: {error:?}"
        ),
        Ok(_) => panic!("actual local release unexpectedly succeeded"),
    }
}

#[test]
fn local_release_exact_logical_byte_limit_then_excess_preserves_prior_witness() {
    let service = fixture_service();
    let mut state = service.lock_state().unwrap();
    let (epoch, first) = VaultService::begin_governed(&mut state).unwrap();
    // Raw is deliberately empty: exercise actual retention without hashing
    // a 2MiB raw public request. This distinction must survive evidence labels.
    VaultService::release(
        &mut state,
        &epoch,
        first,
        b"",
        vec![b'x'; WITNESS_MAX_BYTES],
    )
    .unwrap();
    assert_eq!(state.witness.len(), 1);
    assert_eq!(state.witness_bytes, WITNESS_MAX_BYTES);
    assert!(state.egress.was_released(&epoch, first));
    let before = state.witness.clone();
    let (same_epoch, refused) = VaultService::begin_governed(&mut state).unwrap();
    assert_eq!(same_epoch, epoch);
    assert_local_full(VaultService::release(
        &mut state,
        &epoch,
        refused,
        b"",
        vec![b'y'],
    ));
    assert!(state.witness == before, "previous retained folds changed");
    assert_eq!(state.witness_bytes, WITNESS_MAX_BYTES);
    assert!(state.egress.was_released(&epoch, first));
    assert!(!state.egress.was_released(&epoch, refused));
    assert!(state.egress.was_issued(&epoch, refused));
    assert!(!state.egress.was_tombstoned(&epoch, refused));
    assert!(state.egress.reserve_tombstone(&epoch, refused).is_ok());
    assert!(state.egress.was_tombstoned(&epoch, refused));
}

#[test]
fn local_release_single_payload_over_logical_limit_never_records_release() {
    let service = fixture_service();
    let mut state = service.lock_state().unwrap();
    let (epoch, refused) = VaultService::begin_governed(&mut state).unwrap();
    assert_local_full(VaultService::release(
        &mut state,
        &epoch,
        refused,
        b"",
        vec![b'x'; WITNESS_MAX_BYTES + 1],
    ));
    assert!(state.witness.is_empty());
    assert_eq!(state.witness_bytes, 0);
    assert!(!state.egress.was_released(&epoch, refused));
    assert!(state.egress.was_issued(&epoch, refused));
    assert!(state.egress.reserve_tombstone(&epoch, refused).is_ok());
}

#[test]
fn local_release_checked_logical_byte_addition_overflow_refuses_without_mutation() {
    let service = fixture_service();
    let mut state = service.lock_state().unwrap();
    let (epoch, refused) = VaultService::begin_governed(&mut state).unwrap();
    // Explicit defensive impossible-state injection. This is NOT reachable
    // healthy-state/public API accounting or actual process memory evidence.
    let healthy_bytes = state.witness_bytes;
    state.witness_bytes = usize::MAX;
    let result = VaultService::release(&mut state, &epoch, refused, b"", vec![1]);
    let observed_bytes = state.witness_bytes;
    let remained_empty = state.witness.is_empty();
    let released = state.egress.was_released(&epoch, refused);
    state.witness_bytes = healthy_bytes; // restore before terminal assertions.
    assert_local_full(result);
    assert_eq!(observed_bytes, usize::MAX);
    assert!(remained_empty);
    assert!(!released);
}

#[test]
fn local_release_zero_payload_still_obeys_real_entry_limit_and_keeps_all_old_folds() {
    let service = fixture_service();
    let mut state = service.lock_state().unwrap();
    let mut epoch = String::new();
    for _ in 0..WITNESS_MAX_ENTRIES {
        let (current_epoch, seq) = VaultService::begin_governed(&mut state).unwrap();
        epoch = current_epoch;
        VaultService::release(&mut state, &epoch, seq, b"", Vec::new()).unwrap();
    }
    assert_eq!(state.witness.len(), WITNESS_MAX_ENTRIES);
    assert_eq!(state.witness_bytes, 0);
    let before = state.witness.clone();
    let (same_epoch, refused) = VaultService::begin_governed(&mut state).unwrap();
    assert_eq!(same_epoch, epoch);
    assert_local_full(VaultService::release(
        &mut state,
        &epoch,
        refused,
        b"",
        Vec::new(),
    ));
    assert!(state.witness == before, "previous retained folds changed");
    assert_eq!(state.witness_bytes, 0);
    assert!(!state.egress.was_released(&epoch, refused));
    assert!(before
        .iter()
        .all(|fold| state.egress.was_released(&epoch, fold.rpc_seq_u64)));
}

#[test]
fn local_prepared_drop_keeps_egress_and_logical_state_uncommitted_in_both_stream_modes() {
    for stream_configured in [false, true] {
        let service = fixture_service();
        let mut state = service.lock_state().unwrap();
        // Drop makes no peer call. This generated pathname is never created
        // and must not be an unrelated live socket path.
        state.socket_dir = stream_configured.then(|| {
            std::env::temp_dir().join(format!(
                "mc-uncreated-prepared-drop-{:x}",
                enclave_core::rng::u64()
            ))
        });
        let (epoch, seq) = VaultService::begin_governed(&mut state).unwrap();
        let before = state.witness.clone();
        let before_bytes = state.witness_bytes;
        let before_capacity = state.witness.capacity();
        let prepared =
            PreparedLocalWitness::prepare(&mut state, &epoch, seq, b"", vec![1, 2, 3]).unwrap();
        drop(prepared);
        assert!(state.witness == before, "previous retained folds changed");
        assert_eq!(state.witness_bytes, before_bytes);
        assert!(!state.egress.was_released(&epoch, seq));
        assert!(state.egress.was_issued(&epoch, seq));
        // Reservation may leave spare allocation. Zero logical mutation is
        // intentionally not a claim of identical allocator/physical state.
        assert!(state.witness.capacity() >= before_capacity);
        // Successful later real release of that same issued slot establishes
        // that dropping a prepared handle did not finalize or poison it.
        state.socket_dir = None;
        VaultService::release(&mut state, &epoch, seq, b"", vec![4, 5]).unwrap();
        assert!(state.egress.was_released(&epoch, seq));
        assert_eq!(state.witness.len(), 1);
        assert_eq!(state.witness_bytes, 2);
        assert_eq!(state.witness[0].scrubbed, vec![4, 5]);
    }
}

#[test]
fn local_release_tombstoned_slot_refusal_preserves_prior_fifo_and_byte_accounting() {
    let service = fixture_service();
    let mut state = service.lock_state().unwrap();
    let (epoch, first) = VaultService::begin_governed(&mut state).unwrap();
    VaultService::release(&mut state, &epoch, first, b"", vec![10, 11, 12]).unwrap();
    let before = state.witness.clone();
    let before_bytes = state.witness_bytes;
    let (same_epoch, finalized) = VaultService::begin_governed(&mut state).unwrap();
    assert_eq!(same_epoch, epoch);
    state.egress.reserve_tombstone(&epoch, finalized).unwrap();
    let before_capacity = state.witness.capacity();
    // This now exercises early preparation refusal, before staging/reserving,
    // rather than a failure from commit's still-retained registry defense.
    let error =
        match PreparedLocalWitness::prepare(&mut state, &epoch, finalized, b"", vec![13, 14]) {
            Err(error) => error,
            Ok(_) => panic!("terminal T must refuse preparation"),
        };
    assert!(error.is("TOMBSTONE_SLOT_FINALIZED"));
    assert_eq!(state.witness.capacity(), before_capacity);
    let error =
        VaultService::release(&mut state, &epoch, finalized, b"", vec![13, 14]).unwrap_err();
    assert!(error.is("TOMBSTONE_SLOT_FINALIZED"));
    assert!(state.egress.was_tombstoned(&epoch, finalized));
    assert!(!state.egress.was_released(&epoch, finalized));
    assert!(state.egress.was_released(&epoch, first));
    assert!(state.witness == before, "previous retained folds changed");
    assert_eq!(state.witness_bytes, before_bytes);
}

#[test]
fn local_terminal_t_precedes_full_byte_capacity_and_preserves_retained_witness() {
    let service = fixture_service();
    let mut state = service.lock_state().unwrap();
    let (epoch, first) = VaultService::begin_governed(&mut state).unwrap();
    // Healthy real logical-byte boundary, private API with empty raw input;
    // not a transport-sized request or physical-memory budget measurement.
    VaultService::release(
        &mut state,
        &epoch,
        first,
        b"",
        vec![b'x'; WITNESS_MAX_BYTES],
    )
    .unwrap();
    let before = state.witness.clone();
    let before_capacity = state.witness.capacity();
    let (same_epoch, finalized) = VaultService::begin_governed(&mut state).unwrap();
    assert_eq!(same_epoch, epoch);
    state.egress.reserve_tombstone(&epoch, finalized).unwrap();
    // Both terminalT and excess-capacity apply. Terminal eligibility wins
    // before byte admission/reserve, using the existing exact named refusal.
    let error = VaultService::release(&mut state, &epoch, finalized, b"", vec![b'y']).unwrap_err();
    assert!(error.is("TOMBSTONE_SLOT_FINALIZED"));
    assert!(state.witness == before, "prior retained witness changed");
    assert_eq!(state.witness_bytes, WITNESS_MAX_BYTES);
    assert_eq!(state.witness.capacity(), before_capacity);
    assert!(state.egress.was_released(&epoch, first));
    assert!(state.egress.was_tombstoned(&epoch, finalized));
    assert!(!state.egress.was_released(&epoch, finalized));
}
