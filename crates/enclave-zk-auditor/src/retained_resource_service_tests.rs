//! Actual witness dispatch, derivation and proof-commit resource ownership.
//! Software same-UID relay fixtures do not establish installed daemon identity,
//! whole-prover memory bounds, physical erasure or original gate acceptance.

use super::*;
use crate::witness::{dispatch_witness_request, WitnessChannelRequest, WitnessChannelResponse};
use enclave_core::seq::BootEpoch;
use std::os::unix::fs::DirBuilderExt;
use std::sync::atomic::AtomicUsize;

#[path = "../tests/support/relay_peer.rs"]
mod relay_peer;

struct Directory(PathBuf);

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ResourcePeers {
    epoch: BootEpoch,
    received: Arc<AtomicUsize>,
    acknowledge: bool,
    next_slot: u64,
    fetched: Arc<AtomicUsize>,
    prepared: Arc<AtomicUsize>,
}

impl Peers for ResourcePeers {
    fn cosign(&self, _: DaemonId, _: u64, _: &str) -> EnclaveResult<(Vec<u8>, Vec<u8>)> {
        panic!("resource fixture uses only journaled streamed vault slots")
    }

    fn prepare_relay(&self, frame: &[u8]) -> EnclaveResult<PreparedCall> {
        self.prepared.fetch_add(1, Ordering::SeqCst);
        let received = self.received.clone();
        let acknowledge = self.acknowledge;
        relay_peer::prepare_with_reply(frame, move |bytes| {
            assert!(!bytes.is_empty());
            received.fetch_add(1, Ordering::SeqCst);
            if acknowledge {
                relay_peer::ReplyAction::Queued
            } else {
                relay_peer::ReplyAction::Close
            }
        })
    }

    fn fetch_witness(&self, epoch: &str, _: u64, _: u64) -> EnclaveResult<(Vec<WitnessFold>, u64)> {
        assert_eq!(epoch, self.epoch.boot_epoch_id);
        self.fetched.fetch_add(1, Ordering::SeqCst);
        Ok((Vec::new(), self.next_slot))
    }

    fn boot_epoch(&self) -> EnclaveResult<BootEpoch> {
        Ok(self.epoch.clone())
    }
}

struct Fixture {
    _directory: Directory,
    service: Arc<ZkService>,
    epoch: String,
    other: String,
    received: Arc<AtomicUsize>,
    fetched: Arc<AtomicUsize>,
    prepared: Arc<AtomicUsize>,
}

impl Fixture {
    fn new(acknowledge: bool) -> Self {
        Self::with_slots(acknowledge, &[1])
    }

    fn with_slots(acknowledge: bool, slots: &[u64]) -> Self {
        assert!(!slots.is_empty());
        assert!(slots.windows(2).all(|pair| pair[0] < pair[1]));
        let next_slot = slots.last().unwrap().checked_add(1).unwrap();
        let target = std::env::temp_dir();
        let directory = Directory(target.canonicalize().unwrap().join(format!(
            "rr-{:x}", enclave_core::rng::u64()
        )));
        std::fs::DirBuilder::new().mode(0o700).create(&directory.0).unwrap();
        let epoch = enclave_core::seq::new_boot_epoch_id();
        let other = enclave_core::seq::new_boot_epoch_id();
        let signed = enclave_crypto::epoch::EpochSigner::random().sign(&epoch);
        let journal_root = directory.0.join("logs");
        let vault = DaemonId::CustodyVault;
        let path = journal_root.join(vault.dir_name())
            .join(format!("{}-audit.jsonl", vault.plist_suffix()));
        let mut journal = AuditJournal::open(&path, vault, epoch.clone()).unwrap();
        for &slot in slots {
            journal.append(slot, json!({"event":"SCRUB_TEXT", "slot":slot})).unwrap();
        }
        drop(journal);
        let mut config = ZkConfig::new(Profile::L2, directory.0.join("state"));
        config.audit_path = Some(directory.0.join("auditor.jsonl"));
        config.journal_dir = Some(journal_root);
        config.hardware_batch_anchor_sigs = Some(vec!["3045".into()]);
        config.entity = "registered-witness-resource-fixture".into();
        let received = Arc::new(AtomicUsize::new(0));
        let fetched = Arc::new(AtomicUsize::new(0));
        let prepared = Arc::new(AtomicUsize::new(0));
        let service = ZkService::start(config, Box::new(ResourcePeers {
            epoch: signed,
            received: received.clone(),
            acknowledge,
            next_slot,
            fetched: fetched.clone(),
            prepared: prepared.clone(),
        })).unwrap();
        Self { _directory: directory, service, epoch, other, received, fetched, prepared }
    }

    fn request(&self) -> ProveEpochRequest {
        ProveEpochRequest { boot_epoch_id: self.epoch.clone(), s_start: 1, s_end: 1 }
    }

    fn stream(&self, epoch: &str, folds: Vec<WitnessFold>) -> EnclaveResult<WitnessChannelResponse> {
        dispatch_witness_request(&self.service, WitnessChannelRequest::StreamWitness {
            boot_epoch_id: epoch.into(), folds,
        })
    }

    fn slots(&self, epoch: &str) -> Vec<u64> {
        let snapshot = self.service.lock().unwrap().streamed_witnesses
            .snapshot_range(epoch, 0, u64::MAX).unwrap();
        let (mut folds, lease) = snapshot.into_parts();
        let mut slots: Vec<_> = folds.iter().map(|fold| fold.rpc_seq_u64).collect();
        slots.sort_unstable();
        for fold in &mut folds {
            fold.scrubbed.zeroize();
            fold.c_raw.zeroize();
            fold.h_ingress_mac.zeroize();
        }
        drop(folds);
        drop(lease);
        slots
    }
}

fn fold(slot: u64) -> WitnessFold {
    WitnessFold {
        rpc_seq_u64: slot,
        scrubbed: b"[REDACTED_EMAIL]".to_vec(),
        c_raw: "1".repeat(64),
        h_ingress_mac: "2".repeat(64),
    }
}

#[test]
fn resource_dispatch_refuses_complete_overbudget_batch_without_ack_or_partial_insert() {
    let fixture = Fixture::new(true);
    assert_eq!(fixture.stream(&fixture.epoch, vec![fold(1)]).unwrap(), WitnessChannelResponse::Ack);
    let held = {
        let state = fixture.service.lock().unwrap();
        let usage = state.streamed_witnesses.usage();
        state.streamed_witnesses.reserve_owned_capacity(
            usage.limit_bytes - usage.registered_capacity_bytes
        ).unwrap()
    };
    let before = fixture.service.lock().unwrap().streamed_witnesses.usage();
    let error = fixture.stream(&fixture.other, vec![fold(2), fold(3)]).unwrap_err();
    assert!(error.is("WITNESS_CAPACITY_FULL"));
    assert_eq!(fixture.service.lock().unwrap().streamed_witnesses.usage(), before);
    drop(held);
    assert_eq!(fixture.slots(&fixture.epoch), vec![1]);
    assert!(fixture.slots(&fixture.other).is_empty());
    // The real authenticated listener serializes Ack only after successful
    // dispatch; this fixture exercises dispatch and makes no kernel-UID703 claim.
}

#[test]
fn resource_dispatch_supplies_committed_floor_and_rejects_mixed_stale_batch() {
    let fixture = Fixture::new(true);
    fixture.stream(&fixture.epoch, vec![fold(3)]).unwrap();
    fixture.service.lock().unwrap().proven.insert(fixture.epoch.clone(), 1);
    let before = fixture.service.lock().unwrap().streamed_witnesses.usage();
    assert!(fixture.stream(&fixture.epoch, vec![fold(1), fold(4)]).unwrap_err().is("WITNESS_ALREADY_PROVEN"));
    assert_eq!(fixture.service.lock().unwrap().streamed_witnesses.usage(), before);
    assert_eq!(fixture.slots(&fixture.epoch), vec![3]);
    assert_eq!(fixture.service.lock().unwrap().proven.get(&fixture.epoch), Some(&1));
}

#[test]
fn resource_derived_snapshot_lease_survives_real_wipe_dispatch_until_data_owner_drops() {
    let fixture = Fixture::new(true);
    fixture.stream(&fixture.epoch, vec![fold(1)]).unwrap();
    let derived = fixture.service.derive_chunks(&fixture.request()).unwrap();
    assert!(matches!(&derived.chunks[0].0[0], Derived::Fold { seq:1, scrubbed, .. }
        if scrubbed == b"[REDACTED_EMAIL]"));
    fixture.service.handle(&PeerCredentials::local(0, 0), ZkRequest::Wipe).unwrap();
    let usage = fixture.service.lock().unwrap().streamed_witnesses.usage();
    assert_eq!(usage.retained_entries, 0);
    assert_eq!(usage.retained_capacity_bytes, 0);
    assert!(usage.registered_capacity_bytes > 0);
    // The allocation remains active by design. This does not claim that wipe
    // erased an active clone or that its proof could pass the release fence.
    drop(derived);
    assert_eq!(fixture.service.lock().unwrap().streamed_witnesses.usage().registered_capacity_bytes, 0);
}

#[test]
fn resource_actual_acknowledged_proof_retires_exact_range_preserving_unproved_witnesses() {
    let fixture = Fixture::new(true);
    fixture.stream(&fixture.epoch, vec![fold(1), fold(2)]).unwrap();
    fixture.stream(&fixture.other, vec![fold(3)]).unwrap();
    let (response, _) = fixture.service.prove(&fixture.request()).unwrap();
    assert!(matches!(response, ZkResponse::Proven { relayed:true, .. }));
    assert_eq!(fixture.received.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.slots(&fixture.epoch), vec![2]);
    assert_eq!(fixture.slots(&fixture.other), vec![3]);
    let state = fixture.service.lock().unwrap();
    assert_eq!(state.proven.get(&fixture.epoch), Some(&1));
    let usage = state.streamed_witnesses.usage();
    assert_eq!(usage.retained_entries, 2);
    assert_eq!(usage.registered_capacity_bytes, usage.retained_capacity_bytes);
    assert!(!fixture.service.relay_failed.load(Ordering::SeqCst));
    assert!(!fixture.service.relay_debt_path.exists());
}

#[test]
fn resource_actual_lost_ack_keeps_inputs_and_progress_while_latching_delivery_debt() {
    let fixture = Fixture::new(false);
    fixture.stream(&fixture.epoch, vec![fold(1), fold(2)]).unwrap();
    let before = fixture.service.lock().unwrap().streamed_witnesses.usage();
    assert!(fixture.service.prove(&fixture.request()).is_err());
    assert_eq!(fixture.received.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.slots(&fixture.epoch), vec![1, 2]);
    let state = fixture.service.lock().unwrap();
    assert_eq!(state.streamed_witnesses.usage(), before);
    assert!(!state.proven.contains_key(&fixture.epoch));
    assert!(state.anchors.is_empty());
    assert_eq!(state.j_state, genesis());
    assert!(fixture.service.relay_failed.load(Ordering::SeqCst));
    assert!(fixture.service.relay_debt_path.exists());
}


#[test]
fn progress_actual_gap_refuses_before_fetch_or_relay_and_contiguous_recovery_preserves_inputs() {
    let fixture = Fixture::with_slots(true, &[1, 2, 3, 4]);
    fixture.stream(&fixture.epoch, (1..=4).map(fold).collect()).unwrap();
    let prove = |s_start, s_end| fixture.service.handle(&PeerCredentials::local(0, 0),
        ZkRequest::ProveEpoch(Box::new(ProveEpochRequest {
            boot_epoch_id: fixture.epoch.clone(), s_start, s_end,
        })));
    assert!(matches!(prove(1, 1).unwrap(), ZkResponse::Proven { relayed:true, .. }));
    assert_eq!(fixture.received.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.fetched.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.prepared.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.slots(&fixture.epoch), vec![2, 3, 4]);
    let (j_state, anchors, proven, usage, seq) = {
        let state = fixture.service.lock().unwrap();
        assert_eq!(state.proven.get(&fixture.epoch), Some(&1));
        (state.j_state, state.anchors.clone(), state.proven.clone(),
            state.streamed_witnesses.usage(), state.seq.current())
    };
    let audit_path = fixture._directory.0.join("auditor.jsonl");
    let audit = std::fs::read(&audit_path).unwrap();
    // The first subcase is the existing-source red. An early panic means the
    // later subcase/recovery assertions are unreached, never inferred passed.
    for (start, end) in [(3, 3), (3, 4)] {
        match prove(start, end) {
            Err(error) => assert!(error.is("EPOCH_RANGE_GAP"), "{error}"),
            Ok(_) => panic!("actual skipped-range proof unexpectedly succeeded before covering slot 2"),
        }
        let state = fixture.service.lock().unwrap();
        assert_eq!(state.j_state, j_state);
        assert_eq!(state.anchors, anchors);
        assert_eq!(state.proven, proven);
        assert_eq!(state.streamed_witnesses.usage(), usage);
        assert_eq!(state.seq.current(), seq);
        drop(state);
        assert_eq!(fixture.fetched.load(Ordering::SeqCst), 1, "gap must refuse before witness fetch");
        assert_eq!(fixture.prepared.load(Ordering::SeqCst), 1, "gap must refuse before relay preparation");
        assert_eq!(fixture.received.load(Ordering::SeqCst), 1, "no skipped-range frame may transfer");
        assert_eq!(fixture.slots(&fixture.epoch), vec![2, 3, 4]);
        assert_eq!(std::fs::read(&audit_path).unwrap(), audit, "no gap success journal event");
        assert!(!fixture.service.relay_failed.load(Ordering::SeqCst));
        assert!(!fixture.service.relay_debt_path.exists());
        assert!(!fixture.service.fence_debt_path.exists());
    }
    // Previously refused gaps must not poison supported contiguous progress.
    assert!(matches!(prove(2, 4).unwrap(), ZkResponse::Proven { relayed:true, .. }));
    assert_eq!(fixture.received.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.fetched.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.prepared.load(Ordering::SeqCst), 2);
    assert!(fixture.slots(&fixture.epoch).is_empty());
    assert_eq!(fixture.service.lock().unwrap().proven.get(&fixture.epoch), Some(&4));
    assert!(!fixture.service.relay_debt_path.exists());
}

#[test]
fn progress_actual_first_nonzero_range_overlap_and_next_range_keep_existing_contract() {
    let fixture = Fixture::with_slots(true, &[7, 8, 9]);
    fixture.stream(&fixture.epoch, (7..=9).map(fold).collect()).unwrap();
    let prove = |s_start, s_end| fixture.service.handle(&PeerCredentials::local(0, 0),
        ZkRequest::ProveEpoch(Box::new(ProveEpochRequest {
            boot_epoch_id: fixture.epoch.clone(), s_start, s_end,
        })));
    // BootEpoch has no authenticated initial-slot field. This bounded repair
    // preserves first-range policy; it must not silently invent start 0 or 1.
    assert!(matches!(prove(7, 7).unwrap(), ZkResponse::Proven { relayed:true, .. }));
    assert_eq!(fixture.service.lock().unwrap().proven.get(&fixture.epoch), Some(&7));
    let (j_state, anchors, usage, seq) = {
        let state = fixture.service.lock().unwrap();
        (state.j_state, state.anchors.clone(), state.streamed_witnesses.usage(), state.seq.current())
    };
    match prove(7, 8) {
        Err(error) => assert!(error.is("EPOCH_ALREADY_PROVEN"), "{error}"),
        Ok(_) => panic!("overlapping proof unexpectedly succeeded"),
    }
    let state = fixture.service.lock().unwrap();
    assert_eq!(state.j_state, j_state);
    assert_eq!(state.anchors, anchors);
    assert_eq!(state.proven.get(&fixture.epoch), Some(&7));
    assert_eq!(state.streamed_witnesses.usage(), usage);
    assert_eq!(state.seq.current(), seq);
    drop(state);
    assert_eq!(fixture.received.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.fetched.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.prepared.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.slots(&fixture.epoch), vec![8, 9]);
    assert!(matches!(prove(8, 9).unwrap(), ZkResponse::Proven { relayed:true, .. }));
    assert_eq!(fixture.received.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.fetched.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.prepared.load(Ordering::SeqCst), 2);
    assert!(fixture.slots(&fixture.epoch).is_empty());
    assert_eq!(fixture.service.lock().unwrap().proven.get(&fixture.epoch), Some(&9));
    assert!(!fixture.service.relay_failed.load(Ordering::SeqCst));
    assert!(!fixture.service.relay_debt_path.exists());
}
