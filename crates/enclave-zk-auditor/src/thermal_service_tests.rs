//! Actual DeferWitness ownership/refusal and authorized thermal teardown.
//! Finite registered queue assertions, not encrypted storage, physical erasure,
//! installed identity, producer FIFO or whole-process memory acceptance.

use super::*;
use enclave_core::quarantine_types::FaultKind;
use std::os::unix::fs::DirBuilderExt;

struct Directory(PathBuf);

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct NoPeers;

impl Peers for NoPeers {
    fn cosign(&self, _: DaemonId, _: u64, _: &str) -> EnclaveResult<(Vec<u8>, Vec<u8>)> {
        panic!("thermal dispatch must not request a tombstone")
    }

    fn prepare_relay(&self, _: &[u8]) -> EnclaveResult<PreparedCall> {
        panic!("thermal dispatch must not relay")
    }

    fn fetch_witness(&self, _: &str, _: u64, _: u64) -> EnclaveResult<(Vec<WitnessFold>, u64)> {
        panic!("thermal dispatch must not fetch witnesses")
    }

    fn boot_epoch(&self) -> EnclaveResult<enclave_core::seq::BootEpoch> {
        panic!("thermal dispatch must not fetch an epoch")
    }
}

struct Fixture {
    _directory: Directory,
    service: Arc<ZkService>,
}

impl Fixture {
    fn new(limit: usize) -> Self {
        let target = std::env::temp_dir();
        let directory = Directory(
            target
                .canonicalize()
                .unwrap()
                .join(format!("tq-{:x}", enclave_core::rng::u64())),
        );
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory.0)
            .unwrap();
        let config = ZkConfig::new(Profile::L2, directory.0.join("state"));
        let service = ZkService::start(config, Box::new(NoPeers)).unwrap();
        service.lock().unwrap().thermal = ThermalQueue::with_limit(limit);
        Self {
            _directory: directory,
            service,
        }
    }

    fn defer(&self, bytes: Vec<u8>) -> EnclaveResult<ZkResponse> {
        self.service.handle(
            &root(),
            ZkRequest::DeferWitness {
                witness: ByteBuf::from(bytes),
            },
        )
    }

    fn seed(&self) {
        assert!(matches!(
            self.defer(vec![b'A'; 17]).unwrap(),
            ZkResponse::Ok
        ));
        assert!(matches!(
            self.defer(vec![b'B'; 31]).unwrap(),
            ZkResponse::Ok
        ));
    }

    fn usage(&self) -> crate::thermal::ResourceUsage {
        self.service.lock().unwrap().thermal.resource_usage()
    }

    fn drain(&self) -> Vec<Vec<u8>> {
        let mut state = self.service.lock().unwrap();
        let mut output = Vec::new();
        while let Some(secret) = state.thermal.pop() {
            // Synthetic nonsecret test bytes, copied only to observe FIFO. This
            // is not a production consumer or an active-owner memory claim.
            output.push(secret.expose().to_vec());
        }
        output
    }

    fn exhaust_sequence(&self) {
        self.service.lock().unwrap().seq =
            RpcSequencer::new(enclave_core::seq::new_boot_epoch_id(), u64::MAX);
    }

    fn assert_freed(&self, limit: usize) {
        let usage = self.usage();
        assert_eq!(usage.entries, 0);
        assert_eq!(usage.payload_bytes, 0);
        assert_eq!(usage.payload_registered_capacity_bytes, 0);
        assert_eq!(
            usage.metadata_capacity_bytes, 0,
            "empty metadata must actually be freed"
        );
        assert_eq!(usage.registered_capacity_bytes, 0);
        assert_eq!(usage.limit_bytes, limit);
    }
}

fn root() -> PeerCredentials {
    PeerCredentials::local(0, 0)
}

fn unauthorized() -> PeerCredentials {
    let uid = if enclave_core::ipc::geteuid() == 703 {
        704
    } else {
        703
    };
    PeerCredentials::local(uid, 0)
}

fn fault(at_ms: u64) -> FaultReport {
    FaultReport {
        kind: FaultKind::HeapTag,
        fault_addr: 0x10000,
        at_ms,
    }
}

#[test]
fn thermal_service_exact_boundary_and_excess_refusal_preserve_fifo_and_sequence_semantics() {
    let fixture = Fixture::new(8192);
    assert!(matches!(
        fixture.defer(vec![b'A'; 17]).unwrap(),
        ZkResponse::Ok
    ));
    let first = fixture.usage();
    assert!(first.metadata_capacity_bytes > 0);
    let remaining = first.limit_bytes - first.registered_capacity_bytes;
    let mut second = Vec::with_capacity(remaining);
    second.push(b'B');
    assert_eq!(second.capacity(), remaining);
    assert!(matches!(fixture.defer(second).unwrap(), ZkResponse::Ok));
    let full = fixture.usage();
    assert_eq!(full.entries, 2);
    assert_eq!(full.payload_bytes, 18);
    assert_eq!(
        full.payload_registered_capacity_bytes,
        first.payload_registered_capacity_bytes + remaining
    );
    assert_eq!(full.metadata_capacity_bytes, first.metadata_capacity_bytes);
    assert_eq!(full.registered_capacity_bytes, full.limit_bytes);
    let seq_before = fixture.service.lock().unwrap().seq.current();
    assert!(fixture
        .defer(vec![b'C'])
        .unwrap_err()
        .is("THERMAL_QUEUE_FULL"));
    assert_eq!(fixture.usage(), full);
    // Preserve existing service behavior: an admitted dispatcher sequence can
    // advance even when queue admission refuses. No queue mutation follows.
    assert_eq!(
        fixture.service.lock().unwrap().seq.current(),
        seq_before + 1
    );
    assert_eq!(fixture.drain(), vec![vec![b'A'; 17], vec![b'B']]);
    let drained = fixture.usage();
    assert_eq!(drained.entries, 0);
    assert_eq!(drained.payload_bytes, 0);
    assert_eq!(drained.payload_registered_capacity_bytes, 0);
    assert_eq!(
        drained.metadata_capacity_bytes,
        full.metadata_capacity_bytes
    );
    assert_eq!(
        drained.registered_capacity_bytes,
        drained.metadata_capacity_bytes
    );
}

#[test]
fn thermal_service_empty_entries_consume_bounded_metadata_and_refusal_is_transactional() {
    let fixture = Fixture::new(2048);
    let limit = fixture.usage().limit_bytes;
    let mut refused = false;
    let mut accepted = 0;
    // Every admitted queue entry has nonzero metadata. This bound is derived
    // from the byte allowance, not a new production entry-count restriction.
    for _ in 0..=limit {
        let before = fixture.usage();
        match fixture.defer(Vec::new()) {
            Ok(ZkResponse::Ok) => {
                accepted += 1;
                let after = fixture.usage();
                assert_eq!(after.entries, before.entries + 1);
                assert_eq!(after.payload_bytes, 0);
                assert_eq!(after.payload_registered_capacity_bytes, 0);
                assert!(after.metadata_capacity_bytes > 0);
                assert_eq!(
                    after.registered_capacity_bytes,
                    after.metadata_capacity_bytes
                );
                assert!(after.registered_capacity_bytes <= limit);
            }
            Err(error) => {
                assert!(error.is("THERMAL_QUEUE_FULL"));
                assert_eq!(fixture.usage(), before);
                refused = true;
                break;
            }
            Ok(_) => panic!("unexpected thermal response"),
        }
    }
    assert!(accepted > 0);
    assert!(
        refused,
        "empty witnesses must not grow metadata without bound"
    );
}

#[test]
fn thermal_service_spare_capacity_refusal_preserves_existing_payload_and_metadata() {
    let fixture = Fixture::new(2048);
    fixture.seed();
    let before = fixture.usage();
    let mut rejected = Vec::with_capacity(4096);
    rejected.push(b'C');
    assert!(rejected.capacity() > before.limit_bytes);
    assert!(fixture
        .defer(rejected)
        .unwrap_err()
        .is("THERMAL_QUEUE_FULL"));
    assert_eq!(fixture.usage(), before);
    assert_eq!(fixture.drain(), vec![vec![b'A'; 17], vec![b'B'; 31]]);
}

#[test]
fn thermal_service_authorized_wipe_and_fault_free_metadata_and_allow_clear_state_refill() {
    for is_fault in [false, true] {
        let fixture = Fixture::new(8192);
        fixture.seed();
        fixture.defer(Vec::new()).unwrap();
        assert!(fixture.usage().metadata_capacity_bytes > 0);
        let request = if is_fault {
            ZkRequest::ReportFault(fault(1_000))
        } else {
            ZkRequest::Wipe
        };
        let response = fixture.service.handle(&root(), request).unwrap();
        if is_fault {
            assert!(matches!(response, ZkResponse::Fault(_)));
        } else {
            assert!(matches!(response, ZkResponse::Ok));
        }
        fixture.assert_freed(8192);
        // A first L2 integrity strike is not the two-strike latch. Neither it
        // nor ordinary Wipe permanently blocks otherwise supported intake.
        assert!(!fixture.service.lock().unwrap().quarantine.is_latched());
        assert!(matches!(fixture.defer(vec![b'D']).unwrap(), ZkResponse::Ok));
        assert_eq!(fixture.drain(), vec![vec![b'D']]);
    }
}

#[test]
fn thermal_service_exhausted_sequence_teardown_purges_before_error_for_wipe_and_fault() {
    for is_fault in [false, true] {
        let fixture = Fixture::new(8192);
        fixture.seed();
        assert!(fixture.usage().metadata_capacity_bytes > 0);
        fixture.exhaust_sequence();
        let request = if is_fault {
            ZkRequest::ReportFault(fault(1_000))
        } else {
            ZkRequest::Wipe
        };
        let error = fixture.service.handle(&root(), request).unwrap_err();
        assert!(error.is("RPC_SEQ_EXHAUSTED"));
        fixture.assert_freed(8192);
        assert!(fixture.service.relay_failed.load(Ordering::SeqCst));
        assert!(fixture.service.fence_debt_path.exists());
        assert_eq!(fixture.service.fence_pending.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn thermal_service_defer_sequence_refusal_preserves_fifo_without_establishing_teardown() {
    let fixture = Fixture::new(8192);
    fixture.seed();
    let before = fixture.usage();
    let generation = fixture.service.release_generation.load(Ordering::SeqCst);
    fixture.exhaust_sequence();
    assert!(fixture
        .defer(vec![b'C'])
        .unwrap_err()
        .is("RPC_SEQ_EXHAUSTED"));
    assert_eq!(fixture.usage(), before);
    assert_eq!(
        fixture.service.release_generation.load(Ordering::SeqCst),
        generation
    );
    assert!(!fixture.service.fence_debt_path.exists());
    assert_eq!(fixture.drain(), vec![vec![b'A'; 17], vec![b'B'; 31]]);
    // Candidate cleanup is verified by source ownership review, not a read of
    // a freed buffer or replacement of the process global allocator.
}

#[test]
fn thermal_service_real_quarantine_refuses_guarded_candidate_after_dispatch_sequence() {
    let fixture = Fixture::new(8192);
    fixture.seed();
    fixture
        .service
        .handle(&root(), ZkRequest::ReportFault(fault(1_000)))
        .unwrap();
    fixture.assert_freed(8192);
    fixture.seed();
    fixture
        .service
        .handle(&root(), ZkRequest::ReportFault(fault(2_000)))
        .unwrap();
    assert!(fixture.service.lock().unwrap().quarantine.is_latched());
    fixture.assert_freed(8192);
    let before = fixture.usage();
    let seq_before = fixture.service.lock().unwrap().seq.current();
    assert!(fixture
        .defer(vec![b'C'])
        .unwrap_err()
        .is("HARDWARE_INTEGRITY_QUARANTINE"));
    assert_eq!(fixture.usage(), before);
    assert_eq!(
        fixture.service.lock().unwrap().seq.current(),
        seq_before + 1
    );
}

#[test]
fn thermal_service_unauthorized_wipe_and_fault_preserve_fifo_allocations_and_generation() {
    let fixture = Fixture::new(8192);
    fixture.seed();
    let before = fixture.usage();
    let generation = fixture.service.release_generation.load(Ordering::SeqCst);
    let seq_before = fixture.service.lock().unwrap().seq.current();
    assert!(fixture
        .service
        .handle(&unauthorized(), ZkRequest::Wipe)
        .unwrap_err()
        .is("WIPE_PEER_REJECTED"));
    assert_eq!(fixture.usage(), before);
    assert!(fixture
        .service
        .handle(&unauthorized(), ZkRequest::ReportFault(fault(1_000)))
        .unwrap_err()
        .is("FAULT_REPORTER_REJECTED"));
    assert_eq!(fixture.usage(), before);
    assert_eq!(
        fixture.service.release_generation.load(Ordering::SeqCst),
        generation
    );
    assert_eq!(fixture.service.lock().unwrap().seq.current(), seq_before);
    assert_eq!(fixture.drain(), vec![vec![b'A'; 17], vec![b'B'; 31]]);
}

#[test]
fn thermal_service_status_reports_only_defined_usage_and_wipe_resets_all_but_limit() {
    const SENTINEL: &str = "THERMAL_SYNTHETIC_PRIVATE_SENTINEL_97531";
    let fixture = Fixture::new(8192);
    let mut witness = Vec::with_capacity(256);
    witness.extend_from_slice(SENTINEL.as_bytes());
    assert!(matches!(fixture.defer(witness).unwrap(), ZkResponse::Ok));
    let assert_status = |expected: crate::thermal::ResourceUsage| {
        let response = fixture.service.handle(&root(), ZkRequest::Status).unwrap();
        let ZkResponse::Status(status) = response else {
            panic!("missing actual daemon Status response")
        };
        assert!(
            !status.state.contains(SENTINEL),
            "status must not expose queued witness text"
        );
        let fields: Vec<_> = status
            .state
            .split_whitespace()
            .filter_map(|field| field.split_once('='))
            .collect();
        for (name, value) in [
            ("thermal_entries", expected.entries),
            ("thermal_payload_bytes", expected.payload_bytes),
            (
                "thermal_payload_registered_capacity",
                expected.payload_registered_capacity_bytes,
            ),
            (
                "thermal_metadata_capacity",
                expected.metadata_capacity_bytes,
            ),
            (
                "thermal_registered_capacity",
                expected.registered_capacity_bytes,
            ),
            ("thermal_capacity_limit", expected.limit_bytes),
        ] {
            let matching: Vec<_> = fields.iter().filter(|(key, _)| *key == name).collect();
            assert_eq!(
                matching.len(),
                1,
                "usage gauge must appear exactly once: {name}"
            );
            assert_eq!(
                matching[0].1.parse::<usize>().unwrap(),
                value,
                "incorrect usage gauge: {name}"
            );
        }
    };
    let queued = fixture.usage();
    assert_eq!(queued.entries, 1);
    assert_eq!(queued.payload_bytes, SENTINEL.len());
    assert_eq!(queued.payload_registered_capacity_bytes, 256);
    assert!(queued.metadata_capacity_bytes > 0);
    assert_status(queued);
    assert!(matches!(
        fixture.service.handle(&root(), ZkRequest::Wipe).unwrap(),
        ZkResponse::Ok
    ));
    fixture.assert_freed(8192);
    assert_status(fixture.usage());
}
