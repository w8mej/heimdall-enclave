//! Acceptance tests for GAP-26: outbox drainer, ledger gateway, and AC/battery gating.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use enclave_core::audit::tombstone_message;
use enclave_core::poseidon2::hash_bytes;
use enclave_swarm_syncd::outbox::{
    measure_outbox_disk, DrainStatus, HostConditions, OutboxDrainer, OutboxTransport,
    TcpOutboxTransport,
};
use enclave_zk_auditor::relation::{prove_rollup, EpochPublic, SlotWitness};
use enclave_zk_auditor::tombstone::{Tombstone, TombstoneKeys};
use enclave_zk_auditor::zk::manifest::VkManifestV1;
use ledger_gateway::{create_ohttp_rollup_request, serve_tcp, LedgerGateway, LEDGER_AUTHORITY};

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "enclave-outbox-{tag}-{}-{}",
        std::process::id(),
        enclave_core::rng::u64()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

struct Signers {
    a: SigningKey,
    b: SigningKey,
}

impl Signers {
    fn new() -> Self {
        Self {
            a: SigningKey::generate(&mut rand_core::OsRng),
            b: SigningKey::generate(&mut rand_core::OsRng),
        }
    }
    fn keys(&self) -> TombstoneKeys {
        TombstoneKeys {
            k703: self.a.verifying_key(),
            k704: self.b.verifying_key(),
        }
    }
    fn tomb(&self, slot: u64, epoch: &str) -> Tombstone {
        let m = tombstone_message(slot, epoch);
        Tombstone {
            slot,
            boot_epoch_id: epoch.into(),
            sig_703: self.a.sign(&m).to_bytes().to_vec(),
            sig_704: self.b.sign(&m).to_bytes().to_vec(),
        }
    }
}

fn generate_valid_l2_frame() -> Vec<u8> {
    let s = Signers::new();
    let epoch = enclave_core::seq::new_boot_epoch_id();
    let public = EpochPublic {
        profile: 2,
        policy_blake3: [7; 32],
        tuf_snapshot_root: [8; 32],
        j_prev: hash_bytes(b"genesis", b""),
    };
    let slots = vec![
        SlotWitness::Fold {
            seq: 1,
            scrubbed: b"{\"status\":\"ok\"}".to_vec(),
            qif_delta_mb: 10,
        },
        SlotWitness::Tombstone(s.tomb(2, &epoch)),
    ];
    let lines = vec![b"{\"line\":1}".to_vec(), b"{\"line\":2}".to_vec()];
    prove_rollup(
        &public,
        &[1; 32],
        "acct:corporate",
        &slots,
        &lines,
        &s.keys(),
        None,
        Some(vec!["3045".into()]),
        false,
    )
    .expect("prove_rollup must succeed")
}

#[test]
fn test_end_to_end_drain_to_local_gateway() {
    let outbox_dir = tmpdir("e2e-drain");
    let manifest = VkManifestV1::production_hiding();
    let (gw, key_config) = LedgerGateway::new_accounting_fixture(1, manifest);
    let gw = Arc::new(gw);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let local_addr = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));

    let gw_clone = gw.clone();
    let stop_clone = stop.clone();
    let server_handle = std::thread::spawn(move || {
        serve_tcp(listener, gw_clone, stop_clone).unwrap();
    });

    // 1. Generate valid frame and encapsulate in OHTTP
    let frame_bytes = generate_valid_l2_frame();
    let enc_req = create_ohttp_rollup_request(&key_config, &frame_bytes).unwrap();

    // 2. Queue into outbox directory
    let frame_path = outbox_dir.join("00000000000000000001.ohttp");
    std::fs::write(&frame_path, &enc_req).unwrap();

    let (disk_before, files_before) = measure_outbox_disk(&outbox_dir).unwrap();
    assert_eq!(files_before.len(), 1);
    assert_eq!(disk_before, enc_req.len() as u64);

    // 3. Create drainer with TCP transport
    let transport = Arc::new(TcpOutboxTransport::new(local_addr, LEDGER_AUTHORITY));
    let drainer = OutboxDrainer::new(&outbox_dir, transport);

    let cond = HostConditions {
        ac_power: true,
        low_power: false,
        ..Default::default()
    };

    let report = drainer.drain_once(&cond).unwrap();
    assert_eq!(report.status, DrainStatus::Success);
    assert_eq!(report.frames_drained, 1);
    assert_eq!(report.bytes_drained, enc_req.len() as u64);
    assert_eq!(report.frames_remaining, 0);

    // 4. Assert outbox file removed on disk
    let (disk_after, files_after) = measure_outbox_disk(&outbox_dir).unwrap();
    assert_eq!(files_after.len(), 0);
    assert_eq!(disk_after, 0);

    // 5. Assert frame is registered in ledger
    let verified = gw.verified_frames();
    assert_eq!(verified.len(), 1);
    assert_eq!(verified[0].profile, 2);
    assert_eq!(verified[0].s_start, 1);
    assert_eq!(verified[0].s_end, 2);
    assert!(!verified[0].heartbeat);

    stop.store(true, Ordering::Relaxed);
    let _ = std::net::TcpStream::connect(local_addr);
    let _ = server_handle.join();
}

#[test]
fn test_outbox_battery_gating() {
    let outbox_dir = tmpdir("battery-gating");
    let key_config = enclave_crypto::ohttp::gateway_keypair(1).0;
    let enc_req = create_ohttp_rollup_request(&key_config, b"dummy-frame").unwrap();
    std::fs::write(outbox_dir.join("00000000000000000001.ohttp"), &enc_req).unwrap();

    struct MockTransport;
    impl OutboxTransport for MockTransport {
        fn transmit(&self, _enc: &[u8]) -> enclave_core::error::EnclaveResult<()> {
            panic!("Transport should not be called when battery-gated");
        }
    }

    let drainer = OutboxDrainer::new(&outbox_dir, Arc::new(MockTransport));

    // Defers drain if on battery
    let cond_battery = HostConditions {
        ac_power: false,
        low_power: false,
        ..Default::default()
    };
    let report = drainer.drain_once(&cond_battery).unwrap();
    assert_eq!(report.status, DrainStatus::DeferredOnBattery);
    assert_eq!(report.frames_drained, 0);
    assert_eq!(report.frames_remaining, 1);

    // Defers drain if in Low Power Mode
    let cond_low_power = HostConditions {
        ac_power: true,
        low_power: true,
        ..Default::default()
    };
    let report2 = drainer.drain_once(&cond_low_power).unwrap();
    assert_eq!(report2.status, DrainStatus::DeferredOnBattery);
    assert_eq!(report2.frames_drained, 0);
    assert_eq!(report2.frames_remaining, 1);
}

#[test]
fn test_outbox_disk_bounding_and_fifo_retries() {
    let outbox_dir = tmpdir("disk-bound");

    struct FlakyTransport {
        fail: AtomicBool,
    }
    impl OutboxTransport for FlakyTransport {
        fn transmit(&self, _enc: &[u8]) -> enclave_core::error::EnclaveResult<()> {
            if self.fail.load(Ordering::Relaxed) {
                enclave_core::fail!(EIO, "GATEWAY_DOWN", "Transient connection refused");
            }
            Ok(())
        }
    }

    let transport = Arc::new(FlakyTransport {
        fail: AtomicBool::new(true),
    });

    // Small disk ceiling: 1000 bytes
    let drainer = OutboxDrainer::with_options(&outbox_dir, 1000, 3, transport.clone());

    // 1. Verify disk cap assertion
    assert!(drainer.assert_can_enqueue(800).is_ok());
    assert!(drainer.assert_can_enqueue(1200).is_err());

    // Write file 1 and file 2
    let f1 = outbox_dir.join("00000000000000000001.ohttp");
    let f2 = outbox_dir.join("00000000000000000002.ohttp");
    std::fs::write(&f1, [1u8; 300]).unwrap();
    std::fs::write(&f2, [2u8; 300]).unwrap();

    let cond = HostConditions {
        ac_power: true,
        low_power: false,
        ..Default::default()
    };

    // 2. When transport fails, drainer halts immediately and preserves FIFO order
    let report = drainer.drain_once(&cond).unwrap();
    assert_eq!(report.status, DrainStatus::NetworkError);
    assert_eq!(report.frames_drained, 0);
    assert_eq!(report.frames_remaining, 2);
    assert!(f1.exists());
    assert!(f2.exists());

    // 3. When transport recovers, both files drain in FIFO order
    transport.fail.store(false, Ordering::Relaxed);
    let report2 = drainer.drain_once(&cond).unwrap();
    assert_eq!(report2.status, DrainStatus::Success);
    assert_eq!(report2.frames_drained, 2);
    assert_eq!(report2.frames_remaining, 0);
    assert!(!f1.exists());
    assert!(!f2.exists());
}

#[test]
fn test_gateway_rejects_unpinned_vk() {
    let frame_bytes = generate_valid_l2_frame();
    // Tamper with manifest vk_digest
    let manifest = VkManifestV1 {
        vk_digest: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into(),
        ..Default::default()
    };

    let (gw, key_config) = LedgerGateway::new_accounting_fixture(1, manifest);
    let enc_req = create_ohttp_rollup_request(&key_config, &frame_bytes).unwrap();

    let res = gw.handle_ohttp_post(&enc_req);
    assert!(
        res.is_err(),
        "Gateway must reject frame with unpinned vk_digest"
    );
}
