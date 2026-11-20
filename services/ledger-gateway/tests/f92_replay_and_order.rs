//! DEFECT-F-92 end to end: real STARK-proved frames through OHTTP into the
//! gateway. Replays (including a fresh OHTTP encapsulation of captured frame
//! bytes) are not recorded twice, out-of-order and overlapping frames are
//! refused, chains of different hosts interleave, and the ledger survives a
//! restart when given a journal.

use ed25519_dalek::SigningKey;
use enclave_core::poseidon2::hash_bytes;
use enclave_crypto::ohttp::gateway_keypair;
use enclave_zk_auditor::relation::{prove_rollup_series, EpochChunk, EpochPublic, SlotWitness};
use enclave_zk_auditor::tombstone::TombstoneKeys;
use enclave_zk_auditor::zk::manifest::VkManifestV1;
use ledger_gateway::{create_ohttp_rollup_request, Ledger, LedgerGateway};

fn issuer()->&'static enclave_crypto::pqc::HybridSigningKey {
    static KEY:std::sync::OnceLock<enclave_crypto::pqc::HybridSigningKey>=std::sync::OnceLock::new();
    KEY.get_or_init(enclave_crypto::pqc::HybridSigningKey::generate)
}
fn trust()->enclave_zk_auditor::receiver_trust::ReceiverTrust {
    enclave_zk_auditor::receiver_trust::ReceiverTrust::l2_anchor(issuer().verifying_key()).unwrap()
}

fn keys() -> TombstoneKeys {
    let mut r = rand_core::OsRng;
    TombstoneKeys {
        k703: SigningKey::generate(&mut r).verifying_key(),
        k704: SigningKey::generate(&mut r).verifying_key(),
    }
}

fn chunk(s_start: u64, n: u64) -> EpochChunk {
    EpochChunk {
        slots: (0..n)
            .map(|i| SlotWitness::Fold {
                seq: s_start + i,
                scrubbed: b"[REDACTED]".to_vec(),
                qif_delta_mb: 5,
            })
            .collect(),
        journal_lines: (0..n)
            .map(|i| format!("{{\"line\":{}}}", s_start + i).into_bytes())
            .collect(),
    }
}

/// A three-frame series for one enclave (`id`) in one epoch.
fn series(id: u8) -> Vec<Vec<u8>> {
    let public = EpochPublic {
        profile: 2,
        policy_blake3: [1; 32],
        tuf_snapshot_root: [2; 32],
        j_prev: hash_bytes(b"depot-Genesis-v1", b""),
    };
    prove_rollup_series(
        &public,
        &[id; 32],
        "acct:corp",
        &[chunk(1, 2), chunk(3, 2), chunk(5, 2)],
        &keys(),
        None,
        Some(vec!["3045".into()]),
        false,
    )
    .expect("prove series").into_iter().map(|bytes|{
        let frame=enclave_zk_auditor::rollup::ComplianceRollupProofV1::decode(&bytes).unwrap();
        let statement=frame.statement().unwrap();
        enclave_zk_auditor::rollup::ComplianceRollupProofV1::build(&statement,frame.proof,None,false,
            Some(vec![enclave_zk_auditor::rollup::ComplianceRollupProofV1::sign_l2_hybrid_anchor(&statement,issuer())])).unwrap()
    }).collect()
}

fn gw() -> (LedgerGateway, enclave_crypto::ohttp::KeyConfig) {
    let (gateway,key)=LedgerGateway::new(1, VkManifestV1::production_hiding());
    (gateway.with_receiver_trust(trust()),key)
}

fn post(
    gw: &LedgerGateway,
    kc: &enclave_crypto::ohttp::KeyConfig,
    frame: &[u8],
) -> Result<(bool, bool), String> {
    let req = create_ohttp_rollup_request(kc, frame).expect("encapsulate");
    gw.handle_ohttp_post(&req)
        .map(|r| (r.accepted, r.duplicate))
        .map_err(|e| e.reason)
}

#[test]
fn replay_overlap_reorder_and_interleave() {
    let a = series(7);
    let b = series(8);
    let (g, kc) = gw();

    // Out of order: frame 2 cannot open the chain.
    assert_eq!(post(&g, &kc, &a[1]), Err("QIF_INITIAL_NONZERO".into()));
    assert_eq!(post(&g, &kc, &a[0]), Ok((true, false)));
    // Skipping frame 2 is a gap.
    assert_eq!(post(&g, &kc, &a[2]), Err("SLOT_GAP".into()));
    // Another host's chain interleaves freely.
    assert_eq!(post(&g, &kc, &b[0]), Ok((true, false)));
    assert_eq!(post(&g, &kc, &a[1]), Ok((true, false)));
    assert_eq!(post(&g, &kc, &b[1]), Ok((true, false)));
    // Replays of captured frames, each in a fresh OHTTP encapsulation.
    for f in [&a[0], &a[1], &b[0]] {
        assert_eq!(
            post(&g, &kc, f),
            Ok((false, true)),
            "replay must not be recorded"
        );
    }
    assert_eq!(post(&g, &kc, &a[2]), Ok((true, false)));
    assert_eq!(g.verified_frames().len(), 5);
    let a_frames: Vec<(u64, u64)> = g
        .verified_frames()
        .iter()
        .filter(|f| f.nullifier_e == g.verified_frames()[0].nullifier_e)
        .map(|f| (f.s_start, f.s_end))
        .collect();
    assert_eq!(a_frames, vec![(1, 2), (3, 4), (5, 6)]);
}

#[test]
fn ledger_journal_survives_gateway_restart() {
    let a = series(9);
    let dir = std::env::temp_dir().join(format!("ledger-f92-gw-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let path = dir.join("ledger.jsonl");
    let (kc, sk) = gateway_keypair(1);
    {
        let g = LedgerGateway::with_ledger(
            kc.clone(),
            sk.clone(),
            VkManifestV1::production_hiding(),
            Ledger::open(&path, 100).expect("open"),
        ).with_receiver_trust(trust());
        assert_eq!(post(&g, &kc, &a[0]), Ok((true, false)));
    }
    let g = LedgerGateway::with_ledger(
        kc.clone(),
        sk,
        VkManifestV1::production_hiding(),
        Ledger::open(&path, 100).expect("reopen"),
    ).with_receiver_trust(trust());
    assert_eq!(g.verified_frames().len(), 1);
    assert_eq!(
        post(&g, &kc, &a[0]),
        Ok((false, true)),
        "replay after restart"
    );
    assert_eq!(post(&g, &kc, &a[2]), Err("SLOT_GAP".into()));
    assert_eq!(post(&g, &kc, &a[1]), Ok((true, false)));
}

/// Exclusive, private resources for adversarial gateway regressions. Never
/// remove a deterministic path that another process could already own.
struct F92PrivateDirectory(std::path::PathBuf);
impl F92PrivateDirectory {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(format!("f92-security-{}", enclave_core::rng::u64()));
        std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for F92PrivateDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn f92_equivalent_valid_cbor_cannot_bypass_overlap_or_change_durable_tip() {
    use enclave_zk_auditor::rollup::ComplianceRollupProofV1;
    let frames = series(31);
    // Reverse the outer map's field order: same verified statement/proof,
    // different raw bytes and digest. This cannot pass by digest replay alone.
    let mut value: ciborium::Value = ciborium::de::from_reader(frames[0].as_slice()).unwrap();
    let ciborium::Value::Map(fields) = &mut value else { panic!("frame must be a map") };
    fields.reverse();
    let mut alternate = Vec::new();
    ciborium::ser::into_writer(&value, &mut alternate).unwrap();
    assert_ne!(blake3::hash(&frames[0]), blake3::hash(&alternate));
    let manifest = VkManifestV1::production_hiding();
    let pins = [manifest.vk_digest_bytes().unwrap()];
    let original = ComplianceRollupProofV1::verify(&frames[0], &pins).unwrap();
    let equivalent = ComplianceRollupProofV1::verify(&alternate, &pins).unwrap();
    assert_eq!(original.s_start, equivalent.s_start);
    assert_eq!(original.s_end, equivalent.s_end);
    assert_eq!(original.public_inputs.nullifier_e, equivalent.public_inputs.nullifier_e);
    assert_eq!(original.public_inputs.J_curr, equivalent.public_inputs.J_curr);
    assert_eq!(original.public_inputs.used_out, equivalent.public_inputs.used_out);

    let directory = F92PrivateDirectory::new();
    let path = directory.0.join("frames.jsonl");
    let (key, secret) = gateway_keypair(1);
    let gateway = LedgerGateway::with_ledger(
        key.clone(), secret.clone(), manifest.clone(), Ledger::open(&path, 10).unwrap(),
    ).with_receiver_trust(trust());
    assert_eq!(post(&gateway, &key, &frames[0]), Ok((true, false)));
    let journal = std::fs::read(&path).unwrap();
    assert_eq!(post(&gateway, &key, &alternate), Err("SLOT_OVERLAP".into()));
    assert_eq!(post(&gateway, &key, &frames[2]), Err("SLOT_GAP".into()));
    assert_eq!(gateway.verified_frames().len(), 1);
    assert_eq!(std::fs::read(&path).unwrap(), journal, "refused frames must not append");
    drop(gateway);

    let restarted = LedgerGateway::with_ledger(
        key.clone(), secret, manifest, Ledger::open(&path, 10).unwrap(),
    ).with_receiver_trust(trust());
    assert_eq!(restarted.verified_frames().len(), 1);
    assert_eq!(post(&restarted, &key, &alternate), Err("SLOT_OVERLAP".into()));
    assert_eq!(post(&restarted, &key, &frames[0]), Ok((false, true)));
    assert_eq!(post(&restarted, &key, &frames[1]), Ok((true, false)));
    assert_eq!(post(&restarted, &key, &frames[2]), Ok((true, false)));
    assert_eq!(restarted.verified_frames().len(), 3);
    drop(restarted);
    assert_eq!(Ledger::open(&path, 10).unwrap().frames().len(), 3);
}

#[test]
fn f92_concurrent_captured_ohttp_replays_admit_once_and_recover_at_capacity() {
    use std::sync::{Arc, Barrier};
    let frames = series(32);
    let directory = F92PrivateDirectory::new();
    let path = directory.0.join("frames.jsonl");
    let (key, secret) = gateway_keypair(1);
    let gateway = Arc::new(LedgerGateway::with_ledger(
        key.clone(), secret.clone(), VkManifestV1::production_hiding(), Ledger::open(&path, 2).unwrap(),
    ).with_receiver_trust(trust()));
    let captured = create_ohttp_rollup_request(&key, &frames[0]).unwrap();
    let barrier = Arc::new(Barrier::new(9));
    let mut workers = Vec::new();
    for _ in 0..8 {
        let (gateway, barrier, request) = (gateway.clone(), barrier.clone(), captured.clone());
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            gateway.handle_ohttp_post(&request).unwrap()
        }));
    }
    barrier.wait();
    let responses: Vec<_> = workers.into_iter().map(|worker| worker.join().unwrap()).collect();
    assert_eq!(responses.iter().filter(|r| r.accepted).count(), 1);
    assert_eq!(responses.iter().filter(|r| r.duplicate).count(), 7);
    assert!(responses.iter().all(|r| r.accepted != r.duplicate));
    assert_eq!(gateway.verified_frames().len(), 1);
    assert_eq!(gateway.verified_frames()[0].frame_digest, *blake3::hash(&frames[0]).as_bytes());
    drop(gateway);

    let restarted = LedgerGateway::with_ledger(
        key.clone(), secret, VkManifestV1::production_hiding(), Ledger::open(&path, 2).unwrap(),
    ).with_receiver_trust(trust());
    assert_eq!(restarted.verified_frames().len(), 1);
    assert_eq!(post(&restarted, &key, &frames[0]), Ok((false, true)));
    assert_eq!(post(&restarted, &key, &frames[2]), Err("SLOT_GAP".into()));
    assert_eq!(post(&restarted, &key, &frames[1]), Ok((true, false)));
    let full_journal = std::fs::read(&path).unwrap();
    assert_eq!(post(&restarted, &key, &frames[2]), Err("LEDGER_FULL".into()));
    // Full capacity must not strand the honest lost-ack retry path.
    assert_eq!(post(&restarted, &key, &frames[0]), Ok((false, true)));
    assert_eq!(post(&restarted, &key, &frames[1]), Ok((false, true)));
    assert_eq!(std::fs::read(&path).unwrap(), full_journal);
    drop(restarted);
    let ledger = Ledger::open(&path, 2).unwrap();
    assert_eq!(ledger.frames().len(), 2);
    assert_eq!(ledger.frames()[1].s_end, 4);
}
