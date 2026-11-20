//! Acceptance tests for GAP-24 target (Prompt 4A, FS-705 Rev 1.4):
//! Single constant-size proof per epoch up to 4,096 slots under the revised
//! 320 KiB frame budget (`MAX_PROOF_BYTES = 327_680`, `L3_FRAME_BYTES = 327_680`),
//! preserving 84 FRI queries (proven Johnson bound).

use ed25519_dalek::{Signer, SigningKey};
use enclave_core::audit::tombstone_message;
use enclave_core::poseidon2::hash_bytes;
use enclave_zk_auditor::cohort::{leaf, CohortTree};
use enclave_zk_auditor::relation::{
    prove_rollup, prove_rollup_series, EpochChunk, EpochPublic, HardwareWitness, SlotWitness,
};
use enclave_zk_auditor::rollup::{ComplianceRollupProofV1, L3_FRAME_BYTES};
use enclave_zk_auditor::tombstone::{Tombstone, TombstoneKeys};
use enclave_zk_auditor::zk::engine::{hiding_vk_digest as vk_digest, MAX_PROOF_BYTES};

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

fn cohort(n: usize, member: usize) -> HardwareWitness {
    let keys: Vec<(Vec<u8>, Vec<u8>)> = (0..n)
        .map(|i| {
            (
                format!("cohort-sep-{i}").into_bytes(),
                format!("cohort-yk-{i}").into_bytes(),
            )
        })
        .collect();
    let tree = CohortTree::build(keys.iter().map(|(a, b)| leaf(a, b)).collect()).unwrap();
    HardwareWitness {
        pk_sep: keys[member].0.clone(),
        pk_yk: keys[member].1.clone(),
        path: tree.path(member).unwrap(),
        root: tree.root(),
        cohort_size: tree.size(),
    }
}

#[test]
fn test_single_proof_epoch_roundtrip_4096_slots() {
    let s = Signers::new();
    let epoch = enclave_core::seq::new_boot_epoch_id();
    const NUM_SLOTS: u64 = 4096;

    let slots: Vec<SlotWitness> = (1..=NUM_SLOTS)
        .map(|seq| {
            if seq % 16 == 0 {
                SlotWitness::Tombstone(s.tomb(seq, &epoch))
            } else {
                SlotWitness::Fold {
                    seq,
                    scrubbed: b"{\"audit\":\"normal\"}".to_vec(),
                    qif_delta_mb: 2,
                }
            }
        })
        .collect();

    let journal_lines: Vec<Vec<u8>> = (0..NUM_SLOTS)
        .map(|i| format!("{{\"line\":{i}}}").into_bytes())
        .collect();

    let public = EpochPublic {
        profile: 2,
        policy_blake3: [0x11; 32],
        tuf_snapshot_root: [0x22; 32],
        j_prev: hash_bytes(b"genesis", b""),
    };

    let vk = vk_digest();

    // 1. Prove single epoch of 4,096 slots
    let t0 = std::time::Instant::now();
    let frame_bytes = prove_rollup(
        &public,
        &[0x33; 32],
        "corp:epoch-audit",
        &slots,
        &journal_lines,
        &s.keys(),
        None,
        Some(vec!["3045".into()]),
        false,
    )
    .expect("prove_rollup must succeed for full 4,096-slot epoch");
    let prove_time = t0.elapsed();

    println!(
        "4,096 slots single proof: frame size = {} bytes, prove time = {:?}",
        frame_bytes.len(),
        prove_time
    );

    // 2. Decode and check size against revised budget
    let decoded = ComplianceRollupProofV1::decode(&frame_bytes).unwrap();
    assert_eq!(decoded.s_start, 1);
    assert_eq!(decoded.s_end, NUM_SLOTS);
    assert!(
        decoded.proof_bytes_len <= MAX_PROOF_BYTES as u64,
        "proof_bytes_len {} must be <= MAX_PROOF_BYTES {}",
        decoded.proof_bytes_len,
        MAX_PROOF_BYTES
    );
    assert!(
        decoded.proof_bytes_len <= 327_680,
        "proof_bytes_len {} must fit in 320 KiB",
        decoded.proof_bytes_len
    );

    // 3. Verify single frame against verifier key
    let t1 = std::time::Instant::now();
    let verified = ComplianceRollupProofV1::verify(&frame_bytes, &[vk]).unwrap();
    let verify_time = t1.elapsed();

    println!("4,096 slots verify time = {:?}", verify_time);
    assert_eq!(verified.profile, 2);
    assert_eq!(verified.s_start, 1);
    assert_eq!(verified.s_end, NUM_SLOTS);
    assert_eq!(verified.public_inputs.used_in, 0);
    assert!(verified.public_inputs.used_out <= 12_000);
}

#[test]
fn test_l3_single_proof_padded_to_320_kib() {
    let s = Signers::new();
    let _epoch = enclave_core::seq::new_boot_epoch_id();
    let hw = cohort(32, 5);

    let slots: Vec<SlotWitness> = (1..=64)
        .map(|seq| SlotWitness::Fold {
            seq,
            scrubbed: b"{\"cover\":false}".to_vec(),
            qif_delta_mb: 10,
        })
        .collect();

    let journal_lines: Vec<Vec<u8>> = (0..64)
        .map(|i| format!("{{\"l3_line\":{i}}}").into_bytes())
        .collect();

    let public = EpochPublic {
        profile: 3,
        policy_blake3: [0x55; 32],
        tuf_snapshot_root: [0x66; 32],
        j_prev: hash_bytes(b"genesis", b""),
    };

    let frame_bytes = prove_rollup(
        &public,
        &[0x77; 32],
        "corp:l3-single",
        &slots,
        &journal_lines,
        &s.keys(),
        Some(&hw),
        None,
        false,
    )
    .unwrap();

    assert_eq!(frame_bytes.len(), L3_FRAME_BYTES);
    assert_eq!(frame_bytes.len(), 327_680);

    let verified = ComplianceRollupProofV1::verify(&frame_bytes, &[vk_digest()]).unwrap();
    assert_eq!(verified.profile, 3);
    assert_eq!(verified.cohort_size, Some(32));
}

#[test]
fn test_series_attacks_still_fail() {
    let s = Signers::new();
    let _epoch = enclave_core::seq::new_boot_epoch_id();

    // 1. 3-frame series spending 6,000 mb each (total 18,000 mb > 12,000 cap) fails
    let chunk1 = EpochChunk {
        slots: (1..=10)
            .map(|seq| SlotWitness::Fold {
                seq,
                scrubbed: b"{}".to_vec(),
                qif_delta_mb: 600,
            })
            .collect(),
        journal_lines: vec![b"{}".to_vec()],
    };
    let chunk2 = EpochChunk {
        slots: (11..=20)
            .map(|seq| SlotWitness::Fold {
                seq,
                scrubbed: b"{}".to_vec(),
                qif_delta_mb: 600,
            })
            .collect(),
        journal_lines: vec![b"{}".to_vec()],
    };
    let chunk3 = EpochChunk {
        slots: (21..=30)
            .map(|seq| SlotWitness::Fold {
                seq,
                scrubbed: b"{}".to_vec(),
                qif_delta_mb: 600,
            })
            .collect(),
        journal_lines: vec![b"{}".to_vec()],
    };

    let public = EpochPublic {
        profile: 2,
        policy_blake3: [1; 32],
        tuf_snapshot_root: [2; 32],
        j_prev: hash_bytes(b"genesis", b""),
    };

    let err = prove_rollup_series(
        &public,
        &[1; 32],
        "corp:attack",
        &[chunk1, chunk2, chunk3],
        &s.keys(),
        None,
        Some(vec!["30".into()]),
        false,
    )
    .unwrap_err();

    assert!(err.is("QIF_BUDGET_EXCEEDED"));
}
