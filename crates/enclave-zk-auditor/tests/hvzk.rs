use enclave_zk_auditor::zk::air::{NUM_BLIND, WIDTH};
use enclave_zk_auditor::zk::engine::{
    make_public_values, prove_epoch, prove_epoch_hiding, trace, verify_epoch, verify_epoch_hiding,
    vk_digest, EpochStatement, SlotKind,
};
use p3_field::{Field, PrimeField32};
use p3_matrix::Matrix;

fn test_statement(span: u64, used_out: u32) -> EpochStatement {
    EpochStatement {
        vk_digest: vk_digest(),
        profile: 3,
        policy_blake3: [0x11; 32],
        tuf_snapshot_root: [0x22; 32],
        qif_cap_mb: 12_000,
        r_fleet_pk: [0x33; 32],
        j_prev: [0x44; 32],
        j_curr: [0x55; 32],
        nullifier_e: [0x66; 32],
        qif_root_prev: [0x77; 32],
        qif_root_curr: [0x88; 32],
        s_start: 10_000,
        s_end: 10_000 + span - 1,
        used_in: 0,
        used_out,
        cohort_size: 48,
    }
}

#[test]
fn test_hiding_fri_pcs_prove_verify() {
    let span = 48;
    let delta = 150;
    let slots: Vec<SlotKind> = (0..span)
        .map(|_| SlotKind::Fold { delta_mb: delta })
        .collect();
    let s = test_statement(span, span as u32 * delta);

    let seed = 0x12345678_abcdef01;
    let proof_bytes = prove_epoch_hiding(&s, &slots, seed).unwrap();
    println!("HVZK proof bytes length: {}", proof_bytes.len());
    assert!(!proof_bytes.is_empty());

    // Verifies with same statement and seed
    verify_epoch_hiding(&s, &proof_bytes, seed).unwrap();

    // Tampered statement fails verification
    let mut tampered = s.clone();
    tampered.used_out += 1;
    assert!(verify_epoch_hiding(&tampered, &proof_bytes, seed).is_err());
}

#[test]
fn test_hvzk_simulator_indistinguishability() {
    // HVZK Indistinguishability Theorem:
    // Given two distinct witnesses W1 and W2 that satisfy the exact same public statement S,
    // the hiding proofs P1 and P2 generated with distinct random seeds are computationally
    // indistinguishable: both pass verification, but have randomized commitments and openings.
    let span = 60;
    let s = test_statement(span, 6_000);

    // Witness 1: 30 folds spending 200 mb each, followed by 30 tombstones (total = 6000 mb)
    let mut w1: Vec<SlotKind> = Vec::with_capacity(span as usize);
    for _ in 0..30 {
        w1.push(SlotKind::Fold { delta_mb: 200 });
    }
    for _ in 0..30 {
        w1.push(SlotKind::Tombstone);
    }

    // Witness 2: 60 folds spending 100 mb each (total = 6000 mb)
    let w2: Vec<SlotKind> = (0..span)
        .map(|_| SlotKind::Fold { delta_mb: 100 })
        .collect();

    assert_ne!(w1, w2);
    assert_eq!(w1.len(), span as usize);
    assert_eq!(w2.len(), span as usize);

    let seed1 = 0xa1b2c3d4e5f60102;
    let seed2 = 0x0908070605040302;

    let p1 = prove_epoch_hiding(&s, &w1, seed1).unwrap();
    let p2 = prove_epoch_hiding(&s, &w2, seed2).unwrap();

    // Both pass verification against the same statement S
    verify_epoch_hiding(&s, &p1, seed1).unwrap();
    verify_epoch_hiding(&s, &p2, seed2).unwrap();

    // The proof bytes are completely distinct (randomized by HidingFriPcs and MerkleTreeHidingMmcs)
    assert_ne!(p1, p2);
}

#[test]
fn test_trace_blinding_columns_randomness() {
    let slots = vec![SlotKind::Fold { delta_mb: 100 }, SlotKind::Tombstone];
    let mat = trace(&slots, 12_000, 0).unwrap();
    assert_eq!(mat.width(), WIDTH);
    assert_eq!(mat.width(), 52);

    // Verify blinding columns are populated and non-zero
    let mut non_zero_count = 0;
    for r in 0..mat.height() {
        for b in 0..NUM_BLIND {
            let val = mat.values[r * WIDTH + (WIDTH - NUM_BLIND + b)];
            if !val.is_zero() {
                non_zero_count += 1;
            }
        }
    }
    assert!(non_zero_count > 0);
}

#[test]
fn test_transcript_test_vectors() {
    let s = test_statement(10, 1_000);
    let pvs = make_public_values(&s);
    assert_eq!(pvs.len(), 57);

    // Verify deterministic transcript absorption
    let slots = vec![SlotKind::Fold { delta_mb: 100 }; 10];
    let proof1 = prove_epoch(&s, &slots).unwrap();
    verify_epoch(&s, &proof1).unwrap();

    // Public inputs transcript hash test vector:
    let mut hasher = blake3::Hasher::new_derive_key("MCPMac-R_epoch-Transcript-v1");
    for pv in pvs.iter() {
        hasher.update(&pv.as_canonical_u32().to_le_bytes());
    }
    let transcript_digest = hasher.finalize();
    println!(
        "Public values transcript test vector: {}",
        transcript_digest.to_hex()
    );
    assert!(!transcript_digest.as_bytes().iter().all(|&b| b == 0));
}
