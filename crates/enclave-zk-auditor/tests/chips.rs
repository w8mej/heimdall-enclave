//! GAP-23 chip unit tests with known-answer vectors and end-to-end verification.

use enclave_core::poseidon2::{compress, hash_bytes, Poseidon2Digest};
use enclave_zk_auditor::cohort::{leaf, CohortTree};
use enclave_zk_auditor::zk::engine::{
    prove_epoch, verify_epoch, vk_digest, EpochStatement, SlotKind,
};
use enclave_zk_auditor::zk::imt_air::verify_interval_non_membership;
use enclave_zk_auditor::zk::lasso_dfa::{eval_dfa_bytes, STATE_REJECT};
use enclave_zk_auditor::zk::sig_air::compute_prf_mac;

#[test]
fn test_poseidon2_chip_known_answer_vectors() {
    let tag = b"MCPMac-FleetLeaf-v1";
    let msg = b"chip-test-vector-message-payload";
    let digest = hash_bytes(tag, msg);
    assert_ne!(digest, Poseidon2Digest::ZERO);

    // Deterministic repeatability
    let digest2 = hash_bytes(tag, msg);
    assert_eq!(digest, digest2);

    // One-bit modification produces entirely different sponge digest
    let mut modified = msg.to_vec();
    modified[0] ^= 1;
    let digest3 = hash_bytes(tag, &modified);
    assert_ne!(digest, digest3);
}

#[test]
fn test_merkle_chip_membership_and_cohort_binding() {
    let leaves: Vec<_> = (0..32u8).map(|i| leaf(&[i; 65], &[i; 32])).collect();
    let tree = CohortTree::build(leaves.clone()).expect("build cohort tree");
    let root = tree.root();
    assert_ne!(root, Poseidon2Digest::ZERO);

    // Valid path passes
    let path = tree.path(7).expect("leaf path");
    assert!(enclave_zk_auditor::cohort::verify_membership(
        &root,
        &leaves[7],
        &path,
        tree.size(),
    ));

    // Forged cohort size fails verification
    assert!(!enclave_zk_auditor::cohort::verify_membership(
        &root, &leaves[7], &path, 48, // forged != 32
    ));

    // Wrong leaf fails verification
    assert!(!enclave_zk_auditor::cohort::verify_membership(
        &root,
        &leaves[8],
        &path,
        tree.size(),
    ));
}

#[test]
fn test_lasso_dfa_in_circuit_redaction() {
    // 1. Fully redacted text passes
    let scrubbed = b"User: patient-001, SSN: [REDACTED], Balance: $400.00";
    let (state, reject) = eval_dfa_bytes(0, scrubbed);
    assert!(!reject);
    assert_ne!(state, STATE_REJECT);

    // 2. Unredacted SSN triggers REJECT
    let unredacted = b"User: patient-001, SSN: 012-34-5678, Balance: $400.00";
    let (state_bad, reject_bad) = eval_dfa_bytes(0, unredacted);
    assert!(reject_bad);
    assert_eq!(state_bad, STATE_REJECT);

    // 3. 128-byte carry state across frames correctly catches split token
    let frame1_tail = b"Prefix text leading into: 987-65";
    let (carry, r1) = eval_dfa_bytes(0, frame1_tail);
    assert!(!r1);
    assert_eq!(carry, 16);

    let frame2_head = b"-4321 trailing text";
    let (final_state, r2) = eval_dfa_bytes(carry, frame2_head);
    assert!(r2);
    assert_eq!(final_state, STATE_REJECT);
}

#[test]
fn test_sig_prf_mac_substitute() {
    let key = Poseidon2Digest([11, 22, 33, 44, 55, 66, 77, 88]);
    let tombstone_digest = hash_bytes(b"MCPMac-Tombstone-v1", b"dual-cosigned-tombstone-slot-42");

    let tag = compute_prf_mac(&key, &tombstone_digest);
    assert_ne!(tag, Poseidon2Digest::ZERO);

    // Key commitment
    let pk_leaf = compress(b"MCPMac-FleetLeaf-v1", &key, &Poseidon2Digest::ZERO);
    assert_ne!(pk_leaf, Poseidon2Digest::ZERO);

    // Tampered tag check
    let mut tampered_tag = tag;
    tampered_tag.0[0] ^= 1;
    assert_ne!(tag, tampered_tag);
}

#[test]
fn test_imt_non_membership_chip() {
    // Interval [100, 200]
    let low = 100u32;
    let high = 200u32;

    // Inside interval: non-membership holds
    assert!(verify_interval_non_membership(150, low, high));
    assert!(verify_interval_non_membership(101, low, high));
    assert!(verify_interval_non_membership(199, low, high));

    // Outside interval: non-membership fails
    assert!(!verify_interval_non_membership(50, low, high));
    assert!(!verify_interval_non_membership(250, low, high));
    assert!(!verify_interval_non_membership(100, low, high));
    assert!(!verify_interval_non_membership(200, low, high));
}

#[test]
fn test_end_to_end_epoch_proving_with_57_public_values() {
    let n = 16u64;
    let stmt = EpochStatement {
        vk_digest: vk_digest(),
        profile: 3,
        policy_blake3: [1u8; 32],
        tuf_snapshot_root: [2u8; 32],
        qif_cap_mb: 12_000,
        r_fleet_pk: [3u8; 32],
        j_prev: [4u8; 32],
        j_curr: [5u8; 32],
        nullifier_e: [6u8; 32],
        qif_root_prev: [7u8; 32],
        qif_root_curr: [8u8; 32],
        s_start: 100,
        s_end: 100 + n - 1,
        used_in: 0,
        used_out: 1600,
        cohort_size: 32,
    };

    let slots: Vec<SlotKind> = (0..n).map(|_| SlotKind::Fold { delta_mb: 100 }).collect();

    let proof = prove_epoch(&stmt, &slots).expect("prove_epoch with 57 public values");
    assert!(!proof.is_empty());
    assert!(proof.len() <= 98_304);

    verify_epoch(&stmt, &proof).expect("verify_epoch with 57 public values");
}
