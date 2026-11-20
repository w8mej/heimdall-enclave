use ed25519_dalek::{Signer, SigningKey};
use enclave_core::audit::tombstone_message;
use enclave_core::poseidon2::{compress, hash_bytes, Poseidon2Digest};
use enclave_zk_auditor::cohort::{leaf, verify_membership, CohortTree};
use enclave_zk_auditor::relation::{prove_rollup, EpochPublic, HardwareWitness, SlotWitness};
use enclave_zk_auditor::rollup::ComplianceRollupProofV1;
use enclave_zk_auditor::tombstone::{Tombstone, TombstoneKeys};
use enclave_zk_auditor::zk::engine::{prove_epoch, trace, vk_digest, EpochStatement, SlotKind};
use enclave_zk_auditor::zk::imt_air::verify_interval_non_membership;
use enclave_zk_auditor::zk::sig_air::compute_prf_mac;

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

    #[allow(dead_code)]
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

fn cohort(n: usize, member: usize) -> (HardwareWitness, CohortTree) {
    let keys: Vec<(Vec<u8>, Vec<u8>)> = (0..n)
        .map(|i| {
            (
                format!("sep-{i}").into_bytes(),
                format!("yk-{i}").into_bytes(),
            )
        })
        .collect();
    let tree = CohortTree::build(keys.iter().map(|(a, b)| leaf(a, b)).collect()).unwrap();
    let w = HardwareWitness {
        pk_sep: keys[member].0.clone(),
        pk_yk: keys[member].1.clone(),
        path: tree.path(member).unwrap(),
        root: tree.root(),
        cohort_size: tree.size(),
    };
    (w, tree)
}

fn public(profile: u8) -> EpochPublic {
    EpochPublic {
        profile,
        policy_blake3: [7; 32],
        tuf_snapshot_root: [8; 32],
        j_prev: hash_bytes(b"genesis", b""),
    }
}

#[test]
fn test_forged_witness_wrong_journal_line() {
    let s = Signers::new();
    let (hw, _) = cohort(48, 0);
    let pub_ctx = public(3);
    let correct_lines = [b"{\"line\":\"legitimate_audit_event\"}".to_vec()];
    let forged_lines = [b"{\"line\":\"tampered_forged_journal_line\"}".to_vec()];

    let slots = vec![SlotWitness::Fold {
        seq: 7000,
        scrubbed: b"scrubbed content".to_vec(),
        qif_delta_mb: 100,
    }];

    // Prover proves with forged journal line
    let proof_bytes = prove_rollup(
        &pub_ctx,
        &[0x12; 32],
        "test-epoch",
        &slots,
        &forged_lines,
        &s.keys(),
        Some(&hw),
        Some(vec!["30".into()]),
        false,
    )
    .unwrap();

    // Verifier computes expected J_curr from real journal lines
    let expected_j_curr = correct_lines.iter().fold(pub_ctx.j_prev, |acc, l| {
        compress(
            b"depot-JournalFold-v1",
            &acc,
            &hash_bytes(b"depot-AuditLine-v1", l),
        )
    });

    let frame = ComplianceRollupProofV1::verify(&proof_bytes, &[enclave_zk_auditor::zk::engine::hiding_vk_digest()]).unwrap();
    assert_eq!(frame.public_inputs.redaction_checked.as_deref(), Some("native"));
    // Verification strictly fails against real journal chain
    assert_ne!(frame.public_inputs.J_curr, expected_j_curr.to_hex());
}

#[test]
fn test_forged_witness_unredacted_ssn_in_d_scrub() {
    let s = Signers::new();
    let (hw, _) = cohort(48, 0);
    let pub_ctx = public(3);
    let lines = vec![b"journal line".to_vec()];

    // Scrub fold contains an unredacted SSN (C4 sensitive text)
    let bad_slots = vec![SlotWitness::Fold {
        seq: 7000,
        scrubbed: b"user ssn is 123-45-6789 confidential".to_vec(),
        qif_delta_mb: 100,
    }];

    let err = prove_rollup(
        &pub_ctx,
        &[0x12; 32],
        "test-epoch",
        &bad_slots,
        &lines,
        &s.keys(),
        Some(&hw),
        Some(vec!["30".into()]),
        false,
    )
    .unwrap_err();

    // In-circuit Lasso DFA rejects unredacted C4
    assert!(
        err.is("UNREDACTED_C4_IN_FOLD"),
        "Expected UNREDACTED_C4_IN_FOLD, got {err}"
    );
}

#[test]
fn test_forged_witness_foreign_tombstone_key() {
    let key = Poseidon2Digest([1, 2, 3, 4, 5, 6, 7, 8]);
    let foreign_key = Poseidon2Digest([9, 9, 9, 9, 9, 9, 9, 9]);
    let msg = Poseidon2Digest([10, 20, 30, 40, 50, 60, 70, 80]);

    let legitimate_tag = compute_prf_mac(&key, &msg);
    let forged_tag = compute_prf_mac(&foreign_key, &msg);

    assert_ne!(
        legitimate_tag, forged_tag,
        "Foreign tombstone key must produce distinct MAC tag"
    );
}

#[test]
fn test_forged_witness_non_member_leaf() {
    let (_, tree) = cohort(48, 0);
    let foreign_leaf = leaf(b"foreign-sep", b"foreign-yk");

    // Path for legitimate member 0
    let path = tree.path(0).unwrap();
    // Attempting to verify membership using a foreign leaf under cohort root fails
    let verified = verify_membership(&tree.root(), &foreign_leaf, &path, tree.size());
    assert!(
        !verified,
        "Non-member leaf must fail cohort membership verification"
    );
}

#[test]
fn test_forged_witness_self_built_1_leaf_tree_claiming_cohort_48() {
    // 1. Minimum cohort size enforcement: building a 1-leaf tree fails closed natively
    let one_leaf = vec![leaf(b"my-sep", b"my-yk")];
    let err = CohortTree::build(one_leaf).unwrap_err();
    assert!(
        err.is("COHORT_TOO_SMALL"),
        "Building < 32 tree must fail with COHORT_TOO_SMALL"
    );

    // 2. Size commitment in root: attacker builds minimum 32-leaf tree but claims cohort 48
    let (hw_32, tree_32) = cohort(32, 0);
    let my_leaf = leaf(&hw_32.pk_sep, &hw_32.pk_yk);

    // Attacker presents this 32-leaf tree but claims cohort_size = 48
    let verified = verify_membership(&tree_32.root(), &my_leaf, &hw_32.path, 48);
    // Must fail because size is committed into the root preimage
    assert!(
        !verified,
        "Claiming cohort 48 on 32-leaf tree must fail root verification"
    );

    // Claiming true size 32 passes
    let verified_32 = verify_membership(&tree_32.root(), &my_leaf, &hw_32.path, 32);
    assert!(verified_32);
}

#[test]
fn test_forged_witness_reused_nullifier() {
    // IMT non-membership requires low < target < high
    let v_low = 1000u32;
    let v_high = 2000u32;

    // A reused nullifier X is already an existing member (e.g. X == v_low)
    let reused_x = 1000u32;
    let verified = verify_interval_non_membership(reused_x, v_low, v_high);
    assert!(
        !verified,
        "Reused nullifier (X == v_low) must fail non-membership"
    );

    // Nullifier outside interval also fails
    assert!(!verify_interval_non_membership(2500u32, v_low, v_high));
    assert!(!verify_interval_non_membership(500u32, v_low, v_high));

    // Valid non-member strictly inside interval passes
    assert!(verify_interval_non_membership(1500u32, v_low, v_high));
}

#[test]
fn test_forged_witness_out_of_window_qif() {
    let s = EpochStatement {
        vk_digest: vk_digest(),
        profile: 3,
        policy_blake3: [1; 32],
        tuf_snapshot_root: [2; 32],
        qif_cap_mb: 12_000,
        r_fleet_pk: [3; 32],
        j_prev: [4; 32],
        j_curr: [5; 32],
        nullifier_e: [6; 32],
        qif_root_prev: [7; 32],
        qif_root_curr: [8; 32],
        s_start: 50_000,
        s_end: 40_000, // Inverted / out of window span
        used_in: 0,
        used_out: 100,
        cohort_size: 48,
    };

    let slots = vec![SlotKind::Fold { delta_mb: 100 }];
    let err = prove_epoch(&s, &slots).unwrap_err();
    assert!(err.is("EPOCH_SPAN"), "Expected EPOCH_SPAN error, got {err}");
}

#[test]
fn test_forged_witness_l3_c4_cap_exceeded() {
    // 12,000 mb is the normative L3 cap. Attempting to spend 12,500 mb fails closed.
    let slots = vec![SlotKind::Fold { delta_mb: 12_500 }];
    let err = trace(&slots, 12_000, 0).unwrap_err();
    assert!(
        err.is("QIF_BUDGET_EXCEEDED"),
        "Expected QIF_BUDGET_EXCEEDED, got {err}"
    );
}
