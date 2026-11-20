//! Executable evidence of F78, not a passing compliance-closure contract.
use enclave_zk_auditor::zk::engine::{
    prove_epoch, prove_epoch_hiding, verify_epoch, verify_epoch_hiding, vk_digest, EpochStatement,
    SlotKind,
};
use rand::RngCore;

fn arbitrary_statement() -> EpochStatement {
    let digest = || {
        let mut bytes = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        bytes
    };
    EpochStatement {
        vk_digest: vk_digest(),
        profile: 3,
        policy_blake3: digest(),
        tuf_snapshot_root: digest(),
        qif_cap_mb: 12_000,
        r_fleet_pk: digest(),
        j_prev: digest(),
        j_curr: digest(),
        nullifier_e: digest(),
        qif_root_prev: digest(),
        qif_root_curr: digest(),
        s_start: (7u64 << 32) + 40,
        s_end: (7u64 << 32) + 41,
        used_in: 0,
        used_out: 3,
        cohort_size: 48,
    }
}

#[test]
fn reproduces_unbound_journal_fleet_nullifier_and_qif_roots() {
    let slots = [
        SlotKind::Fold { delta_mb: 1 },
        SlotKind::Fold { delta_mb: 2 },
    ];
    for _ in 0..3 {
        // No real journal, fleet keys, membership witness, nullifier preimage or
        // authenticated QIF tree is provided; all roots are independently random.
        let statement = arbitrary_statement();
        let proof = prove_epoch(&statement, &slots).unwrap();
        verify_epoch(&statement, &proof).expect("F78 remains: arbitrary commitments accepted");
        // Absorption does prevent reattaching an existing proof to a new root.
        let mut changed = statement.clone();
        changed.j_curr[0] ^= 1;
        assert!(verify_epoch(&changed, &proof).is_err());
    }
}

#[test]
fn hiding_configuration_has_the_same_accounting_only_relation() {
    let statement = arbitrary_statement();
    let slots = [
        SlotKind::Fold { delta_mb: 1 },
        SlotKind::Fold { delta_mb: 2 },
    ];
    let proof = prove_epoch_hiding(&statement, &slots, 0xabc).unwrap();
    verify_epoch_hiding(&statement, &proof, 0xabc).unwrap();
}

#[test]
fn production_private_entropy_and_pinned_cohort_still_prove_only_accounting() {
    use enclave_zk_auditor::rollup::{ComplianceRollupProofV1, RollupTrust};
    use enclave_zk_auditor::zk::engine::{
        hiding_vk_digest, prove_epoch_private, verify_epoch_private,
    };

    // Exercise the actual production hiding configuration and independent
    // receiver API. Fresh private coins, transcript binding and an independently
    // selected root do not supply the missing authenticated witness relation.
    let mut statement = arbitrary_statement();
    statement.vk_digest = hiding_vk_digest();
    let configured_fleet_root = [0x5a; 32];
    statement.r_fleet_pk = configured_fleet_root;
    // Match the frame's existing transcript placeholder. No authenticated QIF
    // tree/preimage/update witness is available to this hostile prover.
    let qif_placeholder = enclave_zk_auditor::cohort::digest_bytes(
        &enclave_core::poseidon2::hash_bytes(b"MCPMac-QifTree-v1", &statement.nullifier_e),
    );
    statement.qif_root_prev = qif_placeholder;
    statement.qif_root_curr = qif_placeholder;
    let slots = [
        SlotKind::Fold { delta_mb: 1 },
        SlotKind::Fold { delta_mb: 2 },
    ];
    let proof = prove_epoch_private(&statement, &slots).unwrap();
    verify_epoch_private(&statement, &proof).unwrap();
    let frame = ComplianceRollupProofV1::build(
        &statement,
        proof,
        Some(u64::from(statement.cohort_size)),
        true,
        None,
    )
    .unwrap();
    let accepted = ComplianceRollupProofV1::verify_with_trust(
        &frame,
        &[hiding_vk_digest()],
        RollupTrust::L3Cohort {
            root: &configured_fleet_root,
            size: statement.cohort_size,
        },
    )
    .expect("scope reproduction: no membership, journal or QIF witness was supplied");
    assert_eq!(accepted.v, 2);
    // This acceptance demonstrates an OPEN relation gap. It must never be
    // counted as successful full-compliance or membership acceptance.
    assert_eq!(accepted.statement().unwrap(), statement);
}
