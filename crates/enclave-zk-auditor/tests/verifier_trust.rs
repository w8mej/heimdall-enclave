use enclave_crypto::pqc::HybridSigningKey;
use enclave_zk_auditor::cohort::digest_bytes;
use enclave_zk_auditor::rollup::{ComplianceRollupProofV1 as Frame, RollupTrust, L3_FRAME_BYTES};
use enclave_zk_auditor::zk::engine::{prove_epoch, vk_digest, EpochStatement, SlotKind};

fn statement(profile: u8) -> EpochStatement {
    let nullifier_e = [4; 32];
    let root = digest_bytes(&enclave_core::poseidon2::hash_bytes(
        b"MCPMac-QifTree-v1",
        &nullifier_e,
    ));
    EpochStatement {
        vk_digest: vk_digest(),
        profile,
        policy_blake3: [1; 32],
        tuf_snapshot_root: [2; 32],
        qif_cap_mb: 12_000,
        r_fleet_pk: [3; 32],
        j_prev: [4; 32],
        j_curr: [5; 32],
        nullifier_e,
        qif_root_prev: root,
        qif_root_curr: root,
        s_start: 1,
        s_end: 1,
        used_in: 0,
        used_out: 3,
        cohort_size: if profile == 3 { 48 } else { 0 },
    }
}

#[test]
fn l2_requires_expected_issuer_and_a_real_bound_composite_signature() {
    let expected = HybridSigningKey::generate();
    let foreign = HybridSigningKey::generate();
    let st = statement(2);
    let proof = prove_epoch(&st, &[SlotKind::Fold { delta_mb: 3 }]).unwrap();
    let make =
        |signature| Frame::build(&st, proof.clone(), None, false, Some(vec![signature])).unwrap();
    let bytes = make(Frame::sign_l2_hybrid_anchor(&st, &expected));
    Frame::verify_with_trust(
        &bytes,
        &[vk_digest()],
        RollupTrust::L2Anchor(&expected.verifying_key()),
    )
    .unwrap();
    assert!(Frame::verify_with_trust(
        &bytes,
        &[vk_digest()],
        RollupTrust::L2Anchor(&foreign.verifying_key())
    )
    .is_err());
    let foreign_signed = make(Frame::sign_l2_hybrid_anchor(&st, &foreign));
    assert!(Frame::verify_with_trust(
        &foreign_signed,
        &[vk_digest()],
        RollupTrust::L2Anchor(&expected.verifying_key())
    )
    .is_err());
    let absent = make("not-a-signature".into());
    assert!(
        Frame::verify(&absent, &[vk_digest()]).is_ok(),
        "accounting API makes no issuer claim"
    );
    assert!(Frame::verify_with_trust(
        &absent,
        &[vk_digest()],
        RollupTrust::L2Anchor(&expected.verifying_key())
    )
    .is_err());
    let mut other_statement = st.clone();
    other_statement.policy_blake3[0] ^= 1;
    let wrong_context = make(Frame::sign_l2_hybrid_anchor(&other_statement, &expected));
    assert!(Frame::verify_with_trust(
        &wrong_context,
        &[vk_digest()],
        RollupTrust::L2Anchor(&expected.verifying_key())
    )
    .is_err());
    assert!(Frame::verify_with_trust(
        &bytes,
        &[vk_digest()],
        RollupTrust::L3Cohort {
            root: &[3; 32],
            size: 48
        }
    )
    .is_err());
}

#[test]
fn l3_uses_external_root_and_count_and_the_normative_size() {
    let st = statement(3);
    let proof = prove_epoch(&st, &[SlotKind::Fold { delta_mb: 3 }]).unwrap();
    let bytes = Frame::build(&st, proof, Some(48), true, None).unwrap();
    assert_eq!(bytes.len(), L3_FRAME_BYTES);
    let checked = Frame::verify_with_trust(
        &bytes,
        &[vk_digest()],
        RollupTrust::L3Cohort {
            root: &[3; 32],
            size: 48,
        },
    )
    .unwrap();
    assert!(Frame::verify_with_trust(
        &bytes,
        &[vk_digest()],
        RollupTrust::L3Cohort {
            root: &[9; 32],
            size: 48
        }
    )
    .is_err());
    assert!(Frame::verify_with_trust(
        &bytes,
        &[vk_digest()],
        RollupTrust::L3Cohort {
            root: &[3; 32],
            size: 32
        }
    )
    .is_err());
    let mut wrong_size = checked;
    wrong_size.padded_frame_bytes = 4_096;
    assert!(wrong_size
        .validate_frame(4_096)
        .unwrap_err()
        .is("L3_FRAME_NOT_320KIB"));
    // Even the positive case does not establish sender membership: no private
    // membership witness was passed to the accounting prover. F78 remains open.
}
