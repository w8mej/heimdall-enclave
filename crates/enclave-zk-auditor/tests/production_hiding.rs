//! Production prover/frame/receiver plumbing, not a cryptographic privacy proof.
use enclave_core::poseidon2::hash_bytes;
use enclave_zk_auditor::{
    relation::{prove_rollup, EpochPublic, SlotWitness},
    rollup::{ComplianceRollupProofV1 as Frame, RollupTrust},
    tombstone::TombstoneKeys,
    zk::engine::{hiding_vk_digest, prove_epoch, verify_epoch_private, vk_digest, SlotKind},
};

#[test]
fn phase5_production_frame_uses_private_entropy_public_verifier_and_distinct_version() {
    let k1 = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let k2 = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let keys = TombstoneKeys {
        k703: k1.verifying_key(),
        k704: k2.verifying_key(),
    };
    let issuer = enclave_crypto::pqc::HybridSigningKey::generate();
    let public = EpochPublic {
        profile: 2,
        policy_blake3: [1; 32],
        tuf_snapshot_root: [2; 32],
        j_prev: hash_bytes(b"MCPMac-Genesis-v1", b""),
    };
    let make = || {
        prove_rollup(
            &public,
            &[7; 32],
            "acct:test",
            &[SlotWitness::Fold {
                seq: 1,
                scrubbed: b"[REDACTED]".to_vec(),
                qif_delta_mb: 3,
            }],
            &[b"{\"slot\":1}".to_vec()],
            &keys,
            None,
            Some(vec!["fixture".into()]),
            false,
        )
        .unwrap()
    };
    let first = Frame::verify(&make(), &[hiding_vk_digest()]).unwrap();
    let second = Frame::verify(&make(), &[hiding_vk_digest()]).unwrap();
    assert_eq!(first.v, 2);
    assert_eq!(first.statement().unwrap(), second.statement().unwrap());
    assert_ne!(
        first.proof, second.proof,
        "fresh randomness regression only, not proof of HVZK"
    );
    let stmt = first.statement().unwrap();
    // Independent receiver has no access to any private seed.
    let signed = Frame::build(
        &stmt,
        first.proof.clone(),
        None,
        false,
        Some(vec![Frame::sign_l2_hybrid_anchor(&stmt, &issuer)]),
    )
    .unwrap();
    Frame::verify_with_trust(
        &signed,
        &[hiding_vk_digest()],
        RollupTrust::L2Anchor(&issuer.verifying_key()),
    )
    .unwrap();
    assert!(Frame::verify(&signed, &[vk_digest()]).is_err());
    let mut wrong = stmt.clone();
    wrong.policy_blake3[0] ^= 1;
    assert!(verify_epoch_private(&wrong, &first.proof).is_err());
    let mut trailing = first.proof.clone();
    trailing.push(0);
    assert!(verify_epoch_private(&stmt, &trailing)
        .unwrap_err()
        .is("PROOF_DECODE"));
    // Relabeling a legacy non-hiding proof with the new key cannot upgrade it.
    let mut old = stmt.clone();
    old.vk_digest = vk_digest();
    let proof = prove_epoch(&old, &[SlotKind::Fold { delta_mb: 3 }]).unwrap();
    assert!(verify_epoch_private(&stmt, &proof).is_err());
    let old_frame = Frame::build(&old, proof, None, false, Some(vec!["fixture".into()])).unwrap();
    assert!(Frame::verify(&old_frame, &[hiding_vk_digest()]).is_err());
    // Wire version is checked even when both keys were deliberately pinned.
    let mut swapped = first;
    swapped.v = 1;
    let mut bytes = Vec::new();
    ciborium::into_writer(&swapped, &mut bytes).unwrap();
    assert!(Frame::verify(&bytes, &[vk_digest(), hiding_vk_digest()]).is_err());
}
