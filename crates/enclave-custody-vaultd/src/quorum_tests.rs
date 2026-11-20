use super::*;
use crate::ctap::assertion::CredentialKey;
use ed25519_dalek::{Signer, SigningKey};

fn credential(key: &SigningKey, id: u8) -> EnrolledCredential {
    EnrolledCredential {
        credential_id: vec![id],
        key: CredentialKey::Ed25519(key.verifying_key()),
        aaguid: [0; 16],
        firmware_version: 0,
    }
}
fn approval(key: &SigningKey, id: u8) -> QuorumApproval {
    let mut auth_data = crate::ctap::rp_id_hash().to_vec();
    auth_data.push(0x05);
    auth_data.extend_from_slice(&1u32.to_be_bytes());
    let mut message = auth_data.clone();
    message.extend_from_slice(&[9; 32]);
    QuorumApproval {
        credential_id: vec![id],
        auth_data,
        signature: key.sign(&message).to_bytes().to_vec(),
        collected_at: 0,
    }
}

#[test]
fn duplicate_key_or_credential_enrollment_refuses_before_counter_use() {
    let first = SigningKey::from_bytes(&[1; 32]);
    let second = SigningKey::from_bytes(&[2; 32]);
    for enrolled in [
        vec![credential(&first, 1), credential(&first, 2)],
        vec![credential(&first, 1), credential(&second, 1)],
    ] {
        let mut counters = SignCountStore::default();
        assert!(verify_quorum_ext(
            &enrolled,
            2,
            &[9; 32],
            &[approval(&first, 1), approval(&first, 2)],
            true,
            &mut counters,
            0
        )
        .unwrap_err()
        .is("QUORUM_DUPLICATE_ENROLLMENT"));
        assert_eq!(counters.get(&[1]), 0);
    }
    let enrolled = [credential(&first, 1), credential(&second, 2)];
    assert_eq!(
        verify_quorum_ext(
            &enrolled,
            2,
            &[9; 32],
            &[approval(&first, 1), approval(&second, 2)],
            true,
            &mut SignCountStore::default(),
            0
        )
        .unwrap(),
        2
    );
    assert!(verify_quorum_ext(
        &enrolled,
        2,
        &[9; 32],
        &[approval(&first, 1), approval(&first, 1)],
        true,
        &mut SignCountStore::default(),
        0
    )
    .unwrap_err()
    .is("QUORUM_NOT_MET"));
}
