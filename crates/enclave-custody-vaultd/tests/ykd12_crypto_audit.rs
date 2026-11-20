//! Audit-only reproductions for YKD-12, not acceptance tests for a new protocol.
//! All keys/assertions are software fixtures; no transport or hardware is opened.

use ed25519_dalek::{Signer, SigningKey};
use enclave_crypto::multisig::{QuorumPolicy, QuorumSignature};
use enclave_crypto::tuf::{RepoBuilder, TufClient};
use enclave_custody_vaultd::ctap::assertion::{CredentialKey, EnrolledCredential, SignCountStore};
use enclave_custody_vaultd::ctap::rp_id_hash;
use enclave_custody_vaultd::quorum::{verify_quorum, verify_quorum_ext, QuorumApproval, QUORUM_TTL_S};
use sha2::{Digest, Sha256};

fn key(byte: u8) -> SigningKey { SigningKey::from_bytes(&[byte; 32]) }
fn credential(key: &SigningKey, id: u8) -> EnrolledCredential {
    EnrolledCredential {
        credential_id: vec![id], key: CredentialKey::Ed25519(key.verifying_key()),
        aaguid: [0; 16], firmware_version: 0,
    }
}
fn approval(key: &SigningKey, id: u8, digest: &[u8; 32], uv: bool) -> QuorumApproval {
    let mut auth_data = rp_id_hash().to_vec();
    auth_data.push(if uv { 0x05 } else { 0x01 });
    auth_data.extend_from_slice(&1u32.to_be_bytes());
    let mut message = auth_data.clone(); message.extend_from_slice(digest);
    QuorumApproval { credential_id: vec![id], auth_data,
        signature: key.sign(&message).to_bytes().to_vec(), collected_at: 0 }
}
fn plain(key: &SigningKey, digest: &[u8], at: u64) -> QuorumSignature {
    QuorumSignature { public_key: key.verifying_key().to_bytes().to_vec(),
        signature: key.sign(digest).to_bytes().to_vec(), collected_at_ms: at }
}

#[test]
fn audit_ctap_and_raw_digest_signatures_are_not_interchangeable() {
    let k = key(1); let d = [3; 32]; let c = credential(&k, 1);
    let a = approval(&k, 1, &d, true);
    assert!(verify_quorum_ext(&[c.clone()], 1, &d, &[a.clone()], true, &mut SignCountStore::default(), 0).is_ok());
    let p = QuorumPolicy::new(vec![k.verifying_key()], 1).unwrap();
    let raw = QuorumSignature { public_key: k.verifying_key().to_bytes().to_vec(),
        signature: a.signature.clone(), collected_at_ms: 0 };
    assert!(p.verify(&d, &[raw], 0).is_err());
    let signed = plain(&k, &d, 0);
    assert!(p.verify(&d, &[signed.clone()], 0).is_ok());
    let mut fake_ctap = a; fake_ctap.signature = signed.signature;
    assert!(verify_quorum_ext(&[c], 1, &d, &[fake_ctap], true, &mut SignCountStore::default(), 0).is_err());
}

#[test]
fn audit_unsigned_raw_collection_time_can_be_relabelled() {
    let k = key(2); let d = [4; 32];
    let p = QuorumPolicy::new(vec![k.verifying_key()], 1).unwrap();
    let old = plain(&k, &d, 0); let now = p.collection_ttl_ms + 1;
    assert!(p.verify(&d, &[old.clone()], now).is_err());
    let mut relabelled = old.clone(); relabelled.collected_at_ms = now;
    assert_eq!(old.signature, relabelled.signature);
    assert!(p.verify(&d, &[relabelled], now).is_ok());
}

#[test]
fn audit_unsigned_ctap_collection_time_can_be_relabelled_before_consumption() {
    let k = key(3); let d = [5; 32]; let c = credential(&k, 1);
    let old = approval(&k, 1, &d, true); let now = QUORUM_TTL_S + 1;
    let mut counters = SignCountStore::default();
    assert!(verify_quorum_ext(&[c.clone()], 1, &d, &[old.clone()], true, &mut counters, now).is_err());
    let mut relabelled = old.clone(); relabelled.collected_at = now;
    assert_eq!(old.signature, relabelled.signature);
    assert!(verify_quorum_ext(&[c.clone()], 1, &d, &[relabelled.clone()], true, &mut counters, now).is_ok());
    // Positive control: a fully consumed assertion is still rejected by signCount.
    assert!(verify_quorum_ext(&[c], 1, &d, &[relabelled], true, &mut counters, now).is_err());
}

#[test]
fn audit_ctap_credential_aliases_do_not_establish_independent_keys() {
    let k = key(4); let d = [6; 32];
    let enrolled = [credential(&k, 1), credential(&k, 2)];
    let first = approval(&k, 1, &d, true);
    let mut alias = first.clone(); alias.credential_id = vec![2];
    assert_eq!(first.signature, alias.signature);
    // 2026-11-15 supersession: exact pre-fix probe bytes are retained under
    // agent3/implementation-attempt-3/ykd12_crypto_audit_before_alias_fix.rs.
    // The legacy helper now refuses aliases; independent people remain a
    // separate enrollment/protocol requirement.
    assert!(verify_quorum_ext(&enrolled, 2, &d, &[first, alias], true,
        &mut SignCountStore::default(), 0).unwrap_err().is("QUORUM_DUPLICATE_ENROLLMENT"));
    // The raw-key policy correctly rejects duplicate public-key enrollment.
    assert!(QuorumPolicy::new(vec![k.verifying_key(), k.verifying_key()], 2).is_err());
}

#[test]
fn audit_default_quorum_does_not_require_l3_uv() {
    let k = key(5); let d = [7; 32]; let c = credential(&k, 1);
    let up_only = approval(&k, 1, &d, false);
    assert!(verify_quorum(&[c.clone()], 1, &d, &[up_only.clone()], &mut SignCountStore::default(), 0).is_ok());
    assert!(verify_quorum_ext(&[c], 1, &d, &[up_only], true, &mut SignCountStore::default(), 0).is_err());
}

#[test]
fn audit_plain_grant_helper_does_not_verify_the_sep_chained_preimage() {
    let k = key(6); let d = [8; 32]; let c = credential(&k, 1);
    let mut h = Sha256::new(); h.update(d); h.update(b"synthetic-sep-signature"); h.update(1u64.to_be_bytes());
    let chained: [u8; 32] = h.finalize().into();
    let a = approval(&k, 1, &chained, true);
    assert!(verify_quorum_ext(&[c.clone()], 1, &d, &[a.clone()], true, &mut SignCountStore::default(), 0).is_err());
    assert!(verify_quorum_ext(&[c], 1, &chained, &[a], true, &mut SignCountStore::default(), 0).is_ok());
    // The helper accepts a caller-provided hash, but never verifies the synthetic SEP bytes.
}

#[test]
fn audit_failed_quorum_discards_consumed_counter_progress() {
    let a = key(7); let b = key(8); let d = [9; 32];
    let enrolled = [credential(&a, 1), credential(&b, 2)];
    let first = approval(&a, 1, &d, true); let mut counters = SignCountStore::default();
    assert!(verify_quorum_ext(&enrolled, 2, &d, &[first.clone()], true, &mut counters, 0).is_err());
    assert_eq!(counters.get(&[1]), 0);
    assert!(verify_quorum_ext(&enrolled, 2, &d, &[first, approval(&b, 2, &d, true)], true, &mut counters, 0).is_ok());
    assert_eq!(counters.get(&[1]), 1);
}

#[test]
fn audit_standard_tuf_keys_can_rotate_without_external_fido_receipts() {
    let mut repo = RepoBuilder::new(3, 2);
    let first = repo.root("2099-01-01T00:00:00Z").unwrap();
    let mut client = TufClient::bootstrap(&first).unwrap();
    repo.root_version = 2;
    let second = repo.root("2099-01-01T00:00:00Z").unwrap();
    client.update_root(&second).unwrap();
    assert_eq!(client.root().version, 2);
    // Expected TUF behavior: no FIDO approval object was supplied. Not a TUF vulnerability.
}
