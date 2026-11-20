//! Candidate v2 byte/cryptographic composition review probes, never production
//! protocol approval. No signer, durable store, native SEP or hardware is used.
use ed25519_dalek::{Signer, SigningKey};
use p256::ecdsa::{signature::Verifier, Signature};
use sha2::{Digest, Sha256};
use serde_json::Value;
use enclave_custody_vaultd::ctap::{assertion::{verify_assertion, AssertionResponse, CredentialKey, EnrolledCredential, SignCountStore}, rp_id_hash};

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/vector-2.json")).unwrap()
}
fn h(data: &[u8]) -> [u8; 32] { Sha256::digest(data).into() }
fn preimages(intent: &Value, context: &Value, sep_signature: &[u8]) -> (Vec<u8>, Vec<u8>) {
    assert_eq!(sep_signature.len(), 64);
    let d = h(&enclave_core::jcs::to_jcs_bytes(intent).unwrap());
    let c = h(&enclave_core::jcs::to_jcs_bytes(context).unwrap());
    let nonce = hex::decode(context["nonce_sha256"].as_str().unwrap()).unwrap();
    let start = hex::decode(context["start_ns_hex"].as_str().unwrap()).unwrap();
    assert_eq!((nonce.len(), start.len()), (32, 8));
    let mut sep = b"MCPMac-SEP-Approval-v2\0".to_vec();
    sep.extend_from_slice(&d); sep.extend_from_slice(&c); sep.extend_from_slice(&nonce); sep.extend_from_slice(&start);
    let mut ctap = b"MCPMac-CTAP-Approval-v2\0".to_vec();
    ctap.extend_from_slice(&d); ctap.extend_from_slice(&c); ctap.extend_from_slice(sep_signature); ctap.extend_from_slice(&start);
    (sep, ctap)
}
#[test]
fn candidate_exact_bytes_match_golden_vector_and_canonical_domains_are_distinct() {
    let f = fixture();
    let (intent, context) = (&f["intent"], &f["context"]);
    for (object, field) in [(intent,"intent_jcs_hex"),(context,"context_jcs_hex")] {
        assert_eq!(hex::encode(enclave_core::jcs::to_jcs_bytes(object).unwrap()), f[field].as_str().unwrap());
    }
    let signature = hex::decode(f["synthetic_sep_signature_hex"].as_str().unwrap()).unwrap();
    let (sep, ctap) = preimages(intent, context, &signature);
    assert_eq!(hex::encode(sep), f["sep_preimage_hex"].as_str().unwrap());
    assert_eq!(hex::encode(&ctap), f["ctap_hash_preimage_hex"].as_str().unwrap());
    assert_eq!(hex::encode(h(&ctap)), f["client_data_hash_hex"].as_str().unwrap());
    let metadata = serde_json::json!({"_type":"targets","custom":"line\nnext","version":5});
    assert_ne!(enclave_core::jcs::to_jcs_bytes(&metadata).unwrap(), enclave_crypto::canonical_json::to_canonical_json_bytes(&metadata).unwrap());
}
#[test]
fn candidate_software_sep_then_ctap_positive_rejects_splicing_and_raw_substitution() {
    let f = fixture(); let (intent, context) = (&f["intent"], &f["context"]);
    let sep_key = p256::ecdsa::SigningKey::from_slice(&[7;32]).unwrap();
    let (sep_message, _) = preimages(intent, context, &[0;64]);
    let signature: Signature = sep_key.sign(&sep_message);
    let signature = signature.normalize_s().unwrap_or(signature);
    let signature_bytes = signature.to_bytes();
    sep_key.verifying_key().verify(&sep_message, &signature).unwrap();
    let (_, ctap_message) = preimages(intent, context, &signature_bytes);
    let challenge = h(&ctap_message);
    let fido = SigningKey::from_bytes(&[8;32]);
    let credential = EnrolledCredential { credential_id: vec![1,2,3], key: CredentialKey::Ed25519(fido.verifying_key()), aaguid:[0;16], firmware_version:0 };
    let mut auth = rp_id_hash().to_vec(); auth.push(0x05); auth.extend_from_slice(&1u32.to_be_bytes());
    let mut signed = auth.clone(); signed.extend_from_slice(&challenge);
    let response = AssertionResponse { credential_id:Some(credential.credential_id.clone()), auth_data:auth, signature:fido.sign(&signed).to_bytes().to_vec() };
    verify_assertion(&credential, &response, &challenge, true, &mut SignCountStore::default()).unwrap();
    for field in ["boot_id_sha256","gui_session_sha256","policy_sha256","publication_id","nonce_sha256","sep_key_sha256","fido_key_sha256","custodian_id"] {
        let mut changed = context.clone(); changed[field] = Value::String("ff".repeat(32));
        let (other_sep, other_ctap) = preimages(intent,&changed,&signature_bytes);
        assert!(sep_key.verifying_key().verify(&other_sep,&signature).is_err(), "{field}");
        assert!(verify_assertion(&credential,&response,&h(&other_ctap),true,&mut SignCountStore::default()).is_err(), "{field}");
    }
    let plain_digest=h(&enclave_core::jcs::to_jcs_bytes(intent).unwrap());
    assert!(verify_assertion(&credential,&response,&plain_digest,true,&mut SignCountStore::default()).is_err());
    let mut fake=response; fake.signature=fido.sign(&challenge).to_bytes().to_vec();
    assert!(verify_assertion(&credential,&fake,&challenge,true,&mut SignCountStore::default()).is_err());
}

#[test]
fn candidate_staged_tuf_links_bind_complete_child_envelopes() {
    use enclave_crypto::tuf::{RepoBuilder,TufClient};
    let repository=RepoBuilder::new(3,2);
    let expiry="2035-01-01T00:00:00Z";
    let root=repository.root(expiry).unwrap();
    let targets=repository.targets(1,expiry,Default::default()).unwrap();
    let snapshot=repository.snapshot(1,expiry,1,&targets).unwrap();
    let timestamp=repository.timestamp(1,expiry,1,&snapshot).unwrap();
    let now=1_793_884_860;
    TufClient::bootstrap(&root).unwrap().refresh(&timestamp,&snapshot,&targets,now).unwrap();

    // Reformatting preserves the signed member and every standard role signature,
    // but changes the exact child file committed by the already-signed parent.
    let parsed:Value=serde_json::from_slice(&targets).unwrap();
    let reformatted=serde_json::to_vec_pretty(&parsed).unwrap();
    assert_ne!(targets,reformatted);
    let mut original=TufClient::bootstrap(&root).unwrap();
    assert!(original.refresh(&timestamp,&snapshot,&reformatted,now).is_err());
    // A new staged parent must commit to the actual complete child bytes.
    let next_snapshot=repository.snapshot(2,expiry,1,&reformatted).unwrap();
    let next_timestamp=repository.timestamp(2,expiry,2,&next_snapshot).unwrap();
    TufClient::bootstrap(&root).unwrap().refresh(&next_timestamp,&next_snapshot,&reformatted,now).unwrap();
    assert!(TufClient::bootstrap(&root).unwrap().refresh(&timestamp,&next_snapshot,&reformatted,now).is_err());

    // Candidate approval challenges bind the exact complete-file commitment.
    let f=fixture(); let mut intent=f["intent"].clone();
    intent["metadata"][0]["role"]=Value::String("snapshot".into());
    intent["linked_metadata"]=serde_json::json!([{"role":"targets","version":1,
        "envelope_sha256":hex::encode(h(&targets)),"envelope_bytes":targets.len()}]);
    let signature=hex::decode(f["synthetic_sep_signature_hex"].as_str().unwrap()).unwrap();
    let approved=preimages(&intent,&f["context"],&signature);
    intent["linked_metadata"][0]["envelope_sha256"]=Value::String(hex::encode(h(&reformatted)));
    assert_ne!(approved,preimages(&intent,&f["context"],&signature));
}
