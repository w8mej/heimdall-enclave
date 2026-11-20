//! Candidate4 cryptographic proof checks, deliberately disconnected from signing.
//!
//! The caller supplies independently authenticated intent/context, enrollment,
//! issuer and trusted time. This module does not establish those authorities,
//! durable publication/counter consumption, human independence or isolation.
//! Returned facts are not a grant. YKD12 production approval remains pending.
use std::collections::BTreeSet;
use std::fmt;

use ed25519_dalek::{Signature as EdSignature, VerifyingKey as EdKey};
use enclave_core::{err, fail, error::EnclaveResult};
use p256::ecdsa::{signature::Verifier, Signature as SepSignature, VerifyingKey as SepKey};
use serde::{Deserialize, de::{self, MapAccess, SeqAccess, Visitor}};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use crate::ctap::assertion::{verify_assertion, AssertionResponse, EnrolledCredential, SignCountStore};

const MAX_WIRE: usize = 256 * 1024;
const MAX_INTEGER: u64 = 9_007_199_254_740_991;

#[path = "guarded_intent.rs"]
mod intent_validation;

/// Independent inputs; none may be derived from an untrusted proof's claims.
pub struct CandidateProofTrust<'a> {
    /// Exact approved intent in JCS, after separate closed-schema/role review.
    pub intent_jcs: &'a [u8],
    /// Exact independently approved current context in JCS.
    pub context_jcs: &'a [u8],
    /// Independently enrolled SEP P256 public key with reviewed biometric policy.
    pub sep_key: &'a SepKey,
    /// Independently enrolled FIDO public credential and metadata identity.
    pub credential: &'a EnrolledCredential,
    /// Pinned independently administered freshness issuer.
    pub freshness_issuer: &'a EdKey,
    /// Locally configured finite freshness bound, at most the complete10s cap.
    pub maximum_ttl_ms: u64,
}

/// A trusted clock's complete uncertainty interval, in UTC milliseconds.
#[derive(Clone, Copy, Debug)]
pub struct TrustedUtcRange {
    /// Earliest possible current instant.
    pub earliest: u64,
    /// Latest possible current instant; must remain strictly before expiry.
    pub latest: u64,
}

/// Diagnostic proof facts only; not a durable approval or signing capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateProofFacts {
    /// Hash of the exact canonical proof bytes checked.
    pub proof_sha256: [u8; 32],
    /// Hash of the exact independently approved application intent.
    pub intent_sha256: [u8; 32],
    /// Authenticated counter high-water mark, still requiring durable commit.
    pub sign_count: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    protocol: String,
    #[serde(deserialize_with = "strict_intent")]
    intent: Value,
    freshness: Freshness,
    context: Context,
    sep_signature_hex: String,
    credential_id_hex: String,
    authenticator_data_hex: String,
    algorithm: i64,
    assertion_signature_hex: String,
}
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Context {
    protocol: String, custodian_id: String, sep_key_sha256: String,
    fido_key_sha256: String, credential_id_sha256: String, boot_id_sha256: String,
    gui_session_sha256: String, policy_sha256: String, publication_id: String,
    nonce_sha256: String, start_ns_hex: String, stage: String,
}
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Freshness {
    certificate: Certificate, issuer_key_sha256: String, signature_ed25519_hex: String,
}
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Certificate {
    protocol: String, publication_id: String, repository_id: String, purpose: String,
    policy_sha256: String, policy_version: u64, authority_generation: u64,
    issued_utc_ms: u64, not_before_utc_ms: u64, expires_utc_ms: u64,
    nonce_sha256: String, intent_constraints_sha256: String, stage: String,
}

// Reject duplicate members before constructing a map, including in generic
// intent objects. serde's default recursion bound and the wire bound also apply.
struct Strict(Value);
// `Value`'s arbitrary_precision visitor recognizes a reserved private Number
// map. Reuse our map-preserving visitor during typed conversion too: canonical
// checking must describe exactly the intent later bound to all signatures.
fn strict_intent<'de, D: serde::Deserializer<'de>>(decoder: D) -> Result<Value, D::Error> {
    Strict::deserialize(decoder).map(|Strict(value)| value)
}
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("bounded integer JSON") }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Strict,E> { Ok(Strict(Value::Bool(v))) }
            fn visit_unit<E: de::Error>(self) -> Result<Strict,E> { Ok(Strict(Value::Null)) }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Strict,E> { Ok(Strict(Value::String(v.into()))) }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Strict,E> { Ok(Strict(Value::String(v))) }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Strict,E> {
                if v > MAX_INTEGER { return Err(E::custom("integer bound")); }
                Ok(Strict(Value::Number(Number::from(v))))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Strict,E> {
                if v >= 0 { return self.visit_u64(v as u64); }
                if v != -8 && v != -7 { return Err(E::custom("negative integer")); }
                Ok(Strict(Value::Number(Number::from(v))))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut values: A) -> Result<Strict,A::Error> {
                let mut out=Vec::new();
                while let Some(Strict(v))=values.next_element()? { out.push(v); }
                Ok(Strict(Value::Array(out)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut values: A) -> Result<Strict,A::Error> {
                let mut out=Map::new(); let mut seen=BTreeSet::new();
                while let Some(key)=values.next_key::<String>()? {
                    if !seen.insert(key.clone()) { return Err(de::Error::custom("duplicate member")); }
                    let Strict(value)=values.next_value()?;out.insert(key,value);
                }
                Ok(Strict(Value::Object(out)))
            }
        }
        decoder.deserialize_any(V)
    }
}
fn digest(data: &[u8]) -> [u8;32] { Sha256::digest(data).into() }
fn jcs<T: serde::Serialize>(value: &T) -> EnclaveResult<Vec<u8>> { enclave_core::jcs::to_jcs_bytes(value) }
fn hex_bytes(value: &str, minimum: usize, maximum: usize) -> EnclaveResult<Vec<u8>> {
    if value.len()%2 != 0 || value.len()<minimum*2 || value.len()>maximum*2
        || !value.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)) {
        fail!(EINVAL,"CANDIDATE_HEX");
    }
    hex::decode(value).map_err(|_|err!(EINVAL,"CANDIDATE_HEX"))
}
fn matching_hash(value: &str, bytes: &[u8]) -> EnclaveResult<()> {
    if hex_bytes(value,32,32)?.as_slice()!=digest(bytes) { fail!(EACCES,"CANDIDATE_KEY_BINDING"); }
    Ok(())
}
fn current(certificate: &Certificate, time: TrustedUtcRange) -> EnclaveResult<()> {
    if time.earliest>time.latest || time.earliest<certificate.not_before_utc_ms
        || time.latest>=certificate.expires_utc_ms { fail!(EACCES,"CANDIDATE_TRUSTED_TIME"); }
    Ok(())
}

/// Check a candidate Snapshot/Timestamp body and its exact signed child against
/// the same closed canonical intent format used by the proof primitive.
///
/// The caller must independently authenticate this intent, current repository
/// policy and the supplied TUF client/time. This diagnostic does not verify a
/// custodian proof, approve a publication, sign, or mutate trusted state. Root
/// rotation and recovery are deliberately outside this one-child API.
pub fn check_candidate_parent_linkage(
    client: &enclave_crypto::tuf::TufClient, intent_jcs: &[u8], signed_body: &[u8],
    children: &[&[u8]], trusted_now: i64,
) -> EnclaveResult<enclave_crypto::tuf::candidate::ParentFacts> {
    use enclave_crypto::tuf::{Role, candidate::{ExpectedChild, ExpectedParent, verify_parent_linkage}};
    if intent_jcs.is_empty() || intent_jcs.len()>MAX_WIRE {fail!(EINVAL,"CANDIDATE_BOUND");}
    let Strict(intent)=serde_json::from_slice(intent_jcs).map_err(|_|err!(EINVAL,"CANDIDATE_JSON"))?;
    if jcs(&intent)?!=intent_jcs {fail!(EINVAL,"CANDIDATE_CANONICAL");}
    intent_validation::check(&intent)?;
    if intent["purpose"]!="tuf-publication" {fail!(EINVAL,"CANDIDATE_PARENT_ROLE");}
    let metadata=&intent["metadata"][0];
    let (role,child_role)=match metadata["role"].as_str() {
        Some("snapshot")=>(Role::Snapshot,Role::Targets),
        Some("timestamp")=>(Role::Timestamp,Role::Snapshot),
        _=>fail!(EINVAL,"CANDIDATE_PARENT_ROLE"),
    };
    let link=&intent["linked_metadata"][0];
    let number=|value:&Value|value.as_u64().ok_or_else(||err!(EINVAL,"CANDIDATE_INTENT_SCHEMA"));
    let hash=|value:&Value| -> EnclaveResult<[u8;32]> {
        hex_bytes(value.as_str().ok_or_else(||err!(EINVAL,"CANDIDATE_INTENT_SCHEMA"))?,32,32)?
            .try_into().map_err(|_|err!(EINVAL,"CANDIDATE_HEX"))
    };
    let expected=ExpectedParent {role,base_version:number(&metadata["base_version"])?,
        new_version:number(&metadata["new_version"])?,signed_body_bytes:number(&metadata["signed_body_bytes"])?,
        signed_body_sha256:hash(&metadata["signed_body_sha256"])?,expires_utc_ms:number(&metadata["expires_utc_ms"])?,
        linked_child:ExpectedChild {role:child_role,version:number(&link["version"])?,
            length:number(&link["envelope_bytes"])?,sha256:hash(&link["envelope_sha256"])?}};
    verify_parent_linkage(client,&expected,signed_body,children,trusted_now)
}

/// Check candidate4 issuer -> SEP -> actual CTAP signatures against pinned inputs.
///
/// This checks one proof only. It does not sign, aggregate, establish current MDS
/// or enrollment policy, or durably commit counters/approvals. After a genuine
/// assertion its verified counter advances even if the final trusted-time read
/// denies success; callers must retain that progress atomically before any use.
/// Native ceremony execution must separately enforce its original local10s cap.
pub fn check_candidate_proof(
    bytes: &[u8], trust: &CandidateProofTrust<'_>, counters: &mut SignCountStore,
    mut trusted_time: impl FnMut() -> EnclaveResult<TrustedUtcRange>,
) -> EnclaveResult<CandidateProofFacts> {
    if bytes.is_empty() || bytes.len()>MAX_WIRE || trust.maximum_ttl_ms==0 || trust.maximum_ttl_ms>10_000 {
        fail!(EINVAL,"CANDIDATE_BOUND");
    }
    let Strict(value)=serde_json::from_slice(bytes).map_err(|_|err!(EINVAL,"CANDIDATE_JSON"))?;
    if jcs(&value)?!=bytes { fail!(EINVAL,"CANDIDATE_CANONICAL"); }
    let proof: Proof=serde_json::from_value(value).map_err(|_|err!(EINVAL,"CANDIDATE_SCHEMA"))?;
    let context=&proof.context;let freshness=&proof.freshness;let certificate=&freshness.certificate;
    if proof.protocol!="mcpmac.custodian-proof.v2" || context.protocol!="mcpmac.ceremony-context.v2"
        || certificate.protocol!="mcpmac.approval-freshness.v2" || jcs(&proof.intent)?!=trust.intent_jcs
        || jcs(context)?!=trust.context_jcs { fail!(EACCES,"CANDIDATE_BOUND_INPUT"); }
    let intent=&proof.intent;
    intent_validation::check(intent)?;
    if intent["protocol"]!="mcpmac.guarded-tuf-approval.v2" || intent["action"]!="A4"
        || !matches!(intent["profile"].as_str(),Some("L2"|"L3"))
        || !matches!(context.stage.as_str(),"administrative-consent"|"final-dispatch") {
        fail!(EACCES,"CANDIDATE_PURPOSE");
    }
    for (name, expected) in [("publication_id",certificate.publication_id.as_str()),("repository_id",&certificate.repository_id),
        ("purpose",&certificate.purpose),("policy_sha256",&certificate.policy_sha256)] {
        if intent[name].as_str()!=Some(expected) { fail!(EACCES,"CANDIDATE_TICKET_BINDING"); }
    }
    if !matches!(certificate.purpose.as_str(),"tuf-publication"|"unquarantine")
        || intent["policy_version"].as_u64()!=Some(certificate.policy_version)
        || intent["authority_generation"].as_u64()!=Some(certificate.authority_generation)
        || context.publication_id!=certificate.publication_id || context.policy_sha256!=certificate.policy_sha256
        || context.nonce_sha256!=certificate.nonce_sha256 || context.stage!=certificate.stage {
        fail!(EACCES,"CANDIDATE_TICKET_BINDING");
    }
    let mut constraints=intent.clone();constraints["authority_ticket_sha256"]=Value::String("0".repeat(64));
    matching_hash(&certificate.intent_constraints_sha256,&jcs(&constraints)?)?;
    let ticket=intent["authority_ticket_sha256"].as_str().ok_or_else(||err!(EINVAL,"CANDIDATE_TICKET"))?;
    matching_hash(ticket,&jcs(freshness)?)?;
    matching_hash(&freshness.issuer_key_sha256,trust.freshness_issuer.as_bytes())?;
    let signature=EdSignature::from_slice(&hex_bytes(&freshness.signature_ed25519_hex,64,64)?)
        .map_err(|_|err!(EACCES,"CANDIDATE_ISSUER_SIGNATURE"))?;
    let certificate_bytes=jcs(certificate)?;
    let mut issuer_message=b"MCPMac-Approval-Freshness-v2\0".to_vec();
    issuer_message.extend_from_slice(&(certificate_bytes.len() as u32).to_be_bytes());
    issuer_message.extend_from_slice(&certificate_bytes);
    trust.freshness_issuer.verify_strict(&issuer_message,&signature)
        .map_err(|_|err!(EACCES,"CANDIDATE_ISSUER_SIGNATURE"))?;
    if certificate.issued_utc_ms>certificate.not_before_utc_ms
        || certificate.not_before_utc_ms>=certificate.expires_utc_ms
        || certificate.expires_utc_ms.saturating_sub(certificate.issued_utc_ms)>trust.maximum_ttl_ms {
        fail!(EACCES,"CANDIDATE_FRESHNESS");
    }
    let initial_time=trusted_time()?;
    current(certificate,initial_time)?;
    let credential_id=hex_bytes(&proof.credential_id_hex,1,1023)?;
    if credential_id!=trust.credential.credential_id || proof.algorithm!=trust.credential.key.alg() {
        fail!(EACCES,"CANDIDATE_CREDENTIAL");
    }
    matching_hash(&context.credential_id_sha256,&credential_id)?;
    matching_hash(&context.sep_key_sha256,trust.sep_key.to_encoded_point(false).as_bytes())?;
    let mut fido_key=(proof.algorithm as i32).to_be_bytes().to_vec();
    let normalized=match &trust.credential.key {
        crate::ctap::assertion::CredentialKey::Ed25519(key)=>key.to_edwards().compress().to_bytes().to_vec(),
        crate::ctap::assertion::CredentialKey::Es256(key)=>key.to_encoded_point(false).as_bytes().to_vec(),
    };fido_key.extend_from_slice(&normalized);matching_hash(&context.fido_key_sha256,&fido_key)?;
    for value in [&context.custodian_id,&context.boot_id_sha256,&context.gui_session_sha256,&context.policy_sha256,&context.publication_id] {
        hex_bytes(value,32,32)?;
    }
    let nonce=hex_bytes(&context.nonce_sha256,32,32)?;let start=hex_bytes(&context.start_ns_hex,8,8)?;
    let intent_hash=digest(trust.intent_jcs);let context_hash=digest(trust.context_jcs);
    let signature_bytes=hex_bytes(&proof.sep_signature_hex,64,64)?;
    let signature=SepSignature::from_slice(&signature_bytes).map_err(|_|err!(EACCES,"CANDIDATE_SEP_SIGNATURE"))?;
    if signature.normalize_s().is_some() { fail!(EACCES,"CANDIDATE_SEP_HIGH_S"); }
    let mut sep=b"MCPMac-SEP-Approval-v2\0".to_vec();sep.extend_from_slice(&intent_hash);
    sep.extend_from_slice(&context_hash);sep.extend_from_slice(&nonce);sep.extend_from_slice(&start);
    trust.sep_key.verify(&sep,&signature).map_err(|_|err!(EACCES,"CANDIDATE_SEP_SIGNATURE"))?;
    let mut ctap=b"MCPMac-CTAP-Approval-v2\0".to_vec();ctap.extend_from_slice(&intent_hash);
    ctap.extend_from_slice(&context_hash);ctap.extend_from_slice(&signature_bytes);ctap.extend_from_slice(&start);
    let assertion=AssertionResponse { credential_id:Some(credential_id),
        auth_data:hex_bytes(&proof.authenticator_data_hex,37,4096)?,
        signature:hex_bytes(&proof.assertion_signature_hex,64,144)? };
    // Candidate4 negotiates no authenticator extensions. The broader CTAP
    // parser accepts well-formed extension maps for other operations.
    if assertion.auth_data[32] & crate::ctap::assertion::FLAG_ED != 0 {
        fail!(EACCES,"CANDIDATE_UNNEGOTIATED_EXTENSION");
    }
    verify_assertion(trust.credential,&assertion,&digest(&ctap),intent["profile"]=="L3",counters)?;
    let final_time=trusted_time()?;
    current(certificate,final_time)?;
    if final_time.latest<initial_time.earliest { fail!(EACCES,"CANDIDATE_TIME_REGRESSION"); }
    Ok(CandidateProofFacts {proof_sha256:digest(bytes),intent_sha256:intent_hash,
        sign_count:counters.get_credential(trust.credential)})
}

#[cfg(test)]
#[path = "guarded_approval_tests.rs"]
mod tests;
