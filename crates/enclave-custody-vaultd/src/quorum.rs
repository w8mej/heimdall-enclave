//! ADR-013 discrete `k`-of-`n` hardware quorum built from independent
//! `CTAP 2.1` assertions over **one** JCS grant digest (`L3` `A4` org root
//! mutations, per-host `UnquarantineGrant`s). Each custodian's YubiKey signs
//! `authenticatorData ‖ clientDataHash` with `clientDataHash = SHA-256(JCS(grant))`;
//! assertions are counted per distinct enrolled credential and normalized key
//! within the 24-hour collection TTL. This legacy helper does not authenticate
//! custodian identity or its unsigned collection time and is not the guarded
//! publisher protocol. Production org-root acquisition remains unavailable.

use std::collections::BTreeSet;

use enclave_core::error::EnclaveResult;
use enclave_core::fail;
use serde::{Deserialize, Serialize};

use crate::ctap::assertion::{
    verify_assertion, AssertionResponse, EnrolledCredential, SignCountStore,
};

/// Candidate local durable consumption/aggregation only. This is not the
/// production guarded signer protocol and returns no authorization capability.
#[path = "quorum_durable.rs"]
pub mod durable;

/// One collected approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumApproval {
    /// Credential ID that produced it.
    #[serde(with = "serde_bytes")]
    pub credential_id: Vec<u8>,
    /// Raw authenticator data.
    #[serde(with = "serde_bytes")]
    pub auth_data: Vec<u8>,
    /// Signature.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// Collection time (Unix seconds).
    pub collected_at: i64,
}

/// Collection TTL (24 h).
pub const QUORUM_TTL_S: i64 = 24 * 3600;

/// Verify `k` distinct enrolled custodians approved `grant_digest`.
pub fn verify_quorum(
    enrolled: &[EnrolledCredential],
    k: usize,
    grant_digest: &[u8; 32],
    approvals: &[QuorumApproval],
    counters: &mut SignCountStore,
    now: i64,
) -> EnclaveResult<usize> {
    verify_quorum_ext(enrolled, k, grant_digest, approvals, false, counters, now)
}

/// Verify `k` distinct enrolled custodians approved `grant_digest`, with optional `require_uv`
/// and two-phase transactional commit on `SignCountStore` (GAP-14, DEFECT-F-17).
pub fn verify_quorum_ext(
    enrolled: &[EnrolledCredential],
    k: usize,
    grant_digest: &[u8; 32],
    approvals: &[QuorumApproval],
    require_uv: bool,
    counters: &mut SignCountStore,
    now: i64,
) -> EnclaveResult<usize> {
    if k == 0 || k > enrolled.len() {
        fail!(EINVAL, "QUORUM_BAD_THRESHOLD");
    }
    let mut credential_ids = BTreeSet::new();
    let mut public_keys = BTreeSet::new();
    for credential in enrolled {
        let key = match &credential.key {
            crate::ctap::assertion::CredentialKey::Ed25519(key) =>
                key.to_edwards().compress().to_bytes().to_vec(),
            crate::ctap::assertion::CredentialKey::Es256(key) =>
                key.to_encoded_point(false).as_bytes().to_vec(),
        };
        if credential.credential_id.is_empty()
            || !credential_ids.insert(credential.credential_id.as_slice())
            || !public_keys.insert((credential.key.alg(), key))
        {
            fail!(EINVAL, "QUORUM_DUPLICATE_ENROLLMENT");
        }
    }
    let mut staged_counters = counters.clone();
    let mut ok: BTreeSet<Vec<u8>> = BTreeSet::new();
    for a in approvals {
        if ok.contains(&a.credential_id)
            || now < a.collected_at
            || now.checked_sub(a.collected_at).is_none_or(|age| age > QUORUM_TTL_S)
        {
            continue;
        }
        let Some(cred) = enrolled.iter().find(|c| c.credential_id == a.credential_id) else {
            continue;
        };
        let resp = AssertionResponse {
            credential_id: Some(a.credential_id.clone()),
            auth_data: a.auth_data.clone(),
            signature: a.signature.clone(),
        };
        if verify_assertion(cred, &resp, grant_digest, require_uv, &mut staged_counters).is_ok() {
            ok.insert(a.credential_id.clone());
        }
    }
    if ok.len() < k {
        // Quorum not met: staged counters are discarded without burning / advancing store
        fail!(EACCES, "QUORUM_NOT_MET", "{} of {k}", ok.len());
    }
    // Commit staged counters only when quorum is fully satisfied
    *counters = staged_counters;
    Ok(ok.len())
}

#[cfg(test)]
#[path = "quorum_tests.rs"]
mod tests;
