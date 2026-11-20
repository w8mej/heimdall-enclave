//! Succinct pre-egress redaction proof (pi_redact) for L3 synchronous egress gating (GAP-25, FS-705 §4.3.1).
//!
//! Evaluates the in-circuit redaction DFA over chunks <= 64 KiB, proving the absence of
//! unredacted SSN/C4 data before any bytes cross an external sink. Verification latency
//! is budgeted to < 1.5 ms.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use enclave_core::error::EnclaveResult;
use enclave_core::ipc::{from_cbor, to_cbor};
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};

use crate::zk::lasso_dfa::{eval_dfa_bytes, STATE_REJECT};

/// Maximum chunk size permitted through the egress gate (64 KiB, FS-705 §4.3.1).
pub const MAX_CHUNK_SIZE: usize = 64 * 1024;

/// Domain separator for pi_redact proof signature binding.
pub const PI_REDACT_SIG_DOMAIN: &[u8] = b"depot-pi_redact-v1";

/// Succinct pre-egress redaction proof (pi_redact).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactProofV1 {
    /// Schema version (1).
    pub schema_version: u32,
    /// Blake3 hash of the request/decision envelope or payload context (D_JCS).
    pub d_jcs_hash: [u8; 32],
    /// Blake3 hash of the chunk payload.
    pub chunk_hash: [u8; 32],
    /// Byte length of the chunk (<= 64 KiB).
    pub chunk_len: u32,
    /// Wall-clock timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Final DFA state achieved after scanning chunk.
    pub dfa_final_state: u32,
    /// Ed25519 signature by UID 705's redaction authority key.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// Verifying key bytes of UID 705.
    pub signer_pubkey: [u8; 32],
}

impl RedactProofV1 {
    /// Construct and sign a new `RedactProofV1`.
    pub fn create(
        signing_key: &SigningKey,
        d_jcs_hash: [u8; 32],
        chunk_hash: [u8; 32],
        chunk_len: u32,
        timestamp_ns: u64,
        dfa_final_state: u32,
    ) -> Self {
        let signer_pubkey = signing_key.verifying_key().to_bytes();
        let signing_bytes = Self::digest_for_signing(
            &d_jcs_hash,
            &chunk_hash,
            chunk_len,
            timestamp_ns,
            dfa_final_state,
        );
        let sig = signing_key.sign(&signing_bytes);
        Self {
            schema_version: 1,
            d_jcs_hash,
            chunk_hash,
            chunk_len,
            timestamp_ns,
            dfa_final_state,
            signature: sig.to_bytes().to_vec(),
            signer_pubkey,
        }
    }

    /// Compute canonical digest for signing.
    fn digest_for_signing(
        d_jcs_hash: &[u8; 32],
        chunk_hash: &[u8; 32],
        chunk_len: u32,
        timestamp_ns: u64,
        dfa_final_state: u32,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(&blake3::hash(PI_REDACT_SIG_DOMAIN).into());
        hasher.update(d_jcs_hash);
        hasher.update(chunk_hash);
        hasher.update(&chunk_len.to_le_bytes());
        hasher.update(&timestamp_ns.to_le_bytes());
        hasher.update(&dfa_final_state.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Verify this proof against expected context, chunk hash, and optional pinned signer.
    pub fn verify(
        &self,
        expected_signer: Option<&VerifyingKey>,
        expected_d_jcs_hash: &[u8; 32],
        expected_chunk_hash: &[u8; 32],
    ) -> EnclaveResult<()> {
        if self.schema_version != 1 {
            fail!(
                EINVAL,
                "INVALID_PI_REDACT_VERSION",
                "got {}",
                self.schema_version
            );
        }
        if self.chunk_len as usize > MAX_CHUNK_SIZE {
            fail!(EINVAL, "CHUNK_TOO_LARGE", "{} > 65536", self.chunk_len);
        }
        if self.dfa_final_state == STATE_REJECT {
            fail!(EPERM, "UNREDACTED_C4_IN_PROOF", "DFA ended in reject state");
        }
        if &self.d_jcs_hash != expected_d_jcs_hash {
            fail!(EACCES, "D_JCS_HASH_MISMATCH");
        }
        if &self.chunk_hash != expected_chunk_hash {
            fail!(EACCES, "CHUNK_HASH_MISMATCH");
        }

        let vk = VerifyingKey::from_bytes(&self.signer_pubkey)
            .map_err(|e| err!(EINVAL, "INVALID_SIGNER_KEY", "{e}"))?;

        if let Some(expected_vk) = expected_signer {
            if &vk != expected_vk {
                fail!(EACCES, "SIGNER_MISMATCH");
            }
        }

        let signing_bytes = Self::digest_for_signing(
            &self.d_jcs_hash,
            &self.chunk_hash,
            self.chunk_len,
            self.timestamp_ns,
            self.dfa_final_state,
        );
        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| err!(EINVAL, "INVALID_SIG_LEN", "expected 64 bytes"))?;
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify(&signing_bytes, &sig)
            .map_err(|e| err!(EACCES, "INVALID_PI_REDACT_SIG", "{e}"))?;

        Ok(())
    }

    /// Encode proof to CBOR bytes.
    pub fn to_bytes(&self) -> EnclaveResult<Vec<u8>> {
        to_cbor(self)
    }

    /// Decode proof from CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> EnclaveResult<Self> {
        from_cbor(bytes)
    }
}

/// Evaluate redaction DFA over `chunk` and generate a `RedactProofV1`.
pub fn evaluate_and_prove_chunk(
    signing_key: &SigningKey,
    d_jcs: &[u8],
    chunk: &[u8],
    timestamp_ns: u64,
) -> EnclaveResult<RedactProofV1> {
    evaluate_and_prove_chunk_with_state(signing_key, d_jcs, chunk, 0, timestamp_ns)
}

/// Evaluate redaction DFA over `chunk` starting from `initial_state` and generate a `RedactProofV1`.
pub fn evaluate_and_prove_chunk_with_state(
    signing_key: &SigningKey,
    d_jcs: &[u8],
    chunk: &[u8],
    initial_state: u32,
    timestamp_ns: u64,
) -> EnclaveResult<RedactProofV1> {
    if chunk.len() > MAX_CHUNK_SIZE {
        fail!(EINVAL, "CHUNK_TOO_LARGE", "{} > 65536", chunk.len());
    }

    // Evaluate in-circuit DFA
    let (final_state, reached_reject) = eval_dfa_bytes(initial_state, chunk);
    if reached_reject {
        fail!(
            EPERM,
            "UNREDACTED_C4_IN_EGRESS",
            "Unredacted C4 pattern detected in egress chunk"
        );
    }

    let d_jcs_hash: [u8; 32] = *blake3::hash(d_jcs).as_bytes();
    let chunk_hash: [u8; 32] = *blake3::hash(chunk).as_bytes();

    Ok(RedactProofV1::create(
        signing_key,
        d_jcs_hash,
        chunk_hash,
        chunk.len() as u32,
        timestamp_ns,
        final_state,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prove_and_verify_valid_chunk() {
        let sk = SigningKey::generate(&mut rand_core::OsRng);
        let vk = sk.verifying_key();
        let d_jcs = b"{\"action\":\"query\",\"table\":\"users\"}";
        let chunk = b"User ID 42 query result: John Doe, anonymized record.";

        let proof = evaluate_and_prove_chunk(&sk, d_jcs, chunk, 1_000_000_000).unwrap();
        let d_jcs_hash = *blake3::hash(d_jcs).as_bytes();
        let chunk_hash = *blake3::hash(chunk).as_bytes();

        assert!(proof.verify(Some(&vk), &d_jcs_hash, &chunk_hash).is_ok());

        // Serialization round-trip
        let bytes = proof.to_bytes().unwrap();
        let decoded = RedactProofV1::from_bytes(&bytes).unwrap();
        assert_eq!(proof, decoded);
    }

    #[test]
    fn test_unredacted_c4_rejected() {
        let sk = SigningKey::generate(&mut rand_core::OsRng);
        let d_jcs = b"{\"action\":\"export\"}";
        let chunk = b"Customer SSN: 123-45-6789 confidential";

        let err = evaluate_and_prove_chunk(&sk, d_jcs, chunk, 1_000_000_000).unwrap_err();
        assert!(err.is("UNREDACTED_C4_IN_EGRESS"));
    }

    #[test]
    fn test_chunk_too_large_rejected() {
        let sk = SigningKey::generate(&mut rand_core::OsRng);
        let d_jcs = b"{}";
        let chunk = vec![0u8; MAX_CHUNK_SIZE + 1];

        let err = evaluate_and_prove_chunk(&sk, d_jcs, &chunk, 1_000_000_000).unwrap_err();
        assert!(err.is("CHUNK_TOO_LARGE"));
    }

    #[test]
    fn test_tampered_proof_rejected() {
        let sk = SigningKey::generate(&mut rand_core::OsRng);
        let vk = sk.verifying_key();
        let d_jcs = b"context";
        let chunk = b"clean data";
        let mut proof = evaluate_and_prove_chunk(&sk, d_jcs, chunk, 1_000_000_000).unwrap();

        let d_jcs_hash = *blake3::hash(d_jcs).as_bytes();
        let chunk_hash = *blake3::hash(chunk).as_bytes();

        // Tamper chunk_hash
        proof.chunk_hash[0] ^= 0xff;
        assert!(proof.verify(Some(&vk), &d_jcs_hash, &chunk_hash).is_err());
    }
}
