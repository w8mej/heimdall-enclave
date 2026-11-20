//! Byzantine PoisonReceipt generation and verification (FS-702 §4.2 step 3).
//!
//! Emitted when a peer serves a slice that fails Bao Merkle verification over mTLS.
//! Binds TLS session exporter / binding, offending peer ID, target root, slice index,
//! expected slice hash, and corrupted slice payload. Signed by the detecting node.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};

/// Structured signed proof of peer data poisoning (FS-702 §4.2 step 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoisonReceipt {
    /// Signing node ID / public key (hex-encoded Ed25519 public key).
    pub detector_id: String,
    /// Offending peer ID / node ID / SVID.
    pub peer_id: String,
    /// CAS target logical plaintext or ciphertext root.
    pub target_root: String,
    /// Corrupted slice index.
    pub slice_index: u64,
    /// Expected Bao parent / slice hash (hex-encoded).
    pub expected_hash: String,
    /// BLAKE3 digest of the corrupted slice received from the peer (hex-encoded).
    pub received_slice_blake3: String,
    /// TLS session exporter / binding token (hex-encoded).
    pub session_binding: String,
    /// Detection timestamp (UTC milliseconds).
    pub timestamp_utc_ms: u64,
    /// Ed25519 signature by detector over Canonical JSON representation of receipt claims.
    pub signature_hex: String,
}

/// Evidence collected when detecting Byzantine slice data corruption.
#[derive(Debug, Clone, Copy)]
pub struct PoisonEvidence<'a> {
    /// Offending peer ID / node ID / SVID.
    pub peer_id: &'a str,
    /// CAS target logical plaintext or ciphertext root.
    pub target_root: &'a str,
    /// Corrupted slice index.
    pub slice_index: u64,
    /// Expected Bao parent / slice hash (hex-encoded).
    pub expected_hash: &'a str,
    /// Corrupted slice payload bytes received from peer.
    pub corrupted_slice: &'a [u8],
    /// TLS session exporter / binding token (hex-encoded).
    pub session_binding: &'a str,
    /// Detection timestamp (UTC milliseconds).
    pub timestamp_utc_ms: u64,
}

impl PoisonReceipt {
    /// Build unsigned receipt claims with domain-separation prefix (DEFECT-F-59).
    fn claims_bytes(&self) -> Vec<u8> {
        let claims = serde_json::json!({
            "detector_id": self.detector_id,
            "expected_hash": self.expected_hash,
            "peer_id": self.peer_id,
            "received_slice_blake3": self.received_slice_blake3,
            "session_binding": self.session_binding,
            "slice_index": self.slice_index,
            "target_root": self.target_root,
            "timestamp_utc_ms": self.timestamp_utc_ms,
        });
        let mut out = b"enclave-swarm-poison-receipt-v1:".to_vec();
        out.extend_from_slice(&serde_json::to_vec(&claims).unwrap_or_default());
        out
    }

    /// Construct and sign a new PoisonReceipt using the detecting node's signing key.
    pub fn sign(signing_key: &SigningKey, evidence: &PoisonEvidence) -> Self {
        let detector_id = hex::encode(signing_key.verifying_key().as_bytes());
        let received_slice_blake3 = blake3::hash(evidence.corrupted_slice).to_hex().to_string();

        let mut receipt = Self {
            detector_id,
            peer_id: evidence.peer_id.to_string(),
            target_root: evidence.target_root.to_string(),
            slice_index: evidence.slice_index,
            expected_hash: evidence.expected_hash.to_string(),
            received_slice_blake3,
            session_binding: evidence.session_binding.to_string(),
            timestamp_utc_ms: evidence.timestamp_utc_ms,
            signature_hex: String::new(),
        };

        let msg = receipt.claims_bytes();
        let sig = signing_key.sign(&msg);
        receipt.signature_hex = hex::encode(sig.to_bytes());
        receipt
    }

    /// Verify the signature and structural consistency of a PoisonReceipt.
    pub fn verify(&self) -> EnclaveResult<()> {
        let vk_bytes = hex::decode(&self.detector_id)
            .map_err(|e| err!(EINVAL, "RECEIPT_DETECTOR_ID", "{e}"))?;
        if vk_bytes.len() != 32 {
            fail!(
                EINVAL,
                "RECEIPT_KEY_LEN",
                "detector public key must be 32 bytes"
            );
        }
        let vk = VerifyingKey::from_bytes(vk_bytes.as_slice().try_into().unwrap())
            .map_err(|e| err!(EINVAL, "RECEIPT_KEY_PARSE", "{e}"))?;

        let sig_bytes =
            hex::decode(&self.signature_hex).map_err(|e| err!(EINVAL, "RECEIPT_SIG_HEX", "{e}"))?;
        if sig_bytes.len() != 64 {
            fail!(EINVAL, "RECEIPT_SIG_LEN", "signature must be 64 bytes");
        }
        let sig = ed25519_dalek::Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());

        let msg = self.claims_bytes();
        vk.verify(&msg, &sig)
            .map_err(|e| err!(EACCES, "RECEIPT_SIGNATURE_INVALID", "{e}"))?;
        Ok(())
    }
}

/// Thread-safe Byzantine peer quarantine blacklist table (GAP-59 / FS-702 §4.2).
#[derive(Debug, Default)]
pub struct QuarantineTable {
    quarantined: std::sync::RwLock<std::collections::HashSet<String>>,
}

/// Retains the quarantine read lock through one actual nonblocking enqueue.
#[derive(Debug)]
pub(crate) struct QuarantineReadGuard<'a> {
    set:std::sync::RwLockReadGuard<'a,std::collections::HashSet<String>>,
}
impl QuarantineReadGuard<'_> {
    pub(crate) fn contains(&self,peer:&str)->bool { self.set.contains(peer) }
}

impl QuarantineTable {
    /// Create an empty quarantine blacklist table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an offending peer ID to quarantine upon receiving a valid PoisonReceipt.
    pub fn quarantine_peer(&self, peer_id: &str) {
        let mut set = self.quarantined.write().unwrap();
        set.insert(peer_id.to_string());
    }

    /// Assert that peer is not quarantined.
    pub fn check_peer(&self, peer_id: &str) -> EnclaveResult<()> {
        let set = self.quarantined.read().unwrap();
        if set.contains(peer_id) {
            fail!(
                EPERM,
                "PEER_QUARANTINED_BYZANTINE",
                "Peer {peer_id} is quarantined due to detected slice poisoning"
            );
        }
        Ok(())
    }

    /// Check whether a peer is quarantined.
    pub fn is_quarantined(&self, peer_id: &str) -> bool {
        self.quarantined.read().unwrap().contains(peer_id)
    }

    /// Final handoff never waits for, or recovers, quarantined-state writers.
    pub(crate) fn try_read_guard(&self)->Result<QuarantineReadGuard<'_>,enclave_core::enterprise_authority::FinalReleaseRefusal> {
        use enclave_core::{enterprise_authority::FinalReleaseRefusal,error::Errno};
        let set=self.quarantined.try_read().map_err(|error|match error {
            std::sync::TryLockError::WouldBlock=>FinalReleaseRefusal::new(Errno::EAGAIN,"QUARANTINE_BUSY"),
            std::sync::TryLockError::Poisoned(_)=>FinalReleaseRefusal::new(Errno::EIO,"QUARANTINE_POISONED"),
        })?;
        Ok(QuarantineReadGuard{set})
    }

    #[cfg(test)]
    pub(crate) fn try_write_for_test(&self)->std::sync::TryLockResult<std::sync::RwLockWriteGuard<'_,std::collections::HashSet<String>>> {
        self.quarantined.try_write()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poison_receipt_sign_and_verify() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let peer_id = "peer-node-99";
        let target_root = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let slice_idx = 7;
        let expected_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let corrupted_slice = b"this is corrupted slice data injected by byzantine node";
        let session_binding = "b160c87b9c6560da";
        let ts = 1730900000000;

        let evidence = PoisonEvidence {
            peer_id,
            target_root,
            slice_index: slice_idx,
            expected_hash,
            corrupted_slice,
            session_binding,
            timestamp_utc_ms: ts,
        };

        let receipt = PoisonReceipt::sign(&signing_key, &evidence);

        assert_eq!(receipt.peer_id, peer_id);
        assert_eq!(receipt.slice_index, 7);
        assert_eq!(
            receipt.received_slice_blake3,
            blake3::hash(corrupted_slice).to_hex().to_string()
        );
        assert!(receipt.verify().is_ok());

        // Tampering with claim must fail verification
        let mut tampered = receipt.clone();
        tampered.slice_index = 8;
        assert!(tampered.verify().is_err());

        // Tampering with signature must fail verification
        let mut tampered_sig = receipt.clone();
        tampered_sig.signature_hex = hex::encode([0xffu8; 64]);
        assert!(tampered_sig.verify().is_err());
    }
}
