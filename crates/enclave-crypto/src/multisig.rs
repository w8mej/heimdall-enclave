//! ADR-013 discrete `k`-of-`n` `Ed25519` hardware multi-signatures.
//!
//! Each of `k` distinct enrolled custodian keys signs the *same* digest
//! independently (in production: `k` CTAP 2.1 assertions over one JCS grant
//! digest). There is no interactive threshold protocol: unratified threshold
//! Schnorr schemes are not used because stock authenticators cannot run them.
//! Verification counts distinct enrolled keys with a valid signature; unknown
//! keys, duplicates and invalid signatures never count toward `k`.

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, VerifyingKey};
use enclave_core::error::EnclaveResult;
use enclave_core::fail;
use serde::{Deserialize, Serialize};

/// One partial approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumSignature {
    /// Raw 32-byte Ed25519 public key.
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    /// 64-byte signature.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// Collection time (ms) — used for the 24h quorum-collection TTL.
    pub collected_at_ms: u64,
}

/// A `k`-of-`n` policy over an enrolled set.
#[derive(Debug, Clone)]
pub struct QuorumPolicy {
    enrolled: Vec<VerifyingKey>,
    threshold: usize,
    /// Quorum-collection TTL (FS-703 §4.3: 24h).
    pub collection_ttl_ms: u64,
}

impl QuorumPolicy {
    /// Build. `1 <= k <= n` and enrolled keys must be distinct.
    pub fn new(enrolled: Vec<VerifyingKey>, threshold: usize) -> EnclaveResult<Self> {
        let distinct: BTreeSet<[u8; 32]> = enrolled.iter().map(|k| k.to_bytes()).collect();
        if distinct.len() != enrolled.len() {
            fail!(EINVAL, "QUORUM_DUPLICATE_ENROLLMENT");
        }
        if threshold == 0 || threshold > enrolled.len() {
            fail!(
                EINVAL,
                "QUORUM_BAD_THRESHOLD",
                "{threshold}-of-{}",
                enrolled.len()
            );
        }
        Ok(Self {
            enrolled,
            threshold,
            collection_ttl_ms: 24 * 3_600_000,
        })
    }
    /// `k`.
    pub fn threshold(&self) -> usize {
        self.threshold
    }
    /// `n`.
    pub fn n(&self) -> usize {
        self.enrolled.len()
    }

    /// Verify that at least `k` distinct enrolled keys signed `digest`, all
    /// within the collection TTL ending at `now_ms`. Returns the signer count.
    pub fn verify(
        &self,
        digest: &[u8],
        sigs: &[QuorumSignature],
        now_ms: u64,
    ) -> EnclaveResult<usize> {
        let mut counted: BTreeSet<[u8; 32]> = BTreeSet::new();
        for s in sigs {
            let Ok(pk) = <[u8; 32]>::try_from(s.public_key.as_slice()) else {
                continue;
            };
            if !self.enrolled.iter().any(|e| e.to_bytes() == pk) || counted.contains(&pk) {
                continue;
            }
            if now_ms < s.collected_at_ms || now_ms - s.collected_at_ms > self.collection_ttl_ms {
                continue;
            }
            let (Ok(vk), Ok(sig)) = (
                VerifyingKey::from_bytes(&pk),
                Signature::from_slice(&s.signature),
            ) else {
                continue;
            };
            if vk.verify_strict(digest, &sig).is_ok() {
                counted.insert(pk);
            }
        }
        if counted.len() < self.threshold {
            fail!(
                EACCES,
                "QUORUM_NOT_MET",
                "{} of required {}",
                counted.len(),
                self.threshold
            );
        }
        Ok(counted.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

    fn keys(n: usize) -> Vec<SigningKey> {
        (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
    }

    fn sign(k: &SigningKey, d: &[u8], t: u64) -> QuorumSignature {
        QuorumSignature {
            public_key: k.verifying_key().to_bytes().to_vec(),
            signature: k.sign(d).to_bytes().to_vec(),
            collected_at_ms: t,
        }
    }

    #[test]
    fn two_of_three() {
        let ks = keys(3);
        let p = QuorumPolicy::new(ks.iter().map(|k| k.verifying_key()).collect(), 2).unwrap();
        let d = b"jcs-grant-digest";
        assert_eq!(
            p.verify(d, &[sign(&ks[0], d, 0), sign(&ks[2], d, 10)], 100)
                .unwrap(),
            2
        );
        // Duplicate signer does not count twice.
        assert!(p
            .verify(d, &[sign(&ks[0], d, 0), sign(&ks[0], d, 0)], 100)
            .is_err());
        // Outsider does not count.
        let outsider = keys(1);
        assert!(p
            .verify(d, &[sign(&ks[0], d, 0), sign(&outsider[0], d, 0)], 100)
            .is_err());
        // Signature over a different digest does not count.
        assert!(p
            .verify(d, &[sign(&ks[0], d, 0), sign(&ks[1], b"other", 0)], 100)
            .is_err());
        // Expired collection.
        assert!(p
            .verify(
                d,
                &[sign(&ks[0], d, 0), sign(&ks[1], d, 0)],
                24 * 3_600_000 + 1
            )
            .is_err());
    }

    #[test]
    fn bad_policies_rejected() {
        let ks = keys(2);
        let vks: Vec<_> = ks.iter().map(|k| k.verifying_key()).collect();
        assert!(QuorumPolicy::new(vks.clone(), 3).is_err());
        assert!(QuorumPolicy::new(vks.clone(), 0).is_err());
        assert!(QuorumPolicy::new(vec![vks[0], vks[0]], 1).is_err());
    }
}
