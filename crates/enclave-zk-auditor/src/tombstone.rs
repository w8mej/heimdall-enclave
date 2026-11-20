//! `AbortedPreEgressTombstone` dual co-signatures (FS-705 §3.2.2, ADR-016):
//! a slot wiped before egress is accounted for only if **both** UID 703
//! (`_piivault`) and UID 704 (`_enclaveifc`) signed
//! `tombstone_message(slot, boot_epoch_id, egress_released = false)`.

use ed25519_dalek::{Signature, VerifyingKey};
use enclave_core::audit::tombstone_message;
use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};

/// A co-signed tombstone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tombstone {
    /// Slot (`rpc_seq_u64`).
    pub slot: u64,
    /// Boot epoch.
    pub boot_epoch_id: String,
    /// UID 703 signature.
    #[serde(with = "serde_bytes")]
    pub sig_703: Vec<u8>,
    /// UID 704 signature.
    #[serde(with = "serde_bytes")]
    pub sig_704: Vec<u8>,
}

/// Pinned co-signer keys.
#[derive(Debug, Clone)]
pub struct TombstoneKeys {
    /// UID 703 tombstone key.
    pub k703: VerifyingKey,
    /// UID 704 tombstone key.
    pub k704: VerifyingKey,
}

impl Tombstone {
    /// Verify both signatures (a single compromised daemon cannot forge an abort).
    pub fn verify(&self, keys: &TombstoneKeys) -> EnclaveResult<()> {
        let m = tombstone_message(self.slot, &self.boot_epoch_id);
        for (k, s, who) in [
            (&keys.k703, &self.sig_703, "703"),
            (&keys.k704, &self.sig_704, "704"),
        ] {
            let sig = Signature::from_slice(s)
                .map_err(|_| err!(EACCES, "TOMBSTONE_SIGNATURE", "{who}"))?;
            if k.verify_strict(&m, &sig).is_err() {
                fail!(
                    EACCES,
                    "TOMBSTONE_SIGNATURE",
                    "UID {who} co-signature invalid"
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn requires_both_daemons() {
        let (a, b) = (
            SigningKey::generate(&mut rand_core::OsRng),
            SigningKey::generate(&mut rand_core::OsRng),
        );
        let keys = TombstoneKeys {
            k703: a.verifying_key(),
            k704: b.verifying_key(),
        };
        let epoch = enclave_core::seq::new_boot_epoch_id();
        let m = tombstone_message(42, &epoch);
        let t = Tombstone {
            slot: 42,
            boot_epoch_id: epoch.clone(),
            sig_703: a.sign(&m).to_bytes().to_vec(),
            sig_704: b.sign(&m).to_bytes().to_vec(),
        };
        t.verify(&keys).unwrap();
        // UID 703 alone forging both halves fails.
        let forged = Tombstone {
            sig_704: a.sign(&m).to_bytes().to_vec(),
            ..t.clone()
        };
        assert!(forged.verify(&keys).is_err());
        // Replaying a tombstone for another slot fails.
        assert!(Tombstone { slot: 43, ..t }.verify(&keys).is_err());
    }
}
