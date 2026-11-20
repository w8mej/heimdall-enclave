//! GAP-27, ADR-010: UID 703 is the sequence authority. It signs one
//! `BootEpoch` per boot with the SEP epoch key (P-256 ECDSA); every other
//! daemon verifies that signature before it records a governed slot of the
//! epoch, and pins the signer key: the first verified key is sealed in the
//! daemon's state (`epoch-signer`), and a later epoch signed by another key
//! is refused (`EPOCH_SIGNER_CHANGED`). Together with the authenticated
//! channel to UID 703 (GAP-02) this anchors every journal's
//! `(boot_epoch_id, rpc_seq_u64)` to one hardware key.

use std::path::Path;
use std::sync::Mutex;

use enclave_core::error::EnclaveResult;
use enclave_core::sealed::{Loaded, SealedStore};
use enclave_core::seq::{epoch_signing_message, validate_epoch_id, BootEpoch};
use enclave_core::{err, fail};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Verify a `BootEpoch`'s signature by the key it names.
pub fn verify(be: &BootEpoch) -> EnclaveResult<()> {
    validate_epoch_id(&be.boot_epoch_id)?;
    let vk = VerifyingKey::from_sec1_bytes(&be.signer_public_key)
        .map_err(|_| err!(EACCES, "EPOCH_SIGNER_KEY"))?;
    let sig = Signature::from_der(&be.signature)
        .or_else(|_| Signature::from_slice(&be.signature))
        .map_err(|_| err!(EACCES, "EPOCH_SIGNATURE_MALFORMED"))?;
    vk.verify(&epoch_signing_message(&be.boot_epoch_id), &sig)
        .map_err(|_| err!(EACCES, "EPOCH_SIGNATURE_INVALID"))
}

/// A software epoch signer (tests; the SEP signs on hardware).
#[derive(Clone)]
pub struct EpochSigner(SigningKey);

impl std::fmt::Debug for EpochSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EpochSigner")
    }
}

impl EpochSigner {
    /// A fresh key.
    pub fn random() -> Self {
        Self(SigningKey::random(&mut rand_core::OsRng))
    }
    /// SEC1 uncompressed public key.
    pub fn public_key(&self) -> Vec<u8> {
        self.0
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }
    /// DER signature over [`epoch_signing_message`].
    pub fn sign_message(&self, msg: &[u8]) -> Vec<u8> {
        let s: Signature = self.0.sign(msg);
        s.to_der().as_bytes().to_vec()
    }
    /// Sign `boot_epoch_id`.
    pub fn sign(&self, boot_epoch_id: &str) -> BootEpoch {
        BootEpoch {
            boot_epoch_id: boot_epoch_id.to_owned(),
            signature: self.sign_message(&epoch_signing_message(boot_epoch_id)),
            signer_public_key: self.public_key(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Pin {
    signer_public_key: String,
}

#[derive(Debug)]
enum PinState {
    Unpinned,
    Pinned(Vec<u8>),
    // A failed save may already have published authenticated signer state.
    // Never retry persistence or grant pin authority on this live verifier.
    Uncertain,
}

/// Verifies epochs and pins their signer (trust on first verified epoch).
#[derive(Debug)]
pub struct EpochVerifier {
    pinned: Mutex<PinState>,
    store: Mutex<Option<SealedStore>>,
}

impl EpochVerifier {
    /// Pin kept in memory only (tests; daemons without a state directory).
    pub fn volatile() -> Self {
        Self {
            pinned: Mutex::new(PinState::Unpinned),
            store: Mutex::new(None),
        }
    }

    /// Load the pin sealed in `dir` (`epoch-signer`). A deleted, edited or
    /// rolled-back pin refuses to start (`EPOCH_PIN_STATE`).
    pub fn open(dir: Option<&Path>) -> EnclaveResult<Self> {
        let Some(d) = dir else {
            return Ok(Self::volatile());
        };
        let (store, loaded) = SealedStore::open(d, "epoch-signer")
            .map_err(|e| err!(EACCES, "EPOCH_PIN_STATE", "{e}"))?;
        let pinned = match loaded {
            Loaded::Fresh => PinState::Unpinned,
            Loaded::State(b) => {
                let p: Pin = enclave_core::sealed::decode(&b)?;
                PinState::Pinned(
                    hex::decode(p.signer_public_key)
                        .map_err(|_| err!(EACCES, "EPOCH_PIN_STATE"))?,
                )
            }
        };
        Ok(Self {
            pinned: Mutex::new(pinned),
            store: Mutex::new(Some(store)),
        })
    }

    /// Verify `be` and its signer against the pin, pinning on first use.
    /// A persistent save failure returns its original error and permanently
    /// fences subsequent valid checks on this object (`EPOCH_PIN_UNCERTAIN`).
    pub fn check(&self, be: &BootEpoch) -> EnclaveResult<()> {
        verify(be)?;
        let mut pin = self
            .pinned
            .lock()
            .map_err(|_| err!(EIO, "EPOCH_PIN_POISONED"))?;
        match &*pin {
            PinState::Uncertain => fail!(EIO, "EPOCH_PIN_UNCERTAIN"),
            PinState::Pinned(k) if k == &be.signer_public_key => Ok(()),
            PinState::Pinned(_) => fail!(
                EACCES,
                "EPOCH_SIGNER_CHANGED",
                "boot epoch {} is signed by a key other than the pinned SEP epoch key",
                be.boot_epoch_id
            ),
            PinState::Unpinned => {
                if let Some(s) = self
                    .store
                    .lock()
                    .map_err(|_| err!(EIO, "EPOCH_PIN_POISONED"))?
                    .as_mut()
                {
                    if let Err(error) = s.save_json(&Pin {
                        signer_public_key: hex::encode(&be.signer_public_key),
                    }) {
                        // State publication precedes the checkpoint. Latch
                        // uncertainty while holding the same pin mutex that
                        // serializes every check, preserving the first error.
                        *pin = PinState::Uncertain;
                        return Err(error);
                    }
                }
                *pin = PinState::Pinned(be.signer_public_key.clone());
                Ok(())
            }
        }
    }

    /// The successfully pinned signer key, if any. `None` also covers an
    /// uncertain verifier and never authorizes an epoch; use [`Self::check`].
    pub fn pinned(&self) -> Option<Vec<u8>> {
        self.pinned.lock().ok().and_then(|p| match &*p {
            PinState::Pinned(key) => Some(key.clone()),
            PinState::Unpinned | PinState::Uncertain => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_pin_and_persistence() {
        let a = EpochSigner::random();
        let e = enclave_core::seq::new_boot_epoch_id();
        let be = a.sign(&e);
        verify(&be).unwrap();
        // A signature over another epoch id does not transfer.
        let mut moved = be.clone();
        moved.boot_epoch_id = enclave_core::seq::new_boot_epoch_id();
        assert!(verify(&moved).unwrap_err().is("EPOCH_SIGNATURE_INVALID"));
        let d = std::env::temp_dir().join(format!("mcpmac-epoch-{}", enclave_core::rng::u64()));
        let v = EpochVerifier::open(Some(&d)).unwrap();
        v.check(&be).unwrap();
        // Another key — even validly self-signed — is refused, also after a restart.
        let b = EpochSigner::random().sign(&enclave_core::seq::new_boot_epoch_id());
        assert!(v.check(&b).unwrap_err().is("EPOCH_SIGNER_CHANGED"));
        let v2 = EpochVerifier::open(Some(&d)).unwrap();
        assert_eq!(v2.pinned(), Some(a.public_key()));
        assert!(v2.check(&b).unwrap_err().is("EPOCH_SIGNER_CHANGED"));
        v2.check(&a.sign(&enclave_core::seq::new_boot_epoch_id()))
            .unwrap();
        let _ = std::fs::remove_dir_all(d);
    }
}
