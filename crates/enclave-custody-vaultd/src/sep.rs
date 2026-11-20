//! Secure Enclave key agent abstraction.
//!
//! On hardware the SEP holds non-exportable P-256 keys in the Data Protection
//! Keychain (the `.app` bundle's `keychain-access-groups` entitlement,
//! ADR-010) and releases ECDH shares via `SecKeyCreateSharedSecret` only after
//! the `.biometryCurrentSet` evaluation. [`SoftwareSep`] performs the same
//! P-256 ECDH and ECDSA operations in software for CI and is never used when
//! the daemon runs in production mode.

#[cfg(any(test, feature = "simulation"))]
use enclave_core::err;
use enclave_core::error::EnclaveResult;
use enclave_core::secret::SecretBytes;
#[cfg(any(test, feature = "simulation"))]
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
#[cfg(any(test, feature = "simulation"))]
use p256::{PublicKey, SecretKey};
#[cfg(any(test, feature = "simulation"))]
use sha2::{Digest, Sha256};

use crate::ceremony::PrfTier;

/// SEP operations used by UID 703.
pub trait SepAgent: std::fmt::Debug + Send {
    /// Tier-specific ECDH share (`ECDH_SEP(sk_SEP, Q_tier)`, X9.63-SHA256).
    fn ecdh_share(&self, tier: PrfTier) -> EnclaveResult<SecretBytes>;
    /// Secondary SEP-derived share used in `L1` (no external authenticator).
    fn l1_secondary_share(&self, tier: PrfTier) -> EnclaveResult<SecretBytes>;
    /// Sign a boot epoch / checkpoint with the SEP epoch key.
    fn sign_epoch(&self, msg: &[u8]) -> EnclaveResult<Vec<u8>>;
    /// Epoch public key (SEC1).
    fn epoch_public_key(&self) -> Vec<u8>;
    /// Create the SEP tier keys during custodian enrollment.
    fn create_tier_keys(&self) -> EnclaveResult<()> {
        Ok(())
    }
    /// Create an RFC 9449 DPoP proof using the non-biometric SEP workload key (FS-703 §4.1).
    fn create_dpop_proof(
        &self,
        htm: &str,
        htu: &str,
        iat: i64,
        jti: &str,
        access_token: Option<&str>,
    ) -> EnclaveResult<String> {
        let _ = (htm, htu, iat, jti, access_token);
        enclave_core::fail!(EPERM, "DPOP_UNSUPPORTED");
    }
    /// Public JWK of the SEP workload key.
    fn dpop_public_jwk(&self) -> serde_json::Value {
        serde_json::json!({})
    }
}

/// Software stand-in performing real P-256 ECDH / ECDSA.
#[derive(Debug)]
#[cfg(any(test, feature = "simulation"))]
pub struct SoftwareSep {
    ecdh_sk: SecretKey,
    peers: [PublicKey; 4],
    epoch_key: SigningKey,
    workload_key: enclave_crypto::dpop::DpopKey,
}

#[cfg(any(test, feature = "simulation"))]
impl Default for SoftwareSep {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "simulation"))]
impl SoftwareSep {
    /// Fresh keys.
    pub fn new() -> Self {
        let peers = std::array::from_fn(|_| SecretKey::random(&mut rand_core::OsRng).public_key());
        Self {
            ecdh_sk: SecretKey::random(&mut rand_core::OsRng),
            peers,
            epoch_key: SigningKey::random(&mut rand_core::OsRng),
            workload_key: enclave_crypto::dpop::DpopKey::generate(),
        }
    }
    /// As [`Self::new`], with the epoch key derived from a persisted seed so
    /// the simulated SEP keeps one epoch key across restarts, as the real SEP
    /// does (peers pin it, GAP-27).
    pub fn with_epoch_seed(seed: &[u8; 32]) -> EnclaveResult<Self> {
        let k = blake3::derive_key("MCPMac simulated SEP epoch key v1", seed);
        let epoch_key =
            SigningKey::from_bytes(&k.into()).map_err(|_| err!(EINVAL, "EPOCH_SEED"))?;
        Ok(Self {
            epoch_key,
            ..Self::new()
        })
    }
    fn share(&self, peer: &PublicKey, label: &[u8]) -> SecretBytes {
        let z = p256::ecdh::diffie_hellman(self.ecdh_sk.to_nonzero_scalar(), peer.as_affine());
        // ANSI X9.63 KDF with SHA-256, one block (kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256).
        let mut h = Sha256::new();
        h.update(z.raw_secret_bytes());
        h.update(1u32.to_be_bytes());
        h.update(label);
        SecretBytes::new(h.finalize().to_vec())
    }
    /// Epoch verifying key.
    pub fn epoch_verifying_key(&self) -> VerifyingKey {
        *self.epoch_key.verifying_key()
    }
}

#[cfg(any(test, feature = "simulation"))]
impl SepAgent for SoftwareSep {
    fn ecdh_share(&self, tier: PrfTier) -> EnclaveResult<SecretBytes> {
        Ok(match tier {
            PrfTier::A3 => self.share(&self.peers[0], b"MCPMac-SEP-A3"),
            PrfTier::A4 => self.share(&self.peers[1], b"MCPMac-SEP-A4"),
        })
    }
    fn l1_secondary_share(&self, tier: PrfTier) -> EnclaveResult<SecretBytes> {
        Ok(match tier {
            PrfTier::A3 => self.share(&self.peers[2], b"MCPMac-SEP-L1-A3"),
            PrfTier::A4 => self.share(&self.peers[3], b"MCPMac-SEP-L1-A4"),
        })
    }
    fn sign_epoch(&self, msg: &[u8]) -> EnclaveResult<Vec<u8>> {
        let s: Signature = self
            .epoch_key
            .try_sign(msg)
            .map_err(|_| err!(EIO, "SEP_SIGN"))?;
        Ok(s.to_der().as_bytes().to_vec())
    }
    fn epoch_public_key(&self) -> Vec<u8> {
        self.epoch_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }
    fn create_dpop_proof(
        &self,
        htm: &str,
        htu: &str,
        iat: i64,
        jti: &str,
        access_token: Option<&str>,
    ) -> EnclaveResult<String> {
        self.workload_key
            .create_proof(htm, htu, iat, jti, access_token)
    }
    fn dpop_public_jwk(&self) -> serde_json::Value {
        self.workload_key.public_jwk()
    }
}
