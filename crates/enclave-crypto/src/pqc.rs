//! Post-Quantum Cryptography (PQC) & Hybrid Cryptosystem Implementation (GAP-62).
//!
//! Standards Compliance:
//! - **NIST FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism Standard (`ML-KEM-768`,
//!   polynomial ring $\mathcal{R}_q = \mathbb{Z}_{3329}[X]/(X^{256}+1)$, rank $k=3$, implicit
//!   Fujisaki-Okamoto $\text{FO}^{\not\perp}$ rejection).
//! - **NIST FIPS 204**: Module-Lattice-Based Digital Signature Standard (`ML-DSA-65`,
//!   polynomial ring $\mathbb{Z}_{8380417}[X]/(X^{256}+1)$, dimensions $(k,\ell)=(6,5)$).
//! - **Bespoke MCPMac hybrid KEM combiner (NIST SP 800-56C Rev. 2 two-step KDF)**:
//!   `HKDF-SHA256(salt = none, ikm = ss_ML-KEM ‖ ss_X25519 ‖ ct_X25519 ‖ pk_X25519,
//!   info = HYBRID_COMBINER_LABEL)`. It binds the same four values, in the same order, as
//!   IETF CFRG X-Wing, but it is **not X-Wing** (X-Wing uses SHA3-256 with its own label
//!   and its own key and ciphertext encodings) and does not interoperate with it
//!   (DEFECT-F-76). On the OHTTP wire it is identified by the unregistered local id
//!   `ohttp::KEM_ID_HYBRID_MCPMAC`, never by X-Wing's `0x647A`.
//! - **IETF LAMPS Composite Signatures (`draft-ietf-lamps-pq-composite-sigs`)**: Domain-separated
//!   composite message and public-key binding for `Ed25519 + ML-DSA-65`.
//!
//! Provides:
//! - [`HybridKemPublicKey`] & [`HybridKemCiphertext`]: Hybrid `X25519 + ML-KEM-768` encapsulation.
//! - [`HybridVerifyingKey`] & [`HybridSignature`]: Dual-signature `Ed25519 + ML-DSA-65` authentication.
//! - [`WireCryptoSuite`]: Fail-closed anti-downgrade wire enforcement.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use enclave_core::error::EnclaveResult;
use enclave_core::fail;
use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen as KemKeyGen, SerDes as KemSerDes};
use fips204::ml_dsa_65;
use fips204::traits::{
    KeyGen as DsaKeyGen, SerDes as DsaSerDes, Signer as DsaSigner, Verifier as DsaVerifier,
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Size of ML-KEM-768 encapsulation (public) key in bytes (NIST FIPS 203 Table 2).
pub const ML_KEM_768_PUBLIC_KEY_SIZE: usize = ml_kem_768::EK_LEN; // 1184
/// Size of ML-KEM-768 ciphertext in bytes (NIST FIPS 203 Table 2).
pub const ML_KEM_768_CIPHERTEXT_SIZE: usize = ml_kem_768::CT_LEN; // 1088
/// Size of ML-KEM-768 shared secret in bytes (NIST FIPS 203 Table 2).
pub const ML_KEM_768_SHARED_SECRET_SIZE: usize = 32;
/// Size of ML-KEM-768 decapsulation (private) key in bytes (NIST FIPS 203 Table 2).
pub const ML_KEM_768_PRIVATE_KEY_SIZE: usize = ml_kem_768::DK_LEN; // 2400

/// Size of ML-DSA-65 verifying (public) key in bytes (NIST FIPS 204 Table 1).
pub const ML_DSA_65_PUBLIC_KEY_SIZE: usize = ml_dsa_65::PK_LEN; // 1952
/// Size of ML-DSA-65 signature in bytes (NIST FIPS 204 Table 1).
pub const ML_DSA_65_SIGNATURE_SIZE: usize = ml_dsa_65::SIG_LEN; // 3309
/// Size of ML-DSA-65 signing (private) key in bytes (NIST FIPS 204 Table 1).
pub const ML_DSA_65_PRIVATE_KEY_SIZE: usize = ml_dsa_65::SK_LEN; // 4032

/// Size of X25519 public key in bytes.
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;
/// Size of Ed25519 public key in bytes.
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
/// Size of Ed25519 signature in bytes.
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// Composite wire size of a `HybridKemPublicKey` (`32B X25519 + 1184B ML-KEM-768 = 1216B`).
pub const HYBRID_KEM_PUBLIC_KEY_SIZE: usize = X25519_PUBLIC_KEY_SIZE + ML_KEM_768_PUBLIC_KEY_SIZE;
/// Composite wire size of a `HybridKemCiphertext` (`32B X25519 + 1088B ML-KEM-768 = 1120B`).
pub const HYBRID_KEM_CIPHERTEXT_SIZE: usize = X25519_PUBLIC_KEY_SIZE + ML_KEM_768_CIPHERTEXT_SIZE;
/// Composite secret key size of a `HybridKemKeyPair` (`32B X25519 + 2400B ML-KEM-768 = 2432B`).
pub const HYBRID_KEM_SECRET_KEY_SIZE: usize = 32 + ML_KEM_768_PRIVATE_KEY_SIZE;
/// Composite wire size of a `HybridVerifyingKey` (`32B Ed25519 + 1952B ML-DSA-65 = 1984B`).
pub const HYBRID_VERIFYING_KEY_SIZE: usize = ED25519_PUBLIC_KEY_SIZE + ML_DSA_65_PUBLIC_KEY_SIZE;
/// Composite wire size of a `HybridSignature` (`64B Ed25519 + 3309B ML-DSA-65 = 3373B`).
pub const HYBRID_SIGNATURE_SIZE: usize = ED25519_SIGNATURE_SIZE + ML_DSA_65_SIGNATURE_SIZE;

/// NIST FIPS 204 §5.2 domain separation context string (`ctx`, max 255 bytes) for composite signatures.
pub const ML_DSA_COMPOSITE_CTX: &[u8] = b"MCPMac-v3-Composite-MLDSA65-Ed25519";

/// IETF LAMPS composite signature domain prefix binding both component public keys.
const COMPOSITE_MSG_DOMAIN: &[u8] = b"MCPMac-v3-LAMPS-MLDSA65-Ed25519-v1";

/// Hybrid Key Encapsulation Mechanism Public Key (`X25519 + ML-KEM-768`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridKemPublicKey {
    /// Classical X25519 32-byte public key.
    pub classical: [u8; X25519_PUBLIC_KEY_SIZE],
    /// Post-quantum ML-KEM-768 1184-byte encapsulation key (`ek`).
    #[serde(with = "serde_bytes")]
    pub pqc: Vec<u8>,
}

impl HybridKemPublicKey {
    /// Serialize the composite public key as `classical (32B) || pqc (1184B)` (`1216B`).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_KEM_PUBLIC_KEY_SIZE);
        out.extend_from_slice(&self.classical);
        out.extend_from_slice(&self.pqc);
        out
    }

    /// Parse and validate a 1,216-byte composite public key, enforcing the NIST FIPS 203 §7.2
    /// encapsulation-key modulus check on the `ML-KEM-768` component.
    pub fn from_bytes(bytes: &[u8]) -> EnclaveResult<Self> {
        if bytes.len() != HYBRID_KEM_PUBLIC_KEY_SIZE {
            fail!(
                EINVAL,
                "HYBRID_KEM_PUBKEY_LEN_INVALID",
                "Expected {} bytes, got {}",
                HYBRID_KEM_PUBLIC_KEY_SIZE,
                bytes.len()
            );
        }
        let mut classical = [0u8; X25519_PUBLIC_KEY_SIZE];
        classical.copy_from_slice(&bytes[0..X25519_PUBLIC_KEY_SIZE]);
        let ek_bytes: [u8; ML_KEM_768_PUBLIC_KEY_SIZE] = bytes[X25519_PUBLIC_KEY_SIZE..]
            .try_into()
            .expect("slice length checked above");
        let _ = ml_kem_768::EncapsKey::try_from_bytes(ek_bytes).map_err(|e| {
            enclave_core::err!(
                EINVAL,
                "ML_KEM_PUBKEY_MODULUS_REJECTED",
                "NIST FIPS 203 ML-KEM-768 encapsulation key failed modulus check: {e}"
            )
        })?;
        Ok(Self {
            classical,
            pqc: ek_bytes.to_vec(),
        })
    }
}

/// Hybrid Key Encapsulation Mechanism Ciphertext (`X25519 + ML-KEM-768`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridKemCiphertext {
    /// Ephemeral X25519 32-byte public key.
    pub classical_ephemeral: [u8; X25519_PUBLIC_KEY_SIZE],
    /// Post-quantum ML-KEM-768 1088-byte ciphertext (`c`).
    #[serde(with = "serde_bytes")]
    pub pqc_ciphertext: Vec<u8>,
}

impl HybridKemCiphertext {
    /// Serialize the composite ciphertext as `classical_ephemeral (32B) || pqc_ciphertext (1088B)` (`1120B`).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_KEM_CIPHERTEXT_SIZE);
        out.extend_from_slice(&self.classical_ephemeral);
        out.extend_from_slice(&self.pqc_ciphertext);
        out
    }

    /// Parse a 1,120-byte composite ciphertext.
    pub fn from_bytes(bytes: &[u8]) -> EnclaveResult<Self> {
        if bytes.len() != HYBRID_KEM_CIPHERTEXT_SIZE {
            fail!(
                EINVAL,
                "HYBRID_KEM_CIPHERTEXT_LEN_INVALID",
                "Expected {} bytes, got {}",
                HYBRID_KEM_CIPHERTEXT_SIZE,
                bytes.len()
            );
        }
        let mut classical_ephemeral = [0u8; X25519_PUBLIC_KEY_SIZE];
        classical_ephemeral.copy_from_slice(&bytes[0..X25519_PUBLIC_KEY_SIZE]);
        Ok(Self {
            classical_ephemeral,
            pqc_ciphertext: bytes[X25519_PUBLIC_KEY_SIZE..].to_vec(),
        })
    }
}

/// A 32-byte zeroizing shared secret produced by hybrid decapsulation.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridSharedSecret(pub [u8; 32]);

impl std::fmt::Debug for HybridSharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HybridSharedSecret([REDACTED])")
    }
}

/// Hybrid KEM Key Pair (`X25519 + ML-KEM-768`).
#[derive(Clone)]
pub struct HybridKemKeyPair {
    /// Classical static secret key.
    pub classical_secret: [u8; 32],
    /// Classical public key.
    pub classical_public: [u8; X25519_PUBLIC_KEY_SIZE],
    /// Post-quantum NIST FIPS 203 `ML-KEM-768` 2400-byte decapsulation key (`dk`).
    pub pqc_private: Vec<u8>,
    /// Post-quantum NIST FIPS 203 `ML-KEM-768` 1184-byte encapsulation key (`ek`).
    pub pqc_public: Vec<u8>,
}

impl std::fmt::Debug for HybridKemKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridKemKeyPair")
            .field("classical_public", &self.classical_public)
            .field("pqc_public_len", &self.pqc_public.len())
            .field("classical_secret", &"[REDACTED]")
            .field("pqc_private", &"[REDACTED]")
            .finish()
    }
}

impl Drop for HybridKemKeyPair {
    fn drop(&mut self) {
        self.classical_secret.zeroize();
        self.pqc_private.zeroize();
    }
}

impl HybridKemKeyPair {
    /// Generate a new hybrid `X25519 + ML-KEM-768` key pair using the OS/hardware CSPRNG
    /// (NIST FIPS 203 Algorithm 19 `ML-KEM.KeyGen`).
    pub fn generate() -> Self {
        let mut classical_bytes = [0u8; 32];
        enclave_core::rng::fill(&mut classical_bytes);
        let static_secret = StaticSecret::from(classical_bytes);
        let classical_public = X25519PublicKey::from(&static_secret).to_bytes();

        let (mlkem_ek, mlkem_dk) = ml_kem_768::KG::try_keygen()
            .expect("OS CSPRNG failure during NIST FIPS 203 ML-KEM-768 keygen");

        Self {
            classical_secret: classical_bytes,
            classical_public,
            pqc_private: mlkem_dk.into_bytes().to_vec(),
            pqc_public: mlkem_ek.into_bytes().to_vec(),
        }
    }

    /// Expose the composite hybrid public key.
    pub fn public_key(&self) -> HybridKemPublicKey {
        HybridKemPublicKey {
            classical: self.classical_public,
            pqc: self.pqc_public.clone(),
        }
    }

    /// Serialize the composite secret key material (`32B X25519 || 2400B ML-KEM-768 dk = 2432B`)
    /// inside a zeroizing buffer for hardware-share KEK wrapping (`Envelope_A3` / `Envelope_A4`).
    pub fn to_secret_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let mut buf = Vec::with_capacity(HYBRID_KEM_SECRET_KEY_SIZE);
        buf.extend_from_slice(&self.classical_secret);
        buf.extend_from_slice(&self.pqc_private);
        zeroize::Zeroizing::new(buf)
    }

    /// Reconstruct a [`HybridKemKeyPair`] from its 2,432-byte composite secret representation.
    pub fn from_secret_bytes(bytes: &[u8]) -> EnclaveResult<Self> {
        if bytes.len() != HYBRID_KEM_SECRET_KEY_SIZE {
            fail!(
                EINVAL,
                "HYBRID_KEM_PRIVKEY_LEN_INVALID",
                "Expected {} bytes, got {}",
                HYBRID_KEM_SECRET_KEY_SIZE,
                bytes.len()
            );
        }
        let mut classical_secret = [0u8; 32];
        classical_secret.copy_from_slice(&bytes[0..32]);
        let static_secret = StaticSecret::from(classical_secret);
        let classical_public = X25519PublicKey::from(&static_secret).to_bytes();

        let mut dk_bytes = [0u8; ML_KEM_768_PRIVATE_KEY_SIZE];
        dk_bytes.copy_from_slice(&bytes[32..]);
        let _mlkem_dk = ml_kem_768::DecapsKey::try_from_bytes(dk_bytes).map_err(|e| {
            dk_bytes.zeroize();
            classical_secret.zeroize();
            enclave_core::err!(
                EINVAL,
                "ML_KEM_PRIVKEY_INVALID",
                "Corrupted ML-KEM-768 decapsulation key: {e}"
            )
        })?;
        // Per NIST FIPS 203 §7.1 Algorithm 16, dk = dk_PKE (1152B) || ek (1184B) || H(ek) (32B) || z (32B).
        let mut ek_bytes = [0u8; ML_KEM_768_PUBLIC_KEY_SIZE];
        ek_bytes.copy_from_slice(&dk_bytes[1152..1152 + ML_KEM_768_PUBLIC_KEY_SIZE]);
        let mlkem_ek = ml_kem_768::EncapsKey::try_from_bytes(ek_bytes).map_err(|e| {
            dk_bytes.zeroize();
            classical_secret.zeroize();
            enclave_core::err!(
                EINVAL,
                "ML_KEM_PUBKEY_MODULUS_REJECTED",
                "Embedded ML-KEM-768 encapsulation key failed modulus check: {e}"
            )
        })?;
        let pqc_private = dk_bytes.to_vec();
        dk_bytes.zeroize();

        Ok(Self {
            classical_secret,
            classical_public,
            pqc_private,
            pqc_public: mlkem_ek.into_bytes().to_vec(),
        })
    }

    /// Encapsulate a shared secret towards a peer's hybrid public key
    /// (NIST FIPS 203 Algorithm 20 `ML-KEM.Encaps` + X25519 + bespoke MCPMac combiner).
    pub fn encapsulate(
        peer_pk: &HybridKemPublicKey,
    ) -> EnclaveResult<(HybridKemCiphertext, HybridSharedSecret)> {
        let ek_bytes: [u8; ML_KEM_768_PUBLIC_KEY_SIZE] =
            peer_pk.pqc.as_slice().try_into().map_err(|_| {
                enclave_core::err!(
                    EINVAL,
                    "ML_KEM_PUBKEY_LEN_INVALID",
                    "Expected {} bytes, got {}",
                    ML_KEM_768_PUBLIC_KEY_SIZE,
                    peer_pk.pqc.len()
                )
            })?;

        // 1. NIST FIPS 203 §7.2 Encapsulation key modulus check (coefficients in [0, q-1])
        //    and Module-LWE encapsulation over Z_3329[X]/(X^256 + 1).
        let mlkem_ek = ml_kem_768::EncapsKey::try_from_bytes(ek_bytes).map_err(|e| {
            enclave_core::err!(
                EINVAL,
                "ML_KEM_PUBKEY_MODULUS_REJECTED",
                "NIST FIPS 203 ML-KEM-768 encapsulation key failed modulus check: {e}"
            )
        })?;
        let (pqc_ss, pqc_ct) = mlkem_ek.try_encaps().map_err(|e| {
            enclave_core::err!(
                EIO,
                "ML_KEM_ENCAPS_FAIL",
                "NIST FIPS 203 ML-KEM-768 encapsulation failed: {e}"
            )
        })?;
        let mut pqc_ss_bytes = pqc_ss.into_bytes();

        // 2. Classical X25519 ephemeral Diffie-Hellman (with RFC 7748 all-zero shared-secret check).
        let mut eph_bytes = [0u8; 32];
        enclave_core::rng::fill(&mut eph_bytes);
        let eph_secret = StaticSecret::from(eph_bytes);
        eph_bytes.zeroize();
        let eph_public = X25519PublicKey::from(&eph_secret);
        let peer_classical_pk = X25519PublicKey::from(peer_pk.classical);
        let classical_ss = eph_secret.diffie_hellman(&peer_classical_pk);
        if classical_ss.as_bytes() == &[0u8; 32] {
            pqc_ss_bytes.zeroize();
            fail!(
                EACCES,
                "X25519_LOW_ORDER_POINT",
                "Rejected low-order X25519 public key"
            );
        }

        // 3. Bespoke MCPMac transcript-bound hybrid combiner (not X-Wing; DEFECT-F-76).
        let combined_ss = combine_shared_secrets(
            classical_ss.as_bytes(),
            &pqc_ss_bytes,
            eph_public.as_bytes(),
            &peer_pk.classical,
        )?;
        pqc_ss_bytes.zeroize();

        let ciphertext = HybridKemCiphertext {
            classical_ephemeral: eph_public.to_bytes(),
            pqc_ciphertext: pqc_ct.into_bytes().to_vec(),
        };

        Ok((ciphertext, combined_ss))
    }

    /// Decapsulate a shared secret from a received hybrid ciphertext
    /// (NIST FIPS 203 Algorithm 21 `ML-KEM.Decaps` with implicit FO rejection + X25519).
    ///
    /// Note on CCA2 security (NIST FIPS 203 §7.3): If `ct.pqc_ciphertext` has been tampered
    /// with in transit, `ML-KEM.Decaps` performs constant-time Fujisaki-Okamoto re-encryption
    /// comparison and returns a pseudorandom implicit-rejection shared secret $K' = J(z \parallel c)$
    /// rather[ than] leaking an error oracle.
    pub fn decapsulate(&self, ct: &HybridKemCiphertext) -> EnclaveResult<HybridSharedSecret> {
        let ct_bytes: [u8; ML_KEM_768_CIPHERTEXT_SIZE] =
            ct.pqc_ciphertext.as_slice().try_into().map_err(|_| {
                enclave_core::err!(
                    EINVAL,
                    "ML_KEM_CIPHERTEXT_LEN_INVALID",
                    "Expected {} bytes, got {}",
                    ML_KEM_768_CIPHERTEXT_SIZE,
                    ct.pqc_ciphertext.len()
                )
            })?;

        let mut dk_bytes: [u8; ML_KEM_768_PRIVATE_KEY_SIZE] =
            self.pqc_private.as_slice().try_into().map_err(|_| {
                enclave_core::err!(
                    EINVAL,
                    "ML_KEM_PRIVKEY_LEN_INVALID",
                    "Expected {} bytes, got {}",
                    ML_KEM_768_PRIVATE_KEY_SIZE,
                    self.pqc_private.len()
                )
            })?;

        // 1. NIST FIPS 203 §7.3 ML-KEM-768 decapsulation (constant-time FO implicit rejection).
        let mlkem_dk = ml_kem_768::DecapsKey::try_from_bytes(dk_bytes).map_err(|e| {
            dk_bytes.zeroize();
            enclave_core::err!(
                EINVAL,
                "ML_KEM_PRIVKEY_INVALID",
                "Corrupted ML-KEM-768 decapsulation key: {e}"
            )
        })?;
        dk_bytes.zeroize();

        let mlkem_ct = ml_kem_768::CipherText::try_from_bytes(ct_bytes).map_err(|e| {
            enclave_core::err!(
                EINVAL,
                "ML_KEM_CIPHERTEXT_INVALID",
                "Malformed ML-KEM-768 ciphertext: {e}"
            )
        })?;
        let pqc_ss = mlkem_dk.try_decaps(&mlkem_ct).map_err(|e| {
            enclave_core::err!(
                EACCES,
                "ML_KEM_DECAPS_FAIL",
                "ML-KEM-768 decapsulation error: {e}"
            )
        })?;
        let mut pqc_ss_bytes = pqc_ss.into_bytes();

        // 2. Classical X25519 Diffie-Hellman (with RFC 7748 all-zero check).
        let static_sec = StaticSecret::from(self.classical_secret);
        let peer_eph = X25519PublicKey::from(ct.classical_ephemeral);
        let classical_ss = static_sec.diffie_hellman(&peer_eph);
        if classical_ss.as_bytes() == &[0u8; 32] {
            pqc_ss_bytes.zeroize();
            fail!(
                EACCES,
                "X25519_LOW_ORDER_POINT",
                "Rejected low-order X25519 ephemeral key"
            );
        }

        // 3. Combine shared secrets with X25519 transcript binding.
        let res = combine_shared_secrets(
            classical_ss.as_bytes(),
            &pqc_ss_bytes,
            &ct.classical_ephemeral,
            &self.classical_public,
        );
        pqc_ss_bytes.zeroize();
        res
    }
}

/// HKDF `info` label of the bespoke hybrid combiner. **Frozen**: these bytes are part
/// of every derived key, including at-rest `Envelope_A3`/`A4` seals, so changing them
/// would make existing ciphertexts unopenable. The `XWing` substring is historical; the
/// construction is not X-Wing (DEFECT-F-76).
pub const HYBRID_COMBINER_LABEL: &[u8] = b"MCPMac-v3-XWing-X25519-ML-KEM-768";

/// Bespoke MCPMac hybrid shared-secret combiner (NIST SP 800-56C Rev. 2 two-step KDF):
/// `HKDF-SHA256(salt = none, ikm = ss_pqc || ss_x25519 || ct_x25519 || pk_x25519,
/// info = HYBRID_COMBINER_LABEL)`. Not IETF CFRG X-Wing (DEFECT-F-76).
///
/// Binding `ct_x25519` and `pk_x25519` into the KDF input guarantees IND-CCA2 security
/// even against multi-target or re-encapsulation attacks on the classical/PQ components.
fn combine_shared_secrets(
    classical_ss: &[u8; 32],
    pqc_ss: &[u8; 32],
    classical_ephemeral: &[u8; 32],
    classical_public: &[u8; 32],
) -> EnclaveResult<HybridSharedSecret> {
    let mut ikm = [0u8; 128];
    ikm[0..32].copy_from_slice(pqc_ss);
    ikm[32..64].copy_from_slice(classical_ss);
    ikm[64..96].copy_from_slice(classical_ephemeral);
    ikm[96..128].copy_from_slice(classical_public);

    let info = HYBRID_COMBINER_LABEL;
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    let expand_res = hk.expand(info, &mut okm);
    ikm.zeroize();

    expand_res.map_err(|_| {
        enclave_core::err!(
            EACCES,
            "HYBRID_HKDF_EXPAND_FAIL",
            "HKDF-SHA256 derivation failure"
        )
    })?;

    Ok(HybridSharedSecret(okm))
}

/// Construct the domain-separated composite message binding both the Ed25519 and ML-DSA-65
/// verifying keys to prevent signature stripping and key-substitution attacks
/// (`draft-ietf-lamps-pq-composite-sigs`).
fn build_composite_message(
    classical_vk: &[u8; ED25519_PUBLIC_KEY_SIZE],
    pqc_vk: &[u8],
    message: &[u8],
) -> Vec<u8> {
    let pqc_vk_digest = blake3::hash(pqc_vk);
    let mut out = Vec::with_capacity(COMPOSITE_MSG_DOMAIN.len() + 32 + 32 + 8 + message.len());
    out.extend_from_slice(COMPOSITE_MSG_DOMAIN);
    out.extend_from_slice(classical_vk);
    out.extend_from_slice(pqc_vk_digest.as_bytes());
    out.extend_from_slice(&(message.len() as u64).to_le_bytes());
    out.extend_from_slice(message);
    out
}

/// Hybrid Verifying Key (`Ed25519 + ML-DSA-65`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridVerifyingKey {
    /// Classical 32-byte Ed25519 verifying key.
    pub classical: [u8; ED25519_PUBLIC_KEY_SIZE],
    /// Post-quantum NIST FIPS 204 `ML-DSA-65` 1952-byte public key.
    #[serde(with = "serde_bytes")]
    pub pqc: Vec<u8>,
}

impl HybridVerifyingKey {
    /// Serialize the composite verifying key (`32B Ed25519 || 1952B ML-DSA-65 = 1984B`).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_VERIFYING_KEY_SIZE);
        out.extend_from_slice(&self.classical);
        out.extend_from_slice(&self.pqc);
        out
    }

    /// Parse a 1,984-byte composite verifying key.
    pub fn from_bytes(bytes: &[u8]) -> EnclaveResult<Self> {
        if bytes.len() != HYBRID_VERIFYING_KEY_SIZE {
            fail!(
                EINVAL,
                "HYBRID_VERIFYING_KEY_LEN_INVALID",
                "Expected {} bytes, got {}",
                HYBRID_VERIFYING_KEY_SIZE,
                bytes.len()
            );
        }
        let mut classical = [0u8; ED25519_PUBLIC_KEY_SIZE];
        classical.copy_from_slice(&bytes[0..ED25519_PUBLIC_KEY_SIZE]);
        Ok(Self {
            classical,
            pqc: bytes[ED25519_PUBLIC_KEY_SIZE..].to_vec(),
        })
    }
}

/// Hybrid Dual-Signature (`Ed25519 + ML-DSA-65`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridSignature {
    /// Classical Ed25519 64-byte signature.
    #[serde(with = "serde_bytes")]
    pub classical: Vec<u8>,
    /// Post-quantum NIST FIPS 204 `ML-DSA-65` 3309-byte signature.
    #[serde(with = "serde_bytes")]
    pub pqc: Vec<u8>,
}

impl HybridSignature {
    /// Serialize the composite signature (`64B Ed25519 || 3309B ML-DSA-65 = 3373B`).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_SIGNATURE_SIZE);
        out.extend_from_slice(&self.classical);
        out.extend_from_slice(&self.pqc);
        out
    }

    /// Parse a 3,373-byte composite signature.
    pub fn from_bytes(bytes: &[u8]) -> EnclaveResult<Self> {
        if bytes.len() != HYBRID_SIGNATURE_SIZE {
            fail!(
                EINVAL,
                "HYBRID_SIGNATURE_LEN_INVALID",
                "Expected {} bytes, got {}",
                HYBRID_SIGNATURE_SIZE,
                bytes.len()
            );
        }
        Ok(Self {
            classical: bytes[0..ED25519_SIGNATURE_SIZE].to_vec(),
            pqc: bytes[ED25519_SIGNATURE_SIZE..].to_vec(),
        })
    }
}

/// Hybrid Signing Key (`Ed25519 + ML-DSA-65`).
pub struct HybridSigningKey {
    classical: SigningKey,
    pqc_private: Vec<u8>,
    pqc_public: Vec<u8>,
}

impl std::fmt::Debug for HybridSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridSigningKey")
            .field("classical_verifying_key", &self.classical.verifying_key())
            .field("pqc_public_len", &self.pqc_public.len())
            .field("pqc_private", &"[REDACTED]")
            .finish()
    }
}

impl Drop for HybridSigningKey {
    fn drop(&mut self) {
        self.pqc_private.zeroize();
    }
}

impl HybridSigningKey {
    /// Generate a new hybrid `Ed25519 + ML-DSA-65` signing key pair using CSPRNG
    /// (NIST FIPS 204 Algorithm 1 `ML-DSA.KeyGen`).
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        enclave_core::rng::fill(&mut seed);
        let classical = SigningKey::from_bytes(&seed);
        seed.zeroize();

        let (mldsa_pk, mldsa_sk) = ml_dsa_65::KG::try_keygen()
            .expect("OS CSPRNG failure during NIST FIPS 204 ML-DSA-65 keygen");

        Self {
            classical,
            pqc_private: mldsa_sk.into_bytes().to_vec(),
            pqc_public: mldsa_pk.into_bytes().to_vec(),
        }
    }

    /// Expose the composite hybrid verifying key.
    pub fn verifying_key(&self) -> HybridVerifyingKey {
        HybridVerifyingKey {
            classical: self.classical.verifying_key().to_bytes(),
            pqc: self.pqc_public.clone(),
        }
    }

    /// Produce a hybrid composite signature over `message`
    /// (Ed25519 + NIST FIPS 204 Algorithm 2 `ML-DSA.Sign`).
    pub fn sign(&self, message: &[u8]) -> HybridSignature {
        let classical_vk = self.classical.verifying_key().to_bytes();
        let composite_msg = build_composite_message(&classical_vk, &self.pqc_public, message);

        // 1. Classical Ed25519 signature over composite message.
        let classical_sig = self.classical.sign(&composite_msg);

        // 2. Post-quantum NIST FIPS 204 ML-DSA-65 signature over composite message.
        let mut sk_bytes: [u8; ML_DSA_65_PRIVATE_KEY_SIZE] = self
            .pqc_private
            .as_slice()
            .try_into()
            .expect("invariant: HybridSigningKey holds valid 4032-byte ML-DSA-65 secret key");
        let mldsa_sk = ml_dsa_65::PrivateKey::try_from_bytes(sk_bytes)
            .expect("invariant: HybridSigningKey holds valid ML-DSA-65 secret key");
        sk_bytes.zeroize();

        let pqc_sig = mldsa_sk
            .try_sign(&composite_msg, ML_DSA_COMPOSITE_CTX)
            .expect("NIST FIPS 204 ML-DSA-65 signing failed");

        HybridSignature {
            classical: classical_sig.to_bytes().to_vec(),
            pqc: pqc_sig.to_vec(),
        }
    }
}

impl HybridVerifyingKey {
    /// Verify that both classical `Ed25519` and post-quantum NIST FIPS 204 `ML-DSA-65`
    /// signatures are cryptographically valid over the domain-separated composite message.
    /// Fails closed if either signature, public key, or message bit is tampered.
    pub fn verify(&self, message: &[u8], signature: &HybridSignature) -> EnclaveResult<()> {
        let pk_bytes: [u8; ML_DSA_65_PUBLIC_KEY_SIZE] =
            self.pqc.as_slice().try_into().map_err(|_| {
                enclave_core::err!(
                    EINVAL,
                    "ML_DSA_PUBKEY_LEN_INVALID",
                    "Expected {} bytes, got {}",
                    ML_DSA_65_PUBLIC_KEY_SIZE,
                    self.pqc.len()
                )
            })?;
        let sig_bytes: [u8; ML_DSA_65_SIGNATURE_SIZE] =
            signature.pqc.as_slice().try_into().map_err(|_| {
                enclave_core::err!(
                    EINVAL,
                    "ML_DSA_SIGNATURE_LEN_INVALID",
                    "Expected {} bytes, got {}",
                    ML_DSA_65_SIGNATURE_SIZE,
                    signature.pqc.len()
                )
            })?;

        if signature.classical.len() != ED25519_SIGNATURE_SIZE {
            fail!(
                EINVAL,
                "ED25519_SIGNATURE_LEN_INVALID",
                "Expected {} bytes, got {}",
                ED25519_SIGNATURE_SIZE,
                signature.classical.len()
            );
        }

        let composite_msg = build_composite_message(&self.classical, &self.pqc, message);

        // 1. Classical Ed25519 verification over composite message.
        let ed_vk = VerifyingKey::from_bytes(&self.classical).map_err(|e| {
            enclave_core::err!(
                EACCES,
                "ED25519_VERIFYING_KEY_INVALID",
                "Malformed Ed25519 key: {e}"
            )
        })?;
        let mut ed_sig_arr = [0u8; ED25519_SIGNATURE_SIZE];
        ed_sig_arr.copy_from_slice(&signature.classical);
        let ed_sig = ed25519_dalek::Signature::from_bytes(&ed_sig_arr);
        ed_vk.verify(&composite_msg, &ed_sig).map_err(|e| {
            enclave_core::err!(
                EACCES,
                "HYBRID_CLASSICAL_SIG_INVALID",
                "Ed25519 verification failed: {e}"
            )
        })?;

        // 2. Post-quantum NIST FIPS 204 Algorithm 3 (`ML-DSA.Verify`) over composite message.
        let mldsa_pk = ml_dsa_65::PublicKey::try_from_bytes(pk_bytes).map_err(|e| {
            enclave_core::err!(
                EACCES,
                "ML_DSA_PUBKEY_INVALID",
                "Malformed ML-DSA-65 public key: {e}"
            )
        })?;
        if !mldsa_pk.verify(&composite_msg, &sig_bytes, ML_DSA_COMPOSITE_CTX) {
            fail!(
                EACCES,
                "HYBRID_PQC_SIG_INVALID",
                "NIST FIPS 204 ML-DSA-65 lattice signature verification failed"
            );
        }

        Ok(())
    }
}

/// Wire protocol cryptographic suite descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireCryptoSuite {
    /// Classical-only cryptography (legacy fallback).
    ClassicalOnly,
    /// Hybrid Post-Quantum Cryptography (`X25519 + ML-KEM-768` & `Ed25519 + ML-DSA-65`).
    HybridPqc,
}

/// Enforce handshake anti-downgrade policy. Fails closed on any downgrade attempt.
pub fn enforce_handshake_suite(
    required_suite: WireCryptoSuite,
    offered_suite: WireCryptoSuite,
) -> EnclaveResult<()> {
    match (required_suite, offered_suite) {
        (WireCryptoSuite::HybridPqc, WireCryptoSuite::ClassicalOnly) => {
            fail!(
                EPERM,
                "PQC_DOWNGRADE_ATTEMPT_REJECTED",
                "Policy requires HybridPqc suite; classical-only handshake rejected"
            );
        }
        (WireCryptoSuite::HybridPqc, WireCryptoSuite::HybridPqc) => Ok(()),
        (WireCryptoSuite::ClassicalOnly, _) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DEFECT-F-76: pins the combiner to the construction the docs now state
    /// (HKDF-SHA256 over `ss_pqc ‖ ss_x25519 ‖ ct_x25519 ‖ pk_x25519`, frozen label).
    /// The expected value was computed independently (Python `hmac`/`hashlib`
    /// RFC 5869 HKDF), so a silent change of label, order or KDF fails here.
    #[test]
    fn f76_combiner_is_the_documented_bespoke_hkdf() {
        let ss = combine_shared_secrets(&[2u8; 32], &[1u8; 32], &[3u8; 32], &[4u8; 32]).unwrap();
        assert_eq!(
            hex::encode(ss.0),
            "6505411a39edf9e50eaf50cdbcd9272ab3a069aa7caa9d44bea3686cf38410ca"
        );
        assert_eq!(HYBRID_COMBINER_LABEL, b"MCPMac-v3-XWing-X25519-ML-KEM-768");
        // Every input is bound: changing any one changes the output.
        let base = ss.0;
        for which in 0..4 {
            let mut v = [[2u8; 32], [1u8; 32], [3u8; 32], [4u8; 32]];
            v[which][0] ^= 1;
            let other = combine_shared_secrets(&v[0], &v[1], &v[2], &v[3]).unwrap();
            assert_ne!(other.0, base, "input {which} not bound");
        }
    }

    #[test]
    fn test_hybrid_kem_encapsulate_decapsulate_equality() {
        let alice = HybridKemKeyPair::generate();
        let alice_pk = alice.public_key();
        assert_eq!(alice_pk.pqc.len(), ML_KEM_768_PUBLIC_KEY_SIZE);
        assert_eq!(alice.pqc_private.len(), ML_KEM_768_PRIVATE_KEY_SIZE);

        // Bob encapsulates to Alice
        let (ct, bob_ss) = HybridKemKeyPair::encapsulate(&alice_pk).unwrap();
        assert_eq!(ct.pqc_ciphertext.len(), ML_KEM_768_CIPHERTEXT_SIZE);

        // Alice decapsulates Bob's ciphertext
        let alice_ss = alice.decapsulate(&ct).unwrap();

        // Invariant: Both shared secrets must be non-zero and identical
        assert_ne!(bob_ss.0, [0u8; 32]);
        assert_eq!(bob_ss.0, alice_ss.0);
    }

    #[test]
    fn test_hybrid_kem_tampered_ciphertext_implicit_rejection() {
        let alice = HybridKemKeyPair::generate();
        let alice_pk = alice.public_key();

        let (mut ct, bob_ss) = HybridKemKeyPair::encapsulate(&alice_pk).unwrap();
        // Flip 1 bit inside the ML-KEM-768 lattice ciphertext
        ct.pqc_ciphertext[64] ^= 0x01;

        // Per NIST FIPS 203 §7.3 (Fujisaki-Okamoto implicit rejection), decapsulation
        // returns a pseudorandom rejection key K' != K without leaking an error oracle.
        let alice_ss = alice.decapsulate(&ct).unwrap();
        assert_ne!(
            alice_ss.0, bob_ss.0,
            "Tampered ML-KEM-768 ciphertext must implicitly reject to an independent shared secret"
        );
    }

    #[test]
    fn test_hybrid_kem_modulus_check_rejects_non_canonical_pubkey() {
        let alice = HybridKemKeyPair::generate();
        let mut bad_pk = alice.public_key();
        // Set first 12-bit polynomial coefficient to 0xFFF = 4095 >= q (3329),
        // which MUST be rejected by the NIST FIPS 203 §7.2 encapsulation key modulus check.
        bad_pk.pqc[0] = 0xFF;
        bad_pk.pqc[1] = 0xFF;
        bad_pk.pqc[2] = 0xFF;

        let err = HybridKemKeyPair::encapsulate(&bad_pk).unwrap_err();
        assert_eq!(err.reason, "ML_KEM_PUBKEY_MODULUS_REJECTED");
    }

    #[test]
    fn test_hybrid_signature_sign_and_verify_clean() {
        let signer = HybridSigningKey::generate();
        let vk = signer.verifying_key();
        assert_eq!(vk.pqc.len(), ML_DSA_65_PUBLIC_KEY_SIZE);

        let msg = b"Audit Root Attestation: Epoch 42, Hash 0x11223344";
        let sig = signer.sign(msg);
        assert_eq!(sig.pqc.len(), ML_DSA_65_SIGNATURE_SIZE);
        assert_eq!(sig.classical.len(), ED25519_SIGNATURE_SIZE);

        assert!(vk.verify(msg, &sig).is_ok());
    }

    #[test]
    fn test_hybrid_signature_tampered_classical_rejected() {
        let signer = HybridSigningKey::generate();
        let vk = signer.verifying_key();
        let msg = b"Critical state commit";

        let mut sig = signer.sign(msg);
        sig.classical[0] ^= 0x01; // Flip 1 bit in classical Ed25519 signature

        let err = vk.verify(msg, &sig).unwrap_err();
        assert_eq!(err.reason, "HYBRID_CLASSICAL_SIG_INVALID");
    }

    #[test]
    fn test_hybrid_signature_single_bit_flip_in_mldsa65_rejected() {
        let signer = HybridSigningKey::generate();
        let vk = signer.verifying_key();
        let msg = b"Audit Root Attestation: Epoch 42, Hash 0x11223344";

        let sig = signer.sign(msg);

        // Flip a single bit at the beginning, middle, and end of the 3,309-byte ML-DSA-65 signature
        for idx in [0, 64, 1650, ML_DSA_65_SIGNATURE_SIZE - 1] {
            let mut corrupted = sig.clone();
            corrupted.pqc[idx] ^= 0x01;
            let err = vk.verify(msg, &corrupted).unwrap_err();
            assert_eq!(
                err.reason, "HYBRID_PQC_SIG_INVALID",
                "Single-bit flip at ML-DSA-65 signature byte {idx} must fail verification"
            );
        }
    }

    #[test]
    fn test_hybrid_signature_component_key_substitution_rejected() {
        let alice = HybridSigningKey::generate();
        let attacker = HybridSigningKey::generate();
        let msg = b"Epoch 99 Compliance Rollup";

        // Alice signs msg legitimately
        let alice_sig = alice.sign(msg);

        // Attacker attempts to pair Alice's Ed25519 public key with Attacker's ML-DSA-65 key
        let franken_vk = HybridVerifyingKey {
            classical: alice.verifying_key().classical,
            pqc: attacker.verifying_key().pqc,
        };
        assert!(franken_vk.verify(msg, &alice_sig).is_err());
    }

    #[test]
    fn test_hybrid_anti_downgrade_enforcement() {
        let required = WireCryptoSuite::HybridPqc;
        let offered = WireCryptoSuite::ClassicalOnly;
        let res = enforce_handshake_suite(required, offered);

        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.reason, "PQC_DOWNGRADE_ATTEMPT_REJECTED");

        assert!(enforce_handshake_suite(required, WireCryptoSuite::HybridPqc).is_ok());
    }
}
