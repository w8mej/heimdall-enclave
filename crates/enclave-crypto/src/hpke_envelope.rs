//! ADR-009 / FS-707 dual-key `Envelope_A3` / `Envelope_A4` tier separation with
//! Hybrid Post-Quantum Cryptography (`X25519 + ML-KEM-768`, bespoke MCPMac combiner).
//!
//! `_piivault` holds two **cryptographically independent** hybrid `X25519 + ML-KEM-768`
//! keypairs (`1,216`-byte composite public key, `2,432`-byte composite private key):
//!
//! * `Envelope_A3` — `(pk_detok_a3_epoch, sk_detok_a3_epoch)`: seals `C3`
//!   surrogates only, at most [`A3_MAX_SEALS_PER_EPOCH`] (= 64) per epoch
//!   before a mandatory re-key.
//! * `Envelope_A4` — `(pk_detok_a4, sk_detok_a4)`: exclusively seals every
//!   `C4` surrogate and every bulk (`> 1` row) set.
//!
//! Sealing uses Hybrid `X25519 + NIST FIPS 203 ML-KEM-768` (`1,120`-byte encapsulation)
//! with the bespoke transcript-bound combiner in [`crate::pqc`] (HKDF-SHA256; it binds the
//! same values as IETF CFRG X-Wing but is not X-Wing, DEFECT-F-76), `HKDF-SHA256`, and
//! `ChaCha20Poly1305`, with tier-specific `info` strings so a
//! ciphertext can never be opened under the other tier even if keys were
//! confused. Private keys exist at rest only as [`WrappedTierKey`]s whose KEK
//! is `HKDF(SEP ECDH share ‖ YubiKey PRF(tier label))`; an unwrapped key is a
//! zeroizing [`UnwrappedTierKey`] that the vault drops right after the bounded
//! detokenization. The tier is a type parameter, so an `A3` code path cannot
//! even name `sk_detok_a4` (zero bits of it are exposed during `A3` work).

use std::marker::PhantomData;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use enclave_core::error::EnclaveResult;
use enclave_core::secret::SecretBytes;
use enclave_core::{err, fail};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

pub mod legacy;

use crate::pqc::{
    HybridKemCiphertext, HybridKemKeyPair, HybridKemPublicKey, HYBRID_KEM_PUBLIC_KEY_SIZE,
    HYBRID_KEM_SECRET_KEY_SIZE,
};

/// Current authenticated envelope format. Version 1 requires an explicit migration reader.
pub const ENVELOPE_VERSION: u32 = 2;
/// The frozen MCPMac hybrid combiner, not the standardized X-Wing construction.
pub const HYBRID_SUITE: &str = "MCPMac-X25519-MLKEM768-HKDFSHA256-ChaCha20Poly1305-v1";
/// Reserved authenticated policy target; request payloads cannot select another target.
pub const ENVELOPE_POLICY_TARGET: &str = "custody-envelope-policy-v1.json";

/// Signed administrator policy. A request never supplies the authority or expected scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopePolicy {
    /// Policy schema version (1).
    pub version: u32,
    /// Monotonic authenticated policy revision, checkpointed by the service.
    pub revision: u64,
    /// Exact administrator-provisioned host/asset identity.
    pub subject: String,
    /// Exact administrator-provisioned data namespace.
    pub namespace: String,
    /// Inclusive issuance and exclusive expiry/review boundaries, in Unix seconds.
    pub issued_unix: i64,
    /// Exclusive expiry.
    pub expires_unix: i64,
    /// Exclusive mandatory review time.
    pub review_unix: i64,
    /// Named accountable owner.
    pub owner: String,
    /// Affected profiles, never selected by an untrusted RPC.
    pub profiles: Vec<enclave_core::profile::Profile>,
    /// Exact permitted data classes (C3 and/or C4).
    pub data_classes: Vec<String>,
    /// Human-readable purpose, included in the authenticated policy.
    pub purpose: String,
    /// Named migration/retirement plan; changing it changes the context digest.
    pub migration: String,
    /// Acknowledged disclosure identifier. Required for a classical exception.
    pub disclosure: Option<String>,
    /// Explicit finite classical exception. Hybrid surfaces always refuse this suite.
    pub classical_exception: bool,
}

/// Detached UID 704/admin signature over canonical, domain-separated policy bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEnvelopePolicy {
    /// Exact signed policy.
    pub policy: EnvelopePolicy,
    /// Raw Ed25519 signature.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// Verified policy capability. Its private fields prevent caller-invented authorization.
#[derive(Debug, Clone)]
pub struct VerifiedEnvelopeContext {
    policy: EnvelopePolicy,
    digest: [u8; 32],
    transport_expires_unix: Option<i64>,
    transport_deadline_ns: Option<u64>,
}
impl EnvelopePolicy {
    /// Exact canonical signature preimage, also used by offline policy issuers.
    pub fn signing_message(&self) -> EnclaveResult<Vec<u8>> {
        let mut message = b"MCPMac-CustodyEnvelopePolicy-v1\0".to_vec();
        message.extend(enclave_core::jcs::to_jcs_bytes(self)?);
        Ok(message)
    }
}
impl SignedEnvelopePolicy {
    /// Verify independently pinned authority, exact configured scope and all time bounds.
    pub fn verify(
        &self,
        issuer: &ed25519_dalek::VerifyingKey,
        subject: &str,
        namespace: &str,
        now: i64,
    ) -> EnclaveResult<VerifiedEnvelopeContext> {
        let p = &self.policy;
        let bounded = |v: &str| !v.is_empty() && v.len() <= 256 && !v.chars().any(char::is_control);
        if p.version != 1
            || p.revision == 0
            || p.subject != subject
            || p.namespace != namespace
            || !bounded(&p.subject)
            || !bounded(&p.namespace)
            || !bounded(&p.owner)
            || !bounded(&p.purpose)
            || !bounded(&p.migration)
            || now < 0
            || p.issued_unix < 0
            || p.issued_unix > now
            || p.expires_unix <= now
            || p.review_unix <= now
            || p.review_unix > p.expires_unix
            || p.profiles.is_empty()
            || p.profiles.len() > 3
            || p.data_classes.is_empty()
            || p.data_classes.len() > 2
            || p.data_classes.iter().any(|c| c != "C3" && c != "C4")
            || p.profiles
                .iter()
                .enumerate()
                .any(|(i, v)| p.profiles[..i].contains(v))
            || p.data_classes
                .iter()
                .enumerate()
                .any(|(i, v)| p.data_classes[..i].contains(v))
            || (p.classical_exception && !p.disclosure.as_ref().is_some_and(|v| bounded(v)))
        {
            fail!(EACCES, "ENVELOPE_POLICY_SCOPE_OR_TIME");
        }
        let message = p.signing_message()?;
        let signature = ed25519_dalek::Signature::from_slice(&self.signature)
            .map_err(|_| err!(EACCES, "ENVELOPE_POLICY_SIGNATURE"))?;
        issuer
            .verify_strict(&message, &signature)
            .map_err(|_| err!(EACCES, "ENVELOPE_POLICY_SIGNATURE"))?;
        Ok(VerifiedEnvelopeContext {
            policy: p.clone(),
            digest: *blake3::hash(&message).as_bytes(),
            transport_expires_unix: None,
            transport_deadline_ns: None,
        })
    }
}
impl VerifiedEnvelopeContext {
    /// Revalidate an exact operation; expiry/review is never extended by a captured capability.
    pub fn admit(
        &self,
        profile: enclave_core::profile::Profile,
        data_class: &str,
        now: i64,
        classical: bool,
    ) -> EnclaveResult<()> {
        if now < self.policy.issued_unix
            || now >= self.policy.expires_unix
            || now >= self.policy.review_unix
            || self
                .transport_expires_unix
                .is_some_and(|expiry| now >= expiry)
            || self
                .transport_deadline_ns
                .is_some_and(|deadline| enclave_core::clock::boot_clock_ns() >= deadline)
            || !self.policy.profiles.contains(&profile)
            || !self.policy.data_classes.iter().any(|v| v == data_class)
            || (classical && !self.policy.classical_exception)
        {
            fail!(EACCES, "ENVELOPE_POLICY_REFUSED");
        }
        Ok(())
    }
    /// Authenticated context identifier bound into every key and ciphertext.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Monotonic policy revision for durable admission floors.
    pub fn revision(&self) -> u64 {
        self.policy.revision
    }
    /// Restrict this exact policy by an independently authenticated transport
    /// chain expiry. Repeated restriction can only shorten an existing bound;
    /// it changes neither the issuer-signed policy nor its stable digest.
    pub fn with_transport_expiry(mut self, expires_unix: i64, now: i64) -> EnclaveResult<Self> {
        if now < 0 || expires_unix <= now {
            fail!(EACCES, "ENVELOPE_TRANSPORT_EXPIRED");
        }
        self.transport_expires_unix = Some(
            self.transport_expires_unix
                .map_or(expires_unix, |old| old.min(expires_unix)),
        );
        Ok(self)
    }
    /// Retain the conservative local wall and boot bounds captured before an
    /// authenticated receipt fetch. The caller includes signed policy expiry
    /// and review in that receipt-domain calculation before translating clocks.
    pub fn with_transport_lifetime(
        self,
        lifetime: enclave_core::custody_lifetime::CapturedCustodyLifetime,
        now: i64,
    ) -> EnclaveResult<Self> {
        let mut context = self.with_transport_expiry(lifetime.valid_until_unix, now)?;
        if enclave_core::clock::boot_clock_ns() >= lifetime.deadline_ns {
            fail!(EACCES, "ENVELOPE_TRANSPORT_EXPIRED");
        }
        context.transport_deadline_ns = Some(
            context
                .transport_deadline_ns
                .map_or(lifetime.deadline_ns, |old| old.min(lifetime.deadline_ns)),
        );
        Ok(context)
    }
    /// Captured monotone transport limit for long-lived derived leases.
    pub fn deadline_ns(&self) -> Option<u64> {
        self.transport_deadline_ns
    }
    /// Exclusive signed-policy expiry/review, independent of transport refresh.
    pub fn policy_expires_unix(&self) -> i64 {
        self.policy.expires_unix.min(self.policy.review_unix)
    }
    /// Exclusive earliest independent policy or authenticated transport boundary.
    pub fn expires_unix(&self) -> i64 {
        self.transport_expires_unix
            .map_or(self.policy_expires_unix(), |expiry| {
                expiry.min(self.policy_expires_unix())
            })
    }
}

// Zero is a compatibility scope for the existing software API only. Native
// service admission must supply a verified nonzero policy through new_bound.
const SOFTWARE_CONTEXT: [u8; 32] = [0; 32];

/// Adapter exposing the enclave CSPRNG through the `rand_core` 0.9 traits used by `hpke`.
#[derive(Debug, Clone, Copy, Default)]
pub struct EnclaveRng;

impl hpke::rand_core::RngCore for EnclaveRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        enclave_core::rng::fill(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        enclave_core::rng::u64()
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        enclave_core::rng::fill(dst);
    }
}

impl hpke::rand_core::CryptoRng for EnclaveRng {}

/// Hard cap on `C3` surrogates sealed under one `A3` epoch key (ADR-009).
pub const A3_MAX_SEALS_PER_EPOCH: u32 = 64;

/// Tier marker trait (sealed).
pub trait Tier: private::Sealed + Copy + std::fmt::Debug + 'static {
    /// Wire name.
    const NAME: &'static str;
    /// HPKE `info` string.
    const HPKE_INFO: &'static [u8];
    /// YubiKey `hmac-secret` PRF salt label (FS-703 §4.2).
    const PRF_LABEL: &'static [u8];
}

mod private {
    pub trait Sealed {}
    impl Sealed for super::A3 {}
    impl Sealed for super::A4 {}
}

/// `Envelope_A3` marker.
#[derive(Debug, Clone, Copy)]
pub struct A3;
/// `Envelope_A4` marker.
#[derive(Debug, Clone, Copy)]
pub struct A4;

impl Tier for A3 {
    const NAME: &'static str = "A3";
    const HPKE_INFO: &'static [u8] = b"MCPMac-Envelope-A3-v1";
    const PRF_LABEL: &'static [u8] = b"MCPMac-A3-Row-v1";
}
impl Tier for A4 {
    const NAME: &'static str = "A4";
    const HPKE_INFO: &'static [u8] = b"MCPMac-Envelope-A4-v1";
    const PRF_LABEL: &'static [u8] = b"MCPMac-A4-Bulk-v1";
}

/// A tier public key (always resident: tokenize-only / airplane mode needs no secret).
#[derive(Clone)]
pub struct TierPublicKey<T: Tier> {
    pk: HybridKemPublicKey,
    epoch: u32,
    context: [u8; 32],
    _t: PhantomData<T>,
}

impl<T: Tier> std::fmt::Debug for TierPublicKey<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TierPublicKey<{}>(epoch={}, x25519={}, mlkem768_len={})",
            T::NAME,
            self.epoch,
            hex::encode(self.pk.classical),
            self.pk.pqc.len()
        )
    }
}

impl<T: Tier> TierPublicKey<T> {
    /// Raw 1,216-byte composite `X25519 (32B) || ML-KEM-768 (1184B)` public key.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.pk.to_bytes()
    }
    /// Epoch.
    pub fn epoch(&self) -> u32 {
        self.epoch
    }
}

/// An unwrapped tier private key (`X25519 + ML-KEM-768`). Zeroized on drop.
pub struct UnwrappedTierKey<T: Tier> {
    kp: HybridKemKeyPair,
    epoch: u32,
    context: [u8; 32],
    _t: PhantomData<T>,
}

impl<T: Tier> std::fmt::Debug for UnwrappedTierKey<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UnwrappedTierKey<{}>(epoch={}, [REDACTED])",
            T::NAME,
            self.epoch
        )
    }
}

/// A sealed surrogate ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedValue {
    /// Authenticated wire version (2).
    pub version: u32,
    /// Exact supported cryptographic suite.
    pub suite: String,
    /// Digest of authenticated subject/namespace/policy/migration context.
    pub context: [u8; 32],
    /// `"A3"` or `"A4"`.
    pub tier: String,
    /// Key epoch.
    pub epoch: u32,
    /// Hybrid `X25519 + ML-KEM-768` encapsulated key (`1,120` bytes).
    #[serde(with = "serde_bytes")]
    pub enc: Vec<u8>,
    /// AEAD ciphertext.
    #[serde(with = "serde_bytes")]
    pub ct: Vec<u8>,
}

/// A private key wrapped under the two-factor hardware KEK.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedTierKey {
    /// Authenticated wire version (2).
    pub version: u32,
    /// Exact supported cryptographic suite.
    pub suite: String,
    /// Digest of authenticated subject/namespace/policy/migration context.
    pub context: [u8; 32],
    /// Tier name.
    pub tier: String,
    /// Epoch.
    pub epoch: u32,
    /// Composite public key (`1,216` bytes, for sanity binding).
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    /// AEAD nonce.
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    /// Ciphertext of the 2,432-byte composite `X25519 + ML-KEM-768` secret key.
    #[serde(with = "serde_bytes")]
    pub ct: Vec<u8>,
}

/// The two hardware factor shares that reconstruct a tier KEK.
pub struct KekShares<'a> {
    /// SEP `.biometryCurrentSet` ECDH shared secret (tier-specific share).
    pub sep_ecdh_share: &'a [u8],
    /// YubiKey `hmac-secret` PRF output evaluated on [`Tier::PRF_LABEL`].
    pub yubikey_prf: &'a [u8],
}

impl std::fmt::Debug for KekShares<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KekShares([REDACTED])")
    }
}

fn derive_kek<T: Tier>(
    shares: &KekShares<'_>,
    epoch: u32,
    pk: &[u8],
) -> EnclaveResult<SecretBytes> {
    if shares.sep_ecdh_share.len() < 32 || shares.yubikey_prf.len() < 32 {
        fail!(EACCES, "KEK_SHARE_TOO_SHORT");
    }
    let mut ikm = Vec::with_capacity(shares.sep_ecdh_share.len() + shares.yubikey_prf.len());
    ikm.extend_from_slice(shares.sep_ecdh_share);
    ikm.extend_from_slice(shares.yubikey_prf);
    let mut salt = T::PRF_LABEL.to_vec();
    salt.extend_from_slice(&epoch.to_be_bytes());
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    ikm.zeroize();
    let mut okm = SecretBytes::zeroed(32);
    let mut info = b"MCPMac-TierKEK-v1:".to_vec();
    info.extend_from_slice(T::NAME.as_bytes());
    info.extend_from_slice(pk);
    hk.expand(&info, okm.expose_mut())
        .map_err(|_| err!(EINVAL, "HKDF_EXPAND"))?;
    Ok(okm)
}

/// Generate a fresh hybrid `X25519 + ML-KEM-768` tier keypair and immediately wrap its secret.
/// Returns the resident public key and the at-rest wrapped secret; the
/// plaintext secret never outlives this call.
pub fn generate_tier<T: Tier>(
    epoch: u32,
    shares: &KekShares<'_>,
) -> EnclaveResult<(TierPublicKey<T>, WrappedTierKey)> {
    generate_tier_in_context::<T>(epoch, shares, SOFTWARE_CONTEXT)
}

/// Generate with an independently verified policy/context capability.
pub fn generate_tier_bound<T: Tier>(
    epoch: u32,
    shares: &KekShares<'_>,
    context: &VerifiedEnvelopeContext,
) -> EnclaveResult<(TierPublicKey<T>, WrappedTierKey)> {
    generate_tier_in_context::<T>(epoch, shares, context.digest())
}
fn generate_tier_in_context<T: Tier>(
    epoch: u32,
    shares: &KekShares<'_>,
    context: [u8; 32],
) -> EnclaveResult<(TierPublicKey<T>, WrappedTierKey)> {
    let kp = HybridKemKeyPair::generate();
    let pk = kp.public_key();
    let pk_bytes = pk.to_bytes();
    let sk_bytes = kp.to_secret_bytes();
    let kek = derive_kek::<T>(shares, epoch, &pk_bytes)?;
    let mut nonce = [0u8; 12];
    enclave_core::rng::fill(&mut nonce);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(kek.expose()));
    let aad = wrap_aad::<T>(epoch, &pk_bytes, &context);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &sk_bytes,
                aad: &aad,
            },
        )
        .map_err(|_| err!(EIO, "WRAP_FAILED"))?;
    drop(sk_bytes);
    drop(kp);
    Ok((
        TierPublicKey {
            pk,
            epoch,
            context,
            _t: PhantomData,
        },
        WrappedTierKey {
            version: ENVELOPE_VERSION,
            suite: HYBRID_SUITE.into(),
            context,
            tier: T::NAME.into(),
            epoch,
            public_key: pk_bytes,
            nonce: nonce.to_vec(),
            ct,
        },
    ))
}

fn header_aad<T: Tier>(epoch: u32, context: &[u8; 32]) -> Vec<u8> {
    let mut a = b"MCPMac-TierEnvelope-v2\0".to_vec();
    a.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
    a.extend_from_slice(&(HYBRID_SUITE.len() as u32).to_be_bytes());
    a.extend_from_slice(HYBRID_SUITE.as_bytes());
    a.extend_from_slice(context);
    a.extend_from_slice(T::NAME.as_bytes());
    a.extend_from_slice(&epoch.to_be_bytes());
    a
}
fn wrap_aad<T: Tier>(epoch: u32, pk: &[u8], context: &[u8; 32]) -> Vec<u8> {
    let mut a = b"MCPMac-WrappedTierKey-v2\0".to_vec();
    a.extend(header_aad::<T>(epoch, context));
    a.extend_from_slice(T::NAME.as_bytes());
    a.extend_from_slice(&epoch.to_be_bytes());
    a.extend_from_slice(pk);
    a
}

/// Unwrap a tier key with both factor shares. Wrong tier, wrong epoch or a
/// wrong share fails closed with `EACCES: TIER_UNWRAP_FAILED`.
pub fn unwrap_tier<T: Tier>(
    w: &WrappedTierKey,
    shares: &KekShares<'_>,
) -> EnclaveResult<UnwrappedTierKey<T>> {
    if w.tier != T::NAME {
        fail!(
            EACCES,
            "TIER_MISMATCH",
            "wrapped {} presented as {}",
            w.tier,
            T::NAME
        );
    }
    validate_wrapped::<T>(w)?;
    let kek = derive_kek::<T>(shares, w.epoch, &w.public_key)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(kek.expose()));
    if w.nonce.len() != 12 {
        fail!(EINVAL, "BAD_NONCE");
    }
    let aad = wrap_aad::<T>(w.epoch, &w.public_key, &w.context);
    let mut pt = cipher
        .decrypt(
            Nonce::from_slice(&w.nonce),
            Payload {
                msg: &w.ct,
                aad: &aad,
            },
        )
        .map_err(|_| err!(EACCES, "TIER_UNWRAP_FAILED"))?;
    let kp = HybridKemKeyPair::from_secret_bytes(&pt).map_err(|_| {
        pt.zeroize();
        err!(EACCES, "TIER_UNWRAP_FAILED")
    })?;
    pt.zeroize();
    // Bind: the unwrapped secret must match the recorded composite public key.
    if kp.public_key().to_bytes().as_slice() != w.public_key.as_slice() {
        fail!(EACCES, "TIER_KEY_BINDING");
    }
    Ok(UnwrappedTierKey {
        kp,
        epoch: w.epoch,
        context: w.context,
        _t: PhantomData,
    })
}

/// Stage an alternate hybrid wrapper for the exact existing content key.
///
/// This primitive verifies both factor pairs and the current signed context; it
/// grants no credential enrollment, membership, recovery or key-retirement
/// authority. Callers must independently admit the target credential and
/// durably publish its complete wrapper set before using it. The source remains
/// unchanged and all temporary 2,432-byte private-key owners zeroize on drop.
pub fn rewrap_tier<T: Tier>(
    source: &WrappedTierKey,
    source_shares: &KekShares<'_>,
    target_shares: &KekShares<'_>,
    context: &VerifiedEnvelopeContext,
    profile: enclave_core::profile::Profile,
    now: i64,
) -> EnclaveResult<WrappedTierKey> {
    context.admit(
        profile,
        if T::NAME == A3::NAME { "C3" } else { "C4" },
        now,
        false,
    )?;
    if source.context != context.digest() {
        fail!(EACCES, "TIER_REWRAP_CONTEXT");
    }
    let unwrapped = unwrap_tier::<T>(source, source_shares)?;
    let secret = unwrapped.kp.to_secret_bytes();
    let kek = derive_kek::<T>(target_shares, source.epoch, &source.public_key)?;
    let mut nonce = [0; 12];
    enclave_core::rng::fill(&mut nonce);
    let ct = ChaCha20Poly1305::new(Key::from_slice(kek.expose()))
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &secret,
                aad: &wrap_aad::<T>(source.epoch, &source.public_key, &source.context),
            },
        )
        .map_err(|_| err!(EIO, "TIER_REWRAP_FAILED"))?;
    let target = WrappedTierKey {
        nonce: nonce.to_vec(),
        ct,
        ..source.clone()
    };
    let verified = unwrap_tier::<T>(&target, target_shares)?;
    let verified_secret = verified.kp.to_secret_bytes();
    if !enclave_core::secret::ct_eq(&secret, &verified_secret) {
        fail!(EACCES, "TIER_REWRAP_VERIFY");
    }
    verify_tier_wrapping::<T>(&target, target_shares)?;
    Ok(target)
}

/// Verify actual hybrid KEM possession for a stored wrapped private key.
/// Embedded ML-KEM public bytes alone do not prove the private decapsulation
/// component matches them. This bounded random seal/open challenge grants no
/// credential or publication authority and retains no raw key after return.
pub fn verify_tier_wrapping<T: Tier>(
    wrapped: &WrappedTierKey,
    shares: &KekShares<'_>,
) -> EnclaveResult<()> {
    let private = unwrap_tier::<T>(wrapped, shares)?;
    let public = restore_public::<T>(wrapped)?;
    let mut challenge = [0; 32];
    enclave_core::rng::fill(&mut challenge);
    let sealed = seal(&public, &challenge, b"MCPMac-BackupTierPossession-v1")?;
    let opened = open(&private, &sealed, b"MCPMac-BackupTierPossession-v1")?;
    if !enclave_core::secret::ct_eq(&challenge, opened.expose()) {
        fail!(EACCES, "TIER_KEY_POSSESSION");
    }
    Ok(())
}

fn derive_seal_key_and_nonce<T: Tier>(
    shared_secret: &[u8; 32],
    epoch: u32,
    enc: &[u8],
) -> EnclaveResult<zeroize::Zeroizing<[u8; 44]>> {
    let mut salt = b"MCPMac-HybridHPKE-Salt-v1:".to_vec();
    salt.extend_from_slice(&epoch.to_be_bytes());
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut info = b"MCPMac-HybridHPKE-Seal-v1:".to_vec();
    info.extend_from_slice(T::HPKE_INFO);
    info.extend_from_slice(enc);
    let mut okm = zeroize::Zeroizing::new([0u8; 44]);
    hk.expand(&info, &mut *okm)
        .map_err(|_| err!(EIO, "HPKE_KDF_FAILED"))?;
    Ok(okm)
}

/// Seal `plaintext` under a hybrid `X25519 + ML-KEM-768` tier public key with associated data.
pub fn seal<T: Tier>(
    pk: &TierPublicKey<T>,
    plaintext: &[u8],
    aad: &[u8],
) -> EnclaveResult<SealedValue> {
    let (kem_ct, shared_secret) =
        HybridKemKeyPair::encapsulate(&pk.pk).map_err(|_| err!(EIO, "HPKE_SEAL_FAILED"))?;
    let enc = kem_ct.to_bytes();
    let key_and_nonce = derive_seal_key_and_nonce::<T>(&shared_secret.0, pk.epoch, &enc)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_and_nonce[0..32]));
    let nonce = Nonce::from_slice(&key_and_nonce[32..44]);
    let mut bound_aad = header_aad::<T>(pk.epoch, &pk.context);
    bound_aad.extend_from_slice(&(aad.len() as u64).to_be_bytes());
    bound_aad.extend_from_slice(aad);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &bound_aad,
            },
        )
        .map_err(|_| err!(EIO, "HPKE_SEAL_FAILED"))?;
    Ok(SealedValue {
        version: ENVELOPE_VERSION,
        suite: HYBRID_SUITE.into(),
        context: pk.context,
        tier: T::NAME.into(),
        epoch: pk.epoch,
        enc,
        ct,
    })
}

/// Open a sealed value with an unwrapped hybrid `X25519 + ML-KEM-768` tier key.
pub fn open<T: Tier>(
    key: &UnwrappedTierKey<T>,
    sealed: &SealedValue,
    aad: &[u8],
) -> EnclaveResult<SecretBytes> {
    if sealed.version != ENVELOPE_VERSION || sealed.suite != HYBRID_SUITE {
        fail!(EACCES, "ENVELOPE_VERSION_OR_SUITE");
    }
    if sealed.context != key.context {
        fail!(EACCES, "ENVELOPE_CONTEXT_MISMATCH");
    }
    if sealed.tier != T::NAME {
        fail!(EACCES, "TIER_MISMATCH");
    }
    if sealed.epoch != key.epoch {
        fail!(ESTALE, "EPOCH_MISMATCH");
    }
    let kem_ct =
        HybridKemCiphertext::from_bytes(&sealed.enc).map_err(|_| err!(EINVAL, "BAD_ENCAP"))?;
    let shared_secret = key
        .kp
        .decapsulate(&kem_ct)
        .map_err(|_| err!(EACCES, "HPKE_OPEN_FAILED"))?;
    let key_and_nonce = derive_seal_key_and_nonce::<T>(&shared_secret.0, key.epoch, &sealed.enc)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_and_nonce[0..32]));
    let nonce = Nonce::from_slice(&key_and_nonce[32..44]);
    let mut bound_aad = header_aad::<T>(key.epoch, &key.context);
    bound_aad.extend_from_slice(&(aad.len() as u64).to_be_bytes());
    bound_aad.extend_from_slice(aad);
    let pt = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &sealed.ct,
                aad: &bound_aad,
            },
        )
        .map_err(|_| err!(EACCES, "HPKE_OPEN_FAILED"))?;
    Ok(SecretBytes::new(pt))
}

fn validate_wrapped<T: Tier>(w: &WrappedTierKey) -> EnclaveResult<()> {
    if w.version != ENVELOPE_VERSION || w.suite != HYBRID_SUITE {
        fail!(EACCES, "ENVELOPE_VERSION_OR_SUITE");
    }
    if w.tier != T::NAME {
        fail!(EACCES, "TIER_MISMATCH");
    }
    if w.public_key.len() != HYBRID_KEM_PUBLIC_KEY_SIZE
        || w.nonce.len() != 12
        || w.ct.len() != HYBRID_KEM_SECRET_KEY_SIZE + 16
    {
        fail!(EINVAL, "ENVELOPE_LENGTH");
    }
    Ok(())
}
fn restore_public<T: Tier>(w: &WrappedTierKey) -> EnclaveResult<TierPublicKey<T>> {
    validate_wrapped::<T>(w)?;
    let pk = HybridKemPublicKey::from_bytes(&w.public_key)
        .map_err(|_| err!(EINVAL, "ENVELOPE_PUBLIC_KEY"))?;
    Ok(TierPublicKey {
        pk,
        epoch: w.epoch,
        context: w.context,
        _t: PhantomData,
    })
}

/// Public and wrapped A3 state; safe to authenticate at rest without exposing tier secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A3Checkpoint {
    /// Wrapped independent epoch key and public half.
    pub wrapped: WrappedTierKey,
    /// Durable seal count; may never decrease on restore.
    pub sealed_this_epoch: u32,
}

/// `Envelope_A3`: the per-epoch `C3` sealer with the 64-surrogate cap.
#[derive(Debug)]
pub struct EnvelopeA3 {
    pk: TierPublicKey<A3>,
    wrapped: WrappedTierKey,
    sealed_this_epoch: u32,
}

impl EnvelopeA3 {
    /// Create epoch `epoch`.
    pub fn new(epoch: u32, shares: &KekShares<'_>) -> EnclaveResult<Self> {
        let (pk, wrapped) = generate_tier::<A3>(epoch, shares)?;
        Ok(Self {
            pk,
            wrapped,
            sealed_this_epoch: 0,
        })
    }
    /// Create under independently authenticated context.
    pub fn new_bound(
        epoch: u32,
        shares: &KekShares<'_>,
        context: &VerifiedEnvelopeContext,
    ) -> EnclaveResult<Self> {
        let (pk, wrapped) = generate_tier_bound::<A3>(epoch, shares, context)?;
        Ok(Self {
            pk,
            wrapped,
            sealed_this_epoch: 0,
        })
    }
    /// Persist after every seal before publishing a new surrogate.
    pub fn checkpoint(&self) -> A3Checkpoint {
        A3Checkpoint {
            wrapped: self.wrapped.clone(),
            sealed_this_epoch: self.sealed_this_epoch,
        }
    }
    /// Restore only from an authenticated, rollback-checked durable checkpoint.
    pub fn restore(checkpoint: A3Checkpoint) -> EnclaveResult<Self> {
        if checkpoint.sealed_this_epoch > A3_MAX_SEALS_PER_EPOCH {
            fail!(EACCES, "A3_CHECKPOINT_COUNT");
        }
        let pk = restore_public::<A3>(&checkpoint.wrapped)?;
        Ok(Self {
            pk,
            wrapped: checkpoint.wrapped,
            sealed_this_epoch: checkpoint.sealed_this_epoch,
        })
    }
    /// Seal one `C3` surrogate. The 65th seal of an epoch fails closed with
    /// `ESTALE: A3_EPOCH_EXHAUSTED` until [`EnvelopeA3::rekey`].
    pub fn seal_c3(&mut self, plaintext: &[u8], aad: &[u8]) -> EnclaveResult<SealedValue> {
        if self.sealed_this_epoch >= A3_MAX_SEALS_PER_EPOCH {
            fail!(
                ESTALE,
                "A3_EPOCH_EXHAUSTED",
                "re-key required after {A3_MAX_SEALS_PER_EPOCH} surrogates"
            );
        }
        let s = seal(&self.pk, plaintext, aad)?;
        self.sealed_this_epoch += 1;
        Ok(s)
    }
    /// Mandatory re-key: new independent keypair, counter reset.
    pub fn rekey(&mut self, shares: &KekShares<'_>) -> EnclaveResult<()> {
        let next = self
            .pk
            .epoch
            .checked_add(1)
            .ok_or_else(|| err!(ENOMEM, "A3_EPOCH_OVERFLOW"))?;
        let (pk, wrapped) = generate_tier_in_context::<A3>(next, shares, self.pk.context)?;
        *self = Self {
            pk,
            wrapped,
            sealed_this_epoch: 0,
        };
        Ok(())
    }
    /// Wrapped secret for this epoch.
    pub fn wrapped(&self) -> &WrappedTierKey {
        &self.wrapped
    }
    /// Public key.
    pub fn public_key(&self) -> &TierPublicKey<A3> {
        &self.pk
    }
    /// Seals used in this epoch.
    pub fn sealed_this_epoch(&self) -> u32 {
        self.sealed_this_epoch
    }
}

/// `Envelope_A4`: seals every `C4` surrogate and every bulk set.
#[derive(Debug)]
pub struct EnvelopeA4 {
    pk: TierPublicKey<A4>,
    wrapped: WrappedTierKey,
}

impl EnvelopeA4 {
    /// Create.
    pub fn new(epoch: u32, shares: &KekShares<'_>) -> EnclaveResult<Self> {
        let (pk, wrapped) = generate_tier::<A4>(epoch, shares)?;
        Ok(Self { pk, wrapped })
    }
    /// Create under independently authenticated context.
    pub fn new_bound(
        epoch: u32,
        shares: &KekShares<'_>,
        context: &VerifiedEnvelopeContext,
    ) -> EnclaveResult<Self> {
        let (pk, wrapped) = generate_tier_bound::<A4>(epoch, shares, context)?;
        Ok(Self { pk, wrapped })
    }
    /// Restore public sealing state without either hardware factor or plaintext tier key.
    pub fn restore(wrapped: WrappedTierKey) -> EnclaveResult<Self> {
        let pk = restore_public::<A4>(&wrapped)?;
        Ok(Self { pk, wrapped })
    }
    /// Seal a `C4` surrogate or bulk set.
    pub fn seal_c4_or_bulk(&self, plaintext: &[u8], aad: &[u8]) -> EnclaveResult<SealedValue> {
        seal(&self.pk, plaintext, aad)
    }
    /// Wrapped secret.
    pub fn wrapped(&self) -> &WrappedTierKey {
        &self.wrapped
    }
    /// Public key.
    pub fn public_key(&self) -> &TierPublicKey<A4> {
        &self.pk
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorized_context() -> VerifiedEnvelopeContext {
        use ed25519_dalek::{Signer, SigningKey};
        let issuer = SigningKey::from_bytes(&[31; 32]);
        let policy = EnvelopePolicy {
            version: 1,
            revision: 4,
            subject: "asset-a".into(),
            namespace: "casework".into(),
            issued_unix: 10,
            expires_unix: 100,
            review_unix: 90,
            owner: "custody-admin".into(),
            profiles: vec![enclave_core::profile::Profile::L2],
            data_classes: vec!["C3".into(), "C4".into()],
            purpose: "approved workflow".into(),
            migration: "hybrid-v2; retire on reviewed successor".into(),
            disclosure: None,
            classical_exception: false,
        };
        let signature = issuer
            .sign(&policy.signing_message().unwrap())
            .to_bytes()
            .to_vec();
        SignedEnvelopePolicy { policy, signature }
            .verify(&issuer.verifying_key(), "asset-a", "casework", 20)
            .unwrap()
    }

    #[test]
    fn alternate_wrappers_preserve_both_existing_hybrid_keys_and_ciphertexts() {
        fn check<T: Tier>() {
            let context = authorized_context();
            let (s, y) = shares(4);
            let (new_s, new_y) = shares(9);
            let old = KekShares {
                sep_ecdh_share: &s,
                yubikey_prf: &y,
            };
            let new = KekShares {
                sep_ecdh_share: &new_s,
                yubikey_prf: &new_y,
            };
            let (public, wrapped) = generate_tier_bound::<T>(7, &old, &context).unwrap();
            let before = serde_json::to_vec(&wrapped).unwrap();
            let ciphertext =
                seal(&public, b"retained synthetic plaintext", b"retained-aad").unwrap();
            let alternate = rewrap_tier::<T>(
                &wrapped,
                &old,
                &new,
                &context,
                enclave_core::profile::Profile::L2,
                20,
            )
            .unwrap();
            assert_eq!(alternate.public_key, wrapped.public_key);
            assert_eq!(alternate.context, wrapped.context);
            assert_eq!(alternate.tier, wrapped.tier);
            assert_eq!(alternate.epoch, wrapped.epoch);
            assert_eq!(alternate.ct.len(), 2432 + 16);
            let restored = unwrap_tier::<T>(&alternate, &new).unwrap();
            assert_eq!(
                open(&restored, &ciphertext, b"retained-aad")
                    .unwrap()
                    .expose(),
                b"retained synthetic plaintext"
            );
            assert!(unwrap_tier::<T>(&alternate, &old).is_err());
            assert!(unwrap_tier::<T>(&wrapped, &new).is_err());
            assert_eq!(serde_json::to_vec(&wrapped).unwrap(), before);
            assert_eq!(
                open(
                    &unwrap_tier::<T>(&wrapped, &old).unwrap(),
                    &ciphertext,
                    b"retained-aad"
                )
                .unwrap()
                .expose(),
                b"retained synthetic plaintext"
            );
        }
        check::<A3>();
        check::<A4>();
    }

    #[test]
    fn stored_wrapper_possession_rejects_corrupt_mlkem_private_with_unchanged_embedded_public() {
        let context = authorized_context();
        let (s, y) = shares(4);
        let shares = KekShares {
            sep_ecdh_share: &s,
            yubikey_prf: &y,
        };
        let (_, source) = generate_tier_bound::<A3>(7, &shares, &context).unwrap();
        verify_tier_wrapping::<A3>(&source, &shares).unwrap();
        let kek = derive_kek::<A3>(&shares, source.epoch, &source.public_key).unwrap();
        let aad = wrap_aad::<A3>(source.epoch, &source.public_key, &source.context);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(kek.expose()));
        let mut private = zeroize::Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&source.nonce),
                    Payload {
                        msg: &source.ct,
                        aad: &aad,
                    },
                )
                .unwrap(),
        );
        // Offset32 begins ML-KEM dk_PKE. The embedded ek and H(ek) are retained,
        // so key import's existing public binding accepts this hostile wrapper.
        private[32] ^= 1;
        let mut changed = source.clone();
        changed.ct = cipher
            .encrypt(
                Nonce::from_slice(&changed.nonce),
                Payload {
                    msg: &private,
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(changed.public_key, source.public_key);
        assert!(
            unwrap_tier::<A3>(&changed, &shares).is_ok(),
            "positive reproduction of insufficient embedded-public validation"
        );
        assert!(
            verify_tier_wrapping::<A3>(&changed, &shares).is_err(),
            "actual KEM challenge rejects the unusable private component"
        );
        assert!(rewrap_tier::<A3>(
            &changed,
            &shares,
            &shares,
            &context,
            enclave_core::profile::Profile::L2,
            20
        )
        .is_err());
    }

    #[test]
    fn alternate_wrapper_refuses_wrong_context_tier_shares_format_and_expiry() {
        let context = authorized_context();
        let (s, y) = shares(4);
        let shares = KekShares {
            sep_ecdh_share: &s,
            yubikey_prf: &y,
        };
        let (_, source) = generate_tier_bound::<A3>(7, &shares, &context).unwrap();
        let before = serde_json::to_vec(&source).unwrap();
        let mut changed_context = context.clone();
        changed_context.digest[0] ^= 1;
        assert!(rewrap_tier::<A3>(
            &source,
            &shares,
            &shares,
            &changed_context,
            enclave_core::profile::Profile::L2,
            20
        )
        .unwrap_err()
        .is("TIER_REWRAP_CONTEXT"));
        assert!(rewrap_tier::<A4>(
            &source,
            &shares,
            &shares,
            &context,
            enclave_core::profile::Profile::L2,
            20
        )
        .is_err());
        let short = KekShares {
            sep_ecdh_share: &[0; 31],
            yubikey_prf: &y,
        };
        assert!(rewrap_tier::<A3>(
            &source,
            &short,
            &shares,
            &context,
            enclave_core::profile::Profile::L2,
            20
        )
        .is_err());
        assert!(rewrap_tier::<A3>(
            &source,
            &shares,
            &short,
            &context,
            enclave_core::profile::Profile::L2,
            20
        )
        .is_err());
        let mut malformed = source.clone();
        malformed.ct.pop();
        assert!(rewrap_tier::<A3>(
            &malformed,
            &shares,
            &shares,
            &context,
            enclave_core::profile::Profile::L2,
            20
        )
        .is_err());
        assert!(rewrap_tier::<A3>(
            &source,
            &shares,
            &shares,
            &context,
            enclave_core::profile::Profile::L2,
            90
        )
        .is_err());
        assert_eq!(serde_json::to_vec(&source).unwrap(), before);
    }

    #[test]
    fn signed_policy_binds_authority_scope_profile_and_exclusive_review() {
        let context = authorized_context();
        context
            .admit(enclave_core::profile::Profile::L2, "C3", 89, false)
            .unwrap();
        assert!(context
            .admit(enclave_core::profile::Profile::L2, "C3", 90, false)
            .is_err());
        assert!(context
            .admit(enclave_core::profile::Profile::L3, "C3", 20, false)
            .is_err());
        assert!(context
            .admit(enclave_core::profile::Profile::L2, "C3", 20, true)
            .is_err());
        let mut policy = context.policy.clone();
        policy.subject = "asset-b".into();
        let signed = SignedEnvelopePolicy {
            policy,
            signature: vec![0; 64],
        };
        let key = ed25519_dalek::SigningKey::from_bytes(&[31; 32]).verifying_key();
        assert!(signed.verify(&key, "asset-a", "casework", 20).is_err());
        assert!(signed.verify(&key, "asset-b", "casework", 20).is_err());
    }

    #[test]
    fn transport_lifetime_retains_boot_bound_when_later_receipts_refresh() {
        use enclave_core::custody_lifetime::CapturedCustodyLifetime;
        let original = authorized_context();
        let digest = original.digest();
        let deadline = enclave_core::clock::boot_clock_ns() + 30_000_000_000;
        let restricted = original
            .with_transport_lifetime(
                CapturedCustodyLifetime {
                    valid_until_unix: 30,
                    deadline_ns: deadline,
                },
                20,
            )
            .unwrap();
        let refreshed = restricted
            .with_transport_lifetime(
                CapturedCustodyLifetime {
                    valid_until_unix: 40,
                    deadline_ns: deadline + 10_000_000_000,
                },
                20,
            )
            .unwrap();
        assert_eq!(refreshed.digest(), digest);
        assert_eq!(refreshed.expires_unix(), 30);
        assert_eq!(refreshed.deadline_ns(), Some(deadline));
        refreshed
            .admit(enclave_core::profile::Profile::L2, "C3", 20, false)
            .unwrap();
        let mut expired = refreshed;
        expired.transport_deadline_ns = Some(0);
        assert!(expired
            .admit(enclave_core::profile::Profile::L2, "C3", 20, false)
            .is_err());
        assert!(expired
            .with_transport_lifetime(
                CapturedCustodyLifetime {
                    valid_until_unix: 40,
                    deadline_ns: 0
                },
                20
            )
            .unwrap_err()
            .is("ENVELOPE_TRANSPORT_EXPIRED"));
    }

    #[test]
    fn transport_expiry_only_shortens_exact_policy_and_preserves_ciphertext_context() {
        let original = authorized_context();
        let digest = original.digest();
        let restricted = original.clone().with_transport_expiry(30, 20).unwrap();
        assert_eq!(restricted.digest(), digest);
        assert_eq!(restricted.policy_expires_unix(), 90);
        assert_eq!(restricted.expires_unix(), 30);
        restricted
            .admit(enclave_core::profile::Profile::L2, "C3", 29, false)
            .unwrap();
        assert!(restricted
            .admit(enclave_core::profile::Profile::L2, "C3", 30, false)
            .is_err());
        assert_eq!(
            restricted
                .clone()
                .with_transport_expiry(80, 20)
                .unwrap()
                .expires_unix(),
            30
        );
        assert_eq!(
            restricted
                .with_transport_expiry(25, 20)
                .unwrap()
                .expires_unix(),
            25
        );
        assert!(original
            .clone()
            .with_transport_expiry(20, 20)
            .unwrap_err()
            .is("ENVELOPE_TRANSPORT_EXPIRED"));
        assert_eq!(
            original
                .with_transport_expiry(200, 20)
                .unwrap()
                .expires_unix(),
            90
        );
    }

    #[test]
    fn authenticated_v2_headers_and_public_restart_refuse_tampering() {
        let context = authorized_context();
        let (s, y) = shares(8);
        let shares = KekShares {
            sep_ecdh_share: &s,
            yubikey_prf: &y,
        };
        let mut envelope = EnvelopeA3::new_bound(0, &shares, &context).unwrap();
        let sealed = envelope
            .seal_c3(b"synthetic", b"session/surrogate")
            .unwrap();
        let checkpoint = envelope.checkpoint();
        assert_eq!(checkpoint.wrapped.ct.len(), HYBRID_KEM_SECRET_KEY_SIZE + 16);
        let mut restored = EnvelopeA3::restore(checkpoint.clone()).unwrap();
        assert_eq!(restored.sealed_this_epoch(), 1);
        // Public-only restart needs no hardware factors and preserves the epoch count.
        restored
            .seal_c3(b"after-restart", b"another-surrogate")
            .unwrap();
        let key = unwrap_tier::<A3>(restored.wrapped(), &shares).unwrap();
        assert_eq!(
            open(&key, &sealed, b"session/surrogate").unwrap().expose(),
            b"synthetic"
        );
        for mutation in 0..4 {
            let mut bad = sealed.clone();
            match mutation {
                0 => bad.version = 1,
                1 => bad.suite = "X-Wing".into(),
                2 => bad.context[0] ^= 1,
                _ => bad.ct[0] ^= 1,
            }
            assert!(open(&key, &bad, b"session/surrogate").is_err());
        }
        let mut bad = checkpoint.clone();
        bad.wrapped.context[0] ^= 1;
        assert!(unwrap_tier::<A3>(&bad.wrapped, &shares).is_err());
        let mut bad = checkpoint.clone();
        bad.wrapped.public_key.pop();
        assert!(EnvelopeA3::restore(bad).is_err());
        let mut bad = checkpoint;
        bad.sealed_this_epoch = 65;
        assert!(EnvelopeA3::restore(bad).is_err());
    }

    fn shares(seed: u8) -> ([u8; 32], [u8; 32]) {
        ([seed; 32], [seed.wrapping_add(100); 32])
    }

    #[test]
    fn a3_roundtrip_and_cap_of_64() {
        let (s, y) = shares(1);
        let sh = KekShares {
            sep_ecdh_share: &s,
            yubikey_prf: &y,
        };
        let mut env = EnvelopeA3::new(0, &sh).unwrap();
        let mut last = None;
        for i in 0..A3_MAX_SEALS_PER_EPOCH {
            last = Some(
                env.seal_c3(format!("acct-{i}").as_bytes(), b"sess||SYNTH")
                    .unwrap(),
            );
        }
        assert!(env.seal_c3(b"x", b"").unwrap_err().is("A3_EPOCH_EXHAUSTED"));
        let k = unwrap_tier::<A3>(env.wrapped(), &sh).unwrap();
        assert_eq!(
            open(&k, last.as_ref().unwrap(), b"sess||SYNTH")
                .unwrap()
                .expose(),
            b"acct-63"
        );
        assert!(open(&k, last.as_ref().unwrap(), b"other-aad").is_err());
        env.rekey(&sh).unwrap();
        assert_eq!(env.public_key().epoch(), 1);
        env.seal_c3(b"after-rekey", b"").unwrap();
    }

    #[test]
    fn a3_unwrap_reveals_nothing_about_a4() {
        // Same hardware shares for both tiers: tier labels still produce independent KEKs,
        // and the keypairs are independently generated.
        let (s, y) = shares(2);
        let sh = KekShares {
            sep_ecdh_share: &s,
            yubikey_prf: &y,
        };
        let mut a3 = EnvelopeA3::new(0, &sh).unwrap();
        let a4 = EnvelopeA4::new(0, &sh).unwrap();
        assert_ne!(a3.public_key().to_bytes(), a4.public_key().to_bytes());
        let c4 = a4.seal_c4_or_bulk(b"SSN 078-05-1120", b"aad").unwrap();
        let k3 = unwrap_tier::<A3>(a3.wrapped(), &sh).unwrap();
        // A3 key cannot open A4 ciphertexts (type check + tier tag + key mismatch).
        let mut forged = c4.clone();
        forged.tier = "A3".into();
        assert!(open(&k3, &forged, b"aad").is_err());
        // The A4 wrapped blob does not unwrap as A3 and vice versa.
        assert!(unwrap_tier::<A3>(a4.wrapped(), &sh)
            .unwrap_err()
            .is("TIER_MISMATCH"));
        let mut relabelled = a4.wrapped().clone();
        relabelled.tier = "A3".into();
        assert!(unwrap_tier::<A3>(&relabelled, &sh)
            .unwrap_err()
            .is("TIER_UNWRAP_FAILED"));
        let _ = a3.seal_c3(b"c3", b"").unwrap();
        let k4 = unwrap_tier::<A4>(a4.wrapped(), &sh).unwrap();
        assert_eq!(open(&k4, &c4, b"aad").unwrap().expose(), b"SSN 078-05-1120");
    }

    #[test]
    fn missing_or_wrong_factor_fails_closed() {
        let (s, y) = shares(3);
        let sh = KekShares {
            sep_ecdh_share: &s,
            yubikey_prf: &y,
        };
        let a4 = EnvelopeA4::new(7, &sh).unwrap();
        let wrong = [9u8; 32];
        assert!(unwrap_tier::<A4>(
            a4.wrapped(),
            &KekShares {
                sep_ecdh_share: &s,
                yubikey_prf: &wrong
            }
        )
        .is_err());
        assert!(unwrap_tier::<A4>(
            a4.wrapped(),
            &KekShares {
                sep_ecdh_share: &wrong,
                yubikey_prf: &y
            }
        )
        .is_err());
        assert!(unwrap_tier::<A4>(
            a4.wrapped(),
            &KekShares {
                sep_ecdh_share: &s,
                yubikey_prf: &[]
            }
        )
        .is_err());
    }

    #[test]
    fn stale_epoch_rejected() {
        let (s, y) = shares(4);
        let sh = KekShares {
            sep_ecdh_share: &s,
            yubikey_prf: &y,
        };
        let mut a3 = EnvelopeA3::new(0, &sh).unwrap();
        let old = a3.seal_c3(b"old", b"").unwrap();
        a3.rekey(&sh).unwrap();
        let k_new = unwrap_tier::<A3>(a3.wrapped(), &sh).unwrap();
        assert!(open(&k_new, &old, b"").unwrap_err().is("EPOCH_MISMATCH"));
    }

    #[test]
    fn hybrid_ml_kem_768_and_x25519_tamper_fails_closed() {
        let (s, y) = shares(5);
        let sh = KekShares {
            sep_ecdh_share: &s,
            yubikey_prf: &y,
        };
        let a4 = EnvelopeA4::new(0, &sh).unwrap();
        assert_eq!(
            a4.public_key().to_bytes().len(),
            crate::pqc::HYBRID_KEM_PUBLIC_KEY_SIZE
        );

        let sealed = a4
            .seal_c4_or_bulk(b"PHI: patient-record-9921", b"ctx-aad")
            .unwrap();
        assert_eq!(sealed.enc.len(), crate::pqc::HYBRID_KEM_CIPHERTEXT_SIZE);

        let k4 = unwrap_tier::<A4>(a4.wrapped(), &sh).unwrap();

        // 1. Tamper with the X25519 ephemeral public key (first 32 bytes of enc).
        let mut bad_x25519 = sealed.clone();
        bad_x25519.enc[0] ^= 0x01;
        assert!(open(&k4, &bad_x25519, b"ctx-aad")
            .unwrap_err()
            .is("HPKE_OPEN_FAILED"));

        // 2. Tamper with the NIST FIPS 203 ML-KEM-768 ciphertext (bytes 32..1120 of enc).
        // FO transform implicit rejection produces a divergent pseudorandom shared secret,
        // causing ChaCha20Poly1305 authentication to fail closed.
        let mut bad_mlkem = sealed.clone();
        bad_mlkem.enc[512] ^= 0x01;
        assert!(open(&k4, &bad_mlkem, b"ctx-aad")
            .unwrap_err()
            .is("HPKE_OPEN_FAILED"));
    }
}
