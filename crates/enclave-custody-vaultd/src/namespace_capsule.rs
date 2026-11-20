//! Local alternate-member access to an exact existing namespace envelope.
//!
//! A capsule contains an encrypted KEK, never authorization. The service must
//! independently check current admitted membership, the complete fresh intent
//! ceremony, enterprise authority, clocks, counters and the final release fence.
//! No persistence or activation lives here. In particular, a missing capsule
//! must never trigger a direct-KDF/primary/caller-key retry under membership.
use enclave_core::{err, fail, error::EnclaveResult, profile::Profile, secret::SecretKey32};
use enclave_crypto::{hpke_envelope::{self, A4, EnvelopeA4, SealedValue, UnwrappedTierKey,
    VerifiedEnvelopeContext, ENVELOPE_VERSION, HYBRID_SUITE}, namespace::{self, WrappedNamespaceKey}};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Bounds one capsule, not the aggregate keyring. The parent must also bound
/// its whole serialized candidate before a single atomic publication.
pub(crate) const MAX_CAPSULE_JSON_BYTES: usize = 4096;
const MAX_MIGRATION_ENVELOPES: usize = 64;

/// Stable pool identity, deliberately independent of receipt-renewal generation.
/// Only the vault derives the expected scope from its current exact checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NamespaceCapsuleScope {
    pub(crate) profile: Profile,
    pub(crate) policy_revision: u64,
    pub(crate) policy_digest: [u8; 32],
    pub(crate) source_binding: [u8; 32],
    pub(crate) pool_digest: [u8; 32],
    pub(crate) a4_public_sha256: [u8; 32],
}
impl NamespaceCapsuleScope {
    fn check(&self, context: &VerifiedEnvelopeContext, now: i64) -> EnclaveResult<()> {
        context.admit(self.profile, "C4", now, false)?;
        if self.profile == Profile::L1 || self.policy_revision != context.revision()
            || self.policy_digest != context.digest() {
            fail!(EACCES, "NAMESPACE_CAPSULE_SCOPE");
        }
        Ok(())
    }
}

/// Compact public encoding avoids thousands of JSON integer-array bytes per
/// encapsulation. These are exact existing hybrid seal bytes, not a new suite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ciphertext {
    version: u32, suite: String, context: [u8; 32], tier: String, epoch: u32,
    enc_hex: String, ct_hex: String,
}
impl Ciphertext {
    fn encode(value: SealedValue) -> Self {
        Self { version: value.version, suite: value.suite, context: value.context,
            tier: value.tier, epoch: value.epoch, enc_hex: hex::encode(value.enc), ct_hex: hex::encode(value.ct) }
    }
    fn validate(&self, context: [u8; 32]) -> EnclaveResult<()> {
        let lower_hex = |text: &str, length| text.len() == length
            && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if self.version != ENVELOPE_VERSION || self.suite != HYBRID_SUITE
            || self.context != context || self.tier != "A4" || self.epoch != 0
            || !lower_hex(&self.enc_hex, 2240) || !lower_hex(&self.ct_hex, 96) {
            fail!(EACCES, "NAMESPACE_CAPSULE_FORMAT");
        }
        Ok(())
    }
    fn decode(&self) -> EnclaveResult<SealedValue> {
        Ok(SealedValue { version: self.version, suite: self.suite.clone(), context: self.context,
            tier: self.tier.clone(), epoch: self.epoch,
            enc: hex::decode(&self.enc_hex).map_err(|_| err!(EACCES, "NAMESPACE_CAPSULE_FORMAT"))?,
            ct: hex::decode(&self.ct_hex).map_err(|_| err!(EACCES, "NAMESPACE_CAPSULE_FORMAT"))? })
    }
}

/// Encrypted local staging fact only. Deserializing this type grants nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NamespaceKekCapsule {
    version: u32,
    scope: NamespaceCapsuleScope,
    envelope_sha256: [u8; 32],
    sealed: Ciphertext,
}
fn envelope_digest(canonical: &WrappedNamespaceKey) -> EnclaveResult<[u8; 32]> {
    canonical.validate()?;
    let mut hash = Sha256::new(); hash.update(b"depot-NamespaceCanonicalEnvelope-v1\0");
    hash.update(enclave_core::jcs::to_jcs_bytes(canonical)?); Ok(hash.finalize().into())
}
fn aad(scope: &NamespaceCapsuleScope, canonical: &WrappedNamespaceKey) -> EnclaveResult<Vec<u8>> {
    #[derive(Serialize)]
    struct Aad<'a> { kind: &'static str, version: u32, scope: &'a NamespaceCapsuleScope,
        namespace: &'a str, epoch: u64, wrapping_epoch: u64, envelope_sha256: [u8; 32] }
    enclave_core::jcs::to_jcs_bytes(&Aad { kind: "depot-NamespaceKekCapsule", version: 1, scope,
        namespace: &canonical.namespace, epoch: canonical.epoch, wrapping_epoch: canonical.wrapping_epoch,
        envelope_sha256: envelope_digest(canonical)? })
}
impl NamespaceKekCapsule {
    /// Authenticate the actual canonical envelope before staging its KEK. The
    /// returned encrypted candidate must join that exact envelope in ONE parent
    /// keyring save; it is never an independently authoritative sidecar.
    pub(crate) fn seal_checked(public: &EnvelopeA4, expected: &NamespaceCapsuleScope,
        canonical: &WrappedNamespaceKey, kek: &SecretKey32,
        context: &VerifiedEnvelopeContext, now: i64) -> EnclaveResult<Self> {
        expected.check(context, now)?;
        let wrapped = public.wrapped();
        if wrapped.context != expected.policy_digest || wrapped.epoch != 0
            || <[u8; 32]>::from(Sha256::digest(&wrapped.public_key)) != expected.a4_public_sha256 {
            fail!(EACCES, "NAMESPACE_CAPSULE_SCOPE");
        }
        drop(namespace::unwrap(canonical, kek)?);
        let sealed = Ciphertext::encode(public.seal_c4_or_bulk(kek.expose(), &aad(expected, canonical)?)?);
        let result = Self { version: 1, scope: expected.clone(), envelope_sha256: envelope_digest(canonical)?, sealed };
        result.validate(expected, canonical, context, now)?; Ok(result)
    }
    /// Public validation only, useful before any private-tier work.
    pub(crate) fn validate(&self, expected: &NamespaceCapsuleScope, canonical: &WrappedNamespaceKey,
        context: &VerifiedEnvelopeContext, now: i64) -> EnclaveResult<()> {
        expected.check(context, now)?;
        if self.scope != *expected {
            fail!(EACCES, "NAMESPACE_CAPSULE_SCOPE");
        }
        self.validate_canonical(canonical)
    }
    /// Sealed-keyring shape/exact canonical association only. This deliberately
    /// cannot assert current policy, membership, factors or key possession; the
    /// parent must separately use the vault's current expected-scope validator.
    pub(crate) fn validate_canonical(&self, canonical: &WrappedNamespaceKey) -> EnclaveResult<()> {
        if self.version != 1 || self.scope.profile == Profile::L1 || self.scope.policy_revision == 0
            || self.envelope_sha256 != envelope_digest(canonical)? {
            fail!(EACCES, "NAMESPACE_CAPSULE_SCOPE");
        }
        self.sealed.validate(self.scope.policy_digest)?;
        if serde_json::to_vec(self).map_err(|_| err!(EIO, "NAMESPACE_CAPSULE_ENCODE"))?.len() > MAX_CAPSULE_JSON_BYTES {
            fail!(E2BIG, "NAMESPACE_CAPSULE_SIZE");
        }
        Ok(())
    }
    /// Open only this fixed purpose, then actually authenticate its canonical
    /// namespace envelope. The caller owns the short-lived returned KEK.
    pub(crate) fn open_checked(&self, private: &UnwrappedTierKey<A4>, expected: &NamespaceCapsuleScope,
        canonical: &WrappedNamespaceKey, context: &VerifiedEnvelopeContext, now: i64) -> EnclaveResult<SecretKey32> {
        self.validate(expected, canonical, context, now)?;
        let plain = hpke_envelope::open(private, &self.sealed.decode()?, &aad(expected, canonical)?)?;
        let kek = SecretKey32::new(plain.expose().try_into().map_err(|_| err!(EACCES, "NAMESPACE_CAPSULE_KEY_LENGTH"))?);
        drop(namespace::unwrap(canonical, &kek)?); Ok(kek)
    }
    /// Explicit legacy-primary staging. No prefix can escape on failure. The
    /// service must authenticate that these are ORIGINAL PRIMARY shares and
    /// check the same original operation window/generation in `check` before
    /// input reads, during every item and again after durable publication.
    pub(crate) fn stage_primary_migration(public: &EnvelopeA4, expected: &NamespaceCapsuleScope,
        canonical: &[WrappedNamespaceKey], sep: &[u8], primary_prf: &[u8],
        context: &VerifiedEnvelopeContext, now: i64, mut check: impl FnMut() -> EnclaveResult<()>)
        -> EnclaveResult<Vec<Self>> {
        check()?; expected.check(context, now)?;
        if canonical.is_empty() || canonical.len() > MAX_MIGRATION_ENVELOPES {
            fail!(E2BIG, "NAMESPACE_CAPSULE_MIGRATION_SIZE");
        }
        for (index, key) in canonical.iter().enumerate() {
            key.validate()?;
            if key.namespace != canonical[0].namespace || canonical[..index].iter().any(|old| old.epoch == key.epoch) {
                fail!(EACCES, "NAMESPACE_CAPSULE_MIGRATION_SET");
            }
        }
        let mut result = Vec::with_capacity(canonical.len());
        for key in canonical {
            check()?;
            let kek = namespace::custody_kek(sep, primary_prf, &key.namespace, key.wrapping_epoch)?;
            result.push(Self::seal_checked(public, expected, key, &kek, context, now)?);
            check()?;
        }
        check()?; Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use enclave_crypto::hpke_envelope::{EnvelopePolicy, SignedEnvelopePolicy, KekShares,
        rewrap_tier, unwrap_tier};
    const SEP: [u8; 32] = [11; 32];
    const PRIMARY: [u8; 32] = [12; 32];
    const BACKUP: [u8; 32] = [13; 32];
    fn shares(prf: &[u8; 32]) -> KekShares<'_> { KekShares { sep_ecdh_share: &SEP, yubikey_prf: prf } }
    fn context() -> VerifiedEnvelopeContext {
        let signer = SigningKey::from_bytes(&[39; 32]);
        let policy = EnvelopePolicy { version: 1, revision: 2, subject: "fixture-host".into(),
            namespace: "fixture-data".into(), issued_unix: 1, expires_unix: 100, review_unix: 90,
            owner: "fixture-owner".into(), profiles: vec![Profile::L2], data_classes: vec!["C3".into(), "C4".into()],
            purpose: "synthetic namespace capsule fixture".into(), migration: "reviewed successor".into(),
            disclosure: None, classical_exception: false };
        let signature = signer.sign(&policy.signing_message().unwrap()).to_bytes().to_vec();
        SignedEnvelopePolicy { policy, signature }.verify(&signer.verifying_key(), "fixture-host", "fixture-data", 20).unwrap()
    }
    fn fixture() -> (VerifiedEnvelopeContext, EnvelopeA4, NamespaceCapsuleScope) {
        let context = context(); let public = EnvelopeA4::new_bound(0, &shares(&PRIMARY), &context).unwrap();
        let expected = NamespaceCapsuleScope { profile: Profile::L2, policy_revision: context.revision(),
            policy_digest: context.digest(), source_binding: [255; 32], pool_digest: [254; 32],
            a4_public_sha256: Sha256::digest(&public.wrapped().public_key).into() };
        (context, public, expected)
    }
    fn canonical(prf: &[u8; 32], epoch: u64, wrapping: u64) -> (WrappedNamespaceKey, SecretKey32) {
        let kek = namespace::custody_kek(&SEP, prf, "models", wrapping).unwrap();
        (namespace::wrap("models", epoch, wrapping, &[epoch as u8; 32], &kek).unwrap(), kek)
    }
    fn corrupt_nonce(key: &mut WrappedNamespaceKey) {
        let first = u8::from_str_radix(&key.envelope_hex[..2], 16).unwrap();
        key.envelope_hex.replace_range(..2, &format!("{:02x}", first ^ 1));
    }

    #[test]
    fn actual_alternate_hybrid_wrapper_opens_legacy_kek_and_preserves_canonical_artifact() {
        let (context, public, expected) = fixture(); let (canonical, kek) = canonical(&PRIMARY, 1, 1);
        let before = serde_json::to_vec(&canonical).unwrap();
        let dek = namespace::unwrap(&canonical, &kek).unwrap(); let root = [9; 32];
        let (ciphertext, record) = namespace::encrypt_chunk(&dek, &root, 0, true, b"retained synthetic model bytes").unwrap();
        let capsule = NamespaceKekCapsule::seal_checked(&public, &expected, &canonical, &kek, &context, 20).unwrap();
        let alternate = rewrap_tier::<A4>(public.wrapped(), &shares(&PRIMARY), &shares(&BACKUP), &context, Profile::L2, 20).unwrap();
        let selected = unwrap_tier::<A4>(&alternate, &shares(&BACKUP)).unwrap();
        let restored = capsule.open_checked(&selected, &expected, &canonical, &context, 20).unwrap();
        assert_eq!(restored.expose(), kek.expose());
        assert_eq!(&*namespace::decrypt_chunk(&namespace::unwrap(&canonical, &restored).unwrap(), &root, 0, true, &ciphertext, &record).unwrap(), b"retained synthetic model bytes");
        let wrong = namespace::custody_kek(&SEP, &BACKUP, "models", 1).unwrap();
        assert!(namespace::unwrap(&canonical, &wrong).is_err(), "actual reproduction of direct selected-PRF incompatibility");
        assert_eq!(serde_json::to_vec(&canonical).unwrap(), before);
        let bytes = serde_json::to_vec(&capsule).unwrap(); assert!(bytes.len() <= MAX_CAPSULE_JSON_BYTES);
        let restarted: NamespaceKekCapsule = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(restarted.open_checked(&selected, &expected, &canonical, &context, 20).unwrap().expose(), kek.expose());
    }

    #[test]
    fn backup_created_canonical_becomes_primary_readable_without_other_prf_or_reupload() {
        let (context, public, expected) = fixture(); let (canonical, backup_kek) = canonical(&BACKUP, 7, 3);
        let capsule = NamespaceKekCapsule::seal_checked(&public, &expected, &canonical, &backup_kek, &context, 20).unwrap();
        let primary = unwrap_tier::<A4>(public.wrapped(), &shares(&PRIMARY)).unwrap();
        let reopened = capsule.open_checked(&primary, &expected, &canonical, &context, 20).unwrap();
        assert_eq!(namespace::unwrap(&canonical, &reopened).unwrap().expose(), &[7; 32]);
        let direct = namespace::custody_kek(&SEP, &PRIMARY, "models", 3).unwrap();
        assert!(namespace::unwrap(&canonical, &direct).is_err());
        assert!(NamespaceKekCapsule::seal_checked(&public, &expected, &canonical, &direct, &context, 20).is_err(), "wrong KEK cannot even become a candidate");
    }

    #[test]
    fn exact_scope_aad_canonical_identity_and_current_policy_reject_substitution() {
        let (context, public, expected) = fixture(); let (canonical, kek) = canonical(&PRIMARY, 1, 1);
        let capsule = NamespaceKekCapsule::seal_checked(&public, &expected, &canonical, &kek, &context, 20).unwrap();
        let private = unwrap_tier::<A4>(public.wrapped(), &shares(&PRIMARY)).unwrap();
        for field in 0..6 {
            let mut changed = expected.clone();
            match field { 0 => changed.source_binding[0] ^= 1, 1 => changed.pool_digest[0] ^= 1,
                2 => changed.a4_public_sha256[0] ^= 1, 3 => changed.policy_revision += 1,
                4 => changed.policy_digest[0] ^= 1, _ => changed.profile = Profile::L3 }
            assert!(capsule.open_checked(&private, &changed, &canonical, &context, 20).is_err());
            // Altering the stored header to match the false expected scope
            // still cannot reauthenticate the original hybrid ciphertext.
            let mut forged = capsule.clone(); forged.scope = changed.clone();
            assert!(forged.open_checked(&private, &changed, &canonical, &context, 20).is_err());
        }
        for field in 0..4 {
            let mut changed = canonical.clone();
            match field { 0 => changed.namespace = "other".into(), 1 => changed.epoch += 1,
                2 => changed.wrapping_epoch += 1, _ => corrupt_nonce(&mut changed) }
            let mut forged = capsule.clone(); forged.envelope_sha256 = envelope_digest(&changed).unwrap();
            assert!(forged.open_checked(&private, &expected, &changed, &context, 20).is_err());
        }
        assert!(capsule.open_checked(&private, &expected, &canonical, &context, 90).is_err());
        let expired_transport = context.clone().with_transport_expiry(21, 20).unwrap();
        assert!(capsule.open_checked(&private, &expected, &canonical, &expired_transport, 21).is_err());
    }

    #[test]
    fn bounded_fixed_format_wrong_key_and_authentic_bad_plaintext_never_fallback() {
        let (context, public, expected) = fixture(); let (canonical, kek) = canonical(&PRIMARY, 1, 1);
        let capsule = NamespaceKekCapsule::seal_checked(&public, &expected, &canonical, &kek, &context, 20).unwrap();
        let private = unwrap_tier::<A4>(public.wrapped(), &shares(&PRIMARY)).unwrap();
        for field in 0..9 {
            let mut changed = capsule.clone();
            match field { 0 => changed.version += 1, 1 => changed.sealed.version += 1,
                2 => changed.sealed.suite.push('x'), 3 => changed.sealed.tier = "A3".into(),
                4 => changed.sealed.epoch += 1, 5 => changed.sealed.enc_hex.push('0'),
                6 => changed.sealed.enc_hex.replace_range(0..1, "A"), 7 => changed.sealed.ct_hex.push('0'),
                _ => changed.sealed.context[0] ^= 1 }
            assert!(changed.open_checked(&private, &expected, &canonical, &context, 20).is_err());
        }
        for bad_plain in [&[8; 31][..], &[8; 32][..]] {
            let mut changed = capsule.clone();
            changed.sealed = Ciphertext::encode(public.seal_c4_or_bulk(bad_plain, &aad(&expected, &canonical).unwrap()).unwrap());
            assert!(changed.open_checked(&private, &expected, &canonical, &context, 20).is_err());
        }
        let other = EnvelopeA4::new_bound(0, &shares(&PRIMARY), &context).unwrap();
        let wrong_private = unwrap_tier::<A4>(other.wrapped(), &shares(&PRIMARY)).unwrap();
        assert!(capsule.open_checked(&wrong_private, &expected, &canonical, &context, 20).is_err());
        let mut unknown = serde_json::to_value(&capsule).unwrap(); unknown["extra"] = serde_json::json!(true);
        assert!(serde_json::from_value::<NamespaceKekCapsule>(unknown).is_err());
    }

    #[test]
    fn primary_migration_requires_every_actual_historical_envelope_and_checks_whole_work_window() {
        let (context, public, expected) = fixture();
        let keys: Vec<_> = (1..=3).map(|epoch| canonical(&PRIMARY, epoch, epoch).0).collect();
        let capsules = NamespaceKekCapsule::stage_primary_migration(&public, &expected, &keys, &SEP, &PRIMARY, &context, 20, || Ok(())).unwrap();
        let private = unwrap_tier::<A4>(public.wrapped(), &shares(&PRIMARY)).unwrap();
        for (key, capsule) in keys.iter().zip(&capsules) {
            assert_eq!(namespace::unwrap(key, &capsule.open_checked(&private, &expected, key, &context, 20).unwrap()).unwrap().expose(), &[key.epoch as u8; 32]);
        }
        let mut bad_last = keys.clone(); corrupt_nonce(&mut bad_last[2]);
        assert!(NamespaceKekCapsule::stage_primary_migration(&public, &expected, &bad_last, &SEP, &PRIMARY, &context, 20, || Ok(())).is_err());
        assert!(NamespaceKekCapsule::stage_primary_migration(&public, &expected, &keys, &SEP, &BACKUP, &context, 20, || Ok(())).is_err());
        let mut checks = 0;
        assert!(NamespaceKekCapsule::stage_primary_migration(&public, &expected, &keys, &SEP, &PRIMARY, &context, 20, || {
            checks += 1; if checks == 4 { fail!(ETIMEDOUT, "SYNTHETIC_OPERATION_DEADLINE"); } Ok(())
        }).unwrap_err().is("SYNTHETIC_OPERATION_DEADLINE"));
        for invalid in [Vec::new(), vec![keys[0].clone(); 2], vec![keys[0].clone(); 65]] {
            assert!(NamespaceKekCapsule::stage_primary_migration(&public, &expected, &invalid, &SEP, &PRIMARY, &context, 20, || Ok(())).is_err());
        }
    }
}
