//! Explicit historical-v1 readers and staged migration. Never an automatic
//! fallback from v2. Formats/labels come from 8495daaa^ (classical) and e40f7076
//! (hybrid). A separately signed exact-batch policy authorizes each import.
use super::*;
use enclave_core::profile::Profile;
use hpke::kem::X25519HkdfSha256 as ClassicalKem;
use hpke::{Deserializable, Kem as _, Serializable};

/// Exact historical source codec, selected by authenticated migration policy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum LegacyFormat {
    /// RFC 9180 X25519/HKDF-SHA256/ChaCha20Poly1305, before 8495daaa.
    ClassicalV1,
    /// The frozen MCPMac bespoke hybrid format before authenticated v2 headers.
    HybridV1,
}
impl LegacyFormat {
    fn migration_prefix(self) -> &'static str {
        match self {
            Self::ClassicalV1 => "legacy-classical-v1-to-hybrid-v2:",
            Self::HybridV1 => "legacy-hybrid-v1-to-hybrid-v2:",
        }
    }
}
/// Historical wrapped key, deliberately a different type from the v2 codec.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyWrappedTierKey {
    /// Exact tier.
    pub tier: String,
    /// Exact source epoch.
    pub epoch: u32,
    /// Source public key, 32 classical or 1216 hybrid bytes.
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    /// AEAD nonce, exactly 12 bytes.
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    /// Authenticated wrapped source private key.
    #[serde(with = "serde_bytes")]
    pub ct: Vec<u8>,
}
/// Historical sealed value; no ambiguous serde defaults on the v2 type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacySealedValue {
    /// Exact tier.
    pub tier: String,
    /// Exact source epoch.
    pub epoch: u32,
    /// Source encapsulation.
    #[serde(with = "serde_bytes")]
    pub enc: Vec<u8>,
    /// Source ciphertext.
    #[serde(with = "serde_bytes")]
    pub ct: Vec<u8>,
}
/// A signed-manifest-bound record, including its exact source AAD and class.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyRecord {
    /// C3 or C4, authenticated by the exact-batch policy.
    pub data_class: String,
    /// Exact historical associated data, never re-created from caller claims.
    #[serde(with = "serde_bytes")]
    pub aad: Vec<u8>,
    /// Ciphertext.
    pub sealed: LegacySealedValue,
}
/// Immutable source batch; caller retains it until durable verified cutover.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyBatch {
    /// Explicit reader, never guessed from failure or input lengths.
    pub format: LegacyFormat,
    /// One independent source tier/epoch.
    pub wrapped: LegacyWrappedTierKey,
    /// Records scoped by the issuer's exact canonical batch digest.
    pub records: Vec<LegacyRecord>,
}
impl LegacyBatch {
    /// Put this exact value in the signed policy's `migration` field. The issuer
    /// must independently authenticate the old asset/namespace and this inventory.
    pub fn migration_binding(&self) -> EnclaveResult<String> {
        self.bounds()?;
        let bytes = enclave_core::jcs::to_jcs_bytes(self)?;
        Ok(format!(
            "{}{}",
            self.format.migration_prefix(),
            blake3::hash(&bytes).to_hex()
        ))
    }
    fn bounds(&self) -> EnclaveResult<()> {
        if self.records.is_empty() || self.records.len() > 4096 {
            fail!(E2BIG, "LEGACY_MIGRATION_BOUNDS");
        }
        let (public_max, secret_max, enc_max) = match self.format {
            LegacyFormat::ClassicalV1 => (32, 32, 32),
            LegacyFormat::HybridV1 => (
                HYBRID_KEM_PUBLIC_KEY_SIZE,
                HYBRID_KEM_SECRET_KEY_SIZE,
                crate::pqc::HYBRID_KEM_CIPHERTEXT_SIZE,
            ),
        };
        let wrapped = &self.wrapped;
        if wrapped.tier.len() > 2
            || wrapped.public_key.len() > public_max
            || wrapped.nonce.len() > 12
            || wrapped.ct.len() > secret_max + 16
        {
            fail!(E2BIG, "LEGACY_MIGRATION_BOUNDS");
        }
        let mut total = 0usize;
        let mut add = |length: usize| -> EnclaveResult<()> {
            total = total
                .checked_add(length)
                .ok_or_else(|| err!(E2BIG, "LEGACY_MIGRATION_BOUNDS"))?;
            if total > 8 * 1024 * 1024 {
                fail!(E2BIG, "LEGACY_MIGRATION_BOUNDS");
            }
            Ok(())
        };
        for length in [
            wrapped.tier.len(),
            wrapped.public_key.len(),
            wrapped.nonce.len(),
            wrapped.ct.len(),
        ] {
            add(length)?;
        }
        for record in &self.records {
            if record.data_class.len() > 2
                || record.sealed.tier.len() > 2
                || record.sealed.enc.len() > enc_max
            {
                fail!(E2BIG, "LEGACY_MIGRATION_BOUNDS");
            }
            for length in [
                record.data_class.len(),
                record.aad.len(),
                record.sealed.tier.len(),
                record.sealed.enc.len(),
                record.sealed.ct.len(),
            ] {
                add(length)?;
            }
        }
        // Upper bounds precede JCS allocation. Short/malformed inputs still bind
        // exactly and fail the explicit authenticated format checks on import.
        Ok(())
    }
}
/// Staged hybrid output. No source key or data is retired by creating this value.
#[derive(Debug)]
pub struct MigratedTierBatch<T: Tier> {
    /// Independently generated new hybrid public key.
    pub public_key: TierPublicKey<T>,
    /// New wrapped 2432-byte secret, with authenticated v2 context.
    pub wrapped: WrappedTierKey,
    /// Re-sealed records, in the same order and using the exact bound AAD.
    pub records: Vec<SealedValue>,
}

fn source_wrap_aad<T: Tier>(w: &LegacyWrappedTierKey) -> Vec<u8> {
    let mut aad = b"MCPMac-WrappedTierKey-v1:".to_vec();
    aad.extend_from_slice(T::NAME.as_bytes());
    aad.extend_from_slice(&w.epoch.to_be_bytes());
    aad.extend_from_slice(&w.public_key);
    aad
}
fn source_secret<T: Tier>(
    batch: &LegacyBatch,
    shares: &KekShares<'_>,
) -> EnclaveResult<SecretBytes> {
    let w = &batch.wrapped;
    let (pk_len, sk_len) = match batch.format {
        LegacyFormat::ClassicalV1 => (32, 32),
        LegacyFormat::HybridV1 => (HYBRID_KEM_PUBLIC_KEY_SIZE, HYBRID_KEM_SECRET_KEY_SIZE),
    };
    if w.tier != T::NAME
        || w.public_key.len() != pk_len
        || w.nonce.len() != 12
        || w.ct.len() != sk_len + 16
    {
        fail!(EACCES, "LEGACY_MIGRATION_KEY_FORMAT");
    }
    let kek = derive_kek::<T>(shares, w.epoch, &w.public_key)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(kek.expose()));
    let secret = SecretBytes::new(
        cipher
            .decrypt(
                Nonce::from_slice(&w.nonce),
                Payload {
                    msg: &w.ct,
                    aad: &source_wrap_aad::<T>(w),
                },
            )
            .map_err(|_| err!(EACCES, "LEGACY_MIGRATION_UNWRAP"))?,
    );
    let actual = match batch.format {
        LegacyFormat::ClassicalV1 => {
            let sk = <ClassicalKem as hpke::Kem>::PrivateKey::from_bytes(secret.expose())
                .map_err(|_| err!(EACCES, "LEGACY_MIGRATION_KEY"))?;
            ClassicalKem::sk_to_pk(&sk).to_bytes().to_vec()
        }
        LegacyFormat::HybridV1 => HybridKemKeyPair::from_secret_bytes(secret.expose())?
            .public_key()
            .to_bytes(),
    };
    if actual != w.public_key {
        fail!(EACCES, "LEGACY_MIGRATION_KEY_BINDING");
    }
    Ok(secret)
}
fn source_open<T: Tier>(
    batch: &LegacyBatch,
    secret: &SecretBytes,
    r: &LegacyRecord,
) -> EnclaveResult<SecretBytes> {
    if r.sealed.tier != T::NAME || r.sealed.epoch != batch.wrapped.epoch || r.sealed.ct.len() < 16 {
        fail!(EACCES, "LEGACY_MIGRATION_RECORD_FORMAT");
    }
    let plaintext = match batch.format {
        LegacyFormat::ClassicalV1 => {
            let sk = <ClassicalKem as hpke::Kem>::PrivateKey::from_bytes(secret.expose())
                .map_err(|_| err!(EACCES, "LEGACY_MIGRATION_KEY"))?;
            let enc = <ClassicalKem as hpke::Kem>::EncappedKey::from_bytes(&r.sealed.enc)
                .map_err(|_| err!(EACCES, "LEGACY_MIGRATION_ENCAP"))?;
            hpke::single_shot_open::<
                hpke::aead::ChaCha20Poly1305,
                hpke::kdf::HkdfSha256,
                ClassicalKem,
            >(
                &hpke::OpModeR::Base,
                &sk,
                &enc,
                T::HPKE_INFO,
                &r.sealed.ct,
                &r.aad,
            )
            .map_err(|_| err!(EACCES, "LEGACY_MIGRATION_OPEN"))?
        }
        LegacyFormat::HybridV1 => {
            let key = HybridKemKeyPair::from_secret_bytes(secret.expose())?;
            let enc = HybridKemCiphertext::from_bytes(&r.sealed.enc)?;
            let shared = key.decapsulate(&enc)?;
            let derived = derive_seal_key_and_nonce::<T>(&shared.0, r.sealed.epoch, &r.sealed.enc)?;
            ChaCha20Poly1305::new(Key::from_slice(&derived[..32]))
                .decrypt(
                    Nonce::from_slice(&derived[32..]),
                    Payload {
                        msg: &r.sealed.ct,
                        aad: &r.aad,
                    },
                )
                .map_err(|_| err!(EACCES, "LEGACY_MIGRATION_OPEN"))?
        }
    };
    Ok(SecretBytes::new(plaintext))
}
/// Explicit verified open/reseal transaction in memory. The signed migration
/// string must commit to the complete source batch. Classical input additionally
/// requires a disclosed scoped exception. On any failure, new secret/partial
/// output drops; the immutable original batch remains intact. Caller must
/// durably commit all output and a nondecreasing migration/policy floor before
/// retiring old keys or acknowledging cutover; never overwrite records piecemeal.
pub fn migrate_batch<T: Tier>(
    source: &LegacyBatch,
    source_shares: &KekShares<'_>,
    target_shares: &KekShares<'_>,
    target_epoch: u32,
    context: &VerifiedEnvelopeContext,
    profile: Profile,
    now: i64,
) -> EnclaveResult<MigratedTierBatch<T>> {
    source.bounds()?;
    if source.migration_binding()? != context.policy.migration {
        fail!(EACCES, "LEGACY_MIGRATION_NOT_AUTHORIZED");
    }
    if T::NAME == A3::NAME && source.records.len() > A3_MAX_SEALS_PER_EPOCH as usize {
        fail!(EACCES, "A3_EPOCH_EXHAUSTED");
    }
    for record in &source.records {
        if (T::NAME == A3::NAME && record.data_class != "C3")
            || (record.data_class != "C3" && record.data_class != "C4")
        {
            fail!(EACCES, "LEGACY_MIGRATION_CLASS");
        }
        context.admit(
            profile,
            &record.data_class,
            now,
            matches!(source.format, LegacyFormat::ClassicalV1),
        )?;
    }
    let old_secret = source_secret::<T>(source, source_shares)?;
    let (public_key, wrapped) = generate_tier_bound::<T>(target_epoch, target_shares, context)?;
    let verification_key = unwrap_tier::<T>(&wrapped, target_shares)?;
    let mut records = Vec::with_capacity(source.records.len());
    for record in &source.records {
        let plaintext = source_open::<T>(source, &old_secret, record)?;
        let sealed = seal(&public_key, plaintext.expose(), &record.aad)?;
        let verified = open(&verification_key, &sealed, &record.aad)?;
        if !enclave_core::secret::ct_eq(verified.expose(), plaintext.expose()) {
            fail!(EACCES, "LEGACY_MIGRATION_VERIFY");
        }
        records.push(sealed);
    }
    drop(verification_key);
    drop(old_secret);
    Ok(MigratedTierBatch {
        public_key,
        wrapped,
        records,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn shares(seed: u8) -> ([u8; 32], [u8; 32]) {
        ([seed; 32], [seed + 1; 32])
    }
    fn fixture(format: LegacyFormat, shares: &KekShares<'_>) -> LegacyBatch {
        let (secret, public) = match format {
            LegacyFormat::ClassicalV1 => {
                let (sk, pk) = ClassicalKem::gen_keypair(&mut EnclaveRng);
                (
                    SecretBytes::new(sk.to_bytes().to_vec()),
                    pk.to_bytes().to_vec(),
                )
            }
            LegacyFormat::HybridV1 => {
                let key = HybridKemKeyPair::generate();
                (
                    SecretBytes::from_slice(&key.to_secret_bytes()),
                    key.public_key().to_bytes(),
                )
            }
        };
        let mut wrapped = LegacyWrappedTierKey {
            tier: "A3".into(),
            epoch: 2,
            public_key: public,
            nonce: vec![17; 12],
            ct: vec![],
        };
        let kek = derive_kek::<A3>(shares, wrapped.epoch, &wrapped.public_key).unwrap();
        wrapped.ct = ChaCha20Poly1305::new(Key::from_slice(kek.expose()))
            .encrypt(
                Nonce::from_slice(&wrapped.nonce),
                Payload {
                    msg: secret.expose(),
                    aad: &source_wrap_aad::<A3>(&wrapped),
                },
            )
            .unwrap();
        let mut records = Vec::new();
        for message in [
            b"synthetic-first".as_slice(),
            b"synthetic-second".as_slice(),
        ] {
            let aad = b"historical-session/surrogate".to_vec();
            let (enc, ct) = match format {
                LegacyFormat::ClassicalV1 => {
                    let pk =
                        <ClassicalKem as hpke::Kem>::PublicKey::from_bytes(&wrapped.public_key)
                            .unwrap();
                    let (enc, ct) = hpke::single_shot_seal::<
                        hpke::aead::ChaCha20Poly1305,
                        hpke::kdf::HkdfSha256,
                        ClassicalKem,
                        _,
                    >(
                        &hpke::OpModeS::Base,
                        &pk,
                        A3::HPKE_INFO,
                        message,
                        &aad,
                        &mut EnclaveRng,
                    )
                    .unwrap();
                    (enc.to_bytes().to_vec(), ct)
                }
                LegacyFormat::HybridV1 => {
                    let pk = HybridKemPublicKey::from_bytes(&wrapped.public_key).unwrap();
                    let (enc, shared) = HybridKemKeyPair::encapsulate(&pk).unwrap();
                    let enc = enc.to_bytes();
                    let key = derive_seal_key_and_nonce::<A3>(&shared.0, 2, &enc).unwrap();
                    let ct = ChaCha20Poly1305::new(Key::from_slice(&key[..32]))
                        .encrypt(
                            Nonce::from_slice(&key[32..]),
                            Payload {
                                msg: message,
                                aad: &aad,
                            },
                        )
                        .unwrap();
                    (enc, ct)
                }
            };
            records.push(LegacyRecord {
                data_class: "C3".into(),
                aad,
                sealed: LegacySealedValue {
                    tier: "A3".into(),
                    epoch: 2,
                    enc,
                    ct,
                },
            });
        }
        LegacyBatch {
            format,
            wrapped,
            records,
        }
    }
    fn context(batch: &LegacyBatch, classical: bool) -> VerifiedEnvelopeContext {
        let issuer = SigningKey::from_bytes(&[72; 32]);
        let policy = EnvelopePolicy {
            version: 1,
            revision: 2,
            subject: "legacy-fixture-host".into(),
            namespace: "fixture".into(),
            issued_unix: 1,
            expires_unix: 100,
            review_unix: 100,
            owner: "fixture-admin".into(),
            profiles: vec![Profile::L2],
            data_classes: vec!["C3".into()],
            purpose: "explicit legacy import".into(),
            migration: batch.migration_binding().unwrap(),
            disclosure: classical.then(|| "fixture-classical-risk-ack".into()),
            classical_exception: classical,
        };
        let signature = issuer
            .sign(&policy.signing_message().unwrap())
            .to_bytes()
            .to_vec();
        SignedEnvelopePolicy { policy, signature }
            .verify(&issuer.verifying_key(), "legacy-fixture-host", "fixture", 2)
            .unwrap()
    }
    #[test]
    fn every_variable_batch_field_is_bounded_before_manifest_canonicalization() {
        let (s, y) = shares(4);
        let shares = KekShares {
            sep_ecdh_share: &s,
            yubikey_prf: &y,
        };
        let source = fixture(LegacyFormat::ClassicalV1, &shares);
        let mut variants = Vec::new();
        let mut changed = source.clone();
        changed.wrapped.tier = "A33".into();
        variants.push(changed);
        let mut changed = source.clone();
        changed.wrapped.public_key.resize(33, 0);
        variants.push(changed);
        let mut changed = source.clone();
        changed.wrapped.nonce.resize(13, 0);
        variants.push(changed);
        let mut changed = source.clone();
        changed.wrapped.ct.resize(49, 0);
        variants.push(changed);
        let mut changed = source.clone();
        changed.records[0].data_class = "C33".into();
        variants.push(changed);
        let mut changed = source.clone();
        changed.records[0].sealed.tier = "A33".into();
        variants.push(changed);
        let mut changed = source.clone();
        changed.records[0].sealed.enc.resize(33, 0);
        variants.push(changed);
        for oversized in variants {
            assert!(oversized
                .migration_binding()
                .unwrap_err()
                .is("LEGACY_MIGRATION_BOUNDS"));
        }
        let mut total = source.clone();
        total.records[0].aad.resize(4 * 1024 * 1024, 0);
        total.records[1].sealed.ct.resize(4 * 1024 * 1024, 0);
        assert!(total
            .migration_binding()
            .unwrap_err()
            .is("LEGACY_MIGRATION_BOUNDS"));
        let mut short = source;
        short.wrapped.public_key.pop();
        assert!(short.migration_binding().is_ok());
    }
    #[test]
    fn explicit_historical_readers_reseal_verified_independent_hybrid_output() {
        let (s, y) = shares(4);
        let source_shares = KekShares {
            sep_ecdh_share: &s,
            yubikey_prf: &y,
        };
        let (new_s, new_y) = shares(8);
        let target_shares = KekShares {
            sep_ecdh_share: &new_s,
            yubikey_prf: &new_y,
        };
        for format in [LegacyFormat::ClassicalV1, LegacyFormat::HybridV1] {
            let source = fixture(format, &source_shares);
            let before = serde_json::to_vec(&source).unwrap();
            let authorized = context(&source, matches!(format, LegacyFormat::ClassicalV1));
            let result = migrate_batch::<A3>(
                &source,
                &source_shares,
                &target_shares,
                9,
                &authorized,
                Profile::L2,
                2,
            )
            .unwrap();
            assert_eq!(result.public_key.to_bytes().len(), 1216);
            assert_eq!(result.wrapped.ct.len(), 2432 + 16);
            let key = unwrap_tier::<A3>(&result.wrapped, &target_shares).unwrap();
            for (i, expected) in [
                b"synthetic-first".as_slice(),
                b"synthetic-second".as_slice(),
            ]
            .iter()
            .enumerate()
            {
                assert_eq!(
                    open(&key, &result.records[i], &source.records[i].aad)
                        .unwrap()
                        .expose(),
                    *expected
                );
            }
            assert!(unwrap_tier::<A3>(&result.wrapped, &source_shares).is_err());
            assert_eq!(serde_json::to_vec(&source).unwrap(), before);
        }
    }
    #[test]
    fn no_fallback_and_atomic_failure_on_wrong_manifest_expiry_or_late_corruption() {
        let (s, y) = shares(4);
        let shares = KekShares {
            sep_ecdh_share: &s,
            yubikey_prf: &y,
        };
        let source = fixture(LegacyFormat::ClassicalV1, &shares);
        assert!(migrate_batch::<A3>(
            &source,
            &shares,
            &shares,
            9,
            &context(&source, false),
            Profile::L2,
            2
        )
        .is_err());
        let authorized = context(&source, true);
        assert!(
            migrate_batch::<A3>(&source, &shares, &shares, 9, &authorized, Profile::L2, 100)
                .is_err()
        );
        let mut changed = source.clone();
        changed.records[1].sealed.ct[0] ^= 1;
        assert!(
            migrate_batch::<A3>(&changed, &shares, &shares, 9, &authorized, Profile::L2, 2)
                .unwrap_err()
                .is("LEGACY_MIGRATION_NOT_AUTHORIZED")
        );
        // Even an authorized malformed late record cannot produce partial success
        // or mutate/delete the first source record or its old wrapped key.
        let before = serde_json::to_vec(&changed).unwrap();
        let authorized = context(&changed, true);
        assert!(
            migrate_batch::<A3>(&changed, &shares, &shares, 9, &authorized, Profile::L2, 2)
                .is_err()
        );
        assert_eq!(serde_json::to_vec(&changed).unwrap(), before);
        let mut malformed = source;
        malformed.wrapped.public_key.pop();
        let authorized = context(&malformed, true);
        assert!(
            migrate_batch::<A3>(&malformed, &shares, &shares, 9, &authorized, Profile::L2, 2)
                .is_err()
        );
    }
}
