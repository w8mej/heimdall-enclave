//! Authenticator-data parsing and the five-invariant assertion verifier of
//! FS-703 §3.3: pinned `rpIdHash`, `UP` (and `UV` when required), strictly
//! monotonic `signCount` (anti-clone), and a valid `Ed25519` (`-8`) or `ES256`
//! (`-7`) signature over `authenticatorData ‖ clientDataHash`.

use std::collections::BTreeMap;

use ciborium::Value;
use enclave_core::error::EnclaveResult;
use enclave_core::secret::SecretKey32;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};

use super::{alg, cbor, rp_id_hash};

/// `UP` flag.
pub const FLAG_UP: u8 = 0x01;
/// `UV` flag.
pub const FLAG_UV: u8 = 0x04;
/// Attested credential data present.
pub const FLAG_AT: u8 = 0x40;
/// Extensions present.
pub const FLAG_ED: u8 = 0x80;

/// Attested credential data (makeCredential).
#[derive(Debug, Clone, PartialEq)]
pub struct AttestedCredential {
    /// AAGUID.
    pub aaguid: [u8; 16],
    /// Credential ID.
    pub credential_id: Vec<u8>,
    /// COSE public key.
    pub cose_key: Value,
}

/// Parsed `authenticatorData`.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthenticatorData {
    /// SHA-256 of the RP ID.
    pub rp_id_hash: [u8; 32],
    /// Flags.
    pub flags: u8,
    /// Signature counter.
    pub sign_count: u32,
    /// Attested credential data.
    pub attested: Option<AttestedCredential>,
    /// Extension outputs.
    pub extensions: Option<Value>,
    /// Raw bytes (signed).
    pub raw: Vec<u8>,
}

impl AuthenticatorData {
    /// Parse.
    pub fn parse(raw: &[u8]) -> EnclaveResult<Self> {
        if raw.len() < 37 {
            fail!(EINVAL, "AUTHDATA_SHORT");
        }
        let mut rp = [0u8; 32];
        rp.copy_from_slice(&raw[..32]);
        let flags = raw[32];
        let sign_count = u32::from_be_bytes([raw[33], raw[34], raw[35], raw[36]]);
        let mut pos = 37usize;
        let mut attested = None;
        if flags & FLAG_AT != 0 {
            if raw.len() < pos + 18 {
                fail!(EINVAL, "AUTHDATA_SHORT");
            }
            let mut aaguid = [0u8; 16];
            aaguid.copy_from_slice(&raw[pos..pos + 16]);
            let l = u16::from_be_bytes([raw[pos + 16], raw[pos + 17]]) as usize;
            pos += 18;
            if raw.len() < pos + l || l == 0 || l > 1023 {
                fail!(EINVAL, "AUTHDATA_CRED_ID");
            }
            let credential_id = raw[pos..pos + l].to_vec();
            pos += l;
            let (cose_key, used) = cbor::decode_prefix(&raw[pos..])?;
            pos += used;
            attested = Some(AttestedCredential {
                aaguid,
                credential_id,
                cose_key,
            });
        }
        let mut extensions = None;
        if flags & FLAG_ED != 0 {
            let (ext, used) = cbor::decode_prefix(&raw[pos..])?;
            if !matches!(ext, Value::Map(_)) {
                fail!(EINVAL, "AUTHDATA_EXT_NOT_MAP");
            }
            pos += used;
            extensions = Some(ext);
        }
        if pos != raw.len() {
            fail!(EINVAL, "AUTHDATA_TRAILING_BYTES");
        }
        Ok(Self {
            rp_id_hash: rp,
            flags,
            sign_count,
            attested,
            extensions,
            raw: raw.to_vec(),
        })
    }
}

/// A credential public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialKey {
    /// COSE `-8`.
    Ed25519(ed25519_dalek::VerifyingKey),
    /// COSE `-7`.
    Es256(p256::ecdsa::VerifyingKey),
}

impl Serialize for CredentialKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (self.alg(), self.to_raw()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CredentialKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (alg_id, raw): (i64, Vec<u8>) = Deserialize::deserialize(deserializer)?;
        CredentialKey::from_raw(alg_id, &raw).map_err(serde::de::Error::custom)
    }
}

impl CredentialKey {
    /// From a COSE key.
    pub fn from_cose(v: &Value) -> EnclaveResult<Self> {
        let kty = cbor::int(cbor::iget(v, 1))?;
        let a = cbor::int(cbor::iget(v, 3))?;
        match (kty, a) {
            (1, alg::EDDSA) => {
                if cbor::int(cbor::iget(v, -1))? != 6 {
                    fail!(EINVAL, "COSE_NOT_ED25519");
                }
                let x: [u8; 32] = cbor::bytes(cbor::iget(v, -2))?
                    .try_into()
                    .map_err(|_| err!(EINVAL, "COSE_LEN"))?;
                Ok(Self::Ed25519(
                    ed25519_dalek::VerifyingKey::from_bytes(&x)
                        .map_err(|_| err!(EACCES, "COSE_BAD_KEY"))?,
                ))
            }
            (2, alg::ES256) => {
                if cbor::int(cbor::iget(v, -1))? != 1 {
                    fail!(EINVAL, "COSE_NOT_P256");
                }
                let pk = super::pin::cose_to_p256(&cbor::imap(vec![
                    (1, Value::Integer(2.into())),
                    (-1, Value::Integer(1.into())),
                    (-2, Value::Bytes(cbor::bytes(cbor::iget(v, -2))?)),
                    (-3, Value::Bytes(cbor::bytes(cbor::iget(v, -3))?)),
                ]))?;
                Ok(Self::Es256(p256::ecdsa::VerifyingKey::from(pk)))
            }
            _ => fail!(EACCES, "COSE_UNSUPPORTED_ALG", "kty {kty} alg {a}"),
        }
    }
    /// COSE algorithm.
    pub fn alg(&self) -> i64 {
        match self {
            Self::Ed25519(_) => alg::EDDSA,
            Self::Es256(_) => alg::ES256,
        }
    }
    /// Raw public key bytes (Ed25519 32 B, or SEC1 uncompressed 65 B).
    pub fn to_raw(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(k) => k.to_bytes().to_vec(),
            Self::Es256(k) => k.to_encoded_point(false).as_bytes().to_vec(),
        }
    }
    /// From raw bytes with an algorithm.
    pub fn from_raw(alg_id: i64, raw: &[u8]) -> EnclaveResult<Self> {
        match alg_id {
            alg::EDDSA => {
                let b: [u8; 32] = raw.try_into().map_err(|_| err!(EINVAL, "KEY_LEN"))?;
                Ok(Self::Ed25519(
                    ed25519_dalek::VerifyingKey::from_bytes(&b).map_err(|_| err!(EINVAL, "KEY"))?,
                ))
            }
            alg::ES256 => Ok(Self::Es256(
                p256::ecdsa::VerifyingKey::from_sec1_bytes(raw).map_err(|_| err!(EINVAL, "KEY"))?,
            )),
            _ => fail!(EINVAL, "KEY_ALG"),
        }
    }
    /// Verify a signature over `msg`.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        match self {
            Self::Ed25519(k) => ed25519_dalek::Signature::from_slice(sig)
                .is_ok_and(|s| k.verify_strict(msg, &s).is_ok()),
            Self::Es256(k) => {
                use p256::ecdsa::signature::Verifier;
                p256::ecdsa::Signature::from_der(sig)
                    .or_else(|_| p256::ecdsa::Signature::from_slice(sig))
                    .is_ok_and(|s| k.verify(msg, &s).is_ok())
            }
        }
    }
}

/// An enrolled custodian credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrolledCredential {
    /// Credential ID.
    pub credential_id: Vec<u8>,
    /// Public key.
    pub key: CredentialKey,
    /// AAGUID.
    pub aaguid: [u8; 16],
    /// Firmware at enrollment.
    pub firmware_version: u32,
}

/// A `getAssertion` response.
#[derive(Debug, Clone)]
pub struct AssertionResponse {
    /// Credential ID returned (if any).
    pub credential_id: Option<Vec<u8>>,
    /// Raw authenticator data.
    pub auth_data: Vec<u8>,
    /// Signature.
    pub signature: Vec<u8>,
}

/// Persisted (MAC-authenticated) last-seen counters.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignCountStore {
    counts: BTreeMap<String, u32>,
    /// Algorithm plus normalized public-key fingerprint; aliases share a floor.
    #[serde(default)]
    key_counts: BTreeMap<String, u32>,
}

impl SignCountStore {
    /// Last persisted count for a credential.
    pub fn get(&self, cred: &[u8]) -> u32 {
        self.counts.get(&hex::encode(cred)).copied().unwrap_or(0)
    }
    /// Whether this complete authenticated snapshot preserves every earlier
    /// handle and key-alias floor. Unrelated entries must survive recovery too;
    /// comparing only the ceremony's selected credentials can hide rollback.
    pub(crate) fn dominates(&self, previous: &Self) -> bool {
        previous
            .counts
            .iter()
            .all(|(id, floor)| self.counts.get(id).is_some_and(|count| count >= floor))
            && previous
                .key_counts
                .iter()
                .all(|(id, floor)| self.key_counts.get(id).is_some_and(|count| count >= floor))
    }
    fn key_id(key: &CredentialKey) -> String {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update((key.alg() as i32).to_be_bytes());
        let normalized = match key {
            CredentialKey::Ed25519(key) => key.to_edwards().compress().to_bytes().to_vec(),
            CredentialKey::Es256(_) => key.to_raw(),
        };
        hash.update(normalized);
        hex::encode(hash.finalize())
    }
    fn legacy_key_id(key: &CredentialKey) -> String {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update((key.alg() as i32).to_be_bytes());
        hash.update(key.to_raw());
        hex::encode(hash.finalize())
    }
    /// Highest authenticated counter for either the handle or public-key alias.
    pub fn get_credential(&self, cred: &EnrolledCredential) -> u32 {
        self.get(&cred.credential_id)
            .max(
                self.key_counts
                    .get(&Self::key_id(&cred.key))
                    .copied()
                    .unwrap_or(0),
            )
            .max(
                self.key_counts
                    .get(&Self::legacy_key_id(&cred.key))
                    .copied()
                    .unwrap_or(0),
            )
    }
    /// Bind legacy handle counts to the enrolled normalized key before use.
    /// Call for every restored credential before accepting any assertion: a new
    /// alias cannot otherwise discover a historical handle-to-key relationship.
    pub fn bind_credentials<'a>(
        &mut self,
        credentials: impl IntoIterator<Item = &'a EnrolledCredential>,
    ) {
        for credential in credentials {
            let count = self.get_credential(credential);
            self.key_counts
                .entry(Self::key_id(&credential.key))
                .and_modify(|old| *old = (*old).max(count))
                .or_insert(count);
        }
    }
    fn set_credential(&mut self, cred: &EnrolledCredential, c: u32) {
        self.counts.insert(hex::encode(&cred.credential_id), c);
        self.key_counts.insert(Self::key_id(&cred.key), c);
    }
    /// MAC-sealed JSON.
    pub fn seal(&self, k: &SecretKey32) -> (String, String) {
        let s = serde_json::to_string(self).unwrap_or_default();
        let m = hex::encode(k.mac(s.as_bytes()));
        (s, m)
    }
    /// Restore; bad MAC fails closed.
    pub fn unseal(state: &str, mac: &str, k: &SecretKey32) -> EnclaveResult<Self> {
        if !enclave_core::secret::ct_eq(
            hex::encode(k.mac(state.as_bytes())).as_bytes(),
            mac.as_bytes(),
        ) {
            fail!(EACCES, "SIGN_COUNT_STATE_TAMPERED");
        }
        serde_json::from_str(state).map_err(|e| err!(EINVAL, "SIGN_COUNT_STATE", "{e}"))
    }
}

/// Verified assertion facts.
#[derive(Debug, Clone)]
pub struct VerifiedAssertion {
    /// New counter.
    pub sign_count: u32,
    /// `UV` asserted.
    pub user_verified: bool,
    /// Encrypted `hmac-secret` output, if requested.
    pub hmac_secret_enc: Option<Vec<u8>>,
    /// Parsed authenticator data.
    pub auth_data: AuthenticatorData,
}

/// Verify an assertion (all five invariants). A counter regression is a
/// clone indicator (`SEV-1`) and fails closed.
pub fn verify_assertion(
    cred: &EnrolledCredential,
    resp: &AssertionResponse,
    client_data_hash: &[u8; 32],
    require_uv: bool,
    counters: &mut SignCountStore,
) -> EnclaveResult<VerifiedAssertion> {
    verify_response(cred, resp, client_data_hash, true, require_uv, counters)
}

/// Authenticated nonaction observation. Contains no factor, PRF or tier material.
#[derive(Debug, Clone, Copy)]
pub struct PresenceObservation {
    /// New counter; caller durably persists the shared store before observing.
    pub sign_count: u32,
}
/// Verify a silent observation while keeping action assertions' UP invariant.
/// It cannot authorize a grant, lease, thaw or fast-reinsertion recovery.
pub fn verify_presence(
    cred: &EnrolledCredential,
    resp: &AssertionResponse,
    challenge: &[u8; 32],
    counters: &mut SignCountStore,
) -> EnclaveResult<PresenceObservation> {
    let ad = AuthenticatorData::parse(&resp.auth_data)?;
    if ad.flags & FLAG_ED != 0 {
        fail!(EACCES, "PRESENCE_EXTENSIONS_FORBIDDEN");
    }
    let verified = verify_response(cred, resp, challenge, false, false, counters)?;
    Ok(PresenceObservation {
        sign_count: verified.sign_count,
    })
}

fn verify_response(
    cred: &EnrolledCredential,
    resp: &AssertionResponse,
    client_data_hash: &[u8; 32],
    require_up: bool,
    require_uv: bool,
    counters: &mut SignCountStore,
) -> EnclaveResult<VerifiedAssertion> {
    if let Some(id) = &resp.credential_id {
        if id != &cred.credential_id {
            fail!(EACCES, "CREDENTIAL_ID_MISMATCH");
        }
    }
    let ad = AuthenticatorData::parse(&resp.auth_data)?;
    if ad.flags & FLAG_AT != 0 {
        fail!(EACCES, "ASSERTION_UNEXPECTED_ATTESTED_DATA");
    }
    if ad.rp_id_hash != rp_id_hash() {
        fail!(EACCES, "RP_ID_HASH_MISMATCH");
    }
    if require_up && ad.flags & FLAG_UP == 0 {
        fail!(EACCES, "USER_PRESENCE_MISSING", "UP bit not set");
    }
    let uv = ad.flags & FLAG_UV != 0;
    if require_uv && !uv {
        fail!(EACCES, "USER_VERIFICATION_MISSING", "PIN/UV required in L3");
    }
    let mut signed = resp.auth_data.clone();
    signed.extend_from_slice(client_data_hash);
    if !cred.key.verify(&signed, &resp.signature) {
        fail!(EACCES, "ASSERTION_SIGNATURE_INVALID");
    }
    let last = counters.get_credential(cred);
    if ad.sign_count <= last {
        fail!(
            EACCES,
            "SIGN_COUNT_REGRESSION",
            "SEV-1: possible cloned authenticator ({} <= {last})",
            ad.sign_count
        );
    }
    counters.set_credential(cred, ad.sign_count);
    let hmac_secret_enc = ad
        .extensions
        .as_ref()
        .and_then(|e| cbor::tget(e, "hmac-secret"))
        .and_then(|v| match v {
            Value::Bytes(b) => Some(b.clone()),
            _ => None,
        });
    Ok(VerifiedAssertion {
        sign_count: ad.sign_count,
        user_verified: uv,
        hmac_secret_enc,
        auth_data: ad,
    })
}

#[cfg(test)]
mod parser_security_tests {
    use super::*;
    #[test]
    fn duplicate_extension_and_wrong_curve_are_rejected() {
        let mut auth = rp_id_hash().to_vec();
        auth.push(FLAG_UP | FLAG_ED);
        auth.extend(1u32.to_be_bytes());
        auth.extend(
            cbor::encode(&cbor::tmap(vec![
                ("hmac-secret", Value::Bytes(vec![1; 48])),
                ("hmac-secret", Value::Bytes(vec![2; 48])),
            ]))
            .unwrap(),
        );
        assert!(AuthenticatorData::parse(&auth)
            .unwrap_err()
            .is("CBOR_DUPLICATE_MAP_KEY"));
        let secret = p256::SecretKey::random(&mut rand_core::OsRng);
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let point = secret.public_key().to_encoded_point(false);
        let mut key = cbor::cose_ecdh_key(point.x().unwrap(), point.y().unwrap());
        if let Value::Map(entries) = &mut key {
            for (field, value) in entries {
                if cbor::int(Some(field)).ok() == Some(3) {
                    *value = Value::Integer(alg::ES256.into());
                }
                if cbor::int(Some(field)).ok() == Some(-1) {
                    *value = Value::Integer(2.into());
                }
            }
        }
        assert!(CredentialKey::from_cose(&key)
            .unwrap_err()
            .is("COSE_NOT_P256"));
    }
}

#[cfg(test)]
mod counter_alias_tests {
    use super::*;
    #[test]
    fn accepted_noncanonical_edwards_encodings_share_the_durable_counter_floor() {
        // y and p+y can decompress to the same Edwards point. Exercise accepted
        // encodings directly; this test does not admit weak signatures.
        let pair = (0u8..19)
            .find_map(|y| {
                let mut canonical = [0u8; 32];
                canonical[0] = y;
                let mut alias = [0xffu8; 32];
                alias[0] = 0xed + y;
                alias[31] = 0x7f;
                let first = ed25519_dalek::VerifyingKey::from_bytes(&canonical).ok()?;
                let second = ed25519_dalek::VerifyingKey::from_bytes(&alias).ok()?;
                Some((first, second))
            })
            .expect("dalek accepts at least one alternate compressed-point encoding");
        let first = EnrolledCredential {
            credential_id: vec![91],
            key: CredentialKey::Ed25519(pair.0),
            aaguid: [0; 16],
            firmware_version: 1,
        };
        let alias = EnrolledCredential {
            credential_id: vec![92],
            key: CredentialKey::Ed25519(pair.1),
            ..first.clone()
        };
        let mut store = SignCountStore::default();
        store.set_credential(&first, 41);
        assert_eq!(store.get_credential(&alias), 41);
        let mut legacy = SignCountStore::default();
        legacy
            .key_counts
            .insert(SignCountStore::legacy_key_id(&alias.key), 49);
        legacy.bind_credentials([&alias]);
        let restored: SignCountStore =
            serde_json::from_slice(&serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert_eq!(restored.get_credential(&first), 49);
    }

    use ed25519_dalek::{Signer, SigningKey};
    fn response(key: &SigningKey, count: u32, hash: &[u8; 32]) -> AssertionResponse {
        let mut auth = rp_id_hash().to_vec();
        auth.push(FLAG_UP);
        auth.extend(count.to_be_bytes());
        let mut signed = auth.clone();
        signed.extend(hash);
        AssertionResponse {
            credential_id: None,
            auth_data: auth,
            signature: key.sign(&signed).to_bytes().to_vec(),
        }
    }
    #[test]
    fn aliases_and_restored_legacy_counts_share_a_public_key_floor() {
        let key = SigningKey::from_bytes(&[37; 32]);
        let first = EnrolledCredential {
            credential_id: vec![1],
            key: CredentialKey::Ed25519(key.verifying_key()),
            aaguid: [1; 16],
            firmware_version: 1,
        };
        let mut alias = first.clone();
        alias.credential_id = vec![2];
        let hash = [9; 32];
        let mut counts = SignCountStore::default();
        verify_assertion(&first, &response(&key, 8, &hash), &hash, false, &mut counts).unwrap();
        assert!(
            verify_assertion(&alias, &response(&key, 8, &hash), &hash, false, &mut counts)
                .unwrap_err()
                .is("SIGN_COUNT_REGRESSION")
        );
        let seal_key = SecretKey32::new([6; 32]);
        let (state, mac) = counts.seal(&seal_key);
        let mut restored = SignCountStore::unseal(&state, &mac, &seal_key).unwrap();
        verify_assertion(
            &alias,
            &response(&key, 9, &hash),
            &hash,
            false,
            &mut restored,
        )
        .unwrap();
        assert_eq!(restored.get_credential(&first), 9);
        let mut legacy: SignCountStore = serde_json::from_str(r#"{"counts":{"01":12}}"#).unwrap();
        legacy.bind_credentials([&first, &alias]);
        assert!(verify_assertion(
            &alias,
            &response(&key, 12, &hash),
            &hash,
            false,
            &mut legacy
        )
        .unwrap_err()
        .is("SIGN_COUNT_REGRESSION"));
        verify_assertion(
            &alias,
            &response(&key, 13, &hash),
            &hash,
            false,
            &mut legacy,
        )
        .unwrap();
        let secret = p256::SecretKey::from_slice(&[7; 32]).unwrap();
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let raw = secret.public_key().to_encoded_point(true);
        let compressed = CredentialKey::from_raw(alg::ES256, raw.as_bytes()).unwrap();
        let uncompressed = CredentialKey::from_raw(alg::ES256, &compressed.to_raw()).unwrap();
        assert_eq!(
            SignCountStore::key_id(&compressed),
            SignCountStore::key_id(&uncompressed)
        );
    }

    #[test]
    fn recovery_snapshot_preserves_unrelated_handles_and_all_alias_floors() {
        let key = SigningKey::from_bytes(&[43; 32]);
        let first = EnrolledCredential {
            credential_id: vec![1],
            key: CredentialKey::Ed25519(key.verifying_key()),
            aaguid: [1; 16],
            firmware_version: 1,
        };
        let alias = EnrolledCredential {
            credential_id: vec![2],
            ..first.clone()
        };
        let unrelated_key = SigningKey::from_bytes(&[44; 32]);
        let unrelated = EnrolledCredential {
            credential_id: vec![3],
            key: CredentialKey::Ed25519(unrelated_key.verifying_key()),
            ..first.clone()
        };
        let hash = [11; 32];
        let mut previous = SignCountStore::default();
        verify_assertion(
            &first,
            &response(&key, 8, &hash),
            &hash,
            false,
            &mut previous,
        )
        .unwrap();
        verify_assertion(
            &alias,
            &response(&key, 9, &hash),
            &hash,
            false,
            &mut previous,
        )
        .unwrap();
        verify_assertion(
            &unrelated,
            &response(&unrelated_key, 20, &hash),
            &hash,
            false,
            &mut previous,
        )
        .unwrap();
        let seal_key = SecretKey32::new([12; 32]);
        let (state, mac) = previous.seal(&seal_key);
        let mut current = SignCountStore::unseal(&state, &mac, &seal_key).unwrap();
        assert!(current.dominates(&previous));
        // An interrupted later proof may durably consume a higher count.
        verify_assertion(
            &first,
            &response(&key, 10, &hash),
            &hash,
            false,
            &mut current,
        )
        .unwrap();
        assert!(current.dominates(&previous));
        assert!(!previous.dominates(&current));
        assert!(current.dominates(&SignCountStore::default()));

        // The selected credential still sees10 if an old alias handle is lost.
        // Every authenticated entry must survive, even when another floor masks it.
        let mut missing_alias = current.clone();
        missing_alias
            .counts
            .remove(&hex::encode(&alias.credential_id));
        assert_eq!(
            missing_alias.get_credential(&alias),
            current.get_credential(&alias)
        );
        assert!(!missing_alias.dominates(&previous));
        let mut regressed_unrelated = current.clone();
        regressed_unrelated
            .counts
            .insert(hex::encode(&unrelated.credential_id), 19);
        assert_eq!(regressed_unrelated.get_credential(&unrelated), 20);
        assert!(!regressed_unrelated.dominates(&previous));
        let mut regressed_key = current.clone();
        regressed_key
            .key_counts
            .insert(SignCountStore::key_id(&unrelated.key), 19);
        assert_eq!(regressed_key.get_credential(&unrelated), 20);
        assert!(!regressed_key.dominates(&previous));
        let mut missing_key = current.clone();
        missing_key
            .key_counts
            .remove(&SignCountStore::key_id(&unrelated.key));
        assert_eq!(missing_key.get_credential(&unrelated), 20);
        assert!(!missing_key.dominates(&previous));
        assert!(verify_assertion(
            &alias,
            &response(&key, 10, &hash),
            &hash,
            false,
            &mut current
        )
        .unwrap_err()
        .is("SIGN_COUNT_REGRESSION"));
    }
}
