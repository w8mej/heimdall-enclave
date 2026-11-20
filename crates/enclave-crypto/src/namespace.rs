//! Versioned namespace keys. Public manifests carry only custody-wrapped keys.
//! A wrapping epoch can be changed without rewriting historical artifact bytes.
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use enclave_core::{err, error::EnclaveResult, fail, secret::SecretKey32};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// A secret field whose Debug representation is always redacted.
#[derive(Clone, Serialize, Deserialize)]
pub struct SecretMaterial(#[serde(with = "serde_bytes")] pub Vec<u8>);
impl std::fmt::Debug for SecretMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretMaterial([REDACTED])")
    }
}
impl Drop for SecretMaterial {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}
/// Opaque local custody envelope, suitable for inclusion in signed TUF metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedNamespaceKey {
    /// Domain identifier.
    pub namespace: String,
    /// Data-key epoch; zero is never valid.
    pub epoch: u64,
    /// Active KEK epoch. This may advance while `epoch` remains unchanged.
    pub wrapping_epoch: u64,
    /// Random nonce and authenticated wrapped 32-byte key (72 bytes total).
    pub envelope_hex: String,
}
impl WrappedNamespaceKey {
    /// Validate the public envelope before asking hardware for shares.
    pub fn validate(&self) -> EnclaveResult<()> {
        if self.namespace.is_empty()
            || self.namespace.len() > 128
            || !self
                .namespace
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || self.epoch == 0
            || self.wrapping_epoch == 0
            || self.envelope_hex.len() != 144
            || !self
                .envelope_hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            fail!(EINVAL, "NAMESPACE_KEY_SHAPE");
        }
        Ok(())
    }
    fn aad(&self) -> Vec<u8> {
        format!(
            "MCPMac-CAS-namespace-key-v1\0{}\0{}\0{}",
            self.namespace, self.epoch, self.wrapping_epoch
        )
        .into_bytes()
    }
}
/// Derive a local wrapping key from two independently obtained hardware shares.
/// Neither share alone permits namespace-key release.
pub fn custody_kek(
    sep: &[u8],
    prf: &[u8],
    namespace: &str,
    wrapping_epoch: u64,
) -> EnclaveResult<SecretKey32> {
    if sep.len() != 32 || prf.len() != 32 {
        fail!(EACCES, "NAMESPACE_CUSTODY_SHARES");
    }
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(sep);
    ikm.extend_from_slice(prf);
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(b"MCPMac-CAS-dual-custody-v1"), &ikm);
    let info = format!("{namespace}\0{wrapping_epoch}");
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(info.as_bytes(), &mut *key)
        .map_err(|_| err!(EIO, "NAMESPACE_KDF"))?;
    Ok(SecretKey32::new(*key))
}
/// Wrap one DEK using local dual custody. No private signing material is needed.
pub fn wrap(
    namespace: &str,
    epoch: u64,
    wrapping_epoch: u64,
    dek: &[u8; 32],
    kek: &SecretKey32,
) -> EnclaveResult<WrappedNamespaceKey> {
    let mut value = WrappedNamespaceKey {
        namespace: namespace.into(),
        epoch,
        wrapping_epoch,
        envelope_hex: "00".repeat(72),
    };
    value.validate()?;
    let nonce: [u8; 24] = enclave_core::rng::bytes32()[..24].try_into().unwrap();
    let c =
        XChaCha20Poly1305::new_from_slice(kek.expose()).map_err(|_| err!(EIO, "NAMESPACE_KEY"))?;
    let encrypted = c
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: dek,
                aad: &value.aad(),
            },
        )
        .map_err(|_| err!(EIO, "NAMESPACE_WRAP"))?;
    let mut envelope = nonce.to_vec();
    envelope.extend_from_slice(&encrypted);
    value.envelope_hex = hex::encode(envelope);
    Ok(value)
}
/// Authenticate and unwrap exactly one key. Epoch/domain edits cannot release it.
pub fn unwrap(value: &WrappedNamespaceKey, kek: &SecretKey32) -> EnclaveResult<SecretKey32> {
    value.validate()?;
    let envelope =
        hex::decode(&value.envelope_hex).map_err(|_| err!(EINVAL, "NAMESPACE_KEY_SHAPE"))?;
    let c =
        XChaCha20Poly1305::new_from_slice(kek.expose()).map_err(|_| err!(EIO, "NAMESPACE_KEY"))?;
    let plain = Zeroizing::new(
        c.decrypt(
            XNonce::from_slice(&envelope[..24]),
            Payload {
                msg: &envelope[24..],
                aad: &value.aad(),
            },
        )
        .map_err(|_| err!(EACCES, "NAMESPACE_UNWRAP"))?,
    );
    let key: [u8; 32] = plain
        .as_slice()
        .try_into()
        .map_err(|_| err!(EACCES, "NAMESPACE_KEY_LENGTH"))?;
    Ok(SecretKey32::new(key))
}

/// A 16KiB ciphertext transport leaf. Wrapped content-key records travel in a
/// separately signed Bao stream so each ciphertext leaf keeps16B tag overhead.
pub const LEAF_SIZE: usize = 16 * 1024;
/// Ciphertext leaves preserve the specified16B AEAD tag overhead.
pub const CHUNK_OVERHEAD: usize = 16;
/// Independent per-leaf wrapped-key record length.
pub const KEY_RECORD_SIZE: usize = 72;
/// Maximum plaintext in one encrypted leaf.
pub const PLAINTEXT_SIZE: usize = LEAF_SIZE - CHUNK_OVERHEAD;
fn chunk_aad(root: &[u8; 32], index: u64, final_chunk: bool) -> Vec<u8> {
    let mut b = b"MCPMac-CAS-chunk-v1\0".to_vec();
    b.extend_from_slice(root);
    b.extend_from_slice(&index.to_be_bytes());
    b.push(u8::from(final_chunk));
    b
}
fn content_key(dek: &SecretKey32, plain: &[u8]) -> SecretKey32 {
    let mut h = blake3::Hasher::new_keyed(dek.expose());
    h.update(b"enclave-cas-chunk-v1");
    h.update(plain);
    SecretKey32::new(*blake3::Hasher::finalize(&h).as_bytes())
}
fn encryption_key(content: &SecretKey32, aad: &[u8]) -> SecretKey32 {
    let mut h = blake3::Hasher::new_keyed(content.expose());
    h.update(b"MCPMac-CAS-context-key-v1\0");
    h.update(aad);
    SecretKey32::new(*blake3::Hasher::finalize(&h).as_bytes())
}
fn content_nonce(key: &SecretKey32) -> [u8; 24] {
    blake3::derive_key("enclave-cas-xchacha-nonce-v1", key.expose())[..24]
        .try_into()
        .unwrap()
}
/// Encrypt a plaintext chunk with the specified namespace-keyed construction.
/// The derived key is wrapped under DEK so recipients can decrypt low-entropy chunks
/// without knowing their plaintext. Bao authenticates this whole record first.
pub fn encrypt_chunk(
    dek: &SecretKey32,
    root: &[u8; 32],
    index: u64,
    final_chunk: bool,
    plain: &[u8],
) -> EnclaveResult<(Vec<u8>, Vec<u8>)> {
    if plain.is_empty()
        || plain.len() > PLAINTEXT_SIZE
        || (!final_chunk && plain.len() != PLAINTEXT_SIZE)
    {
        fail!(EINVAL, "NAMESPACE_CHUNK_LENGTH");
    }
    let key = content_key(dek, plain);
    let aad = chunk_aad(root, index, final_chunk);
    let nonce: [u8; 24] = enclave_core::rng::bytes32()[..24].try_into().unwrap();
    let wrap =
        XChaCha20Poly1305::new_from_slice(dek.expose()).map_err(|_| err!(EIO, "NAMESPACE_KEY"))?;
    let mut out = nonce.to_vec();
    out.extend(
        wrap.encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: key.expose(),
                aad: &aad,
            },
        )
        .map_err(|_| err!(EIO, "NAMESPACE_CHUNK_WRAP"))?,
    );
    let subkey = encryption_key(&key, &aad);
    let cipher = XChaCha20Poly1305::new_from_slice(subkey.expose())
        .map_err(|_| err!(EIO, "NAMESPACE_KEY"))?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&content_nonce(&subkey)),
            Payload {
                msg: plain,
                aad: &aad,
            },
        )
        .map_err(|_| err!(EIO, "NAMESPACE_CHUNK_ENCRYPT"))?;
    Ok((ciphertext, out))
}
/// Decrypt only a previously Bao-authenticated leaf, then check content-key derivation.
pub fn decrypt_chunk(
    dek: &SecretKey32,
    root: &[u8; 32],
    index: u64,
    final_chunk: bool,
    bytes: &[u8],
    wrapped_key: &[u8],
) -> EnclaveResult<Zeroizing<Vec<u8>>> {
    if wrapped_key.len() != KEY_RECORD_SIZE
        || bytes.len() <= CHUNK_OVERHEAD
        || bytes.len() > LEAF_SIZE
        || (!final_chunk && bytes.len() != LEAF_SIZE)
    {
        fail!(EACCES, "NAMESPACE_CHUNK_LENGTH");
    }
    let aad = chunk_aad(root, index, final_chunk);
    let wrap =
        XChaCha20Poly1305::new_from_slice(dek.expose()).map_err(|_| err!(EIO, "NAMESPACE_KEY"))?;
    let unwrapped = Zeroizing::new(
        wrap.decrypt(
            XNonce::from_slice(&wrapped_key[..24]),
            Payload {
                msg: &wrapped_key[24..72],
                aad: &aad,
            },
        )
        .map_err(|_| err!(EACCES, "NAMESPACE_CHUNK_KEY"))?,
    );
    let key = SecretKey32::new(
        unwrapped
            .as_slice()
            .try_into()
            .map_err(|_| err!(EACCES, "NAMESPACE_KEY_LENGTH"))?,
    );
    let subkey = encryption_key(&key, &aad);
    let cipher = XChaCha20Poly1305::new_from_slice(subkey.expose())
        .map_err(|_| err!(EIO, "NAMESPACE_KEY"))?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&content_nonce(&subkey)),
                Payload {
                    msg: bytes,
                    aad: &aad,
                },
            )
            .map_err(|_| err!(EACCES, "NAMESPACE_CHUNK_DECRYPT"))?,
    );
    use subtle::ConstantTimeEq;
    if !bool::from(content_key(dek, &plain).expose().ct_eq(key.expose())) {
        fail!(EACCES, "NAMESPACE_CHUNK_DERIVATION");
    }
    Ok(plain)
}

/// A bounded custody lease. Restarts and every local wipe invalidate all leases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CasKeyLease {
    /// Independent engineer membership; absent for operator provisioning and
    /// explicitly simulated historical fixtures only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enterprise: Option<enclave_core::enterprise_authority::EnterpriseLease>,
    /// Unpredictable issued lease identifier, checked against custody's registry.
    pub id: String,
    /// Namespace whose current custody authorization released this key.
    pub namespace: String,
    /// Authenticated DEK epoch from the namespace envelope.
    pub key_epoch: u64,
    /// Custody daemon boot identifier; restart invalidates every old lease.
    pub boot_epoch: String,
    /// Atomic local revocation generation observed before hardware release.
    pub generation: u64,
    /// Absolute trusted UTC expiration, at most60seconds after issuance.
    pub expires_unix: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn f38_namespace_custody_binding_and_zero_reupload_rotation() {
        let old = custody_kek(&[1; 32], &[2; 32], "models", 1).unwrap();
        let new = custody_kek(&[1; 32], &[2; 32], "models", 2).unwrap();
        let dek = SecretKey32::new([7; 32]);
        let wrapped = wrap("models", 1, 1, dek.expose(), &old).unwrap();
        assert_eq!(unwrap(&wrapped, &old).unwrap().expose(), dek.expose());
        for other in [
            custody_kek(&[9; 32], &[2; 32], "models", 1).unwrap(),
            custody_kek(&[1; 32], &[9; 32], "models", 1).unwrap(),
            new.clone(),
        ] {
            assert!(unwrap(&wrapped, &other).is_err());
        }
        let historical = b"historical policy";
        let root = *blake3::hash(historical).as_bytes();
        let (ciphertext, key_record) = encrypt_chunk(&dek, &root, 0, true, historical).unwrap();
        let rotated = wrap("models", 1, 2, dek.expose(), &new).unwrap();
        let restored = unwrap(&rotated, &new).unwrap();
        assert_eq!(
            &*decrypt_chunk(&restored, &root, 0, true, &ciphertext, &key_record).unwrap(),
            historical
        );
        let mut edited = rotated.clone();
        edited.namespace = "elsewhere".into();
        assert!(unwrap(&edited, &new).is_err());
        edited = rotated.clone();
        edited.epoch += 1;
        assert!(unwrap(&edited, &new).is_err());
    }
    #[test]
    fn f38_namespace_leaf_geometry_and_authentication_before_plaintext() {
        let key = SecretKey32::new([7; 32]);
        let plain = vec![42; PLAINTEXT_SIZE];
        let root = *blake3::hash(&plain).as_bytes();
        let (ciphertext, record) = encrypt_chunk(&key, &root, 0, false, &plain).unwrap();
        assert_eq!(ciphertext.len(), 16384);
        assert_eq!(plain.len(), 16368);
        assert_eq!(record.len(), 72);
        assert_eq!(
            &*decrypt_chunk(&key, &root, 0, false, &ciphertext, &record).unwrap(),
            &plain
        );
        assert!(decrypt_chunk(&key, &root, 1, false, &ciphertext, &record).is_err());
        assert!(decrypt_chunk(&key, &root, 0, true, &ciphertext, &record).is_err());
        assert!(decrypt_chunk(
            &SecretKey32::new([8; 32]),
            &root,
            0,
            false,
            &ciphertext,
            &record
        )
        .is_err());
        for offset in [0, 15, ciphertext.len() - 1] {
            let mut bad = ciphertext.clone();
            bad[offset] ^= 1;
            assert!(decrypt_chunk(&key, &root, 0, false, &bad, &record).is_err());
        }
        for offset in [0, 23, 71] {
            let mut bad = record.clone();
            bad[offset] ^= 1;
            assert!(decrypt_chunk(&key, &root, 0, false, &ciphertext, &bad).is_err());
        }
        let (same_context, _) = encrypt_chunk(&key, &root, 0, false, &plain).unwrap();
        assert_eq!(
            ciphertext, same_context,
            "the deterministic body is stable in one authenticated context"
        );
        for (other_root, other_index, other_final) in
            [(root, 1, false), ([9; 32], 0, false), (root, 0, true)]
        {
            let (other, other_record) =
                encrypt_chunk(&key, &other_root, other_index, other_final, &plain).unwrap();
            // Different AAD already changes the Poly1305 tag even with reused
            // key/nonce. Compare only the encrypted body to detect actual
            // keystream reuse across contexts, then authenticate each result.
            assert_ne!(
                &ciphertext[..plain.len()],
                &other[..plain.len()],
                "root/index/finality must separate the encryption stream"
            );
            assert_eq!(
                &*decrypt_chunk(
                    &key,
                    &other_root,
                    other_index,
                    other_final,
                    &other,
                    &other_record
                )
                .unwrap(),
                &plain
            );
            assert!(decrypt_chunk(&key, &root, 0, false, &other, &other_record).is_err());
        }
        assert!(encrypt_chunk(&key, &root, 0, false, b"short").is_err());
    }
}
