//! `pinUvAuthProtocol = 2` (CTAP 2.1 §6.5.7): ECDH P-256 key agreement,
//! `HKDF-SHA-256` into separate HMAC and AES-256 keys, `AES-256-CBC` with a
//! random IV for `encrypt`, and full 32-byte `HMAC-SHA-256` for `authenticate`.
//! Used to carry `hmac-secret` PRF salts/outputs so a passive USB-C/Thunderbolt
//! sniffer observes zero plaintext PRF bytes.

use aes::Aes256;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use enclave_core::error::EnclaveResult;
use enclave_core::secret::SecretBytes;
use enclave_core::{err, fail};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{AffinePoint, EncodedPoint, PublicKey};
use sha2::Sha256;

use super::cbor;

/// Shared secret = `hmac_key(32) ‖ aes_key(32)`.
pub struct SharedSecret(SecretBytes);

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SharedSecret([REDACTED])")
    }
}

impl SharedSecret {
    /// KDF(Z) per protocol 2.
    pub fn from_z(z: &[u8]) -> EnclaveResult<Self> {
        let salt = [0u8; 32];
        let hk = Hkdf::<Sha256>::new(Some(&salt), z);
        let mut s = SecretBytes::zeroed(64);
        hk.expand(b"CTAP2 HMAC key", &mut s.expose_mut()[..32])
            .map_err(|_| err!(EINVAL, "HKDF"))?;
        hk.expand(b"CTAP2 AES key", &mut s.expose_mut()[32..])
            .map_err(|_| err!(EINVAL, "HKDF"))?;
        Ok(Self(s))
    }
    fn hmac_key(&self) -> &[u8] {
        &self.0.expose()[..32]
    }
    fn aes_key(&self) -> &[u8] {
        &self.0.expose()[32..]
    }
    /// `encrypt(key, pt) = iv ‖ AES-256-CBC(aes_key, iv, pt)`; `pt` must be block aligned.
    pub fn encrypt(&self, pt: &[u8]) -> EnclaveResult<Vec<u8>> {
        if pt.is_empty() || !pt.len().is_multiple_of(16) {
            fail!(EINVAL, "PIN_PROTO_ALIGNMENT");
        }
        let mut iv = [0u8; 16];
        enclave_core::rng::fill(&mut iv);
        let enc = cbc::Encryptor::<Aes256>::new(self.aes_key().into(), (&iv).into());
        let ct = enc.encrypt_padded_vec_mut::<NoPadding>(pt);
        let mut out = iv.to_vec();
        out.extend_from_slice(&ct);
        Ok(out)
    }
    /// `decrypt(key, iv ‖ ct)`.
    pub fn decrypt(&self, data: &[u8]) -> EnclaveResult<SecretBytes> {
        if data.len() < 32 || !(data.len() - 16).is_multiple_of(16) {
            fail!(EINVAL, "PIN_PROTO_ALIGNMENT");
        }
        let (iv, ct) = data.split_at(16);
        let dec = cbc::Decryptor::<Aes256>::new(self.aes_key().into(), iv.into());
        let pt = dec
            .decrypt_padded_vec_mut::<NoPadding>(ct)
            .map_err(|_| err!(EACCES, "PIN_PROTO_DECRYPT"))?;
        Ok(SecretBytes::new(pt))
    }
    /// `authenticate(key, msg) = HMAC-SHA-256(hmac_key, msg)` (32 bytes).
    pub fn authenticate(&self, msg: &[u8]) -> [u8; 32] {
        let mut m =
            <Hmac<Sha256> as Mac>::new_from_slice(self.hmac_key()).expect("32-byte HMAC key");
        m.update(msg);
        m.finalize().into_bytes().into()
    }
    /// Constant-time verification of `authenticate`.
    pub fn verify(&self, msg: &[u8], tag: &[u8]) -> bool {
        enclave_core::secret::ct_eq(&self.authenticate(msg), tag)
    }
}

/// Parse a COSE_Key (EC2 P-256) into a public key.
pub fn cose_to_p256(v: &ciborium::Value) -> EnclaveResult<PublicKey> {
    if cbor::int(cbor::iget(v, 1))? != 2 || cbor::int(cbor::iget(v, -1))? != 1 {
        fail!(EINVAL, "COSE_NOT_P256");
    }
    let x = cbor::bytes(cbor::iget(v, -2))?;
    let y = cbor::bytes(cbor::iget(v, -3))?;
    if x.len() != 32 || y.len() != 32 {
        fail!(EINVAL, "COSE_COORD_LEN");
    }
    let ep = EncodedPoint::from_affine_coordinates(x.as_slice().into(), y.as_slice().into(), false);
    let ap: Option<AffinePoint> = AffinePoint::from_encoded_point(&ep).into();
    let ap = ap.ok_or_else(|| err!(EACCES, "COSE_POINT_NOT_ON_CURVE"))?;
    PublicKey::from_affine(ap).map_err(|_| err!(EACCES, "COSE_POINT_INVALID"))
}

/// COSE encoding of a P-256 public key.
pub fn p256_to_cose(pk: &PublicKey) -> ciborium::Value {
    let ep = pk.to_encoded_point(false);
    cbor::cose_ecdh_key(
        ep.x().map(|x| x.as_slice()).unwrap_or_default(),
        ep.y().map(|y| y.as_slice()).unwrap_or_default(),
    )
}

/// Platform side: fresh ephemeral key, shared secret with the peer's key.
pub fn platform_agree(peer: &PublicKey) -> EnclaveResult<(PublicKey, SharedSecret)> {
    let eph = EphemeralSecret::random(&mut rand_core::OsRng);
    let ours = eph.public_key();
    let z = eph.diffie_hellman(peer);
    let ss = SharedSecret::from_z(z.raw_secret_bytes().as_slice())?;
    Ok((ours, ss))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_derive_the_same_secret_and_roundtrip() {
        let auth = EphemeralSecret::random(&mut rand_core::OsRng);
        let auth_pk = auth.public_key();
        let (plat_pk, plat_ss) = platform_agree(&auth_pk).unwrap();
        let auth_ss =
            SharedSecret::from_z(auth.diffie_hellman(&plat_pk).raw_secret_bytes().as_slice())
                .unwrap();
        let salt = [7u8; 32];
        let enc = plat_ss.encrypt(&salt).unwrap();
        assert_ne!(&enc[16..], &salt[..], "no plaintext on the wire");
        assert_eq!(auth_ss.decrypt(&enc).unwrap().expose(), &salt);
        let tag = plat_ss.authenticate(&enc);
        assert!(auth_ss.verify(&enc, &tag));
        assert!(!auth_ss.verify(&enc[1..], &tag));
        let cose = p256_to_cose(&plat_pk);
        assert_eq!(cose_to_p256(&cose).unwrap(), plat_pk);
    }
}
