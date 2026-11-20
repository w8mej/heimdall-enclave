//! RFC 9458 Oblivious HTTP request encapsulation (+ RFC 9292 known-length
//! Binary HTTP) used by UID 702 to relay `ComplianceRollupProofV1` frames to the ledger
//! gateway (UID 705 holds no sockets).
//!
//! `hdr = key_id ‖ kem_id ‖ kdf_id ‖ aead_id`,
//! `info = "message/bhttp request" ‖ 0x00 ‖ hdr`,
//! `enc_request = hdr ‖ enc ‖ Seal(info, bhttp)`.
//!
//! Default production suite (`FS-707` / `GAP-62`):
//! - Hybrid Post-Quantum KEM: `X25519 + NIST FIPS 203 ML-KEM-768` with the **bespoke**
//!   depot combiner in [`crate::pqc`] (HKDF-SHA256; *not* IETF CFRG X-Wing), sent as
//!   the unregistered local id `KEM_ID_HYBRID_depot = 0xFF41` / `HKDF-SHA256` /
//!   `ChaCha20Poly1305`. The hybrid suite is depot-to-depot only and does not
//!   interoperate with RFC 9180 / X-Wing peers (DEFECT-F-76). A request carrying the
//!   IANA X-Wing id `0x647A` is refused with `OHTTP_KEM_XWING_UNSUPPORTED`.
//! - Legacy classical suite (`KEM_ID = 0x0020`, `DHKEM(X25519, HKDF-SHA256)`) is retained
//!   only for explicit `ClassicalOnly` cryptographic-agility override drills (`RB-219`);
//!   offering `0x0020` to a `HybridPqc` gateway fails closed with `PQC_DOWNGRADE_ATTEMPT_REJECTED`.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305 as AeadChaCha20Poly1305, Key, Nonce};
use enclave_core::error::EnclaveResult;
use enclave_core::profile::Profile;
use enclave_core::{err, fail};
use hkdf::Hkdf;
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::hpke_envelope::EnclaveRng as Rng;
use crate::pqc::{
    enforce_handshake_suite, HybridKemCiphertext, HybridKemKeyPair, HybridKemPublicKey,
    WireCryptoSuite, HYBRID_KEM_CIPHERTEXT_SIZE, HYBRID_KEM_PUBLIC_KEY_SIZE,
    HYBRID_KEM_SECRET_KEY_SIZE,
};

/// Classical HPKE KEM id (`DHKEM(X25519, HKDF-SHA256)`).
pub const KEM_ID: u16 = 0x0020;
/// Wire id for the bespoke depot hybrid KEM (`X25519 + ML-KEM-768`, HKDF-SHA256
/// combiner, see [`crate::pqc`]). **Not** an IANA HPKE KEM assignment: the HPKE
/// KEM registry has no private-use range, and `0xFF41` was unassigned when chosen
/// (2026-11-10; assigned values then: 0x0010-0x0016, 0x0020-0x0022, 0x0030,
/// 0x0040-0x0042, 0x0050-0x0051, 0x647A). Use between depot peers only
/// (DEFECT-F-76).
pub const KEM_ID_HYBRID_depot: u16 = 0xFF41;
/// IANA HPKE KEM id of X-Wing (`draft-connolly-cfrg-xwing-kem`). This crate does
/// **not** implement X-Wing; the id is named only so it can be refused explicitly.
pub const KEM_ID_XWING_IANA: u16 = 0x647A;
/// KDF id (`HKDF-SHA256`).
pub const KDF_ID: u16 = 0x0001;
/// AEAD id (`ChaCha20Poly1305`).
pub const AEAD_ID: u16 = 0x0003;

fn varint(out: &mut Vec<u8>, v: u64) {
    match v {
        0..=63 => out.push(v as u8),
        64..=16383 => out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes()),
        16384..=1_073_741_823 => out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes()),
        _ => out.extend_from_slice(&(v | 0xC000_0000_0000_0000).to_be_bytes()),
    }
}

fn read_varint(b: &[u8], i: &mut usize) -> EnclaveResult<u64> {
    let f = *b.get(*i).ok_or_else(|| err!(EINVAL, "BHTTP_TRUNCATED"))?;
    let len = 1usize << (f >> 6);
    let s = b
        .get(*i..*i + len)
        .ok_or_else(|| err!(EINVAL, "BHTTP_TRUNCATED"))?;
    let mut v = (s[0] & 0x3f) as u64;
    for x in &s[1..] {
        v = (v << 8) | *x as u64;
    }
    *i += len;
    Ok(v)
}

fn lp(out: &mut Vec<u8>, s: &[u8]) {
    varint(out, s.len() as u64);
    out.extend_from_slice(s);
}

/// Encode a known-length BHTTP `POST` request.
pub fn bhttp_post(authority: &str, path: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut o = vec![0u8]; // framing indicator: known-length request
    lp(&mut o, b"POST");
    lp(&mut o, b"https");
    lp(&mut o, authority.as_bytes());
    lp(&mut o, path.as_bytes());
    let mut fields = Vec::new();
    lp(&mut fields, b"content-type");
    lp(&mut fields, content_type.as_bytes());
    lp(&mut o, &fields);
    lp(&mut o, body);
    varint(&mut o, 0); // empty trailer section
    o
}

/// Decode a known-length BHTTP request → `(path, body)`.
pub fn bhttp_parse(b: &[u8]) -> EnclaveResult<(String, Vec<u8>)> {
    let mut i = 0;
    if read_varint(b, &mut i)? != 0 {
        fail!(EINVAL, "BHTTP_FRAMING");
    }
    let take = |i: &mut usize| -> EnclaveResult<Vec<u8>> {
        let n = read_varint(b, i)? as usize;
        let s = b
            .get(*i..*i + n)
            .ok_or_else(|| err!(EINVAL, "BHTTP_TRUNCATED"))?
            .to_vec();
        *i += n;
        Ok(s)
    };
    let _method = take(&mut i)?;
    let _scheme = take(&mut i)?;
    let _auth = take(&mut i)?;
    let path = String::from_utf8(take(&mut i)?).map_err(|_| err!(EINVAL, "BHTTP_PATH"))?;
    let _fields = take(&mut i)?;
    let body = take(&mut i)?;
    Ok((path, body))
}

fn header_with_kem(key_id: u8, kem_id: u16) -> Vec<u8> {
    let mut h = vec![key_id];
    h.extend_from_slice(&kem_id.to_be_bytes());
    h.extend_from_slice(&KDF_ID.to_be_bytes());
    h.extend_from_slice(&AEAD_ID.to_be_bytes());
    h
}

/// Gateway key configuration.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KeyConfig {
    /// Key id.
    pub key_id: u8,
    /// Gateway composite `X25519 + ML-KEM-768` (`1,216B`) or legacy `X25519` (`32B`) public key.
    pub public_key: Vec<u8>,
}

impl KeyConfig {
    /// Parse `"<key_id>:<public key hex>"`.
    /// Accepts either a 1,216-byte Hybrid `X25519 + ML-KEM-768` composite key (`HybridPqc`)
    /// or a 32-byte legacy `X25519` key (`ClassicalOnly`).
    pub fn parse(s: &str) -> EnclaveResult<Self> {
        let (id, pk) = s
            .split_once(':')
            .ok_or_else(|| err!(EINVAL, "OHTTP_KEY_CONFIG"))?;
        let key_id = id.parse().map_err(|_| err!(EINVAL, "OHTTP_KEY_CONFIG"))?;
        let public_key = hex::decode(pk).map_err(|_| err!(EINVAL, "OHTTP_KEY_CONFIG"))?;
        if public_key.len() == HYBRID_KEM_PUBLIC_KEY_SIZE {
            // Enforce NIST FIPS 203 §7.2 encapsulation-key modulus check on parse.
            let _ = HybridKemPublicKey::from_bytes(&public_key)?;
        } else if public_key.len() != 32 {
            fail!(
                EINVAL,
                "OHTTP_KEY_CONFIG",
                "OHTTP public key must be {} bytes (Hybrid X25519+ML-KEM-768) or 32 bytes (Classical X25519)",
                HYBRID_KEM_PUBLIC_KEY_SIZE
            );
        }
        Ok(Self { key_id, public_key })
    }
    /// Inverse of [`KeyConfig::parse`].
    pub fn render(&self) -> String {
        format!("{}:{}", self.key_id, hex::encode(&self.public_key))
    }
    /// Wire cryptographic suite negotiated by this gateway key configuration.
    pub fn suite(&self) -> WireCryptoSuite {
        if self.public_key.len() == HYBRID_KEM_PUBLIC_KEY_SIZE {
            WireCryptoSuite::HybridPqc
        } else {
            WireCryptoSuite::ClassicalOnly
        }
    }
}

/// Generate a Hybrid Post-Quantum (`X25519 + ML-KEM-768` / `KEM_ID_HYBRID_depot = 0xFF41`)
/// OHTTP gateway keypair (`1,216`-byte composite public key, `2,432`-byte composite secret key).
pub fn gateway_keypair(key_id: u8) -> (KeyConfig, Vec<u8>) {
    let kp = HybridKemKeyPair::generate();
    let pk_bytes = kp.public_key().to_bytes();
    let sk_bytes = kp.to_secret_bytes().to_vec();
    (
        KeyConfig {
            key_id,
            public_key: pk_bytes,
        },
        sk_bytes,
    )
}

/// Generate a classical-only (`DHKEM(X25519, HKDF-SHA256)`, `KEM_ID = 0x0020`) OHTTP gateway
/// keypair for cryptographic-agility fallback (`RB-219`) and anti-downgrade test vectors.
pub fn gateway_classical_keypair(key_id: u8) -> (KeyConfig, Vec<u8>) {
    let (sk, pk) = X25519HkdfSha256::gen_keypair(&mut Rng);
    (
        KeyConfig {
            key_id,
            public_key: pk.to_bytes().to_vec(),
        },
        sk.to_bytes().to_vec(),
    )
}

fn derive_ohttp_hybrid_key_and_nonce(
    shared_secret: &[u8; 32],
    hdr: &[u8],
    enc: &[u8],
) -> EnclaveResult<zeroize::Zeroizing<[u8; 44]>> {
    let hk = Hkdf::<Sha256>::new(Some(hdr), shared_secret);
    let mut info = b"message/bhttp request\0".to_vec();
    info.extend_from_slice(hdr);
    info.extend_from_slice(enc);
    let mut okm = zeroize::Zeroizing::new([0u8; 44]);
    hk.expand(&info, &mut *okm)
        .map_err(|_| err!(EIO, "OHTTP_KDF"))?;
    Ok(okm)
}

/// Derive symmetric key and nonce for RFC 9458 response decapsulation (GAP-44 / DEFECT-F-44).
pub fn derive_ohttp_response_key_and_nonce(
    shared_secret: &[u8; 32],
    hdr: &[u8],
    enc: &[u8],
) -> EnclaveResult<zeroize::Zeroizing<[u8; 44]>> {
    let hk = Hkdf::<Sha256>::new(Some(hdr), shared_secret);
    let mut info = b"message/bhttp response\0".to_vec();
    info.extend_from_slice(hdr);
    info.extend_from_slice(enc);
    let mut okm = zeroize::Zeroizing::new([0u8; 44]);
    hk.expand(&info, &mut *okm)
        .map_err(|_| err!(EIO, "OHTTP_RESPONSE_KDF"))?;
    Ok(okm)
}

/// Client context for decrypting an RFC 9458 encapsulated response.
#[derive(Debug, Clone)]
pub struct ClientResponseContext {
    /// Shared secret derived during request encapsulation.
    pub shared_secret: [u8; 32],
    /// Header bytes.
    pub hdr: Vec<u8>,
    /// Encapsulated key bytes.
    pub enc: Vec<u8>,
}

impl ClientResponseContext {
    /// Decapsulate an encrypted response from the gateway.
    pub fn decapsulate_response(&self, encapsulated_response: &[u8]) -> EnclaveResult<Vec<u8>> {
        decapsulate_response(
            &self.shared_secret,
            &self.hdr,
            &self.enc,
            encapsulated_response,
        )
    }
}

/// Gateway-side: Encapsulate a response using RFC 9458 symmetric response encryption.
pub fn encapsulate_response(
    shared_secret: &[u8; 32],
    hdr: &[u8],
    enc: &[u8],
    response: &[u8],
) -> EnclaveResult<Vec<u8>> {
    let key_and_nonce = derive_ohttp_response_key_and_nonce(shared_secret, hdr, enc)?;
    let cipher = AeadChaCha20Poly1305::new(Key::from_slice(&key_and_nonce[0..32]));
    let nonce = Nonce::from_slice(&key_and_nonce[32..44]);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: response,
                aad: b"",
            },
        )
        .map_err(|e| err!(EIO, "OHTTP_RESPONSE_SEAL", "{e}"))
}

/// Client-side: Decapsulate a response using RFC 9458 symmetric response encryption.
pub fn decapsulate_response(
    shared_secret: &[u8; 32],
    hdr: &[u8],
    enc: &[u8],
    encapsulated_response: &[u8],
) -> EnclaveResult<Vec<u8>> {
    let key_and_nonce = derive_ohttp_response_key_and_nonce(shared_secret, hdr, enc)?;
    let cipher = AeadChaCha20Poly1305::new(Key::from_slice(&key_and_nonce[0..32]));
    let nonce = Nonce::from_slice(&key_and_nonce[32..44]);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: encapsulated_response,
                aad: b"",
            },
        )
        .map_err(|e| err!(EACCES, "OHTTP_RESPONSE_OPEN", "{e}"))
}

/// Encapsulate a BHTTP request and return both wire ciphertext and response decryption context.
pub fn encapsulate_with_context(
    cfg: &KeyConfig,
    request: &[u8],
) -> EnclaveResult<(Vec<u8>, ClientResponseContext)> {
    if cfg.public_key.len() == HYBRID_KEM_PUBLIC_KEY_SIZE {
        let hybrid_pk = HybridKemPublicKey::from_bytes(&cfg.public_key)
            .map_err(|_| err!(EINVAL, "OHTTP_KEY"))?;
        let hdr = header_with_kem(cfg.key_id, KEM_ID_HYBRID_depot);
        let (kem_ct, shared_secret) =
            HybridKemKeyPair::encapsulate(&hybrid_pk).map_err(|_| err!(EIO, "OHTTP_SETUP"))?;
        let enc = kem_ct.to_bytes();
        let key_and_nonce = derive_ohttp_hybrid_key_and_nonce(&shared_secret.0, &hdr, &enc)?;
        let cipher = AeadChaCha20Poly1305::new(Key::from_slice(&key_and_nonce[0..32]));
        let nonce = Nonce::from_slice(&key_and_nonce[32..44]);
        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: request,
                    aad: b"",
                },
            )
            .map_err(|_| err!(EIO, "OHTTP_SEAL"))?;
        let mut out = Vec::with_capacity(hdr.len() + enc.len() + ct.len());
        out.extend_from_slice(&hdr);
        out.extend_from_slice(&enc);
        out.extend_from_slice(&ct);
        let ctx = ClientResponseContext {
            shared_secret: shared_secret.0,
            hdr,
            enc: enc.to_vec(),
        };
        return Ok((out, ctx));
    }

    fail!(
        EINVAL,
        "OHTTP_UNSUPPORTED_SUITE",
        "response context requires hybrid KEM"
    );
}

/// Encapsulate a BHTTP request while enforcing Profile minimum cryptographic suites.
/// In Profile L3, classical KEM is strictly forbidden to prevent quantum downgrade (DEFECT-F-48).
pub fn encapsulate_for_profile(
    cfg: &KeyConfig,
    request: &[u8],
    profile: Profile,
) -> EnclaveResult<Vec<u8>> {
    if profile == Profile::L3 && cfg.suite() == WireCryptoSuite::ClassicalOnly {
        fail!(
            EPERM,
            "POST_QUANTUM_REQUIRED_IN_L3",
            "Profile L3 mandates Hybrid X25519+ML-KEM-768; classical KEM downgrade rejected"
        );
    }
    encapsulate(cfg, request)
}

/// Encapsulate a BHTTP request using either Hybrid `X25519 + ML-KEM-768` (`0xFF41`)
/// or legacy classical `X25519` (`0x0020`), determined by `cfg.public_key`.
pub fn encapsulate(cfg: &KeyConfig, request: &[u8]) -> EnclaveResult<Vec<u8>> {
    if cfg.public_key.len() == HYBRID_KEM_PUBLIC_KEY_SIZE {
        let hybrid_pk = HybridKemPublicKey::from_bytes(&cfg.public_key)
            .map_err(|_| err!(EINVAL, "OHTTP_KEY"))?;
        let hdr = header_with_kem(cfg.key_id, KEM_ID_HYBRID_depot);
        let (kem_ct, shared_secret) =
            HybridKemKeyPair::encapsulate(&hybrid_pk).map_err(|_| err!(EIO, "OHTTP_SETUP"))?;
        let enc = kem_ct.to_bytes();
        let key_and_nonce = derive_ohttp_hybrid_key_and_nonce(&shared_secret.0, &hdr, &enc)?;
        let cipher = AeadChaCha20Poly1305::new(Key::from_slice(&key_and_nonce[0..32]));
        let nonce = Nonce::from_slice(&key_and_nonce[32..44]);
        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: request,
                    aad: b"",
                },
            )
            .map_err(|_| err!(EIO, "OHTTP_SEAL"))?;
        let mut out = Vec::with_capacity(hdr.len() + enc.len() + ct.len());
        out.extend_from_slice(&hdr);
        out.extend_from_slice(&enc);
        out.extend_from_slice(&ct);
        return Ok(out);
    }

    let pk = <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(&cfg.public_key)
        .map_err(|_| err!(EINVAL, "OHTTP_KEY"))?;
    let hdr = header_with_kem(cfg.key_id, KEM_ID);
    let mut info = b"message/bhttp request\0".to_vec();
    info.extend_from_slice(&hdr);
    let (enc, mut ctx) = hpke::setup_sender::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256, _>(
        &OpModeS::Base,
        &pk,
        &info,
        &mut Rng,
    )
    .map_err(|_| err!(EIO, "OHTTP_SETUP"))?;
    let ct = ctx
        .seal(request, b"")
        .map_err(|_| err!(EIO, "OHTTP_SEAL"))?;
    let mut out = hdr;
    out.extend_from_slice(&enc.to_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Gateway side: decapsulate an OHTTP request while enforcing anti-downgrade policy.
///
/// When `sk` is a Hybrid `X25519 + ML-KEM-768` gateway key (`2,432` bytes), any request
/// offering classical `KEM_ID = 0x0020` is rejected with `PQC_DOWNGRADE_ATTEMPT_REJECTED`.
pub fn decapsulate(key_id: u8, sk: &[u8], enc_request: &[u8]) -> EnclaveResult<Vec<u8>> {
    if enc_request.len() < 7 {
        fail!(EACCES, "OHTTP_HEADER");
    }
    if enc_request[0] != key_id
        || enc_request[3..5] != KDF_ID.to_be_bytes()
        || enc_request[5..7] != AEAD_ID.to_be_bytes()
    {
        fail!(EACCES, "OHTTP_HEADER");
    }
    let kem_id = u16::from_be_bytes([enc_request[1], enc_request[2]]);
    let offered_suite = match kem_id {
        KEM_ID_HYBRID_depot => WireCryptoSuite::HybridPqc,
        KEM_ID => WireCryptoSuite::ClassicalOnly,
        KEM_ID_XWING_IANA => fail!(
            EACCES,
            "OHTTP_KEM_XWING_UNSUPPORTED",
            "X-Wing (0x647A) is not implemented; depot hybrid KEM is 0xFF41"
        ),
        _ => fail!(EACCES, "OHTTP_HEADER"),
    };
    let required_suite = if sk.len() == HYBRID_KEM_SECRET_KEY_SIZE {
        WireCryptoSuite::HybridPqc
    } else if sk.len() == 32 {
        WireCryptoSuite::ClassicalOnly
    } else {
        fail!(EINVAL, "OHTTP_KEY");
    };

    // Fail-closed anti-downgrade check (`PQC_DOWNGRADE_ATTEMPT_REJECTED` if offered < required).
    enforce_handshake_suite(required_suite, offered_suite)?;

    match offered_suite {
        WireCryptoSuite::HybridPqc => {
            if sk.len() != HYBRID_KEM_SECRET_KEY_SIZE {
                fail!(EINVAL, "OHTTP_KEY");
            }
            if enc_request.len() < 7 + HYBRID_KEM_CIPHERTEXT_SIZE {
                fail!(EACCES, "OHTTP_HEADER");
            }
            let kp =
                HybridKemKeyPair::from_secret_bytes(sk).map_err(|_| err!(EINVAL, "OHTTP_KEY"))?;
            let enc_slice = &enc_request[7..7 + HYBRID_KEM_CIPHERTEXT_SIZE];
            let kem_ct = HybridKemCiphertext::from_bytes(enc_slice)
                .map_err(|_| err!(EINVAL, "OHTTP_ENC"))?;
            let mut shared_secret = kp
                .decapsulate(&kem_ct)
                .map_err(|_| err!(EACCES, "OHTTP_SETUP"))?;
            let key_and_nonce =
                derive_ohttp_hybrid_key_and_nonce(&shared_secret.0, &enc_request[..7], enc_slice)?;
            shared_secret.0.zeroize();
            let cipher = AeadChaCha20Poly1305::new(Key::from_slice(&key_and_nonce[0..32]));
            let nonce = Nonce::from_slice(&key_and_nonce[32..44]);
            cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: &enc_request[7 + HYBRID_KEM_CIPHERTEXT_SIZE..],
                        aad: b"",
                    },
                )
                .map_err(|_| err!(EACCES, "OHTTP_OPEN"))
        }
        WireCryptoSuite::ClassicalOnly => {
            if enc_request.len() < 7 + 32 {
                fail!(EACCES, "OHTTP_HEADER");
            }
            let sk = <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(sk)
                .map_err(|_| err!(EINVAL, "OHTTP_KEY"))?;
            let enc = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&enc_request[7..39])
                .map_err(|_| err!(EINVAL, "OHTTP_ENC"))?;
            let mut info = b"message/bhttp request\0".to_vec();
            info.extend_from_slice(&enc_request[..7]);
            let mut ctx = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
                &OpModeR::Base,
                &sk,
                &enc,
                &info,
            )
            .map_err(|_| err!(EACCES, "OHTTP_SETUP"))?;
            ctx.open(&enc_request[39..], b"")
                .map_err(|_| err!(EACCES, "OHTTP_OPEN"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper() {
        let (cfg, sk) = gateway_keypair(7);
        assert_eq!(cfg.suite(), WireCryptoSuite::HybridPqc);
        assert_eq!(cfg.public_key.len(), HYBRID_KEM_PUBLIC_KEY_SIZE);
        let req = bhttp_post(
            "ledger.corporate.internal",
            "/v1/rollup",
            "application/cbor",
            &[0xab; 1000],
        );
        let enc = encapsulate(&cfg, &req).unwrap();
        assert_eq!(u16::from_be_bytes([enc[1], enc[2]]), KEM_ID_HYBRID_depot);
        let (path, body) = bhttp_parse(&decapsulate(7, &sk, &enc).unwrap()).unwrap();
        assert_eq!(path, "/v1/rollup");
        assert_eq!(body, vec![0xab; 1000]);
        let mut bad = enc.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(decapsulate(7, &sk, &bad).is_err());
        assert!(decapsulate(8, &sk, &enc).is_err());

        // Tamper with ML-KEM-768 lattice ciphertext inside the OHTTP encapsulation header:
        let mut bad_mlkem = enc.clone();
        bad_mlkem[7 + 256] ^= 0x01;
        assert!(decapsulate(7, &sk, &bad_mlkem).is_err());
    }

    #[test]
    fn classical_downgrade_against_hybrid_gateway_rejected() {
        let (_hybrid_cfg, hybrid_sk) = gateway_keypair(4);
        let (classical_cfg, classical_sk) = gateway_classical_keypair(4);
        let req = bhttp_post(
            "ledger.corporate.internal",
            "/v1/rollup",
            "application/cbor",
            b"downgrade-probe",
        );
        let classical_enc = encapsulate(&classical_cfg, &req).unwrap();
        // Classical gateway accepts classical encapsulation during emergency RB-219 override:
        assert!(decapsulate(4, &classical_sk, &classical_enc).is_ok());
        // Production HybridPqc gateway rejects classical encapsulation with PQC_DOWNGRADE_ATTEMPT_REJECTED:
        let err = decapsulate(4, &hybrid_sk, &classical_enc).unwrap_err();
        assert!(err.is("PQC_DOWNGRADE_ATTEMPT_REJECTED"));
    }

    #[test]
    fn test_sender_suite_selection_l3_forbids_classical_kem() {
        let (classical_cfg, _) = gateway_classical_keypair(1);
        let (hybrid_cfg, _) = gateway_keypair(2);
        let req = b"payload";

        // L1 allows classical
        assert!(encapsulate_for_profile(&classical_cfg, req, Profile::L1).is_ok());
        // L3 forbids classical
        let err = encapsulate_for_profile(&classical_cfg, req, Profile::L3).unwrap_err();
        assert!(err.is("POST_QUANTUM_REQUIRED_IN_L3"));
        // L3 allows hybrid
        assert!(encapsulate_for_profile(&hybrid_cfg, req, Profile::L3).is_ok());
    }

    #[test]
    fn test_bidirectional_ohttp_response_encryption_roundtrip() {
        let (cfg, _) = gateway_keypair(5);
        let req = b"ping";
        let (_enc_req, ctx) = encapsulate_with_context(&cfg, req).unwrap();

        let resp_payload = b"authenticated-gateway-response-bytes-12345";
        let enc_resp =
            encapsulate_response(&ctx.shared_secret, &ctx.hdr, &ctx.enc, resp_payload).unwrap();

        let dec_resp = ctx.decapsulate_response(&enc_resp).unwrap();
        assert_eq!(dec_resp, resp_payload);

        let mut tampered = enc_resp.clone();
        *tampered.last_mut().unwrap() ^= 0x55;
        assert!(ctx.decapsulate_response(&tampered).is_err());
    }
}
