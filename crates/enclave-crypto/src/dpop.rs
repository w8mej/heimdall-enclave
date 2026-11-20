//! RFC 9449 DPoP proof creation and validation (`ES256`, P-256 — the SEP
//! workload key algorithm, ADR-003).
//!
//! Validation (fail closed, mirrors `identity/dpop.py` / check `V10`):
//! * compact JWS with exactly three parts; `typ == "dpop+jwt"`; `alg == "ES256"`
//!   (no `none`, no HMAC, no algorithm confusion); embedded public `jwk` only;
//! * signature verifies under the embedded key;
//! * `htm` equals the request method; `htu` equals the request URI after
//!   normalization (scheme/host lower-cased, query and fragment dropped);
//! * `iat` within `±max_skew_s`, compared with overflow-free arithmetic
//!   (`iat_within_skew`, DEFECT-F-74): an extreme `iat` is rejected, never a
//!   process abort under the release profile's `overflow-checks`;
//! * `jti` 16..=128 chars and `(jkt, jti)` unseen within the replay window — a
//!   saturated cache rejects new proofs instead of evicting live entries. The
//!   cache is partitioned by key binding (DEFECT-F-75): proofs checked against
//!   an `expected_jkt` and self-signed unbound proofs fill separate pools, so
//!   unauthenticated senders cannot saturate the pool bound proofs use;
//! * optional `cnf.jkt` binding (RFC 7638 thumbprint) and `ath` (access-token hash).

use std::collections::HashMap;

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint};
use p256::{AffinePoint, NistP256};
use rand_core::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::b64;

/// A DPoP signing key (in production this is the non-exportable SEP P-256
/// workload key; this software key is the CI/headless provider).
#[derive(Debug, Clone)]
pub struct DpopKey {
    sk: SigningKey,
}

impl Default for DpopKey {
    fn default() -> Self {
        Self::generate()
    }
}

impl DpopKey {
    /// Fresh software key.
    pub fn generate() -> Self {
        Self {
            sk: SigningKey::random(&mut OsRng),
        }
    }
    /// Public JWK `{crv, kty, x, y}`.
    pub fn public_jwk(&self) -> Value {
        jwk_of(self.sk.verifying_key())
    }
    /// RFC 7638 thumbprint.
    pub fn thumbprint(&self) -> String {
        jwk_thumbprint(&self.public_jwk()).unwrap_or_default()
    }
    /// Create a proof. `ath` binds an access token when supplied.
    pub fn create_proof(
        &self,
        htm: &str,
        htu: &str,
        iat: i64,
        jti: &str,
        access_token: Option<&str>,
    ) -> EnclaveResult<String> {
        let header = json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": self.public_jwk()});
        let mut claims =
            json!({"jti": jti, "htm": htm.to_ascii_uppercase(), "htu": htu, "iat": iat});
        if let Some(t) = access_token {
            claims["ath"] = Value::String(b64::enc(&Sha256::digest(t.as_bytes())));
        }
        let h =
            b64::enc(&serde_json::to_vec(&header).map_err(|e| err!(EINVAL, "DPOP_ENCODE", "{e}"))?);
        let c =
            b64::enc(&serde_json::to_vec(&claims).map_err(|e| err!(EINVAL, "DPOP_ENCODE", "{e}"))?);
        let signing_input = format!("{h}.{c}");
        let sig: Signature = self.sk.sign(signing_input.as_bytes());
        Ok(format!("{signing_input}.{}", b64::enc(&sig.to_bytes())))
    }
}

fn jwk_of(vk: &VerifyingKey) -> Value {
    let p = vk.to_encoded_point(false);
    json!({
        "crv": "P-256",
        "kty": "EC",
        "x": b64::enc(p.x().map(|x| x.as_slice()).unwrap_or_default()),
        "y": b64::enc(p.y().map(|y| y.as_slice()).unwrap_or_default()),
    })
}

/// RFC 7638 JWK thumbprint (members `crv, kty, x, y` in lexicographic order).
pub fn jwk_thumbprint(jwk: &Value) -> EnclaveResult<String> {
    let get = |k: &str| {
        jwk.get(k)
            .and_then(Value::as_str)
            .ok_or_else(|| err!(EINVAL, "DPOP_BAD_JWK", "missing {k}"))
    };
    let canon = format!(
        r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
        get("crv")?,
        get("kty")?,
        get("x")?,
        get("y")?
    );
    Ok(b64::enc(&Sha256::digest(canon.as_bytes())))
}

fn vk_from_jwk(jwk: &Value) -> EnclaveResult<VerifyingKey> {
    let obj = jwk
        .as_object()
        .ok_or_else(|| err!(EINVAL, "DPOP_BAD_JWK"))?;
    if obj.contains_key("d") {
        fail!(EACCES, "DPOP_PRIVATE_JWK", "private key material in header");
    }
    if obj.get("kty").and_then(Value::as_str) != Some("EC")
        || obj.get("crv").and_then(Value::as_str) != Some("P-256")
    {
        fail!(EACCES, "DPOP_BAD_JWK", "only EC P-256");
    }
    let x = obj
        .get("x")
        .and_then(Value::as_str)
        .and_then(b64::dec)
        .ok_or_else(|| err!(EINVAL, "DPOP_BAD_JWK"))?;
    let y = obj
        .get("y")
        .and_then(Value::as_str)
        .and_then(b64::dec)
        .ok_or_else(|| err!(EINVAL, "DPOP_BAD_JWK"))?;
    if x.len() != 32 || y.len() != 32 {
        fail!(EINVAL, "DPOP_BAD_JWK");
    }
    let ep = EncodedPoint::<NistP256>::from_affine_coordinates(
        x.as_slice().into(),
        y.as_slice().into(),
        false,
    );
    let ap: Option<AffinePoint> = AffinePoint::from_encoded_point(&ep).into();
    let ap = ap.ok_or_else(|| err!(EACCES, "DPOP_BAD_JWK", "point not on curve"))?;
    VerifyingKey::from_affine(ap).map_err(|_| err!(EACCES, "DPOP_BAD_JWK"))
}

/// Normalize an `htu`: lower-case scheme and authority, default path `/`,
/// drop query and fragment.
pub fn normalize_htu(uri: &str) -> String {
    let no_frag = uri.split('#').next().unwrap_or("");
    let no_query = no_frag.split('?').next().unwrap_or("");
    match no_query.split_once("://") {
        Some((scheme, rest)) => {
            let (auth, path) = match rest.find('/') {
                Some(i) => (&rest[..i], &rest[i..]),
                None => (rest, "/"),
            };
            format!(
                "{}://{}{}",
                scheme.to_ascii_lowercase(),
                auth.to_ascii_lowercase(),
                path
            )
        }
        None => no_query.to_owned(),
    }
}

/// `|now - iat| <= max_skew_s`, computed without any arithmetic that can
/// overflow (DEFECT-F-74). `iat` is attacker-chosen: a DPoP proof is signed by
/// the key in its own header, so any `i64` arrives validly signed. The release
/// profile sets `overflow-checks = true` and `panic = "abort"`, so a plain
/// `(now - iat).abs()` would abort the process on `iat = i64::MIN`.
/// `i64::abs_diff` is total over all `(now, iat)` pairs. A negative
/// `max_skew_s` is treated as zero (fail closed).
pub fn iat_within_skew(now: i64, iat: i64, max_skew_s: i64) -> bool {
    let allowed = u64::try_from(max_skew_s).unwrap_or(0);
    now.abs_diff(iat) <= allowed
}

/// Outcome of a successful verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpopVerified {
    /// Thumbprint of the proof key.
    pub jkt: String,
    /// `jti`.
    pub jti: String,
    /// `iat`.
    pub iat: i64,
}

/// One partition of the replay cache: `(jkt, jti)` -> expiry (Unix seconds).
#[derive(Debug, Default)]
struct ReplayPool {
    seen: HashMap<(String, String), i64>,
}

impl ReplayPool {
    /// Drop expired entries. `>=`: an expiry saturated at `i64::MAX` must
    /// still block a replay at `now == i64::MAX` (DEFECT-F-74).
    fn prune(&mut self, now: i64) {
        self.seen.retain(|_, exp| *exp >= now);
    }

    fn contains(&self, entry: &(String, String)) -> bool {
        self.seen.contains_key(entry)
    }

    fn admit(&mut self, entry: (String, String), expires: i64, cap: usize) -> EnclaveResult<()> {
        if self.seen.len() >= cap {
            fail!(EAGAIN, "DPOP_REPLAY_CACHE_SATURATED");
        }
        self.seen.insert(entry, expires);
        Ok(())
    }
}

/// Whether the proof key was checked against a caller-supplied `cnf.jkt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Binding {
    /// `expected_jkt` was supplied and matched: the sender holds the key the
    /// access token was issued to.
    Bound,
    /// No `expected_jkt`: the proof is self-signed by a key anyone can mint.
    Unbound,
}

/// Stateful verifier holding the `jti` replay cache.
///
/// The cache is partitioned by key binding (DEFECT-F-75). Proofs verified
/// against a caller-supplied `expected_jkt` are admitted to the *bound* pool
/// (`max_cache` entries); proofs without one go to a separate *unbound* pool
/// (`max_unbound_cache` entries). Anyone can mint unbound proofs, so a flood
/// of them can saturate only the unbound pool and never denies key-bound
/// proofs. `max_unbound_cache = 0` refuses unbound proofs outright
/// (`DPOP_KEY_BINDING_REQUIRED`). Entries are keyed by `(jkt, jti)`, so one
/// key cannot pre-register (poison) another key's `jti`.
#[derive(Debug)]
pub struct DpopVerifier {
    /// Allowed clock skew (seconds).
    pub max_skew_s: i64,
    /// Replay window (seconds).
    pub replay_window_s: i64,
    /// Maximum live entries for key-bound proofs.
    pub max_cache: usize,
    /// Maximum live entries for proofs verified without `expected_jkt`;
    /// `0` requires key binding for every proof.
    pub max_unbound_cache: usize,
    bound: ReplayPool,
    unbound: ReplayPool,
}

impl Default for DpopVerifier {
    fn default() -> Self {
        Self::new(60, 300, 100_000)
    }
}

/// Validate an egress RPC's DPoP proof header (FS-703 §4.1).
///
/// One-shot: this builds a fresh [`DpopVerifier`] per call, so it checks the
/// proof's signature, binding and time window but provides **no `jti` replay
/// protection across calls**. A service that must reject replays keeps one
/// long-lived `DpopVerifier` and calls [`DpopVerifier::verify`].
pub fn verify_egress_dpop(
    proof: &str,
    htm: &str,
    htu: &str,
    access_token: Option<&str>,
    expected_jkt: Option<&str>,
    now_unix: i64,
) -> EnclaveResult<DpopVerified> {
    let mut verifier = DpopVerifier::default();
    let req = DpopRequest {
        htm,
        htu,
        expected_jkt,
        access_token,
    };
    verifier.verify(proof, &req, now_unix)
}

/// Request context to bind the proof to.
#[derive(Debug, Clone, Default)]
pub struct DpopRequest<'a> {
    /// HTTP method.
    pub htm: &'a str,
    /// Request URI.
    pub htu: &'a str,
    /// Access token presented with the proof (enables `ath` check).
    pub access_token: Option<&'a str>,
    /// Expected `cnf.jkt` of the access token.
    pub expected_jkt: Option<&'a str>,
}

impl DpopVerifier {
    /// New verifier. The bound and unbound pools each hold up to
    /// `max_cache` entries; see [`Self::with_unbound_capacity`].
    pub fn new(max_skew_s: i64, replay_window_s: i64, max_cache: usize) -> Self {
        Self {
            max_skew_s,
            replay_window_s,
            max_cache,
            max_unbound_cache: max_cache,
            bound: ReplayPool::default(),
            unbound: ReplayPool::default(),
        }
    }

    /// Set the unbound pool's capacity; `0` requires `expected_jkt` on every
    /// request (DEFECT-F-75).
    pub fn with_unbound_capacity(self, max_unbound_cache: usize) -> Self {
        Self {
            max_unbound_cache,
            ..self
        }
    }

    fn remember(&mut self, jkt: &str, jti: &str, binding: Binding, now: i64) -> EnclaveResult<()> {
        if binding == Binding::Unbound && self.max_unbound_cache == 0 {
            fail!(EACCES, "DPOP_KEY_BINDING_REQUIRED", "no expected cnf.jkt");
        }
        self.bound.prune(now);
        self.unbound.prune(now);
        let entry = (jkt.to_owned(), jti.to_owned());
        if self.bound.contains(&entry) || self.unbound.contains(&entry) {
            fail!(EALREADY, "DPOP_REPLAY", "jti replay detected");
        }
        let expires = now.saturating_add(self.replay_window_s.max(0));
        match binding {
            Binding::Bound => self.bound.admit(entry, expires, self.max_cache),
            Binding::Unbound => self.unbound.admit(entry, expires, self.max_unbound_cache),
        }
    }

    /// Verify a proof at time `now` (Unix seconds).
    pub fn verify(
        &mut self,
        proof: &str,
        req: &DpopRequest<'_>,
        now: i64,
    ) -> EnclaveResult<DpopVerified> {
        let parts: Vec<&str> = proof.split('.').collect();
        if parts.len() != 3 {
            fail!(EINVAL, "DPOP_MALFORMED", "expected 3 JWS parts");
        }
        let header: Value = b64::dec(parts[0])
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or_else(|| err!(EINVAL, "DPOP_MALFORMED", "header"))?;
        let claims: Value = b64::dec(parts[1])
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or_else(|| err!(EINVAL, "DPOP_MALFORMED", "claims"))?;
        if header.get("typ").and_then(Value::as_str) != Some("dpop+jwt") {
            fail!(EACCES, "DPOP_BAD_TYP");
        }
        if header.get("alg").and_then(Value::as_str) != Some("ES256") {
            fail!(EACCES, "DPOP_BAD_ALG", "alg must be ES256");
        }
        let jwk = header
            .get("jwk")
            .ok_or_else(|| err!(EACCES, "DPOP_NO_JWK"))?;
        let vk = vk_from_jwk(jwk)?;
        let sig_bytes = b64::dec(parts[2]).ok_or_else(|| err!(EINVAL, "DPOP_MALFORMED", "sig"))?;
        let sig =
            Signature::from_slice(&sig_bytes).map_err(|_| err!(EACCES, "DPOP_BAD_SIGNATURE"))?;
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        vk.verify(signing_input.as_bytes(), &sig)
            .map_err(|_| err!(EACCES, "DPOP_BAD_SIGNATURE"))?;
        let htm = claims.get("htm").and_then(Value::as_str).unwrap_or("");
        if htm != req.htm.to_ascii_uppercase() {
            fail!(EACCES, "DPOP_HTM_MISMATCH");
        }
        let htu = claims.get("htu").and_then(Value::as_str).unwrap_or("");
        if normalize_htu(htu) != normalize_htu(req.htu) {
            fail!(EACCES, "DPOP_HTU_MISMATCH");
        }
        let iat = claims
            .get("iat")
            .and_then(Value::as_i64)
            .ok_or_else(|| err!(EINVAL, "DPOP_NO_IAT"))?;
        if !iat_within_skew(now, iat, self.max_skew_s) {
            fail!(ESTALE, "DPOP_IAT_OUT_OF_WINDOW");
        }
        let jkt = jwk_thumbprint(jwk)?;
        if let Some(want) = req.expected_jkt {
            if want != jkt {
                fail!(
                    EACCES,
                    "DPOP_JKT_MISMATCH",
                    "proof key not bound to access token"
                );
            }
        }
        if let Some(tok) = req.access_token {
            let ath = claims.get("ath").and_then(Value::as_str).unwrap_or("");
            if ath != b64::enc(&Sha256::digest(tok.as_bytes())) {
                fail!(EACCES, "DPOP_ATH_MISMATCH");
            }
        }
        let jti = claims.get("jti").and_then(Value::as_str).unwrap_or("");
        if !(16..=128).contains(&jti.len()) {
            fail!(EINVAL, "DPOP_BAD_JTI");
        }
        let binding = match req.expected_jkt {
            Some(_) => Binding::Bound,
            None => Binding::Unbound,
        };
        self.remember(&jkt, jti, binding, now)?;
        Ok(DpopVerified {
            jkt,
            jti: jti.to_owned(),
            iat,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const URI: &str = "https://Enclave.Local.Internal/depot/tools/call?x=1#f";

    fn setup() -> (DpopKey, DpopVerifier) {
        (DpopKey::generate(), DpopVerifier::default())
    }

    #[test]
    fn valid_proof_accepted() {
        let (k, mut v) = setup();
        let p = k
            .create_proof("post", URI, 1000, "jti-0000000000000001", Some("tok"))
            .unwrap();
        let r = DpopRequest {
            htm: "POST",
            htu: "https://enclave.local.internal/depot/tools/call",
            access_token: Some("tok"),
            expected_jkt: Some(&k.thumbprint()),
        };
        let ok = v.verify(&p, &r, 1010).unwrap();
        assert_eq!(ok.jkt, k.thumbprint());
    }

    #[test]
    fn attacks_rejected() {
        let (k, mut v) = setup();
        let req = DpopRequest {
            htm: "POST",
            htu: URI,
            ..Default::default()
        };
        let p = k
            .create_proof("POST", URI, 1000, "jti-replay-000000001", None)
            .unwrap();
        v.verify(&p, &req, 1000).unwrap();
        assert!(v.verify(&p, &req, 1001).unwrap_err().is("DPOP_REPLAY"));
        let p = k
            .create_proof("GET", URI, 1000, "jti-htm-00000000001", None)
            .unwrap();
        assert!(v
            .verify(&p, &req, 1000)
            .unwrap_err()
            .is("DPOP_HTM_MISMATCH"));
        let p = k
            .create_proof(
                "POST",
                "https://evil.example/depot",
                1000,
                "jti-htu-00000000001",
                None,
            )
            .unwrap();
        assert!(v
            .verify(&p, &req, 1000)
            .unwrap_err()
            .is("DPOP_HTU_MISMATCH"));
        let p = k
            .create_proof("POST", URI, 1000, "jti-iat-00000000001", None)
            .unwrap();
        assert!(v
            .verify(&p, &req, 1100)
            .unwrap_err()
            .is("DPOP_IAT_OUT_OF_WINDOW"));
        // Signature tamper: flip a claims byte.
        let p = k
            .create_proof("POST", URI, 1000, "jti-sig-00000000001", None)
            .unwrap();
        let mut parts: Vec<String> = p.split('.').map(str::to_owned).collect();
        let mut c: Value = serde_json::from_slice(&b64::dec(&parts[1]).unwrap()).unwrap();
        c["htm"] = "POST".into();
        c["iat"] = 1001.into();
        parts[1] = b64::enc(&serde_json::to_vec(&c).unwrap());
        assert!(v
            .verify(&parts.join("."), &req, 1000)
            .unwrap_err()
            .is("DPOP_BAD_SIGNATURE"));
        // jkt binding: a different key's proof is rejected for this token.
        let other = DpopKey::generate();
        let p = other
            .create_proof("POST", URI, 1000, "jti-jkt-00000000001", None)
            .unwrap();
        let bound = DpopRequest {
            expected_jkt: Some(&k.thumbprint()),
            ..req.clone()
        };
        assert!(v
            .verify(&p, &bound, 1000)
            .unwrap_err()
            .is("DPOP_JKT_MISMATCH"));
    }

    #[test]
    fn alg_none_and_private_jwk_rejected() {
        let (k, mut v) = setup();
        let req = DpopRequest {
            htm: "POST",
            htu: URI,
            ..Default::default()
        };
        let p = k
            .create_proof("POST", URI, 1000, "jti-alg-00000000001", None)
            .unwrap();
        let parts: Vec<&str> = p.split('.').collect();
        let mut h: Value = serde_json::from_slice(&b64::dec(parts[0]).unwrap()).unwrap();
        h["alg"] = "none".into();
        let forged = format!(
            "{}.{}.",
            b64::enc(&serde_json::to_vec(&h).unwrap()),
            parts[1]
        );
        assert!(v.verify(&forged, &req, 1000).is_err());
        h["alg"] = "ES256".into();
        h["jwk"]["d"] = "AAAA".into();
        let forged = format!(
            "{}.{}.{}",
            b64::enc(&serde_json::to_vec(&h).unwrap()),
            parts[1],
            parts[2]
        );
        assert!(v
            .verify(&forged, &req, 1000)
            .unwrap_err()
            .is("DPOP_PRIVATE_JWK"));
    }

    #[test]
    fn saturated_cache_fails_closed() {
        let k = DpopKey::generate();
        let mut v = DpopVerifier::new(60, 300, 2);
        let req = DpopRequest {
            htm: "POST",
            htu: URI,
            ..Default::default()
        };
        for i in 0..2 {
            v.verify(
                &k.create_proof("POST", URI, 1000, &format!("jti-sat-{i:012}"), None)
                    .unwrap(),
                &req,
                1000,
            )
            .unwrap();
        }
        let e = v
            .verify(
                &k.create_proof("POST", URI, 1000, "jti-sat-000000000099", None)
                    .unwrap(),
                &req,
                1000,
            )
            .unwrap_err();
        assert!(e.is("DPOP_REPLAY_CACHE_SATURATED"));
        // After expiry entries are dropped and new proofs pass.
        v.verify(
            &k.create_proof("POST", URI, 1400, "jti-sat-000000000100", None)
                .unwrap(),
            &req,
            1400,
        )
        .unwrap();
    }
}
