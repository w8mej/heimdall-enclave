//! OIDC IdP step-up authentication protocol boundary (FS-703 §3.1, §4.1).
//!
//! `A4` extreme/break-glass actions require the inherited out-of-band OIDC
//! IdP step-up in every profile (`max_age=0` / recent `auth_time`). Higher
//! profiles retain their additional Touch ID, YubiKey, UV and quorum factors.
//!
//! Tokens are verified against TUF-pinned IdP JWKS / public keys.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};

/// Verified OIDC step-up identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcSubject {
    /// Subject identifier.
    pub sub: String,
    /// Token issuer.
    pub iss: String,
    /// Audience identifier.
    pub aud: String,
    /// User authentication timestamp.
    pub auth_time: i64,
    /// Earliest exclusive bound from signed token expiry and permitted auth age.
    /// Callers must preserve this limit through final release and derived leases.
    pub valid_until_unix: i64,
    /// Captured authority-only shared boot expiry, when an authenticated
    /// receipt supplied clock provenance. Separate from the ceremony10s cap.
    #[serde(default)]
    pub valid_until_boot_ns: Option<u64>,
}

/// OIDC step-up verifier trait.
pub trait OidcVerifier: std::fmt::Debug + Send + Sync {
    /// Verify an OIDC step-up ID token, checking signature, issuer, audience,
    /// expiration, and freshness (`auth_time`).
    fn verify_step_up(&self, token: &str, now_unix: i64) -> EnclaveResult<OidcSubject>;
}

/// Maximum permitted age between `auth_time` and step-up ceremony (5 minutes).
pub const MAX_AUTH_AGE_S: i64 = 300;

/// Largest supported compact JWS. Bound before allocating decoded fields.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StepUpHeader {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    kid: Option<String>,
}

/// Claims verified in an OIDC step-up token.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StepUpClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    auth_time: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nbf: Option<i64>,
}

/// A verifier configured with TUF-pinned Ed25519 IdP keys.
#[derive(Debug, Clone)]
pub struct PinnedOidcVerifier {
    /// Expected issuer claim (`iss`).
    pub expected_issuer: String,
    /// Expected audience claim (`aud`).
    pub expected_audience: String,
    /// Pinned IdP public keys.
    pub verifying_keys: Vec<VerifyingKey>,
}

impl PinnedOidcVerifier {
    /// Create a new verifier with expected issuer, audience, and public keys.
    pub fn new(
        expected_issuer: impl Into<String>,
        expected_audience: impl Into<String>,
        verifying_keys: Vec<VerifyingKey>,
    ) -> Self {
        Self {
            expected_issuer: expected_issuer.into(),
            expected_audience: expected_audience.into(),
            verifying_keys,
        }
    }
}

impl OidcVerifier for PinnedOidcVerifier {
    fn verify_step_up(&self, token: &str, now_unix: i64) -> EnclaveResult<OidcSubject> {
        if token.len() > MAX_TOKEN_BYTES { fail!(E2BIG, "OIDC_TOKEN_TOO_LARGE"); }
        if self.expected_issuer.is_empty() || self.expected_audience.is_empty() || self.verifying_keys.is_empty() {
            fail!(EACCES, "OIDC_AUTHORITY_UNCONFIGURED");
        }
        let mut segments = token.split('.');
        let parts = [segments.next(), segments.next(), segments.next()];
        if segments.next().is_some() || parts.iter().any(|p| p.is_none_or(str::is_empty)) {
            fail!(EINVAL, "OIDC_TOKEN_MALFORMED", "expected 3 nonempty JWS parts");
        }
        let parts = parts.map(Option::unwrap);
        if parts[0].len() > 1024 { fail!(E2BIG, "OIDC_HEADER_TOO_LARGE"); }
        let header_bytes = enclave_crypto::b64::dec(parts[0]).ok_or_else(|| err!(EINVAL, "OIDC_BAD_HEADER_B64"))?;
        let header: StepUpHeader = serde_json::from_slice(&header_bytes)
            .map_err(|_| err!(EINVAL, "OIDC_HEADER_INVALID"))?;
        // Never treat a valid pinned-key signature as permission to ignore the
        // JOSE algorithm, detached/unencoded payload or critical extensions.
        // `kid` can select no new authority: every signature still uses only
        // the independently configured key set below.
        if header.alg != "EdDSA" || header.typ.as_deref().is_some_and(|typ| typ != "JWT")
            || header.kid.as_ref().is_some_and(|kid| kid.is_empty() || kid.len() > 256) {
            fail!(EACCES, "OIDC_HEADER_UNSUPPORTED");
        }

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes =
            enclave_crypto::b64::dec(parts[2]).ok_or_else(|| err!(EINVAL, "OIDC_BAD_SIG_B64"))?;
        let sig = Signature::from_slice(&sig_bytes)
            .map_err(|_| err!(EACCES, "OIDC_BAD_SIGNATURE_FORMAT"))?;

        let payload_bytes = enclave_crypto::b64::dec(parts[1])
            .ok_or_else(|| err!(EINVAL, "OIDC_BAD_PAYLOAD_B64"))?;
        let claims: StepUpClaims = serde_json::from_slice(&payload_bytes)
            .map_err(|_| err!(EINVAL, "OIDC_CLAIMS_INVALID"))?;

        if claims.iss != self.expected_issuer {
            fail!(EACCES, "OIDC_ISSUER_MISMATCH");
        }
        if claims.aud != self.expected_audience {
            fail!(EACCES, "OIDC_AUDIENCE_MISMATCH");
        }
        if claims.sub.is_empty() || claims.sub.len() > 1024 {
            fail!(EACCES, "OIDC_SUBJECT_INVALID");
        }
        if now_unix < 0 || claims.iat < 0 || claims.auth_time < 0
            || claims.iat > now_unix || claims.auth_time > now_unix
            || claims.nbf.is_some_and(|nbf| nbf < 0 || nbf > now_unix)
            || claims.auth_time > claims.iat || claims.iat >= claims.exp {
            fail!(EACCES, "OIDC_TIME_INVALID");
        }
        if now_unix >= claims.exp {
            fail!(ESTALE, "OIDC_TOKEN_EXPIRED");
        }
        if now_unix.saturating_sub(claims.auth_time) > MAX_AUTH_AGE_S {
            fail!(ESTALE, "OIDC_AUTH_TIME_STALE", "auth_time exceeds 300 s");
        }

        let mut verified = false;
        for vk in &self.verifying_keys {
            if vk.verify_strict(signing_input.as_bytes(), &sig).is_ok() {
                verified = true;
                break;
            }
        }
        if !verified {
            fail!(EACCES, "OIDC_SIGNATURE_INVALID");
        }

        Ok(OidcSubject {
            sub: claims.sub,
            iss: claims.iss,
            aud: claims.aud,
            auth_time: claims.auth_time,
            // The existing freshness rule admits age == MAX_AUTH_AGE_S, hence
            // the next integer second is its exclusive boundary.
            valid_until_unix: claims.exp.min(claims.auth_time.saturating_add(MAX_AUTH_AGE_S).saturating_add(1)),
            valid_until_boot_ns: None,
        })
    }
}

/// Test/Local IdP for headless CI and local verification.
#[derive(Debug)]
pub struct TestIdp {
    signing_key: SigningKey,
    issuer: String,
    audience: String,
}

impl Default for TestIdp {
    fn default() -> Self {
        Self::new("https://idp.local.internal", "mcpmac-enclave")
    }
}

impl TestIdp {
    /// Create a test IdP with the given issuer and audience.
    pub fn new(issuer: &str, audience: &str) -> Self {
        Self {
            signing_key: SigningKey::generate(&mut rand_core::OsRng),
            issuer: issuer.to_string(),
            audience: audience.to_string(),
        }
    }

    /// Public verifying key of the test IdP.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Build a verifier matching this test IdP.
    pub fn verifier(&self) -> PinnedOidcVerifier {
        PinnedOidcVerifier::new(&self.issuer, &self.audience, vec![self.verifying_key()])
    }

    /// Mint a signed step-up token.
    pub fn mint_token(&self, sub: &str, now_unix: i64, auth_age_s: i64) -> EnclaveResult<String> {
        let header = serde_json::json!({
            "typ": "JWT",
            "alg": "EdDSA"
        });
        let claims = StepUpClaims {
            iss: self.issuer.clone(),
            sub: sub.to_string(),
            aud: self.audience.clone(),
            exp: now_unix + 3600,
            iat: now_unix,
            auth_time: now_unix - auth_age_s,
            nbf: None,
        };

        let h_b64 = enclave_crypto::b64::enc(
            &serde_json::to_vec(&header).map_err(|e| err!(EINVAL, "JSON", "{e}"))?,
        );
        let c_b64 = enclave_crypto::b64::enc(
            &serde_json::to_vec(&claims).map_err(|e| err!(EINVAL, "JSON", "{e}"))?,
        );
        let signing_input = format!("{h_b64}.{c_b64}");

        use ed25519_dalek::Signer;
        let sig: Signature = self.signing_key.sign(signing_input.as_bytes());
        let s_b64 = enclave_crypto::b64::enc(&sig.to_bytes());

        Ok(format!("{signing_input}.{s_b64}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_idp_roundtrip() {
        let idp = TestIdp::default();
        let verifier = idp.verifier();
        let now = 1_700_000_000;

        let token = idp.mint_token("user@example.com", now, 30).unwrap();
        let sub = verifier.verify_step_up(&token, now).unwrap();
        assert_eq!(sub.sub, "user@example.com");

        // Stale auth_time (> 300s):
        let stale_token = idp.mint_token("user@example.com", now, 301).unwrap();
        assert!(verifier
            .verify_step_up(&stale_token, now)
            .unwrap_err()
            .is("OIDC_AUTH_TIME_STALE"));

        // Tampered token:
        let tampered = format!("{token}extra");
        assert!(verifier.verify_step_up(&tampered, now).is_err());
    }

    fn signed(idp: &TestIdp, header: &str, claims: &str) -> String {
        use ed25519_dalek::Signer;
        let message = format!("{}.{}", enclave_crypto::b64::enc(header.as_bytes()),
            enclave_crypto::b64::enc(claims.as_bytes()));
        let signature = idp.signing_key.sign(message.as_bytes());
        format!("{}.{}", message, enclave_crypto::b64::enc(&signature.to_bytes()))
    }

    fn claims(now: i64) -> serde_json::Value {
        serde_json::json!({"iss":"https://idp.local.internal","sub":"synthetic-user",
            "aud":"mcpmac-enclave","exp":now+100,"iat":now,"auth_time":now})
    }

    #[test]
    fn signed_algorithm_confusion_critical_headers_and_duplicate_headers_refuse() {
        let idp = TestIdp::default();
        let verifier = idp.verifier();
        let now = 1_800_000_000;
        let claims = claims(now).to_string();
        for header in [r#"{"alg":"none","typ":"JWT"}"#,
            r#"{"alg":"HS256","typ":"JWT"}"#, r#"{"alg":"EdDSA","typ":"other"}"#,
            r#"{"alg":"EdDSA","crit":["future"]}"#, r#"{"alg":"EdDSA","b64":false}"#,
            r#"{"alg":"EdDSA","alg":"EdDSA"}"#, r#"{"alg":"EdDSA","jku":"https://untrusted.invalid"}"#] {
            assert!(verifier.verify_step_up(&signed(&idp, header, &claims), now).is_err());
        }
        for header in [r#"{"alg":"EdDSA"}"#, r#"{"alg":"EdDSA","typ":"JWT","kid":"pinned-id"}"#] {
            assert!(verifier.verify_step_up(&signed(&idp, header, &claims), now).is_ok());
        }
    }

    #[test]
    fn future_inconsistent_and_boundary_times_cannot_extend_step_up() {
        let idp = TestIdp::default(); let verifier = idp.verifier(); let now = 1_800_000_000;
        let header = r#"{"alg":"EdDSA","typ":"JWT"}"#;
        for (field, value) in [("iat",now+1),("auth_time",now+1),("auth_time",-1),
            ("exp",now),("exp",now-1),("iat",-1)] {
            let mut claims = claims(now); claims[field] = value.into();
            assert!(verifier.verify_step_up(&signed(&idp,header,&claims.to_string()),now).is_err(),"{field}={value}");
        }
        let mut value = claims(now); value["iat"] = (now-1).into();
        assert!(verifier.verify_step_up(&signed(&idp,header,&value.to_string()),now).is_err());
        for (age, allowed) in [(300,true),(301,false)] {
            let mut value = claims(now); value["auth_time"] = (now-age).into();
            assert_eq!(verifier.verify_step_up(&signed(&idp,header,&value.to_string()),now).is_ok(),allowed);
        }
    }

    #[test]
    fn compact_token_bounds_empty_subject_and_unpinned_signer_refuse() {
        let idp = TestIdp::default(); let verifier = idp.verifier(); let now = 1_800_000_000;
        assert!(verifier.verify_step_up(&"x".repeat(MAX_TOKEN_BYTES+1),now).unwrap_err().is("OIDC_TOKEN_TOO_LARGE"));
        for value in ["a.b.c.d", "a..c", ".b.c", "a.b.", "", "..."] {
            assert!(verifier.verify_step_up(value,now).is_err());
        }
        let mut value = claims(now); value["sub"] = "".into();
        assert!(verifier.verify_step_up(&signed(&idp,r#"{"alg":"EdDSA"}"#,&value.to_string()),now).unwrap_err().is("OIDC_SUBJECT_INVALID"));
        let foreign = TestIdp::default();
        let token = signed(&foreign,r#"{"alg":"EdDSA"}"#,&claims(now).to_string());
        assert!(verifier.verify_step_up(&token,now).unwrap_err().is("OIDC_SIGNATURE_INVALID"));
        let authority = PinnedOidcVerifier::new("","",vec![]);
        assert!(authority.verify_step_up(&token,now).unwrap_err().is("OIDC_AUTHORITY_UNCONFIGURED"));
    }

    #[test]
    fn signed_not_before_and_private_parse_errors_are_enforced() {
        let idp = TestIdp::default(); let verifier = idp.verifier(); let now = 1_800_000_000;
        let header = r#"{"alg":"EdDSA","typ":"JWT"}"#;
        for (nbf, allowed) in [(now-1,true), (now,true), (now+1,false), (-1,false)] {
            let mut value = claims(now); value["nbf"] = nbf.into();
            assert_eq!(verifier.verify_step_up(&signed(&idp,header,&value.to_string()),now).is_ok(),allowed);
        }
        let marker = "synthetic-private-claim-marker";
        for field in ["iat", "auth_time", "exp", "nbf"] {
            let mut value = claims(now); value[field] = marker.into();
            let error = verifier.verify_step_up(&signed(&idp,header,&value.to_string()),now).unwrap_err();
            assert!(error.is("OIDC_CLAIMS_INVALID"));
            assert!(!format!("{error:?} {error}").contains(marker));
        }
    }

    #[test]
    fn verified_subject_carries_earliest_signed_expiry_or_auth_age_boundary() {
        let idp=TestIdp::default();let verifier=idp.verifier();let now=1_800_000_000;
        let mut value=claims(now);value["exp"]=(now+1).into();
        let token=signed(&idp,r#"{"alg":"EdDSA"}"#,&value.to_string());
        assert_eq!(verifier.verify_step_up(&token,now).unwrap().valid_until_unix,now+1);
        assert!(verifier.verify_step_up(&token,now+1).unwrap_err().is("OIDC_TOKEN_EXPIRED"));
        value["exp"]=(now+1000).into();value["auth_time"]=(now-300).into();
        let token=signed(&idp,r#"{"alg":"EdDSA"}"#,&value.to_string());
        assert_eq!(verifier.verify_step_up(&token,now).unwrap().valid_until_unix,now+1);
        assert!(verifier.verify_step_up(&token,now+1).unwrap_err().is("OIDC_AUTH_TIME_STALE"));
    }

}
