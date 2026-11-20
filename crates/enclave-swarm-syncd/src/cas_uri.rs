//! FS-702 §3.2 `cas://` URI grammar:
//!
//! ```abnf
//! cas-uri      = "cas://" cas-alg "/" hex64 "?" cas-params
//! cas-alg      = "blake3-bao-v1"
//! hex64        = 64HEXDIG          ; logical_plaintext_blake3_root
//! cas-params   = "target=" target-slug "&ns=" namespace [ "&min_profile=" profile-tier ] [ "&rekor=" uint64 ]
//! profile-tier = "L1" / "L2" / "L3"
//! ```
//!
//! `min_profile` is only an **upward floor hint** (anti-downgrade).

use enclave_core::error::EnclaveResult;
use enclave_core::fail;
use enclave_core::profile::Profile;

/// A parsed URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CasUri {
    /// `logical_plaintext_blake3_root` (lowercase hex).
    pub root: String,
    /// TUF target slug.
    pub target: String,
    /// Namespace.
    pub ns: String,
    /// Floor hint.
    pub min_profile: Option<Profile>,
    /// Rekor index.
    pub rekor: Option<u64>,
}

fn slug_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

impl CasUri {
    /// Strict parse (fails closed on any deviation from the grammar).
    pub fn parse(s: &str) -> EnclaveResult<Self> {
        let Some(rest) = s.strip_prefix("cas://blake3-bao-v1/") else {
            fail!(EINVAL, "CAS_URI_SCHEME", "{s}")
        };
        let (hex, q) = rest.split_once('?').unwrap_or((rest, ""));
        if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            fail!(EINVAL, "CAS_URI_HEX64");
        }
        let mut parts = q.split('&');
        let target = parts
            .next()
            .and_then(|p| p.strip_prefix("target="))
            .filter(|t| slug_ok(t));
        let ns = parts
            .next()
            .and_then(|p| p.strip_prefix("ns="))
            .filter(|t| slug_ok(t));
        let (Some(target), Some(ns)) = (target, ns) else {
            fail!(
                EINVAL,
                "CAS_URI_PARAMS",
                "target= and ns= are mandatory, in order"
            )
        };
        let mut min_profile = None;
        let mut rekor = None;
        for p in parts {
            if let Some(v) = p.strip_prefix("min_profile=") {
                if min_profile.is_some() || rekor.is_some() {
                    fail!(EINVAL, "CAS_URI_PARAM_ORDER");
                }
                min_profile = Some(Profile::parse(v)?);
            } else if let Some(v) = p.strip_prefix("rekor=") {
                if rekor.is_some() || !v.bytes().all(|b| b.is_ascii_digit()) || v.is_empty() {
                    fail!(EINVAL, "CAS_URI_REKOR");
                }
                rekor = Some(
                    v.parse()
                        .map_err(|_| enclave_core::err!(EINVAL, "CAS_URI_REKOR"))?,
                );
            } else {
                fail!(EINVAL, "CAS_URI_UNKNOWN_PARAM", "{p}");
            }
        }
        Ok(Self {
            root: hex.to_owned(),
            target: target.to_owned(),
            ns: ns.to_owned(),
            min_profile,
            rekor,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grammar() {
        let h = "a".repeat(64);
        let u = CasUri::parse(&format!(
            "cas://blake3-bao-v1/{h}?target=llada-8b&ns=models&min_profile=L2&rekor=149281723"
        ))
        .unwrap();
        assert_eq!(u.min_profile, Some(Profile::L2));
        assert_eq!(u.rekor, Some(149_281_723));
        for bad in [
            format!("cas://sha256/{h}?target=a&ns=b"),
            format!("cas://blake3-bao-v1/{}?target=a&ns=b", "A".repeat(64)),
            format!("cas://blake3-bao-v1/{h}?ns=b&target=a"),
            format!("cas://blake3-bao-v1/{h}?target=a&ns=b&evil=1"),
            format!("cas://blake3-bao-v1/{h}?target=a&ns=b&min_profile=L4"),
            format!("cas://blake3-bao-v1/{h}?target=../x&ns=b"),
        ] {
            assert!(CasUri::parse(&bad).is_err(), "{bad}");
        }
    }
}
