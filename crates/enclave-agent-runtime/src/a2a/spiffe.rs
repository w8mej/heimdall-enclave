//! SPIFFE SVID definitions and validation (D-35a). Test CAs live only in tests/.

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};

/// A validated SPIFFE ID (e.g. `spiffe://corporate.internal/enclave/uid/704/worker1`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct SpiffeId {
    raw: String,
    trust_domain: String,
    path: String,
}

impl SpiffeId {
    /// Parse a SPIFFE ID from string.
    pub fn parse(s: &str) -> EnclaveResult<Self> {
        let rest = s
            .strip_prefix("spiffe://")
            .ok_or_else(|| err!(EINVAL, "INVALID_SPIFFE_SCHEME", "expected spiffe:// prefix"))?;
        let slash_pos = rest
            .find('/')
            .ok_or_else(|| err!(EINVAL, "INVALID_SPIFFE_PATH", "missing path in spiffe id"))?;
        let trust_domain = &rest[..slash_pos];
        let path = &rest[slash_pos..];
        if trust_domain.is_empty() {
            fail!(
                EINVAL,
                "EMPTY_TRUST_DOMAIN",
                "spiffe trust domain cannot be empty"
            );
        }
        if s.len() > 2048
            || trust_domain.len() > 255
            || !trust_domain
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        {
            fail!(EINVAL, "INVALID_SPIFFE_TRUST_DOMAIN");
        }
        if !path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-._~!$&'()*+,;=:@".contains(&b))
            || path[1..]
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            fail!(EINVAL, "INVALID_SPIFFE_PATH");
        }
        if path.is_empty() || !path.starts_with('/') {
            fail!(
                EINVAL,
                "INVALID_SPIFFE_PATH",
                "spiffe path must start with /"
            );
        }
        Ok(Self {
            raw: s.to_owned(),
            trust_domain: trust_domain.to_owned(),
            path: path.to_owned(),
        })
    }

    /// Construct a SPIFFE ID from trust domain and path.
    pub fn new(trust_domain: &str, path: &str) -> EnclaveResult<Self> {
        let clean_path = if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        };
        let raw = format!("spiffe://{trust_domain}{clean_path}");
        Self::parse(&raw)
    }

    /// The trust domain portion (e.g. `corporate.internal`).
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    /// The path portion (e.g. `/enclave/uid/704/node1`).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The full canonical URI.
    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

impl<'de> Deserialize<'de> for SpiffeId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            raw: String,
            trust_domain: String,
            path: String,
        }
        let wire = Wire::deserialize(deserializer)?;
        let parsed = Self::parse(&wire.raw).map_err(serde::de::Error::custom)?;
        if parsed.trust_domain != wire.trust_domain || parsed.path != wire.path {
            return Err(serde::de::Error::custom(
                "inconsistent SPIFFE identity fields",
            ));
        }
        Ok(parsed)
    }
}

impl std::fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.raw)
    }
}

/// An X.509 SVID carrying a validated SPIFFE ID and keypair.
#[derive(Debug, Clone)]
pub struct SpiffeSvid {
    /// SPIFFE ID extracted from SAN URI.
    pub spiffe_id: SpiffeId,
    /// DER-encoded certificate chain (leaf first).
    pub cert_der_chain: Vec<Vec<u8>>,
    /// DER-encoded private key (PKCS#8).
    pub private_key_der: Vec<u8>,
}

/// Workload API source for obtaining ephemeral SPIFFE SVIDs.
pub trait SpiffeWorkloadSource: Send + Sync {
    /// Retrieve the current valid SVID.
    fn fetch_svid(&self) -> EnclaveResult<SpiffeSvid>;
    /// Retrieve the CA trust bundle (DER certificates).
    fn fetch_bundle(&self) -> EnclaveResult<Vec<Vec<u8>>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn f73_spiffe_syntax_rejects_ambiguous_authorities_and_paths() {
        for id in [
            "spiffe://EXAMPLE.org/work",
            "spiffe://user@example.org/work",
            "spiffe://example.org:443/work",
            "spiffe://example.org/a?query",
            "spiffe://example.org/a#fragment",
            "spiffe://example.org/a//b",
            "spiffe://example.org/a/../b",
            "spiffe://example.org/./b",
            "spiffe://example.org/a%2fb",
            "spiffe://example.org/a\nb",
            "spiffe:///a",
        ] {
            assert!(SpiffeId::parse(id).is_err(), "{id:?}");
        }
        let id = SpiffeId::parse("spiffe://example.org/enclave/uid/704/worker_1").unwrap();
        let wire = serde_json::to_value(&id).unwrap();
        assert_eq!(
            serde_json::from_value::<SpiffeId>(wire.clone()).unwrap(),
            id
        );
        let mut forged = wire;
        forged["trust_domain"] = "other.org".into();
        assert!(serde_json::from_value::<SpiffeId>(forged).is_err());
    }
}
