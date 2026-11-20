//! Live, authenticated UID 702 → UID 703 custody metadata receipt.
//!
//! This is an IPC trust assertion by the verified CAS service, not a new
//! signature format or hardware anti-rollback proof. The consumer authenticates
//! the server and rechecks the complete signed-chain expiry and profile age.

use crate::error::EnclaveResult;
use crate::profile::Profile;
use serde::{Deserialize, Serialize};

/// The only target admitted by the custody metadata endpoint.
pub const FIDO_MDS_TARGET: &str = "fido-mds-allowlist.json";
/// Bound receipt payload before parsing certificates/allowlist structures.
pub const MAX_MDS_BYTES: usize = 256 * 1024;

/// Closed set of independently issuer-authenticated custody policy targets.
/// This endpoint cannot request an arbitrary TUF target or a model artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CustodyTarget {
    /// Independently signed tier-envelope policy.
    EnvelopePolicy,
    /// Pinned OIDC issuer and broker authority document.
    OidcAuthority,
}

impl CustodyTarget {
    /// Exact signed TUF target path, independent of caller-provided strings.
    pub const fn target_name(self) -> &'static str {
        match self {
            Self::EnvelopePolicy => "custody-envelope-policy-v1.json",
            Self::OidcAuthority => "custody-oidc-authority-v1.json",
        }
    }

    /// Maximum body size before policy parsing or receipt construction.
    pub const fn max_bytes(self) -> usize { 16 * 1024 }
}

fn profile_window(profile: Profile) -> i64 {
    match profile {
        Profile::L3 => 24 * 3600,
        Profile::L2 => 72 * 3600,
        Profile::L1 => 168 * 3600,
    }
}

/// Authenticated CAS assertion for one fixed custody policy target.
///
/// The verified UID 702 channel authenticates this receipt. Its digest binds
/// the body; it does not replace the consumer's independent issuer and scope
/// checks, or supply a signature/native rollback proof of its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyTargetReceipt {
    /// Receipt format, currently one.
    pub v: u8,
    /// Exact fixed target path, checked against the requested enum variant.
    pub target: String,
    /// Exact TUF-verified body, bounded by the fixed target's maximum.
    pub bytes: serde_bytes::ByteBuf,
    /// Trusted CAS clock at its last verified metadata refresh.
    pub refreshed_at: i64,
    /// Earliest exclusive root/timestamp/snapshot/targets expiry.
    pub expires_at: i64,
    /// Trusted CAS clock when constructing this receipt.
    pub verified_now: i64,
    /// CAS host/configuration floor used when issuing this receipt. Consumers
    /// may tighten it but cannot recompute a longer profile freshness window.
    pub effective_profile: Profile,
    /// Accepted timestamp/snapshot/targets versions, respectively.
    pub versions: (u64, u64, u64),
    /// Lowercase BLAKE3 digest binding the exact returned body.
    pub blake3: String,
}

impl CustodyTargetReceipt {
    /// Exclusive lifetime bound to retain after `validate`: the earlier of
    /// complete signed-chain expiry and the captured profile refresh deadline.
    /// Later refreshes never extend an already captured operation's bound.
    pub fn valid_until_unix(&self, profile: Profile) -> EnclaveResult<i64> {
        let age_deadline = self.refreshed_at.checked_add(profile_window(profile.max(self.effective_profile)))
            .filter(|_| self.refreshed_at >= 0)
            .ok_or_else(|| crate::err!(ESTALE, "CUSTODY_TARGET_STALE"))?;
        Ok(self.expires_at.min(age_deadline))
    }

    /// Check the exact requested target, body and independent freshness limits
    /// after authenticating the CAS server. Use the maximum clock observation
    /// so a client's earlier wall clock cannot extend CAS authority.
    pub fn validate(&self, local_now: i64, profile: Profile, expected: CustodyTarget) -> EnclaveResult<()> {
        if self.v != 1 || self.target != expected.target_name() || self.bytes.is_empty()
            || self.bytes.len() > expected.max_bytes() || self.versions.0 == 0
            || self.versions.1 == 0 || self.versions.2 == 0
            || self.blake3 != blake3::hash(&self.bytes).to_hex().as_str()
        { crate::fail!(EACCES, "CUSTODY_TARGET_RECEIPT"); }
        let now = local_now.max(self.verified_now);
        if local_now < 0 || self.verified_now < self.refreshed_at
            || now < self.refreshed_at || now >= self.valid_until_unix(profile)?
        { crate::fail!(ESTALE, "CUSTODY_TARGET_STALE"); }
        Ok(())
    }
}

#[cfg(test)]
mod target_tests {
    use super::*;
    fn receipt(target: CustodyTarget) -> CustodyTargetReceipt {
        let bytes = b"{\"policy\":1}".to_vec();
        CustodyTargetReceipt { v:1, target:target.target_name().into(),
            blake3:blake3::hash(&bytes).to_hex().to_string(), bytes:bytes.into(),
            refreshed_at:100, expires_at:1_000_000, verified_now:101,
            effective_profile:Profile::L1, versions:(1,2,3) }
    }

    #[test]
    fn fixed_target_receipt_retains_strict_chain_and_profile_deadlines() {
        let expected = CustodyTarget::EnvelopePolicy;
        for (profile, window) in [(Profile::L3,24*3600),(Profile::L2,72*3600),(Profile::L1,168*3600)] {
            let mut r = receipt(expected);
            assert_eq!(r.valid_until_unix(profile).unwrap(),100+window);
            r.validate(100+window-1,profile,expected).unwrap();
            assert!(r.validate(100+window,profile,expected).unwrap_err().is("CUSTODY_TARGET_STALE"));
            r.expires_at = 200;
            assert_eq!(r.valid_until_unix(profile).unwrap(),200);
            r.validate(199,profile,expected).unwrap();
            assert!(r.validate(200,profile,expected).is_err());
            r.verified_now = 200;
            assert!(r.validate(150,profile,expected).is_err());
        }
        let mut strict = receipt(expected);
        strict.effective_profile = Profile::L3;
        assert_eq!(strict.valid_until_unix(Profile::L1).unwrap(),100+24*3600);
        assert!(strict.validate(100+24*3600,Profile::L1,expected).is_err());
    }

    #[test]
    fn fixed_target_receipt_rejects_substitution_body_versions_and_clock_relabeling() {
        let expected = CustodyTarget::OidcAuthority;
        for mutation in 0..13 {
            let mut r = receipt(expected);
            match mutation {
                0 => r.v = 2,
                1 => r.target = CustodyTarget::EnvelopePolicy.target_name().into(),
                2 => r.bytes = vec![0].into(),
                3 => r.versions.0 = 0,
                4 => r.versions.1 = 0,
                5 => r.versions.2 = 0,
                6 => r.refreshed_at = 102,
                7 => r.refreshed_at = -1,
                8 => r.refreshed_at = i64::MAX,
                9 => r.bytes = Vec::new().into(),
                10 => { let bytes = vec![0;expected.max_bytes()+1]; r.blake3 = blake3::hash(&bytes).to_hex().to_string(); r.bytes = bytes.into(); },
                11 => r.blake3 = r.blake3.to_ascii_uppercase(),
                _ => r.expires_at = 101,
            }
            assert!(r.validate(101,Profile::L3,expected).is_err(),"mutation {mutation}");
        }
        let r = receipt(expected);
        assert!(r.validate(-1,Profile::L3,expected).is_err());
        assert!(r.validate(101,Profile::L3,CustodyTarget::EnvelopePolicy).is_err());
        let mut r = r;
        r.refreshed_at = i64::MAX; r.verified_now = i64::MAX;
        assert!(r.valid_until_unix(Profile::L3).is_err());
    }

    #[test]
    fn fixed_target_wire_is_closed_and_exact_at_body_limit() {
        assert!(serde_json::from_str::<CustodyTarget>("\"arbitrary.json\"").is_err());
        assert!(serde_json::from_str::<CustodyTarget>("\"HostConfig\"").is_err());
        for expected in [CustodyTarget::EnvelopePolicy,CustodyTarget::OidcAuthority] {
            let mut r = receipt(expected);
            let bytes = vec![0;expected.max_bytes()];
            r.blake3 = blake3::hash(&bytes).to_hex().to_string(); r.bytes = bytes.into();
            r.validate(101,Profile::L3,expected).unwrap();
            let encoded = crate::ipc::to_cbor(&r).unwrap();
            assert_eq!(crate::ipc::from_cbor::<CustodyTargetReceipt>(&encoded).unwrap(),r);
            let mut extra = serde_json::to_value(&r).unwrap();
            extra["expiry_override"] = serde_json::json!(9999999);
            assert!(serde_json::from_value::<CustodyTargetReceipt>(extra).is_err());
        }
    }
}

/// Exact versioned payload of `CasResponse::CustodyMetadata`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyMetadataReceipt {
    /// Receipt format, currently one.
    pub v: u8,
    /// Fixed target path; callers cannot request an arbitrary target.
    pub target: String,
    /// TUF-verified exact target bytes, bounded by `MAX_MDS_BYTES`.
    pub bytes: serde_bytes::ByteBuf,
    /// Trusted CAS clock at the last verified metadata refresh.
    pub refreshed_at: i64,
    /// Earliest expiry of root/timestamp/snapshot/targets metadata.
    pub expires_at: i64,
    /// Current trusted CAS clock when this receipt was constructed.
    pub verified_now: i64,
    /// CAS host/configuration floor; consumers may only tighten this freshness
    /// profile when retaining the receipt's effective lifetime.
    pub effective_profile: Profile,
    /// Accepted timestamp/snapshot/targets versions, respectively.
    pub versions: (u64, u64, u64),
    /// Lowercase BLAKE3 digest, also checked against signed host configuration.
    pub blake3: String,
}

impl CustodyMetadataReceipt {
    /// Earlier exclusive signed-chain and effective profile refresh deadline.
    /// Retain this bound in derived MDS state after successful `validate`.
    pub fn valid_until_unix(&self, profile: Profile) -> EnclaveResult<i64> {
        let age_deadline = self.refreshed_at.checked_add(profile_window(profile.max(self.effective_profile)))
            .filter(|_| self.refreshed_at >= 0)
            .ok_or_else(|| crate::err!(ESTALE, "CUSTODY_METADATA_STALE"))?;
        Ok(self.expires_at.min(age_deadline))
    }

    /// Check the authenticated receipt without trusting the client's file mtime
    /// or treating cached model grace as custody authority.
    pub fn validate(&self, local_now: i64, profile: Profile) -> EnclaveResult<()> {
        if self.v != 1 || self.target != FIDO_MDS_TARGET || self.bytes.is_empty()
            || self.bytes.len() > MAX_MDS_BYTES || self.versions.0 == 0
            || self.versions.1 == 0 || self.versions.2 == 0
            || self.blake3 != blake3::hash(&self.bytes).to_hex().as_str()
        { crate::fail!(EACCES, "CUSTODY_METADATA_RECEIPT"); }
        let now = local_now.max(self.verified_now);
        if self.refreshed_at < 0 || self.verified_now < self.refreshed_at
            || local_now < 0 || now < self.refreshed_at
            || now >= self.valid_until_unix(profile)?
        { crate::fail!(ESTALE, "CUSTODY_METADATA_STALE"); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn receipt() -> CustodyMetadataReceipt {
        let bytes = b"{\"entries\":[]}".to_vec();
        CustodyMetadataReceipt { v: 1, target: FIDO_MDS_TARGET.into(),
            blake3: blake3::hash(&bytes).to_hex().to_string(), bytes: bytes.into(),
            refreshed_at: 100, expires_at: 1_000_000, verified_now: 101,
            effective_profile: Profile::L1, versions: (1,1,1) }
    }
    #[test]
    fn authenticated_expiry_and_profile_age_are_independent_strict_limits() {
        let mut receipt = receipt();
        assert!(receipt.validate(101, Profile::L3).is_ok());
        assert!(receipt.validate(100 + 24*3600 - 1, Profile::L3).is_ok());
        assert!(receipt.validate(100 + 24*3600, Profile::L3).unwrap_err().is("CUSTODY_METADATA_STALE"));
        assert!(receipt.validate(100 + 72*3600, Profile::L2).unwrap_err().is("CUSTODY_METADATA_STALE"));
        receipt.expires_at = 200;
        assert!(receipt.validate(199, Profile::L3).is_ok());
        assert!(receipt.validate(200, Profile::L3).unwrap_err().is("CUSTODY_METADATA_STALE"));
        receipt.verified_now = 200;
        assert!(receipt.validate(150, Profile::L3).unwrap_err().is("CUSTODY_METADATA_STALE"));
        receipt.expires_at = 1_000_000;
        receipt.effective_profile = Profile::L3;
        assert_eq!(receipt.valid_until_unix(Profile::L1).unwrap(),100+24*3600);
        assert!(receipt.validate(100+24*3600, Profile::L1).unwrap_err().is("CUSTODY_METADATA_STALE"));
    }
    #[test]
    fn unknown_version_target_digest_and_clock_relabeling_refuse() {
        for mutation in 0..6 {
            let mut receipt = receipt();
            match mutation { 0 => receipt.v = 2, 1 => receipt.target = "other.json".into(),
                2 => receipt.bytes = vec![0].into(), 3 => receipt.versions.1 = 0,
                4 => receipt.refreshed_at = 102, _ => receipt.refreshed_at = -1 }
            assert!(receipt.validate(101, Profile::L3).is_err());
        }
    }
}
