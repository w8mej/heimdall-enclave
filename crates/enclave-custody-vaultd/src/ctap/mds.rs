//! FIDO Metadata Service allowlist (FS-703 §3.3.1, `RB-201`): the
//! TUF-distributed `fido-mds-allowlist.json` is re-validated on **every**
//! assertion; revoked authenticators and firmware below the minimum fail on
//! their very next use; `A3`/`A4` assertions are accepted only while the
//! TUF metadata is fresher than `24h` (`L3`) / `72h` (`L2`).

use enclave_core::error::EnclaveResult;
use enclave_core::profile::{ActionClass, Profile};
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};

use super::alg;

/// Status reports that disqualify an authenticator.
pub const REVOKING_STATUSES: &[&str] = &[
    "REVOKED",
    "ATTESTATION_KEY_COMPROMISE",
    "USER_VERIFICATION_BYPASS",
    "USER_KEY_REMOTE_COMPROMISE",
    "USER_KEY_PHYSICAL_COMPROMISE",
];

/// Minimum firmware for Ed25519 credentials (YubiKey 5.7.0).
pub const MIN_FW_ED25519: u32 = 0x05_07_00;
/// Minimum firmware for ES256 credentials (YubiKey 5.4.0).
pub const MIN_FW_ES256: u32 = 0x05_04_00;

/// One allowlisted authenticator model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MdsEntry {
    /// AAGUID (32 hex).
    pub aaguid: String,
    /// Description.
    pub description: String,
    /// Minimum firmware (`major << 16 | minor << 8 | patch`).
    pub min_firmware_version: u32,
    /// Status reports.
    pub status_reports: Vec<String>,
    /// Basic-attestation public keys: `"ed25519:<hex>"` or `"es256:<sec1 hex>"`.
    #[serde(default)]
    pub attestation_public_keys: Vec<String>,
    /// Trusted attestation root CA certificates (base64 DER, PEM, or hex).
    #[serde(default)]
    pub attestation_root_certificates: Vec<String>,
}

/// The allowlist document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MdsAllowlist {
    /// Entries.
    pub entries: Vec<MdsEntry>,
}

/// Allowlist plus the time its TUF metadata was last verified fresh.
#[derive(Debug, Clone)]
pub struct MdsState {
    /// Allowlist.
    pub allowlist: MdsAllowlist,
    /// Unix seconds of the last successful TUF refresh.
    pub refreshed_at: i64,
    /// Earliest verified TUF chain expiry and authenticated producer profile-age
    /// bound. A lower consumer profile must not extend the producer's floor.
    pub expires_at: i64,
}

/// Freshness window per profile.
pub fn freshness_window_s(p: Profile) -> i64 {
    match p {
        Profile::L3 => 24 * 3600,
        Profile::L2 => 72 * 3600,
        Profile::L1 => 168 * 3600,
    }
}

impl MdsState {
    /// Parse a TUF-verified `fido-mds-allowlist.json` target.
    pub fn from_verified_target(bytes: &[u8], refreshed_at: i64) -> EnclaveResult<Self> {
        // No authenticated expiry supplied: this constructor cannot grant
        // critical custody authority merely from a refreshed-at timestamp.
        Self::from_verified_target_with_expiry(bytes, refreshed_at, refreshed_at)
    }

    /// Construct only from the authenticated CAS/TUF target response, with its
    /// earliest signed chain expiry. Caller provenance remains mandatory.
    pub fn from_verified_target_with_expiry(
        bytes: &[u8],
        refreshed_at: i64,
        expires_at: i64,
    ) -> EnclaveResult<Self> {
        let allowlist: MdsAllowlist =
            serde_json::from_slice(bytes).map_err(|e| err!(EINVAL, "MDS_PARSE", "{e}"))?;
        Ok(Self {
            allowlist,
            refreshed_at,
            expires_at,
        })
    }

    fn entry(&self, aaguid: &[u8; 16]) -> EnclaveResult<&MdsEntry> {
        let h = hex::encode(aaguid);
        self.allowlist
            .entries
            .iter()
            .find(|e| e.aaguid == h)
            .ok_or_else(|| err!(EACCES, "AAGUID_NOT_ALLOWLISTED", "{h}"))
    }

    /// Validate an authenticator for an action at `now`.
    pub fn check(
        &self,
        aaguid: &[u8; 16],
        firmware: u32,
        cred_alg: i64,
        profile: Profile,
        action: ActionClass,
        now: i64,
    ) -> EnclaveResult<()> {
        let age = now.checked_sub(self.refreshed_at);
        if action >= ActionClass::A3
            && (self.refreshed_at < 0
                || self.expires_at <= self.refreshed_at
                || now >= self.expires_at
                || age.is_none_or(|age| age < 0 || age >= freshness_window_s(profile)))
        {
            fail!(
                ESTALE,
                "CUSTODY_METADATA_STALE",
                "TUF MDS metadata older than the {profile} window"
            );
        }
        let e = self.entry(aaguid)?;
        if let Some(s) = e
            .status_reports
            .iter()
            .find(|s| REVOKING_STATUSES.contains(&s.as_str()))
        {
            fail!(EACCES, "AUTHENTICATOR_REVOKED", "{s}");
        }
        if firmware < e.min_firmware_version {
            fail!(
                EACCES,
                "FIRMWARE_BELOW_MINIMUM",
                "{firmware:#08x} < {:#08x}",
                e.min_firmware_version
            );
        }
        let alg_floor = match cred_alg {
            alg::EDDSA => MIN_FW_ED25519,
            alg::ES256 => MIN_FW_ES256,
            _ => fail!(EACCES, "AUTHENTICATOR_ALGORITHM_UNSUPPORTED"),
        };
        if firmware < alg_floor {
            fail!(EACCES, "FIRMWARE_BELOW_ALG_MINIMUM");
        }
        Ok(())
    }

    /// Attestation keys for an AAGUID.
    pub fn attestation_keys(&self, aaguid: &[u8; 16]) -> EnclaveResult<Vec<(i64, Vec<u8>)>> {
        let e = self.entry(aaguid)?;
        let mut out = Vec::new();
        for k in &e.attestation_public_keys {
            let (a, h) = k
                .split_once(':')
                .ok_or_else(|| err!(EINVAL, "MDS_KEY_FORMAT"))?;
            let alg_id = match a {
                "ed25519" => alg::EDDSA,
                "es256" => alg::ES256,
                _ => fail!(EINVAL, "MDS_KEY_ALG"),
            };
            out.push((
                alg_id,
                hex::decode(h).map_err(|_| err!(EINVAL, "MDS_KEY_HEX"))?,
            ));
        }
        Ok(out)
    }

    /// Trusted root certificates (DER bytes) for an AAGUID.
    pub fn attestation_roots(&self, aaguid: &[u8; 16]) -> EnclaveResult<Vec<Vec<u8>>> {
        let e = self.entry(aaguid)?;
        let mut out = Vec::new();
        for cert_str in &e.attestation_root_certificates {
            out.push(decode_cert_str(cert_str)?);
        }
        Ok(out)
    }
}

fn decode_cert_str(s: &str) -> EnclaveResult<Vec<u8>> {
    let s = s.trim();
    if s.chars().all(|c| c.is_ascii_hexdigit()) && s.len().is_multiple_of(2) {
        return hex::decode(s).map_err(|e| err!(EINVAL, "HEX_DECODE", "{e}"));
    }
    let filtered = s
        .lines()
        .filter(|l| !l.starts_with("---"))
        .collect::<Vec<_>>()
        .join("");
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for &b in filtered.as_bytes() {
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' | b' ' | b'\n' | b'\r' => continue,
            _ => fail!(EINVAL, "BASE64_CHAR", "invalid char: {b}"),
        };
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod custody_boundary_tests {
    use super::*;
    fn mds(refreshed_at: i64) -> MdsState {
        MdsState {
            refreshed_at,
            expires_at: i64::MAX,
            allowlist: MdsAllowlist {
                entries: vec![MdsEntry {
                    aaguid: hex::encode([8; 16]),
                    description: "synthetic".into(),
                    min_firmware_version: MIN_FW_ED25519,
                    status_reports: vec![],
                    attestation_public_keys: vec![],
                    attestation_root_certificates: vec![],
                }],
            },
        }
    }
    #[test]
    fn custody_freshness_is_strict_at_24_and_72_hours() {
        for profile in [Profile::L2, Profile::L3] {
            let state = mds(100);
            for action in [ActionClass::A3, ActionClass::A4] {
                assert!(state
                    .check(
                        &[8; 16],
                        MIN_FW_ED25519,
                        alg::EDDSA,
                        profile,
                        action,
                        100 + freshness_window_s(profile) - 1
                    )
                    .is_ok());
                for now in [
                    100 + freshness_window_s(profile),
                    101 + freshness_window_s(profile),
                    99,
                    i64::MIN,
                    i64::MAX,
                ] {
                    assert!(state
                        .check(&[8; 16], MIN_FW_ED25519, alg::EDDSA, profile, action, now)
                        .unwrap_err()
                        .is("CUSTODY_METADATA_STALE"));
                }
            }
        }
    }
    #[test]
    fn invalid_timestamp_unknown_algorithm_and_revocation_refuse() {
        assert!(mds(-1)
            .check(
                &[8; 16],
                MIN_FW_ED25519,
                alg::EDDSA,
                Profile::L3,
                ActionClass::A3,
                0
            )
            .unwrap_err()
            .is("CUSTODY_METADATA_STALE"));
        assert!(mds(100)
            .check(
                &[8; 16],
                MIN_FW_ED25519,
                123,
                Profile::L3,
                ActionClass::A3,
                100
            )
            .unwrap_err()
            .is("AUTHENTICATOR_ALGORITHM_UNSUPPORTED"));
        let mut state = mds(100);
        state.expires_at = 101;
        assert!(state
            .check(
                &[8; 16],
                MIN_FW_ED25519,
                alg::EDDSA,
                Profile::L3,
                ActionClass::A3,
                100
            )
            .is_ok());
        assert!(state
            .check(
                &[8; 16],
                MIN_FW_ED25519,
                alg::EDDSA,
                Profile::L3,
                ActionClass::A3,
                101
            )
            .unwrap_err()
            .is("CUSTODY_METADATA_STALE"));
        state.expires_at = i64::MAX;
        state.allowlist.entries[0]
            .status_reports
            .push("REVOKED".into());
        assert!(state
            .check(
                &[8; 16],
                MIN_FW_ED25519,
                alg::EDDSA,
                Profile::L3,
                ActionClass::A3,
                100
            )
            .unwrap_err()
            .is("AUTHENTICATOR_REVOKED"));
    }
}
