//! Signed host configuration distributed via TUF (GAP-20, ADR-007 §3).

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::daemon::DaemonId;
use crate::error::EnclaveResult;
use crate::profile::Profile;
use crate::{err, fail};

/// Reserved TUF target name for the host configuration.
pub const HOST_CONFIG_TARGET: &str = "enclave-host-config.json";

/// Bound configuration parsing independently of artifact-size limits.
pub const MAX_HOST_CONFIG_BYTES: usize = 64 * 1024;

/// Versioned calibration payload whose digest is pinned by the host config.
pub const CALIBRATION_CORPUS_TARGET: &str = "enclave-calib-eval-v1.jsonl";

/// The signed host configuration payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnclaveHostConfig {
    /// Workstation profile floor.
    pub profile_floor: Profile,
    /// UID 704's custody-grant public key (hex-encoded Ed25519).
    pub ifc_grant_public_key: String,
    /// Optional OHTTP gateway key config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ohttp_key_config: Option<String>,
    /// BLAKE3 digest of the calibration corpus.
    pub calibration_corpus_digest: String,
    /// BLAKE3 digest of the STARK verifying key (vk).
    pub vk_digest: String,
    /// BLAKE3 digest of the MCP tool lock.
    pub mcp_lock_digest: String,
    /// BLAKE3 digest of the FIDO MDS allowlist.
    pub fido_mds_allowlist_digest: String,
    /// Optional codesign pins for LocalPins mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codesign_pins: Option<BTreeMap<String, String>>,
}

impl EnclaveHostConfig {
    /// Validate structural fields of the host config.
    pub fn validate(&self) -> EnclaveResult<()> {
        if self.ifc_grant_public_key.len() != 64 || hex::decode(&self.ifc_grant_public_key).is_err()
        {
            fail!(
                EINVAL,
                "HOST_CONFIG_INVALID",
                "invalid ifc_grant_public_key (must be 64-hex chars)"
            );
        }
        for (name, d) in [
            ("calibration_corpus_digest", &self.calibration_corpus_digest),
            ("vk_digest", &self.vk_digest),
            ("mcp_lock_digest", &self.mcp_lock_digest),
            ("fido_mds_allowlist_digest", &self.fido_mds_allowlist_digest),
        ] {
            if d.len() != 64 || hex::decode(d).is_err() {
                fail!(
                    EINVAL,
                    "HOST_CONFIG_INVALID",
                    "invalid {name} (must be 64-hex chars)"
                );
            }
        }
        Ok(())
    }

    /// Refuse a requested daemon profile below this authenticated floor.
    /// Callers must obtain this payload through verified TUF/CAS, not local JSON.
    pub fn admit_profile(&self, requested: Profile) -> EnclaveResult<()> {
        self.validate()?;
        if requested < self.profile_floor {
            fail!(EPERM, "HOST_PROFILE_BELOW_FLOOR",
                "requested {requested} is below signed host floor {}", self.profile_floor);
        }
        Ok(())
    }

    /// Parse and validate from JSON bytes.
    pub fn from_json_bytes(bytes: &[u8]) -> EnclaveResult<Self> {
        if bytes.len() > MAX_HOST_CONFIG_BYTES {
            fail!(E2BIG, "HOST_CONFIG_TOO_LARGE");
        }
        let config: Self =
            serde_json::from_slice(bytes).map_err(|e| err!(EINVAL, "HOST_CONFIG_DECODE", "{e}"))?;
        config.validate()?;
        Ok(config)
    }

    /// Serialize to canonical JSON bytes.
    pub fn to_json_bytes(&self) -> EnclaveResult<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec_pretty(self).map_err(|e| err!(EINVAL, "HOST_CONFIG_ENCODE", "{e}"))
    }
}

/// Fetch arbitrary TUF target payload from UID 702 (SwarmSync) over UDS.
pub fn fetch_tuf_target(socket_dir: &Path, target: &str, dev: bool) -> EnclaveResult<Vec<u8>> {
    let cas_sock = socket_dir
        .join(DaemonId::SwarmSync.dir_name())
        .join(format!("{}.sock", DaemonId::SwarmSync.dir_name()));

    #[derive(Serialize)]
    enum CasFetchReq<'a> {
        FetchTarget { target: &'a str },
        FetchHostConfig,
    }
    #[derive(Deserialize)]
    enum CasFetchResp {
        Bytes(serde_bytes::ByteBuf),
    }

    let mut c = if dev {
        crate::ipc::Client::connect(&cas_sock, crate::ipc::geteuid())?
    } else {
        crate::ipc::Client::connect_verified(
            &cas_sock,
            DaemonId::SwarmSync.uid(),
            Some(&crate::codesign::CodeRequirement::daemon(
                DaemonId::SwarmSync,
            )),
        )?
    };

    let request = if target == HOST_CONFIG_TARGET {
        CasFetchReq::FetchHostConfig
    } else {
        CasFetchReq::FetchTarget { target }
    };
    let resp: CasFetchResp = c.call(&request)?;
    match resp {
        CasFetchResp::Bytes(b) => Ok(b.into_vec()),
    }
}

/// Fetch and verify the signed host configuration from UID 702 (SwarmSync).
pub fn fetch_host_config(socket_dir: &Path, dev: bool) -> EnclaveResult<EnclaveHostConfig> {
    let bytes = fetch_tuf_target(socket_dir, HOST_CONFIG_TARGET, dev)?;
    EnclaveHostConfig::from_json_bytes(&bytes)
}

/// Authenticate the host configuration and admit the exact requested profile.
/// Development uses same-UID fixture authentication; production pins CAS UID and
/// signing identity. Missing, stale, malformed or unauthenticated config refuses.
pub fn require_profile_floor(socket_dir: &Path, requested: Profile, dev: bool) -> EnclaveResult<()> {
    fetch_host_config(socket_dir, dev)?.admit_profile(requested)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_config_roundtrip_and_validation() {
        let cfg = EnclaveHostConfig {
            profile_floor: Profile::L2,
            ifc_grant_public_key: "01".repeat(32),
            ohttp_key_config: None,
            calibration_corpus_digest: "02".repeat(32),
            vk_digest: "03".repeat(32),
            mcp_lock_digest: "04".repeat(32),
            fido_mds_allowlist_digest: "05".repeat(32),
            codesign_pins: None,
        };

        let bytes = cfg.to_json_bytes().unwrap();
        let loaded = EnclaveHostConfig::from_json_bytes(&bytes).unwrap();
        assert_eq!(cfg, loaded);

        let mut bad = cfg.clone();
        bad.ifc_grant_public_key = "invalid".into();
        assert!(bad.validate().is_err());
    }
}
