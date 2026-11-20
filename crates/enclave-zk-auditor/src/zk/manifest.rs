//! Verifier Key Manifest for TUF distribution (GAP-20 / GAP-23 / FS-705 §3.5.4).

use serde::{Deserialize, Serialize};

/// Target filename in TUF repository.
pub const VK_MANIFEST_TARGET: &str = "vk_manifest.json";
/// Media type for TUF custom metadata.
pub const VK_MANIFEST_MEDIA_TYPE: &str = "application/vnd.enclave.vk_manifest.v1+json";

/// Pinned verifier key manifest published via TUF.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VkManifestV1 {
    /// Schema version ("v1").
    pub schema_version: String,
    /// Hex-encoded BLAKE3-keyed verifier key digest.
    pub vk_digest: String,
    /// Versioned AIR domain identifier, matching the verifier-key digest.
    pub air_domain: String,
    /// Public input limb count (57).
    pub num_public: usize,
    /// Number of FRI queries (84).
    pub num_queries: usize,
    /// Merkle cap height (4).
    pub merkle_cap_height: usize,
    /// Normative maximum wire proof size in bytes (320 KiB, FS-705 Rev 1.4).
    pub max_proof_bytes: usize,
}

impl Default for VkManifestV1 {
    fn default() -> Self {
        Self {
            schema_version: "v1".into(),
            vk_digest: hex::encode(super::engine::vk_digest()),
            air_domain: super::air::AIR_DOMAIN.into(),
            num_public: super::air::NUM_PUBLIC,
            num_queries: super::engine::NUM_QUERIES,
            merkle_cap_height: super::engine::MERKLE_CAP_HEIGHT,
            max_proof_bytes: super::engine::MAX_PROOF_BYTES,
        }
    }
}

impl VkManifestV1 {
    /// Refuse unsupported relation/parameter combinations rather than treating
    /// a digest string as authority for incompatible codec or security settings.
    /// This admits the two existing accounting relations only; neither is the
    /// complete hardware/redaction compliance relation.
    pub fn validate_supported(&self) -> enclave_core::error::EnclaveResult<()> {
        if self != &Self::default() && self != &Self::production_hiding() {
            enclave_core::fail!(EACCES, "ROLLUP_MANIFEST_UNSUPPORTED");
        }
        Ok(())
    }

    /// Production hiding accounting parameters. Distribution and approval of
    /// this key remain an external TUF/release responsibility.
    pub fn production_hiding() -> Self {
        Self {
            vk_digest: hex::encode(super::engine::hiding_vk_digest()),
            air_domain: format!(
                "{}|{}",
                super::air::AIR_DOMAIN,
                super::engine::HIDING_DOMAIN
            ),
            ..Self::default()
        }
    }

    /// Serialize manifest to formatted JSON bytes.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec_pretty(self)
    }

    /// Parse and validate manifest from JSON bytes.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Return the 32-byte raw digest.
    pub fn vk_digest_bytes(&self) -> Result<[u8; 32], hex::FromHexError> {
        let b = hex::decode(&self.vk_digest)?;
        b.try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)
    }
}
