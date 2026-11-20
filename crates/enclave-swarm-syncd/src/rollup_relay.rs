//! Local compliance-frame admission before any OHTTP encapsulation or queueing.
//! Authority and verifier parameters come from current verified TUF targets,
//! never from the received frame or a sender's success flag.
use std::path::Path;
use enclave_core::{err, fail, error::EnclaveResult, profile::Profile};
use enclave_crypto::tuf::TufClient;
use enclave_zk_auditor::{
    receiver_trust::{ReceiverTrust, TRUST_TARGET, MAX_TRUST_BYTES},
    rollup::MAX_FRAME_BYTES,
    zk::manifest::{VkManifestV1, VK_MANIFEST_TARGET},
};

/// Verify the complete frame and receiver authority at the relay's live trusted
/// clock. Accounting verification still does not establish the missing complete
/// compliance relation or private hardware membership (F78/F115).
pub fn verify_for_relay(
    frame: &[u8], profile: Profile, store: &Path, tuf: &TufClient, now: i64,
) -> EnclaveResult<()> {
    if frame.len() > MAX_FRAME_BYTES { fail!(E2BIG, "ROLLUP_FRAME_TOO_LARGE"); }
    let manifest_bytes = crate::config::get_target_bytes_with_limit(store, tuf, VK_MANIFEST_TARGET, now, 16 * 1024)?;
    let manifest = VkManifestV1::from_json_bytes(&manifest_bytes)
        .map_err(|_| err!(EINVAL, "ROLLUP_MANIFEST_JSON"))?;
    manifest.validate_supported()?;
    let digest = manifest.vk_digest_bytes().map_err(|_| err!(EINVAL, "MANIFEST_VK_DIGEST"))?;
    let trust_bytes = crate::config::get_target_bytes_with_limit(store, tuf, TRUST_TARGET, now, MAX_TRUST_BYTES as u64)?;
    let trust = ReceiverTrust::from_json(&trust_bytes)?;
    let verified = trust.verify(frame, &[digest])?;
    if verified.profile != profile.number() { fail!(EACCES, "ROLLUP_RELAY_PROFILE_MISMATCH"); }
    Ok(())
}
