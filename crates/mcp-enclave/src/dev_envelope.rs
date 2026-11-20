//! Track C development fleet: the custody envelope policy for real custody.
//!
//! On real hardware UID 703 seals vault data only under a signed envelope
//! policy that it fetches from CAS (TUF target `custody-envelope-policy-v1.json`)
//! and verifies against an independently configured issuer, subject and
//! namespace. An installed deployment gets these from provisioning. The dev
//! fleet with `depot_ENCLAVE_REAL_CUSTODY=1` acts as its own administrator: it
//! generates an issuer key in its private state directory, signs one `L1`
//! policy and publishes it next to the host config. Custody's checks are
//! unchanged; the policy dies with the state directory.

use std::path::{Path, PathBuf};

use enclave_core::error::EnclaveResult;
use enclave_core::profile::Profile;
use enclave_core::{err, fail};
use enclave_crypto::hpke_envelope::{EnvelopePolicy, SignedEnvelopePolicy, ENVELOPE_POLICY_TARGET};

use crate::devtuf::DevRepo;

/// Issuer seed (hex, private) in the dev state directory.
pub const KEY_FILE: &str = "envelope-policy.key";
/// Issuer public key (hex), handed to custody as `--envelope-policy-key-file`.
pub const PUBLIC_FILE: &str = "envelope-policy.pub";
/// Subject custody expects; the dev fleet has one host.
pub const SUBJECT: &str = "dev-fleet-host";
/// Namespace custody expects.
pub const NAMESPACE: &str = "dev-fleet-l1";
/// Policy lifetime. A ceremony uses a fresh state directory.
const LIFETIME_SECS: i64 = 30 * 24 * 3600;
/// Back-dating so small clock differences between processes never refuse.
const SKEW_SECS: i64 = 60;

/// Custody arguments naming the dev issuer and scope.
pub fn custody_args(state_dir: &Path) -> Vec<String> {
    vec![
        "--envelope-policy-key-file".into(),
        state_dir.join(PUBLIC_FILE).display().to_string(),
        "--envelope-policy-subject".into(),
        SUBJECT.into(),
        "--envelope-policy-namespace".into(),
        NAMESPACE.into(),
    ]
}

/// The unsigned dev policy for `profile`, valid from `now`.
pub fn policy(profile: Profile, now: i64) -> EnvelopePolicy {
    EnvelopePolicy {
        version: 1,
        revision: 1,
        subject: SUBJECT.into(),
        namespace: NAMESPACE.into(),
        issued_unix: now - SKEW_SECS,
        expires_unix: now + LIFETIME_SECS,
        review_unix: now + LIFETIME_SECS,
        owner: "local developer (dev fleet)".into(),
        profiles: vec![profile],
        data_classes: vec!["C3".into(), "C4".into()],
        purpose: "Track C L1 ceremony on this Mac's Secure Enclave".into(),
        migration: "discarded with the dev fleet state directory".into(),
        disclosure: None,
        classical_exception: false,
    }
}

/// Sign `policy` with the issuer seed.
pub fn sign(policy: EnvelopePolicy, seed: &[u8; 32]) -> EnclaveResult<SignedEnvelopePolicy> {
    use ed25519_dalek::Signer;
    let message = policy.signing_message()?;
    let signature = ed25519_dalek::SigningKey::from_bytes(seed).sign(&message);
    Ok(SignedEnvelopePolicy { policy, signature: signature.to_bytes().to_vec() })
}

/// Create the issuer and publish the signed policy once per state directory.
/// Returns the target's path in the repository, for copying into the CAS store.
pub fn ensure_published(state_dir: &Path, profile: Profile) -> EnclaveResult<PathBuf> {
    let repo_dir = state_dir.join("tuf/repo");
    let target = repo_dir.join(ENVELOPE_POLICY_TARGET);
    if target.exists() {
        return Ok(target);
    }
    let seed = enclave_core::rng::bytes32();
    enclave_core::fsutil::write_private(&state_dir.join(KEY_FILE), hex::encode(seed).as_bytes())?;
    let public = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
    // Custody reads this with `read_public_file`: owned by us, not group/world writable.
    enclave_core::fsutil::write_private(&state_dir.join(PUBLIC_FILE), hex::encode(public.to_bytes()).as_bytes())?;
    let now = enclave_crypto::time::now_unix();
    let signed = sign(policy(profile, now), &seed)?;
    // Refuse to publish anything custody would refuse.
    signed.verify(&public, SUBJECT, NAMESPACE, now)?;
    let bytes = serde_json::to_vec(&signed).map_err(|e| err!(EIO, "ENVELOPE_POLICY_ENCODE", "{e}"))?;
    if bytes.len() > enclave_core::custody_metadata::CustodyTarget::EnvelopePolicy.max_bytes() {
        fail!(E2BIG, "ENVELOPE_POLICY_SIZE");
    }
    let mut repo = DevRepo::open_with_keys(&state_dir.join("tuf/keys.json"), &repo_dir)?;
    // No model-descriptor keys: CAS refuses custody targets that carry them.
    repo.add_target(ENVELOPE_POLICY_TARGET, &bytes, serde_json::json!({"media_type": "application/json"}))?;
    enclave_core::fsutil::write_private(&target, &bytes)?;
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_policy_verifies_under_the_custody_scope() {
        let seed = [7u8; 32];
        let public = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
        let now = 1_800_000_000;
        let signed = sign(policy(Profile::L1, now), &seed).unwrap();
        assert!(signed.verify(&public, SUBJECT, NAMESPACE, now).is_ok());
        assert!(signed.verify(&public, SUBJECT, NAMESPACE, now + LIFETIME_SECS).is_err());
        assert!(signed.verify(&public, "other-host", NAMESPACE, now).is_err());
        let other = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]).verifying_key();
        assert!(signed.verify(&other, SUBJECT, NAMESPACE, now).is_err());
    }

    #[test]
    fn custody_args_name_the_public_key_and_scope() {
        let args = custody_args(Path::new("/s"));
        assert_eq!(args, ["--envelope-policy-key-file", "/s/envelope-policy.pub",
            "--envelope-policy-subject", SUBJECT, "--envelope-policy-namespace", NAMESPACE]);
    }
}
