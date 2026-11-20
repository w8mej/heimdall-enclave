//! Artifact admission & resolution (FS-702 §3.2): only roots that appear in
//! the locally verified, TUF-signed targets metadata are resolvable; the
//! effective profile is `max(workstation, signed target, URI hint)`;
//! mandatory companion safety layers are hydrated and verified eagerly; the
//! artifact passes the structural sanitizer before any FD is returned.

use std::fs::File;

use enclave_core::error::EnclaveResult;
use enclave_core::profile::Profile;
use enclave_core::{err, fail};
use enclave_crypto::tuf::TufClient;

use crate::cas::ContentStore;
use crate::cas_uri::CasUri;
use crate::governance::TargetPolicy;
use crate::sanitizer;

/// Admitted artifact.
#[derive(Debug)]
pub struct Resolved {
    /// Effective profile.
    pub effective_profile: Profile,
    /// Signed policy.
    pub policy: TargetPolicy,
    /// Read-only FDs: the artifact followed by eagerly hydrated companions.
    pub fds: Vec<File>,
    /// SHA-256 of the artifact.
    pub sha256: String,
}

/// Find the target whose `blake3` equals the URI root and parse its policy.
pub fn lookup<'a>(
    tuf: &'a TufClient,
    uri: &CasUri,
    now: i64,
) -> EnclaveResult<(&'a enclave_crypto::tuf::TargetFile, TargetPolicy)> {
    let tf = tuf.target(&uri.target, now)?;
    if tf.hashes.get("blake3").map(String::as_str) != Some(uri.root.as_str()) {
        fail!(
            EACCES,
            "ROOT_NOT_IN_SIGNED_TARGETS",
            "arbitrary hashes are never resolved"
        );
    }
    if tf.custom.as_ref().is_some_and(|custom|custom.get("encrypted_transport").is_some()) {
        crate::transport::oblivious::EncryptedTarget::from_target(tf,&uri.ns)?;
    }
    let custom = tf
        .custom
        .clone()
        .ok_or_else(|| err!(EACCES, "TARGET_POLICY_MISSING"))?;
    let policy: TargetPolicy =
        serde_json::from_value(custom).map_err(|e| err!(EINVAL, "TARGET_POLICY", "{e}"))?;
    if policy.revoked {
        fail!(EACCES, "TARGET_REVOKED", "{}", uri.target);
    }
    Ok((tf, policy))
}

/// Admit an artifact into the CAS: TUF length + dual-hash verification, then
/// format sanitization (safetensors / zipped mlpackage by magic).
pub fn admit(
    store: &ContentStore,
    tuf: &TufClient,
    target: &str,
    bytes: &[u8],
    now: i64,
) -> EnclaveResult<String> {
    let tf = tuf.verify_target(target, bytes, now)?;
    if tf
        .custom
        .as_ref()
        .and_then(|c| c.get("revoked"))
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        fail!(EACCES, "TARGET_REVOKED", "{target}");
    }
    let lower = target.to_ascii_lowercase();
    if lower.ends_with(".safetensors") {
        sanitizer::check_safetensors(bytes)?;
    } else if lower.ends_with(".mlpackage.zip") || lower.ends_with(".mlpackage") {
        sanitizer::check_mlpackage_zip(bytes, tf.length)?;
    } else if lower.ends_with(".gguf") {
        if bytes.len() < 4 || &bytes[..4] != b"GGUF" {
            fail!(EINVAL, "GGUF_MAGIC_INVALID", "expected GGUF magic header");
        }
    } else if lower.ends_with(".bin") || lower.ends_with(".json") {
        sanitizer::check_magic(target, bytes)?;
    } else {
        fail!(
            EACCES,
            "UNSUPPORTED_ARTIFACT_FORMAT",
            "target {target} has unapproved extension; must be .safetensors, .mlpackage, .gguf, .bin, or .json"
        );
    }
    let m = store.put(bytes)?;
    Ok(m.blake3)
}

/// Resolve a `cas://` URI for a consumer.
pub fn resolve(
    store: &ContentStore,
    tuf: &TufClient,
    uri_s: &str,
    workstation: Profile,
    now: i64,
) -> EnclaveResult<Resolved> {
    let uri = CasUri::parse(uri_s)?;
    let (tf, policy) = lookup(tuf, &uri, now)?;
    let hints: Vec<Profile> = uri
        .min_profile
        .into_iter()
        .chain([policy.classification.floor()])
        .collect();
    let effective = Profile::effective(workstation, policy.min_profile, &hints);
    let mut fds = vec![store.open_readonly(&uri.root)?];
    let sha = store.manifest(&uri.root)?.sha256;
    if tf.hashes.get("sha256") != Some(&sha) {
        fail!(EACCES, "SHA256_MISMATCH");
    }
    // This low-level resolver computes the effective context; service callers
    // separately admit that context against their actual host before handoff.
    // Validate companions against the computed main context, preserving the
    // existing anti-downgrade API for callers inspecting a signed higher floor.
    fds.extend(open_companions(store, tuf, &policy, effective)?);
    Ok(Resolved {
        effective_profile: effective,
        policy,
        fds,
        sha256: sha,
    })
}

/// Verify/open just the eager companion closure. Named-file export may have
/// no main CAS manifest, so it must not invoke the CAS-only main resolver.
pub(crate) fn open_companions(
    store: &ContentStore, tuf: &TufClient, policy: &TargetPolicy, workstation: Profile,
) -> EnclaveResult<Vec<File>> {
    let mut fds = Vec::new();
    for c in &policy.companion_safety_layers {
        if c.eager_hydrate_required {
            // Companions must themselves be signed targets of the same snapshot.
            let signed = tuf
                .targets()
                .and_then(|t| {
                    t.values()
                        .find(|t| t.hashes.get("blake3") == Some(&c.blake3))
                })
                .ok_or_else(|| err!(EACCES, "COMPANION_NOT_SIGNED", "{}", c.role))?;
            crate::streaming::validate_target(signed)?;
            if let Some(custom) = &signed.custom {
                if custom.get("classification").is_some() || custom.get("min_profile").is_some() {
                    let companion_policy: TargetPolicy = serde_json::from_value(custom.clone())
                        .map_err(|e| err!(EINVAL, "TARGET_POLICY", "{e}"))?;
                    if companion_policy.min_profile.max(companion_policy.classification.floor()) > workstation {
                        fail!(EPERM, "PROFILE_FLOOR_EXCEEDED");
                    }
                }
            }
            let manifest = store.manifest(&c.blake3)
                .map_err(|_| err!(EACCES, "COMPANION_NOT_HYDRATED", "{}", c.role))?;
            if manifest.len != signed.length || signed.hashes.get("sha256") != Some(&manifest.sha256) {
                fail!(EACCES, "COMPANION_METADATA_MISMATCH");
            }
            fds.push(
                store
                    .open_readonly(&c.blake3)
                    .map_err(|_| err!(EACCES, "COMPANION_NOT_HYDRATED", "{}", c.role))?,
            );
        }
    }
    Ok(fds)
}
