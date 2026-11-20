//! Pure cryptographic preflight, conditional on an explicitly supplied pin.
//!
//! No pin provenance, fresh namespace, current provisioning file, sealed floor,
//! live CAS receipt or runtime authority is established here. The caller must
//! retain those real boundaries. This module never opens a path or returns a
//! TUF client, verified envelope context, receipt or activation capability.

use std::collections::BTreeMap;
use enclave_core::{custody_metadata::{CustodyTarget,FIDO_MDS_TARGET},
    deployment::{DeploymentRole,DeploymentTarget,normalized_path},error::EnclaveResult,
    host_config::{EnclaveHostConfig,HOST_CONFIG_TARGET},err,fail,Profile};
use enclave_crypto::{hpke_envelope::SignedEnvelopePolicy,tuf::TufClient};
use enclave_custody_vaultd::{ctap::mds::MdsAllowlist,provisioning::CustodyProvisioning};
use serde::Serialize;
use sha2::{Digest,Sha256};
use super::target_runtime_trust::{self,RuntimeInputRole,RuntimeTrustInput,RuntimeTrustPlan};

const MAX_PIN_BYTES:usize=4*1024*1024;

/// Diagnostic data only, never a checked runtime/import/installation token.
#[derive(Debug,Serialize)]
pub(crate) struct RuntimePreflightReport {
    pub(crate) version:u8,
    pub(crate) kind:&'static str,
    pub(crate) verification:&'static str,
    pub(crate) checked_at_supplied_unix:i64,
    pub(crate) supplied_pin_sha256:String,
    pub(crate) pin_provenance_verified:bool,
    pub(crate) fresh_namespace_proven:bool,
    pub(crate) provisioning_currentness_verified:bool,
    pub(crate) provisioning_manifest_sha256:String,
    pub(crate) root_version:u64,
    pub(crate) versions:(u64,u64,u64),
    pub(crate) rotations_applied:usize,
    pub(crate) metadata_expires_at:i64,
    pub(crate) envelope_review_or_expiry:i64,
    pub(crate) candidate_root_authenticated:bool,
    pub(crate) live_cas_receipt:bool,
    pub(crate) runtime_authority:bool,
    pub(crate) installation_supported:bool,
    pub(crate) qualified:bool,
    pub(crate) input_plan:RuntimeTrustPlan,
}

/// Check fresh dedicated L2 candidate bytes against the supplied root and the
/// genuine already-loaded independent custody issuer/scope. The expected pin
/// digest checks expectation integrity only; it never proves pin provenance.
/// `now` must be the caller's actual observation, not a persisted trusted-clock
/// substitute. This pure call cannot revalidate the provisioning file or any
/// sealed state; the caller must do so at its actual I/O/effect boundaries.
pub(crate) fn preflight(target:&DeploymentTarget,descriptor_sha256:&str,
    entries:&[RuntimeTrustInput<'_>],runtime_pin:&[u8],expected_pin_sha256:&str,
    provisioning:&CustodyProvisioning,now:i64)->EnclaveResult<RuntimePreflightReport> {
    if target.role!=DeploymentRole::DedicatedTest||target.profile!=Profile::L2 {
        fail!(EACCES,"RUNTIME_PREFLIGHT_FRESH_DEDICATED_L2_REQUIRED");
    }
    if now<0 {fail!(EINVAL,"RUNTIME_PREFLIGHT_TIME");}
    let plan=target_runtime_trust::describe(target,descriptor_sha256,entries)?;
    if !plan.supplied_inputs_complete {fail!(EINVAL,"RUNTIME_PREFLIGHT_INPUTS_INCOMPLETE");}
    if runtime_pin.is_empty()||runtime_pin.len()>MAX_PIN_BYTES {
        fail!(E2BIG,"RUNTIME_PREFLIGHT_PIN_BOUND");
    }
    let pin_sha256=hex::encode(Sha256::digest(runtime_pin));
    if expected_pin_sha256.len()!=64||!expected_pin_sha256.bytes()
        .all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))||expected_pin_sha256!=pin_sha256 {
        fail!(EACCES,"RUNTIME_PREFLIGHT_PIN_EXPECTATION");
    }
    let receipt=provisioning.receipt();
    if normalized_path(provisioning.manifest_path())?!=normalized_path(&target.authority_config)? {
        fail!(EACCES,"RUNTIME_PREFLIGHT_PROVISIONING_BINDING");
    }
    if receipt.profile!=Profile::L2||now>=receipt.asset_policy_expires_unix {
        fail!(EACCES,"RUNTIME_PREFLIGHT_PROVISIONING_SCOPE_OR_EXPIRY");
    }
    // describe already proved each direct source role and exact byte/inventory
    // binding. Match those original borrowed bytes; never read report paths.
    let mut bytes=BTreeMap::new();
    for entry in &plan.inputs {
        let input=entries.iter().find(|input|input.source==entry.source.as_path())
            .ok_or_else(||err!(EINVAL,"RUNTIME_PREFLIGHT_INPUT_BINDING"))?;
        bytes.insert(entry.name.clone(),input.bytes);
    }
    let get=|name:&str|bytes.get(name).copied().ok_or_else(||err!(EINVAL,"RUNTIME_PREFLIGHT_INPUTS_INCOMPLETE"));
    let mut client=TufClient::bootstrap(runtime_pin)?;
    let current=client.root().version;
    let mut rotations=BTreeMap::new();
    for entry in &plan.inputs {
        if entry.role==RuntimeInputRole::RootRotation {
            // Actual startup ignores historical numbered documents. Later
            // versions are ordered numerically and checked by update_root.
            let version=entry.name.strip_suffix(".root.json").and_then(|n|n.parse::<u64>().ok())
                .ok_or_else(||err!(EINVAL,"RUNTIME_PREFLIGHT_ROOT_NAME"))?;
            if version>current {rotations.insert(version,get(&entry.name)?);}
        }
    }
    let rotations_applied=rotations.len();
    for root in rotations.into_values() {client.update_root(root)?;}
    // root.json remains a diagnostic candidate: it is NEVER used to bootstrap
    // or substitute for the supplied pin and is not claimed authenticated.
    client.refresh(get("timestamp.json")?,get("snapshot.json")?,get("targets.json")?,now)?;
    client.ensure_fresh(now)?;
    for name in [HOST_CONFIG_TARGET,FIDO_MDS_TARGET,CustodyTarget::EnvelopePolicy.target_name()] {
        let metadata=client.verify_target(name,get(name)?,now)?;
        if metadata.custom.as_ref().and_then(|v|v.get("revoked")).and_then(serde_json::Value::as_bool)==Some(true) {
            fail!(EACCES,"TARGET_REVOKED");
        }
        if name==CustodyTarget::EnvelopePolicy.target_name()
            && metadata.custom.as_ref().is_some_and(|v|["classification","min_profile","license_policy",
                "jurisdiction_shard","companion_safety_layers","encrypted_transport"].iter().any(|key|v.get(*key).is_some())) {
            fail!(EACCES,"MODEL_DESCRIPTOR_REQUIRED");
        }
    }
    let host=EnclaveHostConfig::from_json_bytes(get(HOST_CONFIG_TARGET)?)?;
    host.admit_profile(target.profile)?;
    let mds=get(FIDO_MDS_TARGET)?;
    let _:MdsAllowlist=serde_json::from_slice(mds).map_err(|_|err!(EINVAL,"RUNTIME_PREFLIGHT_MDS_SCHEMA"))?;
    if host.fido_mds_allowlist_digest!=blake3::hash(mds).to_hex().as_str() {
        fail!(EACCES,"RUNTIME_PREFLIGHT_MDS_BINDING");
    }
    let signed:SignedEnvelopePolicy=serde_json::from_slice(get(CustodyTarget::EnvelopePolicy.target_name())?)
        .map_err(|_|err!(EINVAL,"RUNTIME_PREFLIGHT_ENVELOPE_SCHEMA"))?;
    let authority=provisioning.authorities().1;
    let envelope=signed.verify(&authority.issuer,&authority.subject,&authority.namespace,now)?;
    if !signed.policy.profiles.contains(&target.profile) {fail!(EACCES,"RUNTIME_PREFLIGHT_ENVELOPE_PROFILE");}
    Ok(RuntimePreflightReport {version:1,kind:"depot-runtime-crypto-preflight",
        verification:"CONDITIONAL_ON_SUPPLIED_PIN_NOT_RUNTIME_AUTHORITY",checked_at_supplied_unix:now,
        supplied_pin_sha256:pin_sha256,pin_provenance_verified:false,fresh_namespace_proven:false,
        provisioning_currentness_verified:false,provisioning_manifest_sha256:receipt.manifest_sha256.clone(),
        root_version:client.root().version,versions:client.versions(),rotations_applied,
        metadata_expires_at:client.fresh_until()?,envelope_review_or_expiry:envelope.policy_expires_unix(),
        candidate_root_authenticated:false,live_cas_receipt:false,runtime_authority:false,
        installation_supported:false,qualified:false,input_plan:plan})
}

#[cfg(test)]
#[path="target_runtime_preflight_tests.rs"]
mod tests;
