//! Inert inventory and route closure for the first custody runtime inputs.
//!
//! This module reads no files, authenticates no metadata, obtains no authority,
//! opens no trust store and publishes nothing. Supplied descriptor/inventory
//! digests are context, not proof of protected loading. Even a complete result
//! remains UNVERIFIED: the actual UID 702/703 consumers must perform the existing
//! independently anchored verification, freshness and durable-state protocol.
//! Software-release approval never provisions or approves a runtime TUF root.

use std::{collections::{BTreeMap, BTreeSet}, path::{Path, PathBuf}};
use enclave_core::{custody_metadata::{CustodyTarget, FIDO_MDS_TARGET, MAX_MDS_BYTES},
    deployment::{DeploymentRole, DeploymentTarget, normalized_path,
        startup_lease::STARTUP_LIFETIME_LEAF, upgrade::UPGRADE_INHIBITION_LEAF}, error::EnclaveResult,
    host_config::{EnclaveHostConfig, HOST_CONFIG_TARGET, MAX_HOST_CONFIG_BYTES},
    err, fail, Profile};
use enclave_crypto::{hpke_envelope::SignedEnvelopePolicy,
    tuf::{MetaListing, RootMeta, Signed, TargetsMeta}};
use enclave_custody_vaultd::ctap::mds::MdsAllowlist;
use serde::Serialize;
use sha2::{Digest, Sha256};

// CAS entry::read_metadata/read_root_chain transport bounds. The narrower
// count/version scope comes from the CURRENT selected target_plan inventory;
// this is not a new CAS authentication or root-rotation policy.
const MAX_METADATA: usize = 4 * 1024 * 1024;
const MAX_ROTATION_BYTES: usize = 16 * 1024 * 1024;
const MAX_INVENTORY_ROTATIONS: usize = 32;
const MAX_INVENTORY_ROOT_VERSION: u64 = 2_147_483_647;
const REQUIRED: [&str; 7] = ["root.json", "timestamp.json", "snapshot.json", "targets.json",
    HOST_CONFIG_TARGET, FIDO_MDS_TARGET, CustodyTarget::EnvelopePolicy.target_name()];

/// Borrowed exact candidate bytes and their claimed inventory binding. There
/// is deliberately no constructor that confers protected-file or trust status.
pub(crate) struct RuntimeTrustInput<'a> {
    pub(crate) source: &'a Path,
    pub(crate) inventory_sha256: &'a str,
    pub(crate) inventory_size: u64,
    pub(crate) bytes: &'a [u8],
}

/// One closed input role; metadata and policy payload routes cannot interchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuntimeInputRole {
    RootCandidate, RootRotation, Timestamp, Snapshot, Targets,
    HostConfiguration, FidoMetadata, EnvelopePolicy,
}

/// A proposed transport destination, never an accepted/publication operation.
#[derive(Debug, Serialize)]
pub(crate) struct RuntimeTrustEntry {
    pub(crate) name: String,
    pub(crate) role: RuntimeInputRole,
    pub(crate) source: PathBuf,
    /// None for root.json: candidate bytes never provision the runtime pin.
    pub(crate) proposed_transport_path: Option<PathBuf>,
    pub(crate) size: u64,
    pub(crate) maximum_bytes: usize,
    pub(crate) sha256: String,
    pub(crate) blake3: String,
    pub(crate) authentication: &'static str,
}

/// Required production verification in dependency order, with actual owners.
#[derive(Debug, Serialize)]
pub(crate) struct RuntimeVerificationStep {
    pub(crate) source: &'static str,
    pub(crate) calls: &'static str,
    pub(crate) requirement: &'static str,
}

/// Read-only report of supplied bytes, closed routes and unmet trust work.
/// Completeness describes inventory presence only; it never grants admission.
#[derive(Serialize)]
pub(crate) struct RuntimeTrustPlan {
    pub(crate) version: u8,
    pub(crate) kind: &'static str,
    pub(crate) target_id: String,
    pub(crate) role: DeploymentRole,
    pub(crate) profile: Profile,
    pub(crate) deployment_config_sha256: String,
    pub(crate) apply_supported: bool,
    pub(crate) readiness: &'static str,
    pub(crate) authentication: &'static str,
    pub(crate) runtime_pin_file: PathBuf,
    pub(crate) runtime_pin_requirement: &'static str,
    pub(crate) repository: PathBuf,
    pub(crate) cas_store: PathBuf,
    pub(crate) cas_state: PathBuf,
    pub(crate) diagnostic_mds_file: PathBuf,
    pub(crate) supplied_inputs_complete: bool,
    pub(crate) missing_required_sources: Vec<PathBuf>,
    pub(crate) inputs: Vec<RuntimeTrustEntry>,
    pub(crate) host_mds_binding: &'static str,
    pub(crate) release_approval_scope: &'static str,
    pub(crate) required_verification: Vec<RuntimeVerificationStep>,
    pub(crate) exclusions: Vec<&'static str>,
}
impl std::fmt::Debug for RuntimeTrustPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeTrustPlan").field("authentication", &self.authentication)
            .field("readiness", &self.readiness).field("apply_supported", &self.apply_supported)
            .field("supplied_inputs_complete", &self.supplied_inputs_complete).finish_non_exhaustive()
    }
}

fn lower_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn overlap(a: &Path, b: &Path) -> EnclaveResult<bool> {
    let key = |path: &Path| -> EnclaveResult<PathBuf> {
        Ok(PathBuf::from(normalized_path(path)?.to_str()
            .ok_or_else(|| err!(EINVAL, "RUNTIME_TRUST_PATH"))?.to_ascii_lowercase()))
    };
    let (a, b) = (key(a)?, key(b)?);
    Ok(a.starts_with(&b) || b.starts_with(&a))
}
fn classify(name: &str) -> EnclaveResult<(RuntimeInputRole, usize, Option<u64>)> {
    use RuntimeInputRole::*;
    let fixed = match name {
        "root.json" => Some((RootCandidate, MAX_METADATA)),
        "timestamp.json" => Some((Timestamp, MAX_METADATA)),
        "snapshot.json" => Some((Snapshot, MAX_METADATA)),
        "targets.json" => Some((Targets, MAX_METADATA)),
        HOST_CONFIG_TARGET => Some((HostConfiguration, MAX_HOST_CONFIG_BYTES)),
        FIDO_MDS_TARGET => Some((FidoMetadata, MAX_MDS_BYTES)),
        value if value == CustodyTarget::EnvelopePolicy.target_name() =>
            Some((EnvelopePolicy, CustodyTarget::EnvelopePolicy.max_bytes())),
        _ => None,
    };
    if let Some((role, maximum)) = fixed { return Ok((role, maximum, None)); }
    if let Some(number) = name.strip_suffix(".root.json") {
        let version = number.parse::<u64>().map_err(|_| err!(EINVAL, "RUNTIME_TRUST_ROOT_NAME"))?;
        if version == 0 || version > MAX_INVENTORY_ROOT_VERSION || number != version.to_string() {
            fail!(EINVAL, "RUNTIME_TRUST_ROOT_NAME");
        }
        return Ok((RootRotation, MAX_METADATA, Some(version)));
    }
    fail!(EINVAL, "RUNTIME_TRUST_UNSUPPORTED_INPUT")
}

// Typed schema/role checks ONLY. A missing/invalid signature, expired role or
// unauthorised signing key is intentionally NOT authenticated by this parser.
fn metadata_shape(role: RuntimeInputRole, bytes: &[u8], numbered: Option<u64>) -> EnclaveResult<()> {
    use RuntimeInputRole::*;
    let parse = || err!(EINVAL, "RUNTIME_TRUST_METADATA_SCHEMA");
    let (actual, expected, version) = match role {
        RootCandidate | RootRotation => {
            let value: Signed<RootMeta> = serde_json::from_slice(bytes).map_err(|_| parse())?;
            (value.signed._type, "root", value.signed.version)
        }
        Timestamp | Snapshot => {
            let value: Signed<MetaListing> = serde_json::from_slice(bytes).map_err(|_| parse())?;
            (value.signed._type, if role == Timestamp { "timestamp" } else { "snapshot" }, value.signed.version)
        }
        Targets => {
            let value: Signed<TargetsMeta> = serde_json::from_slice(bytes).map_err(|_| parse())?;
            (value.signed._type, "targets", value.signed.version)
        }
        _ => return Ok(()),
    };
    if actual != expected || version == 0 || numbered.is_some_and(|n| n != version) {
        fail!(EINVAL, "RUNTIME_TRUST_METADATA_ROLE");
    }
    Ok(())
}

/// Describe only the first-custody input subset supplied by a future protected
/// importer. The caller retains held source FDs and must later run the genuine
/// consumers below. This pure function never reads the paths it reports. Its
/// schema/profile/hash consistency checks authenticate none of those inputs.
pub(crate) fn describe(target: &DeploymentTarget, descriptor_sha256: &str,
    entries: &[RuntimeTrustInput<'_>]) -> EnclaveResult<RuntimeTrustPlan> {
    target.validate()?;
    if !lower_digest(descriptor_sha256) { fail!(EINVAL, "RUNTIME_TRUST_DESCRIPTOR_DIGEST"); }
    if entries.len() > REQUIRED.len() + MAX_INVENTORY_ROTATIONS { fail!(E2BIG, "RUNTIME_TRUST_INPUT_COUNT"); }
    let layout = &target.layout;
    let pin = target.broker.as_ref().map(|b| b.tuf_root_file.clone())
        .unwrap_or_else(|| layout.support_root.join("tuf/root.json"));
    // The L2 pin route is implicit in the actual launchd renderer, so the
    // descriptor validator alone cannot detect aliases with its other inputs.
    for other in [&target.authority_config, &target.expected_artifacts_manifest,
        &target.codesign_pins_file, &layout.custody_bundle, &layout.binary_dir,
        &layout.sandbox_dir, &layout.socket_root, &layout.state_root, &layout.audit_root,
        &layout.cas_store_root, &layout.staging_root] {
        if overlap(&pin, other)? { fail!(EINVAL, "RUNTIME_TRUST_PIN_COLLISION"); }
    }
    // These existing fixed support roles are implicit in their real consumers,
    // rather than independent fields checked by DeploymentTarget::validate.
    // A configured L3 pin cannot adopt a control file, diagnostic or helper
    // configuration/bundle route as if it were the independent runtime root.
    for other in [layout.support_root.join(STARTUP_LIFETIME_LEAF),
        layout.support_root.join(UPGRADE_INHIBITION_LEAF),
        layout.support_root.join("fido-mds.json"),
        layout.support_root.join("oidc-broker-identity.json"),
        layout.support_root.join("oidc-oauth.json"),
        layout.support_root.join("EnclaveOIDC.app")] {
        if overlap(&pin, &other)? { fail!(EINVAL, "RUNTIME_TRUST_PIN_COLLISION"); }
    }
    let repository = layout.state_root.join("cas/tuf/repo");
    // Match the actual inventory planner's fixed OS-alias routing. This is
    // lexical normalization only; no filesystem alias or source is opened.
    let staging = normalized_path(&layout.staging_root)?.join("tuf/repo");
    let mut inputs = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut rotations = 0;
    let mut rotation_bytes = 0usize;
    let mut host = None;
    let mut mds_digest = None;
    for input in entries {
        // Compare supported OS aliases consistently while retaining the exact
        // supplied source spelling in the unverified report below.
        let source = normalized_path(input.source)?;
        let name = source.strip_prefix(&staging).ok().and_then(|p| p.to_str())
            .filter(|name| !name.is_empty() && !name.contains('/'))
            .ok_or_else(|| err!(EINVAL, "RUNTIME_TRUST_SOURCE_ROUTE"))?;
        let (role, maximum, numbered) = classify(name)?;
        if !seen.insert(name.to_ascii_lowercase()) { fail!(EINVAL, "RUNTIME_TRUST_DUPLICATE_INPUT"); }
        if input.bytes.is_empty() || input.bytes.len() > maximum {
            fail!(E2BIG, "RUNTIME_TRUST_INPUT_SIZE");
        }
        let sha256 = hex::encode(Sha256::digest(input.bytes));
        if !lower_digest(input.inventory_sha256) || input.inventory_size != input.bytes.len() as u64
            || input.inventory_sha256 != sha256 { fail!(EINVAL, "RUNTIME_TRUST_INVENTORY_BINDING"); }
        let blake3 = blake3::hash(input.bytes).to_hex().to_string();
        if role == RuntimeInputRole::RootRotation {
            rotations += 1;
            rotation_bytes = rotation_bytes.checked_add(input.bytes.len())
                .ok_or_else(|| err!(E2BIG, "RUNTIME_TRUST_ROOT_CHAIN_LIMIT"))?;
            if rotations > MAX_INVENTORY_ROTATIONS || rotation_bytes > MAX_ROTATION_BYTES {
                fail!(E2BIG, "RUNTIME_TRUST_ROOT_CHAIN_LIMIT");
            }
        }
        metadata_shape(role, input.bytes, numbered)?;
        match role {
            RuntimeInputRole::HostConfiguration => {
                let config = EnclaveHostConfig::from_json_bytes(input.bytes)?;
                config.admit_profile(target.profile)?;
                host = Some(config);
            }
            RuntimeInputRole::FidoMetadata => {
                // Parse the actual schema without fabricating MdsState refresh
                // timestamps, expiry, attestation approval or live-device facts.
                let _: MdsAllowlist = serde_json::from_slice(input.bytes)
                    .map_err(|_| err!(EINVAL, "RUNTIME_TRUST_MDS_SCHEMA"))?;
                mds_digest = Some(blake3.clone());
            }
            RuntimeInputRole::EnvelopePolicy => {
                let policy: SignedEnvelopePolicy = serde_json::from_slice(input.bytes)
                    .map_err(|_| err!(EINVAL, "RUNTIME_TRUST_ENVELOPE_SCHEMA"))?;
                if !policy.policy.profiles.contains(&target.profile) {
                    fail!(EINVAL, "RUNTIME_TRUST_ENVELOPE_PROFILE");
                }
            }
            _ => {},
        }
        let proposed_transport_path = match role {
            RuntimeInputRole::RootCandidate => None,
            RuntimeInputRole::HostConfiguration | RuntimeInputRole::FidoMetadata | RuntimeInputRole::EnvelopePolicy =>
                Some(layout.cas_store_root.join(name)),
            _ => Some(repository.join(name)),
        };
        inputs.insert(name.to_owned(), RuntimeTrustEntry { name: name.into(), role,
            source: input.source.to_owned(), proposed_transport_path, size: input.inventory_size,
            maximum_bytes: maximum, sha256, blake3, authentication: "UNVERIFIED" });
    }
    let host_mds_binding = match (&host, &mds_digest) {
        (Some(host), Some(mds)) => {
            if host.fido_mds_allowlist_digest != *mds { fail!(EINVAL, "RUNTIME_TRUST_MDS_CONFIG_DIGEST"); }
            "MATCHES_UNAUTHENTICATED_BYTES"
        }
        _ => "MISSING_INPUTS_UNVERIFIED",
    };
    let missing_required_sources: Vec<_> = REQUIRED.into_iter().filter(|name| !inputs.contains_key(*name))
        .map(|name| staging.join(name)).collect();
    Ok(RuntimeTrustPlan { version: 1, kind: "mcpmac-runtime-trust-input-plan",
        target_id: target.target_id.clone(), role: target.role, profile: target.profile,
        deployment_config_sha256: descriptor_sha256.into(), apply_supported: false,
        readiness: "NOT_QUALIFIED", authentication: "UNVERIFIED", runtime_pin_file: pin,
        runtime_pin_requirement: "independently_provisioned_runtime_purpose_pin_never_copied_from_candidate_root_json",
        repository, cas_store: layout.cas_store_root.clone(), cas_state: layout.state_root.join("cas"),
        diagnostic_mds_file: layout.support_root.join("fido-mds.json"),
        supplied_inputs_complete: missing_required_sources.is_empty(), missing_required_sources,
        inputs: inputs.into_values().collect(), host_mds_binding,
        release_approval_scope: "software_release_only_never_runtime_root_or_policy_authority",
        required_verification: verification_steps(), exclusions: vec![
            "no_input_is_authenticated_or_approved_by_this_report_even_when_complete",
            "no_file_read_copy_pin_provisioning_cas_import_trust_store_open_or_service_start",
            "diagnostic_mds_file_cannot_replace_authenticated_fido_mds_allowlist_target",
            "existing_canonical_cas_objects_take_precedence_over_loose_payloads_and_require_real_verification",
            "no_existing_tuf_rollback_clock_policy_enrollment_counter_or_consumption_state_reset_or_restore",
            "calibration_vk_mcp_lock_cedar_oidc_broker_l3_broker_and_other_runtime_contracts_require_separate_closure",
            "no_attestation_device_factor_ceremony_profile_or_installed_readiness_qualification",
        ] })
}

fn verification_steps() -> Vec<RuntimeVerificationStep> {
    vec![
        RuntimeVerificationStep { source: "crates/enclave-swarm-syncd/src/service.rs",
            calls: "CasService::start; SealedStore::open_required; TufClient::restore/chain_contains/bootstrap; TrustedClock",
            requirement: "independent runtime pin and genuine protected CAS state; restore existing anchor/version/clock floors; bootstrap only actual fresh state; never learn a pin from staging or release approval" },
        RuntimeVerificationStep { source: "crates/enclave-swarm-syncd/src/entry.rs; crates/enclave-swarm-syncd/src/service.rs",
            calls: "read_root_chain; validate_initial_tuf_refresh; CasRequest::TufRefresh; TufClient::update_root/refresh",
            requirement: "read exact protected repository metadata; verify consecutive dual-signed rotations and complete four-role signatures/hashes/freshness/rollback; enforce revocations and durably persist through existing release fence before serving" },
        RuntimeVerificationStep { source: "crates/enclave-swarm-syncd/src/config.rs; crates/enclave-core/src/host_config.rs",
            calls: "get_host_config; get_target_bytes_with_limit; TufClient::verify_target; EnclaveHostConfig::admit_profile",
            requirement: "real CAS target length/SHA256/BLAKE3 and revocation checks; canonical object precedence; authenticated host profile floor; no local-JSON authority" },
        RuntimeVerificationStep { source: "crates/enclave-swarm-syncd/src/service.rs; crates/enclave-custody-vaultd/src/metadata_source.rs",
            calls: "FetchCustodyMetadata; CustodyMetadataSource::fetch; CustodyMetadataReceipt::validate; MdsState::from_verified_target_with_expiry",
            requirement: "authenticated UID702/code identity channel to UID703; exact hostconfig BLAKE3 binding; complete chain expiry and actual captured refresh age strictly below 24hL3/72hL2; no invented refresh time or diagnostic-file substitute" },
        RuntimeVerificationStep { source: "crates/enclave-custody-vaultd/src/provisioning.rs; crates/enclave-custody-vaultd/src/metadata_source.rs",
            calls: "CustodyProvisioning::load/revalidate/authorities; FetchCustodyTarget(EnvelopePolicy); envelope_context; SignedEnvelopePolicy::verify",
            requirement: "genuine independent issuer/subject/namespace; reject model-target roles; authenticate CAS receipt and independent signature/scope/review/expiry; retain earliest chain/profile-age/policy bounds and boot deadline; persist actual policy floors in custody owner" },
    ]
}

#[cfg(test)]
#[path = "target_runtime_trust_tests.rs"]
mod tests;
