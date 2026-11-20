//! Inert, source-bound target installation reports. Nothing in this module
//! installs files, executes staged programs, changes ownership or grants trust.

use std::{collections::{BTreeMap, BTreeSet}, path::{Component, Path, PathBuf}};
use enclave_core::{daemon::{self, DaemonId}, deployment::{CheckedDeploymentTarget,
    DeploymentRole, DeploymentSigningMode, DeploymentTarget, normalized_path},
    error::EnclaveResult, err, fail, Profile};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_INVENTORY: usize = 1024 * 1024;
const BINARIES: &[&str] = &["mcp-enclave", "enclave-model-runnerd", "enclave-swarm-syncd",
    "enclave-apfs-broker", "enclave-agent-runtime", "enclave-zk-auditor", "enclave-cdp-browser",
    "enclave-client-gateway", "enclave-intent"];
const JOBS: &[&str] = &["adapter", "cas", "custody", "ifc", "zk", "supervisor", "intent",
    "oidc-broker", "hydrate", "browser", "gateway", "apfs-broker"];
const SANDBOXES: &[&str] = &["adapter", "cas", "custody", "ifc", "zk", "browser", "gateway"];
const PUBLIC_TUF: &[&str] = &["root.json", "timestamp.json", "snapshot.json", "targets.json",
    "enclave-host-config.json", "enclave-policy.cedar.v1.json", "vk_manifest.json", "enclave-distribution-v1.json"];
// Candidate transport only. These runtime inputs need independent CAS/issuer
// authentication and never receive a public-payload destination here.
const CUSTODY_TUF: &[&str] = &[enclave_core::custody_metadata::FIDO_MDS_TARGET,
    enclave_core::custody_metadata::CustodyTarget::EnvelopePolicy.target_name()];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    version: u8, kind: String, target_id: String, profile: Profile,
    signing_identity_mode: DeploymentSigningMode, deployment_config_sha256: String,
    source_git_commit: String, source_manifest_sha256: String, source_input_count: u32,
    codesign_pins_sha256: String, staging_root: PathBuf, external_provenance: String,
    files: Vec<InventoryFile>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryFile { path: String, sha256: String, size: u64 }

/// Proposed public payload copy. This is a report, never an executable action.
#[derive(Debug, Serialize)]
pub struct CopyEntry {
    /// Exact selected staging file.
    pub source: PathBuf,
    /// Destination derived from the fixed packaging map and descriptor.
    pub destination: PathBuf,
    /// Exact candidate bytes; must be rehashed under held FDs before any apply.
    pub sha256: String,
    /// Expected byte length.
    pub size: u64,
    /// Files remain root owned, irrespective of daemon runtime account.
    pub uid: u32,
    /// macOS wheel GID.
    pub gid: u32,
    /// Explicit octal file mode.
    pub mode: String,
    /// Replacement constraints; no copy has occurred.
    pub condition: &'static str,
}
/// Proposed directory metadata; existing directories must be verified without
/// recursive chmod/chown or changes to their contents.
#[derive(Debug, Serialize)]
pub struct DirectoryEntry {
    /// Exact directory path.
    pub path: PathBuf,
    /// Expected owner UID.
    pub uid: u32,
    /// Expected group GID.
    pub gid: u32,
    /// Octal directory mode.
    pub mode: String,
    /// No repair of existing state is authorized by this report.
    pub condition: &'static str,
}
/// A candidate item deliberately retained in staging for separate validation.
#[derive(Debug, Serialize)]
pub struct RetainedEntry {
    /// Exact selected staging file.
    pub source: PathBuf,
    /// Observed candidate digest.
    pub sha256: String,
    /// Observed byte length.
    pub size: u64,
    /// Why this file has no installed destination in this report.
    pub reason: &'static str,
}
/// Machine-readable report. A successful report is not installation approval,
/// a code-signature check, source attestation or profile qualification.
#[derive(Serialize)]
pub struct TargetInstallPlan {
    /// Report version.
    pub version: u8,
    /// Fixed report discriminator.
    pub kind: &'static str,
    /// Selected local target.
    pub target_id: String,
    /// Target deployment purpose.
    pub role: DeploymentRole,
    /// Target profile.
    pub profile: Profile,
    /// Always false: selected-target apply remains unavailable.
    pub apply_supported: bool,
    /// Always NOT_QUALIFIED.
    pub readiness: &'static str,
    /// Exact descriptor digest recorded by the protected loader.
    pub deployment_config_sha256: String,
    /// Exact protected inventory byte digest.
    pub artifact_inventory_sha256: String,
    /// Observed source revision, not independently attested provenance.
    pub source_git_commit: String,
    /// Exact observed snapshot digest.
    pub source_manifest_sha256: String,
    /// Snapshot input count from the bounded inventory.
    pub source_input_count: u32,
    /// UNKNOWN until supplied through independent release authority.
    pub external_provenance: String,
    /// Final selected pin destination; preparation never overwrites it.
    pub selected_pins_file: PathBuf,
    /// Candidate pin bytes required at the future cutover.
    pub candidate_codesign_pins_sha256: String,
    /// Fixed proposed copies with exact ownership and modes.
    pub copies: Vec<CopyEntry>,
    /// Create-if-absent, verify-if-present metadata only.
    pub directories: Vec<DirectoryEntry>,
    /// Candidate tooling and trust data needing separate acceptance.
    pub retained_in_staging: Vec<RetainedEntry>,
    /// Missing required public packaging files, not silently considered ready.
    pub missing_required_files: Vec<String>,
    /// Existing stores that must never be reset, restored or overwritten.
    pub preserved_roots: Vec<PathBuf>,
    /// Required checks/actions which this report has not performed.
    pub prerequisites: Vec<&'static str>,
}
impl std::fmt::Debug for TargetInstallPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TargetInstallPlan").field("apply_supported",&self.apply_supported)
            .field("readiness",&self.readiness).finish_non_exhaustive()
    }
}

fn digest(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn relative(path: &str) -> bool {
    !path.is_empty() && path.len() <= 4096 && path.is_ascii()
        && !path.bytes().any(|b| b.is_ascii_control() || b"'\"`$;&|<>()\\".contains(&b))
        && Path::new(path).components().all(|p| matches!(p, Component::Normal(_)))
        && Path::new(path).components().collect::<PathBuf>().as_os_str() == path
}
fn overlaps(a: &Path, b: &Path) -> EnclaveResult<bool> {
    // Configured paths are ASCII; compare conservatively for common macOS
    // case-insensitive volumes while preserving every actual routed spelling.
    let a=PathBuf::from(normalized_path(a)?.to_str().ok_or_else(||err!(EINVAL,"DEPLOYMENT_PATH"))?.to_ascii_lowercase());
    let b=PathBuf::from(normalized_path(b)?.to_str().ok_or_else(||err!(EINVAL,"DEPLOYMENT_PATH"))?.to_ascii_lowercase());
    Ok(a.starts_with(&b) || b.starts_with(&a))
}
fn bundle_file(path: &str) -> Option<(&str, &str)> {
    for (bundle, binary) in [("EnclaveCustody.app", "enclave-custody-vaultd"), ("EnclaveOIDC.app", "enclave-oidc")] {
        if let Some(suffix) = path.strip_prefix(&format!("{bundle}/")) {
            if ["Contents/Info.plist", "Contents/PkgInfo", "Contents/embedded.provisionprofile",
                "Contents/_CodeSignature/CodeResources"].contains(&suffix)
                || suffix == format!("Contents/MacOS/{binary}") { return Some((bundle,suffix)); }
        }
    }
    None
}
fn public_tuf(path: &str) -> bool {
    let Some(name) = path.strip_prefix("tuf/repo/") else {return false};
    if PUBLIC_TUF.contains(&name)||CUSTODY_TUF.contains(&name) {return true;}
    name.strip_suffix(".root.json").is_some_and(|v| !v.is_empty() && !v.starts_with('0')
        && v.bytes().all(|b| b.is_ascii_digit()) && v.parse::<u32>().is_ok_and(|n| n <= 2_147_483_647))
}
fn required(target: &DeploymentTarget) -> BTreeSet<String> {
    let mut files = BTreeSet::new();
    for name in BINARIES {files.insert(format!("bin/{name}"));}
    for (bundle,binary) in [("EnclaveCustody.app","enclave-custody-vaultd"),("EnclaveOIDC.app","enclave-oidc")] {
        for suffix in ["Contents/Info.plist".to_owned(), "Contents/_CodeSignature/CodeResources".into(),
            format!("Contents/MacOS/{binary}")] {files.insert(format!("{bundle}/{suffix}"));}
    }
    for name in SANDBOXES {files.insert(format!("launchd/{name}.sb"));}
    for name in JOBS {
        if *name != "apfs-broker" || target.profile == Profile::L3 {
            files.insert(format!("launchd/{}.{name}.plist",target.layout.launchd_namespace));
        }
    }
    for name in ["codesign-pins.json","SHA256SUMS","custody.entitlements","yubikey-transport",
        "install.sh","uninstall.sh","public-trust.sh","fido-mds/yubico.json",
        "launchd/provision-accounts.sh","launchd/enclave-daemon.entitlements"] {files.insert(name.into());}
    for name in PUBLIC_TUF {files.insert(format!("tuf/repo/{name}"));}
    if target.profile!=Profile::L1 {
        for name in CUSTODY_TUF {files.insert(format!("tuf/repo/{name}"));}
    }
    files
}

/// Describe an already observed inventory against exact descriptor bytes. This
/// pure function reads no paths and grants no authority. Call [`prepare`] for
/// the protected selected-context CLI path. External provenance stays UNKNOWN.
pub fn describe(target: &DeploymentTarget, descriptor_sha256: &str, raw: &[u8]) -> EnclaveResult<TargetInstallPlan> {
    target.validate()?;
    if raw.is_empty() || raw.len() > MAX_INVENTORY {fail!(E2BIG,"DEPLOYMENT_INVENTORY_SCHEMA");}
    let inventory: Inventory = serde_json::from_slice(raw).map_err(|_|err!(EINVAL,"DEPLOYMENT_INVENTORY_SCHEMA"))?;
    if inventory.version != 1 || inventory.kind != "mcpmac-first-touch-artifact-inventory"
        || inventory.target_id != target.target_id || inventory.profile != target.profile
        || inventory.signing_identity_mode != target.signing_identity_mode
        || !digest(descriptor_sha256,64) || inventory.deployment_config_sha256 != descriptor_sha256
        || !digest(&inventory.source_git_commit,40) || !digest(&inventory.source_manifest_sha256,64)
        || !digest(&inventory.codesign_pins_sha256,64) || inventory.source_input_count == 0
        || inventory.source_input_count > 100_000 || inventory.external_provenance != "UNKNOWN"
        || inventory.staging_root != normalized_path(&target.layout.staging_root)?
        || inventory.files.is_empty() || inventory.files.len() > 4096 {
        fail!(EINVAL,"DEPLOYMENT_INVENTORY_CONTEXT");
    }
    let mut copies = Vec::new(); let mut retained = Vec::new();
    let mut seen = BTreeSet::new(); let mut previous: Option<&str> = None;
    let mut roots = 0;
    for file in &inventory.files {
        if !relative(&file.path) || !digest(&file.sha256,64) || file.size > 512*1024*1024
            || previous.is_some_and(|p| p >= file.path.as_str()) || !seen.insert(file.path.to_ascii_lowercase()) {
            fail!(EINVAL,"DEPLOYMENT_INVENTORY_FILE");
        }
        previous = Some(&file.path);
        let source = inventory.staging_root.join(&file.path);
        let mut mode = "0644"; let mut condition = "after_verified_quiescence_and_authorized_apply";
        let destination = if file.path == "codesign-pins.json" {
            if file.sha256 != inventory.codesign_pins_sha256 || file.size == 0 || file.size > MAX_INVENTORY as u64 {
                fail!(EINVAL,"DEPLOYMENT_INVENTORY_PINS");
            }
            condition = "atomic_final_cutover_only_after_exact_candidate_hash_and_identity_verification";
            Some(target.codesign_pins_file.clone())
        } else if let Some(binary) = file.path.strip_prefix("bin/").filter(|n| BINARIES.contains(n)) {
            mode = "0755"; Some(target.layout.binary_dir.join(binary))
        } else if let Some((bundle,suffix)) = bundle_file(&file.path) {
            if suffix.starts_with("Contents/MacOS/") {mode = "0755";}
            Some(if bundle == "EnclaveCustody.app" {target.layout.custody_bundle.join(suffix)}
                else {target.layout.support_root.join(bundle).join(suffix)})
        } else if file.path == "fido-mds/yubico.json" {
            if file.size > 16*1024*1024 {fail!(EINVAL,"DEPLOYMENT_INVENTORY_FILE");}
            Some(target.layout.support_root.join("fido-mds.json"))
        } else if let Some(name) = file.path.strip_prefix("launchd/") {
            if SANDBOXES.iter().any(|n| name == format!("{n}.sb")) {Some(target.layout.sandbox_dir.join(name))}
            else if let Some(job) = JOBS.iter().find(|n| name == format!("{}.{n}.plist",target.layout.launchd_namespace)) {
                if *job == "apfs-broker" && target.profile != Profile::L3 {fail!(EINVAL,"DEPLOYMENT_PLAN_PROFILE");}
                Some(Path::new(if ["intent","oidc-broker"].contains(job) {"/Library/LaunchAgents"}
                    else {"/Library/LaunchDaemons"}).join(name))
            } else if ["provision-accounts.sh","enclave-daemon.entitlements"].contains(&name) {None}
            else {fail!(EINVAL,"DEPLOYMENT_PLAN_UNSUPPORTED_FILE");}
        } else if public_tuf(&file.path) {
            if file.size == 0 || file.size > 16*1024*1024 {fail!(EINVAL,"DEPLOYMENT_INVENTORY_FILE");}
            let name=file.path.strip_prefix("tuf/repo/").expect("validated public TUF path");
            let maximum=if name==enclave_core::custody_metadata::FIDO_MDS_TARGET {
                enclave_core::custody_metadata::MAX_MDS_BYTES
            }else if name==enclave_core::custody_metadata::CustodyTarget::EnvelopePolicy.target_name() {
                enclave_core::custody_metadata::CustodyTarget::EnvelopePolicy.max_bytes()
            }else {16*1024*1024};
            if file.size>maximum as u64 {fail!(EINVAL,"DEPLOYMENT_INVENTORY_FILE");}
            if file.path.ends_with(".root.json") {roots+=1;}
            None
        } else if ["SHA256SUMS","custody.entitlements","yubikey-transport","install.sh","uninstall.sh","public-trust.sh"].contains(&file.path.as_str()) {
            None
        } else {fail!(EINVAL,"DEPLOYMENT_PLAN_UNSUPPORTED_FILE");};
        if let Some(destination) = destination {
            if file.size == 0 {fail!(EINVAL,"DEPLOYMENT_INVENTORY_FILE");}
            for root in [&target.layout.socket_root,&target.layout.state_root,&target.layout.audit_root,
                &target.layout.cas_store_root,&target.layout.staging_root] {
                if overlaps(&destination,root)? {fail!(EINVAL,"DEPLOYMENT_PLAN_STATE_COLLISION");}
            }
            for input in [&target.authority_config, &target.expected_artifacts_manifest] {
                if overlaps(&destination,input)? {fail!(EINVAL,"DEPLOYMENT_PLAN_INPUT_COLLISION");}
            }
            if let Some(broker) = &target.broker {
                if overlaps(&destination,&broker.tuf_root_file)? {fail!(EINVAL,"DEPLOYMENT_PLAN_INPUT_COLLISION");}
            }
            if file.path != "codesign-pins.json" && overlaps(&destination,&target.codesign_pins_file)? {
                fail!(EINVAL,"DEPLOYMENT_PLAN_INPUT_COLLISION");
            }
            for old in &copies {
                let old: &CopyEntry = old;
                if overlaps(&old.destination,&destination)? {fail!(EINVAL,"DEPLOYMENT_PLAN_DESTINATION_COLLISION");}
            }
            copies.push(CopyEntry {source,destination,sha256:file.sha256.clone(),size:file.size,
                uid:0,gid:0,mode:mode.into(),condition});
        } else {
            retained.push(RetainedEntry {source,sha256:file.sha256.clone(),size:file.size,
                reason:if public_tuf(&file.path) {"requires_independent_tuf_authority_freshness_floors_and_state_preserving_migration"}
                    else {"packaging_input_only_never_execute_legacy_installer_for_selected_target"}});
        }
    }
    if roots > 32 || !seen.contains("codesign-pins.json") || !seen.contains("bin/mcp-enclave") {
        fail!(EINVAL,"DEPLOYMENT_INVENTORY_REQUIRED");
    }
    let missing_required_files = required(target).difference(&inventory.files.iter().map(|f|f.path.clone()).collect())
        .cloned().collect();
    let mut directories = BTreeMap::new();
    for copy in &copies {
        let mut directory = copy.destination.parent();
        // Public bundle subdirectories are fixed by the packaging map. All
        // existing ancestors still require held-FD protection at future apply.
        while let Some(path) = directory {
            if path == Path::new("/") {break;}
            directories.entry(normalized_path(path)?).or_insert((0,0,"0755"));
            directory = path.parent();
        }
    }
    for root in [&target.layout.socket_root,&target.layout.state_root,&target.layout.audit_root] {
        directories.insert(normalized_path(root)?,(0,0,"0755"));
    }
    for d in DaemonId::ALL {
        directories.insert(normalized_path(&target.layout.socket_root.join(d.dir_name()))?,(d.uid(),d.client_gid(),"2750"));
        directories.insert(normalized_path(&target.layout.state_root.join(d.dir_name()))?,(d.uid(),d.gid(),"0700"));
        directories.insert(normalized_path(&target.layout.audit_root.join(d.dir_name()))?,(d.uid(),crate::launchd::JOURNAL_READ_GID,"2750"));
    }
    directories.insert(normalized_path(&target.layout.cas_store_root)?,(702,8702,"0700"));
    for (suffix,uid,gid,mode) in [
        ("supervisor",0,enclave_core::supervisor::CLIENT_GID,"2750"),
        ("intent",0,0,"0755"),("oidc",0,0,"0755"),
        (crate::launchd::BROWSER_SOCKET_DIR,daemon::BROWSER_UID,daemon::BROWSER_CLIENT_GID,"2750"),
        (daemon::GATEWAY_SOCKET_DIR,daemon::GATEWAY_UID,daemon::GATEWAY_GID,"0755"),
        (daemon::WITNESS_SOCKET_DIR,705,daemon::WITNESS_CLIENT_GID,"2750"),
        ("jobs",702,8702,"0700")] {
        directories.insert(normalized_path(&target.layout.socket_root.join(suffix))?,(uid,gid,mode));
    }
    for (suffix,uid,gid) in [("browser",daemon::BROWSER_UID,daemon::BROWSER_GID),
        ("gateway",daemon::GATEWAY_UID,daemon::GATEWAY_GID)] {
        if suffix == "browser" {directories.insert(normalized_path(&target.layout.state_root.join(suffix))?,(uid,gid,"0700"));}
        directories.insert(normalized_path(&target.layout.audit_root.join(suffix))?,(uid,gid,"0700"));
    }
    if let Some(broker) = &target.broker {
        for path in [broker.base_dir.clone(),broker.base_dir.join("state"),broker.base_dir.join("tuf"),
            broker.base_dir.join("tuf/repo"),target.layout.audit_root.join("apfs-broker")] {
            directories.insert(normalized_path(&path)?,(0,0,"0700"));
        }
        directories.insert(normalized_path(&target.layout.socket_root.join("apfs-broker"))?,(0,8702,"2750"));
    }
    let mut unique_directories = BTreeMap::<String,DirectoryEntry>::new();
    for (path,(uid,gid,mode)) in directories {
        let key=path.to_str().ok_or_else(||err!(EINVAL,"DEPLOYMENT_PATH"))?.to_ascii_lowercase();
        if let Some(old)=unique_directories.get(&key) {
            if old.uid!=uid || old.gid!=gid || old.mode!=mode {fail!(EINVAL,"DEPLOYMENT_PLAN_DIRECTORY_COLLISION");}
            continue;
        }
        unique_directories.insert(key,DirectoryEntry {path,uid,gid,mode:mode.into(),
            condition:"create_if_absent_verify_if_present_never_recursive_repair"});
    }
    let directories=unique_directories.into_values().collect();
    Ok(TargetInstallPlan {version:1,kind:"mcpmac-target-installation-plan",target_id:target.target_id.clone(),
        role:target.role,profile:target.profile,apply_supported:false,readiness:"NOT_QUALIFIED",
        deployment_config_sha256:descriptor_sha256.into(),artifact_inventory_sha256:hex::encode(Sha256::digest(raw)),
        source_git_commit:inventory.source_git_commit,source_manifest_sha256:inventory.source_manifest_sha256,
        source_input_count:inventory.source_input_count,external_provenance:inventory.external_provenance,
        selected_pins_file:target.codesign_pins_file.clone(),candidate_codesign_pins_sha256:inventory.codesign_pins_sha256,
        copies,directories,retained_in_staging:retained,missing_required_files,
        preserved_roots:vec![target.layout.state_root.clone(),target.layout.audit_root.clone(),target.layout.cas_store_root.clone()],
        prerequisites:vec!["selected_target_apply_is_not_implemented_or_authorized_by_this_report",
            "rehash_every_staged_file_and_descriptor_under_held_nofollow_fds_at_apply_time",
            "independent_release_provenance_and_native_signature_identifiers_entitlements_and_candidate_pins_verification",
            "complete_payload_and_exact_target_renderer_parity_no_default_paths_or_emulator_fallback",
            "authorized_mac_host_preflight_accounts_groups_and_fixed_uid_collision_checks",
            "native_live_console_uid_audit_session_and_per_login_helper_directories_are_not_inferred_from_json",
            "quiesce_exact_target_system_and_all_live_console_jobs_and_broker_before_replacing_payload",
            "preserve_enrollment_counters_policy_and_tuf_floors_consumed_grants_keys_wrappers_and_ciphertexts",
            "no_private_key_restore_old_lease_revival_or_recursive_state_chown_chmod",
            "independent_public_authorities_tuf_validation_and_state_preserving_migration_before_trust_publication",
            "target_aware_grant_key_oidc_session_pf_and_lifecycle_paths_require_implementation_and_verification",
            "atomic_pin_cutover_must_hash_match_candidate_without_old_new_union_or_default_fallback",
            "failure_stops_new_jobs_preserves_pf_and_durable_state_no_automatic_old_payload_state_restore",
            "distinct_uid_installed_identity_btm_seatbelt_and_physical_factor_acceptance_remain_open"]})
}

/// Read the selected protected inventory and emit an inert report. The shared
/// core owns all protected-path reads; no walker is duplicated here.
pub fn prepare(checked: &CheckedDeploymentTarget) -> EnclaveResult<TargetInstallPlan> {
    let raw = checked.read_artifact_inventory()?;
    let plan = describe(checked.target(),checked.descriptor_sha256(),&raw)?;
    for copy in &plan.copies {
        if overlaps(&copy.destination,checked.config_path())? {fail!(EINVAL,"DEPLOYMENT_PLAN_INPUT_COLLISION");}
    }
    Ok(plan)
}
