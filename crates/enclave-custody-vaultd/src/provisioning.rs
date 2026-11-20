//! Root-provisioned public inputs for genuine native single-key setup.
//!
//! This module reads configuration and verifies the existing independent asset
//! policy. It never opens SEP/HID, connects IPC, initializes sealed state, issues
//! a receipt, or creates an issuer. Envelope authority still requires the live
//! authenticated CAS/TUF context at the existing activation boundary.

use std::{collections::BTreeSet, ffi::CString, fs::File, io::Read,
    os::{fd::{AsRawFd, FromRawFd}, unix::{ffi::OsStrExt, fs::MetadataExt}},
    path::{Component, Path, PathBuf}};
use ed25519_dalek::VerifyingKey;
use enclave_core::{err, fail, error::EnclaveResult, profile::Profile, runtime::DaemonArgs};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::{ctap::asset_enrollment::SignedAssetEnrollmentPolicy,
    metadata_source::EnvelopeAuthorityConfig, service::AssetEnrollmentAuthority};

/// Existing direct arguments cannot be combined with a protected manifest.
pub const LEGACY_AUTHORITY_ARGUMENTS: [&str; 9] = [
    "asset-policy-file", "asset-policy-key-file", "asset-inventory-key-file",
    "asset-host-id", "asset-id", "asset-custodian-id", "envelope-policy-key-file",
    "envelope-policy-subject", "envelope-policy-namespace",
];
const MAX_CONFIG: usize = 16 * 1024;

// No Serialize/Debug implementation: these public authority inputs can contain
// linkable inventory scope. Only hashes from ProvisioningReceipt are exported.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    v: u8,
    profile: Profile,
    asset_policy_file: PathBuf,
    asset_policy_key_file: PathBuf,
    asset_inventory_key_file: PathBuf,
    asset_host_id: String,
    asset_id: String,
    asset_custodian_id: String,
    envelope_policy_key_file: PathBuf,
    envelope_policy_subject: String,
    envelope_policy_namespace: String,
}

/// Syntactically checked public-file references from an untrusted manifest.
///
/// This contains paths only, never checked provisioning or issuer authority.
/// No file has been opened, and neither file identity nor path isolation has
/// been established. Callers must enforce their own destination boundaries.
/// No Debug/Serialize implementation exports linkable configuration paths.
pub struct CustodyManifestInputPaths {
    asset_policy_file: PathBuf,
    asset_policy_key_file: PathBuf,
    asset_inventory_key_file: PathBuf,
    envelope_policy_key_file: PathBuf,
}

impl CustodyManifestInputPaths {
    /// Independently signed asset enrollment policy file.
    pub fn asset_policy_file(&self) -> &Path { &self.asset_policy_file }
    /// Public issuer key for the signed asset enrollment policy.
    pub fn asset_policy_key_file(&self) -> &Path { &self.asset_policy_key_file }
    /// Public issuer key for independent asset inventory evidence.
    pub fn asset_inventory_key_file(&self) -> &Path { &self.asset_inventory_key_file }
    /// Public issuer key for envelope policy evidence.
    pub fn envelope_policy_key_file(&self) -> &Path { &self.envelope_policy_key_file }
}

/// Parse bounded inert manifest bytes using the actual provisioning parser.
///
/// Checks the existing closed schema, exact supported profile, scope syntax
/// and four path syntaxes, including the platform's existing path aliases.
/// Does not read files, verify a policy/key, select a deployment or construct
/// checked authority. Repeated paths retain the existing parser's behavior;
/// importers must separately reject aliases and enforce destination isolation.
pub fn manifest_input_paths(raw: &[u8], profile: Profile) -> EnclaveResult<CustodyManifestInputPaths> {
    Manifest::parse(raw, profile).map(|(_, paths)| paths)
}

/// Non-secret identity of configuration actually read and checked. It does not
/// certify live metadata, physical asset enrollment, factors or installed use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProvisioningReceipt {
    /// Exact configured profile.
    pub profile: Profile,
    /// Exact protected manifest bytes.
    pub manifest_sha256: String,
    /// Exact independently signed asset policy bytes.
    pub asset_policy_sha256: String,
    /// Exact policy issuer public-key file bytes.
    pub asset_policy_key_sha256: String,
    /// Exact independent inventory issuer public-key file bytes.
    pub asset_inventory_key_sha256: String,
    /// Exact envelope issuer public-key file bytes.
    pub envelope_policy_key_sha256: String,
    /// Asset policy expiry only; no claim about live CAS or receipt expiry.
    pub asset_policy_expires_unix: i64,
}

/// Opaque checked root-provisioned inputs. Only this module constructs one.
/// Issuer pins are fixed for this process; changing them requires a controlled
/// restart. The existing asset-policy reader still revalidates each operation.
#[derive(Clone)]
pub struct CustodyProvisioning {
    manifest_path: PathBuf,
    read_paths: [PathBuf; 4],
    asset: AssetEnrollmentAuthority,
    envelope: EnvelopeAuthorityConfig,
    receipt: ProvisioningReceipt,
}
impl std::fmt::Debug for CustodyProvisioning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustodyProvisioning").field("receipt", &self.receipt).finish()
    }
}

fn digest(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }
fn valid_scope(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn protected_path(path: &Path) -> EnclaveResult<PathBuf> {
    let text = path.to_str().ok_or_else(|| err!(EACCES, "CUSTODY_PROVISIONING_PATH"))?;
    if !path.is_absolute() || text.len() > 4096 || text.chars().any(|c|
        c.is_control() || matches!(c, '\'' | '"' | '`' | '$' | ';' | '&' | '|' | '<' | '>' | '(' | ')' | '\\'))
        || !path.components().all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
        || path.components().collect::<PathBuf>().as_os_str() != path.as_os_str()
    { fail!(EACCES, "CUSTODY_PROVISIONING_PATH"); }
    #[cfg(target_os = "macos")]
    if let Ok(suffix) = path.strip_prefix("/var") { return Ok(Path::new("/private/var").join(suffix)); }
    Ok(path.to_owned())
}

impl Manifest {
    fn parse(raw: &[u8], profile: Profile) -> EnclaveResult<(Self, CustodyManifestInputPaths)> {
        // Protected loading already enforces this bound before reading; the
        // inert parser must apply the same limit before deserializing bytes.
        if raw.len() > MAX_CONFIG { fail!(EACCES, "CUSTODY_PROVISIONING_SCHEMA"); }
        let manifest: Self = serde_json::from_slice(raw)
            .map_err(|_| err!(EACCES, "CUSTODY_PROVISIONING_SCHEMA"))?;
        if manifest.v != 1 || manifest.profile != profile || profile == Profile::L1 {
            fail!(EACCES, "CUSTODY_PROVISIONING_PROFILE");
        }
        if [&manifest.asset_host_id, &manifest.asset_id, &manifest.asset_custodian_id,
            &manifest.envelope_policy_subject, &manifest.envelope_policy_namespace]
            .into_iter().any(|value| !valid_scope(value)) {
            fail!(EACCES, "CUSTODY_PROVISIONING_SCOPE");
        }
        let paths = CustodyManifestInputPaths {
            asset_policy_file: protected_path(&manifest.asset_policy_file)?,
            asset_policy_key_file: protected_path(&manifest.asset_policy_key_file)?,
            asset_inventory_key_file: protected_path(&manifest.asset_inventory_key_file)?,
            envelope_policy_key_file: protected_path(&manifest.envelope_policy_key_file)?,
        };
        Ok((manifest, paths))
    }
}

fn root_protected(metadata: &std::fs::Metadata) -> bool {
    metadata.uid() == 0 && metadata.mode() & 0o022 == 0
}

// Hold each no-follow directory FD while opening its next component. A pathname
// pre-check followed by an unrelated open is insufficient for this trust input.
fn read_protected(path: &Path, maximum: usize) -> EnclaveResult<Vec<u8>> {
    let path = protected_path(path)?;
    let parts: Vec<_> = path.components().filter_map(|c| match c {
        Component::Normal(v) => Some(v), _ => None,
    }).collect();
    if parts.is_empty() { fail!(EACCES, "CUSTODY_PROVISIONING_PATH"); }
    let root = CString::new("/").expect("literal");
    let fd = unsafe { libc::open(root.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 { fail!(EACCES, "CUSTODY_PROVISIONING_PROTECTED_PATH"); }
    let mut directory = unsafe { File::from_raw_fd(fd) };
    for (index, part) in parts.iter().enumerate() {
        let metadata = directory.metadata().map_err(|_| err!(EACCES, "CUSTODY_PROVISIONING_PROTECTED_PATH"))?;
        if !metadata.is_dir() || !root_protected(&metadata) {
            fail!(EACCES, "CUSTODY_PROVISIONING_PROTECTED_PATH");
        }
        let last = index + 1 == parts.len();
        let name = CString::new(part.as_bytes()).map_err(|_| err!(EACCES, "CUSTODY_PROVISIONING_PATH"))?;
        let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK
            | if last { 0 } else { libc::O_DIRECTORY };
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 { fail!(EACCES, "CUSTODY_PROVISIONING_PROTECTED_FILE"); }
        let mut file = unsafe { File::from_raw_fd(fd) };
        if last {
            let before = file.metadata().map_err(|_| err!(EACCES, "CUSTODY_PROVISIONING_PROTECTED_FILE"))?;
            if !before.is_file() || !root_protected(&before)
                || before.len() == 0 || before.len() > maximum as u64 {
                fail!(EACCES, "CUSTODY_PROVISIONING_PROTECTED_FILE");
            }
            let mut bytes = Vec::new();
            (&mut file).take(maximum as u64 + 1).read_to_end(&mut bytes)
                .map_err(|_| err!(EIO, "CUSTODY_PROVISIONING_READ"))?;
            let after = file.metadata().map_err(|_| err!(EACCES, "CUSTODY_PROVISIONING_PROTECTED_FILE"))?;
            if bytes.len() as u64 != before.len() || before.len() != after.len()
                || before.uid() != after.uid() || before.mode() != after.mode()
                || before.mtime() != after.mtime() || before.mtime_nsec() != after.mtime_nsec()
                || before.ctime() != after.ctime() || before.ctime_nsec() != after.ctime_nsec() {
                fail!(ESTALE, "CUSTODY_PROVISIONING_CHANGED");
            }
            return Ok(bytes);
        }
        directory = file;
    }
    fail!(EACCES, "CUSTODY_PROVISIONING_PROTECTED_FILE")
}

fn public_key(bytes: &[u8]) -> EnclaveResult<VerifyingKey> {
    let text = std::str::from_utf8(bytes).map_err(|_| err!(EACCES, "CUSTODY_PROVISIONING_PUBLIC_KEY"))?;
    let raw: [u8; 32] = hex::decode(text.trim()).ok().and_then(|v| v.try_into().ok())
        .ok_or_else(|| err!(EACCES, "CUSTODY_PROVISIONING_PUBLIC_KEY"))?;
    let key = VerifyingKey::from_bytes(&raw).map_err(|_| err!(EACCES, "CUSTODY_PROVISIONING_PUBLIC_KEY"))?;
    if key.is_weak() { fail!(EACCES, "CUSTODY_PROVISIONING_PUBLIC_KEY"); }
    Ok(key)
}

impl CustodyProvisioning {
    /// Read strictly protected public files and reuse the existing independent
    /// asset-policy verifier. There is no default issuer or enrollment bypass.
    pub fn load(path: &Path, profile: Profile, now: i64) -> EnclaveResult<Self> {
        let manifest_path = protected_path(path)?;
        let raw = read_protected(&manifest_path, MAX_CONFIG)?;
        let (manifest, paths) = Manifest::parse(&raw, profile)?;
        let read_paths = [paths.asset_policy_file, paths.asset_policy_key_file,
            paths.asset_inventory_key_file, paths.envelope_policy_key_file];
        let policy_bytes = read_protected(&read_paths[0], MAX_CONFIG)?;
        let policy_key_bytes = read_protected(&read_paths[1], 128)?;
        let inventory_key_bytes = read_protected(&read_paths[2], 128)?;
        let envelope_key_bytes = read_protected(&read_paths[3], 128)?;
        let policy_issuer = public_key(&policy_key_bytes)?;
        let inventory_issuer = public_key(&inventory_key_bytes)?;
        let issuer = public_key(&envelope_key_bytes)?;
        let signed: SignedAssetEnrollmentPolicy = serde_json::from_slice(&policy_bytes)
            .map_err(|_| err!(EACCES, "CUSTODY_PROVISIONING_POLICY"))?;
        // Startup/configuration checks do not consume or lower the service's
        // durable policy floor. The actual enrollment owner checks that floor.
        signed.verify(&policy_issuer, &manifest.asset_host_id, &manifest.asset_id,
            &manifest.asset_custodian_id, 0, now)
            .map_err(|_| err!(EACCES, "CUSTODY_PROVISIONING_POLICY"))?;
        let receipt = ProvisioningReceipt { profile, manifest_sha256: digest(&raw),
            asset_policy_sha256: digest(&policy_bytes), asset_policy_key_sha256: digest(&policy_key_bytes),
            asset_inventory_key_sha256: digest(&inventory_key_bytes), envelope_policy_key_sha256: digest(&envelope_key_bytes),
            asset_policy_expires_unix: signed.policy.expires_unix };
        let asset = AssetEnrollmentAuthority { policy_issuer, inventory_issuer, policy_file: read_paths[0].clone(),
            host: manifest.asset_host_id, asset: manifest.asset_id, custodian: manifest.asset_custodian_id };
        let envelope = EnvelopeAuthorityConfig { issuer, subject: manifest.envelope_policy_subject,
            namespace: manifest.envelope_policy_namespace };
        Ok(Self { manifest_path, read_paths, asset, envelope, receipt })
    }

    /// Reject ambiguous legacy/new input and test transports before reading
    /// files. Native entry calls this before monitors, SEP, HID or service state.
    /// With no manifest the existing legacy authority loaders remain in use.
    pub fn from_daemon_args(args: &DaemonArgs, now: i64) -> EnclaveResult<Option<Self>> {
        let paths: Vec<_> = args.extra.iter().filter(|(key, _)| key == "custody-authority-config").collect();
        if paths.is_empty() { return Ok(None); }
        if paths.len() != 1 || args.extra.iter().any(|(key, _)| LEGACY_AUTHORITY_ARGUMENTS.contains(&key.as_str())) {
            fail!(EACCES, "CUSTODY_PROVISIONING_MIXED_ARGUMENTS");
        }
        if args.dev_same_uid || args.simulated_hardware || args.get("yubikey-transport").is_some_and(|value| value != "hid") {
            fail!(EACCES, "CUSTODY_PROVISIONING_NATIVE_REQUIRED");
        }
        Self::load(Path::new(&paths[0].1), args.profile, now).map(Some)
    }

    /// Check the loaded manifest and all referenced bytes remain current before
    /// rendering. A changed source requires loading a new reviewed configuration.
    pub fn revalidate(&self, profile: Profile, now: i64) -> EnclaveResult<()> {
        if Self::load(&self.manifest_path, profile, now)?.receipt != self.receipt {
            fail!(ESTALE, "CUSTODY_PROVISIONING_CHANGED");
        }
        Ok(())
    }
    /// Existing authority types consumed by native entry; no raw input is logged.
    pub fn authorities(&self) -> (AssetEnrollmentAuthority, EnvelopeAuthorityConfig) {
        (self.asset.clone(), self.envelope.clone())
    }
    /// The only authority value placed in rendered process arguments.
    pub fn manifest_path(&self) -> &Path { &self.manifest_path }
    /// Exact public files needing read access, never a recursive directory grant.
    pub fn read_paths(&self) -> Vec<&Path> {
        std::iter::once(self.manifest_path.as_path()).chain(self.read_paths.iter().map(PathBuf::as_path)).collect()
    }
    /// Ancestor directories opened for the no-follow root-protection walk.
    /// Seatbelt may permit reading each literal directory, without child reads.
    pub fn ancestor_paths(&self) -> BTreeSet<PathBuf> {
        self.read_paths().into_iter().flat_map(|path| path.parent().into_iter().flat_map(Path::ancestors))
            .map(Path::to_owned).collect()
    }
    /// Hash-only evidence from the exact protected bytes checked.
    pub fn receipt(&self) -> &ProvisioningReceipt { &self.receipt }
}

#[cfg(test)]
mod manifest_input_path_tests {
    use super::*;
    use serde_json::{json, Value};

    const PATH_FIELDS: [&str; 4] = ["asset_policy_file", "asset_policy_key_file",
        "asset_inventory_key_file", "envelope_policy_key_file"];
    const SCOPE_FIELDS: [&str; 5] = ["asset_host_id", "asset_id", "asset_custodian_id",
        "envelope_policy_subject", "envelope_policy_namespace"];

    fn manifest() -> Value {
        json!({"v":1,"profile":"L2",
            "asset_policy_file":"/mcpmac-inert-parser-fixture-unopened/policy.json",
            "asset_policy_key_file":"/mcpmac-inert-parser-fixture-unopened/policy.pub",
            "asset_inventory_key_file":"/mcpmac-inert-parser-fixture-unopened/inventory.pub",
            "envelope_policy_key_file":"/mcpmac-inert-parser-fixture-unopened/envelope.pub",
            "asset_host_id":"fixture-private-host", "asset_id":"fixture-private-asset",
            "asset_custodian_id":"fixture-private-custodian",
            "envelope_policy_subject":"fixture-private-subject",
            "envelope_policy_namespace":"fixture-private-namespace"})
    }

    fn parse(value: &Value, profile: Profile) -> EnclaveResult<CustodyManifestInputPaths> {
        manifest_input_paths(&serde_json::to_vec(value).unwrap(), profile)
    }

    #[track_caller]
    fn denied(raw: &[u8], profile: Profile, reason: &str) {
        let error = match manifest_input_paths(raw, profile) {
            Err(error) => error,
            Ok(_) => panic!("untrusted manifest unexpectedly accepted"),
        };
        assert!(error.is(reason), "unexpected category: {}", error.reason);
        assert_eq!(error.errno, enclave_core::error::Errno::EACCES);
        assert!(error.detail.is_empty());
        let exported = format!("{error:?}");
        assert!(!exported.contains("fixture-private"));
        assert!(!exported.contains("mcpmac-inert-parser-fixture-unopened"));
    }

    #[track_caller]
    fn denied_value(value: &Value, profile: Profile, reason: &str) {
        denied(&serde_json::to_vec(value).unwrap(), profile, reason);
    }

    #[test]
    fn raw_paths_keep_semantic_roles_without_opening_referenced_files() {
        let paths = parse(&manifest(), Profile::L2).unwrap();
        assert_eq!(paths.asset_policy_file(), Path::new("/mcpmac-inert-parser-fixture-unopened/policy.json"));
        assert_eq!(paths.asset_policy_key_file(), Path::new("/mcpmac-inert-parser-fixture-unopened/policy.pub"));
        assert_eq!(paths.asset_inventory_key_file(), Path::new("/mcpmac-inert-parser-fixture-unopened/inventory.pub"));
        assert_eq!(paths.envelope_policy_key_file(), Path::new("/mcpmac-inert-parser-fixture-unopened/envelope.pub"));
        let mut l3 = manifest(); l3["profile"] = json!("L3");
        assert!(parse(&l3, Profile::L3).is_ok());
    }

    #[test]
    fn every_required_field_and_duplicate_is_checked_by_the_closed_schema() {
        let complete = manifest();
        let serialized = serde_json::to_string(&complete).unwrap();
        for (field, value) in complete.as_object().unwrap() {
            let mut missing = complete.clone(); missing.as_object_mut().unwrap().remove(field);
            denied_value(&missing, Profile::L2, "CUSTODY_PROVISIONING_SCHEMA");
            let prefix = format!("{{{}:{},", serde_json::to_string(field).unwrap(),
                serde_json::to_string(value).unwrap());
            denied(serialized.replacen('{', &prefix, 1).as_bytes(), Profile::L2,
                "CUSTODY_PROVISIONING_SCHEMA");
        }
        let mut unknown = complete; unknown["private_issuer_seed"] = json!("fixture-private-refused");
        denied_value(&unknown, Profile::L2, "CUSTODY_PROVISIONING_SCHEMA");
    }

    #[test]
    fn malformed_trailing_and_oversize_raw_bytes_are_refused_before_use() {
        let raw = serde_json::to_vec(&manifest()).unwrap();
        for malformed in [Vec::new(), vec![0xff], b"null".to_vec(), b"[]".to_vec(),
            raw[..raw.len() - 1].to_vec(), [raw.as_slice(), b"{}"].concat()] {
            denied(&malformed, Profile::L2, "CUSTODY_PROVISIONING_SCHEMA");
        }
        let mut at_limit = raw; at_limit.resize(MAX_CONFIG, b' ');
        assert!(manifest_input_paths(&at_limit, Profile::L2).is_ok());
        at_limit.push(b' ');
        denied(&at_limit, Profile::L2, "CUSTODY_PROVISIONING_SCHEMA");
    }

    #[test]
    fn exact_version_and_profile_precede_scope_and_path_validation() {
        denied_value(&manifest(), Profile::L3, "CUSTODY_PROVISIONING_PROFILE");
        let mut l1 = manifest(); l1["profile"] = json!("L1");
        denied_value(&l1, Profile::L1, "CUSTODY_PROVISIONING_PROFILE");
        for version in [0, 2, 255] {
            let mut value = manifest(); value["v"] = json!(version);
            value["asset_id"] = json!(""); value["asset_policy_file"] = json!("relative");
            denied_value(&value, Profile::L2, "CUSTODY_PROVISIONING_PROFILE");
        }
        let mut unknown = manifest(); unknown["profile"] = json!("unknown");
        denied_value(&unknown, Profile::L2, "CUSTODY_PROVISIONING_SCHEMA");
    }

    #[test]
    fn every_scope_retains_nonempty_byte_bound_and_control_refusal() {
        for field in SCOPE_FIELDS {
            for invalid in [String::new(), "x".repeat(257), "é".repeat(129),
                "fixture-private\nvalue".into(), "fixture-private\0value".into(), "fixture-private\u{7f}value".into()] {
                let mut value = manifest(); value[field] = json!(invalid);
                // Existing validation checks all scopes before any path.
                value["asset_policy_file"] = json!("relative");
                denied_value(&value, Profile::L2, "CUSTODY_PROVISIONING_SCOPE");
            }
            for valid in ["x".repeat(256), "é".repeat(128), "scope with spaces".into()] {
                let mut value = manifest(); value[field] = json!(valid);
                assert!(parse(&value, Profile::L2).is_ok());
            }
        }
    }

    #[test]
    fn every_semantic_path_uses_the_existing_protected_path_syntax() {
        for field in PATH_FIELDS {
            for invalid in ["", "relative.json", "/fixture/../policy", "/fixture/./policy",
                "/fixture//policy", "/fixture/policy/", "/fixture/evil\"name", "/fixture/evil'name",
                "/fixture/evil`name", "/fixture/$name", "/fixture/;name", "/fixture/&name",
                "/fixture/|name", "/fixture/<name", "/fixture/>name", "/fixture/(name",
                "/fixture/)name", "/fixture/evil\\name", "/fixture/evil\nname", "/fixture/evil\0name"] {
                let mut value = manifest(); value[field] = json!(invalid);
                denied_value(&value, Profile::L2, "CUSTODY_PROVISIONING_PATH");
            }
            let mut value = manifest(); value[field] = json!(format!("/{}", "x".repeat(4096)));
            denied_value(&value, Profile::L2, "CUSTODY_PROVISIONING_PATH");
            value[field] = json!(format!("/{}", "x".repeat(4095)));
            assert!(parse(&value, Profile::L2).is_ok());
        }
    }

    #[test]
    fn path_syntax_does_not_claim_distinct_regular_files_or_import_isolation() {
        let mut value = manifest();
        for field in PATH_FIELDS { value[field] = json!("/"); }
        let paths = parse(&value, Profile::L2).unwrap();
        assert_eq!(paths.asset_policy_file(), Path::new("/"));
        assert_eq!(paths.asset_policy_key_file(), paths.asset_policy_file());
        assert_eq!(paths.asset_inventory_key_file(), paths.asset_policy_file());
        assert_eq!(paths.envelope_policy_key_file(), paths.asset_policy_file());
        // Root and duplicate paths were already syntactically accepted. Only
        // protected loading or a caller's stricter closure checks file roles.
    }

    #[test]
    fn platform_aliases_and_spaces_match_the_shared_loader_paths() {
        let mut value = manifest();
        for field in PATH_FIELDS { value[field] = json!("/var/fixture path/public input"); }
        let paths = parse(&value, Profile::L2).unwrap();
        let expected = if cfg!(target_os = "macos") { "/private/var/fixture path/public input" }
            else { "/var/fixture path/public input" };
        assert_eq!(paths.asset_policy_file(), Path::new(expected));
        assert_eq!(paths.asset_policy_key_file(), Path::new(expected));
        assert_eq!(paths.asset_inventory_key_file(), Path::new(expected));
        assert_eq!(paths.envelope_policy_key_file(), Path::new(expected));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn kernel_fd_nonroot_owner_is_refused_by_reader_metadata_predicate() {
        assert_eq!(unsafe { libc::geteuid() }, 0, "kernel ownership fixture requires root");
        let name = CString::new("custody-provisioning-owner-fixture").unwrap();
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0, "kernel memfd unavailable: {}", std::io::Error::last_os_error());
        let file = unsafe { File::from_raw_fd(fd) };
        assert_eq!(unsafe { libc::fchmod(file.as_raw_fd(), 0o644) }, 0);
        let original = file.metadata().unwrap();
        assert!(original.is_file());
        assert_eq!(original.uid(), 0);
        assert_eq!(original.mode() & 0o7777, 0o644);
        assert!(root_protected(&original));

        assert_eq!(unsafe { libc::fchown(file.as_raw_fd(), 12345, 0) }, 0);
        let changed = file.metadata().unwrap();
        // The shared workspace mount can report successful chown without an
        // owner change. This anonymous kernel inode must prove the transition.
        assert_eq!(changed.uid(), 12345, "kernel owner change must actually occur");
        assert_eq!(changed.mode() & 0o7777, 0o644);
        assert!(!root_protected(&changed));

        assert_eq!(unsafe { libc::fchown(file.as_raw_fd(), 0, 0) }, 0);
        let restored = file.metadata().unwrap();
        assert_eq!(restored.uid(), 0, "kernel root restoration must actually occur");
        assert_eq!(restored.mode() & 0o7777, 0o644);
        assert!(root_protected(&restored));
    }
}
