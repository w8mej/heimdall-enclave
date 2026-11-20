//! Protected, immutable deployment selection. This is public configuration,
//! not enrollment, issuer authority, installation or service readiness.
//!
//! A parsed descriptor is inert. Only a protected load constructs the checked
//! process capability; the first code requirement freezes either that target
//! or the legacy default. Configured trust never falls back or unions pinsets.

use std::{ffi::CString, fs::File, io::Read,
    os::{fd::{AsRawFd, FromRawFd}, unix::{ffi::OsStrExt, fs::MetadataExt}},
    path::{Component, Path, PathBuf}, sync::Mutex};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::{err, fail, error::EnclaveResult, profile::Profile};

#[path = "deployment_teardown.rs"]
pub mod teardown;
#[path = "deployment_upgrade.rs"]
pub mod upgrade;
#[path = "deployment_startup_lease.rs"]
pub mod startup_lease;

/// Maximum descriptor size, separate from public referenced-file caps.
pub const MAX_DESCRIPTOR_BYTES: usize = 64 * 1024;
const MAX_REFERENCE_BYTES: usize = 1024 * 1024;
const MAX_ROOT_BYTES: usize = 4 * 1024 * 1024;

/// Operational destination; this never authorizes a physical ceremony.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeploymentRole {
    /// Separate first supervised test installation.
    DedicatedTest,
    /// Preparation for a separately authorized existing-installation upgrade.
    ExistingUpgrade,
}
/// Must match the actual build; JSON cannot choose another trust mode.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeploymentSigningMode {
    /// Existing exact local cdhash pin mode.
    LocalPins,
    /// Existing compiled Team ID mode, retaining exact boundary pins.
    TeamId,
}
/// Explicit output and runtime namespaces. Signing identifiers and UIDs do not
/// change when launchd job labels change.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentLayout {
    /// Target executable directory.
    pub binary_dir: PathBuf,
    /// Target custody application bundle.
    pub custody_bundle: PathBuf,
    /// Target confinement profiles.
    pub sandbox_dir: PathBuf,
    /// Target runtime parent, including per-console helper sockets.
    pub socket_root: PathBuf,
    /// Target persistent state parent.
    pub state_root: PathBuf,
    /// Target audit parent.
    pub audit_root: PathBuf,
    /// Exact target CAS store, including its objects child.
    pub cas_store_root: PathBuf,
    /// Root-owned target artifact/output staging parent.
    pub staging_root: PathBuf,
    /// Root-owned public support configuration and separately signed bundles.
    pub support_root: PathBuf,
    /// Launchd job-label namespace, independent of signing identifiers.
    pub launchd_namespace: String,
    /// Exact target Mach bootstrap service.
    pub mach_service: String,
}
/// L3 broker paths; signed configuration and volume authority still come from
/// the existing genuine TUF/source checks, never this descriptor.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentBroker {
    /// Target-local root-only base; state and repository are fixed descendants.
    pub base_dir: PathBuf,
    /// Independently supplied protected public TUF root.
    pub tuf_root_file: PathBuf,
}
/// Closed public schema. Deserialization alone grants no process authority.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentTarget {
    /// Exactly version one.
    pub version: u8,
    /// Nonempty bounded local target identity.
    pub target_id: String,
    /// Dedicated test or existing upgrade destination.
    pub role: DeploymentRole,
    /// Exact L2 or L3 profile, not a hint or replacement for signed floors.
    pub profile: Profile,
    /// Existing independent custody authority configuration.
    pub authority_config: PathBuf,
    /// Protected source-bound artifact/hash/signing-identity manifest reference.
    pub expected_artifacts_manifest: PathBuf,
    /// Only selected pin file; no default fallback or old/new union.
    pub codesign_pins_file: PathBuf,
    /// Expectation checked against the compiled signing mode on protected load.
    pub signing_identity_mode: DeploymentSigningMode,
    /// Exact target output and runtime layout.
    pub layout: DeploymentLayout,
    /// Required for L3; explicitly null for L2.
    #[serde(deserialize_with="required_broker")]
    pub broker: Option<DeploymentBroker>,
    /// At most eight exact read-only references explicitly shared by BOTH
    /// descriptors. Pins and mutable/output roots can never be shared.
    pub shared_read_only_inputs: Vec<PathBuf>,
}
fn required_broker<'de,D:serde::Deserializer<'de>>(deserializer:D)->Result<Option<DeploymentBroker>,D::Error> {
    Option::<DeploymentBroker>::deserialize(deserializer)
}
impl std::fmt::Debug for DeploymentTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeploymentTarget").finish_non_exhaustive()
    }
}
impl DeploymentLayout {
    fn roots(&self) -> [&Path; 9] {
        [&self.binary_dir, &self.custody_bundle, &self.sandbox_dir, &self.socket_root,
            &self.state_root, &self.audit_root, &self.cas_store_root, &self.staging_root, &self.support_root]
    }
}
fn normal_path(path: &Path) -> EnclaveResult<()> {
    let text = path.to_str().ok_or_else(|| err!(EINVAL, "DEPLOYMENT_PATH"))?;
    if text.len() > 4096 || !text.is_ascii() || path == Path::new("/") || !path.is_absolute()
        || text.chars().any(|c| c.is_control() || matches!(c,
            '\'' | '"' | '`' | '$' | ';' | '&' | '|' | '<' | '>' | '(' | ')' | '\\'))
        || !path.components().all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
        || path.components().collect::<PathBuf>().as_os_str() != path.as_os_str()
    { fail!(EINVAL, "DEPLOYMENT_PATH"); }
    // macOS commonly resolves these OS-owned aliases case-insensitively. Do
    // not turn a differently spelled root into a different lexical namespace,
    // or silently rewrite its route. Other ASCII route spelling is preserved.
    let mut parts=text.trim_start_matches('/').split('/');
    let first=parts.next().unwrap_or_default();
    if ["var","tmp","etc","private"].iter().any(|name|first.eq_ignore_ascii_case(name) && first!=*name) {
        fail!(EINVAL,"DEPLOYMENT_PATH");
    }
    if first=="private" {
        let second=parts.next().unwrap_or_default();
        if ["var","tmp","etc"].iter().any(|name|second.eq_ignore_ascii_case(name) && second!=*name) {
            fail!(EINVAL,"DEPLOYMENT_PATH");
        }
    }
    Ok(())
}
/// Normalize only the fixed OS aliases for comparisons and resolved routing.
/// This does not follow arbitrary filesystem symlinks or establish protection.
pub fn normalized_path(path: &Path) -> EnclaveResult<PathBuf> {
    normal_path(path)?;
    for top in ["/var", "/tmp", "/etc"] {
        if let Ok(suffix) = path.strip_prefix(top) {
            return Ok(Path::new("/private").join(top.trim_start_matches('/')).join(suffix));
        }
    }
    Ok(path.to_owned())
}
fn overlap(a: &Path, b: &Path) -> EnclaveResult<bool> {
    // Use a conservative case-insensitive comparison even on case-sensitive
    // development filesystems. Never lowercase actual routing paths.
    let a=PathBuf::from(normalized_path(a)?.to_str().ok_or_else(||err!(EINVAL,"DEPLOYMENT_PATH"))?.to_ascii_lowercase());
    let b=PathBuf::from(normalized_path(b)?.to_str().ok_or_else(||err!(EINVAL,"DEPLOYMENT_PATH"))?.to_ascii_lowercase());
    Ok(a.starts_with(&b) || b.starts_with(&a))
}
fn target_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.as_bytes()[0].is_ascii_lowercase()
        && s.as_bytes()[s.len()-1].is_ascii_alphanumeric()
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn service_name(s: &str, maximum: usize) -> bool {
    s.len() <= maximum && s.split('.').count() >= 2 && s.split('.').all(|part|
        !part.is_empty() && part.len() <= 63 && part.as_bytes()[0].is_ascii_lowercase()
        && part.as_bytes()[part.len()-1].is_ascii_alphanumeric()
        && part.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
}
impl DeploymentTarget {
    /// Parse and validate bounded syntax. This is NOT a protected load.
    pub fn parse(bytes: &[u8]) -> EnclaveResult<Self> {
        if bytes.is_empty() || bytes.len() > MAX_DESCRIPTOR_BYTES { fail!(E2BIG, "DEPLOYMENT_SCHEMA"); }
        let target: Self = serde_json::from_slice(bytes).map_err(|_| err!(EINVAL, "DEPLOYMENT_SCHEMA"))?;
        target.validate()?;
        Ok(target)
    }
    fn read_only_inputs(&self) -> Vec<&Path> {
        let mut paths = vec![self.authority_config.as_path(), self.expected_artifacts_manifest.as_path()];
        if let Some(broker) = &self.broker { paths.push(&broker.tuf_root_file); }
        paths
    }
    fn output_roots(&self) -> Vec<&Path> {
        let mut paths = self.layout.roots().to_vec();
        if let Some(broker) = &self.broker { paths.push(&broker.base_dir); }
        paths
    }
    /// Validate syntax and internal isolation, without reading files or granting
    /// trust. Dedicated targets independently exclude standard installed roots.
    pub fn validate(&self) -> EnclaveResult<()> {
        if self.version != 1 || !target_name(&self.target_id) || self.profile == Profile::L1
            || (self.profile == Profile::L3) != self.broker.is_some()
            || !service_name(&self.layout.launchd_namespace, 112)
            // bootstrap name_t has128 bytes including its terminating NUL.
            || !service_name(&self.layout.mach_service, 127)
            || self.shared_read_only_inputs.len() > 8 { fail!(EINVAL, "DEPLOYMENT_SCHEMA"); }
        for path in self.output_roots().into_iter().chain(self.read_only_inputs()).chain([self.codesign_pins_file.as_path()]) {
            normal_path(path)?;
        }
        for path in [&self.layout.socket_root, &self.layout.state_root, &self.layout.audit_root,
            &self.layout.cas_store_root, &self.layout.staging_root] {
            if path.to_str().is_none_or(|s| s.chars().any(char::is_whitespace)) { fail!(EINVAL, "DEPLOYMENT_PATH"); }
        }
        let roots = self.layout.roots();
        for (index, left) in roots.iter().enumerate() {
            for right in roots.iter().skip(index+1) {
                let bundle_below_support = (*left == self.layout.custody_bundle.as_path() && *right == self.layout.support_root.as_path())
                    || (*right == self.layout.custody_bundle.as_path() && *left == self.layout.support_root.as_path());
                if overlap(left, right)? && !(bundle_below_support
                    && normalized_path(&self.layout.custody_bundle)? != normalized_path(&self.layout.support_root)?
                    && normalized_path(&self.layout.custody_bundle)?.starts_with(normalized_path(&self.layout.support_root)?)) {
                    fail!(EINVAL, "DEPLOYMENT_OUTPUT_OVERLAP");
                }
            }
        }
        let inputs = self.read_only_inputs();
        for (index, path) in self.shared_read_only_inputs.iter().enumerate() {
            normal_path(path)?;
            if !inputs.iter().any(|p| normalized_path(p).ok() == normalized_path(path).ok())
                || self.shared_read_only_inputs[..index].iter().any(|p| normalized_path(p).ok() == normalized_path(path).ok())
            { fail!(EINVAL, "DEPLOYMENT_SHARED_INPUT"); }
        }
        // A pin file cannot alias any other input or be writable through an
        // output root. Public independent-authority inputs are read-only too.
        for input in inputs.iter().copied().chain([self.codesign_pins_file.as_path()]) {
            if self.output_roots().iter().filter(|root| root.as_os_str() != self.layout.support_root.as_os_str())
                .any(|root| overlap(input, root).unwrap_or(true)) {
                fail!(EINVAL, "DEPLOYMENT_INPUT_OUTPUT_OVERLAP");
            }
        }
        for (index,input) in inputs.iter().enumerate() {
            if overlap(input, &self.codesign_pins_file)? { fail!(EINVAL, "DEPLOYMENT_PIN_OVERLAP"); }
            for other in inputs.iter().skip(index+1) {
                if overlap(input,other)? { fail!(EINVAL,"DEPLOYMENT_INPUT_OVERLAP"); }
            }
        }
        if let Some(broker) = &self.broker {
            if normalized_path(&broker.base_dir)? != normalized_path(&self.layout.state_root.join("apfs-broker"))? {
                fail!(EINVAL, "DEPLOYMENT_BROKER_LAYOUT");
            }
        }
        if self.role == DeploymentRole::DedicatedTest {
            for root in self.output_roots().into_iter().chain([self.codesign_pins_file.as_path()]) {
                for installed in ["/opt/enterprise/enclave", "/var/run/enclave", "/var/db/enclave", "/var/log/enclave",
                    "/Library/Application Support/EnterpriseEnclave"] {
                    if overlap(root, Path::new(installed))? { fail!(EINVAL, "DEPLOYMENT_INSTALLED_OVERLAP"); }
                }
            }
            if self.layout.launchd_namespace == "com.enterprise.enclave"
                || self.layout.mach_service == "com.enterprise.enclave.exception" {
                fail!(EINVAL, "DEPLOYMENT_INSTALLED_OVERLAP");
            }
        }
        Ok(())
    }
    /// Reject cross-target output/alias/ancestor collisions. The only permitted
    /// shared references are exact read-only inputs explicitly listed by both.
    pub fn validate_pair(&self, other: &Self) -> EnclaveResult<()> {
        self.validate()?; other.validate()?;
        if self.target_id == other.target_id || self.role == other.role
            || self.layout.launchd_namespace == other.layout.launchd_namespace
            || self.layout.mach_service == other.layout.mach_service {
            fail!(EINVAL, "DEPLOYMENT_PAIR_COLLISION");
        }
        let left = self.output_roots(); let right = other.output_roots();
        for a in &left { for b in &right { if overlap(a,b)? { fail!(EINVAL, "DEPLOYMENT_PAIR_COLLISION"); } } }
        // Pins are never shared, nor placed below either target's output roots.
        for (pin, roots) in [(&self.codesign_pins_file, &right), (&other.codesign_pins_file, &left)] {
            for root in roots { if overlap(pin,root)? { fail!(EINVAL, "DEPLOYMENT_PAIR_COLLISION"); } }
        }
        if overlap(&self.codesign_pins_file,&other.codesign_pins_file)? { fail!(EINVAL, "DEPLOYMENT_PAIR_COLLISION"); }
        for (a, peer) in [(self,other),(other,self)] {
            for input in a.read_only_inputs() {
                let normalized=normalized_path(input)?;
                let explicitly_shared=peer.read_only_inputs().iter().any(|p|normalized_path(p).ok().as_ref()==Some(&normalized))
                    && a.shared_read_only_inputs.iter().any(|p|normalized_path(p).ok().as_ref()==Some(&normalized))
                    && peer.shared_read_only_inputs.iter().any(|p|normalized_path(p).ok().as_ref()==Some(&normalized));
                for root in peer.output_roots().into_iter().chain([peer.codesign_pins_file.as_path()]) {
                    let shared_protected_support=normalized_path(root)?==normalized_path(&peer.layout.support_root)?
                        && normalized.starts_with(normalized_path(&peer.layout.support_root)?) && explicitly_shared;
                    if overlap(input,root)? && !shared_protected_support { fail!(EINVAL, "DEPLOYMENT_PAIR_COLLISION"); }
                }
                for other_input in peer.read_only_inputs() {
                    if overlap(input,other_input)? {
                        if normalized != normalized_path(other_input)?
                            || !explicitly_shared {
                            fail!(EINVAL, "DEPLOYMENT_SHARED_INPUT");
                        }
                    }
                }
            }
        }
        Ok(())
    }
    /// Exact console helper path; observation of the actual console is separate.
    pub fn intent_socket(&self, uid: u32) -> EnclaveResult<PathBuf> {
        if uid < 500 || uid == u32::MAX { fail!(EINVAL, "DEPLOYMENT_CONSOLE_UID"); }
        Ok(crate::runtime_paths::intent_socket(&self.layout.socket_root, uid))
    }
    /// Exact target supervisor endpoint, retaining the existing suffix.
    pub fn supervisor_socket(&self) -> PathBuf { crate::supervisor::socket_path(&self.layout.socket_root) }
    /// Exact narrow broker endpoint; never caller-selected per request.
    pub fn broker_socket(&self) -> PathBuf { self.layout.socket_root.join("apfs-broker/broker.sock") }
}

fn protected(metadata: &std::fs::Metadata) -> bool { metadata.uid() == 0 && metadata.mode() & 0o022 == 0 }
/// Root-protected bounded public-file reader for this module's trust inputs.
/// Every path component is opened no-follow relative to its held parent FD.
pub(crate) fn read_protected_public(path: &Path, maximum: usize) -> EnclaveResult<Vec<u8>> {
    normal_path(path)?;
    #[cfg(target_os="macos")]
    let path = normalized_path(path)?;
    #[cfg(not(target_os="macos"))]
    let path = path.to_owned();
    let parts: Vec<_> = path.components().filter_map(|p| if let Component::Normal(v)=p {Some(v)} else {None}).collect();
    let root = CString::new("/").expect("literal");
    // SAFETY: constant C string, returned fd is owned after a successful open.
    let fd = unsafe { libc::open(root.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC) };
    if fd < 0 { fail!(EACCES,"DEPLOYMENT_PROTECTED_PATH"); }
    let mut directory = unsafe { File::from_raw_fd(fd) };
    for (index, part) in parts.iter().enumerate() {
        let m = directory.metadata().map_err(|_|err!(EACCES,"DEPLOYMENT_PROTECTED_PATH"))?;
        if !m.is_dir() || !protected(&m) { fail!(EACCES,"DEPLOYMENT_PROTECTED_PATH"); }
        let last = index+1==parts.len();
        let name = CString::new(part.as_bytes()).map_err(|_|err!(EINVAL,"DEPLOYMENT_PATH"))?;
        let flags = libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC|if last {0} else {libc::O_DIRECTORY};
        // SAFETY: live held directory, bounded component without NUL; no follow.
        let fd = unsafe { libc::openat(directory.as_raw_fd(),name.as_ptr(),flags) };
        if fd < 0 { fail!(EACCES,"DEPLOYMENT_PROTECTED_PATH"); }
        let mut file = unsafe { File::from_raw_fd(fd) };
        if last {
            let before = file.metadata().map_err(|_|err!(EACCES,"DEPLOYMENT_PROTECTED_FILE"))?;
            if !before.is_file() || !protected(&before) || before.nlink()!=1 || before.len()==0 || before.len()>maximum as u64 {
                fail!(EACCES,"DEPLOYMENT_PROTECTED_FILE");
            }
            let mut bytes=Vec::new();
            (&mut file).take(maximum as u64+1).read_to_end(&mut bytes).map_err(|_|err!(EIO,"DEPLOYMENT_READ"))?;
            let after=file.metadata().map_err(|_|err!(EACCES,"DEPLOYMENT_PROTECTED_FILE"))?;
            if !protected(&after) || after.nlink()!=1 || before.len()!=after.len() || bytes.len() as u64!=before.len()
                || before.mode()!=after.mode() || before.uid()!=after.uid() || before.mtime()!=after.mtime()
                || before.mtime_nsec()!=after.mtime_nsec() || before.ctime()!=after.ctime() || before.ctime_nsec()!=after.ctime_nsec() {
                fail!(ESTALE,"DEPLOYMENT_CHANGED");
            }
            return Ok(bytes);
        }
        directory=file;
    }
    fail!(EINVAL,"DEPLOYMENT_PATH")
}
/// Only a protected load constructs this process-selection capability. There is
/// no public constructor, deserializer, mutable getter or parsed-to-checked cast.
#[derive(Clone)]
pub struct CheckedDeploymentTarget {
    target: DeploymentTarget,
    config_path: PathBuf,
    descriptor_sha256: String,
}
impl std::fmt::Debug for CheckedDeploymentTarget {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        f.debug_struct("CheckedDeploymentTarget").field("descriptor_sha256",&self.descriptor_sha256).finish_non_exhaustive()
    }
}
impl CheckedDeploymentTarget {
    /// Immutable checked public configuration.
    pub fn target(&self)->&DeploymentTarget { &self.target }
    /// Exact selected descriptor path; root-protected provenance checked at load.
    pub fn config_path(&self)->&Path { &self.config_path }
    /// SHA-256 of the exact descriptor bytes accepted by the protected load.
    pub fn descriptor_sha256(&self)->&str { &self.descriptor_sha256 }
    /// Read only the selected protected public inventory. A changed descriptor
    /// invalidates this observation; this is not artifact/provenance validation.
    pub fn read_artifact_inventory(&self)->EnclaveResult<Vec<u8>> {
        let current=read_protected_public(&self.config_path,MAX_DESCRIPTOR_BYTES)?;
        if hex::encode(Sha256::digest(&current))!=self.descriptor_sha256 {
            fail!(ESTALE,"DEPLOYMENT_CHANGED");
        }
        let bytes=read_protected_public(&self.target.expected_artifacts_manifest,MAX_REFERENCE_BYTES)?;
        let current=read_protected_public(&self.config_path,MAX_DESCRIPTOR_BYTES)?;
        if hex::encode(Sha256::digest(&current))!=self.descriptor_sha256 {
            fail!(ESTALE,"DEPLOYMENT_CHANGED");
        }
        Ok(bytes)
    }
}
/// Load protected descriptor and every explicit public reference. This checks
/// file protection and syntax, not issuer signatures/artifact compatibility or
/// installed readiness; those existing downstream checks remain mandatory.
pub fn load(path:&Path)->EnclaveResult<CheckedDeploymentTarget> {
    let bytes=read_protected_public(path,MAX_DESCRIPTOR_BYTES)?;
    let target=DeploymentTarget::parse(&bytes)?;
    let actual=match crate::codesign::signing_mode() {
        crate::codesign::SigningMode::LocalPins=>DeploymentSigningMode::LocalPins,
        crate::codesign::SigningMode::TeamId=>DeploymentSigningMode::TeamId,
    };
    if target.signing_identity_mode!=actual { fail!(EACCES,"DEPLOYMENT_SIGNING_MODE"); }
    for reference in [&target.authority_config,&target.expected_artifacts_manifest] {
        read_protected_public(reference,MAX_REFERENCE_BYTES)?;
    }
    let pins=read_protected_public(&target.codesign_pins_file,MAX_REFERENCE_BYTES)?;
    // Keep existing pin schema/identifiers/required-ID checks at their original
    // callers. Parsing does not invent an identifier or choose fallback hashes.
    crate::codesign::pins::parse(&pins).map_err(|_|err!(EACCES,"DEPLOYMENT_PINS"))?;
    if let Some(broker)=&target.broker { read_protected_public(&broker.tuf_root_file,MAX_ROOT_BYTES)?; }
    for root in target.output_roots().into_iter().filter(|root| root.as_os_str() != target.layout.support_root.as_os_str()) {
        if overlap(path,root)? { fail!(EACCES,"DEPLOYMENT_CONFIG_OUTPUT_OVERLAP"); }
    }
    Ok(CheckedDeploymentTarget {target,config_path:path.to_owned(),descriptor_sha256:hex::encode(Sha256::digest(bytes))})
}
struct ContextSlot { checked: Option<&'static CheckedDeploymentTarget>, frozen: bool }
impl ContextSlot {
    const fn empty()->Self { Self {checked:None,frozen:false} }
    fn select(&mut self,checked:CheckedDeploymentTarget)->EnclaveResult<()> {
        if self.frozen || self.checked.is_some() { fail!(EACCES,"DEPLOYMENT_CONTEXT_FROZEN"); }
        self.checked=Some(Box::leak(Box::new(checked))); Ok(())
    }
    fn pin_file(&mut self)->PathBuf {
        self.frozen=true;
        self.checked.map(|c|c.target.codesign_pins_file.clone()).unwrap_or_else(||crate::codesign::PIN_FILE.into())
    }
}
static CONTEXT:Mutex<ContextSlot>=Mutex::new(ContextSlot::empty());
/// Select exactly once before any code requirement or pin lookup. Even repeated
/// identical selection is refused; the checked process context is immutable.
pub fn select(checked:CheckedDeploymentTarget)->EnclaveResult<()> {
    CONTEXT.lock().unwrap_or_else(std::sync::PoisonError::into_inner).select(checked)
}
/// Current checked target, without selecting or freezing the legacy default.
pub fn selected()->Option<&'static CheckedDeploymentTarget> {
    CONTEXT.lock().unwrap_or_else(std::sync::PoisonError::into_inner).checked
}
/// Exact pin path, freezing the selected context or legacy default immediately.
/// Both cached ordinary readers and fresh boundaries must call this accessor.
pub fn selected_pin_file()->PathBuf {
    CONTEXT.lock().unwrap_or_else(std::sync::PoisonError::into_inner).pin_file()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink,PermissionsExt};

    fn target(id:&str,role:DeploymentRole)->DeploymentTarget {
        let root=Path::new("/deployment-fixtures").join(id);
        DeploymentTarget {version:1,target_id:id.into(),role,profile:Profile::L2,
            authority_config:root.join("support/authority.json"),
            expected_artifacts_manifest:root.join("support/artifacts.json"),
            codesign_pins_file:root.join("support/pins.json"),
            signing_identity_mode:match crate::codesign::signing_mode() {
                crate::codesign::SigningMode::LocalPins=>DeploymentSigningMode::LocalPins,
                crate::codesign::SigningMode::TeamId=>DeploymentSigningMode::TeamId,
            },
            layout:DeploymentLayout {binary_dir:root.join("bin"),custody_bundle:root.join("support/Custody.app"),
                sandbox_dir:root.join("sandbox"),socket_root:root.join("run"),state_root:root.join("state"),
                audit_root:root.join("audit"),cas_store_root:root.join("cas"),staging_root:root.join("stage"),support_root:root.join("support"),
                launchd_namespace:format!("com.mcpmac.{id}"),mach_service:format!("com.mcpmac.{id}.exception")},
            broker:None,shared_read_only_inputs:vec![]}
    }
    fn checked_fixture(target:DeploymentTarget)->CheckedDeploymentTarget {
        // Private synthetic state-machine fixture only. No production API
        // converts parsed configuration into a checked selection capability.
        CheckedDeploymentTarget {target,config_path:"/fixtures/target.json".into(),descriptor_sha256:"synthetic".into()}
    }
    #[test]
    fn deployment_schema_is_closed_bounded_and_redacted() {
        let t=target("dedicated",DeploymentRole::DedicatedTest);
        let bytes=serde_json::to_vec(&t).unwrap();
        assert!(DeploymentTarget::parse(&bytes).unwrap()==t);
        assert!(!format!("{t:?}").contains("deployment-fixtures"));
        for (key,value) in [("unknown",serde_json::json!(true)),("profile",serde_json::json!("L1")),
            ("target_id",serde_json::json!("../scope")),("version",serde_json::json!(2))] {
            let mut v=serde_json::to_value(&t).unwrap();v[key]=value;
            let error=DeploymentTarget::parse(&serde_json::to_vec(&v).unwrap()).unwrap_err();
            assert!(!format!("{error}").contains("deployment-fixtures"));
        }
        for field in ["broker","shared_read_only_inputs","authority_config"] {
            let mut v=serde_json::to_value(&t).unwrap();v.as_object_mut().unwrap().remove(field);
            assert!(DeploymentTarget::parse(&serde_json::to_vec(&v).unwrap()).is_err());
        }
        let duplicate=String::from_utf8(bytes).unwrap().replacen("{","{\"version\":1,",1);
        assert!(DeploymentTarget::parse(duplicate.as_bytes()).is_err());
        assert!(DeploymentTarget::parse(&vec![b' ';MAX_DESCRIPTOR_BYTES+1]).is_err());
        let mut nested=serde_json::to_value(&t).unwrap();nested["layout"]["shell"]=serde_json::json!("ignored");
        assert!(DeploymentTarget::parse(&serde_json::to_vec(&nested).unwrap()).is_err());
        let mut l3=t.clone();l3.profile=Profile::L3;assert!(l3.validate().is_err());
        l3.broker=Some(DeploymentBroker {base_dir:l3.layout.state_root.join("apfs-broker"),tuf_root_file:l3.layout.support_root.join("tuf-root.json")});
        l3.validate().unwrap();
    }
    #[test]
    fn deployment_case_aliases_and_non_ascii_cannot_bypass_namespace_isolation() {
        let a=target("dedicated",DeploymentRole::DedicatedTest);
        let mut b=target("existing",DeploymentRole::ExistingUpgrade);
        a.validate_pair(&b).unwrap();
        b.layout.binary_dir=PathBuf::from(a.layout.binary_dir.to_str().unwrap().to_ascii_uppercase());
        assert!(a.validate_pair(&b).is_err());
        for installed in ["/OPT/ENTERPRISE/ENCLAVE/bin","/Library/Application Support/ENTERPRISEENCLAVE/test"] {
            let mut changed=a.clone();changed.layout.binary_dir=installed.into();
            assert!(changed.validate().is_err());
        }
        let mut changed=a.clone();changed.layout.audit_root=PathBuf::from(a.layout.state_root.to_str().unwrap().to_ascii_uppercase());
        assert!(changed.validate().is_err());
        for path in ["/VAR/run/test","/Tmp/test","/ETC/test","/Private/var/test","/private/VAR/test",
            "/private/Tmp/test","/private/ETC/test","/state/caf\u{00e9}","/state/cafe\u{0301}"] {
            assert!(normalized_path(Path::new(path)).is_err());
            let mut changed=a.clone();changed.layout.binary_dir=path.into();assert!(changed.validate().is_err());
        }
        assert_eq!(normalized_path(Path::new("/var/MixedCase")).unwrap(),Path::new("/private/var/MixedCase"));
        assert_eq!(normalized_path(Path::new("/state/MixedCase")).unwrap(),Path::new("/state/MixedCase"));
        assert!(overlap(Path::new("/state/A"),Path::new("/STATE/a/child")).unwrap());
        assert!(!overlap(Path::new("/state/A"),Path::new("/state/Ab")).unwrap());
    }
    #[test]
    fn deployment_paths_names_and_fixed_derivations_reject_alias_tricks() {
        let mut t=target("dedicated",DeploymentRole::DedicatedTest);
        for path in ["relative","/a/../b","/a/./b","/a//b","/a/b/","/","/a/$x","/a/line\n"] {
            t.layout.binary_dir=path.into();assert!(t.validate().is_err());
        }
        let t=target("dedicated",DeploymentRole::DedicatedTest);
        assert!(normalized_path(Path::new("/var/run/mesh")).unwrap()==Path::new("/private/var/run/mesh"));
        assert!(normalized_path(Path::new("/variable/mesh")).unwrap()==Path::new("/variable/mesh"));
        assert!(overlap(Path::new("/var/run/mesh"),Path::new("/private/var/run/mesh/child")).unwrap());
        for name in ["com..bad","com.bad-","com.UPPER","-com.bad","com.bad space"] {
            let mut bad=t.clone();bad.layout.mach_service=name.into();assert!(bad.validate().is_err());
        }
        for size in [127usize,128,129] {
            let mut bounded=t.clone();
            bounded.layout.mach_service=format!("{}.{}.c", "a".repeat(63), "b".repeat(size-66));
            // Keep every label valid so total bootstrap width is decisive.
            assert_eq!(bounded.layout.mach_service.len(),size);
            assert_eq!(bounded.validate().is_ok(),size==127);
        }
        assert_eq!(t.intent_socket(501).unwrap(),t.layout.socket_root.join("intent/501/intent.sock"));
        assert!(t.intent_socket(0).is_err());
        assert_eq!(t.supervisor_socket(),t.layout.socket_root.join("supervisor/supervisor.sock"));
        assert_eq!(t.broker_socket(),t.layout.socket_root.join("apfs-broker/broker.sock"));
        let mut equal=t.clone();equal.layout.custody_bundle=equal.layout.support_root.clone();
        assert!(equal.validate().is_err());
    }
    #[test]
    fn deployment_dedicated_target_independently_excludes_installed_roots() {
        let t=target("dedicated",DeploymentRole::DedicatedTest);
        for root in ["/opt/enterprise/enclave/bin/child","/private/var/run/enclave","/var/db/enclave/child", "/var/log/enclave", "/Library/Application Support/EnterpriseEnclave/test"] {
            let mut bad=t.clone();bad.layout.staging_root=root.into();assert!(bad.validate().is_err());
        }
        let mut bad=t.clone();bad.codesign_pins_file=crate::codesign::PIN_FILE.into();assert!(bad.validate().is_err());
        let mut bad=t.clone();bad.layout.launchd_namespace="com.enterprise.enclave".into();assert!(bad.validate().is_err());
        let mut bad=t;bad.layout.mach_service="com.enterprise.enclave.exception".into();assert!(bad.validate().is_err());
    }
    #[test]
    fn deployment_pair_excludes_cross_target_outputs_and_requires_explicit_read_sharing() {
        let dedicated=target("dedicated",DeploymentRole::DedicatedTest);
        let existing=target("existing",DeploymentRole::ExistingUpgrade);
        dedicated.validate_pair(&existing).unwrap();
        for path in [&dedicated.layout.binary_dir,&dedicated.layout.custody_bundle,&dedicated.layout.sandbox_dir,
            &dedicated.layout.socket_root,&dedicated.layout.state_root,&dedicated.layout.audit_root,
            &dedicated.layout.cas_store_root,&dedicated.layout.staging_root,&dedicated.layout.support_root] {
            let mut bad=existing.clone();bad.layout.staging_root=path.join("nested");assert!(dedicated.validate_pair(&bad).is_err());
        }
        let mut bad=existing.clone();bad.codesign_pins_file=dedicated.codesign_pins_file.clone();assert!(dedicated.validate_pair(&bad).is_err());
        let mut a=dedicated;let mut b=existing;
        a.authority_config="/shared-public/authority.json".into();b.authority_config=a.authority_config.clone();
        assert!(a.validate_pair(&b).is_err());a.shared_read_only_inputs.push(a.authority_config.clone());
        assert!(a.validate_pair(&b).is_err());b.shared_read_only_inputs=a.shared_read_only_inputs.clone();a.validate_pair(&b).unwrap();
        let shared=b.layout.support_root.join("authority.json");a.authority_config=shared.clone();b.authority_config=shared.clone();
        a.shared_read_only_inputs=vec![shared.clone()];b.shared_read_only_inputs=vec![shared];a.validate_pair(&b).unwrap();
        a.shared_read_only_inputs.push(a.codesign_pins_file.clone());assert!(a.validate().is_err());
    }
    #[test]
    fn deployment_context_freezes_default_or_one_checked_target_without_union() {
        let mut slot=ContextSlot::empty();assert_eq!(slot.pin_file(),Path::new(crate::codesign::PIN_FILE));
        assert!(slot.select(checked_fixture(target("dedicated",DeploymentRole::DedicatedTest))).is_err());
        let mut slot=ContextSlot::empty();let selected=checked_fixture(target("dedicated",DeploymentRole::DedicatedTest));
        let expected=selected.target.codesign_pins_file.clone();slot.select(selected.clone()).unwrap();
        assert!(slot.select(selected).is_err());assert_eq!(slot.pin_file(),expected);
        assert!(slot.select(checked_fixture(target("existing",DeploymentRole::ExistingUpgrade))).is_err());
        assert_eq!(slot.pin_file(),expected);
    }
    struct Fixture {base:PathBuf,config:PathBuf,pins:PathBuf}
    impl Fixture {
        fn new()->Self {
            let parent=std::env::var_os("ENCLAVE_TEST_STATE_ROOT").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
            let base=parent.join(format!("deployment-b1-{}",crate::rng::u64()));
            std::fs::create_dir(&base).unwrap();std::fs::set_permissions(&base,std::fs::Permissions::from_mode(0o700)).unwrap();
            let support=base.join("support");std::fs::create_dir(&support).unwrap();
            let mut t=target("dedicated",DeploymentRole::DedicatedTest);t.layout.support_root=support.clone();t.layout.custody_bundle=support.join("Custody.app");
            t.authority_config=support.join("authority.json");t.expected_artifacts_manifest=support.join("artifacts.json");t.codesign_pins_file=support.join("pins.json");
            for p in [&t.authority_config,&t.expected_artifacts_manifest] {std::fs::write(p,b"{}").unwrap();}
            let pins=t.codesign_pins_file.clone();write_pins(&pins,"ab");
            let config=base.join("deployment.json");std::fs::write(&config,serde_json::to_vec(&t).unwrap()).unwrap();
            Self {base,config,pins}
        }
        fn root_protection_available(&self)->bool {
            #[cfg(target_os="macos")]
            let path=normalized_path(&self.config).unwrap();
            #[cfg(not(target_os="macos"))]
            let path=self.config.clone();
            // Classify actual fixture ownership before the tested load. A load
            // regression on a supported fixture must FAIL, never become UNKNOWN.
            for ancestor in path.ancestors() {
                let m=std::fs::symlink_metadata(ancestor).unwrap();
                if !protected(&m) || m.file_type().is_symlink() {
                    eprintln!("UNKNOWN_DEPLOYMENT_FULL_PATH_PROTECTION: actual fixture chain is not immutable root-owned");
                    return false;
                }
            }
            load(&self.config).unwrap();true
        }
    }
    impl Drop for Fixture { fn drop(&mut self) {let _=std::fs::remove_dir_all(&self.base);} }
    fn write_pins(path:&Path,hash:&str) {
        let pins=serde_json::json!({"v":1,"pins":{"com.enterprise.enclave.ctl":[hash.repeat(20)],
            "com.enterprise.enclave.custody":[hash.repeat(20)]}});
        std::fs::write(path,serde_json::to_vec(&pins).unwrap()).unwrap();
        std::fs::set_permissions(path,std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[test]
    fn deployment_protected_loader_rejects_unsafe_files_and_ancestors() {
        let f=Fixture::new();if !f.root_protection_available() {return;}
        assert_eq!(std::fs::metadata(&f.pins).unwrap().uid(),0);
        assert_eq!(load(&f.config).unwrap().config_path(),f.config.as_path());
        let descriptor=std::fs::read(&f.config).unwrap();let mut wrong=DeploymentTarget::parse(&descriptor).unwrap();
        wrong.signing_identity_mode=match wrong.signing_identity_mode {
            DeploymentSigningMode::LocalPins=>DeploymentSigningMode::TeamId,
            DeploymentSigningMode::TeamId=>DeploymentSigningMode::LocalPins,
        };
        std::fs::write(&f.config,serde_json::to_vec(&wrong).unwrap()).unwrap();
        assert!(load(&f.config).unwrap_err().is("DEPLOYMENT_SIGNING_MODE"));std::fs::write(&f.config,descriptor).unwrap();
        std::fs::set_permissions(&f.pins,std::fs::Permissions::from_mode(0o620)).unwrap();assert!(load(&f.config).is_err());
        std::fs::set_permissions(&f.pins,std::fs::Permissions::from_mode(0o600)).unwrap();
        let link=f.base.join("pin-hardlink");std::fs::hard_link(&f.pins,&link).unwrap();assert!(load(&f.config).is_err());std::fs::remove_file(link).unwrap();
        let saved=f.base.join("saved-pins");std::fs::rename(&f.pins,&saved).unwrap();symlink(&saved,&f.pins).unwrap();assert!(load(&f.config).is_err());
        std::fs::remove_file(&f.pins).unwrap();std::fs::rename(saved,&f.pins).unwrap();
        let alias=f.base.join("support-alias");symlink(f.pins.parent().unwrap(),&alias).unwrap();
        assert!(read_protected_public(&alias.join("pins.json"),MAX_REFERENCE_BYTES).is_err());
        std::fs::set_permissions(f.pins.parent().unwrap(),std::fs::Permissions::from_mode(0o770)).unwrap();assert!(load(&f.config).is_err());
        std::fs::set_permissions(f.pins.parent().unwrap(),std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(read_protected_public(&f.pins,1).is_err());
        let original=std::fs::read(&f.pins).unwrap();std::os::unix::fs::chown(&f.pins,Some(4242),None).unwrap();
        if std::fs::metadata(&f.pins).unwrap().uid()==4242 {
            assert!(load(&f.config).is_err());std::os::unix::fs::chown(&f.pins,Some(0),None).unwrap();
            assert_eq!(std::fs::metadata(&f.pins).unwrap().uid(),0);std::fs::write(&f.pins,original).unwrap();
        } else { eprintln!("UNKNOWN_DEPLOYMENT_WRONG_OWNER: filesystem did not apply distinct chown"); }
    }
    #[test]
    fn deployment_inventory_read_binds_descriptor_and_protected_reference() {
        let f=Fixture::new();if !f.root_protection_available() {return;}
        let selected=load(&f.config).unwrap();
        assert_eq!(selected.descriptor_sha256(),hex::encode(Sha256::digest(std::fs::read(&f.config).unwrap())));
        assert_eq!(selected.read_artifact_inventory().unwrap(),b"{}");
        let inventory=&selected.target().expected_artifacts_manifest;
        std::fs::set_permissions(inventory,std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(selected.read_artifact_inventory().is_err());
        std::fs::set_permissions(inventory,std::fs::Permissions::from_mode(0o644)).unwrap();
        let original=std::fs::read(&f.config).unwrap();
        let mut changed=original.clone();changed.push(b'\n');std::fs::write(&f.config,changed).unwrap();
        assert!(selected.read_artifact_inventory().unwrap_err().is("DEPLOYMENT_CHANGED"));
        std::fs::write(&f.config,original).unwrap();
        assert_eq!(selected.read_artifact_inventory().unwrap(),b"{}");
        let backup=f.base.join("inventory-backup");std::fs::rename(inventory,&backup).unwrap();
        symlink(&backup,inventory).unwrap();assert!(selected.read_artifact_inventory().is_err());
    }
    #[test]
    fn deployment_process_pin_selection_and_fresh_boundary_revocation() {
        const CHILD:&str="MCPMAC_DEPLOYMENT_B1_TEST_CHILD";
        if let Some(mode)=std::env::var_os(CHILD) {
            let path=PathBuf::from(std::env::var_os("MCPMAC_DEPLOYMENT_B1_TEST_CONFIG").unwrap());
            let checked=load(&path).unwrap();let clone=checked.clone();
            if mode=="default" {
                let _=crate::codesign::CodeRequirement::ctl();assert!(select(checked).is_err());return;
            }
            if mode=="fresh-default" {
                let _=crate::codesign::CodeRequirement::pinned_boundary(crate::codesign::CTL_IDENTIFIER);
                assert!(select(checked).is_err());return;
            }
            select(checked).unwrap();assert!(select(clone).is_err());
            let target=selected().unwrap().target();
            let mut args=crate::runtime::DaemonArgs::parse(["daemon".to_owned(),"--deployment-target".into(),path.to_str().unwrap().into(),
                "--profile".into(),target.profile.to_string(),"--socket-dir".into(),target.layout.socket_root.to_str().unwrap().into(),
                "--audit-dir".into(),target.layout.audit_root.to_str().unwrap().into()]).unwrap();
            args.bind_deployment_context().unwrap();
            args.inherit_listener_fd=Some(123);
            assert!(args.bind_deployment_context().unwrap_err().is("DEPLOYMENT_INHERITED_LISTENER_UNAVAILABLE"));
            args.inherit_listener_fd=None;
            for daemon in crate::daemon::DaemonId::ALL {
                args.state_dir=Some(target.layout.state_root.join(daemon.dir_name()));
                args.sandbox_profile=Some(target.layout.sandbox_dir.join(format!("{}.sb",daemon.plist_suffix())));
                args.bind_deployment_for_daemon(daemon).unwrap();
                let mut wrong=args.clone();wrong.state_dir=Some(target.layout.state_root.join("substituted"));
                assert!(wrong.bind_deployment_for_daemon(daemon).is_err());
                let mut wrong=args.clone();wrong.sandbox_profile=Some(target.layout.sandbox_dir.join("substituted.sb"));
                assert!(wrong.bind_deployment_for_daemon(daemon).is_err());
                let mut missing=args.clone();missing.state_dir=None;assert!(missing.bind_deployment_for_daemon(daemon).is_err());
                let mut missing=args.clone();missing.sandbox_profile=None;assert!(missing.bind_deployment_for_daemon(daemon).is_err());
            }
            args.profile=Profile::L1;assert!(args.bind_deployment_context().is_err());
            assert!(crate::runtime::check_identity(crate::daemon::DaemonId::CustodyVault,&args).unwrap_err().is("DEPLOYMENT_ARGUMENTS"));
            args.profile=target.profile;
            args.dev_same_uid=true;assert!(args.bind_deployment_context().is_err());args.dev_same_uid=false;
            args.socket_dir="/foreign/run".into();assert!(args.bind_deployment_context().is_err());args.socket_dir=target.layout.socket_root.clone();
            args.extra.push(("deployment-target".into(),path.to_str().unwrap().into()));assert!(args.bind_deployment_context().is_err());args.extra.pop();
            args.extra.clear();assert!(args.bind_deployment_context().is_err());
            let identifier="com.enterprise.enclave.custody";
            let ordinary=crate::codesign::CodeRequirement::daemon(crate::daemon::DaemonId::CustodyVault);
            assert_eq!(ordinary.cdhash_allowlist,vec!["ab".repeat(20)]);
            let identity=|hash:&str|crate::codesign::CodeIdentity {identifier:identifier.into(),team_id:crate::codesign::TEAM_ID.into(),cdhash:hash.repeat(20)};
            assert!(ordinary.matches(&identity("ab")));assert!(!ordinary.matches(&identity("cd")));
            let foreign=path.parent().unwrap().join("separate-foreign-pins.json");write_pins(&foreign,"cd");
            let foreign_manifest=crate::codesign::pins::load(&foreign).unwrap();
            let foreign_requirement=crate::codesign::CodeRequirement::pinned_from_manifest(identifier,&foreign_manifest).unwrap();
            assert!(foreign_requirement.matches(&identity("cd")));assert!(!foreign_requirement.matches(&identity("ab")));
            assert!(!ordinary.matches(&identity("cd")),"selected ordinary pins cannot union the other file's hashes");
            let pin=selected_pin_file();write_pins(&pin,"cd");
            let fresh=crate::codesign::CodeRequirement::pinned_boundary(identifier).unwrap();
            assert!(!fresh.matches(&identity("ab")));assert!(fresh.matches(&identity("cd")));
            assert_eq!(crate::codesign::CodeRequirement::daemon(crate::daemon::DaemonId::CustodyVault).cdhash_allowlist,ordinary.cdhash_allowlist);
            assert!(crate::codesign::CodeRequirement::pinned_boundary(crate::codesign::INTENT_IDENTIFIER).is_err());
            let missing=crate::codesign::CodeRequirement::intent();assert_eq!(missing.requirement_text(),"never");
            assert!(!missing.matches(&crate::codesign::CodeIdentity {identifier:crate::codesign::INTENT_IDENTIFIER.into(),team_id:crate::codesign::TEAM_ID.into(),cdhash:"ab".repeat(20)}));
            std::fs::remove_file(pin).unwrap();assert!(crate::codesign::CodeRequirement::pinned_boundary(identifier).is_err());
            return;
        }
        let f=Fixture::new();if !f.root_protection_available() {return;}
        // The coordinator's exact private chroot intentionally has no /proc.
        // Only that declared harness may use its fixed copied test executable.
        let executable=std::env::current_exe().or_else(|error| {
            if std::env::var_os("ENCLAVE_TEST_STATE_ROOT").as_deref()==Some(std::ffi::OsStr::new("/state"))
                && std::fs::symlink_metadata("/test-binary").is_ok_and(|m|m.is_file()) {
                Ok(PathBuf::from("/test-binary"))
            } else { Err(error) }
        }).unwrap();
        for mode in ["default","fresh-default","selected"] {
            write_pins(&f.pins,"ab");
            let lease=f.pins.parent().unwrap().join(startup_lease::STARTUP_LIFETIME_LEAF);
            if !lease.exists() {
                std::fs::write(&lease,b"").unwrap();
                std::fs::set_permissions(&lease,std::fs::Permissions::from_mode(0o644)).unwrap();
            }
            let output=std::process::Command::new(&executable)
                .args(["--exact","deployment::tests::deployment_process_pin_selection_and_fresh_boundary_revocation","--nocapture"])
                .env(CHILD,mode).env("MCPMAC_DEPLOYMENT_B1_TEST_CONFIG",&f.config)
                .stdin(std::process::Stdio::inherit()).output().unwrap();
            assert!(output.status.success(),"{} {}",String::from_utf8_lossy(&output.stdout),String::from_utf8_lossy(&output.stderr));
        }
    }

    #[test]
    #[ignore = "requires actual root-protected fixture ancestry and subprocess executable"]
    fn deployment_upgrade_startup_rechecks_before_selection_and_service_effects() {
        const CHILD:&str="MCPMAC_UPGRADE_STARTUP_TEST_CHILD";
        const CONFIG:&str="MCPMAC_UPGRADE_STARTUP_TEST_CONFIG";
        if let Some(mode)=std::env::var_os(CHILD) {
            let path=PathBuf::from(std::env::var_os(CONFIG).unwrap());
            let checked=load(&path).unwrap();let target=checked.target().clone();
            let marker=target.layout.support_root.join(upgrade::UPGRADE_INHIBITION_LEAF);
            let mut args=crate::runtime::DaemonArgs::parse(["daemon".to_owned(),"--deployment-target".into(),
                path.to_str().unwrap().into(),"--profile".into(),target.profile.to_string(),"--socket-dir".into(),
                target.layout.socket_root.to_str().unwrap().into(),"--audit-dir".into(),
                target.layout.audit_root.to_str().unwrap().into()]).unwrap();
            if mode=="delayed" {
                args.bind_deployment_context().unwrap();assert!(selected().is_some());
                std::fs::write(&marker,b"{").unwrap();
            } else {
                assert!(selected().is_none());
                assert!(args.bind_deployment_context().unwrap_err().is("DEPLOYMENT_UPGRADE_INHIBITED"));
                assert!(selected().is_none(),"failed startup must not select a context");
            }
            // Denial does not prevent general checked loading/selection used by
            // teardown, quiescence, diagnostics and future forward recovery.
            let current=load(&path).unwrap();
            if selected().is_none() {select(current).unwrap();}
            let denial=if mode=="delayed" {
                assert!(args.bind_deployment_context().unwrap_err().is("DEPLOYMENT_UPGRADE_INHIBITED"));
                "STARTUP_LEASE_POISONED"
            }else {"DEPLOYMENT_UPGRADE_INHIBITED"};
            for daemon in crate::daemon::DaemonId::ALL {
                args.state_dir=Some(target.layout.state_root.join(daemon.dir_name()));
                args.sandbox_profile=Some(target.layout.sandbox_dir.join(format!("{}.sb",daemon.plist_suffix())));
                assert!(args.bind_deployment_for_daemon(daemon).unwrap_err().is(denial));
                assert!(crate::runtime::check_identity(daemon,&args).unwrap_err().is(denial));
                let called=std::sync::atomic::AtomicBool::new(false);
                let error=crate::runtime::run_service_with_startup::<(),(),_,_,_>(daemon,&args,|| {
                    called.store(true,std::sync::atomic::Ordering::SeqCst);
                    Ok((|_:&crate::ipc::PeerCredentials,_:()|Ok(()),()))
                },||{}).unwrap_err();
                assert!(error.is(denial));
                assert!(!called.load(std::sync::atomic::Ordering::SeqCst),"initializer ran under inhibition");
            }
            let stop=std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
            assert!(crate::supervisor::serve_with_profile(&target.layout.socket_root,true,target.profile,stop)
                .unwrap_err().is(denial));
            assert_eq!(std::fs::read(&marker).unwrap(),if mode=="delayed" {b"{".as_slice()}else {b"".as_slice()});
            return;
        }
        assert_eq!(unsafe {libc::geteuid()},0,"this ignored fixture requires actual root, without a gate bypass");
        let executable=std::env::current_exe().or_else(|error| {
            if std::env::var_os("ENCLAVE_TEST_STATE_ROOT").as_deref()==Some(std::ffi::OsStr::new("/state"))
                && std::fs::symlink_metadata("/test-binary").is_ok_and(|m|m.is_file()) {
                Ok(PathBuf::from("/test-binary"))
            }else {Err(error)}
        }).unwrap();
        for role in [DeploymentRole::DedicatedTest,DeploymentRole::ExistingUpgrade] {
            for profile in [Profile::L2,Profile::L3] {
                let f=Fixture::new();let mut target=DeploymentTarget::parse(&std::fs::read(&f.config).unwrap()).unwrap();
                target.role=role;target.profile=profile;
                let support=target.layout.support_root.clone();
                std::fs::set_permissions(&support,std::fs::Permissions::from_mode(0o700)).unwrap();
                let lease=support.join(startup_lease::STARTUP_LIFETIME_LEAF);
                std::fs::write(&lease,b"").unwrap();
                std::fs::set_permissions(&lease,std::fs::Permissions::from_mode(0o644)).unwrap();
                if profile==Profile::L3 {
                    let root=support.join("broker-root.json");std::fs::write(&root,b"{}").unwrap();
                    std::fs::set_permissions(&root,std::fs::Permissions::from_mode(0o644)).unwrap();
                    target.broker=Some(DeploymentBroker {base_dir:target.layout.state_root.join("apfs-broker"),tuf_root_file:root});
                }
                std::fs::write(&f.config,serde_json::to_vec(&target).unwrap()).unwrap();
                for path in [&f.config,&target.authority_config,&target.expected_artifacts_manifest] {
                    std::fs::set_permissions(path,std::fs::Permissions::from_mode(0o644)).unwrap();
                }
                assert!(f.root_protection_available(),"UNKNOWN root protection cannot pass this ignored fixture");
                let marker=support.join(upgrade::UPGRADE_INHIBITION_LEAF);
                for mode in ["initial-present","delayed"] {
                    if mode=="initial-present" {std::fs::write(&marker,b"").unwrap();}
                    else {std::fs::remove_file(&marker).unwrap();}
                    let output=std::process::Command::new(&executable)
                        .args(["--ignored","--exact","deployment::tests::deployment_upgrade_startup_rechecks_before_selection_and_service_effects","--nocapture"])
                        .env(CHILD,mode).env(CONFIG,&f.config)
                        .stdin(std::process::Stdio::inherit()).output().unwrap();
                    assert!(output.status.success(),"{} {}",String::from_utf8_lossy(&output.stdout),String::from_utf8_lossy(&output.stderr));
                }
            }
        }
    }

    #[test]
    #[ignore = "requires actual root-protected fixture ancestry and subprocess executable"]
    fn deployment_actor_retains_real_shared_lease_but_administrative_selection_does_not() {
        use std::os::fd::AsRawFd;
        const CHILD:&str="MCPMAC_ACTOR_LIFETIME_TEST_CHILD";
        const CONFIG:&str="MCPMAC_ACTOR_LIFETIME_TEST_CONFIG";
        const TEST:&str="deployment::tests::deployment_actor_retains_real_shared_lease_but_administrative_selection_does_not";
        let executable=||std::env::current_exe().or_else(|error| {
            if std::env::var_os("ENCLAVE_TEST_STATE_ROOT").as_deref()==Some(std::ffi::OsStr::new("/state"))
                && std::fs::symlink_metadata("/test-binary").is_ok_and(|m|m.is_file()) {
                Ok(PathBuf::from("/test-binary"))
            }else {Err(error)}
        }).unwrap();
        if let Some(mode)=std::env::var_os(CHILD) {
            let path=PathBuf::from(std::env::var_os(CONFIG).unwrap());
            let checked=load(&path).unwrap();let target=checked.target().clone();
            let leaf=target.layout.support_root.join(startup_lease::STARTUP_LIFETIME_LEAF);
            if mode=="probe-free" || mode=="probe-busy" {
                // Independent process and independent open description. This
                // raw fixture probe grants no native EX/maintenance authority.
                let file=File::open(&leaf).unwrap();
                let result=unsafe {libc::flock(file.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)};
                if mode=="probe-free" {assert_eq!(result,0);}else {
                    assert_ne!(result,0);
                    let error=std::io::Error::last_os_error().raw_os_error();
                    assert!(error==Some(libc::EWOULDBLOCK)||error==Some(libc::EAGAIN));
                }
                return;
            }
            let probe=|mode:&str| {
                let output=std::process::Command::new(executable())
                    .args(["--ignored","--exact",TEST,"--nocapture"])
                    .env(CHILD,mode).env(CONFIG,&path)
                    .stdin(std::process::Stdio::inherit()).output().unwrap();
                assert!(output.status.success(),"{} {}",String::from_utf8_lossy(&output.stdout),String::from_utf8_lossy(&output.stderr));
            };
            select(checked).unwrap();
            let marker=target.layout.support_root.join(upgrade::UPGRADE_INHIBITION_LEAF);
            let make_args=||crate::runtime::DaemonArgs::parse(["daemon".to_owned(),"--deployment-target".into(),
                path.to_str().unwrap().into(),"--profile".into(),target.profile.to_string(),"--socket-dir".into(),
                target.layout.socket_root.to_str().unwrap().into(),"--audit-dir".into(),
                target.layout.audit_root.to_str().unwrap().into()]).unwrap();
            let args=make_args();
            if mode=="missing" {
                assert!(args.bind_deployment_context().unwrap_err().is("STARTUP_LEASE_MISSING_OR_UNKNOWN"));
                assert!(!leaf.exists(),"startup repaired missing leaf");
                assert!(load(&path).is_ok(),"administrative loading remains available");return;
            }
            probe("probe-free"); // load/select did not acquire actor SH
            args.bind_deployment_context().unwrap();
            args.bind_deployment_context().unwrap(); // same retained owner
            drop(args);
            probe("probe-busy"); // lifetime exceeds the successful stack frame
            std::fs::write(&marker,b"SYNTHETIC DENIAL").unwrap();
            assert!(make_args().bind_deployment_context().unwrap_err().is("DEPLOYMENT_UPGRADE_INHIBITED"));
            assert!(load(&path).is_ok());probe("probe-busy");
            std::fs::remove_file(&marker).unwrap(); // fixture only; no product clear API
            assert!(make_args().bind_deployment_context().unwrap_err().is("STARTUP_LEASE_POISONED"));
            probe("probe-busy"); // poison cannot release or revive actor SH
            return;
        }
        assert_eq!(unsafe {libc::geteuid()},0,"actual protected-root fixture required");
        for role in [DeploymentRole::DedicatedTest,DeploymentRole::ExistingUpgrade] {
            for profile in [Profile::L2,Profile::L3] {
                let f=Fixture::new();let mut target=DeploymentTarget::parse(&std::fs::read(&f.config).unwrap()).unwrap();
                target.role=role;target.profile=profile;
                let support=target.layout.support_root.clone();
                if profile==Profile::L3 {
                    let root=support.join("broker-root.json");std::fs::write(&root,b"{}").unwrap();
                    std::fs::set_permissions(&root,std::fs::Permissions::from_mode(0o644)).unwrap();
                    target.broker=Some(DeploymentBroker {base_dir:target.layout.state_root.join("apfs-broker"),tuf_root_file:root});
                }
                std::fs::write(&f.config,serde_json::to_vec(&target).unwrap()).unwrap();
                assert!(f.root_protection_available(),"unknown protection is not PASS");
                let leaf=support.join(startup_lease::STARTUP_LIFETIME_LEAF);
                for mode in ["missing","retained"] {
                    if mode=="retained" {
                        std::fs::write(&leaf,b"").unwrap();
                        std::fs::set_permissions(&leaf,std::fs::Permissions::from_mode(0o644)).unwrap();
                    }
                    let output=std::process::Command::new(executable())
                        .args(["--ignored","--exact",TEST,"--nocapture"])
                        .env(CHILD,mode).env(CONFIG,&f.config)
                        .stdin(std::process::Stdio::inherit()).output().unwrap();
                    assert!(output.status.success(),"{} {}",String::from_utf8_lossy(&output.stdout),String::from_utf8_lossy(&output.stderr));
                    if mode=="retained" {
                        let file=File::open(&leaf).unwrap();
                        assert_eq!(unsafe {libc::flock(file.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)},0,
                            "actual actor process exit did not release its SH");
                    }
                }
            }
        }
    }
}
