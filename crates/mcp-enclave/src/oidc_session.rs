//! Explicit root provisioning of the public, current-console OIDC binding.
//!
//! This writes no OAuth, principal, signing or code-pin authority. Renewal
//! replaces the exact identity bytes so previously admitted broker transactions
//! and custody proofs fail their existing digest rechecks. There is no automatic
//! login watcher or host invocation in this module's tests.

use enclave_core::{error::EnclaveResult, fail};
use serde::Serialize;
#[cfg(any(target_os = "macos", test))]
use std::{ffi::CString, fs::{File, Metadata}, io::{Read, Write}, os::{fd::{AsRawFd, FromRawFd}, unix::fs::MetadataExt}, path::{Component, Path, PathBuf}};
#[cfg(any(target_os = "macos", test))]
use enclave_core::{codesign, daemon::DaemonId, err};
#[cfg(any(target_os = "macos", test))]
use serde::Deserialize;
#[cfg(any(target_os = "macos", test))]
use sha2::{Digest, Sha256};

#[cfg(target_os = "macos")]
const DIRECTORY: &str = "/Library/Application Support/EnterpriseEnclave";
#[cfg(any(target_os = "macos", test))]
const IDENTITY: &str = "oidc-broker-identity.json";
#[cfg(any(target_os = "macos", test))]
const OAUTH: &str = "oidc-oauth.json";
#[cfg(any(target_os = "macos", test))]
const PINS: &str = "codesign-pins.json";
#[cfg(any(target_os = "macos", test))]
const LOCK: &str = ".oidc-session-renew.lock";
#[cfg(any(target_os = "macos", test))]
const HIGH_WATER: &str = "oidc-session-highwater.json";

/// Public receipt of one successfully persisted identity replacement. It carries
/// no username, audit token, OAuth token or principal identifier.
#[derive(Debug, Serialize)]
pub struct SessionReceipt {
    /// Exact default or selected destination used by both production peers.
    pub identity_path: String,
    /// Digest of the exact compact sorted JSON bytes that were persisted.
    pub identity_sha256: String,
    /// Exclusive operator-selected expiry, bounded by existing OAuth authority.
    pub expires_unix: i64,
}

/// Replace the fixed public session record as root on macOS. The actual native
/// console UID/AuditID must be available; there are no caller identity overrides.
/// The explicit expiry must be future, no later than protected OAuth expiry,
/// and be strictly later than every prior identity produced through this seam.
/// A separate protected marker retains the global expiry floor even if the
/// public identity is removed. This same-disk state is not native rollback
/// resistance; deleting both records or restoring older storage is outside the
/// renewal seam. This command neither
/// starts a browser nor installs/starts a helper. Any uncertain publication or
/// changed session/configuration returns an error, never a success receipt.
pub fn renew_current_session(expires_unix: i64) -> EnclaveResult<SessionReceipt> {
    if enclave_core::deployment::selected().is_some() {
        return renew_target_current_session(expires_unix);
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = expires_unix;
        fail!(ENOSYS, "OIDC_SESSION_NATIVE_REQUIRED");
    }
    #[cfg(target_os = "macos")]
    {
        if unsafe { libc::geteuid() } != 0 { fail!(EACCES, "OIDC_SESSION_ROOT_REQUIRED"); }
        let directory = protected::Directory::open(Path::new(DIRECTORY))?;
        protected::renew_in(&directory, expires_unix, &mut || {
            let (uid, audit) = enclave_custody_vaultd::oidc_acquisition::current_console_session()
                .ok_or_else(|| err!(EACCES, "OIDC_SESSION_UNAVAILABLE"))?;
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| err!(EACCES, "OIDC_SESSION_CLOCK"))?.as_secs();
            Ok((uid, audit, i64::try_from(now).map_err(|_| err!(EACCES, "OIDC_SESSION_CLOCK"))?))
        })
    }
}

/// Renew only within the actual selected checked deployment. Selection changes
/// routing, not the OIDC signing identifier or current-console authority. No
/// selected path or pin read falls back to the installed default.
pub fn renew_target_current_session(expires_unix: i64) -> EnclaveResult<SessionReceipt> {
    let checked = enclave_core::deployment::selected()
        .ok_or_else(|| enclave_core::err!(EACCES, "DEPLOYMENT_CONTEXT_REQUIRED"))?;
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (checked, expires_unix);
        fail!(ENOSYS, "OIDC_SESSION_NATIVE_REQUIRED");
    }
    #[cfg(target_os = "macos")]
    {
        if unsafe { libc::geteuid() } != 0 { fail!(EACCES, "OIDC_SESSION_ROOT_REQUIRED"); }
        checked.read_artifact_inventory()?;
        let target = checked.target();
        let support = enclave_core::deployment::normalized_path(&target.layout.support_root)?;
        let pin_path = enclave_core::deployment::normalized_path(&target.codesign_pins_file)?;
        let socket_root = &target.layout.socket_root;
        let directory = protected::Directory::open(&support)?;
        let pin_directory = protected::Directory::open(pin_path.parent()
            .ok_or_else(|| err!(EACCES, "OIDC_SESSION_PATH"))?)?;
        let pin_leaf = pin_path.file_name().and_then(|v| v.to_str())
            .ok_or_else(|| err!(EACCES, "OIDC_SESSION_PATH"))?;
        let scope = protected::Renewal { directory: &directory, pin_directory: &pin_directory,
            pin_leaf, socket_root, checked: Some(checked) };
        protected::renew_scoped(&scope, expires_unix, &mut || {
            let (uid, audit) = enclave_custody_vaultd::oidc_acquisition::current_console_session()
                .ok_or_else(|| err!(EACCES, "OIDC_SESSION_UNAVAILABLE"))?;
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| err!(EACCES, "OIDC_SESSION_CLOCK"))?.as_secs();
            Ok((uid, audit, i64::try_from(now).map_err(|_| err!(EACCES, "OIDC_SESSION_CLOCK"))?))
        })
    }
}

#[cfg(any(target_os = "macos", test))]
mod protected {
use super::*;
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    v: u8,
    socket: String,
    identifier: String,
    console_uid: u32,
    audit_session_id: u32,
    expires_unix: i64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Tombstone { v: u8, expires_unix: i64, invalid: bool }
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HighWater { v: u8, max_expires_unix: i64 }
impl HighWater {
    fn floor(raw: &[u8]) -> EnclaveResult<i64> {
        let value: Self = serde_json::from_slice(raw).map_err(|_| err!(EACCES, "OIDC_SESSION_HIGHWATER_INVALID"))?;
        if canonical(&value)? != raw || value.v != 1 || value.max_expires_unix < 0 {
            fail!(EACCES, "OIDC_SESSION_HIGHWATER_INVALID");
        }
        Ok(value.max_expires_unix)
    }
}
impl Identity {
    #[cfg(test)]
    fn expiry_floor(raw: &[u8]) -> EnclaveResult<i64> {
        Self::expiry_floor_at(raw, Path::new("/var/run/enclave"))
    }
    fn expiry_floor_at(raw: &[u8], socket_root: &Path) -> EnclaveResult<i64> {
        // A failed publication keeps the same monotonic floor in an explicit
        // tombstone that both ordinary consumers reject as an invalid schema.
        if let Ok(value) = serde_json::from_slice::<Tombstone>(raw) {
            if canonical(&value)? == raw && value.v == 1 && value.invalid && value.expires_unix >= 0 { return Ok(value.expires_unix); }
            fail!(EACCES, "OIDC_SESSION_PREVIOUS_INVALID");
        }
        let value: Self = serde_json::from_slice(raw).map_err(|_| err!(EACCES, "OIDC_SESSION_PREVIOUS_INVALID"))?;
        if canonical(&value)? != raw || value.v != 1 || value.identifier != crate::launchd::OIDC_LABEL
            || value.console_uid == 0 || value.console_uid == u32::MAX
            || value.audit_session_id == 0 || value.audit_session_id == u32::MAX || value.expires_unix < 0
            || value.socket != socket_path(socket_root, value.console_uid) {
            fail!(EACCES, "OIDC_SESSION_PREVIOUS_INVALID");
        }
        Ok(value.expires_unix)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OAuth {
    v: u8,
    issuer: String,
    audience: String,
    client_id: String,
    authorization_endpoint: String,
    token_endpoint: String,
    redirect_uri: String,
    callback_scheme: String,
    expires_unix: i64,
}

impl OAuth {
    fn parse(raw: &[u8], now: i64) -> EnclaveResult<Self> {
        let value: Self = serde_json::from_slice(raw).map_err(|_| err!(EACCES, "OIDC_SESSION_OAUTH_INVALID"))?;
        // The Swift consumer requires exact sorted compact JSON without escaped
        // slashes. Deserialize the closed typed struct first to reject duplicate
        // members, then compare its normalized representation to the input.
        if canonical(&value)? != raw || value.v != 1 || value.expires_unix <= now
            || value.audience.is_empty() || value.audience.len() > 1024
            || value.client_id.is_empty() || value.client_id.len() > 1024
            || value.client_id.chars().any(char::is_control)
            || !https_endpoint(&value.issuer) || !https_endpoint(&value.authorization_endpoint)
            || !https_endpoint(&value.token_endpoint)
            || !value.callback_scheme.starts_with("com.enterprise.enclave.oidc")
            || value.callback_scheme.len() > 128
            || !value.callback_scheme.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b".-".contains(&c))
            || !redirect(&value.redirect_uri, &value.callback_scheme)
        { fail!(EACCES, "OIDC_SESSION_OAUTH_INVALID"); }
        Ok(value)
    }
}

// Conservative ASCII URL admission; the browser independently performs its
// native URLComponents checks. Internationalized authorities and IPv6 literals
// require a reviewed parser extension, rather than guessed URL normalization.
fn authority(text: &str, allow_https_port: bool) -> bool {
    let host = text.split('/').next().unwrap_or("");
    let host = if allow_https_port { host.strip_suffix(":443").unwrap_or(host) } else { host };
    !host.is_empty() && host.len() <= 253
        && host.bytes().all(|c| c.is_ascii_alphanumeric() || b".-".contains(&c))
        && !host.starts_with('.') && !host.ends_with('.') && !host.contains("..")
}
fn url_bytes(text: &str) -> bool {
    !text.is_empty() && text.len() <= 2048
        && text.bytes().all(|c| (0x21..=0x7e).contains(&c) && !b"\\?#@".contains(&c))
}
fn https_endpoint(text: &str) -> bool {
    url_bytes(text) && text.strip_prefix("https://").is_some_and(|rest| authority(rest, true))
}
fn redirect(text: &str, scheme: &str) -> bool {
    url_bytes(text) && text.strip_prefix(&format!("{scheme}://")).is_some_and(|rest| authority(rest, false))
}
fn canonical(value: &impl Serialize) -> EnclaveResult<Vec<u8>> {
    // Workspace serde_json enables preserve_order. JCS explicitly sorts these
    // closed ASCII configuration member names regardless of map insertion order.
    enclave_core::jcs::to_jcs_bytes(value).map_err(|_| err!(EINVAL, "OIDC_SESSION_JSON"))
}

fn protected(metadata: &Metadata, directory: bool) -> bool {
    metadata.uid() == 0 && metadata.mode() & 0o022 == 0
        && if directory { metadata.is_dir() } else { metadata.is_file() && metadata.nlink() == 1 }
}
fn same_file(left: &Metadata, right: &Metadata) -> bool { left.dev() == right.dev() && left.ino() == right.ino() }
fn name(text: &str) -> EnclaveResult<CString> {
    CString::new(text).map_err(|_| err!(EINVAL, "OIDC_SESSION_PATH"))
}
fn opened(fd: i32) -> EnclaveResult<File> {
    if fd < 0 { fail!(EACCES, "OIDC_SESSION_PROTECTION"); }
    Ok(unsafe { File::from_raw_fd(fd) })
}
pub(super) struct Directory { file: File, path: PathBuf }
impl Directory {
    pub(super) fn open(path: &Path) -> EnclaveResult<Self> {
        if !path.is_absolute() { fail!(EACCES, "OIDC_SESSION_PROTECTION"); }
        let mut file = File::open("/").map_err(|_| err!(EACCES, "OIDC_SESSION_PROTECTION"))?;
        if !protected(&file.metadata().map_err(|_| err!(EACCES, "OIDC_SESSION_PROTECTION"))?, true) {
            fail!(EACCES, "OIDC_SESSION_PROTECTION");
        }
        for component in path.components() {
            match component {
                Component::RootDir => (),
                Component::Normal(component) => {
                    use std::os::unix::ffi::OsStrExt;
                    let component = CString::new(component.as_bytes()).map_err(|_| err!(EACCES, "OIDC_SESSION_PROTECTION"))?;
                    file = opened(unsafe { libc::openat(file.as_raw_fd(), component.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) })?;
                    if !protected(&file.metadata().map_err(|_| err!(EACCES, "OIDC_SESSION_PROTECTION"))?, true) {
                        fail!(EACCES, "OIDC_SESSION_PROTECTION");
                    }
                },
                _ => fail!(EACCES, "OIDC_SESSION_PROTECTION"),
            }
        }
        Ok(Self { file, path: path.to_owned() })
    }
    fn current(&self) -> EnclaveResult<()> {
        let fresh = Self::open(&self.path)?;
        if !same_file(&fresh.file.metadata().map_err(|_| err!(EIO, "OIDC_SESSION_STAT"))?,
            &self.file.metadata().map_err(|_| err!(EIO, "OIDC_SESSION_STAT"))?) {
            fail!(EACCES, "OIDC_SESSION_DIRECTORY_CHANGED");
        }
        Ok(())
    }
    fn read(&self, leaf: &str, limit: u64) -> EnclaveResult<Option<Vec<u8>>> {
        self.read_mode(leaf, limit, leaf == HIGH_WATER)
    }
    // A selected public pin file may have any basename in its independently
    // protected parent. Only the actual support marker requires mode 0600.
    fn read_public(&self, leaf: &str, limit: u64) -> EnclaveResult<Option<Vec<u8>>> {
        self.read_mode(leaf, limit, false)
    }
    fn read_mode(&self, leaf: &str, limit: u64, private: bool) -> EnclaveResult<Option<Vec<u8>>> {
        let leaf = name(leaf)?;
        let fd = unsafe { libc::openat(self.file.as_raw_fd(), leaf.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC) };
        if fd < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound { return Ok(None); }
        let mut file = opened(fd)?;
        let before = file.metadata().map_err(|_| err!(EIO, "OIDC_SESSION_STAT"))?;
        if !protected(&before, false) || before.len() == 0 || before.len() > limit
            || (private && before.mode() & 0o777 != 0o600) { fail!(EACCES, "OIDC_SESSION_PROTECTION"); }
        let mut bytes = Vec::new(); (&mut file).take(limit + 1).read_to_end(&mut bytes).map_err(|_| err!(EIO, "OIDC_SESSION_READ"))?;
        let after = file.metadata().map_err(|_| err!(EIO, "OIDC_SESSION_STAT"))?;
        if bytes.len() as u64 != before.len() || !protected(&after, false) || before.len() != after.len()
            || before.mtime() != after.mtime() || before.mtime_nsec() != after.mtime_nsec()
            || (private && after.mode() & 0o777 != 0o600) {
            fail!(EACCES, "OIDC_SESSION_CONFIG_CHANGED");
        }
        Ok(Some(bytes))
    }
    fn lock(&self) -> EnclaveResult<File> {
        let leaf = name(LOCK)?;
        let file = opened(unsafe { libc::openat(self.file.as_raw_fd(), leaf.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC, 0o600) })?;
        let metadata = file.metadata().map_err(|_| err!(EIO, "OIDC_SESSION_STAT"))?;
        if !protected(&metadata, false) || metadata.mode() & 0o777 != 0o600 { fail!(EACCES, "OIDC_SESSION_PROTECTION"); }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 { fail!(EAGAIN, "OIDC_SESSION_BUSY"); }
        Ok(file)
    }
    fn burn_highwater(&self, expiry: i64, previous: Option<&[u8]>, rebind: &impl Fn() -> EnclaveResult<()>) -> EnclaveResult<Vec<u8>> {
        rebind()?;
        let raw = canonical(&HighWater { v: 1, max_expires_unix: expiry })?;
        let temporary = format!(".oidc-session-highwater-{}.tmp", hex::encode(enclave_core::rng::bytes32()));
        let mut file = opened(unsafe { libc::openat(self.file.as_raw_fd(), name(&temporary)?.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600) })?;
        let prepared = (|| {
            file.write_all(&raw).map_err(|_| err!(EIO, "OIDC_SESSION_HIGHWATER_UNCERTAIN"))?;
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 { fail!(EIO, "OIDC_SESSION_HIGHWATER_UNCERTAIN"); }
            let metadata = file.metadata().map_err(|_| err!(EIO, "OIDC_SESSION_STAT"))?;
            if !protected(&metadata, false) || metadata.mode() & 0o777 != 0o600 { fail!(EACCES, "OIDC_SESSION_PROTECTION"); }
            enclave_core::fsutil::full_fsync(&file)?;
            self.current()?;
            if self.read(HIGH_WATER, 4096)?.as_deref() != previous { fail!(EACCES, "OIDC_SESSION_CONFIG_CHANGED"); }
            rebind()?;
            Ok(())
        })();
        if let Err(error) = prepared { let _ = self.remove(&temporary); return Err(error); }
        if unsafe { libc::renameat(self.file.as_raw_fd(), name(&temporary)?.as_ptr(), self.file.as_raw_fd(), name(HIGH_WATER)?.as_ptr()) } != 0 {
            let _ = self.remove(&temporary); fail!(EIO, "OIDC_SESSION_HIGHWATER_UNCERTAIN");
        }
        // Never remove or restore a marker after rename, including uncertain
        // durability or a later failure before public identity publication.
        self.file.sync_all().map_err(|_| err!(EIO, "OIDC_SESSION_HIGHWATER_UNCERTAIN"))?;
        self.current()?;
        if self.read(HIGH_WATER, 4096)?.as_deref() != Some(raw.as_slice()) {
            fail!(EIO, "OIDC_SESSION_HIGHWATER_UNCERTAIN");
        }
        rebind()?;
        Ok(raw)
    }
    fn invalidate(&self, expiry: i64, expected: &[u8]) -> EnclaveResult<()> {
        let raw = canonical(&Tombstone { v: 1, expires_unix: expiry, invalid: true })?;
        let temporary = format!(".oidc-session-invalid-{}.tmp", hex::encode(enclave_core::rng::bytes32()));
        let mut file = opened(unsafe { libc::openat(self.file.as_raw_fd(), name(&temporary)?.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600) })?;
        let prepared = (|| {
            file.write_all(&raw).map_err(|_| err!(EIO, "OIDC_SESSION_INVALIDATION_UNCERTAIN"))?;
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o644) } != 0 { fail!(EIO, "OIDC_SESSION_INVALIDATION_UNCERTAIN"); }
            enclave_core::fsutil::full_fsync(&file)?;
            if self.read(IDENTITY, 4096)?.as_deref() != Some(expected) { fail!(EIO, "OIDC_SESSION_INVALIDATION_UNCERTAIN"); }
            Ok(())
        })();
        if prepared.is_err() { let _ = self.remove(&temporary); fail!(EIO, "OIDC_SESSION_INVALIDATION_UNCERTAIN"); }
        if unsafe { libc::renameat(self.file.as_raw_fd(), name(&temporary)?.as_ptr(), self.file.as_raw_fd(), name(IDENTITY)?.as_ptr()) } != 0 {
            let _ = self.remove(&temporary); fail!(EIO, "OIDC_SESSION_INVALIDATION_UNCERTAIN");
        }
        self.file.sync_all().map_err(|_| err!(EIO, "OIDC_SESSION_INVALIDATION_UNCERTAIN"))
    }
    fn remove(&self, leaf: &str) -> EnclaveResult<()> {
        if unsafe { libc::unlinkat(self.file.as_raw_fd(), name(leaf)?.as_ptr(), 0) } != 0 {
            fail!(EIO, "OIDC_SESSION_INVALIDATION_UNCERTAIN");
        }
        self.file.sync_all().map_err(|_| err!(EIO, "OIDC_SESSION_INVALIDATION_UNCERTAIN"))
    }
}

#[derive(PartialEq, Eq)]
struct Context { uid: u32, audit: u32, oauth: [u8;32], pins: [u8;32], expires_unix: i64 }
pub(super) struct Renewal<'a> {
    pub(super) directory: &'a Directory,
    pub(super) pin_directory: &'a Directory,
    pub(super) pin_leaf: &'a str,
    pub(super) socket_root: &'a Path,
    pub(super) checked: Option<&'a enclave_core::deployment::CheckedDeploymentTarget>,
}
impl Renewal<'_> {
    fn rebind(&self) -> EnclaveResult<()> {
        if let Some(checked) = self.checked {
            use enclave_core::deployment::normalized_path;
            let target = checked.target();
            if self.directory.path != normalized_path(&target.layout.support_root)?
                || self.pin_directory.path.join(self.pin_leaf) != normalized_path(&target.codesign_pins_file)?
                || self.socket_root != target.layout.socket_root.as_path() {
                fail!(EACCES, "DEPLOYMENT_OIDC_CONTEXT_MISMATCH");
            }
            // The checked load protects public references but does not parse
            // their authority schemas. Never let a mutable renewal destination
            // overwrite any declared read-only input, even malformed input.
            let mut inputs = vec![target.authority_config.as_path(), target.expected_artifacts_manifest.as_path(),
                target.codesign_pins_file.as_path(), checked.config_path()];
            if let Some(broker) = &target.broker { inputs.push(&broker.tuf_root_file); }
            for input in inputs {
                let path = normalized_path(input)?;
                if [IDENTITY, HIGH_WATER, LOCK].iter().any(|leaf| same_casefolded_path(&path, &self.directory.path.join(leaf))) {
                    fail!(EACCES, "DEPLOYMENT_OIDC_RESERVED_INPUT_PATH");
                }
            }
            if same_casefolded_path(&normalized_path(&target.codesign_pins_file)?, &self.directory.path.join(OAUTH)) {
                fail!(EACCES, "DEPLOYMENT_OIDC_RESERVED_INPUT_PATH");
            }
            checked.read_artifact_inventory()?;
        }
        self.directory.current()?;
        self.pin_directory.current()?;
        if let Some(checked) = self.checked { checked.read_artifact_inventory()?; }
        Ok(())
    }
}
fn same_casefolded_path(left: &Path, right: &Path) -> bool {
    // Checked descriptor routes are ASCII. Isolation must also hold on the
    // common case-insensitive macOS filesystem; never fold actual routing.
    match (left.to_str(), right.to_str()) {
        (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
        _ => true,
    }
}
fn socket_path(root: &Path, uid: u32) -> String {
    root.join("oidc").join(uid.to_string()).join("broker.sock").to_string_lossy().into_owned()
}
fn observe(scope: &Renewal<'_>, session: &mut impl FnMut() -> EnclaveResult<(u32,u32,i64)>) -> EnclaveResult<(Context,i64)> {
    scope.rebind()?;
    let directory = scope.directory;
    let (uid, audit, now) = session()?;
    if uid == 0 || uid == u32::MAX || audit == 0 || audit == u32::MAX || now < 0 { fail!(EACCES, "OIDC_SESSION_UNAVAILABLE"); }
    let oauth = directory.read(OAUTH, 16384)?.ok_or_else(|| err!(EACCES, "OIDC_SESSION_OAUTH_MISSING"))?;
    let parsed = OAuth::parse(&oauth, now)?;
    let pins = scope.pin_directory.read_public(scope.pin_leaf, 1024 * 1024)?.ok_or_else(|| err!(EACCES, "OIDC_SESSION_PINS_MISSING"))?;
    let manifest = codesign::pins::parse(&pins)?;
    for identifier in [crate::launchd::OIDC_LABEL, codesign::INTENT_IDENTIFIER,
        codesign::CTL_IDENTIFIER, &DaemonId::CustodyVault.launchd_label()] {
        let _ = codesign::CodeRequirement::pinned_from_manifest(identifier, &manifest)?;
    }
    scope.rebind()?;
    Ok((Context { uid, audit, oauth: Sha256::digest(oauth).into(), pins: Sha256::digest(pins).into(), expires_unix: parsed.expires_unix }, now))
}

pub(super) fn renew_in(directory: &Directory, expiry: i64, session: &mut impl FnMut() -> EnclaveResult<(u32,u32,i64)>) -> EnclaveResult<SessionReceipt> {
    let scope = Renewal { directory, pin_directory: directory, pin_leaf: PINS,
        socket_root: Path::new("/var/run/enclave"), checked: None };
    renew_scoped(&scope, expiry, session)
}
pub(super) fn renew_scoped(scope: &Renewal<'_>, expiry: i64, session: &mut impl FnMut() -> EnclaveResult<(u32,u32,i64)>) -> EnclaveResult<SessionReceipt> {
    scope.rebind()?;
    let directory = scope.directory;
    let _lease = directory.lock()?;
    let (context, now) = observe(scope, session)?;
    let old = directory.read(IDENTITY, 4096)?;
    let mut old_marker = directory.read(HIGH_WATER, 4096)?;
    // A strict GLOBAL floor prevents digest revival through this API even when
    // fast user switching returns to an earlier still-live audit session. It is
    // intentionally not reset for a different UID/AuditID or expired record.
    // Either surviving record retains the floor. Existing-identity migration
    // adopts its validated floor; only absence of BOTH records is fresh state.
    let identity_floor = old.as_deref().map(|raw| Identity::expiry_floor_at(raw, scope.socket_root)).transpose()?;
    let marker_floor = old_marker.as_deref().map(HighWater::floor).transpose()?;
    // Migrate a valid older identity even if this renewal will refuse. Losing
    // the public record after a refused retry must not erase an observed floor.
    if let Some(floor) = identity_floor {
        if marker_floor.map_or(true, |marker| marker < floor) {
            old_marker = Some(directory.burn_highwater(floor, old_marker.as_deref(), &|| scope.rebind())?);
        }
    }
    if expiry <= now || expiry > context.expires_unix { fail!(EACCES, "OIDC_SESSION_EXPIRY"); }
    if identity_floor.into_iter().chain(marker_floor).any(|floor| expiry <= floor) {
        fail!(EACCES, "OIDC_SESSION_EXPIRY_FLOOR");
    }
    let bytes = canonical(&serde_json::json!({"v":1,"socket":socket_path(scope.socket_root, context.uid),
        "identifier":crate::launchd::OIDC_LABEL,"console_uid":context.uid,"audit_session_id":context.audit,"expires_unix":expiry}))?;
    // Burn and durably synchronize the strictly higher floor BEFORE the first
    // public identity write. A failed attempt may consume an expiry, never
    // restore an earlier digest. The renewal flock serializes both records.
    let marker = directory.burn_highwater(expiry, old_marker.as_deref(), &|| scope.rebind())?;
    let temporary = format!(".oidc-session-{}.tmp", hex::encode(enclave_core::rng::bytes32()));
    let mut file = opened(unsafe { libc::openat(directory.file.as_raw_fd(), name(&temporary)?.as_ptr(),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600) })?;
    let before_publish = (|| {
        file.write_all(&bytes).map_err(|_| err!(EIO, "OIDC_SESSION_WRITE"))?;
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o644) } != 0 { fail!(EIO, "OIDC_SESSION_MODE"); }
        let metadata = file.metadata().map_err(|_| err!(EIO, "OIDC_SESSION_STAT"))?;
        if !protected(&metadata, false) || metadata.mode() & 0o777 != 0o644 { fail!(EACCES, "OIDC_SESSION_PROTECTION"); }
        enclave_core::fsutil::full_fsync(&file)?;
        let (fresh, now) = observe(scope, session)?;
        if fresh != context || now >= expiry || directory.read(IDENTITY, 4096)? != old
            || directory.read(HIGH_WATER, 4096)?.as_deref() != Some(marker.as_slice()) { fail!(EACCES, "OIDC_SESSION_CONFIG_CHANGED"); }
        scope.rebind()?;
        Ok(())
    })();
    if let Err(error) = before_publish { let _ = directory.remove(&temporary); return Err(error); }
    if unsafe { libc::renameat(directory.file.as_raw_fd(), name(&temporary)?.as_ptr(), directory.file.as_raw_fd(), name(IDENTITY)?.as_ptr()) } != 0 {
        let _ = directory.remove(&temporary); fail!(EIO, "OIDC_SESSION_RENAME");
    }
    let after_publish = (|| {
        directory.file.sync_all().map_err(|_| err!(EIO, "OIDC_SESSION_PERSISTENCE_UNCERTAIN"))?;
        let (fresh, now) = observe(scope, session)?;
        if fresh != context || now >= expiry || directory.read(IDENTITY, 4096)?.as_deref() != Some(bytes.as_slice())
            || directory.read(HIGH_WATER, 4096)?.as_deref() != Some(marker.as_slice()) { fail!(EACCES, "OIDC_SESSION_CONFIG_CHANGED"); }
        scope.rebind()?;
        Ok(())
    })();
    if let Err(error) = after_publish {
        // Never restore or delete either floor. Publish a closed tombstone that
        // consumers refuse; the separate marker survives even its deletion.
        // If invalidation itself fails, no success receipt is issued and the
        // newer valid record/tombstone still supplies the floor on retry.
        // Rebinding cannot authorize a changed destination. Cleanup remains
        // confined to the held original directory and exact bytes we published,
        // even when descriptor drift itself caused this refusal.
        let _ = scope.rebind();
        directory.invalidate(expiry, &bytes)?;
        let _ = scope.rebind();
        return Err(error);
    }
    Ok(SessionReceipt { identity_path: directory.path.join(IDENTITY).to_string_lossy().into_owned(),
        identity_sha256: hex::encode(Sha256::digest(&bytes)), expires_unix: expiry })
}

#[cfg(test)]
mod tests { include!("oidc_session_tests.rs"); }

}
