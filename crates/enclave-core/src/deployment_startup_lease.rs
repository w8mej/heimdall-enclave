//! Permanent-inode lifetime exclusion for cooperating selected actors.
//!
//! Startup retains a read-only SH flock in a private process-static owner.
//! Even a later poisoned check cannot release it before process exit. An
//! inhibited native root operator may separately acquire an EX observation.
//! Neither lock proves old/ungated/copied actors absent or grants mutation,
//! installation, activation, account, software-release or recovery authority.
//! Callers must acquire before their first service effect. Administrative
//! readers, teardown and a controller's PreparedStart must not retain actor SH.
//!
//! Provisioning is separate. Missing/foreign/unsafe names always refuse; this
//! module never creates, writes, repairs, removes or explicitly unlocks either
//! permanent lease or denial marker. CLOEXEC requires a cooperating exec to
//! reacquire before new service effects; a fork/dup can retain the OS lock.

use super::upgrade::directory_mode::VerifiedModeChange;
pub use super::upgrade::directory_mode::{DirectoryModeEffect, DirectoryModeIdentity};
use super::{
    upgrade::{HeldUpgradeDirectory, UPGRADE_INHIBITION_LEAF},
    CheckedDeploymentTarget, DeploymentRole,
};
use crate::{
    err,
    error::{EnclaveError, EnclaveResult},
    fail,
};
use std::{
    ffi::CString,
    fs::{File, Metadata},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Instant,
};

/// The one permanent support-root lease name. It is never caller selected.
pub const STARTUP_LIFETIME_LEAF: &str = ".depot-startup-lifetime-v1.lock";

#[derive(Clone, Copy)]
struct Owner {
    uid: u32,
    gid: u32,
}
impl Owner {
    const ROOT: Self = Self { uid: 0, gid: 0 };
}
#[derive(Clone, Copy)]
enum Lock {
    Shared,
    Exclusive,
    DedicatedExclusive,
}
impl Lock {
    fn operation(self) -> i32 {
        match self {
            Self::Shared => libc::LOCK_SH,
            Self::Exclusive | Self::DedicatedExclusive => libc::LOCK_EX,
        }
    }
    fn marker_present(self) -> bool {
        matches!(self, Self::Exclusive)
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct NameStamp {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    size: i64,
}
impl NameStamp {
    fn raw(m: &libc::stat) -> Self {
        Self {
            dev: m.st_dev as u64,
            ino: m.st_ino as u64,
            uid: m.st_uid,
            gid: m.st_gid,
            mode: m.st_mode as u32,
            links: m.st_nlink as u64,
            size: m.st_size,
        }
    }
    fn metadata(m: &Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            links: m.nlink(),
            size: m.len() as i64,
        }
    }
    fn protected(&self, owner: Owner) -> bool {
        self.mode & libc::S_IFMT as u32 == libc::S_IFREG as u32
            && self.uid == owner.uid
            && self.gid == owner.gid
            && self.mode & 0o7777 == 0o644
            && self.links == 1
            && self.size == 0
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp {
    name: NameStamp,
    modified: (i64, i64),
    changed: (i64, i64),
}
fn stamp(m: &Metadata) -> Stamp {
    Stamp {
        name: NameStamp::metadata(m),
        modified: (m.mtime(), m.mtime_nsec()),
        changed: (m.ctime(), m.ctime_nsec()),
    }
}
fn named(parent: &File) -> EnclaveResult<NameStamp> {
    let name = CString::new(STARTUP_LIFETIME_LEAF).expect("literal");
    let mut m = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: held directory, fixed C component and valid output storage.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            m.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        fail!(EACCES, "STARTUP_LEASE_MISSING_OR_UNKNOWN");
    }
    Ok(NameStamp::raw(&unsafe { m.assume_init() }))
}
fn marker(parent: &File, present: bool) -> EnclaveResult<()> {
    let name = CString::new(UPGRADE_INHIBITION_LEAF).expect("literal");
    let mut m = std::mem::MaybeUninit::<libc::stat>::uninit();
    // Presence alone denies startup, including invalid bytes/types. Never open.
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            m.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        if present {
            return Ok(());
        }
        fail!(EACCES, "DEPLOYMENT_UPGRADE_INHIBITED");
    }
    if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
        fail!(EACCES, "STARTUP_LEASE_MARKER_UNKNOWN");
    }
    if present {
        fail!(EACCES, "STARTUP_LEASE_INHIBITION_REQUIRED");
    }
    Ok(())
}
struct LeaseFile {
    file: File,
    stamp: Stamp,
    owner: Owner,
}
impl LeaseFile {
    fn open(parent: &File, owner: Owner) -> EnclaveResult<Self> {
        // Refuse known symlinks/FIFOs/devices/directories before opening. The
        // production held parent has no ordinary-user writable ancestry.
        let before = named(parent)?;
        if !before.protected(owner) {
            fail!(EACCES, "STARTUP_LEASE_PROTECTION");
        }
        let name = CString::new(STARTUP_LIFETIME_LEAF).expect("literal");
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            fail!(EACCES, "STARTUP_LEASE_OPEN");
        }
        // SAFETY: successful openat transferred one owned descriptor.
        let file = unsafe { File::from_raw_fd(fd) };
        let observed = stamp(
            &file
                .metadata()
                .map_err(|_| err!(EIO, "STARTUP_LEASE_STAT"))?,
        );
        if observed.name != before || !observed.name.protected(owner) {
            fail!(ESTALE, "STARTUP_LEASE_CHANGED");
        }
        let result = Self {
            file,
            stamp: observed,
            owner,
        };
        result.assert_current(parent)?;
        Ok(result)
    }
    fn assert_current(&self, parent: &File) -> EnclaveResult<()> {
        let before = stamp(
            &self
                .file
                .metadata()
                .map_err(|_| err!(EIO, "STARTUP_LEASE_STAT"))?,
        );
        // SAFETY: descriptor flag observations with no variadic argument.
        let access = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GETFL) };
        let descriptor = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GETFD) };
        if access < 0
            || descriptor < 0
            || access & libc::O_ACCMODE != libc::O_RDONLY
            || access & libc::O_NONBLOCK == 0
            || descriptor & libc::FD_CLOEXEC == 0
            || !before.name.protected(self.owner)
            || before != self.stamp
            || named(parent)? != self.stamp.name
        {
            fail!(ESTALE, "STARTUP_LEASE_CHANGED");
        }
        let after = stamp(
            &self
                .file
                .metadata()
                .map_err(|_| err!(EIO, "STARTUP_LEASE_STAT"))?,
        );
        if after != self.stamp {
            fail!(ESTALE, "STARTUP_LEASE_CHANGED");
        }
        Ok(())
    }
}
// Private seam substitutes only a synthetic fixture anchor/check. It always
// invokes actual openat/fstatat/fcntl/flock; no production provider is exposed.
fn acquire(
    parent: &File,
    owner: Owner,
    lock: Lock,
    check: &mut impl FnMut() -> EnclaveResult<()>,
) -> EnclaveResult<LeaseFile> {
    // Legacy actor/dedicated callers release unadmitted partial owners on Err.
    // The additive inhibited EX API below keeps this failure instead.
    acquire_retained(parent, owner, lock, check).map_err(|failure| failure.error)
}
struct AcquisitionFailure {
    error: EnclaveError,
    final_errors: Vec<EnclaveError>,
    file: Option<LeaseFile>,
    acquired: bool,
}
fn acquire_retained(
    parent: &File,
    owner: Owner,
    lock: Lock,
    check: &mut impl FnMut() -> EnclaveResult<()>,
) -> Result<LeaseFile, AcquisitionFailure> {
    let mut retained = None;
    let mut acquired = false;
    let mut final_errors = Vec::new();
    let operation = (|| {
        check()?;
        marker(parent, lock.marker_present())?;
        retained = Some(LeaseFile::open(parent, owner)?);
        let file = retained.as_ref().expect("original opened lease");
        check()?;
        marker(parent, lock.marker_present())?;
        file.assert_current(parent)?;
        // NB is mandatory: no actor/upgrade waits indefinitely while holding
        // other authority. Retain this SAME owner immediately after flock.
        if unsafe { libc::flock(file.file.as_raw_fd(), lock.operation() | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error().raw_os_error();
            if error == Some(libc::EWOULDBLOCK) || error == Some(libc::EAGAIN) {
                fail!(EACCES, "STARTUP_LEASE_BUSY");
            }
            fail!(EIO, "STARTUP_LEASE_LOCK_UNKNOWN");
        }
        acquired = true;
        let binding = check();
        let name = file.assert_current(parent);
        let denial = marker(parent, lock.marker_present());
        // Keep the existing primary precedence and all available post-lock
        // refusals. The legacy adapter preserves its original check schedule.
        for result in [binding, name, denial] {
            if let Err(error) = result {
                final_errors.push(error);
            }
        }
        if let Some(error) = final_errors.first() {
            return Err(error.clone());
        }
        check()?;
        file.assert_current(parent)?;
        marker(parent, lock.marker_present())?;
        Ok(())
    })();
    match operation {
        Ok(()) => Ok(retained.take().expect("original acquired lease")),
        Err(error) => Err(AcquisitionFailure {
            error,
            final_errors,
            file: retained,
            acquired,
        }),
    }
}
fn selected(checked: &CheckedDeploymentTarget) -> EnclaveResult<()> {
    let current = super::selected().ok_or_else(|| err!(EACCES, "DEPLOYMENT_CONTEXT_REQUIRED"))?;
    if current.config_path() != checked.config_path()
        || current.descriptor_sha256() != checked.descriptor_sha256()
        || current.target() != checked.target()
    {
        fail!(ESTALE, "STARTUP_LEASE_CONTEXT_CHANGED");
    }
    Ok(())
}
struct ActorOwner {
    directory: HeldUpgradeDirectory,
    file: LeaseFile,
    checked: CheckedDeploymentTarget,
}
impl ActorOwner {
    fn assert_current(&self) -> EnclaveResult<()> {
        let selection = selected(&self.checked);
        let directory = self.directory.assert_current(&self.checked);
        let file = self.file.assert_current(self.directory.directory());
        let denial = marker(self.directory.directory(), false);
        selection?;
        directory?;
        file?;
        denial?;
        self.directory.assert_current(&self.checked)?;
        self.file.assert_current(self.directory.directory())?;
        marker(self.directory.directory(), false)
    }
}
struct Retained<T> {
    owner: T,
    poisoned: bool,
}
impl<T> Retained<T> {
    fn check(&mut self, check: impl FnOnce(&T) -> EnclaveResult<()>) -> EnclaveResult<()> {
        if self.poisoned {
            fail!(EACCES, "STARTUP_LEASE_POISONED");
        }
        let result = check(&self.owner);
        if result.is_err() {
            self.poisoned = true;
        }
        // Do not take, replace or drop the established owner on refusal.
        result
    }
    fn check_deadline(
        &mut self,
        deadline: Instant,
        check: impl FnOnce(&T) -> EnclaveResult<()>,
    ) -> EnclaveResult<()> {
        self.check(|owner| {
            if Instant::now() >= deadline {
                fail!(ETIMEDOUT, "STARTUP_LEASE_OBSERVATION_DEADLINE");
            }
            check(owner)?;
            if Instant::now() >= deadline {
                fail!(ETIMEDOUT, "STARTUP_LEASE_OBSERVATION_DEADLINE");
            }
            Ok(())
        })
    }
}
static ACTOR: Mutex<Option<Retained<ActorOwner>>> = Mutex::new(None);

/// Retain one actual SH lease until this process exits, before actor effects.
/// Call only after successful immutable selected-context binding. Repeated
/// checks freshly validate the same owner; poison retains its SH until exit.
/// No owner/FD or release/clear/replacement API is returned to the caller.
pub fn retain_selected_startup_lease() -> EnclaveResult<()> {
    let checked = super::selected().ok_or_else(|| err!(EACCES, "DEPLOYMENT_CONTEXT_REQUIRED"))?;
    let mut slot = ACTOR
        .lock()
        .map_err(|_| err!(EACCES, "STARTUP_LEASE_OWNER_POISONED"))?;
    if let Some(retained) = slot.as_mut() {
        return retained.check(ActorOwner::assert_current);
    }
    selected(checked)?;
    let directory = HeldUpgradeDirectory::open(checked)?;
    let file = acquire(
        directory.directory(),
        Owner::ROOT,
        Lock::Shared,
        &mut || {
            selected(checked)?;
            directory.assert_current(checked)
        },
    )?;
    let owner = ActorOwner {
        directory,
        file,
        checked: checked.clone(),
    };
    owner.assert_current()?;
    *slot = Some(Retained {
        owner,
        poisoned: false,
    });
    Ok(())
}

/// Observe the SAME already-retained actor lease without acquiring, creating,
/// replacing or repairing anything. Readiness must never acquire a late lease
/// after monitors/listeners have already begun their service effects.
pub(crate) fn require_retained_selected_startup_lease(deadline: Instant) -> EnclaveResult<()> {
    if Instant::now() >= deadline {
        fail!(ETIMEDOUT, "STARTUP_LEASE_OBSERVATION_DEADLINE");
    }
    native_root()?;
    let mut slot = ACTOR
        .try_lock()
        .map_err(|_| err!(EAGAIN, "STARTUP_LEASE_OBSERVATION_BUSY"))?;
    let retained = slot
        .as_mut()
        .ok_or_else(|| err!(EACCES, "STARTUP_LEASE_NOT_RETAINED"))?;
    retained.check_deadline(deadline, ActorOwner::assert_current)
}

/// An exclusive kernel lock observation under existing inhibition. This is
/// neither whole-target inactivity nor permission to mutate/replace/install.
/// The native wrapper must also retain its genuine same host guard and exact
/// owned marker/inventory binding. No file descriptor or unlock API exists.
pub struct ExclusiveStartupLease {
    owner: ExclusiveOwner,
}
struct ExclusiveOwner {
    directory: HeldUpgradeDirectory,
    file: LeaseFile,
    checked: CheckedDeploymentTarget,
    lock: Lock,
    poisoned: bool,
    identity: Arc<()>,
}

/// Two fixed original held-ancestry roles only; no path, mode or FD input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateBirthAncestor {
    /// The exact support root configured in the selected deployment target.
    SupportRoot,
    /// The exact nonce ancestor derived from that target's dedicated-test ID.
    NonceRoot,
}

/// Actual own-syscall event, bound to the SAME EX acquisition and original
/// selected context. No constructor, Clone, serde, FD or lease extraction.
/// This is historical metadata evidence, not visibility/install authority.
pub struct DirectoryModeChange {
    checked: CheckedDeploymentTarget,
    owner_identity: Arc<()>,
    lease_stamp: Stamp,
    ancestor: PrivateBirthAncestor,
    change: VerifiedModeChange,
}
impl std::fmt::Debug for DirectoryModeChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectoryModeChange")
            .field("ancestor", &self.ancestor)
            .field("before", &self.before())
            .field("after", &self.after())
            .field("durability_completed", &self.durability_completed())
            .finish_non_exhaustive()
    }
}
impl DirectoryModeChange {
    /// Fixed original ancestor role changed by this actual syscall event.
    pub fn ancestor(&self) -> PrivateBirthAncestor {
        self.ancestor
    }
    /// Original selected path bound to this event.
    pub fn path(&self) -> &Path {
        self.change.path()
    }
    /// Immutable original directory identity before the verified transition.
    pub fn before(&self) -> DirectoryModeIdentity {
        self.change.before()
    }
    /// Verified identity after the exact directory mode transition.
    pub fn after(&self) -> DirectoryModeIdentity {
        self.change.after()
    }
    /// Whether synchronization of the original directory and parent completed.
    pub fn durability_completed(&self) -> bool {
        self.change.durable()
    }
    fn context(&self, checked: &CheckedDeploymentTarget) -> EnclaveResult<()> {
        if self.checked.config_path() != checked.config_path()
            || self.checked.target() != checked.target()
            || self.checked.descriptor_sha256() != checked.descriptor_sha256()
        {
            fail!(ESTALE, "DIRECTORY_MODE_EVENT_CONTEXT");
        }
        Ok(())
    }
    /// Validate ONLY against an already-retained recipient's ORIGINAL cached
    /// old identity and its held/named descriptors. These borrowed inputs do
    /// not authorize an effect. Caller must keep its old stamp/provenance and
    /// actual SAME guard/EX/approval, consume once, and never revive poison.
    pub fn verify_recipient(
        &self,
        checked: &CheckedDeploymentTarget,
        path: &Path,
        original: &File,
        named: &File,
        expected_old: DirectoryModeIdentity,
    ) -> EnclaveResult<()> {
        native_root()?;
        selected(checked)?;
        self.context(checked)?;
        self.change
            .verify_recipient(path, original, named, expected_old, true)
    }
}

/// Refusal retains the SAME poisoned EX, any verified applied event and the
/// actual partial syscall record. Names/modes are never restored or repaired.
#[must_use = "retain same EX and actual directory effect through refusal"]
pub struct DirectoryModeChangeFailure {
    /// Primary operation refusal, or the first final refusal if it arose later.
    pub error: EnclaveError,
    /// Independent boundary refusals observed during the attempted operation.
    pub boundary_errors: Vec<EnclaveError>,
    /// Independent retained-owner refusals observed after the operation.
    pub final_errors: Vec<EnclaveError>,
    ancestor: PrivateBirthAncestor,
    effect: Option<DirectoryModeEffect>,
    change: Option<DirectoryModeChange>,
    owner: ExclusiveStartupLease,
}
impl std::fmt::Debug for DirectoryModeChangeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectoryModeChangeFailure")
            .field("error", &self.error)
            .field("boundary_errors", &self.boundary_errors)
            .field("final_errors", &self.final_errors)
            .field("ancestor", &self.ancestor)
            .field("effect", &self.effect)
            .field("verified_change", &self.change)
            .finish_non_exhaustive()
    }
}
impl DirectoryModeChangeFailure {
    /// Borrow historical partial-effect observations without extracting the EX.
    pub fn effect(&self) -> Option<&DirectoryModeEffect> {
        self.effect.as_ref()
    }
    /// An applied event may survive an overall refusal. Borrowing it cannot
    /// extract/retry the lease or convert any poisoned owner into success.
    pub fn verified_change(&self) -> Option<&DirectoryModeChange> {
        self.change.as_ref()
    }
    /// Conservatively report any actual nonce-root chmod attempt; an unknown
    /// poststate cannot justify claiming that namespace privacy was preserved.
    pub fn namespace_visibility_may_have_changed(&self) -> bool {
        self.ancestor == PrivateBirthAncestor::NonceRoot
            && self
                .effect
                .as_ref()
                .is_some_and(|effect| effect.syscall_attempted())
    }
    /// Evaluate available real checks on the same retained owner even though
    /// this refusal has poisoned it; success never revives its authority.
    pub fn retained_checks(&self, checked: &CheckedDeploymentTarget) -> Vec<EnclaveError> {
        self.owner.owner.observations(checked)
    }
}

fn private_birth_nonce_root(checked: &CheckedDeploymentTarget) -> EnclaveResult<PathBuf> {
    private_birth_root_for(checked.target(), checked.config_path())
}
// Pure closed scope only; never a native/checked/birth authority constructor.
fn private_birth_root_for(
    target: &super::DeploymentTarget,
    config: &Path,
) -> EnclaveResult<PathBuf> {
    if target.role != DeploymentRole::DedicatedTest
        || target.profile != crate::profile::Profile::L2
        || target.broker.is_some()
        || !target.shared_read_only_inputs.is_empty()
    {
        fail!(EACCES, "DIRECTORY_MODE_PRIVATE_BIRTH_SCOPE");
    }
    let token = target
        .target_id
        .strip_prefix("ykft-")
        .ok_or_else(|| err!(EACCES, "DIRECTORY_MODE_NONCE_BINDING"))?;
    if token.len() != 32
        || !token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        fail!(EACCES, "DIRECTORY_MODE_NONCE_BINDING");
    }
    let roots = target
        .layout
        .support_root
        .ancestors()
        .filter(|path| path.file_name().and_then(|s| s.to_str()) == Some(token))
        .collect::<Vec<_>>();
    if roots.len() != 1 {
        fail!(EACCES, "DIRECTORY_MODE_NONCE_BINDING");
    }
    let root = roots[0];
    let l = &target.layout;
    let references: [&Path; 13] = [
        &l.binary_dir,
        &l.custody_bundle,
        &l.sandbox_dir,
        &l.socket_root,
        &l.state_root,
        &l.audit_root,
        &l.cas_store_root,
        &l.staging_root,
        &l.support_root,
        &target.authority_config,
        &target.expected_artifacts_manifest,
        &target.codesign_pins_file,
        config,
    ];
    for path in references {
        if super::normalized_path(path)?.as_path() != path
            || path == root
            || !path.starts_with(root)
        {
            fail!(EACCES, "DIRECTORY_MODE_NONCE_BINDING");
        }
    }
    Ok(root.to_owned())
}
// Original admission owners only. Before complete-owner construction, keep
// every successfully opened LeaseFile and any acquired EX in these Options.
// No partial owner is reloaded, replaced or made available to the caller.
struct ExclusiveAcquisition {
    checked: CheckedDeploymentTarget,
    directory: Option<HeldUpgradeDirectory>,
    file: Option<LeaseFile>,
    owner: Option<ExclusiveOwner>,
    acquired: bool,
}
impl ExclusiveAcquisition {
    fn observations(&self, checked: &CheckedDeploymentTarget) -> Vec<EnclaveError> {
        let context = if self.checked.config_path() != checked.config_path()
            || self.checked.descriptor_sha256() != checked.descriptor_sha256()
            || self.checked.target() != checked.target()
        {
            Err(err!(ESTALE, "STARTUP_LEASE_CONTEXT_CHANGED"))
        } else {
            Ok(())
        };
        let mut errors = Vec::new();
        for result in [
            native_root(),
            selected(&self.checked),
            exclusive_role(self.checked.target().role, Lock::Exclusive),
            context,
        ] {
            if let Err(error) = result {
                errors.push(error);
            }
        }
        let (directory, file) = if let Some(owner) = &self.owner {
            if owner.poisoned {
                errors.push(err!(EACCES, "STARTUP_LEASE_POISONED"));
            }
            (Some(&owner.directory), Some(&owner.file))
        } else {
            (self.directory.as_ref(), self.file.as_ref())
        };
        if let Some(directory) = directory {
            if let Err(error) = directory.assert_current(&self.checked) {
                errors.push(error);
            }
            if let Some(file) = file {
                if let Err(error) = file.assert_current(directory.directory()) {
                    errors.push(error);
                }
            }
            if let Err(error) = marker(directory.directory(), true) {
                errors.push(error);
            }
            // Re-observe original ancestry even if file/marker observation
            // failed. No lock reacquisition or directory/file replacement.
            if let Err(error) = directory.assert_current(&self.checked) {
                errors.push(error);
            }
        }
        errors
    }
}
/// Refused inhibited-EX acquisition, retaining all original admitted partial
/// owners and any actual acquired EX until Drop. No Clone, retry, extraction,
/// FD, explicit unlock, marker repair or successful-owner conversion exists.
/// Drop releases only these held descriptors; it never changes on-disk names.
#[must_use = "retain acquisition failure owners through same-invocation final checks"]
pub struct ExclusiveStartupLeaseFailure {
    /// Original operation refusal, or first final refusal after operation success.
    pub error: EnclaveError,
    /// All observed post-lock and outer-final failures in observation order.
    pub final_errors: Vec<EnclaveError>,
    owner: ExclusiveAcquisition,
}
impl std::fmt::Debug for ExclusiveStartupLeaseFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExclusiveStartupLeaseFailure")
            .field("error", &self.error)
            .field("final_errors", &self.final_errors)
            .field("retained_owners", &"<redacted>")
            .finish_non_exhaustive()
    }
}
impl ExclusiveStartupLeaseFailure {
    /// Historical kernel flock success on the ORIGINAL inode only. This is
    /// not a currentness, inhibition, inactivity, visibility or mutation grant.
    pub fn exclusive_acquired(&self) -> bool {
        self.owner.acquired
    }
    /// Immutable fresh observations of the actual retained originals and
    /// exact checked context. Every available independent gate is evaluated.
    /// An empty vector cannot clear the original refusal or create authority;
    /// a complete poisoned owner also reports its existing poison. No caller
    /// callback, save, adoption, unlock, reacquisition or retry takes place.
    pub fn retained_checks(&self, checked: &CheckedDeploymentTarget) -> Vec<EnclaveError> {
        self.owner.observations(checked)
    }
}
fn native_root() -> EnclaveResult<()> {
    if !cfg!(target_os = "macos") || unsafe { libc::geteuid() } != 0 {
        fail!(EACCES, "STARTUP_EXCLUSION_NATIVE_ROOT_REQUIRED");
    }
    Ok(())
}
impl ExclusiveStartupLease {
    /// Denial-only membership over immutable ORIGINAL ancestry identities.
    /// False is not currentness, ownership, privacy or mutation authority.
    pub fn retains_directory_identity(&self, dev: u64, ino: u64) -> bool {
        self.owner.directory.retains_directory_identity(dev, ino)
    }

    /// Perform only an actual original-held root:wheel directory700->755
    /// event for one of two fixed Dedicated L2 nonce roles. Same EX and every
    /// effect survive refusal. The genuine birth caller must independently
    /// enforce born-only provenance, actual guard/accounts/software/candidate,
    /// complete durable preparation and LAST root visibility. This core event
    /// supplies none of those authorities and never clears inhibition.
    pub fn prepare_private_birth_ancestor(
        mut self,
        checked: &CheckedDeploymentTarget,
        ancestor: PrivateBirthAncestor,
    ) -> Result<(Self, DirectoryModeChange), DirectoryModeChangeFailure> {
        let mut boundary_errors = Vec::new();
        let mut effect = None;
        let mut change = None;
        let operation = (|| {
            if self.owner.poisoned {
                fail!(EACCES, "STARTUP_LEASE_POISONED");
            }
            if !matches!(self.owner.lock, Lock::Exclusive) {
                fail!(EACCES, "DIRECTORY_MODE_INHIBITED_EX_REQUIRED");
            }
            let checks = self.owner.observations(checked);
            let result = checks.first().cloned().map_or(Ok(()), Err);
            boundary_errors.extend(checks);
            result?;
            let root = private_birth_nonce_root(checked)?;
            if !self.owner.directory.unchanged_private_directory(&root) {
                fail!(EACCES, "DIRECTORY_MODE_PRIVATE_ROOT_REQUIRED");
            }
            let support = &checked.target().layout.support_root;
            if ancestor == PrivateBirthAncestor::NonceRoot
                && !self.owner.directory.completed_mode_change(support)
            {
                fail!(EACCES, "DIRECTORY_MODE_SUPPORT_FIRST_REQUIRED");
            }
            let path = match ancestor {
                PrivateBirthAncestor::SupportRoot => support.as_path(),
                PrivateBirthAncestor::NonceRoot => root.as_path(),
            };
            let original_checked = &self.owner.checked;
            let file = &self.owner.file;
            let outcome = self.owner.directory.change_original_mode(
                checked,
                path,
                &mut |parent| {
                    let context = if original_checked.config_path() != checked.config_path()
                        || original_checked.descriptor_sha256() != checked.descriptor_sha256()
                        || original_checked.target() != checked.target()
                    {
                        Err(err!(ESTALE, "STARTUP_LEASE_CONTEXT_CHANGED"))
                    } else {
                        Ok(())
                    };
                    [
                        native_root(),
                        selected(checked),
                        context,
                        file.assert_current(parent),
                        marker(parent, true),
                    ]
                    .into_iter()
                    .filter_map(Result::err)
                    .collect()
                },
                &mut boundary_errors,
                &mut crate::fsutil::full_fsync,
            );
            effect = Some(outcome.effect);
            change = outcome.change.map(|change| DirectoryModeChange {
                checked: checked.clone(),
                owner_identity: Arc::clone(&self.owner.identity),
                lease_stamp: self.owner.file.stamp,
                ancestor,
                change,
            });
            outcome.operation
        })();
        // All independent current-owner/name/selection/denial gates run even
        // after an uncertain syscall; neither partial nor late failure unlocks.
        let final_errors = self.owner.observations(checked);
        match super::upgrade::directory_mode::resolve_retained(
            self,
            operation,
            boundary_errors,
            final_errors,
            effect,
            change,
        ) {
            Ok((owner, change)) => Ok((owner, change)),
            Err(mut refusal) => {
                refusal.owner.owner.poisoned = true;
                Err(DirectoryModeChangeFailure {
                    error: refusal.error,
                    boundary_errors: refusal.boundary_errors,
                    final_errors: refusal.final_errors,
                    ancestor,
                    effect: refusal.effect,
                    change: refusal.change,
                    owner: refusal.owner,
                })
            }
        }
    }

    /// Bind a borrowed actual event to THIS exact retained acquisition. A new
    /// EX on an equal inode cannot adopt an event from a dropped old owner.
    pub fn assert_directory_change(
        &mut self,
        checked: &CheckedDeploymentTarget,
        event: &DirectoryModeChange,
    ) -> EnclaveResult<()> {
        let current = self.owner.assert_current(checked);
        let binding = (|| {
            event.context(checked)?;
            if !Arc::ptr_eq(&self.owner.identity, &event.owner_identity)
                || self.owner.file.stamp != event.lease_stamp
            {
                fail!(ESTALE, "DIRECTORY_MODE_EVENT_LEASE_MISMATCH");
            }
            Ok(())
        })();
        if current.is_err() || binding.is_err() {
            self.owner.poisoned = true;
        }
        current?;
        binding
    }
    /// Recheck retained exact selected descriptor, ancestry, permanent inode
    /// and inhibition. Any refusal poisons this owner without releasing EX.
    pub fn assert_current(&mut self, checked: &CheckedDeploymentTarget) -> EnclaveResult<()> {
        self.owner.assert_current(checked)
    }

    /// Observe the final absence of inhibition for the SAME selected dedicated
    /// target while retaining the original EX descriptor without unlocking or
    /// reacquiring it. This never removes a marker or authorizes installation.
    /// A caller must separately retain its genuine birth, owned denial removal,
    /// maintenance and complete durable installation evidence. A refusal owns
    /// the poisoned original lease until the returned failure is dropped.
    pub fn observe_dedicated_after_clear(
        mut self,
        checked: &CheckedDeploymentTarget,
    ) -> Result<DedicatedStartupLease, DedicatedLeaseTransitionFailure> {
        let result = if self.owner.poisoned {
            Err(err!(EACCES, "STARTUP_LEASE_POISONED"))
        } else {
            observe_dedicated_clear(
                self.owner.directory.directory(),
                &self.owner.file,
                self.owner.lock,
                checked.target().role,
                &mut || {
                    native_root()?;
                    selected(checked)?;
                    if self.owner.checked.config_path() != checked.config_path()
                        || self.owner.checked.descriptor_sha256() != checked.descriptor_sha256()
                        || self.owner.checked.target() != checked.target()
                    {
                        fail!(ESTALE, "STARTUP_LEASE_CONTEXT_CHANGED");
                    }
                    self.owner.directory.assert_current(checked)
                },
            )
        };
        match result {
            Ok(()) => {
                self.owner.lock = Lock::DedicatedExclusive;
                Ok(DedicatedStartupLease { owner: self.owner })
            }
            Err(error) => {
                self.owner.poisoned = true;
                Err(DedicatedLeaseTransitionFailure {
                    error,
                    _owner: self,
                })
            }
        }
    }
}
/// Failed final absence observation, retaining the SAME poisoned EX owner.
/// There is no retry, owner extraction, descriptor, unlock or repair API.
pub struct DedicatedLeaseTransitionFailure {
    /// Original refusal. No completion or continuing inhibition is inferred.
    pub error: crate::error::EnclaveError,
    _owner: ExclusiveStartupLease,
}
impl std::fmt::Debug for DedicatedLeaseTransitionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DedicatedLeaseTransitionFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
// Private kernel-observation seam. Tests use original synthetic lease inodes;
// only the public owner above can supply genuine checked/native context.
fn observe_dedicated_clear(
    parent: &File,
    file: &LeaseFile,
    previous: Lock,
    role: DeploymentRole,
    check: &mut impl FnMut() -> EnclaveResult<()>,
) -> EnclaveResult<()> {
    if !matches!(previous, Lock::Exclusive) {
        fail!(EACCES, "STARTUP_LEASE_TRANSITION_REQUIRES_INHIBITED_EX");
    }
    exclusive_role(role, Lock::DedicatedExclusive)?;
    check()?;
    file.assert_current(parent)?;
    marker(parent, false)?;
    check()?;
    file.assert_current(parent)?;
    marker(parent, false)
}
fn exclusive_role(role: DeploymentRole, lock: Lock) -> EnclaveResult<()> {
    match lock {
        Lock::Exclusive => Ok(()),
        Lock::DedicatedExclusive if role == DeploymentRole::DedicatedTest => Ok(()),
        _ => Err(err!(EACCES, "STARTUP_LEASE_DEDICATED_REQUIRED")),
    }
}
impl ExclusiveOwner {
    fn observations(&self, checked: &CheckedDeploymentTarget) -> Vec<EnclaveError> {
        let context = if self.checked.config_path() != checked.config_path()
            || self.checked.target() != checked.target()
            || self.checked.descriptor_sha256() != checked.descriptor_sha256()
        {
            Err(err!(ESTALE, "STARTUP_LEASE_CONTEXT_CHANGED"))
        } else {
            Ok(())
        };
        let mut observed = Vec::new();
        if self.poisoned {
            observed.push(err!(EACCES, "STARTUP_LEASE_POISONED"));
        }
        for result in [
            native_root(),
            selected(&self.checked),
            exclusive_role(self.checked.target().role, self.lock),
            context,
            self.directory.assert_current(&self.checked),
            self.file.assert_current(self.directory.directory()),
            marker(self.directory.directory(), self.lock.marker_present()),
            self.directory.assert_current(&self.checked),
        ] {
            if let Err(error) = result {
                observed.push(error);
            }
        }
        observed
    }
    fn assert_current(&mut self, checked: &CheckedDeploymentTarget) -> EnclaveResult<()> {
        if self.poisoned {
            fail!(EACCES, "STARTUP_LEASE_POISONED");
        }
        let result = (|| {
            native_root()?;
            selected(checked)?;
            exclusive_role(checked.target().role, self.lock)?;
            if self.checked.config_path() != checked.config_path()
                || self.checked.descriptor_sha256() != checked.descriptor_sha256()
                || self.checked.target() != checked.target()
            {
                fail!(ESTALE, "STARTUP_LEASE_CONTEXT_CHANGED");
            }
            let directory = self.directory.assert_current(checked);
            let file = self.file.assert_current(self.directory.directory());
            let denial = marker(self.directory.directory(), self.lock.marker_present());
            directory?;
            file?;
            denial?;
            self.directory.assert_current(checked)?;
            self.file.assert_current(self.directory.directory())?;
            marker(self.directory.directory(), self.lock.marker_present())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}
/// Observe EX on the same permanent inode only while inhibition is present.
/// No marker bytes are adopted as transaction authority. Provisioning, actual
/// host maintenance exclusion and old/ungated process handling are separate.
pub fn try_exclusive_inhibited(
    checked: &CheckedDeploymentTarget,
) -> EnclaveResult<ExclusiveStartupLease> {
    // Compatibility: existing EnclaveResult callers release an unadmitted
    // partial EX on Err. Same-invocation owners needing refusal retention must
    // use the additive retained API below and keep its entire failure alive.
    try_exclusive_inhibited_retained(checked).map_err(|failure| failure.error)
}
/// Observe inhibited EX with opaque original-owner retention on EVERY refusal.
/// Native root, immutable selection, exact checked descriptor/ancestry, original
/// fixed read-only inode and inhibition gates are unchanged. No creation or
/// installation authority is supplied. The genuine caller separately retains
/// its same maintenance guard and exact owned denial/inventory binding.
pub fn try_exclusive_inhibited_retained(
    checked: &CheckedDeploymentTarget,
) -> Result<ExclusiveStartupLease, ExclusiveStartupLeaseFailure> {
    let mut retained = ExclusiveAcquisition {
        checked: checked.clone(),
        directory: None,
        file: None,
        owner: None,
        acquired: false,
    };
    let mut final_errors = Vec::new();
    let operation = (|| {
        native_root()?;
        selected(checked)?;
        exclusive_role(checked.target().role, Lock::Exclusive)?;
        retained.directory = Some(HeldUpgradeDirectory::open(checked)?);
        let directory = retained
            .directory
            .as_ref()
            .expect("original support ancestry");
        match acquire_retained(
            directory.directory(),
            Owner::ROOT,
            Lock::Exclusive,
            &mut || {
                native_root()?;
                selected(checked)?;
                exclusive_role(checked.target().role, Lock::Exclusive)?;
                directory.assert_current(checked)
            },
        ) {
            Ok(file) => {
                retained.file = Some(file);
                retained.acquired = true;
            }
            Err(failure) => {
                retained.file = failure.file;
                retained.acquired = failure.acquired;
                final_errors.extend(failure.final_errors);
                return Err(failure.error);
            }
        }
        retained.owner = Some(ExclusiveOwner {
            directory: retained
                .directory
                .take()
                .expect("original support ancestry"),
            file: retained.file.take().expect("original EX"),
            checked: checked.clone(),
            lock: Lock::Exclusive,
            poisoned: false,
            identity: Arc::new(()),
        });
        // Install the complete actual owner BEFORE its final assertion. A
        // refusal poisons it in place but cannot release the acquired EX.
        retained
            .owner
            .as_mut()
            .expect("installed original EX owner")
            .assert_current(checked)
    })();
    // All available final gates run even after an earlier native/selection,
    // ancestry, name/marker or lock refusal. They cannot authorize a retry.
    final_errors.extend(retained.observations(checked));
    if let Some(error) = operation.err().or_else(|| final_errors.first().cloned()) {
        if let Some(owner) = &mut retained.owner {
            owner.poisoned = true;
        }
        return Err(ExclusiveStartupLeaseFailure {
            error,
            final_errors,
            owner: retained,
        });
    }
    Ok(ExclusiveStartupLease {
        owner: retained.owner.take().expect("verified original EX owner"),
    })
}

/// Exclusive kernel observation for a dedicated target with no denial marker.
/// This does not prove a private birth, absence of old/ungated actors, complete
/// inactivity or authority to publish any files. A native installer must retain
/// its own genuine birth, host-maintenance, account and release owners. Existing
/// upgrade targets cannot use this type to bypass their inhibition protocol.
/// No descriptors, unlock, creation, marker removal or authority APIs exist.
pub struct DedicatedStartupLease {
    owner: ExclusiveOwner,
}
impl DedicatedStartupLease {
    /// Recheck the same selected dedicated target, ancestry and permanent
    /// inode. Poison retains EX until this owner is dropped, even if a later
    /// check would otherwise pass. Presence of any denial-marker type refuses.
    pub fn assert_current(&mut self, checked: &CheckedDeploymentTarget) -> EnclaveResult<()> {
        self.owner.assert_current(checked)
    }
}
/// Try a nonblocking EX observation without provisioning or changing visibility.
/// Native root, immutable selection and DedicatedTest role are mandatory.
/// Dropping EX permits cooperating startup; the caller must separately ensure
/// it never exposes an incomplete target or infers a completed installation.
pub fn try_exclusive_dedicated(
    checked: &CheckedDeploymentTarget,
) -> EnclaveResult<DedicatedStartupLease> {
    Ok(DedicatedStartupLease {
        owner: exclusive_owner(checked, Lock::DedicatedExclusive)?,
    })
}
fn exclusive_owner(checked: &CheckedDeploymentTarget, lock: Lock) -> EnclaveResult<ExclusiveOwner> {
    native_root()?;
    selected(checked)?;
    exclusive_role(checked.target().role, lock)?;
    let directory = HeldUpgradeDirectory::open(checked)?;
    let file = acquire(directory.directory(), Owner::ROOT, lock, &mut || {
        native_root()?;
        selected(checked)?;
        exclusive_role(checked.target().role, lock)?;
        directory.assert_current(checked)
    })?;
    let mut result = ExclusiveOwner {
        directory,
        file,
        checked: checked.clone(),
        lock,
        poisoned: false,
        identity: Arc::new(()),
    };
    result.assert_current(checked)?;
    Ok(result)
}

#[cfg(test)]
#[path = "deployment_startup_lease_tests.rs"]
mod tests;
