//! Selected intent's create-only console leaf. The native owner accepts only
//! real checked selection, maintenance and console observations. Kernel-only
//! tests below cannot manufacture that native owner.
use super::*;
use crate::deploy::{HostMaintenanceGuard, MaintenanceExclusion};

/// Observed syscall history; a returned success alone is never completion.
#[derive(Debug, Default, Clone, Serialize)]
pub struct IntentDirectorySyscall {
    /// Invocation was entered, including an uncertain error return.
    pub attempted: bool,
    /// Actual observed return; never inferred from later metadata.
    pub returned_success: Option<bool>,
    /// Fresh errno only on a failing direct syscall, never a composite sync.
    pub errno: Option<i32>,
}
impl IntentDirectorySyscall {
    fn enter(&mut self) {
        self.attempted = true;
    }
    fn returned(&mut self, success: bool) {
        self.returned_success = Some(success);
        self.errno = (!success)
            .then(|| std::io::Error::last_os_error().raw_os_error())
            .flatten();
    }
    fn sync_returned(&mut self, success: bool) {
        self.returned_success = Some(success);
        self.errno = None;
    }
}
/// Redacted directory progress, without installation or factor authority.
#[derive(Debug, Default, Clone, Serialize)]
pub struct IntentConsoleDirectoryReceipt {
    /// Existing exact leaf was observed; it was never modified.
    pub existing_exact: bool,
    /// Actual exclusive creation history.
    pub mkdir: IntentDirectorySyscall,
    /// Actual original-FD ownership handoff history.
    pub chown: IntentDirectorySyscall,
    /// Actual original-FD permission handoff history.
    pub chmod: IntentDirectorySyscall,
    /// Original child durability was attempted and returned successfully.
    pub child_sync: IntentDirectorySyscall,
    /// Original parent durability was attempted and returned successfully.
    pub parent_sync: IntentDirectorySyscall,
    /// Every required operation and final observation succeeded.
    pub complete: bool,
    /// All observed directory/native boundary refusals, in observation order.
    pub errors: Vec<EnclaveError>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Probe,
    Absent,
    Opened,
    Chowned,
    Chmodded,
    ChildSynced,
    Complete,
}
struct KernelDirectory {
    parent: File,
    parent_stamp: Stamp,
    path: PathBuf,
    uid: u32,
    gid: u32,
    child: Option<File>,
    original: Option<Stamp>,
    phase: Phase,
    failed: bool,
    receipt: IntentConsoleDirectoryReceipt,
}
fn directory_stat(file: &File) -> EnclaveResult<Metadata> {
    read_only_flags(file)?;
    native_acl(file)?;
    let m = file
        .metadata()
        .map_err(|_| err!(EIO, "INTENT_DIRECTORY_STAT"))?;
    if !m.is_dir() || m.nlink() == 0 {
        fail!(ESTALE, "INTENT_DIRECTORY_CHANGED");
    }
    Ok(m)
}
fn same_identity(a: &Stamp, b: &Stamp) -> bool {
    (a.dev, a.ino, a.uid, a.gid, a.mode) == (b.dev, b.ino, b.uid, b.gid, b.mode)
}
fn optional_child(parent: &File, path: &Path) -> EnclaveResult<Option<File>> {
    let name = leaf(path)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        fail!(EACCES, "INTENT_DIRECTORY_OPEN");
    }
    Ok(Some(unsafe { File::from_raw_fd(fd) }))
}
impl KernelDirectory {
    fn retain(&mut self, result: EnclaveResult<()>) -> EnclaveResult<()> {
        if let Err(error) = &result {
            self.failed = true;
            self.receipt.complete = false;
            self.receipt.errors.push(error.clone());
        }
        result
    }
    // Private kernel primitive only, never native/session/guard authority.
    fn new(parent: File, path: PathBuf, uid: u32, gid: u32) -> EnclaveResult<Self> {
        let parent_stamp = stamp(&directory_stat(&parent)?);
        Ok(Self {
            parent,
            parent_stamp,
            path,
            uid,
            gid,
            child: None,
            original: None,
            phase: Phase::Probe,
            failed: false,
            receipt: IntentConsoleDirectoryReceipt::default(),
        })
    }
    fn parent_current(&self) -> EnclaveResult<()> {
        if !same_identity(&self.parent_stamp, &stamp(&directory_stat(&self.parent)?)) {
            fail!(ESTALE, "INTENT_DIRECTORY_PARENT_CHANGED");
        }
        Ok(())
    }
    fn expected(&self) -> EnclaveResult<Stamp> {
        let mut expected = self
            .original
            .clone()
            .ok_or_else(|| err!(ESTALE, "INTENT_DIRECTORY_ORIGINAL_REQUIRED"))?;
        if self.receipt.existing_exact
            || matches!(
                self.phase,
                Phase::Chowned | Phase::Chmodded | Phase::ChildSynced | Phase::Complete
            )
        {
            expected.uid = self.uid;
            expected.gid = self.gid;
        }
        if self.receipt.existing_exact
            || matches!(
                self.phase,
                Phase::Chmodded | Phase::ChildSynced | Phase::Complete
            )
        {
            expected.mode = (expected.mode & !0o7777) | 0o2710;
        }
        Ok(expected)
    }
    fn current(&self) -> EnclaveResult<()> {
        self.parent_current()?;
        if let Some(child) = &self.child {
            let expected = self.expected()?;
            let held = stamp(&directory_stat(child)?);
            let named = optional_child(&self.parent, &self.path)?
                .ok_or_else(|| err!(ESTALE, "INTENT_DIRECTORY_NAME_LOST"))?;
            if !same_identity(&expected, &held)
                || !same_identity(&expected, &stamp(&directory_stat(&named)?))
            {
                fail!(ESTALE, "INTENT_DIRECTORY_CHANGED");
            }
        } else if self.phase == Phase::Absent && optional_child(&self.parent, &self.path)?.is_some()
        {
            fail!(ESTALE, "INTENT_DIRECTORY_APPEARED");
        }
        self.parent_current()
    }
    fn advance(&mut self) -> EnclaveResult<()> {
        let observed = self.current();
        self.retain(observed)?;
        self.advance_after_native_gate()
    }
    // Native caller just performed ALL original/current observations followed
    // by actual session+guard+deadline last. No duplicate slow precheck moves
    // that endpoint earlier than the real mutation. Kernel tests use advance.
    fn advance_after_native_gate(&mut self) -> EnclaveResult<()> {
        if self.failed {
            return self.retain(Err(err!(ESTALE, "INTENT_DIRECTORY_ATTEMPT_POISONED")));
        }
        let result = self.advance_once();
        self.retain(result)
    }
    fn advance_once(&mut self) -> EnclaveResult<()> {
        match self.phase {
            Phase::Probe => match optional_child(&self.parent, &self.path)? {
                None => self.phase = Phase::Absent,
                Some(child) => {
                    // Keep the actual opened FD even when its first metadata,
                    // ACL or descriptor-flag observation refuses.
                    self.child = Some(child);
                    let original =
                        stamp(&directory_stat(self.child.as_ref().expect("opened child"))?);
                    self.original = Some(original.clone());
                    if (original.uid, original.gid, original.mode & 0o7777)
                        != (self.uid, self.gid, 0o2710)
                    {
                        fail!(EACCES, "INTENT_DIRECTORY_EXISTING_METADATA");
                    }
                    self.receipt.existing_exact = true;
                    self.phase = Phase::Complete;
                }
            },
            Phase::Absent => {
                self.receipt.mkdir.enter();
                let ok = unsafe {
                    libc::mkdirat(self.parent.as_raw_fd(), leaf(&self.path)?.as_ptr(), 0o700)
                } == 0;
                self.receipt.mkdir.returned(ok);
                if !ok {
                    fail!(EIO, "INTENT_DIRECTORY_CREATE_UNCERTAIN");
                }
                let child = optional_child(&self.parent, &self.path)?
                    .ok_or_else(|| err!(ESTALE, "INTENT_DIRECTORY_NAME_LOST"))?;
                // Retain before any fallible first observation or metadata handoff.
                self.child = Some(child);
                let original = stamp(&directory_stat(self.child.as_ref().expect("opened child"))?);
                self.original = Some(original.clone());
                if original.uid != unsafe { libc::geteuid() }
                    || original.gid != self.parent_stamp.gid
                    || original.mode & 0o7077 != 0
                {
                    fail!(EACCES, "INTENT_DIRECTORY_NEW_METADATA");
                }
                self.phase = Phase::Opened;
            }
            Phase::Opened => {
                self.receipt.chown.enter();
                let ok = unsafe {
                    libc::fchown(
                        self.child.as_ref().expect("original child").as_raw_fd(),
                        self.uid,
                        self.gid,
                    )
                } == 0;
                self.receipt.chown.returned(ok);
                if !ok {
                    fail!(EIO, "INTENT_DIRECTORY_CHOWN_UNCERTAIN");
                }
                // Record actual syscall success, but do not advance expected state until
                // exact observed metadata agrees. Error-return state is never adopted.
                self.check_applied(
                    self.uid,
                    self.gid,
                    self.original.as_ref().expect("original").mode & 0o7777,
                )?;
                self.phase = Phase::Chowned;
            }
            Phase::Chowned => {
                self.receipt.chmod.enter();
                let ok = unsafe {
                    libc::fchmod(
                        self.child.as_ref().expect("original child").as_raw_fd(),
                        0o2710,
                    )
                } == 0;
                self.receipt.chmod.returned(ok);
                if !ok {
                    fail!(EIO, "INTENT_DIRECTORY_CHMOD_UNCERTAIN");
                }
                self.check_applied(self.uid, self.gid, 0o2710)?;
                self.phase = Phase::Chmodded;
            }
            Phase::Chmodded => {
                self.receipt.child_sync.enter();
                let result =
                    enclave_core::fsutil::full_fsync(self.child.as_ref().expect("original child"));
                self.receipt.child_sync.sync_returned(result.is_ok());
                if let Err(error) = &result {
                    self.receipt.errors.push(error.clone());
                }
                result.map_err(|_| err!(EIO, "INTENT_DIRECTORY_CHILD_SYNC_UNCERTAIN"))?;
                self.phase = Phase::ChildSynced;
            }
            Phase::ChildSynced => {
                self.receipt.parent_sync.enter();
                let result = enclave_core::fsutil::full_fsync(&self.parent);
                self.receipt.parent_sync.sync_returned(result.is_ok());
                if let Err(error) = &result {
                    self.receipt.errors.push(error.clone());
                }
                result.map_err(|_| err!(EIO, "INTENT_DIRECTORY_PARENT_SYNC_UNCERTAIN"))?;
                self.phase = Phase::Complete;
            }
            Phase::Complete => {
                fail!(EALREADY, "INTENT_DIRECTORY_ALREADY_PREPARED");
            }
        }
        self.current()?;
        Ok(())
    }
    fn check_applied(&self, uid: u32, gid: u32, mode: u32) -> EnclaveResult<()> {
        let original = self.original.as_ref().expect("original before mutation");
        let held = directory_stat(self.child.as_ref().expect("original child"))?;
        let named = optional_child(&self.parent, &self.path)?
            .ok_or_else(|| err!(ESTALE, "INTENT_DIRECTORY_NAME_LOST"))?;
        for m in [held, directory_stat(&named)?] {
            if (m.dev(), m.ino(), m.uid(), m.gid(), m.mode() & 0o7777)
                != (original.dev, original.ino, uid, gid, mode)
            {
                fail!(ESTALE, "INTENT_DIRECTORY_APPLIED_METADATA");
            }
        }
        self.parent_current()
    }
}

/// Actual native owner; no constructor accepts an externally asserted session.
pub(in crate::ctl) struct IntentConsoleDirectoryAttempt {
    paths: HeldPaths,
    descriptor: HeldFile,
    checked: CheckedDeploymentTarget,
    session: (u32, u32),
    parent: PathBuf,
    kernel: KernelDirectory,
}
/// Refusal owns the actual constructed native attempt through terminal checks.
#[must_use = "retain actual constructed directory owner and all its observations"]
pub(in crate::ctl) struct IntentConsoleDirectoryOpenFailure {
    pub(in crate::ctl) error: EnclaveError,
    pub(in crate::ctl) owner: Option<IntentConsoleDirectoryAttempt>,
}
fn native_session() -> EnclaveResult<(u32, u32)> {
    #[cfg(target_os = "macos")]
    {
        match enclave_custody_vaultd::oidc_acquisition::current_console_session() {
            Some((uid, audit)) if uid >= 500 && uid < u32::MAX && audit > 0 && audit < u32::MAX => {
                Ok((uid, audit))
            }
            _ => Err(err!(EACCES, "INTENT_DIRECTORY_CONSOLE_UNAVAILABLE")),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        fail!(ENOSYS, "INTENT_DIRECTORY_NATIVE_REQUIRED");
    }
}
impl IntentConsoleDirectoryAttempt {
    pub(in crate::ctl) fn open(
        checked: &CheckedDeploymentTarget,
        guard: &mut HostMaintenanceGuard,
        until: Instant,
    ) -> Result<Self, IntentConsoleDirectoryOpenFailure> {
        let mut owner = match Self::open_originals(checked, guard, until) {
            Ok(owner) => owner,
            Err(error) => return Err(IntentConsoleDirectoryOpenFailure { error, owner: None }),
        };
        match owner.gate(checked, guard, until) {
            Ok(()) => Ok(owner),
            Err(error) => Err(IntentConsoleDirectoryOpenFailure {
                error,
                owner: Some(owner),
            }),
        }
    }
    fn open_originals(
        checked: &CheckedDeploymentTarget,
        guard: &mut HostMaintenanceGuard,
        until: Instant,
    ) -> EnclaveResult<Self> {
        if !cfg!(target_os = "macos") {
            fail!(ENOSYS, "INTENT_DIRECTORY_NATIVE_REQUIRED");
        }
        if unsafe { libc::geteuid() } != 0 {
            fail!(EPERM, "INTENT_DIRECTORY_ROOT_REQUIRED");
        }
        guard.assert_held()?;
        deployment::upgrade::assert_start_allowed(checked)?;
        if Instant::now() >= until {
            fail!(ETIMEDOUT, "INTENT_DIRECTORY_DEADLINE");
        }
        let selected =
            deployment::selected().ok_or_else(|| err!(EACCES, "DEPLOYMENT_CONTEXT_REQUIRED"))?;
        if selected.target() != checked.target()
            || selected.config_path() != checked.config_path()
            || selected.descriptor_sha256() != checked.descriptor_sha256()
        {
            fail!(EACCES, "INTENT_DIRECTORY_SELECTION");
        }
        let session = native_session()?;
        let mut paths = HeldPaths::new_native_acl_protected()?;
        let (descriptor, _) = HeldFile::open(&mut paths, checked.config_path(), 65536, None)?;
        if descriptor.sha256() != checked.descriptor_sha256() {
            fail!(ESTALE, "DEPLOYMENT_CHANGED");
        }
        let parent = checked.target().layout.socket_root.join("intent");
        paths.hold_directory(&checked.target().layout.socket_root, Some((0, 0, 0o755)))?;
        paths.hold_directory(&parent, Some((0, 0, 0o755)))?;
        let file = paths.directories[&parent]
            .file
            .try_clone()
            .map_err(|_| err!(EIO, "INTENT_DIRECTORY_PARENT_FD"))?;
        let kernel =
            KernelDirectory::new(file, parent.join(session.0.to_string()), session.0, 8703)?;
        Ok(Self {
            paths,
            descriptor,
            checked: checked.clone(),
            session,
            parent,
            kernel,
        })
    }
    pub(in crate::ctl) fn session_matches(&self, uid: u32, audit: u32) -> EnclaveResult<()> {
        if self.session != (uid, audit) {
            fail!(ESTALE, "INTENT_DIRECTORY_CONSOLE_CHANGED");
        }
        Ok(())
    }
    fn observations(
        &self,
        checked: &CheckedDeploymentTarget,
        guard: &mut HostMaintenanceGuard,
        until: Instant,
    ) -> Vec<EnclaveError> {
        let mut errors = Vec::new();
        let binding = if self.checked.target() != checked.target()
            || self.checked.config_path() != checked.config_path()
            || self.checked.descriptor_sha256() != checked.descriptor_sha256()
        {
            Err(err!(ESTALE, "INTENT_DIRECTORY_SELECTION"))
        } else {
            Ok(())
        };
        for result in [
            binding,
            self.paths.revalidate(),
            self.descriptor.revalidate(&self.paths),
            self.kernel.current(),
            deployment::upgrade::assert_start_allowed(checked),
            native_session().and_then(|pair| self.session_matches(pair.0, pair.1)),
            guard.assert_held(),
            if Instant::now() >= until {
                Err(err!(ETIMEDOUT, "INTENT_DIRECTORY_DEADLINE"))
            } else {
                Ok(())
            },
        ] {
            if let Err(error) = result {
                errors.push(error);
            }
        }
        errors
    }
    fn gate(
        &mut self,
        checked: &CheckedDeploymentTarget,
        guard: &mut HostMaintenanceGuard,
        until: Instant,
    ) -> EnclaveResult<()> {
        let errors = self.observations(checked, guard, until);
        let first = errors.first().cloned();
        self.kernel.receipt.errors.extend(errors);
        if let Some(error) = first {
            self.kernel.failed = true;
            self.kernel.receipt.complete = false;
            return Err(error);
        }
        Ok(())
    }
    pub(in crate::ctl) fn prepare(
        &mut self,
        checked: &CheckedDeploymentTarget,
        guard: &mut HostMaintenanceGuard,
        prepared: &crate::ctl::target_intent::PreparedIntent,
        until: Instant,
    ) -> EnclaveResult<()> {
        while self.kernel.phase != Phase::Complete {
            // Concrete original public/native owner, no verifier callback/provider.
            let original = prepared.revalidate(checked);
            let original = self.kernel.retain(original);
            let before = self.gate(checked, guard, until);
            original?;
            before?;
            let step = self.kernel.advance_after_native_gate();
            let original = prepared.revalidate(checked);
            let original = self.kernel.retain(original);
            let after = self.gate(checked, guard, until);
            step?;
            original?;
            after?;
        }
        self.gate(checked, guard, until)?;
        if self.kernel.failed || !self.kernel.receipt.errors.is_empty() {
            return self
                .kernel
                .retain(Err(err!(ESTALE, "INTENT_DIRECTORY_ATTEMPT_POISONED")));
        }
        self.kernel.receipt.complete = true;
        Ok(())
    }
    pub(in crate::ctl) fn admit_same_child(&mut self, paths: &mut HeldPaths) -> EnclaveResult<()> {
        let admitted = (|| {
            if !self.kernel.receipt.complete || self.kernel.failed {
                fail!(ESTALE, "INTENT_DIRECTORY_INCOMPLETE");
            }
            self.kernel.current()?;
            paths.hold_directory(&self.parent, Some((0, 0, 0o755)))?;
            paths.hold_directory(&self.kernel.path, Some((self.session.0, 8703, 0o2710)))?;
            let admitted = &paths.directories[&self.kernel.path].file;
            let original = self.kernel.original.as_ref().expect("complete original");
            let current = stamp(&directory_stat(admitted)?);
            if (current.dev, current.ino) != (original.dev, original.ino) {
                fail!(ESTALE, "INTENT_DIRECTORY_CHANGED");
            }
            self.kernel.current()
        })();
        self.kernel.retain(admitted)
    }
    pub(in crate::ctl) fn finish(
        &mut self,
        checked: &CheckedDeploymentTarget,
        guard: &mut HostMaintenanceGuard,
        until: Instant,
    ) -> EnclaveResult<()> {
        self.gate(checked, guard, until)?;
        if !self.kernel.receipt.complete || self.kernel.failed {
            return self
                .kernel
                .retain(Err(err!(ESTALE, "INTENT_DIRECTORY_INCOMPLETE")));
        }
        Ok(())
    }
    pub(in crate::ctl) fn receipt(&self) -> IntentConsoleDirectoryReceipt {
        self.kernel.receipt.clone()
    }
}

#[cfg(test)]
#[path = "ctl_target_intent_directory_tests.rs"]
mod tests;
