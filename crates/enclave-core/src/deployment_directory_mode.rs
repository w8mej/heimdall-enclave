//! Private actual-syscall engine for a retained support-ancestry directory.
//! Immutable admission stamps remain intact. Only a verified own chmod may
//! add the exact predicted metadata overlay. No lookup supplies a new owner.
use super::*;
use crate::error::EnclaveError;

/// Public metadata only. Constructing this value supplies no event authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectoryModeIdentity {
    /// Device containing the observed directory.
    pub dev: u64,
    /// Inode number of the observed directory.
    pub ino: u64,
    /// Numeric owner UID from the observed metadata.
    pub uid: u32,
    /// Numeric group GID from the observed metadata.
    pub gid: u32,
    /// Complete Unix mode, including the directory file type.
    pub mode: u32,
}
impl DirectoryModeIdentity {
    fn of(m: &Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
        }
    }
    fn stamp(self) -> DirectoryStamp {
        DirectoryStamp {
            dev: self.dev,
            ino: self.ino,
            uid: self.uid,
            gid: self.gid,
            mode: self.mode,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Snapshot {
    identity: DirectoryModeIdentity,
    links: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
impl Snapshot {
    fn of(m: &Metadata) -> Self {
        Self {
            identity: DirectoryModeIdentity::of(m),
            links: m.nlink(),
            modified: (m.mtime(), m.mtime_nsec()),
            changed: (m.ctime(), m.ctime_nsec()),
        }
    }
}
/// Historical effect observations only; even a successful chmod is not an
/// inactivity, visibility policy, readiness or installation approval.
#[derive(Debug)]
pub struct DirectoryModeEffect {
    path: PathBuf,
    before: Option<DirectoryModeIdentity>,
    observed: Option<DirectoryModeIdentity>,
    attempted: bool,
    succeeded: bool,
    errno: Option<i32>,
    verified: bool,
    durable: bool,
}
impl DirectoryModeEffect {
    fn new(path: &Path) -> Self {
        Self {
            path: path.to_owned(),
            before: None,
            observed: None,
            attempted: false,
            succeeded: false,
            errno: None,
            verified: false,
            durable: false,
        }
    }
    /// Original selected path of the attempted transition.
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Original held metadata, if inspection reached that observation.
    pub fn before(&self) -> Option<DirectoryModeIdentity> {
        self.before
    }
    /// Post-syscall held metadata, if it could be observed.
    pub fn observed(&self) -> Option<DirectoryModeIdentity> {
        self.observed
    }
    /// Whether the actual original-descriptor chmod syscall was attempted.
    pub fn syscall_attempted(&self) -> bool {
        self.attempted
    }
    /// Whether that syscall returned success; later verification may refuse.
    pub fn syscall_succeeded(&self) -> bool {
        self.succeeded
    }
    /// Immediate syscall errno when the attempted chmod returned failure.
    pub fn syscall_errno(&self) -> Option<i32> {
        self.errno
    }
    /// Whether both held and named metadata matched the exact predicted change.
    pub fn metadata_verified(&self) -> bool {
        self.verified
    }
    /// Whether synchronization of the original directory and parent completed.
    pub fn durability_completed(&self) -> bool {
        self.durable
    }
}
// Internal copies retain the same actual event in the ancestry overlay and
// outer opaque proof. No public event constructor/Clone/serde exists.
#[derive(Clone)]
pub(crate) struct VerifiedModeChange {
    path: PathBuf,
    before: Snapshot,
    after: Snapshot,
    durable: bool,
}
impl VerifiedModeChange {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn before(&self) -> DirectoryModeIdentity {
        self.before.identity
    }
    pub(crate) fn after(&self) -> DirectoryModeIdentity {
        self.after.identity
    }
    pub(crate) fn durable(&self) -> bool {
        self.durable
    }
    pub(crate) fn verify_recipient(
        &self,
        path: &Path,
        original: &File,
        named: &File,
        expected_old: DirectoryModeIdentity,
        native_acl: bool,
    ) -> EnclaveResult<()> {
        if path != self.path || expected_old != self.before.identity {
            fail!(ESTALE, "DIRECTORY_MODE_EVENT_ORIGINAL_MISMATCH");
        }
        for file in [original, named] {
            descriptor(file, native_acl)?;
            if Snapshot::of(&stat(file)?) != self.after {
                fail!(ESTALE, "DIRECTORY_MODE_EVENT_CURRENT_MISMATCH");
            }
        }
        Ok(())
    }
}
pub(crate) struct ModeOutcome {
    pub(crate) operation: EnclaveResult<()>,
    pub(crate) effect: DirectoryModeEffect,
    pub(crate) change: Option<VerifiedModeChange>,
}
impl ModeOutcome {
    pub(crate) fn refused(path: &Path, error: EnclaveError) -> Self {
        Self {
            operation: Err(error),
            effect: DirectoryModeEffect::new(path),
            change: None,
        }
    }
}
pub(crate) struct RetainedModeRefusal<T, C> {
    pub(crate) error: EnclaveError,
    pub(crate) boundary_errors: Vec<EnclaveError>,
    pub(crate) final_errors: Vec<EnclaveError>,
    pub(crate) effect: Option<DirectoryModeEffect>,
    pub(crate) change: Option<C>,
    pub(crate) owner: T,
}
// Same actual owned value on every path. SOFTWARE tests can exercise kernel
// owners here without constructing a native ExclusiveStartupLease capability.
pub(crate) fn resolve_retained<T, C>(
    owner: T,
    operation: EnclaveResult<()>,
    boundary_errors: Vec<EnclaveError>,
    final_errors: Vec<EnclaveError>,
    effect: Option<DirectoryModeEffect>,
    change: Option<C>,
) -> Result<(T, C), RetainedModeRefusal<T, C>> {
    let error = operation
        .err()
        .or_else(|| final_errors.first().cloned())
        .or_else(|| {
            change
                .is_none()
                .then(|| err!(EIO, "DIRECTORY_MODE_EVENT_REQUIRED"))
        });
    match error {
        Some(error) => Err(RetainedModeRefusal {
            error,
            boundary_errors,
            final_errors,
            effect,
            change,
            owner,
        }),
        None => Ok((owner, change.expect("successful actual event"))),
    }
}
fn descriptor(file: &File, native_acl: bool) -> EnclaveResult<()> {
    let access = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    if access < 0
        || access & libc::O_ACCMODE != libc::O_RDONLY
        || access & libc::O_NONBLOCK == 0
        || flags < 0
        || flags & libc::FD_CLOEXEC == 0
    {
        fail!(ESTALE, "DIRECTORY_MODE_DESCRIPTOR_FLAGS");
    }
    if !native_acl {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        use std::ffi::c_void;
        unsafe extern "C" {
            fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut c_void;
            fn acl_valid(acl: *mut c_void) -> libc::c_int;
            fn acl_get_entry(
                acl: *mut c_void,
                entry_id: libc::c_int,
                entry: *mut *mut c_void,
            ) -> libc::c_int;
            fn acl_free(object: *mut c_void) -> libc::c_int;
        }
        unsafe {
            *libc::__error() = 0;
        }
        let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), 0x100) };
        let errno = std::io::Error::last_os_error().raw_os_error();
        if acl.is_null() {
            if errno == Some(libc::ENOENT) {
                return Ok(());
            }
            fail!(EACCES, "DIRECTORY_MODE_ACL_INSPECTION_REQUIRED");
        }
        let valid = unsafe { acl_valid(acl) };
        let mut entry = std::ptr::null_mut();
        let found = unsafe { acl_get_entry(acl, 0, &mut entry) };
        let errno = std::io::Error::last_os_error().raw_os_error();
        let freed = unsafe { acl_free(acl) };
        if valid != 0 || found != -1 || errno != Some(libc::EINVAL) || freed != 0 {
            fail!(EACCES, "DIRECTORY_MODE_ACL_REFUSED");
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        fail!(ENOSYS, "DIRECTORY_MODE_NATIVE_ACL_REQUIRED");
    }
}
impl Node {
    fn expected_stamp(&self) -> DirectoryStamp {
        self.mode_change
            .as_ref()
            .map_or(self.stamp, |change| change.after.identity.stamp())
    }
}
impl Ancestry {
    pub(super) fn unchanged_private_directory(&self, path: &Path) -> bool {
        self.paths()
            .iter()
            .position(|held| held == path)
            .is_some_and(|index| {
                index > 0 && {
                    let node = &self.nodes[index];
                    node.mode_change.is_none()
                        && node.stamp.uid == 0
                        && node.stamp.gid == 0
                        && node.stamp.mode & 0o7777 == 0o700
                }
            })
    }
    pub(super) fn completed_mode_change(&self, path: &Path) -> bool {
        self.paths()
            .iter()
            .position(|held| held == path)
            .is_some_and(|index| {
                self.nodes[index]
                    .mode_change
                    .as_ref()
                    .is_some_and(|change| change.durable)
            })
    }
    pub(super) fn current_with_mode(
        &self,
        changed: Option<(usize, DirectoryStamp)>,
    ) -> EnclaveResult<()> {
        for (index, node) in self.nodes.iter().enumerate() {
            let expected = changed
                .filter(|(i, _)| *i == index)
                .map_or_else(|| node.expected_stamp(), |(_, stamp)| stamp);
            let held = stat(&node.file)?;
            if !protected(&held, self.owner) || DirectoryStamp::of(&held) != expected {
                fail!(ESTALE, "UPGRADE_INHIBITION_PARENT_CHANGED");
            }
            if let Some(name) = &node.name {
                let named = open_child(&self.nodes[index - 1].file, name)?;
                let fresh = stat(&named)?;
                if !protected(&fresh, self.owner) || DirectoryStamp::of(&fresh) != expected {
                    fail!(ESTALE, "UPGRADE_INHIBITION_PARENT_CHANGED");
                }
            }
        }
        Ok(())
    }
    fn paths(&self) -> Vec<PathBuf> {
        let mut path = self.base.clone();
        self.nodes
            .iter()
            .map(|node| {
                if let Some(name) = &node.name {
                    path.push(std::ffi::OsStr::from_bytes(name.as_bytes()));
                }
                path.clone()
            })
            .collect()
    }
    fn mode_checks(
        &self,
        check: &mut impl FnMut(&File) -> Vec<EnclaveError>,
        observed: &mut Vec<EnclaveError>,
        native_acl: bool,
    ) -> EnclaveResult<()> {
        let mut checks = check(self.parent());
        if let Err(error) = self.current() {
            checks.push(error);
        }
        for node in &self.nodes {
            if let Err(error) = descriptor(&node.file, native_acl) {
                checks.push(error);
            }
        }
        checks.extend(check(self.parent()));
        let result = checks.first().cloned().map_or(Ok(()), Err);
        observed.extend(checks);
        result
    }
    fn target(
        &self,
        index: usize,
        expected: Snapshot,
        native_acl: bool,
    ) -> EnclaveResult<Snapshot> {
        let node = &self.nodes[index];
        let name = node
            .name
            .as_ref()
            .ok_or_else(|| err!(EACCES, "DIRECTORY_MODE_EXTERNAL_ANCESTOR"))?;
        let named = open_child(&self.nodes[index - 1].file, name)?;
        for file in [&node.file, &named] {
            descriptor(file, native_acl)?;
        }
        let held = Snapshot::of(&stat(&node.file)?);
        let fresh = Snapshot::of(&stat(&named)?);
        if held != expected || fresh != expected {
            fail!(ESTALE, "DIRECTORY_MODE_ORIGINAL_CHANGED");
        }
        Ok(held)
    }
    // Production fixes owner to root:wheel and native ACL inspection. Ordinary
    // SOFTWARE tests supply only a synthetic anchor/owner, never a native EX.
    pub(super) fn change_original_mode(
        &mut self,
        path: &Path,
        owner: (u32, u32),
        native_acl: bool,
        check: &mut impl FnMut(&File) -> Vec<EnclaveError>,
        observed: &mut Vec<EnclaveError>,
        sync: &mut impl FnMut(&File) -> EnclaveResult<()>,
    ) -> ModeOutcome {
        self.change_original_mode_inner(path, owner, native_acl, check, observed, sync, &mut || {})
    }
    #[cfg(test)]
    pub(super) fn fixture_mode_post_syscall(
        &mut self,
        path: &Path,
        hook: &mut impl FnMut(),
        observed: &mut Vec<EnclaveError>,
    ) -> ModeOutcome {
        // Negative deterministic races AFTER a real fchmod, never a synthetic
        // syscall success or a constructor for a native/public EX capability.
        self.change_original_mode_inner(
            path,
            (unsafe { libc::geteuid() }, unsafe { libc::getegid() }),
            false,
            &mut |_| Vec::new(),
            observed,
            &mut |file| {
                file.sync_all()
                    .map_err(|_| err!(EIO, "DIRECTORY_MODE_FIXTURE_SYNC"))
            },
            hook,
        )
    }
    fn change_original_mode_inner(
        &mut self,
        path: &Path,
        owner: (u32, u32),
        native_acl: bool,
        check: &mut impl FnMut(&File) -> Vec<EnclaveError>,
        observed: &mut Vec<EnclaveError>,
        sync: &mut impl FnMut(&File) -> EnclaveResult<()>,
        after_syscall: &mut impl FnMut(),
    ) -> ModeOutcome {
        let mut effect = DirectoryModeEffect::new(path);
        let mut change = None;
        let operation = (|| {
            self.mode_checks(check, observed, native_acl)?;
            let index = self
                .paths()
                .iter()
                .position(|held| held == path)
                .ok_or_else(|| err!(EACCES, "DIRECTORY_MODE_ORIGINAL_NOT_HELD"))?;
            if index == 0 || self.nodes[index].mode_change.is_some() {
                fail!(EACCES, "DIRECTORY_MODE_EXTERNAL_OR_REPEATED");
            }
            let before = Snapshot::of(&stat(&self.nodes[index].file)?);
            effect.before = Some(before.identity);
            if before.identity.uid != owner.0
                || before.identity.gid != owner.1
                || before.identity.mode & 0o7777 != 0o700
                || before.identity.mode & libc::S_IFMT as u32 != libc::S_IFDIR as u32
                || before.identity.stamp() != self.nodes[index].stamp
            {
                fail!(EACCES, "DIRECTORY_MODE_ORIGINAL_PROTECTION");
            }
            if self.nodes.iter().enumerate().any(|(i, node)| {
                i != index
                    && node.stamp.dev == before.identity.dev
                    && node.stamp.ino == before.identity.ino
            }) {
                fail!(EACCES, "DIRECTORY_MODE_ORIGINAL_ALIAS");
            }
            self.mode_checks(check, observed, native_acl)?;
            // Last direct OLD binding after callbacks; no caller code runs
            // between this check and the actual syscall on the original FD.
            self.target(index, before, native_acl)?;
            self.current()?;
            effect.attempted = true;
            let result = unsafe { libc::fchmod(self.nodes[index].file.as_raw_fd(), 0o755) };
            if result != 0 {
                effect.errno = std::io::Error::last_os_error().raw_os_error();
                effect.observed = stat(&self.nodes[index].file)
                    .ok()
                    .map(|m| DirectoryModeIdentity::of(&m));
                fail!(EIO, "DIRECTORY_MODE_SYSCALL_UNCERTAIN");
            }
            effect.succeeded = true;
            after_syscall();
            let after = Snapshot::of(&stat(&self.nodes[index].file)?);
            effect.observed = Some(after.identity);
            let mut predicted = before.identity;
            predicted.mode = (predicted.mode & !0o7777) | 0o755;
            if after.identity != predicted
                || after.links != before.links
                || after.modified != before.modified
            {
                fail!(ESTALE, "DIRECTORY_MODE_UNEXPECTED_DELTA");
            }
            self.target(index, after, native_acl)?;
            self.current_with_mode(Some((index, predicted.stamp())))?;
            let verified = VerifiedModeChange {
                path: path.to_owned(),
                before,
                after,
                durable: false,
            };
            // Original node.stamp is immutable. Only proven own success
            // installs this one predicted overlay; a failed postcheck cannot.
            self.nodes[index].mode_change = Some(verified.clone());
            change = Some(verified);
            effect.verified = true;
            self.mode_checks(check, observed, native_acl)?;
            for node in [index, index - 1] {
                self.mode_checks(check, observed, native_acl)?;
                let synced = sync(&self.nodes[node].file);
                let post = self.mode_checks(check, observed, native_acl);
                synced?;
                post?;
            }
            effect.durable = true;
            change.as_mut().expect("verified own syscall").durable = true;
            self.nodes[index]
                .mode_change
                .as_mut()
                .expect("same verified overlay")
                .durable = true;
            self.mode_checks(check, observed, native_acl)
        })();
        // Keep every independent final observation, even after an uncertain
        // effect. Unknown metadata never becomes a new expected baseline.
        let finals = self.mode_checks(check, observed, native_acl);
        ModeOutcome {
            operation: operation.and(finals),
            effect,
            change,
        }
    }
}
