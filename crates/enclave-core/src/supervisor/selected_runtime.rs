//! Selected runtime originals, with an effect-free startup refusal.
//!
//! This branch cannot serve until the actual monitor/resource/PF/Begin owners
//! are integrated. It never calls the legacy normalizer or restoring watcher.
use std::{ffi::CString, fs::{File, Metadata}, os::{fd::{AsRawFd, FromRawFd},
    unix::{ffi::OsStrExt, fs::{FileExt, MetadataExt}}}, path::{Component, Path, PathBuf},
    sync::Arc, time::{Duration, Instant}};
use sha2::{Digest, Sha256};
use crate::{deployment::{self, CheckedDeploymentTarget, DeploymentRole, DeploymentSigningMode,
    DeploymentTarget}, error::EnclaveResult, profile::Profile, err};

const MAX_ANCESTORS: usize = 64;
const ADMISSION_LIMIT: Duration = Duration::from_secs(5);
const MISSING_DEPENDENCIES: &str = "actual retained startup lifetime lease, power/USB owner health, primary/held worker progress, selected Mach receiver and current custody exception assignment, effective BOTH-anchor PF/root policy and kqueue/SCDynamicStore atomic-restoration health, actual custody Begin dependency gate";

fn target_scope(target: &DeploymentTarget) -> bool {
    target.role == DeploymentRole::DedicatedTest && target.profile == Profile::L2
        && target.signing_identity_mode == DeploymentSigningMode::LocalPins
        && target.broker.is_none() && target.shared_read_only_inputs.is_empty()
}

/// Dispatch before every legacy service effect. A wrong runtime path/profile
/// still enters this refusing branch, rather than falling back to legacy work.
pub(super) fn handles_selected(dev: bool) -> bool {
    cfg!(target_os = "macos") && !dev
        && deployment::selected().is_some_and(|checked| target_scope(checked.target()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reason {
    NativeRequired, RootRequired, SelectionRequired, ContextChanged, UnsupportedScope,
    ProfileMismatch, RouteMismatch, UpgradeDenied, Deadline, InvalidPath,
    Open, Metadata, Type, Protection, Links, Size, DescriptorFlags,
    NativeAclRequired, AclInspection, AclRefused, Changed, Read,
    DescriptorMismatch, Incomplete, Poisoned, SelectedOwner,
}
type Check<T> = Result<T, Reason>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role { Descriptor, Mesh, Supervisor }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase { Admission, Revalidation }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Refusal { role: Option<Role>, phase: Phase, reason: Reason }

fn within(until: Instant) -> Check<()> {
    if Instant::now() >= until { Err(Reason::Deadline) } else { Ok(()) }
}
fn native_root() -> Check<()> {
    if !cfg!(target_os = "macos") { return Err(Reason::NativeRequired); }
    if unsafe { libc::geteuid() } != 0 { return Err(Reason::RootRequired); }
    Ok(())
}
enum Context {
    Native(&'static CheckedDeploymentTarget),
    #[cfg(test)]
    Fixture(Box<dyn FnMut() -> Check<()>>),
}
impl Context {
    fn current(&mut self) -> Check<()> {
        match self {
            Self::Native(checked) => {
                native_root()?;
                let actual = deployment::selected().ok_or(Reason::SelectionRequired)?;
                if !std::ptr::eq(*checked, actual) { return Err(Reason::ContextChanged); }
                if !target_scope(actual.target()) || crate::codesign::signing_mode() != crate::codesign::SigningMode::LocalPins {
                    return Err(Reason::UnsupportedScope);
                }
                deployment::upgrade::assert_start_allowed(actual).map_err(|_| Reason::UpgradeDenied)
            }
            #[cfg(test)]
            Self::Fixture(check) => check(),
        }
    }
}

#[derive(Clone)]
enum Protection {
    NativeRoot,
    // An explicit private software root never claims native/root protection.
    #[cfg(test)]
    Fixture { root: PathBuf, uid: u32 },
}
impl Protection {
    fn uid(&self) -> u32 {
        match self { Self::NativeRoot => 0, #[cfg(test)] Self::Fixture { uid, .. } => *uid }
    }
    fn inspect(&self, file: &File) -> Check<()> {
        let access = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
        if access < 0 || access & libc::O_ACCMODE != libc::O_RDONLY || access & libc::O_NONBLOCK == 0
            || flags < 0 || flags & libc::FD_CLOEXEC == 0 { return Err(Reason::DescriptorFlags); }
        match self {
            Self::NativeRoot => native_empty_acl(file),
            #[cfg(test)] Self::Fixture { .. } => Ok(()),
        }
    }
}
fn native_empty_acl(file: &File) -> Check<()> {
    #[cfg(target_os = "macos")]
    {
        use std::ffi::c_void;
        unsafe extern "C" {
            fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut c_void;
            fn acl_valid(acl: *mut c_void) -> libc::c_int;
            fn acl_get_entry(acl: *mut c_void, id: libc::c_int, entry: *mut *mut c_void) -> libc::c_int;
            fn acl_free(object: *mut c_void) -> libc::c_int;
        }
        unsafe { *libc::__error() = 0; }
        let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), 0x100) };
        let errno = std::io::Error::last_os_error().raw_os_error();
        if acl.is_null() { return if errno == Some(libc::ENOENT) { Ok(()) } else { Err(Reason::AclInspection) }; }
        let valid = unsafe { acl_valid(acl) };
        let mut entry = std::ptr::null_mut();
        let found = unsafe { acl_get_entry(acl, 0, &mut entry) };
        let errno = std::io::Error::last_os_error().raw_os_error();
        let freed = unsafe { acl_free(acl) };
        if valid != 0 || found != -1 || errno != Some(libc::EINVAL) || freed != 0 { return Err(Reason::AclRefused); }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    { let _ = file; Err(Reason::NativeAclRequired) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity { dev: u64, ino: u64, uid: u32, gid: u32, mode: u32 }
impl Identity {
    fn of(metadata: &Metadata) -> Self {
        Self { dev: metadata.dev(), ino: metadata.ino(), uid: metadata.uid(), gid: metadata.gid(), mode: metadata.mode() }
    }
    fn named(metadata: &libc::stat) -> Self {
        Self { dev: metadata.st_dev as u64, ino: metadata.st_ino as u64, uid: metadata.st_uid,
            gid: metadata.st_gid, mode: metadata.st_mode as u32 }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp { identity: Identity, content: Option<(u64, u64, i64, i64, i64, i64)> }
impl Stamp {
    fn of(metadata: &Metadata, file: bool) -> Self {
        Self { identity: Identity::of(metadata), content: file.then(|| (metadata.len(), metadata.nlink(),
            metadata.mtime(), metadata.mtime_nsec(), metadata.ctime(), metadata.ctime_nsec())) }
    }
}
enum Expected { Descriptor(String), Directory { gid: u32, mode: u32 } }
struct Spec { role: Role, path: PathBuf, expected: Expected }
fn binding(socket_dir: &Path, profile: Profile, target: &DeploymentTarget) -> Check<()> {
    if profile != target.profile { return Err(Reason::ProfileMismatch); }
    if socket_dir != target.layout.socket_root { return Err(Reason::RouteMismatch); }
    Ok(())
}
fn runtime_specs(target: &DeploymentTarget, descriptor: &Path, descriptor_sha256: &str) -> Check<Vec<Spec>> {
    Ok(vec![
        Spec { role: Role::Descriptor, path: deployment::normalized_path(descriptor).map_err(|_| Reason::InvalidPath)?,
            expected: Expected::Descriptor(descriptor_sha256.into()) },
        Spec { role: Role::Mesh, path: deployment::normalized_path(&target.layout.socket_root).map_err(|_| Reason::InvalidPath)?,
            expected: Expected::Directory { gid: 0, mode: 0o755 } },
        Spec { role: Role::Supervisor, path: deployment::normalized_path(&target.layout.socket_root.join(super::SOCKET_DIR)).map_err(|_| Reason::InvalidPath)?,
            expected: Expected::Directory { gid: super::CLIENT_GID, mode: 0o2750 } },
    ])
}
impl Spec {
    fn is_file(&self) -> bool { matches!(&self.expected, Expected::Descriptor(_)) }
    fn safe(&self, metadata: &Metadata, leaf: bool, uid: u32) -> Check<()> {
        if leaf && self.is_file() {
            if !metadata.is_file() { return Err(Reason::Type); }
            if metadata.nlink() != 1 { return Err(Reason::Links); }
            if metadata.len() == 0 || metadata.len() > deployment::MAX_DESCRIPTOR_BYTES as u64 { return Err(Reason::Size); }
        } else if !metadata.is_dir() { return Err(Reason::Type); }
        if metadata.uid() != uid || metadata.mode() & 0o022 != 0 { return Err(Reason::Protection); }
        if let Expected::Directory { gid, mode } = &self.expected {
            if leaf && (metadata.gid() != *gid || metadata.mode() & 0o7777 != *mode) { return Err(Reason::Protection); }
        }
        Ok(())
    }
}
struct Node { name: CString, file: Arc<File>, leaf: bool, stamp: Option<Stamp> }
struct HeldRoute { spec: Spec, protection: Protection, nodes: Vec<Node>, admitted: bool }
fn named(parent: Option<&File>, name: &CString) -> Check<libc::stat> {
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(parent.map_or(libc::AT_FDCWD, AsRawFd::as_raw_fd), name.as_ptr(),
        &mut metadata, libc::AT_SYMLINK_NOFOLLOW) } != 0 { return Err(Reason::Metadata); }
    Ok(metadata)
}
impl HeldRoute {
    fn new(spec: Spec, protection: Protection) -> Self { Self { spec, protection, nodes: Vec::new(), admitted: false } }
    fn admit_last(&mut self) -> Check<()> {
        let node = self.nodes.last_mut().expect("retain every opened descriptor first");
        let metadata = node.file.metadata().map_err(|_| Reason::Metadata)?;
        node.stamp = Some(Stamp::of(&metadata, node.leaf && self.spec.is_file()));
        self.spec.safe(&metadata, node.leaf, self.protection.uid())?;
        self.protection.inspect(&node.file)
    }
    fn open(&mut self, until: Instant) -> Check<()> {
        within(until)?;
        deployment::normalized_path(&self.spec.path).map_err(|_| Reason::InvalidPath)?;
        let (root, relative) = match &self.protection {
            Protection::NativeRoot => (Path::new("/"), self.spec.path.as_path()),
            #[cfg(test)] Protection::Fixture { root, .. } => (root.as_path(), self.spec.path.strip_prefix(root).map_err(|_| Reason::InvalidPath)?),
        };
        let parts = relative.components().filter_map(|part| match part {
            Component::Normal(name) => Some(CString::new(name.as_bytes()).map_err(|_| Reason::InvalidPath)), _ => None,
        }).collect::<Check<Vec<_>>>()?;
        if parts.is_empty() || parts.len() > MAX_ANCESTORS { return Err(Reason::InvalidPath); }
        let root = CString::new(root.as_os_str().as_bytes()).map_err(|_| Reason::InvalidPath)?;
        let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
        let fd = unsafe { libc::open(root.as_ptr(), flags | libc::O_DIRECTORY) };
        if fd < 0 { return Err(Reason::Open); }
        self.nodes.push(Node { name: root, file: Arc::new(unsafe { File::from_raw_fd(fd) }), leaf: false, stamp: None });
        self.admit_last()?;
        let count = parts.len();
        for (index, name) in parts.into_iter().enumerate() {
            within(until)?;
            let leaf = index + 1 == count;
            let file = leaf && self.spec.is_file();
            let parent = &self.nodes.last().expect("retained root").file;
            let before = named(Some(parent), &name)?;
            if before.st_mode & libc::S_IFMT != if file { libc::S_IFREG } else { libc::S_IFDIR } { return Err(Reason::Type); }
            let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags | if file { 0 } else { libc::O_DIRECTORY }) };
            if fd < 0 { return Err(Reason::Open); }
            self.nodes.push(Node { name, file: Arc::new(unsafe { File::from_raw_fd(fd) }), leaf, stamp: None });
            self.admit_last()?;
            let after = self.nodes.last().expect("retained opened node").file.metadata().map_err(|_| Reason::Metadata)?;
            if Identity::named(&before) != Identity::of(&after) { return Err(Reason::Changed); }
        }
        self.descriptor_current(until)?;
        if let Some(error) = self.inspect(until).first() { return Err(*error); }
        self.admitted = true;
        Ok(())
    }
    fn descriptor_current(&self, until: Instant) -> Check<()> {
        let Expected::Descriptor(expected) = &self.spec.expected else { return Ok(()); };
        let node = self.nodes.last().filter(|node| node.leaf).ok_or(Reason::Incomplete)?;
        let before = node.file.metadata().map_err(|_| Reason::Metadata)?;
        self.spec.safe(&before, true, self.protection.uid())?;
        let mut digest = Sha256::new(); let mut offset = 0u64; let mut buffer = [0u8; 8192];
        loop {
            within(until)?;
            let wanted = buffer.len().min(deployment::MAX_DESCRIPTOR_BYTES + 1 - offset as usize);
            if wanted == 0 { return Err(Reason::Size); }
            let count = node.file.read_at(&mut buffer[..wanted], offset).map_err(|_| Reason::Read)?;
            if count == 0 { break; }
            offset += count as u64;
            if offset > deployment::MAX_DESCRIPTOR_BYTES as u64 { return Err(Reason::Size); }
            digest.update(&buffer[..count]);
        }
        let after = node.file.metadata().map_err(|_| Reason::Metadata)?;
        if Stamp::of(&before, true) != Stamp::of(&after, true) || offset != before.len() { return Err(Reason::Changed); }
        if hex::encode(digest.finalize()) != *expected { return Err(Reason::DescriptorMismatch); }
        within(until)
    }
    fn inspect(&self, until: Instant) -> Vec<Reason> {
        let mut errors = Vec::new();
        if let Err(error) = within(until) { errors.push(error); }
        for (index, node) in self.nodes.iter().enumerate() {
            let metadata = match node.file.metadata() { Ok(metadata) => metadata, Err(_) => { errors.push(Reason::Metadata); continue; } };
            if let Err(error) = self.spec.safe(&metadata, node.leaf, self.protection.uid()) { errors.push(error); }
            if let Err(error) = self.protection.inspect(&node.file) { errors.push(error); }
            if node.stamp != Some(Stamp::of(&metadata, node.leaf && self.spec.is_file())) { errors.push(Reason::Changed); }
            let parent = index.checked_sub(1).map(|parent| self.nodes[parent].file.as_ref());
            match named(parent, &node.name) {
                Ok(current) if Identity::named(&current) == Identity::of(&metadata) => (),
                Ok(_) => errors.push(Reason::Changed), Err(error) => errors.push(error),
            }
        }
        if let Err(error) = within(until) { errors.push(error); }
        errors
    }
    fn current(&self, until: Instant) -> Vec<Reason> {
        let mut errors = self.inspect(until);
        if !self.admitted { errors.push(Reason::Incomplete); }
        if let Err(error) = self.descriptor_current(until) { errors.push(error); }
        errors.extend(self.inspect(until));
        errors
    }
}

/// Private actual owner: never Clone/serde/FD-extractable or caller-constructible.
/// Any refusal permanently poisons this owner without replacing its originals.
pub(super) struct SelectedRuntime {
    // Drop this bundle before the route Arcs: SAME session is revoked before
    // any listener/worker/monitor/parent cleanup can block or become unknown.
    #[cfg(target_os = "macos")]
    selected_owner: Option<SelectedOwner>,
    context: Option<Context>, routes: Vec<HeldRoute>, refusals: Vec<Refusal>, poisoned: bool,
}
impl SelectedRuntime {
    fn empty() -> Self { Self {
        #[cfg(target_os = "macos")]
        selected_owner: None,
        context: None, routes: Vec::new(), refusals: Vec::new(), poisoned: false,
    } }
    fn retain(&mut self, role: Option<Role>, phase: Phase, reason: Reason) {
        self.poisoned = true; self.refusals.push(Refusal { role, phase, reason });
    }
    pub(super) fn acquire_selected(socket_dir: &Path, profile: Profile, until: Instant) -> Self {
        let mut owner = Self::empty();
        let admission = (|| {
            within(until)?; native_root()?;
            let checked = deployment::selected().ok_or(Reason::SelectionRequired)?;
            owner.context = Some(Context::Native(checked));
            owner.context.as_mut().expect("actual selected context").current()?;
            binding(socket_dir, profile, checked.target())?;
            let specs = runtime_specs(checked.target(), checked.config_path(), checked.descriptor_sha256())?;
            owner.open(specs, Protection::NativeRoot, until);
            Ok(())
        })();
        if let Err(error) = admission { owner.retain(None, Phase::Admission, error); }
        owner.revalidate(until);
        owner
    }
    fn open(&mut self, specs: Vec<Spec>, protection: Protection, until: Instant) {
        for spec in specs {
            let mut route = HeldRoute::new(spec, protection.clone());
            let error = route.open(until).err();
            let role = route.spec.role;
            self.routes.push(route); // Retain partial owners before any refusal.
            if let Some(error) = error { self.retain(Some(role), Phase::Admission, error); }
        }
    }
    fn revalidate(&mut self, until: Instant) -> bool {
        let mut errors = Vec::new();
        if self.poisoned { errors.push((None, Reason::Poisoned)); }
        if self.routes.len() != 3 { errors.push((None, Reason::Incomplete)); }
        for route in &self.routes {
            errors.extend(route.current(until).into_iter().map(|error| (Some(route.spec.role), error)));
        }
        let context = self.context.as_mut().ok_or(Reason::SelectionRequired).and_then(Context::current);
        if let Err(error) = context { errors.push((None, error)); }
        if let Err(error) = within(until) { errors.push((None, error)); }
        for (role, reason) in errors { self.retain(role, Phase::Revalidation, reason); }
        !self.poisoned
    }
    /// Recheck only the admitted descriptor and protected routes; failure is
    /// irreversible. This is no session, actor-ACK, readiness or startup permit.
    pub(super) fn require_current(&mut self, until: Instant) -> EnclaveResult<()> {
        if !self.revalidate(until) {
            return Err(err!(EACCES, "SUPERVISOR_SELECTED_ORIGINALS_REFUSED"));
        }
        Ok(())
    }
    /// Borrow the original admitted mesh directory without reopening its name.
    /// Callers must require_current under their same shortening endpoint first.
    pub(super) fn mesh_parent(&self) -> EnclaveResult<&File> {
        if self.poisoned { return Err(err!(EACCES, "SUPERVISOR_SELECTED_ORIGINALS_REFUSED")); }
        self.routes.iter().find(|route| route.spec.role == Role::Mesh && route.admitted)
            .and_then(|route| route.nodes.last()).filter(|node| node.leaf)
            .map(|node| node.file.as_ref())
            .ok_or_else(|| err!(EACCES, "SUPERVISOR_SELECTED_ORIGINALS_REFUSED"))
    }
    /// Revalidate first, then share the SAME admitted mesh File allocation.
    /// This clones only Rust ownership: no name reopen or duplicate OS handle.
    pub(super) fn mesh_parent_lease(&mut self, until: Instant) -> EnclaveResult<Arc<File>> {
        self.require_current(until)?;
        let parent = self.routes.iter().find(|route| route.spec.role == Role::Mesh && route.admitted)
            .and_then(|route| route.nodes.last()).filter(|node| node.leaf)
            .map(|node| Arc::clone(&node.file))
            .ok_or_else(|| err!(EACCES, "SUPERVISOR_SELECTED_ORIGINALS_REFUSED"))?;
        self.require_current(until)?;
        Ok(parent)
    }
    /// Borrow the already-admitted original supervisor directory. The caller
    /// must first require_current under the same shortening endpoint.
    pub(super) fn supervisor_parent(&self) -> EnclaveResult<&File> {
        if self.poisoned { return Err(err!(EACCES, "SUPERVISOR_SELECTED_ORIGINALS_REFUSED")); }
        self.routes.iter().find(|route| route.spec.role == Role::Supervisor && route.admitted)
            .and_then(|route| route.nodes.last()).filter(|node| node.leaf)
            .map(|node| node.file.as_ref())
            .ok_or_else(|| err!(EACCES, "SUPERVISOR_SELECTED_ORIGINALS_REFUSED"))
    }
}

// This is pre-start composition only. The actual selected entry remains the
// unconditional refusal below; no readiness/PF/Mach prerequisite is supplied.
trait SelectedSessionVeto {fn veto_atomic(&self);}
#[cfg(target_os="macos")]
impl SelectedSessionVeto for crate::power::selected_owner_session::SelectedOwnerSession {
    fn veto_atomic(&self) {self.revoke();}
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum InputBindingFailure {Missing,Mismatch}
// Shared private identity algorithm: no native/file/current/stop/journal work.
// Failure revokes both original sessions before returning even an error value.
fn original_input_binding<M,S:SelectedSessionVeto>(
    original:Option<(&Arc<M>,&Arc<S>,Instant)>,monitor:&Arc<M>,session:&Arc<S>,
)->Result<Instant,InputBindingFailure> {
    let result=match original {
        Some((original_monitor,original_session,end))
            if Arc::ptr_eq(original_monitor,monitor) && Arc::ptr_eq(original_session,session)=>Ok(end),
        Some(_)=>Err(InputBindingFailure::Mismatch),None=>Err(InputBindingFailure::Missing),
    };
    if result.is_err() {
        session.veto_atomic();
        if let Some((_,original_session,_))=original {original_session.veto_atomic();}
    }
    result
}

#[cfg(target_os = "macos")]
struct SelectedOwner {
    // Drop the partial/accepted worker while all SAME originals remain held.
    // Its own Drop retains unknown work in its existing sticky registry.
    worker: Option<crate::power::selected_owner_listener::RootSelectedOwnerWorker>,
    session: Arc<crate::power::selected_owner_session::SelectedOwnerSession>,
    monitor: Arc<crate::power::darwin::PowerMonitor>,
    parent: Option<Arc<File>>,
    stop: crate::power::selected_owner_listener::RootSelectedOwnerListenerStop,
    lifetime_end: Instant,
    accept_end: Instant,
}
#[cfg(target_os = "macos")]
impl SelectedOwner {
    fn stop(&self) {
        self.session.revoke();
        self.stop.stop();
    }
}
#[cfg(target_os = "macos")]
impl Drop for SelectedOwner { fn drop(&mut self) { self.stop(); } }

#[cfg(target_os = "macos")]
struct SelectedOwnerAttempt {
    session: Arc<crate::power::selected_owner_session::SelectedOwnerSession>,
    stop: crate::power::selected_owner_listener::RootSelectedOwnerListenerStop,
    armed: bool,
}
#[cfg(target_os = "macos")]
impl Drop for SelectedOwnerAttempt {
    fn drop(&mut self) { if self.armed { self.session.revoke(); self.stop.stop(); } }
}

#[cfg(target_os = "macos")]
impl SelectedRuntime {
    /// Pure pointer/cap binding and atomic failure veto only. Used before a
    /// different retained owner's validation can enter evidence/native cleanup.
    /// Success establishes neither current context nor actor progress.
    pub(super) fn selected_owner_input_binding(&self,
        monitor:&Arc<crate::power::darwin::PowerMonitor>,
        session:&Arc<crate::power::selected_owner_session::SelectedOwnerSession>,
    )->EnclaveResult<Instant> {
        original_input_binding(self.selected_owner.as_ref().map(|owner|
            (&owner.monitor,&owner.session,owner.lifetime_end)),monitor,session).map_err(|failure|match failure {
            InputBindingFailure::Missing=>err!(EACCES,"SUPERVISOR_SELECTED_OWNER_REQUIRED"),
            InputBindingFailure::Mismatch=>err!(EACCES,"SUPERVISOR_SELECTED_OWNER_INPUT_MISMATCH"),
        })
    }

    /// Private one-shot pre-start composition from ACTUAL caller-retained
    /// originals only. The caller must have retained its permanent startup SH
    /// before starting this SAME monitor, and publish `stop` before this call.
    /// `stop` must already use min(enclosing lifetime, original session Instant).
    /// This method acquires no late lease and returns no readiness/start permit.
    /// Ok records local setup return only, never a fresh custody/root ACK or
    /// future actor health. Callers must independently keep every other gate.
    pub(super) fn prepare_selected_owner(&mut self,
        monitor: Arc<crate::power::darwin::PowerMonitor>,
        session: Arc<crate::power::selected_owner_session::SelectedOwnerSession>,
        lifetime_end: Instant, accept_end: Instant,
        stop: &crate::power::selected_owner_listener::RootSelectedOwnerListenerStop,
    ) -> EnclaveResult<()> {
        let mut attempt = SelectedOwnerAttempt { session: session.clone(), stop: stop.clone(), armed: true };
        if let Some(original) = &self.selected_owner {
            // Rebinding cannot revive the first allocation or leave the newly
            // offered session live behind possibly blocking original cleanup.
            session.revoke(); original.stop();
            self.retain(None, Phase::Admission, Reason::SelectedOwner);
            return Err(err!(EACCES, "SUPERVISOR_SELECTED_OWNER_ALREADY_BOUND"));
        }
        let lifetime_end = lifetime_end.min(session.original_instant_end());
        let accept_end = accept_end.min(lifetime_end);
        // Retain input owners before any fallible health/path/native work.
        self.selected_owner = Some(SelectedOwner { worker: None, session, monitor, parent: None,
            stop: stop.clone(), lifetime_end, accept_end });
        let result = (|| {
            crate::deployment::startup_lease::require_retained_selected_startup_lease(accept_end)?;
            self.selected_owner.as_ref().expect("retained inputs").session.require_current()?;
            let parent = self.mesh_parent_lease(accept_end)?;
            self.selected_owner.as_mut().expect("retained inputs").parent = Some(parent);
            let owner = self.selected_owner.as_mut().expect("retained inputs");
            owner.monitor.observe_health(owner.accept_end)?;
            owner.session.require_current()?;
            let listener = crate::power::selected_owner_listener::RootSelectedOwnerListener::bind(
                owner.monitor.clone(), owner.parent.as_ref().expect("retained original parent").clone(),
                owner.lifetime_end, owner.accept_end, &owner.stop, owner.session.clone());
            let bound = listener.require_bound(owner.accept_end);
            // Consume even a refused partial bind into the retention-owning
            // worker BEFORE propagating its error. Never use try_finish as
            // positive health: accepted channel cleanup remains UNKNOWN.
            owner.worker = Some(listener.start());
            bound?;
            owner.session.require_current()?;
            self.require_current(accept_end)?;
            self.selected_owner.as_ref().expect("retained inputs").session.require_current()
        })();
        if result.is_err() {
            self.retain(None, Phase::Admission, Reason::SelectedOwner);
            self.selected_owner.as_ref().expect("retained failure inputs").stop();
        } else { attempt.armed = false; }
        result
    }

    /// Exact retained input identity and original lifetime only. This neither
    /// samples listener/channel actor progress nor grants startup/readiness.
    pub(super) fn selected_owner_lifetime(&mut self,
        monitor:&Arc<crate::power::darwin::PowerMonitor>,
        session:&Arc<crate::power::selected_owner_session::SelectedOwnerSession>,end:Instant,
    )->EnclaveResult<Instant> {
        let result=(|| {
            // Pure pointer checks FIRST. On mismatch both sessions are revoked
            // below before caller cleanup can block on either original owner.
            let original_end=self.selected_owner_input_binding(monitor,session)?;
            session.require_current()?;
            self.require_current(end)?;
            if Instant::now()>=original_end || Instant::now()>=end {
                return Err(err!(ETIMEDOUT,"SUPERVISOR_SELECTED_OWNER_EXPIRED"));
            }
            session.require_current()?;Ok(original_end)
        })();
        if result.is_err() {
            // Revoke offered and original SAME sessions before native cleanup.
            session.revoke();self.stop_selected_owner();
            self.retain(None,Phase::Revalidation,Reason::SelectedOwner);
        }
        result
    }

    /// Borrow comparison admission from the SAME retained actor allocation.
    /// Capturing this handle observes neither actor progress nor readiness;
    /// only its fresh, bounded request can ask the channel-owning thread.
    pub(super) fn selected_owner_actor_comparison(&mut self,
        monitor:&Arc<crate::power::darwin::PowerMonitor>,
        session:&Arc<crate::power::selected_owner_session::SelectedOwnerSession>,end:Instant,
    )->EnclaveResult<crate::power::selected_owner_listener::RootSelectedOwnerActorComparison> {
        let original_end=self.selected_owner_lifetime(monitor,session,end)?;
        let result=(|| {
            let owner=self.selected_owner.as_ref().ok_or_else(||err!(EACCES,"SUPERVISOR_SELECTED_OWNER_REQUIRED"))?;
            let worker=owner.worker.as_ref().ok_or_else(||err!(EACCES,"SUPERVISOR_SELECTED_OWNER_REQUIRED"))?;
            let comparison=worker.original_actor_comparison()?;
            comparison.require_same_session(session,end.min(original_end))?;
            session.require_current()?;
            Ok(comparison)
        })();
        if result.is_err() {
            session.revoke();self.stop_selected_owner();
            self.retain(None,Phase::Revalidation,Reason::SelectedOwner);
        }
        result
    }

    /// Negative-only stop of this SAME retained bundle. Route/session/worker
    /// ownership is never taken, replaced or treated as completed cleanup.
    pub(super) fn stop_selected_owner(&self) {
        if let Some(owner) = &self.selected_owner { owner.stop(); }
    }
}

/// A real selected branch with no service effects until missing owners/gates
/// exist. Successful protection observations are not startup/readiness success.
pub(super) fn refuse_selected_start(socket_dir: &Path, profile: Profile) -> EnclaveResult<()> {
    let until = Instant::now() + ADMISSION_LIMIT;
    let mut owner = SelectedRuntime::acquire_selected(socket_dir, profile, until);
    owner.revalidate(until); // SAME originals/context live through final checks.
    if !owner.refusals.is_empty() {
        return Err(err!(EACCES, "SUPERVISOR_SELECTED_ORIGINALS_REFUSED", "{:?}", owner.refusals));
    }
    Err(err!(ENOSYS, "SUPERVISOR_SELECTED_DEPENDENCIES_UNAVAILABLE", "{MISSING_DEPENDENCIES}"))
}

#[cfg(test)]
#[path = "selected_runtime_tests.rs"]
mod tests;
