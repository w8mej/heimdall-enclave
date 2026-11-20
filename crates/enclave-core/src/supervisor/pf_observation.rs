//! Private, read-only PF collection. The private readiness owner retains the
//! bound collector as a negative prerequisite. Collection is never an enforcement permit.
//!
//! Narrow native output components are bound to one actual protected tool.
//! They cannot establish unobserved interface skips/translations/state bypass,
//! watcher liveness, atomic restoration or first-Begin admission.
#![allow(dead_code)] // Private diagnostics and refusing pre-start composition.

use std::{ffi::CString, fs::{File, Metadata}, os::{fd::{AsRawFd, FromRawFd},
    unix::{ffi::OsStrExt, fs::{FileExt, MetadataExt}}}, path::{Component, Path, PathBuf},
    process::Command, sync::{Arc,atomic::{AtomicBool,Ordering}}, time::{Duration, Instant}};
use sha2::{Digest, Sha256};
use super::pf_restore_input::{self, CanonicalFilterImage, ContentRefusal};
use crate::{deployment::{self, CheckedDeploymentTarget, DeploymentRole, DeploymentSigningMode},
    native_command::{self, CommandFailure, CommandOutput, MAX_OUTPUT},
    profile::Profile, error::EnclaveResult, err};

#[path = "pf_native_schema.rs"]
mod native_schema;

const SAFE_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
const QUERY_LIMIT: Duration = Duration::from_secs(1);
const OVERALL_LIMIT: Duration = Duration::from_secs(5);
const LLM_FILE: &str = "/private/etc/pf.anchors/com.enterprise.llm.isolation";
const CAS_FILE: &str = "/private/etc/pf.anchors/com.enterprise.cas.swarm";
const LLM_POLICY: &[u8] = include_str!("pf_policy_llm.pf").as_bytes();
const CAS_POLICY: &[u8] = include_str!("pf_policy_cas.pf").as_bytes();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Query { Info, RootRules, LlmRules, CasRules, CompileLlm, CompileCas, RootTranslations }
impl Query {
    const ALL: [Self; 7] = [Self::Info, Self::RootRules, Self::LlmRules,
        Self::CasRules, Self::CompileLlm, Self::CompileCas, Self::RootTranslations];
    fn command(self) -> Command {
        let mut command = Command::new("/sbin/pfctl");
        command.current_dir("/").env_clear().env("PATH", SAFE_PATH).env("LC_ALL", "C");
        match self {
            Self::Info => { command.args(["-s", "info"]); }
            Self::RootRules => { command.arg("-sr"); }
            Self::LlmRules => { command.args(["-a", "com.enterprise.llm.isolation", "-sr"]); }
            Self::CasRules => { command.args(["-a", "com.enterprise.cas.swarm", "-sr"]); }
            Self::CompileLlm => { command.args(["-nvf", LLM_FILE]); }
            Self::CompileCas => { command.args(["-nvf", CAS_FILE]); }
            // Root-default query only: no caller-provided anchor or selector.
            Self::RootTranslations => { command.args(["-s", "nat"]); }
        }
        command
    }
    fn schema_query(self) -> native_schema::Query {
        match self {
            Self::Info => native_schema::Query::Info, Self::RootRules => native_schema::Query::RootRules,
            Self::LlmRules => native_schema::Query::LlmRules, Self::CasRules => native_schema::Query::CasRules,
            Self::CompileLlm => native_schema::Query::CompileLlm, Self::CompileCas => native_schema::Query::CompileCas,
            Self::RootTranslations => native_schema::Query::RootTranslations,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role { Descriptor, RootPolicy, LlmPolicy, CasPolicy, NativeTool }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase { Admission, BeforeQuery, AfterQuery, Final }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reason {
    NativeRequired, RootRequired, SelectionRequired, UnsupportedScope,
    ContextChanged, UpgradeDenied, InvalidPath, InputOpen, InputMetadata,
    InputType, InputProtection, InputLinks, InputSize, DescriptorFlags,
    NativeAclRequired, AclInspection, AclRefused, InputRead, InputChanged,
    InputIncomplete, CanonicalMismatch, DescriptorMismatch, Deadline,
    ClockUnavailable, QueryFailed(CommandFailure), QueryExit,
    NativeSchema(native_schema::Error), RestoreContent(ContentRefusal), RestorePlanPoisoned, OwnerVetoed, SessionVetoed, NotificationWindowRefused,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Refusal { role: Option<Role>, phase: Phase, reason: Reason }
type Check<T> = Result<T, Reason>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Knowledge { Unknown, NotObserved, Established, NotEstablished }
#[derive(Debug)]
struct Fingerprint { bytes: usize, sha256: [u8; 32] }
impl Fingerprint {
    fn of(bytes: &[u8]) -> Self { Self { bytes: bytes.len(), sha256: digest(bytes) } }
}
#[derive(Debug)]
struct QueryObservation {
    query: Query, exit: Option<i32>, failure: Option<CommandFailure>,
    stdout: Option<Fingerprint>, stderr: Option<Fingerprint>,
}
#[derive(Debug)]
struct InputObservation { role: Role, admitted: bool, bytes: Option<u64>, sha256: Option<[u8; 32]> }

/// An observation owns all successfully opened originals, including partial
/// routes on refusal. It is private, nonserializable and has no permit accessor.
struct Observation {
    started_boot_ns: u64, ended_boot_ns: u64, original_enclosing_end: Instant, sample_end: Instant,
    collection_complete: bool, queries: Vec<QueryObservation>,
    primary_refusal: Option<Refusal>, boundary_refusals: Vec<Refusal>,
    final_refusals: Vec<Refusal>,
    native_schema: Knowledge, pf_enabled: Knowledge, root_rule_interpretation: Knowledge,
    llm_compiled_live_comparison: Knowledge, cas_compiled_live_comparison: Knowledge,
    interface_skip_policy: Knowledge, translation_policy: Knowledge, preexisting_state_policy: Knowledge,
    // Descriptive Info snapshot only; never participates in a policy permit.
    preexisting_state_count: Option<native_schema::StateCount>,
    // Complete empty command output only; never full translation policy.
    root_translation_output: Option<native_schema::RootTranslationOutput>,
    mandatory_watcher: Knowledge, atomic_restoration: Knowledge,
    protected_inputs_current: bool, originals: Originals, retained_context: Option<Context>,
}
impl Observation {
    fn required_enforcement_established(&self) -> bool {
        self.collection_complete && self.protected_inputs_current
            && self.primary_refusal.is_none() && self.final_refusals.is_empty()
            && [self.native_schema, self.pf_enabled, self.root_rule_interpretation,
                self.llm_compiled_live_comparison, self.cas_compiled_live_comparison,
                self.interface_skip_policy, self.translation_policy, self.preexisting_state_policy,
                self.mandatory_watcher, self.atomic_restoration]
                .into_iter().all(|component| component == Knowledge::Established)
    }
    fn first_begin_prerequisites_met(&self) -> bool { false }
    fn input_progress(&self) -> Vec<InputObservation> {
        self.originals.routes.iter().map(|route| InputObservation {
            role: route.spec.role, admitted: route.admitted,
            bytes: route.nodes.last().and_then(|node| node.stamp).and_then(|stamp| stamp.file.map(|file| file.0)),
            sha256: route.content_digest,
        }).collect()
    }
    fn selected_descriptor_digest(&self) -> Option<&str> {
        match &self.retained_context {
            Some(Context::Native(checked)) => Some(checked.descriptor_sha256()),
            _ => None,
        }
    }
}
// A prepared closed command is deliberately unavailable to native_command.
// No execute/spawn/into_command method or caller-controlled command exists.
// Actual independent complete-root policy authority and supported transaction
// semantics must be composed before adding any execution path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RestoreExecutionGap { CompleteRootPolicyAuthorityAndNativeTransaction }
struct PreparedRestorePlan<'a> {
    observation: &'a mut Observation,
    deadline: Instant,
    poisoned: bool,
    command: Command,
    root: Fingerprint, llm: Fingerprint, cas: Fingerprint,
}
impl PreparedRestorePlan<'_> {
    fn execution_gap(&self) -> RestoreExecutionGap {
        RestoreExecutionGap::CompleteRootPolicyAuthorityAndNativeTransaction
    }
    fn require_current_inputs(&mut self) -> Result<(), Vec<Refusal>> {
        let mut errors = self.observation.restore_boundary(self.deadline);
        if self.poisoned { errors.push(Refusal { role: None, phase: Phase::Final, reason: Reason::RestorePlanPoisoned }); }
        if errors.is_empty() { Ok(()) } else { self.poisoned = true; Err(errors) }
    }
}
impl std::fmt::Debug for PreparedRestorePlan<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedPfRestorePlan").field("root", &self.root)
            .field("llm", &self.llm).field("cas", &self.cas)
            .field("execution_gap", &self.execution_gap()).finish()
    }
}
impl Observation {
    fn restore_boundary(&mut self, deadline: Instant) -> Vec<Refusal> {
        let deadline = deadline.min(self.original_enclosing_end).min(self.sample_end);
        let mut errors = self.originals.current(Phase::Final, deadline);
        if self.originals.routes.len() != 5 {
            errors.push(Refusal { role: None, phase: Phase::Final, reason: Reason::InputIncomplete });
        }
        match &mut self.retained_context {
            Some(context) => if let Err(reason) = context.current() {
                errors.push(Refusal { role: None, phase: Phase::Final, reason });
            },
            None => errors.push(Refusal { role: None, phase: Phase::Final, reason: Reason::SelectionRequired }),
        }
        if let Err(reason) = within(deadline) {
            errors.push(Refusal { role: None, phase: Phase::Final, reason });
        }
        errors
    }
    fn restore_bytes(&self, role: Role, deadline: Instant) -> Check<Vec<u8>> {
        let mut routes = self.originals.routes.iter().filter(|route| route.spec.role == role);
        let route = routes.next().filter(|route| route.admitted).ok_or(Reason::InputIncomplete)?;
        if routes.next().is_some() { return Err(Reason::InputIncomplete); }
        let file = &route.nodes.last().ok_or(Reason::InputIncomplete)?.file;
        read_original(file, route.spec.maximum, deadline.min(self.original_enclosing_end).min(self.sample_end))
    }
    /// Prepare only: borrows SAME protected originals/context and the original
    /// finite cap. Complete collection is not required because the repair
    /// trigger can itself be an empty-anchor refusal. No observation, content
    /// image or Command is a complete-root authorization or restoration permit.
    fn prepare_restore(&mut self, deadline: Instant) -> Result<PreparedRestorePlan<'_>, Vec<Refusal>> {
        let deadline = deadline.min(self.original_enclosing_end).min(self.sample_end);
        let mut errors = self.restore_boundary(deadline);
        let mut inputs = Vec::new();
        for role in [Role::RootPolicy, Role::LlmPolicy, Role::CasPolicy] {
            match self.restore_bytes(role, deadline) {
                Ok(bytes) => inputs.push(bytes),
                Err(reason) => errors.push(Refusal { role: Some(role), phase: Phase::Final, reason }),
            }
        }
        if inputs.len() == 3 {
            if let Err(error) = CanonicalFilterImage::require(&inputs[0], &inputs[1], &inputs[2]) {
                let role = match error { ContentRefusal::RootFilter => Role::RootPolicy,
                    ContentRefusal::LlmPolicy => Role::LlmPolicy, ContentRefusal::CasPolicy => Role::CasPolicy };
                errors.push(Refusal { role: Some(role), phase: Phase::Final, reason: Reason::RestoreContent(error) });
            }
        }
        // Preserve every independent original/context refusal after content
        // reads too. A later plan must never adopt replacement path bytes.
        errors.extend(self.restore_boundary(deadline));
        if !errors.is_empty() { return Err(errors); }
        let mut command = Command::new("/sbin/pfctl");
        command.current_dir("/").env_clear().env("PATH", SAFE_PATH).env("LC_ALL", "C")
            .args(["-R", "-f", "/private/etc/pf.conf"]);
        Ok(PreparedRestorePlan { deadline, poisoned: false, command,
            root: Fingerprint::of(&inputs[0]), llm: Fingerprint::of(&inputs[1]), cas: Fingerprint::of(&inputs[2]),
            observation: self })
    }
}
impl std::fmt::Debug for Observation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PfObservation").field("started_boot_ns", &self.started_boot_ns)
            .field("ended_boot_ns", &self.ended_boot_ns)
            .field("collection_complete", &self.collection_complete)
            .field("queries", &self.queries).field("primary_refusal", &self.primary_refusal)
            .field("boundary_refusals", &self.boundary_refusals)
            .field("final_refusals", &self.final_refusals)
            .field("native_schema", &self.native_schema).field("pf_enabled", &self.pf_enabled)
            .field("root_rule_interpretation", &self.root_rule_interpretation)
            .field("llm_compiled_live_comparison", &self.llm_compiled_live_comparison)
            .field("cas_compiled_live_comparison", &self.cas_compiled_live_comparison)
            .field("interface_skip_policy", &self.interface_skip_policy)
            .field("translation_policy", &self.translation_policy)
            .field("preexisting_state_policy", &self.preexisting_state_policy)
            .field("preexisting_state_count", &self.preexisting_state_count)
            .field("root_translation_output", &self.root_translation_output)
            .field("mandatory_watcher", &self.mandatory_watcher)
            .field("atomic_restoration", &self.atomic_restoration)
            .field("protected_inputs_current", &self.protected_inputs_current)
            .field("inputs", &self.input_progress())
            .field("selected_descriptor_sha256", &self.selected_descriptor_digest())
            .field("required_enforcement_established", &self.required_enforcement_established())
            .field("first_begin_prerequisites_met", &self.first_begin_prerequisites_met())
            .field("retained_routes", &self.originals.routes.len()).finish()
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] { Sha256::digest(bytes).into() }
fn within(deadline: Instant) -> Check<()> {
    if Instant::now() >= deadline { Err(Reason::Deadline) } else { Ok(()) }
}
fn native_root() -> Check<()> {
    if !cfg!(target_os = "macos") { return Err(Reason::NativeRequired); }
    if unsafe { libc::geteuid() } != 0 { return Err(Reason::RootRequired); }
    Ok(())
}
fn selected_scope(checked: &CheckedDeploymentTarget) -> Check<()> {
    target_scope(checked.target())
}
fn target_scope(target: &deployment::DeploymentTarget) -> Check<()> {
    if target.role != DeploymentRole::DedicatedTest || target.profile != Profile::L2
        || target.signing_identity_mode != DeploymentSigningMode::LocalPins
        || crate::codesign::signing_mode() != crate::codesign::SigningMode::LocalPins
        || target.broker.is_some() || !target.shared_read_only_inputs.is_empty() {
        return Err(Reason::UnsupportedScope);
    }
    Ok(())
}
enum Context {
    Native(&'static CheckedDeploymentTarget),
    // Only software fixtures can substitute context/query observations. There
    // is no production provider field, bool, path or deserializable authority.
    #[cfg(test)]
    Fixture(Box<dyn FnMut() -> EnclaveResult<()>>),
}
impl Context {
    fn current(&mut self) -> Check<()> {
        match self {
            Self::Native(checked) => {
                native_root()?;
                let actual = deployment::selected().ok_or(Reason::SelectionRequired)?;
                if !std::ptr::eq(actual, *checked) { return Err(Reason::ContextChanged); }
                selected_scope(actual)?;
                // This is a read-only denial check, not acquisition of an
                // actor startup SH lease or a claim that a later start is safe.
                deployment::upgrade::assert_start_allowed(actual).map_err(|_| Reason::UpgradeDenied)
            }
            #[cfg(test)]
            Self::Fixture(check) => check().map_err(|_| Reason::ContextChanged),
        }
    }
}

#[derive(Clone)]
enum Protection {
    NativeRoot,
    #[cfg(test)]
    Fixture { uid: u32, root: PathBuf },
}
impl Protection {
    fn uid(&self) -> u32 {
        match self {
            Self::NativeRoot => 0,
            #[cfg(test)]
            Self::Fixture { uid, .. } => *uid,
        }
    }
    fn descriptor(&self, file: &File) -> Check<()> {
        let access = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
        if access < 0 || access & libc::O_ACCMODE != libc::O_RDONLY
            || access & libc::O_NONBLOCK == 0 || flags < 0 || flags & libc::FD_CLOEXEC == 0 {
            return Err(Reason::DescriptorFlags);
        }
        match self {
            Self::NativeRoot => native_empty_acl(file),
            #[cfg(test)]
            Self::Fixture { .. } => Ok(()), // Not native ACL evidence.
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
        if acl.is_null() {
            return if errno == Some(libc::ENOENT) { Ok(()) } else { Err(Reason::AclInspection) };
        }
        let valid = unsafe { acl_valid(acl) };
        let mut entry = std::ptr::null_mut();
        let found = unsafe { acl_get_entry(acl, 0, &mut entry) };
        let errno = std::io::Error::last_os_error().raw_os_error();
        let freed = unsafe { acl_free(acl) };
        if valid != 0 || found != -1 || errno != Some(libc::EINVAL) || freed != 0 {
            return Err(Reason::AclRefused);
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    { let _ = file; Err(Reason::NativeAclRequired) }
}

enum Expected { Descriptor(String), Canonical(&'static [u8]), RootPolicy, NativeTool }
struct InputSpec { role: Role, path: PathBuf, maximum: usize, expected: Expected }
impl InputSpec {
    fn exact_mode(&self) -> Option<u32> {
        match self.role { Role::Descriptor => None, Role::NativeTool => Some(0o555), _ => Some(0o644) }
    }
    fn compare(&self, bytes: &[u8]) -> Check<()> {
        match &self.expected {
            Expected::Descriptor(expected) if hex::encode(digest(bytes)) != *expected => Err(Reason::DescriptorMismatch),
            Expected::Canonical(expected) if bytes != *expected => Err(Reason::CanonicalMismatch),
            Expected::RootPolicy if bytes != pf_restore_input::render_root_filter() => Err(Reason::RestoreContent(ContentRefusal::RootFilter)),
            Expected::NativeTool if bytes.len() as u64 != native_schema::TOOL_SIZE
                || hex::encode(digest(bytes)) != native_schema::TOOL_SHA256 => Err(Reason::NativeSchema(native_schema::Error::UnsupportedTool)),
            _ => Ok(()),
        }
    }
}

/// Directory stamps omit timestamps/link counts: unrelated root directory
/// changes must not be confused with a replacement of our protected ancestry.
/// File stamps retain all content/protection-relevant observed metadata.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp {
    dev: u64, ino: u64, uid: u32, gid: u32, mode: u32,
    file: Option<(u64, u64, i64, i64, i64, i64)>,
}
impl Stamp {
    fn of(metadata: &Metadata, leaf: bool) -> Self {
        Self { dev: metadata.dev(), ino: metadata.ino(), uid: metadata.uid(), gid: metadata.gid(), mode: metadata.mode(),
            file: leaf.then(|| (metadata.len(), metadata.nlink(), metadata.mtime(), metadata.mtime_nsec(),
                metadata.ctime(), metadata.ctime_nsec())) }
    }
}
struct Node { file: File, name: CString, stamp: Option<Stamp> }
struct HeldRoute {
    spec: InputSpec, protection: Protection, nodes: Vec<Node>,
    admitted: bool, content_digest: Option<[u8; 32]>,
}
struct Originals { routes: Vec<HeldRoute> }

fn named_stat(parent: Option<&File>, name: &CString) -> Check<libc::stat> {
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    let fd = parent.map_or(libc::AT_FDCWD, AsRawFd::as_raw_fd);
    if unsafe { libc::fstatat(fd, name.as_ptr(), &mut value, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(Reason::InputMetadata);
    }
    Ok(value)
}
fn named_matches(named: &libc::stat, held: &Metadata) -> bool {
    named.st_dev as u64 == held.dev() && named.st_ino as u64 == held.ino()
        && named.st_mode as u32 == held.mode() && named.st_uid == held.uid() && named.st_gid == held.gid()
        && (!held.is_file() || (named.st_size >= 0 && named.st_size as u64 == held.len()
            && named.st_nlink as u64 == held.nlink()))
}
fn metadata_safe(metadata: &Metadata, leaf: bool, protection: &Protection, spec: &InputSpec) -> Check<()> {
    if (leaf && !metadata.is_file()) || (!leaf && !metadata.is_dir()) { return Err(Reason::InputType); }
    if metadata.uid() != protection.uid() || metadata.mode() & 0o022 != 0
        || (leaf && spec.role == Role::NativeTool && matches!(protection, Protection::NativeRoot) && metadata.gid() != 0)
        || (leaf && spec.exact_mode().is_some_and(|mode| metadata.mode() & 0o7777 != mode)) {
        return Err(Reason::InputProtection);
    }
    if leaf && metadata.nlink() != 1 { return Err(Reason::InputLinks); }
    if leaf && (metadata.len() == 0 || metadata.len() > spec.maximum as u64) { return Err(Reason::InputSize); }
    Ok(())
}
fn read_original(file: &File, maximum: usize, deadline: Instant) -> Check<Vec<u8>> {
    within(deadline)?;
    let before = file.metadata().map_err(|_| Reason::InputMetadata)?;
    if !before.is_file() { return Err(Reason::InputType); }
    if before.len() == 0 || before.len() > maximum as u64 { return Err(Reason::InputSize); }
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        within(deadline)?;
        let wanted = buffer.len().min(maximum + 1 - bytes.len());
        if wanted == 0 { return Err(Reason::InputSize); }
        let count = file.read_at(&mut buffer[..wanted], bytes.len() as u64).map_err(|_| Reason::InputRead)?;
        if count == 0 { break; }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len() > maximum { return Err(Reason::InputSize); }
    }
    let after = file.metadata().map_err(|_| Reason::InputMetadata)?;
    if Stamp::of(&before, true) != Stamp::of(&after, true) || bytes.len() as u64 != before.len() {
        return Err(Reason::InputChanged);
    }
    within(deadline)?;
    Ok(bytes)
}

impl HeldRoute {
    fn new(spec: InputSpec, protection: Protection) -> Self {
        Self { spec, protection, nodes: Vec::new(), admitted: false, content_digest: None }
    }
    fn open(&mut self, deadline: Instant) -> Check<()> {
        within(deadline)?;
        // Strict lexical validation; only production construction performs the
        // existing fixed OS alias translation, never canonicalize()/realpath().
        deployment::normalized_path(&self.spec.path).map_err(|_| Reason::InvalidPath)?;
        let (root_path, relative) = match &self.protection {
            Protection::NativeRoot => (Path::new("/"), self.spec.path.as_path()),
            // Software fixtures start at their real, private fixture directory.
            // They intentionally establish no native/root ancestry observation.
            #[cfg(test)]
            Protection::Fixture { root, .. } => (root.as_path(), self.spec.path.strip_prefix(root).map_err(|_| Reason::InvalidPath)?),
        };
        let parts: Vec<CString> = relative.components().filter_map(|part| match part {
            Component::Normal(name) => Some(CString::new(name.as_bytes()).map_err(|_| Reason::InvalidPath)), _ => None,
        }).collect::<Check<_>>()?;
        if parts.is_empty() { return Err(Reason::InvalidPath); }
        let root = CString::new(root_path.as_os_str().as_bytes()).map_err(|_| Reason::InvalidPath)?;
        let fd = unsafe { libc::open(root.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY
            | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC) };
        if fd < 0 { return Err(Reason::InputOpen); }
        // Own every opened descriptor before any later inspection can fail.
        self.nodes.push(Node { file: unsafe { File::from_raw_fd(fd) }, name: root, stamp: None });
        self.admit_last(false)?;
        let part_count = parts.len();
        for (index, name) in parts.into_iter().enumerate() {
            within(deadline)?;
            let leaf = index + 1 == part_count;
            let parent = &self.nodes.last().expect("retained root").file;
            // Refuse special named objects before opening; NONBLOCK also
            // prevents a raced FIFO from blocking the read-only opener.
            let named = named_stat(Some(parent), &name)?;
            let required = if leaf { libc::S_IFREG } else { libc::S_IFDIR };
            if named.st_mode & libc::S_IFMT != required { return Err(Reason::InputType); }
            let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC
                | if leaf { 0 } else { libc::O_DIRECTORY };
            let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
            if fd < 0 { return Err(Reason::InputOpen); }
            self.nodes.push(Node { file: unsafe { File::from_raw_fd(fd) }, name, stamp: None });
            self.admit_last(leaf)?;
            let current = self.nodes.last().expect("retained opened node").file.metadata().map_err(|_| Reason::InputMetadata)?;
            if !named_matches(&named, &current) { return Err(Reason::InputChanged); }
        }
        let file = &self.nodes.last().expect("retained leaf").file;
        let bytes = read_original(file, self.spec.maximum, deadline)?;
        self.content_digest = Some(digest(&bytes));
        self.spec.compare(&bytes)?;
        if let Some(error) = self.inspect_nodes().into_iter().next() { return Err(error); }
        within(deadline)?;
        self.admitted = true;
        Ok(())
    }
    fn admit_last(&mut self, leaf: bool) -> Check<()> {
        let node = self.nodes.last_mut().expect("opened node retained first");
        let metadata = node.file.metadata().map_err(|_| Reason::InputMetadata)?;
        node.stamp = Some(Stamp::of(&metadata, leaf));
        metadata_safe(&metadata, leaf, &self.protection, &self.spec)?;
        self.protection.descriptor(&node.file)
    }
    fn inspect_nodes(&self) -> Vec<Reason> {
        let mut errors = Vec::new();
        for (index, node) in self.nodes.iter().enumerate() {
            let leaf = index + 1 == self.nodes.len() && self.content_digest.is_some();
            // Use the original stamp's kind on partial routes as well.
            let leaf = node.stamp.map_or(leaf, |stamp| stamp.file.is_some());
            let metadata = match node.file.metadata() {
                Ok(value) => value, Err(_) => { errors.push(Reason::InputMetadata); continue; }
            };
            if let Err(error) = metadata_safe(&metadata, leaf, &self.protection, &self.spec) { errors.push(error); }
            if let Err(error) = self.protection.descriptor(&node.file) { errors.push(error); }
            if node.stamp != Some(Stamp::of(&metadata, leaf)) { errors.push(Reason::InputChanged); }
            let parent = index.checked_sub(1).map(|parent| &self.nodes[parent].file);
            match named_stat(parent, &node.name) {
                Ok(named) if named_matches(&named, &metadata) => (),
                Ok(_) => errors.push(Reason::InputChanged), Err(error) => errors.push(error),
            }
        }
        errors
    }
    fn current(&self, deadline: Instant) -> Vec<Reason> {
        let mut errors = self.inspect_nodes();
        if !self.admitted { errors.push(Reason::InputIncomplete); }
        if let (Some(file), Some(expected)) = (self.nodes.last(), self.content_digest) {
            match read_original(&file.file, self.spec.maximum, deadline) {
                Ok(bytes) => {
                    if digest(&bytes) != expected { errors.push(Reason::InputChanged); }
                    if let Err(error) = self.spec.compare(&bytes) { errors.push(error); }
                }
                Err(error) => errors.push(error),
            }
        }
        // A successful read must not hide a name/protection/metadata change
        // between the earlier metadata inspection and the final content hash.
        errors.extend(self.inspect_nodes());
        errors
    }
}
impl Originals {
    fn open(&mut self, specs: Vec<InputSpec>, protection: Protection, deadline: Instant) -> Vec<Refusal> {
        let mut errors = Vec::new();
        for spec in specs {
            let mut route = HeldRoute::new(spec, protection.clone());
            let result = route.open(deadline);
            let role = route.spec.role;
            self.routes.push(route); // Partial originals survive refusal, too.
            if let Err(reason) = result { errors.push(Refusal { role: Some(role), phase: Phase::Admission, reason }); }
        }
        errors
    }
    fn current(&self, phase: Phase, deadline: Instant) -> Vec<Refusal> {
        self.routes.iter().flat_map(|route| route.current(deadline).into_iter()
            .map(move |reason| Refusal { role: Some(route.spec.role), phase, reason })).collect()
    }
}

struct Producer {
    observation: Observation,
    retained_veto:Option<Arc<AtomicBool>>,
    retained_session:Option<Arc<ReadOnlySessionBinding>>,
    components: Option<native_schema::Components>,
    #[cfg(test)]
    fixture_query: Option<Box<dyn FnMut(Query, Instant) -> Result<CommandOutput, CommandFailure>>>,
}
impl Producer {
    fn empty() -> Self { Self::empty_until(Instant::now() + OVERALL_LIMIT) }
    fn empty_until(original_enclosing_end: Instant) -> Self {
        let started_boot_ns = crate::clock::boot_clock_ns();
        Self { retained_veto:None, retained_session:None, components: None, observation: Observation {
            started_boot_ns, ended_boot_ns: started_boot_ns, original_enclosing_end,
            sample_end: original_enclosing_end.min(Instant::now()+OVERALL_LIMIT), collection_complete: false,
            queries: Vec::new(), primary_refusal: None, boundary_refusals: Vec::new(), final_refusals: Vec::new(),
            native_schema: Knowledge::Unknown, pf_enabled: Knowledge::Unknown,
            root_rule_interpretation: Knowledge::Unknown,
            llm_compiled_live_comparison: Knowledge::Unknown, cas_compiled_live_comparison: Knowledge::Unknown,
            interface_skip_policy: Knowledge::Unknown, translation_policy: Knowledge::Unknown, preexisting_state_policy: Knowledge::Unknown,
            preexisting_state_count: None, root_translation_output: None,
            mandatory_watcher: Knowledge::NotObserved, atomic_restoration: Knowledge::NotObserved,
            protected_inputs_current: false, originals: Originals { routes: Vec::new() }, retained_context: None,
        }, #[cfg(test)] fixture_query: None }
    }
    fn veto_if_retained(&self) {
        if let Some(session)=&self.retained_session {session.veto();}
        if let Some(veto)=&self.retained_veto {veto.store(true,Ordering::SeqCst);}
    }
    fn require_retained_session(&self,deadline:Instant)->Check<()> {
        if let Some(session)=&self.retained_session {session.current(deadline)?;}
        Ok(())
    }
    fn retain_errors(&mut self, errors: Vec<Refusal>) {
        if !errors.is_empty() {self.veto_if_retained();}
        if self.observation.primary_refusal.is_none() { self.observation.primary_refusal = errors.first().copied(); }
        self.observation.boundary_refusals.extend(errors);
    }
    fn context_error(&mut self, phase: Phase) -> Option<Refusal> {
        self.observation.retained_context.as_mut().and_then(|context| context.current().err())
            .map(|reason| Refusal { role: None, phase, reason })
    }
    fn boundary(&mut self, phase: Phase, deadline: Instant) -> Vec<Refusal> {
        self.boundary_with_collection(phase, deadline, None)
    }
    fn collection_current(&self, collection: Option<&dyn super::pf_watch::NegativeCollectionCheck>,
        deadline: Instant) -> Check<()> {
        if let Some(collection) = collection {
            collection.require_current(deadline).map_err(|_| {
                self.veto_if_retained(); Reason::NotificationWindowRefused
            })?;
        }
        Ok(())
    }
    fn boundary_with_collection(&mut self, phase: Phase, deadline: Instant,
        collection: Option<&dyn super::pf_watch::NegativeCollectionCheck>) -> Vec<Refusal> {
        // The actual readiness path always supplies its borrowed same-original
        // notification window. None is reserved for private diagnostics.
        if let Err(reason) = self.collection_current(collection, deadline) {
            return vec![Refusal {role:None,phase,reason}];
        }
        // SAME selected session/stop/immutable endpoint precede all input and
        // context work, before AND after each of the seven fixed native queries.
        if let Err(reason)=self.require_retained_session(deadline) {
            self.veto_if_retained();return vec![Refusal {role:None,phase,reason}];
        }
        if self.retained_veto.as_ref().is_some_and(|veto|veto.load(Ordering::SeqCst)) {
            self.veto_if_retained();return vec![Refusal {role:None,phase,reason:Reason::OwnerVetoed}];
        }
        let mut errors = self.observation.originals.current(phase, deadline);
        if !errors.is_empty() {self.veto_if_retained();}
        if self.observation.originals.routes.len() != 5 {
            errors.push(Refusal { role: None, phase, reason: Reason::InputIncomplete });
        }
        if self.observation.retained_context.is_none() { errors.push(Refusal { role: None, phase, reason: Reason::SelectionRequired }); }
        if let Some(error) = self.context_error(phase) { self.veto_if_retained();errors.push(error); }
        if let Err(reason) = within(deadline) { self.veto_if_retained();errors.push(Refusal { role: None, phase, reason }); }
        if let Err(reason)=self.require_retained_session(deadline) {
            self.veto_if_retained();errors.push(Refusal {role:None,phase,reason});
        }
        if !errors.is_empty() {self.veto_if_retained();}
        if self.retained_veto.as_ref().is_some_and(|veto|veto.load(Ordering::SeqCst)) {
            errors.push(Refusal {role:None,phase,reason:Reason::OwnerVetoed});
        }
        if let Err(reason) = self.collection_current(collection, deadline) {
            errors.push(Refusal {role:None,phase,reason});
        }
        errors
    }
    fn query(&mut self, query: Query, deadline: Instant) -> Result<CommandOutput, CommandFailure> {
        #[cfg(test)]
        if let Some(fixture) = &mut self.fixture_query { return fixture(query, deadline); }
        native_command::run_owned_command(query.command(), deadline)
    }
    fn collect(&mut self, deadline: Instant) {
        self.collect_with_collection(deadline, None)
    }
    fn collect_with_collection(&mut self, deadline: Instant,
        collection: Option<&dyn super::pf_watch::NegativeCollectionCheck>) {
        self.observation.sample_end = self.observation.sample_end.min(self.observation.original_enclosing_end).min(deadline);
        let deadline = self.observation.sample_end;
        let mut total_output = 0usize;
        for query in Query::ALL {
            let errors = self.boundary_with_collection(Phase::BeforeQuery, deadline, collection);
            self.retain_errors(errors);
            if self.observation.primary_refusal.is_some() { break; }
            // Each query can only shorten the one original total endpoint.
            let query_deadline = deadline.min(Instant::now() + QUERY_LIMIT);
            let output = self.query(query, query_deadline);
            if self.retained_veto.is_some() && (output.is_err() || Instant::now()>=query_deadline) {self.veto_if_retained();}
            let mut observed = QueryObservation { query, exit: None, failure: None, stdout: None, stderr: None };
            // Refuse an invalidated/late notification window immediately after
            // the actual command, BEFORE interpreting its returned PF bytes.
            if let Err(reason) = self.collection_current(collection, deadline) {
                // Preserve facts already returned by the owned command even
                // when the window vetoes all PF-byte interpretation. In
                // particular, OwnershipUnknown must never disappear here.
                let command_reason = match &output {
                    Err(failure) => { observed.failure = Some(*failure); Some(Reason::QueryFailed(*failure)) }
                    Ok(output) => {
                        observed.exit = output.code;
                        (output.code != Some(0)).then_some(Reason::QueryExit)
                    }
                };
                self.observation.queries.push(observed);
                let mut errors = vec![Refusal {role:None,phase:Phase::AfterQuery,reason}];
                if let Some(reason) = command_reason {
                    errors.push(Refusal {role:None,phase:Phase::AfterQuery,reason});
                }
                self.retain_errors(errors);
                break;
            }
            let reason = match output {
                Err(error) => { observed.failure = Some(error); Some(Reason::QueryFailed(error)) }
                Ok(output) => {
                    observed.exit = output.code;
                    let count = output.stdout.len().checked_add(output.stderr.len());
                    let cumulative = count.and_then(|count| total_output.checked_add(count));
                    if cumulative.is_none_or(|count| count > MAX_OUTPUT) {
                        observed.failure = Some(CommandFailure::OutputLimit);
                        Some(Reason::QueryFailed(CommandFailure::OutputLimit))
                    } else {
                        total_output = cumulative.expect("bounded combined output");
                        observed.stdout = Some(Fingerprint::of(&output.stdout));
                        observed.stderr = Some(Fingerprint::of(&output.stderr));
                        if Instant::now() >= query_deadline { Some(Reason::Deadline) }
                        else if output.code != Some(0) { Some(Reason::QueryExit) }
                        else if let Some(components) = &mut self.components {
                            components.observe(query.schema_query(), &output.stdout, &output.stderr).err().map(Reason::NativeSchema)
                        } else { None }
                    }
                }
            };
            self.observation.queries.push(observed);
            if let Some(reason) = reason {
                self.retain_errors(vec![Refusal { role: None, phase: Phase::AfterQuery, reason }]);
            }
            // Even cleanup uncertainty retains every independent original and
            // context refusal. No error leads to another query or a retry.
            let errors = self.boundary_with_collection(Phase::AfterQuery, deadline, collection);
            self.retain_errors(errors);
            if self.observation.primary_refusal.is_some() { break; }
        }
    }
    fn finish_in_place(&mut self, deadline: Instant) {
        self.finish_with_collection_in_place(deadline, None)
    }
    fn finish_with_collection_in_place(&mut self, deadline: Instant,
        collection: Option<&dyn super::pf_watch::NegativeCollectionCheck>) {
        self.observation.sample_end = self.observation.sample_end.min(self.observation.original_enclosing_end).min(deadline);
        let deadline = self.observation.sample_end;
        self.observation.final_refusals = self.boundary_with_collection(Phase::Final, deadline, collection);
        self.observation.protected_inputs_current = self.observation.originals.routes.len() == 5
            && self.observation.originals.routes.iter().all(|route| route.admitted)
            && !self.observation.final_refusals.iter().any(|error| error.role.is_some());
        self.observation.ended_boot_ns = crate::clock::boot_clock_ns();
        if self.observation.started_boot_ns == u64::MAX || self.observation.ended_boot_ns == u64::MAX
            || self.observation.ended_boot_ns < self.observation.started_boot_ns {
            self.veto_if_retained();
            self.observation.final_refusals.push(Refusal { role: None, phase: Phase::Final, reason: Reason::ClockUnavailable });
        }
        if let Err(reason) = within(deadline) {
            self.veto_if_retained();
            self.observation.final_refusals.push(Refusal { role: None, phase: Phase::Final, reason });
        }
        if let Err(reason) = self.collection_current(collection, deadline) {
            self.observation.final_refusals.push(Refusal {role:None,phase:Phase::Final,reason});
        }
        if self.observation.primary_refusal.is_none() {
            self.observation.primary_refusal = self.observation.final_refusals.first().copied();
        }
        self.observation.collection_complete = self.observation.queries.len() == Query::ALL.len()
            && self.observation.primary_refusal.is_none() && self.observation.final_refusals.is_empty();
        // Component positives are published only after EVERY actual command
        // and original/context/final check. A later refusal leaves them Unknown.
        if self.observation.collection_complete {
            if let Some(components) = &self.components {
                self.observation.native_schema = Knowledge::Established;
                self.observation.pf_enabled = match components.enabled() {
                    Some(true) => Knowledge::Established, Some(false) => Knowledge::NotEstablished, None => Knowledge::Unknown,
                };
                self.observation.preexisting_state_count = components.state_count();
                self.observation.root_translation_output = components.root_translation_output();
                if components.root_linkage_order() { self.observation.root_rule_interpretation = Knowledge::Established; }
                if components.llm_equal() { self.observation.llm_compiled_live_comparison = Knowledge::Established; }
                if components.cas_equal() { self.observation.cas_compiled_live_comparison = Knowledge::Established; }
            }
        }
    }
    fn finish(mut self, deadline: Instant) -> Observation {
        self.finish_in_place(deadline);self.observation
    }
}

/// Only real production constructor: internally selected native/root context,
/// fixed external roles and immutable policy assets. The caller can supply
/// only a trusted shortening endpoint. Readiness uses the retained bound owner.
impl Producer {
    fn admit_selected(&mut self, deadline:Instant) {
    let admission = (|| {
        within(deadline)?;
        native_root()?;
        let checked = deployment::selected().ok_or(Reason::SelectionRequired)?;
        selected_scope(checked)?;
        self.observation.retained_context = Some(Context::Native(checked));
        self.observation.retained_context.as_mut().expect("actual selected context").current()?;
        // Translate only the fixed Darwin OS aliases lexically. Every later
        // file operation uses protected nofollow components under /private;
        // dry-run commands use the identical fixed protected anchor names.
        let descriptor = deployment::normalized_path(checked.config_path()).map_err(|_| Reason::InvalidPath)?;
        let specs = vec![
            InputSpec { role: Role::Descriptor, path: descriptor, maximum: deployment::MAX_DESCRIPTOR_BYTES,
                expected: Expected::Descriptor(checked.descriptor_sha256().into()) },
            InputSpec { role: Role::RootPolicy, path: "/private/etc/pf.conf".into(), maximum: MAX_OUTPUT, expected: Expected::RootPolicy },
            InputSpec { role: Role::LlmPolicy, path: LLM_FILE.into(), maximum: MAX_OUTPUT, expected: Expected::Canonical(LLM_POLICY) },
            InputSpec { role: Role::CasPolicy, path: CAS_FILE.into(), maximum: MAX_OUTPUT, expected: Expected::Canonical(CAS_POLICY) },
            InputSpec { role: Role::NativeTool, path: native_schema::TOOL_PATH.into(), maximum: MAX_OUTPUT, expected: Expected::NativeTool },
        ];
        let errors = self.observation.originals.open(specs, Protection::NativeRoot, deadline);
        self.retain_errors(errors);
        let tool = self.observation.originals.routes.iter().find(|route| route.spec.role == Role::NativeTool)
            .filter(|route| route.admitted).ok_or(Reason::InputIncomplete)?;
        let hash = tool.content_digest.as_ref().ok_or(Reason::InputIncomplete)?;
        let size = tool.nodes.last().and_then(|node| node.stamp).and_then(|stamp| stamp.file.map(|file| file.0)).ok_or(Reason::InputIncomplete)?;
        let schema = native_schema::SupportedSchema::from_original(hash, size).map_err(Reason::NativeSchema)?;
        self.components = Some(native_schema::Components::new(schema));
        Ok(())
    })();
    if let Err(reason) = admission { self.retain_errors(vec![Refusal { role: None, phase: Phase::Admission, reason }]); }
    }
}


// Concrete originals only. This private enum has no provider/callback arm in
// production; a fixture domain cannot construct any actual selected session.
enum ReadOnlySessionBinding {
    Native {session:Arc<crate::power::selected_owner_session::SelectedOwnerSession>,
        stop:Arc<AtomicBool>,end:Instant},
    #[cfg(test)]
    Fixture {identity:Arc<()>,live:Arc<AtomicBool>,stop:Arc<AtomicBool>,end:Instant},
}
impl ReadOnlySessionBinding {
    fn current(&self,requested_end:Instant)->Check<()> {
        match self {
            Self::Native {session,stop,end}=>{
                let cap=requested_end.min(*end);
                if stop.load(Ordering::SeqCst) {return Err(Reason::SessionVetoed);}
                within(cap)?;session.require_current().map_err(|_|Reason::SessionVetoed)?;
                within(cap)?;
                if stop.load(Ordering::SeqCst) {return Err(Reason::SessionVetoed);}
                Ok(())
            },
            #[cfg(test)] Self::Fixture {live,stop,end,..}=>{
                if !live.load(Ordering::SeqCst) || stop.load(Ordering::SeqCst) {return Err(Reason::SessionVetoed);}
                within(requested_end.min(*end))
            },
        }
    }
    fn veto(&self) {
        match self {
            Self::Native {session,stop,..}=>{session.revoke();stop.store(true,Ordering::SeqCst);},
            #[cfg(test)] Self::Fixture {live,stop,..}=>{live.store(false,Ordering::SeqCst);stop.store(true,Ordering::SeqCst);},
        }
    }
    #[cfg(target_os="macos")]
    fn matches(&self,session:&Arc<crate::power::selected_owner_session::SelectedOwnerSession>,
        stop:&Arc<AtomicBool>,enclosing_end:Instant)->bool {
        match self {
            Self::Native {session:original,stop:original_stop,end}=>Arc::ptr_eq(original,session)
                && Arc::ptr_eq(original_stop,stop) && enclosing_end<=*end
                && *end<=original.original_instant_end(),
            #[cfg(test)] Self::Fixture {..}=>false,
        }
    }
}

// This read-only owner grants no startup/readiness authority. It has no serde,
// Clone, provider, mutation method or diagnostic accessor outside this module.
// The original enclosing end, admitted schema, context and all partial routes
// remain in this SAME owner until teardown. Samples borrow diagnostics only.
pub(super) struct RetainedReadOnlyOwner {
    original_enclosing_end:Instant,
    terminal:Arc<AtomicBool>,
    producer:Producer,
}
struct SampleVeto { terminal:Arc<AtomicBool>,session:Option<Arc<ReadOnlySessionBinding>>,armed:bool }
impl Drop for SampleVeto {
    fn drop(&mut self) {if self.armed {
        if let Some(session)=&self.session {session.veto();}
        self.terminal.store(true,Ordering::SeqCst);
    }}
}
impl Observation {
    fn invalidate_components(&mut self) {
        self.collection_complete=false;self.protected_inputs_current=false;
        self.native_schema=Knowledge::Unknown;self.pf_enabled=Knowledge::Unknown;
        self.root_rule_interpretation=Knowledge::Unknown;
        self.llm_compiled_live_comparison=Knowledge::Unknown;self.cas_compiled_live_comparison=Knowledge::Unknown;
        self.interface_skip_policy=Knowledge::Unknown;self.translation_policy=Knowledge::Unknown;
        self.preexisting_state_policy=Knowledge::Unknown;self.preexisting_state_count=None;
        self.root_translation_output=None;
        self.mandatory_watcher=Knowledge::NotObserved;self.atomic_restoration=Knowledge::NotObserved;
    }
}
impl Producer {
    fn begin_sample(&mut self,end:Instant) {
        // Only the outer owner may start a sample, after checking sticky veto.
        // No held route/context/schema is replaced or reopened here.
        self.observation.invalidate_components();
        self.observation.queries.clear();self.observation.primary_refusal=None;
        self.observation.boundary_refusals.clear();self.observation.final_refusals.clear();
        self.observation.sample_end=end.min(self.observation.original_enclosing_end);
        let started=crate::clock::boot_clock_ns();
        self.observation.started_boot_ns=started;self.observation.ended_boot_ns=started;
        if started==u64::MAX {self.retain_errors(vec![Refusal {role:None,phase:Phase::BeforeQuery,reason:Reason::ClockUnavailable}]);}
        if let Some(components)=&mut self.components {components.clear_observations();}
    }
    fn owner_vetoed(&mut self) {
        self.observation.invalidate_components();
        let error=Refusal {role:None,phase:Phase::BeforeQuery,reason:Reason::OwnerVetoed};
        // Repeated refused calls cannot create an unbounded failure journal.
        if self.observation.primary_refusal.is_none() {self.observation.primary_refusal=Some(error);}
        if !self.observation.boundary_refusals.contains(&error) {self.observation.boundary_refusals.push(error);}
    }
}
impl RetainedReadOnlyOwner {
    fn prepare_selected(original_enclosing_end:Instant)->Self {
        Self::prepare(original_enclosing_end,None)
    }
    /// Retain the actual SAME session and stop allocation BEFORE admission.
    /// The only runtime caller is private refusing pre-start composition.
    #[cfg(target_os="macos")]
    pub(super) fn prepare_selected_bound(
        session:Arc<crate::power::selected_owner_session::SelectedOwnerSession>,
        stop:Arc<AtomicBool>,enclosing_end:Instant)->Self {
        let end=enclosing_end.min(session.original_instant_end());
        let binding=Arc::new(ReadOnlySessionBinding::Native {session,stop,end});
        Self::prepare(end,Some(binding))
    }
    fn prepare(original_enclosing_end:Instant,session:Option<Arc<ReadOnlySessionBinding>>)->Self {
        let terminal=Arc::new(AtomicBool::new(false));
        let mut producer=Producer::empty_until(original_enclosing_end);
        producer.retained_veto=Some(terminal.clone());producer.retained_session=session;
        let mut owner=Self {original_enclosing_end,terminal,producer};
        // Guard includes SAME session before admission, so even caught context
        // or query unwind revokes all originals before any owned cleanup.
        let mut veto=owner.sample_veto();
        let end=owner.producer.observation.sample_end;
        if let Err(reason)=owner.producer.require_retained_session(end) {
            owner.producer.retain_errors(vec![Refusal {role:None,phase:Phase::Admission,reason}]);
        } else if owner.producer.observation.started_boot_ns==u64::MAX {
            owner.producer.retain_errors(vec![Refusal {role:None,phase:Phase::Admission,reason:Reason::ClockUnavailable}]);
        } else {owner.producer.admit_selected(end);}
        let errors=owner.producer.boundary(Phase::Admission,end);owner.producer.retain_errors(errors);
        if owner.producer.observation.primary_refusal.is_none() && !owner.terminal.load(Ordering::SeqCst) {
            veto.armed=false;
        }
        drop(veto);owner
    }
    fn sample_veto(&self)->SampleVeto {
        SampleVeto {terminal:self.terminal.clone(),session:self.producer.retained_session.clone(),armed:true}
    }
    pub(super) fn veto(&self) {self.producer.veto_if_retained();self.terminal.store(true,Ordering::SeqCst);}
    /// Passive identity/cap check only; a mismatch vetoes the retained actual
    /// session, never adopts the caller's offered session or stop allocation.
    #[cfg(target_os="macos")]
    pub(super) fn require_original(&self,
        session:&Arc<crate::power::selected_owner_session::SelectedOwnerSession>,
        stop:&Arc<AtomicBool>,enclosing_end:Instant)->EnclaveResult<()> {
        if self.terminal.load(Ordering::SeqCst) || self.producer.retained_session.as_ref()
            .is_none_or(|binding|!binding.matches(session,stop,enclosing_end))
            || enclosing_end>self.original_enclosing_end {
            self.veto();return Err(err!(EACCES,"PF_READONLY_ORIGINAL_BINDING_REFUSED"));
        }
        Ok(())
    }
    /// Negative collection health only. No component knowledge/observations,
    /// permit or readiness term can leave this module through this API.
    pub(super) fn require_health_until<C:super::pf_watch::NegativeCollectionCheck>(
        &mut self,requested_end:Instant,collection:&C)->EnclaveResult<()> {
        if self.producer.retained_session.is_none() {
            self.veto();return Err(err!(EACCES,"PF_READONLY_SESSION_REQUIRED"));
        }
        let mut health_veto=self.sample_veto();
        // Native production bindings must match the actual notification
        // window's session/stop/cap BEFORE any collection work. Test-only
        // synthetic sessions exercise boundary sequencing without native claims.
        if let Some(ReadOnlySessionBinding::Native {session,stop,end})=self.producer.retained_session.as_deref() {
            if collection.require_same_original(session,stop,requested_end.min(*end)).is_err() {
                self.veto();return Err(err!(EACCES,"PF_READONLY_NOTIFICATION_BINDING_REFUSED"));
            }
        }
        let observed=self.sample_with_collection_until(requested_end,Some(collection));
        let sample_end=observed.sample_end;
        let healthy=observed.collection_complete && observed.protected_inputs_current
            && observed.primary_refusal.is_none() && observed.boundary_refusals.is_empty()
            && observed.final_refusals.is_empty();
        if !healthy || self.terminal.load(Ordering::SeqCst)
            || self.producer.require_retained_session(sample_end).is_err()
            || collection.require_current(sample_end).is_err() {
            self.veto();self.producer.owner_vetoed();return Err(err!(EACCES,"PF_READONLY_COLLECTION_REFUSED"));
        }
        health_veto.armed=false;Ok(())
    }
    // Private diagnostic collection only; it never supplies readiness health.
    fn sample_until(&mut self,requested_end:Instant)->&Observation {
        self.sample_with_collection_until(requested_end,None)
    }
    fn sample_with_collection_until(&mut self,requested_end:Instant,
        collection:Option<&dyn super::pf_watch::NegativeCollectionCheck>)->&Observation {
        if self.terminal.load(Ordering::SeqCst) {
            self.veto();self.producer.owner_vetoed();return &self.producer.observation;
        }
        let mut veto=self.sample_veto();
        let end=self.original_enclosing_end.min(requested_end).min(Instant::now()+OVERALL_LIMIT);
        self.producer.begin_sample(end);
        self.producer.collect_with_collection(end,collection);self.producer.finish_with_collection_in_place(end,collection);
        if self.terminal.load(Ordering::SeqCst) {self.producer.owner_vetoed();}
        if self.producer.observation.collection_complete {veto.armed=false;}
        drop(veto);&self.producer.observation
    }
}
impl Drop for RetainedReadOnlyOwner {
    fn drop(&mut self) {self.veto();} // Before any producer/held owner fields drop.
}

fn observe_selected(deadline: Instant) -> Observation {
    let deadline = deadline.min(Instant::now() + OVERALL_LIMIT);
    let mut producer = Producer::empty_until(deadline);
    producer.admit_selected(deadline);
    if producer.observation.primary_refusal.is_none() { producer.collect(deadline); }
    producer.finish(deadline)
}

#[cfg(test)]
#[path = "pf_observation_tests.rs"]
mod tests;
