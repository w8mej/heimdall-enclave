//! Dedicated-target public payload preparation only; this is not installation.
//!
//! There is deliberately no CLI or production authority implementation here.
//! The production entry requires actual fixed-account admission and the actual
//! host maintenance guard and genuine software approval throughout the operation.
//! Candidate native signatures and renderer bytes are checked concretely; only
//! the separate complete target-inactivity authority remains unimplemented.
//! A root-protected inventory or its
//! candidate pins cannot approve themselves. Hostile/concurrent root and a
//! dishonest in-process authority provider are outside this primitive's trust
//! boundary. Ordinary users and daemon UIDs may not write any traversed parent.
//!
//! Only absent public payload names are published. Pins, launchd jobs, TUF and
//! all mutable/runtime stores remain untouched. Failure can leave a verified
//! prefix and newly created public directories; there is no automatic rollback,
//! replacement, service activation, state restore or claim of installation.

use std::{collections::{BTreeMap, BTreeSet}, ffi::CString, fs::{File, Metadata},
    io::{Read, Seek, SeekFrom, Write}, os::{fd::{AsRawFd, FromRawFd, RawFd},
    unix::{ffi::OsStrExt, fs::MetadataExt}}, path::{Path, PathBuf}};
use enclave_core::{deployment::{CheckedDeploymentTarget, DeploymentRole, normalized_path},
    error::{EnclaveError,EnclaveResult}, err, fail};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use super::{target_accounts::FixedAccountAdmission,target_activity::MaintenanceExclusion,
    target_maintenance::HostMaintenanceGuard,target_plan::{self, TargetInstallPlan},
    target_release::SoftwareApproval,target_candidate::{self,CandidateFileView}};

const MAX_FILES: usize = 128;
const MAX_DIRECTORIES: usize = 96;
const MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Stamp { dev:u64, ino:u64, uid:u32, gid:u32, mode:u32, links:u64, size:u64,
    modified:i64, modified_ns:i64, changed:i64, changed_ns:i64 }
fn stamp(m:&Metadata)->Stamp { Stamp {dev:m.dev(),ino:m.ino(),uid:m.uid(),gid:m.gid(),
    mode:m.mode(),links:m.nlink(),size:m.len(),modified:m.mtime(),modified_ns:m.mtime_nsec(),
    changed:m.ctime(),changed_ns:m.ctime_nsec()} }
fn protected(m:&Metadata)->bool {m.uid()==0 && m.mode()&0o022==0}
fn name(value:&std::ffi::OsStr)->EnclaveResult<CString> {
    CString::new(value.as_bytes()).map_err(|_|err!(EINVAL,"PAYLOAD_PATH"))
}
fn io_code()->enclave_core::error::EnclaveError {err!(EIO,"PAYLOAD_IO")}
fn route(path:&Path)->EnclaveResult<PathBuf> {
    let normalized=normalized_path(path)?;
    if cfg!(target_os="macos") {Ok(normalized)} else {Ok(path.to_owned())}
}
fn open_at(parent:RawFd, leaf:&CString, flags:i32)->EnclaveResult<File> {
    // SAFETY: live held parent FD and a single NUL-terminated component.
    let fd=unsafe {libc::openat(parent,leaf.as_ptr(),flags)};
    if fd<0 {fail!(EACCES,"PAYLOAD_PROTECTED_PATH");}
    // SAFETY: successful open returned this owned FD exactly once.
    Ok(unsafe {File::from_raw_fd(fd)})
}

struct Directory {file:File, dev:u64, ino:u64, uid:u32, gid:u32, mode:u32}
impl Directory {
    fn new(file:File)->EnclaveResult<Self> {
        let m=file.metadata().map_err(|_|io_code())?;
        if !m.is_dir() || !protected(&m) {fail!(EACCES,"PAYLOAD_DIRECTORY_PROTECTION");}
        Ok(Self {file,dev:m.dev(),ino:m.ino(),uid:m.uid(),gid:m.gid(),mode:m.mode()})
    }
    fn matches(&self,m:&Metadata)->bool {m.is_dir() && protected(m) && self.dev==m.dev()
        && self.ino==m.ino() && self.uid==m.uid() && self.gid==m.gid() && self.mode==m.mode()}
}
struct Directories {held:BTreeMap<PathBuf,Directory>}
impl Directories {
    fn new()->EnclaveResult<Self> {
        let root=CString::new("/").expect("literal");
        // SAFETY: constant C string, successful FD is exclusively owned.
        let fd=unsafe {libc::open(root.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)};
        if fd<0 {fail!(EACCES,"PAYLOAD_PROTECTED_PATH");}
        let root=Directory::new(unsafe {File::from_raw_fd(fd)})?;
        Ok(Self {held:BTreeMap::from([(PathBuf::from("/"),root)])})
    }
    fn fd(&self,path:&Path)->EnclaveResult<RawFd> {
        let d=self.held.get(path).ok_or_else(||err!(EINVAL,"PAYLOAD_DIRECTORY_NOT_HELD"))?;
        if !d.matches(&d.file.metadata().map_err(|_|io_code())?) {fail!(ESTALE,"PAYLOAD_DIRECTORY_CHANGED");}
        Ok(d.file.as_raw_fd())
    }
    /// Returns false only for an absent component when creation is forbidden.
    /// Existing directories are never repaired, chmodded or chowned.
    fn ensure_existing(&mut self,path:&Path)->EnclaveResult<bool> {
        self.ensure_checked(path,false,&mut PublicPayloadProgress::empty(),&mut ||Ok(()))
    }
    #[cfg(test)]
    fn ensure(&mut self,path:&Path,create:bool)->EnclaveResult<bool> {
        self.ensure_checked(path,create,&mut PublicPayloadProgress::empty(),&mut ||Ok(()))
    }
    fn ensure_checked(&mut self,path:&Path,create:bool,progress:&mut PublicPayloadProgress,
        check:&mut impl FnMut()->EnclaveResult<()>)->EnclaveResult<bool> {
        if path.components().count()>MAX_DIRECTORIES {fail!(E2BIG,"PAYLOAD_DIRECTORY_LIMIT");}
        if self.held.contains_key(path) {self.fd(path)?;return Ok(true);}
        if self.held.len()>=MAX_DIRECTORIES {fail!(E2BIG,"PAYLOAD_DIRECTORY_LIMIT");}
        let parent=path.parent().ok_or_else(||err!(EINVAL,"PAYLOAD_PATH"))?;
        if !self.ensure_checked(parent,create,progress,check)? {return Ok(false);}
        // Recursive parent insertion can exhaust the budget after this frame's
        // first check. Refuse before opening or creating its child.
        if self.held.len()>=MAX_DIRECTORIES {fail!(E2BIG,"PAYLOAD_DIRECTORY_LIMIT");}
        let pfd=self.fd(parent)?;let leaf=name(path.file_name().ok_or_else(||err!(EINVAL,"PAYLOAD_PATH"))?)?;
        let flags=libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK;
        // SAFETY: held parent and canonical single component.
        let fd=unsafe {libc::openat(pfd,leaf.as_ptr(),flags)};
        let file=if fd>=0 {unsafe {File::from_raw_fd(fd)}} else {
            if std::io::Error::last_os_error().raw_os_error()!=Some(libc::ENOENT) {fail!(EACCES,"PAYLOAD_PROTECTED_PATH");}
            if !create {return Ok(false);}
            self.validate()?;check()?;progress.incomplete=Some(path.to_owned());
            // Creation is exclusive; another creator is a refusal, not a repair.
            if unsafe {libc::mkdirat(pfd,leaf.as_ptr(),0o700)}!=0 {fail!(EALREADY,"PAYLOAD_DIRECTORY_RACE");}
            progress.created_directories.push(path.to_owned());
            let file=open_at(pfd,&leaf,flags)?;
            // Only a directory created by this invocation is assigned metadata.
            check()?;
            if unsafe {libc::fchown(file.as_raw_fd(),0,0)}!=0 {fail!(EACCES,"PAYLOAD_NEW_DIRECTORY_METADATA");}
            check()?;
            if unsafe {libc::fchmod(file.as_raw_fd(),0o755)}!=0 {fail!(EACCES,"PAYLOAD_NEW_DIRECTORY_METADATA");}
            check()?;
            file.sync_all().map_err(|_|io_code())?;
            self.held.get(parent).expect("held parent").file.sync_all().map_err(|_|io_code())?;
            file
        };
        self.held.insert(path.to_owned(),Directory::new(file)?);
        if progress.incomplete.as_deref()==Some(path) {progress.incomplete=None;}
        Ok(true)
    }
    fn absent(&mut self,path:&Path)->EnclaveResult<bool> {
        let parent=path.parent().ok_or_else(||err!(EINVAL,"PAYLOAD_PATH"))?;
        if !self.ensure_existing(parent)? {return Ok(true);}
        let leaf=name(path.file_name().ok_or_else(||err!(EINVAL,"PAYLOAD_PATH"))?)?;
        let mut value=std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: held FD, valid C component, writable stat storage; no follow.
        if unsafe {libc::fstatat(self.fd(parent)?,leaf.as_ptr(),value.as_mut_ptr(),libc::AT_SYMLINK_NOFOLLOW)}==0 {return Ok(false);}
        if std::io::Error::last_os_error().raw_os_error()==Some(libc::ENOENT) {Ok(true)}
        else {fail!(EACCES,"PAYLOAD_DESTINATION_OBSERVATION");}
    }
    fn validate(&self)->EnclaveResult<()> {
        for (path,d) in &self.held {
            self.fd(path)?;
            if path==Path::new("/") {continue;}
            let parent=path.parent().ok_or_else(||err!(EINVAL,"PAYLOAD_PATH"))?;
            let leaf=name(path.file_name().ok_or_else(||err!(EINVAL,"PAYLOAD_PATH"))?)?;
            let current=open_at(self.fd(parent)?,&leaf,libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK)?;
            if !d.matches(&current.metadata().map_err(|_|io_code())?) {fail!(ESTALE,"PAYLOAD_DIRECTORY_CHANGED");}
        }
        Ok(())
    }
}

/// Read-only held file view for the trusted native/release verifier. There is
/// no public constructor or writable FD. Paths alone do not establish trust.
pub(crate) struct HeldPublicFile {path:PathBuf,parent:PathBuf,leaf:CString,file:File,hash:String,observed:Stamp}
impl HeldPublicFile {
    /// Exact observed canonical source route, never an executable invocation.
    pub(crate) fn path(&self)->&Path {&self.path}
    /// Held read-only inode for a verifier that can inspect file descriptors.
    pub(crate) fn file(&self)->&File {&self.file}
    /// SHA-256 observed over exactly `size()` bytes, not source attestation.
    pub(crate) fn sha256(&self)->&str {&self.hash}
    /// Exact observed length.
    pub(crate) fn size(&self)->u64 {self.observed.size}
    fn open(dirs:&mut Directories,path:&Path,expected:Option<(&str,u64)>,maximum:u64)->EnclaveResult<Self> {
        let path=route(path)?;let parent=path.parent().ok_or_else(||err!(EINVAL,"PAYLOAD_PATH"))?.to_owned();
        if !dirs.ensure_existing(&parent)? {fail!(EACCES,"PAYLOAD_SOURCE_MISSING");}
        let leaf=name(path.file_name().ok_or_else(||err!(EINVAL,"PAYLOAD_PATH"))?)?;
        let file=open_at(dirs.fd(&parent)?,&leaf,libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK)?;
        let m=file.metadata().map_err(|_|io_code())?;
        if !m.is_file() || !protected(&m) || m.nlink()!=1 || m.len()==0 || m.len()>maximum {fail!(EACCES,"PAYLOAD_SOURCE_PROTECTION");}
        let observed=stamp(&m);let hash=hash_file(&file,maximum)?;
        if let Some((digest,size))=expected {
            if digest!=hash || size!=m.len() {fail!(EINVAL,"PAYLOAD_SOURCE_DIGEST");}
        }
        let held=Self {path,parent,leaf,file,hash,observed};held.validate(dirs)?;Ok(held)
    }
    fn validate(&self,dirs:&Directories)->EnclaveResult<()> {
        if stamp(&self.file.metadata().map_err(|_|io_code())?)!=self.observed {fail!(ESTALE,"PAYLOAD_SOURCE_CHANGED");}
        let current=open_at(dirs.fd(&self.parent)?,&self.leaf,libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK)?;
        if stamp(&current.metadata().map_err(|_|io_code())?)!=self.observed {fail!(ESTALE,"PAYLOAD_SOURCE_CHANGED");}
        Ok(())
    }
}
fn hash_file(file:&File,maximum:u64)->EnclaveResult<String> {
    let mut read=file.try_clone().map_err(|_|io_code())?;read.seek(SeekFrom::Start(0)).map_err(|_|io_code())?;
    let mut hash=Sha256::new();let mut count=0u64;let mut buffer=[0u8;65536];
    loop {let n=read.read(&mut buffer).map_err(|_|io_code())?;if n==0 {break;}
        count=count.checked_add(n as u64).ok_or_else(||err!(E2BIG,"PAYLOAD_SOURCE_LIMIT"))?;
        if count>maximum {fail!(E2BIG,"PAYLOAD_SOURCE_LIMIT");}hash.update(&buffer[..n]);}
    Ok(hex::encode(hash.finalize()))
}

/// Independent whole-target inactivity authority, deliberately unimplemented
/// in production. Registration absence or a JSON flag cannot supply it.
pub(crate) trait PublicPayloadAuthority {
    /// Check every target system/GUI job and process under the SAME actual
    /// maintenance owner. Account for already-admitted delayed startup. The
    /// caller retains this guard throughout publication; never reacquire it.
    fn verify_target_inactive(&mut self,checked:&CheckedDeploymentTarget,
        guard:&mut HostMaintenanceGuard)->EnclaveResult<()>;
}

// A single private owner composes all boundaries without aliasing the actual
// guard between a callback and a candidate/inactivity authority provider.
trait PayloadBoundary {
    fn check(&mut self,phase:CheckPhase)->EnclaveResult<()>;
    fn verify_candidate(&mut self,checked:&CheckedDeploymentTarget,
        plan:&TargetInstallPlan,files:&[HeldPublicFile])->EnclaveResult<()>;
    fn verify_inactive(&mut self,checked:&CheckedDeploymentTarget)->EnclaveResult<()>;
}
struct NativePayloadBoundary<'a> {
    checked:&'a CheckedDeploymentTarget,authority:&'a mut dyn PublicPayloadAuthority,
    accounts:&'a FixedAccountAdmission,approval:&'a mut SoftwareApproval,
    guard:&'a mut HostMaintenanceGuard,
}
impl PayloadBoundary for NativePayloadBoundary<'_> {
    fn check(&mut self,phase:CheckPhase)->EnclaveResult<()> {
        let root=if unsafe {libc::geteuid()}==0 {Ok(())}else{Err(err!(EACCES,"PAYLOAD_ROOT_REQUIRED"))};
        let exclusion=self.guard.assert_held();
        // Evaluate every available postcheck even after another one refused.
        let admission=if phase==CheckPhase::Accounts {
            self.accounts.assert_current(self.checked,self.guard)
        }else{Ok(())};
        let release=self.approval.assert_current(self.checked,self.guard);
        let final_exclusion=self.guard.assert_held();
        root?;exclusion?;admission?;release?;final_exclusion
    }
    fn verify_candidate(&mut self,checked:&CheckedDeploymentTarget,
        plan:&TargetInstallPlan,files:&[HeldPublicFile])->EnclaveResult<()> {
        let views=files.iter().map(|file|CandidateFileView {path:file.path(),file:file.file(),
            sha256:file.sha256(),size:file.size()}).collect::<Vec<_>>();
        // No injectable production native/release/renderer verifier.
        target_candidate::verify_candidate_native_and_rendered(checked,plan,&views,self.approval,self.guard)
    }
    fn verify_inactive(&mut self,checked:&CheckedDeploymentTarget)->EnclaveResult<()> {
        self.authority.verify_target_inactive(checked,self.guard)
    }
}

// Software fixtures cannot construct native guards or genuine approvals and
// never enter the production API. This injection surface is test-only.
#[cfg(test)]
trait SyntheticPayloadAuthority {
    fn verify_release_and_native_code(&mut self,checked:&CheckedDeploymentTarget,
        plan:&TargetInstallPlan,files:&[HeldPublicFile])->EnclaveResult<()>;
    fn verify_target_inactive(&mut self,checked:&CheckedDeploymentTarget)->EnclaveResult<()>;
}
#[cfg(test)]
fn run_payload(checked:&CheckedDeploymentTarget,authority:&mut dyn SyntheticPayloadAuthority,
    checks:&mut impl FnMut(CheckPhase)->EnclaveResult<()>)->Result<PublicPayloadReceipt,PublicPayloadFailure> {
    struct SyntheticBoundary<'a,C> {authority:&'a mut dyn SyntheticPayloadAuthority,checks:&'a mut C}
    impl<C:FnMut(CheckPhase)->EnclaveResult<()>> PayloadBoundary for SyntheticBoundary<'_,C> {
        fn check(&mut self,phase:CheckPhase)->EnclaveResult<()> {(self.checks)(phase)}
        fn verify_candidate(&mut self,checked:&CheckedDeploymentTarget,plan:&TargetInstallPlan,
            files:&[HeldPublicFile])->EnclaveResult<()> {
            self.authority.verify_release_and_native_code(checked,plan,files)
        }
        fn verify_inactive(&mut self,checked:&CheckedDeploymentTarget)->EnclaveResult<()> {
            self.authority.verify_target_inactive(checked)
        }
    }
    run_payload_with_boundary(checked,&mut SyntheticBoundary {authority,checks})
}

/// Successful inert payload publication; never an installed/readiness receipt.
#[derive(Debug)]
pub(crate) struct PublicPayloadReceipt {
    pub(crate) target_id:String,
    pub(crate) descriptor_sha256:String,
    pub(crate) artifact_inventory_sha256:String,
    pub(crate) published:Vec<PathBuf>,
    pub(crate) selected_pins_sha256_unchanged:String,
    pub(crate) installation_supported:bool,
    pub(crate) qualified:bool,
}
/// Observations after refusal, never a successful payload/runtime capability.
/// Paths confer no cleanup, repair, rollback or replacement authority.
#[derive(Debug)]
pub(crate) struct PublicPayloadProgress {
    pub(crate) target_id:String,
    pub(crate) descriptor_sha256:String,
    pub(crate) artifact_inventory_sha256:Option<String>,
    /// Files whose exclusive publication and parent sync completed. A later
    /// context/binding refusal does not make the whole operation successful.
    pub(crate) published:Vec<PathBuf>,
    /// mkdir returned success; metadata/durability may still be incomplete.
    pub(crate) created_directories:Vec<PathBuf>,
    /// Current attempted directory/file; final state may be unconfirmed.
    pub(crate) incomplete:Option<PathBuf>,
    /// An exclusively created temporary whose durable removal is unconfirmed;
    /// its name may already be absent. This is not cleanup authority.
    pub(crate) temporary:Option<PathBuf>,
}
impl PublicPayloadProgress {
    fn empty()->Self {Self {target_id:String::new(),descriptor_sha256:String::new(),
        artifact_inventory_sha256:None,published:Vec::new(),created_directories:Vec::new(),
        incomplete:None,temporary:None}}
    fn new(checked:&CheckedDeploymentTarget)->Self {Self {target_id:checked.target().target_id.clone(),
        descriptor_sha256:checked.descriptor_sha256().into(),..Self::empty()}}
}
#[derive(Debug)]
pub(crate) struct PublicPayloadFailure {
    pub(crate) error:EnclaveError,
    /// Retained even when a conservative final postcheck takes precedence.
    pub(crate) operation_error:Option<EnclaveError>,
    pub(crate) receipt:PublicPayloadProgress,
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum CheckPhase {Accounts,Context}
fn payload_copy(copy:&target_plan::CopyEntry,pins:&Path)->bool {
    copy.destination!=pins && !copy.destination.starts_with("/Library/LaunchDaemons")
        && !copy.destination.starts_with("/Library/LaunchAgents")
}
fn check_inactive_paths(checked:&CheckedDeploymentTarget,plan:&TargetInstallPlan,dirs:&mut Directories)->EnclaveResult<()> {
    let t=checked.target();
    if t.role!=DeploymentRole::DedicatedTest {fail!(EACCES,"PAYLOAD_UPGRADE_UNAVAILABLE");}
    for root in [&t.layout.socket_root,&t.layout.state_root,&t.layout.audit_root,&t.layout.cas_store_root] {
        if !dirs.absent(&route(root)?)? {fail!(EALREADY,"PAYLOAD_TARGET_NOT_PRISTINE");}
    }
    if let Some(b)=&t.broker {
        if !dirs.absent(&route(&b.base_dir)?)? {fail!(EALREADY,"PAYLOAD_TARGET_NOT_PRISTINE");}
    }
    // Existing jobs are refused even though this primitive never publishes one.
    for copy in &plan.copies {
        if copy.destination==plan.selected_pins_file {continue;}
        if !dirs.absent(&route(&copy.destination)?)? {fail!(EALREADY,"PAYLOAD_REPLACEMENT_UNAVAILABLE");}
    }
    Ok(())
}
fn unchanged_context(checked:&CheckedDeploymentTarget,plan:&TargetInstallPlan)->EnclaveResult<()> {
    let raw=checked.read_artifact_inventory()?;
    if hex::encode(Sha256::digest(raw))!=plan.artifact_inventory_sha256 {fail!(ESTALE,"PAYLOAD_CONTEXT_CHANGED");}
    Ok(())
}

/// Create only the fixed public payload subset of a COMPLETE dedicated plan.
/// No caller-created plan is accepted. There is no production authority hook
/// implementation/caller, CLI flag or general installation/apply support.
/// Retain this same guard through subsequent runtime provisioning. Account
/// observation excludes concurrent directory-administrator changes; cooperative
/// locking alone does not establish process inactivity or release authority.
pub(crate) fn create_only_public_payload(checked:&CheckedDeploymentTarget,
    authority:&mut dyn PublicPayloadAuthority,accounts:&FixedAccountAdmission,
    approval:&mut SoftwareApproval,guard:&mut HostMaintenanceGuard)
    ->Result<PublicPayloadReceipt,PublicPayloadFailure> {
    #[cfg(not(target_os="macos"))]
    {let _=(authority,accounts,approval,guard);Err(PublicPayloadFailure {error:err!(ENOSYS,"PAYLOAD_NATIVE_REQUIRED"),
        operation_error:None,receipt:PublicPayloadProgress::new(checked)})}
    #[cfg(target_os="macos")]
    {run_payload_with_boundary(checked,&mut NativePayloadBoundary {checked,authority,accounts,approval,guard})}
}
fn context_boundary(checked:&CheckedDeploymentTarget,plan:&TargetInstallPlan,
    boundary:&mut dyn PayloadBoundary)->EnclaveResult<()> {
    let exclusion=boundary.check(CheckPhase::Context);
    let context=unchanged_context(checked,plan);
    context?;exclusion
}
fn validate_inputs(dirs:&Directories,files:&[HeldPublicFile],trust:&[HeldPublicFile])->EnclaveResult<()> {
    dirs.validate()?;
    for file in files.iter().chain(trust) {file.validate(dirs)?;}
    Ok(())
}
/// Private engine shared with explicitly synthetic tests. The only production
/// caller supplies actual guard/account checks above; there is no unchecked
/// overload, runtime flag, CLI or production fixture authority implementation.
fn run_payload_with_boundary(checked:&CheckedDeploymentTarget,boundary:&mut dyn PayloadBoundary)
    ->Result<PublicPayloadReceipt,PublicPayloadFailure> {
    let mut progress=PublicPayloadProgress::new(checked);
    let mut plan=None;let mut directories=None;let mut trust=Vec::new();let mut files=Vec::new();
    let mut old_pins=String::new();
    let operation=(|| {
    boundary.check(CheckPhase::Accounts)?;
    if checked.target().role!=DeploymentRole::DedicatedTest {fail!(EACCES,"PAYLOAD_UPGRADE_UNAVAILABLE");}
    plan=Some(target_plan::prepare(checked)?);let plan=plan.as_ref().expect("prepared");
    progress.artifact_inventory_sha256=Some(plan.artifact_inventory_sha256.clone());
    if !plan.missing_required_files.is_empty() {fail!(EINVAL,"PAYLOAD_INCOMPLETE");}
    if plan.copies.len()+plan.retained_in_staging.len()>MAX_FILES {fail!(E2BIG,"PAYLOAD_SOURCE_LIMIT");}
    directories=Some(Directories::new()?);let dirs=directories.as_mut().expect("opened");
    check_inactive_paths(checked,plan,dirs)?;
    // Preserve exact old selected pins and all selected public trust references.
    let t=checked.target();
    for (path,maximum) in [(checked.config_path(),65536),(&t.authority_config,1048576),
        (&t.expected_artifacts_manifest,1048576),(&t.codesign_pins_file,1048576)] {
        trust.push(HeldPublicFile::open(dirs,path,None,maximum)?);
    }
    if let Some(b)=&t.broker {trust.push(HeldPublicFile::open(dirs,&b.tuf_root_file,None,4194304)?);}
    old_pins=trust[3].sha256().to_owned();
    let mut identities=BTreeSet::new();let mut total=0u64;
    for (path,digest,size) in plan.copies.iter().map(|c|(&c.source,c.sha256.as_str(),c.size))
        .chain(plan.retained_in_staging.iter().map(|c|(&c.source,c.sha256.as_str(),c.size))) {
        total=total.checked_add(size).ok_or_else(||err!(E2BIG,"PAYLOAD_SOURCE_LIMIT"))?;
        if total>MAX_TOTAL_BYTES {fail!(E2BIG,"PAYLOAD_SOURCE_LIMIT");}
        let file=HeldPublicFile::open(dirs,path,Some((digest,size)),MAX_FILE_BYTES)?;
        if !identities.insert((file.observed.dev,file.observed.ino)) {fail!(EINVAL,"PAYLOAD_SOURCE_ALIAS");}
        files.push(file);
    }
    context_boundary(checked,plan,boundary)?;
    boundary.verify_candidate(checked,plan,&files)?;
    context_boundary(checked,plan,boundary)?;
    boundary.verify_inactive(checked)?;
    context_boundary(checked,plan,boundary)?;validate_inputs(dirs,&files,&trust)?;
    check_inactive_paths(checked,plan,dirs)?;
    for copy in plan.copies.iter().filter(|c|payload_copy(c,&plan.selected_pins_file)) {
        let path=route(&copy.source)?;
        let source=files.iter().find(|f|f.path==path).ok_or_else(||err!(EINVAL,"PAYLOAD_SOURCE_MISSING"))?;
        let destination=route(&copy.destination)?;
        let parent=destination.parent().ok_or_else(||err!(EINVAL,"PAYLOAD_PATH"))?;
        let mut check=||context_boundary(checked,plan,boundary);
        check()?;dirs.ensure_checked(parent,true,&mut progress,&mut check)?;
        validate_inputs(dirs,&files,&trust)?;check()?;
        let mode=match copy.mode.as_str() {"0644"=>0o644,"0755"=>0o755,_=>{fail!(EINVAL,"PAYLOAD_MODE");}};
        if copy.uid!=0 || copy.gid!=0 {fail!(EINVAL,"PAYLOAD_OWNER");}
        publish_one_checked(dirs,source,&destination,mode,&mut progress,&mut check)?;
        // Record the verified file before a later boundary may refuse.
        progress.published.push(destination);check()?;
    }
    Ok(())
    })();
    // Every operation error, including preparation/authority errors and partial
    // publication, receives all available read-only postchecks. Do not use ?
    // until account/exclusion, descriptor/inventory and held/named checks run.
    let admission=boundary.check(CheckPhase::Accounts);
    let context=match &plan {Some(p)=>context_boundary(checked,p,boundary),None=>Ok(())};
    let bindings=match &directories {Some(d)=>validate_inputs(d,&files,&trust),None=>Ok(())};
    let operation_error=operation.err();
    let refusal=bindings.err().or(context.err()).or(admission.err()).or_else(||operation_error.clone());
    if let Some(error)=refusal {return Err(PublicPayloadFailure {error,operation_error,receipt:progress});}
    Ok(PublicPayloadReceipt {target_id:progress.target_id,descriptor_sha256:progress.descriptor_sha256,
        artifact_inventory_sha256:progress.artifact_inventory_sha256.expect("successful plan"),published:progress.published,
        selected_pins_sha256_unchanged:old_pins,installation_supported:false,qualified:false})
}

#[cfg(test)]
fn publish_one(dirs:&Directories,source:&HeldPublicFile,destination:&Path,mode:u32)->EnclaveResult<()> {
    publish_one_checked(dirs,source,destination,mode,&mut PublicPayloadProgress::empty(),&mut ||Ok(()))
}
fn publish_one_checked(dirs:&Directories,source:&HeldPublicFile,destination:&Path,mode:u32,
    progress:&mut PublicPayloadProgress,check:&mut impl FnMut()->EnclaveResult<()>)->EnclaveResult<()> {
    let parent=destination.parent().ok_or_else(||err!(EINVAL,"PAYLOAD_PATH"))?;
    let directory=&dirs.held.get(parent).ok_or_else(||err!(EINVAL,"PAYLOAD_DIRECTORY_NOT_HELD"))?.file;
    let pfd=dirs.fd(parent)?;let leaf=name(destination.file_name().ok_or_else(||err!(EINVAL,"PAYLOAD_PATH"))?)?;
    let mut random=[0u8;16];OsRng.try_fill_bytes(&mut random).map_err(|_|err!(EIO,"PAYLOAD_RANDOM"))?;
    let temporary=CString::new(format!(".mcpmac-payload-{}",hex::encode(random))).expect("hex literal");
    check()?;dirs.validate()?;progress.incomplete=Some(destination.to_owned());
    // Exclusive temporary name, never a caller-provided writable path.
    let fd=unsafe {libc::openat(pfd,temporary.as_ptr(),libc::O_RDWR|libc::O_CREAT|libc::O_EXCL|libc::O_NOFOLLOW|libc::O_CLOEXEC,0o600)};
    if fd<0 {fail!(EACCES,"PAYLOAD_TEMPORARY_REFUSED");}
    let mut output=unsafe {File::from_raw_fd(fd)};
    progress.temporary=Some(parent.join(std::ffi::OsStr::from_bytes(temporary.as_bytes())));
    let operation=(|| {
    let mut input=source.file.try_clone().map_err(|_|io_code())?;input.seek(SeekFrom::Start(0)).map_err(|_|io_code())?;
    let mut hash=Sha256::new();let mut count=0u64;let mut buffer=[0u8;65536];
    loop {let n=input.read(&mut buffer).map_err(|_|io_code())?;if n==0 {break;}
        count=count.checked_add(n as u64).ok_or_else(||err!(E2BIG,"PAYLOAD_SOURCE_LIMIT"))?;
        if count>source.size() {fail!(ESTALE,"PAYLOAD_SOURCE_CHANGED");}
        hash.update(&buffer[..n]);check()?;dirs.validate()?;
        output.write_all(&buffer[..n]).map_err(|_|io_code())?;}
    if count!=source.size() || hex::encode(hash.finalize())!=source.sha256() {fail!(ESTALE,"PAYLOAD_SOURCE_CHANGED");}
    source.validate(dirs)?;
    check()?;
    if unsafe {libc::fchown(fd,0,0)}!=0 {fail!(EACCES,"PAYLOAD_NEW_FILE_METADATA");}
    check()?;
    if unsafe {libc::fchmod(fd,mode as libc::mode_t)}!=0 {fail!(EACCES,"PAYLOAD_NEW_FILE_METADATA");}
    check()?;
    output.sync_all().map_err(|_|io_code())?;
    let before=output.metadata().map_err(|_|io_code())?;
    if !before.is_file() || before.uid()!=0 || before.gid()!=0 || before.nlink()!=1
        || before.mode()&0o7777!=mode || before.len()!=count
        || hash_file(&output,MAX_FILE_BYTES)?!=source.sha256() {fail!(EIO,"PAYLOAD_TEMPORARY_VERIFY");}
    dirs.validate()?;source.validate(dirs)?;
    let named=open_at(pfd,&temporary,libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK)?;
    if stamp(&named.metadata().map_err(|_|io_code())?)!=stamp(&before)
        || stamp(&output.metadata().map_err(|_|io_code())?)!=stamp(&before) {fail!(ESTALE,"PAYLOAD_TEMPORARY_CHANGED");}
    // linkat publishes complete bytes atomically AND refuses every existing
    // destination (including symlink). It never replaces a pathname. A crash
    // between link/unlink may leave a root-owned temporary hardlink; this is
    // not silently repaired, and nlink1 readers refuse it until reviewed.
    check()?;
    if unsafe {libc::linkat(pfd,temporary.as_ptr(),pfd,leaf.as_ptr(),0)}!=0 {fail!(EALREADY,"PAYLOAD_REPLACEMENT_UNAVAILABLE");}
    check()?;
    if unsafe {libc::unlinkat(pfd,temporary.as_ptr(),0)}!=0 {fail!(EIO,"PAYLOAD_PUBLICATION_INCOMPLETE");}
    // Removal is not durably confirmed until the final parent sync succeeds.
    let final_file=open_at(pfd,&leaf,libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK)?;
    let m=final_file.metadata().map_err(|_|io_code())?;
    if m.dev()!=before.dev() || m.ino()!=before.ino() || m.uid()!=0 || m.gid()!=0
        || m.nlink()!=1 || m.mode()&0o7777!=mode || m.len()!=count {fail!(ESTALE,"PAYLOAD_PUBLICATION_CHANGED");}
    check()?;directory.sync_all().map_err(|_|io_code())?;
    progress.temporary=None;progress.incomplete=None;Ok(())
    })();
    if operation.is_err() && progress.temporary.is_some() {
        // Never perform Drop-time writes after a boundary refusal. Best-effort
        // cleanup itself requires current exclusion/context and exact held/named
        // temporary inode identity; uncertainty remains explicitly reported.
        let cleanup=(|| {
            check()?;dirs.validate()?;
            let mut observed=std::mem::MaybeUninit::<libc::stat>::uninit();
            if unsafe {libc::fstatat(pfd,temporary.as_ptr(),observed.as_mut_ptr(),libc::AT_SYMLINK_NOFOLLOW)}==0 {
                let observed=unsafe {observed.assume_init()};let held=output.metadata().map_err(|_|io_code())?;
                if observed.st_dev as u64!=held.dev() || observed.st_ino as u64!=held.ino() {
                    fail!(ESTALE,"PAYLOAD_TEMPORARY_CHANGED");
                }
                check()?;
                if unsafe {libc::unlinkat(pfd,temporary.as_ptr(),0)}!=0 {fail!(EIO,"PAYLOAD_TEMPORARY_CLEANUP_UNCERTAIN");}
            } else if std::io::Error::last_os_error().raw_os_error()!=Some(libc::ENOENT) {
                fail!(EIO,"PAYLOAD_TEMPORARY_CLEANUP_UNCERTAIN");
            }
            check()?;directory.sync_all().map_err(|_|io_code())?;
            progress.temporary=None;Ok(())
        })();
        // Preserve the original publication refusal; the nonempty temporary
        // field records cleanup uncertainty even when cleanup also refuses.
        let _:EnclaveResult<()>=cleanup;
    }
    operation
}

#[cfg(test)]
#[path="target_payload_tests.rs"]
mod tests;
