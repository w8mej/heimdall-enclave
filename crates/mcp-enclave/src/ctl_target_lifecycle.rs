//! Selected core-five launchd operations. No production verifier/runner provider
//! or CLI dispatch is supplied here. Trusted adapters must satisfy the native
//! code and bounded owned-child contracts before this seam can be connected.
//! Auxiliary jobs and full-installation/readiness authority are outside scope.

use super::{Env, START_ORDER};
use std::{collections::BTreeMap, ffi::CString, fs::{File, Metadata},
    os::{fd::{AsRawFd, FromRawFd}, unix::{ffi::OsStrExt, fs::{FileExt, MetadataExt}}},
    path::{Path, PathBuf}, process::Command, time::{Duration, Instant}};
use enclave_core::{codesign::{self, CodeRequirement}, daemon::DaemonId,
    deployment::{self, CheckedDeploymentTarget, normalized_path, teardown::TeardownDeploymentTarget},
    error::{EnclaveError, EnclaveResult}, err, fail, Profile};
use serde::Serialize;
use sha2::{Digest, Sha256};

const MAX_PUBLIC:u64=1024*1024;
const MAX_CODE:u64=512*1024*1024;
const MAX_ANCESTORS:usize=96;
const MAX_HELD_DIRECTORIES:usize=256;
// Command safety bounds and admission cutoffs only, not measured ceremony or
// secret-lifecycle budgets. Synchronous filesystem/native signature calls are
// not forcibly interruptible; check their observed completion before effects.
const COMMAND_LIMIT:Duration=Duration::from_secs(5);
const OPERATION_LIMIT:Duration=Duration::from_secs(30);
const INSTALLED_PLISTS:&str="/Library/LaunchDaemons";

/// Only these two closed operations can reach the runner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all="kebab-case")]
pub(crate) enum CoreAction { Start, Stop }
/// Root-derived command; callers cannot inject an action, domain or label.
pub(crate) struct CoreCommand {action:CoreAction,label:String,plist:PathBuf}
impl CoreCommand {
    /// A scrubbed fixed launchctl command; no shell, kickstart or target PID.
    pub(crate) fn command(&self)->Command {
        let mut command=crate::syscmd::command(crate::syscmd::Tool::Launchctl);
        command.current_dir("/");
        match self.action {
            CoreAction::Start=>{command.arg("bootstrap").arg("system").arg(&self.plist);},
            CoreAction::Stop=>{command.arg("bootout").arg(format!("system/{}",self.label));},
        }
        command
    }
    /// Exact selected core job label, for bounded public outcome reporting.
    pub(crate) fn label(&self)->&str {&self.label}
}
/// The adapter must honor the absolute deadline, bound combined output, retain
/// owned-child lifetime identity through cleanup, and return an error on any
/// uncertain command/cleanup result. Raw launchctl output must not be exported.
pub(crate) trait CoreRunner {
    fn run(&mut self,command:&CoreCommand,deadline:Instant)->EnclaveResult<()>;
}
/// Read-only executable/resource view. All entries remain held and are rehashed
/// around pathname native verification. Hashes are observations, not release
/// provenance. The native adapter must also call `revalidate` around its checks.
pub(crate) struct CoreCodeView<'a> {
    pub(crate) code_path:&'a Path,
    pub(crate) executable_path:&'a Path,
    pub(crate) executable:&'a File,
    pub(crate) executable_sha256:&'a str,
    pub(crate) executable_size:u64,
    pub(crate) members:Vec<CoreResourceView<'a>>,
    pub(crate) revalidate:&'a dyn Fn()->EnclaveResult<()>,
}
/// Held public native-bundle resource, without writable descriptors.
pub(crate) struct CoreResourceView<'a> {
    pub(crate) path:&'a Path,
    pub(crate) file:&'a File,
    pub(crate) sha256:&'a str,
    pub(crate) size:u64,
}
/// No default/provider exists. The trusted native adapter must verify valid
/// native code, original identifier, exact compiled Team ID and selected hash,
/// hardened runtime and the exact built-in daemon entitlement policy (including
/// custody's approved Team-specific fields), before returning. It must refuse
/// unsupported policy/platform and check the deadline before/after native work.
/// Synchronous Security.framework calls cannot be forcibly interrupted by an
/// Instant: late completion must refuse, without claiming a hard wall-time cap.
/// It cannot infer
/// release provenance or approve candidate pins from inventory contents.
pub(crate) trait CoreCodeVerifier {
    fn verify(&mut self,daemon:DaemonId,view:&CoreCodeView<'_>,requirement:&CodeRequirement,
        deadline:Instant)->EnclaveResult<()>;
}
/// Successful registration commands do not establish process health or full
/// deployment readiness. Partial failures retain the exact completed prefix.
#[derive(Debug, Serialize)]
pub(crate) struct CoreLifecycleReceipt {
    pub(crate) target_id:String,
    pub(crate) descriptor_sha256:String,
    pub(crate) action:CoreAction,
    pub(crate) scope:&'static str,
    pub(crate) completed_labels:Vec<String>,
    pub(crate) boundary_label:Option<String>,
    pub(crate) uncertain_command_effects:bool,
    pub(crate) complete:bool,
    pub(crate) readiness:&'static str,
    pub(crate) qualified:bool,
}
#[derive(Debug)]
pub(crate) struct CoreLifecycleFailure {
    pub(crate) error:EnclaveError,
    pub(crate) receipt:CoreLifecycleReceipt,
}
type LifecycleResult=Result<CoreLifecycleReceipt,CoreLifecycleFailure>;
fn receipt(checked:&CheckedDeploymentTarget,action:CoreAction)->CoreLifecycleReceipt {
    receipt_for_target(checked.target(),checked.descriptor_sha256(),action)
}
fn receipt_for_target(target:&deployment::DeploymentTarget,descriptor_sha256:&str,action:CoreAction)->CoreLifecycleReceipt {
    CoreLifecycleReceipt {target_id:target.target_id.clone(),descriptor_sha256:descriptor_sha256.into(),
        action,scope:"CORE_FIVE_LAUNCHD_REGISTRATIONS_ONLY_AUXILIARY_JOBS_EXCLUDED",completed_labels:vec![],boundary_label:None,uncertain_command_effects:false,
        complete:false,readiness:"UNKNOWN_RUNTIME_AND_FULL_INSTALLATION_READINESS",qualified:false}
}
fn bind(env:&Env,checked:&CheckedDeploymentTarget)->EnclaveResult<()> {
    bind_target(env,checked.target())
}
fn bind_target(env:&Env,target:&deployment::DeploymentTarget)->EnclaveResult<()> {
    if env.dev || env.profile!=target.profile || env.socket_dir!=target.layout.socket_root
        || env.state_dir!=target.layout.state_root || env.audit_dir!=target.layout.audit_root {
        fail!(EACCES,"DEPLOYMENT_LIFECYCLE_CONTEXT_MISMATCH");
    }
    Ok(())
}
fn native_selection(env:&Env,checked:&CheckedDeploymentTarget)->EnclaveResult<()> {
    if !cfg!(target_os="macos") {fail!(ENOSYS,"DEPLOYMENT_LIFECYCLE_NATIVE_REQUIRED");}
    if unsafe {libc::geteuid()}!=0 {fail!(EPERM,"DEPLOYMENT_LIFECYCLE_ROOT_REQUIRED");}
    let selected=deployment::selected().ok_or_else(||err!(EACCES,"DEPLOYMENT_CONTEXT_REQUIRED"))?;
    if selected.config_path()!=checked.config_path() || selected.descriptor_sha256()!=checked.descriptor_sha256()
        || selected.target()!=checked.target() {fail!(EACCES,"DEPLOYMENT_LIFECYCLE_CONTEXT_MISMATCH");}
    bind(env,checked)
}
fn commands(checked:&CheckedDeploymentTarget,action:CoreAction)->Vec<CoreCommand> {
    commands_for_target(checked.target(),action)
}
fn commands_for_target(target:&deployment::DeploymentTarget,action:CoreAction)->Vec<CoreCommand> {
    let namespace=&target.layout.launchd_namespace;
    let mut order=START_ORDER.to_vec();if action==CoreAction::Stop {order.reverse();}
    order.into_iter().map(|daemon| {
        let label=format!("{namespace}.{}",daemon.plist_suffix());
        let plist=Path::new(INSTALLED_PLISTS).join(format!("{label}.plist"));CoreCommand {action,label,plist}
    }).collect()
}
fn operate(checked:&CheckedDeploymentTarget,action:CoreAction,runner:&mut dyn CoreRunner,
    revalidate:&mut impl FnMut()->EnclaveResult<()>,until:Instant)->LifecycleResult {
    operate_commands(receipt(checked,action),commands(checked,action),runner,revalidate,until)
}
fn operate_commands(mut result:CoreLifecycleReceipt,commands:Vec<CoreCommand>,runner:&mut dyn CoreRunner,
    revalidate:&mut impl FnMut()->EnclaveResult<()>,until:Instant)->LifecycleResult {
    for command in commands {
        result.boundary_label=Some(command.label.clone());
        let attempt=(|| {
            if Instant::now()>=until {fail!(ETIMEDOUT,"DEPLOYMENT_LIFECYCLE_TIMEOUT");}
            revalidate()?;
            if Instant::now()>=until {fail!(ETIMEDOUT,"DEPLOYMENT_LIFECYCLE_TIMEOUT");}
            let deadline=until.min(Instant::now()+COMMAND_LIMIT);
            result.uncertain_command_effects=true;
            runner.run(&command,deadline)?;
            result.uncertain_command_effects=false;
            // A successful tool result may already have changed registration.
            // Record that prefix BEFORE any later descriptor/context refusal.
            result.completed_labels.push(command.label.clone());
            if Instant::now()>deadline {fail!(ETIMEDOUT,"DEPLOYMENT_LIFECYCLE_TIMEOUT");}
            revalidate()?;Ok(())
        })();
        if let Err(error)=attempt {return Err(CoreLifecycleFailure {error,receipt:result});}
    }
    result.boundary_label=None;result.complete=true;Ok(result)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Stamp {dev:u64,ino:u64,uid:u32,gid:u32,mode:u32,links:u64,size:u64,mtime:i64,mtime_ns:i64,ctime:i64,ctime_ns:i64}
fn stamp(m:&Metadata)->Stamp {Stamp {dev:m.dev(),ino:m.ino(),uid:m.uid(),gid:m.gid(),mode:m.mode(),links:m.nlink(),size:m.len(),
    mtime:m.mtime(),mtime_ns:m.mtime_nsec(),ctime:m.ctime(),ctime_ns:m.ctime_nsec()}}
fn protected(m:&Metadata)->bool {m.uid()==0 && m.mode()&0o022==0}
fn read_only_flags(file:&File)->EnclaveResult<()> {
    let status=unsafe {libc::fcntl(file.as_raw_fd(),libc::F_GETFL)};
    let descriptor=unsafe {libc::fcntl(file.as_raw_fd(),libc::F_GETFD)};
    if status<0 || status&libc::O_ACCMODE!=libc::O_RDONLY || status&libc::O_NONBLOCK==0
        || descriptor<0 || descriptor&libc::FD_CLOEXEC==0 {
        fail!(ESTALE,"DEPLOYMENT_LIFECYCLE_DESCRIPTOR_FLAGS");
    }
    Ok(())
}
fn native_acl(file:&File)->EnclaveResult<()> {
    #[cfg(target_os="macos")]
    {crate::native_fs::require_no_extended_acl(file)}
    // Portable owner/mode software fixtures are not native ACL evidence. All
    // actual macOS callers above use the strict branch, without an opt-in flag.
    #[cfg(not(target_os="macos"))]
    {let _=file;Ok(())}
}
fn leaf(path:&Path)->EnclaveResult<CString> {
    CString::new(path.file_name().ok_or_else(||err!(EINVAL,"DEPLOYMENT_LIFECYCLE_PATH"))?.as_bytes())
        .map_err(|_|err!(EINVAL,"DEPLOYMENT_LIFECYCLE_PATH"))
}
fn opened(fd:i32)->EnclaveResult<File> {
    if fd<0 {fail!(EACCES,"DEPLOYMENT_LIFECYCLE_PROTECTION");}
    Ok(unsafe {File::from_raw_fd(fd)})
}
struct Directory {file:File,observed:Stamp}
pub(crate) struct HeldPaths {directories:BTreeMap<PathBuf,Directory>}
impl HeldPaths {
    // macOS always enforces native ACL absence. NonmacOS use is restricted to
    // the existing portable owner/mode software scope, not native protection.
    pub(crate) fn new()->EnclaveResult<Self> {
        let file=opened(unsafe {libc::open(b"/\0".as_ptr().cast(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)})?;
        let m=file.metadata().map_err(|_|err!(EIO,"DEPLOYMENT_LIFECYCLE_STAT"))?;
        if !m.is_dir() || !protected(&m) {fail!(EACCES,"DEPLOYMENT_LIFECYCLE_PROTECTION");}
        read_only_flags(&file)?;native_acl(&file)?;
        Ok(Self {directories:BTreeMap::from([(PathBuf::from("/"),Directory {file,observed:stamp(&m)})])})
    }
    /// Explicit native-root constructor for callers requiring native evidence.
    /// Other platforms refuse rather than returning the portable fixture view.
    pub(crate) fn new_native_acl_protected()->EnclaveResult<Self> {
        if !cfg!(target_os="macos") {fail!(ENOSYS,"NATIVE_ACL_UNSUPPORTED");}
        if unsafe {libc::geteuid()}!=0 {fail!(EPERM,"DEPLOYMENT_LIFECYCLE_ROOT_REQUIRED");}
        Self::new()
    }
    pub(crate) fn hold_directory(&mut self,path:&Path,expected:Option<(u32,u32,u32)>)->EnclaveResult<()> {
        let path=if path==Path::new("/") {path.to_owned()} else {normalized_path(path)?};
        if path.components().count()>MAX_ANCESTORS {fail!(E2BIG,"DEPLOYMENT_LIFECYCLE_PATH");}
        self.revalidate()?;
        if !self.directories.contains_key(&path) {
            if self.directories.len()>=MAX_HELD_DIRECTORIES {fail!(E2BIG,"DEPLOYMENT_LIFECYCLE_PATH");}
            let parent=path.parent().ok_or_else(||err!(EINVAL,"DEPLOYMENT_LIFECYCLE_PATH"))?;
            if parent!=Path::new("/") {self.hold_directory(parent,None)?;}
            if self.directories.len()>=MAX_HELD_DIRECTORIES {fail!(E2BIG,"DEPLOYMENT_LIFECYCLE_PATH");}
            let pfd=self.directories.get(parent).ok_or_else(||err!(EACCES,"DEPLOYMENT_LIFECYCLE_PROTECTION"))?.file.as_raw_fd();
            let file=opened(unsafe {libc::openat(pfd,leaf(&path)?.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)})?;
            let m=file.metadata().map_err(|_|err!(EIO,"DEPLOYMENT_LIFECYCLE_STAT"))?;
            if !m.is_dir() {fail!(EACCES,"DEPLOYMENT_LIFECYCLE_PROTECTION");}
            if let Some((uid,gid,mode))=expected {
                if m.uid()!=uid || m.gid()!=gid || m.mode()&0o7777!=mode {fail!(EACCES,"DEPLOYMENT_LIFECYCLE_RUNTIME_IDENTITY");}
            } else if !protected(&m) {fail!(EACCES,"DEPLOYMENT_LIFECYCLE_PROTECTION");}
            // Refusal must not leave an unsafe directory cached as an admitted
            // original; validate protection and ACL before insertion.
            read_only_flags(&file)?;native_acl(&file)?;
            self.directories.insert(path.clone(),Directory {file,observed:stamp(&m)});
        }
        let d=&self.directories[&path];let m=d.file.metadata().map_err(|_|err!(EIO,"DEPLOYMENT_LIFECYCLE_STAT"))?;
        if let Some((uid,gid,mode))=expected {
            if m.uid()!=uid || m.gid()!=gid || m.mode()&0o7777!=mode {fail!(EACCES,"DEPLOYMENT_LIFECYCLE_RUNTIME_IDENTITY");}
        } else if !protected(&m) {fail!(EACCES,"DEPLOYMENT_LIFECYCLE_PROTECTION");}
        read_only_flags(&d.file)?;native_acl(&d.file)?;
        self.revalidate()
    }
    pub(crate) fn revalidate(&self)->EnclaveResult<()> {
        for (path,directory) in &self.directories {
            let m=directory.file.metadata().map_err(|_|err!(EIO,"DEPLOYMENT_LIFECYCLE_STAT"))?;
            let s=stamp(&m);let old=&directory.observed;
            if !m.is_dir() || (s.dev,s.ino,s.uid,s.gid,s.mode)!=(old.dev,old.ino,old.uid,old.gid,old.mode) {
                fail!(ESTALE,"DEPLOYMENT_LIFECYCLE_DIRECTORY_CHANGED");
            }
            read_only_flags(&directory.file)?;native_acl(&directory.file)?;
            if path==Path::new("/") {continue;}
            let parent=&self.directories[path.parent().ok_or_else(||err!(EINVAL,"DEPLOYMENT_LIFECYCLE_PATH"))?];
            let file=opened(unsafe {libc::openat(parent.file.as_raw_fd(),leaf(path)?.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)})?;
            read_only_flags(&file)?;native_acl(&file)?;
            let fresh=stamp(&file.metadata().map_err(|_|err!(EIO,"DEPLOYMENT_LIFECYCLE_STAT"))?);
            if (fresh.dev,fresh.ino,fresh.uid,fresh.gid,fresh.mode)!=(old.dev,old.ino,old.uid,old.gid,old.mode) {
                fail!(ESTALE,"DEPLOYMENT_LIFECYCLE_DIRECTORY_CHANGED");
            }
        }
        Ok(())
    }
    /// Recheck original/named metadata, ACL and flags for a concrete file set.
    /// Complete held ancestry is checked once before and after the set. This
    /// does not rehash contents and cannot replace a full admission/final hash.
    pub(crate) fn revalidate_files_metadata(&self,files:&[&HeldFile])->EnclaveResult<()> {
        let mut first=self.revalidate().err();
        // These are read-only observations. A refusal must not skip the other
        // retained files or the final ancestry observation.
        for file in files {
            if let Err(error)=file.revalidate_inode_metadata(self) {if first.is_none(){first=Some(error);}}
        }
        if let Err(error)=self.revalidate() {if first.is_none(){first=Some(error);}}
        first.map_or(Ok(()),Err)
    }
}
pub(crate) struct HeldFile {path:PathBuf,file:File,observed:Stamp,sha256:String,maximum:u64}
fn hash_file(file:&File,maximum:u64)->EnclaveResult<(String,Vec<u8>)> {
    read_only_flags(file)?;native_acl(file)?;
    let length=file.metadata().map_err(|_|err!(EIO,"DEPLOYMENT_LIFECYCLE_STAT"))?.len();
    if length==0 || length>maximum {fail!(E2BIG,"DEPLOYMENT_LIFECYCLE_FILE_SIZE");}
    let mut digest=Sha256::new();let mut offset=0u64;let mut buffer=[0u8;65536];
    let mut bytes=Vec::new();
    while offset<=maximum {
        let count=file.read_at(&mut buffer,offset).map_err(|_|err!(EIO,"DEPLOYMENT_LIFECYCLE_READ"))?;
        if count==0 {break;}
        offset=offset.checked_add(count as u64).ok_or_else(||err!(E2BIG,"DEPLOYMENT_LIFECYCLE_FILE_SIZE"))?;
        if offset>maximum {fail!(E2BIG,"DEPLOYMENT_LIFECYCLE_FILE_SIZE");}
        digest.update(&buffer[..count]);if maximum<=MAX_PUBLIC {bytes.extend_from_slice(&buffer[..count]);}
    }
    if offset!=length {fail!(ESTALE,"DEPLOYMENT_LIFECYCLE_FILE_CHANGED");}
    read_only_flags(file)?;native_acl(file)?;
    Ok((hex::encode(digest.finalize()),bytes))
}
impl HeldFile {
    // Trusted selected-lifecycle siblings can inspect the same read-only held
    // inode. No mutable descriptor, raw FD or public construction is exposed.
    pub(crate) fn path(&self)->&Path {&self.path}
    pub(crate) fn file(&self)->&File {&self.file}
    pub(crate) fn sha256(&self)->&str {&self.sha256}
    pub(crate) fn size(&self)->u64 {self.observed.size}
    pub(crate) fn open(paths:&mut HeldPaths,path:&Path,maximum:u64,mode:Option<u32>)->EnclaveResult<(Self,Vec<u8>)> {
        let path=normalized_path(path)?;let parent=path.parent().ok_or_else(||err!(EINVAL,"DEPLOYMENT_LIFECYCLE_PATH"))?;
        paths.hold_directory(parent,None)?;
        let file=opened(unsafe {libc::openat(paths.directories[parent].file.as_raw_fd(),leaf(&path)?.as_ptr(),libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)})?;
        let m=file.metadata().map_err(|_|err!(EIO,"DEPLOYMENT_LIFECYCLE_STAT"))?;
        if !m.is_file() || !protected(&m) || m.nlink()!=1 || mode.is_some_and(|mode|m.gid()!=0 || m.mode()&0o7777!=mode) {
            fail!(EACCES,"DEPLOYMENT_LIFECYCLE_PROTECTION");
        }
        let observed=stamp(&m);let (sha256,bytes)=hash_file(&file,maximum)?;
        let held=Self {path,file,observed,sha256,maximum};held.revalidate(paths)?;Ok((held,bytes))
    }
    pub(crate) fn revalidate(&self,paths:&HeldPaths)->EnclaveResult<()> {
        self.revalidate_metadata(paths)?;
        let hashed=hash_file(&self.file,self.maximum).and_then(|(actual,_)| {
            if actual!=self.sha256 {fail!(ESTALE,"DEPLOYMENT_LIFECYCLE_FILE_CHANGED");}Ok(())
        });
        // Recheck metadata/ACL/names even when the data read itself refused;
        // preserve that original read/hash error as the primary refusal.
        let current=self.revalidate_metadata(paths);
        hashed?;current
    }
    /// Original/named identity, protection, size, timestamps, ACL and flags only.
    /// Contents still require full revalidate at the actual admission boundary.
    pub(crate) fn revalidate_metadata(&self,paths:&HeldPaths)->EnclaveResult<()> {
        paths.revalidate_files_metadata(&[self])
    }
    fn revalidate_inode_metadata(&self,paths:&HeldPaths)->EnclaveResult<()> {
        read_only_flags(&self.file)?;native_acl(&self.file)?;
        let m=self.file.metadata().map_err(|_|err!(EIO,"DEPLOYMENT_LIFECYCLE_STAT"))?;
        if stamp(&m)!=self.observed {fail!(ESTALE,"DEPLOYMENT_LIFECYCLE_FILE_CHANGED");}
        let parent=paths.directories.get(self.path.parent().ok_or_else(||err!(EINVAL,"DEPLOYMENT_LIFECYCLE_PATH"))?)
            .ok_or_else(||err!(EACCES,"DEPLOYMENT_LIFECYCLE_PROTECTION"))?;
        let fresh=opened(unsafe {libc::openat(parent.file.as_raw_fd(),leaf(&self.path)?.as_ptr(),libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)})?;
        read_only_flags(&fresh)?;native_acl(&fresh)?;
        if stamp(&fresh.metadata().map_err(|_|err!(EIO,"DEPLOYMENT_LIFECYCLE_STAT"))?)!=self.observed {
            fail!(ESTALE,"DEPLOYMENT_LIFECYCLE_FILE_CHANGED");
        }
        read_only_flags(&self.file)?;native_acl(&self.file)?;
        if stamp(&self.file.metadata().map_err(|_|err!(EIO,"DEPLOYMENT_LIFECYCLE_STAT"))?)!=self.observed {
            fail!(ESTALE,"DEPLOYMENT_LIFECYCLE_FILE_CHANGED");
        }
        Ok(())
    }
}

struct DescriptorBinding {paths:HeldPaths,descriptor:HeldFile}
impl DescriptorBinding {
    fn open(config_path:&Path,descriptor_sha256:&str)->EnclaveResult<Self> {
        let mut paths=HeldPaths::new()?;
        let (descriptor,_)=HeldFile::open(&mut paths,config_path,65536,None)?;
        if descriptor.sha256!=descriptor_sha256 {fail!(ESTALE,"DEPLOYMENT_CHANGED");}
        Ok(Self {paths,descriptor})
    }
    fn revalidate(&self,descriptor_sha256:&str)->EnclaveResult<()> {
        self.descriptor.revalidate(&self.paths)?;
        if self.descriptor.sha256!=descriptor_sha256 {fail!(ESTALE,"DEPLOYMENT_CHANGED");}
        Ok(())
    }
}
struct PreparedStart {
    paths:HeldPaths,
    files:BTreeMap<PathBuf,HeldFile>,
    descriptor:HeldFile,
    inventory:HeldFile,
    pins:HeldFile,
    layout:crate::launchd::Layout,
    requirements:BTreeMap<DaemonId,CodeRequirement>,
}
fn hold_copy(paths:&mut HeldPaths,files:&mut BTreeMap<PathBuf,HeldFile>,
    plan:&crate::deploy::target_plan::TargetInstallPlan,destination:&Path)->EnclaveResult<()> {
    let destination=normalized_path(destination)?;
    if files.contains_key(&destination) {return Ok(());}
    let copy=plan.copies.iter().find(|copy|normalized_path(&copy.destination).ok().as_ref()==Some(&destination))
        .ok_or_else(||err!(EACCES,"DEPLOYMENT_LIFECYCLE_INVENTORY_MISSING"))?;
    let mode=u32::from_str_radix(&copy.mode,8).map_err(|_|err!(EINVAL,"DEPLOYMENT_LIFECYCLE_INVENTORY_MODE"))?;
    if copy.uid!=0 || copy.gid!=0 {fail!(EACCES,"DEPLOYMENT_LIFECYCLE_INVENTORY_MODE");}
    let maximum=if mode==0o755 {MAX_CODE}else{MAX_PUBLIC};
    let (file,_)=HeldFile::open(paths,&destination,maximum,Some(mode))?;
    if file.sha256!=copy.sha256 || file.observed.size!=copy.size {fail!(ESTALE,"DEPLOYMENT_LIFECYCLE_INSTALLED_HASH");}
    files.insert(destination,file);Ok(())
}
fn exact_bytes(paths:&mut HeldPaths,files:&mut BTreeMap<PathBuf,HeldFile>,
    plan:&crate::deploy::target_plan::TargetInstallPlan,path:&Path,expected:&[u8])->EnclaveResult<()> {
    hold_copy(paths,files,plan,path)?;
    let path=normalized_path(path)?;let file=&files[&path];
    if file.observed.mode&0o7777!=0o644 || hash_file(&file.file,MAX_PUBLIC)?.1!=expected {
        fail!(EACCES,"DEPLOYMENT_LIFECYCLE_RENDERER_MISMATCH");
    }
    file.revalidate(paths)
}
impl PreparedStart {
    fn open(env:&Env,checked:&CheckedDeploymentTarget)->EnclaveResult<Self> {
        bind(env,checked)?;
        deployment::upgrade::assert_start_allowed(checked)?;
        if env.profile==Profile::L3 && codesign::TEAM_ID.is_empty() {fail!(EACCES,"L3_REQUIRES_TEAM_ID");}
        let target=checked.target();
        let mut paths=HeldPaths::new()?;
        let (descriptor,_)=HeldFile::open(&mut paths,checked.config_path(),65536,None)?;
        if descriptor.sha256!=checked.descriptor_sha256() {fail!(ESTALE,"DEPLOYMENT_CHANGED");}
        let (inventory,inventory_bytes)=HeldFile::open(&mut paths,&target.expected_artifacts_manifest,MAX_PUBLIC,None)?;
        let plan=crate::deploy::target_plan::describe(target,checked.descriptor_sha256(),&inventory_bytes)?;
        let (pins,pin_bytes)=HeldFile::open(&mut paths,&target.codesign_pins_file,MAX_PUBLIC,None)?;
        if pins.sha256!=plan.candidate_codesign_pins_sha256 {fail!(ESTALE,"DEPLOYMENT_LIFECYCLE_PIN_CUTOVER_REQUIRED");}
        let pin_map=codesign::pins::parse(&pin_bytes)?;
        let layout=crate::launchd::Layout::for_target(checked.clone())?;
        let mut files=BTreeMap::new();
        // Public authority bytes cannot change under a successful start prefix.
        let authority=normalized_path(&target.authority_config)?;
        let (authority_file,_)=HeldFile::open(&mut paths,&authority,MAX_PUBLIC,None)?;
        files.insert(authority,authority_file);
        if let Some(broker)=&target.broker {
            let (file,_)=HeldFile::open(&mut paths,&broker.tuf_root_file,4*MAX_PUBLIC,None)?;
            files.insert(file.path.clone(),file);
        }
        let mut requirements=BTreeMap::new();
        for daemon in START_ORDER {
            let label=format!("{}.{}",target.layout.launchd_namespace,daemon.plist_suffix());
            exact_bytes(&mut paths,&mut files,&plan,&Path::new(INSTALLED_PLISTS).join(format!("{label}.plist")),
                crate::launchd::plist(daemon,&layout).as_bytes())?;
            exact_bytes(&mut paths,&mut files,&plan,&target.layout.sandbox_dir.join(format!("{}.sb",daemon.plist_suffix())),
                crate::launchd::sandbox_profile(daemon,&layout).as_bytes())?;
            hold_copy(&mut paths,&mut files,&plan,Path::new(&crate::launchd::program(daemon,&layout)))?;
            let identifier=daemon.launchd_label();
            let hashes=pin_map.get(&identifier).filter(|hashes|!hashes.is_empty())
                .ok_or_else(||err!(EACCES,"CODESIGN_PINS_MISSING"))?.clone();
            // No global/cached requirement constructor or candidate-pin union.
            requirements.insert(daemon,CodeRequirement {identifier,team_id:codesign::TEAM_ID.into(),cdhash_allowlist:hashes});
        }
        let bundle=normalized_path(&target.layout.custody_bundle)?;
        for member in ["Contents/Info.plist","Contents/_CodeSignature/CodeResources"] {
            hold_copy(&mut paths,&mut files,&plan,&bundle.join(member))?;
        }
        for copy in &plan.copies {
            if normalized_path(&copy.destination)?.starts_with(&bundle) {
                hold_copy(&mut paths,&mut files,&plan,&copy.destination)?;
            }
        }
        for root in [&target.layout.socket_root,&target.layout.state_root,&target.layout.audit_root] {
            paths.hold_directory(root,Some((0,0,0o755)))?;
        }
        for daemon in START_ORDER {
            paths.hold_directory(&target.layout.socket_root.join(daemon.dir_name()),Some((daemon.uid(),daemon.client_gid(),0o2750)))?;
            paths.hold_directory(&target.layout.state_root.join(daemon.dir_name()),Some((daemon.uid(),daemon.gid(),0o700)))?;
            paths.hold_directory(&target.layout.audit_root.join(daemon.dir_name()),Some((daemon.uid(),crate::launchd::JOURNAL_READ_GID,0o2750)))?;
        }
        paths.hold_directory(&target.layout.cas_store_root,Some((702,8702,0o700)))?;
        paths.hold_directory(&target.layout.socket_root.join(enclave_core::daemon::WITNESS_SOCKET_DIR),
            Some((705,enclave_core::daemon::WITNESS_CLIENT_GID,0o2750)))?;
        let result=Self {paths,files,descriptor,inventory,pins,layout,requirements};
        result.revalidate(checked)?;Ok(result)
    }
    fn revalidate(&self,checked:&CheckedDeploymentTarget)->EnclaveResult<()> {
        deployment::upgrade::assert_start_allowed(checked)?;
        self.descriptor.revalidate(&self.paths)?;
        if self.descriptor.sha256!=checked.descriptor_sha256() {fail!(ESTALE,"DEPLOYMENT_CHANGED");}
        self.inventory.revalidate(&self.paths)?;self.pins.revalidate(&self.paths)?;
        let inventory=checked.read_artifact_inventory()?;
        if hex::encode(Sha256::digest(&inventory))!=self.inventory.sha256 {fail!(ESTALE,"DEPLOYMENT_LIFECYCLE_INVENTORY_CHANGED");}
        self.layout.validate()?;
        for file in self.files.values() {file.revalidate(&self.paths)?;}
        self.paths.revalidate()
    }
    fn verify_codes(&self,checked:&CheckedDeploymentTarget,verifier:&mut dyn CoreCodeVerifier,until:Instant)->EnclaveResult<()> {
        for daemon in START_ORDER {
            if Instant::now()>=until {fail!(ETIMEDOUT,"DEPLOYMENT_LIFECYCLE_TIMEOUT");}
            self.revalidate(checked)?;
            let executable_path=normalized_path(Path::new(&crate::launchd::program(daemon,&self.layout)))?;
            let executable=&self.files[&executable_path];
            let code_path=if daemon==DaemonId::CustodyVault {normalized_path(&checked.target().layout.custody_bundle)?}else{executable_path.clone()};
            let members=self.files.values().filter(|file|daemon==DaemonId::CustodyVault
                && file.path.starts_with(&code_path) && file.path!=executable_path)
                .map(|file|CoreResourceView {path:&file.path,file:&file.file,sha256:&file.sha256,size:file.observed.size}).collect();
            let revalidate=||self.revalidate(checked);
            let view=CoreCodeView {code_path:&code_path,executable_path:&executable_path,executable:&executable.file,
                executable_sha256:&executable.sha256,executable_size:executable.observed.size,members,revalidate:&revalidate};
            verifier.verify(daemon,&view,&self.requirements[&daemon],until)?;
            if Instant::now()>=until {fail!(ETIMEDOUT,"DEPLOYMENT_LIFECYCLE_TIMEOUT");}
            self.revalidate(checked)?;
        }
        Ok(())
    }
}

/// Start the selected core five only after every native/protected precheck.
/// Requires actual selection and trusted concrete verifier/runner adapters.
pub(crate) fn start_core(env:&Env,checked:&CheckedDeploymentTarget,verifier:&mut dyn CoreCodeVerifier,runner:&mut dyn CoreRunner)->LifecycleResult {
    let until=Instant::now()+OPERATION_LIMIT;
    let prepared=(|| {native_selection(env,checked)?;let prepared=PreparedStart::open(env,checked)?;
        prepared.verify_codes(checked,verifier,until)?;Ok(prepared)})();
    let prepared=match prepared {Ok(prepared)=>prepared,Err(error)=>return Err(CoreLifecycleFailure {error,receipt:receipt(checked,CoreAction::Start)})};
    operate(checked,CoreAction::Start,runner,&mut ||prepared.revalidate(checked),until)
}
/// Deactivate only the explicit teardown target's core labels after admission,
/// expiry or pin loss. The real native-root teardown capability rechecks only
/// the protected descriptor; no general selection or current signing mode is
/// required. Inventory, authority, pins, installed plist, state, runtime and
/// sockets are never read, and no target PID is signaled. The caller must retain
/// cooperative maintenance exclusion across these checks and registration effects.
pub(crate) fn stop_core(env:&Env,teardown:&TeardownDeploymentTarget,runner:&mut dyn CoreRunner)->LifecycleResult {
    let until=Instant::now()+OPERATION_LIMIT;
    let binding=(|| {
        teardown.recheck()?;bind_target(env,teardown.target())?;
        DescriptorBinding::open(teardown.config_path(),teardown.descriptor_sha256())
    })();
    let binding=match binding {Ok(binding)=>binding,Err(error)=>return Err(CoreLifecycleFailure {error,
        receipt:receipt_for_target(teardown.target(),teardown.descriptor_sha256(),CoreAction::Stop)})};
    operate_commands(receipt_for_target(teardown.target(),teardown.descriptor_sha256(),CoreAction::Stop),
        commands_for_target(teardown.target(),CoreAction::Stop),runner,&mut || {
            teardown.recheck()?;bind_target(env,teardown.target())?;
            binding.revalidate(teardown.descriptor_sha256())
        },until)
}

#[cfg(test)]
mod tests {
    use super::*;
    use deployment::{DeploymentLayout,DeploymentRole,DeploymentSigningMode,DeploymentTarget};
    use std::os::unix::fs::{DirBuilderExt,PermissionsExt};
    fn target(root:&Path)->DeploymentTarget {
        DeploymentTarget {version:1,target_id:"core-lifecycle".into(),role:DeploymentRole::ExistingUpgrade,profile:Profile::L2,
            authority_config:root.join("support/authority.json"),expected_artifacts_manifest:root.join("support/artifacts.json"),
            codesign_pins_file:root.join("support/pins.json"),signing_identity_mode:match codesign::signing_mode() {
                codesign::SigningMode::LocalPins=>DeploymentSigningMode::LocalPins,codesign::SigningMode::TeamId=>DeploymentSigningMode::TeamId},
            layout:DeploymentLayout {binary_dir:root.join("bin"),custody_bundle:root.join("support/Custody.app"),
                sandbox_dir:root.join("sandbox"),socket_root:root.join("run"),state_root:root.join("state"),audit_root:root.join("audit"),
                cas_store_root:root.join("cas"),staging_root:root.join("stage"),support_root:root.join("support"),
                launchd_namespace:"com.depot.lifecycle-core".into(),mach_service:"com.depot.lifecycle-core.exception".into()},
            broker:None,shared_read_only_inputs:vec![]}
    }
    fn env(target:&DeploymentTarget)->Env {Env {dev:false,profile:target.profile,state_dir:target.layout.state_root.clone(),
        audit_dir:target.layout.audit_root.clone(),socket_dir:target.layout.socket_root.clone()}}
    fn test_receipt(action:CoreAction)->CoreLifecycleReceipt {
        CoreLifecycleReceipt {target_id:"core-lifecycle".into(),descriptor_sha256:"a".repeat(64),action,
            scope:"CORE_FIVE_LAUNCHD_REGISTRATIONS_ONLY_AUXILIARY_JOBS_EXCLUDED",completed_labels:vec![],boundary_label:None,
            uncertain_command_effects:false,complete:false,readiness:"UNKNOWN_RUNTIME_AND_FULL_INSTALLATION_READINESS",qualified:false}
    }
    #[derive(Default)]
    struct Runner {labels:Vec<String>,fail_at:Option<usize>}
    impl CoreRunner for Runner {
        fn run(&mut self,query:&CoreCommand,deadline:Instant)->EnclaveResult<()> {
            assert!(deadline<=Instant::now()+COMMAND_LIMIT);assert!(deadline>Instant::now());
            self.labels.push(query.label().into());
            if self.fail_at==Some(self.labels.len()) {Err(err!(EIO,"TEST_COMMAND_UNCERTAIN"))}else{Ok(())}
        }
    }
    #[test]
    fn commands_are_closed_exact_core_five_and_stop_reverses_start_without_auxiliaries() {
        let target=target(Path::new("/unopened-lifecycle-fixture"));target.validate().unwrap();
        for action in [CoreAction::Start,CoreAction::Stop] {
            let queries=commands_for_target(&target,action);assert_eq!(queries.len(),5);
            let mut order=START_ORDER.to_vec();if action==CoreAction::Stop {order.reverse();}
            for (query,daemon) in queries.iter().zip(order) {
                let label=format!("{}.{}",target.layout.launchd_namespace,daemon.plist_suffix());assert_eq!(query.label(),label);
                let command=query.command();assert_eq!(command.get_program(),"/bin/launchctl");assert_eq!(command.get_current_dir(),Some(Path::new("/")));
                let args=command.get_args().map(|v|v.to_string_lossy().into_owned()).collect::<Vec<_>>();
                assert_eq!(args,if action==CoreAction::Start {vec!["bootstrap".to_owned(),"system".into(),format!("/Library/LaunchDaemons/{label}.plist")]}
                    else {vec!["bootout".to_owned(),format!("system/{label}")]});
                let environment=command.get_envs().collect::<Vec<_>>();
                assert!(environment.iter().any(|(key,value)|*key=="LC_ALL" && *value==Some(std::ffi::OsStr::new("C"))));
                assert!(environment.iter().any(|(key,value)|*key=="PATH" && *value==Some(std::ffi::OsStr::new(crate::syscmd::SAFE_PATH))));
            }
            for auxiliary in ["supervisor","hydrate","browser","gateway","intent","oidc-broker","apfs-broker"] {
                assert!(!queries.iter().any(|query|query.label.ends_with(&format!(".{auxiliary}"))));
            }
        }
    }
    #[test]
    fn every_environment_route_and_profile_are_bound_without_io() {
        let target=target(Path::new("/unopened-lifecycle-fixture"));let valid=env(&target);
        bind_target(&valid,&target).unwrap();
        // The protected capability is not manufactured for pure routing tests.
        for slot in 0..5 {
            let mut wrong=valid.clone();match slot {0=>wrong.dev=true,1=>wrong.profile=Profile::L3,
                2=>wrong.socket_dir="/var/run/enclave".into(),3=>wrong.state_dir="/var/db/enclave".into(),_=>wrong.audit_dir="/var/log/enclave".into()}
            assert!(bind_target(&wrong,&target).unwrap_err().is("DEPLOYMENT_LIFECYCLE_CONTEXT_MISMATCH"));
        }
    }
    #[test]
    fn command_errors_retain_completed_prefix_and_mark_current_effects_uncertain() {
        let target=target(Path::new("/unopened-lifecycle-fixture"));
        for action in [CoreAction::Start,CoreAction::Stop] {for fail_at in 1..=5 {
            let mut runner=Runner {fail_at:Some(fail_at),..Default::default()};let mut checks=0;
            let error=operate_commands(test_receipt(action),commands_for_target(&target,action),&mut runner,&mut || {checks+=1;Ok(())},
                Instant::now()+OPERATION_LIMIT).unwrap_err();
            assert!(error.error.is("TEST_COMMAND_UNCERTAIN"));assert_eq!(error.receipt.completed_labels,runner.labels[..fail_at-1]);
            assert_eq!(error.receipt.boundary_label.as_ref(),runner.labels.last());assert!(error.receipt.uncertain_command_effects);
            assert!(!error.receipt.complete && !error.receipt.qualified);assert_eq!(checks,2*fail_at-1);
        }}
    }
    #[test]
    fn context_refusal_before_or_after_each_command_never_rolls_back_a_known_prefix() {
        let target=target(Path::new("/unopened-lifecycle-fixture"));
        for cut in 1..=10 {
            let mut runner=Runner::default();let mut checks=0;
            let error=operate_commands(test_receipt(CoreAction::Start),commands_for_target(&target,CoreAction::Start),&mut runner,&mut || {
                checks+=1;if checks==cut {Err(err!(ESTALE,"TEST_CONTEXT_CHANGED"))}else{Ok(())}
            },Instant::now()+OPERATION_LIMIT).unwrap_err();
            assert!(error.error.is("TEST_CONTEXT_CHANGED"));assert_eq!(runner.labels.len(),cut/2);
            assert_eq!(error.receipt.completed_labels,runner.labels);assert!(!error.receipt.uncertain_command_effects);
            assert!(!error.receipt.complete && !error.receipt.qualified);assert_eq!(checks,cut);
        }
    }
    #[test]
    fn expired_operation_refuses_before_any_runner_or_context_call() {
        let target=target(Path::new("/unopened-lifecycle-fixture"));let mut runner=Runner::default();
        let error=operate_commands(test_receipt(CoreAction::Stop),commands_for_target(&target,CoreAction::Stop),&mut runner,
            &mut ||panic!("no context read after expired operation"),Instant::now()).unwrap_err();
        assert!(error.error.is("DEPLOYMENT_LIFECYCLE_TIMEOUT"));assert!(runner.labels.is_empty());assert!(error.receipt.completed_labels.is_empty());
        assert!(!error.receipt.uncertain_command_effects && !error.receipt.complete);
    }
    #[test]
    fn successful_registration_receipt_does_not_claim_process_health_or_full_installation() {
        let target=target(Path::new("/unopened-lifecycle-fixture"));let mut runner=Runner::default();
        let result=operate_commands(test_receipt(CoreAction::Start),commands_for_target(&target,CoreAction::Start),&mut runner,
            &mut ||Ok(()),Instant::now()+OPERATION_LIMIT).unwrap();
        assert!(result.complete);assert_eq!(result.completed_labels.len(),5);assert!(result.boundary_label.is_none());
        assert!(!result.uncertain_command_effects && !result.qualified);assert!(result.scope.contains("AUXILIARY_JOBS_EXCLUDED"));
        assert!(result.readiness.starts_with("UNKNOWN"));
    }
    #[cfg(not(target_os="macos"))]
    #[test]
    fn explicit_native_held_paths_cannot_use_portable_uid_mode_fixture_policy() {
        assert!(HeldPaths::new_native_acl_protected().err().unwrap().is("NATIVE_ACL_UNSUPPORTED"));
    }
    #[test]
    fn original_read_only_descriptor_nonblock_and_exec_flags_cannot_drift() {
        use std::{fs::OpenOptions,os::unix::fs::OpenOptionsExt};
        let file=OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK|libc::O_CLOEXEC)
            .open(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
        read_only_flags(&file).unwrap();
        let descriptor=unsafe{libc::fcntl(file.as_raw_fd(),libc::F_GETFD)};assert!(descriptor>=0);
        assert_eq!(unsafe{libc::fcntl(file.as_raw_fd(),libc::F_SETFD,descriptor&!libc::FD_CLOEXEC)},0);
        assert!(read_only_flags(&file).unwrap_err().is("DEPLOYMENT_LIFECYCLE_DESCRIPTOR_FLAGS"));
        assert_eq!(unsafe{libc::fcntl(file.as_raw_fd(),libc::F_SETFD,descriptor)},0);read_only_flags(&file).unwrap();
        let status=unsafe{libc::fcntl(file.as_raw_fd(),libc::F_GETFL)};assert!(status>=0);
        assert_eq!(unsafe{libc::fcntl(file.as_raw_fd(),libc::F_SETFL,status&!libc::O_NONBLOCK)},0);
        assert!(read_only_flags(&file).unwrap_err().is("DEPLOYMENT_LIFECYCLE_DESCRIPTOR_FLAGS"));
        assert_eq!(unsafe{libc::fcntl(file.as_raw_fd(),libc::F_SETFL,status)},0);read_only_flags(&file).unwrap();
    }

    struct Fixture {base:PathBuf,checked:CheckedDeploymentTarget}
    impl Fixture {
        fn new()->Self {
            assert_eq!(unsafe {libc::geteuid()},0,"actual private root required");
            let parent=Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
            // External CARGO_TARGET_DIR does not create the compiling checkout's
            // private fixture parent. Tests must not depend on another selector.
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&parent).unwrap();
            let path=parent.join(format!("core-lifecycle-{}",hex::encode(enclave_core::rng::bytes32())));
            std::fs::create_dir(&path).unwrap();std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o755)).unwrap();
            let base=path.canonicalize().unwrap();let target=target(&base);target.validate().unwrap();
            std::fs::create_dir(&target.layout.support_root).unwrap();std::fs::set_permissions(&target.layout.support_root,std::fs::Permissions::from_mode(0o755)).unwrap();
            let config=target.layout.support_root.join("deployment.json");
            for (path,bytes) in [(&config,serde_json::to_vec(&target).unwrap()),(&target.authority_config,b"{}".to_vec()),
                (&target.expected_artifacts_manifest,b"{}".to_vec()),(&target.codesign_pins_file,br#"{"v":1,"pins":{"com.enterprise.enclave.cas":["1111111111111111111111111111111111111111"]}}"#.to_vec())] {
                std::fs::write(path,bytes).unwrap();std::fs::set_permissions(path,std::fs::Permissions::from_mode(0o644)).unwrap();
            }
            let checked=deployment::load(&config).unwrap();Self {base,checked}
        }
        fn write(&self,name:&str,bytes:&[u8],mode:u32)->PathBuf {
            let path=self.base.join(name);std::fs::write(&path,bytes).unwrap();std::fs::set_permissions(&path,std::fs::Permissions::from_mode(mode)).unwrap();path
        }
    }
    impl Drop for Fixture {fn drop(&mut self) {let _=std::fs::remove_dir_all(&self.base);}}
    #[test]
    #[ignore="requires actual protected private-root filesystem"]
    fn stop_descriptor_binding_survives_all_missing_authority_inventory_and_pin_inputs() {
        let fixture=Fixture::new();let checked=&fixture.checked;
        for path in [&checked.target().authority_config,&checked.target().expected_artifacts_manifest,&checked.target().codesign_pins_file] {
            std::fs::remove_file(path).unwrap();
        }
        // Exercise the shared protected descriptor/stop-command inner logic.
        // This does not construct a real native-root teardown capability or
        // claim execution of the public stop_core entry on this test platform.
        assert!(deployment::load(checked.config_path()).is_err());
        let binding=DescriptorBinding::open(checked.config_path(),checked.descriptor_sha256()).unwrap();
        binding.revalidate(checked.descriptor_sha256()).unwrap();
        let mut runner=Runner::default();let mut checks=0;
        let result=operate_commands(receipt_for_target(checked.target(),checked.descriptor_sha256(),CoreAction::Stop),
            commands_for_target(checked.target(),CoreAction::Stop),&mut runner,&mut || {
                checks+=1;binding.revalidate(checked.descriptor_sha256())
            },Instant::now()+OPERATION_LIMIT).unwrap();
        assert!(result.complete);assert_eq!(runner.labels.len(),5);assert_eq!(checks,10);
        assert_eq!(result.target_id,checked.target().target_id);assert_eq!(result.descriptor_sha256,checked.descriptor_sha256());
        let mut bytes=std::fs::read(checked.config_path()).unwrap();bytes.push(b' ');std::fs::write(checked.config_path(),bytes).unwrap();
        assert!(binding.revalidate(checked.descriptor_sha256()).is_err());
    }
    #[test]
    #[ignore="requires actual protected private-root filesystem"]
    fn held_public_inputs_refuse_mode_link_content_name_and_ancestor_changes() {
        let fixture=Fixture::new();let file=fixture.write("public.json",b"original",0o644);
        let mut paths=HeldPaths::new().unwrap();let (held,raw)=HeldFile::open(&mut paths,&file,MAX_PUBLIC,Some(0o644)).unwrap();
        assert_eq!(raw,b"original");held.revalidate(&paths).unwrap();
        std::fs::write(&file,b"modified").unwrap();assert!(held.revalidate(&paths).is_err());
        let symlink=fixture.base.join("symlink.json");std::os::unix::fs::symlink(&file,&symlink).unwrap();
        assert!(HeldFile::open(&mut paths,&symlink,MAX_PUBLIC,None).is_err());
        let hardlink=fixture.base.join("hardlink.json");std::fs::hard_link(&file,&hardlink).unwrap();
        assert!(HeldFile::open(&mut paths,&file,MAX_PUBLIC,None).is_err());std::fs::remove_file(hardlink).unwrap();
        std::fs::set_permissions(&file,std::fs::Permissions::from_mode(0o666)).unwrap();assert!(HeldFile::open(&mut paths,&file,MAX_PUBLIC,None).is_err());
        std::fs::set_permissions(&file,std::fs::Permissions::from_mode(0o644)).unwrap();
        let (held,_)=HeldFile::open(&mut paths,&file,MAX_PUBLIC,None).unwrap();let replaced=fixture.base.join("replaced.json");
        std::fs::rename(&file,&replaced).unwrap();fixture.write("public.json",b"modified",0o644);assert!(held.revalidate(&paths).is_err());
        std::fs::set_permissions(&fixture.base,std::fs::Permissions::from_mode(0o777)).unwrap();assert!(paths.revalidate().is_err());
    }
    #[test]
    #[ignore="requires actual protected private-root filesystem"]
    fn fixed_runtime_owner_checks_never_accept_neutral_root_instead_of_uid703() {
        let fixture=Fixture::new();let child=fixture.base.join("custody");std::fs::create_dir(&child).unwrap();
        std::fs::set_permissions(&child,std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut paths=HeldPaths::new().unwrap();
        assert!(paths.hold_directory(&child,Some((703,8703,0o700))).unwrap_err().is("DEPLOYMENT_LIFECYCLE_RUNTIME_IDENTITY"));
        assert_eq!(std::fs::metadata(&child).unwrap().uid(),0);
    }
    #[test]
    #[ignore="requires actual protected private-root filesystem; nonmacOS checks uid/mode only"]
    fn refused_unsafe_directory_is_never_cached_as_an_admitted_original() {
        let fixture=Fixture::new();let child=fixture.base.join("unsafe");std::fs::create_dir(&child).unwrap();
        std::fs::set_permissions(&child,std::fs::Permissions::from_mode(0o777)).unwrap();
        let mut paths=HeldPaths::new().unwrap();
        assert!(paths.hold_directory(&child,None).unwrap_err().is("DEPLOYMENT_LIFECYCLE_PROTECTION"));
        assert!(!paths.directories.contains_key(&child));paths.revalidate().unwrap();
        assert_eq!(std::fs::metadata(&child).unwrap().mode()&0o7777,0o777);
    }
    #[test]
    #[ignore="requires actual protected private-root filesystem; nonmacOS checks uid/mode only"]
    fn metadata_batch_retains_original_names_and_size_times_without_adopting_other_owners() {
        let fixture=Fixture::new();let first=fixture.write("first.json",b"first",0o644);
        let second=fixture.write("second.json",b"second",0o644);let mut paths=HeldPaths::new().unwrap();
        let (first,_)=HeldFile::open(&mut paths,&first,MAX_PUBLIC,None).unwrap();
        let (second,_)=HeldFile::open(&mut paths,&second,MAX_PUBLIC,None).unwrap();
        paths.revalidate_files_metadata(&[&first,&second]).unwrap();first.revalidate_metadata(&paths).unwrap();
        let unrelated=HeldPaths::new().unwrap();
        assert!(first.revalidate_metadata(&unrelated).unwrap_err().is("DEPLOYMENT_LIFECYCLE_PROTECTION"));
        std::fs::write(second.path(),b"second changed").unwrap();
        assert!(paths.revalidate_files_metadata(&[&first,&second]).unwrap_err().is("DEPLOYMENT_LIFECYCLE_FILE_CHANGED"));
        first.revalidate(&paths).unwrap();
        assert!(second.revalidate(&paths).unwrap_err().is("DEPLOYMENT_LIFECYCLE_FILE_CHANGED"));
    }
    #[cfg(target_os="macos")]
    #[test]
    #[ignore="requires actual macOS root and protected repository ancestry; original owned fixture inode only"]
    fn held_and_new_file_reads_refuse_actual_acl_even_when_uid_mode_and_bytes_match() {
        use crate::native_fs::acl_fixture;
        let fixture=Fixture::new();let path=fixture.write("acl-public.json",b"public original",0o644);
        let mut paths=HeldPaths::new_native_acl_protected().unwrap();
        let (held,raw)=HeldFile::open(&mut paths,&path,MAX_PUBLIC,Some(0o644)).unwrap();
        assert_eq!(raw,b"public original");held.revalidate(&paths).unwrap();
        let before=held.file.metadata().unwrap();acl_fixture::set_allow(&held.file);
        let named=std::fs::symlink_metadata(&path).unwrap();
        assert_eq!((before.dev(),before.ino(),before.uid(),before.gid(),before.mode(),before.len()),
            (named.dev(),named.ino(),named.uid(),named.gid(),named.mode(),named.len()));
        assert!(held.revalidate(&paths).unwrap_err().is("NATIVE_EXTENDED_ACL_REFUSED"));
        assert!(HeldFile::open(&mut paths,&path,MAX_PUBLIC,None).err().unwrap().is("NATIVE_EXTENDED_ACL_REFUSED"));
        assert_eq!(std::fs::read(&path).unwrap(),b"public original");
        acl_fixture::set_empty(&held.file); // Restore ONLY the fixture's own original inode.
    }
    #[cfg(target_os="macos")]
    #[test]
    #[ignore="requires actual macOS root and protected repository ancestry; original owned fixture inode only"]
    fn every_held_ancestor_and_subsequent_open_refuses_actual_extended_acl() {
        use crate::native_fs::acl_fixture;
        let fixture=Fixture::new();let path=fixture.write("acl-child.json",b"public original",0o644);
        let mut paths=HeldPaths::new_native_acl_protected().unwrap();
        paths.hold_directory(&fixture.base,None).unwrap();paths.revalidate().unwrap();
        let original=&paths.directories[&fixture.base].file;
        let before=original.metadata().unwrap();acl_fixture::set_allow(original);
        let after=std::fs::symlink_metadata(&fixture.base).unwrap();
        assert_eq!((before.dev(),before.ino(),before.uid(),before.gid(),before.mode()),
            (after.dev(),after.ino(),after.uid(),after.gid(),after.mode()));
        assert!(paths.revalidate().unwrap_err().is("NATIVE_EXTENDED_ACL_REFUSED"));
        assert!(HeldFile::open(&mut paths,&path,MAX_PUBLIC,None).err().unwrap().is("NATIVE_EXTENDED_ACL_REFUSED"));
        acl_fixture::set_empty(&paths.directories[&fixture.base].file);
    }
}

// Private selected intent creator; no public directory-FD/provider seam.
#[path="ctl_target_intent_directory.rs"]
pub(in crate::ctl) mod intent_directory;
