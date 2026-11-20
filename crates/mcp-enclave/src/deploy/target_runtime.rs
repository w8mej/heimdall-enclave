//! Bounded dedicated-target directory provisioning AFTER public payload publication.
//!
//! The only production entry requires the successful in-process public-payload
//! receipt, a freshly checked selected target, actual opaque fixed-account
//! admission and the actual host maintenance guard. Account admission is
//! reobserved before and after the complete directory operation. There is no
//! CLI, caller-supplied plan, serialized capability, platform fallback or
//! production test provider. This primitive neither creates/adopts accounts nor
//! authorizes account provisioning; concrete installer orchestration is absent.
//!
//! The public-payload engine requires runtime/state/audit/CAS roots absent, so
//! invoking this primitive first would prevent that engine's pristine admission.
//! Existing-upgrade payload migration has no successful producer yet and is
//! deliberately refused here; its state-preserving orchestration remains work.
//!
//! Existing exact directories and ALL contents are preserved. Only absent fixed
//! plan directory names may be created; only an inode created by this invocation
//! may be chowned/chmodded. Missing nonplanned ancestors refuse. Ordinary failure
//! leaves a completed prefix and possibly an incomplete directory, never removes,
//! repairs, restores or rolls back anything. No jobs, sockets, trust files, keys,
//! counters, leases, APFS volumes or per-console directories are created/opened.
//! Cooperative exclusion is not authoritative target/process inactivity, native
//! service readiness, release approval or installation/profile qualification.

use std::{collections::{BTreeMap,BTreeSet},ffi::{CString,OsStr},fs::{File,Metadata},
    io,os::{fd::{AsRawFd,FromRawFd,RawFd},unix::{ffi::OsStrExt,fs::MetadataExt}},
    path::{Path,PathBuf}};
use enclave_core::{deployment::{CheckedDeploymentTarget,DeploymentRole,DeploymentTarget,normalized_path},
    error::{EnclaveError,EnclaveResult},err,fail};
use sha2::{Digest,Sha256};
use super::{target_accounts::FixedAccountAdmission,target_activity::MaintenanceExclusion,target_maintenance::HostMaintenanceGuard,
    target_payload::PublicPayloadReceipt,target_plan::{self,TargetInstallPlan}};

const MAX_RUNTIME_DIRECTORIES:usize=64;
const MAX_HELD_DIRECTORIES:usize=192;
const MAX_COMPONENTS:usize=64;

/// Bounded progress only; never an installed/readiness authorization token.
#[derive(Debug)]
pub(crate) struct RuntimeDirectoryReceipt {
    pub(crate) target_id:String,
    pub(crate) descriptor_sha256:String,
    pub(crate) artifact_inventory_sha256:String,
    /// Newly created, exact metadata verified, inode and parent synchronized.
    pub(crate) created:Vec<PathBuf>,
    /// Existing exact inode observed; contents were neither read nor changed.
    pub(crate) verified_existing:Vec<PathBuf>,
    /// Creation was attempted but its complete durable result is unconfirmed.
    /// It may be absent, a prefix owned by us, or a concurrent creator's entry;
    /// this field never grants cleanup or repair authority.
    pub(crate) incomplete:Option<PathBuf>,
    pub(crate) complete:bool,
    pub(crate) inactivity_proven:bool,
    pub(crate) installation_supported:bool,
    pub(crate) qualified:bool,
}
#[derive(Debug)]
pub(crate) struct RuntimeDirectoryFailure {
    pub(crate) error:EnclaveError,
    pub(crate) receipt:RuntimeDirectoryReceipt,
}
impl RuntimeDirectoryReceipt {
    fn new(checked:&CheckedDeploymentTarget)->Self {
        Self {target_id:checked.target().target_id.clone(),descriptor_sha256:checked.descriptor_sha256().into(),
            artifact_inventory_sha256:String::new(),created:Vec::new(),verified_existing:Vec::new(),
            incomplete:None,complete:false,inactivity_proven:false,installation_supported:false,qualified:false}
    }
}

#[derive(Clone,Debug,PartialEq,Eq)]
struct Spec {path:PathBuf,uid:u32,gid:u32,mode:u32}
fn specs(target:&DeploymentTarget,plan:&TargetInstallPlan)->EnclaveResult<Vec<Spec>> {
    let roots=[&target.layout.socket_root,&target.layout.state_root,
        &target.layout.audit_root,&target.layout.cas_store_root].into_iter()
        .map(|p|normalized_path(p)).collect::<EnclaveResult<Vec<_>>>()?;
    let mut result=Vec::new();let mut keys=BTreeSet::new();
    for entry in &plan.directories {
        let path=normalized_path(&entry.path)?;
        if !roots.iter().any(|root|path.starts_with(root)) {continue;}
        if path.components().count()>MAX_COMPONENTS {fail!(E2BIG,"RUNTIME_DIRECTORY_LIMIT");}
        let mode=match entry.mode.as_str() {"0700"=>0o700,"0755"=>0o755,"2750"=>0o2750,
            _=>{fail!(EINVAL,"RUNTIME_DIRECTORY_MODE");}};
        let key=path.to_str().ok_or_else(||err!(EINVAL,"RUNTIME_DIRECTORY_PATH"))?.to_ascii_lowercase();
        if !keys.insert(key) {fail!(EINVAL,"RUNTIME_DIRECTORY_COLLISION");}
        result.push(Spec {path,uid:entry.uid,gid:entry.gid,mode});
    }
    if result.is_empty() || result.len()>MAX_RUNTIME_DIRECTORIES
        || roots.iter().any(|root|!result.iter().any(|s|&s.path==root)) {
        fail!(EINVAL,"RUNTIME_DIRECTORY_PLAN");
    }
    // No creation may occur below a daemon-writable planned directory. Only
    // fixed root-owned parents contain the fixed names created by this engine.
    for spec in &result {
        for ancestor in &result {
            if spec.path!=ancestor.path && spec.path.starts_with(&ancestor.path)
                && (ancestor.uid!=0 || ancestor.mode&0o022!=0) {
                fail!(EACCES,"RUNTIME_MUTABLE_PLANNED_ANCESTOR");
            }
        }
    }
    result.sort_by(|a,b|a.path.components().count().cmp(&b.path.components().count()).then(a.path.cmp(&b.path)));
    Ok(result)
}
fn payload_binding(target:&DeploymentTarget,descriptor:&str,plan:&TargetInstallPlan,payload:&PublicPayloadReceipt)->EnclaveResult<()> {
    if target.role!=DeploymentRole::DedicatedTest || plan.role!=DeploymentRole::DedicatedTest {
        fail!(EACCES,"RUNTIME_UPGRADE_SEQUENCE_UNAVAILABLE");
    }
    if plan.target_id!=target.target_id || plan.deployment_config_sha256!=descriptor
        || payload.target_id!=plan.target_id || payload.descriptor_sha256!=descriptor
        || payload.artifact_inventory_sha256!=plan.artifact_inventory_sha256
        || payload.installation_supported || payload.qualified {
        fail!(ESTALE,"RUNTIME_PAYLOAD_BINDING");
    }
    let expected=plan.copies.iter().filter(|copy|copy.destination!=plan.selected_pins_file
        && !copy.destination.starts_with("/Library/LaunchDaemons")
        && !copy.destination.starts_with("/Library/LaunchAgents"))
        .map(|copy|normalized_path(&copy.destination)).collect::<EnclaveResult<BTreeSet<_>>>()?;
    let actual=payload.published.iter().map(|path|normalized_path(path)).collect::<EnclaveResult<BTreeSet<_>>>()?;
    if expected.is_empty() || actual!=expected || actual.len()!=payload.published.len()
        || !plan.missing_required_files.is_empty() {
        fail!(EINVAL,"RUNTIME_PAYLOAD_INCOMPLETE");
    }
    Ok(())
}
fn require_root(uid:u32)->EnclaveResult<()> {
    if uid!=0 {fail!(EACCES,"RUNTIME_ROOT_REQUIRED");}Ok(())
}
fn context(checked:&CheckedDeploymentTarget,inventory:&str)->EnclaveResult<()> {
    if hex::encode(Sha256::digest(checked.read_artifact_inventory()?))!=inventory {
        fail!(ESTALE,"RUNTIME_CONTEXT_CHANGED");
    }Ok(())
}

/// The caller must retain the same maintenance guard from payload publication
/// through this operation and separately authorize any account adoption and
/// later installation/trust/lifecycle effects. Actual fixed-account observation
/// is repeated before/after the entire operation, with the account primitive's
/// explicit exclusion of concurrent directory-administrator changes. Lightweight
/// guard/context checks still bracket each directory. A guard borrowed here
/// cannot be dropped during the operation. Arbitrary JSON records, fixture
/// providers and activity observations cannot satisfy the account parameter.
pub(crate) fn provision_dedicated_runtime_after_payload(checked:&CheckedDeploymentTarget,
    payload:&PublicPayloadReceipt,accounts:&FixedAccountAdmission,guard:&mut HostMaintenanceGuard)
    ->Result<RuntimeDirectoryReceipt,RuntimeDirectoryFailure> {
    let mut receipt=RuntimeDirectoryReceipt::new(checked);
    #[cfg(not(target_os="macos"))]
    let result:EnclaveResult<()>= {let _=(payload,accounts,guard);Err(err!(ENOSYS,"RUNTIME_NATIVE_REQUIRED"))};
    #[cfg(target_os="macos")]
    let result=(|| {
        require_root(unsafe {libc::geteuid()})?;guard.assert_held()?;
        let plan=target_plan::prepare(checked)?;
        receipt.artifact_inventory_sha256=plan.artifact_inventory_sha256.clone();
        payload_binding(checked.target(),checked.descriptor_sha256(),&plan,payload)?;
        let desired=specs(checked.target(),&plan)?;
        accounts.assert_current(checked,guard)?;
        let mut directories=Directories::native()?;
        let operation=apply(&mut directories,&desired,&mut receipt,|| {
            guard.assert_held()?;context(checked,&plan.artifact_inventory_sha256)?;
            guard.assert_held()
        });
        // Reobserve actual accounts even when directory work refused. Native
        // queries run only before/after the whole apply, never per directory.
        let admission=accounts.assert_current(checked,guard);
        let bindings=directories.validate();
        if admission.is_err() || bindings.is_err() {receipt.complete=false;}
        bindings?;admission?;operation
    })();
    match result {Ok(())=>Ok(receipt),Err(error)=>Err(RuntimeDirectoryFailure {error,receipt})}
}

fn name(value:&OsStr)->EnclaveResult<CString> {
    CString::new(value.as_bytes()).map_err(|_|err!(EINVAL,"RUNTIME_DIRECTORY_PATH"))
}
fn stat(file:&File)->EnclaveResult<Metadata> {file.metadata().map_err(|_|err!(EIO,"RUNTIME_DIRECTORY_STAT"))}
fn from_fd(fd:RawFd)->EnclaveResult<File> {
    if fd<0 {fail!(EACCES,"RUNTIME_DIRECTORY_PROTECTION");}Ok(unsafe {File::from_raw_fd(fd)})
}
const OPEN_DIRECTORY:i32=libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC;
fn open_named(parent:&File,leaf:&CString)->EnclaveResult<Option<File>> {
    let fd=unsafe {libc::openat(parent.as_raw_fd(),leaf.as_ptr(),OPEN_DIRECTORY)};
    if fd>=0 {return Ok(Some(unsafe {File::from_raw_fd(fd)}));}
    if io::Error::last_os_error().raw_os_error()==Some(libc::ENOENT) {Ok(None)}
    else {fail!(EACCES,"RUNTIME_DIRECTORY_PROTECTION");}
}
fn exact(m:&Metadata,spec:&Spec)->bool {
    m.is_dir() && m.nlink()>0 && m.uid()==spec.uid && m.gid()==spec.gid && m.mode()&0o7777==spec.mode
}
fn same_inode(a:&Metadata,b:&Metadata)->bool {a.dev()==b.dev() && a.ino()==b.ino()}
#[derive(PartialEq,Eq)]
struct Stamp {dev:u64,ino:u64,uid:u32,gid:u32,mode:u32}
impl Stamp {
    // Directory contents/mtime/ctime/nlink are deliberately not frozen: creating
    // a fixed child changes them, and existing mutable contents are not audited.
    fn of(m:&Metadata)->Self {Self {dev:m.dev(),ino:m.ino(),uid:m.uid(),gid:m.gid(),mode:m.mode()}}
}
struct Held {file:File,stamp:Stamp}
impl Held {
    fn new(file:File)->EnclaveResult<Self> {
        let metadata=stat(&file)?;
        if !metadata.is_dir() || metadata.nlink()==0 {fail!(EACCES,"RUNTIME_DIRECTORY_PROTECTION");}
        Ok(Self {file,stamp:Stamp::of(&metadata)})
    }
    fn current(&self)->EnclaveResult<()> {
        let current=stat(&self.file)?;
        if !current.is_dir() || current.nlink()==0 || self.stamp!=Stamp::of(&current) {
            fail!(ESTALE,"RUNTIME_DIRECTORY_CHANGED");
        }Ok(())
    }
}
struct Directories {anchor:PathBuf,held:BTreeMap<PathBuf,Held>,creator_uid:u32}
impl Directories {
    fn native()->EnclaveResult<Self> {
        let file=from_fd(unsafe {libc::open(b"/\0".as_ptr().cast(),OPEN_DIRECTORY)})?;
        let root=Held::new(file)?;
        if root.stamp.uid!=0 || root.stamp.mode&0o022!=0 {fail!(EACCES,"RUNTIME_DIRECTORY_PROTECTION");}
        Ok(Self {anchor:"/".into(),held:BTreeMap::from([(PathBuf::from("/"),root)]),creator_uid:0})
    }
    fn get(&self,path:&Path)->EnclaveResult<&Held> {
        let held=self.held.get(path).ok_or_else(||err!(EINVAL,"RUNTIME_DIRECTORY_NOT_HELD"))?;
        held.current()?;Ok(held)
    }
    fn protected_parent(&self,path:&Path)->EnclaveResult<&Held> {
        let held=self.get(path)?;
        if held.stamp.uid!=self.creator_uid || held.stamp.mode&0o022!=0 {
            fail!(EACCES,"RUNTIME_MUTABLE_ANCESTOR");
        }Ok(held)
    }
    /// Hold existing ancestry only. This function NEVER creates missing parents.
    fn ancestry(&mut self,path:&Path)->EnclaveResult<()> {
        if path.components().count()>MAX_COMPONENTS || !path.starts_with(&self.anchor) {
            fail!(EINVAL,"RUNTIME_DIRECTORY_PATH");
        }
        if self.held.contains_key(path) {self.protected_parent(path)?;return Ok(());}
        if self.held.len()>=MAX_HELD_DIRECTORIES {fail!(E2BIG,"RUNTIME_DIRECTORY_LIMIT");}
        let parent=path.parent().ok_or_else(||err!(EINVAL,"RUNTIME_DIRECTORY_PATH"))?;
        self.ancestry(parent)?;
        if self.held.len()>=MAX_HELD_DIRECTORIES {fail!(E2BIG,"RUNTIME_DIRECTORY_LIMIT");}
        let leaf=name(path.file_name().ok_or_else(||err!(EINVAL,"RUNTIME_DIRECTORY_PATH"))?)?;
        let file=open_named(&self.protected_parent(parent)?.file,&leaf)?
            .ok_or_else(||err!(EACCES,"RUNTIME_ANCESTOR_MISSING"))?;
        let held=Held::new(file)?;
        if held.stamp.uid!=self.creator_uid || held.stamp.mode&0o022!=0 {fail!(EACCES,"RUNTIME_MUTABLE_ANCESTOR");}
        self.held.insert(path.to_owned(),held);Ok(())
    }
    fn named(&self,path:&Path)->EnclaveResult<File> {
        let parent=path.parent().ok_or_else(||err!(EINVAL,"RUNTIME_DIRECTORY_PATH"))?;
        let leaf=name(path.file_name().ok_or_else(||err!(EINVAL,"RUNTIME_DIRECTORY_PATH"))?)?;
        open_named(&self.protected_parent(parent)?.file,&leaf)?
            .ok_or_else(||err!(ESTALE,"RUNTIME_DIRECTORY_CHANGED"))
    }
    fn validate(&self)->EnclaveResult<()> {
        for (path,held) in &self.held {
            held.current()?;
            if path==&self.anchor {
                #[cfg(test)]
                if path!=Path::new("/") {
                    let absolute=name(path.as_os_str())?;
                    let named=from_fd(unsafe {libc::open(absolute.as_ptr(),OPEN_DIRECTORY)})?;
                    if held.stamp!=Stamp::of(&stat(&named)?) {fail!(ESTALE,"RUNTIME_DIRECTORY_CHANGED");}
                }
                continue;
            }
            if held.stamp!=Stamp::of(&stat(&self.named(path)?)?) {fail!(ESTALE,"RUNTIME_DIRECTORY_CHANGED");}
        }Ok(())
    }
    fn one(&mut self,spec:&Spec,receipt:&mut RuntimeDirectoryReceipt)->EnclaveResult<()> {
        if self.held.len()>=MAX_HELD_DIRECTORIES {fail!(E2BIG,"RUNTIME_DIRECTORY_LIMIT");}
        let parent=spec.path.parent().ok_or_else(||err!(EINVAL,"RUNTIME_DIRECTORY_PATH"))?;
        self.ancestry(parent)?;self.validate()?;
        if self.held.len()>=MAX_HELD_DIRECTORIES {fail!(E2BIG,"RUNTIME_DIRECTORY_LIMIT");}
        let leaf=name(spec.path.file_name().ok_or_else(||err!(EINVAL,"RUNTIME_DIRECTORY_PATH"))?)?;
        let directory=&self.protected_parent(parent)?.file;
        let (file,created)=match open_named(directory,&leaf)? {
            Some(file)=>(file,false),
            None=>{
                receipt.incomplete=Some(spec.path.clone());
                // mkdirat is exclusive. EEXIST/race is a refusal, never adoption.
                if unsafe {libc::mkdirat(directory.as_raw_fd(),leaf.as_ptr(),0o700)}!=0 {
                    fail!(EALREADY,"RUNTIME_DIRECTORY_CREATE_UNCERTAIN");
                }
                let file=open_named(directory,&leaf)?.ok_or_else(||err!(ESTALE,"RUNTIME_DIRECTORY_CHANGED"))?;
                let before=stat(&file)?;
                if !before.is_dir() || before.nlink()==0 || before.uid()!=self.creator_uid || before.mode()&0o077!=0 {
                    fail!(EACCES,"RUNTIME_NEW_DIRECTORY_PROTECTION");
                }
                let named=open_named(directory,&leaf)?.ok_or_else(||err!(ESTALE,"RUNTIME_DIRECTORY_CHANGED"))?;
                if Stamp::of(&before)!=Stamp::of(&stat(&named)?) {fail!(ESTALE,"RUNTIME_DIRECTORY_CHANGED");}
                self.validate()?;
                // ONLY this invocation's newly created inode is mutated.
                if unsafe {libc::fchown(file.as_raw_fd(),spec.uid,spec.gid)}!=0
                    || unsafe {libc::fchmod(file.as_raw_fd(),spec.mode as libc::mode_t)}!=0 {
                    fail!(EACCES,"RUNTIME_NEW_DIRECTORY_METADATA");
                }
                if !exact(&stat(&file)?,spec) {fail!(EACCES,"RUNTIME_NEW_DIRECTORY_METADATA");}
                file.sync_all().map_err(|_|err!(EIO,"RUNTIME_DIRECTORY_SYNC_UNCERTAIN"))?;
                directory.sync_all().map_err(|_|err!(EIO,"RUNTIME_DIRECTORY_SYNC_UNCERTAIN"))?;
                (file,true)
            }
        };
        let metadata=stat(&file)?;
        if !exact(&metadata,spec) {fail!(EACCES,"RUNTIME_EXISTING_DIRECTORY_METADATA");}
        let named=open_named(directory,&leaf)?.ok_or_else(||err!(ESTALE,"RUNTIME_DIRECTORY_CHANGED"))?;
        if !same_inode(&metadata,&stat(&named)?) || !exact(&stat(&named)?,spec) {
            fail!(ESTALE,"RUNTIME_DIRECTORY_CHANGED");
        }
        self.held.insert(spec.path.clone(),Held::new(file)?);
        if created {receipt.created.push(spec.path.clone());receipt.incomplete=None;}
        else {receipt.verified_existing.push(spec.path.clone());}
        self.validate()
    }
}
fn apply(directories:&mut Directories,desired:&[Spec],receipt:&mut RuntimeDirectoryReceipt,
    mut recheck:impl FnMut()->EnclaveResult<()>)->EnclaveResult<()> {
    boundary(directories,&mut recheck)?;
    for spec in desired {
        boundary(directories,&mut recheck)?;
        let operation=directories.one(spec,receipt);
        // Even an otherwise complete prefix cannot become complete if context
        // or exclusion changes at the last boundary. Ordinary operation errors
        // still receive BOTH postchecks. Binding/exclusion uncertainty takes
        // precedence; the original error survives when both postchecks pass.
        boundary(directories,&mut recheck)?;
        operation?;
    }
    boundary(directories,&mut recheck)?;receipt.complete=true;Ok(())
}
fn boundary(directories:&Directories,recheck:&mut impl FnMut()->EnclaveResult<()>)->EnclaveResult<()> {
    let context_and_exclusion=recheck();
    let bindings=directories.validate();
    // Do not short-circuit the second read-only check when the first refuses.
    bindings?;context_and_exclusion
}

#[cfg(test)]
#[path="target_runtime_tests.rs"]
mod tests;
