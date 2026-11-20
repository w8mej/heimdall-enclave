//! Independently configured TUF approval of the exact selected inventory.
//!
//! This is ONLY software-approval evidence. It does not verify candidate native
//! code, entitlements, rendered configuration, inactivity, account admission or
//! installation. It deliberately does not implement PublicPayloadAuthority.
//! Genuine software-purpose provisioning of the config/root and an approved
//! initial time lower bound are external requirements. File ownership, host
//! wall time and self-signatures cannot manufacture those authorities.
//!
//! Admission persistently initializes/advances a dedicated trust store. These
//! effects survive later refusal. No CLI, private signing key, network fetch,
//! fixture fallback or automatic trust reset exists. Hostile concurrent root,
//! wholesale root restore and noncooperating privileged writers are excluded.
//! Before the first sealed opener can load/create a seed, actual process
//! hardening must succeed. SealedStore owns the derived zeroizing SecretKey32;
//! this module never reads, copies, clones or formats seed/key bytes. Existing
//! sealed-core seed temporaries retain their separately recorded limitations.

use std::{collections::{BTreeMap,BTreeSet}, ffi::CString, fs::{File,Metadata},
    os::{fd::{AsRawFd,FromRawFd},unix::{ffi::OsStrExt,fs::{FileExt,MetadataExt}}},
    path::{Path,PathBuf},sync::Arc};
use enclave_core::{deployment::{CheckedDeploymentTarget,DeploymentSigningMode,DeploymentTarget,normalized_path},
    deployment::startup_lease::{DirectoryModeChange,DirectoryModeIdentity,ExclusiveStartupLease,PrivateBirthAncestor},
    error::{EnclaveError,EnclaveResult}, profile::Profile,
    sealed::{Loaded,SealedStore,StateDirectoryLease}, err, fail};
use enclave_crypto::tuf::{Role,TufClient,TufTrustedState,TrustedClock};
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use super::{target_activity::MaintenanceExclusion,target_maintenance::HostMaintenanceGuard,
    target_plan, target_release_json::{self as json,MinimumThresholds,MAX_METADATA}};

const MAX_CONFIG:usize=65536;
const MAX_ROOTS:usize=32;
const MAX_RETAINED:usize=8*1024*1024;
const MAX_INPUT_BYTES:usize=12*1024*1024;
const MAX_STATE_BODY:usize=16*1024*1024;
const MAX_STATE_ENVELOPE:usize=32*1024*1024;
const MAX_TIME:i64=253_402_300_799;
const STORE:&str="software-release-approval-v1";
const KIND:&str="mcpmac-software-release-authority";
const PURPOSE:&str="software-release";

/// Explicit caller intent; neither variant grants permission to provision a
/// host. FirstProvisioning requires an already provisioned empty private dir.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) enum ReleaseStateMode {FirstProvisioning,Existing}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseConfig {
    version:u8,kind:String,purpose:String,target_id:String,descriptor_sha256:String,
    profile:Profile,signing_identity_mode:DeploymentSigningMode,
    bootstrap_root_file:PathBuf,bootstrap_root_sha256:String,
    approval_repository:PathBuf,trust_state_directory:PathBuf,inventory_target:String,
    minimum_thresholds:MinimumThresholds,
    /// Independently approved lower bound; host clock can only advance it.
    minimum_time_unix:i64,
}
fn config(raw:&[u8],target:&DeploymentTarget,descriptor:&str)->EnclaveResult<ReleaseConfig> {
    json::strict(raw,MAX_CONFIG)?;
    let c:ReleaseConfig=serde_json::from_slice(raw).map_err(|_|err!(EINVAL,"RELEASE_CONFIG_SCHEMA"))?;
    let mode=if enclave_core::codesign::TEAM_ID.is_empty() {DeploymentSigningMode::LocalPins}
        else {DeploymentSigningMode::TeamId};
    let suffix=c.inventory_target.strip_prefix("mcpmac/software-release/").unwrap_or("");
    if c.version!=1 || c.kind!=KIND || c.purpose!=PURPOSE || c.target_id!=target.target_id
        || !json::lower_hex(&c.descriptor_sha256,64) || c.descriptor_sha256!=descriptor
        || c.profile!=target.profile || c.signing_identity_mode!=target.signing_identity_mode
        || c.signing_identity_mode!=mode || !json::lower_hex(&c.bootstrap_root_sha256,64)
        || !c.minimum_thresholds.valid(c.profile==Profile::L3) || !(1..=MAX_TIME).contains(&c.minimum_time_unix)
        || c.inventory_target.len()>256 || suffix.is_empty() || !suffix.ends_with(".json")
        || suffix.contains('/') || !suffix.as_bytes()[0].is_ascii_lowercase()
        || !suffix.bytes().all(|b|b.is_ascii_lowercase()||b.is_ascii_digit()||b"-._".contains(&b))
        || suffix.contains("..") {fail!(EINVAL,"RELEASE_CONFIG_SCOPE");}
    for p in [&c.bootstrap_root_file,&c.approval_repository,&c.trust_state_directory] {route(p)?;}
    Ok(c)
}
fn wall_time()->EnclaveResult<i64> {
    let now=enclave_crypto::time::now_unix();
    if !(1..=MAX_TIME).contains(&now) {fail!(EACCES,"RELEASE_TIME_RANGE");}
    Ok(now)
}
fn route(path:&Path)->EnclaveResult<PathBuf> {
    // Preserve Linux fixture routes; fixed platform aliases are Darwin routes.
    let normalized=normalized_path(path)?;
    if cfg!(target_os="macos") {Ok(normalized)}else{Ok(path.to_owned())}
}
fn overlaps(a:&Path,b:&Path)->EnclaveResult<bool> {
    let a=PathBuf::from(normalized_path(a)?.to_str().ok_or_else(||err!(EINVAL,"RELEASE_PATH"))?.to_ascii_lowercase());
    let b=PathBuf::from(normalized_path(b)?.to_str().ok_or_else(||err!(EINVAL,"RELEASE_PATH"))?.to_ascii_lowercase());
    Ok(a.starts_with(&b)||b.starts_with(&a))
}
fn excluded(target:&DeploymentTarget)->Vec<PathBuf> {
    let l=&target.layout;
    let mut paths=vec![l.binary_dir.clone(),l.custody_bundle.clone(),l.sandbox_dir.clone(),
        l.socket_root.clone(),l.state_root.clone(),l.audit_root.clone(),l.cas_store_root.clone(),
        l.staging_root.clone(),l.support_root.clone(),target.authority_config.clone(),
        target.codesign_pins_file.clone(),PathBuf::from("/Library/LaunchAgents"),PathBuf::from("/Library/LaunchDaemons")];
    if let Some(b)=&target.broker {paths.extend([b.base_dir.clone(),b.tuf_root_file.clone()]);}
    paths
}
fn isolation(c:&ReleaseConfig,config_path:&Path,descriptor:&Path,target:&DeploymentTarget)->EnclaveResult<Vec<PathBuf>> {
    let protected=[config_path,c.bootstrap_root_file.as_path(),c.approval_repository.as_path(),
        c.trust_state_directory.as_path(),descriptor,target.expected_artifacts_manifest.as_path()];
    let excluded=excluded(target);
    for (i,a) in protected.iter().enumerate() {
        for b in protected.iter().skip(i+1) {if overlaps(a,b)? {fail!(EACCES,"RELEASE_AUTHORITY_OVERLAP");}}
        for b in &excluded {if overlaps(a,b)? {fail!(EACCES,"RELEASE_MUTATION_DOMAIN");}}
    }
    Ok(excluded)
}

#[derive(Clone,Debug,PartialEq,Eq)]
struct Stamp {dev:u64,ino:u64,uid:u32,gid:u32,mode:u32,links:u64,len:u64,modified:(i64,i64),changed:(i64,i64)}
impl Stamp {fn of(m:&Metadata)->Self {Self {dev:m.dev(),ino:m.ino(),uid:m.uid(),gid:m.gid(),mode:m.mode(),
    links:m.nlink(),len:m.len(),modified:(m.mtime(),m.mtime_nsec()),changed:(m.ctime(),m.ctime_nsec())}}}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct DirStamp {dev:u64,ino:u64,uid:u32,gid:u32,mode:u32}
impl DirStamp {
    fn of(m:&Metadata)->Self {Self {dev:m.dev(),ino:m.ino(),uid:m.uid(),gid:m.gid(),mode:m.mode()}}
    fn identity(self)->DirectoryModeIdentity {DirectoryModeIdentity {
        dev:self.dev,ino:self.ino,uid:self.uid,gid:self.gid,mode:self.mode}}
    fn from_identity(identity:DirectoryModeIdentity)->Self {Self {
        dev:identity.dev,ino:identity.ino,uid:identity.uid,gid:identity.gid,mode:identity.mode}}
}
fn stat(file:&File)->EnclaveResult<Metadata> {file.metadata().map_err(|_|err!(EIO,"RELEASE_STAT"))}
fn leaf(path:&Path)->EnclaveResult<CString> {
    CString::new(path.file_name().ok_or_else(||err!(EINVAL,"RELEASE_PATH"))?.as_bytes())
        .map_err(|_|err!(EINVAL,"RELEASE_PATH"))
}
fn open_at(parent:&File,name:&CString,directory:bool)->EnclaveResult<File> {
    let flags=libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC
        |if directory {libc::O_DIRECTORY}else{0};
    // SAFETY: held parent descriptor and one NUL-terminated component.
    let fd=unsafe {libc::openat(parent.as_raw_fd(),name.as_ptr(),flags)};
    if fd<0 {fail!(EACCES,"RELEASE_PROTECTED_PATH");}
    Ok(unsafe {File::from_raw_fd(fd)})
}
// The original stamp is immutable. Only a verified real event can install an
// overlay; current stat is never accepted as a replacement admission baseline.
struct HeldDirectory {file:File,stamp:DirStamp,mode_change:Option<Arc<DirectoryModeChange>>}
fn predicted_mode_stamp(original:DirStamp,before:DirectoryModeIdentity,after:DirectoryModeIdentity)->EnclaveResult<DirStamp> {
    if original.identity()!=before||before.uid!=0||before.gid!=0
        ||before.mode!=(libc::S_IFDIR as u32|0o700)||after.dev!=before.dev||after.ino!=before.ino
        ||after.uid!=before.uid||after.gid!=before.gid||after.mode!=(libc::S_IFDIR as u32|0o755) {
        fail!(ESTALE,"RELEASE_DIRECTORY_MODE_DELTA");
    }
    Ok(DirStamp::from_identity(after))
}
impl HeldDirectory {
    fn expected(&self,path:&Path)->EnclaveResult<DirStamp> {
        match &self.mode_change {
            None=>Ok(self.stamp),
            Some(event)=>{
                if event.path()!=path {fail!(ESTALE,"RELEASE_DIRECTORY_MODE_PATH");}
                predicted_mode_stamp(self.stamp,event.before(),event.after())
            },
        }
    }
}
struct DirectoryTransition<'a> {checked:&'a CheckedDeploymentTarget,event:&'a Arc<DirectoryModeChange>}
fn directory_observations(directories:&BTreeMap<PathBuf,HeldDirectory>,base:&Path,
    transition:Option<&DirectoryTransition<'_>>)->Vec<EnclaveError> {
    let mut errors=Vec::new();
    for (path,directory) in directories {
        let result=(|| {
            let pending=transition.filter(|transition| {
                path==transition.event.path()||(directory.stamp.dev,directory.stamp.ino)
                    ==(transition.event.before().dev,transition.event.before().ino)
            });
            let expected=if let Some(transition)=pending {
                if directory.mode_change.is_some() {fail!(EALREADY,"RELEASE_DIRECTORY_MODE_REPLAY");}
                predicted_mode_stamp(directory.stamp,transition.event.before(),transition.event.after())?
            }else{directory.expected(path)?};
            // Preserve ordinary held-before-named refusal precedence.
            if DirStamp::of(&stat(&directory.file)?)!=expected {fail!(ESTALE,"RELEASE_DIRECTORY_CHANGED");}
            let named=if path!=base {
                let parent=path.parent().and_then(|p|directories.get(p)).ok_or_else(||err!(EINVAL,"RELEASE_PATH"))?;
                Some(open_at(&parent.file,&leaf(path)?,true)?)
            }else{None};
            if let Some(transition)=pending {
                // This ONE-TIME recipient verification checks the complete
                // actual event snapshot on BOTH original and named FDs.
                let named=named.as_ref().ok_or_else(||err!(EACCES,"RELEASE_DIRECTORY_MODE_BASE"))?;
                return transition.event.verify_recipient(transition.checked,path,&directory.file,named,directory.stamp.identity());
            }
            if named.as_ref().map(|file|stat(file).map(|m|DirStamp::of(&m)))
                    .transpose()?.is_some_and(|stamp|stamp!=expected) {
                fail!(ESTALE,"RELEASE_DIRECTORY_CHANGED");
            }
            Ok(())
        })();
        if let Err(error)=result {errors.push(error);}
    }
    errors
}
// Both maps were completely validated against the same actual event before
// either install. This step cannot acquire an owner, observe stat, or fail.
fn install_directory_change(directories:&mut BTreeMap<PathBuf,HeldDirectory>,event:&Arc<DirectoryModeChange>)->usize {
    let mut installed=0;
    for (path,directory) in directories {
        if path==event.path() {directory.mode_change=Some(Arc::clone(event));installed+=1;}
    }
    installed
}
// Immutable retained identity membership is useful only as a denial predicate.
// Neither membership nor its absence proves currentness or mutation authority.
fn retains_directory_identity(directories:&BTreeMap<PathBuf,HeldDirectory>,dev:u64,ino:u64)->bool {
    directories.values().any(|directory|(directory.stamp.dev,directory.stamp.ino)==(dev,ino))
}
struct StateBinding {base:PathBuf,directories:BTreeMap<PathBuf,HeldDirectory>}
impl StateBinding {
    fn capture(inputs:&ProtectedInputs,path:&Path)->EnclaveResult<Self> {
        let mut directories=BTreeMap::new();
        for (p,d) in &inputs.directories {
            if path.starts_with(p) {
                let file=d.file.try_clone().map_err(|_|err!(EIO,"RELEASE_STATE_BINDING"))?;
                // A state owner is captured only during initial admission,
                // before a transition; never restamp an admitted overlay.
                if d.mode_change.is_some() {fail!(EACCES,"RELEASE_STATE_BINDING_AFTER_TRANSITION");}
                directories.insert(p.clone(),HeldDirectory {stamp:d.stamp,file,mode_change:None});
            }
        }
        let binding=Self {base:inputs.base.clone(),directories};binding.validate()?;Ok(binding)
    }
    fn validate(&self)->EnclaveResult<()> {
        directory_observations(&self.directories,&self.base,None).first().cloned().map_or(Ok(()),|error| {
            if error.is("RELEASE_DIRECTORY_CHANGED") {Err(err!(ESTALE,"RELEASE_STATE_DIRECTORY_CHANGED"))}else{Err(error)}
        })
    }
}
struct HeldInput {file:File,stamp:Stamp,bytes:Vec<u8>}
fn read_exact(file:&File,maximum:usize)->EnclaveResult<Vec<u8>> {
    let before=stat(file)?;
    if !before.is_file()||before.nlink()!=1||before.len()==0||before.len()>maximum as u64 {fail!(EACCES,"RELEASE_FILE_BOUND");}
    let mut bytes=vec![0;before.len() as usize];let mut offset=0;
    while offset<bytes.len() {
        let n=file.read_at(&mut bytes[offset..],offset as u64).map_err(|_|err!(EIO,"RELEASE_READ"))?;
        if n==0 {fail!(ESTALE,"RELEASE_INPUT_CHANGED");}offset+=n;
    }
    let mut extra=[0u8;1];
    if file.read_at(&mut extra,offset as u64).map_err(|_|err!(EIO,"RELEASE_READ"))?!=0
        || Stamp::of(&before)!=Stamp::of(&stat(file)?) {fail!(ESTALE,"RELEASE_INPUT_CHANGED");}
    Ok(bytes)
}
struct ProtectedInputs {directories:BTreeMap<PathBuf,HeldDirectory>,files:BTreeMap<PathBuf,HeldInput>,owner:u32,base:PathBuf,bytes:usize}
fn external_runtime_sources_separate(inputs:&ProtectedInputs,repository:&Path,state:&Path,
    sources:&[(&Path,&File)])->EnclaveResult<()> {
    if sources.is_empty()||sources.len()>2 {fail!(EINVAL,"RELEASE_EXTERNAL_RUNTIME_SOURCE_COUNT");}
    let mut identities=BTreeSet::new();let mut paths:Vec<PathBuf>=Vec::new();
    for (path,file) in sources {
        let path=route(path)?;
        let before=stat(file)?;
        if !before.is_file()||before.nlink()!=1 {fail!(EACCES,"RELEASE_EXTERNAL_RUNTIME_SOURCE_TYPE");}
        if overlaps(&path,repository)?||overlaps(&path,state)? {
            fail!(EACCES,"RELEASE_EXTERNAL_RUNTIME_SOURCE_DOMAIN");
        }
        for original in inputs.files.keys() {
            if overlaps(&path,original)? {fail!(EACCES,"RELEASE_EXTERNAL_RUNTIME_SOURCE_DOMAIN");}
        }
        if inputs.files.values().any(|original|(original.stamp.dev,original.stamp.ino)==(before.dev(),before.ino()))
            ||retains_directory_identity(&inputs.directories,before.dev(),before.ino())
            ||!identities.insert((before.dev(),before.ino())) {
            fail!(EACCES,"RELEASE_EXTERNAL_RUNTIME_SOURCE_INODE");
        }
        for previous in &paths {if overlaps(&path,previous)? {fail!(EACCES,"RELEASE_EXTERNAL_RUNTIME_SOURCE_DOMAIN");}}
        if Stamp::of(&before)!=Stamp::of(&stat(file)?) {fail!(ESTALE,"RELEASE_EXTERNAL_RUNTIME_SOURCE_CHANGED");}
        paths.push(path);
    }
    Ok(())
}
impl ProtectedInputs {
    fn new()->EnclaveResult<Self> {
        // SAFETY: literal path, read-only owned descriptor with no exec leakage.
        let fd=unsafe {libc::open(c"/".as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)};
        if fd<0 {fail!(EACCES,"RELEASE_PROTECTED_PATH");}
        Self::at_root(PathBuf::from("/"),unsafe {File::from_raw_fd(fd)},0)
    }
    fn at_root(base:PathBuf,file:File,owner:u32)->EnclaveResult<Self> {
        let m=stat(&file)?;
        if !m.is_dir()||(m.uid()!=0&&m.uid()!=owner)||m.mode()&0o022!=0 {fail!(EACCES,"RELEASE_DIRECTORY_PROTECTION");}
        Ok(Self {directories:BTreeMap::from([(base.clone(),HeldDirectory {file,stamp:DirStamp::of(&m),mode_change:None})]),
            files:BTreeMap::new(),owner,base,bytes:0})
    }
    fn directory(&mut self,path:&Path)->EnclaveResult<()> {
        if self.directories.contains_key(path) {return Ok(());}
        if !path.starts_with(&self.base)||path.components().count()>96||self.directories.len()>=192 {fail!(E2BIG,"RELEASE_DIRECTORY_BOUND");}
        let parent=path.parent().ok_or_else(||err!(EINVAL,"RELEASE_PATH"))?;
        self.directory(parent)?;
        let file=open_at(&self.directories[parent].file,&leaf(path)?,true)?;
        let m=stat(&file)?;
        if !m.is_dir()||(m.uid()!=0&&m.uid()!=self.owner)||m.mode()&0o022!=0 {fail!(EACCES,"RELEASE_DIRECTORY_PROTECTION");}
        self.directories.insert(path.to_owned(),HeldDirectory {file,stamp:DirStamp::of(&m),mode_change:None});
        Ok(())
    }
    fn read(&mut self,path:&Path,maximum:usize)->EnclaveResult<Vec<u8>> {
        let path=route(path)?;
        if let Some(held)=self.files.get(&path) {self.validate_file(&path,held)?;return Ok(held.bytes.clone());}
        let parent=path.parent().ok_or_else(||err!(EINVAL,"RELEASE_PATH"))?;
        self.directory(parent)?;
        if self.files.len()>=64 {fail!(E2BIG,"RELEASE_FILE_COUNT");}
        let file=open_at(&self.directories[parent].file,&leaf(&path)?,false)?;
        let m=stat(&file)?;
        if m.uid()!=self.owner || m.mode()&0o022!=0 {fail!(EACCES,"RELEASE_FILE_PROTECTION");}
        let size=usize::try_from(m.len()).map_err(|_|err!(E2BIG,"RELEASE_INPUT_BOUND"))?;
        let total=self.bytes.checked_add(size).ok_or_else(||err!(E2BIG,"RELEASE_INPUT_BOUND"))?;
        if total>MAX_INPUT_BYTES {fail!(E2BIG,"RELEASE_INPUT_BOUND");}
        let bytes=read_exact(&file,maximum)?;let stamp=Stamp::of(&m);
        if stamp!=Stamp::of(&stat(&file)?) {fail!(ESTALE,"RELEASE_INPUT_CHANGED");}
        if self.files.values().any(|f|(f.stamp.dev,f.stamp.ino)==(stamp.dev,stamp.ino)) {fail!(EACCES,"RELEASE_INPUT_ALIAS");}
        let held=HeldInput {file,stamp,bytes};self.validate_file(&path,&held)?;
        let bytes=held.bytes.clone();self.files.insert(path,held);self.bytes=total;Ok(bytes)
    }
    fn validate_file(&self,path:&Path,held:&HeldInput)->EnclaveResult<()> {
        let parent=path.parent().ok_or_else(||err!(EINVAL,"RELEASE_PATH"))?;
        let named=open_at(&self.directories[parent].file,&leaf(path)?,false)?;
        if Stamp::of(&stat(&held.file)?)!=held.stamp || Stamp::of(&stat(&named)?)!=held.stamp
            || read_exact(&held.file,held.bytes.len())?!=held.bytes {fail!(ESTALE,"RELEASE_INPUT_CHANGED");}
        Ok(())
    }
    fn validate(&self)->EnclaveResult<()> {
        if let Some(error)=directory_observations(&self.directories,&self.base,None).first(){return Err(error.clone());}
        for (path,file) in &self.files {self.validate_file(path,file)?;}
        Ok(())
    }
    fn transition_observations(&self,transition:&DirectoryTransition<'_>)->Vec<EnclaveError> {
        let mut errors=directory_observations(&self.directories,&self.base,Some(transition));
        for (path,file) in &self.files {if let Err(error)=self.validate_file(path,file){errors.push(error);}}
        errors
    }
    fn reject_domain_aliases(&self,domains:&[PathBuf])->EnclaveResult<()> {
        for path in domains {
            if let Some(m)=probe_domain(&route(path)?)? {
                if self.directories.iter().any(|(p,d)|p!=&self.base&&(d.stamp.dev,d.stamp.ino)==(m.dev(),m.ino()))
                    ||self.files.values().any(|f|(f.stamp.dev,f.stamp.ino)==(m.dev(),m.ino())) {fail!(EACCES,"RELEASE_MUTATION_INODE_ALIAS");}
            }
        }
        Ok(())
    }
}
// Observe an excluded domain without following any links or trusting its owner.
// An absent suffix has no current inode; existing non-directory/symlink ancestry
// refuses. No output/custody/broker path is repaired, created or enumerated.
fn probe_domain(path:&Path)->EnclaveResult<Option<Metadata>> {
    let mut parent=File::open("/").map_err(|_|err!(EACCES,"RELEASE_DOMAIN_OBSERVATION"))?;
    let parts:Vec<_>=path.components().skip(1).collect();
    for (index,part) in parts.iter().enumerate() {
        let std::path::Component::Normal(name)=part else{fail!(EINVAL,"RELEASE_PATH");};
        let name=CString::new(name.as_bytes()).map_err(|_|err!(EINVAL,"RELEASE_PATH"))?;
        let flags=libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC
            |if index+1<parts.len(){libc::O_DIRECTORY}else{0};
        let fd=unsafe {libc::openat(parent.as_raw_fd(),name.as_ptr(),flags)};
        if fd<0 {
            if std::io::Error::last_os_error().raw_os_error()==Some(libc::ENOENT) {return Ok(None);}
            fail!(EACCES,"RELEASE_DOMAIN_OBSERVATION");
        }
        parent=unsafe {File::from_raw_fd(fd)};
        let m=stat(&parent)?;
        if index+1==parts.len() {
            if !m.is_file()&&!m.is_dir() {fail!(EACCES,"RELEASE_DOMAIN_OBSERVATION");}
            return Ok(Some(m));
        }
    }
    fail!(EINVAL,"RELEASE_PATH")
}

#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseState {
    version:u8,purpose:String,target_id:String,inventory_target:String,
    minimum_thresholds:MinimumThresholds,high_water:i64,trusted:TufTrustedState,
}
fn validate_trusted(state:&TufTrustedState,c:&ReleaseConfig)->EnclaveResult<()> {
    if state.v!=1||state.roots.len()>MAX_ROOTS {fail!(E2BIG,"RELEASE_TRUST_BOUND");}
    let mut total=0usize;
    for (raw,role) in std::iter::once((state.anchor.as_str(),Role::Root))
        .chain(state.roots.iter().map(|r|(r.as_str(),Role::Root)))
        .chain(state.timestamp.iter().map(|r|(r.as_str(),Role::Timestamp)))
        .chain(state.snapshot.iter().map(|r|(r.as_str(),Role::Snapshot)))
        .chain(state.targets.iter().map(|r|(r.as_str(),Role::Targets))) {
        total=total.checked_add(raw.len()).ok_or_else(||err!(E2BIG,"RELEASE_TRUST_BOUND"))?;
        if total>MAX_RETAINED {fail!(E2BIG,"RELEASE_TRUST_BOUND");}
        json::metadata(raw.as_bytes(),role,&c.minimum_thresholds,&c.inventory_target)?;
    }
    Ok(())
}
fn state_names(mode:ReleaseStateMode,path:&Path)->EnclaveResult<()> {
    let mut names=BTreeSet::new();
    for entry in std::fs::read_dir(path).map_err(|_|err!(EACCES,"RELEASE_STATE_DIRECTORY"))? {
        if names.len()>=4 {fail!(EACCES,"RELEASE_STATE_CONTENTS");}
        let name=entry.map_err(|_|err!(EIO,"RELEASE_STATE_DIRECTORY"))?.file_name();
        names.insert(name.into_string().map_err(|_|err!(EACCES,"RELEASE_STATE_CONTENTS"))?);
    }
    let expected=BTreeSet::from(["sealing.key".to_owned(),format!("{STORE}.sealed"),format!("{STORE}.gen")]);
    if (mode==ReleaseStateMode::FirstProvisioning&&!names.is_empty())
        ||(mode==ReleaseStateMode::Existing&&names!=expected) {fail!(EACCES,"RELEASE_STATE_MODE");}
    Ok(())
}
struct TrustOwner {
    store:SealedStore,state:ReleaseState,client:TufClient,clock:TrustedClock,
    path:PathBuf,persisted:Option<Vec<u8>>,poisoned:bool,saves:u64,saved_versions:Option<(u64,u64,u64)>,
    binding:StateBinding,_lease:StateDirectoryLease,
}
impl TrustOwner {
    fn current_disk(&self)->EnclaveResult<()> {
        if self.poisoned {fail!(EACCES,"RELEASE_AUTHORITY_POISONED");}
        self.binding.validate()?;
        self.current_disk_contents()
    }
    fn current_disk_with_transition(&self,transition:&DirectoryTransition<'_>)->EnclaveResult<()> {
        if self.poisoned {fail!(EACCES,"RELEASE_AUTHORITY_POISONED");}
        // Never invoke the sealed opener through a substituted state route.
        // An independent earlier refusal does not waive this binding gate.
        if let Some(error)=directory_observations(&self.binding.directories,&self.binding.base,Some(transition)).first() {
            return Err(error.clone());
        }
        self.current_disk_contents()
    }
    // The acceptance path validates this same ORIGINAL binding separately
    // against its one exact event before inspecting the ordinary disk state.
    fn current_disk_contents(&self)->EnclaveResult<()> {
        if self.poisoned {fail!(EACCES,"RELEASE_AUTHORITY_POISONED");}
        if let Some(expected)=&self.persisted {
            state_names(ReleaseStateMode::Existing,&self.path)?;
            let (store,loaded)=SealedStore::open_bounded_required(&self.path,STORE,MAX_STATE_ENVELOPE)?;
            if store.generation()!=self.store.generation() || !matches!(loaded,Loaded::State(ref body) if body==expected) {
                fail!(ESTALE,"RELEASE_STATE_CHANGED");
            }
        } else {
            // The required opener has created only its seed. Do not overwrite
            // an intervening state/checkpoint or reset a failed initialization.
            let mut count=0;
            for entry in std::fs::read_dir(&self.path).map_err(|_|err!(EIO,"RELEASE_STATE_DIRECTORY"))? {
                count+=1;
                if count>1||entry.map_err(|_|err!(EIO,"RELEASE_STATE_DIRECTORY"))?.file_name()!="sealing.key" {
                    fail!(EACCES,"RELEASE_STATE_MODE");
                }
            }
            if count!=1 {fail!(EACCES,"RELEASE_STATE_MODE");}
        }
        Ok(())
    }
    fn save(&mut self)->EnclaveResult<()> {
        let result=(|| {
            self.current_disk()?;
            self.state.high_water=self.clock.high_water();
            let bytes=serde_json::to_vec(&self.state).map_err(|_|err!(EIO,"RELEASE_STATE_ENCODING"))?;
            if bytes.len()>MAX_STATE_BODY {fail!(E2BIG,"RELEASE_STATE_BOUND");}
            self.store.save(&bytes)?;
            self.saves=self.saves.checked_add(1).ok_or_else(||err!(E2BIG,"RELEASE_STATE_GENERATION"))?;
            self.persisted=Some(bytes);
            self.saved_versions=Some(self.client.versions());
            self.current_disk()
        })();
        if result.is_err(){self.poisoned=true;}
        result
    }
}

/// Progress is public non-secret observation, never an approval capability.
/// Trust-state effects remain even when no capability is returned.
#[derive(Debug,Default)]
pub(crate) struct SoftwareApprovalProgress {
    pub(crate) process_hardening_attempted:bool,
    pub(crate) process_hardening_succeeded:bool,
    pub(crate) state_initialization_attempted:bool,
    pub(crate) state_initialized:bool,
    pub(crate) trust_state_saved:bool,
    pub(crate) generation:Option<u64>,
    pub(crate) versions:Option<(u64,u64,u64)>,
    pub(crate) high_water:Option<i64>,
    pub(crate) persistence_poisoned:bool,
}
impl SoftwareApprovalProgress {
    fn observe(&mut self,owner:&TrustOwner) {
        self.trust_state_saved=owner.saves>0;self.generation=Some(owner.store.generation());
        self.versions=owner.saved_versions;self.high_water=Some(owner.clock.high_water());
        self.persistence_poisoned=owner.poisoned;
    }
}
/// A refusal retains the original observations and any acquired state lease.
/// If a complete TrustOwner was established, its existing zeroizing key owner
/// now lives until this failure is dropped. Drop releases descriptors/lease and
/// the existing SealedStore key; it does not restore, remove or rewrite state.
/// No owner extraction, retry or conversion to approval is provided.
#[must_use="retain refusal owners through same-invocation final checks"]
pub(crate) struct SoftwareApprovalFailure {
    pub(crate) error:EnclaveError,pub(crate) operation_error:Option<EnclaveError>,
    pub(crate) progress:SoftwareApprovalProgress,
    /// All failed admission-final gates, in the existing precedence order.
    pub(crate) final_errors:Vec<EnclaveError>,
    inputs:Option<ProtectedInputs>,owner:Option<TrustOwner>,
    _pending_lease:Option<StateDirectoryLease>,
}
impl std::fmt::Debug for SoftwareApprovalFailure {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        f.debug_struct("SoftwareApprovalFailure").field("error",&self.error)
            .field("operation_error",&self.operation_error).field("progress",&self.progress)
            .field("final_errors",&self.final_errors).field("retained_owners",&"<redacted>").finish()
    }
}
impl SoftwareApprovalFailure {
    fn retain(error:EnclaveError,progress:SoftwareApprovalProgress,inputs:Option<ProtectedInputs>,
        owner:Option<TrustOwner>,pending_lease:Option<StateDirectoryLease>,
        finals:[EnclaveResult<()>;4])->Self {
        let final_errors:Vec<_>=finals.into_iter().filter_map(Result::err).collect();
        let (error,operation_error)=match final_errors.first() {
            Some(post)=>(post.clone(),Some(error)),None=>(error,None),
        };
        Self {error,operation_error,progress,final_errors,inputs,owner,_pending_lease:pending_lease}
    }
    /// Read-only observations of the ORIGINAL retained owners. Evaluate both
    /// available gates even if one refuses. No time observation/save, refresh,
    /// path adoption, lease reacquisition or approval can result. An empty
    /// vector does not clear the original refusal or prove native authority.
    pub(crate) fn retained_checks(&self)->Vec<EnclaveError> {
        let mut errors=Vec::new();
        if let Some(inputs)=&self.inputs {if let Err(e)=inputs.validate(){errors.push(e);}}
        if let Some(owner)=&self.owner {if let Err(e)=owner.current_disk(){errors.push(e);}}
        errors
    }
}

/// Opaque, same-invocation TUF approval of exact raw inventory bytes ONLY.
/// No Clone/Serialize/Deserialize/public constructor or native-release cast.
#[must_use="TUF approval must be combined with native/config and inactivity authority"]
pub(crate) struct SoftwareApproval {
    inputs:ProtectedInputs,owner:TrustOwner,config:ReleaseConfig,domains:Vec<PathBuf>,
    descriptor_sha256:String,inventory_sha256:String,poisoned:bool,initialized:bool,
    checked:CheckedDeploymentTarget,
    // Fixed role slots retain actual immutable checked-context-bound events
    // even when this owner's ancestry has no matching node for a support root.
    directory_changes:[Option<Arc<DirectoryModeChange>>;2],
}

/// A historical recipient refusal. The caller must retain its SAME poisoned
/// SoftwareApproval, host guard and EX; this value cannot extract or revive any
/// owner. The opaque proof and exact installed-overlay counts survive refusal.
#[must_use="retain same approval/guard/EX and actual event on recipient refusal"]
pub(crate) struct DirectoryModeAcceptanceFailure {
    /// First boundary refusal, or first final refusal if the boundary passed.
    pub(crate) error:EnclaveError,
    /// Every independently observed pre-install boundary refusal.
    pub(crate) boundary_errors:Vec<EnclaveError>,
    /// Every independently observed final/currentness refusal.
    pub(crate) final_errors:Vec<EnclaveError>,
    /// Original input nodes overlaid by this attempt before any late refusal.
    pub(crate) input_overlays_installed:usize,
    /// Original state-binding nodes overlaid by this attempt.
    pub(crate) state_overlays_installed:usize,
    /// Whether this attempt recorded the proof, including zero-node recipients.
    pub(crate) proof_recorded:bool,
    event:Arc<DirectoryModeChange>,
}
impl std::fmt::Debug for DirectoryModeAcceptanceFailure {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        f.debug_struct("DirectoryModeAcceptanceFailure").field("error",&self.error)
            .field("boundary_errors",&self.boundary_errors).field("final_errors",&self.final_errors)
            .field("input_overlays_installed",&self.input_overlays_installed)
            .field("state_overlays_installed",&self.state_overlays_installed)
            .field("proof_recorded",&self.proof_recorded)
            .field("event",&self.event).finish_non_exhaustive()
    }
}
impl DirectoryModeAcceptanceFailure {
    /// Borrow only historical evidence; this does not supply recipient success.
    pub(crate) fn event(&self)->&DirectoryModeChange {&self.event}
}

fn append_errors(errors:&mut Vec<EnclaveError>,results:impl IntoIterator<Item=EnclaveResult<()>>) {
    errors.extend(results.into_iter().filter_map(Result::err));
}
fn require_native_root(native:bool,uid:u32)->EnclaveResult<()> {
    if !native {fail!(ENOSYS,"RELEASE_NATIVE_REQUIRED");}
    if uid!=0 {fail!(EACCES,"RELEASE_ROOT_REQUIRED");}
    Ok(())
}
fn native_boundary(guard:&mut HostMaintenanceGuard)->EnclaveResult<()> {
    require_native_root(cfg!(target_os="macos"),unsafe{libc::geteuid()})?;
    guard.assert_held()
}
fn scope_current(checked:&CheckedDeploymentTarget,c:&ReleaseConfig,inventory_sha256:&str)->EnclaveResult<()> {
    let raw=checked.read_artifact_inventory()?;
    if checked.descriptor_sha256()!=c.descriptor_sha256 || checked.target().target_id!=c.target_id
        ||checked.target().profile!=c.profile||checked.target().signing_identity_mode!=c.signing_identity_mode
        ||hex::encode(Sha256::digest(&raw))!=inventory_sha256 {fail!(ESTALE,"RELEASE_CONTEXT_CHANGED");}
    Ok(())
}
impl SoftwareApproval {
    pub(crate) fn inventory_sha256(&self)->&str {&self.inventory_sha256}
    pub(crate) fn descriptor_sha256(&self)->&str {&self.descriptor_sha256}
    fn original_context(&self,checked:&CheckedDeploymentTarget)->EnclaveResult<()> {
        if self.checked.config_path()!=checked.config_path()||self.checked.target()!=checked.target()
            ||self.checked.descriptor_sha256()!=checked.descriptor_sha256() {
            fail!(ESTALE,"RELEASE_ORIGINAL_CONTEXT_CHANGED");
        }Ok(())
    }
    /// Denial-only identity query over both original retained directory owners.
    /// This neither rechecks them nor permits a caller to mutate another inode.
    pub(crate) fn retains_directory_identity(&self,dev:u64,ino:u64)->bool {
        retains_directory_identity(&self.inputs.directories,dev,ino)
            ||retains_directory_identity(&self.owner.binding.directories,dev,ino)
    }
    /// Refuse runtime operator inputs overlapping actual SOFTWARE inputs/state.
    /// Callers retain and recheck their original sources and genuine guard/EX;
    /// success here supplies no operator choice, freshness or runtime authority.
    /// No save, wall-clock observation, refresh, adoption or state mutation runs.
    pub(crate) fn assert_external_runtime_sources_separate(&self,sources:&[(&Path,&File)])->EnclaveResult<()> {
        let mut errors=Vec::new();
        if self.poisoned||self.owner.poisoned {errors.push(err!(EACCES,"RELEASE_AUTHORITY_POISONED"));}
        for result in [self.inputs.validate(),self.owner.current_disk(),
            external_runtime_sources_separate(&self.inputs,&self.config.approval_repository,
                &self.config.trust_state_directory,sources),
            self.inputs.validate(),self.owner.current_disk()] {
            if let Err(error)=result {errors.push(error);}
        }
        errors.first().cloned().map_or(Ok(()),Err)
    }
    /// Accept only an actual original-FD chmod event from the SAME retained EX.
    /// Both recipient maps are verified before either receives an overlay.
    /// The original cached stamps and every original file remain unchanged.
    /// This supplies no born provenance, visibility or installation authority.
    pub(crate) fn accept_directory_change(&mut self,checked:&CheckedDeploymentTarget,
        guard:&mut HostMaintenanceGuard,same_ex:&mut ExclusiveStartupLease,event:&Arc<DirectoryModeChange>)
        ->Result<(),DirectoryModeAcceptanceFailure> {
        let mut boundary_errors=Vec::new();let mut final_errors=Vec::new();
        let mut input_overlays_installed=0;let mut state_overlays_installed=0;let mut installed=false;
        let slot=match event.ancestor(){PrivateBirthAncestor::SupportRoot=>0,PrivateBirthAncestor::NonceRoot=>1};
        if self.poisoned||self.owner.poisoned {boundary_errors.push(err!(EACCES,"RELEASE_AUTHORITY_POISONED"));}
        if self.directory_changes[slot].is_some() {boundary_errors.push(err!(EALREADY,"RELEASE_DIRECTORY_MODE_REPLAY"));}
        if slot==1&&self.directory_changes[0].is_none() {boundary_errors.push(err!(EACCES,"RELEASE_DIRECTORY_MODE_SUPPORT_FIRST"));}
        if !event.durability_completed() {boundary_errors.push(err!(EIO,"RELEASE_DIRECTORY_MODE_NOT_DURABLE"));}
        let transition=DirectoryTransition {checked,event};
        // No normal old-mode gate runs before this bounded transition-aware
        // pass. A real wrong old identity, unrelated change or preexisting
        // poison still refuses; no exception is available for another node.
        append_errors(&mut boundary_errors,[self.original_context(checked),native_boundary(guard),same_ex.assert_directory_change(checked,event)]);
        boundary_errors.extend(self.inputs.transition_observations(&transition));
        boundary_errors.extend(directory_observations(&self.owner.binding.directories,&self.owner.binding.base,Some(&transition)));
        append_errors(&mut boundary_errors,[self.owner.current_disk_with_transition(&transition),
            self.inputs.reject_domain_aliases(&self.domains),scope_current(checked,&self.config,&self.inventory_sha256)]);
        boundary_errors.extend(self.inputs.transition_observations(&transition));
        boundary_errors.extend(directory_observations(&self.owner.binding.directories,&self.owner.binding.base,Some(&transition)));
        append_errors(&mut boundary_errors,[native_boundary(guard),same_ex.assert_directory_change(checked,event)]);
        if boundary_errors.is_empty() {
            // No callback, lookup or fallible action between the two installs.
            input_overlays_installed=install_directory_change(&mut self.inputs.directories,event);
            state_overlays_installed=install_directory_change(&mut self.owner.binding.directories,event);
            self.directory_changes[slot]=Some(Arc::clone(event));installed=true;
        }
        // An earlier refusal cannot skip available real checks or revive this
        // owner. If no overlay was installed, observe only the one exact event
        // target through the same transition-aware gate once more.
        if installed {
            append_errors(&mut final_errors,[self.inputs.validate(),self.owner.current_disk()]);
        }else{
            final_errors.extend(self.inputs.transition_observations(&transition));
            final_errors.extend(directory_observations(&self.owner.binding.directories,&self.owner.binding.base,Some(&transition)));
            append_errors(&mut final_errors,[self.owner.current_disk_with_transition(&transition)]);
        }
        append_errors(&mut final_errors,[scope_current(checked,&self.config,&self.inventory_sha256),
            native_boundary(guard),same_ex.assert_directory_change(checked,event)]);
        if installed {
            // Includes actual expiry, observed-time floors, guarded saves and
            // every existing independently evaluated final check. A late
            // refusal retains BOTH overlays and the SAME opaque event.
            final_errors.extend(self.current_errors(checked,guard));
        }
        let error=boundary_errors.first().or_else(||final_errors.first()).cloned();
        if let Some(error)=error {
            self.poisoned=true;
            Err(DirectoryModeAcceptanceFailure {error,boundary_errors,final_errors,
                input_overlays_installed,state_overlays_installed,proof_recorded:installed,event:Arc::clone(event)})
        }else{Ok(())}
    }
    /// Denial-only assertion that this SAME approval accepted this exact event.
    /// Fixed role slots also prove acceptance for zero-node recipients. This
    /// performs no time observation, save, new acceptance or fresh approval;
    /// the consuming wrapper must separately run its normal assert_current.
    pub(crate) fn assert_accepted_directory_change(&mut self,checked:&CheckedDeploymentTarget,
        same_ex:&mut ExclusiveStartupLease,event:&Arc<DirectoryModeChange>)->EnclaveResult<()> {
        let mut errors=Vec::new();
        let slot=match event.ancestor(){PrivateBirthAncestor::SupportRoot=>0,PrivateBirthAncestor::NonceRoot=>1};
        if self.poisoned||self.owner.poisoned {errors.push(err!(EACCES,"RELEASE_AUTHORITY_POISONED"));}
        if !self.directory_changes[slot].as_ref().is_some_and(|accepted|Arc::ptr_eq(accepted,event)) {
            errors.push(err!(EACCES,"RELEASE_DIRECTORY_MODE_NOT_ACCEPTED"));
        }
        append_errors(&mut errors,[self.original_context(checked),same_ex.assert_directory_change(checked,event),
            self.inputs.validate(),self.owner.current_disk(),self.inputs.reject_domain_aliases(&self.domains),
            scope_current(checked,&self.config,&self.inventory_sha256),self.inputs.validate(),
            self.owner.current_disk(),same_ex.assert_directory_change(checked,event)]);
        if let Some(error)=errors.first().cloned(){self.poisoned=true;Err(error)}else{Ok(())}
    }
    /// Denial-only history/current-originals query after an owned marker clear.
    /// The exact previously accepted event, including zero-node recipients,
    /// remains required. This does NOT assert SAME EX or Dedicated acquisition,
    /// own marker removal, freshness, guard, readiness or installation authority.
    /// A concrete consuming caller separately retains and verifies its genuine
    /// own-removal proof and SAME acquisition's Dedicated transition, and runs
    /// normal assert_current. No inhibited-EX check, time observation or save.
    pub(crate) fn assert_accepted_directory_change_history(&mut self,checked:&CheckedDeploymentTarget,
        event:&Arc<DirectoryModeChange>)->EnclaveResult<()> {
        let mut errors=Vec::new();
        let slot=match event.ancestor(){PrivateBirthAncestor::SupportRoot=>0,PrivateBirthAncestor::NonceRoot=>1};
        if self.poisoned||self.owner.poisoned {errors.push(err!(EACCES,"RELEASE_AUTHORITY_POISONED"));}
        if !self.directory_changes[slot].as_ref().is_some_and(|accepted|Arc::ptr_eq(accepted,event)) {
            errors.push(err!(EACCES,"RELEASE_DIRECTORY_MODE_NOT_ACCEPTED"));
        }
        append_errors(&mut errors,[self.original_context(checked),self.inputs.validate(),self.owner.current_disk(),
            self.inputs.reject_domain_aliases(&self.domains),scope_current(checked,&self.config,&self.inventory_sha256),
            self.inputs.validate(),self.owner.current_disk()]);
        if let Some(error)=errors.first().cloned(){self.poisoned=true;Err(error)}else{Ok(())}
    }
    /// Recheck on every use boundary. Any refusal permanently poisons this
    /// same-invocation owner; a successful old receipt cannot revive it.
    pub(crate) fn assert_current(&mut self,checked:&CheckedDeploymentTarget,
        guard:&mut HostMaintenanceGuard)->EnclaveResult<()> {
        self.current_errors(checked,guard).first().cloned().map_or(Ok(()),Err)
    }
    // Same established first-error precedence as assert_current, with all
    // actually evaluated independent final refusals available to acceptance.
    fn current_errors(&mut self,checked:&CheckedDeploymentTarget,guard:&mut HostMaintenanceGuard)->Vec<EnclaveError> {
        if self.poisoned||self.owner.poisoned {return vec![err!(EACCES,"RELEASE_AUTHORITY_POISONED")];}
        // A process that lost native/root authority may not write trust state.
        if !cfg!(target_os="macos")||unsafe{libc::geteuid()}!=0 {
            self.poisoned=true;return vec![err!(EACCES,"RELEASE_NATIVE_ROOT_REQUIRED")];
        }
        let guard_before=native_boundary(guard);
        let reported=match wall_time() {Ok(t)=>t,Err(e)=>{
            self.poisoned=true;let mut errors=vec![e];append_errors(&mut errors,[guard_before]);return errors;
        }};
        let now=self.owner.clock.now(reported);
        let result=(|| {
            self.inputs.validate()?;self.inputs.reject_domain_aliases(&self.domains)?;
            scope_current(checked,&self.config,&self.inventory_sha256)?;
            // Config/root/repo/inventory are held and byte-rechecked above;
            // no refresh from a substituted later generation is permitted.
            self.owner.client.ensure_fresh(now)?;
            guard_before.clone()?;native_boundary(guard)
        })();
        // Persist observed time even on expiry/context refusal; own state lease
        // is independent of the cooperative host guard. Never reset the floor.
        let binding=self.inputs.validate();
        // Independent held state ancestry remains authoritative even if some
        // other admission input changed. Preserve this observed time floor.
        let saved=self.owner.save();
        let final_context=scope_current(checked,&self.config,&self.inventory_sha256);
        let final_guard=native_boundary(guard);
        let final_fresh=(||self.owner.client.ensure_fresh(self.owner.clock.now(wall_time()?)))();
        // Never return approval after a slow state save crossed expiry. On that
        // refusal persist the newly observed time as well, under its own lease.
        let expiry_save=if final_fresh.is_err(){self.owner.save()}else{Ok(())};
        let mut errors=Vec::new();
        append_errors(&mut errors,[binding,saved,expiry_save,final_context,final_guard,final_fresh,result,guard_before]);
        if !errors.is_empty(){self.poisoned=true;}errors
    }
    pub(crate) fn progress(&self)->SoftwareApprovalProgress {
        let mut p=SoftwareApprovalProgress {process_hardening_attempted:true,process_hardening_succeeded:true,
            state_initialization_attempted:self.initialized,
            state_initialized:self.initialized,..SoftwareApprovalProgress::default()};
        p.observe(&self.owner);p
    }
}

/// Authenticate public inputs and persist rollback/time floors before issuing
/// ONLY an exact-inventory TUF approval. Caller must preserve this owner/lease
/// and guard through use. Explicit mode is not host-installation authorization.
pub(crate) fn admit_software_approval(checked:&CheckedDeploymentTarget,config_path:&Path,
    mode:ReleaseStateMode,guard:&mut HostMaintenanceGuard)->Result<SoftwareApproval,SoftwareApprovalFailure> {
    let mut progress=SoftwareApprovalProgress::default();
    let mut owner:Option<TrustOwner>=None;
    let mut held_inputs:Option<ProtectedInputs>=None;
    // Install immediately after acquisition: every later refusal must retain
    // this same lock even before a complete TrustOwner can be constructed.
    let mut pending_lease:Option<StateDirectoryLease>=None;
    let operation=(|| {
        native_boundary(guard)?;
        held_inputs=Some(ProtectedInputs::new()?);
        let inputs=held_inputs.as_mut().expect("held inputs");
        let config_raw=inputs.read(config_path,MAX_CONFIG)?;
        let c=config(&config_raw,checked.target(),checked.descriptor_sha256())?;
        let domains=isolation(&c,config_path,checked.config_path(),checked.target())?;
        let descriptor=inputs.read(checked.config_path(),MAX_CONFIG)?;
        if hex::encode(Sha256::digest(&descriptor))!=checked.descriptor_sha256() {fail!(ESTALE,"RELEASE_CONTEXT_CHANGED");}
        let inventory=inputs.read(&checked.target().expected_artifacts_manifest,MAX_METADATA)?;
        let inventory_sha256=hex::encode(Sha256::digest(&inventory));
        scope_current(checked,&c,&inventory_sha256)?;
        let pin=inputs.read(&c.bootstrap_root_file,MAX_METADATA)?;
        if hex::encode(Sha256::digest(&pin))!=c.bootstrap_root_sha256 {fail!(EACCES,"RELEASE_BOOTSTRAP_PIN");}
        json::metadata(&pin,Role::Root,&c.minimum_thresholds,&c.inventory_target)?;
        let path=route(&c.trust_state_directory)?;inputs.directory(&path)?;
        let state_meta=stat(&inputs.directories[&path].file)?;
        if state_meta.uid()!=0||state_meta.mode()&0o7777!=0o700 {fail!(EACCES,"RELEASE_STATE_PROTECTION");}
        inputs.directory(&route(&c.approval_repository)?)?;
        inputs.validate()?;inputs.reject_domain_aliases(&domains)?;native_boundary(guard)?;
        state_names(mode,&path)?;
        pending_lease=Some(StateDirectoryLease::acquire(&path)?);
        inputs.validate()?;state_names(mode,&path)?;
        // Authenticate bootstrap before the first required opener creates seed.
        let bootstrap=if mode==ReleaseStateMode::FirstProvisioning {Some(TufClient::bootstrap(&pin)?)}else{None};
        progress.state_initialization_attempted=mode==ReleaseStateMode::FirstProvisioning;
        let binding=StateBinding::capture(inputs,&path)?;
        let reported_time=wall_time()?;
        // This may change process core-dump/attach/crash-report policy even on
        // refusal. No seed has been read or created by this module before it.
        progress.process_hardening_attempted=true;
        if !enclave_core::resource::harden_process() {fail!(EACCES,"RELEASE_PROCESS_HARDENING");}
        progress.process_hardening_succeeded=true;
        native_boundary(guard)?;
        let (store,loaded)=SealedStore::open_bounded_required(&path,STORE,MAX_STATE_ENVELOPE)?;
        let (state,client,persisted)=match (mode,loaded) {
            (ReleaseStateMode::FirstProvisioning,Loaded::Fresh)=>{
                progress.state_initialized=true;
                let client=bootstrap.ok_or_else(||err!(EACCES,"RELEASE_STATE_MODE"))?;
                let state=ReleaseState {version:1,purpose:PURPOSE.into(),target_id:c.target_id.clone(),
                    inventory_target:c.inventory_target.clone(),minimum_thresholds:c.minimum_thresholds.clone(),
                    high_water:c.minimum_time_unix,trusted:client.export()?};
                (state,client,None)
            }
            (ReleaseStateMode::Existing,Loaded::State(bytes))=>{
                let (state,client)=restore_state(&bytes,&c,&pin)?;
                (state,client,Some(bytes))
            }
            _=>fail!(EACCES,"RELEASE_STATE_MODE"),
        };
        let clock=TrustedClock::resumed(reported_time,state.high_water.max(c.minimum_time_unix));
        let saved_versions=if persisted.is_some(){Some(client.versions())}else{None};
        owner=Some(TrustOwner {store,state,client,clock,path,persisted,poisoned:false,saves:0,saved_versions,binding,
            _lease:pending_lease.take().expect("acquired state lease")});
        let trust=owner.as_mut().expect("installed owner");
        trust.state.minimum_thresholds=c.minimum_thresholds.clone();
        // First initialization and observed time survive even a bad repository.
        trust.clock.now(wall_time()?);trust.save()?;
        let mut roots=BTreeMap::new();let mut count=0;
        for entry in std::fs::read_dir(&c.approval_repository).map_err(|_|err!(EACCES,"RELEASE_REPOSITORY"))? {
            count+=1;if count>MAX_ROOTS+3 {fail!(E2BIG,"RELEASE_REPOSITORY_BOUND");}
            let name=entry.map_err(|_|err!(EIO,"RELEASE_REPOSITORY"))?.file_name();
            let name=name.to_str().ok_or_else(||err!(EINVAL,"RELEASE_REPOSITORY_NAME"))?;
            if ["timestamp.json","snapshot.json","targets.json"].contains(&name) {continue;}
            let version=name.strip_suffix(".root.json").ok_or_else(||err!(EINVAL,"RELEASE_REPOSITORY_NAME"))?;
            let n=version.parse::<u64>().map_err(|_|err!(EINVAL,"RELEASE_ROOT_CHAIN"))?;
            if n==0||n>u32::MAX as u64||n.to_string()!=version||roots.len()>=MAX_ROOTS {fail!(EINVAL,"RELEASE_ROOT_CHAIN");}
            roots.insert(n,name.to_owned());
        }
        let mut root_bytes=Vec::new();
        for (version,name) in roots {
            let bytes=inputs.read(&c.approval_repository.join(name),MAX_METADATA)?;
            root_bytes.push((version,bytes));
        }
        let timestamp=inputs.read(&c.approval_repository.join("timestamp.json"),MAX_METADATA)?;
        let snapshot=inputs.read(&c.approval_repository.join("snapshot.json"),MAX_METADATA)?;
        let targets=inputs.read(&c.approval_repository.join("targets.json"),MAX_METADATA)?;
        let now=trust.clock.now(wall_time()?);
        let next=refresh_verified(&trust.client,&root_bytes,&timestamp,&snapshot,&targets,now,&c)?;
        let exported=next.export()?;
        // No provisional root/role state is saved before complete refresh;
        // previously committed floors remain on every refresh refusal.
        trust.state.trusted=exported;trust.client=next;
        inputs.validate()?;inputs.reject_domain_aliases(&domains)?;native_boundary(guard)?;
        trust.save()?;
        // TUF floors are committed BEFORE inventory schema/native/config errors.
        verify_inventory(&trust.client,&c,checked.target(),checked.descriptor_sha256(),&inventory,now)?;
        inputs.validate()?;inputs.reject_domain_aliases(&domains)?;
        scope_current(checked,&c,&inventory_sha256)?;native_boundary(guard)?;
        trust.client.ensure_fresh(trust.clock.now(wall_time()?))?;trust.save()?;
        inputs.validate()?;scope_current(checked,&c,&inventory_sha256)?;native_boundary(guard)?;
        trust.client.ensure_fresh(trust.clock.now(wall_time()?))?;
        Ok(SoftwareApproval {inputs:held_inputs.take().expect("held inputs"),owner:owner.take().expect("live owner"),config:c,domains,
            descriptor_sha256:checked.descriptor_sha256().into(),inventory_sha256,poisoned:false,
            initialized:mode==ReleaseStateMode::FirstProvisioning,checked:checked.clone(),directory_changes:[None,None]})
    })();
    match operation {
        Ok(cap)=>Ok(cap),
        Err(error)=>{
            let save_error=if let Some(trust)=owner.as_mut() {
                if let Ok(now)=wall_time(){trust.clock.now(now);}
                // TrustOwner checks current named disk state before every save.
                // Root/lease and path validity are still required on refusal.
                let save=if cfg!(target_os="macos")&&unsafe{libc::geteuid()}==0 {trust.save()}
                    else{Err(err!(EACCES,"RELEASE_ROOT_REQUIRED"))};
                progress.observe(trust);
                save.err()
            }else{None};
            let binding=held_inputs.as_ref().map(ProtectedInputs::validate).unwrap_or(Ok(()));
            let context=checked.read_artifact_inventory();
            let exclusion=native_boundary(guard);
            Err(SoftwareApprovalFailure::retain(error,progress,held_inputs,owner,pending_lease,
                [save_error.map_or(Ok(()),Err),binding,context.map(|_|()),exclusion]))
        }
    }
}

fn verify_inventory(client:&TufClient,c:&ReleaseConfig,target:&DeploymentTarget,
    descriptor:&str,raw:&[u8],now:i64)->EnclaveResult<target_plan::TargetInstallPlan> {
    client.verify_target(&c.inventory_target,raw,now)?;
    json::strict(raw,MAX_METADATA)?;
    if target.target_id!=c.target_id||target.profile!=c.profile||target.signing_identity_mode!=c.signing_identity_mode
        ||descriptor!=c.descriptor_sha256 {fail!(EACCES,"RELEASE_INVENTORY_SCOPE");}
    let plan=target_plan::describe(target,descriptor,raw)?;
    if !plan.missing_required_files.is_empty() {fail!(EINVAL,"RELEASE_INVENTORY_INCOMPLETE");}
    Ok(plan)
}

fn restore_state(bytes:&[u8],c:&ReleaseConfig,pin:&[u8])->EnclaveResult<(ReleaseState,TufClient)> {
    let value=json::strict(bytes,MAX_STATE_BODY)?;
    json::closed(&value,&["version","purpose","target_id","inventory_target","minimum_thresholds","high_water","trusted"],&[])?;
    json::closed(&value["trusted"],&["v","anchor","roots","timestamp","snapshot","targets"],&[])?;
    let state:ReleaseState=serde_json::from_slice(bytes).map_err(|_|err!(EACCES,"RELEASE_STATE_SCHEMA"))?;
    if state.version!=1||state.purpose!=PURPOSE||state.target_id!=c.target_id
        ||state.inventory_target!=c.inventory_target||!(1..=MAX_TIME).contains(&state.high_water)
        ||!state.minimum_thresholds.valid(false)||!c.minimum_thresholds.preserves(&state.minimum_thresholds) {
        fail!(EACCES,"RELEASE_STATE_SCOPE");
    }
    validate_trusted(&state.trusted,c)?;
    let client=TufClient::restore(&state.trusted)?;
    if !client.chain_contains(pin) {fail!(EACCES,"RELEASE_BOOTSTRAP_PIN");}
    Ok((state,client))
}

// Shared by actual production loading and pure signed-metadata tests. This
// returns only verified TUF state, never SoftwareApproval or a release provider.
fn refresh_verified(current:&TufClient,roots:&[(u64,Vec<u8>)],timestamp:&[u8],snapshot:&[u8],
    targets:&[u8],now:i64,c:&ReleaseConfig)->EnclaveResult<TufClient> {
    if roots.len()>MAX_ROOTS {fail!(E2BIG,"RELEASE_ROOT_CHAIN");}
    let mut next=current.clone();let mut previous=0;
    for (version,bytes) in roots {
        if *version<=previous {fail!(EINVAL,"RELEASE_ROOT_CHAIN");}previous=*version;
        json::metadata(bytes,Role::Root,&c.minimum_thresholds,&c.inventory_target)?;
        let root:enclave_crypto::tuf::Signed<enclave_crypto::tuf::RootMeta>=serde_json::from_slice(bytes)
            .map_err(|_|err!(EINVAL,"RELEASE_ROOT_CHAIN"))?;
        if root.signed.version!=*version {fail!(EINVAL,"RELEASE_ROOT_CHAIN");}
        if *version>next.root().version {
            if *version!=next.root().version.checked_add(1).ok_or_else(||err!(EINVAL,"RELEASE_ROOT_CHAIN"))? {fail!(EACCES,"RELEASE_ROOT_CHAIN");}
            next.update_root(bytes)?;
        }else if !next.chain_contains(bytes) {fail!(EACCES,"RELEASE_ROOT_CHAIN");}
    }
    for (bytes,role) in [(timestamp,Role::Timestamp),(snapshot,Role::Snapshot),(targets,Role::Targets)] {
        json::metadata(bytes,role,&c.minimum_thresholds,&c.inventory_target)?;
    }
    next.refresh(timestamp,snapshot,targets,now)?;
    validate_trusted(&next.export()?,c)?;
    Ok(next)
}

#[cfg(test)]
#[path="target_release_tests.rs"]
mod tests;
