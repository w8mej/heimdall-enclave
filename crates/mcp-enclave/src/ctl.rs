//! Daemon lifecycle and operator commands.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use enclave_core::daemon::{DaemonId, MIB, STEADY_STATE_BUDGET_MIB, UID_702_705_BUDGET_MIB};
use enclave_core::error::EnclaveResult;
use enclave_core::ipc::{Client, DaemonStatus};
use enclave_core::profile::Profile;
use enclave_core::{err, fail};
use enclave_model_runnerd::manifest::{ExecutionClass, ModelManifestV1};
use enclave_model_runnerd::service::{RunnerRequest, RunnerResponse};
use enclave_swarm_syncd::service::{CasRequest, CasResponse};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::devtuf::{read_repo, restrict, DevRepo};

#[path = "ctl_target_lifecycle.rs"]
mod target_lifecycle;
pub(crate) use target_lifecycle::{HeldPaths, HeldFile};
#[path = "ctl_target_native.rs"]
mod target_native;
pub(crate) use target_native::{selected_core_start_with_retained_guard,RetainedGuardCoreStartOutcome};
#[path = "ctl_target_intent.rs"]
mod target_intent;
pub use target_intent::{selected_intent_start, TargetIntentStartReport};
#[path = "ctl_target_supervisor.rs"]
mod target_supervisor;
pub use target_supervisor::{selected_supervisor_start, TargetSupervisorStartReport};
#[path = "ctl_target_aux_stop.rs"]
mod target_aux_stop;
#[path = "ctl_target_broker_stop.rs"]
mod target_broker_stop;
pub use target_native::{selected_auxiliary_stop, selected_broker_stop, selected_core_start, selected_core_stop,
    TargetAuxiliaryStopReport, TargetBrokerStopReport, TargetLifecycleReport};

/// Where the CLI talks to the daemons.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Env {
    /// Development (same-UID, simulated hardware) mode.
    pub dev: bool,
    /// Profile.
    pub profile: Profile,
    /// Socket directory.
    pub socket_dir: PathBuf,
    /// Journal directory.
    pub audit_dir: PathBuf,
    /// Dev state directory.
    pub state_dir: PathBuf,
}

impl Env {
    /// Development layout under `state`.
    pub fn dev(state: &Path, profile: Profile) -> Self {
        Self {
            dev: true,
            profile,
            socket_dir: state.join("run"),
            audit_dir: state.join("log"),
            state_dir: state.to_owned(),
        }
    }
    /// Production layout.
    pub fn production(profile: Profile) -> Self {
        Self {
            dev: false,
            profile,
            socket_dir: enclave_core::runtime::DEFAULT_SOCKET_DIR.into(),
            audit_dir: enclave_core::runtime::DEFAULT_AUDIT_DIR.into(),
            state_dir: "/var/db/enclave".into(),
        }
    }
    /// Production paths from the already selected protected target. Kernel UIDs
    /// and code requirements remain the same as the ordinary production mesh.
    pub fn production_for_target(target: &enclave_core::deployment::CheckedDeploymentTarget) -> EnclaveResult<Self> {
        let selected = enclave_core::deployment::selected()
            .ok_or_else(|| err!(EACCES, "DEPLOYMENT_CONTEXT_REQUIRED"))?;
        if selected.config_path() != target.config_path() || selected.target() != target.target() {
            fail!(EACCES, "DEPLOYMENT_CONTEXT_MISMATCH");
        }
        let target = target.target();
        Ok(Self { dev: false, profile: target.profile,
            socket_dir: target.layout.socket_root.clone(), audit_dir: target.layout.audit_root.clone(),
            state_dir: target.layout.state_root.clone() })
    }
    /// Inert routes for restrictive teardown only. This does not select a
    /// general deployment context or grant start/credential authority.
    pub fn production_for_teardown(target: &enclave_core::deployment::teardown::TeardownDeploymentTarget) -> EnclaveResult<Self> {
        target.recheck()?;
        let target=target.target();
        Ok(Self {dev:false,profile:target.profile,socket_dir:target.layout.socket_root.clone(),
            audit_dir:target.layout.audit_root.clone(),state_dir:target.layout.state_root.clone()})
    }
    /// Expected server UID.
    pub fn uid_of(&self, d: DaemonId) -> u32 {
        if self.dev {
            enclave_core::ipc::geteuid()
        } else {
            d.uid()
        }
    }
    /// Mutually authenticated connection.
    pub fn connect(&self, d: DaemonId) -> EnclaveResult<Client> {
        // Production: also pin the daemon's signing identity (GAP-02).
        let req = (!self.dev).then(|| enclave_core::codesign::CodeRequirement::daemon(d));
        Client::connect_verified(
            &self.socket_dir.join(d.socket_name()),
            self.uid_of(d),
            req.as_ref(),
        )
    }
}

/// Provision only the selected target's local IFC grant key. This preserves
/// existing key bytes, requires already-provisioned private daemon directories
/// and never selects defaults or creates independent enrollment/issuer keys.
/// The unselected installation path retains its existing launchd helper.
pub fn provision_target_grant_key(env: &Env, requested_state: Option<&Path>) -> EnclaveResult<String> {
    let selected=enclave_core::deployment::selected()
        .ok_or_else(||err!(EACCES,"DEPLOYMENT_CONTEXT_REQUIRED"))?;
    target_grant_key::provision(env,requested_state,selected)
}

mod target_grant_key {
    use super::*;
    use std::{ffi::CString,fs::{File,Metadata},io::{Read,Write},
        os::{fd::{AsRawFd,FromRawFd},unix::{ffi::OsStrExt,fs::MetadataExt}}};
    use enclave_core::{deployment::{CheckedDeploymentTarget,DeploymentTarget,normalized_path},
        secret::SecretBytes};

    const LOCK:&str=".ifc-grant-provision.lock";
    const LIMIT:usize=128;
    // No deserializer, public constructor, runtime flag or environment lookup
    // can choose ownership. The production entry point supplies only these
    // fixed daemon identities. Neutral ownership exists solely in unit tests.
    #[derive(Clone,Copy)]
    struct KeyOwner {uid:u32,gid:u32}
    impl KeyOwner {fn daemon(d:DaemonId)->Self {Self {uid:d.uid(),gid:d.gid()}}}
    #[derive(Clone,Copy)]
    struct KeyOwners {ifc:KeyOwner,custody:KeyOwner}
    impl KeyOwners {
        fn production()->Self {Self {ifc:KeyOwner::daemon(DaemonId::AgentRuntime),custody:KeyOwner::daemon(DaemonId::CustodyVault)}}
        #[cfg(test)]
        fn neutral()->Self {Self {ifc:KeyOwner {uid:0,gid:0},custody:KeyOwner {uid:0,gid:0}}}
    }

    fn bind<'a>(env:&Env,requested:Option<&Path>,target:&'a DeploymentTarget)->EnclaveResult<&'a Path> {
        target.validate()?;
        if env.dev || env.profile!=target.profile || env.state_dir!=target.layout.state_root
            || env.socket_dir!=target.layout.socket_root || env.audit_dir!=target.layout.audit_root {
            fail!(EACCES,"DEPLOYMENT_GRANT_CONTEXT_MISMATCH");
        }
        if requested.is_some_and(|path|path!=target.layout.state_root) {
            fail!(EACCES,"DEPLOYMENT_GRANT_STATE_MISMATCH");
        }
        Ok(&target.layout.state_root)
    }
    fn name(value:&str)->EnclaveResult<CString> {
        CString::new(value).map_err(|_|err!(EINVAL,"GRANT_KEY_PATH"))
    }
    fn metadata(file:&File)->EnclaveResult<Metadata> {
        file.metadata().map_err(|_|err!(EIO,"GRANT_KEY_METADATA"))
    }
    fn protected(m:&Metadata)->bool {m.uid()==0 && m.mode()&0o022==0 && m.is_dir()}
    fn open_root(path:&Path)->EnclaveResult<File> {
        let normalized=normalized_path(path)?;
        #[cfg(target_os="macos")]
        let path=normalized.as_path();
        #[cfg(not(target_os="macos"))]
        let _=normalized;
        let slash=name("/")?;
        // SAFETY: constant C string; successful FD is immediately owned.
        let fd=unsafe {libc::open(slash.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)};
        if fd<0 {fail!(EACCES,"GRANT_KEY_PROTECTED_ROOT");}
        let mut directory=unsafe {File::from_raw_fd(fd)};
        for part in path.components().skip(1) {
            if !protected(&metadata(&directory)?) {fail!(EACCES,"GRANT_KEY_PROTECTED_ROOT");}
            let component=CString::new(part.as_os_str().as_bytes()).map_err(|_|err!(EINVAL,"GRANT_KEY_PATH"))?;
            let fd=unsafe {libc::openat(directory.as_raw_fd(),component.as_ptr(),
                libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)};
            if fd<0 {fail!(EACCES,"GRANT_KEY_PROTECTED_ROOT");}
            directory=unsafe {File::from_raw_fd(fd)};
        }
        if !protected(&metadata(&directory)?) {fail!(EACCES,"GRANT_KEY_PROTECTED_ROOT");}
        Ok(directory)
    }
    #[cfg(test)]
    fn child(state:&File,d:DaemonId)->EnclaveResult<File> {
        child_owned(state,d,KeyOwner::daemon(d))
    }
    fn child_owned(state:&File,d:DaemonId,owner:KeyOwner)->EnclaveResult<File> {
        let component=name(d.dir_name())?;
        let fd=unsafe {libc::openat(state.as_raw_fd(),component.as_ptr(),
            libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)};
        if fd<0 {fail!(EACCES,"GRANT_KEY_DIRECTORY");}
        let file=unsafe {File::from_raw_fd(fd)};check_child(&file,owner)?;
        Ok(file)
    }
    fn check_child(file:&File,owner:KeyOwner)->EnclaveResult<()> {
        let m=metadata(file)?;
        if !m.is_dir() || m.uid()!=owner.uid || m.gid()!=owner.gid || m.mode()&0o7777!=0o700 {
            fail!(EACCES,"GRANT_KEY_DIRECTORY");
        }
        Ok(())
    }
    fn stamp(m:&Metadata)->[u64;10] {
        [m.dev(),m.ino(),u64::from(m.uid()),u64::from(m.gid()),u64::from(m.mode()),m.nlink(),m.len(),
            m.mtime() as u64,m.mtime_nsec() as u64,m.ctime() as u64]
    }
    fn unchanged(a:&Metadata,b:&Metadata)->bool {stamp(a)==stamp(b) && a.ctime_nsec()==b.ctime_nsec()}
    fn named(directory:&File,component:&str,file:&File)->EnclaveResult<()> {
        let component=name(component)?;let mut observed=std::mem::MaybeUninit::<libc::stat>::uninit();
        let result=unsafe {libc::fstatat(directory.as_raw_fd(),component.as_ptr(),observed.as_mut_ptr(),libc::AT_SYMLINK_NOFOLLOW)};
        if result!=0 {fail!(ESTALE,"GRANT_KEY_CHANGED");}
        let observed=unsafe {observed.assume_init()};let held=metadata(file)?;
        if observed.st_dev as u64!=held.dev() || observed.st_ino as u64!=held.ino()
            || observed.st_mode as u32!=held.mode() || observed.st_uid!=held.uid() || observed.st_gid!=held.gid() {
            fail!(ESTALE,"GRANT_KEY_CHANGED");
        }
        Ok(())
    }
    struct KeyFile {file:File,bytes:SecretBytes,len:usize,before:Metadata}
    impl KeyFile {fn raw(&self)->&[u8] {&self.bytes.expose()[..self.len]}}
    fn read(directory:&File,component:&str,owner:KeyOwner)->EnclaveResult<Option<KeyFile>> {
        let component_c=name(component)?;
        let fd=unsafe {libc::openat(directory.as_raw_fd(),component_c.as_ptr(),
            libc::O_RDONLY|libc::O_NONBLOCK|libc::O_NOFOLLOW|libc::O_CLOEXEC)};
        if fd<0 {
            if std::io::Error::last_os_error().raw_os_error()==Some(libc::ENOENT) {return Ok(None);}
            fail!(EACCES,"GRANT_KEY_FILE");
        }
        let mut file=unsafe {File::from_raw_fd(fd)};let before=metadata(&file)?;
        if !before.is_file() || before.nlink()!=1 || before.uid()!=owner.uid || before.gid()!=owner.gid
            || before.mode()&0o7777!=0o600 || before.len()==0 || before.len()>LIMIT as u64 {
            fail!(EACCES,"GRANT_KEY_FILE");
        }
        let len=before.len() as usize;let mut bytes=SecretBytes::zeroed(LIMIT);
        file.read_exact(&mut bytes.expose_mut()[..len]).map_err(|_|err!(EIO,"GRANT_KEY_READ"))?;
        if !unchanged(&before,&metadata(&file)?) {fail!(ESTALE,"GRANT_KEY_CHANGED");}
        named(directory,component,&file)?;
        Ok(Some(KeyFile {file,bytes,len,before}))
    }
    fn parsed(raw:&[u8])->EnclaveResult<SecretBytes> {
        let text=std::str::from_utf8(raw).map_err(|_|err!(EINVAL,"GRANT_KEY_INVALID"))?.trim();
        let mut key=SecretBytes::zeroed(32);
        hex::decode_to_slice(text,key.expose_mut()).map_err(|_|err!(EINVAL,"GRANT_KEY_INVALID"))?;
        Ok(key)
    }
    fn key_public(seed:&SecretBytes)->EnclaveResult<String> {
        let array:&[u8;32]=seed.expose().try_into().map_err(|_|err!(EINVAL,"GRANT_KEY_INVALID"))?;
        Ok(hex::encode(ed25519_dalek::SigningKey::from_bytes(array).verifying_key().to_bytes()))
    }
    fn lock(state:&File)->EnclaveResult<File> {
        let component=name(LOCK)?;
        let first=unsafe {libc::openat(state.as_raw_fd(),component.as_ptr(),
            libc::O_RDWR|libc::O_CREAT|libc::O_EXCL|libc::O_NOFOLLOW|libc::O_CLOEXEC,0o600)};
        let created=first>=0;
        let fd=if created {first} else {
            if std::io::Error::last_os_error().raw_os_error()!=Some(libc::EEXIST) {fail!(EACCES,"GRANT_KEY_LOCK");}
            unsafe {libc::openat(state.as_raw_fd(),component.as_ptr(),libc::O_RDWR|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)}
        };
        if fd<0 {fail!(EACCES,"GRANT_KEY_LOCK");}
        let file=unsafe {File::from_raw_fd(fd)};
        if created && (unsafe {libc::fchmod(file.as_raw_fd(),0o600)}!=0
            || unsafe {libc::fchown(file.as_raw_fd(),0,0)}!=0) {fail!(EPERM,"GRANT_KEY_LOCK");}
        let m=metadata(&file)?;
        if !m.is_file() || m.uid()!=0 || m.gid()!=0 || m.mode()&0o7777!=0o600 || m.nlink()!=1 || m.len()!=0 {
            fail!(EACCES,"GRANT_KEY_LOCK");
        }
        named(state,LOCK,&file)?;
        if unsafe {libc::flock(file.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)}!=0 {fail!(EAGAIN,"GRANT_KEY_BUSY");}
        Ok(file)
    }
    struct Temporary<'a> {state:&'a File,component:CString}
    impl Drop for Temporary<'_> {
        fn drop(&mut self) {unsafe {libc::unlinkat(self.state.as_raw_fd(),self.component.as_ptr(),0)};}
    }
    #[cfg(test)]
    fn create(state:&File,directory:&File,component:&str,owner:DaemonId,bytes:&[u8])->EnclaveResult<()> {
        create_owned(state,directory,component,KeyOwner::daemon(owner),bytes)
    }
    fn create_owned(state:&File,directory:&File,component:&str,owner:KeyOwner,bytes:&[u8])->EnclaveResult<()> {
        let temporary=name(&format!(".ifc-grant-tmp-{}",hex::encode(enclave_core::rng::bytes32())))?;
        let fd=unsafe {libc::openat(state.as_raw_fd(),temporary.as_ptr(),
            libc::O_WRONLY|libc::O_CREAT|libc::O_EXCL|libc::O_NOFOLLOW|libc::O_CLOEXEC,0o600)};
        if fd<0 {fail!(EACCES,"GRANT_KEY_CREATE");}
        let _temporary=Temporary {state,component:temporary.clone()};
        let mut file=unsafe {File::from_raw_fd(fd)};
        if unsafe {libc::fchmod(file.as_raw_fd(),0o600)}!=0 {fail!(EPERM,"GRANT_KEY_CREATE");}
        file.write_all(bytes).map_err(|_|err!(EIO,"GRANT_KEY_WRITE"))?;
        if unsafe {libc::fchown(file.as_raw_fd(),owner.uid,owner.gid)}!=0 {fail!(EPERM,"GRANT_KEY_CREATE");}
        publish_created(state,directory,component,owner,bytes.len(),&temporary,&file)
    }
    fn publish_created(state:&File,directory:&File,component:&str,owner:KeyOwner,length:usize,
        temporary:&CString,file:&File)->EnclaveResult<()> {
        // A successful chown return is not ownership evidence (some fixture
        // filesystems report success without applying it). Refuse before the
        // first final-name publication, keeping only our disposable temp file.
        let observed=metadata(file)?;
        if !observed.is_file() || observed.uid()!=owner.uid || observed.gid()!=owner.gid
            || observed.mode()&0o7777!=0o600 || observed.nlink()!=1 || observed.len()!=length as u64 {
            fail!(EACCES,"GRANT_KEY_CREATE");
        }
        enclave_core::fsutil::full_fsync(file)?;
        let final_name=name(component)?;
        // linkat is create-only on both supported Unix platforms. An existing
        // key, including one raced into place, is never replaced or truncated.
        if unsafe {libc::linkat(state.as_raw_fd(),temporary.as_ptr(),directory.as_raw_fd(),final_name.as_ptr(),0)}!=0 {
            fail!(EIO,"GRANT_KEY_PUBLICATION_REFUSED");
        }
        if unsafe {libc::unlinkat(state.as_raw_fd(),temporary.as_ptr(),0)}!=0 {fail!(EIO,"GRANT_KEY_TEMP_CLEANUP");}
        directory.sync_all().map_err(|_|err!(EIO,"GRANT_KEY_DIRECTORY_SYNC"))?;
        state.sync_all().map_err(|_|err!(EIO,"GRANT_KEY_DIRECTORY_SYNC"))?;
        named(directory,component,file)?;
        Ok(())
    }
    fn verify(directory:&File,component:&str,owner:KeyOwner,expected:&[u8])->EnclaveResult<()> {
        let observed=read(directory,component,owner)?.ok_or_else(||err!(ESTALE,"GRANT_KEY_CHANGED"))?;
        if !enclave_core::secret::ct_eq(observed.raw(),expected) {fail!(ESTALE,"GRANT_KEY_CHANGED");}
        Ok(())
    }
    fn work(state:&File,checked:&CheckedDeploymentTarget,owners:KeyOwners)->EnclaveResult<String> {
        let _lock=lock(state)?;
        let ifc=child_owned(state,DaemonId::AgentRuntime,owners.ifc)?;let custody=child_owned(state,DaemonId::CustodyVault,owners.custody)?;
        let seed_file=read(&ifc,crate::launchd::GRANT_SEED_FILE,owners.ifc)?;
        let public_file=read(&custody,crate::launchd::GRANT_PUBLIC_FILE,owners.custody)?;
        if seed_file.is_none() && public_file.is_some() {fail!(EACCES,"GRANT_KEY_ORPHAN_PUBLIC");}
        let mut seed=SecretBytes::zeroed(32);
        if let Some(existing)=&seed_file {seed=parsed(existing.raw())?;}
        else {rand_core::RngCore::try_fill_bytes(&mut rand_core::OsRng,seed.expose_mut())
            .map_err(|_|err!(EIO,"GRANT_KEY_ENTROPY"))?;}
        let public=key_public(&seed)?;
        if let Some(existing)=&public_file {
            if hex::encode(parsed(existing.raw())?.expose())!=public {fail!(EACCES,"GRANT_KEY_PUBLIC_MISMATCH");}
        }
        let mut encoded=SecretBytes::zeroed(64);
        hex::encode_to_slice(seed.expose(),encoded.expose_mut()).map_err(|_|err!(EINVAL,"GRANT_KEY_INVALID"))?;
        checked.read_artifact_inventory()?;
        if !protected(&metadata(state)?) {fail!(EACCES,"GRANT_KEY_PROTECTED_ROOT");}
        check_child(&ifc,owners.ifc)?;check_child(&custody,owners.custody)?;
        named(state,DaemonId::AgentRuntime.dir_name(),&ifc)?;named(state,DaemonId::CustodyVault.dir_name(),&custody)?;
        if seed_file.is_none() {create_owned(state,&ifc,crate::launchd::GRANT_SEED_FILE,owners.ifc,encoded.expose())?;}
        else if let Some(existing)=&seed_file {
            if !unchanged(&existing.before,&metadata(&existing.file)?) {fail!(ESTALE,"GRANT_KEY_CHANGED");}
            verify(&ifc,crate::launchd::GRANT_SEED_FILE,owners.ifc,existing.raw())?;
        }
        if public_file.is_none() {create_owned(state,&custody,crate::launchd::GRANT_PUBLIC_FILE,owners.custody,public.as_bytes())?;}
        let seed_expected=seed_file.as_ref().map_or(encoded.expose(),KeyFile::raw);
        verify(&ifc,crate::launchd::GRANT_SEED_FILE,owners.ifc,seed_expected)?;
        let public_expected=public_file.as_ref().map_or(public.as_bytes(),KeyFile::raw);
        verify(&custody,crate::launchd::GRANT_PUBLIC_FILE,owners.custody,public_expected)?;
        if !protected(&metadata(state)?) {fail!(EACCES,"GRANT_KEY_PROTECTED_ROOT");}
        check_child(&ifc,owners.ifc)?;check_child(&custody,owners.custody)?;
        named(state,DaemonId::AgentRuntime.dir_name(),&ifc)?;named(state,DaemonId::CustodyVault.dir_name(),&custody)?;
        checked.read_artifact_inventory()?;
        Ok(public)
    }
    pub(super) fn provision(env:&Env,requested:Option<&Path>,checked:&CheckedDeploymentTarget)->EnclaveResult<String> {
        let path=bind(env,requested,checked.target())?;
        checked.read_artifact_inventory()?;
        if enclave_core::ipc::geteuid()!=0 {fail!(EPERM,"GRANT_KEY_ROOT_REQUIRED");}
        let state=open_root(path)?;let initial=metadata(&state)?;
        let public=work(&state,checked,KeyOwners::production())?;
        let current=open_root(path)?;let now=metadata(&current)?;
        if initial.dev()!=now.dev() || initial.ino()!=now.ino() {fail!(ESTALE,"GRANT_KEY_CHANGED");}
        Ok(public)
    }

    #[cfg(test)]
    include!("ctl_target_grant_key_tests.rs");
}

/// Persisted dev session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DevSession {
    /// PIDs by UID.
    pub pids: BTreeMap<u32, u32>,
    /// Profile.
    pub profile: Option<Profile>,
    /// Touch ID helper started for real custody (Track C), if any.
    #[serde(default)]
    pub intent_helper_pid: Option<u32>,
}

/// Track C development option: run UID 703 on the real Secure Enclave and
/// Touch ID helper instead of simulated custody hardware. Dev fleet only.
pub const REAL_CUSTODY_ENV: &str = "MCP_ENCLAVE_REAL_CUSTODY";
/// Absolute path of the dev-signed `enclave-intent` helper (real custody).
pub const INTENT_HELPER_ENV: &str = "MCP_ENCLAVE_INTENT_HELPER";

/// Whether this dev fleet runs custody on real hardware.
pub fn real_custody() -> bool {
    std::env::var_os(REAL_CUSTODY_ENV).is_some_and(|v| v == "1")
}

/// Start the Touch ID helper in the fleet's private `intent/` socket
/// directory (0700, this user), where UID 703 connects to it on demand.
fn start_intent_helper(env: &Env) -> EnclaveResult<u32> {
    use std::os::unix::fs::PermissionsExt;
    let helper = std::env::var_os(INTENT_HELPER_ENV).map(PathBuf::from)
        .ok_or_else(|| err!(EINVAL, "INTENT_HELPER_REQUIRED", "set {INTENT_HELPER_ENV} (scripts/pin-local-build.sh)"))?;
    if !helper.is_absolute() || !helper.is_file() {
        fail!(EINVAL, "INTENT_HELPER_PATH_INVALID");
    }
    let dir = env.socket_dir.join("intent");
    mkdir(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| err!(EIO, "INTENT_DIR_MODE", "{e}"))?;
    let log = std::fs::OpenOptions::new().create(true).append(true)
        .open(env.audit_dir.join("intent-helper.log")).map_err(|e| err!(EIO, "LOG_OPEN", "{e}"))?;
    let child = Command::new(helper).arg("--socket").arg(dir.join("intent.sock"))
        .stdin(Stdio::null()).stdout(log.try_clone().map_err(|e| err!(EIO, "LOG_OPEN", "{e}"))?).stderr(log)
        .spawn().map_err(|e| err!(EIO, "SPAWN", "enclave-intent: {e}"))?;
    let pid = child.id();
    // Re-parented when the CLI exits, like the daemons.
    std::mem::forget(child);
    Ok(pid)
}

fn session_path(env: &Env) -> PathBuf {
    env.state_dir.join("dev-session.json")
}

/// Load the dev session file.
pub fn load_session(env: &Env) -> DevSession {
    std::fs::read(session_path(env))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn mkdir(p: &Path) -> EnclaveResult<()> {
    std::fs::create_dir_all(p).map_err(|e| err!(EIO, "MKDIR", "{}: {e}", p.display()))?;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta = std::fs::symlink_metadata(p).map_err(|e| err!(EIO, "STATE_STAT", "{e}"))?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } {
        fail!(EPERM, "STATE_OWNER_OR_LINK");
    }
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| err!(EIO, "STATE_MODE", "{e}"))?;
    Ok(())
}

/// How a daemon process is launched.
fn daemon_command(d: DaemonId) -> EnclaveResult<Command> {
    let me = std::env::current_exe().map_err(|e| err!(EIO, "CURRENT_EXE", "{e}"))?;
    // Prefer the dedicated binary next to the CLI (its own address space and
    // RSS); otherwise re-exec the CLI's embedded entry point.
    if let Some(dir) = me.parent() {
        let sib = dir.join(d.binary());
        // Real custody must be the separately signed custody binary: the
        // helper pins its code identity, which the embedded CLI cannot match.
        if d == DaemonId::CustodyVault && real_custody() {
            if !sib.is_file() { fail!(EINVAL, "REAL_CUSTODY_BINARY_MISSING", "{}", sib.display()); }
            return Ok(Command::new(sib));
        }
        if sib.is_file() && std::env::var_os("MCP_ENCLAVE_EMBEDDED_DAEMONS").is_none() {
            return Ok(Command::new(sib));
        }
    }
    let mut c = Command::new(me);
    c.arg("__daemon").arg(d.uid().to_string());
    Ok(c)
}

/// Common daemon arguments for the dev layout.
pub fn dev_args(env: &Env, d: DaemonId) -> Vec<String> {
    let st = env.state_dir.display().to_string();
    let mut a = vec![
        "--socket-dir".into(),
        env.socket_dir.display().to_string(),
        "--audit-dir".into(),
        env.audit_dir.display().to_string(),
        "--profile".into(),
        env.profile.to_string(),
        "--dev-same-uid".into(),
        // GAP-11: per-daemon persistent state (tombstone keys, egress records).
        "--state-dir".into(),
        format!("{st}/daemon-state/{}", d.dir_name()),
    ];
    // Track C: custody alone may run on the real SEP/Touch ID in the dev fleet.
    if d == DaemonId::CustodyVault && real_custody() {
        a.extend(crate::dev_envelope::custody_args(&env.state_dir));
    } else {
        a.push("--simulated-hardware".into());
    }
    match d {
        DaemonId::ModelRunner => a.extend([
            "--calib-corpus-blake3".into(),
            blake3::hash(&enclave_model_runnerd::zoo::calibrated_corpus())
                .to_hex()
                .to_string(),
        ]),
        DaemonId::SwarmSync => {
            a.extend([
                "--store-dir".into(),
                format!("{st}/cas"),
                "--tuf-root".into(),
                format!("{st}/tuf/repo/root.json"),
                "--tuf-repo".into(),
                format!("{st}/tuf/repo"),
            ]);
            if let Ok(c) = std::fs::read_to_string(env.state_dir.join("ohttp-gateway.config")) {
                a.extend(["--ohttp-key-config".into(), c.trim().to_owned()]);
            }
        }
        DaemonId::CustodyVault => {
            if let Ok(k) = std::fs::read_to_string(env.state_dir.join("ifc-policy.pub")) {
                a.extend(["--grant-key-hex".into(), k.trim().to_owned()]);
            }
        }
        DaemonId::AgentRuntime => {
            a.extend(["--policy-key-file".into(), format!("{st}/ifc-policy.key")])
        }
        DaemonId::ZkAuditor => a.extend(["--strike-file".into(), format!("{st}/zk-strikes.json")]),
    }
    a
}

/// Generic `Status` probe (every daemon's request enum has a unit `Status`
/// variant and its response enum a `Status(DaemonStatus)` variant).
pub fn status_of(env: &Env, d: DaemonId) -> EnclaveResult<DaemonStatus> {
    #[derive(Serialize)]
    enum Req {
        Status,
    }
    #[derive(Deserialize)]
    enum Resp {
        Status(DaemonStatus),
    }
    let Resp::Status(s) = env.connect(d)?.call(&Req::Status)?;
    if s.daemon_uid != d.uid() {
        fail!(
            EACCES,
            "DAEMON_IDENTITY_MISMATCH",
            "socket {} answered as {}",
            d.socket_name(),
            s.daemon_uid
        );
    }
    Ok(s)
}

fn wait_up(
    env: &Env,
    d: DaemonId,
    child: &mut Child,
    timeout: Duration,
) -> EnclaveResult<DaemonStatus> {
    let t = Instant::now();
    loop {
        if let Ok(s) = status_of(env, d) {
            return Ok(s);
        }
        if let Ok(Some(code)) = child.try_wait() {
            fail!(
                EIO,
                "DAEMON_EXITED",
                "{} exited with {code}; see {}/{}.log",
                d.binary(),
                env.audit_dir.display(),
                d.plist_suffix()
            );
        }
        if t.elapsed() > timeout {
            fail!(ETIMEDOUT, "DAEMON_START_TIMEOUT", "{}", d.binary());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Prepare dev state: TUF repo, IFC policy key, OHTTP gateway key.
pub fn prepare_dev_state(env: &Env) -> EnclaveResult<()> {
    prepare_dev_state_at(env, Path::new("."))
}

/// Prepare development state from explicit real input files (including test fixtures).
/// This does not synthesize production calibration or trust artifacts.
pub fn prepare_dev_state_at(env: &Env, input_root: &Path) -> EnclaveResult<()> {
    for p in [&env.state_dir, &env.socket_dir, &env.audit_dir] {
        mkdir(p)?;
    }
    mkdir(&env.state_dir.join("cas"))?;
    DevRepo::open(&env.state_dir.join("tuf"))?;
    let kp = env.state_dir.join("ifc-policy.key");
    if !kp.exists() {
        let seed = enclave_core::rng::bytes32();
        enclave_core::fsutil::write_private(&kp, hex::encode(seed).as_bytes())?;
        let pk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
        std::fs::write(
            env.state_dir.join("ifc-policy.pub"),
            hex::encode(pk.to_bytes()),
        )
        .map_err(|e| err!(EIO, "KEY_WRITE", "{e}"))?;
    }
    let gp = env.state_dir.join("ohttp-gateway.config");
    if !gp.exists() {
        let (cfg, sk) = enclave_crypto::ohttp::gateway_keypair(1);
        std::fs::write(&gp, cfg.render()).map_err(|e| err!(EIO, "KEY_WRITE", "{e}"))?;
        let skp = env.state_dir.join("ohttp-gateway.key");
        enclave_core::fsutil::write_private(&skp, hex::encode(sk).as_bytes())?;
    }
    let host_config_target = env
        .state_dir
        .join("tuf/repo")
        .join(enclave_core::host_config::HOST_CONFIG_TARGET);
    if !host_config_target.exists() {
        let public = std::fs::read_to_string(env.state_dir.join("ifc-policy.pub"))
            .map_err(|e| err!(EIO, "GRANT_KEY_READ", "{e}"))?;
        let _ = tuf_publish_host_config_at(
            &env.state_dir.join("tuf/keys.json"),
            &env.state_dir.join("tuf/repo"),
            env.profile,
            Some(public.trim().to_owned()),
            &env.state_dir,
            input_root,
        )?;
    }
    let policy_target = env
        .state_dir
        .join("tuf/repo")
        .join(enclave_agent_runtime::cedar_engine::CEDAR_BUNDLE_TARGET);
    if !policy_target.exists() {
        let _ = tuf_publish_policy(
            &env.state_dir.join("tuf/keys.json"),
            &env.state_dir.join("tuf/repo"),
            None,
            None,
        )?;
    }
    if real_custody() {
        crate::dev_envelope::ensure_published(&env.state_dir, env.profile)?;
    }
    let cas_dir = env.state_dir.join("cas");
    let repo_dir = env.state_dir.join("tuf/repo");
    for target in [
        enclave_core::host_config::HOST_CONFIG_TARGET,
        enclave_core::host_config::CALIBRATION_CORPUS_TARGET,
        enclave_agent_runtime::cedar_engine::CEDAR_BUNDLE_TARGET,
        enclave_crypto::hpke_envelope::ENVELOPE_POLICY_TARGET,
    ] {
        let src = repo_dir.join(target);
        if src.exists() {
            let _ = std::fs::copy(&src, cas_dir.join(target));
        }
    }
    Ok(())
}

/// Start order: the CAS first (others resolve weights / relay through it).
pub const START_ORDER: [DaemonId; 5] = [
    DaemonId::SwarmSync,
    DaemonId::CustodyVault,
    DaemonId::ModelRunner,
    DaemonId::AgentRuntime,
    DaemonId::ZkAuditor,
];

/// `daemon start`.
pub fn start(env: &Env) -> EnclaveResult<Vec<DaemonStatus>> {
    crate::custody_notice::show_for_profile(&env.profile.to_string());
    if !env.dev {
        return launchctl("bootstrap");
    }
    prepare_dev_state(env)?;
    // Everything this call spawns, so a failure part way stops exactly those
    // processes: the session file `daemon stop` reads is written only after
    // the whole fleet is up, so nothing else would find them.
    let mut launched = Vec::new();
    let result = start_dev(env, &mut launched);
    if result.is_err() {
        terminate(&launched);
    }
    result
}

fn start_dev(env: &Env, launched: &mut Vec<u32>) -> EnclaveResult<Vec<DaemonStatus>> {
    let mut sess = load_session(env);
    if real_custody() && !sess.intent_helper_pid.is_some_and(alive) {
        let pid = start_intent_helper(env)?;
        launched.push(pid);
        sess.intent_helper_pid = Some(pid);
    }
    let mut out = Vec::new();
    for d in START_ORDER {
        match status_of(env, d) {
            Ok(s) => { out.push(s); continue; }
            Err(e) if env.connect(d).is_ok() => {
                // An authenticated live listener can be configuration-restricted.
                // Never unlink/rebind its socket or duplicate that daemon.
                return Err(e);
            }
            Err(_) => {}
        }
        mkdir(&env.audit_dir.join(d.dir_name()))?;
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(
                env.audit_dir
                    .join(d.dir_name())
                    .join(format!("{}.log", d.plist_suffix())),
            )
            .map_err(|e| err!(EIO, "LOG_OPEN", "{e}"))?;
        let log2 = log.try_clone().map_err(|e| err!(EIO, "LOG_OPEN", "{e}"))?;
        let mut c = daemon_command(d)?;
        c.envs(crate::launchd::DAEMON_MALLOC_ENV);
        let mut child = c
            .args(dev_args(env, d))
            .stdin(Stdio::null())
            .stdout(log)
            .stderr(log2)
            .spawn()
            .map_err(|e| err!(EIO, "SPAWN", "{}: {e}", d.binary()))?;
        launched.push(child.id());
        if d == DaemonId::SwarmSync {
            // CAS exposes signed-config management before healthy Status. Feed
            // the prepared metadata first, then require normal admission.
            let started = Instant::now();
            loop {
                match tuf_refresh(env, &env.state_dir.join("tuf/repo"), false) {
                    Ok(_) => break,
                    Err(e) => {
                        if child.try_wait().ok().flatten().is_some()
                            || started.elapsed() >= Duration::from_secs(20) {
                            let _ = child.kill();
                            let _ = child.wait();
                            return Err(e);
                        }
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }
            }
        }
        let s = wait_up(env, d, &mut child, Duration::from_secs(20))?;
        sess.pids.insert(d.uid(), child.id());
        out.push(s);
        if d == DaemonId::SwarmSync {
            // In dev mode, immediately refresh TUF targets so CAS has targets hydrated
            // for downstream daemons (host-config for 703, cedar-bundle for 704).
            let repo = env.state_dir.join("tuf/repo");
            let _ = tuf_refresh(env, &repo, false);
        }
        // The child is re-parented when the CLI exits; it is a daemon now.
        std::mem::forget(child);
    }
    sess.profile = Some(env.profile);
    std::fs::write(
        session_path(env),
        serde_json::to_vec_pretty(&sess).map_err(|e| err!(EIO, "SESSION", "{e}"))?,
    )
    .map_err(|e| err!(EIO, "SESSION", "{e}"))?;
    // Sync the TUF client with the dev repository.
    tuf_refresh(env, &env.state_dir.join("tuf/repo"), false)?;
    Ok(out)
}

/// Stop processes this CLI spawned: SIGTERM, then SIGKILL after a grace
/// period, reaping each so none is left as a zombie or an orphan.
fn terminate(pids: &[u32]) {
    const GRACE: Duration = Duration::from_secs(3);
    let raw: Vec<libc::pid_t> = pids.iter().filter_map(|p| libc::pid_t::try_from(*p).ok()).filter(|p| *p > 0).collect();
    for pid in &raw {
        // SAFETY: signalling a PID this process spawned.
        unsafe { libc::kill(*pid, libc::SIGTERM) };
    }
    let deadline = Instant::now() + GRACE;
    for pid in &raw {
        loop {
            let mut status = 0;
            // SAFETY: non-blocking reap of our own child; ECHILD for an
            // already reaped or re-parented one, which `alive` then decides.
            let reaped = unsafe { libc::waitpid(*pid, &mut status, libc::WNOHANG) };
            if reaped == *pid || !alive(*pid as u32) {
                break;
            }
            if Instant::now() >= deadline {
                // SAFETY: as above; blocking reap after SIGKILL.
                unsafe {
                    libc::kill(*pid, libc::SIGKILL);
                    libc::waitpid(*pid, &mut status, 0);
                }
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn launchctl(verb: &str) -> EnclaveResult<Vec<DaemonStatus>> {
    if enclave_core::deployment::selected().is_some() {
        fail!(ENOSYS, "DEPLOYMENT_LIFECYCLE_UNAVAILABLE");
    }
    if !cfg!(target_os = "macos") {
        fail!(
            EPERM,
            "LAUNCHD_UNAVAILABLE",
            "production lifecycle requires macOS launchd; use --dev"
        );
    }
    if enclave_core::ipc::geteuid() != 0 {
        fail!(
            EPERM,
            "ROOT_REQUIRED",
            "launchctl {verb} system/* requires root"
        );
    }
    for d in START_ORDER {
        let plist = format!("/Library/LaunchDaemons/{}.plist", d.launchd_label());
        let st = match verb {
            "bootstrap" => {
                if !Path::new(&plist).exists() {
                    fail!(
                        EIO,
                        "PLIST_NOT_INSTALLED",
                        "{plist}: run `mcp-enclave launchd render --out /Library/LaunchDaemons`"
                    );
                }
                Command::new("/bin/launchctl")
                    .args(["bootstrap", "system", &plist])
                    .status()
            }
            _ => Command::new("/bin/launchctl")
                .args(["bootout", &format!("system/{}", d.launchd_label())])
                .status(),
        }
        .map_err(|e| err!(EIO, "LAUNCHCTL", "{e}"))?;
        if !st.success() {
            fail!(
                EIO,
                "LAUNCHCTL",
                "launchctl {verb} {} failed ({st})",
                d.launchd_label()
            );
        }
    }
    Ok(vec![])
}

fn alive(pid: u32) -> bool {
    // SAFETY: signal 0 only probes for existence / permission.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

/// `daemon stop`.
pub fn stop(env: &Env) -> EnclaveResult<usize> {
    if !env.dev {
        launchctl("bootout")?;
        return Ok(5);
    }
    let sess = load_session(env);
    let mut stopped = 0;
    for (uid, pid) in sess.pids.iter().rev() {
        if !alive(*pid) {
            continue;
        }
        // Make sure the PID is still our daemon before signalling it.
        let ok = DaemonId::from_uid(*uid)
            .and_then(|d| env.connect(d).ok())
            // Healthy Status is intentionally unavailable after admission loss.
            // Bind cleanup to the connected server's kernel PID, never a PID
            // supplied in an unhealthy or spoofed application response.
            .is_some_and(|c| c.server.pid.is_some_and(|actual| actual > 0 && u32::try_from(actual).ok() == Some(*pid)));
        if !ok {
            continue;
        }
        // SAFETY: plain kill(2) on a PID we spawned.
        unsafe { libc::kill(*pid as libc::pid_t, libc::SIGTERM) };
        let t = Instant::now();
        while alive(*pid) && t.elapsed() < Duration::from_secs(5) {
            // Reap if it is our child; otherwise just poll.
            // SAFETY: non-blocking waitpid on a specific PID.
            unsafe { libc::waitpid(*pid as libc::pid_t, std::ptr::null_mut(), libc::WNOHANG) };
            std::thread::sleep(Duration::from_millis(25));
        }
        if alive(*pid) {
            // SAFETY: as above.
            unsafe { libc::kill(*pid as libc::pid_t, libc::SIGKILL) };
        }
        stopped += 1;
    }
    if let Some(pid) = sess.intent_helper_pid.filter(|pid| alive(*pid)) {
        // SAFETY: plain kill(2) on the helper PID this fleet started.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    }
    let _ = std::fs::remove_file(session_path(env));
    Ok(stopped)
}

/// Status table row.
#[derive(Debug, Clone, Serialize)]
pub struct Row {
    /// UID.
    pub uid: u32,
    /// Binary.
    pub binary: String,
    /// Up?
    pub up: bool,
    /// PID.
    pub pid: Option<u32>,
    /// RSS bytes.
    pub rss_bytes: u64,
    /// Physical footprint bytes, when the daemon reports one.
    pub footprint_bytes: Option<u64>,
    /// Ceiling bytes (checked against the footprint, else RSS).
    pub ceiling_bytes: u64,
    /// State line / error.
    pub state: String,
}

/// Fleet summary.
#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    /// Rows.
    pub rows: Vec<Row>,
    /// Sum of UID 702–705 RSS.
    pub rss_702_705_bytes: u64,
    /// Sum of all RSS.
    pub rss_total_bytes: u64,
    /// All up and within ceilings and budgets.
    pub healthy: bool,
}

/// `daemon status`.
pub fn status(env: &Env) -> Summary {
    let rows: Vec<Row> = DaemonId::ALL
        .iter()
        .map(|d| match status_of(env, *d) {
            Ok(s) => Row {
                uid: d.uid(),
                binary: d.binary().into(),
                up: true,
                pid: Some(s.pid),
                rss_bytes: s.rss_bytes,
                footprint_bytes: (s.phys_footprint_bytes > 0).then_some(s.phys_footprint_bytes),
                ceiling_bytes: s.rss_ceiling_bytes,
                state: s.state,
            },
            Err(e) => Row {
                uid: d.uid(),
                binary: d.binary().into(),
                up: false,
                pid: None,
                rss_bytes: 0,
                footprint_bytes: None,
                ceiling_bytes: d.rss_ceiling_bytes(),
                state: e.to_string(),
            },
        })
        .collect();
    let rss_702_705_bytes = rows
        .iter()
        .filter(|r| r.uid != 701)
        .map(|r| r.rss_bytes)
        .sum();
    let rss_total_bytes = rows.iter().map(|r| r.rss_bytes).sum();
    // Budgets apply to owned memory: the footprint where reported, else RSS
    // (RSS also counts reclaimable pages of read-only mapped model weights).
    let owned = |r: &Row| r.footprint_bytes.unwrap_or(r.rss_bytes);
    let owned_702_705: u64 = rows.iter().filter(|r| r.uid != 701).map(owned).sum();
    let owned_total: u64 = rows.iter().map(owned).sum();
    let healthy = rows.iter().all(|r| r.up && owned(r) <= r.ceiling_bytes)
        && owned_702_705 <= UID_702_705_BUDGET_MIB * MIB
        && owned_total <= STEADY_STATE_BUDGET_MIB * MIB;
    Summary {
        rows,
        rss_702_705_bytes,
        rss_total_bytes,
        healthy,
    }
}

/// Daemon measurement record (GAP-38).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonMeasurement {
    /// Daemon UID.
    pub uid: u32,
    /// Daemon binary name.
    pub name: String,
    /// Process ID.
    pub pid: Option<u32>,
    /// Running status.
    pub running: bool,
    /// Physical footprint in bytes (`task_vm_info.phys_footprint`).
    pub phys_footprint_bytes: u64,
    /// API origin; unknown never establishes compliance.
    pub phys_footprint_source: enclave_core::resource::FootprintSource,
    /// Whether a positive genuine authenticated measurement was available.
    pub footprint_known: bool,
    /// Physical footprint in MiB.
    pub phys_footprint_mib: f64,
    /// Static ceiling in MiB from enclave.lock.toml.
    pub ceiling_mib: f64,
    /// Remaining headroom in MiB.
    pub headroom_mib: f64,
    /// Whether within the static ceiling.
    pub within_ceiling: bool,
}

/// Fleet budget analysis (GAP-38).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetAnalysis {
    /// Non-model UIDs 702–705 ceiling in MiB (ADR-006: 152 MiB).
    pub uid_702_705_ceiling_mib: u64,
    /// Non-model UIDs 702–705 actual footprint in MiB.
    pub uid_702_705_actual_mib: f64,
    /// Steady state ceiling in MiB (ADR-006: 200 MiB).
    pub steady_state_ceiling_mib: u64,
    /// Steady state actual footprint in MiB.
    pub steady_state_actual_mib: f64,
    /// Active prompt ceiling in MiB (ADR-006: 232 MiB).
    pub active_prompt_ceiling_mib: u64,
    /// Non-model mesh ceiling in MiB (GAP-38: 1200 MiB / 1.2 GB).
    pub non_model_mesh_ceiling_mib: u64,
    /// Non-model mesh actual footprint in MiB.
    pub non_model_mesh_actual_mib: f64,
    /// Transient connection allowance in MiB for UID 703 (1 MiB).
    pub transient_connection_allowance_mib: f64,
    /// Hardware memory page size in bytes (16 KiB on Apple Silicon).
    pub page_size_bytes: usize,
    /// Whether all ceilings are strictly satisfied.
    pub compliant: bool,
}

/// Full GAP-38 physical footprint report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeasureReport {
    /// Shared exact-byte decisions; aggregate totals are null when unknown.
    pub physical_memory: crate::memory::MemoryBudget,
    /// Target machine chip model and memory.
    pub machine: String,
    /// Operating system name.
    pub os: String,
    /// Per-daemon measurements.
    pub daemons: Vec<DaemonMeasurement>,
    /// Fleet budget analysis.
    pub budget: BudgetAnalysis,
}

/// Measure physical footprint (task_vm_info.phys_footprint) of all running daemons (GAP-38).
pub fn measure(env: &Env, _lock_path: Option<&Path>) -> EnclaveResult<MeasureReport> {
    let (machine, os) = get_machine_info();
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    let statuses = DaemonId::ALL.map(|d| status_of(env, d).ok());
    let auxiliary=crate::memory::observe_auxiliary(env);
    Ok(measure_with_auxiliary(statuses,auxiliary,machine,os,page_size))
}

pub(crate) fn measure_observations(
    statuses: [Option<DaemonStatus>; 5], machine: String, os: String, page_size: usize,
) -> MeasureReport {
    measure_with_auxiliary(statuses,crate::memory::AuxiliaryObservations::default(),machine,os,page_size)
}

pub(crate) fn measure_with_auxiliary(statuses:[Option<DaemonStatus>;5],auxiliary:crate::memory::AuxiliaryObservations,machine:String,os:String,page_size:usize)->MeasureReport {
    let mut measurements = Vec::new();
    let memory = crate::memory::evaluate_with_auxiliary(std::array::from_fn(|i| statuses[i].as_ref()),&auxiliary);
    for (i, d) in DaemonId::ALL.into_iter().enumerate() {
        let decision = &memory.daemons[i];
        let footprint = decision.bytes.unwrap_or(0);
        let ceiling_mib = d.rss_ceiling_mib() as f64;
        let footprint_mib = footprint as f64 / (1024.0 * 1024.0);
        measurements.push(DaemonMeasurement {
            uid: d.uid(), name: d.binary().into(),
            pid: statuses[i].as_ref().map(|s| s.pid), running: statuses[i].is_some(),
            phys_footprint_bytes: footprint,
            phys_footprint_source: statuses[i].as_ref().map(|s| s.phys_footprint_source).unwrap_or_default(),
            footprint_known: decision.bytes.is_some(),
            phys_footprint_mib: (footprint_mib * 100.0).round() / 100.0,
            ceiling_mib, headroom_mib: ((ceiling_mib-footprint_mib).max(0.0)*100.0).round()/100.0,
            within_ceiling: decision.within_ceiling,
        });
    }
    // JSON totals are null when a required reading is missing or overflowed.
    // Retained MiB presentation fields are estimates only; compliant is exact.
    let uid_702_705_actual_mib = memory.other_bytes.unwrap_or(0) as f64 / (1024.0*1024.0);
    let steady_state_actual_mib = memory.total_bytes.unwrap_or(0) as f64 / (1024.0*1024.0);
    let transient_mib = 1.0;
    let non_model_mesh_actual_mib = memory.specified_process_bytes.unwrap_or(0) as f64 / (1024.0*1024.0) + transient_mib;
    let compliant = memory.compliant && non_model_mesh_actual_mib <= 1200.0;

    MeasureReport {
        machine,
        os,
        daemons: measurements,
        physical_memory: memory,
        budget: BudgetAnalysis {
            uid_702_705_ceiling_mib: 152,
            uid_702_705_actual_mib: (uid_702_705_actual_mib * 100.0).round() / 100.0,
            steady_state_ceiling_mib: 200,
            steady_state_actual_mib: (steady_state_actual_mib * 100.0).round() / 100.0,
            active_prompt_ceiling_mib: 232,
            non_model_mesh_ceiling_mib: 1200,
            non_model_mesh_actual_mib: (non_model_mesh_actual_mib * 100.0).round() / 100.0,
            transient_connection_allowance_mib: transient_mib,
            page_size_bytes: page_size,
            compliant,
        },
    }
}

fn get_machine_info() -> (String, String) {
    #[cfg(target_os = "macos")]
    {
        let mut cpu = [0u8; 64];
        let mut cpu_len = cpu.len();
        let cpu_key = c"machdep.cpu.brand_string";
        let _ = unsafe {
            libc::sysctlbyname(
                cpu_key.as_ptr(),
                cpu.as_mut_ptr().cast(),
                &mut cpu_len,
                std::ptr::null_mut(),
                0,
            )
        };
        let cpu_str =
            std::str::from_utf8(&cpu[..cpu_len.saturating_sub(1)]).unwrap_or("Apple Silicon");
        let mut mem: u64 = 0;
        let mut mem_len = std::mem::size_of::<u64>();
        let mem_key = c"hw.memsize";
        let _ = unsafe {
            libc::sysctlbyname(
                mem_key.as_ptr(),
                (&mut mem as *mut u64).cast(),
                &mut mem_len,
                std::ptr::null_mut(),
                0,
            )
        };
        let ram_gb = mem / (1024 * 1024 * 1024);
        (format!("{cpu_str} ({ram_gb} GB)"), "macOS (Darwin)".into())
    }
    #[cfg(not(target_os = "macos"))]
    {
        ("Linux / VM".into(), "Linux".into())
    }
}

/// `tuf refresh`.
pub fn tuf_refresh(env: &Env, repo: &Path, bootstrap: bool) -> EnclaveResult<(u64, u64, u64)> {
    let f = read_repo(repo)?;
    let mut c = env.connect(DaemonId::SwarmSync)?;
    if bootstrap {
        let _: CasResponse = c.call(&CasRequest::TufBootstrap {
            root: f.root.clone().into(),
        })?;
    }
    let r: CasResponse = c.call(&CasRequest::TufRefresh {
        roots: f.rotations.into_iter().map(Into::into).collect(),
        timestamp: f.timestamp.into(),
        snapshot: f.snapshot.into(),
        targets: f.targets.into(),
    })?;
    let versions = match r {
        CasResponse::Tuf { versions } => versions,
        _ => fail!(EIO, "UNEXPECTED_RESPONSE"),
    };
    // GAP-32: on each refresh, UID 704 resolves policy from UID 702
    if status_of(env, DaemonId::AgentRuntime).is_ok() {
        let _ = ifc_refresh_policy(&env.socket_dir, None, env.dev);
    }
    Ok(versions)
}

/// Initialize a TUF repository at `repo_dir` with keys at `keys_file`.
pub fn tuf_init(keys_file: &Path, repo_dir: &Path) -> EnclaveResult<u64> {
    let repo = DevRepo::open_with_keys(keys_file, repo_dir)?;
    Ok(repo.version())
}

/// Re-sign all metadata in `repo_dir` with TUF canonical JSON (GAP-31).
pub fn tuf_migrate_canonical(keys_file: &Path, repo_dir: &Path) -> EnclaveResult<u64> {
    let mut repo = DevRepo::open_with_keys(keys_file, repo_dir)?;
    repo.migrate_canonical()
}

/// Sign a target file into the TUF repository.
pub fn tuf_sign(
    keys_file: &Path,
    repo_dir: &Path,
    target_name: &str,
    target_bytes: &[u8],
    custom: Option<serde_json::Value>,
) -> EnclaveResult<u64> {
    let mut repo = DevRepo::open_with_keys(keys_file, repo_dir)?;
    repo.add_target(
        target_name,
        target_bytes,
        custom.unwrap_or(serde_json::json!({})),
    )?;
    Ok(repo.version())
}

/// Generate host config for the given parameters.
pub fn tuf_generate_host_config(
    profile_floor: Profile,
    ifc_grant_pubkey: Option<String>,
    state_dir: &Path,
) -> EnclaveResult<enclave_core::host_config::EnclaveHostConfig> {
    tuf_generate_host_config_at(profile_floor, ifc_grant_pubkey, state_dir, Path::new("."))
}

/// Generate configuration from explicit, complete artifact inputs. Missing inputs fail closed.
pub fn tuf_generate_host_config_at(
    profile_floor: Profile,
    ifc_grant_pubkey: Option<String>,
    state_dir: &Path,
    input_root: &Path,
) -> EnclaveResult<enclave_core::host_config::EnclaveHostConfig> {
    crate::custody_notice::show_for_profile(&profile_floor.to_string());
    let pk = if let Some(k) = ifc_grant_pubkey {
        k
    } else {
        let p1 = state_dir.join("ifc").join("grant.pub");
        let p2 = state_dir.join("custody").join("ifc-grant.pub");
        let p3 = state_dir.join("custody").join("ifc_grant.pub");
        if p1.exists() {
            std::fs::read_to_string(&p1)
                .map_err(|e| err!(EIO, "GRANT_KEY_READ", "{e}"))?
                .trim()
                .to_string()
        } else if p2.exists() {
            std::fs::read_to_string(&p2)
                .map_err(|e| err!(EIO, "GRANT_KEY_READ", "{e}"))?
                .trim()
                .to_string()
        } else if p3.exists() {
            std::fs::read_to_string(&p3)
                .map_err(|e| err!(EIO, "GRANT_KEY_READ", "{e}"))?
                .trim()
                .to_string()
        } else {
            return Err(err!(EINVAL, "GRANT_KEY_REQUIRED", "provision the actual IFC grant key or provide --grant-key; no throwaway authority is generated"));
        }
    };

    let vk = hex::encode(enclave_zk_auditor::zk::engine::hiding_vk_digest());

    let digest = |relative: &str| -> EnclaveResult<String> {
        let path = input_root.join(relative);
        let bytes = std::fs::read(&path)
            .map_err(|e| err!(EIO, "HOST_CONFIG_INPUT_REQUIRED", "{}: {e}", path.display()))?;
        if bytes.is_empty() {
            return Err(err!(
                EINVAL,
                "HOST_CONFIG_INPUT_EMPTY",
                "{}",
                path.display()
            ));
        }
        Ok(hex::encode(blake3::hash(&bytes).as_bytes()))
    };
    let mcp_digest = digest("schemas/enclave.lock.toml")?;
    let corpus_digest = digest("assets/calibration.corpus")?;
    let mds_digest = digest("packaging/fido-mds/yubico.json")?;

    let cfg = enclave_core::host_config::EnclaveHostConfig {
        profile_floor,
        ifc_grant_public_key: pk,
        ohttp_key_config: None,
        calibration_corpus_digest: corpus_digest,
        vk_digest: vk,
        mcp_lock_digest: mcp_digest,
        fido_mds_allowlist_digest: mds_digest,
        codesign_pins: None,
    };
    cfg.validate()?;
    Ok(cfg)
}

/// Generate, sign and publish enclave-host-config.json.
pub fn tuf_publish_host_config(
    keys_file: &Path,
    repo_dir: &Path,
    profile_floor: Profile,
    ifc_grant_pubkey: Option<String>,
    state_dir: &Path,
) -> EnclaveResult<(enclave_core::host_config::EnclaveHostConfig, u64)> {
    tuf_publish_host_config_at(keys_file, repo_dir, profile_floor, ifc_grant_pubkey, state_dir, Path::new("."))
}

/// Publish using explicit source artifacts, preserving generation's mandatory inputs.
pub fn tuf_publish_host_config_at(
    keys_file: &Path,
    repo_dir: &Path,
    profile_floor: Profile,
    ifc_grant_pubkey: Option<String>,
    state_dir: &Path,
    input_root: &Path,
) -> EnclaveResult<(enclave_core::host_config::EnclaveHostConfig, u64)> {
    let cfg = tuf_generate_host_config_at(profile_floor, ifc_grant_pubkey, state_dir, input_root)?;
    let bytes = cfg.to_json_bytes()?;
    let corpus = std::fs::read(input_root.join("assets/calibration.corpus"))
        .map_err(|e| err!(EIO, "HOST_CONFIG_INPUT_REQUIRED", "{e}"))?;
    if blake3::hash(&corpus).to_hex().as_str() != cfg.calibration_corpus_digest {
        fail!(EACCES, "HOST_CONFIG_INPUT_CHANGED");
    }
    let mut repo = DevRepo::open_with_keys(keys_file, repo_dir)?;
    repo.add_target(
        enclave_core::host_config::CALIBRATION_CORPUS_TARGET,
        &corpus,
        // No profile policy here: the runner fetches this target through the
        // generic target path, which refuses policy-bearing (model) targets.
        // Its integrity is pinned by the digest in the signed host config.
        serde_json::json!({"media_type": "application/x-ndjson"}),
    )?;
    enclave_core::fsutil::write_private(
        &repo_dir.join(enclave_core::host_config::CALIBRATION_CORPUS_TARGET),
        &corpus,
    )?;
    repo.add_target(
        enclave_core::host_config::HOST_CONFIG_TARGET,
        &bytes,
        serde_json::json!({
            "min_profile": profile_floor.to_string(),
            "classification": "public_l1",
        }),
    )?;
    std::fs::write(
        repo_dir.join(enclave_core::host_config::HOST_CONFIG_TARGET),
        &bytes,
    ).map_err(|e| err!(EIO,"HOST_CONFIG_WRITE","{e}"))?;
    Ok((cfg, repo.version()))
}

/// Generate, sign and publish the Cedar policy bundle (GAP-32).
pub fn tuf_publish_policy(
    keys_file: &Path,
    repo_dir: &Path,
    schema_src: Option<String>,
    policies_src: Option<String>,
) -> EnclaveResult<(enclave_agent_runtime::cedar_engine::CedarBundle, u64)> {
    let schema = schema_src
        .unwrap_or_else(|| enclave_agent_runtime::cedar_engine::DEFAULT_SCHEMA.to_owned());
    let policies = policies_src
        .unwrap_or_else(|| enclave_agent_runtime::cedar_engine::BASELINE_POLICIES.to_owned());
    // Strictly validate before publishing
    let _ = enclave_agent_runtime::cedar_engine::CedarEngine::load(&schema, &policies)?;
    let bundle = enclave_agent_runtime::cedar_engine::CedarBundle::new(schema, policies);
    let bytes = bundle.to_json_bytes()?;

    let mut repo = DevRepo::open_with_keys(keys_file, repo_dir)?;
    repo.add_target(
        enclave_agent_runtime::cedar_engine::CEDAR_BUNDLE_TARGET,
        &bytes,
        // No model policy keys: UID 704 fetches this through the generic
        // target path, which refuses classification/min_profile (model
        // descriptor) targets, and would otherwise fall back to deny-all.
        serde_json::json!({
            "media_type": enclave_agent_runtime::cedar_engine::CEDAR_BUNDLE_MEDIA_TYPE,
        }),
    )?;
    let _ = std::fs::write(
        repo_dir.join(enclave_agent_runtime::cedar_engine::CEDAR_BUNDLE_TARGET),
        &bytes,
    );
    Ok((bundle, repo.version()))
}

/// Generate, sign and publish the verifier key manifest (GAP-20 / GAP-23 / Prompt 2D).
pub fn tuf_publish_vk_manifest(
    keys_file: &Path,
    repo_dir: &Path,
) -> EnclaveResult<(enclave_zk_auditor::zk::manifest::VkManifestV1, u64)> {
    let manifest = enclave_zk_auditor::zk::manifest::VkManifestV1::production_hiding();
    let bytes = manifest
        .to_json_bytes()
        .map_err(|e| err!(EINVAL, "VK_MANIFEST_ENCODE", "{e}"))?;

    let mut repo = DevRepo::open_with_keys(keys_file, repo_dir)?;
    repo.add_target(
        enclave_zk_auditor::zk::manifest::VK_MANIFEST_TARGET,
        &bytes,
        serde_json::json!({
            "media_type": enclave_zk_auditor::zk::manifest::VK_MANIFEST_MEDIA_TYPE,
            "min_profile": "L1",
            "classification": "public_l1",
        }),
    )?;
    let _ = std::fs::write(
        repo_dir.join(enclave_zk_auditor::zk::manifest::VK_MANIFEST_TARGET),
        &bytes,
    );
    Ok((manifest, repo.version()))
}

/// Send a policy refresh request to UID 704 (AgentRuntime) (GAP-32).
pub fn ifc_refresh_policy(
    socket_dir: &Path,
    bundle_bytes: Option<Vec<u8>>,
    dev: bool,
) -> EnclaveResult<()> {
    let ifc_sock = socket_dir
        .join(DaemonId::AgentRuntime.dir_name())
        .join(format!("{}.sock", DaemonId::AgentRuntime.dir_name()));

    let mut c = if dev {
        enclave_core::ipc::Client::connect(&ifc_sock, enclave_core::ipc::geteuid())?
    } else {
        enclave_core::ipc::Client::connect_verified(
            &ifc_sock,
            DaemonId::AgentRuntime.uid(),
            Some(&enclave_core::codesign::CodeRequirement::daemon(
                DaemonId::AgentRuntime,
            )),
        )?
    };

    let req = enclave_agent_runtime::service::IfcRequest::RefreshPolicy {
        bundle_json: bundle_bytes.map(serde_bytes::ByteBuf::from),
    };
    let resp: enclave_agent_runtime::service::IfcResponse = c.call(&req)?;
    match resp {
        enclave_agent_runtime::service::IfcResponse::Ok => Ok(()),
        _ => enclave_core::fail!(
            EIO,
            "POLICY_REFRESH_FAILED",
            "unexpected response from UID 704"
        ),
    }
}

/// Inputs for `model admit`.
#[derive(Debug, Clone, Default)]
pub struct AdmitInput {
    /// Manifest file (production; dev defaults to the reference zoo).
    pub manifest: Option<PathBuf>,
    /// Weights file.
    pub weights: Option<PathBuf>,
    /// Calibration corpus (Class 1).
    pub corpus: Option<PathBuf>,
    /// TUF target name.
    pub target: Option<String>,
}

/// `model admit` result.
#[derive(Debug, Clone, Serialize)]
pub struct Admitted {
    /// Model.
    pub model_id: String,
    /// Class.
    pub class: String,
    /// CAS URI.
    pub cas_uri: String,
    /// ECE (ppm) for Class 1.
    pub ece_ppm: Option<u32>,
    /// Topology fingerprint.
    pub topology_fingerprint: String,
}

/// Upper bound on one model bind (artifact verification plus graph load).
const BIND_TIMEOUT: Duration = Duration::from_secs(300);

/// `model admit --class <CLASS>`.
pub fn model_admit(env: &Env, class: ExecutionClass, inp: &AdmitInput) -> EnclaveResult<Admitted> {
    let rd = |p: &Path| std::fs::read(p).map_err(|e| err!(EIO, "READ", "{}: {e}", p.display()));
    // File-backed production weights stay a reader throughout admission.
    // Only explicit tiny development zoo fixtures are held in memory.
    enum Weights { File(std::fs::File), Reference(std::io::Cursor<Vec<u8>>) }
    impl std::io::Read for Weights {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> { match self {Self::File(f)=>std::io::Read::read(f,b),Self::Reference(c)=>std::io::Read::read(c,b)} }
    }
    impl std::io::Seek for Weights {
        fn seek(&mut self, p: std::io::SeekFrom) -> std::io::Result<u64> {match self {Self::File(f)=>std::io::Seek::seek(f,p),Self::Reference(c)=>std::io::Seek::seek(c,p)}}
    }
    let (manifest, mut weights, corpus) = match (&inp.manifest, &inp.weights) {
        (Some(m), Some(w)) => {
            use std::os::unix::fs::OpenOptionsExt;
            let file=std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)
                .open(w).map_err(|e|err!(EIO,"WEIGHTS_OPEN","{e}"))?;
            let meta=file.metadata().map_err(|e|err!(EIO,"WEIGHTS_STAT","{e}"))?;
            if !meta.is_file() || meta.len()>crate::artifact_stream::MAX_MODEL_BYTES {fail!(EACCES,"WEIGHTS_TYPE_OR_SIZE");}
            (rd(m)?,Weights::File(file),inp.corpus.as_deref().map(rd).transpose()?)
        },
        (None,None) if env.dev => {
            let p=enclave_model_runnerd::zoo::package(class)?;
            (p.manifest_bytes(),Weights::Reference(std::io::Cursor::new(p.weights)),p.corpus)
        },
        _=>fail!(EINVAL,"ADMIT_ARGS","--manifest and --weights are required outside --dev"),
    };
    let parsed = ModelManifestV1::from_json(&manifest)?;
    let manifest_target = enclave_model_runnerd::service::model_manifest_target(&parsed.model_id)?;
    if parsed.execution_class != class {
        fail!(
            EACCES,
            "EXECUTION_CLASS_MISMATCH",
            "--class {} but the signed manifest declares {}",
            class.name(),
            parsed.execution_class.name()
        );
    }
    let target = inp
        .target
        .clone()
        .unwrap_or_else(|| format!("{}.safetensors", parsed.model_id));
    if env.dev {
        // Publish into the dev TUF repository, then sync UID 702.
        let mut repo = DevRepo::open(&env.state_dir.join("tuf"))?;
        let min = parsed
            .security_controls
            .as_ref()
            .and_then(|c| c.min_swarm_profile.clone())
            .unwrap_or_else(|| "L1".into());
        // The development classification follows the manifest's own minimum
        // profile, so an L1 model is admissible on an L1 host. Anything that
        // does not name a known profile stays at the restrictive default.
        let classification = match min.as_str() {
            "L1" => "public_l1",
            "L3" => "restricted_l3",
            _ => "internal_l2",
        };
        repo.add_target_reader(
            &target,
            &mut weights,
            json!({"classification": classification, "min_profile": min, "license_policy": {"spdx_id": parsed.license_policy.spdx_id, "allow_p2p_seeding": parsed.license_policy.allow_p2p_seeding}, "lazy_fuse_t": false, "companion_safety_layers": []}),
        )?;
        tuf_refresh(env, &repo.repo_dir(), false)?;
    }
    let root = crate::artifact_stream::admit_reader(env, &target, &mut weights)?;
    let (manifest, cas_uri) = admission_manifest(env.dev, manifest, &root, &target)?;
    if env.dev {
        // The runner independently fetches this exact manifest through UID 702.
        // Publish only the finalized bytes, after the weights' CAS root is known.
        // This is the local development signer, never a production trust root.
        let mut repo = DevRepo::open(&env.state_dir.join("tuf"))?;
        repo.add_target(&manifest_target, &manifest, json!({}))?;
        enclave_core::fsutil::write_private(
            &env.state_dir.join("cas").join(&manifest_target),
            &manifest,
        )?;
        tuf_refresh(env, &repo.repo_dir(), false)?;
    }
    let mut runner = env.connect(DaemonId::ModelRunner)?;
    // Binding verifies and loads the whole artifact (and a real model's
    // graph), which outlasts the default 30 s I/O bound for GB-sized pairs.
    runner.set_timeout(Some(BIND_TIMEOUT))?;
    let r: RunnerResponse = runner.call(&RunnerRequest::Bind {
        manifest: manifest.into(),
        cas_uri: cas_uri.clone(),
        calibration_corpus: corpus.map(Into::into),
    })?;
    match r {
        RunnerResponse::Bound {
            model_id,
            class,
            ece_ppm,
            topology_fingerprint,
        } => Ok(Admitted {
            model_id,
            class: class.name().into(),
            cas_uri,
            ece_ppm,
            topology_fingerprint,
        }),
        _ => fail!(EIO, "UNEXPECTED_RESPONSE"),
    }
}

/// Keep publisher-authenticated bytes intact outside the local dev signer.
fn admission_manifest(
    dev: bool,
    bytes: Vec<u8>,
    admitted_root: &str,
    target: &str,
) -> EnclaveResult<(Vec<u8>, String)> {
    if !dev {
        let manifest = ModelManifestV1::from_json(&bytes)?;
        if manifest.artifact.blake3 != admitted_root {
            fail!(EACCES, "MODEL_ARTIFACT_ROOT_MISMATCH");
        }
        return Ok((bytes, manifest.artifact.cas_uri));
    }
    let mut manifest: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| err!(EINVAL, "MANIFEST_SCHEMA", "{e}"))?;
    let cas_uri = format!("cas://blake3-bao-v1/{admitted_root}?target={target}&ns=models");
    manifest["artifact"]["blake3"] = json!(admitted_root);
    manifest["artifact"]["cas_uri"] = json!(cas_uri);
    let bytes = serde_json::to_vec(&manifest)
        .map_err(|e| err!(EIO, "MANIFEST_ENCODE", "{e}"))?;
    Ok((bytes, cas_uri))
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    #[test]
    fn production_admission_preserves_publisher_bytes_and_rejects_wrong_root() {
        let mut package = enclave_model_runnerd::zoo::package(ExecutionClass::ArCausal).unwrap();
        package.manifest["artifact"]["cas_uri"] = json!(format!(
            "cas://blake3-bao-v1/{}?target=publisher-target.safetensors&ns=models",
            package.manifest["artifact"]["blake3"].as_str().unwrap(),
        ));
        let bytes = package.manifest_bytes(); // Deliberately pretty-printed publisher bytes.
        let parsed = ModelManifestV1::from_json(&bytes).unwrap();
        let (forwarded, uri) = admission_manifest(
            false,
            bytes.clone(),
            &parsed.artifact.blake3,
            "publisher-target.safetensors",
        ).unwrap();
        assert_eq!(forwarded, bytes);
        assert_eq!(uri, parsed.artifact.cas_uri);
        assert!(admission_manifest(false, bytes, &"0".repeat(64), "unused")
            .unwrap_err().is("MODEL_ARTIFACT_ROOT_MISMATCH"));
    }
}

#[path="ctl_asset_enrollment.rs"]
mod asset_enrollment;
pub use asset_enrollment::{vault_enrollment_begin,vault_enrollment_activate,vault_enrollment_renew,
    vault_enrollment_begin_backup,vault_enrollment_add_backup,vault_enrollment_renew_membership,
    vault_namespace_backup_migrate,vault_travel_recovery_activate,vault_member_loss_record,
    vault_member_replacement_prepare};

/// `vault enroll-biometric` (`L1` only): register this Mac's Touch ID with
/// custody in one ceremony. Prints the key's SAS words, never key material.
pub fn vault_enroll_biometric(env: &Env) -> EnclaveResult<serde_json::Value> {
    crate::custody_notice::show_for_profile(&env.profile.to_string());
    use enclave_custody_vaultd::service::{VaultRequest, VaultResponse};
    match env
        .connect(DaemonId::CustodyVault)?
        .call::<_, VaultResponse>(&VaultRequest::EnrollBiometricL1)?
    {
        VaultResponse::BiometricEnrolled { sas } => Ok(json!({"enrolled": "touch_id_l1", "sas": sas})),
        _ => fail!(EIO, "UNEXPECTED_RESPONSE"),
    }
}

/// `vault enroll`.
pub fn vault_enroll(env: &Env) -> EnclaveResult<serde_json::Value> {
    crate::custody_notice::show_for_profile(&env.profile.to_string());
    use enclave_custody_vaultd::service::{VaultRequest, VaultResponse};
    match env
        .connect(DaemonId::CustodyVault)?
        .call::<_, VaultResponse>(&VaultRequest::Enroll)?
    {
        VaultResponse::Enrolled {
            credential_id,
            aaguid,
            firmware_version,
            sas,
        } => Ok(
            json!({"credential_id": credential_id, "aaguid": aaguid, "firmware_version": firmware_version, "sas": sas}),
        ),
        _ => fail!(EIO, "UNEXPECTED_RESPONSE"),
    }
}

fn cas_operator_response(env:&Env,request:enclave_custody_vaultd::service::VaultRequest)->EnclaveResult<serde_json::Value> {
    use enclave_custody_vaultd::service::VaultResponse;
    if !env.dev&&enclave_core::ipc::geteuid()!=0{fail!(EPERM,"CAS_KEY_PROVISION_PEER");}
    match env.connect(DaemonId::CustodyVault)?.call(&request)? {
        VaultResponse::WrappedCasKey(key)=>serde_json::to_value(key).map_err(|error|err!(EIO,"CAS_KEY_ENCODE","{error}")),
        VaultResponse::CasKeyLeaseValid=>Ok(json!({"status":"wrapping floor committed"})),
        _=>fail!(EIO,"UNEXPECTED_RESPONSE"),
    }
}
fn read_cas_envelope(path:&Path)->EnclaveResult<enclave_crypto::namespace::WrappedNamespaceKey> {
    use std::{io::Read,os::unix::fs::OpenOptionsExt};
    let file=std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK).open(path).map_err(|error|err!(EIO,"CAS_KEY_ENVELOPE_READ","{error}"))?;
    if !file.metadata().map_err(|error|err!(EIO,"CAS_KEY_ENVELOPE_READ","{error}"))?.is_file(){fail!(EINVAL,"CAS_KEY_ENVELOPE_FILE");}
    let mut bytes=Vec::new();file.take(4097).read_to_end(&mut bytes).map_err(|error|err!(EIO,"CAS_KEY_ENVELOPE_READ","{error}"))?;
    if bytes.len()>4096{fail!(E2BIG,"CAS_KEY_ENVELOPE_FILE");}
    let key:enclave_crypto::namespace::WrappedNamespaceKey=serde_json::from_slice(&bytes).map_err(|_|err!(EINVAL,"CAS_KEY_ENVELOPE_SHAPE"))?;key.validate()?;Ok(key)
}
/// Generate/register a fresh DEK through the operator-pinned custody RPC.
/// The only returned bytes are the opaque wrapped envelope.
pub fn vault_cas_wrap(env:&Env,namespace:String,epoch:u64,wrapping_epoch:u64)->EnclaveResult<serde_json::Value> {
    cas_operator_response(env,enclave_custody_vaultd::service::VaultRequest::WrapCasKey{namespace,epoch,wrapping_epoch,key:enclave_crypto::namespace::SecretMaterial(enclave_core::rng::bytes32().to_vec())})
}
/// Authenticate/register an existing opaque envelope during operator migration.
pub fn vault_cas_import(env:&Env,path:&Path)->EnclaveResult<serde_json::Value> {
    cas_operator_response(env,enclave_custody_vaultd::service::VaultRequest::ImportCasKey{wrapped:read_cas_envelope(path)?})
}
/// Rewrap a registered historical DEK without changing any artifact ciphertext.
pub fn vault_cas_rotate(env:&Env,path:&Path,new_wrapping_epoch:u64)->EnclaveResult<serde_json::Value> {
    cas_operator_response(env,enclave_custody_vaultd::service::VaultRequest::RotateCasKey{wrapped:read_cas_envelope(path)?,new_wrapping_epoch})
}
/// Advance the monotonic namespace floor after all registered histories rewrap.
pub fn vault_cas_floor(env:&Env,namespace:String,minimum_wrapping_epoch:u64)->EnclaveResult<serde_json::Value> {
    cas_operator_response(env,enclave_custody_vaultd::service::VaultRequest::AdvanceCasWrappingFloor{namespace,minimum_wrapping_epoch})
}

/// `vault detokenize`.
pub fn vault_detokenize(
    env: &Env,
    surrogates: Vec<String>,
    profile: Profile,
    action_class: enclave_core::profile::ActionClass,
) -> EnclaveResult<serde_json::Value> {
    use enclave_custody_vaultd::service::{VaultRequest, VaultResponse};
    let count = surrogates.len() as u64;
    let mut sorted = surrogates.clone();
    sorted.sort();
    let arguments =
        serde_json::to_vec(&sorted).map_err(|e| err!(EINVAL, "DETOKENIZE_ARGUMENTS", "{e}"))?;
    use sha2::Digest as _;
    let draft = Box::new(enclave_core::intent_draft::IntentDraftV1 {
        action_class,
        profile,
        data_class: enclave_core::label::Conf::C4,
        tool_name: "detokenize".into(),
        target_namespace: "custody".into(),
        canonical_verb: "Detokenize".into(),
        row_count_bound: count,
        arguments_jcs_sha256: hex::encode(sha2::Sha256::digest(&arguments)),
        canonical_arguments_blake3: blake3::hash(&arguments).to_hex().to_string(),
        policy_blake3: hex::encode([0u8; 32]),
        qif_millibits_delta: 0,
        org_root_mutation: false,
    });
    match env
        .connect(DaemonId::CustodyVault)?
        .call::<_, VaultResponse>(&VaultRequest::Detokenize { surrogates, draft })?
    {
        VaultResponse::Delivered { rows, d_jcs } => Ok(json!({
            "rows": rows,
            "d_jcs": d_jcs,
            "profile": profile.to_string(),
        })),
        _ => fail!(EIO, "UNEXPECTED_RESPONSE"),
    }
}

/// One verified journal.
#[derive(Debug, Clone, Serialize)]
pub struct JournalReport {
    /// Path.
    pub path: String,
    /// Internal chain validity; use truncation_checked to assess checkpoint coverage.
    pub ok: bool,
    /// Whether a separately trusted checkpoint was supplied.
    pub truncation_checked: bool,
    /// Entries.
    pub entries: u64,
    /// Tip BLAKE3.
    pub tip_blake3: String,
    /// Tip Poseidon2.
    pub tip_poseidon2: String,
    /// Error.
    pub error: Option<String>,
}

/// Every `*-audit.jsonl` in `dir` or one level below it (journals live in
/// per-daemon sub-directories, `<audit>/<suffix>/<suffix>-audit.jsonl`).
pub fn journal_files(dir: &Path) -> EnclaveResult<Vec<PathBuf>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir)
        .map_err(|e| err!(EIO, "AUDIT_DIR", "{e}"))?
        .filter_map(Result::ok)
    {
        let p = e.path();
        let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if is_dir {
            if let Ok(rd) = std::fs::read_dir(&p) {
                out.extend(
                    rd.filter_map(Result::ok)
                        .map(|e| e.path())
                        .filter(|p| p.to_string_lossy().ends_with("-audit.jsonl")),
                );
            }
        } else if p.to_string_lossy().ends_with("-audit.jsonl") {
            out.push(p);
        }
    }
    Ok(out)
}

/// `audit verify`: every `*-audit.jsonl` under `dir` (or one file).
pub fn audit_verify(target: &Path) -> EnclaveResult<Vec<JournalReport>> {
    audit_verify_with_anchor(target, None)
}

/// Verify a single journal with a separately trusted off-host checkpoint.
pub fn audit_verify_with_anchor(
    target: &Path,
    anchor: Option<enclave_core::audit::ChainAnchor>,
) -> EnclaveResult<Vec<JournalReport>> {
    if target.is_dir() && anchor.is_some() {
        fail!(EINVAL, "AUDIT_ANCHOR_SINGLE_JOURNAL");
    }
    let files: Vec<PathBuf> = if target.is_dir() {
        let mut v = journal_files(target)?;
        v.sort();
        v
    } else {
        vec![target.to_owned()]
    };
    if files.is_empty() {
        fail!(EINVAL, "NO_JOURNALS", "{}", target.display());
    }
    Ok(files
        .into_iter()
        .map(|p| match enclave_core::audit::verify_journal(&p, anchor) {
            Ok(s) => JournalReport {
                path: p.display().to_string(),
                ok: true,
                truncation_checked: anchor.is_some(),
                entries: s.entries,
                tip_blake3: s.tip_blake3,
                tip_poseidon2: s.tip_poseidon2,
                error: None,
            },
            Err(e) => JournalReport {
                path: p.display().to_string(),
                ok: false,
                truncation_checked: anchor.is_some(),
                entries: 0,
                tip_blake3: String::new(),
                tip_poseidon2: String::new(),
                error: Some(e.to_string()),
            },
        })
        .collect())
}

/// Submit a user turn to the enclave (GAP-18).
pub fn turn_submit(
    env: &Env,
    directive: &str,
    attachments: &[PathBuf],
) -> EnclaveResult<serde_json::Value> {
    enclave_core::user_turn::validate_directive(directive)?;
    let mut att_refs = Vec::new();
    let mut att_payloads = Vec::new();

    for (idx, p) in attachments.iter().enumerate() {
        let bytes =
            std::fs::read(p).map_err(|e| err!(EIO, "READ_ATTACHMENT", "{}: {e}", p.display()))?;
        let hash = blake3::hash(&bytes).to_hex().to_string();
        let handle = format!("$paste_{idx}");
        att_refs.push(enclave_core::user_turn::AttachmentRef {
            handle: handle.clone(),
            label: enclave_core::label::Label::new(
                enclave_core::label::Conf::C3,
                enclave_core::label::Taint::T3,
            ),
            blake3: hash,
            kind: None,
        });
        att_payloads.push((handle, serde_bytes::ByteBuf::from(bytes)));
    }

    let turn = enclave_core::user_turn::UserTurnV1 {
        directive_short: directive.to_string(),
        attachments: att_refs,
    };

    let ifc_sock = env.socket_dir.join("ifc").join("ifc.sock");
    let target_uid = env.uid_of(DaemonId::AgentRuntime);
    let mut client = if env.dev {
        enclave_core::ipc::Client::connect(&ifc_sock, target_uid)?
    } else {
        enclave_core::ipc::Client::connect_verified(
            &ifc_sock,
            target_uid,
            Some(&enclave_core::codesign::CodeRequirement::daemon(
                DaemonId::AgentRuntime,
            )),
        )?
    };
    let req = enclave_agent_runtime::service::IfcRequest::SubmitTurn {
        turn,
        attachments: att_payloads,
        tools: Vec::new(),
        holder_pk: None,
        budget_mb: 1000,
    };
    let resp: enclave_agent_runtime::service::IfcResponse = client.call(&req)?;
    match resp {
        enclave_agent_runtime::service::IfcResponse::Plan {
            context,
            root_token,
        } => Ok(json!({
            "status": "compiled",
            "directive": directive,
            "plan_context": context,
            "has_root_token": root_token.is_some(),
        })),
        other => fail!(EIO, "TURN_SUBMIT_FAILED", "unexpected response: {other:?}"),
    }
}

/// Hidden `__daemon <uid> [args...]`: run a daemon's entry point in-process.
pub fn run_embedded(uid: u32, rest: Vec<String>) -> EnclaveResult<()> {
    let d = DaemonId::from_uid(uid).ok_or_else(|| err!(EINVAL, "UNKNOWN_DAEMON_UID", "{uid}"))?;
    let args = enclave_core::runtime::DaemonArgs::parse(
        std::iter::once(d.binary().to_owned()).chain(rest),
    )?;
    args.bind_deployment_context()?;
    match d {
        DaemonId::ModelRunner => enclave_model_runnerd::entry::run(args),
        DaemonId::SwarmSync => enclave_swarm_syncd::entry::run(args),
        DaemonId::CustodyVault => enclave_custody_vaultd::entry::run(args),
        DaemonId::AgentRuntime => enclave_agent_runtime::entry::run(args),
        DaemonId::ZkAuditor => enclave_zk_auditor::entry::run(args),
    }
}

/// Persisted cryptographic agility policy (`FS-707 §7`, `RB-219`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoPolicyState {
    /// Active wire suite (`HybridPqc` or `ClassicalOnly`).
    pub active_suite: String,
    /// Optional emergency override ticket (`RB-219`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub override_ticket: Option<String>,
}

/// Report active Post-Quantum Cryptographic status, FIPS 203/204 parameters, and suite policy.
pub fn crypto_status(env: &Env) -> EnclaveResult<serde_json::Value> {
    let policy_path = env.state_dir.join("crypto-policy.json");
    let policy: CryptoPolicyState = std::fs::read(&policy_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(CryptoPolicyState {
            active_suite: "HybridPqc".into(),
            override_ticket: None,
        });

    let ohttp_suite = std::fs::read_to_string(env.state_dir.join("ohttp-gateway.config"))
        .ok()
        .and_then(|s| enclave_crypto::ohttp::KeyConfig::parse(s.trim()).ok())
        .map(|cfg| format!("{:?}", cfg.suite()))
        .unwrap_or_else(|| "HybridPqc".into());

    Ok(json!({
        "active_suite": policy.active_suite,
        "override_ticket": policy.override_ticket,
        "ohttp_gateway_suite": ohttp_suite,
        "kem": {
            "standard": "NIST FIPS 203 (ML-KEM-768) + RFC 7748 (X25519)",
            "combiner": "MCPMac bespoke HKDF-SHA256 transcript-bound (not X-Wing)",
            "public_key_bytes": enclave_crypto::pqc::HYBRID_KEM_PUBLIC_KEY_SIZE,
            "ciphertext_bytes": enclave_crypto::pqc::HYBRID_KEM_CIPHERTEXT_SIZE,
            "secret_key_bytes": enclave_crypto::pqc::HYBRID_KEM_SECRET_KEY_SIZE,
            "enforced_surfaces": [
                "Envelope_A3 (UID 703 C3 custody surrogates)",
                "Envelope_A4 (UID 703 C4/bulk custody surrogates)",
                "OHTTP Relay & L3 Model Fetch (UID 702 local KEM_ID 0xFF41)"
            ]
        },
        "signatures": {
            "standard": "NIST FIPS 204 (ML-DSA-65) + RFC 8032 (Ed25519)",
            "combiner": "IETF LAMPS Composite (domain + dual public-key bound)",
            "verifying_key_bytes": enclave_crypto::pqc::HYBRID_VERIFYING_KEY_SIZE,
            "signature_bytes": enclave_crypto::pqc::HYBRID_SIGNATURE_SIZE,
            "enforced_surfaces": [
                "ComplianceRollupProofV1 L2 Batch Anchor (UID 705)",
                "Audit Journal Checkpoint Attestation"
            ]
        }
    }))
}

/// Run live NIST FIPS 203 (`ML-KEM-768` + X25519) and NIST FIPS 204 (`ML-DSA-65` + Ed25519)
/// Known-Answer / round-trip and tamper-rejection self-tests.
pub fn crypto_self_test() -> EnclaveResult<serde_json::Value> {
    use enclave_crypto::pqc::{
        enforce_handshake_suite, HybridKemKeyPair, HybridSigningKey, WireCryptoSuite,
    };

    let kem_kp = HybridKemKeyPair::generate();
    let kem_pk = kem_kp.public_key();
    let (ct, ss_sender) = HybridKemKeyPair::encapsulate(&kem_pk)?;
    let ss_receiver = kem_kp.decapsulate(&ct)?;
    if ss_sender.0 != ss_receiver.0 {
        fail!(EIO, "PQC_SELFTEST_KEM_MISMATCH");
    }

    let mut bad_ct = ct.clone();
    bad_ct.pqc_ciphertext[0] ^= 0x01;
    let ss_implicit_reject = kem_kp.decapsulate(&bad_ct)?;
    if ss_implicit_reject.0 == ss_sender.0 {
        fail!(EIO, "PQC_SELFTEST_FO_IMPLICIT_REJECTION_FAILED");
    }

    let sig_kp = HybridSigningKey::generate();
    let sig_vk = sig_kp.verifying_key();
    let msg = b"MCPMac-FIPS203-FIPS204-SelfTest-v1";
    let sig = sig_kp.sign(msg);
    sig_vk.verify(msg, &sig)?;

    let mut bad_sig = sig.clone();
    bad_sig.pqc[0] ^= 0x01;
    if sig_vk.verify(msg, &bad_sig).is_ok() {
        fail!(EIO, "PQC_SELFTEST_DSA_TAMPER_ACCEPTED");
    }

    if enforce_handshake_suite(WireCryptoSuite::HybridPqc, WireCryptoSuite::ClassicalOnly).is_ok() {
        fail!(EIO, "PQC_SELFTEST_DOWNGRADE_GUARD_FAILED");
    }

    Ok(json!({
        "status": "passed",
        "fips203_ml_kem_768_x25519": "ok",
        "fips203_fo_implicit_rejection": "ok",
        "fips204_ml_dsa_65_ed25519": "ok",
        "anti_downgrade_guard": "ok"
    }))
}

/// Set the active wire cryptographic suite (`RB-219` emergency cryptographic-agility drill).
pub fn crypto_policy_set(
    env: &Env,
    wire_suite: &str,
    temporary_override_ticket: Option<&str>,
) -> EnclaveResult<serde_json::Value> {
    let normalized = match wire_suite {
        "HybridPqc" | "hybrid-pqc" => "HybridPqc",
        "ClassicalOnly" | "classical-only" => {
            let ticket = temporary_override_ticket
                .map(str::trim)
                .filter(|s| { let digits = s.strip_prefix("INC-").or_else(|| s.strip_prefix("SEC-")); digits.is_some_and(|d| (3..=10).contains(&d.len()) && d.bytes().all(|b| b.is_ascii_digit())) })
                .ok_or_else(|| {
                    err!(
                        EACCES,
                        "PQC_OVERRIDE_TICKET_REQUIRED",
                        "Downgrading wire suite to ClassicalOnly requires --temporary-override-ticket (RB-219)"
                    )
                })?;
            let _ = ticket;
            "ClassicalOnly"
        }
        other => fail!(
            EINVAL,
            "UNKNOWN_WIRE_SUITE",
            "Expected HybridPqc or ClassicalOnly, got {other}"
        ),
    };

    mkdir(&env.state_dir)?;
    let state = CryptoPolicyState {
        active_suite: normalized.into(),
        override_ticket: if normalized == "ClassicalOnly" {
            temporary_override_ticket.map(str::to_owned)
        } else {
            None
        },
    };
    let policy_path = env.state_dir.join("crypto-policy.json");
    let bytes =
        serde_json::to_vec_pretty(&state).map_err(|e| err!(EIO, "CRYPTO_POLICY_ENCODE", "{e}"))?;
    std::fs::write(&policy_path, bytes).map_err(|e| err!(EIO, "CRYPTO_POLICY_WRITE", "{e}"))?;
    restrict(&policy_path);

    let mut status = crypto_status(env)?;
    status["configuration_only"] = json!(true);
    status["runtime_applied"] = json!(false);
    Ok(status)
}

/// Flush cached PQC / OHTTP gateway session keys and regenerate fresh key material (`RB-219`).
pub fn crypto_flush_sessions(env: &Env) -> EnclaveResult<serde_json::Value> {
    mkdir(&env.state_dir)?;
    let gp = env.state_dir.join("ohttp-gateway.config");
    let skp = env.state_dir.join("ohttp-gateway.key");
    let policy_path = env.state_dir.join("crypto-policy.json");
    let is_classical = std::fs::read(&policy_path)
        .ok()
        .and_then(|b| serde_json::from_slice::<CryptoPolicyState>(&b).ok())
        .is_some_and(|p| p.active_suite == "ClassicalOnly");

    let (cfg, sk) = if is_classical {
        enclave_crypto::ohttp::gateway_classical_keypair(1)
    } else {
        enclave_crypto::ohttp::gateway_keypair(1)
    };
    std::fs::write(&gp, cfg.render()).map_err(|e| err!(EIO, "KEY_WRITE", "{e}"))?;
    enclave_core::fsutil::write_private(&skp, hex::encode(sk).as_bytes())?;

    Ok(json!({
        "status": "flushed",
        "ohttp_gateway_suite": format!("{:?}", cfg.suite()),
        "public_key_bytes": cfg.public_key.len()
    }))
}

/// Authenticated policy telemetry acquisition; this is never a release approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySliExport {
    /// Kernel-attested server UID.
    pub peer_uid: u32,
    /// Kernel-attested server PID when available.
    pub peer_pid: Option<u32>,
    /// Actual verified server signing identity, absent for development/Linux.
    pub peer_code_identity: Option<enclave_core::codesign::CodeIdentity>,
    /// True only when production code verification actually ran on this host.
    pub server_code_verified: bool,
    /// All 4320 policy minutes present without errors/unknowns (not SLO success).
    pub history_complete: bool,
    /// Exact number of strict rows available for the offline aggregator.
    pub exported_rows: usize,
    /// Bounded, privacy-safe daemon data, including partial/current counts.
    pub snapshot: enclave_agent_runtime::policy_sli::PolicySliSnapshot,
}

/// Authenticated configured-queue metadata, never a delivery approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboxDiagnosticsExport {
    /// Actual kernel-attested service UID.
    pub peer_uid: u32,
    /// Actual positive kernel service PID.
    pub peer_pid: u32,
    /// Actual code-verification receipt when that check ran.
    pub peer_code_identity: Option<enclave_core::codesign::CodeIdentity>,
    /// True only for actually enforced production code verification.
    pub server_code_verified: bool,
    /// Fixed bounded metadata from the service-owned configured directory.
    pub snapshot: enclave_swarm_syncd::outbox::OutboxDiagnosticsSnapshot,
}

/// Acquire queue metadata through the existing authenticated one-shot IPC.
/// Connection, request handoff and reply each have their documented separate
/// bounds; no shared end-to-end or host-scheduling hard deadline is claimed.
pub fn outbox_diagnostics(env: &Env) -> EnclaveResult<OutboxDiagnosticsExport> {
    let daemon = DaemonId::SwarmSync;
    let requirement = (!env.dev).then(|| enclave_core::codesign::CodeRequirement::daemon(daemon));
    let client = Client::connect_verified_deadline(&env.socket_dir.join(daemon.socket_name()),
        env.uid_of(daemon), requirement.as_ref(), Duration::from_secs(5))
        .map_err(|_| err!(EIO, "OUTBOX_DIAGNOSTICS_CONNECT"))?;
    let server = client.server.clone();
    let response: CasResponse = client.prepare_call(&CasRequest::OutboxDiagnostics)
        .and_then(|prepared| prepared.handoff())
        .and_then(|pending| pending.receive())
        .map_err(|_| err!(EIO, "OUTBOX_DIAGNOSTICS_ACQUIRE"))?;
    let CasResponse::OutboxDiagnostics(snapshot) = response else {
        fail!(EIO, "OUTBOX_DIAGNOSTICS_RESPONSE");
    };
    let peer_pid = validate_outbox_diagnostics(&snapshot, &server, env.dev)?;
    let server_code_verified = !env.dev && enclave_core::codesign::enforced() && server.code_identity.is_some();
    Ok(OutboxDiagnosticsExport { peer_uid: server.uid, peer_pid,
        peer_code_identity: server.code_identity, server_code_verified, snapshot })
}

fn validate_outbox_diagnostics(snapshot: &enclave_swarm_syncd::outbox::OutboxDiagnosticsSnapshot,
    peer: &enclave_core::ipc::PeerCredentials, dev: bool) -> EnclaveResult<u32> {
    if !snapshot.valid() { fail!(EINVAL, "OUTBOX_DIAGNOSTICS_METADATA"); }
    let Some(pid) = peer.pid.and_then(|p| u32::try_from(p).ok()).filter(|p| *p > 0) else {
        fail!(EACCES, "OUTBOX_DIAGNOSTICS_PEER_PID");
    };
    if snapshot.process_uid != peer.uid || snapshot.process_pid != pid || snapshot.dev_same_uid != dev {
        fail!(EACCES, "OUTBOX_DIAGNOSTICS_IDENTITY");
    }
    Ok(pid)
}

/// Authenticated acquisition of fixed local synchronization-stage diagnostics.
/// Successful acquisition, including a measurement fault, is never SLO health.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncDiagnosticsExport {
    /// Actual server kernel UID.
    pub peer_uid:u32,
    /// Strictly positive actual server kernel PID.
    pub peer_pid:u32,
    /// Actual code-verification receipt, absent when verification did not run.
    pub peer_code_identity:Option<enclave_core::codesign::CodeIdentity>,
    /// True only when production macOS code verification actually ran.
    pub server_code_verified:bool,
    /// Service-owned, bounded per-process stage diagnostics.
    pub snapshot:enclave_swarm_syncd::sync_diagnostics::SyncDiagnosticsSnapshot,
}

/// Read UID 702 diagnostics with bounded existing IPC and privacy-safe errors.
pub fn swarm_sync_diagnostics(env:&Env)->EnclaveResult<SyncDiagnosticsExport> {
    let daemon=DaemonId::SwarmSync;
    let requirement=(!env.dev).then(||enclave_core::codesign::CodeRequirement::daemon(daemon));
    let mut client=Client::connect_verified_deadline(&env.socket_dir.join(daemon.socket_name()),
        env.uid_of(daemon),requirement.as_ref(),Duration::from_secs(5))
        .map_err(|_|err!(EIO,"SYNC_DIAGNOSTICS_CONNECT"))?;
    client.set_timeout(Some(Duration::from_secs(5)))
        .map_err(|_|err!(EIO,"SYNC_DIAGNOSTICS_TIMEOUT"))?;
    // Never propagate arbitrary backend Reply::Err, decoding or signing text.
    let response:CasResponse=client.call(&CasRequest::SyncDiagnostics)
        .map_err(|_|err!(EIO,"SYNC_DIAGNOSTICS_ACQUIRE"))?;
    let CasResponse::SyncDiagnostics(snapshot)=response else {fail!(EIO,"SYNC_DIAGNOSTICS_RESPONSE");};
    let peer_pid=validate_sync_diagnostics(&snapshot,&client.server,env.dev)?;
    let server_code_verified=!env.dev&&enclave_core::codesign::enforced()&&client.server.code_identity.is_some();
    Ok(SyncDiagnosticsExport {peer_uid:client.server.uid,peer_pid,
        peer_code_identity:client.server.code_identity.clone(),server_code_verified,snapshot})
}

fn validate_sync_diagnostics(snapshot:&enclave_swarm_syncd::sync_diagnostics::SyncDiagnosticsSnapshot,
    peer:&enclave_core::ipc::PeerCredentials,dev:bool)->EnclaveResult<u32> {
    use enclave_swarm_syncd::sync_diagnostics::PRODUCER;
    if snapshot.schema!=1||snapshot.producer!=PRODUCER||snapshot.process_epoch_id.len()!=36
        ||enclave_core::seq::validate_epoch_id(&snapshot.process_epoch_id).is_err()
        ||!snapshot.valid_measurement() {
        fail!(EINVAL,"SYNC_DIAGNOSTICS_METADATA");
    }
    let Some(pid)=peer.pid.and_then(|p|u32::try_from(p).ok()).filter(|p|*p>0) else {
        fail!(EACCES,"SYNC_DIAGNOSTICS_PEER_PID");
    };
    if snapshot.process_uid!=peer.uid||snapshot.process_pid!=pid||snapshot.dev_same_uid!=dev {
        fail!(EACCES,"SYNC_DIAGNOSTICS_IDENTITY");
    }
    Ok(pid)
}

#[cfg(test)]
mod sync_diagnostics_tests {
    use super::*;
    use enclave_swarm_syncd::sync_diagnostics::{CounterAvailability,MeasurementFaults,StageRecords,SyncDiagnosticsSnapshot,PRODUCER};
    fn snapshot()->SyncDiagnosticsSnapshot {SyncDiagnosticsSnapshot {schema:1,producer:PRODUCER.into(),
        process_epoch_id:enclave_core::seq::new_boot_epoch_id(),process_uid:enclave_core::ipc::geteuid(),
        process_pid:std::process::id(),dev_same_uid:true,measurement_fault:MeasurementFaults::default(),
        availability:CounterAvailability::Current,stages:Some(StageRecords::default())}}

    #[test]
    fn sync_diagnostics_requires_positive_kernel_pid_and_exact_uid_pid_mode_binding() {
        let snapshot=snapshot();let mut peer=enclave_core::ipc::PeerCredentials::local(snapshot.process_uid,0);
        peer.pid=Some(i32::try_from(snapshot.process_pid).unwrap());
        assert_eq!(validate_sync_diagnostics(&snapshot,&peer,true).unwrap(),snapshot.process_pid);
        // Explicit unit controls for impossible-to-forge kernel metadata; these
        // are not claims that a supported host produced missing/negative PIDs.
        for pid in [None,Some(0),Some(-1),Some(i32::MIN)] {
            peer.pid=pid;assert!(validate_sync_diagnostics(&snapshot,&peer,true).unwrap_err().is("SYNC_DIAGNOSTICS_PEER_PID"));
        }
        peer.pid=Some(i32::try_from(snapshot.process_pid).unwrap());
        for field in 0..3 {let mut invalid=snapshot.clone();match field {0=>invalid.process_uid^=1,1=>invalid.process_pid^=1,_=>invalid.dev_same_uid=false}
            assert!(validate_sync_diagnostics(&invalid,&peer,true).unwrap_err().is("SYNC_DIAGNOSTICS_IDENTITY"));}
    }

    #[test]
    fn sync_diagnostics_validation_refuses_ambiguous_availability_and_private_metadata() {
        let snapshot=snapshot();let mut peer=enclave_core::ipc::PeerCredentials::local(snapshot.process_uid,0);peer.pid=Some(snapshot.process_pid as i32);
        for field in 0..6 {
            let mut invalid=snapshot.clone();match field {
                0=>invalid.producer="canary-target/ns/path/uri/token/backend".into(),
                1=>invalid.process_epoch_id="canary-target/ns/path/uri/token/backend".into(),
                2=>invalid.measurement_fault.overflow=true,
                3=>invalid.availability=CounterAvailability::LastKnown,
                4=>invalid.stages=None,
                _=>invalid.stages.as_mut().unwrap().registry_fetch.started=1,
            }
            let error=validate_sync_diagnostics(&invalid,&peer,true).unwrap_err();
            assert!(error.is("SYNC_DIAGNOSTICS_METADATA"));assert!(!error.to_string().contains("canary"));
        }
        let mut last=snapshot.clone();last.measurement_fault.overflow=true;last.availability=CounterAvailability::LastKnown;
        validate_sync_diagnostics(&last,&peer,true).unwrap();
        last.measurement_fault.poisoned=true;last.availability=CounterAvailability::Unavailable;last.stages=None;
        validate_sync_diagnostics(&last,&peer,true).unwrap();
        // A fresh CLI has no independently trusted expected collector UUID.
        let mut changed=snapshot.clone();changed.process_epoch_id=enclave_core::seq::new_boot_epoch_id();
        validate_sync_diagnostics(&changed,&peer,true).unwrap();
    }
}

/// Fetch bounded policy counters over the operator's existing authenticated IPC.
/// A five-second connect timeout and five-second I/O timeouts bound waits.
pub fn ifc_policy_sli(env: &Env) -> EnclaveResult<PolicySliExport> {
    use enclave_agent_runtime::service::{IfcRequest, IfcResponse};
    let daemon = DaemonId::AgentRuntime;
    let requirement = (!env.dev).then(|| enclave_core::codesign::CodeRequirement::daemon(daemon));
    let mut client = Client::connect_verified_deadline(
        &env.socket_dir.join(daemon.socket_name()), env.uid_of(daemon),
        requirement.as_ref(), Duration::from_secs(5),
    )?;
    client.set_timeout(Some(Duration::from_secs(5)))?;
    let response: IfcResponse = client.call(&IfcRequest::PolicySli)?;
    let IfcResponse::PolicySli(snapshot) = response else { fail!(EIO, "POLICY_SLI_RESPONSE"); };
    validate_policy_sli(&snapshot)?;
    let peer_pid = client.server.pid.map(u32::try_from).transpose()
        .map_err(|_| err!(EACCES, "POLICY_SLI_INVALID_PEER_PID"))?;
    if peer_pid == Some(0) { fail!(EACCES, "POLICY_SLI_INVALID_PEER_PID"); }
    if snapshot.runtime_uid != client.server.uid
        || peer_pid.is_some_and(|pid| pid != snapshot.runtime_pid)
        || snapshot.dev_same_uid != env.dev {
        fail!(EACCES, "POLICY_SLI_IDENTITY_MISMATCH");
    }
    let server_code_verified = !env.dev && enclave_core::codesign::enforced()
        && client.server.code_identity.is_some();
    Ok(PolicySliExport {
        peer_uid: client.server.uid, peer_pid,
        peer_code_identity: client.server.code_identity.clone(), server_code_verified,
        history_complete: snapshot.history_complete(), exported_rows: snapshot.rows().len(), snapshot,
    })
}

fn validate_policy_sli(snapshot: &enclave_agent_runtime::policy_sli::PolicySliSnapshot) -> EnclaveResult<()> {
    use enclave_agent_runtime::policy_sli::{HISTORY_MINUTES, MAX_COUNT};
    let digest = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if snapshot.schema != 1 || snapshot.producer != "uid704-conjunctive-policy-v1"
        || snapshot.boot_epoch_id.is_empty() || snapshot.boot_epoch_id.len() > 128
        || !matches!(snapshot.profile.as_str(), "L1" | "L2" | "L3")
        || !digest(&snapshot.cedar_bundle_blake3) || !digest(&snapshot.mcp_lock_blake3)
        || snapshot.buckets.len() > HISTORY_MINUTES
        || snapshot.observed_total > MAX_COUNT || snapshot.observed_errors > snapshot.observed_total {
        fail!(EINVAL, "POLICY_SLI_INVALID_METADATA");
    }
    let bucket_valid = |b: &enclave_agent_runtime::policy_sli::PolicyBucket| {
        b.minute % 60 == 0 && b.total <= MAX_COUNT && b.bad <= b.total
            && b.unknown <= b.total - b.bad && b.errors <= b.bad + b.unknown
    };
    if !snapshot.buckets.iter().all(bucket_valid) || snapshot.current.as_ref().is_some_and(|b| !bucket_valid(b))
        || snapshot.buckets.windows(2).any(|pair| pair[0].minute >= pair[1].minute) {
        fail!(EINVAL, "POLICY_SLI_INVALID_COUNTERS");
    }
    // Before overflow, retained/current events are a subset of lifetime counts.
    // With overflow latched those counters are diagnostic lower bounds; rows()
    // remains empty, and the fault receipt must remain available.
    if !snapshot.overflow {
        let sum = snapshot.buckets.iter().chain(snapshot.current.iter()).try_fold((0_u64, 0_u64), |(total, errors), b| {
            Some((total.checked_add(b.total)?, errors.checked_add(b.errors)?))
        });
        if !matches!(sum, Some((total, errors)) if total <= snapshot.observed_total && errors <= snapshot.observed_errors) {
            fail!(EINVAL, "POLICY_SLI_COUNTER_CONSERVATION");
        }
    }
    if !snapshot.clock_fault {
        let Some(as_of) = snapshot.as_of_unix_s else { fail!(EINVAL, "POLICY_SLI_INVALID_CLOCK"); };
        if as_of % 60 != 0 || snapshot.current.as_ref().is_none_or(|b| b.minute != as_of)
            || snapshot.buckets.iter().any(|b| b.minute >= as_of || as_of - b.minute > HISTORY_MINUTES as u64 * 60)
            {
            fail!(EINVAL, "POLICY_SLI_INVALID_COVERAGE");
        }
    }
    Ok(())
}

#[cfg(test)]
mod policy_sli_tests {
    use super::*;
    use enclave_agent_runtime::policy_sli::{PolicyBucket, PolicySliSnapshot, MAX_COUNT};

    fn snapshot() -> PolicySliSnapshot {
        PolicySliSnapshot {
            schema: 1, producer: "uid704-conjunctive-policy-v1".into(), boot_epoch_id: "test-boot".into(),
            profile: "L2".into(), cedar_bundle_blake3: "a".repeat(64), mcp_lock_blake3: "b".repeat(64),
            runtime_uid: 704, runtime_pid: 1234, dev_same_uid: false, as_of_unix_s: Some(1_800_000_000),
            clock_fault: false, overflow: false, observed_total: 1, observed_errors: 0,
            buckets: vec![PolicyBucket { minute: 1_799_999_940, total: 1, bad: 0, unknown: 0, errors: 0 }],
            current: Some(PolicyBucket { minute: 1_800_000_000, total: 0, bad: 0, unknown: 0, errors: 0 }),
        }
    }

    #[test]
    fn policy_sli_refuses_ambiguous_counts_and_coverage_before_export() {
        let mut sample = snapshot();
        validate_policy_sli(&sample).unwrap();
        sample.buckets[0].unknown = 1;
        sample.buckets[0].bad = 1;
        assert!(validate_policy_sli(&sample).unwrap_err().is("POLICY_SLI_INVALID_COUNTERS"));
        sample = snapshot(); sample.buckets[0].total = MAX_COUNT + 1;
        assert!(validate_policy_sli(&sample).is_err());
        sample = snapshot(); sample.buckets.push(sample.buckets[0].clone());
        assert!(validate_policy_sli(&sample).is_err());
        sample = snapshot(); sample.buckets[0].minute = 1_800_000_000;
        assert!(validate_policy_sli(&sample).is_err());
        sample = snapshot(); sample.current = None;
        assert!(validate_policy_sli(&sample).is_err());
        sample = snapshot(); sample.cedar_bundle_blake3 = "caller assertion".into();
        assert!(validate_policy_sli(&sample).unwrap_err().is("POLICY_SLI_INVALID_METADATA"));
    }

    #[test]
    fn policy_sli_checks_lifetime_conservation_but_keeps_overflow_diagnostics() {
        let mut sample = snapshot();
        sample.current.as_mut().unwrap().total = 1;
        assert!(validate_policy_sli(&sample).unwrap_err().is("POLICY_SLI_COUNTER_CONSERVATION"));
        sample = snapshot(); sample.buckets[0].bad = 1; sample.buckets[0].errors = 1;
        assert!(validate_policy_sli(&sample).unwrap_err().is("POLICY_SLI_COUNTER_CONSERVATION"));
        sample.observed_errors = 1;
        validate_policy_sli(&sample).unwrap();
        sample.current.as_mut().unwrap().total = 1;
        sample.overflow = true;
        validate_policy_sli(&sample).unwrap();
        assert!(sample.rows().is_empty());
        sample = snapshot(); sample.buckets[0].errors = 1;
        assert!(validate_policy_sli(&sample).unwrap_err().is("POLICY_SLI_INVALID_COUNTERS"));
    }

    #[test]
    fn policy_sli_faults_and_outcome_gaps_cannot_export_healthy_rows() {
        let mut sample = snapshot();
        sample.clock_fault = true;
        validate_policy_sli(&sample).unwrap();
        assert!(sample.rows().is_empty());
        sample = snapshot(); sample.overflow = true;
        assert!(sample.rows().is_empty());
        sample = snapshot(); sample.buckets[0].bad = 1; sample.buckets[0].errors = 1; sample.observed_errors = 1;
        validate_policy_sli(&sample).unwrap();
        assert!(sample.rows().is_empty(), "known slow error must leave an explicit missing bucket");
        assert_eq!(sample.buckets[0].bad, 1, "retain the known bad lower bound in the authenticated snapshot");
        assert!(!sample.history_complete());
    }
}

#[cfg(test)]
mod terminate_tests {
    use super::*;

    fn spawn(script: &str) -> u32 {
        let child = Command::new("/bin/sh").arg("-c").arg(script).spawn().unwrap();
        let pid = child.id();
        std::mem::forget(child);
        pid
    }

    /// A failed `daemon start` stops what it launched, including a process
    /// that ignores SIGTERM, and reaps both.
    #[test]
    fn terminate_stops_and_reaps_what_start_launched() {
        let polite = spawn("exec sleep 60");
        let stubborn = spawn("trap '' TERM; while :; do sleep 1; done");
        std::thread::sleep(Duration::from_millis(200));
        let started = Instant::now();
        terminate(&[polite, stubborn]);
        assert!(!alive(polite), "SIGTERM stops a cooperative child");
        assert!(!alive(stubborn), "SIGKILL follows the grace period");
        assert!(started.elapsed() < Duration::from_secs(6));
    }
}
