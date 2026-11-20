//! Protected per-boot finite selected-owner session input, not readiness.
//!
//! The operator provisions the endpoint. This reader never writes/repairs a
//! record, chooses a duration, renews a session, or enables selected startup.
use std::{ffi::CString, fs::{File, Metadata}, os::{fd::{AsRawFd, FromRawFd},
    unix::{ffi::OsStrExt, fs::{FileExt, MetadataExt}}}, path::{Component, Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering}, time::{Duration, Instant}};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use crate::{codesign, daemon::DaemonId, deployment::{self, CheckedDeploymentTarget,
    DeploymentRole, DeploymentSigningMode}, error::EnclaveResult, Profile, err, fail};

/// Fixed public input under the actual selected root-owned0755 socket root.
pub const SESSION_LEAF: &str = ".depot-selected-owner-session-v1.json";
const MAX_RECORD: usize = 8192;
const MAX_PARENTS: usize = 64;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    v: u8, target_id: String, descriptor_sha256: String, profile: Profile,
    signing: DeploymentSigningMode, boot_session_uuid: String,
    policy_session_id: String, not_before_boot_ns_hex: String, not_after_boot_ns_hex: String,
}
struct Parsed { session: [u8;32], boot: [u8;16], start: u64, end: u64 }
struct Binding { target: String, descriptor: String }
fn hex_array<const N: usize>(value: &str) -> EnclaveResult<[u8;N]> {
    if value.len() != N*2 || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        fail!(EINVAL, "SELECTED_SESSION_SCHEMA");
    }
    hex::decode(value).ok().and_then(|raw| raw.try_into().ok())
        .ok_or_else(|| err!(EINVAL, "SELECTED_SESSION_SCHEMA"))
}
fn uuid_bytes(value: &str) -> EnclaveResult<[u8;16]> {
    let uuid = uuid::Uuid::parse_str(value).map_err(|_| err!(EINVAL, "SELECTED_SESSION_BOOT"))?;
    if uuid.is_nil() || uuid.hyphenated().to_string() != value { fail!(EINVAL, "SELECTED_SESSION_BOOT"); }
    Ok(*uuid.as_bytes())
}
fn parse(raw: &[u8], binding: &Binding) -> EnclaveResult<Parsed> {
    if raw.is_empty() || raw.len() > MAX_RECORD { fail!(EINVAL, "SELECTED_SESSION_SCHEMA"); }
    // Struct deserialization rejects duplicate and unknown fields; from_slice
    // rejects trailing values. Never export offending bytes/identifiers.
    let record: Record = serde_json::from_slice(raw).map_err(|_| err!(EINVAL, "SELECTED_SESSION_SCHEMA"))?;
    hex_array::<32>(&record.descriptor_sha256)?;
    if record.v != 1 || record.target_id != binding.target || record.descriptor_sha256 != binding.descriptor
        || record.profile != Profile::L2 || record.signing != DeploymentSigningMode::LocalPins {
        fail!(EACCES, "SELECTED_SESSION_BINDING");
    }
    let session = hex_array::<32>(&record.policy_session_id)?;
    let start = u64::from_be_bytes(hex_array::<8>(&record.not_before_boot_ns_hex)?);
    let end = u64::from_be_bytes(hex_array::<8>(&record.not_after_boot_ns_hex)?);
    if session == [0;32] || start == 0 || end == u64::MAX || end <= start {
        fail!(EINVAL, "SELECTED_SESSION_INTERVAL");
    }
    Ok(Parsed { session, boot: uuid_bytes(&record.boot_session_uuid)?, start, end })
}
fn time_current(parsed: &Parsed, boot: u64, boot_id: [u8;16], now: Instant, end: Instant) -> EnclaveResult<()> {
    if boot == 0 || boot == u64::MAX || boot_id != parsed.boot || boot < parsed.start || boot >= parsed.end || now >= end {
        fail!(ESTALE, "SELECTED_SESSION_EXPIRED_OR_BOOT_CHANGED");
    }
    Ok(())
}
fn conservative_end(instant_before: Instant, boot_after: u64, end: u64) -> EnclaveResult<Instant> {
    if boot_after == 0 || boot_after == u64::MAX || end == u64::MAX {
        fail!(ESTALE, "SELECTED_SESSION_CLOCK");
    }
    let left = end.checked_sub(boot_after).filter(|left| *left > 0)
        .ok_or_else(|| err!(ESTALE, "SELECTED_SESSION_CLOCK"))?;
    instant_before.checked_add(Duration::from_nanos(left)).ok_or_else(|| err!(ESTALE, "SELECTED_SESSION_CLOCK"))
}
fn native_boot_id() -> EnclaveResult<[u8;16]> {
    #[cfg(target_os="macos")]
    {
        let mut raw = [0u8;37]; let mut size = raw.len();
        // One bounded actual kernel read. No caller/provider supplies boot ID.
        let result = unsafe { libc::sysctlbyname(b"kern.bootsessionuuid\0".as_ptr().cast(),
            raw.as_mut_ptr().cast(), &mut size, std::ptr::null_mut(), 0) };
        if result != 0 || size != raw.len() || raw[36] != 0 { fail!(EIO, "SELECTED_SESSION_KERNEL_BOOT"); }
        let text = std::str::from_utf8(&raw[..36]).map_err(|_| err!(EIO, "SELECTED_SESSION_KERNEL_BOOT"))?;
        let uuid = uuid::Uuid::parse_str(text).map_err(|_| err!(EIO, "SELECTED_SESSION_KERNEL_BOOT"))?;
        if uuid.is_nil() { fail!(EIO, "SELECTED_SESSION_KERNEL_BOOT"); }
        Ok(*uuid.as_bytes())
    }
    #[cfg(not(target_os="macos"))]
    { fail!(ENOSYS, "SELECTED_SESSION_NATIVE_REQUIRED"); }
}
fn native_process() -> EnclaveResult<()> {
    if !cfg!(target_os="macos") || !codesign::enforced() { fail!(ENOSYS, "SELECTED_SESSION_NATIVE_REQUIRED"); }
    if ![0, DaemonId::CustodyVault.uid()].contains(&crate::ipc::geteuid()) { fail!(EPERM, "SELECTED_SESSION_PROCESS"); }
    Ok(())
}
fn shape(checked: &CheckedDeploymentTarget) -> EnclaveResult<()> {
    let target = checked.target();
    if target.role != DeploymentRole::DedicatedTest || target.profile != Profile::L2
        || target.signing_identity_mode != DeploymentSigningMode::LocalPins
        || codesign::signing_mode() != codesign::SigningMode::LocalPins
        || target.broker.is_some() || !target.shared_read_only_inputs.is_empty() {
        fail!(EACCES, "SELECTED_SESSION_CONTEXT");
    }
    deployment::upgrade::assert_start_allowed(checked)
}
enum Context {
    Native { checked: &'static CheckedDeploymentTarget, pins: [u8;32] },
    // Private fixtures never supply production context/identity/clock authority.
    #[cfg(test)] Fixture { root: PathBuf, uid:u32, gid:u32, binding:Binding,
        clock: std::sync::Arc<std::sync::atomic::AtomicU64>, boot:[u8;16] },
}
impl Context {
    fn capture() -> EnclaveResult<Self> {
        native_process()?;
        let checked = deployment::selected().ok_or_else(|| err!(EACCES, "DEPLOYMENT_CONTEXT_REQUIRED"))?;
        shape(checked)?;
        let raw = deployment::read_protected_public(&checked.target().codesign_pins_file, 1024*1024)?;
        let context = Self::Native { checked, pins: Sha256::digest(raw).into() };
        context.current()?; Ok(context)
    }
    fn current(&self) -> EnclaveResult<()> {
        match self {
            Self::Native { checked, pins } => {
                native_process()?; shape(checked)?;
                if !std::ptr::eq(*checked, deployment::selected().ok_or_else(|| err!(EACCES, "DEPLOYMENT_CONTEXT_REQUIRED"))?) {
                    fail!(ESTALE, "SELECTED_SESSION_CONTEXT");
                }
                let fresh = deployment::load(checked.config_path())?;
                if fresh.target() != checked.target() || fresh.descriptor_sha256() != checked.descriptor_sha256() {
                    fail!(ESTALE, "SELECTED_SESSION_CONTEXT");
                }
                let raw = deployment::read_protected_public(&checked.target().codesign_pins_file, 1024*1024)?;
                let hash: [u8;32] = Sha256::digest(raw).into();
                if hash != *pins { fail!(ESTALE, "SELECTED_SESSION_PINS"); }
                Ok(())
            },
            #[cfg(test)] Self::Fixture {..} => Ok(()),
        }
    }
    fn root(&self) -> &Path { match self { Self::Native {..} => Path::new("/"), #[cfg(test)] Self::Fixture {root,..} => root } }
    fn ids(&self) -> (u32,u32) { match self { Self::Native {..} => (0,0), #[cfg(test)] Self::Fixture {uid,gid,..} => (*uid,*gid) } }
    fn native(&self) -> bool { matches!(self, Self::Native {..}) }
    fn path(&self) -> PathBuf { match self { Self::Native {checked,..} => checked.target().layout.socket_root.clone(), #[cfg(test)] Self::Fixture {root,..} => root.join("mesh") } }
    fn binding(&self) -> Binding { match self {
        Self::Native {checked,..} => Binding {target:checked.target().target_id.clone(),descriptor:checked.descriptor_sha256().into()},
        #[cfg(test)] Self::Fixture {binding,..} => Binding {target:binding.target.clone(),descriptor:binding.descriptor.clone()},
    } }
    fn clock(&self) -> EnclaveResult<(u64,[u8;16])> { match self {
        Self::Native {..} => { let id=native_boot_id()?; Ok((crate::clock::boot_clock_ns(),id)) },
        #[cfg(test)] Self::Fixture {clock,boot,..} => Ok((clock.load(Ordering::SeqCst),*boot)),
    } }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity { dev:u64, ino:u64, uid:u32, gid:u32, mode:u32 }
impl Identity {
    fn of(m:&Metadata)->Self { Self {dev:m.dev(),ino:m.ino(),uid:m.uid(),gid:m.gid(),mode:m.mode()} }
    fn named(m:&libc::stat)->Self { Self {dev:m.st_dev as u64,ino:m.st_ino as u64,uid:m.st_uid,gid:m.st_gid,mode:m.st_mode as u32} }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp { identity:Identity, links:u64, size:u64, times:(i64,i64,i64,i64) }
impl Stamp { fn of(m:&Metadata)->Self { Self {identity:Identity::of(m),links:m.nlink(),size:m.len(),times:(m.mtime(),m.mtime_nsec(),m.ctime(),m.ctime_nsec())} } }
fn named(parent:&File,name:&CString)->EnclaveResult<Identity> {
    let mut raw=std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: held parent, single NUL-terminated component, valid out storage.
    if unsafe {libc::fstatat(parent.as_raw_fd(),name.as_ptr(),raw.as_mut_ptr(),libc::AT_SYMLINK_NOFOLLOW)} != 0 {
        fail!(EIO,"SELECTED_SESSION_NAME");
    }
    Ok(Identity::named(&unsafe {raw.assume_init()}))
}
fn flags(file:&File)->EnclaveResult<()> {
    let access=unsafe {libc::fcntl(file.as_raw_fd(),libc::F_GETFL)};
    let descriptor=unsafe {libc::fcntl(file.as_raw_fd(),libc::F_GETFD)};
    if access < 0 || access&libc::O_ACCMODE != libc::O_RDONLY || access&libc::O_NONBLOCK == 0
        || descriptor < 0 || descriptor&libc::FD_CLOEXEC == 0 { fail!(EACCES,"SELECTED_SESSION_FLAGS"); }
    Ok(())
}
fn empty_acl(file:&File,native:bool)->EnclaveResult<()> {
    if !native { return Ok(()); }
    #[cfg(target_os="macos")]
    {
        use std::ffi::c_void;
        unsafe extern "C" {
            fn acl_get_fd_np(fd:i32,kind:i32)->*mut c_void;
            fn acl_valid(acl:*mut c_void)->i32;
            fn acl_get_entry(acl:*mut c_void,id:i32,entry:*mut *mut c_void)->i32;
            fn acl_free(acl:*mut c_void)->i32;
        }
        unsafe {*libc::__error()=0;}
        let acl=unsafe {acl_get_fd_np(file.as_raw_fd(),0x100)};
        if acl.is_null() {
            if std::io::Error::last_os_error().raw_os_error()==Some(libc::ENOENT) {return Ok(());}
            fail!(EACCES,"SELECTED_SESSION_ACL");
        }
        let valid=unsafe {acl_valid(acl)};let mut entry=std::ptr::null_mut();
        let found=unsafe {acl_get_entry(acl,0,&mut entry)};
        let errno=std::io::Error::last_os_error().raw_os_error();let freed=unsafe {acl_free(acl)};
        if valid != 0 || found != -1 || errno != Some(libc::EINVAL) || freed != 0 {fail!(EACCES,"SELECTED_SESSION_ACL");}
        Ok(())
    }
    #[cfg(not(target_os="macos"))]
    { let _=file;fail!(ENOSYS,"SELECTED_SESSION_NATIVE_REQUIRED"); }
}
fn protect(file:&File,context:&Context,directory:bool,exact_mode:Option<u32>)->EnclaveResult<Metadata> {
    flags(file)?;empty_acl(file,context.native())?;
    let metadata=file.metadata().map_err(|_|err!(EIO,"SELECTED_SESSION_STAT"))?;
    let (uid,gid)=context.ids();
    if metadata.uid()!=uid || metadata.mode()&0o022 != 0
        || (directory && !metadata.is_dir()) || (!directory && !metadata.is_file())
        || exact_mode.is_some_and(|mode|metadata.gid()!=gid || metadata.mode()&0o7777!=mode) {
        fail!(EACCES,"SELECTED_SESSION_PROTECTION");
    }
    Ok(metadata)
}
struct Node {name:CString,file:File,identity:Identity}
struct Source {nodes:Vec<Node>,leaf:CString,file:File,stamp:Stamp,raw:Vec<u8>}
fn open_at(parent:Option<&File>,name:&CString,directory:bool)->EnclaveResult<File> {
    let flags=libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC|if directory {libc::O_DIRECTORY} else {0};
    // SAFETY: names are validated and each successful fd transfers ownership.
    let fd=unsafe {match parent {Some(parent)=>libc::openat(parent.as_raw_fd(),name.as_ptr(),flags),None=>libc::open(name.as_ptr(),flags)}};
    if fd < 0 {fail!(EACCES,"SELECTED_SESSION_OPEN");}
    Ok(unsafe {File::from_raw_fd(fd)})
}
fn read_bytes(file:&File)->EnclaveResult<Vec<u8>> {
    let mut raw=vec![0;MAX_RECORD+1];let mut done=0;
    while done < raw.len() {
        match file.read_at(&mut raw[done..],done as u64) {
            Ok(0)=>break,Ok(n)=>done+=n,
            Err(error) if error.kind()==std::io::ErrorKind::Interrupted=>continue,
            Err(_)=>{fail!(EIO,"SELECTED_SESSION_READ");},
        }
    }
    raw.truncate(done);if raw.is_empty() || raw.len()>MAX_RECORD {fail!(EINVAL,"SELECTED_SESSION_SCHEMA");}Ok(raw)
}
impl Source {
    fn open(context:&Context)->EnclaveResult<Self> {
        let path=deployment::normalized_path(&context.path())?;
        let relative=path.strip_prefix(context.root()).map_err(|_|err!(EINVAL,"SELECTED_SESSION_PATH"))?;
        let mut names=Vec::new();
        for component in relative.components() {
            let Component::Normal(name)=component else {fail!(EINVAL,"SELECTED_SESSION_PATH");};
            names.push(CString::new(name.as_bytes()).map_err(|_|err!(EINVAL,"SELECTED_SESSION_PATH"))?);
        }
        if names.is_empty() || names.len()>MAX_PARENTS {fail!(EINVAL,"SELECTED_SESSION_PATH");}
        let root_name=CString::new(context.root().as_os_str().as_bytes()).map_err(|_|err!(EINVAL,"SELECTED_SESSION_PATH"))?;
        let root=open_at(None,&root_name,true)?;
        let identity=Identity::of(&protect(&root,context,true,None)?);
        let mut nodes=vec![Node {name:root_name,file:root,identity}];
        let count=names.len();
        for (index,name) in names.into_iter().enumerate() {
            let parent=&nodes.last().expect("root retained").file;
            let before=named(parent,&name)?;let file=open_at(Some(parent),&name,true)?;
            let identity=Identity::of(&protect(&file,context,true,(index+1==count).then_some(0o755))?);
            if identity!=before || named(parent,&name)?!=identity {fail!(ESTALE,"SELECTED_SESSION_REPLACED");}
            nodes.push(Node {name,file,identity});
        }
        let parent=&nodes.last().expect("mesh retained").file;let leaf=CString::new(SESSION_LEAF).expect("literal");
        let before=named(parent,&leaf)?;let file=open_at(Some(parent),&leaf,false)?;
        let stamp=Stamp::of(&protect(&file,context,false,Some(0o644))?);
        if stamp.identity!=before || stamp.links!=1 || stamp.size==0 || stamp.size>MAX_RECORD as u64 {
            fail!(EACCES,"SELECTED_SESSION_PROTECTION");
        }
        let raw=read_bytes(&file)?;
        let source=Self {nodes,leaf,file,stamp,raw};source.current(context)?;Ok(source)
    }
    fn current(&self,context:&Context)->EnclaveResult<()> {
        let root=std::fs::symlink_metadata(context.root()).map_err(|_|err!(EIO,"SELECTED_SESSION_NAME"))?;
        if Identity::of(&root)!=self.nodes[0].identity {fail!(ESTALE,"SELECTED_SESSION_REPLACED");}
        for (index,node) in self.nodes.iter().enumerate() {
            let mode=(index+1==self.nodes.len()).then_some(0o755);
            if Identity::of(&protect(&node.file,context,true,mode)?)!=node.identity
                || (index>0 && named(&self.nodes[index-1].file,&node.name)?!=node.identity) {
                fail!(ESTALE,"SELECTED_SESSION_REPLACED");
            }
        }
        if Stamp::of(&protect(&self.file,context,false,Some(0o644))?)!=self.stamp
            || named(&self.nodes.last().expect("mesh retained").file,&self.leaf)?!=self.stamp.identity
            || read_bytes(&self.file)?!=self.raw
            || Stamp::of(&protect(&self.file,context,false,Some(0o644))?)!=self.stamp {
            fail!(ESTALE,"SELECTED_SESSION_REPLACED");
        }
        Ok(())
    }
}

/// Opaque retained original public record. It grants no connection, native
/// owner, enrollment, action, startup or readiness authority. No replacement.
pub struct SelectedOwnerSession {context:Context,source:Source,parsed:Parsed,hash:[u8;32],end:Instant,poisoned:AtomicBool}
impl std::fmt::Debug for SelectedOwnerSession {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.debug_struct("SelectedOwnerSession").finish_non_exhaustive()}
}
struct Failure<'a> {poisoned:&'a AtomicBool,armed:bool}
impl Drop for Failure<'_> {fn drop(&mut self) {if self.armed {self.poisoned.store(true,Ordering::SeqCst);}}}
impl SelectedOwnerSession {
    /// Load only the actual native selected record. No path/time/provider input.
    pub fn capture()->EnclaveResult<Self> {Self::open(Context::capture()?)}
    fn open(context:Context)->EnclaveResult<Self> {
        context.current()?;let source=Source::open(&context)?;
        let parsed=parse(&source.raw,&context.binding())?;
        // Earlier Instant plus later boot remainder can only shorten this cap.
        let instant_before=Instant::now();let (boot,id)=context.clock()?;
        let end=conservative_end(instant_before,boot,parsed.end)?;
        time_current(&parsed,boot,id,Instant::now(),end)?;
        let hash=Sha256::digest(&source.raw).into();
        let owner=Self {context,source,parsed,hash,end,poisoned:AtomicBool::new(false)};
        owner.require_current()?;Ok(owner)
    }
    fn checked<T>(&self,operation:impl FnOnce()->EnclaveResult<T>)->EnclaveResult<T> {
        if self.poisoned.load(Ordering::SeqCst) {fail!(EACCES,"SELECTED_SESSION_POISONED");}
        let mut failure=Failure {poisoned:&self.poisoned,armed:true};
        let result=operation()?;
        if self.poisoned.load(Ordering::SeqCst) {fail!(EACCES,"SELECTED_SESSION_POISONED");}
        failure.armed=false;Ok(result)
    }
    /// Observe only the SAME terminal revocation latch, without filesystem,
    /// socket, owner, metadata-lock or native cleanup work. Success supplies no
    /// current-file, connection, authentication, expiry or readiness evidence.
    /// A final release must independently preserve its immutable original caps.
    pub fn require_not_revoked(&self) -> EnclaveResult<()> {
        if self.poisoned.load(Ordering::SeqCst) { fail!(EACCES, "SELECTED_SESSION_POISONED"); }
        Ok(())
    }
    /// Recheck SAME file/parents/bytes/context/kernel boot and original ends.
    /// Every error/caught unwind is terminal; no native work holds a mutex.
    pub fn require_current(&self)->EnclaveResult<()> {self.checked(|| {
        self.context.current()?;
        let (boot,id)=self.context.clock()?;time_current(&self.parsed,boot,id,Instant::now(),self.end)?;
        self.source.current(&self.context)?;self.context.current()?;
        let (boot,id)=self.context.clock()?;time_current(&self.parsed,boot,id,Instant::now(),self.end)
    })}
    /// Compare the independently admitted raw end exactly, preserving the
    /// original local Instant and any earlier enclosing endpoint. No renewal.
    pub fn shorten_before(&self,expected_boot_end:u64,enclosing_end:Instant)->EnclaveResult<Instant> {self.checked(|| {
        self.require_current()?;
        if expected_boot_end!=self.parsed.end {fail!(EACCES,"SELECTED_SESSION_END_MISMATCH");}
        let end=self.end.min(enclosing_end);
        if Instant::now()>=end {fail!(ESTALE,"SELECTED_SESSION_EXPIRED_OR_BOOT_CHANGED");}
        self.require_current()?;Ok(end)
    })}
    /// Negative-only terminal revocation. There is no reset or source reload.
    pub fn revoke(&self) {self.poisoned.store(true,Ordering::SeqCst);}
    /// Exact original bytes hash for future authenticated channel binding.
    pub fn record_sha256(&self)->[u8;32] {self.hash}
    /// Public policy-session identifier, distinct from a connection nonce.
    pub fn policy_session_id(&self)->[u8;32] {self.parsed.session}
    /// Exact original shared boot endpoint; this getter grants no authority.
    pub fn expires_boot_ns(&self)->u64 {self.parsed.end}
    /// Original conservative local cap; this getter grants no authority.
    pub fn original_instant_end(&self)->Instant {self.end}
}

#[cfg(test)]
#[path="selected_owner_session_tests.rs"]
mod tests;
