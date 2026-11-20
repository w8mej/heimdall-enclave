//! Static native-code observations over held protected files; never release approval.
//!
//! The caller must hold host maintenance exclusion across verification, use and
//! final revalidation. Security.framework uses paths, not our FDs. Protected
//! ancestry and before/after named-inode/digest checks bind those paths under
//! that exclusion; a hostile concurrent root is outside this boundary. This
//! module neither authenticates candidate inventory/pins nor proves inactivity.
//! Universal binaries deliberately refuse until every slice's identity and
//! entitlements can be observed and authorized. No candidate code is executed.
//! Native calls are synchronous; no hard interruption deadline is claimed.
//! Signature/resource validity does not grant restricted entitlement/profile
//! approval or establish actual Keychain/SEP/APFS capability.
//! The native selected digest is pinned. Digest-algorithm arrays describe hash
//! variants of that signature, not an inventory or approval of signature slots.

use std::{collections::{BTreeMap, BTreeSet}, ffi::{CStr, CString}, fs::{File, Metadata},
    os::{fd::{AsRawFd, FromRawFd}, unix::{ffi::OsStrExt, fs::{FileExt, MetadataExt}}},
    path::{Path, PathBuf}};
use enclave_core::{codesign::{CodeIdentity, CodeRequirement, TEAM_ID},
    deployment::normalized_path, error::EnclaveResult, err, fail};
use sha2::{Digest, Sha256};

const MAX_FILE:u64=512*1024*1024;
const MAX_DIRECTORIES:usize=96;
// CSCommon.h: kSecCodeSignatureRuntime, confirmed in retained native SDK read.
const RUNTIME:u32=0x10000;
const BASELINE:[&str;7]=[
    "com.apple.security.cs.allow-jit", "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.allow-dyld-environment-variables", "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.disable-executable-page-protection", "com.apple.security.cs.debugger",
    "com.apple.security.get-task-allow",
];

/// Borrowed read-only input. Construction alone establishes no authority.
#[derive(Clone, Copy)]
pub(crate) struct ProtectedNativeFile<'a> {
    pub(crate) path:&'a Path,
    pub(crate) file:&'a File,
    pub(crate) sha256:&'a str,
    pub(crate) size:u64,
}
pub(crate) enum NativeCodeShape<'a> {
    Executable(ProtectedNativeFile<'a>),
    /// `members` contains resources only; `executable` is included separately.
    Bundle {root:&'a Path, executable:ProtectedNativeFile<'a>, members:&'a [ProtectedNativeFile<'a>]},
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeEntitlementPolicy {DaemonBaseline, CustodyForCompiledSigningMode}

/// An observation, not a serializable authorization token or release receipt.
#[derive(Debug)]
pub(crate) struct NativeCodeObservation {
    pub(crate) identity:CodeIdentity,
    pub(crate) flags:u32,
    pub(crate) executable_sha256:String,
    pub(crate) member_sha256:BTreeMap<PathBuf,String>,
    pub(crate) entitlement_policy:NativeEntitlementPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Entitlement {Boolean(bool), Text(String), TextArray(Vec<String>)}
struct SigningObservation {identity:CodeIdentity, flags:u32,
    entitlements:BTreeMap<String,Entitlement>, code_path:PathBuf, executable_path:PathBuf,
    bundle_info:Option<(String,String)>}
trait StaticBackend {
    fn inspect(&mut self,path:&Path,bundle:bool,requirement:&str)->EnclaveResult<SigningObservation>;
}

fn role(identifier:&str)->Option<(&'static str,bool)> {
    Some(match identifier {
        "com.enterprise.enclave.ctl"=>("depot-enclave",false),
        "com.enterprise.enclave.adapter"=>("enclave-model-runnerd",false),
        "com.enterprise.enclave.cas"=>("enclave-swarm-syncd",false),
        "com.enterprise.enclave.apfs-broker"=>("enclave-apfs-broker",false),
        "com.enterprise.enclave.ifc"=>("enclave-agent-runtime",false),
        "com.enterprise.enclave.zk"=>("enclave-zk-auditor",false),
        "com.enterprise.enclave.browser"=>("enclave-cdp-browser",false),
        "com.enterprise.enclave.gateway"=>("enclave-client-gateway",false),
        "com.enterprise.enclave.intent"=>("enclave-intent",false),
        "com.enterprise.enclave.fido"=>("enclave-fido-emulator",false),
        "com.enterprise.enclave.custody"=>("enclave-custody-vaultd",true),
        "com.enterprise.enclave.oidc-broker"=>("enclave-oidc",true),
        _=>return None,
    })
}
fn digest(value:&str,length:usize)->bool {
    value.len()==length && value.bytes().all(|b|b.is_ascii_hexdigit())
}
fn requirement_text(req:&CodeRequirement,policy:NativeEntitlementPolicy)->EnclaveResult<String> {
    role(&req.identifier).ok_or_else(||err!(EACCES,"NATIVE_CODE_ROLE"))?;
    if req.team_id!=TEAM_ID || (!TEAM_ID.is_empty() && (TEAM_ID.len()!=10
        || !TEAM_ID.bytes().all(|b|b.is_ascii_uppercase() || b.is_ascii_digit()))) {
        fail!(EACCES,"NATIVE_CODE_COMPILED_TEAM");
    }
    let custody=req.identifier=="com.enterprise.enclave.custody";
    if custody!=(policy==NativeEntitlementPolicy::CustodyForCompiledSigningMode) {
        fail!(EACCES,"NATIVE_CODE_ENTITLEMENT_POLICY");
    }
    if req.cdhash_allowlist.is_empty() || req.cdhash_allowlist.len()>32
        || req.cdhash_allowlist.iter().any(|v|!digest(v,40)) {
        fail!(EACCES,"NATIVE_CODE_PINS");
    }
    let mut hashes=BTreeSet::new();
    for hash in &req.cdhash_allowlist {
        if !hashes.insert(hash.to_ascii_lowercase()) {fail!(EINVAL,"NATIVE_CODE_PINS");}
    }
    let hashes=hashes.into_iter().map(|h|format!("cdhash H\"{h}\"" )).collect::<Vec<_>>().join(" or ");
    let anchor=if TEAM_ID.is_empty() {String::new()} else {
        format!("anchor apple generic and certificate leaf[subject.OU] = \"{TEAM_ID}\" and ")};
    Ok(format!("{anchor}identifier \"{}\" and ({hashes})",req.identifier))
}
fn expected_entitlements(policy:NativeEntitlementPolicy)->BTreeMap<String,Entitlement> {
    let mut expected=BASELINE.into_iter().map(|k|(k.into(),Entitlement::Boolean(false))).collect::<BTreeMap<_,_>>();
    if policy==NativeEntitlementPolicy::CustodyForCompiledSigningMode && !TEAM_ID.is_empty() {
        let app=format!("{TEAM_ID}.com.enterprise.enclave.custody");
        expected.insert("com.apple.application-identifier".into(),Entitlement::Text(app.clone()));
        expected.insert("com.apple.developer.team-identifier".into(),Entitlement::Text(TEAM_ID.into()));
        expected.insert("keychain-access-groups".into(),Entitlement::TextArray(vec![app]));
    }
    expected
}
fn verify_observation(obs:&SigningObservation,req:&CodeRequirement,policy:NativeEntitlementPolicy)->EnclaveResult<()> {
    if obs.identity.identifier!=req.identifier || obs.identity.team_id!=TEAM_ID
        || !digest(&obs.identity.cdhash,40)
        || !req.cdhash_allowlist.iter().any(|h|h.eq_ignore_ascii_case(&obs.identity.cdhash)) {
        fail!(EACCES,"NATIVE_CODE_IDENTITY");
    }
    if obs.flags&RUNTIME==0 {fail!(EACCES,"NATIVE_CODE_RUNTIME");}
    if obs.entitlements!=expected_entitlements(policy) {fail!(EACCES,"NATIVE_CODE_ENTITLEMENTS");}
    Ok(())
}

fn consistent_selected_cdhash(unique:&[u8],selected:i64,algorithms:&[i64],hashes:&[Vec<u8>])->EnclaveResult<String> {
    // SecCode.h documents parallel digest-algorithm/hash arrays and requires
    // Unique to equal the hash corresponding to DigestAlgorithm. Do not infer
    // signature-slot count or architecture coverage from these arrays.
    if unique.len()!=20 || algorithms.is_empty() || algorithms.len()>16 || algorithms.len()!=hashes.len() {
        fail!(EACCES,"NATIVE_CODE_SIGNING_INFO");
    }
    let mut seen=BTreeSet::new();let mut selected_index=None;
    for (index,algorithm) in algorithms.iter().enumerate() {
        if *algorithm<=0 || u32::try_from(*algorithm).is_err() || !seen.insert(*algorithm) || hashes[index].len()!=20 {
            fail!(EACCES,"NATIVE_CODE_SIGNING_INFO");
        }
        if *algorithm==selected {selected_index=Some(index);}
    }
    if selected_index.is_none_or(|index|hashes[index].as_slice()!=unique) {
        fail!(EACCES,"NATIVE_CODE_SIGNING_INFO");
    }
    Ok(hex::encode(unique))
}

fn route(path:&Path)->EnclaveResult<PathBuf> {
    // `normalized_path` rejects noncanonical spelling before fixed alias routing.
    normalized_path(path).map_err(|_|err!(EINVAL,"NATIVE_CODE_PATH"))
}
fn c_name(value:&std::ffi::OsStr)->EnclaveResult<CString> {
    CString::new(value.as_bytes()).map_err(|_|err!(EINVAL,"NATIVE_CODE_PATH"))
}
fn io_error()->enclave_core::error::EnclaveError {err!(EACCES,"NATIVE_CODE_PROTECTED_PATH")}
fn from_fd(fd:i32)->EnclaveResult<File> {
    if fd<0 {return Err(io_error());}
    // SAFETY: successful syscall transferred ownership of a fresh FD.
    Ok(unsafe {File::from_raw_fd(fd)})
}
fn open_at(parent:&File,name:&CString,directory:bool)->EnclaveResult<File> {
    let flags=libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC
        |if directory {libc::O_DIRECTORY}else{0};
    // SAFETY: held directory and a single NUL-terminated leaf component.
    from_fd(unsafe {libc::openat(parent.as_raw_fd(),name.as_ptr(),flags)})
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Stamp {dev:u64,ino:u64,uid:u32,gid:u32,mode:u32,links:u64,size:u64,
    modified:(i64,i64),changed:(i64,i64)}
impl Stamp {
    fn of(m:&Metadata)->Self {Self {dev:m.dev(),ino:m.ino(),uid:m.uid(),gid:m.gid(),mode:m.mode(),
        links:m.nlink(),size:m.len(),modified:(m.mtime(),m.mtime_nsec()),changed:(m.ctime(),m.ctime_nsec())}}
}
#[derive(Clone, Copy)]
struct FsPolicy {owner:u32}
impl FsPolicy {
    const PRODUCTION:Self=Self {owner:0};
    fn protected(self,m:&Metadata)->bool {m.uid()==self.owner && m.mode()&0o022==0 && m.mode()&0o7000==0}
}
struct Directory {file:File,stamp:(u64,u64,u32,u32,u32)}
impl Directory {
    fn of(file:File,policy:FsPolicy)->EnclaveResult<Self> {
        let m=file.metadata().map_err(|_|io_error())?;
        if !m.is_dir() || !policy.protected(&m) {fail!(EACCES,"NATIVE_CODE_ANCESTRY");}
        Ok(Self {file,stamp:(m.dev(),m.ino(),m.uid(),m.gid(),m.mode())})
    }
    fn matches(&self,m:&Metadata,policy:FsPolicy)->bool {
        m.is_dir() && policy.protected(m) && self.stamp==(m.dev(),m.ino(),m.uid(),m.gid(),m.mode())
    }
}
struct Directories {held:BTreeMap<PathBuf,Directory>,policy:FsPolicy}
impl Directories {
    fn new()->EnclaveResult<Self> {
        let name=CString::new("/").expect("literal");
        // SAFETY: fixed root path, owned successful FD.
        let file=from_fd(unsafe {libc::open(name.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)})?;
        let policy=FsPolicy::PRODUCTION;
        Ok(Self {held:BTreeMap::from([(PathBuf::from("/"),Directory::of(file,policy)?)]),policy})
    }
    #[cfg(test)]
    fn fixture(root:&Path,owner:u32)->EnclaveResult<Self> {
        let name=c_name(root.as_os_str())?;
        let file=from_fd(unsafe {libc::open(name.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)})?;
        let policy=FsPolicy {owner};
        Ok(Self {held:BTreeMap::from([(root.to_owned(),Directory::of(file,policy)?)]),policy})
    }
    fn ensure(&mut self,path:&Path)->EnclaveResult<()> {
        if self.held.contains_key(path) {return Ok(());}
        if self.held.len()>=MAX_DIRECTORIES || path.components().count()>MAX_DIRECTORIES {
            fail!(E2BIG,"NATIVE_CODE_DIRECTORY_LIMIT");
        }
        let parent=path.parent().ok_or_else(||err!(EINVAL,"NATIVE_CODE_PATH"))?;
        self.ensure(parent)?;
        if self.held.len()>=MAX_DIRECTORIES {fail!(E2BIG,"NATIVE_CODE_DIRECTORY_LIMIT");}
        let leaf=c_name(path.file_name().ok_or_else(||err!(EINVAL,"NATIVE_CODE_PATH"))?)?;
        let file=open_at(&self.held.get(parent).expect("held parent").file,&leaf,true)?;
        self.held.insert(path.to_owned(),Directory::of(file,self.policy)?);Ok(())
    }
    fn validate(&self)->EnclaveResult<()> {
        for (path,dir) in &self.held {
            if !dir.matches(&dir.file.metadata().map_err(|_|io_error())?,self.policy) {fail!(ESTALE,"NATIVE_CODE_ANCESTRY_CHANGED");}
            if let Some(parent)=path.parent().and_then(|p|self.held.get(p)) {
                let leaf=c_name(path.file_name().ok_or_else(||err!(EINVAL,"NATIVE_CODE_PATH"))?)?;
                let current=open_at(&parent.file,&leaf,true)?;
                if !dir.matches(&current.metadata().map_err(|_|io_error())?,self.policy) {fail!(ESTALE,"NATIVE_CODE_ANCESTRY_CHANGED");}
            }
        }Ok(())
    }
}
fn hash_file(file:&File,size:u64)->EnclaveResult<String> {
    if size==0 || size>MAX_FILE {fail!(E2BIG,"NATIVE_CODE_SIZE");}
    let mut hash=Sha256::new();let mut offset=0u64;let mut buf=[0u8;65536];
    while offset<size {
        let length=buf.len().min((size-offset) as usize);
        let n=match file.read_at(&mut buf[..length],offset) {
            Err(e) if e.kind()==std::io::ErrorKind::Interrupted=>continue,
            result=>result.map_err(|_|err!(EIO,"NATIVE_CODE_READ"))?,
        };
        if n==0 {fail!(ESTALE,"NATIVE_CODE_SIZE");}hash.update(&buf[..n]);offset+=n as u64;
    }
    if file.read_at(&mut buf[..1],size).map_err(|_|err!(EIO,"NATIVE_CODE_READ"))?!=0 {fail!(ESTALE,"NATIVE_CODE_SIZE");}
    Ok(hex::encode(hash.finalize()))
}
struct BoundFile<'a> {input:ProtectedNativeFile<'a>,path:PathBuf,stamp:Stamp}
impl<'a> BoundFile<'a> {
    fn bind(input:ProtectedNativeFile<'a>,dirs:&mut Directories)->EnclaveResult<Self> {
        let path=route(input.path)?;let parent=path.parent().ok_or_else(||err!(EINVAL,"NATIVE_CODE_PATH"))?;
        dirs.ensure(parent)?;
        let metadata=input.file.metadata().map_err(|_|io_error())?;
        let flags=unsafe {libc::fcntl(input.file.as_raw_fd(),libc::F_GETFL)};
        if flags<0 || flags&libc::O_ACCMODE!=libc::O_RDONLY || !metadata.is_file()
            || !dirs.policy.protected(&metadata) || metadata.nlink()!=1
            || !digest(input.sha256,64) || metadata.len()!=input.size || input.size==0 || input.size>MAX_FILE {
            fail!(EACCES,"NATIVE_CODE_FILE_PROTECTION");
        }
        #[cfg(target_os="linux")]
        if flags&libc::O_PATH!=0 {fail!(EACCES,"NATIVE_CODE_FILE_PROTECTION");}
        let bound=Self {input,path,stamp:Stamp::of(&metadata)};bound.validate(dirs)?;Ok(bound)
    }
    fn validate(&self,dirs:&Directories)->EnclaveResult<()> {
        if Stamp::of(&self.input.file.metadata().map_err(|_|io_error())?)!=self.stamp {fail!(ESTALE,"NATIVE_CODE_FILE_CHANGED");}
        let parent=self.path.parent().ok_or_else(||err!(EINVAL,"NATIVE_CODE_PATH"))?;
        let leaf=c_name(self.path.file_name().ok_or_else(||err!(EINVAL,"NATIVE_CODE_PATH"))?)?;
        let named=open_at(&dirs.held.get(parent).ok_or_else(||err!(EINVAL,"NATIVE_CODE_PATH"))?.file,&leaf,false)?;
        if Stamp::of(&named.metadata().map_err(|_|io_error())?)!=self.stamp
            || !self.input.sha256.eq_ignore_ascii_case(&hash_file(self.input.file,self.input.size)?) {
            fail!(ESTALE,"NATIVE_CODE_FILE_CHANGED");
        }
        if Stamp::of(&self.input.file.metadata().map_err(|_|io_error())?)!=self.stamp {fail!(ESTALE,"NATIVE_CODE_FILE_CHANGED");}
        Ok(())
    }
}
fn thin_executable(file:&File)->EnclaveResult<()> {
    let mut header=[0u8;32];let mut offset=0;
    while offset<header.len() {
        let n=match file.read_at(&mut header[offset..],offset as u64) {
            Err(e) if e.kind()==std::io::ErrorKind::Interrupted=>continue,
            r=>r.map_err(|_|err!(EIO,"NATIVE_CODE_READ"))?,
        };if n==0 {fail!(EINVAL,"NATIVE_CODE_MACHO");}offset+=n;
    }
    let little=match &header[..4] {
        [0xcf,0xfa,0xed,0xfe]=>true,
        [0xfe,0xed,0xfa,0xcf]=>false,
        [0xca,0xfe,0xba,0xbe]|[0xbe,0xba,0xfe,0xca]|[0xca,0xfe,0xba,0xbf]|[0xbf,0xba,0xfe,0xca]=>{
            fail!(ENOSYS,"NATIVE_CODE_UNIVERSAL_UNSUPPORTED");
        },
        _=>fail!(EINVAL,"NATIVE_CODE_MACHO"),
    };
    let bytes:[u8;4]=header[12..16].try_into().expect("fixed slice");
    if (if little {u32::from_le_bytes(bytes)}else{u32::from_be_bytes(bytes)})!=2 {fail!(EINVAL,"NATIVE_CODE_MACHO_EXECUTABLE");}
    Ok(())
}

struct DirStream(*mut libc::DIR);
impl Drop for DirStream {fn drop(&mut self) {unsafe {libc::closedir(self.0)};}}
fn directory_names(file:&File)->EnclaveResult<BTreeSet<Vec<u8>>> {
    // Open a fresh file description so readdir does not move a retained FD's
    // directory offset. The held FD is the base; no pathname traversal occurs.
    let dot=CString::new(".").expect("literal");
    let opened=open_at(file,&dot,true)?;
    use std::os::fd::IntoRawFd;
    let fd=opened.into_raw_fd();let stream=unsafe {libc::fdopendir(fd)};
    if stream.is_null() {unsafe {libc::close(fd)};return Err(io_error());}
    let stream=DirStream(stream);let mut names=BTreeSet::new();
    loop {
        #[cfg(target_os="macos")]
        unsafe {*libc::__error()=0;}
        #[cfg(target_os="linux")]
        unsafe {*libc::__errno_location()=0;}
        let entry=unsafe {libc::readdir(stream.0)};
        if entry.is_null() {
            if std::io::Error::last_os_error().raw_os_error()!=Some(0) {return Err(io_error());}break;
        }
        // SAFETY: readdir supplies a NUL-terminated name valid until next call.
        let name=unsafe {CStr::from_ptr((*entry).d_name.as_ptr())}.to_bytes();
        if name==b"." || name==b".." {continue;}
        if names.len()>=16 || !names.insert(name.to_vec()) {fail!(E2BIG,"NATIVE_CODE_BUNDLE_CLOSURE");}
    }Ok(names)
}
fn bundle_closure(root:&Path,files:&[BoundFile<'_>],dirs:&mut Directories,executable:&str,team_custody:bool)->EnclaveResult<()> {
    let mut expected_files=BTreeSet::new();
    for file in files {
        let relative=file.path.strip_prefix(root).map_err(|_|err!(EINVAL,"NATIVE_CODE_BUNDLE_MEMBER"))?;
        let name=relative.to_str().ok_or_else(||err!(EINVAL,"NATIVE_CODE_BUNDLE_MEMBER"))?;
        if !["Contents/Info.plist","Contents/_CodeSignature/CodeResources","Contents/PkgInfo","Contents/embedded.provisionprofile"].contains(&name)
            && name!=format!("Contents/MacOS/{executable}") {fail!(EINVAL,"NATIVE_CODE_BUNDLE_MEMBER");}
        if !expected_files.insert(relative.to_owned()) {fail!(EINVAL,"NATIVE_CODE_BUNDLE_MEMBER");}
    }
    for name in ["Contents/Info.plist".to_owned(),"Contents/_CodeSignature/CodeResources".into(),format!("Contents/MacOS/{executable}")]
        .into_iter().chain(team_custody.then_some("Contents/embedded.provisionprofile".into())) {
        if !expected_files.contains(Path::new(&name)) {fail!(EINVAL,"NATIVE_CODE_BUNDLE_INCOMPLETE");}
    }
    let mut expected_dirs=BTreeSet::from([PathBuf::new()]);
    for file in &expected_files {let mut parent=file.parent();while let Some(p)=parent {expected_dirs.insert(p.to_owned());parent=p.parent();}}
    for relative in &expected_dirs {
        let path=root.join(relative);dirs.ensure(&path)?;
        let expected=expected_files.iter().chain(&expected_dirs).filter(|p|p.parent()==Some(relative.as_path()))
            .filter_map(|p|p.file_name()).map(|n|n.as_bytes().to_vec()).collect::<BTreeSet<_>>();
        if directory_names(&dirs.held.get(&path).expect("held bundle directory").file)?!=expected {
            fail!(EACCES,"NATIVE_CODE_BUNDLE_CLOSURE");
        }
    }Ok(())
}

fn verify_with(shape:NativeCodeShape<'_>,req:&CodeRequirement,policy:NativeEntitlementPolicy,
    backend:&mut dyn StaticBackend,mut dirs:Directories)->EnclaveResult<NativeCodeObservation> {
    let requirement=requirement_text(req,policy)?;
    let (executable,is_bundle)=role(&req.identifier).ok_or_else(||err!(EACCES,"NATIVE_CODE_ROLE"))?;
    let (root,input,members)=match shape {
        NativeCodeShape::Executable(file)=>{
            if is_bundle {fail!(EINVAL,"NATIVE_CODE_SHAPE");}(route(file.path)?,file,&[][..])
        },
        NativeCodeShape::Bundle {root,executable:file,members}=>{
            if !is_bundle || members.len()>4 {fail!(EINVAL,"NATIVE_CODE_SHAPE");}
            (route(root)?,file,members)
        },
    };
    let executable_path=route(input.path)?;
    if executable_path.file_name().is_none_or(|n|n.as_bytes()!=executable.as_bytes())
        || (is_bundle && executable_path!=root.join("Contents/MacOS").join(executable)) {
        fail!(EINVAL,"NATIVE_CODE_EXECUTABLE_PATH");
    }
    let mut files=vec![BoundFile::bind(input,&mut dirs)?];
    for member in members {files.push(BoundFile::bind(*member,&mut dirs)?);}
    let mut identities=BTreeSet::new();let mut paths=BTreeSet::new();
    for file in &files {
        if !identities.insert((file.stamp.dev,file.stamp.ino)) || !paths.insert(file.path.clone()) {
            fail!(EINVAL,"NATIVE_CODE_FILE_ALIAS");
        }
    }
    let team_custody=req.identifier=="com.enterprise.enclave.custody" && !TEAM_ID.is_empty();
    if is_bundle {bundle_closure(&root,&files,&mut dirs,executable,team_custody)?;}
    thin_executable(input.file)?;dirs.validate()?;
    for file in &files {file.validate(&dirs)?;}
    let result=backend.inspect(&root,is_bundle,&requirement);
    // Revalidate even when Security.framework refuses. A changed binding must
    // never leave a successful observation or authorize subsequent mutation.
    dirs.validate()?;
    for file in &files {file.validate(&dirs)?;}
    if is_bundle {bundle_closure(&root,&files,&mut dirs,executable,team_custody)?;}
    dirs.validate()?;
    let observed=result?;
    if route(&observed.code_path)?!=root || route(&observed.executable_path)?!=executable_path {
        fail!(EACCES,"NATIVE_CODE_RESOLVED_PATH");
    }
    if is_bundle && observed.bundle_info.as_ref()!=Some(&(req.identifier.clone(),executable.to_owned())) {
        fail!(EACCES,"NATIVE_CODE_BUNDLE_INFO");
    }
    verify_observation(&observed,req,policy)?;
    Ok(NativeCodeObservation {identity:observed.identity,flags:observed.flags,
        executable_sha256:input.sha256.to_ascii_lowercase(),
        member_sha256:files.iter().map(|f|(f.path.clone(),f.input.sha256.to_ascii_lowercase())).collect(),
        entitlement_policy:policy})
}

pub(crate) fn verify_static_code(shape:NativeCodeShape<'_>,requirement:&CodeRequirement,
    policy:NativeEntitlementPolicy)->EnclaveResult<NativeCodeObservation> {
    #[cfg(target_os="macos")]
    {verify_with(shape,requirement,policy,&mut darwin::SecurityBackend,Directories::new()?)}
    #[cfg(not(target_os="macos"))]
    {let _=(shape,requirement,policy);fail!(ENOSYS,"NATIVE_CODE_VERIFICATION_UNAVAILABLE");}
}

#[cfg(target_os="macos")]
mod darwin {
    use super::*;
    use std::{ffi::c_void,os::raw::c_char};
    type CfRef=*const c_void;
    const UTF8:u32=0x0800_0100;
    // SecStaticCode.h, macOS26.6.2 SDK; see retained header hash in evidence.
    const VALIDATION_FLAGS:u32=(1<<0)|(1<<3)|(1<<4)|(1<<7);
    const SIGNING_INFORMATION:u32=1<<1;
    #[link(name="CoreFoundation",kind="framework")]
    extern "C" {
        fn CFRelease(value:CfRef);
        fn CFGetTypeID(value:CfRef)->usize;
        fn CFStringGetTypeID()->usize;
        fn CFDataGetTypeID()->usize;
        fn CFDictionaryGetTypeID()->usize;
        fn CFArrayGetTypeID()->usize;
        fn CFBooleanGetTypeID()->usize;
        fn CFNumberGetTypeID()->usize;
        fn CFURLGetTypeID()->usize;
        fn CFStringCreateWithBytes(allocator:CfRef,bytes:*const u8,length:isize,encoding:u32,external:u8)->CfRef;
        fn CFStringGetLength(string:CfRef)->isize;
        fn CFStringGetCString(string:CfRef,buffer:*mut c_char,size:isize,encoding:u32)->u8;
        fn CFDataGetLength(value:CfRef)->isize;
        fn CFDataGetBytePtr(value:CfRef)->*const u8;
        #[cfg(test)]
        fn CFDataCreate(allocator:CfRef,bytes:*const u8,length:isize)->CfRef;
        fn CFDictionaryGetCount(value:CfRef)->isize;
        fn CFDictionaryGetValue(value:CfRef,key:CfRef)->CfRef;
        fn CFDictionaryGetKeysAndValues(value:CfRef,keys:*mut CfRef,values:*mut CfRef);
        fn CFArrayGetCount(value:CfRef)->isize;
        fn CFArrayGetValueAtIndex(value:CfRef,index:isize)->CfRef;
        #[cfg(test)]
        fn CFArrayCreate(allocator:CfRef,values:*const CfRef,count:isize,callbacks:CfRef)->CfRef;
        fn CFBooleanGetValue(value:CfRef)->u8;
        fn CFNumberIsFloatType(value:CfRef)->u8;
        fn CFNumberGetValue(value:CfRef,kind:isize,out:*mut c_void)->u8;
        #[cfg(test)]
        fn CFNumberCreate(allocator:CfRef,kind:isize,value:*const c_void)->CfRef;
        fn CFURLCreateFromFileSystemRepresentation(allocator:CfRef,bytes:*const u8,length:isize,directory:u8)->CfRef;
        fn CFURLGetFileSystemRepresentation(url:CfRef,resolve:u8,buffer:*mut u8,maximum:isize)->u8;
    }
    #[link(name="Security",kind="framework")]
    extern "C" {
        static kSecCodeInfoIdentifier:CfRef;
        static kSecCodeInfoTeamIdentifier:CfRef;
        static kSecCodeInfoUnique:CfRef;
        static kSecCodeInfoDigestAlgorithm:CfRef;
        static kSecCodeInfoDigestAlgorithms:CfRef;
        static kSecCodeInfoCdHashes:CfRef;
        static kSecCodeInfoFlags:CfRef;
        static kSecCodeInfoEntitlementsDict:CfRef;
        static kSecCodeInfoMainExecutable:CfRef;
        static kSecCodeInfoPList:CfRef;
        fn SecStaticCodeCreateWithPath(path:CfRef,flags:u32,out:*mut CfRef)->i32;
        fn SecRequirementCreateWithString(text:CfRef,flags:u32,out:*mut CfRef)->i32;
        fn SecStaticCodeCheckValidityWithErrors(code:CfRef,flags:u32,requirement:CfRef,errors:*mut CfRef)->i32;
        fn SecCodeCopySigningInformation(code:CfRef,flags:u32,out:*mut CfRef)->i32;
        fn SecCodeCopyPath(code:CfRef,flags:u32,out:*mut CfRef)->i32;
    }
    struct Cf(CfRef);
    impl Drop for Cf {fn drop(&mut self) {if !self.0.is_null() {unsafe {CFRelease(self.0)};}}}
    fn typed(value:CfRef,kind:usize)->EnclaveResult<CfRef> {
        if value.is_null() || unsafe {CFGetTypeID(value)}!=kind {fail!(EACCES,"NATIVE_CODE_SIGNING_INFO");}Ok(value)
    }
    fn text(value:CfRef)->EnclaveResult<String> {
        typed(value,unsafe {CFStringGetTypeID()})?;let mut buffer=[0i8;4096];
        if unsafe {CFStringGetCString(value,buffer.as_mut_ptr(),buffer.len() as isize,UTF8)}==0 {fail!(EACCES,"NATIVE_CODE_SIGNING_INFO");}
        let result=unsafe {CStr::from_ptr(buffer.as_ptr())}.to_str().map_err(|_|err!(EACCES,"NATIVE_CODE_SIGNING_INFO"))?;
        // C string extraction must not truncate a signed CFString containing
        // an embedded NUL and accidentally accept a known key/value prefix.
        if result.encode_utf16().count() as isize!=unsafe {CFStringGetLength(value)} {
            fail!(EACCES,"NATIVE_CODE_SIGNING_INFO");
        }
        Ok(result.to_owned())
    }
    fn cf_text(value:&str)->EnclaveResult<Cf> {
        let result=Cf(unsafe {CFStringCreateWithBytes(std::ptr::null(),value.as_ptr(),value.len() as isize,UTF8,0)});
        typed(result.0,unsafe {CFStringGetTypeID()})?;Ok(result)
    }
    fn number(value:CfRef)->EnclaveResult<i64> {
        typed(value,unsafe {CFNumberGetTypeID()})?;let mut result=0i64;
        if unsafe {CFNumberIsFloatType(value)}!=0
            || unsafe {CFNumberGetValue(value,4,(&mut result as *mut i64).cast())}==0 {
            fail!(EACCES,"NATIVE_CODE_SIGNING_INFO");
        }Ok(result)
    }
    fn value(dict:CfRef,key:CfRef)->CfRef {unsafe {CFDictionaryGetValue(dict,key)}}
    fn cdhash_data(value:CfRef)->EnclaveResult<Vec<u8>> {
        typed(value,unsafe {CFDataGetTypeID()})?;
        if unsafe {CFDataGetLength(value)}!=20 {fail!(EACCES,"NATIVE_CODE_SIGNING_INFO");}
        let bytes=unsafe {CFDataGetBytePtr(value)};
        if bytes.is_null() {fail!(EACCES,"NATIVE_CODE_SIGNING_INFO");}
        Ok(unsafe {std::slice::from_raw_parts(bytes,20)}.to_vec())
    }
    fn selected_cdhash(unique:CfRef,selected:CfRef,algorithms:CfRef,hashes:CfRef)->EnclaveResult<String> {
        let unique=cdhash_data(unique)?;let selected=number(selected)?;
        typed(algorithms,unsafe {CFArrayGetTypeID()})?;typed(hashes,unsafe {CFArrayGetTypeID()})?;
        let count=unsafe {CFArrayGetCount(algorithms)};
        if !(1..=16).contains(&count) || unsafe {CFArrayGetCount(hashes)}!=count {
            fail!(EACCES,"NATIVE_CODE_SIGNING_INFO");
        }
        let mut digest_algorithms=Vec::new();let mut cdhashes=Vec::new();
        for index in 0..count {
            digest_algorithms.push(number(unsafe {CFArrayGetValueAtIndex(algorithms,index)})?);
            cdhashes.push(cdhash_data(unsafe {CFArrayGetValueAtIndex(hashes,index)})?);
        }
        consistent_selected_cdhash(&unique,selected,&digest_algorithms,&cdhashes)
    }
    fn url_path(value:CfRef)->EnclaveResult<PathBuf> {
        typed(value,unsafe {CFURLGetTypeID()})?;let mut bytes=[0u8;4096];
        if unsafe {CFURLGetFileSystemRepresentation(value,1,bytes.as_mut_ptr(),bytes.len() as isize)}==0 {
            fail!(EACCES,"NATIVE_CODE_SIGNING_INFO");
        }
        let end=bytes.iter().position(|b|*b==0).ok_or_else(||err!(EACCES,"NATIVE_CODE_SIGNING_INFO"))?;
        Ok(PathBuf::from(std::ffi::OsStr::from_bytes(&bytes[..end])))
    }
    fn entitlements(dict:CfRef)->EnclaveResult<BTreeMap<String,Entitlement>> {
        typed(dict,unsafe {CFDictionaryGetTypeID()})?;
        let count=unsafe {CFDictionaryGetCount(dict)};
        if !(0..=16).contains(&count) {fail!(EACCES,"NATIVE_CODE_ENTITLEMENTS");}
        let mut keys=vec![std::ptr::null();count as usize];let mut values=keys.clone();
        unsafe {CFDictionaryGetKeysAndValues(dict,keys.as_mut_ptr(),values.as_mut_ptr())};
        let mut result=BTreeMap::new();
        for (key,value) in keys.into_iter().zip(values) {
            let key=text(key)?;if key.len()>256 || value.is_null() {fail!(EACCES,"NATIVE_CODE_ENTITLEMENTS");}
            let kind=unsafe {CFGetTypeID(value)};
            let entry=if kind==unsafe {CFBooleanGetTypeID()} {Entitlement::Boolean(unsafe {CFBooleanGetValue(value)}!=0)}
                else if kind==unsafe {CFStringGetTypeID()} {let s=text(value)?;if s.len()>256 {fail!(EACCES,"NATIVE_CODE_ENTITLEMENTS");}Entitlement::Text(s)}
                else if kind==unsafe {CFArrayGetTypeID()} {
                    let count=unsafe {CFArrayGetCount(value)};if !(0..=8).contains(&count) {fail!(EACCES,"NATIVE_CODE_ENTITLEMENTS");}
                    let mut strings=Vec::new();for i in 0..count {let s=text(unsafe {CFArrayGetValueAtIndex(value,i)})?;
                        if s.len()>256 {fail!(EACCES,"NATIVE_CODE_ENTITLEMENTS");}strings.push(s);}
                    Entitlement::TextArray(strings)
                }else{fail!(EACCES,"NATIVE_CODE_ENTITLEMENTS");};
            if result.insert(key,entry).is_some() {fail!(EACCES,"NATIVE_CODE_ENTITLEMENTS");}
        }Ok(result)
    }
    #[cfg(test)]
    pub(super) fn test_cf_boundaries() {
        let good=cf_text("public fixture").unwrap();assert_eq!(text(good.0).unwrap(),"public fixture");
        let nul=cf_text("known-prefix\0untrusted-suffix").unwrap();assert!(text(nul.0).is_err());
        assert!(text(std::ptr::null()).is_err());assert!(number(good.0).is_err());
        assert!(url_path(good.0).is_err());assert!(entitlements(good.0).is_err());
    }
    #[cfg(test)]
    pub(super) fn test_selected_hash_boundaries() {
        let empty=std::ptr::null();let bytes=[0xabu8;20];let algorithm=2i64;
        let data=Cf(unsafe {CFDataCreate(empty,bytes.as_ptr(),bytes.len() as isize)});
        let short=Cf(unsafe {CFDataCreate(empty,bytes.as_ptr(),19)});
        let number=Cf(unsafe {CFNumberCreate(empty,4,(&algorithm as *const i64).cast())});
        let text=cf_text("2").unwrap();
        let arrays=[number.0];let hashes=[data.0];
        // Null callbacks keep values borrowed; the owning CF objects above
        // outlive all uses of these arrays.
        let algorithms=Cf(unsafe {CFArrayCreate(empty,arrays.as_ptr(),1,empty)});
        let cdhashes=Cf(unsafe {CFArrayCreate(empty,hashes.as_ptr(),1,empty)});
        assert_eq!(selected_cdhash(data.0,number.0,algorithms.0,cdhashes.0).unwrap(),"ab".repeat(20));
        for (unique,selected,kinds,values) in [
            (empty,number.0,algorithms.0,cdhashes.0),
            (text.0,number.0,algorithms.0,cdhashes.0),
            (short.0,number.0,algorithms.0,cdhashes.0),
            (data.0,empty,algorithms.0,cdhashes.0),
            (data.0,number.0,empty,cdhashes.0),
            (data.0,number.0,algorithms.0,empty),
            (data.0,text.0,algorithms.0,cdhashes.0),
            (data.0,number.0,text.0,cdhashes.0),
            (data.0,number.0,algorithms.0,text.0),
            (data.0,number.0,cdhashes.0,cdhashes.0),
            (data.0,number.0,algorithms.0,algorithms.0),
        ] {assert!(selected_cdhash(unique,selected,kinds,values).is_err());}
    }
    pub(super) struct SecurityBackend;
    impl StaticBackend for SecurityBackend {
        fn inspect(&mut self,path:&Path,bundle:bool,requirement:&str)->EnclaveResult<SigningObservation> {
            let bytes=path.as_os_str().as_bytes();
            let url=Cf(unsafe {CFURLCreateFromFileSystemRepresentation(std::ptr::null(),bytes.as_ptr(),bytes.len() as isize,u8::from(bundle))});
            typed(url.0,unsafe {CFURLGetTypeID()})?;
            let mut code=std::ptr::null();let status=unsafe {SecStaticCodeCreateWithPath(url.0,0,&mut code)};let code=Cf(code);
            if status!=0 || code.0.is_null() {fail!(EACCES,"NATIVE_CODE_UNRESOLVED");}
            let req_text=cf_text(requirement)?;let mut req=std::ptr::null();
            let status=unsafe {SecRequirementCreateWithString(req_text.0,0,&mut req)};let req=Cf(req);
            if status!=0 || req.0.is_null() {fail!(EACCES,"NATIVE_CODE_REQUIREMENT");}
            let mut errors=std::ptr::null();
            let status=unsafe {SecStaticCodeCheckValidityWithErrors(code.0,VALIDATION_FLAGS,req.0,&mut errors)};let _errors=Cf(errors);
            if status!=0 {fail!(EACCES,"NATIVE_CODE_SIGNATURE");}
            let mut info=std::ptr::null();let status=unsafe {SecCodeCopySigningInformation(code.0,SIGNING_INFORMATION,&mut info)};let info=Cf(info);
            if status!=0 {fail!(EACCES,"NATIVE_CODE_SIGNING_INFO");}typed(info.0,unsafe {CFDictionaryGetTypeID()})?;
            let identifier=text(value(info.0,unsafe {kSecCodeInfoIdentifier}))?;
            let team=value(info.0,unsafe {kSecCodeInfoTeamIdentifier});
            let team_id=if team.is_null() {String::new()}else{text(team)?};
            let cdhash=selected_cdhash(value(info.0,unsafe {kSecCodeInfoUnique}),
                value(info.0,unsafe {kSecCodeInfoDigestAlgorithm}),
                value(info.0,unsafe {kSecCodeInfoDigestAlgorithms}),
                value(info.0,unsafe {kSecCodeInfoCdHashes}))?;
            let flags=u32::try_from(number(value(info.0,unsafe {kSecCodeInfoFlags}))?).map_err(|_|err!(EACCES,"NATIVE_CODE_SIGNING_INFO"))?;
            let entitlements=entitlements(value(info.0,unsafe {kSecCodeInfoEntitlementsDict}))?;
            let executable_path=url_path(value(info.0,unsafe {kSecCodeInfoMainExecutable}))?;
            let mut actual_path=std::ptr::null();let status=unsafe {SecCodeCopyPath(code.0,0,&mut actual_path)};let actual_path=Cf(actual_path);
            if status!=0 {fail!(EACCES,"NATIVE_CODE_SIGNING_INFO");}let code_path=url_path(actual_path.0)?;
            let bundle_info=if bundle {
                let plist=value(info.0,unsafe {kSecCodeInfoPList});typed(plist,unsafe {CFDictionaryGetTypeID()})?;
                let identifier=cf_text("CFBundleIdentifier")?;let executable=cf_text("CFBundleExecutable")?;
                Some((text(value(plist,identifier.0))?,text(value(plist,executable.0))?))
            }else{None};
            Ok(SigningObservation {identity:CodeIdentity {identifier,team_id,cdhash},flags,entitlements,code_path,executable_path,bundle_info})
        }
    }
}

#[cfg(test)]
#[path="target_native_code_tests.rs"]
mod tests;
