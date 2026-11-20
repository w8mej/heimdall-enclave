//! Native create-only birth of an inert dedicated L2 namespace.
//!
//! No checked target, inactivity/payload authority, EX, publication, permission
//! cutover, provider, account operation or service start is constructed here.
//! A raw descriptor is only data. Genuine authority/inventory/pins must still
//! arrive independently before protected deployment loading can succeed.
//!
//! The SAME borrowed host guard constrains cooperating root writers. Hostile
//! root is excluded: mkdirat cannot atomically return an open directory, so its
//! immediate nofollow observation relies on the protected parent and guard.
//! Original observed created identities are retained thereafter. All errors and
//! drops leave names untouched, including partial files and private directories.

use std::{collections::{BTreeMap,BTreeSet},ffi::CString,fs::{File,Metadata},io::Write,
    os::{fd::{AsRawFd,FromRawFd},unix::{ffi::OsStrExt,fs::{FileExt,MetadataExt}}},
    path::{Component,Path,PathBuf}};
use enclave_core::{deployment::{DeploymentRole,DeploymentSigningMode,DeploymentTarget,
    normalized_path,startup_lease::STARTUP_LIFETIME_LEAF,upgrade::UPGRADE_INHIBITION_LEAF},
    error::{EnclaveError,EnclaveResult},profile::Profile,err,fail};
use serde::Serialize;
use sha2::{Digest,Sha256};
use super::{HostMaintenanceGuard,MaintenanceExclusion};

#[path="target_birth_import.rs"]
mod input_import;
#[path="target_birth_admit.rs"]
mod admit;
#[path="target_birth_stage.rs"]
mod staging_import;
#[path="target_birth_candidate.rs"]
mod candidate;
#[path="target_birth_metadata.rs"]
mod metadata;
#[path="target_birth_directory_event.rs"]
mod directory_event;
#[path="target_birth_denial_handoff.rs"]
mod denial_handoff;
#[path="target_birth_live_directories.rs"]
mod live_directories;
#[path="target_birth_session.rs"]
mod session;
pub use session::{DedicatedBirthSessionArgs,DedicatedBirthSessionExit,DedicatedBirthRenderArgs,
    run_dedicated_birth_session,render_dedicated_birth_public_data};

// A private timing observation from THIS successful actual verification only.
// No caller/report constructor or runtime authority is provided. The same
// actual owners must remain checked through the final current() observation.
struct CryptoExpiryObservation {checked_at:i64,not_after:i64}
fn within_crypto_window(checked_at:i64,not_after:i64,now:i64)->EnclaveResult<()> {
    if checked_at<0||now<checked_at||not_after<=checked_at||now>=not_after {
        fail!(EACCES,"BIRTH_RUNTIME_FINAL_CRYPTO_EXPIRED");
    }Ok(())
}
impl CryptoExpiryObservation {
    fn current(&self)->EnclaveResult<()> {
        within_crypto_window(self.checked_at,self.not_after,enclave_crypto::time::now_unix())
    }
}

const MAX_NODES:usize=96;
const DESCRIPTOR:&str="config/deployment.json";
const DARWIN_SOCKET_CAPACITY:usize=104;

#[derive(Clone,Debug,Serialize)]
pub(crate) struct BirthProgress {
    pub(crate) operation:&'static str,
    pub(crate) root:Option<PathBuf>,
    pub(crate) descriptor:Option<PathBuf>,
    pub(crate) target_id:Option<String>,
    pub(crate) attempted:Vec<PathBuf>,
    pub(crate) created_directories:Vec<PathBuf>,
    pub(crate) created_files:Vec<PathBuf>,
    pub(crate) existing_names:Vec<PathBuf>,
    pub(crate) synced:Vec<PathBuf>,
    pub(crate) seeds_complete:bool,
    pub(crate) denial_prepared:bool,
    pub(crate) pending_descriptor_sha256:Option<String>,
    pub(crate) pending_inventory_sha256:Option<String>,
    pub(crate) complete:bool,
    pub(crate) uncertain_effects:bool,
    pub(crate) mutation_allowed:bool,
    pub(crate) inactivity_proven:bool,
    pub(crate) activation_allowed:bool,
    pub(crate) installation_supported:bool,
    pub(crate) qualified:bool,
}
impl BirthProgress {
    fn new()->Self {Self {operation:"begin_birth",root:None,descriptor:None,target_id:None,
        attempted:Vec::new(),created_directories:Vec::new(),created_files:Vec::new(),
        existing_names:Vec::new(),synced:Vec::new(),seeds_complete:false,denial_prepared:false,
        pending_descriptor_sha256:None,pending_inventory_sha256:None,complete:false,
        uncertain_effects:false,mutation_allowed:false,inactivity_proven:false,
        activation_allowed:false,installation_supported:false,qualified:false}}
}
#[derive(Debug)]
pub(crate) struct BirthFailure {
    pub(crate) error:EnclaveError,
    pub(crate) boundary_errors:Vec<EnclaveError>,
    pub(crate) final_errors:Vec<EnclaveError>,
    pub(crate) progress:BirthProgress,
}
fn errors(results:impl IntoIterator<Item=EnclaveResult<()>>)->Vec<EnclaveError> {
    results.into_iter().filter_map(Result::err).collect()
}
fn first(values:&[EnclaveError])->EnclaveResult<()> {
    values.first().cloned().map_or(Ok(()),Err)
}
fn outcome<T>(progress:&mut BirthProgress,operation:EnclaveResult<T>,
    boundary_errors:Vec<EnclaveError>,final_errors:Vec<EnclaveError>)->Result<T,BirthFailure> {
    progress.complete=operation.is_ok()&&final_errors.is_empty();
    if !progress.complete&&(!progress.created_directories.is_empty()||!progress.created_files.is_empty()) {
        progress.uncertain_effects=true;
    }
    match operation {
        Err(error)=>Err(BirthFailure {error,boundary_errors,final_errors,progress:progress.clone()}),
        Ok(value)=>match first(&final_errors) {
            Ok(())=>Ok(value),
            Err(error)=>Err(BirthFailure {error,boundary_errors,final_errors,progress:progress.clone()}),
        },
    }
}
fn folded(path:&Path)->EnclaveResult<PathBuf> {
    Ok(PathBuf::from(normalized_path(path)?.to_str().ok_or_else(||err!(EINVAL,"BIRTH_PATH"))?.to_ascii_lowercase()))
}
fn overlaps(a:&Path,b:&Path)->EnclaveResult<bool> {
    let a=folded(a)?;let b=folded(b)?;Ok(a.starts_with(&b)||b.starts_with(&a))
}
fn below(path:&Path,root:&Path)->EnclaveResult<PathBuf> {
    let path=normalized_path(path)?;let root=normalized_path(root)?;
    let suffix=path.strip_prefix(root).map_err(|_|err!(EACCES,"BIRTH_PATH_OUTSIDE_TEMPLATE"))?;
    if suffix.as_os_str().is_empty(){fail!(EACCES,"BIRTH_STRICT_DESCENDANT_REQUIRED");}Ok(suffix.to_owned())
}
fn roots(t:&DeploymentTarget)->[&Path;9] {
    let l=&t.layout;[&l.binary_dir,&l.custody_bundle,&l.sandbox_dir,&l.socket_root,&l.state_root,
        &l.audit_root,&l.cas_store_root,&l.staging_root,&l.support_root]
}
struct BirthPlan {root:PathBuf,target:DeploymentTarget,descriptor:PathBuf,bytes:Vec<u8>,seed_dirs:Vec<PathBuf>}
impl BirthPlan {
    /// Private deterministic engine seam. Production nonce is generated by the
    /// native constructor, never accepted from a CLI, caller, receipt or file.
    fn build(template:&DeploymentTarget,template_root:&Path,parent:&Path,nonce:&[u8;16])->EnclaveResult<Self> {
        template.validate()?;
        if template.role!=DeploymentRole::DedicatedTest||template.profile!=Profile::L2
            ||template.signing_identity_mode!=DeploymentSigningMode::LocalPins
            ||template.broker.is_some()||!template.shared_read_only_inputs.is_empty() {
            fail!(EACCES,"BIRTH_DEDICATED_L2_LOCAL_PINS_REQUIRED");
        }
        let template_root=normalized_path(template_root)?;let parent=normalized_path(parent)?;
        let token=hex::encode(nonce);let root=parent.join(&token);
        normalized_path(&root)?;
        let rebase=|path:&Path|->EnclaveResult<PathBuf>{Ok(root.join(below(path,&template_root)?))};
        let mut target=template.clone();
        target.target_id=format!("ykft-{token}");
        target.authority_config=rebase(&template.authority_config)?;
        target.expected_artifacts_manifest=rebase(&template.expected_artifacts_manifest)?;
        target.codesign_pins_file=rebase(&template.codesign_pins_file)?;
        let old=&template.layout;let l=&mut target.layout;
        l.binary_dir=rebase(&old.binary_dir)?;l.custody_bundle=rebase(&old.custody_bundle)?;
        l.sandbox_dir=rebase(&old.sandbox_dir)?;l.socket_root=rebase(&old.socket_root)?;
        l.state_root=rebase(&old.state_root)?;l.audit_root=rebase(&old.audit_root)?;
        l.cas_store_root=rebase(&old.cas_store_root)?;l.staging_root=rebase(&old.staging_root)?;
        l.support_root=rebase(&old.support_root)?;
        // Prefix the component: a bare random hex component can start numeric,
        // which the deployment service-name schema correctly refuses.
        l.launchd_namespace=format!("com.enterprise.enclave.ykft.n{token}");
        l.mach_service=format!("{}.exception",l.launchd_namespace);
        target.validate()?;
        let descriptor=root.join(DESCRIPTOR);
        let inventory=&target.expected_artifacts_manifest;
        let excluded=roots(&target).into_iter().chain([target.authority_config.as_path(),target.codesign_pins_file.as_path()]);
        for path in excluded {
            if overlaps(&descriptor,path)?||overlaps(inventory,path)? {fail!(EACCES,"BIRTH_RELEASE_MUTATION_DOMAIN");}
        }
        if overlaps(&descriptor,inventory)? {fail!(EACCES,"BIRTH_DESCRIPTOR_INVENTORY_OVERLAP");}
        let lease=target.layout.support_root.join(STARTUP_LIFETIME_LEAF);
        let denial=target.layout.support_root.join(UPGRADE_INHIBITION_LEAF);
        for path in roots(&target).into_iter().chain([target.authority_config.as_path(),inventory,
            target.codesign_pins_file.as_path(),descriptor.as_path()]) {
            below(path,&root)?;
            if path.components().any(|part|matches!(part,Component::Normal(name) if name.as_bytes().len()>255)) {
                fail!(E2BIG,"BIRTH_PATH_COMPONENT_BOUND");
            }
            for reserved in [&lease,&denial] {
                if path!=target.layout.support_root.as_path()&&overlaps(path,reserved)? {fail!(EACCES,"BIRTH_RESERVED_NAME");}
            }
        }
        // Validate future maximum-width console routes on every platform,
        // rather than accidentally using Linux's larger sockaddr_un capacity.
        let mut suffixes=vec!["intent/4294967294/intent.sock".to_owned(),"oidc/4294967294/oidc.sock".into(),
            "supervisor/supervisor.sock".into(),"browser/browser.sock".into(),
            enclave_core::daemon::WITNESS_SOCKET_NAME.into(),"fido/fido.sock".into()];
        suffixes.extend(enclave_core::daemon::DaemonId::ALL.into_iter().map(|d|d.socket_name()));
        for suffix in suffixes {
            if target.layout.socket_root.join(suffix).as_os_str().as_bytes().len()>=DARWIN_SOCKET_CAPACITY {
                fail!(E2BIG,"BIRTH_DARWIN_SOCKET_PATH");
            }
        }
        // Only the exact config/support/staging chains may be prepared. Do not
        // accidentally create any payload bundle or runtime/state/CAS ancestor.
        let mut dirs=BTreeSet::new();
        for path in [descriptor.parent().expect("fixed descriptor parent"),
            target.layout.support_root.as_path(),target.layout.staging_root.as_path()] {
            let mut path=path;
            while path!=root {
                below(path,&root)?;dirs.insert(path.to_owned());
                path=path.parent().ok_or_else(||err!(EINVAL,"BIRTH_PATH"))?;
            }
        }
        for path in &dirs {
            for prohibited in [&target.layout.binary_dir,&target.layout.custody_bundle,&target.layout.sandbox_dir,
                &target.layout.socket_root,&target.layout.state_root,&target.layout.audit_root,&target.layout.cas_store_root] {
                let support_for_future_bundle=path==&target.layout.support_root
                    &&prohibited==&target.layout.custody_bundle
                    &&folded(prohibited)?.starts_with(folded(path)?)&&folded(prohibited)?!=folded(path)?;
                if overlaps(path,prohibited)?&&!support_for_future_bundle {fail!(EACCES,"BIRTH_SEED_RUNTIME_OVERLAP");}
            }
            for input in [inventory,target.authority_config.as_path(),target.codesign_pins_file.as_path(),descriptor.as_path()] {
                if folded(path)?==folded(input)?||folded(path)?.starts_with(folded(input)?) {
                    fail!(EACCES,"BIRTH_SEED_INPUT_OVERLAP");
                }
            }
        }
        if dirs.len()+root.components().count()>MAX_NODES {fail!(E2BIG,"BIRTH_DIRECTORY_LIMIT");}
        let mut seed_dirs:Vec<_>=dirs.into_iter().collect();
        seed_dirs.sort_by_key(|p|(p.components().count(),p.clone()));
        let bytes=serde_json::to_vec(&target).map_err(|_|err!(EIO,"BIRTH_DESCRIPTOR_ENCODING"))?;
        DeploymentTarget::parse(&bytes)?;
        Ok(Self {root,target,descriptor,bytes,seed_dirs})
    }
}

#[derive(Clone,Copy)]
struct Protection {owner:(u32,u32),native_acl:bool}
#[derive(Clone,PartialEq,Eq)]
struct DirStamp {dev:u64,ino:u64,uid:u32,gid:u32,mode:u32}
impl DirStamp {fn of(m:&Metadata)->Self {Self {dev:m.dev(),ino:m.ino(),uid:m.uid(),gid:m.gid(),mode:m.mode()}}}
fn stat(file:&File)->EnclaveResult<Metadata> {file.metadata().map_err(|_|err!(EIO,"BIRTH_STAT"))}
fn name(path:&Path)->EnclaveResult<CString> {
    let leaf=path.file_name().ok_or_else(||err!(EINVAL,"BIRTH_PATH"))?;
    CString::new(leaf.as_bytes()).map_err(|_|err!(EINVAL,"BIRTH_PATH"))
}
fn flags(file:&File,access:i32)->EnclaveResult<()> {
    let status=unsafe {libc::fcntl(file.as_raw_fd(),libc::F_GETFL)};
    let descriptor=unsafe {libc::fcntl(file.as_raw_fd(),libc::F_GETFD)};
    if status<0||status&libc::O_ACCMODE!=access||status&libc::O_NONBLOCK==0
        ||descriptor<0||descriptor&libc::FD_CLOEXEC==0 {fail!(ESTALE,"BIRTH_DESCRIPTOR_FLAGS");}Ok(())
}
fn open_at(parent:&File,path:&Path,directory:bool)->EnclaveResult<File> {
    let leaf=name(path)?;
    let fd=unsafe {libc::openat(parent.as_raw_fd(),leaf.as_ptr(),libc::O_RDONLY|libc::O_NOFOLLOW
        |libc::O_NONBLOCK|libc::O_CLOEXEC|if directory {libc::O_DIRECTORY}else{0})};
    if fd<0 {fail!(ESTALE,"BIRTH_NAME_CHANGED");}Ok(unsafe {File::from_raw_fd(fd)})
}

/// No ACL repair/removal. Unsupported or ambiguous inspection denies birth.
fn no_extended_acl(file:&File,protection:Protection)->EnclaveResult<()> {
    if !protection.native_acl {return Ok(());}
    #[cfg(target_os="macos")]
    {
        use std::ffi::c_void;
        unsafe extern "C" {
            fn acl_get_fd_np(fd:libc::c_int,kind:libc::c_int)->*mut c_void;
            fn acl_get_entry(acl:*mut c_void,entry_id:libc::c_int,entry:*mut *mut c_void)->libc::c_int;
            fn acl_valid(acl:*mut c_void)->libc::c_int;
            fn acl_free(object:*mut c_void)->libc::c_int;
        }
        // Clear the thread-local errno so a null result cannot accidentally
        // inherit a stale ENOENT from an earlier unrelated operation.
        unsafe {*libc::__error()=0;}
        let acl=unsafe {acl_get_fd_np(file.as_raw_fd(),0x100)}; // Darwin ACL_TYPE_EXTENDED.
        let get_errno=std::io::Error::last_os_error().raw_os_error();
        if acl.is_null() {
            // Darwin filesec_get_property reports absent FILESEC_ACL as
            // ENOENT. Any other inspection failure refuses the operation.
            if get_errno==Some(libc::ENOENT){return Ok(());}
            fail!(EACCES,"BIRTH_ACL_INSPECTION_REQUIRED");
        }
        let valid=unsafe {acl_valid(acl)};
        let mut entry=std::ptr::null_mut();
        let result=unsafe {acl_get_entry(acl,0,&mut entry)}; // Darwin ACL_FIRST_ENTRY.
        let errno=std::io::Error::last_os_error().raw_os_error();
        let freed=unsafe {acl_free(acl)};
        // Darwin (unlike Linux POSIX ACL) returns -1/EINVAL for empty FIRST,
        // and 0 for an entry. Validate the actual returned ACL first.
        if valid!=0||result!=-1||errno!=Some(libc::EINVAL)||freed!=0 {fail!(EACCES,"BIRTH_EXTENDED_ACL_REFUSED");}
        Ok(())
    }
    #[cfg(not(target_os="macos"))]
    {let _=file;fail!(ENOSYS,"BIRTH_NATIVE_ACL_REQUIRED");}
}
struct Directory {file:File,parent:Option<PathBuf>,stamp:DirStamp,links:u64,private:bool}
impl Directory {
    fn capture(file:File,parent:Option<PathBuf>,private:bool,p:Protection)->EnclaveResult<Self> {
        let m=stat(&file)?;Self::protection(&file,&m,private,p)?;
        Ok(Self {file,parent,stamp:DirStamp::of(&m),links:m.nlink(),private})
    }
    fn protection(file:&File,m:&Metadata,private:bool,p:Protection)->EnclaveResult<()> {
        if !m.is_dir()||m.uid()!=p.owner.0||m.mode()&0o022!=0||m.nlink()==0
            ||(private&&(m.gid()!=p.owner.1||m.mode()&0o7777!=0o700)) {
            fail!(EACCES,"BIRTH_DIRECTORY_PROTECTION");
        }
        flags(file,libc::O_RDONLY)?;no_extended_acl(file,p)
    }
    fn current(&self,file:&File,p:Protection,links:bool)->EnclaveResult<()> {
        // Immutable own-creation provenance; expected metadata advances only
        // through a closed original-inode own-syscall transition.
        if self.private {return metadata::current_created_directory(self,file,p,links);}
        let m=stat(file)?;Self::protection(file,&m,self.private,p)?;
        if DirStamp::of(&m)!=self.stamp||(links&&m.nlink()!=self.links) {fail!(ESTALE,"BIRTH_DIRECTORY_CHANGED");}Ok(())
    }
}
#[derive(PartialEq,Eq)]
struct FileStamp {directory:DirStamp,links:u64,len:u64,modified:(i64,i64),changed:(i64,i64)}
impl FileStamp {fn of(m:&Metadata)->Self {Self {directory:DirStamp::of(m),links:m.nlink(),len:m.len(),
    modified:(m.mtime(),m.mtime_nsec()),changed:(m.ctime(),m.ctime_nsec())}}}
// Small seeds retain exact bytes; streamed public package files retain only
// their bounded digest expectation. Empty exact files and streamed files are
// distinguished explicitly, never inferred from the byte vector's length.
struct StreamedContent {length:u64,sha256:String}
struct SeedFile {file:File,stamp:FileStamp,bytes:Vec<u8>,access:i32,
    streamed:Option<StreamedContent>}
impl SeedFile {
    fn exact_bytes(&self)->Option<&[u8]> {if self.streamed.is_none(){Some(&self.bytes)}else{None}}
    fn current(&self,parent:&File,path:&Path,p:Protection)->EnclaveResult<()> {
        self.current_with_content(parent,path,p,true)
    }
    fn current_with_content(&self,parent:&File,path:&Path,p:Protection,full:bool)->EnclaveResult<()> {
        self.current_on(&self.file,self.access,parent,path,p,full)
    }
    // Verify another descriptor against THIS original stamp/content, without
    // cloning public payload bytes or changing the retained original owner.
    fn current_on(&self,file:&File,access:i32,parent:&File,path:&Path,p:Protection,full:bool)->EnclaveResult<()> {
        let named=open_at(parent,path,false)?;
        let held=stat(file)?;let fresh=stat(&named)?;
        if FileStamp::of(&held)!=self.stamp||FileStamp::of(&fresh)!=self.stamp
            ||!held.is_file()||held.nlink()!=1||held.uid()!=p.owner.0||held.gid()!=p.owner.1 {
            fail!(ESTALE,"BIRTH_SEED_CHANGED");
        }
        flags(file,access)?;flags(&named,libc::O_RDONLY)?;
        no_extended_acl(file,p)?;no_extended_acl(&named,p)?;
        if let Some(expected)=&self.streamed {
            if !self.bytes.is_empty()||expected.length!=self.stamp.len {fail!(ESTALE,"BIRTH_SEED_CHANGED");}
            if full&&file_sha256(file,expected.length)?!=expected.sha256 {
                fail!(ESTALE,"BIRTH_STREAM_DIGEST_CHANGED");
            }
        }else {
            let mut bytes=vec![0;self.bytes.len()+1];
            let count=file.read_at(&mut bytes,0).map_err(|_|err!(EIO,"BIRTH_SEED_READ"))?;
            if count!=self.bytes.len()||bytes[..count]!=self.bytes {fail!(ESTALE,"BIRTH_SEED_CHANGED");}
        }
        if FileStamp::of(&stat(file)?)!=self.stamp||FileStamp::of(&stat(&named)?)!=self.stamp {
            fail!(ESTALE,"BIRTH_SEED_CHANGED");
        }Ok(())
    }
}
fn file_sha256(file:&File,length:u64)->EnclaveResult<String> {
    let mut hash=Sha256::new();let mut buffer=[0;64*1024];let mut offset=0u64;
    while offset<length {
        let wanted=(length-offset).min(buffer.len() as u64) as usize;let mut done=0;
        while done<wanted {
            let count=loop {match file.read_at(&mut buffer[done..wanted],offset+done as u64) {
                Err(e) if e.kind()==std::io::ErrorKind::Interrupted=>continue,
                result=>break result.map_err(|_|err!(EIO,"BIRTH_STREAM_READ"))?,
            }};
            if count==0 {fail!(ESTALE,"BIRTH_STREAM_TRUNCATED");}done+=count;
        }
        hash.update(&buffer[..wanted]);offset+=wanted as u64;
    }
    let eof=loop {match file.read_at(&mut [0u8;1],offset) {
        Err(e) if e.kind()==std::io::ErrorKind::Interrupted=>continue,
        result=>break result.map_err(|_|err!(EIO,"BIRTH_STREAM_READ"))?,
    }};
    if eof!=0 {fail!(ESTALE,"BIRTH_STREAM_LENGTH");}
    Ok(hex::encode(hash.finalize()))
}
// Only the private creator can construct this original O_EXCL file. It stays
// local while being seeded; every failure leaves its name untouched and the
// enclosing birth poisoned. It is never exported as a writer capability.
struct CreatedFile {file:File,initial:Metadata,path:PathBuf,parent:PathBuf,mode:u32,access:i32}
impl CreatedFile {
    fn current(&self,state:&BirthState,length:u64)->EnclaveResult<()> {
        original_file(&self.file,&state.dirs[&self.parent].file,&self.path,&self.initial,
            state.protection,state.protection.owner,self.mode,length,self.access)
    }
}

fn original_file(file:&File,parent:&File,path:&Path,original:&Metadata,p:Protection,
    ownership:(u32,u32),mode:u32,length:u64,access:i32)->EnclaveResult<()> {
    let named=open_at(parent,path,false)?;
    for descriptor in [file,&named] {
        let m=stat(descriptor)?;
        if !m.is_file()||m.dev()!=original.dev()||m.ino()!=original.ino()||m.uid()!=ownership.0
            ||m.gid()!=ownership.1||m.mode()&0o7777!=mode||m.nlink()!=1||m.len()!=length {
            fail!(ESTALE,"BIRTH_SEED_CHANGED");
        }
        no_extended_acl(descriptor,p)?;
    }
    flags(file,access)
}
/// Unadmitted public inventory data only, retained from the actual bounded
/// bytes. This cannot construct SoftwareApproval or checked/selected authority.
struct PendingInventory {bytes:Vec<u8>,descriptor_sha256:String,inventory_sha256:String}
impl PendingInventory {
    fn new(plan:&BirthPlan,raw:&[u8])->EnclaveResult<Self> {
        if raw.is_empty()||raw.len()>1024*1024 {fail!(E2BIG,"BIRTH_PENDING_INVENTORY_BOUND");}
        let descriptor_sha256=hex::encode(Sha256::digest(&plan.bytes));
        // Existing pure schema/path/descriptor/staging binding, not approval.
        super::target_plan::describe(&plan.target,&descriptor_sha256,raw)?;
        Ok(Self {bytes:raw.to_owned(),descriptor_sha256,inventory_sha256:hex::encode(Sha256::digest(raw))})
    }
    fn current(&self,plan:&BirthPlan)->EnclaveResult<()> {
        if self.descriptor_sha256!=hex::encode(Sha256::digest(&plan.bytes))
            ||self.inventory_sha256!=hex::encode(Sha256::digest(&self.bytes)) {
            fail!(ESTALE,"BIRTH_PENDING_BINDING_CHANGED");
        }
        super::target_plan::describe(&plan.target,&self.descriptor_sha256,&self.bytes)?;Ok(())
    }
    fn marker_bytes(&self,plan:&BirthPlan)->EnclaveResult<Vec<u8>> {
        // Exact existing v1 negative marker schema. Presence alone denies;
        // these public hashes do not approve the inventory or grant inactivity.
        #[derive(Serialize)]
        struct Marker<'a> {version:u8,kind:&'static str,target_id:&'a str,
            descriptor_sha256:&'a str,artifact_inventory_sha256:&'a str}
        serde_json::to_vec(&Marker {version:1,kind:"depot-upgrade-start-inhibition",
            target_id:&plan.target.target_id,descriptor_sha256:&self.descriptor_sha256,
            artifact_inventory_sha256:&self.inventory_sha256}).map_err(|_|err!(EIO,"BIRTH_PENDING_ENCODING"))
    }
}
struct BirthState {plan:BirthPlan,dirs:BTreeMap<PathBuf,Directory>,files:BTreeMap<PathBuf,SeedFile>,
    protection:Protection,progress:BirthProgress,poisoned:bool,pending:Option<PendingInventory>,
    private_load:Option<admit::PrivateLoadedInputs>}
impl BirthState {
    /// Observe ONLY the parent of this invocation's just-bound created child.
    /// APFS can change directory nlink for regular files as well as directories.
    /// No caller receipt, arbitrary path or later repair may invoke this path.
    fn parent_links_after_own_creation(&mut self,parent:&Path)->EnclaveResult<()> {
        let directory=self.dirs.get(parent).ok_or_else(||err!(EINVAL,"BIRTH_PARENT_NOT_HELD"))?;
        directory.current(&directory.file,self.protection,false)?;
        if let Some(ancestor)=&directory.parent {
            let named=open_at(&self.dirs[ancestor].file,parent,true)?;
            directory.current(&named,self.protection,false)?;
        }
        let links=stat(&directory.file)?.nlink();
        self.dirs.get_mut(parent).expect("held original parent").links=links;Ok(())
    }
    fn checks(&self,check:&mut impl FnMut()->Vec<EnclaveError>)->Vec<EnclaveError> {
        self.checks_with_content(check,true)
    }
    fn metadata_checks(&self,check:&mut impl FnMut()->Vec<EnclaveError>)->Vec<EnclaveError> {
        self.checks_with_content(check,false)
    }
    fn checks_with_content(&self,check:&mut impl FnMut()->Vec<EnclaveError>,full:bool)->Vec<EnclaveError> {
        self.checks_with_content_event(check,full,None)
    }
    fn checks_with_content_event(&self,check:&mut impl FnMut()->Vec<EnclaveError>,full:bool,
        event:Option<&directory_event::PendingDirectoryEvent>)->Vec<EnclaveError> {
        self.checks_with_content_phase(check,full,event,None)
    }
    fn checks_with_content_owned_removal(&self,check:&mut impl FnMut()->Vec<EnclaveError>,full:bool,
        removal:Option<&denial_handoff::OwnedDenialRemoval>)->Vec<EnclaveError> {
        self.checks_with_content_phase(check,full,None,removal)
    }
    fn checks_with_content_live_directories(&self,check:&mut impl FnMut()->Vec<EnclaveError>,full:bool,
        removal:Option<&denial_handoff::OwnedDenialRemoval>,live:Option<&live_directories::LiveDirectoryScope>)->Vec<EnclaveError> {
        self.checks_with_content_live_phase(check,full,None,removal,live)
    }
    fn checks_with_content_phase(&self,check:&mut impl FnMut()->Vec<EnclaveError>,full:bool,
        event:Option<&directory_event::PendingDirectoryEvent>,removal:Option<&denial_handoff::OwnedDenialRemoval>)->Vec<EnclaveError> {
        self.checks_with_content_live_phase(check,full,event,removal,None)
    }
    fn checks_with_content_live_phase(&self,check:&mut impl FnMut()->Vec<EnclaveError>,full:bool,
        event:Option<&directory_event::PendingDirectoryEvent>,removal:Option<&denial_handoff::OwnedDenialRemoval>,
        live:Option<&live_directories::LiveDirectoryScope>)->Vec<EnclaveError> {
        let mut result=check();
        if event.is_some()&&(removal.is_some()||live.is_some()){result.push(err!(EACCES,"BIRTH_OVERLAPPING_ORIGINAL_PHASES"));}
        for (path,d) in &self.dirs {
            // ONLY an actual bounded one-way recipient phase may substitute
            // full event proof for this exact original directory's old mode.
            // Every untouched directory/file/Layout/pending gate is unchanged.
            if let Some(event)=event.filter(|event|event.targets(path)) {
                result.extend(errors([event.verify_directory(self,path,d)]));continue;
            }
            result.extend(errors([live_directories::current_directory(self,path,d,&d.file,removal,live)]));
            if let Some(parent)=&d.parent {
                let named=open_at(&self.dirs[parent].file,path,true)
                    .and_then(|named|live_directories::current_directory(self,path,d,&named,removal,live));
                result.extend(errors([named]));
            }
        }
        for (path,file) in &self.files {
            // Only a genuine native owned-removal proof can account for this
            // exact original denial inode. Cache/stamp/bytes stay unchanged.
            if let Some(removal)=removal.filter(|proof|proof.targets(path)) {
                result.extend(errors([removal.current_marker(self,path,file)]));continue;
            }
            result.extend(errors([file.current_with_content(&self.dirs[path.parent().expect("seed parent")].file,path,self.protection,full)]));
        }
        if let Some(pending)=&self.pending {
            result.extend(errors([pending.current(&self.plan)]));
            if self.progress.denial_prepared {
                let path=self.plan.target.layout.support_root.join(UPGRADE_INHIBITION_LEAF);
                let binding=(|| {
                    let marker=self.files.get(&path).ok_or_else(||err!(ESTALE,"BIRTH_PENDING_MARKER_NOT_HELD"))?;
                    if marker.exact_bytes()!=Some(pending.marker_bytes(&self.plan)?.as_slice()) {fail!(ESTALE,"BIRTH_PENDING_BINDING_CHANGED");}Ok(())
                })();result.extend(errors([binding]));
            }
        }
        if let Some(loaded)=&self.private_load {
            result.extend(errors([loaded.current_with_owned_removal(self,removal)]));
        }
        result.extend(check());result
    }
    fn boundary<T>(&self,operation:EnclaveResult<T>,check:&mut impl FnMut()->Vec<EnclaveError>,
        observed:&mut Vec<EnclaveError>)->EnclaveResult<T> {
        let checks=self.checks(check);let binding=first(&checks);observed.extend(checks);
        let value=operation?;binding?;Ok(value)
    }
    // Typed staging and private payload copies use metadata chunk boundaries
    // with mandatory full outer admission/final gates. Exact-byte small seeds
    // and any actual private-load currentness/expiry remain checked here.
    fn content_boundary<T>(&self,operation:EnclaveResult<T>,full:bool,
        check:&mut impl FnMut()->Vec<EnclaveError>,observed:&mut Vec<EnclaveError>)->EnclaveResult<T> {
        let checks=if full{self.checks(check)}else{self.metadata_checks(check)};
        let binding=first(&checks);observed.extend(checks);let value=operation?;binding?;Ok(value)
    }
    fn metadata_boundary<T>(&self,operation:EnclaveResult<T>,check:&mut impl FnMut()->Vec<EnclaveError>,
        observed:&mut Vec<EnclaveError>)->EnclaveResult<T> {
        self.content_boundary(operation,false,check,observed)
    }
    fn active_boundary<T>(&self,operation:EnclaveResult<T>,created:&CreatedFile,length:u64,full:bool,
        check:&mut impl FnMut()->Vec<EnclaveError>,observed:&mut Vec<EnclaveError>)->EnclaveResult<T> {
        self.content_boundary(operation,full,&mut ||{
            let mut result=check();result.extend(errors([created.current(self,length)]));result
        },observed)
    }
    fn open_ancestry(&mut self,parent:&Path)->EnclaveResult<()> {
        let fd=unsafe {libc::open(c"/".as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)};
        if fd<0 {fail!(EACCES,"BIRTH_ANCESTRY_REQUIRED");}
        let root=Directory::capture(unsafe {File::from_raw_fd(fd)},None,false,self.protection)?;
        let mut path=PathBuf::from("/");self.dirs.insert(path.clone(),root);
        for part in parent.components() {match part {
            Component::RootDir=>(),
            Component::Normal(part)=>{
                let next=path.join(part);let file=open_at(&self.dirs[&path].file,&next,true)?;
                let directory=Directory::capture(file,Some(path),false,self.protection)?;
                self.dirs.insert(next.clone(),directory);path=next;
            },
            _=>fail!(EINVAL,"BIRTH_PATH"),
        }}
        if self.dirs.len()>=MAX_NODES {fail!(E2BIG,"BIRTH_DIRECTORY_LIMIT");}Ok(())
    }
    fn sync_path(&mut self,path:&Path,check:&mut impl FnMut()->Vec<EnclaveError>,
        observed:&mut Vec<EnclaveError>,sync:&mut impl FnMut(&File)->EnclaveResult<()>)->EnclaveResult<()> {
        self.boundary(Ok(()),check,observed)?;
        let file=if let Some(d)=self.dirs.get(path){&d.file}else{&self.files[path].file};
        let synced=sync(file);if synced.is_ok(){self.progress.synced.push(path.to_owned());}
        self.boundary(synced,check,observed)
    }
    fn create_directory(&mut self,path:&Path,check:&mut impl FnMut()->Vec<EnclaveError>,
        observed:&mut Vec<EnclaveError>,sync:&mut impl FnMut(&File)->EnclaveResult<()>)->EnclaveResult<()> {
        self.boundary(Ok(()),check,observed)?;
        if self.dirs.len()>=MAX_NODES {fail!(E2BIG,"BIRTH_DIRECTORY_LIMIT");}
        let parent=path.parent().ok_or_else(||err!(EINVAL,"BIRTH_PATH"))?.to_owned();
        let held=self.dirs.get(&parent).ok_or_else(||err!(EINVAL,"BIRTH_PARENT_NOT_HELD"))?;
        let leaf=name(path)?;
        self.progress.attempted.push(path.to_owned());self.progress.uncertain_effects=true;
        let created=unsafe {libc::mkdirat(held.file.as_raw_fd(),leaf.as_ptr(),0o700)};
        let operation=if created!=0 {
            if std::io::Error::last_os_error().raw_os_error()==Some(libc::EEXIST) {
                self.progress.existing_names.push(path.to_owned());
                if self.progress.created_directories.is_empty(){self.progress.uncertain_effects=false;}
                Err(err!(EALREADY,"BIRTH_ALREADY_EXISTS"))
            }else{Err(err!(EIO,"BIRTH_CREATE_UNCERTAIN"))}
        }else {
            self.progress.created_directories.push(path.to_owned());
            // No callbacks or path traversal between successful mkdirat and
            // binding its original nofollow name to a held FD. Root adversaries
            // are excluded; ordinary writers cannot change the protected parent.
            let bound=(|| {
                let mut named=std::mem::MaybeUninit::<libc::stat>::uninit();
                if unsafe {libc::fstatat(held.file.as_raw_fd(),leaf.as_ptr(),named.as_mut_ptr(),libc::AT_SYMLINK_NOFOLLOW)}!=0 {
                    fail!(ESTALE,"BIRTH_CREATED_IDENTITY_LOST");
                }
                let named=unsafe {named.assume_init()};
                let file=open_at(&held.file,path,true)?;let m=stat(&file)?;
                if named.st_dev as u64!=m.dev()||named.st_ino as u64!=m.ino()
                    ||named.st_mode as u32&libc::S_IFMT as u32!=libc::S_IFDIR as u32 {
                    fail!(ESTALE,"BIRTH_CREATED_IDENTITY_LOST");
                }
                let directory=Directory::capture(file,Some(parent.clone()),true,self.protection)?;
                // Only this own successful mkdir permits observing the parent's
                // new link count. Never assume directory nlink==2 (APFS differs).
                held.current(&held.file,self.protection,false)?;
                let links=stat(&held.file)?.nlink();
                Ok((directory,links))
            })();
            match bound {
                Ok((directory,links))=>{
                    self.dirs.get_mut(&parent).expect("held parent").links=links;
                    self.dirs.insert(path.to_owned(),directory);Ok(())
                },
                Err(error)=>Err(error),
            }
        };
        self.boundary(operation,check,observed)?;
        self.sync_path(path,check,observed,sync)?;self.sync_path(&parent,check,observed,sync)
    }
    fn begin_file(&mut self,path:&Path,mode:u32,access:i32,full:bool,
        check:&mut impl FnMut()->Vec<EnclaveError>,observed:&mut Vec<EnclaveError>)->EnclaveResult<CreatedFile> {
        self.content_boundary(Ok(()),full,check,observed)?;
        let parent=path.parent().ok_or_else(||err!(EINVAL,"BIRTH_PATH"))?.to_owned();
        let held=&self.dirs.get(&parent).ok_or_else(||err!(EINVAL,"BIRTH_PARENT_NOT_HELD"))?.file;
        let leaf=name(path)?;
        self.progress.attempted.push(path.to_owned());self.progress.uncertain_effects=true;
        let fd=unsafe {libc::openat(held.as_raw_fd(),leaf.as_ptr(),access|libc::O_CREAT|libc::O_EXCL
            |libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC,mode as libc::c_uint)};
        if fd<0 {
            let error=if std::io::Error::last_os_error().raw_os_error()==Some(libc::EEXIST) {
                self.progress.existing_names.push(path.to_owned());err!(EALREADY,"BIRTH_ALREADY_EXISTS")
            }else{err!(EIO,"BIRTH_CREATE_UNCERTAIN")};
            return self.content_boundary(Err(error),full,check,observed);
        }
        self.progress.created_files.push(path.to_owned());
        let file=unsafe {File::from_raw_fd(fd)};let initial=stat(&file)?;
        // No callback or path-owner adoption between O_EXCL and its original
        // named identity binding. Only this success updates own parent nlinks.
        original_file(&file,held,path,&initial,self.protection,(initial.uid(),initial.gid()),
            initial.mode()&0o7777,0,access)?;
        self.parent_links_after_own_creation(&parent)?;
        self.content_boundary(Ok(()),full,&mut ||{
            let mut result=check();result.extend(errors([original_file(&file,&self.dirs[&parent].file,
                path,&initial,self.protection,(initial.uid(),initial.gid()),initial.mode()&0o7777,0,access)]));result
        },observed)?;
        let protection=if !initial.is_file()||initial.uid()!=self.protection.owner.0||initial.nlink()!=1
            ||initial.len()!=0||initial.mode()&0o077!=0&&mode==0o600 {
            Err(err!(EACCES,"BIRTH_SEED_PROTECTION"))
        }else if unsafe {libc::fchown(file.as_raw_fd(),self.protection.owner.0,self.protection.owner.1)}!=0
            ||unsafe {libc::fchmod(file.as_raw_fd(),mode as libc::mode_t)}!=0 {
            Err(err!(EACCES,"BIRTH_SEED_PROTECTION"))
        }else{Ok(())};
        let created=CreatedFile {file,initial,path:path.to_owned(),parent,mode,access};
        self.active_boundary(protection,&created,0,full,check,observed)?;Ok(created)
    }
    fn finish_file(&mut self,created:CreatedFile,bytes:Vec<u8>,streamed:Option<StreamedContent>,full:bool,
        check:&mut impl FnMut()->Vec<EnclaveError>,observed:&mut Vec<EnclaveError>,
        sync:&mut impl FnMut(&File)->EnclaveResult<()>)->EnclaveResult<()> {
        let length=streamed.as_ref().map_or(bytes.len() as u64,|s|s.length);
        self.active_boundary(Ok(()),&created,length,full,check,observed)?;
        let m=stat(&created.file)?;
        let seed=SeedFile {file:created.file,stamp:FileStamp::of(&m),bytes,access:created.access,streamed};
        // Whole same-FD content readback always runs at sealing, even when
        // intermediate boundaries check completed payload metadata only.
        let readback=seed.current(&self.dirs[&created.parent].file,&created.path,self.protection);
        self.content_boundary(readback,full,check,observed)?;
        self.files.insert(created.path.clone(),seed);
        for path in [&created.path,&created.parent] {
            self.content_boundary(Ok(()),full,check,observed)?;
            let file=if let Some(d)=self.dirs.get(path){&d.file}else{&self.files[path].file};
            let synced=sync(file);if synced.is_ok(){self.progress.synced.push(path.to_owned());}
            self.content_boundary(synced,full,check,observed)?;
        }
        self.seal_file_readonly(&created.path,full,check,observed)
    }
    /// Drop the original writer only after a real nofollow readonly reopen is
    /// bound to the SAME stamp, original name and complete exact/digest bytes.
    /// No inode metadata changes, pathname adoption or writer restoration.
    fn seal_file_readonly(&mut self,path:&Path,full:bool,
        check:&mut impl FnMut()->Vec<EnclaveError>,observed:&mut Vec<EnclaveError>)->EnclaveResult<()> {
        let mut candidate=None;
        let operation=(|| {
            if self.poisoned {fail!(EACCES,"BIRTH_OWNER_POISONED");}
            self.content_boundary(Ok(()),full,check,observed)?;
            let seed=self.files.get(path).ok_or_else(||err!(EINVAL,"BIRTH_READONLY_ORIGINAL_REQUIRED"))?;
            let parent=path.parent().and_then(|p|self.dirs.get(p))
                .ok_or_else(||err!(EACCES,"BIRTH_PARENT_NOT_HELD"))?;
            self.content_boundary(seed.current(&parent.file,path,self.protection),full,check,observed)?;
            if seed.access==libc::O_RDONLY {return Ok(());}
            if seed.access!=libc::O_RDWR {fail!(EACCES,"BIRTH_READONLY_WRITER_FLAGS");}
            // The original writer remains retained in self.files throughout
            // all candidate opens/reads/guard checks. Reopen never grants birth.
            candidate=Some(self.content_boundary(open_at(&parent.file,path,false),full,check,observed)?);
            let readonly=candidate.as_ref().expect("actual readonly reopen");
            let gates=errors([seed.current(&parent.file,path,self.protection),
                seed.current_on(readonly,libc::O_RDONLY,&parent.file,path,self.protection,true)]);
            let binding=first(&gates);observed.extend(gates);
            self.content_boundary(binding,full,check,observed)?;
            // Recheck candidate/original metadata, content and flags AFTER the
            // last guard callbacks too, immediately before changing ownership.
            let gates=errors([seed.current(&parent.file,path,self.protection),
                seed.current_on(readonly,libc::O_RDONLY,&parent.file,path,self.protection,true)]);
            let binding=first(&gates);observed.extend(gates);binding?;
            let seed=self.files.get_mut(path).expect("same retained original seed");
            let writer=std::mem::replace(&mut seed.file,candidate.take().expect("verified readonly reopen"));
            seed.access=libc::O_RDONLY;
            drop(writer);
            // A refusal after this point leaves the readonly original held.
            // The final gates below never restore or reacquire a writer.
            let seed=&self.files[path];let parent=&self.dirs[path.parent().expect("held seed parent")];
            self.content_boundary(seed.current(&parent.file,path,self.protection),full,check,observed)
        })();
        // Even on refusal evaluate independent full current-file/candidate
        // gates and all guard/original-state gates. Other completed streams
        // keep the caller's full-vs-metadata mode: no quadratic payload reads.
        let mut finals=self.checks_with_content(check,full);
        if let Some(seed)=self.files.get(path) {
            if let Some(parent)=path.parent().and_then(|p|self.dirs.get(p)) {
                finals.extend(errors([seed.current(&parent.file,path,self.protection)]));
                if let Some(readonly)=&candidate {
                    finals.extend(errors([seed.current_on(readonly,libc::O_RDONLY,
                        &parent.file,path,self.protection,true)]));
                }
            }else{finals.push(err!(EACCES,"BIRTH_PARENT_NOT_HELD"));}
        }else{finals.push(err!(EINVAL,"BIRTH_READONLY_ORIGINAL_REQUIRED"));}
        finals.extend(self.checks_with_content(check,full));
        let binding=first(&finals);observed.extend(finals);
        let result=operation.and(binding);
        if result.is_err(){self.poisoned=true;}result
    }
    fn create_file(&mut self,path:&Path,bytes:&[u8],mode:u32,check:&mut impl FnMut()->Vec<EnclaveError>,
        observed:&mut Vec<EnclaveError>,sync:&mut impl FnMut(&File)->EnclaveResult<()>)->EnclaveResult<()> {
        let access=if bytes.is_empty(){libc::O_RDONLY}else{libc::O_RDWR};
        let mut created=self.begin_file(path,mode,access,true,check,observed)?;
        let written=created.file.write_all(bytes).map_err(|_|err!(EIO,"BIRTH_SEED_WRITE_UNCERTAIN"));
        self.active_boundary(written,&created,bytes.len() as u64,true,check,observed)?;
        self.finish_file(created,bytes.to_owned(),None,true,check,observed,sync)
    }
    fn create_file_from_source(&mut self,path:&Path,
        sources:&mut super::target_birth_inputs::UnadmittedBirthSources,index:usize,
        expected_size:u64,expected_sha256:&str,check:&mut impl FnMut()->Vec<EnclaveError>,
        observed:&mut Vec<EnclaveError>,sync:&mut impl FnMut(&File)->EnclaveResult<()>)->EnclaveResult<()> {
        if self.private_load.is_some(){fail!(EACCES,"BIRTH_STAGE_AFTER_PRIVATE_LOAD");}
        if expected_size==0||expected_size>512*1024*1024
            ||sources.size(index)!=Some(expected_size)||sources.sha256(index)!=Some(expected_sha256) {
            fail!(ESTALE,"BIRTH_STAGE_SOURCE_BINDING");
        }
        let mut created=self.begin_file(path,0o600,libc::O_RDWR,false,check,observed)?;
        let mut buffer=[0;64*1024];let mut hash=Sha256::new();let mut offset=0u64;
        while offset<expected_size {
            self.active_boundary(Ok(()),&created,offset,false,check,observed)?;
            let wanted=(expected_size-offset).min(buffer.len() as u64) as usize;
            let read=sources.read_chunk(index,offset,&mut buffer[..wanted]);
            let count=self.active_boundary(read,&created,offset,false,check,observed)?;
            if count!=wanted {fail!(ESTALE,"BIRTH_STAGE_SOURCE_LENGTH");}
            hash.update(&buffer[..count]);
            let written=created.file.write_all(&buffer[..count]).map_err(|_|err!(EIO,"BIRTH_STREAM_WRITE_UNCERTAIN"));
            offset+=count as u64;
            self.active_boundary(written,&created,offset,false,check,observed)?;
        }
        if hex::encode(hash.finalize())!=expected_sha256 {fail!(ESTALE,"BIRTH_STAGE_SOURCE_DIGEST");}
        self.finish_file(created,Vec::new(),Some(StreamedContent {length:expected_size,
            sha256:expected_sha256.to_owned()}),false,check,observed,sync)
    }
    /// Typed original-owner staging copy only. The consuming native excluded
    /// birth caller closes destinations and keeps actual authorities/EX. No
    /// pathname reopen, dup, source FD or general reader capability is used.
    /// Metadata chunk gates still run actual private-load currentness/expiry;
    /// full source and complete-candidate gates surround every complete copy.
    fn create_file_from_birth_stage(&mut self,source:&Path,destination:&Path,
        expected_size:u64,expected_sha256:&str,mode:u32,check:&mut impl FnMut()->Vec<EnclaveError>,
        observed:&mut Vec<EnclaveError>,sync:&mut impl FnMut(&File)->EnclaveResult<()>)->EnclaveResult<()> {
        if self.poisoned {fail!(EACCES,"BIRTH_OWNER_POISONED");}
        if !matches!(mode,0o644|0o755)||expected_size==0||expected_size>512*1024*1024 {
            fail!(EACCES,"BIRTH_PAYLOAD_COPY_BOUND");
        }
        below(source,&self.plan.target.layout.staging_root)?;below(destination,&self.plan.root)?;
        if overlaps(destination,&self.plan.target.layout.staging_root)? {
            fail!(EACCES,"BIRTH_PAYLOAD_STAGING_DESTINATION");
        }
        let root=self.dirs.get(&self.plan.root).ok_or_else(||err!(EACCES,"BIRTH_PAYLOAD_PRIVATE_ROOT_REQUIRED"))?;
        if !root.private {fail!(EACCES,"BIRTH_PAYLOAD_PRIVATE_ROOT_REQUIRED");}
        self.boundary(Ok(()),check,observed)?;
        let source_stamp={
            let seed=self.files.get(source).ok_or_else(||err!(EACCES,"BIRTH_PAYLOAD_ORIGINAL_SOURCE_REQUIRED"))?;
            if seed.access!=libc::O_RDONLY||seed.stamp.len!=expected_size {
                fail!(EACCES,"BIRTH_PAYLOAD_READONLY_SOURCE_REQUIRED");
            }
            let parent=&self.dirs.get(source.parent().ok_or_else(||err!(EINVAL,"BIRTH_PAYLOAD_SOURCE_PATH"))?)
                .ok_or_else(||err!(EACCES,"BIRTH_PAYLOAD_ORIGINAL_PARENT_REQUIRED"))?.file;
            seed.current(parent,source,self.protection)?;
            if file_sha256(&seed.file,expected_size)?!=expected_sha256 {fail!(ESTALE,"BIRTH_PAYLOAD_SOURCE_DIGEST");}
            seed.current(parent,source,self.protection)?;FileStamp::of(&stat(&seed.file)?)
        };
        self.boundary(Ok(()),check,observed)?;
        let mut created=self.begin_file(destination,mode,libc::O_RDWR,false,check,observed)?;
        let mut buffer=[0;64*1024];let mut hash=Sha256::new();let mut offset=0u64;
        while offset<expected_size {
            self.active_boundary(Ok(()),&created,offset,false,check,observed)?;
            let wanted=(expected_size-offset).min(buffer.len() as u64) as usize;
            let read=(|| {
                let seed=self.files.get(source).ok_or_else(||err!(ESTALE,"BIRTH_PAYLOAD_ORIGINAL_SOURCE_REQUIRED"))?;
                let parent=&self.dirs.get(source.parent().expect("validated source parent"))
                    .ok_or_else(||err!(EACCES,"BIRTH_PAYLOAD_ORIGINAL_PARENT_REQUIRED"))?.file;
                seed.current_with_content(parent,source,self.protection,false)?;
                if seed.stamp!=source_stamp {fail!(ESTALE,"BIRTH_PAYLOAD_SOURCE_CHANGED");}
                let mut done=0;
                while done<wanted {
                    let count=loop {match seed.file.read_at(&mut buffer[done..wanted],offset+done as u64) {
                        Err(e) if e.kind()==std::io::ErrorKind::Interrupted=>continue,
                        result=>break result.map_err(|_|err!(EIO,"BIRTH_PAYLOAD_SOURCE_READ"))?,
                    }};
                    if count==0 {fail!(ESTALE,"BIRTH_PAYLOAD_SOURCE_TRUNCATED");}done+=count;
                }
                seed.current_with_content(parent,source,self.protection,false)?;Ok(done)
            })();
            let count=self.active_boundary(read,&created,offset,false,check,observed)?;
            if count!=wanted {fail!(ESTALE,"BIRTH_PAYLOAD_SOURCE_TRUNCATED");}
            hash.update(&buffer[..count]);
            let written=created.file.write_all(&buffer[..count]).map_err(|_|err!(EIO,"BIRTH_PAYLOAD_WRITE_UNCERTAIN"));
            offset+=count as u64;
            self.active_boundary(written,&created,offset,false,check,observed)?;
        }
        if hex::encode(hash.finalize())!=expected_sha256 {fail!(ESTALE,"BIRTH_PAYLOAD_SOURCE_DIGEST");}
        let source_check=(|| {
            let seed=self.files.get(source).ok_or_else(||err!(ESTALE,"BIRTH_PAYLOAD_ORIGINAL_SOURCE_REQUIRED"))?;
            let parent=&self.dirs.get(source.parent().expect("validated source parent"))
                    .ok_or_else(||err!(EACCES,"BIRTH_PAYLOAD_ORIGINAL_PARENT_REQUIRED"))?.file;
            seed.current(parent,source,self.protection)?;
            if seed.stamp!=source_stamp||file_sha256(&seed.file,expected_size)?!=expected_sha256 {
                fail!(ESTALE,"BIRTH_PAYLOAD_SOURCE_CHANGED");
            }
            seed.current(parent,source,self.protection)
        })();
        self.active_boundary(source_check,&created,offset,false,check,observed)?;
        self.finish_file(created,Vec::new(),Some(StreamedContent {length:expected_size,
            sha256:expected_sha256.to_owned()}),false,check,observed,sync)
    }
    fn seeds(&mut self,check:&mut impl FnMut()->Vec<EnclaveError>,observed:&mut Vec<EnclaveError>,
        sync:&mut impl FnMut(&File)->EnclaveResult<()>)->EnclaveResult<()> {
        if self.progress.seeds_complete {fail!(EALREADY,"BIRTH_SEEDS_ALREADY_PREPARED");}
        for path in self.plan.seed_dirs.clone(){self.create_directory(&path,check,observed,sync)?;}
        self.create_file(&self.plan.descriptor.clone(),&self.plan.bytes.clone(),0o644,check,observed,sync)?;
        self.create_file(&self.plan.target.layout.support_root.join(STARTUP_LIFETIME_LEAF),b"",0o644,check,observed,sync)?;
        self.progress.seeds_complete=true;Ok(())
    }
    fn revalidate(&mut self,check:&mut impl FnMut()->Vec<EnclaveError>)->Result<BirthProgress,BirthFailure> {
        self.progress.operation="revalidate_birth";
        let final_errors=self.checks(check);
        let operation=if self.poisoned{Err(err!(EACCES,"BIRTH_OWNER_POISONED"))}else{Ok(())};
        let result=outcome(&mut self.progress,operation,Vec::new(),final_errors);
        if result.is_err(){self.poisoned=true;}result.map(|()|self.progress.clone())
    }
    fn prepare_seeds(&mut self,check:&mut impl FnMut()->Vec<EnclaveError>,
        sync:&mut impl FnMut(&File)->EnclaveResult<()>)->Result<BirthProgress,BirthFailure> {
        self.progress.operation="prepare_inert_seeds";
        let mut boundary_errors=Vec::new();
        let operation=if self.poisoned{Err(err!(EACCES,"BIRTH_OWNER_POISONED"))}else {
            self.seeds(check,&mut boundary_errors,sync)
        };
        let final_errors=self.checks(check);
        let result=outcome(&mut self.progress,operation,boundary_errors,final_errors);
        if result.is_err(){self.poisoned=true;}else{self.progress.uncertain_effects=false;}
        result.map(|()|self.progress.clone())
    }
    fn prepare_denial(&mut self,raw_inventory:&[u8],check:&mut impl FnMut()->Vec<EnclaveError>,
        sync:&mut impl FnMut(&File)->EnclaveResult<()>)->Result<BirthProgress,BirthFailure> {
        self.progress.operation="prepare_startup_denial";let mut boundary_errors=Vec::new();
        let operation=(|| {
            if self.poisoned {fail!(EACCES,"BIRTH_OWNER_POISONED");}
            self.boundary(Ok(()),check,&mut boundary_errors)?;
            if !self.progress.seeds_complete||!self.files.contains_key(&self.plan.descriptor)
                ||!self.files.contains_key(&self.plan.target.layout.support_root.join(STARTUP_LIFETIME_LEAF)) {
                fail!(EACCES,"BIRTH_PENDING_SEEDS_REQUIRED");
            }
            if self.pending.is_some() {fail!(EALREADY,"BIRTH_PENDING_ALREADY_PREPARED");}
            let pending=PendingInventory::new(&self.plan,raw_inventory)?;
            let bytes=pending.marker_bytes(&self.plan)?;
            self.progress.pending_descriptor_sha256=Some(pending.descriptor_sha256.clone());
            self.progress.pending_inventory_sha256=Some(pending.inventory_sha256.clone());
            self.pending=Some(pending);
            let path=self.plan.target.layout.support_root.join(UPGRADE_INHIBITION_LEAF);
            // Actual O_EXCL descriptor is retained in files after all own-file
            // metadata/write/sync/name checks, never reconstructed from data.
            // Empty/partial final name already denies after a crash. No clear,
            // repair, removal, resume or activation operation exists here.
            self.create_file(&path,&bytes,0o600,check,&mut boundary_errors,sync)?;
            self.progress.denial_prepared=true;Ok(())
        })();
        let final_errors=self.checks(check);
        let result=outcome(&mut self.progress,operation,boundary_errors,final_errors);
        if result.is_err(){self.poisoned=true;}else{self.progress.uncertain_effects=false;}
        result.map(|()|self.progress.clone())
    }
}

fn require_native_root()->EnclaveResult<()> {
    if !cfg!(target_os="macos")||unsafe {libc::geteuid()}!=0 {fail!(EACCES,"BIRTH_NATIVE_ROOT_REQUIRED");}Ok(())
}
/// Non-cloneable, non-serializable native owner. No FD, guard, callback, checked
/// selection or authority export. A failed established check permanently
/// poisons it while retaining its descriptors and SAME borrowed guard.
pub(crate) struct NativeDedicatedBirth<'guard> {state:BirthState,guard:&'guard mut HostMaintenanceGuard,
    directory_events:directory_event::DirectoryEventLedger,denial_removal:denial_handoff::DenialRemovalLedger,
    live_directories:live_directories::LiveDirectoryLedger}
impl NativeDedicatedBirth<'_> {
    pub(crate) fn target(&self)->&DeploymentTarget {&self.state.plan.target}
    pub(crate) fn descriptor_path(&self)->&Path {&self.state.plan.descriptor}
    pub(crate) fn descriptor_bytes(&self)->&[u8] {&self.state.plan.bytes}
    pub(crate) fn progress(&self)->&BirthProgress {&self.state.progress}
    pub(crate) fn assert_current(&mut self)->Result<BirthProgress,BirthFailure> {
        self.state.revalidate(&mut ||errors([require_native_root(),self.guard.assert_held()]))
    }
    pub(crate) fn prepare_inert_seeds(&mut self)->Result<BirthProgress,BirthFailure> {
        self.state.prepare_seeds(&mut ||errors([require_native_root(),self.guard.assert_held()]),
            &mut enclave_core::fsutil::full_fsync)
    }
    /// Durable negative startup state only. Supplied public inventory is held
    /// and bound, never approved/imported/selected or exposed as a capability.
    pub(crate) fn prepare_startup_denial(&mut self,raw_inventory:&[u8])->Result<BirthProgress,BirthFailure> {
        self.state.prepare_denial(raw_inventory,&mut ||errors([require_native_root(),self.guard.assert_held()]),
            &mut enclave_core::fsutil::full_fsync)
    }
}

/// A refused native begin retains the SAME guard and every original actually
/// bound into the partial BirthState. None is used only before state exists.
/// No state/FD/guard extraction, retry, adoption or resume API is exposed.
#[must_use="retain actual partial birth and SAME guard through terminal handling"]
pub(crate) struct NativeBirthBeginFailure<'guard> {
    pub(crate) error:EnclaveError,
    pub(crate) boundary_errors:Vec<EnclaveError>,pub(crate) final_errors:Vec<EnclaveError>,
    pub(crate) progress:BirthProgress,
    _state:Option<BirthState>,_guard:&'guard mut HostMaintenanceGuard,
}
impl std::fmt::Debug for NativeBirthBeginFailure<'_> {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        f.debug_struct("NativeBirthBeginFailure").field("reason",&self.error.reason)
            .field("boundary_error_count",&self.boundary_errors.len()).field("final_error_count",&self.final_errors.len())
            .field("actual_state_retained",&self._state.is_some()).finish_non_exhaustive()
    }
}
fn retain_begin_refusal<'guard>(state:Option<BirthState>,guard:&'guard mut HostMaintenanceGuard,
    failure:BirthFailure)->NativeBirthBeginFailure<'guard> {
    NativeBirthBeginFailure {error:failure.error,boundary_errors:failure.boundary_errors,final_errors:failure.final_errors,
        progress:failure.progress,_state:state,_guard:guard}
}

/// Allocate an unpredictable 128-bit leaf under an EXISTING protected parent.
/// Never retry/adopt an existing name. Every template reference is rebased as a
/// strict descendant; actual target/job/Mach identities derive from this nonce.
pub(crate) fn begin_dedicated_birth<'guard>(template:&DeploymentTarget,template_root:&Path,
    allocator_parent:&Path,guard:&'guard mut HostMaintenanceGuard)->Result<NativeDedicatedBirth<'guard>,NativeBirthBeginFailure<'guard>> {
    let mut progress=BirthProgress::new();
    let initial=errors([require_native_root(),guard.assert_held()]);
    if let Err(error)=first(&initial) {
        let finals=errors([require_native_root(),guard.assert_held()]);
        let failure=outcome::<()>(&mut progress,Err(error),initial,finals).unwrap_err();
        return Err(retain_begin_refusal(None,guard,failure));
    }
    let mut nonce=[0;16];enclave_core::rng::fill(&mut nonce);
    let plan=BirthPlan::build(template,template_root,allocator_parent,&nonce);
    let plan=match plan {Ok(plan)=>plan,Err(error)=>{
        let finals=errors([require_native_root(),guard.assert_held()]);
        let failure=outcome::<()>(&mut progress,Err(error),Vec::new(),finals).unwrap_err();
        return Err(retain_begin_refusal(None,guard,failure));
    }};
    progress.root=Some(plan.root.clone());progress.descriptor=Some(plan.descriptor.clone());
    progress.target_id=Some(plan.target.target_id.clone());
    let parent=plan.root.parent().expect("planned root parent").to_owned();
    let root=plan.root.clone();
    let mut state=BirthState {plan,dirs:BTreeMap::new(),files:BTreeMap::new(),
        protection:Protection {owner:(0,0),native_acl:true},progress,poisoned:false,pending:None,private_load:None};
    let mut boundary_errors=Vec::new();
    let operation=(|| {
        let opened=state.open_ancestry(&parent);
        state.boundary(opened,&mut ||errors([require_native_root(),guard.assert_held()]),&mut boundary_errors)?;
        state.create_directory(&root,&mut ||errors([require_native_root(),guard.assert_held()]),
            &mut boundary_errors,&mut enclave_core::fsutil::full_fsync)
    })();
    let final_errors=state.checks(&mut ||errors([require_native_root(),guard.assert_held()]));
    if let Err(failure)=outcome(&mut state.progress,operation,boundary_errors,final_errors) {
        state.poisoned=true;
        return Err(retain_begin_refusal(Some(state),guard,failure));
    }
    state.progress.uncertain_effects=false;
    Ok(NativeDedicatedBirth {state,guard,directory_events:directory_event::DirectoryEventLedger::new(),denial_removal:denial_handoff::DenialRemovalLedger::new(),live_directories:live_directories::LiveDirectoryLedger::new()})
}

#[cfg(test)]
#[path="target_birth_tests.rs"]
mod tests;

#[cfg(test)]
#[path="target_birth_readonly_tests.rs"]
mod readonly_tests;
