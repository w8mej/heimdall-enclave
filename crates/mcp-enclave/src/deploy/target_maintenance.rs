//! Cooperative host-wide deployment exclusion, never target inactivity authority.
//!
//! Every cooperating deployment operation must hold the same guard throughout
//! observation AND subsequent mutation. Existing installers do not yet follow
//! this protocol. Unmanaged processes, same-UID peers and hostile root remain
//! outside it; possession cannot authorize payload publication or installation.
//!
//! The native constructor has no deployment/configuration/path inputs. Darwin's
//! fixed /var alias is handled by opening /private/var/run directly, never by
//! following arbitrary symlinks. The persistent lock is never removed on drop:
//! unlinking it would let another caller lock a different inode concurrently.
//!
//! New files are prepared privately and published with create-only linkat. A
//! crash between link and unlink can leave nlink=2; later callers refuse it and
//! do not repair it. Recovery requires separately reviewed exact-inode cleanup
//! after all possible holders are excluded. No automatic restore is supplied.

use std::{ffi::CString, fs::{File, Metadata}, io, os::{fd::{AsRawFd, FromRawFd},
    unix::{ffi::OsStrExt, fs::MetadataExt}}, path::{Component, Path}};
use enclave_core::{error::EnclaveResult, err, fail};
use super::target_activity::MaintenanceExclusion;

const LOCK_LEAF:&str="depot-deployment-maintenance.lock";
const NATIVE_PARENT:&str="/private/var/run";
#[derive(Clone, Copy)]
struct Owner {uid:u32,gid:u32}
impl Owner {const ROOT:Self=Self {uid:0,gid:0};}

fn require_root(uid:u32)->EnclaveResult<()> {
    if uid!=0 {fail!(EACCES,"MAINTENANCE_ROOT_REQUIRED");}Ok(())
}
fn protected_directory(m:&Metadata,owner:Owner)->bool {
    // Production owner is always root. The alternate owner is private test
    // construction only; it permits protected root-owned fixture ancestors.
    m.is_dir() && (m.uid()==0 || m.uid()==owner.uid) && m.mode()&0o022==0
}
fn protected_lock(m:&Metadata,owner:Owner)->bool {
    m.is_file() && m.uid()==owner.uid && m.gid()==owner.gid
        && m.mode()&0o7777==0o600 && m.nlink()==1 && m.len()==0
}
fn same_inode(a:&Metadata,b:&Metadata)->bool {a.dev()==b.dev() && a.ino()==b.ino()}
#[derive(PartialEq, Eq)]
struct Stamp {dev:u64,ino:u64,uid:u32,gid:u32,mode:u32,nlink:u64,len:u64,
    modified:(i64,i64),changed:(i64,i64)}
impl Stamp {
    fn of(m:&Metadata)->Self {Self {dev:m.dev(),ino:m.ino(),uid:m.uid(),gid:m.gid(),mode:m.mode(),
        nlink:m.nlink(),len:m.len(),modified:(m.mtime(),m.mtime_nsec()),changed:(m.ctime(),m.ctime_nsec())}}
}
fn name(bytes:&[u8])->EnclaveResult<CString> {
    CString::new(bytes).map_err(|_|err!(EINVAL,"MAINTENANCE_PATH"))
}
fn from_fd(fd:i32)->EnclaveResult<File> {
    if fd<0 {fail!(EACCES,"MAINTENANCE_PROTECTION");}Ok(unsafe {File::from_raw_fd(fd)})
}
fn stat(file:&File)->EnclaveResult<Metadata> {file.metadata().map_err(|_|err!(EIO,"MAINTENANCE_STAT"))}
fn open_named(parent:&File,leaf:&CString,directory:bool)->EnclaveResult<File> {
    let flags=libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC
        |if directory {libc::O_RDONLY|libc::O_DIRECTORY}else{libc::O_RDWR};
    from_fd(unsafe {libc::openat(parent.as_raw_fd(),leaf.as_ptr(),flags)})
}
#[derive(PartialEq,Eq)]
struct DirectoryStamp {identity:(u64,u64),ownership:(u32,u32),mode:u32}
impl DirectoryStamp {
    fn of(m:&Metadata)->Self {Self {identity:(m.dev(),m.ino()),ownership:(m.uid(),m.gid()),mode:m.mode()}}
}
struct Ancestor {file:File,name:Option<CString>,stamp:DirectoryStamp}
impl Ancestor {
    fn new(file:File,name:Option<CString>,owner:Owner)->EnclaveResult<Self> {
        let metadata=stat(&file)?;
        if !protected_directory(&metadata,owner) {fail!(EACCES,"MAINTENANCE_PROTECTION");}
        Ok(Self {file,name,stamp:DirectoryStamp::of(&metadata)})
    }
}
struct Ancestry {nodes:Vec<Ancestor>,owner:Owner}
impl Ancestry {
    fn append(&mut self,leaf:CString)->EnclaveResult<()> {
        let file=open_named(self.parent(),&leaf,true)?;
        self.nodes.push(Ancestor::new(file,Some(leaf),self.owner)?);Ok(())
    }
    fn open(path:&Path,owner:Owner)->EnclaveResult<Self> {
        if !path.is_absolute() {fail!(EINVAL,"MAINTENANCE_PATH");}
        let root=from_fd(unsafe {libc::open(b"/\0".as_ptr().cast(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)})?;
        let mut result=Self {nodes:vec![Ancestor::new(root,None,owner)?],owner};
        for component in path.components() {match component {
            Component::RootDir=>(),
            Component::Normal(part)=>result.append(name(part.as_bytes())?)?,
            _=>fail!(EINVAL,"MAINTENANCE_PATH"),
        }}
        result.current()?;Ok(result)
    }
    #[cfg(test)]
    fn fixture(root:&Path,children:&[&str],owner:Owner)->EnclaveResult<Self> {
        // Test-only synthetic trust anchor; fixture ancestors may live under
        // an ordinary writable build directory. Production always starts at /.
        let root=name(root.as_os_str().as_bytes())?;
        let file=from_fd(unsafe {libc::open(root.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)})?;
        let mut result=Self {nodes:vec![Ancestor::new(file,None,owner)?],owner};
        for child in children {result.append(name(child.as_bytes())?)?;}
        result.current()?;Ok(result)
    }
    fn parent(&self)->&File {&self.nodes.last().expect("root node").file}
    fn current(&self)->EnclaveResult<()> {
        for (index,node) in self.nodes.iter().enumerate() {
            let held=stat(&node.file)?;
            if !protected_directory(&held,self.owner) || node.stamp!=DirectoryStamp::of(&held) {
                fail!(ESTALE,"MAINTENANCE_ANCESTRY_CHANGED");
            }
            if let Some(leaf)=&node.name {
                let named=open_named(&self.nodes[index-1].file,leaf,true)?;
                let fresh=stat(&named)?;
                if !protected_directory(&fresh,self.owner) || node.stamp!=DirectoryStamp::of(&fresh) {
                    fail!(ESTALE,"MAINTENANCE_ANCESTRY_CHANGED");
                }
            }
        }Ok(())
    }
}

struct Prepared<'a> {file:File,parent:&'a File,leaf:CString,linked:bool}
impl Prepared<'_> {
    fn unlink_own_temporary(&mut self)->EnclaveResult<()> {
        if !self.linked {return Ok(());}
        let named=open_named(self.parent,&self.leaf,false)?;
        if !same_inode(&stat(&named)?,&stat(&self.file)?) {fail!(ESTALE,"MAINTENANCE_TEMP_CHANGED");}
        if unsafe {libc::unlinkat(self.parent.as_raw_fd(),self.leaf.as_ptr(),0)}!=0 {
            fail!(EIO,"MAINTENANCE_TEMP_CLEANUP_UNCERTAIN");
        }
        self.linked=false;Ok(())
    }
}
impl Drop for Prepared<'_> {
    fn drop(&mut self) {let _=self.unlink_own_temporary();}
}
fn prepare(parent:&File,owner:Owner)->EnclaveResult<Prepared<'_>> {
    let leaf=name(format!(".depot-maintenance-{}.tmp",hex::encode(enclave_core::rng::bytes32())).as_bytes())?;
    let file=from_fd(unsafe {libc::openat(parent.as_raw_fd(),leaf.as_ptr(),
        libc::O_RDWR|libc::O_CREAT|libc::O_EXCL|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC,0o600)})?;
    let prepared=Prepared {file,parent,leaf,linked:true};
    // Mutations apply only to our own O_EXCL temporary, never an existing lock.
    if unsafe {libc::fchown(prepared.file.as_raw_fd(),owner.uid,owner.gid)}!=0
        || unsafe {libc::fchmod(prepared.file.as_raw_fd(),0o600)}!=0
        || !protected_lock(&stat(&prepared.file)?,owner) {
        fail!(EACCES,"MAINTENANCE_PROTECTION");
    }
    prepared.file.sync_all().map_err(|_|err!(EIO,"MAINTENANCE_PUBLICATION_UNCERTAIN"))?;
    Ok(prepared)
}
fn existing_or_publish(ancestry:&Ancestry)->EnclaveResult<File> {
    let parent=ancestry.parent();let leaf=name(LOCK_LEAF.as_bytes())?;
    let fd=unsafe {libc::openat(parent.as_raw_fd(),leaf.as_ptr(),libc::O_RDWR|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)};
    if fd>=0 {return from_fd(fd);}
    if io::Error::last_os_error().kind()!=io::ErrorKind::NotFound {fail!(EACCES,"MAINTENANCE_PROTECTION");}
    let mut prepared=prepare(parent,ancestry.owner)?;
    ancestry.current()?;
    let linked=unsafe {libc::linkat(parent.as_raw_fd(),prepared.leaf.as_ptr(),parent.as_raw_fd(),leaf.as_ptr(),0)};
    if linked!=0 && io::Error::last_os_error().kind()!=io::ErrorKind::AlreadyExists {
        fail!(EIO,"MAINTENANCE_PUBLICATION_UNCERTAIN");
    }
    // A concurrent creator may have won. Remove only our exact temporary;
    // open/validate the winner without truncation, repair or unlinking it.
    prepared.unlink_own_temporary()?;
    if linked==0 {parent.sync_all().map_err(|_|err!(EIO,"MAINTENANCE_PUBLICATION_UNCERTAIN"))?;}
    open_named(parent,&leaf,false)
}

/// Non-cloneable/non-serializable guard. Its private FD is never handed out or
/// explicitly unlocked; trusted integration must not duplicate/unlock it. Drop
/// closes it and releases the advisory flock, leaving the persistent name.
pub(crate) struct HostMaintenanceGuard {ancestry:Ancestry,file:File,stamp:Stamp,poisoned:bool}
impl HostMaintenanceGuard {
    /// Fixed native host-wide path, independent of selected state/runtime roots.
    /// No platform fallback and no command/CLI/environment path override.
    pub(crate) fn acquire()->EnclaveResult<Self> {
        #[cfg(target_os="macos")]
        {require_root(unsafe {libc::geteuid()})?;
            Self::acquire_ancestry(Ancestry::open(Path::new(NATIVE_PARENT),Owner::ROOT)?)}
        #[cfg(not(target_os="macos"))]
        {fail!(ENOSYS,"MAINTENANCE_NATIVE_REQUIRED");}
    }
    fn acquire_ancestry(ancestry:Ancestry)->EnclaveResult<Self> {
        let owner=ancestry.owner;
        let file=existing_or_publish(&ancestry)?;
        let metadata=stat(&file)?;
        if !protected_lock(&metadata,owner) {fail!(EACCES,"MAINTENANCE_PROTECTION");}
        let stamp=Stamp::of(&metadata);
        let mut guard=Self {ancestry,file,stamp,poisoned:false};
        guard.current()?;
        if unsafe {libc::flock(guard.file.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)}!=0 {
            let error=io::Error::last_os_error();
            if error.raw_os_error()==Some(libc::EWOULDBLOCK) {fail!(EAGAIN,"MAINTENANCE_BUSY");}
            fail!(EIO,"MAINTENANCE_LOCK_UNCERTAIN");
        }
        guard.assert_held()?;Ok(guard)
    }
    fn current(&self)->EnclaveResult<()> {
        self.ancestry.current()?;
        let held=stat(&self.file)?;
        let named=open_named(self.ancestry.parent(),&name(LOCK_LEAF.as_bytes())?,false)?;
        let fresh=stat(&named)?;
        if !protected_lock(&held,self.ancestry.owner) || !protected_lock(&fresh,self.ancestry.owner)
            || self.stamp!=Stamp::of(&held) || self.stamp!=Stamp::of(&fresh) {
            fail!(ESTALE,"MAINTENANCE_LOCK_CHANGED");
        }
        self.ancestry.current()?;Ok(())
    }
}
impl MaintenanceExclusion for HostMaintenanceGuard {
    fn assert_held(&mut self)->EnclaveResult<()> {
        if self.poisoned {fail!(ESTALE,"MAINTENANCE_GUARD_POISONED");}
        let result=self.current();
        if result.is_err() {self.poisoned=true;}
        result
    }
}

#[cfg(test)]
#[path="target_maintenance_tests.rs"]
mod tests;
