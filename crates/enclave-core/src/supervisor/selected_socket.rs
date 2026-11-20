//! Original selected primary/held socket names. No runtime activation lives here.
//! Failure retains partial objects and poisons this allocation; Drop never unlinks
//! a name, repairs a directory, shuts down a worker's duplicate, or adopts a socket.
use std::{ffi::CString, fs::{File, Metadata}, os::{fd::{AsRawFd, FromRawFd},
    unix::{ffi::OsStrExt, fs::MetadataExt, net::UnixListener}}, path::{Path, PathBuf}, time::Instant};
use crate::{codesign, deployment::{self, CheckedDeploymentTarget, DeploymentRole,
    DeploymentSigningMode}, error::EnclaveResult, Profile, err};
use super::selected_runtime::SelectedRuntime;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role { Primary, Held }
impl Role {
    fn path(self, root: &Path) -> PathBuf {
        match self { Self::Primary => super::socket_path(root), Self::Held => super::held_socket_path(root) }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reason { Native, Context, Lease, Originals, Parent, ParentChanged, Flags, Acl,
    Occupied, NameUnknown, Path, Socket, Bind, NameChanged, Dac, Listen, ListenerChanged,
    Deadline, Duplicate, AlreadyTaken, Incomplete, Poisoned }
type Check<T> = Result<T, Reason>;
fn within(end: Instant) -> Check<()> { if Instant::now() >= end { Err(Reason::Deadline) } else { Ok(()) } }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity { dev: u64, ino: u64, uid: u32, gid: u32, mode: u32 }
impl Identity {
    fn of(m: &Metadata) -> Self { Self { dev:m.dev(), ino:m.ino(), uid:m.uid(), gid:m.gid(), mode:m.mode() } }
    fn named(m: &libc::stat) -> Self { Self { dev:m.st_dev as u64, ino:m.st_ino as u64,
        uid:m.st_uid, gid:m.st_gid, mode:m.st_mode as u32 } }
    fn inode(self) -> (u64,u64) { (self.dev,self.ino) }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stamp { identity: Identity, links:u64, mtime:i64, mtime_ns:i64, ctime:i64, ctime_ns:i64 }
impl Stamp {
    fn named(m: &libc::stat) -> Self { Self { identity:Identity::named(m), links:m.st_nlink as u64,
        mtime:m.st_mtime as i64, mtime_ns:m.st_mtime_nsec as i64,
        ctime:m.st_ctime as i64, ctime_ns:m.st_ctime_nsec as i64 } }
}
enum Context {
    Native(&'static CheckedDeploymentTarget),
    // A private fixture root explicitly does NOT attest system ancestry/ACLs.
    #[cfg(test)]
    Fixture { root:PathBuf, file:File, identity:Identity, gid:u32 },
}
impl Context {
    fn ids(&self) -> (u32,u32) {
        match self { Self::Native(_) => (0,super::CLIENT_GID),
            #[cfg(test)] Self::Fixture { identity,gid,.. } => (identity.uid,*gid) }
    }
    fn current(&self, originals:&mut Option<&mut SelectedRuntime>, end:Instant) -> Check<()> {
        within(end)?;
        match self {
            Self::Native(checked) => {
                native()?;
                let actual=deployment::selected().ok_or(Reason::Context)?;
                if !std::ptr::eq(*checked,actual) { return Err(Reason::Context); }
                shape(actual)?;
                deployment::startup_lease::require_retained_selected_startup_lease(end).map_err(|_|Reason::Lease)?;
                originals.as_deref_mut().ok_or(Reason::Originals)?.require_current(end).map_err(|_|Reason::Originals)?;
            },
            #[cfg(test)] Self::Fixture { root,file,identity,.. } => {
                let actual=file.metadata().map_err(|_|Reason::Parent)?;
                let named=std::fs::symlink_metadata(root).map_err(|_|Reason::Parent)?;
                directory_fd(file)?;
                if Identity::of(&actual)!=*identity || Identity::of(&named)!=*identity
                    || !actual.is_dir() || actual.mode()&0o022!=0 { return Err(Reason::ParentChanged); }
            },
        }
        within(end)
    }
}
fn native() -> Check<()> {
    if !cfg!(target_os="macos") || unsafe {libc::geteuid()}!=0 || !codesign::enforced() { Err(Reason::Native) } else { Ok(()) }
}
fn shape(checked:&CheckedDeploymentTarget) -> Check<()> {
    let t=checked.target();
    if t.role!=DeploymentRole::DedicatedTest || t.profile!=Profile::L2
        || t.signing_identity_mode!=DeploymentSigningMode::LocalPins
        || codesign::signing_mode()!=codesign::SigningMode::LocalPins
        || t.broker.is_some() || !t.shared_read_only_inputs.is_empty() { return Err(Reason::Context); }
    deployment::upgrade::assert_start_allowed(checked).map_err(|_|Reason::Context)
}
fn directory_fd(file:&File) -> Check<()> {
    let flags=unsafe {libc::fcntl(file.as_raw_fd(),libc::F_GETFL)};
    let descriptor=unsafe {libc::fcntl(file.as_raw_fd(),libc::F_GETFD)};
    if flags<0 || flags&libc::O_ACCMODE!=libc::O_RDONLY || flags&libc::O_NONBLOCK==0
        || descriptor<0 || descriptor&libc::FD_CLOEXEC==0 { Err(Reason::Flags) } else { Ok(()) }
}
// Inspect directory ACLs through the original FD, socket ACLs without following
// the leaf. Protected original ancestry plus pre/post identity checks remain
// required: Darwin has no bindat or atomic identity-conditional chmodat.
fn acl(file:Option<&File>, path:Option<&Path>, native_context:bool) -> Check<()> {
    if !native_context { return Ok(()); }
    #[cfg(target_os="macos")]
    {
        use std::ffi::c_void;
        unsafe extern "C" {
            fn acl_get_fd_np(fd:i32,kind:i32)->*mut c_void;
            fn acl_get_link_np(path:*const libc::c_char,kind:i32)->*mut c_void;
            fn acl_valid(acl:*mut c_void)->i32;
            fn acl_get_entry(acl:*mut c_void,id:i32,entry:*mut *mut c_void)->i32;
            fn acl_free(acl:*mut c_void)->i32;
        }
        let name=path.map(|p|CString::new(p.as_os_str().as_bytes()).map_err(|_|Reason::Path)).transpose()?;
        unsafe { *libc::__error()=0; }
        let value=unsafe {match (file,name.as_ref()) {
            (Some(file),None)=>acl_get_fd_np(file.as_raw_fd(),0x100),
            (None,Some(name))=>acl_get_link_np(name.as_ptr(),0x100), _=>return Err(Reason::Acl),
        }};
        if value.is_null() { return if std::io::Error::last_os_error().raw_os_error()==Some(libc::ENOENT) {Ok(())} else {Err(Reason::Acl)}; }
        let valid=unsafe {acl_valid(value)};let mut entry=std::ptr::null_mut();
        let found=unsafe {acl_get_entry(value,0,&mut entry)};
        let errno=std::io::Error::last_os_error().raw_os_error();let freed=unsafe {acl_free(value)};
        if valid!=0 || found!=-1 || errno!=Some(libc::EINVAL) || freed!=0 { return Err(Reason::Acl); }
        Ok(())
    }
    #[cfg(not(target_os="macos"))]
    { let _=(file,path);Err(Reason::Native) }
}
fn named(parent:&File,leaf:&CString) -> Check<libc::stat> {
    let mut value:libc::stat=unsafe {std::mem::zeroed()};
    if unsafe {libc::fstatat(parent.as_raw_fd(),leaf.as_ptr(),&mut value,libc::AT_SYMLINK_NOFOLLOW)}!=0 {
        return Err(Reason::NameUnknown);
    } Ok(value)
}
fn listener_identity(listener:&UnixListener, path:Option<&Path>) -> Check<Identity> {
    let raw=listener.as_raw_fd();let mut metadata:libc::stat=unsafe {std::mem::zeroed()};
    let flags=unsafe {libc::fcntl(raw,libc::F_GETFL)};let descriptor=unsafe {libc::fcntl(raw,libc::F_GETFD)};
    if flags<0 || flags&libc::O_NONBLOCK==0 || descriptor<0 || descriptor&libc::FD_CLOEXEC==0
        || unsafe {libc::fstat(raw,&mut metadata)}!=0 || metadata.st_mode as u32&libc::S_IFMT as u32!=libc::S_IFSOCK as u32 {
        return Err(Reason::Flags);
    }
    // Darwin AF_UNIX SO_ACCEPTCONN returned ENOPROTOOPT in retained native
    // evidence. This checks object/type/route, not live acceptance. The owner
    // separately retains actual listen syscall success; only the future SAME
    // object's ServerProgress can establish ongoing accept-loop health.
    let mut kind=0i32;let mut size=std::mem::size_of::<i32>() as libc::socklen_t;
    if unsafe {libc::getsockopt(raw,libc::SOL_SOCKET,libc::SO_TYPE,std::ptr::addr_of_mut!(kind).cast(),&mut size)}!=0
        || size as usize!=std::mem::size_of::<i32>() || kind!=libc::SOCK_STREAM { return Err(Reason::ListenerChanged); }
    if let Some(path)=path {
        let mut address:libc::sockaddr_un=unsafe {std::mem::zeroed()};let mut length=std::mem::size_of_val(&address) as libc::socklen_t;
        if unsafe {libc::getsockname(raw,std::ptr::addr_of_mut!(address).cast(),&mut length)}!=0 {return Err(Reason::ListenerChanged);}
        let bytes=path.as_os_str().as_bytes();let offset=std::mem::offset_of!(libc::sockaddr_un,sun_path);
        if address.sun_family as i32!=libc::AF_UNIX || bytes.len()>=address.sun_path.len()
            || (length as usize)<offset+bytes.len() || length as usize>std::mem::size_of_val(&address)
            || !address.sun_path.iter().zip(bytes).all(|(a,b)|*a as u8==*b) || address.sun_path[bytes.len()]!=0 {
            return Err(Reason::ListenerChanged);
        }
    }
    Ok(Identity::named(&metadata))
}

#[cfg(test)]
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum Point { AfterBind, AfterDac, AfterListen, AfterDuplicate }
struct Owner {
    role:Role, context:Option<Context>, path:Option<PathBuf>, leaf:Option<CString>,
    parent:Option<File>, parent_identity:Option<Identity>, original_parent_fd:Option<i32>,
    listener:Option<UnixListener>, listener_identity:Option<Identity>, created:Option<(u64,u64)>,
    // Historical syscall fact, never a live acceptance/worker-health claim.
    protected:Option<Stamp>, listen_succeeded:bool, taken:bool, poisoned:bool, failures:Vec<Reason>,
    #[cfg(test)] hook:Option<Box<dyn FnMut(Point,&Path)>>,
}
impl Owner {
    fn empty(role:Role) -> Self { Self {role,context:None,path:None,leaf:None,parent:None,parent_identity:None,
        original_parent_fd:None,listener:None,listener_identity:None,created:None,protected:None,
        listen_succeeded:false,taken:false,poisoned:false,failures:Vec::new(),#[cfg(test)] hook:None} }
    fn retain(&mut self,reason:Reason) { self.poisoned=true;if !self.failures.contains(&reason) {self.failures.push(reason);} }
    fn result(&self) -> Check<()> { if self.poisoned { Err(*self.failures.first().unwrap_or(&Reason::Poisoned)) } else { Ok(()) } }
    fn acquire(role:Role, originals:&mut SelectedRuntime, end:Instant) -> Self {
        let mut owner=Self::empty(role);
        let result=(|| {
            within(end)?;native()?;
            let checked=deployment::selected().ok_or(Reason::Context)?;shape(checked)?;
            owner.context=Some(Context::Native(checked));
            let mut originals=Some(originals);owner.gate(&mut originals,end)?;
            owner.path=Some(role.path(&deployment::normalized_path(&checked.target().layout.socket_root).map_err(|_|Reason::Path)?));
            let parent=originals.as_deref().ok_or(Reason::Originals)?.supervisor_parent().map_err(|_|Reason::Originals)?;
            owner.original_parent_fd=Some(parent.as_raw_fd());
            owner.parent=Some(parent.try_clone().map_err(|_|Reason::Duplicate)?);
            owner.prepare(&mut originals,end)
        })();
        if let Err(reason)=result {owner.retain(reason);}owner
    }
    fn is_native(&self) -> bool {matches!(self.context,Some(Context::Native(_)))}
    fn inspect(&self, originals:&Option<&mut SelectedRuntime>) -> Check<()> {
        let Some(parent)=&self.parent else {return Ok(());};directory_fd(parent)?;
        let identity=Identity::of(&parent.metadata().map_err(|_|Reason::Parent)?);
        let (uid,gid)=self.context.as_ref().ok_or(Reason::Context)?.ids();
        if identity.mode&libc::S_IFMT as u32!=libc::S_IFDIR as u32 || identity.uid!=uid || identity.gid!=gid
            || identity.mode&0o7777!=0o2750 || self.parent_identity.is_some_and(|old|old!=identity) {return Err(Reason::ParentChanged);}
        let path=self.path.as_ref().ok_or(Reason::Path)?;
        let route=std::fs::symlink_metadata(path.parent().ok_or(Reason::Path)?).map_err(|_|Reason::Parent)?;
        if Identity::of(&route)!=identity {return Err(Reason::ParentChanged);}
        if self.is_native() {
            let actual=originals.as_deref().ok_or(Reason::Originals)?.supervisor_parent().map_err(|_|Reason::Originals)?;
            if Some(actual.as_raw_fd())!=self.original_parent_fd || Identity::of(&actual.metadata().map_err(|_|Reason::Originals)?)!=identity {
                return Err(Reason::Originals);
            }
        }
        acl(Some(parent),None,self.is_native())?;
        if let Some(listener)=&self.listener {
            let actual=listener_identity(listener,self.created.map(|_|path.as_path()))?;
            if self.listener_identity!=Some(actual) {return Err(Reason::ListenerChanged);}
        }
        if let Some(created)=self.created {
            let actual=named(parent,self.leaf.as_ref().ok_or(Reason::Path)?)?;let stamp=Stamp::named(&actual);
            if stamp.identity.inode()!=created || stamp.identity.mode&libc::S_IFMT as u32!=libc::S_IFSOCK as u32
                || stamp.identity.uid!=uid || stamp.links!=1 {return Err(Reason::NameChanged);}
            if let Some(expected)=self.protected {
                if stamp!=expected || stamp.identity.gid!=gid || stamp.identity.mode&0o7777!=0o660 {return Err(Reason::Dac);}
                acl(None,Some(path),self.is_native())?;
            }
            let route=std::fs::symlink_metadata(path).map_err(|_|Reason::NameChanged)?;
            if Identity::of(&route)!=stamp.identity {return Err(Reason::NameChanged);}
            if let Some(expected)=self.protected {
                let after=named(parent,self.leaf.as_ref().ok_or(Reason::Path)?)?;
                if Stamp::named(&after)!=expected {return Err(Reason::NameChanged);}
            }
        } Ok(())
    }
    fn gate(&mut self, originals:&mut Option<&mut SelectedRuntime>, end:Instant) -> Check<()> {
        if self.poisoned {self.retain(Reason::Poisoned);return self.result();}
        within(end).inspect_err(|reason|self.retain(*reason))?;
        let context=self.context.as_ref().ok_or(Reason::Context).and_then(|context|context.current(originals,end));
        if let Err(reason)=context {self.retain(reason);}
        if let Err(reason)=self.inspect(originals) {self.retain(reason);}
        let context=self.context.as_ref().ok_or(Reason::Context).and_then(|context|context.current(originals,end));
        if let Err(reason)=context {self.retain(reason);}
        if let Err(reason)=within(end) {self.retain(reason);}self.result()
    }
    fn prepare(&mut self, originals:&mut Option<&mut SelectedRuntime>, end:Instant) -> Check<()> {
        let path=self.path.as_ref().ok_or(Reason::Path)?;
        self.leaf=Some(CString::new(path.file_name().ok_or(Reason::Path)?.as_bytes()).map_err(|_|Reason::Path)?);
        self.parent_identity=Some(Identity::of(&self.parent.as_ref().ok_or(Reason::Parent)?.metadata().map_err(|_|Reason::Parent)?));
        self.gate(originals,end)?;
        let parent=self.parent.as_ref().ok_or(Reason::Parent)?;let leaf=self.leaf.as_ref().ok_or(Reason::Path)?;
        let mut metadata:libc::stat=unsafe {std::mem::zeroed()};
        if unsafe {libc::fstatat(parent.as_raw_fd(),leaf.as_ptr(),&mut metadata,libc::AT_SYMLINK_NOFOLLOW)}==0 {return Err(Reason::Occupied);}
        if std::io::Error::last_os_error().raw_os_error()!=Some(libc::ENOENT) {return Err(Reason::NameUnknown);}
        let mut address:libc::sockaddr_un=unsafe {std::mem::zeroed()};let bytes=self.path.as_ref().ok_or(Reason::Path)?.as_os_str().as_bytes();
        if bytes.len()>=address.sun_path.len() {return Err(Reason::Path);}
        address.sun_family=libc::AF_UNIX as _;for (to,from) in address.sun_path.iter_mut().zip(bytes) {*to=*from as _;}
        let length=std::mem::offset_of!(libc::sockaddr_un,sun_path)+bytes.len()+1;
        #[cfg(target_os="macos")] {address.sun_len=length as _;}
        self.gate(originals,end)?;
        let raw=unsafe {libc::socket(libc::AF_UNIX,libc::SOCK_STREAM,0)};if raw<0 {return Err(Reason::Socket);}
        self.listener=Some(unsafe {UnixListener::from_raw_fd(raw)}); // Retain before every later failure.
        if unsafe {libc::fcntl(raw,libc::F_SETFD,libc::FD_CLOEXEC)}<0 {return Err(Reason::Flags);}
        self.listener.as_ref().ok_or(Reason::Socket)?.set_nonblocking(true).map_err(|_|Reason::Flags)?;
        self.listener_identity=Some(listener_identity(self.listener.as_ref().ok_or(Reason::Socket)?,None)?);
        self.gate(originals,end)?;
        if unsafe {libc::bind(raw,std::ptr::addr_of!(address).cast(),length as _)}!=0 {return Err(Reason::Bind);}
        let actual=named(self.parent.as_ref().ok_or(Reason::Parent)?,self.leaf.as_ref().ok_or(Reason::Path)?)?;
        self.created=Some(Identity::named(&actual).inode());
        #[cfg(test)] self.checkpoint(Point::AfterBind);
        self.gate(originals,end)?;
        let (uid,gid)=self.context.as_ref().ok_or(Reason::Context)?.ids();
        let parent=self.parent.as_ref().ok_or(Reason::Parent)?.as_raw_fd();let leaf=self.leaf.as_ref().ok_or(Reason::Path)?;
        if unsafe {libc::fchownat(parent,leaf.as_ptr(),uid,gid,libc::AT_SYMLINK_NOFOLLOW)}!=0 {return Err(Reason::Dac);}
        self.gate(originals,end)?;
        if unsafe {libc::fchmodat(parent,self.leaf.as_ref().ok_or(Reason::Path)?.as_ptr(),0o660,libc::AT_SYMLINK_NOFOLLOW)}!=0 {return Err(Reason::Dac);}
        self.protected=Some(Stamp::named(&named(self.parent.as_ref().ok_or(Reason::Parent)?,self.leaf.as_ref().ok_or(Reason::Path)?)?));
        #[cfg(test)] self.checkpoint(Point::AfterDac);
        self.gate(originals,end)?;
        if unsafe {libc::listen(raw,4)}!=0 {return Err(Reason::Listen);}self.listen_succeeded=true;
        #[cfg(test)] self.checkpoint(Point::AfterListen);
        self.gate(originals,end)
    }
    fn require_current(&mut self, originals:&mut Option<&mut SelectedRuntime>, end:Instant) -> Check<()> {
        self.gate(originals,end)?;
        if !self.listen_succeeded || self.protected.is_none() || self.listener.is_none() {self.retain(Reason::Incomplete);}
        self.result()
    }
    fn take_listener(&mut self, originals:&mut Option<&mut SelectedRuntime>, end:Instant) -> Check<UnixListener> {
        let result=(|| {
            self.require_current(originals,end)?;
            if self.taken {return Err(Reason::AlreadyTaken);}
            // Duplicate THIS original open object, never bind/connect/reopen a path.
            let duplicate=self.listener.as_ref().ok_or(Reason::Incomplete)?.try_clone().map_err(|_|Reason::Duplicate)?;
            self.taken=true;
            #[cfg(test)] self.checkpoint(Point::AfterDuplicate);
            if Some(listener_identity(&duplicate,Some(self.path.as_ref().ok_or(Reason::Path)?))?)!=self.listener_identity {
                return Err(Reason::ListenerChanged);
            }
            self.require_current(originals,end)?;Ok(duplicate)
        })();
        if let Err(reason)=result.as_ref() {self.retain(*reason);}result
    }
    fn error(&self) -> crate::error::EnclaveError {
        err!(EACCES,"SUPERVISOR_SELECTED_SOCKET_REFUSED","role={:?}; stages={:?}",self.role,self.failures)
    }
    #[cfg(test)]
    fn checkpoint(&mut self, point:Point) {if let (Some(hook),Some(path))=(&mut self.hook,&self.path) {hook(point,path);}}
}

// Distinct concrete roles prevent an aggregate from exchanging primary/held
// slots. Future fixed-handler wrappers consume the one duplicate and retain the
// socket owner alongside actual ServerProgress. No path/policy/FD provider API.
pub(super) struct PrimarySocket { inner:Owner }
pub(super) struct HeldSocket { inner:Owner }
macro_rules! socket_api {
    ($socket:ident,$role:ident) => {impl $socket {
        pub(super) fn bind(originals:&mut SelectedRuntime,end:Instant)->Self {Self {inner:Owner::acquire(Role::$role,originals,end)}}
        pub(super) fn require_current(&mut self,originals:&mut SelectedRuntime,end:Instant)->EnclaveResult<()> {
            self.inner.require_current(&mut Some(originals),end).map_err(|_|self.inner.error())
        }
        pub(super) fn take_listener(&mut self,originals:&mut SelectedRuntime,end:Instant)->EnclaveResult<UnixListener> {
            self.inner.take_listener(&mut Some(originals),end).map_err(|_|self.inner.error())
        }
    }};
}
socket_api!(PrimarySocket,Primary);
socket_api!(HeldSocket,Held);

#[cfg(test)]
#[path="selected_socket_tests.rs"]
mod tests;
