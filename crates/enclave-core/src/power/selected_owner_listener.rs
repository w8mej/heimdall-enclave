//! One finite protected selected-owner listener. No startup/action authority.
//!
//! The original monitor, parent ancestry, socket and actor handles remain owned.
//! One native allocation per process; a failed/finished lifetime cannot reaccept,
//! reconnect, unlink a name or create a replacement. Unknown worker completion
//! retains its resource bundle and charge in a process-owned registry.
use std::{ffi::CString, fs::{File, Metadata}, os::{fd::{AsRawFd, FromRawFd},
    unix::{ffi::OsStrExt, fs::MetadataExt, net::{UnixListener, UnixStream}}},
    path::{Component, Path, PathBuf}, sync::{Arc, Mutex, atomic::{AtomicBool, AtomicU64, Ordering}},
    time::{Duration, Instant}};
use sha2::{Digest, Sha256};
use crate::{codesign, daemon::DaemonId, deployment::{self, CheckedDeploymentTarget,
    DeploymentRole, DeploymentSigningMode}, error::EnclaveResult, Profile, err};
use super::selected_owner_channel::SOCKET_LEAF;
#[cfg(target_os="macos")]
use super::selected_owner_session::SelectedOwnerSession;

const POLL: Duration = Duration::from_millis(10);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reason { Native, Scope, Context, Pins, Path, Open, Parent, Changed, Flags, Acl,
    Occupied, NameUnknown, Socket, Dac, Bind, Listen, Incomplete, Stopped, Deadline,
    Reused, Poisoned, Accept, Thread, Actor, Guardian, Unwound, CleanupUnknown }
type Check<T> = Result<T, Reason>;
fn error(reason: Reason) -> crate::error::EnclaveError {
    err!(EACCES, "SELECTED_OWNER_LISTENER_REFUSED", "{reason:?}")
}
fn within(end: Instant) -> Check<()> { if Instant::now() >= end { Err(Reason::Deadline) } else { Ok(()) } }
fn native() -> Check<()> {
    if !cfg!(target_os="macos") || crate::ipc::geteuid()!=0 || !codesign::enforced() { Err(Reason::Native) } else { Ok(()) }
}
fn shape(checked: &CheckedDeploymentTarget) -> Check<()> {
    let target = checked.target();
    if target.role!=DeploymentRole::DedicatedTest || target.profile!=Profile::L2
        || target.signing_identity_mode!=DeploymentSigningMode::LocalPins
        || codesign::signing_mode()!=codesign::SigningMode::LocalPins
        || target.broker.is_some() || !target.shared_read_only_inputs.is_empty() { return Err(Reason::Scope); }
    deployment::upgrade::assert_start_allowed(checked).map_err(|_| Reason::Scope)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity { dev:u64, ino:u64, uid:u32, gid:u32, mode:u32 }
impl Identity {
    fn of(value:&Metadata) -> Self { Self { dev:value.dev(), ino:value.ino(), uid:value.uid(), gid:value.gid(), mode:value.mode() } }
    fn named(value:&libc::stat) -> Self { Self { dev:value.st_dev as u64, ino:value.st_ino as u64,
        uid:value.st_uid, gid:value.st_gid, mode:value.st_mode as u32 } }
    fn inode(self) -> (u64,u64) { (self.dev,self.ino) }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stamp { identity:Identity, links:u64, mtime:i64, mtime_ns:i64, ctime:i64, ctime_ns:i64 }
impl Stamp {
    fn named(value:&libc::stat) -> Self { Self { identity:Identity::named(value), links:value.st_nlink as u64,
        mtime:value.st_mtime as i64, mtime_ns:value.st_mtime_nsec as i64,
        ctime:value.st_ctime as i64, ctime_ns:value.st_ctime_nsec as i64 } }
}
fn named(parent:&File, name:&CString) -> Check<libc::stat> {
    let mut value:libc::stat = unsafe {std::mem::zeroed()};
    if unsafe {libc::fstatat(parent.as_raw_fd(),name.as_ptr(),&mut value,libc::AT_SYMLINK_NOFOLLOW)}!=0 { return Err(Reason::NameUnknown); }
    Ok(value)
}
fn directory_flags(file:&File) -> Check<()> {
    let access = unsafe {libc::fcntl(file.as_raw_fd(),libc::F_GETFL)};
    let descriptor = unsafe {libc::fcntl(file.as_raw_fd(),libc::F_GETFD)};
    if access<0 || access&libc::O_ACCMODE!=libc::O_RDONLY || access&libc::O_NONBLOCK==0
        || descriptor<0 || descriptor&libc::FD_CLOEXEC==0 { Err(Reason::Flags) } else { Ok(()) }
}
// Exact same Darwin empty-ACL policy as selected_socket. Never follow the leaf
// or normalize/repair an existing ACL, directory, mode, owner or socket name.
fn empty_acl(file:Option<&File>, path:Option<&Path>, native_context:bool) -> Check<()> {
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
        let name=path.map(|path|CString::new(path.as_os_str().as_bytes()).map_err(|_|Reason::Path)).transpose()?;
        unsafe { *libc::__error()=0; }
        let value=unsafe {match (file,name.as_ref()) {
            (Some(file),None)=>acl_get_fd_np(file.as_raw_fd(),0x100),
            (None,Some(name))=>acl_get_link_np(name.as_ptr(),0x100), _=>return Err(Reason::Acl),
        }};
        if value.is_null() { return if std::io::Error::last_os_error().raw_os_error()==Some(libc::ENOENT) {Ok(())} else {Err(Reason::Acl)}; }
        let valid=unsafe {acl_valid(value)};let mut entry=std::ptr::null_mut();
        let found=unsafe {acl_get_entry(value,0,&mut entry)};
        let errno=std::io::Error::last_os_error().raw_os_error();let freed=unsafe {acl_free(value)};
        if valid!=0 || found!=-1 || errno!=Some(libc::EINVAL) || freed!=0 {return Err(Reason::Acl);}
        Ok(())
    }
    #[cfg(not(target_os="macos"))]
    { let _=(file,path);Err(Reason::Native) }
}

enum Context {
    Native { checked:&'static CheckedDeploymentTarget, pins:[u8;32] },
    // Private fixture roots prove only repository-local software identities.
    #[cfg(test)] Fixture { root:PathBuf, uid:u32, gid:u32 },
}
impl Context {
    fn capture(end:Instant) -> Check<Self> {
        within(end)?;native()?;
        let checked=deployment::selected().ok_or(Reason::Context)?;shape(checked)?;
        let raw=deployment::read_protected_public(&checked.target().codesign_pins_file,1024*1024).map_err(|_|Reason::Pins)?;
        let value=Self::Native {checked,pins:Sha256::digest(raw).into()};value.current(end)?;Ok(value)
    }
    fn current(&self,end:Instant) -> Check<()> {
        within(end)?;
        match self {
            Self::Native {checked,pins}=>{
                native()?;shape(checked)?;
                if !std::ptr::eq(*checked,deployment::selected().ok_or(Reason::Context)?) {return Err(Reason::Context);}
                let fresh=deployment::load(checked.config_path()).map_err(|_|Reason::Context)?;
                if fresh.descriptor_sha256()!=checked.descriptor_sha256() || fresh.target()!=checked.target() {return Err(Reason::Context);}
                let raw=deployment::read_protected_public(&checked.target().codesign_pins_file,1024*1024).map_err(|_|Reason::Pins)?;
                let actual:[u8;32]=Sha256::digest(raw).into();if actual!=*pins {return Err(Reason::Pins);}
            },
            #[cfg(test)] Self::Fixture {..}=>{},
        }
        within(end)
    }
    fn ids(&self) -> (u32,u32) {match self {
        Self::Native {..}=>(0,DaemonId::CustodyVault.gid()),
        #[cfg(test)] Self::Fixture {uid,gid,..}=>(*uid,*gid),
    }}
    fn native_context(&self)->bool {matches!(self,Self::Native {..})}
    fn root(&self)->&Path {match self {Self::Native {..}=>Path::new("/"),#[cfg(test)] Self::Fixture {root,..}=>root}}
}
struct Node { name:CString, file:File, identity:Identity }
struct Route { path:PathBuf, provided:Arc<File>, provided_fd:i32, nodes:Vec<Node> }
impl Route {
    fn new(path:PathBuf,provided:Arc<File>)->Self {let provided_fd=provided.as_raw_fd();Self {path,provided,provided_fd,nodes:Vec::new()}}
    fn open(&mut self,context:&Context,end:Instant)->Check<()> {
        let relative=if context.native_context() {self.path.as_path()} else {self.path.strip_prefix(context.root()).map_err(|_|Reason::Path)?};
        let parts=relative.components().map(|part|match part {
            Component::Normal(name)=>CString::new(name.as_bytes()).map(Some).map_err(|_|Reason::Path),
            Component::RootDir if context.native_context()=>Ok(None), _=>Err(Reason::Path),
        }).filter_map(|part|part.transpose()).collect::<Check<Vec<_>>>()?;
        if parts.is_empty() || parts.len()>64 {return Err(Reason::Path);}
        let root=CString::new(context.root().as_os_str().as_bytes()).map_err(|_|Reason::Path)?;
        let flags=libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC|libc::O_DIRECTORY;
        let raw=unsafe {libc::open(root.as_ptr(),flags)};if raw<0 {return Err(Reason::Open);}
        let file=unsafe {File::from_raw_fd(raw)};let identity=Identity::of(&file.metadata().map_err(|_|Reason::Parent)?);
        self.nodes.push(Node {name:root,file,identity});
        for name in parts {
            self.check_nodes(context,end)?;
            let parent=&self.nodes.last().ok_or(Reason::Incomplete)?.file;let before=named(parent,&name)?;
            if before.st_mode&libc::S_IFMT!=libc::S_IFDIR {return Err(Reason::Parent);}
            let raw=unsafe {libc::openat(parent.as_raw_fd(),name.as_ptr(),flags)};if raw<0 {return Err(Reason::Open);}
            let file=unsafe {File::from_raw_fd(raw)};let identity=Identity::of(&file.metadata().map_err(|_|Reason::Parent)?);
            self.nodes.push(Node {name,file,identity});
            if Identity::named(&before)!=identity {return Err(Reason::Changed);}
        }
        self.current(context,end)
    }
    fn check_nodes(&self,context:&Context,end:Instant)->Check<()> {
        within(end)?;let (uid,_)=context.ids();
        for (index,node) in self.nodes.iter().enumerate() {
            let metadata=node.file.metadata().map_err(|_|Reason::Parent)?;directory_flags(&node.file)?;
            if !metadata.is_dir() || metadata.uid()!=uid || metadata.mode()&0o022!=0 || Identity::of(&metadata)!=node.identity {return Err(Reason::Changed);}
            empty_acl(Some(&node.file),None,context.native_context())?;
            let actual=if index==0 {
                std::fs::symlink_metadata(context.root()).map(|value|Identity::of(&value)).map_err(|_|Reason::Parent)?
            } else {Identity::named(&named(&self.nodes[index-1].file,&node.name)?)};
            if actual!=node.identity {return Err(Reason::Changed);}
        }
        within(end)
    }
    fn current(&self,context:&Context,end:Instant)->Check<()> {
        self.check_nodes(context,end)?;
        let last=self.nodes.last().ok_or(Reason::Incomplete)?;let metadata=last.file.metadata().map_err(|_|Reason::Parent)?;
        let parent_gid=if context.native_context() {0} else {context.ids().1};
        directory_flags(&self.provided)?;empty_acl(Some(&self.provided),None,context.native_context())?;
        if last.identity.gid!=parent_gid || last.identity.mode&0o7777!=0o755
            || self.provided.as_raw_fd()!=self.provided_fd || Identity::of(&self.provided.metadata().map_err(|_|Reason::Parent)?)!=last.identity
            || Identity::of(&std::fs::symlink_metadata(&self.path).map_err(|_|Reason::Parent)?)!=Identity::of(&metadata) {return Err(Reason::Changed);}
        within(end)
    }
    fn parent(&self)->Check<&File> {self.nodes.last().map(|node|&node.file).ok_or(Reason::Incomplete)}
}

// Clone only Rust ownership metadata under this mutex. A lease pins the SAME
// original descriptor through native calls without preventing terminal stop.
// Retiring a cell forbids future leases; an in-flight call can remain UNKNOWN.
struct ListenerCell(Mutex<Option<Arc<UnixListener>>>);
impl ListenerCell {
    fn lease(&self)->Check<Arc<UnixListener>> {
        self.0.lock().map_err(|_|Reason::Poisoned)?.as_ref().cloned().ok_or(Reason::Stopped)
    }
    fn retire(&self)->Option<Arc<UnixListener>> {
        self.0.lock().unwrap_or_else(|error|error.into_inner()).take()
    }
}

fn listener_identity(listener:&UnixListener,path:Option<&Path>)->Check<Identity> {
    let raw=listener.as_raw_fd();let mut metadata:libc::stat=unsafe {std::mem::zeroed()};
    let flags=unsafe {libc::fcntl(raw,libc::F_GETFL)};let descriptor=unsafe {libc::fcntl(raw,libc::F_GETFD)};
    if flags<0 || flags&libc::O_NONBLOCK==0 || descriptor<0 || descriptor&libc::FD_CLOEXEC==0
        || unsafe {libc::fstat(raw,&mut metadata)}!=0 || metadata.st_mode&libc::S_IFMT!=libc::S_IFSOCK {return Err(Reason::Flags);}
    let mut kind=0i32;let mut size=std::mem::size_of_val(&kind) as libc::socklen_t;
    if unsafe {libc::getsockopt(raw,libc::SOL_SOCKET,libc::SO_TYPE,std::ptr::addr_of_mut!(kind).cast(),&mut size)}!=0
        || size as usize!=std::mem::size_of_val(&kind) || kind!=libc::SOCK_STREAM {return Err(Reason::Socket);}
    if let Some(path)=path {
        let mut address:libc::sockaddr_un=unsafe {std::mem::zeroed()};let mut size=std::mem::size_of_val(&address) as libc::socklen_t;
        if unsafe {libc::getsockname(raw,std::ptr::addr_of_mut!(address).cast(),&mut size)}!=0 {return Err(Reason::Socket);}
        let bytes=path.as_os_str().as_bytes();let offset=std::mem::offset_of!(libc::sockaddr_un,sun_path);
        if address.sun_family as i32!=libc::AF_UNIX || bytes.len()>=address.sun_path.len() || (size as usize)<offset+bytes.len()
            || (size as usize)>std::mem::size_of_val(&address) || address.sun_path[bytes.len()]!=0
            || !address.sun_path.iter().zip(bytes).all(|(a,b)|*a as u8==*b) {return Err(Reason::Socket);}
    }
    // SO_ACCEPTCONN is unsupported on retained Darwin AF_UNIX evidence; actual
    // listen success is a separate local historical fact, never a ready permit.
    Ok(Identity::named(&metadata))
}
trait StopOriginal:Clone+Send+Sync+'static {fn stop_original(&self);}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum Phase {Fresh,Binding,Bound,Running,Accepting,Accepted,Terminal}
struct Life {phase:Phase, accepted:bool, accept_end:Option<Instant>, next:u64, ticket:Option<u64>, listener:Option<Arc<ListenerCell>>}
#[derive(Clone)]
struct Control<S:StopOriginal> {original:Instant,flag:Arc<AtomicBool>,life:Arc<Mutex<Life>>,signal:S}
impl<S:StopOriginal> Control<S> {
    fn new(original:Instant,signal:S)->Self {Self {original,signal,flag:Arc::new(AtomicBool::new(false)),life:Arc::new(Mutex::new(Life {phase:Phase::Fresh,accepted:false,accept_end:None,next:0,ticket:None,listener:None}))}}
    fn stop(&self) {
        self.flag.store(true,Ordering::Release);
        let listener={let mut state=self.life.lock().unwrap_or_else(|error|error.into_inner());
            state.phase=Phase::Terminal;state.listener.take()};
        let retired=listener.as_ref().and_then(|listener|listener.retire());
        // Do not drop the last socket Arc (native close) or wait for any native
        // lease before SAME root cancellation. No lifecycle/cell lock is held.
        self.signal.stop_original();
        drop(retired);drop(listener);
    }
    fn ever_accepted(&self)->bool {
        // Poison can never establish that channel cleanup was unnecessary.
        self.life.lock().map(|state|state.accepted).unwrap_or(true)
    }
    fn deadline(&self,state:&Life,end:Instant)->Instant {
        self.original.min(end).min(if state.phase==Phase::Accepted {self.original} else {state.accept_end.unwrap_or(self.original)})
    }
    fn check(&self,end:Instant)->Check<()> {
        let result=(||{
            let state=self.life.lock().map_err(|_|Reason::Poisoned)?;within(self.deadline(&state,end))?;
            if self.flag.load(Ordering::Acquire) || state.phase==Phase::Terminal {return Err(Reason::Stopped);}Ok(())})();
        if result.is_err() {self.stop();}result
    }
    fn advance(&self,from:Phase,to:Phase,end:Instant)->Check<()> {
        let result=(||{let mut state=self.life.lock().map_err(|_|Reason::Poisoned)?;
            within(self.deadline(&state,end))?;
            if self.flag.load(Ordering::Acquire) || state.phase!=from
                || !matches!((from,to),(Phase::Fresh,Phase::Binding)|(Phase::Binding,Phase::Bound)|(Phase::Bound,Phase::Running)) {return Err(Reason::Reused);}
            if from==Phase::Fresh {state.accept_end=Some(self.original.min(end));}
            state.phase=to;Ok(())})();
        if result.is_err() {self.stop();}result
    }
    fn accept(&self,cell:&Arc<ListenerCell>,end:Instant)->Check<Option<UnixStream>> {
        self.accept_with(cell,end,&mut |_|{})
    }
    fn accept_with(&self,cell:&Arc<ListenerCell>,end:Instant,hook:&mut impl FnMut(Point))->Check<Option<UnixStream>> {
        let ticket=(||{
            let mut state=self.life.lock().map_err(|_|Reason::Poisoned)?;within(self.deadline(&state,end))?;
            if self.flag.load(Ordering::Acquire) || state.phase!=Phase::Running
                || !state.listener.as_ref().is_some_and(|original|Arc::ptr_eq(original,cell)) {return Err(Reason::Reused);}
            state.next=state.next.checked_add(1).ok_or(Reason::Reused)?;
            let ticket=state.next;state.ticket=Some(ticket);state.phase=Phase::Accepting;Ok(ticket)
        })();
        let ticket=match ticket {Ok(ticket)=>ticket,Err(reason)=>{self.stop();return Err(reason);}};
        // Install the stop guard before acquiring the lease. Even a caught
        // unwind/cell poison after reservation cannot rearm the allocation.
        let mut attempt=AcceptAttempt {control:self.clone(),ticket,socket:None,stream:None,armed:true};
        attempt.socket=Some(cell.lease()?);
        hook(Point::BeforeAcceptCall);
        // The native syscall runs with neither Life nor ListenerCell locked.
        match attempt.socket.as_ref().ok_or(Reason::Incomplete)?.accept() {
            Ok((stream,_))=>attempt.stream=Some(stream),
            Err(error) if error.kind()==std::io::ErrorKind::WouldBlock || error.kind()==std::io::ErrorKind::Interrupted=>{},
            Err(_)=>return Err(Reason::Accept),
        }
        // Remember an actual kernel acceptance BEFORE a test/native completion
        // boundary can unwind; this negative charge is sticky even after stop.
        if attempt.stream.is_some() {
            self.life.lock().unwrap_or_else(|error|error.into_inner()).accepted=true;
        }
        hook(Point::AfterAcceptCall);
        {
            let mut state=self.life.lock().map_err(|_|Reason::Poisoned)?;within(self.deadline(&state,end))?;
            if self.flag.load(Ordering::Acquire) || state.phase!=Phase::Accepting || state.ticket!=Some(attempt.ticket) {return Err(Reason::Stopped);}
            state.ticket=None;
            state.phase=if attempt.stream.is_some() {Phase::Accepted} else {Phase::Running};
        }
        // Late WouldBlock can never renew a stopped/expired reservation, and a
        // late real stream never leaves this guard for peer authentication.
        attempt.armed=false;Ok(attempt.stream.take())
    }
    fn attach(&self,listener:Arc<ListenerCell>,end:Instant)->Check<()> {
        let result=(||{let mut state=self.life.lock().map_err(|_|Reason::Poisoned)?;within(self.deadline(&state,end))?;
            if self.flag.load(Ordering::Acquire) || state.phase!=Phase::Binding || state.listener.is_some() {return Err(Reason::Reused);}
            state.listener=Some(listener.clone());Ok(())})();
        if result.is_err() {
            let retired=listener.retire();self.stop();drop(retired);
        }result
    }
}
struct AcceptAttempt<S:StopOriginal> {control:Control<S>,ticket:u64,socket:Option<Arc<UnixListener>>,stream:Option<UnixStream>,armed:bool}
impl<S:StopOriginal> Drop for AcceptAttempt<S> {
    fn drop(&mut self) {
        if self.armed {
            self.control.stop();
            if let Some(stream)=&self.stream {let _=stream.shutdown(std::net::Shutdown::Both);}
        }
        // Original listener/stream owners drop only after negative cancellation
        // and outside all metadata locks; native cleanup can still be UNKNOWN.
    }
}
struct PreparationAttempt<S:StopOriginal> {control:Control<S>,armed:bool}
impl<S:StopOriginal> Drop for PreparationAttempt<S> {fn drop(&mut self) {if self.armed {self.control.stop();}}}
struct StopOnExit<S:StopOriginal>(Control<S>);
impl<S:StopOriginal> Drop for StopOnExit<S> {fn drop(&mut self) {self.0.stop();}}
#[derive(Clone,Copy,PartialEq,Eq)]
enum Point {AfterSocket,BeforeBindCall,AfterBindCall,AfterBind,AfterDac,BeforeListenCall,AfterListenCall,AfterListen,BeforeAcceptCall,AfterAcceptCall,AfterAccept}
struct Bound {context:Context,route:Route,path:PathBuf,leaf:CString,
    listener:Option<Arc<ListenerCell>>,identity:Option<Identity>,created:Option<(u64,u64)>,protected:Option<Stamp>,listened:bool}
impl Bound {
    fn new(context:Context,path:PathBuf,parent:Arc<File>)->Check<Self> {
        let leaf=CString::new(SOCKET_LEAF).map_err(|_|Reason::Path)?;
        Ok(Self {route:Route::new(path.clone(),parent),context,path:path.join(SOCKET_LEAF),leaf,
            listener:None,identity:None,created:None,protected:None,listened:false})
    }
    fn inspect(&self,end:Instant)->Check<()> {
        self.context.current(end)?;self.route.current(&self.context,end)?;
        if let Some(cell)=&self.listener {
            let socket=cell.lease()?;
            let actual=listener_identity(&socket,self.created.map(|_|self.path.as_path()))?;
            if Some(actual)!=self.identity {return Err(Reason::Changed);}
        }
        if let Some(created)=self.created {
            let actual=Stamp::named(&named(self.route.parent()?,&self.leaf)?);let (uid,gid)=self.context.ids();
            if actual.identity.inode()!=created || actual.identity.uid!=uid || actual.links!=1
                || actual.identity.mode&libc::S_IFMT as u32!=libc::S_IFSOCK as u32 {return Err(Reason::Changed);}
            if let Some(protected)=self.protected {
                if actual!=protected || actual.identity.gid!=gid || actual.identity.mode&0o7777!=0o660 {return Err(Reason::Dac);}
                empty_acl(None,Some(&self.path),self.context.native_context())?;
            }
            if Identity::of(&std::fs::symlink_metadata(&self.path).map_err(|_|Reason::Changed)?)!=actual.identity {return Err(Reason::Changed);}
            if self.protected.is_some_and(|stamp|named(self.route.parent().expect("retained parent"),&self.leaf).map(|actual|Stamp::named(&actual)!=stamp).unwrap_or(true)) {return Err(Reason::Changed);}
        }
        self.route.current(&self.context,end)?;self.context.current(end)
    }
    fn prepare<S:StopOriginal>(&mut self,control:&Control<S>,end:Instant,hook:&mut impl FnMut(Point,&Path))->Check<()> {
        let mut attempt=PreparationAttempt {control:control.clone(),armed:true};
        control.check(end)?;self.context.current(end)?;self.route.open(&self.context,end)?;
        let parent=self.route.parent()?;let mut actual:libc::stat=unsafe {std::mem::zeroed()};
        if unsafe {libc::fstatat(parent.as_raw_fd(),self.leaf.as_ptr(),&mut actual,libc::AT_SYMLINK_NOFOLLOW)}==0 {return Err(Reason::Occupied);}
        if std::io::Error::last_os_error().raw_os_error()!=Some(libc::ENOENT) {return Err(Reason::NameUnknown);}
        let bytes=self.path.as_os_str().as_bytes();let mut address:libc::sockaddr_un=unsafe {std::mem::zeroed()};
        if bytes.is_empty() || bytes.contains(&0) || bytes.len()>=address.sun_path.len() {return Err(Reason::Path);}
        address.sun_family=libc::AF_UNIX as _;for (to,from) in address.sun_path.iter_mut().zip(bytes) {*to=*from as _;}
        let length=std::mem::offset_of!(libc::sockaddr_un,sun_path)+bytes.len()+1;
        #[cfg(target_os="macos")] {address.sun_len=length as _;}
        control.check(end)?;self.route.current(&self.context,end)?;
        let raw=unsafe {libc::socket(libc::AF_UNIX,libc::SOCK_STREAM,0)};if raw<0 {return Err(Reason::Socket);}
        let listener=unsafe {UnixListener::from_raw_fd(raw)};
        let cell=Arc::new(ListenerCell(Mutex::new(Some(Arc::new(listener)))));self.listener=Some(cell.clone());control.attach(cell.clone(),end)?;
        hook(Point::AfterSocket,&self.path);
        {
            let listener=cell.lease()?;let raw=listener.as_raw_fd();
            let flags=unsafe {libc::fcntl(raw,libc::F_GETFD)};
            if flags<0 || unsafe {libc::fcntl(raw,libc::F_SETFD,flags|libc::FD_CLOEXEC)}<0 {return Err(Reason::Flags);}
            listener.set_nonblocking(true).map_err(|_|Reason::Flags)?;
            self.identity=Some(listener_identity(&listener,None)?);
        }
        control.check(end)?;self.inspect(end)?;
        // A private Arc lease pins the exact FD while bind may block. Stop can
        // retire the cell/cancel root concurrently; completion is checked below.
        let bind_lease=cell.lease()?;hook(Point::BeforeBindCall,&self.path);
        if unsafe {libc::bind(bind_lease.as_raw_fd(),std::ptr::addr_of!(address).cast(),length as _)}!=0 {return Err(Reason::Bind);}
        self.created=Some(Identity::named(&named(self.route.parent()?,&self.leaf)?).inode());
        hook(Point::AfterBindCall,&self.path);drop(bind_lease);hook(Point::AfterBind,&self.path);
        control.check(end)?;self.inspect(end)?;
        let (uid,gid)=self.context.ids();let parent=self.route.parent()?.as_raw_fd();
        if unsafe {libc::fchownat(parent,self.leaf.as_ptr(),uid,gid,libc::AT_SYMLINK_NOFOLLOW)}!=0 {return Err(Reason::Dac);}
        control.check(end)?;self.inspect(end)?;
        if unsafe {libc::fchmodat(parent,self.leaf.as_ptr(),0o660,libc::AT_SYMLINK_NOFOLLOW)}!=0 {return Err(Reason::Dac);}
        self.protected=Some(Stamp::named(&named(self.route.parent()?,&self.leaf)?));hook(Point::AfterDac,&self.path);
        control.check(end)?;self.inspect(end)?;
        let listen_lease=cell.lease()?;hook(Point::BeforeListenCall,&self.path);
        if unsafe {libc::listen(listen_lease.as_raw_fd(),1)}!=0 {return Err(Reason::Listen);}self.listened=true;
        hook(Point::AfterListenCall,&self.path);drop(listen_lease);
        hook(Point::AfterListen,&self.path);control.check(end)?;self.inspect(end)?;
        attempt.armed=false;Ok(())
    }
    fn current<S:StopOriginal>(&self,control:&Control<S>,end:Instant)->Check<()> {
        let result=(||{control.check(end)?;self.inspect(end)?;
            if !self.listened || self.protected.is_none() || self.listener.is_none() {return Err(Reason::Incomplete);}control.check(end)})();
        if result.is_err() {control.stop();}result
    }
    fn accept_one<S:StopOriginal>(&self,control:&Control<S>,end:Instant,hook:&mut impl FnMut(Point,&Path))->Check<UnixStream> {
        let result=(||{loop {
            self.current(control,end)?;
            let accepted=control.accept_with(self.listener.as_ref().ok_or(Reason::Incomplete)?,end,&mut |point|hook(point,&self.path))?;
            if let Some(stream)=accepted {
                struct Pending(Option<UnixStream>);
                impl Drop for Pending {fn drop(&mut self) {if let Some(stream)=&self.0 {let _=stream.shutdown(std::net::Shutdown::Both);}}}
                let mut pending=Pending(Some(stream));
                hook(Point::AfterAccept,&self.path);
                self.current(control,end)?;return pending.0.take().ok_or(Reason::Incomplete);
            }
            std::thread::sleep(end.min(control.original).saturating_duration_since(Instant::now()).min(POLL));
        }})();if result.is_err() {control.stop();}result
    }
}

// Private shared actor machinery. Only Native implementations below can enter
// the production wrapper; fixtures cannot construct a native audit certificate.
trait ActorSession:Send+Sync+'static {
    fn check_atomic(&self)->EnclaveResult<()>;
    fn check_current(&self)->EnclaveResult<()>;
    fn revoke_atomic(&self);
    fn original_end(&self)->Instant;
}
trait ActorAudit<S:ActorSession>:Send+Sync+'static {
    fn check_original(&self,session:&Arc<S>,end:Instant)->EnclaveResult<()>;
    fn original_end(&self)->Instant;
}
struct ActorKey {actor:Arc<()>,serial:u64,challenge:[u8;32]}
struct ActorRequest<A> {key:Arc<ActorKey>,audit:Arc<A>,end:Instant,
    response:std::sync::mpsc::SyncSender<Arc<ActorKey>>}
struct ActorState<A> {next:u64,inflight:Option<Arc<ActorKey>>,pending:Option<ActorRequest<A>>}
struct ActorMailbox<A:ActorAudit<S>,S:ActorSession> {
    actor:Arc<()>,session:Arc<S>,original:Instant,veto:Arc<AtomicBool>,
    alive:AtomicBool,busy:AtomicBool,pending_published:AtomicBool,serial:AtomicU64,state:Mutex<ActorState<A>>,
}
// This guard NEVER takes the queue/socket/owner mutex, shuts down, joins, drops
// an original native owner, or invokes synchronous cancellation. An actor in a
// <=2s existing step can remain blocked/charged after the waiter has refused.
struct ActorAbort<'a,A:ActorAudit<S>,S:ActorSession> {
    mailbox:&'a ActorMailbox<A,S>,offered:Option<&'a Arc<S>>,armed:bool,
}
impl<A:ActorAudit<S>,S:ActorSession> Drop for ActorAbort<'_,A,S> {
    fn drop(&mut self) {if self.armed {
        self.mailbox.invalidate();
        if let Some(session)=self.offered {session.revoke_atomic();}
    }}
}
struct ActorPresence<A:ActorAudit<S>,S:ActorSession> {mailbox:Arc<ActorMailbox<A,S>>}
impl<A:ActorAudit<S>,S:ActorSession> Drop for ActorPresence<A,S> {
    fn drop(&mut self) {self.mailbox.invalidate();self.mailbox.alive.store(false,Ordering::SeqCst);}
}
struct ActorReceipt<A:ActorAudit<S>,S:ActorSession> {
    mailbox:Arc<ActorMailbox<A,S>>,key:Arc<ActorKey>,audit:Arc<A>,end:Instant,
}
impl<A:ActorAudit<S>,S:ActorSession> ActorMailbox<A,S> {
    fn new(session:Arc<S>,original:Instant,veto:Arc<AtomicBool>)->Arc<Self> {
        Arc::new(Self {actor:Arc::new(()),session,original,veto,alive:AtomicBool::new(false),
            busy:AtomicBool::new(false),pending_published:AtomicBool::new(false),serial:AtomicU64::new(0),
            state:Mutex::new(ActorState {next:0,inflight:None,pending:None})})
    }
    fn invalidate(&self) {
        self.veto.store(true,Ordering::SeqCst);self.session.revoke_atomic();
    }
    // No filesystem/native/owner work. Handle pickup does not claim that the
    // actor has accepted a stream, made progress, or processed a comparison.
    fn binding(&self,session:&Arc<S>,end:Instant)->EnclaveResult<()> {
        if !Arc::ptr_eq(session,&self.session) || self.original>self.session.original_end()
            || self.veto.load(Ordering::SeqCst) || Instant::now()>=self.original.min(end) {
            return Err(err!(EACCES,"SELECTED_OWNER_ACTOR_BINDING"));
        }
        self.session.check_atomic()
    }
    fn current(&self,audit:&A,end:Instant)->EnclaveResult<()> {
        self.binding(&self.session,end)?;
        if !self.alive.load(Ordering::SeqCst) {return Err(err!(EACCES,"SELECTED_OWNER_ACTOR_MISSING"));}
        self.session.check_current()?;
        audit.check_original(&self.session,end)?;
        self.binding(&self.session,end)
    }
    fn enter_actor(self:&Arc<Self>)->EnclaveResult<ActorPresence<A,S>> {
        let mut abort=ActorAbort {mailbox:self,offered:None,armed:true};
        self.binding(&self.session,self.original)?;
        if self.alive.compare_exchange(false,true,Ordering::SeqCst,Ordering::SeqCst).is_err() {
            return Err(err!(EACCES,"SELECTED_OWNER_ACTOR_REUSED"));
        }
        abort.armed=false;Ok(ActorPresence {mailbox:self.clone()})
    }
    fn take(&self)->EnclaveResult<Option<ActorRequest<A>>> {
        let mut abort=ActorAbort {mailbox:self,offered:None,armed:true};
        self.binding(&self.session,self.original)?;
        // The sole actor must not race the sender's brief enqueue critical
        // section. Publication occurs only AFTER that queue lock is released.
        // An unpublished slot needs no lock, wait, retry or actor progress.
        if self.pending_published.compare_exchange(true,false,Ordering::SeqCst,Ordering::SeqCst).is_err() {
            abort.armed=false;return Ok(None);
        }
        let request={let mut state=self.state.try_lock().map_err(|_|err!(EACCES,"SELECTED_OWNER_ACTOR_QUEUE"))?;
            state.pending.take().ok_or_else(||err!(ESTALE,"SELECTED_OWNER_ACTOR_REQUEST_MISSING"))?};
        abort.armed=false;Ok(Some(request))
    }
    fn compare(self:&Arc<Self>,audit:Arc<A>,session:&Arc<S>,requested:Instant)->EnclaveResult<ActorReceipt<A,S>> {
        let mut abort=ActorAbort {mailbox:self,offered:Some(session),armed:true};
        self.binding(session,requested)?;
        // Same preexisting exchange admission cap; not a new lifecycle budget.
        let end=self.original.min(audit.original_end()).min(requested)
            .min(Instant::now()+Duration::from_secs(2));
        if self.busy.compare_exchange(false,true,Ordering::SeqCst,Ordering::SeqCst).is_err() {
            return Err(err!(EACCES,"SELECTED_OWNER_ACTOR_BUSY"));
        }
        // Reserve the single operation BEFORE certificate/session callbacks.
        self.current(audit.as_ref(),end)?;
        let challenge=crate::rng::bytes32();
        if challenge==[0;32] {return Err(err!(EIO,"SELECTED_OWNER_ACTOR_CHALLENGE"));}
        let (send,receive)=std::sync::mpsc::sync_channel(1);
        let key={
            let mut state=self.state.try_lock().map_err(|_|err!(EACCES,"SELECTED_OWNER_ACTOR_QUEUE"))?;
            if state.inflight.is_some() || state.pending.is_some() || self.pending_published.load(Ordering::SeqCst) {
                return Err(err!(EACCES,"SELECTED_OWNER_ACTOR_BUSY"));
            }
            let serial=state.next.checked_add(1).ok_or_else(||err!(EACCES,"SELECTED_OWNER_ACTOR_SERIAL"))?;
            let key=Arc::new(ActorKey {actor:self.actor.clone(),serial,challenge});
            state.next=serial;state.inflight=Some(key.clone());
            state.pending=Some(ActorRequest {key:key.clone(),audit:audit.clone(),end,response:send});
            self.serial.store(serial,Ordering::SeqCst);key
        };
        self.pending_published.store(true,Ordering::SeqCst);
        // Receiver is operation-local. No second stream reader, timeout reset,
        // metadata lock, native handle or native cleanup enters this wait.
        let reply=receive.recv_timeout(end.saturating_duration_since(Instant::now()))
            .map_err(|_|err!(ETIMEDOUT,"SELECTED_OWNER_ACTOR_REPLY_UNAVAILABLE"))?;
        if !Arc::ptr_eq(&key,&reply) || !Arc::ptr_eq(&reply.actor,&self.actor)
            || reply.serial!=key.serial || reply.challenge!=key.challenge {
            return Err(err!(ESTALE,"SELECTED_OWNER_ACTOR_REPLY_CHANGED"));
        }
        self.current(audit.as_ref(),end)?;
        {
            let mut state=self.state.try_lock().map_err(|_|err!(EACCES,"SELECTED_OWNER_ACTOR_QUEUE"))?;
            if self.pending_published.load(Ordering::SeqCst) || state.pending.is_some()
                || !state.inflight.as_ref().is_some_and(|original|Arc::ptr_eq(original,&key)) {
                return Err(err!(ESTALE,"SELECTED_OWNER_ACTOR_REPLY_CHANGED"));
            }
            state.inflight=None;
        }
        let receipt=ActorReceipt {mailbox:self.clone(),key,audit,end};
        receipt.require(&receipt.audit,session,end)?;
        self.busy.store(false,Ordering::SeqCst);abort.armed=false;Ok(receipt)
    }
    fn process(&self,request:ActorRequest<A>,compare:impl FnOnce(&A,Instant)->EnclaveResult<()>)->EnclaveResult<()> {
        let mut abort=ActorAbort {mailbox:self,offered:None,armed:true};
        self.current(request.audit.as_ref(),request.end)?;
        if !Arc::ptr_eq(&request.key.actor,&self.actor) || request.key.challenge==[0;32]
            || self.serial.load(Ordering::SeqCst)!=request.key.serial {
            return Err(err!(ESTALE,"SELECTED_OWNER_ACTOR_REQUEST_CHANGED"));
        }
        {
            let state=self.state.try_lock().map_err(|_|err!(EACCES,"SELECTED_OWNER_ACTOR_QUEUE"))?;
            if self.pending_published.load(Ordering::SeqCst) || state.pending.is_some()
                || !state.inflight.as_ref().is_some_and(|key|Arc::ptr_eq(key,&request.key)) {
                return Err(err!(ESTALE,"SELECTED_OWNER_ACTOR_REQUEST_CHANGED"));
            }
        }
        compare(request.audit.as_ref(),request.end)?;
        self.current(request.audit.as_ref(),request.end)?;
        request.response.try_send(request.key.clone()).map_err(|_|err!(EACCES,"SELECTED_OWNER_ACTOR_WAITER_GONE"))?;
        abort.armed=false;Ok(())
    }
}
impl<A:ActorAudit<S>,S:ActorSession> ActorReceipt<A,S> {
    fn require(&self,audit:&Arc<A>,session:&Arc<S>,end:Instant)->EnclaveResult<()> {
        let mut abort=ActorAbort {mailbox:self.mailbox.as_ref(),offered:Some(session),armed:true};
        if !Arc::ptr_eq(audit,&self.audit) || !Arc::ptr_eq(&self.key.actor,&self.mailbox.actor)
            || self.key.serial!=self.mailbox.serial.load(Ordering::SeqCst) || self.key.challenge==[0;32] {
            return Err(err!(ESTALE,"SELECTED_OWNER_ACTOR_MATCH_CHANGED"));
        }
        self.mailbox.binding(session,self.end.min(end))?;
        self.mailbox.current(audit.as_ref(),self.end.min(end))?;
        abort.armed=false;Ok(())
    }
}
#[cfg(target_os="macos")]
impl ActorSession for SelectedOwnerSession {
    fn check_atomic(&self)->EnclaveResult<()> {self.require_not_revoked()}
    fn check_current(&self)->EnclaveResult<()> {self.require_current()}
    fn revoke_atomic(&self) {self.revoke();}
    fn original_end(&self)->Instant {self.original_instant_end()}
}
#[cfg(target_os="macos")]
impl ActorAudit<SelectedOwnerSession> for crate::supervisor::CertifiedReceivedTaskAudit {
    fn check_original(&self,session:&Arc<SelectedOwnerSession>,end:Instant)->EnclaveResult<()> {self.require_same_session(session,end)}
    fn original_end(&self)->Instant {self.original_instant_end()}
}
/// Private-allocation handle, supplied only by the actual retained root worker.
/// Cloning it never clones a socket, native owner or positive readiness permit.
#[cfg(target_os="macos")]
#[derive(Clone)]
pub(crate) struct RootSelectedOwnerActorComparison {
    inner:Arc<ActorMailbox<crate::supervisor::CertifiedReceivedTaskAudit,SelectedOwnerSession>>,
}
#[cfg(target_os="macos")]
impl RootSelectedOwnerActorComparison {
    pub(crate) fn require_same_session(&self,session:&Arc<SelectedOwnerSession>,end:Instant)->EnclaveResult<()> {
        let mut abort=ActorAbort {mailbox:self.inner.as_ref(),offered:Some(session),armed:true};
        self.inner.binding(session,end)?;abort.armed=false;Ok(())
    }
    pub(crate) fn compare_received_task(&self,audit:Arc<crate::supervisor::CertifiedReceivedTaskAudit>,
        session:&Arc<SelectedOwnerSession>,end:Instant)->EnclaveResult<OriginalCustodyActorMatch> {
        self.inner.compare(audit,session,end).map(|receipt|OriginalCustodyActorMatch {receipt})
    }
}
/// Fresh one-request comparison only; never Ready/Begin or assignment proof.
#[cfg(target_os="macos")]
pub(crate) struct OriginalCustodyActorMatch {
    receipt:ActorReceipt<crate::supervisor::CertifiedReceivedTaskAudit,SelectedOwnerSession>,
}
#[cfg(target_os="macos")]
impl OriginalCustodyActorMatch {
    /// The immutable endpoint of THIS actual one-request comparison. Reading
    /// it grants no currentness or dispatch authority and never renews it.
    pub(crate) fn original_instant_end(&self)->Instant {self.receipt.end}
    pub(crate) fn require_same_original(&self,audit:&Arc<crate::supervisor::CertifiedReceivedTaskAudit>,
        session:&Arc<SelectedOwnerSession>,end:Instant)->EnclaveResult<()> {self.receipt.require(audit,session,end)}
}

#[cfg(target_os="macos")]
#[derive(Clone)]
struct RootSignal(super::selected_owner_channel::RootSelectedOwnerStop,
    Arc<std::sync::OnceLock<Arc<SelectedOwnerSession>>>);
#[cfg(target_os="macos")]
impl StopOriginal for RootSignal {fn stop_original(&self) {
    // A Bound path failure can invoke Control::stop before returning to its
    // guardian. Poison the linked original before root socket cleanup can block.
    if let Some(session)=self.1.get() {session.revoke();}
    self.0.stop();
}}
#[cfg(target_os="macos")]
struct SessionOnExit(Arc<SelectedOwnerSession>);
#[cfg(target_os="macos")]
impl Drop for SessionOnExit {fn drop(&mut self) {self.0.revoke();}}
/// Prepublished negative-only stop for one finite listener and SAME root actor.
#[cfg(target_os="macos")]
#[derive(Clone)]
pub(crate) struct RootSelectedOwnerListenerStop {control:Control<RootSignal>}
#[cfg(target_os="macos")]
impl RootSelectedOwnerListenerStop {
    /// Capture the original lifetime before listener/actor allocation.
    pub(crate) fn new(lifetime_end:Instant)->Self {Self {control:Control::new(lifetime_end,RootSignal(
        super::selected_owner_channel::RootSelectedOwnerStop::new(lifetime_end),Arc::new(std::sync::OnceLock::new())))}}
    /// Retire original listener admission and cancel the SAME pending/bound
    /// generation. In-flight native leases remain owned with UNKNOWN cleanup;
    /// stop neither interrupts those calls nor waits for their socket Arc.
    pub(crate) fn stop(&self) {self.control.stop();}
}
#[cfg(target_os="macos")]
static NATIVE_ALLOCATED:AtomicBool=AtomicBool::new(false);
/// Partial-failure-retaining original protected listener; no startup permit.
#[cfg(target_os="macos")]
pub(crate) struct RootSelectedOwnerListener {bound:Option<Arc<Bound>>,monitor:Option<Arc<super::darwin::PowerMonitor>>,
    session:Arc<SelectedOwnerSession>,stop:RootSelectedOwnerListenerStop,accept_end:Instant,failure:Option<Reason>,transferred:bool}
#[cfg(target_os="macos")]
impl RootSelectedOwnerListener {
    /// Bind only the fixed selected path using the actual retained parent FD and
    /// original monitor. Failure keeps every acquired object without repairs.
    pub(crate) fn bind(monitor:Arc<super::darwin::PowerMonitor>,original_parent:Arc<File>,
        lifetime_end:Instant,accept_end:Instant,stop:&RootSelectedOwnerListenerStop,session:Arc<SelectedOwnerSession>)->Self {
        let lifetime_end=lifetime_end.min(session.original_instant_end());
        let mut owner=Self {bound:None,monitor:Some(monitor),session,stop:stop.clone(),accept_end:accept_end.min(lifetime_end),failure:None,transferred:false};
        let result=(||{native()?;
            owner.session.require_current().map_err(|_|Reason::Context)?;
            if NATIVE_ALLOCATED.compare_exchange(false,true,Ordering::AcqRel,Ordering::Acquire).is_err() {return Err(Reason::Reused);}
            if lifetime_end!=stop.control.original {return Err(Reason::Deadline);}
            // One negative-only association. A pre-bind stop stays terminal;
            // its later association cannot admit Binding or another session.
            stop.control.signal.1.set(owner.session.clone()).map_err(|_|Reason::Reused)?;
            stop.control.advance(Phase::Fresh,Phase::Binding,owner.accept_end)?;
            let context=Context::capture(owner.accept_end)?;
            let path=match &context {Context::Native {checked,..}=>deployment::normalized_path(&checked.target().layout.socket_root).map_err(|_|Reason::Path)?,
                #[cfg(test)] Context::Fixture {..}=>return Err(Reason::Native)};
            let mut bound=Bound::new(context,path,original_parent)?;
            let result=(||{owner.monitor.as_ref().ok_or(Reason::Incomplete)?.observe_health(owner.accept_end).map_err(|_|Reason::Context)?;
                owner.session.require_current().map_err(|_|Reason::Context)?;
                bound.prepare(&stop.control,owner.accept_end,&mut |_,_|{})?;
                owner.session.require_current().map_err(|_|Reason::Context)?;
                stop.control.advance(Phase::Binding,Phase::Bound,owner.accept_end)})();
            owner.bound=Some(Arc::new(bound));result
        })();
        if let Err(reason)=result {owner.failure=Some(reason);owner.session.revoke();stop.stop();}owner
    }
    /// Observe this allocation's protected originals; never a startup permit.
    pub(crate) fn require_bound(&self,end:Instant)->EnclaveResult<()> {
        let result=(||{
            self.session.require_current()?;
            if let Some(reason)=self.failure {return Err(error(reason));}
            self.bound.as_ref().ok_or_else(||error(Reason::Incomplete))?.current(&self.stop.control,end).map_err(error)?;
            self.session.require_current()
        })();
        if result.is_err() {self.session.revoke();self.stop.stop();}result
    }
    /// Consume this allocation once. Spawn/refusal failures stay in the returned
    /// worker owner so partial native threads are never mistaken for cleaned up.
    pub(crate) fn start(mut self)->RootSelectedOwnerWorker {
        let comparison=ActorMailbox::new(self.session.clone(),self.stop.control.original,self.stop.control.flag.clone());
        let resources=Resources {bound:self.bound.take(),monitor:self.monitor.take(),session:self.session.clone(),stop:self.stop.clone(),
            comparison,threads:Threads::new()};
        // Install the final retained-resource Drop guard BEFORE spawning either
        // thread. Caught allocation/spawn unwind must preserve partial workers.
        let mut worker=RootSelectedOwnerWorker {resources:Some(resources),failures:self.failure.into_iter().collect()};
        self.transferred=true;
        let started=(||{
            if !worker.failures.is_empty() {return Err(Reason::Incomplete);}
            let resources=worker.resources.as_mut().ok_or(Reason::Incomplete)?;
            resources.session.require_current().map_err(|_|Reason::Context)?;
            resources.stop.control.advance(Phase::Bound,Phase::Running,self.accept_end)?;
            let bound=resources.bound.as_ref().ok_or(Reason::Incomplete)?.clone();let guardian_bound=bound.clone();
            let stop=resources.stop.clone();let guardian_stop=stop.clone();
            let session=resources.session.clone();let guardian_session=session.clone();
            resources.threads.guardian=Some(std::thread::Builder::new().name("selected-owner-route".into()).spawn(move||{
                let exit=StopOnExit(guardian_stop.control.clone());
                // Revoke SAME session before root stop/native cleanup can block.
                let _session_exit=SessionOnExit(guardian_session.clone());
                while !exit.0.flag.load(Ordering::Acquire) {
                    if guardian_session.require_current().is_err() {break;}
                    if guardian_bound.current(&exit.0,exit.0.original).is_err() {break;}
                    if guardian_session.require_current().is_err() {break;}
                    std::thread::sleep(exit.0.original.saturating_duration_since(Instant::now()).min(POLL));
                }
            }).map_err(|_|Reason::Thread)?);
            let monitor=resources.monitor.as_ref().ok_or(Reason::Incomplete)?.clone();let accept_end=self.accept_end;
            let comparison=resources.comparison.clone();
            resources.threads.actor=Some(std::thread::Builder::new().name("selected-owner-actor".into()).spawn(move||{
                let _exit=StopOnExit(stop.control.clone());
                let _session_exit=SessionOnExit(session.clone());
                session.require_current()?;
                let stream=bound.accept_one(&stop.control,accept_end,&mut |_,_|{}).map_err(error)?;
                session.require_current()?;
                let mut channel=super::selected_owner_channel::RootSelectedOwnerChannel::accept_stoppable(stream,&monitor,stop.control.original,
                    accept_end.min(stop.control.original),&stop.control.signal.0,session.clone())?;
                // Declared after channel: atomic invalidation precedes channel
                // Drop/socket shutdown/native owner cleanup on every unwind.
                let _actor=comparison.enter_actor()?;
                loop {
                    session.require_current()?;
                    bound.current(&stop.control,stop.control.original).map_err(error)?;
                    // Only this original channel-owning thread services the
                    // mailbox, between unchanged stream steps. No second
                    // reader, socket clone or shortened/reset step timeout.
                    if let Some(request)=comparison.take()? {
                        comparison.process(request,|audit,end| {
                            bound.current(&stop.control,end).map_err(error)?;
                            channel.compare_received_task(audit,&session,&monitor,end)?;
                            bound.current(&stop.control,end).map_err(error)?;
                            session.require_current()
                        })?;
                    }
                    channel.step(&monitor,stop.control.original)?;
                    bound.current(&stop.control,stop.control.original).map_err(error)?;
                    session.require_current()?;
                }
            }).map_err(|_|Reason::Thread)?);Ok(())
        })();
        if let Err(reason)=started {worker.failures.push(reason);worker.stop();}
        worker
    }
}
#[cfg(target_os="macos")]
impl Drop for RootSelectedOwnerListener {fn drop(&mut self) {if !self.transferred {self.session.revoke();self.stop.stop();}}}
#[cfg(target_os="macos")]
struct Resources {bound:Option<Arc<Bound>>,monitor:Option<Arc<super::darwin::PowerMonitor>>,session:Arc<SelectedOwnerSession>,stop:RootSelectedOwnerListenerStop,
    comparison:Arc<ActorMailbox<crate::supervisor::CertifiedReceivedTaskAudit,SelectedOwnerSession>>,threads:Threads}
// Shared production/fixture ownership accounting. A pending JoinHandle stays
// retained; only is_finished followed by actual join can remove that charge.
struct Threads {actor:Option<std::thread::JoinHandle<EnclaveResult<()>>>,guardian:Option<std::thread::JoinHandle<()>>}
impl Threads {
    fn new()->Self {Self {actor:None,guardian:None}}
    fn join_finished(&mut self,failures:&mut Vec<Reason>) {
        if self.actor.as_ref().is_some_and(|worker|worker.is_finished()) {
            match self.actor.take().expect("finished actor").join() {Ok(Ok(()))=>{},Ok(Err(_))=>failures.push(Reason::Actor),Err(_)=>failures.push(Reason::Unwound)}
        }
        if self.guardian.as_ref().is_some_and(|worker|worker.is_finished()) {
            if self.guardian.take().expect("finished guardian").join().is_err() {failures.push(Reason::Guardian);}
        }
    }
    fn complete(&self)->bool {self.actor.is_none() && self.guardian.is_none()}
}
#[cfg(target_os="macos")]
impl Resources {
    fn join_finished(&mut self,failures:&mut Vec<Reason>) {self.threads.join_finished(failures);}
    fn complete(&self)->bool {
        // Current channel WatchWorker may detach without exposing an exact
        // completion receipt. Actor/route joins alone cannot clear that owner.
        // Keep every accepted lifetime charged until a source-owned channel
        // watcher completion API is integrated; no caller bool substitutes.
        self.threads.complete() && !self.stop.control.ever_accepted()
    }
}
#[cfg(target_os="macos")]
static RETAINED:std::sync::OnceLock<Mutex<Vec<Resources>>>=std::sync::OnceLock::new();
/// Owns the finite actor/guard even when synchronous native cleanup is unknown.
#[cfg(target_os="macos")]
pub(crate) struct RootSelectedOwnerWorker {resources:Option<Resources>,failures:Vec<Reason>}
#[cfg(target_os="macos")]
impl RootSelectedOwnerWorker {
    /// Acquire only this worker's original private mailbox. This is neither
    /// actor progress nor successful peer comparison; actual requests can fail
    /// while accept/handshake/the existing stream step is still blocked.
    pub(crate) fn original_actor_comparison(&self)->EnclaveResult<RootSelectedOwnerActorComparison> {
        let resources=self.resources.as_ref().ok_or_else(||error(Reason::Incomplete))?;
        let handle=RootSelectedOwnerActorComparison {inner:resources.comparison.clone()};
        handle.require_same_session(&resources.session,resources.stop.control.original)?;Ok(handle)
    }
    /// Independent negative stop; never waits for an actor mutex or joins it.
    pub(crate) fn stop(&self) {if let Some(resources)=&self.resources {resources.session.revoke();resources.stop.stop();}}
    /// Join only finished threads. Unknown completion retains both handles and
    /// original resource charge. Current channel watcher completion is OPEN,
    /// so every accepted lifetime stays UNKNOWN even after these two joins.
    /// Ok describes never-accepted cleanup only, never availability.
    pub(crate) fn try_finish(&mut self)->EnclaveResult<()> {
        let resources=self.resources.as_mut().ok_or_else(||error(Reason::Incomplete))?;
        resources.join_finished(&mut self.failures);
        if !resources.complete() {return Err(error(Reason::CleanupUnknown));}
        if let Some(reason)=self.failures.first() {return Err(error(*reason));}Ok(())
    }
}
#[cfg(target_os="macos")]
impl Drop for RootSelectedOwnerWorker {
    fn drop(&mut self) {
        self.stop();
        if let Some(mut resources)=self.resources.take() {
            resources.join_finished(&mut self.failures);
            if !resources.complete() {
                // Sticky one-allocation charge bounds this registry to one
                // native bundle. No detached cleanup/reaper thread is created.
                RETAINED.get_or_init(||Mutex::new(Vec::new())).lock().unwrap_or_else(|error|error.into_inner()).push(resources);
            }
        }
    }
}
/// Reap only demonstrably completed retained workers; never renew allocation or
/// unlink/adopt the old socket. Current channel watcher completion has no
/// source-owned observation, so every accepted lifetime remains UNKNOWN.
#[cfg(target_os="macos")]
pub(crate) fn reap_retained_selected_owner_listener()->EnclaveResult<()> {
    let Some(retained)=RETAINED.get() else {return Ok(());};
    let mut retained=retained.lock().unwrap_or_else(|error|error.into_inner());let mut failures=Vec::new();
    for resources in retained.iter_mut() {resources.join_finished(&mut failures);}
    let mut completed=Vec::new();let mut index=0;
    while index<retained.len() {if retained[index].complete() {completed.push(retained.swap_remove(index));} else {index+=1;}}
    let unknown=!retained.is_empty();drop(retained);
    // The last actual monitor/native owners may run synchronous teardown.
    // Release completed bundles outside the registry metadata mutex.
    drop(completed);
    if unknown {return Err(error(Reason::CleanupUnknown));}
    if let Some(reason)=failures.first() {return Err(error(*reason));}Ok(())
}

#[cfg(test)]
#[path="selected_owner_listener_tests.rs"]
mod tests;

// Test-only opaque ownership fixture for readiness retirement. This exercises
// the actual Control::stop, Life and ListenerCell locks; it cannot construct
// native selected context, session, actor, RootSelectedOwnerListenerStop or a
// positive owner. No raw lock/resource getter or production API is exposed.
#[cfg(test)]
#[derive(Clone)]
struct ReadinessFixtureSignal;
#[cfg(test)]
impl StopOriginal for ReadinessFixtureSignal {fn stop_original(&self){}}
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct ReadinessStopFixture {
    control:Control<ReadinessFixtureSignal>,entries:Arc<AtomicU64>,
}
#[cfg(test)]
impl ReadinessStopFixture {
    pub(crate) fn new(listener:UnixListener)->Self {
        let control=Control::new(Instant::now()+Duration::from_secs(30),ReadinessFixtureSignal);
        let cell=Arc::new(ListenerCell(Mutex::new(Some(Arc::new(listener)))));
        control.life.lock().expect("software Life").listener=Some(cell);
        Self {control,entries:Arc::new(AtomicU64::new(0))}
    }
    pub(crate) fn stop(&self) {self.entries.fetch_add(1,Ordering::SeqCst);self.control.stop();}
    pub(crate) fn stop_entries(&self)->u64 {self.entries.load(Ordering::SeqCst)}
    pub(crate) fn hold(&self,cell:bool,ready:std::sync::mpsc::SyncSender<()>,
        release:std::sync::mpsc::Receiver<()>)->bool {
        if cell {
            let listener=self.control.life.lock().expect("software Life").listener.as_ref().expect("original ListenerCell").clone();
            let _held=listener.0.lock().expect("software ListenerCell");
            ready.send(()).expect("held-cell signal");release.recv_timeout(Duration::from_secs(5)).is_ok()
        } else {
            let _held=self.control.life.lock().expect("software Life");
            ready.send(()).expect("held-Life signal");release.recv_timeout(Duration::from_secs(5)).is_ok()
        }
    }
}
