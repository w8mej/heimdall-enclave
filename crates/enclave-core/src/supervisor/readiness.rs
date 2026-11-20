//! Fixed selected supervisor dependency channel. Wire data is never an owner.
use std::{collections::BTreeMap, ffi::CString, fs::{File, Metadata},
    io::Cursor, os::{fd::{AsRawFd, FromRawFd}, unix::{ffi::OsStrExt, fs::{FileExt, MetadataExt}, net::{UnixListener, UnixStream}}},
    path::{Path, PathBuf}, sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}, mpsc},
    time::{Duration, Instant}};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use crate::{codesign::{self, CodeRequirement}, daemon::DaemonId,
    deployment::{self, CheckedDeploymentTarget, DeploymentRole, DeploymentSigningMode},
    error::EnclaveResult, ipc::{self, FrameIoLimits, PeerPolicy}, Profile, err, fail};

#[path = "readiness_server_peer.rs"]
mod readiness_server_peer;

const LEAF: &str = "supervisor-ready-v1.sock";
const FRAME: usize = 8192;
const PROBE: Duration = Duration::from_secs(2);
const PREFLIGHT: Duration = Duration::from_secs(30);

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Binding { target_id: String, descriptor_sha256: String, profile: Profile, signing: DeploymentSigningMode }
impl Binding {
    fn selected(checked: &CheckedDeploymentTarget) -> Self {
        Self { target_id: checked.target().target_id.clone(), descriptor_sha256: checked.descriptor_sha256().into(),
            profile: checked.target().profile, signing: checked.target().signing_identity_mode }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
enum Term { Context, StartupLease, Originals, PowerUsb, PrimaryWorker, HeldWorker, Mach,
    PfInputs, PfEnabled, PfRootTopology, PfLlm, PfCas, PfInterfacesNoSkip,
    PfTranslations, PfExistingStateEffects, PfEffectiveEnforcement,
    PfKqueue, PfDynamicStore, PfAtomicRestore }
const REQUIRED: [Term; 19] = [Term::Context,Term::StartupLease,Term::Originals,Term::PowerUsb,
    Term::PrimaryWorker,Term::HeldWorker,Term::Mach,Term::PfInputs,Term::PfEnabled,
    Term::PfRootTopology,Term::PfLlm,Term::PfCas,Term::PfInterfacesNoSkip,
    Term::PfTranslations,Term::PfExistingStateEffects,Term::PfEffectiveEnforcement,
    Term::PfKqueue,Term::PfDynamicStore,Term::PfAtomicRestore];
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
enum Outcome { Observed, Missing, Refused(String) }
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request { version: u8, challenge: [u8; 32] }
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation { version: u8, kind: String, challenge: [u8; 32], binding: Binding,
    instance: [u8; 32], started_boot_ns: u64, ended_boot_ns: u64, terms: BTreeMap<Term, Outcome>,
    retained_errors: Vec<String> }

fn within(end: Instant) -> EnclaveResult<()> {
    if Instant::now() >= end { fail!(ETIMEDOUT,"SUPERVISOR_DEPENDENCY_DEADLINE"); } Ok(())
}
fn shape(checked: &CheckedDeploymentTarget) -> EnclaveResult<()> {
    let t=checked.target();
    if t.role!=DeploymentRole::DedicatedTest || t.profile!=Profile::L2
        || t.signing_identity_mode!=DeploymentSigningMode::LocalPins
        || codesign::signing_mode()!=codesign::SigningMode::LocalPins
        || t.broker.is_some() || !t.shared_read_only_inputs.is_empty() {
        fail!(EACCES,"SUPERVISOR_DEPENDENCY_SCOPE");
    } Ok(())
}
fn selection(checked: &CheckedDeploymentTarget, end: Instant) -> EnclaveResult<()> {
    within(end)?;
    if !cfg!(target_os="macos") || !codesign::enforced() { fail!(ENOSYS,"SUPERVISOR_DEPENDENCY_NATIVE_REQUIRED"); }
    let actual=deployment::selected().ok_or_else(||err!(EACCES,"DEPLOYMENT_CONTEXT_REQUIRED"))?;
    if !std::ptr::eq(actual,checked) { fail!(ESTALE,"SUPERVISOR_DEPENDENCY_CONTEXT_CHANGED"); }
    shape(actual)?;
    let current=deployment::load(checked.config_path())?;
    if current.descriptor_sha256()!=checked.descriptor_sha256() || current.target()!=checked.target() {
        fail!(ESTALE,"SUPERVISOR_DEPENDENCY_CONTEXT_CHANGED");
    }
    deployment::upgrade::assert_start_allowed(actual)?; within(end)
}
fn strict_decode<T: DeserializeOwned>(bytes: &[u8]) -> EnclaveResult<T> {
    if bytes.is_empty() || bytes.len()>FRAME { fail!(EINVAL,"SUPERVISOR_DEPENDENCY_SCHEMA"); }
    let mut cursor=Cursor::new(bytes);
    let raw:ciborium::value::Value=ciborium::from_reader(&mut cursor).map_err(|_|err!(EINVAL,"SUPERVISOR_DEPENDENCY_SCHEMA"))?;
    if cursor.position()!=bytes.len() as u64 { fail!(EINVAL,"SUPERVISOR_DEPENDENCY_TRAILING_DATA"); }
    fn unique(value:&ciborium::value::Value,depth:usize)->bool {
        if depth>12 {return false;}
        match value {
            ciborium::value::Value::Map(entries)=>entries.iter().enumerate().all(|(i,(key,value))|
                !entries[..i].iter().any(|(old,_)|old==key) && unique(key,depth+1) && unique(value,depth+1)),
            ciborium::value::Value::Array(entries)=>entries.iter().all(|v|unique(v,depth+1)),
            ciborium::value::Value::Tag(_,_)=>false,
            _=>true,
        }
    }
    if !matches!(raw,ciborium::value::Value::Map(_)) || !unique(&raw,0) {fail!(EINVAL,"SUPERVISOR_DEPENDENCY_SCHEMA");}
    ciborium::from_reader(bytes).map_err(|_|err!(EINVAL,"SUPERVISOR_DEPENDENCY_SCHEMA"))
}
fn frame_limits(end: Instant) -> EnclaveResult<FrameIoLimits> {
    within(end)?; let left=end.saturating_duration_since(Instant::now()).min(PROBE);
    Ok(FrameIoLimits {max_frame:FRAME,frame_deadline:left,idle_timeout:left})
}
fn complete(observation: &Observation) -> bool {
    observation.terms.len()==REQUIRED.len() && REQUIRED.iter().all(|term|observation.terms.get(term)==Some(&Outcome::Observed))
        && observation.retained_errors.is_empty()
}
fn exchange_owned(operation: &mut ReadinessOperation<'_, '_>, binding: &Binding, instance: &mut Option<[u8;32]>, end: Instant) -> EnclaveResult<()> {
    operation.current()?;
    let started=crate::clock::boot_clock_ns();
    let challenge=crate::rng::bytes32();
    let request=Request {version:1,challenge};
    let encoded=ipc::to_cbor(&request)?;
    operation.current()?;
    let bytes=ipc::exchange_selected_readiness_until(operation.stream,&mut operation.guard,&encoded,end)?;
    operation.current()?;
    let observation=match strict_decode::<ipc::Reply<Observation>>(&bytes)? {
        ipc::Reply::Ok(value)=>value,ipc::Reply::Err(error)=>return Err(error),
    };
    operation.current()?;
    within(end)?;
    let now=crate::clock::boot_clock_ns();
    if observation.version!=1 || observation.kind!="mcpmac-selected-supervisor-observation"
        || observation.challenge!=challenge || &observation.binding!=binding
        || observation.instance==[0;32] || instance.is_some_and(|nonce|nonce!=observation.instance)
        || started==u64::MAX || now==u64::MAX || observation.started_boot_ns<started
        || observation.ended_boot_ns<observation.started_boot_ns || observation.ended_boot_ns>now {
        fail!(ESTALE,"SUPERVISOR_DEPENDENCY_BINDING");
    }
    if instance.is_none() {*instance=Some(observation.instance);}
    if !complete(&observation) {
        let missing=REQUIRED.iter().filter(|term|observation.terms.get(term)!=Some(&Outcome::Observed)).collect::<Vec<_>>();
        fail!(EACCES,"SUPERVISOR_DEPENDENCY_UNAVAILABLE","required={missing:?}; retained={:?}",observation.retained_errors);
    }
    operation.current()?;
    Ok(())
}

#[derive(Clone, PartialEq, Eq)]
struct Stamp {dev:u64,ino:u64,uid:u32,gid:u32,mode:u32,links:u64,size:u64,mtime:i64,mtime_ns:i64,ctime:i64,ctime_ns:i64}
fn stamp(m:&Metadata)->Stamp {Stamp {dev:m.dev(),ino:m.ino(),uid:m.uid(),gid:m.gid(),mode:m.mode(),links:m.nlink(),size:m.len(),
    mtime:m.mtime(),mtime_ns:m.mtime_nsec(),ctime:m.ctime(),ctime_ns:m.ctime_nsec()}}
fn directory_equal(a:&Stamp,b:&Stamp)->bool {(a.dev,a.ino,a.uid,a.gid,a.mode)==(b.dev,b.ino,b.uid,b.gid,b.mode)}
fn fd(file:&File)->EnclaveResult<()> {
    let flags=unsafe{libc::fcntl(file.as_raw_fd(),libc::F_GETFL)};
    let descriptor=unsafe{libc::fcntl(file.as_raw_fd(),libc::F_GETFD)};
    if flags<0 || flags&libc::O_ACCMODE!=libc::O_RDONLY || flags&libc::O_NONBLOCK==0 || descriptor<0 || descriptor&libc::FD_CLOEXEC==0 {
        fail!(ESTALE,"SUPERVISOR_DEPENDENCY_FD_CHANGED");
    } native_acl(file)
}
fn native_acl(file:&File)->EnclaveResult<()> {
    #[cfg(target_os="macos")]
    {
        use std::ffi::c_void;
        unsafe extern "C" {
            fn acl_get_fd_np(fd:libc::c_int,kind:libc::c_int)->*mut c_void;
            fn acl_valid(acl:*mut c_void)->libc::c_int;
            fn acl_get_entry(acl:*mut c_void,id:libc::c_int,entry:*mut *mut c_void)->libc::c_int;
            fn acl_free(acl:*mut c_void)->libc::c_int;
        }
        let acl=unsafe{acl_get_fd_np(file.as_raw_fd(),0x00000100)};
        if acl.is_null() {
            if std::io::Error::last_os_error().raw_os_error()==Some(libc::ENOENT) {return Ok(());}
            fail!(EACCES,"SUPERVISOR_DEPENDENCY_ACL_UNKNOWN");
        }
        let mut entry=std::ptr::null_mut();
        let valid=unsafe{acl_valid(acl)};let count=unsafe{acl_get_entry(acl,0,&mut entry)};
        let errno=std::io::Error::last_os_error().raw_os_error();
        let freed=unsafe{acl_free(acl)};
        if valid!=0 || count != -1 || errno!=Some(libc::EINVAL) || freed!=0 {fail!(EACCES,"SUPERVISOR_DEPENDENCY_ACL_REFUSED");}
        Ok(())
    }
    #[cfg(not(target_os="macos"))]
    {let _=file;Ok(())} // Test-only metadata observations cannot mint native clients.
}
fn opened(raw:i32)->EnclaveResult<File> {
    if raw<0 {fail!(EACCES,"SUPERVISOR_DEPENDENCY_PROTECTED_INPUT");} Ok(unsafe{File::from_raw_fd(raw)})
}
fn name(path:&Path)->EnclaveResult<CString> {
    CString::new(path.file_name().ok_or_else(||err!(EINVAL,"SUPERVISOR_DEPENDENCY_PATH"))?.as_bytes())
        .map_err(|_|err!(EINVAL,"SUPERVISOR_DEPENDENCY_PATH"))
}
// Fixed public client inputs only. Keep every original ancestor and file;
// opening a replacement never replaces a retained owner.
struct Input {nodes:Vec<(PathBuf,File,Stamp)>,hash:String}
impl Input {
    fn open(path:&Path)->EnclaveResult<Self> {
        let path=deployment::normalized_path(path)?;
        if path.components().count()>96 {fail!(E2BIG,"SUPERVISOR_DEPENDENCY_PATH");}
        let file=opened(unsafe{libc::open(c"/".as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)})?;
        let root_stamp=stamp(&file.metadata().map_err(|_|err!(EIO,"SUPERVISOR_DEPENDENCY_STAT"))?);
        let mut owner=Self {nodes:vec![(PathBuf::from("/"),file,root_stamp)],hash:String::new()};
        let mut route=PathBuf::from("/");
        let parts=path.components().filter_map(|p|if let std::path::Component::Normal(n)=p {Some(n)}else{None}).collect::<Vec<_>>();
        for (index,part) in parts.iter().enumerate() {
            let parent=&owner.nodes.last().expect("root").1;fd(parent)?;
            let metadata=parent.metadata().map_err(|_|err!(EIO,"SUPERVISOR_DEPENDENCY_STAT"))?;
            if !metadata.is_dir() || metadata.uid()!=0 || metadata.mode()&0o022!=0 {fail!(EACCES,"SUPERVISOR_DEPENDENCY_PROTECTED_INPUT");}
            route.push(part); let last=index+1==parts.len();
            let leaf=CString::new(part.as_bytes()).map_err(|_|err!(EINVAL,"SUPERVISOR_DEPENDENCY_PATH"))?;
            let file=opened(unsafe{libc::openat(owner.nodes.last().expect("root").1.as_raw_fd(),leaf.as_ptr(),
                libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC|if last {0}else{libc::O_DIRECTORY})})?;
            let metadata=file.metadata().map_err(|_|err!(EIO,"SUPERVISOR_DEPENDENCY_STAT"))?;
            owner.nodes.push((route.clone(),file,stamp(&metadata)));
            if last && (!metadata.is_file() || metadata.nlink()!=1 || metadata.len()==0 || metadata.len()>1024*1024) {
                fail!(EACCES,"SUPERVISOR_DEPENDENCY_PROTECTED_INPUT");
            }
        }
        owner.hash=owner.digest()?;owner.current()?;Ok(owner)
    }
    fn digest(&self)->EnclaveResult<String> {
        let file=&self.nodes.last().ok_or_else(||err!(EACCES,"SUPERVISOR_DEPENDENCY_PROTECTED_INPUT"))?.1;
        let mut hash=Sha256::new();let mut at=0;let mut buffer=[0u8;16384];
        loop {let count=file.read_at(&mut buffer,at).map_err(|_|err!(EIO,"SUPERVISOR_DEPENDENCY_READ"))?;
            if count==0 {break;} at+=count as u64;if at>1024*1024 {fail!(E2BIG,"SUPERVISOR_DEPENDENCY_INPUT_SIZE");}hash.update(&buffer[..count]);}
        Ok(hex::encode(hash.finalize()))
    }
    fn current(&self)->EnclaveResult<()> {
        for (index,(path,file,old)) in self.nodes.iter().enumerate() {
            fd(file)?;let metadata=file.metadata().map_err(|_|err!(EIO,"SUPERVISOR_DEPENDENCY_STAT"))?;
            if metadata.uid()!=0 || metadata.mode()&0o022!=0 {fail!(EACCES,"SUPERVISOR_DEPENDENCY_PROTECTED_INPUT");}
            let actual=stamp(&metadata);let last=index+1==self.nodes.len();
            if (last && actual!=*old) || (!last && (!metadata.is_dir() || !directory_equal(&actual,old))) {
                fail!(ESTALE,"SUPERVISOR_DEPENDENCY_INPUT_CHANGED");
            }
            if index>0 {
                let fresh=opened(unsafe{libc::openat(self.nodes[index-1].1.as_raw_fd(),name(path)?.as_ptr(),
                    libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC|if last {0}else{libc::O_DIRECTORY})})?;
                fd(&fresh)?;let named=stamp(&fresh.metadata().map_err(|_|err!(EIO,"SUPERVISOR_DEPENDENCY_STAT"))?);
                if (last && named!=*old) || (!last && !directory_equal(&named,old)) {fail!(ESTALE,"SUPERVISOR_DEPENDENCY_INPUT_CHANGED");}
            }
        }
        if self.digest()!=Ok(self.hash.clone()) {fail!(ESTALE,"SUPERVISOR_DEPENDENCY_INPUT_CHANGED");} Ok(())
    }
}

// Private phase/owner machinery shared by the native client and software
// sequencing fixtures. It cannot be provided through any public constructor.
trait CurrentTaskAssignment {fn observe_current(&mut self,end:Instant)->EnclaveResult<()>;}
impl CurrentTaskAssignment for crate::resource::SelectedExceptionAssignment {
    fn observe_current(&mut self,end:Instant)->EnclaveResult<()> {Self::observe_current(self,end)}
}
struct TaskAssignment<A:CurrentTaskAssignment> {owner:Option<A>,initial_observed:bool,poisoned:bool}
impl<A:CurrentTaskAssignment> TaskAssignment<A> {
    fn new()->Self {Self {owner:None,initial_observed:false,poisoned:false}}
    fn require_phase(&self,phase:ReadinessPhase)->EnclaveResult<()> {
        require_assignment_phase(self.owner.is_some(),self.initial_observed,self.poisoned,phase)
    }
    fn current_phase(&mut self,phase:ReadinessPhase,end:Instant)->EnclaveResult<()> {
        within(end)?;self.require_phase(phase)?;
        if let Some(owner)=&mut self.owner {owner.observe_current(end)?;}
        within(end)?;self.require_phase(phase)
    }
    fn probe(&mut self,end:Instant,exchange:impl FnOnce()->EnclaveResult<()>)->EnclaveResult<()> {
        if self.poisoned {fail!(EACCES,"SUPERVISOR_DEPENDENCY_POISONED");}
        let result=(||{
            within(end)?;
            // Same phase rules are used by the actual Native progress guard.
            self.require_phase(if self.initial_observed {ReadinessPhase::AssignedProbe}else{ReadinessPhase::InitialProbe})?;
            if let Some(owner)=&mut self.owner {owner.observe_current(end)?;}
            exchange()?;
            if let Some(owner)=&mut self.owner {owner.observe_current(end)?;}
            within(end)?;self.initial_observed=true;Ok(())
        })();
        if result.is_err() {self.poisoned=true;}result
    }
    fn assign(&mut self,end:Instant,construct:impl FnOnce(Instant)->EnclaveResult<A>)->EnclaveResult<()> {
        if self.poisoned {fail!(EACCES,"SUPERVISOR_DEPENDENCY_POISONED");}
        let result=(||{
            within(end)?;
            if !self.initial_observed || self.owner.is_some() {fail!(EACCES,"SUPERVISOR_DEPENDENCY_ASSIGNMENT_ORDER");}
            self.owner=Some(construct(end)?);
            // A late successful constructor's original owner is retained.
            within(end)
        })();
        if result.is_err() {self.poisoned=true;}result
    }
}

// These private comparison/sequence fixtures cannot authenticate a native
// socket or construct SelectedReadinessClient. Production always obtains both
// snapshots from the SAME owned stream and the actual pinned code policy.
struct RootPeerPin {original:ipc::PeerCredentials,poisoned:bool}
impl RootPeerPin {
    fn new(original:ipc::PeerCredentials)->EnclaveResult<Self> {
        if original.uid!=0 || original.audit_token.is_none() || original.code_identity.is_none()
            || original.tls_channel_binding.is_some() {fail!(EACCES,"SUPERVISOR_DEPENDENCY_PEER_REQUIRED");}
        Ok(Self {original,poisoned:false})
    }
    fn same(&self,current:&ipc::PeerCredentials)->EnclaveResult<()> {
        if current!=&self.original {fail!(ESTALE,"SUPERVISOR_DEPENDENCY_PEER_CHANGED");}Ok(())
    }
    fn checked_with<T,S>(&mut self,socket:&mut S,end:Instant,
        mut authenticate:impl FnMut(&S,Instant)->EnclaveResult<ipc::PeerCredentials>,
        operation:impl FnOnce(&mut S)->EnclaveResult<T>)->EnclaveResult<T> {
        if self.poisoned {fail!(EACCES,"SUPERVISOR_DEPENDENCY_PEER_POISONED");}
        // Consume the attempt before any callback/native work. Error or caught
        // unwind cannot restore this original peer or repeat an operation.
        self.poisoned=true;within(end)?;
        self.same(&authenticate(socket,end)?)?;within(end)?;
        let value=operation(socket)?;
        within(end)?;self.same(&authenticate(socket,end)?)?;within(end)?;
        self.poisoned=false;Ok(value)
    }
    fn checked<T>(&mut self,stream:&mut UnixStream,end:Instant,
        operation:impl FnOnce(&mut UnixStream)->EnclaveResult<T>)->EnclaveResult<T> {
        self.checked_with(stream,end,|stream,end| {
            within(end)?;
            if !cfg!(target_os="macos") || !codesign::enforced() {fail!(ENOSYS,"SUPERVISOR_DEPENDENCY_NATIVE_REQUIRED");}
            let requirement=CodeRequirement::pinned_boundary(codesign::CTL_IDENTIFIER)?;
            let peer=PeerPolicy::allow([]).require(0,requirement).check(&ipc::peer_credentials(stream)?)?;
            within(end)?;Ok(peer)
        },operation)
    }
}

// Fixed phases preserve one initial observation, then exactly one retained
// current-task assignment. No production constructor accepts a phase flag.
#[derive(Clone,Copy,PartialEq,Eq)]
enum ReadinessPhase { Connect, InitialProbe, AssignedProbe, Assignment }

fn require_assignment_phase(owned:bool,initial:bool,poisoned:bool,phase:ReadinessPhase)->EnclaveResult<()> {
    if poisoned {fail!(EACCES,"SUPERVISOR_DEPENDENCY_POISONED");}
    match phase {
        ReadinessPhase::Connect|ReadinessPhase::InitialProbe if !owned && !initial=>{},
        ReadinessPhase::AssignedProbe if owned && initial=>{},
        ReadinessPhase::Assignment if initial=>{},
        _=>fail!(EACCES,"SUPERVISOR_DEPENDENCY_ASSIGNMENT_ORDER"),
    }
    Ok(())
}
// Closed backing choice, not a production supplied trait/provider. Both
// Native and cfgtest owners use the same phase and retained-readback engine.
enum ReadinessAssignment<'a> {
    Native(&'a mut TaskAssignment<crate::resource::SelectedExceptionAssignment>),
    #[cfg(test)] EmptyFixture,
    #[cfg(test)] Fixture(&'a mut TaskAssignment<FixtureReadinessAssignment>),
}
impl ReadinessAssignment<'_> {
    fn current(&mut self,phase:ReadinessPhase,end:Instant)->EnclaveResult<()> {
        match self {
            Self::Native(state)=>state.current_phase(phase,end),
            #[cfg(test)] Self::Fixture(state)=>state.current_phase(phase,end),
            #[cfg(test)] Self::EmptyFixture=>{within(end)?;require_assignment_phase(false,false,false,phase)},
        }
    }
    fn veto(&mut self) {
        match self {
            Self::Native(state)=>state.poisoned=true,
            #[cfg(test)] Self::Fixture(state)=>state.poisoned=true,
            #[cfg(test)] Self::EmptyFixture=>{},
        }
    }
    fn complete_probe(&mut self,phase:ReadinessPhase)->EnclaveResult<()> {
        if !matches!(phase,ReadinessPhase::InitialProbe|ReadinessPhase::AssignedProbe) {fail!(EACCES,"SUPERVISOR_DEPENDENCY_ASSIGNMENT_ORDER");}
        match self {
            Self::Native(state)=>{state.require_phase(phase)?;state.initial_observed=true;},
            #[cfg(test)] Self::Fixture(state)=>{state.require_phase(phase)?;state.initial_observed=true;},
            #[cfg(test)] Self::EmptyFixture=>{},
        }
        Ok(())
    }
}
#[cfg(test)]
struct FixtureReadinessAssignment {
    valid:Arc<AtomicBool>,panic:Arc<AtomicBool>,reads:Arc<std::sync::atomic::AtomicUsize>,
    drops:Arc<std::sync::atomic::AtomicUsize>,
}
#[cfg(test)]
impl CurrentTaskAssignment for FixtureReadinessAssignment {
    fn observe_current(&mut self,end:Instant)->EnclaveResult<()> {
        within(end)?;self.reads.fetch_add(1,Ordering::SeqCst);
        if self.panic.load(Ordering::SeqCst) {panic!("SCRIPTED_ORIGINAL_ASSIGNMENT_READBACK_UNWIND");}
        if !self.valid.load(Ordering::SeqCst) {fail!(EACCES,"SCRIPTED_ORIGINAL_ASSIGNMENT_LOST");}
        within(end)
    }
}
#[cfg(test)]
impl Drop for FixtureReadinessAssignment {fn drop(&mut self){self.drops.fetch_add(1,Ordering::SeqCst);}}

enum ReadinessOriginal<'a> {
    Native { checked: &'static CheckedDeploymentTarget, descriptor: &'a Input, pins: &'a Input,
        peer: &'a mut Option<RootPeerPin> },
    #[cfg(test)]
    Fixture { valid: &'a AtomicBool, calls: &'a std::sync::atomic::AtomicUsize,
        delay: Duration, panic: bool, veto_at: Option<usize> },
}

// Opaque concrete negative observer. Only this module's Native construction
// binds actual retained deployment/input/peer/assignment components. IPC may
// validate or veto it; no supplied verifier/provider or positive permit exists.
pub(crate) struct SelectedReadinessIoGuard<'a> {
    original: ReadinessOriginal<'a>, assignment:ReadinessAssignment<'a>,failed: &'a AtomicBool,
    end: Instant, client_end: Instant, phase: ReadinessPhase,
}
struct ReadinessCheck<'a> { failed: &'a AtomicBool, armed: bool }
impl Drop for ReadinessCheck<'_> {
    fn drop(&mut self) { if self.armed { self.failed.store(true,Ordering::SeqCst); } }
}
fn authenticate_original_root(stream:&UnixStream,end:Instant)->EnclaveResult<ipc::PeerCredentials> {
    within(end)?;
    if !cfg!(target_os="macos") || !codesign::enforced() { fail!(ENOSYS,"SUPERVISOR_DEPENDENCY_NATIVE_REQUIRED"); }
    let requirement=CodeRequirement::pinned_boundary(codesign::CTL_IDENTIFIER)?;
    within(end)?;
    let metadata=ipc::peer_credentials(stream);
    within(end)?;
    let peer=PeerPolicy::allow([]).require(0,requirement).check(&metadata?);
    within(end)?;
    let peer=peer?;
    // Preserve original mandatory native full audit/code/non-network binding.
    if peer.uid!=0 || peer.audit_token.is_none() || peer.code_identity.is_none()
        || peer.tls_channel_binding.is_some() { fail!(EACCES,"SUPERVISOR_DEPENDENCY_PEER_REQUIRED"); }
    Ok(peer)
}
impl<'a> SelectedReadinessIoGuard<'a> {
    fn native(checked:&'static CheckedDeploymentTarget, descriptor:&'a Input,pins:&'a Input,
        peer:&'a mut Option<RootPeerPin>,assignment:&'a mut TaskAssignment<crate::resource::SelectedExceptionAssignment>,
        failed:&'a AtomicBool,end:Instant,client_end:Instant,phase:ReadinessPhase)->Self {
        Self { original:ReadinessOriginal::Native {checked,descriptor,pins,peer},assignment:ReadinessAssignment::Native(assignment),failed,end,client_end,phase }
    }
    #[cfg(test)]
    pub(crate) fn fixture(end:Instant,valid:&'a AtomicBool,calls:&'a std::sync::atomic::AtomicUsize,
        failed:&'a AtomicBool)->Self {
        Self { original:ReadinessOriginal::Fixture {valid,calls,delay:Duration::ZERO,panic:false,veto_at:None},
            assignment:ReadinessAssignment::EmptyFixture,failed,end,client_end:end,phase:ReadinessPhase::InitialProbe }
    }
    pub(crate) fn veto(&mut self) {
        // Infallible negative state precedes stream shutdown/close and any
        // later native original-assignment or retained-file destruction.
        self.failed.store(true,Ordering::SeqCst);
        self.assignment.veto();
        match &mut self.original {
            ReadinessOriginal::Native {peer,..} => {
                if let Some(peer)=peer { peer.poisoned=true; }
            },
            #[cfg(test)] ReadinessOriginal::Fixture {valid,..} => valid.store(false,Ordering::SeqCst),
        }
    }
    pub(crate) fn current(&mut self,requested_end:Instant,stream:Option<&UnixStream>)->EnclaveResult<()> {
        let mut check=ReadinessCheck {failed:self.failed,armed:true};
        if self.failed.load(Ordering::SeqCst) {fail!(EACCES,"SUPERVISOR_DEPENDENCY_POISONED");}
        if requested_end!=self.end || self.end>self.client_end {fail!(EACCES,"SUPERVISOR_DEPENDENCY_ENDPOINT_CHANGED");}
        let end=self.end;within(end)?;
        match &mut self.original {
            ReadinessOriginal::Native {checked,descriptor,pins,peer} => {
                selection(checked,end)?;within(end)?;
                descriptor.current()?;within(end)?;pins.current()?;within(end)?;
                self.assignment.current(self.phase,end)?;
                match peer {
                    Some(peer) => {
                        if peer.poisoned {fail!(EACCES,"SUPERVISOR_DEPENDENCY_PEER_POISONED");}
                        let stream=stream.ok_or_else(||err!(EACCES,"SUPERVISOR_DEPENDENCY_STREAM_REQUIRED"))?;
                        let fresh=authenticate_original_root(stream,end)?;peer.same(&fresh)?;within(end)?;
                    },
                    None if self.phase==ReadinessPhase::Connect => {},
                    None => fail!(EACCES,"SUPERVISOR_DEPENDENCY_PEER_REQUIRED"),
                }
                self.assignment.current(self.phase,end)?;
                descriptor.current()?;within(end)?;pins.current()?;within(end)?;selection(checked,end)?;
            },
            #[cfg(test)]
            ReadinessOriginal::Fixture {valid,calls,delay,panic,veto_at} => {
                let call=calls.fetch_add(1,Ordering::SeqCst)+1;
                if *veto_at==Some(call) {valid.store(false,Ordering::SeqCst);}
                if !valid.load(Ordering::SeqCst) {fail!(EACCES,"SUPERVISOR_DEPENDENCY_FIXTURE_CONTEXT");}
                if !delay.is_zero() {std::thread::sleep(*delay);}
                if *panic {panic!("SCRIPTED_READINESS_CONTEXT_UNWIND");}
                if !valid.load(Ordering::SeqCst) {fail!(EACCES,"SUPERVISOR_DEPENDENCY_FIXTURE_CONTEXT");}
                self.assignment.current(self.phase,end)?;
                self.assignment.current(self.phase,end)?;
            },
        }
        within(end)?;
        if self.failed.load(Ordering::SeqCst) {fail!(EACCES,"SUPERVISOR_DEPENDENCY_POISONED");}
        check.armed=false;Ok(())
    }
    pub(crate) fn authenticate(&mut self,stream:&UnixStream,end:Instant)->EnclaveResult<()> {
        self.current(end,Some(stream))?;
        match &mut self.original {
            ReadinessOriginal::Native {peer,..} => {
                if self.phase!=ReadinessPhase::Connect || peer.is_some() {fail!(EACCES,"SUPERVISOR_DEPENDENCY_PEER_CHANGED");}
                let authenticated=authenticate_original_root(stream,end)?;
                **peer=Some(RootPeerPin::new(authenticated)?);
            },
            #[cfg(test)] ReadinessOriginal::Fixture {..} => {},
        }
        self.current(end,Some(stream))
    }
    pub(crate) fn frame_end(&self,requested_end:Instant)->EnclaveResult<Instant> {
        if requested_end!=self.end || self.failed.load(Ordering::SeqCst) {fail!(EACCES,"SUPERVISOR_DEPENDENCY_ENDPOINT_CHANGED");}
        within(requested_end)?;
        // Preserve existing per-frame2s budget, capped by exact original end.
        Ok(requested_end.min(Instant::now().checked_add(PROBE).ok_or_else(||err!(EINVAL,"SUPERVISOR_DEPENDENCY_DEADLINE"))?))
    }
    fn complete_probe(&mut self)->EnclaveResult<()> {self.assignment.complete_probe(self.phase)}

}

fn retire_readiness_stream(stream:&mut Option<UnixStream>) {
    if let Some(original)=stream.take() { let _=original.shutdown(std::net::Shutdown::Both); }
}
// Constructed before socket creation; on final client Drop this field is
// retired before any original descriptor, pin or assignment field can drop.
struct ReadinessTransport {stream:Option<UnixStream>,failed:AtomicBool}
impl ReadinessTransport {fn new()->Self {Self {stream:None,failed:AtomicBool::new(false)}}}
impl Drop for ReadinessTransport {
    fn drop(&mut self) {self.failed.store(true,Ordering::SeqCst);retire_readiness_stream(&mut self.stream);}
}
// Distinct outer veto survives raw transport success and stays armed during
// strict decoding,19-term validation, original readback and final postchecks.
struct ReadinessOperation<'io,'owner> {
    guard:SelectedReadinessIoGuard<'owner>,stream:&'io mut Option<UnixStream>,armed:bool,
}
impl ReadinessOperation<'_, '_> {
    fn current(&mut self)->EnclaveResult<()> {self.guard.current(self.guard.end,self.stream.as_ref())}
    fn complete(&mut self) {self.armed=false;}
}
impl Drop for ReadinessOperation<'_, '_> {
    fn drop(&mut self) {if self.armed {self.guard.veto();retire_readiness_stream(self.stream);}}
}

/// One native selected custody operation's actual authenticated connection.
/// No constructor accepts a stream, receipt, provider, UID or ready flag.
pub struct SelectedReadinessClient {
    transport:ReadinessTransport,
    checked:&'static CheckedDeploymentTarget,descriptor:Input,pins:Input,
    binding:Binding,instance:Option<[u8;32]>,end:Instant,
    peer:Option<RootPeerPin>,assignment:TaskAssignment<crate::resource::SelectedExceptionAssignment>,
}
impl SelectedReadinessClient {
    /// Authenticate the selected root CTL supervisor before any request bytes.
    /// Native code verification is synchronous; late completion is refused.
    pub fn connect_custody(end:Instant)->EnclaveResult<Self> {
        let mut transport=ReadinessTransport::new();
        if !cfg!(target_os="macos") {fail!(ENOSYS,"SUPERVISOR_DEPENDENCY_NATIVE_REQUIRED");}
        if ipc::geteuid()!=DaemonId::CustodyVault.uid() {fail!(EPERM,"SUPERVISOR_DEPENDENCY_CUSTODY_REQUIRED");}
        let checked=deployment::selected().ok_or_else(||err!(EACCES,"DEPLOYMENT_CONTEXT_REQUIRED"))?;
        let end=end.min(Instant::now().checked_add(PREFLIGHT).ok_or_else(||err!(EINVAL,"SUPERVISOR_DEPENDENCY_DEADLINE"))?);
        selection(checked,end)?;
        let descriptor=Input::open(checked.config_path())?;within(end)?;
        let pins=Input::open(&checked.target().codesign_pins_file)?;within(end)?;
        if descriptor.hash!=checked.descriptor_sha256() {fail!(ESTALE,"DEPLOYMENT_CHANGED");}
        // Complete all allocating output construction before socket creation
        // and before the final armed publication check. Publication is moves.
        let binding=Binding::selected(checked);within(end)?;
        let mut peer=None;let mut assignment=TaskAssignment::new();
        {
            let guard=SelectedReadinessIoGuard::native(checked,&descriptor,&pins,&mut peer,&mut assignment,
                &transport.failed,end,end,ReadinessPhase::Connect);
            let mut operation=ReadinessOperation {guard,stream:&mut transport.stream,armed:true};
            let path=checked.target().layout.socket_root.join(LEAF);
            ipc::connect_selected_readiness_until(&path,operation.stream,&mut operation.guard,end)?;
            operation.current()?;operation.complete();
        }
        Ok(Self {transport,checked,descriptor,pins,binding,instance:None,end,peer,assignment})
    }
    /// Freshly inspect every mandatory term on the same stream and instance.
    /// Any error/unwind irreversibly poisons this operation; no reconnect/retry.
    pub fn probe(&mut self,end:Instant)->EnclaveResult<()> {
        let end=end.min(self.end);
        let phase=if self.assignment.initial_observed {ReadinessPhase::AssignedProbe}else{ReadinessPhase::InitialProbe};
        let guard=SelectedReadinessIoGuard::native(self.checked,&self.descriptor,&self.pins,&mut self.peer,
            &mut self.assignment,&self.transport.failed,end,self.end,phase);
        let mut operation=ReadinessOperation {guard,stream:&mut self.transport.stream,armed:true};
        operation.current()?;
        exchange_owned(&mut operation,&self.binding,&mut self.instance,end)?;
        operation.current()?;operation.guard.complete_probe()?;operation.complete();Ok(())
    }
    /// Assign the calling live custody task to the actual selected Mach service.
    /// This is a real kernel effect, separate from the server's wire observations.
    pub fn assign_current_task(&mut self,end:Instant)->EnclaveResult<()> {
        let end=end.min(self.end);
        let guard=SelectedReadinessIoGuard::native(self.checked,&self.descriptor,&self.pins,&mut self.peer,
            &mut self.assignment,&self.transport.failed,end,self.end,ReadinessPhase::Assignment);
        let mut operation=ReadinessOperation {guard,stream:&mut self.transport.stream,armed:true};
        operation.current()?;
        if self.instance.is_none() || ipc::geteuid()!=DaemonId::CustodyVault.uid() {
            fail!(EACCES,"SUPERVISOR_DEPENDENCY_ASSIGNMENT_ORDER");
        }
        match &mut operation.guard.assignment {
            ReadinessAssignment::Native(assignment)=>
                assignment.assign(end,crate::resource::SelectedExceptionAssignment::assign_current)?,
            #[cfg(test)] _=>unreachable!(),
        }
        operation.current()?;
        operation.guard.phase=ReadinessPhase::AssignedProbe;
        // The SAME outer veto stays armed through the followup probe. A valid
        // inner raw exchange cannot rehabilitate outer error or unwind.
        exchange_owned(&mut operation,&self.binding,&mut self.instance,end)?;
        operation.current()?;operation.guard.complete_probe()?;operation.complete();Ok(())
    }
}

// A private lifetime algorithm used by the concrete owner, not a readiness
// provider. Software fixtures exercise only its terminal/ordering behavior;
// the public production constructor accepts the opaque native session only.
pub(super) trait SessionDependency {
    fn current(&self)->EnclaveResult<()>;
    fn revoke(&self);
    fn original_end(&self)->Instant;
}
impl SessionDependency for Arc<crate::power::selected_owner_session::SelectedOwnerSession> {
    fn current(&self)->EnclaveResult<()> {self.require_current()}
    fn revoke(&self) {self.as_ref().revoke();}
    fn original_end(&self)->Instant {self.original_instant_end()}
}
pub(super) struct SessionLifetime<S:SessionDependency> {
    pub(super) session:S,pub(super) stop:Arc<AtomicBool>,pub(super) end:Instant,
}
struct SessionCheck<'a,S:SessionDependency> {owner:&'a SessionLifetime<S>,armed:bool}
impl<S:SessionDependency> Drop for SessionCheck<'_,S> {
    fn drop(&mut self) {if self.armed {self.owner.stop();}}
}
impl<S:SessionDependency> SessionLifetime<S> {
    pub(super) fn new(session:S,stop:Arc<AtomicBool>)->Self {
        let end=session.original_end();Self {session,stop,end}
    }
    pub(super) fn stop(&self) {
        // SAME terminal session veto precedes every potentially blocking cleanup.
        self.session.revoke();self.stop.store(true,Ordering::SeqCst);
    }
    fn checked<T>(&self,operation:impl FnOnce()->EnclaveResult<T>)->EnclaveResult<T> {
        // Caught unwind must not leave the original session reusable either.
        let mut guard=SessionCheck {owner:self,armed:true};
        let result=(|| {
            if self.stop.load(Ordering::SeqCst) {fail!(EACCES,"SUPERVISOR_DEPENDENCY_STOPPED");}
            within(self.end)?;self.session.current()?;
            let value=operation()?;
            // Declared AFTER a newly returned owner: postcheck refusal/unwind
            // revokes SAME session before that owner's Drop can block.
            let mut returned=SessionCheck {owner:self,armed:true};
            self.session.current()?;within(self.end)?;
            if self.stop.load(Ordering::SeqCst) {fail!(EACCES,"SUPERVISOR_DEPENDENCY_STOPPED");}
            returned.armed=false;Ok(value)
        })();
        if result.is_ok() {guard.armed=false;}result
    }
    pub(super) fn current(&self)->EnclaveResult<()> {self.checked(||Ok(()))}
    pub(super) fn shorten(&mut self,end:Instant)->EnclaveResult<()> {
        self.end=self.end.min(end);self.current()
    }
}
impl<S:SessionDependency> Drop for SessionLifetime<S> {fn drop(&mut self){self.stop();}}

// Retain each actual returned owner BEFORE the session's postchecks. A failed
// constructor is consumed, and cannot be retried by replacing its original.
// This private seam supplies no production owner, policy or readiness evidence.
struct PreparedSlot<T> {owner:Option<T>,attempted:bool}
impl<T> PreparedSlot<T> {
    fn empty()->Self {Self {owner:None,attempted:false}}
    fn construct<S:SessionDependency>(&mut self,lifetime:&SessionLifetime<S>,
        operation:impl FnOnce(Instant)->EnclaveResult<T>)->EnclaveResult<()> {
        if self.attempted {lifetime.stop();fail!(EACCES,"SUPERVISOR_PREPARATION_ALREADY_ATTEMPTED");}
        self.attempted=true;
        lifetime.checked(||{self.owner=Some(operation(lifetime.end)?);Ok(())})
    }
    fn get(&mut self)->&mut T {self.owner.as_mut().expect("successful original construction")}
    fn take(&mut self)->T {self.owner.take().expect("successful original construction")}
}

// Private negative-only sequencing. Production fixes N to the retained native
// notification owner and S to the SAME opaque selected-session allocation.
trait NotificationDependency<S:SessionDependency> {
    type Collection<'a>:super::pf_watch::NegativeCollectionCheck where Self:'a;
    fn begin_collection(&self,end:Instant)->EnclaveResult<Self::Collection<'_>>;
    fn require_original(&self,session:&S,stop:&Arc<AtomicBool>,end:Instant)->EnclaveResult<()>;
    fn observe_progress(&self,end:Instant)->EnclaveResult<()>;
    fn request_stop(&self);
}
#[cfg(target_os="macos")]
impl NotificationDependency<Arc<crate::power::selected_owner_session::SelectedOwnerSession>>
    for super::pf_watch::PfNotifications {
    type Collection<'a>=super::pf_watch::NegativeCollectionWindow<'a>;
    fn begin_collection(&self,end:Instant)->EnclaveResult<Self::Collection<'_>> {
        self.begin_collection_window(end)
    }
    fn require_original(&self,session:&Arc<crate::power::selected_owner_session::SelectedOwnerSession>,
        stop:&Arc<AtomicBool>,end:Instant)->EnclaveResult<()> {
        self.require_same_original(session,stop,end)
    }
    fn observe_progress(&self,end:Instant)->EnclaveResult<()> {
        // Challenge BOTH real retained workers under the SAME shortening cap.
        // This narrow health check grants none of the twelve PF ready terms:
        // configd session continuity remains unavailable, and its mandatory
        // query invalidation may advance generation during a healthy sample.
        super::pf_watch::PfNotifications::observe_current(self,end).map(|_|())
    }
    fn request_stop(&self) {super::pf_watch::PfNotifications::request_stop(self);}
}
fn stop_notification<S:SessionDependency,N:NotificationDependency<S>>(
    lifetime:&SessionLifetime<S>,notification:&N) {
    lifetime.stop();notification.request_stop();
}
struct NotificationCleanup<'a,S:SessionDependency,N:NotificationDependency<S>> {
    session:&'a S,stop:&'a Arc<AtomicBool>,notification:&'a N,armed:bool,
}
impl<S:SessionDependency,N:NotificationDependency<S>> Drop for NotificationCleanup<'_,S,N> {
    fn drop(&mut self) {if self.armed {
        self.session.revoke();self.stop.store(true,Ordering::SeqCst);
        self.notification.request_stop();
    }}
}
fn require_notification<S:SessionDependency,N:NotificationDependency<S>>(
    lifetime:&SessionLifetime<S>,notification:&N,end:Instant)->EnclaveResult<()> {
    let end=end.min(lifetime.end);
    let mut guard=NotificationCleanup {session:&lifetime.session,stop:&lifetime.stop,notification,armed:true};
    // Check original pointer bindings BEFORE filesystem/native session work.
    notification.require_original(&lifetime.session,&lifetime.stop,end)?;
    lifetime.checked(||{
        within(end)?;notification.observe_progress(end)?;within(end)
    })?;
    // Keep the same armed veto through all observer/session postchecks. The
    // caller's shorter endpoint cannot be renewed by progress or native work.
    notification.require_original(&lifetime.session,&lifetime.stop,end)?;
    lifetime.current()?;within(end)?;
    guard.armed=false;Ok(())
}

// Negative collection sequencing only. Production fixes P to the actual
// retained PF owner; this private seam cannot supply positive ready terms.
trait ReadOnlyPfDependency<S:SessionDependency> {
    fn require_original(&self,session:&S,stop:&Arc<AtomicBool>,end:Instant)->EnclaveResult<()>;
    fn require_health_until<C:super::pf_watch::NegativeCollectionCheck>(&mut self,end:Instant,collection:&C)->EnclaveResult<()>;
    fn veto(&self);
}
#[cfg(target_os="macos")]
impl ReadOnlyPfDependency<Arc<crate::power::selected_owner_session::SelectedOwnerSession>>
    for super::pf_observation::RetainedReadOnlyOwner {
    fn require_original(&self,session:&Arc<crate::power::selected_owner_session::SelectedOwnerSession>,
        stop:&Arc<AtomicBool>,end:Instant)->EnclaveResult<()> {
        super::pf_observation::RetainedReadOnlyOwner::require_original(self,session,stop,end)
    }
    fn require_health_until<C:super::pf_watch::NegativeCollectionCheck>(&mut self,end:Instant,collection:&C)->EnclaveResult<()> {
        super::pf_observation::RetainedReadOnlyOwner::require_health_until(self,end,collection)
    }
    fn veto(&self) {super::pf_observation::RetainedReadOnlyOwner::veto(self);}
}
struct ReadOnlyPfCleanup<'a,S:SessionDependency,P:ReadOnlyPfDependency<S>> {
    session:&'a S,stop:&'a Arc<AtomicBool>,pf:&'a mut P,armed:bool,
}
impl<S:SessionDependency,P:ReadOnlyPfDependency<S>> Drop for ReadOnlyPfCleanup<'_,S,P> {
    fn drop(&mut self) {if self.armed {
        self.session.revoke();self.stop.store(true,Ordering::SeqCst);self.pf.veto();
    }}
}
fn require_readonly_pf<S:SessionDependency,N:NotificationDependency<S>,P:ReadOnlyPfDependency<S>>(
    lifetime:&SessionLifetime<S>,notification:&N,pf:&mut P,end:Instant)->EnclaveResult<()> {
    let end=end.min(lifetime.end);
    let mut notification_guard=NotificationCleanup {session:&lifetime.session,stop:&lifetime.stop,notification,armed:true};
    let mut guard=ReadOnlyPfCleanup {session:&lifetime.session,stop:&lifetime.stop,pf,armed:true};
    // Identity/cap reads precede any native/filesystem session or PF work.
    notification.require_original(&lifetime.session,&lifetime.stop,end)?;
    guard.pf.require_original(&lifetime.session,&lifetime.stop,lifetime.end)?;
    // Mandatory actual notification owner borrow spans every query and
    // final check. A fresh challenge occurs only BEFORE this fixed window.
    let collection=notification.begin_collection(end)?;
    lifetime.checked(||{
        within(end)?;guard.pf.require_health_until(end,&collection)?;within(end)
    })?;
    guard.pf.require_original(&lifetime.session,&lifetime.stop,lifetime.end)?;
    notification.require_original(&lifetime.session,&lifetime.stop,end)?;
    lifetime.current()?;within(end)?;
    super::pf_watch::NegativeCollectionCheck::complete(collection,end)?;
    notification_guard.armed=false;guard.armed=false;Ok(())
}

// A partial root construction owns every returned object until handoff. Its
// Drop body revokes first, while all monitor/socket/worker originals still live.
#[cfg(target_os="macos")]
struct RootPreparation {
    transferred:bool,
    primary:PreparedSlot<super::selected_accept::PrimaryAccept>,
    held:PreparedSlot<super::selected_accept::HeldAccept>,
    mach:PreparedSlot<super::mach_exception::ExceptionListener>,
    originals:PreparedSlot<super::selected_runtime::SelectedRuntime>,
    notifications:PreparedSlot<super::pf_watch::PfNotifications>,
    pf:PreparedSlot<super::pf_observation::RetainedReadOnlyOwner>,
    monitor:PreparedSlot<Arc<crate::power::darwin::PowerMonitor>>,
    lifetime:Option<SessionLifetime<Arc<crate::power::selected_owner_session::SelectedOwnerSession>>>,
    listener_stop:crate::power::selected_owner_listener::RootSelectedOwnerListenerStop,
}
#[cfg(target_os="macos")]
impl Drop for RootPreparation {
    fn drop(&mut self) {
        if self.transferred {return;}
        if let Some(pf)=&self.pf.owner {pf.veto();}
        if let Some(lifetime)=&self.lifetime {
            if let Some(notifications)=&self.notifications.owner {stop_notification(lifetime,notifications);}
            else {lifetime.stop();}
        } else if let Some(notifications)=&self.notifications.owner {notifications.request_stop();}
        self.listener_stop.stop();
        if let Some(originals)=&self.originals.owner {originals.stop_selected_owner();}
    }
}

// Concrete original named sockets AND their actual accept-loop owners are
// retained. A status bool, cloned progress or wire report cannot populate them.
#[cfg(target_os="macos")]
pub(super) struct ReadinessOwner {
    // Drop workers while the original routes, monitor and session remain held.
    primary:super::selected_accept::PrimaryAccept,held:super::selected_accept::HeldAccept,
    mach:super::mach_exception::ExceptionListener,originals:super::selected_runtime::SelectedRuntime,
    notifications:super::pf_watch::PfNotifications,
    pf:super::pf_observation::RetainedReadOnlyOwner,
    monitor:Arc<crate::power::darwin::PowerMonitor>,
    lifetime:SessionLifetime<Arc<crate::power::selected_owner_session::SelectedOwnerSession>>,
    checked:&'static CheckedDeploymentTarget,pins:Input,instance:[u8;32],
}
#[cfg(target_os="macos")]
impl ReadinessOwner {
    /// Concrete root pre-start composition only. This is deliberately NOT
    /// called by public selected dispatch while PF and Begin gates are absent.
    /// No paths, session endpoints, provider handles or authority are invented.
    pub(super) fn prepare(socket_dir:&Path,profile:Profile,stop:Arc<AtomicBool>,
        enclosing_end:Instant)->EnclaveResult<Self> {
        require_ipc_admission(&IPC_CLEANUP_UNKNOWN)?; // Before a new native session/effect.
        within(enclosing_end)?;
        if stop.load(Ordering::SeqCst) {fail!(EACCES,"SUPERVISOR_DEPENDENCY_STOPPED");}
        let checked=deployment::selected().ok_or_else(||err!(EACCES,"DEPLOYMENT_CONTEXT_REQUIRED"))?;
        if ipc::geteuid()!=0 {fail!(EPERM,"SUPERVISOR_DEPENDENCY_ROOT_REQUIRED");}
        selection(checked,enclosing_end)?;
        if profile!=checked.target().profile || socket_dir!=checked.target().layout.socket_root {
            fail!(EACCES,"SUPERVISOR_PREPARATION_SCOPE");
        }
        // Permanent actual startup SH PRECEDES the monitor and all native
        // service effects. Capture only the already-provisioned per-boot input.
        deployment::startup_lease::retain_selected_startup_lease()?;
        deployment::startup_lease::require_retained_selected_startup_lease(enclosing_end)?;
        let session=Arc::new(crate::power::selected_owner_session::SelectedOwnerSession::capture()?);
        let mut lifetime=SessionLifetime::new(session,stop);
        lifetime.shorten(enclosing_end)?;
        let listener_stop=crate::power::selected_owner_listener::RootSelectedOwnerListenerStop::new(lifetime.end);
        let mut partial=RootPreparation {transferred:false,lifetime:Some(lifetime),listener_stop,
            originals:PreparedSlot::empty(),notifications:PreparedSlot::empty(),pf:PreparedSlot::empty(),monitor:PreparedSlot::empty(),mach:PreparedSlot::empty(),
            held:PreparedSlot::empty(),primary:PreparedSlot::empty()};
        let lifetime=partial.lifetime.as_ref().expect("retained original lifetime");
        partial.originals.construct(lifetime,|end|Ok(super::selected_runtime::SelectedRuntime::acquire_selected(socket_dir,profile,end)))?;
        lifetime.checked(||partial.originals.get().require_current(lifetime.end))?;
        // Retain even a refused/partial owner before postchecks or any later
        // monitor/HID/Mach/socket effect. These checks grant no PF ready term.
        partial.notifications.construct(lifetime,|end|Ok(super::pf_watch::PfNotifications::start_selected(
            lifetime.session.clone(),lifetime.stop.clone(),end)))?;
        require_notification(lifetime,partial.notifications.get(),lifetime.end)?;
        // Store the actual partial PF owner before all session postchecks.
        // Its bound constructor installs SAME session/stop/end before admission.
        partial.pf.construct(lifetime,|end|Ok(super::pf_observation::RetainedReadOnlyOwner::prepare_selected_bound(
            lifetime.session.clone(),lifetime.stop.clone(),end)))?;
        require_readonly_pf(lifetime,partial.notifications.get(),partial.pf.get(),lifetime.end)?;
        partial.monitor.construct(lifetime,|end|{
            deployment::startup_lease::require_retained_selected_startup_lease(end)?;
            crate::power::start_for_profile(profile,crate::power::darwin::PowerMonitor::start)?
                .map(Arc::new).ok_or_else(||err!(EACCES,"SUPERVISOR_PREPARATION_MONITOR_REQUIRED"))
        })?;
        lifetime.checked(||partial.originals.get().prepare_selected_owner(partial.monitor.get().clone(),
            lifetime.session.clone(),lifetime.end,lifetime.end,&partial.listener_stop))?;
        let tracker=Arc::new(super::RespawnTracker::new());
        partial.mach.construct(lifetime,|end|{
            let comparison=partial.originals.get().selected_owner_actor_comparison(
                partial.monitor.get(),&lifetime.session,end)?;
            super::mach_exception::start_selected_exception_listener(
                socket_dir.to_path_buf(),tracker.clone(),lifetime.stop.clone(),
                lifetime.session.clone(),end,comparison)
        })?;
        partial.held.construct(lifetime,|end|{
            let socket=super::selected_socket::HeldSocket::bind(partial.originals.get(),end);
            Ok(super::selected_accept::HeldAccept::start(socket,partial.originals.get(),lifetime.stop.clone(),end))
        })?;
        lifetime.checked(||partial.held.get().observe_health(partial.originals.get(),lifetime.end))?;
        partial.primary.construct(lifetime,|end|{
            let socket=super::selected_socket::PrimarySocket::bind(partial.originals.get(),end);
            Ok(super::selected_accept::PrimaryAccept::start(socket,partial.originals.get(),tracker,
                partial.held.get(),lifetime.stop.clone(),end))
        })?;
        lifetime.checked(||partial.primary.get().observe_health(partial.originals.get(),lifetime.end))?;
        // Move the SAME shortened lifetime and actual workers. The receiving
        // constructor's guard is declared after all inputs before any checks.
        let result=Self::new_with_lifetime(partial.originals.take(),partial.monitor.take(),
            partial.mach.take(),partial.primary.take(),partial.held.take(),
            partial.notifications.take(),partial.pf.take(),
            partial.lifetime.take().expect("retained original lifetime"));
        // The original listener stop is now retained inside selected_runtime.
        // Suppress only this transferred duplicate's stop; no owner is replaced.
        if result.is_ok() {partial.transferred=true;}
        result
    }

    /// Private pre-start composition only; no startup permit is returned.
    /// Original startup SH must predate the caller's SAME native monitor.
    pub(super) fn new(originals:super::selected_runtime::SelectedRuntime,
        monitor:Arc<crate::power::darwin::PowerMonitor>,
        session:Arc<crate::power::selected_owner_session::SelectedOwnerSession>,
        mach:super::mach_exception::ExceptionListener,
        primary:super::selected_accept::PrimaryAccept,held:super::selected_accept::HeldAccept,
        notifications:super::pf_watch::PfNotifications,
        pf:super::pf_observation::RetainedReadOnlyOwner,
        stop:Arc<AtomicBool>)->EnclaveResult<Self> {
        let lifetime=SessionLifetime::new(session,stop);
        Self::new_with_lifetime(originals,monitor,mach,primary,held,notifications,pf,lifetime)
    }
    fn new_with_lifetime(mut originals:super::selected_runtime::SelectedRuntime,
        monitor:Arc<crate::power::darwin::PowerMonitor>,
        mut mach:super::mach_exception::ExceptionListener,
        mut primary:super::selected_accept::PrimaryAccept,mut held:super::selected_accept::HeldAccept,
        notifications:super::pf_watch::PfNotifications,
        mut pf:super::pf_observation::RetainedReadOnlyOwner,
        lifetime:SessionLifetime<Arc<crate::power::selected_owner_session::SelectedOwnerSession>>,
    )->EnclaveResult<Self> {
        // This guard is declared after every input owner, so refusal/unwind
        // revokes SAME session before any argument's native teardown can block.
        let mut lifetime=lifetime;
        // Clone only passive Arc ownership of the SAME session/stop allocation.
        // This guard outlives every fallible check and vetoes PF before any
        // argument owner can enter potentially blocking native cleanup.
        let guard_session=lifetime.session.clone();let guard_stop=lifetime.stop.clone();
        let mut notification_cleanup=NotificationCleanup {session:&guard_session,stop:&guard_stop,
            notification:&notifications,armed:true};
        let mut pf_cleanup=ReadOnlyPfCleanup {session:&guard_session,stop:&guard_stop,pf:&mut pf,armed:true};
        let end=(Instant::now()+PROBE).min(lifetime.end);
        // FIRST check binds the retained actor using pointer/cap reads only.
        // Its mismatch veto has no socket/native stop: the armed guard can
        // therefore veto the distinct PF original before argument cleanup.
        originals.selected_owner_input_binding(&monitor,&lifetime.session)?;
        pf_cleanup.pf.require_original(&lifetime.session,&lifetime.stop,lifetime.end)?;
        // Now a PF mismatch also revokes the known SAME actual actor session.
        require_notification(&lifetime,&notifications,end)?;
        // Original selected actor/monitor identities remain independently required.
        // A wrong offered session cannot leave the retained original session
        // live while primary/held argument cleanup starts on this refusal.
        let original_end=originals.selected_owner_lifetime(&monitor,&lifetime.session,end)?;
        lifetime.shorten(original_end)?;
        let end=end.min(lifetime.end);
        let checked=deployment::selected().ok_or_else(||err!(EACCES,"DEPLOYMENT_CONTEXT_REQUIRED"))?;
        if ipc::geteuid()!=0 {fail!(EPERM,"SUPERVISOR_DEPENDENCY_ROOT_REQUIRED");}
        selection(checked,end)?;
        deployment::startup_lease::require_retained_selected_startup_lease(end)?;
        primary.require_stop(&lifetime.stop)?;held.require_stop(&lifetime.stop)?;
        let mach_end=mach.require_selected(&lifetime.session,&lifetime.stop)?;
        lifetime.shorten(mach_end)?;
        let end=end.min(lifetime.end);
        lifetime.checked(||held.observe_health(&mut originals,end))?;
        lifetime.checked(||primary.observe_health(&mut originals,end))?;
        lifetime.checked(||monitor.observe_health(end))?;
        lifetime.checked(||mach.observe_health(end))?;
        let pins=lifetime.checked(||Input::open(&checked.target().codesign_pins_file))?;
        require_notification(&lifetime,&notifications,end)?;
        require_readonly_pf(&lifetime,&notifications,pf_cleanup.pf,end)?;
        lifetime.current()?;
        let instance=crate::rng::bytes32();
        pf_cleanup.armed=false;drop(pf_cleanup);
        notification_cleanup.armed=false;drop(notification_cleanup);
        Ok(Self {originals,monitor,lifetime,mach,primary,held,notifications,pf,checked,pins,instance})
    }
    fn stop(&self) {
        self.pf.veto();stop_notification(&self.lifetime,&self.notifications);self.originals.stop_selected_owner();
    }
    fn sample(&mut self,request:Request,end:Instant)->Observation {
        let end=end.min(self.lifetime.end);
        // Remain armed across all other original samples and wire construction.
        // Any caught unwind revokes SAME session+stop+PF before owner cleanup.
        let mut pf_cleanup=ReadOnlyPfCleanup {session:&self.lifetime.session,stop:&self.lifetime.stop,
            pf:&mut self.pf,armed:true};
        let mut terms=REQUIRED.into_iter().map(|term|(term,Outcome::Missing)).collect::<BTreeMap<_,_>>();
        let mut retained_errors=Vec::new();let started_boot_ns=crate::clock::boot_clock_ns();
        // Real worker health is a negative prerequisite only; no PF term is observed.
        if let Err(error)=require_notification(&self.lifetime,&self.notifications,end) {retained_errors.push(error.reason);}
        if let Err(error)=require_readonly_pf(&self.lifetime,&self.notifications,pf_cleanup.pf,end) {retained_errors.push(error.reason);}
        // Session validity is a negative prerequisite, not a positive ready term.
        // Check it before/after EACH possibly blocking original-owner sample.
        let mut record=|term,result:EnclaveResult<()>|{
            match result {
                Ok(())=>{if !matches!(terms.get(&term),Some(Outcome::Refused(_))) {terms.insert(term,Outcome::Observed);}},
                Err(error)=>{self.lifetime.stop();retained_errors.push(error.reason.clone());terms.insert(term,Outcome::Refused(error.reason));},
            }
        };
        record(Term::Context,self.lifetime.checked(||selection(self.checked,end)));
        record(Term::StartupLease,self.lifetime.checked(||deployment::startup_lease::require_retained_selected_startup_lease(end)));
        record(Term::Originals,self.lifetime.checked(||self.originals.require_current(end)));
        record(Term::PowerUsb,self.lifetime.checked(||self.monitor.observe_health(end)));
        record(Term::Mach,self.lifetime.checked(||self.mach.observe_health(end)));
        record(Term::HeldWorker,self.lifetime.checked(||self.held.observe_health(&mut self.originals,end)));
        record(Term::PrimaryWorker,self.lifetime.checked(||self.primary.observe_health(&mut self.originals,end)));
        // Recheck the SAME originals after all intervening samples. Do not
        // overwrite an earlier refusal with a later successful observation.
        record(Term::Context,self.lifetime.checked(||selection(self.checked,end)));
        record(Term::StartupLease,self.lifetime.checked(||deployment::startup_lease::require_retained_selected_startup_lease(end)));
        record(Term::Originals,self.lifetime.checked(||self.originals.require_current(end)));
        record(Term::PowerUsb,self.lifetime.checked(||self.monitor.observe_health(end)));
        record(Term::Mach,self.lifetime.checked(||self.mach.observe_health(end)));
        record(Term::HeldWorker,self.lifetime.checked(||self.held.observe_health(&mut self.originals,end)));
        record(Term::PrimaryWorker,self.lifetime.checked(||self.primary.observe_health(&mut self.originals,end)));
        // PF omissions cannot be supplied by P2/P3 reports or status bools.
        // Actual concrete enforcement owners must replace them separately.
        if let Err(error)=self.lifetime.checked(||{self.pins.current()?;within(end)}) {retained_errors.push(error.reason);}
        if let Err(error)=require_readonly_pf(&self.lifetime,&self.notifications,pf_cleanup.pf,end) {retained_errors.push(error.reason);}
        if let Err(error)=require_notification(&self.lifetime,&self.notifications,end) {retained_errors.push(error.reason);}
        let observation=Observation {version:1,kind:"mcpmac-selected-supervisor-observation".into(),challenge:request.challenge,
            binding:Binding::selected(self.checked),instance:self.instance,started_boot_ns,ended_boot_ns:crate::clock::boot_clock_ns(),terms,retained_errors};
        if observation.retained_errors.is_empty() {pf_cleanup.armed=false;}
        observation
    }
}
#[cfg(target_os="macos")]
impl Drop for ReadinessOwner {fn drop(&mut self){self.stop();}}

struct BoundSocket {parent:File,parent_stamp:Stamp,path:PathBuf,socket_stamp:Stamp,listener:UnixListener}
impl BoundSocket {
    fn bind(parent:&File,root:&Path)->EnclaveResult<Self> {
        let path=deployment::normalized_path(root)?.join(LEAF);
        let parent=parent.try_clone().map_err(|_|err!(EIO,"SUPERVISOR_DEPENDENCY_PARENT"))?;
        let before=parent.metadata().map_err(|_|err!(EIO,"SUPERVISOR_DEPENDENCY_PARENT"))?;
        fd(&parent)?;
        if !before.is_dir() || before.uid()!=0 || before.gid()!=0 || before.mode()&0o7777!=0o755 {fail!(EACCES,"SUPERVISOR_DEPENDENCY_PARENT");}
        let leaf=name(&path)?;let mut metadata=std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe{libc::fstatat(parent.as_raw_fd(),leaf.as_ptr(),metadata.as_mut_ptr(),libc::AT_SYMLINK_NOFOLLOW)}==0 {
            fail!(EALREADY,"SUPERVISOR_DEPENDENCY_SOCKET_EXISTS");
        }
        if std::io::Error::last_os_error().raw_os_error()!=Some(libc::ENOENT) {fail!(EACCES,"SUPERVISOR_DEPENDENCY_SOCKET_UNKNOWN");}
        // Bind before listen: no connection or frame can be accepted before the
        // actual newly-created name has its final restrictive DAC/protection.
        let mut address:libc::sockaddr_un=unsafe{std::mem::zeroed()};let bytes=path.as_os_str().as_bytes();
        if bytes.len()>=address.sun_path.len() {fail!(EINVAL,"SUPERVISOR_DEPENDENCY_PATH");}
        address.sun_family=libc::AF_UNIX as _;for (a,b) in address.sun_path.iter_mut().zip(bytes) {*a=*b as _;}
        let length=std::mem::offset_of!(libc::sockaddr_un,sun_path)+bytes.len()+1;
        #[cfg(target_os="macos")] {address.sun_len=length as _;}
        let raw=unsafe{libc::socket(libc::AF_UNIX,libc::SOCK_STREAM,0)};
        if raw<0 {fail!(EIO,"SUPERVISOR_DEPENDENCY_BIND");}
        let listener=unsafe{UnixListener::from_raw_fd(raw)};
        if unsafe{libc::fcntl(raw,libc::F_SETFD,libc::FD_CLOEXEC)}<0 || unsafe{libc::bind(raw,std::ptr::addr_of!(address).cast(),length as _)}!=0 {
            fail!(EIO,"SUPERVISOR_DEPENDENCY_BIND");
        }
        let own=std::fs::symlink_metadata(&path).map_err(|_|err!(EIO,"SUPERVISOR_DEPENDENCY_BOUND_SOCKET"))?;
        if !std::os::unix::fs::FileTypeExt::is_socket(&own.file_type()) || own.uid()!=0 {fail!(EACCES,"SUPERVISOR_DEPENDENCY_BOUND_SOCKET");}
        let original=stamp(&own);
        if unsafe{libc::fchownat(parent.as_raw_fd(),leaf.as_ptr(),0,DaemonId::CustodyVault.gid(),libc::AT_SYMLINK_NOFOLLOW)}!=0 {
            fail!(EIO,"SUPERVISOR_DEPENDENCY_SOCKET_DAC");
        }
        let middle=std::fs::symlink_metadata(&path).map_err(|_|err!(EIO,"SUPERVISOR_DEPENDENCY_BOUND_SOCKET"))?;
        if (middle.dev(),middle.ino())!=(original.dev,original.ino) {fail!(ESTALE,"SUPERVISOR_DEPENDENCY_SOCKET_CHANGED");}
        if unsafe{libc::fchmodat(parent.as_raw_fd(),leaf.as_ptr(),0o660,libc::AT_SYMLINK_NOFOLLOW)}!=0 {fail!(EIO,"SUPERVISOR_DEPENDENCY_SOCKET_DAC");}
        let final_metadata=std::fs::symlink_metadata(&path).map_err(|_|err!(EIO,"SUPERVISOR_DEPENDENCY_BOUND_SOCKET"))?;
        if (final_metadata.dev(),final_metadata.ino())!=(original.dev,original.ino) {fail!(ESTALE,"SUPERVISOR_DEPENDENCY_SOCKET_CHANGED");}
        let owner=Self {parent,parent_stamp:stamp(&before),path,socket_stamp:stamp(&final_metadata),listener};owner.current()?;
        if unsafe{libc::listen(owner.listener.as_raw_fd(),4)}!=0 {fail!(EIO,"SUPERVISOR_DEPENDENCY_LISTEN");} Ok(owner)
    }
    fn current(&self)->EnclaveResult<()> {
        let p=stamp(&self.parent.metadata().map_err(|_|err!(EIO,"SUPERVISOR_DEPENDENCY_PARENT"))?);
        fd(&self.parent)?;
        let named=std::fs::symlink_metadata(self.path.parent().expect("fixed parent")).map_err(|_|err!(EIO,"SUPERVISOR_DEPENDENCY_PARENT"))?;
        let s=std::fs::symlink_metadata(&self.path).map_err(|_|err!(EIO,"SUPERVISOR_DEPENDENCY_BOUND_SOCKET"))?;
        if !directory_equal(&p,&self.parent_stamp) || !directory_equal(&stamp(&named),&self.parent_stamp)
            || !std::os::unix::fs::FileTypeExt::is_socket(&s.file_type()) || s.uid()!=0 || s.gid()!=DaemonId::CustodyVault.gid()
            || s.mode()&0o7777!=0o660 || s.nlink()!=1 || stamp(&s)!=self.socket_stamp {
            fail!(ESTALE,"SUPERVISOR_DEPENDENCY_SOCKET_CHANGED");
        }
        // Listener identity is retained separately; it need not equal the name.
        let flags=unsafe{libc::fcntl(self.listener.as_raw_fd(),libc::F_GETFD)};
        if flags<0 || flags&libc::FD_CLOEXEC==0 {fail!(ESTALE,"SUPERVISOR_DEPENDENCY_FD_CHANGED");} Ok(())
    }
}
fn peer_policy()->EnclaveResult<PeerPolicy> {
    Ok(PeerPolicy::allow([]).require(0,CodeRequirement::pinned_boundary(codesign::CTL_IDENTIFIER)?)
        .require(DaemonId::CustodyVault.uid(),CodeRequirement::pinned_boundary(&DaemonId::CustodyVault.launchd_label())?))
}
type ProbeRequest=(Request,Instant,mpsc::SyncSender<Observation>);
struct ConnectionCharge {uid:u32,counts:Arc<Mutex<BTreeMap<u32,usize>>>}
impl Drop for ConnectionCharge {fn drop(&mut self){if let Ok(mut counts)=self.counts.lock(){
    if let Some(count)=counts.get_mut(&self.uid){*count=count.saturating_sub(1);}
}}}
// One original selected IPC cancellation domain. These atomics describe only
// unfinished cleanup; none can supply a positive readiness or PF observation.
static IPC_CLEANUP_UNKNOWN:AtomicBool=AtomicBool::new(false);
fn require_ipc_admission(unknown:&AtomicBool)->EnclaveResult<()> {
    if unknown.load(Ordering::SeqCst) {fail!(EACCES,"SUPERVISOR_DEPENDENCY_PRIOR_CLEANUP_UNKNOWN");} Ok(())
}
enum IpcSession {
    Native(Arc<crate::power::selected_owner_session::SelectedOwnerSession>),
    #[cfg(test)] Fixture {revoked:Arc<AtomicBool>,process_unknown:Arc<AtomicBool>},
}
struct IpcShutdown {
    session:IpcSession,stop:Arc<AtomicBool>,cleanup_unknown:AtomicBool,
    joined_unwind:AtomicBool,server_error:AtomicBool,root_retained:AtomicBool,
    retained_peer_workers:std::sync::atomic::AtomicU64,
    retention_collisions:std::sync::atomic::AtomicU64,
}
impl IpcShutdown {
    fn new(session:IpcSession,stop:Arc<AtomicBool>)->Arc<Self> {
        Arc::new(Self {session,stop,cleanup_unknown:AtomicBool::new(false),
            joined_unwind:AtomicBool::new(false),server_error:AtomicBool::new(false),
            root_retained:AtomicBool::new(false),
            retained_peer_workers:std::sync::atomic::AtomicU64::new(0),
            retention_collisions:std::sync::atomic::AtomicU64::new(0)})
    }
    fn veto(&self) {
        // No session record/filesystem/native query, evidence mutex or cleanup.
        match &self.session {
            IpcSession::Native(session)=>session.revoke(),
            #[cfg(test)] IpcSession::Fixture {revoked,..}=>revoked.store(true,Ordering::SeqCst),
        }
        self.stop.store(true,Ordering::SeqCst);
    }
    fn process_unknown(&self)->&AtomicBool {
        match &self.session {
            IpcSession::Native(_)=>&IPC_CLEANUP_UNKNOWN,
            #[cfg(test)] IpcSession::Fixture {process_unknown,..}=>process_unknown,
        }
    }
    fn require_admission(&self)->EnclaveResult<()> {
        let result=require_ipc_admission(self.process_unknown());
        if result.is_err() {self.veto();}result
    }
    fn unknown(&self) {
        self.veto();self.cleanup_unknown.store(true,Ordering::SeqCst);
        // Process-sticky refusal is published BEFORE retention/native cleanup.
        // A new pre-start attempt may not grow another original session/tree.
        self.process_unknown().store(true,Ordering::SeqCst);
    }
    fn unwind(&self) {self.unknown();self.joined_unwind.store(true,Ordering::SeqCst);}
    fn collision(&self) {
        self.unknown();
        let _=self.retention_collisions.try_update(Ordering::SeqCst,Ordering::SeqCst,|v|Some(v.saturating_add(1)));
    }
}

// The exact accepted streams and quota charges stay owned by their original
// closures. Retain their actual handles AND the server's original listener and
// quota map together; do not turn a dropped JoinHandle into completed cleanup.
struct PeerResources {
    listener:UnixListener,counts:Arc<Mutex<BTreeMap<u32,usize>>>,
    workers:Vec<std::thread::JoinHandle<()>>,shutdown:Arc<IpcShutdown>,
}
impl PeerResources {
    fn join_finished(&mut self)->EnclaveResult<()> {
        let mut index=0;let mut unwound=false;
        while index<self.workers.len() {
            if self.workers[index].is_finished() {
                let worker=self.workers.swap_remove(index);
                if worker.join().is_err() {self.shutdown.unwind();unwound=true;}
            } else {index+=1;}
        }
        if unwound {fail!(EIO,"SUPERVISOR_DEPENDENCY_PEER_UNWOUND");} Ok(())
    }
}
static RETAINED_PEERS:std::sync::OnceLock<Box<PeerResources>>=std::sync::OnceLock::new();
struct PeerWorkers<'a> {
    resources:Option<Box<PeerResources>>,retained:&'a std::sync::OnceLock<Box<PeerResources>>,
}
impl<'a> PeerWorkers<'a> {
    fn new(listener:UnixListener,shutdown:Arc<IpcShutdown>,
        retained:&'a std::sync::OnceLock<Box<PeerResources>>)->Self {
        Self {resources:Some(Box::new(PeerResources {listener,
            counts:Arc::new(Mutex::new(BTreeMap::new())),workers:Vec::new(),shutdown})),retained}
    }
    fn get(&mut self)->&mut PeerResources {self.resources.as_deref_mut().expect("original peer bundle")}
}
impl Drop for PeerWorkers<'_> {
    fn drop(&mut self) {
        let Some(mut resources)=self.resources.take() else {return;};
        resources.shutdown.veto(); // BEFORE join, listener close or quota drop.
        let _=resources.join_finished(); // Finished only; no timeout reset/wait.
        if !resources.workers.is_empty() {resources.shutdown.unknown();}
        if resources.shutdown.cleanup_unknown.load(Ordering::SeqCst) {
            let count=resources.workers.len() as u64;
            let _=resources.shutdown.retained_peer_workers.try_update(
                Ordering::SeqCst,Ordering::SeqCst,|v|Some(v.saturating_add(count)));
            if let Err(resources)=self.retained.set(resources) {
                // An unexpected second retirement cannot discard either exact
                // original. No registry/evidence mutex or native cleanup here.
                resources.shutdown.collision();std::mem::forget(resources);
            }
        }
    }
}

// A closed server input also vetoes before captured resources can drop on
// failed thread spawn or unwind. Production supplies only its actual owners.
struct ServerInput {
    listener:Option<UnixListener>,policy:Option<PeerPolicy>,
    send:Option<mpsc::SyncSender<ProbeRequest>>,shutdown:Arc<IpcShutdown>,
}
impl ServerInput {
    fn run(mut self)->EnclaveResult<()> {
        serve_requests(self.listener.take().expect("original listener"),
            self.policy.take().expect("original policy"),self.send.take().expect("original queue"),
            self.shutdown.clone())
    }
}
impl Drop for ServerInput {fn drop(&mut self){self.shutdown.veto();}}

// The generic ownership algorithm keeps real resources, never a readiness
// provider or cleanup callback. Its sole uncertain-stop action is the SAME
// native session/stop atomic veto; no listener/root cleanup may precede UNKNOWN.
struct ServingResources<R:'static> {
    originals:R,server:Option<std::thread::JoinHandle<EnclaveResult<()>>>,shutdown:Arc<IpcShutdown>,
}
impl<R:'static> ServingResources<R> {
    fn join_finished(&mut self)->Option<EnclaveResult<()>> {
        if !self.server.as_ref().is_some_and(std::thread::JoinHandle::is_finished) {return None;}
        let result=match self.server.take().expect("finished original server").join() {
            Ok(result)=>result,
            Err(_)=>{self.shutdown.unwind();Err(err!(EIO,"SUPERVISOR_DEPENDENCY_SERVER_UNWOUND"))},
        };
        if result.is_err() {self.shutdown.veto();self.shutdown.server_error.store(true,Ordering::SeqCst);}
        Some(result)
    }
    fn finish_server(&mut self,end:Instant)->EnclaveResult<()> {
        self.shutdown.veto();
        while self.server.as_ref().is_some_and(|worker|!worker.is_finished()) && Instant::now()<end {
            std::thread::sleep(end.saturating_duration_since(Instant::now()).min(Duration::from_millis(2)));
        }
        if let Some(result)=self.join_finished() {return result;}
        self.shutdown.unknown();Err(err!(EIO,"SUPERVISOR_DEPENDENCY_SERVER_CLEANUP_UNKNOWN"))
    }
}
struct ServingOwner<'a,R:'static> {
    resources:Option<Box<ServingResources<R>>>,
    retained:&'a std::cell::OnceCell<&'static ServingResources<R>>,
}
impl<'a,R:'static> ServingOwner<'a,R> {
    fn new(originals:R,shutdown:Arc<IpcShutdown>,
        retained:&'a std::cell::OnceCell<&'static ServingResources<R>>)->Self {
        Self {resources:Some(Box::new(ServingResources {originals,server:None,shutdown})),retained}
    }
    fn get(&mut self)->&mut ServingResources<R> {self.resources.as_deref_mut().expect("original serving bundle")}
}
impl<R:'static> Drop for ServingOwner<'_,R> {
    fn drop(&mut self) {
        let Some(mut resources)=self.resources.take() else {return;};
        resources.shutdown.veto();
        let _=resources.join_finished(); // Also covers early return/caught unwind.
        if resources.server.is_some() {resources.shutdown.unknown();}
        if resources.shutdown.cleanup_unknown.load(Ordering::SeqCst) {
            resources.shutdown.root_retained.store(true,Ordering::SeqCst);
            // Keep non-Send/thread-affine originals on their creating thread.
            // The exact Box remains alive for process lifetime, including TLS
            // teardown. A TLS reference's destruction cannot free these owners.
            let resources:&'static ServingResources<R>=Box::leak(resources);
            if self.retained.set(resources).is_err() {resources.shutdown.collision();}
        }
    }
}

#[cfg(target_os="macos")]
struct NativeServingOriginals {owner:ReadinessOwner,bound:BoundSocket,receive:mpsc::Receiver<ProbeRequest>}
#[cfg(target_os="macos")]
thread_local! {
    static RETAINED_SERVING:std::cell::OnceCell<&'static ServingResources<NativeServingOriginals>>=
        const {std::cell::OnceCell::new()};
}

// Keep a closed payload through spawn: a failed spawn vetoes before its actual
// stream/charge fields can enter socket teardown or quota-map cleanup.
struct PeerInput {
    stream:Option<UnixStream>,_charge:ConnectionCharge,policy:Option<PeerPolicy>,
    send:Option<mpsc::SyncSender<ProbeRequest>>,shutdown:Arc<IpcShutdown>,started:bool,
}
struct PeerUnwindVeto(Arc<IpcShutdown>);
impl Drop for PeerUnwindVeto {
    fn drop(&mut self) {if std::thread::panicking(){self.0.veto();}}
}
impl PeerInput {
    fn run(mut self) {
        self.started=true;
        let until=Instant::now()+PREFLIGHT;
        let mut peer=match readiness_server_peer::ServerPeer::authenticate(
            self.stream.take().expect("original stream"),self.policy.take().expect("original policy"),
            self._charge.uid,self.shutdown.clone(),until) {Ok(peer)=>peer,Err(_)=>return};
        let _unwind=PeerUnwindVeto(self.shutdown.clone());
        let send=self.send.as_ref().expect("original request queue");
        while !self.shutdown.stop.load(Ordering::Acquire) && Instant::now()<until {
            // SAME consumed original connection through read/queue/reply.
            let mut exchange=match peer.begin(){Ok(exchange)=>exchange,Err(_)=>return};
            let bytes=match exchange.read_frame(){Ok(bytes)=>bytes,Err(_)=>return};
            let request=match strict_decode::<Request>(&bytes){Ok(request) if request.version==1=>request,_=>return};
            let (reply,wait)=mpsc::sync_channel(1);
            let (end,sent)=match exchange.publish(|end|send.try_send((request,end,reply))){
                Ok(value)=>value,Err(_)=>return,
            };
            let response=match sent {
                Ok(())=>match wait.recv_timeout(end.saturating_duration_since(Instant::now())) {
                    Ok(observation)=>ipc::Reply::Ok(observation),
                    Err(_)=>ipc::Reply::Err(err!(ETIMEDOUT,"SUPERVISOR_DEPENDENCY_DEADLINE")),
                },Err(_)=>ipc::Reply::Err(err!(EAGAIN,"SUPERVISOR_DEPENDENCY_BUSY")),
            };
            let encoded=match ipc::to_cbor(&response){Ok(bytes)=>bytes,Err(_)=>return};
            if exchange.reply(&encoded).is_err(){return;}
        }
    }
}
impl Drop for PeerInput {
    fn drop(&mut self) {if !self.started || std::thread::panicking(){self.shutdown.veto();}}
}

// Closed framing: strict CBOR and the original4total/2perUID/32KiB bounds.
// All early returns/unwinds retire the SAME worker/listener/quota bundle.
fn serve_requests(listener:UnixListener,policy:PeerPolicy,send:mpsc::SyncSender<ProbeRequest>,
    shutdown:Arc<IpcShutdown>)->EnclaveResult<()> {
    shutdown.require_admission()?;
    let mut workers=PeerWorkers::new(listener,shutdown.clone(),&RETAINED_PEERS);
    workers.get().listener.set_nonblocking(true).map_err(|_|err!(EIO,"SUPERVISOR_DEPENDENCY_NONBLOCK"))?;
    while !shutdown.stop.load(Ordering::Acquire) {
        let resources=workers.get();resources.join_finished()?;
        let (stream,_)=match resources.listener.accept() {
            Ok(value)=>value,
            Err(error) if error.kind()==std::io::ErrorKind::WouldBlock=>{std::thread::sleep(Duration::from_millis(5));continue;},
            Err(_)=>fail!(EIO,"SUPERVISOR_DEPENDENCY_ACCEPT"),
        };
        let peer=match ipc::peer_credentials(&stream){Ok(peer)=>peer,Err(_)=>continue};
        if !policy.allowed_uids.contains(&peer.uid){continue;}
        let mut active=resources.counts.lock().map_err(|_|err!(EIO,"SUPERVISOR_DEPENDENCY_QUOTA"))?;
        if active.values().sum::<usize>()>=4 || active.get(&peer.uid).copied().unwrap_or(0)>=2 {continue;}
        *active.entry(peer.uid).or_default()+=1;drop(active);
        let input=PeerInput {stream:Some(stream),
            _charge:ConnectionCharge {uid:peer.uid,counts:resources.counts.clone()},
            policy:Some(policy.clone()),send:Some(send.clone()),shutdown:shutdown.clone(),started:false};
        let worker=std::thread::Builder::new().name("supervisor-readiness-peer".into()).stack_size(256*1024)
            .spawn(move||input.run()).map_err(|_|err!(EIO,"SUPERVISOR_DEPENDENCY_THREAD"))?;
        resources.workers.push(worker); // Keep exact returned handle immediately.
    }
    let resources=workers.get();resources.shutdown.veto();resources.join_finished()?;
    if !resources.workers.is_empty() {
        resources.shutdown.unknown();fail!(EIO,"SUPERVISOR_DEPENDENCY_PEER_CLEANUP_UNKNOWN");
    }
    Ok(())
}

// Keep the non-Send original S1 owner on its actual creating thread. Handlers
// cannot manufacture observations; they enqueue a challenge to that SAME owner.
#[cfg(target_os="macos")]
pub(super) fn serve(owner:ReadinessOwner)->EnclaveResult<()> {
    RETAINED_SERVING.with(|retained|serve_retained(owner,retained))
}
#[cfg(target_os="macos")]
fn serve_retained(mut owner:ReadinessOwner,
    retained:&std::cell::OnceCell<&'static ServingResources<NativeServingOriginals>>)->EnclaveResult<()> {
    require_ipc_admission(&IPC_CLEANUP_UNKNOWN)?; // Before binding/spawning any new readiness owner.
    owner.lifetime.current()?;
    let end=(Instant::now()+PROBE).min(owner.lifetime.end);
    owner.lifetime.checked(||owner.originals.require_current(end))?;
    let bound=owner.lifetime.checked(||BoundSocket::bind(owner.originals.mesh_parent()?,&owner.checked.target().layout.socket_root))?;
    let (send,receive)=mpsc::sync_channel::<ProbeRequest>(1);
    let shutdown=IpcShutdown::new(IpcSession::Native(owner.lifetime.session.clone()),owner.lifetime.stop.clone());
    let mut serving=ServingOwner::new(NativeServingOriginals {owner,bound,receive},shutdown.clone(),retained);
    let resources=serving.get();
    let originals=&mut resources.originals;
    let listener=originals.owner.lifetime.checked(||originals.bound.listener.try_clone()
        .map_err(|_|err!(EIO,"SUPERVISOR_DEPENDENCY_LISTENER")))?;
    let policy=originals.owner.lifetime.checked(peer_policy)?;
    originals.owner.lifetime.checked(||originals.owner.pins.current())?;
    let input=ServerInput {listener:Some(listener),policy:Some(policy),send:Some(send),shutdown:shutdown.clone()};
    resources.server=Some(std::thread::Builder::new().name("supervisor-readiness-ipc".into())
        .spawn(move||input.run()).map_err(|_|err!(EIO,"SUPERVISOR_DEPENDENCY_THREAD"))?);
    let result=(|| {
        while !shutdown.stop.load(Ordering::Acquire) {
            originals.owner.lifetime.current()?;
            if resources.server.as_ref().is_none_or(std::thread::JoinHandle::is_finished) {
                fail!(EIO,"SUPERVISOR_DEPENDENCY_SERVER_EXITED");
            }
            match originals.receive.recv_timeout(Duration::from_millis(10)) {
                Ok((request,end,reply))=>{
                    let end=end.min(originals.owner.lifetime.end);
                    originals.owner.lifetime.checked(||{originals.bound.current()?;originals.owner.originals.require_current(end)})?;
                    let observation=originals.owner.sample(request,end);
                    originals.owner.lifetime.checked(||originals.bound.current())?;
                    let _=reply.try_send(observation);
                },Err(mpsc::RecvTimeoutError::Timeout)=>{},Err(_)=>fail!(EIO,"SUPERVISOR_DEPENDENCY_DISCONNECTED"),
            }
        } Ok(())
    })();
    // Establish the original administrative cleanup endpoint BEFORE any final
    // evidence check. Unknown server/peer completion returns through retention;
    // a metadata/native/evidence wait cannot postpone that retirement decision.
    let until=Instant::now()+PROBE;
    resources.finish_server(until)?;
    let originals=&mut resources.originals;
    let current=originals.bound.current();
    let original=originals.owner.originals.require_current(until);
    result?;current?;original
}

#[cfg(test)]
#[path="readiness_tests.rs"]
mod tests;
