//! Closed selected accept-worker composition. No startup/ready/PF caller exists.
//! The named socket owner and actual accept-loop owner remain separate, original
//! objects. Accept progress never proves handler completion or factor authority.
use std::{os::unix::net::UnixListener, path::PathBuf, sync::{Arc,atomic::{AtomicBool,Ordering}},time::Instant};
use crate::{deployment, error::{EnclaveError,EnclaveResult,Errno}, ipc, err};
use super::{selected_runtime::SelectedRuntime, selected_socket::{PrimarySocket,HeldSocket},RespawnTracker};

// Private concrete adapters only. No production provider/handler/policy/FD input.
trait NamedSocket {
    fn current(&mut self,originals:&mut Option<&mut SelectedRuntime>,end:Instant)->EnclaveResult<()>;
    fn take(&mut self,originals:&mut Option<&mut SelectedRuntime>,end:Instant)->EnclaveResult<UnixListener>;
}
macro_rules! socket_adapter {
    ($socket:ident) => {impl NamedSocket for $socket {
        fn current(&mut self,originals:&mut Option<&mut SelectedRuntime>,end:Instant)->EnclaveResult<()> {
            self.require_current(originals.as_deref_mut().ok_or_else(||err!(EACCES,"SELECTED_ACCEPT_ORIGINALS"))?,end)
        }
        fn take(&mut self,originals:&mut Option<&mut SelectedRuntime>,end:Instant)->EnclaveResult<UnixListener> {
            self.take_listener(originals.as_deref_mut().ok_or_else(||err!(EACCES,"SELECTED_ACCEPT_ORIGINALS"))?,end)
        }
    }};
}
socket_adapter!(PrimarySocket);
socket_adapter!(HeldSocket);

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum Role {Primary,Held}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum Stage {SocketBefore,SocketAfter,Duplicate,Scope,Policy,Spawn,Worker,Deadline,Stopped,
    Incomplete,AlreadyStarted,HeldDependency,Poisoned,WorkerCleanup,SocketCleanup}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct Failure {stage:Stage,errno:Errno}
impl Failure {
    fn at(stage:Stage,errno:Errno)->Self {Self {stage,errno}}
    fn from(stage:Stage,error:EnclaveError)->Self {Self {stage,errno:error.errno}}
}
type Check<T> = Result<T,Failure>;
#[cfg(test)]
enum Admission {Local,Deny}
enum Mode {
    Selected,
    // Explicit software admission, unavailable to production constructors.
    #[cfg(test)] Fixture {root:PathBuf,admission:Admission},
}
impl Mode {
    fn dev(&self)->bool {match self {Self::Selected=>false,#[cfg(test)] Self::Fixture {..}=>true}}
    fn root(&self)->Check<PathBuf> {
        match self {
            Self::Selected=>deployment::selected().map(|checked|checked.target().layout.socket_root.clone())
                .ok_or_else(||Failure::at(Stage::Scope,Errno::EACCES)),
            #[cfg(test)] Self::Fixture {root,..}=>Ok(root.clone()),
        }
    }
    fn deny(&self)->bool {match self {Self::Selected=>false,
        #[cfg(test)] Self::Fixture {admission,..}=>matches!(admission,Admission::Deny)}}
}
enum Service {
    Primary {tracker:Arc<RespawnTracker>,held_status:Arc<AtomicBool>}, Held,
}
struct WorkerOwner<S:NamedSocket> {
    // Revoke/drop progress before dropping the separate original socket owner.
    progress:Option<ipc::ServerProgress>,socket:S,stop:Arc<AtomicBool>,
    status:Arc<AtomicBool>,role:Role,attempted:bool,poisoned:bool,failures:Vec<Failure>,
}
impl<S:NamedSocket> WorkerOwner<S> {
    fn new(socket:S,stop:Arc<AtomicBool>,role:Role)->Self {
        Self {progress:None,socket,stop,status:Arc::new(AtomicBool::new(false)),role,
            attempted:false,poisoned:false,failures:Vec::new()}
    }
    fn reject(&mut self,failure:Failure) {
        self.poisoned=true;self.status.store(false,Ordering::SeqCst);self.stop.store(true,Ordering::SeqCst);
        if !self.failures.contains(&failure) {self.failures.push(failure);}
    }
    fn control(&self,end:Instant)->Check<()> {
        if self.poisoned {return Err(Failure::at(Stage::Poisoned,Errno::EACCES));}
        if self.stop.load(Ordering::SeqCst) {return Err(Failure::at(Stage::Stopped,Errno::EACCES));}
        if Instant::now()>=end {return Err(Failure::at(Stage::Deadline,Errno::ETIMEDOUT));}Ok(())
    }
    fn error(&self)->EnclaveError {
        EnclaveError::with(self.failures.first().map_or(Errno::EACCES,|failure|failure.errno),
            "SUPERVISOR_SELECTED_ACCEPT_REFUSED",format!("role={:?}; stages={:?}",self.role,self.failures))
    }
    fn start(&mut self,originals:&mut Option<&mut SelectedRuntime>,mode:Mode,service:Service,end:Instant) {
        let result=(|| {
            self.control(end)?;
            if self.attempted {return Err(Failure::at(Stage::AlreadyStarted,Errno::EACCES));}
            self.attempted=true;
            self.socket.current(originals,end).map_err(|error|Failure::from(Stage::SocketBefore,error))?;
            let root=mode.root()?;let dev=mode.dev();let me=ipc::geteuid();
            // Same mandatory CLI-pin admission as the existing primary path.
            if matches!(&service,Service::Primary {..}) && !dev {
                crate::codesign::pins::require(crate::codesign::CTL_IDENTIFIER)
                    .map_err(|error|Failure::from(Stage::Policy,error))?;
            }
            let progress=match service {
                Service::Primary {tracker,held_status}=>{
                    let console_user=crate::fsutil::console_uid();
                    let policy=if mode.deny() {ipc::PeerPolicy::allow([])} else {super::primary_peer_policy(dev,me,console_user)};
                    let handler=Arc::new(super::primary_handler(root,dev,me,console_user,tracker,held_status));
                    let listener=self.socket.take(originals,end).map_err(|error|Failure::from(Stage::Duplicate,error))?;
                    self.socket.current(originals,end).map_err(|error|Failure::from(Stage::SocketBefore,error))?;self.control(end)?;
                    ipc::spawn_monitored(listener,policy,handler,self.stop.clone())
                },
                Service::Held=>{
                    let policy=if mode.deny() {ipc::PeerPolicy::allow([])} else {
                        super::held_peer_policy(dev).map_err(|error|Failure::from(Stage::Policy,error))?
                    };
                    let handler=super::held_handler(dev,me);let classifier=Arc::new(super::held_fd_classifier());
                    let listener=self.socket.take(originals,end).map_err(|error|Failure::from(Stage::Duplicate,error))?;
                    self.socket.current(originals,end).map_err(|error|Failure::from(Stage::SocketBefore,error))?;self.control(end)?;
                    ipc::spawn_monitored_with_fds(listener,policy,handler,classifier,self.stop.clone())
                },
            }.map_err(|error|Failure::from(Stage::Spawn,error))?;
            self.progress=Some(progress); // Retain actual worker before late/error checks.
            self.observe(originals,end).map_err(|error|Failure::from(Stage::Worker,error))
        })();
        if let Err(failure)=result {self.reject(failure);}
    }
    fn observe(&mut self,originals:&mut Option<&mut SelectedRuntime>,end:Instant)->EnclaveResult<()> {
        if let Err(failure)=self.control(end) {self.reject(failure);return Err(self.error());}
        if let Err(error)=self.socket.current(originals,end) {self.reject(Failure::from(Stage::SocketBefore,error));}
        if !self.poisoned {
            let result=self.progress.as_ref().ok_or_else(||Failure::at(Stage::Incomplete,Errno::EACCES))
                .and_then(|progress|progress.observe_health(end).map_err(|error|Failure::from(Stage::Worker,error)));
            if let Err(failure)=result {self.reject(failure);}
        }
        // Keep original-name/context loss independent of worker/late failure.
        if let Err(error)=self.socket.current(originals,end) {self.reject(Failure::from(Stage::SocketAfter,error));}
        if Instant::now()>=end {self.reject(Failure::at(Stage::Deadline,Errno::ETIMEDOUT));}
        if self.stop.load(Ordering::SeqCst) {self.reject(Failure::at(Stage::Stopped,Errno::EACCES));}
        if self.poisoned {return Err(self.error());}
        self.status.store(true,Ordering::SeqCst);Ok(())
    }
    fn stop(&mut self,originals:&mut Option<&mut SelectedRuntime>,end:Instant)->EnclaveResult<()> {
        self.poisoned=true;self.status.store(false,Ordering::SeqCst);self.stop.store(true,Ordering::SeqCst);
        let mut failed=false;
        if let Some(progress)=&mut self.progress {
            if let Err(error)=progress.stop(end) {failed=true;self.reject(Failure::from(Stage::WorkerCleanup,error));}
        }
        if let Err(error)=self.socket.current(originals,end) {failed=true;self.reject(Failure::from(Stage::SocketCleanup,error));}
        if Instant::now()>=end {failed=true;self.reject(Failure::at(Stage::Deadline,Errno::ETIMEDOUT));}
        // Cleanup success does not clear poison, replace a socket or restart.
        if failed {Err(self.error())} else {Ok(())}
    }
}
impl<S:NamedSocket> Drop for WorkerOwner<S> {
    fn drop(&mut self) {
        self.poisoned=true;self.status.store(false,Ordering::SeqCst);self.stop.store(true,Ordering::SeqCst);
        // ServerProgress's own Drop joins only finished workers, retains the
        // duplicate on any unfinished thread, and reports cleanup pending.
    }
}

pub(super) struct HeldAccept {inner:WorkerOwner<HeldSocket>}
pub(super) struct PrimaryAccept {inner:WorkerOwner<PrimarySocket>}
impl HeldAccept {
    /// Identity only: a shared stop cannot prove socket/worker readiness.
    pub(super) fn require_stop(&self,stop:&Arc<AtomicBool>)->EnclaveResult<()> {
        if !Arc::ptr_eq(&self.inner.stop,stop) {return Err(err!(EACCES,"SUPERVISOR_SELECTED_ACCEPT_STOP_MISMATCH"));}
        Ok(())
    }
    pub(super) fn start(socket:HeldSocket,originals:&mut SelectedRuntime,stop:Arc<AtomicBool>,end:Instant)->Self {
        let mut owner=Self {inner:WorkerOwner::new(socket,stop,Role::Held)};
        owner.inner.start(&mut Some(originals),Mode::Selected,Service::Held,end);owner
    }
    pub(super) fn observe_health(&mut self,originals:&mut SelectedRuntime,end:Instant)->EnclaveResult<()> {
        self.inner.observe(&mut Some(originals),end)
    }
    pub(super) fn stop(&mut self,originals:&mut SelectedRuntime,end:Instant)->EnclaveResult<()> {
        self.inner.stop(&mut Some(originals),end)
    }
}
impl PrimaryAccept {
    /// Identity only: a shared stop cannot prove socket/worker readiness.
    pub(super) fn require_stop(&self,stop:&Arc<AtomicBool>)->EnclaveResult<()> {
        if !Arc::ptr_eq(&self.inner.stop,stop) {return Err(err!(EACCES,"SUPERVISOR_SELECTED_ACCEPT_STOP_MISMATCH"));}
        Ok(())
    }
    pub(super) fn start(socket:PrimarySocket,originals:&mut SelectedRuntime,tracker:Arc<RespawnTracker>,
        held:&mut HeldAccept,stop:Arc<AtomicBool>,end:Instant)->Self {
        let mut owner=Self {inner:WorkerOwner::new(socket,stop,Role::Primary)};
        let admitted=(|| {
            owner.inner.control(end)?;
            if !Arc::ptr_eq(&owner.inner.stop,&held.inner.stop) {return Err(Failure::at(Stage::HeldDependency,Errno::EACCES));}
            held.observe_health(originals,end).map_err(|error|Failure::from(Stage::HeldDependency,error))
        })();
        match admitted {
            Ok(())=>owner.inner.start(&mut Some(originals),Mode::Selected,
                Service::Primary {tracker,held_status:held.inner.status.clone()},end),
            Err(failure)=>owner.inner.reject(failure),
        }owner
    }
    pub(super) fn observe_health(&mut self,originals:&mut SelectedRuntime,end:Instant)->EnclaveResult<()> {
        self.inner.observe(&mut Some(originals),end)
    }
    pub(super) fn stop(&mut self,originals:&mut SelectedRuntime,end:Instant)->EnclaveResult<()> {
        self.inner.stop(&mut Some(originals),end)
    }
}

#[cfg(test)]
#[path="selected_accept_tests.rs"]
mod tests;
