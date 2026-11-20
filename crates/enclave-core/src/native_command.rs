//! Bounded command plumbing for trusted, internally constructed native commands.
//!
//! This module grants no operation, installation or host authority. A trusted
//! Rust adapter must construct its own closed command, enforce its real guards
//! and native admission, and interpret exit status without exposing raw output.
//! No command/argv CLI, deserializable request, policy provider or launchd absence
//! contract is supplied here. Production execution remains macOS-only.
//!
//! The caller must preserve default SIGCHLD disposition and exclusive wait
//! ownership for the child until cleanup. The original unreaped leader pins the
//! process group; uncertain ownership/cleanup refuses rather than retrying. The
//! existing deadline and combined output cap are unchanged. A denied group
//! signal requires a fresh owned terminal observation before the first reap.

use std::{io::{self, Read}, os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Child, Command, Stdio}, time::{Duration, Instant}};

/// Existing combined stdout/stderr limit, in bytes.
pub const MAX_OUTPUT:usize=1024*1024;

/// Raw command output for trusted in-process adapters only.
///
/// This deliberately has no Serialize or content-bearing Debug implementation.
#[derive(Clone)]
pub struct CommandOutput {
    /// Observed exit code; None denotes termination without a numeric exit code.
    pub code:Option<i32>,
    /// Captured stdout; the trusted adapter must not log or serialize these bytes.
    pub stdout:Vec<u8>,
    /// Captured stderr; the trusted adapter must not log or serialize these bytes.
    pub stderr:Vec<u8>,
}
impl std::fmt::Debug for CommandOutput {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        f.debug_struct("CommandOutput").field("code",&self.code)
            .field("stdout_bytes",&self.stdout.len()).field("stderr_bytes",&self.stderr.len()).finish()
    }
}

/// Redacted command/ownership failure; never a successful absence observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandFailure {
    /// Native production execution or child creation was unavailable.
    Unavailable,
    /// The original absolute observation deadline expired.
    Timeout,
    /// The combined output bound was exceeded.
    OutputLimit,
    /// Child pipe/setup/read or already-finalized owner failed.
    Io,
    /// Original child/group ownership or complete cleanup was not confirmed.
    OwnershipUnknown,
}

/// Run a trusted internally constructed command with the existing owner bounds.
///
/// This is plumbing, not permission to accept raw commands/argv from an external
/// caller. The adapter must enforce operation-specific authority and redact all
/// output. No non-macOS production fallback or automatic retry is supplied.
pub fn run_owned_command(command:Command,deadline:Instant)->Result<CommandOutput,CommandFailure> {
    #[cfg(target_os="macos")]
    {bounded_output(command,deadline)}
    #[cfg(not(target_os="macos"))]
    {let _=(command,deadline);Err(CommandFailure::Unavailable)}
}

struct OwnedObserver {child:Child,group:i32,cleaned:bool}
fn cleanup_signal_decision(leader_terminal:bool,result:i32,error:Option<i32>)->Result<bool,CommandFailure> {
    match (result,error,leader_terminal) {
        (0,_,_)|(-1,Some(libc::ESRCH),_)=>Ok(false),
        // Darwin can report EPERM for an all-zombie group. This is only a
        // candidate: require a known terminal leader, reap, then prove the
        // former group absent with a non-signalling existence probe below.
        (-1,Some(libc::EPERM),true)=>Ok(true),
        _=>Err(CommandFailure::OwnershipUnknown),
    }
}
fn group_gone_after_reap(result:i32,error:Option<i32>)->bool {
    result==-1 && error==Some(libc::ESRCH)
}
impl OwnedObserver {
    fn terminal(&self)->Result<bool,CommandFailure> {
        let mut info=std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        // Observe without reaping: the owned leader pins its PID/PGID even
        // after exit. Child::try_wait is forbidden until group cleanup below.
        let result=unsafe {libc::waitid(libc::P_PID,self.child.id() as libc::id_t,
            info.as_mut_ptr(),libc::WEXITED|libc::WNOHANG|libc::WNOWAIT)};
        // BEGIN CLEANUP_DIAGNOSTIC_ONLY
        #[cfg(test)]
        tests::diagnostic_terminal(result,
            if result<0 {io::Error::last_os_error().raw_os_error()}else{None},
            result==0 && unsafe {info.assume_init_ref()}.si_signo!=0);
        // END CLEANUP_DIAGNOSTIC_ONLY
        if result<0 {return Err(CommandFailure::OwnershipUnknown);}
        Ok(unsafe {info.assume_init()}.si_signo!=0)
    }
    fn cleanup(&mut self)->Result<Option<i32>,CommandFailure> {
        // BEGIN CLEANUP_DIAGNOSTIC_ONLY
        #[cfg(test)]
        tests::diagnostic_cleanup_start(self.cleaned);
        // END CLEANUP_DIAGNOSTIC_ONLY
        if self.cleaned {return Err(CommandFailure::Io);}
        // Auto-reap or a competing reaper may have removed our lifetime pin.
        // Without a successful WNOWAIT immediately before signalling, no
        // numeric process-group identity is safe to signal.
        let leader_terminal=match self.terminal() {Ok(value)=>value,
            Err(_)=>{self.cleaned=true;return Err(CommandFailure::OwnershipUnknown);}};
        // BEGIN CLEANUP_DIAGNOSTIC_ONLY
        #[cfg(test)]
        tests::diagnostic_after_initial(self.child.id(),leader_terminal);
        // END CLEANUP_DIAGNOSTIC_ONLY
        // The leader remains unreaped here, preventing PGID recycling. Kill
        // only this isolated observer group, then permit its first reap.
        let result=unsafe {libc::kill(-self.group,libc::SIGKILL)};
        let error=if result<0 {io::Error::last_os_error().raw_os_error()}else{None};
        self.cleaned=true;
        // BEGIN CLEANUP_DIAGNOSTIC_ONLY
        #[cfg(test)]
        tests::diagnostic_signal(result,error,cleanup_signal_decision(leader_terminal,result,error));
        // END CLEANUP_DIAGNOSTIC_ONLY
        // Pipe closure can terminate the leader after the first live snapshot.
        // EPERM is only a candidate: freshly observe the still-owned unreaped
        // leader, then retain the exact post-reap ESRCH requirement below.
        // False or lost ownership still refuses; no second signal is sent.
        let leader_terminal=if result==-1 && error==Some(libc::EPERM) {
            self.terminal()?
        } else {leader_terminal};
        let require_absence=cleanup_signal_decision(leader_terminal,result,error)?;
        let until=Instant::now()+Duration::from_millis(250);
        loop {match self.child.try_wait() {
            Ok(Some(status))=>{
                // BEGIN CLEANUP_DIAGNOSTIC_ONLY
                #[cfg(test)]
                tests::diagnostic_reaped(status.code());
                // END CLEANUP_DIAGNOSTIC_ONLY
                if require_absence {
                    // No mutating signal after reap. A recycled PGID can only
                    // cause conservative refusal, never signal another group.
                    // A live unkillable member returns 0/EPERM rather than the
                    // exact ESRCH required here and therefore cannot succeed.
                    let probe=unsafe {libc::kill(-self.group,0)};
                    let error=if probe<0 {io::Error::last_os_error().raw_os_error()}else{None};
                    // BEGIN CLEANUP_DIAGNOSTIC_ONLY
                    #[cfg(test)]
                    tests::diagnostic_probe(probe,error);
                    // END CLEANUP_DIAGNOSTIC_ONLY
                    if !group_gone_after_reap(probe,error) {return Err(CommandFailure::OwnershipUnknown);}
                }
                return Ok(status.code());
            },
            Ok(None) if Instant::now()<until=>std::thread::sleep(Duration::from_millis(1)),
            // Even after a successful group signal, failure to confirm our
            // child's reap leaves cleanup uncertain. Do not spawn another.
            _=>return Err(CommandFailure::OwnershipUnknown),
        }}
    }
}
fn safe_child_policy(action:&libc::sigaction)->bool {
    action.sa_sigaction==libc::SIG_DFL && action.sa_flags&libc::SA_NOCLDWAIT==0
}
fn verify_child_policy()->Result<(),CommandFailure> {
    let mut action=std::mem::MaybeUninit::<libc::sigaction>::zeroed();
    // A custom/ignored SIGCHLD disposition may reap before our own waitid. The
    // trusted caller must preserve default disposition and exclusive ownership
    // of waits for this child through cleanup; no other in-process reaper may
    // consume it between WNOWAIT and kill. No production integration asserts
    // that contract yet. Refuse known unsupported policies before spawning.
    if unsafe {libc::sigaction(libc::SIGCHLD,std::ptr::null(),action.as_mut_ptr())}!=0
        || !safe_child_policy(&unsafe {action.assume_init()}) {
        Err(CommandFailure::OwnershipUnknown)
    } else {Ok(())}
}
impl Drop for OwnedObserver {
    fn drop(&mut self) {
        // No second group signal after the first reap, even on error paths.
        if !self.cleaned {let _=self.cleanup();}
    }
}
fn nonblocking(fd:i32)->Result<(),CommandFailure> {
    let flags=unsafe {libc::fcntl(fd,libc::F_GETFL)};
    if flags<0 || unsafe {libc::fcntl(fd,libc::F_SETFL,flags|libc::O_NONBLOCK)}<0 {
        Err(CommandFailure::Io)
    } else {Ok(())}
}
fn drain(reader:&mut impl Read,out:&mut Vec<u8>,total:&mut usize,deadline:Instant)->Result<bool,CommandFailure> {
    let mut buffer=[0u8;4096];
    loop {
        if Instant::now()>=deadline {return Err(CommandFailure::Timeout);}
        match reader.read(&mut buffer) {
            Ok(0)=>return Ok(true),
            Ok(size)=>{
                *total=total.checked_add(size).ok_or(CommandFailure::OutputLimit)?;
                if *total>MAX_OUTPUT {return Err(CommandFailure::OutputLimit);}
                out.extend_from_slice(&buffer[..size]);
            },
            Err(error) if error.kind()==io::ErrorKind::WouldBlock=>return Ok(false),
            Err(error) if error.kind()==io::ErrorKind::Interrupted=>continue,
            Err(_)=>return Err(CommandFailure::Io),
        }
    }
}
fn with_observer_cleanup<T>(owned:&mut OwnedObserver,
    operation:impl FnOnce(&mut OwnedObserver)->Result<T,CommandFailure>)
    ->Result<(T,Option<i32>),CommandFailure> {
    let result=operation(owned);
    // BEGIN CLEANUP_DIAGNOSTIC_ONLY
    #[cfg(test)]
    tests::diagnostic_operation(result.as_ref().err().copied());
    // END CLEANUP_DIAGNOSTIC_ONLY
    // Every ordinary postspawn exit must explicitly observe cleanup, including
    // early pipe/setup/read/deadline errors. Drop is only a panic/unwind fallback.
    // An uncertain cleanup takes priority over the original observation error
    // so observed_run stops rather than accumulating uncertain child groups.
    let code=owned.cleanup().map_err(|_|CommandFailure::OwnershipUnknown)?;
    result.map(|value|(value,code))
}
fn bounded_output(mut command:Command,deadline:Instant)->Result<CommandOutput,CommandFailure> {
    if Instant::now()>=deadline {return Err(CommandFailure::Timeout);}
    verify_child_policy()?;
    command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).process_group(0);
    let child=command.spawn().map_err(|_|CommandFailure::Unavailable)?;
    // Child::id originates from the native positive pid_t, never caller input.
    let group=child.id() as libc::pid_t;
    let mut owned=OwnedObserver {child,group,cleaned:false};
    let ((out,error),code)=with_observer_cleanup(&mut owned,|owned| {
        let mut stdout=owned.child.stdout.take().ok_or(CommandFailure::Io)?;
        let mut stderr=owned.child.stderr.take().ok_or(CommandFailure::Io)?;
        nonblocking(stdout.as_raw_fd())?;nonblocking(stderr.as_raw_fd())?;
        let (mut out,mut error,mut total)=(Vec::new(),Vec::new(),0usize);
        let (mut out_done,mut error_done)=(false,false);
        loop {
            if Instant::now()>=deadline {return Err(CommandFailure::Timeout);}
            if !out_done {out_done=drain(&mut stdout,&mut out,&mut total,deadline)?;}
            if !error_done {error_done=drain(&mut stderr,&mut error,&mut total,deadline)?;}
            if owned.terminal()? && out_done && error_done {return Ok((out,error));}
            std::thread::sleep(Duration::from_millis(2));
        }
    })?;
    Ok(CommandOutput {code,stdout:out,stderr:error})
}

// A separate strict engine: existing read-only adapters retain their legacy
// compatibility API above. This engine is NOT root-operation authority and has
// NO production scope issuer. In particular, sigaction observation or a bool
// cannot prove process-wide exclusive wait ownership over a later interval.
mod wait_discipline {
    pub(super) struct Seal(());
    #[cfg(test)]
    pub(super) fn fixture_seal()->Seal {Seal(())}
}

/// Unconstructible in production until an independently reviewed process owner
/// actually establishes the required wait/SIGCHLD discipline. Not Send/Sync:
/// one issued scope could not be moved/shared to run concurrent attempts.
///
/// Future admission must exclude every competing wait for this child and any
/// SIGCHLD disposition change for the complete child lifetime, including retained
/// uncertainty. A cooperative mutex/source grep is not that enforcement. There
/// is deliberately no bool, unsafe authorization escape hatch or safe issuer.
pub(crate) struct ExclusiveCommandWaitScope {
    _seal:wait_discipline::Seal,
    _thread:std::marker::PhantomData<std::rc::Rc<()>>,
}

/// Independent observation/cleanup failure facts, without output bytes.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) struct StrictCommandFailure {
    pub(crate) operation:Option<CommandFailure>,
    pub(crate) cleanup:Option<CommandFailure>,
    // Outer None means no exit was observed; Some(None) means signal exit.
    pub(crate) exit_code:Option<Option<i32>>,
    pub(crate) original_retained:bool,
}
impl StrictCommandFailure {
    fn before_spawn(error:CommandFailure)->Self {
        Self {operation:Some(error),cleanup:None,exit_code:None,original_retained:false}
    }
}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum StrictCleanupPhase {Unstarted,SignalMayHaveBeenIssued,AwaitReap,Reaped,Confirmed,Uncertain}

// Allocate this full frame BEFORE spawn. Install the returned Child immediately
// into its already-live guard; its stdout/stderr stay inside that SAME Child.
// No pipe extraction, fallback Drop cleanup or replacement Child is possible.
struct StrictCommandResources {
    child:Option<Child>,
    group:Option<i32>,
    end:Instant,
    phase:StrictCleanupPhase,
    exit_code:Option<Option<i32>>,
    stdout:Vec<u8>,
    stderr:Vec<u8>,
    total:usize,
    stdout_done:bool,
    stderr_done:bool,
    #[cfg(test)]
    signal_calls:usize,
}
impl StrictCommandResources {
    fn before_spawn(end:Instant)->Self {
        Self {child:None,group:None,end,phase:StrictCleanupPhase::Unstarted,
            exit_code:None,stdout:Vec::new(),stderr:Vec::new(),total:0,
            stdout_done:false,stderr_done:false,
            #[cfg(test)] signal_calls:0}
    }
    fn within(&self)->Result<(),CommandFailure> {
        if Instant::now()>=self.end {Err(CommandFailure::Timeout)} else {Ok(())}
    }
    fn terminal(&self)->Result<bool,CommandFailure> {
        self.within()?;
        let child=self.child.as_ref().ok_or(CommandFailure::OwnershipUnknown)?;
        let mut info=std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        let result=unsafe {libc::waitid(libc::P_PID,child.id() as libc::id_t,
            info.as_mut_ptr(),libc::WEXITED|libc::WNOHANG|libc::WNOWAIT)};
        if result<0 {return Err(CommandFailure::OwnershipUnknown);}
        self.within()?;
        Ok(unsafe {info.assume_init()}.si_signo!=0)
    }
    fn pause(&self)->Result<(),CommandFailure> {
        self.within()?;
        std::thread::sleep(Duration::from_millis(1)
            .min(self.end.saturating_duration_since(Instant::now())));
        self.within()
    }
    fn observe(&mut self)->Result<(),CommandFailure> {
        self.within()?;
        let child=self.child.as_ref().ok_or(CommandFailure::Io)?;
        nonblocking(child.stdout.as_ref().ok_or(CommandFailure::Io)?.as_raw_fd())?;
        self.within()?;
        nonblocking(child.stderr.as_ref().ok_or(CommandFailure::Io)?.as_raw_fd())?;
        loop {
            self.within()?;
            if !self.stdout_done {
                let pipe=self.child.as_mut().and_then(|child|child.stdout.as_mut())
                    .ok_or(CommandFailure::Io)?;
                self.stdout_done=drain(pipe,&mut self.stdout,&mut self.total,self.end)?;
            }
            if !self.stderr_done {
                let pipe=self.child.as_mut().and_then(|child|child.stderr.as_mut())
                    .ok_or(CommandFailure::Io)?;
                self.stderr_done=drain(pipe,&mut self.stderr,&mut self.total,self.end)?;
            }
            if self.terminal()? && self.stdout_done && self.stderr_done {return self.within();}
            self.pause()?;
        }
    }
    fn cleanup(&mut self)->Result<(),CommandFailure> {
        if self.phase!=StrictCleanupPhase::Unstarted {return Err(CommandFailure::OwnershipUnknown);}
        let result=self.cleanup_once();
        if result.is_err() {self.phase=StrictCleanupPhase::Uncertain;}
        result
    }
    fn cleanup_once(&mut self)->Result<(),CommandFailure> {
        self.within()?;
        verify_child_policy()?; // negative check only; NOT an exclusive-wait issuer
        let terminal=self.terminal()?;
        let group=self.group.ok_or(CommandFailure::OwnershipUnknown)?;
        self.within()?;
        // Set BEFORE the syscall: unwind/unknown return must never signal twice.
        self.phase=StrictCleanupPhase::SignalMayHaveBeenIssued;
        #[cfg(test)]
        {self.signal_calls+=1;}
        let result=unsafe {libc::kill(-group,libc::SIGKILL)};
        let error=if result<0 {io::Error::last_os_error().raw_os_error()}else{None};
        self.within()?;
        // Darwin EPERM can describe an all-zombie group; require a FRESH owned
        // terminal observation before the original leader's first reap.
        let terminal=if result==-1 && error==Some(libc::EPERM) {self.terminal()?} else {terminal};
        cleanup_signal_decision(terminal,result,error)?;
        self.phase=StrictCleanupPhase::AwaitReap;
        loop {
            self.within()?;
            let child=self.child.as_mut().ok_or(CommandFailure::OwnershipUnknown)?;
            match child.try_wait() {
                Ok(Some(status))=>{
                    self.exit_code=Some(status.code());
                    self.phase=StrictCleanupPhase::Reaped;
                    break;
                },
                Ok(None)=>self.pause()?,
                Err(_)=>return Err(CommandFailure::OwnershipUnknown),
            }
        }
        // Stricter than legacy compatibility: ALL signal outcomes require exact
        // original-group absence. A successful SIGKILL alone is not disposal.
        // Never send a mutating signal after reap; a recycled PGID can only
        // prolong/refuse this non-signalling probe, never be killed/adopted.
        loop {
            self.within()?;
            let result=unsafe {libc::kill(-group,0)};
            let error=if result<0 {io::Error::last_os_error().raw_os_error()}else{None};
            self.within()?;
            if group_gone_after_reap(result,error) {
                self.phase=StrictCleanupPhase::Confirmed;
                return Ok(());
            }
            if result!=0 && !(result==-1 && error==Some(libc::EPERM)) {
                return Err(CommandFailure::OwnershipUnknown);
            }
            self.pause()?;
        }
    }
}

// Bounded parking is a single try_lock and move of the already allocated full
// owner. Poison, contention and occupied-slot collisions forget the intact
// additional Box, never run Child/pipe destructors or block for another owner.
// Unknown is permanent: no retry, adoption, disposal worker or second attempt.
struct StrictRetention {
    unknown:std::sync::atomic::AtomicBool,
    original:std::sync::Mutex<Option<Box<StrictCommandResources>>>,
}
impl StrictRetention {
    const fn new()->Self {
        Self {unknown:std::sync::atomic::AtomicBool::new(false),original:std::sync::Mutex::new(None)}
    }
    fn retain(&self,bundle:Box<StrictCommandResources>) {
        self.unknown.store(true,std::sync::atomic::Ordering::SeqCst);
        match self.original.try_lock() {
            Ok(mut original) if original.is_none()=>*original=Some(bundle),
            _=>std::mem::forget(bundle),
        }
    }
    fn refused(&self)->bool {self.unknown.load(std::sync::atomic::Ordering::SeqCst)}
}
static STRICT_RETAINED:StrictRetention=StrictRetention::new();

struct StrictCommandAttempt<'a> {
    original:Option<Box<StrictCommandResources>>,
    retention:&'a StrictRetention,
}
impl<'a> StrictCommandAttempt<'a> {
    fn before_spawn(end:Instant,retention:&'a StrictRetention)->Self {
        Self {original:Some(Box::new(StrictCommandResources::before_spawn(end))),retention}
    }
    fn retain_original(&mut self) {
        if let Some(original)=self.original.take() {self.retention.retain(original);}
    }
    fn complete(mut self,operation:Result<(),CommandFailure>)->Result<CommandOutput,StrictCommandFailure> {
        let original=self.original.as_mut().expect("original command frame");
        let cleanup=original.cleanup();
        let exit_code=original.exit_code;
        if let Err(error)=cleanup {
            let failure=StrictCommandFailure {operation:operation.err(),cleanup:Some(error),
                exit_code,original_retained:true};
            self.retain_original();
            return Err(failure);
        }
        if let Err(error)=operation {
            return Err(StrictCommandFailure {operation:Some(error),cleanup:None,
                exit_code,original_retained:false});
        }
        let mut original=self.original.take().expect("confirmed original frame");
        // Recheck the SAME endpoint after cleanup, before success publication.
        original.within().map_err(|error|StrictCommandFailure {
            operation:Some(error),cleanup:None,exit_code,original_retained:false})?;
        Ok(CommandOutput {code:exit_code.expect("confirmed original exit"),
            stdout:std::mem::take(&mut original.stdout),stderr:std::mem::take(&mut original.stderr)})
    }
}
impl Drop for StrictCommandAttempt<'_> {
    fn drop(&mut self) {
        let retain=self.original.as_ref().is_some_and(|original|
            original.child.is_some() && original.phase!=StrictCleanupPhase::Confirmed);
        // Unwind never invokes legacy cleanup, blocks or starts a fresh timer.
        if retain {self.retain_original();}
    }
}

fn strict_output_inner(mut command:Command,end:Instant,_scope:&mut ExclusiveCommandWaitScope,
    retention:&StrictRetention)->Result<CommandOutput,StrictCommandFailure> {
    if retention.refused() {return Err(StrictCommandFailure::before_spawn(CommandFailure::OwnershipUnknown));}
    if Instant::now()>=end {return Err(StrictCommandFailure::before_spawn(CommandFailure::Timeout));}
    verify_child_policy().map_err(StrictCommandFailure::before_spawn)?;
    command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).process_group(0);
    let mut attempt=StrictCommandAttempt::before_spawn(end,retention);
    if retention.refused() {return Err(StrictCommandFailure::before_spawn(CommandFailure::OwnershipUnknown));}
    attempt.original.as_ref().expect("preallocated command frame").within()
        .map_err(StrictCommandFailure::before_spawn)?;
    let child=command.spawn().map_err(|_|StrictCommandFailure::before_spawn(CommandFailure::Unavailable))?;
    // No fallible setup, pipe extraction or user callback between actual spawn
    // and storing the returned original Child in the already-live guard.
    attempt.original.as_mut().expect("preallocated command frame").child=Some(child);
    let original=attempt.original.as_mut().expect("original command frame");
    let group=original.child.as_ref().expect("spawned original child").id();
    let operation=match i32::try_from(group) {
        Ok(group) if group>0=>{original.group=Some(group);original.observe()},
        _=>Err(CommandFailure::OwnershipUnknown),
    };
    attempt.complete(operation)
}

/// Strict full-endpoint command mechanism; no production scope can currently
/// be constructed, so this enables neither PF mutation nor root authority.
pub(crate) fn run_retained_strict_command(command:Command,end:Instant,scope:&mut ExclusiveCommandWaitScope)
    ->Result<CommandOutput,StrictCommandFailure> {
    #[cfg(target_os="macos")]
    {strict_output_inner(command,end,scope,&STRICT_RETAINED)}
    #[cfg(not(target_os="macos"))]
    {let _=(command,end,scope);Err(StrictCommandFailure::before_spawn(CommandFailure::Unavailable))}
}

#[cfg(test)]
#[path="native_command_tests.rs"]
mod tests;
