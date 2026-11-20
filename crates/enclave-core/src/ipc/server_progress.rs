//! Fresh activity from the original accept loop, never from a helper or handler.
//! This owner does not attest handler completion, socket path protection or peer
//! authorization. Those remain separate requirements of selected readiness.
use crate::{
    err,
    error::{EnclaveError, EnclaveResult, Errno},
};
use std::{
    os::{fd::AsRawFd, unix::net::UnixListener},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError},
        Arc, Mutex,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WorkerFailure {
    Accept(Errno),
    Nonblock(Errno),
    Spawn(Errno),
    Quota(Errno),
    Listener(Errno),
    Identity(Errno),
    Challenge(Errno),
    Other(Errno),
    Panic,
}
impl WorkerFailure {
    fn from_error(error: &EnclaveError) -> Self {
        match error.reason.as_str() {
            "IPC_ACCEPT" => Self::Accept(error.errno),
            "IPC_NONBLOCK" => Self::Nonblock(error.errno),
            "IPC_SPAWN" => Self::Spawn(error.errno),
            "IPC_QUOTA_POISONED" => Self::Quota(error.errno),
            "IPC_PROGRESS_LISTENER" => Self::Listener(error.errno),
            "IPC_PROGRESS_IDENTITY" => Self::Identity(error.errno),
            "IPC_PROGRESS_RECEIVER" | "IPC_PROGRESS_OWNER_GONE" => Self::Challenge(error.errno),
            _ => Self::Other(error.errno),
        }
    }
}
struct State {
    revoked: AtomicBool,
    stop: Arc<AtomicBool>,
    terminal: Mutex<Option<WorkerFailure>>,
    diagnostic_lost: AtomicBool,
    stop_pending: AtomicBool,
}
impl State {
    fn current(&self, until: Instant) -> EnclaveResult<()> {
        if self.revoked.load(Ordering::SeqCst) || self.stop.load(Ordering::SeqCst) {
            return Err(err!(EIO, "IPC_PROGRESS_REVOKED"));
        }
        if Instant::now() >= until {
            return Err(err!(ETIMEDOUT, "IPC_PROGRESS_DEADLINE"));
        }
        Ok(())
    }
    fn revoke(&self) {
        self.revoked.store(true, Ordering::SeqCst);
    }
    fn retain_failure(&self, failure: WorkerFailure) {
        self.revoke();
        match self.terminal.try_lock() {
            Ok(mut terminal) => {
                if terminal.is_none() {
                    *terminal = Some(failure);
                }
            }
            Err(_) => {
                self.diagnostic_lost.store(true, Ordering::SeqCst);
            }
        }
        // Closed stage + typed errno only. Never log a handler's raw reason or
        // free-form detail, including during detached worker cleanup/unwind.
        eprintln!("IPC_ACCEPT_OWNER_FAILED stage={failure:?}");
    }
}
struct Challenge {
    until: Instant,
    reply: SyncSender<()>,
}

/// The actual accept thread is retained. No Clone/serde or externally supplied
/// progress callback can construct this owner or acknowledge a challenge.
pub(crate) struct ServerProgress {
    state: Arc<State>,
    challenge: SyncSender<Challenge>,
    probe: Mutex<()>,
    thread: Option<JoinHandle<EnclaveResult<()>>>,
}
impl ServerProgress {
    pub(super) fn attach(mut self, thread: JoinHandle<EnclaveResult<()>>) -> Self {
        self.thread = Some(thread);
        self
    }
    pub(super) fn terminal_observer(&self) -> impl FnOnce(&EnclaveResult<()>) + Send + 'static {
        let state = self.state.clone();
        move |result| {
            if let Err(error) = result {
                state.retain_failure(WorkerFailure::from_error(error));
            }
        }
    }
    pub(crate) fn observe_health(&self, until: Instant) -> EnclaveResult<()> {
        let _serial = self
            .probe
            .try_lock()
            .map_err(|_| err!(EAGAIN, "IPC_PROGRESS_BUSY"))?;
        let result = (|| {
            self.require_worker(until)?;
            // A private channel per request prevents a delayed or old reply
            // from satisfying any later request. The queue has exactly one slot.
            let (reply, receive) = mpsc::sync_channel(1);
            self.challenge
                .try_send(Challenge { until, reply })
                .map_err(|_| err!(EIO, "IPC_PROGRESS_QUEUE"))?;
            let remaining = until
                .checked_duration_since(Instant::now())
                .ok_or_else(|| err!(ETIMEDOUT, "IPC_PROGRESS_DEADLINE"))?;
            receive
                .recv_timeout(remaining)
                .map_err(|_| err!(ETIMEDOUT, "IPC_PROGRESS_ACK"))?;
            self.require_worker(until)
        })();
        if result.is_err() {
            self.state.revoke();
        }
        result
    }
    fn require_worker(&self, until: Instant) -> EnclaveResult<()> {
        self.state.current(until)?;
        if self.thread.as_ref().is_none_or(JoinHandle::is_finished) {
            return Err(err!(EIO, "IPC_PROGRESS_WORKER"));
        }
        self.state.current(until)
    }
    /// Revoke first. An unfinished thread remains owned for a later bounded stop;
    /// never join a live thread or destroy its listener from a competing thread.
    pub(crate) fn stop(&mut self, until: Instant) -> EnclaveResult<()> {
        self.state.revoke();
        self.state.stop.store(true, Ordering::SeqCst);
        while self
            .thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished())
        {
            let remaining = until
                .checked_duration_since(Instant::now())
                .ok_or_else(|| {
                    self.state.stop_pending.store(true, Ordering::SeqCst);
                    err!(ETIMEDOUT, "IPC_PROGRESS_STOP_PENDING")
                })?;
            std::thread::sleep(remaining.min(Duration::from_millis(1)));
        }
        if Instant::now() >= until {
            self.state.stop_pending.store(true, Ordering::SeqCst);
            return Err(err!(ETIMEDOUT, "IPC_PROGRESS_STOP_PENDING"));
        }
        if let Some(thread) = self.thread.take() {
            self.retain_join(thread);
        }
        if self.state.diagnostic_lost.load(Ordering::SeqCst)
            || self
                .state
                .terminal
                .try_lock()
                .map_or(true, |failure| failure.is_some())
        {
            return Err(err!(EIO, "IPC_PROGRESS_TERMINAL_FAILURE"));
        }
        Ok(())
    }
    fn retain_join(&self, thread: JoinHandle<EnclaveResult<()>>) {
        match thread.join() {
            Ok(Ok(())) => (),
            Ok(Err(error)) => self.state.retain_failure(WorkerFailure::from_error(&error)),
            Err(_) => self.state.retain_failure(WorkerFailure::Panic),
        }
    }
}
impl Drop for ServerProgress {
    fn drop(&mut self) {
        self.state.revoke();
        self.state.stop.store(true, Ordering::SeqCst);
        if self.thread.as_ref().is_some_and(JoinHandle::is_finished) {
            if let Some(thread) = self.thread.take() {
                self.retain_join(thread);
            }
        } else if self.thread.is_some() {
            self.state.stop_pending.store(true, Ordering::SeqCst);
            eprintln!("IPC_ACCEPT_OWNER_CLEANUP_PENDING");
        }
        // Otherwise the worker retains and eventually drops its own listener.
        // Detaching here does not establish completed cleanup.
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ListenerIdentity {
    fd: i32,
    dev: u64,
    ino: u64,
    mode: u32,
}
impl ListenerIdentity {
    fn observe(listener: &UnixListener) -> EnclaveResult<Self> {
        let fd = listener.as_raw_fd();
        let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        let descriptor = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if unsafe { libc::fstat(fd, &mut metadata) } != 0
            || flags < 0
            || descriptor < 0
            || flags & libc::O_NONBLOCK == 0
            || descriptor & libc::FD_CLOEXEC == 0
            || metadata.st_mode as u32 & libc::S_IFMT as u32 != libc::S_IFSOCK as u32
        {
            return Err(err!(EIO, "IPC_PROGRESS_LISTENER"));
        }
        // Darwin AF_UNIX returns ENOPROTOOPT for SO_ACCEPTCONN. Listening is
        // established by the actual successful accept/WouldBlock iteration
        // before every ACK, never inferred from an unsupported socket option.
        Ok(Self {
            fd,
            dev: metadata.st_dev as u64,
            ino: metadata.st_ino as u64,
            mode: metadata.st_mode as u32,
        })
    }
}
pub(super) struct LoopProgress {
    state: Arc<State>,
    challenge: Receiver<Challenge>,
    original: Option<ListenerIdentity>,
    // Private, bounded test handshake on the actual original accept loop.
    #[cfg(test)]
    after_ack_pause: Option<(SyncSender<()>, Receiver<()>)>,
}
impl LoopProgress {
    pub(super) fn bind(&mut self, listener: &UnixListener) -> EnclaveResult<()> {
        if self.original.is_some() {
            return Err(err!(EIO, "IPC_PROGRESS_REBIND"));
        }
        self.original = Some(ListenerIdentity::observe(listener)?);
        Ok(())
    }
    fn current(&self, listener: &UnixListener, until: Instant) -> EnclaveResult<()> {
        self.state.current(until)?;
        if self.original != Some(ListenerIdentity::observe(listener)?) {
            return Err(err!(EIO, "IPC_PROGRESS_IDENTITY"));
        }
        self.state.current(until)
    }
    /// Called only by the original accept loop after successful dispatch or
    /// documented WouldBlock. Unexpected accept/spawn errors exit and revoke.
    pub(super) fn observe_iteration(&mut self, listener: &UnixListener) -> EnclaveResult<()> {
        match self.challenge.try_recv() {
            Ok(challenge) => {
                self.current(listener, challenge.until)?;
                challenge
                    .reply
                    .try_send(())
                    .map_err(|_| err!(EIO, "IPC_PROGRESS_RECEIVER"))?;
                // The ACK commits this sample after original/state/deadline
                // checks. The owner rechecks state/deadline after receiving it.
                // A later intentional stop cannot retroactively invalidate the
                // sample by turning the worker's normal shutdown into failure.
                // No fallible production action follows a successful ACK.
                #[cfg(test)]
                if let Some((entered, release)) = self.after_ack_pause.take() {
                    entered
                        .try_send(())
                        .expect("after-ACK test observer retained");
                    release
                        .recv_timeout(Duration::from_secs(3))
                        .expect("bounded after-ACK test release");
                }
                Ok(())
            }
            Err(TryRecvError::Empty) => Ok(()),
            Err(TryRecvError::Disconnected) => Err(err!(EIO, "IPC_PROGRESS_OWNER_GONE")),
        }
    }
}
impl Drop for LoopProgress {
    fn drop(&mut self) {
        self.state.revoke();
        if std::thread::panicking() {
            self.state.retain_failure(WorkerFailure::Panic);
        }
    }
}

pub(super) fn prepare(stop: Arc<AtomicBool>) -> (ServerProgress, LoopProgress) {
    let state = Arc::new(State {
        revoked: AtomicBool::new(false),
        stop,
        terminal: Mutex::new(None),
        diagnostic_lost: AtomicBool::new(false),
        stop_pending: AtomicBool::new(false),
    });
    let (send, receive) = mpsc::sync_channel(1);
    (
        ServerProgress {
            state: state.clone(),
            challenge: send,
            probe: Mutex::new(()),
            thread: None,
        },
        LoopProgress {
            state,
            challenge: receive,
            original: None,
            #[cfg(test)]
            after_ack_pause: None,
        },
    )
}

#[cfg(test)]
#[path = "server_progress_tests.rs"]
mod tests;
