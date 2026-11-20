//! One finite custody actor and an independent original-transport watchdog.
//! This composes negative authority only; it cannot enable supervisor startup.
use super::{
    selected_owner::SelectedOwnerConnection, selected_transport_lifetime::SelectedTransportLifetime,
};
use crate::service::{SelectedOwnerFailure, VaultService};
use enclave_core::{
    err,
    error::EnclaveResult,
    fail,
    power::{
        darwin::PowerMonitor, selected_owner_channel::CustodySelectedOwnerStop,
        selected_owner_session::SelectedOwnerSession,
    },
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex, OnceLock, Weak,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

// Scheduling admissions only, never calibrated lifecycle/erasure budgets.
const WATCH: Duration = Duration::from_millis(10);
const HEARTBEAT: Duration = Duration::from_millis(250);
static NATIVE_ALLOCATED: OnceLock<()> = OnceLock::new();

// Production has exactly one source-owned original. Private scheduling tests
// cannot construct a native session, channel, code identity or startup owner.
enum Session {
    Native(Arc<SelectedOwnerSession>),
    #[cfg(test)]
    Fixture,
    #[cfg(test)]
    BlockedFixture {
        entered: mpsc::SyncSender<()>,
        resume: Mutex<mpsc::Receiver<()>>,
    },
}
impl Session {
    fn current(&self) -> EnclaveResult<()> {
        match self {
            Self::Native(session) => session.require_current(),
            #[cfg(test)]
            Self::Fixture => Ok(()),
            #[cfg(test)]
            Self::BlockedFixture { entered, resume } => {
                entered.send(()).unwrap();
                resume
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(3))
                    .unwrap();
                Ok(())
            }
        }
    }
    fn revoke(&self) {
        match self {
            Self::Native(session) => session.revoke(),
            #[cfg(test)]
            Self::Fixture | Self::BlockedFixture { .. } => {}
        }
    }
    fn original(&self) -> EnclaveResult<Arc<SelectedOwnerSession>> {
        match self {
            Self::Native(session) => Ok(session.clone()),
            #[cfg(test)]
            Self::Fixture | Self::BlockedFixture { .. } => {
                fail!(EACCES, "SELECTED_OWNER_RUNTIME_NATIVE_SESSION_REQUIRED")
            }
        }
    }
}
fn native_process() -> EnclaveResult<()> {
    if !cfg!(target_os = "macos") {
        fail!(ENOSYS, "SELECTED_OWNER_RUNTIME_NATIVE_REQUIRED");
    }
    if enclave_core::ipc::geteuid() != enclave_core::daemon::DaemonId::CustodyVault.uid()
        || !enclave_core::codesign::enforced()
    {
        fail!(EPERM, "SELECTED_OWNER_RUNTIME_PROCESS");
    }
    Ok(())
}

struct Control {
    token: SelectedTransportLifetime,
    session: Session,
    stop: CustodySelectedOwnerStop,
    failed: SelectedOwnerFailure,
    ended: AtomicBool,
    fence_started: AtomicBool,
    service: Mutex<Option<Weak<VaultService>>>,
    end: Instant,
}
impl Control {
    fn signal_failure(&self) {
        // No service/actor/State/release lock precedes the sticky failure and
        // same pending/socket shutdown. Neither can be cleared by fresh auth.
        self.failed.fail();
        self.ended.store(true, Ordering::SeqCst);
        self.session.revoke();
        self.stop.stop();
    }
    fn current(&self) -> EnclaveResult<()> {
        self.failed.require_current()?;
        if self.ended.load(Ordering::SeqCst) || Instant::now() >= self.end {
            fail!(EACCES, "SELECTED_OWNER_RUNTIME_ENDED");
        }
        // The independent channel watcher can stop on EOF or an earlier
        // active/boot bound while the actor is blocked in native work. Observe
        // its SAME terminal control; success never substitutes for fresh ACK.
        self.stop.require_not_stopped()?;
        self.token.require_current()?;
        // SAME protected original and finite end, independent of actor progress.
        // Filesystem/kernel checks run outside every runtime metadata mutex.
        self.session.current()
    }
    fn fence_service(&self) {
        // Poison drains authority but must not discard the retained real
        // service. Recover only to copy its Weak; no admission under this lock.
        let service = {
            let slot = self
                .service
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            slot.as_ref().and_then(Weak::upgrade)
        };
        if let Some(service) = service {
            if !self.fence_started.swap(true, Ordering::SeqCst) {
                // This directly fences before State/preflight, outside every
                // runtime lock. Its later cleanup may block; completion is not
                // implied by the earlier terminal metadata/socket shutdown.
                let _ = service.fail_selected_owner();
            }
        }
    }
    fn observe(
        &self,
        send: &mpsc::SyncSender<Probe>,
        sequence: &mut u64,
        requested: Instant,
    ) -> EnclaveResult<()> {
        let result = (|| {
            self.current()?;
            let end = requested.min(self.end);
            if Instant::now() >= end {
                fail!(ETIMEDOUT, "SELECTED_OWNER_RUNTIME_PROBE");
            }
            *sequence = sequence
                .checked_add(1)
                .ok_or_else(|| err!(EACCES, "SELECTED_OWNER_RUNTIME_SEQUENCE"))?;
            let (reply, receive) = mpsc::sync_channel(1);
            send.try_send(Probe {
                sequence: *sequence,
                end,
                reply,
            })
            .map_err(|_| err!(EACCES, "SELECTED_OWNER_RUNTIME_BACKPRESSURE"))?;
            let received = receive
                .recv_timeout(end.saturating_duration_since(Instant::now()))
                .map_err(|_| err!(ETIMEDOUT, "SELECTED_OWNER_RUNTIME_PROBE"))?;
            self.current()?;
            if received != *sequence || Instant::now() >= end {
                fail!(ESTALE, "SELECTED_OWNER_RUNTIME_PROBE");
            }
            Ok(())
        })();
        if result.is_err() {
            self.signal_failure();
        }
        result
    }
}
struct ActorExit(Arc<Control>);
impl Drop for ActorExit {
    fn drop(&mut self) {
        self.0.signal_failure();
        self.0.fence_service();
    }
}
struct Probe {
    sequence: u64,
    end: Instant,
    reply: mpsc::SyncSender<u64>,
}
struct PendingFailure {
    failure: SelectedOwnerFailure,
    armed: bool,
}
impl Drop for PendingFailure {
    fn drop(&mut self) {
        if self.armed {
            self.failure.fail();
        }
    }
}
struct RuntimeAttempt {
    control: Arc<Control>,
    armed: bool,
}
impl Drop for RuntimeAttempt {
    fn drop(&mut self) {
        if self.armed {
            self.control.signal_failure();
        }
    }
}
fn watchdog(control: Arc<Control>) {
    let _exit = ActorExit(control.clone());
    while control.current().is_ok() {
        std::thread::sleep(WATCH);
    }
}

// Retain unfinished owners instead of describing detached threads as cleanup.
// Native allocation is process-sticky, so this registry admits at most one
// runtime and never enables replacement after unknown completion.
struct Retained {
    _control: Arc<Control>,
    _monitor: Arc<PowerMonitor>,
    _actor: Option<JoinHandle<()>>,
    _watchdog: Option<JoinHandle<()>>,
}
static RETAINED: OnceLock<Mutex<Vec<Retained>>> = OnceLock::new();

/// Private embedding owner; only the actual native hardware capture supplies
/// the token. The original monitor is shared, never restarted or replaced.
pub(crate) struct SelectedOwnerRuntime {
    control: Arc<Control>,
    monitor: Arc<PowerMonitor>,
    requests: mpsc::SyncSender<Probe>,
    sequence: u64,
    actor: Option<JoinHandle<()>>,
    watchdog: Option<JoinHandle<()>>,
}
impl SelectedOwnerRuntime {
    pub(crate) fn start(
        token: SelectedTransportLifetime,
        monitor: Arc<PowerMonitor>,
        lifetime_end: Instant,
        startup_end: Instant,
        failed: SelectedOwnerFailure,
        session: Arc<SelectedOwnerSession>,
    ) -> EnclaveResult<Self> {
        let mut attempt = PendingFailure {
            failure: failed.clone(),
            armed: true,
        };
        native_process()?;
        failed.require_current()?;
        token.require_current()?;
        session.require_current()?;
        let lifetime_end = failed.bind_original(
            session.clone(),
            lifetime_end.min(session.original_instant_end()),
            session.expires_boot_ns(),
        )?;
        session.require_current()?;
        if Instant::now() >= lifetime_end.min(startup_end) {
            failed.fail();
            fail!(ETIMEDOUT, "SELECTED_OWNER_RUNTIME_STARTUP");
        }
        if NATIVE_ALLOCATED.set(()).is_err() {
            failed.fail();
            fail!(EACCES, "SELECTED_OWNER_RUNTIME_ALREADY_ALLOCATED");
        }
        let control = Arc::new(Control {
            token,
            session: Session::Native(session),
            stop: CustodySelectedOwnerStop::new(lifetime_end),
            failed,
            ended: AtomicBool::new(false),
            fence_started: AtomicBool::new(false),
            service: Mutex::new(None),
            end: lifetime_end,
        });
        let (send, receive) = mpsc::sync_channel(1);
        let mut owner = Self {
            control: control.clone(),
            monitor: monitor.clone(),
            requests: send,
            sequence: 0,
            actor: None,
            watchdog: None,
        };
        // Watch before actor creation/connect. It can stop Pending while native
        // context/health/code authentication is blocked and no socket exists.
        let watch = control.clone();
        owner.watchdog = Some(
            std::thread::Builder::new()
                .name("selected-transport-watch".into())
                .spawn(move || watchdog(watch))
                .map_err(|_| err!(EIO, "SELECTED_OWNER_RUNTIME_WATCHDOG"))?,
        );
        owner.actor = Some(std::thread::Builder::new().name("selected-owner-custody".into())
            .spawn(move || {
                let _exit = ActorExit(control.clone());
                let Ok(session) = control.session.original() else { return; };
                let Ok(mut channel) = SelectedOwnerConnection::connect_lifetime(control.token.clone(), &monitor,
                    lifetime_end, startup_end, &control.stop, session) else { return; };
                loop {
                    if control.current().is_err() { return; }
                    let request = match receive.recv_timeout(HEARTBEAT.min(lifetime_end.saturating_duration_since(Instant::now()))) {
                        Ok(request) => Some(request),
                        Err(mpsc::RecvTimeoutError::Timeout) => None,
                        Err(mpsc::RecvTimeoutError::Disconnected) => return,
                    };
                    if control.current().is_err() { return; }
                    let end = request.as_ref().map_or(lifetime_end, |request: &Probe| request.end.min(lifetime_end));
                    if channel.probe(&monitor, end).is_err() || control.current().is_err() { return; }
                    if let Some(request) = request {
                        if Instant::now() >= request.end || request.reply.try_send(request.sequence).is_err() { return; }
                    }
                }
            }).map_err(|_| err!(EIO, "SELECTED_OWNER_RUNTIME_ACTOR"))?);
        owner.observe_health(startup_end)?;
        attempt.armed = false;
        Ok(owner)
    }

    /// Fresh completed probe from this same actor, never a cached ready bit.
    pub(crate) fn observe_health(&mut self, requested: Instant) -> EnclaveResult<()> {
        let mut attempt = RuntimeAttempt {
            control: self.control.clone(),
            armed: true,
        };
        self.control
            .observe(&self.requests, &mut self.sequence, requested)?;
        attempt.armed = false;
        Ok(())
    }

    /// Install the SAME negative dependency before service listener exposure.
    /// Native service installation separately checks retained actual hardware.
    pub(crate) fn bind_service(
        &mut self,
        service: &Arc<VaultService>,
        end: Instant,
    ) -> EnclaveResult<()> {
        let mut attempt = RuntimeAttempt {
            control: self.control.clone(),
            armed: true,
        };
        let result = (|| {
            service.install_selected_owner_failure(self.control.failed.clone())?;
            {
                let mut slot = self
                    .control
                    .service
                    .lock()
                    .map_err(|_| err!(EIO, "SELECTED_OWNER_RUNTIME_SERVICE"))?;
                if slot.is_some() {
                    fail!(EACCES, "SELECTED_OWNER_RUNTIME_SERVICE_ALREADY_BOUND");
                }
                *slot = Some(Arc::downgrade(service));
            }
            self.observe_health(end)
        })();
        if result.is_err() {
            self.control.signal_failure();
            // The caller's actual service must be fenced even if weak binding
            // or installation failed. Existing cleanup completion may block.
            let _ = service.fail_selected_owner();
        }
        if result.is_ok() {
            attempt.armed = false;
        }
        result
    }
}

#[cfg(test)]
#[path = "selected_owner_runtime_tests.rs"]
mod tests;
impl Drop for SelectedOwnerRuntime {
    fn drop(&mut self) {
        self.control.signal_failure();
        for worker in [&mut self.actor, &mut self.watchdog] {
            if worker.as_ref().is_some_and(JoinHandle::is_finished) {
                if let Some(worker) = worker.take() {
                    let _ = worker.join();
                }
            }
        }
        if self.actor.is_some() || self.watchdog.is_some() {
            let retained = Retained {
                _control: self.control.clone(),
                _monitor: self.monitor.clone(),
                _actor: self.actor.take(),
                _watchdog: self.watchdog.take(),
            };
            match RETAINED.get_or_init(|| Mutex::new(Vec::new())).lock() {
                Ok(mut owners) => owners.push(retained),
                Err(error) => error.into_inner().push(retained),
            }
        }
    }
}
