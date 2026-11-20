//! Composition of the original native HID lifetime and its root connection.
//! This supplies no credential/action authority or supervisor startup permit.
use super::{hid::HidDevice, selected_transport_lifetime::SelectedTransportLifetime};
use enclave_core::{
    err,
    error::EnclaveResult,
    power::{
        darwin::PowerMonitor,
        selected_owner_channel::{CustodySelectedOwnerChannel, CustodySelectedOwnerStop},
        selected_owner_session::SelectedOwnerSession,
    },
};
use std::{sync::Arc, time::Instant};

trait Shutdown {
    fn shutdown(&mut self);
}
impl Shutdown for CustodySelectedOwnerChannel {
    fn shutdown(&mut self) {
        self.stop();
    }
}
struct PendingStop<'a> {
    stop: &'a CustodySelectedOwnerStop,
    session: &'a SelectedOwnerSession,
    armed: bool,
}
impl Drop for PendingStop<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.session.revoke();
            self.stop.stop();
        }
    }
}

// The generic is private and shared only with fixtures. Production construction
// always opens the concrete authenticated channel, never a supplied provider.
struct BoundChannel<C: Shutdown> {
    lifetime: SelectedTransportLifetime,
    channel: C,
    poisoned: bool,
}
impl<C: Shutdown> BoundChannel<C> {
    fn connect(
        lifetime: SelectedTransportLifetime,
        open: impl FnOnce() -> EnclaveResult<C>,
    ) -> EnclaveResult<Self> {
        lifetime.require_current()?;
        let mut owner = Self {
            lifetime,
            channel: open()?,
            poisoned: false,
        };
        if let Err(error) = owner.lifetime.require_current() {
            owner.stop();
            return Err(error);
        }
        Ok(owner)
    }
    fn stop(&mut self) {
        self.poisoned = true;
        self.channel.shutdown();
    }
    fn call(&mut self, action: impl FnOnce(&mut C) -> EnclaveResult<()>) -> EnclaveResult<()> {
        if self.poisoned {
            return Err(err!(EACCES, "SELECTED_OWNER_TRANSPORT_POISONED"));
        }
        // Caught unwinds, precheck failures, exchange errors and late transport
        // loss all close the same channel before control leaves this call.
        let mut guard = CallGuard {
            owner: self,
            armed: true,
        };
        guard.owner.lifetime.require_current()?;
        action(&mut guard.owner.channel)?;
        guard.owner.lifetime.require_current()?;
        guard.armed = false;
        Ok(())
    }
}
impl<C: Shutdown> Drop for BoundChannel<C> {
    fn drop(&mut self) {
        self.stop();
    }
}
struct CallGuard<'a, C: Shutdown> {
    owner: &'a mut BoundChannel<C>,
    armed: bool,
}
impl<C: Shutdown> Drop for CallGuard<'_, C> {
    fn drop(&mut self) {
        if self.armed {
            self.owner.stop();
        }
    }
}

/// One native transport's persistent root connection. No token replacement,
/// reconnect, mutable stream access or channel extraction is exposed.
pub struct SelectedOwnerConnection {
    owner: BoundChannel<CustodySelectedOwnerChannel>,
    session: Arc<SelectedOwnerSession>,
}
impl std::fmt::Debug for SelectedOwnerConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectedOwnerConnection")
            .finish_non_exhaustive()
    }
}
impl SelectedOwnerConnection {
    /// The caller supplies the original independently bounded owner lifetime,
    /// retaining all earlier ceremony/policy/transport ends. Runtime must drive
    /// probes and stop on idle transport failure; this wrapper is not a worker.
    pub fn connect(
        device: &dyn HidDevice,
        monitor: &PowerMonitor,
        lifetime_end: Instant,
        exchange_end: Instant,
        session: Arc<SelectedOwnerSession>,
    ) -> EnclaveResult<Self> {
        let lifetime_end = lifetime_end.min(session.original_instant_end());
        let stop = CustodySelectedOwnerStop::new(lifetime_end);
        Self::connect_stoppable(device, monitor, lifetime_end, exchange_end, &stop, session)
    }
    /// Publish `stop` to the independent original-token watcher before this call.
    /// Pending cancellation prevents late connection success during native work.
    pub fn connect_stoppable(
        device: &dyn HidDevice,
        monitor: &PowerMonitor,
        lifetime_end: Instant,
        exchange_end: Instant,
        stop: &CustodySelectedOwnerStop,
        session: Arc<SelectedOwnerSession>,
    ) -> EnclaveResult<Self> {
        let mut attempt = PendingStop {
            stop,
            session: &session,
            armed: true,
        };
        session.require_current()?;
        let lifetime_end = lifetime_end.min(session.original_instant_end());
        let lifetime = device.selected_transport_lifetime()?;
        let owner = Self::connect_lifetime(
            lifetime,
            monitor,
            lifetime_end,
            exchange_end,
            stop,
            session.clone(),
        )?;
        session.require_current()?;
        attempt.armed = false;
        Ok(owner)
    }
    // Only the service's original hardware capture moves this opaque metadata
    // into its actor; no native HID object or replacement handle crosses threads.
    pub(crate) fn connect_lifetime(
        lifetime: SelectedTransportLifetime,
        monitor: &PowerMonitor,
        lifetime_end: Instant,
        exchange_end: Instant,
        stop: &CustodySelectedOwnerStop,
        session: Arc<SelectedOwnerSession>,
    ) -> EnclaveResult<Self> {
        let mut attempt = PendingStop {
            stop,
            session: &session,
            armed: true,
        };
        session.require_current()?;
        let lifetime_end = lifetime_end.min(session.original_instant_end());
        let owner = BoundChannel::connect(lifetime, || {
            CustodySelectedOwnerChannel::connect_stoppable(
                monitor,
                lifetime_end,
                exchange_end,
                stop,
                session.clone(),
            )
        })?;
        session.require_current()?;
        attempt.armed = false;
        drop(attempt);
        Ok(Self { owner, session })
    }
    /// A failed observation permanently closes this connection. A later
    /// successful exchange cannot repair its original transport or session.
    pub fn probe(&mut self, monitor: &PowerMonitor, end: Instant) -> EnclaveResult<()> {
        let session = &self.session;
        self.owner.call(|channel| {
            session.require_current()?;
            channel.probe(monitor, end.min(session.original_instant_end()))?;
            session.require_current()
        })
    }
    /// Negative-only shutdown; cleanup completion is a separate observation.
    pub fn stop(&mut self) {
        self.session.revoke();
        self.owner.stop();
    }
}
impl Drop for SelectedOwnerConnection {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctap::selected_transport_lifetime::{
        OwnerThreadGuard, OwnerThreadState, TransportLifetimeState,
    };
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };

    struct FakeChannel(Arc<AtomicUsize>);
    impl Shutdown for FakeChannel {
        fn shutdown(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn lifetime() -> (
        TransportLifetimeState,
        SelectedTransportLifetime,
        OwnerThreadGuard,
    ) {
        let thread = OwnerThreadState::new();
        let guard = thread.enter().unwrap();
        let state = TransportLifetimeState::new(thread, Arc::new(AtomicBool::new(false)));
        state.singleton_bound();
        let lifetime = state.capture().unwrap();
        (state, lifetime, guard)
    }

    #[test]
    fn closed_original_refuses_before_connect_and_never_opens_channel() {
        let (state, token, _thread) = lifetime();
        state.close();
        assert!(BoundChannel::<FakeChannel>::connect(token, || panic!(
            "opened for dead transport"
        ))
        .is_err());
    }
    #[test]
    fn transport_loss_during_connect_closes_new_channel_before_returning_error() {
        let (state, token, _thread) = lifetime();
        let closed = Arc::new(AtomicUsize::new(0));
        assert!(BoundChannel::connect(token, || {
            state.fail();
            Ok(FakeChannel(closed.clone()))
        })
        .is_err());
        assert!(closed.load(Ordering::SeqCst) > 0);
    }
    #[test]
    fn original_owner_exit_prevents_probe_and_permanently_closes_channel() {
        let (_state, token, thread) = lifetime();
        let closed = Arc::new(AtomicUsize::new(0));
        let mut connection =
            BoundChannel::connect(token, || Ok(FakeChannel(closed.clone()))).unwrap();
        drop(thread);
        assert!(connection
            .call(|_| panic!("probed after original owner exit"))
            .is_err());
        assert!(closed.load(Ordering::SeqCst) > 0);
        assert!(connection
            .call(|_| panic!("revived failed connection"))
            .is_err());
    }
    #[test]
    fn transport_loss_during_successful_probe_refuses_result_and_closes_original() {
        let (state, token, _thread) = lifetime();
        let closed = Arc::new(AtomicUsize::new(0));
        let mut connection =
            BoundChannel::connect(token, || Ok(FakeChannel(closed.clone()))).unwrap();
        assert!(connection
            .call(|_| {
                state.close();
                Ok(())
            })
            .is_err());
        assert!(closed.load(Ordering::SeqCst) > 0);
        assert!(connection
            .call(|_| panic!("reused after late loss"))
            .is_err());
    }
    #[test]
    fn probe_error_and_caught_unwind_close_even_when_wrapper_is_retained() {
        for unwind in [false, true] {
            let (_state, token, _thread) = lifetime();
            let closed = Arc::new(AtomicUsize::new(0));
            let mut connection =
                BoundChannel::connect(token, || Ok(FakeChannel(closed.clone()))).unwrap();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                connection.call(|_| {
                    if unwind {
                        panic!("fixture exchange panic");
                    }
                    Err(err!(EIO, "FIXTURE_EXCHANGE_ERROR"))
                })
            }));
            assert!(if unwind {
                result.is_err()
            } else {
                result.unwrap().is_err()
            });
            assert!(closed.load(Ordering::SeqCst) > 0);
            assert!(connection
                .call(|_| panic!("reused failed exchange"))
                .is_err());
        }
    }
    #[test]
    fn successful_probes_keep_same_token_but_stop_and_drop_close_channel() {
        let (_state, token, _thread) = lifetime();
        let closed = Arc::new(AtomicUsize::new(0));
        let mut connection =
            BoundChannel::connect(token, || Ok(FakeChannel(closed.clone()))).unwrap();
        for _ in 0..3 {
            connection.call(|_| Ok(())).unwrap();
        }
        assert_eq!(closed.load(Ordering::SeqCst), 0);
        connection.stop();
        assert!(closed.load(Ordering::SeqCst) > 0);
        assert!(connection
            .call(|_| panic!("reused stopped connection"))
            .is_err());
        let before = closed.load(Ordering::SeqCst);
        drop(connection);
        assert!(closed.load(Ordering::SeqCst) > before);
    }
}
