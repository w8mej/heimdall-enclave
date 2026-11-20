//! Original selected native HID handle and owner-thread continuity.
//!
//! This metadata owns no USB registration, secret, cleanup callback or release
//! authority. A current observation is not a quiescent-close or same-key proof.

use std::sync::{
    atomic::{AtomicBool, AtomicU8, Ordering},
    Arc,
};

#[cfg(any(test, all(target_os = "macos", feature = "macos-hid")))]
use enclave_core::err;
use enclave_core::error::EnclaveResult;
use enclave_core::fail;

#[cfg(any(test, all(target_os = "macos", feature = "macos-hid")))]
const NOT_ENTERED: u8 = 0;
const LIVE: u8 = 1;
#[cfg(any(test, all(target_os = "macos", feature = "macos-hid")))]
const ENDED: u8 = 2;

/// Continuity of one successfully singleton-bound native public HID handle.
///
/// Only the native transport can create this capability. Clones retain the
/// original handle and owner markers; they cannot reopen or replace either.
#[derive(Clone)]
pub struct SelectedTransportLifetime {
    state: TransportLifetimeState,
}

impl std::fmt::Debug for SelectedTransportLifetime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectedTransportLifetime")
            .finish_non_exhaustive()
    }
}

impl SelectedTransportLifetime {
    /// Refuse after original handle closure, failure, poison or owner exit.
    /// This observation does not replace selected-topology and release fencing.
    pub fn require_current(&self) -> EnclaveResult<()> {
        self.state.require_current()
    }
}

// These constructors and transitions are internal metadata operations. Their
// only production caller is macos_hid; software transports cannot mint a native
// capability through the public HidDevice trait.
pub(super) struct OwnerThreadState {
    phase: AtomicU8,
}

#[cfg(any(test, all(target_os = "macos", feature = "macos-hid")))]
impl OwnerThreadState {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            phase: AtomicU8::new(NOT_ENTERED),
        })
    }

    // Called at the actual owner thread's entry, never by its spawning caller.
    pub(super) fn enter(self: &Arc<Self>) -> EnclaveResult<OwnerThreadGuard> {
        self.phase
            .compare_exchange(NOT_ENTERED, LIVE, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| err!(EACCES, "HID_OWNER_LIFETIME_ENDED"))?;
        Ok(OwnerThreadGuard {
            state: self.clone(),
            _thread: std::marker::PhantomData,
        })
    }

    pub(super) fn abandon(&self) {
        self.phase.store(ENDED, Ordering::SeqCst);
    }
}

// Never transferable to a different thread. Declared after native device/pair
// locals in the owning scope, so unwind closes metadata before native cleanup.
#[cfg(any(test, all(target_os = "macos", feature = "macos-hid")))]
pub(super) struct OwnerThreadGuard {
    state: Arc<OwnerThreadState>,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

#[cfg(any(test, all(target_os = "macos", feature = "macos-hid")))]
impl Drop for OwnerThreadGuard {
    fn drop(&mut self) {
        self.state.abandon();
    }
}

struct HandleState {
    open: AtomicBool,
    singleton_bound: AtomicBool,
    failed: AtomicBool,
}

#[derive(Clone)]
pub(super) struct TransportLifetimeState {
    handle: Arc<HandleState>,
    owner: Arc<OwnerThreadState>,
    poisoned: Arc<AtomicBool>,
}

impl TransportLifetimeState {
    #[cfg(any(test, all(target_os = "macos", feature = "macos-hid")))]
    pub(super) fn new(owner: Arc<OwnerThreadState>, poisoned: Arc<AtomicBool>) -> Self {
        Self {
            handle: Arc::new(HandleState {
                open: AtomicBool::new(true),
                singleton_bound: AtomicBool::new(false),
                failed: AtomicBool::new(false),
            }),
            owner,
            poisoned,
        }
    }

    // Only after the real owner has acquired the singleton core USB guard.
    #[cfg(any(test, all(target_os = "macos", feature = "macos-hid")))]
    pub(super) fn singleton_bound(&self) {
        self.handle.singleton_bound.store(true, Ordering::SeqCst);
    }

    pub(super) fn fail(&self) {
        self.handle.failed.store(true, Ordering::SeqCst);
    }
    #[cfg(any(test, all(target_os = "macos", feature = "macos-hid")))]
    pub(super) fn close(&self) {
        self.handle.open.store(false, Ordering::SeqCst);
    }

    #[cfg(any(test, all(target_os = "macos", feature = "macos-hid")))]
    pub(super) fn capture(&self) -> EnclaveResult<SelectedTransportLifetime> {
        self.require_current()?;
        Ok(SelectedTransportLifetime {
            state: self.clone(),
        })
    }

    fn require_current(&self) -> EnclaveResult<()> {
        if !self.handle.singleton_bound.load(Ordering::SeqCst) {
            fail!(EACCES, "HID_SELECTED_TRANSPORT_UNBOUND");
        }
        if !self.handle.open.load(Ordering::SeqCst) {
            fail!(EACCES, "HID_SELECTED_TRANSPORT_CLOSED");
        }
        if self.handle.failed.load(Ordering::SeqCst) {
            fail!(EACCES, "HID_SELECTED_TRANSPORT_FAILED");
        }
        if self.poisoned.load(Ordering::SeqCst) {
            // Latch poison into this capability as well: clearing an original
            // poison bit accidentally must never revive an observed failure.
            self.fail();
            fail!(EACCES, "HID_OWNER_POISONED");
        }
        if self.owner.phase.load(Ordering::SeqCst) != LIVE {
            self.fail();
            fail!(EACCES, "HID_OWNER_LIFETIME_ENDED");
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "selected_transport_lifetime_tests.rs"]
mod tests;
