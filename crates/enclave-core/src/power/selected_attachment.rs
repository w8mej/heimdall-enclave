//! Selected USB attachment observations, never enrolled-key or action authority.
//!
//! The caller must retain these owners on the actual authenticated connection.
//! No endpoint/startup is enabled here. Local epochs/generations never go on wire.
use std::time::Instant;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::{SelectedUsbInstance, UsbObservationEpoch, UsbSelection, UsbSelectionGuard};
use crate::{error::EnclaveResult, err, fail};

/// An untrusted lookup hint. Only fresh native observation can create a local
/// attachment guard; neither this value nor a guard authenticates a credential.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AttachmentHint {
    version: u8,
    service_registry_id: u64,
}
impl std::fmt::Debug for AttachmentHint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentHint").field("version", &self.version)
            .field("service_registry_id", &"<redacted>").finish()
    }
}
impl AttachmentHint {
    fn validate(self) -> EnclaveResult<()> {
        if self.version != 1 || self.service_registry_id == 0 {
            fail!(EINVAL, "ATTACHMENT_HINT_INVALID");
        }
        Ok(())
    }
}

fn within(end: Instant) -> EnclaveResult<()> {
    if Instant::now() >= end { fail!(ETIMEDOUT, "ATTACHMENT_DEADLINE"); }
    Ok(())
}

fn monitor_current(state: &UsbSelection, generation: u64) -> EnclaveResult<()> {
    if !state.monitor_active || generation == 0 || state.monitor_generation != generation
        || state.event_epoch == u64::MAX {
        fail!(EACCES, "ATTACHMENT_MONITOR_CHANGED");
    }
    Ok(())
}

/// Borrows the local transport's selection. Drop never revokes that selection.
/// This owner is intentionally not serializable or constructible from wire data.
pub(crate) struct LocalSelectionWitness {
    generation: u64,
    monitor_generation: u64,
    hint: AttachmentHint,
}
impl LocalSelectionWitness {
    fn capture(state: &UsbSelection) -> EnclaveResult<Self> {
        state.require(None, 1)?;
        monitor_current(state, state.monitor_generation)?;
        let (generation, instances) = state.selected.as_ref()
            .ok_or_else(|| err!(EACCES, "USB_SELECTION_UNAVAILABLE"))?;
        let hint = AttachmentHint { version: 1, service_registry_id: instances[0].service_registry_id };
        hint.validate()?;
        Ok(Self { generation: *generation, monitor_generation: state.monitor_generation, hint })
    }
    fn require(&self, state: &UsbSelection) -> EnclaveResult<()> {
        monitor_current(state, self.monitor_generation)?;
        state.require(Some(self.generation), 1)?;
        if state.selected.as_ref().map(|(_, instances)| instances[0].service_registry_id)
            != Some(self.hint.service_registry_id) {
            fail!(ESTALE, "ATTACHMENT_SELECTION_CHANGED");
        }
        Ok(())
    }
    pub(crate) fn capture_singleton(monitor: &super::darwin::PowerMonitor, end: Instant) -> EnclaveResult<Self> {
        if !cfg!(target_os = "macos") { fail!(ENOSYS, "ATTACHMENT_NATIVE_REQUIRED"); }
        if crate::ipc::geteuid() != crate::daemon::DaemonId::CustodyVault.uid() {
            fail!(EPERM, "ATTACHMENT_CUSTODY_REQUIRED");
        }
        monitor.observe_health(end)?;
        let witness = {
            let state = super::usb_selection().lock().map_err(|_| err!(EIO, "USB_SELECTION_POISONED"))?;
            Self::capture(&state)?
        };
        witness.require_current(monitor, end)?;
        Ok(witness)
    }
    pub(crate) fn hint(&self) -> AttachmentHint { self.hint }
    pub(crate) fn require_current(&self, monitor: &super::darwin::PowerMonitor, end: Instant) -> EnclaveResult<()> {
        within(end)?;
        monitor.observe_health(end)?;
        {
            let state = super::usb_selection().lock().map_err(|_| err!(EIO, "USB_SELECTION_POISONED"))?;
            self.require(&state)?;
        }
        monitor.observe_health(end)?;
        {
            let state = super::usb_selection().lock().map_err(|_| err!(EIO, "USB_SELECTION_POISONED"))?;
            self.require(&state)?;
        }
        within(end)
    }
}

// Private seams shared by the production native owner and software fixtures.
// No public provider or bool can construct a successful native owner.
trait Registry {
    type Object;
    fn root(&mut self) -> EnclaveResult<Self::Object>;
    fn lookup(&mut self, id: u64) -> EnclaveResult<Self::Object>;
    fn identity(&mut self, object: &Self::Object) -> EnclaveResult<u64>;
    fn is_usb(&mut self, object: &Self::Object) -> bool;
    fn equal(&mut self, left: &Self::Object, right: &Self::Object) -> bool;
    fn parent(&mut self, object: &Self::Object) -> EnclaveResult<Self::Object>;
}
struct Resolved<O> { original: O, ancestors: Vec<u64> }
fn resolve<R: Registry>(registry: &mut R, hint: AttachmentHint, end: Instant) -> EnclaveResult<Resolved<R::Object>> {
    within(end)?;
    hint.validate()?;
    let root = registry.root()?;
    let original = registry.lookup(hint.service_registry_id)?;
    if registry.identity(&original)? != hint.service_registry_id || !registry.is_usb(&original)
        || registry.equal(&original, &root) {
        fail!(ESTALE, "ATTACHMENT_NATIVE_IDENTITY");
    }
    within(end)?;
    let mut ancestors = Vec::new();
    let mut parent = registry.parent(&original)?;
    for _ in 0..64 {
        within(end)?;
        let id = registry.identity(&parent)?;
        if id == 0 || id == hint.service_registry_id || ancestors.contains(&id) {
            fail!(EINVAL, "ATTACHMENT_ANCESTRY_INVALID");
        }
        ancestors.push(id);
        // A positive comparison with the actual root is the ONLY termination.
        // No parent lookup error, including NoDevice, means successful root.
        if registry.equal(&parent, &root) {
            within(end)?;
            return Ok(Resolved { original, ancestors });
        }
        parent = registry.parent(&parent)?;
    }
    fail!(E2BIG, "ATTACHMENT_ANCESTRY_LIMIT");
}

trait Health { fn observe(&self, end: Instant) -> EnclaveResult<()>; }
impl Health for super::darwin::PowerMonitor {
    fn observe(&self, end: Instant) -> EnclaveResult<()> { self.observe_health(end) }
}
trait SelectionStore {
    type Guard;
    fn observation(&self) -> EnclaveResult<(u64, UsbObservationEpoch)>;
    fn bind_generation(&self, monitor: u64, instance: SelectedUsbInstance) -> EnclaveResult<u64>;
    fn own_generation(&self, generation: u64) -> Self::Guard;
    fn generation(&self, guard: &Self::Guard) -> u64;
    fn revoke(&self, generation: u64);
    fn require(&self, monitor: u64, guard: &Self::Guard) -> EnclaveResult<()>;
}

#[derive(Debug)]
enum CancellationState { Pending, Bound(u64), Cancelled }

/// Negative-only cancellation of one original attachment generation. This can
/// cross threads; retained native objects and their owner cannot. Cancellation
/// does not interrupt native calls: it revokes selection independently of them.
#[derive(Clone)]
pub(crate) struct RootAttachmentCancellation(Arc<Mutex<CancellationState>>);
impl RootAttachmentCancellation {
    pub(crate) fn new() -> Self { Self(Arc::new(Mutex::new(CancellationState::Pending))) }

    pub(crate) fn cancel(&self) { self.cancel_with(super::release_usb_selection); }

    fn cancel_with(&self, revoke: impl FnOnce(u64)) {
        let generation = {
            // Recover only to drain original authority and become terminal.
            let mut state = self.0.lock().unwrap_or_else(|error| error.into_inner());
            match std::mem::replace(&mut *state, CancellationState::Cancelled) {
                CancellationState::Bound(generation) => Some(generation),
                _ => None,
            }
        };
        // Wipe hooks may reenter cancellation/topology. Hold neither mutex.
        if let Some(generation) = generation { revoke(generation); }
    }

    fn require_pending(&self) -> EnclaveResult<()> {
        let state = self.0.lock().map_err(|_| err!(EIO, "ATTACHMENT_CANCELLATION_POISONED"))?;
        if !matches!(*state, CancellationState::Pending) { fail!(EACCES, "ATTACHMENT_CANCELLED_OR_USED"); }
        Ok(())
    }

    fn bind<S: SelectionStore>(&self, selection: &S, monitor: u64, instance: SelectedUsbInstance) -> EnclaveResult<S::Guard> {
        let mut state = match self.0.lock() {
            Ok(state) => state,
            Err(error) => {
                drop(error.into_inner());
                self.cancel_with(|generation| selection.revoke(generation));
                fail!(EIO, "ATTACHMENT_CANCELLATION_POISONED");
            }
        };
        if !matches!(*state, CancellationState::Pending) { fail!(EACCES, "ATTACHMENT_CANCELLED_OR_USED"); }
        // Only the short topology mutation is serialized with cancellation.
        // Native observation already completed; bind never invokes wipe hooks.
        let generation = selection.bind_generation(monitor, instance)?;
        *state = CancellationState::Bound(generation);
        drop(state);
        Ok(selection.own_generation(generation))
    }

    fn require_bound(&self, generation: u64) -> EnclaveResult<()> {
        let state = self.0.lock().map_err(|_| err!(EIO, "ATTACHMENT_CANCELLATION_POISONED"))?;
        if !matches!(*state, CancellationState::Bound(original) if original == generation) {
            fail!(EACCES, "ATTACHMENT_CANCELLED_OR_USED");
        }
        Ok(())
    }
}

// Covers early errors and caught unwinds before an owner exists. It never holds
// cancellation metadata while revoking. Disarmed only when the owner takes over.
struct ObservationAttempt<'a, S: SelectionStore> {
    cancellation: Option<&'a RootAttachmentCancellation>,
    selection: &'a S,
}
impl<S: SelectionStore> Drop for ObservationAttempt<'_, S> {
    fn drop(&mut self) {
        if let Some(cancellation) = self.cancellation {
            cancellation.cancel_with(|generation| self.selection.revoke(generation));
        }
    }
}

struct GlobalSelection;
impl SelectionStore for GlobalSelection {
    type Guard = UsbSelectionGuard;
    fn observation(&self) -> EnclaveResult<(u64, UsbObservationEpoch)> {
        let state = super::usb_selection().lock().map_err(|_| err!(EIO, "USB_SELECTION_POISONED"))?;
        monitor_current(&state, state.monitor_generation)?;
        Ok((state.monitor_generation, UsbObservationEpoch(state.event_epoch)))
    }
    fn bind_generation(&self, monitor: u64, instance: SelectedUsbInstance) -> EnclaveResult<u64> {
        let mut state = super::usb_selection().lock().map_err(|_| err!(EIO, "USB_SELECTION_POISONED"))?;
        monitor_current(&state, monitor)?;
        state.bind(instance)
    }
    fn own_generation(&self, generation: u64) -> Self::Guard { UsbSelectionGuard { generation } }
    fn generation(&self, guard: &Self::Guard) -> u64 { guard.generation }
    fn revoke(&self, generation: u64) { super::release_usb_selection(generation); }
    fn require(&self, monitor: u64, guard: &Self::Guard) -> EnclaveResult<()> {
        let state = super::usb_selection().lock().map_err(|_| err!(EIO, "USB_SELECTION_POISONED"))?;
        monitor_current(&state, monitor)?;
        state.require(Some(guard.generation), 1)
    }
}

struct AttachmentOwner<R: Registry, S: SelectionStore> {
    registry: R,
    selection: S,
    resolved: Resolved<R::Object>,
    hint: AttachmentHint,
    monitor_generation: u64,
    guard: Option<S::Guard>,
    cancellation: Option<RootAttachmentCancellation>,
    poisoned: bool,
}
impl<R: Registry, S: SelectionStore> AttachmentOwner<R, S> {
    fn observe(registry: R, selection: S, hint: AttachmentHint, health: &impl Health, end: Instant) -> EnclaveResult<Self> {
        Self::observe_inner(registry, selection, hint, health, end, None)
    }
    fn observe_cancellable(registry: R, selection: S, hint: AttachmentHint, health: &impl Health, end: Instant,
        cancellation: &RootAttachmentCancellation) -> EnclaveResult<Self> {
        Self::observe_inner(registry, selection, hint, health, end, Some(cancellation.clone()))
    }
    fn observe_inner(mut registry: R, selection: S, hint: AttachmentHint, health: &impl Health, end: Instant,
        cancellation: Option<RootAttachmentCancellation>) -> EnclaveResult<Self> {
        let mut attempt = ObservationAttempt { cancellation: cancellation.as_ref(), selection: &selection };
        within(end)?;
        if let Some(cancellation) = &cancellation { cancellation.require_pending()?; }
        health.observe(end)?;
        // This process's epoch is captured BEFORE its actual native walk.
        let (monitor_generation, epoch) = selection.observation()?;
        let resolved = resolve(&mut registry, hint, end)?;
        health.observe(end)?;
        let instance = SelectedUsbInstance::new_observed(hint.service_registry_id, resolved.ancestors.clone(), epoch)?;
        let guard = match &cancellation {
            Some(cancellation) => cancellation.bind(&selection, monitor_generation, instance)?,
            None => selection.own_generation(selection.bind_generation(monitor_generation, instance)?),
        };
        attempt.cancellation = None;
        drop(attempt);
        let mut owner = Self { registry, selection, resolved, hint, monitor_generation, guard: Some(guard), cancellation, poisoned: false };
        owner.require_current(hint, health, end)?;
        Ok(owner)
    }
    fn require_ready(&self, health: &impl Health, end: Instant) -> EnclaveResult<()> {
        within(end)?;
        if let Some(cancellation) = &self.cancellation {
            let guard = self.guard.as_ref().ok_or_else(|| err!(EACCES, "ATTACHMENT_OWNER_POISONED"))?;
            cancellation.require_bound(self.selection.generation(guard))?;
        }
        health.observe(end)?;
        let guard = self.guard.as_ref().ok_or_else(|| err!(EACCES, "ATTACHMENT_OWNER_POISONED"))?;
        self.selection.require(self.monitor_generation, guard)?;
        if let Some(cancellation) = &self.cancellation {
            cancellation.require_bound(self.selection.generation(guard))?;
        }
        within(end)
    }
    fn require_current(&mut self, hint: AttachmentHint, health: &impl Health, end: Instant) -> EnclaveResult<()> {
        if self.poisoned { fail!(EACCES, "ATTACHMENT_OWNER_POISONED"); }
        let result = (|| {
            hint.validate()?;
            if hint != self.hint { fail!(ESTALE, "ATTACHMENT_HINT_CHANGED"); }
            self.require_ready(health, end)?;
            let fresh = resolve(&mut self.registry, hint, end)?;
            if fresh.ancestors != self.resolved.ancestors
                || !self.registry.equal(&fresh.original, &self.resolved.original) {
                fail!(ESTALE, "ATTACHMENT_NATIVE_CHANGED");
            }
            self.require_ready(health, end)
        })();
        if result.is_err() {
            self.poisoned = true;
            if let Some(cancellation) = &self.cancellation {
                cancellation.cancel_with(|generation| self.selection.revoke(generation));
            }
            // No topology mutex is held here. Guard Drop executes existing wipe
            // hooks. Keep original native object until the owner itself drops.
            drop(self.guard.take());
        }
        result
    }
}
impl<R: Registry, S: SelectionStore> Drop for AttachmentOwner<R, S> {
    fn drop(&mut self) {
        // Revoke before releasing the original native object. No topology
        // mutex is held and a prior failure already took this same guard.
        if let Some(cancellation) = &self.cancellation {
            cancellation.cancel_with(|generation| self.selection.revoke(generation));
        }
        drop(self.guard.take());
    }
}

/// Concrete native root observation owner. The caller must retain it on the
/// authenticated selected-owner connection and drop it on any connection loss.
/// This API cannot restore a poisoned owner or enable supervisor startup/PF.
#[cfg(target_os = "macos")]
pub(crate) struct RootAttachmentOwner(AttachmentOwner<native::NativeRegistry, GlobalSelection>);
#[cfg(target_os = "macos")]
impl RootAttachmentOwner {
    pub(crate) fn observe(hint: AttachmentHint, monitor: &super::darwin::PowerMonitor, end: Instant) -> EnclaveResult<Self> {
        if crate::ipc::geteuid() != 0 { fail!(EPERM, "ATTACHMENT_ROOT_REQUIRED"); }
        AttachmentOwner::observe(native::NativeRegistry, GlobalSelection, hint, monitor, end).map(Self)
    }
    pub(crate) fn observe_cancellable(hint: AttachmentHint, monitor: &super::darwin::PowerMonitor, end: Instant,
        cancellation: &RootAttachmentCancellation) -> EnclaveResult<Self> {
        if crate::ipc::geteuid() != 0 { cancellation.cancel(); fail!(EPERM, "ATTACHMENT_ROOT_REQUIRED"); }
        // Every unsuccessful attempt consumes this token, even before bind.
        let result = AttachmentOwner::observe_cancellable(native::NativeRegistry, GlobalSelection, hint, monitor, end, cancellation).map(Self);
        if result.is_err() { cancellation.cancel(); }
        result
    }
    pub(crate) fn require_current(&mut self, hint: AttachmentHint, monitor: &super::darwin::PowerMonitor, end: Instant) -> EnclaveResult<()> {
        // Privilege loss also poisons/releases the original root guard.
        if crate::ipc::geteuid() != 0 {
            self.0.poisoned = true;
            if let Some(cancellation) = &self.0.cancellation { cancellation.cancel(); }
            drop(self.0.guard.take());
            fail!(EPERM, "ATTACHMENT_ROOT_REQUIRED");
        }
        self.0.require_current(hint, monitor, end)
    }
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use std::{ffi::c_void, marker::PhantomData, rc::Rc};

    #[link(name = "IOKit", kind = "framework")]
    extern "C" {
        fn IORegistryGetRootEntry(main: u32) -> u32;
        fn IORegistryEntryIDMatching(id: u64) -> *mut c_void;
        fn IOServiceGetMatchingService(main: u32, matching: *const c_void) -> u32;
        fn IORegistryEntryGetRegistryEntryID(entry: u32, id: *mut u64) -> i32;
        fn IOObjectConformsTo(object: u32, class: *const libc::c_char) -> i32;
        fn IOObjectIsEqualTo(object: u32, other: u32) -> i32;
        fn IORegistryEntryGetParentEntry(entry: u32, plane: *const libc::c_char, parent: *mut u32) -> i32;
        fn IOObjectRelease(object: u32) -> i32;
    }
    // No run-loop/IOHID handle crosses a thread; prevent accidental transfer of
    // these retained registry rights too. No unsafe Send implementation.
    pub(super) struct Object { raw: u32, _thread: PhantomData<Rc<()>> }
    impl Object {
        fn owned(raw: u32) -> EnclaveResult<Self> {
            if raw == 0 { fail!(EIO, "ATTACHMENT_NATIVE_UNAVAILABLE"); }
            Ok(Self { raw, _thread: PhantomData })
        }
    }
    // Drop attempts release; the return code cannot establish checked native
    // cleanup success. Native/installed resource qualification remains separate.
    impl Drop for Object { fn drop(&mut self) { unsafe { IOObjectRelease(self.raw); } } }
    pub(super) struct NativeRegistry;
    impl Registry for NativeRegistry {
        type Object = Object;
        fn root(&mut self) -> EnclaveResult<Object> { Object::owned(unsafe { IORegistryGetRootEntry(0) }) }
        fn lookup(&mut self, id: u64) -> EnclaveResult<Object> {
            let matching = unsafe { IORegistryEntryIDMatching(id) };
            if matching.is_null() { fail!(EIO, "ATTACHMENT_NATIVE_MATCHING"); }
            // IOKit consumes the dictionary on success AND failure.
            Object::owned(unsafe { IOServiceGetMatchingService(0, matching) })
        }
        fn identity(&mut self, object: &Object) -> EnclaveResult<u64> {
            let mut id = 0;
            if unsafe { IORegistryEntryGetRegistryEntryID(object.raw, &mut id) } != 0 || id == 0 {
                fail!(EIO, "ATTACHMENT_NATIVE_IDENTITY");
            }
            Ok(id)
        }
        fn is_usb(&mut self, object: &Object) -> bool {
            unsafe { IOObjectConformsTo(object.raw, c"IOUSBHostDevice".as_ptr()) != 0 }
        }
        fn equal(&mut self, left: &Object, right: &Object) -> bool {
            unsafe { IOObjectIsEqualTo(left.raw, right.raw) != 0 }
        }
        fn parent(&mut self, object: &Object) -> EnclaveResult<Object> {
            let mut raw = 0;
            let result = unsafe { IORegistryEntryGetParentEntry(object.raw, c"IOService".as_ptr(), &mut raw) };
            if result != 0 {
                // Public API ownership is promised only on success. Never
                // guess that a nonzero error out-parameter is our send right.
                // Preserve explicit uncertainty instead of deallocating an
                // ambiguous name. This cannot be reported as checked cleanup.
                if raw != 0 { fail!(EIO, "ATTACHMENT_NATIVE_PARENT_OWNERSHIP_UNKNOWN"); }
                fail!(EIO, "ATTACHMENT_NATIVE_PARENT");
            }
            Object::owned(raw)
        }
    }
}

#[cfg(test)]
#[path = "selected_attachment_tests.rs"]
mod tests;
