//! System power, screen-lock and authenticator-yank wipe event coordinator
//! (GAP-16, FS-701 §4.3.1/§4.5.3/§4.6.7, FS-703 §4.3/§5.2, FS-704 §4.1.3/§4.3.3, FS-705 §4.3.3).
//!
//! Subscribes to:
//! 1. Kernel sleep transitions via `IORegisterForSystemPower` on a dedicated `CFRunLoop` thread.
//!    Synchronously executes registered wipe hooks within `<= 1 ms` CPU budget, writes
//!    receipts, and calls `IOAllowPowerChange`.
//! 2. Authenticator disconnection (USB yank or emulator socket EOF).
//! 3. Screen-lock notifications (`com.apple.screenIsLocked`) routed via `_enclaveintent`.

use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

use crate::error::EnclaveResult;

// Attachment hints cross processes; selection and native owners never do.
pub(crate) mod selected_attachment;
/// Persistent selected-attachment observations between custody and root.
pub mod selected_owner_channel;
/// Finite original selected-owner listener.
pub(crate) mod selected_owner_listener;
/// Protected original finite selected-owner session.
pub mod selected_owner_session;

/// Wipe trigger classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WipeTrigger {
    /// System entering sleep (lid close, idle sleep, `pmset sleepnow`).
    SystemSleep,
    /// Aqua GUI session locked (`com.apple.screenIsLocked`).
    SessionLocked,
    /// Physical authenticator yanked from USB port or emulator socket disconnected.
    AuthenticatorYank,
    /// Unauthorized peripheral hot-plug while screen locked or sleeping (GAP-60).
    ThunderboltHotPlugLocked,
}

impl std::fmt::Display for WipeTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SystemSleep => write!(f, "SYSTEM_SLEEP"),
            Self::SessionLocked => write!(f, "SESSION_LOCKED"),
            Self::AuthenticatorYank => write!(f, "AUTHENTICATOR_YANK"),
            Self::ThunderboltHotPlugLocked => write!(f, "THUNDERBOLT_HOTPLUG_LOCKED"),
        }
    }
}

/// Opaque process-local event epoch captured before native topology discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbObservationEpoch(u64);

/// Start a topology observation before walking native registry ancestry.
pub fn observe_usb_topology() -> EnclaveResult<UsbObservationEpoch> {
    let state = usb_selection().lock().map_err(|_| crate::err!(EIO, "USB_SELECTION_POISONED"))?;
    if state.event_epoch == u64::MAX { crate::fail!(EACCES, "USB_SELECTION_UNAVAILABLE"); }
    Ok(UsbObservationEpoch(state.event_epoch))
}

/// Observation of one selected USB device and its IOKit ancestor services.
/// Registry IDs identify this attachment only; they do not authenticate a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedUsbInstance {
    service_registry_id: u64,
    ancestor_registry_ids: Vec<u64>,
    observed_event_epoch: u64,
}

impl SelectedUsbInstance {
    /// Capture a nonzero selected service and its bounded, unique ancestry.
    /// A termination between observation and binding makes binding fail closed.
    pub fn new(service_registry_id: u64, ancestor_registry_ids: Vec<u64>) -> EnclaveResult<Self> {
        Self::new_observed(service_registry_id, ancestor_registry_ids, observe_usb_topology()?)
    }

    /// Construct from an epoch captured before resolving this attachment.
    pub fn new_observed(service_registry_id: u64, ancestor_registry_ids: Vec<u64>, observation: UsbObservationEpoch) -> EnclaveResult<Self> {
        let instance = Self { service_registry_id, ancestor_registry_ids, observed_event_epoch: observation.0 };
        instance.validate_identity()?;
        Ok(instance)
    }

    fn validate_identity(&self) -> EnclaveResult<()> {
        if self.service_registry_id == 0 || self.ancestor_registry_ids.len() > 64
            || self.ancestor_registry_ids.contains(&0)
            || self.ancestor_registry_ids.contains(&self.service_registry_id)
        { crate::fail!(EINVAL, "USB_INSTANCE_IDENTITY"); }
        let mut unique = self.ancestor_registry_ids.clone();
        unique.sort_unstable(); unique.dedup();
        if unique.len() != self.ancestor_registry_ids.len() { crate::fail!(EINVAL, "USB_INSTANCE_IDENTITY"); }
        Ok(())
    }

    fn contains(&self, id: u64) -> bool {
        self.service_registry_id == id || self.ancestor_registry_ids.contains(&id)
    }
}

#[derive(Debug, Default)]
struct UsbSelection {
    generation: u64,
    event_epoch: u64,
    // One atomic session, never independently appended bindings. At most the
    // primary and backup device; custody quorum transport is a separate API.
    selected: Option<(u64, Vec<SelectedUsbInstance>)>,
    monitor_generation: u64,
    monitor_active: bool,
}

impl UsbSelection {
    fn monitor_started(&mut self) -> EnclaveResult<u64> {
        if self.monitor_active { crate::fail!(EAGAIN, "POWER_MONITOR_ALREADY_ACTIVE"); }
        self.monitor_generation = self.monitor_generation.checked_add(1)
            .ok_or_else(|| crate::err!(EIO, "POWER_MONITOR_GENERATION_EXHAUSTED"))?;
        self.monitor_active = true;
        Ok(self.monitor_generation)
    }

    fn monitor_lost(&mut self, generation: u64) -> bool {
        if !self.monitor_active || self.monitor_generation != generation { return false; }
        self.monitor_active = false;
        self.event_epoch = self.event_epoch.saturating_add(1);
        self.selected = None;
        true
    }

    fn bind(&mut self, instance: SelectedUsbInstance) -> EnclaveResult<u64> {
        self.bind_set(vec![instance])
    }

    fn bind_set(&mut self, instances: Vec<SelectedUsbInstance>) -> EnclaveResult<u64> {
        if self.selected.is_some() { crate::fail!(EAGAIN, "USB_SELECTION_ALREADY_BOUND"); }
        if instances.is_empty() || instances.len() > 2 { crate::fail!(EINVAL, "USB_SELECTION_SET_SIZE"); }
        for instance in &instances {
            instance.validate_identity()?;
            if self.event_epoch == u64::MAX || instance.observed_event_epoch != self.event_epoch {
                crate::fail!(EACCES, "USB_SELECTION_CHANGED");
            }
        }
        if instances.len() == 2 && (instances[0].contains(instances[1].service_registry_id)
            || instances[1].contains(instances[0].service_registry_id)) {
            // Duplicate services or one selected device masquerading as the
            // other's ancestor cannot supply two independent attachments.
            crate::fail!(EINVAL, "USB_SELECTION_SET_DISTINCT_REQUIRED");
        }
        let generation = self.generation.checked_add(1)
            .ok_or_else(|| crate::err!(EIO, "USB_SELECTION_EXHAUSTED"))?;
        self.generation = generation;
        self.selected = Some((generation, instances));
        Ok(generation)
    }

    fn current(&self, generation: u64, count: usize) -> bool {
        self.selected.as_ref().is_some_and(|(active, instances)| *active == generation && instances.len() == count)
    }

    fn require(&self, generation: Option<u64>, count: usize) -> EnclaveResult<()> {
        if self.event_epoch == u64::MAX || (cfg!(target_os = "macos") && !self.monitor_active)
            || !self.selected.as_ref().is_some_and(|(active, instances)|
                instances.len() == count && generation.is_none_or(|expected| expected == *active)) {
            crate::fail!(EACCES, "USB_SELECTION_UNAVAILABLE");
        }
        Ok(())
    }

    fn release(&mut self, generation: u64) -> bool {
        let current = self.selected.as_ref().is_some_and(|(active, _)| *active == generation);
        if current { self.selected = None; }
        current
    }

    fn terminate(&mut self, ids: &[Option<u64>]) -> bool {
        if ids.is_empty() { return false; }
        // Saturation permanently refuses new binding rather than wrapping.
        self.event_epoch = self.event_epoch.saturating_add(1);
        let relevant = match &self.selected {
            None => true,
            Some((_, selected)) => ids.iter().any(|id| match id {
                Some(id) if *id != 0 => selected.iter().any(|instance| instance.contains(*id)),
                _ => true, // terminated service identity could not be observed
            }),
        };
        if relevant { self.selected = None; }
        relevant
    }
}

static USB_SELECTION: OnceLock<Mutex<UsbSelection>> = OnceLock::new();
fn usb_selection() -> &'static Mutex<UsbSelection> {
    USB_SELECTION.get_or_init(|| Mutex::new(UsbSelection::default()))
}

/// Attachment-lifetime guard owned by the uniquely selected native transport.
/// Dropping an obsolete guard cannot invalidate a newly selected attachment.
#[derive(Debug)]
pub struct UsbSelectionGuard { generation: u64 }

impl UsbSelectionGuard {
    /// Whether the selected attachment remains monitored and unrevoked.
    pub fn is_current(&self) -> bool {
        usb_selection().lock().map(|state| state.current(self.generation, 1)).unwrap_or(false)
    }
}

impl Drop for UsbSelectionGuard {
    fn drop(&mut self) {
        release_usb_selection(self.generation);
    }
}

/// Bind only the unique final selection, never every enumerated candidate.
pub fn bind_selected_usb_instance(instance: SelectedUsbInstance) -> EnclaveResult<UsbSelectionGuard> {
    let generation = usb_selection().lock().map_err(|_| crate::err!(EIO, "USB_SELECTION_POISONED"))?.bind(instance)?;
    Ok(UsbSelectionGuard { generation })
}

/// One non-cloneable owner for an atomically selected primary/backup pair.
/// Either device/ancestor loss or owner drop invalidates the complete session.
/// Registry identities prove attachment continuity, never credential admission.
/// Native multi-device transport must own this guard with both device handles;
/// it is not yet wired into custody enrollment, selection or activation.
#[derive(Debug)]
pub struct UsbSelectionSetGuard { generation: u64 }

impl UsbSelectionSetGuard {
    /// Whether both exact attachments and the required native monitor are live.
    pub fn is_current(&self) -> bool { self.require_current().is_ok() }

    /// Refuse a missing member, obsolete generation or unavailable monitor.
    /// This topology guard cannot authorize a credential or revive a grant.
    pub fn require_current(&self) -> EnclaveResult<()> {
        usb_selection().lock().map_err(|_| crate::err!(EIO, "USB_SELECTION_POISONED"))?
            .require(Some(self.generation), 2)
    }
}
impl Drop for UsbSelectionSetGuard {
    fn drop(&mut self) { release_usb_selection(self.generation); }
}

fn release_usb_selection(generation: u64) {
    let invalidate = usb_selection().lock().map(|mut state| state.release(generation)).unwrap_or(true);
    // Never call cancellation hooks while holding the topology mutex.
    if invalidate { let _ = registry().execute(WipeTrigger::AuthenticatorYank); }
}

/// Bind exactly two final selected attachments in one operation. Existing
/// singleton or pair authority must be dropped/fenced before this call; there
/// is no incremental add, replacement or automatic rebind. Both observations
/// must match the current event epoch. Shared ancestors are allowed, but a
/// duplicate service or a service that is the other's ancestor is rejected.
/// The existing singleton admission API deliberately refuses this pair.
pub fn bind_selected_usb_instances(instances: [SelectedUsbInstance; 2]) -> EnclaveResult<UsbSelectionSetGuard> {
    let generation = usb_selection().lock().map_err(|_| crate::err!(EIO, "USB_SELECTION_POISONED"))?
        .bind_set(Vec::from(instances))?;
    Ok(UsbSelectionSetGuard { generation })
}

/// Native custody admission requires a live selection; USB presence alone
/// remains insufficient authentication and does not grant any action authority.
pub fn require_selected_usb_instance() -> EnclaveResult<()> {
    let state = usb_selection().lock().map_err(|_| crate::err!(EIO, "USB_SELECTION_POISONED"))?;
    state.require(None, 1)
}

fn selected_usb_termination(ids: &[Option<u64>]) -> bool {
    usb_selection().lock().map(|mut state| state.terminate(ids)).unwrap_or(true)
}

// Owned by the native worker after every required source is armed. Unwind,
// unexpected run-loop termination and deliberate stop all revoke admission.
// An obsolete worker cannot invalidate a replacement monitor/attachment.
#[cfg(target_os = "macos")]
struct MonitorLiveness(u64);
#[cfg(target_os = "macos")]
impl MonitorLiveness {
    fn start() -> EnclaveResult<Self> {
        Ok(Self(usb_selection().lock().map_err(|_| crate::err!(EIO, "USB_SELECTION_POISONED"))?.monitor_started()?))
    }
    fn require_current(&self) -> EnclaveResult<()> {
        let state = usb_selection().lock().map_err(|_| crate::err!(EIO, "USB_SELECTION_POISONED"))?;
        if !state.monitor_active || state.monitor_generation != self.0 {
            crate::fail!(EIO, "POWER_HEALTH_UNAVAILABLE");
        }
        Ok(())
    }
}
#[cfg(target_os = "macos")]
impl Drop for MonitorLiveness {
    fn drop(&mut self) {
        let lost = usb_selection().lock().map(|mut state| state.monitor_lost(self.0)).unwrap_or(true);
        if lost { let _ = registry().execute(WipeTrigger::AuthenticatorYank); }
    }
}

/// Cryptographic and execution receipt for a completed wipe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WipeReceipt {
    /// Authenticated daemon targeted by a supervisor fanout. Local registry
    /// receipts have no fanout identity; old wire receipts decode as absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemon_uid: Option<u32>,
    /// Trigger that caused the wipe.
    pub trigger: WipeTrigger,
    /// Daemon boot clock (ns) when the wipe began.
    pub t_start_ns: u64,
    /// Daemon boot clock (ns) when the wipe completed.
    pub t_end_ns: u64,
    /// Wall duration in nanoseconds.
    pub duration_ns: u64,
    /// CPU duration in microseconds (must be `<= 1000 µs` per FS budget).
    pub cpu_us: u64,
    /// Whether all registered wipe hooks reported success.
    pub success: bool,
}

/// A wipe hook callback. Must execute within `<= 1 ms` CPU time.
pub type WipeHook = Box<dyn Fn(WipeTrigger) -> EnclaveResult<()> + Send + Sync>;

struct HookEntry {
    name: &'static str,
    #[allow(dead_code)]
    hook: WipeHook,
}

impl std::fmt::Debug for HookEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookEntry")
            .field("name", &self.name)
            .finish()
    }
}

/// Global registry of wipe callbacks for this process.
#[derive(Default, Debug)]
pub struct WipeRegistry {
    hooks: Mutex<Vec<HookEntry>>,
}

static REGISTRY: OnceLock<WipeRegistry> = OnceLock::new();

/// Access the process wipe registry.
pub fn registry() -> &'static WipeRegistry {
    REGISTRY.get_or_init(WipeRegistry::default)
}

/// Start a monitor under the selected security profile. L2/L3 require complete
/// registration; L1 preserves optional monitoring. The caller retains the
/// returned guard until serving has stopped.
pub fn start_for_profile<T>(profile: crate::profile::Profile, start: impl FnOnce() -> EnclaveResult<T>) -> EnclaveResult<Option<T>> {
    match start() {
        Ok(monitor) => Ok(Some(monitor)),
        Err(_) if profile == crate::profile::Profile::L1 => Ok(None),
        Err(error) => Err(error),
    }
}

impl WipeRegistry {
    /// Register a named wipe hook.
    pub fn register<F>(&self, name: &'static str, hook: F)
    where
        F: Fn(WipeTrigger) -> EnclaveResult<()> + Send + Sync + 'static,
    {
        let mut h = self.hooks.lock().unwrap();
        h.push(HookEntry {
            name,
            hook: Box::new(hook),
        });
    }

    /// Execute all registered wipe hooks for `trigger` synchronously.
    pub fn execute(&self, trigger: WipeTrigger) -> WipeReceipt {
        let t_start = continuous_time_ns();
        let cpu_start = thread_cpu_time_us();
        let mut all_ok = true;

        let hooks = self.hooks.lock().unwrap();
        for entry in hooks.iter() {
            let hook_start_cpu = thread_cpu_time_us();
            if let Err(e) = (entry.hook)(trigger) {
                eprintln!("wipe hook '{}' returned error: {e}", entry.name);
                all_ok = false;
            }
            let hook_cpu = thread_cpu_time_us().saturating_sub(hook_start_cpu);
            if hook_cpu > 1000 {
                eprintln!(
                    "SECURITY WARNING: wipe hook '{}' exceeded 1 ms CPU budget: {hook_cpu} µs",
                    entry.name
                );
            }
        }

        let t_end = continuous_time_ns();
        let cpu_total = thread_cpu_time_us().saturating_sub(cpu_start);
        WipeReceipt {
            daemon_uid: None,
            trigger,
            t_start_ns: t_start,
            t_end_ns: t_end,
            duration_ns: t_end.saturating_sub(t_start),
            cpu_us: cpu_total,
            success: all_ok,
        }
    }
}

/// The same boot-relative nanosecond clock used by ceremony deadlines.
/// macOS `mach_continuous_time` has a different origin from CLOCK_MONOTONIC
/// and must not be compared with those absolute deadlines.
pub fn continuous_time_ns() -> u64 {
    crate::clock::boot_clock_ns()
}

/// Per-thread CPU time in microseconds.
fn thread_cpu_time_us() -> u64 {
    #[cfg(target_os = "macos")]
    {
        use libc::{clock_gettime, timespec, CLOCK_THREAD_CPUTIME_ID};
        let mut ts = timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe { clock_gettime(CLOCK_THREAD_CPUTIME_ID, &mut ts) };
        (ts.tv_sec as u64) * 1_000_000 + (ts.tv_nsec as u64) / 1_000
    }
    #[cfg(not(target_os = "macos"))]
    {
        0
    }
}

// -----------------------------------------------------------------------------
// macOS IOKit Power & USB-yank Monitor
// -----------------------------------------------------------------------------

#[cfg(any(target_os = "macos", test))]
trait MonitorRegistration {
    fn register_power(&mut self) -> EnclaveResult<()>;
    fn register_usb(&mut self) -> EnclaveResult<()>;
    fn attach_source(&mut self) -> EnclaveResult<()>;
}

// The registration object owns partial resources and drops them on every
// failed step. Success is announced only after all required sources are armed.
#[cfg(any(target_os = "macos", test))]
fn initialize_monitor<R: MonitorRegistration>(mut registration: R) -> EnclaveResult<R> {
    registration.register_power()?;
    registration.register_usb()?;
    registration.attach_source()?;
    Ok(registration)
}

#[cfg(any(target_os = "macos", test))]
fn stop_monitor_worker(running: &std::sync::atomic::AtomicBool, thread: &mut Option<std::thread::JoinHandle<()>>) {
    running.store(false, std::sync::atomic::Ordering::Relaxed);
    if let Some(worker) = thread.take() { let _ = worker.join(); }
}

#[cfg(any(target_os = "macos", test))]
fn monitor_iteration_progress(result: i32) -> bool {
    // CFRunLoopRunInMode: TimedOut=3, HandledSource=4. Finished=1,
    // Stopped=2 and every undocumented value revoke the worker's health.
    matches!(result, 3 | 4)
}


#[cfg(any(target_os = "macos", test))]
#[derive(Debug)]
struct MonitorHealth {
    phase: std::sync::Arc<std::sync::atomic::AtomicU8>,
    challenges: std::sync::mpsc::SyncSender<MonitorChallenge>,
}
#[cfg(any(target_os = "macos", test))]
#[derive(Debug)]
struct MonitorChallenge(std::sync::mpsc::SyncSender<()>);
#[cfg(any(target_os = "macos", test))]
struct MonitorHealthWorker {
    phase: std::sync::Arc<std::sync::atomic::AtomicU8>,
    challenges: std::sync::mpsc::Receiver<MonitorChallenge>,
}
#[cfg(any(target_os = "macos", test))]
#[derive(Debug)]
struct ArmedMonitorHealth(std::sync::Arc<std::sync::atomic::AtomicU8>);

#[cfg(any(target_os = "macos", test))]
impl MonitorHealth {
    const INITIAL: u8 = 0;
    const ARMED: u8 = 1;
    const REVOKED: u8 = 2;

    // A fresh private channel/state belongs only to this returned monitor and
    // its original registration-owning worker. No reusable success token.
    fn pair() -> (Self, MonitorHealthWorker) {
        let phase = std::sync::Arc::new(std::sync::atomic::AtomicU8::new(Self::INITIAL));
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        (Self { phase: phase.clone(), challenges: send },
            MonitorHealthWorker { phase, challenges: receive })
    }
    fn revoke(&self) {
        self.phase.store(Self::REVOKED, std::sync::atomic::Ordering::Release);
    }
    fn current(&self, running: &std::sync::atomic::AtomicBool,
        worker: Option<&std::thread::JoinHandle<()>>, deadline: std::time::Instant) -> EnclaveResult<()> {
        if std::time::Instant::now() >= deadline { crate::fail!(ETIMEDOUT, "POWER_HEALTH_DEADLINE"); }
        if self.phase.load(std::sync::atomic::Ordering::Acquire) != Self::ARMED
            || !running.load(std::sync::atomic::Ordering::Acquire)
            || worker.is_none_or(std::thread::JoinHandle::is_finished) {
            crate::fail!(EIO, "POWER_HEALTH_UNAVAILABLE");
        }
        Ok(())
    }
    fn observe(&self, running: &std::sync::atomic::AtomicBool,
        worker: Option<&std::thread::JoinHandle<()>>, deadline: std::time::Instant) -> EnclaveResult<()> {
        self.current(running, worker, deadline)?;
        // Every call owns a fresh one-shot reply. An old reply or a different
        // caller cannot satisfy this challenge, even after an earlier timeout.
        let (reply, receive) = std::sync::mpsc::sync_channel(1);
        match self.challenges.try_send(MonitorChallenge(reply)) {
            Ok(()) => (),
            Err(std::sync::mpsc::TrySendError::Full(_)) => crate::fail!(EAGAIN, "POWER_HEALTH_BUSY"),
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => crate::fail!(EIO, "POWER_HEALTH_UNAVAILABLE"),
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() { crate::fail!(ETIMEDOUT, "POWER_HEALTH_DEADLINE"); }
        match receive.recv_timeout(remaining) {
            Ok(()) => (),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => crate::fail!(ETIMEDOUT, "POWER_HEALTH_DEADLINE"),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => crate::fail!(EIO, "POWER_HEALTH_UNAVAILABLE"),
        }
        // A reply is only a point-in-time worker-loop observation. Stop, exit
        // or unwind after sending it cannot leave a stale armed flag sufficient.
        self.current(running, worker, deadline)
    }
}
#[cfg(any(target_os = "macos", test))]
impl Drop for MonitorHealth {
    fn drop(&mut self) { self.revoke(); }
}
#[cfg(any(target_os = "macos", test))]
impl MonitorHealthWorker {
    fn arm(&self, running: &std::sync::atomic::AtomicBool) -> EnclaveResult<ArmedMonitorHealth> {
        if !running.load(std::sync::atomic::Ordering::Acquire) { crate::fail!(EIO, "POWER_HEALTH_UNAVAILABLE"); }
        self.phase.compare_exchange(MonitorHealth::INITIAL, MonitorHealth::ARMED,
            std::sync::atomic::Ordering::AcqRel, std::sync::atomic::Ordering::Acquire)
            .map_err(|_| crate::err!(EIO, "POWER_HEALTH_UNAVAILABLE"))?;
        Ok(ArmedMonitorHealth(self.phase.clone()))
    }
    fn next_challenge(&self) -> Option<MonitorChallenge> { self.challenges.try_recv().ok() }
    fn acknowledge(&self, challenge: MonitorChallenge, running: &std::sync::atomic::AtomicBool) {
        if self.phase.load(std::sync::atomic::Ordering::Acquire) == MonitorHealth::ARMED
            && running.load(std::sync::atomic::Ordering::Acquire) {
            let _ = challenge.0.try_send(());
        }
    }
}
#[cfg(any(target_os = "macos", test))]
impl Drop for MonitorHealthWorker {
    fn drop(&mut self) { self.phase.store(MonitorHealth::REVOKED, std::sync::atomic::Ordering::Release); }
}
#[cfg(any(target_os = "macos", test))]
impl Drop for ArmedMonitorHealth {
    fn drop(&mut self) { self.0.store(MonitorHealth::REVOKED, std::sync::atomic::Ordering::Release); }
}

/// macOS IOKit power and USB monitoring.
#[cfg(target_os = "macos")]
pub mod darwin {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;

    use super::{registry, WipeTrigger};
    use crate::error::EnclaveResult;

    #[link(name = "IOKit", kind = "framework")]
    extern "C" {
        fn IORegisterForSystemPower(
            refcon: *mut libc::c_void,
            thePortRef: *mut *mut libc::c_void,
            callback: extern "C" fn(
                refcon: *mut libc::c_void,
                service: u32,
                message_type: u32,
                message_arg: *mut libc::c_void,
            ),
            notifier: *mut u32,
        ) -> u32;

        fn IOAllowPowerChange(kernelPort: u32, notificationID: libc::intptr_t) -> i32;
        fn IODeregisterForSystemPower(notifier: *mut u32) -> i32;

        fn IONotificationPortGetRunLoopSource(notify: *mut libc::c_void) -> *mut libc::c_void;
        fn IONotificationPortDestroy(notify: *mut libc::c_void);

        fn IOServiceMatching(name: *const libc::c_char) -> *mut libc::c_void;
        fn IOServiceAddMatchingNotification(
            notifyPort: *mut libc::c_void,
            notificationType: *const libc::c_char,
            matching: *mut libc::c_void,
            callback: extern "C" fn(refcon: *mut libc::c_void, iterator: u32),
            refcon: *mut libc::c_void,
            notification: *mut u32,
        ) -> i32;
        fn IOIteratorNext(iterator: u32) -> u32;
        fn IORegistryEntryGetRegistryEntryID(entry: u32, entry_id: *mut u64) -> i32;
        fn IOObjectRelease(object: u32) -> i32;
        fn IOServiceClose(connection: u32) -> i32;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFRunLoopGetCurrent() -> *mut libc::c_void;
        fn CFRunLoopAddSource(
            rl: *mut libc::c_void,
            source: *mut libc::c_void,
            mode: *const libc::c_void,
        );
        fn CFRunLoopRunInMode(mode: *const libc::c_void, seconds: f64, return_after_source: u8) -> i32;
        fn CFRunLoopRemoveSource(rl: *mut libc::c_void, source: *mut libc::c_void, mode: *const libc::c_void);
        fn CFRunLoopContainsSource(rl: *mut libc::c_void, source: *mut libc::c_void, mode: *const libc::c_void) -> u8;

        static kCFRunLoopDefaultMode: *const libc::c_void;
    }

    const K_IOMESSAGE_CAN_SYSTEM_SLEEP: u32 = 0xe0000270;
    const K_IOMESSAGE_SYSTEM_WILL_SLEEP: u32 = 0xe0000280;

    struct PowerContext {
        root_port: u32,
        #[allow(dead_code)]
        run_loop: *mut libc::c_void,
    }

    unsafe impl Send for PowerContext {}

    struct Registrations {
        context: *mut PowerContext,
        root_port: u32,
        notify_port: *mut libc::c_void,
        notifier: u32,
        usb_iter: u32,
        source: *mut libc::c_void,
        run_loop: *mut libc::c_void,
    }
    impl super::MonitorRegistration for Registrations {
        fn register_power(&mut self) -> EnclaveResult<()> {
            self.root_port = unsafe { IORegisterForSystemPower(self.context.cast(), &mut self.notify_port, power_callback, &mut self.notifier) };
            if self.root_port == 0 || self.notify_port.is_null() || self.notifier == 0 {
                crate::fail!(EIO, "IOKIT_REGISTER_FAILED");
            }
            unsafe { (*self.context).root_port = self.root_port; }
            Ok(())
        }
        fn register_usb(&mut self) -> EnclaveResult<()> {
            let matching = unsafe { IOServiceMatching(c"IOUSBHostDevice".as_ptr()) };
            if matching.is_null() { crate::fail!(EIO, "IOKIT_USB_MATCH_FAILED"); }
            let result = unsafe { IOServiceAddMatchingNotification(self.notify_port, c"IOServiceTerminate".as_ptr(), matching, usb_terminate_callback, std::ptr::null_mut(), &mut self.usb_iter) };
            if result != 0 || self.usb_iter == 0 { crate::fail!(EIO, "IOKIT_USB_REGISTER_FAILED"); }
            let mut object = unsafe { IOIteratorNext(self.usb_iter) };
            while object != 0 { unsafe { IOObjectRelease(object); } object = unsafe { IOIteratorNext(self.usb_iter) }; }
            Ok(())
        }
        fn attach_source(&mut self) -> EnclaveResult<()> {
            self.run_loop = unsafe { CFRunLoopGetCurrent() };
            self.source = unsafe { IONotificationPortGetRunLoopSource(self.notify_port) };
            if self.run_loop.is_null() || self.source.is_null() { crate::fail!(EIO, "POWER_RUNLOOP_SOURCE"); }
            unsafe {
                (*self.context).run_loop = self.run_loop;
                CFRunLoopAddSource(self.run_loop, self.source, kCFRunLoopDefaultMode);
                if CFRunLoopContainsSource(self.run_loop, self.source, kCFRunLoopDefaultMode) == 0 {
                    crate::fail!(EIO, "POWER_RUNLOOP_SOURCE");
                }
            }
            Ok(())
        }
    }
    impl Drop for Registrations {
        fn drop(&mut self) {
            unsafe {
                if !self.run_loop.is_null() && !self.source.is_null() { CFRunLoopRemoveSource(self.run_loop, self.source, kCFRunLoopDefaultMode); }
                if self.usb_iter != 0 { IOObjectRelease(self.usb_iter); }
                if self.notifier != 0 { IODeregisterForSystemPower(&mut self.notifier); }
                if self.root_port != 0 { IOServiceClose(self.root_port); }
                if !self.notify_port.is_null() { IONotificationPortDestroy(self.notify_port); }
            }
        }
    }

    extern "C" fn power_callback(
        refcon: *mut libc::c_void,
        _service: u32,
        message_type: u32,
        message_arg: *mut libc::c_void,
    ) {
        if refcon.is_null() {
            return;
        }
        let ctx = unsafe { &*(refcon as *mut PowerContext) };

        match message_type {
            K_IOMESSAGE_CAN_SYSTEM_SLEEP | K_IOMESSAGE_SYSTEM_WILL_SLEEP => {
                // Synchronously execute every registered wipe hook before allowing sleep
                let receipt = registry().execute(WipeTrigger::SystemSleep);
                eprintln!(
                    "POWER: executed SystemSleep wipes: {} µs CPU, success={}",
                    receipt.cpu_us, receipt.success
                );
                // Allow kernel to proceed with sleep
                unsafe {
                    IOAllowPowerChange(ctx.root_port, message_arg as libc::intptr_t);
                }
            }
            _ => {}
        }
    }

    extern "C" fn usb_terminate_callback(_refcon: *mut libc::c_void, iterator: u32) {
        let mut obj = unsafe { IOIteratorNext(iterator) };
        let mut identities = Vec::new();
        while obj != 0 {
            let mut id = 0;
            let result = unsafe { IORegistryEntryGetRegistryEntryID(obj, &mut id) };
            identities.push(if result == 0 && id != 0 { Some(id) } else { None });
            unsafe { IOObjectRelease(obj) };
            obj = unsafe { IOIteratorNext(iterator) };
        }
        if super::selected_usb_termination(&identities) {
            let receipt = registry().execute(WipeTrigger::AuthenticatorYank);
            eprintln!(
                "POWER: executed AuthenticatorYank wipes: {} µs CPU, success={}",
                receipt.cpu_us, receipt.success
            );
        }
    }

    /// Background handle keeping the IOKit power runloop alive.
    #[derive(Debug)]
    pub struct PowerMonitor {
        running: Arc<AtomicBool>,
        thread: Option<thread::JoinHandle<()>>,
        health: super::MonitorHealth,
    }

    impl PowerMonitor {
        /// Start system power monitoring on a background CFRunLoop thread.
        pub fn start() -> EnclaveResult<Self> {
            let running = Arc::new(AtomicBool::new(true));
            let running_cl = running.clone();
            let (health, health_worker) = super::MonitorHealth::pair();

            let (tx, rx) = std::sync::mpsc::channel();

            let handle = thread::Builder::new()
                .name("depot-power".into())
                .spawn(move || {
                    let mut ctx = Box::new(PowerContext {
                        root_port: 0,
                        run_loop: std::ptr::null_mut(),
                    });

                    let resources = Registrations { context: &mut *ctx, root_port: 0, notify_port: std::ptr::null_mut(), notifier: 0, usb_iter: 0, source: std::ptr::null_mut(), run_loop: std::ptr::null_mut() };
                    let resources = match super::initialize_monitor(resources) {
                        Ok(resources) => resources,
                        Err(error) => { let _ = tx.send(Err(error)); return; }
                    };
                    let liveness = match super::MonitorLiveness::start() {
                        Ok(liveness) => liveness,
                        Err(error) => { let _ = tx.send(Err(error)); return; }
                    };
                    // Declared after the actual registrations/liveness so
                    // unwind revokes health BEFORE those owners are released.
                    let health_armed = match health_worker.arm(&running_cl) {
                        Ok(armed) => armed,
                        Err(error) => { let _ = tx.send(Err(error)); return; }
                    };
                    // If startup abandoned its receiver, drop every resource
                    // on this thread rather than running an orphaned monitor.
                    if tx.send(Ok(())).is_err() { return; }

                    while running_cl.load(Ordering::Relaxed) {
                        unsafe {
                            // A bounded iteration also handles stop racing the
                            // first run-loop entry without an unbounded join.
                            let result = CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.1, 1);
                            // Only documented live outcomes can satisfy a
                            // challenge; unknown results also revoke on exit.
                            if !super::monitor_iteration_progress(result) { break; }
                        }
                        if let Some(challenge) = health_worker.next_challenge() {
                            // Only this exact resource-owning loop may answer;
                            // a blocked callback cannot be answered elsewhere.
                            if !running_cl.load(Ordering::Acquire) || liveness.require_current().is_err() || unsafe {
                                CFRunLoopContainsSource(resources.run_loop, resources.source, kCFRunLoopDefaultMode)
                            } == 0 { break; }
                            health_worker.acknowledge(challenge, &running_cl);
                        }
                    }

                    drop(health_armed);
                    drop(liveness);
                    drop(resources);
                })
                .map_err(|e| crate::err!(EIO, "POWER_THREAD", "{e}"))?;

            match rx.recv_timeout(std::time::Duration::from_secs(5)) {
                Ok(Ok(())) => (),
                Ok(Err(error)) => { let _ = handle.join(); return Err(error); }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => { let _ = handle.join(); return Err(crate::err!(EIO, "POWER_INIT_FAILED")); }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    running.store(false, Ordering::Relaxed);
                    // Native registration itself cannot safely be cancelled.
                    // The thread owns its context/resources and cleans them
                    // when registration returns and observes receiver loss.
                    return Err(crate::err!(ETIMEDOUT, "POWER_INIT_DEADLINE"));
                }
            };

            Ok(Self {
                running,
                thread: Some(handle),
                health,
            })
        }

        /// Observe fresh progress of the original registration-owning worker.
        /// This is neither a readiness permit nor a promise of future delivery.
        pub(crate) fn observe_health(&self, deadline: std::time::Instant) -> EnclaveResult<()> {
            self.health.observe(&self.running, self.thread.as_ref(), deadline)
        }

        /// Stop power monitoring and clean up.
        pub fn stop(&mut self) {
            self.health.revoke();
            // Only the worker accesses its borrowed CFRunLoop. Bounded loop
            // iterations observe the flag; repeated stop never uses a stale
            // thread-owned pointer or attempts to join the thread twice.
            super::stop_monitor_worker(&self.running, &mut self.thread);
        }
    }

    impl Drop for PowerMonitor {
        fn drop(&mut self) {
            self.stop();
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub mod darwin {
    //! Darwin power monitor stub for non-macOS platforms.
    use crate::error::EnclaveResult;

    /// Stub for non-macOS platforms.
    #[derive(Debug)]
    pub struct PowerMonitor;

    impl PowerMonitor {
        /// Start power monitoring (not supported on non-macOS).
        pub fn start() -> EnclaveResult<Self> {
            crate::fail!(
                ENOSYS,
                "NOT_SUPPORTED",
                "Power monitoring is only supported on macOS"
            )
        }

        /// Native registration/worker health is unavailable on this platform.
        pub(crate) fn observe_health(&self, _deadline: std::time::Instant) -> EnclaveResult<()> {
            crate::fail!(ENOSYS, "NOT_SUPPORTED", "Power monitoring is only supported on macOS")
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn yk03_transport_and_ceremony_deadlines_share_the_boot_clock_origin() {
        let before = crate::clock::boot_clock_ns();
        let transport_now = super::continuous_time_ns();
        let after = crate::clock::boot_clock_ns();
        assert!(before <= transport_now && transport_now <= after);
        assert!(transport_now < before.saturating_add(10_000_000_000));
    }
    use super::*;
    use std::sync::Arc;

    // Synthetic worker fixtures use the actual private challenge/owner machinery.
    // They never construct native PowerMonitor success or register IOKit sources.
    struct HealthFixture {
        health: MonitorHealth,
        running: Arc<std::sync::atomic::AtomicBool>,
        worker: Option<std::thread::JoinHandle<()>>,
    }
    impl HealthFixture {
        fn spawn(body: impl FnOnce(MonitorHealthWorker, ArmedMonitorHealth,
            Arc<std::sync::atomic::AtomicBool>) + Send + 'static) -> Self {
            let (health, worker_health) = MonitorHealth::pair();
            let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let worker_running = running.clone();
            let (ready, started) = std::sync::mpsc::sync_channel(1);
            let worker = std::thread::spawn(move || {
                let armed = worker_health.arm(&worker_running).unwrap();
                ready.send(()).unwrap();
                body(worker_health, armed, worker_running);
            });
            started.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
            Self { health, running, worker: Some(worker) }
        }
        fn observe(&self, deadline: std::time::Instant) -> EnclaveResult<()> {
            self.health.observe(&self.running, self.worker.as_ref(), deadline)
        }
        fn stop(&mut self) {
            self.health.revoke();
            stop_monitor_worker(&self.running, &mut self.worker);
        }
    }
    impl Drop for HealthFixture { fn drop(&mut self) { self.stop(); } }
    fn health_deadline() -> std::time::Instant {
        std::time::Instant::now() + std::time::Duration::from_secs(1)
    }
    fn health_loop(worker: &MonitorHealthWorker, running: &std::sync::atomic::AtomicBool) {
        while running.load(std::sync::atomic::Ordering::Acquire) {
            if let Some(challenge) = worker.next_challenge() { worker.acknowledge(challenge, running); }
            std::thread::park_timeout(std::time::Duration::from_millis(1));
        }
    }

    #[test]
    fn power_health_actual_fixture_worker_acknowledges_fresh_requests_and_stop_revokes() {
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = requests.clone();
        let mut fixture = HealthFixture::spawn(move |worker, _armed, running| {
            while running.load(std::sync::atomic::Ordering::Acquire) {
                if let Some(challenge) = worker.next_challenge() {
                    counted.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    worker.acknowledge(challenge, &running);
                }
                std::thread::park_timeout(std::time::Duration::from_millis(1));
            }
        });
        fixture.observe(health_deadline()).unwrap();
        fixture.observe(health_deadline()).unwrap();
        assert_eq!(requests.load(std::sync::atomic::Ordering::Acquire), 2);
        fixture.stop();
        assert!(fixture.worker.is_none());
        assert!(fixture.observe(health_deadline()).unwrap_err().is("POWER_HEALTH_UNAVAILABLE"));
        fixture.stop();
    }

    #[test]
    fn power_health_only_documented_run_loop_progress_can_precede_an_ack() {
        let live = (-128..=127).filter(|result| monitor_iteration_progress(*result)).collect::<Vec<_>>();
        assert_eq!(live, vec![3, 4]);
        for result in [i32::MIN, -65_536, -1, 0, 1, 2, 5, 65_536, i32::MAX] {
            assert!(!monitor_iteration_progress(result), "unknown/terminal run-loop result {result}");
        }
    }

    #[test]
    fn power_health_unarmed_missing_original_handle_and_cancelled_monitor_refuse() {
        let (health, worker_health) = MonitorHealth::pair();
        let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let worker_running = running.clone();
        let (release, held) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            held.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
            // Owner revocation cannot be undone by a late registration worker.
            assert!(worker_health.arm(&worker_running).unwrap_err().is("POWER_HEALTH_UNAVAILABLE"));
        });
        assert!(health.observe(&running, Some(&worker), health_deadline()).unwrap_err().is("POWER_HEALTH_UNAVAILABLE"));
        health.revoke();
        release.send(()).unwrap(); worker.join().unwrap();

        let fixture = HealthFixture::spawn(|worker, _armed, running| health_loop(&worker, &running));
        assert!(fixture.health.observe(&fixture.running, None, health_deadline()).unwrap_err().is("POWER_HEALTH_UNAVAILABLE"));
        fixture.running.store(false, std::sync::atomic::Ordering::Release);
        assert!(fixture.observe(health_deadline()).unwrap_err().is("POWER_HEALTH_UNAVAILABLE"));
    }

    #[test]
    fn power_health_worker_exit_and_unwind_revoke_even_with_running_flag_still_true() {
        for panic_worker in [false, true] {
            let fixture = HealthFixture::spawn(move |_, _armed, _| {
                if panic_worker { panic!("synthetic power health worker unwind"); }
            });
            let until = health_deadline();
            while !fixture.worker.as_ref().unwrap().is_finished() {
                assert!(std::time::Instant::now() < until);
                std::thread::yield_now();
            }
            assert!(fixture.running.load(std::sync::atomic::Ordering::Acquire));
            assert!(fixture.observe(health_deadline()).unwrap_err().is("POWER_HEALTH_UNAVAILABLE"));
            assert_eq!(fixture.health.phase.load(std::sync::atomic::Ordering::Acquire), MonitorHealth::REVOKED);
        }
    }

    #[test]
    fn power_health_stalled_worker_refuses_and_expired_reply_cannot_satisfy_fresh_probe() {
        let (release, held) = std::sync::mpsc::sync_channel(1);
        let (drained, old_drained) = std::sync::mpsc::sync_channel(1);
        let fixture = HealthFixture::spawn(move |worker, _armed, running| {
            held.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
            let expired = worker.challenges.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
            worker.acknowledge(expired, &running);
            drained.send(()).unwrap();
            health_loop(&worker, &running);
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(30);
        assert!(fixture.observe(deadline).unwrap_err().is("POWER_HEALTH_DEADLINE"));
        assert!(fixture.observe(health_deadline()).unwrap_err().is("POWER_HEALTH_BUSY"));
        assert!(fixture.running.load(std::sync::atomic::Ordering::Acquire));
        assert!(!fixture.worker.as_ref().unwrap().is_finished());
        release.send(()).unwrap();
        old_drained.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        fixture.observe(health_deadline()).unwrap();
    }

    #[test]
    fn power_health_revoke_racing_pending_probe_refuses_without_rearming() {
        let (received, pending) = std::sync::mpsc::sync_channel(1);
        let (release, held) = std::sync::mpsc::sync_channel(1);
        let fixture = HealthFixture::spawn(move |worker, armed, running| {
            let challenge = worker.challenges.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
            received.send(()).unwrap();
            held.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
            drop(armed);
            assert!(worker.arm(&running).unwrap_err().is("POWER_HEALTH_UNAVAILABLE"));
            worker.acknowledge(challenge, &running);
        });
        std::thread::scope(|scope| {
            let observer = scope.spawn(|| fixture.observe(health_deadline()));
            pending.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
            fixture.health.revoke();
            release.send(()).unwrap();
            assert!(observer.join().unwrap().unwrap_err().is("POWER_HEALTH_UNAVAILABLE"));
        });
    }

    #[test]
    fn power_health_final_original_state_rejects_ack_from_a_revoked_worker() {
        let fixture = HealthFixture::spawn(move |worker, armed, _| {
            let challenge = worker.challenges.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
            drop(armed);
            // Fault injection in the SAME synthetic owner: deliver an old ack
            // despite revocation. Final state/handle checks must still refuse.
            challenge.0.try_send(()).unwrap();
        });
        assert!(fixture.observe(health_deadline()).unwrap_err().is("POWER_HEALTH_UNAVAILABLE"));
    }

    #[test]
    fn power_health_expired_endpoint_enqueues_nothing_and_old_owner_cannot_revoke_replacement() {
        let mut old = HealthFixture::spawn(|worker, _armed, running| health_loop(&worker, &running));
        let current = HealthFixture::spawn(|worker, _armed, running| health_loop(&worker, &running));
        assert!(current.observe(std::time::Instant::now()).unwrap_err().is("POWER_HEALTH_DEADLINE"));
        old.stop(); drop(old);
        current.observe(health_deadline()).unwrap();
        current.observe(health_deadline()).unwrap();
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn power_health_non_native_monitor_never_reports_native_health() {
        assert!(darwin::PowerMonitor.observe_health(health_deadline()).unwrap_err().is("NOT_SUPPORTED"));
    }

    fn instance(id: u64, ancestors: &[u64], epoch: u64) -> SelectedUsbInstance {
        SelectedUsbInstance { service_registry_id: id, ancestor_registry_ids: ancestors.into(), observed_event_epoch: epoch }
    }

    #[test]
    fn yk02_unrelated_usb_removal_preserves_selected_instance_but_parent_loss_revokes() {
        let mut state = UsbSelection::default();
        let generation = state.bind(instance(42, &[7, 1], 0)).unwrap();
        assert!(!state.terminate(&[Some(99)]));
        assert_eq!(state.selected.as_ref().unwrap().0, generation);
        assert!(state.terminate(&[Some(7)]));
        assert!(state.selected.is_none());
    }

    #[test]
    fn yk02_unknown_missing_and_selected_identity_fail_closed_and_never_auto_rebind() {
        let mut state = UsbSelection::default();
        assert!(!state.terminate(&[]));
        assert!(state.terminate(&[Some(99)])); // no known binding
        state.bind(instance(42, &[7], 1)).unwrap();
        assert!(state.terminate(&[None]));
        assert!(state.selected.is_none());
        assert!(state.bind(instance(42, &[7], 1)).unwrap_err().is("USB_SELECTION_CHANGED"));
        state.bind(instance(43, &[7], 2)).unwrap();
        assert!(state.terminate(&[Some(43)]));
        assert!(state.selected.is_none());
    }

    #[test]
    fn yk02_same_model_reenumeration_and_stale_callbacks_do_not_alias_registry_identity() {
        let mut state = UsbSelection::default();
        let first = state.bind(instance(42, &[7], 0)).unwrap();
        assert!(state.bind(instance(43, &[7], 0)).unwrap_err().is("USB_SELECTION_ALREADY_BOUND"));
        assert!(state.terminate(&[Some(42)]));
        let second = state.bind(instance(43, &[7], 1)).unwrap();
        assert_ne!(first, second);
        assert!(!state.terminate(&[Some(42)]));
        assert_eq!(state.selected.as_ref().unwrap().0, second);
    }

    #[test]
    fn yk12_monitor_loss_revokes_attachment_and_stale_worker_cannot_revoke_replacement() {
        let mut state = UsbSelection::default();
        let first = state.monitor_started().unwrap();
        state.bind(instance(42, &[7], 0)).unwrap();
        assert!(state.monitor_lost(first));
        assert!(!state.monitor_active);
        assert!(state.selected.is_none());
        assert!(state.bind(instance(42, &[7], 0)).is_err());
        let replacement = state.monitor_started().unwrap();
        state.bind(instance(43, &[7], 1)).unwrap();
        assert!(!state.monitor_lost(first));
        assert!(state.monitor_active);
        assert!(state.selected.is_some());
        assert!(state.monitor_lost(replacement));
    }

    fn pair(epoch: u64) -> Vec<SelectedUsbInstance> {
        vec![instance(42, &[7, 1], epoch), instance(43, &[8, 1], epoch)]
    }

    #[test]
    fn yk02_pair_preserves_both_on_unrelated_loss_and_cannot_supply_singleton_admission() {
        let mut state = UsbSelection::default(); state.monitor_started().unwrap();
        let generation = state.bind_set(pair(0)).unwrap();
        state.require(Some(generation), 2).unwrap();
        assert!(state.require(None, 1).unwrap_err().is("USB_SELECTION_UNAVAILABLE"));
        assert!(!state.current(generation, 1)); assert!(state.current(generation, 2));
        assert!(!state.terminate(&[Some(99)]));
        assert_eq!(state.selected.as_ref().unwrap().1.len(), 2);
        state.require(Some(generation), 2).unwrap();
        assert!(state.bind(instance(44, &[9], 1)).unwrap_err().is("USB_SELECTION_ALREADY_BOUND"));
        assert!(state.current(generation, 2), "no implicit downgrade or incremental addition");
    }

    #[test]
    fn yk02_pair_either_device_ancestor_common_parent_or_unknown_loss_revokes_entire_set() {
        for loss in [Some(42), Some(43), Some(7), Some(8), Some(1), Some(0), None] {
            let mut state = UsbSelection::default(); state.monitor_started().unwrap();
            let generation = state.bind_set(pair(0)).unwrap();
            assert!(state.terminate(&[Some(99), loss]));
            assert!(state.selected.is_none()); assert!(!state.current(generation, 2));
            assert!(state.require(Some(generation), 2).is_err());
            assert!(!state.release(generation), "an obsolete owner cannot release again");
            assert!(state.bind_set(pair(0)).unwrap_err().is("USB_SELECTION_CHANGED"));
        }
    }

    #[test]
    fn yk02_pair_rejects_partial_upgrade_alias_stale_or_malformed_sets_without_mutation() {
        let invalid = [vec![], vec![instance(42, &[7], 0), instance(43, &[8], 0), instance(44, &[9], 0)],
            vec![instance(42, &[7], 0), instance(42, &[8], 0)],
            vec![instance(42, &[7], 0), instance(43, &[42, 7], 0)],
            vec![instance(42, &[43, 8], 0), instance(43, &[8], 0)],
            vec![instance(42, &[7], 0), instance(43, &[8], 1)],
            vec![instance(42, &[7], 0), instance(0, &[8], 0)],
            vec![instance(42, &[7], 0), instance(43, &[8, 8], 0)]];
        let mut state = UsbSelection::default();
        for attempted in invalid {
            assert!(state.bind_set(attempted).is_err());
            assert!(state.selected.is_none()); assert_eq!(state.generation, 0);
        }
        let single = state.bind(instance(42, &[7], 0)).unwrap();
        assert!(state.bind_set(pair(0)).unwrap_err().is("USB_SELECTION_ALREADY_BOUND"));
        assert!(state.current(single, 1)); assert!(!state.current(single, 2));
        assert!(state.release(single));
        let complete = state.bind_set(pair(0)).unwrap();
        assert_ne!(single, complete); assert!(!state.release(single));
        assert!(state.current(complete, 2));
    }

    #[test]
    fn yk02_pair_obsolete_owner_and_old_device_callback_cannot_revoke_new_session() {
        let mut state = UsbSelection::default(); state.monitor_started().unwrap();
        let old = state.bind_set(pair(0)).unwrap(); assert!(state.terminate(&[Some(42)]));
        let current = state.bind_set(vec![instance(44, &[9, 1], 1), instance(45, &[10, 1], 1)]).unwrap();
        assert!(!state.release(old)); assert!(!state.terminate(&[Some(42), Some(43)]));
        assert!(state.require(Some(old), 2).is_err()); state.require(Some(current), 2).unwrap();
        assert!(state.release(current)); assert!(state.selected.is_none());
        let single = state.bind(instance(46, &[11, 1], 2)).unwrap();
        assert!(!state.release(current)); assert!(state.current(single, 1));
        state.require(Some(single), 1).unwrap();
    }

    #[test]
    fn yk12_pair_monitor_loss_invalidates_all_and_obsolete_monitor_cannot_revoke_replacement() {
        let mut state = UsbSelection::default(); let monitor = state.monitor_started().unwrap();
        let old = state.bind_set(pair(0)).unwrap(); assert!(state.monitor_lost(monitor));
        assert!(!state.current(old, 2)); assert!(state.selected.is_none());
        assert!(state.bind_set(pair(0)).unwrap_err().is("USB_SELECTION_CHANGED"));
        let replacement = state.monitor_started().unwrap();
        let current = state.bind_set(vec![instance(44, &[9, 1], 1), instance(45, &[10, 1], 1)]).unwrap();
        assert!(!state.monitor_lost(monitor)); state.require(Some(current), 2).unwrap();
        assert!(state.monitor_lost(replacement)); assert!(state.selected.is_none());
        assert!(state.require(Some(current), 2).is_err());
    }

    #[test]
    fn yk02_pair_event_generation_and_monitor_exhaustion_never_wrap_or_admit() {
        let mut state = UsbSelection { generation: u64::MAX, ..Default::default() };
        assert!(state.bind_set(pair(0)).unwrap_err().is("USB_SELECTION_EXHAUSTED"));
        assert!(state.selected.is_none()); assert_eq!(state.generation, u64::MAX);
        let mut state = UsbSelection { event_epoch: u64::MAX, ..Default::default() };
        assert!(state.bind_set(pair(u64::MAX)).unwrap_err().is("USB_SELECTION_CHANGED"));
        assert!(state.selected.is_none()); assert_eq!(state.generation, 0);
        let mut state = UsbSelection { event_epoch: u64::MAX-1, ..Default::default() };
        state.monitor_started().unwrap(); let old = state.bind_set(pair(u64::MAX-1)).unwrap();
        assert!(!state.terminate(&[Some(99)])); assert_eq!(state.event_epoch, u64::MAX);
        assert!(state.require(Some(old), 2).is_err());
        assert!(!state.terminate(&[Some(99)])); assert_eq!(state.event_epoch, u64::MAX);
        assert!(state.release(old));
        assert!(state.bind_set(pair(u64::MAX)).is_err());
        let mut state = UsbSelection { monitor_generation: u64::MAX, ..Default::default() };
        assert!(state.monitor_started().unwrap_err().is("POWER_MONITOR_GENERATION_EXHAUSTED"));
        assert!(!state.monitor_active);
    }

    #[test]
    fn yk02_pair_concurrent_complete_bindings_cannot_publish_a_mixed_or_partial_set() {
        let state = Arc::new(Mutex::new(UsbSelection::default()));
        let start = Arc::new(std::sync::Barrier::new(3));
        let contenders: Vec<_> = [42, 44].into_iter().map(|first| {
            let state = state.clone(); let start = start.clone();
            std::thread::spawn(move || {
                let instances = vec![instance(first, &[7, 1], 0), instance(first+1, &[8, 1], 0)];
                start.wait(); let result = state.lock().unwrap().bind_set(instances); result
            })
        }).collect();
        start.wait(); let results: Vec<_> = contenders.into_iter().map(|worker| worker.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert!(results.iter().filter_map(|result| result.as_ref().err()).all(|error| error.is("USB_SELECTION_ALREADY_BOUND")));
        let state = state.lock().unwrap(); assert_eq!(state.generation, 1);
        let ids: Vec<_> = state.selected.as_ref().unwrap().1.iter().map(|instance| instance.service_registry_id).collect();
        assert!(ids == vec![42, 43] || ids == vec![44, 45]);
    }

    #[test]
    fn yk02_pair_loss_racing_atomic_bind_leaves_no_admission_under_either_order() {
        let state = Arc::new(Mutex::new(UsbSelection::default()));
        state.lock().unwrap().monitor_started().unwrap();
        let start = Arc::new(std::sync::Barrier::new(3));
        let binding = { let state = state.clone(); let start = start.clone();
            std::thread::spawn(move || { start.wait(); let result = state.lock().unwrap().bind_set(pair(0)); result }) };
        let losing = { let state = state.clone(); let start = start.clone();
            std::thread::spawn(move || { start.wait(); let result = state.lock().unwrap().terminate(&[Some(43)]); result }) };
        start.wait(); let result = binding.join().unwrap(); assert!(losing.join().unwrap());
        let state = state.lock().unwrap(); assert!(state.selected.is_none());
        assert_eq!(state.event_epoch, 1); assert!(state.require(None, 2).is_err());
        if let Err(error) = result { assert!(error.is("USB_SELECTION_CHANGED")); }
    }

    #[test]
    fn f38_monitor_stop_joins_once_and_never_reuses_thread_owned_native_handles() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let running = Arc::new(AtomicBool::new(true));
        let released = Arc::new(AtomicUsize::new(0));
        let worker_running = running.clone();
        let worker_released = released.clone();
        let mut worker = Some(std::thread::spawn(move || {
            while worker_running.load(Ordering::Relaxed) { std::thread::yield_now(); }
            worker_released.fetch_add(1, Ordering::SeqCst);
        }));
        stop_monitor_worker(&running, &mut worker);
        assert!(worker.is_none());
        assert_eq!(released.load(Ordering::SeqCst), 1);
        stop_monitor_worker(&running, &mut worker);
        assert_eq!(released.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn f38_monitor_registration_requires_power_usb_and_armed_source_with_partial_cleanup() {
        #[derive(Clone)]
        struct Fixture { calls: Arc<Mutex<Vec<&'static str>>>, fail: &'static str }
        impl Fixture {
            fn step(&self, name: &'static str) -> EnclaveResult<()> {
                self.calls.lock().unwrap().push(name);
                if self.fail == name { return Err(crate::err!(EIO, "FIXTURE_MONITOR_REGISTRATION")); }
                Ok(())
            }
        }
        impl MonitorRegistration for Fixture {
            fn register_power(&mut self) -> EnclaveResult<()> { self.step("power") }
            fn register_usb(&mut self) -> EnclaveResult<()> { self.step("usb") }
            fn attach_source(&mut self) -> EnclaveResult<()> { self.step("source") }
        }
        impl Drop for Fixture { fn drop(&mut self) { self.calls.lock().unwrap().push("cleanup"); } }
        for (failure, expected) in [
            ("power", vec!["power", "cleanup"]),
            ("usb", vec!["power", "usb", "cleanup"]),
            ("source", vec!["power", "usb", "source", "cleanup"]),
            ("", vec!["power", "usb", "source"]),
        ] {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let result = initialize_monitor(Fixture { calls: calls.clone(), fail: failure });
            assert_eq!(*calls.lock().unwrap(), expected);
            if failure.is_empty() {
                drop(result.unwrap());
                assert_eq!(*calls.lock().unwrap(), vec!["power", "usb", "source", "cleanup"]);
            } else { assert!(result.err().unwrap().is("FIXTURE_MONITOR_REGISTRATION")); }
        }
    }

    #[test]
    fn wipe_registry_executes_hooks_and_measures_duration() {
        let reg = registry();
        let executed = Arc::new(Mutex::new(Vec::new()));
        let ex_cl = executed.clone();

        reg.register("test_hook_1", move |trigger| {
            ex_cl.lock().unwrap().push(trigger);
            Ok(())
        });

        let receipt = reg.execute(WipeTrigger::SessionLocked);
        assert_eq!(receipt.trigger, WipeTrigger::SessionLocked);
        assert!(receipt.success);
        assert!(receipt.duration_ns > 0);

        let calls = executed.lock().unwrap();
        assert!(calls.contains(&WipeTrigger::SessionLocked));
    }
}
