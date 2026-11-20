//! Native macOS `IOHIDManager` transport for physical FIDO authenticators
//! (usage page `0xF1D0`, usage `0x01`), opened with
//! `kIOHIDOptionsTypeSeizeDevice` during a ceremony so `uid=501` processes
//! cannot drive the key concurrently (FS-703 §3.3.6).
//!
//! Compiled only with `--features macos-hid` on macOS. CI exercises the same
//! [`HidDevice`] contract through [`super::virtual_device`].

#![allow(non_upper_case_globals, non_camel_case_types)]

use std::cell::UnsafeCell;
use std::collections::VecDeque;
use std::ffi::{c_char, c_void, CString};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{
    mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError},
    Arc, Mutex,
};
use zeroize::{Zeroize, Zeroizing};

use enclave_core::error::EnclaveResult;
use enclave_core::power::{
    SelectedUsbInstance, UsbObservationEpoch, UsbSelectionGuard, UsbSelectionSetGuard,
};
use enclave_core::{err, fail};

use super::hid::{HidDevice, REPORT};
use super::selected_transport_lifetime::{
    OwnerThreadGuard, OwnerThreadState, SelectedTransportLifetime, TransportLifetimeState,
};

type CFTypeRef = *const c_void;
type CFAllocatorRef = *const c_void;
type CFStringRef = *const c_void;
type CFNumberRef = *const c_void;
type CFSetRef = *const c_void;
type CFMutableDictionaryRef = *mut c_void;
type CFRunLoopRef = *mut c_void;
type CFIndex = isize;
type IOHIDManagerRef = *mut c_void;
type IOHIDDeviceRef = *mut c_void;
type IOReturn = i32;

const kIOReturnSuccess: IOReturn = 0;
const kIOHIDOptionsTypeNone: u32 = 0;
const kIOHIDOptionsTypeSeizeDevice: u32 = 1;
const kIOHIDReportTypeOutput: u32 = 1;
const kCFNumberSInt32Type: CFIndex = 3;
const kCFStringEncodingUTF8: u32 = 0x0800_0100;
const FIDO_USAGE_PAGE: i32 = 0xF1D0;
const FIDO_USAGE: i32 = 0x01;

#[repr(C)]
struct CFDictionaryCallBacks {
    _opaque: [u8; 0],
}

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    static kCFAllocatorDefault: CFAllocatorRef;
    static kCFRunLoopDefaultMode: CFStringRef;
    static kCFTypeDictionaryKeyCallBacks: CFDictionaryCallBacks;
    static kCFTypeDictionaryValueCallBacks: CFDictionaryCallBacks;
    fn CFDictionaryCreateMutable(
        alloc: CFAllocatorRef,
        capacity: CFIndex,
        keys: *const CFDictionaryCallBacks,
        values: *const CFDictionaryCallBacks,
    ) -> CFMutableDictionaryRef;
    fn CFDictionarySetValue(d: CFMutableDictionaryRef, k: CFTypeRef, v: CFTypeRef);
    fn CFNumberCreate(alloc: CFAllocatorRef, t: CFIndex, value: *const c_void) -> CFNumberRef;
    fn CFNumberGetValue(n: CFNumberRef, t: CFIndex, out: *mut c_void) -> u8;
    fn CFStringCreateWithCString(alloc: CFAllocatorRef, s: *const c_char, enc: u32) -> CFStringRef;
    fn CFSetGetCount(s: CFSetRef) -> CFIndex;
    fn CFSetGetValues(s: CFSetRef, values: *mut CFTypeRef);
    fn CFRunLoopGetCurrent() -> CFRunLoopRef;
    fn CFRetain(cf: CFTypeRef) -> CFTypeRef;
    fn CFRunLoopRunInMode(mode: CFStringRef, seconds: f64, return_after_source_handled: u8) -> i32;
    fn CFRelease(t: CFTypeRef);
}

#[link(name = "IOKit", kind = "framework")]
extern "C" {
    fn IOHIDManagerCreate(alloc: CFAllocatorRef, options: u32) -> IOHIDManagerRef;
    fn IOHIDManagerSetDeviceMatching(m: IOHIDManagerRef, d: CFMutableDictionaryRef);
    fn IOHIDManagerOpen(m: IOHIDManagerRef, options: u32) -> IOReturn;
    fn IOHIDManagerCopyDevices(m: IOHIDManagerRef) -> CFSetRef;
    fn IOHIDDeviceGetService(d: IOHIDDeviceRef) -> u32;
    fn IORegistryEntryGetRegistryEntryID(entry: u32, id: *mut u64) -> i32;
    fn IORegistryEntryGetParentEntry(entry: u32, plane: *const c_char, parent: *mut u32) -> i32;
    fn IOObjectConformsTo(entry: u32, name: *const c_char) -> i32;
    fn IOObjectRelease(object: u32) -> i32;
    fn IOHIDDeviceOpen(d: IOHIDDeviceRef, options: u32) -> IOReturn;
    fn IOHIDDeviceClose(d: IOHIDDeviceRef, options: u32) -> IOReturn;
    fn IOHIDDeviceSetReport(
        d: IOHIDDeviceRef,
        t: u32,
        id: CFIndex,
        report: *const u8,
        len: CFIndex,
    ) -> IOReturn;
    fn IOHIDDeviceGetProperty(d: IOHIDDeviceRef, key: CFStringRef) -> CFTypeRef;
    fn IOHIDDeviceScheduleWithRunLoop(d: IOHIDDeviceRef, rl: CFRunLoopRef, mode: CFStringRef);
    fn IOHIDDeviceUnscheduleFromRunLoop(d: IOHIDDeviceRef, rl: CFRunLoopRef, mode: CFStringRef);
    fn IOHIDDeviceRegisterInputReportCallback(
        d: IOHIDDeviceRef,
        report: *mut u8,
        len: CFIndex,
        cb: Option<extern "C" fn(*mut c_void, IOReturn, *mut c_void, u32, u32, *mut u8, CFIndex)>,
        ctx: *mut c_void,
    );
}

fn cfstr(s: &str) -> EnclaveResult<CFStringRef> {
    let c = CString::new(s).map_err(|_| err!(EINVAL, "CFSTRING"))?;
    // SAFETY: valid NUL-terminated UTF-8 C string.
    let r = unsafe {
        CFStringCreateWithCString(kCFAllocatorDefault, c.as_ptr(), kCFStringEncodingUTF8)
    };
    if r.is_null() {
        fail!(EIO, "CFSTRING");
    }
    Ok(r)
}

struct InboxState {
    queue: VecDeque<Zeroizing<[u8; REPORT]>>,
    error: Option<enclave_core::EnclaveError>,
}
struct Inbox {
    // IOKit exclusively writes this buffer. Rust never creates a reference to
    // its contents; callbacks copy through the callback's raw report pointer.
    buf: UnsafeCell<[u8; REPORT]>,
    state: Mutex<InboxState>,
    lifetime: TransportLifetimeState,
}
impl Inbox {
    fn with_lifetime(lifetime: TransportLifetimeState) -> Self {
        Self {
            buf: UnsafeCell::new([0; REPORT]),
            state: Mutex::new(InboxState {
                queue: VecDeque::new(),
                error: None,
            }),
            lifetime,
        }
    }
    #[cfg(test)]
    fn new() -> Self {
        Self::with_lifetime(TransportLifetimeState::new(
            OwnerThreadState::new(),
            Arc::new(AtomicBool::new(false)),
        ))
    }
    fn check_error(&self) -> EnclaveResult<()> {
        let input = self.state.lock().map_err(|_| {
            self.lifetime.fail();
            err!(EIO, "HID_INPUT_LOCK")
        })?;
        if let Some(error) = &input.error {
            self.lifetime.fail();
            return Err(error.clone());
        }
        Ok(())
    }
    fn revoke(&self) {
        self.lifetime.fail();
        let mut input = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        input.queue.clear();
        if input.error.is_none() {
            input.error = Some(err!(EACCES, "HID_OWNER_PAIR_REVOKED"));
        }
    }
}
impl Drop for Inbox {
    fn drop(&mut self) {
        self.buf.get_mut().zeroize();
    }
}
extern "C" fn on_input(
    ctx: *mut c_void,
    result: IOReturn,
    _s: *mut c_void,
    _t: u32,
    _id: u32,
    report: *mut u8,
    len: CFIndex,
) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: this shared callback context lives on the owner thread until
    // unscheduling, unregistering and successful close quiesce callbacks.
    let inbox = unsafe { &*(ctx as *const Inbox) };
    let Ok(mut state)=inbox.state.lock() else {inbox.lifetime.fail();return;};
    if state.error.is_some() {
        inbox.lifetime.fail();
        return;
    }
    if result != kIOReturnSuccess {
        state.error = Some(err!(
            EIO,
            "HID_INPUT_ERROR",
            "IOHID input status {result:#x}"
        ));
    } else if report.is_null() || len != REPORT as CFIndex {
        state.error = Some(err!(EINVAL, "HID_INPUT_REPORT_LENGTH"));
    } else if state.queue.len() >= 256 {
        state.error = Some(err!(E2BIG, "HID_INPUT_QUEUE_LIMIT"));
    } else {
        let mut copy = Zeroizing::new([0; REPORT]);
        // SAFETY: valid callback report, exact length, separate owned output.
        unsafe {
            std::ptr::copy_nonoverlapping(report, copy.as_mut_ptr(), REPORT);
        }
        state.queue.push_back(copy);
    }
    // Metadata only: no guard Drop, secret owner or service callback here.
    if state.error.is_some() {
        inbox.lifetime.fail();
    }
}

/// A seized FIDO HID handle. All CF/IOKit objects and callbacks stay on one
/// dedicated owner thread; this public handle is naturally Send.
pub struct MacHidDevice {
    commands: SyncSender<Command>,
    poisoned: Arc<AtomicBool>,
    lifetime: TransportLifetimeState,
    pair: Arc<Mutex<PairState>>,
    index: usize,
    hub_depth: u8,
    deadline_ns: Option<u64>,
    /// Maximum wait outside a caller-supplied absolute ceremony deadline.
    pub timeout_s: f64,
}
impl std::fmt::Debug for MacHidDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacHidDevice")
            .field("hub_depth", &self.hub_depth)
            .field("owner_poisoned", &self.poisoned.load(Ordering::SeqCst))
            .finish()
    }
}
// Never transferred out of the creating thread. No unsafe Send implementation.
struct OwnerDevice {
    manager: IOHIDManagerRef,
    device: IOHIDDeviceRef,
    inbox: Option<Box<Inbox>>,
    run_loop: CFRunLoopRef,
    hub_depth: u8,
    usb_instance: SelectedUsbInstance,
    selection: Option<UsbSelectionGuard>,
    lifetime: TransportLifetimeState,
    closed: bool,
}
// Shared caller/owner metadata only. No CF object, report or key crosses this
// mutex. Caller timeout can invalidate both members even if SetReport blocks;
// the owner retains the core guard/CF storage until safe cleanup is possible.
#[derive(Debug, Default)]
struct PairState {
    members: Option<[usize; 2]>,
    revoked: bool,
    deadline_ns: u64,
}
impl PairState {
    fn can_bind(&self, indices: [usize; 2]) -> EnclaveResult<()> {
        if indices[0] == indices[1] {
            fail!(EINVAL, "HID_OWNER_PAIR_DISTINCT_REQUIRED");
        }
        if self.members.is_some() || self.revoked {
            fail!(EACCES, "HID_OWNER_PAIR_ALREADY_BOUND");
        }
        Ok(())
    }
    fn bind(&mut self, indices: [usize; 2], deadline_ns: u64) -> EnclaveResult<()> {
        self.can_bind(indices)?;
        if deadline_ns == 0 {
            fail!(ETIMEDOUT, "HID_OWNER_PAIR_DEADLINE");
        }
        self.members = Some(indices);
        self.deadline_ns = deadline_ns;
        Ok(())
    }
    fn check(&self, index: usize, at: u64) -> EnclaveResult<()> {
        if self.revoked {
            fail!(EACCES, "HID_OWNER_PAIR_REVOKED");
        }
        if self.members.is_some() && at >= self.deadline_ns {
            fail!(ETIMEDOUT, "HID_OWNER_PAIR_DEADLINE");
        }
        if self
            .members
            .is_some_and(|members| !members.contains(&index))
        {
            fail!(EACCES, "HID_OWNER_PAIR_MEMBER_REQUIRED");
        }
        Ok(())
    }
    fn check_exact(&self, indices: [usize; 2], at: u64) -> EnclaveResult<()> {
        if self.members != Some(indices) {
            fail!(EACCES, "HID_OWNER_PAIR_SCOPE");
        }
        self.check(indices[0], at)?;
        self.check(indices[1], at)
    }
    fn revoke_member(&mut self, index: usize) -> bool {
        let member = self.members.is_some_and(|members| members.contains(&index));
        if member {
            self.revoked = true;
        }
        member
    }
    fn revoke_all(&mut self) {
        self.revoked = true;
    }
}
struct OwnerPair {
    state: Arc<Mutex<PairState>>,
    selection: Option<UsbSelectionSetGuard>,
}
fn check_pair_inputs<'a>(
    members: [usize; 2],
    mut input: impl FnMut(usize) -> EnclaveResult<&'a Inbox>,
) -> EnclaveResult<()> {
    for index in members {
        input(index)?.check_error()?;
    }
    Ok(())
}
fn revoke_pair_inputs<'a>(members: [usize; 2], mut input: impl FnMut(usize) -> Option<&'a Inbox>) {
    for index in members {
        if let Some(inbox) = input(index) {
            inbox.revoke();
        }
    }
}
impl OwnerPair {
    fn require_exact(
        &self,
        indices: [usize; 2],
        deadline: u64,
        poisoned: &AtomicBool,
    ) -> EnclaveResult<()> {
        check_owner(deadline, poisoned)?;
        self.state
            .lock()
            .map_err(|_| err!(EIO, "HID_OWNER_PAIR_POISONED"))?
            .check_exact(indices, now())?;
        self.selection
            .as_ref()
            .ok_or_else(|| err!(EACCES, "HID_OWNER_PAIR_REVOKED"))?
            .require_current()?;
        check_owner(deadline, poisoned)
    }
    fn check(&self, index: usize) -> EnclaveResult<()> {
        let selected = {
            let state = self
                .state
                .lock()
                .map_err(|_| err!(EIO, "HID_OWNER_PAIR_POISONED"))?;
            state.check(index, now())?;
            state.members.is_some()
        };
        if selected {
            self.selection
                .as_ref()
                .ok_or_else(|| err!(EACCES, "HID_OWNER_PAIR_REVOKED"))?
                .require_current()?;
        }
        Ok(())
    }
    fn check_devices(&self, devices: &[Option<OwnerDevice>]) -> EnclaveResult<()> {
        let members = self
            .state
            .lock()
            .map_err(|_| err!(EIO, "HID_OWNER_PAIR_POISONED"))?
            .members;
        if let Some(members) = members {
            check_pair_inputs(members, |index| {
                let device = devices
                    .get(index)
                    .and_then(Option::as_ref)
                    .ok_or_else(|| err!(EACCES, "HID_OWNER_HANDLE"))?;
                if device.closed {
                    fail!(EIO, "HID_OWNER_CLOSED");
                }
                device
                    .inbox
                    .as_deref()
                    .ok_or_else(|| err!(EIO, "HID_OWNER_CLOSED"))
            })?;
        }
        Ok(())
    }
    fn revoke_member(&mut self, index: usize) {
        let revoke = self
            .state
            .lock()
            .map(|mut state| state.revoke_member(index))
            .unwrap_or(true);
        if revoke {
            self.selection = None;
        }
    }
    fn synchronize(&mut self) {
        let revoked = self
            .state
            .lock()
            .map(|state| state.revoked || state.members.is_some() && now() >= state.deadline_ns)
            .unwrap_or(true)
            || self
                .selection
                .as_ref()
                .is_some_and(|guard| !guard.is_current());
        if revoked {
            self.revoke();
        }
    }
    fn scrub_revoked_inputs(&self, devices: &[Option<OwnerDevice>]) {
        let members = match self.state.lock() {
            Ok(state) => {
                if state.revoked {
                    state.members
                } else {
                    None
                }
            }
            Err(poison) => poison.into_inner().members,
        };
        if let Some(members) = members {
            revoke_pair_inputs(members, |index| {
                devices
                    .get(index)
                    .and_then(Option::as_ref)
                    .and_then(|device| device.inbox.as_deref())
            });
        }
        // The IOKit callback buffer itself remains owned until quiescent close.
    }
    fn revoke(&mut self) {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .revoke_all();
        // Guard Drop may execute wipe hooks: never hold pair/topology mutexes.
        self.selection = None;
    }
    fn bind(
        &mut self,
        indices: [usize; 2],
        devices: &[Option<OwnerDevice>],
        deadline: u64,
        poisoned: &AtomicBool,
    ) -> EnclaveResult<()> {
        self.state
            .lock()
            .map_err(|_| err!(EIO, "HID_OWNER_PAIR_POISONED"))?
            .can_bind(indices)?;
        let candidate = |index: usize| -> EnclaveResult<SelectedUsbInstance> {
            let device = devices
                .get(index)
                .and_then(Option::as_ref)
                .ok_or_else(|| err!(EACCES, "HID_OWNER_HANDLE"))?;
            if device.closed || device.selection.is_some() {
                fail!(EACCES, "FIDO_USB_ALREADY_BOUND");
            }
            device.check(deadline, poisoned)?;
            Ok(device.usb_instance.clone())
        };
        let instances = [candidate(indices[0])?, candidate(indices[1])?];
        let guard = enclave_core::power::bind_selected_usb_instances(instances)?;
        // A timeout while binding latches the shared state; do not undo it.
        let assigned = self
            .state
            .lock()
            .map_err(|_| err!(EIO, "HID_OWNER_PAIR_POISONED"))
            .and_then(|mut state| state.bind(indices, deadline));
        assigned?;
        self.selection = Some(guard);
        check_owner(deadline, poisoned)?;
        self.check(indices[0])
    }
}
impl Drop for OwnerPair {
    fn drop(&mut self) {
        self.revoke();
    }
}

enum Request {
    Write(Zeroizing<[u8; REPORT]>),
    Read,
    Bind,
    BindPair { other: usize },
    CheckPair { other: usize },
    Close,
}
enum Response {
    Done,
    Report(Zeroizing<[u8; REPORT]>),
}
struct Command {
    index: usize,
    deadline: u64,
    request: Request,
    reply: SyncSender<EnclaveResult<Response>>,
}
fn now() -> u64 {
    enclave_core::power::continuous_time_ns()
}
fn check_owner(deadline: u64, poisoned: &AtomicBool) -> EnclaveResult<()> {
    if poisoned.load(Ordering::SeqCst) {
        fail!(EACCES, "HID_OWNER_POISONED");
    }
    if now() >= deadline {
        fail!(ETIMEDOUT, "HID_OWNER_DEADLINE");
    }
    Ok(())
}
fn owner_loop(
    rx: Receiver<Command>,
    mut devices: Vec<Option<OwnerDevice>>,
    poisoned: Arc<AtomicBool>,
    pair: Arc<Mutex<PairState>>,
    owner_guard: OwnerThreadGuard,
) {
    let mut pair = OwnerPair {
        state: pair,
        selection: None,
    };
    // On unwind this drops before pair/device native cleanup can block. On
    // ordinary exit it is explicitly dropped before the same cleanup below.
    let owner_guard = owner_guard;
    while devices.iter().any(Option::is_some) && !poisoned.load(Ordering::SeqCst) {
        pair.synchronize();
        if pair.check_devices(&devices).is_err() {
            pair.revoke();
        }
        pair.scrub_revoked_inputs(&devices);
        let command = match rx.recv_timeout(std::time::Duration::from_millis(5)) {
            Ok(command) => command,
            Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => {
                // SAFETY: callback scheduling and run-loop pumping are confined
                // to this exact thread for the complete device lifetime.
                unsafe {
                    CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.0, 1);
                }
                continue;
            }
        };
        let closing = matches!(&command.request, Request::Close);
        let exact_pair = match &command.request {
            Request::BindPair { other } | Request::CheckPair { other } => {
                Some([command.index, *other])
            }
            _ => None,
        };
        let result = check_owner(command.deadline, &poisoned)
            .and_then(|()| {
                if let Request::BindPair { other } = &command.request {
                    pair.bind(
                        [command.index, *other],
                        &devices,
                        command.deadline,
                        &poisoned,
                    )?;
                    return Ok(Response::Done);
                }
                if let Request::CheckPair { other } = &command.request {
                    pair.require_exact([command.index, *other], command.deadline, &poisoned)?;
                    return Ok(Response::Done);
                }
                let slot = devices
                    .get_mut(command.index)
                    .ok_or_else(|| err!(EACCES, "HID_OWNER_HANDLE"))?;
                if closing {
                    pair.revoke_member(command.index);
                    let mut device = slot
                        .take()
                        .ok_or_else(|| err!(EACCES, "HID_OWNER_HANDLE"))?;
                    device.close()?;
                    return Ok(Response::Done);
                }
                pair.check(command.index)?;
                let device = slot
                    .as_mut()
                    .ok_or_else(|| err!(EACCES, "HID_OWNER_HANDLE"))?;
                match command.request {
                    Request::Write(report) => {
                        device.write(&report, command.deadline, &poisoned)?;
                        Ok(Response::Done)
                    }
                    Request::Read => device
                        .read(command.deadline, &poisoned)
                        .map(Response::Report),
                    Request::Bind => {
                        if device.selection.is_some() {
                            fail!(EACCES, "FIDO_USB_ALREADY_BOUND");
                        }
                        device.selection = Some(enclave_core::power::bind_selected_usb_instance(
                            device.usb_instance.clone(),
                        )?);
                        device.lifetime.singleton_bound();
                        Ok(Response::Done)
                    }
                    Request::Close | Request::BindPair { .. } | Request::CheckPair { .. } => {
                        unreachable!()
                    }
                }
            })
            .and_then(|response| {
                check_owner(command.deadline, &poisoned)?;
                if let Some(indices) = exact_pair {
                    pair.require_exact(indices, command.deadline, &poisoned)?;
                } else if !closing {
                    pair.check(command.index)?;
                }
                if !closing {
                    pair.check_devices(&devices)?;
                }
                Ok(response)
            });
        if result.is_err() {
            if let Some(device) = devices.get(command.index).and_then(Option::as_ref) {
                device.lifetime.fail();
            }
            pair.revoke_member(command.index);
        }
        pair.scrub_revoked_inputs(&devices);
        if command.reply.try_send(result).is_err() {
            if let Some(device) = devices.get(command.index).and_then(Option::as_ref) {
                device.lifetime.fail();
            }
            // A caller that cannot receive a paired success has no live group.
            pair.revoke_member(command.index);
        }
    }
    // If a synchronous SetReport never returns, this frame and all callback
    // storage remain alive on the blocked thread. Caller timeout poisons future
    // use, but cannot claim IOKit quiescence or free that storage prematurely.
    drop(owner_guard);
    pair.revoke();
    drop(devices);
}

/// Topology depth from an IOKit `LocationID` (bus byte + one nibble per tier).
pub fn depth_from_location_id(loc: u32) -> u8 {
    let mut d = 0u8;
    for shift in (0..24).step_by(4).rev() {
        if (loc >> shift) & 0xf == 0 {
            break;
        }
        d += 1;
    }
    d
}

/// Resolve the actual IOUSBHostDevice and its ancestors, not a VID/PID/model.
/// Registry IDs are local ephemeral observations; never enrolled key identity.
fn usb_instance(
    device: IOHIDDeviceRef,
    observation: UsbObservationEpoch,
) -> EnclaveResult<SelectedUsbInstance> {
    // SAFETY: device is retained by the enumeration CFSet during this walk.
    // IOHIDDeviceGetService is borrowed; each acquired parent is released.
    unsafe {
        let mut node = IOHIDDeviceGetService(device);
        if node == 0 {
            fail!(EIO, "FIDO_USB_BINDING_UNAVAILABLE");
        }
        let mut owned = false;
        let mut selected = None;
        let mut ancestors = Vec::new();
        for _ in 0..64 {
            let mut id = 0u64;
            if IORegistryEntryGetRegistryEntryID(node, &mut id) != 0 || id == 0 {
                if owned {
                    IOObjectRelease(node);
                }
                fail!(EIO, "FIDO_USB_BINDING_UNAVAILABLE");
            }
            if selected.is_some() {
                ancestors.push(id);
            } else if IOObjectConformsTo(node, b"IOUSBHostDevice\0".as_ptr().cast()) != 0 {
                selected = Some(id);
            }
            let mut parent = 0;
            let result =
                IORegistryEntryGetParentEntry(node, b"IOService\0".as_ptr().cast(), &mut parent);
            if owned {
                IOObjectRelease(node);
            }
            if result != 0 || parent == 0 {
                return SelectedUsbInstance::new_observed(
                    selected.ok_or_else(|| err!(EIO, "FIDO_USB_BINDING_UNAVAILABLE"))?,
                    ancestors,
                    observation,
                );
            }
            node = parent;
            owned = true;
        }
        if owned {
            IOObjectRelease(node);
        }
        fail!(E2BIG, "FIDO_USB_ANCESTRY_LIMIT");
    }
}

impl OwnerDevice {
    // Runs exclusively inside the dedicated owner thread.
    fn enumerate(
        owner: &Arc<OwnerThreadState>,
        poisoned: &Arc<AtomicBool>,
    ) -> EnclaveResult<Vec<Self>> {
        struct Owned(CFTypeRef);
        impl Drop for Owned {
            fn drop(&mut self) {
                unsafe {
                    CFRelease(self.0);
                }
            }
        }
        fn owned(p: CFTypeRef) -> EnclaveResult<Owned> {
            if p.is_null() {
                fail!(EIO, "IOHID_ALLOCATION");
            }
            Ok(Owned(p))
        }
        // SAFETY: CF objects are checked, owned by RAII guards or retained for
        // each returned device. Callback storage remains boxed for device lifetime.
        unsafe {
            let manager =
                owned(IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDOptionsTypeNone).cast())?;
            let raw_manager = manager.0 as IOHIDManagerRef;
            {
                let dict = owned(
                    CFDictionaryCreateMutable(
                        kCFAllocatorDefault,
                        2,
                        &kCFTypeDictionaryKeyCallBacks,
                        &kCFTypeDictionaryValueCallBacks,
                    )
                    .cast(),
                )?;
                let page = owned(cfstr("DeviceUsagePage")?)?;
                let usage = owned(cfstr("DeviceUsage")?)?;
                let vp = owned(CFNumberCreate(
                    kCFAllocatorDefault,
                    kCFNumberSInt32Type,
                    (&FIDO_USAGE_PAGE as *const i32).cast(),
                ))?;
                let vu = owned(CFNumberCreate(
                    kCFAllocatorDefault,
                    kCFNumberSInt32Type,
                    (&FIDO_USAGE as *const i32).cast(),
                ))?;
                CFDictionarySetValue(dict.0 as CFMutableDictionaryRef, page.0, vp.0);
                CFDictionarySetValue(dict.0 as CFMutableDictionaryRef, usage.0, vu.0);
                IOHIDManagerSetDeviceMatching(raw_manager, dict.0 as CFMutableDictionaryRef);
            }
            if IOHIDManagerOpen(raw_manager, kIOHIDOptionsTypeNone) != kIOReturnSuccess {
                fail!(EPERM, "IOHID_MANAGER_OPEN");
            }
            let observation = enclave_core::power::observe_usb_topology()?;
            let raw_set = IOHIDManagerCopyDevices(raw_manager);
            if raw_set.is_null() {
                fail!(EIO, "NO_FIDO_DEVICE");
            }
            let set = owned(raw_set)?;
            let count = CFSetGetCount(set.0);
            if count < 1 {
                fail!(EIO, "NO_FIDO_DEVICE");
            }
            if count > 32 {
                fail!(E2BIG, "FIDO_DEVICE_LIMIT");
            }
            let mut devices = vec![std::ptr::null(); count as usize];
            CFSetGetValues(set.0, devices.as_mut_ptr());
            let location = owned(cfstr("LocationID")?)?;
            let mut output = Vec::new();
            for raw in devices {
                let device = raw as IOHIDDeviceRef;
                let usb_instance = usb_instance(device, observation)?;
                if IOHIDDeviceOpen(device, kIOHIDOptionsTypeSeizeDevice) != kIOReturnSuccess {
                    fail!(EAGAIN, "FIDO_DEVICE_BUSY");
                }
                let property = IOHIDDeviceGetProperty(device, location.0);
                let mut loc = 0u32;
                if !property.is_null() {
                    CFNumberGetValue(property, kCFNumberSInt32Type, (&mut loc as *mut u32).cast());
                }
                let lifetime = TransportLifetimeState::new(owner.clone(), poisoned.clone());
                let inbox = Box::new(Inbox::with_lifetime(lifetime.clone()));
                let ctx = (&*inbox as *const Inbox as *mut Inbox).cast::<c_void>();
                IOHIDDeviceRegisterInputReportCallback(
                    device,
                    inbox.buf.get().cast::<u8>(),
                    REPORT as CFIndex,
                    Some(on_input),
                    ctx,
                );
                let run_loop = CFRetain(CFRunLoopGetCurrent().cast()) as CFRunLoopRef;
                IOHIDDeviceScheduleWithRunLoop(device, run_loop, kCFRunLoopDefaultMode);
                CFRetain(device.cast());
                CFRetain(raw_manager.cast());
                output.push(Self {
                    manager: raw_manager,
                    device,
                    inbox: Some(inbox),
                    run_loop,
                    // Unknown topology must never become a claimed root port.
                    hub_depth: match depth_from_location_id(loc) {
                        0 => u8::MAX,
                        depth => depth,
                    },
                    usb_instance,
                    selection: None,
                    lifetime,
                    closed: false,
                });
            }
            if output.is_empty() {
                fail!(EAGAIN, "FIDO_DEVICE_BUSY");
            }
            Ok(output)
        }
    }

    fn check(&self, deadline: u64, poisoned: &AtomicBool) -> EnclaveResult<()> {
        check_owner(deadline, poisoned)?;
        if self
            .selection
            .as_ref()
            .is_some_and(|guard| !guard.is_current())
        {
            fail!(EACCES, "FIDO_USB_SELECTION_REVOKED");
        }
        self.inbox
            .as_ref()
            .ok_or_else(|| err!(EIO, "HID_OWNER_CLOSED"))?
            .check_error()
    }
    fn write(
        &mut self,
        report: &[u8; REPORT],
        deadline: u64,
        poisoned: &AtomicBool,
    ) -> EnclaveResult<()> {
        self.check(deadline, poisoned)?;
        // SAFETY: open device and exact report, used only by its owner thread.
        let result = unsafe {
            IOHIDDeviceSetReport(
                self.device,
                kIOHIDReportTypeOutput,
                0,
                report.as_ptr(),
                REPORT as CFIndex,
            )
        };
        if result != kIOReturnSuccess {
            fail!(EIO, "DEVICE_REMOVED", "IOHIDDeviceSetReport {result:#x}");
        }
        self.check(deadline, poisoned)
    }
    fn read(
        &mut self,
        deadline: u64,
        poisoned: &AtomicBool,
    ) -> EnclaveResult<Zeroizing<[u8; REPORT]>> {
        loop {
            self.check(deadline, poisoned)?;
            {
                let mut state = self
                    .inbox
                    .as_ref()
                    .ok_or_else(|| err!(EIO, "HID_OWNER_CLOSED"))?
                    .state
                    .lock()
                    .map_err(|_| err!(EIO, "HID_INPUT_LOCK"))?;
                if let Some(error) = &state.error {
                    return Err(error.clone());
                }
                if let Some(report) = state.queue.pop_front() {
                    return Ok(report);
                }
            }
            let seconds = (deadline.saturating_sub(now()) as f64 / 1_000_000_000.0).min(0.01);
            // SAFETY: this is the same run loop used at registration.
            unsafe {
                CFRunLoopRunInMode(kCFRunLoopDefaultMode, seconds, 1);
            }
        }
    }
    fn close(&mut self) -> EnclaveResult<()> {
        self.lifetime.close();
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        // SAFETY: all callback calls/run-loop pumping are serialized on this
        // owner thread. Unregister before close and release only after success.
        let result = unsafe {
            IOHIDDeviceUnscheduleFromRunLoop(self.device, self.run_loop, kCFRunLoopDefaultMode);
            let buffer = self
                .inbox
                .as_ref()
                .map_or(std::ptr::null_mut(), |inbox| inbox.buf.get().cast::<u8>());
            IOHIDDeviceRegisterInputReportCallback(
                self.device,
                buffer,
                REPORT as CFIndex,
                None,
                std::ptr::null_mut(),
            );
            IOHIDDeviceClose(self.device, kIOHIDOptionsTypeNone)
        };
        if result != kIOReturnSuccess {
            // No quiescent-close proof: deliberately retain storage and CF
            // objects, so a delayed callback can never reach freed memory.
            if let Some(inbox) = self.inbox.take() {
                let _ = Box::leak(inbox);
            }
            fail!(EIO, "HID_OWNER_CLOSE_UNCONFIRMED");
        }
        self.selection = None;
        unsafe {
            CFRelease(self.run_loop.cast());
            CFRelease(self.device.cast());
            CFRelease(self.manager.cast());
        }
        self.inbox = None;
        Ok(())
    }
}
impl Drop for OwnerDevice {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
impl MacHidDevice {
    /// Enumerate and seize FIDO matches on one owner thread. Selection still
    /// requires getInfo and unique enrolled AAGUID, never enumeration order.
    pub fn enumerate() -> EnclaveResult<Vec<Self>> {
        let (commands, rx) = mpsc::sync_channel(8);
        let (ready, started) = mpsc::sync_channel(1);
        let poisoned = Arc::new(AtomicBool::new(false));
        let owner_poisoned = poisoned.clone();
        let owner = OwnerThreadState::new();
        let owner_thread = owner.clone();
        let pair = Arc::new(Mutex::new(PairState::default()));
        let owner_pair = pair.clone();
        std::thread::Builder::new()
            .name("ctap-hid-owner".into())
            .spawn(move || {
                let owner_guard = match owner_thread.enter() {
                    Ok(guard) => guard,
                    Err(_) => return,
                };
                match OwnerDevice::enumerate(&owner_thread, &owner_poisoned) {
                    Ok(devices) => {
                        let metadata = devices
                            .iter()
                            .map(|device| (device.hub_depth, device.lifetime.clone()))
                            .collect::<Vec<_>>();
                        let devices = devices.into_iter().map(Some).collect();
                        // Close liveness before native cleanup on readiness
                        // abandonment or unwind, not after a possibly blocked Close.
                        let owner_guard = owner_guard;
                        if ready.send(Ok(metadata)).is_ok() {
                            owner_loop(rx, devices, owner_poisoned, owner_pair, owner_guard);
                        }
                    }
                    Err(error) => {
                        let _ = ready.send(Err(error));
                    }
                }
            })
            .map_err(|_| {
                owner.abandon();
                err!(EIO, "HID_OWNER_START")
            })?;
        let metadata = match started.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(result) => result?,
            Err(_) => {
                owner.abandon();
                poisoned.store(true, Ordering::SeqCst);
                fail!(ETIMEDOUT, "HID_OWNER_START_TIMEOUT");
            }
        };
        Ok(metadata
            .into_iter()
            .enumerate()
            .map(|(index, (hub_depth, lifetime))| Self {
                commands: commands.clone(),
                poisoned: poisoned.clone(),
                lifetime,
                pair: pair.clone(),
                index,
                hub_depth,
                deadline_ns: None,
                timeout_s: 30.0,
            })
            .collect())
    }
    /// Enrollment convenience: exactly one FIDO device is required.
    pub fn open_first() -> EnclaveResult<Self> {
        let mut devices = Self::enumerate()?;
        if devices.len() != 1 {
            fail!(EACCES, "FIDO_MULTIPLE_MATCHING_DEVICES");
        }
        Ok(devices.remove(0))
    }
    /// USB hub topology depth.
    pub fn hub_depth(&self) -> u8 {
        self.hub_depth
    }
    /// Atomically select exactly these two unbound handles from one enumeration.
    /// This is attachment continuity only; separate independent asset admission,
    /// fresh D2/CTAP authorization and v3 service cutover are still required.
    /// The earlier of both original device deadlines bounds this operation.
    pub fn bind_selected_pair(&mut self, other: &mut Self) -> EnclaveResult<()> {
        let deadline = self.pair_deadline(other)?;
        match self.request(Request::BindPair { other: other.index }, deadline)? {
            Response::Done => Ok(()),
            _ => Err(err!(EIO, "HID_OWNER_RESPONSE")),
        }
    }
    /// Revalidate the exact ordered primary/backup pair through its native owner
    /// and core selected-set guard. Both original device/group deadlines apply;
    /// this performs no assertion, PIN operation or new authority admission.
    /// Use at every D2/CTAP/persistence boundary of a separately authorized flow.
    pub fn require_selected_pair(&self, other: &Self) -> EnclaveResult<()> {
        let deadline = self.pair_deadline(other)?;
        let indices = [self.index, other.index];
        self.pair
            .lock()
            .map_err(|_| err!(EIO, "HID_OWNER_PAIR_POISONED"))?
            .check_exact(indices, now())?;
        match self.request(Request::CheckPair { other: other.index }, deadline)? {
            Response::Done => {}
            _ => {
                fail!(EIO, "HID_OWNER_RESPONSE");
            }
        }
        self.pair
            .lock()
            .map_err(|_| err!(EIO, "HID_OWNER_PAIR_POISONED"))?
            .check_exact(indices, now())?;
        check_owner(deadline, &other.poisoned)
    }
    fn pair_deadline(&self, other: &Self) -> EnclaveResult<u64> {
        if self.index == other.index
            || !Arc::ptr_eq(&self.pair, &other.pair)
            || !Arc::ptr_eq(&self.poisoned, &other.poisoned)
        {
            fail!(EACCES, "HID_OWNER_PAIR_DIFFERENT_OWNER");
        }
        let deadline = self.effective_deadline()?.min(other.effective_deadline()?);
        check_owner(deadline, &other.poisoned)?;
        Ok(deadline)
    }
    fn effective_deadline(&self) -> EnclaveResult<u64> {
        if !self.timeout_s.is_finite() || self.timeout_s <= 0.0 || self.timeout_s > 30.0 {
            fail!(EINVAL, "HID_TIMEOUT_BOUNDS");
        }
        let timeout = now().saturating_add((self.timeout_s * 1_000_000_000.0) as u64);
        Ok(self
            .deadline_ns
            .map_or(timeout, |deadline| deadline.min(timeout)))
    }
    fn request(&self, request: Request, deadline: u64) -> EnclaveResult<Response> {
        let report = matches!(&request, Request::Read);
        let result =
            self.request_inner(request, deadline)
                .and_then(|response| match (&response, report) {
                    (Response::Report(_), true) | (Response::Done, false) => Ok(response),
                    _ => Err(err!(EIO, "HID_OWNER_RESPONSE")),
                });
        if result.is_err() {
            self.lifetime.fail();
            // Metadata only: never run core guard Drop/wipe hooks on a caller
            // that may hold service locks or while the native owner is blocked.
            if let Ok(mut state) = self.pair.lock() {
                if self.poisoned.load(Ordering::SeqCst) {
                    state.revoke_all();
                } else {
                    state.revoke_member(self.index);
                }
            }
        }
        result
    }
    fn request_inner(&self, request: Request, deadline: u64) -> EnclaveResult<Response> {
        check_owner(deadline, &self.poisoned)?;
        let closing = matches!(&request, Request::Close);
        let deadline = if !closing {
            let state = self
                .pair
                .lock()
                .map_err(|_| err!(EIO, "HID_OWNER_PAIR_POISONED"))?;
            state.check(self.index, now())?;
            if state.members.is_some() {
                deadline.min(state.deadline_ns)
            } else {
                deadline
            }
        } else {
            deadline
        };
        let (reply, receiver) = mpsc::sync_channel(1);
        match self.commands.try_send(Command {
            index: self.index,
            deadline,
            request,
            reply,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                fail!(EAGAIN, "HID_OWNER_BACKPRESSURE");
            }
            Err(TrySendError::Disconnected(_)) => {
                self.poisoned.store(true, Ordering::SeqCst);
                fail!(EIO, "HID_OWNER_STOPPED");
            }
        }
        let remaining = std::time::Duration::from_nanos(deadline.saturating_sub(now()));
        let response = match receiver.recv_timeout(remaining) {
            Ok(response) => response?,
            Err(_) => {
                self.poisoned.store(true, Ordering::SeqCst);
                fail!(ETIMEDOUT, "HID_OWNER_RESPONSE_TIMEOUT");
            }
        };
        check_owner(deadline, &self.poisoned)?;
        if !closing {
            self.pair
                .lock()
                .map_err(|_| err!(EIO, "HID_OWNER_PAIR_POISONED"))?
                .check(self.index, now())?;
        }
        Ok(response)
    }
}
impl HidDevice for MacHidDevice {
    fn write_report(&mut self, report: &[u8; REPORT]) -> EnclaveResult<()> {
        let deadline = self.effective_deadline()?;
        match self.request(Request::Write(Zeroizing::new(*report)), deadline)? {
            Response::Done => Ok(()),
            _ => Err(err!(EIO, "HID_OWNER_RESPONSE")),
        }
    }
    fn read_report(&mut self) -> EnclaveResult<[u8; REPORT]> {
        let deadline = self.effective_deadline()?;
        match self.request(Request::Read, deadline)? {
            Response::Report(report) => Ok(*report),
            _ => Err(err!(EIO, "HID_OWNER_RESPONSE")),
        }
    }
    fn hub_depth(&self) -> u8 {
        self.hub_depth
    }
    fn deadline_ns(&self) -> Option<u64> {
        self.deadline_ns
    }
    fn set_deadline_ns(&mut self, deadline: Option<u64>) -> EnclaveResult<()> {
        self.deadline_ns = deadline;
        Ok(())
    }
    fn bind_selected_instance(&mut self) -> EnclaveResult<()> {
        let deadline = self.effective_deadline()?;
        match self.request(Request::Bind, deadline)? {
            Response::Done => Ok(()),
            _ => Err(err!(EIO, "HID_OWNER_RESPONSE")),
        }
    }
    fn selected_transport_lifetime(&self) -> EnclaveResult<SelectedTransportLifetime> {
        self.lifetime.capture()
    }
}
impl Drop for MacHidDevice {
    fn drop(&mut self) {
        // First, before any mutex or bounded native Close acknowledgement wait.
        // Existing capabilities refuse even when the native owner is blocked.
        self.lifetime.close();
        if let Ok(mut state) = self.pair.lock() {
            state.revoke_member(self.index);
        }
        if self.poisoned.load(Ordering::SeqCst) {
            return;
        }
        // Acknowledgement proves owner-thread close completed; bounded timeout
        // poisons all handles and preserves a possibly blocked owner thread.
        let deadline = now().saturating_add(250_000_000);
        if self.request(Request::Close, deadline).is_err() {
            self.poisoned.store(true, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn location_id_depth() {
        assert_eq!(depth_from_location_id(0x0110_0000), 1);
        assert_eq!(depth_from_location_id(0x0112_3000), 3);
    }
    #[test]
    fn native_callback_rejects_malformed_reports_and_latches_overflow() {
        let inbox = Inbox::new();
        let ctx = (&inbox as *const Inbox as *mut Inbox).cast();
        let mut report = [0; REPORT];
        on_input(ctx, 0, std::ptr::null_mut(), 0, 0, report.as_mut_ptr(), 63);
        assert!(inbox
            .state
            .lock()
            .unwrap()
            .error
            .as_ref()
            .unwrap()
            .is("HID_INPUT_REPORT_LENGTH"));
        assert!(inbox.state.lock().unwrap().queue.is_empty());
        inbox.state.lock().unwrap().error = None;
        for _ in 0..256 {
            on_input(ctx, 0, std::ptr::null_mut(), 0, 0, report.as_mut_ptr(), 64);
        }
        assert_eq!(inbox.state.lock().unwrap().queue.len(), 256);
        on_input(ctx, 0, std::ptr::null_mut(), 0, 0, report.as_mut_ptr(), 64);
        assert!(inbox
            .state
            .lock()
            .unwrap()
            .error
            .as_ref()
            .unwrap()
            .is("HID_INPUT_QUEUE_LIMIT"));
        inbox.state.lock().unwrap().error = None;
        on_input(ctx, -1, std::ptr::null_mut(), 0, 0, report.as_mut_ptr(), 64);
        assert!(inbox
            .state
            .lock()
            .unwrap()
            .error
            .as_ref()
            .unwrap()
            .is("HID_INPUT_ERROR"));
    }
    #[test]
    fn public_handle_is_naturally_send() {
        fn require_send<T: Send>() {}
        require_send::<MacHidDevice>();
    }
    #[test]
    fn caller_timeout_poisons_owner_and_refuses_late_report() {
        let (commands, rx) = mpsc::sync_channel(1);
        let poisoned = Arc::new(AtomicBool::new(false));
        let owner = OwnerThreadState::new();
        let _owner_guard = owner.enter().unwrap();
        let lifetime = TransportLifetimeState::new(owner, poisoned.clone());
        lifetime.singleton_bound();
        let mut handle = MacHidDevice {
            commands,
            poisoned: poisoned.clone(),
            lifetime,
            pair: Arc::new(Mutex::new(PairState::default())),
            index: 0,
            hub_depth: 1,
            deadline_ns: None,
            timeout_s: 1.0,
        };
        let selected = handle.selected_transport_lifetime().unwrap();
        selected.require_current().unwrap();
        let error = handle
            .request(Request::Read, now() + 1_000_000)
            .err()
            .unwrap();
        assert!(error.is("HID_OWNER_RESPONSE_TIMEOUT"));
        assert!(poisoned.load(Ordering::SeqCst));
        assert!(selected.require_current().is_err());
        let queued = rx.try_recv().unwrap();
        assert!(queued
            .reply
            .try_send(Ok(Response::Report(Zeroizing::new([7; REPORT]))))
            .is_err());
        assert!(
            selected.require_current().is_err(),
            "a late report cannot revive the original capability"
        );
        assert!(handle
            .write_report(&[0; REPORT])
            .unwrap_err()
            .is("HID_OWNER_POISONED"));
    }
    #[test]
    fn command_queue_refuses_backpressure_without_blocking() {
        let (commands, _rx) = mpsc::sync_channel(1);
        let poisoned = Arc::new(AtomicBool::new(false));
        let (reply, _) = mpsc::sync_channel(1);
        assert!(commands
            .try_send(Command {
                index: 0,
                deadline: now() + 1_000_000_000,
                request: Request::Read,
                reply
            })
            .is_ok());
        let mut handle = MacHidDevice {
            commands,
            poisoned: poisoned.clone(),
            lifetime: TransportLifetimeState::new(OwnerThreadState::new(), poisoned.clone()),
            pair: Arc::new(Mutex::new(PairState::default())),
            index: 0,
            hub_depth: 1,
            deadline_ns: None,
            timeout_s: 1.0,
        };
        assert!(handle
            .request(Request::Read, now() + 1_000_000_000)
            .err()
            .unwrap()
            .is("HID_OWNER_BACKPRESSURE"));
        assert!(!poisoned.load(Ordering::SeqCst));
        poisoned.store(true, Ordering::SeqCst);
    }

    fn handles() -> ([MacHidDevice; 2], Receiver<Command>) {
        let (commands, receiver) = mpsc::sync_channel(8);
        let poisoned = Arc::new(AtomicBool::new(false));
        let pair = Arc::new(Mutex::new(PairState::default()));
        (
            [0, 1].map(|index| MacHidDevice {
                commands: commands.clone(),
                poisoned: poisoned.clone(),
                pair: pair.clone(),
                lifetime: TransportLifetimeState::new(OwnerThreadState::new(), poisoned.clone()),
                index,
                hub_depth: 1,
                deadline_ns: None,
                timeout_s: 1.0,
            }),
            receiver,
        )
    }

    // Software-only fixture: no real core USB guard or hardware binding is
    // claimed. It exercises the actual public handle/request/drop machinery.
    fn selected_handle() -> (MacHidDevice, Receiver<Command>, OwnerThreadGuard) {
        let (commands, receiver) = mpsc::sync_channel(8);
        let poisoned = Arc::new(AtomicBool::new(false));
        let owner = OwnerThreadState::new();
        let guard = owner.enter().unwrap();
        let lifetime = TransportLifetimeState::new(owner, poisoned.clone());
        lifetime.singleton_bound();
        (
            MacHidDevice {
                commands,
                poisoned,
                lifetime,
                pair: Arc::new(Mutex::new(PairState::default())),
                index: 0,
                hub_depth: 1,
                deadline_ns: None,
                timeout_s: 1.0,
            },
            receiver,
            guard,
        )
    }

    #[test]
    fn candidates_pairs_and_a_fabricated_bind_acknowledgment_cannot_mint_lifetime() {
        let ([mut first, second], receiver) = handles();
        assert!(first
            .selected_transport_lifetime()
            .unwrap_err()
            .is("HID_SELECTED_TRANSPORT_UNBOUND"));
        first.pair.lock().unwrap().bind([0, 1], u64::MAX).unwrap();
        assert!(first.selected_transport_lifetime().is_err());
        assert!(second.selected_transport_lifetime().is_err());
        assert!(receiver.try_recv().is_err());
        first.poisoned.store(true, Ordering::SeqCst);
        let ([mut candidate, other], receiver) = handles();
        let worker = std::thread::spawn(move || {
            let command = receiver
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap();
            assert!(matches!(command.request, Request::Bind));
            command.reply.send(Ok(Response::Done)).ok().unwrap();
        });
        candidate.bind_selected_instance().unwrap();
        worker.join().unwrap();
        assert!(candidate
            .selected_transport_lifetime()
            .unwrap_err()
            .is("HID_SELECTED_TRANSPORT_UNBOUND"));
        candidate.poisoned.store(true, Ordering::SeqCst);
        drop(other);
    }

    #[test]
    fn selected_drop_closes_marker_before_waiting_for_native_acknowledgment() {
        let (handle, receiver, _guard) = selected_handle();
        let selected = handle.selected_transport_lifetime().unwrap();
        let (done, finished) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            drop(handle);
            done.send(()).unwrap();
        });
        let command = receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        assert!(matches!(command.request, Request::Close));
        assert!(selected
            .require_current()
            .unwrap_err()
            .is("HID_SELECTED_TRANSPORT_CLOSED"));
        assert!(matches!(
            finished.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        command.reply.send(Ok(Response::Done)).ok().unwrap();
        finished
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        worker.join().unwrap();
        assert!(selected.require_current().is_err());
    }

    #[test]
    fn selected_drop_timeout_poisons_but_keeps_original_capability_closed_after_late_completion() {
        let (handle, receiver, _guard) = selected_handle();
        let selected = handle.selected_transport_lifetime().unwrap();
        let poisoned = handle.poisoned.clone();
        let (done, finished) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            drop(handle);
            done.send(()).unwrap();
        });
        let command = receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        assert!(selected
            .require_current()
            .unwrap_err()
            .is("HID_SELECTED_TRANSPORT_CLOSED"));
        // Deliberately withhold native completion until the original bounded
        // Close wait has ended. No CF object is allocated or prematurely freed.
        finished
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        worker.join().unwrap();
        assert!(poisoned.load(Ordering::SeqCst));
        assert!(command.reply.try_send(Ok(Response::Done)).is_err());
        assert!(selected.require_current().is_err());
    }

    #[test]
    fn callback_failures_latch_matching_lifetime_before_another_owner_request() {
        for fault in 0..4 {
            let owner = OwnerThreadState::new();
            let _guard = owner.enter().unwrap();
            let state = TransportLifetimeState::new(owner, Arc::new(AtomicBool::new(false)));
            state.singleton_bound();
            let selected = state.capture().unwrap();
            let inbox = Inbox::with_lifetime(state);
            let mut report = [0; REPORT];
            let ctx = (&inbox as *const Inbox as *mut Inbox).cast();
            match fault {
                0 => on_input(ctx, -1, std::ptr::null_mut(), 0, 0, report.as_mut_ptr(), 64),
                1 => on_input(ctx, 0, std::ptr::null_mut(), 0, 0, report.as_mut_ptr(), 63),
                2 => {
                    for _ in 0..257 {
                        on_input(ctx, 0, std::ptr::null_mut(), 0, 0, report.as_mut_ptr(), 64);
                    }
                }
                _ => {
                    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let _guard = inbox.state.lock().unwrap();
                        panic!("synthetic input-state poison");
                    }))
                    .is_err());
                    on_input(ctx, 0, std::ptr::null_mut(), 0, 0, report.as_mut_ptr(), 64);
                }
            }
            assert!(selected
                .require_current()
                .unwrap_err()
                .is("HID_SELECTED_TRANSPORT_FAILED"));
        }
    }

    #[test]
    fn selected_request_error_and_malformed_response_latch_capability_without_global_poison() {
        for malformed in [false, true] {
            let (mut handle, receiver, _guard) = selected_handle();
            let selected = handle.selected_transport_lifetime().unwrap();
            let worker = std::thread::spawn(move || {
                let command = receiver
                    .recv_timeout(std::time::Duration::from_secs(1))
                    .unwrap();
                let response = if malformed {
                    Ok(Response::Done)
                } else {
                    Err(err!(EIO, "SYNTHETIC_NATIVE_ERROR"))
                };
                command.reply.send(response).ok().unwrap();
            });
            assert!(handle.read_report().is_err());
            worker.join().unwrap();
            assert!(!handle.poisoned.load(Ordering::SeqCst));
            assert!(selected.require_current().is_err());
            handle.poisoned.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn actual_owner_loop_exit_ends_lifetime_even_while_public_handle_stays_open() {
        let (handle, receiver, guard) = selected_handle();
        let selected = handle.selected_transport_lifetime().unwrap();
        selected.require_current().unwrap();
        // An empty native-owner loop allocates no CF object and executes the
        // real owner exit path without pumping IOKit's run loop.
        owner_loop(
            receiver,
            Vec::new(),
            handle.poisoned.clone(),
            handle.pair.clone(),
            guard,
        );
        assert!(!handle.poisoned.load(Ordering::SeqCst));
        assert!(selected
            .require_current()
            .unwrap_err()
            .is("HID_OWNER_LIFETIME_ENDED"));
        assert!(handle.selected_transport_lifetime().is_err());
        handle.poisoned.store(true, Ordering::SeqCst);
    }
    #[test]
    fn pair_state_has_one_complete_binding_and_no_partial_or_incremental_admission() {
        let mut state = PairState::default();
        assert!(state
            .bind([0, 0], u64::MAX)
            .unwrap_err()
            .is("HID_OWNER_PAIR_DISTINCT_REQUIRED"));
        assert!(state.members.is_none());
        state.bind([0, 1], u64::MAX).unwrap();
        state.check(0, now()).unwrap();
        state.check(1, now()).unwrap();
        assert!(state
            .check(2, now())
            .unwrap_err()
            .is("HID_OWNER_PAIR_MEMBER_REQUIRED"));
        assert!(state
            .bind([1, 2], u64::MAX)
            .unwrap_err()
            .is("HID_OWNER_PAIR_ALREADY_BOUND"));
        assert_eq!(state.members, Some([0, 1]));
        assert!(!state.revoked);
    }
    #[test]
    fn pair_either_member_failure_revokes_both_and_never_rebinds() {
        for failed in [0, 1] {
            let mut state = PairState::default();
            state.bind([0, 1], u64::MAX).unwrap();
            assert!(!state.revoke_member(2));
            state.check(0, now()).unwrap();
            state.check(1, now()).unwrap();
            assert!(state.revoke_member(failed));
            for index in [0, 1, 2] {
                assert!(state
                    .check(index, now())
                    .unwrap_err()
                    .is("HID_OWNER_PAIR_REVOKED"));
            }
            assert!(state.bind([2, 3], u64::MAX).is_err());
        }
        let mut state = PairState::default();
        state.revoke_all();
        assert!(
            state.bind([0, 1], u64::MAX).is_err(),
            "poison before BindPair cannot be undone by a late command"
        );
    }
    #[test]
    fn pair_owner_preflight_rejects_duplicate_missing_or_closed_handles_before_global_bind() {
        let state = Arc::new(Mutex::new(PairState::default()));
        let mut pair = OwnerPair {
            state: state.clone(),
            selection: None,
        };
        let poisoned = AtomicBool::new(false);
        assert!(pair
            .bind([0, 0], &[], now() + 1_000_000_000, &poisoned)
            .unwrap_err()
            .is("HID_OWNER_PAIR_DISTINCT_REQUIRED"));
        assert!(pair
            .bind([0, 1], &[], now() + 1_000_000_000, &poisoned)
            .unwrap_err()
            .is("HID_OWNER_HANDLE"));
        assert!(pair
            .bind([0, 1], &[None, None], now() + 1_000_000_000, &poisoned)
            .unwrap_err()
            .is("HID_OWNER_HANDLE"));
        assert!(state.lock().unwrap().members.is_none());
        assert!(pair.selection.is_none());
    }
    #[test]
    fn public_pair_rejects_different_owner_before_enqueue_and_preserves_earlier_deadline() {
        let ([mut first, mut second], receiver) = handles();
        let ([mut stranger, _other], other_receiver) = handles();
        assert!(first
            .bind_selected_pair(&mut stranger)
            .unwrap_err()
            .is("HID_OWNER_PAIR_DIFFERENT_OWNER"));
        assert!(receiver.try_recv().is_err());
        assert!(other_receiver.try_recv().is_err());
        stranger.poisoned.store(true, Ordering::SeqCst);
        let earlier = now() + 500_000_000;
        second.deadline_ns = Some(earlier);
        first.deadline_ns = Some(earlier + 100_000_000);
        let pair = first.pair.clone();
        let worker = std::thread::spawn(move || {
            let command = receiver
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap();
            assert_eq!(command.index, 0);
            assert_eq!(command.deadline, earlier);
            assert!(matches!(command.request, Request::BindPair { other: 1 }));
            pair.lock().unwrap().bind([0, 1], command.deadline).unwrap();
            assert!(command.reply.send(Ok(Response::Done)).is_ok());
        });
        first.bind_selected_pair(&mut second).unwrap();
        worker.join().unwrap();
        first.poisoned.store(true, Ordering::SeqCst);
    }
    #[test]
    fn paired_caller_timeout_revokes_both_and_refuses_late_report_without_caller_guard_drop() {
        let ([mut first, mut second], receiver) = handles();
        first.pair.lock().unwrap().bind([0, 1], u64::MAX).unwrap();
        assert!(first
            .request(Request::Read, now() + 1_000_000)
            .err()
            .unwrap()
            .is("HID_OWNER_RESPONSE_TIMEOUT"));
        assert!(first.poisoned.load(Ordering::SeqCst));
        assert!(first.pair.lock().unwrap().revoked);
        let queued = receiver.try_recv().unwrap();
        assert!(queued
            .reply
            .try_send(Ok(Response::Report(Zeroizing::new([9; REPORT]))))
            .is_err());
        assert!(second
            .write_report(&[0; REPORT])
            .unwrap_err()
            .is("HID_OWNER_POISONED"));
    }
    #[test]
    fn paired_close_latches_shared_revocation_before_owner_acknowledgment() {
        let ([first, second], receiver) = handles();
        let state = first.pair.clone();
        state.lock().unwrap().bind([0, 1], u64::MAX).unwrap();
        let worker = std::thread::spawn(move || {
            let command = receiver
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap();
            assert!(matches!(command.request, Request::Close));
            assert!(state.lock().unwrap().revoked);
            assert!(command.reply.send(Ok(Response::Done)).is_ok());
        });
        drop(first);
        worker.join().unwrap();
        assert!(second.pair.lock().unwrap().check(1, now()).is_err());
        second.poisoned.store(true, Ordering::SeqCst);
    }
    #[test]
    fn paired_request_error_revokes_other_member() {
        let ([mut first, mut second], receiver) = handles();
        first.pair.lock().unwrap().bind([0, 1], u64::MAX).unwrap();
        let worker = std::thread::spawn(move || {
            let command = receiver
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap();
            assert!(command
                .reply
                .send(Err(err!(EIO, "SYNTHETIC_NATIVE_ERROR")))
                .is_ok());
        });
        assert!(first
            .read_report()
            .unwrap_err()
            .is("SYNTHETIC_NATIVE_ERROR"));
        worker.join().unwrap();
        assert!(second
            .write_report(&[0; REPORT])
            .unwrap_err()
            .is("HID_OWNER_PAIR_REVOKED"));
        first.poisoned.store(true, Ordering::SeqCst);
    }
    #[test]
    fn pair_captured_deadline_bounds_both_members_and_every_later_command() {
        let mut state = PairState::default();
        state.bind([0, 1], 100).unwrap();
        state.check(0, 99).unwrap();
        state.check(1, 99).unwrap();
        assert!(state
            .check(0, 100)
            .unwrap_err()
            .is("HID_OWNER_PAIR_DEADLINE"));
        assert!(state
            .check(1, 101)
            .unwrap_err()
            .is("HID_OWNER_PAIR_DEADLINE"));
        let ([mut first, second], receiver) = handles();
        let bound = now() + 500_000_000;
        first.pair.lock().unwrap().bind([0, 1], bound).unwrap();
        let worker = std::thread::spawn(move || {
            let command = receiver
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap();
            assert_eq!(command.deadline, bound);
            assert!(command
                .reply
                .send(Ok(Response::Report(Zeroizing::new([8; REPORT]))))
                .is_ok());
        });
        assert!(matches!(
            first.request(Request::Read, bound + 100_000_000).unwrap(),
            Response::Report(_)
        ));
        worker.join().unwrap();
        first.poisoned.store(true, Ordering::SeqCst);
        drop(second);
    }
    #[test]
    fn poisoned_pair_metadata_refuses_before_any_native_command() {
        let ([mut first, second], receiver) = handles();
        let state = first.pair.clone();
        assert!(std::thread::spawn(move || {
            let _guard = state.lock().unwrap();
            panic!("synthetic pair-state poison");
        })
        .join()
        .is_err());
        assert!(first
            .request(Request::Read, now() + 1_000_000_000)
            .err()
            .unwrap()
            .is("HID_OWNER_PAIR_POISONED"));
        assert!(receiver.try_recv().is_err());
        first.poisoned.store(true, Ordering::SeqCst);
        drop(second);
    }
    #[test]
    fn actual_callback_copies_from_both_inboxes_are_checked_and_revocation_drains_both() {
        let inboxes = [Inbox::new(), Inbox::new()];
        let mut report = [7; REPORT];
        for inbox in &inboxes {
            on_input(
                (inbox as *const Inbox as *mut Inbox).cast(),
                0,
                std::ptr::null_mut(),
                0,
                0,
                report.as_mut_ptr(),
                64,
            );
        }
        check_pair_inputs([0, 1], |index| Ok(&inboxes[index])).unwrap();
        assert!(check_pair_inputs([0, 1], |index| if index == 0 {
            Ok(&inboxes[0])
        } else {
            Err(err!(EACCES, "HID_OWNER_HANDLE"))
        })
        .unwrap_err()
        .is("HID_OWNER_HANDLE"));
        on_input(
            (&inboxes[1] as *const Inbox as *mut Inbox).cast(),
            0,
            std::ptr::null_mut(),
            0,
            0,
            report.as_mut_ptr(),
            63,
        );
        assert!(check_pair_inputs([0, 1], |index| Ok(&inboxes[index]))
            .unwrap_err()
            .is("HID_INPUT_REPORT_LENGTH"));
        revoke_pair_inputs([0, 1], |index| Some(&inboxes[index]));
        for inbox in &inboxes {
            assert!(inbox.state.lock().unwrap().queue.is_empty());
            assert!(inbox.check_error().is_err());
            on_input(
                (inbox as *const Inbox as *mut Inbox).cast(),
                0,
                std::ptr::null_mut(),
                0,
                0,
                report.as_mut_ptr(),
                64,
            );
            assert!(
                inbox.state.lock().unwrap().queue.is_empty(),
                "revocation latches before any further callback copy"
            );
        }
        // Synthetic in-memory callback invocation; no physical callback
        // scheduling/quiescence or inaccessible IOKit storage erasure proof.
    }
    #[test]
    fn unexpected_response_type_revokes_pair_and_never_exports_a_report() {
        let ([mut first, mut second], receiver) = handles();
        first.pair.lock().unwrap().bind([0, 1], u64::MAX).unwrap();
        let worker = std::thread::spawn(move || {
            let command = receiver
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap();
            assert!(command.reply.send(Ok(Response::Done)).is_ok());
        });
        assert!(first.read_report().unwrap_err().is("HID_OWNER_RESPONSE"));
        worker.join().unwrap();
        assert!(second
            .write_report(&[0; REPORT])
            .unwrap_err()
            .is("HID_OWNER_PAIR_REVOKED"));
        first.poisoned.store(true, Ordering::SeqCst);
    }
    #[test]
    fn exact_pair_continuity_refuses_missing_reversed_or_substituted_members() {
        let mut state = PairState::default();
        assert!(state
            .check_exact([0, 1], 0)
            .unwrap_err()
            .is("HID_OWNER_PAIR_SCOPE"));
        state.bind([0, 1], 100).unwrap();
        state.check_exact([0, 1], 99).unwrap();
        for other in [[1, 0], [0, 2], [2, 1]] {
            assert!(state
                .check_exact(other, 99)
                .unwrap_err()
                .is("HID_OWNER_PAIR_SCOPE"));
        }
        assert!(state
            .check_exact([0, 1], 100)
            .unwrap_err()
            .is("HID_OWNER_PAIR_DEADLINE"));
        state.revoke_member(1);
        assert!(state
            .check_exact([0, 1], 99)
            .unwrap_err()
            .is("HID_OWNER_PAIR_REVOKED"));
    }
    #[test]
    fn continuity_command_keeps_ordered_owner_pair_and_original_deadline() {
        let ([first, second], receiver) = handles();
        assert!(first
            .require_selected_pair(&second)
            .unwrap_err()
            .is("HID_OWNER_PAIR_SCOPE"));
        assert!(receiver.try_recv().is_err());
        let bound = now() + 500_000_000;
        first.pair.lock().unwrap().bind([0, 1], bound).unwrap();
        assert!(second
            .require_selected_pair(&first)
            .unwrap_err()
            .is("HID_OWNER_PAIR_SCOPE"));
        assert!(receiver.try_recv().is_err());
        let worker = std::thread::spawn(move || {
            let command = receiver
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap();
            assert_eq!(command.index, 0);
            assert!(matches!(command.request, Request::CheckPair { other: 1 }));
            assert_eq!(command.deadline, bound);
            assert!(command.reply.send(Ok(Response::Done)).is_ok());
        });
        first.require_selected_pair(&second).unwrap();
        worker.join().unwrap();
        first.poisoned.store(true, Ordering::SeqCst);
        // Mock channel checks client metadata/order/deadline, not a genuine
        // native core guard or physical pair. Actual owner requires both.
    }
    #[test]
    fn continuity_reply_delayed_until_revocation_cannot_succeed() {
        let ([first, second], receiver) = handles();
        let pair = first.pair.clone();
        pair.lock().unwrap().bind([0, 1], u64::MAX).unwrap();
        let worker = std::thread::spawn(move || {
            let command = receiver
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap();
            assert!(matches!(command.request, Request::CheckPair { other: 1 }));
            pair.lock().unwrap().revoke_member(1);
            assert!(command.reply.send(Ok(Response::Done)).is_ok());
        });
        assert!(first
            .require_selected_pair(&second)
            .unwrap_err()
            .is("HID_OWNER_PAIR_REVOKED"));
        worker.join().unwrap();
        first.poisoned.store(true, Ordering::SeqCst);
    }
    #[test]
    fn owner_continuity_requires_real_core_set_guard_beyond_shared_metadata() {
        let state = Arc::new(Mutex::new(PairState::default()));
        state.lock().unwrap().bind([0, 1], u64::MAX).unwrap();
        let pair = OwnerPair {
            state,
            selection: None,
        };
        assert!(pair
            .require_exact([0, 1], now() + 1_000_000_000, &AtomicBool::new(false))
            .unwrap_err()
            .is("HID_OWNER_PAIR_REVOKED"));
    }
}
