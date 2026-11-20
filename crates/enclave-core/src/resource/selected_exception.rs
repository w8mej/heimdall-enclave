//! Operation-owned current-task exception assignment. No raw port leaves this
//! module. Legacy process hardening retains its routing with checked name bounds.
use crate::{
    codesign,
    daemon::DaemonId,
    deployment::{self, CheckedDeploymentTarget, DeploymentRole, DeploymentSigningMode},
    err,
    error::EnclaveResult,
    fail, Profile,
};
use std::{ffi::CString, time::Instant};

const CAPACITY: usize = 32; // Observed SDK task.h reply arrays each have32 slots.
const REQUIRED_MASK: u32 = (1 << 1) | (1 << 2) | (1 << 12);
const BEHAVIOR: i32 = 1 | i32::MIN; // EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES.
#[cfg(target_arch = "aarch64")]
const FLAVOR: i32 = 5;
#[cfg(target_arch = "x86_64")]
const FLAVOR: i32 = 13;
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
const FLAVOR: i32 = -1; // Unsupported native architecture always refuses.
const SEND: u32 = 1 << 16;
const DEAD_NAME: u32 = 1 << 20;
fn valid_name(port: u32) -> bool {
    port != 0 && port != u32::MAX
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    ServiceName,
    Deadline,
    CurrentTask,
    TaskAuditRead,
    TaskAuditCount,
    TaskAuditValue,
    TaskAuditChanged,
    Lookup,
    LookupName,
    OriginalType,
    Set,
    Get,
    Count,
    Mask,
    Port,
    Behavior,
    Flavor,
    ReturnedCleanup,
    OriginalCleanup,
    CleanupTaskChanged,
    Poisoned,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Failure {
    stage: Stage,
    code: Option<i32>,
}
impl Failure {
    fn at(stage: Stage) -> Self {
        Self { stage, code: None }
    }
    fn native(stage: Stage, code: i32) -> Self {
        Self {
            stage,
            code: Some(code),
        }
    }
    fn error(self) -> crate::error::EnclaveError {
        let errno = if self.stage == Stage::Deadline {
            crate::error::Errno::ETIMEDOUT
        } else {
            crate::error::Errno::EACCES
        };
        crate::error::EnclaveError::with(
            errno,
            "SELECTED_EXCEPTION_ASSIGNMENT_REFUSED",
            format!("stage={:?}; code={:?}", self.stage, self.code),
        )
    }
    fn report(self) {
        eprintln!(
            "SELECTED_EXCEPTION_ASSIGNMENT_FAILED stage={:?} code={:?}",
            self.stage, self.code
        );
    }
}
struct Ports {
    count: u32,
    masks: [u32; CAPACITY],
    ports: [u32; CAPACITY],
    behaviors: [i32; CAPACITY],
    flavors: [i32; CAPACITY],
}
impl Ports {
    fn empty() -> Self {
        Self {
            count: CAPACITY as u32,
            masks: [0; CAPACITY],
            ports: [0; CAPACITY],
            behaviors: [0; CAPACITY],
            flavors: [0; CAPACITY],
        }
    }
    fn matches(&self, original: u32) -> Result<(), Failure> {
        let count = self.count as usize;
        if count == 0 || count > CAPACITY {
            return Err(Failure::at(Stage::Count));
        }
        // No unexpected output may hide beyond a claimed count. These slots
        // were initialized before the call and are also cleaned on refusal.
        if self.ports[count..].iter().any(|port| *port != 0) {
            return Err(Failure::at(Stage::Count));
        }
        let mut seen = 0;
        for index in 0..count {
            let mask = self.masks[index];
            if mask == 0 || mask & !REQUIRED_MASK != 0 || seen & mask != 0 {
                return Err(Failure::at(Stage::Mask));
            }
            seen |= mask;
            if self.ports[index] != original {
                return Err(Failure::at(Stage::Port));
            }
            if self.behaviors[index] != BEHAVIOR {
                return Err(Failure::at(Stage::Behavior));
            }
            if self.flavors[index] != FLAVOR {
                return Err(Failure::at(Stage::Flavor));
            }
        }
        if seen != REQUIRED_MASK {
            return Err(Failure::at(Stage::Mask));
        }
        Ok(())
    }
}
// Private synthetic seam. Production constructs only Native and never accepts
// providers, caller port names, masks, tasks, service names or expected values.
enum Cleanup {
    Released,
    NativeError(i32),
    TaskChanged,
}
trait Kernel {
    // Namespace guard only: cleanup may run after identity/credential changes,
    // but must never deallocate an inherited name in a different task namespace.
    fn current(&mut self) -> bool;
    // ONLY Native's actual captured mach_task_self_ is queried. This is never
    // a task supplied by a socket, request, received descriptor, PID or caller.
    fn task_audit(&mut self) -> (i32, u32, [u32; 8]);
    fn lookup(&mut self, service: &CString) -> (i32, u32);
    fn port_type(&mut self, port: u32) -> Result<u32, i32>;
    fn set(&mut self, port: u32) -> i32;
    fn get(&mut self, ports: &mut Ports) -> i32;
    fn deallocate(&mut self, port: u32) -> Cleanup;
}
struct Assignment<K: Kernel> {
    kernel: K,
    port: Option<u32>,
    audit: Option<[u32; 8]>,
    end: Instant,
    poisoned: bool,
    failures: Vec<Failure>,
    uncertain_references: Vec<u32>,
}
impl<K: Kernel> Assignment<K> {
    fn retain(&mut self, failure: Failure) {
        self.poisoned = true;
        failure.report();
        self.failures.push(failure);
    }
    fn within(&self, end: Instant) -> Result<(), Failure> {
        if Instant::now() >= end.min(self.end) {
            return Err(Failure::at(Stage::Deadline));
        }
        Ok(())
    }
    fn current(&mut self, end: Instant) -> Result<(), Failure> {
        self.within(end)?;
        if !self.kernel.current() {
            return Err(Failure::at(Stage::CurrentTask));
        }
        let (code, count, audit) = self.kernel.task_audit();
        if code != 0 {
            return Err(Failure::native(Stage::TaskAuditRead, code));
        }
        if count != 8 {
            return Err(Failure::at(Stage::TaskAuditCount));
        }
        // Conservatively refuse the retained SDK's unset sentinel and kernel
        // token for this custody-only owner. No field/index is interpreted.
        if audit == [u32::MAX; 8] || audit == [0; 8] {
            return Err(Failure::at(Stage::TaskAuditValue));
        }
        if let Some(original) = self.audit {
            if audit != original {
                return Err(Failure::at(Stage::TaskAuditChanged));
            }
        } else {
            self.audit = Some(audit);
        }
        // Retain the original opaque token before the late namespace/time
        // check. No exec/credential/incarnation change can recapture it.
        if !self.kernel.current() {
            return Err(Failure::at(Stage::CurrentTask));
        }
        self.within(end)
    }
    fn original(&mut self, end: Instant) -> Result<u32, Failure> {
        self.current(end)?;
        let port = self.port.ok_or_else(|| Failure::at(Stage::LookupName))?;
        let kind = self
            .kernel
            .port_type(port)
            .map_err(|code| Failure::native(Stage::OriginalType, code))?;
        if kind & SEND == 0 || kind & DEAD_NAME != 0 {
            return Err(Failure::at(Stage::OriginalType));
        }
        self.current(end)?;
        Ok(port)
    }
    fn release_reference(&mut self, port: u32, stage: Stage) -> Result<(), Failure> {
        // Cleanup is not a reason to act on a captured task in another process
        // or task namespace. Unlike normal admission, cleanup still runs after
        // a deadline, but only for the SAME actual current task and process.
        let result = if self.kernel.current() {
            self.kernel.deallocate(port)
        } else {
            Cleanup::TaskChanged
        };
        match result {
            Cleanup::Released => Ok(()),
            Cleanup::NativeError(code) => Err(Failure::native(stage, code)),
            Cleanup::TaskChanged => Err(Failure::at(Stage::CleanupTaskChanged)),
        }
    }
    fn assign(kernel: K, service: &CString, end: Instant) -> Result<Self, Failure> {
        if service.as_bytes().is_empty()
            || service.as_bytes().len() > super::MAX_EXCEPTION_SERVICE_NAME_BYTES
        {
            return Err(Failure::at(Stage::ServiceName));
        }
        let mut owner = Self {
            kernel,
            port: None,
            audit: None,
            end,
            poisoned: false,
            failures: Vec::new(),
            uncertain_references: Vec::new(),
        };
        let result = (|| {
            owner.current(end)?;
            let (code, port) = owner.kernel.lookup(service);
            // Retain a real returned name before any later type/time/error
            // check. A failed call's initialized partial output is not ignored.
            if valid_name(port) {
                owner.port = Some(port);
            }
            if code != 0 {
                return Err(Failure::native(Stage::Lookup, code));
            }
            owner.current(end)?;
            if !valid_name(port) {
                return Err(Failure::at(Stage::LookupName));
            }
            let original = owner.original(end)?;
            let code = owner.kernel.set(original);
            if code != 0 {
                return Err(Failure::native(Stage::Set, code));
            }
            owner.current(end)?;
            owner.observe(end)
        })();
        if let Err(error) = result {
            // observe retains its own failure; earlier constructor failures
            // are retained here. Drop releases only this original lookup ref.
            if !owner.poisoned {
                owner.retain(error);
            }
            return Err(error);
        }
        Ok(owner)
    }
    fn observe(&mut self, end: Instant) -> Result<(), Failure> {
        if self.poisoned {
            return Err(Failure::at(Stage::Poisoned));
        }
        let end = end.min(self.end);
        let result = (|| {
            let original = self.original(end)?;
            let mut returned = Ports::empty();
            let code = self.kernel.get(&mut returned);
            let observed = if code != 0 {
                Err(Failure::native(Stage::Get, code))
            } else {
                returned.matches(original)
            };
            if let Err(error) = observed {
                self.retain(error);
            }
            // Always consume every nonnull returned slot, including errors,
            // malformed count and duplicate numeric names. Each output slot
            // is one returned uref: deduplicating names would leak references.
            let mut cleanup_failure = None;
            for port in &mut returned.ports {
                let name = std::mem::replace(port, 0);
                if valid_name(name) {
                    if let Err(failure) = self.release_reference(name, Stage::ReturnedCleanup) {
                        self.uncertain_references.push(name);
                        cleanup_failure.get_or_insert(failure);
                        self.retain(failure);
                    }
                }
            }
            // Preserve primary failure and all cleanup failures independently.
            if let Err(error) = observed {
                return Err(error);
            }
            if let Some(error) = cleanup_failure {
                return Err(error);
            }
            self.original(end)?;
            self.current(end)
        })();
        if let Err(error) = result {
            if !self.failures.contains(&error) {
                self.retain(error);
            }
        }
        result
    }
}
impl<K: Kernel> Drop for Assignment<K> {
    fn drop(&mut self) {
        // Never unset, restore or reassign task exception handlers on return.
        // Task assignment holds its own kernel reference; only our lookup's
        // one owned user reference is released, with no cleanup retry.
        if let Some(port) = self.port.take() {
            if let Err(failure) = self.release_reference(port, Stage::OriginalCleanup) {
                self.uncertain_references.push(port);
                self.retain(failure);
            }
        }
        if !self.uncertain_references.is_empty() {
            eprintln!(
                "SELECTED_EXCEPTION_ASSIGNMENT_CLEANUP_UNKNOWN count={}",
                self.uncertain_references.len()
            );
        }
    }
}

/// One selected custody operation's original exception-port assignment.
/// No Clone, serde, raw-port extraction or external provider constructor exists.
pub(crate) struct SelectedExceptionAssignment {
    inner: Assignment<Native>,
    checked: &'static CheckedDeploymentTarget,
    service: CString,
    end: Instant,
    poisoned: bool,
}
fn selected(
    checked: &CheckedDeploymentTarget,
    service: &CString,
    end: Instant,
) -> EnclaveResult<()> {
    if Instant::now() >= end {
        fail!(ETIMEDOUT, "SELECTED_EXCEPTION_ASSIGNMENT_DEADLINE");
    }
    if !cfg!(all(
        target_os = "macos",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )) || !codesign::enforced()
    {
        fail!(ENOSYS, "SELECTED_EXCEPTION_ASSIGNMENT_NATIVE_REQUIRED");
    }
    if crate::ipc::geteuid() != DaemonId::CustodyVault.uid() {
        fail!(EPERM, "SELECTED_EXCEPTION_ASSIGNMENT_CUSTODY_REQUIRED");
    }
    let actual =
        deployment::selected().ok_or_else(|| err!(EACCES, "DEPLOYMENT_CONTEXT_REQUIRED"))?;
    let target = actual.target();
    if !std::ptr::eq(actual, checked)
        || target.role != DeploymentRole::DedicatedTest
        || target.profile != Profile::L2
        || target.signing_identity_mode != DeploymentSigningMode::LocalPins
        || codesign::signing_mode() != codesign::SigningMode::LocalPins
        || target.broker.is_some()
        || !target.shared_read_only_inputs.is_empty()
        || service.as_bytes() != target.layout.mach_service.as_bytes()
    {
        fail!(EACCES, "SELECTED_EXCEPTION_ASSIGNMENT_CONTEXT");
    }
    let current = deployment::load(checked.config_path())?;
    if current.descriptor_sha256() != checked.descriptor_sha256()
        || current.target() != checked.target()
    {
        fail!(ESTALE, "SELECTED_EXCEPTION_ASSIGNMENT_CONTEXT");
    }
    deployment::upgrade::assert_start_allowed(actual)?;
    if Instant::now() >= end {
        fail!(ETIMEDOUT, "SELECTED_EXCEPTION_ASSIGNMENT_DEADLINE");
    }
    Ok(())
}
impl SelectedExceptionAssignment {
    pub(crate) fn assign_current(end: Instant) -> EnclaveResult<Self> {
        let checked =
            deployment::selected().ok_or_else(|| err!(EACCES, "DEPLOYMENT_CONTEXT_REQUIRED"))?;
        let service = super::exception_service_name(Some(&checked.target().layout.mach_service))?;
        selected(checked, &service, end)?;
        let inner = Assignment::assign(Native::current(), &service, end).map_err(Failure::error)?;
        let owner = Self {
            inner,
            checked,
            service,
            end,
            poisoned: false,
        };
        selected(owner.checked, &owner.service, end)?;
        Ok(owner)
    }
    /// Observe the actual current task's complete required assignment again.
    /// Caller retains this SAME owner with its authenticated stream/generation.
    pub(crate) fn observe_current(&mut self, end: Instant) -> EnclaveResult<()> {
        if self.poisoned {
            fail!(EACCES, "SELECTED_EXCEPTION_ASSIGNMENT_POISONED");
        }
        let end = end.min(self.end);
        let result = (|| {
            selected(self.checked, &self.service, end)?;
            self.inner.observe(end).map_err(Failure::error)?;
            selected(self.checked, &self.service, end)
        })();
        if result.is_err() {
            self.poisoned = true;
            self.inner.poisoned = true;
        }
        result
    }
}

#[cfg(target_os = "macos")]
struct Native {
    task: u32,
    pid: u32,
}
#[cfg(target_os = "macos")]
impl Native {
    fn current() -> Self {
        Self {
            task: unsafe { ffi::mach_task_self_ },
            pid: std::process::id(),
        }
    }
}
#[cfg(target_os = "macos")]
impl Kernel for Native {
    fn current(&mut self) -> bool {
        self.pid == std::process::id() && self.task == unsafe { ffi::mach_task_self_ }
    }
    fn task_audit(&mut self) -> (i32, u32, [u32; 8]) {
        // The PID above only prevents use after fork/task-namespace change.
        // Identity comes from this actual self-task query, never a PID lookup.
        if !<Self as Kernel>::current(self) {
            return (-1, 0, [u32::MAX; 8]);
        }
        let mut token = [u32::MAX; 8];
        let mut count = 8;
        let code = unsafe { ffi::task_info(self.task, 15, token.as_mut_ptr().cast(), &mut count) };
        (code, count, token)
    }
    fn lookup(&mut self, service: &CString) -> (i32, u32) {
        let mut port = 0;
        let code =
            unsafe { ffi::bootstrap_look_up(ffi::bootstrap_port, service.as_ptr(), &mut port) };
        (code, port)
    }
    fn port_type(&mut self, port: u32) -> Result<u32, i32> {
        let mut kind = 0;
        let code = unsafe { ffi::mach_port_type(self.task, port, &mut kind) };
        if code == 0 {
            Ok(kind)
        } else {
            Err(code)
        }
    }
    fn set(&mut self, port: u32) -> i32 {
        unsafe { ffi::task_set_exception_ports(self.task, REQUIRED_MASK, port, BEHAVIOR, FLAVOR) }
    }
    fn get(&mut self, ports: &mut Ports) -> i32 {
        unsafe {
            ffi::task_get_exception_ports(
                self.task,
                REQUIRED_MASK,
                ports.masks.as_mut_ptr(),
                &mut ports.count,
                ports.ports.as_mut_ptr(),
                ports.behaviors.as_mut_ptr(),
                ports.flavors.as_mut_ptr(),
            )
        }
    }
    fn deallocate(&mut self, port: u32) -> Cleanup {
        // Defense at the actual syscall adapter as well as the generic owner.
        if !<Self as Kernel>::current(self) {
            return Cleanup::TaskChanged;
        }
        let code = unsafe { ffi::mach_port_deallocate(self.task, port) };
        if code == 0 {
            Cleanup::Released
        } else {
            Cleanup::NativeError(code)
        }
    }
}
#[cfg(target_os = "macos")]
mod ffi {
    unsafe extern "C" {
        pub(super) static mach_task_self_: u32;
        pub(super) static bootstrap_port: u32;
        pub(super) fn bootstrap_look_up(
            bootstrap: u32,
            service: *const libc::c_char,
            port: *mut u32,
        ) -> i32;
        pub(super) fn mach_port_type(task: u32, port: u32, kind: *mut u32) -> i32;
        pub(super) fn mach_port_deallocate(task: u32, port: u32) -> i32;
        pub(super) fn task_info(task: u32, flavor: i32, info: *mut i32, count: *mut u32) -> i32;
        pub(super) fn task_set_exception_ports(
            task: u32,
            mask: u32,
            port: u32,
            behavior: i32,
            flavor: i32,
        ) -> i32;
        pub(super) fn task_get_exception_ports(
            task: u32,
            mask: u32,
            masks: *mut u32,
            count: *mut u32,
            ports: *mut u32,
            behaviors: *mut i32,
            flavors: *mut i32,
        ) -> i32;
    }
}
#[cfg(not(target_os = "macos"))]
struct Native;
#[cfg(not(target_os = "macos"))]
impl Native {
    fn current() -> Self {
        Self
    }
}
#[cfg(not(target_os = "macos"))]
impl Kernel for Native {
    fn current(&mut self) -> bool {
        false
    }
    fn task_audit(&mut self) -> (i32, u32, [u32; 8]) {
        (-1, 0, [u32::MAX; 8])
    }
    fn lookup(&mut self, _: &CString) -> (i32, u32) {
        (-1, 0)
    }
    fn port_type(&mut self, _: u32) -> Result<u32, i32> {
        Err(-1)
    }
    fn set(&mut self, _: u32) -> i32 {
        -1
    }
    fn get(&mut self, _: &mut Ports) -> i32 {
        -1
    }
    fn deallocate(&mut self, _: u32) -> Cleanup {
        Cleanup::TaskChanged
    }
}

#[cfg(test)]
#[path = "selected_exception_tests.rs"]
mod tests;
