//! Current exception assignment of the SAME certified, actor-matched received
//! task. This is a child of selected_mach_native: no raw task/receiver getter,
//! external constructor, public provider or positive readiness proof exists.
//!
//! Public SDK27.2 task.h supplies the fixed 32-slot ABI. Pinned public XNU
//! task.defs:290/ipc_tt.c:4807 require CONTROL for owned-handler readback. READ
//! explicitly refuses. The READ-capable *_info API returns debug information,
//! which cannot establish equality to our retained original receive right.

use std::time::Instant;

const CAPACITY: usize = 32;
const REQUIRED_MASK: u32 = (1 << 1) | (1 << 2) | (1 << 12);
const BEHAVIOR: i32 = 1 | i32::MIN; // EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES.
#[cfg(target_arch = "aarch64")]
const FLAVOR: i32 = 5; // ARM_THREAD_STATE64, as in the original assignment.
#[cfg(target_arch = "x86_64")]
const FLAVOR: i32 = 13; // x86_THREAD_STATE64.
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
const FLAVOR: i32 = -1;
const CONTROL: u32 = 2; // Public IPC_OTYPE_TASK_CONTROL, not internal IKOT.
const READ: u32 = 45; // Public IPC_OTYPE_TASK_READ.

fn valid_name(name: u32) -> bool {
    name != 0 && name != u32::MAX
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Deadline,
    OriginalContext,
    ActorBinding,
    Namespace,
    UnsupportedRead,
    UnsupportedClass,
    UnsupportedArchitecture,
    OriginalReceiver,
    Query,
    Count,
    Mask,
    Receiver,
    Behavior,
    Flavor,
    ReturnedCleanup,
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
}

struct Ports {
    count: u32,
    masks: [u32; CAPACITY],
    names: [u32; CAPACITY],
    behaviors: [i32; CAPACITY],
    flavors: [i32; CAPACITY],
}
impl Ports {
    fn empty() -> Self {
        Self {
            count: CAPACITY as u32,
            masks: [0; CAPACITY],
            names: [0; CAPACITY],
            behaviors: [0; CAPACITY],
            flavors: [0; CAPACITY],
        }
    }
    fn matches(&self, receiver: u32) -> Result<(), Failure> {
        let count = self.count as usize;
        if count == 0 || count > CAPACITY {
            return Err(Failure::at(Stage::Count));
        }
        if self.names[count..].iter().any(|v| *v != 0)
            || self.masks[count..].iter().any(|v| *v != 0)
            || self.behaviors[count..].iter().any(|v| *v != 0)
            || self.flavors[count..].iter().any(|v| *v != 0)
        {
            return Err(Failure::at(Stage::Count));
        }
        let mut union = 0;
        for row in 0..count {
            let mask = self.masks[row];
            if mask == 0 || mask & !REQUIRED_MASK != 0 || union & mask != 0 {
                return Err(Failure::at(Stage::Mask));
            }
            union |= mask;
            if self.names[row] != receiver {
                return Err(Failure::at(Stage::Receiver));
            }
            if self.behaviors[row] != BEHAVIOR {
                return Err(Failure::at(Stage::Behavior));
            }
            if self.flavors[row] != FLAVOR {
                return Err(Failure::at(Stage::Flavor));
            }
        }
        if union != REQUIRED_MASK {
            return Err(Failure::at(Stage::Mask));
        }
        Ok(())
    }
}

enum Release {
    Released,
    NativeError(i32),
    NamespaceChanged,
}

// Private software seam. Native fixes every method to one lifetime-borrowed
// sealed received owner and one sealed result from its original custody actor.
// No production caller chooses a task, class, receiver, provider or clock.
trait Operation {
    fn original_end(&self) -> Instant;
    fn now(&self) -> Instant;
    fn current(&mut self, end: Instant) -> Result<(), Failure>;
    fn task_class(&self) -> u32;
    fn receiver(&self) -> u32;
    fn get(&mut self, ports: &mut Ports) -> i32;
    fn release(&mut self, name: u32) -> Release;
    fn invalidate(&mut self);
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CleanupSummary {
    attempted: u32,
    uncertain: u32,
}
struct ObservationResult {
    result: Result<(), Failure>,
    cleanup: CleanupSummary,
}

struct ReleaseVeto<'a, O: Operation> {
    operation: &'a mut O,
    armed: bool,
}
impl<O: Operation> Drop for ReleaseVeto<'_, O> {
    fn drop(&mut self) {
        if self.armed {
            self.operation.invalidate();
        }
    }
}

struct Observation<'a, O: Operation> {
    operation: &'a mut O,
    returned: Ports,
    end: Instant,
    armed: bool,
    cleanup: CleanupSummary,
}
impl<'a, O: Operation> Observation<'a, O> {
    fn new(operation: &'a mut O, requested: Instant) -> Self {
        let end = requested.min(operation.original_end());
        Self {
            operation,
            returned: Ports::empty(),
            end,
            armed: true,
            cleanup: CleanupSummary::default(),
        }
    }
    fn current(&mut self) -> Result<(), Failure> {
        if self.operation.now() >= self.end {
            return Err(Failure::at(Stage::Deadline));
        }
        self.operation.current(self.end)?;
        if self.operation.now() >= self.end {
            return Err(Failure::at(Stage::Deadline));
        }
        Ok(())
    }
    fn inspect(&mut self) -> Result<(), Failure> {
        self.current()?;
        match self.operation.task_class() {
            CONTROL => {}
            READ => return Err(Failure::at(Stage::UnsupportedRead)),
            _ => return Err(Failure::at(Stage::UnsupportedClass)),
        }
        if FLAVOR < 0 {
            return Err(Failure::at(Stage::UnsupportedArchitecture));
        }
        let receiver = self.operation.receiver();
        if !valid_name(receiver) {
            return Err(Failure::at(Stage::OriginalReceiver));
        }
        self.current()?;
        // Initialized storage is owned before the call. Even a native error or
        // caught unwind must consume every valid name written into its slots.
        let code = self.operation.get(&mut self.returned);
        if code != 0 {
            return Err(Failure::native(Stage::Query, code));
        }
        self.current()?;
        self.returned.matches(receiver)?;
        self.current()
    }
    fn clean(&mut self) -> Result<(), Failure> {
        let mut first = None;
        for slot in &mut self.returned.names {
            // Each output slot owns a uref, even when several numeric names
            // equal the same original receiver. Never deduplicate or retry.
            let name = std::mem::replace(slot, 0);
            if !valid_name(name) {
                continue;
            }
            self.cleanup.attempted += 1;
            // Before entering a possibly blocking cleanup call, retain that
            // completion is unknown. An unwind cannot silently clear it.
            self.cleanup.uncertain += 1;
            let mut veto = ReleaseVeto {
                operation: &mut *self.operation,
                armed: true,
            };
            let result = match veto.operation.release(name) {
                Release::Released => {
                    self.cleanup.uncertain -= 1;
                    Ok(())
                }
                Release::NativeError(code) => Err(Failure::native(Stage::ReturnedCleanup, code)),
                Release::NamespaceChanged => Err(Failure::at(Stage::Namespace)),
            };
            if let Err(failure) = result {
                // Immediate same-session veto precedes any next cleanup call.
                veto.operation.invalidate();
                first.get_or_insert(failure);
            }
            veto.armed = false;
        }
        first.map_or(Ok(()), Err)
    }
    fn run(mut self) -> ObservationResult {
        let primary = self.inspect();
        if primary.is_err() {
            self.operation.invalidate();
        }
        let cleanup = self.clean();
        let result = primary.and(cleanup).and_then(|()| self.current());
        if result.is_ok() {
            self.armed = false;
        } else {
            self.operation.invalidate();
        }
        ObservationResult {
            result,
            cleanup: self.cleanup,
        }
    }
}
impl<O: Operation> Drop for Observation<'_, O> {
    fn drop(&mut self) {
        // This includes a panic during a post-query check or cleanup. The
        // original message/audit owner is still borrowed by Operation here.
        if self.armed {
            self.operation.invalidate();
        }
        if self.clean().is_err() {
            self.operation.invalidate();
        }
        if self.cleanup.uncertain != 0 {
            eprintln!(
                "SELECTED_RECEIVED_ASSIGNMENT_CLEANUP_UNKNOWN count={}",
                self.cleanup.uncertain
            );
        }
    }
}

#[cfg(target_os = "macos")]
struct Native<'a, 'original> {
    original: &'a mut super::OriginalReceivedTask<'original>,
    binding: &'a crate::power::selected_owner_listener::OriginalCustodyActorMatch,
    namespace_task: u32,
    namespace_pid: u32,
}
#[cfg(target_os = "macos")]
impl Native<'_, '_> {
    fn same_namespace(&self) -> bool {
        self.namespace_pid == std::process::id()
            && self.namespace_task == unsafe { ffi::mach_task_self_ }
    }
}
#[cfg(target_os = "macos")]
impl Operation for Native<'_, '_> {
    fn original_end(&self) -> Instant {
        self.original.end.min(self.original.lifetime.end)
    }
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn current(&mut self, end: Instant) -> Result<(), Failure> {
        if !self.same_namespace() {
            return Err(Failure::at(Stage::Namespace));
        }
        self.original
            .require_current(end)
            .map_err(|_| Failure::at(Stage::OriginalContext))?;
        self.binding
            .require_same_original(
                self.original.certificate,
                &self.original.lifetime.session,
                end,
            )
            .map_err(|_| Failure::at(Stage::ActorBinding))?;
        self.original
            .require_current(end)
            .map_err(|_| Failure::at(Stage::OriginalContext))?;
        if !self.same_namespace() {
            return Err(Failure::at(Stage::Namespace));
        }
        Ok(())
    }
    fn task_class(&self) -> u32 {
        self.original.task_kind
    }
    fn receiver(&self) -> u32 {
        self.original.receive_name
    }
    fn get(&mut self, ports: &mut Ports) -> i32 {
        // Defense at the actual syscall boundary too. No RPC to a READ,
        // unclassified, caller-supplied or replacement task is permitted.
        if self.original.task_kind != CONTROL || !self.same_namespace() {
            return -1;
        }
        unsafe {
            ffi::task_get_exception_ports(
                self.original.task_name,
                REQUIRED_MASK,
                ports.masks.as_mut_ptr(),
                &mut ports.count,
                ports.names.as_mut_ptr(),
                ports.behaviors.as_mut_ptr(),
                ports.flavors.as_mut_ptr(),
            )
        }
    }
    fn release(&mut self, name: u32) -> Release {
        // Cleanup remains allowed after deadline/credential change, solely in
        // the same captured actual local task namespace. This is no task lookup.
        if !self.same_namespace() {
            return Release::NamespaceChanged;
        }
        let code = unsafe { ffi::mach_port_deallocate(self.namespace_task, name) };
        if code == 0 {
            Release::Released
        } else {
            Release::NativeError(code)
        }
    }
    fn invalidate(&mut self) {
        self.original.lifetime.stop();
    }
}

/// Check only the original CONTROL task's current required assignment after
/// actual same-actor/peer matching. Success grants no Ready/Begin/fault action.
/// Whole message, AuditLease and original receiver stay borrowed through all
/// readback, cleanup and late checks. Native calls have no proven hard latency
/// bound; expiry prevents late success and never claims complete cleanup.
#[cfg(target_os = "macos")]
pub(super) fn observe(
    original: &mut super::OriginalReceivedTask<'_>,
    binding: &crate::power::selected_owner_listener::OriginalCustodyActorMatch,
    end: Instant,
) -> crate::error::EnclaveResult<()> {
    let mut native = Native {
        original,
        binding,
        namespace_task: unsafe { ffi::mach_task_self_ },
        namespace_pid: std::process::id(),
    };
    let observed = Observation::new(&mut native, end).run();
    observed.result.map_err(|failure| {
        let errno = if failure.stage == Stage::Deadline {
            crate::error::Errno::ETIMEDOUT
        } else {
            crate::error::Errno::EACCES
        };
        crate::error::EnclaveError::with(
            errno,
            "SELECTED_RECEIVED_ASSIGNMENT_REFUSED",
            format!(
                "stage={:?}; code={:?}; cleanup_attempted={}; cleanup_unknown={}",
                failure.stage, failure.code, observed.cleanup.attempted, observed.cleanup.uncertain
            ),
        )
    })
}

#[cfg(target_os = "macos")]
mod ffi {
    unsafe extern "C" {
        pub(super) static mach_task_self_: u32;
        pub(super) fn task_get_exception_ports(
            task: u32,
            mask: u32,
            masks: *mut u32,
            count: *mut u32,
            ports: *mut u32,
            behaviors: *mut i32,
            flavors: *mut i32,
        ) -> i32;
        pub(super) fn mach_port_deallocate(task: u32, port: u32) -> i32;
    }
}

#[cfg(test)]
#[path = "selected_exception_assignment_tests.rs"]
mod tests;
