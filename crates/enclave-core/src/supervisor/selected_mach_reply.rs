//! Terminal failure-only reply with actual consumed-message validation.
//! Public-source result correspondence is not installed-kernel qualification.
//! This owner cannot grant fault handling, positive reply or startup authority.

use super::{
    mach_wire, AuditEvidence, AuditLease, FaultEvidence, MessagePhase, OriginalFaultPreparation,
    Refusal, Resources, ValidReportReceipt,
};
use super::{Duration, Instant, Ordering, SessionDependency};

const SEND_OPTIONS: i32 = 0x0000_0001 | 0x0000_0010 | 0x0000_0040;
const INVALID_DEST: i32 = 0x1000_0003;
const TIMED_OUT: i32 = 0x1000_0004;
const INTERRUPTED: i32 = 0x1000_0007;
const MOVE_SEND_ONCE: u32 = 18;
const REMOTE_MASK: u32 = 0x1f;
const KERN_FAILURE: i32 = 5;

#[repr(C, align(16))]
pub(super) struct ReplyStorage([u8; mach_wire::REPLY_BYTES]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReplyRefusal {
    NotReceived,
    AlreadyDetached,
    Frame,
    Wire(mach_wire::WireError),
    ReceiveName,
    Context,
    Endpoint,
    TimeoutRange,
    ReturnedShape,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReplyOwnership {
    NeverSent,
    TransferredDeliveryUnqualified,
    ReturnedUnsent,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReplyCleanup {
    NotRequired,
    DestroyInvokedCompletionUnqualified,
    UnknownNoSafeReplyCleanup,
}
/// Diagnostics only. An accepted native send transfers ownership, not proof
/// of peer receipt/handling, positive RPC outcome, health or selected startup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ReplyObservation {
    pub(super) native_result: Option<i32>,
    pub(super) ownership: ReplyOwnership,
    pub(super) cleanup: ReplyCleanup,
    pub(super) refusal: Option<ReplyRefusal>,
}

// Private software seam. The sole production constructor fixes NativeReply;
// no external provider, mutable pointer, original name or right getter exists.
pub(super) trait ReplyKernel {
    fn send(&mut self, reply: &mut ReplyStorage, options: i32, timeout_ms: u32) -> i32;
    fn destroy_unsent(&mut self, reply: &mut ReplyStorage);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplyState {
    OwnedUnsent,
    InFlightUnknown,
    Transferred,
    ReturnedUnsent,
    Unknown,
    Retired,
}

// The mutable actual resource-slot borrow and shared retained-body borrow
// prevent body destruction while detached reply ownership remains unsettled.
// There is no self-reference or raw-pointer identity between these components.
pub(super) struct ReplyOwner<'r, S: SessionDependency, R: ReplyKernel> {
    storage: &'r super::Storage,
    _resources: &'r mut Resources,
    lifetime: &'r super::SessionLifetime<S>,
    audit: &'r AuditLease,
    preparation: &'r OriginalFaultPreparation,
    guard: ConsumedFaultIoGuard<'r>,
    reply: Box<ReplyStorage>,
    kernel: R,
    end: Instant,
    state: ReplyState,
}
impl<S: SessionDependency, R: ReplyKernel> std::fmt::Debug for ReplyOwner<'_, S, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DetachedFailureReply([EXCLUSIVE OWNERSHIP; REDACTED])")
    }
}

// Closed source choice. Only Native exists in production and it retains the
// actual receive owner, actual lifetime and same audit certificate.
pub(super) enum ConsumedSource<'a> {
    #[cfg(target_os = "macos")]
    Native {
        original: &'a super::super::mach_exception::ReceiveRight,
        lifetime: &'a super::super::mach_exception::SelectedLifetime,
        certificate: &'a std::sync::Arc<super::CertifiedReceivedTaskAudit>,
    },
    #[cfg(test)]
    Fixture(std::sync::Arc<FixtureConsumedChecks>),
    #[cfg(not(any(test, target_os = "macos")))]
    Unavailable(std::marker::PhantomData<&'a ()>),
    #[cfg(all(test, not(target_os = "macos")))]
    Lifetime(std::marker::PhantomData<&'a ()>),
}
#[cfg(test)]
pub(super) struct FixtureConsumedChecks {
    class: super::AtomicBool,
    audit: super::AtomicBool,
    assignment: super::AtomicBool,
    calls: std::sync::atomic::AtomicUsize,
    panic: super::AtomicBool,
}
#[cfg(test)]
impl FixtureConsumedChecks {
    fn new() -> Self {
        Self {
            class: super::AtomicBool::new(true),
            audit: super::AtomicBool::new(true),
            assignment: super::AtomicBool::new(true),
            calls: std::sync::atomic::AtomicUsize::new(0),
            panic: super::AtomicBool::new(false),
        }
    }
}

// Distinct from SelectedFaultIoGuard. No method can turn consumed storage back
// into Original or reparse its modified header as attested received bytes.
struct ConsumedFaultIoGuard<'a> {
    source: ConsumedSource<'a>,
    storage: &'a super::Storage,
    audit: &'a AuditLease,
    preparation: &'a OriginalFaultPreparation,
    receive_name: u32,
    end: Instant,
}
impl ConsumedFaultIoGuard<'_> {
    fn current(&mut self, end: Instant) -> Result<(), Refusal> {
        let mut veto = super::PreparationVeto {
            evidence: &self.preparation.evidence,
            armed: true,
        };
        if end != self.end || !self.audit.active.load(Ordering::SeqCst) {
            return Err(Refusal::FaultPreparationOriginal);
        }
        let task_name = self.preparation.inputs.names[3];
        let task_kind = super::IPC_OTYPE_TASK_CONTROL;
        self.preparation.require_consumed(
            self.storage,
            task_name,
            task_kind,
            self.receive_name,
            end,
        )?;
        match &self.source {
            #[cfg(target_os = "macos")]
            ConsumedSource::Native {
                original,
                lifetime,
                certificate,
            } => {
                let mut consumed = super::OriginalReceivedTask {
                    original,
                    lifetime,
                    storage: self.storage,
                    phase: super::ReceivedTaskPhase::Consumed(self.preparation),
                    audit: self.audit,
                    certificate,
                    task_name,
                    task_kind,
                    receive_name: self.receive_name,
                    end: lifetime.end,
                };
                super::require_retained_fault(&mut consumed, self.preparation, end)?;
            }
            #[cfg(test)]
            ConsumedSource::Fixture(checks) => {
                checks.calls.fetch_add(1, Ordering::SeqCst);
                if checks.panic.load(Ordering::SeqCst) {
                    panic!("SCRIPTED_CONSUMED_GUARD_UNWIND");
                }
                match &self.preparation.evidence {
                    FaultEvidence::Fixture(proof)
                        if std::sync::Arc::ptr_eq(&proof.audit, &self.audit.active)
                            && !proof.revoked.load(Ordering::SeqCst)
                            && proof.actor.load(Ordering::SeqCst) => {}
                    _ => return Err(Refusal::ActorPeerComparison),
                }
                if !checks.class.load(Ordering::SeqCst) {
                    return Err(Refusal::FaultPreparationTaskClass);
                }
                if !checks.audit.load(Ordering::SeqCst) {
                    return Err(Refusal::TaskAuditOriginalContext);
                }
                if !checks.assignment.load(Ordering::SeqCst) {
                    return Err(Refusal::CurrentExceptionAssignment);
                }
            }
            #[cfg(not(any(test, target_os = "macos")))]
            ConsumedSource::Unavailable(_) => return Err(Refusal::FaultPreparationOriginal),
            #[cfg(all(test, not(target_os = "macos")))]
            ConsumedSource::Lifetime(_) => return Err(Refusal::FaultPreparationOriginal),
        }
        self.preparation.require_consumed(
            self.storage,
            task_name,
            task_kind,
            self.receive_name,
            end,
        )?;
        if !self.audit.active.load(Ordering::SeqCst) {
            return Err(Refusal::FaultPreparationOriginal);
        }
        veto.armed = false;
        Ok(())
    }
}

fn timeout_millis(left: Duration) -> Result<u32, ReplyRefusal> {
    // Floor, including a zero nonblocking send for a live sub-millisecond cap.
    // Reject overflow instead of truncating, clamping or minting another cap.
    u32::try_from(left.as_millis()).map_err(|_| ReplyRefusal::TimeoutRange)
}

fn returned_simple_reply(reply: &ReplyStorage) -> bool {
    let raw = &reply.0;
    // Only the current remote name may be rewritten (including NULL/DEAD).
    // No complex/local/voucher/extra disposition can reach public destruction.
    u32::from_le_bytes(raw[0..4].try_into().unwrap()) == MOVE_SEND_ONCE
        && u32::from_le_bytes(raw[4..8].try_into().unwrap()) == mach_wire::REPLY_BYTES as u32
        && raw[12..20] == [0; 8]
        && i32::from_le_bytes(raw[20..24].try_into().unwrap()) == 2505
        && raw[24..32] == [0, 0, 0, 0, 1, 0, 0, 0]
        && i32::from_le_bytes(raw[32..36].try_into().unwrap()) == KERN_FAILURE
}

pub(super) fn detach_components<'r, S: SessionDependency, R: ReplyKernel>(
    storage: &'r mut super::Storage,
    resources: &'r mut Resources,
    lifetime: &'r super::SessionLifetime<S>,
    receive_name: u32,
    audit: &'r AuditLease,
    preparation: &'r OriginalFaultPreparation,
    receipt: ValidReportReceipt<'r>,
    kernel: R,
    source: ConsumedSource<'r>,
) -> Result<ReplyOwner<'r, S, R>, ReplyRefusal> {
    if *resources != Resources::Received {
        return Err(ReplyRefusal::NotReceived);
    }
    if storage.1 != MessagePhase::Original {
        return Err(ReplyRefusal::AlreadyDetached);
    }
    if !std::ptr::eq(preparation, receipt.preparation) {
        return Err(ReplyRefusal::Context);
    }
    match (&preparation.evidence, &audit.evidence) {
        (FaultEvidence::Native { certificate, .. }, AuditEvidence::Native(actual))
            if std::sync::Arc::ptr_eq(certificate, actual) => {}
        #[cfg(test)]
        (FaultEvidence::Fixture(proof), AuditEvidence::Fixture)
            if std::sync::Arc::ptr_eq(&proof.audit, &audit.active) => {}
        _ => return Err(ReplyRefusal::Context),
    }
    let end = preparation.end;
    if !preparation.dispatch_consumed.load(Ordering::SeqCst) {
        return Err(ReplyRefusal::Context);
    }
    if end > lifetime.end || Instant::now() >= end {
        return Err(ReplyRefusal::Endpoint);
    }
    lifetime.current().map_err(|_| ReplyRefusal::Context)?;
    if !audit.active.load(Ordering::SeqCst) {
        return Err(ReplyRefusal::Context);
    }
    preparation
        .require_original(
            storage,
            preparation.inputs.names[3],
            super::IPC_OTYPE_TASK_CONTROL,
            receive_name,
            end,
        )
        .map_err(|_| ReplyRefusal::Context)?;
    let frame = super::actual_frame(storage).ok_or(ReplyRefusal::Frame)?;
    let parsed = mach_wire::decode_wide_raise(frame).map_err(ReplyRefusal::Wire)?;
    if parsed.names()[1] != receive_name {
        return Err(ReplyRefusal::ReceiveName);
    }
    // Allocate and finish every fallible operation BEFORE ownership mutation.
    // This is always the negative RPC code, never caller-chosen KERN_SUCCESS.
    let reply = Box::new(ReplyStorage(mach_wire::encode_wire_reply(
        parsed,
        KERN_FAILURE,
    )));
    lifetime.current().map_err(|_| ReplyRefusal::Context)?;
    if Instant::now() >= end {
        return Err(ReplyRefusal::Endpoint);
    }

    // Straight-line exclusive commit: primitive fixed-size stores only.
    let bits = u32::from_le_bytes(storage.0[0..4].try_into().unwrap());
    storage.1 = MessagePhase::ReplyDetached;
    storage.0[8..12].fill(0);
    storage.0[0..4].copy_from_slice(&(bits & !REMOTE_MASK).to_le_bytes());
    // Construct owner and distinct consumed observer without any fallible work
    // after ownership mutation. Its first validation failure retires unsent.
    Ok(ReplyOwner {
        storage,
        _resources: resources,
        lifetime,
        audit,
        preparation,
        guard: ConsumedFaultIoGuard {
            source,
            storage,
            audit,
            preparation,
            receive_name,
            end,
        },
        reply,
        kernel,
        end,
        state: ReplyState::OwnedUnsent,
    })
}

impl<S: SessionDependency, R: ReplyKernel> ReplyOwner<'_, S, R> {
    fn current(&mut self) -> Result<(), ReplyRefusal> {
        if self.end > self.lifetime.end || Instant::now() >= self.end {
            return Err(ReplyRefusal::Endpoint);
        }
        self.lifetime.current().map_err(|_| ReplyRefusal::Context)?;
        self.guard
            .current(self.end)
            .map_err(|_| ReplyRefusal::Context)?;
        self.lifetime.current().map_err(|_| ReplyRefusal::Context)?;
        if Instant::now() >= self.end {
            return Err(ReplyRefusal::Endpoint);
        }
        Ok(())
    }
    fn veto_original(&self) {
        self.audit.active.store(false, Ordering::SeqCst);
        if let AuditEvidence::Native(value) = &self.audit.evidence {
            value.binding.invalidate();
        }
        self.preparation.evidence.invalidate();
        self.lifetime.stop();
    }
    fn retire(&mut self) -> ReplyCleanup {
        self.veto_original();
        // Consume BEFORE void native cleanup. A cleanup panic cannot retry.
        match std::mem::replace(&mut self.state, ReplyState::Retired) {
            ReplyState::OwnedUnsent | ReplyState::ReturnedUnsent => {
                self.kernel.destroy_unsent(&mut self.reply);
                ReplyCleanup::DestroyInvokedCompletionUnqualified
            }
            ReplyState::InFlightUnknown | ReplyState::Unknown => {
                ReplyCleanup::UnknownNoSafeReplyCleanup
            }
            ReplyState::Transferred | ReplyState::Retired => ReplyCleanup::NotRequired,
        }
    }
    pub(super) fn send_failure(mut self) -> ReplyObservation {
        if let Err(stage) = self.current() {
            let cleanup = self.retire();
            return ReplyObservation {
                native_result: None,
                ownership: ReplyOwnership::NeverSent,
                cleanup,
                refusal: Some(stage),
            };
        }
        let timeout = match timeout_millis(self.end.saturating_duration_since(Instant::now())) {
            Ok(value) => value,
            Err(stage) => {
                let cleanup = self.retire();
                return ReplyObservation {
                    native_result: None,
                    ownership: ReplyOwnership::NeverSent,
                    cleanup,
                    refusal: Some(stage),
                };
            }
        };
        if Instant::now() >= self.end {
            let cleanup = self.retire();
            return ReplyObservation {
                native_result: None,
                ownership: ReplyOwnership::NeverSent,
                cleanup,
                refusal: Some(ReplyRefusal::Endpoint),
            };
        }
        // No second send is possible: exclusive self is consumed, and an
        // unwind inside the call leaves UNKNOWN, never a stale-name destructor.
        self.state = ReplyState::InFlightUnknown;
        let result = self.kernel.send(&mut self.reply, SEND_OPTIONS, timeout);
        // Native ownership classification MUST precede any fallible postcheck.
        let (ownership, mut refusal) = match result {
            0 => {
                self.state = ReplyState::Transferred;
                (ReplyOwnership::TransferredDeliveryUnqualified, None)
            }
            INVALID_DEST | TIMED_OUT | INTERRUPTED => {
                if returned_simple_reply(&self.reply) {
                    self.state = ReplyState::ReturnedUnsent;
                    (ReplyOwnership::ReturnedUnsent, None)
                } else {
                    self.state = ReplyState::Unknown;
                    (ReplyOwnership::Unknown, Some(ReplyRefusal::ReturnedShape))
                }
            }
            _ => {
                self.state = ReplyState::Unknown;
                (ReplyOwnership::Unknown, None)
            }
        };
        // A success transfers the right even if the original session expires,
        // fails or unwinds here. Never reverse ownership from that observation.
        // Known native failures proceed directly to veto/cleanup, no extra I/O.
        if result == 0 {
            refusal = self.current().err();
        }
        let cleanup = self.retire();
        ReplyObservation {
            native_result: Some(result),
            ownership,
            cleanup,
            refusal,
        }
    }
}
impl<S: SessionDependency, R: ReplyKernel> Drop for ReplyOwner<'_, S, R> {
    fn drop(&mut self) {
        if self.retire() == ReplyCleanup::UnknownNoSafeReplyCleanup {
            eprintln!("SUPERVISOR_SELECTED_REPLY_OWNERSHIP_UNKNOWN");
        }
    }
}

#[cfg(target_os = "macos")]
pub(super) struct NativeReply;
#[cfg(target_os = "macos")]
impl ReplyKernel for NativeReply {
    fn send(&mut self, reply: &mut ReplyStorage, options: i32, timeout_ms: u32) -> i32 {
        unsafe {
            super::ffi::mach_msg(
                reply.0.as_mut_ptr().cast(),
                options,
                mach_wire::REPLY_BYTES as u32,
                0,
                0,
                timeout_ms,
                0,
            )
        }
    }
    fn destroy_unsent(&mut self, reply: &mut ReplyStorage) {
        unsafe {
            super::ffi::mach_msg_destroy(reply.0.as_mut_ptr().cast());
        }
    }
}

#[cfg(test)]
#[path = "selected_mach_reply_tests.rs"]
mod tests;
