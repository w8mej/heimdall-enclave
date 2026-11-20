//! Selected-only native receive/resource adapter with terminal failure-only reply.
//!
//! Receive options/results bind the retained SDK27.2/MIG layout and public
//! XNU/libsyscall f6217f8 result-to-resource matrix in agent1/mach-result-ownership.
//! Those sources do not qualify installed-kernel ownership or cleanup behavior.
//! The original native receive right stays borrowed; parsed names/audit never
//! become owned rights, custody identity/assignment, classifier or forwarding
//! authority. Successful exact frames get negative-only kernel-trailer and
//! local object-class checks, an actual task audit read, original actor-peer
//! comparison and supported current-assignment readback. A single guarded
//! fault report may reach the fixed auditor through the actual shared tracker.
//! Every delivered message still terminates/refuses; startup is unavailable.
//! Fault preparation retains the actual original actor match, raw fault inputs
//! and its immutable earlier endpoint; it is never a forwarding permit.
//! The already-retained permanent startup SH owner is freshly observed around
//! receive progress and after actor/CONTROL readback; it is never acquired here.

use super::{mach_wire, readiness::{SessionDependency, SessionLifetime}};
use std::{fmt, sync::{Arc, atomic::{AtomicBool, Ordering}}, time::{Duration, Instant}};
use crate::{error::EnclaveResult, err};

const RCV_MSG: i32 = 0x0000_0002;
const RCV_TIMEOUT: i32 = 0x0000_0100;
const RCV_INTERRUPT: i32 = 0x0000_0400;
const AUDIT_TRAILER: i32 = 3 << 24; // FORMAT_0=0; ELEMENTS(AUDIT=3).
const OPTIONS: i32 = RCV_MSG | RCV_TIMEOUT | RCV_INTERRUPT | AUDIT_TRAILER;
const SHORTAGE_MASK: i32 = 0x0000_3e00;
const KNOWN_SHORTAGES: i32 = 0x0000_3c00;
const TIMED_OUT: i32 = 0x1000_4003;
const TOO_LARGE: i32 = 0x1000_4004;
const INTERRUPTED: i32 = 0x1000_4005;
const INVALID_DATA: i32 = 0x1000_4008;
const HEADER_ERROR: i32 = 0x1000_400b;
const BODY_ERROR: i32 = 0x1000_400c;
const POLL: Duration = Duration::from_millis(500);

// Public ABI, NOT internal IKOT values. Pinned f6217f8
// mach_debug/ipc_info.h:90-136; mach_debug.c:446 maps IKOT to IPC_OTYPE.
// Installed SDK/native behavior remains a coordinator acceptance prerequisite.
const IPC_OTYPE_TASK_CONTROL: u32 = 2;
const IPC_OTYPE_TASK_READ: u32 = 45;
const IPC_OTYPE_THREAD_CONTROL: u32 = 1;
const IPC_OTYPE_THREAD_READ: u32 = 47;
// Public message.h:878-882 initializers, compared as WHOLE opaque values.
// Narrow codec supports little-endian only. No token fields are interpreted.
const KERNEL_SECURITY_TOKEN: [u8; 8] = [0, 0, 0, 0, 1, 0, 0, 0];
const KERNEL_AUDIT_TOKEN: [u8; 32] = [0; 32];
const TASK_AUDIT_TOKEN: i32 = 15;
const TASK_AUDIT_TOKEN_COUNT: u32 = 8;

// Stable fixed storage; no user-size growth, reuse, packed reference or raw
// pointer escapes. Native rcv_size is136, excluding the alignment tail padding.
#[repr(C, align(16))]
struct Storage([u8; mach_wire::FRAME_BYTES], MessagePhase);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MessagePhase { Original, ReplyDetached }
impl Storage {
    fn fresh() -> Box<Self> { Box::new(Self([0; mach_wire::FRAME_BYTES], MessagePhase::Original)) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Refusal {
    BeforeReceive, BeforeReceiveStartupLease, PostReceiveContext, PostReceiveStartupLease,
    AfterActorAndAssignmentStartupLease, Interrupted, HeaderError, TooLarge,
    PartialBody, InvalidData, UnknownNativeResult, InvalidNativeExtent,
    FrameExtent, Wire(mach_wire::WireError), ReceiveName,
    KernelTrailer, BeforeTaskObjectQuery, AfterTaskObjectQuery,
    TaskObjectQuery(i32), TaskObjectType,
    BeforeThreadObjectQuery, AfterThreadObjectQuery,
    ThreadObjectQuery(i32), ThreadObjectType,
    BeforeTaskAudit, AfterTaskAudit, TaskAuditRead(i32), TaskAuditCount,
    TaskAuditOriginalContext, BeforeActorAndAssignment, AfterActorAndAssignment,
    ActorPeerComparison, CurrentExceptionAssignment,
    FaultPreparationTaskClass, FaultPreparationFrame, FaultPreparationException,
    FaultPreparationEndpoint, FaultPreparationOriginal,
    BeforeFaultPreparationValidation, AfterFaultPreparationValidation,
    FaultDispatchUnavailable, NativeReplyAndStartupCompositionUnavailable,
    RemainingFaultAndStartupCompositionUnavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cleanup {
    NotRequired,
    NativeDestroyInvokedCompletionUnqualified,
    UnknownNoSafeDescribedResourceCleanup,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    TimeoutProgress,
    Refused { stage: Refusal, native_result: Option<i32>, cleanup: Cleanup },
}
impl Outcome {
    pub(super) fn native_result(self) -> Option<i32> {
        match self { Self::TimeoutProgress => None, Self::Refused { native_result, .. } => native_result }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Resources { None, Received, Unknown }

// Passive snapshot only: this neither owns nor exposes the received task right.
// Its sole production constructor is the fixed Native audit read below. The
// nonClone AuditLease stays inside the ORIGINAL whole-message Attempt and
// invalidates all queued Arc snapshots before terminal message destruction.
// No Clone/Debug/serde/raw getter or constructor is exposed.
pub(crate) struct CertifiedReceivedTaskAudit {
    binding: AuditBinding<Arc<crate::power::selected_owner_session::SelectedOwnerSession>>,
}
struct AuditBinding<S: SessionDependency> {
    audit: [u32; 8], session: S, end: Instant, active: Arc<AtomicBool>,
}
struct AuditCheck<'a, S: SessionDependency> { binding: &'a AuditBinding<S>, armed: bool }
impl<S: SessionDependency> Drop for AuditCheck<'_, S> {
    fn drop(&mut self) { if self.armed { self.binding.invalidate(); } }
}
impl<S: SessionDependency> AuditBinding<S> {
    fn invalidate(&self) {
        self.active.store(false, Ordering::SeqCst);
        self.session.revoke();
    }
    fn checked(&self, end: Instant, operation: impl FnOnce() -> EnclaveResult<()>) -> EnclaveResult<()> {
        let mut guard = AuditCheck { binding: self, armed: true };
        let result = (|| {
            if !self.active.load(Ordering::SeqCst) || end > self.end
                || self.end > self.session.original_end() || Instant::now() >= end {
                return Err(err!(EACCES, "SUPERVISOR_RECEIVED_TASK_AUDIT_INACTIVE"));
            }
            self.session.current()?;
            operation()?;
            self.session.current()?;
            if !self.active.load(Ordering::SeqCst) || Instant::now() >= end {
                return Err(err!(EACCES, "SUPERVISOR_RECEIVED_TASK_AUDIT_INACTIVE"));
            }
            Ok(())
        })();
        if result.is_ok() { guard.armed = false; }
        result
    }
    fn matches_peer(&self, peer: &crate::ipc::PeerCredentials) -> EnclaveResult<()> {
        self.checked(self.end, || {
            if peer.uid != crate::daemon::DaemonId::CustodyVault.uid()
                || peer.audit_token.as_ref() != Some(&self.audit)
                || peer.code_identity.is_none() || peer.tls_channel_binding.is_some() {
                return Err(err!(EACCES, "SUPERVISOR_RECEIVED_TASK_AUDIT_PEER"));
            }
            Ok(())
        })
    }
}
impl CertifiedReceivedTaskAudit {
    pub(crate) fn require_same_session(&self,
        session: &Arc<crate::power::selected_owner_session::SelectedOwnerSession>,
        end: Instant) -> EnclaveResult<()> {
        self.binding.checked(end, || {
            if !Arc::ptr_eq(session, &self.binding.session) {
                return Err(err!(EACCES, "SUPERVISOR_RECEIVED_TASK_AUDIT_SESSION"));
            }
            Ok(())
        })
    }
    // Only the original channel actor supplies its privately retained, freshly
    // authenticated peer. Success is opaque equality only, never Ready or an
    // exception assignment capability. Native audit must be re-read around any
    // future actor wait by the STILL OWNED original message/task-right guard.
    pub(crate) fn matches_original_peer(&self, peer: &crate::ipc::PeerCredentials) -> EnclaveResult<()> {
        self.binding.matches_peer(peer)
    }
    pub(crate) fn original_instant_end(&self) -> Instant { self.binding.end }
}
enum AuditEvidence {
    Native(Arc<CertifiedReceivedTaskAudit>),
    #[cfg(test)] Fixture,
}
struct AuditLease { active: Arc<AtomicBool>, evidence: AuditEvidence }
impl Drop for AuditLease {
    fn drop(&mut self) {
        // This happens BEFORE original session revocation/native message
        // destruction, including failed postchecks and caught unwind.
        self.active.store(false, Ordering::SeqCst);
        if let AuditEvidence::Native(snapshot) = &self.evidence { snapshot.binding.invalidate(); }
    }
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum AuditReadFailure { Native(i32), Count, OriginalContext }
impl AuditReadFailure {
    fn refusal(self) -> Refusal {
        match self { Self::Native(code) => Refusal::TaskAuditRead(code),
            Self::Count => Refusal::TaskAuditCount, Self::OriginalContext => Refusal::TaskAuditOriginalContext }
    }
}

// No Clone/Debug/serde/public constructor or report conversion. Raw wire data
// alone has no authority; the actual Native variant retains the SAME original
// actor match and certificate while Attempt still owns the whole message.
enum FaultEvidence {
    Native {
        certificate: Arc<CertifiedReceivedTaskAudit>,
        #[cfg(target_os = "macos")]
        actor: crate::power::selected_owner_listener::OriginalCustodyActorMatch,
    },
    #[cfg(test)]
    Fixture(FixtureFaultEvidence),
}
impl FaultEvidence {
    fn invalidate(&self) {
        match self {
            Self::Native { certificate, .. } => certificate.binding.invalidate(),
            #[cfg(test)]
            Self::Fixture(proof) => {
                proof.revoked.store(true, Ordering::SeqCst);
                proof.audit.store(false, Ordering::SeqCst);
            },
        }
    }
    fn original_actor_end(&self) -> Result<Instant, Refusal> {
        match self {
            #[cfg(target_os = "macos")]
            Self::Native { actor, .. } => Ok(actor.original_instant_end()),
            #[cfg(not(target_os = "macos"))]
            Self::Native { .. } => Err(Refusal::FaultPreparationOriginal),
            #[cfg(test)]
            Self::Fixture(proof) => Ok(proof.end),
        }
    }
}
struct PreparationVeto<'a> { evidence: &'a FaultEvidence, armed: bool }
impl Drop for PreparationVeto<'_> {
    fn drop(&mut self) { if self.armed { self.evidence.invalidate(); } }
}
#[cfg(test)]
struct FixtureFaultEvidence {
    end: Instant, audit: Arc<AtomicBool>, actor: Arc<AtomicBool>,
    revoked: Arc<AtomicBool>, dropped: Arc<AtomicBool>, armed: bool,
}
#[cfg(test)]
impl Drop for FixtureFaultEvidence {
    fn drop(&mut self) {
        if self.armed {
            assert!(self.revoked.load(Ordering::SeqCst),
                "same session veto must precede dropping returned fault preparation");
        }
        self.dropped.store(true, Ordering::SeqCst);
    }
}
#[derive(PartialEq, Eq)]
struct FaultInputs { names: [u32; 4], exception: i32, codes: [i64; 2] }
impl FaultInputs {
    fn read(storage: &Storage) -> Result<Self, Refusal> {
        let frame = actual_frame(storage).ok_or(Refusal::FaultPreparationFrame)?;
        let parsed = mach_wire::decode_wide_raise(frame)
            .map_err(|_| Refusal::FaultPreparationFrame)?;
        if parsed.security_token_bytes() != &KERNEL_SECURITY_TOKEN
            || parsed.audit().bytes() != &KERNEL_AUDIT_TOKEN {
            return Err(Refusal::FaultPreparationFrame);
        }
        Ok(Self { names: parsed.names(), exception: parsed.exception(), codes: parsed.codes() })
    }
}
struct OriginalFaultPreparation {
    evidence: FaultEvidence, inputs: FaultInputs, snapshot: [u8; mach_wire::FRAME_BYTES],
    session_end: Instant, end: Instant,
    kind: crate::quarantine_types::FaultKind, address: u64,
    dispatch_consumed: AtomicBool,
}
impl OriginalFaultPreparation {
    fn from_original(storage: &Storage, task_name: u32, task_kind: u32,
        receive_name: u32, session_end: Instant, evidence: FaultEvidence)
        -> Result<Self, Refusal> {
        // Constructor failure/unwind vetoes the same original certificate
        // BEFORE its just-returned actor match can be dropped.
        let mut veto = PreparationVeto { evidence: &evidence, armed: true };
        if task_kind != IPC_OTYPE_TASK_CONTROL { return Err(Refusal::FaultPreparationTaskClass); }
        let end = session_end.min(evidence.original_actor_end()?);
        if Instant::now() >= end { return Err(Refusal::FaultPreparationEndpoint); }
        let inputs = FaultInputs::read(storage)?;
        if inputs.names[1] != receive_name || inputs.names[3] != task_name {
            return Err(Refusal::FaultPreparationOriginal);
        }
        // Same three exception families as the actual selected assignment.
        // Keep existing conservative subtype policy; invent no new PAC/guard meaning.
        if !matches!(inputs.exception, 1 | 2 | 12) {
            return Err(Refusal::FaultPreparationException);
        }
        let (kind, address) = super::classify_mach_exception(
            inputs.exception, inputs.codes[0], inputs.codes[1]);
        veto.armed = false;
        drop(veto);
        Ok(Self { evidence, inputs, snapshot: storage.0, session_end, end, kind, address,
            dispatch_consumed: AtomicBool::new(false) })
    }
    fn require_endpoint(&self, end: Instant) -> Result<(), Refusal> {
        // A later session cap cannot silently replace the original actor cap.
        if end != self.end || self.end != self.session_end.min(self.evidence.original_actor_end()?)
            || Instant::now() >= self.end {
            return Err(Refusal::FaultPreparationEndpoint);
        }
        Ok(())
    }
    fn require_original(&self, storage: &Storage, task_name: u32, task_kind: u32,
        receive_name: u32, end: Instant) -> Result<(), Refusal> {
        self.require_endpoint(end)?;
        if task_kind != IPC_OTYPE_TASK_CONTROL { return Err(Refusal::FaultPreparationTaskClass); }
        if storage.0 != self.snapshot { return Err(Refusal::FaultPreparationOriginal); }
        let inputs = FaultInputs::read(storage)?;
        let classified = super::classify_mach_exception(inputs.exception, inputs.codes[0], inputs.codes[1]);
        if inputs != self.inputs || inputs.names[1] != receive_name || inputs.names[3] != task_name
            || classified != (self.kind, self.address) {
            return Err(Refusal::FaultPreparationOriginal);
        }
        Ok(())
    }
    fn require_consumed(&self, storage: &Storage, task_name: u32, task_kind: u32,
        receive_name: u32, end: Instant) -> Result<(), Refusal> {
        self.require_endpoint(end)?;
        if storage.1 != MessagePhase::ReplyDetached || task_kind != IPC_OTYPE_TASK_CONTROL
            || self.inputs.names[1] != receive_name || self.inputs.names[3] != task_name
            || !self.dispatch_consumed.load(Ordering::SeqCst) {
            return Err(Refusal::FaultPreparationOriginal);
        }
        // Exact original snapshot, normalized in-place for comparison only.
        // No decoding of the changed frame as a new received Original.
        let bits = u32::from_le_bytes(self.snapshot[0..4].try_into().unwrap()) & !0x1f;
        if storage.0[0..4] != bits.to_le_bytes() || storage.0[8..12] != [0; 4]
            || storage.0[4..8] != self.snapshot[4..8]
            || storage.0[12..] != self.snapshot[12..]
            || super::classify_mach_exception(self.inputs.exception,
                self.inputs.codes[0], self.inputs.codes[1]) != (self.kind, self.address) {
            return Err(Refusal::FaultPreparationOriginal);
        }
        Ok(())
    }
}

// Private, nonClone, non-serializable receipt. It is neither a startup permit
// nor authority for a positive RPC. Only the completed dispatch engine mints it.
struct ValidReportReceipt<'a> {
    preparation: &'a OriginalFaultPreparation,
    response: crate::quarantine_types::Response,
}

// Independent terminal owner remains armed during original-guard teardown,
// exclusive detach, consumed revalidation, native send and reply cleanup.
struct OriginalTerminalVeto<'a, S: SessionDependency> {
    lifetime: &'a SessionLifetime<S>, audit: &'a AuditLease,
    preparation: &'a OriginalFaultPreparation,
}
impl<S: SessionDependency> Drop for OriginalTerminalVeto<'_, S> {
    fn drop(&mut self) {
        self.audit.active.store(false, Ordering::SeqCst);
        if let AuditEvidence::Native(value) = &self.audit.evidence { value.binding.invalidate(); }
        self.preparation.evidence.invalidate();
        self.lifetime.stop();
    }
}

// Fixed native task_info output contract, shared with private software tests.
// A failed RPC's buffer/count is never treated as partially certified output.
fn checked_audit_output(result:i32, count:u32, audit:[u32;8])
    -> Result<[u32;8],AuditReadFailure> {
    if result != 0 { return Err(AuditReadFailure::Native(result)); }
    if count != TASK_AUDIT_TOKEN_COUNT { return Err(AuditReadFailure::Count); }
    Ok(audit)
}

// Private software seam. Production always constructs the fixed Native below,
// which borrows the actual check-in-owned ReceiveRight; no provider is accepted.
trait Kernel {
    // Observe ONLY the already-retained original startup SH owner. Native fixes
    // this to the actual process owner API; no late acquisition or provider.
    fn retained_startup_current(&mut self, end: Instant) -> EnclaveResult<()>;
    fn receive(&mut self, storage: &mut Storage, options: i32, timeout_ms: u32) -> i32;
    // Production sends ONLY to known mach_task_self_; name is a local-space
    // lookup argument. Never send an RPC to an unclassified descriptor name.
    // No address, raw token, resource extraction or task_info result escapes.
    fn object_type_in_self(&mut self, name: u32) -> Result<u32, i32>;
    // Called ONLY after original whole native-message ownership, exact full
    // kernel trailer and both local object classes were checked. The private
    // production implementation queries the SAME classified task descriptor.
    fn task_audit_of_classified_original(&mut self, name: u32, end: Instant)
        -> Result<AuditLease, AuditReadFailure>;
    // Same original storage/task/audit lease remain borrowed across the actual
    // actor wait and assignment readback. Production has no supplied callback.
    fn actor_and_assignment_of_original(&mut self, storage:&Storage, task_name:u32,
        task_kind:u32, end:Instant, audit:&AuditLease) -> Result<OriginalFaultPreparation,Refusal>;
    // Recheck the SAME retained proof and actual task/assignment after the
    // final startup observation. Never compare a replacement actor or renew.
    fn validate_fault_preparation_of_original(&mut self, storage:&Storage,
        task_name:u32, task_kind:u32, end:Instant, audit:&AuditLease,
        preparation:&OriginalFaultPreparation) -> Result<(),Refusal>;
    // Fixed production dispatch, not a supplied provider. The same original
    // whole message/audit/preparation remain owned until this terminal returns.
    fn dispatch_fault_of_original(&mut self, storage:&mut Storage, resources:&mut Resources,
        task_name:u32, task_kind:u32, end:Instant, audit:&AuditLease,
        preparation:&OriginalFaultPreparation) -> Result<crate::quarantine_types::Response,Refusal>;
    fn destroy_received(&mut self, storage: &mut Storage);
}

struct Attempt<'a, K: Kernel, S: SessionDependency> {
    kernel: K,
    lifetime: &'a SessionLifetime<S>,
    receive_name: u32,
    storage: Box<Storage>,
    resources: Resources,
    terminal: bool,
    audit: Option<AuditLease>,
    preparation: Option<OriginalFaultPreparation>,
}
impl<K: Kernel, S: SessionDependency> fmt::Debug for Attempt<'_, K, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SelectedMachAttempt([ORIGINAL NATIVE RESOURCES; REDACTED])")
    }
}

fn native_body_end(storage: &Storage) -> Option<usize> {
    let size = u32::from_le_bytes(storage.0[4..8].try_into().ok()?) as usize;
    // A complete native body must fit alongside the requested full audit trailer.
    // An impossible successful-native extent is uncertainty, never a reason to
    // walk an out-of-bounds destruction layout or invent resource names.
    if !(24..=mach_wire::REQUEST_BYTES).contains(&size) { return None; }
    let rounded = size.checked_add(3)? & !3;
    if rounded.checked_add(mach_wire::AUDIT_TRAILER_BYTES)? > storage.0.len() { return None; }
    Some(rounded)
}
fn actual_frame(storage: &Storage) -> Option<&[u8]> {
    // Detaching the actual remote send-once right irreversibly consumes this
    // frame's ORIGINAL phase. Neither native guard nor preparation may pretend
    // the rewritten ownership header is the immutable attested original.
    if storage.1 != MessagePhase::Original { return None; }
    let body_end = native_body_end(storage)?;
    let trailer_size = u32::from_le_bytes(storage.0.get(body_end + 4..body_end + 8)?.try_into().ok()?) as usize;
    if trailer_size < 8 { return None; }
    let end = body_end.checked_add(trailer_size)?;
    storage.0.get(..end)
}

impl<'a, K: Kernel, S: SessionDependency> Attempt<'a, K, S> {
    fn new(kernel: K, lifetime: &'a SessionLifetime<S>, receive_name: u32) -> Self {
        Self { kernel, lifetime, receive_name, storage: Storage::fresh(),
            resources: Resources::None, terminal: true, audit: None, preparation: None }
    }
    fn finish(&mut self) -> Cleanup {
        // Every terminal return/unwind revokes the SAME original session before
        // any native cleanup can block. Timeout-only progress is the exception.
        // A passive actor snapshot must become terminal before the original
        // task right can be destroyed. Keep this order even during unwind.
        drop(self.audit.take());
        if self.terminal { self.lifetime.stop(); }
        drop(self.preparation.take());
        match std::mem::replace(&mut self.resources, Resources::None) {
            Resources::None => Cleanup::NotRequired,
            Resources::Unknown => Cleanup::UnknownNoSafeDescribedResourceCleanup,
            Resources::Received => {
                if native_body_end(&self.storage).is_none() {
                    return Cleanup::UnknownNoSafeDescribedResourceCleanup;
                }
                // Consumption precedes the void native call. Never manually
                // deallocate parsed descriptors/reply or invoke cleanup twice.
                self.kernel.destroy_received(&mut self.storage);
                Cleanup::NativeDestroyInvokedCompletionUnqualified
            }
        }
    }
    fn refused(&mut self, stage: Refusal, native_result: Option<i32>) -> Outcome {
        let cleanup = self.finish();
        Outcome::Refused { stage, native_result, cleanup }
    }
    fn startup_current(&mut self, end: Instant) -> EnclaveResult<()> {
        if end > self.lifetime.end || Instant::now() >= end {
            return Err(err!(ETIMEDOUT, "SUPERVISOR_MACH_STARTUP_ORIGINAL_ENDPOINT"));
        }
        self.kernel.retained_startup_current(end)?;
        // The observer can block in filesystem/kernel work. Its return never
        // renews the SAME original session/stop/end or admits late progress.
        self.lifetime.current()?;
        if Instant::now() >= end {
            return Err(err!(ETIMEDOUT, "SUPERVISOR_MACH_STARTUP_ORIGINAL_ENDPOINT"));
        }
        Ok(())
    }
    fn run(mut self) -> Outcome {
        if self.lifetime.current().is_err() { return self.refused(Refusal::BeforeReceive, None); }
        if self.startup_current(self.lifetime.end).is_err() {
            return self.refused(Refusal::BeforeReceiveStartupLease, None);
        }
        let left = self.lifetime.end.saturating_duration_since(Instant::now()).min(POLL);
        let millis = left.as_millis(); // Floor: never round a short endpoint up.
        if millis == 0 { return self.refused(Refusal::BeforeReceive, None); }
        let result = self.kernel.receive(&mut self.storage, OPTIONS, millis as u32);
        // Classify actual transferred-resource ownership BEFORE endpoint, extent
        // or codec checks. BODY_ERROR may carry any known shortage-mask bits.
        let family = result & !SHORTAGE_MASK;
        let supported_flags = result & SHORTAGE_MASK & !KNOWN_SHORTAGES == 0;
        let body_error = supported_flags && family == BODY_ERROR;
        let header_error = supported_flags && family == HEADER_ERROR;
        self.resources = if result == 0 || body_error { Resources::Received }
            else if result == INVALID_DATA { Resources::Unknown }
            else if result == TIMED_OUT || result == INTERRUPTED || result == TOO_LARGE || header_error {
                Resources::None
            } else { Resources::Unknown };
        if self.lifetime.current().is_err() {
            return self.refused(Refusal::PostReceiveContext, Some(result));
        }
        // Only a complete receive or timeout can otherwise advance this
        // selected attempt. Native error paths already terminate: do not delay
        // their veto with extra dependency I/O. Ownership was classified first.
        if (result == 0 || result == TIMED_OUT) && self.startup_current(self.lifetime.end).is_err() {
            return self.refused(Refusal::PostReceiveStartupLease, Some(result));
        }
        if result == TIMED_OUT {
            self.terminal = false;
            return Outcome::TimeoutProgress;
        }
        if body_error { return self.refused(Refusal::PartialBody, Some(result)); }
        if header_error { return self.refused(Refusal::HeaderError, Some(result)); }
        if result == TOO_LARGE { return self.refused(Refusal::TooLarge, Some(result)); }
        if result == INTERRUPTED { return self.refused(Refusal::Interrupted, Some(result)); }
        if result == INVALID_DATA { return self.refused(Refusal::InvalidData, Some(result)); }
        if result != 0 { return self.refused(Refusal::UnknownNativeResult, Some(result)); }
        if native_body_end(&self.storage).is_none() {
            return self.refused(Refusal::InvalidNativeExtent, Some(result));
        }
        let Some(frame) = actual_frame(&self.storage) else {
            return self.refused(Refusal::FrameExtent, Some(result));
        };
        let parsed = match mach_wire::decode_wide_raise(frame) {
            Ok(parsed) => parsed,
            Err(error) => return self.refused(Refusal::Wire(error), Some(result)),
        };
        if parsed.names()[1] != self.receive_name {
            return self.refused(Refusal::ReceiveName, Some(result));
        }
        // Only actual complete SUCCESS + exact bounded frame reaches this
        // comparison. A zeroed unused tail, user body, BODY_ERROR or synthetic
        // parse alone is never kernel-origin authority. Kernel exception sends
        // carry the kernel token, NOT the faulting custody task's audit token.
        if parsed.security_token_bytes() != &KERNEL_SECURITY_TOKEN
            || parsed.audit().bytes() != &KERNEL_AUDIT_TOKEN {
            return self.refused(Refusal::KernelTrailer, Some(result));
        }
        let [_, _, thread_name, task_name] = parsed.names();
        drop(parsed);
        // Whole received native-message resources stay owned across EVERY
        // check/call/unwind. A failed pre/postcheck revokes this SAME session
        // before once-only destruction; no name/right is replaced or rearmed.
        if self.lifetime.current().is_err() {
            return self.refused(Refusal::BeforeTaskObjectQuery, Some(result));
        }
        let task_type = self.kernel.object_type_in_self(task_name);
        if self.lifetime.current().is_err() {
            return self.refused(Refusal::AfterTaskObjectQuery, Some(result));
        }
        let task_kind = match task_type {
            Ok(kind @ (IPC_OTYPE_TASK_CONTROL | IPC_OTYPE_TASK_READ)) => kind,
            Ok(_) => return self.refused(Refusal::TaskObjectType, Some(result)),
            Err(code) => return self.refused(Refusal::TaskObjectQuery(code), Some(result)),
        };
        if self.lifetime.current().is_err() {
            return self.refused(Refusal::BeforeThreadObjectQuery, Some(result));
        }
        let thread_type = self.kernel.object_type_in_self(thread_name);
        if self.lifetime.current().is_err() {
            return self.refused(Refusal::AfterThreadObjectQuery, Some(result));
        }
        match thread_type {
            Ok(IPC_OTYPE_THREAD_CONTROL | IPC_OTYPE_THREAD_READ) => {},
            Ok(_) => return self.refused(Refusal::ThreadObjectType, Some(result)),
            Err(code) => return self.refused(Refusal::ThreadObjectQuery(code), Some(result)),
        }
        if self.lifetime.current().is_err() {
            return self.refused(Refusal::BeforeTaskAudit, Some(result));
        }
        let read = self.kernel.task_audit_of_classified_original(task_name, self.lifetime.end);
        // Retain the returned original lease BEFORE any fallible postcheck.
        // On error there is no produced snapshot; context is still rechecked.
        match read {
            Ok(audit) => self.audit = Some(audit),
            Err(error) => {
                if self.lifetime.current().is_err() {
                    return self.refused(Refusal::AfterTaskAudit, Some(result));
                }
                return self.refused(error.refusal(), Some(result));
            },
        }
        if self.lifetime.current().is_err() {
            return self.refused(Refusal::AfterTaskAudit, Some(result));
        }
        if self.lifetime.current().is_err() {
            return self.refused(Refusal::BeforeActorAndAssignment, Some(result));
        }
        let prepared = self.kernel.actor_and_assignment_of_original(&self.storage,
            task_name, task_kind, self.lifetime.end, self.audit.as_ref().unwrap());
        // Retain the just-produced SAME proof before a postcheck can fail or
        // unwind. Its actor endpoint is immutable and may be much earlier.
        let preparation_error = match prepared {
            Ok(preparation) => { self.preparation = Some(preparation); None },
            Err(stage) => Some(stage),
        };
        if self.lifetime.current().is_err() {
            return self.refused(Refusal::AfterActorAndAssignment, Some(result));
        }
        if let Some(stage) = preparation_error { return self.refused(stage, Some(result)); }
        let preparation_end = self.preparation.as_ref().unwrap().end;
        if let Err(stage) = self.preparation.as_ref().unwrap().require_endpoint(preparation_end) {
            return self.refused(stage, Some(result));
        }
        // Keep the original whole-message/audit ownership through this final
        // actual startup-owner observation, including error and caught unwind.
        if self.startup_current(preparation_end).is_err() {
            return self.refused(Refusal::AfterActorAndAssignmentStartupLease, Some(result));
        }
        if self.lifetime.current().is_err() {
            return self.refused(Refusal::BeforeFaultPreparationValidation, Some(result));
        }
        let checked = self.kernel.validate_fault_preparation_of_original(&self.storage,
            task_name, task_kind, preparation_end, self.audit.as_ref().unwrap(),
            self.preparation.as_ref().unwrap());
        if self.lifetime.current().is_err() {
            return self.refused(Refusal::AfterFaultPreparationValidation, Some(result));
        }
        if let Err(stage) = checked { return self.refused(stage, Some(result)); }
        if let Err(stage) = self.preparation.as_ref().unwrap().require_endpoint(preparation_end) {
            return self.refused(stage, Some(result));
        }
        let dispatched = self.kernel.dispatch_fault_of_original(&mut self.storage, &mut self.resources,
            task_name, task_kind, preparation_end, self.audit.as_ref().unwrap(),
            self.preparation.as_ref().unwrap());
        // Native dispatch may consume a valid report receipt into exactly one
        // failure-only reply. Every outcome still retires this same session;
        // no startup/Ready/PF/Begin authority follows from reply transfer.
        self.refused(match dispatched {
            Ok(_) => Refusal::NativeReplyAndStartupCompositionUnavailable,
            Err(stage) => stage,
        }, Some(result))
    }
}
impl<K: Kernel, S: SessionDependency> Drop for Attempt<'_, K, S> {
    fn drop(&mut self) {
        if self.finish() == Cleanup::UnknownNoSafeDescribedResourceCleanup {
            eprintln!("SUPERVISOR_SELECTED_MACH_CLEANUP_UNKNOWN");
        }
    }
}

#[cfg(target_os = "macos")]
struct Native<'a> {
    _original: &'a super::mach_exception::ReceiveRight, name: u32,
    tracker: &'a super::RespawnTracker, socket_root: &'a std::path::Path,
}

// A child assignment adapter can inspect these private fields, but cannot
// construct this view outside this module. Borrowing immutable original storage
// prevents its mach_msg_destroy(&mut Storage), and borrowing the nonClone audit
// lease keeps its passive certificate live throughout actor/readback waits.
// This view never owns, clones, upgrades or exports any Mach right.
#[cfg(target_os = "macos")]
pub(super) struct OriginalReceivedTask<'a> {
    original: &'a super::mach_exception::ReceiveRight,
    lifetime: &'a super::mach_exception::SelectedLifetime,
    storage: &'a Storage,
    phase: ReceivedTaskPhase<'a>,
    audit: &'a AuditLease,
    certificate: &'a Arc<CertifiedReceivedTaskAudit>,
    task_name:u32, task_kind:u32, receive_name:u32, end:Instant,
}

// Original is used only before detach. Consumed is privately constructed
// from the exact same retained preparation after the exclusive header commit.
#[cfg(target_os = "macos")]
enum ReceivedTaskPhase<'a> { Original, Consumed(&'a OriginalFaultPreparation) }

#[cfg(target_os = "macos")]
fn native_object_type(name:u32)->Result<u32,i32> {
    let mut kind=u32::MAX; let mut discarded_address=0u64;
    // Destination is ONLY our known self task. `name` is a local IPC-space
    // lookup argument, never an RPC destination; no address is exported.
    let result=unsafe {ffi::mach_port_kobject(ffi::mach_task_self_,name,&mut kind,&mut discarded_address)};
    if result==0 {Ok(kind)} else {Err(result)}
}

#[cfg(target_os = "macos")]
fn native_task_audit(name:u32)->Result<[u32;8],AuditReadFailure> {
    let mut audit=[0u32;8]; let mut count=TASK_AUDIT_TOKEN_COUNT;
    // Called ONLY for a locally class-checked, still-owned original task right.
    // Pinned XNU f6217f8 task.c:5788/6458 and task_info.h:261. Flavor15 uses
    // convert_port_to_task_name; no PID lookup or stronger-right reacquisition.
    // This native MIG call has NO asserted hard return-time bound.
    let result=unsafe {ffi::task_info(name,TASK_AUDIT_TOKEN,audit.as_mut_ptr().cast(),&mut count)};
    checked_audit_output(result,count,audit)
}

#[cfg(target_os = "macos")]
impl OriginalReceivedTask<'_> {
    fn require_current(&mut self,end:Instant)->EnclaveResult<()> {
        self.certificate.binding.checked(end,|| {
            let (current,name)=self.original.selected_receive_context()?;
            if !std::ptr::eq(current,self.lifetime) || name!=self.receive_name
                || current.end!=self.end || end>self.end
                || !Arc::ptr_eq(&current.session,&self.certificate.binding.session)
                || !Arc::ptr_eq(&current.stop,&self.lifetime.stop) {
                return Err(err!(EACCES,"SUPERVISOR_RECEIVED_TASK_ORIGINAL_CONTEXT"));
            }
            match &self.audit.evidence {
                AuditEvidence::Native(value) if Arc::ptr_eq(value,self.certificate)
                    && Arc::ptr_eq(&self.audit.active,&self.certificate.binding.active) => {},
                _ => return Err(err!(EACCES,"SUPERVISOR_RECEIVED_TASK_ORIGINAL_LEASE")),
            }
            match self.phase {
                ReceivedTaskPhase::Original => {
                    let frame=actual_frame(self.storage).ok_or_else(||err!(EACCES,"SUPERVISOR_RECEIVED_TASK_ORIGINAL_FRAME"))?;
                    let parsed=mach_wire::decode_wide_raise(frame).map_err(|_|err!(EACCES,"SUPERVISOR_RECEIVED_TASK_ORIGINAL_FRAME"))?;
                    if parsed.names()[1]!=self.receive_name || parsed.names()[3]!=self.task_name
                        || parsed.security_token_bytes()!=&KERNEL_SECURITY_TOKEN || parsed.audit().bytes()!=&KERNEL_AUDIT_TOKEN {
                        return Err(err!(EACCES,"SUPERVISOR_RECEIVED_TASK_ORIGINAL_FRAME"));
                    }
                },
                ReceivedTaskPhase::Consumed(preparation) => {
                    preparation.require_consumed(self.storage,self.task_name,self.task_kind,self.receive_name,end)
                        .map_err(|_|err!(EACCES,"SUPERVISOR_RECEIVED_TASK_CONSUMED_FRAME"))?;
                },
            }
            if !matches!(self.task_kind,IPC_OTYPE_TASK_CONTROL|IPC_OTYPE_TASK_READ)
                || native_object_type(self.task_name).ok()!=Some(self.task_kind) {
                return Err(err!(EACCES,"SUPERVISOR_RECEIVED_TASK_ORIGINAL_CLASS"));
            }
            self.lifetime.current()?;
            let read=native_task_audit(self.task_name);
            // Recheck actual original receive owner/session and endpoint after
            // the potentially blocking kernel call, before comparing all words.
            let (after,name)=self.original.selected_receive_context()?;
            let audit=read.map_err(|_|err!(EACCES,"SUPERVISOR_RECEIVED_TASK_ORIGINAL_AUDIT"))?;
            if !std::ptr::eq(after,self.lifetime) || name!=self.receive_name || after.end!=self.end
                || end>self.end || Instant::now()>=end || audit!=self.certificate.binding.audit
                || native_object_type(self.task_name).ok()!=Some(self.task_kind) {
                return Err(err!(EACCES,"SUPERVISOR_RECEIVED_TASK_ORIGINAL_AUDIT"));
            }
            self.certificate.require_same_session(&after.session,end)
        })
    }
}

// Both original and consumed guards share the exact real task/audit/actor/
// CONTROL observations. Their private views independently enforce their phase.
#[cfg(target_os = "macos")]
fn require_retained_fault(original: &mut OriginalReceivedTask<'_>,
    preparation: &OriginalFaultPreparation, end: Instant) -> Result<(), Refusal> {
    if preparation.session_end != original.lifetime.end {
        return Err(Refusal::FaultPreparationOriginal);
    }
    let (certificate,binding) = match &preparation.evidence {
        FaultEvidence::Native { certificate,actor } => (certificate,actor),
        #[cfg(test)] FaultEvidence::Fixture(_) => return Err(Refusal::FaultPreparationOriginal),
    };
    if !Arc::ptr_eq(certificate,original.certificate) {
        return Err(Refusal::FaultPreparationOriginal);
    }
    original.require_current(end).map_err(|_| Refusal::TaskAuditOriginalContext)?;
    binding.require_same_original(certificate,&original.lifetime.session,end)
        .map_err(|_| Refusal::ActorPeerComparison)?;
    selected_exception_assignment::observe(original,binding,end)
        .map_err(|_| Refusal::CurrentExceptionAssignment)?;
    original.require_current(end).map_err(|_| Refusal::TaskAuditOriginalContext)?;
    binding.require_same_original(certificate,&original.lifetime.session,end)
        .map_err(|_| Refusal::ActorPeerComparison)?;
    preparation.require_endpoint(end)
}

// Concrete negative-only observer of the same still-owned original fault.
// Its native constructor and fields are private to this adapter. A transport
// may only revalidate or veto it, never construct proof or replace its cap.
enum FaultIoOriginal<'a> {
    #[cfg(target_os = "macos")]
    Native { original: OriginalReceivedTask<'a>, preparation: &'a OriginalFaultPreparation },
    #[cfg(test)]
    Fixture { valid: &'a AtomicBool, calls: &'a std::sync::atomic::AtomicUsize,
        delay: Duration, panic: bool, veto_at: Option<usize>,
        preparation: Option<&'a OriginalFaultPreparation> },
}
enum FaultIoVeto<'a> {
    #[cfg(target_os = "macos")]
    Native(&'a CertifiedReceivedTaskAudit),
    #[cfg(test)]
    Fixture(&'a AtomicBool),
}
impl FaultIoVeto<'_> {
    fn invalidate(&self) {
        match self {
            #[cfg(target_os = "macos")]
            Self::Native(certificate) => certificate.binding.invalidate(),
            #[cfg(test)]
            Self::Fixture(valid) => valid.store(false, Ordering::SeqCst),
        }
    }
}
struct FaultIoCheck<'a, 'b> { veto: &'a FaultIoVeto<'b>, retired: &'a AtomicBool, armed: bool }
impl Drop for FaultIoCheck<'_, '_> {
    fn drop(&mut self) {
        if self.armed {
            self.retired.store(true, Ordering::SeqCst);
            self.veto.invalidate();
        }
    }
}

/// Opaque borrowed original-fault validity, never a report/dispatch permit.
/// Native calls may block; callers must independently check their immutable
/// endpoint before and after every current() and every subsequent I/O step.
/// Error/unwind teardown must invoke veto() BEFORE dropping owned transport.
pub(crate) struct SelectedFaultIoGuard<'a> {
    original: FaultIoOriginal<'a>, veto: FaultIoVeto<'a>, end: Instant, retired: AtomicBool,
}
impl<'a> SelectedFaultIoGuard<'a> {
    #[cfg(target_os = "macos")]
    fn from_native(original: OriginalReceivedTask<'a>, preparation: &'a OriginalFaultPreparation,
        end: Instant) -> Self {
        let veto = FaultIoVeto::Native(original.certificate.as_ref());
        Self { original: FaultIoOriginal::Native { original, preparation }, veto, end,
            retired: AtomicBool::new(false) }
    }
    /// Synthetic negative-only validity for transport tests; never production
    /// identity. true is current; veto sets false and privately retires guard.
    /// Counts fixture validations only after original cap/retired checks.
    #[cfg(test)]
    pub(crate) fn fixture(end: Instant, valid: &'a AtomicBool,
        calls: &'a std::sync::atomic::AtomicUsize) -> Self {
        Self { original: FaultIoOriginal::Fixture { valid, calls, delay: Duration::ZERO,
                panic: false, veto_at: None, preparation: None },
            veto: FaultIoVeto::Fixture(valid), end, retired: AtomicBool::new(false) }
    }
    #[cfg(test)]
    fn fixture_bound(end: Instant, valid: &'a AtomicBool,
        calls: &'a std::sync::atomic::AtomicUsize, preparation: &'a OriginalFaultPreparation) -> Self {
        let mut guard = Self::fixture(end,valid,calls);
        if let FaultIoOriginal::Fixture { preparation: bound,.. } = &mut guard.original {
            *bound = Some(preparation);
        }
        guard
    }
    fn require_preparation(&self, offered: &OriginalFaultPreparation) -> Result<(), Refusal> {
        let bound = match &self.original {
            #[cfg(target_os = "macos")]
            FaultIoOriginal::Native { preparation,.. } => *preparation,
            #[cfg(test)]
            FaultIoOriginal::Fixture { preparation: Some(value),.. } => *value,
            #[cfg(test)]
            FaultIoOriginal::Fixture { preparation: None,.. } => return Err(Refusal::FaultPreparationOriginal),
        };
        if !std::ptr::eq(bound,offered) { return Err(Refusal::FaultPreparationOriginal); }
        Ok(())
    }
    /// Atomically retire THIS original certificate/session; no positive grant.
    pub(crate) fn veto(&self) {
        self.retired.store(true, Ordering::SeqCst);
        self.veto.invalidate();
    }
    fn require_current(&mut self, requested_end: Instant) -> Result<(), Refusal> {
        let end = self.end;
        let mut check = FaultIoCheck { veto: &self.veto, retired: &self.retired, armed: true };
        if self.retired.load(Ordering::SeqCst) { return Err(Refusal::FaultPreparationOriginal); }
        // The transport cannot substitute even an apparently reasonable fresh
        // or shortened endpoint for this exact original prepared actor cap.
        if requested_end != end || Instant::now() >= end {
            return Err(Refusal::FaultPreparationEndpoint);
        }
        match &mut self.original {
            #[cfg(target_os = "macos")]
            FaultIoOriginal::Native { original, preparation } => {
                preparation.require_original(original.storage, original.task_name, original.task_kind,
                    original.receive_name, end)?;
                require_retained_fault(original,preparation,end)?;
            },
            #[cfg(test)]
            FaultIoOriginal::Fixture { valid, calls, delay, panic, veto_at, .. } => {
                let call = calls.fetch_add(1, Ordering::SeqCst) + 1;
                if *veto_at == Some(call) { valid.store(false, Ordering::SeqCst); }
                if !valid.load(Ordering::SeqCst) { return Err(Refusal::FaultPreparationOriginal); }
                if !delay.is_zero() { std::thread::sleep(*delay); }
                if *panic { panic!("SYNTHETIC_ORIGINAL_FAULT_IO_GUARD_UNWIND"); }
                if !valid.load(Ordering::SeqCst) { return Err(Refusal::FaultPreparationOriginal); }
            },
        }
        if self.retired.load(Ordering::SeqCst) { return Err(Refusal::FaultPreparationOriginal); }
        if Instant::now() >= end { return Err(Refusal::FaultPreparationEndpoint); }
        check.armed = false;
        Ok(())
    }
    /// Revalidate the actual SAME owner/proof and exact original endpoint.
    /// There is no supplied verifier, replacement actor comparison or renewal.
    pub(crate) fn current(&mut self, end: Instant) -> EnclaveResult<()> {
        self.require_current(end).map_err(|_| err!(EACCES, "SUPERVISOR_SELECTED_FAULT_IO_CONTEXT"))
    }
}
impl Drop for SelectedFaultIoGuard<'_> {
    fn drop(&mut self) { if std::thread::panicking() { self.veto(); } }
}

#[cfg(any(test, target_os = "macos"))]
#[derive(serde::Serialize, serde::Deserialize)]
enum SelectedZkFaultRequest { ReportFault(crate::quarantine_types::FaultReport) }
#[cfg(any(test, target_os = "macos"))]
#[derive(serde::Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
enum SelectedZkFaultResponse { Fault(crate::quarantine_types::Response) }

// Closed production choice. Only the fixed Native adapter constructs Native;
// the scripted choice is compiled out of every production build. This is no
// verifier callback or alternative production identity/transport provider.
#[cfg(any(test, target_os = "macos"))]
enum FaultDispatchBackend<'a> {
    Native(std::marker::PhantomData<&'a ()>),
    #[cfg(test)] Scripted(&'a mut tests::DispatchScript),
}

#[cfg(any(test, target_os = "macos"))]
fn selected_zk_socket(socket_root: &std::path::Path) -> std::path::PathBuf {
    let daemon = crate::daemon::DaemonId::ZkAuditor;
    socket_root.join(daemon.dir_name()).join(format!("{}.sock", daemon.dir_name()))
}

#[cfg(any(test, target_os = "macos"))]
fn checked_fault_wall_millis(now: std::time::SystemTime) -> EnclaveResult<u64> {
    let duration = now.duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| err!(EIO, "SUPERVISOR_SELECTED_FAULT_WALL_TIME"))?;
    u64::try_from(duration.as_millis())
        .map_err(|_| err!(EIO, "SUPERVISOR_SELECTED_FAULT_WALL_TIME"))
}

#[cfg(any(test, target_os = "macos"))]
fn require_selected_zk_peer(peer: &crate::ipc::PeerCredentials,
    requirement: &crate::codesign::CodeRequirement) -> EnclaveResult<()> {
    let identity = peer.code_identity.as_ref()
        .ok_or_else(|| err!(EACCES, "SUPERVISOR_SELECTED_FAULT_AUDITOR"))?;
    if peer.uid != crate::daemon::DaemonId::ZkAuditor.uid()
        || peer.audit_token.is_none() || peer.tls_channel_binding.is_some()
        || identity.identifier != requirement.identifier || identity.cdhash.is_empty()
        || (!requirement.team_id.is_empty() && identity.team_id != requirement.team_id)
        || (!requirement.cdhash_allowlist.is_empty()
            && !requirement.cdhash_allowlist.contains(&identity.cdhash)) {
        return Err(err!(EACCES, "SUPERVISOR_SELECTED_FAULT_AUDITOR"));
    }
    Ok(())
}

#[cfg(any(test, target_os = "macos"))]
impl FaultDispatchBackend<'_> {
    fn require_native_authority(&self) -> EnclaveResult<()> {
        match self {
            Self::Native(_) => {
                if !cfg!(target_os = "macos") || !crate::codesign::enforced()
                    || crate::ipc::geteuid() != 0 {
                    return Err(err!(EPERM, "SUPERVISOR_SELECTED_FAULT_NATIVE_ROOT"));
                }
                Ok(())
            },
            #[cfg(test)] Self::Scripted(script) => script.require_native_authority(),
        }
    }
    fn wall_time(&mut self) -> std::time::SystemTime {
        match self {
            Self::Native(_) => std::time::SystemTime::now(),
            #[cfg(test)] Self::Scripted(script) => script.wall_time(),
        }
    }
    fn exchange(&mut self, socket_root: &std::path::Path, end: Instant,
        guard: &mut SelectedFaultIoGuard<'_>, requirement: &crate::codesign::CodeRequirement,
        request: &SelectedZkFaultRequest) -> EnclaveResult<SelectedZkFaultResponse> {
        match self {
            Self::Native(_) => {
                let client = crate::ipc::Client::connect_selected_fault_until(
                    &selected_zk_socket(socket_root), crate::daemon::DaemonId::ZkAuditor.uid(),
                    Some(requirement), end, guard)?;
                // The concrete client keeps SAME guard armed while metadata
                // is checked and through the consumed typed request/reply.
                require_selected_zk_peer(client.server(), requirement)?;
                client.call(request)
            },
            #[cfg(test)] Self::Scripted(script) =>
                script.exchange(socket_root, end, guard, requirement, request),
        }
    }
}

// Dispatch keeps its veto armed until a typed Fault receipt, actual tracker
// completion and all final original postchecks succeed. Only then may a private
// nonClone receipt pass to the independently armed terminal composition owner.
#[cfg(any(test, target_os = "macos"))]
struct TerminalDispatchVeto<'g, 'o> {
    guard: &'g mut SelectedFaultIoGuard<'o>, evidence: &'g FaultEvidence, armed: bool,
}
#[cfg(any(test, target_os = "macos"))]
impl Drop for TerminalDispatchVeto<'_, '_> {
    fn drop(&mut self) {
        if self.armed {
            self.guard.veto();
            self.evidence.invalidate();
        }
    }
}
#[cfg(any(test, target_os = "macos"))]
impl TerminalDispatchVeto<'_, '_> {
    fn current(&mut self, end: Instant) -> EnclaveResult<()> {
        // The concrete guard already checks its cap, but keep independent
        // pre/post observations around potentially blocking native validation.
        if Instant::now() >= end { return Err(err!(ETIMEDOUT, "SUPERVISOR_SELECTED_FAULT_END")); }
        let result = self.guard.current(end);
        if Instant::now() >= end { return Err(err!(ETIMEDOUT, "SUPERVISOR_SELECTED_FAULT_END")); }
        result
    }
}

#[cfg(any(test, target_os = "macos"))]
fn dispatch_original_fault<'p>(tracker: &super::RespawnTracker, socket_root: &std::path::Path,
    preparation: &'p OriginalFaultPreparation, guard: &mut SelectedFaultIoGuard<'_>,
    backend: &mut FaultDispatchBackend<'_>) -> EnclaveResult<ValidReportReceipt<'p>> {
    let end = preparation.end;
    let mut veto = TerminalDispatchVeto { guard, evidence: &preparation.evidence, armed: true };
    veto.guard.require_preparation(preparation)
        .map_err(|_| err!(EACCES,"SUPERVISOR_SELECTED_FAULT_GUARD_PREPARATION"))?;
    // Irreversible original-attempt consumption precedes connection or ANY
    // request byte, even if admission/authentication/time/receipt later fails.
    if preparation.dispatch_consumed.swap(true, Ordering::SeqCst) {
        return Err(err!(EACCES, "SUPERVISOR_SELECTED_FAULT_ALREADY_CONSUMED"));
    }
    let result = tracker.report_fault_before(crate::daemon::DaemonId::CustodyVault.uid(), end, |same_end| {
        preparation.require_endpoint(same_end)
            .map_err(|_| err!(EACCES, "SUPERVISOR_SELECTED_FAULT_END"))?;
        veto.current(same_end)?;
        backend.require_native_authority()?;
        // Validate actual original before/after sampling AND checked UTC
        // conversion. No default epoch or truncating u128-to-u64 cast.
        veto.current(same_end)?;
        let timestamp = checked_fault_wall_millis(backend.wall_time());
        veto.current(same_end)?;
        let at_ms = timestamp?;
        let requirement = crate::codesign::CodeRequirement::daemon(crate::daemon::DaemonId::ZkAuditor);
        veto.current(same_end)?;
        let request = SelectedZkFaultRequest::ReportFault(crate::quarantine_types::FaultReport {
            kind: preparation.kind, fault_addr: preparation.address, at_ms,
        });
        let receipt = backend.exchange(socket_root, same_end, veto.guard, &requirement, &request)?;
        // This outer owner remains armed after transport typed-positive
        // disarm, including wrong/late/unknown receipt and tracker completion.
        veto.current(same_end)?;
        let SelectedZkFaultResponse::Fault(response) = receipt;
        preparation.require_endpoint(same_end)
            .map_err(|_| err!(EACCES, "SUPERVISOR_SELECTED_FAULT_END"))?;
        veto.current(same_end)?;
        Ok(response)
    });
    // On failed authority or busy tracker completion, go directly to the
    // terminal veto: do not delay a known failure with another native call.
    let response = result?;
    veto.current(end)?;
    preparation.require_endpoint(end)
        .map_err(|_| err!(EACCES, "SUPERVISOR_SELECTED_FAULT_END"))?;
    veto.current(end)?;
    // Only this completed path can hand authority to the independently armed
    // original owner. Every earlier error/unwind retains the dispatch veto.
    veto.armed = false;
    Ok(ValidReportReceipt { preparation, response })
}

#[cfg(target_os = "macos")]
impl Native<'_> {
    // Sole production factory: it borrows the actual receive-owning adapter,
    // storage, audit and retained preparation. No supplied implementation.
    fn fault_io_guard<'a>(&'a self, storage: &'a Storage, task_name: u32, task_kind: u32,
        end: Instant, audit: &'a AuditLease, preparation: &'a OriginalFaultPreparation)
        -> Result<SelectedFaultIoGuard<'a>, Refusal> {
        let certificate = match &audit.evidence {
            AuditEvidence::Native(value) => value,
            #[cfg(test)] AuditEvidence::Fixture => return Err(Refusal::FaultPreparationOriginal),
        };
        let (lifetime, receive_name) = self._original.selected_receive_context()
            .map_err(|_| Refusal::TaskAuditOriginalContext)?;
        if receive_name != self.name { return Err(Refusal::FaultPreparationOriginal); }
        let original = OriginalReceivedTask { original: self._original, lifetime, storage, phase: ReceivedTaskPhase::Original, audit,
            certificate, task_name, task_kind, receive_name, end: lifetime.end };
        let mut guard = SelectedFaultIoGuard::from_native(original, preparation, end);
        guard.require_current(end)?;
        Ok(guard)
    }
}

#[cfg(target_os = "macos")]
impl Kernel for Native<'_> {
    fn retained_startup_current(&mut self, end: Instant) -> EnclaveResult<()> {
        let (original, name) = self._original.selected_receive_context()?;
        if name != self.name || end > original.end {
            return Err(err!(EACCES, "SUPERVISOR_MACH_STARTUP_ORIGINAL_CONTEXT"));
        }
        // Freshly observe the SAME process-retained SH owner. Never call the
        // acquiring retain_selected_startup_lease API after service effects.
        crate::deployment::startup_lease::require_retained_selected_startup_lease(end)?;
        let (after, after_name) = self._original.selected_receive_context()?;
        if !std::ptr::eq(after, original) || after_name != name || after.end != original.end {
            return Err(err!(EACCES, "SUPERVISOR_MACH_STARTUP_ORIGINAL_CONTEXT"));
        }
        after.current()
    }
    fn receive(&mut self, storage: &mut Storage, options: i32, timeout_ms: u32) -> i32 {
        unsafe { ffi::mach_msg(storage.0.as_mut_ptr().cast(), options, 0,
            mach_wire::FRAME_BYTES as u32, self.name, timeout_ms, 0) }
    }
    fn object_type_in_self(&mut self, name: u32) -> Result<u32, i32> {
        native_object_type(name)
    }
    fn task_audit_of_classified_original(&mut self, name: u32, end: Instant)
        -> Result<AuditLease, AuditReadFailure> {
        let (original, receive_name) = self._original.selected_receive_context()
            .map_err(|_| AuditReadFailure::OriginalContext)?;
        if receive_name!=self.name || end!=original.end || Instant::now()>=end {
            return Err(AuditReadFailure::OriginalContext);
        }
        let read=native_task_audit(name).map(|audit| {
            let active=Arc::new(AtomicBool::new(true));
            let snapshot=Arc::new(CertifiedReceivedTaskAudit {binding:AuditBinding {
                audit,session:original.session.clone(),end,active:active.clone(),
            }});
            AuditLease {active,evidence:AuditEvidence::Native(snapshot)}
        });
        // The just-returned lease is ALREADY retained here: postcheck failure
        // drops it/inactivates snapshots before outer message cleanup.
        let (after,after_name)=self._original.selected_receive_context().map_err(|_| AuditReadFailure::OriginalContext)?;
        if !std::ptr::eq(after,original) || !Arc::ptr_eq(&after.session,&original.session)
            || !Arc::ptr_eq(&after.stop,&original.stop) || after_name!=receive_name
            || after.end!=end || Instant::now()>=end {return Err(AuditReadFailure::OriginalContext);}
        read
    }
    fn actor_and_assignment_of_original(&mut self,storage:&Storage,task_name:u32,
        task_kind:u32,end:Instant,audit:&AuditLease)->Result<OriginalFaultPreparation,Refusal> {
        let certificate=match &audit.evidence {
            AuditEvidence::Native(value)=>value,
            #[cfg(test)] AuditEvidence::Fixture=>return Err(Refusal::TaskAuditOriginalContext),
        };
        let (lifetime,receive_name)=self._original.selected_receive_context()
            .map_err(|_|Refusal::TaskAuditOriginalContext)?;
        if receive_name!=self.name || end!=lifetime.end {return Err(Refusal::TaskAuditOriginalContext);}
        let mut original=OriginalReceivedTask {original:self._original,lifetime,storage,phase:ReceivedTaskPhase::Original,audit,
            certificate,task_name,task_kind,receive_name,end};
        original.require_current(end).map_err(|_|Refusal::TaskAuditOriginalContext)?;
        let actor=self._original.selected_actor_comparison().map_err(|_|Refusal::ActorPeerComparison)?;
        let binding=actor.compare_received_task(certificate.clone(),&lifetime.session,end)
            .map_err(|_|Refusal::ActorPeerComparison)?;
        // Retain and arm immediately after the actual actor returns: even an
        // intervening assignment error/unwind vetoes before proof destruction.
        let evidence=FaultEvidence::Native {certificate:certificate.clone(),actor:binding};
        let mut veto=PreparationVeto {evidence:&evidence,armed:true};
        let binding=match &evidence {
            FaultEvidence::Native {actor,..}=>actor,
            #[cfg(test)] FaultEvidence::Fixture(_)=>unreachable!(),
        };
        original.require_current(end).map_err(|_|Refusal::TaskAuditOriginalContext)?;
        binding.require_same_original(certificate,&lifetime.session,end).map_err(|_|Refusal::ActorPeerComparison)?;
        selected_exception_assignment::observe(&mut original,binding,end)
            .map_err(|_|Refusal::CurrentExceptionAssignment)?;
        original.require_current(end).map_err(|_|Refusal::TaskAuditOriginalContext)?;
        binding.require_same_original(certificate,&lifetime.session,end).map_err(|_|Refusal::ActorPeerComparison)?;
        veto.armed=false;drop(veto);
        OriginalFaultPreparation::from_original(storage, task_name, task_kind, receive_name, end,
            evidence)
    }
    fn validate_fault_preparation_of_original(&mut self,storage:&Storage,
        task_name:u32,task_kind:u32,end:Instant,audit:&AuditLease,
        preparation:&OriginalFaultPreparation)->Result<(),Refusal> {
        self.fault_io_guard(storage,task_name,task_kind,end,audit,preparation).map(|_| ())
    }
    fn dispatch_fault_of_original(&mut self, storage:&mut Storage, resources:&mut Resources,
        task_name:u32, task_kind:u32, end:Instant, audit:&AuditLease,
        preparation:&OriginalFaultPreparation) -> Result<crate::quarantine_types::Response,Refusal> {
        let (lifetime, receive_name) = self._original.selected_receive_context()
            .map_err(|_| Refusal::TaskAuditOriginalContext)?;
        if receive_name != self.name || *resources != Resources::Received {
            return Err(Refusal::FaultPreparationOriginal);
        }
        let _terminal = OriginalTerminalVeto { lifetime, audit, preparation };
        let receipt = {
            let mut guard = self.fault_io_guard(storage,task_name,task_kind,end,audit,preparation)?;
            dispatch_original_fault(self.tracker,self.socket_root,preparation,&mut guard,
                &mut FaultDispatchBackend::Native(std::marker::PhantomData))
                .map_err(|_| Refusal::FaultDispatchUnavailable)?
        }; // Original guard is gone; the independent terminal veto stays armed.
        let response = receipt.response;
        let certificate = match &audit.evidence {
            AuditEvidence::Native(value) => value,
            #[cfg(test)] AuditEvidence::Fixture => return Err(Refusal::FaultPreparationOriginal),
        };
        let source = selected_mach_reply::ConsumedSource::Native {
            original: self._original, lifetime, certificate,
        };
        let owner = selected_mach_reply::detach_components(storage,resources,lifetime,
            receive_name,audit,preparation,receipt,selected_mach_reply::NativeReply,source)
            .map_err(|_| Refusal::NativeReplyAndStartupCompositionUnavailable)?;
        // Diagnostics cannot grant positive progress, regardless of transfer.
        let observation = owner.send_failure();
        // Bounded diagnostics contain no right names, task/audit/raw snapshot
        // or actor data. Preserve unknown reply ownership separately from the
        // original receive result and separately owned body cleanup.
        eprintln!("SUPERVISOR_SELECTED_FAILURE_REPLY result={:?} ownership={:?} cleanup={:?} refusal={:?}",
            observation.native_result,observation.ownership,observation.cleanup,observation.refusal);
        Ok(response)
    }
    fn destroy_received(&mut self, storage: &mut Storage) {
        unsafe { ffi::mach_msg_destroy(storage.0.as_mut_ptr().cast()); }
    }
}
#[cfg(target_os = "macos")]
pub(super) fn receive_selected_once(original: &super::mach_exception::ReceiveRight,
    tracker: &super::RespawnTracker, socket_root: &std::path::Path) -> Outcome {
    let (lifetime, name) = match original.selected_receive_context() {
        Ok(context) => context,
        Err(_) => return Outcome::Refused { stage: Refusal::BeforeReceive, native_result: None, cleanup: Cleanup::NotRequired },
    };
    Attempt::new(Native { _original: original, name, tracker, socket_root }, lifetime, name).run()
}
#[cfg(target_os = "macos")]
mod ffi {
    unsafe extern "C" {
        pub(super) fn mach_msg(message: *mut libc::c_void, options: i32, send_size: u32,
            receive_size: u32, receive_name: u32, timeout: u32, notify: u32) -> i32;
        pub(super) fn mach_msg_destroy(message: *mut libc::c_void);
        pub(super) static mach_task_self_: u32;
        pub(super) fn mach_port_kobject(task: u32, name: u32, kind: *mut u32,
            address: *mut u64) -> i32;
        pub(super) fn task_info(task: u32, flavor: i32, info: *mut i32, count: *mut u32) -> i32;
    }
}

#[path = "selected_exception_assignment.rs"]
mod selected_exception_assignment;

// Failure-only reply composition; every path remains terminal/refused.
// No positive reply, Ready/PF/Begin or startup authority is introduced.
#[path = "selected_mach_reply.rs"]
mod selected_mach_reply;

#[cfg(test)]
#[path = "selected_mach_native_tests.rs"]
mod tests;
