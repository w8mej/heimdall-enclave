//! Owned selected PF notification components. Registration and loop progress
//! never establish PF enforcement, restoration or original configd continuity.
//! Same-original negative cancellation only; no positive PF/readiness permit.
#![allow(dead_code)]

use std::{ffi::CString, fs::{File, Metadata}, os::{fd::{AsRawFd, FromRawFd, IntoRawFd},
    unix::{ffi::OsStrExt, fs::{FileExt, MetadataExt}}}, path::{Component, Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering}, mpsc},
    thread::{self, JoinHandle}, time::Instant};
use sha2::{Digest, Sha256};
use crate::{deployment::{self, CheckedDeploymentTarget, DeploymentRole, DeploymentSigningMode},
    error::{EnclaveError, EnclaveResult, Errno}, profile::Profile};

const MAX_NODES: usize = 32;
const MAX_FAILURES: usize = 16;
const MAX_CLEANUP_FAILURES: usize = 4 * MAX_NODES + 8;
const MAX_RECEIPTS: usize = 4 * MAX_NODES + 1;
const MAX_INPUT: usize = 1_048_576;
const LLM_FILE: &str = "/private/etc/pf.anchors/com.enterprise.llm.isolation";
const CAS_FILE: &str = "/private/etc/pf.anchors/com.enterprise.cas.swarm";
const LLM_POLICY: &[u8] = include_bytes!("pf_policy_llm.pf");
const CAS_POLICY: &[u8] = include_bytes!("pf_policy_cas.pf");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source { Owner, Kqueue, DynamicStore }
impl Source {
    fn slot(self) -> usize { match self { Self::Kqueue => 0, Self::DynamicStore => 1, Self::Owner => 2 } }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reason {
    NativeRequired, RootRequired, SelectionRequired, UnsupportedScope, ContextChanged, UpgradeDenied,
    Deadline, Clock, Stopped, StopPending, Spawn, Unwound, MissingWorker, Unarmed, ChannelBusy,
    ChannelClosed, ReplyClosed, LateReply, Poisoned, CounterOverflow, FailureOverflow,
    InvalidPath, InputOpen, InputMetadata, InputType, InputProtection, InputLinks, InputSize,
    DescriptorFlags, AclUnavailable, AclInspection, AclRefused, InputRead, InputChanged,
    InputIncomplete, CanonicalMismatch, DescriptorMismatch, NativeCall, RegistrationReceipt,
    UnknownEvent, TimerMissing, DrainBound, CfAllocation, ScSession, ScRegistration,
    ScQuery, SourceInvalid, RunLoopResult, MalformedCallback, ServerRestart, Close,
    SourceCleanup, CleanupUncertain, OriginalBinding, AlreadyAttempted, RetentionCollision, CollectionChanged,
    RepairObservationClosed, RepairObservationUnknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Failure { source: Source, reason: Reason, code: Option<i32>, resource: Option<u16> }
impl Failure {
    fn new(source: Source, reason: Reason) -> Self { Self { source, reason, code: None, resource: None } }
    fn code(source: Source, reason: Reason, code: i32) -> Self { Self { source, reason, code: Some(code), resource: None } }
}
type Check<T> = Result<T, Failure>;

enum BoundSession {
    Native(Arc<crate::power::selected_owner_session::SelectedOwnerSession>),
    #[cfg(test)]
    Fixture(Arc<AtomicBool>),
}
struct OriginalNegativeBinding { session: BoundSession, supervisor_stop: Arc<AtomicBool>, end: Instant }
impl OriginalNegativeBinding {
    fn revoke(&self) {
        match &self.session {
            BoundSession::Native(session) => session.revoke(),
            #[cfg(test)] BoundSession::Fixture(session) => session.store(true, Ordering::SeqCst),
        }
        self.supervisor_stop.store(true, Ordering::SeqCst);
    }
    fn revoked(&self) -> bool {
        self.supervisor_stop.load(Ordering::SeqCst) || Instant::now() >= self.end || match &self.session {
            BoundSession::Native(session) => session.require_not_revoked().is_err(),
            #[cfg(test)] BoundSession::Fixture(session) => session.load(Ordering::SeqCst),
        }
    }
    fn current(&self) -> Check<()> {
        if self.revoked() { self.revoke(); return Err(Failure::new(Source::Owner, Reason::Stopped)); }
        match &self.session {
            BoundSession::Native(session) => session.require_current().map_err(|_| {
                self.revoke(); Failure::new(Source::Owner, Reason::OriginalBinding)
            })?,
            #[cfg(test)] BoundSession::Fixture(_) => (),
        }
        if self.revoked() { self.revoke(); return Err(Failure::new(Source::Owner, Reason::Stopped)); }
        Ok(())
    }
    fn matches(&self, session: &Arc<crate::power::selected_owner_session::SelectedOwnerSession>,
        stop: &Arc<AtomicBool>, end: Instant) -> Check<()> {
        let matches = match &self.session {
            BoundSession::Native(original) => Arc::ptr_eq(original, session),
            #[cfg(test)] BoundSession::Fixture(_) => false,
        };
        if !matches || !Arc::ptr_eq(&self.supervisor_stop, stop) || end > self.end || Instant::now() >= end {
            session.revoke(); stop.store(true, Ordering::SeqCst); self.revoke();
            return Err(Failure::new(Source::Owner, Reason::OriginalBinding));
        }
        self.endpoint(end).map(|_| ())
    }
    fn operation_end(&self, requested: Instant) -> Instant {
        requested.min(self.end).min(Instant::now() + ADMIN_LIMIT)
    }
    fn endpoint(&self, requested: Instant) -> Check<Instant> {
        let end = requested.min(self.end);
        if Instant::now() >= end {
            self.revoke(); return Err(Failure::new(Source::Owner, Reason::Deadline));
        }
        self.current()?;
        if let Err(error) = within(end, Source::Owner) {self.revoke(); return Err(error);}
        Ok(end)
    }
    #[cfg(test)]
    fn fixture(end: Instant) -> Arc<Self> {
        Arc::new(Self {session: BoundSession::Fixture(Arc::new(AtomicBool::new(false))),
            supervisor_stop: Arc::new(AtomicBool::new(false)), end})
    }
}
// Exactly one native attempt per supervisor process. Never point a delayed or
// NULL-info callback at a later session or free its original negative domain.
static ORIGINAL_DOMAIN: OnceLock<Arc<OriginalNegativeBinding>> = OnceLock::new();
fn publish_domain(domain: &OnceLock<Arc<OriginalNegativeBinding>>, binding: Arc<OriginalNegativeBinding>) -> Check<()> {
    if let Err(offered) = domain.set(binding) {
        offered.revoke();
        if let Some(original) = domain.get() { original.revoke(); }
        return Err(Failure::new(Source::Owner, Reason::AlreadyAttempted));
    }
    Ok(())
}
fn veto_orphan(domain: &OnceLock<Arc<OriginalNegativeBinding>>) {
    if let Some(original) = domain.get() { original.revoke(); }
}

#[derive(Debug)]
struct Journal { first: Option<Failure>, failures: Vec<Failure>, cleanup: Vec<Failure>, overflow: bool,
    receipts: Vec<(Event, u64)>, last_loop_result: [Option<i32>; 2] }
impl Default for Journal {
    fn default() -> Self { Self { first: None, failures: Vec::with_capacity(MAX_FAILURES),
        cleanup: Vec::with_capacity(MAX_CLEANUP_FAILURES), overflow: false,
        receipts: Vec::with_capacity(MAX_RECEIPTS), last_loop_result: [None, None] } }
}
impl Journal {
    fn record(&mut self, failure: Failure, cleanup: bool) {
        if self.first.is_none() { self.first = Some(failure); }
        let list = if cleanup { &mut self.cleanup } else { &mut self.failures };
        let maximum = if cleanup { MAX_CLEANUP_FAILURES } else { MAX_FAILURES };
        if list.len() < maximum {list.push(failure);} else {self.overflow = true;}
    }
}
struct Shared {
    binding: Arc<OriginalNegativeBinding>,
    revoked: AtomicBool, stop: AtomicBool, generation: AtomicU64, ticks: AtomicU64,
    stop_pending: AtomicBool, stop_evidence_unknown: AtomicBool, joined_unwind_sources: AtomicU8,
    source_bits: AtomicU8, phase: [AtomicU8; 2], running: [AtomicBool; 2],
    resources: [AtomicU64; 2], registrations: [AtomicU64; 2],
    last_loop_ns: [AtomicU64; 2], last_invalidation_ns: [AtomicU64; 2],
    journal: Mutex<Journal>,
    repair_closed: AtomicBool, repair_unknown: AtomicBool, repair_native_active: AtomicU64,
    repair_bounds: Mutex<Option<RepairBounds>>,
}
const STARTING: u8 = 0;
const ARMED: u8 = 1;
const STOPPED: u8 = 2;
impl Shared {
    #[cfg(test)]
    fn new() -> Arc<Self> {
        Self::bound(OriginalNegativeBinding::fixture(Instant::now() + std::time::Duration::from_secs(30)))
    }
    fn bound(binding: Arc<OriginalNegativeBinding>) -> Arc<Self> {
        Arc::new(Self { binding, revoked: AtomicBool::new(false), stop: AtomicBool::new(false),
            generation: AtomicU64::new(0), ticks: AtomicU64::new(0),
            stop_pending: AtomicBool::new(false), stop_evidence_unknown: AtomicBool::new(false),
            joined_unwind_sources: AtomicU8::new(0), source_bits: AtomicU8::new(0),
            phase: [AtomicU8::new(STARTING), AtomicU8::new(STARTING)],
            running: [AtomicBool::new(false), AtomicBool::new(false)],
            resources: [AtomicU64::new(0), AtomicU64::new(0)], registrations: [AtomicU64::new(0), AtomicU64::new(0)],
            last_loop_ns: [AtomicU64::new(0), AtomicU64::new(0)], last_invalidation_ns: [AtomicU64::new(0), AtomicU64::new(0)],
            journal: Mutex::new(Journal::default()),
            repair_closed: AtomicBool::new(false), repair_unknown: AtomicBool::new(false),
            repair_native_active: AtomicU64::new(0), repair_bounds: Mutex::new(None) })
    }
    fn terminal_veto(&self) {
        self.binding.revoke();
        self.revoked.store(true, Ordering::SeqCst);
        self.stop.store(true, Ordering::SeqCst);
    }
    fn event_invalidate(&self, source: Source) -> Check<u64> {
        // Must precede event parsing, clocks, mutexes and native cleanup.
        self.terminal_veto();
        self.invalidate(source)
    }
    fn dispatch_event(&self, event: Event, registered: &[usize]) -> Check<()> {
        if event.filter != FILTER_TIMER { self.event_invalidate(Source::Kqueue)?; }
        let result = match classify_event(event, registered) {
            Ok(EventKind::Timer) => self.tick().map(|_| ()),
            Ok(EventKind::Vnode) => Ok(()),
            Ok(EventKind::RevokedVnode) => Err(input_error(Reason::InputChanged)),
            Err(error) => Err(error),
        };
        if let Err(error) = result { self.record(error, false); }
        result
    }
    fn dispatch_callback(&self, parse: impl FnOnce() -> Check<()>) -> Check<()> {
        self.event_invalidate(Source::DynamicStore)?;
        parse()
    }
    fn complete_runloop(&self, result: i32, deadline: Instant) -> Check<()> {
        let valid = if !runloop_progress(result) {
            Err(Failure::code(Source::DynamicStore, Reason::RunLoopResult, result))
        } else {
            self.binding.endpoint(deadline).map(|_| ())
        };
        // Known negative native completion must precede evidence clocks/locks.
        if valid.is_err() { self.terminal_veto(); }
        let noted = self.note_loop(Source::DynamicStore, result);
        valid.and(noted)
    }
    fn complete_query<T>(&self, deadline: Instant, inspect: impl FnOnce() -> Check<T>,
        release: impl FnOnce()) -> Check<T> {
        let valid = (|| {
            // Refuse an already late completion before parsing more CF data.
            self.binding.endpoint(deadline)?;
            let value = inspect()?;
            self.binding.endpoint(deadline)?;
            Ok(value)
        })();
        // Native release can block; retain the original resource charge and
        // revoke before entering it for every known invalid/late outcome.
        if valid.is_err() { self.terminal_veto(); }
        release();
        let result = valid.and_then(|value| {
            self.binding.endpoint(deadline)?;
            Ok(value)
        });
        if result.is_err() { self.terminal_veto(); }
        result
    }
    fn complete_registration_receipt(&self, count: i32, event: Event,
        ident: usize, filter: i16, fflags: u32, deadline: Instant) -> Check<()> {
        let valid = if count == 1 && receipt_valid(event, ident, filter, REGISTER_FLAGS, fflags) {
            self.binding.endpoint(deadline).map(|_| ())
        } else {
            Err(Failure { source: Source::Kqueue, reason: Reason::RegistrationReceipt,
                code: if event.flags & ERROR != 0 {i32::try_from(event.data).ok()} else {Some(count)}, resource: None })
        };
        // The raw result is known invalid before any evidence clock/lock.
        if valid.is_err() { self.terminal_veto(); }
        let noted = if count == 1 {self.note_receipt(event)} else {Ok(())};
        valid.and(noted)
    }
    fn record(&self, failure: Failure, cleanup: bool) {
        self.terminal_veto();
        let mut journal = match self.journal.lock() {
            Ok(value) => value,
            Err(poisoned) => {
                let mut value = poisoned.into_inner();
                if value.first.is_none() { value.first = Some(Failure::new(Source::Owner, Reason::Poisoned)); }
                value
            }
        };
        journal.record(failure, cleanup);
    }
    fn record_stop(&self, failure: Failure) {
        self.terminal_veto();
        match failure.reason {
            Reason::StopPending => self.stop_pending.store(true, Ordering::SeqCst),
            Reason::Unwound => {self.joined_unwind_sources.fetch_or(1 << failure.source.slot(), Ordering::SeqCst);},
            _ => self.stop_evidence_unknown.store(true, Ordering::SeqCst),
        }
        match self.journal.try_lock() {
            Ok(mut journal) => journal.record(failure, true),
            Err(_) => self.stop_evidence_unknown.store(true, Ordering::SeqCst),
        }
    }
    fn stop_uncertain(&self) -> bool {
        self.stop_pending.load(Ordering::SeqCst) || self.stop_evidence_unknown.load(Ordering::SeqCst)
            || self.joined_unwind_sources.load(Ordering::SeqCst) != 0
    }
    fn usable(&self, source: Source) -> Check<()> {
        if let Err(error) = self.binding.current() {
            self.terminal_veto(); return Err(Failure { source, ..error });
        }
        #[cfg(target_os = "macos")]
        if native::orphaned_callback() {
            let failure = Failure::new(Source::DynamicStore, Reason::MalformedCallback);
            self.record(failure, false);
            return Err(failure);
        }
        if self.revoked.load(Ordering::SeqCst) || self.stop.load(Ordering::SeqCst) {
            return Err(Failure::new(source, Reason::Stopped));
        }
        if self.journal.is_poisoned() {
            let failure = Failure::new(source, Reason::Poisoned);
            self.record(failure, false);
            return Err(failure);
        }
        Ok(())
    }
    fn advance(&self, counter: &AtomicU64, source: Source) -> Check<u64> {
        match counter.try_update(Ordering::SeqCst, Ordering::SeqCst, |value| value.checked_add(1)) {
            Ok(old) => Ok(old + 1),
            Err(_) => { let error = Failure::new(source, Reason::CounterOverflow); self.record(error, false); Err(error) }
        }
    }
    fn invalidate(&self, source: Source) -> Check<u64> {
        self.source_bits.fetch_or(1 << source.slot(), Ordering::SeqCst);
        let generation = self.advance(&self.generation, source)?;
        if source.slot() < 2 { self.last_invalidation_ns[source.slot()].store(boot_time(source)?, Ordering::SeqCst); }
        Ok(generation)
    }
    fn tick(&self) -> Check<u64> { self.advance(&self.ticks, Source::Kqueue) }
    fn resource_acquired(&self, source: Source) { let _ = self.advance(&self.resources[source.slot()], source); }
    fn resource_released(&self, source: Source) {
        if self.resources[source.slot()].try_update(Ordering::SeqCst, Ordering::SeqCst, |value| value.checked_sub(1)).is_err() {
            self.record(Failure::new(source, Reason::CounterOverflow), true);
        }
    }
    fn note_loop(&self, source: Source, code: i32) -> Check<()> {
        let at = boot_time(source)?;
        let mut journal = self.journal.lock().map_err(|_| Failure::new(source, Reason::Poisoned))?;
        journal.last_loop_result[source.slot()] = Some(code);
        self.last_loop_ns[source.slot()].store(at, Ordering::SeqCst);
        Ok(())
    }
    fn note_receipt(&self, event: Event) -> Check<()> {
        let at = boot_time(Source::Kqueue)?;
        let mut journal = self.journal.lock().map_err(|_| input_error(Reason::Poisoned))?;
        if journal.receipts.len() >= MAX_RECEIPTS { return Err(input_error(Reason::FailureOverflow)); }
        journal.receipts.push((event, at));
        Ok(())
    }
    fn phase_current(&self, source: Source) -> Check<()> {
        self.usable(source)?;
        let slot = source.slot();
        if slot >= 2 || !self.running[slot].load(Ordering::SeqCst) || self.phase[slot].load(Ordering::SeqCst) != ARMED {
            Err(Failure::new(source, Reason::Unarmed))
        } else { Ok(()) }
    }
    fn error(&self, reason: &'static str) -> EnclaveError {
        let first = match self.journal.lock() {
            Ok(journal) => journal.first,
            Err(_) => Some(Failure::new(Source::Owner, Reason::Poisoned)),
        };
        EnclaveError::with(Errno::EACCES, reason, format!("{first:?}"))
    }
}
// This deadline is a conservative scheduling cap only, not measured repair
// latency, complete-root mutation authority or installed transaction evidence.
const REPAIR_LIMIT: std::time::Duration = std::time::Duration::from_millis(1000);
#[derive(Clone, Copy)]
struct NativeRepairWindow { allocation: usize, source: Source, started: Instant, end: Instant }
#[derive(Clone, Copy)]
struct RepairBounds { started: Instant, end: Instant }
struct NativeRepairObservation {
    shared: Arc<Shared>, window: Option<NativeRepairWindow>, completed: bool,
}
impl NativeRepairObservation {
    fn window(&self) -> NativeRepairWindow { self.window.expect("admitted original native observation") }
    fn complete(mut self) { self.completed = true; }
}
impl Drop for NativeRepairObservation {
    fn drop(&mut self) {
        if !self.completed {
            self.shared.terminal_veto();
            self.shared.repair_unknown.store(true, Ordering::SeqCst);
        }
        if self.shared.repair_native_active.try_update(Ordering::SeqCst, Ordering::SeqCst,
            |value| value.checked_sub(1)).is_err() {
            self.shared.terminal_veto();
            self.shared.repair_unknown.store(true, Ordering::SeqCst);
        }
    }
}
struct RepairDispatch<'a> { shared: &'a Shared, completed: bool }
impl RepairDispatch<'_> { fn complete(mut self) { self.completed = true; } }
impl Drop for RepairDispatch<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.shared.terminal_veto();
            self.shared.repair_unknown.store(true, Ordering::SeqCst);
        }
    }
}
impl Shared {
    fn repair_trigger_unknown(&self) -> bool {
        #[cfg(target_os = "macos")]
        if native::orphaned_callback() { return true; }
        self.repair_unknown.load(Ordering::SeqCst)
    }
    fn begin_repair_observation(self: &Arc<Self>, source: Source, deadline: Instant)
        -> Check<NativeRepairObservation> {
        // Count BEFORE reading closed and BEFORE any actual native entry.
        // A handoff closes admission BEFORE reading this same SeqCst count.
        if self.repair_native_active.try_update(Ordering::SeqCst, Ordering::SeqCst,
            |value| value.checked_add(1)).is_err() {
            self.terminal_veto(); self.repair_unknown.store(true, Ordering::SeqCst);
            return Err(Failure::new(source, Reason::RepairObservationUnknown));
        }
        // A counted entry has its unwind/failure guard before any fallible work.
        let mut observation = NativeRepairObservation { shared: self.clone(), window: None, completed: false };
        if self.repair_closed.load(Ordering::SeqCst) {
            return Err(Failure::new(source, Reason::RepairObservationClosed));
        }
        if source.slot() >= 2 || self.repair_trigger_unknown() {
            return Err(Failure::new(source, Reason::RepairObservationUnknown));
        }
        self.binding.endpoint(deadline)?;
        let started = Instant::now();
        let end = started.checked_add(REPAIR_LIMIT)
            .ok_or(Failure::new(source, Reason::Clock))?.min(deadline).min(self.binding.end);
        within(end, source)?;
        observation.window = Some(NativeRepairWindow { allocation: Arc::as_ptr(self) as usize,
            source, started, end });
        Ok(observation)
    }
    fn begin_repair_dispatch(&self, source: Source, window: Option<NativeRepairWindow>) -> RepairDispatch<'_> {
        // Original ceremony veto precedes trigger-state locks/clocks and parsing.
        self.terminal_veto();
        let guard = RepairDispatch { shared: self, completed: false };
        let Some(window) = window else {
            self.repair_unknown.store(true, Ordering::SeqCst); return guard;
        };
        let now = Instant::now();
        if window.allocation != self as *const Self as usize || window.source != source
            || window.started > now || window.end <= now || window.end > self.binding.end
            || window.end > window.started.checked_add(REPAIR_LIMIT).unwrap_or(window.started)
            || self.repair_native_active.load(Ordering::SeqCst) == 0 {
            self.repair_unknown.store(true, Ordering::SeqCst); return guard;
        }
        match self.repair_bounds.try_lock() {
            Ok(mut retained) => {
                *retained = Some(match *retained {
                    Some(original) => RepairBounds { started: original.started.min(window.started),
                        end: original.end.min(window.end) },
                    None => RepairBounds { started: window.started, end: window.end },
                });
            }
            Err(_) => self.repair_unknown.store(true, Ordering::SeqCst),
        }
        guard
    }
    fn dispatch_observed_event(&self, window: NativeRepairWindow, event: Event, registered: &[usize]) -> Check<()> {
        if event.filter == FILTER_TIMER { return self.dispatch_event(event, registered); }
        let guard = self.begin_repair_dispatch(Source::Kqueue, Some(window));
        let result = self.dispatch_event(event, registered);
        if result.is_ok() { guard.complete(); }
        result
    }
    fn dispatch_observed_callback(&self, window: Option<NativeRepairWindow>, parse: impl FnOnce() -> Check<()>) -> Check<()> {
        let guard = self.begin_repair_dispatch(Source::DynamicStore, window);
        let result = self.dispatch_callback(parse);
        if result.is_ok() { guard.complete(); }
        result
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RepairRequestRefusal { AlreadyClaimed, MissingTrigger, TriggerUnknown,
    NativeObservationPending, OriginalVetoRequired, Deadline }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RepairExecutionGap { IndependentRootMutationAuthorityAndInstalledTransaction }
/// Own SAME notification Resources, including unfinished/uncertain originals.
/// A negative scheduling request has no executor/command/authority conversion.
pub(super) struct RepairRequest {
    owner: PfNotifications, endpoint: Option<Instant>, refusal: Option<RepairRequestRefusal>,
}
impl RepairRequest {
    pub(super) fn execution_gap(&self) -> RepairExecutionGap {
        RepairExecutionGap::IndependentRootMutationAuthorityAndInstalledTransaction
    }
    pub(super) fn require_pending_until(&mut self, requested: Instant) -> Result<Instant, RepairRequestRefusal> {
        if let Some(refusal) = self.refusal { return Err(refusal); }
        let result = (|| {
            let shared = &self.owner.shared;
            if !shared.repair_closed.load(Ordering::SeqCst) || shared.repair_trigger_unknown() {
                return Err(RepairRequestRefusal::TriggerUnknown);
            }
            if shared.repair_native_active.load(Ordering::SeqCst) != 0 {
                return Err(RepairRequestRefusal::NativeObservationPending);
            }
            // Passive original negative bits only. Never require_current() on
            // a revoked ceremony or turn that ceremony into repair permission.
            let ceremony_revoked = match &shared.binding.session {
                BoundSession::Native(session) => session.require_not_revoked().is_err(),
                #[cfg(test)] BoundSession::Fixture(session) => session.load(Ordering::SeqCst),
            };
            if !shared.revoked.load(Ordering::SeqCst) || !shared.stop.load(Ordering::SeqCst)
                || !shared.binding.supervisor_stop.load(Ordering::SeqCst) || !ceremony_revoked {
                return Err(RepairRequestRefusal::OriginalVetoRequired);
            }
            let bounds = *shared.repair_bounds.try_lock().map_err(|_| RepairRequestRefusal::TriggerUnknown)?;
            let bounds = bounds.ok_or(RepairRequestRefusal::MissingTrigger)?;
            let end = self.endpoint.ok_or(RepairRequestRefusal::MissingTrigger)?
                .min(bounds.end).min(shared.binding.end).min(requested);
            if Instant::now() >= end { return Err(RepairRequestRefusal::Deadline); }
            if shared.repair_trigger_unknown()
                || shared.repair_native_active.load(Ordering::SeqCst) != 0 {
                return Err(RepairRequestRefusal::TriggerUnknown);
            }
            Ok(end)
        })();
        match result {
            Ok(end) => { self.endpoint = Some(end); Ok(end) }
            Err(refusal) => { self.owner.shared.terminal_veto(); self.refusal = Some(refusal); Err(refusal) }
        }
    }
}
impl PfNotifications {
    pub(super) fn into_repair_request(self) -> RepairRequest {
        // Close FIRST. Later counted entrants see closed and cannot call native.
        // Earlier entrants either completed or are seen in flight and refuse.
        let claimed = self.shared.repair_closed.swap(true, Ordering::SeqCst);
        self.shared.terminal_veto();
        let mut refusal = if claimed { Some(RepairRequestRefusal::AlreadyClaimed) } else { None };
        if self.shared.repair_native_active.load(Ordering::SeqCst) != 0 {
            refusal.get_or_insert(RepairRequestRefusal::NativeObservationPending);
        }
        if self.shared.repair_trigger_unknown() { refusal.get_or_insert(RepairRequestRefusal::TriggerUnknown); }
        let endpoint = match self.shared.repair_bounds.try_lock() {
            Ok(bounds) => bounds.map(|bounds| bounds.end),
            Err(_) => { refusal.get_or_insert(RepairRequestRefusal::TriggerUnknown); None }
        };
        if endpoint.is_none() { refusal.get_or_insert(RepairRequestRefusal::MissingTrigger); }
        RepairRequest { owner: self, endpoint, refusal }
    }
}

fn within(deadline: Instant, source: Source) -> Check<()> {
    if Instant::now() >= deadline { Err(Failure::new(source, Reason::Deadline)) } else { Ok(()) }
}
fn boot_time(source: Source) -> Check<u64> {
    match crate::clock::boot_clock_ns() {
        u64::MAX => Err(Failure::new(source, Reason::Clock)),
        value => Ok(value),
    }
}
fn context_current(checked: &'static CheckedDeploymentTarget, deadline: Instant) -> Check<()> {
    within(deadline, Source::Owner)?;
    if !cfg!(target_os = "macos") { return Err(Failure::new(Source::Owner, Reason::NativeRequired)); }
    if unsafe { libc::geteuid() } != 0 { return Err(Failure::new(Source::Owner, Reason::RootRequired)); }
    let actual = deployment::selected().ok_or(Failure::new(Source::Owner, Reason::SelectionRequired))?;
    if !std::ptr::eq(actual, checked) { return Err(Failure::new(Source::Owner, Reason::ContextChanged)); }
    let target = actual.target();
    if target.role != DeploymentRole::DedicatedTest || target.profile != Profile::L2
        || target.signing_identity_mode != DeploymentSigningMode::LocalPins
        || crate::codesign::signing_mode() != crate::codesign::SigningMode::LocalPins
        || target.broker.is_some() || !target.shared_read_only_inputs.is_empty() {
        return Err(Failure::new(Source::Owner, Reason::UnsupportedScope));
    }
    deployment::upgrade::assert_start_allowed(actual).map_err(|_| Failure::new(Source::Owner, Reason::UpgradeDenied))?;
    within(deadline, Source::Owner)
}

struct Challenge { deadline: Instant, reply: mpsc::SyncSender<WorkerReceipt> }
#[derive(Debug)]
struct WorkerReceipt { source: Source, observed_boot_ns: u64, generation: u64, ticks: u64 }
struct WorkerEndpoint { source: Source, requests: mpsc::SyncSender<Challenge> }
struct WorkerFlow { source: Source, requests: mpsc::Receiver<Challenge>, shared: Arc<Shared> }
impl WorkerEndpoint {
    fn pair(source: Source, shared: Arc<Shared>) -> (Self, WorkerFlow) {
        let (requests, receiver) = mpsc::sync_channel(1);
        (Self { source, requests }, WorkerFlow { source, requests: receiver, shared })
    }
    fn request(&self, shared: &Shared, deadline: Instant) -> Check<mpsc::Receiver<WorkerReceipt>> {
        shared.phase_current(self.source)?;
        within(deadline, self.source)?;
        let (reply, receiver) = mpsc::sync_channel(1);
        self.requests.try_send(Challenge { deadline, reply }).map_err(|error| Failure::new(self.source,
            match error { mpsc::TrySendError::Full(_) => Reason::ChannelBusy, mpsc::TrySendError::Disconnected(_) => Reason::ChannelClosed }))?;
        Ok(receiver)
    }
    fn receive(&self, shared: &Shared, receiver: mpsc::Receiver<WorkerReceipt>, deadline: Instant) -> Check<WorkerReceipt> {
        let remaining = deadline.checked_duration_since(Instant::now()).ok_or(Failure::new(self.source, Reason::Deadline))?;
        let receipt = receiver.recv_timeout(remaining).map_err(|error| Failure::new(self.source,
            match error { mpsc::RecvTimeoutError::Timeout => Reason::Deadline, mpsc::RecvTimeoutError::Disconnected => Reason::ReplyClosed }))?;
        within(deadline, self.source)?;
        shared.phase_current(self.source)?;
        if receipt.source != self.source { return Err(Failure::new(self.source, Reason::LateReply)); }
        Ok(receipt)
    }
}
impl WorkerFlow {
    fn next(&self) -> Check<Option<Challenge>> {
        match self.requests.try_recv() {
            Ok(request) => { within(request.deadline, self.source)?; Ok(Some(request)) }
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Err(Failure::new(self.source, Reason::ChannelClosed)),
        }
    }
    /// Called only by the original resource-owning worker AFTER native iteration
    /// and original/context checks. A channel/helper cannot establish native facts.
    fn acknowledge(&self, challenge: Challenge) -> Check<()> {
        self.shared.phase_current(self.source)?;
        within(challenge.deadline, self.source)?;
        let receipt = WorkerReceipt { source: self.source, observed_boot_ns: boot_time(self.source)?,
            generation: self.shared.generation.load(Ordering::SeqCst), ticks: self.shared.ticks.load(Ordering::SeqCst) };
        challenge.reply.try_send(receipt).map_err(|_| Failure::new(self.source, Reason::ReplyClosed))
    }
}
struct WorkerExit { shared: Arc<Shared>, source: Source }
impl Drop for WorkerExit {
    fn drop(&mut self) {
        self.shared.terminal_veto();
        self.shared.phase[self.source.slot()].store(STOPPED, Ordering::SeqCst);
        self.shared.running[self.source.slot()].store(false, Ordering::SeqCst);
        if thread::panicking() { self.shared.record(Failure::new(self.source, Reason::Unwound), false); }
    }
}

/// One allocation owns both original thread handles, even after refused startup
/// or an expired stop endpoint. No Clone, deserialization or external constructor.
pub(super) struct Resources {
    shared: Arc<Shared>, checked: Option<&'static CheckedDeploymentTarget>,
    endpoints: [WorkerEndpoint; 2], workers: [Option<JoinHandle<()>>; 2],
}
pub(super) struct PfNotifications { resources: Option<Box<Resources>> }
impl std::ops::Deref for PfNotifications {
    type Target = Resources;
    fn deref(&self) -> &Resources { self.resources.as_deref().expect("original notification bundle retained") }
}
impl std::ops::DerefMut for PfNotifications {
    fn deref_mut(&mut self) -> &mut Resources { self.resources.as_deref_mut().expect("original notification bundle retained") }
}
static RETAINED: OnceLock<Box<Resources>> = OnceLock::new();
static RETENTION_COLLISIONS: AtomicU64 = AtomicU64::new(0);
fn retain_bundle(slot: &OnceLock<Box<Resources>>, bundle: Box<Resources>) {
    if let Err(bundle) = slot.set(bundle) {
        // Preserve the exact owner even after an unexpected second insertion.
        // No blocking registry lock, native cleanup, retry or lost JoinHandle.
        bundle.shared.terminal_veto();
        let _ = RETENTION_COLLISIONS.try_update(Ordering::SeqCst, Ordering::SeqCst, |v| Some(v.saturating_add(1)));
        std::mem::forget(bundle);
    }
}
fn retire_bundle(slot: &OnceLock<Box<Resources>>, bundle: Box<Resources>) {
    bundle.shared.terminal_veto();
    if bundle.needs_retention() { retain_bundle(slot, bundle); }
}
impl Resources {
    fn join_finished(&mut self) {
        for (index, worker) in self.workers.iter_mut().enumerate() {
            if worker.as_ref().is_some_and(JoinHandle::is_finished) {
                if worker.take().expect("finished original handle retained").join().is_err() {
                    self.shared.record_stop(Failure::new(if index == 0 {Source::Kqueue} else {Source::DynamicStore}, Reason::Unwound));
                }
            }
        }
    }
    fn needs_retention(&self) -> bool {
        self.workers.iter().any(Option::is_some)
            || self.shared.stop_uncertain()
            || self.shared.resources.iter().any(|v| v.load(Ordering::SeqCst) != 0)
            || self.shared.registrations.iter().any(|v| v.load(Ordering::SeqCst) != 0)
            || match self.shared.journal.try_lock() { Ok(journal) => !journal.cleanup.is_empty() || journal.overflow, Err(_) => true }
    }
}
#[derive(Debug)]
pub(super) struct NotificationAccounting {
    retained_thread_handles: usize, running: [bool; 2], phases: [u8; 2],
    owned_fds_live_or_close_uncertain: u64, owned_cf_references_not_yet_released: u64,
    vnode_timer_registered_or_queue_close_unknown: u64, sc_patterns_registered_or_server_cleanup_unknown: u64,
    last_loop_boot_ns: [u64; 2], last_invalidation_boot_ns: [u64; 2],
    first_failure: Option<Failure>, retained_failures: usize, retained_cleanup_failures: usize,
    native_registration_receipts: usize, journal_overflow: bool,
    retention_collisions_unknown: u64,
    stop_pending: bool, stop_evidence_unknown: bool, joined_unwind_sources: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SessionContinuity { UnavailablePublicContract }
/// Narrow local component observations only; this value cannot grant enforcement.
pub(super) struct NotificationProgress {
    allocation: Arc<Shared>,
    generation: u64, ticks: u64, source_bits: u8, unstable: bool,
    started_boot_ns: u64, ended_boot_ns: u64, worker_boot_ns: [u64; 2],
    session_continuity: SessionContinuity,
}
impl std::fmt::Debug for NotificationProgress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotificationComponents").field("generation", &self.generation)
            .field("timer_sequence", &self.ticks).field("source_bits", &self.source_bits)
            .field("changed_during_observation", &self.unstable)
            .field("started_boot_ns", &self.started_boot_ns).field("ended_boot_ns", &self.ended_boot_ns)
            .field("worker_boot_ns", &self.worker_boot_ns)
            .field("session_continuity", &self.session_continuity).finish()
    }
}
impl NotificationProgress {
    pub(super) fn invalidation_generation(&self) -> u64 { self.generation }
    pub(super) fn timer_sequence(&self) -> u64 { self.ticks }
    pub(super) fn changed_during_observation(&self) -> bool { self.unstable }
    pub(super) fn session_continuity(&self) -> SessionContinuity { self.session_continuity }
}

/// Same-original negative collection checks only. Production has one
/// implementation, the borrowed actual notification owner below. A successful
/// check proves neither undelivered-event absence nor configd continuity.
mod negative_collection_seal {
    // The module path is private. Non-test builds admit only the actual
    // borrowed notification window; fixture implementations exist only in tests.
    pub trait Sealed {}
    #[cfg(test)]
    impl<T: ?Sized> Sealed for T {}
}
#[cfg(not(test))]
impl negative_collection_seal::Sealed for NegativeCollectionWindow<'_> {}
pub(super) trait NegativeCollectionCheck: negative_collection_seal::Sealed {
    fn require_current(&self, end: Instant) -> EnclaveResult<()>;
    fn require_same_original(&self,
        session: &Arc<crate::power::selected_owner_session::SelectedOwnerSession>,
        stop: &Arc<AtomicBool>, end: Instant) -> EnclaveResult<()>;
    fn complete(self, end: Instant) -> EnclaveResult<()> where Self: Sized;
}
struct CollectionFailureVeto<'a> { shared: &'a Shared, armed: bool }
impl Drop for CollectionFailureVeto<'_> {
    fn drop(&mut self) { if self.armed { self.shared.terminal_veto(); } }
}
/// The borrow retains the SAME Resources owner, actual JoinHandles and native
/// originals throughout collection. Generation is sampled only AFTER the
/// required fresh worker challenges. No challenge is issued inside the window:
/// configd queries deliberately invalidate generation, including healthy ones.
/// Ordinary worker progress can therefore conservatively refuse this window.
/// No Clone/reset/public constructor, positive permit or readiness term.
pub(super) struct NegativeCollectionWindow<'a> {
    owner: &'a PfNotifications, allocation: Arc<Shared>, generation: u64,
    end: Instant, armed: bool,
}
impl<'a> NegativeCollectionWindow<'a> {
    fn from_progress(owner: &'a PfNotifications, progress: NotificationProgress, end: Instant) -> Check<Self> {
        if !Arc::ptr_eq(&owner.shared, &progress.allocation) {
            // Refuse both actual domains, never adopt a foreign allocation
            // merely because its numeric generation happens to be equal.
            owner.shared.terminal_veto(); progress.allocation.terminal_veto();
            return Err(Failure::new(Source::Owner, Reason::OriginalBinding));
        }
        let window = Self { owner, allocation: progress.allocation, generation: progress.generation,
            end: end.min(owner.shared.binding.end), armed: true };
        window.check(end)?;
        Ok(window)
    }
    fn negative_current(&self, requested: Instant) -> Check<()> {
        within(requested.min(self.end), Source::Owner)?;
        if !Arc::ptr_eq(&self.owner.shared, &self.allocation) {
            return Err(Failure::new(Source::Owner, Reason::OriginalBinding));
        }
        if self.allocation.binding.revoked() || self.allocation.revoked.load(Ordering::SeqCst)
            || self.allocation.stop.load(Ordering::SeqCst) || self.allocation.stop_uncertain() {
            return Err(Failure::new(Source::Owner, Reason::Stopped));
        }
        if self.allocation.generation.load(Ordering::SeqCst) != self.generation {
            return Err(Failure::new(Source::Owner, Reason::CollectionChanged));
        }
        if self.allocation.journal.is_poisoned() {
            return Err(Failure::new(Source::Owner, Reason::Poisoned));
        }
        for source in [Source::Kqueue, Source::DynamicStore] {
            if !self.allocation.running[source.slot()].load(Ordering::SeqCst)
                || self.allocation.phase[source.slot()].load(Ordering::SeqCst) != ARMED {
                return Err(Failure::new(source, Reason::Unarmed));
            }
        }
        Ok(())
    }
    fn check(&self, requested: Instant) -> Check<()> {
        // All fast negative/generation checks precede potentially blocking
        // actual session work; the armed veto also covers errors and unwind.
        let mut veto = CollectionFailureVeto { shared: &self.allocation, armed: true };
        self.negative_current(requested)?;
        self.owner.handles_current()?;
        self.negative_current(requested)?;
        self.allocation.binding.endpoint(requested.min(self.end))?;
        self.negative_current(requested)?;
        veto.armed = false;
        Ok(())
    }
}
impl NegativeCollectionCheck for NegativeCollectionWindow<'_> {
    fn require_current(&self, end: Instant) -> EnclaveResult<()> {
        self.check(end).map_err(|error| {
            // check's atomic veto precedes any journal acquisition/reporting.
            self.allocation.record(error, false);
            self.allocation.error("PF_NOTIFICATION_COLLECTION_WINDOW_REFUSED")
        })
    }
    fn require_same_original(&self,
        session: &Arc<crate::power::selected_owner_session::SelectedOwnerSession>,
        stop: &Arc<AtomicBool>, end: Instant) -> EnclaveResult<()> {
        let mut veto = CollectionFailureVeto { shared: &self.allocation, armed: true };
        self.require_current(end)?;
        self.owner.require_same_original(session, stop, end.min(self.end))?;
        self.require_current(end)?;
        veto.armed = false;
        Ok(())
    }
    fn complete(mut self, end: Instant) -> EnclaveResult<()> {
        self.require_current(end)?;
        self.armed = false;
        Ok(())
    }
}
impl Drop for NegativeCollectionWindow<'_> {
    fn drop(&mut self) { if self.armed { self.allocation.terminal_veto(); } }
}

/// Every native descriptor is owned before its first fallible inspection.
/// Teardown revokes first, closes once and retains an independent numeric error.
struct OwnedFile { file: Option<File>, shared: Arc<Shared>, resource: u16 }
impl OwnedFile {
    unsafe fn take(fd: i32, shared: Arc<Shared>, resource: u16) -> Self {
        let owned = Self { file: Some(unsafe { File::from_raw_fd(fd) }), shared, resource };
        owned.shared.resource_acquired(Source::Kqueue);
        owned
    }
    fn file(&self) -> &File { self.file.as_ref().expect("owned file not released before Drop") }
    fn fd(&self) -> i32 { self.file().as_raw_fd() }
}
impl Drop for OwnedFile {
    fn drop(&mut self) {
        self.shared.terminal_veto();
        if let Some(file) = self.file.take() {
            let fd = file.into_raw_fd();
            if unsafe { libc::close(fd) } != 0 {
                self.shared.record(Failure { source: Source::Kqueue, reason: Reason::Close,
                    code: std::io::Error::last_os_error().raw_os_error(), resource: Some(self.resource) }, true);
            } else {
                self.shared.resource_released(Source::Kqueue);
                if self.resource == (4 * MAX_NODES) as u16 { self.shared.registrations[0].store(0, Ordering::SeqCst); }
            }
        }
    }
}
#[derive(Clone)]
enum Protection {
    NativeRoot,
    #[cfg(test)]
    Fixture { uid: u32, root: PathBuf },
}
impl Protection {
    fn uid(&self) -> u32 {
        match self {
            Self::NativeRoot => 0,
            #[cfg(test)] Self::Fixture { uid, .. } => *uid,
        }
    }
    fn descriptor(&self, file: &File) -> Check<()> {
        let access = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
        if access < 0 || access & libc::O_ACCMODE != libc::O_RDONLY || access & libc::O_NONBLOCK == 0
            || flags < 0 || flags & libc::FD_CLOEXEC == 0 {
            return Err(Failure::new(Source::Kqueue, Reason::DescriptorFlags));
        }
        match self {
            Self::NativeRoot => native_empty_acl(file),
            #[cfg(test)] Self::Fixture { .. } => Ok(()), // Explicitly not native ACL evidence.
        }
    }
}
fn native_empty_acl(file: &File) -> Check<()> {
    #[cfg(target_os = "macos")]
    {
        use std::ffi::c_void;
        unsafe extern "C" {
            fn acl_get_fd_np(fd: i32, kind: i32) -> *mut c_void;
            fn acl_valid(acl: *mut c_void) -> i32;
            fn acl_get_entry(acl: *mut c_void, id: i32, entry: *mut *mut c_void) -> i32;
            fn acl_free(object: *mut c_void) -> i32;
        }
        unsafe { *libc::__error() = 0; }
        let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), 0x100) };
        let code = std::io::Error::last_os_error().raw_os_error();
        if acl.is_null() {
            return if code == Some(libc::ENOENT) { Ok(()) }
                else { Err(Failure::new(Source::Kqueue, Reason::AclInspection)) };
        }
        let valid = unsafe { acl_valid(acl) };
        let mut entry = std::ptr::null_mut();
        let found = unsafe { acl_get_entry(acl, 0, &mut entry) };
        let code = std::io::Error::last_os_error().raw_os_error();
        let freed = unsafe { acl_free(acl) };
        if valid != 0 || found != -1 || code != Some(libc::EINVAL) || freed != 0 {
            return Err(Failure::new(Source::Kqueue, Reason::AclRefused));
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    { let _ = file; Err(Failure::new(Source::Kqueue, Reason::AclUnavailable)) }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role { Descriptor, RootPolicy, LlmPolicy, CasPolicy }
impl Role { fn resource_base(self) -> u16 { self as u16 * MAX_NODES as u16 } }
enum Expected { Descriptor(String), Canonical(&'static [u8]), RootPolicy }
struct InputSpec { role: Role, path: PathBuf, maximum: usize, expected: Expected }
impl InputSpec {
    fn compare(&self, bytes: &[u8]) -> Check<()> {
        let reason = match &self.expected {
            Expected::Descriptor(expected) if hex::encode(Sha256::digest(bytes)) != *expected => Some(Reason::DescriptorMismatch),
            Expected::Canonical(expected) if bytes != *expected => Some(Reason::CanonicalMismatch),
            Expected::RootPolicy if bytes != super::pf_restore_input::render_root_filter() => Some(Reason::CanonicalMismatch),
            _ => None,
        };
        reason.map_or(Ok(()), |reason| Err(Failure::new(Source::Kqueue, reason)))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stamp {
    dev: u64, ino: u64, uid: u32, gid: u32, mode: u32,
    file: Option<(u64, u64, i64, i64, i64, i64)>,
}
impl Stamp {
    fn of(metadata: &Metadata, leaf: bool) -> Self {
        Self { dev: metadata.dev(), ino: metadata.ino(), uid: metadata.uid(), gid: metadata.gid(), mode: metadata.mode(),
            file: leaf.then(|| (metadata.len(), metadata.nlink(), metadata.mtime(), metadata.mtime_nsec(),
                metadata.ctime(), metadata.ctime_nsec())) }
    }
}
struct Node { owned: OwnedFile, name: CString, stamp: Option<Stamp> }
struct HeldRoute {
    spec: InputSpec, protection: Protection, nodes: Vec<Node>, admitted: bool, digest: Option<[u8; 32]>,
}
struct Originals { routes: Vec<HeldRoute>, shared: Arc<Shared> }
fn input_error(reason: Reason) -> Failure { Failure::new(Source::Kqueue, reason) }
fn named_stat(parent: Option<&File>, name: &CString) -> Check<libc::stat> {
    let mut result: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(parent.map_or(libc::AT_FDCWD, AsRawFd::as_raw_fd), name.as_ptr(),
        &mut result, libc::AT_SYMLINK_NOFOLLOW) } != 0 { return Err(input_error(Reason::InputMetadata)); }
    Ok(result)
}
fn named_matches(named: &libc::stat, held: &Metadata) -> bool {
    named.st_dev as u64 == held.dev() && named.st_ino as u64 == held.ino()
        && named.st_mode as u32 == held.mode() && named.st_uid == held.uid() && named.st_gid == held.gid()
        && (!held.is_file() || (named.st_size >= 0 && named.st_size as u64 == held.len()
            && named.st_nlink as u64 == held.nlink()))
}
fn metadata_safe(metadata: &Metadata, leaf: bool, protection: &Protection, spec: &InputSpec) -> Check<()> {
    if (leaf && !metadata.is_file()) || (!leaf && !metadata.is_dir()) { return Err(input_error(Reason::InputType)); }
    if metadata.uid() != protection.uid() || metadata.mode() & 0o022 != 0
        || (leaf && spec.role != Role::Descriptor && metadata.mode() & 0o7777 != 0o644) {
        return Err(input_error(Reason::InputProtection));
    }
    if leaf && metadata.nlink() != 1 { return Err(input_error(Reason::InputLinks)); }
    if leaf && (metadata.len() == 0 || metadata.len() > spec.maximum as u64) { return Err(input_error(Reason::InputSize)); }
    Ok(())
}
fn read_original(file: &File, maximum: usize, deadline: Instant) -> Check<Vec<u8>> {
    within(deadline, Source::Kqueue)?;
    let before = file.metadata().map_err(|_| input_error(Reason::InputMetadata))?;
    if !before.is_file() { return Err(input_error(Reason::InputType)); }
    if before.len() == 0 || before.len() > maximum as u64 { return Err(input_error(Reason::InputSize)); }
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        within(deadline, Source::Kqueue)?;
        let wanted = buffer.len().min(maximum + 1 - bytes.len());
        if wanted == 0 { return Err(input_error(Reason::InputSize)); }
        let count = file.read_at(&mut buffer[..wanted], bytes.len() as u64).map_err(|_| input_error(Reason::InputRead))?;
        if count == 0 { break; }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len() > maximum { return Err(input_error(Reason::InputSize)); }
    }
    let after = file.metadata().map_err(|_| input_error(Reason::InputMetadata))?;
    if Stamp::of(&before, true) != Stamp::of(&after, true) || bytes.len() as u64 != before.len() {
        return Err(input_error(Reason::InputChanged));
    }
    within(deadline, Source::Kqueue)?;
    Ok(bytes)
}
impl HeldRoute {
    fn new(spec: InputSpec, protection: Protection) -> Self {
        Self { spec, protection, nodes: Vec::new(), admitted: false, digest: None }
    }
    fn retain(&mut self, fd: i32, name: CString, shared: &Arc<Shared>, leaf: bool) -> Check<()> {
        let resource = self.spec.role.resource_base() + self.nodes.len() as u16;
        self.nodes.push(Node { owned: unsafe { OwnedFile::take(fd, shared.clone(), resource) }, name, stamp: None });
        let node = self.nodes.last_mut().expect("opened file retained first");
        let metadata = node.owned.file().metadata().map_err(|_| input_error(Reason::InputMetadata))?;
        node.stamp = Some(Stamp::of(&metadata, leaf));
        metadata_safe(&metadata, leaf, &self.protection, &self.spec)?;
        self.protection.descriptor(node.owned.file())
    }
    fn open(&mut self, shared: &Arc<Shared>, deadline: Instant) -> Check<()> {
        within(deadline, Source::Kqueue)?;
        deployment::normalized_path(&self.spec.path).map_err(|_| input_error(Reason::InvalidPath))?;
        let (root, relative) = match &self.protection {
            Protection::NativeRoot => (Path::new("/"), self.spec.path.as_path()),
            #[cfg(test)] Protection::Fixture { root, .. } =>
                (root.as_path(), self.spec.path.strip_prefix(root).map_err(|_| input_error(Reason::InvalidPath))?),
        };
        let names: Vec<CString> = relative.components().filter_map(|part| match part {
            Component::Normal(name) => Some(CString::new(name.as_bytes()).map_err(|_| input_error(Reason::InvalidPath))), _ => None,
        }).collect::<Check<_>>()?;
        if names.is_empty() || names.len() + 1 > MAX_NODES { return Err(input_error(Reason::InvalidPath)); }
        let root = CString::new(root.as_os_str().as_bytes()).map_err(|_| input_error(Reason::InvalidPath))?;
        let fd = unsafe { libc::open(root.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC) };
        if fd < 0 { return Err(input_error(Reason::InputOpen)); }
        self.retain(fd, root, shared, false)?;
        let count = names.len();
        for (index, name) in names.into_iter().enumerate() {
            within(deadline, Source::Kqueue)?;
            let leaf = index + 1 == count;
            let parent = self.nodes.last().expect("retained root").owned.file();
            let named = named_stat(Some(parent), &name)?;
            let required = if leaf { libc::S_IFREG } else { libc::S_IFDIR };
            if named.st_mode & libc::S_IFMT != required { return Err(input_error(Reason::InputType)); }
            let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC
                | if leaf { 0 } else { libc::O_DIRECTORY };
            let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
            if fd < 0 { return Err(input_error(Reason::InputOpen)); }
            self.retain(fd, name, shared, leaf)?;
            let metadata = self.nodes.last().expect("retained node").owned.file().metadata().map_err(|_| input_error(Reason::InputMetadata))?;
            if !named_matches(&named, &metadata) { return Err(input_error(Reason::InputChanged)); }
        }
        let bytes = read_original(self.nodes.last().expect("retained leaf").owned.file(), self.spec.maximum, deadline)?;
        self.digest = Some(Sha256::digest(&bytes).into());
        self.spec.compare(&bytes)?;
        self.inspect(deadline)?;
        self.admitted = true;
        Ok(())
    }
    fn inspect(&self, deadline: Instant) -> Check<()> {
        for (index, node) in self.nodes.iter().enumerate() {
            within(deadline, Source::Kqueue)?;
            let leaf = node.stamp.is_some_and(|stamp| stamp.file.is_some());
            let metadata = node.owned.file().metadata().map_err(|_| input_error(Reason::InputMetadata))?;
            metadata_safe(&metadata, leaf, &self.protection, &self.spec)?;
            self.protection.descriptor(node.owned.file())?;
            if node.stamp != Some(Stamp::of(&metadata, leaf)) { return Err(input_error(Reason::InputChanged)); }
            let parent = index.checked_sub(1).map(|index| self.nodes[index].owned.file());
            if !named_matches(&named_stat(parent, &node.name)?, &metadata) { return Err(input_error(Reason::InputChanged)); }
        }
        Ok(())
    }
    fn current(&self, deadline: Instant) -> Check<()> {
        self.inspect(deadline)?;
        if !self.admitted { return Err(input_error(Reason::InputIncomplete)); }
        let file = self.nodes.last().ok_or(input_error(Reason::InputIncomplete))?.owned.file();
        let bytes = read_original(file, self.spec.maximum, deadline)?;
        let actual: [u8; 32] = Sha256::digest(&bytes).into();
        if Some(actual) != self.digest { return Err(input_error(Reason::InputChanged)); }
        self.spec.compare(&bytes)?;
        self.inspect(deadline)
    }
}
impl Originals {
    fn open(&mut self, specs: Vec<InputSpec>, protection: Protection, deadline: Instant) -> Check<()> {
        if specs.len() != 4 || !self.routes.is_empty() { return Err(input_error(Reason::InputIncomplete)); }
        let mut first = None;
        for spec in specs {
            let mut route = HeldRoute::new(spec, protection.clone());
            let result = route.open(&self.shared, deadline);
            self.routes.push(route); // Preserve all partial originals on refusal.
            if let Err(error) = result { self.shared.record(error, false); first.get_or_insert(error); }
        }
        first.map_or(Ok(()), Err)
    }
    fn current(&self, deadline: Instant) -> Check<()> {
        let mut first = None;
        if self.routes.len() != 4 { first = Some(input_error(Reason::InputIncomplete)); }
        for route in &self.routes {
            if let Err(error) = route.current(deadline) { self.shared.record(error, false); first.get_or_insert(error); }
        }
        first.map_or(Ok(()), Err)
    }
}

// These constants come from the actual SDK27.2 header and public XNU source.
// Numeric classifiers are shared with software tests; they do not register a
// native-success test provider or establish actual native component health.
const FILTER_VNODE: i16 = -4;
const FILTER_TIMER: i16 = -7;
const ADD: u16 = 0x01;
const DELETE: u16 = 0x02;
const ENABLE: u16 = 0x04;
const CLEAR: u16 = 0x20;
const RECEIPT: u16 = 0x40;
const ERROR: u16 = 0x4000;
const EOF: u16 = 0x8000;
const NOTE_DELETE_: u32 = 0x01;
const NOTE_WRITE_: u32 = 0x02;
const NOTE_EXTEND_: u32 = 0x04;
const NOTE_ATTRIB_: u32 = 0x08;
const NOTE_LINK_: u32 = 0x10;
const NOTE_RENAME_: u32 = 0x20;
const NOTE_REVOKE_: u32 = 0x40;
const VNODE_NOTES: u32 = NOTE_DELETE_ | NOTE_WRITE_ | NOTE_EXTEND_ | NOTE_ATTRIB_ | NOTE_LINK_ | NOTE_RENAME_ | NOTE_REVOKE_;
const REGISTER_FLAGS: u16 = ADD | ENABLE | CLEAR;
const TIMER_ID: usize = 0x5046_5731;
#[derive(Clone, Copy, Debug)]
struct Event { ident: usize, filter: i16, flags: u16, fflags: u32, data: isize, udata_null: bool }
fn receipt_valid(event: Event, ident: usize, filter: i16, flags: u16, fflags: u32) -> bool {
    event.ident == ident && event.filter == filter && event.flags == (flags | RECEIPT | ERROR)
        && event.fflags == fflags && event.data == 0 && event.udata_null
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EventKind { Timer, Vnode, RevokedVnode }
fn classify_event(event: Event, original_fds: &[usize]) -> Check<EventKind> {
    if !event.udata_null || event.flags != (REGISTER_FLAGS | RECEIPT) {
        return Err(input_error(Reason::UnknownEvent));
    }
    match event.filter {
        FILTER_TIMER if event.ident == TIMER_ID && event.fflags == 0 && event.data > 0 => Ok(EventKind::Timer),
        FILTER_VNODE if original_fds.contains(&event.ident) && event.fflags != 0
            && event.fflags & !VNODE_NOTES == 0 && event.data == 0 => {
            if event.fflags & NOTE_REVOKE_ != 0 { Ok(EventKind::RevokedVnode) } else { Ok(EventKind::Vnode) }
        }
        _ => Err(input_error(Reason::UnknownEvent)),
    }
}
fn runloop_progress(result: i32) -> bool { matches!(result, 3 | 4) }
fn callback_kind(correct_store: bool, correct_thread: bool, string_count: Option<usize>) -> Check<()> {
    if !correct_store || !correct_thread || string_count.is_none_or(|count| count > 4096) {
        Err(Failure::new(Source::DynamicStore, Reason::MalformedCallback))
    } else if string_count == Some(0) {
        Err(Failure::new(Source::DynamicStore, Reason::ServerRestart))
    } else { Ok(()) }
}

// Coordinator native calibration attempt3 (2026-11-15) observed eight serial
// own-process samples at load3.277832/4.834473/8.945312: empty100ms max103.965ms,
// SC100ms max108.964959ms. These are administrative settings, NOT lifecycle or
// restoration budgets, bounds on native call completion, or measured PF latency.
// The5s overall endpoint allows scheduling/inspection latitude and never extends
// the caller's endpoint. The separate complete10s ceremony cap is untouched.
const ADMIN_LIMIT: std::time::Duration = std::time::Duration::from_secs(5);
const ITERATION_WAIT: std::time::Duration = std::time::Duration::from_millis(100);
const TIMER_PERIOD_MS: isize = 250;
const JOIN_POLL: std::time::Duration = std::time::Duration::from_millis(1);
const DRAIN_MAX: usize = 16;

impl PfNotifications {
    pub(super) fn accounting(&self) -> NotificationAccounting {
        let (first_failure, retained_failures, retained_cleanup_failures, native_registration_receipts, journal_overflow) =
            match self.shared.journal.lock() {
                Ok(journal) => (journal.first, journal.failures.len(), journal.cleanup.len(), journal.receipts.len(), journal.overflow),
                Err(_) => (Some(Failure::new(Source::Owner, Reason::Poisoned)), 0, 0, 0, true),
            };
        NotificationAccounting { retained_thread_handles: self.workers.iter().filter(|worker| worker.is_some()).count(),
            running: std::array::from_fn(|index| self.shared.running[index].load(Ordering::SeqCst)),
            phases: std::array::from_fn(|index| self.shared.phase[index].load(Ordering::SeqCst)),
            owned_fds_live_or_close_uncertain: self.shared.resources[0].load(Ordering::SeqCst),
            owned_cf_references_not_yet_released: self.shared.resources[1].load(Ordering::SeqCst),
            vnode_timer_registered_or_queue_close_unknown: self.shared.registrations[0].load(Ordering::SeqCst),
            sc_patterns_registered_or_server_cleanup_unknown: self.shared.registrations[1].load(Ordering::SeqCst),
            last_loop_boot_ns: std::array::from_fn(|index| self.shared.last_loop_ns[index].load(Ordering::SeqCst)),
            last_invalidation_boot_ns: std::array::from_fn(|index| self.shared.last_invalidation_ns[index].load(Ordering::SeqCst)),
            first_failure, retained_failures, retained_cleanup_failures, native_registration_receipts, journal_overflow,
            retention_collisions_unknown: RETENTION_COLLISIONS.load(Ordering::SeqCst),
            stop_pending: self.shared.stop_pending.load(Ordering::SeqCst),
            stop_evidence_unknown: self.shared.stop_evidence_unknown.load(Ordering::SeqCst),
            joined_unwind_sources: self.shared.joined_unwind_sources.load(Ordering::SeqCst) }
    }
    pub(super) fn start_selected(
        session: Arc<crate::power::selected_owner_session::SelectedOwnerSession>,
        supervisor_stop: Arc<AtomicBool>, requested_end: Instant,
    ) -> Self {
        let end = requested_end.min(session.original_instant_end());
        let binding = Arc::new(OriginalNegativeBinding {session: BoundSession::Native(session), supervisor_stop, end});
        Self::start_bound(binding)
    }
    fn start_bound(binding: Arc<OriginalNegativeBinding>) -> Self {
        let deadline = binding.operation_end(binding.end);
        let shared = Shared::bound(binding);
        let (kqueue, kqueue_flow) = WorkerEndpoint::pair(Source::Kqueue, shared.clone());
        let (store, store_flow) = WorkerEndpoint::pair(Source::DynamicStore, shared.clone());
        let mut owner = Self { resources: Some(Box::new(Resources { shared, checked: None,
            endpoints: [kqueue, store], workers: [None, None] })) };
        let admission = (|| {
            owner.shared.binding.current()?;
            within(deadline, Source::Owner)?;
            if !cfg!(target_os = "macos") { return Err(Failure::new(Source::Owner, Reason::NativeRequired)); }
            if unsafe { libc::geteuid() } != 0 { return Err(Failure::new(Source::Owner, Reason::RootRequired)); }
            let checked = deployment::selected().ok_or(Failure::new(Source::Owner, Reason::SelectionRequired))?;
            context_current(checked, deadline)?;
            owner.checked = Some(checked);
            // Publish before any worker/callback can exist, and never replace
            // the original domain with a later selected session.
            publish_domain(&ORIGINAL_DOMAIN, owner.shared.binding.clone())?;
            for (index, flow) in [kqueue_flow, store_flow].into_iter().enumerate() {
                match launch_worker(checked, flow, deadline) {
                    Ok(worker) => owner.workers[index] = Some(worker),
                    Err(error) => {
                        return Err(Failure { source: if index == 0 { Source::Kqueue } else { Source::DynamicStore },
                            reason: Reason::Spawn, code: error.raw_os_error(), resource: None });
                    }
                }
            }
            loop {
                owner.shared.usable(Source::Owner)?;
                within(deadline, Source::Owner)?;
                if owner.workers.iter().any(|worker| worker.as_ref().is_none_or(JoinHandle::is_finished)) {
                    return Err(Failure::new(Source::Owner, Reason::MissingWorker));
                }
                if owner.shared.phase.iter().all(|phase| phase.load(Ordering::SeqCst) == ARMED) { break; }
                thread::park_timeout(JOIN_POLL.min(deadline.saturating_duration_since(Instant::now())));
            }
            context_current(checked, deadline)?;
            owner.shared.binding.endpoint(deadline).map(|_| ())
        })();
        if let Err(error) = admission {
            owner.shared.record(error, false);
            owner.shared.stop.store(true, Ordering::SeqCst);
        }
        owner
    }
    pub(super) fn require_same_original(&self,
        session: &Arc<crate::power::selected_owner_session::SelectedOwnerSession>,
        supervisor_stop: &Arc<AtomicBool>, end: Instant,
    ) -> EnclaveResult<()> {
        // Caller may offer its enclosing cap; this owner only shortens it.
        let result = self.shared.binding.matches(session, supervisor_stop, end.min(self.shared.binding.end));
        if result.is_err() { self.shared.terminal_veto(); }
        result.map_err(|_| self.shared.error("PF_NOTIFICATION_ORIGINAL_BINDING_REFUSED"))
    }
    pub(super) fn request_stop(&self) { self.shared.terminal_veto(); }
    fn handles_current(&self) -> Check<()> {
        for source in [Source::Kqueue, Source::DynamicStore] {
            if self.workers[source.slot()].as_ref().is_none_or(JoinHandle::is_finished) {
                return Err(Failure::new(source, Reason::MissingWorker));
            }
            self.shared.phase_current(source)?;
        }
        Ok(())
    }
    pub(super) fn begin_collection_window(&self, requested: Instant) -> EnclaveResult<NegativeCollectionWindow<'_>> {
        // Fix the cap BEFORE fresh challenges; observation cannot renew it.
        let end = self.shared.binding.operation_end(requested);
        let mut veto = CollectionFailureVeto { shared: &self.shared, armed: true };
        let progress = self.observe_current(end)?;
        let window = NegativeCollectionWindow::from_progress(self, progress, end).map_err(|error| {
            self.shared.record(error, false);
            self.shared.error("PF_NOTIFICATION_COLLECTION_BEGIN_REFUSED")
        })?;
        veto.armed = false;
        Ok(window)
    }
    pub(super) fn observe_current(&self, deadline: Instant) -> EnclaveResult<NotificationProgress> {
        let result = (|| {
            let deadline = self.shared.binding.endpoint(self.shared.binding.operation_end(deadline))?;
            let checked = self.checked.ok_or(Failure::new(Source::Owner, Reason::SelectionRequired))?;
            let started_boot_ns = boot_time(Source::Owner)?;
            context_current(checked, deadline)?;
            self.handles_current()?;
            self.shared.binding.endpoint(deadline)?;
            let before = self.shared.generation.load(Ordering::SeqCst);
            // Enqueue BOTH fresh challenges before waiting, under ONE endpoint.
            let one = self.endpoints[0].request(&self.shared, deadline)?;
            let two = self.endpoints[1].request(&self.shared, deadline)?;
            let one = self.endpoints[0].receive(&self.shared, one, deadline)?;
            let two = self.endpoints[1].receive(&self.shared, two, deadline)?;
            self.handles_current()?;
            context_current(checked, deadline)?;
            let ended_boot_ns = boot_time(Source::Owner)?;
            if ended_boot_ns < started_boot_ns || [one.observed_boot_ns, two.observed_boot_ns].into_iter()
                .any(|time| time < started_boot_ns || time > ended_boot_ns) {
                return Err(Failure::new(Source::Owner, Reason::Clock));
            }
            let generation = self.shared.generation.load(Ordering::SeqCst);
            let ticks = self.shared.ticks.load(Ordering::SeqCst);
            if one.ticks == 0 || ticks < one.ticks || generation < one.generation || generation < two.generation {
                return Err(Failure::new(Source::Owner, Reason::CounterOverflow));
            }
            within(deadline, Source::Owner)?;
            self.handles_current()?;
            self.shared.binding.endpoint(deadline)?;
            Ok(NotificationProgress { allocation: self.shared.clone(), generation, ticks,
                source_bits: self.shared.source_bits.load(Ordering::SeqCst), unstable: before != generation,
                started_boot_ns, ended_boot_ns, worker_boot_ns: [one.observed_boot_ns, two.observed_boot_ns],
                session_continuity: SessionContinuity::UnavailablePublicContract })
        })();
        result.map_err(|error| {
            self.shared.record(error, false);
            self.shared.error("PF_NOTIFICATION_COMPONENT_OBSERVATION_REFUSED")
        })
    }
    pub(super) fn stop(&mut self, deadline: Instant) -> EnclaveResult<()> {
        self.request_stop();
        let deadline = deadline.min(self.shared.binding.end);
        loop {
            self.resources.as_deref_mut().expect("retained original bundle").join_finished();
            if self.workers.iter().all(Option::is_none) { break; }
            if Instant::now() >= deadline {
                self.shared.record_stop(Failure::new(Source::Owner, Reason::StopPending));
                return Err(EnclaveError::with(Errno::EACCES, "PF_NOTIFICATION_STOP_PENDING_OR_UNCERTAIN",
                    "original worker or cleanup evidence remains unknown"));
            }
            if self.workers.iter().any(Option::is_some) {
                thread::park_timeout(JOIN_POLL.min(deadline.saturating_duration_since(Instant::now())));
            }
        }
        let refused = self.shared.stop_uncertain() || match self.shared.journal.try_lock() {
            Ok(journal) => journal.first.is_some() || journal.overflow || !journal.cleanup.is_empty(),
            Err(_) => {self.shared.stop_evidence_unknown.store(true, Ordering::SeqCst); true},
        };
        if refused {
            Err(EnclaveError::with(Errno::EACCES, "PF_NOTIFICATION_STOP_PRIOR_REFUSAL_OR_CLEANUP_UNCERTAIN",
                "original stop or cleanup evidence remains unknown"))
        } else { Ok(()) }
    }
}
impl Drop for PfNotifications {
    fn drop(&mut self) {
        if let Some(bundle) = self.resources.take() {
            // Atomic same-session veto precedes registry publication. Do not
            // join or take any journal lock during Drop; a live original stays
            // owned and charged, including blocked native/CF cleanup.
            retire_bundle(&RETAINED, bundle);
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn launch_worker(_checked: &'static CheckedDeploymentTarget, _flow: WorkerFlow, _deadline: Instant) -> std::io::Result<JoinHandle<()>> {
    Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
}

#[cfg(target_os = "macos")]
fn launch_worker(checked: &'static CheckedDeploymentTarget, flow: WorkerFlow, deadline: Instant) -> std::io::Result<JoinHandle<()>> {
    let source = flow.source;
    thread::Builder::new().name(match source { Source::Kqueue => "selected-pf-kqueue", _ => "selected-pf-configd" }.into())
        .spawn(move || {
            flow.shared.running[source.slot()].store(true, Ordering::SeqCst);
            let _exit = WorkerExit { shared: flow.shared.clone(), source };
            match source {
                Source::Kqueue => native::kqueue_worker(checked, flow, deadline),
                Source::DynamicStore => native::store_worker(checked, flow, deadline),
                Source::Owner => unreachable!("closed worker source constructor"),
            }
        })
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use std::{cell::Cell, ffi::{c_char, c_void}, panic::{catch_unwind, AssertUnwindSafe}};
    type CFRef = *const c_void;
    const UTF8: u32 = 0x0800_0100;
    static ORPHAN_CALLBACK: AtomicBool = AtomicBool::new(false);
    const _: () = {
        assert!(libc::EVFILT_VNODE == FILTER_VNODE && libc::EVFILT_TIMER == FILTER_TIMER);
        assert!(libc::EV_ADD == ADD && libc::EV_DELETE == DELETE && libc::EV_ENABLE == ENABLE);
        assert!(libc::EV_CLEAR == CLEAR && libc::EV_RECEIPT == RECEIPT && libc::EV_ERROR == ERROR && libc::EV_EOF == EOF);
        assert!(libc::NOTE_DELETE == NOTE_DELETE_ && libc::NOTE_WRITE == NOTE_WRITE_ && libc::NOTE_EXTEND == NOTE_EXTEND_);
        assert!(libc::NOTE_ATTRIB == NOTE_ATTRIB_ && libc::NOTE_LINK == NOTE_LINK_ && libc::NOTE_RENAME == NOTE_RENAME_ && libc::NOTE_REVOKE == NOTE_REVOKE_);
    };
    #[repr(C)]
    struct StoreContext {
        version: isize, info: *mut c_void,
        retain: Option<unsafe extern "C" fn(*const c_void) -> *const c_void>,
        release: Option<unsafe extern "C" fn(*const c_void)>,
        description: Option<unsafe extern "C" fn(*const c_void) -> CFRef>,
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        static kCFRunLoopDefaultMode: CFRef;
        fn CFStringCreateWithCString(allocator: CFRef, bytes: *const c_char, encoding: u32) -> CFRef;
        fn CFArrayCreate(allocator: CFRef, values: *const CFRef, count: isize, callbacks: *const c_void) -> CFRef;
        fn CFGetTypeID(value: CFRef) -> usize;
        fn CFArrayGetTypeID() -> usize;
        fn CFStringGetTypeID() -> usize;
        fn CFArrayGetCount(array: CFRef) -> isize;
        fn CFArrayGetValueAtIndex(array: CFRef, index: isize) -> CFRef;
        fn CFRunLoopGetCurrent() -> CFRef;
        fn CFRunLoopAddSource(loop_: CFRef, source: CFRef, mode: CFRef);
        fn CFRunLoopContainsSource(loop_: CFRef, source: CFRef, mode: CFRef) -> u8;
        fn CFRunLoopRunInMode(mode: CFRef, seconds: f64, after_source: u8) -> i32;
        fn CFRunLoopSourceIsValid(source: CFRef) -> u8;
        fn CFRunLoopRemoveSource(loop_: CFRef, source: CFRef, mode: CFRef);
        fn CFRunLoopSourceInvalidate(source: CFRef);
        fn CFRelease(object: CFRef);
    }
    #[link(name = "SystemConfiguration", kind = "framework")]
    unsafe extern "C" {
        fn SCDynamicStoreCreate(allocator: CFRef, name: CFRef,
            callback: Option<unsafe extern "C" fn(CFRef, CFRef, *mut c_void)>, context: *mut StoreContext) -> CFRef;
        fn SCDynamicStoreSetNotificationKeys(store: CFRef, keys: CFRef, patterns: CFRef) -> u8;
        fn SCDynamicStoreCreateRunLoopSource(allocator: CFRef, store: CFRef, order: isize) -> CFRef;
        fn SCDynamicStoreCopyKeyList(store: CFRef, pattern: CFRef) -> CFRef;
        fn SCError() -> i32;
    }
    fn errno(reason: Reason) -> Failure {
        Failure { source: Source::Kqueue, reason,
            code: std::io::Error::last_os_error().raw_os_error(), resource: None }
    }
    fn event(raw: &libc::kevent) -> Event {
        Event { ident: raw.ident, filter: raw.filter, flags: raw.flags, fflags: raw.fflags,
            data: raw.data, udata_null: raw.udata.is_null() }
    }
    fn change(ident: usize, filter: i16, flags: u16, fflags: u32, data: isize) -> libc::kevent {
        libc::kevent { ident, filter, flags, fflags, data, udata: std::ptr::null_mut() }
    }
    struct KqueueOwner {
        queue: Option<OwnedFile>, // Always close queue before releasing vnode originals.
        originals: Originals,
        registered: Vec<usize>,
        timer_registered: bool,
    }
    impl KqueueOwner {
        fn register(&mut self, ident: usize, filter: i16, fflags: u32, data: isize, deadline: Instant) -> Check<()> {
            within(deadline, Source::Kqueue)?;
            let change = change(ident, filter, REGISTER_FLAGS | RECEIPT, fflags, data);
            let mut result = change;
            let zero = libc::timespec { tv_sec: 0, tv_nsec: 0 };
            let count = unsafe { libc::kevent(self.queue.as_ref().expect("own queue").fd(), &change, 1, &mut result, 1, &zero) };
            if count < 0 { return Err(errno(Reason::NativeCall)); }
            self.originals.shared.complete_registration_receipt(count, event(&result), ident, filter, fflags, deadline)?;
            // Retain exact successful local registration facts before a later
            // endpoint/context check can refuse; queue closure owns teardown.
            if filter == FILTER_TIMER { self.timer_registered = true; } else { self.registered.push(ident); }
            self.originals.shared.advance(&self.originals.shared.registrations[0], Source::Kqueue)?;
            within(deadline, Source::Kqueue)
        }
        fn poll(&self, timeout: std::time::Duration, deadline: Instant) -> Check<usize> {
            within(deadline, Source::Kqueue)?;
            let duration = timeout.min(deadline.saturating_duration_since(Instant::now()));
            let timespec = libc::timespec { tv_sec: duration.as_secs() as libc::time_t,
                tv_nsec: duration.subsec_nanos() as libc::c_long };
            let mut events = [change(0, 0, 0, 0, 0); 8];
            let observation = self.originals.shared.begin_repair_observation(Source::Kqueue, deadline)?;
            let count = unsafe { libc::kevent(self.queue.as_ref().expect("own queue").fd(), std::ptr::null(), 0,
                events.as_mut_ptr(), events.len() as i32, &timespec) };
            if count < 0 { return Err(errno(Reason::NativeCall)); }
            if count as usize > events.len() { return Err(input_error(Reason::UnknownEvent)); }
            for raw in &events[..count as usize] {
                // Every event received on our original queue invalidates an
                // earlier policy epoch unless it is a validated timer tick.
                let value = event(raw);
                self.originals.shared.dispatch_observed_event(observation.window(), value, &self.registered)?;
            }
            observation.complete();
            // Non-timer/malformed events have already vetoed the original
            // before taking the loop-evidence journal lock or clock sample.
            self.originals.shared.note_loop(Source::Kqueue, count)?;
            within(deadline, Source::Kqueue)?;
            Ok(count as usize)
        }
    }
    pub(super) fn kqueue_worker(checked: &'static CheckedDeploymentTarget, flow: WorkerFlow, startup: Instant) {
        let mut owned = KqueueOwner { queue: None,
            originals: Originals { routes: Vec::new(), shared: flow.shared.clone() },
            registered: Vec::with_capacity(4 * MAX_NODES), timer_registered: false };
        let result = (|| {
            context_current(checked, startup)?;
            let descriptor = deployment::normalized_path(checked.config_path()).map_err(|_| input_error(Reason::InvalidPath))?;
            let specs = vec![
                InputSpec { role: Role::Descriptor, path: descriptor, maximum: deployment::MAX_DESCRIPTOR_BYTES,
                    expected: Expected::Descriptor(checked.descriptor_sha256().into()) },
                InputSpec { role: Role::RootPolicy, path: "/private/etc/pf.conf".into(), maximum: MAX_INPUT, expected: Expected::RootPolicy },
                InputSpec { role: Role::LlmPolicy, path: LLM_FILE.into(), maximum: MAX_INPUT, expected: Expected::Canonical(LLM_POLICY) },
                InputSpec { role: Role::CasPolicy, path: CAS_FILE.into(), maximum: MAX_INPUT, expected: Expected::Canonical(CAS_POLICY) },
            ];
            owned.originals.open(specs, Protection::NativeRoot, startup)?;
            let fd = unsafe { libc::kqueue() };
            if fd < 0 { return Err(errno(Reason::NativeCall)); }
            owned.queue = Some(unsafe { OwnedFile::take(fd, flow.shared.clone(), (4 * MAX_NODES) as u16) });
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } != 0
                || unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC == 0 {
                return Err(errno(Reason::DescriptorFlags));
            }
            let fds: Vec<usize> = owned.originals.routes.iter().flat_map(|route| route.nodes.iter()
                .map(|node| node.owned.fd() as usize)).collect();
            for fd in fds { owned.register(fd, FILTER_VNODE, VNODE_NOTES, 0, startup)?; }
            owned.register(TIMER_ID, FILTER_TIMER, 0, TIMER_PERIOD_MS, startup)?;
            owned.originals.current(startup)?;
            context_current(checked, startup)?;
            let mut pending: Option<(Challenge, u64)> = None;
            loop {
                if flow.shared.stop.load(Ordering::SeqCst) { break; }
                flow.shared.usable(Source::Kqueue)?;
                let armed = flow.shared.phase[0].load(Ordering::SeqCst) == ARMED;
                if armed && pending.is_none() {
                    pending = flow.next()?.map(|challenge| (challenge, flow.shared.ticks.load(Ordering::SeqCst)));
                }
                let deadline = flow.shared.binding.operation_end(if !armed { startup }
                    else { pending.as_ref().map_or(flow.shared.binding.end, |(challenge, _)| challenge.deadline) });
                context_current(checked, deadline)?;
                owned.originals.current(deadline)?;
                let count = owned.poll(ITERATION_WAIT, deadline)?;
                if count > 0 {
                    let mut empty = false;
                    for _ in 0..DRAIN_MAX {
                        if owned.poll(std::time::Duration::ZERO, deadline)? == 0 { empty = true; break; }
                    }
                    if !empty { return Err(input_error(Reason::DrainBound)); }
                }
                owned.originals.current(deadline)?;
                context_current(checked, deadline)?;
                flow.shared.usable(Source::Kqueue)?;
                within(deadline, Source::Kqueue)?;
                let ticks = flow.shared.ticks.load(Ordering::SeqCst);
                if !armed && ticks > 0 {
                    flow.shared.phase[0].store(ARMED, Ordering::SeqCst);
                }
                if pending.as_ref().is_some_and(|(_, before)| ticks > *before) {
                    flow.acknowledge(pending.take().expect("pending original challenge").0)?;
                }
            }
            Ok(())
        })();
        if let Err(error) = result { flow.shared.record(error, false); }
        // Queue closure deletes its owned subscriptions. The original worker
        // revokes before close and retains all independent close errors.
        flow.shared.terminal_veto();
        drop(owned.queue.take());
        drop(owned);
    }

    pub(super) fn orphaned_callback() -> bool { ORPHAN_CALLBACK.load(Ordering::SeqCst) }
    struct CallbackState {
        shared: Arc<Shared>, expected_store: Cell<CFRef>, thread: libc::pthread_t,
        repair_window: Cell<Option<NativeRepairWindow>>,
    }
    fn array_count(array: CFRef) -> Check<isize> {
        if array.is_null() || unsafe { CFGetTypeID(array) } != unsafe { CFArrayGetTypeID() } {
            return Err(Failure::new(Source::DynamicStore, Reason::MalformedCallback));
        }
        let count = unsafe { CFArrayGetCount(array) };
        if !(0..=4096).contains(&count) { return Err(Failure::new(Source::DynamicStore, Reason::MalformedCallback)); }
        for index in 0..count {
            let item = unsafe { CFArrayGetValueAtIndex(array, index) };
            if item.is_null() || unsafe { CFGetTypeID(item) } != unsafe { CFStringGetTypeID() } {
                return Err(Failure::new(Source::DynamicStore, Reason::MalformedCallback));
            }
        }
        Ok(count)
    }
    unsafe extern "C" fn changed(store: CFRef, keys: CFRef, info: *mut c_void) {
        // The context is allocated/retained only by this original worker. The
        // public C API returns the supplied info verbatim; NULL is a process-
        // wide sticky contract violation because there is then no safe owner.
        if info.is_null() {
            veto_orphan(&ORIGINAL_DOMAIN);
            ORPHAN_CALLBACK.store(true, Ordering::SeqCst); return;
        }
        let context = unsafe { &*info.cast::<CallbackState>() };
        context.shared.terminal_veto();
        let correct_thread = unsafe { libc::pthread_equal(libc::pthread_self(), context.thread) } != 0;
        // Never read thread-affine Cells from an unexpected callback thread.
        let window = if correct_thread { context.repair_window.get() } else { None };
        let result = catch_unwind(AssertUnwindSafe(|| context.shared.dispatch_observed_callback(window, || {
            // Atomic veto precedes all callback parsing and context checks.
            if !correct_thread { return callback_kind(false, false, None); }
            let correct_store = context.expected_store.get() == store;
            if !correct_store { return callback_kind(false, true, None); }
            let count = array_count(keys)?;
            callback_kind(correct_store, correct_thread, usize::try_from(count).ok())
        })));
        match result {
            Ok(Ok(())) => (),
            Ok(Err(error)) => context.shared.record(error, false),
            Err(_) => context.shared.record(Failure::new(Source::DynamicStore, Reason::Unwound), false),
        }
    }
    /// No CF pointer, borrowed runloop or callback Box crosses a thread. All
    /// partial references are kept until teardown on this original worker.
    struct StoreOwner {
        shared: Arc<Shared>, context: Box<CallbackState>, store: CFRef, source: CFRef,
        loop_: CFRef, strings: [CFRef; 3], patterns: CFRef,
    }
    impl StoreOwner {
        fn new(shared: Arc<Shared>) -> Self {
            Self { context: Box::new(CallbackState { shared: shared.clone(), expected_store: Cell::new(std::ptr::null()),
                thread: unsafe { libc::pthread_self() }, repair_window: Cell::new(None) }), shared,
                store: std::ptr::null(), source: std::ptr::null(),
                loop_: std::ptr::null(), strings: [std::ptr::null(); 3], patterns: std::ptr::null() }
        }
        fn initialize(&mut self, deadline: Instant) -> Check<()> {
            let values: [&[u8]; 3] = [b"MCPMac-selected-PF-notifications\0", b"State:/Network/.*\0", b"Setup:/Network/.*\0"];
            for (index, value) in values.into_iter().enumerate() {
                within(deadline, Source::DynamicStore)?;
                self.strings[index] = unsafe { CFStringCreateWithCString(std::ptr::null(), value.as_ptr().cast(), UTF8) };
                if self.strings[index].is_null() { return Err(Failure::new(Source::DynamicStore, Reason::CfAllocation)); }
                self.shared.resource_acquired(Source::DynamicStore);
            }
            let values = [self.strings[1], self.strings[2]];
            // NULL callbacks borrow our original strings; both stay retained
            // until after patterns/source/store teardown on this worker.
            self.patterns = unsafe { CFArrayCreate(std::ptr::null(), values.as_ptr(), 2, std::ptr::null()) };
            if self.patterns.is_null() { return Err(Failure::new(Source::DynamicStore, Reason::CfAllocation)); }
            self.shared.resource_acquired(Source::DynamicStore);
            let mut context = StoreContext { version: 0, info: (&mut *self.context as *mut CallbackState).cast(),
                retain: None, release: None, description: None };
            within(deadline, Source::DynamicStore)?;
            self.store = unsafe { SCDynamicStoreCreate(std::ptr::null(), self.strings[0], Some(changed), &mut context) };
            if self.store.is_null() { return Err(Failure::code(Source::DynamicStore, Reason::ScSession, unsafe { SCError() })); }
            self.shared.resource_acquired(Source::DynamicStore);
            self.context.expected_store.set(self.store);
            within(deadline, Source::DynamicStore)?;
            if unsafe { SCDynamicStoreSetNotificationKeys(self.store, std::ptr::null(), self.patterns) } == 0 {
                return Err(Failure::code(Source::DynamicStore, Reason::ScRegistration, unsafe { SCError() }));
            }
            self.shared.registrations[1].store(2, Ordering::SeqCst);
            within(deadline, Source::DynamicStore)?;
            self.source = unsafe { SCDynamicStoreCreateRunLoopSource(std::ptr::null(), self.store, 0) };
            if self.source.is_null() { return Err(Failure::code(Source::DynamicStore, Reason::CfAllocation, unsafe { SCError() })); }
            self.shared.resource_acquired(Source::DynamicStore);
            self.loop_ = unsafe { CFRunLoopGetCurrent() };
            if self.loop_.is_null() { return Err(Failure::new(Source::DynamicStore, Reason::SourceInvalid)); }
            unsafe { CFRunLoopAddSource(self.loop_, self.source, kCFRunLoopDefaultMode); }
            self.current_source(deadline)
        }
        fn current_source(&self, deadline: Instant) -> Check<()> {
            within(deadline, Source::DynamicStore)?;
            self.shared.usable(Source::DynamicStore)?;
            if self.store.is_null() || self.source.is_null() || self.loop_.is_null()
                || self.context.expected_store.get() != self.store
                || unsafe { libc::pthread_equal(libc::pthread_self(), self.context.thread) } == 0
                || unsafe { CFRunLoopContainsSource(self.loop_, self.source, kCFRunLoopDefaultMode) } == 0
                || unsafe { CFRunLoopSourceIsValid(self.source) } == 0 {
                return Err(Failure::new(Source::DynamicStore, Reason::SourceInvalid));
            }
            // Only actual local original-source membership is observed here.
            // It is NOT original configd session/subscription continuity.
            within(deadline, Source::DynamicStore)
        }
        fn run(&self, wait: std::time::Duration, deadline: Instant) -> Check<i32> {
            self.current_source(deadline)?;
            let wait = wait.min(deadline.saturating_duration_since(Instant::now()));
            let observation = self.shared.begin_repair_observation(Source::DynamicStore, deadline)?;
            struct WindowSlot<'a>(&'a Cell<Option<NativeRepairWindow>>);
            impl Drop for WindowSlot<'_> { fn drop(&mut self) { self.0.set(None); } }
            if self.context.repair_window.replace(Some(observation.window())).is_some() {
                self.context.repair_window.set(None);
                self.shared.repair_unknown.store(true, Ordering::SeqCst);
                return Err(Failure::new(Source::DynamicStore, Reason::RepairObservationUnknown));
            }
            let slot = WindowSlot(&self.context.repair_window);
            let result = unsafe { CFRunLoopRunInMode(kCFRunLoopDefaultMode, wait.as_secs_f64(), 1) };
            drop(slot);
            // Callback dispatch completed inside the original native call.
            // Its deliberate old-session veto is not a reason to reset timing.
            if runloop_progress(result) { observation.complete(); }
            self.shared.complete_runloop(result, deadline)?;
            self.current_source(deadline)?;
            Ok(result)
        }
        fn drain(&self, deadline: Instant) -> Check<()> {
            for _ in 0..DRAIN_MAX {
                if self.run(std::time::Duration::ZERO, deadline)? == 3 { return Ok(()); }
            }
            Err(Failure::new(Source::DynamicStore, Reason::DrainBound))
        }
        fn query_component(&self, deadline: Instant) -> Check<()> {
            self.current_source(deadline)?;
            // Public Apple configd CopyKeyList may reconnect and retry without
            // synchronous restart delivery. Discard the old policy epoch BEFORE
            // the call, then process queued callbacks before any component ACK.
            // Even successful drains leave complete session continuity UNKNOWN.
            self.shared.invalidate(Source::DynamicStore)?;
            let result = unsafe { SCDynamicStoreCopyKeyList(self.store, self.strings[1]) };
            if result.is_null() { return Err(Failure::code(Source::DynamicStore, Reason::ScQuery, unsafe { SCError() })); }
            self.shared.resource_acquired(Source::DynamicStore);
            self.shared.complete_query(deadline,
                || array_count(result).map_err(|_| Failure::new(Source::DynamicStore, Reason::ScQuery)),
                || {
                    unsafe { CFRelease(result); }
                    self.shared.resource_released(Source::DynamicStore);
                })?;
            self.drain(deadline)
        }
    }
    impl Drop for StoreOwner {
        fn drop(&mut self) {
            self.shared.terminal_veto();
            // These APIs may block. Caller timeout retains this worker handle;
            // Drop never dispatches cleanup onto a helper or frees live context.
            if !self.source.is_null() {
                if !self.loop_.is_null() { unsafe { CFRunLoopRemoveSource(self.loop_, self.source, kCFRunLoopDefaultMode); } }
                unsafe { CFRunLoopSourceInvalidate(self.source); }
                if unsafe { CFRunLoopSourceIsValid(self.source) } != 0
                    || (!self.loop_.is_null() && unsafe { CFRunLoopContainsSource(self.loop_, self.source, kCFRunLoopDefaultMode) } != 0) {
                    self.shared.record(Failure::new(Source::DynamicStore, Reason::SourceCleanup), true);
                }
                unsafe { CFRelease(self.source); }
                self.shared.resource_released(Source::DynamicStore);
            }
            if !self.store.is_null() {
                unsafe { CFRelease(self.store); }
                self.shared.resource_released(Source::DynamicStore);
                // Void CFRelease/local source invalidation cannot prove final
                // configd-side cleanup. Preserve this uncertainty explicitly.
                self.shared.record(Failure::new(Source::DynamicStore, Reason::CleanupUncertain), true);
            }
            if !self.patterns.is_null() { unsafe { CFRelease(self.patterns); } self.shared.resource_released(Source::DynamicStore); }
            for string in self.strings {
                if !string.is_null() { unsafe { CFRelease(string); } self.shared.resource_released(Source::DynamicStore); }
            }
            // Borrowed loop_ is NEVER released. context Box is dropped last,
            // only after source/store callbacks are disabled and released here.
        }
    }
    pub(super) fn store_worker(checked: &'static CheckedDeploymentTarget, flow: WorkerFlow, startup: Instant) {
        let mut owned = StoreOwner::new(flow.shared.clone());
        let result = (|| {
            context_current(checked, startup)?;
            owned.initialize(startup)?;
            let mut armed = false;
            loop {
                if flow.shared.stop.load(Ordering::SeqCst) { break; }
                flow.shared.usable(Source::DynamicStore)?;
                // The challenge is taken BEFORE the actual original loop/query.
                let challenge = if armed { flow.next()? } else { None };
                let deadline = flow.shared.binding.operation_end(if !armed { startup }
                    else { challenge.as_ref().map_or(flow.shared.binding.end, |value| value.deadline) });
                context_current(checked, deadline)?;
                owned.drain(deadline)?;
                owned.query_component(deadline)?;
                owned.run(ITERATION_WAIT, deadline)?;
                owned.drain(deadline)?;
                context_current(checked, deadline)?;
                owned.current_source(deadline)?;
                flow.shared.usable(Source::DynamicStore)?;
                within(deadline, Source::DynamicStore)?;
                if !armed { flow.shared.phase[1].store(ARMED, Ordering::SeqCst); armed = true; }
                if let Some(challenge) = challenge { flow.acknowledge(challenge)?; }
            }
            Ok(())
        })();
        if let Err(error) = result { flow.shared.record(error, false); }
        flow.shared.terminal_veto();
        drop(owned);
    }
}

#[cfg(test)]
#[path = "pf_watch_tests.rs"]
mod tests;
