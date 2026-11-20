//! Local delayed-work fence only. There is no production restart permit.
//! Protected persistent supervisor/host authority and installed qualification
//! remain required before automatic bootstrap can be implemented.
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, TryLockError, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant};

use crate::error::EnclaveResult;
use crate::quarantine_types::Response;
use crate::{err, fail};

const STRIKE_DELAY: Duration = Duration::from_secs(300);

pub(super) fn pii_uid(uid: u32) -> bool { matches!(uid, 701 | 703 | 704 | 705) }

#[derive(Debug)]
struct Pending { ticket: u64, deadline: Instant }

#[derive(Debug, Default)]
struct State {
    pending: HashMap<u32, Pending>,
    revision: u64,
    next_ticket: u64,
    inflight: u64,
    latched: bool,
    faulted: bool,
}

impl State {
    fn close(&mut self) {
        self.faulted = true;
        self.pending.retain(|uid, _| !pii_uid(*uid));
    }
    fn advance_revision(&mut self) -> EnclaveResult<()> {
        match self.revision.checked_add(1) {
            Some(next) => { self.revision = next; Ok(()) }
            None => { self.close(); fail!(EIO, "RESTART_REVISION_EXHAUSTED"); }
        }
    }
    fn delay(&mut self, uid: u32, duration: Duration, now: Instant) -> EnclaveResult<()> {
        let deadline = match now.checked_add(duration) {
            Some(value) => value,
            None => { self.close(); fail!(EIO, "RESTART_DEADLINE_EXHAUSTED"); }
        };
        let ticket = match self.next_ticket.checked_add(1) {
            Some(value) => value,
            None => { self.close(); fail!(EIO, "RESTART_TICKET_EXHAUSTED"); }
        };
        self.advance_revision()?;
        self.next_ticket = ticket;
        let deadline = self.pending.get(&uid).map_or(deadline, |old| old.deadline.max(deadline));
        self.pending.insert(uid, Pending { ticket, deadline });
        Ok(())
    }
    fn begin_report(&mut self, uid: u32) -> EnclaveResult<Report> {
        self.advance_revision()?;
        self.inflight = match self.inflight.checked_add(1) {
            Some(next) => next,
            None => { self.close(); fail!(EIO, "RESTART_REPORT_EXHAUSTED"); }
        };
        Ok(Report { uid })
    }
    fn finish_report(&mut self, report: Report, result: Option<Response>) -> EnclaveResult<()> {
        self.inflight = match self.inflight.checked_sub(1) {
            Some(next) => next,
            None => { self.close(); fail!(EIO, "RESTART_REPORT_STATE"); }
        };
        self.advance_revision()?;
        match result {
            None => self.close(),
            Some(Response::Latched) => {
                self.latched = true;
                self.pending.retain(|uid, _| !pii_uid(*uid));
            }
            Some(Response::StrikeDelayRespawn) if report.uid != 702 && !self.latched && !self.faulted => {
                self.delay(report.uid, STRIKE_DELAY, Instant::now())?;
            }
            Some(_) => {}
        }
        Ok(())
    }
}

struct Report { uid: u32 }

// A try_lock refusal cannot reach State::close. This guard publishes a sticky
// negative admission latch on the SAME tracker before returning/unwinding,
// without waiting for that mutex. It grants no restart or completed teardown.
struct ReportDeadline<'a> { tracker: &'a RespawnTracker, end: Instant, armed: bool }
impl ReportDeadline<'_> {
    fn current(&self) -> EnclaveResult<()> {
        if self.tracker.deadline_vetoed.load(Ordering::SeqCst) {
            fail!(EACCES, "RESTART_REPORT_VETOED");
        }
        if Instant::now() >= self.end {
            self.tracker.deadline_vetoed.store(true, Ordering::SeqCst);
            fail!(ETIMEDOUT, "RESTART_REPORT_DEADLINE");
        }
        Ok(())
    }
}
impl Drop for ReportDeadline<'_> {
    fn drop(&mut self) {
        if self.armed { self.tracker.deadline_vetoed.store(true, Ordering::SeqCst); }
    }
}

/// Tracks local delay tickets and fault-report fencing. Expiry is not restart
/// authority, and a later positive report never clears a known latch/error.
#[derive(Debug, Default)]
pub struct RespawnTracker { state: Mutex<State>, deadline_vetoed: AtomicBool }

impl RespawnTracker {
    /// Create an empty local tracker; this does not authorize any restart.
    pub fn new() -> Self { Self::default() }

    /// Record a minimum delay. Overlapping delays can only extend it.
    /// This compatibility API grants no launch authority.
    pub fn record_delay(&self, uid: u32, duration: Duration) {
        let _ = self.record_delay_at(uid, duration, Instant::now());
    }

    fn record_delay_at(&self, uid: u32, duration: Duration, now: Instant) -> EnclaveResult<()> {
        let mut state = self.state.lock().map_err(|_| err!(EIO, "RESTART_FENCE_POISONED"))?;
        if pii_uid(uid) && (self.deadline_vetoed.load(Ordering::SeqCst) || state.latched || state.faulted) {
            fail!(EACCES, "RESTART_FENCED");
        }
        state.delay(uid, duration, now)
    }

    /// Remaining local delay, or a continuing PII hold after latch/error.
    /// Quarantine never adds a hold for UID 702's patch-pull service.
    pub fn is_throttled(&self, uid: u32) -> Option<Duration> {
        if pii_uid(uid) && self.deadline_vetoed.load(Ordering::SeqCst) { return Some(STRIKE_DELAY); }
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return pii_uid(uid).then_some(STRIKE_DELAY),
        };
        if pii_uid(uid) && (self.deadline_vetoed.load(Ordering::SeqCst)
            || state.latched || state.faulted || state.inflight != 0) {
            return Some(STRIKE_DELAY);
        }
        state.pending.get(&uid).and_then(|pending| pending.deadline.checked_duration_since(Instant::now()))
    }

    fn begin_report(&self, uid: u32) -> EnclaveResult<Report> {
        let mut state = self.state.lock().map_err(|_| err!(EIO, "RESTART_FENCE_POISONED"))?;
        state.begin_report(uid)
    }

    fn finish_report(&self, report: Report, result: Option<Response>) -> EnclaveResult<()> {
        let mut state = self.state.lock().map_err(|_| err!(EIO, "RESTART_FENCE_POISONED"))?;
        state.finish_report(report, result)
    }

    /// Used by BOTH actual root-request and Mach paths. Fence creation precedes
    /// all authority I/O. An unwinding authority leaves inflight nonzero, so no
    /// subsequent local handoff can succeed through this owner.
    pub(super) fn report_fault(&self, uid: u32, authority: impl FnOnce() -> EnclaveResult<Response>) -> EnclaveResult<Response> {
        let report = self.begin_report(uid)?;
        let result = authority();
        self.finish_report(report, result.as_ref().ok().copied())?;
        result
    }

    fn try_report_state(&self) -> EnclaveResult<MutexGuard<'_, State>> {
        match self.state.try_lock() {
            Ok(state) => Ok(state),
            Err(error) => {
                // Publish BEFORE even a poisoned guard held by error drops.
                self.deadline_vetoed.store(true, Ordering::SeqCst);
                match error {
                    TryLockError::WouldBlock => Err(err!(EAGAIN, "RESTART_REPORT_BUSY")),
                    TryLockError::Poisoned(_) => Err(err!(EIO, "RESTART_FENCE_POISONED")),
                }
            }
        }
    }

    /// Deadline-aware prerequisite for selected fault dispatch. `end` must be
    /// the caller's ORIGINAL earliest actor/session endpoint, not a new budget.
    /// This does not authenticate a fault, bound the supplied authority's own
    /// syscalls, send a report, authorize replay or grant a restart/Ready/Begin.
    ///
    /// Both admission and completion use try_lock. The authority receives the
    /// unchanged endpoint and runs once after the existing inflight fence. On
    /// busy/expiry/error/unwind, a sticky atomic veto keeps future PII admission
    /// closed even when the State mutex is unavailable. A callback admitted
    /// before this veto is not recalled; completed teardown is not claimed.
    /// UID702 retains its independently recorded delay and is not PII-fenced.
    pub(super) fn report_fault_before(&self, uid: u32, end: Instant,
        authority: impl FnOnce(Instant) -> EnclaveResult<Response>) -> EnclaveResult<Response> {
        let mut deadline = ReportDeadline { tracker: self, end, armed: true };
        deadline.current()?;
        let report = {
            let mut state = self.try_report_state()?;
            deadline.current()?;
            state.begin_report(uid)?
        };
        deadline.current()?;
        let response = authority(end)?;
        deadline.current()?;
        {
            let mut state = self.try_report_state()?;
            deadline.current()?;
            state.finish_report(report, Some(response))?;
            // Keep the original mutex through the final deadline/veto check.
            // Expiry cannot expose a clear gap after inflight was decremented.
            deadline.current()?;
            deadline.armed = false;
        }
        Ok(response)
    }
}

/// No automatic bootstrap call exists. Keep the first-strike bootout bounded
/// and refuse unsupported UIDs before any command. This is not proof that the
/// installed launchd service stopped or stayed stopped.
#[cfg(target_os = "macos")]
pub(super) fn bounded_bootout(label: &str) -> EnclaveResult<()> {
    use std::process::{Command, Stdio};
    let mut child = Command::new("/bin/launchctl")
        .args(["bootout", &format!("system/{label}")])
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().map_err(|_| err!(EIO, "DAEMON_BOOTOUT_SPAWN"))?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(_)) => fail!(EIO, "DAEMON_BOOTOUT_STATUS"),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => break,
        }
    }
    let _ = child.kill();
    let reap_deadline = Instant::now() + Duration::from_millis(250);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < reap_deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => break,
        }
    }
    fail!(ETIMEDOUT, "DAEMON_BOOTOUT_TIMEOUT")
}

// Deliberately test-only: these tokens are synthetic local-race capabilities,
// not authenticated current host/latch observations or production permits.
#[cfg(test)]
struct SyntheticPermit { uid: u32, ticket: u64, revision: u64, deadline: Instant }

#[cfg(test)]
impl RespawnTracker {
    fn synthetic_permit(&self, uid: u32) -> EnclaveResult<SyntheticPermit> {
        let state = self.state.lock().map_err(|_| err!(EIO, "RESTART_FENCE_POISONED"))?;
        if !pii_uid(uid) || self.deadline_vetoed.load(Ordering::SeqCst)
            || state.latched || state.faulted || state.inflight != 0 { fail!(EACCES, "RESTART_FENCED"); }
        let pending = state.pending.get(&uid).ok_or_else(|| err!(EACCES, "RESTART_TICKET_MISSING"))?;
        Ok(SyntheticPermit { uid, ticket: pending.ticket, revision: state.revision, deadline: pending.deadline })
    }

    fn synthetic_handoff(&self, permit: SyntheticPermit, now: Instant,
        callback: impl FnOnce() -> EnclaveResult<()>) -> EnclaveResult<()> {
        let mut state = self.state.lock().map_err(|_| err!(EIO, "RESTART_FENCE_POISONED"))?;
        if self.deadline_vetoed.load(Ordering::SeqCst) || state.latched || state.faulted
            || state.inflight != 0 || state.revision != permit.revision
            || !state.pending.get(&permit.uid).is_some_and(|p| p.ticket == permit.ticket && p.deadline == permit.deadline)
        { fail!(EACCES, "RESTART_FENCED"); }
        if now < permit.deadline { fail!(EAGAIN, "RESTART_DELAY_PENDING"); }
        state.pending.remove(&permit.uid);
        // Same serial as begin_report; the tests supply bounded callbacks.
        let result = callback();
        if result.is_err() { state.close(); }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, mpsc};

    fn delayed(tracker: &RespawnTracker, uid: u32) -> SyntheticPermit {
        assert_eq!(tracker.report_fault(uid, || Ok(Response::StrikeDelayRespawn)).unwrap(), Response::StrikeDelayRespawn);
        tracker.synthetic_permit(uid).unwrap()
    }

    #[test]
    fn exact_synthetic_ticket_requires_complete_delay_and_is_consumed_once() {
        let tracker = RespawnTracker::new();
        let first = delayed(&tracker, 701);
        assert!(tracker.synthetic_handoff(first, Instant::now(), || panic!("early launch")).unwrap_err().is("RESTART_DELAY_PENDING"));
        let permit = tracker.synthetic_permit(701).unwrap();
        let duplicate = tracker.synthetic_permit(701).unwrap();
        let at = permit.deadline;
        tracker.synthetic_handoff(permit, at, || Ok(())).unwrap();
        assert!(tracker.synthetic_handoff(duplicate, at, || panic!("duplicate launch")).is_err());
    }

    #[test]
    fn overlapping_delays_keep_maximum_deadline_and_invalidate_stale_ticket() {
        let tracker = RespawnTracker::new(); let at = Instant::now();
        tracker.record_delay_at(703, STRIKE_DELAY, at).unwrap();
        let stale = tracker.synthetic_permit(703).unwrap();
        tracker.record_delay_at(703, Duration::from_secs(10), at + Duration::from_secs(1)).unwrap();
        assert_eq!(tracker.synthetic_permit(703).unwrap().deadline, stale.deadline);
        tracker.record_delay_at(703, STRIKE_DELAY, at + Duration::from_secs(20)).unwrap();
        assert_eq!(tracker.synthetic_permit(703).unwrap().deadline, at + Duration::from_secs(320));
        assert!(tracker.synthetic_handoff(stale, at + Duration::from_secs(400), || panic!("old launch")).is_err());
        let latest = tracker.synthetic_permit(703).unwrap();
        assert!(tracker.synthetic_handoff(latest, at + Duration::from_secs(310), || panic!("shortened delay")).is_err());
        let latest = tracker.synthetic_permit(703).unwrap();
        tracker.synthetic_handoff(latest, at + Duration::from_secs(320), || Ok(())).unwrap();
    }

    #[test]
    fn actual_report_wrapper_fences_before_authority_io_and_latch_cancels_all_pii_only() {
        let tracker = Arc::new(RespawnTracker::new());
        for uid in [701, 703, 704, 705] { delayed(&tracker, uid); }
        tracker.record_delay(702, STRIKE_DELAY);
        let stale = tracker.synthetic_permit(701).unwrap(); let at = stale.deadline;
        let (entered_tx, entered_rx) = mpsc::channel(); let (resume_tx, resume_rx) = mpsc::channel();
        let worker = tracker.clone();
        let report = std::thread::spawn(move || worker.report_fault(703, || {
            entered_tx.send(()).unwrap(); resume_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            Ok(Response::Latched)
        }));
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(tracker.synthetic_handoff(stale, at, || panic!("launch during authority I/O")).is_err());
        resume_tx.send(()).unwrap(); assert_eq!(report.join().unwrap().unwrap(), Response::Latched);
        for uid in [701, 703, 704, 705] {
            assert!(tracker.synthetic_permit(uid).is_err()); assert!(tracker.is_throttled(uid).is_some());
        }
        let state = tracker.state.lock().unwrap();
        assert_eq!(state.pending.len(), 1); assert!(state.pending.contains_key(&702)); drop(state);
        // A subsequent benign/delay response cannot undo the known latch.
        tracker.report_fault(701, || Ok(Response::StrikeDelayRespawn)).unwrap();
        assert!(tracker.synthetic_permit(701).is_err());
    }

    #[test]
    fn completed_pre_fence_callback_stands_and_later_handoffs_are_rejected() {
        let tracker = Arc::new(RespawnTracker::new()); let permit = delayed(&tracker, 704); let at = permit.deadline;
        let (entered_tx, entered_rx) = mpsc::channel(); let (resume_tx, resume_rx) = mpsc::channel();
        let worker = tracker.clone();
        let handoff = std::thread::spawn(move || worker.synthetic_handoff(permit, at, || {
            entered_tx.send(()).unwrap(); resume_rx.recv_timeout(Duration::from_secs(2)).unwrap(); Ok(())
        }));
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let (attempt_tx, attempt_rx) = mpsc::channel(); let (authority_tx, authority_rx) = mpsc::channel();
        let worker = tracker.clone();
        let fence = std::thread::spawn(move || {
            attempt_tx.send(()).unwrap();
            worker.report_fault(704, || { authority_tx.send(()).unwrap(); Ok(Response::Latched) })
        });
        attempt_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(authority_rx.recv_timeout(Duration::from_millis(30)).is_err());
        resume_tx.send(()).unwrap(); handoff.join().unwrap().unwrap();
        authority_rx.recv_timeout(Duration::from_secs(2)).unwrap(); fence.join().unwrap().unwrap();
        assert!(tracker.synthetic_permit(704).is_err());
    }

    #[test]
    fn authority_failure_and_unwind_keep_pii_closed_without_blocking_patch_service() {
        let tracker = RespawnTracker::new(); delayed(&tracker, 701);
        assert!(tracker.report_fault(701, || Err(err!(EIO, "FIXTURE_AUTHORITY_UNKNOWN"))).unwrap_err().is("FIXTURE_AUTHORITY_UNKNOWN"));
        assert!(tracker.synthetic_permit(701).is_err()); assert!(tracker.is_throttled(702).is_none());
        let tracker = RespawnTracker::new(); let stale = delayed(&tracker, 705); let at = stale.deadline;
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = tracker.report_fault(705, || panic!("authority unwind"));
        }));
        assert!(unwind.is_err());
        assert!(tracker.synthetic_handoff(stale, at, || panic!("post-unwind launch")).is_err());
        assert!(tracker.is_throttled(705).is_some()); assert!(tracker.is_throttled(702).is_none());
    }

    #[test]
    fn checked_exhaustion_refuses_before_authority_and_poison_or_callback_error_never_reopens() {
        for counter in 0..3 {
            let tracker = RespawnTracker::new();
            { let mut state = tracker.state.lock().unwrap();
                match counter { 0 => state.revision = u64::MAX, 1 => state.inflight = u64::MAX, _ => state.next_ticket = u64::MAX }
            }
            if counter < 2 {
                assert!(tracker.report_fault(701, || panic!("authority after exhausted fence")).is_err());
            } else { assert!(tracker.record_delay_at(701, STRIKE_DELAY, Instant::now()).is_err()); }
            assert!(tracker.is_throttled(701).is_some()); assert!(tracker.is_throttled(702).is_none());
        }
        let tracker = RespawnTracker::new(); let permit = delayed(&tracker, 701); let at = permit.deadline;
        assert!(tracker.synthetic_handoff(permit, at, || Err(err!(EIO, "FIXTURE_COMMAND_FAILURE"))).is_err());
        assert!(tracker.synthetic_permit(701).is_err());
        let tracker = RespawnTracker::new(); let permit = delayed(&tracker, 701); let at = permit.deadline;
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = tracker.synthetic_handoff(permit, at, || panic!("bounded callback unwind"));
        })).is_err());
        assert!(tracker.is_throttled(701).is_some()); assert!(tracker.is_throttled(702).is_none());
    }

    fn assert_deadline_pii_fenced(tracker: &RespawnTracker) {
        assert!(tracker.deadline_vetoed.load(Ordering::SeqCst));
        for uid in [701, 703, 704, 705] {
            assert!(tracker.is_throttled(uid).is_some());
            assert!(tracker.synthetic_permit(uid).is_err());
        }
    }

    #[test]
    fn original_deadline_report_keeps_same_endpoint_single_authority_and_existing_response_uid702_rules() {
        for uid in [701, 702, 703, 704, 705] {
            for response in [Response::RestartThrottled, Response::StrikeDelayRespawn, Response::Latched] {
                let tracker = RespawnTracker::new();
                tracker.record_delay(702, Duration::from_secs(60));
                let patch_end = tracker.state.lock().unwrap().pending[&702].deadline;
                let end = Instant::now() + Duration::from_secs(60);
                let calls = std::cell::Cell::new(0);
                assert_eq!(tracker.report_fault_before(uid, end, |actual_end| {
                    calls.set(calls.get() + 1); assert_eq!(actual_end, end);
                    let state = tracker.state.lock().unwrap(); assert_eq!(state.inflight, 1);
                    drop(state);
                    for pii in [701, 703, 704, 705] { assert!(tracker.is_throttled(pii).is_some()); }
                    Ok(response)
                }).unwrap(), response);
                assert_eq!(calls.get(), 1); assert!(!tracker.deadline_vetoed.load(Ordering::SeqCst));
                let state = tracker.state.lock().unwrap(); assert_eq!(state.inflight, 0);
                assert_eq!(state.pending[&702].deadline, patch_end);
                assert_eq!(state.latched, response == Response::Latched);
                assert!(!state.faulted);
                if uid != 702 {
                    assert_eq!(state.pending.contains_key(&uid), response == Response::StrikeDelayRespawn);
                }
                drop(state);
                if response == Response::Latched {
                    for pii in [701, 703, 704, 705] { assert!(tracker.is_throttled(pii).is_some()); }
                }
                assert!(tracker.is_throttled(702).is_some(), "preserve the independently recorded patch delay");
            }
        }
    }

    #[test]
    fn original_deadline_exact_expiry_refuses_before_authority_and_never_reopens_after_later_legacy_success() {
        for already_past in [false, true] {
            let tracker = RespawnTracker::new();
            let end = if already_past { Instant::now() - Duration::from_secs(1) } else { Instant::now() };
            assert!(tracker.report_fault_before(703, end, |_| panic!("authority after original expiry"))
                .unwrap_err().is("RESTART_REPORT_DEADLINE"));
            { let state = tracker.state.lock().unwrap(); assert_eq!((state.revision, state.inflight), (0, 0)); }
            assert_deadline_pii_fenced(&tracker); assert!(tracker.is_throttled(702).is_none());
            assert!(tracker.report_fault_before(703, Instant::now() + Duration::from_secs(60),
                |_| panic!("fresh endpoint cannot revive original tracker"))
                .unwrap_err().is("RESTART_REPORT_VETOED"));
            assert_eq!(tracker.report_fault(703, || Ok(Response::RestartThrottled)).unwrap(), Response::RestartThrottled);
            assert_deadline_pii_fenced(&tracker); assert!(tracker.is_throttled(702).is_none());
        }
    }

    #[test]
    fn original_deadline_busy_admission_returns_while_original_mutex_is_still_owned_and_closes_future_pii() {
        let tracker = Arc::new(RespawnTracker::new());
        let state = tracker.state.lock().unwrap();
        let (completed, result) = mpsc::channel(); let worker = tracker.clone();
        let end = Instant::now() + Duration::from_secs(60);
        let thread = std::thread::spawn(move || {
            completed.send(worker.report_fault_before(703, end, |_| panic!("authority without original mutex")))
                .unwrap();
        });
        let refused = result.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(refused.unwrap_err().is("RESTART_REPORT_BUSY"));
        assert!(tracker.deadline_vetoed.load(Ordering::SeqCst));
        for uid in [701, 703, 704, 705] { assert!(tracker.is_throttled(uid).is_some()); }
        assert_eq!((state.revision, state.inflight), (0, 0));
        drop(state); thread.join().unwrap();
        assert_deadline_pii_fenced(&tracker); assert!(tracker.is_throttled(702).is_none());
    }

    #[test]
    fn original_deadline_authority_return_after_expiry_cannot_publish_any_positive_response_or_reset_fence() {
        for response in [Response::RestartThrottled, Response::StrikeDelayRespawn, Response::Latched] {
            let tracker = RespawnTracker::new();
            let end = Instant::now() + Duration::from_millis(250);
            assert!(tracker.report_fault_before(703, end, |actual_end| {
                assert_eq!(actual_end, end);
                std::thread::sleep(end.saturating_duration_since(Instant::now()) + Duration::from_millis(10));
                Ok(response)
            }).unwrap_err().is("RESTART_REPORT_DEADLINE"));
            let state = tracker.state.lock().unwrap(); assert_eq!(state.inflight, 1);
            assert!(!state.latched && !state.pending.contains_key(&703)); drop(state);
            assert_deadline_pii_fenced(&tracker); assert!(tracker.is_throttled(702).is_none());
        }
    }

    #[test]
    fn original_deadline_authority_error_or_unwind_keeps_same_inflight_fence_despite_later_legacy_reports() {
        for unwind in [false, true] {
            let tracker = RespawnTracker::new(); let stale = delayed(&tracker, 703); let at = stale.deadline;
            let end = Instant::now() + Duration::from_secs(60);
            if unwind {
                assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _ = tracker.report_fault_before(703, end, |actual_end| {
                        assert_eq!(actual_end, end); panic!("selected original authority unwind");
                    });
                })).is_err());
            } else {
                assert!(tracker.report_fault_before(703, end, |actual_end| {
                    assert_eq!(actual_end, end); Err(err!(EIO, "ORIGINAL_AUTHORITY_RECEIPT_UNKNOWN"))
                }).unwrap_err().is("ORIGINAL_AUTHORITY_RECEIPT_UNKNOWN"));
            }
            assert_eq!(tracker.state.lock().unwrap().inflight, 1);
            assert!(tracker.synthetic_handoff(stale, at, || panic!("stale release after authority failure")).is_err());
            assert_deadline_pii_fenced(&tracker); assert!(tracker.is_throttled(702).is_none());
            tracker.report_fault(703, || Ok(Response::StrikeDelayRespawn)).unwrap();
            assert_eq!(tracker.state.lock().unwrap().inflight, 1);
            assert_deadline_pii_fenced(&tracker); assert!(tracker.is_throttled(702).is_none());
        }
    }

    #[test]
    fn original_deadline_busy_completion_never_waits_for_replacement_mutex_or_discards_unknown_inflight_report() {
        let tracker = Arc::new(RespawnTracker::new());
        let (hold, requested) = mpsc::channel(); let (ready, held) = mpsc::channel();
        let (release, wait) = mpsc::channel(); let worker = tracker.clone();
        let holder = std::thread::spawn(move || {
            requested.recv_timeout(Duration::from_secs(2)).unwrap();
            let state = worker.state.lock().unwrap(); ready.send(()).unwrap();
            wait.recv_timeout(Duration::from_secs(2)).unwrap(); state.inflight
        });
        let end = Instant::now() + Duration::from_secs(60);
        let result = tracker.report_fault_before(703, end, |actual_end| {
            assert_eq!(actual_end, end); hold.send(()).unwrap();
            held.recv_timeout(Duration::from_secs(2)).unwrap(); Ok(Response::RestartThrottled)
        });
        assert!(result.unwrap_err().is("RESTART_REPORT_BUSY"));
        assert!(tracker.deadline_vetoed.load(Ordering::SeqCst));
        for uid in [701, 703, 704, 705] { assert!(tracker.is_throttled(uid).is_some()); }
        release.send(()).unwrap(); assert_eq!(holder.join().unwrap(), 1);
        assert_deadline_pii_fenced(&tracker); assert!(tracker.is_throttled(702).is_none());
    }

    #[test]
    fn original_deadline_actual_authority_fences_same_tracker_and_invalidates_old_synthetic_tickets_before_io() {
        let tracker = Arc::new(RespawnTracker::new()); let stale = delayed(&tracker, 701); let at = stale.deadline;
        let (entered, entry) = mpsc::channel(); let (release, wait) = mpsc::channel();
        let worker = tracker.clone(); let end = Instant::now() + Duration::from_secs(60);
        let report = std::thread::spawn(move || worker.report_fault_before(703, end, |actual_end| {
            assert_eq!(actual_end, end); entered.send(()).unwrap();
            wait.recv_timeout(Duration::from_secs(2)).unwrap(); Ok(Response::StrikeDelayRespawn)
        }));
        entry.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(tracker.state.lock().unwrap().inflight, 1);
        assert!(tracker.synthetic_handoff(stale, at, || panic!("PII handoff during same original authority")).is_err());
        for uid in [701, 703, 704, 705] { assert!(tracker.is_throttled(uid).is_some()); }
        assert!(tracker.is_throttled(702).is_none());
        release.send(()).unwrap(); assert_eq!(report.join().unwrap().unwrap(), Response::StrikeDelayRespawn);
        assert!(!tracker.deadline_vetoed.load(Ordering::SeqCst));
        assert!(tracker.synthetic_permit(703).is_ok());
        assert_eq!(tracker.state.lock().unwrap().inflight, 0);
    }

    #[test]
    fn original_deadline_failed_concurrent_report_cuts_off_late_success_of_other_original_inflight_authority() {
        let tracker = Arc::new(RespawnTracker::new());
        let (entered, entry) = mpsc::channel(); let (release, wait) = mpsc::channel();
        let worker = tracker.clone(); let end = Instant::now() + Duration::from_secs(60);
        let report = std::thread::spawn(move || worker.report_fault_before(703, end, |_| {
            entered.send(()).unwrap(); wait.recv_timeout(Duration::from_secs(2)).unwrap();
            Ok(Response::RestartThrottled)
        }));
        entry.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(tracker.report_fault_before(701, Instant::now(), |_| panic!("expired second authority"))
            .unwrap_err().is("RESTART_REPORT_DEADLINE"));
        release.send(()).unwrap();
        assert!(report.join().unwrap().unwrap_err().is("RESTART_REPORT_VETOED"));
        assert_eq!(tracker.state.lock().unwrap().inflight, 1);
        assert_deadline_pii_fenced(&tracker); assert!(tracker.is_throttled(702).is_none());
    }

    #[test]
    fn original_deadline_counter_exhaustion_or_poison_refuses_without_losing_pii_fence_or_patch_exception() {
        for condition in ["begin_revision", "begin_inflight", "finish_revision", "finish_ticket", "finish_inflight"] {
            let tracker = RespawnTracker::new(); let called = std::cell::Cell::new(false);
            { let mut state = tracker.state.lock().unwrap();
                match condition { "begin_revision" => state.revision = u64::MAX,
                    "begin_inflight" => state.inflight = u64::MAX, _ => {} }
            }
            assert!(tracker.report_fault_before(703, Instant::now() + Duration::from_secs(60), |_| {
                called.set(true); let mut state = tracker.state.lock().unwrap();
                match condition { "finish_revision" => state.revision = u64::MAX,
                    "finish_ticket" => state.next_ticket = u64::MAX,
                    "finish_inflight" => state.inflight = 0, _ => {} }
                Ok(Response::StrikeDelayRespawn)
            }).is_err());
            assert_eq!(called.get(), condition.starts_with("finish_"));
            assert!(tracker.state.lock().unwrap().faulted);
            assert_deadline_pii_fenced(&tracker); assert!(tracker.is_throttled(702).is_none());
        }
        let tracker = RespawnTracker::new();
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _state = tracker.state.lock().unwrap(); panic!("original state poisoned");
        })).is_err());
        assert!(tracker.report_fault_before(703, Instant::now() + Duration::from_secs(60),
            |_| panic!("authority through poisoned tracker")).unwrap_err().is("RESTART_FENCE_POISONED"));
        assert_deadline_pii_fenced(&tracker); assert!(tracker.is_throttled(702).is_none());
    }

    #[test]
    fn original_deadline_busy_veto_cannot_recall_preexisting_entered_callback_but_blocks_every_later_handoff() {
        let tracker = Arc::new(RespawnTracker::new()); let permit = delayed(&tracker, 703); let at = permit.deadline;
        let (entered, entry) = mpsc::channel(); let (release, wait) = mpsc::channel(); let worker = tracker.clone();
        let handoff = std::thread::spawn(move || worker.synthetic_handoff(permit, at, || {
            entered.send(()).unwrap(); wait.recv_timeout(Duration::from_secs(2)).unwrap(); Ok(())
        }));
        entry.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(tracker.report_fault_before(703, Instant::now() + Duration::from_secs(60),
            |_| panic!("authority while original handoff owns serial")).unwrap_err().is("RESTART_REPORT_BUSY"));
        assert!(tracker.is_throttled(703).is_some(), "negative admission latch requires no mutex wait");
        release.send(()).unwrap(); handoff.join().unwrap().unwrap();
        assert_deadline_pii_fenced(&tracker); assert!(tracker.is_throttled(702).is_none());
        tracker.report_fault(703, || Ok(Response::StrikeDelayRespawn)).unwrap();
        assert!(tracker.synthetic_permit(703).is_err());
    }
}
