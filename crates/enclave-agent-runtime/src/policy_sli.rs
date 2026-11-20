//! Bounded, per-boot telemetry for actual conjunctive policy evaluations.
//!
//! This collector is diagnostic: it never decides authorization or substitutes
//! for installed/load acceptance. The first partial minute is never covered.

use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Retained completed minutes (72 hours).
pub const HISTORY_MINUTES: usize = 4320;
/// Inclusive counter ceiling accepted by the offline aggregator.
pub const MAX_COUNT: u64 = 1_000_000_000_000_000;
/// A measured duration is bad strictly above this threshold (45 microseconds).
pub const BAD_ABOVE_NS: u64 = 45_000;
const MINUTE_NS: u64 = 60_000_000_000;
const CLOCK_TOLERANCE_NS: u64 = 1_000_000_000;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ClockSample {
    utc_ns: u64,
    continuous_ns: u64,
}

impl ClockSample {
    pub(crate) fn now() -> Option<Self> {
        let utc_ns = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_nanos()).ok()?;
        let continuous_ns = enclave_core::clock::boot_clock_ns();
        (continuous_ns != u64::MAX).then_some(Self { utc_ns, continuous_ns })
    }
}

/// Privacy-safe counts for one completed UTC minute, or the current partial minute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBucket {
    /// Aligned Unix seconds at the beginning of the minute.
    pub minute: u64,
    /// Calls reaching the conjunctive PDP, including early errors.
    pub total: u64,
    /// Known durations strictly above 45 microseconds, including slow errors.
    pub bad: u64,
    /// Calls with unavailable duration, or fast calls with unavailable verdict.
    pub unknown: u64,
    /// Calls returning an error instead of an authorization decision.
    /// Such buckets must be omitted from aggregator input: a known slow error
    /// remains bad here, but its outcome must never silently establish health.
    pub errors: u64,
}

impl PolicyBucket {
    fn empty(minute: u64) -> Self {
        Self { minute, total: 0, bad: 0, unknown: 0, errors: 0 }
    }
}

/// Bounded snapshot. Metadata is supplied by the authenticated daemon, not callers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySliSnapshot {
    /// Wire/producer version.
    pub schema: u8,
    /// Exact producer implementation contract.
    pub producer: String,
    /// Runtime boot epoch; no data survives a restart.
    pub boot_epoch_id: String,
    /// Runtime-selected profile.
    pub profile: String,
    /// Active Cedar bundle digest at snapshot time (not each historical call).
    pub cedar_bundle_blake3: String,
    /// Configured depot lock digest (signature provenance is installation evidence).
    pub depot_lock_blake3: String,
    /// Actual runtime UID.
    pub runtime_uid: u32,
    /// Actual runtime PID.
    pub runtime_pid: u32,
    /// True only for the explicitly configured same-UID development service.
    pub dev_same_uid: bool,
    /// Exclusive aligned UTC endpoint; absent if the clock is unavailable.
    pub as_of_unix_s: Option<u64>,
    /// Latched clock failure/regression/discontinuity; invalidates exported rows.
    pub clock_fault: bool,
    /// Latched counter overflow; invalidates exported rows.
    pub overflow: bool,
    /// Total observed calls since this process boot, bounded by MAX_COUNT.
    pub observed_total: u64,
    /// Error returns since this process boot, bounded by MAX_COUNT.
    pub observed_errors: u64,
    /// Completed, fully covered minutes only, in increasing order.
    pub buckets: Vec<PolicyBucket>,
    /// Current partial minute, never eligible for aggregation.
    pub current: Option<PolicyBucket>,
}

/// Aggregator's exact privacy-safe row shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySliRow {
    /// Aggregator schema.
    pub schema: u8,
    /// Fixed metric name.
    pub metric: String,
    /// Aligned minute in Unix seconds.
    pub minute: u64,
    /// Observed denominator.
    pub total: u64,
    /// Known slow evaluations.
    pub bad: u64,
    /// Unavailable timings/outcomes.
    pub unknown: u64,
}

impl PolicySliSnapshot {
    /// Produce strict aggregator rows. Clock/overflow faults invalidate all rows;
    /// error-return buckets are omitted, leaving visible coverage holes.
    pub fn rows(&self) -> Vec<PolicySliRow> {
        if self.clock_fault || self.overflow { return Vec::new(); }
        self.buckets.iter().filter(|b| b.errors == 0).map(|b| PolicySliRow {
            schema: 1, metric: "policy_evaluation".into(), minute: b.minute,
            total: b.total, bad: b.bad, unknown: b.unknown,
        }).collect()
    }

    /// Whether all 4320 minutes are present without unknown timings/errors.
    /// This says nothing about load, SLO success, synchronization or installation.
    pub fn history_complete(&self) -> bool {
        if self.clock_fault || self.overflow || self.buckets.len() != HISTORY_MINUTES { return false; }
        let Some(as_of) = self.as_of_unix_s else { return false; };
        let Some(start) = as_of.checked_sub(HISTORY_MINUTES as u64 * 60) else { return false; };
        self.buckets.iter().enumerate().all(|(i, b)|
            b.minute == start + i as u64 * 60 && b.errors == 0 && b.unknown == 0)
    }
}

#[derive(Debug)]
pub(crate) struct PolicySli {
    buckets: VecDeque<PolicyBucket>,
    current: Option<PolicyBucket>,
    first_minute: Option<u64>,
    origin: Option<ClockSample>,
    last: Option<ClockSample>,
    clock_fault: bool,
    overflow: bool,
    total: u64,
    errors: u64,
}

impl PolicySli {
    pub(crate) fn new(now: Option<ClockSample>) -> Self {
        let current = now.map(|n| PolicyBucket::empty(n.utc_ns / MINUTE_NS * 60));
        Self { buckets: VecDeque::with_capacity(HISTORY_MINUTES), first_minute: current.as_ref().map(|b| b.minute),
            current, origin: now, last: now, clock_fault: now.is_none(), overflow: false, total: 0, errors: 0 }
    }

    fn advance(&mut self, now: Option<ClockSample>) -> Option<u64> {
        let Some(now) = now else { self.clock_fault = true; return None; };
        if let (Some(origin), Some(last)) = (self.origin, self.last) {
            let utc = now.utc_ns.checked_sub(origin.utc_ns);
            let mono = now.continuous_ns.checked_sub(origin.continuous_ns);
            if now.utc_ns < last.utc_ns || now.continuous_ns < last.continuous_ns
                || !matches!((utc, mono), (Some(u), Some(m)) if u.abs_diff(m) <= CLOCK_TOLERANCE_NS) {
                self.clock_fault = true;
            }
        } else { self.clock_fault = true; }
        self.last = Some(now);
        let minute = now.utc_ns / MINUTE_NS * 60;
        if self.clock_fault { return Some(minute); }
        if let Some(current) = &self.current {
            if minute > current.minute {
                let previous = self.current.take().unwrap();
                let old_minute = previous.minute;
                if Some(old_minute) != self.first_minute {
                    if self.buckets.len() == HISTORY_MINUTES { self.buckets.pop_front(); }
                    self.buckets.push_back(previous);
                }
                // A process can be idle arbitrarily long. Iterate at most 4320
                // times and retain only the actual covered horizon.
                let earliest = minute.saturating_sub(HISTORY_MINUTES as u64 * 60);
                let mut next = old_minute.saturating_add(60).max(earliest);
                while next < minute {
                    if self.buckets.len() == HISTORY_MINUTES { self.buckets.pop_front(); }
                    self.buckets.push_back(PolicyBucket::empty(next));
                    next += 60;
                }
                while self.buckets.front().is_some_and(|b| b.minute < earliest)
                    || self.buckets.len() > HISTORY_MINUTES { self.buckets.pop_front(); }
                self.current = Some(PolicyBucket::empty(minute));
            }
        }
        Some(minute)
    }

    fn increment(value: &mut u64, overflow: &mut bool) {
        if *value == MAX_COUNT { *overflow = true; } else { *value += 1; }
    }

    pub(crate) fn observe(&mut self, now: Option<ClockSample>, elapsed_ns: Option<u64>, outcome_available: bool) {
        self.advance(now);
        if self.overflow { return; }
        Self::increment(&mut self.total, &mut self.overflow);
        if self.overflow { return; }
        if !outcome_available { Self::increment(&mut self.errors, &mut self.overflow); }
        if self.clock_fault { return; }
        if let Some(bucket) = &mut self.current {
            Self::increment(&mut bucket.total, &mut self.overflow);
            if !outcome_available { Self::increment(&mut bucket.errors, &mut self.overflow); }
            match elapsed_ns {
                Some(n) if n > BAD_ABOVE_NS => Self::increment(&mut bucket.bad, &mut self.overflow),
                None => Self::increment(&mut bucket.unknown, &mut self.overflow),
                Some(_) if !outcome_available => Self::increment(&mut bucket.unknown, &mut self.overflow),
                Some(_) => {}
            }
        }
    }

    pub(crate) fn snapshot(&mut self, now: Option<ClockSample>) -> PolicySliSnapshot {
        let as_of_unix_s = self.advance(now);
        PolicySliSnapshot { schema: 1, producer: "uid704-conjunctive-policy-v1".into(),
            boot_epoch_id: String::new(), profile: String::new(), cedar_bundle_blake3: String::new(),
            depot_lock_blake3: String::new(), runtime_uid: enclave_core::ipc::geteuid(),
            runtime_pid: std::process::id(), dev_same_uid: false, as_of_unix_s,
            clock_fault: self.clock_fault, overflow: self.overflow, observed_total: self.total,
            observed_errors: self.errors, buckets: self.buckets.iter().cloned().collect(), current: self.current.clone() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clock(seconds: u64) -> Option<ClockSample> {
        Some(ClockSample { utc_ns: seconds * 1_000_000_000, continuous_ns: seconds * 1_000_000_000 })
    }

    #[test]
    fn boundaries_errors_and_unknown_are_disjoint_and_never_fast_healthy() {
        let mut sli = PolicySli::new(clock(61));
        sli.observe(clock(62), Some(1), true); // first partial minute excluded
        sli.observe(clock(120), Some(45_000), true);
        sli.observe(clock(121), Some(45_001), true);
        sli.observe(clock(122), Some(1), false);
        sli.observe(clock(123), Some(45_001), false);
        sli.observe(clock(124), None, true);
        let snapshot = sli.snapshot(clock(180));
        assert_eq!(snapshot.buckets, vec![PolicyBucket { minute: 120, total: 5, bad: 2, unknown: 2, errors: 2 }]);
        assert!(snapshot.rows().is_empty());
        assert!(!snapshot.history_complete());
        assert_eq!((snapshot.observed_total, snapshot.observed_errors), (6, 2));
    }

    #[test]
    fn idle_horizon_is_bounded_and_restart_cannot_inherit_coverage() {
        let mut sli = PolicySli::new(clock(61));
        let snapshot = sli.snapshot(clock(61 + (HISTORY_MINUTES as u64 + 20) * 60));
        assert_eq!(snapshot.buckets.len(), HISTORY_MINUTES);
        assert!(snapshot.history_complete());
        assert!(snapshot.rows().iter().all(|b| b.total == 0));
        let mut restarted = PolicySli::new(clock(61 + (HISTORY_MINUTES as u64 + 20) * 60));
        assert!(restarted.snapshot(clock(62 + (HISTORY_MINUTES as u64 + 20) * 60)).buckets.is_empty());
    }

    #[test]
    fn unavailable_regressed_and_discontinuous_clocks_latch_incomplete() {
        let failures = [None, clock(60), Some(ClockSample { utc_ns: 180_000_000_000, continuous_ns: 62_000_000_000 }),
            Some(ClockSample { utc_ns: 62_000_000_000, continuous_ns: 60_000_000_000 })];
        for failure in failures {
            let mut sli = PolicySli::new(clock(61));
            sli.observe(clock(62), Some(1), true);
            sli.snapshot(failure);
            let snapshot = sli.snapshot(clock(240));
            assert!(snapshot.clock_fault);
            assert!(snapshot.rows().is_empty());
            assert!(!snapshot.history_complete());
        }
        assert!(PolicySli::new(None).snapshot(clock(180)).clock_fault);
    }

    #[test]
    fn full_ring_single_minute_advances_never_grow_capacity() {
        let mut sli = PolicySli::new(clock(61));
        let start = 61 + (HISTORY_MINUTES as u64 + 20) * 60;
        sli.snapshot(clock(start));
        for i in 1..=10 {
            sli.snapshot(clock(start + i * 60));
            assert_eq!(sli.buckets.len(), HISTORY_MINUTES);
            assert!(sli.buckets.capacity() <= HISTORY_MINUTES);
        }
    }

    #[test]
    fn counter_overflow_is_visible_and_invalidates_rows() {
        let mut sli = PolicySli::new(clock(61));
        sli.total = MAX_COUNT;
        sli.observe(clock(120), Some(1), true);
        let snapshot = sli.snapshot(clock(180));
        assert!(snapshot.overflow);
        assert_eq!(snapshot.observed_total, MAX_COUNT);
        assert_eq!(snapshot.current.as_ref().unwrap().total, 0);
        assert!(snapshot.rows().is_empty());
        sli.observe(clock(181), Some(BAD_ABOVE_NS + 1), false);
        let later = sli.snapshot(clock(240));
        assert_eq!(later.observed_errors, snapshot.observed_errors);
        assert!(later.buckets.iter().all(|b| b.bad + b.unknown <= b.total && b.errors <= b.total));
    }

    #[test]
    fn maximum_snapshot_is_below_ipc_frame_limit_including_reply_envelope() {
        let mut sli = PolicySli::new(clock(61));
        let mut snapshot = sli.snapshot(clock(61 + (HISTORY_MINUTES as u64 + 20) * 60));
        snapshot.boot_epoch_id = "f".repeat(36);
        snapshot.profile = "L3".into();
        snapshot.cedar_bundle_blake3 = "f".repeat(64);
        snapshot.depot_lock_blake3 = "f".repeat(64);
        snapshot.observed_total = MAX_COUNT;
        snapshot.observed_errors = MAX_COUNT;
        for b in snapshot.buckets.iter_mut().chain(snapshot.current.iter_mut()) {
            b.minute = u64::MAX;
            b.total = MAX_COUNT; b.bad = MAX_COUNT; b.unknown = MAX_COUNT; b.errors = MAX_COUNT;
        }
        let response = crate::service::IfcResponse::PolicySli(snapshot);
        let wire = enclave_core::ipc::to_cbor(&enclave_core::ipc::Reply::Ok(response.clone())).unwrap();
        assert!(wire.len() < enclave_core::ipc::MAX_FRAME);
        assert!(serde_json::to_vec(&response).unwrap().len() < enclave_core::ipc::MAX_FRAME);
    }
}
