//! FS-703 §5.2 two-phase **Lock-Then-Scrub** panic zeroizer.
//!
//! Freeze registered CPU pages, arm every accelerator fence, then scrub owned
//! regions only after every fence confirms completion. Incomplete fences retain
//! frozen regions for a later cleanup attempt; CPU protection is not DMA isolation.
//!
//! YKD-05's optional fast reinsertion recovery is disabled. Every yank follows
//! cancellation and fresh authorization; a boolean reattestation cannot thaw old
//! secrets. The existing timeout constants below are legacy implementation
//! limits, not calibrated YKD-02 profile budgets or native acceptance evidence.

use std::sync::Arc;
use std::time::{Duration, Instant};

use enclave_core::error::EnclaveResult;
use enclave_core::guarded::GuardedRegion;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};

/// CPU freeze budget.
pub const CPU_FREEZE_BUDGET: Duration = Duration::from_micros(500);
/// GPU/ANE fence budget.
pub const FENCE_BUDGET: Duration = Duration::from_micros(4500);
/// Historical docked re-attestation window; recovery is disabled (YKD-05).
pub const DOCKED_REATTEST_WINDOW: Duration = Duration::from_millis(250);

/// Tamper / power events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TamperEvent {
    /// `kIOTerminatedNotification` for the YubiKey.
    UsbYank {
        /// On AC behind the enrolled root-port dock (glitch shield eligible).
        docked: bool,
    },
    /// `com.apple.screenIsLocked`.
    ScreenLock,
    /// `kIOMessageSystemWillSleep`.
    LidSleep,
    /// Keep-alive signature failure.
    KeepaliveFailure,
    /// The service loop has stopped and its live authorization is closing.
    Shutdown,
}

/// A GPU/ANE completion fence (`MTLSharedEvent` on hardware).
pub trait GpuFence: std::fmt::Debug + Send + Sync {
    /// Abort/fence in-flight command buffers.
    fn arm(&self);
    /// Wait until DMA isolation is guaranteed, up to `deadline`.
    fn wait(&self, deadline: Duration) -> bool;
}

/// A fence that signals after a fixed latency (CI stand-in for Metal).
#[derive(Debug, Clone)]
#[cfg(any(test, feature = "simulation"))]
pub struct SimulatedFence {
    latency: Duration,
    armed_at: Arc<std::sync::Mutex<Option<Instant>>>,
}

#[cfg(any(test, feature = "simulation"))]
impl SimulatedFence {
    /// New fence with the given completion latency.
    pub fn new(latency: Duration) -> Self {
        Self {
            latency,
            armed_at: Arc::new(std::sync::Mutex::new(None)),
        }
    }
}

#[cfg(any(test, feature = "simulation"))]
impl GpuFence for SimulatedFence {
    fn arm(&self) {
        if let Ok(mut g) = self.armed_at.lock() {
            *g = Some(Instant::now());
        }
    }
    fn wait(&self, deadline: Duration) -> bool {
        let start = self
            .armed_at
            .lock()
            .ok()
            .and_then(|g| *g)
            .unwrap_or_else(Instant::now);
        let done = start + self.latency;
        let limit = Instant::now() + deadline;
        if done > limit {
            std::thread::sleep(limit.saturating_duration_since(Instant::now()));
            return false;
        }
        std::thread::sleep(done.saturating_duration_since(Instant::now()));
        true
    }
}

/// Measured outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZeroizeReport {
    /// Event.
    pub event: TamperEvent,
    /// Phase-1 CPU freeze time (ns).
    pub freeze_ns: u64,
    /// Fence wait time (ns).
    pub fence_ns: u64,
    /// Scrub time (ns).
    pub scrub_ns: u64,
    /// Whether the docked re-attestation thawed the regions instead of scrubbing.
    pub thawed: bool,
    /// Regions scrubbed.
    pub regions_scrubbed: usize,
}

/// The zeroizer.
#[derive(Debug, Default)]
pub struct PanicZeroizer {
    regions: Vec<Arc<GuardedRegion>>,
    fences: Vec<Arc<dyn GpuFence>>,
}

impl PanicZeroizer {
    /// New.
    pub fn new() -> Self {
        Self::default()
    }
    /// Register a secret region.
    pub fn register(&mut self, r: Arc<GuardedRegion>) {
        self.regions.push(r);
    }
    /// Register a GPU/ANE fence.
    pub fn register_fence(&mut self, f: Arc<dyn GpuFence>) {
        self.fences.push(f);
    }

    fn scrub_all(&self) -> (u64, usize) {
        let t = Instant::now();
        let n = self.regions.iter().filter(|r| r.scrub()).count();
        (t.elapsed().as_nanos() as u64, n)
    }

    /// Handle an event. The legacy callback is deliberately never called:
    /// optional recovery has no approved contract and cannot restore old state.
    pub fn handle(
        &self,
        event: TamperEvent,
        _reattest: impl FnMut() -> bool,
    ) -> EnclaveResult<ZeroizeReport> {
        let t0 = Instant::now();
        let mut froze_all = true;
        for r in &self.regions {
            froze_all &= r.freeze();
        }
        for f in &self.fences {
            f.arm();
        }
        let freeze_ns = t0.elapsed().as_nanos() as u64;

        let tf = Instant::now();
        // Do not short-circuit: every armed owner must observe cancellation.
        let mut fences_ok = true;
        for fence in &self.fences {
            fences_ok &= fence.wait(FENCE_BUDGET.saturating_sub(t0.elapsed()));
        }
        let fence_ns = tf.elapsed().as_nanos() as u64;
        if !fences_ok {
            // An accelerator may still write. Scrubbing/reusing that backing
            // memory now would permit late writes after the reported scrub.
            // Keep ownership and CPU restrictions; a later handle call retries.
            return Err(err!(ETIMEDOUT, "FENCE_BUDGET_MISSED",
                "event={event:?}, freeze_ns={freeze_ns}, fence_ns={fence_ns}, scrub_deferred=true"));
        }
        let (scrub_ns, n) = self.scrub_all();
        let report = ZeroizeReport {
            event,
            freeze_ns,
            fence_ns,
            scrub_ns,
            thawed: false,
            regions_scrubbed: n,
        };
        if !froze_all {
            fail!(EIO, "FREEZE_FAILED", "{report:?}");
        }
        if Duration::from_nanos(freeze_ns) > CPU_FREEZE_BUDGET {
            return Err(err!(ETIMEDOUT, "CPU_FREEZE_BUDGET_MISSED", "{report:?}"));
        }
        if n != self.regions.len() {
            fail!(EIO, "SCRUB_INCOMPLETE");
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret_region() -> Arc<GuardedRegion> {
        let mut r = GuardedRegion::new(4096).unwrap();
        r.as_mut_slice().unwrap()[..16].copy_from_slice(b"sk_detok_a4_____");
        Arc::new(r)
    }

    #[test]
    fn undocked_yank_freezes_fast_and_scrubs_within_fence_budget() {
        let mut z = PanicZeroizer::new();
        let regs: Vec<_> = (0..8).map(|_| secret_region()).collect();
        for r in &regs {
            z.register(r.clone());
        }
        z.register_fence(Arc::new(SimulatedFence::new(Duration::from_millis(1))));
        let rep = z
            .handle(TamperEvent::UsbYank { docked: false }, || false)
            .unwrap();
        assert!(
            Duration::from_nanos(rep.freeze_ns) < CPU_FREEZE_BUDGET,
            "{rep:?}"
        );
        assert!(
            Duration::from_nanos(rep.freeze_ns + rep.fence_ns + rep.scrub_ns)
                <= FENCE_BUDGET + Duration::from_millis(1),
            "{rep:?}"
        );
        assert!(regs.iter().all(|r| r.is_scrubbed() && r.verify_zeroed()));
    }

    #[test]
    fn docked_return_never_calls_reattest_or_revives_scrubbed_secrets() {
        let mut z = PanicZeroizer::new();
        let r = secret_region();
        z.register(r.clone());
        let rep = z.handle(TamperEvent::UsbYank { docked: true }, || {
            panic!("optional fast recovery must remain disabled")
        }).unwrap();
        assert!(!rep.thawed);
        assert!(r.is_scrubbed() && r.verify_zeroed());
        assert!(r.as_slice().is_err());
        assert!(r.thaw().is_err());
    }

    #[derive(Debug)]
    struct ControlledFence {
        completed: std::sync::atomic::AtomicBool,
        waits: std::sync::atomic::AtomicUsize,
    }
    impl GpuFence for ControlledFence {
        fn arm(&self) {}
        fn wait(&self, _: Duration) -> bool {
            self.waits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.completed.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[test]
    fn incomplete_fence_retains_frozen_owner_attempts_all_waits_and_retries_cleanup() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let mut z = PanicZeroizer::new();
        let r = secret_region(); z.register(r.clone());
        let first = Arc::new(ControlledFence { completed: AtomicBool::new(false), waits: AtomicUsize::new(0) });
        let second = Arc::new(ControlledFence { completed: AtomicBool::new(true), waits: AtomicUsize::new(0) });
        z.register_fence(first.clone()); z.register_fence(second.clone());
        assert!(z.handle(TamperEvent::LidSleep, || false).unwrap_err().is("FENCE_BUDGET_MISSED"));
        assert_eq!(first.waits.load(Ordering::SeqCst), 1);
        assert_eq!(second.waits.load(Ordering::SeqCst), 1);
        assert!(r.is_frozen() && !r.is_scrubbed());
        assert!(r.as_slice().is_err());
        first.completed.store(true, Ordering::SeqCst);
        let report = z.handle(TamperEvent::LidSleep, || false).unwrap();
        assert_eq!(report.regions_scrubbed, 1);
        assert!(r.is_scrubbed() && r.verify_zeroed());
    }
}
