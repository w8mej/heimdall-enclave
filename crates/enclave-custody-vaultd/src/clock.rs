//! Injectable clocks (monotonic ns + wall seconds) so rate limits, the 10 s
//! ceremony budget and metadata freshness are testable deterministically.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

/// Clock source.
pub trait Clock: std::fmt::Debug + Send + Sync {
    /// Monotonic nanoseconds (`mach_continuous_time` on macOS).
    fn now_ns(&self) -> u64;
    /// Wall-clock Unix seconds.
    fn now_unix(&self) -> i64;
    /// Monotonic milliseconds.
    fn now_ms(&self) -> u64 {
        self.now_ns() / 1_000_000
    }
}

/// Real clocks.
#[derive(Debug, Clone, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ns(&self) -> u64 {
        // The GUI helper is another process: a per-instance Instant origin
        // cannot be compared with its boot-relative timestamps. The shared
        // continuous clock also includes suspend time in the complete budget.
        enclave_core::clock::boot_clock_ns()
    }
    fn now_unix(&self) -> i64 {
        enclave_crypto::time::now_unix()
    }
}

/// Manually advanced clock for tests.
#[derive(Debug, Clone, Default)]
pub struct TestClock {
    ns: Arc<AtomicU64>,
    unix: Arc<AtomicI64>,
}

impl TestClock {
    /// Start at the given wall time.
    pub fn at(unix: i64) -> Self {
        let c = Self::default();
        c.unix.store(unix, Ordering::SeqCst);
        c.ns.store(1_000_000_000, Ordering::SeqCst);
        c
    }
    /// Advance both clocks.
    pub fn advance_ms(&self, ms: u64) {
        self.ns.fetch_add(ms * 1_000_000, Ordering::SeqCst);
        self.unix.fetch_add((ms / 1000) as i64, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now_ns(&self) -> u64 {
        self.ns.load(Ordering::SeqCst)
    }
    fn now_unix(&self) -> i64 {
        self.unix.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::{Clock, SystemClock};

    #[test]
    fn system_clock_uses_the_shared_boot_origin() {
        let before = enclave_core::clock::boot_clock_ns();
        let clock = SystemClock::default();
        let observed = clock.now_ns();
        let after = enclave_core::clock::boot_clock_ns();
        assert!(before <= observed && observed <= after);
        assert!(SystemClock::default().now_ns() >= observed);
    }
}
