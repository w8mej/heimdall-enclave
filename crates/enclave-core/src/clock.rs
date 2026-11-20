//! The enclave's own clocks (GAP-04). Expiry and freshness decisions read
//! time inside the daemon; a caller never supplies "now".

/// Boot-relative monotonic clock in nanoseconds: `CLOCK_MONOTONIC` on macOS
/// and `CLOCK_BOOTTIME` on Linux. Absolute ceremony, helper and transport
/// deadlines must use this same origin. In particular, scaled macOS
/// `mach_continuous_time` ticks have a different origin and are not comparable.
pub fn boot_clock_ns() -> u64 {
    #[cfg(target_os = "macos")]
    let id = libc::CLOCK_MONOTONIC;
    #[cfg(not(target_os = "macos"))]
    let id = libc::CLOCK_BOOTTIME;
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid clock id and out-pointer.
    if unsafe { libc::clock_gettime(id, &mut ts) } != 0 {
        // A broken clock must never extend a token's life: report "far future".
        return u64::MAX;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

#[cfg(test)]
mod tests {
    #[test]
    fn monotone() {
        let a = super::boot_clock_ns();
        let b = super::boot_clock_ns();
        assert!(a > 0 && b >= a);
    }
}
