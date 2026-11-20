//! Dual-socket QoS & LEDBAT++ delay-based congestion controller (FS-702 §5.1, §5.2, §7.1).
//!
//! - Interactive socket: `SO_TC_BE` (Darwin best effort, 0)
//! - Scavenger socket: `SO_TC_BK_SYS` (Darwin system background, 0x100 / 256)
//! - Application-level LEDBAT++ congestion controller:
//!   - Target queue delay: tau_target = 5.0 ms
//!   - If queue delay exceeds 10.0 ms for > 3 s: clamp cwnd to 0 for 60 s (FS-702 §7.1)

use enclave_core::err;
use enclave_core::error::EnclaveResult;
use std::net::TcpStream;
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
const SO_TRAFFIC_CLASS: libc::c_int = 0x1086;
#[cfg(target_os = "macos")]
/// Darwin best-effort interactive traffic class (0).
pub const SO_TC_BE: libc::c_int = 0;
#[cfg(target_os = "macos")]
/// Darwin system background scavenger traffic class (100).
pub const SO_TC_BK_SYS: libc::c_int = 100;

/// Apply Darwin QoS traffic class to a socket.
pub fn apply_traffic_class(stream: &TcpStream, traffic_class: libc::c_int) -> EnclaveResult<()> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_TRAFFIC_CLASS,
                &traffic_class as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            let e = std::io::Error::last_os_error();
            return Err(err!(EIO, "SETSOCKOPT_TRAFFIC_CLASS", "{e}"));
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (stream, traffic_class);
    }
    Ok(())
}

/// Apply scavenger QoS (`SO_TC_BK_SYS`) to a socket.
pub fn set_scavenger_qos(stream: &TcpStream) -> EnclaveResult<()> {
    #[cfg(target_os = "macos")]
    {
        apply_traffic_class(stream, SO_TC_BK_SYS)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = stream;
        Ok(())
    }
}

/// Apply interactive QoS (`SO_TC_BE`) to a socket.
pub fn set_interactive_qos(stream: &TcpStream) -> EnclaveResult<()> {
    #[cfg(target_os = "macos")]
    {
        apply_traffic_class(stream, SO_TC_BE)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = stream;
        Ok(())
    }
}

/// LEDBAT++ delay-based congestion controller (RFC 6817 / FS-702 §5.1 & §7.1).
#[derive(Debug, Clone)]
pub struct LedbatController {
    /// Target queuing delay (default 5.0 ms per FS-702 §5.2).
    pub target_delay: Duration,
    /// Base delay estimate (minimum observed RTT / one-way delay).
    pub base_delay: Duration,
    /// Current congestion window (bytes).
    pub cwnd: u64,
    /// Minimum congestion window (e.g. 2 * MTU = 3000 bytes).
    pub min_cwnd: u64,
    /// Maximum congestion window.
    pub max_cwnd: u64,
    /// High-delay persistence tracker for the 3-second SLA clamp.
    pub high_delay_start: Option<Instant>,
    /// Clamp expiration time (if paused for SLA violation).
    pub clamped_until: Option<Instant>,
}

impl LedbatController {
    /// Initialize with target delay (e.g. 5.0 ms) and initial cwnd.
    pub fn new(target_delay: Duration, initial_cwnd: u64, max_cwnd: u64) -> Self {
        Self {
            target_delay,
            base_delay: Duration::from_secs(3600), // Initialize high
            cwnd: initial_cwnd,
            min_cwnd: 3000, // 2 * MTU
            max_cwnd,
            high_delay_start: None,
            clamped_until: None,
        }
    }

    /// Default configuration per FS-702 §5.2 (5 ms target, 64 KiB initial).
    pub fn default_scavenger() -> Self {
        Self::new(Duration::from_millis(5), 65536, 16 * 1024 * 1024)
    }

    /// Check if scavenger transmissions are currently permitted.
    pub fn is_transmitting_allowed(&mut self, now: Instant) -> bool {
        if let Some(until) = self.clamped_until {
            if now < until {
                return false;
            }
            self.clamped_until = None;
            self.cwnd = self.min_cwnd;
        }
        self.cwnd > 0
    }

    /// Update controller with a new round-trip or one-way delay measurement.
    pub fn on_delay_sample(&mut self, sample_delay: Duration, now: Instant) {
        // Update base delay if a lower delay is observed
        if sample_delay < self.base_delay {
            self.base_delay = sample_delay;
        }

        let queue_delay = sample_delay.saturating_sub(self.base_delay);

        // Check FS-702 §7.1 SLA: if delta OWD > 10.0 ms for > 3.0 s, clamp cwnd to 0 for 60 s
        let sla_threshold = Duration::from_millis(10);
        if queue_delay > sla_threshold {
            let start = *self.high_delay_start.get_or_insert(now);
            if now.saturating_duration_since(start) >= Duration::from_secs(3) {
                // Clamp cwnd to 0 for 60 seconds
                self.cwnd = 0;
                self.clamped_until = Some(now + Duration::from_secs(60));
                self.high_delay_start = None;
                return;
            }
        } else {
            self.high_delay_start = None;
        }

        // Standard LEDBAT++ linear rate adaptation
        if queue_delay <= self.target_delay {
            // Queue is below target: increase window
            let gain = (self.target_delay.as_micros() - queue_delay.as_micros()) as u64;
            let increment = (gain * 100).clamp(512, 16384);
            self.cwnd = (self.cwnd + increment).min(self.max_cwnd);
        } else {
            // Queue is above target: back off window
            let loss_ratio = (queue_delay.as_micros() - self.target_delay.as_micros()) as f64
                / self.target_delay.as_micros().max(1) as f64;
            let backoff = (self.cwnd as f64 * loss_ratio.min(0.5)) as u64;
            self.cwnd = self.cwnd.saturating_sub(backoff).max(self.min_cwnd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ledbat_controller_adaptation() {
        let mut c = LedbatController::default_scavenger();
        let now = Instant::now();

        // Establish base delay 10ms
        c.on_delay_sample(Duration::from_millis(10), now);
        assert_eq!(c.base_delay, Duration::from_millis(10));

        // Sample with 2ms queue delay (12ms total <= 10ms base + 5ms target)
        let initial_cwnd = c.cwnd;
        c.on_delay_sample(Duration::from_millis(12), now);
        assert!(
            c.cwnd > initial_cwnd,
            "cwnd should increase when queue delay <= 5ms"
        );

        // Sample with 8ms queue delay (18ms total > 10ms base + 5ms target)
        let high_cwnd = c.cwnd;
        c.on_delay_sample(Duration::from_millis(18), now);
        assert!(
            c.cwnd < high_cwnd,
            "cwnd should decrease when queue delay > 5ms"
        );
    }

    #[test]
    fn test_ledbat_controller_sla_clamp() {
        let mut c = LedbatController::default_scavenger();
        let t0 = Instant::now();

        // Base delay 5ms
        c.on_delay_sample(Duration::from_millis(5), t0);

        // Queue delay 15ms (> 10ms SLA threshold) at t0
        c.on_delay_sample(Duration::from_millis(20), t0);
        assert!(c.is_transmitting_allowed(t0));

        // Still high at t0 + 2s (under 3s threshold)
        let t2 = t0 + Duration::from_secs(2);
        c.on_delay_sample(Duration::from_millis(20), t2);
        assert!(c.is_transmitting_allowed(t2));

        // Exceeds 3s at t0 + 3.1s -> clamps cwnd to 0 for 60s
        let t3 = t0 + Duration::from_millis(3100);
        c.on_delay_sample(Duration::from_millis(20), t3);
        assert_eq!(c.cwnd, 0);
        assert!(!c.is_transmitting_allowed(t3));

        // At t0 + 50s, still clamped
        assert!(!c.is_transmitting_allowed(t0 + Duration::from_secs(50)));

        // At t0 + 64s, clamp expires
        assert!(c.is_transmitting_allowed(t0 + Duration::from_secs(64)));
    }
}
