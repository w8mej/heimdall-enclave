//! WireGuard/IPsec-style 64-bit sliding anti-replay window (FS-704 §3.4.3).
//!
//! `O(1)` per check; supports out-of-order concurrent async calls within the
//! 64-sequence window; anything older than the window or already seen is a
//! replay (`EALREADY: REPLAY`).

use enclave_core::error::EnclaveResult;
use enclave_core::fail;

/// Window width in sequence numbers.
pub const WINDOW: u64 = 64;

/// Per-chain replay state.
#[derive(Debug, Clone, Default)]
pub struct ReplayWindow {
    highest: Option<u64>,
    bitmap: u64,
}

impl ReplayWindow {
    /// New, empty window.
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept `seq` exactly once.
    pub fn check_and_update(&mut self, seq: u64) -> EnclaveResult<()> {
        let Some(h) = self.highest else {
            self.highest = Some(seq);
            self.bitmap = 1;
            return Ok(());
        };
        if seq > h {
            let shift = seq - h;
            self.bitmap = if shift >= WINDOW {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.highest = Some(seq);
            return Ok(());
        }
        let off = h - seq;
        if off >= WINDOW {
            fail!(
                EALREADY,
                "REPLAY",
                "seq {seq} older than window (highest {h})"
            );
        }
        let bit = 1u64 << off;
        if self.bitmap & bit != 0 {
            fail!(EALREADY, "REPLAY", "seq {seq} already seen");
        }
        self.bitmap |= bit;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order_out_of_order_and_replays() {
        let mut w = ReplayWindow::new();
        for s in [10u64, 12, 11, 13, 40, 20] {
            w.check_and_update(s).unwrap();
        }
        assert!(w.check_and_update(12).is_err());
        assert!(w.check_and_update(40).is_err());
        w.check_and_update(1000).unwrap();
        assert!(w.check_and_update(40).unwrap_err().is("REPLAY"));
        w.check_and_update(999).unwrap();
        w.check_and_update(1000 - 63).unwrap();
        assert!(w.check_and_update(1000 - 64).is_err());
    }
}
