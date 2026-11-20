//! Epoch-anchored sequence numbers (ADR-010).
//!
//! `rpc_seq_u64` is an in-RAM atomic counter anchored to a per-boot
//! `boot_epoch_id` that the SEP signs once at boot. The SEP is checkpointed
//! only at boot, clean shutdown and hourly (`<= 30` writes/day) — never per RPC.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::EnclaveResult;
use crate::fail;

/// Per-boot epoch identity, signed by the hardware epoch key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootEpoch {
    /// Lowercase hyphenated UUID (schema pattern).
    pub boot_epoch_id: String,
    /// Signature by the SEP epoch key over `epoch_signing_message(boot_epoch_id)`.
    pub signature: Vec<u8>,
    /// SEC1/raw public key of the signer (verifier pins it).
    pub signer_public_key: Vec<u8>,
}

/// A governed slot handed from one daemon to another (GAP-27): the sequence
/// authority's signed epoch and the slot number, so the receiver can verify
/// the epoch before it journals the slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedSlot {
    /// UID 703's signed epoch.
    pub epoch: BootEpoch,
    /// `rpc_seq_u64` issued by UID 703.
    pub rpc_seq_u64: u64,
}

/// Bytes signed for a boot epoch.
pub fn epoch_signing_message(boot_epoch_id: &str) -> Vec<u8> {
    let mut m = b"MCPMac-BootEpoch-v1\0".to_vec();
    m.extend_from_slice(boot_epoch_id.as_bytes());
    m
}

/// Fresh random boot-epoch UUID string.
pub fn new_boot_epoch_id() -> String {
    let mut b = [0u8; 16];
    crate::rng::fill(&mut b);
    uuid::Builder::from_random_bytes(b)
        .into_uuid()
        .hyphenated()
        .to_string()
}

/// Validate the schema pattern `^[0-9a-f]{8}-…-[0-9a-f]{12}$`.
pub fn validate_epoch_id(s: &str) -> EnclaveResult<()> {
    match Uuid::try_parse(s) {
        Ok(u) if u.hyphenated().to_string() == s => Ok(()),
        _ => fail!(EINVAL, "BAD_BOOT_EPOCH_ID", "{s:?}"),
    }
}

/// Monotonic, lock-free `rpc_seq_u64` allocator. Overflow fails closed.
#[derive(Debug)]
pub struct RpcSequencer {
    next: AtomicU64,
    boot_epoch_id: String,
}

impl RpcSequencer {
    /// Start at `start` (normally 0 or the last SEP checkpoint + 1).
    pub fn new(boot_epoch_id: String, start: u64) -> Self {
        Self {
            next: AtomicU64::new(start),
            boot_epoch_id,
        }
    }
    /// Allocate the next sequence number.
    pub fn next(&self) -> EnclaveResult<u64> {
        let v = self.next.fetch_add(1, Ordering::SeqCst);
        if v == u64::MAX {
            // Pin at MAX so every later call fails as well.
            self.next.store(u64::MAX, Ordering::SeqCst);
            fail!(ENOMEM, "RPC_SEQ_EXHAUSTED");
        }
        Ok(v)
    }
    /// Peek without allocating.
    pub fn current(&self) -> u64 {
        self.next.load(Ordering::SeqCst)
    }
    /// Epoch anchor.
    pub fn boot_epoch_id(&self) -> &str {
        &self.boot_epoch_id
    }
}

/// Why a checkpoint is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointReason {
    /// Process start.
    Boot,
    /// Clean shutdown.
    Shutdown,
    /// Hourly timer.
    Hourly,
}

/// Decides when the (slow, wear-limited) SEP checkpoint is written.
#[derive(Debug, Clone)]
pub struct CheckpointPolicy {
    last_ms: Option<u64>,
    day_start_ms: u64,
    writes_today: u32,
}

/// Maximum SEP checkpoint writes per 24h (ADR-010).
pub const MAX_CHECKPOINTS_PER_DAY: u32 = 30;
const HOUR_MS: u64 = 3_600_000;
const DAY_MS: u64 = 86_400_000;

impl CheckpointPolicy {
    /// New policy starting at `now_ms`.
    pub fn new(now_ms: u64) -> Self {
        Self {
            last_ms: None,
            day_start_ms: now_ms,
            writes_today: 0,
        }
    }
    /// Return `Some(reason)` if a checkpoint must be written now. Per-RPC calls
    /// (`on_rpc`) never trigger a write by themselves.
    pub fn poll(&mut self, now_ms: u64, shutdown: bool) -> Option<CheckpointReason> {
        if now_ms.saturating_sub(self.day_start_ms) >= DAY_MS {
            self.day_start_ms = now_ms;
            self.writes_today = 0;
        }
        let reason = match self.last_ms {
            None => Some(CheckpointReason::Boot),
            Some(_) if shutdown => Some(CheckpointReason::Shutdown),
            Some(l) if now_ms.saturating_sub(l) >= HOUR_MS => Some(CheckpointReason::Hourly),
            _ => None,
        }?;
        if self.writes_today >= MAX_CHECKPOINTS_PER_DAY && reason == CheckpointReason::Hourly {
            return None;
        }
        self.writes_today += 1;
        self.last_ms = Some(now_ms);
        Some(reason)
    }
    /// Writes in the current 24h window.
    pub fn writes_today(&self) -> u32 {
        self.writes_today
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequencer_is_strictly_monotonic_across_threads() {
        let s = std::sync::Arc::new(RpcSequencer::new(new_boot_epoch_id(), 0));
        let mut hs = vec![];
        for _ in 0..4 {
            let s = s.clone();
            hs.push(std::thread::spawn(move || {
                (0..1000).map(|_| s.next().unwrap()).collect::<Vec<_>>()
            }));
        }
        let mut all: Vec<u64> = hs.into_iter().flat_map(|h| h.join().unwrap()).collect();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), 4000);
        assert_eq!(*all.last().unwrap(), 3999);
    }

    #[test]
    fn sequencer_overflow_fails_closed() {
        let s = RpcSequencer::new(new_boot_epoch_id(), u64::MAX);
        assert!(s.next().is_err());
        assert!(s.next().is_err());
    }

    #[test]
    fn ten_thousand_receipts_cost_at_most_one_checkpoint() {
        // ADR-010 verification: 10,000 A1 receipts with <= 1 NVRAM write.
        let mut p = CheckpointPolicy::new(0);
        let mut writes = 0;
        for i in 0..10_000u64 {
            if p.poll(i * 10, false).is_some() {
                writes += 1;
            }
        }
        assert_eq!(writes, 1); // the boot checkpoint only (100 s elapsed)
    }

    #[test]
    fn at_most_30_writes_per_day() {
        let mut p = CheckpointPolicy::new(0);
        let mut writes = 0;
        // Poll every minute for a day.
        for m in 0..(24 * 60) {
            if p.poll(m * 60_000, false).is_some() {
                writes += 1;
            }
        }
        assert!(writes <= MAX_CHECKPOINTS_PER_DAY as usize, "{writes}");
        assert_eq!(writes, 24);
    }

    #[test]
    fn epoch_id_pattern() {
        let id = new_boot_epoch_id();
        validate_epoch_id(&id).unwrap();
        assert!(validate_epoch_id("7B2E9A10-4C11-4F88-9D21-0019E2A4B7F1").is_err());
    }
}
