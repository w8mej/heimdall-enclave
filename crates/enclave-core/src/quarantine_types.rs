//! Shared types for HardwareIntegrityQuarantine (ADR-012, FS-705 §5.3).

use serde::{Deserialize, Serialize};

/// Null-page threshold (0x10000 = 64 KiB).
pub const NULL_PAGE_LIMIT: u64 = 0x10000;
/// Strike window (24 hours).
pub const STRIKE_WINDOW_MS: u64 = 24 * 3_600_000;
/// Null-fault burst window (10 minutes).
pub const NULL_BURST_WINDOW_MS: u64 = 10 * 60_000;
/// Null-fault burst count that triggers latching.
pub const NULL_BURST_COUNT: usize = 5;

/// Fault classes for hardware and memory integrity violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FaultKind {
    /// Memory-tag mismatch (EMTE) or cookie corruption.
    HeapTag,
    /// Pointer-authentication failure (PAC).
    Pac,
    /// Guard-page / redzone hit.
    Redzone,
    /// Plain segmentation fault at an address (classified by address).
    Segv,
}

/// A fault report from a daemon crash handler / exception port supervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultReport {
    /// Kind of fault.
    pub kind: FaultKind,
    /// Faulting address.
    pub fault_addr: u64,
    /// Timestamp in milliseconds.
    pub at_ms: u64,
}

/// Response required from HardwareIntegrityQuarantine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    /// Kill, zeroize, restart after ThrottleInterval (30 s).
    RestartThrottled,
    /// Strike recorded: kill, zeroize, rotate tag seeds, delay respawn 300 s.
    StrikeDelayRespawn,
    /// HardwareIntegrityQuarantine latched.
    Latched,
}
