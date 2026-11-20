//! Fail-closed error taxonomy shared by every depot v3.0 daemon.
//!
//! Every variant maps onto a POSIX-style errno class plus a stable reason
//! string (`EACCES: HANDLE_FORGERY`, `E2BIG: PROVENANCE_FANIN_EXCEEDED`, ...)
//! so audit receipts and IPC error frames are deterministic. There is no
//! "warn and continue" variant: callers that receive an [`EnclaveError`] MUST
//! deny the operation.

use serde::{Deserialize, Serialize};

/// POSIX-style error class carried on the IPC wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Errno {
    /// Permission denied by a cryptographic or label check.
    EACCES,
    /// Operation not permitted in the current profile / state.
    EPERM,
    /// Argument list or fan-in too long.
    E2BIG,
    /// Resource temporarily unavailable (rate-limit, cooldown, surprise abort).
    EAGAIN,
    /// Malformed input.
    EINVAL,
    /// Stale metadata or expired credential.
    ESTALE,
    /// Replay or duplicate detected.
    EALREADY,
    /// Ceremony or deadline timed out.
    ETIMEDOUT,
    /// Resource ceiling (RSS, queue, frame) breached.
    ENOMEM,
    /// Physical staging allocation or per-artifact quota refused.
    EDQUOT,
    /// I/O failure on a local resource.
    EIO,
    /// Function not implemented or not supported on this platform.
    ENOSYS,
}

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

/// A fail-closed enclave error: errno class + stable machine reason + detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{errno}: {reason}{}", if detail.is_empty() { String::new() } else { format!(" ({detail})") })]
pub struct EnclaveError {
    /// Errno class.
    pub errno: Errno,
    /// Stable upper-snake reason code, e.g. `T3_BIBA_VIOLATION`.
    pub reason: String,
    /// Human-readable detail. MUST NOT contain raw `C3`/`C4` payload bytes.
    pub detail: String,
}

impl EnclaveError {
    /// Construct an error with an empty detail string.
    pub fn new(errno: Errno, reason: &str) -> Self {
        Self {
            errno,
            reason: reason.to_owned(),
            detail: String::new(),
        }
    }
    /// Construct an error with a detail string.
    pub fn with(errno: Errno, reason: &str, detail: impl Into<String>) -> Self {
        Self {
            errno,
            reason: reason.to_owned(),
            detail: detail.into(),
        }
    }
    /// `true` when the error has the given reason code.
    pub fn is(&self, reason: &str) -> bool {
        self.reason == reason
    }
}

/// Crate-wide result alias.
pub type EnclaveResult<T> = Result<T, EnclaveError>;

/// Shorthand: `fail!(EACCES, "HANDLE_FORGERY")` or with a format detail.
#[macro_export]
macro_rules! fail {
    ($errno:ident, $reason:expr) => {
        return Err($crate::error::EnclaveError::new($crate::error::Errno::$errno, $reason))
    };
    ($errno:ident, $reason:expr, $($arg:tt)+) => {
        return Err($crate::error::EnclaveError::with($crate::error::Errno::$errno, $reason, format!($($arg)+)))
    };
}

/// Shorthand constructor without early return.
#[macro_export]
macro_rules! err {
    ($errno:ident, $reason:expr) => {
        $crate::error::EnclaveError::new($crate::error::Errno::$errno, $reason)
    };
    ($errno:ident, $reason:expr, $($arg:tt)+) => {
        $crate::error::EnclaveError::with($crate::error::Errno::$errno, $reason, format!($($arg)+))
    };
}
