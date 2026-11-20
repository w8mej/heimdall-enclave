//! Progressive wire protocol keep-alive progress frames (FS-701 §7.1, GAP-52).
//!
//! Emits structured progress frames to clients during model weight hydration,
//! cold-booting, or pipeline compilation, extending client RPC timeouts.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Structured progress keep-alive frame emitted to clients during model cold-boot / weight hydration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProgressFrame {
    /// High-level lifecycle state ("hydrating", "compiling", "ready", "failed").
    pub status: String,
    /// Detailed execution stage description.
    pub stage: String,
    /// Completion percentage (0.0 to 100.0).
    pub progress_pct: f64,
    /// Verified bytes synced so far.
    pub bytes_synced: u64,
    /// Total expected model weight bytes.
    pub bytes_total: u64,
    /// Estimated time remaining in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eta_seconds: Option<u64>,
}

impl ProgressFrame {
    /// Create a new progress keep-alive frame.
    pub fn new(status: impl Into<String>, stage: impl Into<String>, progress_pct: f64) -> Self {
        Self {
            status: status.into(),
            stage: stage.into(),
            progress_pct: progress_pct.clamp(0.0, 100.0),
            bytes_synced: 0,
            bytes_total: 0,
            eta_seconds: None,
        }
    }

    /// Set byte synchronization progress.
    pub fn with_bytes(mut self, synced: u64, total: u64) -> Self {
        self.bytes_synced = synced;
        self.bytes_total = total;
        if total > 0 {
            self.progress_pct = ((synced as f64 / total as f64) * 100.0).clamp(0.0, 100.0);
        }
        self
    }

    /// Set estimated time remaining.
    pub fn with_eta(mut self, eta_seconds: u64) -> Self {
        self.eta_seconds = Some(eta_seconds);
        self
    }

    /// Check if hydration has completed.
    pub fn is_complete(&self) -> bool {
        self.progress_pct >= 100.0 || self.status == "ready"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress_frame_construction() {
        let f = ProgressFrame::new("hydrating", "Verifying Bao Merkle tree", 42.5)
            .with_bytes(4250, 10000)
            .with_eta(15);
        assert_eq!(f.status, "hydrating");
        assert_eq!(f.stage, "Verifying Bao Merkle tree");
        assert!((f.progress_pct - 42.5).abs() < f64::EPSILON);
        assert_eq!(f.bytes_synced, 4250);
        assert_eq!(f.bytes_total, 10000);
        assert_eq!(f.eta_seconds, Some(15));
        assert!(!f.is_complete());

        let ready = ProgressFrame::new("ready", "Model pipeline compiled", 100.0);
        assert!(ready.is_complete());
    }
}
