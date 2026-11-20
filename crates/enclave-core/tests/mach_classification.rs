//! Tests for Mach exception classification and respawn throttling (GAP-12, ADR-012, FS-705 §5.3.5).

use std::time::Duration;

use enclave_core::quarantine_types::FaultKind;
use enclave_core::supervisor::{classify_mach_exception, RespawnTracker};

#[test]
fn test_mach_classification_table() {
    // Public SDK27.2 mach/arm/exception.h declares PAC105 and MTE106/107.
    // This table exercises decoded-value policy, not Mach wire authenticity,
    // native fault delivery, or actual allocator/guard provenance.
    for (code, address) in [(1, 0), (1, 0x4000), (1, 0x10000), (2, 0xdead_beef_0000),
        (0x102, 0x1000_2000), (1, 0x7f00_0001_0000_2000)] {
        assert_eq!(classify_mach_exception(1, code, address), (FaultKind::Segv, address as u64));
    }

    for (code, arm_kind) in [(0x105, FaultKind::Pac), (0x106, FaultKind::HeapTag), (0x107, FaultKind::HeapTag)] {
        let expected = if cfg!(target_arch = "aarch64") { arm_kind } else { FaultKind::Segv };
        for address in [8, 0x8000_1234_5678, -1] {
            assert_eq!(classify_mach_exception(1, code, address), (expected, address as u64));
        }
    }

    // Neither instruction aliases nor a guessed GUARD encoding prove PAC.
    // These retain only the legacy conservative Redzone policy bucket.
    for code in [1, 0x100, 0x102, 0x105, 0x106, 0x107] {
        assert_eq!(classify_mach_exception(2, code, 0x2000), (FaultKind::Redzone, 0x2000));
    }
    for code in [(2i64 << 32) | 1, (5i64 << 32) | 1, -1] {
        assert_eq!(classify_mach_exception(12, code, 0x3000), (FaultKind::Redzone, 0x3000));
    }
}

#[test]
fn test_respawn_tracker_delays() {
    let tracker = RespawnTracker::new();
    assert!(tracker.is_throttled(701).is_none());

    tracker.record_delay(701, Duration::from_secs(300));
    let remaining = tracker.is_throttled(701);
    assert!(remaining.is_some());
    assert!(remaining.unwrap() > Duration::from_secs(290));

    // Other UIDs are not throttled
    assert!(tracker.is_throttled(702).is_none());
    assert!(tracker.is_throttled(703).is_none());
}
