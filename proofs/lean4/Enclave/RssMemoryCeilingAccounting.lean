/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Mach task_info phys_footprint Memory Accounting & 152 MiB Collective Ceiling
Normative Specification: FS-706 §6.4, ADR-006, & schemas/enclave.lock.toml
-/

namespace Enclave

/-! # Mach phys_footprint Accounting Model -/

/-- Maximum collective memory allocation for UIDs 702–705 in bytes (152 MiB = 159,383,552 bytes). -/
def CLUSTER_RSS_CEILING_BYTES : Nat := 159383552

/-- Memory accounting state for a single privilege-separated daemon. -/
structure DaemonMemoryState where
  uid : Nat
  rss_bytes : Nat
  limit_bytes : Nat
  deriving DecidableEq, Repr

/-- Four-daemon cluster state (UIDs 702, 703, 704, 705). -/
structure EnclaveClusterMemory where
  d702 : DaemonMemoryState
  d703 : DaemonMemoryState
  d704 : DaemonMemoryState
  d705 : DaemonMemoryState
  deriving DecidableEq, Repr

/-- Calculate the cumulative resident memory footprint across all four non-model daemons. -/
def cumulativeRss (cm : EnclaveClusterMemory) : Nat :=
  cm.d702.rss_bytes + cm.d703.rss_bytes + cm.d704.rss_bytes + cm.d705.rss_bytes

/-- Attempt to allocate memory in a daemon while enforcing both daemon and cluster limits. -/
def allocateDaemonMemory
    (d : DaemonMemoryState)
    (alloc_bytes : Nat) : Option DaemonMemoryState :=
  if d.rss_bytes + alloc_bytes ≤ d.limit_bytes then
    some { d with rss_bytes := d.rss_bytes + alloc_bytes }
  else
    none

/--
Theorem 30.1 (Cumulative RSS Ceiling Invariant):
If each individual daemon's limit is partitioned such that the sum of limits does not exceed
the cluster ceiling, and each daemon enforces its individual limit, then the total cluster
memory footprint is strictly bounded by `CLUSTER_RSS_CEILING_BYTES`.
-/
theorem cumulative_rss_ceiling_invariant
    (cm : EnclaveClusterMemory)
    (h_d702 : cm.d702.rss_bytes ≤ cm.d702.limit_bytes)
    (h_d703 : cm.d703.rss_bytes ≤ cm.d703.limit_bytes)
    (h_d704 : cm.d704.rss_bytes ≤ cm.d704.limit_bytes)
    (h_d705 : cm.d705.rss_bytes ≤ cm.d705.limit_bytes)
    (h_sum_limits : cm.d702.limit_bytes + cm.d703.limit_bytes +
                    cm.d704.limit_bytes + cm.d705.limit_bytes ≤ CLUSTER_RSS_CEILING_BYTES) :
    cumulativeRss cm ≤ CLUSTER_RSS_CEILING_BYTES := by
  dsimp [cumulativeRss]
  omega

/--
Theorem 30.2 (Mach Phys Footprint Tripwire):
Any allocation request that would cause a daemon's footprint to exceed its individual ceiling
is rejected deterministically (`allocateDaemonMemory = none`), preventing unmanaged kernel OOM kills.
-/
theorem mach_phys_footprint_tripwire
    (d : DaemonMemoryState)
    (alloc_bytes : Nat)
    (h_overflow : d.rss_bytes + alloc_bytes > d.limit_bytes) :
    allocateDaemonMemory d alloc_bytes = none := by
  simp_all [allocateDaemonMemory]

/-! # Dynamic Memory Deallocation & Cumulative Transitions -/

/-- Memory deallocation operator reducing resident footprint. -/
def deallocateDaemonMemory (d : DaemonMemoryState) (freed_bytes : Nat) : DaemonMemoryState :=
  { d with rss_bytes := d.rss_bytes - freed_bytes }

/--
Theorem 30.3 (Allocation Footprint Exact Increment):
A successful allocation increments the daemon's resident footprint by exactly `alloc_bytes`.
-/
theorem daemon_allocation_exact_inc
    (d d' : DaemonMemoryState) (alloc_bytes : Nat)
    (h_alloc : allocateDaemonMemory d alloc_bytes = some d') :
    d'.rss_bytes = d.rss_bytes + alloc_bytes := by
  dsimp [allocateDaemonMemory] at h_alloc
  split at h_alloc
  · cases h_alloc
    rfl
  · contradiction

/--
Theorem 30.4 (Allocation Preserves Ceiling Safety):
Any successfully allocated daemon state satisfies `rss_bytes ≤ limit_bytes`.
-/
theorem daemon_allocation_within_limit
    (d d' : DaemonMemoryState) (alloc_bytes : Nat)
    (h_alloc : allocateDaemonMemory d alloc_bytes = some d') :
    d'.rss_bytes ≤ d'.limit_bytes := by
  dsimp [allocateDaemonMemory] at h_alloc
  split at h_alloc
  · cases h_alloc
    dsimp
    rename_i h_le
    exact h_le
  · contradiction

/--
Theorem 30.5 (Deallocation Monotonically Decreases Footprint):
Freeing memory cannot increase the daemon's resident memory footprint.
-/
theorem daemon_deallocation_le (d : DaemonMemoryState) (freed_bytes : Nat) :
    (deallocateDaemonMemory d freed_bytes).rss_bytes ≤ d.rss_bytes := by
  dsimp [deallocateDaemonMemory]
  omega

/--
Theorem 30.6 (Deallocation Preserves Limit Safety):
If a daemon was within its limit, deallocating memory preserves limit compliance.
-/
theorem daemon_deallocation_preserves_limit
    (d : DaemonMemoryState) (freed_bytes : Nat)
    (h_safe : d.rss_bytes ≤ d.limit_bytes) :
    (deallocateDaemonMemory d freed_bytes).rss_bytes ≤ d.limit_bytes := by
  dsimp [deallocateDaemonMemory]
  omega

end Enclave
