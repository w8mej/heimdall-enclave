/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

WASI 0.2 Component Sandbox & Linear Memory Confinement
Normative Specification: ADR-011, crates/enclave-tool-host, & Wasmtime Zero-JIT
-/

-- ASSURANCE: a standalone specification using Nat, records and Booleans.
-- Its original mechanism terminology is an interpretation of model fields.
-- No cryptographic protocol, deployed constraints, OS or hardware is verified here.
namespace Enclave

/-! # WASI Linear Memory and Pre-Opened Directory Table -/

/-- WASI linear memory page size in bytes (64 KiB). -/
def WASI_PAGE_BYTES : Nat := 65536

/-- Linear memory sandbox allocation. -/
structure WasiMemoryState where
  allocated_pages : Nat
  max_pages : Nat
  deriving DecidableEq, Repr

/-- Compute maximum accessible byte offset in linear memory. -/
def maxLinearMemoryOffset (mem : WasiMemoryState) : Nat :=
  mem.allocated_pages * WASI_PAGE_BYTES

/-- Check whether a memory access offset and size are strictly within sandboxed bounds. -/
def isMemoryAccessValid (mem : WasiMemoryState) (offset : Nat) (size : Nat) : Bool :=
  offset + size ≤ maxLinearMemoryOffset mem

/-- Pre-opened virtual file descriptor table for WASI capability confinement. -/
structure WasiFdTable where
  preopened_fds : List Nat
  deriving DecidableEq, Repr

/-- Resolve an incoming syscall file descriptor against pre-opened capabilities. -/
def resolveWasiFd (tbl : WasiFdTable) (fd : Nat) : Option Nat :=
  if fd ∈ tbl.preopened_fds then
    some fd
  else
    none

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem nat_memory_limit_rejects
    (mem : WasiMemoryState)
    (offset size : Nat)
    (h_oob : offset + size > maxLinearMemoryOffset mem) :
    isMemoryAccessValid mem offset size = false := by
  simp_all [isMemoryAccessValid]

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem numeric_fd_membership_rejects
    (tbl : WasiFdTable)
    (fd : Nat)
    (h_not_mem : fd ∉ tbl.preopened_fds) :
    resolveWasiFd tbl fd = none := by
  simp_all [resolveWasiFd]

/-! # Dynamic Memory Growth and Capability Rights Attenuation -/

/-- Attempt to grow WASI linear memory by `delta_pages`. -/
def growWasiMemory (mem : WasiMemoryState) (delta_pages : Nat) : Option WasiMemoryState :=
  if mem.allocated_pages + delta_pages ≤ mem.max_pages then
    some { mem with allocated_pages := mem.allocated_pages + delta_pages }
  else
    none

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem memory_growth_monotonic
    (mem mem' : WasiMemoryState) (delta offset size : Nat)
    (h_grow : growWasiMemory mem delta = some mem')
    (h_valid : isMemoryAccessValid mem offset size = true) :
    isMemoryAccessValid mem' offset size = true := by
  dsimp [growWasiMemory] at h_grow
  split at h_grow
  · cases h_grow
    simp [isMemoryAccessValid, maxLinearMemoryOffset] at h_valid ⊢
    exact Nat.le_trans h_valid (Nat.mul_le_mul_right _ (Nat.le_add_right _ _))
  · contradiction

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem memory_growth_ceiling
    (mem mem' : WasiMemoryState) (delta : Nat)
    (h_grow : growWasiMemory mem delta = some mem') :
    mem'.allocated_pages ≤ mem'.max_pages := by
  dsimp [growWasiMemory] at h_grow
  split at h_grow
  · cases h_grow
    dsimp
    rename_i h_bound
    exact h_bound
  · contradiction

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem memory_growth_overflow_rejected
    (mem : WasiMemoryState) (delta : Nat)
    (h_overflow : mem.allocated_pages + delta > mem.max_pages) :
    growWasiMemory mem delta = none := by
  simp_all [growWasiMemory]

/-! # Operational Memory Confinement & Host Address Space Invariance -/

/-- Linear memory heap represented as an address-to-byte mapping -/
def LinearMemoryHeap := Nat → Nat

/-- Execute a bounded memory write within the WASI linear memory page bounds -/
def checkedMemoryWrite
    (mem : WasiMemoryState)
    (heap : LinearMemoryHeap)
    (addr : Nat)
    (val : Nat) : Option LinearMemoryHeap :=
  if addr < maxLinearMemoryOffset mem then
    some (fun a => if a = addr then val else heap a)
  else
    none

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem checked_write_preserves_other_index
    (mem : WasiMemoryState)
    (heap heap' : LinearMemoryHeap)
    (write_addr write_val : Nat)
    (h_write : checkedMemoryWrite mem heap write_addr write_val = some heap')
    (host_addr : Nat)
    (h_host : host_addr ≥ maxLinearMemoryOffset mem) :
    heap' host_addr = heap host_addr := by
  dsimp [checkedMemoryWrite] at h_write
  split at h_write
  · cases h_write
    simp
    intro h
    omega
  · contradiction

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem checked_write_out_of_range_returns_none
    (mem : WasiMemoryState)
    (heap : LinearMemoryHeap)
    (addr val : Nat)
    (h_oob : addr ≥ maxLinearMemoryOffset mem) :
    checkedMemoryWrite mem heap addr val = none := by
  simp_all [isMemoryAccessValid, resolveWasiFd, growWasiMemory, checkedMemoryWrite]

end Enclave
