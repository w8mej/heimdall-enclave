/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Multi-Tenant PagedAttention KV-Cache Memory Isolation Proofs
Normative Specification: FS-701 §4.1, §4.3, ADR-018, & crates/enclave-model-runnerd/src/paged_attention.rs
-/

namespace Enclave

/-! # PagedAttention Block Allocation & Tenant Isolation -/

/-- An assigned physical KV-cache memory block in unified memory -/
structure BlockAllocation where
  block_id : Nat
  tenant_id : Nat
  is_zeroed : Bool
  deriving DecidableEq, Repr

/-- Extract all physical block IDs assigned to a specific tenant -/
def blocksForTenant (allocs : List BlockAllocation) (t : Nat) : List Nat :=
  (allocs.filter (fun a => a.tenant_id == t)).map (fun a => a.block_id)

/--
Predicate: Two tenants possess strictly disjoint physical block allocations.
No single physical memory block is shared across distinct tenant security boundaries.
-/
def isTenantIsolated (allocs : List BlockAllocation) (t1 t2 : Nat) : Prop :=
  ∀ b, b ∈ blocksForTenant allocs t1 → b ∉ blocksForTenant allocs t2

/--
Theorem 22.1 (PagedAttention Cross-Tenant Isolation):
If every allocation entry in `allocs` has distinct block IDs per tenant (i.e.
`∀ a1 a2 ∈ allocs, a1.block_id = a2.block_id → a1.tenant_id = a2.tenant_id`),
then any two distinct tenants `t1 ≠ t2` have strictly disjoint physical block sets.
-/
theorem paged_attention_cross_tenant_isolation
    (allocs : List BlockAllocation)
    (h_unique : ∀ a1 a2 : BlockAllocation, a1 ∈ allocs → a2 ∈ allocs →
                a1.block_id = a2.block_id → a1.tenant_id = a2.tenant_id)
    (t1 t2 : Nat)
    (h_diff : t1 ≠ t2) :
    isTenantIsolated allocs t1 t2 := by
  intro b hb1 hb2
  dsimp [blocksForTenant] at hb1 hb2
  have h_mem1 : ∃ a, a ∈ allocs ∧ a.tenant_id == t1 ∧ a.block_id = b := by
    rw [List.mem_map] at hb1
    rcases hb1 with ⟨a, ha_filter, rfl⟩
    rw [List.mem_filter] at ha_filter
    exact ⟨a, ha_filter.1, ha_filter.2, rfl⟩
  have h_mem2 : ∃ a, a ∈ allocs ∧ a.tenant_id == t2 ∧ a.block_id = b := by
    rw [List.mem_map] at hb2
    rcases hb2 with ⟨a, ha_filter, rfl⟩
    rw [List.mem_filter] at ha_filter
    exact ⟨a, ha_filter.1, ha_filter.2, rfl⟩
  rcases h_mem1 with ⟨a1, ha1_in, ha1_t1, rfl⟩
  rcases h_mem2 with ⟨a2, ha2_in, ha2_t2, ha2_eq⟩
  have h_tid_eq := h_unique a1 a2 ha1_in ha2_in ha2_eq.symm
  simp only [beq_iff_eq] at ha1_t1 ha2_t2
  rw [ha1_t1, ha2_t2] at h_tid_eq
  exact h_diff h_tid_eq

/--
Reallocate Block:
Reassigns a freed block to a new tenant `new_tenant`.
Fails closed if the block is not verified to be zeroed (`is_zeroed == false`).
-/
def reallocateBlock (b : BlockAllocation) (new_tenant : Nat) : Option BlockAllocation :=
  if b.is_zeroed then
    some { b with tenant_id := new_tenant, is_zeroed := false }
  else
    none

/--
Theorem 22.2 (Recycled Block Zeroed Before Allocation):
A block cannot be reallocated to a new tenant unless it has been explicitly zeroed.
Un-zeroed residual blocks are strictly rejected (`reallocateBlock = none`).
-/
theorem recycled_block_zeroed_before_alloc
    (b : BlockAllocation)
    (new_tenant : Nat)
    (h_not_zeroed : b.is_zeroed = false) :
    reallocateBlock b new_tenant = none := by
  dsimp [reallocateBlock]
  rw [h_not_zeroed]
  rfl

/--
Theorem 22.3 (Disjoint Block Tables Prevent Attention State Bleed):
Under tenant isolation, querying the physical block space of tenant `t1` never
returns a block belonging to tenant `t2`.
-/
theorem disjoint_block_tables_no_bleed
    (allocs : List BlockAllocation)
    (t1 t2 b : Nat)
    (h_isolated : isTenantIsolated allocs t1 t2)
    (h_in_t1 : b ∈ blocksForTenant allocs t1) :
    b ∉ blocksForTenant allocs t2 := by
  exact h_isolated b h_in_t1

/-! # Block Sanitization & Memory Recycling Soundness -/

/-- Zeroizes a physical block allocation before recycling. -/
def zeroBlock (b : BlockAllocation) : BlockAllocation :=
  { b with is_zeroed := true }

/--
Theorem 22.4 (Zeroed Block Reallocation Strictly Succeeds):
Applying the hardware zeroization barrier guarantees successful reallocation to any new tenant.
-/
theorem zeroed_block_realloc_succeeds (b : BlockAllocation) (new_tenant : Nat) :
    reallocateBlock (zeroBlock b) new_tenant =
    some { b with tenant_id := new_tenant, is_zeroed := false } := by
  rfl

/--
Theorem 22.5 (Reallocated Block Assigned to Target Tenant):
A successfully reallocated block is assigned strictly to `new_tenant`.
-/
theorem reallocated_block_tenant
    (b b' : BlockAllocation) (new_tenant : Nat)
    (h_realloc : reallocateBlock b new_tenant = some b') :
    b'.tenant_id = new_tenant := by
  dsimp [reallocateBlock] at h_realloc
  split at h_realloc
  · cases h_realloc; rfl
  · contradiction

end Enclave
