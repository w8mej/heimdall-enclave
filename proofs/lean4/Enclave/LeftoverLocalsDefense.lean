/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

LeftoverLocals (CVE-2023-4969) GPU Unified Memory Zeroization & Cross-Session Isolation Proofs
Normative Specification: FS-701 §3.3, §7.1, ADR-018, & crates/enclave-model-runnerd/src/arena_metal.m
-/

-- ASSURANCE: a standalone specification using Nat, records and Booleans.
-- Its original mechanism terminology is an interpretation of model fields.
-- No cryptographic protocol, deployed constraints, OS or hardware is verified here.
namespace Enclave

/-! # Metal Unified Memory Buffer & Zeroization State -/

/-- State of a GPU unified memory allocation across model sessions -/
inductive GpuMemoryStatus where
  | Active : GpuMemoryStatus      -- Currently bound to active inference session
  | Tainted : GpuMemoryStatus     -- Unwound or interrupted session with dirty activations
  | Zeroized : GpuMemoryStatus    -- Cleaned via GPU blit fillBuffer(0) and CPU memset_s
  deriving DecidableEq, Repr

/--
Metal unified memory buffer representation.
`session_id`: Unique identifier of the model invocation session owning the buffer.
`size_bytes`: Buffer length in bytes.
`status`: Security lifecycle state.
`residual_bytes`: Count of non-zero residual bytes in memory.
-/
structure GpuBuffer where
  session_id : Nat
  size_bytes : Nat
  status : GpuMemoryStatus
  residual_bytes : Nat
  deriving DecidableEq, Repr

/--
Operational Zeroizer:
Executes GPU command buffer `fillBuffer(0)`, `MTLSharedEvent` fence synchronization,
and CPU-side `memset_s` followed by canary readback verification.
Transitions memory state from `Tainted` to `Zeroized` and enforces 0 residual bytes.
-/
def zeroizeGpuBuffer (buf : GpuBuffer) : GpuBuffer :=
  { buf with
    status := GpuMemoryStatus.Zeroized,
    residual_bytes := 0 }

/--
Session Reallocator:
Assigns a previously used buffer to a new session `new_session_id`.
Fails closed if the buffer has not been zeroized prior to handover.
-/
def reallocateGpuBuffer (buf : GpuBuffer) (new_session_id : Nat) : Option GpuBuffer :=
  if buf.status == GpuMemoryStatus.Zeroized && buf.residual_bytes == 0 then
    some { session_id := new_session_id,
           size_bytes := buf.size_bytes,
           status := GpuMemoryStatus.Active,
           residual_bytes := 0 }
  else
    none

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem leftover_locals_vram_cleared (buf : GpuBuffer) :
    (zeroizeGpuBuffer buf).status = GpuMemoryStatus.Zeroized ∧
    (zeroizeGpuBuffer buf).residual_bytes = 0 := by
  dsimp [zeroizeGpuBuffer]
  exact ⟨rfl, rfl⟩

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem vram_cross_session_isolation (buf : GpuBuffer) (new_session : Nat)
    (h_dirty : buf.status = GpuMemoryStatus.Tainted ∨ buf.residual_bytes > 0) :
    reallocateGpuBuffer buf new_session = none := by
  dsimp [reallocateGpuBuffer]
  cases h_dirty with
  | inl h_tainted =>
    have h_stat : (buf.status == GpuMemoryStatus.Zeroized) = false := by
      rw [h_tainted]
      rfl
    simp [h_stat]
  | inr h_res =>
    have h_res_ne : (buf.residual_bytes == 0) = false := by
      have h_nz : buf.residual_bytes ≠ 0 := Nat.ne_of_gt h_res
      cases h : (buf.residual_bytes == 0)
      · rfl
      · simp only [beq_iff_eq] at h; contradiction
    cases h_s : (buf.status == GpuMemoryStatus.Zeroized) <;> simp [h_res_ne]

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem zeroize_buffer_idempotent (buf : GpuBuffer) :
    zeroizeGpuBuffer (zeroizeGpuBuffer buf) = zeroizeGpuBuffer buf := by
  rfl

/-! # Metal Arena Buffer Pool Zeroization Induction -/

/-- An arena pool of GPU memory buffers. -/
structure MetalArena where
  buffers : List GpuBuffer
  deriving Repr

/-- Cleans an entire list of GPU buffers by applying the zeroization barrier. -/
def zeroizeBufferList : List GpuBuffer → List GpuBuffer
  | [] => []
  | b :: bs => zeroizeGpuBuffer b :: zeroizeBufferList bs

/-- Zeroizes all buffers within a Metal memory arena pool. -/
def zeroizeArena (arena : MetalArena) : MetalArena :=
  { buffers := zeroizeBufferList arena.buffers }

/-- Invariant: all buffers in a list are zeroized and free of residual data. -/
def AllZeroized (bufs : List GpuBuffer) : Prop :=
  ∀ b, b ∈ bufs → b.status = GpuMemoryStatus.Zeroized ∧ b.residual_bytes = 0

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem model_zeroed_buffer_fields (bufs : List GpuBuffer) :
    AllZeroized (zeroizeBufferList bufs) := by
  intro b hb
  induction bufs with
  | nil =>
    contradiction
  | cons x xs ih =>
    dsimp [zeroizeBufferList] at hb
    cases hb with
    | head =>
      dsimp [zeroizeGpuBuffer]
      exact ⟨rfl, rfl⟩
    | tail _ h_in =>
      exact ih h_in

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem zeroize_then_reallocate_success (buf : GpuBuffer) (new_sess : Nat) :
    reallocateGpuBuffer (zeroizeGpuBuffer buf) new_sess =
    some { session_id := new_sess,
           size_bytes := buf.size_bytes,
           status := GpuMemoryStatus.Active,
           residual_bytes := 0 } := by
  rfl

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem zeroize_residual_le (buf : GpuBuffer) :
    (zeroizeGpuBuffer buf).residual_bytes ≤ buf.residual_bytes := by
  dsimp [zeroizeGpuBuffer]
  omega

end Enclave
