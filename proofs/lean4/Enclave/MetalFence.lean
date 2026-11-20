/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Metal Compute Fence (MTLSharedEvent) & Surprise Abort Semantics Proofs
Normative Specification: FS-701 §3.3, ADR-018, & crates/enclave-model-runnerd/src/metal.rs
-/

-- ASSURANCE: a standalone specification using Nat, records and Booleans.
-- Its original mechanism terminology is an interpretation of model fields.
-- No cryptographic protocol, deployed constraints, OS or hardware is verified here.
namespace Enclave

/-! # Metal Shared Event Fence & Command Buffer State -/

inductive FenceStatus where
  | Waiting : FenceStatus
  | Signaled : FenceStatus
  | Aborted : FenceStatus
  deriving DecidableEq, Repr

/--
Metal compute command buffer containing raw tensor operations.
`surprise_basis_points`: Semantic surprise / entropy divergence score (10,000 = 100.0%).
`tensor_bytes`: Size of intermediate activation tensor allocations in unified memory.
-/
structure CommandBuffer where
  cmd_id : Nat
  surprise_basis_points : Nat
  tensor_bytes : Nat
  deriving DecidableEq, Repr

/-- Maximum allowable semantic surprise threshold before trigger abort (85.00%) -/
def SURPRISE_THRESHOLD_BP : Nat := 8500

/-- Result of evaluating a Metal command buffer across the IPC ring boundary -/
structure RingBufferResult where
  status : FenceStatus
  emitted_bytes : Nat
  deriving DecidableEq, Repr

/--
Operational Evaluator:
When semantic surprise exceeds SURPRISE_THRESHOLD_BP, the MTLSharedEvent fence
triggers an immediate command buffer abort and purges memory, emitting 0 bytes.
Otherwise, the fence is signaled and outputs are released to the orchestrator.
-/
def dispatchCommandBuffer (cmd : CommandBuffer) : RingBufferResult :=
  if cmd.surprise_basis_points > SURPRISE_THRESHOLD_BP then
    { status := FenceStatus.Aborted, emitted_bytes := 0 }
  else
    { status := FenceStatus.Signaled, emitted_bytes := cmd.tensor_bytes }

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem surprise_abort_zero_emitted_bytes (cmd : CommandBuffer)
    (h_anomalous : cmd.surprise_basis_points > SURPRISE_THRESHOLD_BP) :
    (dispatchCommandBuffer cmd).emitted_bytes = 0 ∧
    (dispatchCommandBuffer cmd).status = FenceStatus.Aborted := by
  simp_all [SURPRISE_THRESHOLD_BP, dispatchCommandBuffer]

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem abort_branch_emits_zero (cmd : CommandBuffer)
    (h_aborted : (dispatchCommandBuffer cmd).status = FenceStatus.Aborted) :
    (dispatchCommandBuffer cmd).emitted_bytes = 0 := by
  simp [dispatchCommandBuffer] at * <;> split <;> simp_all <;> omega

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem normal_inference_progress (cmd : CommandBuffer)
    (h_nominal : cmd.surprise_basis_points ≤ SURPRISE_THRESHOLD_BP) :
    (dispatchCommandBuffer cmd).status = FenceStatus.Signaled ∧
    (dispatchCommandBuffer cmd).emitted_bytes = cmd.tensor_bytes := by
  simp [dispatchCommandBuffer] at * <;> split <;> simp_all <;> omega

end Enclave
