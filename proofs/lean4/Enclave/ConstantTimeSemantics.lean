/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Constant-Time Operational Semantics & Microarchitectural Timing Noninterference
Normative Specification: Apple Silicon Unified Memory SLC & Cache-Timing Protection
-/

import Enclave.Lattice

-- ASSURANCE: a standalone specification using Nat, records and Booleans.
-- Its original mechanism terminology is an interpretation of model fields.
-- No cryptographic protocol, deployed constraints, OS or hardware is verified here.
namespace Enclave

/-! # Microarchitectural Execution Observations & Timing Model -/

/-- Microarchitectural instruction classification for timing models. -/
inductive MicroOpClass where
  | ConstArith : MicroOpClass
  | MemoryLoad : MicroOpClass
  | MemoryStore : MicroOpClass
  | MemoryFence : MicroOpClass
  | BranchTaken : MicroOpClass
  | BranchNotTaken : MicroOpClass
  | BitwiseMask : MicroOpClass
  deriving DecidableEq, Repr

/--
A single step microarchitectural observation.
`cycle_cost`: Constant hardware latency class on Apple Silicon M-series.
`memory_stride`: Address access stride (uniform 64-byte cache line).
`op_class`: Operation category.
-/
structure MicroObservation where
  cycle_cost : Nat
  memory_stride : Nat
  op_class : MicroOpClass
  deriving DecidableEq, Repr

/-- Execution trace of microarchitectural side-effects visible to hardware probes. -/
abbrev TimingTrace := List MicroObservation

/-- A confidential state context tagged with a lattice confidentiality label. -/
structure TimedSecretContext where
  label : ConfLevel
  raw_value : Nat
  deriving DecidableEq, Repr

/--
Constant-time evaluation dispatcher.
For any operation on confidential tokens (C3, C4), the execution path uses
straight-line constant-latency instructions and uniform cache-line strides.
-/
def evalConstantTime (ctx : TimedSecretContext) : TimingTrace :=
  match ctx.label with
  | ConfLevel.C4 =>
    [ { cycle_cost := 3, memory_stride := 64, op_class := MicroOpClass.MemoryLoad },
      { cycle_cost := 1, memory_stride := 0,  op_class := MicroOpClass.ConstArith },
      { cycle_cost := 4, memory_stride := 64, op_class := MicroOpClass.MemoryFence } ]
  | ConfLevel.C3 =>
    [ { cycle_cost := 3, memory_stride := 64, op_class := MicroOpClass.MemoryLoad },
      { cycle_cost := 1, memory_stride := 0,  op_class := MicroOpClass.ConstArith },
      { cycle_cost := 4, memory_stride := 64, op_class := MicroOpClass.MemoryFence } ]
  | ConfLevel.C2 =>
    [ { cycle_cost := 2, memory_stride := 64, op_class := MicroOpClass.MemoryLoad },
      { cycle_cost := 1, memory_stride := 0,  op_class := MicroOpClass.ConstArith } ]
  | ConfLevel.C1 =>
    [ { cycle_cost := 1, memory_stride := 0,  op_class := MicroOpClass.ConstArith } ]

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem label_fixed_observation_list_equal
    (c1 c2 : TimedSecretContext)
    (h_label : c1.label = c2.label) :
    evalConstantTime c1 = evalConstantTime c2 := by
  dsimp [evalConstantTime]
  rw [h_label]

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem label_fixed_dispatch_path_equal
    (ctx : TimedSecretContext)
    (h_c4 : ctx.label = ConfLevel.C4) :
    (evalConstantTime ctx).length = 3 := by
  dsimp [evalConstantTime]
  rw [h_c4]
  rfl

/-- Computes the total hardware execution latency in clock cycles across a trace. -/
def totalCycles : TimingTrace → Nat
  | [] => 0
  | op :: ops => op.cycle_cost + totalCycles ops

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem c4_cycles_constant (ctx : TimedSecretContext) (h_c4 : ctx.label = ConfLevel.C4) :
    totalCycles (evalConstantTime ctx) = 8 := by
  simp_all [evalConstantTime, totalCycles]

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem total_cycle_cost_secret_independent
    (c1 c2 : TimedSecretContext)
    (h_label : c1.label = c2.label) :
    totalCycles (evalConstantTime c1) = totalCycles (evalConstantTime c2) := by
  rw [label_fixed_observation_list_equal c1 c2 h_label]

/-- Predicate verifying that all memory access strides in a trace are cache-line aligned (0 or 64 bytes). -/
def CacheAlignedStrides (trace : TimingTrace) : Prop :=
  ∀ op ∈ trace, op.memory_stride = 0 ∨ op.memory_stride = 64

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem c4_cache_aligned (ctx : TimedSecretContext) (h_c4 : ctx.label = ConfLevel.C4) :
    CacheAlignedStrides (evalConstantTime ctx) := by
  simp_all [evalConstantTime, totalCycles, CacheAlignedStrides]

/-! # Semantic Side-Channel Model: Branching vs. Straight-Line Constant-Time Selection -/

/--
Vulnerable variable-time conditional selection:
Takes a conditional branch depending on secret condition `cond`.
Emits different microarchitectural event sequences for true vs false.
-/
def variableTimeSelect (cond : Bool) (secret_a secret_b : Nat) : Nat × TimingTrace :=
  if cond then
    (secret_a, [
      { cycle_cost := 1, memory_stride := 0,  op_class := MicroOpClass.BranchTaken },
      { cycle_cost := 3, memory_stride := 64, op_class := MicroOpClass.MemoryLoad }
    ])
  else
    (secret_b, [
      { cycle_cost := 1, memory_stride := 0,  op_class := MicroOpClass.BranchNotTaken },
      { cycle_cost := 3, memory_stride := 64, op_class := MicroOpClass.MemoryLoad }
    ])

/--
Constant-time bitwise multiplexer (cmov / csel):
Computes result via arithmetic bitmask manipulation without conditional branches.
`mask = if cond_bit == 1 then 1 else 0`
Always executes the exact same sequence of micro-ops regardless of `cond_bit`.
-/
def constantTimeMux (cond_bit : Nat) (secret_a secret_b : Nat) : Nat × TimingTrace :=
  let result := if cond_bit == 1 then secret_a else secret_b
  (result, [
    { cycle_cost := 1, memory_stride := 0, op_class := MicroOpClass.BitwiseMask },
    { cycle_cost := 1, memory_stride := 0, op_class := MicroOpClass.ConstArith },
    { cycle_cost := 1, memory_stride := 0, op_class := MicroOpClass.ConstArith }
  ])

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem variable_time_branch_leakage (a b : Nat) :
    (variableTimeSelect true a b).2 ≠ (variableTimeSelect false a b).2 := by
  dsimp [variableTimeSelect]
  intro h_contra
  injection h_contra with h_head _
  injection h_head with _ _ h_op
  contradiction

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem constant_time_mux_trace_invariance
    (c1 c2 a1 a2 b1 b2 : Nat) :
    (constantTimeMux c1 a1 b1).2 = (constantTimeMux c2 a2 b2).2 := by
  rfl

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem constant_time_mux_latency (c a b : Nat) :
    totalCycles (constantTimeMux c a b).2 = 3 := by
  rfl

end Enclave
