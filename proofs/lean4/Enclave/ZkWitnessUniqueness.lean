/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

STARK AIR Constraint System Witness Uniqueness & Quotient Completeness
Normative Specification: FS-705 §3.2, ADR-009, & crates/enclave-zk-auditor
-/

-- ASSURANCE: a standalone specification using Nat, records and Booleans.
-- Its original mechanism terminology is an interpretation of model fields.
-- No cryptographic protocol, deployed constraints, OS or hardware is verified here.
namespace Enclave.ZkWitnessUniqueness

/-! # STARK Algebraic Intermediate Representation (AIR) Determinism -/

/-- A single row of an audit trace matrix. -/
structure TraceRow where
  seq_id : Nat
  state_digest : Nat
  deriving DecidableEq, Repr

/-- Transition function for deterministic audit state updates: state' = (state * 31 + seq) % 1000003. -/
def nextTraceState (state : Nat) (seq : Nat) : Nat :=
  (state * 31 + seq) % 1000003

/-- Check if two adjacent trace rows satisfy the AIR transition constraint equation. -/
def airTransitionValid (r1 r2 : TraceRow) : Bool :=
  (r2.seq_id == r1.seq_id + 1) && (r2.state_digest == nextTraceState r1.state_digest r2.seq_id)

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem modular_recurrence_successor_unique
    (r1 r2_a r2_b : TraceRow)
    (h_a : airTransitionValid r1 r2_a = true)
    (h_b : airTransitionValid r1 r2_b = true) :
    r2_a = r2_b := by
  simp [airTransitionValid] at h_a h_b
  cases r2_a
  cases r2_b
  simp_all

/-- Degree bound of the AIR constraint quotient polynomial: degree(C) - degree(Z_H) <= trace_len. -/
def maxQuotientDegree (trace_len : Nat) (constraint_degree : Nat) : Nat :=
  trace_len * (constraint_degree - 1)

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem model_degree_bound_formula (trace_len : Nat) :
    maxQuotientDegree trace_len 2 = trace_len := by
  dsimp [maxQuotientDegree]
  omega

/-! # Multi-Step AIR Execution Trace Global Uniqueness Induction -/

/-- An execution trace is a list of sequential trace rows. -/
def AirTrace := List TraceRow

/-- Inductive predicate specifying that an entire trace satisfies the AIR transition constraints. -/
inductive ValidTrace : AirTrace → Prop where
  | nil : ValidTrace []
  | single (r : TraceRow) : ValidTrace [r]
  | step (r1 r2 : TraceRow) (rest : AirTrace)
      (h_trans : airTransitionValid r1 r2 = true)
      (h_rest : ValidTrace (r2 :: rest)) :
      ValidTrace (r1 :: r2 :: rest)

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem trace_step_deterministic
    (r1 r2_a r2_b : TraceRow)
    (h_a : airTransitionValid r1 r2_a = true)
    (h_b : airTransitionValid r1 r2_b = true) :
    r2_a = r2_b :=
  modular_recurrence_successor_unique r1 r2_a r2_b h_a h_b

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem modular_recurrence_trace_unique
    (t1 t2 : AirTrace) (r0 : TraceRow)
    (h_t1_init : t1.head? = some r0)
    (h_t2_init : t2.head? = some r0)
    (h_t1_valid : ValidTrace t1)
    (h_t2_valid : ValidTrace t2)
    (h_len : t1.length = t2.length) :
    t1 = t2 := by
  induction t1 generalizing t2 r0 with
  | nil =>
    cases t2 with
    | nil => rfl
    | cons _ _ => simp at h_len
  | cons r1 rest1 ih =>
    cases t2 with
    | nil => simp at h_len
    | cons r2 rest2 =>
      dsimp at h_t1_init h_t2_init h_len
      injection h_t1_init with h_r1
      injection h_t2_init with h_r2
      have h_r_eq : r1 = r2 := by rw [h_r1, h_r2]
      subst h_r_eq
      cases rest1 with
      | nil =>
        cases rest2 with
        | nil => rfl
        | cons _ _ => simp at h_len
      | cons next1 tail1 =>
        cases rest2 with
        | nil => simp at h_len
        | cons next2 tail2 =>
          cases h_t1_valid with
          | step _ _ _ h_step1 h_rest1 =>
            cases h_t2_valid with
            | step _ _ _ h_step2 h_rest2 =>
              have h_next_eq : next1 = next2 := modular_recurrence_successor_unique r1 next1 next2 h_step1 h_step2
              subst h_next_eq
              have h_tail_len : (next1 :: tail1).length = (next1 :: tail2).length := Nat.add_right_cancel h_len
              have ih_res := ih (next1 :: tail2) next1 rfl rfl h_rest1 h_rest2 h_tail_len
              exact congrArg (List.cons r1) ih_res

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem air_transition_seq_monotonic
    (r1 r2 : TraceRow)
    (h_valid : airTransitionValid r1 r2 = true) :
    r2.seq_id = r1.seq_id + 1 := by
  dsimp [airTransitionValid] at h_valid
  revert h_valid
  cases h_eq : (r2.seq_id == r1.seq_id + 1)
  · intro h_c; contradiction
  · intro _
    exact of_decide_eq_true h_eq

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem quotient_degree_monotonic
    (len1 len2 : Nat) (d : Nat)
    (h_len : len1 ≤ len2) :
    maxQuotientDegree len1 d ≤ maxQuotientDegree len2 d := by
  dsimp [maxQuotientDegree]
  exact Nat.mul_le_mul_right (d - 1) h_len

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem quotient_degree_zero (d : Nat) :
    maxQuotientDegree 0 d = 0 := by
  simp [maxQuotientDegree]

end Enclave.ZkWitnessUniqueness
