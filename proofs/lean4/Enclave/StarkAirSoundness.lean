/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Plonky3 STARK AIR Constraint & Lasso Multiset Lookup Soundness Proofs
Normative Specification: FS-705 §3.2, ADR-017, & crates/enclave-zk-auditor/src/zk/
-/

-- ASSURANCE: a standalone specification using Nat, records and Booleans.
-- Its original mechanism terminology is an interpretation of model fields.
-- No cryptographic protocol, deployed constraints, OS or hardware is verified here.
namespace Enclave.StarkAirSoundness

/-- A single row in the Plonky3 STARK AIR execution trace table -/
structure AirTraceRow where
  seq_num : Nat          -- Monotonic step sequence number
  prev_digest : Nat      -- Inbound hash-chain state from previous step
  entry_digest : Nat     -- Event record payload digest
  curr_digest : Nat      -- Outbound hash-chain state computed this step
  deriving DecidableEq, Repr

/--
AIR Transition Constraint:
Evaluated on every adjacent row pair (row_k, row_{k+1}) across the execution trace.
Enforces:
1. Contiguous sequence progression: seq_{k+1} == seq_k + 1 (gap-free).
2. Cryptographic digest chaining: prev_{k+1} == curr_k (tamper-free).
-/
def airTransitionValid (r1 r2 : AirTraceRow) : Prop :=
  r2.seq_num = r1.seq_num + 1 ∧
  r2.prev_digest = r1.curr_digest

/-- Boolean evaluator for the transition constraint in the STARK verifier -/
def evalAirTransition (r1 r2 : AirTraceRow) : Bool :=
  (r2.seq_num == r1.seq_num + 1) &&
  (r2.prev_digest == r1.curr_digest)

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem air_sequence_strictly_monotonic (r1 r2 : AirTraceRow)
    (h_valid : airTransitionValid r1 r2) :
    r1.seq_num < r2.seq_num := by
  have h_step := h_valid.1
  rw [h_step]
  exact Nat.lt_succ_self r1.seq_num

theorem air_sequence_strictly_increasing (r1 r2 : AirTraceRow)
    (h_valid : airTransitionValid r1 r2) :
    r1.seq_num < r2.seq_num :=
  air_sequence_strictly_monotonic r1 r2 h_valid

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem air_gap_free_chaining (r1 r2 : AirTraceRow)
    (h_valid : airTransitionValid r1 r2) :
    r2.seq_num = r1.seq_num + 1 := by
  exact h_valid.1

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem air_hash_chain_contiguous (r1 r2 : AirTraceRow)
    (h_valid : airTransitionValid r1 r2) :
    r2.prev_digest = r1.curr_digest := by
  exact h_valid.2

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem row_prev_mismatch_rejects (r1 r2 : AirTraceRow)
    (h_tamper : r2.prev_digest ≠ r1.curr_digest) :
    evalAirTransition r1 r2 = false := by
  dsimp [evalAirTransition]
  have h_eq : (r2.prev_digest == r1.curr_digest) = false := by
    cases h : (r2.prev_digest == r1.curr_digest)
    · rfl
    · simp only [beq_iff_eq] at h; contradiction
  rw [h_eq]
  simp

/-- Multiset entry representation for Lasso lookup arguments -/
structure MultisetEntry where
  event_type : Nat
  payload_hash : Nat
  deriving DecidableEq, Repr

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem subset_excludes_nonmember
    (table_A table_T : List MultisetEntry)
    (h_subset : ∀ e ∈ table_A, e ∈ table_T)
    (unauth_event : MultisetEntry)
    (h_unauth_not_in_T : unauth_event ∉ table_T) :
    unauth_event ∉ table_A := by
  intro h_in_A
  have h_in_T := h_subset unauth_event h_in_A
  contradiction

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem valid_successors_agree_on_sequence_and_prev (r1 r2a r2b : AirTraceRow)
    (h_valid_a : airTransitionValid r1 r2a)
    (h_valid_b : airTransitionValid r1 r2b) :
    r2a.seq_num = r2b.seq_num ∧ r2a.prev_digest = r2b.prev_digest := by
  have h_seq_a := h_valid_a.1
  have h_seq_b := h_valid_b.1
  have h_dig_a := h_valid_a.2
  have h_dig_b := h_valid_b.2
  have h_seq_eq : r2a.seq_num = r2b.seq_num := by rw [h_seq_a, h_seq_b]
  have h_dig_eq : r2a.prev_digest = r2b.prev_digest := by rw [h_dig_a, h_dig_b]
  exact ⟨h_seq_eq, h_dig_eq⟩

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem row_boolean_check_implies_two_equalities (r1 r2 : AirTraceRow)
    (h_eval : evalAirTransition r1 r2 = true) :
    r2.seq_num = r1.seq_num + 1 ∧ r2.prev_digest = r1.curr_digest := by
  dsimp [evalAirTransition] at h_eval
  simp only [Bool.and_eq_true, beq_iff_eq] at h_eval
  exact h_eval

end Enclave.StarkAirSoundness
