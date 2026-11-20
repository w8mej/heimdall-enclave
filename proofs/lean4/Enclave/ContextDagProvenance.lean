/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Multi-Turn Conversation Context DAG Taint Propagation & Provenance Proofs
Normative Specification: FS-704 §3.1, §5.1, ADR-007, ADR-014, & crates/enclave-agent-runtime/
-/

import Enclave.Lattice

namespace Enclave

/-! # Multi-Turn Context DAG Node & Integrity Taint -/

/-- A node in the multi-turn agent conversation DAG -/
structure DagNode where
  node_id : Nat
  parent_ids : List Nat
  integrity : IntegLevel
  is_sanitized : Bool
  deriving DecidableEq, Repr

/--
Derive Child Node Integrity (Unsanitized):
In the absence of a verified sanitization gate, child integrity is computed as the
least upper bound (join) of all incoming parent integrity taint levels.
If any parent is tainted at T3 (untrusted tool output / prompt injection vector),
the child unconditionally becomes T3.
-/
def deriveChildIntegrity (parent_levels : List IntegLevel) : IntegLevel :=
  parent_levels.foldl IntegLevel.join IntegLevel.T0

/--
Theorem 23.1 (Context DAG Taint Propagation):
If any parent node in the derivation history carries taint level T3 (untrusted external data),
the derived child node is tainted at level T3.
-/
theorem context_dag_taint_propagation
    (parents : List IntegLevel)
    (h_has_t3 : IntegLevel.T3 ∈ parents) :
    deriveChildIntegrity parents = IntegLevel.T3 := by
  dsimp [deriveChildIntegrity]
  induction parents with
  | nil => contradiction
  | cons head tail ih =>
    cases h_has_t3 with
    | head =>
      -- head is T3. Notice foldl over tail starting from IntegLevel.join IntegLevel.T0 T3
      have h_j0 : IntegLevel.join IntegLevel.T0 IntegLevel.T3 = IntegLevel.T3 := rfl
      dsimp [List.foldl]
      rw [h_j0]
      -- For any tail, foldl IntegLevel.join IntegLevel.T3 tail = IntegLevel.T3
      have h_absorb : ∀ l, List.foldl IntegLevel.join IntegLevel.T3 l = IntegLevel.T3 := by
        intro l
        induction l with
        | nil => rfl
        | cons x xs ih_x =>
          dsimp [List.foldl]
          have h_x3 : IntegLevel.join IntegLevel.T3 x = IntegLevel.T3 := by
            cases x <;> rfl
          rw [h_x3]
          exact ih_x
      exact h_absorb tail
    | tail _ h_in_tail =>
      dsimp [List.foldl]
      -- If T3 is in tail, foldl IntegLevel.join (join T0 head) tail is also T3
      cases head with
      | T0 =>
        have h_j : IntegLevel.join IntegLevel.T0 IntegLevel.T0 = IntegLevel.T0 := rfl
        rw [h_j]
        exact ih h_in_tail
      | T1 =>
        have h_absorb : ∀ l, IntegLevel.T3 ∈ l → List.foldl IntegLevel.join IntegLevel.T1 l = IntegLevel.T3 := by
          intro l hl
          induction l with
          | nil => contradiction
          | cons x xs ih_l =>
            cases hl with
            | head =>
              have h_j : IntegLevel.join IntegLevel.T1 IntegLevel.T3 = IntegLevel.T3 := rfl
              dsimp [List.foldl]; rw [h_j]
              have h_top : ∀ rem, List.foldl IntegLevel.join IntegLevel.T3 rem = IntegLevel.T3 := by
                intro rem; induction rem with
                | nil => rfl
                | cons y ys ih_y =>
                  dsimp [List.foldl]
                  have h_y : IntegLevel.join IntegLevel.T3 y = IntegLevel.T3 := by cases y <;> rfl
                  rw [h_y]; exact ih_y
              exact h_top xs
            | tail _ h_tail =>
              dsimp [List.foldl]
              cases x with
              | T0 => exact ih_l h_tail
              | T1 => exact ih_l h_tail
              | T2 =>
                have h_absorb2 : ∀ l, IntegLevel.T3 ∈ l → List.foldl IntegLevel.join IntegLevel.T2 l = IntegLevel.T3 := by
                  intro l2 hl2; induction l2 with
                  | nil => contradiction
                  | cons z zs ih_z =>
                    cases hl2 with
                    | head =>
                      dsimp [List.foldl]
                      have h_z : IntegLevel.join IntegLevel.T2 IntegLevel.T3 = IntegLevel.T3 := rfl
                      rw [h_z]
                      have h_top : ∀ rem, List.foldl IntegLevel.join IntegLevel.T3 rem = IntegLevel.T3 := by
                        intro rem; induction rem with
                        | nil => rfl
                        | cons w ws ih_w =>
                          dsimp [List.foldl]
                          have h_w : IntegLevel.join IntegLevel.T3 w = IntegLevel.T3 := by cases w <;> rfl
                          rw [h_w]; exact ih_w
                      exact h_top zs
                    | tail _ h_t2 =>
                      dsimp [List.foldl]
                      cases z with
                      | T0 => exact ih_z h_t2
                      | T1 => exact ih_z h_t2
                      | T2 => exact ih_z h_t2
                      | T3 =>
                        have h_top : ∀ rem, List.foldl IntegLevel.join IntegLevel.T3 rem = IntegLevel.T3 := by
                          intro rem; induction rem with
                          | nil => rfl
                          | cons w ws ih_w =>
                            dsimp [List.foldl]
                            have h_w : IntegLevel.join IntegLevel.T3 w = IntegLevel.T3 := by cases w <;> rfl
                            rw [h_w]; exact ih_w
                        exact h_top zs
                exact h_absorb2 xs h_tail
              | T3 =>
                have h_top : ∀ rem, List.foldl IntegLevel.join IntegLevel.T3 rem = IntegLevel.T3 := by
                  intro rem; induction rem with
                  | nil => rfl
                  | cons w ws ih_w =>
                    dsimp [List.foldl]
                    have h_w : IntegLevel.join IntegLevel.T3 w = IntegLevel.T3 := by cases w <;> rfl
                    rw [h_w]; exact ih_w
                exact h_top xs
        exact h_absorb tail h_in_tail
      | T2 =>
        have h_absorb2 : ∀ l, IntegLevel.T3 ∈ l → List.foldl IntegLevel.join IntegLevel.T2 l = IntegLevel.T3 := by
          intro l2 hl2; induction l2 with
          | nil => contradiction
          | cons z zs ih_z =>
            cases hl2 with
            | head =>
              dsimp [List.foldl]
              have h_z : IntegLevel.join IntegLevel.T2 IntegLevel.T3 = IntegLevel.T3 := rfl
              rw [h_z]
              have h_top : ∀ rem, List.foldl IntegLevel.join IntegLevel.T3 rem = IntegLevel.T3 := by
                intro rem; induction rem with
                | nil => rfl
                | cons w ws ih_w =>
                  dsimp [List.foldl]
                  have h_w : IntegLevel.join IntegLevel.T3 w = IntegLevel.T3 := by cases w <;> rfl
                  rw [h_w]; exact ih_w
              exact h_top zs
            | tail _ h_t2 =>
              dsimp [List.foldl]
              cases z with
              | T0 => exact ih_z h_t2
              | T1 => exact ih_z h_t2
              | T2 => exact ih_z h_t2
              | T3 =>
                have h_top : ∀ rem, List.foldl IntegLevel.join IntegLevel.T3 rem = IntegLevel.T3 := by
                  intro rem; induction rem with
                  | nil => rfl
                  | cons w ws ih_w =>
                    dsimp [List.foldl]
                    have h_w : IntegLevel.join IntegLevel.T3 w = IntegLevel.T3 := by cases w <;> rfl
                    rw [h_w]; exact ih_w
                exact h_top zs
        exact h_absorb2 tail h_in_tail
      | T3 =>
        have h_top : ∀ rem, List.foldl IntegLevel.join IntegLevel.T3 rem = IntegLevel.T3 := by
          intro rem; induction rem with
          | nil => rfl
          | cons w ws ih_w =>
            dsimp [List.foldl]
            have h_w : IntegLevel.join IntegLevel.T3 w = IntegLevel.T3 := by cases w <;> rfl
            rw [h_w]; exact ih_w
        exact h_top tail

/--
Sanitize Node:
Applies an attested DFA/NLP sanitization filter to cleanse prompt injection markers.
Restores integrity level to T1 if sanitization succeeds.
-/
def sanitizeNode (node : DagNode) (sanitizer_passed : Bool) : DagNode :=
  if sanitizer_passed then
    { node with integrity := IntegLevel.T1, is_sanitized := true }
  else
    node

/--
Theorem 23.2 (Sanitized Node Integrity Restoration):
Applying a verified sanitization filter safely decontaminates the node, restoring its
integrity to T1.
-/
theorem sanitized_node_restoration (node : DagNode) :
    (sanitizeNode node true).integrity = IntegLevel.T1 ∧
    (sanitizeNode node true).is_sanitized = true := by
  dsimp [sanitizeNode]
  exact ⟨rfl, rfl⟩

/--
Theorem 23.3 (Untainted Source Preserves Integrity):
If a turn derives strictly from trusted enclave sources (T0 and T1), the derived
child node remains at integrity ≤ T1.
-/
theorem untainted_source_preserves_integrity
    (parents : List IntegLevel)
    (h_trusted : ∀ p ∈ parents, p = IntegLevel.T0 ∨ p = IntegLevel.T1) :
    deriveChildIntegrity parents ≤ IntegLevel.T1 := by
  dsimp [deriveChildIntegrity]
  induction parents with
  | nil =>
    decide
  | cons head tail ih =>
    have h_head : head = IntegLevel.T0 ∨ head = IntegLevel.T1 :=
      h_trusted head (List.Mem.head tail)
    have h_tail_trusted : ∀ p ∈ tail, p = IntegLevel.T0 ∨ p = IntegLevel.T1 :=
      fun p hp => h_trusted p (List.Mem.tail head hp)
    dsimp [List.foldl]
    cases h_head with
    | inl h0 =>
      rw [h0]
      have h_j0 : IntegLevel.join IntegLevel.T0 IntegLevel.T0 = IntegLevel.T0 := rfl
      rw [h_j0]
      exact ih h_tail_trusted
    | inr h1 =>
      rw [h1]
      have h_j1 : IntegLevel.join IntegLevel.T0 IntegLevel.T1 = IntegLevel.T1 := rfl
      rw [h_j1]
      have h_tail_bounded : ∀ l, (∀ p ∈ l, p = IntegLevel.T0 ∨ p = IntegLevel.T1) →
          List.foldl IntegLevel.join IntegLevel.T1 l ≤ IntegLevel.T1 := by
        intro l hl
        induction l with
        | nil => decide
        | cons x xs ih_xs =>
          have h_x := hl x (List.Mem.head xs)
          have h_rem : ∀ p ∈ xs, p = IntegLevel.T0 ∨ p = IntegLevel.T1 :=
            fun p hp => hl p (List.Mem.tail x hp)
          dsimp [List.foldl]
          cases h_x with
          | inl hx0 =>
            rw [hx0]
            have h_jx : IntegLevel.join IntegLevel.T1 IntegLevel.T0 = IntegLevel.T1 := rfl
            rw [h_jx]
            exact ih_xs h_rem
          | inr hx1 =>
            rw [hx1]
            have h_jx : IntegLevel.join IntegLevel.T1 IntegLevel.T1 = IntegLevel.T1 := rfl
            rw [h_jx]
            exact ih_xs h_rem
      exact h_tail_bounded tail h_tail_trusted

end Enclave
