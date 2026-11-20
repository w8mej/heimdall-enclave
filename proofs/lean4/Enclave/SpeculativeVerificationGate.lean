/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Speculative Draft Verification Gate & Calibration Error Soundness
Normative Specification: FS-701 §3.4, ADR-014, & crates/enclave-model-runnerd
-/

-- ASSURANCE: a standalone specification using Nat, records and Booleans.
-- Its original mechanism terminology is an interpretation of model fields.
-- No cryptographic protocol, deployed constraints, OS or hardware is verified here.
namespace Enclave

/-! # Speculative Verification Sentinel Model -/

/-- Maximum allowed empirical calibration error (ECE) scaled by 1000 (0.015 * 1000 = 15). -/
def MAX_CALIBRATED_ECE_PERMILLE : Nat := 15

/-- Candidate speculative draft token with verification metadata. -/
structure SpeculativeDraftToken where
  token_id : Nat
  calibrated_ece_permille : Nat
  is_safety_cleared : Bool
  deriving DecidableEq, Repr

/-- Verify a single speculative draft token. -/
def verifyDraftToken (t : SpeculativeDraftToken) : Bool :=
  (t.calibrated_ece_permille ≤ MAX_CALIBRATED_ECE_PERMILLE) && t.is_safety_cleared

/--
Batch verification of speculative draft sequence.
Returns the longest approved contiguous prefix. Any anomalous token halts verification.
-/
def verifyDraftPrefix : List SpeculativeDraftToken → List Nat
  | [] => []
  | t :: ts =>
    if verifyDraftToken t then
      t.token_id :: verifyDraftPrefix ts
    else
      []

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem model_draft_flags_reject
    (t : SpeculativeDraftToken)
    (h_ece : t.calibrated_ece_permille > MAX_CALIBRATED_ECE_PERMILLE) :
    verifyDraftToken t = false := by
  simp_all [verifyDraftToken] <;> omega

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem accepted_draft_prefix_length_bound (tokens : List SpeculativeDraftToken) :
    (verifyDraftPrefix tokens).length ≤ tokens.length := by
  induction tokens with
  | nil => simp [verifyDraftPrefix]
  | cons t ts ih =>
    simp [verifyDraftPrefix]
    split <;> simp_all <;> omega

/-! # Extended Safety Verification & Rollback Invariants -/

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem speculative_draft_uncleared_rejected
    (t : SpeculativeDraftToken)
    (h_uncleared : t.is_safety_cleared = false) :
    verifyDraftToken t = false := by
  simp_all [verifyDraftToken] <;> omega

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem invalid_head_empty_prefix
    (t : SpeculativeDraftToken) (ts : List SpeculativeDraftToken)
    (h_invalid : verifyDraftToken t = false) :
    verifyDraftPrefix (t :: ts) = [] := by
  dsimp [verifyDraftPrefix]
  rw [h_invalid]
  rfl

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem all_valid_prefix_full
    (tokens : List SpeculativeDraftToken)
    (h_all : ∀ t ∈ tokens, verifyDraftToken t = true) :
    (verifyDraftPrefix tokens).length = tokens.length := by
  induction tokens with
  | nil => rfl
  | cons t ts ih =>
    have ht : verifyDraftToken t = true := h_all t (List.Mem.head ts)
    have hts : ∀ x ∈ ts, verifyDraftToken x = true := fun x hx => h_all x (List.Mem.tail t hx)
    dsimp [verifyDraftPrefix]
    rw [ht]
    dsimp
    congr 1
    exact ih hts

end Enclave
