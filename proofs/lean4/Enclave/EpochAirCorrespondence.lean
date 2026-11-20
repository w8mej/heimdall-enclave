import Enclave.EpochAirExtracted
import Mathlib.Tactic.Ring

/-! All-field-input theorem about the actual extracted EpochAir polynomials.
The source correspondence check is scripts/extract-epoch-air.py (no --write).
No correctness result is assumed for the unused auxiliary AIRs. -/
namespace Enclave.EpochAirCorrespondence
open Enclave.FieldRangeProofs
open Enclave.EpochAirExtracted (Env satisfies constraint c50 c51)

def usedBits (e : Env) : List F := [e.main 0 34, e.main 0 35, e.main 0 36, e.main 0 37, e.main 0 38, e.main 0 39, e.main 0 40, e.main 0 41, e.main 0 42, e.main 0 43, e.main 0 44, e.main 0 45, e.main 0 46, e.main 0 47]
def slackBits (e : Env) : List F := [e.main 0 6, e.main 0 7, e.main 0 8, e.main 0 9, e.main 0 10, e.main 0 11, e.main 0 12, e.main 0 13, e.main 0 14, e.main 0 15, e.main 0 16, e.main 0 17, e.main 0 18, e.main 0 19]

theorem used_bits_boolean (e : Env) (h : satisfies e) :
    ∀ b ∈ usedBits e, b*(b-1)=0 := by
  intro b hb
  simp only [usedBits, List.mem_cons, List.not_mem_nil, or_false] at hb
  rcases hb with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  · exact h ⟨9, by decide⟩
  · exact h ⟨12, by decide⟩
  · exact h ⟨15, by decide⟩
  · exact h ⟨18, by decide⟩
  · exact h ⟨21, by decide⟩
  · exact h ⟨24, by decide⟩
  · exact h ⟨27, by decide⟩
  · exact h ⟨30, by decide⟩
  · exact h ⟨33, by decide⟩
  · exact h ⟨36, by decide⟩
  · exact h ⟨39, by decide⟩
  · exact h ⟨42, by decide⟩
  · exact h ⟨45, by decide⟩
  · exact h ⟨48, by decide⟩

theorem slack_bits_boolean (e : Env) (h : satisfies e) :
    ∀ b ∈ slackBits e, b*(b-1)=0 := by
  intro b hb
  simp only [slackBits, List.mem_cons, List.not_mem_nil, or_false] at hb
  rcases hb with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  · exact h ⟨7, by decide⟩
  · exact h ⟨10, by decide⟩
  · exact h ⟨13, by decide⟩
  · exact h ⟨16, by decide⟩
  · exact h ⟨19, by decide⟩
  · exact h ⟨22, by decide⟩
  · exact h ⟨25, by decide⟩
  · exact h ⟨28, by decide⟩
  · exact h ⟨31, by decide⟩
  · exact h ⟨34, by decide⟩
  · exact h ⟨37, by decide⟩
  · exact h ⟨40, by decide⟩
  · exact h ⟨43, by decide⟩
  · exact h ⟨46, by decide⟩

theorem extracted_used_decomposition (e : Env) (h : satisfies e) :
    e.main 0 5 = fieldBits (usedBits e) := by
  have hh := h ⟨50,by decide⟩
  change c50 e=0 at hh
  have poly : c50 e = e.main 0 5-fieldBits (usedBits e) := by
    dsimp [c50, usedBits, fieldBits]
    ring
  rw [poly] at hh
  exact sub_eq_zero.mp hh

theorem extracted_slack_decomposition (e : Env) (h : satisfies e) :
    e.public 1-e.main 0 5 = fieldBits (slackBits e) := by
  have hh := h ⟨51,by decide⟩
  change c51 e=0 at hh
  have poly : c51 e = (e.public 1-e.main 0 5)-fieldBits (slackBits e) := by
    dsimp [c51, slackBits, fieldBits]
    ring
  rw [poly] at hh
  exact sub_eq_zero.mp hh

theorem actual_epoch_constraints_enforce_used_cap (e : Env) (h : satisfies e) :
    (e.main 0 5).val ≤ (e.public 1).val := by
  have usedRange := constrained_used_has_fourteen_bit_range (e.main 0 5)
    (usedBits e) rfl (used_bits_boolean e h) (extracted_used_decomposition e h)
  have slackRange := constrained_used_has_fourteen_bit_range (e.public 1-e.main 0 5)
    (slackBits e) rfl (slack_bits_boolean e h) (extracted_slack_decomposition e h)
  exact actual_field_slack_implies_integer_cap (e.public 1) (e.main 0 5)
    (e.public 1-e.main 0 5) usedRange slackRange rfl

def deltaBits (e : Env) : List F := (usedBits {e with
  main := fun offset column => e.main offset (column-14)})

theorem delta_bits_boolean (e : Env) (h : satisfies e) :
    ∀ b ∈ deltaBits e, b*(b-1)=0 := by
  intro b hb
  simp only [deltaBits, usedBits, List.mem_cons, List.not_mem_nil, or_false] at hb
  rcases hb with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  · exact h ⟨8, by decide⟩
  · exact h ⟨11, by decide⟩
  · exact h ⟨14, by decide⟩
  · exact h ⟨17, by decide⟩
  · exact h ⟨20, by decide⟩
  · exact h ⟨23, by decide⟩
  · exact h ⟨26, by decide⟩
  · exact h ⟨29, by decide⟩
  · exact h ⟨32, by decide⟩
  · exact h ⟨35, by decide⟩
  · exact h ⟨38, by decide⟩
  · exact h ⟨41, by decide⟩
  · exact h ⟨44, by decide⟩
  · exact h ⟨47, by decide⟩

theorem actual_delta_range (e : Env) (h : satisfies e) : (e.main 0 4).val < 16384 := by
  apply constrained_used_has_fourteen_bit_range (e.main 0 4) (deltaBits e) rfl
    (delta_bits_boolean e h)
  have hh := h ⟨49,by decide⟩
  change Enclave.EpochAirExtracted.c49 e=0 at hh
  have poly : Enclave.EpochAirExtracted.c49 e = e.main 0 4-fieldBits (deltaBits e) := by
    dsimp [Enclave.EpochAirExtracted.c49, deltaBits, usedBits, fieldBits]
    ring
  rw [poly] at hh
  exact sub_eq_zero.mp hh

theorem actual_used_range (e : Env) (h : satisfies e) : (e.main 0 5).val < 16384 :=
  constrained_used_has_fourteen_bit_range (e.main 0 5) (usedBits e) rfl
    (used_bits_boolean e h) (extracted_used_decomposition e h)

theorem field_addition_lifts (a b c : F) (ha : a.val<16384) (hb : b.val<16384)
    (h : c=a+b) : c.val=a.val+b.val := by
  have sum_lt : a.val+b.val < P := by unfold P; omega
  have eq : c = ((a.val+b.val : Nat) : F) := by
    simpa only [Nat.cast_add, ZMod.natCast_zmod_val] using h
  have hv := congrArg ZMod.val eq
  rwa [ZMod.val_natCast_of_lt sum_lt] at hv

/-- Selectors are constructed from row position. A caller cannot set all of
them to zero to make boundary/transition constraints vacuous. `last` is the
last row index, so the trace is nonempty by construction. -/
def rowEnv (rows : Nat → Nat → F) (public : Nat → F) (last i : Nat) : Env where
  main := fun offset column => rows (i+offset) column
  public := public
  first := if i=0 then 1 else 0
  last := if i=last then 1 else 0
  transition := if i<last then 1 else 0

def ValidTrace (rows : Nat → Nat → F) (public : Nat → F) (last : Nat) : Prop :=
  ∀ i ≤ last, satisfies (rowEnv rows public last i)

theorem actual_transition_integer_accounting (rows : Nat → Nat → F)
    (public : Nat → F) (last i : Nat) (valid : ValidTrace rows public last)
    (hi : i<last) :
    (rows (i+1) 5).val = (rows i 5).val + (rows (i+1) 4).val := by
  have current := valid i (by omega)
  have next := valid (i+1) (by omega)
  have equation := current ⟨60,by decide⟩
  change Enclave.EpochAirExtracted.c60 (rowEnv rows public last i)=0 at equation
  simp only [Enclave.EpochAirExtracted.c60, rowEnv, hi, ↓reduceIte, one_mul,
    Nat.add_zero] at equation
  exact field_addition_lifts _ _ _ (actual_used_range _ current)
    (actual_delta_range _ next) (sub_eq_zero.mp equation)

theorem actual_first_row_accounting (rows : Nat → Nat → F) (public : Nat → F)
    (last : Nat) (valid : ValidTrace rows public last) (inputRange : (public 2).val<16384) :
    (rows 0 5).val = (public 2).val + (rows 0 4).val := by
  have first := valid 0 (Nat.zero_le _)
  have equation := first ⟨55,by decide⟩
  change Enclave.EpochAirExtracted.c55 (rowEnv rows public last 0)=0 at equation
  simp only [Enclave.EpochAirExtracted.c55, rowEnv, ↓reduceIte, one_mul,
    Nat.zero_add] at equation
  exact field_addition_lifts _ _ _ inputRange (actual_delta_range _ first)
    (sub_eq_zero.mp equation)

theorem actual_trace_integer_sum (rows : Nat → Nat → F) (public : Nat → F)
    (last : Nat) (valid : ValidTrace rows public last) (inputRange : (public 2).val<16384)
    (i : Nat) (hi : i≤last) :
    (rows i 5).val = (public 2).val + ((List.range (i+1)).map (fun j => (rows j 4).val)).sum := by
  induction i with
  | zero => simpa using actual_first_row_accounting rows public last valid inputRange
  | succ i ih =>
    have step := actual_transition_integer_accounting rows public last i valid (by omega)
    rw [step, ih (by omega)]
    simp [List.range_succ, List.map_append, Enclave.Protocol.sum_append, Nat.add_assoc]

theorem actual_epoch_full_integer_accounting (rows : Nat → Nat → F) (public : Nat → F)
    (last : Nat) (valid : ValidTrace rows public last) (inputRange : (public 2).val<16384) :
    (public 3).val = (public 2).val +
      ((List.range (last+1)).map (fun j => (rows j 4).val)).sum ∧
    (public 3).val ≤ (public 1).val := by
  have endRow := valid last (Nat.le_refl _)
  have equation := endRow ⟨56,by decide⟩
  change Enclave.EpochAirExtracted.c56 (rowEnv rows public last last)=0 at equation
  simp only [Enclave.EpochAirExtracted.c56, rowEnv, ↓reduceIte, one_mul, Nat.add_zero] at equation
  have output : rows last 5=public 3 := sub_eq_zero.mp equation
  refine ⟨?_, ?_⟩
  · rw [← output]
    exact actual_trace_integer_sum rows public last valid inputRange last (Nat.le_refl _)
  · simpa [rowEnv, output] using actual_epoch_constraints_enforce_used_cap _ endRow

end Enclave.EpochAirCorrespondence

