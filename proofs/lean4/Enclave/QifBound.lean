/- A finite whole-bit charging specification. Every query exposes one symbol
from a power-of-two alphabet and is charged exactly its declared bit width.
This is not a model of adaptive queries, timing, the rolling clock or a SEP. -/
namespace Enclave

def QIF_CAP_MB : Nat := 12000
def MAX_OBSERVABLE_TRANSCRIPTS : Nat := 4096

def totalChargedBits : List Nat → Nat
  | [] => 0
  | bits :: rest => bits + totalChargedBits rest

def chargedMillibits (queries : List Nat) : Nat := 1000 * totalChargedBits queries

-- Enumerate actual possible output sequences; do not assume their cardinality.
def chargedTranscripts : List Nat → List (List Nat)
  | [] => [[]]
  | bits :: rest => (List.range (2 ^ bits)).flatMap
      (fun symbol => (chargedTranscripts rest).map (fun tail => symbol :: tail))

structure ValidChargedChannel (queries : List Nat) : Prop where
  budget_bounded : chargedMillibits queries ≤ QIF_CAP_MB

theorem prepend_choices_length (alphabet : List Nat) (tails : List (List Nat)) :
    (alphabet.flatMap (fun symbol => tails.map (fun tail => symbol :: tail))).length =
      alphabet.length * tails.length := by
  induction alphabet with
  | nil => simp
  | cons x xs ih => simp [List.flatMap_cons, ih, Nat.add_mul, Nat.add_comm]

/-- The cardinality claim is derived from the executable charging model. -/
theorem entropy_bounded (queries : List Nat) :
    (chargedTranscripts queries).length = 2 ^ totalChargedBits queries := by
  induction queries with
  | nil => rfl
  | cons bits rest ih =>
    simp only [chargedTranscripts, prepend_choices_length, List.length_range, totalChargedBits]
    rw [ih, Nat.pow_add]

theorem pow2_le_pow2 {a b : Nat} (h : a ≤ b) : 2 ^ a ≤ 2 ^ b := by
  exact Nat.pow_le_pow_right (by decide) h

theorem div1000_le_12 {c : Nat} (h : c ≤ QIF_CAP_MB) : c / 1000 ≤ 12 := by
  simp [QIF_CAP_MB] at h
  omega

theorem pow2_12_eq_4096 : 2 ^ 12 = 4096 := by rfl

/-- A complete transcript contains at most 4096 possibilities under this model's
whole-bit charging rule. No entropy or cardinality bound is a hypothesis. -/
theorem charged_finite_channel_cardinality_bound (queries : List Nat)
    (h : ValidChargedChannel queries) :
    (chargedTranscripts queries).length ≤ MAX_OBSERVABLE_TRANSCRIPTS := by
  have hc := h.budget_bounded
  simp only [chargedMillibits, QIF_CAP_MB] at hc
  have hb : totalChargedBits queries ≤ 12 := by omega
  rw [entropy_bounded]
  exact pow2_le_pow2 hb

-- This corollary concerns cardinality, not a measure-theoretic entropy theorem.
theorem charged_transcript_count_at_most_4096 (queries : List Nat)
    (h : ValidChargedChannel queries) : (chargedTranscripts queries).length ≤ 4096 :=
  charged_finite_channel_cardinality_bound queries h

end Enclave
