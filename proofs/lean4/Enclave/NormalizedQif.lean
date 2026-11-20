import Enclave.ProtocolTrace

/-! Exact finite probabilities use integer numerators and an explicitly positive
common denominator. Normalization is checked, not assumed leakage bounds. -/
namespace Enclave.NormalizedQif

def maximum : List Nat → Nat := List.foldr max 0

theorem member_le_maximum (xs : List Nat) (x : Nat) (h : x ∈ xs) : x ≤ maximum xs := by
  induction xs with
  | nil => contradiction
  | cons a xs ih =>
    simp only [List.mem_cons] at h
    rcases h with rfl | h
    · exact Nat.le_max_left _ _
    · exact Nat.le_trans (ih h) (Nat.le_max_right _ _)

theorem maximum_le (xs : List Nat) (b : Nat) (h : ∀ x ∈ xs, x ≤ b) : maximum xs ≤ b := by
  induction xs with
  | nil => exact Nat.zero_le _
  | cons a xs ih =>
    apply Nat.max_le.mpr
    exact ⟨h _ (by simp), ih (fun x hx => h x (by simp [hx]))⟩

theorem member_le_sum (xs : List Nat) (x : Nat) (h : x ∈ xs) : x ≤ xs.sum := by
  induction xs with
  | nil => contradiction
  | cons a xs ih =>
    simp only [List.mem_cons] at h
    rcases h with rfl | h
    · simp only [List.sum_cons]; omega
    · have := ih h; simp only [List.sum_cons]; omega

theorem sum_le_count_mul (xs : List Nat) (b : Nat) (h : ∀ x ∈ xs, x ≤ b) :
    xs.sum ≤ xs.length * b := by
  induction xs with
  | nil => simp
  | cons a xs ih =>
    have ha := h a (by simp)
    have ht := ih (fun x hx => h x (by simp [hx]))
    simp only [List.sum_cons, List.length_cons, Nat.succ_mul]
    omega

structure Distribution where
  weights : List Nat
  denominator : Nat
  deriving DecidableEq, Repr

def normalized (p : Distribution) : Bool := decide (0 < p.denominator ∧ p.weights.sum = p.denominator)

theorem normalized_weight_is_probability (p : Distribution) (h : normalized p = true)
    (w : Nat) (hw : w ∈ p.weights) : 0 < p.denominator ∧ w ≤ p.denominator := by
  have hp : 0 < p.denominator ∧ p.weights.sum = p.denominator := of_decide_eq_true h
  exact ⟨hp.1, hp.2 ▸ member_le_sum p.weights w hw⟩

/-- A column of joint weights: prior numerator times channel numerator. -/
def jointColumn (prior likelihood : List Nat) : List Nat :=
  (prior.zip likelihood).map (fun p => p.1 * p.2)

theorem column_vulnerability_bound (prior likelihood : List Nat) (denom : Nat)
    (hk : ∀ w ∈ likelihood, w ≤ denom) :
    maximum (jointColumn prior likelihood) ≤ maximum prior * denom := by
  apply maximum_le
  intro x hx
  obtain ⟨⟨p,k⟩, hm, rfl⟩ := List.mem_map.mp hx
  have hp : p ∈ prior := (List.of_mem_zip hm).1
  have hl : k ∈ likelihood := (List.of_mem_zip hm).2
  exact Nat.mul_le_mul (member_le_maximum prior p hp) (hk k hl)

/-- Multiplying by denominator turns posterior Bayes vulnerability into this
integer sum. Division is unnecessary for an exact cross-multiplied bound. -/
def posteriorNumerator (prior : List Nat) (columns : List (List Nat)) : Nat :=
  (columns.map (fun c => maximum (jointColumn prior c))).sum

theorem channel_bayes_bound (prior : List Nat) (columns : List (List Nat)) (denom : Nat)
    (hk : ∀ c ∈ columns, ∀ w ∈ c, w ≤ denom) :
    posteriorNumerator prior columns ≤ columns.length * (maximum prior * denom) := by
  have bound : ∀ w ∈ columns.map (fun c => maximum (jointColumn prior c)),
      w ≤ maximum prior * denom := by
    intro w hw
    obtain ⟨c, hc, rfl⟩ := List.mem_map.mp hw
    exact column_vulnerability_bound prior c denom (hk c hc)
  simpa only [posteriorNumerator, List.length_map] using
    sum_le_count_mul _ (maximum prior * denom) bound

end Enclave.NormalizedQif
