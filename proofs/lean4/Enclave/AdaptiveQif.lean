import Mathlib.Data.Rat.Defs
import Mathlib.Data.Finset.Lattice.Fold
import Mathlib.Data.Rat.BigOperators
import Mathlib.Data.Rat.Cast.Order
import Mathlib.Data.Fintype.BigOperators
import Mathlib.Algebra.Order.BigOperators.Ring.Finset
import Mathlib.Tactic.Positivity
import Mathlib.Tactic.Ring
import Enclave.FractionalQif

/-! Normalized rational probability kernels, with a query strategy that may
depend on every previous observation. No leakage bound is a structure field. -/
namespace Enclave.AdaptiveQif
open scoped BigOperators

variable {n m : Nat} [NeZero n]

abbrev Weights (n : Nat) := Fin n → ℚ
abbrev Kernel (n m : Nat) := Fin n → Fin m → ℚ

def vulnerability (p : Weights n) : ℚ :=
  Finset.univ.sup' Finset.univ_nonempty p

def normalizedKernel (k : Kernel n m) : Prop :=
  (∀ x y, 0 ≤ k x y) ∧ (∀ x, ∑ y, k x y = 1)

omit [NeZero n] in
theorem kernel_entry_at_most_one (k : Kernel n m) (h : normalizedKernel k) (x : Fin n) (y : Fin m) :
    k x y ≤ 1 := by
  rw [← h.2 x]
  exact Finset.single_le_sum (fun z _ => h.1 x z) (Finset.mem_univ y)

theorem joint_vulnerability_bound (p : Weights n) (k : Kernel n m)
    (hp : ∀ x, 0 ≤ p x) (hk : normalizedKernel k) (y : Fin m) :
    vulnerability (fun x => p x * k x y) ≤ vulnerability p := by
  apply Finset.sup'_le
  intro x _
  calc
    p x * k x y ≤ p x * 1 := mul_le_mul_of_nonneg_left (kernel_entry_at_most_one k hk x y) (hp x)
    _ = p x := mul_one _
    _ ≤ vulnerability p := Finset.le_sup' _ (Finset.mem_univ x)

inductive Strategy (n m : Nat) : Nat → Type where
  | done : Strategy n m 0
  | query {depth : Nat} (kernel : Kernel n m)
      (next : Fin m → Strategy n m depth) : Strategy n m (depth+1)

def valid : Strategy n m depth → Prop
  | .done => True
  | .query k next => normalizedKernel k ∧ ∀ y, valid (next y)

def posterior : Strategy n m depth → Weights n → ℚ
  | .done, p => vulnerability p
  | .query k next, p => ∑ y, posterior (next y) (fun x => p x * k x y)

def mass : Strategy n m depth → Weights n → ℚ
  | .done, p => ∑ x, p x
  | .query k next, p => ∑ y, mass (next y) (fun x => p x * k x y)

omit [NeZero n] in
theorem adaptive_channel_preserves_probability (strategy : Strategy n m depth)
    (h : valid strategy) (p : Weights n) : mass strategy p = ∑ x, p x := by
  induction strategy generalizing p with
  | done => rfl
  | query k next ih =>
    simp only [mass]
    calc
      _ = ∑ y, ∑ x, p x * k x y := Finset.sum_congr rfl (fun y _ => ih y (h.2 y) _)
      _ = ∑ x, ∑ y, p x * k x y := Finset.sum_comm
      _ = ∑ x, p x := by simp_rw [← Finset.mul_sum, h.1.2, mul_one]

theorem adaptive_bayes_cardinality_bound (strategy : Strategy n m depth)
    (h : valid strategy) (p : Weights n) (hp : ∀ x, 0 ≤ p x) :
    posterior strategy p ≤ (m:ℚ)^depth * vulnerability p := by
  induction strategy generalizing p with
  | done => simp [posterior]
  | @query depth k next ih =>
    simp only [posterior]
    calc
      _ ≤ ∑ y : Fin m, (m:ℚ)^depth * vulnerability (fun x => p x*k x y) := by
        apply Finset.sum_le_sum
        intro y _
        exact ih y (h.2 y) _ (fun x => mul_nonneg (hp x) (h.1.1 x y))
      _ ≤ ∑ _y : Fin m, (m:ℚ)^depth * vulnerability p := by
        apply Finset.sum_le_sum
        intro y _
        exact mul_le_mul_of_nonneg_left (joint_vulnerability_bound p k hp h.1 y) (by positivity)
      _ = (m:ℚ)^(depth+1) * vulnerability p := by
        simp [pow_succ, mul_assoc, mul_comm, mul_left_comm]

theorem adaptive_fractional_budget_bayes_bound (strategy : Strategy n m depth)
    (h : valid strategy) (p : Weights n) (hp : ∀ x, 0≤p x)
    (budget : depth * Enclave.FractionalQif.price m≤12000) :
    posterior strategy p≤4096*vulnerability p := by
  have count := Enclave.FractionalQif.repeated_fractional_budget_implies_4096_bound m depth budget
  have countRat : (m:ℚ)^depth≤4096 := by exact_mod_cast count
  have index : Fin n := ⟨0,NeZero.pos n⟩
  have nonnegative : 0≤vulnerability p :=
    (hp index).trans (Finset.le_sup' _ (Finset.mem_univ index))
  exact (adaptive_bayes_cardinality_bound strategy h p hp).trans
    (mul_le_mul_of_nonneg_right countRat nonnegative)

end Enclave.AdaptiveQif
