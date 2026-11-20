import Mathlib.Data.Nat.Log
import Mathlib.Algebra.BigOperators.Group.List
import Mathlib.Algebra.Order.Ring.Nat
import Enclave.ProtocolTrace

/-! Exact millibit pricing. `k^1000 ≤ 2^charge` is the integer form of
`1000 log₂(k) ≤ charge`, so no floating-point or real-log oracle is trusted. -/
namespace Enclave.FractionalQif

set_option maxRecDepth 3000
set_option exponentiation.threshold 12001

def price (k : Nat) : Nat := if k≤1 then 0 else (k^1000-1).log2+1

theorem exact_price_never_undercharges (k : Nat) : k^1000≤2^(price k) := by
  unfold price
  split
  · rename_i small
    have cases : k=0 ∨ k=1 := by omega
    rcases cases with rfl | rfl <;> simp
  · rename_i large
    have positive : 0<k^1000 := Nat.pow_pos (by omega)
    have bound := Nat.lt_pow_succ_log_self (by decide : 1<2) (k^1000-1)
    rw [← Nat.log2_eq_log_two] at bound
    omega

theorem exact_price_is_minimal (k charge : Nat) (safe : k^1000≤2^charge) :
    price k≤charge := by
  unfold price
  split
  · exact Nat.zero_le _
  · rename_i large
    have two : 2≤k^1000 := by
      exact Nat.le_trans (by omega : 2≤k) (Nat.le_self_pow (by decide) k)
    have smaller : k^1000-1<2^charge := by omega
    have positive : k^1000-1 ≠ 0 := by omega
    have logBound := (Nat.lt_pow_iff_log_lt (by decide : 1<2) positive).mp smaller
    rw [← Nat.log2_eq_log_two] at logBound
    omega

theorem exact_price_equals_ceiling_log (k : Nat) : price k=Nat.clog 2 (k^1000) := by
  apply Nat.le_antisymm
  · exact exact_price_is_minimal k _ (Nat.le_pow_clog (by decide) _)
  · exact (Nat.le_pow_iff_clog_le (by decide)).mp (exact_price_never_undercharges k)

theorem power_of_two_exact_charge (bits : Nat) : price (2^bits)=1000*bits := by
  rw [exact_price_equals_ceiling_log, ← Nat.pow_mul, Nat.clog_pow 2 _ (by decide)]
  exact Nat.mul_comm _ _

theorem composed_fractional_cardinality (arities : List Nat) :
    arities.prod^1000 ≤ 2^((arities.map price).sum) := by
  induction arities with
  | nil => simp
  | cons k ks ih =>
    simp only [List.prod_cons, List.map_cons, List.sum_cons, Nat.mul_pow, Nat.pow_add]
    exact Nat.mul_le_mul (exact_price_never_undercharges k) ih

theorem fractional_budget_implies_4096_bound (arities : List Nat)
    (budget : (arities.map price).sum≤12000) : arities.prod≤4096 := by
  apply (pow_le_pow_iff_left₀ (Nat.zero_le _) (Nat.zero_le _) (by decide : 1000≠0)).mp
  calc
    arities.prod^1000 ≤ 2^((arities.map price).sum) := composed_fractional_cardinality arities
    _ ≤ 2^12000 := Nat.pow_le_pow_right (by decide) budget
    _ = 4096^1000 := by change 2^12000=(2^12)^1000; rw [← Nat.pow_mul]

theorem repeated_fractional_budget_implies_4096_bound (arity depth : Nat)
    (budget : depth*price arity≤12000) : arity^depth≤4096 := by
  have h := fractional_budget_implies_4096_bound (List.replicate depth arity)
  simpa using h (by simpa using budget)

end Enclave.FractionalQif
