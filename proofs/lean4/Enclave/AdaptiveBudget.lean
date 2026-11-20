import Enclave.AdaptiveQif

/-! Variable-arity adaptive query trees. Every observation may select a new
alphabet and kernel. Exact fractional charges bound every path, and transcript
cardinality and Bayes vulnerability are derived rather than assumed. -/
namespace Enclave.AdaptiveBudget
open scoped BigOperators

set_option maxRecDepth 3000
set_option exponentiation.threshold 12001

inductive Shape where
  | leaf
  | query (arity : Nat) (next : Fin arity → Shape)

def leaves : Shape → Nat
  | .leaf => 1
  | .query arity next => ∑ y : Fin arity, leaves (next y)

def priced : Shape → Nat → Prop
  | .leaf, _ => True
  | .query arity next, budget => Enclave.FractionalQif.price arity≤budget ∧
      ∀ y, priced (next y) (budget-Enclave.FractionalQif.price arity)

theorem adaptive_tree_fractional_power_bound (tree : Shape) (budget : Nat)
    (checked : priced tree budget) : leaves tree^1000≤2^budget := by
  induction tree generalizing budget with
  | leaf => simpa [leaves] using (Nat.one_le_pow budget 2 (by decide))
  | query arity next ih =>
    by_cases empty : arity=0
    · subst arity
      simp [leaves]
    · have nonempty : (Finset.univ : Finset (Fin arity)).Nonempty :=
        ⟨⟨0,by omega⟩,Finset.mem_univ _⟩
      obtain ⟨largest,_,largestEq⟩ := Finset.exists_mem_eq_sup Finset.univ nonempty
        (fun y => leaves (next y))
      have count : leaves (.query arity next) ≤ arity * leaves (next largest) := by
        calc
          _ ≤ ∑ _y : Fin arity, leaves (next largest) := by
            apply Finset.sum_le_sum
            intro y _
            rw [← largestEq]
            exact Finset.le_sup (f := fun y => leaves (next y)) (Finset.mem_univ y)
          _ = arity * leaves (next largest) := by simp
      calc
        _ ≤ (arity*leaves (next largest))^1000 := Nat.pow_le_pow_left count 1000
        _ = arity^1000 * leaves (next largest)^1000 := Nat.mul_pow _ _ _
        _ ≤ 2^(Enclave.FractionalQif.price arity) *
            2^(budget-Enclave.FractionalQif.price arity) :=
          Nat.mul_le_mul (Enclave.FractionalQif.exact_price_never_undercharges arity)
            (ih largest _ (checked.2 largest))
        _ = 2^budget := by rw [← Nat.pow_add, Nat.add_sub_of_le checked.1]

theorem adaptive_tree_has_at_most_4096_transcripts (tree : Shape)
    (checked : priced tree 12000) : leaves tree≤4096 := by
  apply (pow_le_pow_iff_left₀ (Nat.zero_le _) (Nat.zero_le _) (by decide : 1000≠0)).mp
  have h := adaptive_tree_fractional_power_bound tree 12000 checked
  have same : (4096:Nat)^1000=2^12000 := by change (2^12)^1000=2^12000; rw [← Nat.pow_mul]
  rwa [same]

inductive Strategy (n : Nat) where
  | done
  | query (arity : Nat) (kernel : Enclave.AdaptiveQif.Kernel n arity)
      (next : Fin arity → Strategy n)

def shape : Strategy n → Shape
  | .done => .leaf
  | .query arity _ next => .query arity (fun y => shape (next y))

def valid : Strategy n → Prop
  | .done => True
  | .query _ kernel next => Enclave.AdaptiveQif.normalizedKernel kernel ∧ ∀ y, valid (next y)

def posterior [NeZero n] : Strategy n → Enclave.AdaptiveQif.Weights n → ℚ
  | .done, p => Enclave.AdaptiveQif.vulnerability p
  | .query arity kernel next, p =>
    ∑ y : Fin arity, posterior (next y) (fun x => p x*kernel x y)

/-- Total joint probability of all terminal observations. Branches may have
different alphabets and depths; normalization is checked at every query. -/
def mass : Strategy n → Enclave.AdaptiveQif.Weights n → ℚ
  | .done, p => ∑ x, p x
  | .query arity kernel next, p =>
    ∑ y : Fin arity, mass (next y) (fun x => p x*kernel x y)

theorem variable_arity_channel_preserves_probability (strategy : Strategy n)
    (kernels : valid strategy) (p : Enclave.AdaptiveQif.Weights n) :
    mass strategy p = ∑ x, p x := by
  induction strategy generalizing p with
  | done => rfl
  | query arity kernel next ih =>
    simp only [mass]
    calc
      _ = ∑ y : Fin arity, ∑ x, p x*kernel x y :=
        Finset.sum_congr rfl (fun y _ => ih y (kernels.2 y) _)
      _ = ∑ x, ∑ y : Fin arity, p x*kernel x y := Finset.sum_comm
      _ = ∑ x, p x := by simp_rw [← Finset.mul_sum, kernels.1.2, mul_one]

theorem variable_arity_adaptive_bayes_bound [NeZero n] (strategy : Strategy n)
    (kernels : valid strategy) (p : Enclave.AdaptiveQif.Weights n) (prior : ∀ x, 0≤p x) :
    posterior strategy p≤(leaves (shape strategy):ℚ)*Enclave.AdaptiveQif.vulnerability p := by
  induction strategy generalizing p with
  | done => simp [posterior,shape,leaves]
  | query arity kernel next ih =>
    simp only [posterior,shape,leaves,Nat.cast_sum,Finset.sum_mul]
    apply Finset.sum_le_sum
    intro y _
    calc
      _ ≤ (leaves (shape (next y)):ℚ) * Enclave.AdaptiveQif.vulnerability (fun x => p x*kernel x y) :=
        ih y (kernels.2 y) _ (fun x => mul_nonneg (prior x) (kernels.1.1 x y))
      _ ≤ _ := mul_le_mul_of_nonneg_left
        (Enclave.AdaptiveQif.joint_vulnerability_bound p kernel prior kernels.1 y) (by positivity)

theorem adaptive_fractional_12000_budget_bayes_bound [NeZero n] (strategy : Strategy n)
    (kernels : valid strategy) (budget : priced (shape strategy) 12000)
    (p : Enclave.AdaptiveQif.Weights n) (prior : ∀ x, 0≤p x) :
    posterior strategy p≤4096*Enclave.AdaptiveQif.vulnerability p := by
  have count := adaptive_tree_has_at_most_4096_transcripts (shape strategy) budget
  have countRat : (leaves (shape strategy):ℚ)≤4096 := by exact_mod_cast count
  have index : Fin n := ⟨0,NeZero.pos n⟩
  have nonnegative : 0≤Enclave.AdaptiveQif.vulnerability p :=
    (prior index).trans (Finset.le_sup' _ (Finset.mem_univ index))
  exact (variable_arity_adaptive_bayes_bound strategy kernels p prior).trans
    (mul_le_mul_of_nonneg_right countRat nonnegative)

/-- An executable budget monitor. Refusal terminates with a public outcome;
the hidden variable is never consulted when choosing whether to query. -/
theorem priced_monotone (tree : Shape) (smaller larger : Nat)
    (moreBudget : smaller≤larger) (checked : priced tree smaller) : priced tree larger := by
  induction tree generalizing smaller larger with
  | leaf => trivial
  | query arity next ih =>
    refine ⟨checked.1.trans moreBudget,?_⟩
    intro y
    exact ih y _ _ (by omega) (checked.2 y)

def enforce : Strategy n → Nat → Strategy n
  | .done, _ => .done
  | .query arity kernel next, budget =>
    if Enclave.FractionalQif.price arity≤budget then
      .query arity kernel (fun y => enforce (next y) (budget-Enclave.FractionalQif.price arity))
    else .done

theorem enforced_strategy_preserves_normalized_kernels (strategy : Strategy n)
    (kernels : valid strategy) (budget : Nat) : valid (enforce strategy budget) := by
  induction strategy generalizing budget with
  | done => trivial
  | query arity kernel next ih =>
    unfold enforce
    split
    · exact ⟨kernels.1,fun y => ih y (kernels.2 y) _⟩
    · trivial

theorem enforced_strategy_is_priced_by_construction (strategy : Strategy n)
    (budget : Nat) : priced (shape (enforce strategy budget)) budget := by
  induction strategy generalizing budget with
  | done => trivial
  | query arity kernel next ih =>
    unfold enforce
    split
    · rename_i allowed
      exact ⟨allowed,fun y => ih y _⟩
    · trivial

theorem executable_monitor_enforces_adaptive_bayes_bound [NeZero n]
    (strategy : Strategy n) (kernels : valid strategy)
    (p : Enclave.AdaptiveQif.Weights n) (prior : ∀ x, 0≤p x) :
    posterior (enforce strategy 12000) p≤4096*Enclave.AdaptiveQif.vulnerability p :=
  adaptive_fractional_12000_budget_bayes_bound (enforce strategy 12000)
    (enforced_strategy_preserves_normalized_kernels strategy kernels 12000)
    (enforced_strategy_is_priced_by_construction strategy 12000) p prior

end Enclave.AdaptiveBudget
