import Enclave.RollingQifRefinement

/-! Composition of lazy rolling settlement with adaptive, variable-arity
observations. The monitored interval is shorter than the expiry window. Every
query charges the entity under analysis before sampling its normalized kernel.
No lifetime leakage assertion is made after budget entries expire. -/
namespace Enclave.RollingAdaptiveComposition

open Enclave.RollingQif Enclave.RollingQifRefinement

def recent (b : Bucket) (start : Nat) : Bucket :=
  b.filter (fun entry => decide (start≤entry.1))

theorem used_filter_le (b : Bucket) (predicate : Nat × Nat → Bool) :
    used (b.filter predicate)≤used b := by
  induction b with
  | nil => exact Nat.le_refl 0
  | cons entry rest ih =>
    cases check : predicate entry <;>
      simp [List.filter_cons,check,used] at * <;> omega

theorem recent_survives_window_filter (b : Bucket) (start now : Nat)
    (inside : now<start+window) : recent (prune b now) start=recent b start := by
  unfold recent prune
  rw [List.filter_filter]
  apply List.filter_congr
  intro entry _
  by_cases later : start≤entry.1
  · have positive : 0<window := by decide
    have live : now-entry.1<window := by omega
    simp [later,live]
  · simp [later]

theorem prepared_recent_contents_unchanged (caps : Nat → Nat) (now amount start : Nat)
    (buckets : Buckets) (keys : List Nat) (ordered : Ordered buckets)
    (inside : now<start+window) (key : Nat) :
    recent ((prepare caps now amount buckets keys).1 key) start=recent (buckets key) start := by
  have observations := congrFun
    (prepare_changes_no_live_observation caps now amount buckets keys ordered) key
  have same := congrArg (fun bucket => recent bucket start) observations
  simpa only [observe,recent_survives_window_filter _ start now inside] using same

theorem recent_usage_is_part_of_live_usage (b : Bucket) (start now : Nat)
    (inside : now<start+window) : used (recent b start)≤used (prune b now) := by
  rw [← recent_survives_window_filter b start now inside]
  exact used_filter_le _ _

theorem native_acceptance_bounds_recent_charge (caps : Nat → Nat) (s : State)
    (request : Charge) (start key : Nat) (ordered : Ordered s.buckets)
    (inside : max s.highTime request.now<start+window)
    (selected : key ∈ request.keys) (accepted : (nativeCharge caps s request).2=true) :
    used (recent (s.buckets key) start)+request.amount≤caps key := by
  have checks := prepare_agrees_with_all_live_cap_checks caps
    (max s.highTime request.now) request.amount s.buckets request.keys ordered
  have checked : (prepare caps (max s.highTime request.now) request.amount
      s.buckets request.keys).2=true := by
    unfold nativeCharge at accepted
    dsimp only at accepted
    split at accepted
    · assumption
    · contradiction
  rw [checks] at checked
  have allowed := List.all_eq_true.mp checked key selected
  simp only [decide_eq_true_eq] at allowed
  have lower := recent_usage_is_part_of_live_usage (s.buckets key)
    start (max s.highTime request.now) inside
  omega

theorem accepted_charge_increments_recent_usage (caps : Nat → Nat) (s : State)
    (request : Charge) (start key : Nat) (ordered : Ordered s.buckets)
    (inside : max s.highTime request.now<start+window)
    (afterStart : start≤max s.highTime request.now)
    (selected : key ∈ request.keys) (accepted : (nativeCharge caps s request).2=true) :
    used (recent ((nativeCharge caps s request).1.buckets key) start)=
      used (recent (s.buckets key) start)+request.amount := by
  have same := prepared_recent_contents_unchanged caps (max s.highTime request.now)
    request.amount start s.buckets request.keys ordered inside key
  unfold nativeCharge
  dsimp only
  split
  · simp [debit,selected,recent,List.filter_append,afterStart,used,
      Enclave.Protocol.sum_append] at *
    exact congrArg used same
  · unfold nativeCharge at accepted
    dsimp only at accepted
    split at accepted
    · contradiction
    · contradiction

inductive Program (n : Nat) where
  | done
  | query (arity : Nat) (kernel : Enclave.AdaptiveQif.Kernel n arity)
      (now : Nat) (keys : List Nat) (next : Fin arity → Program n)

def valid : Program n → Prop
  | .done => True
  | .query _ kernel _ _ next =>
    Enclave.AdaptiveQif.normalizedKernel kernel ∧ ∀ y, valid (next y)

/-- The guard checks only public scheduling/provenance and settlement state.
An observation kernel is reached only after a successful native debit. -/
def execute (caps : Nat → Nat) (start finish key : Nat) :
    Program n → State → Enclave.AdaptiveBudget.Strategy n
  | .done, _ => .done
  | .query arity kernel now keys next, s =>
    if start≤max s.highTime now ∧ max s.highTime now≤finish ∧ key∈keys then
      let charged := nativeCharge caps s ⟨keys,Enclave.FractionalQif.price arity,now⟩
      if charged.2 then
        .query arity kernel (fun y => execute caps start finish key (next y) charged.1)
      else .done
    else .done

theorem execution_preserves_normalized_kernels (caps : Nat → Nat)
    (start finish key : Nat) (program : Program n) (kernels : valid program)
    (s : State) : Enclave.AdaptiveBudget.valid (execute caps start finish key program s) := by
  induction program generalizing s with
  | done => trivial
  | query arity kernel now keys next ih =>
    unfold execute
    split
    · dsimp only
      split
      · exact ⟨kernels.1,fun y => ih y (kernels.2 y) _⟩
      · trivial
    · trivial

theorem execution_is_priced_by_actual_rolling_charges (caps : Nat → Nat)
    (start finish key : Nat) (inside : finish<start+window)
    (program : Program n) (s : State) (validState : WellFormed s) :
    Enclave.AdaptiveBudget.priced
      (Enclave.AdaptiveBudget.shape (execute caps start finish key program s))
      (caps key-used (recent (s.buckets key) start)) := by
  induction program generalizing s with
  | done => trivial
  | query arity kernel now keys next ih =>
    unfold execute
    split
    · rename_i publicChecks
      dsimp only
      split
      · rename_i accepted
        have within : max s.highTime now<start+window :=
          publicChecks.2.1.trans_lt inside
        have payment := native_acceptance_bounds_recent_charge caps s
          ⟨keys,Enclave.FractionalQif.price arity,now⟩ start key validState.1
          within publicChecks.2.2 accepted
        have increment := accepted_charge_increments_recent_usage caps s
          ⟨keys,Enclave.FractionalQif.price arity,now⟩ start key validState.1
          within publicChecks.1 publicChecks.2.2 accepted
        dsimp only at payment increment
        refine ⟨by omega,?_⟩
        intro y
        have tail := ih y (nativeCharge caps s
          ⟨keys,Enclave.FractionalQif.price arity,now⟩).1
          (native_charge_preserves_well_formedness caps s _ validState)
        simpa only [increment,Nat.sub_sub] using tail
      · trivial
    · trivial

theorem rolling_settlement_enforces_adaptive_bayes_bound [NeZero n]
    (caps : Nat → Nat) (start finish key : Nat) (inside : finish<start+window)
    (capBound : caps key≤12000) (program : Program n) (kernels : valid program)
    (s : State) (validState : WellFormed s)
    (prior : Enclave.AdaptiveQif.Weights n) (nonnegative : ∀ x, 0≤prior x) :
    Enclave.AdaptiveBudget.posterior (execute caps start finish key program s) prior≤
      4096*Enclave.AdaptiveQif.vulnerability prior := by
  have priced := execution_is_priced_by_actual_rolling_charges caps start finish key
    inside program s validState
  have budget := Enclave.AdaptiveBudget.priced_monotone _ _ 12000
    ((Nat.sub_le _ _).trans capBound) priced
  exact Enclave.AdaptiveBudget.adaptive_fractional_12000_budget_bayes_bound _
    (execution_preserves_normalized_kernels caps start finish key program kernels s)
    budget prior nonnegative

end Enclave.RollingAdaptiveComposition
