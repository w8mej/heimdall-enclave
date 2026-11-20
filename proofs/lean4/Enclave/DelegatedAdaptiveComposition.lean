import Enclave.DelegationAccounting
import Enclave.AdaptiveBudget

/-! Adaptive observations charged to a delegation tree. The monitor executes
the accounting transition before exposing a kernel and derives its pricing
invariant from remaining balances, not from an assumed transcript bound.
Minting new roots is outside a single grant's disclosure bound. -/
namespace Enclave.DelegatedAdaptiveComposition

open Enclave.DelegationAccounting

def scopedResidual (root : Nat) (node : Node) : Nat :=
  if node.root=root then residual node else 0

def remaining (root : Nat) (s : State) : Nat := (s.nodes.map (scopedResidual root)).sum

theorem accepted_call_decreases_tree_balance (s t : State) (root : Nat)
    (before after : List Node) (node : Node) (amount : Nat)
    (sameRoot : node.root=root)
    (accepted : step s (.call before after node amount)=some t) :
    amount≤remaining root s ∧ remaining root t=remaining root s-amount := by
  simp only [step] at accepted
  split at accepted
  · rename_i guards
    cases accepted
    unfold remaining
    rw [guards.1]
    simp only [remaining,List.map_append,List.map_cons,Enclave.Protocol.sum_append,List.sum_cons,
      scopedResidual,sameRoot,↓reduceIte]
    have payment := guards.2.1
    unfold residual at *
    dsimp only at *
    omega
  · contradiction

theorem accepted_spawn_preserves_tree_balance (s t : State) (root : Nat)
    (before after : List Node) (parent : Node) (child amount : Nat) (attenuated : Bool)
    (accepted : step s (.spawn before after parent child amount attenuated)=some t) :
    remaining root t=remaining root s := by
  simp only [step] at accepted
  split at accepted
  · rename_i guards
    cases accepted
    unfold remaining
    rw [guards.1]
    simp only [remaining,List.map_append,List.map_cons,Enclave.Protocol.sum_append,List.sum_cons]
    by_cases same : parent.root=root
    · simp only [scopedResidual,same,↓reduceIte]
      have payment := guards.2.2.2.1
      unfold residual at *
      dsimp only at *
      omega
    · simp [scopedResidual,same]
  · contradiction

inductive Program (n : Nat) where
  | done
  | spawn (before after : List Node) (parent : Node) (child amount : Nat)
      (attenuated : Bool) (next : Program n)
  | query (arity : Nat) (kernel : Enclave.AdaptiveQif.Kernel n arity)
      (before after : List Node) (node : Node) (next : Fin arity → Program n)

def valid : Program n → Prop
  | .done => True
  | .spawn _ _ _ _ _ _ next => valid next
  | .query _ kernel _ _ _ next =>
    Enclave.AdaptiveQif.normalizedKernel kernel ∧ ∀ y, valid (next y)

def execute (root : Nat) : Program n → State → Enclave.AdaptiveBudget.Strategy n
  | .done, _ => .done
  | .spawn before after parent child amount attenuated next, s =>
    execute root next ((step s (.spawn before after parent child amount attenuated)).getD s)
  | .query arity kernel before after node next, s =>
    if node.root=root then
      match step s (.call before after node (Enclave.FractionalQif.price arity)) with
      | none => .done
      | some paid => .query arity kernel (fun y => execute root (next y) paid)
    else .done

theorem execution_preserves_normalization (root : Nat) (program : Program n)
    (kernels : valid program) (s : State) :
    Enclave.AdaptiveBudget.valid (execute root program s) := by
  induction program generalizing s with
  | done => trivial
  | spawn before after parent child amount attenuated next ih =>
    exact ih kernels _
  | query arity kernel before after node next ih =>
    unfold execute
    split
    · split
      · trivial
      · exact ⟨kernels.1,fun y => ih y (kernels.2 y) _⟩
    · trivial

theorem execution_is_priced_by_reserved_tree_balances (root : Nat) (program : Program n)
    (s : State) :
    Enclave.AdaptiveBudget.priced (Enclave.AdaptiveBudget.shape (execute root program s))
      (remaining root s) := by
  induction program generalizing s with
  | done => trivial
  | spawn before after parent child amount attenuated next ih =>
    unfold execute
    cases result : step s (.spawn before after parent child amount attenuated) with
    | none => simpa using ih s
    | some paid =>
      have same := accepted_spawn_preserves_tree_balance s paid root before after parent
        child amount attenuated result
      simpa only [Option.getD_some,same] using ih paid
  | query arity kernel before after node next ih =>
    unfold execute
    split
    · rename_i sameRoot
      split
      · trivial
      · rename_i paid result
        have payment := accepted_call_decreases_tree_balance s paid root before after node
          (Enclave.FractionalQif.price arity) sameRoot result
        refine ⟨payment.1,?_⟩
        intro y
        simpa only [payment.2] using ih y paid
    · trivial

theorem delegation_settlement_enforces_adaptive_bayes_bound [NeZero n]
    (root : Nat) (program : Program n) (kernels : valid program) (s : State)
    (grantBound : remaining root s≤12000)
    (prior : Enclave.AdaptiveQif.Weights n) (nonnegative : ∀ x, 0≤prior x) :
    Enclave.AdaptiveBudget.posterior (execute root program s) prior≤
      4096*Enclave.AdaptiveQif.vulnerability prior :=
  Enclave.AdaptiveBudget.adaptive_fractional_12000_budget_bayes_bound _
    (execution_preserves_normalization root program kernels s)
    (Enclave.AdaptiveBudget.priced_monotone _ _ _ grantBound
      (execution_is_priced_by_reserved_tree_balances root program s)) prior nonnegative

end Enclave.DelegatedAdaptiveComposition
