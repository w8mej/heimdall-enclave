import Enclave.ProtocolTrace

/-! The production accounting fields: granted budget, delegated reservations,
cumulative spent budget, stable token identity and a root-shared call counter.
List contexts represent a selected HashMap entry; every operation checks that
the context describes the current map. Failed attenuation never reserves a
slice. No validity or conservation proposition is stored in a state field. -/
namespace Enclave.DelegationAccounting

structure Node where
  id : Nat
  root : Nat
  depth : Nat
  budget : Nat
  delegated : Nat
  spent : Nat
  deriving DecidableEq, Repr

def residual (node : Node) : Nat := node.budget-node.delegated-node.spent
def funded (node : Node) : Nat := node.budget-node.delegated
def nodeSafe (node : Node) : Prop := node.delegated+node.spent≤node.budget ∧ node.depth≤4
def total (nodes : List Node) : Nat := (nodes.map funded).sum

structure State where
  nodes : List Node
  calls : Nat → Nat
  minted : Nat

inductive Event where
  | mint (id budget : Nat)
  | spawn (before after : List Node) (parent : Node) (childId amount : Nat)
      (attenuationSucceeded : Bool)
  | call (before after : List Node) (node : Node) (amount : Nat)
  deriving DecidableEq, Repr

def step (s : State) : Event → Option State
  | .mint id budget =>
    if s.nodes.any (fun node => node.id==id) then none else
      some ⟨⟨id,id,0,budget,0,0⟩::s.nodes,s.calls,s.minted+budget⟩
  | .spawn before after parent childId amount attenuationSucceeded =>
    if s.nodes=before++parent::after ∧
        ¬s.nodes.any (fun node => node.id==childId) ∧
        parent.depth<4 ∧ amount≤residual parent ∧ attenuationSucceeded=true then
      some ⟨before++{parent with delegated:=parent.delegated+amount}::
        ⟨childId,parent.root,parent.depth+1,amount,0,0⟩::after,s.calls,s.minted⟩
    else none
  | .call before after node amount =>
    if s.nodes=before++node::after ∧ amount≤residual node ∧ s.calls node.root<64 then
      some ⟨before++{node with spent:=node.spent+amount}::after,
        (fun root => if root=node.root then s.calls root+1 else s.calls root),s.minted⟩
    else none

def Safe (s : State) : Prop :=
  (∀ node ∈ s.nodes, nodeSafe node) ∧ (∀ root, s.calls root≤64) ∧ total s.nodes=s.minted

theorem residual_and_spent_account_for_funded_budget (node : Node) (safe : nodeSafe node) :
    residual node+node.spent=funded node := by
  unfold residual funded
  have budget := safe.1
  omega

theorem accepted_spawn_preserves_total (s t : State) (before after : List Node)
    (parent : Node) (child amount : Nat) (attenuated : Bool)
    (nodesSafe : ∀ node ∈ s.nodes, nodeSafe node)
    (accepted : step s (.spawn before after parent child amount attenuated)=some t) :
    total t.nodes=total s.nodes := by
  simp only [step] at accepted
  split at accepted
  · rename_i guards
    have parentSafe := nodesSafe parent (by rw [guards.1]; simp)
    cases accepted
    rw [guards.1]
    simp only [total,List.map_append,List.map_cons,Enclave.Protocol.sum_append,List.sum_cons]
    unfold funded residual at *
    have allocation := guards.2.2.2.1
    have budget := parentSafe.1
    dsimp only at *
    omega
  · contradiction

theorem step_preserves_node_limits (s t : State) (event : Event)
    (nodesSafe : ∀ node ∈ s.nodes, nodeSafe node)
    (accepted : step s event=some t) : ∀ node ∈ t.nodes, nodeSafe node := by
  cases event with
  | mint id budget =>
    simp only [step] at accepted
    split at accepted
    · contradiction
    · cases accepted
      intro node member
      rcases List.mem_cons.mp member with rfl | old
      · simp [nodeSafe]
      · exact nodesSafe node old
  | spawn before after parent child amount attenuated =>
    simp only [step] at accepted
    split at accepted
    · rename_i guards
      have original := nodesSafe parent (by rw [guards.1]; simp)
      cases accepted
      intro node member
      simp only [List.mem_append,List.mem_cons] at member
      rcases member with left | rfl | rfl | right
      · exact nodesSafe node (by rw [guards.1]; simp [left])
      · have budget := original.1
        have amountBound := guards.2.2.2.1
        simp only [nodeSafe,residual] at *
        omega
      · have depth := guards.2.2.1
        simp only [nodeSafe]
        omega
      · exact nodesSafe node (by rw [guards.1]; simp [right])
    · contradiction
  | call before after chosen amount =>
    simp only [step] at accepted
    split at accepted
    · rename_i guards
      have original := nodesSafe chosen (by rw [guards.1]; simp)
      cases accepted
      intro node member
      simp only [List.mem_append,List.mem_cons] at member
      rcases member with left | rfl | right
      · exact nodesSafe node (by rw [guards.1]; simp [left])
      · have budget := original.1
        have amountBound := guards.2.1
        simp only [nodeSafe,residual] at *
        omega
      · exact nodesSafe node (by rw [guards.1]; simp [right])
    · contradiction

theorem step_preserves_safe_accounting (s t : State) (event : Event)
    (safe : Safe s) (accepted : step s event=some t) : Safe t := by
  refine ⟨step_preserves_node_limits s t event safe.1 accepted,?_,?_⟩
  · cases event with
    | mint id budget =>
      simp only [step] at accepted
      split at accepted
      · contradiction
      · cases accepted; exact safe.2.1
    | spawn before after parent child amount attenuated =>
      simp only [step] at accepted
      split at accepted
      · cases accepted; exact safe.2.1
      · contradiction
    | call before after node amount =>
      simp only [step] at accepted
      split at accepted
      · rename_i guards
        cases accepted
        intro root
        dsimp only
        split
        · rename_i same
          rw [same]
          have bound := guards.2.2
          omega
        · exact safe.2.1 root
      · contradiction
  · cases event with
    | mint id budget =>
      simp only [step] at accepted
      split at accepted
      · contradiction
      · cases accepted
        simpa [total,funded,Nat.add_comm] using congrArg (fun n => budget+n) safe.2.2
    | spawn before after parent child amount attenuated =>
      have totalEq := accepted_spawn_preserves_total s t before after parent child amount
        attenuated safe.1 accepted
      have mintEq : t.minted=s.minted := by
        simp only [step] at accepted
        split at accepted
        · cases accepted; rfl
        · contradiction
      exact totalEq.trans (safe.2.2.trans mintEq.symm)
    | call before after node amount =>
      simp only [step] at accepted
      split at accepted
      · rename_i guards
        cases accepted
        have old := safe.2.2
        rw [guards.1] at old
        simpa [total,funded] using old
      · contradiction

theorem arbitrary_accounting_history_safe (events : List Event) :
    Safe (Enclave.Protocol.run step ⟨[],fun _ => 0,0⟩ events) :=
  Enclave.Protocol.run_invariant step Safe
    (fun s event t hs ht => step_preserves_safe_accounting s t event hs ht)
    ⟨[],fun _ => 0,0⟩ events (by simp [Safe,total])

theorem cumulative_spent_does_not_exceed_minted_grants (events : List Event) :
    let final := Enclave.Protocol.run step ⟨[],fun _ => 0,0⟩ events
    (final.nodes.map Node.spent).sum≤final.minted := by
  have safe := arbitrary_accounting_history_safe events
  dsimp only
  rw [← safe.2.2]
  have sumBound (nodes : List Node) (limits : ∀ node ∈ nodes, nodeSafe node) :
      (nodes.map Node.spent).sum≤total nodes := by
    induction nodes with
    | nil => exact Nat.le_refl 0
    | cons node rest ih =>
      have bound := residual_and_spent_account_for_funded_budget node (limits node (by simp))
      have tail := ih (fun x hx => limits x (by simp [hx]))
      simp only [total,List.map_cons,List.sum_cons] at *
      omega
  exact sumBound _ safe.1

def scopedFunded (root : Nat) (node : Node) : Nat :=
  if node.root=root then funded node else 0

def scopedSpent (root : Nat) (node : Node) : Nat :=
  if node.root=root then node.spent else 0

def mintedFor (root : Nat) : Event → Nat
  | .mint id budget => if id=root then budget else 0
  | _ => 0

theorem accepted_step_preserves_each_root_funding (s t : State) (event : Event)
    (safe : Safe s) (accepted : step s event=some t) (root : Nat) :
    (t.nodes.map (scopedFunded root)).sum=
      (s.nodes.map (scopedFunded root)).sum+mintedFor root event := by
  cases event with
  | mint id budget =>
    simp only [step] at accepted
    split at accepted
    · contradiction
    · cases accepted
      simp [scopedFunded,funded,mintedFor,Nat.add_comm]
  | spawn before after parent child amount attenuated =>
    simp only [step] at accepted
    split at accepted
    · rename_i guards
      have original := safe.1 parent (by rw [guards.1]; simp)
      cases accepted
      rw [guards.1]
      simp only [List.map_append,List.map_cons,Enclave.Protocol.sum_append,List.sum_cons,
        mintedFor,Nat.add_zero]
      by_cases same : parent.root=root
      · simp only [scopedFunded,same,↓reduceIte,funded]
        have budget := original.1
        have amountBound := guards.2.2.2.1
        simp only [residual] at amountBound
        omega
      · simp [scopedFunded,same]
    · contradiction
  | call before after node amount =>
    simp only [step] at accepted
    split at accepted
    · rename_i guards
      cases accepted
      rw [guards.1]
      simp [scopedFunded,funded,mintedFor]
    · contradiction

/-- Grants are counted only when minting actually succeeds. Duplicate-ID or
otherwise rejected requests cannot inflate the conservation bound. -/
def successfulGrants (root : Nat) : State → List Event → Nat
  | _, [] => 0
  | s, event::rest => match step s event with
    | none => successfulGrants root s rest
    | some t => mintedFor root event+successfulGrants root t rest

theorem arbitrary_history_conserves_each_root (s : State) (events : List Event)
    (safe : Safe s) (root : Nat) :
    ((Enclave.Protocol.run step s events).nodes.map (scopedFunded root)).sum=
      (s.nodes.map (scopedFunded root)).sum+successfulGrants root s events := by
  induction events generalizing s with
  | nil => simp [Enclave.Protocol.run,successfulGrants]
  | cons event rest ih =>
    cases result : step s event with
    | none => simpa [Enclave.Protocol.run,successfulGrants,result] using ih s safe
    | some t =>
      have tail := ih t (step_preserves_safe_accounting s t event safe result)
      have change := accepted_step_preserves_each_root_funding s t event safe result root
      simpa [Enclave.Protocol.run,successfulGrants,result,change,Nat.add_assoc] using tail

theorem cumulative_spent_of_each_tree_is_bounded (events : List Event) (root : Nat) :
    ((Enclave.Protocol.run step ⟨[],fun _ => 0,0⟩ events).nodes.map (scopedSpent root)).sum≤
      successfulGrants root ⟨[],fun _ => 0,0⟩ events := by
  have conservation := arbitrary_history_conserves_each_root
    ⟨[],fun _ => 0,0⟩ events (by simp [Safe,total]) root
  simp only [List.map_nil,List.sum_nil,Nat.zero_add] at conservation
  rw [← conservation]
  have safe := arbitrary_accounting_history_safe events
  have bound (nodes : List Node) (safeNodes : ∀ node ∈ nodes, nodeSafe node) :
      (nodes.map (scopedSpent root)).sum≤(nodes.map (scopedFunded root)).sum := by
    induction nodes with
    | nil => exact Nat.le_refl 0
    | cons node rest ih =>
      have nodeBalance := residual_and_spent_account_for_funded_budget node (safeNodes node (by simp))
      have tail := ih (fun x hx => safeNodes x (by simp [hx]))
      simp only [List.map_cons,List.sum_cons]
      by_cases same : node.root=root
      · simp only [scopedSpent,scopedFunded,same,↓reduceIte]
        omega
      · simpa [scopedSpent,scopedFunded,same] using tail
  exact bound _ safe.1

end Enclave.DelegationAccounting
