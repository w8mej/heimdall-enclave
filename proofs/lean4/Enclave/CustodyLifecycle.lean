import Enclave.CustodyProtocol

/-! Semantic counterpart of factors.rs and lease.rs. Factor ranks follow the
Rust declaration order; profile/action ranks are 1-based. Hardware signatures,
UI behavior and durable anti-replay are separate trust boundaries. -/
namespace Enclave.CustodyLifecycle

def factors (profile action : Nat) (rootMutation : Bool) : List Nat :=
  (List.range 8).filter (fun f => decide (
    f=0 ∨ (f=1 ∧ 2≤action) ∨ (f=2 ∧ 3≤action ∧ 2≤profile) ∨
    (f=3 ∧ 3≤action ∧ 3≤profile) ∨ (f=4 ∧ 3≤action ∧ 3≤profile) ∨
    (f=5 ∧ action=4 ∧ rootMutation=true ∧ 2≤profile) ∨
    (f=6 ∧ action=4 ∧ profile=1) ∨ (f=7 ∧ 3≤profile)))

theorem hardware_profiles_nested (action factor : Nat) (root : Bool)
    (member : factor ∈ factors 2 action root) : factor ∈ factors 3 action root := by
  simp only [factors, List.mem_filter, List.mem_range, decide_eq_true_eq] at member ⊢
  rcases member with ⟨range, requirement⟩
  refine ⟨range, ?_⟩
  rcases requirement with h | h | h | h | h | h | h | h
  all_goals simp_all

/-- The release wrapper computes the required matrix; an untrusted request
cannot substitute an empty list of required factors. -/
def release (verify : Enclave.CustodyProtocol.Evidence → Bool)
    (s : Enclave.CustodyProtocol.State) (profile action : Nat) (root : Bool)
    (request : Enclave.CustodyProtocol.Intent) (now : Nat) :=
  if request.required = factors profile action root then
    Enclave.CustodyProtocol.step verify s (.release request now) else none

theorem release_obeys_factor_matrix (verify : Enclave.CustodyProtocol.Evidence → Bool)
    (s t : Enclave.CustodyProtocol.State) (profile action : Nat) (root : Bool)
    (request : Enclave.CustodyProtocol.Intent) (now : Nat)
    (ok : release verify s profile action root request now = some t) :
    ∀ f ∈ factors profile action root, ∃ evidence ∈ s.approvals,
      evidence.factor=f ∧ evidence.intent=request ∧ verify evidence=true := by
  unfold release at ok
  split at ok
  · rename_i matrix
    have allFactors := (Enclave.CustodyProtocol.release_has_bound_verified_factors
      verify s t request now ok).2.2
    simpa only [matrix] using allFactors
  · contradiction

structure LeaseKey where
  caller : Nat
  targetNamespace : Nat
  tokenRoot : List Nat
  deriving DecidableEq, Repr

structure Lease where
  key : LeaseKey
  granted : Nat
  expires : Nat
  deriving DecidableEq, Repr

def duration : Nat := 900000000000
def machineMax : Nat := 18446744073709551615

def grant (leases : List Lease) (key : LeaseKey) (now : Nat) : List Lease :=
  ⟨key,now,min machineMax (now+duration)⟩ :: leases.filter (fun l => l.key != key)

def valid (leases : List Lease) (key : LeaseKey) (now : Nat) : Bool :=
  leases.any (fun l => decide (l.key=key ∧ now<l.expires))

theorem live_lease_has_exact_scope (leases : List Lease) (key : LeaseKey) (now : Nat)
    (live : valid leases key now=true) :
    ∃ l ∈ leases, l.key.caller=key.caller ∧ l.key.targetNamespace=key.targetNamespace ∧
      l.key.tokenRoot=key.tokenRoot ∧ now<l.expires := by
  obtain ⟨l, member, binding⟩ := List.any_eq_true.mp live
  simp only [decide_eq_true_eq] at binding
  exact ⟨l,member,congrArg LeaseKey.caller binding.1,
    congrArg LeaseKey.targetNamespace binding.1,congrArg LeaseKey.tokenRoot binding.1,binding.2⟩

theorem saturating_lease_never_exceeds_duration (leases : List Lease) (key : LeaseKey)
    (now : Nat) (l : Lease) (newLease : (grant leases key now).head?=some l) :
    l.expires≤now+duration ∧ l.expires≤machineMax := by
  have equal : l=⟨key,now,min machineMax (now+duration)⟩ := by
    simpa [grant] using newLease.symm
  rw [equal]
  exact ⟨Nat.min_le_right _ _,Nat.min_le_left _ _⟩

inductive LeaseEvent where
  | grant (key : LeaseKey) (now : Nat)
  | prune (now : Nat)
  | lock | sleep | restart | revoke
  deriving DecidableEq, Repr

def leaseStep (s : List Lease) : LeaseEvent → Option (List Lease)
  | .grant key now => some (grant s key now)
  | .prune now => some (s.filter (fun l => decide (now<l.expires)))
  | .lock | .sleep | .restart | .revoke => some []

def IsRevocation : LeaseEvent → Prop
  | .lock | .sleep | .restart | .revoke => True
  | _ => False

theorem revocation_removes_every_scope (s : List Lease) (event : LeaseEvent)
    (revoked : IsRevocation event) (key : LeaseKey) (now : Nat) :
    valid ((leaseStep s event).getD s) key now=false := by
  cases event <;> simp_all [IsRevocation, leaseStep, valid]

end Enclave.CustodyLifecycle
