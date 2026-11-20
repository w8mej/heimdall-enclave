import Enclave.ProtocolTrace

namespace Enclave.CustodyProtocol

structure Intent where
  digest : List Nat
  session : Nat
  key : Nat
  expires : Nat
  required : List Nat
  deriving DecidableEq, Repr

structure Evidence where
  intent : Intent
  factor : Nat
  nonce : Nat
  deriving DecidableEq, Repr

inductive Phase where | pending | released | cancelled deriving DecidableEq, Repr

structure State where
  intent : Intent
  approvals : List Evidence
  phase : Phase
  deriving DecidableEq, Repr

inductive Event where
  | approve (e : Evidence)
  | release (requested : Intent) (now : Nat)
  | cancel
  deriving DecidableEq, Repr

def step (verify : Evidence → Bool) (s : State) : Event → Option State
  | .cancel => some {s with phase := .cancelled}
  | .approve e =>
    if s.phase = .pending ∧ e.intent = s.intent ∧ verify e ∧
        ¬ s.approvals.any (fun a => a.nonce == e.nonce) then
      some {s with approvals := e :: s.approvals} else none
  | .release requested now =>
    if s.phase = .pending ∧ requested = s.intent ∧ now ≤ s.intent.expires ∧
        s.intent.required.all (fun f => s.approvals.any
          (fun a => decide (a.factor = f ∧ a.intent = requested) && verify a)) then
      some {s with phase := .released} else none

theorem release_has_bound_verified_factors (verify : Evidence → Bool) (s t : State)
    (request : Intent) (now : Nat) (h : step verify s (.release request now) = some t) :
    request = s.intent ∧ now ≤ request.expires ∧
    ∀ f ∈ request.required, ∃ a ∈ s.approvals,
      a.factor = f ∧ a.intent = request ∧ verify a = true := by
  simp only [step] at h
  split at h
  · rename_i hg
    refine ⟨hg.2.1, hg.2.1 ▸ hg.2.2.1, ?_⟩
    intro f hf
    have hf' : f ∈ s.intent.required := hg.2.1 ▸ hf
    have ha := (List.all_eq_true.mp hg.2.2.2) f hf'
    obtain ⟨a, ham, ha⟩ := List.any_eq_true.mp ha
    simp only [Bool.and_eq_true, decide_eq_true_eq] at ha
    exact ⟨a, ham, ha.1.1, ha.1.2, ha.2⟩
  · contradiction

theorem release_is_single_use (verify : Evidence → Bool) (s t : State)
    (request next : Intent) (now later : Nat)
    (h : step verify s (.release request now) = some t) :
    step verify t (.release next later) = none := by
  simp only [step] at h
  split at h
  · cases h; simp [step]
  · contradiction

theorem cancelled_cannot_release (verify : Evidence → Bool) (s : State)
    (request : Intent) (now : Nat) :
    step verify {s with phase := .cancelled} (.release request now) = none := by
  simp [step]

end Enclave.CustodyProtocol
