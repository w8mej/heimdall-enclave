import Enclave.ProtocolTrace

namespace Enclave.DpopProtocol

structure Binding where
  method : List Nat
  normalizedUri : List Nat
  holder : List Nat
  tokenHash : Option (List Nat)
  deriving DecidableEq, Repr

structure Proof where
  binding : Binding
  jti : Nat
  issued : Int
  deriving DecidableEq, Repr

/-- Mathematical distance corresponding to i64::abs_diff, without signed abs. -/
def fresh (now issued skew : Int) : Bool :=
  decide (issued - now ≤ max skew 0 ∧ now - issued ≤ max skew 0)

theorem fresh_distance_bounded (now issued skew : Int) (h : fresh now issued skew = true) :
    now - max skew 0 ≤ issued ∧ issued ≤ now + max skew 0 := by
  simp [fresh] at h
  omega

def verify (signatureValid : Proof → Bool) (expected : Binding)
    (now skew : Int) (p : Proof) : Bool :=
  signatureValid p && decide (p.binding = expected) && fresh now p.issued skew

theorem accepted_exact_binding (sig : Proof → Bool) (b : Binding) (now skew : Int)
    (p : Proof) (h : verify sig b now skew p = true) : p.binding = b := by
  simp [verify] at h
  exact h.1.2

structure Replay where
  bound : List (List Nat × Nat)
  unbound : List (List Nat × Nat)
  deriving DecidableEq, Repr

def remember (s : Replay) (holder : List Nat) (jti : Nat) (bound : Bool) : Option Replay :=
  if bound then
    if (holder,jti) ∈ s.bound then none else some {s with bound := (holder,jti)::s.bound}
  else
    if (holder,jti) ∈ s.unbound then none else some {s with unbound := (holder,jti)::s.unbound}

theorem replay_rejected (s t : Replay) (holder : List Nat) (jti : Nat) (b : Bool)
    (h : remember s holder jti b = some t) : remember t holder jti b = none := by
  cases b <;> simp only [remember, Bool.false_eq_true, ↓reduceIte] at h ⊢
  all_goals split at h
  all_goals first | contradiction | skip
  all_goals cases h
  all_goals simp

theorem unbound_cannot_evict_bound (s t : Replay) (holder : List Nat) (jti : Nat)
    (h : remember s holder jti false = some t) : t.bound = s.bound := by
  simp only [remember, Bool.false_eq_true, ↓reduceIte] at h
  split at h
  · contradiction
  · cases h; rfl

end Enclave.DpopProtocol
