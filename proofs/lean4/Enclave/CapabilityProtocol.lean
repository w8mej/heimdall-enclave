import Enclave.ProtocolTrace
import Enclave.Lattice

namespace Enclave.Capabilities

structure Value where
  payload : List Nat
  label : SecurityLabel
  epoch : Nat
  turn : Nat
  deriving DecidableEq, Repr

abbrev Heap := Nat → Option Value

/-- Verification compares the presented record to the server-owned record.
The MAC verifier must establish this relation; it is not modeled as a Boolean. -/
def resolve (h : Heap) (id epoch turn : Nat) (presented : Value) : Option Value :=
  if h id = some presented ∧ presented.epoch = epoch ∧ presented.turn = turn then
    some presented else none

theorem resolution_authentic (h : Heap) (id epoch turn : Nat) (p v : Value)
    (ok : resolve h id epoch turn p = some v) :
    h id = some v ∧ v.epoch = epoch ∧ v.turn = turn := by
  simp only [resolve] at ok
  split at ok
  · rename_i guard
    cases ok
    exact guard
  · contradiction

def release (h : Heap) (ids : List Nat) : Heap :=
  fun id => if id ∈ ids then none else h id

theorem released_unresolvable (h : Heap) (ids : List Nat) (id epoch turn : Nat)
    (p : Value) (hi : id ∈ ids) : resolve (release h ids) id epoch turn p = none := by
  simp [resolve, release, hi]

theorem release_preserves_other (h : Heap) (ids : List Nat) (id : Nat)
    (hi : id ∉ ids) : release h ids id = h id := by simp [release, hi]

def derive (a b : Value) (payload : List Nat) : Value :=
  {a with payload := payload, label := a.label.join b.label}

theorem derivation_cannot_lower (a b : Value) (payload : List Nat) :
    a.label.confidentiality ≤ (derive a b payload).label.confidentiality ∧
    b.label.confidentiality ≤ (derive a b payload).label.confidentiality :=
  ⟨conf_join_le_left _ _, conf_join_le_right _ _⟩

theorem derivation_preserves_t3 (a b : Value) (payload : List Nat)
    (h : a.label.integrity = .T3 ∨ b.label.integrity = .T3) :
    (derive a b payload).label.integrity = .T3 := by
  rcases h with h | h
  · cases hb : b.label.integrity <;>
      simp [derive, SecurityLabel.join, h, hb, IntegLevel.join, IntegLevel.toNat]
  · cases ha : a.label.integrity <;>
      simp [derive, SecurityLabel.join, h, ha, IntegLevel.join, IntegLevel.toNat]

end Enclave.Capabilities
