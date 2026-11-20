import Enclave.ProtocolTrace

namespace Enclave.EgressProtocol

abbrev Slot := Nat × Nat -- boot epoch, sequence

structure State where
  issued : List Slot
  released : List Slot
  deriving DecidableEq, Repr

inductive Event where | issue (s : Slot) | release (s : Slot)
  deriving DecidableEq, Repr

def step (s : State) : Event → Option State
  | .issue slot => some {s with issued := slot :: s.issued}
  | .release slot => some ⟨slot :: s.issued, slot :: s.released⟩

def mayTombstone (s : State) (slot : Slot) : Bool :=
  decide (slot ∈ s.issued ∧ slot ∉ s.released)

theorem release_history_monotone (s t : State) (e : Event) (slot : Slot)
    (hs : slot ∈ s.released) (h : step s e = some t) : slot ∈ t.released := by
  cases e <;> cases h <;> simp_all

theorem released_slot_never_tombstoned_later (s : State) (events : List Event) (slot : Slot)
    (h : slot ∈ s.released) : mayTombstone (Enclave.Protocol.run step s events) slot = false := by
  have keep := Enclave.Protocol.run_invariant step (fun s => slot ∈ s.released)
    (fun a e b ha hb => release_history_monotone a b e slot ha hb) s events h
  simp [mayTombstone, keep]

theorem unknown_slot_denied (s : State) (slot : Slot) (h : slot ∉ s.issued) :
    mayTombstone s slot = false := by simp [mayTombstone, h]

end Enclave.EgressProtocol
