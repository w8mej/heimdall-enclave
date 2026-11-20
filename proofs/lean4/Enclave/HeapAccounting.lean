import Enclave.CapabilityProtocol

namespace Enclave.HeapAccounting
open Enclave.Capabilities

structure Entry where
  id : Nat
  value : Value
  deriving DecidableEq, Repr

def payloadBytes (entries : List Entry) := (entries.map (fun e => e.value.payload.length)).sum

structure State where
  entries : List Entry
  resident : Nat
  next : Nat
  cap : Nat
  deriving DecidableEq, Repr

def machineMax : Nat := 18446744073709551615

inductive Event where
  | allocate (value : Value)
  | release (ids : List Nat)
  | wipe
  deriving DecidableEq, Repr

/-- Allocation consumes a name before a capacity failure, as in heap.rs.
Represent that failure with `some` of the state after name consumption. Other
denials do not mutate anything. The invariant does not depend on success. -/
def step (s : State) : Event → Option State
  | .allocate value =>
    if s.next < machineMax then
      if value.payload.length ≤ s.cap-s.resident then
        some {s with
          entries := ⟨s.next,value⟩::s.entries
          resident := s.resident+value.payload.length
          next := s.next+1}
      else some {s with next := s.next+1}
    else none
  | .release ids =>
    if ids.all (fun id => s.entries.any (fun e => e.id == id)) then
      let removed := s.entries.filter (fun e => decide (e.id ∈ ids))
      let kept := s.entries.filter (fun e => decide (e.id ∉ ids))
      some {s with entries := kept, resident := s.resident-payloadBytes removed}
    else none
  | .wipe => some {s with entries := [], resident := 0}

def Invariant (s : State) : Prop :=
  s.resident=payloadBytes s.entries ∧ s.resident≤s.cap ∧
    s.next≤machineMax ∧ ∀ e ∈ s.entries, e.id<s.next

theorem payload_partition (entries : List Entry) (ids : List Nat) :
    payloadBytes (entries.filter (fun e => decide (e.id ∈ ids))) +
    payloadBytes (entries.filter (fun e => decide (e.id ∉ ids))) = payloadBytes entries := by
  induction entries with
  | nil => rfl
  | cons e es ih =>
    by_cases h : e.id ∈ ids <;> simp [List.filter_cons, h, payloadBytes] at * <;> omega

theorem step_preserves_accounting (s t : State) (e : Event) (hs : Invariant s)
    (ok : step s e=some t) : Invariant t := by
  have ⟨accounted, bounded, counter, live⟩ := hs
  cases e with
  | wipe =>
    cases ok
    exact ⟨rfl,Nat.zero_le _,hs.2.2.1,by simp⟩
  | release ids =>
    simp only [step] at ok
    split at ok
    · cases ok
      have partition := payload_partition s.entries ids
      refine ⟨by dsimp; omega, ?_, hs.2.2.1, ?_⟩
      · dsimp
        omega
      · intro e he
        exact hs.2.2.2 e (List.mem_filter.mp he).1
    · contradiction
  | allocate value =>
    simp only [step] at ok
    split at ok
    · rename_i idRange
      split at ok
      · rename_i capacity
        cases ok
        refine ⟨?_, ?_, by dsimp; omega, ?_⟩
        · simp only [payloadBytes, List.map_cons, List.sum_cons] at *
          omega
        · dsimp
          omega
        · intro e he
          simp only [List.mem_cons] at he
          rcases he with rfl | he
          · exact Nat.lt_succ_self _
          · exact Nat.lt.step (hs.2.2.2 e he)
      · cases ok
        exact ⟨hs.1,hs.2.1,by dsimp; omega,fun e he => Nat.lt.step (hs.2.2.2 e he)⟩
    · contradiction

theorem arbitrary_heap_history_accounted (cap : Nat) (events : List Event) :
    Invariant (Enclave.Protocol.run step ⟨[],0,0,cap⟩ events) := by
  exact Enclave.Protocol.run_invariant step Invariant
    (fun s e t hs ht => step_preserves_accounting s t e hs ht)
    ⟨[],0,0,cap⟩ events (by simp [Invariant,payloadBytes,machineMax])

theorem exhausted_identifier_denied (s : State) (value : Value) (h : s.next=machineMax) :
    step s (.allocate value)=none := by simp [step,h]

theorem wipe_keeps_identifier_high_water (s : State) :
    ((step s .wipe).getD s).next=s.next := rfl

end Enclave.HeapAccounting
