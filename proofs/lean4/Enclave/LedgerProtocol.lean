import Enclave.ProtocolTrace

namespace Enclave.LedgerProtocol

structure State where
  durable : List Nat
  pending : List Nat
  acknowledged : Nat
  deriving DecidableEq, Repr

inductive Event where | append (record : Nat) | sync | acknowledge | crash
  deriving DecidableEq, Repr

def step (s : State) : Event → Option State
  | .append r => some {s with pending := s.pending ++ [r]}
  | .sync => some {s with durable := s.durable ++ s.pending, pending := []}
  | .acknowledge => some {s with acknowledged := s.durable.length}
  | .crash => some {s with pending := []}

theorem acknowledged_prefix_survives_step (s t : State) (e : Event)
    (hs : s.acknowledged ≤ s.durable.length) (h : step s e = some t) :
    t.acknowledged ≤ t.durable.length := by
  cases e <;> cases h <;> simp_all [List.length_append] <;> omega

theorem acknowledged_prefix_survives_crashes (s : State) (events : List Event)
    (hs : s.acknowledged ≤ s.durable.length) :
    (Enclave.Protocol.run step s events).acknowledged ≤
      (Enclave.Protocol.run step s events).durable.length :=
  Enclave.Protocol.run_invariant step (fun s => s.acknowledged ≤ s.durable.length)
    (fun a e b ha hb => acknowledged_prefix_survives_step a b e ha hb) s events hs

theorem durable_prefix_preserved (s t : State) (e : Event) (h : step s e = some t) :
    ∃ suffix, t.durable = s.durable ++ suffix := by
  cases e <;> cases h
  · exact ⟨[], (List.append_nil _).symm⟩
  · exact ⟨s.pending, rfl⟩
  · exact ⟨[], (List.append_nil _).symm⟩
  · exact ⟨[], (List.append_nil _).symm⟩

def anchorAccepts (trustedLength : Nat) (records : List Nat) : Bool :=
  decide (trustedLength ≤ records.length)

theorem anchored_truncation_rejected (n : Nat) (records : List Nat)
    (h : records.length < n) : anchorAccepts n records = false := by
  simp [anchorAccepts]; omega

theorem arbitrary_history_preserves_durable_contents (s : State) (events : List Event) :
    ∃ suffix, (Enclave.Protocol.run step s events).durable = s.durable ++ suffix := by
  refine Enclave.Protocol.run_invariant step
    (fun t => ∃ suffix, t.durable=s.durable++suffix) ?_ s events
    ⟨[],(List.append_nil _).symm⟩
  intro a e b ha hb
  obtain ⟨past,hpast⟩ := ha
  obtain ⟨extra,hextra⟩ := durable_prefix_preserved a b e hb
  exact ⟨past++extra,by rw [hextra,hpast,List.append_assoc]⟩

theorem crash_recovery_preserves_acknowledged_contents (s : State) (events : List Event)
    (acked : s.acknowledged≤s.durable.length) :
    (Enclave.Protocol.run step s events).durable.take s.acknowledged =
      s.durable.take s.acknowledged := by
  obtain ⟨suffix,equal⟩ := arbitrary_history_preserves_durable_contents s events
  rw [equal, List.take_append_of_le_length acked]

end Enclave.LedgerProtocol
