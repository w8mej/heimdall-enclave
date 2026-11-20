import Enclave.ProtocolTrace

/-! Terminal nonrelease reservations for the two-attestor protocol. UID 703
requires issuance; UID 704 may attest its own nonrelease for an unseen slot.
Both reserve a durable terminal state before signing. Signature authenticity
and stable-log durability are external primitives; a check without reservation
is explicitly insufficient for this protocol. -/
namespace Enclave.EgressFinalization

abbrev Slot := Nat × Nat

structure State where
  issued : List Slot
  released : List Slot
  tombstoned : List Slot
  deriving DecidableEq, Repr

inductive Record where
  | issue (slot : Slot)
  | release (slot : Slot)
  | tombstone (slot : Slot)
  deriving DecidableEq, Repr

def replayOne (s : State) : Record → State
  | .issue slot => {s with issued:=slot::s.issued}
  | .release slot => {s with issued:=slot::s.issued,released:=slot::s.released}
  | .tombstone slot => {s with tombstoned:=slot::s.tombstoned}

def replay (records : List Record) : State := records.foldl replayOne ⟨[],[],[]⟩

def Safe (s : State) : Prop := ∀ slot ∈ s.released, slot ∉ s.tombstoned

instance (s : State) : Decidable (Safe s) := inferInstanceAs
  (Decidable (∀ slot ∈ s.released, slot ∉ s.tombstoned))

/-- Successful sync is a primitive. No output or signature is exposed when
it fails. A failed write/sync may conservatively consume a reservation in
storage; this only strengthens denial and is not a refunded observation. -/
inductive Event where
  | issue (slot : Slot)
  | release (slot : Slot) (syncSucceeded : Bool)
  | ownerSign (slot : Slot) (syncSucceeded : Bool)
  | ifcSign (slot : Slot) (syncSucceeded : Bool)
  deriving DecidableEq, Repr

def step (s : State) : Event → Option State
  | .issue slot => some (replayOne s (.issue slot))
  | .release slot synced =>
    if slot ∉ s.tombstoned ∧ synced=true then some (replayOne s (.release slot)) else none
  | .ownerSign slot synced =>
    if slot ∈ s.issued ∧ slot ∉ s.released ∧ synced=true then
      some (replayOne s (.tombstone slot)) else none
  | .ifcSign slot synced =>
    if slot ∉ s.released ∧ synced=true then some (replayOne s (.tombstone slot)) else none

theorem step_preserves_exclusive_terminal_states (s t : State) (event : Event)
    (safe : Safe s) (accepted : step s event=some t) : Safe t := by
  cases event with
  | issue slot => cases accepted; exact safe
  | release slot synced =>
    simp only [step] at accepted
    split at accepted
    · rename_i guards
      cases accepted
      intro key member
      rcases List.mem_cons.mp member with rfl | old
      · exact guards.1
      · exact safe key old
    · contradiction
  | ownerSign slot synced =>
    simp only [step] at accepted
    split at accepted
    · rename_i guards
      cases accepted
      intro key member
      simp only [replayOne,List.mem_cons,not_or]
      exact ⟨fun same => guards.2.1 (same ▸ member),safe key member⟩
    · contradiction
  | ifcSign slot synced =>
    simp only [step] at accepted
    split at accepted
    · rename_i guards
      cases accepted
      intro key member
      simp only [replayOne,List.mem_cons,not_or]
      exact ⟨fun same => guards.1 (same ▸ member),safe key member⟩
    · contradiction

theorem terminal_reservations_never_disappear (s t : State) (event : Event)
    (accepted : step s event=some t) (slot : Slot) :
    (slot ∈ s.released → slot ∈ t.released) ∧
      (slot ∈ s.tombstoned → slot ∈ t.tombstoned) := by
  cases event <;> simp only [step] at accepted
  all_goals first | cases accepted; simp [replayOne] | skip
  all_goals split at accepted
  all_goals first | contradiction | cases accepted; simp_all [replayOne]

theorem arbitrary_history_has_exclusive_terminal_states (events : List Event) :
    Safe (Enclave.Protocol.run step ⟨[],[],[]⟩ events) :=
  Enclave.Protocol.run_invariant step Safe
    (fun s event t hs ht => step_preserves_exclusive_terminal_states s t event hs ht)
    ⟨[],[],[]⟩ events (by simp [Safe])

theorem signed_slot_cannot_be_released_later (s : State) (slot : Slot)
    (signed : slot ∈ s.tombstoned) (events : List Event) (synced : Bool) :
    step (Enclave.Protocol.run step s events) (.release slot synced)=none := by
  have keep := Enclave.Protocol.run_invariant step (fun t => slot ∈ t.tombstoned)
    (fun a event b ha hb => (terminal_reservations_never_disappear a b event hb slot).2 ha)
    s events signed
  simp [step,keep]

theorem released_slot_cannot_be_signed_later (s : State) (slot : Slot)
    (released : slot ∈ s.released) (events : List Event) (synced : Bool) :
    step (Enclave.Protocol.run step s events) (.ownerSign slot synced)=none ∧
      step (Enclave.Protocol.run step s events) (.ifcSign slot synced)=none := by
  have keep := Enclave.Protocol.run_invariant step (fun t => slot ∈ t.released)
    (fun a event b ha hb => (terminal_reservations_never_disappear a b event hb slot).1 ha)
    s events released
  simp [step,keep]

theorem nonowner_can_attest_unseen_slot (slot : Slot) :
    step ⟨[],[],[]⟩ (.ifcSign slot true)=some ⟨[],[],[slot]⟩ := by simp [step,replayOne]

theorem owner_cannot_attest_unissued_slot (s : State) (slot : Slot)
    (unknown : slot ∉ s.issued) : step s (.ownerSign slot true)=none := by simp [step,unknown]

theorem failed_sync_never_releases_or_signs (s : State) (slot : Slot) :
    step s (.release slot false)=none ∧ step s (.ownerSign slot false)=none ∧
      step s (.ifcSign slot false)=none := by simp [step]

/-- Replaying a valid-format log does not by itself establish semantic
consistency. Native restoration rejects overlapping release/tombstone sets. -/
def recover (records : List Record) : Option State :=
  let s := replay records
  if Safe s then some s else none

theorem restored_log_cannot_contain_both_terminal_states (records : List Record)
    (s : State) (restored : recover records=some s) : Safe s := by
  unfold recover at restored
  dsimp only at restored
  split at restored
  · rename_i safe
    cases restored
    exact safe
  · contradiction

theorem syntactically_valid_conflicting_log_is_rejected (slot : Slot) :
    recover [.issue slot,.tombstone slot,.release slot]=none := by
  simp [recover,replay,List.foldl,replayOne,Safe]

end Enclave.EgressFinalization
