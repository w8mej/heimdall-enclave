import Enclave.EgressFinalization

/-! Two independent attestor registries. Each daemon serializes its own
operations; events on the two daemons may interleave arbitrarily. A joint
reservation requires both local terminal records. Signature authenticity and
faithful durable restoration remain external to this transition model. -/
namespace Enclave.EgressAttestorComposition

open Enclave.EgressFinalization

inductive Side where | owner | ifc deriving DecidableEq, Repr

structure System where
  owner : State
  ifc : State
  deriving DecidableEq, Repr

def view (s : System) : Side → State
  | .owner => s.owner
  | .ifc => s.ifc

def replace (s : System) : Side → State → System
  | .owner, nextState => {s with owner:=nextState}
  | .ifc, nextState => {s with ifc:=nextState}

inductive Event where
  | ownerIssue (slot : Slot)
  | ownerRelease (slot : Slot) (synced : Bool)
  | ownerSign (slot : Slot) (synced : Bool)
  | ifcRelease (slot : Slot) (synced : Bool)
  | ifcSign (slot : Slot) (synced : Bool)
  deriving DecidableEq, Repr

def target : Event → Side
  | .ownerIssue _ | .ownerRelease _ _ | .ownerSign _ _ => .owner
  | .ifcRelease _ _ | .ifcSign _ _ => .ifc

def localEvent : Event → Enclave.EgressFinalization.Event
  | .ownerIssue slot => .issue slot
  | .ownerRelease slot synced | .ifcRelease slot synced => .release slot synced
  | .ownerSign slot synced => .ownerSign slot synced
  | .ifcSign slot synced => .ifcSign slot synced

def step (s : System) (event : Event) : Option System :=
  (Enclave.EgressFinalization.step (view s (target event)) (localEvent event)).map
    (replace s (target event))

def Safe (s : System) : Prop :=
  Enclave.EgressFinalization.Safe s.owner ∧ Enclave.EgressFinalization.Safe s.ifc

def jointlyReserved (s : System) (slot : Slot) : Prop :=
  slot∈s.owner.tombstoned ∧ slot∈s.ifc.tombstoned

instance (s : System) (slot : Slot) : Decidable (jointlyReserved s slot) :=
  inferInstanceAs (Decidable (slot∈s.owner.tombstoned ∧ slot∈s.ifc.tombstoned))

theorem step_preserves_both_independent_registries (s t : System) (event : Event)
    (safe : Safe s) (accepted : step s event=some t) : Safe t := by
  cases result : Enclave.EgressFinalization.step (view s (target event)) (localEvent event) with
  | none => simp [step,result] at accepted
  | some nextState =>
    have same : replace s (target event) nextState=t := by simpa [step,result] using accepted
    subst t
    cases side : target event
    · exact ⟨Enclave.EgressFinalization.step_preserves_exclusive_terminal_states
        s.owner nextState (localEvent event) safe.1 (by simpa [side,view] using result),safe.2⟩
    · exact ⟨safe.1,Enclave.EgressFinalization.step_preserves_exclusive_terminal_states
        s.ifc nextState (localEvent event) safe.2 (by simpa [side,view] using result)⟩

theorem arbitrary_interleaving_preserves_both_registries (s : System) (events : List Event)
    (safe : Safe s) : Safe (Enclave.Protocol.run step s events) :=
  Enclave.Protocol.run_invariant step Safe
    (fun a event b ha hb => step_preserves_both_independent_registries a b event ha hb) s events safe

theorem step_preserves_joint_reservation (s t : System) (event : Event) (slot : Slot)
    (reserved : jointlyReserved s slot) (accepted : step s event=some t) : jointlyReserved t slot := by
  cases result : Enclave.EgressFinalization.step (view s (target event)) (localEvent event) with
  | none => simp [step,result] at accepted
  | some nextState =>
    have same : replace s (target event) nextState=t := by simpa [step,result] using accepted
    subst t
    have persists := Enclave.EgressFinalization.terminal_reservations_never_disappear
      (view s (target event)) nextState (localEvent event) result slot
    cases side : target event
    · exact ⟨persists.2 (by simpa [side,view] using reserved.1),reserved.2⟩
    · exact ⟨reserved.1,persists.2 (by simpa [side,view] using reserved.2)⟩

theorem arbitrary_interleaving_preserves_joint_reservation (s : System) (events : List Event)
    (slot : Slot) (reserved : jointlyReserved s slot) :
    jointlyReserved (Enclave.Protocol.run step s events) slot :=
  Enclave.Protocol.run_invariant step (fun state => jointlyReserved state slot)
    (fun a event b ha hb => step_preserves_joint_reservation a b event slot ha hb) s events reserved

theorem joint_reservation_excludes_release_by_either_attestor (s : System) (slot : Slot)
    (safe : Safe s) (reserved : jointlyReserved s slot) :
    slot∉s.owner.released ∧ slot∉s.ifc.released := by
  exact ⟨fun released => safe.1 slot released reserved.1,
    fun released => safe.2 slot released reserved.2⟩

/-- This statement uses two separate local states, not a shared registry. -/
theorem joint_reservation_survives_future_interleavings_without_any_local_release
    (s : System) (events : List Event) (slot : Slot) (safe : Safe s)
    (reserved : jointlyReserved s slot) :
    let final := Enclave.Protocol.run step s events
    jointlyReserved final slot ∧ slot∉final.owner.released ∧ slot∉final.ifc.released := by
  have finalSafe := arbitrary_interleaving_preserves_both_registries s events safe
  have finalReserved := arbitrary_interleaving_preserves_joint_reservation s events slot reserved
  exact ⟨finalReserved,joint_reservation_excludes_release_by_either_attestor _ slot finalSafe finalReserved⟩

end Enclave.EgressAttestorComposition
