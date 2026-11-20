import Enclave.ProtocolTrace
import Enclave.RustModelBridge

namespace Enclave.Lifecycle

def flowTrace (s : RustFlowState) (es : List RustFlowEvent) : RustFlowState :=
  es.foldl rustStep s

theorem quarantine_absorbing (es : List RustFlowEvent) :
    flowTrace .QuarantineAbort es = .QuarantineAbort := by
  induction es with
  | nil => rfl
  | cons e es ih =>
    have h : rustStep .QuarantineAbort e = .QuarantineAbort := by cases e <;> rfl
    simpa [flowTrace, List.foldl_cons, h] using ih

structure Session where
  generation : Nat
  active : Bool
  output : List (Nat × Nat)
  deriving DecidableEq, Repr

inductive Event where
  | cancel
  | begin
  | publish (generation byte : Nat)
  deriving DecidableEq, Repr

def step (s : Session) : Event → Option Session
  | .cancel => some {s with generation := s.generation + 1, active := false}
  | .begin => some {s with generation := s.generation + 1, active := true}
  | .publish generation byte =>
    if s.active ∧ generation = s.generation then
      some {s with output := s.output ++ [(generation, byte)]} else none

theorem generation_monotone (s t : Session) (e : Event) (h : step s e = some t) :
    s.generation ≤ t.generation := by
  cases e <;> simp only [step] at h
  · cases h; simp
  · cases h; simp
  · split at h
    · cases h; exact Nat.le_refl _
    · contradiction

theorem stale_publish_rejected (s : Session) (old byte : Nat) (h : old < s.generation) :
    step s (.publish old byte) = none := by
  simp [step, show old ≠ s.generation by omega]

theorem old_generation_remains_invalid (s : Session) (events : List Event) (old byte : Nat)
    (h : old < s.generation) :
    step (Enclave.Protocol.run step s events) (.publish old byte) = none := by
  apply stale_publish_rejected
  exact Enclave.Protocol.run_invariant step (fun t => old < t.generation)
    (fun a e b ha hb => Nat.lt_of_lt_of_le ha (generation_monotone a b e hb)) s events h

end Enclave.Lifecycle
