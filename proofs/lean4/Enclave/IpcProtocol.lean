import Enclave.ProtocolTrace
import Enclave.NormalizedQif

namespace Enclave.IpcProtocol

structure Reservation where
  id : Nat
  uid : Nat
  bytes : Nat
  deriving DecidableEq, Repr

abbrev State := List Reservation
def bytes (s : State) := (s.map Reservation.bytes).sum
def forUid (s : State) (uid : Nat) := s.filter (fun r => r.uid == uid)

def reserve (s : State) (r : Reservation) (byteCap connCap uidCap : Nat) : Option State :=
  if ¬ s.any (fun x => x.id == r.id) ∧ bytes s + r.bytes ≤ byteCap ∧
      s.length < connCap ∧ (forUid s r.uid).length < uidCap then some (r::s) else none

theorem reserve_enforces_caps (s t : State) (r : Reservation) (b c u : Nat)
    (h : reserve s r b c u = some t) :
    bytes t ≤ b ∧ t.length ≤ c ∧ (forUid t r.uid).length ≤ u := by
  unfold reserve at h
  split at h
  · rename_i hg
    cases h
    simp only [bytes, List.map_cons, List.sum_cons, List.length_cons,
      forUid, List.filter_cons, beq_self_eq_true, ↓reduceIte]
    change r.bytes + bytes s ≤ b ∧ s.length+1 ≤ c ∧ (forUid s r.uid).length+1 ≤ u
    omega
  · contradiction

def release (s : State) (id : Nat) := s.filter (fun r => r.id != id)

theorem sum_filter_le (xs : List Reservation) (p : Reservation → Bool) :
    bytes (xs.filter p) ≤ bytes xs := by
  induction xs with
  | nil => simp [bytes]
  | cons x xs ih =>
    cases h : p x <;> simp [List.filter_cons, h, bytes] at * <;> omega

theorem release_cannot_increase_bytes (s : State) (id : Nat) : bytes (release s id) ≤ bytes s :=
  sum_filter_le s _

structure Frame where
  started : Nat
  deadline : Nat
  received : Nat
  declared : Nat
  deriving DecidableEq, Repr

def readChunk (s : Frame) (now chunk : Nat) : Option Frame :=
  if now ≤ s.deadline ∧ s.received+chunk ≤ s.declared then
    some {s with received := s.received+chunk} else none

theorem partial_reads_do_not_extend_deadline (s t : Frame) (now n : Nat)
    (h : readChunk s now n = some t) : t.deadline = s.deadline ∧ t.received ≤ t.declared := by
  unfold readChunk at h
  split at h
  · rename_i hg; cases h; exact ⟨rfl, hg.2⟩
  · contradiction

structure Limits where
  byteCap : Nat
  connections : Nat
  perUid : Nat
  deriving DecidableEq, Repr

def WithinLimits (l : Limits) (s : State) : Prop :=
  bytes s ≤ l.byteCap ∧ s.length ≤ l.connections ∧
    ∀ uid, (forUid s uid).length ≤ l.perUid

inductive Event where
  | acquire (r : Reservation)
  | drop (id : Nat)
  deriving DecidableEq, Repr

def step (l : Limits) (s : State) : Event → Option State
  | .acquire r => reserve s r l.byteCap l.connections l.perUid
  | .drop id => some (release s id)

theorem release_uid_bound (s : State) (id uid : Nat) :
    (forUid (release s id) uid).length ≤ (forUid s uid).length := by
  unfold forUid release
  have commute : (s.filter (fun r => r.id != id)).filter (fun r => r.uid == uid) =
      (s.filter (fun r => r.uid == uid)).filter (fun r => r.id != id) := by
    simp only [List.filter_filter]
    congr 1
    funext r
    exact Bool.and_comm _ _
  rw [commute]
  exact List.length_filter_le _ _

theorem step_preserves_all_limits (l : Limits) (s t : State) (e : Event)
    (hs : WithinLimits l s) (h : step l s e = some t) : WithinLimits l t := by
  cases e with
  | drop id =>
    cases h
    exact ⟨Nat.le_trans (release_cannot_increase_bytes s id) hs.1,
      Nat.le_trans (List.length_filter_le _ _) hs.2.1,
      fun uid => Nat.le_trans (release_uid_bound s id uid) (hs.2.2 uid)⟩
  | acquire r =>
    have caps := reserve_enforces_caps s t r l.byteCap l.connections l.perUid h
    change reserve s r l.byteCap l.connections l.perUid = some t at h
    unfold reserve at h
    split at h
    · cases h
      refine ⟨caps.1, caps.2.1, ?_⟩
      intro uid
      by_cases equal : r.uid=uid
      · simpa [equal] using caps.2.2
      · simpa [forUid, equal] using hs.2.2 uid
    · contradiction

theorem arbitrary_resource_history_bounded (l : Limits) (events : List Event) :
    WithinLimits l (Enclave.Protocol.run (step l) [] events) := by
  exact Enclave.Protocol.run_invariant (step l) (WithinLimits l)
    (fun s e t hs ht => step_preserves_all_limits l s t e hs ht)
    [] events (by simp [WithinLimits, bytes, forUid])

abbrev Chunk := Nat × Nat -- time, bytes read
def frameStep (s : Frame) (c : Chunk) := readChunk s c.1 c.2

theorem arbitrary_partial_reads_keep_deadline (s : Frame) (chunks : List Chunk) :
    (Enclave.Protocol.run frameStep s chunks).deadline = s.deadline := by
  exact Enclave.Protocol.run_invariant frameStep (fun t => t.deadline=s.deadline)
    (fun a c b ha hb => ((partial_reads_do_not_extend_deadline a b c.1 c.2 hb).1).trans ha)
    s chunks rfl

theorem expired_frame_remains_unreadable (s : Frame) (chunks : List Chunk) (now n : Nat)
    (late : s.deadline < now) :
    readChunk (Enclave.Protocol.run frameStep s chunks) now n = none := by
  have deadline := arbitrary_partial_reads_keep_deadline s chunks
  simp [readChunk, deadline, show ¬now ≤ s.deadline by omega]

end Enclave.IpcProtocol
