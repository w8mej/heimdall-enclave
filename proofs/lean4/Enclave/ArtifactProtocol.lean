import Enclave.ProtocolTrace

namespace Enclave.ArtifactProtocol

structure Target where
  digest : Nat
  length : Nat
  profile : Nat
  classificationFloor : Nat
  companions : List Nat
  revoked : Bool
  deriving DecidableEq, Repr

structure Published where
  bytes : List Nat
  profile : Nat
  target : Target
  deriving DecidableEq, Repr

def publish (hash : List Nat → Nat) (signedTargets : List Target) (t : Target)
    (bytes : List Nat) (availableCompanions : List Nat) (workstation hint : Nat) : Option Published :=
  if t ∈ signedTargets ∧ t.revoked = false ∧ hash bytes = t.digest ∧
      bytes.length = t.length ∧ t.companions.all (fun d => decide (d ∈ availableCompanions)) then
    some ⟨bytes, max workstation (max t.profile (max hint t.classificationFloor)), t⟩
  else none

theorem published_bytes_verified (hash : List Nat → Nat) (signed : List Target)
    (t : Target) (bytes available : List Nat) (w hint : Nat) (p : Published)
    (h : publish hash signed t bytes available w hint = some p) :
    p.target ∈ signed ∧ hash p.bytes = p.target.digest ∧
    p.bytes.length = p.target.length ∧
    ∀ d ∈ p.target.companions, d ∈ available := by
  unfold publish at h
  split at h
  · rename_i hg
    cases h
    refine ⟨hg.1, hg.2.2.1, hg.2.2.2.1, ?_⟩
    simpa only [List.all_eq_true, decide_eq_true_eq] using hg.2.2.2.2
  · contradiction

theorem published_floor_monotone (hash : List Nat → Nat) (signed : List Target)
    (t : Target) (bytes available : List Nat) (w hint : Nat) (p : Published)
    (h : publish hash signed t bytes available w hint = some p) :
    w ≤ p.profile ∧ t.profile ≤ p.profile ∧ hint ≤ p.profile ∧ t.classificationFloor ≤ p.profile := by
  unfold publish at h
  split at h
  · cases h
    simp only
    omega
  · contradiction

def acknowledge (outbox : List Nat) (authenticatedId : Option Nat) : List Nat :=
  match authenticatedId with
  | none => outbox
  | some id => outbox.filter (fun n => n != id)

theorem no_ack_no_deletion (outbox : List Nat) : acknowledge outbox none = outbox := rfl

theorem unrelated_ack_preserves (outbox : List Nat) (id other : Nat)
    (h : other ∈ outbox) (hne : other ≠ id) : other ∈ acknowledge outbox (some id) := by
  simp [acknowledge, h, hne]

/-- A companion carries actual bytes and independently authenticated target
metadata. Merely presenting a required digest is insufficient. -/
structure Companion where
  target : Target
  bytes : List Nat
  deriving DecidableEq, Repr

def companionValid (hash : List Nat → Nat) (signed : List Target) (c : Companion) : Bool :=
  decide (c.target ∈ signed ∧ c.target.revoked=false ∧
    hash c.bytes=c.target.digest ∧ c.bytes.length=c.target.length)

def publishWithCompanions (hash : List Nat → Nat) (signed : List Target) (t : Target)
    (bytes : List Nat) (companions : List Companion) (workstation hint : Nat) :=
  if companions.all (companionValid hash signed) then
    publish hash signed t bytes (companions.map (fun c => c.target.digest)) workstation hint
  else none

theorem publication_requires_authentic_companion_content (hash : List Nat → Nat)
    (signed : List Target) (t : Target) (bytes : List Nat) (companions : List Companion)
    (workstation hint : Nat) (p : Published)
    (ok : publishWithCompanions hash signed t bytes companions workstation hint=some p) :
    ∀ digest ∈ p.target.companions, ∃ c ∈ companions,
      c.target.digest=digest ∧ c.target∈signed ∧ c.target.revoked=false ∧
      hash c.bytes=digest ∧ c.bytes.length=c.target.length := by
  unfold publishWithCompanions at ok
  split at ok
  · rename_i checked
    have required := (published_bytes_verified hash signed t bytes
      (companions.map (fun c => c.target.digest)) workstation hint p ok).2.2.2
    intro digest member
    obtain ⟨c,hc,equal⟩ := List.mem_map.mp (required digest member)
    have valid := List.all_eq_true.mp checked c hc
    simp only [companionValid, decide_eq_true_eq] at valid
    exact ⟨c,hc,equal,valid.1,valid.2.1,valid.2.2.1.trans equal,valid.2.2.2⟩
  · contradiction

structure Candidate where
  target : Target
  bytes : List Nat
  companions : List Companion
  workstation : Nat
  hint : Nat
  deriving DecidableEq, Repr

structure Store where
  staged : Option Candidate
  visible : List Published
  deriving DecidableEq, Repr

inductive Event where
  | stage (candidate : Candidate)
  | install
  | crash
  deriving DecidableEq, Repr

/-- Atomic publication is the storage primitive modeled here: visibility
changes only after the final content checks, and a crash discards staging. -/
def storeStep (hash : List Nat → Nat) (signed : List Target) (s : Store) : Event → Option Store
  | .stage c => some {s with staged := some c}
  | .crash => some {s with staged := none}
  | .install => do
    let c ← s.staged
    let p ← publishWithCompanions hash signed c.target c.bytes c.companions c.workstation c.hint
    return ⟨none,p::s.visible⟩

def VisibleValid (hash : List Nat → Nat) (signed : List Target) (s : Store) : Prop :=
  ∀ p ∈ s.visible, p.target∈signed ∧ hash p.bytes=p.target.digest ∧
    p.bytes.length=p.target.length

theorem store_step_preserves_visible_authenticity (hash : List Nat → Nat) (signed : List Target)
    (s t : Store) (e : Event) (safe : VisibleValid hash signed s)
    (ok : storeStep hash signed s e=some t) : VisibleValid hash signed t := by
  cases e with
  | stage c => cases ok; exact safe
  | crash => cases ok; exact safe
  | install =>
    cases stage : s.staged with
    | none => simp [storeStep,stage] at ok
    | some c =>
      cases result : publishWithCompanions hash signed c.target c.bytes c.companions c.workstation c.hint with
      | none => simp [storeStep,stage,result] at ok
      | some p =>
        have same : t=⟨none,p::s.visible⟩ := by simpa [storeStep,stage,result] using ok.symm
        rw [same]
        intro q member
        simp only [List.mem_cons] at member
        rcases member with rfl | old
        · unfold publishWithCompanions at result
          split at result
          · have verified := published_bytes_verified hash signed c.target c.bytes
              (c.companions.map (fun x => x.target.digest)) c.workstation c.hint q result
            exact ⟨verified.1,verified.2.1,verified.2.2.1⟩
          · contradiction
        · exact safe q old

theorem arbitrary_staging_crash_history_authentic (hash : List Nat → Nat) (signed : List Target)
    (events : List Event) :
    VisibleValid hash signed (Enclave.Protocol.run (storeStep hash signed) ⟨none,[]⟩ events) := by
  exact Enclave.Protocol.run_invariant (storeStep hash signed) (VisibleValid hash signed)
    (fun s e t hs ht => store_step_preserves_visible_authenticity hash signed s t e hs ht)
    ⟨none,[]⟩ events (by simp [VisibleValid])

end Enclave.ArtifactProtocol
