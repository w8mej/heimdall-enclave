import Enclave.ProtocolTrace

/-! LAT-02: executable, single-target broker protocol model. Durable journal
phase and actual platform ownership are deliberately independent. Admissions
abstract successful parser/identity/copy verification; this does not prove those
checks, cryptography, Rust refinement, APFS, hardware or holder revocation.
A crash here models successful validation of the retained sealed journal on
restart, not arbitrary corruption or rollback of that journal. -/
namespace Enclave.SnapshotBrokerProtocol

inductive Phase where
  | absent | intent | ownedIncomplete | complete
  deriving DecidableEq, Repr

inductive Platform where
  | absent | foreign | ours
  deriving DecidableEq, Repr

structure Admission where
  profile : Nat
  authenticated : Bool
  framingValid : Bool
  descriptorValid : Bool
  copyVerified : Bool
  authority : Nat
  deriving DecidableEq, Repr

structure State where
  phase : Phase
  platform : Platform
  originalAuthority : Nat
  currentAuthority : Nat
  currentValid : Bool
  tufFloor : Nat
  busy : Bool
  createAcknowledged : Bool
  poisoned : Bool
  quiesced : Bool
  effects : Nat
  lastDeleteAuthority : Option Nat
  deriving DecidableEq, Repr

def initial (platform : Platform := .absent) : State :=
  ⟨.absent, platform, 0, 7, true, 0, false, false, false, false, 0, none⟩

def owned (phase : Phase) : Bool :=
  phase == .ownedIncomplete || phase == .complete

def admitted (s : State) (a : Admission) (bytes records chain : Nat) : Prop :=
  s.currentValid = true ∧ a.profile = 3 ∧ a.authenticated = true ∧ a.framingValid = true ∧
  a.descriptorValid = true ∧ a.copyVerified = true ∧
  a.authority = s.currentAuthority ∧ bytes ≤ 33554432 ∧ records < 256 ∧ chain ≤ 32

instance (s : State) (a : Admission) (bytes records chain : Nat) :
    Decidable (admitted s a bytes records chain) := inferInstanceAs (Decidable (_ ∧ _))

inductive Event where
  | beginPublish (admission : Admission) (encodedBytes records rootChain : Nat)
  | createSuccess
  | createUnknown (actuallyCreated : Bool)
  | foreignExists
  | saveOwnership
  | markComplete
  | saveFailure
  | finish
  | loseReply
  | crash
  | reopen
  | revoke
  | rotateAuthority (authority version : Nat)
  | invalidateAuthority
  | checkIdle
  | quiesce
  deriving DecidableEq, Repr

/-- One operation lock spans durable intent, creation, ownership save and reply.
Only successful durable ownership save can enable snapshot deletion. -/
def activeStep (s : State) : Event → Option State
  | .beginPublish a bytes records chain =>
    if s.busy = false ∧ s.poisoned = false ∧ s.phase = .absent ∧
        admitted s a bytes records chain then
      some {s with phase := .intent, originalAuthority := a.authority, busy := true, createAcknowledged := false}
    else none
  | .createSuccess =>
    if s.busy = true ∧ s.poisoned = false ∧ s.phase = .intent ∧
        s.platform = .absent then
      some {s with platform := .ours, createAcknowledged := true, effects := s.effects + 1}
    else none
  | .createUnknown created =>
    if s.busy = true ∧ s.poisoned = false ∧ s.phase = .intent ∧
        s.platform = .absent then
      some {s with platform := if created then .ours else .absent, busy := false, createAcknowledged := false, effects := s.effects + if created then 1 else 0}
    else none
  | .foreignExists =>
    if s.busy = true ∧ s.phase = .intent ∧ s.platform = .foreign then
      some {s with phase := .absent, busy := false, createAcknowledged := false}
    else none
  | .saveOwnership =>
    if s.busy = true ∧ s.poisoned = false ∧ s.phase = .intent ∧
        s.createAcknowledged = true ∧ s.platform = .ours then
      some {s with phase := .ownedIncomplete, createAcknowledged := false}
    else none
  | .markComplete =>
    if s.busy = true ∧ s.poisoned = false ∧ s.phase = .ownedIncomplete ∧
        s.originalAuthority = s.currentAuthority ∧ s.currentValid = true then
      some {s with phase := .complete}
    else none
  | .saveFailure =>
    if s.busy = true then
      some {s with poisoned := true, busy := false, createAcknowledged := false}
    else none
  | .finish | .loseReply =>
    if s.busy = true then some {s with busy := false, createAcknowledged := false} else none
  | .crash =>
    some {s with busy := false, createAcknowledged := false, poisoned := false}
  | .reopen =>
    if s.busy = false ∧ s.poisoned = false ∧ s.phase = .complete ∧
        s.originalAuthority = s.currentAuthority ∧ s.platform = .ours ∧ s.currentValid = true then
      some {s with effects := s.effects + 1}
    else none
  | .revoke =>
    if s.busy = false ∧ s.poisoned = false then
      if s.phase = .absent then some s
      else if owned s.phase = true ∧ s.platform = .ours then
        some {s with phase := .absent, platform := .absent, effects := s.effects + 1, lastDeleteAuthority := some s.originalAuthority}
      else none
    else none
  | .rotateAuthority authority version =>
    if s.tufFloor ≤ version then some {s with currentAuthority := authority, currentValid := true, tufFloor := version}
    else none
  | .invalidateAuthority => some {s with currentValid := false}
  | .checkIdle => some s
  | .quiesce =>
    if s.busy = false ∧ s.poisoned = false ∧ s.phase = .absent ∧ s.platform = .absent then
      some {s with quiesced := true}
    else none

/-- The deployment marker is durable and checked before every request/effect.
Removing it is an external deployment operation, outside this request grammar. -/
def step (s : State) (e : Event) : Option State :=
  if s.quiesced then none else activeStep s e

def Safe (s : State) : Prop := owned s.phase = true → s.platform = .ours

theorem step_preserves_owned_platform (s t : State) (e : Event)
    (safe : Safe s) (ok : step s e = some t) : Safe t := by
  unfold step at ok
  split at ok
  · contradiction
  · cases e <;> simp only [activeStep] at ok
    all_goals repeat first | split at ok | cases ok
    all_goals simp_all [Safe, owned]
    all_goals first | subst t | obtain ⟨_, rfl⟩ := ok
    all_goals simp_all [Safe, owned]

theorem arbitrary_history_owned_platform (platform : Platform) (events : List Event) :
    Safe (Enclave.Protocol.run step (initial platform) events) := by
  exact Enclave.Protocol.run_invariant step Safe
    (fun s e t hs ht => step_preserves_owned_platform s t e hs ht)
    (initial platform) events (by simp [Safe, initial, owned])

theorem intent_does_not_grant_delete (s : State) (intent : s.phase = .intent) :
    step s .revoke = none := by
  simp [step, activeStep, intent, owned]

theorem uncertain_creation_refuses_automatic_cleanup (s : State)
    (events : List Event)
    (stillUncertain : (Enclave.Protocol.run step s events).phase = .intent) :
    step (Enclave.Protocol.run step s events) .revoke = none :=
  intent_does_not_grant_delete _ stillUncertain

theorem step_preserves_foreign (s t : State) (e : Event)
    (foreign : s.platform = .foreign) (ok : step s e = some t) :
    t.platform = .foreign := by
  unfold step at ok
  split at ok
  · contradiction
  · cases e <;> simp only [activeStep] at ok
    all_goals repeat first | split at ok | cases ok
    all_goals simp_all

theorem foreign_eexist_never_owned (events : List Event) :
    let final := Enclave.Protocol.run step (initial .foreign) events
    final.platform = .foreign ∧ owned final.phase = false := by
  have foreign := Enclave.Protocol.run_invariant step (fun s => s.platform = .foreign)
    (fun s e t hs ht => step_preserves_foreign s t e hs ht)
    (initial .foreign) events rfl
  have safe := arbitrary_history_owned_platform .foreign events
  refine ⟨foreign, ?_⟩
  cases h : owned (Enclave.Protocol.run step (initial .foreign) events).phase
  · rfl
  · have impossible := safe h
    rw [foreign] at impossible
    contradiction

theorem revoke_uses_original_authority (s t : State) (hasRecord : s.phase ≠ .absent)
    (ok : step s .revoke = some t) :
    t.lastDeleteAuthority = some s.originalAuthority := by
  simp only [step] at ok
  split at ok
  · contradiction
  · simp only [activeStep] at ok
    split at ok
    · try simp only [hasRecord, ↓reduceIte] at ok
      split at ok
      · cases ok; rfl
      · contradiction
    · contradiction

theorem reopen_requires_current_authority (s t : State) (ok : step s .reopen = some t) :
    s.phase = .complete ∧ s.originalAuthority = s.currentAuthority ∧ s.currentValid = true := by
  simp only [step] at ok
  split at ok
  · contradiction
  · simp only [activeStep] at ok
    split at ok
    · rename_i gate
      exact ⟨gate.2.2.1, gate.2.2.2.1, gate.2.2.2.2.2⟩
    · contradiction

theorem quiesced_no_later_effect (s : State) (events : List Event)
    (quiesced : s.quiesced = true) : Enclave.Protocol.run step s events = s := by
  induction events with
  | nil => rfl
  | cons e es ih => simpa [Enclave.Protocol.run, step, quiesced] using ih

theorem state_overflow_precedes_effect_or_overwrite (s : State) (a : Admission)
    (bytes records chain : Nat) (overflow : bytes > 33554432 ∨ records ≥ 256 ∨ chain > 32) :
    step s (.beginPublish a bytes records chain) = none := by
  simp only [step]
  split
  · rfl
  · simp only [activeStep]
    split
    · rename_i gate
      have bounds := gate.2.2.2
      simp only [admitted] at bounds
      omega
    · rfl

theorem crash_keeps_durable_ownership_and_authority (s t : State)
    (ok : step s .crash = some t) :
    t.phase = s.phase ∧ t.platform = s.platform ∧
    t.originalAuthority = s.originalAuthority ∧ t.tufFloor = s.tufFloor := by
  simp only [step] at ok
  split at ok
  · contradiction
  · simp only [activeStep] at ok
    cases ok
    exact ⟨rfl, rfl, rfl, rfl⟩

theorem lost_reply_keeps_durable_record (s t : State)
    (ok : step s .loseReply = some t) : t.phase = s.phase ∧ t.platform = s.platform := by
  simp only [step] at ok
  split at ok
  · contradiction
  · simp only [activeStep] at ok
    split at ok
    · cases ok; exact ⟨rfl, rfl⟩
    · contradiction

theorem operation_lock_blocks_quiescence (s : State) (busy : s.busy = true) :
    step s .quiesce = none := by simp [step, activeStep, busy]

theorem step_never_lowers_tuf_floor (s t : State) (e : Event)
    (ok : step s e = some t) : s.tufFloor ≤ t.tufFloor := by
  unfold step at ok
  split at ok
  · contradiction
  · cases e <;> simp only [activeStep] at ok
    all_goals repeat first | split at ok | cases ok
    all_goals simp_all
    all_goals first | subst t | obtain ⟨_, rfl⟩ := ok
    all_goals simp_all

theorem arbitrary_history_tuf_floor_monotone (s : State) (events : List Event) :
    s.tufFloor ≤ (Enclave.Protocol.run step s events).tufFloor := by
  exact Enclave.Protocol.run_invariant step (fun t => s.tufFloor ≤ t.tufFloor)
    (fun a e b ha hb => Nat.le_trans ha (step_never_lowers_tuf_floor a b e hb))
    s events (Nat.le_refl _)

end Enclave.SnapshotBrokerProtocol
