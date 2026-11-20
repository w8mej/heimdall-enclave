import Enclave.ProtocolTrace

/-!
LAT-01, bounded cancellation subset, source checkpoint 23c7cd83.

`DownloadCancellation::{begin,advance,finish,observe,validate}`, PendingWipe Drop
and the serialized Wipe branch of service.rs motivate these separate steps.
Both native generation advances are explicit: begin before State, then a second
checked advance in the locked Wipe before cleanup. Either can exhaust.
This is an executable abstract model, not Rust extraction or a simulation proof.
Guard IDs represent linear reservations, then RAII ownership after fencing;
the atomic pending count is related to that list by a proved reachable invariant. Nat values
are checked against explicit machine bounds before increment, never wrapped.
The boot identity denotes a fresh service-instance identity, not a persisted Rust
nonce. Freshness across restart is an explicit external premise.

Only cancellation/serialization and the two release race windows are modeled.
TUF, custody/lease, crypto, eager closure, publication ownership, OS descriptor
lifetime and durability are NOT established here. Cleanup and journal outcomes
are supplied primitive results; success must occur in order before latch clear.
The historical `Release` model below intentionally preserves the old check/effect
races and counterexamples. Its `desiredChecked*` events remain stronger atomic
specifications. The separate `LocalSerial` model appended on 2026-11-15 represents
the implemented local mutex ownership across validation and actual bounded send.
It is not a distributed custody/CAS, deadline-progress or Rust-refinement proof.
The appended source is pending pinned Lean/Lake validation; no proof PASS is
claimed by the source update itself.
-/
namespace Enclave.TransportAdmission

structure Limits where
  generationMax : Nat
  pendingMax : Nat
  deriving DecidableEq, Repr

/-- u64 generation and 64-bit usize on the reviewed Darwin arm64 target. -/
def machineLimits : Limits := ⟨2^64-1, 2^64-1⟩

inductive Phase where
  | absent | reserved | fenced | ready | entered | advanced | cleaned | failed | finished
  deriving DecidableEq, Repr

structure Cancellation where
  boot : Nat
  generation : Nat := 0
  pending : Nat := 0
  blocked : Bool := false
  guards : List Nat := []
  phase : Nat → Phase := fun _ => .absent
  owner : Option Nat := none

def initial (boot : Nat) : Cancellation := { boot }

def setPhase (s : Cancellation) (id : Nat) (p : Phase) : Nat → Phase :=
  fun key => if key = id then p else s.phase key

def dropGuard (s : Cancellation) (id : Nat) : Cancellation :=
  {s with pending := s.pending-1, guards := s.guards.erase id, phase := setPhase s id .absent}

inductive Event where
  | reserve (authenticated : Bool) (id : Nat)
  | fence (id : Nat)
  | advance (id : Nat)
  | enter (id : Nat)
  | advanceLocked (id : Nat)
  | cleanup (id : Nat) (ok : Bool)
  | journal (id : Nat) (ok : Bool)
  | abort (id : Nat)
  | drop (id : Nat)
  deriving DecidableEq, Repr

/-- `none` is rejected with no mutation; exhaustion during advance unwinds its
already-created guard but retains blocked, matching PendingWipe Drop on `?`. -/
def step (lim : Limits) (s : Cancellation) : Event → Option Cancellation
  | .reserve authenticated id =>
    if authenticated = true ∧ id ∉ s.guards ∧ s.pending < lim.pendingMax then
      some {s with pending := s.pending+1, guards := id :: s.guards, phase := setPhase s id .reserved}
    else none
  | .fence id =>
    if id ∈ s.guards ∧ s.phase id = .reserved then
      some {s with blocked := true, phase := setPhase s id .fenced}
    else none
  | .advance id =>
    if id ∈ s.guards ∧ s.phase id = .fenced then
      if s.generation < lim.generationMax then
        some {s with generation := s.generation+1, phase := setPhase s id .ready}
      else some (dropGuard s id)
    else none
  | .enter id =>
    if id ∈ s.guards ∧ s.phase id = .ready ∧ s.owner = none then
      some {s with blocked := true, owner := some id, phase := setPhase s id .entered}
    else none
  | .cleanup id ok =>
    if id ∈ s.guards ∧ s.phase id = .advanced ∧ s.owner = some id then
      if ok then some {s with phase := setPhase s id .cleaned}
      else some {s with owner := none, phase := setPhase s id .failed}
    else none
  | .journal id ok =>
    if id ∈ s.guards ∧ s.phase id = .cleaned ∧ s.owner = some id then
      if ok then some {s with blocked := false, owner := none, phase := setPhase s id .finished}
      else some {s with owner := none, phase := setPhase s id .failed}
    else none
  | .drop id =>
    if id ∈ s.guards ∧ (s.phase id = .ready ∨ s.phase id = .failed ∨ s.phase id = .finished) then
      some (dropGuard s id)
    else none
  | .abort id =>
    if id ∈ s.guards ∧ s.owner = some id ∧
        (s.phase id = .entered ∨ s.phase id = .advanced ∨ s.phase id = .cleaned) then
      some {s with owner := none, phase := setPhase s id .failed}
    else none
  | .advanceLocked id =>
    if id ∈ s.guards ∧ s.phase id = .entered ∧ s.owner = some id then
      if s.generation < lim.generationMax then
        some {s with generation := s.generation+1, phase := setPhase s id .advanced}
      else some {s with owner := none, phase := setPhase s id .failed}
    else none

def trace (lim : Limits) := Enclave.Protocol.run (step lim)

def Counters (lim : Limits) (s : Cancellation) : Prop :=
  s.pending = s.guards.length ∧ s.generation ≤ lim.generationMax ∧
    s.pending ≤ lim.pendingMax

theorem step_preserves_counters (lim : Limits) (s t : Cancellation) (e : Event)
    (hs : Counters lim s) (h : step lim s e = some t) : Counters lim t := by
  rcases hs with ⟨hp, hg, hb⟩
  cases e <;> simp only [step] at h
  all_goals repeat first | split at h | cases h
  all_goals try (simp at h; subst t)
  all_goals simp_all [Counters, dropGuard, List.length_erase_of_mem]
  all_goals omega

/-- Arbitrary finite event histories preserve checked bounds and RAII count. -/
theorem arbitrary_history_preserves_counter_bounds (lim : Limits) (boot : Nat)
    (es : List Event) : Counters lim (trace lim (initial boot) es) := by
  apply Enclave.Protocol.run_invariant (step lim) (Counters lim)
    (fun s e t hs h => step_preserves_counters lim s t e hs h) (initial boot) es
  simp [Counters, initial]

theorem unauthorized_wipe_preserves_authority (lim : Limits) (s : Cancellation)
    (id : Nat) : step lim s (.reserve false id) = none := by
  simp [step]

theorem full_pending_refuses_without_leak (lim : Limits) (s : Cancellation)
    (id : Nat) (h : lim.pendingMax ≤ s.pending) :
    step lim s (.reserve true id) = none := by
  simp [step, show ¬s.pending < lim.pendingMax by omega]

theorem exhausted_advance_unwinds_guard (lim : Limits) (s : Cancellation) (id : Nat)
    (member : id ∈ s.guards) (phase : s.phase id = .fenced)
    (exhausted : lim.generationMax ≤ s.generation) :
    step lim s (.advance id) = some (dropGuard s id) ∧
    (dropGuard s id).generation = s.generation ∧
    (dropGuard s id).pending = s.pending-1 ∧
    (dropGuard s id).blocked = s.blocked := by
  simp [step, member, phase, show ¬s.generation < lim.generationMax by omega, dropGuard]

theorem generation_monotone (lim : Limits) (s t : Cancellation) (e : Event)
    (h : step lim s e = some t) : s.generation ≤ t.generation := by
  cases e <;> simp only [step] at h
  all_goals repeat first | split at h | cases h
  all_goals try (simp at h; subst t)
  all_goals simp_all [dropGuard]

theorem boot_preserved (lim : Limits) (s t : Cancellation) (e : Event)
    (h : step lim s e = some t) : t.boot = s.boot := by
  cases e <;> simp only [step] at h
  all_goals repeat first | split at h | cases h
  all_goals try (simp at h; subst t)
  all_goals simp_all [dropGuard]

structure Epoch where
  boot : Nat
  generation : Nat
  deriving DecidableEq, Repr

def current (lim : Limits) (s : Cancellation) (epoch : Epoch) : Prop :=
  epoch.boot = s.boot ∧ epoch.generation = s.generation ∧
  s.blocked = false ∧ s.pending = 0 ∧ s.generation < lim.generationMax

instance (lim : Limits) (s : Cancellation) (epoch : Epoch) :
    Decidable (current lim s epoch) := inferInstanceAs (Decidable (_ ∧ _ ∧ _ ∧ _ ∧ _))

theorem stale_epoch_remains_invalid (lim : Limits) (s : Cancellation)
    (epoch : Epoch) (es : List Event) (h : epoch.generation < s.generation) :
    ¬current lim (trace lim s es) epoch := by
  have hm := Enclave.Protocol.run_invariant (step lim)
    (fun t => epoch.generation < t.generation)
    (fun a e b ha hb => Nat.lt_of_lt_of_le ha (generation_monotone lim a b e hb)) s es h
  simp only [current, trace]
  omega

theorem exhausted_generation_never_current (lim : Limits) (s : Cancellation)
    (epoch : Epoch) (es : List Event) (h : lim.generationMax ≤ s.generation) :
    ¬current lim (trace lim s es) epoch := by
  have hm := Enclave.Protocol.run_invariant (step lim)
    (fun t => lim.generationMax ≤ t.generation)
    (fun a e b ha hb => Nat.le_trans ha (generation_monotone lim a b e hb)) s es h
  simp only [current, trace]
  omega

theorem pending_guard_denies (lim : Limits) (s : Cancellation) (epoch : Epoch)
    (h : 0 < s.pending) : ¬current lim s epoch := by
  simp [current, show s.pending ≠ 0 by omega]

theorem failed_cleanup_keeps_blocked (lim : Limits) (s t : Cancellation) (id : Nat)
    (h : step lim s (.cleanup id false) = some t) : t.blocked = s.blocked := by
  simp only [step, Bool.false_eq_true, ↓reduceIte] at h
  split at h <;> simp_all
  all_goals subst t <;> rfl

theorem failed_journal_keeps_blocked (lim : Limits) (s t : Cancellation) (id : Nat)
    (h : step lim s (.journal id false) = some t) : t.blocked = s.blocked := by
  simp only [step, Bool.false_eq_true, ↓reduceIte] at h
  split at h <;> simp_all
  all_goals subst t <;> rfl

theorem drop_does_not_recover (lim : Limits) (s t : Cancellation) (id : Nat)
    (h : step lim s (.drop id) = some t) : t.blocked = s.blocked := by
  simp only [step] at h
  split at h <;> simp_all [dropGuard]
  all_goals subst t <;> rfl

/-- Reassertion under serialized State, including after an earlier success. -/
theorem serialized_wipe_reasserts_blocked (lim : Limits) (s t : Cancellation) (id : Nat)
    (h : step lim s (.enter id) = some t) : t.blocked = true ∧ t.owner = some id := by
  simp only [step] at h
  split at h <;> simp_all
  all_goals subst t <;> simp

/-- The real locked Wipe performs a SECOND checked generation increment.
Exhaustion fails before cleanup and leaves the guard for normal outer Drop. -/
theorem locked_advance_preserves_blocked (lim : Limits) (s t : Cancellation) (id : Nat)
    (h : step lim s (.advanceLocked id) = some t) : t.blocked = s.blocked := by
  simp only [step] at h
  split at h
  · split at h <;> simp only [Option.some.injEq] at h <;> subst t <;> rfl
  · contradiction

theorem exhausted_locked_advance_keeps_failure_guard (lim : Limits) (s : Cancellation) (id : Nat)
    (member : id ∈ s.guards) (phase : s.phase id = .entered) (owner : s.owner = some id)
    (exhausted : lim.generationMax ≤ s.generation) :
    step lim s (.advanceLocked id) =
      some {s with owner := none, phase := setPhase s id .failed} := by
  simp [step, member, phase, owner, show ¬s.generation < lim.generationMax by omega]

/-- Every successful clear is the journal step after this guard's cleanup. -/
theorem only_successful_journal_clears (lim : Limits) (s t : Cancellation) (e : Event)
    (h : step lim s e = some t) (before : s.blocked = true) (after : t.blocked = false) :
    ∃ id, e = .journal id true ∧ s.phase id = .cleaned ∧ s.owner = some id := by
  cases e <;> simp only [step] at h
  all_goals repeat first | split at h | cases h
  all_goals try (simp at h; subst t)
  all_goals simp_all [dropGuard]

/-- Arbitrary finite suffixes cannot recover the latch without an actual
successful serialized journal event. This is safety, not eventual recovery. -/
theorem blocked_sticky_until_successful_journal (lim : Limits) (s : Cancellation)
    (es : List Event) (blocked : s.blocked = true)
    (noSuccess : ∀ e ∈ es, ∀ id, e ≠ .journal id true) :
    (trace lim s es).blocked = true := by
  induction es generalizing s with
  | nil => exact blocked
  | cons e es ih =>
    have tail : ∀ e ∈ es, ∀ id, e ≠ .journal id true :=
      fun a ha id => noSuccess a (by simp [ha]) id
    cases h : step lim s e with
    | none => simpa [trace, Enclave.Protocol.run, h] using ih s blocked tail
    | some t =>
      have bt : t.blocked = true := by
        cases ht : t.blocked with
        | true => rfl
        | false =>
          obtain ⟨id, he, _, _⟩ := only_successful_journal_clears lim s t e h blocked ht
          exact False.elim (noSuccess e (by simp) id he)
      simpa [trace, Enclave.Protocol.run, h] using ih t bt tail

theorem last_serialized_wipe_controls_latch (lim : Limits)
    (s entered advanced failed dropped : Cancellation) (id : Nat) (es : List Event)
    (enter : step lim s (.enter id) = some entered)
    (advance : step lim entered (.advanceLocked id) = some advanced)
    (failure : step lim advanced (.cleanup id false) = some failed)
    (drop : step lim failed (.drop id) = some dropped)
    (noSuccess : ∀ e ∈ es, ∀ id, e ≠ .journal id true) :
    (trace lim dropped es).blocked = true := by
  apply blocked_sticky_until_successful_journal lim dropped es
  · rw [drop_does_not_recover lim failed dropped id drop,
        failed_cleanup_keeps_blocked lim advanced failed id failure,
        locked_advance_preserves_blocked lim entered advanced id advance]
    exact (serialized_wipe_reasserts_blocked lim s entered id enter).1
  · exact noSuccess

theorem fresh_boot_rejects_old_epoch (lim : Limits) (oldBoot newBoot generation : Nat)
    (fresh : oldBoot ≠ newBoot) :
    ¬current lim (initial newBoot) ⟨oldBoot, generation⟩ := by
  simp [current, initial, fresh]

/-- Observe is three ordered loads, not a coherent atomic snapshot. -/
structure Observation where
  generation : Nat := 0
  blocked : Bool := true
  pending : Nat := 1
  deriving DecidableEq, Repr

inductive Profile where | l1 | l2 | l3
  deriving DecidableEq, Repr

structure Release where
  cancellation : Cancellation
  profile : Profile
  observation : Observation := {}
  checked : Option Epoch := none
  queued : Option Epoch := none
  receipts : List Epoch := []
  sent : List Epoch := []

inductive ReleaseEvent where
  | wipe (event : Event)
  | readGeneration | readBlocked | readPending
  | validate (epoch : Epoch)
  | appendReceipt | handlerReturn | sendQueued
  | desiredCheckedReceipt (epoch : Epoch)
  | desiredCheckedSend (epoch : Epoch)
  deriving DecidableEq, Repr

def releaseStep (lim : Limits) (s : Release) : ReleaseEvent → Option Release
  | .wipe event => (step lim s.cancellation event).map fun c => {s with cancellation := c}
  | .readGeneration => some {s with observation.generation := s.cancellation.generation}
  | .readBlocked => some {s with observation.blocked := s.cancellation.blocked}
  | .readPending => some {s with observation.pending := s.cancellation.pending}
  | .validate epoch =>
    if epoch.boot = s.cancellation.boot ∧ epoch.generation = s.observation.generation ∧
        s.observation.blocked = false ∧ s.observation.pending = 0 ∧
        s.observation.generation < lim.generationMax then
      some {s with checked := some epoch}
    else none
  | .appendReceipt => s.checked.map fun epoch => {s with receipts := s.receipts ++ [epoch]}
  | .handlerReturn => s.checked.map fun epoch => {s with queued := some epoch}
  | .sendQueued => s.queued.map fun epoch => {s with sent := s.sent ++ [epoch], queued := none}
  | .desiredCheckedReceipt epoch =>
    if current lim s.cancellation epoch then
      some {s with receipts := s.receipts ++ [epoch]} else none
  | .desiredCheckedSend epoch =>
    if current lim s.cancellation epoch then
      some {s with sent := s.sent ++ [epoch]} else none

def releaseTrace (lim : Limits) := Enclave.Protocol.run (releaseStep lim)

/-- This theorem applies ONLY to the explicitly strengthened atomic contract. -/
theorem desired_release_requires_current_authority (lim : Limits) (s t : Release)
    (epoch : Epoch) (h : releaseStep lim s (.desiredCheckedReceipt epoch) = some t) :
    current lim s.cancellation epoch := by
  simp only [releaseStep] at h
  split at h <;> simp_all
  all_goals subst t <;> rfl

theorem desired_send_requires_current_authority (lim : Limits) (s t : Release)
    (epoch : Epoch) (h : releaseStep lim s (.desiredCheckedSend epoch) = some t) :
    current lim s.cancellation epoch := by
  simp only [releaseStep] at h
  split at h <;> simp_all
  all_goals subst t <;> rfl


/-!
Local ReleasePermit correspondence, source increment 2026-11-15.

`enclave-core::ipc::ReleasePermit::release` performs optional remote preflight
outside its local serial, then revalidates and retains the serial across the
actual `write_release_before` call. Custody's `revoke_cas_keys` sets cancellation
before waiting, then disables and checked-increments generation under that same
serial. A completed handoff before fence establishment stands. Already delivered
prefixes cannot be recalled; a failed partial handoff closes without replay.
The cancellation-request flag alone does not deny an already admitted handoff:
the source ReleasePermit validator checks enabled/current generation under the
serial. The established fence disables that authority. This is a scoped model
of the intended local contract, not a proof of Rust/OS source refinement.

The serial owner below covers only the bounded handoff primitive. Factor/MDS/
policy validation, State admission, encoding, fsync and remote preflight are
outside it. `fullFactors` is an explicit external premise, not a crypto theorem.
`finish true` denotes a complete successful handoff, not an ACK oracle for prior
partial bytes. Time is a supplied monotone host clock. Timeout progress, OS thread
scheduling, real mutex correspondence, device/SEP correctness, distributed CAS
revocation and physical/backend erasure are excluded. No theorem here bounds
physical event to notification/fence latency. Historical models above remain
unchanged so old hostile schedules retain their original evidence meaning.
-/
namespace LocalSerial

structure State where
  boot : Nat
  generation : Nat := 0
  enabled : Bool := true
  cancelled : Bool := false
  owner : Option (Epoch × Nat) := none
  now : Nat := 0
  fences : Nat := 0
  sent : List Epoch := []
  uncertainPrefixes : Nat := 0
  deriving DecidableEq, Repr

inductive Action where
  | requestRevoke
  | establishFence
  | beginFresh (epoch : Epoch)
  | commitFresh (epoch : Epoch) (fullFactors : Bool)
  | beginHandoff (epoch : Epoch) (exclusiveDeadline : Nat)
  | finish (complete : Bool)
  | tick (now : Nat)
  deriving DecidableEq, Repr

def step (generationMax : Nat) (s : State) : Action → Option State
  | .requestRevoke => some {s with cancelled := true}
  | .establishFence =>
    if s.owner = none then
      some {s with
        enabled := false
        cancelled := true
        fences := s.fences + 1
        generation := if s.generation < generationMax then s.generation + 1 else s.generation}
    else none
  | .beginFresh epoch =>
    if s.owner = none ∧ epoch.boot = s.boot ∧ epoch.generation = s.generation ∧
        s.generation < generationMax then
      some {s with cancelled := false}
    else none
  | .commitFresh epoch fullFactors =>
    if s.owner = none ∧ epoch.boot = s.boot ∧ epoch.generation = s.generation ∧
        s.generation < generationMax ∧ s.cancelled = false ∧ fullFactors = true then
      some {s with enabled := true}
    else none
  | .beginHandoff epoch deadline =>
    if s.owner = none ∧ epoch.boot = s.boot ∧ epoch.generation = s.generation ∧
        s.generation < generationMax ∧ s.enabled = true ∧ s.now < deadline then
      some {s with owner := some (epoch, deadline)}
    else none
  | .finish complete =>
    match s.owner with
    | none => none
    | some (epoch, deadline) =>
      if complete then
        if s.now < deadline then some {s with owner := none, sent := s.sent ++ [epoch]}
        else none
      else some {s with owner := none, uncertainPrefixes := s.uncertainPrefixes + 1}
  | .tick now => if s.now ≤ now then some {s with now} else none

def trace (generationMax : Nat) := Enclave.Protocol.run (step generationMax)

theorem held_serial_prevents_fence (maximum : Nat) (s : State)
    (epoch : Epoch) (deadline : Nat) (held : s.owner = some (epoch, deadline)) :
    step maximum s .establishFence = none := by
  simp [step, held]

theorem established_fence_is_disabled_and_serial_free (maximum : Nat) (s t : State)
    (fence : step maximum s .establishFence = some t) :
    s.owner = none ∧ t.owner = none ∧ t.enabled = false ∧ t.cancelled = true := by
  simp only [step] at fence
  split at fence <;> simp_all
  all_goals subst t <;> simp_all

theorem handoff_requires_current_boot_generation_and_time (maximum : Nat) (s t : State)
    (epoch : Epoch) (deadline : Nat)
    (handoff : step maximum s (.beginHandoff epoch deadline) = some t) :
    epoch.boot = s.boot ∧ epoch.generation = s.generation ∧
      s.enabled = true ∧ s.now < deadline := by
  simp only [step] at handoff
  split at handoff <;> simp_all

theorem old_generation_cannot_begin_handoff (maximum : Nat) (s : State)
    (epoch : Epoch) (deadline : Nat) (old : epoch.generation < s.generation) :
    step maximum s (.beginHandoff epoch deadline) = none := by
  have different : epoch.generation ≠ s.generation := Nat.ne_of_lt old
  simp [step, different]

theorem expired_handoff_cannot_report_complete (maximum : Nat) (s : State)
    (epoch : Epoch) (deadline : Nat) (held : s.owner = some (epoch, deadline))
    (expired : deadline ≤ s.now) : step maximum s (.finish true) = none := by
  simp [step, held, show ¬s.now < deadline by omega]

theorem partial_failure_cannot_record_delivery (maximum : Nat) (s : State)
    (epoch : Epoch) (deadline : Nat) (held : s.owner = some (epoch, deadline)) :
    step maximum s (.finish false) = some
      {s with owner := none, uncertainPrefixes := s.uncertainPrefixes + 1} := by
  simp [step, held]

theorem generation_monotone (maximum : Nat) (s t : State) (action : Action)
    (transition : step maximum s action = some t) : s.generation ≤ t.generation := by
  cases action <;> simp only [step] at transition
  all_goals repeat first | split at transition | cases transition
  all_goals try (simp at transition; subst t)
  all_goals simp_all
  all_goals omega

/-- Exhaustion is a permanent refusal, even after fresh-factor attempts. -/
theorem exhausted_generation_refuses_authorization_and_handoff
    (maximum : Nat) (s : State) (epoch : Epoch) (deadline : Nat)
    (exhausted : maximum ≤ s.generation) :
    step maximum s (.beginFresh epoch) = none ∧
      step maximum s (.commitFresh epoch true) = none ∧
      step maximum s (.beginHandoff epoch deadline) = none := by
  have terminal : ¬s.generation < maximum := by omega
  simp [step, terminal]

theorem exhausted_generation_remains_refused (maximum : Nat) (s : State)
    (epoch : Epoch) (actions : List Action) (deadline : Nat)
    (exhausted : maximum ≤ s.generation) :
    step maximum (trace maximum s actions) (.beginHandoff epoch deadline) = none := by
  have remains : maximum ≤ (trace maximum s actions).generation :=
    Enclave.Protocol.run_invariant (step maximum)
      (fun t => maximum ≤ t.generation)
      (fun a e b ha hb => Nat.le_trans ha (generation_monotone maximum a b e hb))
      s actions exhausted
  exact (exhausted_generation_refuses_authorization_and_handoff
    maximum (trace maximum s actions) epoch deadline remains).2.2

example :
    let epoch : Epoch := ⟨7, 4⟩
    let after := trace 4 {boot := 7, generation := 4}
      [.requestRevoke, .establishFence, .beginFresh epoch, .commitFresh epoch true]
    after.generation = 4 ∧ after.enabled = false ∧
      step 4 after (.beginHandoff epoch 10) = none := by
  decide

/-- Arbitrary later fresh-authorize attempts cannot revive an old generation. -/
theorem stale_generation_remains_unstartable (maximum : Nat) (s : State)
    (epoch : Epoch) (actions : List Action) (deadline : Nat)
    (old : epoch.generation < s.generation) :
    step maximum (trace maximum s actions) (.beginHandoff epoch deadline) = none := by
  apply old_generation_cannot_begin_handoff
  exact Enclave.Protocol.run_invariant (step maximum)
    (fun t => epoch.generation < t.generation)
    (fun a e b ha hb => Nat.lt_of_lt_of_le ha (generation_monotone maximum a b e hb))
    s actions old

/-- Positive witness: a pre-fence handoff completes and remains in history;
the later established fence denies another handoff from that old generation. -/
example :
    let epoch : Epoch := ⟨7, 0⟩
    let before : State := {boot := 7}
    let after := trace 4 before [.beginHandoff epoch 10, .requestRevoke,
      .finish true, .establishFence]
    after.sent = [epoch] ∧ after.generation = 1 ∧ after.enabled = false ∧
      step 4 after (.beginHandoff epoch 10) = none := by
  decide

end LocalSerial

end Enclave.TransportAdmission
