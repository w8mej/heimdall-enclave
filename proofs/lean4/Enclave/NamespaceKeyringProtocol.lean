import Enclave.ProtocolTrace

/-!
LAT-03 bounded executable model, not Rust extraction or a cryptographic proof.
Source baseline: cas_keyring.rs, custody service.rs and core sealed.rs at
23c7cd83d67a9ddb86d09dcfce71530335d8dc2e. Namespace/key/envelope identifiers
abstract authenticated decoded bytes. `dek` is a ghost identity preserved by a
correct unwrap/rewrap primitive, not plaintext persisted by the Rust keyring.
The selected-namespace projection uses an empty list for an absent namespace.
It has at most 64 historical epochs, and checked u64 wrapping/data epochs.

Persistence events separate durable state replacement and checkpoint replacement.
Their atomicity/durability, authenticated decoding, exclusive writer and an intact
checkpoint are interface assumptions; whole-directory rollback is not prevented.
The machines below are separately proved slices, not a proved composition.
No engineer identity, SVID membership, SEP, CTAP or signing authority is invented.
-/
namespace Enclave.NamespaceKeyringProtocol

def maxU64 : Nat := 18446744073709551615
def maxU32 : Nat := 4294967295

structure Envelope where
  ns : Nat
  epoch : Nat
  wrapping : Nat
  dek : Nat
  envelopeId : Nat
  deriving DecidableEq, Repr

structure Ring where
  ns : Nat
  floor : Nat := 1
  keys : List Envelope := []
  deriving DecidableEq, Repr

def envelopeShape (k : Envelope) : Prop :=
  0 < k.epoch ∧ k.epoch ≤ maxU64 ∧ 0 < k.wrapping ∧ k.wrapping ≤ maxU64

/-- Computed structural validator, mirroring decoded map/epoch/floor checks.
The absent namespace projection is allowed to have no keys. -/
def ringShape (r : Ring) : Prop :=
  0 < r.floor ∧ r.floor ≤ maxU64 ∧ r.keys.length ≤ 64 ∧
  (r.keys.map Envelope.epoch).Nodup ∧
  ∀ k ∈ r.keys, envelopeShape k ∧ k.ns = r.ns ∧ r.floor ≤ k.wrapping

instance (k : Envelope) : Decidable (envelopeShape k) := inferInstanceAs
  (Decidable (0 < k.epoch ∧ k.epoch ≤ maxU64 ∧ 0 < k.wrapping ∧ k.wrapping ≤ maxU64))
instance (r : Ring) : Decidable (ringShape r) := by
  unfold ringShape
  infer_instance

inductive RingEvent where
  | register (key : Envelope)
  | rewrap (epoch wrapping envelopeId : Nat)
  | retire (floor : Nat)
  deriving DecidableEq, Repr

def ringStep (r : Ring) : RingEvent → Option Ring
  | .register k =>
    if k.ns = r.ns ∧ envelopeShape k ∧ r.floor ≤ k.wrapping ∧
        ¬ r.keys.any (fun old => old.epoch == k.epoch) then
      let next := {r with floor := (if r.keys.isEmpty then k.wrapping else r.floor), keys := r.keys ++ [k]}
      if ringShape next then some next else none
    else none
  | .rewrap epoch wrapping envelopeId =>
    if r.keys.any (fun k => k.epoch == epoch) ∧
        (∀ k ∈ r.keys, k.epoch = epoch → k.wrapping < wrapping) then
      let next := {r with keys := r.keys.map (fun k =>
        if k.epoch = epoch then {k with wrapping := wrapping, envelopeId := envelopeId} else k)}
      if ringShape next then some next else none
    else none
  | .retire floor =>
    if r.keys ≠ [] ∧ r.floor ≤ floor then
      let next := {r with floor := floor}
      if ringShape next then some next else none
    else none

def epochs (r : Ring) : List Nat := r.keys.map Envelope.epoch
def identities (r : Ring) : List (Nat × Nat) := r.keys.map (fun k => (k.epoch, k.dek))

theorem ring_step_validates (r t : Ring) (e : RingEvent)
    (ok : ringStep r e = some t) : ringShape t := by
  cases e <;> simp only [ringStep] at ok
  all_goals repeat' first | split at ok | contradiction
  all_goals try simp_all
  all_goals subst_vars
  all_goals try simp_all

theorem floor_step_monotone (r t : Ring) (e : RingEvent)
    (ok : ringStep r e = some t) : r.floor ≤ t.floor := by
  cases e with
  | register key =>
    simp only [ringStep] at ok
    split at ok
    · rename_i guard
      have lower : r.floor ≤ key.wrapping := guard.2.2.1
      repeat' first | split at ok | contradiction
      all_goals simp_all only [Option.some.injEq]
      all_goals subst t
      all_goals simp_all
    · contradiction
  | rewrap epoch wrapping envelopeId =>
    simp only [ringStep] at ok
    repeat' first | split at ok | contradiction
    all_goals simp_all only [Option.some.injEq]
    all_goals subst t
    all_goals exact Nat.le_refl _
  | retire floor =>
    simp only [ringStep] at ok
    split at ok
    · rename_i guard
      repeat' first | split at ok | contradiction
      all_goals simp_all only [Option.some.injEq]
      all_goals subst t
      all_goals exact guard.2
    · contradiction

theorem history_step_preserves_deks (r t : Ring) (e : RingEvent)
    (ok : ringStep r e = some t) (identity : Nat × Nat)
    (old : identity ∈ identities r) : identity ∈ identities t := by
  cases e <;> simp only [ringStep] at ok
  all_goals repeat' first | split at ok | contradiction
  all_goals try simp_all only [Option.some.injEq]
  all_goals subst t
  all_goals simp only [identities, List.map_append, List.mem_append] at old ⊢
  all_goals first | exact old | exact Or.inl old | skip
  · simp only [List.mem_map] at old ⊢
    obtain ⟨k, member, equal⟩ := old
    refine ⟨_, ⟨k, member, rfl⟩, ?_⟩
    split <;> simp_all

theorem history_never_lost (r : Ring) (events : List RingEvent)
    (identity : Nat × Nat) (old : identity ∈ identities r) :
    identity ∈ identities (Protocol.run ringStep r events) := by
  apply Protocol.run_invariant ringStep (fun t => identity ∈ identities t)
  · intro s e t member ok
    exact history_step_preserves_deks s t e ok identity member
  · exact old

theorem floor_never_decreases (r : Ring) (events : List RingEvent) :
    r.floor ≤ (Protocol.run ringStep r events).floor := by
  apply Protocol.run_invariant ringStep (fun t => r.floor ≤ t.floor)
  · intro s e t lower ok
    exact Nat.le_trans lower (floor_step_monotone s t e ok)
  · exact Nat.le_refl _

theorem arbitrary_history_shape (r : Ring) (events : List RingEvent)
    (initial : ringShape r) : ringShape (Protocol.run ringStep r events) := by
  apply Protocol.run_invariant ringStep ringShape
  · intro s e t _ ok
    exact ring_step_validates s t e ok
  · exact initial

def verifyEnvelope (r : Ring) (key : Envelope) : Bool :=
  decide (envelopeShape key ∧ r.floor ≤ key.wrapping ∧ key ∈ r.keys)

theorem retired_envelope_denied (r : Ring) (key : Envelope)
    (retired : key.wrapping < r.floor) : verifyEnvelope r key = false := by
  simp [verifyEnvelope, Nat.not_le_of_gt retired]

theorem retired_envelope_denied_after_any_history (r : Ring)
    (events : List RingEvent) (key : Envelope) (retired : key.wrapping < r.floor) :
    verifyEnvelope (Protocol.run ringStep r events) key = false := by
  apply retired_envelope_denied
  exact Nat.lt_of_lt_of_le retired (floor_never_decreases r events)

theorem accepted_envelope_has_exact_registered_identity (r : Ring) (key : Envelope)
    (accepted : verifyEnvelope r key = true) : key ∈ r.keys ∧ r.floor ≤ key.wrapping := by
  simp only [verifyEnvelope, decide_eq_true_eq] at accepted
  exact ⟨accepted.2.2, accepted.2.1⟩

/-! Initialized sealed-store projection. `begin` computes checked generation;
writeState and writeCheckpoint are distinct durable effects. `restore` can replay
only a previously written authenticated image, not manufacture a MAC. -/
structure Image where
  generation : Nat
  body : Ring
  deriving DecidableEq, Repr

inductive SavePhase where
  | idle | state | checkpoint
  deriving DecidableEq, Repr

structure Store where
  disk : Image
  checkpoint : Nat
  writerGeneration : Nat
  pending : Option Image := none
  phase : SavePhase := .idle
  online : Bool := true
  poisoned : Bool := false
  archive : List Image := []
  deriving DecidableEq, Repr

inductive StoreEvent where
  | begin (body : Ring)
  | writeState | writeCheckpoint | failSave | crash | restart
  | restore (image : Image)
  deriving DecidableEq, Repr

def storeStep (s : Store) : StoreEvent → Option Store
  | .begin body =>
    if s.online ∧ ¬s.poisoned ∧ s.phase = .idle ∧
        s.writerGeneration < maxU64 ∧ ringShape body then
      some {s with pending := some ⟨s.writerGeneration + 1, body⟩, phase := .state}
    else none
  | .writeState => match s.pending with
    | some image => if s.online ∧ ¬s.poisoned ∧ s.phase = .state then
        some {s with disk := image, archive := image :: s.archive, phase := .checkpoint}
      else none
    | none => none
  | .writeCheckpoint => match s.pending with
    | some image => if s.online ∧ ¬s.poisoned ∧ s.phase = .checkpoint then
        some {s with checkpoint := image.generation, writerGeneration := image.generation, pending := none, phase := .idle}
      else none
    | none => none
  | .failSave => some {s with poisoned := true, pending := none, phase := .idle}
  | .crash => some {s with online := false, poisoned := false, pending := none, phase := .idle}
  | .restart =>
    if ¬s.online ∧ s.checkpoint ≤ s.disk.generation ∧
        0 < s.disk.generation ∧ s.disk.generation ≤ maxU64 ∧ ringShape s.disk.body then
      some {s with online := true, writerGeneration := s.disk.generation}
    else none
  | .restore image => if image ∈ s.archive then some {s with disk := image} else none

theorem accepted_restart_checkpoint_relative (s t : Store)
    (accepted : storeStep s .restart = some t) :
    s.checkpoint ≤ t.disk.generation ∧ t.writerGeneration = t.disk.generation := by
  simp only [storeStep] at accepted
  split at accepted <;> simp_all
  subst_vars
  simp_all

theorem write_state_does_not_commit_checkpoint (s t : Store)
    (written : storeStep s .writeState = some t) : t.checkpoint = s.checkpoint := by
  simp only [storeStep] at written
  split at written <;> try contradiction
  split at written <;> simp_all
  subst_vars
  simp_all

theorem acknowledged_save_has_matching_checkpoint (s t : Store)
    (written : storeStep s .writeCheckpoint = some t) :
    t.checkpoint = t.writerGeneration ∧ t.pending = none ∧ t.phase = .idle := by
  simp only [storeStep] at written
  split at written <;> try contradiction
  split at written <;> simp_all
  subst_vars
  simp_all

theorem poisoned_store_cannot_begin (s : Store) (body : Ring)
    (poisoned : s.poisoned = true) : storeStep s (.begin body) = none := by
  simp [storeStep, poisoned]

/-- Concrete authenticated state-ahead/checkpoint crash cut. The newer floor is
accepted after restart, yet restoring ONLY the old authenticated state is still
accepted by the unchanged checkpoint. This refutes unconditional monotonicity
of every observed restart state, without claiming whole-directory replacement. -/
theorem state_ahead_checkpoint_allows_old_authenticated_state :
    ∃ initial observed replayed : Store,
      observed = Protocol.run storeStep initial
        [.begin { ns := 7, floor := 2, keys := [⟨7, 1, 2, 9, 11⟩] }, .writeState, .crash, .restart] ∧
      observed.online = true ∧ observed.disk.body.floor = 2 ∧
      observed.checkpoint = 1 ∧
      replayed = Protocol.run storeStep observed
        [.restore initial.disk, .crash, .restart] ∧
      replayed.online = true ∧ replayed.disk.body.floor = 1 ∧
      replayed.checkpoint = 1 := by
  let old : Image := ⟨1, {ns := 7, keys := [⟨7, 1, 2, 9, 11⟩]}⟩
  let initial : Store := {disk := old, checkpoint := 1, writerGeneration := 1, archive := [old]}
  refine ⟨initial, _, _, rfl, ?_, ?_, ?_, rfl, ?_, ?_, ?_⟩
  all_goals decide

/-! Migration captures authenticated legacy state BEFORE persisting intent.
Crash loses only runtime pending; child existence and intent remain durable.
An existing child, even empty, never falls back to legacy. -/
structure Migration where
  legacy : Option Ring
  marker : Bool := false
  childExists : Bool := false
  child : Option Ring := none
  pending : Option Ring := none
  deriving DecidableEq, Repr

inductive MigrationEvent where
  | start | createChild | saveChild | crash | removeChild
  | changeLegacy (legacy : Option Ring)
  deriving DecidableEq, Repr

def migrationStep (s : Migration) : MigrationEvent → Option Migration
  | .start => match s.legacy with
    | some ring => if ¬s.marker ∧ ¬s.childExists ∧ ringShape ring then
        some {s with marker := true, pending := some ring} else none
    | none => none
  | .createChild => if s.marker ∧ ¬s.childExists ∧ s.pending.isSome then
      some {s with childExists := true} else none
  | .saveChild => match s.pending with
    | some ring => if s.childExists ∧ s.child = none then
        some {s with child := some ring, pending := none} else none
    | none => none
  | .crash => some {s with pending := none}
  | .removeChild => some {s with childExists := false, child := none, pending := none}
  | .changeLegacy legacy => some {s with legacy := legacy}

def selectedChild (s : Migration) : Option Ring :=
  if s.childExists then s.child else none

theorem migration_marker_step_sticky (s t : Migration) (e : MigrationEvent)
    (marked : s.marker = true) (ok : migrationStep s e = some t) : t.marker = true := by
  cases e <;> simp only [migrationStep] at ok
  all_goals repeat' first | split at ok | contradiction
  all_goals simp_all only [Option.some.injEq]
  all_goals subst t
  all_goals simp_all

theorem migration_marker_history_sticky (s : Migration) (events : List MigrationEvent)
    (marked : s.marker = true) :
    (Protocol.run migrationStep s events).marker = true := by
  apply Protocol.run_invariant migrationStep (fun t => t.marker = true)
  · intro s e t marked ok
    exact migration_marker_step_sticky s t e marked ok
  · exact marked

theorem marked_store_never_restarts_legacy_migration (s : Migration)
    (marked : s.marker = true) : migrationStep s .start = none := by
  simp only [migrationStep]
  split <;> simp_all

theorem existing_empty_child_has_no_legacy_fallback (s : Migration)
    (present : s.childExists = true) (empty : s.child = none) : selectedChild s = none := by
  simp [selectedChild, present, empty]

theorem saved_child_is_captured_history (s t : Migration)
    (ok : migrationStep s .saveChild = some t) : t.child = s.pending := by
  simp only [migrationStep] at ok
  split at ok <;> try contradiction
  split at ok <;> simp_all
  subst_vars
  simp_all

/-! Counter consumption and result ordering are separate from namespace storage.
`persist` means its counter-store state/checkpoint BOTH succeeded. Failed I/O
does not magically persist consumed hardware assertions; no such theorem is made.
Counters permit only the positive monotonic branch; authenticators supporting
zero/signcount-less assertions require their separately specified policy. -/
structure Ceremony where
  observed : Nat := 0
  durable : Nat := 0
  second : Option Bool := none
  deriving DecidableEq, Repr

inductive CeremonyEvent where
  | consume (counter : Nat)
  | secondResult (success : Bool)
  | persist
  deriving DecidableEq, Repr

def ceremonyStep (s : Ceremony) : CeremonyEvent → Option Ceremony
  | .consume counter => if s.observed < counter ∧ counter ≤ maxU32 then
      some {s with observed := counter, second := none} else none
  | .secondResult success => some {s with second := some success}
  | .persist => some {s with durable := s.observed}

theorem second_factor_failure_keeps_consumed_counter (s : Ceremony) :
    ((ceremonyStep s (.secondResult false)).getD s).observed = s.observed := by rfl

theorem successful_counter_persist_includes_failed_second_factor (s : Ceremony) :
    (Protocol.run ceremonyStep s [.secondResult false, .persist]).durable = s.observed := by
  rfl

theorem observed_counter_history_monotone (s : Ceremony) (events : List CeremonyEvent) :
    s.observed ≤ (Protocol.run ceremonyStep s events).observed := by
  apply Protocol.run_invariant ceremonyStep (fun t => s.observed ≤ t.observed)
  · intro r e t lower ok
    cases e <;> simp only [ceremonyStep] at ok
    · split at ok <;> simp_all
      subst_vars
      simp_all
      omega
    all_goals cases ok; exact lower
  · exact Nat.le_refl _

/-- Issued lease registry, boot binding and sticky KEYRING-save poison.
This permissive projection omits expiry/caller/enrollment gates, so it proves
denial under poison/boot mismatch, not sufficiency for production authorization.
It does not assert that every other persistence domain poisons Rust leases. -/
structure Authority where
  boot : Nat
  generation : Nat := 0
  poisoned : Bool := false
  disabled : Bool := false
  leases : List Nat := []
  deriving DecidableEq, Repr

inductive AuthorityEvent where
  | issue (id : Nat)
  | keyringSaveFailed
  | wipe
  deriving DecidableEq, Repr

def authorityStep (s : Authority) : AuthorityEvent → Option Authority
  | .issue id => if ¬s.poisoned ∧ ¬s.disabled ∧
      s.leases.length < 128 ∧ id ∉ s.leases then
      some {s with leases := id :: s.leases} else none
  | .keyringSaveFailed => some {s with poisoned := true, leases := [], generation := if s.generation < maxU64 then s.generation + 1 else s.generation}
  | .wipe =>
    -- Tamper disables key release BEFORE the checked increment. Exhaustion is
    -- still a state-changing refusal: the old registry cannot stay authorized.
    if s.generation < maxU64 then
      some {s with disabled := true, generation := s.generation + 1, leases := []}
    else some {s with disabled := true}

def leaseValid (s : Authority) (boot generation id : Nat) : Bool :=
  decide (s.poisoned = false ∧ s.disabled = false ∧ boot = s.boot ∧ generation = s.generation ∧ id ∈ s.leases)

theorem poison_step_preserved (s t : Authority) (e : AuthorityEvent)
    (poisoned : s.poisoned = true) (ok : authorityStep s e = some t) :
    t.poisoned = true := by
  cases e <;> simp only [authorityStep] at ok
  all_goals repeat' first | split at ok | contradiction
  all_goals simp_all
  all_goals subst_vars
  all_goals simp_all

theorem keyring_save_failure_clears_lease_registry (s : Authority) :
    ((authorityStep s .keyringSaveFailed).getD s).leases = [] := by rfl

theorem poison_history_denies_all_leases (s : Authority) (events : List AuthorityEvent)
    (poisoned : s.poisoned = true) (boot generation id : Nat) :
    leaseValid (Protocol.run authorityStep s events) boot generation id = false := by
  have sticky : (Protocol.run authorityStep s events).poisoned = true := by
    apply Protocol.run_invariant authorityStep (fun t => t.poisoned = true)
    · intro s e t marked ok
      exact poison_step_preserved s t e marked ok
    · exact poisoned
  simp [leaseValid, sticky]

theorem different_boot_denies_old_lease (s : Authority) (boot generation id : Nat)
    (different : boot ≠ s.boot) : leaseValid s boot generation id = false := by
  simp [leaseValid, different]

theorem wipe_disables_even_at_generation_exhaustion (s : Authority)
    (exhausted : maxU64 ≤ s.generation) :
    (authorityStep s .wipe).getD s = {s with disabled := true} := by
  simp [authorityStep, show ¬s.generation < maxU64 by omega]

theorem disabled_step_sticky (s t : Authority) (e : AuthorityEvent)
    (disabled : s.disabled = true) (ok : authorityStep s e = some t) :
    t.disabled = true := by
  cases e <;> simp only [authorityStep] at ok
  all_goals repeat' first | split at ok | contradiction
  all_goals simp_all
  all_goals subst_vars
  all_goals simp_all

theorem disabled_history_denies_all_leases (s : Authority) (events : List AuthorityEvent)
    (disabled : s.disabled = true) (boot generation id : Nat) :
    leaseValid (Protocol.run authorityStep s events) boot generation id = false := by
  have sticky : (Protocol.run authorityStep s events).disabled = true := by
    apply Protocol.run_invariant authorityStep (fun t => t.disabled = true)
    · intro r e t off ok
      exact disabled_step_sticky r t e off ok
    · exact disabled
  simp [leaseValid, sticky]

end Enclave.NamespaceKeyringProtocol
