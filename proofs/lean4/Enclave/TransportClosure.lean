import Enclave.ProtocolTrace

/-!
LAT-05 bounded direct-closure/resource model, source checkpoint 23c7cd83:
service.rs prepare_download/execute_download/DownloadReservation and the
namespace.rs nonempty encrypted-chunk contract.

`catalog` is an externally authenticated, coherent TUF snapshot, not a parsed or
cryptographically verified document in this model. `hash` and `chunkCheck` are
explicit idealized content-authentication interfaces: no Bao, AEAD, KDF or
collision-resistance theorem is claimed. Metadata invalidation changes the
snapshot number; current-authority rechecks precede effects and commit.

The reservation/quota primitive atomically checks concrete lengths/sums/root
IDs. `aggregateMax` bounds ONLY actual bytes retained in modeled `stages`.
Declared-byte reservations, detached prepared files, canonical materialization,
source allocation order, complete source session accounting and process RSS are
outside this model. Pure proposed lists allocate no modeled I/O. Effects denote local
publication attempts owned by a plan; successful rollback is a primitive result.
Plan IDs are fresh logical ownership tokens, not a native or wire integer counter.
Visibility is logical admission under State. Broker crash/ownership authority,
partial physical effects, receipt/FD races and native cleanup remain separate.
No extraction, universal Rust refinement, recursive graph closure or liveness.
-/
namespace Enclave.TransportClosure

structure Target where
  root : Nat
  length : Nat
  eager : List Nat := []
  revoked : Bool := false
  deriving DecidableEq, Repr

inductive Profile where | l1 | l2 | l3
  deriving DecidableEq, Repr
inductive Transport where | registry | quic | oblivious
  deriving DecidableEq, Repr

def requiredTransport : Profile → Transport
  | .l1 => .registry | .l2 => .quic | .l3 => .oblivious

def directRoots (main : Target) : List Nat := (main.eager ++ [main.root]).eraseDups

def validSelection (catalog : List Target) (main : Target) (targets : List Target)
    (profile : Profile) : Prop :=
  main ∈ catalog ∧ main.revoked = false ∧ main.eager.length ≤ 15 ∧
  targets.map Target.root = directRoots main ∧
  (∀ t ∈ targets, t ∈ catalog ∧ t.revoked = false ∧
    (profile = .l1 ∨ 0 < t.length)) ∧
  main ∈ targets ∧
  (∀ a ∈ targets, ∀ b ∈ targets, a.root = b.root → a = b)

instance (catalog : List Target) (main : Target) (targets : List Target) (p : Profile) :
    Decidable (validSelection catalog main targets p) :=
  inferInstanceAs (Decidable (_ ∧ _ ∧ _ ∧ _ ∧ _))

structure Plan where
  id : Nat
  snapshot : Nat
  main : Target
  targets : List Target
  profile : Profile
  transport : Transport
  deriving DecidableEq, Repr

structure Staged where
  owner : Nat
  target : Target
  bytes : List Nat := []
  sealed : Bool := false
  deriving DecidableEq, Repr

structure Effect where
  owner : Nat
  root : Nat
  deriving DecidableEq, Repr

structure Certificate where
  plan : Plan
  artifacts : List Staged
  deriving DecidableEq, Repr

structure State where
  snapshot : Nat := 0
  nextPlan : Nat := 0
  plans : List Plan := []
  stages : List Staged := []
  effects : List Effect := []
  visible : List Certificate := []
  deriving DecidableEq, Repr

structure Limits where
  artifactMax : Nat
  /-- Actual retained modeled stage bytes only, not declared/reserved/detached
  or canonical materialization bytes in the Rust implementation. -/
  aggregateMax : Nat
  deriving DecidableEq, Repr

def totalBytes (s : State) : Nat := (s.stages.map (fun a => a.bytes.length)).sum

/-- All checks are computed from concrete proposed content and root IDs. -/
def ResourceBounds (lim : Limits) (s : State) : Prop :=
  totalBytes s ≤ lim.aggregateMax ∧
  (∀ a ∈ s.stages, a.bytes.length ≤ a.target.length ∧ a.target.length ≤ lim.artifactMax) ∧
  (s.stages.map (fun a => a.target.root)).Nodup

instance (lim : Limits) (s : State) : Decidable (ResourceBounds lim s) :=
  inferInstanceAs (Decidable (_ ∧ _ ∧ _))

def resourceChecked (lim : Limits) (s : State) : Option State :=
  if ResourceBounds lim s then some s else none

def completeArtifacts (hash : List Nat → Nat) (targets : List Target)
    (artifacts : List Staged) (owner : Nat) : Prop :=
  ∀ t ∈ targets, ∃ a ∈ artifacts, a.owner = owner ∧ a.target = t ∧
    a.sealed = true ∧ a.bytes.length = t.length ∧ hash a.bytes = t.root

instance (hash : List Nat → Nat) (targets : List Target) (artifacts : List Staged) (owner : Nat) :
    Decidable (completeArtifacts hash targets artifacts owner) :=
  inferInstanceAs (Decidable (∀ t ∈ targets, ∃ a ∈ artifacts, _))

def currentPlan (catalog : List Target) (s : State) (p : Plan) : Prop :=
  p ∈ s.plans ∧ p.snapshot = s.snapshot ∧
  validSelection catalog p.main p.targets p.profile ∧ p.transport = requiredTransport p.profile

instance (catalog : List Target) (s : State) (p : Plan) : Decidable (currentPlan catalog s p) :=
  inferInstanceAs (Decidable (_ ∧ _ ∧ _ ∧ _))

def certificateValid (catalog : List Target) (hash : List Nat → Nat) (c : Certificate) : Prop :=
  validSelection catalog c.plan.main c.plan.targets c.plan.profile ∧
  c.plan.transport = requiredTransport c.plan.profile ∧
  completeArtifacts hash c.plan.targets c.artifacts c.plan.id

instance (catalog : List Target) (hash : List Nat → Nat) (c : Certificate) :
    Decidable (certificateValid catalog hash c) :=
  inferInstanceAs (Decidable (_ ∧ _ ∧ _))

inductive Event where
  | reserve (owner : Nat) (main : Target) (targets : List Target) (profile : Profile) (transport : Transport)
  | chunk (owner root : Nat) (bytes : List Nat)
  | seal (owner root : Nat) (eof : Bool)
  | effect (plan : Plan) (root : Nat)
  | commit (plan : Plan)
  | rollback (owner : Nat) (cleanupOK : Bool)
  | invalidate
  deriving DecidableEq, Repr

def releaseOwned (s : State) (owner : Nat) : State :=
  {s with plans := s.plans.filter (fun p => p.id != owner),
          stages := s.stages.filter (fun a => a.owner != owner)}

/-- Proposed effects are checked before the abstract atomic resource step. -/
def propose (catalog : List Target) (hash : List Nat → Nat)
    (chunkCheck : Target → Nat → List Nat → Bool) (s : State) : Event → Option State
  | .reserve owner main targets profile transport =>
    if owner = s.nextPlan ∧ validSelection catalog main targets profile ∧
        transport = requiredTransport profile ∧
        (∀ t ∈ targets, ∀ a ∈ s.stages, a.target.root ≠ t.root) then
      let p : Plan := ⟨owner, s.snapshot, main, targets, profile, transport⟩
      some {s with nextPlan := s.nextPlan+1, plans := p :: s.plans, stages := targets.map (fun t => ⟨owner, t, [], false⟩) ++ s.stages}
    else none
  | .chunk owner root bytes =>
    match s.stages.find? (fun a => a.owner == owner && a.target.root == root) with
    | none => none
    | some a =>
      if a.sealed = false ∧ bytes ≠ [] ∧ chunkCheck a.target a.bytes.length bytes = true then
        some {s with stages := s.stages.map (fun b => if b = a then {b with bytes := b.bytes ++ bytes} else b)}
      else none
  | .seal owner root eof =>
    match s.stages.find? (fun a => a.owner == owner && a.target.root == root) with
    | none => none
    | some a =>
      if eof = true ∧ a.bytes.length = a.target.length ∧ hash a.bytes = a.target.root then
        some {s with stages := s.stages.map (fun b => if b = a then {b with sealed := true} else b)}
      else none
  | .effect p root =>
    if currentPlan catalog s p ∧ root ∈ p.targets.map Target.root ∧
        completeArtifacts hash p.targets s.stages p.id ∧
        (∀ e ∈ s.effects, e.root = root → e.owner = p.id) then
      some {s with effects := ⟨p.id, root⟩ :: s.effects}
    else none
  | .commit p =>
    let owned := s.stages.filter (fun a => a.owner == p.id)
    let c : Certificate := ⟨p, owned⟩
    if currentPlan catalog s p ∧ certificateValid catalog hash c ∧
        (∀ t ∈ p.targets, (⟨p.id, t.root⟩ : Effect) ∈ s.effects) then
      some {(releaseOwned s p.id) with visible := c :: s.visible}
    else none
  | .rollback owner cleanupOK =>
    if cleanupOK = true ∧ s.plans.any (fun p => p.id == owner) = true then
      some {(releaseOwned s owner) with effects := s.effects.filter (fun e => e.owner != owner)}
    else none
  | .invalidate => some {s with snapshot := s.snapshot+1}

def step (lim : Limits) (catalog : List Target) (hash : List Nat → Nat)
    (chunkCheck : Target → Nat → List Nat → Bool) (s : State) (e : Event) : Option State :=
  (propose catalog hash chunkCheck s e).bind (resourceChecked lim)

def trace (lim : Limits) (catalog : List Target) (hash : List Nat → Nat)
    (chunkCheck : Target → Nat → List Nat → Bool) :=
  Enclave.Protocol.run (step lim catalog hash chunkCheck)

theorem checked_result_has_resource_bounds (lim : Limits) (s t : State)
    (h : resourceChecked lim s = some t) : ResourceBounds lim t := by
  simp only [resourceChecked] at h
  split at h <;> simp_all

theorem step_preserves_resource_bounds (lim : Limits) (catalog : List Target)
    (hash : List Nat → Nat) (check : Target → Nat → List Nat → Bool)
    (s t : State) (e : Event) (h : step lim catalog hash check s e = some t) :
    ResourceBounds lim t := by
  unfold step at h
  cases hp : propose catalog hash check s e with
  | none => simp [hp] at h
  | some u =>
    simp only [hp, Option.bind] at h
    exact checked_result_has_resource_bounds lim u t h

/-- Concrete aggregate, per-artifact and unique-root bounds for all histories. -/
theorem arbitrary_history_resource_and_reservation_bounds (lim : Limits)
    (catalog : List Target) (hash : List Nat → Nat)
    (check : Target → Nat → List Nat → Bool) (es : List Event) :
    ResourceBounds lim (trace lim catalog hash check {} es) := by
  apply Enclave.Protocol.run_invariant (step lim catalog hash check) (ResourceBounds lim)
    (fun s e t _ h => step_preserves_resource_bounds lim catalog hash check s t e h) {} es
  simp [ResourceBounds, totalBytes]

theorem effect_requires_complete_verified_direct_set (catalog : List Target)
    (hash : List Nat → Nat) (check : Target → Nat → List Nat → Bool)
    (s t : State) (p : Plan) (root : Nat)
    (h : propose catalog hash check s (.effect p root) = some t) :
    currentPlan catalog s p ∧ root ∈ p.targets.map Target.root ∧
      completeArtifacts hash p.targets s.stages p.id := by
  simp only [propose] at h
  split at h <;> simp_all

theorem commit_requires_current_complete_certificate (catalog : List Target)
    (hash : List Nat → Nat) (check : Target → Nat → List Nat → Bool)
    (s t : State) (p : Plan)
    (h : propose catalog hash check s (.commit p) = some t) :
    currentPlan catalog s p ∧
      certificateValid catalog hash ⟨p, s.stages.filter (fun a => a.owner == p.id)⟩ := by
  simp only [propose] at h
  split at h <;> simp_all

theorem selected_roots_are_exactly_direct (catalog : List Target) (main : Target)
    (targets : List Target) (profile : Profile)
    (h : validSelection catalog main targets profile) :
    targets.map Target.root = (main.eager ++ [main.root]).eraseDups := h.2.2.2.1

theorem selected_main_metadata_is_exact (catalog : List Target) (main : Target)
    (targets : List Target) (profile : Profile)
    (h : validSelection catalog main targets profile) : main ∈ targets := h.2.2.2.2.2.1

theorem selected_same_root_has_coherent_metadata (catalog : List Target) (main target : Target)
    (targets : List Target) (profile : Profile)
    (h : validSelection catalog main targets profile) (member : target ∈ targets)
    (sameRoot : target.root = main.root) : target = main :=
  h.2.2.2.2.2.2 target member main (selected_main_metadata_is_exact catalog main targets profile h) sameRoot

/-- Staging and even local publication attempts do not acknowledge a partial
logical closure; only the commit event can add a visible certificate. -/
theorem only_commit_changes_logical_visibility (catalog : List Target)
    (hash : List Nat → Nat) (check : Target → Nat → List Nat → Bool)
    (s t : State) (e : Event) (h : propose catalog hash check s e = some t)
    (notCommit : ∀ p, e ≠ .commit p) : t.visible = s.visible := by
  cases e <;> simp only [propose] at h
  all_goals repeat first | split at h | cases h
  all_goals try (simp at h; subst t)
  all_goals simp_all [releaseOwned]

def VisibleValid (catalog : List Target) (hash : List Nat → Nat) (s : State) : Prop :=
  ∀ c ∈ s.visible, certificateValid catalog hash c

instance (catalog : List Target) (hash : List Nat → Nat) (s : State) :
    Decidable (VisibleValid catalog hash s) :=
  inferInstanceAs (Decidable (∀ c ∈ s.visible, _))

theorem proposal_preserves_visible_certificates (catalog : List Target)
    (hash : List Nat → Nat) (check : Target → Nat → List Nat → Bool)
    (s t : State) (e : Event) (valid : VisibleValid catalog hash s)
    (h : propose catalog hash check s e = some t) : VisibleValid catalog hash t := by
  cases e <;> simp only [propose] at h
  all_goals repeat first | split at h | cases h
  all_goals try (simp at h; subst t)
  all_goals simp_all [VisibleValid, releaseOwned]

theorem step_preserves_visible_certificates (lim : Limits) (catalog : List Target)
    (hash : List Nat → Nat) (check : Target → Nat → List Nat → Bool)
    (s t : State) (e : Event) (valid : VisibleValid catalog hash s)
    (h : step lim catalog hash check s e = some t) : VisibleValid catalog hash t := by
  unfold step at h
  cases hp : propose catalog hash check s e with
  | none => simp [hp] at h
  | some u =>
    simp only [hp, Option.bind, resourceChecked] at h
    split at h
    · cases h
      exact proposal_preserves_visible_certificates catalog hash check s t e valid hp
    · contradiction

theorem arbitrary_history_visible_certificate_integrity (lim : Limits)
    (catalog : List Target) (hash : List Nat → Nat)
    (check : Target → Nat → List Nat → Bool) (es : List Event) :
    VisibleValid catalog hash (trace lim catalog hash check {} es) := by
  apply Enclave.Protocol.run_invariant (step lim catalog hash check) (VisibleValid catalog hash)
    (fun s e t hs h => step_preserves_visible_certificates lim catalog hash check s t e hs h) {} es
  simp [VisibleValid]

theorem visible_certificate_has_authenticated_full_direct_set (catalog : List Target)
    (hash : List Nat → Nat) (s : State) (c : Certificate)
    (valid : VisibleValid catalog hash s) (member : c ∈ s.visible) :
    c.plan.targets.map Target.root = directRoots c.plan.main ∧
    ∀ t ∈ c.plan.targets, t ∈ catalog ∧
      ∃ a ∈ c.artifacts, a.owner = c.plan.id ∧ a.target = t ∧
        a.sealed = true ∧ a.bytes.length = t.length ∧ hash a.bytes = t.root := by
  have h := valid c member
  refine ⟨h.1.2.2.2.1, ?_⟩
  intro t ht
  exact ⟨(h.1.2.2.2.2.1 t ht).1, h.2.2 t ht⟩

theorem visible_certificate_has_exact_main_metadata (catalog : List Target)
    (hash : List Nat → Nat) (s : State) (c : Certificate)
    (valid : VisibleValid catalog hash s) (member : c ∈ s.visible) :
    ∃ a ∈ c.artifacts, a.owner = c.plan.id ∧ a.target = c.plan.main ∧
      a.sealed = true ∧ a.bytes.length = c.plan.main.length ∧ hash a.bytes = c.plan.main.root := by
  have h := valid c member
  exact h.2.2 c.plan.main
    (selected_main_metadata_is_exact catalog c.plan.main c.plan.targets c.plan.profile h.1)

theorem rollback_failure_retains_ownership (catalog : List Target)
    (hash : List Nat → Nat) (check : Target → Nat → List Nat → Bool)
    (s : State) (owner : Nat) : propose catalog hash check s (.rollback owner false) = none := by
  simp [propose]

theorem rollback_preserves_foreign_effects (catalog : List Target)
    (hash : List Nat → Nat) (check : Target → Nat → List Nat → Bool)
    (s t : State) (owner : Nat) (e : Effect) (foreign : e.owner ≠ owner)
    (present : e ∈ s.effects)
    (h : propose catalog hash check s (.rollback owner true) = some t) : e ∈ t.effects := by
  simp only [propose] at h
  split at h
  · simp only [Option.some.injEq] at h
    subst t
    simp [foreign, present]
  · contradiction

theorem rollback_preserves_committed_visibility (catalog : List Target)
    (hash : List Nat → Nat) (check : Target → Nat → List Nat → Bool)
    (s t : State) (owner : Nat) (ok : Bool)
    (h : propose catalog hash check s (.rollback owner ok) = some t) : t.visible = s.visible := by
  simp only [propose] at h
  split at h
  · simp only [Option.some.injEq] at h
    subst t
    rfl
  · contradiction

theorem l3_registry_fallback_refused (catalog : List Target)
    (hash : List Nat → Nat) (check : Target → Nat → List Nat → Bool)
    (s : State) (owner : Nat) (main : Target) (targets : List Target) :
    propose catalog hash check s (.reserve owner main targets .l3 .registry) = none := by
  simp [propose, requiredTransport]

theorem empty_encrypted_selection_refused (catalog : List Target) (main empty : Target)
    (targets : List Target) (profile : Profile) (member : empty ∈ targets)
    (encrypted : profile ≠ .l1) (zero : empty.length = 0) :
    ¬validSelection catalog main targets profile := by
  intro h
  rcases (h.2.2.2.2.1 empty member).2.2 with h | h
  · exact encrypted h
  · omega

end Enclave.TransportClosure
