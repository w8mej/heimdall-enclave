import Enclave.ProtocolTrace

/-! LAT-06 bounded startup/observation model. These executable guards consume
explicit primitive observations; they do not implement Darwin, signatures,
canonical JSON, descriptor lifetime, raw socket parsing or Rust refinement.
The recorded descriptor check is a snapshot, not a future-listener theorem.
Non-CAS construction order and detached workers remain outside this model. -/
namespace Enclave.TransportStartup

inductive Profile where
  | l1 | l2 | l3
  deriving DecidableEq, Repr

def rank : Profile → Nat | .l1 => 1 | .l2 => 2 | .l3 => 3

structure Monitor where
  power : Bool
  usb : Bool
  sourceAttached : Bool
  deriving DecidableEq, Repr

def completeMonitor (m : Monitor) : Bool := m.power && m.usb && m.sourceAttached
def monitorAllows (p : Profile) (m : Monitor) : Bool := p == .l1 || completeMonitor m

inductive Observation (α : Type) where
  | known (value : α) | incomplete | error
  deriving DecidableEq, Repr

inductive Family where
  | ipv4 | ipv6
  deriving DecidableEq, Repr

inductive Descriptor where
  | unix
  | tcp (family : Family) (listening : Bool)
  | udp (family : Family) (localPort : Nat) (connected : Bool)
      (samePeerFamily : Bool) (peerPort : Nat)
  | unsupportedInternet
  deriving DecidableEq, Repr

def permittedDescriptor : Descriptor → Bool
  | .unix => true
  | .tcp _ listening => !listening
  | .udp _ localPort connected same peer =>
      localPort == 0 || (connected && same && decide (0 < peer))
  | .unsupportedInternet => false

def observedDescriptor : Observation Descriptor → Bool
  | .known d => permittedDescriptor d
  | .incomplete | .error => false

abbrev Snapshot := Observation (List (Observation Descriptor))

def zeroListeners : Snapshot → Bool
  | .known descriptors => descriptors.all observedDescriptor
  | .incomplete | .error => false

def listenerAllows (p : Profile) (snapshot : Snapshot) : Bool :=
  p != .l3 || zeroListeners snapshot

def completeEnumeration (success : Bool) (got capacity item : Nat) : Bool :=
  success && decide (0 < got ∧ got < capacity ∧ 0 < item ∧ got % item = 0)

def exactQuery (success : Bool) (got expected : Nat) : Bool :=
  success && decide (0 < expected ∧ got = expected)

/-- Lists are abstract byte labels, not a canonical JSON/hash/signature codec.
The expected payload is the result of the external authenticated metadata
interface. Its freshness/revocation/path/directory outcomes remain explicit. -/
structure Metadata where
  expected : List Nat
  floor : Profile
  current : Bool
  revoked : Bool
  pathValid : Bool
  directoryOwned : Bool
  deriving DecidableEq, Repr

structure Payload where
  bytes : List Nat
  regular : Bool
  nofollow : Bool
  readable : Bool
  deriving DecidableEq, Repr

inductive ReadResult where
  | missing | failure | present (payload : Payload)
  deriving DecidableEq, Repr

structure Sources where
  canonical : ReadResult
  loose : ReadResult
  chunk : ReadResult
  deriving DecidableEq, Repr

def choose (sources : Sources) : Option Payload :=
  match sources.canonical with
  | .present payload => some payload
  | .failure => none
  | .missing => match sources.loose with
    | .present payload => some payload
    | .failure => none
    | .missing => match sources.chunk with
      | .present payload => some payload
      | .failure | .missing => none

def validatePayload (maximum : Nat) (metadata : Metadata) (payload : Payload) : Option (List Nat) :=
  if metadata.current = true ∧ metadata.revoked = false ∧ metadata.pathValid = true ∧
      metadata.directoryOwned = true ∧ metadata.expected.length ≤ maximum ∧
      payload.regular = true ∧ payload.nofollow = true ∧ payload.readable = true ∧
      payload.bytes = metadata.expected then some payload.bytes else none

def resolve (maximum : Nat) (metadata : Metadata) (sources : Sources) : Option (List Nat) :=
  (choose sources).bind (validatePayload maximum metadata)

theorem canonical_precedes_every_loose_or_chunk_copy (maximum : Nat) (metadata : Metadata)
    (canonical : Payload) (loose chunk : ReadResult) :
    resolve maximum metadata ⟨.present canonical, loose, chunk⟩ =
      validatePayload maximum metadata canonical := rfl

theorem canonical_failure_has_no_fallback (maximum : Nat) (metadata : Metadata)
    (loose chunk : ReadResult) : resolve maximum metadata ⟨.failure, loose, chunk⟩ = none := rfl

theorem resolution_has_exact_current_signed_bytes (maximum : Nat) (metadata : Metadata)
    (sources : Sources) (bytes : List Nat) (ok : resolve maximum metadata sources = some bytes) :
    bytes = metadata.expected ∧ bytes.length ≤ maximum ∧
      metadata.current = true ∧ metadata.revoked = false := by
  unfold resolve at ok
  cases selected : choose sources with
  | none => simp [selected] at ok
  | some payload =>
    rw [selected] at ok
    change validatePayload maximum metadata payload = some bytes at ok
    unfold validatePayload at ok
    split at ok
    · rename_i gate
      cases ok
      obtain ⟨hcurrent, hrevoked, _, _, hbound, _, _, _, heq⟩ := gate
      exact ⟨heq, by rw [heq]; exact hbound, hcurrent, hrevoked⟩
    · contradiction

structure Input where
  profile : Profile
  development : Bool
  simulated : Bool
  daemonUid : Bool
  productionSocket : Bool
  identityValid : Bool
  hardened : Bool
  confined : Bool
  pinsFresh : Bool
  monitor : Monitor
  snapshot : Snapshot
  metadata : Metadata
  sources : Sources
  deriving DecidableEq, Repr

def runtimeAllows (input : Input) : Bool :=
  input.identityValid && (input.development || input.hardened) &&
  (input.development || input.confined) && (input.development || input.pinsFresh) &&
  (!input.simulated || (input.development && !input.daemonUid && !input.productionSocket))

def startupGuard (input : Input) : Bool :=
  runtimeAllows input && monitorAllows input.profile input.monitor &&
  listenerAllows input.profile input.snapshot && decide (rank input.metadata.floor ≤ rank input.profile)

structure Permit where
  input : Input
  bytes : List Nat
  deriving DecidableEq, Repr

def startup (input : Input) : Option Permit :=
  if startupGuard input then (resolve 65536 input.metadata input.sources).map (fun bytes => ⟨input, bytes⟩)
  else none

def Valid (permit : Permit) : Prop :=
  startupGuard permit.input = true ∧ resolve 65536 permit.input.metadata permit.input.sources = some permit.bytes

theorem startup_derives_checked_permit (input : Input) (permit : Permit)
    (ok : startup input = some permit) : Valid permit := by
  unfold startup at ok
  split at ok
  · rename_i guard
    cases resolved : resolve 65536 input.metadata input.sources with
    | none => simp [resolved] at ok
    | some bytes =>
      simp only [resolved, Option.map_some, Option.some.injEq] at ok
      cases ok
      exact ⟨guard, resolved⟩
  · contradiction

structure State where
  session : Option Permit
  fetches : Nat
  deriving DecidableEq, Repr

def initial : State := ⟨none, 0⟩

inductive Event where
  | start (input : Input)
  | stop
  | fetch (snapshot : Snapshot)
  deriving DecidableEq, Repr

def step (s : State) : Event → Option State
  | .start input =>
    if s.session = none then (startup input).map (fun permit => {s with session := some permit}) else none
  | .stop => some {s with session := none}
  | .fetch snapshot => match s.session with
    | none => none
    | some permit => if listenerAllows permit.input.profile snapshot then some {s with fetches := s.fetches + 1} else none

def Safe (s : State) : Prop := ∀ permit, s.session = some permit → Valid permit

theorem step_preserves_startup_checks (s t : State) (e : Event) (safe : Safe s)
    (ok : step s e = some t) : Safe t := by
  cases e with
  | start input =>
    simp only [step] at ok
    split at ok
    · cases result : startup input with
      | none => simp [result] at ok
      | some permit =>
        simp only [result, Option.map_some, Option.some.injEq] at ok
        cases ok
        intro p hp
        cases hp
        exact startup_derives_checked_permit input permit result
    · contradiction
  | stop => cases ok; intro p hp; contradiction
  | fetch snapshot =>
    cases current : s.session with
    | none => simp [step, current] at ok
    | some permit =>
      simp only [step, current] at ok
      split at ok
      · cases ok
        intro p hp
        apply safe p
        simpa [current] using hp
      · contradiction

theorem arbitrary_history_serving_has_startup_checks (events : List Event) :
    Safe (Enclave.Protocol.run step initial events) := by
  exact Enclave.Protocol.run_invariant step Safe
    (fun s e t hs ht => step_preserves_startup_checks s t e hs ht)
    initial events (by intro p hp; contradiction)

theorem strict_profiles_require_complete_registration (p : Profile) (monitor : Monitor)
    (strict : p ≠ .l1) (ok : monitorAllows p monitor = true) :
    monitor.power = true ∧ monitor.usb = true ∧ monitor.sourceAttached = true := by
  simpa [monitorAllows, strict, completeMonitor, Bool.and_eq_true, and_assoc] using ok

theorem incomplete_and_error_observations_refuse_l3 :
    listenerAllows .l3 .incomplete = false ∧ listenerAllows .l3 .error = false := by decide

theorem admitted_l3_snapshot_has_only_known_permitted_descriptors
    (descriptors : List (Observation Descriptor))
    (ok : listenerAllows .l3 (.known descriptors) = true) :
    ∀ descriptor ∈ descriptors, ∃ d, descriptor = .known d ∧ permittedDescriptor d = true := by
  simp only [listenerAllows, bne_self_eq_false, Bool.false_or, zeroListeners, List.all_eq_true] at ok
  intro descriptor member
  have checked := ok descriptor member
  cases descriptor with
  | known d => exact ⟨d, rfl, checked⟩
  | incomplete => contradiction
  | error => contradiction

theorem l1_retains_optional_monitor_policy (monitor : Monitor) :
    monitorAllows .l1 monitor = true := rfl

theorem successful_fetch_checks_the_current_snapshot (s t : State) (permit : Permit)
    (snapshot : Snapshot) (session : s.session = some permit)
    (ok : step s (.fetch snapshot) = some t) : listenerAllows permit.input.profile snapshot = true := by
  simp only [step, session] at ok
  split at ok
  · assumption
  · contradiction

theorem checked_startup_has_monitor_and_floor (permit : Permit) (valid : Valid permit) :
    monitorAllows permit.input.profile permit.input.monitor = true ∧
      rank permit.input.metadata.floor ≤ rank permit.input.profile := by
  have checks := valid.1
  simp only [startupGuard, Bool.and_eq_true, decide_eq_true_eq] at checks
  exact ⟨checks.1.1.2, checks.2⟩

theorem release_simulation_refuses (input : Input) (release : input.development = false)
    (simulation : input.simulated = true) : startup input = none := by
  simp [startup, startupGuard, runtimeAllows, release, simulation]

theorem failed_required_monitor_refuses_startup (input : Input)
    (strict : input.profile ≠ .l1) (failed : completeMonitor input.monitor = false) :
    startup input = none := by
  simp [startup, startupGuard, monitorAllows, strict, failed]

end Enclave.TransportStartup
