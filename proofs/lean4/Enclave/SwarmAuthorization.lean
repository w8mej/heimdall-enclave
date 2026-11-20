import Enclave.ProtocolTrace

/-!
LAT-04 PARTIAL executable specification. This is a supported positive-check
fragment, not Biscuit v3 parsing/Datalog/source correspondence or PROOF-L2-02
completion. Sources: pop_biscuit.rs / pop_biscuit_facts.rs, transport/iroh.rs,
quic.rs and quic_seed.rs at 23c7cd83d67a9ddb86d09dcfce71530335d8dc2e.

`Grant` and `PopObservation` represent outputs of correct signature verification;
`Context.peer/exporter` represent the actual authenticated TLS connection, not
caller-supplied assertions. MAC/signature/exporter security, collision resistance,
SEP binding, and verified ambient-fact construction remain external interfaces.
All equality/scope/time/delegated-grammar checks below are computed transitions.
Unsupported delegated facts/rules reject rather than gain arbitrary Datalog power.
Authority non-amplification concerns roots at fixed ambient/request context;
holder possession can change under delegation and is separately checked at wire
admission. The positive child witness deliberately retains the fixed holder.

The one-pending-request server is a serial subset. Replay stores a mathematical
64-sequence window, not a proved refinement of Rust's u64 bitmap or capacity/TTL
table. `finish` is a logical release event; no native sendmsg/check race is solved.
Local revocation does not establish fleet poison adjudication or dissemination.
-/
namespace Enclave.SwarmAuthorization

def maxSequence : Nat := 18446744073709551615

structure Context where
  peer : Nat
  exporter : Nat
  ns : Nat
  shard : Nat
  tool : Nat
  rows : Nat
  charge : Nat
  now : Nat
  argsDigest : Nat
  deriving DecidableEq, Repr

inductive Check where
  | tools (allowed : List Nat)
  | ns (value : Nat)
  | rows (maximum : Nat)
  | charge (maximum : Nat)
  | expires (maximum : Nat)
  deriving DecidableEq, Repr

def checkHolds (c : Context) : Check → Bool
  | .tools allowed => decide (c.tool ∈ allowed)
  | .ns value => decide (c.ns = value)
  | .rows maximum => decide (c.rows ≤ maximum)
  | .charge maximum => decide (c.charge ≤ maximum)
  | .expires maximum => decide (c.now ≤ maximum)

structure Grant where
  issuer : Nat
  policy : Nat
  epoch : Nat
  peer : Nat
  exporter : Nat
  ns : Nat
  shard : Nat
  right : Nat
  expires : Nat
  roots : List Nat
  holder : Nat
  deriving DecidableEq, Repr

structure Block where
  index : Nat
  holder : Nat
  exporter : Nat
  checks : List Check
  extraFacts : List Nat := []
  rules : List Nat := []
  deriving DecidableEq, Repr

structure Chain where
  grant : Grant
  blocks : List Block := []
  sealed : Bool := false
  deriving DecidableEq, Repr

def supportedBlock (b : Block) (index : Nat) : Bool :=
  decide (b.index = index ∧ b.extraFacts = [] ∧ b.rules = [])

inductive ChainEvent where
  | append (block : Block)
  | sealWire
  deriving DecidableEq, Repr

def chainStep (s : Chain) : ChainEvent → Option Chain
  | .append block => if ¬s.sealed ∧ s.blocks.length < 4 ∧
      supportedBlock block (s.blocks.length + 1) then
      some {s with blocks := s.blocks ++ [block]} else none
  | .sealWire => if ¬s.sealed then some {s with sealed := true} else none

def caveatsHold (s : Chain) (c : Context) : Bool :=
  s.blocks.all (fun b => b.checks.all (checkHolds c))

def rootAllowed (s : Chain) (c : Context) (root : Nat) : Bool :=
  decide (root ∈ s.grant.roots ∧ s.grant.peer = c.peer ∧
    s.grant.ns = c.ns ∧ s.grant.shard = c.shard ∧ s.grant.right = 1 ∧
    c.now ≤ s.grant.expires) && caveatsHold s c

theorem append_computes_narrower_root_authority (s t : Chain) (block : Block)
    (c : Context) (root : Nat) (appended : chainStep s (.append block) = some t)
    (allowed : rootAllowed t c root = true) : rootAllowed s c root = true := by
  simp only [chainStep] at appended
  split at appended <;> try contradiction
  cases appended
  simp only [rootAllowed, caveatsHold, List.all_append, List.all_cons, List.all_nil,
    Bool.and_true, Bool.and_eq_true] at allowed ⊢
  exact ⟨allowed.1, allowed.2.1⟩

theorem chain_step_never_adds_root_authority (s t : Chain) (e : ChainEvent)
    (c : Context) (root : Nat) (ok : chainStep s e = some t)
    (allowed : rootAllowed t c root = true) : rootAllowed s c root = true := by
  cases e with
  | append b => exact append_computes_narrower_root_authority s t b c root ok allowed
  | sealWire =>
    simp only [chainStep] at ok
    split at ok <;> try contradiction
    cases ok
    exact allowed

theorem arbitrary_construction_never_amplifies (s : Chain) (events : List ChainEvent)
    (c : Context) (root : Nat)
    (allowed : rootAllowed (Protocol.run chainStep s events) c root = true) :
    rootAllowed s c root = true := by
  induction events generalizing s with
  | nil => exact allowed
  | cons event events ih =>
    have after := ih ((chainStep s event).getD s) allowed
    cases h : chainStep s event with
    | none => simpa [h] using after
    | some t =>
      have a : rootAllowed t c root = true := by simpa [h] using after
      exact chain_step_never_adds_root_authority s t event c root h a

theorem sealed_chain_cannot_append (s : Chain) (b : Block)
    (sealed : s.sealed = true) : chainStep s (.append b) = none := by
  simp [chainStep, sealed]

theorem delegated_ambient_facts_rejected (s : Chain) (b : Block)
    (extra : b.extraFacts ≠ []) : chainStep s (.append b) = none := by
  simp [chainStep, supportedBlock, extra]

theorem delegated_rules_rejected (s : Chain) (b : Block)
    (extra : b.rules ≠ []) : chainStep s (.append b) = none := by
  simp [chainStep, supportedBlock, extra]

def tipHolder (s : Chain) : Nat :=
  match s.blocks.getLast? with | some b => b.holder | none => s.grant.holder
def tipExporter (s : Chain) : Nat :=
  match s.blocks.getLast? with | some b => b.exporter | none => s.grant.exporter
def grammarHolds (s : Chain) : Bool :=
  decide (s.blocks.length ≤ 4) &&
  (s.blocks.zip (List.range s.blocks.length)).all (fun (b,i) => supportedBlock b (i+1))

structure PopObservation where
  holder : Nat
  exporter : Nat
  chainId : Nat
  argsDigest : Nat
  seq : Nat
  deriving DecidableEq, Repr

structure Wire where
  chain : Chain
  chainId : Nat
  root : Nat
  seq : Nat
  pop : PopObservation
  deriving DecidableEq, Repr

structure Server where
  issuer : Nat
  policy : Nat
  epoch : Nat
  authorized : List Nat
  revoked : List Nat := []
  licensed : List Nat
  lastUtc : Nat := 0
  windows : List (Nat × List Nat) := []
  pending : Option (Wire × Context) := none
  released : List Nat := []
  deriving DecidableEq, Repr

def wireAdmission (s : Server) (w : Wire) (c : Context) : Bool :=
  w.chain.sealed && grammarHolds w.chain && rootAllowed w.chain c w.root &&
  decide (w.chain.grant.issuer = s.issuer ∧ w.chain.grant.policy = s.policy ∧
    w.chain.grant.epoch = s.epoch ∧ tipHolder w.chain = c.peer ∧
    tipExporter w.chain = c.exporter ∧ c.exporter ≠ 0 ∧
    w.pop.holder = c.peer ∧ w.pop.exporter = c.exporter ∧
    w.pop.chainId = w.chainId ∧ w.pop.argsDigest = c.argsDigest ∧
    w.pop.seq = w.seq ∧ w.seq ≤ maxSequence)

def currentlyLive (s : Server) (c : Context) : Bool :=
  decide (c.peer ∈ s.authorized ∧ c.peer ∉ s.revoked ∧ c.ns ∈ s.licensed ∧ s.lastUtc ≤ c.now)

def highest (seen : List Nat) : Nat := seen.foldl max 0
def windowAccept (seen : List Nat) (seq : Nat) : Bool :=
  decide (seq ≤ maxSequence ∧ seq ∉ seen ∧
    (seen = [] ∨ highest seen < seq ∨ highest seen - seq < 64))
def windowUpdate (seen : List Nat) (seq : Nat) : List Nat :=
  seq :: seen.filter (fun n => decide (max seq (highest seen) - n < 64))

theorem repeated_sequence_rejected (seen : List Nat) (seq : Nat) :
    windowAccept (windowUpdate seen seq) seq = false := by
  simp [windowAccept, windowUpdate]

def seenFor (s : Server) (chain : Nat) : List Nat :=
  ((s.windows.find? (fun entry => entry.1 == chain)).map Prod.snd).getD []

inductive ServerEvent where
  | begin (wire : Wire) (context : Context)
  | finish (now : Nat)
  | revoke (peer : Nat)
  | unlicense (ns : Nat)
  | replacePolicy (policy epoch : Nat)
  deriving DecidableEq, Repr

def serverStep (s : Server) : ServerEvent → Option Server
  | .begin w c =>
    if s.pending = none ∧ wireAdmission s w c ∧ currentlyLive s c ∧
        windowAccept (seenFor s w.chainId) w.seq then
      let seen := windowUpdate (seenFor s w.chainId) w.seq
      some {s with lastUtc := c.now, pending := some (w,c), windows := (w.chainId,seen) :: s.windows.filter (fun e => e.1 != w.chainId)}
    else none
  | .finish now => match s.pending with
    | some (w,c) =>
      let fresh := {c with now := now}
      if wireAdmission s w fresh ∧ currentlyLive s fresh then
        some {s with pending := none, lastUtc := now, released := w.root :: s.released}
      else none
    | none => none
  | .revoke peer => some {s with revoked := peer :: s.revoked}
  | .unlicense ns => some {s with licensed := s.licensed.filter (fun n => n != ns)}
  | .replacePolicy policy epoch => some {s with policy := policy, epoch := epoch}

theorem admitted_wire_is_sealed (s : Server) (w : Wire) (c : Context)
    (accepted : wireAdmission s w c = true) : w.chain.sealed = true := by
  simp only [wireAdmission, Bool.and_eq_true] at accepted
  exact accepted.1.1.1

theorem admitted_constructed_wire_preserves_parent_root_scope
    (parent : Chain) (events : List ChainEvent) (s : Server) (w : Wire) (c : Context)
    (constructed : w.chain = Protocol.run chainStep parent events)
    (accepted : wireAdmission s w c = true) : rootAllowed parent c w.root = true := by
  have after : rootAllowed w.chain c w.root = true := by
    simp only [wireAdmission, Bool.and_eq_true] at accepted
    exact accepted.1.2
  rw [constructed] at after
  exact arbitrary_construction_never_amplifies parent events c w.root after

theorem unsealed_wire_rejected (s : Server) (w : Wire) (c : Context)
    (unsealed : w.chain.sealed = false) : wireAdmission s w c = false := by
  simp [wireAdmission, unsealed]

theorem admitted_wire_has_exact_pop_tuple (s : Server) (w : Wire) (c : Context)
    (accepted : wireAdmission s w c = true) :
    w.pop.holder = c.peer ∧ w.pop.exporter = c.exporter ∧
    w.pop.chainId = w.chainId ∧ w.pop.argsDigest = c.argsDigest ∧ w.pop.seq = w.seq := by
  simp only [wireAdmission, Bool.and_eq_true, decide_eq_true_eq] at accepted
  exact ⟨accepted.2.2.2.2.2.2.2.1, accepted.2.2.2.2.2.2.2.2.1,
    accepted.2.2.2.2.2.2.2.2.2.1, accepted.2.2.2.2.2.2.2.2.2.2.1,
    accepted.2.2.2.2.2.2.2.2.2.2.2.1⟩

theorem revoked_peer_cannot_begin (s : Server) (w : Wire) (c : Context)
    (revoked : c.peer ∈ s.revoked) : serverStep s (.begin w c) = none := by
  simp [serverStep, currentlyLive, revoked]

theorem finish_rechecks_current_authority (s t : Server) (now : Nat)
    (released : serverStep s (.finish now) = some t) :
    ∃ w c, s.pending = some (w,c) ∧ wireAdmission s w {c with now := now} = true ∧
      currentlyLive s {c with now := now} = true ∧ t.released = w.root :: s.released := by
  simp only [serverStep] at released
  split at released <;> try contradiction
  split at released <;> try contradiction
  rename_i w c pending live
  cases released
  exact ⟨w,c,pending,live.1,live.2,rfl⟩

theorem revocation_history_sticky (s : Server) (events : List ServerEvent) (peer : Nat)
    (revoked : peer ∈ s.revoked) : peer ∈ (Protocol.run serverStep s events).revoked := by
  apply Protocol.run_invariant serverStep (fun t => peer ∈ t.revoked)
  · intro r e t member ok
    cases e <;> simp only [serverStep] at ok
    all_goals repeat' first | split at ok | contradiction
    all_goals simp_all only [Option.some.injEq]
    all_goals subst t
    all_goals simp_all
  · exact revoked

theorem revoked_peer_cannot_renew_after_any_history (s : Server)
    (events : List ServerEvent) (w : Wire) (c : Context)
    (revoked : c.peer ∈ s.revoked) :
    serverStep (Protocol.run serverStep s events) (.begin w c) = none := by
  exact revoked_peer_cannot_begin _ w c (revocation_history_sticky s events c.peer revoked)

end Enclave.SwarmAuthorization
