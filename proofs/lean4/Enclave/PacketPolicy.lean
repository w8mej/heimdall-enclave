import Enclave.ProtocolTrace

namespace Enclave.PacketPolicy

inductive Family where | ipv4 | ipv6 deriving DecidableEq, Repr
inductive Verdict where | pass | block deriving DecidableEq, Repr

structure Packet where
  family : Family
  outbound : Bool
  agentGroup : Bool
  loopbackInterface : Bool
  loopbackDestination : Bool
  tcp : Bool
  port : Nat
  deriving DecidableEq, Repr

structure Rule where
  predicate : Packet → Bool
  verdict : Verdict
  quick : Bool

/-- PF uses the last matching rule unless a matching quick rule terminates. -/
def evaluate : List Rule → Packet → Verdict → Verdict
  | [], _, previous => previous
  | r::rs, p, previous =>
    if r.predicate p then
      if r.quick then r.verdict else evaluate rs p r.verdict
    else evaluate rs p previous

def permitted (p : Packet) : Bool :=
  p.loopbackInterface && p.loopbackDestination && p.tcp &&
    (p.port == 8443 || p.port == 11434)

def allowRule (family : Family) : Rule :=
  ⟨fun p => p.outbound && p.agentGroup && decide (p.family=family) && permitted p, .pass, true⟩
def blockRule (family : Family) : Rule :=
  ⟨fun p => p.outbound && p.agentGroup && decide (p.family=family), .block, true⟩
def anchor : List Rule := [allowRule .ipv4, allowRule .ipv6, blockRule .ipv4, blockRule .ipv6]

theorem anchor_exact_policy (p : Packet) (ho : p.outbound = true) (hg : p.agentGroup = true)
    (initial : Verdict) :
    evaluate anchor p initial = if permitted p then .pass else .block := by
  cases hf : p.family <;> cases hp : permitted p <;>
    simp [evaluate, anchor, allowRule, blockRule, ho, hg, hf, hp]

def process (states : List Packet) (p : Packet) : List Packet × Verdict :=
  if p ∈ states then (states,.pass)
  else if permitted p then (p::states,.pass) else (states,.block)

def invariant (states : List Packet) : Prop := ∀ p ∈ states, permitted p = true

theorem process_preserves_state_policy (states : List Packet) (p : Packet)
    (hs : invariant states) : invariant (process states p).1 := by
  unfold process
  split
  · exact hs
  · split
    · rename_i hp
      intro q hq
      simp only [List.mem_cons] at hq
      rcases hq with rfl | hq
      · exact hp
      · exact hs q hq
    · exact hs

theorem state_cannot_bypass_policy (states : List Packet) (p : Packet)
    (hs : invariant states) (hp : permitted p = false) : (process states p).2 = .block := by
  have hn : p ∉ states := by intro h; have := hs p h; simp_all
  simp [process, hn, hp]

end Enclave.PacketPolicy
