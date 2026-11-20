/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

macOS Darwin Packet Filter (pf) Stateful Connection Tracking ('keep state') Proofs
Normative Specification: crates/mcp-enclave/src/pf.rs::render_llm_isolation_rules, ADR-001, & FS-701 §3.1
-/

import Enclave.PacketFilter

-- ASSURANCE: a standalone specification using Nat, records and Booleans.
-- Its original mechanism terminology is an interpretation of model fields.
-- No cryptographic protocol, deployed constraints, OS or hardware is verified here.
namespace Enclave

/-- TCP connection lifecycle states for stateful connection tracking -/
inductive TcpConnState where
  | SynSent : TcpConnState
  | Established : TcpConnState
  | FinWait : TcpConnState
  | Closed : TcpConnState
  deriving DecidableEq, Repr

/-- 5-tuple flow identifier uniquely characterizing a connection flow -/
structure FlowKey where
  iface : String
  proto : Protocol
  src_ip : Nat
  src_port : Nat
  dst_ip : Nat
  dst_port : Nat
  group : Nat
  deriving DecidableEq, Repr

/-- Dynamic connection entry in the Darwin pf kernel state table -/
structure StateEntry where
  flow : FlowKey
  conn_state : TcpConnState
  deriving DecidableEq, Repr

/-- Kernel state table represented as a list of active connection flows -/
abbrev StateTable := List StateEntry

/-- Stateful network packet carrying TCP handshake flags -/
structure StatefulPacket where
  flow : FlowKey
  is_syn : Bool
  is_ack : Bool
  is_fin : Bool
  deriving DecidableEq, Repr

/-- Static rule evaluation check for the rendered pf.rs anchor projection -/
def isFlowAllowedStatic (k : FlowKey) : Bool :=
  if k.group == LLM_AGENT_GID then
    k.iface == LOOPBACK_IFACE &&
    k.proto == Protocol.TCP &&
    (k.dst_port == ENVOY_PORT || k.dst_port == INFERENCE_PORT)
  else
    true

/-- Look up an existing flow entry in the kernel state table -/
def findStateEntry (tbl : StateTable) (k : FlowKey) : Option StateEntry :=
  tbl.find? (fun e => e.flow == k)

/-- Update connection state for an existing flow entry in the table -/
def updateEntryState (tbl : StateTable) (k : FlowKey) (new_st : TcpConnState) : StateTable :=
  tbl.map (fun e => if e.flow == k then { e with conn_state := new_st } else e)

/--
Deterministic stateful packet filter evaluation:
1. Lookup in connection state table:
   - If established state exists: pass packet and update TCP lifecycle
   - If closed state exists: drop packet
2. If no state exists:
   - Evaluate static pf rules
   - If permitted and packet has SYN set: create new state entry ('keep state') and pass
   - Otherwise: drop packet (out-of-order / unsolicited / unauthorized)
-/
def evalStatefulFilter (tbl : StateTable) (pkt : StatefulPacket) : (StateTable × Verdict) :=
  match findStateEntry tbl pkt.flow with
  | some entry =>
    match entry.conn_state with
    | TcpConnState.Closed => (tbl, Verdict.Drop)
    | TcpConnState.FinWait => (tbl, Verdict.Pass)
    | TcpConnState.SynSent =>
      if pkt.is_ack then
        (updateEntryState tbl pkt.flow TcpConnState.Established, Verdict.Pass)
      else
        (tbl, Verdict.Pass)
    | TcpConnState.Established =>
      if pkt.is_fin then
        (updateEntryState tbl pkt.flow TcpConnState.FinWait, Verdict.Pass)
      else
        (tbl, Verdict.Pass)
  | none =>
    if isFlowAllowedStatic pkt.flow then
      if pkt.is_syn then
        let new_entry : StateEntry := { flow := pkt.flow, conn_state := TcpConnState.SynSent }
        (new_entry :: tbl, Verdict.Pass)
      else
        (tbl, Verdict.Drop)
    else
      (tbl, Verdict.Drop)

/--
Kernel State Table Quarantine Invariant:
Every flow entry recorded in the kernel state table belonging to GID _llmagent (8701)
is strictly bound to the loopback interface 'lo0', protocol TCP, and authorized ports.
-/
def TableQuarantineInvariant (tbl : StateTable) : Prop :=
  ∀ e ∈ tbl, e.flow.group = LLM_AGENT_GID →
    e.flow.iface = LOOPBACK_IFACE ∧
    e.flow.proto = Protocol.TCP ∧
    (e.flow.dst_port = ENVOY_PORT ∨ e.flow.dst_port = INFERENCE_PORT)

/--
Lemma 13.1 (Initial Empty State Table Satisfies Quarantine Invariant):
The initial empty kernel state table trivially maintains the quarantine invariant.
-/
theorem empty_table_preserves_quarantine : TableQuarantineInvariant [] := by
  intro e he
  cases he

/--
Lemma 13.2 (Non-Loopback State Lookup Impossibility):
Under the quarantine invariant, any lookup for a non-loopback packet belonging
to _llmagent in the state table deterministically yields none.
-/
theorem non_loopback_state_lookup_impossible (tbl : StateTable) (k : FlowKey)
    (h_inv : TableQuarantineInvariant tbl)
    (h_group : k.group = LLM_AGENT_GID)
    (h_not_lo : k.iface ≠ LOOPBACK_IFACE) :
    findStateEntry tbl k = none := by
  dsimp [findStateEntry]
  induction tbl with
  | nil => rfl
  | cons head tail ih =>
    dsimp [List.find?]
    split
    · rename_i h_eq
      simp only [beq_iff_eq] at h_eq
      have h_head_in : head ∈ head :: tail := List.Mem.head tail
      have h_props := h_inv head h_head_in (by rw [h_eq]; exact h_group)
      have h_iface : head.flow.iface = LOOPBACK_IFACE := h_props.1
      have h_k_iface : k.iface = LOOPBACK_IFACE := by
        rw [← h_iface]
        congr 1
        exact h_eq.symm
      contradiction
    · apply ih
      intro e he hg
      exact h_inv e (List.Mem.tail head he) hg

/--
Lemma 13.3 (Static Filter Drop on Non-Loopback):
If a flow from _llmagent targets a non-loopback interface, the static check fails.
-/
theorem static_filter_drops_non_loopback (k : FlowKey)
    (h_group : k.group = LLM_AGENT_GID)
    (h_not_lo : k.iface ≠ LOOPBACK_IFACE) :
    isFlowAllowedStatic k = false := by
  dsimp [isFlowAllowedStatic]
  have hg : (k.group == LLM_AGENT_GID) = true := by
    rw [h_group]
    decide
  rw [hg]
  dsimp
  have h_lo : (k.iface == LOOPBACK_IFACE) = false := by
    cases h : (k.iface == LOOPBACK_IFACE)
    · rfl
    · simp only [beq_iff_eq] at h; contradiction
  rw [h_lo]
  rfl

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem model_agent_packet_verdict_characterization (tbl : StateTable) (pkt : StatefulPacket)
    (h_inv : TableQuarantineInvariant tbl)
    (h_group : pkt.flow.group = LLM_AGENT_GID)
    (h_not_lo : pkt.flow.iface ≠ LOOPBACK_IFACE) :
    (evalStatefulFilter tbl pkt).2 = Verdict.Drop ∧ (evalStatefulFilter tbl pkt).1 = tbl := by
  have h_no_state := non_loopback_state_lookup_impossible tbl pkt.flow h_inv h_group h_not_lo
  have h_static := static_filter_drops_non_loopback pkt.flow h_group h_not_lo
  dsimp [evalStatefulFilter]
  rw [h_no_state]
  dsimp
  rw [h_static]
  dsimp
  exact ⟨rfl, rfl⟩

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem state_table_quarantine_invariant (tbl : StateTable) (pkt : StatefulPacket)
    (h_inv : TableQuarantineInvariant tbl) :
    TableQuarantineInvariant (evalStatefulFilter tbl pkt).1 := by
  dsimp [evalStatefulFilter]
  split
  · -- Existing state entry found
    rename_i entry h_entry
    split
    · -- Closed -> tbl
      exact h_inv
    · -- FinWait -> tbl
      exact h_inv
    · -- SynSent
      split
      · -- updateEntryState
        dsimp [updateEntryState]
        intro e he hg
        rw [List.mem_map] at he
        rcases he with ⟨orig, h_orig_in, h_orig_eq⟩
        split at h_orig_eq
        · subst e
          exact h_inv orig h_orig_in hg
        · subst e
          exact h_inv orig h_orig_in hg
      · exact h_inv
    · -- Established
      split
      · -- updateEntryState
        dsimp [updateEntryState]
        intro e he hg
        rw [List.mem_map] at he
        rcases he with ⟨orig, h_orig_in, h_orig_eq⟩
        split at h_orig_eq
        · subst e
          exact h_inv orig h_orig_in hg
        · subst e
          exact h_inv orig h_orig_in hg
      · exact h_inv
  · -- No existing state entry
    split
    · -- isFlowAllowedStatic = true
      rename_i h_allowed
      split
      · -- pkt.is_syn = true -> new_entry :: tbl
        intro e he hg
        cases he with
        | head =>
          dsimp [isFlowAllowedStatic] at h_allowed
          split at h_allowed
          · -- pkt.flow.group == LLM_AGENT_GID
            rename_i h_grp_eq
            simp only [Bool.and_eq_true, beq_iff_eq] at h_allowed
            rcases h_allowed with ⟨⟨h_iface, h_proto⟩, h_ports⟩
            refine ⟨h_iface, h_proto, ?_⟩
            simp only [Bool.or_eq_true, beq_iff_eq] at h_ports
            exact h_ports
          · -- pkt.flow.group != LLM_AGENT_GID
            rename_i h_grp_neq
            have h_g_eq : pkt.flow.group = LLM_AGENT_GID := hg
            have h_b : (pkt.flow.group == LLM_AGENT_GID) = true := by
              rw [h_g_eq]
              decide
            contradiction
        | tail _ h_tail =>
          exact h_inv e h_tail hg
      · exact h_inv
    · exact h_inv

/-- TCP sequence number window tracking structure -/
structure TcpSeqWindow where
  rcv_nxt : Nat
  rcv_wnd : Nat
  deriving DecidableEq, Repr

/-- Validates whether a packet sequence number falls within the active receive window -/
def isPacketInSeqWindow (pkt_seq : Nat) (win : TcpSeqWindow) : Bool :=
  pkt_seq ≥ win.rcv_nxt && pkt_seq < win.rcv_nxt + win.rcv_wnd

/-- Packet filter sequence number check -/
def evalPacketSeqCheck (pkt_seq : Nat) (win : TcpSeqWindow) : Verdict :=
  if isPacketInSeqWindow pkt_seq win then
    Verdict.Pass
  else
    Verdict.Drop

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem out_of_window_packet_strictly_dropped (pkt_seq : Nat) (win : TcpSeqWindow)
    (h_out : pkt_seq < win.rcv_nxt ∨ pkt_seq ≥ win.rcv_nxt + win.rcv_wnd) :
    evalPacketSeqCheck pkt_seq win = Verdict.Drop := by
  simp [evalPacketSeqCheck, isPacketInSeqWindow]
  omega

end Enclave
