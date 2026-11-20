/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Scoped Ephemeral Delegation Grants & Autonomous Agent Execution Proofs
Normative Specification: FS-703 §4, FS-704 §3.1, ADR-014, & crates/enclave-agent-runtime/src/delegation.rs
-/

namespace Enclave

/-! # Ephemeral Delegation Grant & Bounded Spend Ledger -/

/--
Ephemeral capability token granted to an autonomous agent loop following an initial
human biometric ceremony (Touch ID / YubiKey).
Constrained by bounded wall-clock expiry, cumulative financial/compute budget,
and an explicit tool allowlist.
-/
structure EphemeralGrant where
  grant_id : Nat
  issued_at : Nat
  expires_at : Nat
  max_spend_cents : Nat
  accumulated_spend_cents : Nat
  allowed_tools : List Nat
  revoked : Bool
  deriving DecidableEq, Repr

/-- Validity predicate for an ephemeral grant at a given timestamp -/
def isGrantActive (g : EphemeralGrant) (now : Nat) : Bool :=
  (g.revoked == false) &&
  (now < g.expires_at) &&
  (now ≥ g.issued_at)

/--
Operational Invocation Gate:
Evaluates whether a tool call with specific cost can proceed under the grant.
Updates the cumulative spend counter if permitted; fails closed otherwise.
-/
def evaluateDelegatedCall
    (g : EphemeralGrant)
    (now : Nat)
    (tool_id : Nat)
    (cost_cents : Nat) : Option EphemeralGrant :=
  if isGrantActive g now &&
     (g.allowed_tools.contains tool_id) &&
     (g.accumulated_spend_cents + cost_cents ≤ g.max_spend_cents) then
    some { g with accumulated_spend_cents := g.accumulated_spend_cents + cost_cents }
  else
    none

/--
Theorem 20.1 (Grant Expiry Invariant):
When wall-clock time reaches or exceeds the grant's expiration timestamp (`now ≥ expires_at`),
any attempted tool execution is unconditionally rejected (`evaluateDelegatedCall = none`),
preventing zombie or unattended lingering agent authority.
-/
theorem grant_expiry_invariant
    (g : EphemeralGrant)
    (now tool_id cost : Nat)
    (h_expired : now ≥ g.expires_at) :
    evaluateDelegatedCall g now tool_id cost = none := by
  simp_all [isGrantActive, evaluateDelegatedCall] <;> omega

/--
Theorem 20.2 (Delegation Grant Bounded Budget):
No tool invocation can proceed if the incremental cost causes cumulative spend
to exceed the authorized budget (`accumulated + cost > max_spend`).
-/
theorem delegation_grant_bounded_budget
    (g : EphemeralGrant)
    (now tool_id cost : Nat)
    (h_budget_exceeded : g.accumulated_spend_cents + cost > g.max_spend_cents) :
    evaluateDelegatedCall g now tool_id cost = none := by
  simp_all [isGrantActive, evaluateDelegatedCall] <;> omega

/--
Theorem 20.3 (Unauthorized Tool Rejection):
Invoking a tool not explicitly listed in the grant's allowlist is strictly rejected.
-/
theorem unauthorized_tool_rejected
    (g : EphemeralGrant)
    (now tool_id cost : Nat)
    (h_unauth : g.allowed_tools.contains tool_id = false) :
    evaluateDelegatedCall g now tool_id cost = none := by
  dsimp [evaluateDelegatedCall]
  rw [h_unauth]
  simp

/--
Theorem 20.4 (Attenuated Child Never Widens Budget):
Given a parent grant and an attenuated child grant with budget `c_child ≤ c_parent`,
the total spend under the child is bounded by the parent's maximum spend allowance.
-/
theorem attenuated_child_never_widens
    (parent_budget child_budget child_spend : Nat)
    (h_attenuated : child_budget ≤ parent_budget)
    (h_within_child : child_spend ≤ child_budget) :
    child_spend ≤ parent_budget := by
  exact Nat.le_trans h_within_child h_attenuated

/-! # Formal Capability Attenuation Lattice & Multi-Step Invariants -/

/--
Formal Attenuation Order on Ephemeral Grants:
A child grant `g'` is an attenuation of parent grant `g` if:
1. Child expiry is no later than parent expiry.
2. Child max spend is no greater than parent max spend.
3. Every tool authorized by child is also authorized by parent.
4. Child cannot un-revoke a revoked parent.
-/
def GrantAttenuates (g' g : EphemeralGrant) : Prop :=
  g'.expires_at ≤ g.expires_at ∧
  g'.max_spend_cents ≤ g.max_spend_cents ∧
  (∀ t, g'.allowed_tools.contains t = true → g.allowed_tools.contains t = true) ∧
  (g.revoked = true → g'.revoked = true)

/--
Theorem 20.5 (Grant Attenuation Reflexivity):
Every grant attenuates itself.
-/
theorem grant_attenuation_refl (g : EphemeralGrant) : GrantAttenuates g g := by
  refine ⟨Nat.le_refl _, Nat.le_refl _, fun _ h => h, fun h => h⟩

/--
Theorem 20.6 (Grant Attenuation Transitivity):
Sub-delegation preserves capability attenuation transitively down an arbitrary execution chain.
-/
theorem grant_attenuation_trans {g1 g2 g3 : EphemeralGrant}
    (h12 : GrantAttenuates g1 g2) (h23 : GrantAttenuates g2 g3) :
    GrantAttenuates g1 g3 := by
  rcases h12 with ⟨h_exp12, h_spend12, h_tools12, h_rev12⟩
  rcases h23 with ⟨h_exp23, h_spend23, h_tools23, h_rev23⟩
  refine ⟨
    Nat.le_trans h_exp12 h_exp23,
    Nat.le_trans h_spend12 h_spend23,
    fun t ht => h_tools23 t (h_tools12 t ht),
    fun hr => h_rev12 (h_rev23 hr)
  ⟩

/--
Theorem 20.7 (Spend Monotonicity):
Any successful tool invocation strictly increases or maintains cumulative spend.
-/
theorem delegated_call_spend_monotonic
    (g g' : EphemeralGrant) (now tool_id cost : Nat)
    (h_call : evaluateDelegatedCall g now tool_id cost = some g') :
    g.accumulated_spend_cents ≤ g'.accumulated_spend_cents := by
  dsimp [evaluateDelegatedCall] at h_call
  split at h_call
  · cases h_call
    dsimp
    omega
  · contradiction

/--
Theorem 20.8 (Cumulative Spend Invariant):
Any successful tool execution maintains the invariant that cumulative spend does not exceed max spend.
-/
theorem delegated_call_spend_bounded
    (g g' : EphemeralGrant) (now tool_id cost : Nat)
    (h_call : evaluateDelegatedCall g now tool_id cost = some g') :
    g'.accumulated_spend_cents ≤ g.max_spend_cents := by
  simp [evaluateDelegatedCall] at h_call
  rcases h_call with ⟨hcond, heq⟩
  cases heq
  simp at *
  omega

/--
Theorem 20.9 (Max Spend Invariance Under Execution):
Executing a delegated tool call does not alter the maximum spend cap of the grant.
-/
theorem delegated_call_preserves_cap
    (g g' : EphemeralGrant) (now tool_id cost : Nat)
    (h_call : evaluateDelegatedCall g now tool_id cost = some g') :
    g'.max_spend_cents = g.max_spend_cents := by
  dsimp [evaluateDelegatedCall] at h_call
  split at h_call
  · cases h_call; rfl
  · contradiction

end Enclave
