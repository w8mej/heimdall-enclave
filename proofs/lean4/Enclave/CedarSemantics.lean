/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Cedar Policy Engine Semantics: Default-Deny & Forbid Precedence Proofs
Normative Specification: AWS Cedar Spec, FS-704, & crates/enclave-agent-runtime/src/cedar_engine.rs
-/

namespace Enclave.CedarSemantics

/-- Authorization decisions emitted by the policy decision point (PDP) -/
inductive CedarDecision where
  | Allow : CedarDecision
  | Deny : CedarDecision
  deriving DecidableEq, Repr

/-- Policy effects: Permit allows an action; Forbid unconditionally prohibits it -/
inductive PolicyEffect where
  | Permit : PolicyEffect
  | Forbid : PolicyEffect
  deriving DecidableEq, Repr

/-- Abstract request context representing an incoming agent tool invocation -/
structure AuthRequest where
  principal : String
  action : String
  resource : String
  deriving DecidableEq, Repr

/-- Individual Cedar policy rule with an effect and match predicate -/
structure CedarPolicy where
  policy_id : String
  effect : PolicyEffect
  matchesReq : AuthRequest → Bool

/-- Checks whether any matching policy in the set has effect == Forbid -/
def hasMatchingForbid (policies : List CedarPolicy) (req : AuthRequest) : Bool :=
  policies.any (fun p => p.effect == PolicyEffect.Forbid && p.matchesReq req)

/-- Checks whether any matching policy in the set has effect == Permit -/
def hasMatchingPermit (policies : List CedarPolicy) (req : AuthRequest) : Bool :=
  policies.any (fun p => p.effect == PolicyEffect.Permit && p.matchesReq req)

/--
Deterministic Cedar policy evaluation algorithm:
1. Forbid Precedence: If ANY matching policy is Forbid, decision is strictly Deny.
2. Permit Requirement: If no Forbid matchesReq, at least ONE Permit must match to Allow.
3. Default Deny: If no policies match or only Permits fail to match, decision is Deny.
-/
def evalCedarPolicySet (policies : List CedarPolicy) (req : AuthRequest) : CedarDecision :=
  if hasMatchingForbid policies req then
    CedarDecision.Deny
  else if hasMatchingPermit policies req then
    CedarDecision.Allow
  else
    CedarDecision.Deny

/--
Theorem 16.1 (Cedar Default-Deny Soundness):
An empty policy set deterministically evaluates to Deny: access is never granted
in the absence of an explicit matching Permit policy.
-/
theorem cedar_default_deny (req : AuthRequest) :
    evalCedarPolicySet [] req = CedarDecision.Deny := by
  rfl

/--
Theorem 16.2 (Forbid Precedence / Forbid Overrides Permit):
If any policy in the policy set has effect == Forbid and matchesReq the incoming request,
the final decision is deterministically Deny, regardless of how many Permit policies match.
-/
theorem forbid_overrides_permit (policies : List CedarPolicy) (req : AuthRequest)
    (forbid_p : CedarPolicy)
    (h_in : forbid_p ∈ policies)
    (h_effect : forbid_p.effect = PolicyEffect.Forbid)
    (h_matches : forbid_p.matchesReq req = true) :
    evalCedarPolicySet policies req = CedarDecision.Deny := by
  dsimp [evalCedarPolicySet]
  have h_forbid : hasMatchingForbid policies req = true := by
    dsimp [hasMatchingForbid]
    rw [List.any_eq_true]
    refine ⟨forbid_p, h_in, ?_⟩
    simp only [Bool.and_eq_true, beq_iff_eq]
    exact ⟨h_effect, h_matches⟩
  rw [h_forbid]
  rfl

/--
Theorem 16.3 (Forbid Addition Monotonicity / Privilege Narrowing):
Adding a Forbid policy to an existing policy set can only narrow or maintain permissions:
if the expanded policy set grants Allow, the original policy set must have granted Allow.
-/
theorem permit_monotonicity_under_forbid
    (policies : List CedarPolicy) (req : AuthRequest)
    (forbid_p : CedarPolicy)
    (h_effect : forbid_p.effect = PolicyEffect.Forbid)
    (h_allow_after : evalCedarPolicySet (forbid_p :: policies) req = CedarDecision.Allow) :
    evalCedarPolicySet policies req = CedarDecision.Allow := by
  simp [evalCedarPolicySet, hasMatchingForbid, hasMatchingPermit, h_effect] at *
  split at h_allow_after <;> simp_all

/--
Theorem 16.4 (Forbid Addition Never Widens Permissions):
Adding a Forbid policy can never cause a previously Denied request to become Allowed.
-/
theorem forbid_addition_never_widens
    (policies : List CedarPolicy) (req : AuthRequest)
    (forbid_p : CedarPolicy)
    (h_effect : forbid_p.effect = PolicyEffect.Forbid)
    (h_denied_before : evalCedarPolicySet policies req = CedarDecision.Deny) :
    evalCedarPolicySet (forbid_p :: policies) req = CedarDecision.Deny := by
  cases h_after : evalCedarPolicySet (forbid_p :: policies) req with
  | Deny => rfl
  | Allow =>
    have h_contra := permit_monotonicity_under_forbid policies req forbid_p h_effect h_after
    rw [h_denied_before] at h_contra
    contradiction

end Enclave.CedarSemantics
