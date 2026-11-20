/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Conjunctive Authorization Monotonicity (Cedar ∧ PoP-Biscuit) Proofs
Normative Specification: FS-704 §4.1, ADR-008, & ADVERSARIAL_SPEC_REVIEW_2026-11-04 §10.3
-/

namespace Enclave.ConjunctiveAuth

/-- Authorization request attributes for policy evaluation -/
structure AuthRequest where
  principal : String
  action : String
  resource : String
  epoch_timestamp : Nat
  deriving DecidableEq, Repr

/-- Discrete policy evaluation outcome -/
inductive PolicyDecision where
  | Allow : PolicyDecision
  | Deny : PolicyDecision
  deriving DecidableEq, Repr

/-- Abstract Cedar policy evaluation function (Cedar.Allow / Cedar.Forbid) -/
def CedarPolicySet := AuthRequest → PolicyDecision

/-- Abstract Biscuit token caveat evaluation function -/
def BiscuitToken := AuthRequest → PolicyDecision

/--
Canonical Conjunctive Authorization Guard:
A request is permitted if and ONLY if BOTH Cedar allows it AND the PoP-Biscuit token allows it.
(Cedar.Allow ∧ Biscuit.Allow)
-/
def evaluateConjunctive (cedar : CedarPolicySet) (biscuit : BiscuitToken) (req : AuthRequest) : Bool :=
  (cedar req == PolicyDecision.Allow) ∧ (biscuit req == PolicyDecision.Allow)

/--
Biscuit Token Attenuation Relation (b' ≤ b):
Token b' is a cryptographic attenuation of b if every request authorized
by b' is also authorized by b (caveats can only restrict, never widen).
-/
def Attenuates (b' b : BiscuitToken) : Prop :=
  ∀ req, b' req = PolicyDecision.Allow → b req = PolicyDecision.Allow

/-- Reflexivity of Biscuit attenuation -/
theorem attenuation_refl (b : BiscuitToken) : Attenuates b b := by
  intro req h
  exact h

/-- Transitivity of Biscuit attenuation -/
theorem attenuation_trans {b1 b2 b3 : BiscuitToken}
    (h12 : Attenuates b1 b2) (h23 : Attenuates b2 b3) : Attenuates b1 b3 := by
  intro req h
  exact h23 req (h12 req h)

/--
Cedar Policy Refinement Relation (c' ⊑ c):
A policy set c' refines c (e.g. by adding forbid rules or narrowing permit scopes)
if any request permitted by c' is also permitted by c.
-/
def PolicyRefines (c' c : CedarPolicySet) : Prop :=
  ∀ req, c' req = PolicyDecision.Allow → c req = PolicyDecision.Allow

/--
Theorem 3 (Conjunctive Authorization Monotonicity, F-021):
Given a Cedar policy set `c` and Biscuit tokens `b, b'` where `b'` attenuates `b`,
any request authorized under the attenuated token `b'` is strictly authorized under `b`.
Attenuation cannot widen permissions under conjunctive evaluation.
-/
theorem conjunctive_monotonicity
    (c : CedarPolicySet) (b b' : BiscuitToken) (req : AuthRequest)
    (h_atten : Attenuates b' b)
    (h_auth : evaluateConjunctive c b' req = true) :
    evaluateConjunctive c b req = true := by
  simp_all [evaluateConjunctive, Attenuates, PolicyRefines]

/--
Corollary 3.1 (Dual Monotonicity under Cedar Refinement and Biscuit Attenuation):
Strengthening Cedar policies (e.g. dynamic revocation) while simultaneously attenuating
Biscuit tokens preserves authorization safety monotonically.
-/
theorem conjunctive_dual_monotonicity
    (c c' : CedarPolicySet) (b b' : BiscuitToken) (req : AuthRequest)
    (h_c_refines : PolicyRefines c' c)
    (h_atten : Attenuates b' b)
    (h_auth : evaluateConjunctive c' b' req = true) :
    evaluateConjunctive c b req = true := by
  simp_all [evaluateConjunctive, Attenuates, PolicyRefines]

/--
Corollary 3.2 (Fail-Closed Safety on Compromised Attenuation):
An unauthorized request rejected by either engine remains rejected by the conjunctive gate.
-/
theorem conjunctive_fail_closed
    (c : CedarPolicySet) (b : BiscuitToken) (req : AuthRequest)
    (h_deny : c req = PolicyDecision.Deny ∨ b req = PolicyDecision.Deny) :
    evaluateConjunctive c b req = false := by
  simp [evaluateConjunctive]
  rcases h_deny with h | h <;> simp [h]

end Enclave.ConjunctiveAuth
