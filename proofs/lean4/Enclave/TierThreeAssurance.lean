/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Enterprise Enclave Formal Assurance Team
-/
import Enclave.Lattice

/-!
# Tier 3 Formal Assurance: Post-Quantum Hybrid Cryptography & HNDL Defense (GAP-62)

This module mechanizes formal safety theorems for Tier 3 security:
1. `unbroken_flag_iff_disjunction`: Hybrid key establishment remains uncompromised
   if either the classical (X25519) or post-quantum (ML-KEM-768) primitive is unbroken.
2. `signature_flags_iff_conjunction`: Hybrid root attestation requires both
   Ed25519 and ML-DSA-65 signatures to be valid; forgery requires breaking both primitives.
3. `wire_table_rejects_hybrid_to_classical`: Sessions negotiated with PQC wire capability strictly
   reject downgraded classical-only handshakes.
-/

-- ASSURANCE: a standalone specification using Nat, records and Booleans.
-- Its original mechanism terminology is an interpretation of model fields.
-- No cryptographic protocol, deployed constraints, OS or hardware is verified here.
namespace Enclave.TierThree

/-- Cryptographic primitive compromise state. -/
structure CryptoState where
  classical_broken : Bool
  pqc_broken : Bool
  deriving Repr, DecidableEq

/-- A shared secret is confidential if at least one component remains unbroken. -/
def shared_secret_confidential (s : CryptoState) : Bool :=
  !(s.classical_broken && s.pqc_broken)

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem unbroken_flag_iff_disjunction (s : CryptoState) :
    shared_secret_confidential s = true ↔ (s.classical_broken = false ∨ s.pqc_broken = false) := by
  unfold shared_secret_confidential
  cases s.classical_broken <;> cases s.pqc_broken <;> decide

/-- Dual signature verification requirement. -/
def hybrid_signature_valid (classical_valid : Bool) (pqc_valid : Bool) : Bool :=
  classical_valid && pqc_valid

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem signature_flags_iff_conjunction (c_valid pqc_valid : Bool) :
    hybrid_signature_valid c_valid pqc_valid = true ↔ (c_valid = true ∧ pqc_valid = true) := by
  unfold hybrid_signature_valid
  cases c_valid <;> cases pqc_valid <;> decide

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem false_signature_flag_rejects
    (pqc_sound : Bool) (h_pqc : pqc_sound = false) :
    hybrid_signature_valid true pqc_sound = false := by
  unfold hybrid_signature_valid
  rw [h_pqc]
  decide

/-- Wire protocol cryptographic policy suite. -/
inductive WireSuite where
  | ClassicalOnly : WireSuite
  | HybridPqc : WireSuite
  deriving Repr, DecidableEq

/-- Handshake admission policy enforcing post-quantum wire requirements. -/
def handshake_admissible (required_suite : WireSuite) (offered_suite : WireSuite) : Bool :=
  match required_suite, offered_suite with
  | WireSuite.HybridPqc, WireSuite.HybridPqc => true
  | WireSuite.HybridPqc, WireSuite.ClassicalOnly => false
  | WireSuite.ClassicalOnly, _ => true

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem wire_table_rejects_hybrid_to_classical :
    handshake_admissible WireSuite.HybridPqc WireSuite.ClassicalOnly = false := by
  rfl

/-! # Inductive Multi-Component Hybrid Attestation Chain -/

/-- Verifies an inductive sequence of hybrid signature components. -/
def verifyHybridSignatureChain : List (Bool × Bool) → Bool
  | [] => true
  | (c, p) :: rest => hybrid_signature_valid c p && verifyHybridSignatureChain rest

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem hybrid_chain_invalid_if_step_fails
    (c p : Bool) (rest : List (Bool × Bool))
    (h_step : hybrid_signature_valid c p = false) :
    verifyHybridSignatureChain ((c, p) :: rest) = false := by
  dsimp [verifyHybridSignatureChain]
  rw [h_step]
  rfl

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem handshake_admissible_refl (s : WireSuite) :
    handshake_admissible s s = true := by
  cases s <;> rfl

end Enclave.TierThree
