/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

NIST SP 800-227 Dual-PRF Hybrid KDF Combiner (ML-KEM-768 + X25519)
Normative Specification: FS-707, FIPS 203/204, & crates/enclave-crypto/src/pqc.rs
-/

-- ASSURANCE: a standalone specification using Nat, records and Booleans.
-- Its original mechanism terminology is an interpretation of model fields.
-- No cryptographic protocol, deployed constraints, OS or hardware is verified here.
namespace Enclave

/-! # Dual-Secret HKDF Extractor Model -/

/-- State of an individual shared-secret component. -/
structure SharedSecretComponent where
  is_adversary_broken : Bool
  min_entropy_bits : Nat
  deriving DecidableEq, Repr

/-- Hybrid dual-source key derivation input (ML-KEM-768 + X25519). -/
structure HybridKdfInput where
  classical_ss : SharedSecretComponent
  pqc_ss : SharedSecretComponent
  deriving DecidableEq, Repr

/-- Master derived session key properties. -/
structure MasterSessionKey where
  is_secure : Bool
  effective_entropy_bits : Nat
  deriving DecidableEq, Repr

/--
Dual-source HKDF combiner: K = HKDF-Extract(salt, ss_pqc || ss_classical).
The derived key is secure if at least one shared secret remains unbroken by the adversary.
-/
def deriveHybridMasterKey (input : HybridKdfInput) : MasterSessionKey := {
  is_secure := !(input.classical_ss.is_adversary_broken && input.pqc_ss.is_adversary_broken),
  effective_entropy_bits := max input.classical_ss.min_entropy_bits input.pqc_ss.min_entropy_bits
}

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem model_unbroken_flag_disjunction (input : HybridKdfInput) :
    (deriveHybridMasterKey input).is_secure = true ↔
    (input.classical_ss.is_adversary_broken = false ∨ input.pqc_ss.is_adversary_broken = false) := by
  dsimp [deriveHybridMasterKey]
  cases input.classical_ss.is_adversary_broken <;>
  cases input.pqc_ss.is_adversary_broken <;>
  decide

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem model_max_ge_pqc_field (input : HybridKdfInput) :
    (deriveHybridMasterKey input).effective_entropy_bits ≥ input.pqc_ss.min_entropy_bits := by
  dsimp [deriveHybridMasterKey]
  exact Nat.le_max_right input.classical_ss.min_entropy_bits input.pqc_ss.min_entropy_bits

/-! # Formal NIST SP 800-227 Multi-Key Expansion & Monotonicity -/

/-- HKDF-Expand context label distinguishing derived key streams. -/
inductive KdfContext where
  | EncryptionKey
  | IntegrityKey
  | AttestationKey
  | RollingRatchetKey
  deriving DecidableEq, Repr

/-- Derived sub-key output from the expansion step. -/
structure DerivedSubKey where
  context : KdfContext
  key_entropy_bits : Nat
  is_active : Bool
  deriving DecidableEq, Repr

/-- Derives a domain-separated subkey from the master key. -/
def expandSubKey (master : MasterSessionKey) (ctx : KdfContext) : Option DerivedSubKey :=
  if master.is_secure && master.effective_entropy_bits ≥ 128 then
    some {
      context := ctx,
      key_entropy_bits := min master.effective_entropy_bits 256,
      is_active := true
    }
  else
    none

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem model_max_ge_classical_field (input : HybridKdfInput) :
    (deriveHybridMasterKey input).effective_entropy_bits ≥ input.classical_ss.min_entropy_bits := by
  dsimp [deriveHybridMasterKey]
  exact Nat.le_max_left input.classical_ss.min_entropy_bits input.pqc_ss.min_entropy_bits

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem expand_subkey_requires_secure_master
    (master : MasterSessionKey) (ctx : KdfContext)
    (h_insecure : master.is_secure = false) :
    expandSubKey master ctx = none := by
  dsimp [expandSubKey]
  rw [h_insecure]
  rfl

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem hybrid_entropy_monotonic
    (c : SharedSecretComponent) (pqc1 pqc2 : SharedSecretComponent)
    (h_pqc : pqc1.min_entropy_bits ≤ pqc2.min_entropy_bits) :
    (deriveHybridMasterKey { classical_ss := c, pqc_ss := pqc1 }).effective_entropy_bits ≤
    (deriveHybridMasterKey { classical_ss := c, pqc_ss := pqc2 }).effective_entropy_bits := by
  dsimp [deriveHybridMasterKey]
  omega

/-! # Cryptographic Dual-PRF Distinguishing Advantage Security Reduction -/

/-- Adversary distinguishing advantage scaled to permille (0 to 1000). 1000 = complete break. -/
structure PrfAdvantage where
  adv_permille : Nat
  h_bound : adv_permille ≤ 1000
  deriving DecidableEq, Repr

/-- Dual-PRF security reduction: hybrid distinguishing advantage is bounded by min(adv1, adv2) -/
def dualPrfCombinedAdvantage (adv1 adv2 : PrfAdvantage) : Nat :=
  min adv1.adv_permille adv2.adv_permille

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem minimum_le_each_input (adv_classical adv_pqc : PrfAdvantage) :
    dualPrfCombinedAdvantage adv_classical adv_pqc ≤ adv_classical.adv_permille ∧
    dualPrfCombinedAdvantage adv_classical adv_pqc ≤ adv_pqc.adv_permille := by
  dsimp [dualPrfCombinedAdvantage]
  refine ⟨Nat.min_le_left _ _, Nat.min_le_right _ _⟩

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem minimum_at_left_upper_bound (adv_pqc : PrfAdvantage)
    (adv_classical_broken : PrfAdvantage)
    (h_broken : adv_classical_broken.adv_permille = 1000) :
    dualPrfCombinedAdvantage adv_classical_broken adv_pqc = adv_pqc.adv_permille := by
  dsimp [dualPrfCombinedAdvantage]
  rw [h_broken]
  have h_le := adv_pqc.h_bound
  exact Nat.min_eq_right h_le

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem minimum_at_right_upper_bound (adv_classical : PrfAdvantage)
    (adv_pqc_broken : PrfAdvantage)
    (h_broken : adv_pqc_broken.adv_permille = 1000) :
    dualPrfCombinedAdvantage adv_classical adv_pqc_broken = adv_classical.adv_permille := by
  dsimp [dualPrfCombinedAdvantage]
  rw [h_broken]
  have h_le := adv_classical.h_bound
  exact Nat.min_eq_left h_le

end Enclave
