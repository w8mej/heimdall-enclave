/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Enterprise Enclave Formal Assurance Team
-/
import Enclave.TierThreeAssurance

/-!
# Tier 3 Formal Assurance Test Suite (GAP-62)

Validates the mechanized invariants:
- Hybrid KEM dual-security soundness
- Hybrid dual-signature verification soundness
- Anti-downgrade resistance for post-quantum wire handshakes
-/

namespace Enclave.Test.TierThreeAssurance

open Enclave.TierThree

/-- Test 1: Classical broken, PQC intact -> Hybrid KEM remains confidential. -/
theorem test_kem_classical_broken_pqc_intact :
    shared_secret_confidential ⟨true, false⟩ = true := by
  decide

/-- Test 2: Classical intact, PQC broken -> Hybrid KEM remains confidential. -/
theorem test_kem_classical_intact_pqc_broken :
    shared_secret_confidential ⟨false, true⟩ = true := by
  decide

/-- Test 3: Both broken -> Hybrid KEM compromised. -/
theorem test_kem_both_broken :
    shared_secret_confidential ⟨true, true⟩ = false := by
  decide

/-- Test 4: Forged classical signature with invalid PQC is rejected. -/
theorem test_hybrid_signature_rejects_pqc_invalid :
    hybrid_signature_valid true false = false := by
  decide

/-- Test 5: Valid classical and valid PQC is accepted. -/
theorem test_hybrid_signature_accepts_both_valid :
    hybrid_signature_valid true true = true := by
  decide

/-- Test 6: Hybrid wire downgrade attempt is rejected. -/
theorem test_downgrade_rejected :
    handshake_admissible WireSuite.HybridPqc WireSuite.ClassicalOnly = false := by
  decide

end Enclave.Test.TierThreeAssurance
