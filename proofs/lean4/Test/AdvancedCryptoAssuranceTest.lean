/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Advanced Cryptography & ZK Assurance Test Suite:
Compositional Noninterference, Hybrid KDF, ZK Witness Uniqueness, FRI Soundness, and HPKE AuthEncap.
-/

import Enclave.CompositionalNoninterference
import Enclave.HybridKdfCombiner
import Enclave.ZkWitnessUniqueness
import Enclave.FriProximitySoundness
import Enclave.HpkeAuthEncapSoundness

namespace EnclaveTest

open Enclave
open Enclave.ZkWitnessUniqueness

/-- Test 1: M1 to M2 transmission monotonically updates M2's confidentiality label. -/
def sampleM1 : ReactiveEnclaveState := {
  enclave_uid := 701,
  conf_level := ConfLevel.C1,
  outbox := []
}

def sampleM2 : ReactiveEnclaveState := {
  enclave_uid := 703,
  conf_level := ConfLevel.C1,
  outbox := []
}

def sampleSystem : CompositeEnclaveSystem := { m1 := sampleM1, m2 := sampleM2 }

def sampleMsg : EnclaveMessage := {
  sender_uid := 701,
  receiver_uid := 703,
  label := ConfLevel.C3,
  payload := 42
}

theorem test_composition_label_raised :
    match transmitM1toM2 sampleSystem sampleMsg with
    | some sys' => sys'.m2.conf_level = ConfLevel.C3
    | none => false := by
  rfl

/-- Test 2: Hybrid KDF remains secure if only classical is broken. -/
def sampleKdfInput : HybridKdfInput := {
  classical_ss := { is_adversary_broken := true, min_entropy_bits := 0 },
  pqc_ss := { is_adversary_broken := false, min_entropy_bits := 256 }
}

theorem test_hybrid_kdf_classical_break_tolerated :
    (deriveHybridMasterKey sampleKdfInput).is_secure = true := by
  rfl

/-- Test 3: AIR transition validates correct consecutive row. -/
def rA : TraceRow := { seq_id := 10, state_digest := 100 }
def rB : TraceRow := { seq_id := 11, state_digest := nextTraceState 100 11 }

theorem test_air_row_valid :
    airTransitionValid rA rB = true := by
  rfl

/-- Test 4: FRI folding halves domain size. -/
def sampleFriRound : FriRoundState := {
  round_number := 1,
  domain_size := 1024,
  max_poly_degree := 256
}

theorem test_fri_folding_halves_degree :
    (foldFriRound sampleFriRound).max_poly_degree = 128 := by
  rfl

/-- Test 5: HPKE Decapsulation fails on invalid auth tag. -/
def sampleHpkeCt : HpkeAuthCiphertext := {
  sender_pubkey_id := 10,
  receiver_pubkey_id := 20,
  ciphertext_bytes := 1000,
  auth_tag := 9999
}

theorem test_hpke_tampered_tag_fails :
    authDecap sampleHpkeCt 20 10 1234 = none := by
  rfl

end EnclaveTest
