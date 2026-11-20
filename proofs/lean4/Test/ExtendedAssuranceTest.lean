/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Extended Assurance Test Suite: SQL Guard, DPoP, Cedar, Bao & STARK AIR
-/

import Enclave.SqlAstGuard
import Enclave.DpopBinding
import Enclave.CedarSemantics
import Enclave.BaoStreamVerification
import Enclave.StarkAirSoundness

namespace EnclaveTest

open Enclave
open Enclave.StarkAirSoundness
open Enclave.CedarSemantics

/--
Test 1: SQL AST Guard rejects data modification statements (INSERT).
-/
def sampleInsert : SqlStmt :=
  SqlStmt.Insert "patients" ["name", "ssn"] [SqlExpr.LitString "Alice", SqlExpr.LitString "000-00-0000"]

theorem test_sql_insert_rejected :
    isReadOnlySql sampleInsert = false := by
  rfl

/--
Test 2: RFC 9449 DPoP proof verification succeeds on valid, fresh, un-replayed proofs.
-/
def sampleDpopProof : DpopProof := {
  jti := "dpop-jti-001"
  htm := "POST"
  htu := "/tools/query"
  iat := 1000
  ath := modelTokenPrefix "access_token_xyz"
  public_key := "thumbprint-key-1"
  signature_valid := true
}

theorem test_dpop_valid_verification :
    verifyDpopProof sampleDpopProof "access_token_xyz" "POST" "/tools/query" 1030 [] = true := by
  decide

/--
Test 3: Cedar Forbid Precedence strictly overrides matching Permit policies.
-/
def permitAll : CedarPolicy := {
  policy_id := "permit-all"
  effect := PolicyEffect.Permit
  matchesReq := fun _ => true
}

def forbidToolExec : CedarPolicy := {
  policy_id := "forbid-tool-exec"
  effect := PolicyEffect.Forbid
  matchesReq := fun req => req.action == "execute_destructive"
}

def sampleReq : AuthRequest := {
  principal := "agent_704"
  action := "execute_destructive"
  resource := "vault"
}

theorem test_cedar_forbid_precedence :
    evalCedarPolicySet [permitAll, forbidToolExec] sampleReq = CedarDecision.Deny := by
  rfl

/--
Test 4: BLAKE3 Bao stream verification succeeds on sequential un-tampered chunks.
-/
def chunk0 : BaoChunk := { index := 0, digest := 111 }
def chunk1 : BaoChunk := { index := 1, digest := 222 }
def sampleChunks : List BaoChunk := [chunk0, chunk1]

theorem test_bao_stream_valid :
    let expected_root := linearChunkCode sampleChunks
    verifyBaoStream expected_root 2 sampleChunks = true := by
  decide

/--
Test 5: STARK AIR transition constraint successfully verifies contiguous, gap-free rows.
-/
def row1 : AirTraceRow := { seq_num := 100, prev_digest := 555, entry_digest := 777, curr_digest := 999 }
def row2 : AirTraceRow := { seq_num := 101, prev_digest := 999, entry_digest := 888, curr_digest := 1234 }

theorem test_air_transition_eval :
    evalAirTransition row1 row2 = true := by
  decide

end EnclaveTest
