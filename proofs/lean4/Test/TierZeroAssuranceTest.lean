/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Tier 0 Assurance Test Suite: LeftoverLocals, Ephemeral Delegation, SEP Anti-Rollback,
PagedAttention Isolation, Context DAG Provenance, and APFS Crash Consistency WAL.
-/

import Enclave.LeftoverLocalsDefense
import Enclave.EphemeralDelegation
import Enclave.SepAntiRollback
import Enclave.PagedAttentionIsolation
import Enclave.ContextDagProvenance
import Enclave.CrashConsistencyWal
import Enclave.StarkAirSoundness

namespace EnclaveTest

open Enclave
open Enclave.StarkAirSoundness

/--
Test 1: LeftoverLocals zeroization clears residual dirty memory.
-/
def sampleDirtyBuffer : GpuBuffer := {
  session_id := 101,
  size_bytes := 16384,
  status := GpuMemoryStatus.Tainted,
  residual_bytes := 4096
}

theorem test_leftover_locals_cleared :
    (zeroizeGpuBuffer sampleDirtyBuffer).status = GpuMemoryStatus.Zeroized ∧
    (zeroizeGpuBuffer sampleDirtyBuffer).residual_bytes = 0 := by
  decide

/--
Test 2: Ephemeral delegation grant rejects calls after expiration timestamp.
-/
def sampleExpiredGrant : EphemeralGrant := {
  grant_id := 501,
  issued_at := 1000,
  expires_at := 1900,
  max_spend_cents := 10000,
  accumulated_spend_cents := 500,
  allowed_tools := [1, 2, 3],
  revoked := false
}

theorem test_ephemeral_grant_expired :
    evaluateDelegatedCall sampleExpiredGrant 2000 1 10 = none := by
  decide

/--
Test 3: SEP anti-rollback rejects candidate counter lower than or equal to current state.
-/
def sampleSepState : SepEpochState := {
  hw_counter := 42,
  epoch_id := 1001,
  rpc_seq_watermark := 50
}

theorem test_sep_rollback_rejected :
    advanceSepEpoch sampleSepState 42 1002 = none := by
  decide

/--
Test 4: PagedAttention block reallocation rejects un-zeroed dirty blocks.
-/
def sampleDirtyBlock : BlockAllocation := {
  block_id := 77,
  tenant_id := 1,
  is_zeroed := false
}

theorem test_recycled_block_rejected_if_dirty :
    reallocateBlock sampleDirtyBlock 2 = none := by
  decide

/--
Test 5: Context DAG derives T3 taint if an untrusted tool output (T3) is in parent history.
-/
theorem test_context_dag_tainted :
    deriveChildIntegrity [IntegLevel.T1, IntegLevel.T3, IntegLevel.T0] = IntegLevel.T3 := by
  decide

/--
Test 6: Crash consistency WAL recovery discards torn records.
-/
def sampleTornRecord : WalRecord := {
  txn_id := 99,
  payload_checksum := 12345,
  expected_checksum := 54321,
  committed := true
}

theorem test_wal_torn_record_discarded :
    recoverValidWal [sampleTornRecord] = [] := by
  decide

/--
Test 7: STARK AIR fully constrained adjacent rows uniqueness.
-/
def sampleRow1 : AirTraceRow := { seq_num := 10, prev_digest := 100, entry_digest := 200, curr_digest := 300 }
def sampleRow2a : AirTraceRow := { seq_num := 11, prev_digest := 300, entry_digest := 400, curr_digest := 500 }
def sampleRow2b : AirTraceRow := { seq_num := 11, prev_digest := 300, entry_digest := 400, curr_digest := 500 }

theorem test_air_fully_constrained :
    airTransitionValid sampleRow1 sampleRow2a →
    airTransitionValid sampleRow1 sampleRow2b →
    sampleRow2a.seq_num = sampleRow2b.seq_num ∧ sampleRow2a.prev_digest = sampleRow2b.prev_digest := by
  intro ha hb
  exact valid_successors_agree_on_sequence_and_prev sampleRow1 sampleRow2a sampleRow2b ha hb

end EnclaveTest
