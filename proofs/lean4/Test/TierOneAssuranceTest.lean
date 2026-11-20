/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Tier 1 Assurance Test Suite: Extraction Gap Refinement & Compiler Safety Fence
-/

import Enclave.ExtractionGapDefense

namespace EnclaveTest

open Enclave

/--
Test 1: Extracted program state executes a valid transition step.
-/
def sampleExtractedState : ExtractedProgramState := {
  fsm_state := RustFlowState.PlanCompileT1,
  fuel := 10,
  has_panicked := false,
  quarantine_latched := false
}

theorem test_extraction_valid_step :
    (stepExtracted sampleExtractedState RustFlowEvent.PlanAccepted).fsm_state =
      RustFlowState.CapabilityExec ∧
    (stepExtracted sampleExtractedState RustFlowEvent.PlanAccepted).fuel = 9 := by
  decide

/--
Test 2: Zero fuel triggers immediate quarantine fail-closed safety fence.
-/
def sampleZeroFuelState : ExtractedProgramState := {
  fsm_state := RustFlowState.PlanCompileT1,
  fuel := 0,
  has_panicked := false,
  quarantine_latched := false
}

theorem test_extraction_zero_fuel_quarantined :
    (stepExtracted sampleZeroFuelState RustFlowEvent.PlanAccepted).fsm_state =
      RustFlowState.QuarantineAbort ∧
    (stepExtracted sampleZeroFuelState RustFlowEvent.PlanAccepted).quarantine_latched = true := by
  decide

/--
Test 3: Invalid event in extracted state transitions deterministically to QuarantineAbort.
-/
theorem test_extraction_invalid_event_quarantined :
    (stepExtracted sampleExtractedState RustFlowEvent.SleepOrLock).fsm_state =
      RustFlowState.QuarantineAbort := by
  decide

end EnclaveTest
