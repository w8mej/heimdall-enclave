/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Formal Verification Abstraction Gap & Aeneas/Charon Translation Validation Proofs
Normative Specification: FORMAL_METHODS_DEFENSE.md §2, GAP-48, & crates/enclave-agent-runtime/src/flow_fsm.rs
-/

import Enclave.RustModelBridge

-- ASSURANCE: a standalone specification using Nat, records and Booleans.
-- Its original mechanism terminology is an interpretation of model fields.
-- No cryptographic protocol, deployed constraints, OS or hardware is verified here.
namespace Enclave

/-! # Formal Extraction Gap & Refinement Invariants -/

/--
Low-Level Extracted State representation reflecting Charon/Aeneas Low-Level Borrow
Calculus (LLBC) translated into pure functional terms.
`fsm_state`: Mirror of Rust runtime `FlowGate` state.
`fuel`: Monotonic execution fuel bounding computation steps.
`has_panicked`: Boolean indicating whether a panic condition occurred.
`quarantine_latched`: Hardware integrity quarantine status.
-/
structure ExtractedProgramState where
  fsm_state : RustFlowState
  fuel : Nat
  has_panicked : Bool
  quarantine_latched : Bool
  deriving DecidableEq, Repr

/-- Abstract security classification derived from the extracted state -/
def abstractSecurityState (s : ExtractedProgramState) : SecurityClassification :=
  abstractState s.fsm_state

/--
Operational Stepper in Extracted Borrow Calculus:
Evaluates an event transition under bounded fuel. If fuel is exhausted or an invalid
transition occurs, the system safely halts or transitions to `QuarantineAbort`.
-/
def stepExtracted
    (s : ExtractedProgramState)
    (e : RustFlowEvent) : ExtractedProgramState :=
  if s.fuel == 0 || s.has_panicked || s.quarantine_latched then
    { s with fsm_state := RustFlowState.QuarantineAbort, has_panicked := false, quarantine_latched := true }
  else
    let next_fsm := rustStep s.fsm_state e
    let is_quarantine := (next_fsm == RustFlowState.QuarantineAbort)
    { fsm_state := next_fsm,
      fuel := s.fuel - 1,
      has_panicked := false,
      quarantine_latched := s.quarantine_latched || is_quarantine }

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem model_record_active_step_matches_copied_fsm
    (s : ExtractedProgramState)
    (e : RustFlowEvent)
    (h_active : s.fuel > 0 ∧ ¬s.has_panicked ∧ ¬s.quarantine_latched)
    (h_valid : (rustStep s.fsm_state e) ≠ RustFlowState.QuarantineAbort) :
    abstractSecurityState (stepExtracted s e) =
      specStep (abstractSecurityState s) (abstractEvent e) := by
  have hp : s.has_panicked = false := by simpa using h_active.2.1
  have hq : s.quarantine_latched = false := by simpa using h_active.2.2
  have hf : (s.fuel == 0) = false := by simp; omega
  simpa [stepExtracted, abstractSecurityState, hf, hp, hq] using
    copied_fsm_nonabort_step_refines s.fsm_state e h_valid

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem model_record_fault_latches_quarantine
    (s : ExtractedProgramState)
    (e : RustFlowEvent)
    (h_exhausted : s.fuel = 0 ∨ s.has_panicked ∨ s.quarantine_latched) :
    (stepExtracted s e).fsm_state = RustFlowState.QuarantineAbort ∧
    (stepExtracted s e).quarantine_latched = true := by
  rcases h_exhausted with h | h | h <;> simp [stepExtracted, h]

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem no_panic_termination
    (s : ExtractedProgramState)
    (e : RustFlowEvent) :
    (stepExtracted s e).has_panicked = false ∧
    (stepExtracted s e).fuel ≤ s.fuel := by
  dsimp [stepExtracted]
  split
  · exact ⟨rfl, Nat.le_refl s.fuel⟩
  · exact ⟨rfl, Nat.sub_le s.fuel 1⟩

end Enclave
