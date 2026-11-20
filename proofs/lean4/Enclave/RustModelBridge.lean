/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Rust Runtime Flow FSM Translation Validation & Bisimulation Contract
Normative Specification: crates/enclave-agent-runtime/src/flow_fsm.rs & FS-704 §5.5
-/

-- ASSURANCE: a standalone specification using Nat, records and Booleans.
-- Its original mechanism terminology is an interpretation of model fields.
-- No cryptographic protocol, deployed constraints, OS or hardware is verified here.
namespace Enclave

/-- Concrete Rust FlowGate states mirroring crates/enclave-agent-runtime/src/flow_fsm.rs -/
inductive RustFlowState where
  | PlanCompileT1 : RustFlowState
  | CapabilityExec : RustFlowState
  | OpaqueHandleSealed : RustFlowState
  | FidesJevGate : RustFlowState
  | HwCustodyStepup : RustFlowState
  | SubagentSpawn : RustFlowState
  | L3HeapVmProtNone : RustFlowState
  | QuarantineAbort : RustFlowState
  | SterileWiped : RustFlowState
  deriving DecidableEq, Repr

/-- Concrete Rust FlowGate events mirroring crates/enclave-agent-runtime/src/flow_fsm.rs -/
inductive RustFlowEvent where
  | PlanAccepted : RustFlowEvent
  | ToolReturn : RustFlowEvent
  | DeclassifyCalled : RustFlowEvent
  | QifUnderBudget : RustFlowEvent
  | QifOverBudget : RustFlowEvent
  | HwVerified : RustFlowEvent
  | HwDenied : RustFlowEvent
  | Spawn : RustFlowEvent
  | ChildComplete : RustFlowEvent
  | UsbYank : RustFlowEvent
  | Reattested : RustFlowEvent
  | ReattestFailed : RustFlowEvent
  | SleepOrLock : RustFlowEvent
  deriving DecidableEq, Repr

/-- Deterministic Rust FlowGate transition function matching FlowGate::on() -/
def rustStep (s : RustFlowState) (e : RustFlowEvent) : RustFlowState :=
  match s, e with
  | RustFlowState.PlanCompileT1, RustFlowEvent.PlanAccepted => RustFlowState.CapabilityExec
  | RustFlowState.CapabilityExec, RustFlowEvent.ToolReturn => RustFlowState.OpaqueHandleSealed
  | RustFlowState.OpaqueHandleSealed, RustFlowEvent.ToolReturn => RustFlowState.OpaqueHandleSealed
  | RustFlowState.OpaqueHandleSealed, RustFlowEvent.HwVerified => RustFlowState.CapabilityExec
  | RustFlowState.OpaqueHandleSealed, RustFlowEvent.SleepOrLock => RustFlowState.SterileWiped
  | RustFlowState.SterileWiped, RustFlowEvent.PlanAccepted => RustFlowState.CapabilityExec
  | RustFlowState.OpaqueHandleSealed, RustFlowEvent.DeclassifyCalled => RustFlowState.FidesJevGate
  | RustFlowState.OpaqueHandleSealed, RustFlowEvent.PlanAccepted => RustFlowState.CapabilityExec
  | RustFlowState.FidesJevGate, RustFlowEvent.QifUnderBudget => RustFlowState.CapabilityExec
  | RustFlowState.FidesJevGate, RustFlowEvent.QifOverBudget => RustFlowState.HwCustodyStepup
  | RustFlowState.HwCustodyStepup, RustFlowEvent.HwVerified => RustFlowState.CapabilityExec
  | RustFlowState.HwCustodyStepup, RustFlowEvent.HwDenied => RustFlowState.QuarantineAbort
  | RustFlowState.CapabilityExec, RustFlowEvent.Spawn => RustFlowState.SubagentSpawn
  | RustFlowState.SubagentSpawn, RustFlowEvent.ChildComplete => RustFlowState.CapabilityExec
  | RustFlowState.CapabilityExec, RustFlowEvent.UsbYank => RustFlowState.L3HeapVmProtNone
  | RustFlowState.L3HeapVmProtNone, RustFlowEvent.Reattested => RustFlowState.CapabilityExec
  | RustFlowState.L3HeapVmProtNone, RustFlowEvent.ReattestFailed => RustFlowState.SterileWiped
  | RustFlowState.CapabilityExec, RustFlowEvent.SleepOrLock => RustFlowState.SterileWiped
  | _, _ => RustFlowState.QuarantineAbort

/-- Return status is checked separately: explicit hardware denial returns Ok with
quarantine, while undefined transitions return Err after latching quarantine. -/
def rustReturnsOk (s : RustFlowState) (e : RustFlowEvent) : Bool :=
  rustStep s e != RustFlowState.QuarantineAbort ||
  (s == RustFlowState.HwCustodyStepup && e == RustFlowEvent.HwDenied)

/-- Abstract specification security states for verification -/
inductive AbstractSecurityState where
  | SecureExec : AbstractSecurityState
  | GateCheck : AbstractSecurityState
  | StepUp : AbstractSecurityState
  | SafeAbort : AbstractSecurityState
  | SafeWiped : AbstractSecurityState
  deriving DecidableEq, Repr

/-- Abstract specification events -/
inductive AbstractSecurityEvent where
  | Advance : AbstractSecurityEvent
  | CheckGate : AbstractSecurityEvent
  | FreezeHeap : AbstractSecurityEvent
  | Authorize : AbstractSecurityEvent
  | Reject : AbstractSecurityEvent
  | EmergencyWipe : AbstractSecurityEvent
  | Other : AbstractSecurityEvent
  deriving DecidableEq, Repr

/-- High-level security specification transition relation -/
def specStep (s : AbstractSecurityState) (e : AbstractSecurityEvent) : AbstractSecurityState :=
  match s, e with
  | AbstractSecurityState.SecureExec, AbstractSecurityEvent.Advance => AbstractSecurityState.SecureExec
  | AbstractSecurityState.SecureExec, AbstractSecurityEvent.CheckGate => AbstractSecurityState.GateCheck
  | AbstractSecurityState.SecureExec, AbstractSecurityEvent.FreezeHeap => AbstractSecurityState.StepUp
  | AbstractSecurityState.SecureExec, AbstractSecurityEvent.EmergencyWipe => AbstractSecurityState.SafeWiped
  | AbstractSecurityState.SecureExec, AbstractSecurityEvent.Authorize => AbstractSecurityState.SecureExec
  | AbstractSecurityState.SafeWiped, AbstractSecurityEvent.Advance => AbstractSecurityState.SecureExec
  | AbstractSecurityState.GateCheck, AbstractSecurityEvent.Authorize => AbstractSecurityState.SecureExec
  | AbstractSecurityState.GateCheck, AbstractSecurityEvent.CheckGate => AbstractSecurityState.StepUp
  | AbstractSecurityState.StepUp, AbstractSecurityEvent.Authorize => AbstractSecurityState.SecureExec
  | AbstractSecurityState.StepUp, AbstractSecurityEvent.Reject => AbstractSecurityState.SafeAbort
  | AbstractSecurityState.StepUp, AbstractSecurityEvent.EmergencyWipe => AbstractSecurityState.SafeWiped
  | AbstractSecurityState.SafeAbort, _ => AbstractSecurityState.SafeAbort
  | AbstractSecurityState.SafeWiped, _ => AbstractSecurityState.SafeWiped
  | _, _ => AbstractSecurityState.SafeAbort

/-- State abstraction mapping connecting Rust implementation states to formal specification -/
def stateAbstraction : RustFlowState → AbstractSecurityState
  | RustFlowState.PlanCompileT1 => AbstractSecurityState.SecureExec
  | RustFlowState.CapabilityExec => AbstractSecurityState.SecureExec
  | RustFlowState.OpaqueHandleSealed => AbstractSecurityState.SecureExec
  | RustFlowState.SubagentSpawn => AbstractSecurityState.SecureExec
  | RustFlowState.FidesJevGate => AbstractSecurityState.GateCheck
  | RustFlowState.HwCustodyStepup => AbstractSecurityState.StepUp
  | RustFlowState.L3HeapVmProtNone => AbstractSecurityState.StepUp
  | RustFlowState.QuarantineAbort => AbstractSecurityState.SafeAbort
  | RustFlowState.SterileWiped => AbstractSecurityState.SafeWiped

/-- Event abstraction mapping connecting Rust events to specification events -/
def eventAbstraction : RustFlowEvent → AbstractSecurityEvent
  | RustFlowEvent.PlanAccepted => AbstractSecurityEvent.Advance
  | RustFlowEvent.ToolReturn => AbstractSecurityEvent.Advance
  | RustFlowEvent.Spawn => AbstractSecurityEvent.Advance
  | RustFlowEvent.ChildComplete => AbstractSecurityEvent.Advance
  | RustFlowEvent.DeclassifyCalled => AbstractSecurityEvent.CheckGate
  | RustFlowEvent.QifUnderBudget => AbstractSecurityEvent.Authorize
  | RustFlowEvent.QifOverBudget => AbstractSecurityEvent.CheckGate
  | RustFlowEvent.HwVerified => AbstractSecurityEvent.Authorize
  | RustFlowEvent.Reattested => AbstractSecurityEvent.Authorize
  | RustFlowEvent.HwDenied => AbstractSecurityEvent.Reject
  | RustFlowEvent.ReattestFailed => AbstractSecurityEvent.EmergencyWipe
  | RustFlowEvent.SleepOrLock => AbstractSecurityEvent.EmergencyWipe
  | RustFlowEvent.UsbYank => AbstractSecurityEvent.FreezeHeap

/-- Bisimulation invariant relation between Rust state and Abstract security state -/
def BisimulationRel (rs : RustFlowState) (spec : AbstractSecurityState) : Prop :=
  stateAbstraction rs = spec

abbrev SecurityClassification := AbstractSecurityState
abbrev abstractState := stateAbstraction
abbrev abstractEvent := eventAbstraction

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem copied_fsm_nonabort_step_refines
    (rs : RustFlowState) (re : RustFlowEvent)
    (h_valid : rustStep rs re ≠ RustFlowState.QuarantineAbort) :
    stateAbstraction (rustStep rs re) = specStep (stateAbstraction rs) (eventAbstraction re) := by
  cases rs <;> cases re <;> first | rfl | contradiction

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem copied_fsm_abstract_step_or_safe_outcome (rs : RustFlowState) (re : RustFlowEvent) :
    let next_rs := rustStep rs re
    let next_spec := specStep (stateAbstraction rs) (eventAbstraction re)
    (stateAbstraction next_rs = next_spec) ∨
    (stateAbstraction next_rs = AbstractSecurityState.SafeAbort) ∨
    (stateAbstraction next_rs = AbstractSecurityState.SafeWiped ∧ next_spec = AbstractSecurityState.SafeAbort) := by
  cases rs <;> cases re <;> (first | left; rfl | right; left; rfl | right; right; decide)

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem rust_quarantine_fail_closed (rs : RustFlowState) (re : RustFlowEvent)
    (h_not_exec : rustStep rs re = RustFlowState.QuarantineAbort) :
    stateAbstraction (rustStep rs re) = AbstractSecurityState.SafeAbort := by
  rw [h_not_exec]
  rfl

/-- A wiped session can only resume on admission of a new plan; all other events
quarantine. This is a property of the model table checked against FlowGate::on,
not a guarantee that new-plan admission or the physical wipe is implemented. -/
theorem rust_wiped_requires_new_plan_or_quarantine (re : RustFlowEvent)
    (h : re ≠ RustFlowEvent.PlanAccepted) :
    stateAbstraction (rustStep RustFlowState.SterileWiped re) = AbstractSecurityState.SafeAbort := by
  cases re <;> first | rfl | contradiction

end Enclave
