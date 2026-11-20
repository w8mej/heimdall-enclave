//! FS-704 §5.5 deterministic `FlowGateFSM`.

#![forbid(unsafe_code)]

use enclave_core::error::EnclaveResult;
use enclave_core::fail;
use serde::{Deserialize, Serialize};

/// States.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowState {
    /// Compiling the `T1` directive.
    PlanCompileT1,
    /// Executing capabilities.
    CapabilityExec,
    /// Tool return wrapped as an opaque handle.
    OpaqueHandleSealed,
    /// `declassify_enum` gate.
    FidesJevGate,
    /// Hardware custody step-up.
    HwCustodyStepup,
    /// Child frame running.
    SubagentSpawn,
    /// `L3` heap frozen after a yank.
    L3HeapVmProtNone,
    /// Aborted.
    QuarantineAbort,
    /// Wiped.
    SterileWiped,
}

/// Events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowEvent {
    /// AST valid + Cedar static check + root token minted.
    PlanAccepted,
    /// Tool returned.
    ToolReturn,
    /// `declassify_enum` called on C3/C4 or T3.
    DeclassifyCalled,
    /// QIF under budget.
    QifUnderBudget,
    /// QIF over budget or raw write-down.
    QifOverBudget,
    /// A3/A4 chained co-signature verified.
    HwVerified,
    /// Denied / timeout / Biba violation.
    HwDenied,
    /// Spawn child.
    Spawn,
    /// Child completed.
    ChildComplete,
    /// `L3` yank.
    UsbYank,
    /// Docked silent re-attest within 250 ms.
    Reattested,
    /// Undocked or 250 ms elapsed.
    ReattestFailed,
    /// Lid sleep / screen lock.
    SleepOrLock,
}

/// The FSM.
#[derive(Debug, Clone)]
pub struct FlowGate {
    state: FlowState,
}

impl Default for FlowGate {
    fn default() -> Self {
        Self {
            state: FlowState::PlanCompileT1,
        }
    }
}

impl FlowGate {
    /// Create an FSM in a specific state (for service recovery & verification).
    pub fn from_state(state: FlowState) -> Self {
        Self { state }
    }

    /// Current state.
    pub fn state(&self) -> FlowState {
        self.state
    }
    /// Apply an event; undefined transitions fail closed into `QUARANTINE_ABORT`.
    pub fn on(&mut self, e: FlowEvent) -> EnclaveResult<FlowState> {
        use FlowEvent as E;
        use FlowState as S;
        let next = match (self.state, e) {
            (S::PlanCompileT1, E::PlanAccepted) => S::CapabilityExec,
            (S::CapabilityExec, E::ToolReturn) => S::OpaqueHandleSealed,
            (S::OpaqueHandleSealed, E::ToolReturn) => S::OpaqueHandleSealed,
            (S::OpaqueHandleSealed, E::DeclassifyCalled) => S::FidesJevGate,
            (S::OpaqueHandleSealed, E::PlanAccepted) => S::CapabilityExec,
            (S::OpaqueHandleSealed, E::HwVerified) => S::CapabilityExec,
            (S::FidesJevGate, E::QifUnderBudget) => S::CapabilityExec,
            (S::FidesJevGate, E::QifOverBudget) => S::HwCustodyStepup,
            (S::HwCustodyStepup, E::HwVerified) => S::CapabilityExec,
            (S::HwCustodyStepup, E::HwDenied) => S::QuarantineAbort,
            (S::CapabilityExec, E::Spawn) => S::SubagentSpawn,
            (S::SubagentSpawn, E::ChildComplete) => S::CapabilityExec,
            (S::CapabilityExec, E::UsbYank) => S::L3HeapVmProtNone,
            (S::L3HeapVmProtNone, E::Reattested) => S::CapabilityExec,
            (S::L3HeapVmProtNone, E::ReattestFailed) => S::SterileWiped,
            (S::CapabilityExec, E::SleepOrLock) => S::SterileWiped,
            (S::OpaqueHandleSealed, E::SleepOrLock) => S::SterileWiped,
            (S::SterileWiped, E::PlanAccepted) => S::CapabilityExec,
            (s, e) => {
                self.state = S::QuarantineAbort;
                fail!(EPERM, "FLOW_FSM_INVALID_TRANSITION", "{s:?} --{e:?}-->");
            }
        };
        self.state = next;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_and_step_up() {
        let mut f = FlowGate::default();
        for e in [
            FlowEvent::PlanAccepted,
            FlowEvent::ToolReturn,
            FlowEvent::DeclassifyCalled,
            FlowEvent::QifOverBudget,
            FlowEvent::HwVerified,
        ] {
            f.on(e).unwrap();
        }
        assert_eq!(f.state(), FlowState::CapabilityExec);
        f.on(FlowEvent::UsbYank).unwrap();
        assert_eq!(
            f.on(FlowEvent::ReattestFailed).unwrap(),
            FlowState::SterileWiped
        );
    }

    #[test]
    fn invalid_transition_quarantines() {
        let mut f = FlowGate::default();
        assert!(f.on(FlowEvent::HwVerified).is_err());
        assert_eq!(f.state(), FlowState::QuarantineAbort);
    }
}
