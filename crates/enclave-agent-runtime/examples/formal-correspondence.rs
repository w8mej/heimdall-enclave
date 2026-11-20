//! Emit exhaustive production results for comparison with the compiled Lean models.
use enclave_agent_runtime::flow_fsm::{FlowEvent as E, FlowGate, FlowState as S};
use enclave_core::label::Label;

// Compile both actual renderer and its production process-runner dependency.
#[allow(dead_code)]
#[path = "../../mcp-enclave/src/syscmd.rs"]
mod syscmd;

// Compile the actual renderer source, not a second hand-written pf ruleset.
#[allow(dead_code)]
#[path = "../../mcp-enclave/src/pf.rs"]
mod production_pf;

fn main() {
    let states = [
        S::PlanCompileT1,
        S::CapabilityExec,
        S::OpaqueHandleSealed,
        S::FidesJevGate,
        S::HwCustodyStepup,
        S::SubagentSpawn,
        S::L3HeapVmProtNone,
        S::QuarantineAbort,
        S::SterileWiped,
    ];
    let events = [
        E::PlanAccepted,
        E::ToolReturn,
        E::DeclassifyCalled,
        E::QifUnderBudget,
        E::QifOverBudget,
        E::HwVerified,
        E::HwDenied,
        E::Spawn,
        E::ChildComplete,
        E::UsbYank,
        E::Reattested,
        E::ReattestFailed,
        E::SleepOrLock,
    ];
    for (si, state) in states.iter().enumerate() {
        for (ei, event) in events.iter().enumerate() {
            let mut gate = FlowGate::from_state(*state);
            let ok = gate.on(*event).is_ok();
            let next = states.iter().position(|s| *s == gate.state()).unwrap();
            println!("F,{si},{ei},{next},{}", u8::from(ok));
        }
    }
    for a in Label::all() {
        for b in Label::all() {
            let j = a.join(b);
            println!(
                "L,{},{},{},{},{},{},{}",
                a.c.rank(),
                a.t.rank(),
                b.c.rank(),
                b.t.rank(),
                j.c.rank(),
                j.t.rank(),
                u8::from(a.leq(b))
            );
        }
    }
    for line in production_pf::render_llm_isolation_rules().lines() {
        if !line.trim().is_empty() && !line.starts_with('#') {
            println!("R,{line}");
        }
    }
}
