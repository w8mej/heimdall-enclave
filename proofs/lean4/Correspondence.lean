import Enclave.PacketFilter
import Enclave.Lattice
import Enclave.RustModelBridge

open Enclave

def states : List RustFlowState := [.PlanCompileT1, .CapabilityExec,
  .OpaqueHandleSealed, .FidesJevGate, .HwCustodyStepup, .SubagentSpawn,
  .L3HeapVmProtNone, .QuarantineAbort, .SterileWiped]

def events : List RustFlowEvent := [.PlanAccepted, .ToolReturn, .DeclassifyCalled,
  .QifUnderBudget, .QifOverBudget, .HwVerified, .HwDenied, .Spawn,
  .ChildComplete, .UsbYank, .Reattested, .ReattestFailed, .SleepOrLock]

def labels : List SecurityLabel :=
  [.C1, .C2, .C3, .C4].flatMap fun c =>
    [.T0, .T1, .T2, .T3].map fun t => ⟨c, t⟩

def main : IO Unit := do
  for (s, si) in (states.zip (List.range states.length)) do
    for (e, ei) in (events.zip (List.range events.length)) do
      IO.println s!"F,{si},{ei},{(rustStep s e).toCtorIdx},{if rustReturnsOk s e then 1 else 0}"
  for a in labels do
    for b in labels do
      let j := a.join b
      IO.println s!"L,{a.confidentiality.toNat},{a.integrity.toNat},{b.confidentiality.toNat},{b.integrity.toNat},{j.confidentiality.toNat},{j.integrity.toNat},{if a.canFlowTo b then 1 else 0}"
  IO.println s!"P,{LOOPBACK_IFACE},{LLM_AGENT_GID},{ENVOY_PORT},{INFERENCE_PORT}"
