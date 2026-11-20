import Enclave.RustModelBridge
import Enclave.TierTwoAssurance

namespace Enclave.FormalRegressionTest
open Enclave

theorem yank_during_execution_requires_reattestation :
    stateAbstraction (rustStep .CapabilityExec .UsbYank) = .StepUp ∧
    specStep .SecureExec (eventAbstraction .UsbYank) = .StepUp := by decide

theorem yank_failed_reattestation_wipes :
    rustStep (rustStep .CapabilityExec .UsbYank) .ReattestFailed = .SterileWiped := by decide

-- Keep the original counterexample: malformed 101 percent is clamped to 100.
theorem malformed_progress_is_clamped :
    (stepProgress ⟨101, false⟩ 100).percent = 100 := by decide

theorem bounded_progress_is_monotonic (s : HydrationProgressState) (n : Nat)
    (h : s.percent ≤ 100) : s.percent ≤ (stepProgress s n).percent :=
  progressive_wire_protocol_monotonic s n h
end Enclave.FormalRegressionTest
