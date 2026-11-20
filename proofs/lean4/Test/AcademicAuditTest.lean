/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Academic Audit Test Suite: Small-Step, Rust Bridge, Probabilistic QIF, & Stateful PF
-/

import Enclave.SmallStepSemantics
import Enclave.RustModelBridge
import Enclave.ProbabilisticQif
import Enclave.StatefulPacketFilter

namespace EnclaveTest

open Enclave

/--
Test 1: Static verification rejects any conditional branch on T3 untrusted prompt variables.
-/
def testGamma : TaintContext := fun name =>
  if name == "untrusted_prompt" then IntegLevel.T3
  else if name == "trusted_arg" then IntegLevel.T1
  else IntegLevel.T0

def maliciousBranchExpr : StarlarkExpr :=
  StarlarkExpr.IfThenElse
    (StarlarkExpr.Var "untrusted_prompt")
    (StarlarkExpr.ToolCall "bash_exec" [StarlarkExpr.ConstNat 1])
    StarlarkExpr.Skip

theorem test_small_step_t3_rejected :
    typeCheckExpr testGamma maliciousBranchExpr = none := by
  rfl

/--
Test 2: Rust FlowGate FSM executes the happy-path transition sequence into CapabilityExec.
-/
theorem test_rust_flow_fsm_valid :
    let s0 := RustFlowState.PlanCompileT1
    let s1 := rustStep s0 RustFlowEvent.PlanAccepted
    let s2 := rustStep s1 RustFlowEvent.ToolReturn
    let s3 := rustStep s2 RustFlowEvent.DeclassifyCalled
    let s4 := rustStep s3 RustFlowEvent.QifUnderBudget
    s4 = RustFlowState.CapabilityExec := by
  rfl

/--
Test 3: Discrete channel with cardinality 4 adheres to the posterior vulnerability ratio bound.
-/
def sampleChannel : DiscreteChannel 4 where
  output_cardinality_bound := by decide
  joint_max_per_output := [50, 40, 60, 30]
  length_eq := by rfl
  prior_vulnerability := 100
  joint_le_prior := by
    intro v hv
    simp at hv
    rcases hv with (rfl | rfl | rfl | rfl) <;> decide

theorem test_probabilistic_qif_ratio :
    posteriorVulnerability sampleChannel ≤ 4096 * sampleChannel.prior_vulnerability := by
  apply conditional_bayes_vulnerability_ratio_bound 4 sampleChannel

/--
Test 4: Stateful packet filter rejects Wi-Fi (en0) outbound packets from _llmagent fail-closed.
-/
def wifiPacket : StatefulPacket := {
  flow := {
    iface := "en0"
    proto := Protocol.TCP
    src_ip := 2130706433
    src_port := 55555
    dst_ip := 16843009
    dst_port := 443
    group := LLM_AGENT_GID
  }
  is_syn := true
  is_ack := false
  is_fin := false
}

theorem test_stateful_pf_quarantine :
    (evalStatefulFilter [] wifiPacket).2 = Verdict.Drop ∧
    (evalStatefulFilter [] wifiPacket).1 = [] := by
  decide

end EnclaveTest
