/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Unit Tests & Evaluation for IFC Lattices
-/

import Enclave.Lattice

namespace Enclave.Test

open Enclave

-- Confidentiality Join & Meet Verification
theorem test_conf_join_c1_c4 : ConfLevel.join ConfLevel.C1 ConfLevel.C4 = ConfLevel.C4 := by rfl
theorem test_conf_join_c2_c3 : ConfLevel.join ConfLevel.C2 ConfLevel.C3 = ConfLevel.C3 := by rfl
theorem test_conf_meet_c2_c4 : ConfLevel.meet ConfLevel.C2 ConfLevel.C4 = ConfLevel.C2 := by rfl
theorem test_conf_idem_c3 : ConfLevel.join ConfLevel.C3 ConfLevel.C3 = ConfLevel.C3 := by rfl

-- Integrity & Taint Join Verification
theorem test_integ_join_t0_t3 : IntegLevel.join IntegLevel.T0 IntegLevel.T3 = IntegLevel.T3 := by rfl
theorem test_integ_join_t1_t2 : IntegLevel.join IntegLevel.T1 IntegLevel.T2 = IntegLevel.T2 := by rfl
theorem test_integ_meet_t1_t3 : IntegLevel.meet IntegLevel.T1 IntegLevel.T3 = IntegLevel.T1 := by rfl

-- Composite Security Label Information Flow Check
def label_low : SecurityLabel := { confidentiality := ConfLevel.C1, integrity := IntegLevel.T1 }
def label_high : SecurityLabel := { confidentiality := ConfLevel.C4, integrity := IntegLevel.T3 }

theorem test_flow_low_to_high : SecurityLabel.canFlowTo label_low label_high = true := by
  decide

theorem test_flow_high_to_low : SecurityLabel.canFlowTo label_high label_low = false := by
  decide

end Enclave.Test
