/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Unit Tests for Biba Integrity Noninterference
-/

import Enclave.BibaNoninterference

namespace Enclave.Test

open Enclave

-- Construct a concrete plan with a parameterized SQL tool call
def samplePlan : VerifiedStarlarkAST :=
  { tool_calls := [
      { tool_id := "mcp.database.query"
      , structural_args := [
          ASTStructuralArg.Ident "SELECT_PATIENT_RECORDS"
        , ASTStructuralArg.Op "WHERE_EQUALS" [ASTStructuralArg.SchemaField "patient_id"]
        ]
      , literal_slots := [{ handle := 101 }]
      }
    ]
  , endorseGates := []
  }

-- Environment 1: Handle 101 holds a benign user ID
def env_benign : CapHeap :=
  { lookup := fun h => if h == 101 then [49, 50, 51] else [] -- "123"
  , label := fun _ => { confidentiality := ConfLevel.C3, integrity := IntegLevel.T3 }
  }

-- Environment 2: Handle 101 holds a malicious SQL injection payload
def env_injected : CapHeap :=
  { lookup := fun h => if h == 101 then [39, 32, 79, 82, 32, 49, 61, 49, 59, 45, 45] else [] -- "' OR 1=1;--"
  , label := fun _ => { confidentiality := ConfLevel.C3, integrity := IntegLevel.T3 }
  }

-- Test: The structural traces emitted in both environments are identical
theorem test_noninterference_sql_isolation :
    (evalPlan samplePlan env_benign).structuralToolTrace =
    (evalPlan samplePlan env_injected).structuralToolTrace := by
  rfl

end Enclave.Test
