import Lake
open Lake DSL

package «EnclaveProofs» where
  version := v!"0.1.0"
  keywords := #["security", "formal-verification", "information-flow-control", "zk-audit"]

-- Lean 4.14-compatible mathematics for finite fields and normalized probability.
require mathlib from git "https://github.com/leanprover-community/mathlib4.git" @
  "4bbdccd9c5f862bf90ff12f0a9e2c8be032b9a84"

@[default_target]
lean_lib «Enclave» where
  srcDir := "."

lean_lib «Test» where
  srcDir := "."

@[default_target]
lean_exe «enclave_verifier» where
  root := `Main

lean_exe «correspondence» where
  root := `Correspondence

lean_exe «protocol_vectors» where
  root := `ProtocolVectors

lean_exe «authorization_vectors» where
  root := `AuthorizationVectors
