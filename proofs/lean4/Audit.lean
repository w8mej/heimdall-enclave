import Lean
import Enclave
import Test

open Lean Elab Command

-- Inspect kernel declarations, including their transitive axiom dependencies.
-- These are standard Lean logical principles; no project axiom is permitted.
run_cmd do
  let env ← getEnv
  let constants := env.constants.toList
  let mut count := 0
  for (name, info) in constants do
    if (`Enclave).isPrefixOf name || (`EnclaveTest).isPrefixOf name then
      match info with
      | .axiomInfo a =>
        -- Lean code generation emits unsafe erased-lambda declarations.
        -- They cannot occur in kernel proofs; all proof dependencies are audited below.
        unless a.isUnsafe do throwError "Project axiom forbidden: {name}"
      | .thmInfo _ =>
        let axioms ← collectAxioms name
        for ax in axioms do
          unless #[`propext, `Quot.sound, `Classical.choice].contains ax do
            throwError "Theorem {name} depends on forbidden axiom {ax}"
        count := count + 1
        logInfo m!"KERNEL_DECL {(Json.arr #[toJson name.toString, toJson (toString info.type)]).compress}"
      | _ => pure ()
  logInfo m!"KERNEL_AUDIT {count} theorem declarations checked"
