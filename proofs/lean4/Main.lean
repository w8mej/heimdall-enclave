import Lean
import Enclave
import Test

open Lean Elab Term

-- Compile the list from the imported kernel environment. A renamed or removed
-- theorem changes the output on the next build; no hand-written success ticks.
elab "checkedModelTheorems" : term => do
  let env ← getEnv
  let names := env.constants.toList.filterMap fun (name, info) =>
    if (`Enclave).isPrefixOf name || (`EnclaveTest).isPrefixOf name then
      match info with
      | .thmInfo _ => some name.toString
      | _ => none
    else none
  return toExpr (names.mergeSort (fun a b => a ≤ b))

def checkedTheorems : List String := checkedModelTheorems

def main : IO Unit := do
  IO.println s!"Compiled Lean model environment: {checkedTheorems.length} kernel theorems (including generated lemmas)."
  for name in checkedTheorems do
    IO.println name
  IO.println "Model statements only. Run scripts/check-lean.py for current build, axiom and reviewed-type checks."
  IO.println "Production correspondence and macOS/hardware behavior require separate validation."
