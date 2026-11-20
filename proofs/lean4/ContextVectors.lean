import Enclave.ContextDagProvenance

/-! Finite projection of production ContextDag::add_node and sanitize_node.
The Boolean endorsement update is tested as an update, not sanitizer validation.
This driver adds explicit-taint/unknown-parent admission around the existing
parent-join model; it does not prove the Rust implementation universally. -/
open Enclave

def parentSets : List (List IntegLevel) :=
  let levels := [IntegLevel.T0, .T1, .T2, .T3]
  [[]] ++ levels.map (fun a => [a]) ++
    levels.flatMap (fun a => levels.map (fun b => [a, b])) ++
    levels.flatMap (fun a => levels.flatMap (fun b => levels.map (fun c => [a, b, c])))

def main : IO Unit := do
  let mut row := 0
  for (parents, parentIndex) in (parentSets ++ [[]]).zip (List.range 86) do
    for explicitIndex in List.range 5 do
      for conf in [1, 2, 3, 4] do
        for sanitize in [false, true] do
          let inherited := deriveChildIntegrity parents
          let selected := if explicitIndex == 0 then inherited else
            ([IntegLevel.T0, .T1, .T2, .T3].getD (explicitIndex - 1) .T0)
          let error := if parentIndex == 85 then 2 else
            if inherited.toNat ≤ selected.toNat then 0 else 1
          let node : DagNode := ⟨1, [], selected, false⟩
          let updated := sanitizeNode node sanitize
          let integrity := if error == 0 then updated.integrity.toNat else 255
          let sanitized := if error == 0 && updated.is_sanitized then 1 else 0
          IO.println s!"G,{row},{parentIndex},{explicitIndex},{conf},{if sanitize then 1 else 0},{error},{integrity},{sanitized}"
          row := row + 1
