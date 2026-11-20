import Enclave.CedarSemantics

/-! Bounded projection for actual CedarEngine::load/build/is_authorized.
All111 ordered rule lists of length at most2, both effects and5 predicates,
across64 requests. This is engine/request encoding evidence, not authority. -/
open Enclave.CedarSemantics

def ruleSets : List (List Nat) :=
  [[]] ++ (List.range 10).map (fun n => [n]) ++
    (List.range 10).flatMap (fun a => (List.range 10).map (fun b => [a, b]))

-- Project the actual taint/action/(confidentiality,namespace-match) tuple to
-- the existing model's opaque principal/action/resource strings.
def vectorRequest (taint conf action namespaceMatch : Nat) : AuthRequest :=
  ⟨s!"t{taint}", if action == 0 then "invoke" else "declassify", s!"c{conf}:ns{namespaceMatch}"⟩

def predicate (kind : Nat) (request : AuthRequest) : Bool :=
  match kind with
  | 0 => true
  | 1 => request.principal == "t0" || request.principal == "t1"
  | 2 => ["c1:ns0", "c1:ns1", "c2:ns0", "c2:ns1"].contains request.resource
  | 3 => request.action == "invoke"
  | _ => ["c1:ns0", "c2:ns0", "c3:ns0", "c4:ns0"].contains request.resource

def vectorRule (id : Nat) : CedarPolicy :=
  ⟨s!"rule{id}", if id < 5 then .Permit else .Forbid, predicate (id % 5)⟩

def main : IO Unit := do
  let mut row := 0
  for (rules, setIndex) in ruleSets.zip (List.range ruleSets.length) do
    for taint in List.range 4 do
      for conf in [1, 2, 3, 4] do
        for action in [0, 1] do
          for namespaceMatch in [0, 1] do
            let request := vectorRequest taint conf action namespaceMatch
            let allowed := evalCedarPolicySet (rules.map vectorRule) request == .Allow
            IO.println s!"C,{row},{setIndex},{taint},{conf},{action},{namespaceMatch},{if allowed then 1 else 0}"
            row := row + 1
