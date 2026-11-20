import Enclave.TicketProtocol
import Enclave.DpopProtocol
import Enclave.FractionalQif
import Enclave.RollingKeyNormalization
import Enclave.EgressFinalization

open Enclave

def utf8 (s : String) : List Nat := s.toUTF8.data.toList.map UInt8.toNat
def hexByte (n : Nat) : String :=
  String.mk [("0123456789abcdef".toList[n/16]!), ("0123456789abcdef".toList[n%16]!)]
def hexBytes (bs : List Nat) := String.join (bs.map hexByte)

def rollingBucket (bucket : RollingQif.Bucket) : String :=
  if bucket.isEmpty then "-" else
    String.intercalate ";" (bucket.map (fun (time,amount) => s!"{time}:{amount}"))

def rollingVectors : IO Unit := do
  let max64 : Nat := 18446744073709551615
  let mut index := 0
  for profile in [2,3] do
    for entityCap in [0,4000,12000] do
      for conf in [2,3,4] do
        for unstructured in [false,true] do
          for raw in [[],[1],[1,1],[1,2],[2,1,2]] do
            let poolCap := if profile=3 ∧ conf=4 then 4000 else 12000
            let caps := fun key => if key=0 then poolCap else entityCap
            let mut state : RollingQif.State := ⟨fun _ => [],0⟩
            for (now,amount) in [(0,1000),(1,3000),(2,8000),(86399999,1),
                (86400000,1000),(0,1000),(max64-1,12000),(max64,1),(86400001,1)] do
              let result := if 3≤conf ∧ raw=[] ∧ unstructured=false then (state,false) else
                RollingQifRefinement.nativeCharge caps state
                  ⟨RollingKeyNormalization.keys raw 0 unstructured,amount,now⟩
              state := result.1
              IO.println s!"L,{index},{if result.2 then 1 else 0},{state.highTime},{rollingBucket (state.buckets 0)},{rollingBucket (state.buckets 1)},{rollingBucket (state.buckets 2)}"
              index := index+1

def egressVectors : IO Unit := do
  let mut index := 0
  for code in List.range (6^4) do
    let mut state : EgressFinalization.State := ⟨[],[],[]⟩
    for position in List.range 4 do
      let event := match code / 6^position % 6 with
        | 0 => EgressFinalization.Event.issue (1,1)
        | 1 => .release (1,1) true
        | 2 => .ownerSign (1,1) true
        | 3 => .ifcSign (1,1) true
        | 4 => .release (2,1) true
        | _ => .ownerSign (2,1) true
      let result := EgressFinalization.step state event
      state := result.getD state
      let bits := fun (slot : EgressFinalization.Slot) =>
        s!"{if slot ∈ state.issued then 1 else 0}:{if slot ∈ state.released then 1 else 0}:{if slot ∈ state.tombstoned then 1 else 0}"
      IO.println s!"E,{index},{if result.isSome then 1 else 0},{bits (1,1)},{bits (2,1)}"
      index := index+1

def main : IO Unit := do
  let strings := ["", "a", String.mk ['a', Char.ofNat 0, 'b'], "é"]
  let max64 : Nat := 18446744073709551615
  let numbers := [(0,0,0),(1,0,1),(255,255,256),(256,256,65535),
    (65536,4294967295,4294967296),(max64,0,max64),(7,max64-1,max64),(1,max64,max64)]
  let mut index := 0
  for id in strings do
    for server in strings do
      for tool in strings do
        for args in strings do
          for module in [none,some (List.replicate 32 0),some (List.replicate 32 255)] do
            for format in [false,true] do
              for (rows,issued,expires) in numbers do
                let t : Tickets.Ticket := ⟨⟨utf8 id,utf8 server,utf8 tool,utf8 args,rows,issued,expires⟩,module,format⟩
                IO.println s!"T,{index},{hexBytes (Tickets.signingBytes t)}"
                index := index+1
  let mut replay : Tickets.Replay := ⟨[],0,2⟩
  index := 0
  for (id,expiry,now) in [(1,10,0),(1,10,0),(2,20,0),(3,20,0),(3,20,11),
      (1,10,11),(2,20,0),(2,20,12),(1,30,21)] do
    let result := Tickets.consume replay id expiry now
    IO.println s!"R,{index},{if result.isSome then 1 else 0}"
    replay := result.getD replay
    index := index+1
  let signed : List Int := [-9223372036854775808,-61,-60,-1,0,1,60,61,9223372036854775807]
  index := 0
  for now in signed do
    for issued in signed do
      for skew in [-1,0,60,9223372036854775807] do
        IO.println s!"D,{index},{if DpopProtocol.fresh now issued skew then 1 else 0}"
        index := index+1
  let mut arities := List.range 4097
  for bits in List.range 51 do
    let power := 2^(bits+13)
    arities := arities ++ [power-1,power,power+1]
  arities := arities ++ [max64]
  index := 0
  for k in arities do
    IO.println s!"Q,{index},{k},{FractionalQif.price k}"
    index := index+1
  rollingVectors
  egressVectors
