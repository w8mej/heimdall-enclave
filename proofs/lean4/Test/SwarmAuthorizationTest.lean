import Enclave.SwarmAuthorization

namespace Enclave.SwarmAuthorization.Test

def grant : Grant := ⟨1, 2, 3, 7, 77, 9, 10, 1, 100, [11,12], 7⟩
def context : Context := ⟨7, 77, 9, 10, 1, 1, 0, 10, 500⟩
def parent : Chain := {grant := grant}
def block : Block := ⟨1, 7, 77, [.tools [1], .ns 9, .rows 1, .charge 0, .expires 50], [], []⟩
def child : Chain := Protocol.run chainStep parent [.append block, .sealWire]
def sealedParent : Chain := Protocol.run chainStep parent [.sealWire]
def server : Server := {issuer := 1, policy := 2, epoch := 3, authorized := [7], licensed := [9]}
def wire (chain : Chain := child) (chainId : Nat := 100) (seq : Nat := 0) : Wire :=
  ⟨chain, chainId, 11, seq, ⟨7, 77, chainId, 500, seq⟩⟩

-- Nonvacuous successful parent AND child at the same trusted ambient context.
example : chainStep parent (.append block) = some {parent with blocks := [block]} := by decide
example : wireAdmission server (wire sealedParent) context = true := by decide
example : wireAdmission server (wire child) context = true := by decide
example : rootAllowed parent context 11 = true ∧ rootAllowed child context 11 = true := by decide
example : rootAllowed parent {context with tool := 2} 11 = true ∧
    rootAllowed child {context with tool := 2} 11 = false := by decide
example : rootAllowed parent {context with rows := 2} 11 = true ∧
    rootAllowed child {context with rows := 2} 11 = false := by decide
example : rootAllowed child context 12 = true := by decide
example : rootAllowed child context 13 = false := by decide

example : chainStep parent (.append {block with extraFacts := [999]}) = none := by decide
example : chainStep parent (.append {block with rules := [999]}) = none := by decide
example : chainStep parent (.append {block with index := 2}) = none := by decide
example : chainStep child (.append {block with index := 2}) = none := by decide
example : chainStep {parent with blocks := [block, block, block, block]}
    (.append {block with index := 5}) = none := by decide
example : wireAdmission server (wire parent) context = false := by decide
example : wireAdmission server (wire {child with blocks := [{block with rules := [1]}]}) context = false := by decide
example : wireAdmission server (wire {child with blocks := [{block with index := 2}]}) context = false := by decide

-- Each tuple field must match the authenticated transport/request observation.
example : wireAdmission {server with issuer := 99} (wire) context = false := by decide
example : wireAdmission {server with policy := 99} (wire) context = false := by decide
example : wireAdmission {server with epoch := 99} (wire) context = false := by decide
example : wireAdmission server (wire) {context with peer := 8} = false := by decide
example : wireAdmission server (wire) {context with exporter := 78} = false := by decide
example : wireAdmission server (wire) {context with exporter := 0} = false := by decide
example : wireAdmission server (wire) {context with ns := 8} = false := by decide
example : wireAdmission server (wire) {context with shard := 8} = false := by decide
example : wireAdmission server (wire) {context with argsDigest := 501} = false := by decide
example : wireAdmission server {wire with root := 13} context = false := by decide
example : wireAdmission server {wire with seq := 1} context = false := by decide
example : wireAdmission server {wire with chainId := 101} context = false := by decide
example : wireAdmission server (wire) {context with now := 51} = false := by decide
example : serverStep {server with licensed := []} (.begin wire context) = none := by decide
example : serverStep {server with authorized := []} (.begin wire context) = none := by decide
example : serverStep {server with lastUtc := 11} (.begin wire context) = none := by decide

def served : Server := Protocol.run serverStep server [.begin wire context, .finish 10]
example : served.released = [11] ∧ served.pending = none := by decide
example : serverStep served (.begin wire context) = none := by decide
example : (Protocol.run serverStep served
    [.begin (wire child 100 2) context, .finish 10,
     .begin (wire child 100 1) context, .finish 10]).released = [11,11,11] := by decide
example : windowAccept [1000] 936 = false := by decide
example : windowAccept [1000] 937 = true := by decide
example : windowAccept [] (maxSequence + 1) = false := by decide
example : (Protocol.run serverStep served
    [.begin (wire child 101 0) context, .finish 10]).released = [11,11] := by decide

def pending : Server := Protocol.run serverStep server [.begin wire context]
example : pending.pending = some (wire, context) ∧ pending.released = [] := by decide
example : serverStep (Protocol.run serverStep pending [.revoke 7]) (.finish 10) = none := by decide
example : (Protocol.run serverStep pending [.revoke 7, .finish 10]).released = [] := by decide
example : serverStep (Protocol.run serverStep pending [.unlicense 9]) (.finish 10) = none := by decide
example : serverStep (Protocol.run serverStep pending [.replacePolicy 4 3]) (.finish 10) = none := by decide
example : serverStep pending (.finish 51) = none := by decide
example : serverStep pending (.finish 9) = none := by decide
example : serverStep (Protocol.run serverStep served [.revoke 7])
    (.begin (wire child 101 0) context) = none := by decide

def renewed : Chain := Protocol.run chainStep {parent with grant := {grant with expires := 300}}
  [.append {block with checks := [.tools [1], .ns 9, .rows 1, .charge 0, .expires 200]}, .sealWire]
example : serverStep served (.begin wire {context with now := 60}) = none := by decide
example : (Protocol.run serverStep served
    [.begin (wire renewed 101 0) {context with now := 60}, .finish 60]).released = [11,11] := by decide
example : serverStep (Protocol.run serverStep served [.revoke 7])
    (.begin (wire renewed 101 0) {context with now := 60}) = none := by decide

#eval "LAT04 positive/hostile model traces elaborated; no Biscuit parser or native evidence inferred"

end Enclave.SwarmAuthorization.Test
