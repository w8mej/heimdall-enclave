import Enclave.NamespaceKeyringProtocol

/-! Positive and hostile executable model traces. `decide` is kernel checked;
no native_decide, Rust execution, MAC proof or hardware acceptance is implied. -/
namespace Enclave.NamespaceKeyringProtocol.Test

def emptyRing : Ring := {ns := 7}
def key1 : Envelope := ⟨7, 1, 1, 101, 11⟩
def key2 : Envelope := ⟨7, 2, 1, 202, 22⟩
def populated : Ring := Protocol.run ringStep emptyRing [.register key1, .register key2]
def rotated : Ring := Protocol.run ringStep populated
  [.rewrap 1 2 111, .rewrap 2 2 222, .retire 2]

example : ringShape emptyRing := by decide
example : populated.keys = [key1, key2] := by decide
example : ringShape rotated ∧ rotated.floor = 2 := by decide
example : identities rotated = identities populated := by decide
example : ringStep populated (.retire 2) = none := by decide
example : ringStep (Protocol.run ringStep populated [.rewrap 1 2 111]) (.retire 2) = none := by decide
example : verifyEnvelope rotated key1 = false := by decide
example : verifyEnvelope rotated ⟨7, 1, 2, 101, 111⟩ = true := by decide
example : ringStep rotated (.retire 1) = none := by decide
example : ringStep rotated (.rewrap 1 1 999) = none := by decide
example : ringStep populated (.register key1) = none := by decide
example : ringStep emptyRing (.register {key1 with ns := 8}) = none := by decide
example : ringStep emptyRing (.register {key1 with epoch := 0}) = none := by decide
example : ringStep emptyRing (.register {key1 with wrapping := maxU64 + 1}) = none := by decide
example : ringStep rotated (.rewrap 1 (maxU64 + 1) 999) = none := by decide

def oldImage : Image := ⟨1, populated⟩
def initialized : Store := {disk := oldImage, checkpoint := 1, writerGeneration := 1, archive := [oldImage]}
def acknowledged : Store := Protocol.run storeStep initialized
  [.begin rotated, .writeState, .writeCheckpoint, .crash, .restart]
example : acknowledged.online = true ∧ acknowledged.checkpoint = 2 ∧
    acknowledged.disk.body = rotated := by decide
example : storeStep (Protocol.run storeStep acknowledged [.restore oldImage, .crash])
    .restart = none := by decide
example : storeStep {initialized with writerGeneration := maxU64} (.begin rotated) = none := by decide
example : storeStep initialized .writeCheckpoint = none := by decide
example : storeStep (Protocol.run storeStep initialized [.begin rotated])
    .writeCheckpoint = none := by decide
example : storeStep (Protocol.run storeStep initialized [.failSave]) (.begin rotated) = none := by decide
example : (Protocol.run storeStep initialized [.begin rotated, .crash, .restart]).disk = oldImage := by decide

def legacy : Migration := {legacy := some populated}
def migrated : Migration := Protocol.run migrationStep legacy [.start, .createChild, .saveChild]
example : selectedChild migrated = some populated ∧ migrated.marker = true := by decide
example : migrationStep migrated .start = none := by decide
example : migrationStep (Protocol.run migrationStep migrated [.removeChild]) .start = none := by decide
example : migrationStep (Protocol.run migrationStep legacy [.start, .crash]) .start = none := by decide
example : selectedChild (Protocol.run migrationStep legacy [.start, .createChild, .crash]) = none := by decide
example : selectedChild (Protocol.run migrationStep legacy
    [.start, .changeLegacy (some rotated), .createChild, .saveChild]) = some populated := by decide
example : migrationStep {legacy with childExists := true} .start = none := by decide
example : selectedChild {legacy with childExists := true} = none := by decide
example : migrationStep {legacy := some {emptyRing with floor := 0}} .start = none := by decide

def failedSecond : Ceremony := Protocol.run ceremonyStep {} [.consume 9, .secondResult false, .persist]
example : failedSecond.observed = 9 ∧ failedSecond.durable = 9 ∧
    failedSecond.second = some false := by decide
example : ceremonyStep failedSecond (.consume 9) = none := by decide
example : ceremonyStep failedSecond (.consume (maxU32 + 1)) = none := by decide
example : (Protocol.run ceremonyStep {} [.consume 9, .secondResult false]).durable = 0 := by decide

def live : Authority := Protocol.run authorityStep {boot := 70} [.issue 9]
example : leaseValid live 70 0 9 = true := by decide
example : leaseValid live 71 0 9 = false := by decide
example : leaseValid (Protocol.run authorityStep live [.wipe]) 70 0 9 = false := by decide
example : leaseValid (Protocol.run authorityStep live [.keyringSaveFailed, .issue 10, .wipe]) 70 2 10 = false := by decide
example : (Protocol.run authorityStep live [.keyringSaveFailed]).leases = [] := by decide
example : ((authorityStep {live with generation := maxU64} .wipe).getD live).disabled = true := by decide
example : leaseValid {live with generation := maxU64} 70 maxU64 9 = true := by decide
example : leaseValid (Protocol.run authorityStep {live with generation := maxU64} [.wipe])
    70 maxU64 9 = false := by decide
example : leaseValid (Protocol.run authorityStep {live with generation := maxU64}
    [.wipe, .issue 10, .keyringSaveFailed]) 70 maxU64 9 = false := by decide

#eval "LAT03 examples elaborated; checks are the declarations above"

end Enclave.NamespaceKeyringProtocol.Test
