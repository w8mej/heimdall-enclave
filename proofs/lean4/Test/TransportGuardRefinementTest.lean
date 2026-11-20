import Enclave.TransportGuardRefinement

/-! Positive and hostile controls for exact selected main-source guards.
No native/crypto side effects are executed by these Lean examples. -/
set_option maxRecDepth 4096

namespace EnclaveTest.TransportGuardRefinement
open Enclave.RustGuardSemantics Enclave.TransportGuardSource

theorem chunk_boundaries_and_finality :
    encryptReject 1 true = false ∧ encryptReject 16368 false = false ∧
    encryptReject 16368 true = false ∧ encryptReject 0 true = true ∧
    encryptReject 16369 true = true ∧ encryptReject 16367 false = true ∧
    decryptReject 17 72 true = false ∧ decryptReject 16384 72 false = false ∧
    decryptReject 16 72 true = true ∧ decryptReject 16385 72 true = true ∧
    decryptReject 16383 72 false = true ∧ decryptReject 17 71 true = true ∧
    decryptReject 17 73 true = true := by decide

theorem exact_chunk_refusal_codes :
    encryptPrefix 0 true = .error ⟨"EINVAL", "NAMESPACE_CHUNK_LENGTH"⟩ ∧
    decryptPrefix 17 71 true = .error ⟨"EACCES", "NAMESPACE_CHUNK_LENGTH"⟩ ∧
    encryptPrefix 1 true = .ok () ∧ decryptPrefix 17 72 true = .ok () := by
  exact ⟨rfl, rfl, rfl, rfl⟩

theorem custody_both_shares_are_independently_required :
    custodyReject 32 32 = false ∧ custodyReject 31 32 = true ∧
    custodyReject 32 31 = true ∧ custodyReject 33 32 = true ∧
    custodyReject 32 33 = true := by decide

theorem query_signed_partial_zero_capacity_and_status_boundaries :
    enumerationReject (-2147483648) 16 8 = true ∧ enumerationReject (-1) 16 8 = true ∧
    enumerationReject 0 16 8 = true ∧ enumerationReject 8 16 0 = true ∧
    enumerationReject 8 8 8 = true ∧ enumerationReject 7 16 8 = true ∧
    enumerationReject 8 16 8 = false ∧ enumerationReject 2147483647 2147483648 1 = false ∧
    queryReject 0 0 0 = false ∧ queryReject 0 8 8 = false ∧
    queryReject 1 8 8 = true ∧ queryReject (-1) 8 8 = true ∧
    queryReject 0 7 8 = true := by decide

def ns : List UInt8 := [109, 111, 100, 101, 108, 115, 46, 95, 45, 65, 90, 48, 57]
def envelope : List UInt8 := List.replicate 144 97

theorem envelope_positive_controls_include_maximum_namespace :
    envelopeReject ns envelope 1 1 = false ∧
    envelopeReject (List.replicate 128 90) envelope 18446744073709551615 1 = false := by decide

theorem envelope_each_shape_constraint_has_a_negative_control :
    envelopeReject [] envelope 1 1 = true ∧
    envelopeReject (List.replicate 129 97) envelope 1 1 = true ∧
    envelopeReject [47] envelope 1 1 = true ∧ envelopeReject [128] envelope 1 1 = true ∧
    envelopeReject ns envelope 0 1 = true ∧ envelopeReject ns envelope 1 0 = true ∧
    envelopeReject ns (List.replicate 143 97) 1 1 = true ∧
    envelopeReject ns (List.replicate 145 97) 1 1 = true ∧
    envelopeReject ns (List.replicate 144 65) 1 1 = true ∧
    envelopeReject ns (List.replicate 144 103) 1 1 = true ∧
    envelopeReject ns (List.replicate 144 255) 1 1 = true := by decide

theorem optional_monitor_still_calls_the_callback_once :
    Enclave.TransportGuardRefinement.runMonitorOnce .l1
      (fun n : Nat => ((.error "registration" : Except String Nat), n + 1)) 7 =
      (.ok none, 8) := rfl

theorem monitor_l2_and_l3_preserve_the_same_error :
    startForProfile .l2 (.error "registration" : Except String Nat) = .error "registration" ∧
    startForProfile .l3 (.error "registration" : Except String Nat) = .error "registration" := by
  constructor <;> rfl

theorem disk_both_overflow_cuts_and_exact_maximum :
    requiredDisk 0 0 = .ok 4294967296 ∧
    requiredDisk 18446744069414584319 0 = .ok 18446744073709551615 ∧
    requiredDisk 18446744069414584320 0 = .error ⟨"E2BIG", "ADMISSION_DISK_RESERVE"⟩ ∧
    requiredDisk 18446744069414584319 1 = .error ⟨"E2BIG", "ADMISSION_DISK_RESERVE"⟩ := by
  exact ⟨rfl, rfl, rfl, rfl⟩

theorem bounded_append_empty_exact_limit_and_overrun :
    boundedWrite [1,2] ([] : List Nat) 2 = .ok ([1,2], 0) ∧
    boundedWrite [1] [2,3] 3 = .ok ([1,2,3], 2) ∧
    boundedWrite [1] [2,3] 2 = .error ⟨"InvalidData", "signed target length exceeded"⟩ ∧
    boundedWrite [1,2] ([] : List Nat) 1 = .ok ([1,2], 0) := by
  exact ⟨rfl, rfl, rfl, rfl⟩

end EnclaveTest.TransportGuardRefinement
