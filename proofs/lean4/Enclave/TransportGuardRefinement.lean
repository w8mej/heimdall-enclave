import Enclave.TransportGuardSource

/-! Exact guard-fragment obligations against independent mathematical relations.
The Python translator, Rust compiler and named library primitives remain trusted.
No whole-function crypto, source simulation, native monitor or storage theorem. -/
namespace Enclave.TransportGuardRefinement
open Enclave.RustGuardSemantics Enclave.TransportGuardSource

def EncryptLengths (plain : Nat) (final_chunk : Bool) : Prop :=
  1 ≤ plain ∧ plain ≤ 16368 ∧ (final_chunk = true ∨ plain = 16368)

def DecryptLengths (cipher record : Nat) (final_chunk : Bool) : Prop :=
  record = 72 ∧ 17 ≤ cipher ∧ cipher ≤ 16384 ∧ (final_chunk = true ∨ cipher = 16384)

theorem encrypt_guard_exact (plain : Nat) (final_chunk : Bool) :
    encryptReject plain final_chunk = false ↔ EncryptLengths plain final_chunk := by
  cases final_chunk <;>
    simp [encryptReject, EncryptLengths, plaintextSize, leafSize, chunkOverhead] <;> omega

theorem decrypt_guard_exact (cipher record : Nat) (final_chunk : Bool) :
    decryptReject cipher record final_chunk = false ↔ DecryptLengths cipher record final_chunk := by
  cases final_chunk <;>
    simp [decryptReject, DecryptLengths, keyRecordSize, leafSize, chunkOverhead] <;> omega

theorem accepted_encrypt_has_decrypt_geometry (plain : Nat) (final_chunk : Bool)
    (accepted : encryptReject plain final_chunk = false) :
    decryptReject (plain + 16) 72 final_chunk = false ∧ plain + 16 ≤ 16384 ∧
      plain + 16 ≤ 18446744073709551615 := by
  have h := (encrypt_guard_exact plain final_chunk).mp accepted
  refine ⟨(decrypt_guard_exact _ _ _).mpr ?_, ?_, ?_⟩ <;> unfold EncryptLengths at h
  · unfold DecryptLengths
    rcases h.2.2 with f | size
    · exact ⟨rfl, by omega, by omega, Or.inl f⟩
    · exact ⟨rfl, by omega, by omega, Or.inr (by omega)⟩
  · omega
  · omega

theorem accepted_decrypt_has_encrypt_geometry (cipher record : Nat) (final_chunk : Bool)
    (accepted : decryptReject cipher record final_chunk = false) :
    encryptReject (cipher - 16) final_chunk = false ∧ record = 72 ∧
      24 ≤ record ∧ cipher - 16 + 16 = cipher := by
  have h := (decrypt_guard_exact cipher record final_chunk).mp accepted
  unfold DecryptLengths at h
  refine ⟨(encrypt_guard_exact _ _).mpr ?_, h.1, by omega, by omega⟩
  unfold EncryptLengths
  rcases h.2.2.2 with f | size
  · exact ⟨by omega, by omega, Or.inl f⟩
  · exact ⟨by omega, by omega, Or.inr (by omega)⟩

theorem custody_guard_exact (sep prf : Nat) :
    custodyReject sep prf = false ↔ sep = 32 ∧ prf = 32 := by
  simp [custodyReject]

theorem encrypt_prefix_success_exact (plain : Nat) (final_chunk : Bool) :
    encryptPrefix plain final_chunk = .ok () ↔ EncryptLengths plain final_chunk := by
  rw [← encrypt_guard_exact]
  cases guard : encryptReject plain final_chunk <;> simp [encryptPrefix, guard]

theorem decrypt_prefix_success_exact (cipher record : Nat) (final_chunk : Bool) :
    decryptPrefix cipher record final_chunk = .ok () ↔ DecryptLengths cipher record final_chunk := by
  rw [← decrypt_guard_exact]
  cases guard : decryptReject cipher record final_chunk <;> simp [decryptPrefix, guard]

def CompleteRecords (got : Int) (capacity item : Nat) : Prop :=
  0 < got ∧ got.toNat < capacity ∧ 0 < item ∧ got.toNat % item = 0

theorem enumeration_guard_exact (got : Int) (capacity item : Nat)
    (bounded : got ≤ 2147483647) :
    enumerationReject got capacity item = false ↔ CompleteRecords got capacity item := by
  by_cases positive : 0 < got
  · simp [enumerationReject, CompleteRecords, positive_c_int_cast_exact got positive bounded,
      show ¬got ≤ 0 by omega, positive]
    omega
  · simp [enumerationReject, CompleteRecords, show got ≤ 0 by omega, positive]

theorem enumeration_returns_complete_positive_records (got : Int) (capacity item value : Nat)
    (bounded : got ≤ 2147483647) (accepted : completeQuery got capacity item = .ok value) :
    CompleteRecords got capacity item ∧ value = got.toNat := by
  unfold completeQuery at accepted
  split at accepted
  · contradiction
  · rename_i guard
    have h := (enumeration_guard_exact got capacity item bounded).mp (Bool.eq_false_iff.mpr guard)
    have cast := positive_c_int_cast_exact got h.1 bounded
    exact ⟨h, by simpa [cast] using (Except.ok.inj accepted).symm⟩

theorem enumeration_positive_observation_bridge (got : Int) (capacity item : Nat)
    (bounded : got ≤ 2147483647) :
    enumerationReject got capacity item = false ↔
      Enclave.TransportStartup.completeEnumeration true got.toNat capacity item = true := by
  rw [enumeration_guard_exact got capacity item bounded]
  simp [CompleteRecords, Enclave.TransportStartup.completeEnumeration]
  omega

theorem zero_item_refuses_before_success (got : Int) (capacity : Nat) :
    completeQuery got capacity 0 = .error ⟨"EIO", "KERNEL_FD_QUERY_FAILED"⟩ := by
  simp [completeQuery, enumerationReject]

theorem query_guard_exact (result : Int) (got expected : Nat) :
    queryReject result got expected = false ↔ result = 0 ∧ got = expected := by
  simp [queryReject]

theorem exact_query_positive_domain_bridge (result : Int) (got expected : Nat)
    (positive : 0 < expected) :
    (queryReject result got expected = false) ↔
      Enclave.TransportStartup.exactQuery (decide (result = 0)) got expected = true := by
  simp [query_guard_exact, Enclave.TransportStartup.exactQuery, positive]

theorem zero_length_helper_is_distinct_from_positive_structure_model :
    exactQuery 0 0 0 = .ok () ∧ Enclave.TransportStartup.exactQuery true 0 0 = false := by
  constructor <;> rfl

def NamespaceByte (b : UInt8) : Prop :=
  48 ≤ b.toNat ∧ b.toNat ≤ 57 ∨ 65 ≤ b.toNat ∧ b.toNat ≤ 90 ∨
  97 ≤ b.toNat ∧ b.toNat ≤ 122 ∨ b.toNat = 46 ∨ b.toNat = 95 ∨ b.toNat = 45

def HexByte (b : UInt8) : Prop :=
  48 ≤ b.toNat ∧ b.toNat ≤ 57 ∨ 97 ≤ b.toNat ∧ b.toNat ≤ 102

def EnvelopeShape (ns envelope : List UInt8) (epoch wrapping_epoch : Nat) : Prop :=
  1 ≤ ns.length ∧ ns.length ≤ 128 ∧ (∀ b ∈ ns, NamespaceByte b) ∧
    0 < epoch ∧ 0 < wrapping_epoch ∧ envelope.length = 144 ∧ (∀ b ∈ envelope, HexByte b)

theorem namespace_byte_exact (b : UInt8) : namespaceByte b = true ↔ NamespaceByte b := by
  simp [namespaceByte, NamespaceByte, asciiAlphanumeric, or_assoc]

theorem lowercase_hex_byte_exact (b : UInt8) : lowercaseHexByte b = true ↔ HexByte b := by
  simp [lowercaseHexByte, HexByte, asciiDigit]

theorem envelope_guard_exact (ns envelope : List UInt8) (epoch wrapping_epoch : Nat) :
    envelopeReject ns envelope epoch wrapping_epoch = false ↔
      EnvelopeShape ns envelope epoch wrapping_epoch := by
  simp [envelopeReject, EnvelopeShape, List.all_eq_true, namespace_byte_exact,
    lowercase_hex_byte_exact]
  have nonempty : (¬ns = []) ↔ 1 ≤ ns.length := by cases ns <;> simp
  rw [nonempty]
  simp only [Nat.pos_iff_ne_zero, and_assoc]

theorem monitor_success_preserves_payload {ε α : Type} (profile : Profile) (monitor : α) :
    startForProfile profile (.ok monitor : Except ε α) = .ok (some monitor) := rfl

theorem monitor_strict_error_preserves_payload {ε α : Type} (profile : Profile) (error : ε)
    (strict : profile ≠ .l1) :
    startForProfile profile (.error error : Except ε α) = .error error := by
  simp [startForProfile, strict]

theorem monitor_optional_exact {ε α : Type} (profile : Profile) (observation : Except ε α) :
    startForProfile profile observation = .ok none ↔
      profile = .l1 ∧ ∃ error, observation = .error error := by
  cases observation <;> cases profile <;> simp [startForProfile]

def runMonitorOnce {ε α σ : Type} (profile : Profile) (start : σ → Except ε α × σ)
    (state : σ) : Except ε (Option α) × σ :=
  let (result, next) := start state
  (startForProfile profile result, next)

theorem monitor_single_observation_threads_callback_state {ε α σ : Type} (profile : Profile)
    (start : σ → Except ε α × σ) (state : σ) :
    (runMonitorOnce profile start state).2 = (start state).2 := by
  simp [runMonitorOnce]

theorem checked_add_exact (a b value : Nat) :
    checked64 a b = some value ↔ a + b ≤ 18446744073709551615 ∧ value = a + b := by
  simp [checked64, eq_comm]

theorem disk_reserve_exact (outstanding extra value : Nat) :
    requiredDisk outstanding extra = .ok value ↔
      4294967296 + outstanding + extra ≤ 18446744073709551615 ∧
        value = 4294967296 + outstanding + extra := by
  by_cases first : 4294967296 + outstanding ≤ 18446744073709551615
  · by_cases second : 4294967296 + outstanding + extra ≤ 18446744073709551615
    · simp [requiredDisk, checked64, diskReserve, first, second, eq_comm]
    · simp [requiredDisk, checked64, diskReserve, first, second]
  · have second : ¬4294967296 + outstanding + extra ≤ 18446744073709551615 := by omega
    simp [requiredDisk, checked64, diskReserve, first, second]

theorem disk_overflow_has_exact_refusal (outstanding extra : Nat)
    (overflow : 18446744073709551615 < 4294967296 + outstanding + extra) :
    requiredDisk outstanding extra = .error ⟨"E2BIG", "ADMISSION_DISK_RESERVE"⟩ := by
  by_cases first : 4294967296 + outstanding ≤ 18446744073709551615
  · have second : ¬4294967296 + outstanding + extra ≤ 18446744073709551615 := by omega
    simp [requiredDisk, checked64, diskReserve, first, second]
  · simp [requiredDisk, checked64, diskReserve, first]

theorem bounded_write_exact {α : Type} (current incoming : List α) (expected : Nat)
    (within : current.length ≤ expected) :
    boundedWrite current incoming expected = .ok (current ++ incoming, incoming.length) ↔
      current.length + incoming.length ≤ expected := by
  simp [boundedWrite]
  omega

theorem accepted_write_length_and_contents {α : Type} (current incoming output : List α)
    (expected written : Nat) (within : current.length ≤ expected)
    (accepted : boundedWrite current incoming expected = .ok (output, written)) :
    output = current ++ incoming ∧ written = incoming.length ∧ output.length ≤ expected := by
  unfold boundedWrite at accepted
  split at accepted
  · contradiction
  · have eq := Except.ok.inj accepted
    cases eq
    exact ⟨rfl, rfl, by simp only [List.length_append]; omega⟩

end Enclave.TransportGuardRefinement
