/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Audit Journal Hash-Chaining, Contiguity & Tombstone Contiguity Proofs
Normative Specification: FS-705 §3.2, FS-705 §8.1 (PROOF-Z3-INGRESS-BIND) & ADR-016
-/

-- MODEL ONLY: arithmetic codes/string prefixes, not cryptographic hashes.
-- Coordinate injectivity and equality tests do not establish collision resistance,
-- authenticated streaming or RFC 9449 token/signature verification.
namespace Enclave

/-- Hash digest representation (abstract natural number/finite field element) -/
abbrev HashDigest := Nat

/-- Statement about this arithmetic/string model only. No cryptographic conclusion. -/
def linearEntryCode (prev : HashDigest) (seq : Nat) (payload : HashDigest) (tombstone : Bool) : HashDigest :=
  prev * 31 + seq * 17 + payload * 7 + (if tombstone then 1 else 0)

/-- An individual audit journal envelope entry -/
structure AuditEntry where
  rpc_seq : Nat
  payload_digest : HashDigest
  is_tombstone : Bool
  prev_hash : HashDigest
  entry_hash : HashDigest
  deriving DecidableEq, Repr

/--
Valid entry invariant: the entry hash must be the deterministic evaluation
of linearEntryCode over the previous hash, sequence, payload, and tombstone flag.
-/
def isValidEntry (e : AuditEntry) : Bool :=
  e.entry_hash == linearEntryCode e.prev_hash e.rpc_seq e.payload_digest e.is_tombstone

/-- Statement about this arithmetic/string model only. No cryptographic conclusion. -/
def isContiguousChain (entries : List AuditEntry) (genesis : HashDigest) : Bool :=
  match entries with
  | [] => true
  | e :: es =>
      e.prev_hash == genesis ∧
      isValidEntry e ∧
      (let rec checkTail (prev : AuditEntry) (rest : List AuditEntry) : Bool :=
        match rest with
        | [] => true
        | curr :: next =>
            curr.rpc_seq == prev.rpc_seq + 1 ∧
            curr.prev_hash == prev.entry_hash ∧
            isValidEntry curr ∧
            checkTail curr next
       checkTail e es)

/--
Theorem 5.1 (PROOF-Z3-INGRESS-BIND / Contiguity Preservation):
In any valid contiguous journal of at least two entries, the second entry's sequence
number is strictly greater than the first entry's sequence number.
-/
theorem journal_step_strictly_monotonic (e1 e2 : AuditEntry) (rest : List AuditEntry) (genesis : HashDigest)
    (h_chain : isContiguousChain (e1 :: e2 :: rest) genesis = true) :
    e1.rpc_seq < e2.rpc_seq := by
  simp [isContiguousChain, isContiguousChain.checkTail] at h_chain
  omega

/-- Statement about this arithmetic/string model only. No cryptographic conclusion. -/
theorem linear_payload_coordinate_injective
    (prev : HashDigest) (seq : Nat) (p1 p2 : HashDigest) (tomb : Bool)
    (h_diff : p1 ≠ p2) :
    linearEntryCode prev seq p1 tomb ≠ linearEntryCode prev seq p2 tomb := by
  intro h
  cases tomb <;> simp [linearEntryCode] at h
  all_goals exact h_diff (Nat.eq_of_mul_eq_mul_right (by decide) h)

/--
Theorem 5.3 (Pre-Egress Tombstone Mutual Exclusivity, F-025):
An entry explicitly flagged as an AbortedPreEgressTombstone is distinguishable
from an egress-released payload with the same parameters.
-/
theorem tombstone_distinguishable
    (prev : HashDigest) (seq : Nat) (payload : HashDigest) :
    linearEntryCode prev seq payload true ≠ linearEntryCode prev seq payload false := by
  simp [linearEntryCode]

/-! # Extended Hash Chain Properties -/

/-- Statement about this arithmetic/string model only. No cryptographic conclusion. -/
theorem linear_previous_coordinate_injective
    (prev1 prev2 : HashDigest) (seq : Nat) (payload : HashDigest) (tomb : Bool)
    (h_diff : prev1 ≠ prev2) :
    linearEntryCode prev1 seq payload tomb ≠ linearEntryCode prev2 seq payload tomb := by
  intro h
  cases tomb <;> simp [linearEntryCode] at h
  all_goals exact h_diff (Nat.eq_of_mul_eq_mul_right (by decide) h)

/-- Statement about this arithmetic/string model only. No cryptographic conclusion. -/
theorem linear_sequence_coordinate_injective
    (prev : HashDigest) (seq1 seq2 : Nat) (payload : HashDigest) (tomb : Bool)
    (h_diff : seq1 ≠ seq2) :
    linearEntryCode prev seq1 payload tomb ≠ linearEntryCode prev seq2 payload tomb := by
  cases tomb <;> simp_all [linearEntryCode] <;> omega

end Enclave
