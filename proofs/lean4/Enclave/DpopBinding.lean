/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

RFC 9449 DPoP (Demonstrating Proof of Possession) Application-Layer Token Binding Proofs
Normative Specification: RFC 9449, FS-703, FS-704, & crates/enclave-crypto/src/dpop.rs
-/

-- MODEL ONLY: arithmetic codes/string prefixes, not cryptographic hashes.
-- Coordinate injectivity and equality tests do not establish collision resistance,
-- authenticated streaming or RFC 9449 token/signature verification.
namespace Enclave

/-- Statement about this arithmetic/string model only. No cryptographic conclusion. -/
def modelTokenPrefix (token : String) : String :=
  "sha256:" ++ token

/-- RFC 9449 DPoP Proof Token structure -/
structure DpopProof where
  jti : String          -- Unique token identifier for replay prevention
  htm : String          -- HTTP method binding (e.g., "GET", "POST")
  htu : String          -- HTTP target URI binding (e.g., "/tools/read")
  iat : Nat             -- Issued-at timestamp (seconds)
  ath : String          -- Access token hash binding
  public_key : String   -- Ephemeral client public key (JWK thumbprint / jkt)
  signature_valid : Bool -- Cryptographic signature validity
  deriving DecidableEq, Repr

/-- Maximum allowed clock skew / freshness replay window in seconds (RFC 9449 §4.3) -/
def DPOP_FRESHNESS_WINDOW : Nat := 60

/-- Statement about this arithmetic/string model only. No cryptographic conclusion. -/
def verifyDpopProof
    (p : DpopProof)
    (token : String)
    (expected_method : String)
    (expected_uri : String)
    (now : Nat)
    (seen_jtis : List String) : Bool :=
  p.signature_valid &&
  p.htm == expected_method &&
  p.htu == expected_uri &&
  p.ath == modelTokenPrefix token &&
  now ≥ p.iat &&
  now - p.iat ≤ DPOP_FRESHNESS_WINDOW &&
  !seen_jtis.contains p.jti

/--
Theorem 15.1 (DPoP Method Substitution Rejection):
Any DPoP proof presented with an HTTP method differing from the bound `htm` claim
is deterministically rejected, preventing read-proof replay against write endpoints.
-/
theorem dpop_method_substitution_rejected
    (p : DpopProof) (token : String) (expected_method : String) (expected_uri : String)
    (now : Nat) (seen_jtis : List String)
    (h_method_mismatch : p.htm ≠ expected_method) :
    verifyDpopProof p token expected_method expected_uri now seen_jtis = false := by
  dsimp [verifyDpopProof]
  have h_eq : (p.htm == expected_method) = false := by
    cases h : (p.htm == expected_method)
    · rfl
    · simp only [beq_iff_eq] at h; contradiction
  rw [h_eq]
  simp

/--
Theorem 15.2 (DPoP Target URI Substitution Rejection):
Any DPoP proof presented against a target URI differing from the bound `htu` claim
is deterministically rejected, preventing cross-endpoint token relay.
-/
theorem dpop_uri_substitution_rejected
    (p : DpopProof) (token : String) (expected_method : String) (expected_uri : String)
    (now : Nat) (seen_jtis : List String)
    (h_uri_mismatch : p.htu ≠ expected_uri) :
    verifyDpopProof p token expected_method expected_uri now seen_jtis = false := by
  dsimp [verifyDpopProof]
  have h_eq : (p.htu == expected_uri) = false := by
    cases h : (p.htu == expected_uri)
    · rfl
    · simp only [beq_iff_eq] at h; contradiction
  rw [h_eq]
  simp

/-- Statement about this arithmetic/string model only. No cryptographic conclusion. -/
theorem dpop_token_swap_rejected
    (p : DpopProof) (token : String) (expected_method : String) (expected_uri : String)
    (now : Nat) (seen_jtis : List String)
    (h_hash_mismatch : p.ath ≠ modelTokenPrefix token) :
    verifyDpopProof p token expected_method expected_uri now seen_jtis = false := by
  dsimp [verifyDpopProof]
  have h_eq : (p.ath == modelTokenPrefix token) = false := by
    cases h : (p.ath == modelTokenPrefix token)
    · rfl
    · simp only [beq_iff_eq] at h; contradiction
  rw [h_eq]
  simp

/--
Theorem 15.4 (DPoP Replay Freshness Expiration):
Any DPoP proof whose timestamp is older than 60 seconds is deterministically rejected,
strictly bounding the adversary's window of opportunity.
-/
theorem dpop_replay_window_expired
    (p : DpopProof) (token : String) (expected_method : String) (expected_uri : String)
    (now : Nat) (seen_jtis : List String)
    (h_expired : now - p.iat > DPOP_FRESHNESS_WINDOW) :
    verifyDpopProof p token expected_method expected_uri now seen_jtis = false := by
  dsimp [verifyDpopProof, DPOP_FRESHNESS_WINDOW] at *
  have h_not_le : ¬(now - p.iat ≤ 60) := by omega
  simp [h_not_le]

/--
Theorem 15.5 (DPoP JTI Replay Prevention):
Presenting a proof whose unique `jti` is already recorded in the replay cache
is deterministically rejected fail-closed.
-/
theorem dpop_replayed_jti_rejected
    (p : DpopProof) (token : String) (expected_method : String) (expected_uri : String)
    (now : Nat) (seen_jtis : List String)
    (h_replayed : seen_jtis.contains p.jti = true) :
    verifyDpopProof p token expected_method expected_uri now seen_jtis = false := by
  dsimp [verifyDpopProof]
  rw [h_replayed]
  simp

/-! # Extended Signature and Temporal Rejection Theorems -/

/-- Statement about this arithmetic/string model only. No cryptographic conclusion. -/
theorem dpop_invalid_signature_rejected
    (p : DpopProof) (token : String) (expected_method : String) (expected_uri : String)
    (now : Nat) (seen_jtis : List String)
    (h_sig : p.signature_valid = false) :
    verifyDpopProof p token expected_method expected_uri now seen_jtis = false := by
  dsimp [verifyDpopProof]
  rw [h_sig]
  rfl

/--
Theorem 15.7 (DPoP Future Timestamp Rejection):
A proof dated in the future (`now < p.iat`) fails chronological validation.
-/
theorem dpop_future_timestamp_rejected
    (p : DpopProof) (token : String) (expected_method : String) (expected_uri : String)
    (now : Nat) (seen_jtis : List String)
    (h_future : now < p.iat) :
    verifyDpopProof p token expected_method expected_uri now seen_jtis = false := by
  simp_all [modelTokenPrefix, DPOP_FRESHNESS_WINDOW, verifyDpopProof]
  omega

/-- Records a fresh JTI into the seen set. -/
def recordDpopJti (seen : List String) (jti : String) : List String :=
  jti :: seen

/--
Theorem 15.8 (Recorded JTI Deterministically Replay-Protected):
Recording a proof's JTI ensures subsequent attempts with that JTI are rejected.
-/
theorem recorded_jti_rejected
    (p : DpopProof) (token : String) (expected_method : String) (expected_uri : String)
    (now : Nat) (seen : List String) :
    verifyDpopProof p token expected_method expected_uri now (recordDpopJti seen p.jti) = false := by
  dsimp [recordDpopJti]
  have h_contains : (p.jti :: seen).contains p.jti = true := by
    dsimp [List.contains, List.elem]
    simp
  exact dpop_replayed_jti_rejected p token expected_method expected_uri now (p.jti :: seen) h_contains

end Enclave
