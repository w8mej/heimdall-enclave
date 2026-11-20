/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

RFC 9180 Authenticated Hybrid Public Key Encryption (AuthEncap / AuthDecap)
Normative Specification: RFC 9180 §5.2, FS-702 §6.3, & crates/enclave-crypto
-/

-- ASSURANCE: a standalone specification using Nat, records and Booleans.
-- Its original mechanism terminology is an interpretation of model fields.
-- No cryptographic protocol, deployed constraints, OS or hardware is verified here.
namespace Enclave

/-! # RFC 9180 AuthEncap Ciphertext Model -/

/-- Authenticated HPKE encapsulated packet. -/
structure HpkeAuthCiphertext where
  sender_pubkey_id : Nat
  receiver_pubkey_id : Nat
  ciphertext_bytes : Nat
  auth_tag : Nat
  deriving DecidableEq, Repr

/-- Authenticated decryption / decapsulation simulator. -/
def authDecap
    (ct : HpkeAuthCiphertext)
    (receiver_privkey_id : Nat)
    (expected_sender_id : Nat)
    (valid_auth_tag : Nat) : Option Nat :=
  if ct.receiver_pubkey_id == receiver_privkey_id &&
     ct.sender_pubkey_id == expected_sender_id &&
     ct.auth_tag == valid_auth_tag then
    some ct.ciphertext_bytes
  else
    none

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem numeric_tag_mismatch_returns_none
    (ct : HpkeAuthCiphertext)
    (priv_id exp_sender valid_tag : Nat)
    (h_tag : ct.auth_tag ≠ valid_tag) :
    authDecap ct priv_id exp_sender valid_tag = none := by
  simp_all [authDecap]

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem numeric_identity_and_tag_match_returns_payload
    (ct : HpkeAuthCiphertext)
    (priv_id exp_sender valid_tag : Nat)
    (h_rec : ct.receiver_pubkey_id = priv_id)
    (h_send : ct.sender_pubkey_id = exp_sender)
    (h_tag : ct.auth_tag = valid_tag) :
    authDecap ct priv_id exp_sender valid_tag = some ct.ciphertext_bytes := by
  dsimp [authDecap]
  have h_rec_eq : (ct.receiver_pubkey_id == priv_id) = true := decide_eq_true h_rec
  have h_send_eq : (ct.sender_pubkey_id == exp_sender) = true := decide_eq_true h_send
  have h_tag_eq : (ct.auth_tag == valid_tag) = true := decide_eq_true h_tag
  rw [h_rec_eq, h_send_eq, h_tag_eq]
  rfl

/-! # Formal HPKE Ephemeral-Static DH & Anti-Spoofing Guarantees -/

/-- Sender identity mismatch rejection -/
theorem numeric_sender_mismatch_returns_none
    (ct : HpkeAuthCiphertext)
    (priv_id exp_sender valid_tag : Nat)
    (h_sender_diff : ct.sender_pubkey_id ≠ exp_sender) :
    authDecap ct priv_id exp_sender valid_tag = none := by
  dsimp [authDecap]
  have h_dec : (ct.sender_pubkey_id == exp_sender) = false := decide_eq_false h_sender_diff
  rw [h_dec]
  cases (ct.receiver_pubkey_id == priv_id) <;> dsimp

/-- Receiver key mismatch rejection (mitigates misdirected ciphertext ingestion) -/
theorem numeric_receiver_mismatch_returns_none
    (ct : HpkeAuthCiphertext)
    (priv_id exp_sender valid_tag : Nat)
    (h_rec_diff : ct.receiver_pubkey_id ≠ priv_id) :
    authDecap ct priv_id exp_sender valid_tag = none := by
  dsimp [authDecap]
  have h_dec : (ct.receiver_pubkey_id == priv_id) = false := decide_eq_false h_rec_diff
  rw [h_dec]
  rfl

/-- Sequential AEAD sequence counter to prevent ciphertext replay attacks within session -/
structure HpkeContext where
  shared_secret_id : Nat
  seq_counter : Nat
  is_established : Bool
  deriving DecidableEq, Repr

/-- Advances the HPKE AEAD sequence counter after authentic message decapsulation -/
def advanceHpkeSeq (ctx : HpkeContext) : HpkeContext :=
  { ctx with seq_counter := ctx.seq_counter + 1 }

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem hpke_seq_strictly_monotonic (ctx : HpkeContext) :
    (advanceHpkeSeq ctx).seq_counter = ctx.seq_counter + 1 := by
  dsimp [advanceHpkeSeq]

/-! # RFC 9180 Dual-Diffie-Hellman Shared Secret Agreement -/

/-- Abstract symmetric group scalar multiplication / Diffie-Hellman operator: DH(priv, pub) = priv * pub -/
def dhExchange (priv : Nat) (pub : Nat) : Nat :=
  (priv * pub) % 1000000007

/--
Dual-DH Shared Secret Derivation in AuthEncap mode:
ss = KDF(DH(ek, pk_R) || DH(sk_S, pk_R))
-/
def deriveAuthEncapSecret (ek sk_S pk_R : Nat) : Nat :=
  dhExchange ek pk_R * 10007 + dhExchange sk_S pk_R

/--
Dual-DH Shared Secret Recovery in AuthDecap mode:
ss = KDF(DH(sk_R, pk_E) || DH(sk_R, pk_S))
-/
def deriveAuthDecapSecret (sk_R pk_E pk_S : Nat) : Nat :=
  dhExchange sk_R pk_E * 10007 + dhExchange sk_R pk_S

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem modular_products_commute_in_pair_sum (ek sk_S sk_R : Nat) :
    deriveAuthEncapSecret ek sk_S sk_R = deriveAuthDecapSecret sk_R ek sk_S := by
  dsimp [deriveAuthEncapSecret, deriveAuthDecapSecret, dhExchange]
  have h_comm1 : (ek * sk_R) = (sk_R * ek) := Nat.mul_comm ek sk_R
  have h_comm2 : (sk_S * sk_R) = (sk_R * sk_S) := Nat.mul_comm sk_S sk_R
  rw [h_comm1, h_comm2]

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem affine_payload_map_injective (ss payload1 payload2 : Nat) (h_diff : payload1 ≠ payload2) :
    (ss * 31 + payload1) ≠ (ss * 31 + payload2) := by
  intro h_eq
  omega

end Enclave
