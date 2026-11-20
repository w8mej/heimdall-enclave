/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Hardware Custody, Tiered Ceremonies & Quorum Governance Proofs
Normative Specification: FS-703 §4, FS-703 §8.1 (PROOF-H2-SEPARATION, PROOF-H5-QUORUM) & ADR-009/ADR-013
-/

namespace Enclave

/-! # Action Risk Tiers (A1 < A2 < A3 < A4) -/

inductive ActionTier where
  | A1 : ActionTier  -- Scratchpad / In-Memory Evaluation (0 prompts)
  | A2 : ActionTier  -- Read-Only Query / Scoped Storage Access
  | A3 : ActionTier  -- Reversible Tokenization / Code Edit (Touch ID required)
  | A4 : ActionTier  -- Irreversible Destruction / Plaintext PII Export (2-of-2 Hardware)
  deriving DecidableEq, Repr

def ActionTier.toNat : ActionTier → Nat
  | A1 => 1
  | A2 => 2
  | A3 => 3
  | A4 => 4

instance : LE ActionTier where
  le a b := a.toNat ≤ b.toNat

instance : LT ActionTier where
  lt a b := a.toNat < b.toNat

theorem action_le_refl (a : ActionTier) : a ≤ a :=
  Nat.le_refl a.toNat

theorem action_le_trans {a b c : ActionTier} (hab : a ≤ b) (hbc : b ≤ c) : a ≤ c :=
  Nat.le_trans hab hbc

theorem action_le_antisymm {a b : ActionTier} (hab : a ≤ b) (hba : b ≤ a) : a = b := by
  have heq : a.toNat = b.toNat := Nat.le_antisymm hab hba
  cases a <;> cases b <;> first | rfl | contradiction


/-! # Hardware Custody State Machine & Airplane Mode -/

structure HardwareState where
  sep_present : Bool
  touch_id_verified : Bool
  yubikey_present : Bool
  yubikey_tap_verified : Bool
  airplane_mode : Bool
  deriving DecidableEq, Repr

/--
Action authorization predicate enforcing tiered hardware verification:
- A1: Autonomous (unprompted, pre-authorized fuel budget)
- A2: Requires Secure Enclave present
- A3: Requires Secure Enclave + live Touch ID verification (CoreAuthUI)
- A4: Strict 2-of-2 hardware co-signature: SEP + Touch ID + YubiKey + User Presence tap
      (Strictly forbidden in Airplane Mode)
-/
def isActionAuthorized (tier : ActionTier) (st : HardwareState) : Bool :=
  match tier with
  | ActionTier.A1 => true
  | ActionTier.A2 => st.sep_present
  | ActionTier.A3 => st.sep_present && st.touch_id_verified
  | ActionTier.A4 =>
      st.sep_present &&
      st.touch_id_verified &&
      st.yubikey_present &&
      st.yubikey_tap_verified &&
      (!st.airplane_mode)

/--
Theorem 4.1 (PROOF-H2-SEPARATION / Dual-Silicon Requirement):
Authorizing an irreversible A4 action strictly implies that both Apple Secure Enclave
biometrics (Touch ID) and physical YubiKey user-presence touch were verified.
Single-token or software-only bypass is mathematically impossible.
-/
theorem a4_requires_dual_hardware (st : HardwareState)
    (h_auth : isActionAuthorized ActionTier.A4 st = true) :
    st.sep_present = true ∧
    st.touch_id_verified = true ∧
    st.yubikey_present = true ∧
    st.yubikey_tap_verified = true ∧
    st.airplane_mode = false := by
  simp_all [ActionTier.toNat, isActionAuthorized]

/--
Theorem 4.2 (Airplane Mode Invariant):
When in Airplane Mode or when the physical YubiKey is detached, an A4 action
cannot be authorized under any circumstances.
-/
theorem airplane_mode_blocks_a4 (st : HardwareState)
    (h_airplane : st.airplane_mode = true) :
    isActionAuthorized ActionTier.A4 st = false := by
  simp_all [ActionTier.toNat, isActionAuthorized]

/--
Corollary 4.3 (YubiKey Absence Invariant):
Disconnection of the physical FIDO2 key guarantees fail-closed blocking of A4 actions.
-/
theorem yubikey_absence_blocks_a4 (st : HardwareState)
    (h_absent : st.yubikey_present = false) :
    isActionAuthorized ActionTier.A4 st = false := by
  simp_all [ActionTier.toNat, isActionAuthorized]

/-! # Discrete k-of-n Multi-Signature Quorum Soundness (PROOF-H5-QUORUM, ADR-013) -/

structure QuorumGrant where
  threshold_k : Nat
  approvals : List Nat
  deriving DecidableEq, Repr

def isQuorumValid (q : QuorumGrant) : Bool :=
  q.approvals.eraseDups.length ≥ q.threshold_k

/--
Theorem 4.4 (PROOF-H5-QUORUM / Insider Collusion Bound):
Any coalition of m < k compromised or coerced insider keys strictly fails
to authorize a root rotation or emergency override.
-/
theorem quorum_insufficient_rejected (q : QuorumGrant)
    (h_insufficient : q.approvals.eraseDups.length < q.threshold_k) :
    isQuorumValid q = false := by
  simp only [isQuorumValid, decide_eq_false_iff_not]
  exact Nat.not_le_of_lt h_insufficient

end Enclave
