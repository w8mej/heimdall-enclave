/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Information Flow Control (IFC) Monotonic Security Lattices
Normative Specification: FS-704 §3.1 & ADR-007
-/

namespace Enclave

/-! # Confidentiality Lattice (C1 < C2 < C3 < C4) -/

inductive ConfLevel where
  | C1 : ConfLevel  -- Public / Scrubbed / Declassified
  | C2 : ConfLevel  -- Internal Corporate / Low-Sensitivity
  | C3 : ConfLevel  -- Confidential / Pseudonymized PII
  | C4 : ConfLevel  -- Restricted / High-Entropy Secrets / Raw PAN & SSN
  deriving DecidableEq, Repr

def ConfLevel.toNat : ConfLevel → Nat
  | C1 => 1
  | C2 => 2
  | C3 => 3
  | C4 => 4

instance : LE ConfLevel where
  le a b := a.toNat ≤ b.toNat

instance : LT ConfLevel where
  lt a b := a.toNat < b.toNat

instance (a b : ConfLevel) : Decidable (a ≤ b) :=
  inferInstanceAs (Decidable (a.toNat ≤ b.toNat))

instance (a b : ConfLevel) : Decidable (a < b) :=
  inferInstanceAs (Decidable (a.toNat < b.toNat))

theorem conf_le_refl (a : ConfLevel) : a ≤ a :=
  Nat.le_refl a.toNat

theorem conf_le_trans {a b c : ConfLevel} (hab : a ≤ b) (hbc : b ≤ c) : a ≤ c :=
  Nat.le_trans hab hbc

theorem conf_le_antisymm {a b : ConfLevel} (hab : a ≤ b) (hba : b ≤ a) : a = b := by
  have heq : a.toNat = b.toNat := Nat.le_antisymm hab hba
  cases a <;> cases b <;> first | rfl | contradiction

def ConfLevel.join (a b : ConfLevel) : ConfLevel :=
  if a.toNat ≥ b.toNat then a else b

def ConfLevel.meet (a b : ConfLevel) : ConfLevel :=
  if a.toNat ≤ b.toNat then a else b

theorem conf_join_comm (a b : ConfLevel) : ConfLevel.join a b = ConfLevel.join b a := by
  cases a <;> cases b <;> rfl

theorem conf_join_assoc (a b c : ConfLevel) :
    ConfLevel.join (ConfLevel.join a b) c = ConfLevel.join a (ConfLevel.join b c) := by
  cases a <;> cases b <;> cases c <;> rfl

theorem conf_join_idem (a : ConfLevel) : ConfLevel.join a a = a := by
  cases a <;> rfl

theorem conf_join_le_left (a b : ConfLevel) : a ≤ ConfLevel.join a b := by
  cases a <;> cases b <;> decide

theorem conf_join_le_right (a b : ConfLevel) : b ≤ ConfLevel.join a b := by
  cases a <;> cases b <;> decide

theorem conf_join_least {a b c : ConfLevel} (ha : a ≤ c) (hb : b ≤ c) : ConfLevel.join a b ≤ c := by
  cases a <;> cases b <;> cases c <;> first | decide | contradiction


/-! # Integrity & Taint Lattice (T0 < T1 < T2 < T3) -/

inductive IntegLevel where
  | T0 : IntegLevel  -- Hardware Root of Trust / Secure Enclave
  | T1 : IntegLevel  -- Verified Enclave Plan / Local Policy Engine
  | T2 : IntegLevel  -- Attested MCP Tool / Scoped Output
  | T3 : IntegLevel  -- Untrusted External / Prompt Injection Suspect
  deriving DecidableEq, Repr

def IntegLevel.toNat : IntegLevel → Nat
  | T0 => 0
  | T1 => 1
  | T2 => 2
  | T3 => 3

instance : LE IntegLevel where
  le a b := a.toNat ≤ b.toNat

instance : LT IntegLevel where
  lt a b := a.toNat < b.toNat

instance (a b : IntegLevel) : Decidable (a ≤ b) :=
  inferInstanceAs (Decidable (a.toNat ≤ b.toNat))

instance (a b : IntegLevel) : Decidable (a < b) :=
  inferInstanceAs (Decidable (a.toNat < b.toNat))

theorem integ_le_refl (a : IntegLevel) : a ≤ a :=
  Nat.le_refl a.toNat

theorem integ_le_trans {a b c : IntegLevel} (hab : a ≤ b) (hbc : b ≤ c) : a ≤ c :=
  Nat.le_trans hab hbc

theorem integ_le_antisymm {a b : IntegLevel} (hab : a ≤ b) (hba : b ≤ a) : a = b := by
  have heq : a.toNat = b.toNat := Nat.le_antisymm hab hba
  cases a <;> cases b <;> first | rfl | contradiction

def IntegLevel.join (a b : IntegLevel) : IntegLevel :=
  if a.toNat ≥ b.toNat then a else b

abbrev conf_join := ConfLevel.join
abbrev integ_join := IntegLevel.join

def IntegLevel.meet (a b : IntegLevel) : IntegLevel :=
  if a.toNat ≤ b.toNat then a else b

theorem integ_join_comm (a b : IntegLevel) : IntegLevel.join a b = IntegLevel.join b a := by
  cases a <;> cases b <;> rfl

theorem integ_join_assoc (a b c : IntegLevel) :
    IntegLevel.join (IntegLevel.join a b) c = IntegLevel.join a (IntegLevel.join b c) := by
  cases a <;> cases b <;> cases c <;> rfl

theorem integ_join_idem (a : IntegLevel) : IntegLevel.join a a = a := by
  cases a <;> rfl


/-! # Composite Security Label & Flow Preorder -/

structure SecurityLabel where
  confidentiality : ConfLevel
  integrity : IntegLevel
  deriving DecidableEq, Repr

def SecurityLabel.join (l1 l2 : SecurityLabel) : SecurityLabel :=
  { confidentiality := ConfLevel.join l1.confidentiality l2.confidentiality
  , integrity := IntegLevel.join l1.integrity l2.integrity }

def SecurityLabel.canFlowTo (src dst : SecurityLabel) : Bool :=
  src.confidentiality ≤ dst.confidentiality ∧ src.integrity ≤ dst.integrity

theorem security_flow_refl (l : SecurityLabel) : SecurityLabel.canFlowTo l l = true := by
  simp [SecurityLabel.canFlowTo, conf_le_refl, integ_le_refl]

theorem security_flow_trans {l1 l2 l3 : SecurityLabel}
    (h12 : SecurityLabel.canFlowTo l1 l2 = true)
    (h23 : SecurityLabel.canFlowTo l2 l3 = true) :
    SecurityLabel.canFlowTo l1 l3 = true := by
  simp only [SecurityLabel.canFlowTo, Bool.and_eq_true, decide_eq_true_eq] at h12 h23 ⊢
  exact ⟨conf_le_trans h12.1 h23.1, integ_le_trans h12.2 h23.2⟩

end Enclave
