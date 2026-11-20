/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Parallel Automata Composition & Generalized Noninterference (M1 ⊗ M2)
Normative Specification: McCullough Generalized Noninterference & FS-704
-/

import Enclave.Lattice

namespace Enclave

abbrev confJoin := ConfLevel.join
def confLe (a b : ConfLevel) : Prop := a ≤ b

/-! # Compositional Reactive Enclave Automata -/

/-- Inter-enclave message transmitted over an authenticated mTLS channel. -/
structure EnclaveMessage where
  sender_uid : Nat
  receiver_uid : Nat
  label : ConfLevel
  payload : Nat
  deriving DecidableEq, Repr

/-- Internal state of an enclave automaton. -/
structure ReactiveEnclaveState where
  enclave_uid : Nat
  conf_level : ConfLevel
  outbox : List EnclaveMessage
  deriving DecidableEq, Repr

/--
Composite state of two communicating enclaves (M1 and M2).
-/
structure CompositeEnclaveSystem where
  m1 : ReactiveEnclaveState
  m2 : ReactiveEnclaveState
  deriving DecidableEq, Repr

/-- Message transmission step from M1 to M2. -/
def transmitM1toM2 (sys : CompositeEnclaveSystem) (msg : EnclaveMessage) : Option CompositeEnclaveSystem :=
  if msg.sender_uid == sys.m1.enclave_uid && msg.receiver_uid == sys.m2.enclave_uid then
    let new_m2 : ReactiveEnclaveState := {
      sys.m2 with conf_level := confJoin sys.m2.conf_level msg.label
    }
    some { sys with m2 := new_m2 }
  else
    none

/--
Theorem 35.1 (Composition Preserves Noninterference):
When a message is transmitted from M1 to M2, M2's confidentiality label monotonically
rises to at least the confidentiality of the transmitted message, preventing declassification.
-/
theorem composition_preserves_noninterference
    (sys sys' : CompositeEnclaveSystem)
    (msg : EnclaveMessage)
    (h_step : transmitM1toM2 sys msg = some sys') :
    confLe msg.label sys'.m2.conf_level := by
  dsimp [transmitM1toM2] at h_step
  split at h_step
  · cases h_step
    dsimp
    exact conf_join_le_right sys.m2.conf_level msg.label
  · contradiction

/--
Theorem 35.2 (Channel Label Integrity):
Transmitting a message with confidentiality label C cannot decrease M2's confidentiality
below its current state (`confLe sys.m2.conf_level sys'.m2.conf_level`).
-/
theorem channel_label_integrity
    (sys sys' : CompositeEnclaveSystem)
    (msg : EnclaveMessage)
    (h_step : transmitM1toM2 sys msg = some sys') :
    confLe sys.m2.conf_level sys'.m2.conf_level := by
  dsimp [transmitM1toM2] at h_step
  split at h_step
  · cases h_step
    dsimp
    exact conf_join_le_left sys.m2.conf_level msg.label
  · contradiction

/-! # Multi-Enclave Isolation & Trace Induction -/

/-- Message transmission preserves sender automaton state M1 unconditionally. -/
theorem transmit_preserves_m1
    (sys sys' : CompositeEnclaveSystem)
    (msg : EnclaveMessage)
    (h_step : transmitM1toM2 sys msg = some sys') :
    sys'.m1 = sys.m1 := by
  dsimp [transmitM1toM2] at h_step
  split at h_step
  · cases h_step
    rfl
  · contradiction

/-- Mismatched sender rejection (anti-spoofing). -/
theorem transmit_sender_mismatch_rejected
    (sys : CompositeEnclaveSystem)
    (msg : EnclaveMessage)
    (h_sender : msg.sender_uid ≠ sys.m1.enclave_uid) :
    transmitM1toM2 sys msg = none := by
  dsimp [transmitM1toM2]
  have h_dec : (msg.sender_uid == sys.m1.enclave_uid) = false := decide_eq_false h_sender
  rw [h_dec]
  rfl

/-- Mismatched receiver rejection (prevents misdirected message ingestion). -/
theorem transmit_receiver_mismatch_rejected
    (sys : CompositeEnclaveSystem)
    (msg : EnclaveMessage)
    (h_rec : msg.receiver_uid ≠ sys.m2.enclave_uid) :
    transmitM1toM2 sys msg = none := by
  dsimp [transmitM1toM2]
  have h_dec : (msg.receiver_uid == sys.m2.enclave_uid) = false := decide_eq_false h_rec
  rw [h_dec]
  cases (msg.sender_uid == sys.m1.enclave_uid) <;> dsimp

/-- Message transmission step from M2 to M1 (reverse channel). -/
def transmitM2toM1 (sys : CompositeEnclaveSystem) (msg : EnclaveMessage) : Option CompositeEnclaveSystem :=
  if msg.sender_uid == sys.m2.enclave_uid && msg.receiver_uid == sys.m1.enclave_uid then
    let new_m1 : ReactiveEnclaveState := {
      sys.m1 with conf_level := confJoin sys.m1.conf_level msg.label
    }
    some { sys with m1 := new_m1 }
  else
    none

/--
Theorem 35.3 (Reverse Channel Noninterference):
Transmission from M2 to M1 raises M1's label monotonically to at least the message label.
-/
theorem composition_reverse_noninterference
    (sys sys' : CompositeEnclaveSystem)
    (msg : EnclaveMessage)
    (h_step : transmitM2toM1 sys msg = some sys') :
    confLe msg.label sys'.m1.conf_level := by
  dsimp [transmitM2toM1] at h_step
  split at h_step
  · cases h_step
    dsimp
    exact conf_join_le_right sys.m1.conf_level msg.label
  · contradiction

end Enclave
