/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Hardware Token Disconnect & Instantaneous Volatile Memory Zeroization
Normative Specification: GAP-60, FS-704 §7.2, & crates/enclave-custody-vaultd
-/

namespace Enclave

/-! # Physical YubiKey Yank & Volatile Slot Zeroization -/

/-- Status of a cryptographic key slot in volatile vault memory. -/
inductive VaultKeySlotStatus where
  | ActiveKey : Nat → VaultKeySlotStatus
  | ZeroizedClean : VaultKeySlotStatus
  deriving DecidableEq, Repr

/-- Physical USB bus connection state. -/
inductive UsbHardwareState where
  | Connected : UsbHardwareState
  | Disconnected : UsbHardwareState
  deriving DecidableEq, Repr

/-- Process an asynchronous USB hardware event. -/
def handleUsbBusEvent (usb : UsbHardwareState) (slot : VaultKeySlotStatus) : VaultKeySlotStatus :=
  match usb with
  | UsbHardwareState.Connected => slot
  | UsbHardwareState.Disconnected => VaultKeySlotStatus.ZeroizedClean

/-- Attempt to execute a cryptographic signing or detokenization operation using a slot. -/
def executeSlotOperation (slot : VaultKeySlotStatus) (op_payload : Nat) : Option Nat :=
  match slot with
  | VaultKeySlotStatus.ActiveKey key => some (key + op_payload)
  | VaultKeySlotStatus.ZeroizedClean => none

/--
Theorem 41.1 (USB Disconnect Instant Zeroize):
Upon physical disconnection of the USB hardware key, the volatile vault memory slot
immediately transitions to `ZeroizedClean`.
-/
theorem usb_disconnect_instant_zeroize (slot : VaultKeySlotStatus) :
    handleUsbBusEvent UsbHardwareState.Disconnected slot = VaultKeySlotStatus.ZeroizedClean := by
  dsimp [handleUsbBusEvent]

/--
Theorem 41.2 (Post-Yank Detokenize Impossibility):
Once a vault slot has been zeroized following a hardware disconnect, any subsequent
attempt to detokenize secrets or perform cryptographic operations is strictly impossible (`none`).
-/
theorem post_yank_detokenize_impossibility
    (slot : VaultKeySlotStatus)
    (payload : Nat)
    (h_zero : slot = VaultKeySlotStatus.ZeroizedClean) :
    executeSlotOperation slot payload = none := by
  dsimp [executeSlotOperation]
  rw [h_zero]

/-! # Multi-Slot Vault Keyring Zeroization Cascade & Invariants -/

/-- A multi-slot hardware custody keyring in volatile RAM. -/
structure VaultKeyring where
  slots : List VaultKeySlotStatus
  deriving Repr

/-- Cascades USB event handler across all keyring slots. -/
def handleKeyringUsbEvent (usb : UsbHardwareState) (ring : VaultKeyring) : VaultKeyring :=
  { slots := ring.slots.map (handleUsbBusEvent usb) }

/-- Predicate verifying that all slots in the keyring are zeroized clean. -/
def AllRingSlotsZeroized (ring : VaultKeyring) : Prop :=
  ∀ s ∈ ring.slots, s = VaultKeySlotStatus.ZeroizedClean

/--
Theorem 41.3 (Keyring USB Yank Total Zeroization):
Physical USB disconnect wipes every single slot across the entire keyring.
-/
theorem usb_disconnect_wipes_all_slots (ring : VaultKeyring) :
    AllRingSlotsZeroized (handleKeyringUsbEvent UsbHardwareState.Disconnected ring) := by
  intro s hs
  dsimp [handleKeyringUsbEvent] at hs
  rw [List.mem_map] at hs
  rcases hs with ⟨orig, _, h_mapped⟩
  rw [← h_mapped]
  exact usb_disconnect_instant_zeroize orig

/--
Theorem 41.4 (Connected State Preserves Keyring):
If USB connection is preserved, keyring slot contents remain unchanged.
-/
theorem usb_connected_preserves_keyring (ring : VaultKeyring) :
    (handleKeyringUsbEvent UsbHardwareState.Connected ring).slots = ring.slots := by
  dsimp [handleKeyringUsbEvent]
  induction ring.slots with
  | nil => rfl
  | cons s ss ih =>
    dsimp [handleUsbBusEvent]
    rw [ih]

/--
Theorem 41.5 (Zeroization Idempotency):
Applying disconnect zeroization repeatedly to an already zeroized slot preserves the zeroized state.
-/
theorem usb_zeroize_idempotent (slot : VaultKeySlotStatus) :
    handleUsbBusEvent UsbHardwareState.Disconnected
      (handleUsbBusEvent UsbHardwareState.Disconnected slot) =
    handleUsbBusEvent UsbHardwareState.Disconnected slot := by
  dsimp [handleUsbBusEvent]

end Enclave
