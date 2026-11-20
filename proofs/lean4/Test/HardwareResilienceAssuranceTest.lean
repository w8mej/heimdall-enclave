/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Hardware Resilience Assurance Test Suite:
Crash-Consistent Epoch Recovery and USB Yank Zeroization.
-/

import Enclave.CrashConsistentRecovery
import Enclave.UsbYankZeroization

namespace EnclaveTest

open Enclave

/-- Test 1: Crash during SEP NVRAM increment rolls back to previous valid epoch. -/
def sampleCrashState : CrashSnapshot := {
  phase := EpochCommitPhase.SepNvramIncremented,
  previous_epoch := 40,
  proposed_epoch := 41
}

theorem test_crash_recovery_rolls_back_unflushed :
    recoverEpochState sampleCrashState = 40 := by
  rfl

/-- Test 2: Crash after APFS WAL flush rolls forward to proposed epoch. -/
def sampleCommittedCrash : CrashSnapshot := {
  phase := EpochCommitPhase.ApfsWalFlushed,
  previous_epoch := 40,
  proposed_epoch := 41
}

theorem test_crash_recovery_rolls_forward_committed :
    recoverEpochState sampleCommittedCrash = 41 := by
  rfl

/-- Test 3: USB disconnect event zeroizes vault slot. -/
def sampleActiveSlot : VaultKeySlotStatus := VaultKeySlotStatus.ActiveKey 0xCAFE

theorem test_usb_yank_zeroizes_slot :
    handleUsbBusEvent UsbHardwareState.Disconnected sampleActiveSlot = VaultKeySlotStatus.ZeroizedClean := by
  rfl

/-- Test 4: Detokenization fails on zeroized slot. -/
theorem test_zeroized_slot_fails_detokenize :
    executeSlotOperation VaultKeySlotStatus.ZeroizedClean 42 = none := by
  rfl

end EnclaveTest
