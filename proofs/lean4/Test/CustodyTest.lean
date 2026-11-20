/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Unit Tests for Hardware Custody, Audit Chain, and TUF Anti-Rollback
-/

import Enclave.HardwareCustody
import Enclave.AuditChain
import Enclave.TufAntiRollback

namespace Enclave.Test

open Enclave

-- Hardware Custody Test: Airplane mode blocks A4
def state_airplane : HardwareState :=
  { sep_present := true
  , touch_id_verified := true
  , yubikey_present := true
  , yubikey_tap_verified := true
  , airplane_mode := true }

theorem test_airplane_blocks_a4 : isActionAuthorized ActionTier.A4 state_airplane = false := by
  rfl

-- Hardware Custody Test: Fully verified state authorizes A4
def state_docked_verified : HardwareState :=
  { sep_present := true
  , touch_id_verified := true
  , yubikey_present := true
  , yubikey_tap_verified := true
  , airplane_mode := false }

theorem test_docked_authorizes_a4 : isActionAuthorized ActionTier.A4 state_docked_verified = true := by
  rfl

-- TUF Anti-Rollback Test: Replaying version 1 when current is version 2 fails
def tuf_current : TufMetadata := { version := 2, expires_epoch := 1000, root_keys := [1] }
def tuf_rollback : TufMetadata := { version := 1, expires_epoch := 1000, root_keys := [1] }

theorem test_tuf_rollback_rejected : isUpdateAdmissible tuf_current tuf_rollback 500 = false := by
  rfl

-- Audit Chain Test: Tombstone and regular payload differ in hash
theorem test_tombstone_diff : linearEntryCode 100 1 500 true ≠ linearEntryCode 100 1 500 false := by
  decide

end Enclave.Test
