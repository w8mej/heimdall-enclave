/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Darwin LOCAL_PEERTOKEN Audit Token Monotonicity & PID Reuse Race Immunity
Normative Specification: Darwin audit_token_t & crates/enclave-core/src/ipc.rs
-/

namespace Enclave

/-! # Darwin audit_token_t Generation Monotonicity -/

/--
Darwin kernel audit token model (representing `audit_token_t` from `LOCAL_PEERTOKEN`).
`pid`: Process ID (recycled by kernel over time).
`generation_id`: Strictly monotonic 64-bit generation counter assigned at `fork`/`posix_spawn`.
`euid`: Effective user ID (UID 701–705).
`asid`: Audit session identifier.
-/
structure DarwinAuditToken where
  pid : Nat
  generation_id : Nat
  euid : Nat
  asid : Nat
  deriving DecidableEq, Repr

/-- Process lifecycle registration entry in the kernel task table. -/
structure KernelTaskSlot where
  pid : Nat
  current_generation : Nat
  active : Bool
  deriving DecidableEq, Repr

/-- Advance a kernel task slot by respawning a process into the same PID. -/
def respawnProcessSlot (slot : KernelTaskSlot) : KernelTaskSlot := {
  pid := slot.pid,
  current_generation := slot.current_generation + 1,
  active := true
}

/--
Theorem 29.1 (Audit Token Generation Monotonicity):
Respawning a process on the same PID strictly advances the kernel task generation counter.
-/
theorem audit_token_generation_monotonicity (slot : KernelTaskSlot) :
    (respawnProcessSlot slot).current_generation > slot.current_generation := by
  dsimp [respawnProcessSlot]
  omega

/--
Validate incoming IPC peer credentials against the current kernel process slot.
Accepts only if the token's generation matches the active process generation.
-/
def authenticatePeerToken (slot : KernelTaskSlot) (token : DarwinAuditToken) : Bool :=
  slot.active && (slot.pid == token.pid) && (slot.current_generation == token.generation_id)

/--
Theorem 29.2 (PID Reuse Spoofing Impossible):
A stale audit token minted under an earlier generation (`token.generation_id < slot.current_generation`)
is strictly rejected by `authenticatePeerToken`, even if the PID matches.
-/
theorem pid_reuse_spoofing_impossible
    (slot : KernelTaskSlot)
    (stale_token : DarwinAuditToken)
    (h_pid : slot.pid = stale_token.pid)
    (h_stale : stale_token.generation_id < slot.current_generation) :
    authenticatePeerToken slot stale_token = false := by
  simp_all [respawnProcessSlot, authenticatePeerToken] <;> omega

/-! # Multi-Respawn Generation Induction & Isolation Theorems -/

/-- Respawn a process slot `n` consecutive times. -/
def respawnProcessSlotN (slot : KernelTaskSlot) : Nat → KernelTaskSlot
  | 0 => slot
  | n + 1 => respawnProcessSlot (respawnProcessSlotN slot n)

/--
Theorem 29.3 (N-Fold Respawn Counter Addition):
Respawning `n` times increments the generation counter by exactly `n`.
-/
theorem respawn_n_generation_add (slot : KernelTaskSlot) (n : Nat) :
    (respawnProcessSlotN slot n).current_generation = slot.current_generation + n := by
  induction n with
  | zero =>
    dsimp [respawnProcessSlotN]
  | succ k ih =>
    dsimp [respawnProcessSlotN, respawnProcessSlot]
    rw [ih]
    omega

/--
Theorem 29.4 (Inactive Task Slot Rejection):
An inactive or terminated task slot rejects all peer tokens fail-closed.
-/
theorem inactive_slot_rejects_all
    (slot : KernelTaskSlot) (token : DarwinAuditToken)
    (h_inactive : slot.active = false) :
    authenticatePeerToken slot token = false := by
  dsimp [authenticatePeerToken]
  rw [h_inactive]
  rfl

/--
Theorem 29.5 (PID Mismatch Rejection):
A token with a mismatched PID is rejected even if the generation matches.
-/
theorem pid_mismatch_rejected
    (slot : KernelTaskSlot) (token : DarwinAuditToken)
    (h_pid_diff : slot.pid ≠ token.pid) :
    authenticatePeerToken slot token = false := by
  simp_all [respawnProcessSlot, authenticatePeerToken] <;> omega

/--
Theorem 29.6 (Authentic Active Token Unconditionally Accepted):
An active slot matching both PID and generation admits the peer token.
-/
theorem authentic_peer_token_admitted
    (slot : KernelTaskSlot) (token : DarwinAuditToken)
    (h_active : slot.active = true)
    (h_pid : slot.pid = token.pid)
    (h_gen : slot.current_generation = token.generation_id) :
    authenticatePeerToken slot token = true := by
  dsimp [authenticatePeerToken]
  have h_p_eq : (slot.pid == token.pid) = true := decide_eq_true h_pid
  have h_g_eq : (slot.current_generation == token.generation_id) = true := decide_eq_true h_gen
  rw [h_active, h_p_eq, h_g_eq]
  rfl

end Enclave
