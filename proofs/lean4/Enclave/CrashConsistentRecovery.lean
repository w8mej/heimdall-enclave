/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Two-Phase SEP Hardware NVRAM / APFS Crash-Consistent Recovery
Normative Specification: FS-703 §6.2, ADR-010, & crates/enclave-core/src/seq.rs
-/

namespace Enclave

/-! # Two-Phase Hardware/Filesystem Epoch Commit Protocol -/

/-- Transaction progress stages during an epoch advance. -/
inductive EpochCommitPhase where
  | Unstarted : EpochCommitPhase
  | SepNvramIncremented : EpochCommitPhase
  | ApfsWalFlushed : EpochCommitPhase
  | CommittedTerminal : EpochCommitPhase
  deriving DecidableEq, Repr

/-- State recorded across hardware NVRAM and on-disk journal at time of crash. -/
structure CrashSnapshot where
  phase : EpochCommitPhase
  previous_epoch : Nat
  proposed_epoch : Nat
  deriving DecidableEq, Repr

/-- Recovery procedure executed upon system reboot following an unclean crash. -/
def recoverEpochState (snap : CrashSnapshot) : Nat :=
  match snap.phase with
  | EpochCommitPhase.CommittedTerminal => snap.proposed_epoch
  | EpochCommitPhase.ApfsWalFlushed    => snap.proposed_epoch
  | EpochCommitPhase.SepNvramIncremented => snap.previous_epoch
  | EpochCommitPhase.Unstarted          => snap.previous_epoch

/--
Theorem 40.1 (Two-Phase Epoch Atomicity):
For any crash snapshot across any stage of the commit protocol, the recovered epoch
is deterministically either the initial previous epoch (safe rollback) or the
proposed new epoch (safe forward-roll). It is never undefined or corrupted.
-/
theorem two_phase_epoch_atomicity (snap : CrashSnapshot) :
    recoverEpochState snap = snap.previous_epoch ∨ recoverEpochState snap = snap.proposed_epoch := by
  cases h : snap.phase <;> simp_all [recoverEpochState]

/--
Theorem 40.2 (Zero Intermediate Corruption):
An incomplete commit where only the hardware NVRAM counter was bumped but the APFS WAL
was not yet flushed safely rolls back to the verified previous epoch.
-/
theorem rollback_unflushed_hardware_increment
    (snap : CrashSnapshot)
    (h_phase : snap.phase = EpochCommitPhase.SepNvramIncremented) :
    recoverEpochState snap = snap.previous_epoch := by
  dsimp [recoverEpochState]
  rw [h_phase]

/-! # Two-Phase Commit State Transition System & Monotonicity -/

/-- Permitted state transitions in the two-phase commit protocol. -/
inductive CommitTransition : EpochCommitPhase → EpochCommitPhase → Prop where
  | start : CommitTransition EpochCommitPhase.Unstarted EpochCommitPhase.SepNvramIncremented
  | flushWal : CommitTransition EpochCommitPhase.SepNvramIncremented EpochCommitPhase.ApfsWalFlushed
  | finalize : CommitTransition EpochCommitPhase.ApfsWalFlushed EpochCommitPhase.CommittedTerminal

/--
Theorem 40.3 (Forward Roll on Flushed WAL):
A crash occurring after APFS WAL flush strictly rolls forward to the proposed epoch.
-/
theorem roll_forward_flushed_wal
    (snap : CrashSnapshot)
    (h_phase : snap.phase = EpochCommitPhase.ApfsWalFlushed) :
    recoverEpochState snap = snap.proposed_epoch := by
  dsimp [recoverEpochState]
  rw [h_phase]

/--
Theorem 40.4 (Forward Roll on Committed Terminal):
A crash in the terminal committed state retains the proposed epoch.
-/
theorem roll_forward_committed_terminal
    (snap : CrashSnapshot)
    (h_phase : snap.phase = EpochCommitPhase.CommittedTerminal) :
    recoverEpochState snap = snap.proposed_epoch := by
  dsimp [recoverEpochState]
  rw [h_phase]

/--
Theorem 40.5 (Epoch Monotonicity Under Recovery):
Assuming `proposed_epoch ≥ previous_epoch`, recovery guarantees that the recovered
epoch is at least as large as the previous epoch (anti-rollback invariance).
-/
theorem recovery_anti_rollback
    (snap : CrashSnapshot)
    (h_mono : snap.proposed_epoch ≥ snap.previous_epoch) :
    recoverEpochState snap ≥ snap.previous_epoch := by
  cases h : snap.phase <;> simp_all [recoverEpochState]

/--
Theorem 40.6 (Crash on Unstarted Commit Preserves Previous Epoch):
If no commit phase began before crash, recovery returns the previous epoch identically.
-/
theorem rollback_unstarted
    (snap : CrashSnapshot)
    (h_phase : snap.phase = EpochCommitPhase.Unstarted) :
    recoverEpochState snap = snap.previous_epoch := by
  dsimp [recoverEpochState]
  rw [h_phase]

end Enclave
