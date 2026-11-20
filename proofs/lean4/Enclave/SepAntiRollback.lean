/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Secure Enclave (SEP) Monotonic Counter & Anti-Rollback Proofs
Normative Specification: FS-703 §5.2, ADR-010, & crates/enclave-core/src/seq.rs
-/

namespace Enclave

/-! # Secure Enclave Monotonic Epoch State -/

/--
Secure Enclave hardware-anchored anti-rollback state.
`hw_counter`: Monotonically increasing hardware counter maintained in SEP NVRAM.
`epoch_id`: Unique identifier of the current boot epoch.
`rpc_seq_watermark`: Highest sequence number authorized in this epoch.
-/
structure SepEpochState where
  hw_counter : Nat
  epoch_id : Nat
  rpc_seq_watermark : Nat
  deriving DecidableEq, Repr

/--
Operational Epoch Advancer:
Advances the enclave boot epoch by anchoring to a newly incremented Secure Enclave
hardware monotonic counter value.
Rejects any candidate counter that fails to strictly exceed the previous state.
-/
def advanceSepEpoch
    (st : SepEpochState)
    (candidate_hw_counter : Nat)
    (new_epoch_id : Nat) : Option SepEpochState :=
  if candidate_hw_counter > st.hw_counter then
    some { hw_counter := candidate_hw_counter,
           epoch_id := new_epoch_id,
           rpc_seq_watermark := 0 }
  else
    none

/--
Theorem 21.1 (SEP Counter Strictly Monotonic):
Any successful transition to a new boot epoch guarantees that the hardware monotonic
counter has advanced with a positive increment (`st'.hw_counter > st.hw_counter`).
-/
theorem sep_counter_strictly_monotonic
    (st st' : SepEpochState)
    (cand_counter new_epoch : Nat)
    (h_succ : advanceSepEpoch st cand_counter new_epoch = some st') :
    st'.hw_counter > st.hw_counter := by
  dsimp [advanceSepEpoch] at h_succ
  split at h_succ
  · rename_i h_gt
    injection h_succ with h_eq
    rw [← h_eq]
    exact h_gt
  · contradiction

/--
Theorem 21.2 (SEP Rollback Rejected):
Any attempt to rollback or restore state using a stale, equal, or decremented hardware
counter value (`candidate ≤ st.hw_counter`) is strictly rejected (`advanceSepEpoch = none`).
-/
theorem sep_rollback_rejected
    (st : SepEpochState)
    (candidate_hw_counter new_epoch : Nat)
    (h_rollback : candidate_hw_counter ≤ st.hw_counter) :
    advanceSepEpoch st candidate_hw_counter new_epoch = none := by
  simp_all [advanceSepEpoch]

/--
Theorem 21.3 (Epoch Advancement Requires SEP Increment):
It is mathematically impossible to obtain a valid advanced epoch state `st'` with
`st'.hw_counter ≤ st.hw_counter`.
-/
theorem epoch_advancement_requires_sep_increment
    (st st' : SepEpochState)
    (cand_counter new_epoch : Nat)
    (h_succ : advanceSepEpoch st cand_counter new_epoch = some st') :
    ¬(st'.hw_counter ≤ st.hw_counter) := by
  have h_mono := sep_counter_strictly_monotonic st st' cand_counter new_epoch h_succ
  exact Nat.not_le_of_gt h_mono

/-! # Intra-Epoch Sequence Watermarking & Multi-Step Transitivity -/

/-- Advance the RPC sequence watermark within the current epoch. -/
def advanceRpcWatermark (st : SepEpochState) (next_seq : Nat) : Option SepEpochState :=
  if next_seq = st.rpc_seq_watermark + 1 then
    some { st with rpc_seq_watermark := next_seq }
  else
    none

/--
Theorem 21.4 (RPC Watermark Monotonicity):
Advancing the RPC sequence within an epoch strictly increments the sequence watermark.
-/
theorem rpc_watermark_strictly_monotonic
    (st st' : SepEpochState) (next_seq : Nat)
    (h_step : advanceRpcWatermark st next_seq = some st') :
    st'.rpc_seq_watermark = st.rpc_seq_watermark + 1 := by
  dsimp [advanceRpcWatermark] at h_step
  split at h_step
  · cases h_step
    rename_i h_eq
    rw [h_eq]
  · contradiction

/--
Theorem 21.5 (Intra-Epoch Hardware Invariance):
Advancing the intra-epoch RPC watermark leaves the hardware monotonic counter unchanged.
-/
theorem intra_epoch_preserves_hardware_counter
    (st st' : SepEpochState) (next_seq : Nat)
    (h_step : advanceRpcWatermark st next_seq = some st') :
    st'.hw_counter = st.hw_counter := by
  dsimp [advanceRpcWatermark] at h_step
  split at h_step
  · cases h_step; rfl
  · contradiction

/--
Theorem 21.6 (Epoch Anti-Rollback Transitivity):
Chained epoch advancements strictly preserve counter increase transitively.
-/
theorem epoch_advance_trans
    (s1 s2 s3 : SepEpochState) (c1 e1 c2 e2 : Nat)
    (h12 : advanceSepEpoch s1 c1 e1 = some s2)
    (h23 : advanceSepEpoch s2 c2 e2 = some s3) :
    s3.hw_counter > s1.hw_counter := by
  have m12 := sep_counter_strictly_monotonic s1 s2 c1 e1 h12
  have m23 := sep_counter_strictly_monotonic s2 s3 c2 e2 h23
  exact Nat.lt_trans m12 m23

end Enclave
