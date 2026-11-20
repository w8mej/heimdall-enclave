import Enclave.TransportAdmission

/-! Kernel-reduced witnesses and adversarial traces for the bounded LAT-01 model.
`decide` checks closed propositions in Lean's kernel; no native_decide or FFI.
These are model traces, not observed executions or source refinement evidence. -/
namespace Enclave.TransportAdmission.Tests
open Enclave.TransportAdmission

def small : Limits := ⟨9, 2⟩
def boot : Nat := 17
def old : Epoch := ⟨boot, 0⟩
def fresh : Epoch := ⟨boot, 2⟩

def beginWipe (id : Nat) : List Event := [.reserve true id, .fence id, .advance id]
def finishWipe (id : Nat) : List Event :=
  [.enter id, .advanceLocked id, .cleanup id true, .journal id true, .drop id]
def failWipe (id : Nat) : List Event := [.enter id, .advanceLocked id, .cleanup id false, .drop id]

def observable (s : Cancellation) : Nat × Nat × Bool × Option Nat × List Nat :=
  (s.generation, s.pending, s.blocked, s.owner, s.guards)

theorem valid_wipe_and_fresh_retry :
    let s := trace small (initial boot) (beginWipe 1 ++ finishWipe 1)
    observable s = (2, 0, false, none, []) ∧ current small s fresh ∧ ¬current small s old := by
  decide

/-- Both begins happen before the first success: pending must still deny. -/
theorem overlapping_first_success_still_pending :
    let s := trace small (initial boot) (beginWipe 1 ++ beginWipe 2 ++ finishWipe 1)
    s.blocked = false ∧ s.pending = 1 ∧ s.generation = 3 ∧ ¬current small s ⟨boot, 3⟩ := by
  decide

/-- Regression for earlier success incorrectly clearing a later failure latch. -/
theorem overlap_success_then_failure_stays_blocked :
    let s := trace small (initial boot)
      (beginWipe 1 ++ beginWipe 2 ++ finishWipe 1 ++ failWipe 2)
    observable s = (4, 0, true, none, []) ∧ ¬current small s ⟨boot, 4⟩ := by
  decide

theorem healthy_authorized_retry_recovers :
    let s := trace small (initial boot)
      (beginWipe 1 ++ failWipe 1 ++ beginWipe 2 ++ finishWipe 2)
    observable s = (4, 0, false, none, []) ∧ current small s ⟨boot, 4⟩ := by
  decide

theorem journal_failure_after_cleanup_is_not_recovery :
    let s := trace small (initial boot)
      (beginWipe 1 ++ [.enter 1, .advanceLocked 1, .cleanup 1 true, .journal 1 false, .drop 1])
    observable s = (2, 0, true, none, []) := by
  decide

theorem journal_without_cleanup_is_rejected :
    let s := trace small (initial boot) (beginWipe 1 ++ [.enter 1])
    (step small s (.journal 1 true)).isNone = true ∧ s.blocked = true := by
  decide

theorem unauthorized_while_state_held_has_no_effect :
    let s := trace small (initial boot) (beginWipe 1 ++ [.enter 1])
    observable (trace small s [.reserve false 2]) = observable s ∧
      s.owner = some 1 ∧ s.pending = 1 := by
  decide

theorem pending_limit_and_duplicate_guard_refuse_without_leak :
    let s := trace small (initial boot) [.reserve true 1, .reserve true 2]
    observable (trace small s [.reserve true 3, .reserve true 1]) = observable s ∧
      s.pending = 2 := by
  decide

theorem exhausted_generation_drops_failed_begin_without_wrap :
    let s := trace ⟨0, 2⟩ (initial boot) (beginWipe 1)
    observable s = (0, 0, true, none, []) ∧
      ¬current ⟨0, 2⟩ s ⟨boot, 0⟩ := by
  decide

theorem exhausted_locked_advance_drops_guard_and_stays_blocked :
    let s := trace ⟨1, 2⟩ (initial boot)
      (beginWipe 1 ++ [.enter 1, .advanceLocked 1, .drop 1])
    observable s = (1, 0, true, none, []) ∧
      ¬current ⟨1, 2⟩ s ⟨boot, 1⟩ := by
  decide

theorem successful_second_advance_to_maximum_still_refuses_access :
    let s := trace ⟨2, 2⟩ (initial boot) (beginWipe 1 ++ finishWipe 1)
    observable s = (2, 0, false, none, []) ∧ ¬current ⟨2, 2⟩ s ⟨boot, 2⟩ := by
  decide

theorem checked_machine_bounds_are_u64_and_64bit_usize :
    machineLimits.generationMax = 18446744073709551615 ∧
      machineLimits.pendingMax = 18446744073709551615 := by
  decide

def releaseInitial (profile : Profile) : Release :=
  { cancellation := initial boot, profile }

def validateOld : List ReleaseEvent :=
  [.readGeneration, .readBlocked, .readPending, .validate old]

def fenceRelease : List ReleaseEvent :=
  [.wipe (.reserve true 1), .wipe (.fence 1), .wipe (.advance 1)]

/-- Legitimate current cache/receipt/FD path is reachable in each profile.
Profile-specific metadata, transport and custody gates are outside this model. -/
theorem legitimate_release_all_profiles (p : Profile) :
    let s := releaseTrace small (releaseInitial p)
      (validateOld ++ [.appendReceipt, .handlerReturn, .sendQueued])
    s.receipts = [old] ∧ s.sent = [old] ∧ s.profile = p := by
  cases p <;> decide

/-- Actual current contract COUNTEREXAMPLE: last validate returns, public Wipe
fences before State, then the handler appends its successful journal receipt. -/
theorem current_contract_receipt_after_fence_counterexample :
    let s := releaseTrace small (releaseInitial .l2)
      (validateOld ++ fenceRelease ++ [.appendReceipt])
    s.receipts = [old] ∧ s.cancellation.blocked = true ∧
      s.cancellation.generation = 1 ∧ ¬current small s.cancellation old := by
  decide

/-- Actual current contract COUNTEREXAMPLE: handler prepares/returns FDs, a Wipe
completes its fence, then IPC sends the already queued descriptor. No claim is
made that Wipe revokes a descriptor or mapping previously observed by a client. -/
theorem current_contract_queued_fd_after_wipe_counterexample :
    let s := releaseTrace small (releaseInitial .l3)
      (validateOld ++ [.handlerReturn] ++ fenceRelease ++ [.sendQueued])
    s.sent = [old] ∧ s.cancellation.blocked = true ∧
      ¬current small s.cancellation old := by
  decide

/-- The three loads do not become atomic merely because each is SeqCst. -/
theorem sampled_observe_can_finish_after_reservation_counterexample :
    let s := releaseTrace small (releaseInitial .l1)
      ([.readGeneration, .readBlocked, .readPending,
        .wipe (.reserve true 1), .validate old])
    s.checked = some old ∧ s.cancellation.pending = 1 ∧
      ¬current small s.cancellation old := by
  decide

theorem fresh_reads_reject_cancelled_cache_or_manual_epoch :
    let s := releaseTrace small (releaseInitial .l1)
      (fenceRelease ++ validateOld)
    s.checked = none ∧ s.receipts = [] ∧ s.sent = [] := by
  decide

theorem strengthened_contract_refuses_both_post_fence_effects :
    let s := releaseTrace small (releaseInitial .l3)
      (validateOld ++ fenceRelease ++ [.desiredCheckedReceipt old, .desiredCheckedSend old])
    s.receipts = [] ∧ s.sent = [] := by
  decide

theorem strengthened_contract_has_positive_release :
    let s := releaseTrace small (releaseInitial .l2)
      [.desiredCheckedReceipt old, .desiredCheckedSend old]
    s.receipts = [old] ∧ s.sent = [old] := by
  decide

/-- Equal numeric epochs from different live service instances are distinct. -/
theorem old_boot_does_not_reauthorize_after_restart :
    ¬current small (initial (boot+1)) old := by
  decide

end Enclave.TransportAdmission.Tests
