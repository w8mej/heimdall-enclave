import Enclave.SnapshotBrokerProtocol

/-! Kernel-checked executable traces and arbitrary-history theorem consumers.
These model witnesses do not execute the Rust broker or any platform operation. -/
namespace EnclaveTest.SnapshotBrokerProtocol
open Enclave.SnapshotBrokerProtocol

def good : Admission := ⟨3, true, true, true, true, 7⟩
def begin : Event := .beginPublish good 1024 0 1
def published : List Event := [begin, .createSuccess, .saveOwnership, .markComplete, .finish]
def run := Enclave.Protocol.run step

theorem successful_publish_reopen_revoke_has_real_effects :
    let final := run (initial .absent) (published ++ [.reopen, .revoke])
    final.phase = .absent ∧ final.platform = .absent ∧
      final.effects = 3 ∧ final.lastDeleteAuthority = some 7 := by decide

theorem genuinely_idle_quiescence_survives_restart_and_publish :
    let final := run (initial .absent) [.quiesce, .crash, begin, .createSuccess]
    final.quiesced = true ∧ final.phase = .absent ∧ final.effects = 0 := by decide

theorem crash_after_intent_cannot_revoke_or_reopen :
    let cut := run (initial .absent) [begin, .crash]
    cut.phase = .intent ∧ cut.platform = .absent ∧
      step cut .revoke = none ∧ step cut .reopen = none := by decide

theorem crash_after_creation_does_not_invent_durable_ownership :
    let cut := run (initial .absent) [begin, .createSuccess, .crash]
    cut.phase = .intent ∧ cut.platform = .ours ∧ cut.effects = 1 ∧
      step cut .saveOwnership = none ∧ step cut .revoke = none := by decide

theorem known_owned_incomplete_restart_can_revoke_original_authority :
    let final := run (initial .absent)
      [begin, .createSuccess, .saveOwnership, .crash, .rotateAuthority 99 1, .revoke]
    final.phase = .absent ∧ final.effects = 2 ∧
      final.currentAuthority = 99 ∧ final.lastDeleteAuthority = some 7 := by decide

theorem foreign_eexist_is_not_a_deletion_grant :
    let final := run (initial .foreign) [begin, .foreignExists, .revoke]
    final.platform = .foreign ∧ final.phase = .absent ∧
      final.lastDeleteAuthority = none ∧ final.effects = 0 := by decide

theorem unknown_created_and_unknown_not_created_both_refuse_cleanup :
    let created := run (initial .absent) [begin, .createUnknown true, .crash]
    let absent := run (initial .absent) [begin, .createUnknown false, .crash]
    created.platform = .ours ∧ absent.platform = .absent ∧
      step created .revoke = none ∧ step absent .revoke = none := by decide

theorem save_failure_after_effect_poison_blocks_reopen_and_quiesce :
    let failed := run (initial .absent) [begin, .createSuccess, .saveFailure]
    failed.effects = 1 ∧ failed.phase = .intent ∧ failed.poisoned = true ∧
      step failed .saveOwnership = none ∧ step failed .reopen = none ∧
      step failed .quiesce = none ∧ step (run failed [.crash]) .revoke = none := by decide

theorem lost_reply_preserves_complete_retry_and_original_cleanup :
    let lost := run (initial .absent) [begin, .createSuccess, .saveOwnership, .markComplete, .loseReply]
    lost.phase = .complete ∧ step lost .reopen ≠ none ∧
      (run lost [.revoke]).lastDeleteAuthority = some 7 := by decide

theorem rotation_during_publication_blocks_completion_but_allows_owned_cleanup :
    let changed := run (initial .absent)
      [begin, .createSuccess, .saveOwnership, .rotateAuthority 9 1, .markComplete, .finish]
    changed.phase = .ownedIncomplete ∧ step changed .reopen = none ∧
      (run changed [.revoke]).lastDeleteAuthority = some 7 := by decide

theorem rotation_after_publication_blocks_reopen_but_not_cleanup :
    let changed := run (initial .absent) (published ++ [.rotateAuthority 9 1])
    changed.phase = .complete ∧ step changed .reopen = none ∧
      (run changed [.revoke]).lastDeleteAuthority = some 7 := by decide

theorem operation_lock_excludes_quiescence_during_publication :
    let active := run (initial .absent) [begin]
    active.busy = true ∧ step active .quiesce = none ∧
      (run active [.checkIdle]).quiesced = false := by decide

theorem diagnostic_idle_is_not_a_deployment_barrier :
    let checked := run (initial .absent) [.checkIdle]
    checked.quiesced = false ∧ step checked begin ≠ none := by decide

theorem oversized_state_refuses_before_intent_or_platform_effect :
    run (initial .absent) [.beginPublish good 33554433 0 1, .createSuccess] = initial .absent := by decide

theorem full_record_cap_and_excessive_root_chain_refuse :
    step (initial .absent) (.beginPublish good 1024 256 1) = none ∧
      step (initial .absent) (.beginPublish good 1024 0 33) = none := by decide

theorem exact_supported_bounds_have_a_success_path :
    step (initial .absent) (.beginPublish good 33554432 255 32) ≠ none := by decide

theorem l1_and_l2_cannot_dispatch_the_broker_publish_operation :
    step (initial .absent) (.beginPublish {good with profile := 1} 1024 0 1) = none ∧
      step (initial .absent) (.beginPublish {good with profile := 2} 1024 0 1) = none := by decide

theorem stale_identity_bad_framing_wrong_fd_and_bad_copy_refuse :
    step (initial .absent) (.beginPublish {good with authenticated := false} 1024 0 1) = none ∧
    step (initial .absent) (.beginPublish {good with framingValid := false} 1024 0 1) = none ∧
    step (initial .absent) (.beginPublish {good with descriptorValid := false} 1024 0 1) = none ∧
    step (initial .absent) (.beginPublish {good with copyVerified := false} 1024 0 1) = none := by decide

theorem stale_publisher_authority_and_tuf_rollback_refuse :
    let current := run (initial .absent) [.rotateAuthority 9 2]
    step current begin = none ∧ step current (.rotateAuthority 7 1) = none := by decide

theorem absent_revoke_is_idempotent : step (initial .absent) .revoke = some (initial .absent) := by decide

theorem every_history_preserves_owned_platform_consumer (events : List Event) :
    Safe (run (initial .absent) events) := arbitrary_history_owned_platform .absent events

theorem every_foreign_history_remains_unowned_consumer (events : List Event) :
    let final := run (initial .foreign) events
    final.platform = .foreign ∧ owned final.phase = false := foreign_eexist_never_owned events

theorem every_post_quiescence_history_has_no_effect_consumer (events : List Event) :
    run (run (initial .absent) [.quiesce]) events = run (initial .absent) [.quiesce] :=
  quiesced_no_later_effect _ events rfl

theorem expired_current_authority_blocks_reopen_but_preserves_cleanup :
    let expired := run (initial .absent) (published ++ [.invalidateAuthority])
    step expired .reopen = none ∧ (run expired [.revoke]).lastDeleteAuthority = some 7 := by decide

theorem every_history_preserves_tuf_high_water_consumer (s : State) (events : List Event) :
    s.tufFloor ≤ (run s events).tufFloor := arbitrary_history_tuf_floor_monotone s events

#print axioms arbitrary_history_owned_platform
#print axioms foreign_eexist_never_owned
#print axioms quiesced_no_later_effect
#print axioms state_overflow_precedes_effect_or_overwrite

end EnclaveTest.SnapshotBrokerProtocol
