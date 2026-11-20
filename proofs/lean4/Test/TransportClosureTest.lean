import Enclave.TransportClosure

/-! Finite kernel-reduced closure traces. The sum hash and digit check are
deliberately toy authentication fixtures, not cryptographic implementations. -/
namespace Enclave.TransportClosure.Tests
open Enclave.TransportClosure

def main : Target := ⟨9, 2, [3], false⟩
def companionA : Target := ⟨3, 2, [7], false⟩
def companionB : Target := ⟨7, 1, [], false⟩
def other : Target := ⟨5, 1, [], false⟩
def catalog : List Target := [main, companionA, companionB, other]
def limits : Limits := ⟨4, 4⟩
def hash : List Nat → Nat := List.sum
def check (_ : Target) (_ : Nat) (bytes : List Nat) : Bool := bytes.all (fun n => n ≤ 9)
def p (owner snapshot : Nat) (profile : Profile := .l2) : Plan :=
  ⟨owner, snapshot, main, [companionA, main], profile, requiredTransport profile⟩
def reserveMain (owner : Nat := 0) (profile : Profile := .l2) : Event :=
  .reserve owner main [companionA, main] profile (requiredTransport profile)
def staged : List Event :=
  [reserveMain, .chunk 0 3 [1], .chunk 0 3 [2], .seal 0 3 true,
    .chunk 0 9 [4, 5], .seal 0 9 true]
def effects : List Event := [.effect (p 0 0) 3, .effect (p 0 0) 9]
def run := trace limits catalog hash check

theorem actual_closure_is_direct_not_recursive :
    validSelection catalog main [companionA, main] .l2 ∧
    ¬validSelection catalog main [companionB, companionA, main] .l2 ∧
    7 ∉ directRoots main := by
  decide

theorem valid_multi_artifact_closure_reachable :
    let s := run {} (staged ++ effects ++ [.commit (p 0 0)])
    s.visible.length = 1 ∧ s.stages = [] ∧ s.plans = [] ∧
      totalBytes s = 0 ∧ ResourceBounds limits s ∧ VisibleValid catalog hash s := by
  decide

theorem partial_companion_does_not_publish_or_commit :
    let s := run {} [reserveMain, .chunk 0 3 [1, 2], .seal 0 3 true,
      .effect (p 0 0) 3, .commit (p 0 0)]
    s.visible = [] ∧ s.effects = [] ∧ totalBytes s = 2 := by
  decide

theorem staged_full_bytes_remain_private_before_commit :
    let s := run {} (staged ++ effects)
    s.visible = [] ∧ s.effects.length = 2 ∧ totalBytes s = 4 := by
  decide

theorem untrusted_chunk_rejected_before_staging :
    let s := run {} [reserveMain, .chunk 0 3 [99]]
    totalBytes s = 0 ∧ s.visible = [] := by
  decide

theorem bad_whole_content_never_seals :
    let s := run {} [reserveMain, .chunk 0 3 [2, 2], .seal 0 3 true]
    s.stages.all (fun a => !a.sealed) = true ∧ s.visible = [] := by
  decide

theorem truncated_input_and_false_eof_refused :
    let truncated := run {} [reserveMain, .chunk 0 3 [1], .seal 0 3 true]
    let noEOF := run {} [reserveMain, .chunk 0 3 [1, 2], .seal 0 3 false]
    truncated.stages.all (fun a => !a.sealed) = true ∧
      noEOF.stages.all (fun a => !a.sealed) = true := by
  decide

theorem overlength_chunk_has_no_staging_or_visibility_effect :
    let before := run {} [reserveMain]
    run before [.chunk 0 3 [1, 1, 1]] = before ∧ totalBytes before = 0 := by
  decide

theorem aggregate_quota_covers_concurrent_plans :
    let full := run {} staged
    let reserved := run full [.reserve 1 other [other] .l1 .registry]
    run reserved [.chunk 1 5 [5]] = reserved ∧ totalBytes reserved = 4 ∧
      reserved.plans.length = 2 := by
  decide

theorem per_artifact_limit_refuses_before_reservation :
    trace ⟨1, 100⟩ catalog hash check {} [reserveMain] = ({} : State) := by
  decide

theorem overlapping_roots_cannot_be_reserved_by_another_plan :
    let before := run {} [reserveMain]
    run before [reserveMain 1] = before ∧ before.nextPlan = 1 ∧
      before.stages.length = 2 := by
  decide

theorem stale_snapshot_cannot_create_effects :
    let s := run {} (staged ++ [.invalidate] ++ effects ++ [.commit (p 0 0)])
    s.effects = [] ∧ s.visible = [] ∧ s.snapshot = 1 := by
  decide

theorem invalidation_after_effects_refuses_commit_but_retains_cleanup_owner :
    let s := run {} (staged ++ effects ++ [.invalidate, .commit (p 0 0)])
    s.visible = [] ∧ s.effects.length = 2 ∧ s.plans.length = 1 ∧
      (run s [.rollback 0 true]).effects = [] := by
  decide

theorem failed_rollback_retains_owned_effects_and_reservations :
    let s := run {} (staged ++ effects)
    run s [.rollback 0 false] = s ∧ s.effects.length = 2 ∧ s.stages.length = 2 := by
  decide

theorem healthy_rollback_releases_quota_and_reservations :
    let s := run {} (staged ++ effects ++ [.rollback 0 true])
    s.effects = [] ∧ s.stages = [] ∧ s.plans = [] ∧ totalBytes s = 0 ∧ s.nextPlan = 1 := by
  decide

def otherPlan : Plan := ⟨1, 0, other, [other], .l1, .registry⟩

theorem rollback_preserves_foreign_committed_root :
    let committed := run {} (staged ++ effects ++ [.commit (p 0 0)])
    let s := run committed [.reserve 1 other [other] .l1 .registry, .chunk 1 5 [5],
      .seal 1 5 true, .effect otherPlan 5, .rollback 1 true]
    s.visible = committed.visible ∧ s.effects = committed.effects ∧
      s.visible.length = 1 ∧ s.effects.length = 2 := by
  decide

theorem no_l3_plain_registry_fallback :
    run {} [.reserve 0 main [companionA, main] .l3 .registry] = ({} : State) := by
  decide

theorem valid_l3_oblivious_reservation :
    let s := run {} [reserveMain 0 .l3]
    s.plans.length = 1 ∧ s.stages.length = 2 ∧ s.nextPlan = 1 := by
  decide

def empty : Target := ⟨0, 0, [], false⟩

theorem empty_encrypted_input_refused_but_l1_policy_preserved :
    ¬validSelection [empty] empty [empty] .l2 ∧
    ¬validSelection [empty] empty [empty] .l3 ∧
    validSelection [empty] empty [empty] .l1 := by
  decide

theorem unsigned_or_revoked_direct_companion_refused :
    ¬validSelection [main] main [companionA, main] .l2 ∧
    ¬validSelection [main, {companionA with revoked := true}] main
      [{companionA with revoked := true}, main] .l2 := by
  decide

theorem excessive_direct_companion_count_refused_before_deduplication :
    let many := {main with eager := List.replicate 16 3}
    ¬validSelection [many, companionA] many [companionA, many] .l2 := by
  decide

theorem permitted_duplicate_eager_roots_are_deduplicated :
    let many := {main with eager := List.replicate 15 3}
    validSelection [many, companionA] many [companionA, many] .l2 := by
  decide

theorem forged_plan_cannot_omit_a_required_companion :
    let forged := {(p 0 0) with targets := [main]}
    let s := run {} (staged ++ [.effect forged 9, .commit forged])
    s.effects = [] ∧ s.visible = [] := by
  decide

theorem signed_but_indirect_root_not_published_by_main_plan :
    let s := run {} (staged ++ [.effect (p 0 0) 7])
    s.effects = [] ∧ s.visible = [] := by
  decide

/-- Both metadata records are signed and name the same root. The shorter alias
still cannot replace the exact main_metadata appended by the source planner. -/
theorem signed_root_alias_cannot_replace_exact_main_metadata :
    let alias := {main with length := 1}
    let signed := alias :: catalog
    ¬validSelection signed main [companionA, alias] .l2 ∧
      trace limits signed hash check {}
        [.reserve 0 main [companionA, alias] .l2 .quic] = ({} : State) ∧
      validSelection signed main [companionA, main] .l2 := by
  decide

theorem valid_certificate_contains_actual_main_length :
    let s := run {} (staged ++ effects ++ [.commit (p 0 0)])
    s.visible.head?.map (fun c => c.artifacts.any (fun a => a.target == main && a.bytes.length == 2)) = some true := by
  decide

/-- Deliberate scope witness: declared lengths can exceed aggregateMax while
the actual retained staged-byte sum is zero. No source reservation proof. -/
theorem declared_lengths_are_not_the_modeled_staged_byte_bound :
    let s := trace ⟨4, 1⟩ catalog hash check {} [reserveMain]
    s.stages.length = 2 ∧ totalBytes s = 0 ∧
      (s.stages.map (fun a => a.target.length)).sum = 4 ∧ ResourceBounds ⟨4, 1⟩ s := by
  decide

end Enclave.TransportClosure.Tests
