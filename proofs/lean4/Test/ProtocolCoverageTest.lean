import Enclave

/-! Adversarial regressions and universally quantified test consumers. Every
example is elaborated as a kernel theorem (no native_decide or runtime assert). -/
namespace EnclaveTest.ProtocolCoverage

set_option maxRecDepth 10000
set_option exponentiation.threshold 12001

open scoped BigOperators

open Enclave

theorem ticket_field_boundary_separation :
    Tickets.encodeFields ⟨[],[97,98],[99],[],0,0,1⟩ ≠
      Tickets.encodeFields ⟨[],[97],[98,99],[],0,0,1⟩ := by decide

theorem ticket_module_presence_is_signed :
    Tickets.signingBytes ⟨⟨[],[],[],[],0,0,1⟩,none,false⟩ ≠
      Tickets.signingBytes ⟨⟨[],[],[],[],0,0,1⟩,some (List.replicate 32 0),false⟩ := by decide

theorem ticket_live_replay_survives_capacity_pressure :
    Tickets.consume ⟨[(7,100)],0,1⟩ 7 100 100 = none := by decide

theorem delegation_negative_slice_rejected :
    DelegationProtocol.signedSlice 0 (-1) 100 = false := by decide

theorem delegation_overspend_rejected :
    DelegationProtocol.step ⟨[5],0,0⟩ (.spend [] [] 5 6) = none := by decide

theorem delegation_arbitrary_trace_conserves (s : DelegationProtocol.State)
    (es : List DelegationProtocol.Event) :
    DelegationProtocol.total (Protocol.run DelegationProtocol.step s es) =
      DelegationProtocol.total s := DelegationProtocol.trace_conserves s es

theorem released_capability_unusable (h : Capabilities.Heap) (ids : List Nat)
    (id epoch turn : Nat) (p : Capabilities.Value) (hi : id ∈ ids) :
    Capabilities.resolve (Capabilities.release h ids) id epoch turn p = none :=
  Capabilities.released_unresolvable h ids id epoch turn p hi

theorem plan_bad_condition_rejected :
    PlanSafety.check (.ite (.num 1) (.num 2) (.num 3)) = none := by decide

theorem plan_checked_fragment_progress (e : PlanSafety.Expr) (t : PlanSafety.Ty)
    (h : PlanSafety.check e = some t) :
    ∃ v, PlanSafety.eval e = some v ∧ PlanSafety.valueType v = t :=
  PlanSafety.checker_progress_preservation e t h

theorem plan_loop_seventeen_rejected :
    PlanSafety.bounded (.repeat 17 (.emit 1)) = false := by decide

theorem two_secret_stores_same_observations (c : TraceIFC.Command) (a b : TraceIFC.Store)
    (h : a.public = b.public) : (TraceIFC.execute c a).2 = (TraceIFC.execute c b).2 :=
  (TraceIFC.two_run_noninterference c a b h).2

theorem secret_condition_is_rejected :
    TraceIFC.check (.branch true 0 (.emit 0) (.emit 1)) = none := rfl

theorem checked_raw_language_two_run (r : TraceIFC.Raw) (c : TraceIFC.Command)
    (h : TraceIFC.check r = some c) (a b : TraceIFC.Store) (low : a.public=b.public) :
    (TraceIFC.rawExecute r a).2 = (TraceIFC.rawExecute r b).2 :=
  (TraceIFC.accepted_raw_trace_noninterference r c h a b low).2

theorem policy_forbid_overrides_token :
    Authorization.authorize [fun _ => true] [fun _ => true]
      [⟨[1],10,10,100⟩] ⟨1,1,1,0⟩ = false := by decide

theorem empty_token_never_authorizes :
    Authorization.tokenAllows [] ⟨1,0,0,0⟩ = false := by decide

theorem expired_policy_grace_rejected :
    Authorization.bundleAccepted ⟨2,some 1,0⟩ 1 60000000001 = false := by decide

theorem dpop_extreme_timestamp_rejected :
    DpopProtocol.fresh 0 (-9223372036854775808) 60 = false := by decide

theorem dpop_cross_method_rejected :
    DpopProtocol.verify (fun _ => true) ⟨[71],[],[],none⟩ 0 60
      ⟨⟨[80],[],[],none⟩,1,0⟩ = false := by decide

theorem tuf_duplicate_signatures_not_quorum :
    TufProtocol.threshold [1,2] [1,1,1] 2 = false := by decide

theorem tuf_equal_version_changed_body_rejected :
    TufProtocol.update ⟨3,[1],100⟩ ⟨3,[2],100⟩ 0 = none := by decide

theorem tuf_new_key_only_cannot_rotate :
    TufProtocol.rotate ⟨1,[],100⟩ ⟨2,[],100⟩ [1] [2] [2] 1 1 0 = none := by decide

theorem ledger_crash_drops_unacknowledged_pending :
    Protocol.run LedgerProtocol.step ⟨[],[],0⟩ [.append 9,.crash] = ⟨[],[],0⟩ := by decide

theorem ledger_sync_ack_crash_preserves_record :
    Protocol.run LedgerProtocol.step ⟨[],[],0⟩ [.append 9,.sync,.acknowledge,.crash] =
      ⟨[9],[],1⟩ := by decide

theorem ledger_anchor_detects_truncation :
    LedgerProtocol.anchorAccepts 2 [9] = false := by decide

theorem artifact_missing_companion_denied :
    ArtifactProtocol.publish List.length [⟨1,1,1,1,[7],false⟩]
      ⟨1,1,1,1,[7],false⟩ [1] [] 1 1 = none := by decide

theorem artifact_signed_classification_floor_preserved :
    (ArtifactProtocol.publish List.length [⟨1,1,1,3,[],false⟩]
      ⟨1,1,1,3,[],false⟩ [1] [] 1 1).map ArtifactProtocol.Published.profile = some 3 := by decide

theorem lifecycle_delayed_output_after_cancel_denied :
    Protocol.run Lifecycle.step ⟨4,true,[]⟩ [.cancel,.publish 4 99] = ⟨5,false,[]⟩ := by decide

theorem custody_missing_approval_denied :
    CustodyProtocol.step (fun _ => true) ⟨⟨[1],1,1,100,[1,2]⟩,[],.pending⟩
      (.release ⟨[1],1,1,100,[1,2]⟩ 0) = none := by decide

theorem custody_other_session_approval_denied :
    CustodyProtocol.step (fun _ => true) ⟨⟨[1],1,1,100,[1]⟩,[],.pending⟩
      (.approve ⟨⟨[1],2,1,100,[1]⟩,1,7⟩) = none := by decide

theorem egress_epoch_cannot_be_substituted :
    EgressProtocol.mayTombstone ⟨[(1,7)],[]⟩ (2,7) = false := by decide

theorem egress_release_blocks_tombstone :
    EgressProtocol.mayTombstone ⟨[(1,7)],[(1,7)]⟩ (1,7) = false := by decide

theorem qif_normalized_nonuniform_prior :
    NormalizedQif.normalized ⟨[1,3],4⟩ = true := by decide

theorem qif_unnormalized_prior_rejected :
    NormalizedQif.normalized ⟨[1,3],3⟩ = false := by decide

theorem qif_revealing_channel_bayes_numerator :
    NormalizedQif.posteriorNumerator [1,3] [[1,0],[0,1]] = 4 := by decide

theorem adaptive_probability_is_normalized {n m depth : Nat} [NeZero n]
    (s : AdaptiveQif.Strategy n m depth) (h : AdaptiveQif.valid s)
    (p : AdaptiveQif.Weights n) (hp : ∑ x, p x = 1) : AdaptiveQif.mass s p = 1 := by
  rw [AdaptiveQif.adaptive_channel_preserves_probability s h p, hp]

theorem adaptive_observation_dependent_bayes_bound {n m depth : Nat} [NeZero n]
    (s : AdaptiveQif.Strategy n m depth) (h : AdaptiveQif.valid s)
    (p : AdaptiveQif.Weights n) (hp : ∀ x, 0 ≤ p x) :
    AdaptiveQif.posterior s p ≤ (m:ℚ)^depth * AdaptiveQif.vulnerability p :=
  AdaptiveQif.adaptive_bayes_cardinality_bound s h p hp

theorem dag_unknown_parent_rejected : DagProtocol.add [] [0] 0 [] = none := by decide

theorem dag_taint_laundering_rejected :
    DagProtocol.add [⟨[],3,[]⟩] [0] 1 [] = none := by decide

theorem automaton_chunk_boundaries_irrelevant (δ : AutomataProtocol.Transition)
    (q : Nat) (xs ys : List Nat) :
    AutomataProtocol.run δ q (xs++ys) =
      (AutomataProtocol.run δ q xs).bind (fun r => AutomataProtocol.run δ r ys) :=
  AutomataProtocol.streaming_batch_equivalent δ q xs ys

theorem ipc_oversize_reservation_denied :
    IpcProtocol.reserve [] ⟨1,701,1048577⟩ 1048576 16 4 = none := by decide

theorem ipc_slow_partial_read_cannot_reset_deadline :
    IpcProtocol.readChunk ⟨0,30,1,100⟩ 31 1 = none := by decide

theorem merkle_padding_index_denied : MerkleProtocol.canonical 40 40 6 = false := by decide

theorem merkle_noncanonical_extra_depth_denied :
    MerkleProtocol.canonical 40 0 7 = false := by decide

theorem air_slack_counterexample_is_real :
    EpochAirArithmetic.slackEquation 12000 (EpochAirArithmetic.modulus-1) 12001 = true ∧
      EpochAirArithmetic.modulus-1 > 12000 :=
  EpochAirArithmetic.slack_only_allows_out_of_range_used

theorem air_range_repair_prevents_wrap (c u s : Nat) (hc : c<16384) (hu : u<16384)
    (hs : s<16384) (h : EpochAirArithmetic.slackEquation c u s = true) : u≤c :=
  EpochAirArithmetic.range_equation_no_wrap c u s hc hu hs h

theorem actual_extracted_air_enforces_cap (e : EpochAirExtracted.Env)
    (h : EpochAirExtracted.satisfies e) : (e.main 0 5).val ≤ (e.public 1).val :=
  EpochAirCorrespondence.actual_epoch_constraints_enforce_used_cap e h

theorem pf_ipv6_remote_destination_blocked :
    PacketPolicy.evaluate PacketPolicy.anchor ⟨.ipv6,true,true,true,false,true,8443⟩ .pass =
      .block := by decide

theorem pf_ipv6_inference_allowed :
    PacketPolicy.evaluate PacketPolicy.anchor ⟨.ipv6,true,true,true,true,true,11434⟩ .block =
      .pass := by decide

theorem heap_rejection_still_burns_name :
    HeapAccounting.step ⟨[],0,7,0⟩
      (.allocate ⟨[1],⟨.C1,.T1⟩,1,1⟩) = some ⟨[],0,8,0⟩ := by decide

theorem heap_histories_preserve_accounting (cap : Nat) (events : List HeapAccounting.Event) :
    HeapAccounting.Invariant (Protocol.run HeapAccounting.step ⟨[],0,0,cap⟩ events) :=
  HeapAccounting.arbitrary_heap_history_accounted cap events

theorem heap_exhausted_name_is_denied :
    HeapAccounting.step ⟨[],0,18446744073709551615,8⟩
      (.allocate ⟨[],⟨.C1,.T1⟩,1,1⟩) = none := by decide

theorem constructed_dag_invariant_needs_no_edge_assumption (events : List DagProtocol.BuildEvent) :
    DagProtocol.WellFormed (Protocol.run DagProtocol.buildStep [] events) :=
  DagProtocol.constructed_graph_well_formed events

theorem ipc_entire_history_bounded_for_every_uid (limits : IpcProtocol.Limits)
    (events : List IpcProtocol.Event) :
    IpcProtocol.WithinLimits limits (Protocol.run (IpcProtocol.step limits) [] events) :=
  IpcProtocol.arbitrary_resource_history_bounded limits events

theorem ipc_duplicate_connection_does_not_double_charge :
    Protocol.run (IpcProtocol.step ⟨10,2,2⟩) []
      [.acquire ⟨1,701,4⟩,.acquire ⟨1,701,4⟩] = [⟨1,701,4⟩] := by decide

theorem merkle_bottom_up_direction_is_index_bound :
    MerkleProtocol.bottomPath 5 [10,11,12] = [(true,10),(false,11),(true,12)] := by decide

theorem merkle_bottom_up_reconstruction (compress : Nat → Nat → Nat)
    (siblings : List Nat) (index value : Nat) :
    MerkleProtocol.bottomUp compress value index siblings =
      MerkleProtocol.rebuild compress value (MerkleProtocol.bottomPath index siblings).reverse :=
  MerkleProtocol.bottom_up_matches_reversed_path compress siblings index value

theorem schema_padding_cycle_accepts :
    (SchemaAutomata.finiteRun SchemaAutomata.paddingDfa 0 [0,0,0]).any
      SchemaAutomata.paddingDfa.accepting = true := by decide

theorem schema_padding_rejects_nonzero :
    (SchemaAutomata.finiteRun SchemaAutomata.paddingDfa 0 [0,1,0]).any
      SchemaAutomata.paddingDfa.accepting = false := by decide

def forgedSchemaDfa : SchemaAutomata.FiniteDfa 1 where
  next := fun q _ => some q
  accepting := fun _ => true
  residual := fun _ => .eps

theorem schema_forged_certificate_is_rejected :
    SchemaAutomata.checkCertificate forgedSchemaDfa = false := by decide

theorem custody_l1_a4_oidc_is_not_a_hardware_profile_subset :
    6 ∈ CustodyLifecycle.factors 1 4 false ∧
      6 ∉ CustodyLifecycle.factors 2 4 false := by decide

theorem custody_l3_a4_complete_matrix :
    CustodyLifecycle.factors 3 4 true = [0,1,2,3,4,5,7] := by decide

theorem custody_caller_cannot_remove_required_factors :
    CustodyLifecycle.release (fun _ => true) ⟨⟨[1],1,1,100,[]⟩,[],.pending⟩
      3 4 false ⟨[1],1,1,100,[]⟩ 0 = none := by decide

theorem custody_revocation_wipes_live_lease :
    ((CustodyLifecycle.leaseStep
      (CustodyLifecycle.grant [] ⟨1,2,[3]⟩ 0) .lock).getD []).isEmpty = true := by decide

theorem custody_other_token_cannot_reuse_lease :
    CustodyLifecycle.valid (CustodyLifecycle.grant [] ⟨1,2,[3]⟩ 0) ⟨1,2,[4]⟩ 1 = false := by decide

theorem fractional_every_arity_is_priced_safely (arity : Nat) :
    arity^1000≤2^(FractionalQif.price arity) :=
  FractionalQif.exact_price_never_undercharges arity

theorem fractional_pricing_is_the_least_safe_charge (arity charge : Nat)
    (safe : arity^1000≤2^charge) : FractionalQif.price arity≤charge :=
  FractionalQif.exact_price_is_minimal arity charge safe

theorem fractional_composition_obeys_real_budget (arities : List Nat)
    (budget : (arities.map FractionalQif.price).sum≤12000) : arities.prod≤4096 :=
  FractionalQif.fractional_budget_implies_4096_bound arities budget

theorem actual_trace_sum_and_cap (rows : Nat → Nat → FieldRangeProofs.F)
    (public : Nat → FieldRangeProofs.F) (last : Nat)
    (valid : EpochAirCorrespondence.ValidTrace rows public last)
    (inputRange : (public 2).val<16384) :
    (public 3).val = (public 2).val +
      ((List.range (last+1)).map (fun j => (rows j 4).val)).sum ∧
    (public 3).val≤(public 1).val :=
  EpochAirCorrespondence.actual_epoch_full_integer_accounting rows public last valid inputRange

/-- One observation terminates; the other chooses a four-outcome query.
Checking only the cheapest branch would accept the insufficient 1,000 budget. -/
def unequalQueryTree : AdaptiveBudget.Shape :=
  .query 2 (fun y => if y.val=0 then .leaf else .query 4 (fun _ => .leaf))

theorem exact_binary_price : FractionalQif.price 2=1000 := by
  simpa using FractionalQif.power_of_two_exact_charge 1

theorem exact_four_outcome_price : FractionalQif.price 4=2000 := by
  simpa using FractionalQif.power_of_two_exact_charge 2

theorem adaptive_unequal_branch_transcript_count :
    AdaptiveBudget.leaves unequalQueryTree = 5 := by decide

theorem adaptive_unequal_branch_exact_budget_accepted :
    AdaptiveBudget.priced unequalQueryTree 3000 := by
  simp [unequalQueryTree, AdaptiveBudget.priced, Fin.forall_fin_succ,
    exact_binary_price, exact_four_outcome_price]

theorem adaptive_unequal_branch_undercharge_rejected :
    ¬ AdaptiveBudget.priced unequalQueryTree 2999 := by
  simp [unequalQueryTree, AdaptiveBudget.priced, Fin.forall_fin_succ,
    exact_binary_price, exact_four_outcome_price]

theorem adaptive_cheapest_branch_cannot_hide_expensive_branch :
    ¬ AdaptiveBudget.priced unequalQueryTree 1000 := by
  simp [unequalQueryTree, AdaptiveBudget.priced, Fin.forall_fin_succ,
    exact_binary_price, exact_four_outcome_price]

theorem variable_arity_strategy_preserves_actual_probability {n : Nat}
    (s : AdaptiveBudget.Strategy n) (h : AdaptiveBudget.valid s)
    (p : AdaptiveQif.Weights n) (prior : ∑ x, p x=1) :
    AdaptiveBudget.mass s p=1 := by
  rw [AdaptiveBudget.variable_arity_channel_preserves_probability s h p, prior]

theorem variable_arity_strategy_respects_real_budget {n : Nat} [NeZero n]
    (s : AdaptiveBudget.Strategy n) (h : AdaptiveBudget.valid s)
    (p : AdaptiveQif.Weights n) (nonnegative : ∀ x, 0≤p x)
    (budget : AdaptiveBudget.priced (AdaptiveBudget.shape s) 12000) :
    AdaptiveBudget.posterior s p≤4096*AdaptiveQif.vulnerability p :=
  AdaptiveBudget.adaptive_fractional_12000_budget_bayes_bound s h budget p nonnegative

def exhaustedRollingBucket : RollingQif.State := ⟨fun _ => [(100,12000)],100⟩

theorem rolling_exact_window_boundary_releases_budget :
    (RollingQif.charge (fun _ => 12000) exhaustedRollingBucket
      ⟨[0],1000,100+RollingQif.window⟩).2=true := by decide

theorem rolling_millisecond_before_boundary_still_denies :
    (RollingQif.charge (fun _ => 12000) exhaustedRollingBucket
      ⟨[0],1000,99+RollingQif.window⟩).2=false := by decide

theorem rolling_time_rollback_cannot_refund :
    (RollingQif.charge (fun _ => 12000) exhaustedRollingBucket ⟨[0],1,0⟩).2=false := by decide

theorem rolling_second_entity_denial_never_debits_first :
    let initial : RollingQif.State := ⟨fun key => if key=1 then [(0,12000)] else [],0⟩
    RollingQif.used ((RollingQif.charge (fun _ => 12000) initial ⟨[0,1],1,1⟩).1.buckets 0)=0 :=
  by decide

theorem rolling_every_history_enforces_caps (caps : Nat → Nat) (events : List RollingQif.Charge) :
    RollingQif.Bounded caps
      (Protocol.run (RollingQif.step caps) ⟨fun _ => [],0⟩ events) :=
  RollingQif.arbitrary_rolling_history_bounded caps events

theorem artifact_unsigned_companion_bytes_rejected :
    ArtifactProtocol.publishWithCompanions List.length [⟨1,1,1,1,[2],false⟩]
      ⟨1,1,1,1,[2],false⟩ [1] [⟨⟨2,2,1,1,[],false⟩,[7,8]⟩] 1 1 = none := by decide

theorem artifact_companion_with_wrong_content_length_rejected :
    ArtifactProtocol.publishWithCompanions List.sum
      [⟨1,1,1,1,[2],false⟩,⟨2,2,1,1,[],false⟩]
      ⟨1,1,1,1,[2],false⟩ [1] [⟨⟨2,2,1,1,[],false⟩,[2]⟩] 1 1 = none := by decide

theorem artifact_companion_with_wrong_digest_rejected :
    ArtifactProtocol.publishWithCompanions List.sum
      [⟨1,1,1,1,[2],false⟩,⟨2,2,1,1,[],false⟩]
      ⟨1,1,1,1,[2],false⟩ [1] [⟨⟨2,2,1,1,[],false⟩,[1,2]⟩] 1 1 = none := by decide

theorem artifact_authenticated_companion_has_a_live_success_path :
    (ArtifactProtocol.publishWithCompanions List.sum
      [⟨1,1,1,1,[2],false⟩,⟨2,2,1,1,[],false⟩]
      ⟨1,1,1,1,[2],false⟩ [1] [⟨⟨2,2,1,1,[],false⟩,[1,1]⟩] 1 1).isSome=true := by decide

theorem artifact_crashed_staging_never_becomes_visible :
    (Protocol.run (ArtifactProtocol.storeStep List.length [⟨1,1,1,1,[],false⟩])
      ⟨none,[]⟩ [.stage ⟨⟨1,1,1,1,[],false⟩,[1],[],1,1⟩,.crash,.install]).visible=[] := by decide

theorem artifact_installed_bytes_survive_later_staging_crash :
    (Protocol.run (ArtifactProtocol.storeStep List.length [⟨1,1,1,1,[],false⟩])
      ⟨none,[]⟩ [.stage ⟨⟨1,1,1,1,[],false⟩,[1],[],1,1⟩,.install,.crash]).visible=
      [⟨[1],1,⟨1,1,1,1,[],false⟩⟩] := by decide

theorem rolling_unsorted_bucket_would_break_prefix_filter_equivalence :
    RollingQifRefinement.prefixPrune [(86400000,1),(0,2)] 86400000≠
      RollingQif.prune [(86400000,1),(0,2)] 86400000 := by decide

theorem rolling_native_lazy_storage_preserves_unvisited_expired_entries :
    let s : RollingQif.State := ⟨fun _ => [(0,12000)],0⟩
    ((RollingQifRefinement.nativeCharge (fun _ => 12000) s
      ⟨[0],1,86400000⟩).1.buckets 1)=[(0,12000)] := by decide

theorem rolling_native_failure_can_prune_earlier_keys_without_debit :
    let s : RollingQif.State := ⟨fun _ => [(0,12000)],0⟩
    let caps : Nat → Nat := fun key => if key=0 then 12000 else 0
    let result := RollingQifRefinement.nativeCharge caps s ⟨[0,1],1,86400000⟩
    result.2=false ∧ result.1.buckets 0=[] := by decide

theorem rolling_native_all_histories_refine_the_abstract_ledger
    (caps : Nat → Nat) (events : List RollingQif.Charge) :
    RollingQifRefinement.project
      (Protocol.run (RollingQifRefinement.nativeStep caps) ⟨fun _ => [],0⟩ events)=
      Protocol.run (RollingQif.step caps) ⟨fun _ => [],0⟩ events := by
  exact RollingQifRefinement.arbitrary_native_history_refines_eager_history caps
    ⟨fun _ => [],0⟩ events (by
      simp [RollingQifRefinement.WellFormed,RollingQifRefinement.Ordered,
        RollingQifRefinement.chronological,RollingQifRefinement.Entries])

theorem adaptive_executable_budget_monitor_derives_security {n : Nat} [NeZero n]
    (program : AdaptiveBudget.Strategy n) (kernels : AdaptiveBudget.valid program)
    (prior : AdaptiveQif.Weights n) (nonnegative : ∀ x, 0≤prior x) :
    AdaptiveBudget.posterior (AdaptiveBudget.enforce program 12000) prior≤
      4096*AdaptiveQif.vulnerability prior :=
  AdaptiveBudget.executable_monitor_enforces_adaptive_bayes_bound program kernels prior nonnegative

theorem actual_lazy_settlement_composes_with_adaptive_queries {n : Nat} [NeZero n]
    (caps : Nat → Nat) (start finish key : Nat) (inside : finish<start+RollingQif.window)
    (capBound : caps key≤12000) (program : RollingAdaptiveComposition.Program n)
    (kernels : RollingAdaptiveComposition.valid program)
    (s : RollingQif.State) (validState : RollingQifRefinement.WellFormed s)
    (prior : AdaptiveQif.Weights n) (nonnegative : ∀ x, 0≤prior x) :
    AdaptiveBudget.posterior (RollingAdaptiveComposition.execute caps start finish key program s) prior≤
      4096*AdaptiveQif.vulnerability prior :=
  RollingAdaptiveComposition.rolling_settlement_enforces_adaptive_bayes_bound caps start finish key
    inside capBound program kernels s validState prior nonnegative

theorem delegation_repeated_spending_is_cumulative :
    let start : DelegationAccounting.State := ⟨[⟨1,1,0,2000,0,0⟩],fun _ => 0,2000⟩
    let final := Protocol.run DelegationAccounting.step start
      [.call [] [] ⟨1,1,0,2000,0,0⟩ 1000,
       .call [] [] ⟨1,1,0,2000,0,1000⟩ 1000,
       .call [] [] ⟨1,1,0,2000,0,2000⟩ 1]
    final.nodes=[⟨1,1,0,2000,0,2000⟩] ∧ final.calls 1=2 := by decide

theorem delegation_failed_attenuation_never_reserves_budget :
    (DelegationAccounting.step ⟨[⟨1,1,0,4000,0,0⟩],fun _ => 0,4000⟩
      (.spawn [] [] ⟨1,1,0,4000,0,0⟩ 2 4000 false)).isNone=true := by decide

theorem delegation_parent_cannot_spend_a_delegated_slice :
    (DelegationAccounting.step
      ⟨[⟨1,1,0,4000,3000,1000⟩,⟨2,1,1,3000,0,0⟩],fun _ => 0,4000⟩
      (.call [] [⟨2,1,1,3000,0,0⟩] ⟨1,1,0,4000,3000,1000⟩ 1)).isNone=true := by decide

theorem delegation_each_tree_has_its_own_conservation_bound
    (events : List DelegationAccounting.Event) (root : Nat) :
    ((Protocol.run DelegationAccounting.step ⟨[],fun _ => 0,0⟩ events).nodes.map
      (DelegationAccounting.scopedSpent root)).sum≤
      DelegationAccounting.successfulGrants root ⟨[],fun _ => 0,0⟩ events :=
  DelegationAccounting.cumulative_spent_of_each_tree_is_bounded events root

theorem repeated_entity_is_charged_once :
    RollingKeyNormalization.pushLoop (fun _ => []) 7 1000
      (RollingKeyNormalization.keys [1,2,1,2,1] 0 true) 1=[(7,1000)] := by decide

theorem pool_and_entities_each_charged_once :
    RollingKeyNormalization.pushLoop (fun _ => []) 7 1000
      (RollingKeyNormalization.keys [1,1] 0 true) 0=[(7,1000)] := by decide

theorem production_key_normalization_first_occurrence_order :
    RollingKeyNormalization.keys [2,1,2,3,1] 0 true=[2,1,3,0] := by decide

theorem private_errors_cannot_encode_additional_symbols :
    FallibleQif.symbol 2 (.error 123)=FallibleQif.symbol 2 (.error 456) := rfl

theorem binary_plus_error_requires_more_than_one_bit :
    ¬(2+1:Nat)^1000≤2^(FractionalQif.price 2) :=
  FallibleQif.charging_only_two_values_undercharges_the_failure_channel

theorem invalid_index_cannot_encode_additional_symbols :
    FallibleQif.symbol 2 (.ok 999)=FallibleQif.symbol 2 (.error 456) := by decide

theorem delegated_spawn_conserves_remaining_tree_budget :
    let root : DelegationAccounting.Node := ⟨1,1,0,12000,0,0⟩
    let initial : DelegationAccounting.State := ⟨[root],fun _ => 0,12000⟩
    DelegatedAdaptiveComposition.remaining 1
      ((DelegationAccounting.step initial (.spawn [] [] root 2 4000 true)).getD initial)=12000 := by decide

theorem delegated_rejected_foreign_tree_cannot_reveal (arity : Nat) (kernel : AdaptiveQif.Kernel n arity) :
    DelegatedAdaptiveComposition.execute 1
      (.query arity kernel [] [] ⟨2,2,0,12000,0,0⟩ (fun _ => .done))
      ⟨[⟨2,2,0,12000,0,0⟩],fun _ => 0,12000⟩=.done := by
  simp [DelegatedAdaptiveComposition.execute]

theorem delegated_adaptive_security_consumer [NeZero n]
    (root : Nat) (program : DelegatedAdaptiveComposition.Program n)
    (kernels : DelegatedAdaptiveComposition.valid program) (s : DelegationAccounting.State)
    (bound : DelegatedAdaptiveComposition.remaining root s≤12000)
    (prior : AdaptiveQif.Weights n) (nonnegative : ∀ x, 0≤prior x) :
    AdaptiveBudget.posterior (DelegatedAdaptiveComposition.execute root program s) prior≤
      4096*AdaptiveQif.vulnerability prior :=
  DelegatedAdaptiveComposition.delegation_settlement_enforces_adaptive_bayes_bound
    root program kernels s bound prior nonnegative

theorem tombstone_then_release_is_denied :
    let initial : EgressFinalization.State := ⟨[(1,7)],[],[]⟩
    let final := Protocol.run EgressFinalization.step initial
      [.ownerSign (1,7) true,.release (1,7) true]
    final.released=[] ∧ final.tombstoned=[(1,7)] := by decide

theorem release_then_tombstone_is_denied :
    let initial : EgressFinalization.State := ⟨[(1,7)],[],[]⟩
    let final := Protocol.run EgressFinalization.step initial
      [.release (1,7) true,.ownerSign (1,7) true,.ifcSign (1,7) true]
    final.released=[(1,7)] ∧ final.tombstoned=[] := by decide

theorem different_epochs_do_not_share_terminal_state :
    EgressFinalization.step ⟨[],[],[(1,7)]⟩ (.release (2,7) true)=
      some ⟨[(2,7)],[(2,7)],[(1,7)]⟩ := by decide

theorem terminal_protocol_is_not_always_denying :
    EgressFinalization.step ⟨[],[],[]⟩ (.ifcSign (1,7) true)=
      some ⟨[],[],[(1,7)]⟩ := by decide

theorem merkle_exact_index_consumer (compress : Nat → Nat → Nat)
    (tree : MerkleProtocol.Tree h) (value index : Nat) (siblings : List Nat)
    (depth : siblings.length=h) (bound : index<2^h)
    (accepted : MerkleProtocol.bottomUp compress value index siblings=MerkleProtocol.root compress tree) :
    MerkleIndexBinding.atIndex tree index=some value ∨ MerkleProtocol.Collision compress :=
  MerkleIndexBinding.accepted_native_opening_binds_claimed_index_or_collision compress tree value index
    siblings depth bound accepted

theorem cohort_padding_does_not_replace_the_last_real_member :
    MerkleIndexBinding.atIndex (MerkleIndexBinding.build 2 [11,22,33,0]) 2=some 33 := by decide

theorem cohort_prefix_framing_prevents_key_boundary_alias :
    MerkleIndexBinding.keyPairBytes [1] [2,3]≠MerkleIndexBinding.keyPairBytes [1,2] [3] := by decide

theorem repeated_key_identity_cannot_inflate_a_checked_cohort (hashLeaf : List Nat → Nat) :
    ¬(([([1],[2]),([1],[2])].map
      (fun keys => hashLeaf (MerkleIndexBinding.keyPairBytes keys.1 keys.2))).Nodup) := by simp

theorem committed_merkle_index_consumer (compress commit : Nat → Nat → Nat)
    (tree : MerkleProtocol.Tree h) (value index actualSize claimedSize : Nat) (siblings : List Nat)
    (depth : siblings.length=h) (fits : actualSize≤2^h) (inClaim : index<claimedSize)
    (accepted : commit (MerkleProtocol.bottomUp compress value index siblings) claimedSize=
      commit (MerkleProtocol.root compress tree) actualSize) :
    (claimedSize=actualSize ∧ index<actualSize ∧ MerkleIndexBinding.atIndex tree index=some value) ∨
      MerkleProtocol.Collision compress ∨ MerkleProtocol.Collision commit :=
  MerkleIndexBinding.size_committed_opening_binds_exact_index_or_collision compress commit tree value
    index actualSize claimedSize siblings depth fits inClaim accepted

/-- A genuine satisfying witness for all 62 constraints: one zero-cost
tombstone, zero entering/leaving budget and a zero public span. -/
def singleTombstoneRow (_ : Nat) (column : Nat) : FieldRangeProofs.F :=
  if column=0 ∨ column=3 then 1 else 0

theorem actual_air_has_a_satisfying_nonempty_trace :
    EpochAirCorrespondence.ValidTrace singleTombstoneRow (fun _ => 0) 0 := by
  intro i inTrace constraint
  have first : i=0 := by omega
  subst i
  fin_cases constraint <;>
    norm_num [EpochAirExtracted.constraint,EpochAirCorrespondence.rowEnv,singleTombstoneRow,
      EpochAirExtracted.c0,EpochAirExtracted.c1,EpochAirExtracted.c2,
      EpochAirExtracted.c3,EpochAirExtracted.c4,EpochAirExtracted.c5,EpochAirExtracted.c6,
      EpochAirExtracted.c7,EpochAirExtracted.c8,EpochAirExtracted.c9,
      EpochAirExtracted.c10,EpochAirExtracted.c11,EpochAirExtracted.c12,
      EpochAirExtracted.c13,EpochAirExtracted.c14,EpochAirExtracted.c15,
      EpochAirExtracted.c16,EpochAirExtracted.c17,EpochAirExtracted.c18,
      EpochAirExtracted.c19,EpochAirExtracted.c20,EpochAirExtracted.c21,
      EpochAirExtracted.c22,EpochAirExtracted.c23,EpochAirExtracted.c24,
      EpochAirExtracted.c25,EpochAirExtracted.c26,EpochAirExtracted.c27,
      EpochAirExtracted.c28,EpochAirExtracted.c29,EpochAirExtracted.c30,
      EpochAirExtracted.c31,EpochAirExtracted.c32,EpochAirExtracted.c33,
      EpochAirExtracted.c34,EpochAirExtracted.c35,EpochAirExtracted.c36,
      EpochAirExtracted.c37,EpochAirExtracted.c38,EpochAirExtracted.c39,
      EpochAirExtracted.c40,EpochAirExtracted.c41,EpochAirExtracted.c42,
      EpochAirExtracted.c43,EpochAirExtracted.c44,EpochAirExtracted.c45,
      EpochAirExtracted.c46,EpochAirExtracted.c47,EpochAirExtracted.c48,
      EpochAirExtracted.c49,EpochAirExtracted.c50,EpochAirExtracted.c51,
      EpochAirExtracted.c52,EpochAirExtracted.c53,EpochAirExtracted.c54,
      EpochAirExtracted.c55,EpochAirExtracted.c56,EpochAirExtracted.c57,
      EpochAirExtracted.c58,EpochAirExtracted.c59,EpochAirExtracted.c60,EpochAirExtracted.c61]

theorem air_unique_slot_consumer (rows : Nat → Nat → FieldRangeProofs.F)
    (public : Nat → FieldRangeProofs.F) (last : Nat)
    (valid : EpochAirCorrespondence.ValidTrace rows public last)
    (heightBound : last<FieldRangeProofs.P) (offset : Nat) (inSpan : offset≤(public 0).val) :
    ∃! i, i≤last ∧ rows i 0=1 ∧ (rows i 1).val=offset :=
  EpochAirSlotCoverage.every_public_offset_has_exactly_one_active_row rows public last valid
    heightBound offset inSpan

theorem actual_air_rejects_an_inactive_gap_before_a_later_slot
    (rows : Nat → Nat → FieldRangeProofs.F) (public : Nat → FieldRangeProofs.F)
    (last endRow i : Nat) (inTrace : endRow≤last) (active : rows endRow 0=1)
    (before : i≤endRow) (gap : rows i 0=0) :
    ¬EpochAirCorrespondence.ValidTrace rows public last := by
  intro valid
  have required := EpochAirSlotCoverage.actual_active_prefix rows public last endRow valid inTrace active i before
  rw [gap] at required
  exact zero_ne_one required

theorem actual_air_rejects_duplicate_active_sequence_positions
    (rows : Nat → Nat → FieldRangeProofs.F) (public : Nat → FieldRangeProofs.F)
    (last i j : Nat) (heightBound : last<FieldRangeProofs.P) (hi : i≤last) (hj : j≤last)
    (ai : rows i 0=1) (aj : rows j 0=1) (different : i≠j) (same : rows i 1=rows j 1) :
    ¬EpochAirCorrespondence.ValidTrace rows public last := by
  intro valid
  exact different (EpochAirSlotCoverage.active_sequence_values_are_injective rows public last valid
    heightBound i j hi hj ai aj same)

theorem actual_accounting_excludes_padding_consumer
    (rows : Nat → Nat → FieldRangeProofs.F) (public : Nat → FieldRangeProofs.F)
    (last : Nat) (valid : EpochAirCorrespondence.ValidTrace rows public last)
    (heightBound : last<FieldRangeProofs.P) (inputRange : (public 2).val<16384) :
    (public 3).val=(public 2).val+
      ((List.range ((public 0).val+1)).map (fun i => (rows i 4).val)).sum ∧
      (public 3).val≤(public 1).val :=
  EpochAirSlotCoverage.actual_epoch_accounts_exactly_the_public_slots rows public last valid
    heightBound inputRange

theorem actual_absolute_interval_consumer
    (rows : Nat → Nat → FieldRangeProofs.F) (public : Nat → FieldRangeProofs.F)
    (last degreeBits start finish sequence : Nat)
    (valid : EpochAirCorrespondence.ValidTrace rows public last) (supported : degreeBits≤24)
    (height : last<2^degreeBits) (ordered : start≤finish) (spanBound : finish-start<1048576)
    (encoded : public 0=((finish-start:Nat):FieldRangeProofs.F))
    (afterStart : start≤sequence) (beforeFinish : sequence≤finish) :
    ∃! i, i≤last ∧ rows i 0=1 ∧ start+(rows i 1).val=sequence :=
  EpochAirSlotCoverage.native_bounded_trace_covers_absolute_interval rows public last degreeBits start
    finish valid supported height ordered spanBound encoded sequence afterStart beforeFinish

theorem accepted_qif_addition_has_the_actual_signed_64_bit_result
    (used amount cap : Nat) (bounded : used+amount≤cap) (capBound : cap≤12000) :
    (BitVec.ofNat 64 used+BitVec.ofNat 64 amount).toInt=(used:Int)+(amount:Int) :=
  (RollingQifRefinement.accepted_machine_addition_is_exact used amount cap bounded capBound).2

theorem signed_64_bit_addition_really_can_overflow_outside_the_budget :
    (BitVec.ofNat 64 9223372036854775807+BitVec.ofNat 64 1).toInt = -9223372036854775808 := by decide

def independentAttestors : EgressAttestorComposition.System := ⟨⟨[],[],[]⟩,⟨[],[],[]⟩⟩

theorem one_attestor_reservation_cannot_stand_for_two_independent_logs :
    let final := Protocol.run EgressAttestorComposition.step independentAttestors
      [.ifcSign (1,7) true,.ownerRelease (1,7) true]
    final.owner.released=[(1,7)] ∧ final.ifc.tombstoned=[(1,7)] ∧
      ¬EgressAttestorComposition.jointlyReserved final (1,7) := by decide

theorem joint_reservation_blocks_both_release_paths :
    let final := Protocol.run EgressAttestorComposition.step independentAttestors
      [.ownerIssue (1,7),.ifcSign (1,7) true,.ownerSign (1,7) true,
       .ownerRelease (1,7) true,.ifcRelease (1,7) true]
    EgressAttestorComposition.jointlyReserved final (1,7) ∧
      final.owner.released=[] ∧ final.ifc.released=[] := by decide

theorem reservations_for_different_epochs_do_not_make_a_joint_attestation :
    let final := Protocol.run EgressAttestorComposition.step independentAttestors
      [.ownerIssue (1,7),.ownerSign (1,7) true,.ifcSign (2,7) true]
    ¬EgressAttestorComposition.jointlyReserved final (1,7) ∧
      ¬EgressAttestorComposition.jointlyReserved final (2,7) := by decide

theorem independent_attestor_history_consumer (s : EgressAttestorComposition.System)
    (events : List EgressAttestorComposition.Event) (slot : EgressFinalization.Slot)
    (safe : EgressAttestorComposition.Safe s) (reserved : EgressAttestorComposition.jointlyReserved s slot) :
    let final := Protocol.run EgressAttestorComposition.step s events
    EgressAttestorComposition.jointlyReserved final slot ∧
      slot∉final.owner.released ∧ slot∉final.ifc.released :=
  EgressAttestorComposition.joint_reservation_survives_future_interleavings_without_any_local_release
    s events slot safe reserved

end EnclaveTest.ProtocolCoverage
