#!/usr/bin/env python3
"""Compile pinned Lean models, tests and executable; audit kernel theorem dependencies.

Missing compiler, compilation errors, custom proof axioms, admits and replacement
of required theorems by definitions are failures. Source text is not proof evidence.
"""

from __future__ import annotations

import hashlib
import json
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

REQUIRED_FILES = [
    "lean-toolchain",
    "lakefile.lean",
    "Enclave.lean",
    "Main.lean",
    "Enclave/Lattice.lean",
    "Enclave/BibaNoninterference.lean",
    "Enclave/QifBound.lean",
    "Enclave/ConjunctiveAuth.lean",
    "Enclave/HardwareCustody.lean",
    "Enclave/AuditChain.lean",
    "Enclave/TufAntiRollback.lean",
    "Enclave/PacketFilter.lean",
    "Enclave/MetalFence.lean",
    "Enclave/MultiAgentQifTree.lean",
    "Enclave/SmallStepSemantics.lean",
    "Enclave/RustModelBridge.lean",
    "Enclave/ProbabilisticQif.lean",
    "Enclave/StatefulPacketFilter.lean",
    "Enclave/SqlAstGuard.lean",
    "Enclave/DpopBinding.lean",
    "Enclave/CedarSemantics.lean",
    "Enclave/BaoStreamVerification.lean",
    "Enclave/StarkAirSoundness.lean",
    "Enclave/LeftoverLocalsDefense.lean",
    "Enclave/EphemeralDelegation.lean",
    "Enclave/SepAntiRollback.lean",
    "Enclave/PagedAttentionIsolation.lean",
    "Enclave/ContextDagProvenance.lean",
    "Enclave/CrashConsistencyWal.lean",
    "Enclave/ExtractionGapDefense.lean",
    "Enclave/TierTwoAssurance.lean",
    "Enclave/TierThreeAssurance.lean",
    "Enclave/ConstantTimeSemantics.lean",
    "Enclave/SeatbeltCapabilityMonotonicity.lean",
    "Enclave/PeerTokenPidReuseImmunity.lean",
    "Enclave/RssMemoryCeilingAccounting.lean",
    "Enclave/SpeculativeVerificationGate.lean",
    "Enclave/FixedPointQ16ArithSafety.lean",
    "Enclave/WasiCapabilitySandbox.lean",
    "Enclave/DelegationTreeConservation.lean",
    "Enclave/CompositionalNoninterference.lean",
    "Enclave/HybridKdfCombiner.lean",
    "Enclave/ZkWitnessUniqueness.lean",
    "Enclave/FriProximitySoundness.lean",
    "Enclave/HpkeAuthEncapSoundness.lean",
    "Enclave/CrashConsistentRecovery.lean",
    "Enclave/UsbYankZeroization.lean",
    "Test.lean",
    "Test/LatticeTest.lean",
    "Test/NoninterferenceTest.lean",
    "Test/CustodyTest.lean",
    "Test/FrontierTest.lean",
    "Test/AcademicAuditTest.lean",
    "Test/ExtendedAssuranceTest.lean",
    "Test/TierZeroAssuranceTest.lean",
    "Test/TierOneAssuranceTest.lean",
    "Test/TierTwoAssuranceTest.lean",
    "Test/TierThreeAssuranceTest.lean",
    "Test/MicroarchitectureAssuranceTest.lean",
    "Test/AgenticGovernanceAssuranceTest.lean",
    "Test/AdvancedCryptoAssuranceTest.lean",
    "Test/HardwareResilienceAssuranceTest.lean",
    "README.md",
]

REQUIRED_THEOREMS = [
    ("Enclave/TicketProtocol.lean", "signing_bytes_injective"),
    ("Enclave/DelegationProtocol.lean", "trace_conserves"),
    (
        "Enclave/DelegatedAdaptiveComposition.lean",
        "delegation_settlement_enforces_adaptive_bayes_bound",
    ),
    ("Enclave/DelegationAccounting.lean", "arbitrary_accounting_history_safe"),
    ("Enclave/DelegationAccounting.lean", "cumulative_spent_of_each_tree_is_bounded"),
    ("Enclave/CapabilityProtocol.lean", "resolution_authentic"),
    ("Enclave/HeapAccounting.lean", "arbitrary_heap_history_accounted"),
    ("Enclave/PlanSafety.lean", "checker_progress_preservation"),
    ("Enclave/TraceNoninterference.lean", "accepted_raw_trace_noninterference"),
    ("Enclave/AuthorizationProtocol.lean", "accepted_request_obeys_every_block"),
    ("Enclave/DpopProtocol.lean", "accepted_exact_binding"),
    ("Enclave/TufProtocol.lean", "threshold_distinct_authorized"),
    ("Enclave/TufProtocol.lean", "refresh_history_no_clock_rollback"),
    ("Enclave/LedgerProtocol.lean", "acknowledged_prefix_survives_crashes"),
    ("Enclave/LedgerProtocol.lean", "crash_recovery_preserves_acknowledged_contents"),
    ("Enclave/ArtifactProtocol.lean", "published_bytes_verified"),
    (
        "Enclave/ArtifactProtocol.lean",
        "publication_requires_authentic_companion_content",
    ),
    ("Enclave/ArtifactProtocol.lean", "arbitrary_staging_crash_history_authentic"),
    ("Enclave/LifecycleProtocol.lean", "old_generation_remains_invalid"),
    ("Enclave/CustodyProtocol.lean", "release_has_bound_verified_factors"),
    ("Enclave/CustodyLifecycle.lean", "release_obeys_factor_matrix"),
    (
        "Enclave/EgressFinalization.lean",
        "arbitrary_history_has_exclusive_terminal_states",
    ),
    ("Enclave/EgressFinalization.lean", "signed_slot_cannot_be_released_later"),
    ("Enclave/EgressFinalization.lean", "released_slot_cannot_be_signed_later"),
    (
        "Enclave/EgressAttestorComposition.lean",
        "arbitrary_interleaving_preserves_both_registries",
    ),
    (
        "Enclave/EgressAttestorComposition.lean",
        "joint_reservation_survives_future_interleavings_without_any_local_release",
    ),
    ("Enclave/EgressProtocol.lean", "released_slot_never_tombstoned_later"),
    ("Enclave/AdaptiveQif.lean", "adaptive_bayes_cardinality_bound"),
    ("Enclave/FallibleQif.lean", "charged_alphabet_includes_failure"),
    (
        "Enclave/FallibleQif.lean",
        "full_window_permits_at_most_4095_values_plus_failure",
    ),
    ("Enclave/FractionalQif.lean", "exact_price_never_undercharges"),
    ("Enclave/FractionalQif.lean", "fractional_budget_implies_4096_bound"),
    ("Enclave/AdaptiveBudget.lean", "variable_arity_channel_preserves_probability"),
    ("Enclave/AdaptiveBudget.lean", "adaptive_fractional_12000_budget_bayes_bound"),
    ("Enclave/AdaptiveBudget.lean", "executable_monitor_enforces_adaptive_bayes_bound"),
    ("Enclave/RollingQif.lean", "arbitrary_rolling_history_bounded"),
    (
        "Enclave/RollingQifRefinement.lean",
        "arbitrary_native_history_refines_eager_history",
    ),
    (
        "Enclave/RollingQifRefinement.lean",
        "arbitrary_native_history_live_usage_bounded",
    ),
    ("Enclave/RollingQifRefinement.lean", "accepted_machine_addition_is_exact"),
    ("Enclave/RollingKeyNormalization.lean", "normalized_native_loop_refines_debit"),
    ("Enclave/RollingKeyNormalization.lean", "actual_string_key_normalization_unique"),
    (
        "Enclave/RollingAdaptiveComposition.lean",
        "rolling_settlement_enforces_adaptive_bayes_bound",
    ),
    ("Enclave/DagProtocol.lean", "accepted_child_dominates_each_parent"),
    ("Enclave/DagProtocol.lean", "constructed_ancestor_taint_monotone"),
    ("Enclave/AutomataProtocol.lean", "executable_iff_path"),
    ("Enclave/SchemaAutomata.lean", "checked_finite_certificate_recognizes_language"),
    ("Enclave/IpcProtocol.lean", "reserve_enforces_caps"),
    ("Enclave/IpcProtocol.lean", "arbitrary_resource_history_bounded"),
    (
        "Enclave/MerkleIndexBinding.lean",
        "accepted_native_opening_binds_claimed_index_or_collision",
    ),
    (
        "Enclave/MerkleIndexBinding.lean",
        "padded_constructor_binds_actual_member_position",
    ),
    ("Enclave/MerkleIndexBinding.lean", "key_pair_encoding_injective"),
    (
        "Enclave/MerkleIndexBinding.lean",
        "size_committed_opening_binds_exact_index_or_collision",
    ),
    (
        "Enclave/MerkleIndexBinding.lean",
        "unique_leaf_digests_exclude_repeated_key_pairs",
    ),
    ("Enclave/MerkleProtocol.lean", "forged_nonmember_exhibits_collision"),
    ("Enclave/MerkleProtocol.lean", "bottom_up_nonmember_exhibits_collision"),
    ("Enclave/FieldRangeProofs.lean", "constrained_used_has_fourteen_bit_range"),
    ("Enclave/EpochAirCorrespondence.lean", "actual_epoch_full_integer_accounting"),
    (
        "Enclave/EpochAirSlotCoverage.lean",
        "actual_trace_covers_every_public_slot_exactly_once",
    ),
    (
        "Enclave/EpochAirSlotCoverage.lean",
        "every_public_offset_has_exactly_one_active_row",
    ),
    ("Enclave/EpochAirSlotCoverage.lean", "supported_degree_prevents_sequence_wrap"),
    (
        "Enclave/EpochAirSlotCoverage.lean",
        "native_bounded_trace_covers_absolute_interval",
    ),
    (
        "Enclave/EpochAirSlotCoverage.lean",
        "encoded_absolute_endpoints_satisfy_actual_span_constraint",
    ),
    (
        "Enclave/EpochAirSlotCoverage.lean",
        "actual_active_row_has_exactly_one_slot_kind",
    ),
    ("Enclave/EpochAirSlotCoverage.lean", "actual_tombstones_have_zero_charge"),
    ("Enclave/EpochAirSlotCoverage.lean", "actual_padding_has_zero_charge"),
    (
        "Enclave/EpochAirSlotCoverage.lean",
        "actual_epoch_accounts_exactly_the_public_slots",
    ),
    ("Enclave/PacketPolicy.lean", "anchor_exact_policy"),
    ("Test/ProtocolCoverageTest.lean", "ticket_live_replay_survives_capacity_pressure"),
    ("Enclave/Lattice.lean", "conf_le_refl"),
    ("Enclave/Lattice.lean", "conf_le_trans"),
    ("Enclave/Lattice.lean", "conf_le_antisymm"),
    ("Enclave/Lattice.lean", "conf_join_comm"),
    ("Enclave/Lattice.lean", "conf_join_least"),
    ("Enclave/Lattice.lean", "integ_le_refl"),
    ("Enclave/Lattice.lean", "integ_join_assoc"),
    ("Enclave/BibaNoninterference.lean", "starlark_biba_noninterference"),
    ("Enclave/BibaNoninterference.lean", "static_projection_index_equal"),
    ("Enclave/QifBound.lean", "charged_finite_channel_cardinality_bound"),
    ("Enclave/QifBound.lean", "charged_transcript_count_at_most_4096"),
    ("Enclave/ConjunctiveAuth.lean", "conjunctive_monotonicity"),
    ("Enclave/ConjunctiveAuth.lean", "conjunctive_dual_monotonicity"),
    ("Enclave/HardwareCustody.lean", "a4_requires_dual_hardware"),
    ("Enclave/HardwareCustody.lean", "airplane_mode_blocks_a4"),
    ("Enclave/HardwareCustody.lean", "quorum_insufficient_rejected"),
    ("Enclave/AuditChain.lean", "journal_step_strictly_monotonic"),
    ("Enclave/AuditChain.lean", "linear_payload_coordinate_injective"),
    ("Enclave/AuditChain.lean", "tombstone_distinguishable"),
    ("Enclave/TufAntiRollback.lean", "anti_rollback_rejected"),
    ("Enclave/TufAntiRollback.lean", "expired_metadata_rejected"),
    ("Enclave/TufAntiRollback.lean", "monotonic_version_transitivity"),
    ("Enclave/PacketFilter.lean", "model_loopback_allowlist_characterization"),
    ("Enclave/PacketFilter.lean", "non_loopback_strictly_dropped"),
    ("Enclave/PacketFilter.lean", "unauthorized_port_strictly_dropped"),
    ("Enclave/MetalFence.lean", "surprise_abort_zero_emitted_bytes"),
    ("Enclave/MetalFence.lean", "abort_branch_emits_zero"),
    ("Enclave/MultiAgentQifTree.lean", "multi_agent_tree_entropy_bound"),
    ("Enclave/MultiAgentQifTree.lean", "topology_bounded_depth"),
    ("Enclave/SmallStepSemantics.lean", "branch_condition_taint_safe"),
    ("Enclave/SmallStepSemantics.lean", "t3_branch_statically_rejected"),
    ("Enclave/SmallStepSemantics.lean", "small_step_trace_noninterference"),
    ("Enclave/SmallStepSemantics.lean", "unbounded_loop_statically_rejected"),
    ("Enclave/SmallStepSemantics.lean", "bounded_loop_fuel_termination"),
    ("Enclave/SmallStepSemantics.lean", "noninterference_modulo_declassification"),
    ("Enclave/RustModelBridge.lean", "copied_fsm_abstract_step_or_safe_outcome"),
    ("Enclave/RustModelBridge.lean", "rust_quarantine_fail_closed"),
    ("Enclave/RustModelBridge.lean", "rust_wiped_requires_new_plan_or_quarantine"),
    ("Enclave/ProbabilisticQif.lean", "bayes_vulnerability_cardinality_bound"),
    ("Enclave/ProbabilisticQif.lean", "conditional_bayes_vulnerability_ratio_bound"),
    ("Enclave/ProbabilisticQif.lean", "conditional_weighted_sum_power_bound"),
    ("Enclave/StatefulPacketFilter.lean", "empty_table_preserves_quarantine"),
    ("Enclave/StatefulPacketFilter.lean", "non_loopback_state_lookup_impossible"),
    (
        "Enclave/StatefulPacketFilter.lean",
        "model_agent_packet_verdict_characterization",
    ),
    ("Enclave/StatefulPacketFilter.lean", "state_table_quarantine_invariant"),
    ("Enclave/StatefulPacketFilter.lean", "out_of_window_packet_strictly_dropped"),
    ("Enclave/SqlAstGuard.lean", "sql_guard_rejects_mutations"),
    ("Enclave/SqlAstGuard.lean", "db_state_immutability"),
    ("Enclave/SqlAstGuard.lean", "filesystem_containment"),
    ("Enclave/SqlAstGuard.lean", "wildcard_projection_rejected"),
    ("Enclave/DpopBinding.lean", "dpop_method_substitution_rejected"),
    ("Enclave/DpopBinding.lean", "dpop_uri_substitution_rejected"),
    ("Enclave/DpopBinding.lean", "dpop_token_swap_rejected"),
    ("Enclave/DpopBinding.lean", "dpop_replay_window_expired"),
    ("Enclave/DpopBinding.lean", "dpop_replayed_jti_rejected"),
    ("Enclave/CedarSemantics.lean", "cedar_default_deny"),
    ("Enclave/CedarSemantics.lean", "forbid_overrides_permit"),
    ("Enclave/CedarSemantics.lean", "permit_monotonicity_under_forbid"),
    ("Enclave/CedarSemantics.lean", "forbid_addition_never_widens"),
    ("Enclave/BaoStreamVerification.lean", "bao_out_of_order_rejected"),
    ("Enclave/BaoStreamVerification.lean", "bao_truncation_detected"),
    ("Enclave/BaoStreamVerification.lean", "linear_root_mismatch_rejects"),
    ("Enclave/BaoStreamVerification.lean", "bao_empty_stream_rejected"),
    ("Enclave/StarkAirSoundness.lean", "air_sequence_strictly_monotonic"),
    ("Enclave/StarkAirSoundness.lean", "air_gap_free_chaining"),
    ("Enclave/StarkAirSoundness.lean", "air_hash_chain_contiguous"),
    ("Enclave/StarkAirSoundness.lean", "row_prev_mismatch_rejects"),
    ("Enclave/StarkAirSoundness.lean", "subset_excludes_nonmember"),
    ("Enclave/StarkAirSoundness.lean", "valid_successors_agree_on_sequence_and_prev"),
    ("Enclave/StarkAirSoundness.lean", "row_boolean_check_implies_two_equalities"),
    ("Enclave/LeftoverLocalsDefense.lean", "leftover_locals_vram_cleared"),
    ("Enclave/LeftoverLocalsDefense.lean", "vram_cross_session_isolation"),
    ("Enclave/LeftoverLocalsDefense.lean", "zeroize_buffer_idempotent"),
    ("Enclave/EphemeralDelegation.lean", "grant_expiry_invariant"),
    ("Enclave/EphemeralDelegation.lean", "delegation_grant_bounded_budget"),
    ("Enclave/EphemeralDelegation.lean", "unauthorized_tool_rejected"),
    ("Enclave/EphemeralDelegation.lean", "attenuated_child_never_widens"),
    ("Enclave/SepAntiRollback.lean", "sep_counter_strictly_monotonic"),
    ("Enclave/SepAntiRollback.lean", "sep_rollback_rejected"),
    ("Enclave/SepAntiRollback.lean", "epoch_advancement_requires_sep_increment"),
    ("Enclave/PagedAttentionIsolation.lean", "paged_attention_cross_tenant_isolation"),
    ("Enclave/PagedAttentionIsolation.lean", "recycled_block_zeroed_before_alloc"),
    ("Enclave/PagedAttentionIsolation.lean", "disjoint_block_tables_no_bleed"),
    ("Enclave/ContextDagProvenance.lean", "context_dag_taint_propagation"),
    ("Enclave/ContextDagProvenance.lean", "sanitized_node_restoration"),
    ("Enclave/ContextDagProvenance.lean", "untainted_source_preserves_integrity"),
    ("Enclave/CrashConsistencyWal.lean", "filtered_wal_records_satisfy_predicate"),
    ("Enclave/CrashConsistencyWal.lean", "wal_torn_write_detection"),
    ("Enclave/CrashConsistencyWal.lean", "wal_committed_atomic_prefix"),
    (
        "Enclave/ExtractionGapDefense.lean",
        "model_record_active_step_matches_copied_fsm",
    ),
    ("Enclave/ExtractionGapDefense.lean", "model_record_fault_latches_quarantine"),
    ("Enclave/ExtractionGapDefense.lean", "no_panic_termination"),
    ("Enclave/TierTwoAssurance.lean", "peer_rate_limiter_bounded_traffic"),
    ("Enclave/TierTwoAssurance.lean", "accepted_staging_allocation_bounded"),
    ("Enclave/TierTwoAssurance.lean", "peripheral_hotplug_locked_wipes_memory"),
    ("Enclave/TierTwoAssurance.lean", "progressive_wire_protocol_monotonic"),
    ("Enclave/TierThreeAssurance.lean", "unbroken_flag_iff_disjunction"),
    ("Enclave/TierThreeAssurance.lean", "signature_flags_iff_conjunction"),
    ("Enclave/TierThreeAssurance.lean", "wire_table_rejects_hybrid_to_classical"),
    ("Test/LatticeTest.lean", "test_conf_join_c1_c4"),
    ("Test/LatticeTest.lean", "test_integ_join_t0_t3"),
    ("Test/NoninterferenceTest.lean", "test_noninterference_sql_isolation"),
    ("Test/CustodyTest.lean", "test_airplane_blocks_a4"),
    ("Test/CustodyTest.lean", "test_docked_authorizes_a4"),
    ("Test/CustodyTest.lean", "test_tuf_rollback_rejected"),
    ("Test/FrontierTest.lean", "test_pf_envoy_allowed"),
    ("Test/FrontierTest.lean", "test_pf_wifi_blocked"),
    ("Test/FrontierTest.lean", "test_metal_anomalous_aborts"),
    ("Test/FrontierTest.lean", "test_tree_within_budget"),
    ("Test/AcademicAuditTest.lean", "test_small_step_t3_rejected"),
    ("Test/AcademicAuditTest.lean", "test_rust_flow_fsm_valid"),
    ("Test/AcademicAuditTest.lean", "test_probabilistic_qif_ratio"),
    ("Test/AcademicAuditTest.lean", "test_stateful_pf_quarantine"),
    ("Test/ExtendedAssuranceTest.lean", "test_sql_insert_rejected"),
    ("Test/ExtendedAssuranceTest.lean", "test_dpop_valid_verification"),
    ("Test/ExtendedAssuranceTest.lean", "test_cedar_forbid_precedence"),
    ("Test/ExtendedAssuranceTest.lean", "test_bao_stream_valid"),
    ("Test/ExtendedAssuranceTest.lean", "test_air_transition_eval"),
    ("Test/TierZeroAssuranceTest.lean", "test_leftover_locals_cleared"),
    ("Test/TierZeroAssuranceTest.lean", "test_ephemeral_grant_expired"),
    ("Test/TierZeroAssuranceTest.lean", "test_sep_rollback_rejected"),
    ("Test/TierZeroAssuranceTest.lean", "test_recycled_block_rejected_if_dirty"),
    ("Test/TierZeroAssuranceTest.lean", "test_context_dag_tainted"),
    ("Test/TierZeroAssuranceTest.lean", "test_wal_torn_record_discarded"),
    ("Test/TierZeroAssuranceTest.lean", "test_air_fully_constrained"),
    ("Test/TierOneAssuranceTest.lean", "test_extraction_valid_step"),
    ("Test/TierOneAssuranceTest.lean", "test_extraction_zero_fuel_quarantined"),
    ("Test/TierOneAssuranceTest.lean", "test_extraction_invalid_event_quarantined"),
    ("Test/TierTwoAssuranceTest.lean", "test_rate_limiter_consumes"),
    ("Test/TierTwoAssuranceTest.lean", "test_rate_limiter_denies_exhausted"),
    ("Test/TierTwoAssuranceTest.lean", "test_staging_quota_allocates"),
    ("Test/TierTwoAssuranceTest.lean", "test_staging_quota_rejects_overflow"),
    ("Test/TierTwoAssuranceTest.lean", "test_peripheral_hotplug_wipe"),
    ("Test/TierTwoAssuranceTest.lean", "test_progressive_wire_advances"),
    ("Test/TierThreeAssuranceTest.lean", "test_kem_classical_broken_pqc_intact"),
    ("Test/TierThreeAssuranceTest.lean", "test_hybrid_signature_accepts_both_valid"),
    ("Test/TierThreeAssuranceTest.lean", "test_downgrade_rejected"),
    ("Enclave/ConstantTimeSemantics.lean", "label_fixed_observation_list_equal"),
    ("Enclave/ConstantTimeSemantics.lean", "label_fixed_dispatch_path_equal"),
    ("Enclave/SeatbeltCapabilityMonotonicity.lean", "filtered_capabilities_subset"),
    ("Enclave/SeatbeltCapabilityMonotonicity.lean", "model_service_nonmember_denied"),
    ("Enclave/PeerTokenPidReuseImmunity.lean", "audit_token_generation_monotonicity"),
    ("Enclave/PeerTokenPidReuseImmunity.lean", "pid_reuse_spoofing_impossible"),
    ("Enclave/RssMemoryCeilingAccounting.lean", "cumulative_rss_ceiling_invariant"),
    ("Enclave/RssMemoryCeilingAccounting.lean", "mach_phys_footprint_tripwire"),
    ("Enclave/SpeculativeVerificationGate.lean", "model_draft_flags_reject"),
    ("Enclave/SpeculativeVerificationGate.lean", "accepted_draft_prefix_length_bound"),
    ("Enclave/FixedPointQ16ArithSafety.lean", "q16_no_overflow_under_bounded_logits"),
    ("Enclave/FixedPointQ16ArithSafety.lean", "monotonic_temperature_scaling"),
    ("Enclave/WasiCapabilitySandbox.lean", "nat_memory_limit_rejects"),
    ("Enclave/WasiCapabilitySandbox.lean", "numeric_fd_membership_rejects"),
    ("Enclave/DelegationTreeConservation.lean", "delegation_tree_fuel_conservation"),
    ("Enclave/DelegationTreeConservation.lean", "max_depth_termination"),
    (
        "Enclave/CompositionalNoninterference.lean",
        "composition_preserves_noninterference",
    ),
    ("Enclave/CompositionalNoninterference.lean", "channel_label_integrity"),
    ("Enclave/HybridKdfCombiner.lean", "model_unbroken_flag_disjunction"),
    ("Enclave/HybridKdfCombiner.lean", "model_max_ge_pqc_field"),
    ("Enclave/ZkWitnessUniqueness.lean", "modular_recurrence_successor_unique"),
    ("Enclave/ZkWitnessUniqueness.lean", "model_degree_bound_formula"),
    ("Enclave/FriProximitySoundness.lean", "model_degree_field_halved"),
    ("Enclave/FriProximitySoundness.lean", "positive_degree_field_decreases"),
    ("Enclave/HpkeAuthEncapSoundness.lean", "numeric_tag_mismatch_returns_none"),
    (
        "Enclave/HpkeAuthEncapSoundness.lean",
        "numeric_identity_and_tag_match_returns_payload",
    ),
    ("Enclave/CrashConsistentRecovery.lean", "two_phase_epoch_atomicity"),
    ("Enclave/CrashConsistentRecovery.lean", "rollback_unflushed_hardware_increment"),
    ("Enclave/UsbYankZeroization.lean", "usb_disconnect_instant_zeroize"),
    ("Enclave/UsbYankZeroization.lean", "post_yank_detokenize_impossibility"),
    ("Test/MicroarchitectureAssuranceTest.lean", "test_constant_time_c4_length"),
    ("Test/MicroarchitectureAssuranceTest.lean", "test_seatbelt_child_narrowed"),
    ("Test/MicroarchitectureAssuranceTest.lean", "test_stale_audit_token_rejected"),
    (
        "Test/MicroarchitectureAssuranceTest.lean",
        "test_rss_allocation_overflow_rejected",
    ),
    ("Test/AgenticGovernanceAssuranceTest.lean", "test_high_ece_draft_rejected"),
    ("Test/AgenticGovernanceAssuranceTest.lean", "test_q16_scaling_order"),
    ("Test/AgenticGovernanceAssuranceTest.lean", "test_wasi_oob_access_fails"),
    ("Test/AgenticGovernanceAssuranceTest.lean", "test_max_depth_agent_cannot_spawn"),
    ("Test/AdvancedCryptoAssuranceTest.lean", "test_composition_label_raised"),
    (
        "Test/AdvancedCryptoAssuranceTest.lean",
        "test_hybrid_kdf_classical_break_tolerated",
    ),
    ("Test/AdvancedCryptoAssuranceTest.lean", "test_air_row_valid"),
    ("Test/AdvancedCryptoAssuranceTest.lean", "test_fri_folding_halves_degree"),
    ("Test/AdvancedCryptoAssuranceTest.lean", "test_hpke_tampered_tag_fails"),
    (
        "Test/HardwareResilienceAssuranceTest.lean",
        "test_crash_recovery_rolls_back_unflushed",
    ),
    (
        "Test/HardwareResilienceAssuranceTest.lean",
        "test_crash_recovery_rolls_forward_committed",
    ),
    ("Test/HardwareResilienceAssuranceTest.lean", "test_usb_yank_zeroizes_slot"),
    (
        "Test/HardwareResilienceAssuranceTest.lean",
        "test_zeroized_slot_fails_detokenize",
    ),
]


PINNED_TOOLCHAIN = "leanprover/lean4:v4.14.0"
PINNED_VERSION = "version 4.14.0,"

REQUIRED_THEOREMS += [
    ("Enclave/TransportAdmission.lean", "arbitrary_history_preserves_counter_bounds"),
    ("Enclave/TransportAdmission.lean", "stale_epoch_remains_invalid"),
    ("Enclave/TransportAdmission.lean", "last_serialized_wipe_controls_latch"),
    (
        "Test/TransportAdmissionTest.lean",
        "current_contract_receipt_after_fence_counterexample",
    ),
    (
        "Test/TransportAdmissionTest.lean",
        "current_contract_queued_fd_after_wipe_counterexample",
    ),
    ("Test/TransportAdmissionTest.lean", "legitimate_release_all_profiles"),
    ("Enclave/SnapshotBrokerProtocol.lean", "arbitrary_history_owned_platform"),
    ("Enclave/SnapshotBrokerProtocol.lean", "foreign_eexist_never_owned"),
    ("Enclave/SnapshotBrokerProtocol.lean", "quiesced_no_later_effect"),
    ("Enclave/SnapshotBrokerProtocol.lean", "revoke_uses_original_authority"),
    ("Enclave/NamespaceKeyringProtocol.lean", "history_never_lost"),
    ("Enclave/NamespaceKeyringProtocol.lean", "floor_never_decreases"),
    (
        "Enclave/NamespaceKeyringProtocol.lean",
        "state_ahead_checkpoint_allows_old_authenticated_state",
    ),
    ("Enclave/NamespaceKeyringProtocol.lean", "migration_marker_history_sticky"),
    ("Enclave/NamespaceKeyringProtocol.lean", "poison_history_denies_all_leases"),
    ("Enclave/NamespaceKeyringProtocol.lean", "disabled_history_denies_all_leases"),
    ("Enclave/SwarmAuthorization.lean", "arbitrary_construction_never_amplifies"),
    (
        "Enclave/SwarmAuthorization.lean",
        "admitted_constructed_wire_preserves_parent_root_scope",
    ),
    ("Enclave/SwarmAuthorization.lean", "admitted_wire_has_exact_pop_tuple"),
    ("Enclave/SwarmAuthorization.lean", "revoked_peer_cannot_renew_after_any_history"),
    (
        "Enclave/TransportClosure.lean",
        "arbitrary_history_resource_and_reservation_bounds",
    ),
    (
        "Enclave/TransportClosure.lean",
        "arbitrary_history_visible_certificate_integrity",
    ),
    ("Enclave/TransportClosure.lean", "visible_certificate_has_exact_main_metadata"),
    ("Enclave/TransportClosure.lean", "rollback_preserves_foreign_effects"),
    ("Enclave/TransportClosure.lean", "l3_registry_fallback_refused"),
    ("Enclave/TransportStartup.lean", "arbitrary_history_serving_has_startup_checks"),
    ("Enclave/TransportStartup.lean", "canonical_failure_has_no_fallback"),
    (
        "Enclave/TransportStartup.lean",
        "admitted_l3_snapshot_has_only_known_permitted_descriptors",
    ),
    ("Enclave/TransportStartup.lean", "strict_profiles_require_complete_registration"),
]

# Reviewed local serialized-release subset; qualified names retain the nested namespace.
REQUIRED_THEOREMS += [
    ("Enclave/TransportAdmission.lean", "LocalSerial." + name)
    for name in (
        "held_serial_prevents_fence",
        "established_fence_is_disabled_and_serial_free",
        "handoff_requires_current_boot_generation_and_time",
        "old_generation_cannot_begin_handoff",
        "expired_handoff_cannot_report_complete",
        "partial_failure_cannot_record_delivery",
        "generation_monotone",
        "exhausted_generation_refuses_authorization_and_handoff",
        "exhausted_generation_remains_refused",
        "stale_generation_remains_unstartable",
    )
]

# These reviewed transport model definitions are part of their theorem contract.
# A theorem-type digest alone does not detect weakening a referenced definition.
# Updating this manifest is an explicit review action, never part of CI.
TRANSPORT_MODULES = (
    "TransportAdmission",
    "SnapshotBrokerProtocol",
    "NamespaceKeyringProtocol",
    "SwarmAuthorization",
    "TransportClosure",
    "TransportStartup",
)
TRANSPORT_CONTRACT_FILES = tuple(
    path
    for name in TRANSPORT_MODULES
    for path in (f"Enclave/{name}.lean", f"Test/{name}Test.lean")
) + (
    "Enclave.lean",
    "Test.lean",
    "Enclave/RustGuardSemantics.lean",
    "Enclave/TransportGuardSource.lean",
    "Enclave/TransportGuardRefinement.lean",
    "Test/TransportGuardRefinementTest.lean",
)

TRANSPORT_GUARD_INPUTS = (
    "scripts/check-transport-guards.py",
    "crates/enclave-crypto/src/namespace.rs",
    "crates/enclave-swarm-syncd/src/transport/ohttp_fetch.rs",
    "crates/enclave-core/src/power.rs",
    "crates/enclave-swarm-syncd/src/streaming.rs",
    "crates/enclave-swarm-syncd/src/config.rs",
)

REQUIRED_THEOREMS += [
    ("Enclave/TransportGuardRefinement.lean", name)
    for name in (
        "encrypt_guard_exact",
        "decrypt_guard_exact",
        "accepted_encrypt_has_decrypt_geometry",
        "accepted_decrypt_has_encrypt_geometry",
        "custody_guard_exact",
        "enumeration_guard_exact",
        "enumeration_returns_complete_positive_records",
        "query_guard_exact",
        "envelope_guard_exact",
        "exact_query_positive_domain_bridge",
        "zero_length_helper_is_distinct_from_positive_structure_model",
        "monitor_optional_exact",
        "monitor_strict_error_preserves_payload",
        "disk_reserve_exact",
        "bounded_write_exact",
        "accepted_write_length_and_contents",
    )
]


def validate_transport_guards(base_dir: Path) -> dict:
    result = subprocess.run(
        [sys.executable, "-B", str(base_dir / TRANSPORT_GUARD_INPUTS[0])],
        cwd=base_dir,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode:
        raise RuntimeError(
            "source-derived transport guard check failed: " + result.stderr.strip()
        )
    provenance = json.loads(result.stdout)
    if provenance.get("status") != "PASS":
        raise RuntimeError("source-derived transport guard check did not pass")
    return provenance


def validate_transport_contracts(lean_dir: Path) -> None:
    manifest = lean_dir / "transport-contracts.json"
    if not manifest.is_file():
        raise RuntimeError("missing reviewed transport definition contracts")
    expected = json.loads(manifest.read_text(encoding="utf-8"))
    if set(expected) != set(TRANSPORT_CONTRACT_FILES):
        raise RuntimeError("reviewed transport definition contract inventory changed")
    for relative, digest in expected.items():
        path = lean_dir / relative
        if (
            not path.is_file()
            or hashlib.sha256(path.read_bytes()).hexdigest() != digest
        ):
            raise RuntimeError(f"reviewed transport definition changed: {relative}")


def validate_compiled(lean_dir: Path, output: str) -> dict[str, str]:
    """Read kernel declarations produced by Audit.lean, never source claims."""
    declarations = {}
    for line in output.splitlines():
        if line.startswith("KERNEL_DECL "):
            name, signature = json.loads(line.removeprefix("KERNEL_DECL "))
            declarations[name] = signature
    if "KERNEL_AUDIT " not in output or not declarations:
        raise RuntimeError("compiler did not produce the kernel audit inventory")
    for rel_file, theorem in REQUIRED_THEOREMS:
        source = (lean_dir / rel_file).read_text(encoding="utf-8")
        namespace = re.search(r"^namespace\s+(\S+)", source, re.MULTILINE)
        if namespace is None:
            raise RuntimeError(f"missing namespace in {rel_file}")
        name = namespace.group(1) + "." + theorem
        if name not in declarations:
            raise RuntimeError(
                f"required kernel theorem missing or replaced by a definition: {name}"
            )
    manifest = lean_dir / "theorem-types.json"
    if manifest.exists():
        expected = json.loads(manifest.read_text(encoding="utf-8"))
        for name, digest in expected.items():
            signature = declarations.get(name)
            if (
                signature is None
                or hashlib.sha256(signature.encode()).hexdigest() != digest
            ):
                raise RuntimeError(
                    f"reviewed theorem type changed or disappeared: {name}"
                )
    return declarations


def check_lean_package(base_dir: Path) -> None:
    lean_dir = base_dir / "proofs" / "lean4"
    report_path = base_dir / "reports" / "lean-build.json"
    report_path.unlink(missing_ok=True)
    for rel_path in (
        REQUIRED_FILES
        + [p for p, _ in REQUIRED_THEOREMS]
        + ["Audit.lean", "lake-manifest.json", "theorem-types.json", "COVERAGE.md"]
    ):
        if not (lean_dir / rel_path).is_file():
            raise RuntimeError(f"missing required Lean source: {rel_path}")
    if (lean_dir / "lean-toolchain").read_text().strip() != PINNED_TOOLCHAIN:
        raise RuntimeError("unexpected Lean toolchain pin")
    validate_transport_contracts(lean_dir)
    guard_provenance = validate_transport_guards(base_dir)
    lake = shutil.which("lake")
    lean = shutil.which("lean")
    if not lake or not lean:
        raise RuntimeError(
            "Lean and Lake are required; install the pinned toolchain. No proof check ran."
        )
    version = subprocess.check_output(
        [lake, "env", "lean", "--version"], cwd=lean_dir, text=True
    )
    if PINNED_VERSION not in version:
        raise RuntimeError(f"wrong Lean compiler: {version.strip()}")
    print(version.strip(), flush=True)
    subprocess.run(
        [lake, "build", "Enclave", "Test", "enclave_verifier"],
        cwd=lean_dir,
        check=True,
        timeout=600,
    )
    audit = subprocess.run(
        [lake, "env", "lean", "Audit.lean"],
        cwd=lean_dir,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if audit.returncode:
        print(audit.stdout, file=sys.stderr)
        print(audit.stderr, file=sys.stderr)
        raise RuntimeError("kernel declaration / transitive axiom audit failed")
    declarations = validate_compiled(lean_dir, audit.stdout)
    sources = sorted(
        [
            *lean_dir.glob("Enclave/*.lean"),
            *lean_dir.glob("Test/*.lean"),
            *lean_dir.glob("*.lean"),
            lean_dir / "lean-toolchain",
            lean_dir / "lake-manifest.json",
            lean_dir / "theorem-types.json",
            lean_dir / "transport-contracts.json",
            base_dir / "scripts/check-lean.py",
            *(base_dir / p for p in TRANSPORT_GUARD_INPUTS),
        ]
    )
    hashes = {
        str(p.relative_to(base_dir)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sources
    }
    report = dict(
        result="PASS",
        git_revision=subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=base_dir, text=True
        ).strip(),
        host=platform.platform(),
        lean_version=version.strip(),
        kernel_theorems=len(declarations),
        source_sha256=hashes,
        selected_guard_translation=guard_provenance,
        assurance="Lean model statements; no production or hardware verification implied",
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(
        f"PASS: compiled models, tests and executable; audited {len(declarations)} kernel theorems."
    )
    print(
        "Assurance: Lean model statements only; production correspondence requires separate checks."
    )


def main() -> None:
    try:
        check_lean_package(Path(__file__).resolve().parent.parent)
    except (RuntimeError, subprocess.SubprocessError, OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
