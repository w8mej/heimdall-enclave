import Enclave.TransportStartup

/-! Positive and adversarial kernel-checked model traces. No host operation or
claim that modeled observations were extracted from a running daemon. -/
namespace EnclaveTest.TransportStartup
open Enclave.TransportStartup

def monitor : Monitor := ⟨true, true, true⟩
def metadata : Metadata := ⟨[1,2,3], .l1, true, false, true, true⟩
def payload : Payload := ⟨[1,2,3], true, true, true⟩
def sources : Sources := ⟨.present payload, .missing, .missing⟩
def good (profile : Profile) : Input :=
  ⟨profile, false, false, true, true, true, true, true, true,
    monitor, .known [], metadata, sources⟩
def run := Enclave.Protocol.run step

theorem normal_release_has_a_serving_path_for_all_three_profiles :
    (startup (good .l1)).isSome = true ∧ (startup (good .l2)).isSome = true ∧
      (startup (good .l3)).isSome = true := by decide

theorem l1_monitor_failure_is_optional_but_l2_l3_refuse :
    (startup {good .l1 with monitor := ⟨false,false,false⟩}).isSome = true ∧
    startup {good .l2 with monitor := ⟨false,false,false⟩} = none ∧
    startup {good .l3 with monitor := ⟨false,false,false⟩} = none := by decide

theorem missing_usb_or_source_rejects_strict_profiles :
    startup {good .l2 with monitor := ⟨true,false,true⟩} = none ∧
    startup {good .l3 with monitor := ⟨true,true,false⟩} = none := by decide

theorem development_mode_does_not_bypass_strict_monitoring :
    startup {good .l3 with development := true, monitor := ⟨false,false,false⟩} = none := by decide

theorem production_simulation_unsafe_uid_and_socket_refuse :
    startup {good .l1 with simulated := true} = none ∧
    startup {good .l1 with simulated := true, development := true, daemonUid := true, productionSocket := false} = none ∧
    startup {good .l1 with simulated := true, development := true, daemonUid := false, productionSocket := true} = none := by decide

theorem isolated_development_simulation_has_an_explicit_success_path :
    (startup {good .l1 with simulated := true, development := true, daemonUid := false, productionSocket := false}).isSome = true := by decide

theorem normal_release_refuses_missing_confinement_stale_pins_or_identity :
    startup {good .l2 with confined := false} = none ∧
    startup {good .l2 with pinsFresh := false} = none ∧
    startup {good .l2 with identityValid := false} = none := by decide

theorem all_ipv4_ipv6_tcp_listeners_and_udp_receivers_refuse :
    listenerAllows .l3 (.known [.known (.tcp .ipv4 true)]) = false ∧
    listenerAllows .l3 (.known [.known (.tcp .ipv6 true)]) = false ∧
    listenerAllows .l3 (.known [.known (.udp .ipv4 4433 false true 0)]) = false ∧
    listenerAllows .l3 (.known [.known (.udp .ipv6 4433 false true 0)]) = false := by decide

theorem tcp_udp_clients_unbound_udp_and_unix_controls_succeed :
    listenerAllows .l3 (.known [.known (.tcp .ipv4 false), .known (.tcp .ipv6 false),
      .known (.udp .ipv4 40000 true true 443), .known (.udp .ipv6 40001 true true 443),
      .known (.udp .ipv4 0 false false 0), .known .unix]) = true := by decide

theorem connected_udp_requires_valid_peer_family_and_port :
    listenerAllows .l3 (.known [.known (.udp .ipv4 100 true false 443)]) = false ∧
    listenerAllows .l3 (.known [.known (.udp .ipv6 100 true true 0)]) = false := by decide

theorem unavailable_enumeration_or_descriptor_query_is_not_empty_success :
    listenerAllows .l3 .incomplete = false ∧ listenerAllows .l3 .error = false ∧
    listenerAllows .l3 (.known [.incomplete]) = false ∧
    listenerAllows .l3 (.known [.error]) = false ∧
    listenerAllows .l3 (.known [.known .unsupportedInternet]) = false := by decide

theorem failed_short_partial_exact_capacity_and_unsupported_queries_refuse :
    completeEnumeration false 8 16 8 = false ∧ completeEnumeration true 7 16 8 = false ∧
    completeEnumeration true 16 16 8 = false ∧ completeEnumeration true 0 16 8 = false ∧
    completeEnumeration true 8 16 0 = false ∧ exactQuery true 7 8 = false ∧
    exactQuery false 8 8 = false ∧ exactQuery true 0 0 = false := by decide

theorem complete_bounded_queries_have_positive_controls :
    completeEnumeration true 8 16 8 = true ∧ exactQuery true 8 8 = true := by decide

theorem closing_receiver_and_retrying_can_start_without_a_skip :
    let failed := {good .l3 with snapshot := .known [.known (.udp .ipv6 4433 false true 0)]}
    let final := run initial [.start failed, .start (good .l3), .fetch (.known [])]
    final.session.isSome = true ∧ final.fetches = 1 := by decide

theorem fetch_repeats_descriptor_guard_and_recovers_after_close :
    let final := run initial [.start (good .l3), .fetch (.known [.known (.tcp .ipv4 true)]),
      .fetch .error, .fetch (.known [.known (.tcp .ipv4 false)])]
    final.session.isSome = true ∧ final.fetches = 1 := by decide

theorem canonical_signed_bytes_win_over_stale_loose_bytes :
    resolve 65536 metadata ⟨.present payload, .present {payload with bytes := [9]}, .missing⟩ =
      some [1,2,3] := by decide

theorem corrupt_or_unreadable_canonical_payload_cannot_fallback_to_valid_loose :
    resolve 65536 metadata ⟨.present {payload with bytes := [9]}, .present payload, .present payload⟩ = none ∧
    resolve 65536 metadata ⟨.failure, .present payload, .present payload⟩ = none := by decide

theorem only_missing_loose_copy_can_fallback_to_verified_chunk :
    resolve 65536 metadata ⟨.missing, .missing, .present payload⟩ = some [1,2,3] ∧
    resolve 65536 metadata ⟨.missing, .failure, .present payload⟩ = none := by decide

theorem revoked_expired_wrong_path_and_unowned_directory_refuse :
    resolve 65536 {metadata with revoked := true} sources = none ∧
    resolve 65536 {metadata with current := false} sources = none ∧
    resolve 65536 {metadata with pathValid := false} sources = none ∧
    resolve 65536 {metadata with directoryOwned := false} sources = none := by decide

theorem links_special_files_truncation_and_growth_refuse :
    resolve 65536 metadata {sources with canonical := .present {payload with nofollow := false}} = none ∧
    resolve 65536 metadata {sources with canonical := .present {payload with regular := false}} = none ∧
    resolve 65536 metadata {sources with canonical := .present {payload with bytes := [1,2]}} = none ∧
    resolve 65536 metadata {sources with canonical := .present {payload with bytes := [1,2,3,4]}} = none := by decide

theorem bounded_resolution_has_exact_positive_and_overflow_controls :
    resolve 3 metadata sources = some [1,2,3] ∧ resolve 2 metadata sources = none := by decide

theorem signed_floor_cannot_be_downgraded :
    startup {good .l1 with metadata := {metadata with floor := .l3}} = none ∧
    (startup {good .l3 with metadata := {metadata with floor := .l3}}).isSome = true := by decide

theorem failed_required_monitor_leaves_no_serving_session :
    let failed := {good .l2 with monitor := ⟨false,false,false⟩}
    (run initial [.start failed]).session = none := by decide

theorem stop_releases_modeled_session_and_allows_valid_restart :
    let final := run initial [.start (good .l3), .stop, .start (good .l2)]
    final.session.map (fun permit => permit.input.profile) = some .l2 := by decide

theorem arbitrary_serving_history_consumer (events : List Event) :
    Safe (run initial events) := arbitrary_history_serving_has_startup_checks events

#print axioms arbitrary_history_serving_has_startup_checks
#print axioms resolution_has_exact_current_signed_bytes
#print axioms admitted_l3_snapshot_has_only_known_permitted_descriptors

end EnclaveTest.TransportStartup
