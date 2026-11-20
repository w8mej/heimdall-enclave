/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Darwin Seatbelt (.sb) Capability Preorders & Sandbox Monotonicity
Normative Specification: Darwin sandbox-exec & crates/mcp-enclave/src/launchd.rs
-/

-- ASSURANCE: a standalone specification using Nat, records and Booleans.
-- Its original mechanism terminology is an interpretation of model fields.
-- No cryptographic protocol, deployed constraints, OS or hardware is verified here.
namespace Enclave

/-! # Darwin Seatbelt Sandbox Capability Model -/

/--
Darwin Seatbelt process capability profile.
`allowed_paths`: Canonical path identifiers permitted for filesystem I/O.
`allowed_mach_services`: Mach bootstrap service endpoints permitted for IPC lookup.
`allow_network_raw`: Kernel permission for raw socket creation.
-/
structure SeatbeltCapabilities where
  allowed_paths : List Nat
  allowed_mach_services : List Nat
  allow_network_raw : Bool
  deriving DecidableEq, Repr

/-- Sub-capability relation (subset inclusion for rights). -/
def isSubCapability (c_child c_parent : SeatbeltCapabilities) : Prop :=
  (∀ p, p ∈ c_child.allowed_paths → p ∈ c_parent.allowed_paths) ∧
  (∀ s, s ∈ c_child.allowed_mach_services → s ∈ c_parent.allowed_mach_services) ∧
  (c_child.allow_network_raw = true → c_parent.allow_network_raw = true)

/--
Derive a constrained child sandbox profile by intersecting parent privileges with child limits.
-/
def restrictChildProfile
    (parent : SeatbeltCapabilities)
    (path_filter : Nat → Bool)
    (service_filter : Nat → Bool) : SeatbeltCapabilities := {
  allowed_paths := parent.allowed_paths.filter path_filter,
  allowed_mach_services := parent.allowed_mach_services.filter service_filter,
  allow_network_raw := false
}

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem filtered_capabilities_subset
    (parent : SeatbeltCapabilities)
    (path_filter service_filter : Nat → Bool) :
    isSubCapability (restrictChildProfile parent path_filter service_filter) parent := by
  simp_all [isSubCapability, restrictChildProfile]

/--
Evaluate Mach service lookup at the kernel boundary.
Returns `some service_id` if authorized, or `none` (KERN_DENIED) if denied.
-/
def resolveMachService (caps : SeatbeltCapabilities) (service_id : Nat) : Option Nat :=
  if service_id ∈ caps.allowed_mach_services then
    some service_id
  else
    none

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem model_service_nonmember_denied
    (caps : SeatbeltCapabilities)
    (service_id : Nat)
    (h_not_mem : service_id ∉ caps.allowed_mach_services) :
    resolveMachService caps service_id = none := by
  simp_all [isSubCapability, restrictChildProfile, resolveMachService]

/-! # Formal Preorder Lattice of Sandbox Profiles -/

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem is_sub_capability_refl (c : SeatbeltCapabilities) : isSubCapability c c := by
  refine ⟨fun _ h => h, fun _ h => h, fun h => h⟩

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem is_sub_capability_trans {c1 c2 c3 : SeatbeltCapabilities}
    (h12 : isSubCapability c1 c2) (h23 : isSubCapability c2 c3) :
    isSubCapability c1 c3 := by
  rcases h12 with ⟨hp12, hs12, hn12⟩
  rcases h23 with ⟨hp23, hs23, hn23⟩
  refine ⟨
    fun p hp => hp23 p (hp12 p hp),
    fun s hs => hs23 s (hs12 s hs),
    fun hn => hn23 (hn12 hn)
  ⟩

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem mach_service_child_parent_confinement
    (c_child c_parent : SeatbeltCapabilities) (s : Nat)
    (h_sub : isSubCapability c_child c_parent)
    (h_child : resolveMachService c_child s = some s) :
    resolveMachService c_parent s = some s := by
  simp_all [isSubCapability, restrictChildProfile, resolveMachService]

/-- Empty baseline Seatbelt capability set with zero granted permissions. -/
def emptyCapabilities : SeatbeltCapabilities := {
  allowed_paths := [],
  allowed_mach_services := [],
  allow_network_raw := false
}

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem empty_capabilities_minimal (c : SeatbeltCapabilities) :
    isSubCapability emptyCapabilities c := by
  dsimp [isSubCapability, emptyCapabilities]
  refine ⟨?_, ?_, ?_⟩
  · intro _ h; contradiction
  · intro _ h; contradiction
  · intro h; contradiction

/-! # Operational Boundary Access Authorization Gate -/

/-- Evaluates an incoming filesystem path access request -/
def isPathAccessPermitted (caps : SeatbeltCapabilities) (path_id : Nat) : Bool :=
  path_id ∈ caps.allowed_paths

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem parent_denial_unbypassable_by_child
    (c_child c_parent : SeatbeltCapabilities) (p : Nat)
    (h_sub : isSubCapability c_child c_parent)
    (h_parent_denies : isPathAccessPermitted c_parent p = false) :
    isPathAccessPermitted c_child p = false := by
  dsimp [isPathAccessPermitted] at h_parent_denies ⊢
  have h_not_in_parent : p ∉ c_parent.allowed_paths := by
    cases h : decide (p ∈ c_parent.allowed_paths)
    · exact of_decide_eq_false h
    · simp only [decide_eq_true_eq] at h; rw [decide_eq_true h] at h_parent_denies; contradiction
  have h_not_in_child : p ∉ c_child.allowed_paths := by
    intro h_child_in
    have h_in_p := h_sub.1 p h_child_in
    exact h_not_in_parent h_in_p
  exact decide_eq_false h_not_in_child

/-- Model-level statement; see ASSURANCE.md for its exact implementation boundary. -/
theorem child_raw_network_disabled
    (parent : SeatbeltCapabilities) (p_filt s_filt : Nat → Bool) :
    (restrictChildProfile parent p_filt s_filt).allow_network_raw = false := by
  dsimp [restrictChildProfile]

end Enclave
