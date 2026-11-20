/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

TUF 4-Role Anti-Rollback & Monotonic Progression Proofs
Normative Specification: FS-702 §3.3, ADR-011, & ADR-019
-/

namespace Enclave

/-- TUF Metadata record representing signed repository state (Root, Snapshot, Targets) -/
structure TufMetadata where
  version : Nat
  expires_epoch : Nat
  root_keys : List Nat
  deriving DecidableEq, Repr

/--
TUF Update Admissibility Rule:
An update is admitted into the local CAS state iff:
1. Monotonic Versioning: update.version > current.version (Anti-Rollback / Anti-Freeze)
2. Expiration Validity: update.expires_epoch ≥ current_time (Non-Expired)
-/
def isUpdateAdmissible (current : TufMetadata) (candidate : TufMetadata) (current_time : Nat) : Bool :=
  (candidate.version > current.version) && (candidate.expires_epoch ≥ current_time)

/--
Theorem 6.1 (Anti-Rollback & Freeze Attack Prevention, F-028):
Any candidate metadata with version number less than or equal to the current state
is deterministically rejected fail-closed.
-/
theorem anti_rollback_rejected
    (current candidate : TufMetadata) (now : Nat)
    (h_rollback : candidate.version ≤ current.version) :
    isUpdateAdmissible current candidate now = false := by
  simp_all [isUpdateAdmissible] <;> omega

/--
Theorem 6.2 (Expired Metadata Replay Rejection):
Replaying an expired metadata blob whose expiration timestamp is in the past
is deterministically rejected.
-/
theorem expired_metadata_rejected
    (current candidate : TufMetadata) (now : Nat)
    (h_expired : candidate.expires_epoch < now) :
    isUpdateAdmissible current candidate now = false := by
  simp_all [isUpdateAdmissible] <;> omega

/--
Theorem 6.3 (Strict Version Progression Transitivity):
Two successive valid updates guarantee strict monotonic version growth.
-/
theorem monotonic_version_transitivity
    (m1 m2 m3 : TufMetadata) (t1 t2 : Nat)
    (h12 : isUpdateAdmissible m1 m2 t1 = true)
    (h23 : isUpdateAdmissible m2 m3 t2 = true) :
    m1.version < m3.version := by
  simp only [isUpdateAdmissible, Bool.and_eq_true, decide_eq_true_eq] at h12 h23
  exact Nat.lt_trans h12.1 h23.1

/-! # Multi-Version TUF Update Chain & Rollback Freedom -/

/-- Inductive chain of sequential TUF metadata releases. -/
inductive TufUpdateChain : TufMetadata → List (TufMetadata × Nat) → TufMetadata → Prop where
  | single (m : TufMetadata) : TufUpdateChain m [] m
  | step (m1 m2 m_end : TufMetadata) (t : Nat) (rest : List (TufMetadata × Nat))
      (h_admit : isUpdateAdmissible m1 m2 t = true)
      (h_rest : TufUpdateChain m2 rest m_end) :
      TufUpdateChain m1 ((m2, t) :: rest) m_end

/--
Theorem 6.4 (Chain Step Version Increase):
Each admitted link in an update chain strictly advances the version number.
-/
theorem chain_step_version_advances
    (m1 m2 : TufMetadata) (t : Nat)
    (h_admit : isUpdateAdmissible m1 m2 t = true) :
    m2.version > m1.version := by
  simp only [isUpdateAdmissible, Bool.and_eq_true, decide_eq_true_eq] at h_admit
  exact h_admit.1

/--
Theorem 6.5 (Fresh Metadata Within Expiry):
Admitted metadata has expiration epoch at or after the admission timestamp.
-/
theorem admitted_metadata_non_expired
    (m1 m2 : TufMetadata) (t : Nat)
    (h_admit : isUpdateAdmissible m1 m2 t = true) :
    m2.expires_epoch ≥ t := by
  simp only [isUpdateAdmissible, Bool.and_eq_true, decide_eq_true_eq] at h_admit
  exact h_admit.2

end Enclave
