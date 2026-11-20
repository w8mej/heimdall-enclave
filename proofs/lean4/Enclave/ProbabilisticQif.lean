/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Natural-weight finite-channel specification; no measure-theoretic or production claim
Normative Specification: FS-704 §8.2, FS-705 §3.2, & ADVERSARIAL_SPEC_REVIEW_2026-11-04 §10.3
-/

import Enclave.QifBound

-- Generic DiscreteChannel lemmas are conditional natural-weight arithmetic.
-- The computed rows/chargedChannel constructors below derive these conditions.
-- No normalized probability, adaptive query, clock, SEP or production theorem.
namespace Enclave

/-- Sum of a list of natural numbers -/
def listSum : List Nat → Nat
  | [] => 0
  | x :: xs => x + listSum xs

/--
Lemma: Sum of a list of length m where each element is bounded by B is at most m * B.
-/
theorem list_sum_le_length_mul_bound (l : List Nat) (bound : Nat)
    (h_bound : ∀ x ∈ l, x ≤ bound) :
    listSum l ≤ l.length * bound := by
  induction l with
  | nil => simp [listSum]
  | cons x xs ih =>
    have hx := h_bound x (List.Mem.head xs)
    have hxs := ih (fun y hy => h_bound y (List.Mem.tail x hy))
    simp [listSum, Nat.add_mul]
    omega

/--
A conditional natural-weight table with m columns and supplied upper bounds.
The historical probability terminology does not supply normalization, a
rolling clock, a SEP, or a production declassification guarantee. Constructors
below compute these fields from deterministic weighted rows and whole-bit charges.
-/
structure DiscreteChannel (m : Nat) where
  output_cardinality_bound : m ≤ 4096
  joint_max_per_output : List Nat
  length_eq : joint_max_per_output.length = m
  prior_vulnerability : Nat
  joint_le_prior : ∀ v ∈ joint_max_per_output, v ≤ prior_vulnerability

/--
Posterior Bayes Vulnerability:
V(X | Y) = ∑_{y ∈ Y} max_{x ∈ X} P(X=x, Y=y)
Computed as the sum over the maximal joint probabilities for each observable transcript.
-/
def posteriorVulnerability (c : DiscreteChannel m) : Nat :=
  listSum c.joint_max_per_output

/--
Theorem 12.1 (Posterior Vulnerability Cardinality Upper Bound):
For any discrete channel, the posterior vulnerability is bounded by the number
of observable outputs multiplied by the prior vulnerability:
V(X | Y) ≤ |Y| · V(X)
-/
theorem bayes_vulnerability_cardinality_bound (m : Nat) (c : DiscreteChannel m) :
    posteriorVulnerability c ≤ m * c.prior_vulnerability := by
  dsimp [posteriorVulnerability]
  have h_bound := list_sum_le_length_mul_bound c.joint_max_per_output c.prior_vulnerability c.joint_le_prior
  rw [c.length_eq] at h_bound
  exact h_bound

/--
Theorem 12.2 (Conditional weighted sum bound):
The record supplies m ≤ 4096 and each column's upper bound; arithmetic
composition gives posteriorVulnerability ≤ 4096 · prior_vulnerability.
This conditional theorem establishes no rolling-window or hardware property.
-/
theorem conditional_bayes_vulnerability_ratio_bound (m : Nat) (c : DiscreteChannel m) :
    posteriorVulnerability c ≤ 4096 * c.prior_vulnerability := by
  have h_card := bayes_vulnerability_cardinality_bound m c
  have h_m_le : m * c.prior_vulnerability ≤ 4096 * c.prior_vulnerability :=
    Nat.mul_le_mul_right c.prior_vulnerability c.output_cardinality_bound
  exact Nat.le_trans h_card h_m_le

/--
Corollary 12.3 (Conditional natural-weight bound with power notation):
Rewrites 4096 as 2^12. No probability, entropy or adversary model is added.
-/
theorem conditional_weighted_sum_power_bound (m : Nat) (c : DiscreteChannel m) :
    posteriorVulnerability c ≤ (2 ^ 12) * c.prior_vulnerability := by
  have h_ratio := conditional_bayes_vulnerability_ratio_bound m c
  have h_pow : 2 ^ 12 = 4096 := by rfl
  rw [h_pow]
  exact h_ratio

-- A deterministic finite channel: each row is a secret with a natural mass
-- and one observable output. Joint maxima are computed, not supplied as bounds.
structure WeightedObservation (m : Nat) where
  output : Fin m
  mass : Nat

def priorMass : List (WeightedObservation m) → Nat
  | [] => 0
  | row :: rest => max row.mass (priorMass rest)

def jointMass (output : Nat) : List (WeightedObservation m) → Nat
  | [] => 0
  | row :: rest => if row.output.val == output then max row.mass (jointMass output rest)
      else jointMass output rest

theorem computed_joint_le_prior (output : Nat) (rows : List (WeightedObservation m)) :
    jointMass output rows ≤ priorMass rows := by
  induction rows with
  | nil => exact Nat.le_refl 0
  | cons row rest ih =>
    simp only [jointMass, priorMass]
    split
    · exact Nat.max_le.mpr ⟨Nat.le_max_left _ _, Nat.le_trans ih (Nat.le_max_right _ _)⟩
    · exact Nat.le_trans ih (Nat.le_max_right _ _)

def channelOfRows (m : Nat) (rows : List (WeightedObservation m)) (hm : m ≤ 4096) : DiscreteChannel m where
  output_cardinality_bound := hm
  joint_max_per_output := (List.range m).map (fun y => jointMass y rows)
  length_eq := by simp
  prior_vulnerability := priorMass rows
  joint_le_prior := by
    intro value h
    simp only [List.mem_map] at h
    rcases h with ⟨output, _, rfl⟩
    exact computed_joint_le_prior output rows

/-- The output bound comes from the charging theorem; each per-output joint bound
comes from an actual deterministic weighted table. It is not assumed in this API. -/
def chargedChannel (queries : List Nat) (h : ValidChargedChannel queries)
    (rows : List (WeightedObservation (chargedTranscripts queries).length)) :
    DiscreteChannel (chargedTranscripts queries).length :=
  channelOfRows _ rows (charged_finite_channel_cardinality_bound queries h)

theorem computed_charged_channel_weighted_bound (queries : List Nat)
    (h : ValidChargedChannel queries)
    (rows : List (WeightedObservation (chargedTranscripts queries).length)) :
    posteriorVulnerability (chargedChannel queries h rows) ≤ 4096 * priorMass rows := by
  exact conditional_bayes_vulnerability_ratio_bound _ (chargedChannel queries h rows)

end Enclave
