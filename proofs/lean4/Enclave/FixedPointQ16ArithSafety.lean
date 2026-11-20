/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Fixed-Point Q16.16 Logit Arithmetic & Monotonic Temperature Invariants
Normative Specification: GAP-41, FS-701 §4.2, & crates/enclave-model-runnerd
-/

namespace Enclave

/-! # Fixed-Point Q16.16 Arithmetic Bounds -/

/-- Maximum representable Q16.16 signed integer magnitude (scaled by 65536). -/
def Q16_SCALE : Nat := 65536
def MAX_Q16_VAL : Nat := 2147483647

/-- Bounded fixed-point logit representation avoiding IEEE-754 NaN/Inf vectors. -/
structure FixedLogit where
  raw_scaled : Nat
  deriving DecidableEq, Repr

/-- Safe logit addition bounded against arithmetic overflow. -/
def safeAddLogit (a b : FixedLogit) : Option FixedLogit :=
  if a.raw_scaled + b.raw_scaled ≤ MAX_Q16_VAL then
    some { raw_scaled := a.raw_scaled + b.raw_scaled }
  else
    none

/-- Scale a logit by a positive fixed-point temperature multiplier `temp_scaled`. -/
def scaleLogit (l : FixedLogit) (temp_scaled : Nat) : Nat :=
  (l.raw_scaled * temp_scaled) / Q16_SCALE

/--
Theorem 32.1 (Q16 No Overflow Under Bounded Logits):
Any safe addition that succeeds guarantees that the resulting scaled logit is within
the maximum fixed-point capacity.
-/
theorem q16_no_overflow_under_bounded_logits
    (a b res : FixedLogit)
    (h_add : safeAddLogit a b = some res) :
    res.raw_scaled ≤ MAX_Q16_VAL := by
  dsimp [safeAddLogit] at h_add
  split at h_add
  · cases h_add
    assumption
  · contradiction

/--
Theorem 32.2 (Monotonic Temperature Scaling):
Multiplying two ordered logits by a positive non-zero temperature preserves their
relative numerical order, preventing temperature-based rank inversion attacks.
-/
theorem monotonic_temperature_scaling
    (l1 l2 : FixedLogit)
    (temp : Nat)
    (h_le : l1.raw_scaled ≤ l2.raw_scaled) :
    scaleLogit l1 temp ≤ scaleLogit l2 temp := by
  unfold scaleLogit
  apply (Nat.le_div_iff_mul_le (by decide : 0 < Q16_SCALE)).2
  exact Nat.le_trans (Nat.div_mul_le_self _ _) (Nat.mul_le_mul_right temp h_le)

/-! # Algebraic Properties & Identity Scaling Theorems -/

/--
Theorem 32.3 (Safe Addition Commutativity):
Safe logit addition is commutative.
-/
theorem safe_add_logit_comm (a b : FixedLogit) :
    safeAddLogit a b = safeAddLogit b a := by
  dsimp [safeAddLogit]
  rw [Nat.add_comm a.raw_scaled b.raw_scaled]

/--
Theorem 32.4 (Unit Temperature Identity Scaling):
Scaling a logit with temperature multiplier 1.0 (Q16_SCALE = 65536) exactly preserves the raw logit.
-/
theorem unit_temperature_identity (l : FixedLogit) :
    scaleLogit l Q16_SCALE = l.raw_scaled := by
  simp_all [Q16_SCALE, MAX_Q16_VAL, safeAddLogit, scaleLogit]

/-- Safe logit subtraction for logit difference / softmax exponent calculation. -/
def safeSubLogit (a b : FixedLogit) : Option FixedLogit :=
  if b.raw_scaled ≤ a.raw_scaled then
    some { raw_scaled := a.raw_scaled - b.raw_scaled }
  else
    none

/--
Theorem 32.5 (Safe Subtraction Bounded Capacity):
If `a` was within maximum capacity, the result of safe subtraction remains bounded by `MAX_Q16_VAL`.
-/
theorem safe_sub_logit_capacity
    (a b res : FixedLogit)
    (h_a : a.raw_scaled ≤ MAX_Q16_VAL)
    (h_sub : safeSubLogit a b = some res) :
    res.raw_scaled ≤ MAX_Q16_VAL := by
  dsimp [safeSubLogit] at h_sub
  split at h_sub
  · cases h_sub
    dsimp
    omega
  · contradiction

/--
Theorem 32.6 (Zero Scaling Yields Zero):
Scaling any logit by zero temperature collapses the output to zero.
-/
theorem zero_temperature_collapses (l : FixedLogit) :
    scaleLogit l 0 = 0 := by
  dsimp [scaleLogit]
  simp

end Enclave
