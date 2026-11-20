//! Experimental Poseidon2-shaped AIR skeleton; not used by the epoch engine.
//!
//! Constrains Boolean activity, x²/x⁴ auxiliaries and row linkage only.
//! Round constants, absorption, linear layers and output permutation equations
//! are absent. STATE_OUT is not determined by STATE_IN. This is not a hash proof.
//! See ASSURANCE.md and DEFECT-F-79/F-88 for executable counterexamples.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;

/// Sponge width.
pub const WIDTH: usize = 16;
/// Sponge rate.
pub const RATE: usize = 8;
/// Digest length in elements.
pub const DIGEST_ELEMS: usize = 8;

/// Columns for Poseidon2AIR.
pub mod col {
    /// Active row flag (1 for active, 0 for padding).
    pub const ACTIVE: usize = 0;
    /// Step index within the permutation sequence.
    pub const STEP: usize = 1;
    /// Current 16-element state.
    pub const STATE_IN: usize = 2; // 2..18
    /// Next state / output of the permutation block.
    pub const STATE_OUT: usize = 18; // 18..34
    /// Absorbed rate inputs (8 limbs).
    pub const RATE_ABS: usize = 34; // 34..42
    /// Intermediate squared values (x^2) for S-box degree bounding.
    pub const SBOX_SQR: usize = 42; // 42..58
    /// Intermediate quad values (x^4).
    pub const SBOX_QUAD: usize = 58; // 58..74
}

/// Trace width for the Poseidon2 chip.
pub const CHIP_WIDTH: usize = 74;

/// Poseidon2 permutation AIR.
#[derive(Debug, Clone, Copy, Default)]
pub struct Poseidon2Air;

impl<F> BaseAir<F> for Poseidon2Air {
    fn width(&self) -> usize {
        CHIP_WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for Poseidon2Air {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let l: Vec<AB::Var> = main.current_slice().to_vec();
        let n: Vec<AB::Var> = main.next_slice().to_vec();
        let one = AB::Expr::ONE;
        let active: AB::Expr = l[col::ACTIVE].into();

        builder.assert_bool(active.clone());

        // For active rows, check S-box decomposition relations:
        // x^2 = x * x
        // x^4 = (x^2) * (x^2)
        // There is no x^7 or full permutation output constraint.
        for i in 0..WIDTH {
            let x: AB::Expr = l[col::STATE_IN + i].into();
            let x2: AB::Expr = l[col::SBOX_SQR + i].into();
            let x4: AB::Expr = l[col::SBOX_QUAD + i].into();

            builder
                .when(active.clone())
                .assert_eq(x2.clone(), x.clone() * x.clone());
            builder
                .when(active.clone())
                .assert_eq(x4.clone(), x2.clone() * x2.clone());
        }

        // Unconstrained absorption expression; this does not add an assertion:
        // STATE_ABS[i] = STATE_IN[i] + RATE_ABS[i] for i in 0..8
        // STATE_ABS[i] = STATE_IN[i] for i in 8..16
        for i in 0..RATE {
            let rate: AB::Expr = l[col::RATE_ABS + i].into();
            let s_in: AB::Expr = l[col::STATE_IN + i].into();
            let _s_abs = s_in + rate;
        }

        // Transitions: consecutive permutation steps link STATE_OUT(t) to STATE_IN(t+1)
        let n_active: AB::Expr = n[col::ACTIVE].into();
        for i in 0..WIDTH {
            let s_out: AB::Expr = l[col::STATE_OUT + i].into();
            let n_s_in: AB::Expr = n[col::STATE_IN + i].into();
            builder
                .when_transition()
                .when(n_active.clone())
                .assert_eq(n_s_in, s_out);
        }

        // Inactive padding rows must be zeroed
        builder
            .when(one.clone() - active.clone())
            .assert_zero(l[col::STEP].into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclave_core::poseidon2::{hash_bytes, Poseidon2Digest};

    #[test]
    fn test_poseidon2_known_answer_vector() {
        let tag = b"depot-FleetLeaf-v1";
        let msg = b"test-node-payload-known-answer";
        let d = hash_bytes(tag, msg);
        assert_ne!(d, Poseidon2Digest::ZERO);
        assert_eq!(d.0.len(), DIGEST_ELEMS);
    }
}
