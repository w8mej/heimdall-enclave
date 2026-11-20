//! Experimental interval AIR skeleton; not used by the epoch engine.
//!
//! Constrains Boolean activity and two 16-bit field differences. It does not
//! bind the interval to an authenticated tree, constrain either tree root,
//! validate next pointers, or prove insertion/nonmembership in any real tree.
//! See ASSURANCE.md and DEFECT-F-79/F-88 for executable counterexamples.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;

/// Digest limbs.
pub const DIGEST_LIMBS: usize = 8;
/// Range check decomposition bits.
pub const RANGE_BITS: usize = 16;

/// Columns for ImtAir.
pub mod col {
    /// Active flag.
    pub const ACTIVE: usize = 0;
    /// Target value to prove non-membership for.
    pub const TARGET_VAL: usize = 1;
    /// Low interval bound from the existing leaf.
    pub const LOW_VAL: usize = 2;
    /// High interval bound from the existing leaf.
    pub const HIGH_VAL: usize = 3;
    /// Next index pointer.
    pub const NEXT_IDX: usize = 4;
    /// Range check bits for (TARGET_VAL - LOW_VAL - 1).
    pub const LOW_BITS: usize = 5; // 5..21
    /// Range check bits for (HIGH_VAL - TARGET_VAL - 1).
    pub const HIGH_BITS: usize = 21; // 21..37
    /// Previous tree root limbs.
    pub const ROOT_PREV: usize = 37; // 37..45
    /// Updated tree root limbs after insertion.
    pub const ROOT_CURR: usize = 45; // 45..53
}

/// Trace width for ImtAir.
pub const CHIP_WIDTH: usize = 53;

/// Indexed Merkle Tree non-membership AIR.
#[derive(Debug, Clone, Copy, Default)]
pub struct ImtAir;

impl<F> BaseAir<F> for ImtAir {
    fn width(&self) -> usize {
        CHIP_WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for ImtAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let l: Vec<AB::Var> = main.current_slice().to_vec();
        let active: AB::Expr = l[col::ACTIVE].into();
        let target: AB::Expr = l[col::TARGET_VAL].into();
        let low: AB::Expr = l[col::LOW_VAL].into();
        let high: AB::Expr = l[col::HIGH_VAL].into();

        builder.assert_bool(active.clone());

        // Range checks: TARGET_VAL - LOW_VAL - 1 >= 0
        // and HIGH_VAL - TARGET_VAL - 1 >= 0
        let mut diff_low_sum = AB::Expr::ZERO;
        let mut diff_high_sum = AB::Expr::ZERO;
        let mut pow = AB::Expr::ONE;

        for i in 0..RANGE_BITS {
            let b_low: AB::Expr = l[col::LOW_BITS + i].into();
            let b_high: AB::Expr = l[col::HIGH_BITS + i].into();

            builder.when(active.clone()).assert_bool(b_low.clone());
            builder.when(active.clone()).assert_bool(b_high.clone());

            diff_low_sum += b_low * pow.clone();
            diff_high_sum += b_high * pow.clone();
            pow = pow.clone() + pow;
        }

        // Verify that target strictly exceeds low bound: target - low - 1 == sum(low_bits)
        builder
            .when(active.clone())
            .assert_eq(target.clone() - low - AB::Expr::ONE, diff_low_sum);

        // Verify that high bound strictly exceeds target: high - target - 1 == sum(high_bits)
        builder
            .when(active)
            .assert_eq(high - target - AB::Expr::ONE, diff_high_sum);
    }
}

/// Verifies non-membership of `target` between `low` and `high`.
pub fn verify_interval_non_membership(target: u32, low: u32, high: u32) -> bool {
    target > low && (high == 0 || target < high)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_imt_non_membership_interval() {
        assert!(verify_interval_non_membership(50, 10, 100));
        assert!(!verify_interval_non_membership(5, 10, 100)); // below low
        assert!(!verify_interval_non_membership(150, 10, 100)); // above high
        assert!(!verify_interval_non_membership(10, 10, 100)); // equal to low
    }
}
