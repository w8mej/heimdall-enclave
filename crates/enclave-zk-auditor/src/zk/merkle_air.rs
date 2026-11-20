//! Experimental Merkle-shaped AIR skeleton; not used by the epoch engine.
//!
//! Constrains activity/direction bits and parent-to-next-current row linkage.
//! The parent hash is not constrained. This does not prove membership, fleet
//! enrollment, cohort size or anonymity. Native cohort.rs is a separate check.
//! See ASSURANCE.md and DEFECT-F-79/F-88 for executable counterexamples.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;

/// Merkle digest limb width.
pub const DIGEST_LIMBS: usize = 8;

/// Columns for MerkleAir.
pub mod col {
    /// Active level step.
    pub const ACTIVE: usize = 0;
    /// Level index (0..depth-1).
    pub const LEVEL: usize = 1;
    /// Direction bit (0 = curr is left, 1 = curr is right).
    pub const DIR_BIT: usize = 2;
    /// Current node digest limbs.
    pub const CURR: usize = 3; // 3..11
    /// Sibling node digest limbs.
    pub const SIBLING: usize = 11; // 11..19
    /// Computed parent digest limbs.
    pub const PARENT: usize = 19; // 19..27
}

/// Trace width for the Merkle chip.
pub const CHIP_WIDTH: usize = 27;

/// Cohort Merkle path verification AIR.
#[derive(Debug, Clone, Copy, Default)]
pub struct MerkleAir;

impl<F> BaseAir<F> for MerkleAir {
    fn width(&self) -> usize {
        CHIP_WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for MerkleAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let l: Vec<AB::Var> = main.current_slice().to_vec();
        let n: Vec<AB::Var> = main.next_slice().to_vec();
        let active: AB::Expr = l[col::ACTIVE].into();
        let dir: AB::Expr = l[col::DIR_BIT].into();

        builder.assert_bool(active.clone());
        builder.when(active.clone()).assert_bool(dir.clone());

        // Direction-controlled left/right selection:
        // left  = (1 - b) * curr + b * sibling
        // right = b * curr + (1 - b) * sibling
        for i in 0..DIGEST_LIMBS {
            let curr: AB::Expr = l[col::CURR + i].into();
            let sib: AB::Expr = l[col::SIBLING + i].into();
            let _left = (AB::Expr::ONE - dir.clone()) * curr.clone() + dir.clone() * sib.clone();
            let _right = dir.clone() * curr + (AB::Expr::ONE - dir.clone()) * sib;
        }

        // Transitions: next level's CURR must equal current level's PARENT
        let n_active: AB::Expr = n[col::ACTIVE].into();
        for i in 0..DIGEST_LIMBS {
            let parent: AB::Expr = l[col::PARENT + i].into();
            let n_curr: AB::Expr = n[col::CURR + i].into();
            builder
                .when_transition()
                .when(n_active.clone())
                .assert_eq(n_curr, parent);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cohort::{leaf, CohortTree};

    #[test]
    fn test_merkle_chip_membership_vectors() {
        let leaves: Vec<_> = (0..32u8).map(|i| leaf(&[i; 65], &[i; 32])).collect();
        let tree = CohortTree::build(leaves.clone()).expect("cohort tree build");
        let path = tree.path(5).expect("path for leaf 5");
        assert_eq!(path.index, 5);
        assert_eq!(path.siblings.len(), 5); // 2^5 = 32
    }
}
