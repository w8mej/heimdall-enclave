//! Experimental MAC-shaped AIR skeleton; not used by the epoch engine.
//!
//! Only Boolean activity is meaningful: the key equation is a tautology when
//! activity is Boolean. Message, public-key and tag columns are unconstrained.
//! No MAC, signature, key registration or EUF-CMA result is proved by this AIR.
//! compute_prf_mac is a separate native function, not an AIR constraint.
//! See ASSURANCE.md and DEFECT-F-79/F-88 for executable counterexamples.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;

/// Limb count for Poseidon2 digests and keys.
pub const DIGEST_LIMBS: usize = 8;

/// Columns for SigAir.
pub mod col {
    /// Active flag.
    pub const ACTIVE: usize = 0;
    /// Private MAC key limbs (witness only, not public).
    pub const K_MAC: usize = 1; // 1..9
    /// Message digest limbs.
    pub const M_DIGEST: usize = 9; // 9..17
    /// Expected enrolled public key leaf limbs.
    pub const PK_LEAF: usize = 17; // 17..25
    /// Generated tag limbs.
    pub const TAG: usize = 25; // 25..33
}

/// Trace width for the SigAir chip.
pub const CHIP_WIDTH: usize = 33;

/// PRF-MAC signature substitute AIR.
#[derive(Debug, Clone, Copy, Default)]
pub struct SigAir;

impl<F> BaseAir<F> for SigAir {
    fn width(&self) -> usize {
        CHIP_WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for SigAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let l: Vec<AB::Var> = main.current_slice().to_vec();
        let active: AB::Expr = l[col::ACTIVE].into();

        builder.assert_bool(active.clone());

        // Historical skeleton: the following expression imposes no key or MAC
        // binding once ACTIVE is Boolean; do not treat it as authorization.
        for i in 0..DIGEST_LIMBS {
            let k: AB::Expr = l[col::K_MAC + i].into();
            let _m: AB::Expr = l[col::M_DIGEST + i].into();
            let _pk: AB::Expr = l[col::PK_LEAF + i].into();
            let _tag: AB::Expr = l[col::TAG + i].into();

            // Tautology for Boolean activity; retained as a documented skeleton.
            builder
                .when(active.clone())
                .assert_zero((AB::Expr::ONE - active.clone()) * k);
        }
    }
}

/// Native computation of PRF-MAC tag for a message digest under key.
pub fn compute_prf_mac(
    k_mac: &enclave_core::poseidon2::Poseidon2Digest,
    m_digest: &enclave_core::poseidon2::Poseidon2Digest,
) -> enclave_core::poseidon2::Poseidon2Digest {
    enclave_core::poseidon2::compress(b"depot-TombstoneMac-v1", k_mac, m_digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclave_core::poseidon2::Poseidon2Digest;

    #[test]
    fn test_prf_mac_evaluation() {
        let key = Poseidon2Digest([1, 2, 3, 4, 5, 6, 7, 8]);
        let msg = Poseidon2Digest([10, 20, 30, 40, 50, 60, 70, 80]);
        let tag1 = compute_prf_mac(&key, &msg);
        let tag2 = compute_prf_mac(&key, &msg);
        assert_eq!(tag1, tag2);

        let tampered_msg = Poseidon2Digest([10, 20, 30, 40, 50, 60, 70, 81]);
        let tag3 = compute_prf_mac(&key, &tampered_msg);
        assert_ne!(tag1, tag3);
    }
}
