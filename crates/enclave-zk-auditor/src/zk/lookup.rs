//! Experimental extension-field column-permutation helper; no engine caller.
//!
//! This is not a cross-table lookup or multiplicity argument. A future engine
//! must commit primary columns, sample the extension challenge from its
//! transcript, and only then commit the permutation auxiliary trace. Current
//! uni-stark engine has no such phase: these constraints are not a live proof.
//! The helper reads builder permutation randomness, never an ordinary beta
//! argument. It uses inclusive prefixes, next-row terms in transitions, and
//! inverse witnesses that exclude poles. See F134 and ASSURANCE.md.

use p3_air::{ExtensionBuilder, PermutationAirBuilder, WindowAccess};
use p3_field::BasedVectorSpace;

/// Experimental two-column permutation constraints over a quintic extension.
/// Auxiliary permutation columns: inclusive sum, inverse(beta-a), inverse(beta-b).
#[derive(Debug, Clone, Copy, Default)]
pub struct LogUpConstraint;

impl LogUpConstraint {
    /// Evaluate all rows with boundary and transition gating built in.
    /// Challenge 0 must be sampled after the primary trace commitment. The
    /// builder interface alone cannot establish that transcript scheduling.
    /// Panics on an invalid field degree, absent challenge or malformed layout.
    pub fn eval<AB: PermutationAirBuilder>(builder: &mut AB, a_column: usize, b_column: usize) {
        assert!(
            <AB::EF as BasedVectorSpace<AB::F>>::DIMENSION >= 5,
            "permutation helper requires a quintic-or-larger extension field"
        );
        let beta: AB::ExprEF = builder
            .permutation_randomness()
            .first()
            .copied()
            .expect("post-commitment permutation challenge required")
            .into();
        let main = builder.main();
        let a: AB::Expr = main.current(a_column).expect("a column").into();
        let b: AB::Expr = main.current(b_column).expect("b column").into();
        let permutation = builder.permutation();
        let sum: AB::ExprEF = permutation.current(0).expect("sum column").into();
        let ia: AB::ExprEF = permutation.current(1).expect("inverse a column").into();
        let ib: AB::ExprEF = permutation.current(2).expect("inverse b column").into();
        let next_sum: AB::ExprEF = permutation.next(0).expect("next sum column").into();
        let next_ia: AB::ExprEF = permutation.next(1).expect("next inverse a column").into();
        let next_ib: AB::ExprEF = permutation.next(2).expect("next inverse b column").into();
        builder.assert_one_ext((beta.clone() - AB::ExprEF::from(a)) * ia.clone());
        builder.assert_one_ext((beta - AB::ExprEF::from(b)) * ib.clone());
        builder.when_first_row().assert_eq_ext(sum.clone(), ia - ib);
        builder
            .when_transition()
            .assert_eq_ext(next_sum - sum.clone(), next_ia - next_ib);
        builder.when_last_row().assert_zero_ext(sum);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::engine::{Challenge, Val};
    use p3_air::DebugConstraintBuilder;
    use p3_field::{Field, PrimeCharacteristicRing};
    use p3_matrix::dense::RowMajorMatrixView;
    use p3_matrix::stack::ViewPair;

    fn challenge() -> Challenge {
        Challenge::from_basis_coefficients_fn(|i| if i == 1 { Val::ONE } else { Val::ZERO })
    }

    fn check(a: &[u32], b: &[u32], tamper_sum: bool, tamper_inverse: bool) -> bool {
        assert_eq!(a.len(), b.len());
        let beta = challenge();
        let mut total = Challenge::ZERO;
        let main: Vec<_> = a
            .iter()
            .zip(b)
            .map(|(&a, &b)| [Val::from_u32(a), Val::from_u32(b)])
            .collect();
        let mut aux: Vec<_> = a
            .iter()
            .zip(b)
            .map(|(&a, &b)| {
                let ia = (beta - Challenge::from_u32(a)).inverse();
                let ib = (beta - Challenge::from_u32(b)).inverse();
                total += ia - ib;
                [total, ia, ib]
            })
            .collect();
        if tamper_sum {
            aux[0][0] += Challenge::ONE;
        }
        if tamper_inverse {
            aux[0][1] += Challenge::ONE;
        }
        let empty = RowMajorMatrixView::new(&[], 0);
        for r in 0..a.len() {
            let n = (r + 1) % a.len();
            let randomness = [beta];
            let mut builder = DebugConstraintBuilder::new_with_permutation(
                r,
                ViewPair::new(
                    RowMajorMatrixView::new(&main[r], 2),
                    RowMajorMatrixView::new(&main[n], 2),
                ),
                ViewPair::new(empty, empty),
                &[],
                Val::from_bool(r == 0),
                Val::from_bool(r + 1 == a.len()),
                Val::from_bool(r + 1 < a.len()),
                ViewPair::new(
                    RowMajorMatrixView::new(&aux[r], 3),
                    RowMajorMatrixView::new(&aux[n], 3),
                ),
                &randomness,
                &[],
                &[],
            );
            LogUpConstraint::eval(&mut builder, 0, 1);
            if builder.has_failures() {
                return false;
            }
        }
        true
    }

    #[test]
    fn permutation_includes_first_and_last_rows_and_preserves_multiplicity() {
        assert!(check(&[1, 2, 3], &[3, 1, 2], false, false));
        assert!(check(&[1, 1, 3], &[3, 1, 1], false, false));
        assert!(check(&[1], &[1], false, false));
        assert!(!check(&[1, 2], &[1, 3], false, false)); // last term must count
        assert!(!check(&[2, 1], &[3, 1], false, false)); // first term must count
        assert!(!check(&[1, 1, 3], &[1, 3, 3], false, false));
        assert!(!check(&[1, 2, 3], &[3, 1, 2], true, false));
        assert!(!check(&[1, 2, 3], &[3, 1, 2], false, true));
    }

    #[test]
    fn pole_cannot_be_hidden_by_zero_inverse_witnesses() {
        let values = [Val::ONE, Val::ONE];
        let aux = [Challenge::ZERO; 3];
        let empty = RowMajorMatrixView::new(&[], 0);
        let randomness = [Challenge::ONE];
        let main = RowMajorMatrixView::new_row(&values);
        let permutation = RowMajorMatrixView::new_row(&aux);
        let mut builder = DebugConstraintBuilder::new_with_permutation(
            0,
            ViewPair::new(main, main),
            ViewPair::new(empty, empty),
            &[],
            Val::ONE,
            Val::ONE,
            Val::ZERO,
            ViewPair::new(permutation, permutation),
            &randomness,
            &[],
            &[],
        );
        LogUpConstraint::eval(&mut builder, 0, 1);
        assert!(builder.has_failures());
    }
}
