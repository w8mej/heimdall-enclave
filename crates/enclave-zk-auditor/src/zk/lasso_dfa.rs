//! Experimental byte-DFA-shaped AIR skeleton; not used by the epoch engine.
//!
//! Flags and limited row linkage are constrained, but bytes are not tied to
//! character classes or a complete transition table, nor reject to next state.
//! This AIR proves no PII absence. eval_dfa_bytes is a separate native scan.
//! See ASSURANCE.md and DEFECT-F-79/F-88 for executable counterexamples.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;

/// DFA reject state indicating unredacted PII detection.
pub const STATE_REJECT: u32 = 99;
/// Maximum carry buffer length in bytes.
pub const CARRY_BYTES: usize = 128;

/// Columns for LassoDfaAir.
pub mod col {
    /// Active byte flag.
    pub const ACTIVE: usize = 0;
    /// Input byte (0..255).
    pub const BYTE: usize = 1;
    /// Current DFA state.
    pub const STATE: usize = 2;
    /// Next DFA state.
    pub const NEXT_STATE: usize = 3;
    /// Is digit flag (1 if BYTE in '0'..='9', else 0).
    pub const IS_DIGIT: usize = 4;
    /// Is hyphen flag (1 if BYTE == '-', else 0).
    pub const IS_HYPHEN: usize = 5;
    /// Reject indicator (1 if NEXT_STATE == STATE_REJECT, else 0).
    pub const IS_REJECT: usize = 6;
    /// Carry forward indicator.
    pub const CARRY_OUT: usize = 7;
}

/// Trace width for the Lasso DFA chip.
pub const CHIP_WIDTH: usize = 8;

/// In-circuit PII scanning DFA chip.
#[derive(Debug, Clone, Copy, Default)]
pub struct LassoDfaAir;

impl<F> BaseAir<F> for LassoDfaAir {
    fn width(&self) -> usize {
        CHIP_WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for LassoDfaAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let l: Vec<AB::Var> = main.current_slice().to_vec();
        let n: Vec<AB::Var> = main.next_slice().to_vec();
        let active: AB::Expr = l[col::ACTIVE].into();
        let is_digit: AB::Expr = l[col::IS_DIGIT].into();
        let is_hyphen: AB::Expr = l[col::IS_HYPHEN].into();
        let is_reject: AB::Expr = l[col::IS_REJECT].into();
        let state: AB::Expr = l[col::STATE].into();
        let next_state: AB::Expr = l[col::NEXT_STATE].into();

        builder.assert_bool(active.clone());
        builder.when(active.clone()).assert_bool(is_digit.clone());
        builder.when(active.clone()).assert_bool(is_hyphen.clone());
        builder.when(active.clone()).assert_bool(is_reject.clone());

        // NOR: a byte cannot be both digit and hyphen
        builder
            .when(active.clone())
            .assert_zero(is_digit.clone() * is_hyphen.clone());

        // Reject flag is zero, but is not tied to the byte/state transition;
        // this is not a proof that C4 is absent.
        builder.when(active.clone()).assert_zero(is_reject);

        // Transitions: next_state in row t must equal state in row t+1
        let n_active: AB::Expr = n[col::ACTIVE].into();
        let n_state: AB::Expr = n[col::STATE].into();
        builder
            .when_transition()
            .when(n_active)
            .assert_eq(n_state, next_state.clone());

        // Constrain non-matching bytes (neither digit nor hyphen) to reset next_state to 0
        let non_matching = (AB::Expr::ONE - is_digit) * (AB::Expr::ONE - is_hyphen);
        builder
            .when(active.clone())
            .assert_zero(non_matching * next_state);

        // When inactive, state must be 0
        builder.when(AB::Expr::ONE - active).assert_zero(state);
    }
}

/// Pure evaluation of DFA transition on a byte slice. Returns (final_state, reached_reject).
pub fn eval_dfa_bytes(initial_state: u32, bytes: &[u8]) -> (u32, bool) {
    let mut st = initial_state;
    for &b in bytes {
        st = match b {
            b'0'..=b'9' => match st {
                0 => 1,
                1 => 2,
                2 => 3,
                3 => 4,
                4 => 5,
                5 => 6,
                6 => 7,
                7 => 8,
                8 => STATE_REJECT,  // 9th consecutive digit (unformatted SSN)
                14 => 15,           // \d{3}+-\d
                15 => 16,           // \d{3}+-\d\d
                16 => 3,            // 3rd digit seen after hyphen
                17 => 18,           // \d{3}+-\d\d-\d
                18 => 19,           // \d{3}+-\d\d-\d\d
                19 => 20,           // \d{3}+-\d\d-\d\d\d
                20 => STATE_REJECT, // \d{3}+-\d\d-\d\d\d\d (formatted SSN complete)
                _ => 1,
            },
            b'-' => match st {
                3..=8 => 14, // \d{3}+-
                16 => 17,    // \d{3}+-\d\d-
                _ => 0,
            },
            _ => 0,
        };
        if st == STATE_REJECT {
            return (STATE_REJECT, true);
        }
    }
    (st, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dfa_scrubbed_text_passes() {
        let clean = b"Patient record [REDACTED] treatment applied successfully.";
        let (st, reject) = eval_dfa_bytes(0, clean);
        assert!(!reject);
        assert_ne!(st, STATE_REJECT);
    }

    #[test]
    fn test_dfa_unredacted_ssn_detected() {
        let dirty = b"Social Security: 123-45-6789 confidential";
        let (st, reject) = eval_dfa_bytes(0, dirty);
        assert!(reject);
        assert_eq!(st, STATE_REJECT);
    }

    #[test]
    fn test_dfa_128b_carry_across_frames() {
        let part1 = b"Partial SSN prefix: 123-45";
        let (carry, reject1) = eval_dfa_bytes(0, part1);
        assert!(!reject1);
        assert_eq!(carry, 16);

        let part2 = b"-6789 suffix";
        let (final_st, reject2) = eval_dfa_bytes(carry, part2);
        assert!(reject2);
        assert_eq!(final_st, STATE_REJECT);
    }

    #[test]
    fn test_dfa_leading_digit_ssn_detected() {
        let dirty = b"Prefix 9123-45-6789 should be rejected";
        let (st, reject) = eval_dfa_bytes(0, dirty);
        assert!(reject);
        assert_eq!(st, STATE_REJECT);
    }
}
