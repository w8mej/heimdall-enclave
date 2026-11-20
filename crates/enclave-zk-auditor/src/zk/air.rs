//! The `R_epoch` accounting AIR (FS-705 §3.5.2 constraints 3 and 4).
//!
//! One row per `rpc_seq_u64` slot of the epoch (padded to a power of two):
//!
//! | col | meaning |
//! |:---|:---|
//! | `ACTIVE` | 1 for real slots, 0 for padding (monotone 1…1 0…0) |
//! | `SEQ` | slot offset from `s_start` |
//! | `IS_FOLD` / `IS_TOMB` | exactly one is 1 on every active row |
//! | `DELTA` | millibits charged in this slot (14-bit range-checked) |
//! | `USED` | running 24 h total for the epoch's entity |
//! | `SLACK_BITS[14]` | binary decomposition of `cap - USED` (proves `USED <= cap`) |
//! | `DELTA_BITS[14]` | binary decomposition of `DELTA` (proves `0 <= DELTA < 2^14`) |
//! | `USED_BITS[14]` | binary decomposition of `USED` (prevents field-wrap slack witnesses) |
//!
//! `SEQ` holds the offset `rpc_seq_u64 - s_start` (31-bit safe); the absolute
//! `s_start`/`s_end` are bound through the Fiat-Shamir transcript.
//!
//! Public values: `[span = s_end - s_start, qif_cap_mb]`.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;

/// Range-check bits (12000 < 2^14).
pub const BITS: usize = 14;
/// Versioned relation domain, shared by the verifier digest and its manifest.
pub const AIR_DOMAIN: &str = "EpochAir-v5-full-span";
/// Column indices.
pub mod col {
    /// Active.
    pub const ACTIVE: usize = 0;
    /// Sequence.
    pub const SEQ: usize = 1;
    /// Fold flag.
    pub const IS_FOLD: usize = 2;
    /// Tombstone flag.
    pub const IS_TOMB: usize = 3;
    /// Delta.
    pub const DELTA: usize = 4;
    /// Running total.
    pub const USED: usize = 5;
    /// First slack bit.
    pub const SLACK: usize = 6;
    /// First delta bit.
    pub const DBITS: usize = 6 + super::BITS;
    /// Range-check the running total as well as its slack. Slack alone admits
    /// USED = p-1, cap = 12000, slack = 12001 in the base field.
    pub const UBITS: usize = 6 + 2 * super::BITS;
    /// First randomized blinding column (GAP-23 / D-23c).
    pub const BLIND: usize = 6 + 3 * super::BITS;
}
/// Number of randomized blinding columns.
pub const NUM_BLIND: usize = 4;
/// Trace width (data columns + 4 blinding columns).
pub const WIDTH: usize = 6 + 3 * BITS + NUM_BLIND;

/// Public value indices (GAP-23 / D-23e / GAP-24).
pub mod pv {
    /// Slot offset span (`s_end - s_start`).
    pub const SPAN: usize = 0;
    /// QIF cap in millibits (12,000).
    pub const CAP: usize = 1;
    /// QIF millibits entering this frame (`used_in`).
    pub const USED_IN: usize = 2;
    /// QIF millibits exiting this frame (`used_out`).
    pub const USED_OUT: usize = 3;
    /// Journal fold entering this frame (`J_in`, 8 KoalaBear limbs).
    pub const J_IN: usize = 4; // 4..12
    /// Journal fold exiting this frame (`J_out`, 8 KoalaBear limbs).
    pub const J_OUT: usize = 12; // 12..20
    /// Nullifier digest (`nullifier_e`, 8 limbs).
    pub const NULLIFIER_E: usize = 20; // 20..28
    /// Fleet public key root (`R_fleet_pk`, 8 limbs).
    pub const R_FLEET_PK: usize = 28; // 28..36
    /// QIF IMT root entering this frame (`qif_root_prev`, 8 limbs).
    pub const QIF_ROOT_PREV: usize = 36; // 36..44
    /// QIF IMT root exiting this frame (`qif_root_curr`, 8 limbs).
    pub const QIF_ROOT_CURR: usize = 44; // 44..52
    /// Absolute start slot sequence (`s_start`, low 32 bits).
    pub const S_START_LOW: usize = 52;
    /// Absolute start slot sequence (`s_start`, high 32 bits).
    pub const S_START_HIGH: usize = 53;
    /// Absolute end slot sequence (`s_end`, low 32 bits).
    pub const S_END_LOW: usize = 54;
    /// Absolute end slot sequence (`s_end`, high 32 bits).
    pub const S_END_HIGH: usize = 55;
    /// Fleet cohort size committed in R_fleet_pk.
    pub const COHORT_SIZE: usize = 56;
}

/// Number of public values:
/// span(1) + cap(1) + used_in(1) + used_out(1) + J_in(8) + J_out(8)
/// + nullifier_e(8) + R_fleet_pk(8) + qif_root_prev(8) + qif_root_curr(8)
/// + s_start(2) + s_end(2) + cohort_size(1) = 57.
pub const NUM_PUBLIC: usize = 57;

/// The AIR.
#[derive(Debug, Clone, Copy, Default)]
pub struct EpochAir;

impl<F> BaseAir<F> for EpochAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        NUM_PUBLIC
    }
}

impl<AB: AirBuilder> Air<AB> for EpochAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let l: Vec<AB::Var> = main.current_slice().to_vec();
        let n: Vec<AB::Var> = main.next_slice().to_vec();
        let pis: Vec<AB::PublicVar> = builder.public_values().to_vec();
        let span: AB::Expr = pis[pv::SPAN].into();
        let cap: AB::Expr = pis[pv::CAP].into();
        let used_in: AB::Expr = pis[pv::USED_IN].into();
        let used_out: AB::Expr = pis[pv::USED_OUT].into();
        let s_start_low: AB::Expr = pis[pv::S_START_LOW].into();
        let s_end_low: AB::Expr = pis[pv::S_END_LOW].into();
        let s_start_high: AB::Expr = pis[pv::S_START_HIGH].into();
        let s_end_high: AB::Expr = pis[pv::S_END_HIGH].into();
        let one = AB::Expr::ONE;
        let active: AB::Expr = l[col::ACTIVE].into();
        let fold: AB::Expr = l[col::IS_FOLD].into();
        let tomb: AB::Expr = l[col::IS_TOMB].into();
        let delta: AB::Expr = l[col::DELTA].into();
        let used: AB::Expr = l[col::USED].into();
        let seq: AB::Expr = l[col::SEQ].into();

        builder.assert_bool(active.clone());
        builder.assert_bool(fold.clone());
        builder.assert_bool(tomb.clone());
        // Exactly one of {fold, tombstone} on active rows; neither on padding.
        builder
            .when(active.clone())
            .assert_eq(fold.clone() + tomb.clone(), one.clone());
        builder
            .when(one.clone() - active.clone())
            .assert_zero(fold.clone() + tomb.clone());
        // Tombstones and padding charge nothing.
        builder.assert_zero(tomb.clone() * delta.clone());
        builder.assert_zero((one.clone() - active.clone()) * delta.clone());
        // Range checks via bit decompositions.
        let mut slack = AB::Expr::ZERO;
        let mut dsum = AB::Expr::ZERO;
        let mut usum = AB::Expr::ZERO;
        let mut pow = AB::Expr::ONE;
        for i in 0..BITS {
            let sb: AB::Expr = l[col::SLACK + i].into();
            let db: AB::Expr = l[col::DBITS + i].into();
            let ub: AB::Expr = l[col::UBITS + i].into();
            builder.assert_bool(sb.clone());
            builder.assert_bool(db.clone());
            builder.assert_bool(ub.clone());
            slack += sb * pow.clone();
            dsum += db * pow.clone();
            usum += ub * pow.clone();
            pow = pow.clone() + pow;
        }
        builder.assert_eq(delta.clone(), dsum);
        builder.assert_eq(used.clone(), usum);
        builder.assert_eq(cap - used.clone(), slack);
        // Reconstruct the entire absolute difference in the field. Low limbs
        // alone incorrectly reject valid ranges crossing a 32-bit boundary.
        builder.assert_eq(
            s_end_low - s_start_low + AB::Expr::from_u64(1u64 << 32) * (s_end_high - s_start_high),
            span.clone(),
        );

        // Boundaries (GAP-24: first_row and last_row bind carried used state).
        let mut first = builder.when_first_row();
        first.assert_eq(active.clone(), one.clone());
        first.assert_zero(seq.clone());
        first.assert_eq(used.clone(), used_in + delta);

        let mut last = builder.when_last_row();
        last.assert_eq(used.clone(), used_out);
        builder
            .when_last_row()
            .assert_zero(active.clone() * (seq.clone() - span.clone()));

        // Transitions.
        let n_active: AB::Expr = n[col::ACTIVE].into();
        let n_seq: AB::Expr = n[col::SEQ].into();
        let n_used: AB::Expr = n[col::USED].into();
        let n_delta: AB::Expr = n[col::DELTA].into();
        let mut t = builder.when_transition();
        t.assert_zero(n_active.clone() * (one.clone() - active.clone()));
        t.assert_zero(n_active.clone() * (n_seq - seq.clone() - one.clone()));
        t.assert_eq(n_used, used + n_delta);
        t.assert_zero(active * (one - n_active) * (seq - span));
    }
}
