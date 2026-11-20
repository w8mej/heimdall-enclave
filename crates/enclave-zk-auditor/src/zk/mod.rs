//! Plonky3 accounting range-proof engine; full R_epoch is not implemented.
//!
//! Normative parameters (`MUST`): base field `KoalaBear` `p = 2^31 - 2^24 + 1`;
//! challenges in the **quintic** extension `F_{p^5}` (`X^5 + X^2 - 1`, ≈ 154.9
//! bits); `Poseidon2` width 16 (rate 8 / capacity 8) for Merkle commitments
//! and the `DuplexChallenger`; FRI blow-up 4 (`ρ = 1/4`), **84** queries and
//! **16**-bit query proof-of-work. These parameters and the challenge-field
//! size are not a proof of an overall security level. The transcript absorbs
//! the domain string and every public
//! input *before* the first trace commitment (§3.5.3 step 1).

pub mod air;
pub mod engine;
pub mod field;
pub mod imt_air;
pub mod lasso_dfa;
pub mod lookup;
pub mod manifest;
pub mod merkle_air;
pub mod poseidon2_air;
pub mod redact;
pub mod sig_air;
