//! # enclave-crypto
//!
//! | Module | Contract |
//! |:---|:---|
//! | [`hpke_envelope`] | ADR-009 dual X25519 HPKE `Envelope_A3` / `Envelope_A4` |
//! | [`dpop`] | RFC 9449 DPoP (`ES256`) with `jti` replay cache |
//! | [`pop_biscuit`] | ADR-015 `PoPBiscuitWireV1` + Biscuit v3 delegation |
//! | [`replay`] | 64-bit sliding anti-replay window |
//! | [`multisig`] | ADR-013 discrete `k`-of-`n` Ed25519 quorums |
//! | [`tuf`] | TUF 4-role verifier (threshold, rollback, freeze, mix-and-match) |
//! | [`ohttp`] | RFC 9458 OHTTP + RFC 9292 BHTTP request encapsulation |
//! | [`sas`] | BIP-39 4-word visual SAS |
//! | [`canonical_json`] | OLPC Canonical JSON (securesystemslib profile) |
//! | [`pqc`] | Post-quantum hybrid cryptosystem (ML-KEM-768 & ML-DSA-65) |

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod b64;
pub mod canonical_json;
pub mod dpop;
pub mod epoch;
pub mod hpke_envelope;
pub mod multisig;
pub mod ohttp;
pub mod pop_biscuit;
mod pop_biscuit_facts;
pub mod pqc;
pub mod replay;
pub mod sas;
pub mod time;
pub mod tuf;

pub use biscuit_auth;
pub use ed25519_dalek;
pub use p256;

/// Namespace encryption and custody-wrapped epoch keys for CAS distribution.
pub mod namespace;
