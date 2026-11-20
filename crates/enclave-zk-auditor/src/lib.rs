//! # enclave-zk-auditor — UID 705 `_enclavezk` (FS-705)
//!
//! | Module | Contract |
//! |:---|:---|
//! | [`slab`] | `SecureSlabAllocator`: guard-page root keys (`<= 32`), cookie slabs, `EMTE` gate |
//! | [`quarantine`] | ADR-012 graduated strikes, SEP-MACed counter, `UnquarantineGrant` |
//! | [`zk`] | Hiding accounting STARK; full compliance relation remains incomplete |
//! | [`relation`] | Native witness prechecks and production hiding accounting prover |
//! | [`rollup`] | Versioned CBOR frames, 320 KiB `L3` padding |
//! | [`cohort`] | `R_fleet_pk` Poseidon2 Merkle cohort (`>= 32`) |
//! | [`tombstone`] | Dual `UID 703 + UID 704` co-signed tombstones |
//! | [`thermal`] | 12 MiB `.serious` thermal queue |
//! | [`witness`] | Epoch witnesses derived from the journals and UID 703 (GAP-10) |
//! | [`service`] | IPC API |

#![deny(missing_docs)]

pub mod cohort;
pub mod heap;
/// Daemon entry point (shared by the binary and `mcp-enclave __daemon`).
pub mod entry;
pub mod quarantine;
pub mod relation;
pub mod rollup;
pub mod receiver_trust;
mod retained;
pub mod service;
pub mod slab;
pub mod thermal;
pub mod tombstone;
pub mod witness;
pub mod zk;

/// Frames leave via UID 702's OHTTP relay (re-exported for the ledger tooling).
pub use enclave_crypto::ohttp;
/// Legacy non-hiding accounting key digest, retained for explicit fixtures.
pub use zk::engine::vk_digest;
/// Production hiding accounting key digest; does not imply full compliance.
pub use zk::engine::hiding_vk_digest;
