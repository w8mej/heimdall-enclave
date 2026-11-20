//! # enclave-core
//!
//! Shared, dependency-light primitives for the depot v3.0 five-daemon
//! zero-trust enclave (`UID 701–705`):
//!
//! | Module | Contract |
//! |:---|:---|
//! | [`label`] | `(C1..C4) x (T0..T3)` monotonic IFC lattice (FS-704 §3.1) |
//! | [`user_turn`] | `UserTurnV1` structured prompt boundary (ADR-014) |
//! | [`ifc_envelope`] | `IfcEnvelopeV1` opaque handle labels (FS-704 §3.2) |
//! | [`qif`] | 24h sliding-window millibit QIF ledger (FS-701 §4.1, FS-704 §3.2) |
//! | [`audit`] | `EnclaveAuditEnvelopeV1` BLAKE3 + Poseidon2 hash chains |
//! | [`pii`] | Deterministic PAN / SSN / credential / C3 identifier detectors |
//! | [`poseidon2`] | KoalaBear Poseidon2 width-16 sponge |
//! | [`jcs`] | RFC 8785 JSON canonicalization |
//! | [`secret`] | Zeroizing secrets |
//! | [`seq`] | Epoch-anchored `rpc_seq_u64` (ADR-010) |
//! | [`daemon`] | UID/RSS/launchd identity table (ADR-006) |
//! | [`profile`] | `L1 ⊂ L2 ⊂ L3`, `A1 < A2 < A3 < A4` |
//! | [`guarded`] | `mmap`/`mprotect` guard-page regions (Lock-Then-Scrub substrate) |
//! | [`ipc`] | Mutually authenticated UDS framing (`LOCAL_PEERTOKEN` / `SO_PEERCRED`) |
//! | [`runtime`] | Daemon args, identity check, RSS watchdog, serve loop |
//! | [`resource`] | RSS ceilings, zero-JIT introspection, process hardening |

#![deny(missing_docs)]

pub mod audit;
pub mod clock;
pub mod codesign;
pub mod custody_metadata;
pub mod custody_lifetime;
pub mod daemon;
pub mod deployment;
pub mod egress;
pub mod enterprise_authority;
pub mod error;
pub mod fsutil;
pub mod guarded;
mod holder_observation;
pub mod host_config;
pub mod ifc_envelope;
pub mod intent_draft;
pub mod ipc;
pub mod jcs;
pub mod label;
pub mod native_command;
pub mod nvram;
pub mod pii;
pub mod poseidon2;
pub mod power;
pub mod process_identity;
pub mod profile;
pub mod qif;
pub mod quarantine_types;
pub mod resource;
pub mod rng;
pub mod runtime;
pub mod runtime_paths;
pub mod sealed;
pub mod secret;
pub mod seq;
pub mod slab;
pub mod staging;
pub mod supervisor;
pub mod user_turn;

pub use error::{EnclaveError, EnclaveResult, Errno};
pub use label::{Conf, Label, SlotKind, Taint};
pub use profile::{ActionClass, Profile};

/// Exact physical-memory policy shared by observers and breach journaling.
pub mod memory_budget;
