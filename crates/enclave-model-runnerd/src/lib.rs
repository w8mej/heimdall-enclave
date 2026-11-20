//! # enclave-model-runnerd — UID 701 `_llmagent` (FS-701)
//!
//! | Module | Contract |
//! |:---|:---|
//! | [`manifest`] | Signed `enclave-model.manifest.json` (V18 schema rules) |
//! | [`safetensors`] | Bounds-checked tensor index over the read-only CAS mapping |
//! | [`topology`] | Static structural class detection + runtime operator attestation |
//! | [`ece`] | 15-bin equal-mass ECE gate (`<= 0.015`) |
//! | [`dfa`] | Bounded-depth schema → `<= 4096`-state DFA + `DINGO` trellis |
//! | [`arena`] | Locked guard-paged scratch arenas with verified wipe |
//! | [`classes`] | The six class gates + `AR_CAUSAL` baseline |
//! | [`adapter`] | `EnclaveModelAdapter::bind()` dispatcher (lattice-join controls) |
//! | [`zoo`] | `enclave-pack` reference checkpoints for every class |
//! | [`service`] | IPC API (`Declassify`, `Invoke`, `Zeroize`, ...) |

#![deny(missing_docs)]

pub mod adapter;
pub mod arena;
pub mod arena_metal;
pub mod backends;
pub mod classes;
pub mod dfa;
pub mod ece;
/// Daemon entry point (shared by the binary and `depot-enclave __daemon`).
pub mod entry;
pub mod manifest;
/// Real WebKit execution restricted to a built-in owned offline document.
pub mod owned_browser;
pub mod paged_attention;
pub mod safetensors;
pub mod screencapture;
pub mod service;
pub mod token_lattice;
pub mod tokenizer;
pub mod world_tokenizer;
pub mod topology;
pub mod zoo;
