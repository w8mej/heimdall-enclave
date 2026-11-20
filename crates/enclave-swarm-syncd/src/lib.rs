//! # enclave-swarm-syncd — UID 702 `_enclavecas` (FS-702)
//!
//! | Module | Contract |
//! |:---|:---|
//! | [`fastcdc`] | FastCDC-v2020, pinned gear table + 1 MiB conformance vector |
//! | [`cas`] | Dual-hash CAS, verified reassembly, ref-counted GC, shredding |
//! | [`cas_uri`] | `cas://blake3-bao-v1/<hex64>?target=..&ns=..` grammar |
//! | [`sanitizer`] | safetensors / `.mlpackage` / pickle / Mach-O / ELF gates |
//! | [`admission`] | TUF-whitelisted resolution, anti-downgrade, eager companions |
//! | [`governance`] | Seeding licence, GDPR shards, peer caps, FUSE-T fence, `SeedGateFSM` |
//! | [`revocation`] | `SIGHUP` → 500 ms → `SIGKILL` consumer enforcement |
//! | [`service`] | IPC API (FDs via `SCM_RIGHTS`) |

#![deny(missing_docs)]

pub mod admission;
pub mod bao;
pub mod cas;
pub mod cas_uri;
pub mod config;
/// Daemon entry point (shared by the binary and `depot-enclave __daemon`).
pub mod entry;
pub mod fastcdc;
pub mod fuse;
pub mod governance;
pub mod outbox;
pub mod revocation;
pub mod rollup_relay;
pub mod sanitizer;
pub mod seedgate;
pub mod service;
pub mod sync_diagnostics;
pub mod snapshot;
pub mod snapshot_publication;
pub mod snapshot_broker;
mod streaming;
pub mod transport;
