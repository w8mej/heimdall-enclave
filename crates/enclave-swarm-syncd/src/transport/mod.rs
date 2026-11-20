//! Swarm transport modules (FS-702 §4.1–§4.3, GAP-19).
//!
//! - [`constant_time`]: Indistinguishable 256-byte `CHUNK_UNAVAILABLE` framing.
//! - [`iroh`]: Profile L2 peer-to-peer swarm over QUIC / Iroh.
//! - [`ohttp_fetch`]: Profile L3 OHTTP relay client with in-RAM Bao slice verification.
//! - [`qos`]: Dual-socket QoS (`SO_TC_BE`, `SO_TC_BK_SYS`) and LEDBAT++ controller.
//! - [`r2`]: Cloudflare R2 / ORAS over OCI v1.1 artifact distribution.
//! - [`receipt`]: Byzantine `PoisonReceipt` generation and peer quarantine.

pub mod constant_time;
pub mod iroh;
pub mod ohttp_fetch;
pub mod qos;
pub mod quota;
pub mod r2;
pub mod receipt;

/// Bounded TUF-configured TLS OCI registry downloads (L1 only).
pub mod registry;
/// Mutual-TLS QUIC distribution with live-exporter issuer capabilities.
pub mod quic;

/// Bounded encrypted chunked OHTTP model delivery.
pub mod oblivious;

/// Authenticated namespace-key custody provider.
pub mod custody;

/// Owned explicit L2 seed listener and authenticated source reader.
pub mod quic_seed;

pub(crate) mod quic_poison;

#[cfg(test)]
mod quic_fence_test_support;
