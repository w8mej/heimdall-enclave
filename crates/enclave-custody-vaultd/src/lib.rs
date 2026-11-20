//! # enclave-custody-vaultd — UID 703 `_piivault` (FS-703)
//!
//! Hardware custody profiles `L1 ⊂ L2 ⊂ L3`, FIDO2 `CTAP 2.1+`, chained
//! `Touch ID → YubiKey` co-signatures, the ADR-009 dual-key vault and the
//! Lock-Then-Scrub panic zeroizer.
//!
//! | Module | Contract |
//! |:---|:---|
//! | [`ctap`] | CTAPHID, CTAP2 CBOR, `pinUvAuthProtocol=2`, `hmac-secret`, assertion verifier, MDS |
//! | [`biometric`] | `CoreAuthUI` / `LAContext` bridge (SEP-signature verified) |
//! | [`ceremony`] | Chained co-signature + `PromptCooldown60s` + rate limits |
//! | [`factors`] | `RequiredFactors(L, A)` with strict nesting |
//! | [`intent`] | RFC 8785 `IntentPayloadV1`, `d_JCS`, SAS |
//! | [`vault`] | ADR-007 erasure / reversible tokenization, `Envelope_A3`/`A4` |
//! | [`zeroizer`] | CPU freeze, retained accelerator ownership and scrub; optional recovery disabled |
//! | [`lifecycle`] | `CustodyLifecycleFSM` |
//! | [`quorum`] | `k`-of-`n` CTAP Ed25519 quorum |
//! | [`service`] | IPC API |

#![deny(missing_docs)]

mod cas_keyring;
mod backup_envelope;
mod namespace_capsule;
mod asset_membership;
mod membership_retirement;
mod replacement_release_authority;
mod guarded_publication;
pub(crate) mod travel_recovery;
pub mod biometric;
pub mod ceremony;
pub mod clock;
pub mod ctap;
pub mod darwin_sep;
/// Authenticated, prepared native display handoff and revocation connection.
#[cfg(unix)]
pub mod display;
pub mod egress_uds;
/// Daemon entry point (shared by the binary and `depot-enclave __daemon`).
pub mod entry;
pub mod factors;
pub mod guarded_approval;
pub mod ingress;
pub mod intent;
pub mod lease;
pub mod lifecycle;
pub mod metadata_source;
pub mod oidc;
/// Intent-bound, current-session acquisition of genuine OIDC step-up proofs.
#[cfg(unix)]
pub mod oidc_acquisition;
/// Secure existing-PIN collection from the mutually authenticated GUI helper.
#[cfg(unix)]
pub mod pin;
pub mod provisioning;
pub use enclave_core::pii;
pub mod quorum;
pub mod sep;
pub mod service;
pub mod vault;
pub mod zeroizer;
