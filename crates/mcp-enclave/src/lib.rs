//! # depot-enclave — operator CLI for the five-daemon enclave
//!
//! | Module | Contract |
//! |:---|:---|
//! | [`ctl`] | `daemon start|stop|status`, `tuf refresh`, `model admit`, `vault enroll`, `audit verify` |
//! | [`deploy`] | `deploy preflight|install|verify|hydrate|healthcheck|purge` |
//! | [`devtuf`] | Persistent 2-of-3 development TUF repository |
//! | [`launchd`] | LaunchDaemon plists, Seatbelt profiles, hardened-runtime entitlements |
//! | [`pf`] | Packet Filter anchor rendering and management |
//! | [`syscmd`] | Pinned absolute tool paths and scrubbed child environment (DEFECT-F-90) |

#![deny(missing_docs)]

pub mod artifact_stream;
pub mod ctl;
pub mod custody_notice;
pub mod deploy;
pub mod dev_envelope;
pub mod devtuf;
pub mod launchd;
pub mod memory;
pub mod model_run;
mod native_fs;
pub mod oidc_session;
pub mod gateway_client;
pub mod pf;
pub mod syscmd;
