//! # enclave-agent-runtime — UID 704 `_enclaveifc` (FS-704)
//!
//! | Module | Contract |
//! |:---|:---|
//! | [`turn`] | `UserTurnV1` compiler; `PLAN_COMPILE` sees only `T1` + `$paste_k` stubs |
//! | [`heap`] | Opaque SSA capability heap; MAC-sealed `IfcEnvelopeV1` labels |
//! | [`cedar_engine`] | Native `cedar-policy` PDP, strict schema validation |
//! | [`pdp`] | `Allow ⇔ Cedar ∧ Biscuit`; `declassify_enum` QIF settlement |
//! | [`delegation`] | Additive QIF conservation, depth `<= 4`, 64 calls/tree |
//! | [`registry`] | Signed depot lock: every tool fact the PDP uses; default-conservative unannotated tools |
//! | [`tools`] | `blake3(JCS(tools/list))` pins; no-follow `openat` |
//! | [`flow_fsm`] | `FlowGateFSM` |
//! | [`service`] | IPC API |

#![deny(missing_docs)]

pub mod cedar_engine;
pub mod context_dag;
pub mod delegation;
/// Daemon entry point (shared by the binary and `depot-enclave __daemon`).
pub mod entry;
/// Trusted offline-artifact transport for authenticated live plan execution.
pub mod execution_host;
pub mod flow_fsm;
pub mod heap;
pub mod model_turn;
pub mod pdp;
pub mod policy_sli;
pub mod plan;
pub mod progressive;
pub mod registry;
pub mod service;
pub mod ssm;
pub mod tools;
pub mod turn;
mod turn_lifecycle;

/// Cross-node A2A over mTLS (FS-704 §3.4, GAP-35, D-35a).
#[cfg(feature = "l2-a2a")]
pub mod a2a;
