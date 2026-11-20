//! Starlark plan interpreter for agent workflows (FS-704 §8.2.1, GAP-18).
//!
//! Evaluates `EnclaveStarlarkV1` with a frozen dialect (no load, no while,
//! fuel metering, opaque `Ref` type for labeled values, static Cedar checks
//! for the standalone evaluator, and L3 error sealing). Authenticated scoped
//! turns dispatch each reached call through the live conjunctive PDP; the
//! standalone evaluator remains fail-closed without that authority.

pub mod ast_check;
pub mod frozen;
pub mod interpreter;
pub mod ref_value;

pub use interpreter::{EnclaveStarlarkV1, PlanResult};
pub use ref_value::PlanRef;

/// Runtime-authorized tool transport interface.
pub mod dispatch;
pub(crate) mod arguments;

pub(crate) mod live_check;
