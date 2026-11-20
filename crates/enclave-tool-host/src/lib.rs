//! Zero-JIT WASI tool host and execution ticket verification (ADR-011, GAP-18).
//!
//! WASI tools execute with Cranelift disabled, running under Hardened Runtime,
//! enforcing single-use execution tickets issued by UID 704 (GAP-04) and
//! post-call row truncation (GAP-09).

#![deny(missing_docs)]

pub mod host;
pub mod artifacts;
pub mod lifecycle;
pub mod proxy;
pub mod ticket;

pub use host::{truncate_rows, ToolHost, ToolOutput};
pub use lifecycle::DurableToolHost;
pub use proxy::{EgressGateClient, IpcEgressGateClient, ToolEgressProxy, DEFAULT_IDLE_TIMEOUT};
pub use ticket::{ExecutionTicket, TicketReplayFilter};

mod replay;
