//! Runtime-authorized dispatch seam. A port is a transport, never an authorizer.
use std::sync::atomic::AtomicBool;
use enclave_core::error::EnclaveResult;
use enclave_core::fail;

/// A single call minted only after the live PDP and accounting have allowed it.
/// Private fields and the absence of Clone prevent an external port from minting
/// authority or accidentally replaying a call through this interface.
pub struct AuthorizedToolCall {
    pub(crate) server: String,
    pub(crate) tool_name: String,
    pub(crate) args_jcs: Vec<u8>,
    pub(crate) row_bound: u64,
    pub(crate) authorization_id: [u8; 32],
    pub(crate) plan_blake3: [u8; 32],
    pub(crate) dispatch_expiry: Option<enclave_tool_host::lifecycle::DispatchExpiry>,
}
impl AuthorizedToolCall {
    /// Dispatcher-selected server, checked against the turn's granted tools.
    pub fn server(&self) -> &str { &self.server }
    /// Dispatcher-selected tool, checked against the turn's granted tools.
    pub fn tool_name(&self) -> &str { &self.tool_name }
    /// Exact canonical, materialized bytes allowed by the PDP and PoP signature.
    pub fn args_jcs(&self) -> &[u8] { &self.args_jcs }
    /// Row bound derived from trusted tool metadata and checked arguments.
    pub fn row_bound(&self) -> u64 { self.row_bound }
    /// Unique identity suitable for the host's durable single-use ticket.
    pub fn authorization_id(&self) -> &[u8; 32] { &self.authorization_id }
    /// The exact plan being evaluated for this invocation.
    pub fn plan_blake3(&self) -> &[u8; 32] { &self.plan_blake3 }
    /// Original custody freshness limits, if this actual allowed call stepped up.
    /// These public facts are not live generation or revocation authority.
    pub fn dispatch_expiry(&self) -> Option<&enclave_tool_host::lifecycle::DispatchExpiry> {
        self.dispatch_expiry.as_ref()
    }
}

/// Untrusted tool output. The runtime, rather than the port, assigns labels,
/// verifies the pinned tools/list, scrubs C4 and creates an opaque reference.
pub struct ToolDispatchOutput {
    /// Actual text or JSON tool output, bounded again before publication.
    pub payload: Vec<u8>,
    /// tools/list supplied by the dispatcher-owned tool table/transport.
    pub tools_list: String,
}

/// Execute an already authorized call. Implementations must select the target
/// independently of ticket/request claims and honor cancellation before starting
/// work and before returning. Native artifact/replay authority is configured by
/// the production adapter, not by a plan or an IPC request.
pub trait ToolDispatchPort: Send + Sync + std::fmt::Debug {
    /// Run one allowed call. The enclosing turn gate fences Finish/Wipe until
    /// this returns; cancellation cannot undo side effects already committed.
    fn execute(&self, call: AuthorizedToolCall, cancel: &AtomicBool) -> EnclaveResult<ToolDispatchOutput>;
}

/// Explicit fail-closed default until a trusted production adapter is configured.
#[derive(Debug, Default)]
pub struct NoToolDispatch;
impl ToolDispatchPort for NoToolDispatch {
    fn execute(&self, _call: AuthorizedToolCall, _cancel: &AtomicBool) -> EnclaveResult<ToolDispatchOutput> {
        fail!(EPERM, "PLAN_TOOL_TRANSPORT_UNAVAILABLE")
    }
}

impl std::fmt::Debug for AuthorizedToolCall {
    fn fmt(&self, f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        f.debug_struct("AuthorizedToolCall").field("server",&self.server).field("tool_name",&self.tool_name)
            .field("args_bytes",&self.args_jcs.len()).field("row_bound",&self.row_bound).finish_non_exhaustive()
    }
}
impl std::fmt::Debug for ToolDispatchOutput {
    fn fmt(&self, f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        f.debug_struct("ToolDispatchOutput").field("payload_bytes",&self.payload.len()).finish_non_exhaustive()
    }
}
