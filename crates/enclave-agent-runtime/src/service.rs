//! UID 704 daemon service: IPC API and state.
//!
//! **Trust boundary (GAP-04 – GAP-07).** Every fact the conjunctive PDP
//! decides on is derived here, never taken from the caller:
//!
//! * the tool's action class, sink clearance, namespace, root-mutation flag,
//!   slot kinds, row bound and QIF charge come from the signed MCP lock
//!   ([`ToolRegistry`]); unannotated tools are default-conservative;
//! * input labels come from the capability heap;
//! * "now" is read from the enclave's own clocks;
//! * the hardware grant is the outcome of this daemon's own call to UID 703
//!   over a mutually authenticated socket — a caller cannot assert it;
//! * the Cedar principal is the verified Biscuit chain, not a free string.
//!
//! Root tokens are minted only for a compiled `UserTurnV1` from the client
//! ingress (administrator) path, custody grants only for workflows the
//! signed Cedar bundle names, tool-output labels only ever rise above the
//! lock's floor, and `C4` spans are erased or sealed by UID 703 before any
//! byte is stored in this address space.

mod execution;
mod recovery;

#[cfg(test)]
#[path = "service/staged_output_tests.rs"]
mod staged_output_tests;

use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer, SigningKey};
use enclave_core::audit::AuditJournal;
use enclave_core::daemon::DaemonId;
use enclave_core::error::EnclaveResult;
use enclave_core::ifc_envelope::{IfcEnvelopeV1, VaultTier};
use enclave_core::intent_draft::IntentDraftV1;
use enclave_core::ipc::{DaemonStatus, PeerCredentials};
use enclave_core::label::{Conf, Label, SlotKind};
use enclave_core::profile::{ActionClass, Profile};
use enclave_core::qif::QifLedger;
use enclave_core::secret::SecretBytes;
use enclave_core::seq::RpcSequencer;
use enclave_core::user_turn::UserTurnV1;
use enclave_core::{err, fail};
use enclave_crypto::biscuit_auth::AuthorizerLimits;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest;

use crate::cedar_engine::{CedarEngine, PolicyProvenance};
use crate::delegation::DelegationManager;
use crate::heap::CapabilityHeap;
use crate::pdp::{Decision, Pdp, ToolCallRequest};
use crate::registry::{ResolvedTool, ToolRegistry};
use crate::turn::{compile_turn, PlanCompileContext, ToolSignature};

/// Minimum label for any model output: confidential, untrusted provenance.
const MODEL_OUTPUT_FLOOR: Label = Label { c: Conf::C1, t: enclave_core::label::Taint::T3 };
/// Largest model text sent to custody for C4 scrubbing.
const MAX_SCRUB_BYTES: usize = 250 * 1024;
/// Largest prompt a turn may send to the model (same bound as SSM ingest).
const MAX_PROMPT_BYTES: usize = 250 * 1024;

/// Keep the existing zeroizing owner across every pre-heap refusal. A successful
/// handoff takes the same Vec only immediately before guarded heap ingress.
struct StagedToolOutput(Option<enclave_crypto::namespace::SecretMaterial>);
impl StagedToolOutput {
    fn new(bytes: Vec<u8>) -> Self {
        let owner = Self(Some(enclave_crypto::namespace::SecretMaterial(bytes)));
        #[cfg(test)]
        staged_output_tests::observe("adopted", &owner.0.as_ref().expect("staged output retained").0);
        owner
    }
    fn bytes(&self) -> &[u8] { &self.0.as_ref().expect("staged output retained").0 }
    fn into_vec(mut self) -> Vec<u8> {
        let mut owner = self.0.take().expect("staged output retained");
        #[cfg(test)]
        staged_output_tests::observe("transferred", &owner.0);
        std::mem::take(&mut owner.0)
    }
}
impl Drop for StagedToolOutput {
    fn drop(&mut self) {
        #[cfg(test)]
        if let Some(owner) = &self.0 {
            staged_output_tests::observe("zeroizing_owner_drop_entered", &owner.0);
        }
        // The still-owned SecretMaterial field now zeroizes its entire Vec.
        // Tests do not read storage after that field's Drop or deallocation.
    }
}

/// Declassifier backend (`jev` / `DINGO` in UID 701).
pub trait Declassifier: Send + Sync + std::fmt::Debug {
    /// Classify an opaque payload into `0..cardinality` for the governed
    /// `slot` (UID 701 journals it under UID 703's epoch, GAP-27).
    fn classify(
        &self,
        payload: &[u8],
        cardinality: u64,
        schema: &str,
        slot: &enclave_core::seq::GovernedSlot,
    ) -> EnclaveResult<u64>;
}

fn required_intent_optional<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where D: serde::Deserializer<'de>, T: Deserialize<'de> {
    Option::<T>::deserialize(deserializer)
}

/// Original public endpoints received with the matching actual custody reply.
/// They can shorten a live allowed call, never authenticate a factor or fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentLifetimeV1 {
    /// Exact schema version, one.
    pub v: u8,
    /// Earliest independent exclusive wall expiry, if present.
    #[serde(deserialize_with="required_intent_optional")]
    pub valid_until_unix: Option<i64>,
    /// Original exclusive boot endpoint. Required for stepped native dispatch.
    #[serde(deserialize_with="required_intent_optional")]
    pub deadline_boot_ns: Option<u64>,
}
impl IntentLifetimeV1 {
    pub(crate) fn dispatch_expiry(&self) -> EnclaveResult<enclave_tool_host::lifecycle::DispatchExpiry> {
        if self.v != 1 {fail!(EACCES,"TOOL_AUTHORITY_LIFETIME_VERSION");}
        let deadline = self.deadline_boot_ns.ok_or_else(||err!(EACCES,"TOOL_AUTHORITY_LIFETIME_REQUIRED"))?;
        let now = enclave_core::clock::boot_clock_ns();
        // The actual complete ceremony cap is ten seconds. A matching response
        // cannot legitimately claim a later new window; never clamp and accept it.
        if deadline.checked_sub(now).is_some_and(|remaining| remaining > 10_000_000_000) {
            fail!(EACCES,"TOOL_AUTHORITY_LIFETIME_BOUND");
        }
        enclave_tool_host::lifecycle::DispatchExpiry::from_original(self.valid_until_unix,deadline)
    }
}

/// A completed chained hardware ceremony, as reported by UID 703.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepUp {
    /// `d_JCS` of the intent UID 703 built from the draft (hex).
    pub d_jcs: String,
    /// Factors proven.
    pub factors: Vec<String>,
    /// Actual custody's original endpoints, never supplied by a request boolean.
    pub lifetime: IntentLifetimeV1,
}

struct CallDecision {
    decision: Decision,
    dispatch_expiry: Option<enclave_tool_host::lifecycle::DispatchExpiry>,
}

/// UID 704's view of UID 703 (`_piivault`).
pub trait CustodyPort: Send + Sync + std::fmt::Debug {
    /// Erase / seal every `C4` span (ADR-007) and return the scrubbed text.
    fn scrub_text(&self, text: &str, bulk_set: bool) -> EnclaveResult<String>;
    /// Run the chained Touch ID → YubiKey ceremony for an `A3`/`A4` call.
    fn authorize_intent(&self, draft: &IntentDraftV1) -> EnclaveResult<StepUp>;
    /// Allocate the governed slot `(boot_epoch_id, rpc_seq_u64)` for one
    /// governed RPC from the sequence authority (UID 703, GAP-27).
    fn allocate_slot(&self) -> EnclaveResult<(String, u64)>;
    /// UID 703's signed epoch for the slots it issues, verified against the
    /// pinned SEP epoch key (GAP-27).
    fn boot_epoch(&self) -> EnclaveResult<enclave_core::seq::BootEpoch>;
    /// Track C `A3` reveal: UID 703 runs the ceremony bound to `value` and
    /// shows it only on the trusted display; returns the approved `d_jcs`.
    fn reveal(&self, _value: &[u8], _draft: &IntentDraftV1) -> EnclaveResult<String> {
        Err(err!(ENOSYS, "CUSTODY_REVEAL_UNAVAILABLE"))
    }
}

/// A custody port that refuses everything (no UID 703 configured).
#[derive(Debug, Default)]
pub struct NoCustody;

impl CustodyPort for NoCustody {
    fn scrub_text(&self, _text: &str, _bulk: bool) -> EnclaveResult<String> {
        fail!(EPERM, "CUSTODY_UNAVAILABLE", "C4 ingress requires UID 703")
    }
    fn authorize_intent(&self, _d: &IntentDraftV1) -> EnclaveResult<StepUp> {
        fail!(
            EPERM,
            "CUSTODY_UNAVAILABLE",
            "hardware step-up requires UID 703"
        )
    }
    fn allocate_slot(&self) -> EnclaveResult<(String, u64)> {
        fail!(
            EPERM,
            "CUSTODY_UNAVAILABLE",
            "governed slots are issued by UID 703"
        )
    }
    fn boot_epoch(&self) -> EnclaveResult<enclave_core::seq::BootEpoch> {
        fail!(
            EPERM,
            "CUSTODY_UNAVAILABLE",
            "the epoch is issued by UID 703"
        )
    }
}

/// IPC requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IfcRequest {
    /// Status.
    Status,
    /// Read bounded privacy-safe policy timing telemetry (operator only).
    PolicySli,
    /// Compile a user turn (client-ingress / administrator only). When
    /// `holder_pk` is set, the turn's single root PoP-Biscuit is minted for
    /// that holder, bound to the caller's channel, and restricted to exactly
    /// the tools named in `tools`; an empty list yields a token that
    /// authorises no tool (DEFECT-F-67).
    SubmitTurn {
        /// Turn.
        turn: UserTurnV1,
        /// `(handle, bytes)`.
        attachments: Vec<(String, serde_bytes::ByteBuf)>,
        /// Curated tool signatures (their `name`s are the root token's tool set).
        tools: Vec<ToolSignature>,
        /// Root token holder.
        holder_pk: Option<[u8; 32]>,
        /// Root QIF budget (`<= 12,000 mb`).
        budget_mb: i64,
    },
    /// Begin a trusted, explicitly completed/cancelled ingress lifetime.
    BeginTurn {
        /// Validated user turn.
        turn: UserTurnV1,
        /// Attachment handles and bytes.
        attachments: Vec<(String, serde_bytes::ByteBuf)>,
        /// Curated tool signatures.
        tools: Vec<ToolSignature>,
        /// Optional root holder.
        holder_pk: Option<[u8;32]>,
        /// Root QIF budget.
        budget_mb: i64,
    },
    /// Dedicated gateway submission with a preallocated reconciliation sequence.
    /// The console identity is forwarded only by the authenticated gateway.
    BeginGatewayTurn {
        /// Strictly increasing within this exact gateway process identity.
        submission_seq: u64,
        /// Kernel-attested console process, never a console wire parameter.
        caller: PeerCredentials,
        /// Validated user turn.
        turn: UserTurnV1,
        /// Attachment handles and bytes.
        attachments: Vec<(String, serde_bytes::ByteBuf)>,
        /// Requested tools, curated again by the runtime.
        tools: Vec<ToolSignature>,
        /// External holder, or private runtime execution.
        holder_pk: Option<[u8;32]>,
        /// Root QIF budget.
        budget_mb: i64,
    },
    /// Retire a gateway sequence before cancelling its original turn. A late
    /// Begin cannot recreate a successfully cancelled submission.
    CancelGatewaySubmission {
        /// Sequence owned by this exact authenticated gateway process.
        submission_seq: u64,
    },
    /// Run bounded trusted recovery and acknowledge this gateway's active IDs.
    RecoverGatewayTurns,
    /// Execute a frozen plan under this active turn's private holder and root.
    /// Only BeginTurn with holder_pk=None supplies the internal executor.
    /// This entry admits a bounded live subset: direct tool calls, literal
    /// containers, scalar comparisons/booleans and literal range(0..=16)
    /// loops. No arbitrary native methods, growth operators or recursion.
    /// Final values are scalar/Ref; see docs/plan-execution.md for limits.
    ExecuteTurnPlan {
        /// Runtime-minted lifetime; owner is authenticated again for each call.
        turn_id: String,
        /// Frozen Starlark source (at most 65536 bytes).
        source: String,
        /// (binding name, handle) pairs, all live and owned by this turn.
        initial_handles: Vec<(String, String)>,
        /// Caller may lower the 10000-tick ceiling, never raise it.
        fuel_budget: u64,
        /// Request actual custody step-up for A3/A4 calls.
        step_up: bool,
    },
    /// Retain verified managed envelopes while another scoped turn is live.
    RetainTurnHandles {
        /// Runtime-minted lifetime ID.
        turn_id: String,
        /// Exact MAC-verified envelopes, never unsigned ownership claims.
        envelopes: Vec<IfcEnvelopeV1>,
    },
    /// Complete or cancel one authenticated ingress lifetime.
    FinishTurn {
        /// Runtime-minted lifetime ID.
        turn_id: String,
        /// Cancellation rather than normal completion (same safe reclamation).
        cancelled: bool,
    },
    /// Ingest exact verified envelopes already owned by this turn into its SSM.
    /// Multiple ingests precede generation; the runner forbids later ingestion.
    SsmIngestTurn {
        /// Runtime-minted turn ID.
        turn_id: String,
        /// MAC-sealed inputs; labels and payloads come from the trusted heap.
        envelopes: Vec<IfcEnvelopeV1>,
    },
    /// Ingest turn-owned attachment stub names, resolved and MAC-verified here.
    SsmIngestTurnHandles {
        /// Runtime-minted turn ID.
        turn_id: String,
        /// Opaque heap names; neither labels nor payloads are caller authored.
        handles: Vec<String>,
    },
    /// Generate UTF-8 text into an opaque managed heap handle. Binary output
    /// is refused so every output passes the C4 custody boundary.
    SsmGenerateTurn {
        /// Runtime-minted turn ID.
        turn_id: String,
        /// Maximum generated bytes (1 through 65536).
        n: u32,
    },
    /// Run one non-session generation (AR, diffusion, depth, world plan) for
    /// an active turn. Prompts are turn-owned handles; the output is sealed
    /// into a new managed handle, never returned as text.
    ModelGenerateTurn {
        /// Runtime-minted turn ID.
        turn_id: String,
        /// What the bound model is asked to do.
        request: crate::model_turn::ModelTurnRequest,
    },
    /// Track C `A2` session lease for an active turn: the first request takes
    /// one Touch ID; repeats within 15 minutes are approved from the lease.
    BeginSessionLease {
        /// Runtime-minted turn ID.
        turn_id: String,
    },
    /// Track C `A3` reveal of one sealed handle the turn owns: custody runs
    /// the ceremony and shows the value on the trusted display only. The
    /// caller never receives the plaintext.
    RevealTurnHandle {
        /// Runtime-minted turn ID.
        turn_id: String,
        /// A handle this turn owns.
        handle: String,
    },
    /// Ingest an output owned by an authenticated active scoped turn.
    IngestTurnToolOutput {
        /// Runtime-minted lifetime ID.
        turn_id: String,
        /// Signed lock server name.
        server: String,
        /// Signed lock tool name.
        tool_name: String,
        /// Live tools/list, checked against the lock.
        tools_list: String,
        /// Actual text/JSON output.
        payload: serde_bytes::ByteBuf,
        /// Optional raising-only hint.
        conf_hint: Option<Conf>,
        /// Source URI.
        source_uri: String,
    },
    /// Wrap an MCP tool return.
    IngestToolOutput {
        /// Server.
        server: String,
        /// Tool.
        tool_name: String,
        /// Live `tools/list` (JSON), verified against the lock's pin.
        tools_list: String,
        /// Payload (UTF-8 text / JSON).
        payload: serde_bytes::ByteBuf,
        /// Optional label hint; it can only **raise** the lock's floor.
        conf_hint: Option<Conf>,
        /// Canonical source URI (fallback entity key).
        source_uri: String,
    },
    /// Authorize one MCP / A2A tool call.
    AuthorizeToolCall {
        /// Server.
        server: String,
        /// Tool.
        tool_name: String,
        /// JCS-canonical JSON arguments (the bytes the PoP signature covers).
        args_jcs: serde_bytes::ByteBuf,
        /// `(argument name, capability handle)` pairs.
        arg_handles: Vec<(String, String)>,
        /// `PoPBiscuitWireV1` CBOR.
        wire_cbor: serde_bytes::ByteBuf,
        /// Ask UID 703 for the chained hardware ceremony if the tool needs it.
        step_up: bool,
    },
    /// `declassify_enum`.
    DeclassifyEnum {
        /// Agent label (receipts only).
        agent: String,
        /// Handle.
        handle: String,
        /// `K`.
        cardinality: u64,
        /// Schema.
        schema: String,
    },
    /// Sign a `Custody::ReversibleTokenize` grant for a workflow the signed
    /// Cedar bundle names (administrator only).
    IssueCustodyGrant {
        /// Workflow.
        workflow: String,
        /// TTL.
        ttl_s: i64,
    },
    /// Co-sign an `AbortedPreEgressTombstone`.
    CoSignTombstone {
        /// Slot.
        slot_rpc_seq: u64,
        /// Epoch.
        boot_epoch_id: String,
    },
    /// Release handles after a turn completes (authenticated administrator /
    /// client ingress only). QIF accounting and unrelated handles survive.
    ReleaseHandles {
        /// The completed turn's handles; every handle must still be live.
        handles: Vec<String>,
    },
    /// Wipe the capability heap.
    Wipe,
    /// Hot-swap or refresh the signed Cedar policy bundle (GAP-32).
    RefreshPolicy {
        /// Optional bundle JSON bytes. If omitted, the signed target is fetched
        /// from UID 702 over UDS. If given, the bytes must be byte-identical to
        /// that TUF-verified target or the call fails `EPERM POLICY_INLINE_UNSIGNED`
        /// (DEFECT-F-64); only `simulation` dev builds may load unsigned bytes.
        bundle_json: Option<serde_bytes::ByteBuf>,
    },
}

/// IPC responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IfcResponse {
    /// Status.
    Status(DaemonStatus),
    /// Bounded per-boot policy timing telemetry; no authorization material.
    PolicySli(crate::policy_sli::PolicySliSnapshot),
    /// Ack.
    Ok,
    /// Planner context (+ the turn's root token when requested).
    Plan {
        /// Planner context.
        context: PlanCompileContext,
        /// Root PoP-Biscuit for the turn.
        root_token: Option<serde_bytes::ByteBuf>,
    },
    /// Planner context with an authenticated ingress lifetime.
    TurnPlan {
        /// Runtime-minted lifetime ID.
        turn_id: String,
        /// Planner-visible context.
        context: PlanCompileContext,
        /// Optional scoped root token.
        root_token: Option<serde_bytes::ByteBuf>,
    },
    /// A completed authenticated plan; raw tool output never enters Starlark.
    PlanExecuted {
        /// Bounded textual return value (opaque Ref summaries only for outputs).
        return_value: String,
        /// Number of tools actually dispatched, not syntactic call sites.
        executed_tool_calls: usize,
        /// Runtime-assigned, MAC-verified output references in execution order.
        output_refs: Vec<IfcEnvelopeV1>,
    },
    /// Completed/cancelled lifetime and exact count of reclaimed handles.
    TurnFinished {
        /// Number of handles reclaimed; shared live references survive.
        released: usize,
    },
    /// Recovery acknowledgement; no handle, payload or holder key is returned.
    GatewayTurns {
        /// IDs still owned by this exact gateway, including pending SSM cleanup.
        active_turns: Vec<String>,
    },
    /// Envelope.
    Handle(IfcEnvelopeV1),
    /// An `A2` session lease approval (prompted, or served from the lease).
    SessionLeased {
        /// `d_jcs` of the approved intent (hex).
        d_jcs: String,
        /// Factors custody reports as proven.
        factors: Vec<String>,
    },
    /// A sealed record was shown on the trusted display after an approved
    /// `A3` ceremony; carries only the approved intent digest.
    Revealed {
        /// `d_jcs` of the approved intent (hex).
        d_jcs: String,
    },
    /// Decision.
    Decision(Decision),
    /// Custody grant (JSON of `ReversibleTokenizeGrant` fields).
    Grant {
        /// Workflow.
        workflow: String,
        /// Profile.
        profile: Profile,
        /// Expiry.
        expires_unix: i64,
        /// Signature.
        signature: serde_bytes::ByteBuf,
    },
    /// Tombstone signature.
    TombstoneSignature {
        /// Signature.
        signature: serde_bytes::ByteBuf,
        /// Public key.
        public_key: serde_bytes::ByteBuf,
    },
}

/// Configuration.
#[derive(Debug)]
pub struct IfcConfig {
    /// Profile.
    pub profile: Profile,
    /// Audit path.
    pub audit_path: Option<std::path::PathBuf>,
    /// Policy-grant signing key seed.
    pub policy_key: SigningKey,
    /// Biscuit authorizer limits.
    pub limits: AuthorizerLimits,
    /// Signed MCP lock.
    pub registry: ToolRegistry,
    /// Cedar bundle (`None`: the embedded default).
    pub cedar: Option<CedarEngine>,
    /// Persistent state (`<state>/ifc`): egress registry, tombstone key.
    pub state_dir: Option<std::path::PathBuf>,
    /// Mesh socket dir (for resolving TUF targets from UID 702).
    pub socket_dir: Option<std::path::PathBuf>,
    /// Dev mode (same UID).
    pub dev_same_uid: bool,
}

struct State {
    profile: Profile,
    socket_dir: Option<std::path::PathBuf>,
    dev_same_uid: bool,
    heap: CapabilityHeap,
    turns: crate::turn_lifecycle::TurnLifecycles,
    executors: std::collections::BTreeMap<String, Arc<execution::PlanExecutor>>,
    gateway_recovery: recovery::GatewayRecovery,
    pdp: Pdp,
    ledger: QifLedger,
    /// Where the ledger is sealed (`None`: in-memory, tests only).
    ledger_store: Option<enclave_core::sealed::SealedStore>,
    /// Why the ledger could not be loaded: every QIF settlement is refused
    /// until an operator re-initialises it (GAP-08: missing ⇒ deny).
    ledger_fault: Option<String>,
    /// Durable, monotone exposure provenance; independent of payload lifetime.
    exposure_store: Option<enclave_core::sealed::SealedStore>,
    delegation: DelegationManager,
    seq: RpcSequencer,
    journal: Option<AuditJournal>,
    _slab: enclave_core::slab::SecureSlabAllocator,
    policy_root_key: enclave_core::slab::RootKeyPage,
    tombstone_root_key: enclave_core::slab::RootKeyPage,
    policy_key: SigningKey,
    tombstone_key: SigningKey,
    egress: enclave_core::egress::EgressRegistry,
    pub flow_gate: crate::flow_fsm::FlowGate,
}

/// The service.
pub struct IfcService {
    state: Mutex<State>,
    registry: ToolRegistry,
    declassifier: Box<dyn Declassifier>,
    custody: Box<dyn CustodyPort>,
    ssm: Box<dyn crate::ssm::SsmPort>,
    dispatch: Box<dyn crate::plan::dispatch::ToolDispatchPort>,
    // Acquired before State for SSM work; Finish/Wipe release State before waiting.
    ssm_gate: Mutex<()>,
    // Turn whose runner generation holds `ssm_gate` right now, so Finish and
    // Wipe can cancel it instead of waiting out the runner call. Never held
    // across a call.
    generating: Mutex<Option<String>>,
    recovery_gate: Mutex<usize>,
}

impl std::fmt::Debug for IfcService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IfcService")
    }
}

/// Administrator = the operator CLI / client-ingress stand-in: `uid 0`
/// (admitted only as the signed CLI, GAP-02) or the single development UID.
fn is_admin(peer: &PeerCredentials) -> bool {
    peer.uid == 0 || peer.uid == enclave_core::ipc::geteuid()
}

/// Client ingress may use only scoped turn operations, never operator controls.
/// The socket layer has verified this dedicated executable's code identity.
fn is_ingress(peer: &PeerCredentials) -> bool {
    is_admin(peer) || (peer.uid == enclave_core::daemon::GATEWAY_UID
        && (!enclave_core::codesign::enforced() || peer.code_identity.as_ref()
            .is_some_and(|identity| identity.identifier == enclave_core::daemon::GATEWAY_IDENTIFIER)))
}

/// Everything resolved for one call before any engine runs.
struct Resolved {
    tool: ResolvedTool,
    request: ToolCallRequest,
    draft: IntentDraftV1,
}

impl IfcService {
    /// Start the service.
    pub fn start(
        cfg: IfcConfig,
        declassifier: Box<dyn Declassifier>,
        custody: Box<dyn CustodyPort>,
    ) -> EnclaveResult<Arc<Self>> {
        Self::start_with_ssm(cfg, declassifier, custody, Box::new(crate::ssm::NoSsm))
    }

    /// Start with the authenticated session runner used by daemon entry.
    pub fn start_with_ssm(
        cfg: IfcConfig,
        declassifier: Box<dyn Declassifier>,
        custody: Box<dyn CustodyPort>,
        ssm: Box<dyn crate::ssm::SsmPort>,
    ) -> EnclaveResult<Arc<Self>> {
        Self::start_with_dispatch(cfg, declassifier, custody, ssm, Box::new(crate::plan::dispatch::NoToolDispatch))
    }

    /// Start with a trusted tool transport. The port receives authority only
    /// after runtime authorization/accounting, and cannot supply output labels.
    pub fn start_with_dispatch(
        cfg: IfcConfig,
        declassifier: Box<dyn Declassifier>,
        custody: Box<dyn CustodyPort>,
        ssm: Box<dyn crate::ssm::SsmPort>,
        dispatch: Box<dyn crate::plan::dispatch::ToolDispatchPort>,
    ) -> EnclaveResult<Arc<Self>> {
        let epoch = enclave_core::seq::new_boot_epoch_id();
        let cedar = match cfg.cedar {
            Some(c) => c,
            None => {
                if let Some(ref dir) = cfg.socket_dir {
                    match crate::cedar_engine::fetch_cedar_bundle(dir, cfg.dev_same_uid) {
                        Ok(b) => match CedarEngine::from_bundle(&b) {
                            Ok(eng) => eng,
                            Err(_) => CedarEngine::default_bundle()?,
                        },
                        Err(_) => CedarEngine::default_bundle()?,
                    }
                } else {
                    CedarEngine::default_bundle()?
                }
            }
        };
        let journal = match &cfg.audit_path {
            Some(p) => Some(AuditJournal::open(
                p,
                DaemonId::AgentRuntime,
                epoch.clone(),
            )?),
            None => None,
        };
        // GAP-11: the tombstone key and the release record survive restarts.
        let (tombstone_key, egress) = match &cfg.state_dir {
            Some(d) => (
                SigningKey::from_bytes(&enclave_core::fsutil::load_or_create_seed(
                    &d.join("tombstone.key"),
                )?),
                enclave_core::egress::EgressRegistry::open(&d.join("egress"))?,
            ),
            None => (
                SigningKey::generate(&mut rand_core::OsRng),
                enclave_core::egress::EgressRegistry::ephemeral(),
            ),
        };
        // GAP-08: a stable K_vault (entity keys) and a sealed, rollback-checked
        // 24 h ledger. A missing, tampered or rolled-back ledger latches deny.
        let existing_installation = cfg.state_dir.as_ref().is_some_and(|dir|
            dir.join("qif-ledger.sealed").exists() || dir.join("qif-ledger.gen").exists());
        let (mut heap, ledger, ledger_store, ledger_fault) = match &cfg.state_dir {
            None => (
                CapabilityHeap::new(epoch.clone()),
                QifLedger::new(cfg.profile),
                None,
                None,
            ),
            Some(d) => {
                let heap = CapabilityHeap::with_vault_key(
                    epoch.clone(),
                    enclave_core::sealed::sealing_key(d, "k_vault")?,
                );
                match enclave_core::sealed::SealedStore::open(d, "qif-ledger") {
                    Ok((mut store, enclave_core::sealed::Loaded::Fresh)) => {
                        let l = QifLedger::new(cfg.profile);
                        store.save_json(&l)?;
                        (heap, l, Some(store), None)
                    }
                    Ok((store, enclave_core::sealed::Loaded::State(b))) => {
                        match enclave_core::sealed::decode::<QifLedger>(&b) {
                            Ok(l) if l.profile() == cfg.profile => (heap, l, Some(store), None),
                            Ok(_) => (
                                heap,
                                QifLedger::new(cfg.profile),
                                None,
                                Some("QIF_LEDGER_PROFILE_CHANGED".to_owned()),
                            ),
                            Err(e) => {
                                (heap, QifLedger::new(cfg.profile), None, Some(e.to_string()))
                            }
                        }
                    }
                    Err(e) => (heap, QifLedger::new(cfg.profile), None, Some(e.to_string())),
                }
            }
        };
        // F66: a peer retains its plaintext across reconnects, heap Wipe and
        // daemon restart. Persist the shared provenance independently of heap
        // contents. Existing installations without this record have unknown
        // historical exposure, so migrate to TOP rather than inventing a clean
        // history. SealedStore rejects partial deletion/tamper/rollback within
        // its documented filesystem threat model; startup fails closed.
        let exposure_store = match &cfg.state_dir {
            None => None, // Explicitly ephemeral test/developer service.
            Some(dir) => {
                let (mut store, loaded) =
                    enclave_core::sealed::SealedStore::open(dir, "literal-exposure")?;
                let observed = match loaded {
                    enclave_core::sealed::Loaded::State(bytes) =>
                        enclave_core::sealed::decode::<Label>(&bytes)?,
                    enclave_core::sealed::Loaded::Fresh if existing_installation => Label::TOP,
                    enclave_core::sealed::Loaded::Fresh => Label::DIRECTIVE,
                };
                heap.raise_literal_exposure(observed);
                store.save_json(&heap.literal_exposure())?;
                Some(store)
            }
        };
        let mut slab =
            enclave_core::slab::SecureSlabAllocator::new(&enclave_core::slab::EmteGate::default());
        let policy_root_key = slab.alloc_root_key(&cfg.policy_key.to_bytes())?;
        let tombstone_root_key = slab.alloc_root_key(&tombstone_key.to_bytes())?;
        Ok(Arc::new(Self {
            state: Mutex::new(State {
                profile: cfg.profile,
                socket_dir: cfg.socket_dir,
                dev_same_uid: cfg.dev_same_uid,
                heap,
                turns: crate::turn_lifecycle::TurnLifecycles::default(),
                executors: Default::default(),
                gateway_recovery: Default::default(),
                pdp: Pdp::new(cedar, epoch.clone(), cfg.profile, cfg.limits),
                ledger,
                ledger_store,
                ledger_fault,
                exposure_store,
                delegation: DelegationManager::new(),
                seq: RpcSequencer::new(epoch, 0),
                journal,
                _slab: slab,
                policy_root_key,
                tombstone_root_key,
                policy_key: cfg.policy_key,
                tombstone_key,
                egress,
                flow_gate: crate::flow_fsm::FlowGate::default(),
            }),
            registry: cfg.registry,
            declassifier,
            custody,
            ssm,
            dispatch,
            ssm_gate: Mutex::new(()),
            generating: Mutex::new(None),
            recovery_gate: Mutex::new(0),
        }))
    }

    /// Return the slab-allocated address ranges for the policy and tombstone root keys (tests).
    pub fn root_key_ranges(&self) -> EnclaveResult<Vec<(usize, usize)>> {
        let st = self.lock()?;
        Ok(vec![
            (
                st.policy_root_key.key_addr(),
                st.policy_root_key.one_past_end(),
            ),
            (
                st.tombstone_root_key.key_addr(),
                st.tombstone_root_key.one_past_end(),
            ),
        ])
    }

    /// Root public key that verifies this process's PoP-Biscuits.
    pub fn root_public(&self) -> EnclaveResult<enclave_crypto::biscuit_auth::PublicKey> {
        Ok(self.lock()?.pdp.root_public())
    }

    /// This process's boot epoch (UDS token clock caveats bind it).
    pub fn boot_epoch_id(&self) -> EnclaveResult<String> {
        Ok(self.lock()?.pdp.boot_epoch_id().to_owned())
    }

    /// Stored bytes behind a handle (tests and local audits only; never on IPC).
    #[doc(hidden)]
    pub fn payload_for_test(&self, handle: &str) -> EnclaveResult<Vec<u8>> {
        Ok(self.lock()?.heap.payload(handle)?.to_vec())
    }

    /// Set flow gate state for testing fault recovery and state transitions.
    #[doc(hidden)]
    pub fn set_flow_state_for_test(&self, state: crate::flow_fsm::FlowState) -> EnclaveResult<()> {
        self.lock()?.flow_gate = crate::flow_fsm::FlowGate::from_state(state);
        Ok(())
    }

    fn lock(&self) -> EnclaveResult<std::sync::MutexGuard<'_, State>> {
        self.state.lock().map_err(|_| err!(EIO, "STATE_POISONED"))
    }

    /// Derive planner metadata locally instead of trusting caller descriptions
    /// or parameter text (DEFECT-F-72). The root-token tool URI is unchanged.
    fn curate_tools(&self, tools: &[ToolSignature]) -> EnclaveResult<Vec<ToolSignature>> {
        tools
            .iter()
            .map(|t| {
                let raw = t
                    .name
                    .strip_prefix("mcp://")
                    .ok_or_else(|| err!(EINVAL, "ROOT_TOOL_NAME", "expected MCP URI"))?;
                let (server, name) = raw
                    .split_once('/')
                    .ok_or_else(|| err!(EINVAL, "ROOT_TOOL_NAME", "expected server/tool"))?;
                let valid = |s: &str| {
                    !s.is_empty()
                        && s.len() <= 128
                        && s.bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c))
                };
                if !valid(server) || !valid(name) {
                    fail!(EINVAL, "ROOT_TOOL_NAME");
                }
                let resolved = self.registry.resolve(server, name);
                let mut params: Vec<String> = resolved.spec.slots.keys().cloned().collect();
                if let Some(arg) = resolved.spec.row_count_arg {
                    params.push(arg);
                }
                params.sort();
                params.dedup();
                Ok(ToolSignature {
                    name: resolved.resource.name,
                    description: format!(
                        "{} operation ({:?}) in {}",
                        resolved.spec.canonical_verb,
                        resolved.resource.action_class,
                        resolved.resource.namespace
                    ),
                    params,
                })
            })
            .collect()
    }

    /// Before accepting an ingress, durably install a crash floor. If a crash
    /// or the final save fails after bytes enter the heap, startup sees TOP
    /// instead of an older clean provenance record. This is a write-ahead
    /// transaction under the service lock; no response is sent between saves.
    fn prepare_literal_ingress(st: &mut State) -> EnclaveResult<()> {
        st.turns.check_available()?;
        // Ingress itself does not spend QIF or authorize an observation. A
        // separate QIF fault must keep authorization/declassification latched,
        // but need not stop safely sealing new data. Exposure write failures
        // still raise the heap to TOP below, and a later successful ingress
        // never clears that monotone floor or the authorization latch.
        if let Some(store) = st.exposure_store.as_mut() {
            if let Err(error) = store.save_json(&Label::TOP) {
                st.heap.raise_literal_exposure(Label::TOP);
                st.ledger_fault = Some(format!("LITERAL_EXPOSURE_PREPARE: {error}"));
                return Err(error);
            }
        }
        Ok(())
    }

    /// Save before any response exposing a handle/result. On failure memory
    /// remains raised and the service latches all authorization until restart;
    /// no later successful request can hide the failed durable transition.
    fn persist_literal_exposure(st: &mut State) -> EnclaveResult<()> {
        if let Some(store) = st.exposure_store.as_mut() {
            if let Err(error) = store.save_json(&st.heap.literal_exposure()) {
                st.heap.raise_literal_exposure(Label::TOP);
                st.ledger_fault = Some(format!("LITERAL_EXPOSURE_PERSIST: {error}"));
                return Err(error);
            }
        }
        Ok(())
    }

    /// Resolve a call from the lock, the heap and the canonical arguments.
    fn resolve(
        &self,
        st: &State,
        server: &str,
        tool_name: &str,
        args_jcs: Vec<u8>,
        arg_handles: &[(String, String)],
        wire_cbor: Vec<u8>,
    ) -> EnclaveResult<Resolved> {
        let tool = self.registry.resolve(server, tool_name);
        let args: Value =
            serde_json::from_slice(&args_jcs).map_err(|e| err!(EINVAL, "ARGS_JSON", "{e}"))?;
        if !args.is_object() || enclave_core::jcs::canonicalize(&args)? != args_jcs {
            fail!(
                EINVAL,
                "ARGS_NOT_JCS",
                "arguments must be a JCS-canonical JSON object"
            );
        }
        let row_count = tool.row_count(&args)?;
        // The signed integer row-bound contract is a narrow T2 sanitizer:
        // row_count() has verified its type and range. Other structural fields
        // inherit exposure taint; bound literals may carry T3 as opaque data.
        let literal_structural = args.as_object().expect("checked object").keys().any(|key|
            tool.slot_kind(key) == SlotKind::AstStructural
                && tool.spec.row_count_arg.as_deref() != Some(key.as_str()));
        let arg_slots: Vec<(SlotKind, String)> = arg_handles
            .iter()
            .map(|(a, h)| (tool.slot_kind(a), h.clone()))
            .collect();
        let handles: Vec<String> = arg_handles.iter().map(|(_, h)| h.clone()).collect();
        let (input, _, _) = st.heap.join(&handles, st.heap.literal_exposure())?;
        let draft = IntentDraftV1 {
            action_class: tool.resource.action_class,
            profile: st.profile,
            data_class: input.c,
            tool_name: tool.resource.name.clone(),
            target_namespace: tool.resource.namespace.clone(),
            canonical_verb: tool.spec.canonical_verb.clone(),
            row_count_bound: row_count,
            arguments_jcs_sha256: hex::encode(sha2::Sha256::digest(&args_jcs)),
            canonical_arguments_blake3: blake3::hash(&args_jcs).to_hex().to_string(),
            policy_blake3: hex::encode(st.pdp.cedar_bundle_blake3()),
            qif_millibits_delta: tool.spec.qif_mb_per_call,
            org_root_mutation: tool.resource.mutates_root,
        };
        let request = ToolCallRequest {
            agent: String::new(),
            tool: tool.resource.clone(),
            args_jcs,
            arg_slots,
            literal_structural,
            row_count,
            qif_mb: tool.spec.qif_mb_per_call,
            hw_grant: false,
            wire_cbor,
        };
        Ok(Resolved {
            tool,
            request,
            draft,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn authorize_tool_call(
        &self,
        peer: &PeerCredentials,
        server: String,
        tool_name: String,
        args_jcs: Vec<u8>,
        arg_handles: Vec<(String, String)>,
        wire_cbor: Vec<u8>,
        step_up: bool,
        turn_id: Option<&str>,
    ) -> EnclaveResult<CallDecision> {
        // Phase 1 (locked): resolve every fact from enclave state.
        let mut r = {
            let st = self.lock()?;
            // Fence already-observed uncertainty before unlocked custody work.
            // A later failure cannot revoke a delegate already in flight.
            st.egress.ensure_healthy()?;
            st.turns.check_available()?;
            if let Some(id) = turn_id {
                let handles = arg_handles.iter().map(|(_, h)| h.clone()).collect::<Vec<_>>();
                st.turns.check_handle_names(peer, id, &handles)?;
            }
            if st.flow_gate.state() == crate::flow_fsm::FlowState::QuarantineAbort {
                fail!(
                    EPERM,
                    "FLOW_GATE_QUARANTINE_ABORT",
                    "flow gate is in QuarantineAbort state"
                );
            }
            self.resolve(&st, &server, &tool_name, args_jcs, &arg_handles, wire_cbor)?
        };
        // Phase 2 (unlocked): the hardware ceremony may take up to 10 s and
        // must not block other callers of this daemon (GAP-39).
        let mut stepup = None;
        let mut dispatch_expiry = None;
        if step_up && r.tool.resource.action_class >= ActionClass::A3 {
            let s = self.custody.authorize_intent(&r.draft)?;
            dispatch_expiry = Some(s.lifetime.dispatch_expiry()?);
            r.request.hw_grant = true;
            stepup = Some(s);
        }
        // The governed slot this call occupies (GAP-27).
        let (slot_epoch, slot) = self.custody.allocate_slot()?;
        // Phase 3 (locked): conjunctive decision on the resolved request.
        let mut st = self.lock()?;
        // Recheck after the unlocked ceremony before local decision/debit work.
        st.egress.ensure_healthy()?;
        st.turns.check_available()?;
        if let Some(id) = turn_id {
            let handles = arg_handles.iter().map(|(_, h)| h.clone()).collect::<Vec<_>>();
            st.turns.check_handle_names(peer, id, &handles)?;
        }
        if st.flow_gate.state() == crate::flow_fsm::FlowState::QuarantineAbort {
            fail!(
                EPERM,
                "FLOW_GATE_QUARANTINE_ABORT",
                "flow gate is in QuarantineAbort state"
            );
        }
        let (now_mach, now_utc) = (
            enclave_core::clock::boot_clock_ns(),
            enclave_core::audit::now_utc_ms(),
        );
        let st = &mut *st;
        if let Some(fault) = &st.ledger_fault {
            fail!(EACCES, "QIF_LEDGER_LATCHED", "{fault}");
        }
        let handles: Vec<String> = r.request.arg_slots.iter().map(|(_, h)| h.clone()).collect();
        let (current_input, _, _) = st.heap.join(&handles, st.heap.literal_exposure())?;
        if current_input.c != r.draft.data_class {
            fail!(EAGAIN, "LITERAL_EXPOSURE_CHANGED", "provenance changed during intent resolution; retry");
        }
        let d = st
            .pdp
            .authorize(&st.heap, peer, &r.request, now_mach, now_utc)?;
        if d.allow {
            if r.tool.resource.action_class >= ActionClass::A3 && dispatch_expiry.is_none() {
                fail!(EACCES,"TOOL_AUTHORITY_LIFETIME_REQUIRED");
            }
            if let Some(expiry) = &dispatch_expiry {expiry.check()?;}
            // The service only releases calls from a locally accounted tree.
            // Denials and parse errors must propagate before an ALLOW response.
            let wire =
                enclave_crypto::pop_biscuit::PopBiscuitWireV1::from_cbor(&r.request.wire_cbor)?;
            let token = enclave_crypto::biscuit_auth::Biscuit::from(
                &wire.sealed_biscuit,
                &st.pdp.root().public(),
            )
            .map_err(|e| err!(EACCES, "BISCUIT_DECODE", "{e}"))?;
            st.delegation
                .record_call_with_charge(&token, r.request.qif_mb)?;
            // Debit every constituent entity and persist before recording that
            // authorization may leave the daemon. A failed later operation may
            // conservatively consume a call/charge, but can never refund it.
            if r.request.qif_mb > 0 {
                let handles: Vec<String> = r
                    .request
                    .arg_slots
                    .iter()
                    .map(|(_, handle)| handle.clone())
                    .collect();
                let (_, entities, unstructured) =
                    st.heap.join(&handles, enclave_core::label::Label::BOTTOM)?;
                st.ledger.charge(
                    &enclave_core::qif::QifCharge {
                        entities,
                        conf: r.draft.data_class,
                        // Literal provenance has no complete per-entity set;
                        // charge the global pool as well as named entities.
                        unstructured: unstructured || st.heap.literal_exposure().c >= Conf::C3,
                        millibits: r.request.qif_mb,
                    },
                    now_utc,
                )?;
                if let Some(store) = st.ledger_store.as_mut() {
                    if let Err(e) = store.save_json(&st.ledger) {
                        st.ledger_fault = Some(e.to_string());
                        return Err(e);
                    }
                }
            }
            st.egress.released(&slot_epoch, slot)?;
            if stepup.is_some()
                && (st.flow_gate.state() == crate::flow_fsm::FlowState::OpaqueHandleSealed
                    || st.flow_gate.state() == crate::flow_fsm::FlowState::HwCustodyStepup)
            {
                st.flow_gate.on(crate::flow_fsm::FlowEvent::HwVerified)?;
            }
        }
        let ev = json!({"event": "TOOL_CALL", "slot": slot, "tool": r.request.tool.name, "annotated": r.tool.annotated, "rows": r.request.row_count,
                        "qif_mb": if d.allow { r.request.qif_mb } else { 0 },
                        "decision": if d.allow {"ALLOW"} else {"DENY"}, "cedar": d.cedar_allow, "biscuit": d.biscuit_allow,
                        "hw_d_jcs": stepup.as_ref().map(|s| s.d_jcs.clone()), "mcp_lock_blake3": self.registry.lock_blake3(), "eval_ns": d.eval_ns});
        if let Some(j) = st.journal.as_mut() {
            j.append_at(&slot_epoch, slot, ev)?;
        }
        if let Some(expiry) = &dispatch_expiry {expiry.check()?;}
        Ok(CallDecision {decision:d,dispatch_expiry})
    }

    fn ingest_tool_output(
        &self,
        turn_owner: Option<(&PeerCredentials, &str)>,
        server: &str,
        tool_name: &str,
        tools_list: &str,
        raw: SecretBytes,
        conf_hint: Option<Conf>,
        source_uri: &str,
        parents: &[String],
    ) -> EnclaveResult<IfcResponse> {
        {
            let st = self.lock()?;
            // Do not start a scrub delegate when uncertainty is already known here.
            st.egress.ensure_healthy()?;
            st.turns.check_available()?;
        }
        if let Some((peer, id)) = turn_owner {
            if !is_ingress(peer) { fail!(EPERM, "SUBMIT_TURN_INGRESS_ONLY"); }
            let st = self.lock()?;
            st.turns.check_append(peer, id)?;
            st.turns.check_handle_names(peer, id, parents)?;
        }
        let tl: Value =
            serde_json::from_str(tools_list).map_err(|e| err!(EINVAL, "TOOLS_LIST_JSON", "{e}"))?;
        let digest = self.registry.verify_tools_list(server, &tl)?;
        let tool = self.registry.resolve(server, tool_name);
        let text = std::str::from_utf8(raw.expose()).map_err(|_| {
            err!(
                EPERM,
                "TOOL_OUTPUT_NOT_TEXT",
                "outputs must be UTF-8 so C4 spans can be found"
            )
        })?;
        // Labels only rise: lock floor, unannotated (C3), caller hint, scanner.
        let mut conf = tool.spec.output_conf.max(conf_hint.unwrap_or(Conf::C1));
        if !tool.annotated {
            conf = conf.max(Conf::C3);
        }
        let entity_ids = tool.entity_ids(raw.expose());
        let has_c4 = enclave_core::pii::scan(text).iter().any(|f| f.kind.is_c4());
        // GAP-07: C4 never rests here — UID 703 erases or seals it first.
        let (stored, tier) = if has_c4 {
            conf = Conf::C4;
            let scrubbed = StagedToolOutput::new(self.custody.scrub_text(text, tool.spec.max_rows > 1)?.into_bytes());
            // String::into_bytes above guarantees UTF-8. Keep an impossible
            // invariant failure conservative while retaining the private owner.
            let scrubbed_text = std::str::from_utf8(scrubbed.bytes())
                .map_err(|_| err!(EPERM, "TOOL_OUTPUT_NOT_TEXT"))?;
            if enclave_core::pii::scan(scrubbed_text)
                .iter()
                .any(|f| f.kind.is_c4())
            {
                fail!(EACCES, "C4_SURVIVED_SCRUB");
            }
            let tier = if scrubbed_text.contains("SYNTH-") {
                VaultTier::A4
            } else {
                VaultTier::None
            };
            (scrubbed, tier)
        } else {
            (StagedToolOutput::new(raw.expose().to_vec()), VaultTier::None)
        };
        drop(raw);
        let (slot_epoch, slot) = self.custody.allocate_slot()?;
        let mut st = self.lock()?;
        // Scrub/slot work ran unlocked; refuse before new local heap effects.
        st.egress.ensure_healthy()?;
        if st.flow_gate.state() == crate::flow_fsm::FlowState::QuarantineAbort {
            fail!(
                EPERM,
                "FLOW_GATE_QUARANTINE_ABORT",
                "flow gate is in QuarantineAbort state"
            );
        }
        let st = &mut *st;
        st.turns.check_available()?;
        if let Some((peer, id)) = turn_owner {
            st.turns.check_append(peer, id)?;
            st.turns.check_handle_names(peer, id, parents)?;
        }
        Self::prepare_literal_ingress(st)?;
        // From this take to PendingPayload adoption in heap ingress there is
        // no fallible operation: remaining arguments are plain field borrows.
        let stored = stored.into_vec();
        let env = st.heap.ingest_derived_tool_output(
            &tool.resource.name,
            &digest,
            stored,
            conf,
            &entity_ids,
            source_uri,
            tier,
            parents,
        )?;
        if let Some((_, id)) = turn_owner { st.turns.append(id, env.handle.clone()); }
        Self::persist_literal_exposure(st)?;
        if st.flow_gate.state() == crate::flow_fsm::FlowState::CapabilityExec
            || st.flow_gate.state() == crate::flow_fsm::FlowState::OpaqueHandleSealed
        {
            st.flow_gate.on(crate::flow_fsm::FlowEvent::ToolReturn)?;
        }
        st.egress.released(&slot_epoch, slot)?;
        if let Some(j) = st.journal.as_mut() {
            j.append_at(&slot_epoch, slot, json!({"event": "TOOL_OUTPUT_SEALED", "slot": slot, "qif_mb": 0, "handle": env.handle, "label": env.label, "annotated": tool.annotated, "c4_scrubbed": has_c4}))?;
        }
        Ok(IfcResponse::Handle(env))
    }

    fn ssm_ingest(&self, peer:&PeerCredentials, id:&str, envelopes:Vec<IfcEnvelopeV1>) -> EnclaveResult<IfcResponse> {
        if !is_ingress(peer) {fail!(EPERM,"SUBMIT_TURN_INGRESS_ONLY");}
        if envelopes.is_empty() || envelopes.len()>64 {fail!(E2BIG,"SSM_INPUT_BOUNDS");}
        let _gate=self.ssm_gate.lock().map_err(|_|err!(EIO,"SSM_LOCK"))?;
        let (session, first, inputs)={
            let mut st=self.lock()?;
            if st.flow_gate.state()==crate::flow_fsm::FlowState::QuarantineAbort {fail!(EPERM,"FLOW_GATE_QUARANTINE_ABORT");}
            st.turns.check_inputs(peer,id,&envelopes,&st.heap)?;
            let previous=st.turns.session(id);
            if previous.as_ref().is_some_and(|s|!s.healthy || s.generated) {fail!(EPERM,"SSM_SESSION_CLOSING");}
            let mut parents=previous.as_ref().map(|s|s.parents.clone()).unwrap_or_default();
            for env in &envelopes {if !parents.contains(&env.handle){parents.push(env.handle.clone());}}
            if parents.len()>64 {fail!(E2BIG,"PROVENANCE_FANIN_EXCEEDED");}
            let old_floor=previous.as_ref().map(|s|s.floor).unwrap_or(Label::BOTTOM);
            // Also checks cumulative entity fan-in before any remote mutation.
            let (floor,_,_)=st.heap.join(&parents,old_floor)?;
            let mut inputs=Vec::new(); let mut bytes=0usize;
            for env in &envelopes {
                let payload=st.heap.payload(&env.handle)?;bytes=bytes.saturating_add(payload.len());
                if bytes>250*1024 {fail!(E2BIG,"SSM_INPUT_BOUNDS");}
                inputs.push((env.label,SecretBytes::from_slice(payload)));
            }
            let session=crate::turn_lifecycle::SsmTurn {
                scope:previous.as_ref().map(|s|s.scope).unwrap_or_else(enclave_core::rng::bytes32),
                floor, output_floor:previous.as_ref().map(|s|s.output_floor).unwrap_or(Label::BOTTOM), parents, healthy:false, generated:false,
            };
            // Record BEFORE fork: even a lost successful reply is cleanable.
            st.turns.set_session(id,session.clone());
            (session,previous.is_none(),inputs)
        };
        if first {self.ssm.fork(session.scope,session.floor)?;}
        for (label,bytes) in inputs {self.ssm.ingest(session.scope,label,bytes.expose())?;}
        let mut st=self.lock()?;st.turns.active(peer,id)?;
        let mut ready=session;ready.healthy=true;st.turns.set_session(id,ready);
        Ok(IfcResponse::Ok)
    }

    fn ssm_generate(&self,peer:&PeerCredentials,id:&str,n:u32)->EnclaveResult<IfcResponse> {
        if !is_ingress(peer) {fail!(EPERM,"SUBMIT_TURN_INGRESS_ONLY");}
        if !(1..=65536).contains(&n) {fail!(E2BIG,"SSM_OUTPUT_BOUNDS");}
        let _gate=self.ssm_gate.lock().map_err(|_|err!(EIO,"SSM_LOCK"))?;
        let mut session={
            let mut st=self.lock()?;
            if st.flow_gate.state()==crate::flow_fsm::FlowState::QuarantineAbort {fail!(EPERM,"FLOW_GATE_QUARANTINE_ABORT");}
            st.turns.check_append(peer,id)?;
            let mut session=st.turns.session(id).ok_or_else(||err!(EPERM,"SSM_INPUT_REQUIRED"))?;
            if !session.healthy {fail!(EPERM,"SSM_SESSION_CLOSING");}
            // Conservatively poison any uncertain runner result. Recovery is
            // explicit Finish, never a hidden refork discarding history.
            session.healthy=false;st.turns.set_session(id,session.clone());session
        };
        let generating=self.mark_generating(id)?;
        let result=self.ssm.generate(session.scope,n);
        drop(generating);
        let result=result?;
        if !session.floor.leq(result.label) {fail!(EACCES,"SSM_LABEL_DOWNGRADE");}
        if result.bytes.len()>n as usize {fail!(E2BIG,"SSM_OUTPUT_BOUNDS");}
        let text=std::str::from_utf8(result.bytes.expose()).map_err(|_|err!(EPERM,"SSM_OUTPUT_NOT_TEXT"))?;
        let mut floor=session.output_floor.join(result.label).join(MODEL_OUTPUT_FLOOR);
        let bytes=self.scrub_model_text(text,&mut floor,"SSM_OUTPUT_BOUNDS")?;
        let mut st=self.lock()?;let st=&mut *st;
        // Finish/Wipe may have begun during generation or custody IPC. No late
        // publication may resurrect a completed lifetime.
        st.turns.check_append(peer,id)?;
        if st.flow_gate.state()==crate::flow_fsm::FlowState::QuarantineAbort {fail!(EPERM,"FLOW_GATE_QUARANTINE_ABORT");}
        Self::prepare_literal_ingress(st)?;
        let env=st.heap.derive(&session.parents,floor,bytes.expose().to_vec(),"ssm-output")?;
        st.turns.append(id,env.handle.clone());
        Self::persist_literal_exposure(st)?;
        session.floor=session.floor.join(result.label);session.output_floor=floor;session.healthy=true;session.generated=true;
        st.turns.set_session(id,session);
        Ok(IfcResponse::Handle(env))
    }

    // Model text is untrusted: raise to C4 and scrub when the scan finds C4
    // material, and refuse if any survives. Returns the bytes to seal.
    fn scrub_model_text(&self,text:&str,floor:&mut Label,bounds:&'static str)->EnclaveResult<SecretBytes> {
        if !enclave_core::pii::scan(text).iter().any(|f|f.kind.is_c4()) {return Ok(SecretBytes::from_slice(text.as_bytes()));}
        floor.c=Conf::C4;
        if text.len()>MAX_SCRUB_BYTES {fail!(E2BIG,bounds);}
        let scrubbed=self.custody.scrub_text(text,true)?;
        if enclave_core::pii::scan(&scrubbed).iter().any(|f|f.kind.is_c4()) {fail!(EACCES,"C4_SURVIVED_SCRUB");}
        Ok(SecretBytes::new(scrubbed.into_bytes()))
    }

    /// Non-session generation for one active turn. The prompt is a verified
    /// handle this turn owns; output is sealed and never returned as text.
    /// Record `id` as the turn generating under `ssm_gate` until the guard drops.
    fn mark_generating(&self,id:&str)->EnclaveResult<GeneratingGuard<'_>> {
        *self.generating.lock().map_err(|_|err!(EIO,"GENERATING_LOCK"))?=Some(id.to_owned());
        Ok(GeneratingGuard(&self.generating))
    }

    /// Stop the runner generation in flight for `id` (any turn when `None`).
    /// Best effort and never waits for the gate: a late result is discarded
    /// by the turn lifecycle either way.
    fn cancel_generation_of(&self,id:Option<&str>) {
        let active=self.generating.lock().ok().and_then(|g|g.clone());
        if active.is_some_and(|turn|id.is_none_or(|id|id==turn)) {
            let _=self.ssm.cancel_generation();
        }
    }

    /// Track C `A2` session lease. Custody keys the lease on the turn (the
    /// session scope in this deployment), so later `A2` approvals for the same
    /// turn within 15 minutes need no prompt. The ceremony runs unlocked.
    fn session_lease(&self,peer:&PeerCredentials,id:&str)->EnclaveResult<IfcResponse> {
        if !is_ingress(peer) {fail!(EPERM,"SUBMIT_TURN_INGRESS_ONLY");}
        let draft={
            let st=self.lock()?;
            if st.flow_gate.state()==crate::flow_fsm::FlowState::QuarantineAbort {fail!(EPERM,"FLOW_GATE_QUARANTINE_ABORT");}
            st.turns.check_append(peer,id)?;
            use sha2::Digest;
            let scope=[b"mcpmac.a2-session-lease.v1\0".as_slice(),id.as_bytes()].concat();
            IntentDraftV1 {
                action_class:ActionClass::A2, profile:st.profile, data_class:enclave_core::label::Conf::C1,
                tool_name:"enclave://session/lease".into(), target_namespace:"session".into(),
                canonical_verb:"Lease".into(), row_count_bound:1,
                arguments_jcs_sha256:hex::encode(sha2::Sha256::digest(&scope)),
                // Custody's lease table reads its root digest from here.
                canonical_arguments_blake3:blake3::hash(&scope).to_hex().to_string(),
                policy_blake3:hex::encode(st.pdp.cedar_bundle_blake3()), qif_millibits_delta:0,
                org_root_mutation:false,
            }
        };
        let approval=self.custody.authorize_intent(&draft)?;
        Ok(IfcResponse::SessionLeased {d_jcs:approval.d_jcs,factors:approval.factors})
    }

    /// Track C `A3` reveal. The value and its label are read under the state
    /// lock; the ceremony (up to 10 s) runs without it, as tool step-up does.
    fn reveal_handle(&self,peer:&PeerCredentials,id:&str,handle:&str)->EnclaveResult<IfcResponse> {
        if !is_ingress(peer) {fail!(EPERM,"SUBMIT_TURN_INGRESS_ONLY");}
        let (value,draft)={
            let st=self.lock()?;
            if st.flow_gate.state()==crate::flow_fsm::FlowState::QuarantineAbort {fail!(EPERM,"FLOW_GATE_QUARANTINE_ABORT");}
            st.turns.check_append(peer,id)?;
            st.turns.check_handle_names(peer,id,&[handle.to_owned()])?;
            let label=st.heap.get(handle)?.envelope.label;
            // C4 never leaves custody's own vault, revealed or not.
            if label.c>=enclave_core::label::Conf::C4 {fail!(EACCES,"REVEAL_C4_REFUSED");}
            let value=SecretBytes::from_slice(st.heap.payload(handle)?);
            let draft=IntentDraftV1 {
                action_class:ActionClass::A3, profile:st.profile, data_class:label.c,
                // UID 703 overrides tool, verb and bound, and binds the value's digests.
                tool_name:"enclave://reveal/model-output".into(), target_namespace:"turn".into(),
                canonical_verb:"Reveal".into(), row_count_bound:1,
                arguments_jcs_sha256:String::new(), canonical_arguments_blake3:String::new(),
                policy_blake3:hex::encode(st.pdp.cedar_bundle_blake3()), qif_millibits_delta:0,
                org_root_mutation:false,
            };
            (value,draft)
        };
        let d_jcs=self.custody.reveal(value.expose(),&draft)?;
        Ok(IfcResponse::Revealed { d_jcs })
    }

    fn model_generate(&self,peer:&PeerCredentials,id:&str,req:crate::model_turn::ModelTurnRequest)->EnclaveResult<IfcResponse> {
        if !is_ingress(peer) {fail!(EPERM,"SUBMIT_TURN_INGRESS_ONLY");}
        req.validate()?;
        // Same gate as session generation and Finish: no generation races a
        // completing turn, and the runner sees one caller at a time.
        let _gate=self.ssm_gate.lock().map_err(|_|err!(EIO,"SSM_LOCK"))?;
        let (prompt,parents)={
            let st=self.lock()?;
            if st.flow_gate.state()==crate::flow_fsm::FlowState::QuarantineAbort {fail!(EPERM,"FLOW_GATE_QUARANTINE_ABORT");}
            st.turns.check_append(peer,id)?;
            match req.prompt() {
                Some(handle) => {
                    let handles=vec![handle.to_owned()];
                    st.turns.check_handle_names(peer,id,&handles)?;
                    let payload=st.heap.payload(handle)?;
                    if payload.len()>MAX_PROMPT_BYTES {fail!(E2BIG,"MODEL_TURN_INPUT_BOUNDS");}
                    (Some(SecretBytes::from_slice(payload)),handles)
                }
                None => (None,Vec::new()),
            }
        };
        let call=crate::model_turn::RunnerCall::of(&req,prompt.as_ref().map(|p|p.expose()))?;
        let generating=self.mark_generating(id)?;
        let reply=self.ssm.model(&call);
        drop(generating);
        let output=SecretBytes::new(reply?.into_sealed_bytes()?);
        if output.expose().len()>crate::model_turn::MAX_MODEL_TURN_BYTES as usize {fail!(E2BIG,"MODEL_TURN_OUTPUT_BOUNDS");}
        let text=std::str::from_utf8(output.expose()).map_err(|_|err!(EPERM,"MODEL_OUTPUT_NOT_TEXT"))?;
        let mut floor=MODEL_OUTPUT_FLOOR;
        let bytes=self.scrub_model_text(text,&mut floor,"MODEL_TURN_OUTPUT_BOUNDS")?;
        let mut st=self.lock()?;let st=&mut *st;
        // Finish/Wipe may have begun during generation; never resurrect a lifetime.
        st.turns.check_append(peer,id)?;
        if st.flow_gate.state()==crate::flow_fsm::FlowState::QuarantineAbort {fail!(EPERM,"FLOW_GATE_QUARANTINE_ABORT");}
        Self::prepare_literal_ingress(st)?;
        let env=st.heap.derive(&parents,floor,bytes.expose().to_vec(),"model-output")?;
        st.turns.append(id,env.handle.clone());
        Self::persist_literal_exposure(st)?;
        Ok(IfcResponse::Handle(env))
    }

    // Shared compilation/minting transaction for legacy and recoverable turns.
    fn begin_turn_locked(&self, st:&mut State, peer:&PeerCredentials, turn:UserTurnV1,
        attachments:Vec<(String,serde_bytes::ByteBuf)>, tools:Vec<ToolSignature>,
        holder_pk:Option<[u8;32]>, budget_mb:i64,retained_limit:Option<usize>)->EnclaveResult<(IfcResponse,Option<Value>,usize)> {
        if !is_ingress(peer) { fail!(EPERM, "SUBMIT_TURN_INGRESS_ONLY"); }
        if !st.dev_same_uid && peer.audit_token.is_none() {fail!(EPERM,"TURN_OWNER_IDENTITY_REQUIRED");}
        st.turns.check_begin(peer)?;
        if !(0..=12_000).contains(&budget_mb) || attachments.len()>64
            || attachments.iter().map(|(_,b)|b.len()).sum::<usize>()>4*1024*1024 { fail!(EINVAL,"TURN_BOUNDS"); }
        let tools=self.curate_tools(&tools)?;
        // An already executing global gate need not advance again.
        // Quarantine/hardware/yank states retain their existing denial.
        if st.flow_gate.state()!=crate::flow_fsm::FlowState::CapabilityExec {
            st.flow_gate.on(crate::flow_fsm::FlowEvent::PlanAccepted)?;
        }
        Self::prepare_literal_ingress(st)?;
        let compiled=compile_turn(&mut st.heap,&turn,attachments.into_iter().map(|(h,b)|(h,b.into_vec())).collect(),&tools);
        if let Err(error)=Self::persist_literal_exposure(st) {
            if let Ok((_,handles))=&compiled {st.heap.release(handles)?;}
            return Err(error);
        }
        let (context,handles)=compiled?;
        let internal = holder_pk.is_none().then(execution::PlanExecutor::new);
        let minted: EnclaveResult<(Option<serde_bytes::ByteBuf>,Option<[u8;32]>,Option<Vec<u8>>)>=(|| {
            let pk = holder_pk.unwrap_or_else(|| internal.as_ref().expect("internal holder").public_key());
            let allowed:Vec<_>=tools.iter().map(|t|t.name.clone()).collect();
            let token=st.delegation.mint_root(&st.pdp,&pk,&peer.channel_binding(),budget_mb,&allowed)?;
            let root=DelegationManager::tracked_root(&token);
            let bytes=match token.to_vec() {Ok(bytes)=>bytes,Err(error)=>{st.delegation.retire_root(root);return Err(err!(EIO,"BISCUIT_SER","{error}"));}};
            if internal.is_some() { Ok((None,Some(root),Some(bytes))) }
            else { Ok((Some(serde_bytes::ByteBuf::from(bytes)),Some(root),None)) }
        })();
        let (root_token,root,private_token)=match minted {Ok(value)=>value,Err(error)=>{st.heap.release(&handles)?;return Err(error);}};
        // The random identifier has a fixed 64-byte encoding. Check the exact
        // retained response/token size before inserting a lifetime. Refusal
        // rolls back this turn's heap/root only; observed exposure stays raised.
        let retained=(||->EnclaveResult<usize> {
            let Some(limit)=retained_limit else {return Ok(0);};
            let bytes=enclave_core::ipc::to_cbor(&IfcResponse::TurnPlan {turn_id:"0".repeat(64),
                context:context.clone(),root_token:root_token.clone()})?.len()
                .saturating_add(private_token.as_ref().map_or(0,Vec::len));
            if bytes>limit {fail!(E2BIG,"GATEWAY_RECOVERY_BYTES");}
            Ok(bytes)
        })();
        let retained_bytes=match retained {Ok(bytes)=>bytes,Err(error)=>{
            st.heap.release(&handles)?;if let Some(root)=root{st.delegation.retire_root(root);}return Err(error);
        }};
        let turn_id=match st.turns.begin(peer.clone(),handles.clone(),root) {
            Ok(id)=>id,
            Err(error)=>{st.heap.release(&handles)?;if let Some(root)=root{st.delegation.retire_root(root);}return Err(error);}
        };
        if let (Some(mut executor),Some(token))=(internal,private_token) {
            executor.token=token;
            executor.allowed_tools=tools.iter().map(|tool|tool.name.clone()).collect();
            st.executors.insert(turn_id.clone(),Arc::new(executor));
        }
        Ok((IfcResponse::TurnPlan {turn_id,context,root_token},Some(json!({"event":"SCOPED_TURN_COMPILED"})),retained_bytes))
    }

    fn finish_turn(&self,peer:&PeerCredentials,id:&str,cancelled:bool)->EnclaveResult<IfcResponse> {
        self.finish_turn_internal(peer,id,cancelled,false)
    }

    fn finish_turn_internal(&self,peer:&PeerCredentials,id:&str,cancelled:bool,recovery:bool)->EnclaveResult<IfcResponse> {
        if !is_ingress(peer) {fail!(EPERM,"SUBMIT_TURN_INGRESS_ONLY");}
        let executor = {
            let mut st=self.lock()?; st.turns.close(peer,id)?;
            let executor=st.executors.get(id).cloned();
            if let Some(executor)=&executor {executor.cancel();}
            executor
        };
        // The turn is closed: its in-flight generation can only be discarded.
        self.cancel_generation_of(Some(id));
        let _execution = executor.as_ref().map(|e| if recovery {
            e.gate.try_lock().map_err(|_|err!(EAGAIN,"TURN_RECOVERY_BUSY"))
        } else {e.gate.lock().map_err(|_|err!(EIO,"PLAN_EXECUTION_LOCK"))}).transpose()?;
        let _gate=if recovery {self.ssm_gate.try_lock().map_err(|_|err!(EAGAIN,"TURN_RECOVERY_BUSY"))?}
            else {self.ssm_gate.lock().map_err(|_|err!(EIO,"SSM_LOCK"))?};
        let scope=self.lock()?.turns.session(id).map(|s|s.scope);
        if let Some(scope)=scope {self.ssm.exit(scope)?;}
        let mut st=self.lock()?;let st=&mut *st;
        st.turns.clear_session(id);
        let (released,root)=st.turns.finish(peer,id,&mut st.heap)?;
        if let Some(root)=root {st.delegation.retire_root(root);}
        st.executors.remove(id);
        st.gateway_recovery.retire_turn(id);
        st.gateway_recovery.prune_finished(&st.turns);
        let seq=st.seq.next()?;
        if let Some(j)=st.journal.as_mut(){j.append(seq,json!({"event":"TURN_FINISHED","cancelled":cancelled,"released":released}))?;}
        Ok(IfcResponse::TurnFinished {released})
    }

    fn wipe(&self,peer:&PeerCredentials)->EnclaveResult<IfcResponse> {
        if !is_admin(peer) {fail!(EPERM,"WIPE_PEER_REJECTED");}
        let executors = {
            let mut st=self.lock()?;
            let executors=st.executors.values().cloned().collect::<Vec<_>>();
            for executor in &executors {executor.cancel();}
            // A failed remote exit leaves local memory already sterile. A
            // retry must not manufacture quarantine by replaying SleepOrLock
            // from SterileWiped. Existing quarantine is never cleared here.
            if st.flow_gate.state()!=crate::flow_fsm::FlowState::SterileWiped {
                let _=st.flow_gate.on(crate::flow_fsm::FlowEvent::SleepOrLock);
            }
            for root in st.turns.emergency_wipe(){st.delegation.retire_root(root);}
            st.heap.wipe();
            executors
        };
        self.cancel_generation_of(None);
        let _executions=executors.iter().map(|e|e.gate.lock().map_err(|_|err!(EIO,"PLAN_EXECUTION_LOCK"))).collect::<EnclaveResult<Vec<_>>>()?;
        self.lock()?.executors.clear();
        let _gate=self.ssm_gate.lock().map_err(|_|err!(EIO,"SSM_LOCK"))?;
        let scopes=self.lock()?.turns.pending_scopes();
        let mut failed=None;
        for (id,scope) in scopes {
            match self.ssm.exit(scope) {
                Ok(())=>self.lock()?.turns.clear_session(&id),
                Err(error)=>{if failed.is_none(){failed=Some(error);}},
            }
        }
        let mut st=self.lock()?;st.turns.complete_emergency();
        if !st.turns.cleanup_pending() {st.gateway_recovery.clear_active();}
        let seq=st.seq.next()?;
        if let Some(j)=st.journal.as_mut(){j.append(seq,json!({"event":"HEAP_WIPED","remote_cleanup_pending":failed.is_some()}))?;}
        if let Some(error)=failed {return Err(error);}
        Ok(IfcResponse::Ok)
    }

    /// Handle one request.
    pub fn handle(&self, peer: &PeerCredentials, req: IfcRequest) -> EnclaveResult<IfcResponse> {
        // This auxiliary identity never inherits other daemons' legacy/global
        // operations simply because it can reach the same socket.
        if peer.uid == enclave_core::daemon::GATEWAY_UID && !matches!(&req,
            IfcRequest::Status | IfcRequest::BeginTurn {..} | IfcRequest::BeginGatewayTurn {..}
            | IfcRequest::CancelGatewaySubmission {..} | IfcRequest::RecoverGatewayTurns | IfcRequest::ExecuteTurnPlan {..}
            | IfcRequest::RetainTurnHandles {..} | IfcRequest::FinishTurn {..}
            | IfcRequest::IngestTurnToolOutput {..} | IfcRequest::SsmIngestTurn {..}
            | IfcRequest::SsmIngestTurnHandles {..} | IfcRequest::SsmGenerateTurn {..}
            | IfcRequest::ModelGenerateTurn {..} | IfcRequest::RevealTurnHandle {..}
            | IfcRequest::BeginSessionLease {..}) {
            fail!(EPERM, "GATEWAY_SCOPED_OPERATIONS_ONLY");
        }
        // Read-only diagnostics allocate no RPC sequence, custody slot, token,
        // journal event or debit, and remain available during cleanup recovery.
        if matches!(&req, IfcRequest::PolicySli) {
            let mut st = self.lock()?;
            if peer.uid != 0 && !(st.dev_same_uid && peer.uid == enclave_core::ipc::geteuid()) {
                fail!(EPERM, "POLICY_SLI_OPERATOR_ONLY");
            }
            let mut snapshot = st.pdp.policy_sli_snapshot();
            snapshot.mcp_lock_blake3 = self.registry.lock_blake3().to_owned();
            snapshot.dev_same_uid = st.dev_same_uid;
            return Ok(IfcResponse::PolicySli(snapshot));
        }
        // Requests that call other daemons run without holding the state lock.
        let req = match req {
            IfcRequest::BeginGatewayTurn {submission_seq,caller,turn,attachments,tools,holder_pk,budget_mb} =>
                return self.begin_gateway_turn(peer,submission_seq,caller,turn,attachments,tools,holder_pk,budget_mb),
            IfcRequest::CancelGatewaySubmission {submission_seq} =>
                return self.cancel_gateway_submission(peer,submission_seq),
            IfcRequest::RecoverGatewayTurns => return self.recover_gateway_turns(peer),
            IfcRequest::AuthorizeToolCall {
                server,
                tool_name,
                args_jcs,
                arg_handles,
                wire_cbor,
                step_up,
            } => {
                return self.authorize_tool_call(
                    peer,
                    server,
                    tool_name,
                    args_jcs.into_vec(),
                    arg_handles,
                    wire_cbor.into_vec(),
                    step_up,
                    None,
                ).map(|outcome| IfcResponse::Decision(outcome.decision));
            }
            IfcRequest::IngestToolOutput {
                server,
                tool_name,
                tools_list,
                payload,
                conf_hint,
                source_uri,
            } => {
                return self.ingest_tool_output(
                    None,
                    &server,
                    &tool_name,
                    &tools_list,
                    SecretBytes::new(payload.into_vec()),
                    conf_hint,
                    &source_uri,
                    &[],
                );
            }
            IfcRequest::IngestTurnToolOutput { turn_id, server, tool_name, tools_list, payload, conf_hint, source_uri } => {
                return self.ingest_tool_output(Some((peer, &turn_id)), &server, &tool_name,
                    &tools_list, SecretBytes::new(payload.into_vec()), conf_hint, &source_uri, &[]);
            }
            IfcRequest::ExecuteTurnPlan {turn_id, source, initial_handles, fuel_budget, step_up} => {
                return self.execute_turn_plan(peer, &turn_id, &source, initial_handles, fuel_budget, step_up);
            }
            IfcRequest::SsmIngestTurn {turn_id,envelopes} => return self.ssm_ingest(peer,&turn_id,envelopes),
            IfcRequest::SsmIngestTurnHandles {turn_id,handles} => {
                if handles.is_empty() || handles.len()>64 {fail!(E2BIG,"SSM_INPUT_BOUNDS");}
                let envelopes={let st=self.lock()?;st.turns.check_handle_names(peer,&turn_id,&handles)?;
                    handles.iter().map(|h|st.heap.get(h).map(|v|v.envelope.clone())).collect::<EnclaveResult<Vec<_>>>()?};
                return self.ssm_ingest(peer,&turn_id,envelopes);
            }
            IfcRequest::SsmGenerateTurn {turn_id,n} => return self.ssm_generate(peer,&turn_id,n),
            IfcRequest::ModelGenerateTurn {turn_id,request} => return self.model_generate(peer,&turn_id,request),
            IfcRequest::RevealTurnHandle {turn_id,handle} => return self.reveal_handle(peer,&turn_id,&handle),
            IfcRequest::BeginSessionLease {turn_id} => return self.session_lease(peer,&turn_id),
            IfcRequest::FinishTurn {turn_id,cancelled} => return self.finish_turn(peer,&turn_id,cancelled),
            IfcRequest::Wipe => return self.wipe(peer),
            other => other,
        };
        // Declassification releases a value, so it occupies a governed slot
        // (GAP-27); the slot comes from UID 703 before the state lock is taken.
        let governed = match &req {
            IfcRequest::DeclassifyEnum { .. } => Some(self.custody.allocate_slot()?),
            _ => None,
        };
        // The signed epoch travels with the slot to UID 701 (GAP-27).
        let slot_ctx = match &governed {
            Some((e, s)) => {
                let epoch = self.custody.boot_epoch()?;
                if &epoch.boot_epoch_id != e {
                    fail!(
                        EACCES,
                        "EPOCH_MISMATCH",
                        "slot epoch {e} is not UID 703's signed epoch {}",
                        epoch.boot_epoch_id
                    );
                }
                Some(enclave_core::seq::GovernedSlot {
                    epoch,
                    rpc_seq_u64: *s,
                })
            }
            None => None,
        };
        let mut g = self.lock()?;
        let st = &mut *g;
        if !matches!(&req,IfcRequest::Status | IfcRequest::ReleaseHandles {..}) {st.turns.check_available()?;}
        let seq = st.seq.next()?;
        let now_ms = enclave_core::audit::now_utc_ms();
        let (resp, event): (IfcResponse, Option<Value>) = match req {
            IfcRequest::Status => {
                let s = DaemonStatus {
                    daemon_uid: DaemonId::AgentRuntime.uid(),
                    binary: DaemonId::AgentRuntime.binary().into(),
                    pid: std::process::id(),
                    rss_bytes: enclave_core::resource::current_rss_bytes().unwrap_or(0),
                    rss_ceiling_bytes: DaemonId::AgentRuntime.rss_ceiling_bytes(),
                    boot_epoch_id: st.seq.boot_epoch_id().into(),
                    rpc_seq_u64: st.seq.current(),
                    state: format!(
                        "profile={} handles={} cedar_bundle={} mcp_lock={} qif_ledger={} ssm_cleanup_pending={}",
                        st.profile,
                        st.heap.len(),
                        hex::encode(st.pdp.cedar_bundle_blake3()),
                        self.registry.lock_blake3(),
                        match (&st.ledger_fault, &st.ledger_store) {
                            (Some(_), _) => "latched",
                            (None, Some(_)) => "sealed",
                            (None, None) => "volatile",
                        },
                        st.turns.cleanup_pending()
                    ),
                    phys_footprint_bytes: enclave_core::resource::current_phys_footprint_bytes()
                        .unwrap_or(0),
                    phys_footprint_source: enclave_core::resource::current_phys_footprint_source(),
                };
                (IfcResponse::Status(s), None)
            }
            IfcRequest::ReleaseHandles { handles } => {
                if !is_admin(peer) {
                    fail!(EPERM, "RELEASE_HANDLES_INGRESS_ONLY");
                }
                if handles.iter().any(|h| st.turns.is_managed(h)) { fail!(EPERM, "TURN_SCOPED_HANDLE_RELEASE_REJECTED"); }
                let released = st.heap.release(&handles)?;
                (
                    IfcResponse::Ok,
                    Some(json!({"event": "TURN_HANDLES_RELEASED", "count": released})),
                )
            }
            IfcRequest::RetainTurnHandles { turn_id, envelopes } => {
                if !is_ingress(peer) { fail!(EPERM, "SUBMIT_TURN_INGRESS_ONLY"); }
                st.turns.retain(peer, &turn_id, &envelopes, &st.heap)?;
                (IfcResponse::Ok, None)
            }
            IfcRequest::BeginTurn { turn, attachments, tools, holder_pk, budget_mb } => {
                let (response,event,_)=self.begin_turn_locked(st,peer,turn,attachments,tools,holder_pk,budget_mb,None)?;
                (response,event)
            },
            IfcRequest::SubmitTurn {
                turn,
                attachments,
                tools,
                holder_pk,
                budget_mb,
            } => {
                // GAP-05: turns (and their root capability) enter only through
                // client ingress, never from the model host or other daemons.
                if !is_admin(peer) {
                    fail!(EPERM, "SUBMIT_TURN_INGRESS_ONLY");
                }
                if !(0..=12_000).contains(&budget_mb) {
                    fail!(EINVAL, "BUDGET_RANGE");
                }
                let tools = self.curate_tools(&tools)?;
                let att = attachments
                    .into_iter()
                    .map(|(h, b)| (h, b.into_vec()))
                    .collect();
                st.flow_gate.on(crate::flow_fsm::FlowEvent::PlanAccepted)?;
                Self::prepare_literal_ingress(st)?;
                let compiled = compile_turn(&mut st.heap, &turn, att, &tools);
                Self::persist_literal_exposure(st)?;
                let (ctx, handles) = compiled?;
                let root_token = match holder_pk {
                    Some(pk) => {
                        // DEFECT-F-67: the root token names exactly the curated
                        // tools; an empty list authorises no tool.
                        let allowed: Vec<String> = tools.iter().map(|t| t.name.clone()).collect();
                        let t = st.delegation.mint_root(
                            &st.pdp,
                            &pk,
                            &peer.channel_binding(),
                            budget_mb,
                            &allowed,
                        )?;
                        Some(serde_bytes::ByteBuf::from(
                            t.to_vec().map_err(|e| err!(EIO, "BISCUIT_SER", "{e}"))?,
                        ))
                    }
                    None => None,
                };
                let minted = root_token.is_some();
                (
                    IfcResponse::Plan {
                        context: ctx,
                        root_token,
                    },
                    Some(
                        json!({"event": "TURN_COMPILED", "attachments": handles.len(), "root_token_minted": minted, "budget_mb": budget_mb}),
                    ),
                )
            }
            IfcRequest::DeclassifyEnum {
                agent,
                handle,
                cardinality,
                schema,
            } => {
                st.turns.check_derived(&handle)?;
                let decl = &self.declassifier;
                if let Some(f) = &st.ledger_fault {
                    fail!(EACCES, "QIF_LEDGER_LATCHED", "{f}");
                }
                let sc = slot_ctx.as_ref().ok_or_else(|| err!(EINVAL, "DISPATCH"))?;
                // The real classifier may send payload to UID 701. Establish
                // exact-slot eligibility before any such callback. State stays
                // exclusively borrowed through the callback and final R guard.
                let (slot_epoch, slot) =
                    governed.as_ref().ok_or_else(|| err!(EINVAL, "DISPATCH"))?;
                st.egress.ensure_healthy()?;
                if st.egress.was_tombstoned(slot_epoch, *slot) {
                    fail!(EACCES, "TOMBSTONE_SLOT_FINALIZED");
                }
                Self::prepare_literal_ingress(st)?;
                let result = st.pdp.declassify_enum(
                    &mut st.heap,
                    &mut st.ledger,
                    &agent,
                    &handle,
                    cardinality,
                    |p| decl.classify(p, cardinality, &schema, sc),
                    now_ms,
                );
                if let Ok(env)=&result {st.turns.derived(&handle,&env.handle);}
                Self::persist_literal_exposure(st)?;
                // A payload-dependent failure is also an observation. Persist
                // its reservation before returning either success or failure;
                // restart must not refund an observed error.
                if let Some(store) = st.ledger_store.as_mut() {
                    if let Err(e) = store.save_json(&st.ledger) {
                        st.ledger_fault = Some(e.to_string());
                        return Err(e);
                    }
                }
                if let Err(error) = &result {
                    if error.is("DECLASSIFIER_FAILED") {
                        // The uniform failure was a charged observation too.
                        // It cannot later be erased by a zero-cost tombstone.
                        st.egress.released(slot_epoch, *slot)?;
                        if let Some(journal) = st.journal.as_mut() {
                            journal.append_at(slot_epoch, *slot, json!({
                                "event": "DECLASSIFY_ENUM_FAILED", "slot": slot,
                                "qif_mb": enclave_core::qif::millibits_for_outcomes(cardinality + 1),
                                "k": cardinality, "parent": handle,
                            }))?;
                        }
                    }
                }
                let env = result?;
                st.egress.released(slot_epoch, *slot)?;
                if st.flow_gate.state() == crate::flow_fsm::FlowState::QuarantineAbort {
                    fail!(
                        EPERM,
                        "FLOW_GATE_QUARANTINE_ABORT",
                        "flow gate is in QuarantineAbort state"
                    );
                }
                if st.flow_gate.state() == crate::flow_fsm::FlowState::OpaqueHandleSealed {
                    st.flow_gate
                        .on(crate::flow_fsm::FlowEvent::DeclassifyCalled)?;
                    st.flow_gate
                        .on(crate::flow_fsm::FlowEvent::QifUnderBudget)?;
                }
                let mb = enclave_core::qif::millibits_for_outcomes(cardinality + 1);
                (
                    IfcResponse::Handle(env.clone()),
                    Some(
                        json!({"event": "DECLASSIFY_ENUM", "slot": slot, "qif_mb": mb, "k": cardinality, "parent": handle}),
                    ),
                )
            }
            IfcRequest::IssueCustodyGrant { workflow, ttl_s } => {
                if !is_admin(peer) {
                    fail!(EPERM, "CUSTODY_GRANT_ADMIN_ONLY");
                }
                // GAP-05: the signed bundle itself names permitted workflows.
                if !st
                    .pdp
                    .cedar()
                    .reversible_tokenize("orchestrator", &workflow, st.profile)?
                {
                    fail!(EACCES, "CEDAR_DENY_REVERSIBLE_TOKENIZE");
                }
                if !(1..=3600).contains(&ttl_s) {
                    fail!(EINVAL, "GRANT_TTL");
                }
                let exp = enclave_crypto::time::now_unix() + ttl_s;
                let m = format!(
                    "MCPMac-Custody::ReversibleTokenize-v1\0{workflow}\0{}\0{exp}",
                    st.profile
                )
                .into_bytes();
                let sig = st.policy_key.sign(&m);
                (
                    IfcResponse::Grant {
                        workflow: workflow.clone(),
                        profile: st.profile,
                        expires_unix: exp,
                        signature: serde_bytes::ByteBuf::from(sig.to_bytes().to_vec()),
                    },
                    Some(json!({"event": "CUSTODY_GRANT", "workflow": workflow})),
                )
            }
            IfcRequest::CoSignTombstone {
                slot_rpc_seq,
                boot_epoch_id,
            } => {
                if peer.uid != DaemonId::ZkAuditor.uid() && peer.uid != enclave_core::ipc::geteuid()
                {
                    fail!(EACCES, "TOMBSTONE_PEER_REJECTED");
                }
                enclave_core::seq::validate_epoch_id(&boot_epoch_id)?;
                // GAP-11: never attest "not delivered" for a slot this daemon
                // released. (UID 704 cannot know slots UID 703 kept to itself,
                // so an unknown slot is UID 703's to vouch for.)
                st.egress.reserve_nonrelease(&boot_epoch_id, slot_rpc_seq)?;
                let sig = st
                    .tombstone_key
                    .sign(&enclave_core::audit::tombstone_message(
                        slot_rpc_seq,
                        &boot_epoch_id,
                    ));
                (
                    IfcResponse::TombstoneSignature {
                        signature: serde_bytes::ByteBuf::from(sig.to_bytes().to_vec()),
                        public_key: serde_bytes::ByteBuf::from(
                            st.tombstone_key.verifying_key().to_bytes().to_vec(),
                        ),
                    },
                    Some(
                        json!({"event": "TOMBSTONE_COSIGN", "tombstone_slot": slot_rpc_seq, "tombstone_epoch": boot_epoch_id}),
                    ),
                )
            }
            IfcRequest::RefreshPolicy { bundle_json } => {
                if !is_admin(peer) {
                    fail!(EPERM, "POLICY_REFRESH_ADMIN_ONLY");
                }
                let admitted = match bundle_json {
                    Some(offered) => {
                        // DEFECT-F-64: inline bytes load only if byte-identical to
                        // the TUF-verified target UID 702 serves (or, in a
                        // `simulation` dev build, as explicitly unsigned).
                        let signed = crate::cedar_engine::fetch_signed_bundle_bytes(
                            st.socket_dir.as_deref(),
                            st.dev_same_uid,
                        );
                        match crate::cedar_engine::admit_inline_bundle(
                            &offered,
                            signed,
                            st.dev_same_uid,
                        ) {
                            Ok(admitted) => Ok(admitted),
                            Err(e) => {
                                if let Some(j) = st.journal.as_mut() {
                                    let _ = j.append(
                                        seq,
                                        json!({
                                            "event": "POLICY_BUNDLE_INLINE_REJECTED",
                                            "offered_blake3": blake3::hash(&offered).to_hex().to_string(),
                                            "error": e.to_string(),
                                        }),
                                    );
                                }
                                return Err(e);
                            }
                        }
                    }
                    None => {
                        let dir = st.socket_dir.as_deref().ok_or_else(|| {
                            err!(
                                EINVAL,
                                "POLICY_REFRESH",
                                "no socket_dir configured to fetch bundle"
                            )
                        })?;
                        crate::cedar_engine::fetch_cedar_bundle(dir, st.dev_same_uid)
                            .map(|b| (b, PolicyProvenance::TufSigned))
                    }
                };

                let (bundle, provenance) = match admitted {
                    Ok(b) => b,
                    Err(e) => {
                        if let Some(j) = st.journal.as_mut() {
                            let _ = j.append(
                                seq,
                                json!({"event": "POLICY_BUNDLE_INVALID", "error": e.to_string()}),
                            );
                        }
                        return Err(e);
                    }
                };

                let new_engine = match CedarEngine::from_bundle(&bundle) {
                    Ok(eng) => eng,
                    Err(e) => {
                        if let Some(j) = st.journal.as_mut() {
                            let _ = j.append(
                                seq,
                                json!({"event": "POLICY_BUNDLE_INVALID", "error": e.to_string()}),
                            );
                        }
                        return Err(e);
                    }
                };

                let now_mach = enclave_core::clock::boot_clock_ns();
                let new_hash = new_engine.bundle_blake3();
                st.pdp.swap_cedar(new_engine, now_mach);
                (
                    IfcResponse::Ok,
                    Some(json!({
                        "event": "POLICY_BUNDLE_HOTSWAP",
                        "policy_bundle_blake3": hex::encode(new_hash),
                        "provenance": provenance.as_str(),
                        "warning": provenance.warning(),
                    })),
                )
            }
            IfcRequest::PolicySli | IfcRequest::AuthorizeToolCall { .. } | IfcRequest::IngestToolOutput { .. } | IfcRequest::IngestTurnToolOutput { .. }
            | IfcRequest::SsmIngestTurn {..} | IfcRequest::SsmIngestTurnHandles {..} | IfcRequest::SsmGenerateTurn {..}
            | IfcRequest::ModelGenerateTurn {..} | IfcRequest::RevealTurnHandle {..} | IfcRequest::BeginSessionLease {..} | IfcRequest::BeginGatewayTurn {..} | IfcRequest::CancelGatewaySubmission {..} | IfcRequest::RecoverGatewayTurns
            | IfcRequest::ExecuteTurnPlan {..} | IfcRequest::FinishTurn {..} | IfcRequest::Wipe => {
                fail!(EINVAL, "DISPATCH")
            }
        };
        if let (Some(j), Some(ev)) = (st.journal.as_mut(), event) {
            match &governed {
                Some((e, slot)) => j.append_at(e, *slot, ev)?,
                None => j.append(seq, ev)?,
            };
        }
        Ok(resp)
    }
}

/// Clears the generating turn when its runner call returns or unwinds.
struct GeneratingGuard<'a>(&'a Mutex<Option<String>>);
impl Drop for GeneratingGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut g)=self.0.lock() {*g=None;}
    }
}
