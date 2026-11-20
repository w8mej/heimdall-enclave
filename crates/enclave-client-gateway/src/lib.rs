//! Client ingress gateway with explicit runtime-owned execution (GAP-18, F97).
//!
//! Models a unix domain socket facing the configured active console user,
//! enforces submission rate limits, and mediates explicitly completed/cancelled
//! turn lifetimes with UID 704. Installed account/signing acceptance is separate.

#![deny(missing_docs)]

pub mod entry;

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, atomic::{AtomicU64, Ordering}};
use std::os::unix::net::UnixStream;
use zeroize::Zeroize;
use std::time::{Duration, Instant};

use enclave_agent_runtime::service::{IfcRequest, IfcResponse};
use enclave_agent_runtime::turn::{PlanCompileContext, ToolSignature};
use enclave_core::daemon::DaemonId;
use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use enclave_core::ifc_envelope::IfcEnvelopeV1;
use enclave_core::label::Conf;
use enclave_core::ipc::{Client, PeerCredentials};
use enclave_core::user_turn::UserTurnV1;
use serde::{Deserialize, Serialize};

/// Maximum turns allowed per rate-limiting window.
pub const DEFAULT_MAX_TURNS_PER_WINDOW: usize = 60;

/// Default rate-limiting window duration (1 minute).
pub const DEFAULT_WINDOW_DURATION: Duration = Duration::from_secs(60);

/// Request accepted by the client ingress gateway.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ClientGatewayRequest {
    /// Submit an agent turn.
    SubmitTurn {
        /// Turn contents.
        turn: UserTurnV1,
        /// Attachment handles and bytes.
        attachments: Vec<(String, serde_bytes::ByteBuf)>,
        /// Tool signatures.
        tools: Vec<ToolSignature>,
        /// Root capability budget in mb.
        budget_mb: i64,
        /// Holder key for the root capability; required in production.
        #[serde(default)]
        holder_pk: Option<[u8; 32]>,
    },
    /// Submit a turn with a private runtime-owned holder, for ExecuteTurnPlan.
    /// No capability or holder secret is returned to the caller.
    SubmitExecutableTurn {
        /// Turn contents.
        turn: UserTurnV1,
        /// Attachment handles and bytes.
        attachments: Vec<(String, serde_bytes::ByteBuf)>,
        /// Exact requested tools, curated again by the runtime.
        tools: Vec<ToolSignature>,
        /// Root capability budget in millibits.
        budget_mb: i64,
    },
    /// Execute the runtime-owned turn's bounded plan; only its original process.
    ExecuteTurnPlan {
        /// Runtime-minted turn ID.
        turn_id: String,
        /// Bounded source in the runtime's EnclaveStarlarkV1 dialect.
        source: String,
        /// Local variable names and handles owned by this turn.
        initial_handles: Vec<(String, String)>,
        /// Parser/evaluator fuel, one through 10000.
        fuel_budget: u64,
        /// Whether to request actual custody approval where policy requires it.
        step_up: bool,
    },
    /// Complete or cancel a turn submitted by this authenticated process.
    FinishTurn {
        /// Runtime-minted turn ID returned in Plan.
        turn_id: String,
        /// Whether the caller cancelled execution.
        cancelled: bool,
    },
    /// Keep MAC-verified references live for this turn.
    RetainTurnHandles {
        /// Runtime-minted turn ID.
        turn_id: String,
        /// Exact verified envelopes.
        envelopes: Vec<IfcEnvelopeV1>,
    },
    /// Wrap a tool return in the authenticated turn's lifetime.
    IngestTurnToolOutput {
        /// Runtime-minted turn ID.
        turn_id: String,
        /// MCP server name.
        server: String,
        /// MCP tool name.
        tool_name: String,
        /// Live tools/list, checked against the signed lock.
        tools_list: String,
        /// Untrusted tool return (labels only rise).
        payload: serde_bytes::ByteBuf,
        /// Optional raising-only confidentiality hint.
        conf_hint: Option<Conf>,
        /// Canonical source URI.
        source_uri: String,
    },
    /// Ingest MAC-verified envelopes owned by this authenticated turn.
    SsmIngestTurn {
        /// Runtime-minted turn ID.
        turn_id: String,
        /// Exact runtime envelopes.
        envelopes: Vec<IfcEnvelopeV1>,
    },
    /// Ingest opaque attachment stubs owned by this authenticated turn.
    SsmIngestTurnHandles {
        /// Runtime-minted turn ID.
        turn_id: String,
        /// Heap names, resolved and MAC-verified by UID 704.
        handles: Vec<String>,
    },
    /// Generate into a sealed handle, preserving the runner's session label.
    SsmGenerateTurn {
        /// Runtime-minted turn ID.
        turn_id: String,
        /// Maximum output bytes (1 through 65536).
        n: u32,
    },
    /// Non-session generation into a sealed handle (AR, diffusion, depth,
    /// world plan). Prompts are handles UID 704 resolves for this turn.
    ModelGenerateTurn {
        /// Runtime-minted turn ID.
        turn_id: String,
        /// What the bound model is asked to do.
        request: enclave_agent_runtime::model_turn::ModelTurnRequest,
    },
}

impl std::fmt::Debug for ClientGatewayRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let operation = match self {
            Self::SubmitTurn {..} => "SubmitTurn",
            Self::SubmitExecutableTurn {..} => "SubmitExecutableTurn",
            Self::ExecuteTurnPlan {..} => "ExecuteTurnPlan",
            Self::FinishTurn {..} => "FinishTurn",
            Self::RetainTurnHandles {..} => "RetainTurnHandles",
            Self::IngestTurnToolOutput {..} => "IngestTurnToolOutput",
            Self::SsmIngestTurn {..} => "SsmIngestTurn",
            Self::SsmIngestTurnHandles {..} => "SsmIngestTurnHandles",
            Self::SsmGenerateTurn {..} => "SsmGenerateTurn",
            Self::ModelGenerateTurn {..} => "ModelGenerateTurn",
        };
        f.debug_struct(operation).finish_non_exhaustive()
    }
}

fn wipe_turn(turn: &mut UserTurnV1, attachments: &mut [(String, serde_bytes::ByteBuf)]) {
    turn.directive_short.zeroize();
    for (name, bytes) in attachments { name.zeroize(); bytes.as_mut().zeroize(); }
}
#[derive(Deserialize)]
#[serde(transparent)]
pub(crate) struct SensitiveGatewayRequest(ClientGatewayRequest);
impl Drop for SensitiveGatewayRequest {
    fn drop(&mut self) {
        match &mut self.0 {
            ClientGatewayRequest::SubmitTurn {turn, attachments, ..} | ClientGatewayRequest::SubmitExecutableTurn {turn, attachments, ..} => wipe_turn(turn, attachments),
            ClientGatewayRequest::ExecuteTurnPlan {source, ..} => source.zeroize(),
            ClientGatewayRequest::IngestTurnToolOutput {tools_list, payload, ..} => {tools_list.zeroize(); payload.as_mut().zeroize();},
            _ => {},
        }
    }
}

// Own the forwarded decoded copy through encode/write/receive failures. Its
// prepared CBOR allocation is independently zeroizing in enclave-core::ipc.
struct SensitiveIfc(IfcRequest);
impl Drop for SensitiveIfc {
    fn drop(&mut self) {
        match &mut self.0 {
            IfcRequest::BeginGatewayTurn {turn, attachments, ..} => wipe_turn(turn, attachments),
            IfcRequest::ExecuteTurnPlan {source, ..} => source.zeroize(),
            IfcRequest::IngestTurnToolOutput {tools_list, payload, ..} => {tools_list.zeroize(); payload.as_mut().zeroize();},
            _ => {},
        }
    }
}
fn wipe_ifc_reply(reply: &mut IfcResponse) {
    match reply {
        IfcResponse::TurnPlan {context, root_token, ..} | IfcResponse::Plan {context, root_token} => {
            context.directive.zeroize();
            if let Some(token) = root_token { token.as_mut().zeroize(); }
        },
        IfcResponse::PlanExecuted {return_value, ..} => return_value.zeroize(),
        _ => {},
    }
}
struct SensitiveIfcReply(IfcResponse);
impl Drop for SensitiveIfcReply {
    fn drop(&mut self) {wipe_ifc_reply(&mut self.0);}
}
fn unexpected_reply(mut reply:IfcResponse)->enclave_core::error::EnclaveError {
    wipe_ifc_reply(&mut reply);
    err!(EIO,"ERR_GATEWAY_UNEXPECTED_RESP")
}
pub(crate) fn wipe_gateway_reply(reply: &mut ClientGatewayResponse) {
    match reply {
        ClientGatewayResponse::Plan {context, root_token, ..} => {
            context.directive.zeroize();
            if let Some(token) = root_token {token.as_mut().zeroize();}
        },
        ClientGatewayResponse::PlanExecuted {return_value, ..} => return_value.zeroize(),
        _ => {},
    }
}
struct ActiveCall<'a> { calls: &'a Mutex<HashMap<u64, (u64, UnixStream)>>, id: u64 }
impl Drop for ActiveCall<'_> {
    fn drop(&mut self) { if let Ok(mut calls) = self.calls.lock() { calls.remove(&self.id); } }
}

/// Response returned by the client ingress gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientGatewayResponse {
    /// Compiled plan context and root token.
    Plan {
        /// Runtime-minted lifetime; the submitting process must finish it.
        turn_id: String,
        /// Compiled plan context.
        context: PlanCompileContext,
        /// Root PoP-Biscuit token (if minted).
        root_token: Option<serde_bytes::ByteBuf>,
    },
    /// Plan result: opaque references only, never raw tool output.
    PlanExecuted {
        /// Interpreter result description.
        return_value: String,
        /// Actual number of dispatched tool calls.
        executed_tool_calls: usize,
        /// Authenticated runtime output references.
        output_refs: Vec<IfcEnvelopeV1>,
    },
    /// Lifetime completed/cancelled; only unreferenced managed handles removed.
    Finished {
        /// Exact number of reclaimed handles.
        released: usize,
    },
    /// Verified reference-retention acknowledgement.
    Retained,
    /// Session-input acknowledgement.
    SsmIngested,
    /// MAC-verified opaque tool or model output.
    Handle(IfcEnvelopeV1),
}

/// Simple sliding-window rate limiter per UID.
#[derive(Debug, Default)]
pub struct RateLimiter {
    history: Mutex<HashMap<u32, Vec<Instant>>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    /// Create a rate limiter with given limit and window.
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            history: Mutex::new(HashMap::new()),
            max_requests,
            window,
        }
    }

    /// Check if a request from `uid` is allowed under the rate limit.
    pub fn check_and_record(&self, uid: u32) -> EnclaveResult<()> {
        let mut guard = self
            .history
            .lock()
            .map_err(|_| enclave_core::err!(EIO, "GATEWAY_RATE_LOCK_POISONED"))?;
        let now = Instant::now();
        let entry = guard.entry(uid).or_default();

        // Evict expired entries
        let window = self.window;
        entry.retain(|&t| now.saturating_duration_since(t) < window);

        if entry.len() >= self.max_requests {
            fail!(
                EAGAIN,
                "ERR_GATEWAY_RATE_LIMITED",
                "uid {uid} exceeded rate limit of {} turns per {:?}",
                self.max_requests,
                self.window
            );
        }

        entry.push(now);
        Ok(())
    }
}

trait ConsoleUser: std::fmt::Debug + Send + Sync {
    fn uid(&self) -> Option<u32>;
}
#[derive(Debug)]
struct SystemConsole;
impl ConsoleUser for SystemConsole {
    fn uid(&self) -> Option<u32> { enclave_core::runtime_paths::console_uid() }
}

#[derive(Debug)]
struct SubmissionState {next_seq:u64,pending:Option<u64>}
impl Default for SubmissionState {
    fn default()->Self {Self {next_seq:1,pending:None}}
}

/// Client gateway service.
#[derive(Debug)]
pub struct ClientGateway {
    /// Gateway socket path.
    pub socket_path: PathBuf,
    /// IFC daemon socket path.
    pub ifc_socket_path: PathBuf,
    rate_limiter: Arc<RateLimiter>,
    console: Arc<dyn ConsoleUser>,
    dev_same_uid: bool,
    // Ownership never comes from a wire field: capture the authenticated
    // console process (full audit-token pidversion on Darwin) at submission.
    turns: Mutex<HashMap<String,PeerCredentials>>,
    submission_gate: Mutex<SubmissionState>,
    completed: Mutex<VecDeque<(String,PeerCredentials)>>,
    turn_generations: Mutex<HashMap<String,u64>>,
    generation: Arc<AtomicU64>,
    release: Arc<Mutex<()>>,
    calls: Mutex<HashMap<u64,(u64,UnixStream)>>,
    next_call: AtomicU64,
}

impl ClientGateway {
    /// Create a new gateway service instance.
    pub fn new(
        socket_path: PathBuf,
        ifc_socket_path: PathBuf,
        max_rate: usize,
        window: Duration,
        dev_same_uid: bool,
    ) -> Self {
        Self {
            socket_path,
            ifc_socket_path,
            rate_limiter: Arc::new(RateLimiter::new(max_rate, window)),
            console: Arc::new(SystemConsole),
            dev_same_uid,
            turns: Mutex::new(HashMap::new()),
            submission_gate: Mutex::new(SubmissionState::default()),
            completed: Mutex::new(VecDeque::new()),
            turn_generations: Mutex::new(HashMap::new()),
            generation: Arc::new(AtomicU64::new(0)), release: Arc::new(Mutex::new(())),
            calls: Mutex::new(HashMap::new()), next_call: AtomicU64::new(0),
        }
    }

    /// Validate peer credentials: must be console user (or dev UID) and pass rate limit.
    pub fn authorize_peer(&self, peer: &PeerCredentials) -> EnclaveResult<()> {
        self.authenticate_peer(peer, false)?;
        self.rate_limiter.check_and_record(peer.uid)
    }

    fn admit_session(&self, peer: &PeerCredentials, cleanup: bool) -> EnclaveResult<()> {
        let uid = if self.dev_same_uid { Some(enclave_core::ipc::geteuid()) } else { self.console.uid() };
        if uid == Some(peer.uid) { return Ok(()); }
        if cleanup && self.turns.lock().map_err(|_|err!(EIO,"GATEWAY_TURNS_POISONED"))?
            .values().any(|owner| owner == peer) { return Ok(()); }
        if cleanup && self.completed.lock().map_err(|_|err!(EIO,"GATEWAY_TURNS_POISONED"))?
            .iter().any(|(_,owner)|owner==peer) {return Ok(());}
        if uid.is_none() { fail!(EPERM,"GATEWAY_NO_CONSOLE"); }
        fail!(EPERM,"ERR_GATEWAY_PEER_DENIED")
    }
    fn authenticate_identity(&self, peer: &PeerCredentials) -> EnclaveResult<PeerCredentials> {
        if self.dev_same_uid {
            if peer.uid!=enclave_core::ipc::geteuid() {fail!(EPERM,"ERR_GATEWAY_PEER_DENIED");}
            return Ok(peer.clone());
        }
        // Verify the actual process before comparing saved owner identity.
        enclave_core::ipc::PeerPolicy::allow([peer.uid])
            .require(peer.uid,enclave_core::codesign::CodeRequirement::ctl()).check(peer)
    }
    fn authenticate_peer(&self, peer: &PeerCredentials, cleanup: bool) -> EnclaveResult<PeerCredentials> {
        let peer=self.authenticate_identity(peer)?;
        self.admit_session(&peer, cleanup)?;
        Ok(peer)
    }
    /// Authenticate before reading a frame. Old owners may connect to finish;
    /// every request repeats the session check and only FinishTurn gets that exception.
    pub fn authenticate_connection(&self, peer: &PeerCredentials) -> EnclaveResult<PeerCredentials> {
        self.authenticate_peer(peer, true)
    }
    fn connect_ifc(&self)->EnclaveResult<Client> {
        let requirement=enclave_core::codesign::CodeRequirement::daemon(DaemonId::AgentRuntime);
        Client::connect_verified_deadline(&self.ifc_socket_path,
            if self.dev_same_uid {enclave_core::ipc::geteuid()} else {DaemonId::AgentRuntime.uid()},
            (!self.dev_same_uid).then_some(&requirement),Duration::from_secs(2))
    }
    fn check_generation(&self, captured:u64)->EnclaveResult<()> {
        if captured==u64::MAX || self.generation.load(Ordering::SeqCst)!=captured {fail!(EACCES,"GATEWAY_LIFECYCLE_REVOKED");}Ok(())
    }
    /// Establish a local release fence and interrupt every older upstream call.
    /// Runtime cancellation remains an acknowledged cleanup debt; this method
    /// makes no claim about already delivered bytes or another process's heap.
    pub fn revoke(&self)->EnclaveResult<()> {
        let _serial=self.release.lock().map_err(|_|err!(EIO,"GATEWAY_RELEASE_POISONED"))?;
        let previous=self.generation.try_update(Ordering::SeqCst,Ordering::SeqCst,|value|Some(value.saturating_add(1)))
            .map_err(|_|err!(EIO,"GATEWAY_GENERATION_UPDATE"))?;
        let current=previous.saturating_add(1);
        let calls=self.calls.lock().map_err(|_|err!(EIO,"GATEWAY_CALLS_POISONED"))?;
        let mut failed=false;
        for (generation,stream) in calls.values() {if *generation<current || current==u64::MAX {
            if let Err(error)=stream.shutdown(std::net::Shutdown::Both) {
                failed|=error.kind()!=std::io::ErrorKind::NotConnected;
            }
        }}
        if failed {fail!(EIO,"GATEWAY_CANCEL_UNCONFIRMED");}
        if previous==u64::MAX {fail!(EACCES,"GATEWAY_GENERATION_EXHAUSTED");}Ok(())
    }
    fn call_ifc(&self, request:IfcRequest, captured:u64, timeout:Duration)->EnclaveResult<IfcResponse> {
        let request=SensitiveIfc(request);self.check_generation(captured)?;
        let client=self.connect_ifc()?;let control=client.cancellation_stream()?;
        let id=self.next_call.try_update(Ordering::SeqCst,Ordering::SeqCst,|value|value.checked_add(1))
            .map_err(|_|err!(EACCES,"GATEWAY_CALL_ID_EXHAUSTED"))?;
        {let mut calls=self.calls.lock().map_err(|_|err!(EIO,"GATEWAY_CALLS_POISONED"))?;self.check_generation(captured)?;calls.insert(id,(captured,control));}
        let _call=ActiveCall{calls:&self.calls,id};
        let prepared=client.prepare_call(&request.0)?;
        let pending={let _serial=self.release.lock().map_err(|_|err!(EIO,"GATEWAY_RELEASE_POISONED"))?;
            self.check_generation(captured)?;prepared.handoff()?};
        let mut reply:IfcResponse=pending.receive_with_timeout(timeout)?;
        if let Err(error)=self.check_generation(captured){wipe_ifc_reply(&mut reply);return Err(error);}Ok(reply)
    }
    fn attach_reply_fence(&self,captured:u64)->EnclaveResult<()> {
        self.check_generation(captured)?;
        let generation=self.generation.clone();
        enclave_core::ipc::attach_release_permit(enclave_core::ipc::ReleasePermit::new(self.release.clone(),Arc::new(move||{
            if captured==u64::MAX || generation.load(Ordering::SeqCst)!=captured {fail!(EACCES,"GATEWAY_LIFECYCLE_REVOKED");}Ok(())
        })));Ok(())
    }

    fn owned(&self,peer:&PeerCredentials,turn_id:&str)->EnclaveResult<()> {
        let turns=self.turns.lock().map_err(|_|err!(EIO,"GATEWAY_TURNS_POISONED"))?;
        let owner=turns.get(turn_id).ok_or_else(||err!(EACCES,"GATEWAY_TURN_UNKNOWN"))?;
        if owner!=peer {fail!(EPERM,"GATEWAY_TURN_OWNER_REJECTED");}
        if self.turn_generations.lock().map_err(|_|err!(EIO,"GATEWAY_TURNS_POISONED"))?.get(turn_id).copied()!=Some(self.generation.load(Ordering::SeqCst)) {fail!(EACCES,"GATEWAY_TURN_REVOKED");}Ok(())
    }

    fn completed_by(&self, peer:&PeerCredentials, id:&str)->EnclaveResult<bool> {
        let completed=self.completed.lock().map_err(|_|err!(EIO,"GATEWAY_TURNS_POISONED"))?;
        match completed.iter().find(|(turn,_)|turn==id) {
            Some((_,owner)) if owner==peer=>Ok(true),
            Some(_)=>Err(err!(EPERM,"GATEWAY_TURN_OWNER_REJECTED")),
            None=>Ok(false),
        }
    }
    fn record_finished(&self, peer:&PeerCredentials, id:&str)->EnclaveResult<()> {
        // Keep at most 64 exact-owner tombstones for lost gateway replies. No
        // execution or handle access is authorized by this cleanup-only cache.
        let mut completed=self.completed.lock().map_err(|_|err!(EIO,"GATEWAY_TURNS_POISONED"))?;
        if !completed.iter().any(|(turn,_)|turn==id) {
            if completed.len()>=64 {completed.pop_front();}
            completed.push_back((id.into(),peer.clone()));
        }
        self.turns.lock().map_err(|_|err!(EIO,"GATEWAY_TURNS_POISONED"))?.remove(id);
        self.turn_generations.lock().map_err(|_|err!(EIO,"GATEWAY_TURNS_POISONED"))?.remove(id);
        Ok(())
    }

    fn maintain_locked(&self,state:&mut SubmissionState)->EnclaveResult<()> {
        // Keep an ambiguous Begin until this exact sequence is acknowledged
        // cancelled. Cancel also retires a delayed, not-yet-processed Begin.
        let captured=self.generation.load(Ordering::SeqCst);
        if let Some(submission_seq)=state.pending {
            match self.call_ifc(IfcRequest::CancelGatewaySubmission {submission_seq},captured,Duration::from_secs(6))? {
                IfcResponse::Ok=>state.pending=None,
                other=>return Err(unexpected_reply(other)),
            }
        }
        let retired=self.turn_generations.lock().map_err(|_|err!(EIO,"GATEWAY_TURNS_POISONED"))?.iter().filter(|(_,generation)|**generation!=captured).map(|(id,_)|id.clone()).collect::<Vec<_>>();
        for turn_id in retired {
            let response=self.call_ifc(IfcRequest::FinishTurn{turn_id:turn_id.clone(),cancelled:true},captured,Duration::from_secs(6));
            match response {Ok(IfcResponse::TurnFinished{..})=>{},Err(error) if error.is("TURN_UNKNOWN")=>{},Err(error)=>return Err(error),Ok(other)=>return Err(unexpected_reply(other)),}
        }
        let response=SensitiveIfcReply(self.call_ifc(IfcRequest::RecoverGatewayTurns,captured,Duration::from_secs(6))?);
        let IfcResponse::GatewayTurns {active_turns}=&response.0 else {fail!(EIO,"ERR_GATEWAY_UNEXPECTED_RESP");};
        if active_turns.len()>64 {fail!(EIO,"ERR_GATEWAY_UNEXPECTED_RESP");}
        let finished=self.turns.lock().map_err(|_|err!(EIO,"GATEWAY_TURNS_POISONED"))?
            .iter().filter(|(id,_)|!active_turns.contains(id)).map(|(id,owner)|(id.clone(),owner.clone())).collect::<Vec<_>>();
        // Absence is a runtime acknowledgement after cancellation/SSM cleanup,
        // never a guessed local lease timeout or a client-supplied death claim.
        for (id,owner) in finished {self.record_finished(&owner,&id)?;}
        Ok(())
    }

    /// Retry ambiguous submission cleanup and ask the runtime to recover only
    /// positively ended owners. This trigger needs no console session/rate slot.
    pub fn maintain_turns(&self)->EnclaveResult<()> {
        let mut state=match self.submission_gate.try_lock() {Ok(state)=>state,Err(_)=>return Ok(())};
        self.maintain_locked(&mut state)
    }

    /// Handle one request, scrubbing its owned plaintext on every return path.
    pub fn handle_request(&self,peer:&PeerCredentials,req:ClientGatewayRequest)->EnclaveResult<ClientGatewayResponse> {
        self.handle_sensitive_request(peer,SensitiveGatewayRequest(req))
    }
    pub(crate) fn handle_sensitive_request(&self,peer:&PeerCredentials,mut req:SensitiveGatewayRequest)->EnclaveResult<ClientGatewayResponse> {
        let captured=self.generation.load(Ordering::SeqCst);self.check_generation(captured)?;
        let peer=self.authenticate_identity(peer)?;
        let submitting=matches!(&req.0,ClientGatewayRequest::SubmitTurn{..}|ClientGatewayRequest::SubmitExecutableTurn{..});
        let mut submission=if submitting{Some(self.submission_gate.lock().map_err(|_|err!(EIO,"GATEWAY_SUBMISSION_POISONED"))?)}else{None};
        if let Some(state)=submission.as_mut(){self.maintain_locked(state)?;}
        let cleanup=matches!(&req.0,ClientGatewayRequest::FinishTurn{..});self.admit_session(&peer,cleanup)?;
        let mut response=match &mut req.0 {
            ClientGatewayRequest::SubmitTurn{turn,attachments,tools,budget_mb,holder_pk}=>self.submit_turn(&peer,turn,attachments,tools,*budget_mb,*holder_pk,false,submission.as_mut().unwrap(),captured),
            ClientGatewayRequest::SubmitExecutableTurn{turn,attachments,tools,budget_mb}=>self.submit_turn(&peer,turn,attachments,tools,*budget_mb,None,true,submission.as_mut().unwrap(),captured),
            ClientGatewayRequest::ExecuteTurnPlan{turn_id,source,initial_handles,fuel_budget,step_up}=>{
                self.owned(&peer,turn_id)?;
                if source.len()>64*1024 || initial_handles.len()>64 || !(1..=10_000).contains(fuel_budget){fail!(E2BIG,"PLAN_EXECUTION_BOUNDS");}
                match self.call_ifc(IfcRequest::ExecuteTurnPlan{turn_id:turn_id.clone(),source:std::mem::take(source),initial_handles:std::mem::take(initial_handles),fuel_budget:*fuel_budget,step_up:*step_up},captured,enclave_core::ipc::IO_TIMEOUT)? {
                    IfcResponse::PlanExecuted{return_value,executed_tool_calls,output_refs}=>Ok(ClientGatewayResponse::PlanExecuted{return_value,executed_tool_calls,output_refs}),other=>return Err(unexpected_reply(other)),
                }
            },
            ClientGatewayRequest::FinishTurn{turn_id,cancelled}=>{
                if self.completed_by(&peer,turn_id)?{return Ok(ClientGatewayResponse::Finished{released:0});}
                // Retired owners retain cleanup authority across a fence.
                {let turns=self.turns.lock().map_err(|_|err!(EIO,"GATEWAY_TURNS_POISONED"))?;let owner=turns.get(turn_id).ok_or_else(||err!(EACCES,"GATEWAY_TURN_UNKNOWN"))?;if owner!=&peer{fail!(EPERM,"GATEWAY_TURN_OWNER_REJECTED");}}
                let response=self.call_ifc(IfcRequest::FinishTurn{turn_id:turn_id.clone(),cancelled:*cancelled},captured,enclave_core::ipc::IO_TIMEOUT);
                let released=match response{Ok(IfcResponse::TurnFinished{released})=>released,Err(error) if error.is("TURN_UNKNOWN")=>0,Err(error)=>return Err(error),Ok(other)=>return Err(unexpected_reply(other)),};
                self.record_finished(&peer,turn_id)?;Ok(ClientGatewayResponse::Finished{released})
            },
            ClientGatewayRequest::RetainTurnHandles{turn_id,envelopes}=>{
                self.owned(&peer,turn_id)?;if envelopes.len()>256{fail!(E2BIG,"TURN_REFERENCE_LIMIT");}
                match self.call_ifc(IfcRequest::RetainTurnHandles{turn_id:turn_id.clone(),envelopes:std::mem::take(envelopes)},captured,enclave_core::ipc::IO_TIMEOUT)?{IfcResponse::Ok=>Ok(ClientGatewayResponse::Retained),other=>return Err(unexpected_reply(other)),}
            },
            ClientGatewayRequest::IngestTurnToolOutput{turn_id,server,tool_name,tools_list,payload,conf_hint,source_uri}=>{
                self.owned(&peer,turn_id)?;
                match self.call_ifc(IfcRequest::IngestTurnToolOutput{turn_id:turn_id.clone(),server:std::mem::take(server),tool_name:std::mem::take(tool_name),tools_list:std::mem::take(tools_list),payload:std::mem::take(payload),conf_hint:*conf_hint,source_uri:std::mem::take(source_uri)},captured,enclave_core::ipc::IO_TIMEOUT)?{IfcResponse::Handle(env)=>Ok(ClientGatewayResponse::Handle(env)),other=>return Err(unexpected_reply(other)),}
            },
            ClientGatewayRequest::SsmIngestTurn{turn_id,envelopes}=>{
                self.owned(&peer,turn_id)?;if envelopes.is_empty()||envelopes.len()>64{fail!(E2BIG,"SSM_INPUT_BOUNDS");}
                match self.call_ifc(IfcRequest::SsmIngestTurn{turn_id:turn_id.clone(),envelopes:std::mem::take(envelopes)},captured,enclave_core::ipc::IO_TIMEOUT)?{IfcResponse::Ok=>Ok(ClientGatewayResponse::SsmIngested),other=>return Err(unexpected_reply(other)),}
            },
            ClientGatewayRequest::SsmIngestTurnHandles{turn_id,handles}=>{
                self.owned(&peer,turn_id)?;if handles.is_empty()||handles.len()>64{fail!(E2BIG,"SSM_INPUT_BOUNDS");}
                match self.call_ifc(IfcRequest::SsmIngestTurnHandles{turn_id:turn_id.clone(),handles:std::mem::take(handles)},captured,enclave_core::ipc::IO_TIMEOUT)?{IfcResponse::Ok=>Ok(ClientGatewayResponse::SsmIngested),other=>return Err(unexpected_reply(other)),}
            },
            ClientGatewayRequest::SsmGenerateTurn{turn_id,n}=>{
                self.owned(&peer,turn_id)?;if !(1..=65536).contains(n){fail!(E2BIG,"SSM_OUTPUT_BOUNDS");}
                match self.call_ifc(IfcRequest::SsmGenerateTurn{turn_id:turn_id.clone(),n:*n},captured,enclave_core::ipc::IO_TIMEOUT)?{IfcResponse::Handle(env)=>Ok(ClientGatewayResponse::Handle(env)),other=>return Err(unexpected_reply(other)),}
            },
            ClientGatewayRequest::ModelGenerateTurn{turn_id,request}=>{
                self.owned(&peer,turn_id)?;request.validate()?;
                let request=IfcRequest::ModelGenerateTurn{turn_id:turn_id.clone(),request:request.clone()};
                match self.call_ifc(request,captured,enclave_core::ipc::IO_TIMEOUT)?{IfcResponse::Handle(env)=>Ok(ClientGatewayResponse::Handle(env)),other=>return Err(unexpected_reply(other)),}
            },
        }?;
        if let Err(error)=self.attach_reply_fence(captured) {wipe_gateway_reply(&mut response);return Err(error);}
        Ok(response)
    }
    #[allow(clippy::too_many_arguments)]
    fn submit_turn(&self,peer:&PeerCredentials,turn:&mut UserTurnV1,attachments:&mut Vec<(String,serde_bytes::ByteBuf)>,tools:&mut Vec<ToolSignature>,budget_mb:i64,holder_pk:Option<[u8;32]>,internal:bool,state:&mut SubmissionState,captured:u64)->EnclaveResult<ClientGatewayResponse> {
        self.rate_limiter.check_and_record(peer.uid)?;
        if peer.pid.is_none_or(|pid|pid<=0){fail!(EPERM,"TURN_OWNER_IDENTITY_REQUIRED");}
        if self.turns.lock().map_err(|_|err!(EIO,"GATEWAY_TURNS_POISONED"))?.len()>=64{fail!(E2BIG,"GATEWAY_TURN_LIMIT");}
        if (!self.dev_same_uid&&!internal&&holder_pk.is_none())||!(0..=12_000).contains(&budget_mb)||attachments.len()>64||tools.len()>1024||attachments.iter().map(|(_,b)|b.len()).sum::<usize>()>4*1024*1024{fail!(EINVAL,"GATEWAY_REQUEST_BOUNDS");}
        self.authenticate_peer(peer,false)?;self.check_generation(captured)?;
        let submission_seq=state.next_seq;state.next_seq=state.next_seq.checked_add(1).ok_or_else(||err!(E2BIG,"GATEWAY_SUBMISSION_EXHAUSTED"))?;state.pending=Some(submission_seq);
        let turn=std::mem::replace(turn,UserTurnV1{directive_short:String::new(),attachments:Vec::new()});
        let mut response=SensitiveIfcReply(self.call_ifc(IfcRequest::BeginGatewayTurn{submission_seq,caller:peer.clone(),turn,attachments:std::mem::take(attachments),tools:std::mem::take(tools),holder_pk,budget_mb},captured,enclave_core::ipc::IO_TIMEOUT)?);
        let IfcResponse::TurnPlan{turn_id,..}=&response.0 else {fail!(EIO,"ERR_GATEWAY_UNEXPECTED_RESP");};
        if turn_id.len()!=64||!turn_id.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)){fail!(EIO,"ERR_GATEWAY_UNEXPECTED_RESP");}
        // Retain the scrubbing reply owner across every fallible validation and
        // map acquisition; transfer plaintext only after cleanup debt is saved.
        let mut turns=self.turns.lock().map_err(|_|err!(EIO,"GATEWAY_TURNS_POISONED"))?;
        let mut generations=self.turn_generations.lock().map_err(|_|err!(EIO,"GATEWAY_TURNS_POISONED"))?;
        turns.insert(turn_id.clone(),peer.clone());generations.insert(turn_id.clone(),captured);state.pending=None;
        let IfcResponse::TurnPlan{turn_id,context,root_token}=std::mem::replace(&mut response.0,IfcResponse::Ok) else {unreachable!("validated reply variant")};
        Ok(ClientGatewayResponse::Plan{turn_id,context,root_token})
    }

}



#[cfg(test)]
mod console_tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    #[derive(Debug)]
    struct MutableConsole(AtomicU32);
    impl ConsoleUser for MutableConsole {
        fn uid(&self)->Option<u32> {match self.0.load(Ordering::SeqCst) {0=>None,n=>Some(n)}}
    }
    #[test]
    fn console_change_and_logout_allow_only_saved_owner_cleanup() {
        let console=Arc::new(MutableConsole(AtomicU32::new(502)));
        let mut g=ClientGateway::new("/unused".into(),"/unused".into(),1,Duration::from_secs(60),false);
        g.console=console.clone();
        let mut owner=PeerCredentials::local(502,20);owner.pid=Some(42);
        let mut other=owner.clone();other.pid=Some(43);
        assert!(g.admit_session(&owner,false).is_ok());
        g.turns.lock().unwrap().insert("fixture".into(),owner.clone());
        console.0.store(503,Ordering::SeqCst);
        assert!(g.admit_session(&owner,false).is_err());
        assert!(g.admit_session(&owner,true).is_ok());
        assert!(g.admit_session(&other,true).is_err());
        assert!(g.admit_session(&PeerCredentials::local(503,20),false).is_ok());
        console.0.store(0,Ordering::SeqCst);
        assert!(g.admit_session(&PeerCredentials::local(501,20),false).unwrap_err().is("GATEWAY_NO_CONSOLE"));
        assert!(g.admit_session(&owner,false).is_err());
        assert!(g.admit_session(&owner,true).is_ok());
        g.turns.lock().unwrap().clear();
        assert!(g.admit_session(&owner,true).is_err());
        // This unit tests session decisions; it does not attest Darwin code identity.
    }
}

#[cfg(test)]
mod lifecycle_fence_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::{fs::PermissionsExt,net::UnixListener};
    use std::sync::mpsc;

    struct Fixture {dir:PathBuf, gateway:Arc<ClientGateway>, listener:UnixListener}
    impl Fixture {
        fn new()->Self {
            let dir=std::env::temp_dir().join(format!("yk-gateway-{}",enclave_core::rng::u64()));
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir,std::fs::Permissions::from_mode(0o700)).unwrap();
            let path=dir.join("runtime.sock");let listener=UnixListener::bind(&path).unwrap();
            let gateway=Arc::new(ClientGateway::new(dir.join("gateway.sock"),path,60,Duration::from_secs(60),true));
            Self {dir,gateway,listener}
        }
    }
    impl Drop for Fixture {fn drop(&mut self){let _=std::fs::remove_dir_all(&self.dir);}}

    #[test]
    fn yk03_positive_upstream_reply_and_revocation_interrupts_blocked_receive() {
        let f=Fixture::new();let listener=f.listener.try_clone().unwrap();
        let server=std::thread::spawn(move||{
            let (mut stream,_)=listener.accept().unwrap();
            assert!(matches!(enclave_core::ipc::from_cbor::<IfcRequest>(&enclave_core::ipc::read_frame(&mut stream).unwrap()).unwrap(),IfcRequest::Status));
            enclave_core::ipc::write_frame(&mut stream,&enclave_core::ipc::to_cbor(&enclave_core::ipc::Reply::Ok(IfcResponse::Ok)).unwrap()).unwrap();
        });
        assert!(matches!(f.gateway.call_ifc(IfcRequest::Status,0,Duration::from_secs(3)).unwrap(),IfcResponse::Ok));
        server.join().unwrap();
        let listener=f.listener.try_clone().unwrap();let (seen,ready)=mpsc::channel();
        let server=std::thread::spawn(move||{
            let (mut stream,_)=listener.accept().unwrap();
            enclave_core::ipc::read_frame(&mut stream).unwrap();seen.send(()).unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut one=[0];assert_eq!(stream.read(&mut one).unwrap(),0,"revoke shuts the active authenticated upstream connection");
        });
        let gateway=f.gateway.clone();
        let caller=std::thread::spawn(move||gateway.call_ifc(IfcRequest::Status,0,Duration::from_secs(30)));
        ready.recv_timeout(Duration::from_secs(3)).unwrap();
        f.gateway.revoke().unwrap();
        assert!(caller.join().unwrap().is_err());server.join().unwrap();
        assert!(f.gateway.calls.lock().unwrap().is_empty());
        assert!(f.gateway.check_generation(0).is_err());
    }

    #[test]
    fn yk03_reply_trickle_cannot_extend_absolute_upstream_deadline() {
        let f=Fixture::new();let listener=f.listener.try_clone().unwrap();
        let server=std::thread::spawn(move||{
            let (mut stream,_)=listener.accept().unwrap();
            enclave_core::ipc::read_frame(&mut stream).unwrap();
            if stream.write_all(&64u32.to_be_bytes()).is_err(){return;}
            for _ in 0..64 {if stream.write_all(&[0]).is_err(){break;}std::thread::sleep(Duration::from_millis(20));}
        });
        let error=f.gateway.call_ifc(IfcRequest::Status,0,Duration::from_millis(100)).unwrap_err();
        assert!(error.is("IPC_FRAME_DEADLINE"));server.join().unwrap();
        assert!(f.gateway.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn yk03_malformed_or_unexpected_upstream_plan_retains_cancellation_debt() {
        for kind in 0..3 {
            let f=Fixture::new();let listener=f.listener.try_clone().unwrap();
            let server=std::thread::spawn(move||{
                let (mut stream,_)=listener.accept().unwrap();
                assert!(matches!(enclave_core::ipc::from_cbor::<IfcRequest>(&enclave_core::ipc::read_frame(&mut stream).unwrap()).unwrap(),IfcRequest::RecoverGatewayTurns));
                enclave_core::ipc::write_frame(&mut stream,&enclave_core::ipc::to_cbor(&enclave_core::ipc::Reply::Ok(IfcResponse::GatewayTurns{active_turns:vec![]})).unwrap()).unwrap();
                let (mut stream,_)=listener.accept().unwrap();
                assert!(matches!(enclave_core::ipc::from_cbor::<IfcRequest>(&enclave_core::ipc::read_frame(&mut stream).unwrap()).unwrap(),IfcRequest::BeginGatewayTurn{..}));
                let context=PlanCompileContext{directive:"synthetic private response".into(),attachment_stubs:vec![],tools:vec![]};
                let reply=match kind {
                    0=>IfcResponse::TurnPlan{turn_id:"invalid".into(),context,root_token:Some(vec![7;32].into())},
                    1=>IfcResponse::Plan{context,root_token:Some(vec![7;32].into())},
                    _=>IfcResponse::PlanExecuted{return_value:"synthetic private result".into(),executed_tool_calls:0,output_refs:vec![]},
                };
                enclave_core::ipc::write_frame(&mut stream,&enclave_core::ipc::to_cbor(&enclave_core::ipc::Reply::Ok(reply)).unwrap()).unwrap();
            });
            let mut peer=PeerCredentials::local(enclave_core::ipc::geteuid(),0);peer.pid=Some(std::process::id() as i32);
            let error=f.gateway.handle_request(&peer,ClientGatewayRequest::SubmitExecutableTurn{
                turn:UserTurnV1{directive_short:"synthetic request".into(),attachments:vec![]},attachments:vec![],tools:vec![],budget_mb:0,
            }).unwrap_err();
            assert!(error.is("ERR_GATEWAY_UNEXPECTED_RESP"));
            assert_eq!(f.gateway.submission_gate.lock().unwrap().pending,Some(1));
            assert!(f.gateway.turns.lock().unwrap().is_empty());server.join().unwrap();
        }
    }

    #[test]
    fn yk03_gateway_generation_fences_a_reply_queued_before_socket_write() {
        struct Paused {ready:mpsc::Sender<()>,resume:Mutex<mpsc::Receiver<()>>}
        impl Serialize for Paused {
            fn serialize<S:serde::Serializer>(&self,serializer:S)->Result<S::Ok,S::Error> {
                self.ready.send(()).unwrap();self.resume.lock().unwrap().recv().unwrap();
                serializer.serialize_u64(7)
            }
        }
        let f=Fixture::new();let path=f.dir.join("downstream.sock");
        let listener=enclave_core::ipc::bind(&path,enclave_core::ipc::SocketAccess::OwnerOnly).unwrap();
        let stop=Arc::new(std::sync::atomic::AtomicBool::new(false));let worker_stop=stop.clone();
        let (ready,waiting)=mpsc::channel();let (resume,proceed)=mpsc::channel();
        let proceed=Arc::new(Mutex::new(Some(proceed)));let gateway=f.gateway.clone();
        let server=std::thread::spawn(move||enclave_core::ipc::serve::<u64,Paused,_>(listener,
            enclave_core::ipc::PeerPolicy::allow([enclave_core::ipc::geteuid()]),
            Arc::new(move|_:&PeerCredentials,_:u64| {gateway.attach_reply_fence(0)?;Ok(Paused{ready:ready.clone(),resume:Mutex::new(proceed.lock().unwrap().take().unwrap())})}),worker_stop).unwrap());
        let client=std::thread::spawn(move||enclave_core::ipc::Client::connect(&path,enclave_core::ipc::geteuid()).unwrap().call::<_,u64>(&1u64));
        waiting.recv_timeout(Duration::from_secs(3)).unwrap();
        f.gateway.revoke().unwrap();resume.send(()).unwrap();
        assert!(client.join().unwrap().is_err(),"queued success cannot cross the established gateway fence");
        stop.store(true,Ordering::SeqCst);server.join().unwrap();
    }

    #[test]
    fn yk03_retired_turn_keeps_cleanup_owner_and_generation_exhaustion_stays_closed() {
        let f=Fixture::new();let mut peer=PeerCredentials::local(enclave_core::ipc::geteuid(),0);peer.pid=Some(42);
        f.gateway.turns.lock().unwrap().insert("turn".into(),peer.clone());
        f.gateway.turn_generations.lock().unwrap().insert("turn".into(),0);
        assert!(f.gateway.owned(&peer,"turn").is_ok());
        f.gateway.revoke().unwrap();
        assert!(f.gateway.owned(&peer,"turn").unwrap_err().is("GATEWAY_TURN_REVOKED"));
        assert_eq!(f.gateway.turns.lock().unwrap().get("turn"),Some(&peer));
        f.gateway.generation.store(u64::MAX,Ordering::SeqCst);
        let (tracked,mut remote)=UnixStream::pair().unwrap();
        f.gateway.calls.lock().unwrap().insert(1,(u64::MAX,tracked));
        assert!(f.gateway.revoke().unwrap_err().is("GATEWAY_GENERATION_EXHAUSTED"));
        let mut byte=[0];assert_eq!(remote.read(&mut byte).unwrap(),0);
        assert!(f.gateway.check_generation(u64::MAX).is_err());
        assert_eq!(f.gateway.generation.load(Ordering::SeqCst),u64::MAX);
    }
}
