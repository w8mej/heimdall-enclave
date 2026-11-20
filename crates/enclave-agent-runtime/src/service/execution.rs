//! Authenticated per-turn executor. Neither plans nor transports mint authority.
use std::cell::{Cell, RefCell};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use super::*;
use crate::plan::arguments::{Argument, MAX_ARGUMENT_BYTES};
use crate::plan::dispatch::AuthorizedToolCall;
use crate::plan::interpreter::{EnclaveStarlarkV1, PlanRuntime};
use crate::plan::PlanRef;
use enclave_crypto::biscuit_auth::Biscuit;
use enclave_crypto::pop_biscuit::{make_call, Transport, WireClock};

pub(super) struct PlanExecutor {
    // Distinct from the daemon's policy/grant and tombstone signing keys.
    holder: SigningKey,
    pub(super) token: Vec<u8>,
    pub(super) allowed_tools: std::collections::BTreeSet<String>,
    next_seq: AtomicU64,
    cancelled: AtomicBool,
    pub(super) gate: Mutex<()>,
}
impl PlanExecutor {
    pub(super) fn new() -> Self {
        Self {holder:SigningKey::generate(&mut rand_core::OsRng),token:Vec::new(),allowed_tools:Default::default(),
            next_seq:AtomicU64::new(1),cancelled:AtomicBool::new(false),gate:Mutex::new(())}
    }
    pub(super) fn public_key(&self)->[u8;32] {self.holder.verifying_key().to_bytes()}
    pub(super) fn cancel(&self) {self.cancelled.store(true,Ordering::SeqCst);}
    fn check(&self)->EnclaveResult<()> {
        if self.cancelled.load(Ordering::SeqCst) {fail!(EPERM,"PLAN_TURN_CANCELLED");} Ok(())
    }
}

struct LivePlan<'a> {
    service: &'a IfcService,
    peer: &'a PeerCredentials,
    turn_id: &'a str,
    executor: &'a PlanExecutor,
    plan_hash: [u8;32],
    step_up: bool,
    calls: Cell<usize>,
    outputs: RefCell<Vec<IfcEnvelopeV1>>,
    precheck_policy: Cell<Option<[u8;32]>>,
    prechecked: Cell<bool>,
}

impl IfcService {
    pub(super) fn execute_turn_plan(
        &self, peer:&PeerCredentials, id:&str, source:&str,
        handles:Vec<(String,String)>, fuel:u64, step_up:bool,
    )->EnclaveResult<IfcResponse> {
        if !is_ingress(peer) {fail!(EPERM,"SUBMIT_TURN_INGRESS_ONLY");}
        if source.len()>64*1024 || handles.len()>64 || !(1..=10_000).contains(&fuel) {
            fail!(E2BIG,"PLAN_EXECUTION_BOUNDS");
        }
        let (executor,refs,profile)={
            let st=self.lock()?;
            let names=handles.iter().map(|(_,h)|h.clone()).collect::<Vec<_>>();
            st.turns.check_handle_names(peer,id,&names)?;
            let executor=st.executors.get(id).cloned().ok_or_else(||err!(EPERM,"PLAN_EXTERNAL_HOLDER_UNSUPPORTED"))?;
            let refs=handles.iter().map(|(name,h)|PlanRef::from_heap(&st.heap,h).map(|r|(name.clone(),r))).collect::<EnclaveResult<Vec<_>>>()?;
            (executor,refs,st.profile)
        };
        let _gate=executor.gate.try_lock().map_err(|_|err!(EAGAIN,"PLAN_TURN_BUSY"))?;
        executor.check()?;
        self.lock()?.turns.active(peer,id)?;
        let live=LivePlan {service:self,peer,turn_id:id,executor:&executor,
            plan_hash:*blake3::hash(source.as_bytes()).as_bytes(),step_up,calls:Cell::new(0),outputs:RefCell::new(Vec::new()),
            precheck_policy:Cell::new(None),prechecked:Cell::new(false)};
        let result=EnclaveStarlarkV1::execute_live(source,profile,&refs,fuel,&live);
        // Include lock/sequence/journal failure in the same partial-effects
        // reporting boundary as evaluation and cancellation failures.
        let result=(|| {
            let mut st=self.lock()?;
            // Even a pure evaluation cannot report success after cancellation.
            let result=result.and_then(|value|{executor.check()?;st.turns.active(peer,id)?;Ok(value)});
            let seq=st.seq.next()?;
            if let Some(j)=st.journal.as_mut() {
                j.append(seq,json!({"event":"TURN_PLAN_EXECUTION","plan_blake3":hex::encode(live.plan_hash),
                    "executed_tool_calls":live.calls.get(),"success":result.is_ok(),
                    "prechecked":live.prechecked.get(),
                    "precheck_policy_blake3":live.precheck_policy.get().map(hex::encode)}))?;
            }
            result
        })();
        let return_value=result.map_err(|mut error| {
            // A call may have had effects even if transport or later admission
            // failed. Never claim rollback or invite automatic retries. Keep
            // L3's sealed error surface, and never include arguments/output.
            if profile==Profile::L3 {return err!(EPERM,"ERR_IFC_SEALED_ABORT");}
            if live.calls.get()>0 {
                error.detail=format!("dispatched_tool_calls={}; prior effects may exist; do not retry automatically",live.calls.get());
            }
            error
        })?;
        Ok(IfcResponse::PlanExecuted {return_value,executed_tool_calls:live.calls.get(),output_refs:live.outputs.into_inner()})
    }
}

impl PlanRuntime for LivePlan<'_> {
    fn precheck(&self,calls:&[crate::plan::frozen::PlanToolCall])->EnclaveResult<()> {
        self.executor.check()?;
        let st=self.service.lock()?;
        st.turns.active(self.peer,self.turn_id)?;
        if st.flow_gate.state()==crate::flow_fsm::FlowState::QuarantineAbort || st.ledger_fault.is_some() {
            fail!(EACCES,"ERR_IFC_STATIC_CEDAR_DENIED");
        }
        let token=Biscuit::from(&self.executor.token,st.pdp.root_public()).map_err(|_|err!(EACCES,"PLAN_ROOT_INVALID"))?;
        let sealed=token.seal().map_err(|_|err!(EACCES,"PLAN_ROOT_INVALID"))?;
        let sealed=sealed.to_vec().map_err(|_|err!(EACCES,"PLAN_ROOT_INVALID"))?;
        let facts=enclave_crypto::pop_biscuit::parse_and_verify_token(&sealed,&st.pdp.root_public())?;
        let principal=format!("chain:{}",hex::encode(&facts.chain_blake3[..8]));
        let cedar=st.pdp.cedar();
        self.precheck_policy.set(Some(cedar.bundle_blake3()));
        for call in calls {
            let target=self.service.registry.resolve(&call.server,&call.tool_name);
            // This immutable set is copied from the same curated list used to
            // mint the service-owned root. It cannot be supplied by the plan.
            if call.arity!=3 || !self.executor.allowed_tools.contains(&target.resource.name)
                || !target.annotated
                || !cedar.plan_eligible(&principal,facts.depth,&target.resource,st.profile,self.step_up) {
                fail!(EACCES,"ERR_IFC_STATIC_CEDAR_DENIED");
            }
        }
        self.executor.check()?;
        self.prechecked.set(true);
        Ok(())
    }
    fn cancelled(&self)->bool {self.executor.cancelled.load(Ordering::SeqCst)}
    fn call(&self,server:&str,tool:&str,args:Argument)->EnclaveResult<PlanRef> {
        self.executor.check()?;
        if self.calls.get()>=64 || self.outputs.borrow().len()>=64 {fail!(E2BIG,"PLAN_TOOL_CALL_LIMIT");}
        // MAC/turn ownership verification and materialization share one lock.
        // Typed Ref values are consumed recursively; handle-like strings remain
        // plain literals and acquire the daemon's monotone exposure floor.
        let (bytes,arg_handles,row_bound,wire)={
            let st=self.service.lock()?;
            st.turns.active(self.peer,self.turn_id)?;
            let mut arg_handles=Vec::new();
            let mut bytes=0usize;
            let materialized=materialize(args,None,&st,self.peer,self.turn_id,&mut arg_handles,&mut bytes)?;
            let canonical=enclave_core::jcs::canonicalize(&materialized)?;
            if canonical.len()>MAX_ARGUMENT_BYTES {fail!(E2BIG,"PLAN_ARGUMENT_BOUNDS");}
            let target=self.service.registry.resolve(server,tool);
            let row_bound=target.row_count(&materialized)?;
            let token=Biscuit::from(&self.executor.token,st.pdp.root_public()).map_err(|_|err!(EACCES,"PLAN_ROOT_INVALID"))?;
            let seq=self.executor.next_seq.try_update(Ordering::SeqCst,Ordering::SeqCst,|n|n.checked_add(1))
                .map_err(|_|err!(E2BIG,"PLAN_SEQUENCE_EXHAUSTED"))?;
            let clock=WireClock {local_boot_id:Some(st.pdp.boot_epoch_id().to_owned()),
                mach_continuous_time_ns_expiry:Some(enclave_core::clock::boot_clock_ns().saturating_add(60_000_000_000)),..Default::default()};
            let wire=make_call(&token,&self.executor.holder,&self.peer.channel_binding(),&canonical,seq,Transport::Uds,clock)?.to_cbor()?;
            (canonical,arg_handles,row_bound,wire)
        };
        let CallDecision {decision,dispatch_expiry}=self.service.authorize_tool_call(self.peer,server.into(),tool.into(),bytes.clone(),
            arg_handles.clone(),wire,self.step_up,Some(self.turn_id))?;
        if !decision.allow {fail!(EACCES,"PLAN_TOOL_DENIED");}
        {
            let st=self.service.lock()?;
            st.turns.active(self.peer,self.turn_id)?;
            self.executor.check()?;
        }
        if let Some(expiry)=&dispatch_expiry {expiry.check()?;}
        let call=AuthorizedToolCall {server:server.into(),tool_name:tool.into(),args_jcs:bytes,row_bound,
            authorization_id:enclave_core::rng::bytes32(),plan_blake3:self.plan_hash,dispatch_expiry};
        self.calls.set(self.calls.get()+1);
        // The default port is deliberately unavailable. The trusted production
        // adapter owns artifact selection, native ticket issuance and replay.
        let output=self.service.dispatch.execute(call,&self.executor.cancelled)
            .map_err(|_|err!(EIO,"PLAN_TOOL_TRANSPORT_FAILED"))?;
        // Retain the zeroizing owner even if cancellation, bounds or pin checks
        // reject this output before heap ingress. Other engine/port copies are
        // outside this buffer's ownership guarantee.
        let raw=SecretBytes::new(output.payload);
        self.executor.check()?;
        if let Some(expiry)=&dispatch_expiry {expiry.check()?;}
        if raw.len()>250*1024 || output.tools_list.len()>64*1024 {fail!(E2BIG,"PLAN_TOOL_OUTPUT_BOUNDS");}
        let mut parents=arg_handles.into_iter().map(|(_,h)|h).collect::<Vec<_>>();
        parents.sort();parents.dedup();
        let response=self.service.ingest_tool_output(Some((self.peer,self.turn_id)),server,tool,
            &output.tools_list,raw,Some(decision.input_label.c),&format!("mcp://{server}/{tool}"),&parents)?;
        let IfcResponse::Handle(env)=response else {fail!(EIO,"PLAN_OUTPUT_INVALID");};
        let st=self.service.lock()?;
        st.turns.active(self.peer,self.turn_id)?;
        self.executor.check()?;
        let reference=PlanRef::from_heap(&st.heap,&env.handle)?;
        self.outputs.borrow_mut().push(env);
        Ok(reference)
    }
}

fn materialize(
    argument:Argument, slot:Option<&str>, st:&State, peer:&PeerCredentials, id:&str,
    refs:&mut Vec<(String,String)>, bytes:&mut usize,
)->EnclaveResult<Value> {
    let value=match argument {
        Argument::Scalar(value)=>value,
        Argument::Ref(reference)=>{
            if refs.len()>=64 {fail!(E2BIG,"PLAN_REFERENCE_BOUNDS");}
            st.turns.check_handle_names(peer,id,&[reference.handle().to_owned()])?;
            let live=st.heap.get(reference.handle())?;
            if live.envelope.label!=reference.label() {fail!(EACCES,"HANDLE_FORGERY");}
            let payload=st.heap.payload(reference.handle())?;
            *bytes=bytes.saturating_add(payload.len());
            if *bytes>MAX_ARGUMENT_BYTES {fail!(E2BIG,"PLAN_ARGUMENT_BOUNDS");}
            refs.push((slot.ok_or_else(||err!(EINVAL,"PLAN_ARGUMENT_OBJECT_REQUIRED"))?.into(),reference.handle().into()));
            match serde_json::from_slice(payload) {
                Ok(value)=>value,
                Err(_)=>Value::String(std::str::from_utf8(payload).map_err(|_|err!(EINVAL,"PLAN_REFERENCE_NOT_TEXT"))?.to_owned()),
            }
        }
        Argument::List(values)=>Value::Array(values.into_iter().map(|v|materialize(v,slot,st,peer,id,refs,bytes)).collect::<EnclaveResult<_>>()?),
        Argument::Object(values)=>{
            let mut result=serde_json::Map::new();
            for (key,value) in values {
                let value=materialize(value,slot.or(Some(&key)),st,peer,id,refs,bytes)?;
                result.insert(key,value);
            }
            Value::Object(result)
        }
    };
    Ok(value)
}
