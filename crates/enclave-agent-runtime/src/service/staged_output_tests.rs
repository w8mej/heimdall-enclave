//! Actual private service path with synthetic custody/registry/turn fixtures.
//! Owner Drop ENTRY is observed before SecretMaterial field cleanup. These
//! tests do not claim post-wipe observation, physical erasure or IPC evidence.
use super::*;
use std::{cell::RefCell, sync::atomic::{AtomicU64, AtomicUsize, Ordering}};

const EPOCH: &str = "6f1c2c1e-3a54-4b8e-9d7a-0c4f5b6a7e81";
const RAW: &str = "synthetic tool result";
const RAW_C4: &str = "4111111111111111"; // Public synthetic payment test number.
const SCRUBBED: &str = "SYNTH-STAGED-SURROGATE";

// Capture identities while live and compare them without dereferencing after
// release. No Debug implementation or assertion formatting can log addresses.
struct Event { kind: &'static str, pointer: usize, length: usize, capacity: usize }
thread_local! {
    static EVENTS: RefCell<Option<Vec<Event>>> = const { RefCell::new(None) };
}
pub(super) fn observe(kind: &'static str, bytes: &Vec<u8>) {
    let _ = EVENTS.try_with(|slot| {
        if let Some(events) = slot.borrow_mut().as_mut() {
            events.push(Event { kind, pointer: bytes.as_ptr() as usize,
                length: bytes.len(), capacity: bytes.capacity() });
        }
    });
}
struct Capture;
impl Capture {
    fn new() -> Self { EVENTS.with(|slot| assert!(slot.replace(Some(Vec::new())).is_none())); Self }
    fn finish(self) -> Vec<Event> { EVENTS.with(|slot| slot.borrow_mut().take().expect("active staging observer")) }
}
impl Drop for Capture {
    fn drop(&mut self) { let _ = EVENTS.try_with(|slot| slot.borrow_mut().take()); }
}
fn assert_events(events: &[Event], kinds: &[&str]) {
    assert_eq!(events.iter().map(|event| event.kind).collect::<Vec<_>>(), kinds);
    for event in events.iter().skip(1) {
        assert!(event.pointer == events[0].pointer, "handoff must retain the original allocation");
        assert_eq!(event.length, events[0].length); assert_eq!(event.capacity, events[0].capacity);
    }
}

struct Control {
    reply: Mutex<Option<String>>,
    scrub_refuses: bool,
    slot_refuses: bool,
    scrubs: AtomicUsize,
    slots: AtomicU64,
    after_slot: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}
impl std::fmt::Debug for Control {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("SyntheticStagingControl") }
}
#[derive(Debug)]
struct Custody(Arc<Control>);
impl CustodyPort for Custody {
    fn scrub_text(&self, _: &str, _: bool) -> EnclaveResult<String> {
        self.0.scrubs.fetch_add(1, Ordering::SeqCst);
        if self.0.scrub_refuses { fail!(EACCES, "SYNTHETIC_SCRUB_REFUSAL"); }
        Ok(self.0.reply.lock().unwrap().take().expect("configured synthetic scrub response"))
    }
    fn authorize_intent(&self, _: &IntentDraftV1) -> EnclaveResult<StepUp> {
        fail!(EACCES, "UNEXPECTED_STAGING_AUTHORIZATION")
    }
    fn allocate_slot(&self) -> EnclaveResult<(String, u64)> {
        let slot = self.0.slots.fetch_add(1, Ordering::SeqCst) + 1;
        if let Some(action) = self.0.after_slot.lock().unwrap().take() { action(); }
        if self.0.slot_refuses { fail!(EACCES, "SYNTHETIC_SLOT_REFUSAL"); }
        Ok((EPOCH.into(), slot))
    }
    fn boot_epoch(&self) -> EnclaveResult<enclave_core::seq::BootEpoch> {
        static SIGNER: std::sync::OnceLock<enclave_crypto::epoch::EpochSigner> = std::sync::OnceLock::new();
        Ok(SIGNER.get_or_init(enclave_crypto::epoch::EpochSigner::random).sign(EPOCH))
    }
}
#[derive(Debug)]
struct NoClassification;
impl Declassifier for NoClassification {
    fn classify(&self, _: &[u8], _: u64, _: &str, _: &enclave_core::seq::GovernedSlot) -> EnclaveResult<u64> {
        fail!(EACCES, "UNEXPECTED_STAGING_DECLASSIFICATION")
    }
}
fn tools() -> Value { json!({"tools":[{"name":"read"}]}) }
fn registry() -> ToolRegistry {
    ToolRegistry::load(&serde_json::to_vec(&json!({"v":1,"servers":[{
        "server":"synthetic", "tools_list_blake3":crate::registry::digest_tools_list(&tools()).unwrap(),
        "tools":[{"name":"read","action_class":"A1","sink_clearance":"C3",
            "namespace":"synthetic","canonical_verb":"Read","output_conf":"C3"}]
    }]})).unwrap()).unwrap()
}
fn fixture(reply: Option<String>, scrub_refuses: bool, slot_refuses: bool) -> (Arc<IfcService>, Arc<Control>) {
    let control = Arc::new(Control { reply:Mutex::new(reply),scrub_refuses,slot_refuses,
        scrubs:AtomicUsize::new(0),slots:AtomicU64::new(0),after_slot:Mutex::new(None) });
    let service = IfcService::start(IfcConfig { profile:Profile::L2,audit_path:None,
        policy_key:SigningKey::generate(&mut rand_core::OsRng),
        limits:enclave_crypto::pop_biscuit::spec_limits(),registry:registry(),
        cedar:Some(CedarEngine::baseline_bundle().unwrap()),state_dir:None,socket_dir:None,dev_same_uid:true },
        Box::new(NoClassification),Box::new(Custody(control.clone()))).unwrap();
    service.lock().unwrap().flow_gate = crate::flow_fsm::FlowGate::from_state(crate::flow_fsm::FlowState::CapabilityExec);
    (service,control)
}
fn ingest(service: &IfcService, text: &str) -> EnclaveResult<IfcResponse> {
    service.ingest_tool_output(None,"synthetic","read",&tools().to_string(),
        SecretBytes::from_slice(text.as_bytes()),None,"synthetic://source",&[])
}
fn assert_unpublished(service: &IfcService, control: &Control) {
    let st = service.lock().unwrap(); assert!(st.heap.is_empty());
    assert!(!st.egress.was_released(EPOCH,control.slots.load(Ordering::SeqCst)));
}
fn reserved(text: &str) -> String {
    let mut output = String::with_capacity(256); output.push_str(text); output
}
fn c4_fixture_check() {
    assert!(enclave_core::pii::scan(RAW_C4).iter().any(|finding|finding.kind.is_c4()));
}

#[test]
fn actual_plaintext_ingress_transfers_staged_allocation_and_preserves_hash_label_and_release() {
    let (service,control) = fixture(None,false,false); let observation = Capture::new();
    let IfcResponse::Handle(envelope) = ingest(&service,RAW).unwrap() else {panic!("expected opaque handle")};
    let events = observation.finish(); assert_events(&events,&["adopted","transferred"]);
    assert_eq!(control.scrubs.load(Ordering::SeqCst),0); assert_eq!(control.slots.load(Ordering::SeqCst),1);
    let st = service.lock().unwrap(); let value = st.heap.get(&envelope.handle).unwrap();
    assert!(value.payload.expose().as_ptr() as usize == events[0].pointer);
    assert_eq!(value.payload.allocation_bytes(),events[0].capacity);
    assert_eq!(value.payload.expose(),RAW.as_bytes());
    assert_eq!(envelope.payload_blake3,Some(blake3::hash(RAW.as_bytes()).to_hex().to_string()));
    assert_eq!(envelope.label,Label::new(Conf::C3,enclave_core::label::Taint::T3));
    assert_eq!(envelope.vault_tier,Some(VaultTier::None)); st.heap.verify_presented(&envelope).unwrap();
    assert!(st.egress.was_released(EPOCH,1));
    assert_eq!(st.flow_gate.state(),crate::flow_fsm::FlowState::OpaqueHandleSealed);
}

#[test]
fn actual_scrubbed_ingress_adopts_returned_string_allocation_before_scan_and_keeps_a4_tier() {
    c4_fixture_check(); let reply = reserved(SCRUBBED);
    let original = reply.as_ptr(); let capacity = reply.capacity();
    let (service,control) = fixture(Some(reply),false,false); let observation = Capture::new();
    let IfcResponse::Handle(envelope) = ingest(&service,RAW_C4).unwrap() else {panic!("expected opaque handle")};
    let events = observation.finish(); assert_events(&events,&["adopted","transferred"]);
    assert!(events[0].pointer == original as usize); assert_eq!(events[0].capacity,capacity);
    assert_eq!(control.scrubs.load(Ordering::SeqCst),1); assert_eq!(control.slots.load(Ordering::SeqCst),1);
    let st = service.lock().unwrap(); let value = st.heap.get(&envelope.handle).unwrap();
    assert!(std::ptr::eq(value.payload.expose().as_ptr(),original));
    assert_eq!(value.payload.allocation_bytes(),capacity); assert_eq!(value.payload.expose(),SCRUBBED.as_bytes());
    assert_eq!(envelope.label,Label::new(Conf::C4,enclave_core::label::Taint::T3));
    assert_eq!(envelope.vault_tier,Some(VaultTier::A4)); st.heap.verify_presented(&envelope).unwrap();
    assert!(st.egress.was_released(EPOCH,1));
}

#[test]
fn actual_slot_refusal_retains_zeroizing_staged_owner_for_plain_and_scrubbed_results() {
    c4_fixture_check();
    for scrub in [false,true] {
        let (service,control) = fixture(scrub.then(||reserved(SCRUBBED)),false,true);
        let floor = service.lock().unwrap().heap.literal_exposure(); let observation = Capture::new();
        assert!(ingest(&service,if scrub {RAW_C4} else {RAW}).unwrap_err().is("SYNTHETIC_SLOT_REFUSAL"));
        let events = observation.finish(); assert_events(&events,&["adopted","zeroizing_owner_drop_entered"]);
        assert_unpublished(&service,&control);
        assert_eq!(service.lock().unwrap().heap.literal_exposure(),floor);
        assert_eq!(control.scrubs.load(Ordering::SeqCst),if scrub {1} else {0});
        assert_eq!(control.slots.load(Ordering::SeqCst),1);
    }
}

#[test]
fn actual_post_slot_state_and_turn_refusals_keep_staged_owner_and_publish_no_handle() {
    for kind in 0..3 {
        let (service,control) = fixture(None,false,false);
        let mut peer = PeerCredentials::local(enclave_core::ipc::geteuid(),0); peer.pid=Some(4242);
        let turn = if kind==2 {Some(service.lock().unwrap().turns.begin(peer.clone(),vec![],None).unwrap())} else {None};
        let weak = Arc::downgrade(&service); let closing_turn=turn.clone(); let owner=peer.clone();
        *control.after_slot.lock().unwrap() = Some(Box::new(move || {
            let service=weak.upgrade().unwrap(); let mut st=service.lock().unwrap();
            match kind {
                0 => st.flow_gate=crate::flow_fsm::FlowGate::from_state(crate::flow_fsm::FlowState::QuarantineAbort),
                1 => {st.turns.emergency_wipe();}
                2 => st.turns.close(&owner,closing_turn.as_ref().unwrap()).unwrap(),
                _ => unreachable!(),
            }
        }));
        let floor = service.lock().unwrap().heap.literal_exposure(); let observation = Capture::new();
        let error = service.ingest_tool_output(turn.as_deref().map(|id|(&peer,id)),"synthetic","read",&tools().to_string(),
            SecretBytes::from_slice(RAW.as_bytes()),None,"synthetic://source",&[]).unwrap_err();
        assert!(error.is(match kind {0=>"FLOW_GATE_QUARANTINE_ABORT",1=>"SSM_CLEANUP_PENDING",2=>"TURN_CLOSING",_=>unreachable!()}));
        assert_events(&observation.finish(),&["adopted","zeroizing_owner_drop_entered"]);
        assert_unpublished(&service,&control); assert_eq!(control.slots.load(Ordering::SeqCst),1);
        let st=service.lock().unwrap(); assert_eq!(st.heap.literal_exposure(),floor);
        if kind==0 {assert_eq!(st.flow_gate.state(),crate::flow_fsm::FlowState::QuarantineAbort);}
        if kind==1 {assert!(st.turns.cleanup_pending());}
        if let Some(id)=&turn {assert!(st.turns.active(&peer,id).unwrap_err().is("TURN_CLOSING"));}
    }
}

#[test]
fn actual_surviving_c4_scrub_refusal_is_owned_before_scanner_and_precedes_slot_allocation() {
    c4_fixture_check(); let reply=reserved(RAW_C4); let original=reply.as_ptr(); let capacity=reply.capacity();
    let (service,control)=fixture(Some(reply),false,true); let observation=Capture::new();
    assert!(ingest(&service,RAW_C4).unwrap_err().is("C4_SURVIVED_SCRUB"));
    let events=observation.finish(); assert_events(&events,&["adopted","zeroizing_owner_drop_entered"]);
    assert!(events[0].pointer==original as usize); assert_eq!(events[0].capacity,capacity);
    assert_eq!(control.scrubs.load(Ordering::SeqCst),1); assert_eq!(control.slots.load(Ordering::SeqCst),0);
    assert_unpublished(&service,&control);
}

#[test]
fn actual_scrub_delegate_refusal_preserves_error_precedence_without_staging_or_slot() {
    c4_fixture_check(); let (service,control)=fixture(None,true,true); let observation=Capture::new();
    assert!(ingest(&service,RAW_C4).unwrap_err().is("SYNTHETIC_SCRUB_REFUSAL"));
    assert!(observation.finish().is_empty()); assert_eq!(control.scrubs.load(Ordering::SeqCst),1);
    assert_eq!(control.slots.load(Ordering::SeqCst),0); assert_unpublished(&service,&control);
}

#[test]
fn actual_heap_refusal_happens_after_same_allocation_transfer_with_no_successful_publication() {
    let (service,control)=fixture(None,false,false); service.lock().unwrap().heap.max_payload_bytes=0;
    let floor=service.lock().unwrap().heap.literal_exposure(); let observation=Capture::new();
    assert!(ingest(&service,RAW).unwrap_err().is("CAPABILITY_HEAP_FULL"));
    assert_events(&observation.finish(),&["adopted","transferred"]);
    assert_unpublished(&service,&control); assert_eq!(control.slots.load(Ordering::SeqCst),1);
    assert_eq!(service.lock().unwrap().heap.literal_exposure(),floor);
}
