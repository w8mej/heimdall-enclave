//! Synthetic production-engine ownership tests; no native Mach invocation.
use super::*;
use crate::{err, error::EnclaveResult};
use std::sync::Mutex;

const FIXTURE: [u8; 136] = [
    0x12, 0x11, 0x00, 0x80, 0x54, 0, 0, 0, 0x44, 0x33, 0x22, 0x11, 0x55, 0x44, 0x33, 0x22, 0, 0, 0,
    0, 0x65, 0x09, 0, 0, 2, 0, 0, 0, 0x66, 0x55, 0x44, 0x33, 0, 0, 0, 0, 0, 0, 17, 0, 0x77, 0x66,
    0x55, 0x44, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0xfe,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 52, 0, 0, 0,
    0x88, 0x77, 0x66, 0x55, 1, 1, 1, 1, 2, 2, 2, 2, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
];

#[derive(Default)]
struct Events {
    trace: Vec<&'static str>,
    receives: usize,
    destroys: usize,
    fresh: usize,
    options: Vec<i32>,
    timeouts: Vec<u32>,
    checks: usize,
    panic_check: Option<usize>,
    refuse: bool,
    revoked: bool,
    refuse_after_receive: bool,
    panic_destroy: bool,
    types: Vec<(u32, Result<u32, i32>)>,
    queries: Vec<u32>,
    receive_address: Option<usize>,
    refuse_check: Option<usize>,
    refuse_after_query: Option<usize>,
    panic_query: Option<usize>,
    query_delay: Option<(usize, Duration)>,
    audit_reads: Vec<(u32, Instant)>,
    audit_result: i32,
    audit_count: Option<u32>,
    audit_original_failure: bool,
    audit_active: Vec<Arc<AtomicBool>>,
    refuse_after_audit: bool,
    panic_audit: bool,
    audit_delay: Option<Duration>,
    binding_calls: Vec<(u32, u32, Instant)>,
    binding_refusal: Option<Refusal>,
    refuse_after_binding: bool,
    panic_binding: bool,
    binding_delay: Option<Duration>,
    startup_calls: Vec<Instant>,
    startup_refusal: Option<(usize, &'static str)>,
    startup_panic: Option<usize>,
    startup_delay: Option<(usize, Duration)>,
    refuse_after_startup: Option<usize>,
    revoked_shared: Arc<AtomicBool>,
    preparation_actor_end: Option<Instant>,
    preparation_caps: Vec<Instant>,
    preparation_drops: Vec<Arc<AtomicBool>>,
    preparation_actors: Vec<Arc<AtomicBool>>,
    preparation_corrupt: Option<&'static str>,
    preparation_checks: Vec<Instant>,
    preparation_refusal: Option<Refusal>,
    preparation_panic: bool,
    preparation_delay: Option<Duration>,
    refuse_after_preparation: bool,
    prepared_data: Vec<(i32, [i64; 2], crate::quarantine_types::FaultKind, u64)>,
    dispatch: Option<DispatchScript>,
    dispatch_guard_calls: Arc<std::sync::atomic::AtomicUsize>,
}
struct Session {
    end: Instant,
    events: Arc<Mutex<Events>>,
}
impl SessionDependency for Session {
    fn current(&self) -> EnclaveResult<()> {
        let mut events = self.events.lock().unwrap();
        events.checks += 1;
        if events.refuse_check == Some(events.checks) {
            events.refuse = true;
        }
        let panic = events.panic_check == Some(events.checks);
        let refuse =
            events.refuse || events.revoked || events.revoked_shared.load(Ordering::SeqCst);
        drop(events);
        if panic {
            panic!("SYNTHETIC_CONTEXT_UNWIND");
        }
        if refuse {
            return Err(err!(EACCES, "SYNTHETIC_CONTEXT_REFUSED"));
        }
        Ok(())
    }
    fn revoke(&self) {
        let mut events = self.events.lock().unwrap();
        events.revoked = true;
        events.revoked_shared.store(true, Ordering::SeqCst);
        events.trace.push("revoke");
    }
    fn original_end(&self) -> Instant {
        self.end
    }
}
struct Scripted {
    events: Arc<Mutex<Events>>,
    result: i32,
    frame: Vec<u8>,
}
impl Kernel for Scripted {
    fn retained_startup_current(&mut self, end: Instant) -> EnclaveResult<()> {
        let mut events = self.events.lock().unwrap();
        events.startup_calls.push(end);
        let call = events.startup_calls.len();
        events.trace.push("retained-startup");
        assert_eq!(
            events.destroys, 0,
            "original resource cleanup cannot precede startup observation"
        );
        if call == 3 {
            assert_eq!(events.binding_calls.len(), 1);
            assert!(
                events.audit_active.last().unwrap().load(Ordering::SeqCst),
                "retain original audit lease across final startup observation"
            );
        }
        let refusal = events
            .startup_refusal
            .filter(|(at, _)| *at == call)
            .map(|(_, reason)| reason);
        let delay = events
            .startup_delay
            .filter(|(at, _)| *at == call)
            .map(|(_, delay)| delay);
        let panic = events.startup_panic == Some(call);
        if events.refuse_after_startup == Some(call) {
            events.refuse = true;
        }
        drop(events);
        if let Some(delay) = delay {
            std::thread::sleep(delay);
        }
        if panic {
            panic!("SYNTHETIC_RETAINED_STARTUP_OBSERVATION_UNWIND");
        }
        if let Some(reason) = refusal {
            return Err(err!(EACCES, reason));
        }
        Ok(())
    }
    fn receive(&mut self, storage: &mut Storage, options: i32, timeout: u32) -> i32 {
        assert_eq!((storage.0.as_ptr() as usize) % 16, 0);
        let mut events = self.events.lock().unwrap();
        events.receives += 1;
        events.receive_address = Some(storage.0.as_ptr() as usize);
        if storage.0.iter().all(|byte| *byte == 0) {
            events.fresh += 1;
        }
        events.trace.push("receive");
        events.options.push(options);
        events.timeouts.push(timeout);
        if events.refuse_after_receive {
            events.refuse = true;
        }
        storage.0[..self.frame.len()].copy_from_slice(&self.frame);
        self.result
    }
    fn object_type_in_self(&mut self, name: u32) -> Result<u32, i32> {
        let mut events = self.events.lock().unwrap();
        events.queries.push(name);
        let index = events.queries.len();
        events.trace.push("local-object-query");
        let result = events
            .types
            .iter()
            .find(|(actual, _)| *actual == name)
            .map(|(_, result)| *result)
            .unwrap_or(Err(15));
        if events.refuse_after_query == Some(index) {
            events.refuse = true;
        }
        let panic = events.panic_query == Some(index);
        let delay = events
            .query_delay
            .filter(|(at, _)| *at == index)
            .map(|(_, delay)| delay);
        drop(events);
        if let Some(delay) = delay {
            std::thread::sleep(delay);
        }
        if panic {
            panic!("SYNTHETIC_LOCAL_OBJECT_QUERY_UNWIND");
        }
        result
    }
    fn task_audit_of_classified_original(
        &mut self,
        name: u32,
        end: Instant,
    ) -> Result<AuditLease, AuditReadFailure> {
        let mut events = self.events.lock().unwrap();
        assert_eq!(
            events.destroys, 0,
            "retain original received message during audit query"
        );
        events.audit_reads.push((name, end));
        events.trace.push("task-audit");
        let result = events.audit_result;
        let count = events.audit_count.unwrap_or(TASK_AUDIT_TOKEN_COUNT);
        let original_failure = events.audit_original_failure;
        let delay = events.audit_delay;
        let panic = events.panic_audit;
        if events.refuse_after_audit {
            events.refuse = true;
        }
        let active = Arc::new(AtomicBool::new(true));
        events.audit_active.push(active.clone());
        let lease = AuditLease {
            active,
            evidence: AuditEvidence::Fixture,
        };
        drop(events);
        if let Some(delay) = delay {
            std::thread::sleep(delay);
        }
        if panic {
            panic!("SYNTHETIC_TASK_AUDIT_UNWIND");
        }
        checked_audit_output(result, count, [0x87654321; 8])?;
        if original_failure {
            return Err(AuditReadFailure::OriginalContext);
        }
        Ok(lease)
    }
    fn actor_and_assignment_of_original(
        &mut self,
        storage: &Storage,
        task_name: u32,
        task_kind: u32,
        end: Instant,
        audit: &AuditLease,
    ) -> Result<OriginalFaultPreparation, Refusal> {
        let mut events = self.events.lock().unwrap();
        assert_eq!(events.destroys, 0);
        assert_eq!(events.receive_address, Some(storage.0.as_ptr() as usize));
        assert!(audit.active.load(Ordering::SeqCst));
        assert!(Arc::ptr_eq(
            events.audit_active.last().unwrap(),
            &audit.active
        ));
        events.binding_calls.push((task_name, task_kind, end));
        events.trace.push("actor-assignment");
        let failure = events.binding_refusal;
        let delay = events.binding_delay;
        let panic = events.panic_binding;
        if events.refuse_after_binding {
            events.refuse = true;
        }
        drop(events);
        if let Some(delay) = delay {
            std::thread::sleep(delay);
        }
        if panic {
            panic!("SYNTHETIC_ACTOR_ASSIGNMENT_UNWIND");
        }
        if let Some(stage) = failure {
            return Err(stage);
        }
        if task_kind != IPC_OTYPE_TASK_CONTROL {
            return Err(Refusal::CurrentExceptionAssignment);
        }
        let (proof, corrupt) = {
            let mut events = self.events.lock().unwrap();
            let actor = Arc::new(AtomicBool::new(true));
            let dropped = Arc::new(AtomicBool::new(false));
            events.preparation_actors.push(actor.clone());
            events.preparation_drops.push(dropped.clone());
            (
                FixtureFaultEvidence {
                    end: events.preparation_actor_end.unwrap_or(end),
                    audit: audit.active.clone(),
                    actor,
                    revoked: events.revoked_shared.clone(),
                    dropped,
                    armed: false,
                },
                events.preparation_corrupt,
            )
        };
        let mut preparation = OriginalFaultPreparation::from_original(
            storage,
            task_name,
            task_kind,
            0x22334455,
            end,
            FaultEvidence::Fixture(proof),
        )?;
        if let FaultEvidence::Fixture(proof) = &mut preparation.evidence {
            proof.armed = true;
        }
        {
            let mut events = self.events.lock().unwrap();
            events.preparation_caps.push(preparation.end);
            events.prepared_data.push((
                preparation.inputs.exception,
                preparation.inputs.codes,
                preparation.kind,
                preparation.address,
            ));
        }
        match corrupt {
            Some("end") => preparation.end = end,
            Some("session") => preparation.session_end = end + Duration::from_secs(1),
            Some("code") => preparation.inputs.codes[0] ^= 1,
            Some("thread") => preparation.inputs.names[2] ^= 1,
            Some("task") => preparation.inputs.names[3] ^= 1,
            Some("reply") => preparation.inputs.names[0] ^= 1,
            Some("exception") => preparation.inputs.exception = 12,
            Some("class") => preparation.kind = crate::quarantine_types::FaultKind::Pac,
            Some("address") => preparation.address ^= 1,
            Some("actor") => {
                if let FaultEvidence::Fixture(proof) = &preparation.evidence {
                    proof.actor.store(false, Ordering::SeqCst);
                }
            }
            Some("audit") => {
                if let FaultEvidence::Fixture(proof) = &mut preparation.evidence {
                    proof.audit = Arc::new(AtomicBool::new(true));
                }
            }
            Some(other) => panic!("unexpected synthetic corruption: {other}"),
            None => {}
        }
        Ok(preparation)
    }
    fn validate_fault_preparation_of_original(
        &mut self,
        storage: &Storage,
        task_name: u32,
        task_kind: u32,
        end: Instant,
        audit: &AuditLease,
        preparation: &OriginalFaultPreparation,
    ) -> Result<(), Refusal> {
        let mut events = self.events.lock().unwrap();
        assert_eq!(events.destroys, 0);
        assert_eq!(events.receive_address, Some(storage.0.as_ptr() as usize));
        assert!(audit.active.load(Ordering::SeqCst));
        assert!(events
            .preparation_drops
            .iter()
            .all(|dropped| !dropped.load(Ordering::SeqCst)));
        events.preparation_checks.push(end);
        events.trace.push("fault-preparation");
        let refusal = events.preparation_refusal;
        let panic = events.preparation_panic;
        let delay = events.preparation_delay;
        let original_session_end = events.binding_calls[0].2;
        if events.refuse_after_preparation {
            events.refuse = true;
        }
        drop(events);
        if preparation.session_end != original_session_end {
            return Err(Refusal::FaultPreparationOriginal);
        }
        preparation.require_original(storage, task_name, task_kind, 0x22334455, end)?;
        match &preparation.evidence {
            FaultEvidence::Fixture(proof)
                if Arc::ptr_eq(&proof.audit, &audit.active)
                    && proof.actor.load(Ordering::SeqCst) => {}
            _ => return Err(Refusal::FaultPreparationOriginal),
        }
        if let Some(delay) = delay {
            std::thread::sleep(delay);
        }
        if panic {
            panic!("SYNTHETIC_ORIGINAL_FAULT_VALIDATION_UNWIND");
        }
        if let Some(stage) = refusal {
            return Err(stage);
        }
        preparation.require_endpoint(end)
    }
    fn destroy_received(&mut self, storage: &mut Storage) {
        let mut events = self.events.lock().unwrap();
        events.destroys += 1;
        events.trace.push("destroy");
        assert_eq!(events.receive_address, Some(storage.0.as_ptr() as usize));
        assert!(
            events
                .audit_active
                .iter()
                .all(|active| !active.load(Ordering::SeqCst)),
            "invalidate every passive audit view before any original message cleanup"
        );
        assert!(
            events
                .preparation_drops
                .iter()
                .all(|dropped| dropped.load(Ordering::SeqCst)),
            "retire original preparation only after veto and before message cleanup"
        );
        let panic = events.panic_destroy;
        drop(events);
        if panic {
            panic!("SYNTHETIC_CLEANUP_UNWIND");
        }
    }
    fn dispatch_fault_of_original(
        &mut self,
        storage: &mut Storage,
        _resources: &mut Resources,
        task_name: u32,
        task_kind: u32,
        end: Instant,
        audit: &AuditLease,
        preparation: &OriginalFaultPreparation,
    ) -> Result<crate::quarantine_types::Response, Refusal> {
        let (script, calls) = {
            let mut events = self.events.lock().unwrap();
            // Older ownership fixtures intentionally stop before this newly
            // implemented seam. New fixtures select the actual shared engine.
            if events.dispatch.is_none() {
                return Err(Refusal::RemainingFaultAndStartupCompositionUnavailable);
            }
            events.trace.push("dispatch-original");
            assert_eq!(events.destroys, 0);
            assert_eq!(events.receive_address, Some(storage.0.as_ptr() as usize));
            assert!(Arc::ptr_eq(
                events.audit_active.last().unwrap(),
                &audit.active
            ));
            assert!(audit.active.load(Ordering::SeqCst));
            assert!(events
                .preparation_drops
                .iter()
                .all(|dropped| !dropped.load(Ordering::SeqCst)));
            (
                events.dispatch.take().unwrap(),
                events.dispatch_guard_calls.clone(),
            )
        };
        preparation.require_original(storage, task_name, task_kind, 0x22334455, end)?;
        let actor = match &preparation.evidence {
            FaultEvidence::Fixture(proof) if Arc::ptr_eq(&proof.audit, &audit.active) => {
                proof.actor.clone()
            }
            _ => return Err(Refusal::FaultPreparationOriginal),
        };
        let original_bytes = storage.0;
        let mut script = script;
        script.valid = Some(actor.clone());
        let tracker = script.tracker.clone();
        let socket_root = script.socket_root.clone();
        let mut guard = SelectedFaultIoGuard::fixture_bound(end, &actor, &calls, &preparation);
        let result = dispatch_original_fault(
            &tracker,
            &socket_root,
            preparation,
            &mut guard,
            &mut FaultDispatchBackend::Scripted(&mut script),
        );
        // This fixture exercises report-only scope; Native composes its valid
        // receipt into failure reply under an independent actual lifetime veto.
        guard.veto();
        preparation.evidence.invalidate();
        assert_eq!(
            storage.0, original_bytes,
            "report-only fixture retains the original whole message"
        );
        assert!(
            !audit.active.load(Ordering::SeqCst),
            "terminal fixture retires original audit before return"
        );
        self.events.lock().unwrap().dispatch = Some(script);
        result
            .map(|receipt| receipt.response)
            .map_err(|_| Refusal::FaultDispatchUnavailable)
    }
}
fn setup(result: i32, frame: &[u8]) -> (SessionLifetime<Session>, Scripted, Arc<Mutex<Events>>) {
    let events = Arc::new(Mutex::new(Events {
        types: vec![
            (0x44556677, Ok(IPC_OTYPE_TASK_CONTROL)),
            (0x33445566, Ok(IPC_OTYPE_THREAD_READ)),
        ],
        ..Events::default()
    }));
    let session = Session {
        end: Instant::now() + Duration::from_secs(60),
        events: events.clone(),
    };
    (
        SessionLifetime::new(session, Arc::new(AtomicBool::new(false))),
        Scripted {
            events: events.clone(),
            result,
            frame: frame.to_vec(),
        },
        events,
    )
}
fn run(result: i32, frame: &[u8]) -> (Outcome, Arc<Mutex<Events>>) {
    let (lifetime, kernel, events) = setup(result, frame);
    let outcome = Attempt::new(kernel, &lifetime, 0x22334455).run();
    (outcome, events)
}
fn refused(outcome: Outcome, stage: Refusal, code: i32, cleanup: Cleanup) {
    assert_eq!(
        outcome,
        Outcome::Refused {
            stage,
            native_result: Some(code),
            cleanup
        }
    );
}
fn revoke_before_destroy(events: &Events) {
    assert!(
        events
            .trace
            .iter()
            .position(|event| *event == "revoke")
            .unwrap()
            < events
                .trace
                .iter()
                .position(|event| *event == "destroy")
                .unwrap()
    );
}
fn kernel_frame() -> [u8; 136] {
    // Explicit synthetic native-return fixture, not an actual kernel receipt.
    let mut frame = FIXTURE;
    frame[96..104].copy_from_slice(&KERNEL_SECURITY_TOKEN);
    frame[104..136].copy_from_slice(&KERNEL_AUDIT_TOKEN);
    frame
}
fn local_refusal(
    result: i32,
    frame: &[u8],
    types: Vec<(u32, Result<u32, i32>)>,
) -> (Outcome, Arc<Mutex<Events>>) {
    let (lifetime, kernel, events) = setup(result, frame);
    events.lock().unwrap().types = types;
    let outcome = Attempt::new(kernel, &lifetime, 0x22334455).run();
    (outcome, events)
}

#[test]
fn exact_structural_user_fixture_refuses_kernel_trailer_without_local_queries_and_destroys_once() {
    let (outcome, events) = run(0, &FIXTURE);
    refused(
        outcome,
        Refusal::KernelTrailer,
        0,
        Cleanup::NativeDestroyInvokedCompletionUnqualified,
    );
    let events = events.lock().unwrap();
    assert_eq!((events.receives, events.destroys, events.fresh), (1, 1, 1));
    revoke_before_destroy(&events);
    assert_eq!(events.options, [0x03000502]);
    assert!(events
        .timeouts
        .iter()
        .all(|timeout| *timeout > 0 && *timeout <= 500));
    assert!(events.queries.is_empty());
}

#[test]
fn malformed_application_id_and_wrong_destination_never_forward_and_keep_actual_message_cleanup() {
    for (offset, value, stage) in [
        (20, 2401, Refusal::Wire(mach_wire::WireError::MessageId)),
        (12, 0x11111111, Refusal::ReceiveName),
    ] {
        let mut frame = FIXTURE;
        frame[offset..offset + 4].copy_from_slice(&u32::to_le_bytes(value));
        let (outcome, events) = run(0, &frame);
        refused(
            outcome,
            stage,
            0,
            Cleanup::NativeDestroyInvokedCompletionUnqualified,
        );
        let events = events.lock().unwrap();
        assert_eq!(events.destroys, 1);
        revoke_before_destroy(&events);
    }
}

#[test]
fn partial_body_with_every_known_shortage_combination_owns_cleanup_before_any_codec_check() {
    let mut frame = FIXTURE;
    frame[52] ^= 0xff; // Invalid application NDR, valid native resource extent.
    for flags in (0..16).map(|subset| subset << 10) {
        let result = BODY_ERROR | flags;
        let (outcome, events) = run(result, &frame);
        refused(
            outcome,
            Refusal::PartialBody,
            result,
            Cleanup::NativeDestroyInvokedCompletionUnqualified,
        );
        let events = events.lock().unwrap();
        assert_eq!(events.destroys, 1);
        revoke_before_destroy(&events);
        assert!(events.queries.is_empty());
    }
}

#[test]
fn timeout_is_only_loop_progress_and_never_constructs_cleanup_or_revokes_live_session() {
    let (lifetime, kernel, events) = setup(TIMED_OUT, &[]);
    let end = lifetime.end;
    assert_eq!(
        Attempt::new(kernel, &lifetime, 0x22334455).run(),
        Outcome::TimeoutProgress
    );
    assert_eq!(lifetime.end, end);
    assert!(lifetime.current().is_ok());
    let events = events.lock().unwrap();
    assert_eq!(events.receives, 1);
    assert_eq!(events.destroys, 0);
    assert_eq!(events.startup_calls, [end, end]);
    assert!(!events.trace.contains(&"revoke"));
}

#[test]
fn known_no_message_failures_never_destroy_fresh_or_spurious_storage_and_remain_terminal() {
    for (result, stage) in [
        (HEADER_ERROR, Refusal::HeaderError),
        (HEADER_ERROR | KNOWN_SHORTAGES, Refusal::HeaderError),
        (TOO_LARGE, Refusal::TooLarge),
        (INTERRUPTED, Refusal::Interrupted),
    ] {
        let (outcome, events) = run(result, &FIXTURE);
        refused(outcome, stage, result, Cleanup::NotRequired);
        let events = events.lock().unwrap();
        assert_eq!(events.destroys, 0);
        assert!(events.trace.contains(&"revoke"));
        assert_eq!(
            events.startup_calls.len(),
            1,
            "known terminal native failure admits no second startup observation"
        );
    }
}

#[test]
fn invalid_data_unknown_result_and_unknown_shortage_bit_never_guess_cleanup_ownership() {
    for (result, stage) in [
        (INVALID_DATA, Refusal::InvalidData),
        (0x12345678, Refusal::UnknownNativeResult),
        (BODY_ERROR | 0x200, Refusal::UnknownNativeResult),
        (TIMED_OUT | 0x400, Refusal::UnknownNativeResult),
    ] {
        let (outcome, events) = run(result, &FIXTURE);
        refused(
            outcome,
            stage,
            result,
            Cleanup::UnknownNoSafeDescribedResourceCleanup,
        );
        let events = events.lock().unwrap();
        assert_eq!(events.destroys, 0);
        assert!(events.trace.contains(&"revoke"));
    }
}

#[test]
fn actual_trailer_extent_is_not_manufactured_from_capacity_or_zeroed_tail() {
    let mut short = FIXTURE;
    short[88..92].copy_from_slice(&8u32.to_le_bytes());
    let (outcome, events) = run(0, &short[..92]);
    refused(
        outcome,
        Refusal::Wire(mach_wire::WireError::FrameLength),
        0,
        Cleanup::NativeDestroyInvokedCompletionUnqualified,
    );
    assert_eq!(events.lock().unwrap().destroys, 1);
    let mut huge = FIXTURE;
    huge[88..92].copy_from_slice(&u32::MAX.to_le_bytes());
    let (outcome, events) = run(0, &huge);
    refused(
        outcome,
        Refusal::FrameExtent,
        0,
        Cleanup::NativeDestroyInvokedCompletionUnqualified,
    );
    assert_eq!(events.lock().unwrap().destroys, 1);
}

#[test]
fn impossible_native_body_extent_keeps_uncertainty_instead_of_walking_unsafe_resource_layout() {
    for size in [0, 23, 85, u32::MAX] {
        let mut frame = FIXTURE;
        frame[4..8].copy_from_slice(&u32::to_le_bytes(size));
        let (outcome, events) = run(0, &frame);
        refused(
            outcome,
            Refusal::InvalidNativeExtent,
            0,
            Cleanup::UnknownNoSafeDescribedResourceCleanup,
        );
        assert_eq!(events.lock().unwrap().destroys, 0);
    }
}

#[test]
fn postreceive_context_failure_retains_resource_owner_until_revocation_and_cleanup() {
    let (lifetime, kernel, events) = setup(0, &FIXTURE);
    events.lock().unwrap().refuse_after_receive = true;
    let outcome = Attempt::new(kernel, &lifetime, 0x22334455).run();
    refused(
        outcome,
        Refusal::PostReceiveContext,
        0,
        Cleanup::NativeDestroyInvokedCompletionUnqualified,
    );
    let events = events.lock().unwrap();
    assert_eq!(events.destroys, 1);
    revoke_before_destroy(&events);
}

#[test]
fn stop_or_expiry_forbids_native_call_and_failed_message_can_never_rearm_a_second_receive() {
    let (mut lifetime, kernel, events) = setup(0, &FIXTURE);
    lifetime.end = Instant::now();
    let end = lifetime.end;
    assert!(matches!(
        Attempt::new(kernel, &lifetime, 0x22334455).run(),
        Outcome::Refused {
            stage: Refusal::BeforeReceive,
            ..
        }
    ));
    assert_eq!(lifetime.end, end);
    assert_eq!(events.lock().unwrap().receives, 0);
    assert!(
        events.lock().unwrap().startup_calls.is_empty(),
        "expired original cannot enter startup observation"
    );
    let (lifetime, kernel, events) = setup(0, &FIXTURE);
    let _ = Attempt::new(kernel, &lifetime, 0x22334455).run();
    let next = Scripted {
        events: events.clone(),
        result: 0,
        frame: FIXTURE.to_vec(),
    };
    assert!(matches!(
        Attempt::new(next, &lifetime, 0x22334455).run(),
        Outcome::Refused {
            stage: Refusal::BeforeReceive,
            ..
        }
    ));
    let events = events.lock().unwrap();
    assert_eq!((events.receives, events.destroys), (1, 1));
}

#[test]
fn caught_postreceive_unwind_revokes_before_exactly_one_cleanup_of_original_storage() {
    let (lifetime, kernel, events) = setup(0, &FIXTURE);
    events.lock().unwrap().panic_check = Some(5);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Attempt::new(kernel, &lifetime, 0x22334455).run()
    }));
    assert!(result.is_err());
    let events = events.lock().unwrap();
    assert_eq!((events.receives, events.destroys), (1, 1));
    revoke_before_destroy(&events);
}

#[test]
fn cleanup_is_consumed_before_native_call_and_unwind_cannot_repeat_it() {
    let (lifetime, kernel, events) = setup(0, &FIXTURE);
    events.lock().unwrap().panic_destroy = true;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Attempt::new(kernel, &lifetime, 0x22334455).run()
    }));
    assert!(result.is_err());
    let events = events.lock().unwrap();
    assert_eq!(events.destroys, 1);
    revoke_before_destroy(&events);
}

#[test]
fn exact_kernel_fixture_checks_all_control_read_pairs_but_never_admits_actor_or_assignment() {
    for task in [IPC_OTYPE_TASK_CONTROL, IPC_OTYPE_TASK_READ] {
        for thread in [IPC_OTYPE_THREAD_CONTROL, IPC_OTYPE_THREAD_READ] {
            let (outcome, events) = local_refusal(
                0,
                &kernel_frame(),
                vec![(0x44556677, Ok(task)), (0x33445566, Ok(thread))],
            );
            refused(
                outcome,
                if task == IPC_OTYPE_TASK_CONTROL {
                    Refusal::RemainingFaultAndStartupCompositionUnavailable
                } else {
                    Refusal::CurrentExceptionAssignment
                },
                0,
                Cleanup::NativeDestroyInvokedCompletionUnqualified,
            );
            let events = events.lock().unwrap();
            assert_eq!(events.queries, [0x44556677, 0x33445566]);
            assert_eq!((events.receives, events.destroys), (1, 1));
            revoke_before_destroy(&events);
        }
    }
}

#[test]
fn every_audit_and_security_byte_must_match_whole_kernel_tokens_before_any_object_query() {
    for offset in 96..136 {
        let mut frame = kernel_frame();
        frame[offset] ^= 1;
        let (outcome, events) = run(0, &frame);
        refused(
            outcome,
            Refusal::KernelTrailer,
            0,
            Cleanup::NativeDestroyInvokedCompletionUnqualified,
        );
        let events = events.lock().unwrap();
        assert!(events.queries.is_empty());
        assert_eq!(events.destroys, 1);
        revoke_before_destroy(&events);
    }
}

#[test]
fn forged_kernel_looking_body_and_short_actual_trailer_cannot_substitute_for_native_trailer() {
    // A kernel-looking pair embedded in application code bytes cannot replace
    // the independently returned full trailer. Codec code fields are opaque.
    let mut body = FIXTURE;
    body[68..84].fill(0);
    let (outcome, events) = run(0, &body);
    refused(
        outcome,
        Refusal::KernelTrailer,
        0,
        Cleanup::NativeDestroyInvokedCompletionUnqualified,
    );
    assert!(events.lock().unwrap().queries.is_empty());
    let mut short = kernel_frame();
    short[88..92].copy_from_slice(&8u32.to_le_bytes());
    let (outcome, events) = run(0, &short[..92]);
    refused(
        outcome,
        Refusal::Wire(mach_wire::WireError::FrameLength),
        0,
        Cleanup::NativeDestroyInvokedCompletionUnqualified,
    );
    assert!(events.lock().unwrap().queries.is_empty());
    for result in [
        BODY_ERROR,
        HEADER_ERROR,
        TIMED_OUT,
        INVALID_DATA,
        0x12345678,
    ] {
        let (_, events) = run(result, &kernel_frame());
        assert!(events.lock().unwrap().queries.is_empty());
    }
}

#[test]
fn ordinary_unknown_wrong_flavor_and_internal_looking_task_types_never_reach_thread_query() {
    for kind in [0, u32::MAX, 1, 20, 44, 46, 47, 50, 51, 0x1000] {
        let (outcome, events) = local_refusal(0, &kernel_frame(), vec![(0x44556677, Ok(kind))]);
        refused(
            outcome,
            Refusal::TaskObjectType,
            0,
            Cleanup::NativeDestroyInvokedCompletionUnqualified,
        );
        let events = events.lock().unwrap();
        assert_eq!(events.queries, [0x44556677]);
        assert_eq!(events.destroys, 1);
        revoke_before_destroy(&events);
    }
}

#[test]
fn thread_type_must_independently_match_original_thread_descriptor_without_task_substitution() {
    for kind in [0, u32::MAX, 2, 20, 44, 45, 46, 50, 0x1000] {
        let (outcome, events) = local_refusal(
            0,
            &kernel_frame(),
            vec![
                (0x44556677, Ok(IPC_OTYPE_TASK_READ)),
                (0x33445566, Ok(kind)),
            ],
        );
        refused(
            outcome,
            Refusal::ThreadObjectType,
            0,
            Cleanup::NativeDestroyInvokedCompletionUnqualified,
        );
        let events = events.lock().unwrap();
        assert_eq!(events.queries, [0x44556677, 0x33445566]);
        assert_eq!(events.destroys, 1);
        revoke_before_destroy(&events);
    }
}

#[test]
fn descriptor_swap_and_alias_cannot_turn_two_numeric_names_into_task_thread_authority() {
    let mut swapped = kernel_frame();
    let thread = swapped[28..32].to_vec();
    let task = swapped[40..44].to_vec();
    swapped[28..32].copy_from_slice(&task);
    swapped[40..44].copy_from_slice(&thread);
    let (outcome, events) = run(0, &swapped);
    refused(
        outcome,
        Refusal::TaskObjectType,
        0,
        Cleanup::NativeDestroyInvokedCompletionUnqualified,
    );
    assert_eq!(events.lock().unwrap().queries, [0x33445566]);
    let mut alias = kernel_frame();
    alias[28..32].copy_from_slice(&0x44556677u32.to_le_bytes());
    let (outcome, events) = run(0, &alias);
    refused(
        outcome,
        Refusal::ThreadObjectType,
        0,
        Cleanup::NativeDestroyInvokedCompletionUnqualified,
    );
    assert_eq!(events.lock().unwrap().queries, [0x44556677, 0x44556677]);
}

#[test]
fn object_query_errors_or_death_are_terminal_and_never_requery_or_guess_output_type() {
    for code in [4, 15, 16, 17, -303, -1] {
        let (outcome, events) = local_refusal(0, &kernel_frame(), vec![(0x44556677, Err(code))]);
        refused(
            outcome,
            Refusal::TaskObjectQuery(code),
            0,
            Cleanup::NativeDestroyInvokedCompletionUnqualified,
        );
        let events = events.lock().unwrap();
        assert_eq!(events.queries, [0x44556677]);
        assert_eq!(events.destroys, 1);
        revoke_before_destroy(&events);
        drop(events);
        let (outcome, events) = local_refusal(
            0,
            &kernel_frame(),
            vec![
                (0x44556677, Ok(IPC_OTYPE_TASK_READ)),
                (0x33445566, Err(code)),
            ],
        );
        refused(
            outcome,
            Refusal::ThreadObjectQuery(code),
            0,
            Cleanup::NativeDestroyInvokedCompletionUnqualified,
        );
        let events = events.lock().unwrap();
        assert_eq!(events.queries, [0x44556677, 0x33445566]);
        assert_eq!(events.destroys, 1);
        revoke_before_destroy(&events);
    }
}

#[test]
fn every_object_query_pre_and_postcheck_keeps_same_lifetime_and_cleans_only_after_revoke() {
    // SessionLifetime.current checks actual dependency both before and after.
    for (check, stage, queries) in [
        (9, Refusal::BeforeTaskObjectQuery, 0),
        (11, Refusal::AfterTaskObjectQuery, 1),
        (13, Refusal::BeforeThreadObjectQuery, 1),
        (15, Refusal::AfterThreadObjectQuery, 2),
    ] {
        let (lifetime, kernel, events) = setup(0, &kernel_frame());
        let end = lifetime.end;
        events.lock().unwrap().refuse_check = Some(check);
        let outcome = Attempt::new(kernel, &lifetime, 0x22334455).run();
        refused(
            outcome,
            stage,
            0,
            Cleanup::NativeDestroyInvokedCompletionUnqualified,
        );
        assert_eq!(lifetime.end, end);
        let events = events.lock().unwrap();
        assert_eq!(events.queries.len(), queries);
        assert_eq!(events.destroys, 1);
        revoke_before_destroy(&events);
    }
}

#[test]
fn object_query_return_cannot_outlive_original_endpoint_or_reset_session_veto() {
    let (mut lifetime, kernel, events) = setup(0, &kernel_frame());
    lifetime.end = Instant::now() + Duration::from_millis(250);
    let end = lifetime.end;
    events.lock().unwrap().query_delay = Some((1, Duration::from_millis(300)));
    let outcome = Attempt::new(kernel, &lifetime, 0x22334455).run();
    refused(
        outcome,
        Refusal::AfterTaskObjectQuery,
        0,
        Cleanup::NativeDestroyInvokedCompletionUnqualified,
    );
    assert_eq!(lifetime.end, end);
    let next = Scripted {
        events: events.clone(),
        result: 0,
        frame: kernel_frame().to_vec(),
    };
    lifetime
        .stop
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(matches!(
        Attempt::new(next, &lifetime, 0x22334455).run(),
        Outcome::Refused {
            stage: Refusal::BeforeReceive,
            ..
        }
    ));
    let events = events.lock().unwrap();
    assert_eq!(events.queries, [0x44556677]);
    assert_eq!((events.receives, events.destroys), (1, 1));
    revoke_before_destroy(&events);
}

#[test]
fn context_loss_during_either_local_query_is_sticky_even_after_external_stop_flag_reset() {
    for (query, stage) in [
        (1, Refusal::AfterTaskObjectQuery),
        (2, Refusal::AfterThreadObjectQuery),
    ] {
        let (lifetime, kernel, events) = setup(0, &kernel_frame());
        events.lock().unwrap().refuse_after_query = Some(query);
        let outcome = Attempt::new(kernel, &lifetime, 0x22334455).run();
        refused(
            outcome,
            stage,
            0,
            Cleanup::NativeDestroyInvokedCompletionUnqualified,
        );
        lifetime
            .stop
            .store(false, std::sync::atomic::Ordering::SeqCst);
        events.lock().unwrap().refuse = false; // Transient context may look healthy again.
        let next = Scripted {
            events: events.clone(),
            result: 0,
            frame: kernel_frame().to_vec(),
        };
        assert!(matches!(
            Attempt::new(next, &lifetime, 0x22334455).run(),
            Outcome::Refused {
                stage: Refusal::BeforeReceive,
                ..
            }
        ));
        let events = events.lock().unwrap();
        assert_eq!(events.queries.len(), query);
        assert_eq!((events.receives, events.destroys), (1, 1));
        revoke_before_destroy(&events);
    }
}

#[test]
fn local_object_query_or_postcheck_unwind_keeps_owned_storage_until_revoke_then_one_cleanup() {
    for (panic_query, panic_check, queries) in [
        (Some(1), None, 1),
        (Some(2), None, 2),
        (None, Some(11), 1),
        (None, Some(15), 2),
    ] {
        let (lifetime, kernel, events) = setup(0, &kernel_frame());
        {
            let mut events = events.lock().unwrap();
            events.panic_query = panic_query;
            events.panic_check = panic_check;
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Attempt::new(kernel, &lifetime, 0x22334455).run()
        }));
        assert!(result.is_err());
        let events = events.lock().unwrap();
        assert_eq!(events.queries.len(), queries);
        assert_eq!(events.destroys, 1);
        revoke_before_destroy(&events);
    }
}

#[test]
fn queried_message_cleanup_is_consumed_before_callback_and_never_uses_descriptor_destructors() {
    let (lifetime, kernel, events) = setup(0, &kernel_frame());
    events.lock().unwrap().panic_destroy = true;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Attempt::new(kernel, &lifetime, 0x22334455).run()
    }));
    assert!(result.is_err());
    let events = events.lock().unwrap();
    assert_eq!(events.queries, [0x44556677, 0x33445566]);
    assert_eq!(events.destroys, 1);
    revoke_before_destroy(&events);
}

#[test]
fn actual_audit_output_requires_success_and_exact_count_preserving_all_eight_opaque_words() {
    assert_eq!((TASK_AUDIT_TOKEN, TASK_AUDIT_TOKEN_COUNT), (15, 8));
    let words = [0, 1, u32::MAX, 0x01020304, 0x05060708, 17, 703, 0x80000000];
    assert_eq!(checked_audit_output(0, 8, words).unwrap(), words);
    for count in [0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 32, u32::MAX] {
        assert_eq!(
            checked_audit_output(0, count, words),
            Err(AuditReadFailure::Count)
        );
    }
    for result in [4, 5, 15, 16, 17, -303, -1] {
        for count in [0, 8, u32::MAX] {
            assert_eq!(
                checked_audit_output(result, count, words),
                Err(AuditReadFailure::Native(result))
            );
        }
    }
    for word in 0..8 {
        let mut changed = words;
        changed[word] ^= 1;
        assert_eq!(checked_audit_output(0, 8, changed).unwrap(), changed);
    }
}

#[test]
fn task_audit_and_actor_wait_borrow_same_original_names_storage_lease_and_endpoint_in_order() {
    let (lifetime, kernel, events) = setup(0, &kernel_frame());
    let end = lifetime.end;
    refused(
        Attempt::new(kernel, &lifetime, 0x22334455).run(),
        Refusal::RemainingFaultAndStartupCompositionUnavailable,
        0,
        Cleanup::NativeDestroyInvokedCompletionUnqualified,
    );
    let events = events.lock().unwrap();
    assert_eq!(events.audit_reads, [(0x44556677, end)]);
    assert_eq!(
        events.binding_calls,
        [(0x44556677, IPC_OTYPE_TASK_CONTROL, end)]
    );
    assert_eq!(
        events
            .trace
            .iter()
            .filter(|event| **event == "local-object-query")
            .count(),
        2
    );
    let audit = events
        .trace
        .iter()
        .position(|event| *event == "task-audit")
        .unwrap();
    let actor = events
        .trace
        .iter()
        .position(|event| *event == "actor-assignment")
        .unwrap();
    let destroy = events
        .trace
        .iter()
        .position(|event| *event == "destroy")
        .unwrap();
    assert!(audit < actor && actor < destroy);
    assert!(events
        .audit_active
        .iter()
        .all(|active| !active.load(Ordering::SeqCst)));
    assert_eq!(events.destroys, 1);
    revoke_before_destroy(&events);
}

#[test]
fn audit_native_errors_bad_counts_and_original_context_refuse_before_actor_without_retry() {
    for failure in [
        AuditReadFailure::Native(4),
        AuditReadFailure::Native(15),
        AuditReadFailure::Native(-303),
        AuditReadFailure::Count,
        AuditReadFailure::OriginalContext,
    ] {
        let (lifetime, kernel, events) = setup(0, &kernel_frame());
        {
            let mut events = events.lock().unwrap();
            match failure {
                AuditReadFailure::Native(code) => events.audit_result = code,
                AuditReadFailure::Count => events.audit_count = Some(7),
                AuditReadFailure::OriginalContext => events.audit_original_failure = true,
            }
        }
        refused(
            Attempt::new(kernel, &lifetime, 0x22334455).run(),
            failure.refusal(),
            0,
            Cleanup::NativeDestroyInvokedCompletionUnqualified,
        );
        let events = events.lock().unwrap();
        assert_eq!(events.audit_reads.len(), 1);
        assert!(events.binding_calls.is_empty());
        assert_eq!(events.destroys, 1);
        assert!(events
            .audit_active
            .iter()
            .all(|active| !active.load(Ordering::SeqCst)));
        revoke_before_destroy(&events);
    }
}

#[test]
fn every_audit_and_actor_pre_postcheck_refuses_without_extending_or_replacing_original_session() {
    for (check, stage, audits, bindings) in [
        (17, Refusal::BeforeTaskAudit, 0, 0),
        (19, Refusal::AfterTaskAudit, 1, 0),
        (21, Refusal::BeforeActorAndAssignment, 1, 0),
        (23, Refusal::AfterActorAndAssignment, 1, 1),
    ] {
        let (lifetime, kernel, events) = setup(0, &kernel_frame());
        let end = lifetime.end;
        events.lock().unwrap().refuse_check = Some(check);
        refused(
            Attempt::new(kernel, &lifetime, 0x22334455).run(),
            stage,
            0,
            Cleanup::NativeDestroyInvokedCompletionUnqualified,
        );
        assert_eq!(lifetime.end, end);
        let events = events.lock().unwrap();
        assert_eq!(events.audit_reads.len(), audits);
        assert_eq!(events.binding_calls.len(), bindings);
        assert_eq!(events.destroys, 1);
        revoke_before_destroy(&events);
    }
}

#[test]
fn audit_or_actor_return_after_original_endpoint_refuses_and_invalidates_before_cleanup() {
    for delayed_audit in [true, false] {
        let (mut lifetime, kernel, events) = setup(0, &kernel_frame());
        lifetime.end = Instant::now() + Duration::from_millis(250);
        let end = lifetime.end;
        {
            let mut events = events.lock().unwrap();
            if delayed_audit {
                events.audit_delay = Some(Duration::from_millis(300));
            } else {
                events.binding_delay = Some(Duration::from_millis(300));
            }
        }
        refused(
            Attempt::new(kernel, &lifetime, 0x22334455).run(),
            if delayed_audit {
                Refusal::AfterTaskAudit
            } else {
                Refusal::AfterActorAndAssignment
            },
            0,
            Cleanup::NativeDestroyInvokedCompletionUnqualified,
        );
        assert_eq!(lifetime.end, end);
        let events = events.lock().unwrap();
        assert_eq!(events.audit_reads, [(0x44556677, end)]);
        assert_eq!(events.binding_calls.len(), usize::from(!delayed_audit));
        assert_eq!(events.destroys, 1);
        revoke_before_destroy(&events);
    }
}

#[test]
fn audit_or_actor_unwind_and_postcheck_panic_preserve_lease_until_invalidation_then_once_cleanup() {
    for condition in ["audit", "audit_post", "actor", "actor_post"] {
        let (lifetime, kernel, events) = setup(0, &kernel_frame());
        {
            let mut events = events.lock().unwrap();
            match condition {
                "audit" => events.panic_audit = true,
                "audit_post" => events.panic_check = Some(19),
                "actor" => events.panic_binding = true,
                "actor_post" => events.panic_check = Some(23),
                _ => unreachable!(),
            }
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Attempt::new(kernel, &lifetime, 0x22334455).run()
        }));
        assert!(result.is_err());
        let events = events.lock().unwrap();
        assert_eq!(events.audit_reads.len(), 1);
        assert_eq!(events.destroys, 1);
        assert_eq!(
            events.binding_calls.len(),
            usize::from(condition.starts_with("actor"))
        );
        assert!(events
            .audit_active
            .iter()
            .all(|active| !active.load(Ordering::SeqCst)));
        revoke_before_destroy(&events);
    }
}

#[test]
fn actor_or_assignment_refusal_still_invalidates_audit_and_destroys_original_once() {
    for stage in [
        Refusal::ActorPeerComparison,
        Refusal::CurrentExceptionAssignment,
    ] {
        let (lifetime, kernel, events) = setup(0, &kernel_frame());
        events.lock().unwrap().binding_refusal = Some(stage);
        refused(
            Attempt::new(kernel, &lifetime, 0x22334455).run(),
            stage,
            0,
            Cleanup::NativeDestroyInvokedCompletionUnqualified,
        );
        let events = events.lock().unwrap();
        assert_eq!(events.binding_calls.len(), 1);
        assert_eq!(events.destroys, 1);
        revoke_before_destroy(&events);
    }
}

#[test]
fn context_loss_during_audit_or_actor_wait_is_sticky_despite_stop_flag_and_transient_reset() {
    for audit_loss in [true, false] {
        let (lifetime, kernel, events) = setup(0, &kernel_frame());
        {
            let mut events = events.lock().unwrap();
            if audit_loss {
                events.refuse_after_audit = true;
            } else {
                events.refuse_after_binding = true;
            }
        }
        refused(
            Attempt::new(kernel, &lifetime, 0x22334455).run(),
            if audit_loss {
                Refusal::AfterTaskAudit
            } else {
                Refusal::AfterActorAndAssignment
            },
            0,
            Cleanup::NativeDestroyInvokedCompletionUnqualified,
        );
        lifetime.stop.store(false, Ordering::SeqCst);
        events.lock().unwrap().refuse = false;
        let next = Scripted {
            events: events.clone(),
            result: 0,
            frame: kernel_frame().to_vec(),
        };
        assert!(matches!(
            Attempt::new(next, &lifetime, 0x22334455).run(),
            Outcome::Refused {
                stage: Refusal::BeforeReceive,
                ..
            }
        ));
        let events = events.lock().unwrap();
        assert_eq!(events.audit_reads.len(), 1);
        assert_eq!((events.receives, events.destroys), (1, 1));
        revoke_before_destroy(&events);
    }
}

fn binding_fixture(
    audit: [u32; 8],
) -> (AuditBinding<Session>, Arc<Mutex<Events>>, Arc<AtomicBool>) {
    let events = Arc::new(Mutex::new(Events::default()));
    let active = Arc::new(AtomicBool::new(true));
    let end = Instant::now() + Duration::from_secs(60);
    (
        AuditBinding {
            audit,
            session: Session {
                end,
                events: events.clone(),
            },
            end,
            active: active.clone(),
        },
        events,
        active,
    )
}
fn fixture_peer(audit: [u32; 8]) -> crate::ipc::PeerCredentials {
    crate::ipc::PeerCredentials {
        uid: crate::daemon::DaemonId::CustodyVault.uid(),
        gid: 0,
        pid: None,
        audit_token: Some(audit),
        code_identity: Some(crate::codesign::CodeIdentity {
            identifier: "synthetic-custody".into(),
            team_id: "synthetic-team".into(),
            cdhash: "ab".repeat(20),
        }),
        tls_channel_binding: None,
    }
}

#[test]
fn private_binding_compares_every_whole_audit_word_and_never_uses_pid_telemetry_as_identity() {
    let audit = [0, 1, 2, 3, 4, 5, 6, 7];
    for word in 0..8 {
        let (binding, events, active) = binding_fixture(audit);
        let mut peer = fixture_peer(audit);
        peer.pid = Some(12345);
        binding.matches_peer(&peer).unwrap();
        peer.audit_token.as_mut().unwrap()[word] ^= 1;
        assert!(binding
            .matches_peer(&peer)
            .unwrap_err()
            .is("SUPERVISOR_RECEIVED_TASK_AUDIT_PEER"));
        assert!(!active.load(Ordering::SeqCst));
        assert!(events.lock().unwrap().revoked);
        peer.audit_token = Some(audit);
        assert!(binding
            .matches_peer(&peer)
            .unwrap_err()
            .is("SUPERVISOR_RECEIVED_TASK_AUDIT_INACTIVE"));
    }
}

#[test]
fn private_binding_rejects_absent_peer_audit_wrong_role_missing_code_and_network_substitution() {
    let audit = [0x12345678; 8];
    for condition in ["audit", "role", "code", "tls"] {
        let (binding, events, active) = binding_fixture(audit);
        let mut peer = fixture_peer(audit);
        match condition {
            "audit" => peer.audit_token = None,
            "role" => peer.uid = 0,
            "code" => peer.code_identity = None,
            "tls" => peer.tls_channel_binding = Some([9; 32]),
            _ => unreachable!(),
        }
        assert!(binding
            .matches_peer(&peer)
            .unwrap_err()
            .is("SUPERVISOR_RECEIVED_TASK_AUDIT_PEER"));
        assert!(!active.load(Ordering::SeqCst));
        assert!(events.lock().unwrap().revoked);
    }
}

#[test]
fn private_binding_endpoint_cannot_extend_original_and_external_liveness_reset_does_not_unrevoke() {
    let (binding, events, active) = binding_fixture([42; 8]);
    let extended = binding.end.checked_add(Duration::from_nanos(1)).unwrap();
    assert!(binding
        .checked(extended, || panic!("must refuse before operation"))
        .unwrap_err()
        .is("SUPERVISOR_RECEIVED_TASK_AUDIT_INACTIVE"));
    assert!(!active.load(Ordering::SeqCst));
    assert!(events.lock().unwrap().revoked);
    active.store(true, Ordering::SeqCst);
    assert!(binding
        .checked(binding.end, || Ok(()))
        .unwrap_err()
        .is("SYNTHETIC_CONTEXT_REFUSED"));
    assert!(!active.load(Ordering::SeqCst));
    let (binding, events, active) = binding_fixture([43; 8]);
    assert!(binding
        .checked(Instant::now(), || panic!("expired operation"))
        .is_err());
    assert!(!active.load(Ordering::SeqCst));
    assert!(events.lock().unwrap().revoked);
}

#[test]
fn private_binding_pre_post_failure_and_unwind_terminally_revoke_same_session() {
    for condition in ["pre", "post", "operation", "panic"] {
        let (binding, events, active) = binding_fixture([73; 8]);
        {
            let mut events = events.lock().unwrap();
            match condition {
                "pre" => events.refuse_check = Some(1),
                "post" => events.refuse_check = Some(2),
                _ => {}
            }
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            binding.checked(binding.end, || {
                if condition == "operation" {
                    return Err(err!(EACCES, "SYNTHETIC_BINDING_OPERATION"));
                }
                if condition == "panic" {
                    panic!("SYNTHETIC_BINDING_UNWIND");
                }
                Ok(())
            })
        }));
        if condition == "panic" {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert!(!active.load(Ordering::SeqCst));
        assert!(events.lock().unwrap().revoked);
    }
}

#[test]
fn private_nonclone_lease_drop_invalidates_all_shared_passive_liveness_views() {
    let active = Arc::new(AtomicBool::new(true));
    let queued = active.clone();
    let other = active.clone();
    let lease = AuditLease {
        active,
        evidence: AuditEvidence::Fixture,
    };
    assert!(queued.load(Ordering::SeqCst));
    assert!(other.load(Ordering::SeqCst));
    drop(lease);
    assert!(!queued.load(Ordering::SeqCst));
    assert!(!other.load(Ordering::SeqCst));
}

#[test]
fn retained_startup_missing_busy_poisoned_or_changed_refuses_before_receive_without_late_acquisition(
) {
    for reason in [
        "STARTUP_LEASE_NOT_RETAINED",
        "STARTUP_LEASE_OBSERVATION_BUSY",
        "STARTUP_LEASE_POISONED",
        "STARTUP_LEASE_CHANGED",
    ] {
        let (lifetime, kernel, events) = setup(0, &kernel_frame());
        let end = lifetime.end;
        events.lock().unwrap().startup_refusal = Some((1, reason));
        assert_eq!(
            Attempt::new(kernel, &lifetime, 0x22334455).run(),
            Outcome::Refused {
                stage: Refusal::BeforeReceiveStartupLease,
                native_result: None,
                cleanup: Cleanup::NotRequired
            }
        );
        assert_eq!(lifetime.end, end);
        assert!(lifetime.stop.load(Ordering::SeqCst));
        {
            let mut events = events.lock().unwrap();
            assert_eq!(events.startup_calls, [end]);
            assert_eq!((events.receives, events.destroys), (0, 0));
            assert!(
                events.queries.is_empty()
                    && events.audit_reads.is_empty()
                    && events.binding_calls.is_empty()
            );
            assert!(events.revoked);
            events.startup_refusal = None;
            events.refuse = false;
        }
        lifetime.stop.store(false, Ordering::SeqCst);
        let next = Scripted {
            events: events.clone(),
            result: 0,
            frame: kernel_frame().to_vec(),
        };
        assert!(matches!(
            Attempt::new(next, &lifetime, 0x22334455).run(),
            Outcome::Refused {
                stage: Refusal::BeforeReceive,
                ..
            }
        ));
        assert_eq!(
            events.lock().unwrap().startup_calls,
            [end],
            "no second owner observation after terminal veto"
        );
    }
}

#[test]
fn retained_startup_loss_after_receive_withholds_timeout_progress_and_preserves_native_resource_accounting(
) {
    for result in [TIMED_OUT, 0] {
        let (lifetime, kernel, events) = setup(result, &kernel_frame());
        let end = lifetime.end;
        events.lock().unwrap().startup_refusal = Some((2, "STARTUP_LEASE_CHANGED"));
        refused(
            Attempt::new(kernel, &lifetime, 0x22334455).run(),
            Refusal::PostReceiveStartupLease,
            result,
            if result == 0 {
                Cleanup::NativeDestroyInvokedCompletionUnqualified
            } else {
                Cleanup::NotRequired
            },
        );
        assert_eq!(lifetime.end, end);
        assert!(lifetime.stop.load(Ordering::SeqCst));
        let events = events.lock().unwrap();
        assert_eq!(events.startup_calls, [end, end]);
        assert_eq!(events.receives, 1);
        assert_eq!(events.destroys, usize::from(result == 0));
        assert!(
            events.queries.is_empty()
                && events.audit_reads.is_empty()
                && events.binding_calls.is_empty()
        );
        assert!(events.revoked);
        if result == 0 {
            revoke_before_destroy(&events);
        }
    }
}

#[test]
fn retained_startup_loss_after_original_control_assignment_keeps_message_and_audit_until_veto_then_once_cleanup(
) {
    let (lifetime, kernel, events) = setup(0, &kernel_frame());
    let end = lifetime.end;
    {
        let mut events = events.lock().unwrap();
        events.types[0].1 = Ok(IPC_OTYPE_TASK_CONTROL);
        events.startup_refusal = Some((3, "STARTUP_LEASE_CHANGED"));
    }
    refused(
        Attempt::new(kernel, &lifetime, 0x22334455).run(),
        Refusal::AfterActorAndAssignmentStartupLease,
        0,
        Cleanup::NativeDestroyInvokedCompletionUnqualified,
    );
    assert_eq!(lifetime.end, end);
    assert!(lifetime.stop.load(Ordering::SeqCst));
    let events = events.lock().unwrap();
    assert_eq!(events.startup_calls, [end, end, end]);
    assert_eq!(
        events.binding_calls,
        [(0x44556677, IPC_OTYPE_TASK_CONTROL, end)]
    );
    assert_eq!(events.audit_reads, [(0x44556677, end)]);
    assert_eq!((events.receives, events.destroys), (1, 1));
    let actor = events
        .trace
        .iter()
        .position(|event| *event == "actor-assignment")
        .unwrap();
    let final_startup = events
        .trace
        .iter()
        .rposition(|event| *event == "retained-startup")
        .unwrap();
    let veto = events
        .trace
        .iter()
        .position(|event| *event == "revoke")
        .unwrap();
    assert!(actor < final_startup && final_startup < veto);
    revoke_before_destroy(&events);
    assert!(events
        .audit_active
        .iter()
        .all(|active| !active.load(Ordering::SeqCst)));
}

#[test]
fn retained_startup_observer_cannot_return_past_original_endpoint_or_emit_late_progress() {
    for call in 1..=3 {
        let (mut lifetime, kernel, events) = setup(0, &kernel_frame());
        lifetime.end = Instant::now() + Duration::from_millis(250);
        let end = lifetime.end;
        {
            let mut events = events.lock().unwrap();
            events.types[0].1 = Ok(IPC_OTYPE_TASK_CONTROL);
            events.startup_delay = Some((call, Duration::from_millis(300)));
        }
        let stage = match call {
            1 => Refusal::BeforeReceiveStartupLease,
            2 => Refusal::PostReceiveStartupLease,
            _ => Refusal::AfterActorAndAssignmentStartupLease,
        };
        assert_eq!(
            Attempt::new(kernel, &lifetime, 0x22334455).run(),
            Outcome::Refused {
                stage,
                native_result: if call == 1 { None } else { Some(0) },
                cleanup: if call == 1 {
                    Cleanup::NotRequired
                } else {
                    Cleanup::NativeDestroyInvokedCompletionUnqualified
                }
            }
        );
        assert_eq!(lifetime.end, end);
        assert!(lifetime.stop.load(Ordering::SeqCst));
        let events = events.lock().unwrap();
        assert_eq!(events.startup_calls, vec![end; call]);
        assert_eq!(events.receives, usize::from(call != 1));
        assert_eq!(events.destroys, usize::from(call != 1));
        assert_eq!(events.binding_calls.len(), usize::from(call == 3));
        assert!(events.revoked);
        if call != 1 {
            revoke_before_destroy(&events);
        }
    }
}

#[test]
fn retained_startup_observer_session_loss_is_terminal_even_if_observer_returns_ok_and_stop_is_reset(
) {
    for call in 1..=3 {
        let (lifetime, kernel, events) = setup(0, &kernel_frame());
        let end = lifetime.end;
        {
            let mut events = events.lock().unwrap();
            events.types[0].1 = Ok(IPC_OTYPE_TASK_CONTROL);
            events.refuse_after_startup = Some(call);
        }
        let stage = match call {
            1 => Refusal::BeforeReceiveStartupLease,
            2 => Refusal::PostReceiveStartupLease,
            _ => Refusal::AfterActorAndAssignmentStartupLease,
        };
        assert!(matches!(Attempt::new(kernel,&lifetime,0x22334455).run(),
            Outcome::Refused {stage:actual,..} if actual==stage));
        {
            let mut events = events.lock().unwrap();
            assert_eq!(events.startup_calls, vec![end; call]);
            assert_eq!(
                (events.receives, events.destroys),
                (usize::from(call != 1), usize::from(call != 1))
            );
            assert!(events.revoked);
            if call != 1 {
                revoke_before_destroy(&events);
            }
            events.refuse = false;
            events.refuse_after_startup = None;
        }
        lifetime.stop.store(false, Ordering::SeqCst);
        let next = Scripted {
            events: events.clone(),
            result: 0,
            frame: kernel_frame().to_vec(),
        };
        assert!(matches!(
            Attempt::new(next, &lifetime, 0x22334455).run(),
            Outcome::Refused {
                stage: Refusal::BeforeReceive,
                ..
            }
        ));
        assert_eq!(events.lock().unwrap().startup_calls, vec![end; call]);
    }
}

#[test]
fn retained_startup_observer_unwind_revokes_originals_before_cleanup_and_never_reobserves_after_reset(
) {
    for call in 1..=3 {
        let (lifetime, kernel, events) = setup(0, &kernel_frame());
        let end = lifetime.end;
        {
            let mut events = events.lock().unwrap();
            events.types[0].1 = Ok(IPC_OTYPE_TASK_CONTROL);
            events.startup_panic = Some(call);
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Attempt::new(kernel, &lifetime, 0x22334455).run()
        }));
        assert!(result.is_err());
        assert!(lifetime.stop.load(Ordering::SeqCst));
        {
            let mut events = events.lock().unwrap();
            assert_eq!(events.startup_calls, vec![end; call]);
            assert_eq!(
                (events.receives, events.destroys),
                (usize::from(call != 1), usize::from(call != 1))
            );
            assert_eq!(events.binding_calls.len(), usize::from(call == 3));
            assert!(events.revoked);
            assert!(events
                .audit_active
                .iter()
                .all(|active| !active.load(Ordering::SeqCst)));
            if call != 1 {
                revoke_before_destroy(&events);
            }
            events.startup_panic = None;
        }
        lifetime.stop.store(false, Ordering::SeqCst);
        let next = Scripted {
            events: events.clone(),
            result: 0,
            frame: kernel_frame().to_vec(),
        };
        assert!(matches!(
            Attempt::new(next, &lifetime, 0x22334455).run(),
            Outcome::Refused {
                stage: Refusal::BeforeReceive,
                ..
            }
        ));
        assert_eq!(events.lock().unwrap().startup_calls, vec![end; call]);
    }
}

#[test]
fn retained_startup_valid_observations_keep_same_original_end_and_control_message_but_never_admit_fault_or_startup(
) {
    let (lifetime, kernel, events) = setup(0, &kernel_frame());
    let end = lifetime.end;
    events.lock().unwrap().types[0].1 = Ok(IPC_OTYPE_TASK_CONTROL);
    refused(
        Attempt::new(kernel, &lifetime, 0x22334455).run(),
        Refusal::RemainingFaultAndStartupCompositionUnavailable,
        0,
        Cleanup::NativeDestroyInvokedCompletionUnqualified,
    );
    assert_eq!(lifetime.end, end);
    let events = events.lock().unwrap();
    assert_eq!(events.startup_calls, [end, end, end]);
    assert_eq!(events.audit_reads, [(0x44556677, end)]);
    assert_eq!(
        events.binding_calls,
        [(0x44556677, IPC_OTYPE_TASK_CONTROL, end)]
    );
    let observations: Vec<_> = events
        .trace
        .iter()
        .enumerate()
        .filter_map(|(index, event)| (*event == "retained-startup").then_some(index))
        .collect();
    let receive = events
        .trace
        .iter()
        .position(|event| *event == "receive")
        .unwrap();
    let actor = events
        .trace
        .iter()
        .position(|event| *event == "actor-assignment")
        .unwrap();
    assert!(
        observations[0] < receive
            && receive < observations[1]
            && observations[1] < actor
            && actor < observations[2]
    );
    assert_eq!((events.receives, events.destroys), (1, 1));
    revoke_before_destroy(&events);
    assert!(events
        .audit_active
        .iter()
        .all(|active| !active.load(Ordering::SeqCst)));
}

#[test]
fn original_fault_preparation_preserves_raw_codes_conservative_classification_and_earliest_actor_cap_without_dispatch(
) {
    use crate::quarantine_types::FaultKind;
    for earlier in [false, true] {
        for (exception, code, arm, other) in [
            (1, 0x105, FaultKind::Pac, FaultKind::Segv),
            (1, 0x106, FaultKind::HeapTag, FaultKind::Segv),
            (1, 0x107, FaultKind::HeapTag, FaultKind::Segv),
            (1, 0x102, FaultKind::Segv, FaultKind::Segv),
            (2, 0x105, FaultKind::Redzone, FaultKind::Redzone),
            (12, 0x106, FaultKind::Redzone, FaultKind::Redzone),
        ] {
            let mut frame = kernel_frame();
            let address = i64::MIN + 7;
            frame[60..64].copy_from_slice(&i32::to_le_bytes(exception));
            frame[68..76].copy_from_slice(&i64::to_le_bytes(code));
            frame[76..84].copy_from_slice(&address.to_le_bytes());
            let (lifetime, kernel, events) = setup(0, &frame);
            let end = lifetime.end;
            let actor_end = if earlier {
                Instant::now() + Duration::from_secs(2)
            } else {
                end + Duration::from_secs(1)
            };
            events.lock().unwrap().preparation_actor_end = Some(actor_end);
            let cap = end.min(actor_end);
            refused(
                Attempt::new(kernel, &lifetime, 0x22334455).run(),
                Refusal::RemainingFaultAndStartupCompositionUnavailable,
                0,
                Cleanup::NativeDestroyInvokedCompletionUnqualified,
            );
            assert_eq!(lifetime.end, end);
            let events = events.lock().unwrap();
            assert_eq!(events.startup_calls, [end, end, cap]);
            assert_eq!(events.preparation_caps, [cap]);
            assert_eq!(events.preparation_checks, [cap]);
            assert_eq!(events.binding_calls.len(), 1);
            assert_eq!(
                events.prepared_data,
                [(
                    exception,
                    [code, address],
                    if cfg!(target_arch = "aarch64") {
                        arm
                    } else {
                        other
                    },
                    address as u64
                )]
            );
            assert!(events
                .preparation_drops
                .iter()
                .all(|dropped| dropped.load(Ordering::SeqCst)));
            assert_eq!((events.receives, events.destroys), (1, 1));
            revoke_before_destroy(&events);
        }
    }
}

#[test]
fn original_fault_preparation_cannot_replace_actor_cap_session_raw_inputs_classification_or_exact_proof(
) {
    for corruption in [
        "end",
        "session",
        "code",
        "thread",
        "task",
        "reply",
        "exception",
        "class",
        "address",
        "actor",
        "audit",
    ] {
        let (lifetime, kernel, events) = setup(0, &kernel_frame());
        let end = lifetime.end;
        let cap = Instant::now() + Duration::from_secs(2);
        {
            let mut events = events.lock().unwrap();
            events.preparation_actor_end = Some(cap);
            events.preparation_corrupt = Some(corruption);
        }
        refused(
            Attempt::new(kernel, &lifetime, 0x22334455).run(),
            if corruption == "end" {
                Refusal::FaultPreparationEndpoint
            } else {
                Refusal::FaultPreparationOriginal
            },
            0,
            Cleanup::NativeDestroyInvokedCompletionUnqualified,
        );
        assert_eq!(lifetime.end, end);
        let events = events.lock().unwrap();
        assert_eq!(events.preparation_caps, [cap]);
        assert_eq!(events.binding_calls.len(), 1);
        if corruption == "end" {
            assert_eq!(events.startup_calls, [end, end]);
        } else {
            assert_eq!(events.startup_calls, [end, end, cap]);
        }
        assert!(events
            .preparation_drops
            .iter()
            .all(|dropped| dropped.load(Ordering::SeqCst)));
        assert!(events
            .audit_active
            .iter()
            .all(|active| !active.load(Ordering::SeqCst)));
        assert_eq!((events.receives, events.destroys), (1, 1));
        revoke_before_destroy(&events);
    }
}

#[test]
fn original_fault_actor_expiry_during_final_startup_observation_cannot_borrow_the_later_session_endpoint(
) {
    let (lifetime, kernel, events) = setup(0, &kernel_frame());
    let end = lifetime.end;
    let cap = Instant::now() + Duration::from_millis(500);
    {
        let mut events = events.lock().unwrap();
        events.preparation_actor_end = Some(cap);
        events.startup_delay = Some((3, Duration::from_millis(600)));
    }
    refused(
        Attempt::new(kernel, &lifetime, 0x22334455).run(),
        Refusal::AfterActorAndAssignmentStartupLease,
        0,
        Cleanup::NativeDestroyInvokedCompletionUnqualified,
    );
    assert_eq!(lifetime.end, end);
    let events = events.lock().unwrap();
    assert_eq!(events.startup_calls, [end, end, cap]);
    assert!(events.preparation_checks.is_empty());
    assert_eq!(events.binding_calls.len(), 1);
    assert_eq!(events.destroys, 1);
    revoke_before_destroy(&events);
    assert!(events
        .preparation_drops
        .iter()
        .all(|dropped| dropped.load(Ordering::SeqCst)));
}

#[test]
fn original_fault_actor_expiry_during_actual_revalidation_never_renews_comparison_or_publishes_a_report(
) {
    let (lifetime, kernel, events) = setup(0, &kernel_frame());
    let end = lifetime.end;
    let cap = Instant::now() + Duration::from_millis(500);
    {
        let mut events = events.lock().unwrap();
        events.preparation_actor_end = Some(cap);
        events.preparation_delay = Some(Duration::from_millis(600));
    }
    refused(
        Attempt::new(kernel, &lifetime, 0x22334455).run(),
        Refusal::FaultPreparationEndpoint,
        0,
        Cleanup::NativeDestroyInvokedCompletionUnqualified,
    );
    assert_eq!(lifetime.end, end);
    let events = events.lock().unwrap();
    assert_eq!(events.preparation_checks, [cap]);
    assert_eq!(events.binding_calls.len(), 1);
    assert_eq!(events.startup_calls, [end, end, cap]);
    assert_eq!(events.destroys, 1);
    revoke_before_destroy(&events);
    assert!(events
        .preparation_drops
        .iter()
        .all(|dropped| dropped.load(Ordering::SeqCst)));
}

#[test]
fn original_fault_poststartup_task_audit_actor_or_control_assignment_loss_keeps_same_preparation_until_veto(
) {
    for stage in [
        Refusal::TaskAuditOriginalContext,
        Refusal::ActorPeerComparison,
        Refusal::CurrentExceptionAssignment,
    ] {
        let (lifetime, kernel, events) = setup(0, &kernel_frame());
        let end = lifetime.end;
        events.lock().unwrap().preparation_refusal = Some(stage);
        refused(
            Attempt::new(kernel, &lifetime, 0x22334455).run(),
            stage,
            0,
            Cleanup::NativeDestroyInvokedCompletionUnqualified,
        );
        {
            let events = events.lock().unwrap();
            assert_eq!(events.preparation_checks, [end]);
            assert_eq!(events.binding_calls.len(), 1);
            assert_eq!(events.destroys, 1);
            revoke_before_destroy(&events);
            assert!(events
                .preparation_drops
                .iter()
                .all(|dropped| dropped.load(Ordering::SeqCst)));
        }
        lifetime.stop.store(false, Ordering::SeqCst);
        let next = Scripted {
            events: events.clone(),
            result: 0,
            frame: kernel_frame().to_vec(),
        };
        assert!(matches!(
            Attempt::new(next, &lifetime, 0x22334455).run(),
            Outcome::Refused {
                stage: Refusal::BeforeReceive,
                ..
            }
        ));
        assert_eq!(
            events.lock().unwrap().binding_calls.len(),
            1,
            "never compare a replacement actor after failure"
        );
    }
}

#[test]
fn original_fault_return_postcheck_and_revalidation_unwind_veto_before_dropping_actual_preparation_and_message(
) {
    for condition in ["return_postcheck", "validation", "validation_postcheck"] {
        let (lifetime, kernel, events) = setup(0, &kernel_frame());
        {
            let mut events = events.lock().unwrap();
            match condition {
                "return_postcheck" => events.panic_check = Some(23),
                "validation" => events.preparation_panic = true,
                _ => events.panic_check = Some(29),
            }
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Attempt::new(kernel, &lifetime, 0x22334455).run()
        }));
        assert!(result.is_err());
        assert!(lifetime.stop.load(Ordering::SeqCst));
        let events = events.lock().unwrap();
        assert_eq!(events.preparation_caps.len(), 1);
        assert_eq!(
            events.preparation_checks.len(),
            usize::from(condition != "return_postcheck")
        );
        assert_eq!(events.binding_calls.len(), 1);
        assert_eq!((events.receives, events.destroys), (1, 1));
        assert!(events
            .preparation_drops
            .iter()
            .all(|dropped| dropped.load(Ordering::SeqCst)));
        assert!(events
            .audit_active
            .iter()
            .all(|active| !active.load(Ordering::SeqCst)));
        revoke_before_destroy(&events);
    }
}

#[test]
fn original_fault_late_session_loss_after_validation_is_sticky_despite_external_stop_reset() {
    let (lifetime, kernel, events) = setup(0, &kernel_frame());
    events.lock().unwrap().refuse_after_preparation = true;
    refused(
        Attempt::new(kernel, &lifetime, 0x22334455).run(),
        Refusal::AfterFaultPreparationValidation,
        0,
        Cleanup::NativeDestroyInvokedCompletionUnqualified,
    );
    {
        let mut events = events.lock().unwrap();
        assert_eq!(events.preparation_checks.len(), 1);
        events.refuse = false;
    }
    lifetime.stop.store(false, Ordering::SeqCst);
    let next = Scripted {
        events: events.clone(),
        result: 0,
        frame: kernel_frame().to_vec(),
    };
    assert!(matches!(
        Attempt::new(next, &lifetime, 0x22334455).run(),
        Outcome::Refused {
            stage: Refusal::BeforeReceive,
            ..
        }
    ));
    let events = events.lock().unwrap();
    assert_eq!(events.binding_calls.len(), 1);
    assert_eq!(events.destroys, 1);
    assert!(events
        .preparation_drops
        .iter()
        .all(|dropped| dropped.load(Ordering::SeqCst)));
    revoke_before_destroy(&events);
}

#[test]
fn original_fault_constructor_rejects_read_right_unsupported_exception_bad_frame_and_expired_actor_before_proof_drop(
) {
    for condition in ["read", "exception", "frame", "expired"] {
        let mut frame = kernel_frame();
        let end = Instant::now() + Duration::from_secs(2);
        if condition == "exception" {
            frame[60..64].copy_from_slice(&3i32.to_le_bytes());
        }
        if condition == "frame" {
            frame[20..24].copy_from_slice(&2404i32.to_le_bytes());
        }
        let storage = Storage(frame, MessagePhase::Original);
        let audit = Arc::new(AtomicBool::new(true));
        let revoked = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let evidence = FaultEvidence::Fixture(FixtureFaultEvidence {
            end: if condition == "expired" {
                Instant::now()
            } else {
                end
            },
            audit: audit.clone(),
            actor: Arc::new(AtomicBool::new(true)),
            revoked: revoked.clone(),
            dropped: dropped.clone(),
            armed: true,
        });
        let expected = match condition {
            "read" => Refusal::FaultPreparationTaskClass,
            "exception" => Refusal::FaultPreparationException,
            "frame" => Refusal::FaultPreparationFrame,
            _ => Refusal::FaultPreparationEndpoint,
        };
        let result = OriginalFaultPreparation::from_original(
            &storage,
            0x44556677,
            if condition == "read" {
                IPC_OTYPE_TASK_READ
            } else {
                IPC_OTYPE_TASK_CONTROL
            },
            0x22334455,
            end,
            evidence,
        );
        assert!(matches!(result,Err(stage) if stage==expected));
        assert!(revoked.load(Ordering::SeqCst));
        assert!(!audit.load(Ordering::SeqCst));
        assert!(
            dropped.load(Ordering::SeqCst),
            "constructor veto precedes original proof destruction"
        );
    }
}

#[test]
fn original_fault_io_guard_fixture_rechecks_same_cap_and_normal_borrow_drop_does_not_replace_or_veto_proof(
) {
    let valid = AtomicBool::new(true);
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let end = Instant::now() + Duration::from_secs(2);
    let mut guard = SelectedFaultIoGuard::fixture(end, &valid, &calls);
    guard.current(end).unwrap();
    guard.current(end).unwrap();
    assert_eq!(guard.end, end);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(!guard.retired.load(Ordering::SeqCst));
    assert!(valid.load(Ordering::SeqCst));
    drop(guard);
    assert!(
        valid.load(Ordering::SeqCst),
        "normal borrowed observation does not retire original owner"
    );
}

#[test]
fn original_fault_io_guard_rejects_replaced_or_exactly_expired_endpoint_and_stays_retired_after_fixture_reset(
) {
    for condition in ["earlier", "later", "expired"] {
        let valid = AtomicBool::new(true);
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let end = if condition == "expired" {
            Instant::now()
        } else {
            Instant::now() + Duration::from_secs(2)
        };
        let requested = match condition {
            "earlier" => end - Duration::from_secs(1),
            "later" => end + Duration::from_secs(1),
            _ => end,
        };
        let mut guard = SelectedFaultIoGuard::fixture(end, &valid, &calls);
        assert_eq!(
            guard.require_current(requested),
            Err(Refusal::FaultPreparationEndpoint)
        );
        assert_eq!(guard.end, end);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(guard.retired.load(Ordering::SeqCst));
        assert!(!valid.load(Ordering::SeqCst));
        valid.store(true, Ordering::SeqCst);
        assert_eq!(
            guard.require_current(end),
            Err(Refusal::FaultPreparationOriginal)
        );
        assert!(!valid.load(Ordering::SeqCst));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn original_fault_io_guard_proof_loss_or_explicit_veto_is_sticky_and_cannot_admit_another_progress_step(
) {
    for explicit in [false, true] {
        let valid = AtomicBool::new(true);
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let end = Instant::now() + Duration::from_secs(2);
        let mut guard = SelectedFaultIoGuard::fixture(end, &valid, &calls);
        guard.current(end).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        if explicit {
            guard.veto();
            guard.veto();
        } else {
            valid.store(false, Ordering::SeqCst);
        }
        assert!(guard
            .current(end)
            .unwrap_err()
            .is("SUPERVISOR_SELECTED_FAULT_IO_CONTEXT"));
        let checked = calls.load(Ordering::SeqCst);
        assert_eq!(checked, if explicit { 1 } else { 2 });
        assert!(guard.retired.load(Ordering::SeqCst));
        assert!(!valid.load(Ordering::SeqCst));
        valid.store(true, Ordering::SeqCst);
        assert!(guard.current(end).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), checked);
        assert!(!valid.load(Ordering::SeqCst));
        assert_eq!(guard.end, end);
    }
}

#[test]
fn original_fault_io_guard_blocking_validation_cannot_return_success_after_original_cap_or_renew_later_io(
) {
    let valid = AtomicBool::new(true);
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let end = Instant::now() + Duration::from_millis(250);
    let mut guard = SelectedFaultIoGuard::fixture(end, &valid, &calls);
    if let FaultIoOriginal::Fixture { delay, .. } = &mut guard.original {
        *delay = Duration::from_millis(300);
    }
    assert_eq!(
        guard.require_current(end),
        Err(Refusal::FaultPreparationEndpoint)
    );
    assert_eq!(guard.end, end);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(guard.retired.load(Ordering::SeqCst));
    assert!(!valid.load(Ordering::SeqCst));
    assert_eq!(
        guard.require_current(Instant::now() + Duration::from_secs(2)),
        Err(Refusal::FaultPreparationOriginal)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn original_fault_io_guard_current_unwind_vetoes_before_return_to_caller_and_cannot_be_reset() {
    let valid = AtomicBool::new(true);
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let end = Instant::now() + Duration::from_secs(2);
    let mut guard = SelectedFaultIoGuard::fixture(end, &valid, &calls);
    if let FaultIoOriginal::Fixture { panic, .. } = &mut guard.original {
        *panic = true;
    }
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| guard.current(end))).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(!valid.load(Ordering::SeqCst));
    assert!(guard.retired.load(Ordering::SeqCst));
    valid.store(true, Ordering::SeqCst);
    assert!(guard.current(end).is_err());
    assert!(!valid.load(Ordering::SeqCst));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn original_fault_io_guard_external_unwind_drop_vetoes_same_borrowed_fixture_without_any_replacement_check(
) {
    let valid = AtomicBool::new(true);
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let end = Instant::now() + Duration::from_secs(2);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = SelectedFaultIoGuard::fixture(end, &valid, &calls);
        panic!("SYNTHETIC_SELECTED_FAULT_IO_OWNER_UNWIND");
    }))
    .is_err());
    assert!(!valid.load(Ordering::SeqCst));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

// Closed cfg(test) script for the SAME dispatch algorithm, distinct from the
// real socket/codec/guard fixtures in ipc.rs. It never becomes a production
// transport/identity provider and makes no installed-auditor claim.
#[derive(Default)]
struct DispatchLog {
    clock_calls: usize,
    exchanges: usize,
    endpoints: Vec<Instant>,
    paths: Vec<std::path::PathBuf>,
    requests: Vec<crate::quarantine_types::FaultReport>,
    fence_before_clock: bool,
    fence_before_request: bool,
    authority_labels: Vec<String>,
}
pub(super) struct DispatchScript {
    tracker: Arc<super::super::RespawnTracker>,
    socket_root: std::path::PathBuf,
    log: Arc<Mutex<DispatchLog>>,
    now: std::time::SystemTime,
    native_authority: bool,
    peer: crate::ipc::PeerCredentials,
    reply: Vec<u8>,
    valid: Option<Arc<AtomicBool>>,
    clock_veto: bool,
    receipt_veto: bool,
    post_completion_veto: bool,
    exchange_delay: Option<Duration>,
    panic_at: Option<&'static str>,
    lost_receipt: bool,
}
impl DispatchScript {
    fn new(response: crate::quarantine_types::Response) -> Self {
        let requirement =
            crate::codesign::CodeRequirement::daemon(crate::daemon::DaemonId::ZkAuditor);
        let cdhash = requirement
            .cdhash_allowlist
            .first()
            .cloned()
            .unwrap_or_else(|| "a".repeat(40));
        Self {
            tracker: Arc::new(super::super::RespawnTracker::new()),
            socket_root: std::path::PathBuf::from("/synthetic-selected-root"),
            log: Arc::new(Mutex::new(DispatchLog::default())),
            now: std::time::UNIX_EPOCH + Duration::from_millis(456_789),
            native_authority: true,
            peer: crate::ipc::PeerCredentials {
                uid: 705,
                gid: 705,
                pid: Some(1234),
                audit_token: Some([0x87654321; 8]),
                tls_channel_binding: None,
                code_identity: Some(crate::codesign::CodeIdentity {
                    identifier: requirement.identifier,
                    team_id: requirement.team_id,
                    cdhash,
                }),
            },
            reply: crate::ipc::to_cbor(&crate::ipc::Reply::Ok(SelectedZkFaultResponse::Fault(
                response,
            )))
            .unwrap(),
            valid: None,
            clock_veto: false,
            receipt_veto: false,
            post_completion_veto: false,
            exchange_delay: None,
            panic_at: None,
            lost_receipt: false,
        }
    }
    pub(super) fn require_native_authority(&self) -> EnclaveResult<()> {
        if !self.native_authority {
            return Err(err!(EPERM, "SUPERVISOR_SELECTED_FAULT_NATIVE_ROOT"));
        }
        Ok(())
    }
    pub(super) fn wall_time(&mut self) -> std::time::SystemTime {
        let mut log = self.log.lock().unwrap();
        log.clock_calls += 1;
        log.fence_before_clock = [701, 703, 704, 705]
            .into_iter()
            .all(|uid| self.tracker.is_throttled(uid).is_some());
        drop(log);
        if self.clock_veto {
            self.valid.as_ref().unwrap().store(false, Ordering::SeqCst);
        }
        if self.panic_at == Some("clock") {
            panic!("SYNTHETIC_SELECTED_WALL_CLOCK_UNWIND");
        }
        self.now
    }
    pub(super) fn exchange(
        &mut self,
        socket_root: &std::path::Path,
        end: Instant,
        guard: &mut SelectedFaultIoGuard<'_>,
        requirement: &crate::codesign::CodeRequirement,
        request: &SelectedZkFaultRequest,
    ) -> EnclaveResult<SelectedZkFaultResponse> {
        guard.current(end)?;
        {
            let mut log = self.log.lock().unwrap();
            log.exchanges += 1;
            log.endpoints.push(end);
            log.paths.push(selected_zk_socket(socket_root));
            log.authority_labels.push(requirement.identifier.clone());
        }
        assert_eq!(socket_root, self.socket_root.as_path());
        require_selected_zk_peer(&self.peer, requirement)?;
        guard.current(end)?;
        let encoded = crate::ipc::to_cbor(request)?;
        guard.current(end)?;
        let SelectedZkFaultRequest::ReportFault(report) = crate::ipc::from_cbor(&encoded)?;
        {
            let mut log = self.log.lock().unwrap();
            log.fence_before_request = [701, 703, 704, 705]
                .into_iter()
                .all(|uid| self.tracker.is_throttled(uid).is_some());
            log.requests.push(report);
        }
        if self.panic_at == Some("receipt") {
            panic!("SYNTHETIC_SELECTED_FAULT_UNCERTAIN_RECEIPT_UNWIND");
        }
        if let Some(delay) = self.exchange_delay {
            std::thread::sleep(delay);
        }
        if self.lost_receipt {
            return Err(err!(EIO, "SYNTHETIC_SELECTED_FAULT_LOST_RECEIPT"));
        }
        let decoded: crate::ipc::Reply<SelectedZkFaultResponse> =
            crate::ipc::from_cbor(&self.reply)?;
        if self.receipt_veto {
            self.valid.as_ref().unwrap().store(false, Ordering::SeqCst);
        }
        if self.post_completion_veto {
            if let FaultIoOriginal::Fixture { calls, veto_at, .. } = &mut guard.original {
                // Shared engine next validates after exchange and before the
                // callback return, then once AFTER actual tracker completion.
                *veto_at = Some(calls.load(Ordering::SeqCst) + 3);
            }
        }
        match decoded {
            crate::ipc::Reply::Ok(response) => Ok(response),
            crate::ipc::Reply::Err(error) => Err(error),
        }
    }
}

fn dispatch_setup(
    script: DispatchScript,
) -> (
    SessionLifetime<Session>,
    Scripted,
    Arc<Mutex<Events>>,
    Arc<super::super::RespawnTracker>,
    Arc<Mutex<DispatchLog>>,
) {
    let (lifetime, kernel, events) = setup(0, &kernel_frame());
    let tracker = script.tracker.clone();
    let log = script.log.clone();
    events.lock().unwrap().dispatch = Some(script);
    (lifetime, kernel, events, tracker, log)
}

#[test]
fn original_selected_dispatch_uses_same_tracker_fixed_custody_target_auditor_and_original_data_once_then_refuses_reply(
) {
    use crate::quarantine_types::Response;
    for response in [
        Response::RestartThrottled,
        Response::StrikeDelayRespawn,
        Response::Latched,
    ] {
        let script = DispatchScript::new(response);
        let (lifetime, kernel, events, tracker, log) = dispatch_setup(script);
        let session_end = lifetime.end;
        let cap = Instant::now() + Duration::from_secs(2);
        events.lock().unwrap().preparation_actor_end = Some(cap);
        tracker.record_delay(702, Duration::from_secs(60));
        refused(
            Attempt::new(kernel, &lifetime, 0x22334455).run(),
            Refusal::NativeReplyAndStartupCompositionUnavailable,
            0,
            Cleanup::NativeDestroyInvokedCompletionUnqualified,
        );
        let log = log.lock().unwrap();
        assert_eq!(
            (log.clock_calls, log.exchanges, log.requests.len()),
            (1, 1, 1)
        );
        assert_eq!(log.endpoints, [cap]);
        assert_eq!(
            log.paths,
            [std::path::PathBuf::from(
                "/synthetic-selected-root/zk/zk.sock"
            )]
        );
        assert_eq!(
            log.authority_labels,
            [crate::daemon::DaemonId::ZkAuditor.launchd_label()]
        );
        assert!(log.fence_before_clock && log.fence_before_request);
        let events = events.lock().unwrap();
        let (_, _, kind, address) = events.prepared_data[0];
        assert_eq!(
            log.requests[0],
            crate::quarantine_types::FaultReport {
                kind,
                fault_addr: address,
                at_ms: 456_789
            }
        );
        assert_eq!(lifetime.end, session_end);
        assert_eq!(events.binding_calls.len(), 1);
        assert!(events.dispatch_guard_calls.load(Ordering::SeqCst) > 8);
        assert!(events.revoked_shared.load(Ordering::SeqCst));
        revoke_before_destroy(&events);
        assert_eq!((events.receives, events.destroys), (1, 1));
        assert!(events
            .audit_active
            .iter()
            .all(|active| !active.load(Ordering::SeqCst)));
        assert!(
            tracker.is_throttled(702).is_some(),
            "preserve existing patch-service delay"
        );
        assert_eq!(
            tracker.is_throttled(703).is_some(),
            response != Response::RestartThrottled
        );
        assert_eq!(
            tracker.is_throttled(701).is_some(),
            response == Response::Latched
        );
    }
}

#[test]
fn original_selected_dispatch_requires_native_root_full_auditor_identity_before_any_request() {
    use crate::quarantine_types::Response;
    for bad in [
        "platform",
        "uid",
        "audit",
        "code",
        "identifier",
        "team",
        "hash",
        "tls",
    ] {
        let mut script = DispatchScript::new(Response::RestartThrottled);
        match bad {
            "platform" => script.native_authority = false,
            "uid" => script.peer.uid = 703,
            "audit" => script.peer.audit_token = None,
            "code" => script.peer.code_identity = None,
            "identifier" => script
                .peer
                .code_identity
                .as_mut()
                .unwrap()
                .identifier
                .push_str(".wrong"),
            "team" => {
                let identity = script.peer.code_identity.as_mut().unwrap();
                identity.team_id.push_str(".wrong");
                if crate::codesign::TEAM_ID.is_empty() {
                    identity.cdhash.clear();
                }
            }
            "hash" => script.peer.code_identity.as_mut().unwrap().cdhash.clear(),
            _ => script.peer.tls_channel_binding = Some([1; 32]),
        }
        let (lifetime, kernel, events, tracker, log) = dispatch_setup(script);
        refused(
            Attempt::new(kernel, &lifetime, 0x22334455).run(),
            Refusal::FaultDispatchUnavailable,
            0,
            Cleanup::NativeDestroyInvokedCompletionUnqualified,
        );
        assert!(log.lock().unwrap().requests.is_empty());
        assert_eq!(
            log.lock().unwrap().exchanges,
            usize::from(bad != "platform")
        );
        assert!(tracker.is_throttled(703).is_some());
        assert!(tracker.is_throttled(702).is_none());
        revoke_before_destroy(&events.lock().unwrap());
    }
}

#[test]
fn original_selected_dispatch_checked_wall_conversion_rejects_before_epoch_and_overflow_without_default_timestamp(
) {
    use crate::quarantine_types::Response;
    assert_eq!(checked_fault_wall_millis(std::time::UNIX_EPOCH).unwrap(), 0);
    assert_eq!(
        checked_fault_wall_millis(std::time::UNIX_EPOCH + Duration::from_millis(1_234)).unwrap(),
        1_234
    );
    for now in [
        std::time::UNIX_EPOCH
            .checked_sub(Duration::from_nanos(1))
            .unwrap(),
        std::time::UNIX_EPOCH
            .checked_add(Duration::from_secs(u64::MAX / 1000 + 1))
            .unwrap(),
    ] {
        let mut script = DispatchScript::new(Response::RestartThrottled);
        script.now = now;
        let (lifetime, kernel, events, tracker, log) = dispatch_setup(script);
        refused(
            Attempt::new(kernel, &lifetime, 0x22334455).run(),
            Refusal::FaultDispatchUnavailable,
            0,
            Cleanup::NativeDestroyInvokedCompletionUnqualified,
        );
        let log = log.lock().unwrap();
        assert_eq!((log.clock_calls, log.exchanges), (1, 0));
        assert!(log.requests.is_empty());
        assert!(tracker.is_throttled(703).is_some());
        revoke_before_destroy(&events.lock().unwrap());
    }
}

#[test]
fn original_selected_dispatch_context_loss_during_timestamp_or_after_typed_receipt_cannot_publish_positive_result(
) {
    use crate::quarantine_types::Response;
    for at_clock in [true, false] {
        let mut script = DispatchScript::new(Response::StrikeDelayRespawn);
        script.clock_veto = at_clock;
        script.receipt_veto = !at_clock;
        let (lifetime, kernel, events, tracker, log) = dispatch_setup(script);
        refused(
            Attempt::new(kernel, &lifetime, 0x22334455).run(),
            Refusal::FaultDispatchUnavailable,
            0,
            Cleanup::NativeDestroyInvokedCompletionUnqualified,
        );
        assert_eq!(log.lock().unwrap().requests.len(), usize::from(!at_clock));
        assert!(
            tracker.is_throttled(701).is_some(),
            "uncertain completion keeps same tracker globally PII-fenced"
        );
        assert!(tracker.is_throttled(702).is_none());
        revoke_before_destroy(&events.lock().unwrap());
    }
}

#[test]
fn original_selected_dispatch_lost_malformed_wrong_variant_and_peer_error_receipts_never_retry() {
    use crate::quarantine_types::Response;
    #[derive(serde::Serialize)]
    enum WrongResponse {
        Status(u64),
    }
    for bad in ["lost", "malformed", "wrong_variant", "peer_error"] {
        let mut script = DispatchScript::new(Response::RestartThrottled);
        match bad {
            "lost" => script.lost_receipt = true,
            "malformed" => script.reply = vec![0xff],
            "wrong_variant" => {
                script.reply =
                    crate::ipc::to_cbor(&crate::ipc::Reply::Ok(WrongResponse::Status(1))).unwrap()
            }
            _ => {
                script.reply =
                    crate::ipc::to_cbor(&crate::ipc::Reply::<SelectedZkFaultResponse>::Err(err!(
                        EPERM,
                        "SCRIPTED_AUDITOR_ERROR"
                    )))
                    .unwrap()
            }
        }
        let (lifetime, kernel, events, tracker, log) = dispatch_setup(script);
        refused(
            Attempt::new(kernel, &lifetime, 0x22334455).run(),
            Refusal::FaultDispatchUnavailable,
            0,
            Cleanup::NativeDestroyInvokedCompletionUnqualified,
        );
        {
            let log = log.lock().unwrap();
            assert_eq!((log.exchanges, log.requests.len()), (1, 1));
        }
        {
            let mut events = events.lock().unwrap();
            assert!(events.revoked_shared.load(Ordering::SeqCst));
            revoke_before_destroy(&events);
            events.refuse = false;
        }
        lifetime.stop.store(false, Ordering::SeqCst);
        let next = Scripted {
            events: events.clone(),
            result: 0,
            frame: kernel_frame().to_vec(),
        };
        assert!(matches!(
            Attempt::new(next, &lifetime, 0x22334455).run(),
            Outcome::Refused {
                stage: Refusal::BeforeReceive,
                ..
            }
        ));
        assert_eq!(log.lock().unwrap().exchanges, 1);
        assert!(tracker.is_throttled(701).is_some());
    }
}

#[test]
fn original_selected_dispatch_post_tracker_original_loss_remains_terminal_despite_valid_typed_transport_receipt(
) {
    let mut script = DispatchScript::new(crate::quarantine_types::Response::RestartThrottled);
    script.post_completion_veto = true;
    let (lifetime, kernel, events, tracker, log) = dispatch_setup(script);
    refused(
        Attempt::new(kernel, &lifetime, 0x22334455).run(),
        Refusal::FaultDispatchUnavailable,
        0,
        Cleanup::NativeDestroyInvokedCompletionUnqualified,
    );
    assert_eq!(log.lock().unwrap().requests.len(), 1);
    assert!(
        tracker.is_throttled(703).is_none(),
        "valid tracker receipt may stand; it is never a restart/session permit"
    );
    let events = events.lock().unwrap();
    assert!(events.revoked_shared.load(Ordering::SeqCst));
    assert!(events
        .preparation_actors
        .iter()
        .all(|actor| !actor.load(Ordering::SeqCst)));
    revoke_before_destroy(&events);
}

#[test]
fn original_selected_dispatch_original_actor_expiry_after_possible_delivery_rejects_without_new_budget_or_replay(
) {
    let mut script = DispatchScript::new(crate::quarantine_types::Response::RestartThrottled);
    script.exchange_delay = Some(Duration::from_millis(160));
    let (lifetime, kernel, events, tracker, log) = dispatch_setup(script);
    let cap = Instant::now() + Duration::from_millis(120);
    events.lock().unwrap().preparation_actor_end = Some(cap);
    refused(
        Attempt::new(kernel, &lifetime, 0x22334455).run(),
        Refusal::FaultDispatchUnavailable,
        0,
        Cleanup::NativeDestroyInvokedCompletionUnqualified,
    );
    let log = log.lock().unwrap();
    assert_eq!(log.endpoints, [cap]);
    assert_eq!(log.requests.len(), 1);
    assert!(tracker.is_throttled(701).is_some());
    revoke_before_destroy(&events.lock().unwrap());
}

#[test]
fn original_selected_dispatch_clock_and_uncertain_receipt_unwind_retire_same_owners_before_whole_message_cleanup(
) {
    for at in ["clock", "receipt"] {
        let mut script = DispatchScript::new(crate::quarantine_types::Response::RestartThrottled);
        script.panic_at = Some(at);
        let (lifetime, kernel, events, tracker, log) = dispatch_setup(script);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| Attempt::new(
                kernel, &lifetime, 0x22334455
            )
            .run()))
            .is_err()
        );
        assert_eq!(
            log.lock().unwrap().requests.len(),
            usize::from(at == "receipt")
        );
        let events = events.lock().unwrap();
        assert_eq!((events.receives, events.destroys), (1, 1));
        assert!(events
            .preparation_drops
            .iter()
            .all(|dropped| dropped.load(Ordering::SeqCst)));
        assert!(events
            .audit_active
            .iter()
            .all(|active| !active.load(Ordering::SeqCst)));
        revoke_before_destroy(&events);
        assert!(tracker.is_throttled(701).is_some());
    }
}

#[test]
fn original_selected_dispatch_consumption_is_irreversible_even_with_new_fixture_guard_and_reset_flags(
) {
    for lost_receipt in [false, true] {
        let end = Instant::now() + Duration::from_secs(2);
        let audit = Arc::new(AtomicBool::new(true));
        let actor = Arc::new(AtomicBool::new(true));
        let revoked = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let preparation = OriginalFaultPreparation::from_original(
            &Storage(kernel_frame(), MessagePhase::Original),
            0x44556677,
            IPC_OTYPE_TASK_CONTROL,
            0x22334455,
            end,
            FaultEvidence::Fixture(FixtureFaultEvidence {
                end,
                audit: audit.clone(),
                actor: actor.clone(),
                revoked: revoked.clone(),
                dropped,
                armed: true,
            }),
        )
        .unwrap();
        let mut script = DispatchScript::new(crate::quarantine_types::Response::RestartThrottled);
        script.lost_receipt = lost_receipt;
        script.valid = Some(actor.clone());
        let tracker = script.tracker.clone();
        let socket_root = script.socket_root.clone();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let mut guard = SelectedFaultIoGuard::fixture_bound(end, &actor, &calls, &preparation);
        let first = dispatch_original_fault(
            &tracker,
            &socket_root,
            &preparation,
            &mut guard,
            &mut FaultDispatchBackend::Scripted(&mut script),
        );
        assert_eq!(first.is_err(), lost_receipt);
        assert!(preparation.dispatch_consumed.load(Ordering::SeqCst));
        actor.store(true, Ordering::SeqCst);
        audit.store(true, Ordering::SeqCst);
        revoked.store(false, Ordering::SeqCst);
        let mut replacement =
            SelectedFaultIoGuard::fixture_bound(end, &actor, &calls, &preparation);
        assert!(dispatch_original_fault(
            &tracker,
            &socket_root,
            &preparation,
            &mut replacement,
            &mut FaultDispatchBackend::Scripted(&mut script)
        )
        .err()
        .unwrap()
        .is("SUPERVISOR_SELECTED_FAULT_ALREADY_CONSUMED"));
        assert_eq!(script.log.lock().unwrap().exchanges, 1);
        assert!(!actor.load(Ordering::SeqCst));
        assert!(!audit.load(Ordering::SeqCst));
        assert!(revoked.load(Ordering::SeqCst));
    }
}

#[test]
fn original_selected_dispatch_existing_tracker_veto_refuses_before_clock_or_transport_and_retires_same_preparation(
) {
    let script = DispatchScript::new(crate::quarantine_types::Response::RestartThrottled);
    let (lifetime, kernel, events, tracker, log) = dispatch_setup(script);
    assert!(tracker
        .report_fault_before(701, Instant::now(), |_| panic!("expired setup authority"))
        .is_err());
    refused(
        Attempt::new(kernel, &lifetime, 0x22334455).run(),
        Refusal::FaultDispatchUnavailable,
        0,
        Cleanup::NativeDestroyInvokedCompletionUnqualified,
    );
    let log = log.lock().unwrap();
    assert_eq!((log.clock_calls, log.exchanges), (0, 0));
    assert!(log.requests.is_empty());
    let events = events.lock().unwrap();
    assert!(events.revoked_shared.load(Ordering::SeqCst));
    assert!(events
        .preparation_drops
        .iter()
        .all(|dropped| dropped.load(Ordering::SeqCst)));
    revoke_before_destroy(&events);
    assert!(tracker.is_throttled(701).is_some());
    assert!(tracker.is_throttled(702).is_none());
}

// Shared report engine for the reply composition tests. It mints the same
// private receipt as Native, with explicitly synthetic identity/transport.
pub(super) fn dispatch_fixture_receipt(
    preparation: &OriginalFaultPreparation,
) -> EnclaveResult<ValidReportReceipt<'_>> {
    let actor = match &preparation.evidence {
        FaultEvidence::Fixture(proof) => proof.actor.clone(),
        _ => return Err(err!(EACCES, "SCRIPTED_REPORT_PREPARATION")),
    };
    let mut script = DispatchScript::new(crate::quarantine_types::Response::RestartThrottled);
    script.valid = Some(actor.clone());
    let tracker = script.tracker.clone();
    let socket_root = script.socket_root.clone();
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let mut guard =
        SelectedFaultIoGuard::fixture_bound(preparation.end, &actor, &calls, preparation);
    dispatch_original_fault(
        &tracker,
        &socket_root,
        preparation,
        &mut guard,
        &mut FaultDispatchBackend::Scripted(&mut script),
    )
}

#[test]
fn original_selected_dispatch_rejects_unbound_or_different_preparation_guard_before_consumption_or_request(
) {
    for unbound in [false, true] {
        let end = Instant::now() + Duration::from_secs(2);
        let audit = Arc::new(AtomicBool::new(true));
        let actor = Arc::new(AtomicBool::new(true));
        let revoked = Arc::new(AtomicBool::new(false));
        let make = || {
            OriginalFaultPreparation::from_original(
                &Storage(kernel_frame(), MessagePhase::Original),
                0x44556677,
                IPC_OTYPE_TASK_CONTROL,
                0x22334455,
                end,
                FaultEvidence::Fixture(FixtureFaultEvidence {
                    end,
                    audit: audit.clone(),
                    actor: actor.clone(),
                    revoked: revoked.clone(),
                    dropped: Arc::new(AtomicBool::new(false)),
                    armed: false,
                }),
            )
            .unwrap()
        };
        let first = make();
        let offered = make();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let mut guard = if unbound {
            SelectedFaultIoGuard::fixture(end, &actor, &calls)
        } else {
            SelectedFaultIoGuard::fixture_bound(end, &actor, &calls, &first)
        };
        let mut script = DispatchScript::new(crate::quarantine_types::Response::RestartThrottled);
        script.valid = Some(actor.clone());
        let tracker = script.tracker.clone();
        let socket_root = script.socket_root.clone();
        let error = dispatch_original_fault(
            &tracker,
            &socket_root,
            &offered,
            &mut guard,
            &mut FaultDispatchBackend::Scripted(&mut script),
        )
        .err()
        .unwrap();
        assert!(error.is("SUPERVISOR_SELECTED_FAULT_GUARD_PREPARATION"));
        assert!(!offered.dispatch_consumed.load(Ordering::SeqCst));
        assert!(!first.dispatch_consumed.load(Ordering::SeqCst));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let log = script.log.lock().unwrap();
        assert_eq!((log.clock_calls, log.exchanges), (0, 0));
        assert!(log.requests.is_empty());
        assert!(!actor.load(Ordering::SeqCst));
        assert!(!audit.load(Ordering::SeqCst));
        assert!(revoked.load(Ordering::SeqCst));
    }
}
