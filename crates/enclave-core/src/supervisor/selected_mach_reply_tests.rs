//! Scripted actual ownership engine only; no native Mach operation.
use super::super::{
    Attempt, AuditLease, AuditReadFailure, Cleanup, FaultEvidence, FixtureFaultEvidence, Kernel,
    OriginalFaultPreparation, Refusal, SessionLifetime, Storage,
};
use super::*;
use crate::{err, error::EnclaveResult, quarantine_types::Response};
use std::sync::{atomic::AtomicBool, Arc, Barrier, Mutex};

const REMOTE: u32 = 0x1122_3344;
const RECEIVE: u32 = 0x2233_4455;
const THREAD: u32 = 0x3344_5566;
const TASK: u32 = 0x4455_6677;

struct Events {
    trace: Vec<&'static str>,
    sends: Vec<([u8; 36], i32, u32, usize)>,
    reply_destroys: Vec<[u8; 36]>,
    body_destroys: usize,
    result: i32,
    returned_name: u32,
    corrupt: Option<&'static str>,
    action: Option<&'static str>,
    destroy_panic: bool,
    refuse: bool,
    panic_current: bool,
    audit: Arc<AtomicBool>,
    actor: Arc<AtomicBool>,
    revoked: Arc<AtomicBool>,
    preparation_dropped: Arc<AtomicBool>,
    barriers: Option<(Arc<Barrier>, Arc<Barrier>)>,
    consumed: Arc<FixtureConsumedChecks>,
}
impl Events {
    fn new() -> Self {
        Self {
            trace: Vec::new(),
            sends: Vec::new(),
            reply_destroys: Vec::new(),
            body_destroys: 0,
            result: 0,
            returned_name: REMOTE,
            corrupt: None,
            action: None,
            destroy_panic: false,
            refuse: false,
            panic_current: false,
            audit: Arc::new(AtomicBool::new(true)),
            actor: Arc::new(AtomicBool::new(true)),
            revoked: Arc::new(AtomicBool::new(false)),
            preparation_dropped: Arc::new(AtomicBool::new(false)),
            barriers: None,
            consumed: Arc::new(FixtureConsumedChecks::new()),
        }
    }
}
struct Session {
    events: Arc<Mutex<Events>>,
    end: Instant,
}
impl SessionDependency for Session {
    fn current(&self) -> EnclaveResult<()> {
        let events = self.events.lock().unwrap();
        let panic = events.panic_current;
        let refuse = events.refuse || events.revoked.load(Ordering::SeqCst);
        drop(events);
        if panic {
            panic!("SCRIPTED_REPLY_POSTCHECK_UNWIND");
        }
        if refuse {
            return Err(err!(EACCES, "SCRIPTED_REPLY_CONTEXT"));
        }
        Ok(())
    }
    fn revoke(&self) {
        let mut events = self.events.lock().unwrap();
        events.revoked.store(true, Ordering::SeqCst);
        events.trace.push("veto");
    }
    fn original_end(&self) -> Instant {
        self.end
    }
}
struct MessageKernel {
    events: Arc<Mutex<Events>>,
}
impl Kernel for MessageKernel {
    fn retained_startup_current(&mut self, _: Instant) -> EnclaveResult<()> {
        panic!("unused")
    }
    fn receive(&mut self, _: &mut Storage, _: i32, _: u32) -> i32 {
        panic!("unused")
    }
    fn object_type_in_self(&mut self, _: u32) -> Result<u32, i32> {
        panic!("unused")
    }
    fn task_audit_of_classified_original(
        &mut self,
        _: u32,
        _: Instant,
    ) -> Result<AuditLease, AuditReadFailure> {
        panic!("unused")
    }
    fn actor_and_assignment_of_original(
        &mut self,
        _: &Storage,
        _: u32,
        _: u32,
        _: Instant,
        _: &AuditLease,
    ) -> Result<OriginalFaultPreparation, Refusal> {
        panic!("unused")
    }
    fn validate_fault_preparation_of_original(
        &mut self,
        _: &Storage,
        _: u32,
        _: u32,
        _: Instant,
        _: &AuditLease,
        _: &OriginalFaultPreparation,
    ) -> Result<(), Refusal> {
        panic!("unused")
    }
    fn dispatch_fault_of_original(
        &mut self,
        _: &mut Storage,
        _: &mut Resources,
        _: u32,
        _: u32,
        _: Instant,
        _: &AuditLease,
        _: &OriginalFaultPreparation,
    ) -> Result<Response, Refusal> {
        panic!("unused")
    }
    fn destroy_received(&mut self, storage: &mut Storage) {
        let mut events = self.events.lock().unwrap();
        assert!(events.revoked.load(Ordering::SeqCst));
        assert!(!events.audit.load(Ordering::SeqCst));
        assert!(events.preparation_dropped.load(Ordering::SeqCst));
        if storage.1 == MessagePhase::ReplyDetached {
            assert_eq!(u32::from_le_bytes(storage.0[8..12].try_into().unwrap()), 0);
            assert_eq!(
                u32::from_le_bytes(storage.0[0..4].try_into().unwrap()) & REMOTE_MASK,
                0
            );
        }
        assert_eq!(
            u32::from_le_bytes(storage.0[28..32].try_into().unwrap()),
            THREAD
        );
        assert_eq!(
            u32::from_le_bytes(storage.0[40..44].try_into().unwrap()),
            TASK
        );
        events.body_destroys += 1;
        events.trace.push("body-destroy");
    }
}
struct ScriptedReply {
    events: Arc<Mutex<Events>>,
}
impl ReplyKernel for ScriptedReply {
    fn send(&mut self, reply: &mut ReplyStorage, options: i32, timeout: u32) -> i32 {
        let mut events = self.events.lock().unwrap();
        events
            .sends
            .push((reply.0, options, timeout, reply.0.as_ptr() as usize));
        events.trace.push("send");
        let (result, name, corrupt, action, barriers) = (
            events.result,
            events.returned_name,
            events.corrupt,
            events.action,
            events.barriers.clone(),
        );
        if action == Some("refuse") {
            events.refuse = true;
        }
        if action == Some("post-panic") {
            events.panic_current = true;
        }
        if action == Some("class") {
            events.consumed.class.store(false, Ordering::SeqCst);
        }
        if action == Some("audit") {
            events.consumed.audit.store(false, Ordering::SeqCst);
        }
        if action == Some("actor") {
            events.actor.store(false, Ordering::SeqCst);
        }
        if action == Some("assignment") {
            events.consumed.assignment.store(false, Ordering::SeqCst);
        }
        if action == Some("consumed-panic") {
            events.consumed.panic.store(true, Ordering::SeqCst);
        }
        drop(events);
        if let Some((entered, resume)) = barriers {
            entered.wait();
            resume.wait();
        }
        if action == Some("during-panic") {
            panic!("SCRIPTED_REPLY_INFLIGHT_UNWIND");
        }
        if action == Some("late") {
            std::thread::sleep(Duration::from_millis(100));
        }
        reply.0[8..12].copy_from_slice(&name.to_le_bytes());
        match corrupt {
            Some("bits") => {
                reply.0[0..4].copy_from_slice(&(0x8000_0000 | MOVE_SEND_ONCE).to_le_bytes())
            }
            Some("type") => reply.0[0..4].copy_from_slice(&17u32.to_le_bytes()),
            Some("size") => reply.0[4..8].copy_from_slice(&40u32.to_le_bytes()),
            Some("local") => reply.0[12..16].copy_from_slice(&1u32.to_le_bytes()),
            Some("voucher") => reply.0[16..20].copy_from_slice(&1u32.to_le_bytes()),
            Some("id") => reply.0[20..24].copy_from_slice(&2506i32.to_le_bytes()),
            Some("ndr") => reply.0[24] ^= 1,
            Some("positive") => reply.0[32..36].fill(0),
            Some(_) => panic!("unknown corruption"),
            None => (),
        }
        result
    }
    fn destroy_unsent(&mut self, reply: &mut ReplyStorage) {
        let mut events = self.events.lock().unwrap();
        assert!(
            events.revoked.load(Ordering::SeqCst),
            "same session veto precedes reply cleanup"
        );
        assert!(
            !events.audit.load(Ordering::SeqCst),
            "passive original audit cannot remain active"
        );
        assert!(
            !events.preparation_dropped.load(Ordering::SeqCst),
            "retain proof/body until reply ownership settled"
        );
        events.reply_destroys.push(reply.0);
        events.trace.push("reply-destroy");
        let panic = events.destroy_panic;
        drop(events);
        if panic {
            panic!("SCRIPTED_REPLY_CLEANUP_UNWIND");
        }
    }
}

fn frame() -> [u8; mach_wire::FRAME_BYTES] {
    let mut raw = [0; mach_wire::FRAME_BYTES];
    for (offset, value) in [
        (0, 0x8000_1112u32),
        (4, 84),
        (8, REMOTE),
        (12, RECEIVE),
        (20, 2405),
        (24, 2),
        (28, THREAD),
        (40, TASK),
        (60, 1),
        (64, 2),
        (88, 52),
    ] {
        raw[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    raw[38] = 17;
    raw[50] = 17;
    raw[52..60].copy_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0]);
    raw[68..76].copy_from_slice(&0x105i64.to_le_bytes());
    raw[76..84].copy_from_slice(&0x1234_5678i64.to_le_bytes());
    raw[96..104].copy_from_slice(&super::super::KERNEL_SECURITY_TOKEN);
    raw
}
fn setup(cap: Duration) -> (SessionLifetime<Session>, Arc<Mutex<Events>>, Instant) {
    let events = Arc::new(Mutex::new(Events::new()));
    let end = Instant::now() + Duration::from_secs(60);
    let lifetime = SessionLifetime::new(
        Session {
            events: events.clone(),
            end,
        },
        Arc::new(AtomicBool::new(false)),
    );
    (lifetime, events, Instant::now() + cap)
}
fn original<'s>(
    lifetime: &'s SessionLifetime<Session>,
    events: &Arc<Mutex<Events>>,
    cap: Instant,
) -> Attempt<'s, MessageKernel, Session> {
    let mut value = Attempt::new(
        MessageKernel {
            events: events.clone(),
        },
        lifetime,
        RECEIVE,
    );
    value.storage.0 = frame();
    value.resources = Resources::Received;
    let events = events.lock().unwrap();
    value.audit = Some(AuditLease {
        active: events.audit.clone(),
        evidence: AuditEvidence::Fixture,
    });
    let mut preparation = OriginalFaultPreparation::from_original(
        &value.storage,
        TASK,
        super::super::IPC_OTYPE_TASK_CONTROL,
        RECEIVE,
        lifetime.end,
        FaultEvidence::Fixture(FixtureFaultEvidence {
            end: cap,
            audit: events.audit.clone(),
            actor: events.actor.clone(),
            revoked: events.revoked.clone(),
            dropped: events.preparation_dropped.clone(),
            armed: false,
        }),
    )
    .unwrap();
    if let FaultEvidence::Fixture(proof) = &mut preparation.evidence {
        proof.armed = true;
    }
    value.preparation = Some(preparation);
    value
}
fn backend(events: &Arc<Mutex<Events>>) -> ScriptedReply {
    ScriptedReply {
        events: events.clone(),
    }
}
// Synthetic receipt only for ownership-engine component tests. The production
// factory can receive one only from the completed actual dispatch engine.
fn detach_with_kernel<'r, R: ReplyKernel>(
    original: &'r mut Attempt<'_, MessageKernel, Session>,
    kernel: R,
) -> Result<ReplyOwner<'r, Session, R>, ReplyRefusal> {
    let checks = original.kernel.events.lock().unwrap().consumed.clone();
    detach_fixture_components(original, kernel, checks)
}
// Generic test-only component helper; it preserves all production snapshot/
// kernel-trailer checks and is not an own-port sender-identity substitute.
fn detach_fixture_components<'r, K: Kernel, S: SessionDependency, R: ReplyKernel>(
    original: &'r mut Attempt<'_, K, S>,
    kernel: R,
    checks: Arc<FixtureConsumedChecks>,
) -> Result<ReplyOwner<'r, S, R>, ReplyRefusal> {
    let preparation = original.preparation.as_ref().unwrap();
    preparation.dispatch_consumed.store(true, Ordering::SeqCst);
    let receipt = ValidReportReceipt {
        preparation,
        response: Response::RestartThrottled,
    };
    detach_components(
        &mut original.storage,
        &mut original.resources,
        original.lifetime,
        original.receive_name,
        original.audit.as_ref().unwrap(),
        preparation,
        receipt,
        kernel,
        ConsumedSource::Fixture(checks),
    )
}
fn order(events: &Events) {
    let veto = events.trace.iter().position(|v| *v == "veto").unwrap();
    let body = events
        .trace
        .iter()
        .position(|v| *v == "body-destroy")
        .unwrap();
    assert!(veto < body);
    if let Some(reply) = events.trace.iter().position(|v| *v == "reply-destroy") {
        assert!(veto < reply && reply < body);
    }
}

#[test]
fn detach_exclusively_moves_only_original_remote_fields_to_exact_failure_reply_and_permanently_consumes_frame(
) {
    let (lifetime, events, cap) = setup(Duration::from_secs(2));
    let mut original = original(&lifetime, &events, cap);
    let before = original.storage.0;
    let owner = detach_with_kernel(&mut original, backend(&events)).unwrap();
    assert_eq!(owner.end, cap);
    assert_eq!(owner.storage.1, MessagePhase::ReplyDetached);
    assert!(super::super::actual_frame(&owner.storage).is_none());
    assert!(super::super::FaultInputs::read(&owner.storage).is_err());
    assert!(owner
        .preparation
        .require_original(
            &owner.storage,
            TASK,
            super::super::IPC_OTYPE_TASK_CONTROL,
            RECEIVE,
            cap
        )
        .is_err());
    let mut expected = before;
    expected[8..12].fill(0);
    expected[0..4].copy_from_slice(&(0x8000_1112u32 & !REMOTE_MASK).to_le_bytes());
    assert_eq!(owner.storage.0, expected);
    assert_eq!((owner.reply.0.as_ptr() as usize) % 16, 0);
    assert!(returned_simple_reply(&owner.reply));
    assert_eq!(
        u32::from_le_bytes(owner.reply.0[8..12].try_into().unwrap()),
        REMOTE
    );
    drop(owner);
    assert_eq!(
        detach_with_kernel(&mut original, backend(&events)).unwrap_err(),
        ReplyRefusal::AlreadyDetached
    );
    assert_eq!(
        original.finish(),
        Cleanup::NativeDestroyInvokedCompletionUnqualified
    );
    let events = events.lock().unwrap();
    assert_eq!(
        (
            events.sends.len(),
            events.reply_destroys.len(),
            events.body_destroys
        ),
        (0, 1, 1)
    );
    order(&events);
}

#[test]
fn invalid_ownership_wire_destination_or_context_refuses_before_detach_and_keeps_original_remote_owned(
) {
    for invalid in [
        "none",
        "unknown",
        "wire",
        "destination",
        "expired",
        "context",
    ] {
        let (lifetime, events, cap) = setup(Duration::from_secs(2));
        let mut original = original(&lifetime, &events, cap);
        match invalid {
            "none" => original.resources = Resources::None,
            "unknown" => original.resources = Resources::Unknown,
            "wire" => original.storage.0[20..24].copy_from_slice(&2404i32.to_le_bytes()),
            "destination" => original.receive_name ^= 1,
            "expired" => original.preparation.as_mut().unwrap().end = Instant::now(),
            _ => events.lock().unwrap().refuse = true,
        }
        assert!(detach_with_kernel(&mut original, backend(&events)).is_err());
        assert_eq!(original.storage.1, MessagePhase::Original);
        assert_eq!(
            u32::from_le_bytes(original.storage.0[8..12].try_into().unwrap()),
            REMOTE
        );
        drop(original);
        let events = events.lock().unwrap();
        assert!(events.sends.is_empty() && events.reply_destroys.is_empty());
        assert_eq!(
            events.body_destroys,
            usize::from(!matches!(invalid, "none" | "unknown"))
        );
    }
}

#[test]
fn accepted_send_transfers_once_even_when_postcheck_refuses_expires_or_unwinds_without_stale_cleanup(
) {
    for action in [None, Some("refuse"), Some("late"), Some("post-panic")] {
        let (lifetime, events, cap) = setup(if action == Some("late") {
            Duration::from_millis(80)
        } else {
            Duration::from_secs(2)
        });
        let mut original = original(&lifetime, &events, cap);
        {
            let mut events = events.lock().unwrap();
            events.action = action;
            events.returned_name = 0x9999_0001;
        }
        let owner = detach_with_kernel(&mut original, backend(&events)).unwrap();
        let outcome =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| owner.send_failure()));
        if action == Some("post-panic") {
            assert!(outcome.is_err());
        } else {
            let outcome = outcome.unwrap();
            assert_eq!(outcome.native_result, Some(0));
            assert_eq!(
                outcome.ownership,
                ReplyOwnership::TransferredDeliveryUnqualified
            );
            assert_eq!(outcome.cleanup, ReplyCleanup::NotRequired);
            assert_eq!(outcome.refusal.is_some(), action.is_some());
        }
        drop(original);
        let events = events.lock().unwrap();
        assert_eq!(
            (
                events.sends.len(),
                events.reply_destroys.len(),
                events.body_destroys
            ),
            (1, 0, 1)
        );
        order(&events);
        assert_eq!(events.sends[0].1, 0x51);
        assert!(events.sends[0].2 <= 2_000);
    }
}

#[test]
fn exact_recoverable_send_errors_destroy_only_current_returned_simple_buffer_once_after_veto() {
    for result in [INVALID_DEST, TIMED_OUT, INTERRUPTED] {
        for returned_name in [0, u32::MAX, 0x9999_0001] {
            let (lifetime, events, cap) = setup(Duration::from_secs(2));
            let mut original = original(&lifetime, &events, cap);
            {
                let mut events = events.lock().unwrap();
                events.result = result;
                events.returned_name = returned_name;
            }
            let outcome = detach_with_kernel(&mut original, backend(&events))
                .unwrap()
                .send_failure();
            assert_eq!(outcome.native_result, Some(result));
            assert_eq!(outcome.ownership, ReplyOwnership::ReturnedUnsent);
            assert_eq!(
                outcome.cleanup,
                ReplyCleanup::DestroyInvokedCompletionUnqualified
            );
            drop(original);
            let events = events.lock().unwrap();
            assert_eq!(
                (
                    events.sends.len(),
                    events.reply_destroys.len(),
                    events.body_destroys
                ),
                (1, 1, 1)
            );
            assert_eq!(
                u32::from_le_bytes(events.reply_destroys[0][8..12].try_into().unwrap()),
                returned_name
            );
            order(&events);
        }
    }
}

#[test]
fn unsupported_flags_ambiguous_filtered_and_unknown_results_remain_unknown_without_cached_name_cleanup(
) {
    for result in [
        0x1000_0009,
        0x1000_000d,
        0x1000_0012,
        0x1000_0013,
        0x1000_0017,
        0x1000_0002,
        0x1000_0010,
        0x1000_000e,
        0x1000_0008,
        0x7654_3210,
        TIMED_OUT | 0x0400,
        TIMED_OUT | 0x0800,
        TIMED_OUT | 0x1000,
        TIMED_OUT | 0x2000,
        INTERRUPTED | 0x0400,
        INVALID_DEST | 0x2000,
    ] {
        let (lifetime, events, cap) = setup(Duration::from_secs(2));
        let mut original = original(&lifetime, &events, cap);
        events.lock().unwrap().result = result;
        let outcome = detach_with_kernel(&mut original, backend(&events))
            .unwrap()
            .send_failure();
        assert_eq!(outcome.native_result, Some(result));
        assert_eq!(outcome.ownership, ReplyOwnership::Unknown);
        assert_eq!(outcome.cleanup, ReplyCleanup::UnknownNoSafeReplyCleanup);
        drop(original);
        let events = events.lock().unwrap();
        assert_eq!(
            (
                events.sends.len(),
                events.reply_destroys.len(),
                events.body_destroys
            ),
            (1, 0, 1)
        );
        order(&events);
    }
}

#[test]
fn malformed_returned_buffer_on_recoverable_code_is_unknown_without_resource_guess_or_destroy() {
    for corruption in [
        "bits", "type", "size", "local", "voucher", "id", "ndr", "positive",
    ] {
        let (lifetime, events, cap) = setup(Duration::from_secs(2));
        let mut original = original(&lifetime, &events, cap);
        {
            let mut events = events.lock().unwrap();
            events.result = TIMED_OUT;
            events.corrupt = Some(corruption);
        }
        let outcome = detach_with_kernel(&mut original, backend(&events))
            .unwrap()
            .send_failure();
        assert_eq!(outcome.native_result, Some(TIMED_OUT));
        assert_eq!(outcome.ownership, ReplyOwnership::Unknown);
        assert_eq!(outcome.refusal, Some(ReplyRefusal::ReturnedShape));
        drop(original);
        let events = events.lock().unwrap();
        assert!(events.reply_destroys.is_empty());
        order(&events);
    }
}

#[test]
fn native_call_unwind_keeps_unknown_ownership_and_cleanup_unwind_consumes_known_buffer_before_call()
{
    for during_call in [true, false] {
        let (lifetime, events, cap) = setup(Duration::from_secs(2));
        let mut original = original(&lifetime, &events, cap);
        {
            let mut events = events.lock().unwrap();
            events.result = TIMED_OUT;
            if during_call {
                events.action = Some("during-panic");
            } else {
                events.destroy_panic = true;
            }
        }
        let owner = detach_with_kernel(&mut original, backend(&events)).unwrap();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| owner.send_failure()))
                .is_err()
        );
        drop(original);
        let events = events.lock().unwrap();
        assert_eq!(events.sends.len(), 1);
        assert_eq!(events.reply_destroys.len(), usize::from(!during_call));
        assert_eq!(events.body_destroys, 1);
        order(&events);
    }
}

#[test]
fn timeout_floor_preserves_zero_nonblocking_and_rejects_integer_overflow_without_new_budget() {
    for duration in [
        Duration::ZERO,
        Duration::from_nanos(1),
        Duration::from_nanos(999_999),
    ] {
        assert_eq!(timeout_millis(duration), Ok(0));
    }
    assert_eq!(timeout_millis(Duration::from_nanos(1_999_999)), Ok(1));
    assert_eq!(
        timeout_millis(Duration::from_millis(u32::MAX as u64)),
        Ok(u32::MAX)
    );
    assert_eq!(
        timeout_millis(Duration::from_millis(u32::MAX as u64 + 1)),
        Err(ReplyRefusal::TimeoutRange)
    );
}

#[test]
fn cap_or_session_loss_after_detach_prevents_send_and_cleans_exclusive_unsent_reply_after_original_veto(
) {
    for expire in [true, false] {
        let (lifetime, events, cap) = setup(Duration::from_secs(2));
        let mut original = original(&lifetime, &events, cap);
        let mut owner = detach_with_kernel(&mut original, backend(&events)).unwrap();
        if expire {
            owner.end = Instant::now();
        } else {
            lifetime.stop();
        }
        let outcome = owner.send_failure();
        assert_eq!(outcome.native_result, None);
        assert_eq!(outcome.ownership, ReplyOwnership::NeverSent);
        assert_eq!(
            outcome.cleanup,
            ReplyCleanup::DestroyInvokedCompletionUnqualified
        );
        drop(original);
        let events = events.lock().unwrap();
        assert_eq!(
            (
                events.sends.len(),
                events.reply_destroys.len(),
                events.body_destroys
            ),
            (0, 1, 1)
        );
        order(&events);
    }
}

#[test]
fn concurrent_same_session_veto_during_send_never_changes_transfer_or_returned_buffer_ownership() {
    for result in [0, TIMED_OUT] {
        let (lifetime, events, cap) = setup(Duration::from_secs(2));
        let mut original = original(&lifetime, &events, cap);
        let entered = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        {
            let mut events = events.lock().unwrap();
            events.result = result;
            events.returned_name = 0x9999_0001;
            events.barriers = Some((entered.clone(), resume.clone()));
        }
        let owner = detach_with_kernel(&mut original, backend(&events)).unwrap();
        let outcome = std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                entered.wait();
                lifetime.stop();
                resume.wait();
            });
            let outcome = owner.send_failure();
            worker.join().unwrap();
            outcome
        });
        assert_eq!(outcome.native_result, Some(result));
        assert_eq!(
            outcome.ownership,
            if result == 0 {
                ReplyOwnership::TransferredDeliveryUnqualified
            } else {
                ReplyOwnership::ReturnedUnsent
            }
        );
        drop(original);
        let events = events.lock().unwrap();
        assert_eq!(events.reply_destroys.len(), usize::from(result != 0));
        assert_eq!(events.sends.len(), 1);
        order(&events);
    }
}

#[test]
fn exact_original_and_consumed_snapshot_reject_every_unpermitted_byte_and_wrong_phase() {
    let (lifetime, events, cap) = setup(Duration::from_secs(2));
    let mut original = original(&lifetime, &events, cap);
    let before = original.storage.0;
    for offset in 0..mach_wire::FRAME_BYTES {
        let mut changed = Storage(before, MessagePhase::Original);
        changed.0[offset] ^= 1;
        assert!(
            original
                .preparation
                .as_ref()
                .unwrap()
                .require_original(
                    &changed,
                    TASK,
                    super::super::IPC_OTYPE_TASK_CONTROL,
                    RECEIVE,
                    cap
                )
                .is_err(),
            "original byte {offset}"
        );
    }
    let owner = detach_with_kernel(&mut original, backend(&events)).unwrap();
    for offset in 0..mach_wire::FRAME_BYTES {
        let mut changed = Storage(owner.storage.0, MessagePhase::ReplyDetached);
        changed.0[offset] ^= 1;
        assert!(
            owner
                .preparation
                .require_consumed(
                    &changed,
                    TASK,
                    super::super::IPC_OTYPE_TASK_CONTROL,
                    RECEIVE,
                    cap
                )
                .is_err(),
            "consumed byte {offset}"
        );
    }
    assert!(owner
        .preparation
        .require_consumed(
            &Storage(owner.storage.0, MessagePhase::Original),
            TASK,
            super::super::IPC_OTYPE_TASK_CONTROL,
            RECEIVE,
            cap
        )
        .is_err());
    assert!(owner
        .preparation
        .require_consumed(
            owner.storage,
            TASK,
            super::super::IPC_OTYPE_TASK_CONTROL,
            RECEIVE,
            cap
        )
        .is_ok());
    drop(owner);
    drop(original);
    order(&events.lock().unwrap());
}

#[test]
fn consumed_class_audit_actor_or_current_control_loss_prevents_send_and_retires_unsent_once() {
    for lost in ["class", "audit", "actor", "assignment", "lease"] {
        let (lifetime, events, cap) = setup(Duration::from_secs(2));
        let mut original = original(&lifetime, &events, cap);
        let owner = detach_with_kernel(&mut original, backend(&events)).unwrap();
        {
            let events = events.lock().unwrap();
            match lost {
                "class" => events.consumed.class.store(false, Ordering::SeqCst),
                "audit" => events.consumed.audit.store(false, Ordering::SeqCst),
                "actor" => events.actor.store(false, Ordering::SeqCst),
                "assignment" => events.consumed.assignment.store(false, Ordering::SeqCst),
                _ => events.audit.store(false, Ordering::SeqCst),
            }
        }
        let outcome = owner.send_failure();
        assert_eq!(outcome.ownership, ReplyOwnership::NeverSent);
        assert_eq!(outcome.refusal, Some(ReplyRefusal::Context));
        drop(original);
        let events = events.lock().unwrap();
        assert_eq!(
            (
                events.sends.len(),
                events.reply_destroys.len(),
                events.body_destroys
            ),
            (0, 1, 1)
        );
        order(&events);
    }
}

#[test]
fn accepted_send_ownership_precedes_consumed_context_failure_or_unwind_and_native_errors_skip_postcheck(
) {
    for result in [0, TIMED_OUT, 0x7654_3210] {
        for lost in ["class", "audit", "actor", "assignment", "consumed-panic"] {
            let (lifetime, events, cap) = setup(Duration::from_secs(2));
            let mut original = original(&lifetime, &events, cap);
            {
                let mut events = events.lock().unwrap();
                events.action = Some(lost);
                events.result = result;
            }
            let owner = detach_with_kernel(&mut original, backend(&events)).unwrap();
            let outcome =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| owner.send_failure()));
            if result == 0 && lost == "consumed-panic" {
                assert!(outcome.is_err());
            } else {
                let outcome = outcome.unwrap();
                assert_eq!(outcome.native_result, Some(result));
                assert_eq!(
                    outcome.ownership,
                    if result == 0 {
                        ReplyOwnership::TransferredDeliveryUnqualified
                    } else if result == TIMED_OUT {
                        ReplyOwnership::ReturnedUnsent
                    } else {
                        ReplyOwnership::Unknown
                    }
                );
                assert_eq!(outcome.refusal.is_some(), result == 0);
            }
            drop(original);
            let events = events.lock().unwrap();
            assert_eq!(
                (
                    events.sends.len(),
                    events.reply_destroys.len(),
                    events.body_destroys
                ),
                (1, usize::from(result == TIMED_OUT), 1)
            );
            assert_eq!(
                events.consumed.calls.load(Ordering::SeqCst),
                if result == 0 { 2 } else { 1 }
            );
            order(&events);
        }
    }
}

#[test]
fn valid_report_receipt_is_bound_to_same_preparation_even_when_snapshot_cap_and_audit_match() {
    let (lifetime, events, cap) = setup(Duration::from_secs(2));
    let mut original = original(&lifetime, &events, cap);
    let evidence = {
        let events = events.lock().unwrap();
        FaultEvidence::Fixture(FixtureFaultEvidence {
            end: cap,
            audit: events.audit.clone(),
            actor: events.actor.clone(),
            revoked: events.revoked.clone(),
            dropped: Arc::new(AtomicBool::new(false)),
            armed: false,
        })
    };
    let other = OriginalFaultPreparation::from_original(
        &original.storage,
        TASK,
        super::super::IPC_OTYPE_TASK_CONTROL,
        RECEIVE,
        lifetime.end,
        evidence,
    )
    .unwrap();
    let receipt = super::super::tests::dispatch_fixture_receipt(&other)
        .ok()
        .unwrap();
    let checks = events.lock().unwrap().consumed.clone();
    let before = original.storage.0;
    let outcome = detach_components(
        &mut original.storage,
        &mut original.resources,
        &lifetime,
        RECEIVE,
        original.audit.as_ref().unwrap(),
        original.preparation.as_ref().unwrap(),
        receipt,
        backend(&events),
        ConsumedSource::Fixture(checks),
    );
    assert_eq!(outcome.unwrap_err(), ReplyRefusal::Context);
    assert_eq!(original.storage.0, before);
    assert_eq!(original.storage.1, MessagePhase::Original);
    drop(other);
    drop(original);
    let events = events.lock().unwrap();
    assert!(events.sends.is_empty() && events.reply_destroys.is_empty());
    order(&events);
}

#[test]
fn completed_shared_report_engine_receipt_composes_once_with_consumed_reply_under_independent_terminal_veto(
) {
    let (lifetime, events, cap) = setup(Duration::from_secs(2));
    let mut original = original(&lifetime, &events, cap);
    {
        let audit = original.audit.as_ref().unwrap();
        let preparation = original.preparation.as_ref().unwrap();
        let _terminal = super::super::OriginalTerminalVeto {
            lifetime: &lifetime,
            audit,
            preparation,
        };
        let receipt = super::super::tests::dispatch_fixture_receipt(preparation)
            .ok()
            .unwrap();
        assert!(audit.active.load(Ordering::SeqCst));
        assert!(!events.lock().unwrap().revoked.load(Ordering::SeqCst));
        let checks = events.lock().unwrap().consumed.clone();
        let owner = detach_components(
            &mut original.storage,
            &mut original.resources,
            &lifetime,
            RECEIVE,
            audit,
            preparation,
            receipt,
            backend(&events),
            ConsumedSource::Fixture(checks),
        )
        .unwrap();
        assert!(super::super::actual_frame(owner.storage).is_none());
        let outcome = owner.send_failure();
        assert_eq!(
            outcome.ownership,
            ReplyOwnership::TransferredDeliveryUnqualified
        );
        assert!(!audit.active.load(Ordering::SeqCst));
    }
    drop(original);
    let events = events.lock().unwrap();
    assert_eq!(
        (
            events.sends.len(),
            events.reply_destroys.len(),
            events.body_destroys
        ),
        (1, 0, 1)
    );
    assert_eq!(
        i32::from_le_bytes(events.sends[0].0[32..36].try_into().unwrap()),
        5
    );
    order(&events);
}

#[test]
fn independent_outer_veto_covers_unwind_after_original_guard_drop_and_after_consumed_owner_construction(
) {
    for after_detach in [false, true] {
        let (lifetime, events, cap) = setup(Duration::from_secs(2));
        let mut original = original(&lifetime, &events, cap);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let audit = original.audit.as_ref().unwrap();
            let preparation = original.preparation.as_ref().unwrap();
            let _terminal = super::super::OriginalTerminalVeto {
                lifetime: &lifetime,
                audit,
                preparation,
            };
            let receipt = super::super::tests::dispatch_fixture_receipt(preparation)
                .ok()
                .unwrap();
            assert!(audit.active.load(Ordering::SeqCst));
            if !after_detach {
                panic!("SCRIPTED_ORIGINAL_TO_CONSUMED_TRANSITION_UNWIND");
            }
            let checks = events.lock().unwrap().consumed.clone();
            let _owner = detach_components(
                &mut original.storage,
                &mut original.resources,
                &lifetime,
                RECEIVE,
                audit,
                preparation,
                receipt,
                backend(&events),
                ConsumedSource::Fixture(checks),
            )
            .unwrap();
            panic!("SCRIPTED_CONSUMED_BEFORE_SEND_UNWIND");
        }));
        assert!(result.is_err());
        assert!(events.lock().unwrap().revoked.load(Ordering::SeqCst));
        assert!(!events.lock().unwrap().audit.load(Ordering::SeqCst));
        assert_eq!(
            original.storage.1,
            if after_detach {
                MessagePhase::ReplyDetached
            } else {
                MessagePhase::Original
            }
        );
        drop(original);
        let events = events.lock().unwrap();
        assert_eq!(
            (
                events.sends.len(),
                events.reply_destroys.len(),
                events.body_destroys
            ),
            (0, usize::from(after_detach), 1)
        );
        order(&events);
    }
}
