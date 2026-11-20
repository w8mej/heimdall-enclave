use super::*;
use std::{
    cell::RefCell,
    panic::{catch_unwind, AssertUnwindSafe},
    rc::Rc,
    time::Duration,
};

const RECEIVER: u32 = 81;
#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    Current(usize),
    Query,
    Veto,
    Release(u32, bool),
}
type Row = (u32, u32, i32, i32);
struct Script {
    end: Instant,
    now: Instant,
    kind: u32,
    receiver: u32,
    rows: Vec<Row>,
    count: u32,
    query_code: i32,
    current_count: usize,
    current_fail: Option<(usize, Stage)>,
    current_panic: Option<usize>,
    current_late: Option<usize>,
    query_panic: bool,
    query_late: bool,
    cancel_after_query: bool,
    namespace_after_query: bool,
    namespace: bool,
    cleanup_count: usize,
    cleanup_failure: Option<usize>,
    cleanup_panic: Option<usize>,
    cleanup_late: bool,
    revoked: bool,
    current_ends: Vec<Instant>,
    trace: Rc<RefCell<Vec<Event>>>,
}
impl Script {
    fn valid() -> Self {
        let now = Instant::now();
        Self {
            end: now + Duration::from_secs(3),
            now,
            kind: CONTROL,
            receiver: RECEIVER,
            rows: vec![(REQUIRED_MASK, RECEIVER, BEHAVIOR, FLAVOR)],
            count: 1,
            query_code: 0,
            current_count: 0,
            current_fail: None,
            current_panic: None,
            current_late: None,
            query_panic: false,
            query_late: false,
            cancel_after_query: false,
            namespace_after_query: true,
            namespace: true,
            cleanup_count: 0,
            cleanup_failure: None,
            cleanup_panic: None,
            cleanup_late: false,
            revoked: false,
            current_ends: Vec::new(),
            trace: Rc::new(RefCell::new(Vec::new())),
        }
    }
    fn observe(&mut self) -> ObservationResult {
        let end = self.end;
        Observation::new(self, end).run()
    }
    fn stage(&mut self) -> Stage {
        self.observe().result.unwrap_err().stage
    }
    fn releases(&self) -> Vec<(u32, bool)> {
        self.trace
            .borrow()
            .iter()
            .filter_map(|event| match event {
                Event::Release(name, revoked) => Some((*name, *revoked)),
                _ => None,
            })
            .collect()
    }
    fn queries(&self) -> usize {
        self.trace
            .borrow()
            .iter()
            .filter(|e| **e == Event::Query)
            .count()
    }
}
impl Operation for Script {
    fn original_end(&self) -> Instant {
        self.end
    }
    fn now(&self) -> Instant {
        self.now
    }
    fn current(&mut self, end: Instant) -> Result<(), Failure> {
        self.current_count += 1;
        self.current_ends.push(end);
        self.trace
            .borrow_mut()
            .push(Event::Current(self.current_count));
        if self.current_panic == Some(self.current_count) {
            panic!("scripted current unwind");
        }
        if self.current_late == Some(self.current_count) {
            self.now = self.end;
        }
        if let Some((number, stage)) = self.current_fail {
            if number == self.current_count {
                return Err(Failure::at(stage));
            }
        }
        if self.revoked {
            return Err(Failure::at(Stage::OriginalContext));
        }
        Ok(())
    }
    fn task_class(&self) -> u32 {
        self.kind
    }
    fn receiver(&self) -> u32 {
        self.receiver
    }
    fn get(&mut self, ports: &mut Ports) -> i32 {
        self.trace.borrow_mut().push(Event::Query);
        assert_eq!(ports.count, 32);
        assert!(ports.names.iter().all(|n| *n == 0));
        assert!(ports.masks.iter().all(|n| *n == 0));
        assert!(ports.behaviors.iter().all(|n| *n == 0));
        assert!(ports.flavors.iter().all(|n| *n == 0));
        for (index, (mask, name, behavior, flavor)) in self.rows.iter().copied().enumerate() {
            ports.masks[index] = mask;
            ports.names[index] = name;
            ports.behaviors[index] = behavior;
            ports.flavors[index] = flavor;
        }
        ports.count = self.count;
        if self.query_late {
            self.now = self.end;
        }
        if self.cancel_after_query {
            self.invalidate();
        }
        self.namespace = self.namespace_after_query;
        if self.query_panic {
            panic!("scripted partial query unwind");
        }
        self.query_code
    }
    fn release(&mut self, name: u32) -> Release {
        self.cleanup_count += 1;
        self.trace
            .borrow_mut()
            .push(Event::Release(name, self.revoked));
        if self.cleanup_panic == Some(self.cleanup_count) {
            self.cleanup_panic = None;
            panic!("scripted cleanup unwind");
        }
        if self.cleanup_late {
            self.now = self.end;
        }
        if !self.namespace {
            return Release::NamespaceChanged;
        }
        if self.cleanup_failure == Some(self.cleanup_count) {
            return Release::NativeError(44);
        }
        Release::Released
    }
    fn invalidate(&mut self) {
        self.revoked = true;
        self.trace.borrow_mut().push(Event::Veto);
    }
}

#[test]
fn control_exact_original_assignment_observed_without_replacing_or_releasing_original() {
    let mut script = Script::valid();
    let result = script.observe();
    assert_eq!(result.result, Ok(()));
    assert_eq!(
        result.cleanup,
        CleanupSummary {
            attempted: 1,
            uncertain: 0
        }
    );
    assert_eq!(script.queries(), 1);
    assert_eq!(script.releases(), vec![(RECEIVER, false)]);
    assert!(!script.revoked);
    assert_eq!(script.current_count, 5);
    // That release is the one newly returned uref. No operation can release
    // the original receiver/message/task, whose ownership is outside this seam.
}

#[test]
fn split_exact_masks_consume_each_returned_uref_even_with_duplicate_numeric_handler_names() {
    let mut script = Script::valid();
    script.rows = [1 << 1, 1 << 2, 1 << 12]
        .into_iter()
        .map(|mask| (mask, RECEIVER, BEHAVIOR, FLAVOR))
        .collect();
    script.count = 3;
    let result = script.observe();
    assert_eq!(result.result, Ok(()));
    assert_eq!(result.cleanup.attempted, 3);
    assert_eq!(script.releases(), vec![(RECEIVER, false); 3]);
}

#[test]
fn read_task_explicitly_refuses_without_any_assignment_rpc_or_right_upgrade() {
    let mut script = Script::valid();
    script.kind = READ;
    assert_eq!(script.stage(), Stage::UnsupportedRead);
    assert_eq!(script.queries(), 0);
    assert!(script.releases().is_empty());
    assert!(script.revoked);
}

#[test]
fn unclassified_or_inspect_task_cannot_enter_native_assignment_query() {
    for kind in [0, 20, 44, 50, u32::MAX] {
        let mut script = Script::valid();
        script.kind = kind;
        assert_eq!(script.stage(), Stage::UnsupportedClass);
        assert_eq!(script.queries(), 0);
        assert!(script.revoked);
    }
}

#[test]
fn no_original_receiver_or_expired_request_cannot_query_any_task() {
    for name in [0, u32::MAX] {
        let mut script = Script::valid();
        script.receiver = name;
        assert_eq!(script.stage(), Stage::OriginalReceiver);
        assert_eq!(script.queries(), 0);
    }
    let mut script = Script::valid();
    let expired = script.now;
    let result = Observation::new(&mut script, expired).run();
    assert_eq!(result.result.unwrap_err().stage, Stage::Deadline);
    assert_eq!(script.current_count, 0);
    assert_eq!(script.queries(), 0);
    assert!(script.revoked);
}

#[test]
fn requested_endpoint_only_shortens_original_and_never_renews_later_checks() {
    let mut script = Script::valid();
    let original = script.end;
    let result = Observation::new(&mut script, original + Duration::from_secs(30)).run();
    assert_eq!(result.result, Ok(()));
    assert!(script.current_ends.iter().all(|end| *end == original));
    let mut script = Script::valid();
    let shorter = script.now + Duration::from_millis(500);
    let result = Observation::new(&mut script, shorter).run();
    assert_eq!(result.result, Ok(()));
    assert!(script.current_ends.iter().all(|end| *end == shorter));
}

#[test]
fn exact_mask_union_rejects_zero_missing_duplicate_overlap_and_extra_masks() {
    for masks in [
        vec![0],
        vec![1 << 1],
        vec![REQUIRED_MASK, 1 << 1],
        vec![REQUIRED_MASK | (1 << 3)],
        vec![1 << 1, 1 << 1, 1 << 12],
    ] {
        let mut script = Script::valid();
        script.rows = masks
            .iter()
            .map(|mask| (*mask, RECEIVER, BEHAVIOR, FLAVOR))
            .collect();
        script.count = masks.len() as u32;
        assert_eq!(script.stage(), Stage::Mask);
        assert_eq!(script.releases(), vec![(RECEIVER, true); masks.len()]);
        assert_eq!(script.queries(), 1);
    }
}

#[test]
fn wrong_handler_default_behavior_code_width_or_thread_state_flavor_refuses() {
    for (row, stage) in [
        ((REQUIRED_MASK, 82, BEHAVIOR, FLAVOR), Stage::Receiver),
        ((REQUIRED_MASK, 0, BEHAVIOR, FLAVOR), Stage::Receiver),
        ((REQUIRED_MASK, RECEIVER, 1, FLAVOR), Stage::Behavior),
        (
            (REQUIRED_MASK, RECEIVER, BEHAVIOR | 2, FLAVOR),
            Stage::Behavior,
        ),
        (
            (REQUIRED_MASK, RECEIVER, BEHAVIOR, FLAVOR + 1),
            Stage::Flavor,
        ),
    ] {
        let mut script = Script::valid();
        script.rows = vec![row];
        assert_eq!(script.stage(), stage);
        assert!(script.revoked);
        assert!(script.releases().iter().all(|(_, vetoed)| *vetoed));
    }
}

#[test]
fn malformed_zero_or_oversized_count_still_cleans_all_initialized_output_slots() {
    for count in [0, 33, u32::MAX] {
        let mut script = Script::valid();
        script.rows = vec![(REQUIRED_MASK, RECEIVER, BEHAVIOR, FLAVOR); CAPACITY];
        script.count = count;
        let result = script.observe();
        assert_eq!(result.result.unwrap_err().stage, Stage::Count);
        assert_eq!(
            result.cleanup,
            CleanupSummary {
                attempted: 32,
                uncertain: 0
            }
        );
        assert_eq!(script.releases(), vec![(RECEIVER, true); 32]);
    }
}

#[test]
fn hidden_output_beyond_claimed_count_never_passes_and_its_uref_is_consumed() {
    for trailing in [(1, 0, 0, 0), (0, 82, 0, 0), (0, 0, 1, 0), (0, 0, 0, 1)] {
        let mut script = Script::valid();
        script.rows.push(trailing);
        assert_eq!(script.stage(), Stage::Count);
        let expected = if trailing.1 == 0 { 1 } else { 2 };
        assert_eq!(script.releases().len(), expected);
        assert!(script.releases().iter().all(|(_, vetoed)| *vetoed));
    }
}

#[test]
fn native_error_preserves_primary_failure_and_consumes_partial_duplicate_and_late_outputs() {
    let mut script = Script::valid();
    script.query_code = 19;
    script.count = 0;
    script.rows = vec![
        (0, RECEIVER, 0, 0),
        (0, RECEIVER, 0, 0),
        (0, u32::MAX, 0, 0),
        (0, 0, 0, 0),
    ];
    script.cleanup_failure = Some(1);
    let result = script.observe();
    assert_eq!(result.result, Err(Failure::native(Stage::Query, 19)));
    assert_eq!(
        result.cleanup,
        CleanupSummary {
            attempted: 2,
            uncertain: 1
        }
    );
    assert_eq!(script.releases(), vec![(RECEIVER, true); 2]);
}

#[test]
fn cleanup_failure_vetoes_before_later_cleanup_and_cannot_become_success() {
    let mut script = Script::valid();
    script.rows = [1 << 1, 1 << 2, 1 << 12]
        .into_iter()
        .map(|mask| (mask, RECEIVER, BEHAVIOR, FLAVOR))
        .collect();
    script.count = 3;
    script.cleanup_failure = Some(1);
    let result = script.observe();
    assert_eq!(
        result.result,
        Err(Failure::native(Stage::ReturnedCleanup, 44))
    );
    assert_eq!(
        result.cleanup,
        CleanupSummary {
            attempted: 3,
            uncertain: 1
        }
    );
    assert_eq!(
        script.releases(),
        vec![(RECEIVER, false), (RECEIVER, true), (RECEIVER, true)]
    );
    assert!(script.revoked);
}

#[test]
fn namespace_change_marks_returned_reference_cleanup_unknown_without_retry_or_admission() {
    let mut script = Script::valid();
    script.namespace_after_query = false;
    let result = script.observe();
    assert_eq!(result.result.unwrap_err().stage, Stage::Namespace);
    assert_eq!(
        result.cleanup,
        CleanupSummary {
            attempted: 1,
            uncertain: 1
        }
    );
    assert_eq!(script.cleanup_count, 1);
    assert!(script.revoked);
}

#[test]
fn actor_binding_or_actual_original_changes_before_or_after_readback_vetoes_same_attempt() {
    for number in 1..=5 {
        for stage in [Stage::ActorBinding, Stage::OriginalContext] {
            let mut script = Script::valid();
            script.current_fail = Some((number, stage));
            assert_eq!(script.stage(), stage);
            assert!(script.revoked);
            assert_eq!(script.queries(), usize::from(number >= 3));
            assert!(script
                .releases()
                .iter()
                .all(|(_, revoked)| *revoked || number == 5));
        }
    }
}

#[test]
fn exact_expiry_during_query_postcheck_or_cleanup_withholds_late_success() {
    let mut query = Script::valid();
    query.query_late = true;
    assert_eq!(query.stage(), Stage::Deadline);
    assert_eq!(query.releases(), vec![(RECEIVER, true)]);
    for number in [1, 2, 3, 4, 5] {
        let mut script = Script::valid();
        script.current_late = Some(number);
        assert_eq!(script.stage(), Stage::Deadline);
        assert!(script.revoked);
    }
    let mut cleanup = Script::valid();
    cleanup.cleanup_late = true;
    assert_eq!(cleanup.stage(), Stage::Deadline);
    assert_eq!(cleanup.cleanup_count, 1);
    assert!(cleanup.revoked);
}

#[test]
fn cancellation_after_native_query_cleans_after_veto_and_never_rearms() {
    let mut script = Script::valid();
    script.cancel_after_query = true;
    assert_eq!(script.stage(), Stage::OriginalContext);
    assert_eq!(script.releases(), vec![(RECEIVER, true)]);
    assert_eq!(script.stage(), Stage::OriginalContext);
    assert_eq!(script.queries(), 1);
}

#[test]
fn unwind_after_partial_query_or_before_cleanup_revokes_before_returned_owner_drop() {
    for partial_query in [false, true] {
        let mut script = Script::valid();
        script.query_panic = partial_query;
        script.current_panic = if partial_query { None } else { Some(3) };
        assert!(catch_unwind(AssertUnwindSafe(|| {
            script.observe();
        }))
        .is_err());
        assert!(script.revoked);
        assert_eq!(script.releases(), vec![(RECEIVER, true)]);
        assert_eq!(script.queries(), 1);
    }
}

#[test]
fn unwind_during_cleanup_consumes_once_vetoes_and_keeps_later_slots_for_guard_cleanup() {
    let mut script = Script::valid();
    script.rows = [1 << 1, 1 << 2, 1 << 12]
        .into_iter()
        .map(|mask| (mask, RECEIVER, BEHAVIOR, FLAVOR))
        .collect();
    script.count = 3;
    script.cleanup_panic = Some(1);
    assert!(catch_unwind(AssertUnwindSafe(|| {
        script.observe();
    }))
    .is_err());
    assert!(script.revoked);
    assert_eq!(
        script.releases(),
        vec![(RECEIVER, false), (RECEIVER, true), (RECEIVER, true)]
    );
    assert_eq!(script.cleanup_count, 3);
    assert_eq!(script.queries(), 1);
}
