//! Private SOFTWARE kernel scripts exercise the production ownership algorithm.
//! No test invokes bootstrap, task_set/get_exception_ports, native assignment,
//! real exception delivery, privileged APIs or a caller-supplied native owner.
use super::*;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};
const ORIGINAL: u32 = 111;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    Current,
    TaskAudit,
    Lookup,
    Type(u32),
    Set(u32),
    Get,
    Deallocate(u32, i32),
}
struct Get {
    ports: Ports,
    code: i32,
    delay_until: Option<Instant>,
    change_task: bool,
}
struct State {
    events: Vec<Event>,
    lookup_names: Vec<Vec<u8>>,
    current: bool,
    lookup: (i32, u32),
    kinds: VecDeque<Result<u32, i32>>,
    set_code: i32,
    gets: VecDeque<Get>,
    deallocations: usize,
    fail_deallocate: Option<(usize, i32)>,
    audit: [u32; 8],
    audits: VecDeque<(i32, u32, [u32; 8])>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            events: Vec::new(),
            lookup_names: Vec::new(),
            current: true,
            lookup: (0, ORIGINAL),
            kinds: VecDeque::new(),
            set_code: 0,
            gets: VecDeque::new(),
            deallocations: 0,
            fail_deallocate: None,
            audit: [7; 8],
            audits: VecDeque::new(),
        }
    }
}
struct Script(Arc<Mutex<State>>);
fn full() -> Ports {
    let mut p = Ports::empty();
    p.count = 1;
    p.masks[0] = REQUIRED_MASK;
    p.ports[0] = ORIGINAL;
    p.behaviors[0] = BEHAVIOR;
    p.flavors[0] = FLAVOR;
    p
}
fn get(ports: Ports) -> Get {
    Get {
        ports,
        code: 0,
        delay_until: None,
        change_task: false,
    }
}
impl Kernel for Script {
    fn current(&mut self) -> bool {
        let mut s = self.0.lock().unwrap();
        s.events.push(Event::Current);
        s.current
    }
    fn task_audit(&mut self) -> (i32, u32, [u32; 8]) {
        let mut s = self.0.lock().unwrap();
        s.events.push(Event::TaskAudit);
        s.audits.pop_front().unwrap_or((0, 8, s.audit))
    }
    fn lookup(&mut self, name: &CString) -> (i32, u32) {
        let mut s = self.0.lock().unwrap();
        s.events.push(Event::Lookup);
        s.lookup_names.push(name.as_bytes().to_vec());
        s.lookup
    }
    fn port_type(&mut self, port: u32) -> Result<u32, i32> {
        let mut s = self.0.lock().unwrap();
        s.events.push(Event::Type(port));
        s.kinds.pop_front().unwrap_or(Ok(SEND))
    }
    fn set(&mut self, port: u32) -> i32 {
        let mut s = self.0.lock().unwrap();
        s.events.push(Event::Set(port));
        s.set_code
    }
    fn get(&mut self, ports: &mut Ports) -> i32 {
        let next = {
            let mut s = self.0.lock().unwrap();
            s.events.push(Event::Get);
            s.gets.pop_front().unwrap_or_else(|| get(full()))
        };
        *ports = next.ports;
        if next.change_task {
            self.0.lock().unwrap().current = false;
        }
        if let Some(until) = next.delay_until {
            while Instant::now() < until {
                std::thread::yield_now();
            }
        }
        next.code
    }
    fn deallocate(&mut self, port: u32) -> Cleanup {
        let mut s = self.0.lock().unwrap();
        s.deallocations += 1;
        let code = s
            .fail_deallocate
            .filter(|(sequence, _)| *sequence == s.deallocations)
            .map_or(0, |(_, code)| code);
        s.events.push(Event::Deallocate(port, code));
        if code == 0 {
            Cleanup::Released
        } else {
            Cleanup::NativeError(code)
        }
    }
}
fn setup() -> (Arc<Mutex<State>>, Script) {
    let s = Arc::new(Mutex::new(State::default()));
    (s.clone(), Script(s))
}
fn service() -> CString {
    CString::new("private.software.fixture").unwrap()
}
fn until() -> Instant {
    Instant::now() + Duration::from_secs(2)
}
fn assigned() -> (Arc<Mutex<State>>, Assignment<Script>) {
    let (state, kernel) = setup();
    let owner = Assignment::assign(kernel, &service(), until())
        .ok()
        .expect("scripted positive assignment");
    (state, owner)
}
fn released(state: &Arc<Mutex<State>>) -> Vec<(u32, i32)> {
    state
        .lock()
        .unwrap()
        .events
        .iter()
        .filter_map(|event| {
            if let Event::Deallocate(port, code) = event {
                Some((*port, *code))
            } else {
                None
            }
        })
        .collect()
}

#[test]
fn bootstrap_name_bounds_refuse_before_adapter_and_preserve_exact_maximum() {
    for size in [0, 127, 128, 129] {
        let (state, kernel) = setup();
        let name = CString::new("a".repeat(size)).unwrap();
        let result = Assignment::assign(kernel, &name, until());
        if size == 127 {
            let owner = result.ok().expect("127byte service is representable");
            assert_eq!(state.lock().unwrap().lookup_names, [name.as_bytes()]);
            drop(owner);
        } else {
            assert_eq!(result.err().unwrap().stage, Stage::ServiceName);
            assert!(
                state.lock().unwrap().events.is_empty(),
                "invalid name must not reach any adapter call"
            );
        }
    }
}
#[test]
fn original_lookup_is_owned_once_and_observation_never_relooks_up_or_reassigns() {
    let (state, mut owner) = assigned();
    owner.observe(until()).unwrap();
    owner.observe(until()).unwrap();
    assert_eq!(owner.port, Some(ORIGINAL));
    assert!(!owner.poisoned);
    assert!(owner.failures.is_empty());
    let events = state.lock().unwrap().events.clone();
    assert_eq!(
        events
            .iter()
            .filter(|event| **event == Event::Lookup)
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| **event == Event::Set(ORIGINAL))
            .count(),
        1
    );
    assert_eq!(
        events.iter().filter(|event| **event == Event::Get).count(),
        3
    );
    assert_eq!(released(&state), vec![(ORIGINAL, 0); 3]);
    drop(owner);
    assert_eq!(released(&state), vec![(ORIGINAL, 0); 4]);
}
#[test]
fn split_required_masks_cleanup_each_returned_uref_even_when_names_repeat() {
    let (state, mut owner) = assigned();
    let mut p = Ports::empty();
    p.count = 3;
    for (index, mask) in [1 << 1, 1 << 2, 1 << 12].into_iter().enumerate() {
        p.masks[index] = mask;
        p.ports[index] = ORIGINAL;
        p.behaviors[index] = BEHAVIOR;
        p.flavors[index] = FLAVOR;
    }
    state.lock().unwrap().gets.push_back(get(p));
    owner.observe(until()).unwrap();
    assert_eq!(released(&state), vec![(ORIGINAL, 0); 4]);
    drop(owner);
    assert_eq!(released(&state), vec![(ORIGINAL, 0); 5]);
}
#[test]
fn every_count_mask_port_behavior_and_flavor_mismatch_is_sticky_refusal() {
    for variant in 0..10 {
        let (state, mut owner) = assigned();
        let mut p = full();
        let expected = match variant {
            0 => {
                p.count = 0;
                Stage::Count
            }
            1 => {
                p.count = CAPACITY as u32 + 1;
                Stage::Count
            }
            2 => {
                p.masks[0] &= !(1 << 2);
                Stage::Mask
            }
            3 => {
                p.count = 2;
                p.masks[1] = 1 << 1;
                p.ports[1] = ORIGINAL;
                p.behaviors[1] = BEHAVIOR;
                p.flavors[1] = FLAVOR;
                Stage::Mask
            }
            4 => {
                p.masks[0] |= 1 << 3;
                Stage::Mask
            }
            5 => {
                p.ports[0] = 222;
                Stage::Port
            }
            6 => {
                p.behaviors[0] = 1;
                Stage::Behavior
            }
            7 => {
                p.flavors[0] = -1;
                Stage::Flavor
            }
            8 => {
                p.ports[0] = 0;
                Stage::Port
            }
            _ => {
                p.ports[0] = u32::MAX;
                Stage::Port
            }
        };
        state.lock().unwrap().gets.push_back(get(p));
        assert_eq!(owner.observe(until()).unwrap_err().stage, expected);
        assert!(owner.poisoned);
        let before = state.lock().unwrap().events.len();
        assert_eq!(owner.observe(until()).unwrap_err().stage, Stage::Poisoned);
        assert_eq!(
            state.lock().unwrap().events.len(),
            before,
            "poison cannot issue another native call"
        );
        assert_eq!(owner.port, Some(ORIGINAL));
        drop(owner);
        assert_eq!(released(&state).last(), Some(&(ORIGINAL, 0)));
    }
}
#[test]
fn malformed_count_and_slots_beyond_count_still_cleanup_all_initialized_outputs() {
    for count in [0, CAPACITY as u32 + 1, 1] {
        let (state, mut owner) = assigned();
        let mut p = full();
        p.count = count;
        p.ports[CAPACITY - 1] = 222;
        state.lock().unwrap().gets.push_back(get(p));
        assert_eq!(owner.observe(until()).unwrap_err().stage, Stage::Count);
        assert_eq!(released(&state), [(ORIGINAL, 0), (ORIGINAL, 0), (222, 0)]);
        drop(owner);
        assert_eq!(released(&state).last(), Some(&(ORIGINAL, 0)));
    }
}
#[test]
fn native_get_error_keeps_primary_and_cleans_every_available_partial_return() {
    let (state, mut owner) = assigned();
    let mut p = full();
    p.count = 2;
    p.ports[1] = 222;
    {
        let mut s = state.lock().unwrap();
        s.gets.push_back(Get {
            ports: p,
            code: 73,
            delay_until: None,
            change_task: false,
        });
        s.fail_deallocate = Some((2, 81));
    }
    assert_eq!(
        owner.observe(until()).unwrap_err(),
        Failure::native(Stage::Get, 73)
    );
    assert_eq!(
        owner.failures,
        [
            Failure::native(Stage::Get, 73),
            Failure::native(Stage::ReturnedCleanup, 81)
        ]
    );
    assert_eq!(owner.uncertain_references, [ORIGINAL]);
    assert_eq!(released(&state), [(ORIGINAL, 0), (ORIGINAL, 81), (222, 0)]);
    drop(owner);
    assert_eq!(released(&state).last(), Some(&(ORIGINAL, 0)));
}
#[test]
fn cleanup_error_never_skips_other_references_or_allows_a_later_positive() {
    let (state, mut owner) = assigned();
    let mut p = full();
    p.count = 3;
    p.masks = [0; CAPACITY];
    for (index, mask) in [1 << 1, 1 << 2, 1 << 12].into_iter().enumerate() {
        p.masks[index] = mask;
        p.ports[index] = ORIGINAL;
        p.behaviors[index] = BEHAVIOR;
        p.flavors[index] = FLAVOR;
    }
    {
        let mut s = state.lock().unwrap();
        s.gets.push_back(get(p));
        s.fail_deallocate = Some((2, 88));
    }
    assert_eq!(
        owner.observe(until()).unwrap_err(),
        Failure::native(Stage::ReturnedCleanup, 88)
    );
    assert_eq!(owner.uncertain_references, [ORIGINAL]);
    assert_eq!(
        released(&state),
        [(ORIGINAL, 0), (ORIGINAL, 88), (ORIGINAL, 0), (ORIGINAL, 0)]
    );
    assert_eq!(owner.observe(until()).unwrap_err().stage, Stage::Poisoned);
    drop(owner);
    assert_eq!(
        released(&state).len(),
        5,
        "failed deallocation is reported, never retried"
    );
}
#[test]
fn constructor_lookup_type_set_and_get_errors_release_only_owned_references() {
    for stage in [Stage::Lookup, Stage::OriginalType, Stage::Set, Stage::Get] {
        let (state, kernel) = setup();
        {
            let mut s = state.lock().unwrap();
            match stage {
                Stage::Lookup => s.lookup.0 = 71,
                Stage::OriginalType => s.kinds.push_back(Err(72)),
                Stage::Set => s.set_code = 73,
                _ => s.gets.push_back(Get {
                    ports: full(),
                    code: 74,
                    delay_until: None,
                    change_task: false,
                }),
            }
        }
        assert_eq!(
            Assignment::assign(kernel, &service(), until())
                .err()
                .unwrap()
                .stage,
            stage
        );
        assert_eq!(
            released(&state),
            vec![(ORIGINAL, 0); if stage == Stage::Get { 2 } else { 1 }]
        );
    }
    for port in [0, u32::MAX] {
        let (state, kernel) = setup();
        state.lock().unwrap().lookup.1 = port;
        assert_eq!(
            Assignment::assign(kernel, &service(), until())
                .err()
                .unwrap()
                .stage,
            Stage::LookupName
        );
        assert!(released(&state).is_empty());
    }
}
#[test]
fn original_send_right_loss_and_changed_current_task_refuse_without_new_assignment() {
    for variant in 0..3 {
        let (state, mut owner) = assigned();
        {
            let mut s = state.lock().unwrap();
            match variant {
                0 => s.current = false,
                1 => s.kinds.push_back(Ok(0)),
                _ => s.kinds.push_back(Ok(SEND | DEAD_NAME)),
            }
        }
        let before = state
            .lock()
            .unwrap()
            .events
            .iter()
            .filter(|event| **event == Event::Get)
            .count();
        assert_eq!(
            owner.observe(until()).unwrap_err().stage,
            if variant == 0 {
                Stage::CurrentTask
            } else {
                Stage::OriginalType
            }
        );
        let events = state.lock().unwrap().events.clone();
        assert_eq!(
            events.iter().filter(|event| **event == Event::Get).count(),
            before
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| **event == Event::Lookup)
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| **event == Event::Set(ORIGINAL))
                .count(),
            1
        );
    }
}
#[test]
fn endpoint_expiry_prevents_calls_and_late_get_cleans_refs_before_refusal() {
    let (state, kernel) = setup();
    assert_eq!(
        Assignment::assign(kernel, &service(), Instant::now())
            .err()
            .unwrap()
            .stage,
        Stage::Deadline
    );
    assert!(state.lock().unwrap().events.is_empty());
    let (state, mut owner) = assigned();
    let end = Instant::now() + Duration::from_millis(10);
    state.lock().unwrap().gets.push_back(Get {
        ports: full(),
        code: 0,
        delay_until: Some(end),
        change_task: false,
    });
    assert_eq!(owner.observe(end).unwrap_err().stage, Stage::Deadline);
    assert_eq!(released(&state), [(ORIGINAL, 0), (ORIGINAL, 0)]);
    assert_eq!(owner.observe(until()).unwrap_err().stage, Stage::Poisoned);
    drop(owner);
    assert_eq!(released(&state), vec![(ORIGINAL, 0); 3]);
}
#[test]
fn drop_reports_original_cleanup_error_once_without_unsetting_or_restore_calls() {
    let (state, owner) = assigned();
    state.lock().unwrap().fail_deallocate = Some((2, 91));
    drop(owner);
    assert_eq!(released(&state), [(ORIGINAL, 0), (ORIGINAL, 91)]);
    assert_eq!(
        state.lock().unwrap().events.last(),
        Some(&Event::Deallocate(ORIGINAL, 91))
    );
    // Kernel has no unset/restore method. Native Drop can call only deallocate.
}
#[test]
fn changed_current_task_during_get_retains_every_return_without_a_stale_deallocate() {
    let (state, mut owner) = assigned();
    let mut p = full();
    p.count = 3;
    for (index, mask) in [1 << 1, 1 << 2, 1 << 12].into_iter().enumerate() {
        p.masks[index] = mask;
        p.ports[index] = ORIGINAL;
        p.behaviors[index] = BEHAVIOR;
        p.flavors[index] = FLAVOR;
    }
    state.lock().unwrap().gets.push_back(Get {
        ports: p,
        code: 0,
        delay_until: None,
        change_task: true,
    });
    assert_eq!(
        owner.observe(until()).unwrap_err().stage,
        Stage::CleanupTaskChanged
    );
    assert_eq!(owner.uncertain_references, [ORIGINAL; 3]);
    assert_eq!(
        released(&state),
        [(ORIGINAL, 0)],
        "generic production owner must not call the stale adapter"
    );
    assert_eq!(
        owner.failures,
        vec![Failure::at(Stage::CleanupTaskChanged); 3]
    );
    drop(owner);
    assert_eq!(
        released(&state),
        [(ORIGINAL, 0)],
        "Drop must also suppress the stale original-reference call"
    );
}
#[test]
fn changed_current_task_before_drop_suppresses_original_deallocate_entirely() {
    let (state, owner) = assigned();
    state.lock().unwrap().current = false;
    drop(owner);
    assert_eq!(released(&state), [(ORIGINAL, 0)]);
    assert_eq!(state.lock().unwrap().events.last(), Some(&Event::Current));
}
#[test]
fn exported_error_and_retained_diagnostics_never_include_a_port_or_service_name() {
    let failure = Failure::native(Stage::ReturnedCleanup, 81);
    let error = failure.error();
    assert!(error.detail.contains("ReturnedCleanup") && error.detail.contains("81"));
    assert!(!error.detail.contains(&ORIGINAL.to_string()));
    assert!(!error.detail.contains(service().to_str().unwrap()));
}

#[test]
fn same_original_opaque_task_identity_is_retained_across_every_assignment_observation() {
    let (state, mut owner) = assigned();
    assert_eq!(owner.audit, Some([7; 8]));
    owner.observe(until()).unwrap();
    owner.observe(until()).unwrap();
    assert_eq!(owner.audit, Some([7; 8]));
    let events = state.lock().unwrap().events.clone();
    assert!(
        events
            .iter()
            .filter(|event| **event == Event::TaskAudit)
            .count()
            > 3
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| **event == Event::Lookup)
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| **event == Event::Set(ORIGINAL))
            .count(),
        1
    );
}

#[test]
fn native_task_audit_failure_short_count_and_unset_values_refuse_before_lookup() {
    for (code, count, audit, stage) in [
        (81, 8, [7; 8], Stage::TaskAuditRead),
        (0, 7, [7; 8], Stage::TaskAuditCount),
        (0, 9, [7; 8], Stage::TaskAuditCount),
        (0, 8, [u32::MAX; 8], Stage::TaskAuditValue),
        (0, 8, [0; 8], Stage::TaskAuditValue),
    ] {
        let (state, kernel) = setup();
        state.lock().unwrap().audits.push_back((code, count, audit));
        assert_eq!(
            Assignment::assign(kernel, &service(), until())
                .err()
                .unwrap()
                .stage,
            stage
        );
        let events = &state.lock().unwrap().events;
        assert!(!events.iter().any(|event| matches!(
            event,
            Event::Lookup | Event::Set(_) | Event::Get | Event::Deallocate(..)
        )));
    }
}

#[test]
fn any_task_identity_word_change_is_terminal_and_cleanup_uses_only_same_namespace() {
    for index in 0..8 {
        let (state, mut owner) = assigned();
        state.lock().unwrap().audit[index] ^= 1;
        assert_eq!(
            owner.observe(until()).unwrap_err().stage,
            Stage::TaskAuditChanged
        );
        assert_eq!(
            owner.audit,
            Some([7; 8]),
            "replacement token must never overwrite original"
        );
        state.lock().unwrap().audit = [7; 8];
        let before = state.lock().unwrap().events.len();
        assert_eq!(owner.observe(until()).unwrap_err().stage, Stage::Poisoned);
        assert_eq!(
            state.lock().unwrap().events.len(),
            before,
            "identity revival must perform no native call"
        );
        drop(owner);
        assert_eq!(
            released(&state),
            [(ORIGINAL, 0), (ORIGINAL, 0)],
            "identity failure does not suppress safe original-reference cleanup in same namespace"
        );
    }
}

#[test]
fn identity_change_after_assignment_readback_retains_original_and_all_returned_refs_are_cleaned() {
    let (state, mut owner) = assigned();
    // First audit precedes original type; second follows it; third follows
    // get+returned-reference cleanup, so a late mismatch is still terminal.
    {
        let mut s = state.lock().unwrap();
        s.audits
            .extend([(0, 8, [7; 8]), (0, 8, [7; 8]), (0, 8, [8; 8])]);
    }
    assert_eq!(
        owner.observe(until()).unwrap_err().stage,
        Stage::TaskAuditChanged
    );
    assert_eq!(owner.audit, Some([7; 8]));
    assert_eq!(owner.port, Some(ORIGINAL));
    assert_eq!(released(&state), [(ORIGINAL, 0), (ORIGINAL, 0)]);
    drop(owner);
    assert_eq!(released(&state), vec![(ORIGINAL, 0); 3]);
}
