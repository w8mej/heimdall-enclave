//! SOFTWARE ordering/fault models only; no native guard, IPC identity or launchd.
use super::*;
use enclave_core::deployment::{
    DeploymentBroker, DeploymentLayout, DeploymentRole, DeploymentSigningMode,
};
use std::{
    cell::{Cell, RefCell},
    path::PathBuf,
    rc::Rc,
};

fn target(role: DeploymentRole) -> DeploymentTarget {
    let base = PathBuf::from("/selected-broker-stop-fixture");
    let support = base.join("support");
    DeploymentTarget {
        version: 1,
        target_id: "broker-stop".into(),
        role,
        profile: Profile::L3,
        authority_config: support.join("authority.json"),
        expected_artifacts_manifest: support.join("inventory.json"),
        codesign_pins_file: support.join("pins.json"),
        signing_identity_mode: DeploymentSigningMode::LocalPins,
        layout: DeploymentLayout {
            binary_dir: base.join("bin"),
            custody_bundle: support.join("Custody.app"),
            sandbox_dir: base.join("sandbox"),
            socket_root: base.join("run"),
            state_root: base.join("state"),
            audit_root: base.join("audit"),
            cas_store_root: base.join("cas"),
            staging_root: base.join("stage"),
            support_root: support.clone(),
            launchd_namespace: "com.depot.broker-stop".into(),
            mach_service: "com.depot.broker-stop.exception".into(),
        },
        broker: Some(DeploymentBroker {
            base_dir: base.join("state/apfs-broker"),
            tuf_root_file: support.join("root.json"),
        }),
        shared_read_only_inputs: vec![],
    }
}
#[derive(Default)]
struct State {
    events: Vec<&'static str>,
    stopped: bool,
}
struct Admission {
    state: Rc<RefCell<State>>,
    fail: bool,
}
impl Quiescence for Admission {
    fn request(&mut self, until: Instant) -> EnclaveResult<()> {
        assert!(until > Instant::now());
        self.state.borrow_mut().events.push("quiesce");
        if self.fail {
            fail!(EACCES, "SYNTHETIC_LIVE_PROTOCOL_REFUSAL");
        }
        Ok(())
    }
}
struct Observation {
    state: Rc<RefCell<State>>,
    absent: bool,
    unknown: bool,
    stays_loaded: bool,
}
impl Observer for Observation {
    fn job(&mut self, job: &BrokerJob, _: Instant) -> EnclaveResult<JobObservation> {
        assert_eq!(job.target(), "system/com.depot.broker-stop.apfs-broker");
        let mut state = self.state.borrow_mut();
        state.events.push("observe");
        Ok(if self.unknown {
            JobObservation::UnknownResponse
        } else if self.absent || (!self.stays_loaded && state.stopped) {
            JobObservation::ObservedServiceAbsent
        } else {
            JobObservation::ObservedLoaded
        })
    }
}
struct Runner {
    state: Rc<RefCell<State>>,
    fail: bool,
}
impl StopRunner for Runner {
    fn bootout(&mut self, job: &BrokerJob, until: Instant) -> EnclaveResult<()> {
        assert!(until > Instant::now());
        let command = job.command();
        assert_eq!(
            command
                .get_args()
                .map(|s| s.to_str().unwrap())
                .collect::<Vec<_>>(),
            ["bootout", "system/com.depot.broker-stop.apfs-broker"]
        );
        let mut state = self.state.borrow_mut();
        state.events.push("bootout");
        state.stopped = true;
        if self.fail {
            fail!(EIO, "SYNTHETIC_CHILD_OWNERSHIP_UNKNOWN");
        }
        Ok(())
    }
}
fn fixtures() -> (Rc<RefCell<State>>, Admission, Observation, Runner) {
    let state = Rc::new(RefCell::new(State::default()));
    (
        state.clone(),
        Admission {
            state: state.clone(),
            fail: false,
        },
        Observation {
            state: state.clone(),
            absent: false,
            unknown: false,
            stays_loaded: false,
        },
        Runner { state, fail: false },
    )
}
fn run(
    admission: &mut Admission,
    observer: &mut Observation,
    runner: &mut Runner,
    check: &mut impl FnMut() -> EnclaveResult<()>,
) -> StopResult {
    operate(
        &target(DeploymentRole::DedicatedTest),
        &"a".repeat(64),
        admission,
        observer,
        runner,
        check,
        Instant::now() + OPERATION_LIMIT,
    )
}

#[test]
fn both_roles_require_live_barrier_before_any_observation_or_exact_bootout() {
    for role in [
        DeploymentRole::DedicatedTest,
        DeploymentRole::ExistingUpgrade,
    ] {
        let (state, mut admission, mut observer, mut runner) = fixtures();
        let result = operate(
            &target(role),
            &"a".repeat(64),
            &mut admission,
            &mut observer,
            &mut runner,
            &mut || Ok(()),
            Instant::now() + OPERATION_LIMIT,
        )
        .unwrap();
        assert_eq!(
            state.borrow().events,
            ["quiesce", "observe", "bootout", "observe"]
        );
        assert!(
            result.complete
                && result.authenticated_quiescence_confirmed
                && result.bootout_succeeded
                && result.registration_absence_observed
        );
        assert!(!result.uncertain_command_effects && !result.uncertain_quiescence_effects);
        assert!(!result.inactivity_proven && !result.installation_supported && !result.qualified);
    }
}
#[test]
fn old_missing_or_refused_protocol_never_reaches_even_an_absence_query() {
    let (state, mut admission, mut observer, mut runner) = fixtures();
    admission.fail = true;
    observer.absent = true;
    let failure = run(&mut admission, &mut observer, &mut runner, &mut || Ok(())).unwrap_err();
    assert_eq!(state.borrow().events, ["quiesce"]);
    assert!(failure.receipt.uncertain_quiescence_effects);
    assert!(
        !failure.receipt.complete
            && !failure.receipt.authenticated_quiescence_confirmed
            && !failure.receipt.already_absent
    );
}
#[test]
fn absence_is_scoped_observation_only_after_authenticated_barrier() {
    let (state, mut admission, mut observer, mut runner) = fixtures();
    observer.absent = true;
    let result = run(&mut admission, &mut observer, &mut runner, &mut || Ok(())).unwrap();
    assert_eq!(state.borrow().events, ["quiesce", "observe"]);
    assert!(result.already_absent && result.complete);
    assert!(!result.bootout_succeeded && !result.inactivity_proven);
}
#[test]
fn initial_binding_refusal_prevents_all_effects_and_still_final_checks() {
    let (state, mut admission, mut observer, mut runner) = fixtures();
    let mut calls = 0;
    let failure = run(&mut admission, &mut observer, &mut runner, &mut || {
        calls += 1;
        Err(err!(ESTALE, "SYNTHETIC_BINDING_LOST"))
    })
    .unwrap_err();
    assert_eq!(calls, 2);
    assert!(state.borrow().events.is_empty());
    assert!(failure.final_binding_error.is_some());
    assert!(!failure.receipt.quiescence_attempted);
}
#[test]
fn guard_loss_during_successful_rpc_never_allows_observation_or_bootout() {
    let (state, mut admission, mut observer, mut runner) = fixtures();
    let failure = run(&mut admission, &mut observer, &mut runner, &mut || {
        if state.borrow().events.is_empty() {
            Ok(())
        } else {
            Err(err!(ESTALE, "SYNTHETIC_GUARD_LOST"))
        }
    })
    .unwrap_err();
    assert_eq!(state.borrow().events, ["quiesce"]);
    assert!(!failure.receipt.complete);
    assert!(failure.receipt.uncertain_quiescence_effects && failure.final_binding_error.is_some());
}
#[test]
fn rpc_failure_and_guard_loss_preserve_original_error_separately() {
    let (state, mut admission, mut observer, mut runner) = fixtures();
    admission.fail = true;
    let failure = run(&mut admission, &mut observer, &mut runner, &mut || {
        if state.borrow().events.is_empty() {
            Ok(())
        } else {
            Err(err!(ESTALE, "SYNTHETIC_GUARD_LOST"))
        }
    })
    .unwrap_err();
    assert!(failure.error.is("SYNTHETIC_LIVE_PROTOCOL_REFUSAL"));
    assert!(failure
        .final_binding_error
        .unwrap()
        .is("SYNTHETIC_GUARD_LOST"));
}
#[test]
fn unknown_observation_refuses_bootout_with_barrier_receipt_preserved() {
    let (state, mut admission, mut observer, mut runner) = fixtures();
    observer.unknown = true;
    let failure = run(&mut admission, &mut observer, &mut runner, &mut || Ok(())).unwrap_err();
    assert_eq!(state.borrow().events, ["quiesce", "observe"]);
    assert!(failure.receipt.authenticated_quiescence_confirmed);
    assert!(!failure.receipt.complete && !failure.receipt.bootout_succeeded);
}
#[test]
fn uncertain_child_stops_without_another_observer_and_retains_scope() {
    let (state, mut admission, mut observer, mut runner) = fixtures();
    runner.fail = true;
    let failure = run(&mut admission, &mut observer, &mut runner, &mut || Ok(())).unwrap_err();
    assert_eq!(state.borrow().events, ["quiesce", "observe", "bootout"]);
    assert!(failure.receipt.uncertain_command_effects && !failure.receipt.complete);
}
#[test]
fn successful_bootout_followed_by_lost_guard_keeps_completed_effect_without_success() {
    let (state, mut admission, mut observer, mut runner) = fixtures();
    let failure = run(&mut admission, &mut observer, &mut runner, &mut || {
        if state.borrow().stopped {
            Err(err!(ESTALE, "SYNTHETIC_GUARD_LOST"))
        } else {
            Ok(())
        }
    })
    .unwrap_err();
    assert_eq!(state.borrow().events, ["quiesce", "observe", "bootout"]);
    assert!(failure.receipt.bootout_succeeded && failure.receipt.uncertain_command_effects);
    assert!(!failure.receipt.complete && !failure.receipt.registration_absence_observed);
}
#[test]
fn still_loaded_after_successful_bootout_is_unknown_and_never_retried() {
    let (state, mut admission, mut observer, mut runner) = fixtures();
    observer.stays_loaded = true;
    let failure = run(&mut admission, &mut observer, &mut runner, &mut || Ok(())).unwrap_err();
    assert_eq!(
        state.borrow().events,
        ["quiesce", "observe", "bootout", "observe"]
    );
    assert!(
        failure.receipt.bootout_succeeded
            && !failure.receipt.complete
            && failure.receipt.uncertain_command_effects
    );
}
#[test]
fn final_binding_loss_does_not_erase_confirmed_barrier_and_registration_effect() {
    let (state, mut admission, mut observer, mut runner) = fixtures();
    let post = Cell::new(0);
    let failure = run(&mut admission, &mut observer, &mut runner, &mut || {
        if state
            .borrow()
            .events
            .iter()
            .filter(|event| **event == "observe")
            .count()
            == 2
        {
            post.set(post.get() + 1);
            if post.get() == 2 {
                return Err(err!(ESTALE, "SYNTHETIC_FINAL_LOSS"));
            }
        }
        Ok(())
    })
    .unwrap_err();
    assert!(failure.receipt.bootout_succeeded && failure.receipt.registration_absence_observed);
    assert!(!failure.receipt.complete && failure.error.is("SYNTHETIC_FINAL_LOSS"));
}
#[test]
fn lower_profile_or_elapsed_deadline_never_contacts_broker() {
    for elapsed in [false, true] {
        let (state, mut admission, mut observer, mut runner) = fixtures();
        let mut selected = target(DeploymentRole::DedicatedTest);
        if !elapsed {
            selected.profile = Profile::L2;
            selected.broker = None;
        }
        let until = if elapsed {
            Instant::now() - Duration::from_secs(1)
        } else {
            Instant::now() + OPERATION_LIMIT
        };
        assert!(operate(
            &selected,
            &"a".repeat(64),
            &mut admission,
            &mut observer,
            &mut runner,
            &mut || Ok(()),
            until
        )
        .is_err());
        assert!(state.borrow().events.is_empty());
    }
}
