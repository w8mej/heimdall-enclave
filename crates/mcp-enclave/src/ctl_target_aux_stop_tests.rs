//! Injected SOFTWARE fixtures; no native root capability or launchctl effects.
use super::*;
use enclave_core::{
    deployment::{DeploymentBroker, DeploymentLayout, DeploymentRole, DeploymentSigningMode},
    Profile,
};
use std::{cell::RefCell, path::PathBuf, rc::Rc};

fn target(role: DeploymentRole, profile: Profile) -> DeploymentTarget {
    let base = PathBuf::from("/auxiliary-stop-fixture");
    let support = base.join("support");
    DeploymentTarget {
        version: 1,
        target_id: "auxiliary-stop".into(),
        role,
        profile,
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
            launchd_namespace: "com.depot.auxiliary-stop".into(),
            mach_service: "com.depot.auxiliary-stop.exception".into(),
        },
        broker: (profile == Profile::L3).then(|| DeploymentBroker {
            base_dir: base.join("state/apfs-broker"),
            tuf_root_file: support.join("tuf-root.json"),
        }),
        shared_read_only_inputs: vec![],
    }
}
#[derive(Default)]
struct State {
    stopped: BTreeSet<String>,
    attempts: Vec<String>,
    queries: Vec<String>,
}
struct FakeObserver {
    state: Rc<RefCell<State>>,
    uids: BTreeSet<u32>,
    domain_calls: usize,
    changed_domains_after_stop: bool,
    inventory_error: bool,
    unknown_for: Option<String>,
    already_absent: bool,
    stays_loaded: bool,
}
impl Observer for FakeObserver {
    fn gui_candidates(&mut self, until: Instant) -> EnclaveResult<BTreeSet<u32>> {
        assert!(until > Instant::now());
        self.domain_calls += 1;
        if self.inventory_error {
            fail!(EIO, "UNKNOWN_ACTIVITY_LIVE_GUI_INVENTORY");
        }
        let mut result = self.uids.clone();
        if self.changed_domains_after_stop && !self.state.borrow().attempts.is_empty() {
            result.insert(991);
        }
        Ok(result)
    }
    fn job(&mut self, job: &AuxiliaryJob, until: Instant) -> EnclaveResult<JobObservation> {
        assert!(until > Instant::now());
        let target = job.target();
        let mut state = self.state.borrow_mut();
        state.queries.push(target.clone());
        if self.unknown_for.as_ref() == Some(&target) {
            return Ok(JobObservation::UnknownResponse);
        }
        if self.already_absent || (!self.stays_loaded && state.stopped.contains(&target)) {
            return Ok(if job.domain.starts_with("gui/") {
                JobObservation::ObservedGuiDomainAbsent
            } else {
                JobObservation::ObservedServiceAbsent
            });
        }
        Ok(JobObservation::ObservedLoaded)
    }
}
struct FakeRunner {
    state: Rc<RefCell<State>>,
    fail_at: Option<usize>,
}
impl StopRunner for FakeRunner {
    fn bootout(&mut self, job: &AuxiliaryJob, until: Instant) -> EnclaveResult<()> {
        assert!(until > Instant::now());
        assert!(until <= Instant::now() + COMMAND_LIMIT);
        let mut state = self.state.borrow_mut();
        state.attempts.push(job.target());
        // Model a command that effected bootout but returned uncertain cleanup.
        state.stopped.insert(job.target());
        if self.fail_at == Some(state.attempts.len()) {
            fail!(EIO, "SYNTHETIC_OWNERSHIP_UNKNOWN");
        }
        Ok(())
    }
}
fn fixtures(uids: &[u32]) -> (Rc<RefCell<State>>, FakeObserver, FakeRunner) {
    let state = Rc::new(RefCell::new(State::default()));
    let observer = FakeObserver {
        state: state.clone(),
        uids: uids.iter().copied().collect(),
        domain_calls: 0,
        changed_domains_after_stop: false,
        inventory_error: false,
        unknown_for: None,
        already_absent: false,
        stays_loaded: false,
    };
    let runner = FakeRunner {
        state: state.clone(),
        fail_at: None,
    };
    (state, observer, runner)
}
fn run(
    observer: &mut FakeObserver,
    runner: &mut FakeRunner,
    binding: &mut impl FnMut() -> EnclaveResult<()>,
) -> StopResult {
    operate(
        &target(DeploymentRole::DedicatedTest, Profile::L2),
        &"a".repeat(64),
        observer,
        runner,
        binding,
        Instant::now() + OPERATION_LIMIT,
    )
}

#[test]
fn fixed_jobs_include_every_supplied_live_gui_uid_and_exclude_core_broker_and_legacy_namespace() {
    for role in [
        DeploymentRole::DedicatedTest,
        DeploymentRole::ExistingUpgrade,
    ] {
        for profile in [Profile::L2, Profile::L3] {
            let selected = target(role, profile);
            let jobs = jobs(&selected, &BTreeSet::from([501, 34001]));
            assert_eq!(jobs.len(), 8);
            assert_eq!(jobs[0].target(), "system/com.depot.auxiliary-stop.hydrate");
            assert_eq!(
                jobs.last().unwrap().target(),
                "system/com.depot.auxiliary-stop.supervisor"
            );
            for uid in [501, 34001] {
                for suffix in AGENTS {
                    assert!(jobs.iter().any(|job| job.target()
                        == format!("gui/{uid}/com.depot.auxiliary-stop.{suffix}")));
                }
            }
            for job in jobs {
                assert!(!job.label.starts_with("com.enterprise.enclave."));
                assert!(![
                    "adapter",
                    "cas",
                    "custody",
                    "ifc",
                    "zk",
                    "apfs-broker",
                    "fido"
                ]
                .iter()
                .any(|suffix| job.label.ends_with(&format!(".{suffix}"))));
                let command = job.command();
                let expected = job.target();
                assert_eq!(
                    command
                        .get_args()
                        .map(|s| s.to_str().unwrap())
                        .collect::<Vec<_>>(),
                    ["bootout", expected.as_str()]
                );
            }
        }
    }
}

#[test]
fn observed_loaded_jobs_stop_and_receipt_preserves_the_restrictive_scope() {
    let (state, mut observer, mut runner) = fixtures(&[501, 34001]);
    let receipt = run(&mut observer, &mut runner, &mut || Ok(())).unwrap();
    assert_eq!(receipt.completed_jobs, state.borrow().attempts);
    assert_eq!(receipt.bootout_succeeded, receipt.completed_jobs);
    assert_eq!(receipt.completed_jobs.len(), 8);
    assert!(receipt.complete);
    assert_eq!(receipt.gui_candidate_uids, [501, 34001]);
    assert_eq!(receipt.scope, SCOPE);
    assert_eq!(receipt.broker_quiescence, "UNKNOWN_NOT_PERFORMED");
    assert_eq!(receipt.core_jobs, "NOT_OPERATED_BY_THIS_SCOPE");
    assert!(!receipt.inactivity_proven && !receipt.installation_supported && !receipt.qualified);
    assert!(receipt.boundary_job.is_none());
    assert!(!receipt.uncertain_command_effects);
}

#[test]
fn already_absent_jobs_and_domains_are_observations_without_bootout() {
    let (state, mut observer, mut runner) = fixtures(&[501]);
    observer.already_absent = true;
    let receipt = run(&mut observer, &mut runner, &mut || Ok(())).unwrap();
    assert!(receipt.complete);
    assert_eq!(receipt.already_absent_jobs.len(), 6);
    assert!(state.borrow().attempts.is_empty());
    assert!(receipt.completed_jobs.is_empty());
    assert!(receipt.bootout_succeeded.is_empty());
}

#[test]
fn unknown_inventory_and_unknown_job_refuse_before_effects_and_still_recheck_binding() {
    for inventory_error in [true, false] {
        let (state, mut observer, mut runner) = fixtures(&[]);
        observer.inventory_error = inventory_error;
        observer.unknown_for = Some("system/com.depot.auxiliary-stop.hydrate".into());
        let mut binding_calls = 0;
        let failure = run(&mut observer, &mut runner, &mut || {
            binding_calls += 1;
            Ok(())
        })
        .unwrap_err();
        assert!(!failure.receipt.complete);
        assert!(state.borrow().attempts.is_empty());
        assert!(binding_calls >= 3);
    }
}

#[test]
fn failed_command_retains_completed_prefix_and_does_not_spawn_post_observers() {
    let (state, mut observer, mut runner) = fixtures(&[]);
    runner.fail_at = Some(2);
    let failure = run(&mut observer, &mut runner, &mut || Ok(())).unwrap_err();
    assert!(failure.error.is("SYNTHETIC_OWNERSHIP_UNKNOWN"));
    assert_eq!(
        failure.receipt.completed_jobs,
        ["system/com.depot.auxiliary-stop.hydrate"]
    );
    assert_eq!(
        failure.receipt.bootout_succeeded,
        failure.receipt.completed_jobs
    );
    assert_eq!(
        failure.receipt.boundary_job.as_deref(),
        Some("system/com.depot.auxiliary-stop.gateway")
    );
    assert!(failure.receipt.uncertain_command_effects && !failure.receipt.complete);
    assert_eq!(state.borrow().attempts.len(), 2);
    // Two hydration observations and one gateway precheck; no post-error child.
    assert_eq!(state.borrow().queries.len(), 3);
}

#[test]
fn successful_command_with_failed_binding_retains_success_and_original_final_errors() {
    let (state, mut observer, mut runner) = fixtures(&[]);
    let binding_state = state.clone();
    let failure = run(&mut observer, &mut runner, &mut || {
        if !binding_state.borrow().attempts.is_empty() {
            fail!(ESTALE, "SYNTHETIC_BINDING_CHANGED");
        }
        Ok(())
    })
    .unwrap_err();
    assert!(failure.error.is("SYNTHETIC_BINDING_CHANGED"));
    assert!(failure
        .final_binding_error
        .unwrap()
        .is("SYNTHETIC_BINDING_CHANGED"));
    assert_eq!(
        failure.receipt.bootout_succeeded,
        ["system/com.depot.auxiliary-stop.hydrate"]
    );
    assert!(failure.receipt.completed_jobs.is_empty());
    assert!(failure.receipt.uncertain_command_effects);
    assert_eq!(state.borrow().queries.len(), 1);
}

#[test]
fn live_domain_change_after_bootout_retains_boundary_and_refuses_later_jobs() {
    let (state, mut observer, mut runner) = fixtures(&[501]);
    observer.changed_domains_after_stop = true;
    let failure = run(&mut observer, &mut runner, &mut || Ok(())).unwrap_err();
    assert!(failure.error.is("AUXILIARY_GUI_DOMAINS_CHANGED"));
    assert_eq!(failure.receipt.bootout_succeeded.len(), 1);
    assert!(failure.receipt.completed_jobs.is_empty());
    assert!(failure.receipt.uncertain_command_effects);
    assert_eq!(state.borrow().attempts.len(), 1);
}

#[test]
fn bootout_success_without_observed_absence_stays_uncertain() {
    let (state, mut observer, mut runner) = fixtures(&[]);
    observer.stays_loaded = true;
    let failure = run(&mut observer, &mut runner, &mut || Ok(())).unwrap_err();
    assert!(failure.error.is("AUXILIARY_JOB_STILL_LOADED"));
    assert_eq!(failure.receipt.bootout_succeeded.len(), 1);
    assert!(failure.receipt.completed_jobs.is_empty());
    assert!(failure.receipt.uncertain_command_effects);
    assert_eq!(state.borrow().attempts.len(), 1);
}

#[test]
fn expired_operation_refuses_before_any_observation_or_command_but_runs_final_binding() {
    let (state, mut observer, mut runner) = fixtures(&[]);
    let mut bindings = 0;
    let failure = operate(
        &target(DeploymentRole::DedicatedTest, Profile::L2),
        &"a".repeat(64),
        &mut observer,
        &mut runner,
        &mut || {
            bindings += 1;
            Ok(())
        },
        Instant::now(),
    )
    .unwrap_err();
    assert!(failure.error.is("AUXILIARY_STOP_TIMEOUT"));
    assert_eq!(observer.domain_calls, 0);
    assert_eq!(bindings, 1);
    assert!(state.borrow().attempts.is_empty());
}

#[test]
fn injected_unbounded_domain_sets_or_invalid_uid_cannot_reach_commands() {
    for uids in [vec![0], vec![u32::MAX], (500..565).collect()] {
        let (state, mut observer, mut runner) = fixtures(&uids);
        let failure = run(&mut observer, &mut runner, &mut || Ok(())).unwrap_err();
        assert!(failure.error.is("AUXILIARY_GUI_INVENTORY_INVALID"));
        assert!(state.borrow().attempts.is_empty());
    }
}

#[test]
fn later_unknown_job_preserves_confirmed_prefix_without_attempting_unknown_registration() {
    let (state, mut observer, mut runner) = fixtures(&[]);
    observer.unknown_for = Some("system/com.depot.auxiliary-stop.gateway".into());
    let failure = run(&mut observer, &mut runner, &mut || Ok(())).unwrap_err();
    assert!(failure.error.is("AUXILIARY_JOB_OBSERVATION_UNKNOWN"));
    assert_eq!(
        failure.receipt.completed_jobs,
        ["system/com.depot.auxiliary-stop.hydrate"]
    );
    assert_eq!(
        failure.receipt.bootout_succeeded,
        failure.receipt.completed_jobs
    );
    assert_eq!(state.borrow().attempts.len(), 1);
    assert!(!failure.receipt.uncertain_command_effects);
    assert_eq!(
        failure.receipt.boundary_job.as_deref(),
        Some("system/com.depot.auxiliary-stop.gateway")
    );
}

#[test]
fn final_binding_refusal_clears_complete_without_erasing_all_successful_effects() {
    let (state, mut observer, mut runner) = fixtures(&[]);
    // Count one completed injected run, then fail precisely its final check.
    let mut checks = 0;
    run(&mut observer, &mut runner, &mut || {
        checks += 1;
        Ok(())
    })
    .unwrap();
    let expected_checks = checks;
    let (_, mut observer, mut runner) = fixtures(&[]);
    let mut checks = 0;
    let failure = run(&mut observer, &mut runner, &mut || {
        checks += 1;
        if checks == expected_checks {
            fail!(ESTALE, "SYNTHETIC_FINAL_BINDING_CHANGED");
        }
        Ok(())
    })
    .unwrap_err();
    assert!(failure.error.is("SYNTHETIC_FINAL_BINDING_CHANGED"));
    assert_eq!(failure.receipt.completed_jobs, state.borrow().attempts);
    assert_eq!(failure.receipt.completed_jobs.len(), 4);
    assert_eq!(
        failure.receipt.bootout_succeeded,
        failure.receipt.completed_jobs
    );
    assert!(!failure.receipt.complete);
    assert!(!failure.receipt.uncertain_command_effects);
}
