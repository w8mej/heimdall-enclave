//! Injected launchctl fixtures. The four absence tuples below are exact outputs
//! of coordinator/native-absent-target-launchd-attempt1.stdout, SHA256
//! 536cabc60e7313801bbaa24047a63ffc633c4818a6617d5a496cf0970d62448a.
//! Loaded/inventory bodies are deliberately synthetic grammar fixtures; they
//! are not retained native process identity or complete inactivity evidence.
use super::*;
use enclave_core::{
    deployment::{DeploymentBroker, DeploymentLayout, DeploymentRole, DeploymentSigningMode},
    err,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    path::PathBuf,
};

const NAMESPACE: &str = "com.enterprise.enclave.yubikey-test";
const DESCRIPTOR_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn target(l3: bool) -> DeploymentTarget {
    let root = PathBuf::from("/activity-fixture/dedicated");
    let support = root.join("support");
    DeploymentTarget {
        version: 1,
        target_id: "activity-fixture".into(),
        role: DeploymentRole::DedicatedTest,
        profile: if l3 { Profile::L3 } else { Profile::L2 },
        authority_config: support.join("authority.json"),
        expected_artifacts_manifest: support.join("inventory.json"),
        codesign_pins_file: support.join("pins.json"),
        signing_identity_mode: DeploymentSigningMode::LocalPins,
        layout: DeploymentLayout {
            binary_dir: root.join("bin"),
            custody_bundle: support.join("Custody.app"),
            sandbox_dir: root.join("sandbox"),
            socket_root: root.join("run"),
            state_root: root.join("state"),
            audit_root: root.join("audit"),
            cas_store_root: root.join("cas"),
            staging_root: root.join("stage"),
            support_root: support.clone(),
            launchd_namespace: NAMESPACE.into(),
            mach_service: format!("{NAMESPACE}.exception"),
        },
        broker: l3.then(|| DeploymentBroker {
            base_dir: root.join("state/apfs-broker"),
            tuf_root_file: support.join("root.json"),
        }),
        shared_read_only_inputs: vec![],
    }
}
fn output(code: i32, out: &str, error: &str) -> NativeOutput {
    NativeOutput {
        code: Some(code),
        stdout: out.as_bytes().into(),
        stderr: error.as_bytes().into(),
        contract: Some(NativeContract::MacOs26_6_2),
    }
}
fn inventory(entries: &str) -> NativeOutput {
    output(
        0,
        &format!("system = {{\n subdomains = {{\n{entries}\n }}\n}}\n"),
        "",
    )
}
fn absent(query: &LaunchQuery) -> NativeOutput {
    let label = query.label.as_ref().unwrap();
    let domain = if query.domain == "system" {
        "system".into()
    } else {
        format!("user gui: {}", &query.domain[4..])
    };
    output(
        113,
        "",
        &format!("Bad request.\nCould not find service \"{label}\" in domain for {domain}\n"),
    )
}
fn absent_domain(query: &LaunchQuery) -> NativeOutput {
    output(
        112,
        "",
        &format!(
            "Bad request.\nCould not find domain for user gui: {}\n",
            &query.domain[4..]
        ),
    )
}
#[derive(Default)]
struct Guard {
    calls: usize,
    deny_at: Option<usize>,
}
impl MaintenanceExclusion for Guard {
    fn assert_held(&mut self) -> EnclaveResult<()> {
        self.calls += 1;
        if self.deny_at == Some(self.calls) {
            Err(err!(EACCES, "TEST_MAINTENANCE_NOT_HELD"))
        } else {
            Ok(())
        }
    }
}
struct Runner {
    inventories: VecDeque<Result<NativeOutput, CommandFailure>>,
    overrides: BTreeMap<String, Result<NativeOutput, CommandFailure>>,
    calls: Vec<String>,
}
impl Runner {
    fn new(entries: &str) -> Self {
        Self {
            inventories: VecDeque::from([Ok(inventory(entries)), Ok(inventory(entries))]),
            overrides: BTreeMap::new(),
            calls: Vec::new(),
        }
    }
}
impl ActivityRunner for Runner {
    fn print(
        &mut self,
        query: &LaunchQuery,
        deadline: Instant,
    ) -> Result<NativeOutput, CommandFailure> {
        assert!(query.allowed());
        assert!(deadline <= Instant::now() + COMMAND_LIMIT);
        self.calls.push(query.target());
        if query.label.is_none() {
            self.inventories.pop_front().unwrap()
        } else {
            self.overrides
                .get(&query.target())
                .cloned()
                .unwrap_or_else(|| Ok(absent(query)))
        }
    }
}

#[test]
fn exact_native_absence_tuples_bind_status_empty_stdout_label_domain_and_complete_error() {
    let fixtures=[
        ("system", "custody",113,"Bad request.\nCould not find service \"com.enterprise.enclave.yubikey-test.custody\" in domain for system\n",
         "09dbf9fa0672d61bbb7e160a9850ca991f8078c54d0c9aee91f42becd7d5605e",JobObservation::ObservedServiceAbsent),
        ("gui/501", "intent",113,"Bad request.\nCould not find service \"com.enterprise.enclave.yubikey-test.intent\" in domain for user gui: 501\n",
         "b4bfaaff6460b65cb9beb4b58269010d76b7ae8838ed728288c50a86ac6b35b2",JobObservation::ObservedServiceAbsent),
        ("gui/501", "oidc-broker",113,"Bad request.\nCould not find service \"com.enterprise.enclave.yubikey-test.oidc-broker\" in domain for user gui: 501\n",
         "2fbd6a0b17ca88fe46cab24f00f3e6d6ad76190427111084f9f287344f2f684c",JobObservation::ObservedServiceAbsent),
        ("gui/4294967294", "intent",112,"Bad request.\nCould not find domain for user gui: 4294967294\n",
         "b68e18e2670fcb817e0ebcb104c730e81eaa6311899811c96a8a42e777be9b94",JobObservation::ObservedGuiDomainAbsent),
    ];
    for (domain, suffix, code, error, hash, expected) in fixtures {
        let query = LaunchQuery::job(domain.into(), format!("{NAMESPACE}.{suffix}"));
        let value = output(code, "", error);
        assert_eq!(hex::encode(Sha256::digest(&value.stderr)), hash);
        assert_eq!(classify(&query, &value), expected);
        for bad in [
            output(1, "", error),
            output(0, "", error),
            output(code, "unexpected", error),
            output(code, "", &format!("{error}extra\n")),
            output(code, "", error.trim_end()),
            output(
                code,
                "",
                &error
                    .replace("user gui: 501", "user: 501")
                    .replace("domain for system", "domain for user gui: 501"),
            ),
        ] {
            // Last mutation is relevant only when it actually changes bytes.
            if bad.code == value.code && bad.stdout == value.stdout && bad.stderr == value.stderr {
                continue;
            }
            assert!(matches!(
                classify(&query, &bad),
                JobObservation::UnknownResponse
            ));
        }
        let mut unknown = value.clone();
        unknown.contract = None;
        assert_eq!(classify(&query, &unknown), JobObservation::UnknownPlatform);
    }
}

#[test]
fn installer_subdomain_grammar_includes_directory_and_noncurrent_users_without_local_lookup() {
    let value=inventory(" user/0 [0]\n user/55 [42]\n user/501 [100003]\n gui/502\n user/502 [999]\n user/4294967295");
    assert_eq!(
        gui_candidates(&value.stdout).unwrap(),
        BTreeSet::from([501, 502])
    );
    assert!(gui_candidates(&inventory("").stdout).unwrap().is_empty());
    for entries in [
        "external/501",
        "user/nope",
        "user/501 [x]",
        "user/501 [1] extra",
        "user/501/extra",
        "user/184467440737095516160",
        "user/501 [1 2]",
        "subdomains = {",
        "user/501\n nested = {",
    ] {
        assert!(gui_candidates(&inventory(entries).stdout).is_err());
    }
    for raw in [
        b"subdomains = {\n}\n".as_slice(),
        b"gui/501 = {\n subdomains = {\n}\n}\n",
        b"system = {\n no_subdomains = {\n}\n}\n",
        b"system = {\n subdomains = {\n user/501\n",
        b"system = {\n subdomains = {\n}\n subdomains = {\n}\n}\n",
        b"\xff",
    ] {
        assert!(gui_candidates(raw).is_err());
    }
    let too_many = (500..500 + MAX_GUI_DOMAINS + 1)
        .map(|uid| format!("user/{uid}"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(gui_candidates(&inventory(&too_many).stdout).is_err());
}

#[test]
fn all_fixed_l2_l3_system_jobs_and_both_agents_in_each_live_candidate_domain_are_observed() {
    for l3 in [false, true] {
        let mut runner = Runner::new("user/501 [1]\n user/502 [2]");
        let mut guard = Guard::default();
        let report = observe(&target(l3), DESCRIPTOR_HASH, &mut guard, &mut runner).unwrap();
        assert_eq!(report.jobs.len(), if l3 { 14 } else { 13 });
        assert_eq!(runner.calls.len(), report.jobs.len() + 2);
        assert_eq!(runner.calls.first().unwrap(), "system");
        assert_eq!(runner.calls.last().unwrap(), "system");
        for suffix in SYSTEM_SUFFIXES {
            assert!(report
                .jobs
                .iter()
                .any(|j| j.target == format!("system/{NAMESPACE}.{suffix}")));
        }
        assert_eq!(
            report
                .jobs
                .iter()
                .any(|j| j.target == format!("system/{NAMESPACE}.apfs-broker")),
            l3
        );
        for uid in [501, 502] {
            for suffix in AGENT_SUFFIXES {
                assert!(report
                    .jobs
                    .iter()
                    .any(|j| j.target == format!("gui/{uid}/{NAMESPACE}.{suffix}")));
            }
        }
        assert_eq!(
            report.selected_jobs_status,
            "OBSERVED_SELECTED_REGISTRATIONS_ABSENT_PROCESS_PROOF_UNKNOWN"
        );
        assert!(!report.inactivity_proven && !report.installation_supported && !report.qualified);
        assert!(report
            .process_instance_status
            .contains("SHARED_UID_CODE_IS_NOT_INSTANCE_AUTHORITY"));
        assert_eq!(guard.calls, report.jobs.len() + 3);
    }
}

#[test]
fn known_gui_domain_absence_is_distinct_and_disagreement_or_new_login_remains_unknown() {
    for mixed in [false, true] {
        let mut runner = Runner::new("user/501");
        for suffix in AGENT_SUFFIXES {
            let query = LaunchQuery::job("gui/501".into(), format!("{NAMESPACE}.{suffix}"));
            runner
                .overrides
                .insert(query.target(), Ok(absent_domain(&query)));
        }
        if mixed {
            let query = LaunchQuery::job("gui/501".into(), format!("{NAMESPACE}.intent"));
            runner.overrides.insert(query.target(), Ok(absent(&query)));
        }
        let report = observe(
            &target(false),
            DESCRIPTOR_HASH,
            &mut Guard::default(),
            &mut runner,
        )
        .unwrap();
        if mixed {
            assert_eq!(
                report.domain_inventory_status,
                "UNKNOWN_GUI_DOMAIN_CHANGED_DURING_OBSERVATION"
            );
            assert_eq!(
                report.selected_jobs_status,
                "UNKNOWN_INCOMPLETE_JOB_OBSERVATIONS"
            );
        } else {
            assert_eq!(
                report
                    .jobs
                    .iter()
                    .filter(|j| j.status == JobObservation::ObservedGuiDomainAbsent)
                    .count(),
                2
            );
        }
        assert!(!report.inactivity_proven);
    }
    let mut runner = Runner::new("user/501");
    runner.inventories[1] = Ok(inventory("user/501\n user/502"));
    let report = observe(
        &target(false),
        DESCRIPTOR_HASH,
        &mut Guard::default(),
        &mut runner,
    )
    .unwrap();
    assert_eq!(
        report.domain_inventory_status,
        "UNKNOWN_LIVE_DOMAIN_INVENTORY_CHANGED"
    );
    assert_eq!(
        report.selected_jobs_status,
        "UNKNOWN_INCOMPLETE_JOB_OBSERVATIONS"
    );
}

#[test]
fn loaded_job_has_no_pid_or_raw_body_export_and_wrong_domain_cannot_claim_loaded_or_absent() {
    for wrong_domain in [false, true] {
        let mut runner = Runner::new("user/501");
        let query = format!("gui/501/{NAMESPACE}.intent");
        let body = format!(
            "{} = {{\n pid = 123456789\n PRIVATE_ENV_SENTINEL = private\n}}\n",
            if wrong_domain {
                format!("user/501/{NAMESPACE}.intent")
            } else {
                query.clone()
            }
        );
        runner
            .overrides
            .insert(query.clone(), Ok(output(0, &body, "")));
        let report = observe(
            &target(false),
            DESCRIPTOR_HASH,
            &mut Guard::default(),
            &mut runner,
        )
        .unwrap();
        assert_eq!(
            report
                .jobs
                .iter()
                .find(|j| j.target == query)
                .unwrap()
                .status,
            if wrong_domain {
                JobObservation::UnknownResponse
            } else {
                JobObservation::ObservedLoaded
            }
        );
        assert_eq!(
            report.selected_jobs_status,
            if wrong_domain {
                "UNKNOWN_INCOMPLETE_JOB_OBSERVATIONS"
            } else {
                "OBSERVED_SELECTED_JOB_LOADED"
            }
        );
        let encoded = serde_json::to_string(&report).unwrap();
        assert!(
            !encoded.contains("123456789")
                && !encoded.contains("PRIVATE_ENV_SENTINEL")
                && !encoded.contains("private")
        );
        assert!(!report.inactivity_proven);
    }
}

#[test]
fn busy_unauthorized_unknown_status_language_signal_timeout_and_cap_are_not_absence() {
    let query = LaunchQuery::job("system".into(), format!("{NAMESPACE}.cas"));
    for response in [
        Err(CommandFailure::Unavailable),
        Err(CommandFailure::Timeout),
        Err(CommandFailure::OutputLimit),
        Err(CommandFailure::Io),
        Ok(output(16, "", "Resource busy\n")),
        Ok(output(1, "", "Operation not permitted\n")),
        Ok(output(113, "", "Could not find service\n")),
        Ok(output(113, "", "Requete incorrecte\n")),
        Ok(NativeOutput {
            code: None,
            ..absent(&query)
        }),
        Ok(NativeOutput {
            stdout: vec![b'x'; MAX_OUTPUT + 1],
            ..absent(&query)
        }),
    ] {
        let mut runner = Runner::new("user/501");
        runner.overrides.insert(query.target(), response);
        let report = observe(
            &target(false),
            DESCRIPTOR_HASH,
            &mut Guard::default(),
            &mut runner,
        )
        .unwrap();
        assert_eq!(
            report.selected_jobs_status,
            "UNKNOWN_INCOMPLETE_JOB_OBSERVATIONS"
        );
        assert!(!report.inactivity_proven);
    }
}

#[test]
fn failed_missing_malformed_or_stderr_inventory_keeps_unqueried_domains_unknown() {
    for response in [
        Err(CommandFailure::Unavailable),
        Err(CommandFailure::Timeout),
        Ok(output(1, "", "denied")),
        Ok(output(0, "system = {\n}\n", "")),
        Ok(output(0, "subdomains = {\n}\n", "")),
        Ok(output(
            0,
            "system = {\n subdomains = {\n external/501\n}\n}\n",
            "",
        )),
        Ok(NativeOutput {
            stderr: b"warning\n".to_vec(),
            ..inventory("user/501")
        }),
    ] {
        let mut runner = Runner::new("user/501");
        runner.inventories[0] = response;
        let report = observe(
            &target(false),
            DESCRIPTOR_HASH,
            &mut Guard::default(),
            &mut runner,
        )
        .unwrap();
        assert_eq!(
            report.domain_inventory_status,
            "UNKNOWN_LIVE_DOMAIN_INVENTORY"
        );
        assert_eq!(
            report.selected_jobs_status,
            "UNKNOWN_INCOMPLETE_JOB_OBSERVATIONS"
        );
        assert_eq!(report.jobs.len(), 9);
        assert!(!report.inactivity_proven);
        assert!(!runner.calls.iter().any(|c| c.starts_with("gui/")));
    }
}

#[test]
fn trusted_maintenance_exclusion_is_required_before_every_query_and_final_receipt() {
    for deny_at in [1, 2, 13, 14] {
        let mut runner = Runner::new("user/501");
        let mut guard = Guard {
            deny_at: Some(deny_at),
            ..Default::default()
        };
        assert!(
            observe(&target(false), DESCRIPTOR_HASH, &mut guard, &mut runner)
                .unwrap_err()
                .is("TEST_MAINTENANCE_NOT_HELD")
        );
        if deny_at == 1 {
            assert!(runner.calls.is_empty());
        }
    }
    let mut bad = target(false);
    bad.layout.launchd_namespace = "com.foreign/target".into();
    let mut runner = Runner::new("");
    assert!(observe(&bad, DESCRIPTOR_HASH, &mut Guard::default(), &mut runner).is_err());
    assert!(runner.calls.is_empty());
    assert!(observe(
        &target(false),
        "unbound",
        &mut Guard::default(),
        &mut runner
    )
    .is_err());
    assert!(runner.calls.is_empty());
}

#[test]
fn native_runner_query_construction_is_closed_to_print_system_and_fixed_target_jobs() {
    assert!(LaunchQuery::system().allowed());
    for (domain, label) in [
        ("system", format!("{NAMESPACE}.adapter")),
        ("gui/501", format!("{NAMESPACE}.intent")),
    ] {
        assert!(LaunchQuery::job(domain.into(), label).allowed());
    }
    for (domain, suffix) in [
        ("user/501", "intent"),
        ("gui/0", "intent"),
        ("gui/0501", "intent"),
        ("system", "intent"),
        ("gui/501", "cas"),
        ("system", "arbitrary"),
        ("system;bootout", "cas"),
        ("gui/4294967295", "intent"),
    ] {
        assert!(!LaunchQuery::job(domain.into(), format!("{NAMESPACE}.{suffix}")).allowed());
    }
    assert!(!LaunchQuery::job("system".into(), "com.test.custody;bootout".into()).allowed());
    #[cfg(not(target_os = "macos"))]
    {
        assert_eq!(
            NativeLaunchctlRunner
                .print(&LaunchQuery::system(), Instant::now() + COMMAND_LIMIT)
                .unwrap_err(),
            CommandFailure::Unavailable
        );
        // If the wrapper improperly falls back to the generic executor, this
        // harmless child would return an output with exit17, not Unavailable.
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 17"]);
        assert_eq!(
            run_owned_command(command, Instant::now() + COMMAND_LIMIT).unwrap_err(),
            CommandFailure::Unavailable
        );
    }
}

#[test]
fn checked_descriptor_rebind_brackets_complete_observation_and_drift_never_returns_receipt() {
    for deny_at in [Some(1), Some(2), None] {
        let mut runner = Runner::new("user/501");
        let mut calls = 0;
        let result = observe_rebound(
            &target(false),
            DESCRIPTOR_HASH,
            &mut Guard::default(),
            &mut runner,
            &mut || {
                calls += 1;
                if deny_at == Some(calls) {
                    Err(err!(ESTALE, "TEST_DESCRIPTOR_CHANGED"))
                } else {
                    Ok(())
                }
            },
        );
        if deny_at.is_some() {
            assert!(result.unwrap_err().is("TEST_DESCRIPTOR_CHANGED"));
        } else {
            assert!(!result.unwrap().inactivity_proven);
        }
        assert_eq!(calls, if deny_at == Some(1) { 1 } else { 2 });
        assert_eq!(runner.calls.is_empty(), deny_at == Some(1));
    }
}

#[test]
fn uncertain_observer_ownership_aborts_further_queries_without_an_activity_receipt() {
    for initial in [true, false] {
        let mut runner = Runner::new("user/501");
        if initial {
            runner.inventories[0] = Err(CommandFailure::OwnershipUnknown);
        } else {
            runner.overrides.insert(
                format!("system/{NAMESPACE}.adapter"),
                Err(CommandFailure::OwnershipUnknown),
            );
        }
        assert!(observe(
            &target(false),
            DESCRIPTOR_HASH,
            &mut Guard::default(),
            &mut runner
        )
        .unwrap_err()
        .is("UNKNOWN_ACTIVITY_OBSERVER_OWNERSHIP"));
        assert_eq!(runner.calls.len(), if initial { 1 } else { 2 });
    }
}

#[test]
fn narrow_inventory_helper_distinguishes_known_empty_from_unknown_or_unowned_observation() {
    assert!(
        observe_live_gui_candidates(&mut Runner::new(""), Instant::now() + OBSERVATION_LIMIT)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        observe_live_gui_candidates(
            &mut Runner::new("gui/502 [8]\nuser/501"),
            Instant::now() + OBSERVATION_LIMIT
        )
        .unwrap(),
        BTreeSet::from([501, 502])
    );
    let mut wrong_platform = inventory("");
    wrong_platform.contract = None;
    for observation in [
        Ok(output(0, "system = {\n}\n", "")),
        Ok(wrong_platform),
        Ok(output(1, "", "")),
        Err(CommandFailure::Timeout),
    ] {
        let mut runner = Runner::new("");
        runner.inventories = VecDeque::from([observation]);
        assert!(
            observe_live_gui_candidates(&mut runner, Instant::now() + OBSERVATION_LIMIT)
                .unwrap_err()
                .is("UNKNOWN_ACTIVITY_LIVE_GUI_INVENTORY")
        );
    }
    let mut runner = Runner::new("");
    runner.inventories = VecDeque::from([Err(CommandFailure::OwnershipUnknown)]);
    assert!(
        observe_live_gui_candidates(&mut runner, Instant::now() + OBSERVATION_LIMIT)
            .unwrap_err()
            .is("UNKNOWN_ACTIVITY_OBSERVER_OWNERSHIP")
    );
}

#[test]
fn narrow_job_helper_preserves_exact_absence_and_never_executes_invalid_queries() {
    let mut runner = Runner::new("");
    let until = Instant::now() + OBSERVATION_LIMIT;
    assert_eq!(
        observe_fixed_job(
            &mut runner,
            "system",
            &format!("{NAMESPACE}.hydrate"),
            until
        )
        .unwrap(),
        JobObservation::ObservedServiceAbsent
    );
    for (domain, label) in [
        ("user/501", format!("{NAMESPACE}.intent")),
        ("gui/0501", format!("{NAMESPACE}.intent")),
        ("system", format!("{NAMESPACE}.arbitrary")),
    ] {
        assert_eq!(
            observe_fixed_job(&mut runner, domain, &label, until).unwrap(),
            JobObservation::UnknownUnavailable
        );
    }
    assert_eq!(runner.calls.len(), 1);
    let label = format!("{NAMESPACE}.intent");
    let query = LaunchQuery::job("gui/501".into(), label.clone());
    runner
        .overrides
        .insert(query.target(), Ok(absent_domain(&query)));
    assert_eq!(
        observe_fixed_job(&mut runner, "gui/501", &label, until).unwrap(),
        JobObservation::ObservedGuiDomainAbsent
    );
    runner
        .overrides
        .insert(query.target(), Err(CommandFailure::OwnershipUnknown));
    assert!(observe_fixed_job(&mut runner, "gui/501", &label, until)
        .unwrap_err()
        .is("UNKNOWN_ACTIVITY_OBSERVER_OWNERSHIP"));
}

#[test]
fn shared_command_adapter_preserves_raw_bytes_status_contract_and_redacted_failures() {
    for code in [Some(0), Some(17), None] {
        for contract in [None, Some(NativeContract::MacOs26_6_2)] {
            let stdout = b"PRIVATE_STDOUT_SENTINEL\0\xff".to_vec();
            let stderr = b"PRIVATE_STDERR_SENTINEL\0\xfe".to_vec();
            let output = native_command::CommandOutput {
                code,
                stdout: stdout.clone(),
                stderr: stderr.clone(),
            };
            let debug = format!("{output:?}");
            assert!(
                !debug.contains("PRIVATE_STDOUT_SENTINEL")
                    && !debug.contains("PRIVATE_STDERR_SENTINEL")
            );
            let adapted = command_output(Ok(output), contract).unwrap();
            assert_eq!(adapted.code, code);
            assert_eq!(adapted.stdout, stdout);
            assert_eq!(adapted.stderr, stderr);
            assert_eq!(adapted.contract, contract);
            let debug = format!("{adapted:?}");
            assert!(
                !debug.contains("PRIVATE_STDOUT_SENTINEL")
                    && !debug.contains("PRIVATE_STDERR_SENTINEL")
            );
        }
    }
    for failure in [
        CommandFailure::Unavailable,
        CommandFailure::Timeout,
        CommandFailure::OutputLimit,
        CommandFailure::Io,
        CommandFailure::OwnershipUnknown,
    ] {
        assert_eq!(
            command_output(Err(failure), Some(NativeContract::MacOs26_6_2)).unwrap_err(),
            failure
        );
    }
}
