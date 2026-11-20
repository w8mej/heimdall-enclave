//! SOFTWARE fixtures only. No test invokes pfctl, the global PF configuration,
//! the old watcher, a deployment selection or any PF mutation. Root owns runs.
use super::*;
use std::{
    cell::{Cell, RefCell},
    os::unix::fs::{symlink, PermissionsExt},
    rc::Rc,
};

struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let parent = std::env::current_dir().unwrap().join("target");
        std::fs::create_dir_all(&parent).unwrap();
        let root = parent.join(format!(
            "pf-observation-{}",
            hex::encode(crate::rng::bytes32())
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(root.join("inputs")).unwrap();
        std::fs::set_permissions(root.join("inputs"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let fixture = Self { root };
        for (role, bytes) in [
            (Role::Descriptor, b"software descriptor".as_slice()),
            (Role::RootPolicy, pf_restore_input::render_root_filter()),
            (Role::LlmPolicy, LLM_POLICY),
            (Role::CasPolicy, CAS_POLICY),
            (Role::NativeTool, b"software pfctl"),
        ] {
            std::fs::write(fixture.path(role), bytes).unwrap();
            std::fs::set_permissions(
                fixture.path(role),
                std::fs::Permissions::from_mode(if role == Role::NativeTool {
                    0o555
                } else {
                    0o644
                }),
            )
            .unwrap();
        }
        fixture
    }
    fn path(&self, role: Role) -> PathBuf {
        self.root.join("inputs").join(match role {
            Role::Descriptor => "descriptor.json",
            Role::RootPolicy => "pf.conf",
            Role::LlmPolicy => "llm.pf",
            Role::CasPolicy => "cas.pf",
            Role::NativeTool => "pfctl",
        })
    }
    fn protection(&self) -> Protection {
        Protection::Fixture {
            uid: unsafe { libc::geteuid() },
            root: self.root.clone(),
        }
    }
    fn specs(&self) -> Vec<InputSpec> {
        vec![
            InputSpec {
                role: Role::Descriptor,
                path: self.path(Role::Descriptor),
                maximum: deployment::MAX_DESCRIPTOR_BYTES,
                expected: Expected::Descriptor(hex::encode(digest(b"software descriptor"))),
            },
            InputSpec {
                role: Role::RootPolicy,
                path: self.path(Role::RootPolicy),
                maximum: MAX_OUTPUT,
                expected: Expected::RootPolicy,
            },
            InputSpec {
                role: Role::LlmPolicy,
                path: self.path(Role::LlmPolicy),
                maximum: MAX_OUTPUT,
                expected: Expected::Canonical(LLM_POLICY),
            },
            InputSpec {
                role: Role::CasPolicy,
                path: self.path(Role::CasPolicy),
                maximum: MAX_OUTPUT,
                expected: Expected::Canonical(CAS_POLICY),
            },
            InputSpec {
                role: Role::NativeTool,
                path: self.path(Role::NativeTool),
                maximum: MAX_OUTPUT,
                expected: Expected::Canonical(b"software pfctl"),
            },
        ]
    }
    fn producer(
        &self,
        query: impl FnMut(Query, Instant) -> Result<CommandOutput, CommandFailure> + 'static,
    ) -> Producer {
        let mut producer = Producer::empty();
        producer.observation.retained_context = Some(Context::Fixture(Box::new(|| Ok(()))));
        producer.fixture_query = Some(Box::new(query));
        let errors = producer
            .observation
            .originals
            .open(self.specs(), self.protection(), until());
        producer.retain_errors(errors);
        producer
    }
    fn observe(&self) -> Observation {
        let mut producer =
            self.producer(|_, _| Ok(output(b"fixture stdout", b"fixture stderr", Some(0))));
        let deadline = until();
        if producer.observation.primary_refusal.is_none() {
            producer.collect(deadline);
        }
        producer.finish(deadline)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn until() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn output(stdout: &[u8], stderr: &[u8], code: Option<i32>) -> CommandOutput {
    CommandOutput {
        code,
        stdout: stdout.to_vec(),
        stderr: stderr.to_vec(),
    }
}
fn assert_no_readiness(observed: &Observation) {
    assert_eq!(observed.native_schema, Knowledge::Unknown);
    assert_eq!(observed.pf_enabled, Knowledge::Unknown);
    assert_eq!(observed.root_rule_interpretation, Knowledge::Unknown);
    assert_eq!(observed.llm_compiled_live_comparison, Knowledge::Unknown);
    assert_eq!(observed.cas_compiled_live_comparison, Knowledge::Unknown);
    assert_eq!(observed.interface_skip_policy, Knowledge::Unknown);
    assert_eq!(observed.translation_policy, Knowledge::Unknown);
    assert_eq!(observed.preexisting_state_policy, Knowledge::Unknown);
    assert_eq!(observed.preexisting_state_count, None);
    assert_eq!(observed.root_translation_output, None);
    assert_eq!(observed.mandatory_watcher, Knowledge::NotObserved);
    assert_eq!(observed.atomic_restoration, Knowledge::NotObserved);
    assert!(!observed.required_enforcement_established());
    assert!(!observed.first_begin_prerequisites_met());
}

// The compiler goldens are exact captured native no-load output. Info/root and
// compile-derived live forms are SOFTWARE examples. This fixture executor does
// not run pfctl or establish a supported native tool/kernel observation.
fn component_bytes(query: Query) -> &'static [u8] {
    match query {
        Query::Info => b"Status: Enabled for 0 days 00:00:00 Debug: Urgent\nState Table Total Rate\ncurrent entries 0\nCounters\nmatch 0 0.0/s\n",
        Query::RootRules => b"anchor \"com.enterprise.llm.isolation\" all\nanchor \"com.enterprise.cas.swarm\" all\n",
        Query::LlmRules => native_schema::OBSERVED_LLM_RULES.as_bytes(),
        Query::CasRules => native_schema::OBSERVED_CAS_RULES.as_bytes(),
        Query::CompileLlm => native_schema::OBSERVED_LLM_COMPILE.as_bytes(),
        Query::CompileCas => native_schema::OBSERVED_CAS_COMPILE.as_bytes(),
        Query::RootTranslations => b"",
    }
}

fn component_stderr(query: Query) -> &'static [u8] {
    if matches!(query, Query::CompileLlm | Query::CompileCas) {
        native_schema::COMPILE_ADVISORY
    } else {
        b""
    }
}

#[test]
fn software_stream_components_are_parsed_in_actual_collection_path_without_effective_enforcement() {
    let fixture = Fixture::new();
    let mut producer = fixture.producer(|query, _| {
        Ok(output(
            component_bytes(query),
            component_stderr(query),
            Some(0),
        ))
    });
    producer.components = Some(native_schema::Components::new(
        native_schema::fixture_schema(),
    ));
    let deadline = until();
    producer.collect(deadline);
    let observed = producer.finish(deadline);
    assert!(observed.collection_complete && observed.protected_inputs_current);
    for component in [
        observed.native_schema,
        observed.pf_enabled,
        observed.root_rule_interpretation,
        observed.llm_compiled_live_comparison,
        observed.cas_compiled_live_comparison,
    ] {
        assert_eq!(component, Knowledge::Established);
    }
    for unobserved in [
        observed.interface_skip_policy,
        observed.translation_policy,
        observed.preexisting_state_policy,
    ] {
        assert_eq!(unobserved, Knowledge::Unknown);
    }
    assert_eq!(
        observed.preexisting_state_count,
        Some(native_schema::StateCount::ZeroAtSnapshot)
    );
    assert_eq!(observed.mandatory_watcher, Knowledge::NotObserved);
    assert_eq!(observed.atomic_restoration, Knowledge::NotObserved);
    assert!(
        !observed.required_enforcement_established() && !observed.first_begin_prerequisites_met()
    );
}

#[test]
fn actual_collection_retains_state_count_snapshot_without_any_state_policy_or_readiness_authority()
{
    for count in [0, 7, u64::MAX] {
        let fixture = Fixture::new();
        let mut producer = fixture.producer(move |query, _| {
            let bytes = if query == Query::Info {
                String::from_utf8(component_bytes(query).to_vec())
                    .unwrap()
                    .replace("current entries 0", &format!("current entries {count}"))
                    .into_bytes()
            } else {
                component_bytes(query).to_vec()
            };
            Ok(output(&bytes, component_stderr(query), Some(0)))
        });
        producer.components = Some(native_schema::Components::new(
            native_schema::fixture_schema(),
        ));
        let deadline = until();
        producer.collect(deadline);
        let observed = producer.finish(deadline);
        assert!(observed.collection_complete && observed.protected_inputs_current);
        assert_eq!(
            observed.preexisting_state_count,
            Some(if count == 0 {
                native_schema::StateCount::ZeroAtSnapshot
            } else {
                native_schema::StateCount::NonzeroAtSnapshot(count)
            })
        );
        assert_eq!(observed.preexisting_state_policy, Knowledge::Unknown);
        assert_eq!(observed.interface_skip_policy, Knowledge::Unknown);
        assert_eq!(observed.translation_policy, Knowledge::Unknown);
        assert!(
            !observed.required_enforcement_established()
                && !observed.first_begin_prerequisites_met()
        );
    }
}

#[test]
fn malformed_info_count_stops_actual_collection_without_publishing_partial_status() {
    for replacement in [
        "current entries 0\ncurrent entries 1",
        "current entries 18446744073709551616",
        "current entries NaN",
    ] {
        let fixture = Fixture::new();
        let mut producer = fixture.producer(move |query, _| {
            assert_eq!(
                query,
                Query::Info,
                "a refused Info must prevent all later queries"
            );
            let bytes = String::from_utf8(component_bytes(query).to_vec())
                .unwrap()
                .replace("current entries 0", replacement);
            Ok(output(bytes.as_bytes(), b"", Some(0)))
        });
        producer.components = Some(native_schema::Components::new(
            native_schema::fixture_schema(),
        ));
        let deadline = until();
        producer.collect(deadline);
        let observed = producer.finish(deadline);
        assert_eq!(observed.queries.len(), 1);
        assert!(matches!(
            observed.primary_refusal.unwrap().reason,
            Reason::NativeSchema(_)
        ));
        assert_no_readiness(&observed);
    }
}

#[test]
fn valid_info_count_never_hides_later_independent_query_failure() {
    for count in [0, 7] {
        let fixture = Fixture::new();
        let mut producer = fixture.producer(move |query, _| {
            let bytes = String::from_utf8(component_bytes(query).to_vec())
                .unwrap()
                .replace("current entries 0", &format!("current entries {count}"));
            Ok(output(
                bytes.as_bytes(),
                component_stderr(query),
                Some(if query == Query::CasRules { 1 } else { 0 }),
            ))
        });
        producer.components = Some(native_schema::Components::new(
            native_schema::fixture_schema(),
        ));
        let deadline = until();
        producer.collect(deadline);
        assert_eq!(
            producer.components.as_ref().unwrap().state_count(),
            Some(if count == 0 {
                native_schema::StateCount::ZeroAtSnapshot
            } else {
                native_schema::StateCount::NonzeroAtSnapshot(count)
            })
        );
        let observed = producer.finish(deadline);
        assert_eq!(observed.queries.len(), 4);
        assert_eq!(observed.primary_refusal.unwrap().reason, Reason::QueryExit);
        assert_no_readiness(&observed);
    }
}

#[test]
fn supported_component_parser_refuses_every_unknown_stream_before_further_queries() {
    for bad_query in Query::ALL {
        let fixture = Fixture::new();
        let calls = Rc::new(Cell::new(0));
        let seen = calls.clone();
        let mut producer = fixture.producer(move |query, _| {
            seen.set(seen.get() + 1);
            Ok(output(
                if query == bad_query {
                    b"unrecognized native output\n"
                } else {
                    component_bytes(query)
                },
                component_stderr(query),
                Some(0),
            ))
        });
        producer.components = Some(native_schema::Components::new(
            native_schema::fixture_schema(),
        ));
        let deadline = until();
        producer.collect(deadline);
        let observed = producer.finish(deadline);
        assert!(!observed.collection_complete);
        assert_no_readiness(&observed);
        assert_eq!(
            calls.get(),
            Query::ALL
                .iter()
                .position(|query| *query == bad_query)
                .unwrap()
                + 1
        );
        assert!(matches!(
            observed.primary_refusal.unwrap().reason,
            Reason::NativeSchema(_)
        ));
    }
}

#[test]
fn one_good_anchor_never_hides_the_other_independent_comparison_failure() {
    for bad in [Query::CompileLlm, Query::CompileCas] {
        let fixture = Fixture::new();
        let mut producer = fixture.producer(move |query, _| {
            let mut bytes = component_bytes(query).to_vec();
            if query == bad {
                bytes.extend_from_slice(if bad == Query::CompileLlm {
                    native_schema::OBSERVED_LLM_RULES.as_bytes()
                } else {
                    native_schema::OBSERVED_CAS_RULES.as_bytes()
                });
            }
            Ok(output(&bytes, component_stderr(query), Some(0)))
        });
        producer.components = Some(native_schema::Components::new(
            native_schema::fixture_schema(),
        ));
        let deadline = until();
        producer.collect(deadline);
        let observed = producer.finish(deadline);
        assert!(matches!(
            observed.primary_refusal.unwrap().reason,
            Reason::NativeSchema(native_schema::Error::CanonicalMismatch)
        ));
        assert_no_readiness(&observed);
    }
}

#[test]
fn successful_component_parsing_is_invalidated_by_final_actual_original_or_context_loss() {
    let fixture = Fixture::new();
    let valid = Rc::new(Cell::new(true));
    let checked = valid.clone();
    let mut producer = fixture.producer(|query, _| {
        Ok(output(
            component_bytes(query),
            component_stderr(query),
            Some(0),
        ))
    });
    producer.observation.retained_context = Some(Context::Fixture(Box::new(move || {
        if checked.get() {
            Ok(())
        } else {
            Err(crate::err!(ESTALE, "FIXTURE_CONTEXT_CHANGED"))
        }
    })));
    producer.components = Some(native_schema::Components::new(
        native_schema::fixture_schema(),
    ));
    let deadline = until();
    producer.collect(deadline);
    assert_eq!(
        producer.components.as_ref().unwrap().state_count(),
        Some(native_schema::StateCount::ZeroAtSnapshot)
    );
    valid.set(false);
    std::fs::rename(
        fixture.path(Role::NativeTool),
        fixture.root.join("original-pfctl"),
    )
    .unwrap();
    std::fs::write(fixture.path(Role::NativeTool), b"software pfctl").unwrap();
    std::fs::set_permissions(
        fixture.path(Role::NativeTool),
        std::fs::Permissions::from_mode(0o555),
    )
    .unwrap();
    let observed = producer.finish(deadline);
    assert!(has_error(&observed, Role::NativeTool, Reason::InputChanged));
    assert!(observed
        .final_refusals
        .iter()
        .any(|error| error.reason == Reason::ContextChanged));
    assert_no_readiness(&observed);
}

#[test]
fn native_tool_original_requires_fixed_read_only_mode_and_is_never_repaired() {
    for mode in [0o444, 0o644, 0o755, 0o575, 0o777] {
        let fixture = Fixture::new();
        std::fs::set_permissions(
            fixture.path(Role::NativeTool),
            std::fs::Permissions::from_mode(mode),
        )
        .unwrap();
        let observed = fixture.observe();
        assert!(has_error(
            &observed,
            Role::NativeTool,
            Reason::InputProtection
        ));
        assert!(observed.queries.is_empty());
        assert_eq!(
            std::fs::metadata(fixture.path(Role::NativeTool))
                .unwrap()
                .mode()
                & 0o7777,
            mode
        );
    }
}

#[test]
fn unsupported_actual_tool_bytes_cannot_create_the_pinned_native_schema() {
    let fixture = Fixture::new();
    let mut specs = fixture.specs();
    let tool = specs
        .iter_mut()
        .find(|spec| spec.role == Role::NativeTool)
        .unwrap();
    tool.expected = Expected::NativeTool;
    let mut originals = Originals { routes: Vec::new() };
    let errors = originals.open(specs, fixture.protection(), until());
    assert!(errors
        .iter()
        .any(|error| error.role == Some(Role::NativeTool)
            && error.reason == Reason::NativeSchema(native_schema::Error::UnsupportedTool)));
    let held = originals
        .routes
        .iter()
        .find(|route| route.spec.role == Role::NativeTool)
        .unwrap();
    assert!(!held.admitted && !held.nodes.is_empty());
}
fn route(observed: &Observation, role: Role) -> &HeldRoute {
    observed
        .originals
        .routes
        .iter()
        .find(|route| route.spec.role == role)
        .unwrap()
}
fn has_error(observed: &Observation, role: Role, reason: Reason) -> bool {
    observed
        .boundary_refusals
        .iter()
        .chain(observed.final_refusals.iter())
        .any(|error| error.role == Some(role) && error.reason == reason)
}

#[test]
fn closed_queries_have_exact_absolute_read_only_commands_and_scrubbed_environment() {
    let expected: [&[&str]; 7] = [
        &["-s", "info"],
        &["-sr"],
        &["-a", "com.enterprise.llm.isolation", "-sr"],
        &["-a", "com.enterprise.cas.swarm", "-sr"],
        &[
            "-nvf",
            "/private/etc/pf.anchors/com.enterprise.llm.isolation",
        ],
        &["-nvf", "/private/etc/pf.anchors/com.enterprise.cas.swarm"],
        &["-s", "nat"],
    ];
    for (query, expected) in Query::ALL.into_iter().zip(expected) {
        let command = query.command();
        assert_eq!(command.get_program(), "/sbin/pfctl");
        assert_eq!(command.get_current_dir(), Some(Path::new("/")));
        assert_eq!(command.get_args().collect::<Vec<_>>(), expected);
        let environment = command
            .get_envs()
            .map(|(key, value)| (key.to_str().unwrap(), value.unwrap().to_str().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(environment, vec![("LC_ALL", "C"), ("PATH", SAFE_PATH)]);
        assert!(
            format!("{command:?}").contains("env -i"),
            "command must clear inherited environment"
        );
        assert!(expected
            .iter()
            .all(|argument| !["-f", "-F", "-E", "-e", "-d"].contains(argument)));
        if matches!(query, Query::CompileLlm | Query::CompileCas) {
            assert_eq!(expected[0], "-nvf");
        }
    }
}

#[test]
fn foreign_or_nonroot_production_admission_refuses_without_a_query() {
    // A Darwin/root test NEVER calls the production observer, even when another
    // test happens to have selected a context in the shared test process.
    if !cfg!(target_os = "macos") || unsafe { libc::geteuid() } != 0 {
        let observed = observe_selected(until());
        assert!(observed.queries.is_empty());
        let expected = if cfg!(target_os = "macos") {
            Reason::RootRequired
        } else {
            Reason::NativeRequired
        };
        assert_eq!(observed.primary_refusal.unwrap().reason, expected);
        assert_no_readiness(&observed);
    } else {
        assert_eq!(native_root(), Ok(()));
    }
}

#[test]
fn missing_context_blocks_collection_even_with_real_originals_and_a_fixture_query() {
    let fixture = Fixture::new();
    let mut producer =
        fixture.producer(|_, _| panic!("missing context must not reach even a fixture query"));
    producer.observation.retained_context = None;
    let deadline = until();
    producer.collect(deadline);
    let observed = producer.finish(deadline);
    assert!(observed.queries.is_empty());
    assert_eq!(
        observed.primary_refusal.unwrap().reason,
        Reason::SelectionRequired
    );
    assert_no_readiness(&observed);
}

#[test]
fn supported_scope_cannot_widen_to_other_roles_profiles_signing_broker_or_shared_inputs() {
    use deployment::{DeploymentBroker, DeploymentLayout, DeploymentTarget};
    let fixture = Fixture::new();
    let root = &fixture.root;
    // Inert public schema only: no protected loader, selection or real native
    // context is constructed by this predicate test.
    let baseline = DeploymentTarget {
        version: 1,
        target_id: "pf-fixture".into(),
        role: DeploymentRole::DedicatedTest,
        profile: Profile::L2,
        authority_config: root.join("support/authority.json"),
        expected_artifacts_manifest: root.join("support/artifacts.json"),
        codesign_pins_file: root.join("support/pins.json"),
        signing_identity_mode: DeploymentSigningMode::LocalPins,
        layout: DeploymentLayout {
            binary_dir: root.join("bin"),
            custody_bundle: root.join("support/Custody.app"),
            sandbox_dir: root.join("sandbox"),
            socket_root: root.join("run"),
            state_root: root.join("state"),
            audit_root: root.join("audit"),
            cas_store_root: root.join("cas"),
            staging_root: root.join("stage"),
            support_root: root.join("support"),
            launchd_namespace: "com.enterprise.pf.fixture".into(),
            mach_service: "com.enterprise.pf.fixture.exception".into(),
        },
        broker: None,
        shared_read_only_inputs: Vec::new(),
    };
    baseline.validate().unwrap();
    if crate::codesign::signing_mode() == crate::codesign::SigningMode::LocalPins {
        assert_eq!(target_scope(&baseline), Ok(()));
    } else {
        assert_eq!(target_scope(&baseline), Err(Reason::UnsupportedScope));
    }
    for variant in 0..7 {
        let mut target = baseline.clone();
        match variant {
            0 => target.role = DeploymentRole::ExistingUpgrade,
            1 => target.profile = Profile::L1,
            2 => target.profile = Profile::L3,
            3 => target.signing_identity_mode = DeploymentSigningMode::TeamId,
            4 => {
                target.broker = Some(DeploymentBroker {
                    base_dir: root.join("state/apfs-broker"),
                    tuf_root_file: root.join("support/tuf.json"),
                })
            }
            5 => target
                .shared_read_only_inputs
                .push(target.authority_config.clone()),
            _ => {
                target.profile = Profile::L3;
                target.broker = Some(DeploymentBroker {
                    base_dir: root.join("state/apfs-broker"),
                    tuf_root_file: root.join("support/tuf.json"),
                });
            }
        }
        assert_eq!(target_scope(&target), Err(Reason::UnsupportedScope));
    }
}

#[test]
fn real_held_fixture_originals_are_read_only_and_complete_collection_never_grants_readiness() {
    let fixture = Fixture::new();
    let before = fixture
        .specs()
        .into_iter()
        .map(|spec| {
            let metadata = std::fs::metadata(&spec.path).unwrap();
            (spec.path, Stamp::of(&metadata, true))
        })
        .collect::<Vec<_>>();
    let observed = fixture.observe();
    assert!(observed.collection_complete);
    assert!(observed.protected_inputs_current);
    assert_eq!(observed.queries.len(), Query::ALL.len());
    assert_eq!(observed.originals.routes.len(), 5);
    for held in &observed.originals.routes {
        assert!(held.admitted);
        assert!(held.current(until()).is_empty());
        for node in &held.nodes {
            held.protection.descriptor(&node.file).unwrap();
        }
    }
    for (path, expected) in before {
        assert!(
            Stamp::of(&std::fs::metadata(path).unwrap(), true) == expected,
            "observer changed original metadata"
        );
    }
    assert!(observed.ended_boot_ns >= observed.started_boot_ns);
    assert_no_readiness(&observed);
}

#[test]
fn each_anchor_must_match_its_complete_independent_canonical_asset() {
    for bad in [Role::LlmPolicy, Role::CasPolicy] {
        let fixture = Fixture::new();
        let mut bytes = std::fs::read(fixture.path(bad)).unwrap();
        bytes.extend_from_slice(b"\n# changed\n");
        std::fs::write(fixture.path(bad), &bytes).unwrap();
        let observed = fixture.observe();
        assert!(has_error(&observed, bad, Reason::CanonicalMismatch));
        assert!(observed.queries.is_empty());
        assert!(!route(&observed, bad).admitted);
        let good = if bad == Role::LlmPolicy {
            Role::CasPolicy
        } else {
            Role::LlmPolicy
        };
        assert!(route(&observed, good).admitted);
        assert_eq!(std::fs::read(fixture.path(bad)).unwrap(), bytes);
        assert_no_readiness(&observed);
    }
}

#[test]
fn missing_inputs_retain_other_originals_without_creation_or_queries() {
    let fixture = Fixture::new();
    std::fs::remove_file(fixture.path(Role::LlmPolicy)).unwrap();
    std::fs::remove_file(fixture.path(Role::CasPolicy)).unwrap();
    let observed = fixture.observe();
    assert!(observed.queries.is_empty());
    assert_eq!(observed.originals.routes.len(), 5);
    for role in [Role::LlmPolicy, Role::CasPolicy] {
        assert!(has_error(&observed, role, Reason::InputMetadata));
        assert!(!fixture.path(role).exists());
        assert!(!route(&observed, role).nodes.is_empty());
    }
    assert!(route(&observed, Role::Descriptor).admitted);
    assert!(route(&observed, Role::RootPolicy).admitted);
}

#[test]
fn fixed_pf_file_modes_refuse_without_permission_repair_but_descriptor_keeps_its_existing_contract()
{
    for mode in [0o600, 0o640, 0o664, 0o666, 0o4755] {
        let fixture = Fixture::new();
        std::fs::set_permissions(
            fixture.path(Role::LlmPolicy),
            std::fs::Permissions::from_mode(mode),
        )
        .unwrap();
        let observed = fixture.observe();
        assert!(has_error(
            &observed,
            Role::LlmPolicy,
            Reason::InputProtection
        ));
        assert_eq!(
            std::fs::metadata(fixture.path(Role::LlmPolicy))
                .unwrap()
                .mode()
                & 0o7777,
            mode
        );
        assert!(observed.queries.is_empty());
    }
    let fixture = Fixture::new();
    std::fs::set_permissions(
        fixture.path(Role::Descriptor),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(fixture.observe().collection_complete);
}

#[test]
fn wrong_actual_owner_and_writable_fixture_ancestor_refuse_without_repair() {
    let fixture = Fixture::new();
    let protection = Protection::Fixture {
        uid: unsafe { libc::geteuid() }.wrapping_add(1),
        root: fixture.root.clone(),
    };
    let mut originals = Originals { routes: Vec::new() };
    let errors = originals.open(fixture.specs(), protection, until());
    assert_eq!(errors.len(), 5);
    assert!(errors
        .iter()
        .all(|error| error.reason == Reason::InputProtection));
    assert!(originals.routes.iter().all(|route| route.nodes.len() == 1));
    let parent = fixture.root.join("inputs");
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
    let observed = fixture.observe();
    assert!(observed.queries.is_empty());
    assert_eq!(std::fs::metadata(parent).unwrap().mode() & 0o7777, 0o777);
    assert!(observed
        .boundary_refusals
        .iter()
        .all(|error| error.reason == Reason::InputProtection));
}

#[test]
fn symlink_leaf_parent_and_alias_spellings_are_never_followed_or_repaired() {
    for parent_alias in [false, true] {
        let fixture = Fixture::new();
        if parent_alias {
            std::fs::rename(
                fixture.root.join("inputs"),
                fixture.root.join("original-inputs"),
            )
            .unwrap();
            symlink("original-inputs", fixture.root.join("inputs")).unwrap();
        } else {
            std::fs::rename(
                fixture.path(Role::LlmPolicy),
                fixture.root.join("original-llm"),
            )
            .unwrap();
            symlink("../original-llm", fixture.path(Role::LlmPolicy)).unwrap();
        }
        let observed = fixture.observe();
        assert!(observed.queries.is_empty());
        assert!(has_error(&observed, Role::LlmPolicy, Reason::InputType));
        let link = if parent_alias {
            fixture.root.join("inputs")
        } else {
            fixture.path(Role::LlmPolicy)
        };
        assert!(std::fs::symlink_metadata(link)
            .unwrap()
            .file_type()
            .is_symlink());
        let original = if parent_alias {
            fixture.root.join("original-inputs/llm.pf")
        } else {
            fixture.root.join("original-llm")
        };
        assert_eq!(std::fs::read(original).unwrap(), LLM_POLICY);
    }
    for path in [
        "/etc/../etc/pf.conf",
        "/etc//pf.conf",
        "/ETC/pf.conf",
        "/etc/./pf.conf",
    ] {
        assert!(deployment::normalized_path(Path::new(path)).is_err());
    }
    assert_eq!(
        deployment::normalized_path(Path::new("/etc/pf.conf")).unwrap(),
        Path::new("/private/etc/pf.conf")
    );
}

#[test]
fn fifo_directory_and_hardlinked_leaves_refuse_without_opening_special_objects_or_repair() {
    for kind in ["fifo", "directory", "hardlink"] {
        let fixture = Fixture::new();
        let path = fixture.path(Role::CasPolicy);
        std::fs::remove_file(&path).unwrap();
        match kind {
            "fifo" => {
                let name = CString::new(path.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o644) }, 0);
            }
            "directory" => std::fs::create_dir(&path).unwrap(),
            _ => std::fs::hard_link(fixture.path(Role::LlmPolicy), &path).unwrap(),
        }
        let before = std::fs::symlink_metadata(&path).unwrap();
        let observed = fixture.observe();
        assert!(observed.queries.is_empty());
        assert!(has_error(
            &observed,
            Role::CasPolicy,
            if kind == "hardlink" {
                Reason::InputLinks
            } else {
                Reason::InputType
            }
        ));
        let after = std::fs::symlink_metadata(&path).unwrap();
        assert_eq!(
            (before.dev(), before.ino(), before.mode(), before.nlink()),
            (after.dev(), after.ino(), after.mode(), after.nlink())
        );
        if kind != "hardlink" {
            assert_eq!(route(&observed, Role::CasPolicy).nodes.len(), 2);
        }
    }
}

#[test]
fn empty_and_oversize_originals_refuse_without_reading_unbounded_data() {
    for length in [0, MAX_OUTPUT + 1] {
        let fixture = Fixture::new();
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(fixture.path(Role::RootPolicy))
            .unwrap();
        file.set_len(length as u64).unwrap();
        let observed = fixture.observe();
        assert!(has_error(&observed, Role::RootPolicy, Reason::InputSize));
        assert!(observed.queries.is_empty());
        assert_eq!(file.metadata().unwrap().len(), length as u64);
        assert_eq!(route(&observed, Role::RootPolicy).content_digest, None);
    }
}

#[test]
fn protected_descriptor_hash_is_bound_independently_of_canonical_pf_assets() {
    let fixture = Fixture::new();
    std::fs::write(
        fixture.path(Role::Descriptor),
        b"different protected descriptor",
    )
    .unwrap();
    let observed = fixture.observe();
    assert!(has_error(
        &observed,
        Role::Descriptor,
        Reason::DescriptorMismatch
    ));
    assert!(observed.queries.is_empty());
    assert!(route(&observed, Role::LlmPolicy).admitted);
    assert!(route(&observed, Role::CasPolicy).admitted);
}

#[test]
fn changed_content_and_growth_after_one_query_refuse_without_a_second_query() {
    for growth in [false, true] {
        let fixture = Fixture::new();
        let path = fixture.path(Role::LlmPolicy);
        let mut changed = LLM_POLICY.to_vec();
        if growth {
            changed.extend_from_slice(b"growth");
        } else {
            changed[0] ^= 1;
        }
        let mut producer = fixture.producer(move |_, _| {
            std::fs::write(&path, &changed).unwrap();
            Ok(output(b"bounded fixture", b"", Some(0)))
        });
        let deadline = until();
        producer.collect(deadline);
        let observed = producer.finish(deadline);
        assert_eq!(observed.queries.len(), 1);
        assert!(has_error(&observed, Role::LlmPolicy, Reason::InputChanged));
        assert!(has_error(
            &observed,
            Role::LlmPolicy,
            Reason::CanonicalMismatch
        ));
        assert!(!observed.collection_complete);
    }
}

#[test]
fn replaced_leaf_keeps_the_original_descriptor_and_never_adopts_the_new_inode() {
    let fixture = Fixture::new();
    let path = fixture.path(Role::LlmPolicy);
    let original = fixture.root.join("old-llm");
    let old_inode = std::fs::metadata(&path).unwrap().ino();
    let saved = original.clone();
    let mut producer = fixture.producer(move |_, _| {
        std::fs::rename(&path, &saved).unwrap();
        std::fs::write(&path, LLM_POLICY).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        Ok(output(b"fixture", b"", Some(0)))
    });
    let deadline = until();
    producer.collect(deadline);
    let observed = producer.finish(deadline);
    assert_eq!(observed.queries.len(), 1);
    assert!(has_error(&observed, Role::LlmPolicy, Reason::InputChanged));
    let held = &route(&observed, Role::LlmPolicy).nodes.last().unwrap().file;
    assert_eq!(held.metadata().unwrap().ino(), old_inode);
    assert_eq!(
        read_original(held, MAX_OUTPUT, until()).unwrap(),
        LLM_POLICY
    );
    assert_eq!(std::fs::metadata(original).unwrap().ino(), old_inode);
    assert_ne!(
        std::fs::metadata(fixture.path(Role::LlmPolicy))
            .unwrap()
            .ino(),
        old_inode
    );
}

#[test]
fn replaced_parent_is_detected_even_when_the_new_named_leaf_has_identical_bytes_and_mode() {
    let fixture = Fixture::new();
    let root = fixture.root.clone();
    let mut producer = fixture.producer(move |_, _| {
        std::fs::rename(root.join("inputs"), root.join("old-inputs")).unwrap();
        std::fs::create_dir(root.join("inputs")).unwrap();
        std::fs::set_permissions(root.join("inputs"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        for name in ["descriptor.json", "pf.conf", "llm.pf", "cas.pf", "pfctl"] {
            std::fs::copy(
                root.join("old-inputs").join(name),
                root.join("inputs").join(name),
            )
            .unwrap();
        }
        Ok(output(b"fixture", b"", Some(0)))
    });
    let deadline = until();
    producer.collect(deadline);
    let observed = producer.finish(deadline);
    assert_eq!(observed.queries.len(), 1);
    for role in [
        Role::Descriptor,
        Role::RootPolicy,
        Role::LlmPolicy,
        Role::CasPolicy,
        Role::NativeTool,
    ] {
        assert!(has_error(&observed, role, Reason::InputChanged));
    }
}

#[test]
fn every_query_shortens_the_original_total_deadline_without_resetting_it() {
    let fixture = Fixture::new();
    let seen = Rc::new(RefCell::new(Vec::new()));
    let saved = seen.clone();
    let mut producer = fixture.producer(move |query, deadline| {
        saved.borrow_mut().push((query, Instant::now(), deadline));
        Ok(output(b"", b"", Some(0)))
    });
    let deadline = until();
    producer.collect(deadline);
    let observed = producer.finish(deadline);
    assert!(observed.collection_complete);
    assert_eq!(seen.borrow().len(), Query::ALL.len());
    for (query, start, end) in seen.borrow().iter() {
        assert!(Query::ALL.contains(query));
        assert!(*end <= deadline);
        assert!(*end <= *start + QUERY_LIMIT);
        assert!(*start < *end);
    }
}

#[test]
fn expired_total_endpoint_prevents_any_query_and_late_return_refuses() {
    let fixture = Fixture::new();
    let mut producer = fixture.producer(|_, _| panic!("expired endpoint must not execute a query"));
    let deadline = Instant::now();
    producer.collect(deadline);
    let observed = producer.finish(deadline);
    assert!(observed.queries.is_empty());
    assert!(observed
        .final_refusals
        .iter()
        .any(|error| error.reason == Reason::Deadline));
    let mut producer = fixture.producer(|_, deadline| {
        std::thread::sleep(
            deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
        );
        Ok(output(b"late software fixture", b"", Some(0)))
    });
    let deadline = Instant::now() + Duration::from_millis(200);
    producer.collect(deadline);
    let observed = producer.finish(deadline);
    assert_eq!(observed.queries.len(), 1);
    assert_eq!(observed.primary_refusal.unwrap().reason, Reason::Deadline);
    assert!(!observed.collection_complete);
}

#[test]
fn combined_stream_and_cumulative_observation_output_caps_stop_collection() {
    for cumulative in [false, true] {
        let fixture = Fixture::new();
        let count = Rc::new(Cell::new(0));
        let seen = count.clone();
        let mut producer = fixture.producer(move |_, _| {
            seen.set(seen.get() + 1);
            let size = if cumulative {
                MAX_OUTPUT / 2
            } else {
                MAX_OUTPUT / 2 + 1
            };
            Ok(CommandOutput {
                code: Some(0),
                stdout: vec![b'x'; size],
                stderr: vec![b'y'; size],
            })
        });
        let deadline = until();
        producer.collect(deadline);
        let observed = producer.finish(deadline);
        assert_eq!(count.get(), if cumulative { 2 } else { 1 });
        assert_eq!(
            observed.primary_refusal.unwrap().reason,
            Reason::QueryFailed(CommandFailure::OutputLimit)
        );
        assert_eq!(
            observed.queries.last().unwrap().failure,
            Some(CommandFailure::OutputLimit)
        );
        assert!(observed.queries.last().unwrap().stdout.is_none());
        assert_no_readiness(&observed);
    }
}

#[test]
fn every_engine_failure_including_unknown_cleanup_stops_without_retry() {
    for failure in [
        CommandFailure::Unavailable,
        CommandFailure::Timeout,
        CommandFailure::OutputLimit,
        CommandFailure::Io,
        CommandFailure::OwnershipUnknown,
    ] {
        let fixture = Fixture::new();
        let count = Rc::new(Cell::new(0));
        let seen = count.clone();
        let mut producer = fixture.producer(move |_, _| {
            seen.set(seen.get() + 1);
            Err(failure)
        });
        let deadline = until();
        producer.collect(deadline);
        let observed = producer.finish(deadline);
        assert_eq!(count.get(), 1);
        assert_eq!(observed.queries.len(), 1);
        assert_eq!(
            observed.primary_refusal.unwrap().reason,
            Reason::QueryFailed(failure)
        );
        assert_eq!(observed.originals.routes.len(), 5);
        assert_no_readiness(&observed);
    }
}

#[test]
fn primary_cleanup_failure_and_all_independent_final_input_context_errors_survive() {
    let fixture = Fixture::new();
    let root_policy = fixture.path(Role::RootPolicy);
    let cas = fixture.path(Role::CasPolicy);
    let context_ok = Rc::new(Cell::new(true));
    let mutate_context = context_ok.clone();
    let mut producer = fixture.producer(move |_, _| {
        std::fs::write(&root_policy, b"changed protected root policy").unwrap();
        std::fs::remove_file(&cas).unwrap();
        mutate_context.set(false);
        Err(CommandFailure::OwnershipUnknown)
    });
    producer.observation.retained_context = Some(Context::Fixture(Box::new(move || {
        if context_ok.get() {
            Ok(())
        } else {
            Err(crate::err!(ESTALE, "SOFTWARE_CONTEXT_DRIFT"))
        }
    })));
    let deadline = until();
    producer.collect(deadline);
    let observed = producer.finish(deadline);
    assert_eq!(
        observed.primary_refusal.unwrap().reason,
        Reason::QueryFailed(CommandFailure::OwnershipUnknown)
    );
    for (role, reason) in [
        (Some(Role::RootPolicy), Reason::InputChanged),
        (Some(Role::CasPolicy), Reason::InputMetadata),
        (None, Reason::ContextChanged),
    ] {
        assert!(observed
            .final_refusals
            .iter()
            .any(|error| error.role == role && error.reason == reason));
    }
    assert_eq!(observed.queries.len(), 1);
    assert_eq!(observed.originals.routes.len(), 5);
    assert_no_readiness(&observed);
}

#[test]
fn wrong_or_missing_exit_status_is_not_bounded_collection_success() {
    for code in [Some(1), Some(64), None] {
        let fixture = Fixture::new();
        let mut producer = fixture.producer(move |_, _| Ok(output(b"Status: Enabled", b"", code)));
        let deadline = until();
        producer.collect(deadline);
        let observed = producer.finish(deadline);
        assert_eq!(observed.primary_refusal.unwrap().reason, Reason::QueryExit);
        assert_eq!(observed.queries.len(), 1);
        assert!(!observed.collection_complete);
        assert_no_readiness(&observed);
    }
}

#[test]
fn every_unqualified_native_output_schema_remains_unknown_even_after_bounded_collection() {
    // These strings are adversarial software payloads, NOT pinned native
    // schemas, supported-version fixtures or positive effective-policy tests.
    let payloads: &[&[u8]] = &[
        b"",
        b"Status: Enabled",
        b"Status: Disabled",
        b"Status: Unknown",
        b"pfctl version invented",
        b"locale changed",
        b"Status: Enabled\nStatus: Disabled\n",
        b"anchor \"com.enterprise.llm.isolation\"",
        b"anchor \"com.enterprise.cas.swarm\"",
        b"pass quick all\nanchor \"com.enterprise.llm.isolation\" all\n",
        b"anchor \"conditional/*\" on en0 inet6",
        b"load anchor unknown from /unheld/file",
        b"pass out inet proto tcp user 0 group 0 to any port 443 keep state",
        b"block quick out on en1 inet6 proto udp user 703 to any port 53 no state",
        b"truncated \"",
        b"\xff\xfe",
        b"unknown rule class",
        LLM_POLICY,
        CAS_POLICY,
    ];
    for payload in payloads {
        let fixture = Fixture::new();
        let payload = payload.to_vec();
        let mut producer = fixture.producer(move |query, _| {
            // Dry-run data can be stderr. Neither stream is interpreted as a
            // policy without an independently qualified native schema.
            if matches!(query, Query::CompileLlm | Query::CompileCas) {
                Ok(output(b"", &payload, Some(0)))
            } else {
                Ok(output(&payload, b"unexplained diagnostic", Some(0)))
            }
        });
        let deadline = until();
        producer.collect(deadline);
        let observed = producer.finish(deadline);
        assert!(observed.collection_complete);
        assert_no_readiness(&observed);
    }
}

#[test]
fn report_debug_contains_only_hash_count_progress_and_never_raw_input_or_stream_sentinels() {
    let fixture = Fixture::new();
    let sentinel = b"DO_NOT_DISCLOSE_RAW_PF_CONFIG_OR_NATIVE_STREAM_SENTINEL";
    // The actual root input must remain canonical; raw stream sentinels
    // still pass through the successful collector and remain redacted.
    let mut producer = fixture.producer(move |_, _| Ok(output(sentinel, sentinel, Some(0))));
    let deadline = until();
    producer.collect(deadline);
    let observed = producer.finish(deadline);
    assert!(observed.collection_complete);
    let debug = format!("{observed:?}");
    assert!(!debug.contains(std::str::from_utf8(sentinel).unwrap()));
    assert!(
        !debug.contains("BEGIN depot PF RULES"),
        "canonical raw root content must remain redacted too"
    );
    assert!(!debug.contains(fixture.root.to_str().unwrap()));
    assert!(!debug.contains(SAFE_PATH));
    for query in &observed.queries {
        for stream in [&query.stdout, &query.stderr] {
            let fingerprint = stream.as_ref().unwrap();
            assert_eq!(fingerprint.bytes, sentinel.len());
            assert_eq!(fingerprint.sha256, digest(sentinel));
        }
    }
}

#[test]
fn changed_original_descriptor_flags_fail_final_checks_without_being_repaired() {
    for close_on_exec in [false, true] {
        let fixture = Fixture::new();
        let mut producer = fixture.producer(|_, _| Ok(output(b"", b"", Some(0))));
        let deadline = until();
        producer.collect(deadline);
        let file = &route(&producer.observation, Role::CasPolicy)
            .nodes
            .last()
            .unwrap()
            .file;
        let fd = file.as_raw_fd();
        if close_on_exec {
            assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, 0) }, 0);
        } else {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            assert!(flags >= 0);
            assert_eq!(
                unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) },
                0
            );
        }
        let observed = producer.finish(deadline);
        assert!(observed
            .final_refusals
            .iter()
            .any(|error| error.role == Some(Role::CasPolicy)
                && error.reason == Reason::DescriptorFlags));
        assert!(!observed.collection_complete);
        assert_no_readiness(&observed);
        assert_eq!(observed.queries.len(), Query::ALL.len());
        assert!(route(&observed, Role::CasPolicy)
            .protection
            .descriptor(&route(&observed, Role::CasPolicy).nodes.last().unwrap().file)
            .is_err());
    }
}

#[test]
fn final_only_drift_keeps_all_independent_refusals_after_successful_queries() {
    let fixture = Fixture::new();
    let mut producer = fixture.producer(|_, _| Ok(output(b"", b"", Some(0))));
    let deadline = until();
    producer.collect(deadline);
    assert_eq!(producer.observation.queries.len(), Query::ALL.len());
    assert!(producer.observation.primary_refusal.is_none());
    for role in [Role::LlmPolicy, Role::CasPolicy] {
        std::fs::write(fixture.path(role), b"final drift").unwrap();
    }
    let observed = producer.finish(deadline);
    for role in [Role::LlmPolicy, Role::CasPolicy] {
        assert!(observed
            .final_refusals
            .iter()
            .any(|error| error.role == Some(role) && error.reason == Reason::CanonicalMismatch));
    }
    assert!(!observed.collection_complete);
    assert_no_readiness(&observed);
}

#[test]
fn fixture_protection_never_silently_substitutes_for_native_acl_inspection() {
    let fixture = Fixture::new();
    let observed = fixture.observe();
    let file = &route(&observed, Role::RootPolicy)
        .nodes
        .last()
        .unwrap()
        .file;
    fixture.protection().descriptor(file).unwrap();
    #[cfg(not(target_os = "macos"))]
    assert_eq!(
        Protection::NativeRoot.descriptor(file),
        Err(Reason::NativeAclRequired)
    );
    assert_no_readiness(&observed);
}

#[test]
fn restore_preparation_uses_same_retained_owner_closed_command_and_never_executes_or_grants_readiness(
) {
    let fixture = Fixture::new();
    let calls = Rc::new(Cell::new(0));
    let seen = calls.clone();
    let producer = fixture.producer(move |_, _| {
        seen.set(seen.get() + 1);
        Err(CommandFailure::OwnershipUnknown)
    });
    let mut observed = producer.finish(until());
    let root_fd = route(&observed, Role::RootPolicy)
        .nodes
        .last()
        .unwrap()
        .file
        .as_raw_fd();
    {
        let mut plan = observed.prepare_restore(until()).unwrap();
        assert_eq!(
            plan.observation
                .originals
                .routes
                .iter()
                .find(|route| route.spec.role == Role::RootPolicy)
                .unwrap()
                .nodes
                .last()
                .unwrap()
                .file
                .as_raw_fd(),
            root_fd
        );
        assert_eq!(plan.command.get_program(), "/sbin/pfctl");
        assert_eq!(
            plan.command
                .get_args()
                .map(|v| v.to_str().unwrap())
                .collect::<Vec<_>>(),
            ["-R", "-f", "/private/etc/pf.conf"]
        );
        assert_eq!(plan.command.get_current_dir(), Some(Path::new("/")));
        assert_eq!(
            plan.command
                .get_envs()
                .map(|(k, v)| (k.to_str().unwrap(), v.unwrap().to_str().unwrap()))
                .collect::<Vec<_>>(),
            [("LC_ALL", "C"), ("PATH", SAFE_PATH)]
        );
        assert_eq!(
            plan.execution_gap(),
            RestoreExecutionGap::CompleteRootPolicyAuthorityAndNativeTransaction
        );
        plan.require_current_inputs().unwrap();
    }
    assert_eq!(
        calls.get(),
        0,
        "preparation must never enter query or native command executor"
    );
    assert_no_readiness(&observed);
}

#[test]
fn restore_preparation_may_retain_a_query_failure_but_cannot_turn_it_into_restoration_success() {
    let fixture = Fixture::new();
    let mut producer = fixture.producer(|query, _| {
        Ok(output(
            if query == Query::LlmRules {
                b""
            } else {
                component_bytes(query)
            },
            component_stderr(query),
            Some(0),
        ))
    });
    producer.components = Some(native_schema::Components::new(
        native_schema::fixture_schema(),
    ));
    producer.collect(until());
    let mut observed = producer.finish(until());
    let refusal = observed.primary_refusal;
    assert!(matches!(
        refusal.unwrap().reason,
        Reason::NativeSchema(native_schema::Error::EmptyRules)
    ));
    observed
        .prepare_restore(until())
        .unwrap()
        .require_current_inputs()
        .unwrap();
    assert_eq!(observed.primary_refusal, refusal);
    assert!(!observed.collection_complete);
    assert_no_readiness(&observed);
}

#[test]
fn arbitrary_root_content_refuses_the_actual_original_owner_and_cannot_prepare_a_mutation_command()
{
    let fixture = Fixture::new();
    let bytes = b"include \"/etc/pf.conf\"\npass quick all\n";
    std::fs::write(fixture.path(Role::RootPolicy), bytes).unwrap();
    let producer =
        fixture.producer(|_, _| panic!("noncanonical root must stop before every query"));
    let mut observed = producer.finish(until());
    assert_eq!(
        observed.primary_refusal.unwrap().reason,
        Reason::RestoreContent(ContentRefusal::RootFilter)
    );
    assert!(observed.prepare_restore(until()).is_err());
    assert_eq!(
        std::fs::read(fixture.path(Role::RootPolicy)).unwrap(),
        bytes
    );
    assert_eq!(
        observed.originals.routes.len(),
        5,
        "all other originals survive root refusal"
    );
}

#[test]
fn restore_plan_keeps_original_finite_endpoint_and_expiry_cannot_be_renewed_by_a_later_request() {
    let fixture = Fixture::new();
    let end = Instant::now() + Duration::from_secs(1);
    let producer = fixture.producer(|_, _| panic!("planning cannot execute"));
    let mut observed = producer.finish(end);
    assert_eq!(observed.prepare_restore(until()).unwrap().deadline, end);
    let producer = fixture.producer(|_, _| panic!("expired planning cannot execute"));
    let mut expired = producer.finish(Instant::now() - Duration::from_millis(1));
    let errors = expired.prepare_restore(until()).err().unwrap();
    assert!(errors.iter().any(|error| error.reason == Reason::Deadline));
}

#[test]
fn restore_plan_retains_independent_context_and_original_failures_and_never_revives_after_replacement(
) {
    let fixture = Fixture::new();
    let valid = Rc::new(Cell::new(true));
    let checked = valid.clone();
    let mut producer = fixture.producer(|_, _| panic!("planning cannot execute"));
    producer.observation.retained_context = Some(Context::Fixture(Box::new(move || {
        if checked.get() {
            Ok(())
        } else {
            Err(crate::err!(ESTALE, "FIXTURE_CONTEXT_LOST"))
        }
    })));
    let mut observed = producer.finish(until());
    let mut plan = observed.prepare_restore(until()).unwrap();
    let root = fixture.path(Role::RootPolicy);
    let retired = root.with_extension("retired");
    std::fs::rename(&root, &retired).unwrap();
    std::fs::write(&root, pf_restore_input::render_root_filter()).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o644)).unwrap();
    valid.set(false);
    let errors = plan.require_current_inputs().unwrap_err();
    assert!(errors
        .iter()
        .any(|e| e.role == Some(Role::RootPolicy) && e.reason == Reason::InputChanged));
    assert!(errors
        .iter()
        .any(|e| e.role.is_none() && e.reason == Reason::ContextChanged));
    std::fs::remove_file(&root).unwrap();
    std::fs::rename(&retired, &root).unwrap();
    valid.set(true);
    assert!(plan
        .require_current_inputs()
        .unwrap_err()
        .iter()
        .any(|e| e.reason == Reason::RestorePlanPoisoned));
}

// This fixture-only constructor uses the same retained Producer/boundaries and
// actual protected private files. It supplies no native root/schema evidence.
fn retained_fixture(
    fixture: &Fixture,
    end: Instant,
    query: impl FnMut(Query, Instant) -> Result<CommandOutput, CommandFailure> + 'static,
    context: impl FnMut() -> EnclaveResult<()> + 'static,
) -> RetainedReadOnlyOwner {
    retained_fixture_bound(fixture, end, None, query, context)
}
fn retained_fixture_bound(
    fixture: &Fixture,
    end: Instant,
    session: Option<Arc<ReadOnlySessionBinding>>,
    query: impl FnMut(Query, Instant) -> Result<CommandOutput, CommandFailure> + 'static,
    context: impl FnMut() -> EnclaveResult<()> + 'static,
) -> RetainedReadOnlyOwner {
    let terminal = Arc::new(AtomicBool::new(false));
    let mut producer = Producer::empty_until(end);
    producer.retained_veto = Some(terminal.clone());
    producer.retained_session = session;
    let mut owner = RetainedReadOnlyOwner {
        original_enclosing_end: end,
        terminal,
        producer,
    };
    let mut veto = owner.sample_veto();
    if let Err(reason) = owner.producer.require_retained_session(end) {
        owner.producer.retain_errors(vec![Refusal {
            role: None,
            phase: Phase::Admission,
            reason,
        }]);
        return owner;
    }
    owner.producer.observation.retained_context = Some(Context::Fixture(Box::new(context)));
    owner.producer.fixture_query = Some(Box::new(query));
    owner.producer.components = Some(native_schema::Components::new(
        native_schema::fixture_schema(),
    ));
    let cap = owner.producer.observation.sample_end;
    let errors =
        owner
            .producer
            .observation
            .originals
            .open(fixture.specs(), fixture.protection(), cap);
    owner.producer.retain_errors(errors);
    let errors = owner.producer.boundary(Phase::Admission, cap);
    owner.producer.retain_errors(errors);
    if owner.producer.observation.primary_refusal.is_none()
        && !owner.terminal.load(Ordering::SeqCst)
    {
        veto.armed = false;
    }
    drop(veto);
    owner
}
fn retained_identities(owner: &RetainedReadOnlyOwner) -> Vec<(Role, i32, u64, u64)> {
    owner
        .producer
        .observation
        .originals
        .routes
        .iter()
        .map(|route| {
            let file = &route.nodes.last().unwrap().file;
            let metadata = file.metadata().unwrap();
            (
                route.spec.role,
                file.as_raw_fd(),
                metadata.dev(),
                metadata.ino(),
            )
        })
        .collect()
}
fn valid_component_output(query: Query) -> Result<CommandOutput, CommandFailure> {
    Ok(output(
        component_bytes(query),
        component_stderr(query),
        Some(0),
    ))
}

#[test]
fn retained_readonly_samples_keep_five_originals_context_schema_and_immutable_outer_end() {
    let fixture = Fixture::new();
    let calls = Rc::new(Cell::new(0));
    let seen = calls.clone();
    let end = Instant::now() + Duration::from_secs(30);
    let mut owner = retained_fixture(
        &fixture,
        end,
        move |query, _| {
            seen.set(seen.get() + 1);
            valid_component_output(query)
        },
        || Ok(()),
    );
    let originals = retained_identities(&owner);
    assert_eq!(originals.len(), 5);
    assert_eq!(calls.get(), 0);
    let context = owner
        .producer
        .observation
        .retained_context
        .as_ref()
        .unwrap() as *const Context;
    let schema = owner.producer.components.as_ref().unwrap() as *const native_schema::Components;
    for _ in 0..2 {
        let observed = owner.sample_until(Instant::now() + Duration::from_secs(2));
        assert!(observed.collection_complete && observed.protected_inputs_current);
        assert_eq!(observed.original_enclosing_end, end);
        assert!(observed.sample_end <= end);
        assert_eq!(observed.native_schema, Knowledge::Established);
        assert_eq!(observed.interface_skip_policy, Knowledge::Unknown);
        assert_eq!(observed.mandatory_watcher, Knowledge::NotObserved);
        assert_eq!(observed.atomic_restoration, Knowledge::NotObserved);
        assert!(
            !observed.required_enforcement_established()
                && !observed.first_begin_prerequisites_met()
        );
        assert_eq!(retained_identities(&owner), originals);
        assert_eq!(
            owner
                .producer
                .observation
                .retained_context
                .as_ref()
                .unwrap() as *const Context,
            context
        );
        assert_eq!(
            owner.producer.components.as_ref().unwrap() as *const native_schema::Components,
            schema
        );
        assert_eq!(owner.original_enclosing_end, end);
    }
    assert_eq!(calls.get(), 2 * Query::ALL.len());
}

#[test]
fn retained_readonly_expiry_and_expired_sample_are_terminal_despite_later_offered_end() {
    for expire_outer in [false, true] {
        let fixture = Fixture::new();
        let calls = Rc::new(Cell::new(0));
        let seen = calls.clone();
        let end = Instant::now()
            + if expire_outer {
                Duration::from_millis(150)
            } else {
                Duration::from_secs(30)
            };
        let mut owner = retained_fixture(
            &fixture,
            end,
            move |query, _| {
                seen.set(seen.get() + 1);
                valid_component_output(query)
            },
            || Ok(()),
        );
        if expire_outer {
            std::thread::sleep(
                end.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
            );
        }
        let requested = if expire_outer {
            until()
        } else {
            Instant::now()
        };
        assert_no_readiness(owner.sample_until(requested));
        assert!(owner.terminal.load(Ordering::SeqCst));
        assert_eq!(calls.get(), 0);
        assert_eq!(owner.original_enclosing_end, end);
        assert_no_readiness(owner.sample_until(until() + Duration::from_secs(30)));
        assert_eq!(calls.get(), 0);
        assert_eq!(owner.producer.observation.original_enclosing_end, end);
    }
}

#[test]
fn retained_readonly_original_name_content_ancestor_or_context_loss_cannot_adopt_restored_inputs() {
    for change in ["name", "content", "ancestor", "context"] {
        let fixture = Fixture::new();
        let calls = Rc::new(Cell::new(0));
        let seen = calls.clone();
        let valid = Rc::new(Cell::new(true));
        let current = valid.clone();
        let mut owner = retained_fixture(
            &fixture,
            until(),
            move |query, _| {
                seen.set(seen.get() + 1);
                valid_component_output(query)
            },
            move || {
                if current.get() {
                    Ok(())
                } else {
                    Err(crate::err!(ESTALE, "FIXTURE_CONTEXT_LOST"))
                }
            },
        );
        assert!(owner.sample_until(until()).collection_complete);
        let originals = retained_identities(&owner);
        assert_eq!(calls.get(), Query::ALL.len());
        let path = fixture.path(Role::LlmPolicy);
        let retired = path.with_extension("retired");
        let parent = path.parent().unwrap();
        match change {
            "name" => {
                std::fs::rename(&path, &retired).unwrap();
                std::fs::write(&path, LLM_POLICY).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            }
            "content" => std::fs::write(&path, b"invalid replacement policy").unwrap(),
            "ancestor" => {
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755)).unwrap()
            }
            "context" => valid.set(false),
            _ => unreachable!(),
        }
        assert_no_readiness(owner.sample_until(until()));
        assert_eq!(calls.get(), Query::ALL.len());
        assert!(owner.terminal.load(Ordering::SeqCst));
        match change {
            "name" => {
                std::fs::remove_file(&path).unwrap();
                std::fs::rename(&retired, &path).unwrap();
            }
            "content" => std::fs::write(&path, LLM_POLICY).unwrap(),
            "ancestor" => {
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).unwrap()
            }
            "context" => valid.set(true),
            _ => unreachable!(),
        }
        assert_no_readiness(owner.sample_until(until()));
        assert_eq!(calls.get(), Query::ALL.len());
        assert_eq!(retained_identities(&owner), originals);
    }
}

#[test]
fn retained_readonly_failed_or_late_new_query_clears_old_components_and_never_retries() {
    for late in [false, true] {
        let fixture = Fixture::new();
        let calls = Rc::new(Cell::new(0));
        let seen = calls.clone();
        let mut owner = retained_fixture(
            &fixture,
            until(),
            move |query, end| {
                seen.set(seen.get() + 1);
                if seen.get() == Query::ALL.len() + 1 {
                    if !late {
                        return Err(CommandFailure::OwnershipUnknown);
                    }
                    std::thread::sleep(
                        end.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
                    );
                }
                valid_component_output(query)
            },
            || Ok(()),
        );
        assert!(owner.sample_until(until()).collection_complete);
        assert_eq!(calls.get(), Query::ALL.len());
        assert_no_readiness(owner.sample_until(Instant::now() + Duration::from_millis(40)));
        assert_eq!(calls.get(), Query::ALL.len() + 1);
        let components = owner.producer.components.as_ref().unwrap();
        assert_eq!(components.enabled(), None);
        assert!(
            !components.root_linkage_order() && !components.llm_equal() && !components.cas_equal()
        );
        assert!(owner.terminal.load(Ordering::SeqCst));
        assert_no_readiness(owner.sample_until(until()));
        assert_eq!(calls.get(), Query::ALL.len() + 1);
    }
}

#[test]
fn retained_readonly_context_and_query_unwind_veto_before_caller_recovers() {
    for context_unwind in [false, true] {
        let fixture = Fixture::new();
        let calls = Rc::new(Cell::new(0));
        let seen = calls.clone();
        let panic_context = Rc::new(Cell::new(false));
        let context = panic_context.clone();
        let mut owner = retained_fixture(
            &fixture,
            until(),
            move |query, _| {
                seen.set(seen.get() + 1);
                assert!(
                    context_unwind || seen.get() != Query::ALL.len() + 1,
                    "query unwind"
                );
                valid_component_output(query)
            },
            move || {
                assert!(!context.get(), "context unwind");
                Ok(())
            },
        );
        assert!(owner.sample_until(until()).collection_complete);
        if context_unwind {
            panic_context.set(true);
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.sample_until(until());
        }));
        assert!(result.is_err());
        assert!(owner.terminal.load(Ordering::SeqCst));
        let before = calls.get();
        panic_context.set(false);
        assert_no_readiness(owner.sample_until(until()));
        assert_eq!(calls.get(), before);
    }
}

#[test]
fn retained_readonly_same_negative_signal_during_query_stops_before_another_query() {
    let fixture = Fixture::new();
    let calls = Rc::new(Cell::new(0));
    let seen = calls.clone();
    let signal = Rc::new(RefCell::new(None::<Arc<AtomicBool>>));
    let raised = signal.clone();
    let mut owner = retained_fixture(
        &fixture,
        until(),
        move |query, _| {
            seen.set(seen.get() + 1);
            if seen.get() == Query::ALL.len() + 1 {
                raised
                    .borrow()
                    .as_ref()
                    .unwrap()
                    .store(true, Ordering::SeqCst);
            }
            valid_component_output(query)
        },
        || Ok(()),
    );
    *signal.borrow_mut() = Some(owner.terminal.clone());
    assert!(Arc::ptr_eq(
        owner.producer.retained_veto.as_ref().unwrap(),
        &owner.terminal
    ));
    assert!(owner.sample_until(until()).collection_complete);
    assert_eq!(calls.get(), Query::ALL.len());
    assert_no_readiness(owner.sample_until(until()));
    assert_eq!(calls.get(), Query::ALL.len() + 1);
    assert!(owner.terminal.load(Ordering::SeqCst));
    assert_no_readiness(owner.sample_until(until()));
    assert_eq!(calls.get(), Query::ALL.len() + 1);
}

#[test]
fn retained_readonly_partial_preparation_retains_original_routes_without_retry_or_reopen() {
    let fixture = Fixture::new();
    std::fs::set_permissions(
        fixture.path(Role::LlmPolicy),
        std::fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    let calls = Rc::new(Cell::new(0));
    let seen = calls.clone();
    let mut owner = retained_fixture(
        &fixture,
        until(),
        move |query, _| {
            seen.set(seen.get() + 1);
            valid_component_output(query)
        },
        || Ok(()),
    );
    assert!(owner.terminal.load(Ordering::SeqCst));
    assert!(owner.producer.observation.primary_refusal.is_some());
    let originals = retained_identities(&owner);
    assert_eq!(originals.len(), 5);
    assert_eq!(calls.get(), 0);
    std::fs::set_permissions(
        fixture.path(Role::LlmPolicy),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert_no_readiness(owner.sample_until(until()));
    assert_eq!(calls.get(), 0);
    assert_eq!(retained_identities(&owner), originals);
}

#[test]
fn retained_readonly_teardown_veto_precedes_owned_fixture_destructor() {
    struct Witness {
        signal: Rc<RefCell<Option<Arc<AtomicBool>>>>,
        observed: Rc<Cell<bool>>,
    }
    impl Drop for Witness {
        fn drop(&mut self) {
            if let Some(signal) = self.signal.borrow().as_ref() {
                assert!(signal.load(Ordering::SeqCst));
                self.observed.set(true);
            }
        }
    }
    let fixture = Fixture::new();
    let signal = Rc::new(RefCell::new(None));
    let observed = Rc::new(Cell::new(false));
    let witness = Witness {
        signal: signal.clone(),
        observed: observed.clone(),
    };
    let mut owner = retained_fixture(
        &fixture,
        until(),
        move |query, _| {
            let _ = &witness;
            valid_component_output(query)
        },
        || Ok(()),
    );
    *signal.borrow_mut() = Some(owner.terminal.clone());
    assert!(owner.sample_until(until()).collection_complete);
    let terminal = owner.terminal.clone();
    assert!(!terminal.load(Ordering::SeqCst));
    drop(owner);
    assert!(terminal.load(Ordering::SeqCst) && observed.get());
}

#[test]
fn retained_readonly_explicit_veto_precedes_every_new_context_query_or_reopen_attempt() {
    let fixture = Fixture::new();
    let calls = Rc::new(Cell::new(0));
    let seen = calls.clone();
    let contexts = Rc::new(Cell::new(0));
    let checked = contexts.clone();
    let mut owner = retained_fixture(
        &fixture,
        until(),
        move |query, _| {
            seen.set(seen.get() + 1);
            valid_component_output(query)
        },
        move || {
            checked.set(checked.get() + 1);
            Ok(())
        },
    );
    let originals = retained_identities(&owner);
    let context_before = contexts.get();
    owner.veto();
    for _ in 0..2 {
        assert_no_readiness(owner.sample_until(until()));
    }
    assert_eq!(calls.get(), 0);
    assert_eq!(contexts.get(), context_before);
    assert!(owner.terminal.load(Ordering::SeqCst));
    assert_eq!(retained_identities(&owner), originals);
}

// The fixture binding exercises the SAME actual producer query boundaries and
// veto guard. It cannot manufacture an opaque native SelectedOwnerSession.
fn readonly_session_fixture(
    end: Instant,
) -> (
    Arc<ReadOnlySessionBinding>,
    Arc<()>,
    Arc<AtomicBool>,
    Arc<AtomicBool>,
) {
    let identity = Arc::new(());
    let live = Arc::new(AtomicBool::new(true));
    let stop = Arc::new(AtomicBool::new(false));
    (
        Arc::new(ReadOnlySessionBinding::Fixture {
            identity: identity.clone(),
            live: live.clone(),
            stop: stop.clone(),
            end,
        }),
        identity,
        live,
        stop,
    )
}
#[test]
fn retained_bound_collection_keeps_same_session_stop_originals_and_fixed_outer_end() {
    let fixture = Fixture::new();
    let end = until();
    let (binding, identity, live, stop) = readonly_session_fixture(end);
    let calls = Rc::new(Cell::new(0));
    let seen = calls.clone();
    let mut owner = retained_fixture_bound(
        &fixture,
        end,
        Some(binding.clone()),
        move |query, deadline| {
            assert!(deadline <= end);
            seen.set(seen.get() + 1);
            valid_component_output(query)
        },
        || Ok(()),
    );
    let originals = retained_identities(&owner);
    owner.require_fixture_health_until(end).unwrap();
    owner
        .require_fixture_health_until(end + OVERALL_LIMIT)
        .unwrap();
    assert_eq!(calls.get(), 2 * Query::ALL.len());
    assert_eq!(retained_identities(&owner), originals);
    assert_eq!(owner.original_enclosing_end, end);
    assert_eq!(owner.producer.observation.original_enclosing_end, end);
    assert!(Arc::ptr_eq(
        owner.producer.retained_session.as_ref().unwrap(),
        &binding
    ));
    match binding.as_ref() {
        ReadOnlySessionBinding::Fixture {
            identity: held,
            stop: held_stop,
            ..
        } => {
            assert!(Arc::ptr_eq(held, &identity));
            assert!(Arc::ptr_eq(held_stop, &stop));
        }
        _ => unreachable!(),
    }
    assert!(live.load(Ordering::SeqCst));
    assert!(!stop.load(Ordering::SeqCst));
    assert_eq!(
        owner.producer.observation.interface_skip_policy,
        Knowledge::Unknown
    );
    assert_eq!(
        owner.producer.observation.translation_policy,
        Knowledge::Unknown
    );
    assert_eq!(
        owner.producer.observation.preexisting_state_policy,
        Knowledge::Unknown
    );
    assert_eq!(
        owner.producer.observation.mandatory_watcher,
        Knowledge::NotObserved
    );
    assert_eq!(
        owner.producer.observation.atomic_restoration,
        Knowledge::NotObserved
    );
    assert!(!owner
        .producer
        .observation
        .required_enforcement_established());
    assert!(!owner.producer.observation.first_begin_prerequisites_met());
    owner.veto();
    assert!(!live.load(Ordering::SeqCst));
    assert!(stop.load(Ordering::SeqCst));
}
#[test]
fn retained_bound_stop_or_session_loss_during_query_prevents_every_later_query_and_revival() {
    for stop_during_query in [false, true] {
        let fixture = Fixture::new();
        let end = until();
        let (binding, _identity, live, stop) = readonly_session_fixture(end);
        let changed_live = live.clone();
        let changed_stop = stop.clone();
        let calls = Rc::new(Cell::new(0));
        let seen = calls.clone();
        let mut owner = retained_fixture_bound(
            &fixture,
            end,
            Some(binding),
            move |query, _| {
                seen.set(seen.get() + 1);
                if stop_during_query {
                    changed_stop.store(true, Ordering::SeqCst);
                } else {
                    changed_live.store(false, Ordering::SeqCst);
                }
                valid_component_output(query)
            },
            || Ok(()),
        );
        let originals = retained_identities(&owner);
        assert!(owner.require_fixture_health_until(end).is_err());
        assert_eq!(calls.get(), 1);
        assert!(
            !live.load(Ordering::SeqCst)
                && stop.load(Ordering::SeqCst)
                && owner.terminal.load(Ordering::SeqCst)
        );
        live.store(true, Ordering::SeqCst);
        stop.store(false, Ordering::SeqCst);
        assert!(owner
            .require_fixture_health_until(end + OVERALL_LIMIT)
            .is_err());
        assert_eq!(calls.get(), 1);
        assert!(!live.load(Ordering::SeqCst) && stop.load(Ordering::SeqCst));
        assert_eq!(retained_identities(&owner), originals);
    }
}
#[test]
fn retained_bound_session_loss_inside_boundary_prevents_first_native_query() {
    let fixture = Fixture::new();
    let end = until();
    let (binding, _identity, live, stop) = readonly_session_fixture(end);
    let lose = Rc::new(Cell::new(false));
    let context_loss = lose.clone();
    let context_live = live.clone();
    let calls = Rc::new(Cell::new(0));
    let seen = calls.clone();
    let mut owner = retained_fixture_bound(
        &fixture,
        end,
        Some(binding),
        move |query, _| {
            seen.set(seen.get() + 1);
            valid_component_output(query)
        },
        move || {
            if context_loss.get() {
                context_live.store(false, Ordering::SeqCst);
            }
            Ok(())
        },
    );
    lose.set(true);
    assert!(owner.require_fixture_health_until(end).is_err());
    assert_eq!(calls.get(), 0);
    assert!(stop.load(Ordering::SeqCst));
    assert!(owner.terminal.load(Ordering::SeqCst));
}
#[test]
fn retained_bound_caught_query_or_context_unwind_revokes_same_session_and_stop_before_recovery() {
    for context_unwind in [false, true] {
        let fixture = Fixture::new();
        let end = until();
        let (binding, _identity, live, stop) = readonly_session_fixture(end);
        let panic_context = Rc::new(Cell::new(false));
        let context = panic_context.clone();
        let calls = Rc::new(Cell::new(0));
        let seen = calls.clone();
        let mut owner = retained_fixture_bound(
            &fixture,
            end,
            Some(binding),
            move |query, _| {
                seen.set(seen.get() + 1);
                assert!(context_unwind, "bound query unwind");
                valid_component_output(query)
            },
            move || {
                assert!(!context.get(), "bound context unwind");
                Ok(())
            },
        );
        panic_context.set(context_unwind);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || owner.require_fixture_health_until(end)
        ))
        .is_err());
        assert!(
            !live.load(Ordering::SeqCst)
                && stop.load(Ordering::SeqCst)
                && owner.terminal.load(Ordering::SeqCst)
        );
        let before = calls.get();
        panic_context.set(false);
        assert!(owner.require_fixture_health_until(end).is_err());
        assert_eq!(calls.get(), before);
    }
}
#[test]
fn retained_bound_stopped_or_expired_session_prevents_admission_and_cannot_reopen() {
    for expired in [false, true] {
        let fixture = Fixture::new();
        let end = if expired { Instant::now() } else { until() };
        let (binding, _identity, live, stop) = readonly_session_fixture(end);
        if !expired {
            stop.store(true, Ordering::SeqCst);
        }
        let calls = Rc::new(Cell::new(0));
        let seen = calls.clone();
        let contexts = Rc::new(Cell::new(0));
        let context = contexts.clone();
        let mut owner = retained_fixture_bound(
            &fixture,
            end,
            Some(binding),
            move |query, _| {
                seen.set(seen.get() + 1);
                valid_component_output(query)
            },
            move || {
                context.set(context.get() + 1);
                Ok(())
            },
        );
        assert!(owner.producer.observation.originals.routes.is_empty());
        assert_eq!(contexts.get(), 0);
        assert_eq!(calls.get(), 0);
        assert!(!live.load(Ordering::SeqCst) && stop.load(Ordering::SeqCst));
        live.store(true, Ordering::SeqCst);
        stop.store(false, Ordering::SeqCst);
        assert!(owner.require_fixture_health_until(until()).is_err());
        assert_eq!(contexts.get(), 0);
        assert_eq!(calls.get(), 0);
        assert!(owner.producer.observation.originals.routes.is_empty());
    }
}
#[test]
fn retained_bound_query_failure_and_owner_drop_veto_before_retained_context_destructor() {
    struct Witness {
        live: Arc<AtomicBool>,
        stop: Arc<AtomicBool>,
        dropped: Rc<Cell<bool>>,
    }
    impl Drop for Witness {
        fn drop(&mut self) {
            assert!(!self.live.load(Ordering::SeqCst));
            assert!(self.stop.load(Ordering::SeqCst));
            self.dropped.set(true);
        }
    }
    for query_failure in [false, true] {
        let fixture = Fixture::new();
        let end = until();
        let (binding, _identity, live, stop) = readonly_session_fixture(end);
        let dropped = Rc::new(Cell::new(false));
        let witness = Witness {
            live: live.clone(),
            stop: stop.clone(),
            dropped: dropped.clone(),
        };
        let mut owner = retained_fixture_bound(
            &fixture,
            end,
            Some(binding),
            move |query, _| {
                if query_failure {
                    Err(CommandFailure::Timeout)
                } else {
                    valid_component_output(query)
                }
            },
            move || {
                let _ = &witness;
                Ok(())
            },
        );
        if query_failure {
            assert!(owner.require_fixture_health_until(end).is_err());
            assert!(!live.load(Ordering::SeqCst) && stop.load(Ordering::SeqCst));
        } else {
            owner.require_fixture_health_until(end).unwrap();
            assert!(live.load(Ordering::SeqCst));
        }
        assert!(!dropped.get());
        drop(owner);
        assert!(dropped.get());
    }
}
#[test]
fn diagnostic_unbound_owner_cannot_supply_bound_negative_readiness_health() {
    let fixture = Fixture::new();
    let calls = Rc::new(Cell::new(0));
    let seen = calls.clone();
    let mut owner = retained_fixture(
        &fixture,
        until(),
        move |query, _| {
            seen.set(seen.get() + 1);
            valid_component_output(query)
        },
        || Ok(()),
    );
    assert!(owner
        .require_fixture_health_until(until())
        .unwrap_err()
        .is("PF_READONLY_SESSION_REQUIRED"));
    assert_eq!(calls.get(), 0);
    assert!(owner.terminal.load(Ordering::SeqCst));
    assert_no_readiness(owner.sample_until(until()));
}

#[test]
fn root_translation_empty_output_is_published_only_after_complete_supported_collection_without_policy_authority(
) {
    let fixture = Fixture::new();
    let seen = Rc::new(RefCell::new(Vec::new()));
    let queries = seen.clone();
    let mut producer = fixture.producer(move |query, _| {
        queries.borrow_mut().push(query);
        valid_component_output(query)
    });
    producer.components = Some(native_schema::Components::new(
        native_schema::fixture_schema(),
    ));
    let end = until();
    producer.collect(end);
    assert_eq!(*seen.borrow(), Query::ALL);
    assert_eq!(Query::ALL.last(), Some(&Query::RootTranslations));
    assert_eq!(
        producer.observation.root_translation_output, None,
        "no partial publication before final checks"
    );
    let observed = producer.finish(end);
    assert!(observed.collection_complete);
    assert_eq!(
        observed.root_translation_output,
        Some(native_schema::RootTranslationOutput::EmptyAtSnapshot)
    );
    assert_eq!(observed.translation_policy, Knowledge::Unknown);
    assert_eq!(observed.interface_skip_policy, Knowledge::Unknown);
    assert_eq!(observed.preexisting_state_policy, Knowledge::Unknown);
    assert!(
        !observed.required_enforcement_established() && !observed.first_begin_prerequisites_met()
    );
    let last = observed.queries.last().unwrap();
    assert_eq!(last.stdout.as_ref().unwrap().bytes, 0);
    assert_eq!(last.stderr.as_ref().unwrap().bytes, 0);
}
#[test]
fn root_translation_nonempty_rule_reference_whitespace_and_diagnostic_outputs_are_never_empty_snapshots(
) {
    let outputs: &[(&[u8], &[u8])] = &[
        (b"nat on en0 from any to any -> 192.0.2.1\n", b""),
        (
            b"rdr on lo0 proto tcp from any to any port 80 -> 127.0.0.1 port 8443\n",
            b"",
        ),
        (
            b"binat on en0 from 192.0.2.0/24 to any -> 198.51.100.0/24\n",
            b"",
        ),
        (b"nat-anchor \"system/*\" all\n", b""),
        (b"rdr-anchor \"system/*\" all\n", b""),
        (b"binat-anchor \"system/*\" all\n", b""),
        (b"\n \t", b""),
        (b"TRANSLATION RULES:\n", b""),
        (b"\xff\x00", b""),
        (b"", b"unexplained diagnostic"),
        (b"", native_schema::COMPILE_ADVISORY),
    ];
    for &(stdout, stderr) in outputs {
        let fixture = Fixture::new();
        let out = stdout.to_vec();
        let err = stderr.to_vec();
        let calls = Rc::new(Cell::new(0));
        let seen = calls.clone();
        let mut producer = fixture.producer(move |query, _| {
            seen.set(seen.get() + 1);
            if query == Query::RootTranslations {
                Ok(output(&out, &err, Some(0)))
            } else {
                valid_component_output(query)
            }
        });
        producer.components = Some(native_schema::Components::new(
            native_schema::fixture_schema(),
        ));
        let end = until();
        producer.collect(end);
        let observed = producer.finish(end);
        assert_eq!(calls.get(), Query::ALL.len());
        assert_eq!(
            observed.queries.last().unwrap().query,
            Query::RootTranslations
        );
        assert!(matches!(
            observed.primary_refusal.unwrap().reason,
            Reason::NativeSchema(_)
        ));
        assert_no_readiness(&observed);
    }
}
#[test]
fn root_translation_failed_incomplete_oversize_or_late_command_never_publishes_empty_output() {
    for failure in 0..9 {
        let fixture = Fixture::new();
        let outer = until();
        let (binding, _identity, live, stop) = readonly_session_fixture(outer);
        let mut owner = retained_fixture_bound(
            &fixture,
            outer,
            Some(binding),
            move |query, end| {
                if query != Query::RootTranslations {
                    return valid_component_output(query);
                }
                match failure {
                    0 => Err(CommandFailure::OwnershipUnknown),
                    1 => Err(CommandFailure::OutputLimit),
                    2 => Err(CommandFailure::Timeout),
                    3 => Err(CommandFailure::Io),
                    4 => Err(CommandFailure::Unavailable),
                    5 => Ok(output(b"", b"", Some(1))),
                    6 => Ok(output(b"", b"", None)),
                    7 => Ok(output(&vec![b'x'; MAX_OUTPUT + 1], b"", Some(0))),
                    _ => {
                        std::thread::sleep(
                            end.saturating_duration_since(Instant::now())
                                + Duration::from_millis(1),
                        );
                        Ok(output(b"", b"", Some(0)))
                    }
                }
            },
            || Ok(()),
        );
        let requested = if failure == 8 {
            Instant::now() + Duration::from_millis(100)
        } else {
            outer
        };
        assert!(owner.require_fixture_health_until(requested).is_err());
        assert_no_readiness(&owner.producer.observation);
        assert_eq!(
            owner.producer.observation.queries.last().unwrap().query,
            Query::RootTranslations
        );
        assert!(
            !live.load(Ordering::SeqCst)
                && stop.load(Ordering::SeqCst)
                && owner.terminal.load(Ordering::SeqCst)
        );
    }
}
#[test]
fn retained_root_translation_snapshot_clears_on_later_seventh_query_refusal_without_reopen_or_retry(
) {
    let fixture = Fixture::new();
    let end = until();
    let (binding, _identity, live, stop) = readonly_session_fixture(end);
    let calls = Rc::new(Cell::new(0));
    let seen = calls.clone();
    let sentinel = b"DO_NOT_DISCLOSE_ROOT_TRANSLATION_STREAM";
    let mut owner = retained_fixture_bound(
        &fixture,
        end,
        Some(binding),
        move |query, _| {
            seen.set(seen.get() + 1);
            if query == Query::RootTranslations && seen.get() > Query::ALL.len() {
                Ok(output(sentinel, b"", Some(0)))
            } else {
                valid_component_output(query)
            }
        },
        || Ok(()),
    );
    owner.require_fixture_health_until(end).unwrap();
    assert_eq!(
        owner.producer.observation.root_translation_output,
        Some(native_schema::RootTranslationOutput::EmptyAtSnapshot)
    );
    let originals = retained_identities(&owner);
    assert!(owner.require_fixture_health_until(end).is_err());
    assert_eq!(calls.get(), 2 * Query::ALL.len());
    assert_no_readiness(&owner.producer.observation);
    assert_eq!(
        owner
            .producer
            .components
            .as_ref()
            .unwrap()
            .root_translation_output(),
        None
    );
    assert!(!format!("{:?}", owner.producer.observation)
        .contains(std::str::from_utf8(sentinel).unwrap()));
    assert!(!live.load(Ordering::SeqCst) && stop.load(Ordering::SeqCst));
    assert!(owner
        .require_fixture_health_until(end + OVERALL_LIMIT)
        .is_err());
    assert_eq!(calls.get(), 2 * Query::ALL.len());
    assert_eq!(retained_identities(&owner), originals);
}
#[test]
fn root_translation_empty_output_cannot_hide_later_original_context_or_session_loss() {
    for failure in 0..3 {
        let fixture = Fixture::new();
        let end = until();
        let (binding, _identity, live, stop) = readonly_session_fixture(end);
        let changed_live = live.clone();
        let valid = Rc::new(Cell::new(true));
        let context = valid.clone();
        let changed_path = fixture.path(Role::LlmPolicy);
        let mut owner = retained_fixture_bound(
            &fixture,
            end,
            Some(binding),
            move |query, _| {
                if query == Query::RootTranslations {
                    match failure {
                        0 => {
                            std::fs::write(&changed_path, b"changed after empty translation output")
                                .unwrap()
                        }
                        1 => valid.set(false),
                        _ => changed_live.store(false, Ordering::SeqCst),
                    }
                }
                valid_component_output(query)
            },
            move || {
                if context.get() {
                    Ok(())
                } else {
                    Err(err!(ESTALE, "FIXTURE_AFTER_TRANSLATION_CONTEXT_LOSS"))
                }
            },
        );
        assert!(owner.require_fixture_health_until(end).is_err());
        assert_no_readiness(&owner.producer.observation);
        assert_eq!(
            owner.producer.observation.queries.last().unwrap().query,
            Query::RootTranslations
        );
        assert!(!live.load(Ordering::SeqCst) && stop.load(Ordering::SeqCst));
    }
}
#[test]
fn unqualified_schema_cannot_turn_complete_empty_root_translation_output_into_a_diagnostic() {
    let fixture = Fixture::new();
    let mut producer = fixture.producer(|query, _| valid_component_output(query));
    assert!(producer.components.is_none());
    let end = until();
    producer.collect(end);
    let observed = producer.finish(end);
    assert_eq!(observed.queries.len(), Query::ALL.len());
    assert!(observed.collection_complete);
    assert_no_readiness(&observed);
    assert_eq!(observed.root_translation_output, None);
    assert!(matches!(
        native_schema::SupportedSchema::from_original(&[0; 32], native_schema::TOOL_SIZE),
        Err(native_schema::Error::UnsupportedTool)
    ));
}

// Synthetic negative notification window for SOFTWARE producer-boundary tests.
// It cannot construct or impersonate the native borrowed Resources owner.
struct FixtureCollection {
    binding: Option<Arc<ReadOnlySessionBinding>>,
    generation: Rc<Cell<u64>>,
    observed: u64,
    checks: Rc<Cell<usize>>,
    panic_at: Option<usize>,
    end: Instant,
    armed: bool,
}
impl FixtureCollection {
    fn new(owner: &RetainedReadOnlyOwner, end: Instant) -> Self {
        Self {
            binding: owner.producer.retained_session.clone(),
            generation: Rc::new(Cell::new(0)),
            observed: 0,
            checks: Rc::new(Cell::new(0)),
            panic_at: None,
            end: end.min(owner.original_enclosing_end),
            armed: true,
        }
    }
    fn veto(&self) {
        if let Some(binding) = &self.binding {
            binding.veto();
        }
    }
}
impl super::super::pf_watch::NegativeCollectionCheck for FixtureCollection {
    fn require_current(&self, end: Instant) -> EnclaveResult<()> {
        let check = self.checks.get() + 1;
        self.checks.set(check);
        if self.panic_at == Some(check) {
            panic!("synthetic notification-window unwind");
        }
        if self.generation.get() != self.observed || Instant::now() >= end.min(self.end) {
            self.veto();
            return Err(err!(EACCES, "FIXTURE_COLLECTION_CHANGED"));
        }
        if let Some(binding) = &self.binding {
            if binding.current(end.min(self.end)).is_err() {
                self.veto();
                return Err(err!(EACCES, "FIXTURE_COLLECTION_BINDING"));
            }
        }
        Ok(())
    }
    fn require_same_original(
        &self,
        _session: &Arc<crate::power::selected_owner_session::SelectedOwnerSession>,
        _stop: &Arc<AtomicBool>,
        _end: Instant,
    ) -> EnclaveResult<()> {
        Err(err!(EACCES, "FIXTURE_CANNOT_BIND_NATIVE_COLLECTION"))
    }
    fn complete(mut self, end: Instant) -> EnclaveResult<()> {
        super::super::pf_watch::NegativeCollectionCheck::require_current(&self, end)?;
        self.armed = false;
        Ok(())
    }
}
impl Drop for FixtureCollection {
    fn drop(&mut self) {
        if self.armed {
            self.veto();
        }
    }
}
impl RetainedReadOnlyOwner {
    fn require_fixture_health_until(&mut self, end: Instant) -> EnclaveResult<()> {
        let collection = FixtureCollection::new(self, end);
        self.require_health_until(end, &collection)?;
        super::super::pf_watch::NegativeCollectionCheck::complete(collection, end)
    }
}
#[test]
fn mandatory_collection_window_generation_loss_during_query_stops_before_interpretation_or_next_command(
) {
    let fixture = Fixture::new();
    let end = until();
    let (binding, _identity, live, stop) = readonly_session_fixture(end);
    let generation = Rc::new(Cell::new(0));
    let changed = generation.clone();
    let calls = Rc::new(Cell::new(0));
    let seen = calls.clone();
    let mut owner = retained_fixture_bound(
        &fixture,
        end,
        Some(binding),
        move |query, _| {
            seen.set(seen.get() + 1);
            changed.set(changed.get() + 1);
            valid_component_output(query)
        },
        || Ok(()),
    );
    let originals = retained_identities(&owner);
    let mut collection = FixtureCollection::new(&owner, end);
    collection.generation = generation;
    assert!(owner.require_health_until(end, &collection).is_err());
    assert_eq!(calls.get(), 1);
    assert_eq!(owner.producer.observation.queries.len(), 1);
    assert!(owner.producer.observation.queries[0].stdout.is_none());
    assert!(owner.producer.observation.queries[0].stderr.is_none());
    assert!(!live.load(Ordering::SeqCst) && stop.load(Ordering::SeqCst));
    assert_no_readiness(&owner.producer.observation);
    assert_eq!(retained_identities(&owner), originals);
    assert!(owner.require_health_until(end, &collection).is_err());
    assert_eq!(calls.get(), 1);
}
#[test]
fn mandatory_collection_window_generation_loss_inside_original_boundary_prevents_first_command() {
    let fixture = Fixture::new();
    let end = until();
    let (binding, _identity, live, stop) = readonly_session_fixture(end);
    let generation = Rc::new(Cell::new(0));
    let changed = generation.clone();
    let enable = Rc::new(Cell::new(false));
    let enabled = enable.clone();
    let calls = Rc::new(Cell::new(0));
    let seen = calls.clone();
    let mut owner = retained_fixture_bound(
        &fixture,
        end,
        Some(binding),
        move |query, _| {
            seen.set(seen.get() + 1);
            valid_component_output(query)
        },
        move || {
            if enabled.get() {
                changed.set(changed.get() + 1);
            }
            Ok(())
        },
    );
    let mut collection = FixtureCollection::new(&owner, end);
    collection.generation = generation;
    enable.set(true);
    assert!(owner.require_health_until(end, &collection).is_err());
    assert_eq!(calls.get(), 0);
    assert!(!live.load(Ordering::SeqCst) && stop.load(Ordering::SeqCst));
    assert_no_readiness(&owner.producer.observation);
}
#[test]
fn mandatory_collection_window_final_generation_loss_withholds_all_component_publication() {
    let fixture = Fixture::new();
    let end = until();
    let (binding, _identity, live, stop) = readonly_session_fixture(end);
    let generation = Rc::new(Cell::new(0));
    let changed = generation.clone();
    let contexts = Rc::new(Cell::new(0));
    let checked = contexts.clone();
    let trigger = Rc::new(Cell::new(usize::MAX));
    let trip = trigger.clone();
    let calls = Rc::new(Cell::new(0));
    let seen = calls.clone();
    let mut owner = retained_fixture_bound(
        &fixture,
        end,
        Some(binding),
        move |query, _| {
            seen.set(seen.get() + 1);
            valid_component_output(query)
        },
        move || {
            let n = checked.get() + 1;
            checked.set(n);
            if n == trip.get() {
                changed.set(1);
            }
            Ok(())
        },
    );
    trigger.set(contexts.get() + 2 * Query::ALL.len() + 1);
    let mut collection = FixtureCollection::new(&owner, end);
    collection.generation = generation;
    assert!(owner.require_health_until(end, &collection).is_err());
    assert_eq!(calls.get(), Query::ALL.len());
    assert!(!live.load(Ordering::SeqCst) && stop.load(Ordering::SeqCst));
    assert_no_readiness(&owner.producer.observation);
    assert_eq!(owner.producer.observation.root_translation_output, None);
}
#[test]
fn mandatory_collection_window_caught_check_unwind_vetoes_session_before_recovery() {
    let fixture = Fixture::new();
    let end = until();
    let (binding, _identity, live, stop) = readonly_session_fixture(end);
    let calls = Rc::new(Cell::new(0));
    let seen = calls.clone();
    let mut owner = retained_fixture_bound(
        &fixture,
        end,
        Some(binding),
        move |query, _| {
            seen.set(seen.get() + 1);
            valid_component_output(query)
        },
        || Ok(()),
    );
    let mut collection = FixtureCollection::new(&owner, end);
    collection.panic_at = Some(3);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || owner.require_health_until(end, &collection)
    ))
    .is_err());
    assert_eq!(calls.get(), 1);
    assert!(!live.load(Ordering::SeqCst) && stop.load(Ordering::SeqCst));
    assert!(owner.terminal.load(Ordering::SeqCst));
    assert!(owner.require_fixture_health_until(end).is_err());
    assert_eq!(calls.get(), 1);
}

#[test]
fn mandatory_collection_window_loss_preserves_owned_command_failure_and_exit_without_interpreting_pf_bytes(
) {
    let failures = [
        CommandFailure::Unavailable,
        CommandFailure::Timeout,
        CommandFailure::OutputLimit,
        CommandFailure::Io,
        CommandFailure::OwnershipUnknown,
    ];
    for case in 0..8 {
        let fixture = Fixture::new();
        let end = until();
        let (binding, _identity, live, stop) = readonly_session_fixture(end);
        let generation = Rc::new(Cell::new(0));
        let changed = generation.clone();
        let calls = Rc::new(Cell::new(0));
        let seen = calls.clone();
        let mut owner = retained_fixture_bound(
            &fixture,
            end,
            Some(binding),
            move |_, _| {
                seen.set(seen.get() + 1);
                changed.set(changed.get() + 1);
                if case < failures.len() {
                    Err(failures[case])
                } else {
                    Ok(CommandOutput {
                        code: match case {
                            5 => Some(9),
                            6 => None,
                            _ => Some(0),
                        },
                        stdout: b"SENTINEL_UNINTERPRETED_PF_BYTES".to_vec(),
                        stderr: b"SENTINEL_DIAGNOSTIC".to_vec(),
                    })
                }
            },
            || Ok(()),
        );
        let mut collection = FixtureCollection::new(&owner, end);
        collection.generation = generation;
        assert!(owner.require_health_until(end, &collection).is_err());
        assert_eq!(calls.get(), 1);
        let observed = &owner.producer.observation;
        assert_eq!(observed.queries.len(), 1);
        assert!(observed.queries[0].stdout.is_none() && observed.queries[0].stderr.is_none());
        let reasons: Vec<_> = observed
            .primary_refusal
            .iter()
            .chain(observed.boundary_refusals.iter())
            .chain(observed.final_refusals.iter())
            .map(|refusal| refusal.reason)
            .collect();
        assert!(reasons.contains(&Reason::NotificationWindowRefused));
        if case < failures.len() {
            assert_eq!(observed.queries[0].failure, Some(failures[case]));
            assert!(reasons.contains(&Reason::QueryFailed(failures[case])));
        } else {
            assert_eq!(observed.queries[0].failure, None);
            assert_eq!(
                observed.queries[0].exit,
                match case {
                    5 => Some(9),
                    6 => None,
                    _ => Some(0),
                }
            );
            assert_eq!(reasons.contains(&Reason::QueryExit), case != 7);
        }
        assert_no_readiness(observed);
        assert!(!live.load(Ordering::SeqCst) && stop.load(Ordering::SeqCst));
        assert!(owner.require_health_until(end, &collection).is_err());
        assert_eq!(calls.get(), 1);
    }
}
