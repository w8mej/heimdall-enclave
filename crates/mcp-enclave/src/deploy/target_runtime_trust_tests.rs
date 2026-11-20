use super::*;
use enclave_core::deployment::{DeploymentBroker, DeploymentLayout, DeploymentSigningMode};
use serde_json::{json, Value};

fn target(profile: Profile, role: DeploymentRole) -> DeploymentTarget {
    let root = Path::new("/runtime-trust-fixtures/selected");
    let layout = DeploymentLayout {
        binary_dir: root.join("bin"),
        custody_bundle: root.join("support/Custody.app"),
        sandbox_dir: root.join("sandbox"),
        socket_root: root.join("run"),
        state_root: root.join("state"),
        audit_root: root.join("audit"),
        cas_store_root: root.join("cas"),
        staging_root: root.join("stage"),
        support_root: root.join("support"),
        launchd_namespace: "com.depot.runtimefixture".into(),
        mach_service: "com.depot.runtimefixture.exception".into(),
    };
    let broker = (profile == Profile::L3).then(|| DeploymentBroker {
        base_dir: layout.state_root.join("apfs-broker"),
        tuf_root_file: layout
            .support_root
            .join("independent-broker-runtime-root.json"),
    });
    DeploymentTarget {
        version: 1,
        target_id: "runtimefixture".into(),
        role,
        profile,
        authority_config: root.join("support/authority.json"),
        expected_artifacts_manifest: root.join("support/artifacts.json"),
        codesign_pins_file: root.join("support/pins.json"),
        signing_identity_mode: DeploymentSigningMode::LocalPins,
        layout,
        broker,
        shared_read_only_inputs: vec![],
    }
}
fn document(value: Value) -> Vec<u8> {
    serde_json::to_vec(&value).unwrap()
}
fn metadata(role: &str, version: u64) -> Vec<u8> {
    // Deliberately unsigned and expired: these are schema-only inventory
    // fixtures and must NEVER become authenticated just because a plan exists.
    let mut signed = json!({"_type":role,"spec_version":"1.0.31","version":version,
        "expires":"2000-01-01T00:00:00Z"});
    match role {
        "root" => {
            signed["keys"] = json!({});
            signed["roles"] = json!({});
        }
        "targets" => {
            signed["targets"] = json!({});
        }
        _ => {
            signed["meta"] = json!({});
        }
    }
    document(json!({"signed":signed,"signatures":[]}))
}
fn files(profile: Profile) -> Vec<(String, Vec<u8>)> {
    let mds = br#"{"entries":[]}"#.to_vec();
    let config = EnclaveHostConfig {
        profile_floor: profile,
        ifc_grant_public_key: "01".repeat(32),
        calibration_corpus_digest: "02".repeat(32),
        vk_digest: "03".repeat(32),
        depot_lock_digest: "04".repeat(32),
        fido_mds_allowlist_digest: blake3::hash(&mds).to_hex().to_string(),
        ohttp_key_config: None,
        codesign_pins: None,
    };
    let envelope = json!({"policy":{"version":1,"revision":1,"subject":"synthetic-host",
        "namespace":"synthetic-namespace","issued_unix":1,"expires_unix":2,"review_unix":2,
        "owner":"fixture","profiles":[profile],"data_classes":["C3","C4"],
        "purpose":"fixture","migration":"fixture","disclosure":null,"classical_exception":false},
        "signature":[]});
    vec![
        ("root.json".into(), metadata("root", 1)),
        ("timestamp.json".into(), metadata("timestamp", 1)),
        ("snapshot.json".into(), metadata("snapshot", 1)),
        ("targets.json".into(), metadata("targets", 1)),
        (HOST_CONFIG_TARGET.into(), config.to_json_bytes().unwrap()),
        (FIDO_MDS_TARGET.into(), mds),
        (
            CustodyTarget::EnvelopePolicy.target_name().into(),
            document(envelope),
        ),
    ]
}
fn describe_files(
    target: &DeploymentTarget,
    files: &[(String, Vec<u8>)],
) -> EnclaveResult<RuntimeTrustPlan> {
    let sources: Vec<_> = files
        .iter()
        .map(|(name, _)| target.layout.staging_root.join("tuf/repo").join(name))
        .collect();
    let hashes: Vec<_> = files
        .iter()
        .map(|(_, bytes)| hex::encode(Sha256::digest(bytes)))
        .collect();
    let inputs: Vec<_> = files
        .iter()
        .enumerate()
        .map(|(i, (_, bytes))| RuntimeTrustInput {
            source: &sources[i],
            inventory_sha256: &hashes[i],
            inventory_size: bytes.len() as u64,
            bytes,
        })
        .collect();
    describe(target, &"ab".repeat(32), &inputs)
}
fn edit(files: &mut [(String, Vec<u8>)], name: &str, change: impl FnOnce(&mut Value)) {
    let bytes = &mut files.iter_mut().find(|(n, _)| n == name).unwrap().1;
    let mut value = serde_json::from_slice(bytes).unwrap();
    change(&mut value);
    *bytes = document(value);
}

#[test]
fn actual_runtime_routes_keep_candidate_roots_diagnostic_mds_and_release_authority_separate() {
    for profile in [Profile::L2, Profile::L3] {
        for role in [
            DeploymentRole::DedicatedTest,
            DeploymentRole::ExistingUpgrade,
        ] {
            let target = target(profile, role);
            let plan = describe_files(&target, &files(profile)).unwrap();
            assert!(plan.supplied_inputs_complete);
            assert!(!plan.apply_supported);
            assert_eq!(plan.readiness, "NOT_QUALIFIED");
            assert_eq!(plan.authentication, "UNVERIFIED");
            assert_eq!(plan.host_mds_binding, "MATCHES_UNAUTHENTICATED_BYTES");
            let expected_pin = target
                .broker
                .as_ref()
                .map(|b| b.tuf_root_file.clone())
                .unwrap_or_else(|| target.layout.support_root.join("tuf/root.json"));
            assert_eq!(plan.runtime_pin_file, expected_pin);
            assert_eq!(
                plan.repository,
                target.layout.state_root.join("cas/tuf/repo")
            );
            assert_eq!(plan.cas_state, target.layout.state_root.join("cas"));
            assert_eq!(plan.cas_store, target.layout.cas_store_root);
            assert_eq!(
                plan.diagnostic_mds_file,
                target.layout.support_root.join("fido-mds.json")
            );
            for entry in &plan.inputs {
                assert_eq!(entry.authentication, "UNVERIFIED");
                assert_ne!(
                    entry.proposed_transport_path.as_ref(),
                    Some(&plan.runtime_pin_file)
                );
                match entry.role {
                    RuntimeInputRole::RootCandidate => {
                        assert!(entry.proposed_transport_path.is_none())
                    }
                    RuntimeInputRole::HostConfiguration
                    | RuntimeInputRole::FidoMetadata
                    | RuntimeInputRole::EnvelopePolicy => assert_eq!(
                        entry.proposed_transport_path,
                        Some(target.layout.cas_store_root.join(&entry.name))
                    ),
                    _ => assert_eq!(
                        entry.proposed_transport_path,
                        Some(plan.repository.join(&entry.name))
                    ),
                }
            }
            let serialized = serde_json::to_value(&plan).unwrap();
            assert_eq!(serialized["role"], serde_json::to_value(role).unwrap());
            assert_eq!(
                serialized["release_approval_scope"],
                "software_release_only_never_runtime_root_or_policy_authority"
            );
            assert_eq!(
                serialized["required_verification"]
                    .as_array()
                    .unwrap()
                    .len(),
                5
            );
        }
    }
}

#[test]
fn complete_unsigned_expired_schema_never_authenticates_or_issues_a_trust_capability() {
    let target = target(Profile::L2, DeploymentRole::DedicatedTest);
    let supplied = files(Profile::L2);
    let plan = describe_files(&target, &supplied).unwrap();
    assert!(plan.supplied_inputs_complete);
    assert!(enclave_crypto::tuf::TufClient::bootstrap(&supplied[0].1).is_err());
    assert!(plan.inputs.iter().all(|i| i.authentication == "UNVERIFIED"));
    assert_eq!(plan.readiness, "NOT_QUALIFIED");
    assert!(!plan.apply_supported);
}

#[test]
fn missing_real_mds_or_envelope_is_reported_and_diagnostic_or_other_role_cannot_substitute() {
    let target = target(Profile::L2, DeploymentRole::DedicatedTest);
    let empty = describe_files(&target, &[]).unwrap();
    assert!(!empty.supplied_inputs_complete);
    assert_eq!(empty.missing_required_sources.len(), 7);
    let mut partial = files(Profile::L2);
    partial.retain(|(name, _)| {
        name != FIDO_MDS_TARGET && name != CustodyTarget::EnvelopePolicy.target_name()
    });
    let plan = describe_files(&target, &partial).unwrap();
    assert_eq!(plan.host_mds_binding, "MISSING_INPUTS_UNVERIFIED");
    assert!(!plan.supplied_inputs_complete);
    assert_eq!(
        plan.missing_required_sources,
        vec![
            target
                .layout
                .staging_root
                .join("tuf/repo")
                .join(FIDO_MDS_TARGET),
            target
                .layout
                .staging_root
                .join("tuf/repo")
                .join(CustodyTarget::EnvelopePolicy.target_name())
        ]
    );
    for unsupported in [
        "fido-mds/yubico.json",
        "fido-mds.json",
        "custody-oidc-authority-v1.json",
        "enclave-distribution-v1.json",
        "enclave-policy.cedar.v1.json",
        "enclave-calib-eval-v1.jsonl",
    ] {
        assert!(
            describe_files(&target, &[(unsupported.into(), b"{}".to_vec())]).is_err(),
            "{unsupported}"
        );
    }
}

#[test]
fn exact_source_binding_rejects_other_targets_traversal_aliases_duplicates_and_inventory_drift() {
    let target = target(Profile::L2, DeploymentRole::DedicatedTest);
    let data = metadata("root", 1);
    let good_source = target.layout.staging_root.join("tuf/repo/root.json");
    let hash = hex::encode(Sha256::digest(&data));
    for source in [
        PathBuf::from("/another-target/stage/tuf/repo/root.json"),
        target.layout.staging_root.join("tuf/repo/../root.json"),
        target.layout.staging_root.join("tuf/repo/nested/root.json"),
        target.layout.staging_root.join("tuf/repo/ROOT.json"),
    ] {
        let input = RuntimeTrustInput {
            source: &source,
            inventory_sha256: &hash,
            inventory_size: data.len() as u64,
            bytes: &data,
        };
        assert!(describe(&target, &"ab".repeat(32), &[input]).is_err());
    }
    for (digest, size, bytes) in [
        ("00".repeat(32), data.len() as u64, data.as_slice()),
        (hash.clone(), data.len() as u64 + 1, data.as_slice()),
        (hash.clone(), data.len() as u64, b"{}".as_slice()),
    ] {
        let input = RuntimeTrustInput {
            source: &good_source,
            inventory_sha256: &digest,
            inventory_size: size,
            bytes,
        };
        assert!(describe(&target, &"ab".repeat(32), &[input])
            .unwrap_err()
            .is("RUNTIME_TRUST_INVENTORY_BINDING"));
    }
    let input = || RuntimeTrustInput {
        source: &good_source,
        inventory_sha256: &hash,
        inventory_size: data.len() as u64,
        bytes: &data,
    };
    assert!(describe(&target, &"ab".repeat(32), &[input(), input()])
        .unwrap_err()
        .is("RUNTIME_TRUST_DUPLICATE_INPUT"));
    assert!(describe(&target, "not-a-descriptor-digest", &[])
        .unwrap_err()
        .is("RUNTIME_TRUST_DESCRIPTOR_DIGEST"));
}

#[test]
fn supported_os_aliases_accept_actual_inventory_routes_and_preserve_unverified_source_spelling() {
    let bytes = metadata("root", 1);
    let hash = hex::encode(Sha256::digest(&bytes));
    let descriptor = "ab".repeat(32);
    for profile in [Profile::L2, Profile::L3] {
        for role in [
            DeploymentRole::DedicatedTest,
            DeploymentRole::ExistingUpgrade,
        ] {
            for top in ["var", "tmp", "etc"] {
                let alias = Path::new("/")
                    .join(top)
                    .join("runtime-trust-fixtures/selected/stage");
                let canonical = Path::new("/private")
                    .join(top)
                    .join("runtime-trust-fixtures/selected/stage");
                for staging in [&alias, &canonical] {
                    let mut target = target(profile, role);
                    target.layout.staging_root = (*staging).clone();
                    // Actual target_plan requires the canonical inventory root
                    // and emits its retained source from that same route.
                    let inventory = document(
                        json!({"version":1,"kind":"depot-first-touch-artifact-inventory",
                        "target_id":target.target_id,"profile":profile,"signing_identity_mode":target.signing_identity_mode,
                        "deployment_config_sha256":descriptor,"source_git_commit":"a".repeat(40),
                        "source_manifest_sha256":"b".repeat(64),"source_input_count":1,
                        "codesign_pins_sha256":"c".repeat(64),"staging_root":canonical,"external_provenance":"UNKNOWN",
                        "files":[{"path":"bin/depot-enclave","sha256":"d".repeat(64),"size":1},
                            {"path":"codesign-pins.json","sha256":"c".repeat(64),"size":1},
                            {"path":"tuf/repo/root.json","sha256":hash,"size":bytes.len()}]}),
                    );
                    let install =
                        crate::deploy::target_plan::describe(&target, &descriptor, &inventory)
                            .unwrap();
                    let retained = install
                        .retained_in_staging
                        .iter()
                        .find(|entry| entry.source.ends_with("tuf/repo/root.json"))
                        .unwrap();
                    assert_eq!(retained.source, canonical.join("tuf/repo/root.json"));
                    let alias_source = alias.join("tuf/repo/root.json");
                    for source in [&retained.source, &alias_source] {
                        let input = RuntimeTrustInput {
                            source,
                            inventory_sha256: &retained.sha256,
                            inventory_size: retained.size,
                            bytes: &bytes,
                        };
                        let plan = describe(&target, &descriptor, &[input]).unwrap();
                        assert_eq!(plan.inputs.len(), 1);
                        let entry = &plan.inputs[0];
                        assert_eq!(entry.role, RuntimeInputRole::RootCandidate);
                        assert_eq!(&entry.source, source);
                        assert_eq!(entry.sha256, hash);
                        assert!(entry.proposed_transport_path.is_none());
                        assert_eq!(entry.authentication, "UNVERIFIED");
                        assert!(!plan.supplied_inputs_complete && !plan.apply_supported);
                        assert_eq!(plan.authentication, "UNVERIFIED");
                        assert_eq!(plan.readiness, "NOT_QUALIFIED");
                        assert_eq!(
                            plan.missing_required_sources,
                            REQUIRED
                                .into_iter()
                                .filter(|name| *name != "root.json")
                                .map(|name| canonical.join("tuf/repo").join(name))
                                .collect::<Vec<_>>()
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn normalized_os_alias_routes_still_refuse_foreign_prefixes_and_duplicate_roles() {
    let bytes = metadata("root", 1);
    let hash = hex::encode(Sha256::digest(&bytes));
    for top in ["var", "tmp", "etc"] {
        let alias = Path::new("/")
            .join(top)
            .join("runtime-trust-fixtures/selected/stage");
        let canonical = Path::new("/private")
            .join(top)
            .join("runtime-trust-fixtures/selected/stage");
        for staging in [&alias, &canonical] {
            let mut target = target(Profile::L2, DeploymentRole::DedicatedTest);
            target.layout.staging_root = (*staging).clone();
            for source in [
                Path::new("/private")
                    .join(top)
                    .join("runtime-trust-fixtures/foreign/stage/tuf/repo/root.json"),
                Path::new("/")
                    .join(top)
                    .join("runtime-trust-fixtures/foreign/stage/tuf/repo/root.json"),
                canonical
                    .with_file_name("stage-sibling")
                    .join("tuf/repo/root.json"),
                alias
                    .with_file_name("stage-sibling")
                    .join("tuf/repo/root.json"),
                PathBuf::from(
                    "/arbitrary-alias/runtime-trust-fixtures/selected/stage/tuf/repo/root.json",
                ),
            ] {
                let input = RuntimeTrustInput {
                    source: &source,
                    inventory_sha256: &hash,
                    inventory_size: bytes.len() as u64,
                    bytes: &bytes,
                };
                assert!(describe(&target, &"ab".repeat(32), &[input])
                    .unwrap_err()
                    .is("RUNTIME_TRUST_SOURCE_ROUTE"));
            }
            let alias_source = alias.join("tuf/repo/root.json");
            let canonical_source = canonical.join("tuf/repo/root.json");
            let inputs = [&alias_source, &canonical_source].map(|source| RuntimeTrustInput {
                source,
                inventory_sha256: &hash,
                inventory_size: bytes.len() as u64,
                bytes: &bytes,
            });
            assert!(describe(&target, &"ab".repeat(32), &inputs)
                .unwrap_err()
                .is("RUNTIME_TRUST_DUPLICATE_INPUT"));
        }
    }
}

#[test]
fn metadata_role_and_numbered_root_version_checks_cannot_be_avoided_with_matching_inventory_hashes()
{
    let target = target(Profile::L2, DeploymentRole::DedicatedTest);
    for (name, body) in [
        ("timestamp.json", metadata("snapshot", 1)),
        ("snapshot.json", metadata("timestamp", 1)),
        ("root.json", metadata("timestamp", 1)),
        ("targets.json", metadata("root", 1)),
        ("2.root.json", metadata("root", 3)),
        ("root.json", metadata("root", 0)),
    ] {
        assert!(
            describe_files(&target, &[(name.into(), body)]).is_err(),
            "{name}"
        );
    }
    for name in [
        "0.root.json",
        "01.root.json",
        "+1.root.json",
        "2147483648.root.json",
        ".root.json",
    ] {
        assert!(
            describe_files(&target, &[(name.into(), metadata("root", 1))])
                .unwrap_err()
                .is("RUNTIME_TRUST_ROOT_NAME")
        );
    }
    let roots = vec![
        ("3.root.json".into(), metadata("root", 3)),
        ("2.root.json".into(), metadata("root", 2)),
    ];
    let plan = describe_files(&target, &roots).unwrap();
    assert_eq!(
        plan.inputs
            .iter()
            .map(|i| i.name.as_str())
            .collect::<Vec<_>>(),
        ["2.root.json", "3.root.json"]
    );
    assert!(plan
        .inputs
        .iter()
        .all(|i| i.role == RuntimeInputRole::RootRotation));
    assert!(!plan.supplied_inputs_complete);
    // Consecutiveness relative to the real current root remains actual CAS work.
}

#[test]
fn typed_payload_profile_and_exact_mds_cross_binding_refuse_consistent_inventory_substitutions() {
    let target = target(Profile::L2, DeploymentRole::DedicatedTest);
    let mut supplied = files(Profile::L2);
    edit(&mut supplied, HOST_CONFIG_TARGET, |v| {
        v["profile_floor"] = json!(Profile::L3)
    });
    assert!(describe_files(&target, &supplied)
        .unwrap_err()
        .is("HOST_PROFILE_BELOW_FLOOR"));
    let mut supplied = files(Profile::L2);
    edit(
        &mut supplied,
        CustodyTarget::EnvelopePolicy.target_name(),
        |v| v["policy"]["profiles"] = json!([Profile::L3]),
    );
    assert!(describe_files(&target, &supplied)
        .unwrap_err()
        .is("RUNTIME_TRUST_ENVELOPE_PROFILE"));
    let mut supplied = files(Profile::L2);
    edit(&mut supplied, HOST_CONFIG_TARGET, |v| {
        v["fido_mds_allowlist_digest"] = json!("00".repeat(32))
    });
    assert!(describe_files(&target, &supplied)
        .unwrap_err()
        .is("RUNTIME_TRUST_MDS_CONFIG_DIGEST"));
    for (name, expected) in [
        (FIDO_MDS_TARGET, "RUNTIME_TRUST_MDS_SCHEMA"),
        (
            CustodyTarget::EnvelopePolicy.target_name(),
            "RUNTIME_TRUST_ENVELOPE_SCHEMA",
        ),
    ] {
        let mut supplied = files(Profile::L2);
        supplied.iter_mut().find(|(n, _)| n == name).unwrap().1 = b"{}".to_vec();
        assert!(describe_files(&target, &supplied).unwrap_err().is(expected));
    }
}

#[test]
fn runtime_pin_cannot_alias_protected_inputs_or_fixed_control_and_diagnostic_roles() {
    for field in ["authority", "inventory", "codesign", "bundle"] {
        let mut target = target(Profile::L2, DeploymentRole::DedicatedTest);
        let pin = target.layout.support_root.join("tuf/root.json");
        match field {
            "authority" => target.authority_config = pin,
            "inventory" => target.expected_artifacts_manifest = pin,
            "codesign" => target.codesign_pins_file = pin,
            _ => target.layout.custody_bundle = target.layout.support_root.join("tuf"),
        }
        target.validate().unwrap();
        assert!(describe_files(&target, &[])
            .unwrap_err()
            .is("RUNTIME_TRUST_PIN_COLLISION"));
    }
    for reserved in [
        STARTUP_LIFETIME_LEAF,
        UPGRADE_INHIBITION_LEAF,
        "fido-mds.json",
        "oidc-broker-identity.json",
        "oidc-oauth.json",
        "EnclaveOIDC.app/Contents/MacOS/enclave-oidc",
    ] {
        let mut l3 = target(Profile::L3, DeploymentRole::DedicatedTest);
        l3.broker.as_mut().unwrap().tuf_root_file = l3.layout.support_root.join(reserved);
        l3.validate().unwrap();
        assert!(
            describe_files(&l3, &[])
                .unwrap_err()
                .is("RUNTIME_TRUST_PIN_COLLISION"),
            "{reserved}"
        );
    }
    let mut invalid = target(Profile::L2, DeploymentRole::DedicatedTest);
    invalid.profile = Profile::L1;
    assert!(describe_files(&invalid, &[])
        .unwrap_err()
        .is("DEPLOYMENT_SCHEMA"));
    let mut overlapping = target(Profile::L2, DeploymentRole::DedicatedTest);
    overlapping.layout.cas_store_root = overlapping.layout.state_root.clone();
    assert!(describe_files(&overlapping, &[])
        .unwrap_err()
        .is("DEPLOYMENT_OUTPUT_OVERLAP"));
}

#[test]
fn actual_consumer_size_bounds_and_selected_inventory_rotation_scope_are_enforced() {
    let target = target(Profile::L2, DeploymentRole::DedicatedTest);
    for (name, maximum) in [
        ("root.json", MAX_METADATA),
        (HOST_CONFIG_TARGET, MAX_HOST_CONFIG_BYTES),
        (FIDO_MDS_TARGET, MAX_MDS_BYTES),
        (
            CustodyTarget::EnvelopePolicy.target_name(),
            CustodyTarget::EnvelopePolicy.max_bytes(),
        ),
    ] {
        assert!(
            describe_files(&target, &[(name.into(), vec![b' '; maximum + 1])])
                .unwrap_err()
                .is("RUNTIME_TRUST_INPUT_SIZE")
        );
        assert!(describe_files(&target, &[(name.into(), vec![])])
            .unwrap_err()
            .is("RUNTIME_TRUST_INPUT_SIZE"));
    }
    let excessive: Vec<_> = (1..=33)
        .map(|v| (format!("{v}.root.json"), metadata("root", v)))
        .collect();
    assert!(describe_files(&target, &excessive)
        .unwrap_err()
        .is("RUNTIME_TRUST_ROOT_CHAIN_LIMIT"));
    let mut large = Vec::new();
    for version in 1..=5 {
        let mut bytes = metadata("root", version);
        bytes.resize(MAX_METADATA, b' ');
        large.push((format!("{version}.root.json"), bytes));
    }
    assert!(describe_files(&target, &large)
        .unwrap_err()
        .is("RUNTIME_TRUST_ROOT_CHAIN_LIMIT"));
}
