//! Pure SOFTWARE recovery fixtures; no filesystem, native capability or effect.
use super::*;
use enclave_core::{
    deployment::{DeploymentBroker, DeploymentSigningMode},
    Profile,
};
use serde_json::{json, Value};

struct Fixture {
    descriptor: Vec<u8>,
    inventory: Vec<u8>,
    journal: Journal,
    observed: Observations,
}
fn target(profile: Profile) -> DeploymentTarget {
    let base = PathBuf::from("/upgrade-fixture");
    let support = base.join("support");
    DeploymentTarget {
        version: 1,
        target_id: "upgrade-fixture".into(),
        role: DeploymentRole::ExistingUpgrade,
        profile,
        authority_config: base.join("authority.json"),
        expected_artifacts_manifest: base.join("inventory.json"),
        codesign_pins_file: support.join("pins.json"),
        signing_identity_mode: DeploymentSigningMode::LocalPins,
        layout: enclave_core::deployment::DeploymentLayout {
            binary_dir: base.join("bin"),
            custody_bundle: support.join("Custody.app"),
            sandbox_dir: base.join("sandbox"),
            socket_root: base.join("run"),
            state_root: base.join("state"),
            audit_root: base.join("audit"),
            cas_store_root: base.join("cas-store"),
            staging_root: base.join("stage"),
            support_root: support.clone(),
            launchd_namespace: "com.mcpmac.upgrade-fixture".into(),
            mach_service: "com.mcpmac.upgrade-fixture.exception".into(),
        },
        broker: (profile == Profile::L3).then(|| DeploymentBroker {
            base_dir: base.join("state/apfs-broker"),
            tuf_root_file: base.join("broker-root.json"),
        }),
        shared_read_only_inputs: vec![],
    }
}
fn paths(profile: Profile) -> Vec<String> {
    let mut files = vec!["codesign-pins.json".into()];
    for executable in [
        "mcp-enclave",
        "enclave-model-runnerd",
        "enclave-swarm-syncd",
        "enclave-apfs-broker",
        "enclave-agent-runtime",
        "enclave-zk-auditor",
        "enclave-cdp-browser",
        "enclave-client-gateway",
        "enclave-intent",
    ] {
        files.push(format!("bin/{executable}"));
    }
    for (bundle, executable) in [
        ("EnclaveCustody.app", "enclave-custody-vaultd"),
        ("EnclaveOIDC.app", "enclave-oidc"),
    ] {
        for member in [
            "Contents/Info.plist".to_owned(),
            "Contents/_CodeSignature/CodeResources".into(),
            format!("Contents/MacOS/{executable}"),
        ] {
            files.push(format!("{bundle}/{member}"));
        }
    }
    for sandbox in [
        "adapter", "cas", "custody", "ifc", "zk", "browser", "gateway",
    ] {
        files.push(format!("launchd/{sandbox}.sb"));
    }
    for job in [
        "adapter",
        "cas",
        "custody",
        "ifc",
        "zk",
        "supervisor",
        "intent",
        "oidc-broker",
        "hydrate",
        "browser",
        "gateway",
    ] {
        files.push(format!("launchd/com.mcpmac.upgrade-fixture.{job}.plist"));
    }
    if profile == Profile::L3 {
        files.push("launchd/com.mcpmac.upgrade-fixture.apfs-broker.plist".into());
    }
    for path in [
        "SHA256SUMS",
        "custody.entitlements",
        "yubikey-transport",
        "install.sh",
        "uninstall.sh",
        "public-trust.sh",
        "fido-mds/yubico.json",
        "launchd/provision-accounts.sh",
        "launchd/enclave-daemon.entitlements",
    ] {
        files.push(path.into());
    }
    for path in [
        "root.json",
        "timestamp.json",
        "snapshot.json",
        "targets.json",
        "enclave-host-config.json",
        "enclave-policy.cedar.v1.json",
        "vk_manifest.json",
        "enclave-distribution-v1.json",
    ] {
        files.push(format!("tuf/repo/{path}"));
    }
    files.sort();
    files
}
impl Fixture {
    fn new(profile: Profile) -> Self {
        let target = target(profile);
        let descriptor = serde_json::to_vec(&target).unwrap();
        let descriptor_sha256 = hex::encode(Sha256::digest(&descriptor));
        let candidate_pins_sha256 = "c".repeat(64);
        let files=paths(profile).into_iter().map(|path|json!({"sha256":if path=="codesign-pins.json" {candidate_pins_sha256.clone()}else{"b".repeat(64)},"path":path,"size":1})).collect::<Vec<_>>();
        let inventory=serde_json::to_vec(&json!({"version":1,"kind":"mcpmac-first-touch-artifact-inventory", "target_id":target.target_id,
            "profile":profile,"signing_identity_mode":target.signing_identity_mode,"deployment_config_sha256":descriptor_sha256,
            "source_git_commit":"a".repeat(40),"source_manifest_sha256":"b".repeat(64),"source_input_count":1,
            "codesign_pins_sha256":candidate_pins_sha256,"staging_root":target.layout.staging_root,"external_provenance":"UNKNOWN","files":files})).unwrap();
        let units = describe_upgrade_public_units(&descriptor, &inventory).unwrap();
        let mut journal = Journal {
            version: 1,
            kind: JOURNAL_KIND.into(),
            target_id: target.target_id,
            descriptor_sha256: hex::encode(Sha256::digest(&descriptor)),
            artifact_inventory_sha256: hex::encode(Sha256::digest(&inventory)),
            transaction_id: String::new(),
            old_pins_sha256: "a".repeat(64),
            candidate_pins_sha256: "c".repeat(64),
            phase: Phase::Prepared,
            units: units
                .into_iter()
                .map(|unit| JournalUnit {
                    unit_id: unit.unit_id,
                    candidate_fingerprint: unit.candidate_fingerprint,
                    original: Original {
                        state: OriginalState::Present,
                        fingerprint: Some("d".repeat(64)),
                    },
                    phase: UnitPhase::Pending,
                })
                .collect(),
        };
        journal.transaction_id = transaction_id(&journal);
        let observed = Observations {
            version: 1,
            kind: OBSERVATION_KIND.into(),
            transaction_id: journal.transaction_id.clone(),
            descriptor_sha256: journal.descriptor_sha256.clone(),
            artifact_inventory_sha256: journal.artifact_inventory_sha256.clone(),
            pins: PinObservation {
                state: ObservedState::Present,
                sha256: Some(journal.old_pins_sha256.clone()),
            },
            units: journal
                .units
                .iter()
                .map(|unit| UnitObservation {
                    unit_id: unit.unit_id.clone(),
                    state: ObservedState::Present,
                    fingerprint: unit.original.fingerprint.clone(),
                })
                .collect(),
        };
        Self {
            descriptor,
            inventory,
            journal,
            observed,
        }
    }
    fn sync_transaction(&mut self) {
        self.journal.transaction_id = transaction_id(&self.journal);
        self.observed.transaction_id = self.journal.transaction_id.clone();
    }
    fn check(&self) -> EnclaveResult<ForwardRecoveryDecision> {
        classify_existing_upgrade_forward(
            &self.descriptor,
            &self.inventory,
            &serde_json::to_vec(&self.journal).unwrap(),
            &serde_json::to_vec(&self.observed).unwrap(),
        )
    }
    fn installed(&mut self, phase: Phase) {
        self.journal.phase = phase;
        for (unit, observed) in self.journal.units.iter_mut().zip(&mut self.observed.units) {
            unit.phase = UnitPhase::Installed;
            observed.state = ObservedState::Present;
            observed.fingerprint = Some(unit.candidate_fingerprint.clone());
        }
    }
    fn candidate_pins(&mut self) {
        self.observed.pins.sha256 = Some(self.journal.candidate_pins_sha256.clone());
    }
    fn journal_value(&self) -> Value {
        serde_json::to_value(&self.journal).unwrap()
    }
    fn observed_value(&self) -> Value {
        serde_json::to_value(&self.observed).unwrap()
    }
    fn check_values(
        &self,
        journal: Value,
        observed: Value,
    ) -> EnclaveResult<ForwardRecoveryDecision> {
        classify_existing_upgrade_forward(
            &self.descriptor,
            &self.inventory,
            &serde_json::to_vec(&journal).unwrap(),
            &serde_json::to_vec(&observed).unwrap(),
        )
    }
}

#[test]
fn fixed_plan_uses_whole_bundles_both_profiles_and_never_mutable_or_pin_units() {
    for profile in [Profile::L2, Profile::L3] {
        let f = Fixture::new(profile);
        let units = describe_upgrade_public_units(&f.descriptor, &f.inventory).unwrap();
        assert_eq!(units.len(), if profile == Profile::L2 { 30 } else { 31 });
        let target = target(profile);
        let mut previous = "";
        for unit in &units {
            assert!(unit.unit_id.as_str() > previous);
            previous = &unit.unit_id;
            assert_ne!(unit.destination, target.codesign_pins_file);
            for root in [
                &target.layout.state_root,
                &target.layout.audit_root,
                &target.layout.socket_root,
                &target.layout.cas_store_root,
            ] {
                assert!(!unit.destination.starts_with(root));
            }
            if unit.unit_id.starts_with("bundle:") {
                assert_eq!(unit.member_count, 3);
                assert_eq!(unit.total_bytes, 3);
            } else {
                assert_eq!(unit.member_count, 1);
            }
        }
        assert_eq!(
            units
                .iter()
                .filter(|u| u.unit_id.starts_with("bundle:"))
                .count(),
            2
        );
        assert!(!units.iter().any(|u| u.unit_id.contains("Contents/")));
        assert_eq!(
            units
                .iter()
                .any(|u| u.unit_id.ends_with("apfs-broker.plist")),
            profile == Profile::L3
        );
    }
}

#[test]
fn prepared_analysis_always_requires_durable_inhibition_and_grants_no_permission() {
    let f = Fixture::new(Profile::L2);
    let decision = f.check().unwrap();
    assert_eq!(decision.next, ForwardAction::PersistReplacingPhase);
    assert!(decision.durable_start_inhibition_required);
    assert!(
        !decision.mutation_allowed && !decision.activation_allowed && !decision.inactivity_proven
    );
    assert!(!decision.installation_supported && !decision.qualified);
    assert!(!decision.pins_equal);
}

#[test]
fn replacement_intent_distinguishes_old_candidate_and_explicit_original_absence() {
    let mut f = Fixture::new(Profile::L2);
    f.journal.phase = Phase::Replacing;
    let id = f.journal.units[0].unit_id.clone();
    assert_eq!(
        f.check().unwrap().next,
        ForwardAction::PersistUnitIntent {
            unit_id: id.clone()
        }
    );
    f.journal.units[0].phase = UnitPhase::ReplaceIntent;
    assert_eq!(
        f.check().unwrap().next,
        ForwardAction::RetryUnitForward {
            unit_id: id.clone()
        }
    );
    f.observed.units[0].fingerprint = Some(f.journal.units[0].candidate_fingerprint.clone());
    assert_eq!(
        f.check().unwrap().next,
        ForwardAction::VerifyAndRecordUnit {
            unit_id: id.clone()
        }
    );
    f.journal.units[0].original = Original {
        state: OriginalState::Absent,
        fingerprint: None,
    };
    f.observed.units[0].state = ObservedState::Absent;
    f.observed.units[0].fingerprint = None;
    f.sync_transaction();
    assert_eq!(
        f.check().unwrap().next,
        ForwardAction::RetryUnitForward { unit_id: id }
    );
}

#[test]
fn completed_prefix_is_preserved_but_later_unknown_blocks_any_forward_proposal() {
    let mut f = Fixture::new(Profile::L3);
    f.journal.phase = Phase::Replacing;
    f.journal.units[0].phase = UnitPhase::Installed;
    f.observed.units[0].fingerprint = Some(f.journal.units[0].candidate_fingerprint.clone());
    f.journal.units[1].phase = UnitPhase::ReplaceIntent;
    f.observed.units[1].fingerprint = Some(f.journal.units[1].candidate_fingerprint.clone());
    assert_eq!(
        f.check().unwrap().next,
        ForwardAction::VerifyAndRecordUnit {
            unit_id: f.journal.units[1].unit_id.clone()
        }
    );
    f.observed.units.last_mut().unwrap().state = ObservedState::Unknown;
    f.observed.units.last_mut().unwrap().fingerprint = None;
    assert!(f.check().unwrap_err().is("UPGRADE_OBSERVATION_UNKNOWN"));
}

#[test]
fn fully_verified_forward_phases_do_not_restore_old_pins_or_activate() {
    let mut f = Fixture::new(Profile::L2);
    f.installed(Phase::Replacing);
    assert_eq!(
        f.check().unwrap().next,
        ForwardAction::VerifyCompletePayload
    );
    f.journal.phase = Phase::PayloadVerified;
    assert_eq!(
        f.check().unwrap().next,
        ForwardAction::VerifyBeforePinCutover
    );
    f.journal.phase = Phase::PinCutoverIntent;
    assert_eq!(
        f.check().unwrap().next,
        ForwardAction::CutoverExactCandidatePins
    );
    f.candidate_pins();
    assert_eq!(
        f.check().unwrap().next,
        ForwardAction::VerifyAndRecordPinCutover
    );
    f.journal.phase = Phase::PinsCandidate;
    assert_eq!(f.check().unwrap().next, ForwardAction::ReverifyAndCommit);
    f.journal.phase = Phase::Committed;
    let decision = f.check().unwrap();
    assert_eq!(decision.next, ForwardAction::VerifyCommittedGeneration);
    assert!(!decision.activation_allowed && !decision.mutation_allowed);
    f.observed.pins.sha256 = Some(f.journal.old_pins_sha256.clone());
    assert!(f.check().unwrap_err().is("UPGRADE_PIN_CUTOVER_REGRESSED"));
}

#[test]
fn distinct_candidate_pins_with_old_or_unknown_units_never_authorize_recovery() {
    for unknown in [false, true] {
        let mut f = Fixture::new(Profile::L3);
        f.journal.phase = Phase::Replacing;
        f.candidate_pins();
        if unknown {
            f.observed.units[0].state = ObservedState::Unknown;
            f.observed.units[0].fingerprint = None;
        }
        assert!(f.check().is_err());
    }
    let mut f = Fixture::new(Profile::L2);
    f.installed(Phase::Replacing);
    f.candidate_pins();
    assert!(
        f.check().unwrap_err().is("UPGRADE_PREMATURE_PIN_CUTOVER"),
        "even complete payload needs durable pin intent"
    );
}

#[test]
fn equal_pin_hashes_never_skip_pending_units_or_transaction_phases() {
    let mut f = Fixture::new(Profile::L2);
    f.journal.old_pins_sha256 = f.journal.candidate_pins_sha256.clone();
    f.candidate_pins();
    f.sync_transaction();
    let decision = f.check().unwrap();
    assert!(decision.pins_equal);
    assert_eq!(decision.next, ForwardAction::PersistReplacingPhase);
    for (unit, observed) in f.journal.units.iter_mut().zip(&mut f.observed.units) {
        unit.original.fingerprint = Some(unit.candidate_fingerprint.clone());
        observed.fingerprint = unit.original.fingerprint.clone();
    }
    f.sync_transaction();
    assert_eq!(
        f.check().unwrap().next,
        ForwardAction::PersistReplacingPhase
    );
    f.journal.phase = Phase::Replacing;
    assert_eq!(
        f.check().unwrap().next,
        ForwardAction::PersistUnitIntent {
            unit_id: f.journal.units[0].unit_id.clone()
        }
    );
    f.installed(Phase::PinCutoverIntent);
    assert_eq!(
        f.check().unwrap().next,
        ForwardAction::CutoverExactCandidatePins
    );
    f.journal.phase = Phase::Committed;
    assert!(!f.check().unwrap().activation_allowed);
}

#[test]
fn unknown_duplicate_and_missing_nested_json_fields_are_rejected() {
    let f = Fixture::new(Profile::L2);
    for field in ["version", "target_id"] {
        let raw = String::from_utf8(serde_json::to_vec(&f.journal).unwrap()).unwrap();
        let duplicate = if field == "version" {
            raw.replacen("\"version\":1", "\"version\":1,\"version\":1", 1)
        } else {
            raw.replacen(
                "\"target_id\":\"upgrade-fixture\"",
                "\"target_id\":\"upgrade-fixture\",\"target_id\":\"upgrade-fixture\"",
                1,
            )
        };
        assert_ne!(raw, duplicate);
        assert!(classify_existing_upgrade_forward(
            &f.descriptor,
            &f.inventory,
            duplicate.as_bytes(),
            &serde_json::to_vec(&f.observed).unwrap()
        )
        .unwrap_err()
        .is("UPGRADE_RECORD_SCHEMA"));
    }
    let raw = String::from_utf8(serde_json::to_vec(&f.journal).unwrap()).unwrap();
    let duplicate = raw.replacen(
        "\"state\":\"present\"",
        "\"state\":\"present\",\"state\":\"present\"",
        1,
    );
    assert!(classify_existing_upgrade_forward(
        &f.descriptor,
        &f.inventory,
        duplicate.as_bytes(),
        &serde_json::to_vec(&f.observed).unwrap()
    )
    .is_err());
    for location in ["root", "unit", "original", "missing-original-fingerprint"] {
        let mut journal = f.journal_value();
        match location {
            "root" => journal["durable_inhibition"] = json!(true),
            "unit" => journal["units"][0]["arbitrary_destination"] = json!("/state/private"),
            "original" => journal["units"][0]["original"]["approved"] = json!(true),
            _ => {
                journal["units"][0]["original"]
                    .as_object_mut()
                    .unwrap()
                    .remove("fingerprint");
            }
        }
        assert!(f
            .check_values(journal, f.observed_value())
            .unwrap_err()
            .is("UPGRADE_RECORD_SCHEMA"));
    }
    let raw = String::from_utf8(serde_json::to_vec(&f.observed).unwrap()).unwrap();
    let duplicate = raw.replacen(
        "\"state\":\"present\"",
        "\"state\":\"present\",\"state\":\"present\"",
        1,
    );
    assert_ne!(raw, duplicate);
    assert!(classify_existing_upgrade_forward(
        &f.descriptor,
        &f.inventory,
        &serde_json::to_vec(&f.journal).unwrap(),
        duplicate.as_bytes()
    )
    .unwrap_err()
    .is("UPGRADE_RECORD_SCHEMA"));
    for location in ["root", "unit", "pins"] {
        let mut observed = f.observed_value();
        match location {
            "root" => observed["allow"] = json!(true),
            "unit" => observed["units"][0]["repair"] = json!(true),
            _ => observed["pins"]["old_new_union"] = json!([]),
        }
        assert!(f
            .check_values(f.journal_value(), observed)
            .unwrap_err()
            .is("UPGRADE_RECORD_SCHEMA"));
    }
}

#[test]
fn exact_raw_revision_scope_and_candidate_pin_binding_are_required() {
    let f = Fixture::new(Profile::L2);
    for field in [
        "target_id",
        "descriptor_sha256",
        "artifact_inventory_sha256",
        "candidate_pins_sha256",
        "old_pins_sha256",
        "transaction_id",
    ] {
        let mut journal = f.journal_value();
        journal[field] = json!(if field == "target_id" {
            "other".into()
        } else {
            "F".repeat(64)
        });
        assert!(
            f.check_values(journal, f.observed_value()).is_err(),
            "{field}"
        );
    }
    let mut descriptor = f.descriptor.clone();
    descriptor.push(b'\n');
    assert!(classify_existing_upgrade_forward(
        &descriptor,
        &f.inventory,
        &serde_json::to_vec(&f.journal).unwrap(),
        &serde_json::to_vec(&f.observed).unwrap()
    )
    .is_err());
    let mut inventory = f.inventory.clone();
    inventory.push(b'\n');
    assert!(classify_existing_upgrade_forward(
        &f.descriptor,
        &inventory,
        &serde_json::to_vec(&f.journal).unwrap(),
        &serde_json::to_vec(&f.observed).unwrap()
    )
    .is_err());
    let mut journal = f.journal.clone();
    journal.units[0].original.fingerprint = Some("e".repeat(64));
    assert!(f
        .check_values(serde_json::to_value(journal).unwrap(), f.observed_value())
        .unwrap_err()
        .is("UPGRADE_TRANSACTION_BINDING"));
}

#[test]
fn duplicate_reordered_extra_or_arbitrary_unit_ids_cannot_change_the_fixed_plan() {
    for kind in [
        "duplicate-journal",
        "reordered-journal",
        "extra-journal",
        "arbitrary-journal",
        "duplicate-observed",
        "reordered-observed",
    ] {
        let mut f = Fixture::new(Profile::L2);
        match kind {
            "duplicate-journal" => f.journal.units[1] = f.journal.units[0].clone(),
            "reordered-journal" => f.journal.units.swap(0, 1),
            "extra-journal" => f.journal.units.push(f.journal.units[0].clone()),
            "arbitrary-journal" => f.journal.units[0].unit_id = "file:/state/vault".into(),
            "duplicate-observed" => f.observed.units[1] = f.observed.units[0].clone(),
            _ => f.observed.units.swap(0, 1),
        }
        f.sync_transaction();
        assert!(f.check().is_err(), "{kind}");
    }
}

#[test]
fn unknown_identity_unexpected_absence_and_missing_current_pins_refuse() {
    for kind in [
        "unknown-unit",
        "foreign-unit",
        "absent-original",
        "installed-absent",
        "unknown-pins",
        "absent-pins",
        "foreign-pins",
    ] {
        let mut f = Fixture::new(Profile::L2);
        match kind {
            "unknown-unit" => {
                f.observed.units[0].state = ObservedState::Unknown;
                f.observed.units[0].fingerprint = None;
            }
            "foreign-unit" => f.observed.units[0].fingerprint = Some("e".repeat(64)),
            "absent-original" => {
                f.observed.units[0].state = ObservedState::Absent;
                f.observed.units[0].fingerprint = None;
            }
            "installed-absent" => {
                f.installed(Phase::Replacing);
                f.observed.units[0].state = ObservedState::Absent;
                f.observed.units[0].fingerprint = None;
            }
            "unknown-pins" => {
                f.observed.pins.state = ObservedState::Unknown;
                f.observed.pins.sha256 = None;
            }
            "absent-pins" => {
                f.observed.pins.state = ObservedState::Absent;
                f.observed.pins.sha256 = None;
            }
            _ => f.observed.pins.sha256 = Some("e".repeat(64)),
        }
        assert!(f.check().is_err(), "{kind}");
    }
}

#[test]
fn original_absence_is_explicit_and_never_creates_unjournaled_ownership() {
    let mut f = Fixture::new(Profile::L2);
    f.journal.units[0].original = Original {
        state: OriginalState::Absent,
        fingerprint: None,
    };
    f.observed.units[0].fingerprint = Some(f.journal.units[0].candidate_fingerprint.clone());
    f.sync_transaction();
    assert!(f
        .check()
        .unwrap_err()
        .is("UPGRADE_REPLACEMENT_WITHOUT_INTENT"));
    f.journal.units[0].original.fingerprint = Some("d".repeat(64));
    f.sync_transaction();
    assert!(f.check().is_err());
    let mut f = Fixture::new(Profile::L2);
    f.journal.units[0].original.fingerprint = None;
    f.sync_transaction();
    assert!(f.check().is_err());
}

#[test]
fn phase_gaps_regression_multiple_intents_and_unknown_phase_refuse() {
    for kind in [
        "prepared-installed",
        "late-installed",
        "late-intent",
        "two-intents",
        "advanced-pending",
        "installed-old",
    ] {
        let mut f = Fixture::new(Profile::L2);
        match kind {
            "prepared-installed" => f.journal.units[0].phase = UnitPhase::Installed,
            "late-installed" => {
                f.journal.phase = Phase::Replacing;
                f.journal.units[1].phase = UnitPhase::Installed;
            }
            "late-intent" => {
                f.journal.phase = Phase::Replacing;
                f.journal.units[1].phase = UnitPhase::ReplaceIntent;
            }
            "two-intents" => {
                f.journal.phase = Phase::Replacing;
                f.journal.units[0].phase = UnitPhase::ReplaceIntent;
                f.journal.units[1].phase = UnitPhase::ReplaceIntent;
            }
            "advanced-pending" => f.journal.phase = Phase::PinCutoverIntent,
            _ => {
                f.journal.phase = Phase::Replacing;
                f.journal.units[0].phase = UnitPhase::Installed;
            }
        }
        assert!(f.check().is_err(), "{kind}");
    }
    let f = Fixture::new(Profile::L2);
    let mut journal = f.journal_value();
    journal["phase"] = json!("restore_old_state");
    assert!(f
        .check_values(journal, f.observed_value())
        .unwrap_err()
        .is("UPGRADE_RECORD_SCHEMA"));
}

#[test]
fn dedicated_role_incomplete_plan_and_record_limits_refuse() {
    let f = Fixture::new(Profile::L2);
    let mut descriptor: Value = serde_json::from_slice(&f.descriptor).unwrap();
    descriptor["role"] = json!("dedicated-test");
    assert!(
        describe_upgrade_public_units(&serde_json::to_vec(&descriptor).unwrap(), &f.inventory)
            .is_err()
    );
    let mut inventory: Value = serde_json::from_slice(&f.inventory).unwrap();
    inventory["files"]
        .as_array_mut()
        .unwrap()
        .retain(|v| v["path"] != "install.sh");
    assert!(
        describe_upgrade_public_units(&f.descriptor, &serde_json::to_vec(&inventory).unwrap())
            .unwrap_err()
            .is("UPGRADE_COMPLETE_PLAN_REQUIRED")
    );
    assert!(
        describe_upgrade_public_units(&vec![b' '; MAX_DESCRIPTOR + 1], &f.inventory)
            .unwrap_err()
            .is("UPGRADE_RECORD_BOUND")
    );
    assert!(
        describe_upgrade_public_units(&f.descriptor, &vec![b' '; MAX_INVENTORY + 1])
            .unwrap_err()
            .is("UPGRADE_RECORD_BOUND")
    );
    assert!(classify_existing_upgrade_forward(
        &f.descriptor,
        &f.inventory,
        &vec![b' '; MAX_RECORD + 1],
        &serde_json::to_vec(&f.observed).unwrap()
    )
    .unwrap_err()
    .is("UPGRADE_RECORD_BOUND"));
}

#[test]
fn unit_fingerprints_are_deterministic_but_bind_exact_candidate_members_and_routes() {
    let f = Fixture::new(Profile::L3);
    let expected = describe_upgrade_public_units(&f.descriptor, &f.inventory).unwrap();
    let mut inventory: Value = serde_json::from_slice(&f.inventory).unwrap();
    inventory["files"].as_array_mut().unwrap().reverse();
    assert!(
        describe_upgrade_public_units(&f.descriptor, &serde_json::to_vec(&inventory).unwrap())
            .unwrap_err()
            .is("DEPLOYMENT_INVENTORY_FILE")
    );
    inventory["files"].as_array_mut().unwrap().reverse();
    assert_eq!(
        describe_upgrade_public_units(&f.descriptor, &serde_json::to_vec(&inventory).unwrap())
            .unwrap(),
        expected
    );
    let member = inventory["files"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|f| f["path"] == "EnclaveCustody.app/Contents/Info.plist")
        .unwrap();
    member["sha256"] = json!("e".repeat(64));
    let changed =
        describe_upgrade_public_units(&f.descriptor, &serde_json::to_vec(&inventory).unwrap())
            .unwrap();
    for (old, new) in expected.iter().zip(changed) {
        assert_eq!(
            old.candidate_fingerprint != new.candidate_fingerprint,
            old.unit_id == "bundle:EnclaveCustody.app"
        );
    }
}
