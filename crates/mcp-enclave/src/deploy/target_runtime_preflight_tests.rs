//! Actual crypto with software-issued signatures and genuine protected fixture
//! provisioning. These tests require the coordinator private root; they do not
//! establish production issuer/pin provenance, native services or fresh state.
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use enclave_core::deployment::{DeploymentLayout, DeploymentSigningMode};
use enclave_crypto::{
    hpke_envelope::EnvelopePolicy,
    tuf::{target_file, RepoBuilder, TargetFile},
};
use enclave_custody_vaultd::ctap::asset_enrollment::{
    AssetEnrollmentPolicy, AttestationMode, SignedAssetEnrollmentPolicy,
};
use serde_json::{json, Value};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const NOW: i64 = 1_800_000_000;
const EXP: &str = "2030-01-01T00:00:00Z";
const SUBJECT: &str = "software-preflight-host";
const NAMESPACE: &str = "software-preflight-namespace";
fn encoded(value: &impl Serialize) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn target(provisioning: &CustodyProvisioning) -> DeploymentTarget {
    let root = Path::new("/runtime-preflight-fixture/selected");
    DeploymentTarget {
        version: 1,
        target_id: "runtime-preflight".into(),
        role: DeploymentRole::DedicatedTest,
        profile: Profile::L2,
        authority_config: provisioning.manifest_path().to_owned(),
        expected_artifacts_manifest: root.join("config/inventory.json"),
        codesign_pins_file: root.join("support/pins.json"),
        signing_identity_mode: DeploymentSigningMode::LocalPins,
        broker: None,
        shared_read_only_inputs: vec![],
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
            launchd_namespace: "com.mcpmac.runtimepreflight".into(),
            mach_service: "com.mcpmac.runtimepreflight.exception".into(),
        },
    }
}
struct Provisioning {
    root: PathBuf,
    checked: CustodyProvisioning,
}
impl Provisioning {
    fn new(profile: Profile) -> Self {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "private-root fixture requires actual root"
        );
        assert_eq!(
            std::env::var("ENCLAVE_TEST_STATE_ROOT").as_deref(),
            Ok("/state"),
            "coordinator private-root runner required"
        );
        let root = Path::new("/state").join(format!(
            "runtime-preflight-{}",
            hex::encode(enclave_core::rng::bytes32())
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let put = |name: &str, bytes: &[u8]| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(root.join(name))
                .unwrap();
            file.write_all(bytes).unwrap();
        };
        let issuer = SigningKey::from_bytes(&[11; 32]);
        let policy = AssetEnrollmentPolicy {
            version: 1,
            revision: 1,
            host_id: SUBJECT.into(),
            asset_id: "fixture-asset".into(),
            custodian_id: "fixture-custodian".into(),
            aaguid: [31; 16],
            mode: AttestationMode::BasicWithIndependentAsset,
            enterprise_leaf_sha256: None,
            rationale: "software fixture only".into(),
            issued_unix: NOW - 1,
            expires_unix: NOW + 3600,
        };
        let signature = issuer
            .sign(&policy.signing_message().unwrap())
            .to_bytes()
            .to_vec();
        put(
            "policy.json",
            &encoded(&SignedAssetEnrollmentPolicy { policy, signature }),
        );
        for (name, seed) in [
            ("policy.pub", 11),
            ("inventory.pub", 12),
            ("envelope.pub", 13),
        ] {
            put(
                name,
                hex::encode(
                    SigningKey::from_bytes(&[seed; 32])
                        .verifying_key()
                        .to_bytes(),
                )
                .as_bytes(),
            );
        }
        let manifest = json!({"v":1,"profile":profile,"asset_policy_file":root.join("policy.json"),
            "asset_policy_key_file":root.join("policy.pub"),"asset_inventory_key_file":root.join("inventory.pub"),
            "envelope_policy_key_file":root.join("envelope.pub"),"asset_host_id":SUBJECT,"asset_id":"fixture-asset",
            "asset_custodian_id":"fixture-custodian","envelope_policy_subject":SUBJECT,"envelope_policy_namespace":NAMESPACE});
        put("custody.json", &encoded(&manifest));
        let checked = CustodyProvisioning::load(&root.join("custody.json"), profile, NOW).unwrap();
        Self { root, checked }
    }
}
impl Drop for Provisioning {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
struct Package {
    repo: RepoBuilder,
    pin: Vec<u8>,
    files: BTreeMap<String, Vec<u8>>,
}
impl Package {
    fn new() -> Self {
        let repo = RepoBuilder::new(2, 2);
        let pin = repo.root(EXP).unwrap();
        let mds = br#"{"entries":[]}"#.to_vec();
        let host = EnclaveHostConfig {
            profile_floor: Profile::L2,
            ifc_grant_public_key: "01".repeat(32),
            ohttp_key_config: None,
            calibration_corpus_digest: "02".repeat(32),
            vk_digest: "03".repeat(32),
            mcp_lock_digest: "04".repeat(32),
            fido_mds_allowlist_digest: blake3::hash(&mds).to_hex().to_string(),
            codesign_pins: None,
        };
        let policy = EnvelopePolicy {
            version: 1,
            revision: 7,
            subject: SUBJECT.into(),
            namespace: NAMESPACE.into(),
            issued_unix: NOW - 1,
            expires_unix: NOW + 1800,
            review_unix: NOW + 900,
            owner: "software-fixture".into(),
            profiles: vec![Profile::L2],
            data_classes: vec!["C3".into(), "C4".into()],
            purpose: "software preflight".into(),
            migration: "software fixture only".into(),
            disclosure: None,
            classical_exception: false,
        };
        let signature = SigningKey::from_bytes(&[13; 32])
            .sign(&policy.signing_message().unwrap())
            .to_bytes()
            .to_vec();
        let files = BTreeMap::from([
            ("root.json".into(), pin.clone()),
            (HOST_CONFIG_TARGET.into(), host.to_json_bytes().unwrap()),
            (FIDO_MDS_TARGET.into(), mds),
            (
                CustodyTarget::EnvelopePolicy.target_name().into(),
                encoded(&SignedEnvelopePolicy { policy, signature }),
            ),
        ]);
        let mut this = Self { repo, pin, files };
        this.refresh(None);
        this
    }
    fn refresh(&mut self, custom: Option<(&str, Value)>) {
        let targets: BTreeMap<String, TargetFile> = [
            HOST_CONFIG_TARGET,
            FIDO_MDS_TARGET,
            CustodyTarget::EnvelopePolicy.target_name(),
        ]
        .into_iter()
        .map(|name| {
            let custom = custom
                .as_ref()
                .filter(|(selected, _)| *selected == name)
                .map(|(_, value)| value.clone());
            (name.to_owned(), target_file(&self.files[name], custom))
        })
        .collect();
        self.metadata(targets);
    }
    fn metadata(&mut self, targets: BTreeMap<String, TargetFile>) {
        let targets = self.repo.targets(1, EXP, targets).unwrap();
        let snapshot = self.repo.snapshot(1, EXP, 1, &targets).unwrap();
        let timestamp = self.repo.timestamp(1, EXP, 1, &snapshot).unwrap();
        self.files.insert("targets.json".into(), targets);
        self.files.insert("snapshot.json".into(), snapshot);
        self.files.insert("timestamp.json".into(), timestamp);
    }
    fn check(&self, provisioning: &CustodyProvisioning) -> EnclaveResult<RuntimePreflightReport> {
        self.check_with(
            &target(provisioning),
            provisioning,
            &self.pin,
            &digest(&self.pin),
            NOW,
        )
    }
    fn check_with(
        &self,
        target: &DeploymentTarget,
        provisioning: &CustodyProvisioning,
        pin: &[u8],
        pin_hash: &str,
        now: i64,
    ) -> EnclaveResult<RuntimePreflightReport> {
        let observations = self
            .files
            .iter()
            .map(|(name, bytes)| {
                (
                    target.layout.staging_root.join("tuf/repo").join(name),
                    digest(bytes),
                    bytes,
                )
            })
            .collect::<Vec<_>>();
        let inputs = observations
            .iter()
            .map(|(source, sha256, bytes)| RuntimeTrustInput {
                source,
                inventory_sha256: sha256,
                inventory_size: bytes.len() as u64,
                bytes,
            })
            .collect::<Vec<_>>();
        preflight(
            target,
            &"ab".repeat(32),
            &inputs,
            pin,
            pin_hash,
            provisioning,
            now,
        )
    }
    fn edit_envelope(&mut self, change: impl FnOnce(&mut SignedEnvelopePolicy), resign: bool) {
        let name = CustodyTarget::EnvelopePolicy.target_name();
        let mut signed: SignedEnvelopePolicy = serde_json::from_slice(&self.files[name]).unwrap();
        change(&mut signed);
        if resign {
            signed.signature = SigningKey::from_bytes(&[13; 32])
                .sign(&signed.policy.signing_message().unwrap())
                .to_bytes()
                .to_vec();
        }
        self.files.insert(name.into(), encoded(&signed));
        self.refresh(None);
    }
}
fn denied(value: EnclaveResult<RuntimePreflightReport>, reason: &str) {
    let error = value.unwrap_err();
    assert!(error.is(reason), "expected {reason}, got {}", error.reason);
}

#[test]
#[ignore = "coordinator private root /state; software signatures and actual protected provisioning only"]
fn signed_production_crypto_paths_return_only_a_conditional_inert_report() {
    let provisioning = Provisioning::new(Profile::L2);
    let mut package = Package::new();
    // An unrelated diagnostic root must never replace the separately supplied
    // anchor, and successful preflight must not claim this candidate verified.
    package.files.insert(
        "root.json".into(),
        RepoBuilder::new(1, 1).root(EXP).unwrap(),
    );
    let report = package.check(&provisioning.checked).unwrap();
    assert_eq!(
        report.verification,
        "CONDITIONAL_ON_SUPPLIED_PIN_NOT_RUNTIME_AUTHORITY"
    );
    assert_eq!(report.root_version, 1);
    assert_eq!(report.versions, (1, 1, 1));
    assert_eq!(report.rotations_applied, 0);
    assert_eq!(report.supplied_pin_sha256, digest(&package.pin));
    assert_eq!(report.checked_at_supplied_unix, NOW);
    assert!(report.metadata_expires_at > NOW);
    assert_eq!(report.envelope_review_or_expiry, NOW + 900);
    assert!(
        !report.pin_provenance_verified
            && !report.fresh_namespace_proven
            && !report.provisioning_currentness_verified
            && !report.candidate_root_authenticated
            && !report.live_cas_receipt
            && !report.runtime_authority
            && !report.installation_supported
            && !report.qualified
    );
    assert!(!report.input_plan.apply_supported);
    assert_eq!(report.input_plan.authentication, "UNVERIFIED");
    assert_eq!(report.input_plan.readiness, "NOT_QUALIFIED");
    assert_eq!(
        report.provisioning_manifest_sha256,
        provisioning.checked.receipt().manifest_sha256
    );
    assert!(fs::read_dir(&provisioning.root).unwrap().all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .contains("sealed")));
}

#[test]
#[ignore = "coordinator private root /state; actual supplied-pin threshold verification"]
fn pin_expectations_and_foreign_anchor_refuse_without_candidate_root_fallback() {
    let p = Provisioning::new(Profile::L2);
    let package = Package::new();
    denied(
        package.check_with(
            &target(&p.checked),
            &p.checked,
            &package.pin,
            &"00".repeat(32),
            NOW,
        ),
        "RUNTIME_PREFLIGHT_PIN_EXPECTATION",
    );
    let foreign = RepoBuilder::new(2, 2).root(EXP).unwrap();
    denied(
        package.check_with(
            &target(&p.checked),
            &p.checked,
            &foreign,
            &digest(&foreign),
            NOW,
        ),
        "TUF_THRESHOLD_NOT_MET",
    );
    denied(
        package.check_with(&target(&p.checked), &p.checked, &[], &digest(&[]), NOW),
        "RUNTIME_PREFLIGHT_PIN_BOUND",
    );
    let mut unsigned: Value = serde_json::from_slice(&package.pin).unwrap();
    unsigned["signatures"] = json!([]);
    let unsigned = encoded(&unsigned);
    denied(
        package.check_with(
            &target(&p.checked),
            &p.checked,
            &unsigned,
            &digest(&unsigned),
            NOW,
        ),
        "TUF_THRESHOLD_NOT_MET",
    );
}

#[test]
#[ignore = "coordinator private root /state; actual numeric root rotation and dual threshold paths"]
fn numbered_rotations_are_numeric_and_gaps_or_foreign_old_thresholds_refuse() {
    let p = Provisioning::new(Profile::L2);
    let mut package = Package::new();
    for version in (2..=12).rev() {
        package.repo.root_version = version;
        package.files.insert(
            format!("{version}.root.json"),
            package.repo.root(EXP).unwrap(),
        );
    }
    let report = package.check(&p.checked).unwrap();
    assert_eq!(report.root_version, 12);
    assert_eq!(report.rotations_applied, 11);
    package.files.remove("2.root.json");
    denied(package.check(&p.checked), "TUF_ROOT_VERSION");
    let mut foreign = RepoBuilder::new(2, 2);
    foreign.root_version = 2;
    package
        .files
        .insert("2.root.json".into(), foreign.root(EXP).unwrap());
    denied(package.check(&p.checked), "TUF_THRESHOLD_NOT_MET");
}

#[test]
#[ignore = "coordinator private root /state; actual signature, expiry and target dual hash checks"]
fn consistent_inventory_does_not_hide_metadata_or_payload_tampering_or_expiry() {
    let p = Provisioning::new(Profile::L2);
    let mut package = Package::new();
    let mut timestamp: Value = serde_json::from_slice(&package.files["timestamp.json"]).unwrap();
    timestamp["signed"]["expires"] = json!("2031-01-01T00:00:00Z");
    package
        .files
        .insert("timestamp.json".into(), encoded(&timestamp));
    denied(package.check(&p.checked), "TUF_THRESHOLD_NOT_MET");
    let mut package = Package::new();
    let mut host: EnclaveHostConfig =
        serde_json::from_slice(&package.files[HOST_CONFIG_TARGET]).unwrap();
    host.vk_digest = "ff".repeat(32);
    package
        .files
        .insert(HOST_CONFIG_TARGET.into(), host.to_json_bytes().unwrap());
    denied(package.check(&p.checked), "TUF_TARGET_SHA256");
    let mut package = Package::new();
    let mut targets = [
        HOST_CONFIG_TARGET,
        FIDO_MDS_TARGET,
        CustodyTarget::EnvelopePolicy.target_name(),
    ]
    .into_iter()
    .map(|name| (name.to_owned(), target_file(&package.files[name], None)))
    .collect::<BTreeMap<_, _>>();
    targets
        .get_mut(HOST_CONFIG_TARGET)
        .unwrap()
        .hashes
        .insert("blake3".into(), "00".repeat(32));
    package.metadata(targets);
    denied(package.check(&p.checked), "TUF_TARGET_BLAKE3");
    let mut package = Package::new();
    package.pin = package.repo.root("2000-01-01T00:00:00Z").unwrap();
    denied(package.check(&p.checked), "TUF_METADATA_EXPIRED");
}

#[test]
#[ignore = "coordinator private root /state; authenticated revoked and envelope model role refusal"]
fn signed_revocation_and_model_policy_roles_cannot_become_runtime_payload_authority() {
    let p = Provisioning::new(Profile::L2);
    for name in [
        HOST_CONFIG_TARGET,
        FIDO_MDS_TARGET,
        CustodyTarget::EnvelopePolicy.target_name(),
    ] {
        let mut package = Package::new();
        package.refresh(Some((name, json!({"revoked":true}))));
        denied(package.check(&p.checked), "TARGET_REVOKED");
    }
    let mut package = Package::new();
    package.refresh(Some((
        CustodyTarget::EnvelopePolicy.target_name(),
        json!({"classification":"public_l1"}),
    )));
    denied(package.check(&p.checked), "MODEL_DESCRIPTOR_REQUIRED");
}

#[test]
#[ignore = "coordinator private root /state; independent envelope signature, scope and review paths"]
fn tuf_signed_envelope_still_requires_independent_issuer_scope_and_review() {
    let p = Provisioning::new(Profile::L2);
    let mut package = Package::new();
    package.edit_envelope(
        |signed| {
            signed.signature = SigningKey::from_bytes(&[14; 32])
                .sign(&signed.policy.signing_message().unwrap())
                .to_bytes()
                .to_vec();
        },
        false,
    );
    denied(package.check(&p.checked), "ENVELOPE_POLICY_SIGNATURE");
    let mut package = Package::new();
    package.edit_envelope(|signed| signed.policy.subject = "foreign-host".into(), true);
    denied(package.check(&p.checked), "ENVELOPE_POLICY_SCOPE_OR_TIME");
    let mut package = Package::new();
    package.edit_envelope(|signed| signed.policy.review_unix = NOW, true);
    denied(package.check(&p.checked), "ENVELOPE_POLICY_SCOPE_OR_TIME");
    let mut package = Package::new();
    package.edit_envelope(|signed| signed.policy.profiles = vec![Profile::L3], true);
    denied(package.check(&p.checked), "RUNTIME_TRUST_ENVELOPE_PROFILE");
}

#[test]
#[ignore = "coordinator private root /state; fresh dedicated L2 and complete input contract only"]
fn scope_time_provisioning_expiry_and_missing_inputs_refuse_without_state_access() {
    let p = Provisioning::new(Profile::L2);
    let mut package = Package::new();
    let mut upgrade = target(&p.checked);
    upgrade.role = DeploymentRole::ExistingUpgrade;
    denied(
        package.check_with(
            &upgrade,
            &p.checked,
            &package.pin,
            &digest(&package.pin),
            NOW,
        ),
        "RUNTIME_PREFLIGHT_FRESH_DEDICATED_L2_REQUIRED",
    );
    let mut l3 = target(&p.checked);
    l3.profile = Profile::L3;
    denied(
        package.check_with(&l3, &p.checked, &package.pin, &digest(&package.pin), NOW),
        "RUNTIME_PREFLIGHT_FRESH_DEDICATED_L2_REQUIRED",
    );
    denied(
        package.check_with(
            &target(&p.checked),
            &p.checked,
            &package.pin,
            &digest(&package.pin),
            -1,
        ),
        "RUNTIME_PREFLIGHT_TIME",
    );
    denied(
        package.check_with(
            &target(&p.checked),
            &p.checked,
            &package.pin,
            &digest(&package.pin),
            NOW + 3600,
        ),
        "RUNTIME_PREFLIGHT_PROVISIONING_SCOPE_OR_EXPIRY",
    );
    let mut foreign = target(&p.checked);
    foreign.authority_config = PathBuf::from("/foreign-preflight/custody.json");
    denied(
        package.check_with(
            &foreign,
            &p.checked,
            &package.pin,
            &digest(&package.pin),
            NOW,
        ),
        "RUNTIME_PREFLIGHT_PROVISIONING_BINDING",
    );
    let p3 = Provisioning::new(Profile::L3);
    denied(
        package.check(&p3.checked),
        "RUNTIME_PREFLIGHT_PROVISIONING_SCOPE_OR_EXPIRY",
    );
    package.files.remove("timestamp.json");
    denied(
        package.check(&p.checked),
        "RUNTIME_PREFLIGHT_INPUTS_INCOMPLETE",
    );
}
