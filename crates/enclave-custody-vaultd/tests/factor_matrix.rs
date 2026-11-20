//! GAP-29: Comprehensive factor matrix & ceremony verification across all
//! 12 `(profile, action)` cells plus the org-root column (FS-703 §3.1, ADR-013).

use std::collections::BTreeSet;

use ed25519_dalek::Signer;
use enclave_core::label::Conf;
use enclave_core::profile::{ActionClass, Profile};
use enclave_crypto::multisig::{QuorumPolicy, QuorumSignature};
use enclave_custody_vaultd::biometric::{Scripted, ScriptedCoreAuthUi};
use enclave_custody_vaultd::ceremony::{CeremonyEngine, CeremonyHardware, EgressGate};
use enclave_custody_vaultd::clock::{Clock, TestClock};
use enclave_custody_vaultd::ctap::assertion::{EnrolledCredential, SignCountStore};
use enclave_custody_vaultd::ctap::mds::{MdsAllowlist, MdsEntry, MdsState};
use enclave_custody_vaultd::ctap::virtual_device::VirtualAuthenticator;
use enclave_custody_vaultd::factors::{required_factors, Factor};
use enclave_custody_vaultd::intent::IntentPayloadV1;
use enclave_custody_vaultd::lease::LeaseTable;
use enclave_custody_vaultd::oidc::TestIdp;
use enclave_custody_vaultd::sep::{SepAgent, SoftwareSep};

const NOW: i64 = 1_700_000_000;

#[derive(Debug, Default)]
struct MockEgressGate(usize);
impl EgressGate for MockEgressGate {
    fn approve(&mut self, _d_jcs: &[u8; 32]) -> enclave_core::error::EnclaveResult<()> {
        self.0 += 1;
        Ok(())
    }
}

struct TestRig {
    dev: VirtualAuthenticator,
    cred: EnrolledCredential,
    mds: MdsState,
    counters: SignCountStore,
}

fn test_rig(profile: Profile) -> TestRig {
    let aaguid = [0xab; 16];
    let mut dev = VirtualAuthenticator::new(aaguid);
    let mds = MdsState {
        allowlist: MdsAllowlist {
            entries: vec![MdsEntry {
                aaguid: hex::encode(aaguid),
                description: "test".into(),
                min_firmware_version: 0x05_07_00,
                status_reports: vec!["FIDO_CERTIFIED".into()],
                attestation_public_keys: vec![dev.attestation_key_mds()],
                attestation_root_certificates: Vec::new(),
            }],
        },
        refreshed_at: NOW,
        expires_at:i64::MAX,
    };
    let cred = enclave_custody_vaultd::ctap::client::enroll_simulated(&mut dev, &mds, profile, NOW).unwrap();
    TestRig {
        dev,
        cred,
        mds,
        counters: SignCountStore::default(),
    }
}

fn make_intent(
    profile: Profile,
    action: ActionClass,
    tool: &str,
    ns: &str,
    rows: u64,
) -> IntentPayloadV1 {
    let org_root = enclave_core::intent_draft::is_org_root_mutation(tool, Some(ns));
    let factors = required_factors(profile, action, org_root);
    IntentPayloadV1 {
        v: 1,
        schema_version: Some("enclave.intent.v1".into()),
        action_class: action,
        profile,
        data_class: Some(Conf::C3),
        spiffe_id: "spiffe://corporate.internal/enclave/uid/704".into(),
        tool_name: tool.into(),
        target_namespace: Some(ns.into()),
        human_summary_trusted: Some(format!("Execute {tool}")),
        row_count_bound: Some(rows),
        arguments_jcs_sha256: Some(hex::encode([0xab; 32])),
        canonical_arguments_blake3: hex::encode([0xcd; 32]),
        model_blake3: None,
        policy_blake3: hex::encode([0xef; 32]),
        qif_millibits_delta: Some(0),
        custody_grant: None,
        boot_epoch_id: enclave_core::seq::new_boot_epoch_id(),
        rpc_seq_u64: 1,
        ts_utc_ms: (NOW as u64) * 1000,
        required_factors: factors.into_iter().collect(),
        user_turn: None,
    }
}

// ---------------------------------------------------------------------------
// 1. Matrix Table Factor Requirements Check (All 12 Cells + Org Root)
// ---------------------------------------------------------------------------

#[test]
fn matrix_required_factors_all_12_cells_and_org_root() {
    use Factor::*;

    // A1
    assert_eq!(
        required_factors(Profile::L1, ActionClass::A1, false),
        BTreeSet::from([SepWorkloadKey])
    );
    assert_eq!(
        required_factors(Profile::L2, ActionClass::A1, false),
        BTreeSet::from([SepWorkloadKey])
    );
    assert_eq!(
        required_factors(Profile::L3, ActionClass::A1, false),
        BTreeSet::from([SepWorkloadKey, YubikeyPresent])
    );

    // A2
    assert_eq!(
        required_factors(Profile::L1, ActionClass::A2, false),
        BTreeSet::from([SepWorkloadKey, TouchIdCoreauthui])
    );
    assert_eq!(
        required_factors(Profile::L2, ActionClass::A2, false),
        BTreeSet::from([SepWorkloadKey, TouchIdCoreauthui])
    );
    assert_eq!(
        required_factors(Profile::L3, ActionClass::A2, false),
        BTreeSet::from([SepWorkloadKey, TouchIdCoreauthui, YubikeyPresent])
    );

    // A3
    assert_eq!(
        required_factors(Profile::L1, ActionClass::A3, false),
        BTreeSet::from([SepWorkloadKey, TouchIdCoreauthui])
    );
    assert_eq!(
        required_factors(Profile::L2, ActionClass::A3, false),
        BTreeSet::from([SepWorkloadKey, TouchIdCoreauthui, YubikeyUp])
    );
    assert_eq!(
        required_factors(Profile::L3, ActionClass::A3, false),
        BTreeSet::from([
            SepWorkloadKey,
            TouchIdCoreauthui,
            YubikeyPresent,
            YubikeyUp,
            YubikeyPinUv,
            ZkEgressGate
        ])
    );

    // A4 Non-Root
    assert_eq!(
        required_factors(Profile::L1, ActionClass::A4, false),
        BTreeSet::from([SepWorkloadKey, TouchIdCoreauthui, OidcStepUp])
    );
    assert_eq!(
        required_factors(Profile::L2, ActionClass::A4, false),
        BTreeSet::from([SepWorkloadKey, TouchIdCoreauthui, YubikeyUp, OidcStepUp])
    );
    assert_eq!(
        required_factors(Profile::L3, ActionClass::A4, false),
        BTreeSet::from([
            SepWorkloadKey,
            TouchIdCoreauthui,
            YubikeyPresent,
            YubikeyUp,
            YubikeyPinUv,
            ZkEgressGate,
                OidcStepUp
        ])
    );

    // A4 Org Root Mutation
    assert_eq!(
        required_factors(Profile::L1, ActionClass::A4, true),
        BTreeSet::from([SepWorkloadKey, TouchIdCoreauthui, OidcStepUp])
    );
    assert_eq!(
        required_factors(Profile::L2, ActionClass::A4, true),
        BTreeSet::from([
            SepWorkloadKey,
            TouchIdCoreauthui,
            YubikeyUp,
            OidcStepUp,
            KofnEd25519Quorum
        ])
    );
    assert_eq!(
        required_factors(Profile::L3, ActionClass::A4, true),
        BTreeSet::from([
            SepWorkloadKey,
            TouchIdCoreauthui,
            YubikeyPresent,
            YubikeyUp,
            YubikeyPinUv,
            ZkEgressGate,
            OidcStepUp,
            KofnEd25519Quorum
        ])
    );
}

// ---------------------------------------------------------------------------
// 2. A1: 0-Prompt Non-Interactive Execution & SEP DPoP per RPC
// ---------------------------------------------------------------------------

#[test]
fn ceremony_a1_l1_l2_l3_and_sep_dpop() {
    let clock = TestClock::at(NOW);

    // L1 A1: 0 prompts, non-interactive
    let mut e1 = CeremonyEngine::new(Profile::L1);
    let i1 = make_intent(
        Profile::L1,
        ActionClass::A1,
        "mcp://postgres/query",
        "dev-billing",
        1,
    );
    let grant1 = e1
        .run(&i1, None, CeremonyHardware::default(), &clock)
        .unwrap();
    assert_eq!(grant1.factors, BTreeSet::from([Factor::SepWorkloadKey]));

    // L2 A1: 0 prompts
    let mut e2 = CeremonyEngine::new(Profile::L2);
    let i2 = make_intent(
        Profile::L2,
        ActionClass::A1,
        "mcp://postgres/query",
        "dev-billing",
        1,
    );
    let grant2 = e2
        .run(&i2, None, CeremonyHardware::default(), &clock)
        .unwrap();
    assert_eq!(grant2.factors, BTreeSet::from([Factor::SepWorkloadKey]));

    // L3 A1: Requires authenticator presence
    let mut e3 = CeremonyEngine::new(Profile::L3);
    let i3 = make_intent(
        Profile::L3,
        ActionClass::A1,
        "mcp://postgres/query",
        "dev-billing",
        1,
    );
    // Missing device => fails closed
    assert!(e3
        .run(&i3, None, CeremonyHardware::default(), &clock)
        .unwrap_err()
        .is("YUBIKEY_NOT_PRESENT"));

    // With device present:
    let mut rig = test_rig(Profile::L3);
    let grant3 = e3
        .run(
            &i3,
            None,
            CeremonyHardware {
                yubikey: Some(&mut rig.dev),
                is_yanked: false,
                ..Default::default()
            },
            &clock,
        )
        .unwrap();
    assert_eq!(
        grant3.factors,
        BTreeSet::from([Factor::SepWorkloadKey, Factor::YubikeyPresent])
    );

    // SEP DPoP verification in egress proxy path
    let sep = SoftwareSep::new();
    let proof = sep
        .create_dpop_proof(
            "POST",
            "https://cas.local.internal/v1/fetch",
            NOW,
            "dpop-test-jti-00000001",
            None,
        )
        .unwrap();
    let verified = enclave_crypto::dpop::verify_egress_dpop(
        &proof,
        "POST",
        "https://cas.local.internal/v1/fetch",
        None,
        None,
        NOW,
    )
    .unwrap();
    assert_eq!(verified.jti, "dpop-test-jti-00000001");
}

// ---------------------------------------------------------------------------
// 3. A2: 15-Minute Biometric Lease Table & Revocation on Lock/Sleep
// ---------------------------------------------------------------------------

#[test]
fn ceremony_a2_lease_table_hit_and_revocation() {
    let clock = TestClock::at(NOW);
    let mut engine = CeremonyEngine::new(Profile::L2);
    let mut leases = LeaseTable::new();
    let intent = make_intent(
        Profile::L2,
        ActionClass::A2,
        "mcp://postgres/schema",
        "dev-billing",
        1,
    );

    // 1st run: Touch ID prompt is evaluated and lease is granted.
    let mut ui = ScriptedCoreAuthUi::new([Scripted::Approve]);
    let sep_key = ui.enrolled_key();
    let grant1 = engine
        .run(
            &intent,
            None,
            CeremonyHardware {
                biometric: Some(&mut ui),
                sep_key: Some(sep_key),
                leases: Some(&mut leases),
                ..Default::default()
            },
            &clock,
        )
        .unwrap();
    assert_eq!(
        grant1.factors,
        BTreeSet::from([Factor::SepWorkloadKey, Factor::TouchIdCoreauthui])
    );
    assert_eq!(leases.active_count(clock.now_ns()), 1);

    // 2nd run (within 15 min): Lease hit, 0 biometric prompts needed (no UI provided).
    let grant2 = engine
        .run(
            &intent,
            None,
            CeremonyHardware {
                leases: Some(&mut leases),
                ..Default::default()
            },
            &clock,
        )
        .unwrap();
    assert_eq!(
        grant2.factors,
        BTreeSet::from([Factor::SepWorkloadKey, Factor::TouchIdCoreauthui])
    );

    // 3rd run after 16 minutes: Lease is expired, requires Touch ID again.
    let t_16m = clock.now_ns() + 16 * 60 * 1_000_000_000;
    assert!(!leases.is_valid(
        &intent.spiffe_id,
        intent.target_namespace.as_deref().unwrap(),
        &[0xcd; 32],
        t_16m
    ));

    // 4th run: Synchronous wipe on screen lock / sleep.
    leases.grant(
        &intent.spiffe_id,
        intent.target_namespace.as_deref().unwrap(),
        [0xcd; 32],
        clock.now_ns(),
    );
    assert_eq!(leases.active_count(clock.now_ns()), 1);
    leases.revoke_all(); // Screen lock / sleep tamper event
    assert_eq!(leases.active_count(clock.now_ns()), 0);
}

// ---------------------------------------------------------------------------
// 4. L1 A4: Out-of-Band OIDC Step-Up Protocol Boundary
// ---------------------------------------------------------------------------

#[test]
fn ceremony_l1_a4_oidc_step_up() {
    let clock = TestClock::at(NOW);
    let mut engine = CeremonyEngine::new(Profile::L1);
    let intent = make_intent(
        Profile::L1,
        ActionClass::A4,
        "mcp://analytics/export_csv",
        "dev-billing",
        100,
    );

    let idp = TestIdp::default();
    let verifier = idp.verifier();
    let valid_token = idp.mint_token("auditor@company.com", NOW, 20).unwrap();

    let mut ui = ScriptedCoreAuthUi::new([Scripted::Approve, Scripted::Approve]);
    let sep_key = ui.enrolled_key();

    // Valid OIDC token + Touch ID => success
    let grant = engine
        .run(
            &intent,
            None,
            CeremonyHardware {
                biometric: Some(&mut ui),
                sep_key: Some(sep_key),
                oidc_verifier: Some(&verifier),
                oidc_token: Some(&valid_token),
                ..Default::default()
            },
            &clock,
        )
        .unwrap();
    assert_eq!(
        grant.factors,
        BTreeSet::from([
            Factor::SepWorkloadKey,
            Factor::TouchIdCoreauthui,
            Factor::OidcStepUp
        ])
    );

    // Stale OIDC token (auth_time > 300s) => fails closed
    let stale_token = idp.mint_token("auditor@company.com", NOW, 301).unwrap();
    let err = engine
        .run(
            &intent,
            None,
            CeremonyHardware {
                biometric: Some(&mut ui),
                sep_key: Some(sep_key),
                oidc_verifier: Some(&verifier),
                oidc_token: Some(&stale_token),
                ..Default::default()
            },
            &clock,
        )
        .unwrap_err();
    assert!(err.is("OIDC_AUTH_TIME_STALE"));
}

// ---------------------------------------------------------------------------
// 5. L2 & L3 A4: Org-Root Mutation & k-of-n Ed25519 Quorum
// ---------------------------------------------------------------------------

#[test]
fn ceremony_org_root_mutation_and_k_of_n_quorum() {
    let clock = TestClock::at(NOW);
    let idp = TestIdp::default();
    let verifier = idp.verifier();
    let token = idp.mint_token("authorized-fixture-subject", NOW, 0).unwrap();
    let mut engine = CeremonyEngine::new(Profile::L2);

    // TUF root tool => mutates org root
    let intent = make_intent(Profile::L2, ActionClass::A4, "mcp://tuf/publish", "tuf", 1);
    assert!(intent.is_org_root_mutation());
    assert!(intent.required_factors.contains(&Factor::KofnEd25519Quorum));

    // 2-of-3 quorum policy
    let sk1 = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let sk2 = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let sk3 = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);

    let policy = QuorumPolicy::new(
        vec![
            sk1.verifying_key(),
            sk2.verifying_key(),
            sk3.verifying_key(),
        ],
        2,
    )
    .unwrap();

    let d_jcs = intent.d_jcs().unwrap();
    let sig1: ed25519_dalek::Signature = sk1.sign(&d_jcs);
    let sig2: ed25519_dalek::Signature = sk2.sign(&d_jcs);

    let sigs_valid = vec![
        QuorumSignature {
            public_key: sk1.verifying_key().to_bytes().to_vec(),
            signature: sig1.to_bytes().to_vec(),
            collected_at_ms: NOW as u64 * 1000,
        },
        QuorumSignature {
            public_key: sk2.verifying_key().to_bytes().to_vec(),
            signature: sig2.to_bytes().to_vec(),
            collected_at_ms: NOW as u64 * 1000,
        },
    ];

    // Hardware devices
    let mut ui = ScriptedCoreAuthUi::new([Scripted::Approve, Scripted::Approve]);
    let sep_key = ui.enrolled_key();
    let mut rig = test_rig(Profile::L2);

    // 2 of 3 valid signatures => quorum satisfied!
    let grant = engine
        .run(
            &intent,
            None,
            CeremonyHardware {
                biometric: Some(&mut ui),
                sep_key: Some(sep_key),
                yubikey: Some(&mut rig.dev),
                credential: Some(&rig.cred),
                mds: Some(&rig.mds),
                counters: Some(&mut rig.counters),
                oidc_verifier: Some(&verifier),
                oidc_token: Some(&token),
                quorum_policy: Some(&policy),
                quorum_signatures: Some(&sigs_valid),
                ..Default::default()
            },
            &clock,
        )
        .unwrap();

    assert!(grant.factors.contains(&Factor::KofnEd25519Quorum));
    assert!(grant.factors.contains(&Factor::YubikeyUp));

    // Only 1 signature => fails closed with QUORUM_NOT_MET
    let sigs_insufficient = vec![sigs_valid[0].clone()];
    let err = engine
        .run(
            &intent,
            None,
            CeremonyHardware {
                biometric: Some(&mut ui),
                sep_key: Some(sep_key),
                yubikey: Some(&mut rig.dev),
                credential: Some(&rig.cred),
                mds: Some(&rig.mds),
                counters: Some(&mut rig.counters),
                oidc_verifier: Some(&verifier),
                oidc_token: Some(&token),
                quorum_policy: Some(&policy),
                quorum_signatures: Some(&sigs_insufficient),
                ..Default::default()
            },
            &clock,
        )
        .unwrap_err();
    assert!(err.is("QUORUM_NOT_MET"));
}

// ---------------------------------------------------------------------------
// 6. L3 A3 & A4: Chained Ceremony + Egress Gate
// ---------------------------------------------------------------------------

#[test]
fn ceremony_l3_a3_and_a4_chained_with_egress_gate() {
    let clock = TestClock::at(NOW);
    let mut engine = CeremonyEngine::new(Profile::L3);
    let intent = make_intent(
        Profile::L3,
        ActionClass::A3,
        "mcp://postgres/query",
        "dev-billing",
        1,
    );
    let mut ui = ScriptedCoreAuthUi::new([Scripted::Approve]);
    let sep_key = ui.enrolled_key();
    let mut rig = test_rig(Profile::L3);
    let mut gate = MockEgressGate::default();

    let grant = engine
        .run(
            &intent,
            None,
            CeremonyHardware {
                biometric: Some(&mut ui),
                sep_key: Some(sep_key),
                yubikey: Some(&mut rig.dev),
                credential: Some(&rig.cred),
                mds: Some(&rig.mds),
                counters: Some(&mut rig.counters),
                egress: Some(&mut gate),
                ..Default::default()
            },
            &clock,
        )
        .unwrap();

    assert_eq!(
        grant.factors,
        BTreeSet::from([
            Factor::SepWorkloadKey,
            Factor::TouchIdCoreauthui,
            Factor::YubikeyPresent,
            Factor::YubikeyUp,
            Factor::YubikeyPinUv,
            Factor::ZkEgressGate,
        ])
    );
    assert_eq!(gate.0, 1);
}


#[test]
fn higher_profile_a4_keeps_baseline_idp_factor_and_requires_genuine_valid_token() {
    for profile in [Profile::L2, Profile::L3] {
        for condition in ["valid", "missing-verifier", "missing-token", "stale", "wrong-signer"] {
            let clock = TestClock::at(NOW);
            let mut engine = CeremonyEngine::new(profile);
            let intent = make_intent(profile, ActionClass::A4, "mcp://analytics/export_csv", "dev-billing", 1);
            let idp = TestIdp::default();
            let verifier = idp.verifier();
            let wrong_idp = TestIdp::default();
            let token = match condition {
                "stale" => idp.mint_token("authorized-fixture-subject", NOW, 301).unwrap(),
                "wrong-signer" => wrong_idp.mint_token("authorized-fixture-subject", NOW, 0).unwrap(),
                _ => idp.mint_token("authorized-fixture-subject", NOW, 0).unwrap(),
            };
            let mut ui = ScriptedCoreAuthUi::new([Scripted::Approve]);
            let sep_key = ui.enrolled_key();
            let mut rig = test_rig(profile);
            let mut gate = MockEgressGate::default();
            let result = engine.run(&intent, None, CeremonyHardware {
                biometric: Some(&mut ui), sep_key: Some(sep_key),
                yubikey: Some(&mut rig.dev), credential: Some(&rig.cred),
                mds: Some(&rig.mds), counters: Some(&mut rig.counters),
                egress: Some(&mut gate),
                oidc_verifier: (condition != "missing-verifier").then_some(&verifier),
                oidc_token: (condition != "missing-token").then_some(token.as_str()),
                ..Default::default()
            }, &clock);
            match condition {
                "valid" => assert!(result.unwrap().factors.contains(&Factor::OidcStepUp)),
                "missing-verifier" => assert!(result.unwrap_err().is("OIDC_VERIFIER_UNAVAILABLE")),
                "missing-token" => assert!(result.unwrap_err().is("OIDC_TOKEN_REQUIRED")),
                "stale" => assert!(result.unwrap_err().is("OIDC_AUTH_TIME_STALE")),
                "wrong-signer" => assert!(result.unwrap_err().is("OIDC_SIGNATURE_INVALID")),
                _ => unreachable!(),
            }
        }
    }
}
