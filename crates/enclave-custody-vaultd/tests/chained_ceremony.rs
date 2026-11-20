//! End-to-end FS-703 ceremonies over the real CTAP stack against the
//! virtual authenticator, with the scripted CoreAuthUI provider.

use enclave_core::ipc::PeerCredentials;
use enclave_core::profile::{ActionClass, Profile};
use enclave_custody_vaultd::biometric::{
    BiometricOutcome, BiometricPrompt, BiometricProvider, Scripted, ScriptedCoreAuthUi,
};
use enclave_custody_vaultd::ceremony::{CeremonyEngine, CeremonyHardware, EgressGate, PrfTier};
use enclave_custody_vaultd::clock::{Clock, TestClock};
use enclave_custody_vaultd::ctap::assertion::{EnrolledCredential, SignCountStore};
use enclave_custody_vaultd::ctap::client::{enroll, CtapClient};
use enclave_custody_vaultd::ctap::mds::{MdsAllowlist, MdsEntry, MdsState};
use enclave_custody_vaultd::ctap::virtual_device::{Presence, VirtualAuthenticator};
use enclave_custody_vaultd::factors::{required_factors, Factor};
use enclave_custody_vaultd::intent::{CustodyGrant, IntentPayloadV1};
use enclave_custody_vaultd::pii::PiiKind;
use enclave_custody_vaultd::quorum::{verify_quorum, QuorumApproval};
use enclave_custody_vaultd::service::{
    TokenizeItem, VaultConfig, VaultHardware, VaultRequest, VaultResponse, VaultService,
};
use enclave_custody_vaultd::vault::ReversibleTokenizeGrant;
use enclave_custody_vaultd::zeroizer::TamperEvent;

const NOW: i64 = 1_793_884_860;

fn intent(profile: Profile, action: ActionClass, rows: u64) -> IntentPayloadV1 {
    IntentPayloadV1 {
        v: 1,
        schema_version: Some("enclave.intent.v1".into()),
        action_class: action,
        profile,
        data_class: None,
        spiffe_id: "spiffe://corporate.internal/enclave/uid/704".into(),
        tool_name: "detokenize_row".into(),
        target_namespace: Some("dev-billing".into()),
        human_summary_trusted: None,
        row_count_bound: Some(rows),
        arguments_jcs_sha256: None,
        canonical_arguments_blake3: "5".repeat(64),
        model_blake3: None,
        policy_blake3: "6".repeat(64),
        qif_millibits_delta: Some(0),
        custody_grant: Some(CustodyGrant::None),
        boot_epoch_id: enclave_core::seq::new_boot_epoch_id(),
        rpc_seq_u64: 1,
        ts_utc_ms: 1_762_308_012_405,
        required_factors: required_factors(profile, action, false)
            .into_iter()
            .collect(),
        user_turn: None,
    }
}

struct Rig {
    dev: VirtualAuthenticator,
    cred: EnrolledCredential,
    mds: MdsState,
    ui: ScriptedCoreAuthUi,
    counters: SignCountStore,
    clock: TestClock,
}

fn rig(profile: Profile) -> Rig {
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
    Rig {
        dev,
        cred,
        mds,
        ui: ScriptedCoreAuthUi::new([]),
        counters: SignCountStore::default(),
        clock: TestClock::at(NOW),
    }
}

#[derive(Debug, Default)]
struct OkGate(usize);
impl EgressGate for OkGate {
    fn approve(&mut self, _d: &[u8; 32]) -> enclave_core::EnclaveResult<()> {
        self.0 += 1;
        Ok(())
    }
}

fn run<'a>(
    engine: &mut CeremonyEngine,
    r: &'a mut Rig,
    i: &IntentPayloadV1,
    tier: Option<PrfTier>,
    gate: Option<&'a mut dyn EgressGate>,
) -> enclave_core::EnclaveResult<enclave_custody_vaultd::ceremony::CeremonyGrant> {
    let k = r.ui.enrolled_key();
    engine.run(
        i,
        tier,
        CeremonyHardware {
            biometric: Some(&mut r.ui),
            sep_key: Some(k),
            sep_bio_blob: None,
            yubikey: Some(&mut r.dev),
            credential: Some(&r.cred),
            mds: Some(&r.mds),
            counters: Some(&mut r.counters),
            egress: gate,
            ..Default::default()
        },
        &r.clock,
    )
}

#[test]
fn l2_a3_chained_touch_id_then_yubikey_with_prf() {
    let mut r = rig(Profile::L2);
    r.ui.push(Scripted::Approve);
    let mut e = CeremonyEngine::new(Profile::L2);
    let g = run(
        &mut e,
        &mut r,
        &intent(Profile::L2, ActionClass::A3, 1),
        Some(PrfTier::A3),
        None,
    )
    .unwrap();
    assert!(
        g.factors.contains(&Factor::TouchIdCoreauthui) && g.factors.contains(&Factor::YubikeyUp)
    );
    assert_eq!(g.prf.as_ref().unwrap().len(), 32);
    assert_eq!(r.dev.assertion_requests, 1);
    assert!(r.ui.shown[0].contains("SAS: "));
}

#[test]
fn cancelled_touch_id_never_arms_the_yubikey() {
    let mut r = rig(Profile::L2);
    r.ui.push(Scripted::Cancel);
    let mut e = CeremonyEngine::new(Profile::L2);
    let err = run(
        &mut e,
        &mut r,
        &intent(Profile::L2, ActionClass::A3, 1),
        Some(PrfTier::A3),
        None,
    )
    .unwrap_err();
    assert!(err.is("TOUCH_ID_CANCELLED"));
    assert_eq!(
        r.dev.assertion_requests, 0,
        "YubiKey LED must never arm after a cancelled Touch ID"
    );
    // Occlusion and dwell violations are equally fatal before step 2.
    r.ui.push(Scripted::Occlude);
    assert!(run(
        &mut e,
        &mut r,
        &intent(Profile::L2, ActionClass::A3, 1),
        None,
        None
    )
    .unwrap_err()
    .is("UI_OCCLUSION_ABORT"));
    r.clock.advance_ms(61_000);
    r.ui.push(Scripted::ApproveWithoutDwell);
    assert!(run(
        &mut e,
        &mut r,
        &intent(Profile::L2, ActionClass::A3, 1),
        None,
        None
    )
    .unwrap_err()
    .is("DWELL_GATE_VIOLATION"));
    assert_eq!(r.dev.assertion_requests, 0);
}

#[test]
fn rate_limit_three_prompts_per_minute() {
    let mut r = rig(Profile::L2);
    let mut e = CeremonyEngine::new(Profile::L2);
    for _ in 0..3 {
        r.ui.push(Scripted::Approve);
        run(
            &mut e,
            &mut r,
            &intent(Profile::L2, ActionClass::A3, 1),
            None,
            None,
        )
        .unwrap();
    }
    r.ui.push(Scripted::Approve);
    assert!(run(
        &mut e,
        &mut r,
        &intent(Profile::L2, ActionClass::A3, 1),
        None,
        None
    )
    .unwrap_err()
    .is("PROMPT_RATE_LIMIT"));
    r.clock.advance_ms(60_001);
    run(
        &mut e,
        &mut r,
        &intent(Profile::L2, ActionClass::A3, 1),
        None,
        None,
    )
    .unwrap();
}

#[test]
fn prompt_cooldown_after_five_timeouts_and_on_report_clearable_by_touch_id() {
    let mut r = rig(Profile::L2);
    let mut e = CeremonyEngine::new(Profile::L2);
    for i in 0..5 {
        r.ui.push(Scripted::Timeout);
        assert!(run(
            &mut e,
            &mut r,
            &intent(Profile::L2, ActionClass::A3, 1),
            None,
            None
        )
        .unwrap_err()
        .is("TOUCH_ID_TIMEOUT"));
        r.clock.advance_ms(21_000); // stay under the 3/60 s cap
        assert_eq!(e.cooldown_active(r.clock.now_ms()), i == 4, "{i}");
    }
    // Rejected before any UI is shown.
    let shown = r.ui.shown.len();
    assert!(run(
        &mut e,
        &mut r,
        &intent(Profile::L2, ActionClass::A3, 1),
        None,
        None
    )
    .unwrap_err()
    .is("PROMPT_COOLDOWN_60S"));
    assert_eq!(r.ui.shown.len(), shown);
    // Two cancellations do NOT latch anything (FS-703: a buggy agent cannot lock the developer out).
    let k = r.ui.enrolled_key();
    r.ui.push(Scripted::Approve);
    e.clear_cooldown(&mut r.ui, &k, &[0u8; 32], &r.clock).unwrap();
    assert!(!e.cooldown_active(r.clock.now_ms()));
    r.clock.advance_ms(61_000);
    r.ui.push(Scripted::Report);
    assert!(run(
        &mut e,
        &mut r,
        &intent(Profile::L2, ActionClass::A3, 1),
        None,
        None
    )
    .unwrap_err()
    .is("USER_REPORTED_SUSPICIOUS_PROMPT"));
    assert!(e.cooldown_active(r.clock.now_ms()));
    r.clock.advance_ms(60_001);
    assert!(
        !e.cooldown_active(r.clock.now_ms()),
        "cooldown is session-local and expires"
    );
}

#[test]
fn yubikey_failures_fail_closed() {
    let mut e = CeremonyEngine::new(Profile::L2);
    // No touch.
    let mut r = rig(Profile::L2);
    r.dev.presence = Presence::NoTouch;
    r.ui.push(Scripted::Approve);
    assert!(run(
        &mut e,
        &mut r,
        &intent(Profile::L2, ActionClass::A3, 1),
        None,
        None
    )
    .unwrap_err()
    .is("YUBIKEY_TOUCH_TIMEOUT"));
    // Unplugged mid-ceremony.
    let mut r = rig(Profile::L2);
    r.dev.presence = Presence::Unplugged;
    r.ui.push(Scripted::Approve);
    let mut e = CeremonyEngine::new(Profile::L2);
    assert!(run(
        &mut e,
        &mut r,
        &intent(Profile::L2, ActionClass::A3, 1),
        None,
        None
    )
    .unwrap_err()
    .is("DEVICE_REMOVED"));
    // Cloned authenticator replays an old counter.
    let mut r = rig(Profile::L2);
    let mut e = CeremonyEngine::new(Profile::L2);
    r.ui.push(Scripted::Approve);
    run(
        &mut e,
        &mut r,
        &intent(Profile::L2, ActionClass::A3, 1),
        None,
        None,
    )
    .unwrap();
    r.dev.force_sign_count(0);
    r.ui.push(Scripted::Approve);
    assert!(run(
        &mut e,
        &mut r,
        &intent(Profile::L2, ActionClass::A3, 1),
        None,
        None
    )
    .unwrap_err()
    .is("SIGN_COUNT_REGRESSION"));
}

#[test]
fn mds_lifecycle_revocation_firmware_and_staleness() {
    let mut r = rig(Profile::L2);
    let mut e = CeremonyEngine::new(Profile::L2);
    r.mds.refreshed_at = NOW - 73 * 3600;
    r.ui.push(Scripted::Approve);
    assert!(run(
        &mut e,
        &mut r,
        &intent(Profile::L2, ActionClass::A3, 1),
        None,
        None
    )
    .unwrap_err()
    .is("CUSTODY_METADATA_STALE"));
    r.mds.refreshed_at = NOW;
    r.mds.allowlist.entries[0]
        .status_reports
        .push("REVOKED".into());
    r.ui.push(Scripted::Approve);
    assert!(run(
        &mut e,
        &mut r,
        &intent(Profile::L2, ActionClass::A3, 1),
        None,
        None
    )
    .unwrap_err()
    .is("AUTHENTICATOR_REVOKED"));
    r.mds.allowlist.entries[0].status_reports.pop();
    r.mds.allowlist.entries[0].min_firmware_version = 0x05_07_02;
    r.ui.push(Scripted::Approve);
    r.clock.advance_ms(61_000);
    assert!(run(
        &mut e,
        &mut r,
        &intent(Profile::L2, ActionClass::A3, 1),
        None,
        None
    )
    .unwrap_err()
    .is("FIRMWARE_BELOW_MINIMUM"));
    assert_eq!(r.dev.assertion_requests, 0);
}

#[test]
fn l3_root_port_uv_and_egress_gate() {
    let mut e = CeremonyEngine::new(Profile::L3);
    let mut r = rig(Profile::L3);
    r.dev.hub_depth = 2;
    r.ui.push(Scripted::Approve);
    let mut g = OkGate::default();
    assert!(run(
        &mut e,
        &mut r,
        &intent(Profile::L3, ActionClass::A3, 1),
        None,
        Some(&mut g)
    )
    .unwrap_err()
    .is("HUB_TOPOLOGY_REJECTED"));
    r.dev.hub_depth = 1;
    r.dev.uv_capable = false;
    r.ui.push(Scripted::Approve);
    assert!(run(
        &mut e,
        &mut r,
        &intent(Profile::L3, ActionClass::A3, 1),
        None,
        Some(&mut g)
    )
    .unwrap_err()
    .is("YUBIKEY_PIN_PROVIDER_REQUIRED"));
    assert_eq!(r.dev.assertion_requests, 0, "missing PIN provider must stop before authenticator assertion");
    r.dev.uv_capable = true;
    r.ui.push(Scripted::Approve);
    r.clock.advance_ms(61_000);
    assert!(run(
        &mut e,
        &mut r,
        &intent(Profile::L3, ActionClass::A3, 1),
        None,
        None
    )
    .unwrap_err()
    .is("ZK_EGRESS_GATE_UNAVAILABLE"));
    r.ui.push(Scripted::Approve);
    let grant = run(
        &mut e,
        &mut r,
        &intent(Profile::L3, ActionClass::A3, 1),
        Some(PrfTier::A3),
        Some(&mut g),
    )
    .unwrap();
    assert!(grant
        .factors
        .is_superset(&required_factors(Profile::L3, ActionClass::A3, false)));
    assert_eq!(g.0, 1);
}

#[derive(Debug)]
struct SlowUi(ScriptedCoreAuthUi, TestClock);
impl BiometricProvider for SlowUi {
    fn evaluate(&mut self, p: &BiometricPrompt) -> BiometricOutcome {
        let o = self.0.evaluate(p);
        self.1.advance_ms(10_500);
        o
    }
}

#[test]
fn ten_second_chained_budget_enforced() {
    let mut r = rig(Profile::L2);
    let mut ui = SlowUi(
        ScriptedCoreAuthUi::new([Scripted::Approve]),
        r.clock.clone(),
    );
    let k = ui.0.enrolled_key();
    let mut e = CeremonyEngine::new(Profile::L2);
    let err = e
        .run(
            &intent(Profile::L2, ActionClass::A3, 1),
            None,
            CeremonyHardware {
                biometric: Some(&mut ui),
                sep_key: Some(k),
                sep_bio_blob: None,
                yubikey: Some(&mut r.dev),
                credential: Some(&r.cred),
                mds: Some(&r.mds),
                counters: Some(&mut r.counters),
                egress: None,
                ..Default::default()
            },
            &r.clock,
        )
        .unwrap_err();
    assert!(err.is("CEREMONY_BUDGET_EXCEEDED"));
    assert_eq!(r.dev.assertion_requests, 0, "expired biometric must never arm CTAP");
}

#[test]
fn counter_checkpoint_precedes_prf_and_rechecks_expiry() {
    for outcome in ["allow", "counter_io", "metadata_expired", "deadline"] {
        let mut r = rig(Profile::L2);
        r.ui.push(Scripted::Approve);
        let key = r.ui.enrolled_key();
        let credential_id = r.cred.credential_id.clone();
        let clock = r.clock.clone();
        let mut checkpoints = 0;
        let mut checkpoint = |counters: &SignCountStore| {
            checkpoints += 1;
            assert!(counters.get(&credential_id) > 0, "persist verified advancement before PRF use");
            match outcome {
                "counter_io" => Err(enclave_core::err!(EIO, "TEST_COUNTER_PERSIST_FAILED")),
                "metadata_expired" => { clock.advance_ms(72 * 3600 * 1000); Ok(()) },
                "deadline" => { clock.advance_ms(10_000); Ok(()) },
                _ => Ok(()),
            }
        };
        let result = CeremonyEngine::new(Profile::L2).run_with_counter_checkpoint(
            &intent(Profile::L2, ActionClass::A3, 1), Some(PrfTier::A3),
            CeremonyHardware {
                biometric: Some(&mut r.ui), sep_key: Some(key),
                yubikey: Some(&mut r.dev), credential: Some(&r.cred),
                mds: Some(&r.mds), counters: Some(&mut r.counters),
                ..Default::default()
            }, &r.clock, &mut checkpoint,
        );
        assert_eq!(checkpoints, 1);
        assert!(r.counters.get(&credential_id) > 0, "denial cannot restore the consumed counter");
        match outcome {
            "allow" => assert_eq!(result.unwrap().prf.unwrap().len(), 32),
            "counter_io" => assert!(result.unwrap_err().is("TEST_COUNTER_PERSIST_FAILED")),
            "metadata_expired" => assert!(result.unwrap_err().is("CUSTODY_METADATA_STALE")),
            "deadline" => assert!(result.unwrap_err().is("CEREMONY_BUDGET_EXCEEDED")),
            _ => unreachable!(),
        }
    }
}

#[test]
fn complete_budget_includes_the_final_egress_factor() {
    #[derive(Debug)]
    struct SlowGate(TestClock);
    impl EgressGate for SlowGate {
        fn approve(&mut self, _: &[u8; 32]) -> enclave_core::EnclaveResult<()> {
            self.0.advance_ms(10_000);
            Ok(())
        }
    }
    let mut r = rig(Profile::L3);
    r.ui.push(Scripted::Approve);
    let mut gate = SlowGate(r.clock.clone());
    let error = run(&mut CeremonyEngine::new(Profile::L3), &mut r,
        &intent(Profile::L3, ActionClass::A3, 1), Some(PrfTier::A3), Some(&mut gate))
        .unwrap_err();
    assert!(error.is("CEREMONY_BUDGET_EXCEEDED"));
}

#[test]
fn two_of_three_custodian_quorum() {
    let digest: [u8; 32] = [7u8; 32];
    let mut rigs: Vec<Rig> = (0..3).map(|_| rig(Profile::L3)).collect();
    let enrolled: Vec<EnrolledCredential> = rigs.iter().map(|r| r.cred.clone()).collect();
    let mut approvals = vec![];
    for r in rigs.iter_mut().take(2) {
        let mut c = CtapClient::open(&mut r.dev).unwrap();
        let (resp, _) = c
            .get_assertion(&r.cred.credential_id, &digest, false, None)
            .unwrap();
        approvals.push(QuorumApproval {
            credential_id: r.cred.credential_id.clone(),
            auth_data: resp.auth_data,
            signature: resp.signature,
            collected_at: NOW,
        });
    }
    let mut counters = SignCountStore::default();
    assert_eq!(
        verify_quorum(&enrolled, 2, &digest, &approvals, &mut counters, NOW + 10).unwrap(),
        2
    );
    let mut counters = SignCountStore::default();
    assert!(
        verify_quorum(&enrolled, 3, &digest, &approvals, &mut counters, NOW + 10)
            .unwrap_err()
            .is("QUORUM_NOT_MET")
    );
    let mut counters = SignCountStore::default();
    assert!(
        verify_quorum(&enrolled, 2, &[8u8; 32], &approvals, &mut counters, NOW).is_err(),
        "different grant digest"
    );
    let mut counters = SignCountStore::default();
    assert!(
        verify_quorum(
            &enrolled,
            2,
            &digest,
            &approvals,
            &mut counters,
            NOW + 25 * 3600
        )
        .is_err(),
        "24h TTL"
    );
    let dup = vec![approvals[0].clone(), approvals[0].clone()];
    let mut counters = SignCountStore::default();
    assert!(verify_quorum(&enrolled, 2, &digest, &dup, &mut counters, NOW).is_err());
}

fn me() -> PeerCredentials {
    PeerCredentials {
        uid: enclave_core::ipc::geteuid(),
        gid: 0,
        pid: None,
        audit_token: None,
        code_identity: None,
        tls_channel_binding: None,
    }
}

#[test]
fn service_l2_tokenize_detokenize_and_tamper_wipe() {
    use ed25519_dalek::Signer;
    use enclave_custody_vaultd::oidc_acquisition::{IntentOidcProvider,BoundOidcStepUp};
    use enclave_core::{EnclaveResult,secret::SecretBytes};
    use std::sync::{Arc,atomic::{AtomicBool,AtomicUsize,Ordering}};
    #[derive(Debug)] struct SignedOidcFixture {key:ed25519_dalek::SigningKey,calls:Arc<AtomicUsize>}
    impl IntentOidcProvider for SignedOidcFixture {
        fn acquire(&mut self,intent:&IntentPayloadV1,start:u64,deadline:u64,cancelled:&AtomicBool)->EnclaveResult<BoundOidcStepUp> {
            if cancelled.load(Ordering::SeqCst) {enclave_core::fail!(EACCES,"FIXTURE_OIDC_CANCELLED");}
            self.calls.fetch_add(1,Ordering::SeqCst);let now=enclave_crypto::time::now_unix();
            let issuer="https://signed-fixture.example";let subject="synthetic-custodian";let nonce=hex::encode(enclave_core::rng::bytes32());
            let header=enclave_crypto::b64::enc(br#"{"alg":"EdDSA","typ":"JWT"}"#);
            let claims=serde_json::json!({"iss":issuer,"aud":"fixture-vault","sub":subject,"exp":now+60,"iat":now,"auth_time":now,"nonce":nonce});
            let claims=enclave_crypto::b64::enc(&serde_json::to_vec(&claims).unwrap());let message=format!("{header}.{claims}");
            let signature=self.key.sign(message.as_bytes());let token=SecretBytes::new(format!("{message}.{}",enclave_crypto::b64::enc(&signature.to_bytes())).into_bytes());
            use sha2::{Digest,Sha256};let mut principal=Sha256::new();principal.update(b"depot-OIDC-Subject-v1\0");principal.update(issuer.as_bytes());principal.update([0]);principal.update(subject.as_bytes());
            let authority=serde_json::to_vec(&serde_json::json!({"v":1,"issuer":issuer,"audience":"fixture-vault",
                "subject_sha256":hex::encode(principal.finalize()),"ed25519_public_keys":[hex::encode(self.key.verifying_key().as_bytes())],
                "not_before_unix":now-1,"expires_unix":now+60})).unwrap();
            BoundOidcStepUp::from_signed_fixture(&authority,token,nonce,intent,start,deadline,now)
        }
    }
    #[derive(Debug)] struct CountingBiometric {inner:Box<dyn BiometricProvider+Send>,calls:Arc<AtomicUsize>}
    impl BiometricProvider for CountingBiometric {fn evaluate(&mut self,prompt:&BiometricPrompt)->BiometricOutcome {
        self.calls.fetch_add(1,Ordering::SeqCst);self.inner.evaluate(prompt)
    }}
    let policy = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let now = enclave_crypto::time::now_unix();
    let mut hw = VaultHardware::simulated(Profile::L2, now).unwrap();
    let oidc_calls=Arc::new(AtomicUsize::new(0));let biometric_calls=Arc::new(AtomicUsize::new(0));
    hw.oidc_provider=Some(Box::new(SignedOidcFixture {key:ed25519_dalek::SigningKey::from_bytes(&[75;32]),calls:oidc_calls.clone()}));
    hw.biometric=Box::new(CountingBiometric {inner:hw.biometric,calls:biometric_calls.clone()});
    let svc = VaultService::start(
        VaultConfig {
            profile: Profile::L2,
            audit_path: None,
            grant_key: Some(policy.verifying_key()),
            state_dir: None,
            socket_dir: None,
            dev_same_uid: false,
        },
        hw,
    )
    .unwrap();
    // C3 single-row → A3; detokenize under an A3 chained ceremony.
    let VaultResponse::Tokens(t) = svc
        .handle(
            &me(),
            VaultRequest::Tokenize {
                items: vec![TokenizeItem {
                    value: "jane@example.com".into(),
                    declared: None,
                }],
                bulk_set: false,
                grant: None,
            },
        )
        .unwrap()
    else {
        panic!()
    };
    let VaultResponse::Delivered { rows, .. } = svc
        .handle(
            &me(),
            VaultRequest::Detokenize {
                surrogates: vec![t[0].token.clone()],
                draft: detok(Profile::L2, ActionClass::A3, 1),
            },
        )
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(rows, 1);
    // C4 SSN with a Cedar grant → A4; requires an A4 ceremony.
    let exp = now + 3600;
    let grant = ReversibleTokenizeGrant {
        workflow: "fraud-review".into(),
        profile: Profile::L2,
        expires_unix: exp,
        signature: policy
            .sign(&ReversibleTokenizeGrant::message(
                "fraud-review",
                Profile::L2,
                exp,
            ))
            .to_bytes()
            .to_vec(),
    };
    let c4_request=VaultRequest::Tokenize {
        items:vec![TokenizeItem {value:"078-05-1120".into(),declared:Some(PiiKind::Ssn)}],
        bulk_set:false,grant:Some(grant),
    };
    let VaultResponse::Tokens(t4)=svc.handle(&me(),c4_request.clone()).unwrap() else {panic!()};
    assert!(t4[0].token.starts_with("SYNTH-SSN-"));
    // A denied A3 attempt still consumes its fresh prompt admission. Exercise
    // wrong-action refusal on a separate real service fixture so the main
    // A3/A4/post-fence sequence preserves the production3-per-minute limit.
    {
        let denied=VaultService::start(VaultConfig {profile:Profile::L2,
            grant_key:Some(policy.verifying_key()),..Default::default()},
            VaultHardware::simulated(Profile::L2,now).unwrap()).unwrap();
        let VaultResponse::Tokens(wrong_tier)=denied.handle(&me(),c4_request).unwrap() else {panic!()};
        let error=denied.handle(&me(),VaultRequest::Detokenize {
            surrogates:vec![wrong_tier[0].token.clone()],draft:detok(Profile::L2,ActionClass::A3,1),
        }).unwrap_err();
        assert!(error.is("A4_GRANT_REQUIRED"),"{error}");
    }
    let VaultResponse::Delivered { rows, .. } = svc
        .handle(
            &me(),
            VaultRequest::Detokenize {
                surrogates: vec![t4[0].token.clone()],
                draft: detok(Profile::L2, ActionClass::A4, 1),
            },
        )
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(rows, 1);
    assert_eq!(oidc_calls.load(Ordering::SeqCst),1,"A4 used a genuine signed, nonce-bound OIDC token");
    // Tamper fences the old authorization; encrypted records remain available
    // only after a complete fresh ceremony, as the durable custody contract requires.
    let VaultResponse::Zeroized(rep) = svc
        .handle(&me(), VaultRequest::Tamper(TamperEvent::ScreenLock))
        .unwrap()
    else {
        panic!()
    };
    assert!(!rep.thawed);
    let before=biometric_calls.load(Ordering::SeqCst);
    assert!(matches!(svc
        .handle(
            &me(),
            VaultRequest::Detokenize {
                surrogates: vec![t[0].token.clone()],
                draft: detok(Profile::L2, ActionClass::A3, 1)
            }
        )
        .unwrap(),VaultResponse::Delivered {rows:1,..}));
    assert_eq!(biometric_calls.load(Ordering::SeqCst),before+1,"post-fence delivery used fresh factors");
}

#[test]
fn service_l1_never_detokenizes_c4_and_rejects_over_bound() {
    let now = enclave_crypto::time::now_unix();
    let svc = VaultService::start(
        VaultConfig {
            profile: Profile::L1,
            audit_path: None,
            grant_key: None,
            state_dir: None,
            socket_dir: None,
            dev_same_uid: false,
        },
        VaultHardware::simulated(Profile::L1, now).unwrap(),
    )
    .unwrap();
    let VaultResponse::Tokens(t) = svc
        .handle(
            &me(),
            VaultRequest::Tokenize {
                items: vec![
                    TokenizeItem {
                        value: "078-05-1120".into(),
                        declared: None,
                    },
                    TokenizeItem {
                        value: "a@b.io".into(),
                        declared: None,
                    },
                    TokenizeItem {
                        value: "c@d.io".into(),
                        declared: None,
                    },
                ],
                bulk_set: false,
                grant: None,
            },
        )
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(t[0].token, "[REDACTED_SSN_C4]");
    // Two surrogates against a 1-row grant: aborted before decryption.
    let e = svc
        .handle(
            &me(),
            VaultRequest::Detokenize {
                surrogates: vec![t[1].token.clone(), t[2].token.clone()],
                draft: detok(Profile::L1, ActionClass::A3, 1),
            },
        )
        .unwrap_err();
    assert!(e.is("ROW_COUNT_EXCEEDS_GRANT"), "{e}");
    svc.handle(
        &me(),
        VaultRequest::Detokenize {
            surrogates: vec![t[1].token.clone()],
            draft: detok(Profile::L1, ActionClass::A3, 1),
        },
    )
    .unwrap();
}

fn detok(
    profile: Profile,
    action: ActionClass,
    rows: u64,
) -> Box<enclave_core::intent_draft::IntentDraftV1> {
    let mut d = draft(action);
    d.profile = profile;
    d.row_count_bound = rows;
    d.tool_name = "detokenize_row".into();
    d.canonical_verb = "Reveal".into();
    d.data_class = if action == ActionClass::A4 {
        enclave_core::label::Conf::C4
    } else {
        enclave_core::label::Conf::C3
    };
    if profile == Profile::L1 {
        d.data_class = enclave_core::label::Conf::C3;
    }
    Box::new(d)
}

fn draft(action: ActionClass) -> enclave_core::intent_draft::IntentDraftV1 {
    enclave_core::intent_draft::IntentDraftV1 {
        action_class: action,
        profile: Profile::L2,
        data_class: enclave_core::label::Conf::C3,
        tool_name: "depot://postgres/export_csv".into(),
        target_namespace: "dev-billing".into(),
        canonical_verb: "Export".into(),
        row_count_bound: 1,
        arguments_jcs_sha256: "ab".repeat(32),
        canonical_arguments_blake3: "cd".repeat(32),
        policy_blake3: "ef".repeat(32),
        qif_millibits_delta: 0,
        org_root_mutation: false,
    }
}

#[test]
fn tool_step_up_intent_is_built_by_uid_703() {
    use enclave_custody_vaultd::service::intent_from_draft;
    let now = enclave_crypto::time::now_unix();
    let mut hardware = VaultHardware::simulated(Profile::L2, now).unwrap();
    let independent_expiry = now + 4;
    hardware.mds.as_mut().unwrap().expires_at = independent_expiry;
    let svc = VaultService::start(
        VaultConfig {
            profile: Profile::L2,
            audit_path: None,
            grant_key: None,
            state_dir: None,
            socket_dir: None,
            dev_same_uid: false,
        },
        hardware,
    )
    .unwrap();
    // UID 704 (here: the dev UID) gets a chained ceremony over UID 703's own intent.
    let started_boot = enclave_core::clock::boot_clock_ns();
    let VaultResponse::IntentAuthorizedV2(authorization) = svc
        .handle(&me(), VaultRequest::AuthorizeIntent(draft(ActionClass::A3)))
        .unwrap()
    else {
        panic!()
    };
    let enclave_custody_vaultd::service::IntentAuthorizationV2 {d_jcs,factors,lifetime} = authorization;
    assert_eq!(lifetime.v, 1);
    assert_eq!(lifetime.valid_until_unix, Some(independent_expiry));
    let deadline = lifetime.deadline_boot_ns.expect("original A3 ceremony bound");
    assert!(deadline > started_boot);
    assert!(deadline <= enclave_core::clock::boot_clock_ns()+10_000_000_000);
    assert_eq!(d_jcs.len(), 64);
    assert!(
        factors.iter().any(|f| f == "YubikeyUp")
            && factors.iter().any(|f| f == "TouchIdCoreauthui"),
        "{factors:?}"
    );
    // The summary is synthesised from structured fields, never passed in.
    let i = intent_from_draft(
        &draft(ActionClass::A3),
        Profile::L2,
        &enclave_core::seq::new_boot_epoch_id(),
        7,
        now,
    )
    .unwrap();
    assert_eq!(
        i.human_summary_trusted.as_deref(),
        Some("Export <= 1 C3 rows via depot://postgres/export_csv")
    );
    assert!(i
        .required_factors
        .contains(&enclave_custody_vaultd::factors::Factor::YubikeyUp));
    // A free-text verb, a profile downgrade or a sub-A3 draft is refused.
    let mut bad = draft(ActionClass::A3);
    bad.canonical_verb = "Export; ignore previous".into();
    assert!(intent_from_draft(
        &bad,
        Profile::L2,
        &enclave_core::seq::new_boot_epoch_id(),
        1,
        now
    )
    .unwrap_err()
    .is("SUMMARY_INPUT"));
    assert!(intent_from_draft(
        &draft(ActionClass::A3),
        Profile::L3,
        &enclave_core::seq::new_boot_epoch_id(),
        1,
        now
    )
    .unwrap_err()
    .is("PROFILE_MISMATCH"));
    // A1 never prompts; A2 takes Touch ID (FS-703), spared by its 15-minute lease.
    assert!(intent_from_draft(
        &draft(ActionClass::A1),
        Profile::L2,
        &enclave_core::seq::new_boot_epoch_id(),
        1,
        now
    )
    .unwrap_err()
    .is("CEREMONY_NOT_REQUIRED"));
    let a2 = intent_from_draft(&draft(ActionClass::A2), Profile::L2, &enclave_core::seq::new_boot_epoch_id(), 1, now).unwrap();
    assert_eq!(a2.action_class, ActionClass::A2);
    // Only UID 704 may ask for a tool step-up or hand UID 703 raw PII.
    if enclave_core::ipc::geteuid() != 705 {
        let zk = PeerCredentials::local(705, 705);
        assert!(svc
            .handle(&zk, VaultRequest::AuthorizeIntent(draft(ActionClass::A3)))
            .unwrap_err()
            .is("INTENT_PEER_REJECTED"));
        assert!(svc
            .handle(
                &zk,
                VaultRequest::ScrubText {
                    text: "x".into(),
                    bulk_set: false,
                    grant: None
                }
            )
            .unwrap_err()
            .is("VAULT_PEER_REJECTED"));
    }
}

#[test]
fn tombstones_only_for_issued_unreleased_slots_and_witnesses_for_released() {
    let now = enclave_crypto::time::now_unix();
    let dir = std::env::temp_dir().join(format!("depot-703-state-{}", enclave_core::rng::u64()));
    let start = || {
        VaultService::start(
            VaultConfig {
                profile: Profile::L1,
                audit_path: None,
                grant_key: None,
                state_dir: Some(dir.clone()),
                socket_dir: None,
                dev_same_uid: false,
            },
            VaultHardware::simulated(Profile::L1, now).unwrap(),
        )
        .unwrap()
    };
    let svc = start();
    let VaultResponse::Epoch(ep) = svc.handle(&me(), VaultRequest::BootEpoch).unwrap() else {
        panic!()
    };
    let e = ep.boot_epoch_id.clone();
    // Slot A: released by UID 703 (scrubbed text left for the model side).
    let VaultResponse::Text(t) = svc
        .handle(
            &me(),
            VaultRequest::ScrubText {
                text: "card 4111 1111 1111 1111".into(),
                bulk_set: false,
                grant: None,
            },
        )
        .unwrap()
    else {
        panic!()
    };
    assert!(!t.contains("4111"));
    // Slot B: allocated to UID 704 and never released by UID 703.
    let VaultResponse::Slot {
        rpc_seq_u64: b,
        boot_epoch_id,
    } = svc.handle(&me(), VaultRequest::AllocateSlot).unwrap()
    else {
        panic!()
    };
    assert_eq!(boot_epoch_id, e);
    let a = b - 1;
    // The prover gets witnesses only for released slots, with an ingress anchor.
    let VaultResponse::Witness { folds, next_slot } = svc
        .handle(
            &me(),
            VaultRequest::FetchWitness {
                boot_epoch_id: e.clone(),
                s_start: 0,
                s_end: 100,
            },
        )
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(
        folds.iter().map(|f| f.rpc_seq_u64).collect::<Vec<_>>(),
        vec![a]
    );
    assert_eq!(folds[0].h_ingress_mac.len(), 64);
    assert_eq!(next_slot, b + 1);
    // Tombstones: refused for the released slot and for a never-issued slot.
    let ts = |slot| {
        svc.handle(
            &me(),
            VaultRequest::CoSignTombstone {
                slot_rpc_seq: slot,
                boot_epoch_id: e.clone(),
            },
        )
    };
    assert!(ts(a).unwrap_err().is("TOMBSTONE_SLOT_RELEASED"));
    assert!(ts(b + 7).unwrap_err().is("TOMBSTONE_SLOT_UNKNOWN"));
    let VaultResponse::TombstoneSignature { public_key: k1, .. } = ts(b).unwrap() else {
        panic!()
    };
    // Non-governed requests consume no slot: the sequence stays contiguous.
    svc.handle(&me(), VaultRequest::Status).unwrap();
    let VaultResponse::Slot { rpc_seq_u64: c, .. } =
        svc.handle(&me(), VaultRequest::AllocateSlot).unwrap()
    else {
        panic!()
    };
    assert_eq!(c, b + 1);
    // Only UID 704 allocates; only UID 705 asks for tombstones and witnesses.
    if enclave_core::ipc::geteuid() != 701 {
        let m = PeerCredentials::local(701, 701);
        assert!(svc
            .handle(&m, VaultRequest::AllocateSlot)
            .unwrap_err()
            .is("SLOT_PEER_REJECTED"));
        assert!(svc
            .handle(
                &m,
                VaultRequest::CoSignTombstone {
                    slot_rpc_seq: b,
                    boot_epoch_id: e.clone()
                }
            )
            .unwrap_err()
            .is("TOMBSTONE_PEER_REJECTED"));
        assert!(svc
            .handle(
                &m,
                VaultRequest::FetchWitness {
                    boot_epoch_id: e.clone(),
                    s_start: 0,
                    s_end: 1
                }
            )
            .unwrap_err()
            .is("WITNESS_PEER_REJECTED"));
    }
    drop(svc);
    // After a restart: same tombstone key, and the old epoch's released slot
    // still cannot be tombstoned.
    let svc = start();
    let VaultResponse::TombstoneSignature { public_key: k2, .. } = svc
        .handle(
            &me(),
            VaultRequest::CoSignTombstone {
                slot_rpc_seq: b,
                boot_epoch_id: e.clone(),
            },
        )
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(k1, k2);
    assert!(svc
        .handle(
            &me(),
            VaultRequest::CoSignTombstone {
                slot_rpc_seq: a,
                boot_epoch_id: e.clone()
            }
        )
        .unwrap_err()
        .is("TOMBSTONE_SLOT_RELEASED"));
    std::fs::remove_dir_all(dir).ok();
}

/// GAP-28: the `signCount` high-water mark survives a restart. A daemon
/// restarted between assertions keeps accepting the real key, refuses a
/// clone whose counter was rewound below what it already saw (including a
/// counter consumed by a request after boot), and refuses to start "clean"
/// when the sealed counter store is deleted.
#[test]
fn sign_count_survives_restart_and_rewound_clone_is_rejected() {
    use enclave_custody_vaultd::ctap::virtual_device::VirtualAuthenticator;
    let now = enclave_crypto::time::now_unix();
    let dir =
        std::env::temp_dir().join(format!("depot-703-signcount-{}", enclave_core::rng::u64()));
    // One physical key, enrolled once; each boot gets a clone of its secrets.
    let aaguid = [0xee; 16];
    let mut key = VirtualAuthenticator::new(aaguid);
    let mds = MdsState {
        allowlist: MdsAllowlist {
            entries: vec![MdsEntry {
                aaguid: hex::encode(aaguid),
                description: "test".into(),
                min_firmware_version: 0x05_07_00,
                status_reports: vec!["FIDO_CERTIFIED".into()],
                attestation_public_keys: vec![key.attestation_key_mds()],
                attestation_root_certificates: Vec::new(),
            }],
        },
        refreshed_at: now,
        expires_at:i64::MAX,
    };
    let cred = enroll(
        &mut CtapClient::open(&mut key).unwrap(),
        &mds,
        Profile::L2,
        now,
    )
    .unwrap();
    let boot = |dev: VirtualAuthenticator| {
        let mut hw = VaultHardware::simulated(Profile::L2, now).unwrap();
        hw.yubikey = Some(Box::new(dev));
        hw.credential = Some(cred.clone());
        hw.mds = Some(mds.clone());
        VaultService::start(
            VaultConfig {
                profile: Profile::L2,
                audit_path: None,
                grant_key: None,
                state_dir: Some(dir.clone()),
                socket_dir: None,
                dev_same_uid: false,
            },
            hw,
        )
    };
    let enrolled = key.clone_secrets();

    // Boot 1: morning enrollment consumes two assertions; a step-up a third.
    let svc = boot(enrolled.clone_secrets()).unwrap();
    svc.handle(&me(), VaultRequest::AuthorizeIntent(draft(ActionClass::A3)))
        .unwrap();
    drop(svc);
    let after_boot1 = enrolled.sign_count() + 3;

    // Boot 2, same key moving forward: accepted, and its step-up counter is
    // persisted before the response.
    let mut real = enrolled.clone_secrets();
    real.force_sign_count(after_boot1);
    let svc = boot(real).unwrap();
    svc.handle(&me(), VaultRequest::AuthorizeIntent(draft(ActionClass::A3)))
        .unwrap();
    drop(svc);
    let high_water = after_boot1 + 3;

    // A clone rewound to the enrollment-time counter is a cloned key.
    let e = boot(enrolled.clone_secrets()).unwrap_err();
    assert!(e.is("SIGN_COUNT_REGRESSION"), "{e}");
    // So is one rewound to just before the last post-boot assertion: the
    // counter consumed by the step-up (not only the boot-time ones) was durable.
    let mut rewound = enrolled.clone_secrets();
    rewound.force_sign_count(high_water - 1);
    let e = boot(rewound).unwrap_err();
    assert!(e.is("SIGN_COUNT_REGRESSION"), "{e}");

    // Deleting the sealed store does not reset the high-water mark.
    std::fs::remove_file(dir.join("signcount.sealed")).unwrap();
    let mut ahead = enrolled.clone_secrets();
    ahead.force_sign_count(high_water + 10);
    let e = boot(ahead).unwrap_err();
    assert!(e.is("SIGN_COUNT_STATE"), "{e}");
    std::fs::remove_dir_all(dir).ok();
}

/// Explicitly holds the software prompt while the test issues ingress calls.
/// No product clock, provider admission or physical factor is overridden.
#[derive(Debug)]
struct PausedTouch {
    inner:Box<dyn BiometricProvider+Send>,
    entered:std::sync::mpsc::SyncSender<()>,
    resume:std::sync::mpsc::Receiver<()>,
}
impl BiometricProvider for PausedTouch {
    fn evaluate(&mut self, prompt: &BiometricPrompt) -> BiometricOutcome {
        self.entered.send(()).unwrap();
        if self.resume.recv_timeout(std::time::Duration::from_secs(3)).is_err() {
            return BiometricOutcome::TimedOut;
        }
        self.inner.evaluate(prompt)
    }
}

/// GAP-39: a ceremony in flight holds only the ceremony lock. Tokenization
/// and slot allocation proceed meanwhile; a second ceremony fails fast.
#[test]
fn ceremony_in_flight_does_not_block_tokenize_and_second_ceremony_fails_fast() {
    let now = enclave_crypto::time::now_unix();
    let mut hw = VaultHardware::simulated(Profile::L2, now).unwrap();
    let inner = std::mem::replace(&mut hw.biometric, Box::new(ScriptedCoreAuthUi::new([])));
    let (entered_tx,entered)=std::sync::mpsc::sync_channel(1);
    let (resume,resume_rx)=std::sync::mpsc::sync_channel(1);
    hw.biometric = Box::new(PausedTouch {inner,entered:entered_tx,resume:resume_rx});
    let svc = VaultService::start(
        VaultConfig {
            profile: Profile::L2,
            audit_path: None,
            grant_key: None,
            state_dir: None,
            socket_dir: None,
            dev_same_uid: false,
        },
        hw,
    )
    .unwrap();
    let s2 = svc.clone();
    let slow = std::thread::spawn(move || {
        s2.handle(&me(), VaultRequest::AuthorizeIntent(draft(ActionClass::A3)))
    });
    entered.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
    let t = std::time::Instant::now();
    let VaultResponse::Tokens(tok) = svc
        .handle(
            &me(),
            VaultRequest::Tokenize {
                items: vec![TokenizeItem {
                    value: "jane@example.com".into(),
                    declared: None,
                }],
                bulk_set: false,
                grant: None,
            },
        )
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(tok.len(), 1);
    assert!(matches!(
        svc.handle(&me(), VaultRequest::AllocateSlot).unwrap(),
        VaultResponse::Slot { .. }
    ));
    assert!(
        t.elapsed() < std::time::Duration::from_millis(500),
        "Tokenize waited {:?} behind the ceremony",
        t.elapsed()
    );
    assert!(svc
        .handle(&me(), VaultRequest::AuthorizeIntent(draft(ActionClass::A3)))
        .unwrap_err()
        .is("CEREMONY_IN_FLIGHT"));
    resume.send(()).unwrap();
    assert!(matches!(
        slow.join().unwrap().unwrap(),
        VaultResponse::IntentAuthorizedV2(_)
    ));
    // A wipe is the supervisor's / operator's, not a peer daemon's.
    if enclave_core::ipc::geteuid() != 704 {
        let ifc = PeerCredentials::local(704, 704);
        assert!(svc
            .handle(&ifc, VaultRequest::Tamper(TamperEvent::ScreenLock))
            .unwrap_err()
            .is("WIPE_PEER_REJECTED"));
    }
}

/// GAP-27 / ADR-010: UID 703 checkpoints its epoch's slot high-water mark at
/// boot and clean shutdown (never per RPC), and the next boot names where the
/// previous epoch ended.
#[test]
fn epoch_checkpoints_at_boot_and_shutdown_name_the_previous_epoch() {
    let now = enclave_crypto::time::now_unix();
    let dir = std::env::temp_dir().join(format!("depot-703-ckpt-{}", enclave_core::rng::u64()));
    let audit = dir.join("custody-audit.jsonl");
    let start = || {
        VaultService::start(
            VaultConfig {
                profile: Profile::L1,
                audit_path: Some(audit.clone()),
                grant_key: None,
                state_dir: Some(dir.join("state")),
                socket_dir: None,
                dev_same_uid: false,
            },
            VaultHardware::simulated_in(Profile::L1, now, Some(&dir.join("state"))).unwrap(),
        )
        .unwrap()
    };
    let svc = start();
    let VaultResponse::Epoch(e1) = svc.handle(&me(), VaultRequest::BootEpoch).unwrap() else {
        panic!()
    };
    for _ in 0..50 {
        svc.handle(&me(), VaultRequest::AllocateSlot).unwrap();
    }
    svc.shutdown().unwrap();
    drop(svc);
    let svc = start();
    let VaultResponse::Epoch(e2) = svc.handle(&me(), VaultRequest::BootEpoch).unwrap() else {
        panic!()
    };
    assert_ne!(e1.boot_epoch_id, e2.boot_epoch_id);
    // The simulated SEP keeps its epoch key across restarts, like the real one.
    assert_eq!(e1.signer_public_key, e2.signer_public_key);
    enclave_crypto::epoch::verify(&e2).unwrap();
    let cps: Vec<serde_json::Value> = std::fs::read_to_string(&audit)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|v| v["payload"]["event"] == "EPOCH_CHECKPOINT")
        .collect();
    let reasons: Vec<&str> = cps
        .iter()
        .map(|c| c["payload"]["reason"].as_str().unwrap())
        .collect();
    assert_eq!(
        reasons,
        vec!["Boot", "Shutdown", "Boot"],
        "50 RPCs cost no checkpoint"
    );
    assert_eq!(cps[1]["payload"]["rpc_seq_high_water"], 50);
    assert_eq!(
        cps[2]["payload"]["previous_epoch"]["boot_epoch_id"],
        e1.boot_epoch_id.as_str()
    );
    assert_eq!(
        cps[2]["payload"]["previous_epoch"]["rpc_seq_high_water"],
        50
    );
    std::fs::remove_dir_all(dir).ok();
}
