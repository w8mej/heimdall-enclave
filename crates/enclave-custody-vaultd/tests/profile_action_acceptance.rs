//! SOFTWARE-ONLY acceptance of the production ceremony engine and CTAP stack.
//!
//! The SEP, existing-PIN input, IdP, authenticator, quorum signers and egress
//! decision are synthetic fixtures. In particular, the bound egress fixture is
//! NOT independent ZK/backend evidence, and these tests establish no physical,
//! installed, native-helper, enrollment-authority or timing qualification.

use std::collections::{BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};

use ciborium::Value;
use ed25519_dalek::{Signer, SigningKey};
use enclave_core::profile::{ActionClass, Profile};
use enclave_core::secret::SecretBytes;
use enclave_core::{err, EnclaveResult};
use enclave_crypto::multisig::{QuorumPolicy, QuorumSignature};
use enclave_custody_vaultd::biometric::{BiometricPrompt, Scripted, ScriptedCoreAuthUi};
use enclave_custody_vaultd::ceremony::{CeremonyEngine, CeremonyGrant, CeremonyHardware, EgressGate, PrfTier};
use enclave_custody_vaultd::clock::{Clock, TestClock};
use enclave_custody_vaultd::ctap::assertion::{EnrolledCredential, SignCountStore, FLAG_UP, FLAG_UV};
use enclave_custody_vaultd::ctap::hid::{packetize, HidDevice, Reassembler, CMD_CBOR, REPORT};
use enclave_custody_vaultd::ctap::mds::{MdsAllowlist, MdsEntry, MdsState};
use enclave_custody_vaultd::ctap::virtual_device::VirtualAuthenticator;
use enclave_custody_vaultd::ctap::{cbor, cmd};
use enclave_custody_vaultd::factors::{required_factors, Factor};
use enclave_custody_vaultd::intent::IntentPayloadV1;
use enclave_custody_vaultd::lease::LeaseTable;
use enclave_custody_vaultd::oidc_acquisition::{BoundOidcStepUp, IntentOidcProvider};
use enclave_custody_vaultd::pin::ExistingPinProvider;

const NOW: i64 = 1_793_884_860;
// This is an emulator-only fixture value, never an input to physical hardware.
const SYNTHETIC_PIN: &[u8] = b"software-fixture-only";

#[derive(Debug, Clone, Copy, Default)]
enum ResponseFault {
    #[default]
    None,
    ClearUv,
    CorruptSignature,
    PinRequired,
}

/// Observe public command metadata and signed flags while forwarding the real
/// CTAPHID wire protocol. Retain no PIN hash, token, signature or PRF transcript.
#[derive(Debug)]
struct SoftwareWire {
    inner: VirtualAuthenticator,
    outgoing: Reassembler,
    pending: Option<u8>,
    ready: VecDeque<[u8; REPORT]>,
    commands: usize,
    pin_token_requests: usize,
    pin_permissions: Vec<i64>,
    assertion_pin_auth: Vec<bool>,
    signed_flags: Vec<u8>,
    fault: ResponseFault,
}

impl HidDevice for SoftwareWire {
    fn write_report(&mut self, report: &[u8; REPORT]) -> EnclaveResult<()> {
        let cid = u32::from_be_bytes(report[..4].try_into().unwrap());
        if let Some((kind, payload)) = self.outgoing.feed(cid, report)? {
            self.commands += 1;
            if kind == CMD_CBOR {
                self.pending = payload.first().copied();
                if let Some(command @ (cmd::CLIENT_PIN | cmd::GET_ASSERTION)) = self.pending {
                    let body = cbor::decode(&payload[1..])?;
                    if command == cmd::CLIENT_PIN && cbor::int(cbor::iget(&body, 2)).ok() == Some(9) {
                        self.pin_token_requests += 1;
                        self.pin_permissions.push(cbor::int(cbor::iget(&body, 9))?);
                        assert_eq!(cbor::text(cbor::iget(&body, 10))?, enclave_custody_vaultd::ctap::RP_ID);
                    }
                    if command == cmd::GET_ASSERTION {
                        self.assertion_pin_auth.push(cbor::iget(&body, 6).is_some());
                    }
                }
            } else {
                self.pending = None;
            }
        }
        self.inner.write_report(report)
    }

    fn read_report(&mut self) -> EnclaveResult<[u8; REPORT]> {
        if let Some(report) = self.ready.pop_front() { return Ok(report); }
        let mut incoming = Reassembler::default();
        loop {
            let report = self.inner.read_report()?;
            let cid = u32::from_be_bytes(report[..4].try_into().unwrap());
            let Some((kind, mut payload)) = incoming.feed(cid, &report)? else { continue; };
            if kind == CMD_CBOR && self.pending == Some(cmd::GET_ASSERTION) && payload.first() == Some(&0) {
                let mut body = cbor::decode(&payload[1..])?;
                let flags = cbor::bytes(cbor::iget(&body, 2))?[32];
                self.signed_flags.push(flags);
                if let Value::Map(entries) = &mut body {
                    for (key, value) in entries {
                        match (cbor::int(Some(key)).ok(), value) {
                            (Some(2), Value::Bytes(bytes)) if matches!(self.fault, ResponseFault::ClearUv) => bytes[32] &= !FLAG_UV,
                            (Some(3), Value::Bytes(bytes)) if matches!(self.fault, ResponseFault::CorruptSignature) => bytes[0] ^= 1,
                            _ => {}
                        }
                    }
                }
                payload = vec![0];
                payload.extend(cbor::encode(&body)?);
                if matches!(self.fault, ResponseFault::PinRequired) { payload = vec![0x36]; }
            }
            self.ready.extend(packetize(cid, kind, &payload)?);
            return Ok(self.ready.pop_front().unwrap());
        }
    }
    fn hub_depth(&self) -> u8 { self.inner.hub_depth() }
    fn deadline_ns(&self) -> Option<u64> { self.inner.deadline_ns() }
    fn set_deadline_ns(&mut self, deadline: Option<u64>) -> EnclaveResult<()> { self.inner.set_deadline_ns(deadline) }
}

#[derive(Debug)]
struct SoftwarePin {
    calls: usize,
    fail: bool,
    digest: [u8; 32],
    start: u64,
    nonces: Vec<Vec<u8>>,
    clock: TestClock,
    delay_ms: u64,
}
impl ExistingPinProvider for SoftwarePin {
    fn read_existing_pin(&mut self, prompt: &BiometricPrompt) -> EnclaveResult<SecretBytes> {
        self.calls += 1;
        assert_eq!(prompt.d_jcs.as_slice(), self.digest);
        assert_eq!(prompt.t_start_ns, self.start);
        assert!(prompt.localized_reason.contains("SAS: "));
        assert_eq!(prompt.nonce.len(), 32);
        assert!(!self.nonces.contains(&prompt.nonce), "fresh approval must not reuse a nonce");
        self.nonces.push(prompt.nonce.clone());
        if self.delay_ms != 0 { self.clock.advance_ms(self.delay_ms); }
        if self.fail { return Err(err!(EACCES, "SOFTWARE_PIN_CANCELLED")); }
        Ok(SecretBytes::new(SYNTHETIC_PIN.to_vec()))
    }
}

#[derive(Debug, Clone, Copy, Default)]
enum OidcMode { #[default] Valid, WrongSigner, WrongIntent, Stale }

#[derive(Debug, Default)]
struct SoftwareOidc { calls: usize, mode: OidcMode }
impl IntentOidcProvider for SoftwareOidc {
    fn acquire(&mut self, intent: &IntentPayloadV1, start: u64, deadline: u64, cancelled: &AtomicBool) -> EnclaveResult<BoundOidcStepUp> {
        if cancelled.load(Ordering::Acquire) { return Err(err!(EACCES, "SOFTWARE_OIDC_CANCELLED")); }
        self.calls += 1;
        let pinned = SigningKey::from_bytes(&[75; 32]);
        let signer = if matches!(self.mode, OidcMode::WrongSigner) { SigningKey::from_bytes(&[76; 32]) } else { pinned.clone() };
        let issuer = "https://software-fixture.example";
        let subject = "synthetic-custodian";
        let nonce = hex::encode(enclave_core::rng::bytes32());
        let header = enclave_crypto::b64::enc(br#"{"alg":"EdDSA","typ":"JWT"}"#);
        let auth_time = NOW - if matches!(self.mode, OidcMode::Stale) { 301 } else { 0 };
        let claims = serde_json::json!({"iss":issuer,"aud":"software-vault","sub":subject,"exp":NOW+60,"iat":NOW,"auth_time":auth_time,"nonce":nonce});
        let claims = enclave_crypto::b64::enc(&serde_json::to_vec(&claims).unwrap());
        let message = format!("{header}.{claims}");
        let token = SecretBytes::new(format!("{message}.{}", enclave_crypto::b64::enc(&signer.sign(message.as_bytes()).to_bytes())).into_bytes());
        use sha2::{Digest, Sha256};
        let mut principal = Sha256::new();
        principal.update(b"depot-OIDC-Subject-v1\0"); principal.update(issuer.as_bytes()); principal.update([0]); principal.update(subject.as_bytes());
        let authority = serde_json::to_vec(&serde_json::json!({"v":1,"issuer":issuer,"audience":"software-vault",
            "subject_sha256":hex::encode(principal.finalize()),"ed25519_public_keys":[hex::encode(pinned.verifying_key().as_bytes())],
            "not_before_unix":NOW-1,"expires_unix":NOW+60})).unwrap();
        let mut bound = intent.clone();
        if matches!(self.mode, OidcMode::WrongIntent) { bound.target_namespace = Some("other-namespace".into()); }
        BoundOidcStepUp::from_signed_fixture(&authority, token, nonce, &bound, start, deadline, NOW)
    }
}

#[derive(Debug)]
struct SoftwareBoundGate { digest: [u8; 32], calls: usize, deny: bool }
impl EgressGate for SoftwareBoundGate {
    fn approve(&mut self, digest: &[u8; 32]) -> EnclaveResult<()> {
        self.calls += 1;
        assert_eq!(*digest, self.digest);
        if self.deny { return Err(err!(EACCES, "SOFTWARE_EGRESS_DENIED")); }
        Ok(())
    }
}

fn intent(profile: Profile, action: ActionClass) -> IntentPayloadV1 {
    IntentPayloadV1 {
        v: 1, schema_version: Some("enclave.intent.v1".into()), action_class: action, profile,
        data_class: None, spiffe_id: "spiffe://corporate.internal/enclave/uid/704".into(),
        tool_name: "depot://software/action".into(), target_namespace: Some("dev-billing".into()),
        human_summary_trusted: Some("Synthetic profile acceptance".into()), row_count_bound: Some(1),
        arguments_jcs_sha256: Some(hex::encode([0xab; 32])), canonical_arguments_blake3: hex::encode([0xcd; 32]),
        model_blake3: None, policy_blake3: hex::encode([0xef; 32]), qif_millibits_delta: Some(0), custody_grant: None,
        boot_epoch_id: enclave_core::seq::new_boot_epoch_id(), rpc_seq_u64: 1, ts_utc_ms: NOW as u64 * 1000,
        required_factors: required_factors(profile, action, false).into_iter().collect(), user_turn: None,
    }
}

#[derive(Default)]
struct Options {
    no_biometric: bool, no_key: bool, no_pin: bool, no_oidc: bool, no_egress: bool,
    no_quorum_policy: bool, no_quorum_signatures: bool,
    attach_optional_key: bool, yanked: bool, cancelled: bool,
}

struct Rig {
    profile: Profile, wire: SoftwareWire, credential: EnrolledCredential, mds: MdsState,
    counters: SignCountStore, clock: TestClock, ui: ScriptedCoreAuthUi,
    pin: SoftwarePin, oidc: SoftwareOidc, gate: SoftwareBoundGate,
    quorum: Option<QuorumPolicy>, signatures: Vec<QuorumSignature>,
}
impl Rig {
    fn new(profile: Profile, intent: &IntentPayloadV1) -> Self {
        let mut dev = VirtualAuthenticator::new([0xab; 16]);
        let mds = MdsState { allowlist: MdsAllowlist { entries: vec![MdsEntry {
            aaguid: hex::encode(dev.aaguid), description: "SOFTWARE profile acceptance".into(),
            min_firmware_version: 0x05_07_00, status_reports: vec!["FIDO_CERTIFIED".into()],
            attestation_public_keys: vec![dev.attestation_key_mds()], attestation_root_certificates: vec![],
        }] }, refreshed_at: NOW, expires_at: i64::MAX };
        let credential = enclave_custody_vaultd::ctap::client::enroll_simulated(&mut dev, &mds, profile, NOW).unwrap();
        dev.configure_synthetic_pin(SYNTHETIC_PIN);
        let clock = TestClock::at(NOW);
        let digest = intent.d_jcs().unwrap();
        Self { profile, wire: SoftwareWire { inner: dev, outgoing: Reassembler::default(), pending: None,
            ready: VecDeque::new(), commands: 0, pin_token_requests: 0, pin_permissions: vec![],
            assertion_pin_auth: vec![], signed_flags: vec![], fault: ResponseFault::None },
            credential, mds, counters: SignCountStore::default(), clock: clock.clone(),
            ui: ScriptedCoreAuthUi::new([Scripted::Approve]),
            pin: SoftwarePin { calls: 0, fail: false, digest, start: clock.now_ns(), nonces: vec![], clock, delay_ms: 0 },
            oidc: SoftwareOidc::default(), gate: SoftwareBoundGate { digest, calls: 0, deny: false },
            quorum: None, signatures: vec![],
        }
    }
    fn run(&mut self, intent: &IntentPayloadV1, options: Options) -> EnclaveResult<CeremonyGrant> {
        let key = self.ui.enrolled_key();
        let key_required = self.profile == Profile::L3 || (self.profile == Profile::L2 && intent.action_class >= ActionClass::A3);
        let cancelled = AtomicBool::new(options.cancelled);
        let tier = if self.profile >= Profile::L2 && intent.action_class >= ActionClass::A3 {
            Some(if intent.action_class == ActionClass::A4 { PrfTier::A4 } else { PrfTier::A3 })
        } else { None };
        CeremonyEngine::new(self.profile).run(intent, tier, CeremonyHardware {
            biometric: (!options.no_biometric).then_some(&mut self.ui), sep_key: Some(key),
            existing_pin: (!options.no_pin).then_some(&mut self.pin), pin_cancelled: Some(&cancelled),
            yubikey: ((!options.no_key) && (key_required || options.attach_optional_key)).then_some(&mut self.wire),
            credential: Some(&self.credential), mds: Some(&self.mds), counters: Some(&mut self.counters),
            oidc_provider: (!options.no_oidc).then_some(&mut self.oidc),
            egress: (!options.no_egress).then_some(&mut self.gate), is_yanked: options.yanked,
            quorum_policy: if options.no_quorum_policy { None } else { self.quorum.as_ref() },
            quorum_signatures: (!options.no_quorum_signatures).then_some(self.signatures.as_slice()),
            ..Default::default()
        }, &self.clock)
    }
    fn set_quorum(&mut self, intent: &IntentPayloadV1) {
        let keys = [SigningKey::from_bytes(&[11; 32]), SigningKey::from_bytes(&[12; 32]), SigningKey::from_bytes(&[13; 32])];
        self.quorum = Some(QuorumPolicy::new(keys.iter().map(SigningKey::verifying_key).collect(), 2).unwrap());
        self.signatures = keys[..2].iter().map(|key| QuorumSignature {
            public_key: key.verifying_key().to_bytes().to_vec(), signature: key.sign(&intent.d_jcs().unwrap()).to_bytes().to_vec(),
            collected_at_ms: NOW as u64 * 1000,
        }).collect();
    }
}

// Independent literal FS-703/YKD-01/08 expectation: a regression in the
// production factor-table function must not change the acceptance oracle.
fn spec_factors(profile: Profile, action: ActionClass) -> BTreeSet<Factor> {
    use ActionClass::*;
    use Factor::*;
    use Profile::*;
    let factors: &[Factor] = match (profile, action) {
        (L1, A1) => &[SepWorkloadKey],
        (L1, A2) => &[SepWorkloadKey, TouchIdCoreauthui],
        (L1, A3) => &[SepWorkloadKey, TouchIdCoreauthui],
        (L1, A4) => &[SepWorkloadKey, TouchIdCoreauthui, OidcStepUp],
        (L2, A1) => &[SepWorkloadKey],
        (L2, A2) => &[SepWorkloadKey, TouchIdCoreauthui],
        (L2, A3) => &[SepWorkloadKey, TouchIdCoreauthui, YubikeyUp],
        (L2, A4) => &[SepWorkloadKey, TouchIdCoreauthui, YubikeyUp, OidcStepUp],
        (L3, A1) => &[SepWorkloadKey, YubikeyPresent],
        (L3, A2) => &[SepWorkloadKey, TouchIdCoreauthui, YubikeyPresent],
        (L3, A3) => &[SepWorkloadKey, TouchIdCoreauthui, YubikeyPresent, YubikeyUp, YubikeyPinUv, ZkEgressGate],
        (L3, A4) => &[SepWorkloadKey, TouchIdCoreauthui, YubikeyPresent, YubikeyUp, YubikeyPinUv, ZkEgressGate, OidcStepUp],
    };
    factors.iter().copied().collect()
}

fn check_cell(profile: Profile, action: ActionClass) {
    let intent = intent(profile, action);
    let mut rig = Rig::new(profile, &intent);
    let mut grant = rig.run(&intent, Options::default()).unwrap();
    assert_eq!(grant.factors, spec_factors(profile, action));
    assert_eq!(grant.d_jcs, intent.d_jcs().unwrap());
    assert_eq!(grant.action, action);
    assert_eq!(grant.row_count_bound, 1);
    assert_eq!(rig.ui.shown.len(), usize::from(action >= ActionClass::A2));
    assert_eq!(rig.oidc.calls, usize::from(action == ActionClass::A4));
    let assertion = profile >= Profile::L2 && action >= ActionClass::A3;
    let uv = profile == Profile::L3 && assertion;
    assert_eq!(rig.wire.inner.assertion_requests, usize::from(assertion));
    assert_eq!(rig.pin.calls, usize::from(uv));
    assert_eq!(rig.wire.pin_token_requests, usize::from(uv));
    assert_eq!(rig.gate.calls, usize::from(uv));
    assert_eq!(grant.prf.as_ref().map(SecretBytes::len), assertion.then_some(32));
    if assertion {
        assert_eq!(rig.wire.assertion_pin_auth, vec![uv]);
        assert_eq!(rig.wire.signed_flags[0] & (FLAG_UP | FLAG_UV), FLAG_UP | if uv { FLAG_UV } else { 0 });
        assert!(rig.counters.get(&rig.credential.credential_id) > 0);
    } else {
        assert_eq!(rig.wire.commands, 0, "presence-only cells and no-key cells must not arm CTAP");
    }
    grant.consume().unwrap();
    assert!(grant.consume().unwrap_err().is("GRANT_ALREADY_USED"));

    // Every cell denies a valid intent for a different effective profile.
    let mut mismatch = Rig::new(if profile == Profile::L3 { Profile::L2 } else { Profile::L3 }, &intent);
    assert!(mismatch.run(&intent, Options::default()).unwrap_err().is("PROFILE_MISMATCH"));
    assert_eq!(mismatch.wire.commands, 0);
    assert!(mismatch.ui.shown.is_empty());
    // Even the noninteractive A1 cells reject a client-declared factor downgrade.
    let mut downgrade = intent.clone();
    downgrade.required_factors.retain(|factor| *factor != Factor::SepWorkloadKey);
    let mut refused = Rig::new(profile, &intent);
    assert!(refused.run(&downgrade, Options::default()).unwrap_err().is("INTENT_FACTORS_BELOW_MATRIX"));
    assert_eq!(refused.wire.commands, 0);
    assert!(refused.ui.shown.is_empty());
    for (rows, qif, expected) in [(0, 0, "INTENT_ROW_RANGE"), (1, 12_001, "INTENT_QIF_RANGE")] {
        let mut invalid = intent.clone();
        invalid.row_count_bound = Some(rows); invalid.qif_millibits_delta = Some(qif);
        assert!(refused.run(&invalid, Options::default()).unwrap_err().is(expected));
    }
    if action >= ActionClass::A2 {
        let mut missing = Rig::new(profile, &intent);
        assert!(missing.run(&intent, Options { no_biometric: true, ..Default::default() }).unwrap_err().is("BIOMETRIC_PROVIDER_UNAVAILABLE"));
        assert_eq!(missing.wire.inner.assertion_requests, 0);
    }
    if profile == Profile::L3 || assertion {
        let mut missing = Rig::new(profile, &intent);
        let expected = if profile == Profile::L3 { "YUBIKEY_NOT_PRESENT" } else { "YUBIKEY_REQUIRED" };
        assert!(missing.run(&intent, Options { no_key: true, ..Default::default() }).unwrap_err().is(expected));
    }
}

macro_rules! cell {
    ($name:ident, $profile:ident, $action:ident) => { #[test] fn $name() { check_cell(Profile::$profile, ActionClass::$action); } };
}
cell!(software_l1_a1, L1, A1);
cell!(software_l1_a2, L1, A2);
cell!(software_l1_a3, L1, A3);
cell!(software_l1_a4, L1, A4);
cell!(software_l2_a1, L2, A1);
cell!(software_l2_a2, L2, A2);
cell!(software_l2_a3, L2, A3);
cell!(software_l2_a4, L2, A4);
cell!(software_l3_a1, L3, A1);
cell!(software_l3_a2, L3, A2);
cell!(software_l3_a3, L3, A3);
cell!(software_l3_a4, L3, A4);

#[test]
fn software_l2_critical_actions_never_read_pin() {
    for action in [ActionClass::A3, ActionClass::A4] {
        for presence in [enclave_custody_vaultd::ctap::virtual_device::Presence::Touch,
            enclave_custody_vaultd::ctap::virtual_device::Presence::NoTouch,
            enclave_custody_vaultd::ctap::virtual_device::Presence::Unplugged] {
            let intent = intent(Profile::L2, action);
            let mut rig = Rig::new(Profile::L2, &intent);
            rig.pin.fail = true; // A secure PIN provider is available, but forbidden here.
            rig.wire.inner.presence = presence;
            let result = rig.run(&intent, Options::default());
            assert_eq!(result.is_ok(), presence == enclave_custody_vaultd::ctap::virtual_device::Presence::Touch);
            assert_eq!(rig.pin.calls, 0);
            assert_eq!(rig.wire.pin_token_requests, 0);
            assert!(rig.wire.assertion_pin_auth.iter().all(|used| !used));
        }
        let intent = intent(Profile::L2, action);
        let mut rig = Rig::new(Profile::L2, &intent);
        rig.ui = ScriptedCoreAuthUi::new([Scripted::Cancel]);
        assert!(rig.run(&intent, Options::default()).unwrap_err().is("TOUCH_ID_CANCELLED"));
        assert_eq!(rig.wire.commands, 0);
        assert_eq!(rig.pin.calls, 0);
        let mut required_pin = Rig::new(Profile::L2, &intent);
        required_pin.wire.fault = ResponseFault::PinRequired;
        assert!(required_pin.run(&intent, Options::default()).unwrap_err().is("CTAP2_ERROR"));
        assert_eq!(required_pin.pin.calls, 0, "a device PIN_REQUIRED reply never enables L2 PIN fallback");
        assert_eq!(required_pin.wire.pin_token_requests, 0);
    }
}

#[test]
fn software_l3_critical_actions_acquire_fresh_pin_and_signed_uv() {
    for action in [ActionClass::A3, ActionClass::A4] {
        let intent = intent(Profile::L3, action);
        let mut rig = Rig::new(Profile::L3, &intent);
        for call in 1..=2 {
            if call == 2 { rig.ui.push(Scripted::Approve); }
            let before = rig.counters.get(&rig.credential.credential_id);
            let grant = rig.run(&intent, Options::default()).unwrap();
            assert!(grant.factors.contains(&Factor::YubikeyPinUv));
            assert_eq!(rig.pin.calls, call);
            assert_eq!(rig.wire.pin_token_requests, call, "never reuse a previous ceremony's host PIN token");
            assert!(rig.counters.get(&rig.credential.credential_id) > before);
        }
        assert_eq!(rig.wire.pin_permissions, vec![2, 2]);
        assert_eq!(rig.wire.assertion_pin_auth, vec![true, true]);
        assert!(rig.wire.signed_flags.iter().all(|flags| flags & (FLAG_UP | FLAG_UV) == FLAG_UP | FLAG_UV));
        assert_eq!(rig.pin.nonces.len(), 2);
    }
}

#[test]
fn software_l3_pin_provider_failure_never_arms_key() {
    for action in [ActionClass::A3, ActionClass::A4] {
        for failure in ["absent", "cancel", "lifecycle", "late", "touch_cancel", "touch_wrong_key"] {
            let intent = intent(Profile::L3, action);
            let mut rig = Rig::new(Profile::L3, &intent);
            rig.pin.fail = failure == "cancel";
            rig.pin.delay_ms = if failure == "late" { 10_000 } else { 0 };
            if failure == "touch_cancel" { rig.ui = ScriptedCoreAuthUi::new([Scripted::Cancel]); }
            if failure == "touch_wrong_key" { rig.ui = ScriptedCoreAuthUi::new([Scripted::WrongKey]); }
            let error = rig.run(&intent, Options { no_pin: failure == "absent", cancelled: failure == "lifecycle", ..Default::default() }).unwrap_err();
            let expected = match failure {
                "absent" => "YUBIKEY_PIN_PROVIDER_REQUIRED", "cancel" => "SOFTWARE_PIN_CANCELLED",
                "lifecycle" if action == ActionClass::A4 => "SOFTWARE_OIDC_CANCELLED",
                "lifecycle" => "FIDO_PIN_CEREMONY_CANCELLED", "late" => "CEREMONY_BUDGET_EXCEEDED",
                "touch_cancel" => "TOUCH_ID_CANCELLED", "touch_wrong_key" => "SEP_SIGNATURE_INVALID", _ => unreachable!(),
            };
            assert!(error.is(expected), "{action:?}/{failure}: {error:?}");
            assert_eq!(rig.wire.inner.assertion_requests, 0);
            assert_eq!(rig.wire.pin_token_requests, 0);
            assert_eq!(rig.gate.calls, 0);
            assert_eq!(rig.counters.get(&rig.credential.credential_id), 0);
        }
    }
}

#[test]
fn software_l3_missing_or_tampered_signed_uv_refuses() {
    for action in [ActionClass::A3, ActionClass::A4] {
        for (fault, expected) in [(ResponseFault::ClearUv, "USER_VERIFICATION_MISSING"),
            (ResponseFault::CorruptSignature, "ASSERTION_SIGNATURE_INVALID")] {
            let intent = intent(Profile::L3, action);
            let mut rig = Rig::new(Profile::L3, &intent);
            rig.wire.fault = fault;
            assert!(rig.run(&intent, Options::default()).unwrap_err().is(expected));
            assert_eq!(rig.pin.calls, 1, "PIN-provider success alone is not UV evidence");
            assert_eq!(rig.wire.signed_flags.len(), 1);
            assert_eq!(rig.gate.calls, 0);
            assert_eq!(rig.counters.get(&rig.credential.credential_id), 0);
        }
    }
    // Obtain a genuinely signed UP-only response, then try to promote its flag.
    // Both failures use the production verifier and leave its counter unchanged.
    use enclave_custody_vaultd::ctap::{assertion::verify_assertion, client::CtapClient};
    let intent = intent(Profile::L3, ActionClass::A3);
    let mut rig = Rig::new(Profile::L3, &intent);
    let challenge = [0x51; 32];
    let (mut response, _) = CtapClient::open(&mut rig.wire).unwrap()
        .get_assertion(&rig.credential.credential_id, &challenge, false, None).unwrap();
    assert_eq!(response.auth_data[32] & FLAG_UV, 0);
    assert!(verify_assertion(&rig.credential, &response, &challenge, true, &mut rig.counters)
        .unwrap_err().is("USER_VERIFICATION_MISSING"));
    response.auth_data[32] |= FLAG_UV;
    assert!(verify_assertion(&rig.credential, &response, &challenge, true, &mut rig.counters)
        .unwrap_err().is("ASSERTION_SIGNATURE_INVALID"));
    assert_eq!(rig.counters.get(&rig.credential.credential_id), 0);
}

#[test]
fn software_l3_egress_denial_refuses_after_verified_uv() {
    for action in [ActionClass::A3, ActionClass::A4] {
        for unavailable in [false, true] {
            let intent = intent(Profile::L3, action);
            let mut rig = Rig::new(Profile::L3, &intent);
            rig.gate.deny = true;
            let error = rig.run(&intent, Options { no_egress: unavailable, ..Default::default() }).unwrap_err();
            assert!(error.is(if unavailable { "ZK_EGRESS_GATE_UNAVAILABLE" } else { "SOFTWARE_EGRESS_DENIED" }));
            assert_eq!(rig.pin.calls, 1);
            assert_eq!(rig.gate.calls, usize::from(!unavailable));
            assert!(rig.counters.get(&rig.credential.credential_id) > 0, "later denial cannot refund an assertion counter");
        }
    }
}

#[test]
fn software_a4_inherits_oidc_for_every_profile() {
    for profile in [Profile::L1, Profile::L2, Profile::L3] {
        let intent = intent(profile, ActionClass::A4);
        let mut missing = Rig::new(profile, &intent);
        assert!(missing.run(&intent, Options { no_oidc: true, ..Default::default() }).unwrap_err().is("OIDC_VERIFIER_UNAVAILABLE"));
        for mode in [OidcMode::WrongSigner, OidcMode::WrongIntent, OidcMode::Stale] {
            let mut rig = Rig::new(profile, &intent);
            rig.oidc.mode = mode;
            assert!(rig.run(&intent, Options::default()).is_err(), "{profile:?}/{mode:?} must not authorize");
            assert_eq!(rig.oidc.calls, 1);
            assert_eq!(rig.gate.calls, 0);
        }
    }
}

#[test]
fn software_org_root_inherits_quorum_for_hardware_profiles() {
    for profile in [Profile::L2, Profile::L3] {
        let mut intent = intent(profile, ActionClass::A4);
        intent.tool_name = "depot://tuf/publish".into(); intent.target_namespace = Some("tuf".into());
        intent.required_factors = required_factors(profile, ActionClass::A4, true).into_iter().collect();
        assert!(intent.is_org_root_mutation());
        for condition in ["valid", "no_policy", "no_signatures", "too_few", "wrong_intent"] {
            let mut rig = Rig::new(profile, &intent);
            rig.set_quorum(&intent);
            if condition == "too_few" { rig.signatures.truncate(1); }
            if condition == "wrong_intent" {
                rig.signatures[0].signature = SigningKey::from_bytes(&[11; 32]).sign(&[0x91; 32]).to_bytes().to_vec();
            }
            let result = rig.run(&intent, Options { no_quorum_policy: condition == "no_policy",
                no_quorum_signatures: condition == "no_signatures", ..Default::default() });
            if condition == "valid" {
                assert!(result.unwrap().factors.contains(&Factor::KofnEd25519Quorum));
            } else {
                let expected = match condition { "no_policy" => "QUORUM_POLICY_UNAVAILABLE", "no_signatures" => "QUORUM_SIGNATURES_REQUIRED", _ => "QUORUM_NOT_MET" };
                assert!(result.unwrap_err().is(expected), "{profile:?}/{condition}");
                assert_eq!(rig.gate.calls, 0);
            }
            assert_eq!(rig.oidc.calls, 1);
            assert!(rig.counters.get(&rig.credential.credential_id) > 0);
        }
    }
}

#[test]
fn software_l2_a2_lease_is_caller_namespace_arguments_and_expiry_bound() {
    let original = intent(Profile::L2, ActionClass::A2);
    let clock = TestClock::at(NOW);
    let mut leases = LeaseTable::new();
    let mut ui = ScriptedCoreAuthUi::new([Scripted::Approve]);
    let key = ui.enrolled_key();
    CeremonyEngine::new(Profile::L2).run(&original, None, CeremonyHardware {
        biometric: Some(&mut ui), sep_key: Some(key), leases: Some(&mut leases), ..Default::default()
    }, &clock).unwrap();
    assert_eq!(ui.shown.len(), 1);
    for mutation in ["none", "caller", "namespace", "arguments", "critical"] {
        let mut changed = original.clone();
        match mutation {
            "caller" => changed.spiffe_id = "spiffe://corporate.internal/enclave/uid/705".into(),
            "namespace" => changed.target_namespace = Some("other-namespace".into()),
            "arguments" => changed.canonical_arguments_blake3 = hex::encode([0xce; 32]),
            "critical" => { changed.action_class = ActionClass::A3; changed.required_factors = required_factors(Profile::L2, ActionClass::A3, false).into_iter().collect(); },
            _ => {}
        }
        let result = CeremonyEngine::new(Profile::L2).run(&changed, None, CeremonyHardware { leases: Some(&mut leases), ..Default::default() }, &clock);
        if mutation == "none" { assert!(result.unwrap().factors.contains(&Factor::TouchIdCoreauthui)); }
        else { assert!(result.unwrap_err().is("BIOMETRIC_PROVIDER_UNAVAILABLE"), "{mutation}"); }
    }
    clock.advance_ms(900_000);
    assert!(CeremonyEngine::new(Profile::L2).run(&original, None, CeremonyHardware { leases: Some(&mut leases), ..Default::default() }, &clock)
        .unwrap_err().is("BIOMETRIC_PROVIDER_UNAVAILABLE"));
    leases.grant(&original.spiffe_id, original.target_namespace.as_deref().unwrap(), [0xcd; 32], clock.now_ns());
    leases.revoke_all();
    assert!(CeremonyEngine::new(Profile::L2).run(&original, None, CeremonyHardware { leases: Some(&mut leases), ..Default::default() }, &clock)
        .unwrap_err().is("BIOMETRIC_PROVIDER_UNAVAILABLE"));
}
