//! Protected NEW initializer for the always-sterile embedding. No RPC or raw
//! import. Captures are inert artifacts; only this live verified completion
//! constructs an enrollment capability. No factor/PRF/wrapper/active operation.
use super::*;

const CAPTURE_LIMIT: usize = 16 * 1024 * 1024;
const MAX_CAPTURES: usize = 16;
const MAX_PENDING_JSON: usize = 512 * 1024;

// Production can contain ONLY the concrete reciprocal authenticated helper.
// Arbitrary VaultHardware.biometric/raw outcomes never enter this owner.
enum SetupHelper {
    Native(crate::biometric::IntentHelperProvider),
    #[cfg(test)]
    Fixture {
        inner: SimulatedTouchId,
        fault: u8,
    },
}
impl SetupHelper {
    fn evaluate(&mut self, prompt: &BiometricPrompt) -> BiometricOutcome {
        match self {
            Self::Native(helper) => helper.evaluate(prompt),
            #[cfg(test)]
            Self::Fixture { inner, fault } => {
                let mut outcome = inner.evaluate(prompt);
                match *fault {
                    1 => outcome = BiometricOutcome::Cancelled,
                    2 => {
                        if let BiometricOutcome::Approved { sep_signature, .. } = &mut outcome {
                            sep_signature[0] ^= 1;
                        }
                    }
                    3 => {
                        if let BiometricOutcome::Approved { enrolled_blob, .. } = &mut outcome {
                            *enrolled_blob = None;
                        }
                    }
                    _ => {}
                }
                outcome
            }
        }
    }
}

/// Runtime provenance only. Never deserialized or reconstructed from capture.
pub(super) struct EnrollmentOrigin {
    scope: [u8; 32],
    incident: [u8; 32],
    profile: Profile,
    boot: [u8; 32],
    generation: u64,
    start_ns: u64,
    deadline_ns: u64,
    valid_until: i64,
}
impl EnrollmentOrigin {
    pub(super) fn preparation_window(
        &self,
        scope: [u8; 32],
        incident: [u8; 32],
        profile: Profile,
        boot: [u8; 32],
        generation: u64,
        request_start: u64,
    ) -> EnclaveResult<(u64, Option<u64>, Option<i64>)> {
        if self.scope != scope
            || self.incident != incident
            || self.profile != profile
            || self.boot != boot
            || self.generation.checked_add(1) != Some(generation)
        {
            fail!(EACCES, "REPLACEMENT_ENROLLMENT_CONTEXT");
        }
        if request_start < self.start_ns || SystemClock::default().now_ns() >= self.deadline_ns {
            fail!(ETIMEDOUT, "REPLACEMENT_ENROLLMENT_EXPIRED");
        }
        Ok((
            self.start_ns,
            Some(self.deadline_ns),
            Some(self.valid_until),
        ))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureAttempt {
    source: MembershipAnchorPin,
    incident: [u8; 32],
    profile: Profile,
    boot: [u8; 32],
    start_ns_hex: String,
    nonce_sha256: [u8; 32],
    pending: Option<Pending>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureLedger {
    version: u32,
    attempts: Vec<CaptureAttempt>,
}
fn capture_store(state: &Path) -> EnclaveResult<(SealedStore, CaptureLedger)> {
    let (store, loaded) = SealedStore::open_bounded(
        &state.join("replacement-enrollment-captures"),
        "attempts",
        CAPTURE_LIMIT,
    )?;
    let ledger = match loaded {
        Loaded::Fresh => CaptureLedger {
            version: 1,
            attempts: vec![],
        },
        Loaded::State(bytes) => enclave_core::sealed::decode::<CaptureLedger>(&bytes)?,
    };
    if ledger.version != 1 || ledger.attempts.len() >= MAX_CAPTURES {
        fail!(E2BIG, "REPLACEMENT_ENROLLMENT_CAPTURE_CAPACITY");
    }
    // Leave room for a complete maximum-sized verified pending BEFORE invoking
    // the factory or makeCredential. No captured handle is evicted to retry.
    if serde_json::to_vec(&ledger)
        .map_err(|_| err!(EIO, "STATE_SERIALIZE"))?
        .len()
        > CAPTURE_LIMIT / 2 - MAX_PENDING_JSON - 64 * 1024
    {
        fail!(E2BIG, "REPLACEMENT_ENROLLMENT_CAPTURE_CAPACITY");
    }
    Ok((store, ledger))
}
fn bind_source(
    owner: &MembershipAuthorityOwner,
    state: &Path,
    ledger: &Ledger,
    profile: Profile,
    observation: &MembershipAnchorObservation,
) -> EnclaveResult<(MemberLossRecord, membership_cutover::MemberLossContext)> {
    match &ledger.phase {
        Phase::MembershipLossRecorded { record } => Ok((
            record.clone(),
            owner.accepted_loss_context(state, ledger, record, profile, observation)?,
        )),
        Phase::MembershipReplacementPreparing { record } => Ok((
            record.loss.clone(),
            owner.accepted_replacement_context(state, ledger, record, profile, observation)?,
        )),
        _ => {
            fail!(EACCES, "MEMBER_LOSS_REQUIRED");
        }
    }
}
fn milliseconds(unix: i64) -> EnclaveResult<u64> {
    u64::try_from(unix)
        .ok()
        .and_then(|n| n.checked_mul(1000))
        .filter(|n| positive(*n))
        .ok_or_else(|| err!(EACCES, "REPLACEMENT_ENROLLMENT_TIME"))
}
fn cap_from_observation(
    start: u64,
    current: u64,
    until: i64,
    observation: &MembershipAnchorObservation,
) -> EnclaveResult<u64> {
    let until = milliseconds(until)?;
    let remaining = until
        .checked_sub(observation.trusted_upper_utc_ms)
        .filter(|n| *n > 0)
        .ok_or_else(|| err!(ETIMEDOUT, "REPLACEMENT_ENROLLMENT_EXPIRED"))?;
    Ok(current.min(
        start
            .checked_add(
                remaining
                    .checked_mul(1_000_000)
                    .ok_or_else(|| err!(EACCES, "REPLACEMENT_ENROLLMENT_TIME"))?,
            )
            .ok_or_else(|| err!(EACCES, "REPLACEMENT_ENROLLMENT_TIME"))?,
    ))
}
fn distinct_new(
    loss: &MemberLossRecord,
    context: &membership_cutover::MemberLossContext,
    authority: &AssetEnrollmentAuthority,
    pending: &Pending,
) -> EnclaveResult<()> {
    let identity = RetirementIdentity::from_credential(pending.evidence.credential())?;
    for member in &context.members {
        let original = RetirementIdentity::from_credential(&member.credential)?;
        if identity.aliases(&original) {
            fail!(EACCES, "REPLACEMENT_ENROLLMENT_IDENTITY");
        }
    }
    let pins = InventoryRetirementPins::from_asset_authority(authority)?;
    if loss.history.denies(&pins, &identity)? {
        fail!(EACCES, "REPLACEMENT_ENROLLMENT_IDENTITY");
    }
    Ok(())
}
/// Private constructor at the actual live producer boundary. It accepts no
/// deserialized completion, inventory receipt or caller-owned blob. The pinned
/// helper produces public key, token blob and signature from one SecKey, and
/// both disclosure and makeCredential attestation have now been verified.
fn completed(
    pending: Pending,
    origin: EnrollmentOrigin,
) -> EnclaveResult<ValidatedReplacementEnrollment> {
    if pending.profile != origin.profile
        || pending.bio_key_blob.is_empty()
        || pending.bio_key_blob.len() > 64 * 1024
        || pending.bio_public_key != pending.evidence.sep_public_key
    {
        fail!(EACCES, "REPLACEMENT_ENROLLMENT_EVIDENCE");
    }
    let id = enrollment_id(origin.scope, &pending)?;
    Ok(ValidatedReplacementEnrollment {
        scope: origin.scope,
        pending,
        id,
        origin: Some(origin),
    })
}

impl VaultService {
    /// Explicit protected EMBEDDING operation. The factory is trusted code,
    /// configured with authenticated metadata/selected HID and existing-PIN
    /// owners. Its arbitrary biometric provider is ignored; only the concrete
    /// authenticated helper parameter supplies D2 creation provenance.
    /// Native invocation creates a credential and requires separate operation
    /// authority. Ordinary startup/diagnostics cannot reach this method.
    pub fn begin_member_replacement_enrollment_with_factory(
        &self,
        peer: &PeerCredentials,
        helper: crate::biometric::IntentHelperProvider,
        hardware: impl FnOnce() -> EnclaveResult<VaultHardware>,
    ) -> EnclaveResult<(PendingAssetEnrollment, [u8; 32])> {
        self.begin_member_replacement_enrollment_inner(
            peer,
            SetupHelper::Native(helper),
            hardware,
            SystemClock::default().now_ns(),
        )
    }
    #[cfg(test)]
    pub(in crate::service::asset_workflow) fn begin_member_replacement_enrollment_for_test(
        &self,
        peer: &PeerCredentials,
        hardware: impl FnOnce() -> EnclaveResult<VaultHardware>,
        start: u64,
        helper_fault: u8,
    ) -> EnclaveResult<(PendingAssetEnrollment, [u8; 32])> {
        self.begin_member_replacement_enrollment_inner(
            peer,
            SetupHelper::Fixture {
                inner: SimulatedTouchId::new(),
                fault: helper_fault,
            },
            hardware,
            start,
        )
    }
    #[cfg(test)]
    pub(in crate::service::asset_workflow) fn begin_member_replacement_enrollment_with_concrete_fixture(
        &self,
        peer: &PeerCredentials,
        hardware: impl FnOnce() -> EnclaveResult<VaultHardware>,
        start: u64,
        helper: SimulatedTouchId,
    ) -> EnclaveResult<(PendingAssetEnrollment, [u8; 32])> {
        self.begin_member_replacement_enrollment_inner(
            peer,
            SetupHelper::Fixture {
                inner: helper,
                fault: 0,
            },
            hardware,
            start,
        )
    }
    #[cfg(test)]
    pub(in crate::service::asset_workflow) fn replacement_enrollment_staged_count_for_test(
        &self,
    ) -> usize {
        self.replacement_preparing.lock().unwrap().evidence.len()
    }
    fn begin_member_replacement_enrollment_inner(
        &self,
        peer: &PeerCredentials,
        mut helper: SetupHelper,
        hardware: impl FnOnce() -> EnclaveResult<VaultHardware>,
        start: u64,
    ) -> EnclaveResult<(PendingAssetEnrollment, [u8; 32])> {
        Self::asset_admin(peer)?;
        let owner = self
            .membership_authority
            .as_ref()
            .ok_or_else(|| err!(EACCES, "MEMBERSHIP_RECOVERY_PROVIDER_REQUIRED"))?;
        let cap = start
            .checked_add(crate::ceremony::CEREMONY_BUDGET_NS)
            .ok_or_else(|| err!(ETIMEDOUT, "REPLACEMENT_ENROLLMENT_EXPIRED"))?;
        if SystemClock::default().now_ns() < start {
            fail!(EACCES, "REPLACEMENT_ENROLLMENT_TIME");
        }
        let mut ceremony = self.lock_ceremony()?;
        let (state, profile, boot) = {
            let st = self.lock_state()?;
            if !st.membership_sterile || !st.loss_attempted || st.profile == Profile::L1 {
                fail!(EACCES, "REPLACEMENT_ENROLLMENT_STERILE_REQUIRED");
            }
            (
                st.state_dir
                    .clone()
                    .ok_or_else(|| err!(EACCES, "ENROLLMENT_STATE_REQUIRED"))?,
                st.profile,
                commitment(b"depot-ReplacementBootEpoch-v1\0", &st.epoch)?,
            )
        };
        let generation = self.revoke_cas_keys_with_generation()?;
        ceremony.setup_only = true;
        ceremony.hw.active_asset_guard = None;
        let _publication = membership_cutover::PublicationLease::acquire(&state)?;
        let mut inner = owner
            .inner
            .lock()
            .map_err(|_| err!(EIO, "MEMBERSHIP_AUTHORITY_LOCK"))?;
        let (_, ledger) = open(&state)?;
        let first = owner.observe(&mut inner)?;
        let (loss, context) = bind_source(owner, &state, &ledger, profile, &first)?;
        let mut runtime = self
            .replacement_preparing
            .lock()
            .map_err(|_| err!(EIO, "REPLACEMENT_PREPARING_LOCK"))?;
        if runtime.evidence.len() >= 4 {
            fail!(E2BIG, "REPLACEMENT_ENROLLMENT_CAPACITY");
        }
        let authority = &owner.config.asset_authority;
        let (lower, upper) = MembershipAuthorityOwner::times(&first)?;
        let signed: SignedAssetEnrollmentPolicy = serde_json::from_slice(
            &read_asset_authority_file(&authority.policy_file, 16 * 1024)?,
        )
        .map_err(|_| err!(EACCES, "ASSET_POLICY_DECODE"))?;
        let policy = signed.verify(
            &authority.policy_issuer,
            &authority.host,
            &authority.asset,
            &authority.custodian,
            ledger.policy_floor,
            lower,
        )?;
        signed.verify(
            &authority.policy_issuer,
            &authority.host,
            &authority.asset,
            &authority.custodian,
            ledger.policy_floor,
            upper,
        )?;
        if signed.policy.revision != ledger.policy_floor {
            fail!(ESTALE, "ASSET_POLICY_CHANGED");
        }
        let until = context.policy_expires_unix.min(signed.policy.expires_unix);
        let mut deadline = cap_from_observation(start, cap, until, &first)?;
        let remaining = deadline
            .checked_sub(SystemClock::default().now_ns())
            .ok_or_else(|| err!(ETIMEDOUT, "REPLACEMENT_ENROLLMENT_EXPIRED"))?
            / 1_000_000;
        let original_cutoff_ms = milliseconds(until)?.min(
            first
                .trusted_lower_utc_ms
                .checked_add(remaining)
                .ok_or_else(|| err!(EACCES, "REPLACEMENT_ENROLLMENT_TIME"))?,
        );
        let (mut capture_store, mut captures) = capture_store(&state)?;
        let mut nonce = [0; 32];
        enclave_core::rng::fill(&mut nonce);
        captures.attempts.push(CaptureAttempt {
            source: first.pin,
            incident: loss.statement_sha256,
            profile,
            boot,
            start_ns_hex: format!("{start:016x}"),
            nonce_sha256: Sha256::digest(nonce).into(),
            pending: None,
        });
        capture_store.save_json(&captures)?;
        // No discovery/helper/credential work precedes exact accepted-source
        // admission, protected policy and durable nonce capture.
        self.prepare_sterile_replacement_enrollment(generation, profile)?;
        let result = (|| {
            self.asset_check(generation, deadline)?;
            let mut hw = hardware()?;
            self.asset_check(generation, deadline)?;
            if hw.credential.is_some()
                || hw.membership_devices.is_some()
                || hw.active_asset_guard.is_some()
                || hw.asset_activation_binding.is_some()
                || (hw.simulated && !cfg!(any(test, feature = "simulation")))
            {
                fail!(EACCES, "REPLACEMENT_ENROLLMENT_HARDWARE_SCOPE");
            }
            hw.refresh_metadata(profile, ActionClass::A4, lower)?;
            self.asset_check(generation, deadline)?;
            let mds = hw
                .mds
                .clone()
                .ok_or_else(|| err!(EACCES, "CUSTODY_METADATA_UNAVAILABLE"))?;
            // Floor to whole seconds conservatively for existing receipt/code
            // interfaces. This ORIGINAL independent10s cap survives consumption.
            let signed_until = until.min(mds.expires_at).min(
                mds.refreshed_at
                    .saturating_add(crate::ctap::mds::freshness_window_s(profile)),
            );
            deadline = cap_from_observation(start, deadline, signed_until, &first)?;
            let valid_until = signed_until.min(
                i64::try_from(original_cutoff_ms / 1000)
                    .map_err(|_| err!(EACCES, "REPLACEMENT_ENROLLMENT_TIME"))?,
            );
            if let Some(bound) = hw
                .metadata_source
                .as_ref()
                .and_then(|source| source.deadline_ns())
            {
                deadline = deadline.min(bound);
            }
            self.asset_check(generation, deadline)?;
            let prompt = BiometricPrompt {
                localized_reason: policy.localized_reason(),
                d_jcs: policy.digest().to_vec(),
                nonce: nonce.to_vec(),
                t_start_ns: start,
                bio_key_blob: vec![],
            };
            let outcome = helper.evaluate(&prompt);
            self.asset_check(generation, deadline)?;
            let (bio_public_key, bio_key_blob) = match &outcome {
                BiometricOutcome::Approved {
                    enrolled_pubkey: Some(key),
                    enrolled_blob: Some(blob),
                    ..
                } if !blob.is_empty() && blob.len() <= 64 * 1024 => (key.clone(), blob.clone()),
                _ => {
                    fail!(EACCES, "ASSET_BIOMETRIC_ENROLLMENT_REQUIRED");
                }
            };
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&bio_public_key)
                .map_err(|_| err!(EACCES, "ASSET_BIOMETRIC_KEY"))?;
            let disclosure = VerifiedSetupDisclosure::verify(&policy, &key, &prompt, &outcome)?;
            let dev = hw
                .yubikey
                .as_mut()
                .ok_or_else(|| err!(EACCES, "YUBIKEY_REQUIRED"))?;
            dev.bind_selected_instance()?;
            if profile == Profile::L3 && dev.hub_depth() != 1 {
                fail!(EACCES, "USB_HUB_FORBIDDEN_L3");
            }
            if !hw.simulated {
                enclave_core::power::require_selected_usb_instance()?;
            }
            let mut client = CtapClient::open_with_deadline(dev.as_mut(), deadline)?;
            let provider = &mut hw.existing_pin;
            let mut pin = || {
                provider
                    .as_mut()
                    .ok_or_else(|| err!(EACCES, "YUBIKEY_PIN_PROVIDER_REQUIRED"))?
                    .read_existing_pin_cancellable(&prompt, &self.ceremony_cancelled)
            };
            let evidence = crate::ctap::client::begin_asset_enrollment_capturing_with_pin(
                &mut client,
                &mds,
                &policy,
                disclosure,
                profile,
                &SystemClock::default(),
                &self.ceremony_cancelled,
                Some(&mut pin),
                |evidence| {
                    let pending = Pending {
                        evidence: evidence.clone(),
                        bio_public_key: bio_public_key.clone(),
                        bio_key_blob: bio_key_blob.clone(),
                        policy_revision: ledger.policy_floor,
                        profile,
                    };
                    if serde_json::to_vec(&pending)
                        .map_err(|_| err!(EIO, "STATE_SERIALIZE"))?
                        .len()
                        > MAX_PENDING_JSON
                    {
                        fail!(E2BIG, "REPLACEMENT_ENROLLMENT_CAPTURE_SIZE");
                    }
                    captures
                        .attempts
                        .last_mut()
                        .ok_or_else(|| err!(EIO, "REPLACEMENT_ENROLLMENT_CAPTURE"))?
                        .pending = Some(pending);
                    capture_store.save_json(&captures)
                },
            )?;
            drop(client);
            self.asset_check(generation, deadline)?;
            if !hw.simulated {
                enclave_core::power::require_selected_usb_instance()?;
            }
            let pending = Pending {
                evidence,
                bio_public_key,
                bio_key_blob,
                policy_revision: ledger.policy_floor,
                profile,
            };
            distinct_new(&loss, &context, authority, &pending)?;
            let current = owner.observe(&mut inner)?;
            if current.pin != first.pin || current.pin.workflow_sha256 != hash(&open(&state)?.1)? {
                fail!(EACCES, "MEMBERSHIP_ANCHOR_MISMATCH");
            }
            let (fresh_lower, fresh_upper) = MembershipAuthorityOwner::times(&current)?;
            if current.trusted_upper_utc_ms >= milliseconds(valid_until)? {
                fail!(ETIMEDOUT, "REPLACEMENT_ENROLLMENT_EXPIRED");
            }
            for at in [fresh_lower, fresh_upper] {
                if authority.policy(ledger.policy_floor, at)?.digest() != policy.digest() {
                    fail!(ESTALE, "ASSET_POLICY_CHANGED");
                }
                mds.check(
                    &pending.evidence.credential().aaguid,
                    pending.evidence.credential().firmware_version,
                    pending.evidence.credential().key.alg(),
                    profile,
                    ActionClass::A4,
                    at,
                )?;
            }
            self.asset_check(generation, deadline)?;
            let public = pending.evidence.clone();
            let capability = completed(
                pending,
                EnrollmentOrigin {
                    scope: owner.config.scope,
                    incident: loss.statement_sha256,
                    profile,
                    boot,
                    generation,
                    start_ns: start,
                    deadline_ns: deadline,
                    valid_until,
                },
            )?;
            let id = capability.id;
            if runtime.evidence.contains_key(&id) {
                fail!(EACCES, "REPLACEMENT_ENROLLMENT_DUPLICATE");
            }
            self.attach_setup_release(generation, deadline, valid_until)?;
            runtime.evidence.insert(id, capability);
            Ok((public, id))
        })();
        if result.is_err() {
            self.ceremony_cancelled
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        result
    }
}
