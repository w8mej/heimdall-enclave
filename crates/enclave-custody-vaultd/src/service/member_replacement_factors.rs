//! Same-invocation durable burn -> genuine survivor+NEW factors -> encrypted
//! inactive result. No saved completion, active commit, grant or release API.
use super::*;
use membership_cutover::{full_member_ceremony_for, FactorOwners, MemberFactorInput, ProofWindow};

enum FactorHelper {
    Native(crate::biometric::IntentHelperProvider),
    #[cfg(test)]
    Fixture {
        members: [SimulatedTouchId; 2],
        next: usize,
    },
}
impl std::fmt::Debug for FactorHelper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplacementFactorHelper")
            .finish_non_exhaustive()
    }
}
impl BiometricProvider for FactorHelper {
    fn evaluate(&mut self, prompt: &BiometricPrompt) -> BiometricOutcome {
        match self {
            Self::Native(helper) => helper.evaluate(prompt),
            #[cfg(test)]
            Self::Fixture { members, next } => {
                let index = *next;
                *next += 1;
                match members.get_mut(index) {
                    Some(helper) => helper.evaluate(prompt),
                    None => BiometricOutcome::Cancelled,
                }
            }
        }
    }
}

/// Only successful real factors plus all17 possessions construct this move-only
/// value. Encrypted wrappers and checked public pins only; no activation or
/// serialization interface and no retained raw PRF/ECDH/plaintext/live grant.
pub(in crate::service::asset_workflow) struct VerifiedReplacementFactors {
    accepted: MembershipAnchorPin,
    candidate_sha256: [u8; 32],
    counter_sha256: [u8; 32],
    generation: u64,
    start: u64,
    deadline: u64,
    until: i64,
    wrappers: crate::backup_envelope::StagedBackupEnvelopes,
}
impl std::fmt::Debug for VerifiedReplacementFactors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedReplacementFactors")
            .finish_non_exhaustive()
    }
}
#[cfg(test)]
impl VerifiedReplacementFactors {
    pub(in crate::service::asset_workflow) fn test_window(&self) -> (u64, u64, u64) {
        (self.generation, self.start, self.deadline)
    }
}

impl LivePreparedReplacement {
    fn record(&self) -> EnclaveResult<&MemberReplacementRecord> {
        let Phase::MembershipReplacementPreparing {record}=&self.accepted.phase else {fail!(EACCES,"REPLACEMENT_FACTORS_LIVE_BURN_REQUIRED");};
        Ok(record)
    }
    fn revalidate(
        &self,
        owner: &MembershipAuthorityOwner,
        inner: &mut AuthorityInner,
        hw: Option<&VaultHardware>,
        until: i64,
    ) -> EnclaveResult<()> {
        self.checked
            .check_at_boot(SystemClock::default().now_ns())?;
        let current = owner.observe(inner)?;
        let record = self.record()?;
        if current.pin
            != (MembershipAnchorPin {
                revision: record.anchor_revision,
                workflow_sha256: hash(&self.accepted)?,
            })
            || hash(&open(&self.state)?.1)? != current.pin.workflow_sha256
        {
            fail!(EACCES, "MEMBERSHIP_ANCHOR_MISMATCH");
        }
        let profile = record.current.pending.profile;
        owner.accepted_replacement_context(
            &self.state,
            &self.accepted,
            record,
            profile,
            &current,
        )?;
        let until_ms = u64::try_from(until)
            .ok()
            .and_then(|n| n.checked_mul(1000))
            .ok_or_else(|| err!(EACCES, "REPLACEMENT_FACTORS_TIME"))?;
        if current.trusted_upper_utc_ms >= record.accept_before_utc_ms.min(until_ms) {
            fail!(ETIMEDOUT, "REPLACEMENT_FACTORS_EXPIRED");
        }
        let (lower, upper) = MembershipAuthorityOwner::times(&current)?;
        for at in [lower, upper] {
            let policy = owner
                .config
                .asset_authority
                .policy(self.accepted.policy_floor, at)?;
            record.current.survivor_receipt.clone().activate(
                self.context.pendings[1 - record.loss.target_index].clone(),
                &policy,
                &owner.config.asset_authority.inventory_issuer,
                record.current.survivor_receipt.generation,
                at,
            )?;
            record.current.replacement_receipt.clone().activate(
                record.current.pending.evidence.clone(),
                &policy,
                &owner.config.asset_authority.inventory_issuer,
                record.current.replacement_receipt.generation,
                at,
            )?;
            if let Some(hw) = hw {
                let mds = hw
                    .mds
                    .as_ref()
                    .ok_or_else(|| err!(EACCES, "CUSTODY_METADATA_UNAVAILABLE"))?;
                for credential in [
                    &self.context.members[1 - record.loss.target_index].credential,
                    record.current.pending.evidence.credential(),
                ] {
                    mds.check(
                        &credential.aaguid,
                        credential.firmware_version,
                        credential.key.alg(),
                        profile,
                        ActionClass::A4,
                        at,
                    )?;
                }
            }
        }
        self.checked.check_at_boot(SystemClock::default().now_ns())
    }
}

fn factor_intent(
    live: &LivePreparedReplacement,
    index: usize,
    epoch: String,
    sequence: u64,
    now: i64,
) -> EnclaveResult<IntentPayloadV1> {
    let r = live.record()?;
    #[derive(Serialize)]
    struct Arguments {
        operation: &'static str,
        head: MembershipAnchorPin,
        incident: [u8; 32],
        candidate: [u8; 32],
        member_role: &'static str,
        credential: RetirementIdentity,
        original_start_ns_hex: String,
    }
    let credential = if index == 0 {
        &live.context.members[1 - r.loss.target_index].credential
    } else {
        r.current.pending.evidence.credential()
    };
    let args = enclave_core::jcs::to_jcs_bytes(&Arguments {
        operation: "replace-member-inactive-factors",
        head: MembershipAnchorPin {
            revision: r.anchor_revision,
            workflow_sha256: hash(&live.accepted)?,
        },
        incident: r.loss.statement_sha256,
        candidate: r.last()?.candidate_sha256,
        member_role: if index == 0 { "survivor" } else { "new" },
        credential: RetirementIdentity::from_credential(credential)?,
        original_start_ns_hex: format!("{:016x}", live.start),
    })?;
    let intent = IntentPayloadV1 {
        v: 1,
        schema_version: Some("enclave.intent.v1".into()),
        action_class: ActionClass::A4,
        profile: r.current.pending.profile,
        data_class: Some(enclave_core::label::Conf::C4),
        spiffe_id: DaemonId::CustodyVault.spiffe_id(),
        tool_name: "depot://custody/replace_member_inactive".into(),
        target_namespace: Some("custody.membership".into()),
        human_summary_trusted: Some(format!(
            "Authorize exact {} credential for inactive member replacement",
            if index == 0 { "survivor" } else { "NEW" }
        )),
        row_count_bound: Some(1),
        arguments_jcs_sha256: Some(hex::encode(Sha256::digest(&args))),
        canonical_arguments_blake3: blake3::hash(&args).to_hex().to_string(),
        model_blake3: None,
        policy_blake3: hex::encode(r.loss.binding.policy_sha256),
        qif_millibits_delta: Some(0),
        custody_grant: None,
        boot_epoch_id: epoch,
        rpc_seq_u64: sequence,
        ts_utc_ms: u64::try_from(now)
            .map_err(|_| err!(EACCES, "REPLACEMENT_FACTORS_TIME"))?
            .saturating_mul(1000),
        required_factors: crate::factors::required_factors(
            r.current.pending.profile,
            ActionClass::A4,
            false,
        )
        .into_iter()
        .collect(),
        user_turn: None,
    };
    intent.validate()?;
    Ok(intent)
}

impl VaultService {
    /// Explicit protected embedding only. No RPC, active member or ordinary
    /// authorization path. Replay ACKs cannot reach the hardware factory.
    pub fn verify_member_replacement_with_factory(
        &self,
        peer: &PeerCredentials,
        candidate: &[u8],
        evidence: [u8; 32],
        receipt: AssetEnrollmentReceipt,
        survivor: Option<AssetEnrollmentReceipt>,
        helper: crate::biometric::IntentHelperProvider,
        hardware: impl FnOnce() -> EnclaveResult<VaultHardware>,
    ) -> EnclaveResult<impl std::fmt::Debug> {
        self.replacement_factors_with_helper(
            peer,
            candidate,
            evidence,
            receipt,
            survivor,
            FactorHelper::Native(helper),
            hardware,
        )
    }
    #[cfg(test)]
    pub(in crate::service::asset_workflow) fn verify_member_replacement_with_concrete_fixtures(
        &self,
        peer: &PeerCredentials,
        candidate: &[u8],
        evidence: [u8; 32],
        receipt: AssetEnrollmentReceipt,
        survivor: Option<AssetEnrollmentReceipt>,
        members: [SimulatedTouchId; 2],
        hardware: impl FnOnce() -> EnclaveResult<VaultHardware>,
    ) -> EnclaveResult<VerifiedReplacementFactors> {
        self.replacement_factors_with_helper(
            peer,
            candidate,
            evidence,
            receipt,
            survivor,
            FactorHelper::Fixture { members, next: 0 },
            hardware,
        )
    }
    fn replacement_factors_with_helper(
        &self,
        peer: &PeerCredentials,
        candidate: &[u8],
        evidence: [u8; 32],
        receipt: AssetEnrollmentReceipt,
        survivor: Option<AssetEnrollmentReceipt>,
        helper: FactorHelper,
        hardware: impl FnOnce() -> EnclaveResult<VaultHardware>,
    ) -> EnclaveResult<VerifiedReplacementFactors> {
        let (_, live) = self.burn_member_replacement(
            peer,
            candidate,
            evidence,
            receipt,
            survivor,
            SystemClock::default().now_ns(),
        )?;
        let live = live.ok_or_else(|| err!(EACCES, "REPLACEMENT_FACTORS_LIVE_BURN_REQUIRED"))?;
        let result = self.verify_live_replacement_factors(live, helper, hardware);
        if result.is_err() {
            self.ceremony_cancelled
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        result
    }
    fn verify_live_replacement_factors(
        &self,
        live: Box<LivePreparedReplacement>,
        helper: FactorHelper,
        hardware: impl FnOnce() -> EnclaveResult<VaultHardware>,
    ) -> EnclaveResult<VerifiedReplacementFactors> {
        // A test-only historical staged Pending cannot enter this production
        // boundary either. The actual producer origin must survive the burn.
        if live.enrollment.origin.is_none() {
            fail!(EACCES, "REPLACEMENT_FACTORS_LIVE_ENROLLMENT_REQUIRED");
        }
        let owner = self
            .membership_authority
            .as_ref()
            .ok_or_else(|| err!(EACCES, "MEMBERSHIP_RECOVERY_PROVIDER_REQUIRED"))?;
        let mut ceremony = self.lock_ceremony()?;
        let c = &mut *ceremony;
        let _publication = membership_cutover::PublicationLease::acquire(&live.state)?;
        let mut inner = owner
            .inner
            .lock()
            .map_err(|_| err!(EIO, "MEMBERSHIP_AUTHORITY_LOCK"))?;
        live.revalidate(owner, &mut inner, None, live.until)?;
        let r = live.record()?;
        let profile = r.current.pending.profile;
        let survivor_index = 1 - r.loss.target_index;
        {
            let st = self.lock_state()?;
            if !st.membership_sterile
                || !st.loss_attempted
                || st.profile != profile
                || st.state_dir.as_ref() != Some(&live.state)
                || commitment(b"depot-ReplacementBootEpoch-v1\0", &st.epoch)?
                    != r.current.boot_epoch_sha256
            {
                fail!(EACCES, "REPLACEMENT_FACTORS_CONTEXT");
            }
        }
        self.prepare_sterile_replacement_enrollment(live.generation, profile)?;
        c.enter_generation(live.generation);
        let mut window = ProofWindow {
            start_ns: live.start,
            start_unix: r.current.verified_lower_unix,
            deadline_ns: live.deadline,
            valid_until_unix: live.until.min(
                i64::try_from(r.accept_before_utc_ms / 1000)
                    .map_err(|_| err!(EACCES, "REPLACEMENT_FACTORS_TIME"))?,
            ),
        };
        self.asset_check(live.generation, window.deadline_ns)?;
        window.check(c.clock.as_ref())?;
        let (_, loaded) =
            SealedStore::open_bounded_required(&live.state, "signcount", 32 * 1024 * 1024)?;
        let Loaded::State(bytes)=loaded else {fail!(EACCES,"SIGN_COUNT_STATE");};
        if enclave_core::sealed::decode::<SignCountStore>(&bytes)? != c.counters {
            fail!(EACCES, "ASSET_MEMBERSHIP_COUNTER_PIN");
        }
        let mut hw = hardware()?;
        self.asset_check(live.generation, window.deadline_ns)?;
        if hw.credential.is_some()
            || hw.yubikey.is_some()
            || hw.active_asset_guard.is_some()
            || hw.asset_activation_binding.is_some()
            || (hw.simulated && !cfg!(any(test, feature = "simulation")))
        {
            fail!(EACCES, "REPLACEMENT_FACTORS_HARDWARE_SCOPE");
        }
        // The pinned concrete helper is the ONLY D2 factor provider. Neither
        // factory biometric/SEP nor factory asset issuer supplies authority.
        hw.biometric = Box::new(helper);
        hw.asset_enrollment_authority = None;
        let mut devices = hw
            .membership_devices
            .take()
            .ok_or_else(|| err!(EACCES, "MEMBERSHIP_NATIVE_PAIR_REQUIRED"))?;
        devices.require_current(hw.simulated)?;
        devices.require_topology(profile)?;
        let envelope_authority = hw
            .envelope_authority
            .clone()
            .ok_or_else(|| err!(EACCES, "ENVELOPE_POLICY_AUTHORITY_REQUIRED"))?;
        let source = hw
            .metadata_source
            .clone()
            .ok_or_else(|| err!(EACCES, "ENVELOPE_POLICY_SOURCE_REQUIRED"))?;
        let context = source.envelope_context(&envelope_authority, profile, c.clock.now_unix())?;
        window.cap(Some(context.expires_unix()), context.deadline_ns());
        window.check(c.clock.as_ref())?;
        let members = [
            &live.context.members[survivor_index].credential,
            r.current.pending.evidence.credential(),
        ];
        for (index, credential) in members.iter().copied().enumerate() {
            hw.asset_metadata(profile, credential, c.clock.now_unix())?;
            let mut client =
                CtapClient::open_with_deadline(devices.member(index)?, window.deadline_ns)?;
            let info = client.get_info()?;
            drop(client);
            if info.aaguid != credential.aaguid {
                fail!(EACCES, "AAGUID_CHANGED");
            }
            hw.mds
                .as_ref()
                .ok_or_else(|| err!(EACCES, "CUSTODY_METADATA_UNAVAILABLE"))?
                .check(
                    &info.aaguid,
                    info.firmware_version,
                    credential.key.alg(),
                    profile,
                    ActionClass::A4,
                    c.clock.now_unix(),
                )?;
            if profile == Profile::L3 && !info.built_in_uv && hw.existing_pin.is_none() {
                fail!(EACCES, "YUBIKEY_PIN_PROVIDER_REQUIRED");
            }
        }
        live.revalidate(owner, &mut inner, Some(&hw), window.valid_until_unix)?;
        let mut outputs = Vec::with_capacity(2);
        for index in 0..2 {
            self.asset_check(live.generation, window.deadline_ns)?;
            window.check(c.clock.as_ref())?;
            let (epoch, sequence) = {
                let mut st = self.lock_state()?;
                if !st.membership_sterile || !st.loss_attempted || st.profile != profile {
                    fail!(EACCES, "REPLACEMENT_FACTORS_CONTEXT");
                }
                Self::begin_governed(&mut st)?
            };
            let intent = factor_intent(&live, index, epoch, sequence, c.clock.now_unix())?;
            let (sep_public, blob) = if index == 0 {
                (
                    &live.context.members[survivor_index].bio_public_key,
                    &live.context.members[survivor_index].bio_key_blob,
                )
            } else {
                (
                    &r.current.pending.bio_public_key,
                    &r.current.pending.bio_key_blob,
                )
            };
            let (mut grant, prompt) = full_member_ceremony_for(
                FactorOwners {
                    engine: &mut c.engine,
                    hw: &mut hw,
                    counters: &mut c.counters,
                    counter_store: c.counter_store.as_mut(),
                    clock: c.clock.as_ref(),
                },
                &mut devices,
                index,
                MemberFactorInput {
                    credential: members[index],
                    sep_public,
                    blob,
                    profile,
                    original_start_ns: live.start,
                },
                &intent,
                &mut window,
                &self.ceremony_cancelled,
            )?;
            self.asset_check(live.generation, window.deadline_ns)?;
            grant.check_valid_at(c.clock.now_unix())?;
            grant.check_valid_at_boot(c.clock.now_ns())?;
            grant.consume()?;
            let mut challenge = b"depot-ReplacementDualPrf-v1\0".to_vec();
            challenge.extend(hash(&live.accepted)?);
            challenge.extend(grant.d_jcs);
            challenge.extend(grant.sep_signature);
            challenge.extend((index as u64).to_be_bytes());
            challenge.extend(live.start.to_be_bytes());
            challenge.extend(enclave_core::rng::bytes32());
            let challenge: [u8; 32] = Sha256::digest(challenge).into();
            let credential = members[index];
            let mut salts = [0; 64];
            salts[..32].copy_from_slice(&PrfTier::A3.salt());
            salts[32..].copy_from_slice(&PrfTier::A4.salt());
            devices.require_current(hw.simulated)?;
            let mut client =
                CtapClient::open_with_deadline(devices.member(index)?, window.deadline_ns)?;
            let info = client.get_info()?;
            if info.aaguid != credential.aaguid {
                fail!(EACCES, "AAGUID_CHANGED");
            }
            let (response, shared) = if profile == Profile::L3 && !info.built_in_uv {
                let provider = hw
                    .existing_pin
                    .as_mut()
                    .ok_or_else(|| err!(EACCES, "YUBIKEY_PIN_PROVIDER_REQUIRED"))?;
                client.get_assertion_dual_prf_with_pin_provider(
                    &credential.credential_id,
                    &challenge,
                    &salts,
                    window.deadline_ns,
                    &self.ceremony_cancelled,
                    || provider.read_existing_pin_cancellable(&prompt, &self.ceremony_cancelled),
                )?
            } else {
                client.get_assertion_dual_prf(
                    &credential.credential_id,
                    &challenge,
                    profile == Profile::L3,
                    &salts,
                )?
            };
            drop(client);
            let verified = crate::ctap::assertion::verify_assertion(
                credential,
                &response,
                &challenge,
                profile == Profile::L3,
                &mut c.counters,
            )?;
            // Persist authentic advances BEFORE PRF decryption or any later
            // policy/second-chain/possession failure. Never restore old floors.
            c.counter_store
                .as_mut()
                .ok_or_else(|| err!(EACCES, "SIGN_COUNT_STATE"))?
                .save_json(&c.counters)?;
            let encrypted = verified
                .hmac_secret_enc
                .ok_or_else(|| err!(EACCES, "PRF_MISSING"))?;
            let prf = crate::ctap::client::decrypt_prf(
                &shared.ok_or_else(|| err!(EACCES, "PRF_MISSING"))?,
                &encrypted,
            )?;
            if prf.len() != 64 {
                fail!(EACCES, "PRF_OUTPUT_LEN");
            }
            outputs.push(prf);
            devices.require_current(hw.simulated)?;
            self.asset_check(live.generation, window.deadline_ns)?;
            hw.asset_metadata(profile, credential, c.clock.now_unix())?;
            window.cap(
                hw.mds.as_ref().map(|mds| {
                    mds.expires_at.min(
                        mds.refreshed_at
                            .saturating_add(crate::ctap::mds::freshness_window_s(profile)),
                    )
                }),
                hw.metadata_source
                    .as_ref()
                    .and_then(|source| source.deadline_ns()),
            );
            let current =
                source.envelope_context(&envelope_authority, profile, c.clock.now_unix())?;
            window.cap(Some(current.expires_unix()), current.deadline_ns());
            window.check(c.clock.as_ref())?;
            live.revalidate(owner, &mut inner, Some(&hw), window.valid_until_unix)?;
        }
        let a3 = c.hw.sep.ecdh_share(PrfTier::A3)?;
        window.check(c.clock.as_ref())?;
        self.asset_check(live.generation, window.deadline_ns)?;
        let a4 = c.hw.sep.ecdh_share(PrfTier::A4)?;
        window.check(c.clock.as_ref())?;
        self.asset_check(live.generation, window.deadline_ns)?;
        if enclave_core::secret::ct_eq(&outputs[0].expose()[..32], &outputs[0].expose()[32..]) {
            fail!(EACCES, "MEMBERSHIP_INDEPENDENT_PRF_REQUIRED");
        }
        let survivor_a3 = KekShares {
            sep_ecdh_share: a3.expose(),
            yubikey_prf: &outputs[0].expose()[..32],
        };
        let survivor_a4 = KekShares {
            sep_ecdh_share: a4.expose(),
            yubikey_prf: &outputs[0].expose()[32..],
        };
        let new_a3 = KekShares {
            sep_ecdh_share: a3.expose(),
            yubikey_prf: &outputs[1].expose()[..32],
        };
        let new_a4 = KekShares {
            sep_ecdh_share: a4.expose(),
            yubikey_prf: &outputs[1].expose()[32..],
        };
        let current = source.envelope_context(&envelope_authority, profile, c.clock.now_unix())?;
        window.cap(Some(current.expires_unix()), current.deadline_ns());
        window.check(c.clock.as_ref())?;
        let selected = if survivor_index == 0 {
            crate::backup_envelope::SelectedMemberWrappers::OriginalPrimary
        } else {
            crate::backup_envelope::SelectedMemberWrappers::Alternate(&live.context.alternate)
        };
        let wrappers = crate::backup_envelope::StagedBackupEnvelopes::stage_from_selected_member(
            &live.context.checkpoint,
            &live.context.members[0].credential,
            members[0],
            members[1],
            selected,
            &survivor_a3,
            &survivor_a4,
            &new_a3,
            &new_a4,
            &current,
            c.clock.now_unix(),
        )?;
        devices.require_current(hw.simulated)?;
        let final_context =
            source.envelope_context(&envelope_authority, profile, c.clock.now_unix())?;
        window.cap(
            Some(final_context.expires_unix()),
            final_context.deadline_ns(),
        );
        wrappers.validate_scope(
            &live.context.checkpoint,
            &live.context.members[0].credential,
            members[1],
            &final_context,
            c.clock.now_unix(),
        )?;
        live.revalidate(owner, &mut inner, Some(&hw), window.valid_until_unix)?;
        let counter_sha256 = commitment(b"depot-ReplacementFactorCounters-v1\0", &c.counters)?;
        window.check(c.clock.as_ref())?;
        self.asset_check(live.generation, window.deadline_ns)?;
        let accepted = MembershipAnchorPin {
            revision: r.anchor_revision,
            workflow_sha256: hash(&live.accepted)?,
        };
        let candidate_sha256 = r.last()?.candidate_sha256;
        // No provider/filesystem/serialization work under the final fence.
        let _release = self
            .cas_key_release
            .lock()
            .map_err(|_| err!(EIO, "CAS_RELEASE_LOCK"))?;
        self.asset_check(live.generation, window.deadline_ns)?;
        live.checked.check_at_boot(c.clock.now_ns())?;
        Ok(VerifiedReplacementFactors {
            accepted,
            candidate_sha256,
            counter_sha256,
            generation: live.generation,
            start: live.start,
            deadline: window.deadline_ns,
            until: window.valid_until_unix,
            wrappers,
        })
    }
}
