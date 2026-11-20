//! Inactive replacement candidate/receipt/grant consumption in the SAME v4
//! workflow. No factor, PRF, wrapper staging, active member or release path.
//! Required production owner/code/enrollment adapters remain separately OPEN.
use super::*;
use crate::{
    membership_retirement::{verify_replacement, ReplacementBinding, RetirementIdentity},
    replacement_release_authority::*,
};
use std::collections::BTreeMap;
const MAX_CONSUMED: usize = 64;
#[path = "member_replacement_enrollment.rs"]
mod member_replacement_enrollment;
#[path = "member_replacement_factors.rs"]
mod member_replacement_factors;

/// Only this invocation's durable fresh burn constructs this owner. Saved ACKs
/// never reconstruct it. It retains the ACTUAL checked provider result and
/// ACTUAL enrollment capability through inactive factors, never serialized.
struct LivePreparedReplacement {
    checked: CheckedReplacementRelease,
    enrollment: ValidatedReplacementEnrollment,
    accepted: Ledger,
    context: membership_cutover::MemberLossContext,
    state: PathBuf,
    generation: u64,
    start: u64,
    deadline: u64,
    until: i64,
}

/// Opaque trusted producer output, NOT deserializable or constructible from RPC
/// pending/receipt/blob fields. Only the actual protected initializer below
/// constructs production capabilities after verified disclosure/attestation
/// and direct helper key/blob provenance. Receipt::activate alone cannot do so.
pub(in crate::service) struct ValidatedReplacementEnrollment {
    scope: [u8; 32],
    pending: Pending,
    id: [u8; 32],
    origin: Option<member_replacement_enrollment::EnrollmentOrigin>,
}
impl std::fmt::Debug for ValidatedReplacementEnrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatedReplacementEnrollment")
            .finish_non_exhaustive()
    }
}
fn enrollment_id(scope: [u8; 32], pending: &Pending) -> EnclaveResult<[u8; 32]> {
    commitment(
        b"MCPMac-ValidatedReplacementEnrollment-v1\0",
        &(scope, pending),
    )
}
#[cfg(test)]
impl ValidatedReplacementEnrollment {
    pub(in crate::service::asset_workflow) fn from_completed_initializer(
        scope: [u8; 32],
        pending: Pending,
    ) -> EnclaveResult<Self> {
        if scope == [0; 32]
            || pending.bio_key_blob.is_empty()
            || pending.bio_key_blob.len() > 64 * 1024
            || pending.bio_public_key != pending.evidence.sep_public_key
        {
            fail!(EACCES, "REPLACEMENT_ENROLLMENT_EVIDENCE");
        }
        pending.evidence.digest()?;
        let id = enrollment_id(scope, &pending)?;
        Ok(Self {
            scope,
            pending,
            id,
            origin: None,
        })
    }
}
#[derive(Default)]
pub(in crate::service) struct ReplacementPreparingRuntime {
    release: Option<ReplacementReleaseAuthority>,
    evidence: BTreeMap<[u8; 32], ValidatedReplacementEnrollment>,
}
fn commitment(domain: &[u8], value: &impl Serialize) -> EnclaveResult<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(enclave_core::jcs::to_jcs_bytes(value)?);
    Ok(h.finalize().into())
}
fn positive(n: u64) -> bool {
    n > 0 && n <= INTEGER_LIMIT
}
fn advance_safe(n: u64) -> EnclaveResult<u64> {
    n.checked_add(1)
        .filter(|n| positive(*n))
        .ok_or_else(|| err!(EACCES, "REPLACEMENT_PREPARING_EXHAUSTED"))
}
fn ns(text: &str) -> EnclaveResult<u64> {
    if text.len() != 16
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        fail!(EACCES, "REPLACEMENT_PREPARING_TIME");
    }
    u64::from_str_radix(text, 16).map_err(|_| err!(EACCES, "REPLACEMENT_PREPARING_TIME"))
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumedCandidate {
    candidate_sha256: [u8; 32],
    wire_sha256: [u8; 32],
    binding_sha256: [u8; 32],
    history_sha256: [u8; 32],
    attempt: u64,
    previous_receipt_floor: u64,
    receipt_floor: u64,
    grant_id: [u8; 32],
    grant_generation: u64,
    release_policy_revision: u64,
    release_version: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparingCandidate {
    #[serde(with = "serde_bytes")]
    candidate: Vec<u8>,
    enrollment_evidence_id: [u8; 32],
    pending: Pending,
    replacement_receipt: AssetEnrollmentReceipt,
    survivor_receipt: AssetEnrollmentReceipt,
    // Preserve request shape for exact inert ACK; no refreshed/live authority.
    submitted_survivor_receipt: Option<AssetEnrollmentReceipt>,
    binding: ReplacementBinding,
    original_start_ns_hex: String,
    boot_deadline_ns_hex: String,
    boot_epoch_sha256: [u8; 32],
    verified_lower_unix: i64,
    verified_upper_unix: i64,
    authority_expires_unix: i64,
    release_policy_expires_utc_ms: u64,
    grant_expires_utc_ms: u64,
}
/// FLAT original loss once plus bounded permanent consumption and ONE current
/// preparation. Repeated attempts replace current; never recursively nest v4.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::service::asset_workflow) struct MemberReplacementRecord {
    loss: MemberLossRecord,
    consumed: Vec<ConsumedCandidate>,
    current: PreparingCandidate,
    predecessor: MembershipAnchorPin,
    anchor_revision: u64,
    accept_before_utc_ms: u64,
}
impl MemberReplacementRecord {
    fn loss_ledger(&self) -> Ledger {
        loss_ledger(&self.loss)
    }
    fn last(&self) -> EnclaveResult<&ConsumedCandidate> {
        self.consumed
            .last()
            .ok_or_else(|| err!(EACCES, "REPLACEMENT_PREPARING_STATE"))
    }
}
fn loss_ledger(loss: &MemberLossRecord) -> Ledger {
    Ledger {
        version: 4,
        attempt: loss.loss_generation,
        policy_floor: loss.origin_policy_floor,
        receipt_floor: loss.origin_receipt_floor,
        phase: Phase::MembershipLossRecorded {
            record: loss.clone(),
        },
    }
}
pub(in crate::service::asset_workflow) fn validate_preparing_shape(
    ledger: &Ledger,
    r: &MemberReplacementRecord,
) -> EnclaveResult<()> {
    validate_v4(&r.loss_ledger())?;
    if ledger.version != 4
        || r.consumed.is_empty()
        || r.consumed.len() > MAX_CONSUMED
        || r.current.candidate.is_empty()
        || r.current.candidate.len() > 64 * 1024
        || r.current.pending.bio_key_blob.is_empty()
        || r.current.pending.bio_key_blob.len() > 64 * 1024
        || r.current.pending.bio_public_key != r.current.pending.evidence.sep_public_key
        || r.current.enrollment_evidence_id == [0; 32]
        || r.current.boot_epoch_sha256 == [0; 32]
        || r.predecessor.revision == 0
        || r.predecessor.workflow_sha256 == [0; 32]
        || advance_safe(r.predecessor.revision)? != r.anchor_revision
        || !positive(r.accept_before_utc_ms)
        || ledger.policy_floor != r.loss.origin_policy_floor
    {
        fail!(EACCES, "REPLACEMENT_PREPARING_STATE");
    }
    let start = ns(&r.current.original_start_ns_hex)?;
    let deadline = ns(&r.current.boot_deadline_ns_hex)?;
    if deadline <= start || deadline - start > crate::ceremony::CEREMONY_BUDGET_NS {
        fail!(EACCES, "REPLACEMENT_PREPARING_TIME");
    }
    let mut attempt = r.loss.loss_generation;
    let mut floor = r.loss.origin_receipt_floor;
    let mut candidates = std::collections::BTreeSet::new();
    let mut wires = std::collections::BTreeSet::new();
    let mut grants = std::collections::BTreeSet::new();
    let (mut grant_floor, mut policy_floor, mut version_floor) = (0, 0, 0);
    for entry in &r.consumed {
        if entry.attempt != advance_safe(attempt)?
            || entry.previous_receipt_floor != floor
            || entry.receipt_floor <= floor
            || !positive(entry.receipt_floor)
            || ![
                entry.candidate_sha256,
                entry.wire_sha256,
                entry.binding_sha256,
                entry.history_sha256,
                entry.grant_id,
            ]
            .iter()
            .all(|h| *h != [0; 32])
            || !candidates.insert(entry.candidate_sha256)
            || !wires.insert(entry.wire_sha256)
            || !grants.insert(entry.grant_id)
            || entry.grant_generation <= grant_floor
            || !positive(entry.grant_generation)
            || entry.release_policy_revision < policy_floor
            || !positive(entry.release_policy_revision)
            || entry.release_version < version_floor
            || !positive(entry.release_version)
        {
            fail!(EACCES, "REPLACEMENT_PREPARING_CONSUMPTION");
        }
        attempt = entry.attempt;
        floor = entry.receipt_floor;
        grant_floor = entry.grant_generation;
        policy_floor = entry.release_policy_revision;
        version_floor = entry.release_version;
    }
    let p = &r.current;
    let last = r.last()?;
    let mut expected_current = r.loss.binding.clone();
    expected_current.receipt_floor = last.previous_receipt_floor;
    if ledger.attempt != attempt
        || ledger.receipt_floor != floor
        || p.binding.current != expected_current
        || p.binding.retirement_sha256 != r.loss.statement_sha256
        || p.binding.replacement_receipt_generation != p.replacement_receipt.generation
        || p.replacement_receipt.generation != floor
        || p.binding.replacement_pending_sha256 != p.pending.evidence.digest()?
        || p.pending.profile != p.binding.current.profile
        || p.pending.policy_revision != ledger.policy_floor
        || p.binding.replacement
            != RetirementIdentity::from_credential(p.pending.evidence.credential())?
        || p.binding.replacement_receipt_sha256
            != commitment(b"MCPMac-ReplacementReceipt-v1\0", &p.replacement_receipt)?
        || p.binding.survivor_receipt_sha256
            != commitment(b"MCPMac-ReplacementReceipt-v1\0", &p.survivor_receipt)?
        || p.binding.replacement_receipt_expires_unix != p.replacement_receipt.expires_unix
        || p.binding.survivor_receipt_expires_unix != p.survivor_receipt.expires_unix
        || p.binding.boot_epoch_sha256 != p.boot_epoch_sha256
        || p.binding.release_policy_revision != last.release_policy_revision
        || p.binding.release_policy_expires_unix
            != i64::try_from(p.release_policy_expires_utc_ms / 1000)
                .map_err(|_| err!(EACCES, "REPLACEMENT_PREPARING_TIME"))?
        || last.wire_sha256 != <[u8; 32]>::from(Sha256::digest(&p.candidate))
        || !positive(p.release_policy_expires_utc_ms)
        || !positive(p.grant_expires_utc_ms)
        || r.accept_before_utc_ms > p.release_policy_expires_utc_ms.min(p.grant_expires_utc_ms)
    {
        fail!(EACCES, "REPLACEMENT_PREPARING_BINDING");
    }
    preflight_size(ledger, u64::MAX)
}
impl MembershipAuthorityOwner {
    fn validate_replacement_preparing(
        &self,
        state: &Path,
        ledger: &Ledger,
        r: &MemberReplacementRecord,
        profile: Profile,
        o: &MembershipAnchorObservation,
    ) -> EnclaveResult<membership_cutover::MemberLossContext> {
        validate_preparing_shape(ledger, r)?;
        let context = self.validate_loss(state, &r.loss_ledger(), &r.loss, profile, o)?;
        let (lower, upper) = Self::times(o)?;
        let policy = self
            .config
            .asset_authority
            .policy(ledger.policy_floor, lower)?;
        self.config
            .asset_authority
            .policy(ledger.policy_floor, upper)?;
        let p = &r.current;
        let historical = RetirementObservation {
            lower_unix: p.verified_lower_unix,
            upper_unix: p.verified_upper_unix,
            authority_expires_unix: p.authority_expires_unix,
        };
        for at in [historical.lower_unix, historical.upper_unix] {
            p.replacement_receipt.clone().activate(
                p.pending.evidence.clone(),
                &policy,
                &self.config.asset_authority.inventory_issuer,
                p.replacement_receipt.generation,
                at,
            )?;
            p.survivor_receipt.clone().activate(
                context.pendings[1 - r.loss.target_index].clone(),
                &policy,
                &self.config.asset_authority.inventory_issuer,
                p.survivor_receipt.generation,
                at,
            )?;
        }
        if enrollment_id(self.config.scope, &p.pending)? != p.enrollment_evidence_id {
            fail!(EACCES, "REPLACEMENT_ENROLLMENT_EVIDENCE");
        }
        let pins = InventoryRetirementPins::from_asset_authority(&self.config.asset_authority)?;
        let candidate =
            verify_replacement(&p.candidate, &pins, &p.binding, &r.loss.history, historical)?;
        let last = r.last()?;
        if candidate.statement_sha256() != last.candidate_sha256
            || candidate.binding_sha256() != last.binding_sha256
            || candidate.history_sha256() != last.history_sha256
            || r.accept_before_utc_ms
                > u64::try_from(candidate.expires_unix())
                    .unwrap_or(0)
                    .saturating_mul(1000)
        {
            fail!(EACCES, "REPLACEMENT_PREPARING_CANDIDATE");
        }
        Ok(context)
    }
    fn accepted_replacement_context(
        &self,
        state: &Path,
        ledger: &Ledger,
        r: &MemberReplacementRecord,
        profile: Profile,
        o: &MembershipAnchorObservation,
    ) -> EnclaveResult<membership_cutover::MemberLossContext> {
        if o.pin
            != (MembershipAnchorPin {
                revision: r.anchor_revision,
                workflow_sha256: hash(ledger)?,
            })
        {
            fail!(EACCES, "MEMBERSHIP_ANCHOR_MISMATCH");
        }
        self.validate_replacement_preparing(state, ledger, r, profile, o)
    }
    pub(super) fn check_replacement_startup(
        &self,
        state: &Path,
        ledger: &Ledger,
        r: &MemberReplacementRecord,
        profile: Profile,
        o: &MembershipAnchorObservation,
        _inner: &mut AuthorityInner,
    ) -> EnclaveResult<bool> {
        self.validate_replacement_preparing(state, ledger, r, profile, o)?;
        let exact = MembershipAnchorPin {
            revision: r.anchor_revision,
            workflow_sha256: hash(ledger)?,
        };
        if o.pin != exact {
            if o.pin != r.predecessor {
                fail!(EACCES, "MEMBERSHIP_ANCHOR_MISMATCH");
            }
            if successor(o.pin, ledger)? != exact {
                fail!(EACCES, "MEMBERSHIP_ANCHOR_MISMATCH");
            }
            // Inert saved facts are NOT a serialized proof of actual NEW
            // attestation/SEP ownership or code/scoped-grant admission. Never
            // reconstruct those authorities from receipt/blob/hash fields.
            if o.trusted_upper_utc_ms >= r.accept_before_utc_ms {
                fail!(EACCES, "REPLACEMENT_PREPARING_EXPIRED_UNACCEPTED");
            }
            fail!(
                EACCES,
                "REPLACEMENT_PREPARING_RECONCILIATION_AUTHORITY_REQUIRED"
            );
        }
        Ok(true)
    }
    pub(super) fn replacement_survivor_setup(
        &self,
        state: &Path,
        ledger: &Ledger,
        r: &MemberReplacementRecord,
        profile: Profile,
        o: &MembershipAnchorObservation,
    ) -> EnclaveResult<ValidatedMemberLossSetup> {
        let context = self.accepted_replacement_context(state, ledger, r, profile, o)?;
        Ok(ValidatedMemberLossSetup {
            enrolled: context.members[1 - r.loss.target_index].clone(),
            survivor: if r.loss.target_index == 1 {
                MemberLossSurvivor::OriginalPrimary
            } else {
                MemberLossSurvivor::Alternate
            },
            source_binding: r.loss.binding.source_v2_binding,
            checkpoint: context.checkpoint,
            alternate: context.alternate,
            statement_sha256: r.loss.statement_sha256,
            loss_generation: r.loss.loss_generation,
        })
    }
}
impl VaultService {
    /// Protected inactive embedding setup, never RPC trust/configuration.
    pub(crate) fn configure_replacement_release_authority(
        &self,
        authority: ReplacementReleaseAuthority,
    ) -> EnclaveResult<()> {
        let _ceremony = self.lock_ceremony()?;
        if self.membership_authority.is_none() {
            fail!(EACCES, "MEMBERSHIP_RECOVERY_PROVIDER_REQUIRED");
        }
        let mut runtime = self
            .replacement_preparing
            .lock()
            .map_err(|_| err!(EIO, "REPLACEMENT_PREPARING_LOCK"))?;
        if runtime.release.is_some() {
            fail!(EACCES, "REPLACEMENT_RELEASE_ALREADY_CONFIGURED");
        }
        runtime.release = Some(authority);
        Ok(())
    }
    /// Only an opaque actual producer capability can stage pending/blob bytes.
    /// Only the concrete authenticated live producer constructs production input.
    pub(crate) fn stage_validated_replacement_enrollment(
        &self,
        evidence: ValidatedReplacementEnrollment,
    ) -> EnclaveResult<[u8; 32]> {
        let _ceremony = self.lock_ceremony()?;
        let owner = self
            .membership_authority
            .as_ref()
            .ok_or_else(|| err!(EACCES, "MEMBERSHIP_RECOVERY_PROVIDER_REQUIRED"))?;
        let profile = self.lock_state()?.profile;
        if evidence.scope != owner.config.scope
            || evidence.pending.profile != profile
            || evidence.id != enrollment_id(evidence.scope, &evidence.pending)?
        {
            fail!(EACCES, "REPLACEMENT_ENROLLMENT_EVIDENCE");
        }
        let mut runtime = self
            .replacement_preparing
            .lock()
            .map_err(|_| err!(EIO, "REPLACEMENT_PREPARING_LOCK"))?;
        if runtime.evidence.len() >= 4 || runtime.evidence.contains_key(&evidence.id) {
            fail!(E2BIG, "REPLACEMENT_ENROLLMENT_CAPACITY");
        }
        let id = evidence.id;
        runtime.evidence.insert(id, evidence);
        Ok(id)
    }
    pub(in crate::service) fn prepare_member_replacement(
        &self,
        peer: &PeerCredentials,
        candidate_wire: &[u8],
        evidence_id: [u8; 32],
        replacement_receipt: AssetEnrollmentReceipt,
        submitted_survivor: Option<AssetEnrollmentReceipt>,
        start: u64,
    ) -> EnclaveResult<VaultResponse> {
        let (response, live) = self.burn_member_replacement(
            peer,
            candidate_wire,
            evidence_id,
            replacement_receipt,
            submitted_survivor,
            start,
        )?;
        // Ordinary RPC ACK remains inert: checked provider/enrollment ownership
        // is dropped here, not saved for a later factor request or restart.
        if let Some(live) = live {
            self.attach_setup_release(live.generation, live.deadline, live.until)?;
        }
        Ok(response)
    }
    fn burn_member_replacement(
        &self,
        peer: &PeerCredentials,
        candidate_wire: &[u8],
        evidence_id: [u8; 32],
        replacement_receipt: AssetEnrollmentReceipt,
        submitted_survivor: Option<AssetEnrollmentReceipt>,
        start: u64,
    ) -> EnclaveResult<(VaultResponse, Option<Box<LivePreparedReplacement>>)> {
        Self::asset_admin(peer)?;
        if candidate_wire.is_empty() || candidate_wire.len() > 64 * 1024 {
            fail!(E2BIG, "REPLACEMENT_CANDIDATE_SIZE");
        }
        let owner = self
            .membership_authority
            .as_ref()
            .ok_or_else(|| err!(EACCES, "MEMBERSHIP_RECOVERY_PROVIDER_REQUIRED"))?;
        let original_cap = start
            .checked_add(crate::ceremony::CEREMONY_BUDGET_NS)
            .ok_or_else(|| err!(ETIMEDOUT, "REPLACEMENT_PREPARING_DEADLINE"))?;
        let mut ceremony = self.lock_ceremony()?;
        let (state, profile, boot_epoch_sha256) = {
            let mut st = self.lock_state()?;
            st.loss_attempted = true;
            st.membership_sterile = true;
            (
                st.state_dir
                    .clone()
                    .ok_or_else(|| err!(EACCES, "ENROLLMENT_STATE_REQUIRED"))?,
                st.profile,
                commitment(b"MCPMac-ReplacementBootEpoch-v1\0", &st.epoch)?,
            )
        };
        let generation = self.revoke_cas_keys_with_generation()?;
        ceremony.setup_only = true;
        ceremony.hw.active_asset_guard = None;
        {
            let mut st = self.lock_state()?;
            st.envelope_fault = true;
            st.active_asset_guard = None;
            st.travel = None;
            st.cas_key_leases.clear();
            st.cas_key_deadlines.clear();
            st.namespace_challenges.clear();
        }
        let publication = membership_cutover::PublicationLease::acquire(&state)?;
        let mut inner = owner
            .inner
            .lock()
            .map_err(|_| err!(EIO, "MEMBERSHIP_AUTHORITY_LOCK"))?;
        let (mut store, ledger) = open(&state)?;
        let observed = owner.observe(&mut inner)?;
        if observed.pin.workflow_sha256 != hash(&ledger)? {
            fail!(EACCES, "MEMBERSHIP_ANCHOR_MISMATCH");
        }
        let (loss, consumed, context, saved_survivor) = match &ledger.phase {
            Phase::MembershipLossRecorded { record } => {
                let context =
                    owner.accepted_loss_context(&state, &ledger, record, profile, &observed)?;
                let receipt = context.receipts[1 - record.target_index].clone();
                (record.clone(), Vec::new(), context, receipt)
            }
            Phase::MembershipReplacementPreparing { record } => {
                let context = owner
                    .accepted_replacement_context(&state, &ledger, record, profile, &observed)?;
                let p = &record.current;
                if candidate_wire == p.candidate
                    && evidence_id == p.enrollment_evidence_id
                    && enclave_core::jcs::to_jcs_bytes(&replacement_receipt)?
                        == enclave_core::jcs::to_jcs_bytes(&p.replacement_receipt)?
                    && enclave_core::jcs::to_jcs_bytes(&submitted_survivor)?
                        == enclave_core::jcs::to_jcs_bytes(&p.submitted_survivor_receipt)?
                {
                    let saved_deadline = ns(&p.boot_deadline_ns_hex)?.min(original_cap);
                    if p.boot_epoch_sha256 != boot_epoch_sha256
                        || SystemClock::default().now_ns() >= saved_deadline
                        || observed.trusted_upper_utc_ms >= record.accept_before_utc_ms
                    {
                        fail!(ETIMEDOUT, "REPLACEMENT_PREPARING_REPLAY_EXPIRED");
                    }
                    self.attach_setup_release(
                        generation,
                        saved_deadline,
                        context
                            .policy_expires_unix
                            .min(p.authority_expires_unix)
                            .min(p.replacement_receipt.expires_unix)
                            .min(p.survivor_receipt.expires_unix),
                    )?;
                    return Ok((
                        VaultResponse::MemberReplacementPrepared {
                            candidate_sha256: record.last()?.candidate_sha256,
                            attempt: ledger.attempt,
                            receipt_floor: ledger.receipt_floor,
                        },
                        None,
                    ));
                }
                (
                    record.loss.clone(),
                    record.consumed.clone(),
                    context,
                    p.survivor_receipt.clone(),
                )
            }
            _ => {
                fail!(EACCES, "MEMBER_LOSS_REQUIRED");
            }
        };
        if consumed.len() >= MAX_CONSUMED {
            fail!(E2BIG, "REPLACEMENT_CONSUMPTION_EXHAUSTED");
        }
        let wire_sha256: [u8; 32] = Sha256::digest(candidate_wire).into();
        if consumed.iter().any(|old| old.wire_sha256 == wire_sha256) {
            fail!(EACCES, "REPLACEMENT_CANDIDATE_CONSUMED");
        }
        let mut runtime = self
            .replacement_preparing
            .lock()
            .map_err(|_| err!(EIO, "REPLACEMENT_PREPARING_LOCK"))?;
        if runtime.release.is_none() {
            fail!(EACCES, "REPLACEMENT_RELEASE_PROVIDER_REQUIRED");
        }
        let evidence = runtime
            .evidence
            .get(&evidence_id)
            .ok_or_else(|| err!(EACCES, "REPLACEMENT_ENROLLMENT_EVIDENCE_REQUIRED"))?;
        if evidence.scope != owner.config.scope
            || evidence.pending.profile != profile
            || evidence.pending.policy_revision != ledger.policy_floor
            || evidence.id != enrollment_id(evidence.scope, &evidence.pending)?
        {
            fail!(EACCES, "REPLACEMENT_ENROLLMENT_EVIDENCE");
        }
        // A genuine completion retains the initializer's ORIGINAL scope and
        // window. Even a separate Preparing call cannot refresh that window.
        let (start, enrollment_deadline, enrollment_expires) = match &evidence.origin {
            Some(origin) => origin.preparation_window(
                owner.config.scope,
                loss.statement_sha256,
                profile,
                boot_epoch_sha256,
                generation,
                start,
            )?,
            None => {
                if !cfg!(test) {
                    fail!(EACCES, "REPLACEMENT_ENROLLMENT_EVIDENCE");
                }
                (start, None, None)
            }
        };
        let pending = evidence.pending.clone();
        let (lower, upper) = MembershipAuthorityOwner::times(&observed)?;
        let policy = owner
            .config
            .asset_authority
            .policy(ledger.policy_floor, lower)?;
        owner
            .config
            .asset_authority
            .policy(ledger.policy_floor, upper)?;
        let survivor_receipt = submitted_survivor.clone().unwrap_or(saved_survivor);
        let survivor_minimum = if submitted_survivor.is_some() {
            advance_safe(ledger.receipt_floor)?
        } else {
            survivor_receipt.generation
        };
        for at in [lower, upper] {
            survivor_receipt.clone().activate(
                context.pendings[1 - loss.target_index].clone(),
                &policy,
                &owner.config.asset_authority.inventory_issuer,
                survivor_minimum,
                at,
            )?;
            replacement_receipt.clone().activate(
                pending.evidence.clone(),
                &policy,
                &owner.config.asset_authority.inventory_issuer,
                advance_safe(ledger.receipt_floor.max(if submitted_survivor.is_some() {
                    survivor_receipt.generation
                } else {
                    0
                }))?,
                at,
            )?;
        }
        if !positive(replacement_receipt.generation) || !positive(survivor_receipt.generation) {
            fail!(EACCES, "REPLACEMENT_RECEIPT_EXHAUSTED");
        }
        let attempt = advance_safe(ledger.attempt)?;
        let release_context = ReplacementReleaseContext::new(
            ReplacementReleaseBinding {
                membership_scope: owner.config.scope,
                owner_pin: observed.pin,
                profile,
                boot_epoch_sha256,
                membership_generation: loss.binding.membership_generation,
                proposed_workflow_attempt: attempt,
                incident_sha256: loss.statement_sha256,
            },
            &context.members[1 - loss.target_index].credential,
            pending.evidence.credential(),
            candidate_wire,
        )?;
        let floors = consumed.last().map_or(
            ReplacementReleaseFloors {
                policy_revision: 0,
                release_version: 0,
                grant_generation: 0,
            },
            |old| ReplacementReleaseFloors {
                policy_revision: old.release_policy_revision,
                release_version: old.release_version,
                grant_generation: old.grant_generation,
            },
        );
        let expiry = context
            .policy_expires_unix
            .min(replacement_receipt.expires_unix)
            .min(survivor_receipt.expires_unix)
            .min(enrollment_expires.unwrap_or(i64::MAX));
        let expiry_ms = u64::try_from(expiry)
            .ok()
            .and_then(|n| n.checked_mul(1000))
            .filter(|n| positive(*n))
            .ok_or_else(|| err!(EACCES, "REPLACEMENT_PREPARING_TIME"))?;
        let window = ReplacementReleaseWindow::new(start, enrollment_deadline, expiry_ms)?;
        let checked = runtime
            .release
            .as_mut()
            .ok_or_else(|| err!(EACCES, "REPLACEMENT_RELEASE_PROVIDER_REQUIRED"))?
            .check(
                &release_context,
                floors,
                observed,
                window,
                &SystemClock::default(),
            )?;
        let trusted = checked.trusted_interval();
        let verified_lower = i64::try_from(trusted.lower_utc_ms / 1000)
            .map_err(|_| err!(EACCES, "REPLACEMENT_PREPARING_TIME"))?;
        let verified_upper = i64::try_from(trusted.upper_utc_ms.div_ceil(1000))
            .map_err(|_| err!(EACCES, "REPLACEMENT_PREPARING_TIME"))?;
        let authority_until = expiry.min(
            i64::try_from(checked.grant_expires_utc_ms() / 1000)
                .map_err(|_| err!(EACCES, "REPLACEMENT_PREPARING_TIME"))?,
        );
        // Revalidate receipt/policy at BOTH endpoints of intersected fresh time.
        let policy = owner
            .config
            .asset_authority
            .policy(ledger.policy_floor, verified_lower)?;
        owner
            .config
            .asset_authority
            .policy(ledger.policy_floor, verified_upper)?;
        for at in [verified_lower, verified_upper] {
            survivor_receipt.clone().activate(
                context.pendings[1 - loss.target_index].clone(),
                &policy,
                &owner.config.asset_authority.inventory_issuer,
                survivor_minimum,
                at,
            )?;
            replacement_receipt.clone().activate(
                pending.evidence.clone(),
                &policy,
                &owner.config.asset_authority.inventory_issuer,
                replacement_receipt.generation,
                at,
            )?;
        }
        let mut current = loss.binding.clone();
        current.receipt_floor = ledger.receipt_floor;
        let binding = ReplacementBinding {
            current,
            retirement_sha256: loss.statement_sha256,
            replacement: RetirementIdentity::from_credential(pending.evidence.credential())?,
            replacement_pending_sha256: pending.evidence.digest()?,
            replacement_receipt_sha256: commitment(
                b"MCPMac-ReplacementReceipt-v1\0",
                &replacement_receipt,
            )?,
            replacement_receipt_generation: replacement_receipt.generation,
            replacement_receipt_expires_unix: replacement_receipt.expires_unix,
            survivor_receipt_sha256: commitment(
                b"MCPMac-ReplacementReceipt-v1\0",
                &survivor_receipt,
            )?,
            survivor_receipt_expires_unix: survivor_receipt.expires_unix,
            proposed_membership_generation: advance_safe(loss.binding.membership_generation)?,
            boot_epoch_sha256,
            running_code_sha256: checked.running_code_sha256(),
            release_policy_sha256: checked.release_policy_sha256(),
            release_policy_revision: checked.release_policy_revision(),
            release_policy_expires_unix: i64::try_from(
                checked.release_policy_expires_utc_ms() / 1000,
            )
            .map_err(|_| err!(EACCES, "REPLACEMENT_PREPARING_TIME"))?,
        };
        let pins = InventoryRetirementPins::from_asset_authority(&owner.config.asset_authority)?;
        let verified = verify_replacement(
            candidate_wire,
            &pins,
            &binding,
            &loss.history,
            RetirementObservation {
                lower_unix: verified_lower,
                upper_unix: verified_upper,
                authority_expires_unix: authority_until,
            },
        )?;
        if consumed.iter().any(|old| {
            old.candidate_sha256 == verified.statement_sha256()
                || old.grant_id == checked.grant_id()
        }) {
            fail!(EACCES, "REPLACEMENT_CANDIDATE_CONSUMED");
        }
        let until = verified.expires_unix();
        let cutoff = checked
            .valid_before_utc_ms()
            .min(u64::try_from(until).unwrap_or(0).saturating_mul(1000));
        checked.check_at_boot(SystemClock::default().now_ns())?;
        if trusted.upper_utc_ms >= cutoff {
            fail!(ETIMEDOUT, "REPLACEMENT_PREPARING_DEADLINE");
        }
        // Candidate expiry may be earlier than code/grant/transport. Map that
        // FINAL independent cutoff from ORIGINAL request start, never return.
        let critical_deadline = start
            .checked_add(
                (cutoff - trusted.upper_utc_ms)
                    .checked_mul(1_000_000)
                    .ok_or_else(|| err!(EACCES, "REPLACEMENT_PREPARING_TIME"))?,
            )
            .ok_or_else(|| err!(EACCES, "REPLACEMENT_PREPARING_TIME"))?
            .min(checked.boot_deadline_ns());
        if SystemClock::default().now_ns() >= critical_deadline {
            fail!(ETIMEDOUT, "REPLACEMENT_PREPARING_DEADLINE");
        }
        let entry = ConsumedCandidate {
            candidate_sha256: verified.statement_sha256(),
            wire_sha256,
            binding_sha256: verified.binding_sha256(),
            history_sha256: verified.history_sha256(),
            attempt,
            previous_receipt_floor: ledger.receipt_floor,
            receipt_floor: replacement_receipt.generation,
            grant_id: checked.grant_id(),
            grant_generation: checked.grant_generation(),
            release_policy_revision: checked.release_policy_revision(),
            release_version: checked.release_version(),
        };
        let mut consumed = consumed;
        consumed.push(entry.clone());
        let record = MemberReplacementRecord {
            loss,
            consumed,
            current: PreparingCandidate {
                candidate: candidate_wire.to_vec(),
                enrollment_evidence_id: evidence_id,
                pending,
                replacement_receipt,
                survivor_receipt,
                submitted_survivor_receipt: submitted_survivor,
                binding,
                original_start_ns_hex: format!("{start:016x}"),
                boot_deadline_ns_hex: format!("{critical_deadline:016x}"),
                boot_epoch_sha256,
                verified_lower_unix: verified_lower,
                verified_upper_unix: verified_upper,
                authority_expires_unix: authority_until,
                release_policy_expires_utc_ms: checked.release_policy_expires_utc_ms(),
                grant_expires_utc_ms: checked.grant_expires_utc_ms(),
            },
            predecessor: observed.pin,
            anchor_revision: advance_safe(observed.pin.revision)?,
            accept_before_utc_ms: cutoff,
        };
        let next = Ledger {
            version: 4,
            attempt,
            policy_floor: ledger.policy_floor,
            receipt_floor: record.current.replacement_receipt.generation,
            phase: Phase::MembershipReplacementPreparing { record },
        };
        validate_v4(&next)?;
        preflight_size(&next, advance_safe(store.generation())?)?;
        let next_pin = successor(observed.pin, &next)?;
        let result = publication.publish_sterile_recovery(&mut store, &ledger, &next, || {
            if SystemClock::default().now_ns() >= critical_deadline {
                fail!(ETIMEDOUT, "REPLACEMENT_PREPARING_DEADLINE");
            }
            checked.check_at_boot(SystemClock::default().now_ns())?;
            owner.accept(&mut inner, observed.pin, next_pin, cutoff)
        });
        if result.is_err() {
            inner.faulted = true;
        }
        result?;
        checked.check_at_boot(SystemClock::default().now_ns())?;
        if SystemClock::default().now_ns() >= critical_deadline {
            fail!(ETIMEDOUT, "REPLACEMENT_PREPARING_DEADLINE");
        }
        let enrollment = runtime
            .evidence
            .remove(&evidence_id)
            .ok_or_else(|| err!(EACCES, "REPLACEMENT_ENROLLMENT_EVIDENCE_REQUIRED"))?;
        Ok((
            VaultResponse::MemberReplacementPrepared {
                candidate_sha256: entry.candidate_sha256,
                attempt,
                receipt_floor: entry.receipt_floor,
            },
            Some(Box::new(LivePreparedReplacement {
                checked,
                enrollment,
                accepted: next,
                context,
                state,
                generation,
                start,
                deadline: critical_deadline,
                until,
            })),
        ))
    }
}
