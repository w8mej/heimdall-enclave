//! Bounded same-workflow denial in an ALWAYS STERILE embedding API.
//! This is deliberately NOT wired into ordinary production entry. Deployment
//! must independently require this owner outside the restored tree before any
//! product-wide permanent-loss/anti-restore claim. Existing active readers and
//! writers have not yet adopted that protected required mode. No production
//! anchor, additional signer, USB factor or active replacement is supplied.
use super::*;
use crate::membership_retirement::{
    verify_retirement, InventoryRetirementPins, RetirementBinding, RetirementHistory,
    RetirementObservation,
};

#[path = "member_replacement_workflow.rs"]
mod member_replacement_workflow;
pub(super) use member_replacement_workflow::MemberReplacementRecord;
pub(in crate::service) use member_replacement_workflow::{
    ReplacementPreparingRuntime, ValidatedReplacementEnrollment,
};

const WORKFLOW_LIMIT: usize = 2 * 1024 * 1024;
const INTEGER_LIMIT: u64 = (1 << 53) - 1;
/// Independently provisioned exact whole-workflow head. Zero is never TOFU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipAnchorPin {
    /// Independently retained monotonic revision.
    pub revision: u64,
    /// Domain-separated canonical complete workflow commitment.
    pub workflow_sha256: [u8; 32],
}
/// Fresh authenticated response from the separately provisioned provider.
#[derive(Debug, Clone, Copy)]
pub struct MembershipAnchorObservation {
    /// Exact fixed protected scope.
    pub scope: [u8; 32],
    /// Exact independently authenticated provider identity.
    pub peer_sha256: [u8; 32],
    /// Fresh request challenge, authenticated in the provider response.
    pub nonce: [u8; 32],
    /// Independently retained current head.
    pub pin: MembershipAnchorPin,
    /// Conservative inclusive trusted lower bound.
    pub trusted_lower_utc_ms: u64,
    /// Conservative inclusive trusted upper bound, at most one second later.
    pub trusted_upper_utc_ms: u64,
}
/// Independently durable linearizable storage/time trust, NOT a recovery signer.
/// Implementations authenticate both peers, exact scope and fresh nonce, bound
/// request lifetime and survive local workflow/whole-directory restoration.
/// A local file, cached receipt or root-restorable journal is not a provider.
/// CAS MUST atomically refuse if actual trusted time is unknown or >= cutoff.
/// Errors can mean CAS applied; callers remain sterile and reconcile on reopen.
pub trait MembershipWorkflowAnchor: Send {
    /// Obtain a fresh authenticated exact-head/time observation.
    fn load(
        &mut self,
        scope: [u8; 32],
        peer_sha256: [u8; 32],
        nonce: [u8; 32],
    ) -> EnclaveResult<MembershipAnchorObservation>;
    /// Accept this exact one-step successor only before the absolute cutoff.
    fn compare_and_advance(
        &mut self,
        scope: [u8; 32],
        peer_sha256: [u8; 32],
        nonce: [u8; 32],
        expected: MembershipAnchorPin,
        next: MembershipAnchorPin,
        valid_before_utc_ms: u64,
    ) -> EnclaveResult<MembershipAnchorObservation>;
}
/// Protected embedding configuration. Provision independently of workflow
/// bytes; no RPC/CLI can choose the scope, provider, peer or existing issuer.
#[derive(Debug, Clone)]
pub struct MembershipAuthorityConfig {
    /// Fixed independently provisioned workflow scope; never learned locally.
    pub scope: [u8; 32],
    /// Independently pinned provider identity.
    pub peer_sha256: [u8; 32],
    /// EXISTING independent asset policy/inventory authority.
    pub asset_authority: AssetEnrollmentAuthority,
}
struct AuthorityInner {
    provider: Box<dyn MembershipWorkflowAnchor>,
    faulted: bool,
}
/// Cloneable opaque owner; all provider observations/publications share one
/// serial. It cannot create a guard, active credential or release permit.
#[derive(Clone)]
pub struct MembershipAuthorityOwner {
    config: MembershipAuthorityConfig,
    inner: Arc<Mutex<AuthorityInner>>,
}
impl std::fmt::Debug for MembershipAuthorityOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MembershipAuthorityOwner")
            .finish_non_exhaustive()
    }
}
fn hash(ledger: &Ledger) -> EnclaveResult<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(b"depot-MembershipWholeWorkflow-v1\0");
    h.update(enclave_core::jcs::to_jcs_bytes(ledger)?);
    Ok(h.finalize().into())
}
fn successor(pin: MembershipAnchorPin, next: &Ledger) -> EnclaveResult<MembershipAnchorPin> {
    Ok(MembershipAnchorPin {
        revision: pin
            .revision
            .checked_add(1)
            .filter(|n| *n <= INTEGER_LIMIT)
            .ok_or_else(|| err!(EACCES, "MEMBERSHIP_ANCHOR_EXHAUSTED"))?,
        workflow_sha256: hash(next)?,
    })
}
fn challenge() -> [u8; 32] {
    let mut n = [0; 32];
    enclave_core::rng::fill(&mut n);
    n
}
impl MembershipAuthorityOwner {
    /// Only protected embedding code may construct this owner. The provider's
    /// exact current pre-loss head MUST already be independently provisioned.
    pub fn new(
        config: MembershipAuthorityConfig,
        provider: Box<dyn MembershipWorkflowAnchor>,
    ) -> EnclaveResult<Self> {
        if config.scope == [0; 32] || config.peer_sha256 == [0; 32] {
            fail!(EACCES, "MEMBERSHIP_AUTHORITY_CONFIG");
        }
        InventoryRetirementPins::from_asset_authority(&config.asset_authority)?;
        Ok(Self {
            config,
            inner: Arc::new(Mutex::new(AuthorityInner {
                provider,
                faulted: false,
            })),
        })
    }
    fn validate_observation(
        &self,
        o: MembershipAnchorObservation,
        nonce: [u8; 32],
    ) -> EnclaveResult<MembershipAnchorObservation> {
        if o.scope != self.config.scope
            || o.peer_sha256 != self.config.peer_sha256
            || o.nonce != nonce
            || o.pin.revision == 0
            || o.pin.revision > INTEGER_LIMIT
            || o.pin.workflow_sha256 == [0; 32]
            || o.trusted_lower_utc_ms > o.trusted_upper_utc_ms
            || o.trusted_upper_utc_ms - o.trusted_lower_utc_ms > 1000
            || o.trusted_upper_utc_ms > INTEGER_LIMIT
        {
            fail!(EACCES, "MEMBERSHIP_ANCHOR_OBSERVATION");
        }
        Ok(o)
    }
    fn observe(&self, inner: &mut AuthorityInner) -> EnclaveResult<MembershipAnchorObservation> {
        if inner.faulted {
            fail!(EACCES, "MEMBERSHIP_AUTHORITY_UNCERTAIN");
        }
        let nonce = challenge();
        let result = inner
            .provider
            .load(self.config.scope, self.config.peer_sha256, nonce)
            .and_then(|o| self.validate_observation(o, nonce));
        if result.is_err() {
            inner.faulted = true;
        }
        result
    }
    fn accept(
        &self,
        inner: &mut AuthorityInner,
        expected: MembershipAnchorPin,
        next: MembershipAnchorPin,
        cutoff: u64,
    ) -> EnclaveResult<()> {
        if inner.faulted {
            fail!(EACCES, "MEMBERSHIP_AUTHORITY_UNCERTAIN");
        }
        if cutoff == 0 || cutoff > INTEGER_LIMIT {
            fail!(EACCES, "MEMBERSHIP_ANCHOR_CUTOFF");
        }
        let nonce = challenge();
        let result = inner
            .provider
            .compare_and_advance(
                self.config.scope,
                self.config.peer_sha256,
                nonce,
                expected,
                next,
                cutoff,
            )
            .and_then(|o| self.validate_observation(o, nonce))
            .and_then(|o| {
                if o.pin != next || o.trusted_upper_utc_ms >= cutoff {
                    fail!(EACCES, "MEMBERSHIP_ANCHOR_ACCEPTANCE");
                }
                Ok(())
            })
            .and_then(|()| {
                // Independent fresh exact-head readback, not a local CAS flag.
                let o = self.observe(inner)?;
                if o.pin != next || o.trusted_upper_utc_ms >= cutoff {
                    fail!(EACCES, "MEMBERSHIP_ANCHOR_READBACK");
                }
                Ok(())
            });
        if result.is_err() {
            inner.faulted = true;
        }
        result
    }
    fn times(o: &MembershipAnchorObservation) -> EnclaveResult<(i64, i64)> {
        let lower = i64::try_from(o.trusted_lower_utc_ms / 1000)
            .map_err(|_| err!(EACCES, "MEMBERSHIP_ANCHOR_TIME"))?;
        let upper = i64::try_from(o.trusted_upper_utc_ms.div_ceil(1000))
            .map_err(|_| err!(EACCES, "MEMBERSHIP_ANCHOR_TIME"))?;
        Ok((lower, upper))
    }
    /// Required exact-head startup/setup check before devices in this embedding.
    /// Only an exact saved one-step successor may reconcile, under its ORIGINAL
    /// absolute cutoff. Restored old v3 never initializes or overwrites a head.
    pub(in crate::service) fn check_startup(
        &self,
        state: &Path,
        profile: Profile,
    ) -> EnclaveResult<bool> {
        let _publication = membership_cutover::PublicationLease::acquire(state)?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| err!(EIO, "MEMBERSHIP_AUTHORITY_LOCK"))?;
        let (_, ledger) = open(state)?;
        let o = self.observe(&mut inner)?;
        if let Phase::MembershipReplacementPreparing { record } = &ledger.phase {
            return self.check_replacement_startup(state, &ledger, record, profile, &o, &mut inner);
        }
        if let Phase::MembershipLossRecorded { record } = &ledger.phase {
            self.validate_loss(state, &ledger, record, profile, &o)?;
            if o.pin.workflow_sha256 != hash(&ledger)? {
                if o.pin != record.predecessor {
                    fail!(EACCES, "MEMBERSHIP_ANCHOR_MISMATCH");
                }
                self.accept(
                    &mut inner,
                    o.pin,
                    successor(o.pin, &ledger)?,
                    record.accept_before_utc_ms,
                )?;
            } else if o.pin.revision != record.anchor_revision {
                fail!(EACCES, "MEMBERSHIP_ANCHOR_MISMATCH");
            }
            return Ok(true);
        }
        if o.pin.workflow_sha256 != hash(&ledger)? {
            fail!(EACCES, "MEMBERSHIP_ANCHOR_MISMATCH");
        }
        // A current v1-v3 source stays sterile. No live receipt freshness or
        // lost-device handle is required merely to reach the denial API.
        if ledger.version == 3 {
            membership_cutover::validate_v3_pins(state, &ledger)?;
        }
        Ok(false)
    }
    fn validate_loss(
        &self,
        state: &Path,
        ledger: &Ledger,
        r: &MemberLossRecord,
        profile: Profile,
        o: &MembershipAnchorObservation,
    ) -> EnclaveResult<membership_cutover::MemberLossContext> {
        validate_v4(ledger)?;
        let (lower, upper) = Self::times(o)?;
        let context = membership_cutover::member_loss_context(
            state,
            &r.origin_ledger(),
            &self.config.asset_authority,
            profile,
            lower,
            upper,
        )?;
        if context.bindings[r.target_index] != r.binding {
            fail!(EACCES, "MEMBER_LOSS_BINDING");
        }
        let pins = InventoryRetirementPins::from_asset_authority(&self.config.asset_authority)?;
        r.history.validate(&pins)?;
        let verified = verify_retirement(
            &r.statement,
            &pins,
            &r.binding,
            &RetirementHistory::empty(&pins),
            RetirementObservation {
                lower_unix: r.verified_lower_unix,
                upper_unix: r.verified_upper_unix,
                authority_expires_unix: r.authority_expires_unix,
            },
        )?;
        if verified.statement_sha256() != r.statement_sha256
            || r.accept_before_utc_ms
                > u64::try_from(verified.expires_unix())
                    .unwrap_or(0)
                    .saturating_mul(1000)
        {
            fail!(EACCES, "MEMBER_LOSS_STATEMENT");
        }
        let mut expected = RetirementHistory::empty(&pins);
        expected.append(&pins, verified)?;
        if expected.commitment(&pins)? != r.history.commitment(&pins)? {
            fail!(EACCES, "MEMBER_LOSS_HISTORY");
        }
        Ok(context)
    }
    fn accepted_loss_context(
        &self,
        state: &Path,
        ledger: &Ledger,
        r: &MemberLossRecord,
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
        self.validate_loss(state, ledger, r, profile, o)
    }
    /// Authenticate sterile surviving identity and original encrypted selector.
    /// No active guard, factor proof, tier key or release capability is returned.
    pub fn load_member_loss_setup(
        &self,
        state: &Path,
        profile: Profile,
    ) -> EnclaveResult<Option<ValidatedMemberLossSetup>> {
        self.check_startup(state, profile)?;
        let _publication = membership_cutover::PublicationLease::acquire(state)?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| err!(EIO, "MEMBERSHIP_AUTHORITY_LOCK"))?;
        let (_, ledger) = open(state)?;
        let o = self.observe(&mut inner)?;
        if o.pin.workflow_sha256 != hash(&ledger)? {
            fail!(EACCES, "MEMBERSHIP_ANCHOR_MISMATCH");
        }
        let record = match &ledger.phase {
            Phase::MembershipLossRecorded { record } => record,
            Phase::MembershipReplacementPreparing { record } => {
                return self
                    .replacement_survivor_setup(state, &ledger, record, profile, &o)
                    .map(Some)
            }
            _ => return Ok(None),
        };
        let context = self.accepted_loss_context(state, &ledger, record, profile, &o)?;
        Ok(Some(ValidatedMemberLossSetup {
            enrolled: context.members[1 - record.target_index].clone(),
            survivor: if record.target_index == 1 {
                MemberLossSurvivor::OriginalPrimary
            } else {
                MemberLossSurvivor::Alternate
            },
            source_binding: record.binding.source_v2_binding,
            checkpoint: context.checkpoint,
            alternate: context.alternate,
            statement_sha256: record.statement_sha256,
            loss_generation: ledger.attempt,
        }))
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MemberLossRecord {
    // FLAT immutable v3 origin once. No recursive v4 record embedding.
    origin: membership_cutover::CommittedMembership,
    origin_attempt: u64,
    origin_policy_floor: u64,
    origin_receipt_floor: u64,
    binding: RetirementBinding,
    target_index: usize,
    history: RetirementHistory,
    #[serde(with = "serde_bytes")]
    statement: Vec<u8>,
    statement_sha256: [u8; 32],
    loss_generation: u64,
    predecessor: MembershipAnchorPin,
    anchor_revision: u64,
    accept_before_utc_ms: u64,
    verified_lower_unix: i64,
    verified_upper_unix: i64,
    authority_expires_unix: i64,
}
impl MemberLossRecord {
    fn origin_ledger(&self) -> Ledger {
        Ledger {
            version: 3,
            attempt: self.origin_attempt,
            policy_floor: self.origin_policy_floor,
            receipt_floor: self.origin_receipt_floor,
            phase: Phase::MembershipCommitted {
                record: self.origin.clone(),
            },
        }
    }
}
pub(super) fn validate_v4(ledger: &Ledger) -> EnclaveResult<()> {
    if let Phase::MembershipReplacementPreparing { record } = &ledger.phase {
        return member_replacement_workflow::validate_preparing_shape(ledger, record);
    }
    let Phase::MembershipLossRecorded {record:r}=&ledger.phase else {fail!(EACCES,"MEMBER_LOSS_STATE");};
    membership_cutover::validate_v3(&r.origin_ledger())?;
    if ledger.version != 4
        || r.target_index > 1
        || r.statement.is_empty()
        || r.statement.len() > 64 * 1024
        || ledger.attempt != r.loss_generation
        || r.origin_attempt.checked_add(1) != Some(r.loss_generation)
        || r.loss_generation > INTEGER_LIMIT
        || ledger.policy_floor != r.origin_policy_floor
        || ledger.receipt_floor != r.origin_receipt_floor
        || r.predecessor.revision == 0
        || r.predecessor.revision.checked_add(1) != Some(r.anchor_revision)
        || r.anchor_revision > INTEGER_LIMIT
        || r.predecessor.workflow_sha256 != hash(&r.origin_ledger())?
        || r.accept_before_utc_ms == 0
        || r.accept_before_utc_ms > INTEGER_LIMIT
        || r.statement_sha256 == [0; 32]
    {
        fail!(EACCES, "MEMBER_LOSS_STATE");
    }
    preflight_size(ledger, u64::MAX)
}
fn preflight_size(ledger: &Ledger, generation: u64) -> EnclaveResult<()> {
    // Match the escaped UTF-8 sealed outer envelope, including next generation
    // and the fixed 64-character MAC. A body-only history bound is insufficient.
    let body = serde_json::to_string(ledger).map_err(|_| err!(EIO, "MEMBER_LOSS_ENCODE"))?;
    let outer = serde_json::json!({"v":1,"domain":"workflow","generation":generation,"mac":"0".repeat(64),"body":body});
    if serde_json::to_vec(&outer)
        .map_err(|_| err!(EIO, "MEMBER_LOSS_ENCODE"))?
        .len()
        > WORKFLOW_LIMIT
    {
        fail!(E2BIG, "MEMBER_LOSS_SIZE");
    }
    Ok(())
}
/// Exact immutable wrapper origin of the surviving member, never display slot0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberLossSurvivor {
    /// Original primary wrappers.
    OriginalPrimary,
    /// Original alternate encrypted wrappers.
    Alternate,
}
/// Sterile survivor setup only. Cannot construct an active membership guard.
pub struct ValidatedMemberLossSetup {
    enrolled: EnrolledCustodyState,
    survivor: MemberLossSurvivor,
    source_binding: [u8; 32],
    checkpoint: crate::vault::VaultEnvelopeCheckpoint,
    alternate: crate::backup_envelope::StagedBackupEnvelopes,
    statement_sha256: [u8; 32],
    loss_generation: u64,
}
impl std::fmt::Debug for ValidatedMemberLossSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatedMemberLossSetup")
            .field("survivor", &self.survivor)
            .finish_non_exhaustive()
    }
}
impl ValidatedMemberLossSetup {
    /// Actual surviving identity/protected biometric binding for NEW factors.
    pub fn enrolled(&self) -> EnrolledCustodyState {
        self.enrolled.clone()
    }
    /// Immutable wrapper origin; no relabeling an alternate as original primary.
    pub fn survivor(&self) -> MemberLossSurvivor {
        self.survivor
    }
    /// Original v2 wrapper binding.
    pub fn source_binding(&self) -> [u8; 32] {
        self.source_binding
    }
    /// Exact retained encrypted content; no factors or keys.
    pub fn checkpoint(&self) -> &crate::vault::VaultEnvelopeCheckpoint {
        &self.checkpoint
    }
    /// Original alternate encrypted wrappers only when that member survives.
    pub fn alternate_wrappers(&self) -> Option<&crate::backup_envelope::StagedBackupEnvelopes> {
        (self.survivor == MemberLossSurvivor::Alternate).then_some(&self.alternate)
    }
    fn response(&self) -> EnclaveResult<VaultResponse> {
        Ok(VaultResponse::MemberLossRecorded {
            statement_sha256: self.statement_sha256,
            loss_generation: self.loss_generation,
            survivor_enrolled_sha256: Sha256::digest(enclave_core::jcs::to_jcs_bytes(
                &self.enrolled.credential,
            )?)
            .into(),
        })
    }
}
impl State {
    pub(in crate::service) fn require_membership_active(&self) -> EnclaveResult<()> {
        if self.membership_sterile || self.loss_attempted {
            fail!(EACCES, "MEMBERSHIP_RECOVERY_STERILE");
        }
        Ok(())
    }
    pub(in crate::service) fn check_member_loss_request(
        &self,
        request: &VaultRequest,
    ) -> EnclaveResult<()> {
        if self.require_membership_active().is_ok()
            || matches!(
                request,
                VaultRequest::Status
                    | VaultRequest::BootEpoch
                    | VaultRequest::Tamper(_)
                    | VaultRequest::RecordMemberLoss { .. }
                    | VaultRequest::PrepareMemberReplacement { .. }
            )
        {
            return Ok(());
        }
        fail!(EACCES, "MEMBERSHIP_RECOVERY_STERILE")
    }
}
impl VaultService {
    /// Denial-only embedding with ALREADY supplied hardware; checks precede
    /// internal hardware use only. Prefer the factory entry before discovery.
    /// No ordinary production entry wiring:
    /// required protected deployment mode and active owner adaptation stay OPEN.
    pub fn start_with_membership_authority(
        cfg: VaultConfig,
        hw: VaultHardware,
        owner: MembershipAuthorityOwner,
    ) -> EnclaveResult<Arc<Self>> {
        Self::start_inner(cfg, hw, None, Some(owner))
    }
    /// Preferred protected embedding entry: require fresh exact-head agreement
    /// BEFORE invoking the hardware factory/discovery at all. The second check
    /// in start_inner also catches a head change while that factory executes.
    /// No ordinary production entry is wired to this always-sterile API.
    pub fn start_with_membership_authority_factory(
        cfg: VaultConfig,
        owner: MembershipAuthorityOwner,
        hardware: impl FnOnce() -> EnclaveResult<VaultHardware>,
    ) -> EnclaveResult<Arc<Self>> {
        if cfg.profile == Profile::L1 {
            fail!(EACCES, "MEMBERSHIP_RECOVERY_STARTUP_PROFILE");
        }
        owner.check_startup(
            cfg.state_dir
                .as_deref()
                .ok_or_else(|| err!(EACCES, "ENROLLMENT_STATE_REQUIRED"))?,
            cfg.profile,
        )?;
        let hw = hardware()?;
        Self::start_inner(cfg, hw, None, Some(owner))
    }
    pub(in crate::service) fn record_member_loss(
        &self,
        peer: &PeerCredentials,
        statement: &[u8],
        start: u64,
    ) -> EnclaveResult<VaultResponse> {
        Self::asset_admin(peer)?;
        if statement.is_empty() || statement.len() > 64 * 1024 {
            fail!(E2BIG, "MEMBER_LOSS_STATEMENT_SIZE");
        }
        let owner = self
            .membership_authority
            .as_ref()
            .ok_or_else(|| err!(EACCES, "MEMBERSHIP_RECOVERY_PROVIDER_REQUIRED"))?;
        let cap = start
            .checked_add(crate::ceremony::CEREMONY_BUDGET_NS)
            .ok_or_else(|| err!(ETIMEDOUT, "MEMBER_LOSS_DEADLINE"))?;
        let mut c = self.lock_ceremony()?;
        let (state, profile) = {
            let mut st = self.lock_state()?;
            // Latch under ceremony -> State BEFORE revocation/persistence.
            st.loss_attempted = true;
            st.membership_sterile = true;
            (
                st.state_dir
                    .clone()
                    .ok_or_else(|| err!(EACCES, "ENROLLMENT_STATE_REQUIRED"))?,
                st.profile,
            )
        };
        let generation = self.revoke_cas_keys_with_generation()?;
        c.setup_only = true;
        c.hw.active_asset_guard = None;
        {
            let mut st = self.lock_state()?;
            st.envelope_fault = true;
            st.active_asset_guard = None;
            st.travel = None;
            st.cas_key_leases.clear();
            st.cas_key_deadlines.clear();
            st.namespace_challenges.clear();
            st.lifecycle = CustodyLifecycle::boot(st.profile);
        }
        let publication = membership_cutover::PublicationLease::acquire(&state)?;
        let mut inner = owner
            .inner
            .lock()
            .map_err(|_| err!(EIO, "MEMBERSHIP_AUTHORITY_LOCK"))?;
        let (mut store, ledger) = open(&state)?;
        let o = owner.observe(&mut inner)?;
        if o.pin.workflow_sha256 != hash(&ledger)? {
            fail!(EACCES, "MEMBERSHIP_ANCHOR_MISMATCH");
        }
        if let Phase::MembershipLossRecorded { record } = &ledger.phase {
            let context = owner.accepted_loss_context(&state, &ledger, record, profile, &o)?;
            if statement != record.statement {
                fail!(EACCES, "MEMBER_LOSS_ALREADY_RECORDED");
            }
            if SystemClock::default().now_ns() >= cap {
                fail!(ETIMEDOUT, "MEMBER_LOSS_DEADLINE");
            }
            self.attach_setup_release(generation, cap, context.policy_expires_unix)?;
            return ValidatedMemberLossSetup {
                enrolled: context.members[1 - record.target_index].clone(),
                survivor: if record.target_index == 1 {
                    MemberLossSurvivor::OriginalPrimary
                } else {
                    MemberLossSurvivor::Alternate
                },
                source_binding: record.binding.source_v2_binding,
                checkpoint: context.checkpoint,
                alternate: context.alternate,
                statement_sha256: record.statement_sha256,
                loss_generation: ledger.attempt,
            }
            .response();
        }
        let (lower, upper) = MembershipAuthorityOwner::times(&o)?;
        let context = membership_cutover::member_loss_context(
            &state,
            &ledger,
            &owner.config.asset_authority,
            profile,
            lower,
            upper,
        )?;
        let pins = InventoryRetirementPins::from_asset_authority(&owner.config.asset_authority)?;
        let mut history = RetirementHistory::empty(&pins);
        let observation = RetirementObservation {
            lower_unix: lower,
            upper_unix: upper,
            authority_expires_unix: context.policy_expires_unix,
        };
        // Trusted pair defines both alternatives; untrusted target/index never
        // selects authority. Only an exact independently signed binding wins.
        let verified0 = verify_retirement(
            statement,
            &pins,
            &context.bindings[0],
            &history,
            observation,
        );
        let (target_index, verified) = match verified0 {
            Ok(v) => (0, v),
            Err(_) => (
                1,
                verify_retirement(
                    statement,
                    &pins,
                    &context.bindings[1],
                    &history,
                    observation,
                )?,
            ),
        };
        let until = verified.expires_unix();
        let statement_sha256 = verified.statement_sha256();
        history.append(&pins, verified)?;
        let Phase::MembershipCommitted {record:origin}=&ledger.phase else {fail!(EACCES,"MEMBER_LOSS_COMMITTED_REQUIRED");};
        let now = SystemClock::default().now_ns();
        if now < start || now >= cap {
            fail!(ETIMEDOUT, "MEMBER_LOSS_DEADLINE");
        }
        let remaining_ms = (cap - now) / 1_000_000;
        // Conservative independent-time cap covers the ORIGINAL request window,
        // and remains immutable on a later restart/repair.
        let accept_before_utc_ms = u64::try_from(until)
            .map_err(|_| err!(EACCES, "MEMBER_LOSS_TIME"))?
            .checked_mul(1000)
            .ok_or_else(|| err!(EACCES, "MEMBER_LOSS_TIME"))?
            .min(o.trusted_lower_utc_ms.saturating_add(remaining_ms));
        let loss_generation = ledger
            .attempt
            .checked_add(1)
            .filter(|n| *n <= INTEGER_LIMIT)
            .ok_or_else(|| err!(EACCES, "MEMBER_LOSS_EXHAUSTED"))?;
        let record = MemberLossRecord {
            origin: origin.clone(),
            origin_attempt: ledger.attempt,
            origin_policy_floor: ledger.policy_floor,
            origin_receipt_floor: ledger.receipt_floor,
            binding: context.bindings[target_index].clone(),
            target_index,
            history,
            statement: statement.to_vec(),
            statement_sha256,
            loss_generation,
            predecessor: o.pin,
            anchor_revision: o
                .pin
                .revision
                .checked_add(1)
                .ok_or_else(|| err!(EACCES, "MEMBERSHIP_ANCHOR_EXHAUSTED"))?,
            accept_before_utc_ms,
            verified_lower_unix: lower,
            verified_upper_unix: upper,
            authority_expires_unix: context.policy_expires_unix,
        };
        let next = Ledger {
            version: 4,
            attempt: loss_generation,
            policy_floor: ledger.policy_floor,
            receipt_floor: ledger.receipt_floor,
            phase: Phase::MembershipLossRecorded { record },
        };
        validate_v4(&next)?;
        preflight_size(
            &next,
            store
                .generation()
                .checked_add(1)
                .ok_or_else(|| err!(EACCES, "STATE_GENERATION"))?,
        )?;
        let next_pin = successor(o.pin, &next)?;
        let result = publication.publish_sterile_recovery(&mut store, &ledger, &next, || {
            if SystemClock::default().now_ns() >= cap {
                fail!(ETIMEDOUT, "MEMBER_LOSS_DEADLINE");
            }
            owner.accept(&mut inner, o.pin, next_pin, accept_before_utc_ms)
        });
        if result.is_err() {
            inner.faulted = true;
        }
        result?;
        // Same original deadline, exact provider and file readback precede ACK.
        if SystemClock::default().now_ns() >= cap {
            fail!(ETIMEDOUT, "MEMBER_LOSS_DEADLINE");
        }
        self.attach_setup_release(generation, cap, until)?;
        Ok(VaultResponse::MemberLossRecorded {
            statement_sha256,
            loss_generation,
            survivor_enrolled_sha256: Sha256::digest(enclave_core::jcs::to_jcs_bytes(
                &context.members[1 - target_index].credential,
            )?)
            .into(),
        })
    }
}
