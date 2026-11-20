//! Authoritative v3 membership admission, genuine dual-member proof and atomic
//! complete-checkpoint adoption. The SAME ledger owns floors and activation.
use super::*;
use crate::asset_membership::MemberEvidence;
use crate::ctap::assertion::{CredentialKey, SignCountStore};
use enclave_crypto::hpke_envelope::VerifiedEnvelopeContext;

#[path = "checkpoint_retirement.rs"]
mod checkpoint_retirement;
pub(super) use checkpoint_retirement::PublicationLease;

/// Keep legacy authority writers under the SAME nonblocking publisher lease.
/// The opaque owner has no publication or admission API; drop releases it.
pub(super) fn publication_lease(state: &Path) -> EnclaveResult<impl std::fmt::Debug> {
    PublicationLease::acquire(state)
}
#[cfg(test)]
pub(super) fn obstruct_next_publication_save(path: std::path::PathBuf) -> impl std::fmt::Debug {
    checkpoint_retirement::obstruct_next_save(path)
}

const CONTENT_LIMIT: usize = 32 * 1024 * 1024;
const COMPLETE_LIMIT: usize = 64 * 1024 * 1024;
const INTEGER_LIMIT: u64 = 1 << 53;
fn is_false(value: &bool) -> bool {
    !*value
}

fn digest(domain: &[u8], value: &impl Serialize) -> EnclaveResult<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(enclave_core::jcs::to_jcs_bytes(value)?);
    Ok(hash.finalize().into())
}
fn advance(value: u64) -> EnclaveResult<u64> {
    value
        .checked_add(1)
        .filter(|next| *next <= INTEGER_LIMIT)
        .ok_or_else(|| err!(EACCES, "ASSET_MEMBERSHIP_EXHAUSTED"))
}
fn distinct(primary: &EnrolledCredential, backup: &EnrolledCredential) -> EnclaveResult<()> {
    let normalized = |credential: &EnrolledCredential| {
        let mut bytes = (credential.key.alg() as i32).to_be_bytes().to_vec();
        bytes.extend(match &credential.key {
            CredentialKey::Ed25519(key) => key.to_edwards().compress().to_bytes().to_vec(),
            CredentialKey::Es256(_) => credential.key.to_raw(),
        });
        bytes
    };
    if primary.credential_id.is_empty()
        || backup.credential_id.is_empty()
        || primary.credential_id.len() > 1023
        || backup.credential_id.len() > 1023
        || primary.credential_id == backup.credential_id
        || normalized(primary) == normalized(backup)
    {
        fail!(EACCES, "ASSET_MEMBERSHIP_DISTINCT_REQUIRED");
    }
    Ok(())
}

/// Retained exact old authority. Never reinterpreted as active after v3 burn.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceAuthority {
    version: u32,
    attempt: u64,
    policy_floor: u64,
    receipt_floor: u64,
    pending: Pending,
    receipt: AssetEnrollmentReceipt,
    vault_binding: [u8; 32],
}
/// Complete public pins plus protected original biometric blob in the sealed
/// authoritative ledger. A plan or a signed inventory receipt is not a factor.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreparingMembership {
    source: SourceAuthority,
    backup: MemberEvidence,
    // Empty/false preserve the exact first sterile-only plan encoding. Such a
    // historical plan can never enter the live producer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    backup_bio_blob: Vec<u8>,
    #[serde(default, skip_serializing_if = "is_false")]
    counter_baseline: bool,
    profile: Profile,
    minimum_members: u8,
    host: String,
    asset: String,
    custodian: String,
    policy_issuer: [u8; 32],
    inventory_issuer: [u8; 32],
    policy_revision: u64,
    policy_digest: [u8; 32],
    attempt: u64,
    generation: u64,
    pool_digest: [u8; 32],
    content_sha256: [u8; 32],
    counter_sha256: [u8; 32],
    primary_counter_floor: u32,
    backup_counter_floor: u32,
    start_ns: u64,
    start_unix: i64,
    deadline_ns: u64,
    valid_until_unix: i64,
}
impl PreparingMembership {
    fn digest(&self) -> EnclaveResult<[u8; 32]> {
        digest(b"depot-AuthoritativeMembershipPreparing-v3\0", self)
    }
    fn check_time(&self, clock: &dyn Clock) -> EnclaveResult<()> {
        let boot = clock.now_ns();
        let wall = clock.now_unix();
        if boot < self.start_ns
            || boot >= self.deadline_ns
            || wall < self.start_unix
            || wall >= self.valid_until_unix
        {
            fail!(ETIMEDOUT, "ASSET_MEMBERSHIP_DEADLINE");
        }
        Ok(())
    }
}

/// Move-only live preparation, with no authorization/activation API. Restart
/// cannot reconstruct it from the sealed plan. A future proof producer must
/// consume this value rather than accepting a caller's digest or success flag.
pub(super) struct MembershipPreparation {
    preparation: PreparingMembership,
    plan_sha256: [u8; 32],
}
impl std::fmt::Debug for MembershipPreparation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MembershipPreparation")
            .field("attempt", &self.preparation.attempt)
            .finish_non_exhaustive()
    }
}

pub(super) fn validate_preparing(ledger: &Ledger) -> EnclaveResult<()> {
    if serde_json::to_vec(ledger)
        .map_err(|_| err!(EIO, "ASSET_MEMBERSHIP_ENCODE"))?
        .len()
        > 2 * 1024 * 1024
    {
        fail!(E2BIG, "ASSET_MEMBERSHIP_SIZE");
    }
    let Phase::MembershipPreparing {preparation:p,plan_sha256}=&ledger.phase else {fail!(EACCES,"ASSET_MEMBERSHIP_STATE");};
    if ledger.version != 3
        || p.minimum_members != 2
        || p.profile == Profile::L1
        || p.backup_bio_blob.len() > 64 * 1024
        || p.counter_baseline == p.backup_bio_blob.is_empty()
        || !(1..=2).contains(&p.source.version)
        || p.source.pending.profile != p.profile
        || p.source.pending.bio_public_key != p.source.pending.evidence.sep_public_key
        || p.source.pending.bio_key_blob.is_empty()
        || p.source.receipt.generation != p.source.receipt_floor
        || p.source.receipt.pending_sha256 != p.source.pending.evidence.digest()?
        || p.backup.receipt.pending_sha256 != p.backup.pending.digest()?
        || p.attempt != ledger.attempt
        || p.attempt <= p.source.attempt
        || p.attempt > INTEGER_LIMIT
        || p.policy_revision != ledger.policy_floor
        || p.policy_revision < p.source.policy_floor
        || ledger.receipt_floor != p.backup.receipt.generation
        || ledger.receipt_floor <= p.source.receipt_floor
        || ledger.receipt_floor > INTEGER_LIMIT
        || p.generation == u64::MAX
        || p.start_unix < 0
        || p.valid_until_unix <= p.start_unix
        || p.deadline_ns <= p.start_ns
        || p.deadline_ns - p.start_ns > crate::ceremony::CEREMONY_BUDGET_NS
        || p.valid_until_unix > p.source.receipt.expires_unix
        || p.valid_until_unix > p.backup.receipt.expires_unix
        || p.digest()? != *plan_sha256
    {
        fail!(EACCES, "ASSET_MEMBERSHIP_STATE");
    }
    distinct(
        p.source.pending.evidence.credential(),
        p.backup.pending.credential(),
    )?;
    Ok(())
}
fn content_store(state: &Path) -> EnclaveResult<(SealedStore, Loaded)> {
    SealedStore::open_bounded_required(&state.join("membership-cutover"), "content", CONTENT_LIMIT)
}
fn counter_baseline_store(state: &Path, hash: &[u8; 32]) -> EnclaveResult<(SealedStore, Loaded)> {
    // Immutable, content-addressed snapshot: staging a later attempt cannot
    // overwrite the counter baseline still referenced by the old ledger.
    SealedStore::open_bounded_required(
        &state
            .join("membership-cutover-counters")
            .join(hex::encode(hash)),
        "counters",
        CONTENT_LIMIT,
    )
}
pub(super) fn validate_saved_pins(state: &Path, ledger: &Ledger) -> EnclaveResult<()> {
    validate_preparing(ledger)?;
    let Phase::MembershipPreparing {preparation:p,..}=&ledger.phase else {unreachable!()};
    let (_, loaded) = content_store(state)?;
    let Loaded::State(bytes)=loaded else {fail!(EACCES,"ASSET_MEMBERSHIP_CONTENT_REQUIRED");};
    let checkpoint: crate::vault::VaultEnvelopeCheckpoint = enclave_core::sealed::decode(&bytes)?;
    if digest(b"depot-MembershipContent-v3\0", &checkpoint)? != p.content_sha256
        || binding(&checkpoint)? != p.source.vault_binding
    {
        fail!(EACCES, "ASSET_MEMBERSHIP_CONTENT_PIN");
    }
    let (_, loaded) = SealedStore::open_bounded_required(state, "signcount", CONTENT_LIMIT)?;
    let Loaded::State(bytes)=loaded else {fail!(EACCES,"SIGN_COUNT_STATE");};
    let counters: SignCountStore = enclave_core::sealed::decode(&bytes)?;
    let original = if p.counter_baseline {
        let (_, loaded) = counter_baseline_store(state, &p.counter_sha256)?;
        let Loaded::State(bytes)=loaded else {fail!(EACCES,"ASSET_MEMBERSHIP_COUNTER_PIN");};
        enclave_core::sealed::decode::<SignCountStore>(&bytes)?
    } else {
        counters.clone()
    };
    if digest(b"depot-MembershipCounters-v3\0", &original)? != p.counter_sha256
        || !counters.dominates(&original)
        || counters.get_credential(p.source.pending.evidence.credential()) < p.primary_counter_floor
        || counters.get_credential(p.backup.pending.credential()) < p.backup_counter_floor
    {
        fail!(EACCES, "ASSET_MEMBERSHIP_COUNTER_PIN");
    }
    Ok(())
}

impl VaultService {
    /// Consume new authoritative floors and stop old authority. This performs
    /// no UI, CTAP, wrapper creation, membership activation or socket release.
    /// The absent dual-device proof producer deliberately has no commit seam.
    pub(super) fn prepare_membership_cutover(
        &self,
        peer: &PeerCredentials,
        backup: MemberEvidence,
    ) -> EnclaveResult<MembershipPreparation> {
        self.prepare_membership_cutover_inner(peer, backup, Vec::new(), None)
    }
    /// Bind the backup's protected biometric blob before any live factor work.
    /// Its bytes are not authority: the producer verifies an actual fresh D2
    /// signature under the separately inventory-admitted pending SEP key.
    pub(super) fn prepare_membership_cutover_with_biometric(
        &self,
        peer: &PeerCredentials,
        backup: MemberEvidence,
        backup_bio_blob: Vec<u8>,
    ) -> EnclaveResult<MembershipPreparation> {
        if backup_bio_blob.is_empty() || backup_bio_blob.len() > 64 * 1024 {
            fail!(EACCES, "ASSET_BIOMETRIC_KEY");
        }
        self.prepare_membership_cutover_inner(peer, backup, backup_bio_blob, None)
    }
    fn prepare_membership_cutover_inner(
        &self,
        peer: &PeerCredentials,
        backup: MemberEvidence,
        backup_bio_blob: Vec<u8>,
        origin: Option<(u64, i64)>,
    ) -> EnclaveResult<MembershipPreparation> {
        if backup_bio_blob.len() > 64 * 1024 {
            fail!(EACCES, "ASSET_BIOMETRIC_KEY");
        }
        Self::asset_admin(peer)?;
        let mut ceremony = self.lock_sensitive_ceremony()?;
        let c = &mut *ceremony;
        // The original complete window includes authority I/O and persistence.
        let (start_ns, start_unix) =
            origin.unwrap_or_else(|| (c.clock.now_ns(), c.clock.now_unix()));
        let cap = start_ns
            .checked_add(crate::ceremony::CEREMONY_BUDGET_NS)
            .ok_or_else(|| err!(ETIMEDOUT, "ASSET_MEMBERSHIP_DEADLINE"))?;
        let (state, profile) = {
            let st = self.lock_sensitive_state()?;
            (
                st.state_dir
                    .clone()
                    .ok_or_else(|| err!(EACCES, "ENROLLMENT_STATE_REQUIRED"))?,
                st.profile,
            )
        };
        if profile == Profile::L1 {
            fail!(EPERM, "ENROLL_NOT_APPLICABLE_L1");
        }
        let authority =
            c.hw.asset_enrollment_authority
                .clone()
                .ok_or_else(|| err!(EACCES, "ASSET_AUTHORITY_REQUIRED"))?;
        if !backup_bio_blob.is_empty() {
            let simulated = c.hw.simulated;
            let devices =
                c.hw.membership_devices
                    .as_mut()
                    .ok_or_else(|| err!(EACCES, "MEMBERSHIP_NATIVE_PAIR_REQUIRED"))?;
            devices.require_current(simulated)?;
            devices.require_topology(profile)?;
            if c.hw.oidc_provider.is_none() {
                fail!(EACCES, "MEMBERSHIP_A4_AUTHORITY_REQUIRED");
            }
            if profile == Profile::L3 && c.hw.egress.is_none() {
                fail!(EACCES, "ZK_EGRESS_GATE_UNAVAILABLE");
            }
        }
        let _publication = PublicationLease::acquire(&state)?;
        let (mut ledger_store, ledger) = open(&state)?;
        let source = match &ledger.phase {
            Phase::Active {
                pending,
                receipt,
                vault_binding,
            } => SourceAuthority {
                version: ledger.version,
                attempt: ledger.attempt,
                policy_floor: ledger.policy_floor,
                receipt_floor: ledger.receipt_floor,
                pending: pending.clone(),
                receipt: receipt.clone(),
                vault_binding: *vault_binding,
            },
            Phase::MembershipPreparing { preparation, .. } => {
                validate_saved_pins(&state, &ledger)?;
                preparation.source.clone()
            }
            _ => {
                fail!(EACCES, "ASSET_ACTIVE_REQUIRED");
            }
        };
        if source.pending.profile != profile
            || source.pending.bio_public_key != source.pending.evidence.sep_public_key
            || source.pending.bio_key_blob.is_empty()
            || source.receipt.generation != source.receipt_floor
        {
            fail!(EACCES, "ASSET_LEDGER_BINDING");
        }
        let bytes = read_asset_authority_file(&authority.policy_file, 16 * 1024)?;
        let signed: SignedAssetEnrollmentPolicy =
            serde_json::from_slice(&bytes).map_err(|_| err!(EACCES, "ASSET_POLICY_DECODE"))?;
        let policy = signed.verify(
            &authority.policy_issuer,
            &authority.host,
            &authority.asset,
            &authority.custodian,
            ledger.policy_floor,
            c.clock.now_unix(),
        )?;
        let primary = source.receipt.clone().activate(
            source.pending.evidence.clone(),
            &policy,
            &authority.inventory_issuer,
            source.receipt_floor,
            c.clock.now_unix(),
        )?;
        let target = backup.receipt.clone().activate(
            backup.pending.clone(),
            &policy,
            &authority.inventory_issuer,
            advance(ledger.receipt_floor)?,
            c.clock.now_unix(),
        )?;
        distinct(&primary, &target)?;
        let current =
            c.hw.credential
                .as_ref()
                .ok_or_else(|| err!(EACCES, "ASSET_ACTIVE_BINDING"))?;
        if enclave_core::jcs::to_jcs_bytes(current)? != enclave_core::jcs::to_jcs_bytes(&primary)? {
            fail!(EACCES, "ASSET_ACTIVE_BINDING");
        }
        let envelope_authority =
            c.hw.envelope_authority
                .clone()
                .ok_or_else(|| err!(EACCES, "ENVELOPE_POLICY_AUTHORITY_REQUIRED"))?;
        let metadata_source =
            c.hw.metadata_source
                .clone()
                .ok_or_else(|| err!(EACCES, "ENVELOPE_POLICY_SOURCE_REQUIRED"))?;
        let context: VerifiedEnvelopeContext =
            metadata_source.envelope_context(&envelope_authority, profile, c.clock.now_unix())?;
        if let Phase::MembershipPreparing { preparation, .. } = &ledger.phase {
            if preparation.host != authority.host
                || preparation.asset != authority.asset
                || preparation.custodian != authority.custodian
                || preparation.policy_issuer != authority.policy_issuer.to_bytes()
                || preparation.inventory_issuer != authority.inventory_issuer.to_bytes()
                || preparation.policy_digest != policy.digest()
            {
                fail!(EACCES, "ASSET_MEMBERSHIP_SOURCE_CHANGED");
            }
        }
        // Never wait for the release serial while holding State. Earlier socket
        // handoffs stand; all later old-generation handoffs are now fenced.
        self.revoke_cas_keys()?;
        let generation = self
            .cas_key_generation
            .load(std::sync::atomic::Ordering::SeqCst);
        c.enter_generation(generation);
        c.setup_only = true;
        let mut st = self.lock_sensitive_state()?;
        // Latch before any potentially uncertain persistence. Neither an error
        // nor a same-process retry may restore old grants or public ingestion.
        st.envelope_fault = true;
        st.cas_key_leases.clear();
        st.cas_key_deadlines.clear();
        st.namespace_challenges.clear();
        let checkpoint = st.vault.checkpoint()?;
        if binding(&checkpoint)? != source.vault_binding {
            fail!(EACCES, "ASSET_VAULT_BINDING");
        }
        let pool = checkpoint.backup_source(&context, c.clock.now_unix())?;
        if pool.profile != profile {
            fail!(EACCES, "ASSET_LEDGER_BINDING");
        }
        if let Phase::MembershipPreparing { preparation, .. } = &ledger.phase {
            if preparation.pool_digest != pool.pool_digest
                || preparation.content_sha256
                    != digest(b"depot-MembershipContent-v3\0", &checkpoint)?
            {
                fail!(EACCES, "ASSET_MEMBERSHIP_CONTENT_PIN");
            }
        }
        // Bind aliases to existing normalized floors without discarding any
        // unrelated credential/counter. Actual shared store persists first.
        c.counters.bind_credentials([&primary, &target]);
        c.counter_store
            .as_mut()
            .ok_or_else(|| err!(EACCES, "SIGN_COUNT_STATE"))?
            .save_json(&c.counters)?;
        let counter_baseline = !backup_bio_blob.is_empty();
        let preparation = PreparingMembership {
            source,
            backup,
            backup_bio_blob,
            counter_baseline,
            profile,
            minimum_members: 2,
            host: authority.host.clone(),
            asset: authority.asset.clone(),
            custodian: authority.custodian.clone(),
            policy_issuer: authority.policy_issuer.to_bytes(),
            inventory_issuer: authority.inventory_issuer.to_bytes(),
            policy_revision: signed.policy.revision,
            policy_digest: policy.digest(),
            attempt: advance(ledger.attempt)?,
            generation,
            pool_digest: pool.pool_digest,
            content_sha256: digest(b"depot-MembershipContent-v3\0", &checkpoint)?,
            counter_sha256: digest(b"depot-MembershipCounters-v3\0", &c.counters)?,
            primary_counter_floor: c.counters.get_credential(&primary),
            backup_counter_floor: c.counters.get_credential(&target),
            start_ns,
            start_unix,
            deadline_ns: [
                Some(cap),
                context.deadline_ns(),
                metadata_source.deadline_ns(),
            ]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(cap),
            valid_until_unix: signed.policy.expires_unix.min(context.expires_unix()),
        };
        // Remaining expiry terms are filled below before any durable floor.
        let mut preparation = preparation;
        preparation.valid_until_unix = preparation
            .valid_until_unix
            .min(preparation.source.receipt.expires_unix)
            .min(preparation.backup.receipt.expires_unix);
        preparation.check_time(c.clock.as_ref())?;
        let plan_sha256 = preparation.digest()?;
        let next = Ledger {
            version: 3,
            attempt: preparation.attempt,
            policy_floor: preparation.policy_revision,
            receipt_floor: preparation.backup.receipt.generation,
            phase: Phase::MembershipPreparing {
                preparation: preparation.clone(),
                plan_sha256,
            },
        };
        validate_preparing(&next)?;
        let (mut content, loaded) = content_store(&state)?;
        if ledger.version == 3 {
            let Loaded::State(bytes)=loaded else {fail!(EACCES,"ASSET_MEMBERSHIP_CONTENT_REQUIRED");};
            let saved: crate::vault::VaultEnvelopeCheckpoint =
                enclave_core::sealed::decode(&bytes)?;
            if digest(b"depot-MembershipContent-v3\0", &saved)? != preparation.content_sha256 {
                fail!(EACCES, "ASSET_MEMBERSHIP_CONTENT_PIN");
            }
        }
        content.save_json(&checkpoint)?;
        if preparation.counter_baseline {
            let (mut baseline, loaded) =
                counter_baseline_store(&state, &preparation.counter_sha256)?;
            match loaded {
                Loaded::Fresh => baseline.save_json(&c.counters)?,
                Loaded::State(bytes) => {
                    if enclave_core::sealed::decode::<SignCountStore>(&bytes)? != c.counters {
                        fail!(EACCES, "ASSET_MEMBERSHIP_COUNTER_PIN");
                    }
                }
            }
        }
        // SAME authoritative ledger is the only v3 decision point. Saving the
        // staged content above alone cannot change the still-v2 active record.
        ledger_store.save_json(&next)?;
        preparation.check_time(c.clock.as_ref())?;
        if self
            .cas_key_generation
            .load(std::sync::atomic::Ordering::SeqCst)
            != generation
        {
            fail!(EACCES, "CAS_ENROLLMENT_REVOKED");
        }
        // Remain cancelled/disabled. Only the future live producer may prepare
        // fresh authorization; this handle cannot enable either old or new key.
        Ok(MembershipPreparation {
            preparation,
            plan_sha256,
        })
    }
}

pub(super) struct ProofWindow {
    pub(super) start_ns: u64,
    pub(super) start_unix: i64,
    pub(super) deadline_ns: u64,
    pub(super) valid_until_unix: i64,
}
impl ProofWindow {
    pub(super) fn check(&self, clock: &dyn Clock) -> EnclaveResult<()> {
        let boot = clock.now_ns();
        let wall = clock.now_unix();
        if boot < self.start_ns
            || boot >= self.deadline_ns
            || wall < self.start_unix
            || wall >= self.valid_until_unix
        {
            fail!(ETIMEDOUT, "ASSET_MEMBERSHIP_DEADLINE");
        }
        Ok(())
    }
    pub(super) fn cap(&mut self, wall: Option<i64>, boot: Option<u64>) {
        if let Some(wall) = wall {
            self.valid_until_unix = self.valid_until_unix.min(wall);
        }
        if let Some(boot) = boot {
            self.deadline_ns = self.deadline_ns.min(boot);
        }
    }
}
/// Only the real verifier below constructs this move-only value. It contains
/// encrypted wrappers and public pins, never raw PRFs/private tier keys. It
/// currently has NO commit, serialization, activation or release interface.
pub(super) struct VerifiedMembershipCeremony {
    preparation: PreparingMembership,
    plan_sha256: [u8; 32],
    window: ProofWindow,
    counter_sha256: [u8; 32],
    backup_wrappers: crate::backup_envelope::StagedBackupEnvelopes,
}
impl std::fmt::Debug for VerifiedMembershipCeremony {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedMembershipCeremony")
            .field("attempt", &self.preparation.attempt)
            .finish_non_exhaustive()
    }
}

struct CapturedBiometric<'a> {
    inner: &'a mut dyn BiometricProvider,
    observed: Option<(BiometricPrompt, BiometricOutcome)>,
}
impl std::fmt::Debug for CapturedBiometric<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapturedBiometric").finish_non_exhaustive()
    }
}
impl BiometricProvider for CapturedBiometric<'_> {
    fn evaluate(&mut self, prompt: &BiometricPrompt) -> BiometricOutcome {
        let outcome = self.inner.evaluate(prompt);
        self.observed = Some((prompt.clone(), outcome.clone()));
        outcome
    }
}

fn current_public_plan(
    p: &PreparingMembership,
    authority: &AssetEnrollmentAuthority,
    checkpoint: &crate::vault::VaultEnvelopeCheckpoint,
    context: &VerifiedEnvelopeContext,
    now: i64,
) -> EnclaveResult<()> {
    if p.host != authority.host
        || p.asset != authority.asset
        || p.custodian != authority.custodian
        || p.policy_issuer != authority.policy_issuer.to_bytes()
        || p.inventory_issuer != authority.inventory_issuer.to_bytes()
    {
        fail!(EACCES, "ASSET_MEMBERSHIP_SOURCE_CHANGED");
    }
    let policy = authority.policy(p.policy_revision, now)?;
    if policy.digest() != p.policy_digest {
        fail!(ESTALE, "ASSET_POLICY_CHANGED");
    }
    p.source.receipt.clone().activate(
        p.source.pending.evidence.clone(),
        &policy,
        &authority.inventory_issuer,
        p.source.receipt_floor,
        now,
    )?;
    p.backup.receipt.clone().activate(
        p.backup.pending.clone(),
        &policy,
        &authority.inventory_issuer,
        p.backup.receipt.generation,
        now,
    )?;
    let source = checkpoint.backup_source(context, now)?;
    if source.pool_digest != p.pool_digest
        || source.profile != p.profile
        || binding(checkpoint)? != p.source.vault_binding
        || digest(b"depot-MembershipContent-v3\0", checkpoint)? != p.content_sha256
    {
        fail!(EACCES, "ASSET_MEMBERSHIP_CONTENT_PIN");
    }
    Ok(())
}

fn member_intent(
    p: &PreparingMembership,
    plan_sha256: [u8; 32],
    index: usize,
    epoch: &str,
    sequence: u64,
    now: i64,
) -> EnclaveResult<IntentPayloadV1> {
    #[derive(Serialize)]
    struct Arguments {
        operation: &'static str,
        plan_sha256: [u8; 32],
        member_index: usize,
        generation: u64,
    }
    let args = enclave_core::jcs::to_jcs_bytes(&Arguments {
        operation: "add-independent-backup",
        plan_sha256,
        member_index: index,
        generation: p.generation,
    })?;
    let intent = IntentPayloadV1 {
        v: 1,
        schema_version: Some("enclave.intent.v1".into()),
        action_class: ActionClass::A4,
        profile: p.profile,
        data_class: Some(enclave_core::label::Conf::C4),
        spiffe_id: DaemonId::CustodyVault.spiffe_id(),
        tool_name: "depot://custody/add_backup".into(),
        target_namespace: Some("custody.membership".into()),
        human_summary_trusted: Some(format!(
            "Authorize exact independent {} credential and unchanged content-key pool",
            if index == 0 { "primary" } else { "backup" }
        )),
        row_count_bound: Some(1),
        arguments_jcs_sha256: Some(hex::encode(Sha256::digest(&args))),
        canonical_arguments_blake3: blake3::hash(&args).to_hex().to_string(),
        model_blake3: None,
        policy_blake3: hex::encode(p.policy_digest),
        qif_millibits_delta: Some(0),
        custody_grant: None,
        boot_epoch_id: epoch.to_owned(),
        rpc_seq_u64: sequence,
        ts_utc_ms: u64::try_from(now)
            .map_err(|_| err!(EINVAL, "ASSET_MEMBERSHIP_DEADLINE"))?
            .saturating_mul(1000),
        required_factors: crate::factors::required_factors(p.profile, ActionClass::A4, false)
            .into_iter()
            .collect(),
        user_turn: None,
    };
    intent.validate()?;
    Ok(intent)
}

/// Private, explicit member input shared by genuine original-membership and
/// sterile replacement verifiers. This is data, never a factor capability.
pub(super) struct MemberFactorInput<'a> {
    pub(super) credential: &'a EnrolledCredential,
    pub(super) sep_public: &'a [u8],
    pub(super) blob: &'a Vec<u8>,
    pub(super) profile: Profile,
    pub(super) original_start_ns: u64,
}
/// Keep original engine/counter/clock ownership separate from the local
/// replacement hardware factory. No runtime hardware swap or active lock waiver.
pub(super) struct FactorOwners<'a> {
    pub(super) engine: &'a mut CeremonyEngine,
    pub(super) hw: &'a mut VaultHardware,
    pub(super) counters: &'a mut SignCountStore,
    pub(super) counter_store: Option<&'a mut SealedStore>,
    pub(super) clock: &'a dyn Clock,
}
fn full_member_ceremony(
    c: &mut Ceremony,
    devices: &mut MembershipDevices,
    index: usize,
    p: &PreparingMembership,
    intent: &IntentPayloadV1,
    window: &mut ProofWindow,
    cancelled: &std::sync::atomic::AtomicBool,
) -> EnclaveResult<(crate::ceremony::CeremonyGrant, BiometricPrompt)> {
    let (credential, sep_public, blob) = if index == 0 {
        (
            &p.source.pending.evidence.credential,
            &p.source.pending.bio_public_key,
            &p.source.pending.bio_key_blob,
        )
    } else {
        (
            &p.backup.pending.credential,
            &p.backup.pending.sep_public_key,
            &p.backup_bio_blob,
        )
    };
    let member = MemberFactorInput {
        credential,
        sep_public,
        blob,
        profile: p.profile,
        original_start_ns: p.start_ns,
    };
    full_member_ceremony_for(
        FactorOwners {
            engine: &mut c.engine,
            hw: &mut c.hw,
            counters: &mut c.counters,
            counter_store: c.counter_store.as_mut(),
            clock: c.clock.as_ref(),
        },
        devices,
        index,
        member,
        intent,
        window,
        cancelled,
    )
}
pub(super) fn full_member_ceremony_for(
    owners: FactorOwners<'_>,
    devices: &mut MembershipDevices,
    index: usize,
    member: MemberFactorInput<'_>,
    intent: &IntentPayloadV1,
    window: &mut ProofWindow,
    cancelled: &std::sync::atomic::AtomicBool,
) -> EnclaveResult<(crate::ceremony::CeremonyGrant, BiometricPrompt)> {
    let FactorOwners {
        engine,
        hw,
        counters,
        counter_store,
        clock,
    } = owners;
    devices.require_current(hw.simulated)?;
    window.check(clock)?;
    let (credential, sep_public, blob) = (member.credential, member.sep_public, member.blob);
    let sep_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(sep_public)
        .map_err(|_| err!(EACCES, "ASSET_BIOMETRIC_KEY"))?;
    let revision = hw.asset_metadata(member.profile, credential, clock.now_unix())?;
    let mds = hw
        .mds
        .clone()
        .ok_or_else(|| err!(EACCES, "CUSTODY_METADATA_UNAVAILABLE"))?;
    let mut source = hw.metadata_source.clone();
    let simulated = hw.simulated;
    let counter_store = counter_store.ok_or_else(|| err!(EACCES, "SIGN_COUNT_STATE"))?;
    let mut metadata_wall = None;
    let mut metadata_boot = None;
    let mut checkpoint = |counters: &SignCountStore| -> EnclaveResult<()> {
        counter_store.save_json(counters)?;
        window.check(clock)?;
        if !simulated {
            let source = source
                .as_mut()
                .ok_or_else(|| err!(EACCES, "CUSTODY_METADATA_AUTHORITY_REQUIRED"))?;
            let now = clock.now_unix();
            let mds = source.fetch(member.profile, now)?;
            mds.check(
                &credential.aaguid,
                credential.firmware_version,
                credential.key.alg(),
                member.profile,
                ActionClass::A4,
                now,
            )?;
            if source.revision() != revision {
                fail!(ESTALE, "CUSTODY_METADATA_CHANGED");
            }
            metadata_wall = Some(
                mds.expires_at.min(
                    mds.refreshed_at
                        .saturating_add(crate::ctap::mds::freshness_window_s(member.profile)),
                ),
            );
            metadata_boot = source.deadline_ns();
        }
        Ok(())
    };
    let mut biometric = CapturedBiometric {
        inner: hw.biometric.as_mut(),
        observed: None,
    };
    let result = engine.run_with_counter_checkpoint(
        intent,
        None,
        CeremonyHardware {
            biometric: Some(&mut biometric),
            existing_pin: hw
                .existing_pin
                .as_mut()
                .map(|provider| provider.as_mut() as &mut dyn crate::pin::ExistingPinProvider),
            pin_cancelled: Some(cancelled),
            ceremony_start_ns: Some(member.original_start_ns),
            oidc_step_up: None,
            oidc_provider: hw.oidc_provider.as_mut().map(|provider| {
                provider.as_mut() as &mut dyn crate::oidc_acquisition::IntentOidcProvider
            }),
            sep_key: Some(sep_key),
            sep_bio_blob: Some(blob.clone()),
            yubikey: Some(devices.member(index)?),
            credential: Some(credential),
            mds: Some(&mds),
            counters: Some(counters),
            egress: hw
                .egress
                .as_mut()
                .map(|gate| gate.as_mut() as &mut dyn EgressGate),
            leases: None,
            is_yanked: false,
            oidc_verifier: None,
            oidc_token: None,
            quorum_policy: None,
            quorum_signatures: None,
        },
        clock,
        &mut checkpoint,
    );
    drop(checkpoint);
    window.cap(metadata_wall, metadata_boot);
    let grant = result?;
    let (prompt, outcome) = biometric
        .observed
        .take()
        .ok_or_else(|| err!(EACCES, "ASSET_BIOMETRIC_KEY"))?;
    if prompt.d_jcs != grant.d_jcs
        || crate::biometric::verify_approval(&sep_key, &prompt, &outcome)? != grant.sep_signature
    {
        fail!(EACCES, "ASSET_BIOMETRIC_KEY");
    }
    window.cap(grant.valid_until_unix, grant.valid_until_boot_ns);
    window.check(clock)?;
    devices.require_current(simulated)?;
    Ok((grant, prompt))
}

impl VaultService {
    /// Genuinely verify/consume both complete inherited A4 factor chains and
    /// both dual-tier PRF assertions. This private producer cannot activate a
    /// member, issue a grant/lease or clear the sterile runtime latch.
    pub(super) fn verify_membership_preparation(
        &self,
        prepared: MembershipPreparation,
    ) -> EnclaveResult<VerifiedMembershipCeremony> {
        let mut ceremony = self.lock_sensitive_ceremony()?;
        let c = &mut *ceremony;
        let p = prepared.preparation;
        if !p.counter_baseline || p.backup_bio_blob.is_empty() {
            fail!(EACCES, "MEMBERSHIP_LIVE_PRODUCER_REQUIRED");
        }
        let state = {
            self.lock_sensitive_state()?
                .state_dir
                .clone()
                .ok_or_else(|| err!(EACCES, "ENROLLMENT_STATE_REQUIRED"))?
        };
        let (_, ledger) = open(&state)?;
        validate_saved_pins(&state, &ledger)?;
        let Phase::MembershipPreparing {plan_sha256,..}=&ledger.phase else {fail!(EACCES,"ASSET_MEMBERSHIP_STATE");};
        if *plan_sha256 != prepared.plan_sha256 || p.digest()? != prepared.plan_sha256 {
            fail!(EACCES, "ASSET_MEMBERSHIP_STATE");
        }
        let (_, loaded) = content_store(&state)?;
        let Loaded::State(bytes)=loaded else {fail!(EACCES,"ASSET_MEMBERSHIP_CONTENT_REQUIRED");};
        let checkpoint: crate::vault::VaultEnvelopeCheckpoint =
            enclave_core::sealed::decode(&bytes)?;
        let (_, loaded) = SealedStore::open_bounded_required(&state, "signcount", CONTENT_LIMIT)?;
        let Loaded::State(bytes)=loaded else {fail!(EACCES,"SIGN_COUNT_STATE");};
        if enclave_core::sealed::decode::<SignCountStore>(&bytes)? != c.counters {
            fail!(EACCES, "ASSET_MEMBERSHIP_COUNTER_PIN");
        }
        let authority =
            c.hw.asset_enrollment_authority
                .clone()
                .ok_or_else(|| err!(EACCES, "ASSET_AUTHORITY_REQUIRED"))?;
        let envelope_authority =
            c.hw.envelope_authority
                .clone()
                .ok_or_else(|| err!(EACCES, "ENVELOPE_POLICY_AUTHORITY_REQUIRED"))?;
        let source =
            c.hw.metadata_source
                .clone()
                .ok_or_else(|| err!(EACCES, "ENVELOPE_POLICY_SOURCE_REQUIRED"))?;
        let context =
            source.envelope_context(&envelope_authority, p.profile, c.clock.now_unix())?;
        current_public_plan(&p, &authority, &checkpoint, &context, c.clock.now_unix())?;
        let mut window = ProofWindow {
            start_ns: p.start_ns,
            start_unix: p.start_unix,
            deadline_ns: p.deadline_ns,
            valid_until_unix: p.valid_until_unix,
        };
        window.cap(Some(context.expires_unix()), context.deadline_ns());
        window.check(c.clock.as_ref())?;
        self.prepare_fresh_authorization(p.generation)?;
        c.enter_generation(p.generation);
        let mut devices =
            c.hw.membership_devices
                .take()
                .ok_or_else(|| err!(EACCES, "MEMBERSHIP_NATIVE_PAIR_REQUIRED"))?;
        let result = (|| {
            devices.require_current(c.hw.simulated)?;
            devices.require_topology(p.profile)?;
            // Diagnose BOTH members before spending either member's factor
            // chain. GetInfo/model/topology do not authenticate a credential;
            // the exact ordered mapping is verified by fresh signatures below.
            for index in 0..2 {
                self.asset_check(p.generation, window.deadline_ns)?;
                window.check(c.clock.as_ref())?;
                let credential = if index == 0 {
                    p.source.pending.evidence.credential()
                } else {
                    p.backup.pending.credential()
                };
                c.hw.asset_metadata(p.profile, credential, c.clock.now_unix())?;
                let mut client =
                    CtapClient::open_with_deadline(devices.member(index)?, window.deadline_ns)?;
                let info = client.get_info()?;
                drop(client);
                if info.aaguid != credential.aaguid {
                    fail!(EACCES, "AAGUID_CHANGED");
                }
                c.hw.mds
                    .as_ref()
                    .ok_or_else(|| err!(EACCES, "CUSTODY_METADATA_UNAVAILABLE"))?
                    .check(
                        &info.aaguid,
                        info.firmware_version,
                        credential.key.alg(),
                        p.profile,
                        ActionClass::A4,
                        c.clock.now_unix(),
                    )?;
                if p.profile == Profile::L3 && !info.built_in_uv && c.hw.existing_pin.is_none() {
                    fail!(EACCES, "YUBIKEY_PIN_PROVIDER_REQUIRED");
                }
                devices.require_current(c.hw.simulated)?;
                window.check(c.clock.as_ref())?;
            }
            let mut outputs = Vec::with_capacity(2);
            for index in 0..2 {
                self.asset_check(p.generation, window.deadline_ns)?;
                window.check(c.clock.as_ref())?;
                let (epoch, sequence) = {
                    let mut st = self.lock_sensitive_state()?;
                    Self::begin_governed(&mut st)?
                };
                let intent = member_intent(
                    &p,
                    prepared.plan_sha256,
                    index,
                    &epoch,
                    sequence,
                    c.clock.now_unix(),
                )?;
                let (mut grant, prompt) = full_member_ceremony(
                    c,
                    &mut devices,
                    index,
                    &p,
                    &intent,
                    &mut window,
                    &self.ceremony_cancelled,
                )?;
                self.asset_check(p.generation, window.deadline_ns)?;
                grant.check_valid_at(c.clock.now_unix())?;
                grant.check_valid_at_boot(c.clock.now_ns())?;
                // A spent full-chain grant authorizes only this exact new
                // challenge. It can never be replayed to another member/plan.
                grant.consume()?;
                let mut challenge = b"depot-MembershipDualPrf-v3\0".to_vec();
                challenge.extend(prepared.plan_sha256);
                challenge.extend(grant.d_jcs);
                challenge.extend(&grant.sep_signature);
                challenge.extend((index as u64).to_be_bytes());
                challenge.extend(p.start_ns.to_be_bytes());
                challenge.extend(enclave_core::rng::bytes32());
                let challenge: [u8; 32] = Sha256::digest(challenge).into();
                let credential = if index == 0 {
                    p.source.pending.evidence.credential()
                } else {
                    p.backup.pending.credential()
                };
                let mut salts = [0; 64];
                salts[..32].copy_from_slice(&PrfTier::A3.salt());
                salts[32..].copy_from_slice(&PrfTier::A4.salt());
                devices.require_current(c.hw.simulated)?;
                let mut client =
                    CtapClient::open_with_deadline(devices.member(index)?, window.deadline_ns)?;
                let info = client.get_info()?;
                if info.aaguid != credential.aaguid {
                    fail!(EACCES, "AAGUID_CHANGED");
                }
                let (response, shared) = if p.profile == Profile::L3 && !info.built_in_uv {
                    let provider =
                        c.hw.existing_pin
                            .as_mut()
                            .ok_or_else(|| err!(EACCES, "YUBIKEY_PIN_PROVIDER_REQUIRED"))?;
                    client.get_assertion_dual_prf_with_pin_provider(
                        &credential.credential_id,
                        &challenge,
                        &salts,
                        window.deadline_ns,
                        &self.ceremony_cancelled,
                        || {
                            provider
                                .read_existing_pin_cancellable(&prompt, &self.ceremony_cancelled)
                        },
                    )?
                } else {
                    client.get_assertion_dual_prf(
                        &credential.credential_id,
                        &challenge,
                        p.profile == Profile::L3,
                        &salts,
                    )?
                };
                drop(client);
                let verified = crate::ctap::assertion::verify_assertion(
                    credential,
                    &response,
                    &challenge,
                    p.profile == Profile::L3,
                    &mut c.counters,
                )?;
                // Persist every genuine advance, even if a later factor, clock,
                // policy or wrapper check refuses this complete operation.
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
                devices.require_current(c.hw.simulated)?;
                window.check(c.clock.as_ref())?;
                self.asset_check(p.generation, window.deadline_ns)?;
                c.hw.asset_metadata(p.profile, credential, c.clock.now_unix())?;
                window.cap(
                    c.hw.mds.as_ref().map(|mds| {
                        mds.expires_at.min(
                            mds.refreshed_at
                                .saturating_add(crate::ctap::mds::freshness_window_s(p.profile)),
                        )
                    }),
                    c.hw.metadata_source
                        .as_ref()
                        .and_then(|source| source.deadline_ns()),
                );
                let current =
                    source.envelope_context(&envelope_authority, p.profile, c.clock.now_unix())?;
                current_public_plan(&p, &authority, &checkpoint, &current, c.clock.now_unix())?;
                window.cap(Some(current.expires_unix()), current.deadline_ns());
                window.check(c.clock.as_ref())?;
            }
            let a3 = c.hw.sep.ecdh_share(PrfTier::A3)?;
            window.check(c.clock.as_ref())?;
            self.asset_check(p.generation, window.deadline_ns)?;
            let a4 = c.hw.sep.ecdh_share(PrfTier::A4)?;
            window.check(c.clock.as_ref())?;
            if enclave_core::secret::ct_eq(&outputs[0].expose()[..32], &outputs[0].expose()[32..]) {
                fail!(EACCES, "MEMBERSHIP_INDEPENDENT_PRF_REQUIRED");
            }
            let source_a3 = KekShares {
                sep_ecdh_share: a3.expose(),
                yubikey_prf: &outputs[0].expose()[..32],
            };
            let source_a4 = KekShares {
                sep_ecdh_share: a4.expose(),
                yubikey_prf: &outputs[0].expose()[32..],
            };
            let backup_a3 = KekShares {
                sep_ecdh_share: a3.expose(),
                yubikey_prf: &outputs[1].expose()[..32],
            };
            let backup_a4 = KekShares {
                sep_ecdh_share: a4.expose(),
                yubikey_prf: &outputs[1].expose()[32..],
            };
            let wrappers = crate::backup_envelope::StagedBackupEnvelopes::stage(
                &checkpoint,
                p.source.pending.evidence.credential(),
                p.backup.pending.credential(),
                &source_a3,
                &source_a4,
                &backup_a3,
                &backup_a4,
                &context,
                c.clock.now_unix(),
            )?;
            devices.require_current(c.hw.simulated)?;
            self.asset_check(p.generation, window.deadline_ns)?;
            let current =
                source.envelope_context(&envelope_authority, p.profile, c.clock.now_unix())?;
            current_public_plan(&p, &authority, &checkpoint, &current, c.clock.now_unix())?;
            window.cap(Some(current.expires_unix()), current.deadline_ns());
            window.check(c.clock.as_ref())?;
            let (_, current) = open(&state)?;
            validate_saved_pins(&state, &current)?;
            let Phase::MembershipPreparing {plan_sha256,..}=current.phase else {fail!(EACCES,"ASSET_MEMBERSHIP_STATE");};
            if plan_sha256 != prepared.plan_sha256 {
                fail!(EACCES, "ASSET_MEMBERSHIP_STATE");
            }
            let counter_sha256 = digest(b"depot-MembershipCounters-v3\0", &c.counters)?;
            window.check(c.clock.as_ref())?;
            self.asset_check(p.generation, window.deadline_ns)?;
            Ok(VerifiedMembershipCeremony {
                preparation: p,
                plan_sha256: prepared.plan_sha256,
                window,
                counter_sha256,
                backup_wrappers: wrappers,
            })
        })();
        c.hw.membership_devices = Some(devices);
        result
    }
}

/// The sole v3 activation record, stored in the SAME workflow ledger as the
/// consumed receipt and attempt floors. Its immutable checkpoint reference is
/// advanced under State for every completed content mutation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommittedMembership {
    preparation: PreparingMembership,
    plan_sha256: [u8; 32],
    membership_sha256: [u8; 32],
    membership_generation: u64,
    backup_sha256: [u8; 32],
    counter_sha256: [u8; 32],
    sequence: u64,
    checkpoint_sha256: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    renewed: Option<RenewedAuthority>,
}
impl CommittedMembership {
    pub(crate) fn travel_scope(&self) -> EnclaveResult<[u8; 32]> {
        digest(
            b"depot-TravelOriginalMembership-v1\0",
            &(
                self.preparation.profile,
                self.preparation.source.vault_binding,
                self.membership_sha256,
                self.membership_generation,
            ),
        )
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteMembershipCheckpoint {
    version: u32,
    membership_sha256: [u8; 32],
    membership_generation: u64,
    sequence: u64,
    primary: crate::vault::VaultEnvelopeCheckpoint,
    backup: crate::backup_envelope::StagedBackupEnvelopes,
}
fn complete_store(state: &Path, hash: &[u8; 32]) -> EnclaveResult<(SealedStore, Loaded)> {
    SealedStore::open_bounded_required(
        &state.join("membership-checkpoints").join(hex::encode(hash)),
        "checkpoint",
        COMPLETE_LIMIT,
    )
}
fn complete_hash(value: &CompleteMembershipCheckpoint) -> EnclaveResult<[u8; 32]> {
    digest(b"depot-CompleteMembershipCheckpoint-v3\0", value)
}
fn membership_identity(plan: [u8; 32], backup: [u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"depot-CommittedMembership-v3\0");
    h.update(plan);
    h.update(backup);
    h.finalize().into()
}
fn preparing_ledger(record: &CommittedMembership) -> Ledger {
    let p = &record.preparation;
    Ledger {
        version: 3,
        attempt: p.attempt,
        policy_floor: p.policy_revision,
        receipt_floor: p.backup.receipt.generation,
        phase: Phase::MembershipPreparing {
            preparation: p.clone(),
            plan_sha256: record.plan_sha256,
        },
    }
}
pub(super) fn validate_v3(ledger: &Ledger) -> EnclaveResult<()> {
    match &ledger.phase {
        Phase::MembershipPreparing { .. } => validate_preparing(ledger),
        Phase::MembershipCommitted { record } => {
            validate_preparing(&preparing_ledger(record))?;
            let p = &record.preparation;
            record.validate_renewed()?;
            if !p.counter_baseline
                || ledger.attempt != record.attempt()
                || ledger.policy_floor != p.policy_revision
                || ledger.receipt_floor != record.receipt_floor()
                || record.membership_generation != record.attempt()
                || record.sequence == 0
                || record.sequence > INTEGER_LIMIT
                || record.membership_sha256
                    != membership_identity(record.plan_sha256, record.backup_sha256)
            {
                fail!(EACCES, "ASSET_MEMBERSHIP_STATE");
            }
            Ok(())
        }
        Phase::MembershipRenewing {
            renewal,
            plan_sha256,
        } => validate_renewing(ledger, renewal, *plan_sha256),
        _ => Err(err!(EACCES, "ASSET_MEMBERSHIP_STATE")),
    }
}
fn load_complete(
    state: &Path,
    record: &CommittedMembership,
) -> EnclaveResult<CompleteMembershipCheckpoint> {
    let (_, loaded) = complete_store(state, &record.checkpoint_sha256)?;
    let Loaded::State(bytes)=loaded else {fail!(EACCES,"ASSET_MEMBERSHIP_CHECKPOINT_REQUIRED");};
    let value: CompleteMembershipCheckpoint = enclave_core::sealed::decode(&bytes)?;
    if value.version != 3
        || value.membership_sha256 != record.membership_sha256
        || value.membership_generation != record.membership_generation
        || value.sequence != record.sequence
        || complete_hash(&value)? != record.checkpoint_sha256
        || digest(b"depot-MembershipBackupWrappers-v3\0", &value.backup)? != record.backup_sha256
        || binding(&value.primary)? != record.preparation.source.vault_binding
    {
        fail!(EACCES, "ASSET_MEMBERSHIP_CHECKPOINT_PIN");
    }
    Ok(value)
}
fn save_complete(state: &Path, value: &CompleteMembershipCheckpoint) -> EnclaveResult<[u8; 32]> {
    let hash = complete_hash(value)?;
    let (mut store, loaded) = complete_store(state, &hash)?;
    match loaded {
        Loaded::Fresh => store.save_json(value)?,
        Loaded::State(bytes) => {
            let existing: CompleteMembershipCheckpoint = enclave_core::sealed::decode(&bytes)?;
            if complete_hash(&existing)? != hash {
                fail!(EACCES, "ASSET_MEMBERSHIP_CHECKPOINT_PIN");
            }
        }
    }
    Ok(hash)
}
fn validate_committed_counters(state: &Path, record: &CommittedMembership) -> EnclaveResult<()> {
    let (_, loaded) = counter_baseline_store(state, &record.counter_sha256)?;
    let Loaded::State(bytes)=loaded else {fail!(EACCES,"ASSET_MEMBERSHIP_COUNTER_PIN");};
    let baseline: SignCountStore = enclave_core::sealed::decode(&bytes)?;
    let (_, loaded) = SealedStore::open_bounded_required(state, "signcount", CONTENT_LIMIT)?;
    let Loaded::State(bytes)=loaded else {fail!(EACCES,"SIGN_COUNT_STATE");};
    let current: SignCountStore = enclave_core::sealed::decode(&bytes)?;
    if digest(b"depot-MembershipCounters-v3\0", &baseline)? != record.counter_sha256
        || !current.dominates(&baseline)
    {
        fail!(EACCES, "ASSET_MEMBERSHIP_COUNTER_PIN");
    }
    Ok(())
}
pub(super) fn validate_v3_pins(state: &Path, ledger: &Ledger) -> EnclaveResult<()> {
    validate_v3(ledger)?;
    match &ledger.phase {
        Phase::MembershipPreparing { .. } => validate_saved_pins(state, ledger),
        Phase::MembershipCommitted { record } => {
            load_complete(state, record)?;
            validate_committed_counters(state, record)
        }
        Phase::MembershipRenewing { renewal, .. } => validate_renewal_pins(state, renewal),
        _ => Err(err!(EACCES, "ASSET_MEMBERSHIP_STATE")),
    }
}

/// Validated independently admitted v3 membership. No deserialization or public
/// constructor can create it. This boot capability never substitutes for a
/// fresh live ceremony or enables an L3 release by itself.
pub struct ValidatedNativeMembership {
    record: CommittedMembership,
    complete: CompleteMembershipCheckpoint,
}
impl std::fmt::Debug for ValidatedNativeMembership {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatedNativeMembership")
            .field("generation", &self.record.membership_generation)
            .field("sequence", &self.record.sequence)
            .finish_non_exhaustive()
    }
}
impl ValidatedNativeMembership {
    /// Exact ordered independently admitted member and its protected SEP blob.
    pub fn enrolled(&self, index: usize) -> EnclaveResult<EnrolledCustodyState> {
        let p = &self.record.preparation;
        match index {
            0 => Ok(EnrolledCustodyState {
                credential: p.source.pending.evidence.credential().clone(),
                bio_public_key: p.source.pending.bio_public_key.clone(),
                bio_key_blob: p.source.pending.bio_key_blob.clone(),
            }),
            1 => Ok(EnrolledCustodyState {
                credential: p.backup.pending.credential().clone(),
                bio_public_key: p.backup.pending.sep_public_key.clone(),
                bio_key_blob: p.backup_bio_blob.clone(),
            }),
            _ => Err(err!(EINVAL, "MEMBERSHIP_MEMBER_INDEX")),
        }
    }
    /// Original v2 wrapper identity; mutable content never changes this binding.
    pub fn source_binding(&self) -> [u8; 32] {
        self.record.preparation.source.vault_binding
    }
    /// Stable identity of exact admission plan and complete alternate wrappers.
    pub fn membership_id(&self) -> [u8; 32] {
        self.record.membership_sha256
    }
    /// Stable current original-membership scope for separately audited travel
    /// admission. This value grants no travel authority or key possession.
    pub fn travel_scope(&self) -> EnclaveResult<[u8; 32]> {
        self.record.travel_scope()
    }
    /// Durable generation, separate from this process's cancellation generation.
    pub fn generation(&self) -> u64 {
        self.record.membership_generation
    }
    /// Exact complete referenced primary content, including all completed ingests.
    pub fn checkpoint(&self) -> &crate::vault::VaultEnvelopeCheckpoint {
        &self.complete.primary
    }
    pub(crate) fn record(&self) -> CommittedMembership {
        self.record.clone()
    }
    pub(crate) fn backup_wrappers(&self) -> &crate::backup_envelope::StagedBackupEnvelopes {
        &self.complete.backup
    }
    pub(crate) fn guard(
        &self,
        state: PathBuf,
        authority: AssetEnrollmentAuthority,
        index: usize,
    ) -> EnclaveResult<ActiveAssetGuard> {
        let p = &self.record.preparation;
        let member = self.enrolled(index)?;
        let (primary, backup) = self.record.receipts();
        let mut guard = ActiveAssetGuard::for_receipt(
            state,
            authority,
            p.profile,
            self.source_binding(),
            &member.credential,
            primary,
        )?;
        guard.valid_from_unix = primary.issued_unix.max(backup.issued_unix);
        guard.expires_unix = primary.expires_unix.min(backup.expires_unix);
        guard.membership = Some((self.membership_id(), self.generation(), index));
        Ok(guard)
    }
}
/// Explicit v3 reader. The historical singleton reader always returns None for
/// v3, and the two-member minimum is checked on each sensitive guard refresh.
pub fn load_native_membership(
    state: &Path,
    authority: Option<&AssetEnrollmentAuthority>,
    profile: Profile,
    now: i64,
) -> EnclaveResult<Option<ValidatedNativeMembership>> {
    let (_, ledger) = open(state)?;
    let Phase::MembershipCommitted {record}=ledger.phase else {return Ok(None)};
    if record.preparation.profile != profile {
        fail!(EACCES, "ASSET_LEDGER_BINDING");
    }
    validate_committed_counters(state, &record)?;
    let complete = load_complete(state, &record)?;
    let authority = authority.ok_or_else(|| err!(EACCES, "ASSET_AUTHORITY_REQUIRED"))?;
    let expired = verify_record_authority(&record, authority, now, true)?;
    if expired {
        return Ok(None);
    }
    Ok(Some(ValidatedNativeMembership { record, complete }))
}

/// State owns the only mutable copy and holds its exclusive lock throughout.
/// Write new complete content first, then atomically change the SAME authority
/// reference; an interrupted new file is unreachable and never activates.
pub(crate) fn persist_checkpoint(
    state: &Path,
    record: &mut CommittedMembership,
    primary: crate::vault::VaultEnvelopeCheckpoint,
) -> EnclaveResult<()> {
    let publication = PublicationLease::acquire(state)?;
    let (mut store, mut ledger) = open(state)?;
    let Phase::MembershipCommitted {record:current}=&ledger.phase else {fail!(EACCES,"ASSET_MEMBERSHIP_STATE");};
    if enclave_core::jcs::to_jcs_bytes(current)? != enclave_core::jcs::to_jcs_bytes(record)? {
        fail!(ESTALE, "ASSET_MEMBERSHIP_REFERENCE_CHANGED");
    }
    let previous = load_complete(state, record)?;
    if binding(&primary)? != record.preparation.source.vault_binding {
        fail!(EACCES, "ASSET_MEMBERSHIP_CHECKPOINT_PIN");
    }
    let sequence = advance(record.sequence)?;
    let complete = CompleteMembershipCheckpoint {
        version: 3,
        membership_sha256: record.membership_sha256,
        membership_generation: record.membership_generation,
        sequence,
        primary,
        backup: previous.backup,
    };
    let mut next = record.clone();
    next.sequence = sequence;
    next.checkpoint_sha256 = save_complete(state, &complete)?;
    ledger.phase = Phase::MembershipCommitted {
        record: next.clone(),
    };
    publication.publish(&mut store, &ledger, Some(record), &[])?;
    *record = next;
    Ok(())
}

impl VaultService {
    /// Install only concrete owned attachment handles; this never authenticates
    /// either identity. Old release authority is fenced before pair adoption.
    pub fn install_membership_devices(
        &self,
        peer: &PeerCredentials,
        devices: MembershipDevices,
    ) -> EnclaveResult<()> {
        Self::asset_admin(peer)?;
        let mut c = self.lock_sensitive_ceremony()?;
        self.revoke_cas_keys()?;
        devices.require_current(c.hw.simulated)?;
        c.hw.yubikey = None;
        c.hw.membership_devices = Some(devices);
        Ok(())
    }
    /// Usable admin request path: independent public evidence is checked before
    /// floor burn, then genuine ordered D2/A4/CTAP proofs produce the only value
    /// accepted by commit. No caller assertion of capability/success is accepted.
    pub(super) fn add_asset_backup(
        &self,
        peer: &PeerCredentials,
        pending: PendingAssetEnrollment,
        receipt: AssetEnrollmentReceipt,
        bio_key_blob: Vec<u8>,
    ) -> EnclaveResult<VaultResponse> {
        self.add_asset_backup_at(peer, pending, receipt, bio_key_blob, None)
    }
    fn add_asset_backup_at(
        &self,
        peer: &PeerCredentials,
        pending: PendingAssetEnrollment,
        receipt: AssetEnrollmentReceipt,
        bio_key_blob: Vec<u8>,
        origin: Option<(u64, i64)>,
    ) -> EnclaveResult<VaultResponse> {
        if bio_key_blob.is_empty() {
            fail!(EACCES, "ASSET_BIOMETRIC_KEY");
        }
        let prepared = self.prepare_membership_cutover_inner(
            peer,
            MemberEvidence { pending, receipt },
            bio_key_blob,
            origin,
        )?;
        let verified = self.verify_membership_preparation(prepared)?;
        self.commit_membership(verified)
    }
    pub(super) fn commit_membership(
        &self,
        verified: VerifiedMembershipCeremony,
    ) -> EnclaveResult<VaultResponse> {
        let mut ceremony = self.lock_sensitive_ceremony()?;
        let c = &mut *ceremony;
        let p = &verified.preparation;
        verified.window.check(c.clock.as_ref())?;
        self.asset_check(p.generation, verified.window.deadline_ns)?;
        let state = {
            self.lock_sensitive_state()?
                .state_dir
                .clone()
                .ok_or_else(|| err!(EACCES, "ENROLLMENT_STATE_REQUIRED"))?
        };
        let publication = PublicationLease::acquire(&state)?;
        let (mut store, mut ledger) = open(&state)?;
        validate_saved_pins(&state, &ledger)?;
        let Phase::MembershipPreparing {plan_sha256,..}=&ledger.phase else {fail!(EACCES,"ASSET_MEMBERSHIP_STATE");};
        if *plan_sha256 != verified.plan_sha256
            || digest(b"depot-MembershipCounters-v3\0", &c.counters)? != verified.counter_sha256
        {
            fail!(EACCES, "ASSET_MEMBERSHIP_STATE");
        }
        let (_, loaded) = SealedStore::open_bounded_required(&state, "signcount", CONTENT_LIMIT)?;
        let Loaded::State(bytes)=loaded else {fail!(EACCES,"SIGN_COUNT_STATE");};
        if enclave_core::sealed::decode::<SignCountStore>(&bytes)? != c.counters {
            fail!(EACCES, "ASSET_MEMBERSHIP_COUNTER_PIN");
        }
        let authority =
            c.hw.asset_enrollment_authority
                .clone()
                .ok_or_else(|| err!(EACCES, "ASSET_AUTHORITY_REQUIRED"))?;
        let envelope_authority =
            c.hw.envelope_authority
                .clone()
                .ok_or_else(|| err!(EACCES, "ENVELOPE_POLICY_AUTHORITY_REQUIRED"))?;
        let source =
            c.hw.metadata_source
                .clone()
                .ok_or_else(|| err!(EACCES, "ENVELOPE_POLICY_SOURCE_REQUIRED"))?;
        let context =
            source.envelope_context(&envelope_authority, p.profile, c.clock.now_unix())?;
        let mut st = self.lock_sensitive_state()?;
        let checkpoint = st.vault.checkpoint()?;
        current_public_plan(p, &authority, &checkpoint, &context, c.clock.now_unix())?;
        let devices =
            c.hw.membership_devices
                .as_mut()
                .ok_or_else(|| err!(EACCES, "MEMBERSHIP_NATIVE_PAIR_REQUIRED"))?;
        devices.require_current(c.hw.simulated)?;
        devices.require_topology(p.profile)?;
        let backup_sha256 = digest(
            b"depot-MembershipBackupWrappers-v3\0",
            &verified.backup_wrappers,
        )?;
        let membership_sha256 = membership_identity(verified.plan_sha256, backup_sha256);
        let complete = CompleteMembershipCheckpoint {
            version: 3,
            membership_sha256,
            membership_generation: p.attempt,
            sequence: 1,
            primary: checkpoint,
            backup: verified.backup_wrappers,
        };
        let checkpoint_sha256 = save_complete(&state, &complete)?;
        let (mut baseline, loaded) = counter_baseline_store(&state, &verified.counter_sha256)?;
        match loaded {
            Loaded::Fresh => baseline.save_json(&c.counters)?,
            Loaded::State(bytes) => {
                if enclave_core::sealed::decode::<SignCountStore>(&bytes)? != c.counters {
                    fail!(EACCES, "ASSET_MEMBERSHIP_COUNTER_PIN");
                }
            }
        }
        let record = CommittedMembership {
            preparation: p.clone(),
            plan_sha256: verified.plan_sha256,
            membership_sha256,
            membership_generation: p.attempt,
            backup_sha256,
            counter_sha256: verified.counter_sha256,
            sequence: 1,
            checkpoint_sha256,
            renewed: None,
        };
        verified.window.check(c.clock.as_ref())?;
        self.asset_check(p.generation, verified.window.deadline_ns)?;
        let active = ValidatedNativeMembership {
            record: record.clone(),
            complete,
        };
        let guard = active.guard(state.clone(), authority.clone(), 0)?;
        // Persistence stays outside the release serial. Once the reference is
        // durable it records completed genuine admission, never a live grant.
        // A cancellation/expiry after this save leaves the running service
        // sterile; boot still needs fresh factors before any L3 release.
        ledger.phase = Phase::MembershipCommitted {
            record: record.clone(),
        };
        validate_v3(&ledger)?;
        publication.publish(&mut store, &ledger, None, &[])?;
        verified.window.check(c.clock.as_ref())?;
        self.asset_check(p.generation, verified.window.deadline_ns)?;
        context.admit(p.profile, "C4", c.clock.now_unix(), false)?;
        // Never wait for the release serial under State. Only bounded public
        // checks and ownership assignments occur while retaining this lock.
        let _release = self
            .cas_key_release
            .try_lock()
            .map_err(|error| match error {
                std::sync::TryLockError::WouldBlock => err!(EAGAIN, "CUSTODY_RELEASE_BUSY"),
                std::sync::TryLockError::Poisoned(_) => err!(EIO, "CAS_RELEASE_LOCK"),
            })?;
        verified.window.check(c.clock.as_ref())?;
        self.asset_check(p.generation, verified.window.deadline_ns)?;
        st.membership_checkpoint = Some(record);
        st.active_asset_guard = Some(guard.clone());
        c.hw.active_asset_guard = Some(guard);
        st.envelope_store = None;
        st.envelope_fault = false;
        st.envelope_policy_digest = Some(context.digest());
        st.envelope_valid_until_unix = Some(context.policy_expires_unix());
        st.envelope_deadline_ns = context.deadline_ns();
        st.envelope_policy_source = Some(source);
        st.envelope_authority = Some(envelope_authority);
        let mut lifecycle = CustodyLifecycle::boot(p.profile);
        if p.profile == Profile::L2 {
            lifecycle.on(CustodyEvent::PublicIngestInit)?;
        }
        st.lifecycle = lifecycle;
        c.hw.asset_activation_binding = Some(p.source.vault_binding);
        c.setup_only = false;
        self.cas_enrolled_generation
            .store(p.generation, std::sync::atomic::Ordering::SeqCst);
        self.cas_keys_enabled
            .store(true, std::sync::atomic::Ordering::SeqCst);
        drop(_release);
        self.attach_lifecycle_release(
            p.generation,
            Some(verified.window.deadline_ns),
            Some(verified.window.valid_until_unix),
            st.active_asset_guard.clone(),
        )?;
        Ok(VaultResponse::AssetBackupAdded {
            membership_id: hex::encode(membership_sha256),
            generation: p.attempt,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupEnrollment {
    version: u32,
    source_sha256: [u8; 32],
    attempt: u64,
    policy_floor: u64,
    phase: BackupEnrollmentPhase,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
enum BackupEnrollmentPhase {
    Preparing { nonce_sha256: [u8; 32] },
    Pending(Pending),
}
fn backup_enrollment_store(state: &Path) -> EnclaveResult<(SealedStore, Loaded)> {
    SealedStore::open_bounded_required(&state.join("backup-enrollment"), "pending", 2 * 1024 * 1024)
}
fn backup_source_pin(ledger: &Ledger) -> EnclaveResult<[u8; 32]> {
    if let Phase::MembershipPreparing { preparation, .. } = &ledger.phase {
        let source = &preparation.source;
        let original = Ledger {
            version: source.version,
            attempt: source.attempt,
            policy_floor: source.policy_floor,
            receipt_floor: source.receipt_floor,
            phase: Phase::Active {
                pending: source.pending.clone(),
                receipt: source.receipt.clone(),
                vault_binding: source.vault_binding,
            },
        };
        return digest(b"depot-BackupEnrollmentSource-v3\0", &original);
    }
    if !matches!(&ledger.phase, Phase::Active { .. }) || !(1..=2).contains(&ledger.version) {
        fail!(EACCES, "ASSET_ACTIVE_REQUIRED");
    }
    digest(b"depot-BackupEnrollmentSource-v3\0", ledger)
}
impl VaultService {
    /// Genuine backup initializer on the second concrete attachment. Only
    /// public pending evidence leaves UID703; its protected SEP blob remains in
    /// a sealed source-bound pending record. A pending never activates custody.
    pub(in crate::service) fn begin_asset_backup(
        &self,
        peer: &PeerCredentials,
    ) -> EnclaveResult<VaultResponse> {
        Self::asset_admin(peer)?;
        let mut ceremony = self.lock_sensitive_ceremony()?;
        let c = &mut *ceremony;
        let start = c.clock.now_ns();
        let start_unix = c.clock.now_unix();
        let generation = self
            .cas_key_generation
            .load(std::sync::atomic::Ordering::SeqCst);
        let cap = start
            .checked_add(crate::ceremony::CEREMONY_BUDGET_NS)
            .ok_or_else(|| err!(ETIMEDOUT, "ASSET_SETUP_DEADLINE"))?;
        // Clearing cancellation for this new setup generation never enables
        // custody or revives an earlier grant/lease.
        self.prepare_fresh_authorization(generation)?;
        let (state, profile) = {
            let st = self.lock_sensitive_state()?;
            if st.envelope_fault {
                fail!(EACCES, "VAULT_ENVELOPE_STATE_UNCERTAIN");
            }
            (
                st.state_dir
                    .clone()
                    .ok_or_else(|| err!(EACCES, "ENROLLMENT_STATE_REQUIRED"))?,
                st.profile,
            )
        };
        if profile == Profile::L1 {
            fail!(EPERM, "ENROLL_NOT_APPLICABLE_L1");
        }
        let (_, ledger) = open(&state)?;
        let source_sha256 = backup_source_pin(&ledger)?;
        let Phase::Active {pending:source,receipt,vault_binding}=&ledger.phase else {fail!(EACCES,"ASSET_ACTIVE_REQUIRED");};
        let authority =
            c.hw.asset_enrollment_authority
                .clone()
                .ok_or_else(|| err!(EACCES, "ASSET_AUTHORITY_REQUIRED"))?;
        let policy = authority.policy(ledger.policy_floor, c.clock.now_unix())?;
        let primary = receipt.clone().activate(
            source.evidence.clone(),
            &policy,
            &authority.inventory_issuer,
            ledger.receipt_floor,
            c.clock.now_unix(),
        )?;
        if c.hw
            .credential
            .as_ref()
            .map(enclave_core::jcs::to_jcs_bytes)
            .transpose()?
            != Some(enclave_core::jcs::to_jcs_bytes(&primary)?)
            || binding(&self.lock_sensitive_state()?.vault.checkpoint()?)? != *vault_binding
        {
            fail!(EACCES, "ASSET_ACTIVE_BINDING");
        }
        let simulated = c.hw.simulated;
        let pair =
            c.hw.membership_devices
                .as_mut()
                .ok_or_else(|| err!(EACCES, "MEMBERSHIP_NATIVE_PAIR_REQUIRED"))?;
        pair.require_current(simulated)?;
        pair.require_topology(profile)?;
        let (mut store, loaded) = backup_enrollment_store(&state)?;
        let previous = match loaded {
            Loaded::Fresh => None,
            Loaded::State(bytes) => Some(enclave_core::sealed::decode::<BackupEnrollment>(&bytes)?),
        };
        if let Some(saved) = &previous {
            if saved.version != 3 || saved.attempt == 0 || saved.attempt > INTEGER_LIMIT {
                fail!(EACCES, "ASSET_BACKUP_PENDING_STATE");
            }
            if saved.source_sha256 == source_sha256 && saved.policy_floor == ledger.policy_floor {
                if let BackupEnrollmentPhase::Pending(pending) = &saved.phase {
                    if pending.profile != profile
                        || pending.bio_key_blob.is_empty()
                        || pending.bio_public_key != pending.evidence.sep_public_key
                        || pending.evidence.policy_digest != policy.digest()
                    {
                        fail!(EACCES, "ASSET_BACKUP_PENDING_STATE");
                    }
                    distinct(&primary, pending.evidence.credential())?;
                    let deadline =
                        c.hw.metadata_source
                            .as_ref()
                            .and_then(|source| source.deadline_ns())
                            .map_or(cap, |bound| cap.min(bound));
                    ProofWindow {
                        start_ns: start,
                        start_unix,
                        deadline_ns: deadline,
                        valid_until_unix: receipt.expires_unix,
                    }
                    .check(c.clock.as_ref())?;
                    self.asset_check(generation, deadline)?;
                    c.hw.membership_devices
                        .as_ref()
                        .ok_or_else(|| err!(EACCES, "MEMBERSHIP_NATIVE_PAIR_REQUIRED"))?
                        .require_current(simulated)?;
                    self.attach_setup_release(generation, deadline, receipt.expires_unix)?;
                    return Ok(VaultResponse::AssetEnrollmentPending {
                        pending: pending.evidence.clone(),
                    });
                }
            }
        }
        c.hw.asset_metadata(profile, &primary, c.clock.now_unix())?;
        let mds =
            c.hw.mds
                .clone()
                .ok_or_else(|| err!(EACCES, "CUSTODY_METADATA_UNAVAILABLE"))?;
        let deadline =
            c.hw.metadata_source
                .as_ref()
                .and_then(|source| source.deadline_ns())
                .map_or(cap, |bound| cap.min(bound));
        self.asset_check(generation, deadline)?;
        let mut nonce = [0; 32];
        enclave_core::rng::fill(&mut nonce);
        let mut saved = BackupEnrollment {
            version: 3,
            source_sha256,
            attempt: advance(previous.as_ref().map_or(0, |saved| saved.attempt))?,
            policy_floor: ledger.policy_floor,
            phase: BackupEnrollmentPhase::Preparing {
                nonce_sha256: Sha256::digest(nonce).into(),
            },
        };
        store.save_json(&saved)?;
        self.asset_check(generation, deadline)?;
        let prompt = BiometricPrompt {
            localized_reason: policy.localized_reason(),
            d_jcs: policy.digest().to_vec(),
            nonce: nonce.to_vec(),
            t_start_ns: start,
            bio_key_blob: vec![],
        };
        let outcome = c.hw.biometric.evaluate(&prompt);
        self.asset_check(generation, deadline)?;
        let (bio_public_key, bio_key_blob) = match &outcome {
            BiometricOutcome::Approved {
                enrolled_pubkey: Some(key),
                enrolled_blob: Some(blob),
                ..
            } if !blob.is_empty() => (key.clone(), blob.clone()),
            _ => {
                fail!(EACCES, "ASSET_BIOMETRIC_ENROLLMENT_REQUIRED");
            }
        };
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&bio_public_key)
            .map_err(|_| err!(EACCES, "ASSET_BIOMETRIC_KEY"))?;
        let disclosure = VerifiedSetupDisclosure::verify(&policy, &key, &prompt, &outcome)?;
        let hw = &mut c.hw;
        let pair = hw
            .membership_devices
            .as_mut()
            .ok_or_else(|| err!(EACCES, "MEMBERSHIP_NATIVE_PAIR_REQUIRED"))?;
        pair.require_current(simulated)?;
        let mut client = CtapClient::open_with_deadline(pair.member(1)?, deadline)?;
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
            c.clock.as_ref(),
            &self.ceremony_cancelled,
            Some(&mut pin),
            |evidence| {
                saved.phase = BackupEnrollmentPhase::Pending(Pending {
                    evidence: evidence.clone(),
                    bio_public_key: bio_public_key.clone(),
                    bio_key_blob: bio_key_blob.clone(),
                    policy_revision: ledger.policy_floor,
                    profile,
                });
                store.save_json(&saved)
            },
        )?;
        drop(client);
        pair.require_current(simulated)?;
        self.asset_check(generation, deadline)?;
        distinct(&primary, evidence.credential())?;
        let (_, current) = open(&state)?;
        if backup_source_pin(&current)? != source_sha256 {
            fail!(ESTALE, "ASSET_MEMBERSHIP_SOURCE_CHANGED");
        }
        let current = authority.policy(ledger.policy_floor, c.clock.now_unix())?;
        if current.digest() != policy.digest() {
            fail!(ESTALE, "ASSET_POLICY_CHANGED");
        }
        let valid_until = receipt.expires_unix.min(mds.expires_at).min(
            mds.refreshed_at
                .saturating_add(crate::ctap::mds::freshness_window_s(profile)),
        );
        self.attach_setup_release(generation, deadline, valid_until)?;
        Ok(VaultResponse::AssetEnrollmentPending { pending: evidence })
    }
    pub(in crate::service) fn add_pending_asset_backup(
        &self,
        peer: &PeerCredentials,
        receipt: AssetEnrollmentReceipt,
    ) -> EnclaveResult<VaultResponse> {
        Self::asset_admin(peer)?;
        // Include authority/sidecar I/O in the SAME original complete window.
        let origin = {
            let c = self.lock_sensitive_ceremony()?;
            (c.clock.now_ns(), c.clock.now_unix())
        };
        let (pending, blob) = {
            let state = self
                .lock_sensitive_state()?
                .state_dir
                .clone()
                .ok_or_else(|| err!(EACCES, "ENROLLMENT_STATE_REQUIRED"))?;
            let (_, ledger) = open(&state)?;
            let (_, loaded) = backup_enrollment_store(&state)?;
            let Loaded::State(bytes)=loaded else {fail!(EACCES,"ASSET_BACKUP_PENDING_REQUIRED");};
            let saved: BackupEnrollment = enclave_core::sealed::decode(&bytes)?;
            if saved.version != 3
                || saved.source_sha256 != backup_source_pin(&ledger)?
                || saved.policy_floor > ledger.policy_floor
            {
                fail!(EACCES, "ASSET_BACKUP_PENDING_STATE");
            }
            let BackupEnrollmentPhase::Pending(pending)=saved.phase else {fail!(EACCES,"ASSET_BACKUP_PENDING_REQUIRED");};
            if pending.bio_public_key != pending.evidence.sep_public_key
                || pending.bio_key_blob.is_empty()
                || receipt.pending_sha256 != pending.evidence.digest()?
            {
                fail!(EACCES, "ASSET_BACKUP_PENDING_STATE");
            }
            (pending.evidence, pending.bio_key_blob)
        };
        self.add_asset_backup_at(peer, pending, receipt, blob, Some(origin))
    }
}

/// Authenticated retained content/identity for resuming setup only. The old
/// preparation window and its proof are never revived or deserialized as live.
pub struct ValidatedMembershipSetup {
    preparation: PreparingMembership,
    checkpoint: crate::vault::VaultEnvelopeCheckpoint,
}
impl std::fmt::Debug for ValidatedMembershipSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatedMembershipSetup")
            .field("attempt", &self.preparation.attempt)
            .finish_non_exhaustive()
    }
}
impl ValidatedMembershipSetup {
    /// Original primary identity, solely for fresh setup factor verification.
    pub fn enrolled(&self) -> EnrolledCustodyState {
        let p = &self.preparation.source.pending;
        EnrolledCustodyState {
            credential: p.evidence.credential().clone(),
            bio_public_key: p.bio_public_key.clone(),
            bio_key_blob: p.bio_key_blob.clone(),
        }
    }
    /// Original v2 wrapper identity, retaining its exact historical meaning.
    pub fn source_binding(&self) -> [u8; 32] {
        self.preparation.source.vault_binding
    }
    /// Exact retained current content at the original preparation fence.
    pub fn checkpoint(&self) -> &crate::vault::VaultEnvelopeCheckpoint {
        &self.checkpoint
    }
}
/// Explicit sterile restart reader, distinct from either active reader. The
/// protected source lets a NEW attempt verify fresh factors and a newer receipt;
/// it cannot create an ActiveAssetGuard or enable ordinary custody.
pub fn load_native_membership_setup(
    state: &Path,
    authority: Option<&AssetEnrollmentAuthority>,
    profile: Profile,
    now: i64,
) -> EnclaveResult<Option<ValidatedMembershipSetup>> {
    let (_, ledger) = open(state)?;
    match &ledger.phase {
        Phase::MembershipCommitted { record } => {
            validate_committed_counters(state, record)?;
            let complete = load_complete(state, record)?;
            if record.preparation.profile != profile {
                fail!(EACCES, "ASSET_LEDGER_BINDING");
            }
            let authority = authority.ok_or_else(|| err!(EACCES, "ASSET_AUTHORITY_REQUIRED"))?;
            if !verify_record_authority(record, authority, now, true)? {
                return Ok(None);
            }
            return Ok(Some(ValidatedMembershipSetup {
                preparation: record.preparation.clone(),
                checkpoint: complete.primary,
            }));
        }
        Phase::MembershipRenewing { renewal, .. } => {
            validate_renewal_pins(state, renewal)?;
            if renewal.previous.preparation.profile != profile {
                fail!(EACCES, "ASSET_LEDGER_BINDING");
            }
            let authority = authority.ok_or_else(|| err!(EACCES, "ASSET_AUTHORITY_REQUIRED"))?;
            verify_record_authority(&renewal.previous, authority, now, true)?;
            verify_renewed_authority(&renewal.previous, &renewal.authority, authority, now, true)?;
            let complete = load_complete(state, &renewal.previous)?;
            return Ok(Some(ValidatedMembershipSetup {
                preparation: renewal.previous.preparation.clone(),
                checkpoint: complete.primary,
            }));
        }
        Phase::MembershipPreparing { .. } => {}
        _ => return Ok(None),
    }
    let Phase::MembershipPreparing {preparation:p,..}=&ledger.phase else {unreachable!()};
    validate_saved_pins(state, &ledger)?;
    if p.profile != profile {
        fail!(EACCES, "ASSET_LEDGER_BINDING");
    }
    let authority = authority.ok_or_else(|| err!(EACCES, "ASSET_AUTHORITY_REQUIRED"))?;
    if p.host != authority.host
        || p.asset != authority.asset
        || p.custodian != authority.custodian
        || p.policy_issuer != authority.policy_issuer.to_bytes()
        || p.inventory_issuer != authority.inventory_issuer.to_bytes()
    {
        fail!(EACCES, "ASSET_MEMBERSHIP_SOURCE_CHANGED");
    }
    let policy = authority.policy(p.policy_revision, now)?;
    if policy.digest() != p.policy_digest {
        fail!(ESTALE, "ASSET_POLICY_CHANGED");
    }
    // Expired evidence may authenticate retained setup identity only. It cannot
    // authorize a new admission: preparation independently rechecks NOW and
    // requires a receipt strictly above the durable consumed floor.
    let historical_time = |receipt: &AssetEnrollmentReceipt| -> EnclaveResult<i64> {
        if now >= receipt.expires_unix {
            receipt
                .expires_unix
                .checked_sub(1)
                .ok_or_else(|| err!(EACCES, "ASSET_ENROLLMENT_RECEIPT"))
        } else {
            Ok(now)
        }
    };
    p.source.receipt.clone().activate(
        p.source.pending.evidence.clone(),
        &policy,
        &authority.inventory_issuer,
        p.source.receipt_floor,
        historical_time(&p.source.receipt)?,
    )?;
    p.backup.receipt.clone().activate(
        p.backup.pending.clone(),
        &policy,
        &authority.inventory_issuer,
        p.backup.receipt.generation,
        historical_time(&p.backup.receipt)?,
    )?;
    let (_, loaded) = content_store(state)?;
    let Loaded::State(bytes)=loaded else {fail!(EACCES,"ASSET_MEMBERSHIP_CONTENT_REQUIRED");};
    let checkpoint: crate::vault::VaultEnvelopeCheckpoint = enclave_core::sealed::decode(&bytes)?;
    Ok(Some(ValidatedMembershipSetup {
        preparation: p.clone(),
        checkpoint,
    }))
}

/// Current authority can advance without changing the original wrapper/member
/// identity. Older receipts/plan remain retained; every new pair advances both
/// the global receipt floor and membership generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RenewedAuthority {
    primary_receipt: AssetEnrollmentReceipt,
    backup_receipt: AssetEnrollmentReceipt,
    previous_receipt_floor: u64,
    previous_attempt: u64,
    attempt: u64,
}
impl RenewedAuthority {
    fn shape(&self, p: &PreparingMembership) -> EnclaveResult<()> {
        if self.previous_receipt_floor < p.backup.receipt.generation
            || self.previous_attempt < p.attempt
            || self.attempt <= self.previous_attempt
            || self.attempt > INTEGER_LIMIT
            || self.primary_receipt.generation <= self.previous_receipt_floor
            || self.backup_receipt.generation <= self.primary_receipt.generation
            || self.backup_receipt.generation > INTEGER_LIMIT
            || self.primary_receipt.pending_sha256 != p.source.pending.evidence.digest()?
            || self.backup_receipt.pending_sha256 != p.backup.pending.digest()?
        {
            fail!(EACCES, "ASSET_MEMBERSHIP_RENEWAL_STATE");
        }
        Ok(())
    }
}
impl CommittedMembership {
    fn receipts(&self) -> (&AssetEnrollmentReceipt, &AssetEnrollmentReceipt) {
        self.renewed.as_ref().map_or(
            (
                &self.preparation.source.receipt,
                &self.preparation.backup.receipt,
            ),
            |r| (&r.primary_receipt, &r.backup_receipt),
        )
    }
    fn attempt(&self) -> u64 {
        self.renewed
            .as_ref()
            .map_or(self.preparation.attempt, |r| r.attempt)
    }
    fn receipt_floor(&self) -> u64 {
        self.receipts().1.generation
    }
    fn validate_renewed(&self) -> EnclaveResult<()> {
        if let Some(r) = &self.renewed {
            r.shape(&self.preparation)?;
        }
        Ok(())
    }
}
fn receipt_time(
    receipt: &AssetEnrollmentReceipt,
    now: i64,
    historical: bool,
) -> EnclaveResult<i64> {
    if historical && now >= receipt.expires_unix {
        receipt
            .expires_unix
            .checked_sub(1)
            .ok_or_else(|| err!(EACCES, "ASSET_ENROLLMENT_RECEIPT"))
    } else {
        Ok(now)
    }
}
fn current_membership_policy(
    p: &PreparingMembership,
    authority: &AssetEnrollmentAuthority,
    now: i64,
) -> EnclaveResult<VerifiedAssetEnrollmentPolicy> {
    if p.host != authority.host
        || p.asset != authority.asset
        || p.custodian != authority.custodian
        || p.policy_issuer != authority.policy_issuer.to_bytes()
        || p.inventory_issuer != authority.inventory_issuer.to_bytes()
    {
        fail!(EACCES, "ASSET_MEMBERSHIP_SOURCE_CHANGED");
    }
    let policy = authority.policy(p.policy_revision, now)?;
    if policy.digest() != p.policy_digest {
        fail!(ESTALE, "ASSET_POLICY_CHANGED");
    }
    Ok(policy)
}
fn verify_receipt_pair(
    p: &PreparingMembership,
    primary: &AssetEnrollmentReceipt,
    backup: &AssetEnrollmentReceipt,
    policy: &VerifiedAssetEnrollmentPolicy,
    issuer: &VerifyingKey,
    now: i64,
    historical: bool,
) -> EnclaveResult<bool> {
    primary.clone().activate(
        p.source.pending.evidence.clone(),
        policy,
        issuer,
        primary.generation,
        receipt_time(primary, now, historical)?,
    )?;
    backup.clone().activate(
        p.backup.pending.clone(),
        policy,
        issuer,
        backup.generation,
        receipt_time(backup, now, historical)?,
    )?;
    Ok(now >= primary.expires_unix || now >= backup.expires_unix)
}
fn verify_record_authority(
    record: &CommittedMembership,
    authority: &AssetEnrollmentAuthority,
    now: i64,
    historical: bool,
) -> EnclaveResult<bool> {
    record.validate_renewed()?;
    let p = &record.preparation;
    let policy = current_membership_policy(p, authority, now)?;
    // Authenticate preserved original history as well as effective current
    // authority; expected expiry never swallows corruption or a bad signature.
    if record.renewed.is_some() {
        verify_receipt_pair(
            p,
            &p.source.receipt,
            &p.backup.receipt,
            &policy,
            &authority.inventory_issuer,
            now,
            true,
        )?;
    }
    let (primary, backup) = record.receipts();
    verify_receipt_pair(
        p,
        primary,
        backup,
        &policy,
        &authority.inventory_issuer,
        now,
        historical,
    )
}
fn verify_renewed_authority(
    previous: &CommittedMembership,
    renewed: &RenewedAuthority,
    authority: &AssetEnrollmentAuthority,
    now: i64,
    historical: bool,
) -> EnclaveResult<bool> {
    renewed.shape(&previous.preparation)?;
    if renewed.previous_attempt < previous.attempt()
        || renewed.previous_receipt_floor < previous.receipt_floor()
    {
        fail!(EACCES, "ASSET_MEMBERSHIP_RENEWAL_STATE");
    }
    let policy = current_membership_policy(&previous.preparation, authority, now)?;
    verify_receipt_pair(
        &previous.preparation,
        &renewed.primary_receipt,
        &renewed.backup_receipt,
        &policy,
        &authority.inventory_issuer,
        now,
        historical,
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RenewingMembership {
    previous: CommittedMembership,
    authority: RenewedAuthority,
    selected_index: usize,
    generation: u64,
    content_sha256: [u8; 32],
    counter_sha256: [u8; 32],
    start_ns: u64,
    start_unix: i64,
    deadline_ns: u64,
    valid_until_unix: i64,
}
impl RenewingMembership {
    fn digest(&self) -> EnclaveResult<[u8; 32]> {
        digest(b"depot-MembershipRenewalPreparing-v3\0", self)
    }
    fn window(&self) -> ProofWindow {
        ProofWindow {
            start_ns: self.start_ns,
            start_unix: self.start_unix,
            deadline_ns: self.deadline_ns,
            valid_until_unix: self.valid_until_unix,
        }
    }
    fn factor_context(&self) -> PreparingMembership {
        // This ephemeral factor context is neither persisted nor accepted by
        // the initial-admission validator. It supplies the unchanged member
        // keys/blobs and NEW original operation window to existing full chains.
        let mut p = self.previous.preparation.clone();
        p.generation = self.generation;
        p.attempt = self.authority.attempt;
        p.source.receipt = self.authority.primary_receipt.clone();
        p.source.receipt_floor = p.source.receipt.generation;
        p.backup.receipt = self.authority.backup_receipt.clone();
        p.start_ns = self.start_ns;
        p.start_unix = self.start_unix;
        p.deadline_ns = self.deadline_ns;
        p.valid_until_unix = self.valid_until_unix;
        p
    }
}
fn committed_ledger(record: &CommittedMembership) -> Ledger {
    Ledger {
        version: 3,
        attempt: record.attempt(),
        policy_floor: record.preparation.policy_revision,
        receipt_floor: record.receipt_floor(),
        phase: Phase::MembershipCommitted {
            record: record.clone(),
        },
    }
}
fn validate_renewing(ledger: &Ledger, r: &RenewingMembership, plan: [u8; 32]) -> EnclaveResult<()> {
    validate_v3(&committed_ledger(&r.previous))?;
    r.authority.shape(&r.previous.preparation)?;
    if ledger.version != 3
        || ledger.attempt != r.authority.attempt
        || ledger.receipt_floor != r.authority.backup_receipt.generation
        || ledger.policy_floor != r.previous.preparation.policy_revision
        || r.authority.previous_attempt < r.previous.attempt()
        || r.authority.previous_receipt_floor < r.previous.receipt_floor()
        || r.selected_index > 1
        || r.generation == u64::MAX
        || r.start_unix < 0
        || r.valid_until_unix <= r.start_unix
        || r.deadline_ns <= r.start_ns
        || r.deadline_ns - r.start_ns > crate::ceremony::CEREMONY_BUDGET_NS
        || r.valid_until_unix > r.authority.primary_receipt.expires_unix
        || r.valid_until_unix > r.authority.backup_receipt.expires_unix
        || r.digest()? != plan
    {
        fail!(EACCES, "ASSET_MEMBERSHIP_RENEWAL_STATE");
    }
    Ok(())
}
fn validate_renewal_pins(state: &Path, r: &RenewingMembership) -> EnclaveResult<()> {
    validate_committed_counters(state, &r.previous)?;
    let complete = load_complete(state, &r.previous)?;
    if digest(b"depot-MembershipContent-v3\0", &complete.primary)? != r.content_sha256 {
        fail!(EACCES, "ASSET_MEMBERSHIP_CONTENT_PIN");
    }
    let (_, loaded) = counter_baseline_store(state, &r.counter_sha256)?;
    let Loaded::State(bytes)=loaded else {fail!(EACCES,"ASSET_MEMBERSHIP_COUNTER_PIN");};
    let baseline: SignCountStore = enclave_core::sealed::decode(&bytes)?;
    let (_, loaded) = SealedStore::open_bounded_required(state, "signcount", CONTENT_LIMIT)?;
    let Loaded::State(bytes)=loaded else {fail!(EACCES,"SIGN_COUNT_STATE");};
    let current: SignCountStore = enclave_core::sealed::decode(&bytes)?;
    if digest(b"depot-MembershipCounters-v3\0", &baseline)? != r.counter_sha256
        || !current.dominates(&baseline)
    {
        fail!(EACCES, "ASSET_MEMBERSHIP_COUNTER_PIN");
    }
    Ok(())
}
fn check_renewal_context(
    r: &RenewingMembership,
    authority: &AssetEnrollmentAuthority,
    complete: &CompleteMembershipCheckpoint,
    context: &VerifiedEnvelopeContext,
    now: i64,
) -> EnclaveResult<()> {
    verify_record_authority(&r.previous, authority, now, true)?;
    verify_renewed_authority(&r.previous, &r.authority, authority, now, false)?;
    let p = &r.previous.preparation;
    complete.backup.validate_scope(
        &complete.primary,
        p.source.pending.evidence.credential(),
        p.backup.pending.credential(),
        context,
        now,
    )?;
    if digest(b"depot-MembershipContent-v3\0", &complete.primary)? != r.content_sha256 {
        fail!(EACCES, "ASSET_MEMBERSHIP_CONTENT_PIN");
    }
    Ok(())
}
pub(super) struct MembershipRenewalPreparation {
    renewal: RenewingMembership,
    plan_sha256: [u8; 32],
}
pub(super) struct VerifiedMembershipRenewal {
    renewal: RenewingMembership,
    plan_sha256: [u8; 32],
    window: ProofWindow,
    counter_sha256: [u8; 32],
}

fn save_counter_snapshot(state: &Path, counters: &SignCountStore) -> EnclaveResult<[u8; 32]> {
    let hash = digest(b"depot-MembershipCounters-v3\0", counters)?;
    let (mut store, loaded) = counter_baseline_store(state, &hash)?;
    match loaded {
        Loaded::Fresh => store.save_json(counters)?,
        Loaded::State(bytes) => {
            if enclave_core::sealed::decode::<SignCountStore>(&bytes)? != *counters {
                fail!(EACCES, "ASSET_MEMBERSHIP_COUNTER_PIN");
            }
        }
    }
    Ok(hash)
}
fn require_durable_counters(state: &Path, counters: &SignCountStore) -> EnclaveResult<()> {
    let (_, loaded) = SealedStore::open_bounded_required(state, "signcount", CONTENT_LIMIT)?;
    let Loaded::State(bytes)=loaded else {fail!(EACCES,"SIGN_COUNT_STATE");};
    if enclave_core::sealed::decode::<SignCountStore>(&bytes)? != *counters {
        fail!(EACCES, "ASSET_MEMBERSHIP_COUNTER_PIN");
    }
    Ok(())
}
fn selected_record_member(c: &Ceremony, record: &CommittedMembership) -> EnclaveResult<usize> {
    let p = &record.preparation;
    for (index, credential, key, blob) in [
        (
            0,
            p.source.pending.evidence.credential(),
            &p.source.pending.bio_public_key,
            &p.source.pending.bio_key_blob,
        ),
        (
            1,
            p.backup.pending.credential(),
            &p.backup.pending.sep_public_key,
            &p.backup_bio_blob,
        ),
    ] {
        if c.hw
            .credential
            .as_ref()
            .map(enclave_core::jcs::to_jcs_bytes)
            .transpose()?
            == Some(enclave_core::jcs::to_jcs_bytes(credential)?)
            && c.hw.sep_bio_key.to_encoded_point(false).as_bytes() == key.as_slice()
            && c.hw.sep_bio_blob.as_ref() == Some(blob)
        {
            return Ok(index);
        }
    }
    Err(err!(EACCES, "ASSET_ACTIVE_BINDING"))
}
impl VaultService {
    pub(in crate::service) fn renew_asset_membership(
        &self,
        peer: &PeerCredentials,
        primary_receipt: AssetEnrollmentReceipt,
        backup_receipt: AssetEnrollmentReceipt,
    ) -> EnclaveResult<VaultResponse> {
        let prepared = self.prepare_membership_renewal(peer, primary_receipt, backup_receipt)?;
        let verified = self.verify_membership_renewal(prepared)?;
        self.commit_membership_renewal(verified)
    }
    pub(super) fn prepare_membership_renewal(
        &self,
        peer: &PeerCredentials,
        primary_receipt: AssetEnrollmentReceipt,
        backup_receipt: AssetEnrollmentReceipt,
    ) -> EnclaveResult<MembershipRenewalPreparation> {
        Self::asset_admin(peer)?;
        let mut ceremony = self.lock_sensitive_ceremony()?;
        let c = &mut *ceremony;
        // Includes every authoritative read and both complete factor chains.
        let start_ns = c.clock.now_ns();
        let start_unix = c.clock.now_unix();
        let cap = start_ns
            .checked_add(crate::ceremony::CEREMONY_BUDGET_NS)
            .ok_or_else(|| err!(ETIMEDOUT, "ASSET_MEMBERSHIP_DEADLINE"))?;
        let (state, profile) = {
            let st = self.lock_sensitive_state()?;
            (
                st.state_dir
                    .clone()
                    .ok_or_else(|| err!(EACCES, "ENROLLMENT_STATE_REQUIRED"))?,
                st.profile,
            )
        };
        if profile == Profile::L1 {
            fail!(EPERM, "ENROLL_NOT_APPLICABLE_L1");
        }
        let _publication = PublicationLease::acquire(&state)?;
        let (mut store, ledger) = open(&state)?;
        let previous = match &ledger.phase {
            Phase::MembershipCommitted { record } => record.clone(),
            Phase::MembershipRenewing { renewal, .. } => {
                validate_renewal_pins(&state, renewal)?;
                renewal.previous.clone()
            }
            _ => {
                fail!(EACCES, "ASSET_MEMBERSHIP_COMMITTED_REQUIRED");
            }
        };
        if previous.preparation.profile != profile {
            fail!(EACCES, "ASSET_LEDGER_BINDING");
        }
        validate_committed_counters(&state, &previous)?;
        let complete = load_complete(&state, &previous)?;
        let selected_index = selected_record_member(c, &previous)?;
        let authority =
            c.hw.asset_enrollment_authority
                .clone()
                .ok_or_else(|| err!(EACCES, "ASSET_AUTHORITY_REQUIRED"))?;
        verify_record_authority(&previous, &authority, c.clock.now_unix(), true)?;
        let renewed = RenewedAuthority {
            primary_receipt,
            backup_receipt,
            previous_receipt_floor: ledger.receipt_floor,
            previous_attempt: ledger.attempt,
            attempt: advance(ledger.attempt)?,
        };
        verify_renewed_authority(&previous, &renewed, &authority, c.clock.now_unix(), false)?;
        let pair =
            c.hw.membership_devices
                .as_mut()
                .ok_or_else(|| err!(EACCES, "MEMBERSHIP_NATIVE_PAIR_REQUIRED"))?;
        pair.require_current(c.hw.simulated)?;
        pair.require_topology(profile)?;
        if c.hw.oidc_provider.is_none() {
            fail!(EACCES, "MEMBERSHIP_A4_AUTHORITY_REQUIRED");
        }
        if profile == Profile::L3 && c.hw.egress.is_none() {
            fail!(EACCES, "ZK_EGRESS_GATE_UNAVAILABLE");
        }
        let envelope_authority =
            c.hw.envelope_authority
                .clone()
                .ok_or_else(|| err!(EACCES, "ENVELOPE_POLICY_AUTHORITY_REQUIRED"))?;
        let source =
            c.hw.metadata_source
                .clone()
                .ok_or_else(|| err!(EACCES, "ENVELOPE_POLICY_SOURCE_REQUIRED"))?;
        let context = source.envelope_context(&envelope_authority, profile, c.clock.now_unix())?;
        let p = &previous.preparation;
        complete.backup.validate_scope(
            &complete.primary,
            p.source.pending.evidence.credential(),
            p.backup.pending.credential(),
            &context,
            c.clock.now_unix(),
        )?;
        // Preserve the established lock order: never wait for the final release
        // fence while holding State. The old generation cannot be revived.
        self.revoke_cas_keys()?;
        let generation = self
            .cas_key_generation
            .load(std::sync::atomic::Ordering::SeqCst);
        c.enter_generation(generation);
        c.setup_only = true;
        let mut st = self.lock_sensitive_state()?;
        st.envelope_fault = true;
        st.cas_key_leases.clear();
        st.cas_key_deadlines.clear();
        st.namespace_challenges.clear();
        let (_, current) = open(&state)?;
        if enclave_core::jcs::to_jcs_bytes(&current)? != enclave_core::jcs::to_jcs_bytes(&ledger)? {
            fail!(ESTALE, "ASSET_MEMBERSHIP_REFERENCE_CHANGED");
        }
        let content_sha256 = digest(b"depot-MembershipContent-v3\0", &complete.primary)?;
        if digest(b"depot-MembershipContent-v3\0", &st.vault.checkpoint()?)? != content_sha256 {
            fail!(EACCES, "ASSET_MEMBERSHIP_CONTENT_PIN");
        }
        require_durable_counters(&state, &c.counters)?;
        let counter_sha256 = save_counter_snapshot(&state, &c.counters)?;
        let renewal = RenewingMembership {
            previous,
            authority: renewed,
            selected_index,
            generation,
            content_sha256,
            counter_sha256,
            start_ns,
            start_unix,
            deadline_ns: [Some(cap), context.deadline_ns(), source.deadline_ns()]
                .into_iter()
                .flatten()
                .min()
                .unwrap_or(cap),
            valid_until_unix: context.expires_unix(),
        };
        let mut renewal = renewal;
        renewal.valid_until_unix = renewal
            .valid_until_unix
            .min(renewal.authority.primary_receipt.expires_unix)
            .min(renewal.authority.backup_receipt.expires_unix);
        renewal.window().check(c.clock.as_ref())?;
        let plan_sha256 = renewal.digest()?;
        let next = Ledger {
            version: 3,
            attempt: renewal.authority.attempt,
            policy_floor: renewal.previous.preparation.policy_revision,
            receipt_floor: renewal.authority.backup_receipt.generation,
            phase: Phase::MembershipRenewing {
                renewal: renewal.clone(),
                plan_sha256,
            },
        };
        validate_v3(&next)?;
        store.save_json(&next)?;
        renewal.window().check(c.clock.as_ref())?;
        if self
            .cas_key_generation
            .load(std::sync::atomic::Ordering::SeqCst)
            != generation
        {
            fail!(EACCES, "CAS_ENROLLMENT_REVOKED");
        }
        Ok(MembershipRenewalPreparation {
            renewal,
            plan_sha256,
        })
    }
}

fn renewal_intent(
    r: &RenewingMembership,
    plan: [u8; 32],
    index: usize,
    epoch: &str,
    sequence: u64,
    now: i64,
) -> EnclaveResult<IntentPayloadV1> {
    let mut intent = member_intent(&r.factor_context(), plan, index, epoch, sequence, now)?;
    #[derive(Serialize)]
    struct Arguments {
        operation: &'static str,
        membership_sha256: [u8; 32],
        old_generation: u64,
        new_generation: u64,
        plan_sha256: [u8; 32],
        member_index: usize,
    }
    let args = enclave_core::jcs::to_jcs_bytes(&Arguments {
        operation: "renew-exact-two-member-authority",
        membership_sha256: r.previous.membership_sha256,
        old_generation: r.previous.membership_generation,
        new_generation: r.authority.attempt,
        plan_sha256: plan,
        member_index: index,
    })?;
    intent.tool_name = "depot://custody/renew_membership".into();
    intent.human_summary_trusted=Some(format!("Renew exact {} member authority; preserve both credentials, all wrappers and stored content",if index==0 {"primary"}else{"backup"}));
    intent.arguments_jcs_sha256 = Some(hex::encode(Sha256::digest(&args)));
    intent.canonical_arguments_blake3 = blake3::hash(&args).to_hex().to_string();
    intent.validate()?;
    Ok(intent)
}
impl VaultService {
    pub(super) fn verify_membership_renewal(
        &self,
        prepared: MembershipRenewalPreparation,
    ) -> EnclaveResult<VerifiedMembershipRenewal> {
        let mut ceremony = self.lock_sensitive_ceremony()?;
        let c = &mut *ceremony;
        let r = prepared.renewal;
        let state = self
            .lock_sensitive_state()?
            .state_dir
            .clone()
            .ok_or_else(|| err!(EACCES, "ENROLLMENT_STATE_REQUIRED"))?;
        let (_, ledger) = open(&state)?;
        let Phase::MembershipRenewing {renewal,plan_sha256}=&ledger.phase else {fail!(EACCES,"ASSET_MEMBERSHIP_RENEWAL_STATE");};
        if *plan_sha256 != prepared.plan_sha256
            || r.digest()? != *plan_sha256
            || renewal.digest()? != *plan_sha256
        {
            fail!(EACCES, "ASSET_MEMBERSHIP_RENEWAL_STATE");
        }
        validate_renewal_pins(&state, &r)?;
        require_durable_counters(&state, &c.counters)?;
        let complete = load_complete(&state, &r.previous)?;
        let p = r.factor_context();
        let authority =
            c.hw.asset_enrollment_authority
                .clone()
                .ok_or_else(|| err!(EACCES, "ASSET_AUTHORITY_REQUIRED"))?;
        let envelope_authority =
            c.hw.envelope_authority
                .clone()
                .ok_or_else(|| err!(EACCES, "ENVELOPE_POLICY_AUTHORITY_REQUIRED"))?;
        let source =
            c.hw.metadata_source
                .clone()
                .ok_or_else(|| err!(EACCES, "ENVELOPE_POLICY_SOURCE_REQUIRED"))?;
        let context =
            source.envelope_context(&envelope_authority, p.profile, c.clock.now_unix())?;
        check_renewal_context(&r, &authority, &complete, &context, c.clock.now_unix())?;
        let mut window = r.window();
        window.cap(Some(context.expires_unix()), context.deadline_ns());
        window.check(c.clock.as_ref())?;
        self.prepare_fresh_authorization(r.generation)?;
        c.enter_generation(r.generation);
        let mut devices =
            c.hw.membership_devices
                .take()
                .ok_or_else(|| err!(EACCES, "MEMBERSHIP_NATIVE_PAIR_REQUIRED"))?;
        let result = (|| {
            devices.require_current(c.hw.simulated)?;
            devices.require_topology(p.profile)?;
            // Both actual model/topology/PIN capabilities are diagnosed before
            // spending either full factor chain; signatures authenticate order.
            for index in 0..2 {
                window.check(c.clock.as_ref())?;
                self.asset_check(r.generation, window.deadline_ns)?;
                let credential = if index == 0 {
                    p.source.pending.evidence.credential()
                } else {
                    p.backup.pending.credential()
                };
                c.hw.asset_metadata(p.profile, credential, c.clock.now_unix())?;
                let mut client =
                    CtapClient::open_with_deadline(devices.member(index)?, window.deadline_ns)?;
                let info = client.get_info()?;
                drop(client);
                if info.aaguid != credential.aaguid {
                    fail!(EACCES, "AAGUID_CHANGED");
                }
                c.hw.mds
                    .as_ref()
                    .ok_or_else(|| err!(EACCES, "CUSTODY_METADATA_UNAVAILABLE"))?
                    .check(
                        &info.aaguid,
                        info.firmware_version,
                        credential.key.alg(),
                        p.profile,
                        ActionClass::A4,
                        c.clock.now_unix(),
                    )?;
                if p.profile == Profile::L3 && !info.built_in_uv && c.hw.existing_pin.is_none() {
                    fail!(EACCES, "YUBIKEY_PIN_PROVIDER_REQUIRED");
                }
                devices.require_current(c.hw.simulated)?;
                window.check(c.clock.as_ref())?;
            }
            let mut outputs = Vec::with_capacity(2);
            for index in 0..2 {
                self.asset_check(r.generation, window.deadline_ns)?;
                window.check(c.clock.as_ref())?;
                let (epoch, sequence) = {
                    let mut st = self.lock_sensitive_state()?;
                    Self::begin_governed(&mut st)?
                };
                let intent = renewal_intent(
                    &r,
                    prepared.plan_sha256,
                    index,
                    &epoch,
                    sequence,
                    c.clock.now_unix(),
                )?;
                let (mut grant, prompt) = full_member_ceremony(
                    c,
                    &mut devices,
                    index,
                    &p,
                    &intent,
                    &mut window,
                    &self.ceremony_cancelled,
                )?;
                self.asset_check(r.generation, window.deadline_ns)?;
                grant.check_valid_at(c.clock.now_unix())?;
                grant.check_valid_at_boot(c.clock.now_ns())?;
                grant.consume()?;
                let mut challenge = b"depot-MembershipRenewalDualPrf-v3\0".to_vec();
                challenge.extend(prepared.plan_sha256);
                challenge.extend(grant.d_jcs);
                challenge.extend(&grant.sep_signature);
                challenge.extend((index as u64).to_be_bytes());
                challenge.extend(r.start_ns.to_be_bytes());
                challenge.extend(enclave_core::rng::bytes32());
                let challenge: [u8; 32] = Sha256::digest(challenge).into();
                let credential = if index == 0 {
                    p.source.pending.evidence.credential()
                } else {
                    p.backup.pending.credential()
                };
                let mut salts = [0; 64];
                salts[..32].copy_from_slice(&PrfTier::A3.salt());
                salts[32..].copy_from_slice(&PrfTier::A4.salt());
                devices.require_current(c.hw.simulated)?;
                let mut client =
                    CtapClient::open_with_deadline(devices.member(index)?, window.deadline_ns)?;
                let info = client.get_info()?;
                if info.aaguid != credential.aaguid {
                    fail!(EACCES, "AAGUID_CHANGED");
                }
                let (response, shared) = if p.profile == Profile::L3 && !info.built_in_uv {
                    let provider =
                        c.hw.existing_pin
                            .as_mut()
                            .ok_or_else(|| err!(EACCES, "YUBIKEY_PIN_PROVIDER_REQUIRED"))?;
                    client.get_assertion_dual_prf_with_pin_provider(
                        &credential.credential_id,
                        &challenge,
                        &salts,
                        window.deadline_ns,
                        &self.ceremony_cancelled,
                        || {
                            provider
                                .read_existing_pin_cancellable(&prompt, &self.ceremony_cancelled)
                        },
                    )?
                } else {
                    client.get_assertion_dual_prf(
                        &credential.credential_id,
                        &challenge,
                        p.profile == Profile::L3,
                        &salts,
                    )?
                };
                drop(client);
                let verified = crate::ctap::assertion::verify_assertion(
                    credential,
                    &response,
                    &challenge,
                    p.profile == Profile::L3,
                    &mut c.counters,
                )?;
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
                devices.require_current(c.hw.simulated)?;
                window.check(c.clock.as_ref())?;
                self.asset_check(r.generation, window.deadline_ns)?;
                c.hw.asset_metadata(p.profile, credential, c.clock.now_unix())?;
                window.cap(
                    c.hw.mds.as_ref().map(|mds| {
                        mds.expires_at.min(
                            mds.refreshed_at
                                .saturating_add(crate::ctap::mds::freshness_window_s(p.profile)),
                        )
                    }),
                    c.hw.metadata_source
                        .as_ref()
                        .and_then(|source| source.deadline_ns()),
                );
                let current =
                    source.envelope_context(&envelope_authority, p.profile, c.clock.now_unix())?;
                check_renewal_context(&r, &authority, &complete, &current, c.clock.now_unix())?;
                window.cap(Some(current.expires_unix()), current.deadline_ns());
                window.check(c.clock.as_ref())?;
            }
            let a3 = c.hw.sep.ecdh_share(PrfTier::A3)?;
            window.check(c.clock.as_ref())?;
            self.asset_check(r.generation, window.deadline_ns)?;
            let a4 = c.hw.sep.ecdh_share(PrfTier::A4)?;
            window.check(c.clock.as_ref())?;
            if enclave_core::secret::ct_eq(&outputs[0].expose()[..32], &outputs[0].expose()[32..])
                || enclave_core::secret::ct_eq(
                    &outputs[1].expose()[..32],
                    &outputs[1].expose()[32..],
                )
                || enclave_core::secret::ct_eq(
                    &outputs[0].expose()[..32],
                    &outputs[1].expose()[..32],
                )
                || enclave_core::secret::ct_eq(
                    &outputs[0].expose()[32..],
                    &outputs[1].expose()[32..],
                )
            {
                fail!(EACCES, "MEMBERSHIP_INDEPENDENT_PRF_REQUIRED");
            }
            let source_a3 = KekShares {
                sep_ecdh_share: a3.expose(),
                yubikey_prf: &outputs[0].expose()[..32],
            };
            let source_a4 = KekShares {
                sep_ecdh_share: a4.expose(),
                yubikey_prf: &outputs[0].expose()[32..],
            };
            let backup_a3 = KekShares {
                sep_ecdh_share: a3.expose(),
                yubikey_prf: &outputs[1].expose()[..32],
            };
            let backup_a4 = KekShares {
                sep_ecdh_share: a4.expose(),
                yubikey_prf: &outputs[1].expose()[32..],
            };
            // Re-prove actual possession of ALL existing source and backup
            // hybrid keys. No wrapper is regenerated or replaced by renewal.
            let source_wrappers = complete
                .primary
                .backup_source(&context, c.clock.now_unix())?;
            for wrapped in &source_wrappers.a3 {
                enclave_crypto::hpke_envelope::verify_tier_wrapping::<
                    enclave_crypto::hpke_envelope::A3,
                >(wrapped, &source_a3)?;
            }
            enclave_crypto::hpke_envelope::verify_tier_wrapping::<enclave_crypto::hpke_envelope::A4>(
                &source_wrappers.a4,
                &source_a4,
            )?;
            complete.backup.verify(
                &complete.primary,
                p.source.pending.evidence.credential(),
                p.backup.pending.credential(),
                &backup_a3,
                &backup_a4,
                &context,
                c.clock.now_unix(),
            )?;
            devices.require_current(c.hw.simulated)?;
            self.asset_check(r.generation, window.deadline_ns)?;
            let current =
                source.envelope_context(&envelope_authority, p.profile, c.clock.now_unix())?;
            check_renewal_context(&r, &authority, &complete, &current, c.clock.now_unix())?;
            window.cap(Some(current.expires_unix()), current.deadline_ns());
            window.check(c.clock.as_ref())?;
            let (_, current) = open(&state)?;
            validate_renewal_pins(&state, &r)?;
            let Phase::MembershipRenewing {plan_sha256,..}=current.phase else {fail!(EACCES,"ASSET_MEMBERSHIP_RENEWAL_STATE");};
            if plan_sha256 != prepared.plan_sha256 {
                fail!(EACCES, "ASSET_MEMBERSHIP_RENEWAL_STATE");
            }
            require_durable_counters(&state, &c.counters)?;
            let counter_sha256 = digest(b"depot-MembershipCounters-v3\0", &c.counters)?;
            window.check(c.clock.as_ref())?;
            self.asset_check(r.generation, window.deadline_ns)?;
            Ok(VerifiedMembershipRenewal {
                renewal: r,
                plan_sha256: prepared.plan_sha256,
                window,
                counter_sha256,
            })
        })();
        c.hw.membership_devices = Some(devices);
        result
    }
    pub(super) fn commit_membership_renewal(
        &self,
        verified: VerifiedMembershipRenewal,
    ) -> EnclaveResult<VaultResponse> {
        let mut ceremony = self.lock_sensitive_ceremony()?;
        let c = &mut *ceremony;
        let r = &verified.renewal;
        verified.window.check(c.clock.as_ref())?;
        self.asset_check(r.generation, verified.window.deadline_ns)?;
        let state = self
            .lock_sensitive_state()?
            .state_dir
            .clone()
            .ok_or_else(|| err!(EACCES, "ENROLLMENT_STATE_REQUIRED"))?;
        let publication = PublicationLease::acquire(&state)?;
        let (mut store, mut ledger) = open(&state)?;
        let Phase::MembershipRenewing {renewal,plan_sha256}=&ledger.phase else {fail!(EACCES,"ASSET_MEMBERSHIP_RENEWAL_STATE");};
        if *plan_sha256 != verified.plan_sha256
            || renewal.digest()? != verified.plan_sha256
            || r.digest()? != verified.plan_sha256
            || digest(b"depot-MembershipCounters-v3\0", &c.counters)? != verified.counter_sha256
        {
            fail!(EACCES, "ASSET_MEMBERSHIP_RENEWAL_STATE");
        }
        validate_renewal_pins(&state, r)?;
        require_durable_counters(&state, &c.counters)?;
        let authority =
            c.hw.asset_enrollment_authority
                .clone()
                .ok_or_else(|| err!(EACCES, "ASSET_AUTHORITY_REQUIRED"))?;
        let envelope_authority =
            c.hw.envelope_authority
                .clone()
                .ok_or_else(|| err!(EACCES, "ENVELOPE_POLICY_AUTHORITY_REQUIRED"))?;
        let source =
            c.hw.metadata_source
                .clone()
                .ok_or_else(|| err!(EACCES, "ENVELOPE_POLICY_SOURCE_REQUIRED"))?;
        let context = source.envelope_context(
            &envelope_authority,
            r.previous.preparation.profile,
            c.clock.now_unix(),
        )?;
        let previous = load_complete(&state, &r.previous)?;
        check_renewal_context(r, &authority, &previous, &context, c.clock.now_unix())?;
        if selected_record_member(c, &r.previous)? != r.selected_index {
            fail!(EACCES, "ASSET_ACTIVE_BINDING");
        }
        let devices =
            c.hw.membership_devices
                .as_mut()
                .ok_or_else(|| err!(EACCES, "MEMBERSHIP_NATIVE_PAIR_REQUIRED"))?;
        devices.require_current(c.hw.simulated)?;
        devices.require_topology(r.previous.preparation.profile)?;
        let mut st = self.lock_sensitive_state()?;
        let checkpoint = st.vault.checkpoint()?;
        if digest(b"depot-MembershipContent-v3\0", &checkpoint)? != r.content_sha256 {
            fail!(EACCES, "ASSET_MEMBERSHIP_CONTENT_PIN");
        }
        let mut record = r.previous.clone();
        record.renewed = Some(r.authority.clone());
        record.membership_generation = r.authority.attempt;
        record.sequence = advance(record.sequence)?;
        record.counter_sha256 = save_counter_snapshot(&state, &c.counters)?;
        if record.counter_sha256 != verified.counter_sha256 {
            fail!(EACCES, "ASSET_MEMBERSHIP_COUNTER_PIN");
        }
        let complete = CompleteMembershipCheckpoint {
            version: 3,
            membership_sha256: record.membership_sha256,
            membership_generation: record.membership_generation,
            sequence: record.sequence,
            primary: checkpoint,
            backup: previous.backup,
        };
        record.checkpoint_sha256 = save_complete(&state, &complete)?;
        let active = ValidatedNativeMembership {
            record: record.clone(),
            complete,
        };
        let guard = active.guard(state.clone(), authority, r.selected_index)?;
        verified.window.check(c.clock.as_ref())?;
        self.asset_check(r.generation, verified.window.deadline_ns)?;
        ledger.phase = Phase::MembershipCommitted {
            record: record.clone(),
        };
        validate_v3(&ledger)?;
        publication.publish(&mut store, &ledger, Some(&r.previous), &[])?;
        // Durable authority is never a live factor grant. Post-save expiry or
        // cancellation leaves the service's existing sterile latch in place.
        verified.window.check(c.clock.as_ref())?;
        self.asset_check(r.generation, verified.window.deadline_ns)?;
        let _release = self
            .cas_key_release
            .try_lock()
            .map_err(|error| match error {
                std::sync::TryLockError::WouldBlock => err!(EAGAIN, "CUSTODY_RELEASE_BUSY"),
                std::sync::TryLockError::Poisoned(_) => err!(EIO, "CAS_RELEASE_LOCK"),
            })?;
        verified.window.check(c.clock.as_ref())?;
        self.asset_check(r.generation, verified.window.deadline_ns)?;
        guard.check_release(c.clock.now_unix())?;
        let membership_id = hex::encode(record.membership_sha256);
        let generation = record.membership_generation;
        let profile = record.preparation.profile;
        st.membership_checkpoint = Some(record);
        st.active_asset_guard = Some(guard.clone());
        c.hw.active_asset_guard = Some(guard);
        st.envelope_fault = false;
        st.envelope_store = None;
        c.setup_only = false;
        st.envelope_policy_digest = Some(context.digest());
        st.envelope_valid_until_unix = Some(context.policy_expires_unix());
        st.envelope_deadline_ns = context.deadline_ns();
        st.envelope_policy_source = Some(source);
        st.envelope_authority = Some(envelope_authority);
        let mut lifecycle = CustodyLifecycle::boot(profile);
        if profile == Profile::L2 {
            lifecycle.on(CustodyEvent::PublicIngestInit)?;
        }
        st.lifecycle = lifecycle;
        self.cas_enrolled_generation
            .store(r.generation, std::sync::atomic::Ordering::SeqCst);
        self.cas_keys_enabled
            .store(true, std::sync::atomic::Ordering::SeqCst);
        drop(_release);
        self.attach_lifecycle_release(
            r.generation,
            Some(verified.window.deadline_ns),
            Some(verified.window.valid_until_unix),
            st.active_asset_guard.clone(),
        )?;
        Ok(VaultResponse::AssetMembershipRenewed {
            membership_id,
            generation,
        })
    }
}

/// Authenticated current pair for factor-free denial only. No guard or live
/// factor is constructed, and expired member receipts authenticate history.
pub(super) struct MemberLossContext {
    pub(super) members: [EnrolledCustodyState; 2],
    pub(super) pendings: [PendingAssetEnrollment; 2],
    pub(super) receipts: [AssetEnrollmentReceipt; 2],
    pub(super) bindings: [crate::membership_retirement::RetirementBinding; 2],
    pub(super) policy_expires_unix: i64,
    pub(super) checkpoint: crate::vault::VaultEnvelopeCheckpoint,
    pub(super) alternate: crate::backup_envelope::StagedBackupEnvelopes,
}
pub(super) fn member_loss_context(
    state: &Path,
    ledger: &Ledger,
    authority: &AssetEnrollmentAuthority,
    profile: Profile,
    lower: i64,
    upper: i64,
) -> EnclaveResult<MemberLossContext> {
    use crate::membership_retirement::{RetirementBinding, RetirementIdentity};
    validate_v3_pins(state, ledger)?;
    let Phase::MembershipCommitted {record}=&ledger.phase else {fail!(EACCES,"MEMBER_LOSS_COMMITTED_REQUIRED");};
    if record.preparation.profile != profile {
        fail!(EACCES, "ASSET_LEDGER_BINDING");
    }
    let signed: SignedAssetEnrollmentPolicy = serde_json::from_slice(&read_asset_authority_file(
        &authority.policy_file,
        16 * 1024,
    )?)
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
    if policy.digest() != record.preparation.policy_digest {
        fail!(ESTALE, "ASSET_POLICY_CHANGED");
    }
    verify_record_authority(record, authority, upper, true)?;
    let complete = load_complete(state, record)?;
    let active = ValidatedNativeMembership {
        record: record.clone(),
        complete: complete.clone(),
    };
    let members = [active.enrolled(0)?, active.enrolled(1)?];
    let identities = [
        RetirementIdentity::from_credential(&members[0].credential)?,
        RetirementIdentity::from_credential(&members[1].credential)?,
    ];
    let make = |target: usize| RetirementBinding {
        profile,
        source_v2_binding: record.preparation.source.vault_binding,
        pool_sha256: record.preparation.pool_digest,
        membership_id: record.membership_sha256,
        membership_generation: record.membership_generation,
        complete_sha256: record.checkpoint_sha256,
        complete_sequence: record.sequence,
        policy_sha256: policy.digest(),
        policy_revision: ledger.policy_floor,
        receipt_floor: ledger.receipt_floor,
        target: identities[target].clone(),
        survivor: identities[1 - target].clone(),
    };
    let (primary_receipt, backup_receipt) = record.receipts();
    let pendings = [
        record.preparation.source.pending.evidence.clone(),
        record.preparation.backup.pending.clone(),
    ];
    let receipts = [primary_receipt.clone(), backup_receipt.clone()];
    Ok(MemberLossContext {
        members,
        pendings,
        receipts,
        bindings: [make(0), make(1)],
        policy_expires_unix: signed.policy.expires_unix,
        checkpoint: complete.primary,
        alternate: complete.backup,
    })
}
