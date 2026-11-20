//! Inactive version-3 two-credential membership staging.
//!
//! This journal is NOT an activation authority. Native adoption must explicitly
//! upgrade the SAME authoritative asset-workflow store to version 3, preserve
//! the old v2 binding, fence old grants and reference one complete checkpoint.
//! No boot/RPC path consumes this module. Persisted candidates and independently
//! signed inventory receipts do not replace fresh D2/CTAP factor ceremonies.
use crate::{
    backup_envelope::StagedBackupEnvelopes,
    clock::Clock,
    ctap::{assertion::{CredentialKey, EnrolledCredential}, asset_enrollment::{
        AssetEnrollmentReceipt, PendingAssetEnrollment, SignedAssetEnrollmentPolicy,
        VerifiedAssetEnrollmentPolicy,
    }},
    service::{read_asset_authority_file, AssetEnrollmentAuthority},
    vault::VaultEnvelopeCheckpoint,
};
use enclave_core::{err, error::EnclaveResult, fail, profile::Profile, secret::ct_eq,
    sealed::{Loaded, SealedStore, StateDirectoryLease}};
use enclave_crypto::hpke_envelope::{verify_tier_wrapping, A3, A4, KekShares, VerifiedEnvelopeContext};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

const VERSION: u32 = 3;
const MAXIMUM: usize = 2 * 1024 * 1024;
const MAX_INTEGER: u64 = 1 << 53;

fn commitment(domain: &[u8], value: &impl Serialize) -> EnclaveResult<[u8; 32]> {
    let bytes = enclave_core::jcs::to_jcs_bytes(value)?;
    if bytes.len() > MAXIMUM { fail!(E2BIG, "MEMBERSHIP_SIZE"); }
    let mut hash = Sha256::new(); hash.update(domain); hash.update(bytes); Ok(hash.finalize().into())
}
fn advance(value: u64) -> EnclaveResult<u64> {
    value.checked_add(1).filter(|next| *next <= MAX_INTEGER)
        .ok_or_else(|| err!(EACCES, "MEMBERSHIP_EXHAUSTED"))
}

/// Untrusted public evidence; verification happens inside every transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MemberEvidence {
    pub(crate) pending: PendingAssetEnrollment,
    pub(crate) receipt: AssetEnrollmentReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scope {
    host: String,
    asset: String,
    custodian: String,
    policy_issuer: [u8; 32],
    inventory_issuer: [u8; 32],
}
impl Scope {
    fn of(authority: &AssetEnrollmentAuthority) -> Self {
        Self { host: authority.host.clone(), asset: authority.asset.clone(),
            custodian: authority.custodian.clone(), policy_issuer: authority.policy_issuer.to_bytes(),
            inventory_issuer: authority.inventory_issuer.to_bytes() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    attempt: u64,
    scope: Scope,
    profile: Profile,
    minimum_members: u8,
    policy_revision: u64,
    policy_digest: [u8; 32],
    pool_digest: [u8; 32],
    source_v2_binding: [u8; 32],
    primary: MemberEvidence,
    backup: MemberEvidence,
}
impl Plan {
    fn digest(&self) -> EnclaveResult<[u8; 32]> { commitment(b"depot-InactiveMembershipPlan-v3\0", self) }
    fn shape(&self) -> EnclaveResult<()> {
        if self.attempt == 0 || self.attempt > MAX_INTEGER || self.minimum_members != 2
            || self.profile == Profile::L1 || self.policy_revision == 0
            || self.policy_revision > MAX_INTEGER || self.primary.receipt.generation == 0
            || self.backup.receipt.generation > MAX_INTEGER
            || self.backup.receipt.generation <= self.primary.receipt.generation {
            fail!(EACCES, "MEMBERSHIP_SCOPE");
        }
        distinct(self.primary.pending.credential(), self.backup.pending.credential())?;
        // Enforce bounded exact attestation bytes/digest even on sterile reopen.
        self.primary.pending.digest()?; self.backup.pending.digest()?; self.digest()?; Ok(())
    }
}

/// Encrypted public candidate only. There is deliberately no activation method.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InactiveMembershipCandidate {
    version: u32,
    plan: Plan,
    plan_sha256: [u8; 32],
    backup_wrappers: StagedBackupEnvelopes,
    backup_wrappers_sha256: [u8; 32],
}
impl InactiveMembershipCandidate {
    fn shape(&self) -> EnclaveResult<()> {
        self.plan.shape()?;
        if self.version != VERSION || self.plan_sha256 != self.plan.digest()?
            || self.backup_wrappers_sha256 != commitment(b"depot-InactiveBackupWrappers-v3\0", &self.backup_wrappers)? {
            fail!(EACCES, "MEMBERSHIP_COMMITMENT");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum Phase {
    Empty,
    Burned { plan: Plan, plan_sha256: [u8; 32] },
    Staged(InactiveMembershipCandidate),
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    attempt: u64,
    policy_floor: u64,
    receipt_floor: u64,
    phase: Phase,
}
impl Default for Journal {
    fn default() -> Self { Self { version: VERSION, attempt: 0, policy_floor: 0,
        receipt_floor: 0, phase: Phase::Empty } }
}
impl Journal {
    fn shape(&self) -> EnclaveResult<()> {
        if self.version != VERSION { fail!(EACCES, "MEMBERSHIP_VERSION"); }
        let plan = match &self.phase {
            Phase::Empty => {
                if self.attempt != 0 || self.policy_floor != 0 || self.receipt_floor != 0 {
                    fail!(EACCES, "MEMBERSHIP_COMMITMENT");
                }
                return Ok(());
            }
            Phase::Burned { plan, plan_sha256 } => {
                plan.shape()?;
                if *plan_sha256 != plan.digest()? { fail!(EACCES, "MEMBERSHIP_COMMITMENT"); }
                plan
            }
            Phase::Staged(candidate) => { candidate.shape()?; &candidate.plan }
        };
        if plan.attempt != self.attempt || plan.policy_revision != self.policy_floor
            || plan.backup.receipt.generation != self.receipt_floor {
            fail!(EACCES, "MEMBERSHIP_COMMITMENT");
        }
        Ok(())
    }
}

fn normalized_key(credential: &EnrolledCredential) -> Vec<u8> {
    let mut result = (credential.key.alg() as i32).to_be_bytes().to_vec();
    result.extend(match &credential.key {
        CredentialKey::Ed25519(key) => key.to_edwards().compress().to_bytes().to_vec(),
        CredentialKey::Es256(_) => credential.key.to_raw(),
    }); result
}
fn distinct(primary: &EnrolledCredential, backup: &EnrolledCredential) -> EnclaveResult<()> {
    if [primary, backup].iter().any(|credential| credential.credential_id.is_empty()
        || credential.credential_id.len() > 1023)
        || primary.credential_id == backup.credential_id || normalized_key(primary) == normalized_key(backup) {
        fail!(EACCES, "MEMBERSHIP_DISTINCT_REQUIRED");
    }
    Ok(())
}
fn current_policy(authority: &AssetEnrollmentAuthority, floor: u64, now: i64)
    -> EnclaveResult<(VerifiedAssetEnrollmentPolicy, u64)> {
    let bytes = read_asset_authority_file(&authority.policy_file, 16 * 1024)?;
    let signed: SignedAssetEnrollmentPolicy = serde_json::from_slice(&bytes)
        .map_err(|_| err!(EACCES, "ASSET_POLICY_DECODE"))?;
    let verified = signed.verify(&authority.policy_issuer, &authority.host, &authority.asset,
        &authority.custodian, floor, now)?;
    Ok((verified, signed.policy.revision))
}

/// Move-only live staging window. Neither serialized nor recovered after restart.
pub(crate) struct MembershipAttempt {
    attempt: u64,
    plan_sha256: [u8; 32],
    nonce: [u8; 32],
    start_ns: u64,
    start_unix: i64,
    deadline_ns: u64,
    valid_until_unix: i64,
}
impl std::fmt::Debug for MembershipAttempt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MembershipAttempt").field("attempt", &self.attempt).finish_non_exhaustive()
    }
}
impl MembershipAttempt {
    fn check(&self, clock: &dyn Clock) -> EnclaveResult<()> {
        let now = clock.now_ns(); let wall = clock.now_unix();
        if now < self.start_ns || now >= self.deadline_ns || wall < self.start_unix
            || wall >= self.valid_until_unix { fail!(ETIMEDOUT, "MEMBERSHIP_DEADLINE"); }
        Ok(())
    }
}

/// No status represents an active or restart-resumable membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InactiveMembershipStatus { Empty, BurnedSterile, StagedSterile }

/// Exclusive inactive staging owner. File-based rollback limits are inherited
/// from SealedStore; replacing the entire directory as root is not prevented.
pub(crate) struct MembershipStagingStore {
    _lease: StateDirectoryLease,
    store: SealedStore,
    journal: Journal,
    live: Option<[u8; 32]>,
    fault: bool,
}
impl MembershipStagingStore {
    /// Separate non-authoritative staging directory; never read by native boot.
    pub(crate) fn open(state: &Path) -> EnclaveResult<Self> {
        let directory = state.join("asset-membership-staging");
        let lease = StateDirectoryLease::acquire(&directory)?;
        let (mut store, loaded) = SealedStore::open_bounded_required(&directory, "candidate", MAXIMUM)?;
        let journal = match loaded {
            Loaded::Fresh => { let journal = Journal::default(); store.save_json(&journal)?; journal }
            Loaded::State(bytes) => enclave_core::sealed::decode::<Journal>(&bytes)?,
        };
        journal.shape()?;
        Ok(Self { _lease: lease, store, journal, live: None, fault: false })
    }
    pub(crate) fn status(&self) -> InactiveMembershipStatus {
        match &self.journal.phase { Phase::Empty => InactiveMembershipStatus::Empty,
            Phase::Burned { .. } => InactiveMembershipStatus::BurnedSterile,
            Phase::Staged(_) => InactiveMembershipStatus::StagedSterile }
    }
    fn healthy(&self) -> EnclaveResult<()> {
        if self.fault { fail!(EIO, "MEMBERSHIP_PERSISTENCE_UNCERTAIN"); } Ok(())
    }
    fn persist(&mut self, journal: Journal) -> EnclaveResult<()> {
        self.live = None; journal.shape()?;
        // Bound before mutation; save_json itself must not admit oversized state.
        if serde_json::to_vec(&journal).map_err(|_| err!(EIO, "MEMBERSHIP_ENCODE"))?.len() > MAXIMUM {
            fail!(E2BIG, "MEMBERSHIP_SIZE");
        }
        self.journal = journal;
        if let Err(error) = self.store.save_json(&self.journal) {
            self.fault = true; return Err(error);
        }
        Ok(())
    }

    /// Verify both independent inventory receipts and durably burn the target
    /// receipt before any factor work. This proves no prior active membership;
    /// authoritative v2 floors and cutover are a separate service integration.
    pub(crate) fn begin(&mut self, checkpoint: &VaultEnvelopeCheckpoint,
        primary: MemberEvidence, backup: MemberEvidence, authority: &AssetEnrollmentAuthority,
        context: &VerifiedEnvelopeContext, clock: &dyn Clock) -> EnclaveResult<MembershipAttempt> {
        self.healthy()?;
        let start_ns = clock.now_ns(); let start_unix = clock.now_unix();
        let cap = start_ns.checked_add(crate::ceremony::CEREMONY_BUDGET_NS)
            .ok_or_else(|| err!(ETIMEDOUT, "MEMBERSHIP_DEADLINE"))?;
        let deadline_ns = context.deadline_ns().map_or(cap, |bound| cap.min(bound));
        let (policy, revision) = current_policy(authority, self.journal.policy_floor, start_unix)?;
        let primary_credential = primary.receipt.clone().activate(primary.pending.clone(), &policy,
            &authority.inventory_issuer, 1, start_unix)?;
        let floor = self.journal.receipt_floor.max(primary.receipt.generation);
        let backup_credential = backup.receipt.clone().activate(backup.pending.clone(), &policy,
            &authority.inventory_issuer, advance(floor)?, start_unix)?;
        distinct(&primary_credential, &backup_credential)?;
        let source = checkpoint.backup_source(context, start_unix)?;
        let plan = Plan { attempt: advance(self.journal.attempt)?, scope: Scope::of(authority),
            profile: source.profile, minimum_members: 2, policy_revision: revision,
            policy_digest: policy.digest(), pool_digest: source.pool_digest,
            source_v2_binding: checkpoint.enrollment_binding()?, primary, backup };
        let previous = match &self.journal.phase {
            Phase::Empty => None, Phase::Burned { plan, .. } => Some(plan),
            Phase::Staged(candidate) => Some(&candidate.plan),
        };
        if let Some(previous) = previous {
            // This is an add-backup staging journal, not an issuer/source-key
            // replacement or migration API. Ordinary ciphertext/count growth
            // leaves the source wrapper binding and public pool unchanged.
            if previous.scope != plan.scope || previous.pool_digest != plan.pool_digest
                || previous.source_v2_binding != plan.source_v2_binding
                || commitment(b"depot-MembershipPrimary-v3\0", previous.primary.pending.credential())?
                    != commitment(b"depot-MembershipPrimary-v3\0", plan.primary.pending.credential())? {
                fail!(EACCES, "MEMBERSHIP_SOURCE_CHANGED");
            }
        }
        plan.shape()?; let plan_sha256 = plan.digest()?;
        let valid_until_unix = context.expires_unix().min(plan.primary.receipt.expires_unix)
            .min(plan.backup.receipt.expires_unix);
        let mut nonce = [0; 32]; enclave_core::rng::fill(&mut nonce);
        let attempt = MembershipAttempt { attempt: plan.attempt, plan_sha256, nonce,
            start_ns, start_unix, deadline_ns, valid_until_unix };
        attempt.check(clock)?;
        self.persist(Journal { version: VERSION, attempt: plan.attempt,
            policy_floor: revision, receipt_floor: plan.backup.receipt.generation,
            phase: Phase::Burned { plan, plan_sha256 } })?;
        // A slow durable save consumes the receipt but cannot extend the cap.
        attempt.check(clock)?; self.live = Some(nonce); Ok(attempt)
    }

    /// Consume this live attempt even on failure. Verify all 34 source/backup
    /// private-key possession challenges and exact current public authority.
    /// Returns encrypted public evidence only, never an activation capability.
    pub(crate) fn stage(&mut self, attempt: MembershipAttempt,
        checkpoint: &VaultEnvelopeCheckpoint, backup_wrappers: StagedBackupEnvelopes,
        source_a3: &KekShares<'_>, source_a4: &KekShares<'_>,
        backup_a3: &KekShares<'_>, backup_a4: &KekShares<'_>,
        authority: &AssetEnrollmentAuthority, context: &VerifiedEnvelopeContext, clock: &dyn Clock)
        -> EnclaveResult<InactiveMembershipCandidate> {
        self.healthy()?;
        let live = self.live.take();
        if live != Some(attempt.nonce) { fail!(EACCES, "MEMBERSHIP_LIVE_ATTEMPT_REQUIRED"); }
        attempt.check(clock)?;
        let Phase::Burned { plan, plan_sha256 } = &self.journal.phase
            else { fail!(EACCES, "MEMBERSHIP_LIVE_ATTEMPT_REQUIRED"); };
        let plan = plan.clone();
        if plan.attempt != attempt.attempt || *plan_sha256 != attempt.plan_sha256
            || plan.digest()? != attempt.plan_sha256 || plan.scope != Scope::of(authority) {
            fail!(EACCES, "MEMBERSHIP_SCOPE");
        }
        let now = clock.now_unix();
        let (policy, revision) = current_policy(authority, self.journal.policy_floor, now)?;
        if revision != plan.policy_revision || policy.digest() != plan.policy_digest {
            fail!(ESTALE, "MEMBERSHIP_POLICY_CHANGED");
        }
        let primary = plan.primary.receipt.clone().activate(plan.primary.pending.clone(), &policy,
            &authority.inventory_issuer, 1, now)?;
        let backup = plan.backup.receipt.clone().activate(plan.backup.pending.clone(), &policy,
            &authority.inventory_issuer, self.journal.receipt_floor, now)?;
        distinct(&primary, &backup)?;
        let source = checkpoint.backup_source(context, now)?;
        if source.pool_digest != plan.pool_digest || source.profile != plan.profile
            || checkpoint.enrollment_binding()? != plan.source_v2_binding {
            fail!(EACCES, "MEMBERSHIP_POOL_CHANGED");
        }
        if ct_eq(source_a3.yubikey_prf, source_a4.yubikey_prf)
            || ct_eq(source_a3.yubikey_prf, backup_a3.yubikey_prf)
            || ct_eq(source_a4.yubikey_prf, backup_a4.yubikey_prf)
            || ct_eq(backup_a3.yubikey_prf, backup_a4.yubikey_prf) {
            fail!(EACCES, "MEMBERSHIP_INDEPENDENT_PRF_REQUIRED");
        }
        for wrapped in &source.a3 { verify_tier_wrapping::<A3>(wrapped, source_a3)?; attempt.check(clock)?; }
        verify_tier_wrapping::<A4>(&source.a4, source_a4)?; attempt.check(clock)?;
        backup_wrappers.verify(checkpoint, &primary, &backup, backup_a3, backup_a4, context, now)?;
        attempt.check(clock)?;
        // Charge verification work and policy I/O to the same original window.
        // A newer valid policy is still a change; it cannot revive this plan.
        let now = clock.now_unix();
        let (final_policy, final_revision) = current_policy(authority, self.journal.policy_floor, now)?;
        if final_revision != plan.policy_revision || final_policy.digest() != plan.policy_digest {
            fail!(ESTALE, "MEMBERSHIP_POLICY_CHANGED");
        }
        plan.primary.receipt.clone().activate(plan.primary.pending.clone(), &final_policy,
            &authority.inventory_issuer, 1, now)?;
        plan.backup.receipt.clone().activate(plan.backup.pending.clone(), &final_policy,
            &authority.inventory_issuer, self.journal.receipt_floor, now)?;
        checkpoint.backup_source(context, now)?; attempt.check(clock)?;
        let candidate = InactiveMembershipCandidate { version: VERSION, plan,
            plan_sha256: attempt.plan_sha256,
            backup_wrappers_sha256: commitment(b"depot-InactiveBackupWrappers-v3\0", &backup_wrappers)?,
            backup_wrappers };
        candidate.shape()?;
        self.persist(Journal { version: VERSION, attempt: self.journal.attempt,
            policy_floor: self.journal.policy_floor, receipt_floor: self.journal.receipt_floor,
            phase: Phase::Staged(candidate.clone()) })?;
        attempt.check(clock)?;
        // Persisted Staged is always sterile on reopen. No commit/activate API.
        Ok(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{biometric::{BiometricPrompt, BiometricProvider, Scripted, ScriptedCoreAuthUi},
        clock::TestClock, ctap::asset_enrollment::{AssetEnrollmentPolicy, AttestationMode, VerifiedSetupDisclosure},
        vault::CustodyVault};
    use ed25519_dalek::{Signer, SigningKey};
    use enclave_core::secret::SecretKey32;
    use enclave_crypto::hpke_envelope::{EnvelopePolicy, SignedEnvelopePolicy};
    use std::{fs, os::unix::fs::{DirBuilderExt, PermissionsExt}, path::PathBuf};
    const S3: [u8;32] = [11;32]; const S4: [u8;32] = [21;32];
    const P3: [u8;32] = [12;32]; const P4: [u8;32] = [22;32];
    const B3: [u8;32] = [13;32]; const B4: [u8;32] = [23;32];
    fn shares<'a>(sep: &'a [u8], prf: &'a [u8]) -> KekShares<'a> { KekShares { sep_ecdh_share: sep, yubikey_prf: prf } }
    struct Root(PathBuf);
    impl Root {
        fn new() -> Self {
            let base = std::env::var_os("ENCLAVE_TEST_STATE_ROOT").map(PathBuf::from)
                .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"));
            let path = base.join(format!("membership-{:x}", enclave_core::rng::u64()));
            fs::DirBuilder::new().recursive(true).mode(0o700).create(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap(); Self(path.canonicalize().unwrap())
        }
    }
    impl Drop for Root { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
    struct Fixture {
        root: Root,
        authority: AssetEnrollmentAuthority,
        policy: SignedAssetEnrollmentPolicy,
        inventory: SigningKey,
        primary: MemberEvidence,
        backup: MemberEvidence,
        checkpoint: VaultEnvelopeCheckpoint,
        context: VerifiedEnvelopeContext,
        clock: TestClock,
    }
    fn evidence(seed: u8, policy: &VerifiedAssetEnrollmentPolicy, issuer: &SigningKey,
        generation: u64, now: i64) -> MemberEvidence {
        let key = SigningKey::from_bytes(&[seed;32]);
        let credential = EnrolledCredential { credential_id: vec![seed;32],
            key: CredentialKey::Ed25519(key.verifying_key()), aaguid: [8;16], firmware_version: 0x050800 };
        let mut ui = ScriptedCoreAuthUi::new([Scripted::Approve]); let sep = ui.enrolled_key();
        let prompt = BiometricPrompt { localized_reason: policy.localized_reason(), d_jcs: policy.digest().to_vec(),
            nonce: vec![seed;32], t_start_ns: enclave_core::power::continuous_time_ns(), bio_key_blob: vec![] };
        let outcome = ui.evaluate(&prompt);
        let (sep_public_key, disclosure_evidence, _) = VerifiedSetupDisclosure::verify(policy, &sep, &prompt, &outcome).unwrap().consume(policy).unwrap();
        let attestation_evidence = vec![seed;64];
        let pending = PendingAssetEnrollment { credential, policy_digest: policy.digest(), sep_public_key,
            disclosure_evidence, evidence_sha256: Sha256::digest(&attestation_evidence).into(),
            attestation_evidence, mode: policy.mode() };
        let mut member = MemberEvidence { receipt: AssetEnrollmentReceipt { version: 1, pending_sha256: pending.digest().unwrap(),
            generation, issued_unix: now, expires_unix: now+120, signature: vec![] }, pending };
        resign(&mut member, issuer); member
    }
    fn resign(member: &mut MemberEvidence, inventory: &SigningKey) {
        member.receipt.pending_sha256 = member.pending.digest().unwrap();
        member.receipt.signature = inventory.sign(&member.receipt.signing_message().unwrap()).to_bytes().to_vec();
    }
    impl Fixture {
        fn new() -> Self {
            let root = Root::new(); let now = enclave_crypto::time::now_unix();
            let issuer = SigningKey::from_bytes(&[61;32]); let inventory = SigningKey::from_bytes(&[62;32]);
            let policy = AssetEnrollmentPolicy { version: 1, revision: 3, host_id: "host".into(), asset_id: "asset".into(),
                custodian_id: "custodian".into(), aaguid: [8;16], mode: AttestationMode::BasicWithIndependentAsset,
                enterprise_leaf_sha256: None, rationale: "synthetic two-key admission fixture".into(), issued_unix: now-1, expires_unix: now+3600 };
            let signature = issuer.sign(&policy.signing_message().unwrap()).to_bytes().to_vec();
            let policy = SignedAssetEnrollmentPolicy { policy, signature };
            let policy_file = root.0.join("policy.json"); fs::write(&policy_file, serde_json::to_vec(&policy).unwrap()).unwrap();
            fs::set_permissions(&policy_file, fs::Permissions::from_mode(0o644)).unwrap();
            let authority = AssetEnrollmentAuthority { policy_issuer: issuer.verifying_key(), inventory_issuer: inventory.verifying_key(),
                policy_file, host: "host".into(), asset: "asset".into(), custodian: "custodian".into() };
            let verified = policy.verify(&issuer.verifying_key(), "host", "asset", "custodian", 0, now).unwrap();
            let primary = evidence(41, &verified, &inventory, 1, now); let backup = evidence(42, &verified, &inventory, 2, now);
            let envelope = EnvelopePolicy { version: 1, revision: 2, subject: "host".into(), namespace: "data".into(),
                issued_unix: now-1, expires_unix: now+3600, review_unix: now+1800, owner: "fixture".into(), profiles: vec![Profile::L2, Profile::L3],
                data_classes: vec!["C3".into(), "C4".into()], purpose: "synthetic backup staging".into(),
                migration: "explicit inactive v3 membership".into(), disclosure: None, classical_exception: false };
            let signature = issuer.sign(&envelope.signing_message().unwrap()).to_bytes().to_vec();
            let context = SignedEnvelopePolicy { policy: envelope, signature }.verify(&issuer.verifying_key(), "host", "data", now).unwrap();
            let vault = CustodyVault::enroll_authorized(Profile::L3, &shares(&S3,&P3), &shares(&S4,&P4), None,
                &context, SecretKey32::new([31;32]), now).unwrap();
            Self { root, authority, policy, inventory, primary, backup, checkpoint: vault.checkpoint().unwrap(), context, clock: TestClock::at(now) }
        }
        fn open(&self) -> MembershipStagingStore { MembershipStagingStore::open(&self.root.0).unwrap() }
        fn begin(&self, store: &mut MembershipStagingStore) -> EnclaveResult<MembershipAttempt> {
            store.begin(&self.checkpoint, self.primary.clone(), self.backup.clone(), &self.authority, &self.context, &self.clock)
        }
        fn wrappers(&self) -> StagedBackupEnvelopes {
            StagedBackupEnvelopes::stage(&self.checkpoint, self.primary.pending.credential(), self.backup.pending.credential(),
                &shares(&S3,&P3), &shares(&S4,&P4), &shares(&S3,&B3), &shares(&S4,&B4), &self.context, self.clock.now_unix()).unwrap()
        }
        fn stage(&self, store: &mut MembershipStagingStore, attempt: MembershipAttempt) -> EnclaveResult<InactiveMembershipCandidate> {
            store.stage(attempt, &self.checkpoint, self.wrappers(), &shares(&S3,&P3), &shares(&S4,&P4),
                &shares(&S3,&B3), &shares(&S4,&B4), &self.authority, &self.context, &self.clock)
        }
    }

    #[test]
    fn two_independent_admissions_stage_all_wrappers_but_restart_is_sterile_and_receipt_burned() {
        let mut f = Fixture::new(); let mut store = f.open();
        let checkpoint = serde_json::to_vec(&f.checkpoint).unwrap(); let attempt = f.begin(&mut store).unwrap();
        assert_eq!(store.status(), InactiveMembershipStatus::BurnedSterile);
        let candidate = f.stage(&mut store, attempt).unwrap(); candidate.shape().unwrap();
        assert_eq!(store.status(), InactiveMembershipStatus::StagedSterile);
        assert_eq!(serde_json::to_vec(&f.checkpoint).unwrap(), checkpoint);
        drop(store); let mut store = f.open();
        assert!(store.live.is_none()); assert_eq!(store.status(), InactiveMembershipStatus::StagedSterile);
        assert!(f.begin(&mut store).is_err(), "consumed receipt cannot begin again after successful staging");
        f.backup.receipt.generation = 3; resign(&mut f.backup, &f.inventory);
        let attempt = f.begin(&mut store).unwrap(); assert_eq!(attempt.attempt, 2);
        f.stage(&mut store, attempt).unwrap();
    }

    #[test]
    fn independent_scope_signature_disclosure_identity_and_current_policy_are_rechecked() {
        let f = Fixture::new(); let mut store = f.open();
        for field in 0..4 {
            let mut authority = f.authority.clone();
            match field { 0 => authority.host.push('x'), 1 => authority.asset.push('x'),
                2 => authority.custodian.push('x'), _ => authority.inventory_issuer = SigningKey::from_bytes(&[99;32]).verifying_key() }
            assert!(store.begin(&f.checkpoint, f.primary.clone(), f.backup.clone(), &authority, &f.context, &f.clock).is_err());
        }
        let mut bad = f.backup.clone(); bad.pending.sep_public_key = f.primary.pending.sep_public_key.clone(); resign(&mut bad,&f.inventory);
        assert!(store.begin(&f.checkpoint, f.primary.clone(), bad, &f.authority, &f.context, &f.clock).is_err());
        let mut alias = f.backup.clone(); alias.pending.credential.key = f.primary.pending.credential.key.clone(); resign(&mut alias,&f.inventory);
        assert!(store.begin(&f.checkpoint, f.primary.clone(), alias, &f.authority, &f.context, &f.clock).unwrap_err().is("MEMBERSHIP_DISTINCT_REQUIRED"));
        assert_eq!(store.status(), InactiveMembershipStatus::Empty);
        let attempt = f.begin(&mut store).unwrap();
        let mut changed = f.policy.clone(); changed.signature[0] ^= 1;
        fs::write(&f.authority.policy_file, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(f.stage(&mut store, attempt).is_err());
        assert!(store.live.is_none()); assert_eq!(store.status(), InactiveMembershipStatus::BurnedSterile);
    }

    #[test]
    fn interrupted_attempt_and_late_factor_failure_burn_receipts_without_partial_candidate() {
        let mut f = Fixture::new(); let mut store = f.open();
        let attempt = f.begin(&mut store).unwrap(); drop(store); let mut store = f.open();
        assert!(f.stage(&mut store, attempt).unwrap_err().is("MEMBERSHIP_LIVE_ATTEMPT_REQUIRED"));
        assert!(f.begin(&mut store).is_err());
        f.backup.receipt.generation = 3; resign(&mut f.backup,&f.inventory);
        let attempt = f.begin(&mut store).unwrap();
        let mut encoded = serde_json::to_value(f.wrappers()).unwrap();
        let byte = encoded["a4"]["ct"][0].as_u64().unwrap(); encoded["a4"]["ct"][0] = serde_json::json!(byte ^ 1);
        let damaged = serde_json::from_value(encoded).unwrap();
        assert!(store.stage(attempt, &f.checkpoint, damaged, &shares(&S3,&P3), &shares(&S4,&P4),
            &shares(&S3,&B3), &shares(&S4,&B4), &f.authority, &f.context, &f.clock).is_err());
        assert_eq!(store.status(), InactiveMembershipStatus::BurnedSterile); assert!(store.live.is_none());
        drop(store); let mut store = f.open(); assert!(f.begin(&mut store).is_err());
    }

    #[test]
    fn complete_cap_and_receipt_expiry_never_refresh_or_resume_an_attempt() {
        let f = Fixture::new(); let mut store = f.open(); let attempt = f.begin(&mut store).unwrap();
        let wrappers = f.wrappers(); f.clock.advance_ms(10_000);
        assert!(store.stage(attempt, &f.checkpoint, wrappers, &shares(&S3,&P3), &shares(&S4,&P4),
            &shares(&S3,&B3), &shares(&S4,&B4), &f.authority, &f.context, &f.clock).unwrap_err().is("MEMBERSHIP_DEADLINE"));
        drop(store); let mut store = f.open(); assert!(f.begin(&mut store).is_err());
        f.clock.advance_ms(120_000); assert!(f.begin(&mut store).is_err());
    }

    #[test]
    fn uncertain_save_latches_and_missing_checkpoint_refuses_without_reusing_receipt() {
        let f = Fixture::new(); let mut store = f.open();
        let generation = f.root.0.join("asset-membership-staging/candidate.gen");
        fs::remove_file(&generation).unwrap(); fs::create_dir(&generation).unwrap();
        assert!(f.begin(&mut store).is_err()); assert!(store.live.is_none()); assert!(store.fault);
        assert!(f.begin(&mut store).unwrap_err().is("MEMBERSHIP_PERSISTENCE_UNCERTAIN"));
        fs::remove_dir(&generation).unwrap(); drop(store);
        // State was replaced before checkpoint save failed. With the old
        // checkpoint absent, the required opener correctly refuses rollback.
        assert!(MembershipStagingStore::open(&f.root.0).err().unwrap().is("STATE_ROLLBACK"));
    }

    #[test]
    fn partial_stage_save_and_older_state_never_recover_live_authority() {
        let f = Fixture::new(); let mut store = f.open(); let attempt = f.begin(&mut store).unwrap();
        let directory = f.root.0.join("asset-membership-staging");
        let old_state = fs::read(directory.join("candidate.sealed")).unwrap();
        let old_generation = fs::read(directory.join("candidate.gen")).unwrap();
        // Break only checkpoint replacement: the candidate state itself may
        // already be durable when save returns an error.
        fs::remove_file(directory.join("candidate.gen")).unwrap();
        fs::create_dir(directory.join("candidate.gen")).unwrap();
        assert!(f.stage(&mut store, attempt).is_err()); assert!(store.fault); assert!(store.live.is_none());
        fs::remove_dir(directory.join("candidate.gen")).unwrap();
        fs::write(directory.join("candidate.gen"), old_generation).unwrap();
        fs::set_permissions(directory.join("candidate.gen"),fs::Permissions::from_mode(0o600)).unwrap(); drop(store);
        let mut reopened = f.open();
        assert_eq!(reopened.status(), InactiveMembershipStatus::StagedSterile);
        assert!(reopened.live.is_none()); assert!(f.begin(&mut reopened).is_err());
        // Advance the current sealed checkpoint without changing membership,
        // then restore the genuinely older state bytes alone.
        let saved = reopened.journal.clone(); reopened.persist(saved).unwrap(); drop(reopened);
        fs::write(directory.join("candidate.sealed"), old_state).unwrap();
        assert!(MembershipStagingStore::open(&f.root.0).err().unwrap().is("STATE_ROLLBACK"));
    }

    #[test]
    fn changed_pool_wrong_source_factor_and_tampered_wrapper_commitment_refuse() {
        let f = Fixture::new(); let mut store = f.open(); let attempt = f.begin(&mut store).unwrap();
        let mut changed = serde_json::to_value(&f.checkpoint).unwrap();
        let byte = changed["session_id"][0].as_u64().unwrap(); changed["session_id"][0] = serde_json::json!(byte ^ 1);
        let changed = serde_json::from_value(changed).unwrap();
        assert!(store.stage(attempt, &changed, f.wrappers(), &shares(&S3,&P3), &shares(&S4,&P4),
            &shares(&S3,&B3), &shares(&S4,&B4), &f.authority, &f.context, &f.clock).unwrap_err().is("MEMBERSHIP_POOL_CHANGED"));
        assert!(store.live.is_none()); drop(store);
        let g = Fixture::new(); let mut store = g.open(); let attempt = g.begin(&mut store).unwrap();
        assert!(store.stage(attempt, &g.checkpoint, g.wrappers(), &shares(&S3,&[97;32]), &shares(&S4,&P4),
            &shares(&S3,&B3), &shares(&S4,&B4), &g.authority, &g.context, &g.clock).is_err());
        assert_eq!(store.status(), InactiveMembershipStatus::BurnedSterile);
        let h = Fixture::new(); let mut store = h.open(); let attempt = h.begin(&mut store).unwrap();
        let mut candidate = h.stage(&mut store, attempt).unwrap(); candidate.backup_wrappers_sha256[0] ^= 1;
        assert!(candidate.shape().unwrap_err().is("MEMBERSHIP_COMMITMENT"));
        assert!(advance(MAX_INTEGER).unwrap_err().is("MEMBERSHIP_EXHAUSTED"));
    }

    #[test]
    fn initialized_missing_tampered_unknown_version_and_competing_owner_refuse() {
        for attack in 0..3 {
            let f = Fixture::new(); let store = f.open();
            assert!(MembershipStagingStore::open(&f.root.0).is_err(), "exclusive owner");
            drop(store);
            let directory = f.root.0.join("asset-membership-staging");
            match attack {
                0 => { fs::remove_file(directory.join("candidate.sealed")).unwrap(); fs::remove_file(directory.join("candidate.gen")).unwrap(); }
                1 => { fs::write(directory.join("candidate.sealed"), b"tampered").unwrap(); }
                _ => { let (mut sealed, _) = SealedStore::open_bounded_required(&directory,"candidate",MAXIMUM).unwrap();
                    let mut journal = Journal::default(); journal.version = 4; sealed.save_json(&journal).unwrap(); }
            }
            assert!(MembershipStagingStore::open(&f.root.0).is_err());
        }
    }

    #[test]
    fn current_workflow_reader_rejects_invalid_v3_unknown_version_and_inactive_candidates() {
        let f = Fixture::new(); let mut store = f.open(); let attempt = f.begin(&mut store).unwrap();
        let candidate = f.stage(&mut store,attempt).unwrap();
        let mut encoded = serde_json::to_value(&candidate).unwrap(); encoded["plan"]["minimum_members"] = serde_json::json!(1);
        let changed: InactiveMembershipCandidate = serde_json::from_value(encoded).unwrap(); assert!(changed.shape().is_err());
        let old_path = f.root.0.join("asset-enrollment");
        let (mut old,_) = SealedStore::open_bounded_required(&old_path,"workflow",MAXIMUM).unwrap();
        // The authoritative reader now supports committed v3 membership, but
        // cannot accept an unrelated phase or an inactive candidate as one.
        old.save_json(&serde_json::json!({"version":3,"attempt":1,"policy_floor":3,"receipt_floor":2,"phase":"Empty"})).unwrap();
        assert!(crate::service::load_native_enrollment(&f.root.0,Some(&f.authority),Profile::L3,f.clock.now_unix())
            .unwrap_err().is("ASSET_MEMBERSHIP_STATE"));
        // Unknown future workflow versions still hit the genuine version gate.
        old.save_json(&serde_json::json!({"version":999,"attempt":1,"policy_floor":3,"receipt_floor":2,"phase":"Empty"})).unwrap();
        assert!(crate::service::load_native_enrollment(&f.root.0,Some(&f.authority),Profile::L3,f.clock.now_unix())
            .unwrap_err().is("ASSET_LEDGER_VERSION"));
        // The actual inactive candidate body cannot be interpreted as authority.
        old.save_json(&candidate).unwrap();
        assert!(crate::service::load_native_enrollment(&f.root.0,Some(&f.authority),Profile::L3,f.clock.now_unix()).is_err());
    }
}
