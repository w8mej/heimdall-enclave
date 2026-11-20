//! Durable native asset admission. This ledger is the activation authority;
//! public pending evidence never grants custody and failed attempts burn state.
use super::*;
use crate::biometric::{BiometricOutcome, BiometricPrompt};
use crate::ctap::asset_enrollment::{
    AssetEnrollmentReceipt, PendingAssetEnrollment, SignedAssetEnrollmentPolicy,
    VerifiedAssetEnrollmentPolicy, VerifiedSetupDisclosure,
};
use enclave_core::sealed::{Loaded, SealedStore};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

// Actual selected dependency remains operation-local, including the final IPC
// preflight. No RPC, persisted receipt or hardware/simulation flag constructs it.
enum BeginDependencyInner {
    Native(std::sync::Mutex<enclave_core::supervisor::SelectedReadinessClient>),
    #[cfg(test)]
    Fixture(PathBuf),
}
struct BeginDependency {
    inner: BeginDependencyInner,
    end: std::time::Instant,
}
impl BeginDependency {
    fn acquire(
        state: &Path,
        profile: Profile,
        socket: Option<&Path>,
        dev: bool,
        simulated: bool,
    ) -> EnclaveResult<Option<Arc<Self>>> {
        let end = std::time::Instant::now() + std::time::Duration::from_secs(30);
        #[cfg(test)]
        if asset_supervisor_dependency_tests::selected(state) {
            let owner = Arc::new(Self {
                inner: BeginDependencyInner::Fixture(state.to_owned()),
                end,
            });
            owner.probe(end)?;
            owner.assign(end)?;
            return Ok(Some(owner));
        }
        let Some(checked)=enclave_core::deployment::selected() else {return Ok(None)};
        let target = checked.target();
        if target.role != enclave_core::deployment::DeploymentRole::DedicatedTest
            || target.profile != Profile::L2
            || target.signing_identity_mode
                != enclave_core::deployment::DeploymentSigningMode::LocalPins
        {
            return Ok(None);
        }
        let path = enclave_core::deployment::normalized_path;
        if dev
            || simulated
            || profile != target.profile
            || socket.is_none()
            || path(socket.expect("checked socket"))? != path(&target.layout.socket_root)?
            || path(state)?
                != path(
                    &target
                        .layout
                        .state_root
                        .join(DaemonId::CustodyVault.dir_name()),
                )?
        {
            fail!(EACCES, "ASSET_SUPERVISOR_CONTEXT_MISMATCH");
        }
        let client = enclave_core::supervisor::SelectedReadinessClient::connect_custody(end)?;
        let owner = Arc::new(Self {
            inner: BeginDependencyInner::Native(std::sync::Mutex::new(client)),
            end,
        });
        owner.probe(end)?;
        owner.assign(end)?;
        Ok(Some(owner))
    }
    fn probe(&self, end: std::time::Instant) -> EnclaveResult<()> {
        let end = end.min(self.end);
        if std::time::Instant::now() >= end {
            fail!(ETIMEDOUT, "ASSET_SUPERVISOR_DEADLINE");
        }
        match &self.inner {
            BeginDependencyInner::Native(client) => client
                .try_lock()
                .map_err(|_| err!(EACCES, "ASSET_SUPERVISOR_BUSY"))?
                .probe(end),
            #[cfg(test)]
            BeginDependencyInner::Fixture(state) => {
                asset_supervisor_dependency_tests::probe(state, end)
            }
        }
    }
    fn assign(&self, end: std::time::Instant) -> EnclaveResult<()> {
        match &self.inner {
            BeginDependencyInner::Native(client) => client
                .try_lock()
                .map_err(|_| err!(EACCES, "ASSET_SUPERVISOR_BUSY"))?
                .assign_current_task(end.min(self.end)),
            #[cfg(test)]
            BeginDependencyInner::Fixture(state) => {
                asset_supervisor_dependency_tests::assign(state)?;
                self.probe(end)
            }
        }
    }
    fn before(&self, deadline: u64) -> EnclaveResult<()> {
        let now = enclave_core::power::continuous_time_ns();
        if now == u64::MAX || now >= deadline {
            fail!(ETIMEDOUT, "ASSET_SETUP_DEADLINE");
        }
        self.probe(std::time::Instant::now() + std::time::Duration::from_nanos(deadline - now))
    }
}

#[cfg(test)]
#[path = "asset_supervisor_dependency_tests.rs"]
mod asset_supervisor_dependency_tests;

#[path = "member_loss_workflow.rs"]
mod member_loss_workflow;
#[path = "membership_cutover.rs"]
mod membership_cutover;
pub use member_loss_workflow::{
    MemberLossSurvivor, MembershipAnchorObservation, MembershipAnchorPin,
    MembershipAuthorityConfig, MembershipAuthorityOwner, MembershipWorkflowAnchor,
    ValidatedMemberLossSetup,
};
pub(in crate::service) use member_loss_workflow::{
    ReplacementPreparingRuntime, ValidatedReplacementEnrollment,
};
pub use membership_cutover::{
    load_native_membership, load_native_membership_setup, ValidatedMembershipSetup,
    ValidatedNativeMembership,
};
pub(super) use membership_cutover::{persist_checkpoint, CommittedMembership};

/// Independently installed asset authority. No RPC supplies trust or scope.
#[derive(Debug, Clone)]
pub struct AssetEnrollmentAuthority {
    /// Independent policy issuer.
    pub policy_issuer: VerifyingKey,
    /// Independent physical inventory issuer; separate from new credential.
    pub inventory_issuer: VerifyingKey,
    /// Protected fixed signed policy file, reread at each use.
    pub policy_file: PathBuf,
    /// Independently configured exact host, asset and custodian.
    pub host: String,
    /// Exact asset.
    pub asset: String,
    /// Exact custodian.
    pub custodian: String,
}
/// Read public authority input only through an absolute, trusted ancestor path.
/// Final no-follow/regular-file/mode/size checks are supplied by the common reader.
pub fn read_asset_authority_file(path: &Path, maximum: usize) -> EnclaveResult<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    #[cfg(target_os = "macos")]
    let platform = path
        .strip_prefix("/var")
        .ok()
        .map(|suffix| Path::new("/private/var").join(suffix));
    #[cfg(target_os = "macos")]
    let path = platform.as_deref().unwrap_or(path);
    if !path.is_absolute()
        || !path.components().all(|part| {
            matches!(
                part,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        fail!(EACCES, "ASSET_AUTHORITY_PATH");
    }
    for parent in path
        .parent()
        .ok_or_else(|| err!(EACCES, "ASSET_AUTHORITY_PATH"))?
        .ancestors()
    {
        let metadata =
            std::fs::symlink_metadata(parent).map_err(|_| err!(EACCES, "ASSET_AUTHORITY_PATH"))?;
        let sticky_root = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
        if !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != enclave_core::ipc::geteuid())
            || (metadata.mode() & 0o022 != 0 && !sticky_root)
        {
            fail!(EACCES, "ASSET_AUTHORITY_PATH");
        }
    }
    enclave_core::enterprise_authority::read_public_file(path, maximum)
}
impl AssetEnrollmentAuthority {
    fn policy(&self, floor: u64, now: i64) -> EnclaveResult<VerifiedAssetEnrollmentPolicy> {
        let bytes = read_asset_authority_file(&self.policy_file, 16 * 1024)?;
        let signed: SignedAssetEnrollmentPolicy =
            serde_json::from_slice(&bytes).map_err(|_| err!(EACCES, "ASSET_POLICY_DECODE"))?;
        signed.verify(
            &self.policy_issuer,
            &self.host,
            &self.asset,
            &self.custodian,
            floor,
            now,
        )
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    evidence: PendingAssetEnrollment,
    bio_public_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    bio_key_blob: Vec<u8>,
    policy_revision: u64,
    profile: Profile,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum Phase {
    Empty,
    Preparing {
        nonce_sha256: [u8; 32],
    },
    Pending(Pending),
    Activating {
        pending: Pending,
        staged: Option<crate::vault::VaultEnvelopeCheckpoint>,
        #[serde(default)]
        renewal: bool,
    },
    Active {
        pending: Pending,
        receipt: AssetEnrollmentReceipt,
        vault_binding: [u8; 32],
    },
    MembershipPreparing {
        preparation: membership_cutover::PreparingMembership,
        plan_sha256: [u8; 32],
    },
    MembershipCommitted {
        record: membership_cutover::CommittedMembership,
    },
    MembershipRenewing {
        renewal: membership_cutover::RenewingMembership,
        plan_sha256: [u8; 32],
    },
    MembershipLossRecorded {
        record: member_loss_workflow::MemberLossRecord,
    },
    MembershipReplacementPreparing {
        record: member_loss_workflow::MemberReplacementRecord,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    version: u32,
    attempt: u64,
    policy_floor: u64,
    receipt_floor: u64,
    phase: Phase,
}
impl Default for Ledger {
    fn default() -> Self {
        Self {
            version: 1,
            attempt: 0,
            policy_floor: 0,
            receipt_floor: 0,
            phase: Phase::Empty,
        }
    }
}
fn open(state: &Path) -> EnclaveResult<(SealedStore, Ledger)> {
    let (mut store, loaded) = SealedStore::open_bounded_required(
        &state.join("asset-enrollment"),
        "workflow",
        2 * 1024 * 1024,
    )?;
    let ledger = match loaded {
        Loaded::Fresh => {
            let v = Ledger::default();
            store.save_json(&v)?;
            v
        }
        Loaded::State(bytes) => enclave_core::sealed::decode(&bytes)?,
    };
    if ledger.version == 4 {
        member_loss_workflow::validate_v4(&ledger)?;
    } else if ledger.version == 3 {
        membership_cutover::validate_v3(&ledger)?;
    } else if !(1..=2).contains(&ledger.version)
        || matches!(
            &ledger.phase,
            Phase::MembershipPreparing { .. }
                | Phase::MembershipCommitted { .. }
                | Phase::MembershipRenewing { .. }
                | Phase::MembershipLossRecorded { .. }
                | Phase::MembershipReplacementPreparing { .. }
        )
        || (ledger.version == 1 && matches!(&ledger.phase, Phase::Activating { renewal: true, .. }))
    {
        fail!(EACCES, "ASSET_LEDGER_VERSION");
    }
    Ok((store, ledger))
}
fn proof_key(pending: &Pending) -> EnclaveResult<p256::ecdsa::VerifyingKey> {
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&pending.bio_public_key)
        .map_err(|_| err!(EACCES, "ASSET_BIOMETRIC_KEY"))
}
fn binding(checkpoint: &crate::vault::VaultEnvelopeCheckpoint) -> EnclaveResult<[u8; 32]> {
    checkpoint.enrollment_binding()
}

/// Load only independently admitted active native enrollment. A pending or
/// interrupted attempt stays sterile after restart; no hardware factor is used.
pub fn load_native_enrollment(
    state: &Path,
    authority: Option<&AssetEnrollmentAuthority>,
    profile: Profile,
    now: i64,
) -> EnclaveResult<Option<(EnrolledCustodyState, [u8; 32])>> {
    let (_, ledger) = open(state)?;
    if ledger.version == 3 {
        membership_cutover::validate_v3_pins(state, &ledger)?;
        return Ok(None); // v3 preparation never becomes singleton authority
    }
    let Phase::Active {pending,receipt,vault_binding}=ledger.phase else {return Ok(None)};
    if pending.profile != profile
        || pending.bio_public_key != pending.evidence.sep_public_key
        || pending.bio_key_blob.is_empty()
        || receipt.generation != ledger.receipt_floor
    {
        fail!(EACCES, "ASSET_LEDGER_BINDING");
    }
    let authority = authority.ok_or_else(|| err!(EACCES, "ASSET_AUTHORITY_REQUIRED"))?;
    let policy = authority.policy(ledger.policy_floor, now)?;
    let expired = now >= receipt.expires_unix;
    // Cryptographically validate an expired receipt at its final valid instant
    // under the still-current exact policy before permitting sterile boot. A
    // fresh independent receipt and all factors are required for any renewal.
    let verified_at = if expired {
        receipt
            .expires_unix
            .checked_sub(1)
            .ok_or_else(|| err!(EACCES, "ASSET_ENROLLMENT_RECEIPT"))?
    } else {
        now
    };
    let credential = receipt.activate(
        pending.evidence,
        &policy,
        &authority.inventory_issuer,
        ledger.receipt_floor,
        verified_at,
    )?;
    if expired {
        return Ok(None);
    }
    Ok(Some((
        EnrolledCustodyState {
            credential,
            bio_public_key: pending.bio_public_key,
            bio_key_blob: pending.bio_key_blob,
        },
        vault_binding,
    )))
}
/// Rechecks the independently admitted identity at each sensitive boundary.
/// This guard contains only public authority and identity material.
#[derive(Debug, Clone)]
pub struct ActiveAssetGuard {
    state: PathBuf,
    authority: AssetEnrollmentAuthority,
    profile: Profile,
    vault_binding: [u8; 32],
    credential_sha256: [u8; 32],
    valid_from_unix: i64,
    expires_unix: i64,
    membership: Option<([u8; 32], u64, usize)>,
}
impl ActiveAssetGuard {
    pub(super) fn new(
        state: PathBuf,
        authority: AssetEnrollmentAuthority,
        profile: Profile,
        vault_binding: [u8; 32],
        credential: &EnrolledCredential,
    ) -> EnclaveResult<Self> {
        let (_, ledger) = open(&state)?;
        let Phase::Active {receipt,..}=ledger.phase else {fail!(EACCES,"ASSET_ACTIVE_REQUIRED");};
        Self::for_receipt(
            state,
            authority,
            profile,
            vault_binding,
            credential,
            &receipt,
        )
    }
    fn for_receipt(
        state: PathBuf,
        authority: AssetEnrollmentAuthority,
        profile: Profile,
        vault_binding: [u8; 32],
        credential: &EnrolledCredential,
        receipt: &AssetEnrollmentReceipt,
    ) -> EnclaveResult<Self> {
        Ok(Self {
            state,
            authority,
            profile,
            vault_binding,
            credential_sha256: Sha256::digest(enclave_core::jcs::to_jcs_bytes(credential)?).into(),
            valid_from_unix: receipt.issued_unix,
            expires_unix: receipt.expires_unix,
            membership: None,
        })
    }
    // The receipt was independently verified and cannot extend its signed
    // policy's expiry. This pure check is safe inside the release serial;
    // file/signature refresh stays outside that bounded handoff.
    pub(super) fn check_release(&self, now: i64) -> EnclaveResult<()> {
        if now < self.valid_from_unix || now >= self.expires_unix {
            fail!(EACCES, "ASSET_ENROLLMENT_RECEIPT");
        }
        Ok(())
    }
    pub(super) fn expires_unix(&self) -> i64 {
        self.expires_unix
    }
    pub(super) fn member_index(&self) -> Option<usize> {
        self.membership.map(|(_, _, index)| index)
    }
    pub(super) fn is_l3_membership(&self) -> bool {
        self.profile == Profile::L3 && self.membership.is_some()
    }
    pub(super) fn check(&self, now: i64) -> EnclaveResult<()> {
        self.check_release(now)?;
        if let Some((identity, generation, index)) = self.membership {
            let active =
                load_native_membership(&self.state, Some(&self.authority), self.profile, now)?
                    .ok_or_else(|| err!(EACCES, "ASSET_ACTIVE_REQUIRED"))?;
            let enrolled = active.enrolled(index)?;
            let digest: [u8; 32] =
                Sha256::digest(enclave_core::jcs::to_jcs_bytes(&enrolled.credential)?).into();
            if active.membership_id() != identity
                || active.generation() != generation
                || active.source_binding() != self.vault_binding
                || digest != self.credential_sha256
            {
                fail!(EACCES, "ASSET_ACTIVE_BINDING");
            }
            return Ok(());
        }
        let (enrolled, binding) =
            load_native_enrollment(&self.state, Some(&self.authority), self.profile, now)?
                .ok_or_else(|| err!(EACCES, "ASSET_ACTIVE_REQUIRED"))?;
        let digest: [u8; 32] =
            Sha256::digest(enclave_core::jcs::to_jcs_bytes(&enrolled.credential)?).into();
        if binding != self.vault_binding || digest != self.credential_sha256 {
            fail!(EACCES, "ASSET_ACTIVE_BINDING");
        }
        Ok(())
    }
}
impl VaultService {
    fn asset_admin(peer: &PeerCredentials) -> EnclaveResult<()> {
        if peer.uid != 0 && peer.uid != enclave_core::ipc::geteuid() {
            fail!(EPERM, "ENROLL_ADMIN_ONLY");
        }
        Ok(())
    }
    fn asset_check(&self, generation: u64, deadline: u64) -> EnclaveResult<()> {
        self.require_selected_owner()?;
        if self
            .ceremony_cancelled
            .load(std::sync::atomic::Ordering::SeqCst)
            || self
                .cas_key_generation
                .load(std::sync::atomic::Ordering::SeqCst)
                != generation
        {
            fail!(EACCES, "CAS_ENROLLMENT_REVOKED");
        }
        if enclave_core::power::continuous_time_ns() >= deadline {
            fail!(ETIMEDOUT, "ASSET_SETUP_DEADLINE");
        }
        Ok(())
    }
    fn attach_setup_release(
        &self,
        generation: u64,
        deadline: u64,
        valid_until: i64,
    ) -> EnclaveResult<()> {
        self.attach_setup_dependency_release(generation, deadline, valid_until, None)
    }
    fn attach_setup_dependency_release(
        &self,
        generation: u64,
        deadline: u64,
        valid_until: i64,
        dependency: Option<Arc<BeginDependency>>,
    ) -> EnclaveResult<()> {
        let current = self.cas_key_generation.clone();
        let permit = self.selected_release_permit(
            self.cas_key_release.clone(),
            Arc::new(move || {
                if generation == u64::MAX
                    || current.load(std::sync::atomic::Ordering::SeqCst) != generation
                {
                    fail!(EACCES, "CAS_ENROLLMENT_REVOKED");
                }
                if SystemClock::default().now_ns() >= deadline {
                    fail!(ETIMEDOUT, "ASSET_SETUP_DEADLINE");
                }
                Self::check_authority_deadline(Some(valid_until), enclave_crypto::time::now_unix())
            }),
            selected_owner_dependency::SelectedOwnerReply::Authority,
        );
        let permit = if let Some(dependency) = dependency {
            permit.with_preflight(Arc::new(move || dependency.before(deadline)))
        } else {
            permit
        };
        let bound = Self::release_boot_deadline(Some(deadline), Some(valid_until))?
            .ok_or_else(|| err!(ETIMEDOUT, "ASSET_SETUP_DEADLINE"))?;
        let instant = std::time::Instant::now();
        let remaining = bound.saturating_sub(SystemClock::default().now_ns());
        enclave_core::ipc::attach_release_permit(
            permit.with_handoff_deadline(instant + std::time::Duration::from_nanos(remaining)),
        );
        Ok(())
    }
    /// Prepare public evidence only. A completed pending is retrievable without
    /// another makeCredential; an interrupted Preparing nonce is never reused.
    pub(super) fn begin_asset(&self, peer: &PeerCredentials) -> EnclaveResult<VaultResponse> {
        Self::asset_admin(peer)?;
        let generation = self
            .cas_key_generation
            .load(std::sync::atomic::Ordering::SeqCst);
        let mut guard = self.lock_sensitive_ceremony()?;
        let c = &mut *guard;
        if c.hw.credential.is_some() {
            fail!(EPERM, "ALREADY_ENROLLED");
        }
        let (state, profile, socket, dev) = {
            let st = self.lock_sensitive_state()?;
            (
                st.state_dir
                    .clone()
                    .ok_or_else(|| err!(EACCES, "ENROLLMENT_STATE_REQUIRED"))?,
                st.profile,
                st.socket_dir.clone(),
                st.dev_same_uid,
            )
        };
        if profile == Profile::L1 {
            fail!(EPERM, "ENROLL_NOT_APPLICABLE_L1");
        }
        if profile == Profile::L3
            && c.hw
                .yubikey
                .as_ref()
                .ok_or_else(|| err!(EACCES, "YUBIKEY_REQUIRED"))?
                .hub_depth()
                != 1
        {
            fail!(EACCES, "USB_HUB_FORBIDDEN_L3");
        }
        let authority =
            c.hw.asset_enrollment_authority
                .clone()
                .ok_or_else(|| err!(EACCES, "ASSET_AUTHORITY_REQUIRED"))?;
        let dependency =
            BeginDependency::acquire(&state, profile, socket.as_deref(), dev, c.hw.simulated)?;
        if self
            .ceremony_cancelled
            .load(std::sync::atomic::Ordering::SeqCst)
            || self
                .cas_key_generation
                .load(std::sync::atomic::Ordering::SeqCst)
                != generation
        {
            fail!(EACCES, "CAS_ENROLLMENT_REVOKED");
        }
        let _publication = membership_cutover::publication_lease(&state)?;
        let (mut store, mut ledger) = open(&state)?;
        match &ledger.phase {
            Phase::Pending(p) | Phase::Activating { pending: p, .. } => {
                if let Some(dependency) = dependency {
                    dependency.probe(dependency.end)?;
                    let current = self.cas_key_generation.clone();
                    let end = dependency.end;
                    let permit = self
                        .selected_release_permit(
                            self.cas_key_release.clone(),
                            Arc::new(move || {
                                if current.load(std::sync::atomic::Ordering::SeqCst) != generation {
                                    fail!(EACCES, "CAS_ENROLLMENT_REVOKED");
                                }
                                if std::time::Instant::now() >= end {
                                    fail!(ETIMEDOUT, "ASSET_SUPERVISOR_DEADLINE");
                                }
                                Ok(())
                            }),
                            selected_owner_dependency::SelectedOwnerReply::Authority,
                        )
                        .with_preflight(Arc::new(move || dependency.probe(end)))
                        .with_handoff_deadline(end);
                    enclave_core::ipc::attach_release_permit(permit);
                }
                return Ok(VaultResponse::AssetEnrollmentPending {
                    pending: p.evidence.clone(),
                });
            }
            Phase::Active { .. } => {
                fail!(EPERM, "ALREADY_ENROLLED");
            }
            Phase::MembershipPreparing { .. }
            | Phase::MembershipCommitted { .. }
            | Phase::MembershipRenewing { .. } => {
                fail!(EACCES, "ASSET_MEMBERSHIP_PENDING");
            }
            _ => {}
        }
        let policy = authority.policy(ledger.policy_floor, c.clock.now_unix())?;
        c.hw.refresh_metadata(profile, ActionClass::A4, c.clock.now_unix())?;
        let mds =
            c.hw.mds
                .clone()
                .ok_or_else(|| err!(EACCES, "CUSTODY_METADATA_UNAVAILABLE"))?;
        let mut nonce = [0; 32];
        enclave_core::rng::fill(&mut nonce);
        ledger.attempt = ledger
            .attempt
            .checked_add(1)
            .ok_or_else(|| err!(EACCES, "ASSET_ATTEMPTS_EXHAUSTED"))?;
        // Policy revision can be observed only after verifying the exact file.
        let signed: SignedAssetEnrollmentPolicy = serde_json::from_slice(
            &read_asset_authority_file(&authority.policy_file, 16 * 1024)?,
        )
        .map_err(|_| err!(EACCES, "ASSET_POLICY_DECODE"))?;
        let checked = signed.verify(
            &authority.policy_issuer,
            &authority.host,
            &authority.asset,
            &authority.custodian,
            ledger.policy_floor,
            c.clock.now_unix(),
        )?;
        if checked.digest() != policy.digest() {
            fail!(ESTALE, "ASSET_POLICY_CHANGED");
        }
        ledger.policy_floor = signed.policy.revision;
        ledger.phase = Phase::Preparing {
            nonce_sha256: Sha256::digest(nonce).into(),
        };
        store.save_json(&ledger)?;
        let start = c.clock.now_ns();
        let deadline = start
            .checked_add(crate::ceremony::CEREMONY_BUDGET_NS)
            .ok_or_else(|| err!(ETIMEDOUT, "ASSET_SETUP_DEADLINE"))?;
        let deadline =
            c.hw.metadata_source
                .as_ref()
                .and_then(|source| source.deadline_ns())
                .map_or(deadline, |bound| deadline.min(bound));
        self.asset_check(generation, deadline)?;
        if let Some(dependency) = &dependency {
            dependency.before(deadline)?;
            self.asset_check(generation, deadline)?;
        }
        let prompt = BiometricPrompt {
            localized_reason: policy.localized_reason(),
            d_jcs: policy.digest().to_vec(),
            nonce: nonce.to_vec(),
            t_start_ns: start,
            bio_key_blob: vec![],
        };
        let outcome = c.hw.biometric.evaluate(&prompt);
        self.asset_check(generation, deadline)?;
        if let Some(dependency) = &dependency {
            dependency.before(deadline)?;
            self.asset_check(generation, deadline)?;
        }
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
        let provider = &mut c.hw.existing_pin;
        let dev =
            c.hw.yubikey
                .as_mut()
                .ok_or_else(|| err!(EACCES, "YUBIKEY_REQUIRED"))?;
        if !c.hw.simulated {
            enclave_core::power::require_selected_usb_instance()?;
        }
        if let Some(dependency) = &dependency {
            dependency.before(deadline)?;
            self.asset_check(generation, deadline)?;
        }
        let mut client = CtapClient::open_with_deadline(dev.as_mut(), deadline)?;
        let policy_revision = ledger.policy_floor;
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
            &SystemClock,
            &self.ceremony_cancelled,
            Some(&mut pin),
            |evidence| {
                ledger.phase = Phase::Pending(Pending {
                    evidence: evidence.clone(),
                    bio_public_key: bio_public_key.clone(),
                    bio_key_blob: bio_key_blob.clone(),
                    policy_revision,
                    profile,
                });
                store.save_json(&ledger)
            },
        )?;
        drop(client);
        let pending = Pending {
            evidence,
            bio_public_key,
            bio_key_blob,
            policy_revision,
            profile,
        };
        // Preserve the new nonresident handle even when removal won immediately
        // after the response. Activation always needs a new live ceremony.
        ledger.phase = Phase::Pending(pending.clone());
        store.save_json(&ledger)?;
        self.asset_check(generation, deadline)?;
        if let Some(dependency) = &dependency {
            dependency.before(deadline)?;
            self.asset_check(generation, deadline)?;
        }
        let valid_until = signed.policy.expires_unix.min(mds.expires_at).min(
            mds.refreshed_at
                .saturating_add(crate::ctap::mds::freshness_window_s(profile)),
        );
        self.attach_setup_dependency_release(generation, deadline, valid_until, dependency)?;
        Ok(VaultResponse::AssetEnrollmentPending {
            pending: pending.evidence,
        })
    }
}

impl VaultService {
    pub(super) fn activate_asset(
        &self,
        peer: &PeerCredentials,
        receipt: AssetEnrollmentReceipt,
    ) -> EnclaveResult<VaultResponse> {
        self.admit_asset(peer, receipt, false)
    }
    pub(super) fn renew_asset(
        &self,
        peer: &PeerCredentials,
        receipt: AssetEnrollmentReceipt,
    ) -> EnclaveResult<VaultResponse> {
        self.admit_asset(peer, receipt, true)
    }
    fn admit_asset(
        &self,
        peer: &PeerCredentials,
        receipt: AssetEnrollmentReceipt,
        renewal: bool,
    ) -> EnclaveResult<VaultResponse> {
        Self::asset_admin(peer)?;
        let mut generation = self
            .cas_key_generation
            .load(std::sync::atomic::Ordering::SeqCst);
        let mut guard = self.lock_sensitive_ceremony()?;
        let c = &mut *guard;
        if !renewal && c.hw.credential.is_some() {
            fail!(EPERM, "ALREADY_ENROLLED");
        }
        let (state, profile, grant_key) = {
            let st = self.lock_sensitive_state()?;
            (
                st.state_dir
                    .clone()
                    .ok_or_else(|| err!(EACCES, "ENROLLMENT_STATE_REQUIRED"))?,
                st.profile,
                st.envelope_grant_key,
            )
        };
        let authority =
            c.hw.asset_enrollment_authority
                .clone()
                .ok_or_else(|| err!(EACCES, "ASSET_AUTHORITY_REQUIRED"))?;
        let _publication = membership_cutover::publication_lease(&state)?;
        let (mut ledger_store, mut ledger) = open(&state)?;
        let (pending, mut staged, active_binding) = match &ledger.phase {
            Phase::Pending(p) if !renewal => (p.clone(), None, None),
            Phase::Activating {
                pending,
                staged,
                renewal: old,
            } if *old == renewal => (pending.clone(), staged.clone(), None),
            Phase::Active {
                pending,
                vault_binding,
                ..
            } if renewal => (pending.clone(), None, Some(*vault_binding)),
            _ => {
                fail!(EACCES, "ASSET_PENDING_REQUIRED");
            }
        };
        if let Some(enrolled) = &c.hw.credential {
            if enclave_core::jcs::to_jcs_bytes(enrolled)?
                != enclave_core::jcs::to_jcs_bytes(pending.evidence.credential())?
            {
                fail!(EACCES, "ASSET_ACTIVE_BINDING");
            }
        }
        if pending.profile != profile || pending.bio_public_key != pending.evidence.sep_public_key {
            fail!(EACCES, "ASSET_LEDGER_BINDING");
        }
        let policy = authority.policy(ledger.policy_floor, c.clock.now_unix())?;
        let minimum = ledger
            .receipt_floor
            .checked_add(1)
            .ok_or_else(|| err!(EACCES, "ASSET_RECEIPT_EXHAUSTED"))?;
        let credential = receipt.clone().activate(
            pending.evidence.clone(),
            &policy,
            &authority.inventory_issuer,
            minimum,
            c.clock.now_unix(),
        )?;
        if profile == Profile::L3
            && c.hw
                .yubikey
                .as_ref()
                .ok_or_else(|| err!(EACCES, "YUBIKEY_REQUIRED"))?
                .hub_depth()
                != 1
        {
            fail!(EACCES, "USB_HUB_FORBIDDEN_L3");
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
        context.admit(profile, "C3", c.clock.now_unix(), false)?;
        context.admit(profile, "C4", c.clock.now_unix(), false)?;
        let now = c.clock.now_unix();
        let revision = c.hw.asset_metadata(profile, &credential, now)?;
        let key = proof_key(&pending)?;
        if renewal {
            // Establish the existing release fence before capturing state.
            // Old leases/grants stay revoked even if renewal later fails.
            self.revoke_cas_keys()?;
            generation = self
                .cas_key_generation
                .load(std::sync::atomic::Ordering::SeqCst);
            self.prepare_fresh_authorization(generation)?;
            c.enter_generation(generation);
        }
        {
            // Serialize the checkpoint with public ingestion. Every completed
            // prior seal is included; after this marker the old guard refuses.
            let mut st = self.lock_sensitive_state()?;
            if let Some(expected) = active_binding {
                let checkpoint = if st.vault.is_enrolled() {
                    st.vault.checkpoint()?
                } else {
                    let (_, loaded) = SealedStore::open_bounded_required(
                        &state.join("vault-envelopes"),
                        "envelopes",
                        32 * 1024 * 1024,
                    )?;
                    let Loaded::State(bytes)=loaded else {fail!(EACCES,"ASSET_STAGED_ENVELOPE_REQUIRED");};
                    enclave_core::sealed::decode::<crate::vault::VaultEnvelopeCheckpoint>(&bytes)?
                };
                if binding(&checkpoint)? != expected {
                    fail!(EACCES, "ASSET_VAULT_BINDING");
                }
                staged = Some(checkpoint);
            }
            if renewal && staged.is_none() {
                fail!(EACCES, "ASSET_STAGED_ENVELOPE_REQUIRED");
            }
            // Burn the independent receipt generation BEFORE any UI/key operation.
            if renewal {
                ledger.version = 2;
            }
            ledger.receipt_floor = receipt.generation;
            ledger.phase = Phase::Activating {
                pending: pending.clone(),
                staged: staged.clone(),
                renewal,
            };
            ledger_store.save_json(&ledger)?;
            if renewal {
                st.cas_key_leases.clear();
                st.cas_key_deadlines.clear();
                st.namespace_challenges.clear();
            }
        }
        let mut intent = b"depot-AssetActivation-v1\0".to_vec();
        intent.push(u8::from(renewal));
        intent.extend(pending.evidence.digest()?);
        intent.extend(receipt.signing_message()?);
        intent.extend(&receipt.signature);
        intent.extend(context.digest());
        let digest: [u8; 32] = Sha256::digest(intent).into();
        let start = c.clock.now_ns();
        let deadline = start
            .checked_add(crate::ceremony::CEREMONY_BUDGET_NS)
            .ok_or_else(|| err!(ETIMEDOUT, "ASSET_SETUP_DEADLINE"))?;
        let deadline = [
            Some(deadline),
            context.deadline_ns(),
            c.hw.metadata_source
                .as_ref()
                .and_then(|source| source.deadline_ns()),
        ]
        .into_iter()
        .flatten()
        .min()
        .ok_or_else(|| err!(ETIMEDOUT, "ASSET_SETUP_DEADLINE"))?;
        let mut nonce = [0; 32];
        enclave_core::rng::fill(&mut nonce);
        let prompt = BiometricPrompt {
            localized_reason: format!(
                "[{} exact independently admitted asset] {}",
                if renewal { "Renew" } else { "Activate" },
                policy.localized_reason()
            ),
            d_jcs: digest.to_vec(),
            nonce: nonce.to_vec(),
            t_start_ns: start,
            bio_key_blob: pending.bio_key_blob.clone(),
        };
        self.asset_check(generation, deadline)?;
        receipt.clone().activate(
            pending.evidence.clone(),
            &policy,
            &authority.inventory_issuer,
            ledger.receipt_floor,
            c.clock.now_unix(),
        )?;
        let outcome = c.hw.biometric.evaluate(&prompt);
        self.asset_check(generation, deadline)?;
        let sep_signature = crate::biometric::verify_approval(&key, &prompt, &outcome)?;
        let mut chained = b"depot-AssetActivation-CTAP-v1\0".to_vec();
        chained.extend(digest);
        chained.extend(sep_signature);
        chained.extend(start.to_be_bytes());
        let challenge: [u8; 32] = Sha256::digest(chained).into();
        if !renewal {
            c.hw.sep.create_tier_keys()?;
        }
        self.asset_check(generation, deadline)?;
        let a3 = c.hw.sep.ecdh_share(PrfTier::A3)?;
        self.asset_check(generation, deadline)?;
        let a4 = c.hw.sep.ecdh_share(PrfTier::A4)?;
        self.asset_check(generation, deadline)?;
        let mut salts = [0; 64];
        salts[..32].copy_from_slice(&PrfTier::A3.salt());
        salts[32..].copy_from_slice(&PrfTier::A4.salt());
        let before = c.counters.clone();
        let prf = (|| {
            let provider = &mut c.hw.existing_pin;
            let dev =
                c.hw.yubikey
                    .as_mut()
                    .ok_or_else(|| err!(EACCES, "YUBIKEY_REQUIRED"))?;
            let mut client = CtapClient::open_with_deadline(dev.as_mut(), deadline)?;
            let builtin = client.get_info()?.built_in_uv;
            let (response, shared) = if profile == Profile::L3 && !builtin {
                let provider = provider
                    .as_mut()
                    .ok_or_else(|| err!(EACCES, "YUBIKEY_PIN_PROVIDER_REQUIRED"))?;
                client.get_assertion_dual_prf_with_pin_provider(
                    &credential.credential_id,
                    &challenge,
                    &salts,
                    deadline,
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
            self.asset_check(generation, deadline)?;
            let verified = crate::ctap::assertion::verify_assertion(
                &credential,
                &response,
                &challenge,
                profile == Profile::L3,
                &mut c.counters,
            )?;
            let encrypted = verified
                .hmac_secret_enc
                .ok_or_else(|| err!(EACCES, "PRF_MISSING"))?;
            crate::ctap::client::decrypt_prf(
                &shared.ok_or_else(|| err!(EACCES, "PRF_MISSING"))?,
                &encrypted,
            )
        })();
        c.persist_counters(&before)?;
        let prf = prf?;
        if prf.len() != 64 {
            fail!(EACCES, "PRF_OUTPUT_LEN");
        }
        self.asset_check(generation, deadline)?;
        c.hw.revalidate_asset_metadata(revision, profile, &credential, c.clock.now_unix())?;
        let mds =
            c.hw.mds
                .as_ref()
                .ok_or_else(|| err!(EACCES, "CUSTODY_METADATA_UNAVAILABLE"))?;
        let valid_until = receipt
            .expires_unix
            .min(context.expires_unix())
            .min(mds.expires_at)
            .min(
                mds.refreshed_at
                    .saturating_add(crate::ctap::mds::freshness_window_s(profile)),
            );
        policy.check(&credential.aaguid, c.clock.now_unix())?;
        let current = authority.policy(ledger.policy_floor, c.clock.now_unix())?;
        if current.digest() != policy.digest() {
            fail!(ESTALE, "ASSET_POLICY_CHANGED");
        }
        let current_context =
            source.envelope_context(&envelope_authority, profile, c.clock.now_unix())?;
        if current_context.digest() != context.digest() {
            fail!(ESTALE, "ENVELOPE_POLICY_CHANGED_MIGRATION_REQUIRED");
        }
        let context = context.with_transport_lifetime(
            enclave_core::custody_lifetime::CapturedCustodyLifetime {
                valid_until_unix: current_context.expires_unix(),
                deadline_ns: current_context
                    .deadline_ns()
                    .ok_or_else(|| err!(ESTALE, "ENVELOPE_TRANSPORT_EXPIRED"))?,
            },
            c.clock.now_unix(),
        )?;
        let deadline = [
            Some(deadline),
            context.deadline_ns(),
            c.hw.metadata_source
                .as_ref()
                .and_then(|source| source.deadline_ns()),
        ]
        .into_iter()
        .flatten()
        .min()
        .ok_or_else(|| err!(ETIMEDOUT, "ASSET_SETUP_DEADLINE"))?;
        let valid_until = valid_until.min(context.expires_unix());
        self.asset_check(generation, deadline)?;
        let directory = state.join("vault-envelopes");
        let (mut envelope_store, loaded) = if renewal {
            SealedStore::open_bounded_required(&directory, "envelopes", 32 * 1024 * 1024)?
        } else {
            SealedStore::open_bounded(&directory, "envelopes", 32 * 1024 * 1024)?
        };
        let seed = enclave_core::sealed::sealing_key(&directory, "custody-surrogate-v2")?;
        let a3_shares = KekShares {
            sep_ecdh_share: a3.expose(),
            yubikey_prf: &prf.expose()[..32],
        };
        let a4_shares = KekShares {
            sep_ecdh_share: a4.expose(),
            yubikey_prf: &prf.expose()[32..],
        };
        let vault = match staged {
            Some(checkpoint) => {
                checkpoint.verify_factor_shares(&a3_shares, &a4_shares)?;
                CustodyVault::restore_authorized(
                    checkpoint,
                    profile,
                    grant_key,
                    &context,
                    seed,
                    c.clock.now_unix(),
                )?
            }
            None => CustodyVault::enroll_authorized(
                profile,
                &a3_shares,
                &a4_shares,
                grant_key,
                &context,
                seed,
                c.clock.now_unix(),
            )?,
        };
        let checkpoint = vault.checkpoint()?;
        let vault_binding = binding(&checkpoint)?;
        if let Loaded::State(bytes) = loaded {
            let old: crate::vault::VaultEnvelopeCheckpoint = enclave_core::sealed::decode(&bytes)?;
            if binding(&old)? != vault_binding {
                fail!(EACCES, "ASSET_STAGED_ENVELOPE_BINDING");
            }
        }
        // Public/wrapped staged keys survive a crash before their separate file
        // is committed. Retrying requires a strictly newer independent receipt.
        ledger.phase = Phase::Activating {
            pending: pending.clone(),
            staged: Some(checkpoint.clone()),
            renewal,
        };
        ledger_store.save_json(&ledger)?;
        self.asset_check(generation, deadline)?;
        envelope_store.save_json(&checkpoint)?;
        self.asset_check(generation, deadline)?;
        let mut st = self.lock_sensitive_state()?;
        self.asset_check(generation, deadline)?;
        policy.check(&credential.aaguid, c.clock.now_unix())?;
        context.admit(profile, "C4", c.clock.now_unix(), false)?;
        receipt.clone().activate(
            pending.evidence.clone(),
            &policy,
            &authority.inventory_issuer,
            ledger.receipt_floor,
            c.clock.now_unix(),
        )?;
        let active_guard = ActiveAssetGuard::for_receipt(
            state,
            authority.clone(),
            profile,
            vault_binding,
            &credential,
            &receipt,
        )?;
        let mut active_lifecycle = CustodyLifecycle::boot(profile);
        if profile == Profile::L2 {
            active_lifecycle.on(CustodyEvent::PublicIngestInit)?;
        }
        ledger.phase = Phase::Active {
            pending: pending.clone(),
            receipt: receipt.clone(),
            vault_binding,
        };
        ledger_store.save_json(&ledger)?;
        let final_admission = self
            .asset_check(generation, deadline)
            .and_then(|()| {
                receipt
                    .clone()
                    .activate(
                        pending.evidence.clone(),
                        &policy,
                        &authority.inventory_issuer,
                        ledger.receipt_floor,
                        c.clock.now_unix(),
                    )
                    .map(|_| ())
            })
            .and_then(|()| active_guard.check(c.clock.now_unix()))
            .and_then(|()| self.asset_check(generation, deadline))
            // State is held: never block waiting for the release serial in this
            // order. All persistence/authority I/O completed before this try.
            .and_then(|()| {
                self.cas_key_release
                    .try_lock()
                    .map_err(|error| match error {
                        std::sync::TryLockError::WouldBlock => err!(EAGAIN, "CUSTODY_RELEASE_BUSY"),
                        std::sync::TryLockError::Poisoned(_) => err!(EIO, "CAS_RELEASE_LOCK"),
                    })
            })
            .and_then(|release| {
                self.asset_check(generation, deadline)?;
                active_guard.check_release(c.clock.now_unix())?;
                Self::check_authority_deadline(Some(valid_until), c.clock.now_unix())?;
                Ok(release)
            });
        let _release = match final_admission {
            Ok(release) => release,
            Err(error) => {
                ledger.phase = Phase::Activating {
                    pending: pending.clone(),
                    staged: Some(checkpoint),
                    renewal,
                };
                if let Err(persist) = ledger_store.save_json(&ledger) {
                    st.envelope_fault = true;
                    self.cas_keys_enabled
                        .store(false, std::sync::atomic::Ordering::SeqCst);
                    return Err(persist);
                }
                return Err(error);
            }
        };
        // The Active ledger is the atomic acknowledgement authority. Existing
        // enrollment.sealed is a legacy format and is never rewritten here.
        st.active_asset_guard = Some(active_guard.clone());
        c.hw.active_asset_guard = Some(active_guard);
        st.vault = vault;
        st.envelope_store = Some(envelope_store);
        st.envelope_policy_digest = Some(context.digest());
        st.envelope_valid_until_unix = Some(context.policy_expires_unix());
        st.envelope_deadline_ns = context.deadline_ns();
        st.envelope_policy_source = Some(source);
        st.envelope_authority = Some(envelope_authority);
        st.envelope_fault = false;
        st.lifecycle = active_lifecycle;
        c.hw.credential = Some(credential.clone());
        c.hw.sep_bio_key = key;
        c.hw.sep_bio_blob = Some(pending.bio_key_blob);
        c.hw.asset_activation_binding = Some(vault_binding);
        c.setup_only = false;
        self.cas_enrolled_generation
            .store(generation, std::sync::atomic::Ordering::SeqCst);
        let setup_only = profile == Profile::L3 && !c.hw.simulated;
        self.cas_keys_enabled
            .store(!setup_only, std::sync::atomic::Ordering::SeqCst);
        if setup_only {
            self.attach_setup_release(generation, deadline, valid_until)?;
        } else {
            self.attach_lifecycle_release(
                generation,
                Some(deadline),
                Some(valid_until),
                st.active_asset_guard.clone(),
            )?;
        }
        let sas = enclave_crypto::sas::sas_words(blake3::hash(&credential.key.to_raw()).as_bytes());
        Ok(VaultResponse::Enrolled {
            credential_id: hex::encode(&credential.credential_id),
            aaguid: hex::encode(credential.aaguid),
            firmware_version: credential.firmware_version,
            sas,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctap::asset_enrollment::{AssetEnrollmentPolicy, AttestationMode};
    use enclave_crypto::hpke_envelope::{EnvelopePolicy, SignedEnvelopePolicy};
    use std::{
        os::unix::{
            fs::{DirBuilderExt, MetadataExt, PermissionsExt},
            net::UnixListener,
        },
        sync::atomic::{AtomicBool, Ordering},
    };
    pub(super) struct Root(pub(super) PathBuf);
    impl Root {
        pub(super) fn new() -> Self {
            // Immutable-source builds can have long manifest paths. The private
            // chroot runner alone supplies a short, already protected fixture base;
            // production never reads this test-only setting or uses global /tmp.
            let base = match std::env::var_os("ENCLAVE_TEST_STATE_ROOT") {
                Some(path) => {
                    let path = PathBuf::from(path);
                    let metadata = std::fs::symlink_metadata(&path).unwrap();
                    assert!(
                        path.is_absolute()
                            && metadata.is_dir()
                            && metadata.uid() == enclave_core::ipc::geteuid()
                            && metadata.mode() & 0o077 == 0
                    );
                    path
                }
                None => Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"),
            };
            let p = base.join(format!("asset-workflow-{:x}", enclave_core::rng::u64()));
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o755)
                .create(&p)
                .unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(p.canonicalize().unwrap())
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    pub(super) fn fixture(
        root: &Root,
    ) -> (Arc<VaultService>, SigningKey, AssetEnrollmentAuthority) {
        fixture_profile(root, Profile::L2)
    }
    fn fixture_profile(
        root: &Root,
        profile: Profile,
    ) -> (Arc<VaultService>, SigningKey, AssetEnrollmentAuthority) {
        let now = enclave_crypto::time::now_unix();
        let issuer = SigningKey::from_bytes(&[61; 32]);
        let inventory = SigningKey::from_bytes(&[62; 32]);
        let hw = VaultHardware::simulated(profile, now).unwrap();
        let aaguid = hw.credential.as_ref().unwrap().aaguid;
        let policy = AssetEnrollmentPolicy {
            version: 1,
            revision: 3,
            host_id: "host".into(),
            asset_id: "asset".into(),
            custodian_id: "custodian".into(),
            aaguid,
            mode: AttestationMode::BasicWithIndependentAsset,
            enterprise_leaf_sha256: None,
            rationale: "independent fixture inventory".into(),
            issued_unix: now - 1,
            expires_unix: now + 3600,
        };
        let signature = issuer
            .sign(&policy.signing_message().unwrap())
            .to_bytes()
            .to_vec();
        let policy_file = root.0.join("asset-policy.json");
        std::fs::write(
            &policy_file,
            serde_json::to_vec(&SignedAssetEnrollmentPolicy { policy, signature }).unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&policy_file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let authority = AssetEnrollmentAuthority {
            policy_issuer: issuer.verifying_key(),
            inventory_issuer: inventory.verifying_key(),
            policy_file,
            host: "host".into(),
            asset: "asset".into(),
            custodian: "custodian".into(),
        };
        let service = VaultService::start(
            VaultConfig {
                profile,
                state_dir: Some(root.0.join("state")),
                ..Default::default()
            },
            hw,
        )
        .unwrap();
        {
            let mut c = service.lock_ceremony().unwrap();
            c.hw.credential = None;
            c.hw.asset_enrollment_authority = Some(authority.clone());
        }
        service.lock_state().unwrap().vault = CustodyVault::unenrolled(profile, None);
        (service, inventory, authority)
    }
    fn receipt(
        pending: &PendingAssetEnrollment,
        inventory: &SigningKey,
        generation: u64,
    ) -> AssetEnrollmentReceipt {
        let now = enclave_crypto::time::now_unix();
        let mut receipt = AssetEnrollmentReceipt {
            version: 1,
            pending_sha256: pending.digest().unwrap(),
            generation,
            issued_unix: now,
            expires_unix: now + 120,
            signature: vec![],
        };
        receipt.signature = inventory
            .sign(&receipt.signing_message().unwrap())
            .to_bytes()
            .to_vec();
        receipt
    }
    fn cas(root: &Root, issuer: &SigningKey) -> (Arc<AtomicBool>, std::thread::JoinHandle<()>) {
        cas_with_expiry(
            root,
            issuer,
            Arc::new(std::sync::atomic::AtomicI64::new(
                enclave_crypto::time::now_unix() + 3600,
            )),
        )
    }
    fn cas_with_expiry(
        root: &Root,
        issuer: &SigningKey,
        expiry: Arc<std::sync::atomic::AtomicI64>,
    ) -> (Arc<AtomicBool>, std::thread::JoinHandle<()>) {
        cas_with_profile(root, issuer, expiry, Profile::L2)
    }
    fn cas_with_profile(
        root: &Root,
        issuer: &SigningKey,
        expiry: Arc<std::sync::atomic::AtomicI64>,
        profile: Profile,
    ) -> (Arc<AtomicBool>, std::thread::JoinHandle<()>) {
        let now = enclave_crypto::time::now_unix();
        let policy = EnvelopePolicy {
            version: 1,
            revision: 1,
            subject: "host".into(),
            namespace: "data".into(),
            issued_unix: now - 1,
            expires_unix: now + 3600,
            review_unix: now + 3600,
            owner: "fixture".into(),
            profiles: vec![profile],
            data_classes: vec!["C3".into(), "C4".into()],
            purpose: "fixture bootstrap".into(),
            migration: "none".into(),
            disclosure: None,
            classical_exception: false,
        };
        let signature = issuer
            .sign(&policy.signing_message().unwrap())
            .to_bytes()
            .to_vec();
        let bytes = serde_json::to_vec(&SignedEnvelopePolicy { policy, signature }).unwrap();
        let path = root.0.join(DaemonId::SwarmSync.socket_name());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let signal = stop.clone();
        let worker = std::thread::spawn(move || {
            // Bounded fixture lifetime also covers real61s prompt-window waits;
            // signed authority expiry and each request's10s cap are unchanged.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(240);
            while !signal.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                            .unwrap();
                        let raw = enclave_core::ipc::read_frame(&mut stream).unwrap();
                        use enclave_core::custody_metadata::{CustodyTarget, CustodyTargetReceipt};
                        #[derive(Deserialize)]
                        enum Request {
                            FetchCustodyTarget { target: CustodyTarget },
                        }
                        let Request::FetchCustodyTarget { target } =
                            enclave_core::ipc::from_cbor(&raw).unwrap();
                        assert_eq!(target, CustodyTarget::EnvelopePolicy);
                        #[derive(Serialize)]
                        enum Response {
                            CustodyTarget(CustodyTargetReceipt),
                        }
                        let receipt = CustodyTargetReceipt {
                            v: 1,
                            effective_profile: profile,
                            target: target.target_name().into(),
                            bytes: bytes.clone().into(),
                            refreshed_at: now,
                            expires_at: expiry.load(Ordering::SeqCst),
                            verified_now: enclave_crypto::time::now_unix(),
                            versions: (1, 1, 1),
                            blake3: blake3::hash(&bytes).to_hex().to_string(),
                        };
                        let reply = enclave_core::ipc::Reply::Ok(Response::CustodyTarget(receipt));
                        enclave_core::ipc::write_frame(
                            &mut stream,
                            &enclave_core::ipc::to_cbor(&reply).unwrap(),
                        )
                        .unwrap();
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(1))
                    }
                    Err(e) => panic!("{e}"),
                }
            }
        });
        (stop, worker)
    }
    #[test]
    fn native_workflow_persists_pending_activates_once_and_restores_public_identity() {
        let root = Root::new();
        let (service, inventory, authority) = fixture(&root);
        let peer = PeerCredentials::local(0, 0);
        let pending = match service.begin_asset(&peer).unwrap() {
            VaultResponse::AssetEnrollmentPending { pending } => pending,
            _ => panic!(),
        };
        let original = pending.digest().unwrap();
        let again = match service.begin_asset(&peer).unwrap() {
            VaultResponse::AssetEnrollmentPending { pending } => pending,
            _ => panic!(),
        };
        assert_eq!(again.digest().unwrap(), original);
        assert!(load_native_enrollment(
            &root.0.join("state"),
            Some(&authority),
            Profile::L2,
            enclave_crypto::time::now_unix()
        )
        .unwrap()
        .is_none());
        let envelope_issuer = SigningKey::from_bytes(&[63; 32]);
        let (stop, worker) = cas(&root, &envelope_issuer);
        {
            let mut c = service.lock_ceremony().unwrap();
            c.hw.metadata_source = Some(crate::metadata_source::CustodyMetadataSource::new(
                root.0.clone(),
                true,
            ));
            c.hw.envelope_authority = Some(crate::metadata_source::EnvelopeAuthorityConfig {
                issuer: envelope_issuer.verifying_key(),
                subject: "host".into(),
                namespace: "data".into(),
            });
        }
        let receipt = receipt(&pending, &inventory, 7);
        service.activate_asset(&peer, receipt.clone()).unwrap();
        assert!(service
            .activate_asset(&peer, receipt)
            .unwrap_err()
            .is("ALREADY_ENROLLED"));
        let (enrolled, admitted) = load_native_enrollment(
            &root.0.join("state"),
            Some(&authority),
            Profile::L2,
            enclave_crypto::time::now_unix(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            enrolled.credential.credential_id,
            pending.credential().credential_id
        );
        assert_eq!(
            service
                .lock_state()
                .unwrap()
                .vault
                .checkpoint()
                .unwrap()
                .enrollment_binding()
                .unwrap(),
            admitted
        );
        let now = enclave_crypto::time::now_unix();
        // A running service must revalidate the independent authority; boot-time
        // admission does not turn this bounded receipt into perpetual custody.
        service
            .lock_state()
            .unwrap()
            .refresh_envelope_policy(now)
            .unwrap();
        assert!(service
            .lock_state()
            .unwrap()
            .refresh_envelope_policy(now + 121)
            .unwrap_err()
            .is("ASSET_ENROLLMENT_RECEIPT"));
        assert!(service
            .lock_ceremony()
            .unwrap()
            .hw
            .refresh_metadata(Profile::L2, ActionClass::A3, now + 121)
            .unwrap_err()
            .is("ASSET_ENROLLMENT_RECEIPT"));
        // Loss of durable admission during execution also refuses at the next
        // release boundary; no in-memory credential can substitute for it.
        std::fs::remove_file(root.0.join("state/asset-enrollment/workflow.sealed")).unwrap();
        assert!(service
            .lock_state()
            .unwrap()
            .refresh_envelope_policy(now)
            .is_err());
        stop.store(true, Ordering::SeqCst);
        worker.join().unwrap();
    }
    fn configure_envelope(service: &VaultService, root: &Root, issuer: &SigningKey) {
        let mut c = service.lock_ceremony().unwrap();
        c.hw.metadata_source = Some(crate::metadata_source::CustodyMetadataSource::new(
            root.0.clone(),
            true,
        ));
        c.hw.envelope_authority = Some(crate::metadata_source::EnvelopeAuthorityConfig {
            issuer: issuer.verifying_key(),
            subject: "host".into(),
            namespace: "data".into(),
        });
    }
    #[test]
    fn l2_public_ingest_needs_no_tier_key_but_prepared_reply_cannot_cross_asset_generation_fence() {
        use enclave_core::ipc::{self, PeerPolicy, SocketAccess};
        use std::{sync::atomic::AtomicUsize, time::Duration};
        let root = Root::new();
        let (service, inventory, _) = fixture(&root);
        let peer = PeerCredentials::local(0, 0);
        let pending = match service.begin_asset(&peer).unwrap() {
            VaultResponse::AssetEnrollmentPending { pending } => pending,
            _ => panic!(),
        };
        let issuer = SigningKey::from_bytes(&[63; 32]);
        let (cas_stop, cas_worker) = cas(&root, &issuer);
        configure_envelope(&service, &root, &issuer);
        service
            .activate_asset(&peer, receipt(&pending, &inventory, 7))
            .unwrap();
        service.cas_keys_enabled.store(false, Ordering::SeqCst);
        let current = std::env::current_dir().unwrap();
        let from: Vec<_> = current.components().collect();
        let to: Vec<_> = root.0.components().collect();
        let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
        let mut relative = std::path::PathBuf::new();
        for _ in common..from.len() {
            relative.push("..");
        }
        for component in &to[common..] {
            relative.push(component.as_os_str());
        }
        let socket = relative.join("v.sock");
        let listener = ipc::bind(&socket, SocketAccess::OwnerOnly).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = service.clone();
        let calls = AtomicUsize::new(0);
        let (prepared_tx, prepared_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let resume = Mutex::new(resume_rx);
        let server = std::thread::spawn(move || {
            ipc::serve(
                listener,
                PeerPolicy::allow([ipc::geteuid()]),
                Arc::new(move |peer: &PeerCredentials, request: VaultRequest| {
                    let result = worker.handle(peer, request);
                    if calls.fetch_add(1, Ordering::SeqCst) == 1 {
                        assert!(result.is_ok(), "{result:?}");
                        prepared_tx.send(()).unwrap();
                        resume
                            .lock()
                            .unwrap()
                            .recv_timeout(Duration::from_secs(5))
                            .unwrap();
                    }
                    result
                }),
                stopped,
            )
        });
        let request = VaultRequest::Tokenize {
            items: vec![TokenizeItem {
                value: "public-ingest@example.invalid".into(),
                declared: None,
            }],
            bulk_set: false,
            grant: None,
        };
        let mut client = ipc::Client::connect(&socket, ipc::geteuid()).unwrap();
        client.set_timeout(Some(Duration::from_secs(5))).unwrap();
        let _: VaultResponse = client.call(&request).unwrap();
        assert!(!service.cas_keys_authorized());
        let blocked = std::thread::spawn(move || client.call::<_, VaultResponse>(&request));
        prepared_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        service.revoke_cas_keys().unwrap();
        resume_tx.send(()).unwrap();
        assert!(blocked.join().unwrap().is_err());
        stop.store(true, Ordering::SeqCst);
        server.join().unwrap().unwrap();
        cas_stop.store(true, Ordering::SeqCst);
        cas_worker.join().unwrap();
    }
    #[test]
    fn shorter_authenticated_chain_refuses_prepared_reply_and_old_lease_but_fresh_admission_works()
    {
        use enclave_core::ipc::{self, PeerPolicy, SocketAccess};
        use std::{
            sync::atomic::{AtomicI64, AtomicUsize},
            time::Duration,
        };
        let root = Root::new();
        let (service, inventory, _) = fixture(&root);
        let peer = PeerCredentials::local(0, 0);
        let pending = match service.begin_asset(&peer).unwrap() {
            VaultResponse::AssetEnrollmentPending { pending } => pending,
            _ => panic!(),
        };
        let issuer = SigningKey::from_bytes(&[63; 32]);
        let now = enclave_crypto::time::now_unix();
        let expiry = Arc::new(AtomicI64::new(now + 60));
        let (cas_stop, cas_worker) = cas_with_expiry(&root, &issuer, expiry.clone());
        configure_envelope(&service, &root, &issuer);
        service
            .activate_asset(&peer, receipt(&pending, &inventory, 7))
            .unwrap();
        // Exercise production State policy refresh with explicitly synthetic
        // authority/factors and local CAS. This is not a native SDK/SEP test.
        service.lock_state().unwrap().simulated = false;
        let shape = enclave_crypto::namespace::WrappedNamespaceKey {
            namespace: "models".into(),
            epoch: 1,
            wrapping_epoch: 1,
            envelope_hex: "00".repeat(72),
        };
        let (_, old_lease) = service.cas_key_custody(&peer, &shape).unwrap();
        let old_expiry = old_lease.expires_unix;
        let old_deadline = *service
            .lock_state()
            .unwrap()
            .cas_key_deadlines
            .get(&old_lease.id)
            .unwrap();
        assert!(
            old_expiry > now + 30 && old_expiry <= now + 60,
            "old admission retains a usable conservatively translated long chain cap"
        );
        let current = std::env::current_dir().unwrap();
        let from: Vec<_> = current.components().collect();
        let to: Vec<_> = root.0.components().collect();
        let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
        let mut relative = std::path::PathBuf::new();
        for _ in common..from.len() {
            relative.push("..");
        }
        for component in &to[common..] {
            relative.push(component.as_os_str());
        }
        let socket = relative.join("c.sock");
        let listener = ipc::bind(&socket, SocketAccess::OwnerOnly).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = service.clone();
        let calls = AtomicUsize::new(0);
        let (prepared_tx, prepared_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let resume = Mutex::new(resume_rx);
        let server = std::thread::spawn(move || {
            ipc::serve(
                listener,
                PeerPolicy::allow([ipc::geteuid()]),
                Arc::new(move |peer: &PeerCredentials, request: VaultRequest| {
                    let result = worker.handle(peer, request);
                    if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        assert!(result.is_ok(), "{result:?}");
                        prepared_tx.send(()).unwrap();
                        resume
                            .lock()
                            .unwrap()
                            .recv_timeout(Duration::from_secs(5))
                            .unwrap();
                    }
                    result
                }),
                stopped,
            )
        });
        let request = VaultRequest::Tokenize {
            items: vec![TokenizeItem {
                value: "chain-bound@example.invalid".into(),
                declared: None,
            }],
            bulk_set: false,
            grant: None,
        };
        let path = socket.clone();
        let outgoing = request.clone();
        let blocked = std::thread::spawn(move || {
            let mut client = ipc::Client::connect(&path, ipc::geteuid()).unwrap();
            client.set_timeout(Some(Duration::from_secs(5))).unwrap();
            client.call::<_, VaultResponse>(&outgoing)
        });
        prepared_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        expiry.store(now + 30, Ordering::SeqCst);
        resume_tx.send(()).unwrap();
        assert!(blocked.join().unwrap().is_err());
        assert!(service
            .check_cas_lease(&peer, &old_lease)
            .unwrap_err()
            .is("ENVELOPE_TRANSPORT_BOUND_CHANGED"));
        let (_, fresh_lease) = service.cas_key_custody(&peer, &shape).unwrap();
        assert!(
            fresh_lease.expires_unix > enclave_crypto::time::now_unix()
                && fresh_lease.expires_unix <= now + 30,
            "fresh admission retains its own earlier captured chain cap"
        );
        assert_eq!(
            old_lease.expires_unix, old_expiry,
            "fresh admission cannot extend the earlier lease"
        );
        let state = service.lock_state().unwrap();
        assert_eq!(
            state.cas_key_deadlines.get(&old_lease.id),
            Some(&old_deadline),
            "old boot cap remains immutable after refresh"
        );
        assert!(state
            .cas_key_deadlines
            .get(&fresh_lease.id)
            .is_some_and(|bound| *bound < old_deadline));
        drop(state);
        let mut client = ipc::Client::connect(&socket, ipc::geteuid()).unwrap();
        client.set_timeout(Some(Duration::from_secs(5))).unwrap();
        let _: VaultResponse = client.call(&request).unwrap();
        drop(client);
        stop.store(true, Ordering::SeqCst);
        server.join().unwrap().unwrap();
        cas_stop.store(true, Ordering::SeqCst);
        cas_worker.join().unwrap();
    }

    #[test]
    fn newer_receipt_renews_exact_identity_preserves_live_ciphertexts_and_revokes_old_generation() {
        let root = Root::new();
        let (service, inventory, authority) = fixture(&root);
        let peer = PeerCredentials::local(0, 0);
        let pending = match service.begin_asset(&peer).unwrap() {
            VaultResponse::AssetEnrollmentPending { pending } => pending,
            _ => panic!(),
        };
        let issuer = SigningKey::from_bytes(&[63; 32]);
        let (stop, worker) = cas(&root, &issuer);
        configure_envelope(&service, &root, &issuer);
        service
            .activate_asset(&peer, receipt(&pending, &inventory, 7))
            .unwrap();
        let now = enclave_crypto::time::now_unix();
        // Validly signed expiry permits sterile boot, never continued admission.
        assert!(load_native_enrollment(
            &root.0.join("state"),
            Some(&authority),
            Profile::L2,
            now + 121
        )
        .unwrap()
        .is_none());
        let (mut store, valid) = open(&root.0.join("state")).unwrap();
        let mut corrupt = valid.clone();
        if let Phase::Active { receipt, .. } = &mut corrupt.phase {
            receipt.signature[0] ^= 1;
        } else {
            panic!()
        }
        store.save_json(&corrupt).unwrap();
        assert!(load_native_enrollment(
            &root.0.join("state"),
            Some(&authority),
            Profile::L2,
            now + 121
        )
        .unwrap_err()
        .is("ASSET_ISSUER_SIGNATURE"));
        store.save_json(&valid).unwrap();
        let before = {
            let mut st = service.lock_state().unwrap();
            let token = st
                .vault
                .tokenize("synthetic@example.invalid", None, false, None, now)
                .unwrap();
            assert!(token.reversible);
            st.persist_envelopes().unwrap();
            serde_json::to_vec(&st.vault.checkpoint().unwrap()).unwrap()
        };
        let generation = service.cas_key_generation.load(Ordering::SeqCst);
        let mut wrong = receipt(&pending, &inventory, 8);
        wrong.pending_sha256[0] ^= 1;
        wrong.signature = inventory
            .sign(&wrong.signing_message().unwrap())
            .to_bytes()
            .to_vec();
        assert!(service
            .renew_asset(&peer, wrong)
            .unwrap_err()
            .is("ASSET_ENROLLMENT_RECEIPT"));
        assert_eq!(
            service.cas_key_generation.load(Ordering::SeqCst),
            generation
        );
        let mut next = receipt(&pending, &inventory, 8);
        next.expires_unix = now + 180;
        next.signature = inventory
            .sign(&next.signing_message().unwrap())
            .to_bytes()
            .to_vec();
        service.renew_asset(&peer, next.clone()).unwrap();
        assert_eq!(
            service.cas_key_generation.load(Ordering::SeqCst),
            generation + 1
        );
        assert_eq!(
            serde_json::to_vec(&service.lock_state().unwrap().vault.checkpoint().unwrap()).unwrap(),
            before
        );
        assert!(load_native_enrollment(
            &root.0.join("state"),
            Some(&authority),
            Profile::L2,
            now + 121
        )
        .unwrap()
        .is_some());
        assert!(service
            .renew_asset(&peer, next)
            .unwrap_err()
            .is("ASSET_ENROLLMENT_RECEIPT"));
        assert_eq!(
            service.cas_key_generation.load(Ordering::SeqCst),
            generation + 1
        );
        let guard = service
            .lock_state()
            .unwrap()
            .active_asset_guard
            .clone()
            .unwrap();
        assert_eq!(guard.expires_unix(), now + 180);
        assert!(guard
            .check_release(now + 180)
            .unwrap_err()
            .is("ASSET_ENROLLMENT_RECEIPT"));
        stop.store(true, Ordering::SeqCst);
        worker.join().unwrap();
    }
    #[test]
    fn failed_renewal_retains_exact_staged_data_and_sterile_restart_view_requires_new_receipt() {
        #[derive(Debug)]
        struct Cancel;
        impl BiometricProvider for Cancel {
            fn evaluate(&mut self, _: &BiometricPrompt) -> BiometricOutcome {
                BiometricOutcome::Cancelled
            }
        }
        let root = Root::new();
        let (service, inventory, _) = fixture(&root);
        let peer = PeerCredentials::local(0, 0);
        let pending = match service.begin_asset(&peer).unwrap() {
            VaultResponse::AssetEnrollmentPending { pending } => pending,
            _ => panic!(),
        };
        let issuer = SigningKey::from_bytes(&[63; 32]);
        let (stop, worker) = cas(&root, &issuer);
        configure_envelope(&service, &root, &issuer);
        service
            .activate_asset(&peer, receipt(&pending, &inventory, 7))
            .unwrap();
        let before = {
            let mut st = service.lock_state().unwrap();
            st.vault
                .tokenize(
                    "retained@example.invalid",
                    None,
                    false,
                    None,
                    enclave_crypto::time::now_unix(),
                )
                .unwrap();
            st.persist_envelopes().unwrap();
            serde_json::to_vec(&st.vault.checkpoint().unwrap()).unwrap()
        };
        let original = {
            let mut c = service.lock_ceremony().unwrap();
            std::mem::replace(&mut c.hw.biometric, Box::new(Cancel))
        };
        assert!(service
            .renew_asset(&peer, receipt(&pending, &inventory, 8))
            .is_err());
        assert!(!service.cas_keys_authorized());
        let ledger = open(&root.0.join("state")).unwrap().1;
        assert_eq!(ledger.receipt_floor, 8);
        let Phase::Activating {staged:Some(staged),renewal:true,..}=ledger.phase else {panic!("retain staged renewal")};
        assert_eq!(serde_json::to_vec(&staged).unwrap(), before);
        // Recreate the sterile daemon view while retaining the same synthetic
        // persistent hardware identities. This is not an installed restart.
        {
            let mut c = service.lock_ceremony().unwrap();
            c.hw.biometric = original;
            c.hw.credential = None;
            c.hw.asset_activation_binding = None;
            c.hw.active_asset_guard = None;
        }
        {
            let mut st = service.lock_state().unwrap();
            st.vault = CustodyVault::unenrolled(Profile::L2, None);
            st.envelope_store = None;
            st.active_asset_guard = None;
        }
        assert!(service
            .renew_asset(&peer, receipt(&pending, &inventory, 8))
            .unwrap_err()
            .is("ASSET_ENROLLMENT_RECEIPT"));
        service
            .renew_asset(&peer, receipt(&pending, &inventory, 9))
            .unwrap();
        assert_eq!(
            serde_json::to_vec(&service.lock_state().unwrap().vault.checkpoint().unwrap()).unwrap(),
            before
        );
        stop.store(true, Ordering::SeqCst);
        worker.join().unwrap();
    }

    #[test]
    fn receipt_expiring_during_hardware_wait_cannot_become_active() {
        use std::sync::atomic::AtomicI64;
        #[derive(Debug)]
        struct WallClock(Arc<AtomicI64>);
        impl Clock for WallClock {
            fn now_ns(&self) -> u64 {
                SystemClock.now_ns()
            }
            fn now_unix(&self) -> i64 {
                SystemClock.now_unix() + self.0.load(Ordering::SeqCst)
            }
        }
        #[derive(Debug)]
        struct Advance {
            inner: Box<dyn BiometricProvider + Send>,
            offset: Arc<AtomicI64>,
        }
        impl BiometricProvider for Advance {
            fn evaluate(&mut self, prompt: &BiometricPrompt) -> BiometricOutcome {
                let outcome = self.inner.evaluate(prompt);
                self.offset.store(2, Ordering::SeqCst);
                outcome
            }
        }
        let root = Root::new();
        let (service, inventory, _) = fixture(&root);
        let peer = PeerCredentials::local(0, 0);
        let pending = match service.begin_asset(&peer).unwrap() {
            VaultResponse::AssetEnrollmentPending { pending } => pending,
            _ => panic!(),
        };
        let issuer = SigningKey::from_bytes(&[63; 32]);
        let (stop, worker) = cas(&root, &issuer);
        let offset = Arc::new(AtomicI64::new(0));
        {
            let mut c = service.lock_ceremony().unwrap();
            c.clock = Box::new(WallClock(offset.clone()));
            // The original provider key must remain the already admitted SEP identity.
            let original =
                std::mem::replace(&mut c.hw.biometric, Box::new(SimulatedTouchId::new()));
            c.hw.biometric = Box::new(Advance {
                inner: original,
                offset,
            });
            c.hw.metadata_source = Some(crate::metadata_source::CustodyMetadataSource::new(
                root.0.clone(),
                true,
            ));
            c.hw.envelope_authority = Some(crate::metadata_source::EnvelopeAuthorityConfig {
                issuer: issuer.verifying_key(),
                subject: "host".into(),
                namespace: "data".into(),
            });
        }
        let mut receipt = receipt(&pending, &inventory, 7);
        receipt.expires_unix = enclave_crypto::time::now_unix() + 1;
        receipt.signature = inventory
            .sign(&receipt.signing_message().unwrap())
            .to_bytes()
            .to_vec();
        assert!(service
            .activate_asset(&peer, receipt)
            .unwrap_err()
            .is("ASSET_ENROLLMENT_RECEIPT"));
        assert!(service.lock_ceremony().unwrap().hw.credential.is_none());
        assert!(matches!(
            open(&root.0.join("state")).unwrap().1.phase,
            Phase::Activating { .. }
        ));
        stop.store(true, Ordering::SeqCst);
        worker.join().unwrap();
    }

    #[test]
    fn failed_activation_burns_receipt_before_ui_and_missing_ledger_never_resets() {
        let root = Root::new();
        let (service, inventory, authority) = fixture(&root);
        let peer = PeerCredentials::local(0, 0);
        let pending = match service.begin_asset(&peer).unwrap() {
            VaultResponse::AssetEnrollmentPending { pending } => pending,
            _ => panic!(),
        };
        let envelope_issuer = SigningKey::from_bytes(&[63; 32]);
        let (stop, worker) = cas(&root, &envelope_issuer);
        {
            let mut c = service.lock_ceremony().unwrap();
            c.hw.metadata_source = Some(crate::metadata_source::CustodyMetadataSource::new(
                root.0.clone(),
                true,
            ));
            c.hw.envelope_authority = Some(crate::metadata_source::EnvelopeAuthorityConfig {
                issuer: envelope_issuer.verifying_key(),
                subject: "host".into(),
                namespace: "data".into(),
            });
        }
        let receipt = receipt(&pending, &inventory, 7);
        service.ceremony_cancelled.store(true, Ordering::SeqCst);
        assert!(service
            .activate_asset(&peer, receipt.clone())
            .unwrap_err()
            .is("CAS_ENROLLMENT_REVOKED"));
        service.ceremony_cancelled.store(false, Ordering::SeqCst);
        assert!(service
            .activate_asset(&peer, receipt)
            .unwrap_err()
            .is("ASSET_ENROLLMENT_RECEIPT"));
        assert!(service.lock_ceremony().unwrap().hw.credential.is_none());
        assert!(load_native_enrollment(
            &root.0.join("state"),
            Some(&authority),
            Profile::L2,
            enclave_crypto::time::now_unix()
        )
        .unwrap()
        .is_none());
        stop.store(true, Ordering::SeqCst);
        worker.join().unwrap();
        std::fs::remove_file(root.0.join("state/asset-enrollment/workflow.sealed")).unwrap();
        assert!(load_native_enrollment(
            &root.0.join("state"),
            Some(&authority),
            Profile::L2,
            enclave_crypto::time::now_unix()
        )
        .is_err());
    }

    struct CutoverFixture {
        root: Root,
        backup_root: Root,
        service: Arc<VaultService>,
        backup: crate::asset_membership::MemberEvidence,
        inventory: SigningKey,
        authority: AssetEnrollmentAuthority,
        stop: Arc<AtomicBool>,
        worker: Option<std::thread::JoinHandle<()>>,
        transport_expiry: Arc<std::sync::atomic::AtomicI64>,
        backup_blob: Vec<u8>,
        backup_biometric: Option<Box<dyn BiometricProvider + Send>>,
        backup_device: Option<Box<dyn HidDevice + Send>>,
    }
    impl Drop for CutoverFixture {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(worker) = self.worker.take() {
                worker.join().unwrap();
            }
        }
    }
    fn cutover_fixture() -> CutoverFixture {
        cutover_fixture_profile(Profile::L2)
    }
    fn cutover_fixture_profile(profile: Profile) -> CutoverFixture {
        let root = Root::new();
        let (service, inventory, authority) = fixture_profile(&root, profile);
        let peer = PeerCredentials::local(0, 0);
        let pending = match service.begin_asset(&peer).unwrap() {
            VaultResponse::AssetEnrollmentPending { pending } => pending,
            _ => panic!(),
        };
        let issuer = SigningKey::from_bytes(&[63; 32]);
        let transport_expiry = Arc::new(std::sync::atomic::AtomicI64::new(
            enclave_crypto::time::now_unix() + 3600,
        ));
        let (stop, worker) = cas_with_profile(&root, &issuer, transport_expiry.clone(), profile);
        configure_envelope(&service, &root, &issuer);
        service
            .activate_asset(&peer, receipt(&pending, &inventory, 7))
            .unwrap();
        let backup_root = Root::new();
        let (backup_service, _, _) = fixture_profile(&backup_root, profile);
        backup_service
            .lock_ceremony()
            .unwrap()
            .hw
            .asset_enrollment_authority = Some(authority.clone());
        let pending = match backup_service.begin_asset(&peer).unwrap() {
            VaultResponse::AssetEnrollmentPending { pending } => pending,
            _ => panic!(),
        };
        let backup = crate::asset_membership::MemberEvidence {
            receipt: receipt(&pending, &inventory, 8),
            pending,
        };
        let Phase::Pending(pending)=open(&backup_root.0.join("state")).unwrap().1.phase else {panic!()};
        let (backup_biometric, backup_device) = {
            let mut c = backup_service.lock_ceremony().unwrap();
            (
                std::mem::replace(&mut c.hw.biometric, Box::new(SimulatedTouchId::new())),
                c.hw.yubikey.take(),
            )
        };
        CutoverFixture {
            root,
            backup_root,
            service,
            backup,
            inventory,
            authority,
            stop,
            worker: Some(worker),
            transport_expiry,
            backup_blob: pending.bio_key_blob,
            backup_biometric: Some(backup_biometric),
            backup_device,
        }
    }
    #[test]
    fn membership_same_store_burn_preserves_completed_ingestion_all_floors_and_sterile_restart() {
        let f = cutover_fixture();
        let state = f.root.0.join("state");
        let peer = PeerCredentials::local(0, 0);
        let old = open(&state).unwrap().1;
        let before = {
            let mut st = f.service.lock_state().unwrap();
            st.vault
                .tokenize(
                    "before-cutover@example.invalid",
                    None,
                    false,
                    None,
                    enclave_crypto::time::now_unix(),
                )
                .unwrap();
            st.persist_envelopes().unwrap();
            serde_json::to_vec(&st.vault.checkpoint().unwrap()).unwrap()
        };
        let old_envelopes = std::fs::read(state.join("vault-envelopes/envelopes.sealed")).unwrap();
        let counters = f.service.lock_ceremony().unwrap().counters.clone();
        let generation = f.service.cas_key_generation.load(Ordering::SeqCst);
        let prepared = f
            .service
            .prepare_membership_cutover(&peer, f.backup.clone())
            .unwrap();
        drop(prepared);
        let ledger = open(&state).unwrap().1;
        assert_eq!(ledger.version, 3);
        assert_eq!(ledger.attempt, old.attempt + 1);
        assert_eq!(ledger.policy_floor, old.policy_floor);
        assert_eq!(ledger.receipt_floor, 8);
        assert!(matches!(ledger.phase, Phase::MembershipPreparing { .. }));
        membership_cutover::validate_saved_pins(&state, &ledger).unwrap();
        assert!(load_native_enrollment(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix()
        )
        .unwrap()
        .is_none());
        assert!(f
            .service
            .lock_state()
            .unwrap()
            .refresh_envelope_policy(enclave_crypto::time::now_unix())
            .unwrap_err()
            .is("VAULT_ENVELOPE_STATE_UNCERTAIN"));
        assert!(!f.service.cas_keys_authorized());
        assert_eq!(
            f.service.cas_key_generation.load(Ordering::SeqCst),
            generation + 1
        );
        assert_eq!(
            std::fs::read(state.join("vault-envelopes/envelopes.sealed")).unwrap(),
            old_envelopes
        );
        assert_eq!(
            serde_json::to_vec(&f.service.lock_state().unwrap().vault.checkpoint().unwrap())
                .unwrap(),
            before
        );
        let current = f.service.lock_ceremony().unwrap().counters.clone();
        let (_, saved) =
            SealedStore::open_bounded_required(&state, "signcount", 32 * 1024 * 1024).unwrap();
        let Loaded::State(bytes)=saved else {panic!()};
        assert_eq!(
            enclave_core::sealed::decode::<SignCountStore>(&bytes).unwrap(),
            current
        );
        let Phase::Active {pending,..}=old.phase else {panic!()};
        assert!(
            current.get_credential(pending.evidence.credential())
                >= counters.get_credential(pending.evidence.credential())
        );
        assert!(f.backup_root.0.exists());
        f.service.lock_ceremony().unwrap().hw.credential = None;
        assert!(f
            .service
            .begin_asset(&peer)
            .unwrap_err()
            .is("ASSET_MEMBERSHIP_PENDING"));
    }
    #[test]
    fn membership_preparing_receipt_cannot_replay_and_new_receipt_keeps_original_source() {
        let f = cutover_fixture();
        let peer = PeerCredentials::local(0, 0);
        let state = f.root.0.join("state");
        f.service
            .prepare_membership_cutover(&peer, f.backup.clone())
            .unwrap();
        let first = serde_json::to_value(open(&state).unwrap().1).unwrap();
        assert!(f
            .service
            .prepare_membership_cutover(&peer, f.backup.clone())
            .unwrap_err()
            .is("ASSET_ENROLLMENT_RECEIPT"));
        let mut next = f.backup.clone();
        next.receipt = receipt(&next.pending, &f.inventory, 9);
        f.service.prepare_membership_cutover(&peer, next).unwrap();
        let second = serde_json::to_value(open(&state).unwrap().1).unwrap();
        assert_eq!(
            second["attempt"].as_u64().unwrap(),
            first["attempt"].as_u64().unwrap() + 1
        );
        assert_eq!(second["receipt_floor"], serde_json::json!(9));
        assert_eq!(
            second["phase"]["MembershipPreparing"]["preparation"]["source"],
            first["phase"]["MembershipPreparing"]["preparation"]["source"]
        );
        assert!(load_native_enrollment(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix()
        )
        .unwrap()
        .is_none());
    }
    #[test]
    fn membership_rejects_alias_wrong_receipt_or_active_binding_before_floor_burn() {
        let f = cutover_fixture();
        let peer = PeerCredentials::local(0, 0);
        let state = f.root.0.join("state");
        let before = std::fs::read(state.join("asset-enrollment/workflow.sealed")).unwrap();
        let generation = f.service.cas_key_generation.load(Ordering::SeqCst);
        let mut wrong = f.backup.clone();
        wrong.receipt.signature[0] ^= 1;
        assert!(f.service.prepare_membership_cutover(&peer, wrong).is_err());
        let mut alias = f.backup.clone();
        alias.pending.credential.key = f
            .service
            .lock_ceremony()
            .unwrap()
            .hw
            .credential
            .as_ref()
            .unwrap()
            .key
            .clone();
        alias.receipt = receipt(&alias.pending, &f.inventory, 8);
        assert!(f
            .service
            .prepare_membership_cutover(&peer, alias)
            .unwrap_err()
            .is("ASSET_MEMBERSHIP_DISTINCT_REQUIRED"));
        assert_eq!(
            std::fs::read(state.join("asset-enrollment/workflow.sealed")).unwrap(),
            before
        );
        assert_eq!(
            f.service.cas_key_generation.load(Ordering::SeqCst),
            generation
        );
        f.service.lock_ceremony().unwrap().hw.credential =
            Some(f.backup.pending.credential().clone());
        assert!(f
            .service
            .prepare_membership_cutover(&peer, f.backup.clone())
            .unwrap_err()
            .is("ASSET_ACTIVE_BINDING"));
        assert_eq!(
            std::fs::read(state.join("asset-enrollment/workflow.sealed")).unwrap(),
            before
        );
    }
    #[test]
    fn membership_actual_workflow_checkpoint_failure_latches_and_reopens_sterile_without_reset() {
        let f = cutover_fixture();
        let peer = PeerCredentials::local(0, 0);
        let state = f.root.0.join("state");
        let checkpoint = state.join("asset-enrollment/workflow.gen");
        let saved = std::fs::read(&checkpoint).unwrap();
        #[derive(Debug)]
        struct ObstructAfterOpen {
            path: PathBuf,
            reads: std::sync::atomic::AtomicUsize,
        }
        impl Clock for ObstructAfterOpen {
            fn now_ns(&self) -> u64 {
                if self.reads.fetch_add(1, Ordering::SeqCst) == 1 {
                    std::fs::remove_file(&self.path).unwrap();
                    std::fs::create_dir(&self.path).unwrap();
                }
                SystemClock.now_ns()
            }
            fn now_unix(&self) -> i64 {
                SystemClock.now_unix()
            }
        }
        f.service.lock_ceremony().unwrap().clock = Box::new(ObstructAfterOpen {
            path: checkpoint.clone(),
            reads: std::sync::atomic::AtomicUsize::new(0),
        });
        assert!(f
            .service
            .prepare_membership_cutover(&peer, f.backup.clone())
            .is_err());
        assert!(f.service.lock_state().unwrap().envelope_fault);
        assert!(!f.service.cas_keys_authorized());
        std::fs::remove_dir(&checkpoint).unwrap();
        std::fs::write(&checkpoint, saved).unwrap();
        std::fs::set_permissions(&checkpoint, std::fs::Permissions::from_mode(0o600)).unwrap();
        // Exact authenticated saved successor may be recovered by SealedStore;
        // regardless of checkpoint repair, no v2 active view may reappear.
        let ledger = open(&state).unwrap().1;
        assert_eq!(ledger.version, 3);
        assert_eq!(ledger.receipt_floor, 8);
        assert!(load_native_enrollment(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix()
        )
        .unwrap()
        .is_none());
        std::fs::remove_file(state.join("asset-enrollment/workflow.sealed")).unwrap();
        assert!(load_native_enrollment(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix()
        )
        .is_err());
    }
    #[test]
    fn membership_v3_missing_content_counter_substitution_and_unknown_phase_refuse() {
        let f = cutover_fixture();
        let peer = PeerCredentials::local(0, 0);
        let state = f.root.0.join("state");
        f.service
            .prepare_membership_cutover(&peer, f.backup.clone())
            .unwrap();
        let content = state.join("membership-cutover/content.sealed");
        let held = state.join("membership-cutover/content.held");
        std::fs::rename(&content, &held).unwrap();
        assert!(load_native_enrollment(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix()
        )
        .is_err());
        std::fs::rename(&held, &content).unwrap();
        let (mut counters, _) =
            SealedStore::open_bounded_required(&state, "signcount", 32 * 1024 * 1024).unwrap();
        let original = f.service.lock_ceremony().unwrap().counters.clone();
        counters.save_json(&SignCountStore::default()).unwrap();
        assert!(load_native_enrollment(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix()
        )
        .unwrap_err()
        .is("ASSET_MEMBERSHIP_COUNTER_PIN"));
        counters.save_json(&original).unwrap();
        let (mut store, mut ledger) = open(&state).unwrap();
        ledger.phase = Phase::Empty;
        store.save_json(&ledger).unwrap();
        assert!(open(&state).unwrap_err().is("ASSET_MEMBERSHIP_STATE"));
        let (_, saved) = SealedStore::open_bounded_required(
            &state.join("asset-enrollment"),
            "workflow",
            2 * 1024 * 1024,
        )
        .unwrap();
        let Loaded::State(bytes)=saved else {panic!()};
        assert_eq!(
            enclave_core::sealed::decode::<Ledger>(&bytes)
                .unwrap()
                .version,
            3
        );
    }

    #[derive(Debug)]
    struct MembershipIdp {
        calls: usize,
        bad_signature_on: Option<usize>,
        advance_on_second: Option<Arc<std::sync::atomic::AtomicU64>>,
    }
    impl crate::oidc_acquisition::IntentOidcProvider for MembershipIdp {
        fn acquire(
            &mut self,
            intent: &IntentPayloadV1,
            start: u64,
            deadline: u64,
            cancelled: &AtomicBool,
        ) -> EnclaveResult<crate::oidc_acquisition::BoundOidcStepUp> {
            if cancelled.load(Ordering::SeqCst) {
                fail!(EACCES, "FIDO_PIN_CEREMONY_CANCELLED");
            }
            let index = self.calls;
            self.calls += 1;
            let now = enclave_crypto::time::now_unix();
            if index == 1 {
                if let Some(offset) = &self.advance_on_second {
                    offset.store(crate::ceremony::CEREMONY_BUDGET_NS, Ordering::SeqCst);
                }
            }
            let issuer = "https://membership-idp.example";
            let subject = "synthetic-membership-operator";
            let nonce = format!("fresh-member-{index}");
            let key = SigningKey::from_bytes(&[71; 32]);
            let mut subject_hash = Sha256::new();
            subject_hash.update(b"depot-OIDC-Subject-v1\0");
            subject_hash.update(issuer);
            subject_hash.update([0]);
            subject_hash.update(subject);
            let authority=serde_json::to_vec(&json!({"v":1,"issuer":issuer,"audience":"depot",
                "subject_sha256":hex::encode(subject_hash.finalize()),"ed25519_public_keys":[hex::encode(key.verifying_key().as_bytes())],
                "not_before_unix":now-1,"expires_unix":now+90})).unwrap();
            let header = enclave_crypto::b64::enc(br#"{"alg":"EdDSA","typ":"JWT"}"#);
            let body = enclave_crypto::b64::enc(
                &serde_json::to_vec(&json!({"iss":issuer,"aud":"depot","sub":subject,
                "iat":now,"auth_time":now,"exp":now+60,"nonce":nonce}))
                .unwrap(),
            );
            let signed = format!("{header}.{body}");
            let signing = if self.bad_signature_on == Some(index) {
                SigningKey::from_bytes(&[72; 32])
            } else {
                key
            };
            let signature = signing.sign(signed.as_bytes());
            let token = SecretBytes::new(
                format!(
                    "{signed}.{}",
                    enclave_crypto::b64::enc(&signature.to_bytes())
                )
                .into_bytes(),
            );
            crate::oidc_acquisition::BoundOidcStepUp::from_signed_fixture(
                &authority, token, nonce, intent, start, deadline, now,
            )
        }
    }
    type SharedBiometric = Arc<Mutex<Box<dyn BiometricProvider + Send>>>;
    #[derive(Debug)]
    struct MembershipBiometrics {
        members: [SharedBiometric; 2],
        next: usize,
        order: Vec<usize>,
    }
    impl BiometricProvider for MembershipBiometrics {
        fn evaluate(&mut self, prompt: &BiometricPrompt) -> BiometricOutcome {
            let index = self.order.get(self.next).copied().unwrap_or(0);
            self.next += 1;
            self.members[index].lock().unwrap().evaluate(prompt)
        }
    }
    #[derive(Debug)]
    struct SelectedBiometric(SharedBiometric);
    impl BiometricProvider for SelectedBiometric {
        fn evaluate(&mut self, prompt: &BiometricPrompt) -> BiometricOutcome {
            self.0.lock().unwrap().evaluate(prompt)
        }
    }
    fn enable_membership_devices(
        f: &mut CutoverFixture,
        bad_signature_on: Option<usize>,
        reverse: bool,
    ) -> [SharedBiometric; 2] {
        let mut c = f.service.lock_ceremony().unwrap();
        let primary = c.hw.yubikey.take().unwrap();
        let mut backup = f.backup_device.take().unwrap();
        // Each emulator has a genuine distinct attestation signer. A shared
        // simulated MDS must explicitly trust BOTH public fixture roots before
        // the initializer may create/verify the second credential.
        let authenticator = backup.virtual_authenticator().unwrap();
        let backup_aaguid = hex::encode(authenticator.aaguid);
        let backup_attestation = authenticator.attestation_key_mds();
        let entry =
            c.hw.mds
                .as_mut()
                .unwrap()
                .allowlist
                .entries
                .iter_mut()
                .find(|entry| entry.aaguid == backup_aaguid)
                .unwrap();
        if !entry.attestation_public_keys.contains(&backup_attestation) {
            entry.attestation_public_keys.push(backup_attestation);
        }
        c.hw.membership_devices = Some(if reverse {
            MembershipDevices::from_simulated(backup, primary)
        } else {
            MembershipDevices::from_simulated(primary, backup)
        });
        let primary = std::mem::replace(&mut c.hw.biometric, Box::new(SimulatedTouchId::new()));
        let members = [
            Arc::new(Mutex::new(primary)),
            Arc::new(Mutex::new(f.backup_biometric.take().unwrap())),
        ];
        c.hw.biometric = Box::new(MembershipBiometrics {
            members: members.clone(),
            next: 0,
            order: vec![0, 1],
        });
        c.hw.oidc_provider = Some(Box::new(MembershipIdp {
            calls: 0,
            bad_signature_on,
            advance_on_second: None,
        }));
        members
    }
    #[test]
    fn membership_genuine_full_a4_dual_device_producer_persists_both_counters_but_never_activates()
    {
        let mut f = cutover_fixture();
        enable_membership_devices(&mut f, None, false);
        let peer = PeerCredentials::local(0, 0);
        let state = f.root.0.join("state");
        let original = f.service.lock_ceremony().unwrap().counters.clone();
        let primary = f
            .service
            .lock_ceremony()
            .unwrap()
            .hw
            .credential
            .clone()
            .unwrap();
        // A newly admitted credential may share an authenticator-wide counter
        // already advanced by earlier setup credentials. Read actual emulator
        // ground truth rather than equating an unseen local handle floor0 with
        // the physical authenticator's current count.
        let initial = {
            let mut c = f.service.lock_ceremony().unwrap();
            let devices = c.hw.membership_devices.as_mut().unwrap();
            [
                devices
                    .member(0)
                    .unwrap()
                    .virtual_authenticator()
                    .unwrap()
                    .sign_count(),
                devices
                    .member(1)
                    .unwrap()
                    .virtual_authenticator()
                    .unwrap()
                    .sign_count(),
            ]
        };
        let prepared = f
            .service
            .prepare_membership_cutover_with_biometric(
                &peer,
                f.backup.clone(),
                f.backup_blob.clone(),
            )
            .unwrap();
        let verified = f.service.verify_membership_preparation(prepared).unwrap();
        assert!(!format!("{verified:?}").contains("synthetic-membership-operator"));
        drop(verified);
        let counters = f.service.lock_ceremony().unwrap().counters.clone();
        assert!(counters.dominates(&original));
        assert_eq!(counters.get_credential(&primary), initial[0] + 2);
        assert_eq!(
            counters.get_credential(f.backup.pending.credential()),
            initial[1] + 2
        );
        let ledger = open(&state).unwrap().1;
        membership_cutover::validate_saved_pins(&state, &ledger).unwrap();
        assert_eq!(ledger.version, 3);
        assert_eq!(ledger.receipt_floor, 8);
        assert!(load_native_enrollment(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix()
        )
        .unwrap()
        .is_none());
        assert!(!f.service.cas_keys_authorized());
        assert!(f.service.lock_state().unwrap().envelope_fault);
    }
    #[test]
    fn membership_second_member_bad_oidc_retains_consumed_first_counters_and_no_activation() {
        let mut f = cutover_fixture();
        enable_membership_devices(&mut f, Some(1), false);
        let peer = PeerCredentials::local(0, 0);
        let state = f.root.0.join("state");
        let primary = f
            .service
            .lock_ceremony()
            .unwrap()
            .hw
            .credential
            .clone()
            .unwrap();
        let before = f.service.lock_ceremony().unwrap().counters.clone();
        let prepared = f
            .service
            .prepare_membership_cutover_with_biometric(
                &peer,
                f.backup.clone(),
                f.backup_blob.clone(),
            )
            .unwrap();
        assert!(f
            .service
            .verify_membership_preparation(prepared)
            .unwrap_err()
            .is("OIDC_SIGNATURE_INVALID"));
        let current = f.service.lock_ceremony().unwrap().counters.clone();
        assert!(current.dominates(&before));
        assert_eq!(
            current.get_credential(&primary),
            before.get_credential(&primary) + 2
        );
        membership_cutover::validate_saved_pins(&state, &open(&state).unwrap().1).unwrap();
        assert!(!f.service.cas_keys_authorized());
        let mut next = f.backup.clone();
        next.receipt = receipt(&next.pending, &f.inventory, 9);
        // A failed proof's genuine consumed counters remain compatible with a
        // newer independent attempt; no historical floor is forgotten.
        f.service
            .prepare_membership_cutover_with_biometric(&peer, next, f.backup_blob.clone())
            .unwrap();
        assert!(f
            .service
            .lock_ceremony()
            .unwrap()
            .counters
            .dominates(&current));
    }
    #[test]
    fn membership_pair_order_requires_actual_credential_signature_and_preflight_refuses_missing_authority(
    ) {
        let mut f = cutover_fixture();
        let peer = PeerCredentials::local(0, 0);
        let state = f.root.0.join("state");
        let before = std::fs::read(state.join("asset-enrollment/workflow.sealed")).unwrap();
        assert!(f
            .service
            .prepare_membership_cutover_with_biometric(
                &peer,
                f.backup.clone(),
                f.backup_blob.clone()
            )
            .unwrap_err()
            .is("MEMBERSHIP_NATIVE_PAIR_REQUIRED"));
        assert_eq!(
            std::fs::read(state.join("asset-enrollment/workflow.sealed")).unwrap(),
            before
        );
        enable_membership_devices(&mut f, None, true);
        f.service.lock_ceremony().unwrap().hw.oidc_provider = None;
        assert!(f
            .service
            .prepare_membership_cutover_with_biometric(
                &peer,
                f.backup.clone(),
                f.backup_blob.clone()
            )
            .unwrap_err()
            .is("MEMBERSHIP_A4_AUTHORITY_REQUIRED"));
        assert_eq!(
            std::fs::read(state.join("asset-enrollment/workflow.sealed")).unwrap(),
            before
        );
        f.service.lock_ceremony().unwrap().hw.oidc_provider = Some(Box::new(MembershipIdp {
            calls: 0,
            bad_signature_on: None,
            advance_on_second: None,
        }));
        let prepared = f
            .service
            .prepare_membership_cutover_with_biometric(
                &peer,
                f.backup.clone(),
                f.backup_blob.clone(),
            )
            .unwrap();
        assert!(
            f.service.verify_membership_preparation(prepared).is_err(),
            "two attached devices do not authenticate their credential mapping"
        );
        assert!(!f.service.cas_keys_authorized());
        assert!(load_native_enrollment(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix()
        )
        .unwrap()
        .is_none());
    }
    #[test]
    fn membership_second_member_cannot_restart_original_complete_window() {
        #[derive(Debug)]
        struct OffsetClock(Arc<std::sync::atomic::AtomicU64>);
        impl Clock for OffsetClock {
            fn now_ns(&self) -> u64 {
                SystemClock
                    .now_ns()
                    .saturating_add(self.0.load(Ordering::SeqCst))
            }
            fn now_unix(&self) -> i64 {
                SystemClock.now_unix()
                    + i64::try_from(self.0.load(Ordering::SeqCst) / 1_000_000_000).unwrap()
            }
        }
        let mut f = cutover_fixture();
        enable_membership_devices(&mut f, None, false);
        let peer = PeerCredentials::local(0, 0);
        let offset = Arc::new(std::sync::atomic::AtomicU64::new(0));
        {
            let mut c = f.service.lock_ceremony().unwrap();
            c.clock = Box::new(OffsetClock(offset.clone()));
            c.hw.oidc_provider = Some(Box::new(MembershipIdp {
                calls: 0,
                bad_signature_on: None,
                advance_on_second: Some(offset),
            }));
        }
        let primary = f
            .service
            .lock_ceremony()
            .unwrap()
            .hw
            .credential
            .clone()
            .unwrap();
        let before = f.service.lock_ceremony().unwrap().counters.clone();
        let prepared = f
            .service
            .prepare_membership_cutover_with_biometric(
                &peer,
                f.backup.clone(),
                f.backup_blob.clone(),
            )
            .unwrap();
        assert!(f
            .service
            .verify_membership_preparation(prepared)
            .unwrap_err()
            .is("CEREMONY_BUDGET_EXCEEDED"));
        assert_eq!(
            f.service
                .lock_ceremony()
                .unwrap()
                .counters
                .get_credential(&primary),
            before.get_credential(&primary) + 2
        );
        assert!(!f.service.cas_keys_authorized());
        assert!(f.service.lock_state().unwrap().envelope_fault);
    }
    #[test]
    fn membership_both_l3_topologies_must_be_exact_root_ports_before_any_factor_traffic() {
        #[derive(Debug)]
        struct Probe {
            depth: u8,
            traffic: Arc<std::sync::atomic::AtomicUsize>,
        }
        impl HidDevice for Probe {
            fn hub_depth(&self) -> u8 {
                self.depth
            }
            fn write_report(&mut self, _: &[u8; 64]) -> EnclaveResult<()> {
                self.traffic.fetch_add(1, Ordering::SeqCst);
                fail!(EIO, "UNEXPECTED_FACTOR_TRAFFIC")
            }
            fn read_report(&mut self) -> EnclaveResult<[u8; 64]> {
                self.traffic.fetch_add(1, Ordering::SeqCst);
                fail!(EIO, "UNEXPECTED_FACTOR_TRAFFIC")
            }
        }
        for depths in [[1, 1], [0, 1], [2, 1], [1, 0], [1, 2]] {
            let traffic = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let mut devices = MembershipDevices::from_simulated(
                Box::new(Probe {
                    depth: depths[0],
                    traffic: traffic.clone(),
                }),
                Box::new(Probe {
                    depth: depths[1],
                    traffic: traffic.clone(),
                }),
            );
            if depths == [1, 1] {
                devices.require_topology(Profile::L3).unwrap();
            } else {
                assert!(devices
                    .require_topology(Profile::L3)
                    .unwrap_err()
                    .is("USB_HUB_FORBIDDEN_L3"));
            }
            devices.require_topology(Profile::L2).unwrap();
            assert_eq!(
                traffic.load(Ordering::SeqCst),
                0,
                "topology refusal must precede all factor traffic"
            );
        }
    }
    fn membership_draft() -> enclave_core::intent_draft::IntentDraftV1 {
        enclave_core::intent_draft::IntentDraftV1 {
            action_class: ActionClass::A3,
            profile: Profile::L2,
            data_class: enclave_core::label::Conf::C3,
            tool_name: "detokenize_row".into(),
            target_namespace: "data".into(),
            canonical_verb: "Reveal".into(),
            row_count_bound: 1,
            arguments_jcs_sha256: "ab".repeat(32),
            canonical_arguments_blake3: "cd".repeat(32),
            policy_blake3: "ef".repeat(32),
            qif_millibits_delta: 0,
            org_root_mutation: false,
        }
    }
    fn membership_tokenize(service: &VaultService, value: &str) -> String {
        let reply = service
            .handle(
                &PeerCredentials::local(0, 0),
                VaultRequest::Tokenize {
                    items: vec![TokenizeItem {
                        value: value.into(),
                        declared: None,
                    }],
                    bulk_set: false,
                    grant: None,
                },
            )
            .unwrap();
        let VaultResponse::Tokens(tokens)=reply else {panic!()};
        tokens[0].token.clone()
    }
    fn ingress_pair_fixture(profile: Profile) -> CutoverFixture {
        let mut f = cutover_fixture_profile(profile);
        enable_membership_devices(&mut f, None, false);
        f.service
            .add_asset_backup(
                &PeerCredentials::local(0, 0),
                f.backup.pending.clone(),
                f.backup.receipt.clone(),
                f.backup_blob.clone(),
            )
            .unwrap();
        let state = f.service.lock_state().unwrap();
        assert!(state.simulated && state.membership_checkpoint.is_some());
        assert_eq!(
            state
                .active_asset_guard
                .as_ref()
                .unwrap()
                .is_l3_membership(),
            profile == Profile::L3
        );
        drop(state);
        f
    }
    fn ingress_pair_requests() -> [VaultRequest; 3] {
        [
            VaultRequest::Tokenize {
                items: vec![TokenizeItem {
                    value: "ingress-pair@example.invalid".into(),
                    declared: None,
                }],
                bulk_set: false,
                grant: None,
            },
            VaultRequest::ScrubText {
                text: "Contact ingress-pair@example.invalid".into(),
                bulk_set: false,
                grant: None,
            },
            VaultRequest::AllocateSlot,
        ]
    }
    #[derive(Debug, PartialEq, Eq)]
    struct IngressEffects {
        memory: serde_json::Value,
        files: std::collections::BTreeMap<PathBuf, [u8; 32]>,
    }
    fn ingress_effects(service: &VaultService) -> IngressEffects {
        fn files(base: &Path, dir: &Path, out: &mut std::collections::BTreeMap<PathBuf, [u8; 32]>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                let metadata = std::fs::symlink_metadata(&path).unwrap();
                if metadata.is_dir() {
                    files(base, &path, out);
                } else {
                    assert!(metadata.is_file());
                    out.insert(
                        path.strip_prefix(base).unwrap().into(),
                        Sha256::digest(std::fs::read(&path).unwrap()).into(),
                    );
                }
            }
        }
        let state = service.lock_state().unwrap();
        let mut persisted = std::collections::BTreeMap::new();
        let base = state.state_dir.as_ref().unwrap();
        files(base, base, &mut persisted);
        IngressEffects {
            memory: json!({"sequence":state.seq.current(),"checkpoint_policy":format!("{:?}",state.checkpoint),
            "vault":state.vault.checkpoint().unwrap(),"witness":&state.witness,"witness_bytes":state.witness_bytes,
            "egress":format!("{:?}",state.egress)}),
            files: persisted,
        }
    }
    #[test]
    fn ingress_pair_state_ceremony_disagreement_refuses_before_all_governed_effects() {
        let f = ingress_pair_fixture(Profile::L3);
        let peer = PeerCredentials::local(DaemonId::AgentRuntime.uid(), 0);
        // The typed guard came from the complete real software membership
        // producer. Only make State demand native admission; Ceremony remains
        // explicitly software, so this mismatch can supply refusal only.
        {
            let mut state = f.service.lock_state().unwrap();
            state.simulated = false;
            assert!(state.requires_ingress_pair());
        }
        assert!(f.service.lock_ceremony().unwrap().hw.simulated);
        let before = ingress_effects(&f.service);
        for request in ingress_pair_requests() {
            assert!(f
                .service
                .handle(&peer, request)
                .unwrap_err()
                .is("CUSTODY_INGRESS_ADMISSION_CHANGED"));
            assert_eq!(
                ingress_effects(&f.service),
                before,
                "no slot, checkpoint, ciphertext, witness, release or journal effect"
            );
        }
    }
    #[test]
    fn ingress_pair_requirement_change_after_snapshot_refuses_before_all_governed_effects() {
        use std::time::Duration;
        let f = ingress_pair_fixture(Profile::L3);
        let before = ingress_effects(&f.service);
        for request in ingress_pair_requests() {
            let service = f.service.clone();
            let (entered_tx, entered_rx) = std::sync::mpsc::channel();
            let (resume_tx, resume_rx) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                super::super::INGRESS_PAIR_SNAPSHOT_FOR_TEST.with(|slot| {
                    assert!(slot.borrow().is_none());
                    *slot.borrow_mut() = Some(Box::new(move |required| {
                        entered_tx.send(required).unwrap();
                        resume_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    }));
                });
                let result = service.handle(
                    &PeerCredentials::local(DaemonId::AgentRuntime.uid(), 0),
                    request,
                );
                super::super::INGRESS_PAIR_SNAPSHOT_FOR_TEST
                    .with(|slot| assert!(slot.borrow().is_none()));
                result
            });
            assert!(
                !entered_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
                "actual handler captured software admission"
            );
            // Owning State here proves the paused snapshot retains no State
            // guard. Resume while State is owned, after the requirement changes.
            let mut state = f.service.lock_state().unwrap();
            state.simulated = false;
            assert!(state.requires_ingress_pair());
            resume_tx.send(()).unwrap();
            drop(state);
            assert!(worker
                .join()
                .unwrap()
                .unwrap_err()
                .is("CUSTODY_INGRESS_ADMISSION_CHANGED"));
            assert_eq!(
                ingress_effects(&f.service),
                before,
                "changed admission must refuse before governed effects"
            );
            f.service.lock_state().unwrap().simulated = true;
        }
    }
    #[test]
    fn ingress_pair_required_busy_ceremony_refuses_before_all_governed_effects() {
        let f = ingress_pair_fixture(Profile::L3);
        let peer = PeerCredentials::local(DaemonId::AgentRuntime.uid(), 0);
        {
            let mut state = f.service.lock_state().unwrap();
            state.simulated = false;
            assert!(state.requires_ingress_pair());
        }
        let before = ingress_effects(&f.service);
        let ceremony = f.service.lock_ceremony().unwrap();
        for request in ingress_pair_requests() {
            assert!(f
                .service
                .handle(&peer, request)
                .unwrap_err()
                .is("CEREMONY_IN_FLIGHT"));
            assert_eq!(
                ingress_effects(&f.service),
                before,
                "required pair owner must remain failclosed while busy"
            );
        }
        drop(ceremony);
    }
    #[test]
    fn ingress_pair_software_memberships_allow_l2_l3_ingress_while_ceremony_owned() {
        for profile in [Profile::L2, Profile::L3] {
            let f = ingress_pair_fixture(profile);
            let peer = PeerCredentials::local(DaemonId::AgentRuntime.uid(), 0);
            let before = f.service.lock_state().unwrap().seq.current();
            assert!(!f.service.lock_state().unwrap().requires_ingress_pair());
            let ceremony = f.service.lock_ceremony().unwrap();
            for (index, request) in ingress_pair_requests().into_iter().enumerate() {
                let reply = f.service.handle(&peer, request).unwrap();
                match (index, reply) {
                    (0, VaultResponse::Tokens(tokens)) => assert_eq!(tokens.len(), 1),
                    (1, VaultResponse::Text(text)) => {
                        assert!(!text.contains("ingress-pair@example.invalid"))
                    }
                    (2, VaultResponse::Slot { rpc_seq_u64, .. }) => {
                        assert_eq!(rpc_seq_u64, before + 2)
                    }
                    (_, reply) => panic!("unexpected actual ingress reply: {reply:?}"),
                }
            }
            drop(ceremony);
            let state = f.service.lock_state().unwrap();
            assert_eq!(state.seq.current(), before + 3);
            assert_eq!(state.witness.len(), 2);
        }
    }
    fn checkpoint_hash(state: &Path) -> String {
        let value = serde_json::to_value(open(state).unwrap().1).unwrap();
        let hash: Vec<u8> = serde_json::from_value(
            value["phase"]["MembershipCommitted"]["record"]["checkpoint_sha256"].clone(),
        )
        .unwrap();
        hex::encode(hash)
    }
    fn checkpoint_names(state: &Path) -> std::collections::BTreeSet<String> {
        std::fs::read_dir(state.join("membership-checkpoints"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.len() == 64 && name.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .collect()
    }
    fn detokenize_membership_batch(service: &VaultService, tokens: Vec<String>) -> VaultResponse {
        let mut draft = membership_draft();
        draft.action_class = ActionClass::A4;
        draft.row_count_bound = tokens.len() as u64;
        service
            .handle(
                &PeerCredentials::local(0, 0),
                VaultRequest::Detokenize {
                    surrogates: tokens,
                    draft: Box::new(draft),
                },
            )
            .unwrap()
    }
    #[test]
    fn membership_public_initializer_commit_ingestion_restart_and_either_single_member_use_real_paths(
    ) {
        let mut f = cutover_fixture();
        let members = enable_membership_devices(&mut f, None, false);
        let peer = PeerCredentials::local(0, 0);
        let state = f.root.0.join("state");
        let original_file = std::fs::read(state.join("vault-envelopes/envelopes.sealed")).unwrap();
        // The same genuine backup biometric owner answers initializer->backup,
        // then the primary and backup full chains, without exporting its key.
        f.service.lock_ceremony().unwrap().hw.biometric = Box::new(MembershipBiometrics {
            members: members.clone(),
            next: 0,
            order: vec![1, 0, 1],
        });
        let pending = match f
            .service
            .handle(&peer, VaultRequest::BeginAssetBackupEnrollment)
            .unwrap()
        {
            VaultResponse::AssetEnrollmentPending { pending } => pending,
            _ => panic!(),
        };
        let count_before = {
            let mut c = f.service.lock_ceremony().unwrap();
            c.hw.membership_devices
                .as_mut()
                .unwrap()
                .member(1)
                .unwrap()
                .virtual_authenticator()
                .unwrap()
                .sign_count()
        };
        let again = match f
            .service
            .handle(&peer, VaultRequest::BeginAssetBackupEnrollment)
            .unwrap()
        {
            VaultResponse::AssetEnrollmentPending { pending } => pending,
            _ => panic!(),
        };
        assert_eq!(pending.digest().unwrap(), again.digest().unwrap());
        assert_eq!(
            {
                let mut c = f.service.lock_ceremony().unwrap();
                c.hw.membership_devices
                    .as_mut()
                    .unwrap()
                    .member(1)
                    .unwrap()
                    .virtual_authenticator()
                    .unwrap()
                    .sign_count()
            },
            count_before,
            "retrieving durable pending creates no second credential"
        );
        let reply = f
            .service
            .handle(
                &peer,
                VaultRequest::AddAssetBackup {
                    receipt: receipt(&pending, &f.inventory, 8),
                },
            )
            .unwrap();
        let VaultResponse::AssetBackupAdded {membership_id,generation}=reply else {panic!()};
        assert!(generation > 0);
        let admitted = load_native_membership(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(hex::encode(admitted.membership_id()), membership_id);
        assert_eq!(
            admitted.enrolled(1).unwrap().credential.credential_id,
            pending.credential().credential_id
        );
        assert!(load_native_enrollment(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix()
        )
        .unwrap()
        .is_none());
        assert!(f.service.cas_keys_authorized());
        assert!(!f.service.lock_state().unwrap().envelope_fault);
        let first_reference = serde_json::to_value(open(&state).unwrap().1).unwrap();
        let first_hash = checkpoint_hash(&state);
        let surrogate = membership_tokenize(&f.service, "single-adopted@example.invalid");
        let mut previous = checkpoint_hash(&state);
        let mut tokens = Vec::new();
        for value in [
            "adopted@example.invalid",
            "second@example.invalid",
            "third@example.invalid",
            "fourth@example.invalid",
        ] {
            let reply = f
                .service
                .handle(
                    &peer,
                    VaultRequest::Tokenize {
                        items: vec![TokenizeItem {
                            value: value.into(),
                            declared: None,
                        }],
                        bulk_set: true,
                        grant: None,
                    },
                )
                .unwrap();
            let VaultResponse::Tokens(mut output)=reply else {panic!()};
            tokens.push(output.remove(0).token);
            let current = checkpoint_hash(&state);
            let names = checkpoint_names(&state);
            assert_eq!(
                names,
                std::collections::BTreeSet::from([previous, current.clone()]),
                "only current and actual predecessor remain after acknowledged ingestion"
            );
            previous = current;
        }
        assert!(
            !state
                .join("membership-checkpoints")
                .join(first_hash)
                .exists(),
            "obsolete genuine initial complete snapshot retired"
        );
        let second_reference = serde_json::to_value(open(&state).unwrap().1).unwrap();
        assert_ne!(
            first_reference["phase"]["MembershipCommitted"]["record"]["checkpoint_sha256"],
            second_reference["phase"]["MembershipCommitted"]["record"]["checkpoint_sha256"]
        );
        assert_eq!(
            first_reference["phase"]["MembershipCommitted"]["record"]["membership_sha256"],
            second_reference["phase"]["MembershipCommitted"]["record"]["membership_sha256"]
        );
        let latest = load_native_membership(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            serde_json::to_vec(latest.checkpoint()).unwrap(),
            serde_json::to_vec(&f.service.lock_state().unwrap().vault.checkpoint().unwrap())
                .unwrap()
        );
        assert_eq!(
            std::fs::read(state.join("vault-envelopes/envelopes.sealed")).unwrap(),
            original_file,
            "original source wrappers/file remain preserved"
        );
        let (mut hw, backup_device) = {
            let mut c = f.service.lock_ceremony().unwrap();
            let mut hw = std::mem::replace(
                &mut c.hw,
                VaultHardware::simulated(Profile::L2, enclave_crypto::time::now_unix()).unwrap(),
            );
            let pair = hw.membership_devices.take().unwrap();
            let MembershipDevicesInner::Simulated([primary,backup])=pair.inner else {panic!()};
            hw.yubikey = Some(primary);
            hw.biometric = Box::new(SelectedBiometric(members[0].clone()));
            hw.active_asset_guard = None;
            (hw, backup)
        };
        hw.oidc_provider = Some(Box::new(MembershipIdp {
            calls: 0,
            bad_signature_on: None,
            advance_on_second: None,
        }));
        let primary = VaultService::start(
            VaultConfig {
                profile: Profile::L2,
                state_dir: Some(state.clone()),
                ..Default::default()
            },
            hw,
        )
        .unwrap();
        assert!(matches!(
            primary
                .handle(
                    &peer,
                    VaultRequest::Detokenize {
                        surrogates: vec![surrogate.clone()],
                        draft: Box::new(membership_draft())
                    }
                )
                .unwrap(),
            VaultResponse::Delivered { rows: 1, .. }
        ));
        assert!(matches!(
            detokenize_membership_batch(&primary, tokens.clone()),
            VaultResponse::Delivered { rows: 4, .. }
        ));
        let mut hw = {
            let mut c = primary.lock_ceremony().unwrap();
            std::mem::replace(
                &mut c.hw,
                VaultHardware::simulated(Profile::L2, enclave_crypto::time::now_unix()).unwrap(),
            )
        };
        let enrolled = latest.enrolled(1).unwrap();
        hw.yubikey = Some(backup_device);
        hw.credential = Some(enrolled.credential);
        hw.sep_bio_key =
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&enrolled.bio_public_key).unwrap();
        hw.sep_bio_blob = Some(enrolled.bio_key_blob);
        hw.biometric = Box::new(SelectedBiometric(members[1].clone()));
        hw.active_asset_guard = None;
        let backup = VaultService::start(
            VaultConfig {
                profile: Profile::L2,
                state_dir: Some(state.clone()),
                ..Default::default()
            },
            hw,
        )
        .unwrap();
        assert!(matches!(
            backup
                .handle(
                    &peer,
                    VaultRequest::Detokenize {
                        surrogates: vec![surrogate],
                        draft: Box::new(membership_draft())
                    }
                )
                .unwrap(),
            VaultResponse::Delivered { rows: 1, .. }
        ));
        assert!(matches!(
            detokenize_membership_batch(&backup, tokens),
            VaultResponse::Delivered { rows: 4, .. }
        ));
        let extra = membership_tokenize(&backup, "backup-ingest@example.invalid");
        assert!(matches!(
            backup
                .handle(
                    &peer,
                    VaultRequest::Detokenize {
                        surrogates: vec![extra],
                        draft: Box::new(membership_draft())
                    }
                )
                .unwrap(),
            VaultResponse::Delivered { rows: 1, .. }
        ));
        assert_eq!(
            backup
                .lock_state()
                .unwrap()
                .vault
                .checkpoint()
                .unwrap()
                .enrollment_binding()
                .unwrap(),
            latest.source_binding()
        );
    }
    #[test]
    fn membership_commit_rechecks_current_policy_counter_and_original_window_without_reviving_old_authority(
    ) {
        for change in ["counter", "policy", "window"] {
            let mut f = cutover_fixture();
            enable_membership_devices(&mut f, None, false);
            let peer = PeerCredentials::local(0, 0);
            let state = f.root.0.join("state");
            let prepared = f
                .service
                .prepare_membership_cutover_with_biometric(
                    &peer,
                    f.backup.clone(),
                    f.backup_blob.clone(),
                )
                .unwrap();
            let verified = f.service.verify_membership_preparation(prepared).unwrap();
            match change {
                "counter" => {
                    let (mut store, _) =
                        SealedStore::open_bounded_required(&state, "signcount", 32 * 1024 * 1024)
                            .unwrap();
                    store.save_json(&SignCountStore::default()).unwrap();
                }
                "policy" => {
                    let mut bytes = std::fs::read(&f.authority.policy_file).unwrap();
                    bytes[0] ^= 1;
                    std::fs::write(&f.authority.policy_file, bytes).unwrap();
                }
                _ => {
                    #[derive(Debug)]
                    struct Late;
                    impl Clock for Late {
                        fn now_ns(&self) -> u64 {
                            SystemClock
                                .now_ns()
                                .saturating_add(crate::ceremony::CEREMONY_BUDGET_NS)
                        }
                        fn now_unix(&self) -> i64 {
                            SystemClock.now_unix()
                        }
                    }
                    f.service.lock_ceremony().unwrap().clock = Box::new(Late);
                }
            }
            assert!(f.service.commit_membership(verified).is_err(), "{change}");
            assert!(!f.service.cas_keys_authorized());
            assert!(f.service.lock_state().unwrap().envelope_fault);
            assert!(matches!(
                open(&state).unwrap().1.phase,
                Phase::MembershipPreparing { .. }
            ));
        }
    }
    #[test]
    fn membership_durable_reference_failure_keeps_prior_acknowledged_content_and_latches_runtime() {
        let mut f = cutover_fixture();
        enable_membership_devices(&mut f, None, false);
        let peer = PeerCredentials::local(0, 0);
        let state = f.root.0.join("state");
        f.service
            .add_asset_backup(
                &peer,
                f.backup.pending.clone(),
                f.backup.receipt.clone(),
                f.backup_blob.clone(),
            )
            .unwrap();
        let original_hash = checkpoint_hash(&state);
        let original = state.join("membership-checkpoints").join(&original_hash);
        let archive: [(&str, Vec<u8>); 3] = ["checkpoint.sealed", "checkpoint.gen", "sealing.key"]
            .map(|name| (name, std::fs::read(original.join(name)).unwrap()));
        for value in [
            "acknowledged@example.invalid",
            "second-ack@example.invalid",
            "third-ack@example.invalid",
            "fourth-ack@example.invalid",
        ] {
            membership_tokenize(&f.service, value);
        }
        // Recreate one exact obsolete encrypted fixture candidate, without ever
        // changing the authoritative reference, so a reached GC would delete it.
        assert!(!original.exists());
        std::fs::create_dir(&original).unwrap();
        std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o700)).unwrap();
        for (name, bytes) in &archive {
            std::fs::write(original.join(name), bytes).unwrap();
            std::fs::set_permissions(original.join(name), std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        let before = load_native_membership(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix(),
        )
        .unwrap()
        .unwrap();
        let names = checkpoint_names(&state);
        assert_eq!(names.len(), 3);
        let path = state.join("asset-enrollment/workflow.gen");
        let saved = std::fs::read(&path).unwrap();
        let reference_before =
            std::fs::read(state.join("asset-enrollment/workflow.sealed")).unwrap();
        let _fault = membership_cutover::obstruct_next_publication_save(path.clone());
        assert!(f
            .service
            .handle(
                &peer,
                VaultRequest::Tokenize {
                    items: vec![TokenizeItem {
                        value: "unacknowledged@example.invalid".into(),
                        declared: None
                    }],
                    bulk_set: false,
                    grant: None
                }
            )
            .is_err());
        assert!(f.service.lock_state().unwrap().envelope_fault);
        // Actual authoritative sealed bytes advanced before the obstructed
        // generation rename failed. This is save uncertainty, not open refusal.
        assert_ne!(
            std::fs::read(state.join("asset-enrollment/workflow.sealed")).unwrap(),
            reference_before
        );
        for hash in names {
            assert!(
                state
                    .join("membership-checkpoints")
                    .join(hash)
                    .join("checkpoint.sealed")
                    .exists(),
                "failed save performs no retirement"
            );
        }
        std::fs::remove_dir(&path).unwrap();
        std::fs::write(&path, saved).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let after = load_native_membership(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(before.membership_id(), after.membership_id());
        // Recovery may choose either authentic completed successor after an
        // uncertain save; every previously acknowledged ciphertext must remain.
        let before = serde_json::to_value(before.checkpoint()).unwrap();
        let after = serde_json::to_value(after.checkpoint()).unwrap();
        for (key, value) in before["store"].as_object().unwrap() {
            assert_eq!(&after["store"][key], value);
        }
    }
    #[test]
    fn membership_committed_missing_reference_expired_member_and_wrong_selected_identity_refuse() {
        let mut f = cutover_fixture();
        enable_membership_devices(&mut f, None, false);
        let peer = PeerCredentials::local(0, 0);
        let state = f.root.0.join("state");
        f.service
            .add_asset_backup(
                &peer,
                f.backup.pending.clone(),
                f.backup.receipt.clone(),
                f.backup_blob.clone(),
            )
            .unwrap();
        let active = load_native_membership(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix(),
        )
        .unwrap()
        .unwrap();
        assert!(load_native_membership(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix() + 121
        )
        .unwrap()
        .is_none());
        assert!(active
            .enrolled(2)
            .unwrap_err()
            .is("MEMBERSHIP_MEMBER_INDEX"));
        let encoded = serde_json::to_value(open(&state).unwrap().1).unwrap();
        let hash: Vec<u8> = serde_json::from_value(
            encoded["phase"]["MembershipCommitted"]["record"]["checkpoint_sha256"].clone(),
        )
        .unwrap();
        let path = state
            .join("membership-checkpoints")
            .join(hex::encode(hash))
            .join("checkpoint.sealed");
        std::fs::remove_file(path).unwrap();
        assert!(load_native_membership(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix()
        )
        .is_err());
        assert!(f
            .service
            .lock_state()
            .unwrap()
            .refresh_envelope_policy(enclave_crypto::time::now_unix())
            .is_err());
    }

    #[test]
    fn membership_native_l3_singleton_is_setup_only_and_cannot_authorize_normal_custody() {
        let f = cutover_fixture();
        let now = enclave_crypto::time::now_unix();
        {
            let mut c = f.service.lock_ceremony().unwrap();
            c.hw.simulated = false;
            assert!(c
                .hw
                .refresh_metadata(Profile::L3, ActionClass::A3, now)
                .unwrap_err()
                .is("L3_TWO_MEMBER_ENROLLMENT_REQUIRED"));
            assert!(c
                .hw
                .refresh_metadata(Profile::L3, ActionClass::A4, now)
                .unwrap_err()
                .is("L3_TWO_MEMBER_ENROLLMENT_REQUIRED"));
            c.hw.simulated = true;
        }
        {
            let mut st = f.service.lock_state().unwrap();
            st.profile = Profile::L3;
            st.simulated = false;
            assert!(st
                .refresh_envelope_policy(now)
                .unwrap_err()
                .is("L3_TWO_MEMBER_ENROLLMENT_REQUIRED"));
        }
    }

    #[test]
    fn membership_busy_release_fence_preserves_durable_admission_but_never_adopts_runtime() {
        let mut f = cutover_fixture();
        enable_membership_devices(&mut f, None, false);
        let peer = PeerCredentials::local(0, 0);
        let state = f.root.0.join("state");
        let prepared = f
            .service
            .prepare_membership_cutover_with_biometric(
                &peer,
                f.backup.clone(),
                f.backup_blob.clone(),
            )
            .unwrap();
        let verified = f.service.verify_membership_preparation(prepared).unwrap();
        let counters = f.service.lock_ceremony().unwrap().counters.clone();
        let _release = f.service.cas_key_release.lock().unwrap();
        assert!(f
            .service
            .commit_membership(verified)
            .unwrap_err()
            .is("CUSTODY_RELEASE_BUSY"));
        assert!(matches!(
            open(&state).unwrap().1.phase,
            Phase::MembershipCommitted { .. }
        ));
        let active = load_native_membership(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            serde_json::to_vec(active.checkpoint()).unwrap(),
            serde_json::to_vec(&f.service.lock_state().unwrap().vault.checkpoint().unwrap())
                .unwrap()
        );
        assert_eq!(f.service.lock_ceremony().unwrap().counters, counters);
        assert!(!f.service.cas_keys_authorized());
        let st = f.service.lock_state().unwrap();
        assert!(st.envelope_fault);
        assert!(st.membership_checkpoint.is_none());
    }

    #[test]
    fn membership_public_pending_reads_cannot_reset_or_escape_original_request_window() {
        #[derive(Debug)]
        struct SlowReads(std::sync::atomic::AtomicUsize);
        impl Clock for SlowReads {
            fn now_ns(&self) -> u64 {
                SystemClock
                    .now_ns()
                    .saturating_add(if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                        0
                    } else {
                        crate::ceremony::CEREMONY_BUDGET_NS
                    })
            }
            fn now_unix(&self) -> i64 {
                SystemClock.now_unix()
            }
        }
        for operation in ["cached-begin", "add"] {
            let mut f = cutover_fixture();
            let members = enable_membership_devices(&mut f, None, false);
            let peer = PeerCredentials::local(0, 0);
            f.service.lock_ceremony().unwrap().hw.biometric = Box::new(MembershipBiometrics {
                members,
                next: 0,
                order: vec![1],
            });
            let pending = match f
                .service
                .handle(&peer, VaultRequest::BeginAssetBackupEnrollment)
                .unwrap()
            {
                VaultResponse::AssetEnrollmentPending { pending } => pending,
                _ => panic!(),
            };
            let count_before = {
                let mut c = f.service.lock_ceremony().unwrap();
                c.hw.membership_devices
                    .as_mut()
                    .unwrap()
                    .member(1)
                    .unwrap()
                    .virtual_authenticator()
                    .unwrap()
                    .sign_count()
            };
            f.service.lock_ceremony().unwrap().clock =
                Box::new(SlowReads(std::sync::atomic::AtomicUsize::new(0)));
            let request = if operation == "cached-begin" {
                VaultRequest::BeginAssetBackupEnrollment
            } else {
                VaultRequest::AddAssetBackup {
                    receipt: receipt(&pending, &f.inventory, 8),
                }
            };
            assert!(
                f.service
                    .handle(&peer, request)
                    .unwrap_err()
                    .is("ASSET_MEMBERSHIP_DEADLINE"),
                "{operation}"
            );
            let count_after = {
                let mut c = f.service.lock_ceremony().unwrap();
                c.hw.membership_devices
                    .as_mut()
                    .unwrap()
                    .member(1)
                    .unwrap()
                    .virtual_authenticator()
                    .unwrap()
                    .sign_count()
            };
            assert_eq!(
                count_after, count_before,
                "late pending I/O cannot spend another factor or create another credential"
            );
            assert!(load_native_membership(
                &f.root.0.join("state"),
                Some(&f.authority),
                Profile::L2,
                enclave_crypto::time::now_unix()
            )
            .unwrap()
            .is_none());
        }
    }

    #[test]
    fn membership_preparing_restart_restores_only_setup_and_new_receipt_runs_fresh_full_proof() {
        let mut f = cutover_fixture();
        let prior = membership_tokenize(&f.service, "before-interruption@example.invalid");
        let members = enable_membership_devices(&mut f, Some(1), false);
        let peer = PeerCredentials::local(0, 0);
        let state = f.root.0.join("state");
        f.service.lock_ceremony().unwrap().hw.biometric = Box::new(MembershipBiometrics {
            members: members.clone(),
            next: 0,
            order: vec![1, 0, 1],
        });
        let pending = match f
            .service
            .handle(&peer, VaultRequest::BeginAssetBackupEnrollment)
            .unwrap()
        {
            VaultResponse::AssetEnrollmentPending { pending } => pending,
            _ => panic!(),
        };
        let consumed = receipt(&pending, &f.inventory, 8);
        assert!(f
            .service
            .handle(
                &peer,
                VaultRequest::AddAssetBackup {
                    receipt: consumed.clone()
                }
            )
            .unwrap_err()
            .is("OIDC_SIGNATURE_INVALID"));
        let original_counters = f.service.lock_ceremony().unwrap().counters.clone();
        let original = serde_json::to_value(open(&state).unwrap().1).unwrap();
        let source = load_native_membership_setup(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            serde_json::to_vec(source.checkpoint()).unwrap(),
            serde_json::to_vec(&f.service.lock_state().unwrap().vault.checkpoint().unwrap())
                .unwrap()
        );
        assert!(load_native_membership(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix()
        )
        .unwrap()
        .is_none());
        assert!(load_native_enrollment(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix()
        )
        .unwrap()
        .is_none());
        let mut hw = {
            let mut c = f.service.lock_ceremony().unwrap();
            std::mem::replace(
                &mut c.hw,
                VaultHardware::simulated(Profile::L2, enclave_crypto::time::now_unix()).unwrap(),
            )
        };
        let enrolled = source.enrolled();
        hw.credential = Some(enrolled.credential);
        hw.sep_bio_key =
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&enrolled.bio_public_key).unwrap();
        hw.sep_bio_blob = Some(enrolled.bio_key_blob);
        hw.active_asset_guard = None;
        hw.asset_activation_binding = Some(source.source_binding());
        hw.biometric = Box::new(MembershipBiometrics {
            members,
            next: 0,
            order: vec![0, 1],
        });
        hw.oidc_provider = Some(Box::new(MembershipIdp {
            calls: 0,
            bad_signature_on: None,
            advance_on_second: None,
        }));
        let restarted = VaultService::start(
            VaultConfig {
                profile: Profile::L2,
                state_dir: Some(state.clone()),
                ..Default::default()
            },
            hw,
        )
        .unwrap();
        assert!(!restarted.cas_keys_authorized());
        assert!(restarted.lock_state().unwrap().envelope_fault);
        assert!(restarted.lock_ceremony().unwrap().setup_only);
        assert!(restarted
            .handle(&peer, VaultRequest::AuthorizeIntent(membership_draft()))
            .unwrap_err()
            .is("ASSET_MEMBERSHIP_PENDING"));
        assert!(restarted
            .handle(
                &peer,
                VaultRequest::Tokenize {
                    items: vec![TokenizeItem {
                        value: "denied@example.invalid".into(),
                        declared: None
                    }],
                    bulk_set: false,
                    grant: None
                }
            )
            .is_err());
        assert_eq!(
            restarted.lock_ceremony().unwrap().counters,
            original_counters
        );
        assert!(restarted
            .handle(&peer, VaultRequest::AddAssetBackup { receipt: consumed })
            .unwrap_err()
            .is("ASSET_ENROLLMENT_RECEIPT"));
        assert_eq!(
            restarted.lock_ceremony().unwrap().counters,
            original_counters
        );
        assert!(matches!(
            restarted
                .handle(
                    &peer,
                    VaultRequest::AddAssetBackup {
                        receipt: receipt(&pending, &f.inventory, 9)
                    }
                )
                .unwrap(),
            VaultResponse::AssetBackupAdded { .. }
        ));
        let current = serde_json::to_value(open(&state).unwrap().1).unwrap();
        assert_eq!(current["receipt_floor"], serde_json::json!(9));
        assert!(current["attempt"].as_u64().unwrap() > original["attempt"].as_u64().unwrap());
        assert!(restarted
            .lock_ceremony()
            .unwrap()
            .counters
            .dominates(&original_counters));
        assert!(!restarted.lock_ceremony().unwrap().setup_only);
        assert!(!restarted.lock_state().unwrap().envelope_fault);
        assert!(matches!(
            restarted
                .handle(
                    &peer,
                    VaultRequest::Detokenize {
                        surrogates: vec![prior],
                        draft: Box::new(membership_draft())
                    }
                )
                .unwrap(),
            VaultResponse::Delivered { rows: 1, .. }
        ));
    }

    fn renewal_fixture() -> (CutoverFixture, [SharedBiometric; 2], PendingAssetEnrollment) {
        let mut f = cutover_fixture();
        let primary = match open(&f.root.0.join("state")).unwrap().1.phase {
            Phase::Active { pending, .. } => pending.evidence,
            _ => panic!(),
        };
        let members = enable_membership_devices(&mut f, None, false);
        f.service
            .add_asset_backup(
                &PeerCredentials::local(0, 0),
                f.backup.pending.clone(),
                f.backup.receipt.clone(),
                f.backup_blob.clone(),
            )
            .unwrap();
        (f, members, primary)
    }
    fn reset_renewal_factors(
        service: &VaultService,
        members: &[SharedBiometric; 2],
        bad: Option<usize>,
    ) {
        // Let the SAME production engine's retained prompt history age through
        // the actual60s rate window. Wait outside every request ceremony: both
        // service and CTAP transport retain their real continuous clock and
        // the complete10s request cap remains unchanged. Two bounded sleeps
        // also allow the coordinator to report progress during the test job.
        std::thread::sleep(std::time::Duration::from_secs(31));
        std::thread::sleep(std::time::Duration::from_secs(30));
        let mut c = service.lock_ceremony().unwrap();
        c.hw.biometric = Box::new(MembershipBiometrics {
            members: members.clone(),
            next: 0,
            order: vec![0, 1],
        });
        c.hw.oidc_provider = Some(Box::new(MembershipIdp {
            calls: 0,
            bad_signature_on: bad,
            advance_on_second: None,
        }));
    }
    fn renewal_request(
        f: &CutoverFixture,
        primary: &PendingAssetEnrollment,
        first: u64,
    ) -> VaultRequest {
        let long = |pending: &PendingAssetEnrollment, generation| {
            let mut r = receipt(pending, &f.inventory, generation);
            r.expires_unix = enclave_crypto::time::now_unix() + 600;
            r.signature = f
                .inventory
                .sign(&r.signing_message().unwrap())
                .to_bytes()
                .to_vec();
            r
        };
        VaultRequest::RenewAssetMembership {
            primary_receipt: long(primary, first),
            backup_receipt: long(&f.backup.pending, first + 1),
        }
    }
    #[test]
    fn membership_renewal_preserves_exact_wrappers_content_and_identity_and_advances_current_authority(
    ) {
        let (f, members, primary) = renewal_fixture();
        let peer = PeerCredentials::local(0, 0);
        let state = f.root.0.join("state");
        let token = membership_tokenize(&f.service, "same-membership@example.invalid");
        let before = load_native_membership(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix(),
        )
        .unwrap()
        .unwrap();
        let old_guard = f
            .service
            .lock_state()
            .unwrap()
            .active_asset_guard
            .clone()
            .unwrap();
        let before_counters = f.service.lock_ceremony().unwrap().counters.clone();
        let counts = {
            let mut c = f.service.lock_ceremony().unwrap();
            let pair = c.hw.membership_devices.as_mut().unwrap();
            [
                pair.member(0)
                    .unwrap()
                    .virtual_authenticator()
                    .unwrap()
                    .sign_count(),
                pair.member(1)
                    .unwrap()
                    .virtual_authenticator()
                    .unwrap()
                    .sign_count(),
            ]
        };
        reset_renewal_factors(&f.service, &members, None);
        let reply = f
            .service
            .handle(&peer, renewal_request(&f, &primary, 9))
            .unwrap();
        let VaultResponse::AssetMembershipRenewed {membership_id,generation}=reply else {panic!()};
        assert_eq!(membership_id, hex::encode(before.membership_id()));
        assert!(generation > before.generation());
        let after = load_native_membership(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(before.source_binding(), after.source_binding());
        assert_eq!(
            serde_json::to_vec(before.checkpoint()).unwrap(),
            serde_json::to_vec(after.checkpoint()).unwrap()
        );
        assert_eq!(
            serde_json::to_vec(before.backup_wrappers()).unwrap(),
            serde_json::to_vec(after.backup_wrappers()).unwrap()
        );
        assert!(old_guard.check(enclave_crypto::time::now_unix()).is_err());
        let counters = f.service.lock_ceremony().unwrap().counters.clone();
        assert!(counters.dominates(&before_counters));
        assert_eq!(
            counters.get_credential(&after.enrolled(0).unwrap().credential),
            counts[0] + 2
        );
        assert_eq!(
            counters.get_credential(&after.enrolled(1).unwrap().credential),
            counts[1] + 2
        );
        reset_renewal_factors(&f.service, &members, None);
        assert!(matches!(
            f.service
                .handle(&peer, renewal_request(&f, &primary, 11))
                .unwrap(),
            VaultResponse::AssetMembershipRenewed { .. }
        ));
        let final_record = load_native_membership(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(final_record.membership_id(), before.membership_id());
        assert_eq!(
            serde_json::to_vec(final_record.backup_wrappers()).unwrap(),
            serde_json::to_vec(before.backup_wrappers()).unwrap()
        );
        assert!(matches!(
            f.service
                .handle(
                    &peer,
                    VaultRequest::Detokenize {
                        surrogates: vec![token],
                        draft: Box::new(membership_draft())
                    }
                )
                .unwrap(),
            VaultResponse::Delivered { rows: 1, .. }
        ));
    }
    #[test]
    fn membership_expired_current_receipts_boot_only_sterile_and_fresh_renewal_restores_access() {
        let (f, members, primary) = renewal_fixture();
        let peer = PeerCredentials::local(0, 0);
        let state = f.root.0.join("state");
        let token = membership_tokenize(&f.service, "receipt-expiry@example.invalid");
        let old_id = load_native_membership(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix(),
        )
        .unwrap()
        .unwrap()
        .membership_id();
        reset_renewal_factors(&f.service, &members, None);
        let expires = enclave_crypto::time::now_unix() + 3;
        let short = |pending: &PendingAssetEnrollment, generation: u64| {
            let mut r = receipt(pending, &f.inventory, generation);
            r.expires_unix = expires;
            r.signature = f
                .inventory
                .sign(&r.signing_message().unwrap())
                .to_bytes()
                .to_vec();
            r
        };
        f.service
            .handle(
                &peer,
                VaultRequest::RenewAssetMembership {
                    primary_receipt: short(&primary, 9),
                    backup_receipt: short(&f.backup.pending, 10),
                },
            )
            .unwrap();
        // Functional expiry observation only, in bounded50ms waits; this is not
        // lifecycle timing calibration or a ceremony-cap measurement.
        while enclave_crypto::time::now_unix() < expires {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(load_native_membership(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix()
        )
        .unwrap()
        .is_none());
        let setup = load_native_membership_setup(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix(),
        )
        .unwrap()
        .unwrap();
        let mut hw = {
            let mut c = f.service.lock_ceremony().unwrap();
            std::mem::replace(
                &mut c.hw,
                VaultHardware::simulated(Profile::L2, enclave_crypto::time::now_unix()).unwrap(),
            )
        };
        let enrolled = setup.enrolled();
        hw.credential = Some(enrolled.credential);
        hw.sep_bio_key =
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&enrolled.bio_public_key).unwrap();
        hw.sep_bio_blob = Some(enrolled.bio_key_blob);
        hw.active_asset_guard = None;
        let restarted = VaultService::start(
            VaultConfig {
                profile: Profile::L2,
                state_dir: Some(state.clone()),
                ..Default::default()
            },
            hw,
        )
        .unwrap();
        assert!(!restarted.cas_keys_authorized());
        assert!(restarted.lock_state().unwrap().envelope_fault);
        assert!(restarted.lock_ceremony().unwrap().setup_only);
        assert!(restarted
            .handle(&peer, VaultRequest::AuthorizeIntent(membership_draft()))
            .is_err());
        reset_renewal_factors(&restarted, &members, None);
        assert!(matches!(
            restarted
                .handle(&peer, renewal_request(&f, &primary, 11))
                .unwrap(),
            VaultResponse::AssetMembershipRenewed { .. }
        ));
        assert_eq!(
            load_native_membership(
                &state,
                Some(&f.authority),
                Profile::L2,
                enclave_crypto::time::now_unix()
            )
            .unwrap()
            .unwrap()
            .membership_id(),
            old_id
        );
        assert!(matches!(
            restarted
                .handle(
                    &peer,
                    VaultRequest::Detokenize {
                        surrogates: vec![token],
                        draft: Box::new(membership_draft())
                    }
                )
                .unwrap(),
            VaultResponse::Delivered { rows: 1, .. }
        ));
    }
    #[test]
    fn membership_renewal_bad_receipts_or_history_never_burn_or_become_expected_expiry() {
        let (f, members, primary) = renewal_fixture();
        let peer = PeerCredentials::local(0, 0);
        let state = f.root.0.join("state");
        let before = std::fs::read(state.join("asset-enrollment/workflow.sealed")).unwrap();
        let counters = f.service.lock_ceremony().unwrap().counters.clone();
        for failure in ["signature", "same-generation", "replay", "wrong-pending"] {
            let mut a = receipt(&primary, &f.inventory, 9);
            let mut b = receipt(&f.backup.pending, &f.inventory, 10);
            match failure {
                "signature" => a.signature[0] ^= 1,
                "same-generation" => b = receipt(&f.backup.pending, &f.inventory, 9),
                "replay" => a = receipt(&primary, &f.inventory, 8),
                _ => b = receipt(&primary, &f.inventory, 10),
            }
            assert!(f
                .service
                .handle(
                    &peer,
                    VaultRequest::RenewAssetMembership {
                        primary_receipt: a,
                        backup_receipt: b
                    }
                )
                .is_err());
            assert_eq!(
                std::fs::read(state.join("asset-enrollment/workflow.sealed")).unwrap(),
                before
            );
            assert_eq!(f.service.lock_ceremony().unwrap().counters, counters);
        }
        reset_renewal_factors(&f.service, &members, None);
        assert!(matches!(
            f.service
                .handle(&peer, renewal_request(&f, &primary, 9))
                .unwrap(),
            VaultResponse::AssetMembershipRenewed { .. }
        ));
        // Corrupt the effective NEW signature while preserving every plan and
        // shape field. Genuine crypto verification must still error after
        // expected expiry, rather than a generic error-to-None fallback.
        let (mut store, mut ledger) = open(&state).unwrap();
        let mut value = serde_json::to_value(&ledger).unwrap();
        let byte = value["phase"]["MembershipCommitted"]["record"]["renewed"]["primary_receipt"]
            ["signature"][0]
            .as_u64()
            .unwrap();
        value["phase"]["MembershipCommitted"]["record"]["renewed"]["primary_receipt"]
            ["signature"][0] = serde_json::json!(byte ^ 1);
        ledger = serde_json::from_value(value).unwrap();
        store.save_json(&ledger).unwrap();
        assert!(load_native_membership(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix() + 601
        )
        .is_err());
        assert!(load_native_membership_setup(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix() + 601
        )
        .is_err());
    }
    #[test]
    fn membership_failed_renewal_restart_retains_burns_and_counters_and_only_new_pair_can_finish() {
        let (f, members, primary) = renewal_fixture();
        let peer = PeerCredentials::local(0, 0);
        let state = f.root.0.join("state");
        let token = membership_tokenize(&f.service, "renewal-restart@example.invalid");
        let before = f.service.lock_ceremony().unwrap().counters.clone();
        reset_renewal_factors(&f.service, &members, Some(1));
        assert!(f
            .service
            .handle(&peer, renewal_request(&f, &primary, 9))
            .unwrap_err()
            .is("OIDC_SIGNATURE_INVALID"));
        let consumed = f.service.lock_ceremony().unwrap().counters.clone();
        assert!(consumed.dominates(&before));
        assert_ne!(consumed, before);
        assert!(matches!(
            open(&state).unwrap().1.phase,
            Phase::MembershipRenewing { .. }
        ));
        assert!(!f.service.cas_keys_authorized());
        let source = load_native_membership_setup(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix(),
        )
        .unwrap()
        .unwrap();
        let mut hw = {
            let mut c = f.service.lock_ceremony().unwrap();
            std::mem::replace(
                &mut c.hw,
                VaultHardware::simulated(Profile::L2, enclave_crypto::time::now_unix()).unwrap(),
            )
        };
        let enrolled = source.enrolled();
        hw.credential = Some(enrolled.credential);
        hw.sep_bio_key =
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&enrolled.bio_public_key).unwrap();
        hw.sep_bio_blob = Some(enrolled.bio_key_blob);
        hw.active_asset_guard = None;
        let restarted = VaultService::start(
            VaultConfig {
                profile: Profile::L2,
                state_dir: Some(state.clone()),
                ..Default::default()
            },
            hw,
        )
        .unwrap();
        assert_eq!(restarted.lock_ceremony().unwrap().counters, consumed);
        assert!(!restarted.cas_keys_authorized());
        assert!(restarted
            .handle(&peer, renewal_request(&f, &primary, 9))
            .is_err());
        assert_eq!(restarted.lock_ceremony().unwrap().counters, consumed);
        reset_renewal_factors(&restarted, &members, None);
        assert!(matches!(
            restarted
                .handle(&peer, renewal_request(&f, &primary, 11))
                .unwrap(),
            VaultResponse::AssetMembershipRenewed { .. }
        ));
        assert!(restarted
            .lock_ceremony()
            .unwrap()
            .counters
            .dominates(&consumed));
        assert_eq!(open(&state).unwrap().1.receipt_floor, 12);
        assert!(matches!(
            restarted
                .handle(
                    &peer,
                    VaultRequest::Detokenize {
                        surrogates: vec![token],
                        draft: Box::new(membership_draft())
                    }
                )
                .unwrap(),
            VaultResponse::Delivered { rows: 1, .. }
        ));
    }
    #[test]
    fn membership_renewal_second_factor_cannot_restart_original_complete_cap() {
        #[derive(Debug)]
        struct OffsetClock {
            late: Arc<std::sync::atomic::AtomicU64>,
        }
        impl Clock for OffsetClock {
            fn now_ns(&self) -> u64 {
                SystemClock
                    .now_ns()
                    .saturating_add(self.late.load(Ordering::SeqCst))
            }
            fn now_unix(&self) -> i64 {
                SystemClock.now_unix()
                    + i64::try_from(self.late.load(Ordering::SeqCst) / 1_000_000_000).unwrap()
            }
        }
        let (f, members, primary) = renewal_fixture();
        let peer = PeerCredentials::local(0, 0);
        let before = f.service.lock_ceremony().unwrap().counters.clone();
        reset_renewal_factors(&f.service, &members, None);
        let offset = Arc::new(std::sync::atomic::AtomicU64::new(0));
        {
            let mut c = f.service.lock_ceremony().unwrap();
            c.clock = Box::new(OffsetClock {
                late: offset.clone(),
            });
            c.hw.oidc_provider = Some(Box::new(MembershipIdp {
                calls: 0,
                bad_signature_on: None,
                advance_on_second: Some(offset),
            }));
        }
        assert!(f
            .service
            .handle(&peer, renewal_request(&f, &primary, 9))
            .unwrap_err()
            .is("CEREMONY_BUDGET_EXCEEDED"));
        assert!(f
            .service
            .lock_ceremony()
            .unwrap()
            .counters
            .dominates(&before));
        assert!(!f.service.cas_keys_authorized());
        assert!(f.service.lock_state().unwrap().envelope_fault);
        assert!(matches!(
            open(&f.root.0.join("state")).unwrap().1.phase,
            Phase::MembershipRenewing { .. }
        ));
    }
    #[test]
    fn membership_renewal_busy_final_release_retains_durable_authority_without_live_adoption() {
        let (f, members, primary) = renewal_fixture();
        let peer = PeerCredentials::local(0, 0);
        let state = f.root.0.join("state");
        reset_renewal_factors(&f.service, &members, None);
        let prepared = f
            .service
            .prepare_membership_renewal(
                &peer,
                receipt(&primary, &f.inventory, 9),
                receipt(&f.backup.pending, &f.inventory, 10),
            )
            .unwrap();
        let verified = f.service.verify_membership_renewal(prepared).unwrap();
        let counters = f.service.lock_ceremony().unwrap().counters.clone();
        let _release = f.service.cas_key_release.lock().unwrap();
        assert!(f
            .service
            .commit_membership_renewal(verified)
            .unwrap_err()
            .is("CUSTODY_RELEASE_BUSY"));
        assert!(matches!(
            open(&state).unwrap().1.phase,
            Phase::MembershipCommitted { .. }
        ));
        assert_eq!(open(&state).unwrap().1.receipt_floor, 10);
        assert!(load_native_membership(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix()
        )
        .unwrap()
        .is_some());
        assert_eq!(f.service.lock_ceremony().unwrap().counters, counters);
        assert!(!f.service.cas_keys_authorized());
        assert!(f.service.lock_state().unwrap().envelope_fault);
        assert!(f.service.lock_ceremony().unwrap().setup_only);
    }

    fn namespace_wrap(
        service: &VaultService,
        namespace: &str,
        epoch: u64,
        key: u8,
    ) -> enclave_crypto::namespace::WrappedNamespaceKey {
        match service
            .handle(
                &PeerCredentials::local(0, 0),
                VaultRequest::WrapCasKey {
                    namespace: namespace.into(),
                    epoch,
                    wrapping_epoch: 1,
                    key: enclave_crypto::namespace::SecretMaterial(vec![key; 32]),
                },
            )
            .unwrap()
        {
            VaultResponse::WrappedCasKey(wrapped) => wrapped,
            _ => panic!(),
        }
    }
    fn namespace_fixture(
        epochs: u64,
    ) -> (
        CutoverFixture,
        [SharedBiometric; 2],
        Vec<enclave_crypto::namespace::WrappedNamespaceKey>,
    ) {
        let mut f = cutover_fixture();
        let keys = (1..=epochs)
            .map(|epoch| namespace_wrap(&f.service, "models", epoch, 6 + epoch as u8))
            .collect();
        let members = enable_membership_devices(&mut f, None, false);
        f.service
            .add_asset_backup(
                &PeerCredentials::local(0, 0),
                f.backup.pending.clone(),
                f.backup.receipt.clone(),
                f.backup_blob.clone(),
            )
            .unwrap();
        (f, members, keys)
    }
    fn namespace_restart(
        f: &CutoverFixture,
        source: &VaultService,
        members: &[SharedBiometric; 2],
        index: usize,
        supplied: Option<Box<dyn HidDevice + Send>>,
    ) -> (Arc<VaultService>, Box<dyn HidDevice + Send>) {
        let state = f.root.0.join("state");
        let admitted = load_native_membership(
            &state,
            Some(&f.authority),
            Profile::L2,
            enclave_crypto::time::now_unix(),
        )
        .unwrap()
        .unwrap();
        let mut hw = {
            let mut c = source.lock_ceremony().unwrap();
            std::mem::replace(
                &mut c.hw,
                VaultHardware::simulated(Profile::L2, enclave_crypto::time::now_unix()).unwrap(),
            )
        };
        let other = if let Some(pair) = hw.membership_devices.take() {
            assert!(supplied.is_none());
            let MembershipDevicesInner::Simulated([primary,backup])=pair.inner else {panic!()};
            if index == 0 {
                hw.yubikey = Some(primary);
                backup
            } else {
                hw.yubikey = Some(backup);
                primary
            }
        } else {
            let old = hw.yubikey.take().unwrap();
            hw.yubikey = Some(supplied.unwrap());
            old
        };
        let enrolled = admitted.enrolled(index).unwrap();
        hw.credential = Some(enrolled.credential);
        hw.sep_bio_key =
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&enrolled.bio_public_key).unwrap();
        hw.sep_bio_blob = Some(enrolled.bio_key_blob);
        hw.biometric = Box::new(SelectedBiometric(members[index].clone()));
        hw.active_asset_guard = None;
        hw.asset_activation_binding = Some(admitted.source_binding());
        hw.oidc_provider = Some(Box::new(MembershipIdp {
            calls: 0,
            bad_signature_on: None,
            advance_on_second: None,
        }));
        (
            VaultService::start(
                VaultConfig {
                    profile: Profile::L2,
                    state_dir: Some(state),
                    ..Default::default()
                },
                hw,
            )
            .unwrap(),
            other,
        )
    }
    fn namespace_enterprise_policy(
        holder: &SigningKey,
        revision: u64,
    ) -> enclave_core::enterprise_authority::EnterprisePolicy {
        use enclave_core::enterprise_authority::{EnterpriseMember, EnterprisePolicy};
        let now = enclave_crypto::time::now_unix();
        EnterprisePolicy {
            version: 1,
            revision,
            trust_domain: "fixture.example".into(),
            issued_unix: now - 1,
            expires_unix: now + 3600,
            members: vec![EnterpriseMember {
                principal: "spiffe://fixture.example/engineer/alice".into(),
                generation: 1,
                holder_public_keys: vec![hex::encode(holder.verifying_key().as_bytes())],
                namespaces: vec!["models".into(), "backup-models".into()],
            }],
        }
    }
    fn namespace_enterprise(
        service: &VaultService,
    ) -> (
        Arc<enclave_core::enterprise_authority::EnterpriseAuthority>,
        SigningKey,
        SigningKey,
    ) {
        use enclave_core::enterprise_authority::{EnterpriseAuthority, SignedEnterprisePolicy};
        let issuer = SigningKey::from_bytes(&[81; 32]);
        let holder = SigningKey::from_bytes(&[82; 32]);
        let authority = EnterpriseAuthority::ephemeral_with_release_serial(
            issuer.verifying_key().to_bytes(),
            SignedEnterprisePolicy::sign(namespace_enterprise_policy(&holder, 1), &issuer).unwrap(),
            service.namespace_release_serial(),
        );
        service.set_enterprise_authority(authority.clone()).unwrap();
        (authority, issuer, holder)
    }
    fn namespace_authorized(
        service: &VaultService,
        wrapped: &enclave_crypto::namespace::WrappedNamespaceKey,
        holder: &SigningKey,
    ) -> EnclaveResult<VaultResponse> {
        use enclave_core::enterprise_authority::NamespaceProof;
        let peer = PeerCredentials::local(0, 0);
        let VaultResponse::NamespaceKeyChallenge {challenge,boot_epoch,expires_unix}=service.handle(&peer,VaultRequest::NamespaceKeyChallenge {wrapped:wrapped.clone()})? else {panic!()};
        let mut proof = NamespaceProof {
            principal: "spiffe://fixture.example/engineer/alice".into(),
            holder_public_key: String::new(),
            challenge,
            boot_epoch,
            envelope_blake3: VaultService::envelope_digest(wrapped)?,
            expires_unix,
            signature_hex: String::new(),
        };
        proof.sign(holder)?;
        service.handle(
            &peer,
            VaultRequest::UnwrapCasKeyAuthorized {
                wrapped: wrapped.clone(),
                proof,
            },
        )
    }
    fn namespace_released(reply: VaultResponse, key: u8) -> enclave_crypto::namespace::CasKeyLease {
        let VaultResponse::CasKey {key:actual,lease}=reply else {panic!()};
        assert_eq!(actual.0, vec![key; 32]);
        lease
    }

    #[test]
    fn namespace_capsule_actual_primary_migration_backup_history_new_provision_primary_restart_and_enterprise_offboarding(
    ) {
        use enclave_core::enterprise_authority::SignedEnterprisePolicy;
        use enclave_crypto::namespace;
        let (f, members, keys) = namespace_fixture(2);
        let peer = PeerCredentials::local(0, 0);
        let state = f.root.0.join("state");
        let before = f.service.lock_ceremony().unwrap().counters.clone();
        assert!(f
            .service
            .handle(
                &peer,
                VaultRequest::UnwrapCasKey {
                    wrapped: keys[0].clone()
                }
            )
            .unwrap_err()
            .is("NAMESPACE_BACKUP_MIGRATION_REQUIRED"));
        assert_eq!(
            f.service.lock_ceremony().unwrap().counters,
            before,
            "missing capsule cannot trigger primary/direct fallback"
        );
        let plaintext = b"unchanged historical artifact";
        let root = *blake3::hash(plaintext).as_bytes();
        let (ciphertext, record) =
            namespace::encrypt_chunk(&SecretKey32::new([7; 32]), &root, 0, true, plaintext)
                .unwrap();
        let saved_ciphertext = ciphertext.clone();
        assert!(matches!(
            f.service
                .handle(
                    &peer,
                    VaultRequest::MigrateNamespaceBackup {
                        namespace: "models".into()
                    }
                )
                .unwrap(),
            VaultResponse::NamespaceBackupMigrated { envelopes: 2, .. }
        ));
        assert_eq!(
            f.service
                .lock_state()
                .unwrap()
                .cas_keyring
                .namespace_snapshot("models")
                .unwrap(),
            keys
        );
        let (backup, primary_device) = namespace_restart(&f, &f.service, &members, 1, None);
        let before = backup.lock_ceremony().unwrap().counters.clone();
        let late = SystemClock
            .now_ns()
            .saturating_sub(crate::ceremony::CEREMONY_BUDGET_NS);
        assert!(backup
            .cas_key_custody_for_started(&peer, &keys[0], NamespaceCustodyOperation::Unwrap, late)
            .unwrap_err()
            .is("CEREMONY_BUDGET_EXCEEDED"));
        assert_eq!(
            backup.lock_ceremony().unwrap().counters,
            before,
            "authority IO cannot start a new complete10s window"
        );
        let (_, _, holder) = namespace_enterprise(&backup);
        let lease =
            namespace_released(namespace_authorized(&backup, &keys[0], &holder).unwrap(), 7);
        namespace_released(namespace_authorized(&backup, &keys[1], &holder).unwrap(), 8);
        assert!(backup
            .handle(
                &peer,
                VaultRequest::UnwrapCasKey {
                    wrapped: keys[0].clone()
                }
            )
            .unwrap_err()
            .is("ENTERPRISE_PROOF_REQUIRED"));
        let new_key = namespace_wrap(&backup, "backup-models", 1, 9);
        assert!(
            backup
                .handle(&peer, VaultRequest::CheckCasKeyLease(lease))
                .is_ok(),
            "other namespace provision does not revive or revoke this valid historical lease"
        );
        let (primary, _backup_device) =
            namespace_restart(&f, &backup, &members, 0, Some(primary_device));
        let (authority, issuer, holder) = namespace_enterprise(&primary);
        namespace_released(
            namespace_authorized(&primary, &new_key, &holder).unwrap(),
            9,
        );
        let VaultResponse::CasKey {key:released,lease}=namespace_authorized(&primary,&keys[0],&holder).unwrap() else {panic!()};
        assert_eq!(released.0, vec![7; 32]);
        let released = SecretKey32::new(released.0.as_slice().try_into().unwrap());
        assert_eq!(
            &*namespace::decrypt_chunk(&released, &root, 0, true, &ciphertext, &record).unwrap(),
            plaintext
        );
        assert_eq!(ciphertext, saved_ciphertext);
        assert_eq!(
            primary
                .lock_state()
                .unwrap()
                .cas_keyring
                .namespace_snapshot("models")
                .unwrap(),
            keys
        );
        assert!(matches!(
            crate::cas_keyring::CasKeyring::open(Some(&state))
                .unwrap()
                .capsule_access(&new_key)
                .unwrap(),
            crate::cas_keyring::NamespaceCapsuleAccess::Required(_)
        ));
        let stranger = SigningKey::from_bytes(&[83; 32]);
        let mut successor = namespace_enterprise_policy(&stranger, 2);
        successor.members[0].generation = 2; // Removing the old holder requires a new principal incarnation.
        authority
            .replace_ephemeral(SignedEnterprisePolicy::sign(successor, &issuer).unwrap())
            .unwrap();
        authority.refresh(enclave_crypto::time::now_unix()).unwrap();
        assert!(primary
            .handle(&peer, VaultRequest::CheckCasKeyLease(lease))
            .is_err());
        let before = primary.lock_ceremony().unwrap().counters.clone();
        assert!(namespace_authorized(&primary, &keys[0], &holder).is_err());
        assert_eq!(primary.lock_ceremony().unwrap().counters, before);
    }

    #[test]
    fn namespace_capsule_backup_rotation_preserves_dek_history_and_primary_can_open_new_wrapping_authority(
    ) {
        #[derive(Debug)]
        struct RecordOrigins {
            inner: MembershipIdp,
            origins: Arc<Mutex<Vec<(u64, u64)>>>,
        }
        impl crate::oidc_acquisition::IntentOidcProvider for RecordOrigins {
            fn acquire(
                &mut self,
                intent: &IntentPayloadV1,
                start: u64,
                deadline: u64,
                cancelled: &AtomicBool,
            ) -> EnclaveResult<crate::oidc_acquisition::BoundOidcStepUp> {
                self.origins.lock().unwrap().push((start, deadline));
                crate::oidc_acquisition::IntentOidcProvider::acquire(
                    &mut self.inner,
                    intent,
                    start,
                    deadline,
                    cancelled,
                )
            }
        }
        let (f, members, keys) = namespace_fixture(1);
        let peer = PeerCredentials::local(0, 0);
        f.service
            .handle(
                &peer,
                VaultRequest::MigrateNamespaceBackup {
                    namespace: "models".into(),
                },
            )
            .unwrap();
        let (backup, primary_device) = namespace_restart(&f, &f.service, &members, 1, None);
        let origins = Arc::new(Mutex::new(Vec::new()));
        backup.lock_ceremony().unwrap().hw.oidc_provider = Some(Box::new(RecordOrigins {
            inner: MembershipIdp {
                calls: 0,
                bad_signature_on: None,
                advance_on_second: None,
            },
            origins: origins.clone(),
        }));
        let VaultResponse::WrappedCasKey(rotated)=backup.handle(&peer,VaultRequest::RotateCasKey {wrapped:keys[0].clone(),new_wrapping_epoch:2}).unwrap() else {panic!()};
        {
            let origins = origins.lock().unwrap();
            assert_eq!(origins.len(), 2);
            assert_eq!(
                origins[0], origins[1],
                "both actual A4 factor chains inherit one original request cap"
            );
            assert_eq!(
                origins[0].1 - origins[0].0,
                crate::ceremony::CEREMONY_BUDGET_NS
            );
        }
        assert_eq!(rotated.epoch, keys[0].epoch);
        assert_eq!(rotated.wrapping_epoch, 2);
        assert!(backup
            .handle(
                &peer,
                VaultRequest::UnwrapCasKey {
                    wrapped: keys[0].clone()
                }
            )
            .is_err());
        backup
            .handle(
                &peer,
                VaultRequest::AdvanceCasWrappingFloor {
                    namespace: "models".into(),
                    minimum_wrapping_epoch: 2,
                },
            )
            .unwrap();
        assert!(backup
            .handle(
                &peer,
                VaultRequest::AdvanceCasWrappingFloor {
                    namespace: "models".into(),
                    minimum_wrapping_epoch: 1
                }
            )
            .is_err());
        namespace_released(
            backup
                .handle(
                    &peer,
                    VaultRequest::UnwrapCasKey {
                        wrapped: rotated.clone(),
                    },
                )
                .unwrap(),
            7,
        );
        let (primary, _) = namespace_restart(&f, &backup, &members, 0, Some(primary_device));
        namespace_released(
            primary
                .handle(
                    &peer,
                    VaultRequest::UnwrapCasKey {
                        wrapped: rotated.clone(),
                    },
                )
                .unwrap(),
            7,
        );
        assert_eq!(
            primary
                .lock_state()
                .unwrap()
                .cas_keyring
                .namespace_snapshot("models")
                .unwrap(),
            vec![rotated]
        );
    }

    #[test]
    fn namespace_capsule_partial_actual_unwrap_failure_publishes_no_prefix_and_backup_cannot_migrate(
    ) {
        let (f, members, keys) = namespace_fixture(2);
        let peer = PeerCredentials::local(0, 0);
        let state = f.root.0.join("state");
        // Explicit sealed-authority fault fixture: a later canonical envelope
        // authenticates only under unrelated shares. Public import cannot do this.
        let wrong =
            enclave_crypto::namespace::wrap("models", 2, 2, &[8; 32], &SecretKey32::new([99; 32]))
                .unwrap();
        f.service
            .lock_state()
            .unwrap()
            .cas_keyring
            .register(wrong.clone(), true)
            .unwrap();
        let path = state.join("cas-namespace-keyring/cas-namespace-keyring.sealed");
        let saved = std::fs::read(&path).unwrap();
        let before = f.service.lock_ceremony().unwrap().counters.clone();
        assert!(f
            .service
            .handle(
                &peer,
                VaultRequest::MigrateNamespaceBackup {
                    namespace: "models".into()
                }
            )
            .unwrap_err()
            .is("NAMESPACE_UNWRAP"));
        assert_eq!(std::fs::read(path).unwrap(), saved);
        let after = f.service.lock_ceremony().unwrap().counters.clone();
        assert!(after.dominates(&before));
        assert_ne!(after, before);
        assert!(matches!(
            f.service
                .lock_state()
                .unwrap()
                .cas_keyring
                .capsule_access(&keys[0])
                .unwrap(),
            crate::cas_keyring::NamespaceCapsuleAccess::LegacyDirect
        ));
        let (backup, _) = namespace_restart(&f, &f.service, &members, 1, None);
        let before = backup.lock_ceremony().unwrap().counters.clone();
        assert!(backup
            .handle(
                &peer,
                VaultRequest::MigrateNamespaceBackup {
                    namespace: "models".into()
                }
            )
            .unwrap_err()
            .is("NAMESPACE_CAPSULE_PRIMARY_REQUIRED"));
        assert_eq!(backup.lock_ceremony().unwrap().counters, before);
    }

    #[test]
    fn namespace_capsule_actual_migration_save_uncertainty_burns_counters_and_fences_every_old_lease(
    ) {
        let (f, _members, keys) = namespace_fixture(2);
        let peer = PeerCredentials::local(0, 0);
        let state = f.root.0.join("state");
        let directory = state.join("cas-namespace-keyring");
        let path = directory.join("cas-namespace-keyring.gen");
        let saved = std::fs::read(&path).unwrap();
        let sealed = directory.join("cas-namespace-keyring.sealed");
        let before_file = std::fs::read(&sealed).unwrap();
        let before = f.service.lock_ceremony().unwrap().counters.clone();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(f
            .service
            .handle(
                &peer,
                VaultRequest::MigrateNamespaceBackup {
                    namespace: "models".into()
                }
            )
            .is_err());
        assert_ne!(
            std::fs::read(sealed).unwrap(),
            before_file,
            "actual save wrote complete candidate before generation rename failure"
        );
        assert!(!f.service.cas_keys_authorized());
        assert!(f.service.lock_state().unwrap().cas_keyring.poisoned());
        let after = f.service.lock_ceremony().unwrap().counters.clone();
        assert!(after.dominates(&before));
        assert_ne!(after, before);
        assert!(f
            .service
            .handle(
                &peer,
                VaultRequest::UnwrapCasKey {
                    wrapped: keys[0].clone()
                }
            )
            .is_err());
        std::fs::remove_dir(&path).unwrap();
        std::fs::write(&path, saved).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let ring = crate::cas_keyring::CasKeyring::open(Some(&state)).unwrap();
        assert_eq!(ring.namespace_snapshot("models").unwrap(), keys);
        for key in keys {
            assert!(matches!(
                ring.capsule_access(&key).unwrap(),
                crate::cas_keyring::NamespaceCapsuleAccess::Required(_)
            ));
        }
    }

    #[test]
    fn namespace_capsule_corrupt_ciphertext_with_valid_primary_factors_never_falls_back_to_direct_kdf(
    ) {
        let (f, members, keys) = namespace_fixture(1);
        let peer = PeerCredentials::local(0, 0);
        let state = f.root.0.join("state");
        f.service
            .handle(
                &peer,
                VaultRequest::MigrateNamespaceBackup {
                    namespace: "models".into(),
                },
            )
            .unwrap();
        let directory = state.join("cas-namespace-keyring");
        let (mut store, loaded) = SealedStore::open_bounded_required(
            &directory,
            "cas-namespace-keyring",
            8 * 1024 * 1024,
        )
        .unwrap();
        let Loaded::State(bytes)=loaded else {panic!()};
        let mut value: serde_json::Value = enclave_core::sealed::decode(&bytes).unwrap();
        let text = value["namespaces"]["models"]["capsules"]["1"]["sealed"]["ct_hex"]
            .as_str()
            .unwrap();
        let mut ciphertext = hex::decode(text).unwrap();
        ciphertext[0] ^= 1;
        value["namespaces"]["models"]["capsules"]["1"]["sealed"]["ct_hex"] =
            serde_json::json!(hex::encode(ciphertext));
        store.save_json(&value).unwrap();
        let (primary, _) = namespace_restart(&f, &f.service, &members, 0, None);
        let before = primary.lock_ceremony().unwrap().counters.clone();
        assert!(primary
            .handle(
                &peer,
                VaultRequest::UnwrapCasKey {
                    wrapped: keys[0].clone()
                }
            )
            .is_err());
        let after = primary.lock_ceremony().unwrap().counters.clone();
        assert!(after.dominates(&before));
        assert_ne!(
            after, before,
            "actual valid primary factors precede the corrupted capsule refusal"
        );
        assert!(
            primary.lock_state().unwrap().cas_key_leases.is_empty(),
            "no direct-KDF fallback can issue a lease"
        );
    }

    #[test]
    fn namespace_capsule_actual_ipc_postsave_cancellation_refuses_ack_without_rolling_back_migration(
    ) {
        use enclave_core::ipc::{self, PeerPolicy, SocketAccess};
        use std::time::Duration;
        let (f, members, keys) = namespace_fixture(1);
        let peer = PeerCredentials::local(0, 0);
        let current = std::env::current_dir().unwrap();
        let from: Vec<_> = current.components().collect();
        let to: Vec<_> = f.root.0.components().collect();
        let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
        let mut relative = PathBuf::new();
        for _ in common..from.len() {
            relative.push("..");
        }
        for component in &to[common..] {
            relative.push(component.as_os_str());
        }
        let socket = relative.join("n.sock");
        let listener = ipc::bind(&socket, SocketAccess::OwnerOnly).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = f.service.clone();
        let (prepared_tx, prepared_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let resume = Mutex::new(resume_rx);
        let server = std::thread::spawn(move || {
            ipc::serve(
                listener,
                PeerPolicy::allow([ipc::geteuid()]),
                Arc::new(move |peer: &PeerCredentials, request: VaultRequest| {
                    let result = worker.handle(peer, request);
                    assert!(
                        matches!(
                            &result,
                            Ok(VaultResponse::NamespaceBackupMigrated { envelopes: 1, .. })
                        ),
                        "{result:?}"
                    );
                    prepared_tx.send(()).unwrap();
                    resume
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(5))
                        .unwrap();
                    result
                }),
                stopped,
            )
        });
        let outgoing = socket.clone();
        let client = std::thread::spawn(move || {
            let mut client = ipc::Client::connect(&outgoing, ipc::geteuid()).unwrap();
            client.set_timeout(Some(Duration::from_secs(5))).unwrap();
            client.call::<_, VaultResponse>(&VaultRequest::MigrateNamespaceBackup {
                namespace: "models".into(),
            })
        });
        prepared_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        f.service
            .handle(&peer, VaultRequest::Tamper(TamperEvent::ScreenLock))
            .unwrap();
        resume_tx.send(()).unwrap();
        assert!(
            client.join().unwrap().is_err(),
            "real wire permit must refuse the post-fence acknowledgment"
        );
        stop.store(true, Ordering::SeqCst);
        server.join().unwrap().unwrap();
        assert!(!f.service.cas_keys_authorized());
        let ring = crate::cas_keyring::CasKeyring::open(Some(&f.root.0.join("state"))).unwrap();
        assert_eq!(ring.namespace_snapshot("models").unwrap(), keys);
        assert!(matches!(
            ring.capsule_access(&keys[0]).unwrap(),
            crate::cas_keyring::NamespaceCapsuleAccess::Required(_)
        ));
        let (backup, _) = namespace_restart(&f, &f.service, &members, 1, None);
        namespace_released(
            backup
                .handle(
                    &peer,
                    VaultRequest::UnwrapCasKey {
                        wrapped: keys[0].clone(),
                    },
                )
                .unwrap(),
            7,
        );
    }

    fn travel_fixture() -> (
        CutoverFixture,
        crate::travel_recovery::tests::ServiceMaterial,
    ) {
        let mut f = cutover_fixture_profile(Profile::L3);
        enable_membership_devices(&mut f, None, false);
        f.service
            .add_asset_backup(
                &PeerCredentials::local(0, 0),
                f.backup.pending.clone(),
                f.backup.receipt.clone(),
                f.backup_blob.clone(),
            )
            .unwrap();
        let path = f.root.0.join("travel-audit.jsonl");
        {
            let mut state = f.service.lock_state().unwrap();
            state.journal = Some(
                AuditJournal::open(
                    &path,
                    DaemonId::CustodyVault,
                    state.seq.boot_epoch_id().into(),
                )
                .unwrap(),
            );
            state.audit_path = Some(path);
        }
        let material = crate::travel_recovery::tests::ServiceMaterial::new(&f.root.0);
        f.service
            .configure_travel_recovery(material.authority.clone(), material.anchor.boxed())
            .unwrap();
        (f, material)
    }
    fn travel_request(service: &VaultService) -> VaultRequest {
        let _ = service;
        VaultRequest::Tokenize {
            items: vec![TokenizeItem {
                value: "travel-public@example.invalid".into(),
                declared: None,
            }],
            bulk_set: false,
            grant: None,
        }
    }
    #[test]
    fn travel_service_inactive_preflight_queued_writers_cannot_cross_completed_activation() {
        use std::time::Duration;
        let (f, material) = travel_fixture();
        let peer = PeerCredentials::local(0, 0);
        // Establish a real persisted public keyring with an advanceable floor.
        // This supplies no custody grant and does not bypass any factor path.
        let mut key = enclave_crypto::namespace::WrappedNamespaceKey {
            namespace: "models".into(),
            epoch: 1,
            wrapping_epoch: 1,
            envelope_hex: "00".repeat(72),
        };
        {
            let mut state = f.service.lock_state().unwrap();
            state.cas_keyring.register(key.clone(), false).unwrap();
            key.wrapping_epoch = 9;
            state.cas_keyring.register(key, true).unwrap();
        }
        let requests = vec![
            VaultRequest::AdvanceCasWrappingFloor {
                namespace: "models".into(),
                minimum_wrapping_epoch: 9,
            },
            VaultRequest::CreateDpopProof {
                htm: "POST".into(),
                htu: "https://example.invalid/travel-race".into(),
                access_token: None,
            },
        ];
        let mut workers = Vec::new();
        let mut resumes = Vec::new();
        for request in requests {
            let service = f.service.clone();
            let (entered_tx, entered_rx) = std::sync::mpsc::channel();
            let (resume_tx, resume_rx) = std::sync::mpsc::channel();
            workers.push(std::thread::spawn(move || {
                // Hook executes inside the actual handler only AFTER its
                // inactive preflight and BEFORE the real writer/SEP dispatch.
                super::super::travel_workflow::AFTER_PREFLIGHT.with(|slot| {
                    *slot.borrow_mut() = Some(Box::new(move || {
                        entered_tx.send(()).unwrap();
                        resume_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    }))
                });
                service.handle(&PeerCredentials::local(0, 0), request)
            }));
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            resumes.push(resume_tx);
        }
        f.service
            .handle(
                &peer,
                VaultRequest::ActivateTravelRecovery {
                    token: material.token(),
                },
            )
            .unwrap();
        let ring = f
            .root
            .0
            .join("state/cas-namespace-keyring/cas-namespace-keyring.gen");
        let ring_before = std::fs::read(&ring).unwrap();
        let state = f.service.lock_state().unwrap();
        let before = serde_json::to_vec(&state.vault.checkpoint().unwrap()).unwrap();
        let sequence = state.seq.current();
        let counters = f.service.lock_ceremony().unwrap().counters.clone();
        // Resume while State is still owned, so real late dispatch contends
        // for its ownership after activation is already completely published.
        for resume in resumes {
            resume.send(()).unwrap();
        }
        drop(state);
        for worker in workers {
            assert!(worker
                .join()
                .unwrap()
                .unwrap_err()
                .is("TRAVEL_SENSITIVE_ACTION_FORBIDDEN"));
        }
        assert_eq!(
            std::fs::read(&ring).unwrap(),
            ring_before,
            "refused floor writer must not persist a new generation"
        );
        let state = f.service.lock_state().unwrap();
        assert_eq!(state.seq.current(), sequence);
        assert_eq!(
            serde_json::to_vec(&state.vault.checkpoint().unwrap()).unwrap(),
            before
        );
        assert!(state.namespace_challenges.is_empty() && state.cas_key_leases.is_empty());
        drop(state);
        assert_eq!(f.service.lock_ceremony().unwrap().counters, counters);
        assert!(f
            .service
            .begin_asset_backup(&peer)
            .unwrap_err()
            .is("TRAVEL_SENSITIVE_ACTION_FORBIDDEN"));
        assert!(f
            .service
            .begin_asset(&peer)
            .unwrap_err()
            .is("TRAVEL_SENSITIVE_ACTION_FORBIDDEN"));
        assert!(f
            .service
            .renew_asset(&peer, f.backup.receipt.clone())
            .unwrap_err()
            .is("TRAVEL_SENSITIVE_ACTION_FORBIDDEN"));
        assert!(f
            .service
            .add_asset_backup(
                &peer,
                f.backup.pending.clone(),
                f.backup.receipt.clone(),
                f.backup_blob.clone()
            )
            .unwrap_err()
            .is("TRAVEL_SENSITIVE_ACTION_FORBIDDEN"));
        assert!(f
            .service
            .renew_asset_membership(&peer, f.backup.receipt.clone(), f.backup.receipt.clone())
            .unwrap_err()
            .is("TRAVEL_SENSITIVE_ACTION_FORBIDDEN"));
        let epoch = f.service.lock_state().unwrap().epoch.clone();
        for request in [
            VaultRequest::FetchWitness {
                boot_epoch_id: epoch.boot_epoch_id.clone(),
                s_start: 0,
                s_end: 1,
            },
            VaultRequest::CoSignTombstone {
                boot_epoch_id: epoch.boot_epoch_id,
                slot_rpc_seq: 1,
            },
        ] {
            assert!(f
                .service
                .handle_state(&peer, request)
                .unwrap_err()
                .is("TRAVEL_SENSITIVE_ACTION_FORBIDDEN"));
        }
    }
    #[test]
    fn travel_service_activation_audit_and_durable_session_retain_earlier_transport_expiry() {
        let (f, material) = travel_fixture();
        let peer = PeerCredentials::local(0, 0);
        let now = enclave_crypto::time::now_unix();
        let earlier = now + 30;
        f.transport_expiry.store(earlier, Ordering::SeqCst);
        f.service.lock_state().unwrap().simulated = false;
        let response = f
            .service
            .handle(
                &peer,
                VaultRequest::ActivateTravelRecovery {
                    token: material.token(),
                },
            )
            .unwrap();
        let VaultResponse::TravelRecoveryActive {valid_until_utc_ms,..}=response else {panic!()};
        assert!(valid_until_utc_ms > u64::try_from(now).unwrap() * 1000);
        assert!(
            valid_until_utc_ms <= u64::try_from(earlier).unwrap() * 1000,
            "acknowledged bound must include actual refreshed transport expiry"
        );
        let mut state = f.service.lock_state().unwrap();
        let session = state.current_travel().unwrap();
        assert!(session.valid_until_utc_ms <= valid_until_utc_ms);
        assert!(session.deadline_ns <= state.envelope_deadline_ns.unwrap());
        drop(state);
        let audit = f.root.0.join("travel-audit.jsonl");
        let entries = std::fs::read_to_string(&audit).unwrap();
        let event = entries
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .find(|entry| entry["payload"]["event"] == "TRAVEL_DOWNGRADE_AUTHORIZED")
            .unwrap();
        assert_eq!(
            event["payload"]["valid_until_utc_ms"].as_u64(),
            Some(valid_until_utc_ms)
        );
        let directory = f.root.0.join("state/travel-recovery-service");
        let (_, loaded) =
            SealedStore::open_bounded_required(&directory, "travel", 4 * 1024 * 1024).unwrap();
        let Loaded::State(bytes)=loaded else {panic!()};
        let durable: serde_json::Value = enclave_core::sealed::decode(&bytes).unwrap();
        assert_eq!(
            durable["service"]["active"]["valid_until_utc_ms"].as_u64(),
            Some(valid_until_utc_ms)
        );
        assert_eq!(
            durable["service"]["active"]["audit"]["payload"]["valid_until_utc_ms"].as_u64(),
            Some(valid_until_utc_ms)
        );
    }
    #[test]
    fn travel_service_activation_independently_expired_transport_refuses_before_authorization_audit(
    ) {
        let (f, material) = travel_fixture();
        let peer = PeerCredentials::local(0, 0);
        let now = enclave_crypto::time::now_unix();
        f.transport_expiry.store(now + 30, Ordering::SeqCst);
        f.service.lock_state().unwrap().simulated = false;
        material.anchor.advance_ms(60_000);
        assert!(f
            .service
            .handle(
                &peer,
                VaultRequest::ActivateTravelRecovery {
                    token: material.token()
                }
            )
            .unwrap_err()
            .is("TRAVEL_DEADLINE"));
        let state = f.service.lock_state().unwrap();
        assert!(!state.travel_active());
        assert!(state.require_no_travel().is_err());
        let audit = f.root.0.join("travel-audit.jsonl");
        let entries = std::fs::read_to_string(&audit).unwrap_or_default();
        assert!(!entries
            .lines()
            .any(
                |line| serde_json::from_str::<serde_json::Value>(line).unwrap()["payload"]["event"]
                    == "TRAVEL_DOWNGRADE_AUTHORIZED"
            ));
    }
    #[test]
    fn travel_service_actual_policy_refresh_trusted_time_rejects_earlier_transport_expiry() {
        let (f, material) = travel_fixture();
        let peer = PeerCredentials::local(0, 0);
        f.service
            .handle(
                &peer,
                VaultRequest::ActivateTravelRecovery {
                    token: material.token(),
                },
            )
            .unwrap();
        let now = enclave_crypto::time::now_unix();
        f.transport_expiry.store(now + 30, Ordering::SeqCst);
        material.anchor.advance_ms(60_000);
        let mut state = f.service.lock_state().unwrap();
        state.simulated = false;
        // Use the actual non-simulated State refresh, authenticated metadata
        // client and separately signed original envelope policy. The fixture
        // server's new earlier transport receipt remains host-wall valid.
        let admitted = state.refresh_envelope_policy(now).unwrap().unwrap();
        assert!(admitted > now && admitted <= now + 30);
        assert!(
            state.envelope_valid_until_unix.unwrap() > admitted,
            "original signed policy bound alone is later"
        );
        assert!(state
            .current_travel()
            .unwrap_err()
            .is("TRAVEL_TOKEN_EXPIRED"));
    }
    #[test]
    fn travel_service_trusted_time_rejects_new_earlier_signed_expiry_despite_host_wall() {
        let (f, material) = travel_fixture();
        let peer = PeerCredentials::local(0, 0);
        f.service
            .handle(
                &peer,
                VaultRequest::ActivateTravelRecovery {
                    token: material.token(),
                },
            )
            .unwrap();
        let now = enclave_crypto::time::now_unix();
        let issuer = SigningKey::from_bytes(&[63; 32]);
        let policy = EnvelopePolicy {
            version: 1,
            revision: 2,
            subject: "host".into(),
            namespace: "data".into(),
            issued_unix: now - 1,
            expires_unix: now + 30,
            review_unix: now + 30,
            owner: "fixture".into(),
            profiles: vec![Profile::L3],
            data_classes: vec!["C3".into(), "C4".into()],
            purpose: "shorter authenticated deadline".into(),
            migration: "none".into(),
            disclosure: None,
            classical_exception: false,
        };
        let signature = issuer
            .sign(&policy.signing_message().unwrap())
            .to_bytes()
            .to_vec();
        let context = SignedEnvelopePolicy { policy, signature }
            .verify(&issuer.verifying_key(), "host", "data", now)
            .unwrap();
        // Exercise the real service admission boundary with the verified bound;
        // the host remains sixty seconds behind the independent anchor.
        let mut state = f.service.lock_state().unwrap();
        state.envelope_valid_until_unix = Some(context.expires_unix());
        material.anchor.advance_ms(60_000);
        assert!(state.clock.now_unix() < context.expires_unix());
        assert!(state
            .current_travel()
            .unwrap_err()
            .is("TRAVEL_TOKEN_EXPIRED"));
    }
    #[test]
    fn travel_service_genuine_l3_quorum_audit_no_key_public_only_restart_and_external_expiry() {
        let (f, material) = travel_fixture();
        let peer = PeerCredentials::local(0, 0);
        let state = f.root.0.join("state");
        assert!(matches!(
            f.service
                .handle(
                    &peer,
                    VaultRequest::Tokenize {
                        items: vec![TokenizeItem {
                            value: "before-travel@example.invalid".into(),
                            declared: None
                        }],
                        bulk_set: false,
                        grant: None
                    }
                )
                .unwrap(),
            VaultResponse::Tokens(_)
        ));
        let before =
            serde_json::to_vec(&f.service.lock_state().unwrap().vault.checkpoint().unwrap())
                .unwrap();
        let counters = f.service.lock_ceremony().unwrap().counters.clone();
        {
            let mut c = f.service.lock_ceremony().unwrap();
            c.hw.membership_devices = None;
            c.hw.yubikey = None;
            c.hw.credential = None;
        }
        let response = f
            .service
            .handle(
                &peer,
                VaultRequest::ActivateTravelRecovery {
                    token: material.token(),
                },
            )
            .unwrap();
        assert!(matches!(
            response,
            VaultResponse::TravelRecoveryActive {
                effective_profile: Profile::L2,
                ..
            }
        ));
        assert_eq!(f.service.lock_state().unwrap().profile, Profile::L3);
        assert_eq!(f.service.lock_state().unwrap().vault.profile(), Profile::L3);
        assert_eq!(
            serde_json::to_vec(&f.service.lock_state().unwrap().vault.checkpoint().unwrap())
                .unwrap(),
            before
        );
        assert_eq!(
            f.service.lock_ceremony().unwrap().counters,
            counters,
            "travel signatures never masquerade as new hardware assertions"
        );
        assert!(!f.service.cas_keys_authorized());
        assert!(matches!(
            f.service.handle(&peer, travel_request(&f.service)).unwrap(),
            VaultResponse::Tokens(_)
        ));
        for request in [
            VaultRequest::Enroll,
            VaultRequest::BeginAssetEnrollment,
            VaultRequest::BeginAssetBackupEnrollment,
            VaultRequest::MigrateNamespaceBackup {
                namespace: "models".into(),
            },
            VaultRequest::AuthorizeIntent(membership_draft()),
            VaultRequest::Detokenize {
                surrogates: vec!["synthetic".into()],
                draft: Box::new(membership_draft()),
            },
        ] {
            assert!(f
                .service
                .handle(&peer, request)
                .unwrap_err()
                .is("TRAVEL_SENSITIVE_ACTION_FORBIDDEN"));
        }
        assert!(f
            .service
            .handle(
                &peer,
                VaultRequest::Tokenize {
                    items: vec![],
                    bulk_set: true,
                    grant: None
                }
            )
            .unwrap_err()
            .is("TRAVEL_A4_INGEST_FORBIDDEN"));
        let scope = f
            .service
            .lock_state()
            .unwrap()
            .membership_checkpoint
            .as_ref()
            .unwrap()
            .travel_scope()
            .unwrap();
        let audit = f.root.0.join("travel-audit.jsonl");
        assert!(
            enclave_core::audit::verify_journal(&audit, None)
                .unwrap()
                .entries
                > 0
        );
        // Release the original owner before genuine restart; the old daemon
        // remains sterile and no runtime permit or physical key is supplied.
        drop(f.service.lock_state().unwrap().travel.take());
        let startup = load_travel_startup(
            &state,
            material.authority.clone(),
            material.anchor.boxed(),
            &audit,
            scope,
        )
        .unwrap();
        let hw = {
            let mut c = f.service.lock_ceremony().unwrap();
            std::mem::replace(
                &mut c.hw,
                VaultHardware::simulated(Profile::L3, enclave_crypto::time::now_unix()).unwrap(),
            )
        };
        let restarted = VaultService::start_with_travel(
            VaultConfig {
                profile: Profile::L3,
                state_dir: Some(state),
                audit_path: Some(audit),
                ..Default::default()
            },
            hw,
            startup,
        )
        .unwrap();
        {
            let c = restarted.lock_ceremony().unwrap();
            assert!(
                c.hw.credential.is_none()
                    && c.hw.yubikey.is_none()
                    && c.hw.membership_devices.is_none()
            );
            assert!(c.setup_only);
        }
        assert!(matches!(
            restarted.handle(&peer, travel_request(&restarted)).unwrap(),
            VaultResponse::Tokens(_)
        ));
        material.anchor.advance_ms(100_000);
        assert!(restarted.handle(&peer, travel_request(&restarted)).is_err());
        assert!(restarted
            .handle(&peer, VaultRequest::AuthorizeIntent(membership_draft()))
            .unwrap_err()
            .is("TRAVEL_SENSITIVE_ACTION_FORBIDDEN"));
    }
    #[test]
    fn travel_service_actual_audit_failure_burns_token_without_effective_transition_or_hardware_replay(
    ) {
        let (f, material) = travel_fixture();
        let peer = PeerCredentials::local(0, 0);
        let path = f.root.0.join("travel-audit.jsonl");
        std::fs::create_dir(&path).unwrap();
        let counters = f.service.lock_ceremony().unwrap().counters.clone();
        assert!(f
            .service
            .handle(
                &peer,
                VaultRequest::ActivateTravelRecovery {
                    token: material.token()
                }
            )
            .is_err());
        assert!(!f.service.lock_state().unwrap().travel_active());
        assert!(!f.service.cas_keys_authorized());
        assert_eq!(f.service.lock_ceremony().unwrap().counters, counters);
        assert!(
            f.service.lock_state().unwrap().require_no_travel().is_err(),
            "failed activation latches independently of session publication"
        );
        assert!(f
            .service
            .begin_asset_backup(&peer)
            .unwrap_err()
            .is("TRAVEL_SENSITIVE_ACTION_FORBIDDEN"));
        assert!(f
            .service
            .renew_asset_membership(&peer, f.backup.receipt.clone(), f.backup.receipt.clone())
            .unwrap_err()
            .is("TRAVEL_SENSITIVE_ACTION_FORBIDDEN"));
        std::fs::remove_dir(&path).unwrap();
        assert!(f
            .service
            .handle(
                &peer,
                VaultRequest::ActivateTravelRecovery {
                    token: material.token()
                }
            )
            .unwrap_err()
            .is("TRAVEL_TOKEN_CONSUMED"));
        assert!(f.service.handle(&peer, travel_request(&f.service)).is_err());
        let scope = f
            .service
            .lock_state()
            .unwrap()
            .membership_checkpoint
            .as_ref()
            .unwrap()
            .travel_scope()
            .unwrap();
        drop(f.service.lock_state().unwrap().travel.take());
        assert!(load_travel_startup(
            &f.root.0.join("state"),
            material.authority.clone(),
            material.anchor.boxed(),
            &path,
            scope
        )
        .is_err());
    }
    #[test]
    fn travel_service_actual_ipc_prepared_dpop_cannot_cross_activation_fence() {
        use enclave_core::ipc::{self, PeerPolicy, SocketAccess};
        use std::time::Duration;
        let (f, material) = travel_fixture();
        let peer = PeerCredentials::local(0, 0);
        let current = std::env::current_dir().unwrap();
        let from: Vec<_> = current.components().collect();
        let to: Vec<_> = f.root.0.components().collect();
        let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
        let mut relative = PathBuf::new();
        for _ in common..from.len() {
            relative.push("..");
        }
        for component in &to[common..] {
            relative.push(component.as_os_str());
        }
        let socket = relative.join("d.sock");
        let listener = ipc::bind(&socket, SocketAccess::OwnerOnly).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = f.service.clone();
        let (prepared_tx, prepared_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let resume = Mutex::new(resume_rx);
        let server = std::thread::spawn(move || {
            ipc::serve(
                listener,
                PeerPolicy::allow([ipc::geteuid()]),
                Arc::new(move |peer: &PeerCredentials, request: VaultRequest| {
                    let result = worker.handle(peer, request);
                    assert!(
                        matches!(&result, Ok(VaultResponse::DpopProof(_))),
                        "{result:?}"
                    );
                    prepared_tx.send(()).unwrap();
                    resume
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(5))
                        .unwrap();
                    result
                }),
                stopped,
            )
        });
        let outgoing = socket.clone();
        let client = std::thread::spawn(move || {
            let mut client = ipc::Client::connect(&outgoing, ipc::geteuid()).unwrap();
            client.set_timeout(Some(Duration::from_secs(5))).unwrap();
            client.call::<_, VaultResponse>(&VaultRequest::CreateDpopProof {
                htm: "POST".into(),
                htu: "https://example.invalid/proof".into(),
                access_token: None,
            })
        });
        prepared_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        f.service
            .handle(
                &peer,
                VaultRequest::ActivateTravelRecovery {
                    token: material.token(),
                },
            )
            .unwrap();
        resume_tx.send(()).unwrap();
        assert!(
            client.join().unwrap().is_err(),
            "actual preactivation DPoP wire reply must fail after activation fence"
        );
        stop.store(true, Ordering::SeqCst);
        server.join().unwrap().unwrap();
    }
    #[test]
    fn travel_service_actual_ipc_prefence_public_reply_cannot_succeed_after_lock_fence() {
        use enclave_core::ipc::{self, PeerPolicy, SocketAccess};
        use std::time::Duration;
        let (f, material) = travel_fixture();
        let peer = PeerCredentials::local(0, 0);
        f.service
            .handle(
                &peer,
                VaultRequest::ActivateTravelRecovery {
                    token: material.token(),
                },
            )
            .unwrap();
        let current = std::env::current_dir().unwrap();
        let from: Vec<_> = current.components().collect();
        let to: Vec<_> = f.root.0.components().collect();
        let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
        let mut relative = PathBuf::new();
        for _ in common..from.len() {
            relative.push("..");
        }
        for component in &to[common..] {
            relative.push(component.as_os_str());
        }
        let socket = relative.join("t.sock");
        let listener = ipc::bind(&socket, SocketAccess::OwnerOnly).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = f.service.clone();
        let (prepared_tx, prepared_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let resume = Mutex::new(resume_rx);
        let server = std::thread::spawn(move || {
            ipc::serve(
                listener,
                PeerPolicy::allow([ipc::geteuid()]),
                Arc::new(move |peer: &PeerCredentials, request: VaultRequest| {
                    let result = worker.handle(peer, request);
                    assert!(
                        matches!(&result, Ok(VaultResponse::Tokens(_))),
                        "{result:?}"
                    );
                    prepared_tx.send(()).unwrap();
                    resume
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(5))
                        .unwrap();
                    result
                }),
                stopped,
            )
        });
        let outgoing = socket.clone();
        let request = travel_request(&f.service);
        let client = std::thread::spawn(move || {
            let mut client = ipc::Client::connect(&outgoing, ipc::geteuid()).unwrap();
            client.set_timeout(Some(Duration::from_secs(5))).unwrap();
            client.call::<_, VaultResponse>(&request)
        });
        prepared_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        f.service
            .handle(&peer, VaultRequest::Tamper(TamperEvent::ScreenLock))
            .unwrap();
        resume_tx.send(()).unwrap();
        assert!(client.join().unwrap().is_err());
        stop.store(true, Ordering::SeqCst);
        server.join().unwrap().unwrap();
        assert!(!f.service.cas_keys_authorized());
    }
    // The provider below is an explicit software fixture. It is not an
    // independently installed/durable provider or physical-loss qualification.
    #[derive(Debug)]
    struct LossAnchorState {
        pin: MembershipAnchorPin,
        now_ms: u64,
        cas: usize,
        fail_before: bool,
        apply_then_error: bool,
        bad_nonce: bool,
        readback_fault: bool,
        loads: usize,
        advance_revision_on_load: Option<usize>,
        local_readback_fault: Option<PathBuf>,
        readback_fault_after: usize,
        advance_time_on_load: Option<(usize, u64)>,
        advance_time_before_cas_ms: u64,
        revoke_on_load: Option<(usize, std::sync::Weak<VaultService>)>,
    }
    #[derive(Clone)]
    struct LossAnchor(Arc<Mutex<LossAnchorState>>);
    impl LossAnchor {
        fn observation(
            &self,
            scope: [u8; 32],
            peer_sha256: [u8; 32],
            nonce: [u8; 32],
        ) -> EnclaveResult<MembershipAnchorObservation> {
            let mut s = self.0.lock().unwrap();
            s.loads += 1;
            if s.advance_revision_on_load == Some(s.loads) {
                s.pin.revision += 1;
            }
            if let Some((load, delta)) = s.advance_time_on_load {
                if s.loads == load {
                    s.now_ms += delta;
                }
            }
            if s.revoke_on_load
                .as_ref()
                .is_some_and(|(load, _)| s.loads == *load)
            {
                let (_, service) = s.revoke_on_load.take().unwrap();
                service.upgrade().unwrap().revoke_cas_keys().unwrap();
            }
            if s.readback_fault && s.cas > s.readback_fault_after {
                fail!(EIO, "FIXTURE_EXTERNAL_READBACK");
            }
            Ok(MembershipAnchorObservation {
                scope,
                peer_sha256,
                nonce: if s.bad_nonce { [0; 32] } else { nonce },
                pin: s.pin,
                trusted_lower_utc_ms: s.now_ms,
                trusted_upper_utc_ms: s.now_ms,
            })
        }
    }
    impl MembershipWorkflowAnchor for LossAnchor {
        fn load(
            &mut self,
            scope: [u8; 32],
            peer: [u8; 32],
            nonce: [u8; 32],
        ) -> EnclaveResult<MembershipAnchorObservation> {
            self.observation(scope, peer, nonce)
        }
        fn compare_and_advance(
            &mut self,
            scope: [u8; 32],
            peer: [u8; 32],
            nonce: [u8; 32],
            expected: MembershipAnchorPin,
            next: MembershipAnchorPin,
            cutoff: u64,
        ) -> EnclaveResult<MembershipAnchorObservation> {
            {
                let mut s = self.0.lock().unwrap();
                let advance = s.advance_time_before_cas_ms;
                s.now_ms += advance;
                if s.fail_before {
                    fail!(EIO, "FIXTURE_EXTERNAL_BEFORE_CAS");
                }
                if s.pin != expected || s.now_ms >= cutoff {
                    fail!(EACCES, "FIXTURE_EXTERNAL_CAS_CUTOFF");
                }
                assert_eq!(next.revision, expected.revision + 1);
                s.pin = next;
                s.cas += 1;
                if let Some(path) = s.local_readback_fault.take() {
                    std::fs::write(path, b"corrupt-readback-after-external-cas").unwrap();
                }
                if s.apply_then_error {
                    fail!(EIO, "FIXTURE_EXTERNAL_AMBIGUOUS_CAS");
                }
            }
            self.observation(scope, peer, nonce)
        }
    }
    fn loss_hash(ledger: &Ledger) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"depot-MembershipWholeWorkflow-v1\0");
        h.update(enclave_core::jcs::to_jcs_bytes(ledger).unwrap());
        h.finalize().into()
    }
    fn loss_owner(f: &CutoverFixture, anchor: &LossAnchor) -> MembershipAuthorityOwner {
        MembershipAuthorityOwner::new(
            MembershipAuthorityConfig {
                scope: [93; 32],
                peer_sha256: [94; 32],
                asset_authority: f.authority.clone(),
            },
            Box::new(anchor.clone()),
        )
        .unwrap()
    }
    fn loss_start(
        f: &CutoverFixture,
        anchor: &LossAnchor,
        profile: Profile,
    ) -> EnclaveResult<Arc<VaultService>> {
        let mut hw = VaultHardware::simulated(profile, enclave_crypto::time::now_unix()).unwrap();
        // Even native-marked L3 startup must not require a selected USB instance
        // or touch these discarded fixture handles in sterile owner mode.
        hw.simulated = false;
        hw.asset_enrollment_authority = Some(f.authority.clone());
        VaultService::start_with_membership_authority(
            VaultConfig {
                profile,
                state_dir: Some(f.root.0.join("state")),
                ..Default::default()
            },
            hw,
            loss_owner(f, anchor),
        )
    }
    fn loss_fixture(profile: Profile, offset: u64) -> (CutoverFixture, LossAnchor, Ledger) {
        let mut f = cutover_fixture_profile(profile);
        enable_membership_devices(&mut f, None, false);
        f.service
            .add_asset_backup(
                &PeerCredentials::local(0, 0),
                f.backup.pending.clone(),
                f.backup.receipt.clone(),
                f.backup_blob.clone(),
            )
            .unwrap();
        if profile == Profile::L3 {
            let mut draft = membership_draft();
            draft.profile = Profile::L3;
            f.service
                .handle(
                    &PeerCredentials::local(enclave_core::ipc::geteuid(), 0),
                    VaultRequest::AuthorizeIntent(draft),
                )
                .unwrap();
        }
        membership_tokenize(&f.service, "preserved-loss-content@example.invalid");
        let ledger = open(&f.root.0.join("state")).unwrap().1;
        let anchor = LossAnchor(Arc::new(Mutex::new(LossAnchorState {
            pin: MembershipAnchorPin {
                revision: 7,
                workflow_sha256: loss_hash(&ledger),
            },
            now_ms: (enclave_crypto::time::now_unix() as u64 + offset) * 1000,
            cas: 0,
            fail_before: false,
            apply_then_error: false,
            bad_nonce: false,
            readback_fault: false,
            loads: 0,
            advance_revision_on_load: None,
            local_readback_fault: None,
            readback_fault_after: 0,
            advance_time_on_load: None,
            advance_time_before_cas_ms: 0,
            revoke_on_load: None,
        })));
        (f, anchor, ledger)
    }
    fn loss_statement(
        f: &CutoverFixture,
        anchor: &LossAnchor,
        ledger: &Ledger,
        target: usize,
    ) -> Vec<u8> {
        let now = (anchor.0.lock().unwrap().now_ms / 1000) as i64;
        let context = membership_cutover::member_loss_context(
            &f.root.0.join("state"),
            ledger,
            &f.authority,
            Profile::L3,
            now,
            now,
        )
        .unwrap();
        loss_sign(f, context.bindings[target].clone(), now)
    }
    fn loss_sign(
        f: &CutoverFixture,
        binding: crate::membership_retirement::RetirementBinding,
        now: i64,
    ) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(b"depot-InventoryRetirementPins-v1\0");
        h.update(
            enclave_core::jcs::to_jcs_bytes(&(
                &f.authority.host,
                &f.authority.asset,
                &f.authority.custodian,
                f.authority.inventory_issuer.to_bytes(),
            ))
            .unwrap(),
        );
        let scope: [u8; 32] = h.finalize().into();
        let statement = serde_json::json!({"version":1,"kind":"member_retirement","inventory_scope_sha256":scope,
            "event_id":vec![95;32],"event_sequence":1,"binding":binding,"issued_unix":now-1,"not_before_unix":now-1,"expires_unix":now+60});
        let mut bytes = b"depot-InventoryMemberRetirement-v1\0".to_vec();
        bytes.extend(enclave_core::jcs::to_jcs_bytes(&statement).unwrap());
        serde_json::to_vec(&serde_json::json!({"statement":statement,"signature":f.inventory.sign(&bytes).to_bytes().to_vec()})).unwrap()
    }
    fn loss_assert_sterile(service: &VaultService) {
        let peer = PeerCredentials::local(0, 0);
        assert!(service.handle(&peer, VaultRequest::Status).is_ok());
        assert!(service.handle(&peer, VaultRequest::BootEpoch).is_ok());
        assert!(!service.cas_keys_authorized());
        let requests = [
            VaultRequest::AllocateSlot,
            VaultRequest::BeginAssetEnrollment,
            VaultRequest::BeginAssetBackupEnrollment,
            VaultRequest::CreateDpopProof {
                htm: "POST".into(),
                htu: "https://example.invalid/loss".into(),
                access_token: None,
            },
            VaultRequest::AdvanceCasWrappingFloor {
                namespace: "models".into(),
                minimum_wrapping_epoch: 9,
            },
            VaultRequest::Tokenize {
                items: vec![],
                bulk_set: false,
                grant: None,
            },
        ];
        for request in requests {
            assert!(service
                .handle(&peer, request)
                .unwrap_err()
                .is("MEMBERSHIP_RECOVERY_STERILE"));
        }
        assert!(service
            .lock_sensitive_state()
            .err()
            .unwrap()
            .is("MEMBERSHIP_RECOVERY_STERILE"));
        assert!(service
            .lock_sensitive_ceremony()
            .err()
            .unwrap()
            .is("MEMBERSHIP_RECOVERY_STERILE"));
        assert!(service
            .lock_state()
            .unwrap()
            .refresh_envelope_policy(enclave_crypto::time::now_unix())
            .unwrap_err()
            .is("MEMBERSHIP_RECOVERY_STERILE"));
    }
    #[test]
    fn member_loss_real_l3_same_store_either_target_expired_receipts_no_devices_and_exact_survivor_setup(
    ) {
        for target in 0..2 {
            let (f, anchor, original) = loss_fixture(Profile::L3, 121);
            let state = f.root.0.join("state");
            let before = enclave_core::jcs::to_jcs_bytes(&original).unwrap();
            let names = checkpoint_names(&state);
            let reference = checkpoint_hash(&state);
            let complete = std::fs::read(
                state
                    .join("membership-checkpoints")
                    .join(&reference)
                    .join("checkpoint.sealed"),
            )
            .unwrap();
            let counters = std::fs::read(state.join("signcount.sealed")).unwrap();
            let original_envelopes =
                std::fs::read(state.join("vault-envelopes/envelopes.sealed")).unwrap();
            let service = loss_start(&f, &anchor, Profile::L3).unwrap();
            loss_assert_sterile(&service);
            {
                let c = service.lock_ceremony().unwrap();
                assert!(
                    c.hw.yubikey.is_none()
                        && c.hw.membership_devices.is_none()
                        && c.hw.credential.is_none()
                        && c.setup_only
                );
            }
            let statement = loss_statement(&f, &anchor, &original, target);
            let reply = service
                .handle(
                    &PeerCredentials::local(0, 0),
                    VaultRequest::RecordMemberLoss {
                        statement: statement.clone(),
                    },
                )
                .unwrap();
            let VaultResponse::MemberLossRecorded {statement_sha256,loss_generation,..}=reply else {panic!()};
            assert_eq!(loss_generation, original.attempt + 1);
            let (_, after) = open(&state).unwrap();
            assert_eq!(after.version, 4);
            assert_eq!(after.policy_floor, original.policy_floor);
            assert_eq!(after.receipt_floor, original.receipt_floor);
            assert_eq!(anchor.0.lock().unwrap().cas, 1);
            assert_eq!(
                anchor.0.lock().unwrap().pin.workflow_sha256,
                loss_hash(&after)
            );
            let record = serde_json::to_value(&after).unwrap();
            let record = &record["phase"]["MembershipLossRecorded"]["record"];
            let rebuilt = Ledger {
                version: 3,
                attempt: serde_json::from_value(record["origin_attempt"].clone()).unwrap(),
                policy_floor: serde_json::from_value(record["origin_policy_floor"].clone())
                    .unwrap(),
                receipt_floor: serde_json::from_value(record["origin_receipt_floor"].clone())
                    .unwrap(),
                phase: Phase::MembershipCommitted {
                    record: serde_json::from_value(record["origin"].clone()).unwrap(),
                },
            };
            assert_eq!(enclave_core::jcs::to_jcs_bytes(&rebuilt).unwrap(), before);
            let setup = loss_owner(&f, &anchor)
                .load_member_loss_setup(&state, Profile::L3)
                .unwrap()
                .unwrap();
            assert_eq!(
                setup.survivor(),
                if target == 0 {
                    MemberLossSurvivor::Alternate
                } else {
                    MemberLossSurvivor::OriginalPrimary
                }
            );
            let now = (anchor.0.lock().unwrap().now_ms / 1000) as i64;
            let context = membership_cutover::member_loss_context(
                &state,
                &original,
                &f.authority,
                Profile::L3,
                now,
                now,
            )
            .unwrap();
            assert_eq!(
                setup.enrolled().credential.credential_id,
                context.members[1 - target].credential.credential_id
            );
            assert_eq!(
                serde_json::to_vec(setup.checkpoint()).unwrap(),
                serde_json::to_vec(&context.checkpoint).unwrap()
            );
            assert_eq!(setup.alternate_wrappers().is_some(), target == 0);
            assert!(load_native_membership(
                &state,
                Some(&f.authority),
                Profile::L3,
                enclave_crypto::time::now_unix()
            )
            .unwrap()
            .is_none());
            assert!(load_native_enrollment(
                &state,
                Some(&f.authority),
                Profile::L3,
                enclave_crypto::time::now_unix()
            )
            .unwrap()
            .is_none());
            assert_eq!(checkpoint_names(&state), names);
            assert_eq!(
                std::fs::read(
                    state
                        .join("membership-checkpoints")
                        .join(reference)
                        .join("checkpoint.sealed")
                )
                .unwrap(),
                complete
            );
            assert_eq!(
                std::fs::read(state.join("signcount.sealed")).unwrap(),
                counters
            );
            assert_eq!(
                std::fs::read(state.join("vault-envelopes/envelopes.sealed")).unwrap(),
                original_envelopes
            );
            assert!(
                matches!(service.handle(&PeerCredentials::local(0,0),VaultRequest::RecordMemberLoss {statement}).unwrap(),VaultResponse::MemberLossRecorded {statement_sha256:s,..} if s==statement_sha256)
            );
            assert_eq!(anchor.0.lock().unwrap().cas, 1);
            loss_assert_sterile(&loss_start(&f, &anchor, Profile::L3).unwrap());
        }
    }
    #[test]
    fn member_loss_required_exact_provider_rejects_whole_workflow_restore_wrong_head_nonce_and_unknown_version(
    ) {
        let (f, anchor, original) = loss_fixture(Profile::L3, 0);
        let state = f.root.0.join("state");
        let files = ["workflow.sealed", "workflow.gen", "sealing.key"].map(|n| {
            (
                n,
                std::fs::read(state.join("asset-enrollment").join(n)).unwrap(),
            )
        });
        let service = loss_start(&f, &anchor, Profile::L3).unwrap();
        let statement = loss_statement(&f, &anchor, &original, 0);
        service
            .handle(
                &PeerCredentials::local(0, 0),
                VaultRequest::RecordMemberLoss { statement },
            )
            .unwrap();
        for (name, bytes) in files {
            std::fs::write(state.join("asset-enrollment").join(name), bytes).unwrap();
        }
        assert!(loss_start(&f, &anchor, Profile::L3)
            .unwrap_err()
            .is("MEMBERSHIP_ANCHOR_MISMATCH"));
        assert_eq!(anchor.0.lock().unwrap().cas, 1);
        {
            let mut s = anchor.0.lock().unwrap();
            s.pin.workflow_sha256 = loss_hash(&original);
            s.bad_nonce = true;
        }
        assert!(loss_start(&f, &anchor, Profile::L3)
            .unwrap_err()
            .is("MEMBERSHIP_ANCHOR_OBSERVATION"));
        let (mut store, mut ledger) = open(&state).unwrap();
        ledger.version = u32::MAX;
        store.save_json(&ledger).unwrap();
        assert!(open(&state).unwrap_err().is("ASSET_LEDGER_VERSION"));
    }
    #[test]
    fn member_loss_bad_statement_and_missing_provider_never_mutate_and_native_l2_stays_sterile() {
        let (f, anchor, original) = loss_fixture(Profile::L3, 0);
        let state = f.root.0.join("state");
        let before = std::fs::read(state.join("asset-enrollment/workflow.sealed")).unwrap();
        assert!(f
            .service
            .handle(
                &PeerCredentials::local(0, 0),
                VaultRequest::RecordMemberLoss { statement: vec![1] }
            )
            .unwrap_err()
            .is("MEMBERSHIP_RECOVERY_PROVIDER_REQUIRED"));
        assert_eq!(
            std::fs::read(state.join("asset-enrollment/workflow.sealed")).unwrap(),
            before
        );
        let service = loss_start(&f, &anchor, Profile::L3).unwrap();
        let mut statement = loss_statement(&f, &anchor, &original, 0);
        statement[0] = b'!';
        assert!(service
            .handle(
                &PeerCredentials::local(0, 0),
                VaultRequest::RecordMemberLoss { statement }
            )
            .is_err());
        loss_assert_sterile(&service);
        assert_eq!(
            std::fs::read(state.join("asset-enrollment/workflow.sealed")).unwrap(),
            before
        );
        assert_eq!(anchor.0.lock().unwrap().cas, 0);
        let (l2, a2, _) = loss_fixture(Profile::L2, 0);
        loss_assert_sterile(&loss_start(&l2, &a2, Profile::L2).unwrap());
    }
    #[test]
    fn member_loss_actual_save_fault_and_ambiguous_external_cas_remain_sterile_and_only_exact_successor_repairs_before_original_cutoff(
    ) {
        for mode in 0..4 {
            let (f, anchor, original) = loss_fixture(Profile::L3, 0);
            let state = f.root.0.join("state");
            let service = loss_start(&f, &anchor, Profile::L3).unwrap();
            let statement = loss_statement(&f, &anchor, &original, 0);
            let _fault = if mode == 0 {
                Some(membership_cutover::obstruct_next_publication_save(
                    state.join("asset-enrollment/workflow.gen"),
                ))
            } else {
                None
            };
            {
                let mut a = anchor.0.lock().unwrap();
                a.fail_before = mode == 1;
                a.apply_then_error = mode == 2;
                a.readback_fault = mode == 3;
            }
            assert!(service
                .handle(
                    &PeerCredentials::local(0, 0),
                    VaultRequest::RecordMemberLoss {
                        statement: statement.clone()
                    }
                )
                .is_err());
            loss_assert_sterile(&service);
            if mode == 0 {
                assert_eq!(anchor.0.lock().unwrap().cas, 0);
                continue;
            }
            assert!(service
                .handle(
                    &PeerCredentials::local(0, 0),
                    VaultRequest::RecordMemberLoss { statement }
                )
                .unwrap_err()
                .is("MEMBERSHIP_AUTHORITY_UNCERTAIN"));
            {
                let mut a = anchor.0.lock().unwrap();
                a.fail_before = false;
                a.apply_then_error = false;
                a.readback_fault = false;
            }
            let restarted = loss_start(&f, &anchor, Profile::L3).unwrap();
            loss_assert_sterile(&restarted);
            assert_eq!(anchor.0.lock().unwrap().cas, 1);
        }
        let (f, anchor, original) = loss_fixture(Profile::L3, 0);
        let service = loss_start(&f, &anchor, Profile::L3).unwrap();
        let statement = loss_statement(&f, &anchor, &original, 1);
        anchor.0.lock().unwrap().fail_before = true;
        assert!(service
            .handle(
                &PeerCredentials::local(0, 0),
                VaultRequest::RecordMemberLoss { statement }
            )
            .is_err());
        {
            let mut a = anchor.0.lock().unwrap();
            a.fail_before = false;
            a.now_ms += 20_000;
        }
        assert!(loss_start(&f, &anchor, Profile::L3).is_err());
        assert_eq!(
            anchor.0.lock().unwrap().cas,
            0,
            "expired unaccepted successor never repairs later"
        );
    }

    #[test]
    fn member_loss_actual_typed_ipc_ack_follows_exact_external_and_local_readback() {
        use enclave_core::ipc::{self, PeerPolicy, SocketAccess};
        use std::time::Duration;
        let (f, anchor, original) = loss_fixture(Profile::L3, 0);
        let service = loss_start(&f, &anchor, Profile::L3).unwrap();
        let statement = loss_statement(&f, &anchor, &original, 0);
        let current = std::env::current_dir().unwrap();
        let from: Vec<_> = current.components().collect();
        let to: Vec<_> = f.root.0.components().collect();
        let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
        let mut relative = PathBuf::new();
        for _ in common..from.len() {
            relative.push("..");
        }
        for component in &to[common..] {
            relative.push(component.as_os_str());
        }
        let socket = relative.join("l.sock");
        let listener = ipc::bind(&socket, SocketAccess::OwnerOnly).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = service.clone();
        let server = std::thread::spawn(move || {
            ipc::serve(
                listener,
                PeerPolicy::allow([ipc::geteuid()]),
                Arc::new(move |peer: &PeerCredentials, request: VaultRequest| {
                    worker.handle(peer, request)
                }),
                stopped,
            )
        });
        let mut client = ipc::Client::connect(&socket, ipc::geteuid()).unwrap();
        client.set_timeout(Some(Duration::from_secs(5))).unwrap();
        assert!(matches!(
            client
                .call::<_, VaultResponse>(&VaultRequest::RecordMemberLoss { statement })
                .unwrap(),
            VaultResponse::MemberLossRecorded { .. }
        ));
        assert_eq!(anchor.0.lock().unwrap().cas, 1);
        let (_, ledger) = open(&f.root.0.join("state")).unwrap();
        assert_eq!(ledger.version, 4);
        assert_eq!(
            anchor.0.lock().unwrap().pin.workflow_sha256,
            loss_hash(&ledger)
        );
        stop.store(true, Ordering::SeqCst);
        server.join().unwrap().unwrap();
        loss_assert_sterile(&service);
    }

    #[test]
    fn member_loss_fresh_replay_and_second_setup_observation_require_exact_revision_and_original_response_deadline(
    ) {
        let (f, anchor, original) = loss_fixture(Profile::L3, 0);
        let state = f.root.0.join("state");
        let service = loss_start(&f, &anchor, Profile::L3).unwrap();
        let statement = loss_statement(&f, &anchor, &original, 0);
        let peer = PeerCredentials::local(0, 0);
        service
            .handle(
                &peer,
                VaultRequest::RecordMemberLoss {
                    statement: statement.clone(),
                },
            )
            .unwrap();
        let deadline_start = SystemClock::default()
            .now_ns()
            .saturating_sub(crate::ceremony::CEREMONY_BUDGET_NS);
        assert!(service
            .record_member_loss(&peer, &statement, deadline_start)
            .unwrap_err()
            .is("MEMBER_LOSS_DEADLINE"));
        // First fresh load inside setup agrees; only the SECOND protected load
        // sees the independently advanced revision with an identical hash.
        let owner = loss_owner(&f, &anchor);
        {
            let mut a = anchor.0.lock().unwrap();
            a.advance_revision_on_load = Some(a.loads + 2);
        }
        assert!(owner
            .load_member_loss_setup(&state, Profile::L3)
            .unwrap_err()
            .is("MEMBERSHIP_ANCHOR_MISMATCH"));
        assert!(service
            .handle(&peer, VaultRequest::RecordMemberLoss { statement })
            .unwrap_err()
            .is("MEMBERSHIP_ANCHOR_MISMATCH"));
        assert_eq!(anchor.0.lock().unwrap().cas, 1);
        loss_assert_sterile(&service);
    }
    #[test]
    fn member_loss_actual_binding_signature_target_time_admin_and_wire_size_checks_precede_publication(
    ) {
        let (f, anchor, original) = loss_fixture(Profile::L3, 0);
        let state = f.root.0.join("state");
        let service = loss_start(&f, &anchor, Profile::L3).unwrap();
        let before = std::fs::read(state.join("asset-enrollment/workflow.sealed")).unwrap();
        let statement = loss_statement(&f, &anchor, &original, 0);
        let peer = PeerCredentials::local(0, 0);
        let mut bad_signature: serde_json::Value = serde_json::from_slice(&statement).unwrap();
        bad_signature["signature"][0] = serde_json::json!(0);
        if serde_json::to_vec(&bad_signature).unwrap() == statement {
            bad_signature["signature"][0] = serde_json::json!(1);
        }
        let now = (anchor.0.lock().unwrap().now_ms / 1000) as i64;
        let context = membership_cutover::member_loss_context(
            &state,
            &original,
            &f.authority,
            Profile::L3,
            now,
            now,
        )
        .unwrap();
        let mut wrong = context.bindings[0].clone();
        wrong.membership_id = [45; 32];
        let wrong_source = loss_sign(&f, wrong, now);
        let mut alias = context.bindings[0].clone();
        alias.target = alias.survivor.clone();
        let wrong_target = loss_sign(&f, alias, now);
        let expired = loss_sign(&f, context.bindings[0].clone(), now - 120);
        for bad in [
            serde_json::to_vec(&bad_signature).unwrap(),
            wrong_source,
            wrong_target,
            expired,
        ] {
            assert!(service
                .handle(&peer, VaultRequest::RecordMemberLoss { statement: bad })
                .is_err());
            assert_eq!(
                std::fs::read(state.join("asset-enrollment/workflow.sealed")).unwrap(),
                before
            );
        }
        assert!(service
            .handle(
                &PeerCredentials::local(65534, 0),
                VaultRequest::RecordMemberLoss {
                    statement: statement.clone()
                }
            )
            .unwrap_err()
            .is("ENROLL_ADMIN_ONLY"));
        assert!(service
            .handle(
                &peer,
                VaultRequest::RecordMemberLoss {
                    statement: vec![b' '; 64 * 1024 + 1]
                }
            )
            .unwrap_err()
            .is("MEMBER_LOSS_STATEMENT_SIZE"));
        assert_eq!(anchor.0.lock().unwrap().cas, 0);
        loss_assert_sterile(&service);
        // Corruption AFTER external acceptance exercises actual authenticated
        // local readback. No ACK, no old authority and no successful reopen.
        anchor.0.lock().unwrap().local_readback_fault =
            Some(state.join("asset-enrollment/workflow.sealed"));
        assert!(service
            .handle(&peer, VaultRequest::RecordMemberLoss { statement })
            .is_err());
        assert_eq!(anchor.0.lock().unwrap().cas, 1);
        assert!(loss_start(&f, &anchor, Profile::L3).is_err());
        loss_assert_sterile(&service);
    }

    #[test]
    fn member_loss_provider_safe_integer_exhaustion_never_burns_or_initializes_a_head() {
        let (f, anchor, original) = loss_fixture(Profile::L3, 0);
        let state = f.root.0.join("state");
        let before = std::fs::read(state.join("asset-enrollment/workflow.sealed")).unwrap();
        anchor.0.lock().unwrap().pin.revision = (1 << 53) - 1;
        let service = loss_start(&f, &anchor, Profile::L3).unwrap();
        let statement = loss_statement(&f, &anchor, &original, 0);
        assert!(service
            .handle(
                &PeerCredentials::local(0, 0),
                VaultRequest::RecordMemberLoss { statement }
            )
            .is_err());
        assert_eq!(anchor.0.lock().unwrap().cas, 0);
        assert_eq!(
            std::fs::read(state.join("asset-enrollment/workflow.sealed")).unwrap(),
            before
        );
        anchor.0.lock().unwrap().pin.revision = 1 << 53;
        assert!(loss_start(&f, &anchor, Profile::L3)
            .unwrap_err()
            .is("MEMBERSHIP_ANCHOR_OBSERVATION"));
        {
            let mut a = anchor.0.lock().unwrap();
            a.pin.revision = 7;
            a.now_ms = 1 << 53;
        }
        assert!(loss_start(&f, &anchor, Profile::L3)
            .unwrap_err()
            .is("MEMBERSHIP_ANCHOR_OBSERVATION"));
    }
    #[test]
    fn member_loss_actual_replay_ipc_ack_loses_real_serialized_revocation_fence() {
        use enclave_core::ipc::{self, PeerPolicy, SocketAccess};
        use std::time::Duration;
        let (f, anchor, original) = loss_fixture(Profile::L3, 0);
        let service = loss_start(&f, &anchor, Profile::L3).unwrap();
        let statement = loss_statement(&f, &anchor, &original, 0);
        service
            .handle(
                &PeerCredentials::local(0, 0),
                VaultRequest::RecordMemberLoss {
                    statement: statement.clone(),
                },
            )
            .unwrap();
        let current = std::env::current_dir().unwrap();
        let from: Vec<_> = current.components().collect();
        let to: Vec<_> = f.root.0.components().collect();
        let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
        let mut relative = PathBuf::new();
        for _ in common..from.len() {
            relative.push("..");
        }
        for component in &to[common..] {
            relative.push(component.as_os_str());
        }
        let socket = relative.join("r.sock");
        let listener = ipc::bind(&socket, SocketAccess::OwnerOnly).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = service.clone();
        let (prepared_tx, prepared_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let resume = Mutex::new(resume_rx);
        let server = std::thread::spawn(move || {
            ipc::serve(
                listener,
                PeerPolicy::allow([ipc::geteuid()]),
                Arc::new(move |peer: &PeerCredentials, request: VaultRequest| {
                    let result = worker.handle(peer, request);
                    assert!(matches!(
                        &result,
                        Ok(VaultResponse::MemberLossRecorded { .. })
                    ));
                    prepared_tx.send(()).unwrap();
                    resume
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(5))
                        .unwrap();
                    result
                }),
                stopped,
            )
        });
        let outgoing = socket.clone();
        let client = std::thread::spawn(move || {
            let mut c = ipc::Client::connect(&outgoing, ipc::geteuid()).unwrap();
            c.set_timeout(Some(Duration::from_secs(5))).unwrap();
            c.call::<_, VaultResponse>(&VaultRequest::RecordMemberLoss { statement })
        });
        prepared_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        service
            .handle(
                &PeerCredentials::local(0, 0),
                VaultRequest::Tamper(TamperEvent::ScreenLock),
            )
            .unwrap();
        resume_tx.send(()).unwrap();
        assert!(client.join().unwrap().is_err());
        stop.store(true, Ordering::SeqCst);
        server.join().unwrap().unwrap();
        assert_eq!(anchor.0.lock().unwrap().cas, 1);
        loss_assert_sterile(&service);
    }

    #[test]
    fn member_loss_factory_checks_required_external_head_before_any_hardware_constructor() {
        let (f, anchor, original) = loss_fixture(Profile::L3, 0);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let invoked = calls.clone();
        anchor.0.lock().unwrap().pin.workflow_sha256 = [77; 32];
        let cfg = VaultConfig {
            profile: Profile::L3,
            state_dir: Some(f.root.0.join("state")),
            ..Default::default()
        };
        let rejected = VaultService::start_with_membership_authority_factory(
            cfg,
            loss_owner(&f, &anchor),
            move || {
                invoked.fetch_add(1, Ordering::SeqCst);
                VaultHardware::simulated(Profile::L3, enclave_crypto::time::now_unix())
            },
        );
        assert!(rejected.unwrap_err().is("MEMBERSHIP_ANCHOR_MISMATCH"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        anchor.0.lock().unwrap().pin.workflow_sha256 = loss_hash(&original);
        let invoked = calls.clone();
        let cfg = VaultConfig {
            profile: Profile::L3,
            state_dir: Some(f.root.0.join("state")),
            ..Default::default()
        };
        let service = VaultService::start_with_membership_authority_factory(
            cfg,
            loss_owner(&f, &anchor),
            move || {
                invoked.fetch_add(1, Ordering::SeqCst);
                let mut hw =
                    VaultHardware::simulated(Profile::L3, enclave_crypto::time::now_unix())?;
                hw.simulated = false;
                Ok(hw)
            },
        )
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        loss_assert_sterile(&service);
    }

    // Actual typed IPC handoff, with optional real Tamper between a completed
    // handler and transport serialization. Provider callbacks separately fence
    // BEFORE attach; that distinct race cannot be covered by this pause alone.
    fn loss_ipc_ack_is_refused(
        root: &Root,
        service: &Arc<VaultService>,
        request: VaultRequest,
        tamper_after_handle: bool,
    ) {
        use enclave_core::ipc::{self, PeerPolicy, SocketAccess};
        use std::time::Duration;
        let current = std::env::current_dir().unwrap();
        let from: Vec<_> = current.components().collect();
        let to: Vec<_> = root.0.components().collect();
        let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
        let mut relative = PathBuf::new();
        for _ in common..from.len() {
            relative.push("..");
        }
        for component in &to[common..] {
            relative.push(component.as_os_str());
        }
        let socket = relative.join("burn.sock");
        let listener = ipc::bind(&socket, SocketAccess::OwnerOnly).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = service.clone();
        let server = std::thread::spawn(move || {
            ipc::serve(
                listener,
                PeerPolicy::allow([ipc::geteuid()]),
                Arc::new(move |peer: &PeerCredentials, request: VaultRequest| {
                    let result = worker.handle(peer, request);
                    assert!(
                        matches!(
                            &result,
                            Ok(VaultResponse::MemberLossRecorded { .. }
                                | VaultResponse::MemberReplacementPrepared { .. })
                        ),
                        "{result:?}"
                    );
                    if tamper_after_handle {
                        worker
                            .handle(peer, VaultRequest::Tamper(TamperEvent::ScreenLock))
                            .unwrap();
                    }
                    result
                }),
                stopped,
            )
        });
        let mut client = ipc::Client::connect(&socket, ipc::geteuid()).unwrap();
        client.set_timeout(Some(Duration::from_secs(5))).unwrap();
        let result = client.call::<_, VaultResponse>(&request);
        drop(client);
        stop.store(true, Ordering::SeqCst);
        server.join().unwrap().unwrap();
        assert!(
            result.is_err(),
            "a fenced recovery ACK crossed actual IPC: {result:?}"
        );
    }
    fn loss_revoke_during_next_observation(anchor: &LossAnchor, service: &Arc<VaultService>) {
        let mut a = anchor.0.lock().unwrap();
        a.revoke_on_load = Some((a.loads + 1, Arc::downgrade(service)));
    }
    #[test]
    fn member_loss_actual_fresh_and_replay_ipc_never_adopt_generation_revoked_during_provider_observation(
    ) {
        for replay in [false, true] {
            let (f, anchor, original) = loss_fixture(Profile::L3, 0);
            let service = loss_start(&f, &anchor, Profile::L3).unwrap();
            let request = VaultRequest::RecordMemberLoss {
                statement: loss_statement(&f, &anchor, &original, 0),
            };
            if replay {
                service
                    .handle(&PeerCredentials::local(0, 0), request.clone())
                    .unwrap();
            }
            let before = service.cas_key_generation.load(Ordering::SeqCst);
            loss_revoke_during_next_observation(&anchor, &service);
            loss_ipc_ack_is_refused(&f.root, &service, request, false);
            assert_eq!(
                service.cas_key_generation.load(Ordering::SeqCst),
                before + 2
            );
            assert_eq!(anchor.0.lock().unwrap().cas, 1);
            loss_assert_sterile(&loss_start(&f, &anchor, Profile::L3).unwrap());
        }
    }
    #[derive(Clone)]
    struct PreparingCodeProvider(Arc<Mutex<(u64, u64, u8, usize)>>); // UTCms,grant generation,fault,calls
    impl crate::replacement_release_authority::ReplacementReleaseProvider for PreparingCodeProvider {
        fn observe(
            &mut self,
            request: &crate::replacement_release_authority::ReplacementReleaseRequest,
        ) -> EnclaveResult<crate::replacement_release_authority::ReplacementReleaseObservation>
        {
            use crate::replacement_release_authority::*;
            let mut s = self.0.lock().unwrap();
            s.3 += 1;
            let at = s.0;
            let generation = s.1;
            let validity = ReplacementDocumentValidity {
                issued_utc_ms: at - 1,
                not_before_utc_ms: at - 1,
                expires_utc_ms: at + 8_000,
            };
            let mut result = ReplacementReleaseObservation {
                request: request.clone(),
                provider_peer_sha256: [136; 32],
                trusted: ReplacementTrustedInterval {
                    lower_utc_ms: at,
                    upper_utc_ms: at,
                },
                running_code_sha256: [131; 32],
                approved_code_sha256: vec![[131; 32]],
                release_policy_sha256: [133; 32],
                release_policy_revision: 5,
                release_version: 7,
                release_policy_validity: ReplacementDocumentValidity {
                    expires_utc_ms: at + 60_000,
                    ..validity
                },
                grant_id: [generation as u8; 32],
                grant_generation: generation,
                grant_validity: validity,
                transport_expires_utc_ms: at + 60_000,
                transport_boot_deadline_ns: None,
            };
            match s.2 {
                1 => result.running_code_sha256 = [132; 32],
                2 => result.request.nonce = [0; 32],
                3 => result.trusted.upper_utc_ms += 60_000,
                _ => {}
            }
            Ok(result)
        }
    }
    fn preparing_code(
        service: &VaultService,
        anchor: &LossAnchor,
        generation: u64,
    ) -> PreparingCodeProvider {
        use crate::replacement_release_authority::*;
        let provider = PreparingCodeProvider(Arc::new(Mutex::new((
            anchor.0.lock().unwrap().now_ms,
            generation,
            0,
            0,
        ))));
        service
            .configure_replacement_release_authority(
                ReplacementReleaseAuthority::new(
                    ReplacementReleaseConfig {
                        membership_scope: [93; 32],
                        host_or_fleet: ReplacementHostFleetScope::Host([135; 32]),
                        provider_peer_sha256: [136; 32],
                        minimum_policy_revision: 5,
                        minimum_release_version: 7,
                        maximum_grant_lifetime_ms: 10_000,
                    },
                    Some(Box::new(provider.clone())),
                )
                .unwrap(),
            )
            .unwrap();
        provider
    }
    fn preparing_digest(domain: &[u8], value: &impl Serialize) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(domain);
        h.update(enclave_core::jcs::to_jcs_bytes(value).unwrap());
        h.finalize().into()
    }
    fn preparing_receipt(
        pending: &PendingAssetEnrollment,
        inventory: &SigningKey,
        generation: u64,
        now: i64,
    ) -> AssetEnrollmentReceipt {
        let mut r = AssetEnrollmentReceipt {
            version: 1,
            pending_sha256: pending.digest().unwrap(),
            generation,
            issued_unix: now - 1,
            expires_unix: now + 120,
            signature: vec![],
        };
        r.signature = inventory
            .sign(&r.signing_message().unwrap())
            .to_bytes()
            .to_vec();
        r
    }
    fn preparing_enrollment(f: &CutoverFixture, service: &VaultService) -> (Pending, [u8; 32]) {
        let new_root = Root::new();
        let (new_service, _, _) = fixture_profile(&new_root, Profile::L3);
        new_service
            .lock_ceremony()
            .unwrap()
            .hw
            .asset_enrollment_authority = Some(f.authority.clone());
        new_service
            .begin_asset(&PeerCredentials::local(0, 0))
            .unwrap();
        let Phase::Pending(pending)=open(&new_root.0.join("state")).unwrap().1.phase else {panic!()};
        let capability =
            ValidatedReplacementEnrollment::from_completed_initializer([93; 32], pending.clone())
                .unwrap();
        let id = service
            .stage_validated_replacement_enrollment(capability)
            .unwrap();
        (pending, id)
    }
    fn preparing_request(
        f: &CutoverFixture,
        service: &VaultService,
        anchor: &LossAnchor,
        pending: &Pending,
        evidence_id: [u8; 32],
        generation: u64,
        survivor: Option<AssetEnrollmentReceipt>,
        candidate_ttl: i64,
        statement_id: u8,
    ) -> VaultRequest {
        use crate::membership_retirement::{
            ReplacementBinding, RetirementBinding, RetirementIdentity,
        };
        let state = f.root.0.join("state");
        let (_, ledger) = open(&state).unwrap();
        let json = serde_json::to_value(&ledger).unwrap();
        let loss = if json["phase"]["MembershipLossRecorded"].is_object() {
            &json["phase"]["MembershipLossRecorded"]["record"]
        } else {
            &json["phase"]["MembershipReplacementPreparing"]["record"]["loss"]
        };
        let mut current: RetirementBinding =
            serde_json::from_value(loss["binding"].clone()).unwrap();
        current.receipt_floor = ledger.receipt_floor;
        let now = (anchor.0.lock().unwrap().now_ms / 1000) as i64;
        let replacement_receipt =
            preparing_receipt(&pending.evidence, &f.inventory, generation, now);
        let survivor_receipt = survivor.clone().unwrap_or_else(|| {
            if json["phase"]["MembershipReplacementPreparing"].is_object() {
                serde_json::from_value(
                    json["phase"]["MembershipReplacementPreparing"]["record"]["current"]
                        ["survivor_receipt"]
                        .clone(),
                )
                .unwrap()
            } else {
                let target: usize = serde_json::from_value(loss["target_index"].clone()).unwrap();
                let origin = Ledger {
                    version: 3,
                    attempt: serde_json::from_value(loss["origin_attempt"].clone()).unwrap(),
                    policy_floor: ledger.policy_floor,
                    receipt_floor: serde_json::from_value(loss["origin_receipt_floor"].clone())
                        .unwrap(),
                    phase: Phase::MembershipCommitted {
                        record: serde_json::from_value(loss["origin"].clone()).unwrap(),
                    },
                };
                membership_cutover::member_loss_context(
                    &state,
                    &origin,
                    &f.authority,
                    Profile::L3,
                    now,
                    now,
                )
                .unwrap()
                .receipts[1 - target]
                    .clone()
            }
        });
        let boot = preparing_digest(
            b"depot-ReplacementBootEpoch-v1\0",
            &service.lock_state().unwrap().epoch,
        );
        let binding = ReplacementBinding {
            current: current.clone(),
            retirement_sha256: serde_json::from_value(loss["statement_sha256"].clone()).unwrap(),
            replacement: RetirementIdentity::from_credential(pending.evidence.credential())
                .unwrap(),
            replacement_pending_sha256: pending.evidence.digest().unwrap(),
            replacement_receipt_sha256: preparing_digest(
                b"depot-ReplacementReceipt-v1\0",
                &replacement_receipt,
            ),
            replacement_receipt_generation: generation,
            replacement_receipt_expires_unix: replacement_receipt.expires_unix,
            survivor_receipt_sha256: preparing_digest(
                b"depot-ReplacementReceipt-v1\0",
                &survivor_receipt,
            ),
            survivor_receipt_expires_unix: survivor_receipt.expires_unix,
            proposed_membership_generation: current.membership_generation + 1,
            boot_epoch_sha256: boot,
            running_code_sha256: [131; 32],
            release_policy_sha256: [133; 32],
            release_policy_revision: 5,
            release_policy_expires_unix: now + 60,
        };
        let scope = preparing_digest(
            b"depot-InventoryRetirementPins-v1\0",
            &(
                &f.authority.host,
                &f.authority.asset,
                &f.authority.custodian,
                f.authority.inventory_issuer.to_bytes(),
            ),
        );
        let statement = serde_json::json!({"version":1,"kind":"member_replacement_candidate","inventory_scope_sha256":scope,"statement_id":vec![statement_id;32],
            "binding":binding,"issued_unix":now-1,"not_before_unix":now-1,"expires_unix":now+candidate_ttl});
        let mut bytes = b"depot-InventoryMemberReplacement-v1\0".to_vec();
        bytes.extend(enclave_core::jcs::to_jcs_bytes(&statement).unwrap());
        let candidate=serde_json::to_vec(&serde_json::json!({"statement":statement,"signature":f.inventory.sign(&bytes).to_bytes().to_vec()})).unwrap();
        VaultRequest::PrepareMemberReplacement {
            candidate,
            enrollment_evidence_id: evidence_id,
            replacement_receipt,
            survivor_receipt: survivor,
        }
    }
    fn preparing_fixture(
        target: usize,
        offset: u64,
    ) -> (CutoverFixture, LossAnchor, Arc<VaultService>) {
        let (f, anchor, original) = loss_fixture(Profile::L3, offset);
        let service = loss_start(&f, &anchor, Profile::L3).unwrap();
        let statement = loss_statement(&f, &anchor, &original, target);
        service
            .handle(
                &PeerCredentials::local(0, 0),
                VaultRequest::RecordMemberLoss { statement },
            )
            .unwrap();
        (f, anchor, service)
    }
    #[derive(Debug)]
    struct PreparingNoPrivate(Arc<std::sync::atomic::AtomicUsize>);
    impl crate::sep::SepAgent for PreparingNoPrivate {
        fn ecdh_share(&self, _: PrfTier) -> EnclaveResult<SecretBytes> {
            self.0.fetch_add(1, Ordering::SeqCst);
            fail!(EACCES, "UNEXPECTED_PRIVATE_FACTOR")
        }
        fn l1_secondary_share(&self, _: PrfTier) -> EnclaveResult<SecretBytes> {
            self.0.fetch_add(1, Ordering::SeqCst);
            fail!(EACCES, "UNEXPECTED_PRIVATE_FACTOR")
        }
        fn sign_epoch(&self, _: &[u8]) -> EnclaveResult<Vec<u8>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            fail!(EACCES, "UNEXPECTED_PRIVATE_FACTOR")
        }
        fn epoch_public_key(&self) -> Vec<u8> {
            self.0.fetch_add(1, Ordering::SeqCst);
            vec![]
        }
        fn create_tier_keys(&self) -> EnclaveResult<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            fail!(EACCES, "UNEXPECTED_PRIVATE_FACTOR")
        }
    }
    impl BiometricProvider for PreparingNoPrivate {
        fn evaluate(&mut self, _: &BiometricPrompt) -> BiometricOutcome {
            self.0.fetch_add(1, Ordering::SeqCst);
            panic!("Preparing must not invoke biometrics")
        }
    }
    #[test]
    fn member_replacement_preparing_real_same_store_either_survivor_preserves_every_origin_byte_and_invokes_zero_private_factors(
    ) {
        for target in 0..2 {
            let (f, anchor, service) = preparing_fixture(target, 0);
            let code = preparing_code(&service, &anchor, 1);
            let state = f.root.0.join("state");
            let before = serde_json::to_value(open(&state).unwrap().1).unwrap();
            let origin = before["phase"]["MembershipLossRecorded"]["record"].clone();
            let checkpoints = checkpoint_names(&state);
            let counters = std::fs::read(state.join("signcount.sealed")).unwrap();
            let envelopes = std::fs::read(state.join("vault-envelopes/envelopes.sealed")).unwrap();
            let (pending, id) = preparing_enrollment(&f, &service);
            let request = preparing_request(&f, &service, &anchor, &pending, id, 9, None, 60, 141);
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            {
                let mut c = service.lock_ceremony().unwrap();
                c.hw.sep = Box::new(PreparingNoPrivate(calls.clone()));
                c.hw.biometric = Box::new(PreparingNoPrivate(calls.clone()));
            }
            let reply = service
                .handle(&PeerCredentials::local(0, 0), request.clone())
                .unwrap();
            assert!(matches!(
                reply,
                VaultResponse::MemberReplacementPrepared {
                    receipt_floor: 9,
                    ..
                }
            ));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(code.0.lock().unwrap().3, 1);
            let (_, ledger) = open(&state).unwrap();
            let after = serde_json::to_value(&ledger).unwrap();
            let record = &after["phase"]["MembershipReplacementPreparing"]["record"];
            assert_eq!(record["loss"], origin);
            assert_eq!(record["consumed"].as_array().unwrap().len(), 1);
            assert_eq!(anchor.0.lock().unwrap().cas, 2);
            assert_eq!(
                std::fs::read(state.join("signcount.sealed")).unwrap(),
                counters
            );
            assert_eq!(
                std::fs::read(state.join("vault-envelopes/envelopes.sealed")).unwrap(),
                envelopes
            );
            assert_eq!(checkpoint_names(&state), checkpoints);
            assert!(matches!(
                service
                    .handle(&PeerCredentials::local(0, 0), request.clone())
                    .unwrap(),
                VaultResponse::MemberReplacementPrepared { .. }
            ));
            assert_eq!(anchor.0.lock().unwrap().cas, 2);
            loss_assert_sterile(&service);
            let reopened = loss_start(&f, &anchor, Profile::L3).unwrap();
            loss_assert_sterile(&reopened);
            assert!(reopened
                .handle(&PeerCredentials::local(0, 0), request)
                .unwrap_err()
                .is("REPLACEMENT_PREPARING_REPLAY_EXPIRED"));
            let setup = loss_owner(&f, &anchor)
                .load_member_loss_setup(&state, Profile::L3)
                .unwrap()
                .unwrap();
            assert_eq!(
                setup.survivor(),
                if target == 0 {
                    MemberLossSurvivor::Alternate
                } else {
                    MemberLossSurvivor::OriginalPrimary
                }
            );
        }
    }
    #[test]
    fn member_replacement_preparing_requires_protected_code_and_enrollment_and_fresh_actual_survivor_receipt(
    ) {
        let (f, anchor, service) = preparing_fixture(0, 121);
        let (pending, id) = preparing_enrollment(&f, &service);
        let state = f.root.0.join("state");
        let before = std::fs::read(state.join("asset-enrollment/workflow.sealed")).unwrap();
        let request = preparing_request(&f, &service, &anchor, &pending, id, 10, None, 60, 142);
        assert!(service
            .handle(&PeerCredentials::local(0, 0), request)
            .unwrap_err()
            .is("REPLACEMENT_RELEASE_PROVIDER_REQUIRED"));
        preparing_code(&service, &anchor, 1);
        let request =
            preparing_request(&f, &service, &anchor, &pending, [0; 32], 10, None, 60, 142);
        assert!(service
            .handle(&PeerCredentials::local(0, 0), request)
            .unwrap_err()
            .is("REPLACEMENT_ENROLLMENT_EVIDENCE_REQUIRED"));
        let request = preparing_request(&f, &service, &anchor, &pending, id, 10, None, 60, 142);
        assert!(service
            .handle(&PeerCredentials::local(0, 0), request)
            .is_err());
        assert_eq!(
            std::fs::read(state.join("asset-enrollment/workflow.sealed")).unwrap(),
            before
        );
        assert_eq!(anchor.0.lock().unwrap().cas, 1);
        let (_, ledger) = open(&state).unwrap();
        let value = serde_json::to_value(&ledger).unwrap();
        let r = &value["phase"]["MembershipLossRecorded"]["record"];
        let original = Ledger {
            version: 3,
            attempt: serde_json::from_value(r["origin_attempt"].clone()).unwrap(),
            policy_floor: ledger.policy_floor,
            receipt_floor: ledger.receipt_floor,
            phase: Phase::MembershipCommitted {
                record: serde_json::from_value(r["origin"].clone()).unwrap(),
            },
        };
        let now = (anchor.0.lock().unwrap().now_ms / 1000) as i64;
        let context = membership_cutover::member_loss_context(
            &state,
            &original,
            &f.authority,
            Profile::L3,
            now,
            now,
        )
        .unwrap();
        let survivor = preparing_receipt(&context.pendings[1], &f.inventory, 9, now);
        let request = preparing_request(
            &f,
            &service,
            &anchor,
            &pending,
            id,
            10,
            Some(survivor),
            60,
            143,
        );
        assert!(matches!(
            service
                .handle(&PeerCredentials::local(0, 0), request)
                .unwrap(),
            VaultResponse::MemberReplacementPrepared {
                receipt_floor: 10,
                ..
            }
        ));
        loss_assert_sterile(&service);
    }
    #[test]
    fn member_replacement_preparing_repeated_burns_are_flat_preserve_history_and_permanently_refuse_prior_candidates_and_grants(
    ) {
        let (f, anchor, service) = preparing_fixture(1, 0);
        let code = preparing_code(&service, &anchor, 1);
        let (pending, id) = preparing_enrollment(&f, &service);
        let first = preparing_request(&f, &service, &anchor, &pending, id, 9, None, 60, 144);
        service
            .handle(&PeerCredentials::local(0, 0), first.clone())
            .unwrap();
        let now = (anchor.0.lock().unwrap().now_ms / 1000) as i64;
        let next = service
            .stage_validated_replacement_enrollment(
                ValidatedReplacementEnrollment::from_completed_initializer(
                    [93; 32],
                    pending.clone(),
                )
                .unwrap(),
            )
            .unwrap();
        let second = preparing_request(&f, &service, &anchor, &pending, next, 10, None, 60, 145);
        assert!(
            service
                .handle(&PeerCredentials::local(0, 0), second.clone())
                .is_err(),
            "grant generation already consumed"
        );
        code.0.lock().unwrap().1 = 2;
        service
            .handle(&PeerCredentials::local(0, 0), second)
            .unwrap();
        assert!(service
            .handle(&PeerCredentials::local(0, 0), first)
            .unwrap_err()
            .is("REPLACEMENT_CANDIDATE_CONSUMED"));
        let value = serde_json::to_value(open(&f.root.0.join("state")).unwrap().1).unwrap();
        let r = &value["phase"]["MembershipReplacementPreparing"]["record"];
        assert_eq!(r["consumed"].as_array().unwrap().len(), 2);
        assert!(r["loss"]["origin"].is_object());
        assert!(r["loss"]["current"].is_null());
        assert_eq!(r["loss"]["history"]["events"].as_array().unwrap().len(), 1);
        assert_eq!(value["receipt_floor"], serde_json::json!(10));
        assert!(now > 0);
        assert_eq!(anchor.0.lock().unwrap().cas, 3);
        loss_assert_sterile(&loss_start(&f, &anchor, Profile::L3).unwrap());
    }
    #[test]
    fn member_replacement_preparing_candidate_earlier_expiry_maps_to_original_start_and_corrupt_provider_or_signature_never_burns(
    ) {
        let (f, anchor, service) = preparing_fixture(0, 0);
        let code = preparing_code(&service, &anchor, 1);
        let (pending, id) = preparing_enrollment(&f, &service);
        let peer = PeerCredentials::local(0, 0);
        let mut bad = preparing_request(&f, &service, &anchor, &pending, id, 9, None, 60, 146);
        if let VaultRequest::PrepareMemberReplacement { candidate, .. } = &mut bad {
            let mut value: serde_json::Value = serde_json::from_slice(candidate).unwrap();
            let byte = value["signature"][0].as_u64().unwrap() ^ 1;
            value["signature"][0] = serde_json::json!(byte);
            *candidate = serde_json::to_vec(&value).unwrap();
        }
        assert!(service.handle(&peer, bad).is_err());
        for mode in 1..=3 {
            code.0.lock().unwrap().2 = mode;
            let request = preparing_request(&f, &service, &anchor, &pending, id, 9, None, 60, 146);
            assert!(service.handle(&peer, request).is_err());
        }
        code.0.lock().unwrap().2 = 0;
        let request = preparing_request(&f, &service, &anchor, &pending, id, 9, None, 2, 147);
        let VaultRequest::PrepareMemberReplacement {candidate,enrollment_evidence_id,replacement_receipt,survivor_receipt}=request else {panic!()};
        let start = SystemClock::default()
            .now_ns()
            .saturating_sub(4_000_000_000);
        assert!(service
            .prepare_member_replacement(
                &peer,
                &candidate,
                enrollment_evidence_id,
                replacement_receipt,
                survivor_receipt,
                start
            )
            .unwrap_err()
            .is("REPLACEMENT_PREPARING_DEADLINE"));
        assert_eq!(anchor.0.lock().unwrap().cas, 1);
        loss_assert_sterile(&service);
    }
    #[test]
    fn member_replacement_preparing_actual_save_cas_and_readback_faults_never_create_ack_or_repair_from_inert_saved_facts(
    ) {
        for mode in 0..4 {
            let (f, anchor, service) = preparing_fixture(0, 0);
            preparing_code(&service, &anchor, 1);
            let (pending, id) = preparing_enrollment(&f, &service);
            let state = f.root.0.join("state");
            let request = preparing_request(&f, &service, &anchor, &pending, id, 9, None, 60, 148);
            let _fault = if mode == 0 {
                Some(membership_cutover::obstruct_next_publication_save(
                    state.join("asset-enrollment/workflow.gen"),
                ))
            } else {
                None
            };
            {
                let mut a = anchor.0.lock().unwrap();
                a.fail_before = mode == 1;
                a.apply_then_error = mode == 2;
                a.readback_fault_after = 1;
                a.readback_fault = mode == 3;
            }
            assert!(service
                .handle(&PeerCredentials::local(0, 0), request)
                .is_err());
            loss_assert_sterile(&service);
            if mode == 0 {
                assert_eq!(anchor.0.lock().unwrap().cas, 1);
                continue;
            }
            {
                let mut a = anchor.0.lock().unwrap();
                a.fail_before = false;
                a.apply_then_error = false;
                a.readback_fault = false;
            }
            if mode == 1 {
                assert!(loss_start(&f, &anchor, Profile::L3)
                    .unwrap_err()
                    .is("REPLACEMENT_PREPARING_RECONCILIATION_AUTHORITY_REQUIRED"));
                assert_eq!(anchor.0.lock().unwrap().cas, 1);
            } else {
                loss_assert_sterile(&loss_start(&f, &anchor, Profile::L3).unwrap());
                assert_eq!(anchor.0.lock().unwrap().cas, 2);
            }
        }
    }

    #[test]
    fn member_replacement_preparing_actual_fresh_and_replay_ipc_never_adopt_provider_revocation_or_cross_later_tamper(
    ) {
        for replay in [false, true] {
            for after_handle in [false, true] {
                let (f, anchor, service) = preparing_fixture(0, 0);
                preparing_code(&service, &anchor, 1);
                let (pending, id) = preparing_enrollment(&f, &service);
                let request =
                    preparing_request(&f, &service, &anchor, &pending, id, 9, None, 60, 149);
                if replay {
                    service
                        .handle(&PeerCredentials::local(0, 0), request.clone())
                        .unwrap();
                }
                let before = service.cas_key_generation.load(Ordering::SeqCst);
                if !after_handle {
                    loss_revoke_during_next_observation(&anchor, &service);
                }
                loss_ipc_ack_is_refused(&f.root, &service, request, after_handle);
                assert_eq!(
                    service.cas_key_generation.load(Ordering::SeqCst),
                    before + 2
                );
                assert_eq!(anchor.0.lock().unwrap().cas, 2);
                let (_, ledger) = open(&f.root.0.join("state")).unwrap();
                assert!(matches!(
                    ledger.phase,
                    Phase::MembershipReplacementPreparing { .. }
                ));
                loss_assert_sterile(&loss_start(&f, &anchor, Profile::L3).unwrap());
            }
        }
    }
    #[test]
    fn member_replacement_preparing_independent_time_expiring_at_atomic_cas_or_fresh_readback_never_acks_or_refreshes_cutoff(
    ) {
        for at_cas in [false, true] {
            let (f, anchor, service) = preparing_fixture(0, 0);
            preparing_code(&service, &anchor, 1);
            let (pending, id) = preparing_enrollment(&f, &service);
            let request = preparing_request(&f, &service, &anchor, &pending, id, 9, None, 60, 150);
            let before = anchor.0.lock().unwrap().pin;
            {
                let mut a = anchor.0.lock().unwrap();
                if at_cas {
                    a.advance_time_before_cas_ms = 20_000;
                } else {
                    a.advance_time_on_load = Some((a.loads + 3, 20_000));
                }
            }
            let error = service
                .handle(&PeerCredentials::local(0, 0), request)
                .unwrap_err();
            assert!(
                error.is(if at_cas {
                    "FIXTURE_EXTERNAL_CAS_CUTOFF"
                } else {
                    "MEMBERSHIP_ANCHOR_READBACK"
                }),
                "{error:?}"
            );
            let (_, ledger) = open(&f.root.0.join("state")).unwrap();
            let Phase::MembershipReplacementPreparing {record:_}=&ledger.phase else {panic!()};
            let saved = serde_json::to_value(&ledger).unwrap();
            let cutoff = saved["phase"]["MembershipReplacementPreparing"]["record"]
                ["accept_before_utc_ms"]
                .as_u64()
                .unwrap();
            assert!(
                enclave_crypto::time::now_unix() < (cutoff / 1000) as i64,
                "host time remained valid while independent time expired"
            );
            assert!(anchor.0.lock().unwrap().now_ms >= cutoff);
            loss_assert_sterile(&service);
            if at_cas {
                assert_eq!(anchor.0.lock().unwrap().pin, before);
                assert_eq!(anchor.0.lock().unwrap().cas, 1);
                assert!(loss_start(&f, &anchor, Profile::L3)
                    .unwrap_err()
                    .is("REPLACEMENT_PREPARING_EXPIRED_UNACCEPTED"));
            } else {
                assert_eq!(anchor.0.lock().unwrap().cas, 2);
                loss_assert_sterile(&loss_start(&f, &anchor, Profile::L3).unwrap());
            }
            assert_eq!(
                serde_json::to_value(open(&f.root.0.join("state")).unwrap().1).unwrap(),
                saved
            );
        }
    }
    #[test]
    fn member_replacement_preparing_actual_authenticated_schema_history_and_complete_old_loss_restore_refuse(
    ) {
        let (f, anchor, service) = preparing_fixture(0, 0);
        preparing_code(&service, &anchor, 1);
        let state = f.root.0.join("state");
        let old = ["workflow.sealed", "workflow.gen", "sealing.key"].map(|n| {
            (
                n,
                std::fs::read(state.join("asset-enrollment").join(n)).unwrap(),
            )
        });
        let (pending, id) = preparing_enrollment(&f, &service);
        let request = preparing_request(&f, &service, &anchor, &pending, id, 9, None, 60, 151);
        service
            .handle(&PeerCredentials::local(0, 0), request)
            .unwrap();
        let (mut store, ledger) = open(&state).unwrap();
        let valid = serde_json::to_value(&ledger).unwrap();
        for mode in 0..7 {
            let mut damaged = valid.clone();
            let wrapper = &mut damaged["phase"]["MembershipReplacementPreparing"];
            match mode {
                0 => wrapper["ignored_authority"] = serde_json::json!(true),
                1 => wrapper["record"]["ignored_authority"] = serde_json::json!(true),
                2 => wrapper["record"]["consumed"] = serde_json::json!([]),
                3 | 4 => {
                    let entry = wrapper["record"]["consumed"][0].clone();
                    wrapper["record"]["consumed"] =
                        serde_json::Value::Array(vec![entry; if mode == 3 { 2 } else { 65 }]);
                }
                5 => {
                    wrapper["record"]["consumed"][0]["previous_receipt_floor"] =
                        serde_json::json!(0)
                }
                6 => {
                    wrapper["record"]["consumed"][0]["wire_sha256"] =
                        serde_json::json!(vec![17; 32])
                }
                _ => unreachable!(),
            }
            store.save_json(&damaged).unwrap();
            assert!(
                open(&state).is_err(),
                "authenticated malformed mode {mode} opened"
            );
            assert!(
                loss_start(&f, &anchor, Profile::L3).is_err(),
                "authenticated malformed mode {mode} booted"
            );
            store.save_json(&ledger).unwrap();
            assert_eq!(
                serde_json::to_value(open(&state).unwrap().1).unwrap(),
                valid
            );
        }
        drop(store);
        for (name, bytes) in old {
            std::fs::write(state.join("asset-enrollment").join(name), bytes).unwrap();
        }
        assert!(matches!(
            open(&state).unwrap().1.phase,
            Phase::MembershipLossRecorded { .. }
        ));
        assert!(loss_start(&f, &anchor, Profile::L3)
            .unwrap_err()
            .is("MEMBERSHIP_ANCHOR_MISMATCH"));
        assert_eq!(anchor.0.lock().unwrap().cas, 2);
    }

    fn replacement_enrollment_fixture(
        profile: Profile,
    ) -> (CutoverFixture, LossAnchor, Arc<VaultService>) {
        let (f, anchor, origin) = loss_fixture(profile, 0);
        let service = loss_start(&f, &anchor, profile).unwrap();
        let now = (anchor.0.lock().unwrap().now_ms / 1000) as i64;
        let context = membership_cutover::member_loss_context(
            &f.root.0.join("state"),
            &origin,
            &f.authority,
            profile,
            now,
            now,
        )
        .unwrap();
        let statement = loss_sign(&f, context.bindings[0].clone(), now);
        service
            .handle(
                &PeerCredentials::local(0, 0),
                VaultRequest::RecordMemberLoss { statement },
            )
            .unwrap();
        (f, anchor, service)
    }
    fn replacement_new_hardware(profile: Profile, anchor: &LossAnchor) -> VaultHardware {
        // The independent fixture clock is fixed. Sampling a later host second
        // would correctly fail the production negative-MDS-age check at final
        // readback; create this synthetic metadata within the protected interval.
        let now = (anchor.0.lock().unwrap().now_ms / 1000) as i64;
        let mut hw = VaultHardware::simulated(profile, now).unwrap();
        hw.credential = None;
        hw
    }
    fn replacement_capture(f: &CutoverFixture) -> serde_json::Value {
        let (_, loaded) = SealedStore::open_bounded_required(
            &f.root.0.join("state/replacement-enrollment-captures"),
            "attempts",
            16 * 1024 * 1024,
        )
        .unwrap();
        let Loaded::State(bytes)=loaded else {panic!()};
        serde_json::from_slice(&bytes).unwrap()
    }
    fn replacement_captured_pending(f: &CutoverFixture) -> Pending {
        let value = replacement_capture(f);
        serde_json::from_value(
            value["attempts"].as_array().unwrap().last().unwrap()["pending"].clone(),
        )
        .unwrap()
    }
    #[derive(Debug)]
    struct ReplacementPin {
        calls: Arc<std::sync::atomic::AtomicUsize>,
        allowed: bool,
    }
    impl crate::pin::ExistingPinProvider for ReplacementPin {
        fn read_existing_pin(&mut self, _: &BiometricPrompt) -> EnclaveResult<SecretBytes> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if !self.allowed {
                fail!(EACCES, "UNEXPECTED_TYPED_PIN");
            }
            Ok(SecretBytes::new(b"synthetic-enrollment-pin".to_vec()))
        }
    }
    #[derive(Debug)]
    struct ReplacementUntrustedBlob {
        inner: SimulatedTouchId,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl BiometricProvider for ReplacementUntrustedBlob {
        fn evaluate(&mut self, prompt: &BiometricPrompt) -> BiometricOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut outcome = self.inner.evaluate(prompt);
            // Valid signature under its advertised key, but this substituted
            // blob was never produced by that key's trusted creation owner.
            if let BiometricOutcome::Approved { enrolled_blob, .. } = &mut outcome {
                *enrolled_blob = Some(vec![0xde; 32]);
            }
            outcome
        }
    }
    #[derive(Debug)]
    struct ReplacementEnrollmentProbe {
        inner: Box<dyn HidDevice + Send>,
        makes: Arc<std::sync::atomic::AtomicUsize>,
        assertions: Arc<std::sync::atomic::AtomicUsize>,
        tail_revoke: Option<std::sync::Weak<VaultService>>,
        making: bool,
        response: crate::ctap::hid::Reassembler,
    }
    impl HidDevice for ReplacementEnrollmentProbe {
        fn write_report(&mut self, report: &[u8; crate::ctap::hid::REPORT]) -> EnclaveResult<()> {
            if report[4] == crate::ctap::hid::CMD_CBOR | 0x80 {
                if report[7] == crate::ctap::cmd::MAKE_CREDENTIAL {
                    self.makes.fetch_add(1, Ordering::SeqCst);
                    self.making = true;
                    self.response = Default::default();
                }
                if report[7] == crate::ctap::cmd::GET_ASSERTION {
                    self.assertions.fetch_add(1, Ordering::SeqCst);
                }
            }
            self.inner.write_report(report)
        }
        fn read_report(&mut self) -> EnclaveResult<[u8; crate::ctap::hid::REPORT]> {
            let report = self.inner.read_report()?;
            if self.making
                && self
                    .response
                    .feed(u32::from_be_bytes(report[..4].try_into().unwrap()), &report)?
                    .is_some()
            {
                self.making = false;
                if let Some(service) = self.tail_revoke.take() {
                    service.upgrade().unwrap().revoke_cas_keys().unwrap();
                }
            }
            Ok(report)
        }
        fn hub_depth(&self) -> u8 {
            self.inner.hub_depth()
        }
        fn bind_selected_instance(&mut self) -> EnclaveResult<()> {
            self.inner.bind_selected_instance()
        }
        fn deadline_ns(&self) -> Option<u64> {
            self.inner.deadline_ns()
        }
        fn set_deadline_ns(&mut self, deadline: Option<u64>) -> EnclaveResult<()> {
            self.inner.set_deadline_ns(deadline)
        }
    }
    fn replacement_probe(
        hw: &mut VaultHardware,
        tail: Option<std::sync::Weak<VaultService>>,
    ) -> (
        Arc<std::sync::atomic::AtomicUsize>,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let makes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let assertions = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        hw.yubikey = Some(Box::new(ReplacementEnrollmentProbe {
            inner: hw.yubikey.take().unwrap(),
            makes: makes.clone(),
            assertions: assertions.clone(),
            tail_revoke: tail,
            making: false,
            response: Default::default(),
        }));
        (makes, assertions)
    }
    #[test]
    fn member_replacement_enrollment_actual_l2_l3_producer_ignores_factory_biometric_and_preserves_origin_then_preparing_consumes_original_window(
    ) {
        for profile in [Profile::L2, Profile::L3] {
            let (f, anchor, service) = replacement_enrollment_fixture(profile);
            let state = f.root.0.join("state");
            let files = [
                "asset-enrollment/workflow.sealed",
                "asset-enrollment/workflow.gen",
                "signcount.sealed",
                "vault-envelopes/envelopes.sealed",
            ]
            .map(|n| (n, std::fs::read(state.join(n)).unwrap()));
            let names = checkpoint_names(&state);
            let mut hw = replacement_new_hardware(profile, &anchor);
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let mut untrusted = f.authority.clone();
            untrusted.host = "factory-cannot-select-issuer-scope".into();
            hw.asset_enrollment_authority = Some(untrusted);
            hw.biometric = Box::new(PreparingNoPrivate(calls.clone()));
            hw.sep = Box::new(PreparingNoPrivate(calls.clone()));
            let pin = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            hw.existing_pin = Some(Box::new(ReplacementPin {
                calls: pin.clone(),
                allowed: false,
            }));
            let (makes, assertions) = replacement_probe(&mut hw, None);
            let start = SystemClock::default().now_ns();
            let (public, id) = service
                .begin_member_replacement_enrollment_for_test(
                    &PeerCredentials::local(0, 0),
                    || Ok(hw),
                    start,
                    0,
                )
                .unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(pin.load(Ordering::SeqCst), 0);
            assert_eq!(makes.load(Ordering::SeqCst), 1);
            assert_eq!(assertions.load(Ordering::SeqCst), 0);
            let pending = replacement_captured_pending(&f);
            assert_eq!(pending.evidence.digest().unwrap(), public.digest().unwrap());
            for (name, bytes) in files {
                assert_eq!(std::fs::read(state.join(name)).unwrap(), bytes);
            }
            assert_eq!(checkpoint_names(&state), names);
            loss_assert_sterile(&service);
            if profile == Profile::L3 {
                preparing_code(&service, &anchor, 1);
                let request =
                    preparing_request(&f, &service, &anchor, &pending, id, 9, None, 60, 151);
                assert!(matches!(
                    service
                        .handle(&PeerCredentials::local(0, 0), request)
                        .unwrap(),
                    VaultResponse::MemberReplacementPrepared { .. }
                ));
                let ledger = serde_json::to_value(open(&state).unwrap().1).unwrap();
                let p = &ledger["phase"]["MembershipReplacementPreparing"]["record"]["current"];
                assert_eq!(p["original_start_ns_hex"], format!("{start:016x}"));
                assert!(
                    u64::from_str_radix(p["boot_deadline_ns_hex"].as_str().unwrap(), 16).unwrap()
                        <= start + crate::ceremony::CEREMONY_BUDGET_NS
                );
            }
        }
    }
    #[test]
    fn member_replacement_enrollment_protected_native_helper_never_uses_arbitrary_factory_outcome_and_missing_head_never_invokes_factory(
    ) {
        let (f, anchor, service) = replacement_enrollment_fixture(Profile::L3);
        let made = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        anchor.0.lock().unwrap().pin.workflow_sha256 = [77; 32];
        let count = made.clone();
        assert!(service
            .begin_member_replacement_enrollment_with_factory(
                &PeerCredentials::local(0, 0),
                crate::biometric::IntentHelperProvider::new(f.root.0.join("missing.sock")),
                || {
                    count.fetch_add(1, Ordering::SeqCst);
                    Ok(replacement_new_hardware(Profile::L3, &anchor))
                }
            )
            .unwrap_err()
            .is("MEMBERSHIP_ANCHOR_MISMATCH"));
        assert_eq!(made.load(Ordering::SeqCst), 0);
        anchor.0.lock().unwrap().pin.workflow_sha256 =
            loss_hash(&open(&f.root.0.join("state")).unwrap().1);
        let mut hw = replacement_new_hardware(Profile::L3, &anchor);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        hw.biometric = Box::new(ReplacementUntrustedBlob {
            inner: SimulatedTouchId::new(),
            calls: calls.clone(),
        });
        let (makes, _) = replacement_probe(&mut hw, None);
        assert!(service
            .begin_member_replacement_enrollment_with_factory(
                &PeerCredentials::local(0, 0),
                crate::biometric::IntentHelperProvider::new(f.root.0.join("missing.sock")),
                || Ok(hw)
            )
            .is_err());
        assert_eq!(makes.load(Ordering::SeqCst), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(service.replacement_enrollment_staged_count_for_test() == 0);
    }
    #[test]
    fn member_replacement_enrollment_actual_signed_uv_pin_is_operation_scoped_and_bad_disclosure_attestation_or_missing_pin_never_stages(
    ) {
        for mode in 0..8 {
            let (f, anchor, service) = replacement_enrollment_fixture(Profile::L3);
            let mut hw = replacement_new_hardware(Profile::L3, &anchor);
            let pins = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            if mode <= 1 {
                let dev = hw
                    .yubikey
                    .as_mut()
                    .unwrap()
                    .virtual_authenticator()
                    .unwrap();
                dev.uv_capable = false;
                dev.configure_synthetic_pin(b"synthetic-enrollment-pin");
                if mode == 0 {
                    hw.existing_pin = Some(Box::new(ReplacementPin {
                        calls: pins.clone(),
                        allowed: true,
                    }));
                }
            }
            if mode == 5 {
                hw.yubikey
                    .as_mut()
                    .unwrap()
                    .virtual_authenticator()
                    .unwrap()
                    .attestation_key = SigningKey::from_bytes(&[177; 32]);
            }
            if mode == 6 {
                hw.mds.as_mut().unwrap().refreshed_at = 0;
            }
            if mode == 7 {
                hw.mds.as_mut().unwrap().refreshed_at = enclave_crypto::time::now_unix() + 60;
            }
            let (makes, assertions) = replacement_probe(&mut hw, None);
            let result = service.begin_member_replacement_enrollment_for_test(
                &PeerCredentials::local(0, 0),
                || Ok(hw),
                SystemClock::default().now_ns(),
                if (2..=4).contains(&mode) { mode - 1 } else { 0 },
            );
            if mode == 0 {
                assert!(result.is_ok());
                assert_eq!(pins.load(Ordering::SeqCst), 1);
                assert_eq!(makes.load(Ordering::SeqCst), 1);
            } else {
                assert!(result.is_err(), "hostile mode {mode} staged");
                assert!(service.replacement_enrollment_staged_count_for_test() == 0);
                if mode >= 6 {
                    let error = result.unwrap_err();
                    // Stale refreshed_at=0 first expires the inherited MDS
                    // authority cap; future metadata reaches the strict age guard.
                    assert!(
                        error.is(if mode == 6 {
                            "REPLACEMENT_ENROLLMENT_EXPIRED"
                        } else {
                            "CUSTODY_METADATA_STALE"
                        }),
                        "hostile MDS mode {mode}: {error:?}"
                    );
                }
                if mode != 5 {
                    assert_eq!(makes.load(Ordering::SeqCst), 0);
                }
            }
            assert_eq!(assertions.load(Ordering::SeqCst), 0);
            loss_assert_sterile(&service);
            let _ = f;
        }
    }
    #[test]
    fn member_replacement_enrollment_actual_tail_removal_final_provider_fault_and_independent_expiry_preserve_inert_capture_without_capability(
    ) {
        for mode in 0..4 {
            let (f, anchor, service) = replacement_enrollment_fixture(Profile::L3);
            let mut hw = replacement_new_hardware(Profile::L3, &anchor);
            let (makes, _) =
                replacement_probe(&mut hw, (mode == 0).then(|| Arc::downgrade(&service)));
            {
                let mut a = anchor.0.lock().unwrap();
                match mode {
                    1 => a.advance_revision_on_load = Some(a.loads + 2),
                    2 => a.advance_time_on_load = Some((a.loads + 2, 20_000)),
                    3 => a.revoke_on_load = Some((a.loads + 2, Arc::downgrade(&service))),
                    _ => {}
                }
            }
            assert!(service
                .begin_member_replacement_enrollment_for_test(
                    &PeerCredentials::local(0, 0),
                    || Ok(hw),
                    SystemClock::default().now_ns(),
                    0
                )
                .is_err());
            assert_eq!(makes.load(Ordering::SeqCst), 1);
            assert!(!replacement_capture(&f)["attempts"][0]["pending"].is_null());
            assert!(service.replacement_enrollment_staged_count_for_test() == 0);
            loss_assert_sterile(&service);
        }
    }
    #[test]
    fn member_replacement_enrollment_actual_restart_tamper_and_original_deadline_never_reconstruct_or_refresh_producer_authority(
    ) {
        for mode in 0..3 {
            let (f, anchor, service) = replacement_enrollment_fixture(Profile::L3);
            let start = SystemClock::default()
                .now_ns()
                .saturating_sub(if mode == 2 { 4_000_000_000 } else { 0 });
            let (_, id) = service
                .begin_member_replacement_enrollment_for_test(
                    &PeerCredentials::local(0, 0),
                    || Ok(replacement_new_hardware(Profile::L3, &anchor)),
                    start,
                    0,
                )
                .unwrap();
            let pending = replacement_captured_pending(&f);
            let target = if mode == 0 {
                loss_start(&f, &anchor, Profile::L3).unwrap()
            } else {
                service.clone()
            };
            preparing_code(&target, &anchor, 1);
            let request = preparing_request(&f, &target, &anchor, &pending, id, 9, None, 60, 152);
            if mode == 1 {
                target
                    .handle(
                        &PeerCredentials::local(0, 0),
                        VaultRequest::Tamper(TamperEvent::ScreenLock),
                    )
                    .unwrap();
            }
            if mode == 2 {
                let remaining = (start + crate::ceremony::CEREMONY_BUDGET_NS)
                    .saturating_sub(SystemClock::default().now_ns());
                std::thread::sleep(std::time::Duration::from_nanos(remaining + 1_000_000));
            }
            let error = target
                .handle(&PeerCredentials::local(0, 0), request)
                .unwrap_err();
            assert!(
                error.is(match mode {
                    0 => "REPLACEMENT_ENROLLMENT_EVIDENCE_REQUIRED",
                    1 => "REPLACEMENT_ENROLLMENT_CONTEXT",
                    _ => "REPLACEMENT_ENROLLMENT_EXPIRED",
                }),
                "{error:?}"
            );
            assert_eq!(anchor.0.lock().unwrap().cas, 1);
            assert!(!replacement_capture(&f)["attempts"][0]["pending"].is_null());
            loss_assert_sterile(&target);
        }
    }
    #[test]
    fn member_replacement_enrollment_actual_nonce_store_admin_original_cap_and_pre_factory_revocation_refuse_before_hardware(
    ) {
        for mode in 0..4 {
            let (f, anchor, service) = replacement_enrollment_fixture(Profile::L3);
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            if mode == 2 {
                let dir = f.root.0.join("state/replacement-enrollment-captures");
                enclave_core::fsutil::private_dir(&dir).unwrap();
                std::fs::create_dir(dir.join("attempts.gen")).unwrap();
            }
            if mode == 3 {
                loss_revoke_during_next_observation(&anchor, &service);
            }
            let start = SystemClock::default()
                .now_ns()
                .saturating_sub(if mode == 1 {
                    crate::ceremony::CEREMONY_BUDGET_NS + 1_000_000
                } else {
                    0
                });
            let count = calls.clone();
            let result = service.begin_member_replacement_enrollment_for_test(
                &PeerCredentials::local(if mode == 0 { 65534 } else { 0 }, 0),
                || {
                    count.fetch_add(1, Ordering::SeqCst);
                    Ok(replacement_new_hardware(Profile::L3, &anchor))
                },
                start,
                0,
            );
            assert!(result.is_err());
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(service.replacement_enrollment_staged_count_for_test(), 0);
            assert_eq!(anchor.0.lock().unwrap().cas, 1);
            loss_assert_sterile(&service);
        }
    }

    // These owners retain the SAME synthetic authenticator across actual
    // initializer/full-chain/dual-PRF calls. No saved evidence invents a device.
    #[derive(Clone, Debug)]
    struct FactorDevice(Arc<Mutex<Box<dyn HidDevice + Send>>>);
    impl HidDevice for FactorDevice {
        fn write_report(&mut self, r: &[u8; crate::ctap::hid::REPORT]) -> EnclaveResult<()> {
            self.0.lock().unwrap().write_report(r)
        }
        fn read_report(&mut self) -> EnclaveResult<[u8; crate::ctap::hid::REPORT]> {
            self.0.lock().unwrap().read_report()
        }
        fn hub_depth(&self) -> u8 {
            self.0.lock().unwrap().hub_depth()
        }
        fn bind_selected_instance(&mut self) -> EnclaveResult<()> {
            self.0.lock().unwrap().bind_selected_instance()
        }
        fn deadline_ns(&self) -> Option<u64> {
            self.0.lock().unwrap().deadline_ns()
        }
        fn set_deadline_ns(&mut self, d: Option<u64>) -> EnclaveResult<()> {
            self.0.lock().unwrap().set_deadline_ns(d)
        }
    }
    fn concrete_touch(key: &SimulatedTouchId) -> SimulatedTouchId {
        SimulatedTouchId {
            key: key.key.clone(),
        }
    }
    fn factor_device_count(d: &FactorDevice) -> u32 {
        d.0.lock()
            .unwrap()
            .virtual_authenticator()
            .unwrap()
            .sign_count()
    }
    struct ReplacementFactorFixture {
        f: CutoverFixture,
        anchor: LossAnchor,
        service: Arc<VaultService>,
        request: VaultRequest,
        survivor: SimulatedTouchId,
        new_bio: SimulatedTouchId,
        devices: [FactorDevice; 2],
        hardware: Option<VaultHardware>,
        start: u64,
        credentials: [EnrolledCredential; 2],
        before: [u32; 2],
    }
    fn replacement_factor_fixture(
        profile: Profile,
        target: usize,
        earlier_start: u64,
    ) -> ReplacementFactorFixture {
        let peer = PeerCredentials::local(0, 0);
        let root = Root::new();
        let (service, inventory, authority) = fixture_profile(&root, profile);
        let primary_bio = SimulatedTouchId::new();
        service.lock_ceremony().unwrap().hw.biometric = Box::new(concrete_touch(&primary_bio));
        let pending = match service.begin_asset(&peer).unwrap() {
            VaultResponse::AssetEnrollmentPending { pending } => pending,
            _ => panic!(),
        };
        let issuer = SigningKey::from_bytes(&[63; 32]);
        let transport_expiry = Arc::new(std::sync::atomic::AtomicI64::new(
            enclave_crypto::time::now_unix() + 3600,
        ));
        let (stop, worker) = cas_with_profile(&root, &issuer, transport_expiry.clone(), profile);
        configure_envelope(&service, &root, &issuer);
        service
            .activate_asset(&peer, receipt(&pending, &inventory, 7))
            .unwrap();
        let backup_root = Root::new();
        let (backup_service, _, _) = fixture_profile(&backup_root, profile);
        let backup_bio = SimulatedTouchId::new();
        {
            let mut c = backup_service.lock_ceremony().unwrap();
            c.hw.asset_enrollment_authority = Some(authority.clone());
            c.hw.biometric = Box::new(concrete_touch(&backup_bio));
        }
        let pending = match backup_service.begin_asset(&peer).unwrap() {
            VaultResponse::AssetEnrollmentPending { pending } => pending,
            _ => panic!(),
        };
        let backup = crate::asset_membership::MemberEvidence {
            receipt: receipt(&pending, &inventory, 8),
            pending,
        };
        let Phase::Pending(backup_pending)=open(&backup_root.0.join("state")).unwrap().1.phase else {panic!()};
        let (backup_biometric, backup_device) = {
            let mut c = backup_service.lock_ceremony().unwrap();
            (
                std::mem::replace(&mut c.hw.biometric, Box::new(SimulatedTouchId::new())),
                c.hw.yubikey.take().unwrap(),
            )
        };
        let primary_device = {
            let mut c = service.lock_ceremony().unwrap();
            let device = FactorDevice(Arc::new(Mutex::new(c.hw.yubikey.take().unwrap())));
            c.hw.yubikey = Some(Box::new(device.clone()));
            device
        };
        let backup_device = FactorDevice(Arc::new(Mutex::new(backup_device)));
        let mut f = CutoverFixture {
            root,
            backup_root,
            service,
            backup,
            inventory,
            authority,
            stop,
            worker: Some(worker),
            transport_expiry,
            backup_blob: backup_pending.bio_key_blob,
            backup_biometric: Some(backup_biometric),
            backup_device: Some(Box::new(backup_device.clone())),
        };
        // Registration helper can inspect its boxed authenticator before the
        // shared transport wrapper; register the genuine second root directly.
        let backup_attestation = backup_device
            .0
            .lock()
            .unwrap()
            .virtual_authenticator()
            .unwrap()
            .attestation_key_mds();
        {
            let mut c = f.service.lock_ceremony().unwrap();
            c.hw.mds.as_mut().unwrap().allowlist.entries[0]
                .attestation_public_keys
                .push(backup_attestation);
            let primary = c.hw.yubikey.take().unwrap();
            let backup = f.backup_device.take().unwrap();
            c.hw.membership_devices = Some(MembershipDevices::from_simulated(primary, backup));
            c.hw.biometric = Box::new(MembershipBiometrics {
                members: [
                    Arc::new(Mutex::new(Box::new(concrete_touch(&primary_bio)))),
                    Arc::new(Mutex::new(Box::new(concrete_touch(&backup_bio)))),
                ],
                next: 0,
                order: vec![0, 1],
            });
            c.hw.oidc_provider = Some(Box::new(MembershipIdp {
                calls: 0,
                bad_signature_on: None,
                advance_on_second: None,
            }));
        }
        f.service
            .add_asset_backup(
                &peer,
                f.backup.pending.clone(),
                f.backup.receipt.clone(),
                f.backup_blob.clone(),
            )
            .unwrap();
        let original = open(&f.root.0.join("state")).unwrap().1;
        let now = enclave_crypto::time::now_unix();
        let anchor = LossAnchor(Arc::new(Mutex::new(LossAnchorState {
            pin: MembershipAnchorPin {
                revision: 7,
                workflow_sha256: loss_hash(&original),
            },
            now_ms: now as u64 * 1000,
            cas: 0,
            fail_before: false,
            apply_then_error: false,
            bad_nonce: false,
            readback_fault: false,
            loads: 0,
            advance_revision_on_load: None,
            local_readback_fault: None,
            readback_fault_after: 0,
            advance_time_on_load: None,
            advance_time_before_cas_ms: 0,
            revoke_on_load: None,
        })));
        let mut sterile_hw = VaultHardware::simulated(profile, now).unwrap();
        sterile_hw.simulated = false;
        sterile_hw.asset_enrollment_authority = Some(f.authority.clone());
        let mut factor_hw = replacement_new_hardware(profile, &anchor);
        factor_hw.yubikey = None;
        {
            let mut c = f.service.lock_ceremony().unwrap();
            sterile_hw.sep = std::mem::replace(&mut c.hw.sep, Box::new(SoftwareSep::new()));
            factor_hw.mds = c.hw.mds.clone();
            factor_hw.metadata_source = c.hw.metadata_source.clone();
            factor_hw.envelope_authority = c.hw.envelope_authority.clone();
        }
        let service = VaultService::start_with_membership_authority(
            VaultConfig {
                profile,
                state_dir: Some(f.root.0.join("state")),
                ..Default::default()
            },
            sterile_hw,
            loss_owner(&f, &anchor),
        )
        .unwrap();
        let context = membership_cutover::member_loss_context(
            &f.root.0.join("state"),
            &original,
            &f.authority,
            profile,
            now,
            now,
        )
        .unwrap();
        service
            .handle(
                &peer,
                VaultRequest::RecordMemberLoss {
                    statement: loss_sign(&f, context.bindings[target].clone(), now),
                },
            )
            .unwrap();
        let mut new_hw = replacement_new_hardware(profile, &anchor);
        let new_device = FactorDevice(Arc::new(Mutex::new(new_hw.yubikey.take().unwrap())));
        new_hw.yubikey = Some(Box::new(new_device.clone()));
        let new_bio = SimulatedTouchId::new();
        let survivor = if target == 0 { backup_bio } else { primary_bio };
        let survivor_device = if target == 0 {
            backup_device
        } else {
            primary_device
        };
        factor_hw.membership_devices = Some(MembershipDevices::from_simulated(
            Box::new(survivor_device.clone()),
            Box::new(new_device.clone()),
        ));
        factor_hw.oidc_provider = Some(Box::new(MembershipIdp {
            calls: 0,
            bad_signature_on: None,
            advance_on_second: None,
        }));
        let start = SystemClock::default()
            .now_ns()
            .saturating_sub(earlier_start);
        let (_, id) = service
            .begin_member_replacement_enrollment_with_concrete_fixture(
                &peer,
                || Ok(new_hw),
                start,
                concrete_touch(&new_bio),
            )
            .unwrap();
        let pending = replacement_captured_pending(&f);
        preparing_code(&service, &anchor, 1);
        let submitted = preparing_receipt(&context.pendings[1 - target], &f.inventory, 9, now);
        let request = preparing_request(
            &f,
            &service,
            &anchor,
            &pending,
            id,
            10,
            Some(submitted),
            60,
            163,
        );
        let devices = [survivor_device, new_device];
        let before = [
            factor_device_count(&devices[0]),
            factor_device_count(&devices[1]),
        ];
        ReplacementFactorFixture {
            f,
            anchor,
            service,
            request,
            survivor,
            new_bio,
            devices,
            hardware: Some(factor_hw),
            start,
            credentials: [
                context.members[1 - target].credential.clone(),
                pending.evidence.credential().clone(),
            ],
            before,
        }
    }
    fn factor_request_parts(
        request: &VaultRequest,
    ) -> (
        Vec<u8>,
        [u8; 32],
        AssetEnrollmentReceipt,
        Option<AssetEnrollmentReceipt>,
    ) {
        let VaultRequest::PrepareMemberReplacement {candidate,enrollment_evidence_id,replacement_receipt,survivor_receipt}=request else {panic!()};
        (
            candidate.clone(),
            *enrollment_evidence_id,
            replacement_receipt.clone(),
            survivor_receipt.clone(),
        )
    }
    fn assert_factor_burned(f: &ReplacementFactorFixture) {
        assert_eq!(f.anchor.0.lock().unwrap().cas, 2);
        let ledger = open(&f.f.root.0.join("state")).unwrap().1;
        assert!(matches!(
            ledger.phase,
            Phase::MembershipReplacementPreparing { .. }
        ));
        assert_eq!(ledger.receipt_floor, 10);
        loss_assert_sterile(&f.service);
    }
    fn assert_factor_counters_durable(f: &ReplacementFactorFixture) {
        let (_, loaded) =
            SealedStore::open_required(&f.f.root.0.join("state"), "signcount").unwrap();
        let Loaded::State(bytes)=loaded else {panic!()};
        let disk: crate::ctap::assertion::SignCountStore =
            enclave_core::sealed::decode(&bytes).unwrap();
        assert_eq!(disk, f.service.lock_ceremony().unwrap().counters);
    }
    #[test]
    fn member_replacement_factors_actual_l2_l3_either_survivor_both_fresh_chains_all17_and_original_pool_stay_inactive(
    ) {
        for profile in [Profile::L2, Profile::L3] {
            for target in 0..2 {
                let mut f = replacement_factor_fixture(profile, target, 0);
                let service = f.service.clone();
                let state = f.f.root.0.join("state");
                let original =
                    std::fs::read(state.join("vault-envelopes/envelopes.sealed")).unwrap();
                let names = checkpoint_names(&state);
                let (candidate, id, receipt, survivor) = factor_request_parts(&f.request);
                let mut hardware = f.hardware.take().unwrap();
                let private_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                hardware.biometric = Box::new(PreparingNoPrivate(private_calls.clone()));
                hardware.sep = Box::new(PreparingNoPrivate(private_calls.clone()));
                let verified = service
                    .verify_member_replacement_with_concrete_fixtures(
                        &PeerCredentials::local(0, 0),
                        &candidate,
                        id,
                        receipt,
                        survivor,
                        [concrete_touch(&f.survivor), concrete_touch(&f.new_bio)],
                        || Ok(hardware),
                    )
                    .unwrap();
                let (_, start, deadline) = verified.test_window();
                assert_eq!(start, f.start);
                assert!(deadline <= start + crate::ceremony::CEREMONY_BUDGET_NS);
                assert_eq!(private_calls.load(Ordering::SeqCst), 0);
                assert!(!format!("{verified:?}").contains("synthetic"));
                drop(verified);
                for i in 0..2 {
                    assert_eq!(factor_device_count(&f.devices[i]), f.before[i] + 2);
                    assert_eq!(
                        service
                            .lock_ceremony()
                            .unwrap()
                            .counters
                            .get_credential(&f.credentials[i]),
                        f.before[i] + 2
                    );
                }
                assert_factor_counters_durable(&f);
                assert_factor_burned(&f);
                assert_eq!(
                    std::fs::read(state.join("vault-envelopes/envelopes.sealed")).unwrap(),
                    original
                );
                assert_eq!(checkpoint_names(&state), names);
                loss_assert_sterile(&loss_start(&f.f, &f.anchor, profile).unwrap());
            }
        }
    }
    #[test]
    fn member_replacement_factors_actual_late_second_chain_mapping_and_wrong_original_sep_failures_burn_and_retain_advances(
    ) {
        for mode in 0..4 {
            let mut f = replacement_factor_fixture(Profile::L3, mode % 2, 0);
            let service = f.service.clone();
            let mut hardware = f.hardware.take().unwrap();
            if mode == 0 {
                hardware.oidc_provider = Some(Box::new(MembershipIdp {
                    calls: 0,
                    bad_signature_on: Some(1),
                    advance_on_second: None,
                }));
            }
            if mode == 1 {
                hardware.membership_devices = Some(MembershipDevices::from_simulated(
                    Box::new(f.devices[1].clone()),
                    Box::new(f.devices[0].clone()),
                ));
            }
            if mode == 3 {
                service.lock_ceremony().unwrap().hw.sep = Box::new(SoftwareSep::new());
            }
            let bios = [
                concrete_touch(&f.survivor),
                if mode == 2 {
                    SimulatedTouchId::new()
                } else {
                    concrete_touch(&f.new_bio)
                },
            ];
            let (candidate, id, receipt, survivor) = factor_request_parts(&f.request);
            assert!(service
                .verify_member_replacement_with_concrete_fixtures(
                    &PeerCredentials::local(0, 0),
                    &candidate,
                    id,
                    receipt,
                    survivor,
                    bios,
                    || Ok(hardware)
                )
                .is_err());
            assert_factor_burned(&f);
            assert_factor_counters_durable(&f);
            if mode != 1 {
                assert_eq!(
                    service
                        .lock_ceremony()
                        .unwrap()
                        .counters
                        .get_credential(&f.credentials[0]),
                    f.before[0] + 2
                );
            }
            if mode == 3 {
                assert_eq!(
                    service
                        .lock_ceremony()
                        .unwrap()
                        .counters
                        .get_credential(&f.credentials[1]),
                    f.before[1] + 2
                );
            }
        }
    }
    #[test]
    fn member_replacement_factors_actual_independent_expiry_and_revocation_after_first_chain_keep_first_counters_and_burn(
    ) {
        for revoke in [false, true] {
            let mut f = replacement_factor_fixture(Profile::L3, 0, 0);
            let service = f.service.clone();
            let hardware = f.hardware.take().unwrap();
            let (candidate, id, receipt, survivor) = factor_request_parts(&f.request);
            assert!(service
                .verify_member_replacement_with_concrete_fixtures(
                    &PeerCredentials::local(0, 0),
                    &candidate,
                    id,
                    receipt,
                    survivor,
                    [concrete_touch(&f.survivor), concrete_touch(&f.new_bio)],
                    || {
                        let mut a = f.anchor.0.lock().unwrap();
                        let next = a.loads + 2;
                        if revoke {
                            a.revoke_on_load = Some((next, Arc::downgrade(&service)));
                        } else {
                            a.advance_time_on_load = Some((next, 20_000));
                        }
                        Ok(hardware)
                    }
                )
                .is_err());
            assert_factor_burned(&f);
            assert_factor_counters_durable(&f);
            assert_eq!(
                service
                    .lock_ceremony()
                    .unwrap()
                    .counters
                    .get_credential(&f.credentials[0]),
                f.before[0] + 2
            );
            assert_eq!(
                service
                    .lock_ceremony()
                    .unwrap()
                    .counters
                    .get_credential(&f.credentials[1]),
                0
            );
        }
    }
    #[test]
    fn member_replacement_factors_actual_rpc_ack_and_restart_never_reconstruct_live_burn_or_invoke_factory(
    ) {
        for restart in [false, true] {
            let f = replacement_factor_fixture(Profile::L3, 1, 0);
            f.service
                .handle(&PeerCredentials::local(0, 0), f.request.clone())
                .unwrap();
            let service = if restart {
                loss_start(&f.f, &f.anchor, Profile::L3).unwrap()
            } else {
                f.service.clone()
            };
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let count = calls.clone();
            let (candidate, id, receipt, survivor) = factor_request_parts(&f.request);
            assert!(service
                .verify_member_replacement_with_concrete_fixtures(
                    &PeerCredentials::local(0, 0),
                    &candidate,
                    id,
                    receipt,
                    survivor,
                    [concrete_touch(&f.survivor), concrete_touch(&f.new_bio)],
                    || {
                        count.fetch_add(1, Ordering::SeqCst);
                        panic!("inert ACK cannot invoke factor hardware")
                    }
                )
                .is_err());
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(f.anchor.0.lock().unwrap().cas, 2);
            loss_assert_sterile(&service);
        }
    }
    #[test]
    fn member_replacement_factors_actual_native_helper_ignores_factory_biometric_sep_and_missing_socket_never_falls_back(
    ) {
        let mut f = replacement_factor_fixture(Profile::L3, 0, 0);
        let service = f.service.clone();
        let mut hardware = f.hardware.take().unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        hardware.biometric = Box::new(PreparingNoPrivate(calls.clone()));
        hardware.sep = Box::new(PreparingNoPrivate(calls.clone()));
        let (candidate, id, receipt, survivor) = factor_request_parts(&f.request);
        assert!(service
            .verify_member_replacement_with_factory(
                &PeerCredentials::local(0, 0),
                &candidate,
                id,
                receipt,
                survivor,
                crate::biometric::IntentHelperProvider::new(
                    f.f.root.0.join("absent-factor-helper.sock")
                ),
                || Ok(hardware)
            )
            .is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_factor_burned(&f);
        assert_factor_counters_durable(&f);
        assert_eq!(factor_device_count(&f.devices[0]), f.before[0]);
        assert_eq!(factor_device_count(&f.devices[1]), f.before[1]);
    }
    #[test]
    fn member_replacement_factors_actual_original_deadline_and_counter_save_fault_never_return_a_result_or_roll_back_burn(
    ) {
        for fault in [false, true] {
            let mut f =
                replacement_factor_fixture(Profile::L3, 1, if fault { 0 } else { 4_000_000_000 });
            let service = f.service.clone();
            let hardware = f.hardware.take().unwrap();
            let (candidate, id, receipt, survivor) = factor_request_parts(&f.request);
            assert!(service
                .verify_member_replacement_with_concrete_fixtures(
                    &PeerCredentials::local(0, 0),
                    &candidate,
                    id,
                    receipt,
                    survivor,
                    [concrete_touch(&f.survivor), concrete_touch(&f.new_bio)],
                    || {
                        if fault {
                            let path = f.f.root.0.join("state/signcount.gen");
                            std::fs::remove_file(&path).unwrap();
                            std::fs::create_dir(path).unwrap();
                        } else {
                            let remaining = (f.start + crate::ceremony::CEREMONY_BUDGET_NS)
                                .saturating_sub(SystemClock::default().now_ns());
                            std::thread::sleep(std::time::Duration::from_nanos(
                                remaining + 1_000_000,
                            ));
                        }
                        Ok(hardware)
                    }
                )
                .is_err());
            assert_factor_burned(&f);
            if !fault {
                assert_eq!(factor_device_count(&f.devices[0]), f.before[0]);
                assert_factor_counters_durable(&f);
            }
        }
    }

    #[test]
    fn member_replacement_factors_actual_l3_each_assertion_gets_fresh_existing_pin_and_l2_never_calls_pin(
    ) {
        for profile in [Profile::L2, Profile::L3] {
            let mut f = replacement_factor_fixture(profile, 1, 0);
            let service = f.service.clone();
            let mut hardware = f.hardware.take().unwrap();
            for device in &f.devices {
                let mut owner = device.0.lock().unwrap();
                let dev = owner.virtual_authenticator().unwrap();
                dev.uv_capable = false;
                dev.configure_synthetic_pin(b"synthetic-enrollment-pin");
            }
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            hardware.existing_pin = Some(Box::new(ReplacementPin {
                calls: calls.clone(),
                allowed: profile == Profile::L3,
            }));
            let (candidate, id, receipt, survivor) = factor_request_parts(&f.request);
            service
                .verify_member_replacement_with_concrete_fixtures(
                    &PeerCredentials::local(0, 0),
                    &candidate,
                    id,
                    receipt,
                    survivor,
                    [concrete_touch(&f.survivor), concrete_touch(&f.new_bio)],
                    || Ok(hardware),
                )
                .unwrap();
            assert_eq!(
                calls.load(Ordering::SeqCst),
                if profile == Profile::L3 { 4 } else { 0 }
            );
            for i in 0..2 {
                assert_eq!(factor_device_count(&f.devices[i]), f.before[i] + 2);
            }
            assert_factor_counters_durable(&f);
            assert_factor_burned(&f);
        }
    }
}
