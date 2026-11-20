//! ADR-007 / ADR-009 dual-key custody vault.
//!
//! **Ingress (`Tokenize`, airplane-safe, zero prompts):**
//! * PANs and credentials → irreversibly erased in every profile; never sealed.
//! * SSN / PHI (`C4`) → erased by default and **always in `L1`**; in `L2`/`L3`
//!   only with a valid Cedar `Custody::ReversibleTokenize` grant they become a
//!   MAC-tagged collision-resistant `SYNTH-*` surrogate sealed under `Envelope_A4`.
//! * `C3` identifiers → random surrogates sealed under `Envelope_A3` (single
//!   row) — or under `Envelope_A4` when they belong to a bulk (`> 1` row) set.
//!
//! **Egress (`Detokenize`, `A3`/`A4` ceremony):** the single-use grant must be
//! bound to the intent's `d_JCS`; only the tier the grant authorises is
//! unwrapped (`A3` ⇒ exactly one row of `A3` entries; `A4` ⇒ any `A4` entries
//! up to `row_count_bound`); the tier key is zeroized immediately after.
//! Plaintext is returned to the trusted UI, never into model context.

use std::collections::{BTreeMap, HashMap};

use ed25519_dalek::{Signature, VerifyingKey};
use enclave_core::error::EnclaveResult;
use enclave_core::profile::{ActionClass, Profile};
use enclave_core::secret::{SecretBytes, SecretKey32};
use enclave_core::{err, fail};
use enclave_crypto::hpke_envelope::{
    open, unwrap_tier, EnvelopeA3, EnvelopeA4, KekShares, SealedValue, A3, A3_MAX_SEALS_PER_EPOCH,
    A4, A3Checkpoint, WrappedTierKey, VerifiedEnvelopeContext, UnwrappedTierKey, verify_tier_wrapping, ENVELOPE_VERSION, HYBRID_SUITE,
};
use serde::{Deserialize, Serialize};

use crate::ceremony::CeremonyGrant;
use crate::intent::IntentPayloadV1;
use crate::pii::{classify, scan, PiiKind};

/// A Cedar `Custody::ReversibleTokenize` grant issued by UID 704.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReversibleTokenizeGrant {
    /// Named workflow.
    pub workflow: String,
    /// Profile the grant applies to.
    pub profile: Profile,
    /// Expiry (Unix seconds).
    pub expires_unix: i64,
    /// Ed25519 signature by UID 704's policy key over [`ReversibleTokenizeGrant::message`].
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl ReversibleTokenizeGrant {
    /// Signed message.
    pub fn message(workflow: &str, profile: Profile, expires_unix: i64) -> Vec<u8> {
        format!("MCPMac-Custody::ReversibleTokenize-v1\0{workflow}\0{profile}\0{expires_unix}")
            .into_bytes()
    }
    /// Verify.
    pub fn verify(&self, key: &VerifyingKey, profile: Profile, now: i64) -> EnclaveResult<()> {
        if self.profile != profile || profile == Profile::L1 {
            fail!(
                EPERM,
                "REVERSIBLE_TOKENIZE_NOT_PERMITTED",
                "ADR-007: L1 never vaults C4"
            );
        }
        if now >= self.expires_unix {
            fail!(ESTALE, "GRANT_EXPIRED");
        }
        let sig =
            Signature::from_slice(&self.signature).map_err(|_| err!(EACCES, "GRANT_SIGNATURE"))?;
        key.verify_strict(
            &Self::message(&self.workflow, self.profile, self.expires_unix),
            &sig,
        )
        .map_err(|_| {
            err!(
                EACCES,
                "GRANT_SIGNATURE",
                "not issued by the UID 704 policy key"
            )
        })
    }
}

/// Which tier holds an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StoredTier {
    /// `Envelope_A3`.
    A3,
    /// `Envelope_A4`.
    A4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEntry {
    tier: StoredTier,
    kind: PiiKind,
    sealed: SealedValue,
    aad: Vec<u8>,
}

/// Result of tokenizing one value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenOutput {
    /// The replacement string (surrogate or erasure token).
    pub token: String,
    /// Detected kind.
    pub kind: Option<PiiKind>,
    /// Whether a reversible ciphertext was stored.
    pub reversible: bool,
    /// Tier if stored.
    pub tier: Option<StoredTier>,
}

/// Zero-PII ingress counters (audit receipts).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressStats {
    /// Erased count by kind.
    pub erased: BTreeMap<String, u64>,
    /// Sealed count by tier.
    pub sealed_a3: u64,
    /// Sealed under A4.
    pub sealed_a4: u64,
}

/// Authenticated, rollback-checked restart state. Contains public/wrapped tier keys
/// and ciphertexts, never raw factors, tier private keys or the surrogate MAC seed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultEnvelopeCheckpoint {
    version: u32,
    profile: Profile,
    session_id: [u8;16],
    a3_pool: Vec<A3Checkpoint>,
    a3_current: usize,
    a4: WrappedTierKey,
    store: BTreeMap<String, StoredEntry>,
    stats: IngressStats,
    enrolled: bool,
    policy_revision: u64,
    policy_digest: [u8;32],
}

impl VaultEnvelopeCheckpoint {
    /// Public pool identity and immutable wrappers for an additional credential.
    /// This is not enrollment/admission and never changes the existing version2
    /// activation binding. A future membership ledger must bind the staged set.
    pub(crate) fn backup_source(&self,context:&VerifiedEnvelopeContext,now:i64)
        ->EnclaveResult<crate::backup_envelope::BackupSource> {
        context.admit(self.profile,"C3",now,false)?;context.admit(self.profile,"C4",now,false)?;
        if self.version!=ENVELOPE_VERSION||!self.enrolled||self.profile==Profile::L1
            ||self.policy_revision!=context.revision()||self.policy_digest!=context.digest()
            ||self.a3_pool.len()!=A3_EPOCHS_PER_ENROLLMENT as usize||self.a3_current>=self.a3_pool.len() {
            fail!(EACCES,"BACKUP_SOURCE_SCOPE");
        }
        let mut a3=Vec::with_capacity(self.a3_pool.len());
        for (i,epoch) in self.a3_pool.iter().enumerate() {
            if epoch.wrapped.epoch!=i as u32||epoch.wrapped.context!=self.policy_digest
                ||(i<self.a3_current&&epoch.sealed_this_epoch!=A3_MAX_SEALS_PER_EPOCH)
                ||(i>self.a3_current&&epoch.sealed_this_epoch!=0) {fail!(EACCES,"BACKUP_SOURCE_SCOPE");}
            EnvelopeA3::restore(epoch.clone())?;a3.push(epoch.wrapped.clone());
        }
        if self.a4.epoch!=0||self.a4.context!=self.policy_digest {fail!(EACCES,"BACKUP_SOURCE_SCOPE");}
        EnvelopeA4::restore(self.a4.clone())?;
        #[derive(Serialize)]
        struct Pool<'a> {domain:&'static str,version:u32,profile:Profile,session_id:[u8;16],
            policy_revision:u64,policy_digest:[u8;32],a3:Vec<(u32,&'a [u8])>,a4:&'a [u8]}
        let public=Pool {domain:"MCPMac-BackupContentPool-v1",version:self.version,profile:self.profile,
            session_id:self.session_id,policy_revision:self.policy_revision,policy_digest:self.policy_digest,
            a3:a3.iter().map(|key|(key.epoch,key.public_key.as_slice())).collect(),a4:&self.a4.public_key};
        let pool_digest=*blake3::hash(&enclave_core::jcs::to_jcs_bytes(&public)?).as_bytes();
        Ok(crate::backup_envelope::BackupSource {profile:self.profile,policy_revision:self.policy_revision,
            policy_digest:self.policy_digest,pool_digest,a3,a4:self.a4.clone()})
    }

    /// Prove current separate factor shares can unwrap every retained tier.
    /// The temporary private tier owners drop here; public restore alone does
    /// not establish compatibility with a fresh hardware ceremony.
    pub fn verify_factor_shares(&self,a3:&KekShares<'_>,a4:&KekShares<'_>)->EnclaveResult<()> {
        if !self.enrolled||self.a3_pool.len()!=A3_EPOCHS_PER_ENROLLMENT as usize {fail!(EACCES,"ASSET_STAGED_ENVELOPE_FACTORS");}
        for epoch in &self.a3_pool {drop(unwrap_tier::<A3>(&epoch.wrapped,a3)?);}
        drop(unwrap_tier::<A4>(&self.a4,a4)?);Ok(())
    }
    /// Stable public enrollment identity; ciphertext/count updates cannot alter
    /// it. Binds atomic asset activation to exact independent tier key pools.
    pub fn enrollment_binding(&self)->EnclaveResult<[u8;32]> {
        #[derive(Serialize)]
        struct Identity<'a> {version:u32,profile:Profile,session_id:[u8;16],a3:Vec<&'a WrappedTierKey>,a4:&'a WrappedTierKey,policy_digest:[u8;32]}
        let identity=Identity {version:self.version,profile:self.profile,session_id:self.session_id,
            a3:self.a3_pool.iter().map(|epoch|&epoch.wrapped).collect(),a4:&self.a4,policy_digest:self.policy_digest};
        Ok(*blake3::hash(&enclave_core::jcs::to_jcs_bytes(&identity)?).as_bytes())
    }
}

/// The vault.
#[derive(Debug)]
pub struct CustodyVault {
    profile: Profile,
    mac_key: SecretKey32,
    persistent_mac_seed: Option<SecretKey32>,
    envelope_context: Option<VerifiedEnvelopeContext>,
    session_id: [u8; 16],
    a3_pool: Vec<EnvelopeA3>,
    a3_current: usize,
    a4: EnvelopeA4,
    // Runtime selection only. Primary wrappers remain the sole serialized v2
    // content checkpoint, including while the backup serves fresh actions.
    backup_projection: Option<crate::backup_envelope::BackupProjection>,
    store: HashMap<String, StoredEntry>,
    store_bytes: usize,
    max_entries: usize,
    max_bytes: usize,
    grant_key: Option<VerifyingKey>,
    /// Ingress statistics.
    pub stats: IngressStats,
    enrolled: bool,
}

/// Number of pre-generated `A3` epochs per enrollment (each seals <= 64).
pub const A3_EPOCHS_PER_ENROLLMENT: u32 = 16;
/// Hard reversible-entry count. No silent eviction of live surrogate data.
pub const MAX_VAULT_ENTRIES: usize = 4096;
/// Ciphertext/key/AAD accounting cap, including a conservative per-entry overhead.
pub const MAX_VAULT_BYTES: usize = 8 * 1024 * 1024;

impl CustodyVault {
    /// Morning enrollment: generate `A3` epoch keys and the `A4` key, each
    /// wrapped under its tier KEK. Only public keys stay resident.
    pub fn enroll(
        profile: Profile,
        a3: &KekShares<'_>,
        a4: &KekShares<'_>,
        grant_key: Option<VerifyingKey>,
    ) -> EnclaveResult<Self> {
        let a3_pool = (0..A3_EPOCHS_PER_ENROLLMENT)
            .map(|e| EnvelopeA3::new(e, a3))
            .collect::<EnclaveResult<Vec<_>>>()?;
        let a4 = EnvelopeA4::new(0, a4)?;
        let mut session_id = [0u8; 16];
        enclave_core::rng::fill(&mut session_id);
        Ok(Self {
            profile,
            mac_key: SecretKey32::random(),
            persistent_mac_seed: None,
            envelope_context: None,
            session_id,
            a3_pool,
            a3_current: 0,
            a4,
            backup_projection: None,
            store: HashMap::new(),
            store_bytes: 0,
            max_entries: MAX_VAULT_ENTRIES,
            max_bytes: MAX_VAULT_BYTES,
            grant_key,
            stats: IngressStats::default(),
            enrolled: true,
        })
    }

    /// Create an unenrolled vault: holds placeholder envelopes and rejects all
    /// operations with `ENROLLMENT_REQUIRED` until enrolled.
    pub fn unenrolled(profile: Profile, grant_key: Option<VerifyingKey>) -> Self {
        let dummy = KekShares {
            sep_ecdh_share: &[0u8; 32],
            yubikey_prf: &[0u8; 32],
        };
        let a3_pool = vec![EnvelopeA3::new(0, &dummy).unwrap()];
        let a4 = EnvelopeA4::new(0, &dummy).unwrap();
        let mut session_id = [0u8; 16];
        enclave_core::rng::fill(&mut session_id);
        Self {
            profile,
            mac_key: SecretKey32::random(),
            persistent_mac_seed: None,
            envelope_context: None,
            session_id,
            a3_pool,
            a3_current: 0,
            a4,
            backup_projection: None,
            store: HashMap::new(),
            store_bytes: 0,
            max_entries: MAX_VAULT_ENTRIES,
            max_bytes: MAX_VAULT_BYTES,
            grant_key,
            stats: IngressStats::default(),
            enrolled: false,
        }
    }

    /// Whether this vault is currently enrolled and active.
    pub fn is_enrolled(&self) -> bool {
        self.enrolled
    }

    /// Complete enrollment after ceremony.
    pub fn reenroll(&mut self, a3: &KekShares<'_>, a4: &KekShares<'_>) -> EnclaveResult<()> {
        // Never orphan live ciphertexts; migration or explicit wipe must precede replacement.
        if !self.store.is_empty() { fail!(EACCES, "REENROLL_LIVE_DATA_REQUIRES_MIGRATION"); }
        let a3_pool = (0..A3_EPOCHS_PER_ENROLLMENT)
            .map(|e| match &self.envelope_context {
                Some(context) => EnvelopeA3::new_bound(e, a3, context),
                None => EnvelopeA3::new(e, a3),
            }).collect::<EnclaveResult<Vec<_>>>()?;
        let a4 = match &self.envelope_context {
            Some(context) => EnvelopeA4::new_bound(0, a4, context)?,
            None => EnvelopeA4::new(0, a4)?,
        };
        // Commit only once both complete independent pools are ready.
        self.a3_pool = a3_pool;
        self.a4 = a4;
        self.backup_projection = None;
        self.a3_current = 0;
        self.enrolled = true;
        Ok(())
    }

    /// Enroll under independently signed subject/namespace policy, using a host-local
    /// stable surrogate seed. Callers must checkpoint before publishing any token.
    pub fn enroll_authorized(profile: Profile, a3: &KekShares<'_>, a4: &KekShares<'_>,
        grant_key: Option<VerifyingKey>, context: &VerifiedEnvelopeContext,
        surrogate_seed: SecretKey32, now: i64) -> EnclaveResult<Self> {
        context.admit(profile, "C3", now, false)?;
        let a3_pool = (0..A3_EPOCHS_PER_ENROLLMENT)
            .map(|e| EnvelopeA3::new_bound(e, a3, context))
            .collect::<EnclaveResult<Vec<_>>>()?;
        let a4 = EnvelopeA4::new_bound(0, a4, context)?;
        let mut session_id = [0u8;16]; enclave_core::rng::fill(&mut session_id);
        let mac_key = Self::derive_surrogate_mac(&surrogate_seed, &session_id);
        Ok(Self { profile, mac_key, persistent_mac_seed: Some(surrogate_seed),
            envelope_context: Some(context.clone()), session_id, a3_pool, a3_current: 0, a4, backup_projection: None,
            store: HashMap::new(), store_bytes: 0, max_entries: MAX_VAULT_ENTRIES,
            max_bytes: MAX_VAULT_BYTES, grant_key, stats: IngressStats::default(), enrolled: true })
    }

    fn derive_surrogate_mac(seed: &SecretKey32, session_id: &[u8;16]) -> SecretKey32 {
        let mut message = b"MCPMac-CustodySurrogateSession-v1\0".to_vec();
        message.extend_from_slice(session_id); SecretKey32::new(seed.mac(&message))
    }

    /// Adopt a newly authenticated transport window for the exact same signed
    /// policy. This refresh changes no key, ciphertext or checkpoint identity;
    /// callers retain the older deadline in every already issued grant/lease.
    pub(crate) fn refresh_authorized_context(&mut self,context:&VerifiedEnvelopeContext,now:i64)->EnclaveResult<()> {
        let old=self.envelope_context.as_ref().ok_or_else(||err!(EACCES,"ENVELOPE_POLICY_REQUIRED"))?;
        if old.digest()!=context.digest()||old.revision()!=context.revision() {fail!(ESTALE,"ENVELOPE_POLICY_CHANGED_MIGRATION_REQUIRED");}
        context.admit(self.profile,"C3",now,false)?;context.admit(self.profile,"C4",now,false)?;
        self.envelope_context=Some(context.clone());Ok(())
    }

    /// Persist only through an authenticated rollback-checked store. The result has
    /// no plaintext PII or private tier key. The MAC seed is separately protected.
    pub fn checkpoint(&self) -> EnclaveResult<VaultEnvelopeCheckpoint> {
        let mut checkpoint=self.key_checkpoint()?;
        checkpoint.store=self.store.iter().map(|(k,v)|(k.clone(),v.clone())).collect();
        Ok(checkpoint)
    }

    // Only public/wrapped key identity and seal counts. Keeping this private
    // avoids copying the entire retained ciphertext store for a capsule scope;
    // only checkpoint() may expose the complete persistent snapshot.
    fn key_checkpoint(&self)->EnclaveResult<VaultEnvelopeCheckpoint> {
        let context = self.envelope_context.as_ref().ok_or_else(||err!(EACCES,"ENVELOPE_POLICY_REQUIRED"))?;
        if self.persistent_mac_seed.is_none() { fail!(EACCES,"SURROGATE_SEED_REQUIRED"); }
        Ok(VaultEnvelopeCheckpoint { version: ENVELOPE_VERSION, profile: self.profile,
            session_id: self.session_id, a3_pool: self.a3_pool.iter().map(EnvelopeA3::checkpoint).collect(),
            a3_current: self.a3_current, a4: self.a4.wrapped().clone(),
            store: BTreeMap::new(), stats: self.stats.clone(),
            enrolled: self.enrolled, policy_revision: context.revision(), policy_digest: context.digest() })
    }

    /// Restore sealing-only operation without SEP/CTAP, after authenticating policy
    /// and the durable checkpoint. This does not unwrap any private tier key.
    pub fn restore_authorized(checkpoint: VaultEnvelopeCheckpoint, profile: Profile,
        grant_key: Option<VerifyingKey>, context: &VerifiedEnvelopeContext,
        surrogate_seed: SecretKey32, now: i64) -> EnclaveResult<Self> {
        context.admit(profile, "C3", now, false)?;
        if checkpoint.version != ENVELOPE_VERSION || checkpoint.profile != profile
            || checkpoint.policy_revision != context.revision() || checkpoint.policy_digest != context.digest()
            || checkpoint.a3_pool.len() != A3_EPOCHS_PER_ENROLLMENT as usize
            || checkpoint.a3_current >= checkpoint.a3_pool.len() || !checkpoint.enrolled
            || checkpoint.store.len() > MAX_VAULT_ENTRIES { fail!(EACCES,"VAULT_CHECKPOINT_SCOPE"); }
        for (i,c) in checkpoint.a3_pool.iter().enumerate() {
            if c.wrapped.epoch != i as u32 || c.wrapped.context != context.digest()
                || (i < checkpoint.a3_current && c.sealed_this_epoch != A3_MAX_SEALS_PER_EPOCH)
                || (i > checkpoint.a3_current && c.sealed_this_epoch != 0) {
                fail!(EACCES,"VAULT_CHECKPOINT_EPOCH");
            }
        }
        if checkpoint.a4.epoch != 0 || checkpoint.a4.context != context.digest() { fail!(EACCES,"VAULT_CHECKPOINT_EPOCH"); }
        let a3_pool = checkpoint.a3_pool.into_iter().map(EnvelopeA3::restore).collect::<EnclaveResult<Vec<_>>>()?;
        let a4 = EnvelopeA4::restore(checkpoint.a4)?;
        let mac_key = Self::derive_surrogate_mac(&surrogate_seed, &checkpoint.session_id);
        let mut vault = Self { profile, mac_key, persistent_mac_seed: Some(surrogate_seed),
            envelope_context: Some(context.clone()), session_id: checkpoint.session_id,
            a3_pool, a3_current: checkpoint.a3_current, a4, backup_projection: None, store: HashMap::new(), store_bytes: 0,
            max_entries: MAX_VAULT_ENTRIES, max_bytes: MAX_VAULT_BYTES, grant_key,
            stats: checkpoint.stats, enrolled: true };
        let mut epoch_entries = [0u32; A3_EPOCHS_PER_ENROLLMENT as usize];
        for (token, entry) in checkpoint.store {
            vault.verify_surrogate(&token)?;
            let sealed = &entry.sealed;
            let valid_kind = match entry.tier {
                StoredTier::A3 => { !entry.kind.is_c4() && sealed.tier == "A3" && (sealed.epoch as usize) < vault.a3_pool.len() },
                StoredTier::A4 => sealed.tier == "A4" && sealed.epoch == 0 && !(profile == Profile::L1 && entry.kind.is_c4()),
            };
            if !valid_kind || matches!(entry.kind, PiiKind::Pan | PiiKind::Credential)
                || entry.aad != vault.aad(&token) || sealed.version != ENVELOPE_VERSION || sealed.suite != HYBRID_SUITE
                || sealed.context != context.digest() || sealed.enc.len() != enclave_crypto::pqc::HYBRID_KEM_CIPHERTEXT_SIZE
                || sealed.ct.len() < 16 { fail!(EACCES,"VAULT_CHECKPOINT_ENTRY"); }
            if entry.kind.is_c4() { context.admit(profile, "C4", now, false)?; }
            if entry.tier == StoredTier::A3 { epoch_entries[sealed.epoch as usize] += 1; }
            vault.insert_unique(token, entry)?;
        }
        for (i,n) in epoch_entries.iter().enumerate() {
            if *n > vault.a3_pool[i].sealed_this_epoch() { fail!(EACCES,"VAULT_CHECKPOINT_COUNT"); }
        }
        Ok(vault)
    }

    fn admitted_backup_projection(&self,membership:&crate::service::ValidatedNativeMembership,
        context:&VerifiedEnvelopeContext,now:i64)->EnclaveResult<crate::backup_envelope::BackupProjection> {
        let checkpoint=self.checkpoint()?;
        if checkpoint.enrollment_binding()?!=membership.source_binding()
            ||membership.checkpoint().enrollment_binding()?!=membership.source_binding() {
            fail!(EACCES,"BACKUP_MEMBERSHIP_SOURCE");
        }
        let primary=membership.enrolled(0)?;let backup=membership.enrolled(1)?;
        membership.backup_wrappers().public_projection(&checkpoint,&primary.credential,&backup.credential,context,now)
    }

    /// Install only the current opaque validated committed member's alternate
    /// wrapped keys. No private tier key/factor is retained. Each action still
    /// needs its existing fresh grant and proves actual selected-tier possession.
    pub(crate) fn select_backup_member(&mut self,membership:&crate::service::ValidatedNativeMembership,
        context:&VerifiedEnvelopeContext,now:i64)->EnclaveResult<()> {
        let projection=self.admitted_backup_projection(membership,context,now)?;
        self.backup_projection=Some(projection);Ok(())
    }

    /// Select the primary of the same validated current committed membership.
    /// Old leases/grants are fenced by the service before changing selection.
    pub(crate) fn select_primary_member(&mut self,membership:&crate::service::ValidatedNativeMembership,
        context:&VerifiedEnvelopeContext,now:i64)->EnclaveResult<()> {
        self.admitted_backup_projection(membership,context,now)?;
        self.backup_projection=None;Ok(())
    }

    fn unwrap_selected_a3(&self,epoch:u32,shares:&KekShares<'_>)->EnclaveResult<UnwrappedTierKey<A3>> {
        let primary=self.a3_pool.iter().find(|key|key.public_key().epoch()==epoch)
            .ok_or_else(||err!(ESTALE,"A3_EPOCH_RETIRED"))?;
        let wrapped=match &self.backup_projection {Some(backup)=>backup.a3(epoch)?,None=>primary.wrapped()};
        // A stored alternate must prove its actual ML-KEM decapsulation part,
        // not merely the matching embedded public fields. Never fall back to
        // primary after a backup factor/possession error.
        if self.backup_projection.is_some() {verify_tier_wrapping::<A3>(wrapped,shares)?;}
        unwrap_tier::<A3>(wrapped,shares)
    }
    fn unwrap_selected_a4(&self,shares:&KekShares<'_>)->EnclaveResult<UnwrappedTierKey<A4>> {
        let wrapped=match &self.backup_projection {Some(backup)=>backup.a4(),None=>self.a4.wrapped()};
        if self.backup_projection.is_some() {verify_tier_wrapping::<A4>(wrapped,shares)?;}
        unwrap_tier::<A4>(wrapped,shares)
    }

    fn namespace_capsule_scope(&self,context:&VerifiedEnvelopeContext,now:i64)
        ->EnclaveResult<crate::namespace_capsule::NamespaceCapsuleScope> {
        use sha2::Digest;
        let checkpoint=self.key_checkpoint()?;let source=checkpoint.backup_source(context,now)?;
        Ok(crate::namespace_capsule::NamespaceCapsuleScope {profile:self.profile,
            policy_revision:source.policy_revision,policy_digest:source.policy_digest,
            source_binding:checkpoint.enrollment_binding()?,pool_digest:source.pool_digest,
            a4_public_sha256:sha2::Sha256::digest(&source.a4.public_key).into()})
    }

    /// Encrypted staging only. The parent must atomically register this with
    /// the exact canonical envelope under current factors/membership/fences.
    /// Only the existing public A4 key is used; no shared tier secret escapes.
    pub(crate) fn seal_namespace_kek(&self,canonical:&enclave_crypto::namespace::WrappedNamespaceKey,
        kek:&SecretKey32,context:&VerifiedEnvelopeContext,now:i64)
        ->EnclaveResult<crate::namespace_capsule::NamespaceKekCapsule> {
        let expected=self.namespace_capsule_scope(context,now)?;
        crate::namespace_capsule::NamespaceKekCapsule::seal_checked(&self.a4,&expected,canonical,kek,context,now)
    }

    /// Public scope validation grants no authority and performs no private
    /// operation. Missing/mismatched capsules never select a legacy fallback.
    pub(crate) fn validate_namespace_kek_capsule(&self,capsule:&crate::namespace_capsule::NamespaceKekCapsule,
        canonical:&enclave_crypto::namespace::WrappedNamespaceKey,context:&VerifiedEnvelopeContext,now:i64)
        ->EnclaveResult<()> {
        capsule.validate(&self.namespace_capsule_scope(context,now)?,canonical,context,now)
    }

    /// Parent supplies fresh authorized shares for the CURRENT selected
    /// member. This fixed-purpose open returns only the exact canonical KEK;
    /// it cannot expose an A4 tier key or decrypt caller-selected plaintext.
    pub(crate) fn open_namespace_kek(&self,capsule:&crate::namespace_capsule::NamespaceKekCapsule,
        canonical:&enclave_crypto::namespace::WrappedNamespaceKey,shares:&KekShares<'_>,
        context:&VerifiedEnvelopeContext,now:i64)->EnclaveResult<SecretKey32> {
        let expected=self.namespace_capsule_scope(context,now)?;
        capsule.validate(&expected,canonical,context,now)?;
        let private=self.unwrap_selected_a4(shares)?;
        capsule.open_checked(&private,&expected,canonical,context,now)
    }

    /// Explicit original-primary migration candidate. No persistent state is
    /// changed here; a later item error drops the entire staged prefix. The
    /// service checks exact original-primary identity and one original10s
    /// operation window before reads, throughout `check`, and after ONE save.
    pub(crate) fn stage_namespace_primary_migration(&self,canonical:&[enclave_crypto::namespace::WrappedNamespaceKey],
        shares:&KekShares<'_>,context:&VerifiedEnvelopeContext,now:i64,mut check:impl FnMut()->EnclaveResult<()>)
        ->EnclaveResult<Vec<crate::namespace_capsule::NamespaceKekCapsule>> {
        check()?;
        if self.backup_projection.is_some() {fail!(EACCES,"NAMESPACE_CAPSULE_PRIMARY_REQUIRED");}
        let expected=self.namespace_capsule_scope(context,now)?;check()?;
        verify_tier_wrapping::<A4>(self.a4.wrapped(),shares)?;check()?;
        crate::namespace_capsule::NamespaceKekCapsule::stage_primary_migration(&self.a4,&expected,canonical,
            shares.sep_ecdh_share,shares.yubikey_prf,context,now,check)
    }

    /// Profile.
    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// Number of reversible entries held.
    pub fn stored_len(&self) -> usize {
        self.store.len()
    }

    fn erase(&mut self, kind: PiiKind) -> TokenOutput {
        *self.stats.erased.entry(format!("{kind:?}")).or_default() += 1;
        TokenOutput {
            token: kind.erasure_token().to_owned(),
            kind: Some(kind),
            reversible: false,
            tier: None,
        }
    }

    fn tag(&self, core: &str) -> String {
        let mut message = b"enclave-surrogate-v2\0".to_vec();
        message.extend_from_slice(core.as_bytes());
        self.mac_key.mac(&message)[..16].iter()
            .flat_map(|b| [char::from(b'a'+(b>>4)), char::from(b'a'+(b&15))]).collect()
    }

    fn random_nonce() -> String {
        let mut bytes = [0u8; 16];
        enclave_core::rng::fill(&mut bytes);
        // Bijective nibble encoding retains128 bits without digit runs that can
        // resemble SSNs/PANs to the conservative egress recognizer.
        bytes
            .iter()
            .flat_map(|b| [char::from(b'a' + (b >> 4)), char::from(b'a' + (b & 15))])
            .collect()
    }
    fn surrogate(&self, prefix: &str) -> String {
        let core = format!("{prefix}{}", Self::random_nonce());
        format!("{core}-{}", self.tag(&core))
    }
    fn synth_ssn(&self) -> String {
        self.surrogate("SYNTH-SSN-")
    }
    fn synth_c3(&self, kind: PiiKind) -> String {
        self.surrogate(match kind {
            PiiKind::Email => "CUST_EMAIL_",
            PiiKind::Phone => "CUST_PHONE_",
            _ => "CUST_NAME_",
        })
    }
    fn check_capacity(&self, cost: usize) -> EnclaveResult<()> {
        if self.store.len() >= self.max_entries || self.store_bytes.checked_add(cost).is_none_or(|n| n > self.max_bytes) {
            fail!(ENOMEM, "VAULT_CAPACITY", "explicit wipe/re-enrollment required; no live entries evicted");
        }
        Ok(())
    }
    fn check_before_seal(&self, plaintext: usize, surrogate: &str, aad: &[u8]) -> EnclaveResult<()> {
        let cost=plaintext.checked_add(2048).and_then(|v|v.checked_add(surrogate.len())).and_then(|v|v.checked_add(aad.len()))
            .ok_or_else(||err!(ENOMEM,"VAULT_CAPACITY"))?;
        self.check_capacity(cost)
    }

    fn insert_unique(&mut self, s: String, entry: StoredEntry) -> EnclaveResult<()> {
        if self.store.contains_key(&s) { fail!(EACCES,"SURROGATE_COLLISION"); }
        let cost=s.len()+entry.aad.len()+entry.sealed.enc.len()+entry.sealed.ct.len()+512;
        self.check_capacity(cost)?;
        match self.store.entry(s) {
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(entry);
                self.store_bytes += cost;
                Ok(())
            }
            std::collections::hash_map::Entry::Occupied(_) => fail!(EACCES, "SURROGATE_COLLISION"),
        }
    }

    /// Verify a surrogate's MAC tag (defeats confused-deputy detokenization
    /// of attacker-forged surrogates).
    pub fn verify_surrogate(&self, s: &str) -> EnclaveResult<()> {
        let (core, tag) = s
            .rsplit_once('-')
            .ok_or_else(|| err!(EACCES, "SURROGATE_FORGED"))?;
        let valid_core = core
            .strip_prefix("SYNTH-")
            .is_some_and(|body| !body.is_empty() && body.split('-').all(|part| !part.is_empty()))
            || core
                .strip_prefix("CUST_")
                .is_some_and(|body| !body.is_empty());
        if !valid_core
            || tag.len() != 32
            || !enclave_core::secret::ct_eq(self.tag(core).as_bytes(), tag.as_bytes())
        {
            fail!(EACCES, "SURROGATE_FORGED");
        }
        Ok(())
    }

    fn aad(&self, surrogate: &str) -> Vec<u8> {
        let mut a = self.session_id.to_vec();
        a.extend_from_slice(surrogate.as_bytes());
        a
    }

    fn seal_a3(&mut self, value: &[u8], aad: &[u8]) -> EnclaveResult<SealedValue> {
        loop {
            let env = self
                .a3_pool
                .get_mut(self.a3_current)
                .ok_or_else(|| err!(ESTALE, "A3_EPOCH_POOL_EXHAUSTED", "re-enrollment required"))?;
            if env.sealed_this_epoch() < A3_MAX_SEALS_PER_EPOCH {
                return env.seal_c3(value, aad);
            }
            if self.a3_current + 1 >= self.a3_pool.len() {
                fail!(ESTALE, "A3_EPOCH_POOL_EXHAUSTED", "explicit migration/re-enrollment required");
            }
            self.a3_current += 1;
        }
    }

    /// Tokenize one field value. `bulk_set` marks values belonging to a
    /// result set of more than one row (sealed under `A4`).
    pub fn tokenize(
        &mut self,
        value: &str,
        declared: Option<PiiKind>,
        bulk_set: bool,
        grant: Option<&ReversibleTokenizeGrant>,
        now: i64,
    ) -> EnclaveResult<TokenOutput> {
        if !self.enrolled {
            fail!(
                EPERM,
                "ENROLLMENT_REQUIRED",
                "custody vault is not enrolled; run mcp-enclave vault enroll"
            );
        }
        let Some(kind) = classify(value, declared) else {
            return Ok(TokenOutput {
                token: value.to_owned(),
                kind: None,
                reversible: false,
                tier: None,
            });
        };
        match kind {
            PiiKind::Pan | PiiKind::Credential => Ok(self.erase(kind)),
            PiiKind::Ssn | PiiKind::Phi => {
                let allowed = match (grant, &self.grant_key) {
                    (Some(g), Some(k)) if self.profile >= Profile::L2 => {
                        g.verify(k, self.profile, now).is_ok()
                    }
                    _ => false,
                };
                if !allowed {
                    return Ok(self.erase(kind));
                }
                let s = if kind == PiiKind::Ssn {
                    self.synth_ssn()
                } else {
                    self.surrogate("SYNTH-PHI-")
                };
                if self.store.contains_key(&s) {
                    fail!(EACCES, "SURROGATE_COLLISION");
                }
                let aad = self.aad(&s);
                self.check_before_seal(value.len(), &s, &aad)?;
                let sealed = self.a4.seal_c4_or_bulk(value.as_bytes(), &aad)?;
                self.insert_unique(
                    s.clone(),
                    StoredEntry {
                        tier: StoredTier::A4,
                        kind,
                        sealed,
                        aad,
                    },
                )?;
                self.stats.sealed_a4 += 1;
                Ok(TokenOutput {
                    token: s,
                    kind: Some(kind),
                    reversible: true,
                    tier: Some(StoredTier::A4),
                })
            }
            PiiKind::Email | PiiKind::Phone | PiiKind::Name => {
                if let Some(context) = &self.envelope_context { context.admit(self.profile, "C3", now, false)?; }
                let s = self.synth_c3(kind);
                if self.store.contains_key(&s) {
                    fail!(EACCES, "SURROGATE_COLLISION");
                }
                let aad = self.aad(&s);
                self.check_before_seal(value.len(), &s, &aad)?;
                let (tier, sealed) = if bulk_set {
                    (
                        StoredTier::A4,
                        self.a4.seal_c4_or_bulk(value.as_bytes(), &aad)?,
                    )
                } else {
                    (StoredTier::A3, self.seal_a3(value.as_bytes(), &aad)?)
                };
                self.insert_unique(
                    s.clone(),
                    StoredEntry {
                        tier,
                        kind,
                        sealed,
                        aad,
                    },
                )?;
                match tier { StoredTier::A3 => self.stats.sealed_a3 += 1, StoredTier::A4 => self.stats.sealed_a4 += 1 }
                Ok(TokenOutput {
                    token: s,
                    kind: Some(kind),
                    reversible: true,
                    tier: Some(tier),
                })
            }
        }
    }

    /// Scrub free text: every detected span is replaced (erased or surrogated).
    pub fn scrub_text(
        &mut self,
        text: &str,
        bulk_set: bool,
        grant: Option<&ReversibleTokenizeGrant>,
        now: i64,
    ) -> EnclaveResult<String> {
        if !self.enrolled {
            fail!(
                EPERM,
                "ENROLLMENT_REQUIRED",
                "custody vault is not enrolled; run mcp-enclave vault enroll"
            );
        }
        let spans = scan(text);
        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        for s in spans {
            out.push_str(&text[last..s.start]);
            let t = self.tokenize(&text[s.start..s.end], Some(s.kind), bulk_set, grant, now)?;
            out.push_str(&t.token);
            last = s.end;
        }
        out.push_str(&text[last..]);
        Ok(out)
    }

    /// Detokenize under a verified ceremony grant. `sep_share` is the
    /// tier-specific SEP ECDH share released by the same biometric
    /// evaluation; in `L2`/`L3` the second share is the grant's YubiKey PRF,
    /// in `L1` it is the SEP's secondary share (`l1_secondary_share`).
    pub fn detokenize(
        &mut self,
        surrogates: &[String],
        intent: &IntentPayloadV1,
        grant: &mut CeremonyGrant,
        sep_share: &[u8],
        l1_secondary_share: Option<&[u8]>,
    ) -> EnclaveResult<Vec<SecretBytes>> {
        if !self.enrolled {
            fail!(
                EPERM,
                "ENROLLMENT_REQUIRED",
                "custody vault is not enrolled; run mcp-enclave vault enroll"
            );
        }
        if grant.d_jcs != intent.d_jcs()? {
            fail!(EACCES, "GRANT_INTENT_MISMATCH");
        }
        grant.check_valid_at(enclave_crypto::time::now_unix())?;
        grant.check_valid_at_boot(enclave_core::clock::boot_clock_ns())?;
        grant.consume()?;
        if surrogates.is_empty() {
            fail!(EINVAL, "NOTHING_TO_DETOKENIZE");
        }
        // Both mandatory digests bind the exact sorted list approved by ceremony.
        intent.verify_surrogate_arguments(surrogates)?;
        // Hard post-call truncation: more rows than granted aborts before any decryption.
        if surrogates.len() as u64 > grant.row_count_bound {
            fail!(
                EACCES,
                "ROW_COUNT_EXCEEDS_GRANT",
                "{} > {}",
                surrogates.len(),
                grant.row_count_bound
            );
        }
        let mut entries = Vec::with_capacity(surrogates.len());
        for s in surrogates {
            self.verify_surrogate(s)?;
            let e = self
                .store
                .get(s)
                .ok_or_else(|| err!(EACCES, "UNKNOWN_SURROGATE"))?;
            entries.push(e.clone());
        }
        let tier = entries[0].tier;
        if entries.iter().any(|e| e.tier != tier) {
            fail!(EACCES, "MIXED_TIER_REQUEST");
        }
        let any_c4 = entries.iter().any(|e| e.kind.is_c4());
        if let Some(context) = &self.envelope_context {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                .map_err(|_|err!(EACCES,"ENVELOPE_POLICY_CLOCK"))?.as_secs();
            let now = i64::try_from(now).map_err(|_|err!(EACCES,"ENVELOPE_POLICY_CLOCK"))?;
            context.admit(self.profile, if any_c4 { "C4" } else { "C3" }, now, false)?;
        }
        match tier {
            StoredTier::A3 => {
                if grant.action < ActionClass::A3 || surrogates.len() != 1 {
                    fail!(EACCES, "A3_SINGLE_ROW_ONLY");
                }
            }
            StoredTier::A4 => {
                if grant.action != ActionClass::A4 {
                    fail!(
                        EACCES,
                        "A4_GRANT_REQUIRED",
                        "C4 or bulk release requires the A4 chained co-signature"
                    );
                }
                if any_c4 && self.profile == Profile::L1 {
                    fail!(EPERM, "L1_NEVER_DETOKENIZES_C4");
                }
            }
        }
        let second: &[u8] = match (self.profile, &grant.prf, l1_secondary_share) {
            (Profile::L1, _, Some(s)) => s,
            (_, Some(prf), _) if prf.len() == 32 || prf.len() == 64 => &prf.expose()[..32],
            (_, Some(_), _) => fail!(EACCES, "PRF_SHARE_LENGTH"),
            _ => fail!(EACCES, "PRF_SHARE_MISSING"),
        };
        let shares = KekShares {
            sep_ecdh_share: sep_share,
            yubikey_prf: second,
        };
        let mut out = Vec::with_capacity(entries.len());
        match tier {
            StoredTier::A3 => {
                let e = &entries[0];
                let key = self.unwrap_selected_a3(e.sealed.epoch, &shares)?;
                grant.check_valid_at(enclave_crypto::time::now_unix())?;
                grant.check_valid_at_boot(enclave_core::clock::boot_clock_ns())?;
                out.push(open(&key, &e.sealed, &e.aad)?);
                drop(key); // zeroized immediately
            }
            StoredTier::A4 => {
                let key = self.unwrap_selected_a4(&shares)?;
                grant.check_valid_at(enclave_crypto::time::now_unix())?;
                grant.check_valid_at_boot(enclave_core::clock::boot_clock_ns())?;
                for e in &entries {
                    out.push(open(&key, &e.sealed, &e.aad)?);
                }
                drop(key);
            }
        }
        Ok(out)
    }

    /// Panic wipe: drop all ciphertexts and rotate the MAC key.
    pub fn wipe(&mut self) {
        self.backup_projection = None;
        self.store.clear();
        self.store_bytes = 0;
        enclave_core::rng::fill(&mut self.session_id);
        self.mac_key = match &self.persistent_mac_seed {
            Some(seed) => Self::derive_surrogate_mac(seed, &self.session_id),
            None => SecretKey32::random(),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn shares() -> ([u8; 32], [u8; 32]) {
        ([3u8; 32], [4u8; 32])
    }

    fn vault(p: Profile, gk: Option<VerifyingKey>) -> CustodyVault {
        let (s, y) = shares();
        let sh = KekShares {
            sep_ecdh_share: &s,
            yubikey_prf: &y,
        };
        CustodyVault::enroll(p, &sh, &sh, gk).unwrap()
    }

    fn policy_context() -> VerifiedEnvelopeContext {
        use enclave_crypto::hpke_envelope::{EnvelopePolicy, SignedEnvelopePolicy};
        let issuer = SigningKey::from_bytes(&[45;32]);
        let policy = EnvelopePolicy { version: 1, revision: 1, subject: "fixture-asset".into(),
            namespace: "fixture-data".into(), issued_unix: 1, expires_unix: 4_000_000_000,
            review_unix: 4_000_000_000, owner: "test-owner".into(), profiles: vec![Profile::L2],
            data_classes: vec!["C3".into(), "C4".into()], purpose: "synthetic fixture".into(),
            migration: "reviewed hybrid successor".into(), disclosure: None, classical_exception: false };
        let signature = issuer.sign(&policy.signing_message().unwrap()).to_bytes().to_vec();
        SignedEnvelopePolicy { policy, signature }.verify(&issuer.verifying_key(),
            "fixture-asset", "fixture-data", 2).unwrap()
    }

    #[test]
    fn authenticated_transport_refresh_preserves_checkpoint_without_reviving_captured_context() {
        let (s,y)=shares();let shares=KekShares {sep_ecdh_share:&s,yubikey_prf:&y};
        let policy=policy_context();let captured=policy.clone().with_transport_expiry(4,2).unwrap();
        let mut vault=CustodyVault::enroll_authorized(Profile::L2,&shares,&shares,None,&captured,SecretKey32::new([9;32]),2).unwrap();
        vault.tokenize("retained@example.invalid",None,false,None,2).unwrap();
        let before=serde_json::to_vec(&vault.checkpoint().unwrap()).unwrap();
        assert!(vault.tokenize("late@example.invalid",None,false,None,4).is_err());
        let refreshed=policy.with_transport_expiry(10,4).unwrap();
        vault.refresh_authorized_context(&refreshed,4).unwrap();
        assert_eq!(serde_json::to_vec(&vault.checkpoint().unwrap()).unwrap(),before);
        assert!(captured.admit(Profile::L2,"C3",4,false).is_err());
        vault.tokenize("fresh@example.invalid",None,false,None,4).unwrap();
        assert_eq!(vault.stored_len(),2);
    }

    #[test]
    fn authenticated_restart_preserves_public_sealing_counts_and_surrogates() {
        let (s,y) = shares(); let shares = KekShares { sep_ecdh_share: &s, yubikey_prf: &y };
        let context = policy_context();
        let mut vault = CustodyVault::enroll_authorized(Profile::L2, &shares, &shares, None,
            &context, SecretKey32::new([9;32]), 2).unwrap();
        let enrollment_binding=vault.checkpoint().unwrap().enrollment_binding().unwrap();
        let first = vault.tokenize("jane@example.com", None, false, None, 2).unwrap();
        let snapshot = vault.checkpoint().unwrap();
        snapshot.verify_factor_shares(&shares,&shares).unwrap();
        let wrong=[77;32];let wrong=KekShares {sep_ecdh_share:&wrong,yubikey_prf:&y};
        assert!(snapshot.verify_factor_shares(&wrong,&shares).is_err());
        assert!(snapshot.verify_factor_shares(&shares,&wrong).is_err());
        assert_eq!(snapshot.enrollment_binding().unwrap(),enrollment_binding);
        let serialized = serde_json::to_vec(&snapshot).unwrap();
        let decoded: VaultEnvelopeCheckpoint = serde_json::from_slice(&serialized).unwrap();
        // Neither factor is needed to restore and continue the public sealing path.
        let mut restored = CustodyVault::restore_authorized(decoded, Profile::L2, None,
            &context, SecretKey32::new([9;32]), 3).unwrap();
        restored.verify_surrogate(&first.token).unwrap();
        assert_eq!(restored.a3_pool[0].sealed_this_epoch(), 1);
        restored.tokenize("john@example.com", None, false, None, 3).unwrap();
        assert_eq!(restored.a3_pool[0].sealed_this_epoch(), 2);
        assert_eq!(restored.stored_len(), 2);
        assert_eq!(restored.checkpoint().unwrap().enrollment_binding().unwrap(),enrollment_binding);
        let mut bad = snapshot.clone(); bad.a3_pool[0].sealed_this_epoch = 0;
        assert!(CustodyVault::restore_authorized(bad, Profile::L2, None,
            &context, SecretKey32::new([9;32]), 3).is_err());
        assert!(CustodyVault::restore_authorized(snapshot, Profile::L2, None,
            &context, SecretKey32::new([8;32]), 3).is_err());
        let mut exhausted = restored.checkpoint().unwrap();
        for epoch in &mut exhausted.a3_pool { epoch.sealed_this_epoch = A3_MAX_SEALS_PER_EPOCH; }
        exhausted.a3_current = exhausted.a3_pool.len()-1;
        let mut exhausted = CustodyVault::restore_authorized(exhausted, Profile::L2, None,
            &context, SecretKey32::new([9;32]), 3).unwrap();
        assert!(exhausted.tokenize("later@example.com", None, false, None, 3)
            .unwrap_err().is("A3_EPOCH_POOL_EXHAUSTED"));
        // A refused 1025th seal leaves a valid durable state; restart cannot
        // accidentally reset counts or strand unrelated retained ciphertexts.
        CustodyVault::restore_authorized(exhausted.checkpoint().unwrap(), Profile::L2, None,
            &context, SecretKey32::new([9;32]), 3).unwrap();
    }

    #[test]
    fn reenrollment_is_failure_atomic_and_refuses_to_orphan_live_data() {
        let mut vault = vault(Profile::L2, None);
        let previous_a3 = vault.a3_pool[0].public_key().to_bytes();
        let previous_a4 = vault.a4.public_key().to_bytes();
        let (s,y) = shares(); let good = KekShares { sep_ecdh_share: &s, yubikey_prf: &y };
        let bad = KekShares { sep_ecdh_share: &s, yubikey_prf: &[] };
        assert!(vault.reenroll(&good, &bad).is_err());
        assert_eq!(vault.a3_pool[0].public_key().to_bytes(), previous_a3);
        assert_eq!(vault.a4.public_key().to_bytes(), previous_a4);
        let token = vault.tokenize("jane@example.com", None, false, None, 2).unwrap();
        assert!(vault.reenroll(&good, &good).unwrap_err().is("REENROLL_LIVE_DATA_REQUIRES_MIGRATION"));
        assert!(vault.store.contains_key(&token.token));
        vault.wipe(); vault.reenroll(&good, &good).unwrap();
        assert_ne!(vault.a3_pool[0].public_key().to_bytes(), previous_a3);
    }

    #[test]
    fn vault_limits_reject_before_sealing_and_do_not_count_failures() {
        let mut v=vault(Profile::L2,None);v.max_entries=1;
        let first=v.tokenize("jane@example.com",None,false,None,1).unwrap();
        let stats=v.stats.clone();let used=v.a3_pool[0].sealed_this_epoch();let bytes=v.store_bytes;
        assert!(v.tokenize("john@example.com",None,false,None,1).unwrap_err().is("VAULT_CAPACITY"));
        assert_eq!(v.stats,stats);assert_eq!(v.a3_pool[0].sealed_this_epoch(),used);assert_eq!(v.store_bytes,bytes);
        assert!(v.store.contains_key(&first.token));
        v.wipe();assert_eq!(v.stored_len(),0);assert_eq!(v.store_bytes,0);assert!(v.verify_surrogate(&first.token).is_err());
        v.max_bytes=64;
        assert!(v.tokenize("person@example.com",None,false,None,1).unwrap_err().is("VAULT_CAPACITY"));
        assert_eq!(v.stats,stats);assert_eq!(v.a3_pool[0].sealed_this_epoch(),used);
        let mut inactive=CustodyVault::unenrolled(Profile::L2,None);
        assert!(inactive.tokenize("jane@example.com",None,false,None,1).unwrap_err().is("ENROLLMENT_REQUIRED"));
    }

    #[test]
    fn f142_v2_issuer_interoperates_with_actual_runner_and_rejects_legacy() {
        use enclave_model_runnerd::classes::byte_concept::{byte_dfa_validate, SurrogateVerifier};
        let mut v = vault(Profile::L2, None);
        v.mac_key = SecretKey32::new([7; 32]);
        let verifier = SurrogateVerifier::new(SecretKey32::new([7; 32]));
        let core = "SYNTH-SSN-904-00-1182";
        let expected = "eogmelfldbbencfahabmgnnfjglgjcfk";
        assert_eq!(v.tag(core), expected);
        assert_eq!(verifier.tag(core), expected);
        let issued = v.synth_ssn();
        v.verify_surrogate(&issued).unwrap();
        byte_dfa_validate(issued.as_bytes(), Some(&verifier)).unwrap();
        for malformed in [
            format!("{core}-{}", &expected[..6]),
            format!("SYNTH-{}", v.tag("SYNTH")),
            format!("SYNTH--{}", v.tag("SYNTH-")),
        ] {
            assert!(v.verify_surrogate(&malformed).is_err());
            assert!(byte_dfa_validate(malformed.as_bytes(), Some(&verifier)).is_err());
        }
        assert!(byte_dfa_validate(
            issued.as_bytes(),
            Some(&SurrogateVerifier::new(SecretKey32::new([8; 32])))
        )
        .is_err());
    }

    #[test]
    fn pan_credential_and_unganted_c4_never_enter_the_vault_in_any_profile() {
        // ADR-007 Level-4 policy (the native analogue of V17).
        let sk = SigningKey::generate(&mut rand_core::OsRng);
        for p in Profile::ALL {
            let mut v = vault(p, Some(sk.verifying_key()));
            let grant = ReversibleTokenizeGrant {
                workflow: "fraud-review".into(),
                profile: p,
                expires_unix: 2_000_000_000,
                signature: sk
                    .sign(&ReversibleTokenizeGrant::message(
                        "fraud-review",
                        p,
                        2_000_000_000,
                    ))
                    .to_bytes()
                    .to_vec(),
            };
            for (val, kind) in [
                ("4111 1111 1111 1111", PiiKind::Pan),
                ("AKIAIOSFODNN7EXAMPLE", PiiKind::Credential),
            ] {
                let t = v.tokenize(val, None, false, Some(&grant), 1).unwrap();
                assert_eq!(t.token, kind.erasure_token());
                assert!(!t.reversible);
            }
            let t = v.tokenize("078-05-1120", None, false, None, 1).unwrap();
            assert_eq!(t.token, "[REDACTED_SSN_C4]");
            assert_eq!(v.stored_len(), 0, "{p}");
            // With a grant: reversible only in L2/L3.
            let t = v
                .tokenize("078-05-1120", None, false, Some(&grant), 1)
                .unwrap();
            assert_eq!(t.reversible, p >= Profile::L2, "{p}");
            if p == Profile::L1 {
                assert_eq!(t.token, "[REDACTED_SSN_C4]");
            } else {
                assert!(t.token.starts_with("SYNTH-SSN-"));
                assert_eq!(t.tier, Some(StoredTier::A4));
            }
        }
    }

    #[test]
    fn forged_or_expired_grants_do_not_enable_reversible_c4() {
        let sk = SigningKey::generate(&mut rand_core::OsRng);
        let other = SigningKey::generate(&mut rand_core::OsRng);
        let mut v = vault(Profile::L2, Some(sk.verifying_key()));
        let forged = ReversibleTokenizeGrant {
            workflow: "w".into(),
            profile: Profile::L2,
            expires_unix: 10,
            signature: other
                .sign(&ReversibleTokenizeGrant::message("w", Profile::L2, 10))
                .to_bytes()
                .to_vec(),
        };
        assert!(
            !v.tokenize("078-05-1120", None, false, Some(&forged), 1)
                .unwrap()
                .reversible
        );
        let expired = ReversibleTokenizeGrant {
            workflow: "w".into(),
            profile: Profile::L2,
            expires_unix: 10,
            signature: sk
                .sign(&ReversibleTokenizeGrant::message("w", Profile::L2, 10))
                .to_bytes()
                .to_vec(),
        };
        assert!(
            !v.tokenize("078-05-1120", None, false, Some(&expired), 11)
                .unwrap()
                .reversible
        );
    }

    #[test]
    fn c3_tiering_and_epoch_rotation() {
        let mut v = vault(Profile::L2, None);
        let single = v
            .tokenize("jane@example.com", None, false, None, 1)
            .unwrap();
        assert_eq!(single.tier, Some(StoredTier::A3));
        assert!(single.token.starts_with("CUST_EMAIL_"));
        v.verify_surrogate(&single.token).unwrap();
        let mut forged = single.token.clone();
        forged.replace_range(forged.len() - 1.., "0");
        if forged != single.token {
            assert!(v.verify_surrogate(&forged).is_err());
        }
        let bulk = v.tokenize("bob@example.com", None, true, None, 1).unwrap();
        assert_eq!(bulk.tier, Some(StoredTier::A4));
        // 64 per epoch: the 65th A3 seal rotates to the next pre-generated epoch.
        for i in 0..70 {
            v.tokenize(&format!("u{i}@example.com"), None, false, None, 1)
                .unwrap();
        }
        assert_eq!(v.a3_current, 1);
    }

    #[test]
    fn scrub_text_replaces_every_span() {
        let mut v = vault(Profile::L1, None);
        let out = v
            .scrub_text(
                "ssn 078-05-1120 card 4111 1111 1111 1111 mail jane@example.com",
                false,
                None,
                1,
            )
            .unwrap();
        assert!(!out.contains("078-05-1120") && !out.contains("4111") && !out.contains("jane@"));
        assert!(
            out.contains("[REDACTED_SSN_C4]")
                && out.contains("[REDACTED_PAN_C4]")
                && out.contains("CUST_EMAIL_")
        );
    }
    #[test]
    fn twenty_thousand_distinct_ssns_keep_distinct_entries_and_pass_egress_scanner() {
        let sk = SigningKey::from_bytes(&[7; 32]);
        let mut v = vault(Profile::L3, Some(sk.verifying_key()));
        // F82's collision population must coexist, without wiping old entries.
        // Raise private fixture limits only; F86 separately verifies production
        // admission limits and nonreplacement under capacity failure.
        v.max_entries = 20_000;
        v.max_bytes = 64 * 1024 * 1024;
        let grant = ReversibleTokenizeGrant {
            workflow: "bulk-test".into(),
            profile: Profile::L3,
            expires_unix: 100,
            signature: sk
                .sign(&ReversibleTokenizeGrant::message(
                    "bulk-test",
                    Profile::L3,
                    100,
                ))
                .to_bytes()
                .to_vec(),
        };
        let mut tokens = std::collections::HashSet::new();
        for i in 0..20_000 {
            let value = format!("100-{:02}-{:04}", i / 9999 + 1, i % 9999 + 1);
            let token = v
                .tokenize(&value, Some(PiiKind::Ssn), true, Some(&grant), 1)
                .unwrap();
            assert!(token.reversible);
            assert!(tokens.insert(token.token.clone()));
            assert!(
                !enclave_zk_auditor::zk::lasso_dfa::eval_dfa_bytes(0, token.token.as_bytes()).1
            );
        }
        assert_eq!(tokens.len(), 20_000);
        assert_eq!(v.stored_len(), 20_000);
    }
    #[test]
    fn occupied_surrogate_never_replaces_original_ciphertext() {
        let mut v = vault(Profile::L2, None);
        let token = v
            .tokenize("jane@example.com", None, true, None, 1)
            .unwrap()
            .token;
        let original = v.store.get(&token).unwrap().clone();
        let before = serde_json::to_vec(&original.sealed).unwrap();
        assert!(v
            .insert_unique(token.clone(), original)
            .unwrap_err()
            .is("SURROGATE_COLLISION"));
        assert_eq!(v.stored_len(), 1);
        assert_eq!(serde_json::to_vec(&v.store[&token].sealed).unwrap(), before);
    }

    const PROJECTION_SEP:[u8;32]=[3;32];
    const PROJECTION_PRIMARY:[u8;32]=[4;32];
    const PROJECTION_BACKUP_A3:[u8;32]=[5;32];
    const PROJECTION_BACKUP_A4:[u8;32]=[6;32];
    fn projection_shares(prf:&[u8])->KekShares<'_> {KekShares {sep_ecdh_share:&PROJECTION_SEP,yubikey_prf:prf}}
    fn projection_credential(seed:u8)->crate::ctap::assertion::EnrolledCredential {
        crate::ctap::assertion::EnrolledCredential {credential_id:vec![seed;32],
            key:crate::ctap::assertion::CredentialKey::Ed25519(SigningKey::from_bytes(&[seed;32]).verifying_key()),
            aaguid:[8;16],firmware_version:crate::ctap::mds::MIN_FW_ED25519}
    }
    fn projection_bundle(checkpoint:&VaultEnvelopeCheckpoint,context:&VerifiedEnvelopeContext)
        ->crate::backup_envelope::StagedBackupEnvelopes {
        crate::backup_envelope::StagedBackupEnvelopes::stage(checkpoint,&projection_credential(41),&projection_credential(42),
            &projection_shares(&PROJECTION_PRIMARY),&projection_shares(&PROJECTION_PRIMARY),
            &projection_shares(&PROJECTION_BACKUP_A3),&projection_shares(&PROJECTION_BACKUP_A4),context,2).unwrap()
    }

    #[test]
    fn backup_projection_serves_existing_and_new_ciphertexts_without_changing_primary_checkpoint() {
        let context=policy_context();
        let mut vault=CustodyVault::enroll_authorized(Profile::L2,&projection_shares(&PROJECTION_PRIMARY),
            &projection_shares(&PROJECTION_PRIMARY),None,&context,SecretKey32::new([9;32]),2).unwrap();
        let first=vault.tokenize("first@example.invalid",None,false,None,2).unwrap().token;
        let bulk=vault.tokenize("bulk@example.invalid",None,true,None,2).unwrap().token;
        let checkpoint=vault.checkpoint().unwrap();let before=serde_json::to_vec(&checkpoint).unwrap();
        let binding=checkpoint.enrollment_binding().unwrap();let staged=projection_bundle(&checkpoint,&context);
        // Unit fixture installs only the private field to exercise the exact
        // production key-choice helpers. Real service installation requires the
        // opaque ValidatedNativeMembership selector; this is not admission proof.
        vault.backup_projection=Some(staged.public_projection(&checkpoint,&projection_credential(41),&projection_credential(42),&context,2).unwrap());
        let entry=&vault.store[&first];let key=vault.unwrap_selected_a3(entry.sealed.epoch,&projection_shares(&PROJECTION_BACKUP_A3)).unwrap();
        assert_eq!(open(&key,&entry.sealed,&entry.aad).unwrap().expose(),b"first@example.invalid");drop(key);
        let entry=&vault.store[&bulk];let key=vault.unwrap_selected_a4(&projection_shares(&PROJECTION_BACKUP_A4)).unwrap();
        assert_eq!(open(&key,&entry.sealed,&entry.aad).unwrap().expose(),b"bulk@example.invalid");drop(key);
        assert!(vault.unwrap_selected_a3(0,&projection_shares(&PROJECTION_PRIMARY)).is_err(),"selected backup never falls back to valid primary factors");
        assert!(vault.unwrap_selected_a4(&projection_shares(&PROJECTION_BACKUP_A3)).is_err(),"A3 PRF cannot unwrap A4");
        assert_eq!(serde_json::to_vec(&vault.checkpoint().unwrap()).unwrap(),before);
        let second=vault.tokenize("second@example.invalid",None,false,None,2).unwrap().token;
        let later=vault.checkpoint().unwrap();assert_eq!(later.enrollment_binding().unwrap(),binding);
        assert_eq!(later.a3_pool[0].sealed_this_epoch,2);assert_eq!(later.store.len(),3);
        let entry=&vault.store[&second];let key=vault.unwrap_selected_a3(entry.sealed.epoch,&projection_shares(&PROJECTION_BACKUP_A3)).unwrap();
        assert_eq!(open(&key,&entry.sealed,&entry.aad).unwrap().expose(),b"second@example.invalid");drop(key);
        let restored=CustodyVault::restore_authorized(later.clone(),Profile::L2,None,&context,SecretKey32::new([9;32]),2).unwrap();
        assert!(restored.backup_projection.is_none(),"runtime selection is never serialized as v2 authority");
        assert_eq!(serde_json::to_vec(&restored.checkpoint().unwrap()).unwrap(),serde_json::to_vec(&later).unwrap());
        let entry=&restored.store[&second];let key=restored.unwrap_selected_a3(entry.sealed.epoch,&projection_shares(&PROJECTION_PRIMARY)).unwrap();
        assert_eq!(open(&key,&entry.sealed,&entry.aad).unwrap().expose(),b"second@example.invalid");drop(key);
        vault.wipe();assert!(vault.backup_projection.is_none());
    }

    #[test]
    fn backup_projection_checks_actual_selected_tier_and_never_falls_back_on_corruption() {
        let context=policy_context();let mut vault=CustodyVault::enroll_authorized(Profile::L2,
            &projection_shares(&PROJECTION_PRIMARY),&projection_shares(&PROJECTION_PRIMARY),None,&context,SecretKey32::new([9;32]),2).unwrap();
        let checkpoint=vault.checkpoint().unwrap();let before=serde_json::to_vec(&checkpoint).unwrap();
        let staged=projection_bundle(&checkpoint,&context);let mut encoded=serde_json::to_value(&staged).unwrap();
        let byte=encoded["a4"]["ct"][0].as_u64().unwrap();encoded["a4"]["ct"][0]=serde_json::json!(byte^1);
        let corrupted:crate::backup_envelope::StagedBackupEnvelopes=serde_json::from_value(encoded).unwrap();
        corrupted.validate_scope(&checkpoint,&projection_credential(41),&projection_credential(42),&context,2).unwrap();
        assert!(corrupted.verify(&checkpoint,&projection_credential(41),&projection_credential(42),
            &projection_shares(&PROJECTION_BACKUP_A3),&projection_shares(&PROJECTION_BACKUP_A4),&context,2).is_err());
        vault.backup_projection=Some(corrupted.public_projection(&checkpoint,&projection_credential(41),&projection_credential(42),&context,2).unwrap());
        drop(vault.unwrap_selected_a3(15,&projection_shares(&PROJECTION_BACKUP_A3)).unwrap());
        assert!(vault.unwrap_selected_a4(&projection_shares(&PROJECTION_BACKUP_A4)).is_err());
        assert!(vault.unwrap_selected_a4(&projection_shares(&PROJECTION_PRIMARY)).is_err());
        assert!(vault.unwrap_selected_a3(16,&projection_shares(&PROJECTION_BACKUP_A3)).unwrap_err().is("A3_EPOCH_RETIRED"));
        assert_eq!(serde_json::to_vec(&vault.checkpoint().unwrap()).unwrap(),before);
        assert!(vault.backup_projection.is_some(),"failed action cannot silently switch selected credential");
    }

    #[test]
    fn namespace_capsules_use_actual_selected_a4_and_preserve_complete_checkpoint() {
        use enclave_crypto::namespace;
        let context=policy_context();let mut vault=CustodyVault::enroll_authorized(Profile::L2,
            &projection_shares(&PROJECTION_PRIMARY),&projection_shares(&PROJECTION_PRIMARY),None,&context,SecretKey32::new([9;32]),2).unwrap();
        vault.tokenize("retained@example.invalid",None,false,None,2).unwrap();
        let checkpoint=vault.checkpoint().unwrap();let before=serde_json::to_vec(&checkpoint).unwrap();
        assert!(vault.key_checkpoint().unwrap().store.is_empty(),"scope reads do not clone retained ciphertexts");
        assert!(!checkpoint.store.is_empty());
        let primary_kek=namespace::custody_kek(&PROJECTION_SEP,&PROJECTION_PRIMARY,"models",1).unwrap();
        let canonical=namespace::wrap("models",1,1,&[7;32],&primary_kek).unwrap();
        let capsules=vault.stage_namespace_primary_migration(std::slice::from_ref(&canonical),
            &projection_shares(&PROJECTION_PRIMARY),&context,2,||Ok(())).unwrap();
        let staged=projection_bundle(&checkpoint,&context);
        // Same explicitly private-field fixture as the neighboring projection
        // tests: actual selected cryptographic path, no service admission claim.
        vault.backup_projection=Some(staged.public_projection(&checkpoint,&projection_credential(41),&projection_credential(42),&context,2).unwrap());
        vault.validate_namespace_kek_capsule(&capsules[0],&canonical,&context,2).unwrap();
        let opened=vault.open_namespace_kek(&capsules[0],&canonical,&projection_shares(&PROJECTION_BACKUP_A4),&context,2).unwrap();
        assert_eq!(namespace::unwrap(&canonical,&opened).unwrap().expose(),&[7;32]);
        assert!(vault.open_namespace_kek(&capsules[0],&canonical,&projection_shares(&PROJECTION_PRIMARY),&context,2).is_err());
        assert!(vault.open_namespace_kek(&capsules[0],&canonical,&projection_shares(&PROJECTION_BACKUP_A3),&context,2).is_err());
        assert!(vault.stage_namespace_primary_migration(std::slice::from_ref(&canonical),
            &projection_shares(&PROJECTION_PRIMARY),&context,2,||Ok(())).unwrap_err().is("NAMESPACE_CAPSULE_PRIMARY_REQUIRED"));
        let backup_kek=namespace::custody_kek(&PROJECTION_SEP,&PROJECTION_BACKUP_A4,"models",2).unwrap();
        let new_canonical=namespace::wrap("models",2,2,&[8;32],&backup_kek).unwrap();
        let new_capsule=vault.seal_namespace_kek(&new_canonical,&backup_kek,&context,2).unwrap();
        let restored=CustodyVault::restore_authorized(checkpoint,Profile::L2,None,&context,SecretKey32::new([9;32]),2).unwrap();
        let primary_open=restored.open_namespace_kek(&new_capsule,&new_canonical,&projection_shares(&PROJECTION_PRIMARY),&context,2).unwrap();
        assert_eq!(namespace::unwrap(&new_canonical,&primary_open).unwrap().expose(),&[8;32]);
        assert_eq!(serde_json::to_vec(&vault.checkpoint().unwrap()).unwrap(),before);
        assert_eq!(serde_json::to_vec(&restored.checkpoint().unwrap()).unwrap(),before);
    }
}
