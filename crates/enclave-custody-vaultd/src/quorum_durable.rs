//! Local candidate progress store for legacy plain-digest CTAP approvals.
//!
//! Each authenticated counter advance and its exact same-publication approval
//! are one sealed replacement. No signing, production authorization, independent
//! human enrollment, authenticated remote freshness or hardware rollback claim.
use super::{QuorumApproval, QUORUM_TTL_S};
use crate::ctap::assertion::{
    verify_assertion, AssertionResponse, EnrolledCredential, SignCountStore,
};
use enclave_core::{
    err,
    error::EnclaveResult,
    fail,
    sealed::{Loaded, SealedStore, StateDirectoryLease},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

const MAX_COLLECTIONS: usize = 32;
const MAX_CREDENTIALS: usize = 32;

/// Exact local candidate scope. Callers must independently authenticate every
/// authority/freshness/enrollment field before production use can be designed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionSpec {
    /// Digest of exact publication bytes/manifest, distinct from CTAP challenge.
    pub publication_sha256: [u8; 32],
    /// Legacy plain-digest CTAP challenge. Never cast to chained/raw/TUF proof.
    pub grant_digest: [u8; 32],
    /// Exact independent policy reference; this store does not authenticate it.
    pub policy_sha256: [u8; 32],
    /// Inclusive local collection validity.
    pub not_before_unix: i64,
    /// Exclusive local collection expiry, at most 24 hours after not-before.
    pub expires_unix: i64,
    /// Required distinct credential threshold, not an independence proof.
    pub threshold: usize,
    /// Whether every stored assertion requires signed UV as well as UP.
    pub require_uv: bool,
    /// Exact enrolled set; aliases and duplicate IDs are rejected.
    pub enrolled: Vec<EnrolledCredential>,
}
impl CollectionSpec {
    fn validate(&self) -> EnclaveResult<()> {
        if self.threshold == 0
            || self.threshold > self.enrolled.len()
            || self.enrolled.len() > MAX_CREDENTIALS
            || self.not_before_unix < 0
            || self.expires_unix <= self.not_before_unix
            || self
                .expires_unix
                .checked_sub(self.not_before_unix)
                .is_none_or(|span| span > QUORUM_TTL_S)
        {
            fail!(EINVAL, "QUORUM_COLLECTION_SCOPE");
        }
        let mut ids = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for credential in &self.enrolled {
            let key = match &credential.key {
                crate::ctap::assertion::CredentialKey::Ed25519(key) => {
                    key.to_edwards().compress().to_bytes().to_vec()
                }
                crate::ctap::assertion::CredentialKey::Es256(key) => {
                    key.to_encoded_point(false).as_bytes().to_vec()
                }
            };
            if credential.credential_id.is_empty()
                || credential.credential_id.len() > 1024
                || !ids.insert(&credential.credential_id)
                || !keys.insert((credential.key.alg(), key))
            {
                fail!(EINVAL, "QUORUM_DUPLICATE_ENROLLMENT");
            }
        }
        Ok(())
    }
    fn identity(&self) -> EnclaveResult<[u8; 32]> {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"MCPMac-LocalQuorumCollection-v1\0");
        hash.update(enclave_core::jcs::to_jcs_bytes(self)?);
        Ok(hash.finalize().into())
    }
    fn current(&self, now: i64) -> EnclaveResult<()> {
        if now < self.not_before_unix || now >= self.expires_unix {
            fail!(EACCES, "QUORUM_COLLECTION_EXPIRED");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredApproval {
    approval: QuorumApproval,
    authenticated_at_unix: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Collection {
    spec: CollectionSpec,
    scope_sha256: [u8; 32],
    approvals: Vec<StoredApproval>,
    revoked: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    version: u8,
    counters: SignCountStore,
    collections: BTreeMap<String, Collection>,
}
impl Default for Ledger {
    fn default() -> Self {
        Self {
            version: 1,
            counters: SignCountStore::default(),
            collections: BTreeMap::new(),
        }
    }
}

/// Durable aggregation statistics. Reaching the threshold is not a custody,
/// signer or publication authorization; all current independent gates remain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionProgress {
    /// Stored same-publication cryptographically verified credential count.
    pub authenticated: usize,
    /// This submission's newly committed approvals.
    pub newly_authenticated: usize,
    /// Submitted untrusted/invalid/replayed/duplicate entries not added.
    pub ignored: usize,
    /// The local collection threshold only; not production authorization.
    pub threshold_reached: bool,
}

/// One exclusively leased local directory. Any uncertain persistence error
/// latches the instance closed; drop/reopen to reconcile authenticated bytes.
/// Preserve this entire directory across code upgrades. Whole-directory root
/// replacement and cross-store counter synchronization remain outside scope.
pub struct DurableQuorumCollector {
    _lease: StateDirectoryLease,
    store: SealedStore,
    ledger: Ledger,
    faulted: bool,
}
impl DurableQuorumCollector {
    /// Open a private absolute path with no-follow bounded required state and
    /// one exclusive inode lease; missing surviving state refuses reset.
    pub fn open(path: &Path) -> EnclaveResult<Self> {
        let lease = StateDirectoryLease::acquire(path)?;
        let (mut store, loaded) =
            SealedStore::open_bounded_required(path, "quorum-progress", 8 * 1024 * 1024)?;
        let mut ledger = match loaded {
            Loaded::Fresh => {
                let ledger = Ledger::default();
                store.save_json(&ledger)?;
                ledger
            }
            Loaded::State(bytes) => enclave_core::sealed::decode::<Ledger>(&bytes)?,
        };
        if ledger.version != 1 || ledger.collections.len() > MAX_COLLECTIONS {
            fail!(EACCES, "QUORUM_PROGRESS_STATE");
        }
        for (publication, collection) in &ledger.collections {
            collection.spec.validate()?;
            if *publication != hex::encode(collection.spec.publication_sha256)
                || collection.scope_sha256 != collection.spec.identity()?
                || collection.approvals.len() > collection.spec.enrolled.len()
            {
                fail!(EACCES, "QUORUM_PROGRESS_STATE");
            }
        }
        // Seed normalized fingerprints from every authenticated historical
        // handle/key before a new alias in another collection can be checked.
        ledger.counters.bind_credentials(
            ledger
                .collections
                .values()
                .flat_map(|collection| collection.spec.enrolled.iter()),
        );
        for collection in ledger.collections.values() {
            let mut seen = BTreeSet::new();
            for stored in &collection.approvals {
                collection.spec.current(stored.authenticated_at_unix)?;
                if !seen.insert(&stored.approval.credential_id) {
                    fail!(EACCES, "QUORUM_PROGRESS_STATE");
                }
                let credential = collection
                    .spec
                    .enrolled
                    .iter()
                    .find(|c| c.credential_id == stored.approval.credential_id)
                    .ok_or_else(|| err!(EACCES, "QUORUM_PROGRESS_STATE"))?;
                let mut observed = SignCountStore::default();
                authenticate(
                    credential,
                    &collection.spec,
                    &stored.approval,
                    stored.authenticated_at_unix,
                    &mut observed,
                )?;
                if ledger.counters.get_credential(credential) < observed.get_credential(credential)
                {
                    fail!(EACCES, "QUORUM_PROGRESS_STATE");
                }
            }
        }
        Ok(Self {
            _lease: lease,
            store,
            ledger,
            faulted: false,
        })
    }
    fn commit(&mut self, next: Ledger) -> EnclaveResult<()> {
        if self.faulted {
            fail!(EACCES, "QUORUM_PROGRESS_REOPEN_REQUIRED");
        }
        self.faulted = true;
        self.store.save_json(&next)?;
        self.ledger = next;
        self.faulted = false;
        Ok(())
    }
    /// Verify each proof once, atomically retaining its counter and exact
    /// approval even when threshold is unmet. Same-byte same-publication retries
    /// use the already authenticated record rather than replaying CTAP evidence.
    /// Invalid evidence never changes a counter. `collected_at` is untrusted
    /// diagnostic input and supplies no independent freshness authority.
    pub fn collect(
        &mut self,
        spec: &CollectionSpec,
        approvals: &[QuorumApproval],
        now: i64,
    ) -> EnclaveResult<CollectionProgress> {
        if self.faulted {
            fail!(EACCES, "QUORUM_PROGRESS_REOPEN_REQUIRED");
        }
        spec.validate()?;
        spec.current(now)?;
        if approvals.len() > MAX_CREDENTIALS {
            fail!(E2BIG, "QUORUM_PROGRESS_INPUT");
        }
        let publication = hex::encode(spec.publication_sha256);
        let scope = spec.identity()?;
        let mut next = self.ledger.clone();
        if let Some(old) = next.collections.get(&publication) {
            if old.scope_sha256 != scope {
                fail!(EACCES, "QUORUM_PUBLICATION_CONFLICT");
            }
            if old.revoked {
                fail!(EACCES, "QUORUM_COLLECTION_REVOKED");
            }
        } else {
            if next.collections.len() >= MAX_COLLECTIONS {
                fail!(E2BIG, "QUORUM_COLLECTION_LIMIT");
            }
            next.collections.insert(
                publication.clone(),
                Collection {
                    spec: spec.clone(),
                    scope_sha256: scope,
                    approvals: vec![],
                    revoked: false,
                },
            );
        }
        let collection = next.collections.get_mut(&publication).unwrap();
        let mut added = 0;
        let mut ignored = 0;
        for approval in approvals {
            if collection
                .approvals
                .iter()
                .any(|old| old.approval.credential_id == approval.credential_id)
            {
                ignored += 1;
                continue;
            }
            let Some(credential)=spec.enrolled.iter().find(|c|c.credential_id==approval.credential_id) else {ignored+=1;continue;};
            if authenticate(credential, spec, approval, now, &mut next.counters).is_err() {
                ignored += 1;
                continue;
            }
            collection.approvals.push(StoredApproval {
                approval: approval.clone(),
                authenticated_at_unix: now,
            });
            added += 1;
        }
        let count = collection.approvals.len();
        // One snapshot contains both effects, including partial quorum. No
        // store operation publishes a counter without its retained approval.
        self.commit(next)?;
        Ok(CollectionProgress {
            authenticated: count,
            newly_authenticated: added,
            ignored,
            threshold_reached: count >= spec.threshold,
        })
    }
    /// Persist terminal revocation without deleting consumed counters or proof
    /// records. Repeated revocation is idempotent; no unrevocation API exists.
    pub fn revoke(&mut self, publication_sha256: &[u8; 32]) -> EnclaveResult<()> {
        if self.faulted {
            fail!(EACCES, "QUORUM_PROGRESS_REOPEN_REQUIRED");
        }
        let mut next = self.ledger.clone();
        let collection = next
            .collections
            .get_mut(&hex::encode(publication_sha256))
            .ok_or_else(|| err!(EINVAL, "QUORUM_COLLECTION_UNKNOWN"))?;
        if collection.revoked {
            return Ok(());
        }
        collection.revoked = true;
        self.commit(next)
    }
}

fn authenticate(
    credential: &EnrolledCredential,
    spec: &CollectionSpec,
    approval: &QuorumApproval,
    now: i64,
    counters: &mut SignCountStore,
) -> EnclaveResult<()> {
    if approval.auth_data.len() > 8192
        || approval.signature.len() > 512
        || approval.collected_at < spec.not_before_unix
        || now < approval.collected_at
        || now
            .checked_sub(approval.collected_at)
            .is_none_or(|age| age > QUORUM_TTL_S)
    {
        fail!(EACCES, "QUORUM_APPROVAL_INVALID");
    }
    verify_assertion(
        credential,
        &AssertionResponse {
            credential_id: Some(approval.credential_id.clone()),
            auth_data: approval.auth_data.clone(),
            signature: approval.signature.clone(),
        },
        &spec.grant_digest,
        spec.require_uv,
        counters,
    )?;
    Ok(())
}

#[cfg(test)]
#[path = "quorum_durable_tests.rs"]
mod tests;
