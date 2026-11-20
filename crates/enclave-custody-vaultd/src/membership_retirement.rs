//! Inert inventory-issuer member retirement and replacement statement checks.
//!
//! No store, RPC, live guard, factor, release, wrapper or activation API exists
//! here. The parent must persist history in the SAME authoritative workflow,
//! fence old releases and authenticate readback before acknowledging loss. A
//! replacement candidate additionally needs scoped code/release authority and
//! survivor + new-member complete fresh factors and all17 wrapper possessions
//! within the ORIGINAL complete10s window at same-store adoption.
//!
//! The signer is the EXISTING independently pinned inventory issuer, with two
//! distinct purpose domains; no new recovery roster/quorum is inferred. Receipt
//! v1 has NO stable physical-key ID. These tombstones deny an exact credential
//! ID OR normalized public key, including aliases, but cannot identify another
//! new credential on the same physical Basic-attested key. That stronger claim
//! requires a separately signed stable inventory-key binding/receipt version.
use crate::{ctap::{assertion::{CredentialKey, EnrolledCredential}, rp_id_hash},
    service::AssetEnrollmentAuthority};
use enclave_core::{err, error::EnclaveResult, fail, profile::Profile};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const MAX_WIRE: usize = 64 * 1024;
const MAX_EVENTS: usize = 64;
const MAX_TOMBSTONES: usize = 256;
const MAX_HISTORY: usize = 256 * 1024;
const MAX_INTEGER: u64 = 9_007_199_254_740_991;
const RETIRE_DOMAIN: &[u8] = b"depot-InventoryMemberRetirement-v1\0";
const REPLACE_DOMAIN: &[u8] = b"depot-InventoryMemberReplacement-v1\0";
type Hash = [u8; 32];

fn message(domain: &[u8], value: &impl Serialize) -> EnclaveResult<Vec<u8>> {
    let body = enclave_core::jcs::to_jcs_bytes(value)?;
    if body.len() > MAX_HISTORY { fail!(E2BIG, "RETIREMENT_SIZE"); }
    let mut bytes = domain.to_vec(); bytes.extend(body); Ok(bytes)
}
fn commitment(domain: &[u8], value: &impl Serialize) -> EnclaveResult<Hash> {
    Ok(Sha256::digest(message(domain, value)?).into())
}
fn nonzero(value: &Hash) -> bool { *value != [0; 32] }
fn bounded(value: u64) -> bool { value > 0 && value <= MAX_INTEGER }
fn text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}
fn parse<T: serde::de::DeserializeOwned>(wire: &[u8]) -> EnclaveResult<T> {
    if wire.is_empty() || wire.len() > MAX_WIRE { fail!(E2BIG, "RETIREMENT_SIZE"); }
    // Closed typed structs reject unknown and duplicate (also escaped) fields.
    serde_json::from_slice(wire).map_err(|_| err!(EINVAL, "RETIREMENT_SCHEMA"))
}
fn verify_signature(key: &ed25519_dalek::VerifyingKey, bytes: &[u8], signature: &[u8]) -> EnclaveResult<()> {
    let signature = ed25519_dalek::Signature::from_slice(signature)
        .map_err(|_| err!(EACCES, "RETIREMENT_SIGNATURE"))?;
    key.verify_strict(bytes, &signature).map_err(|_| err!(EACCES, "RETIREMENT_SIGNATURE"))
}

/// Existing protected asset-inventory pins; never constructed from an RPC body.
#[derive(Debug)]
pub(crate) struct InventoryRetirementPins { issuer: ed25519_dalek::VerifyingKey, scope: Hash }
impl InventoryRetirementPins {
    pub(crate) fn from_asset_authority(authority: &AssetEnrollmentAuthority) -> EnclaveResult<Self> {
        let key = authority.inventory_issuer;
        if ![&authority.host, &authority.asset, &authority.custodian].into_iter().all(|s| text(s))
            || key.is_weak() || key.to_edwards().compress().to_bytes() != key.to_bytes() {
            fail!(EACCES, "RETIREMENT_TRUST_PINS");
        }
        let scope = commitment(b"depot-InventoryRetirementPins-v1\0", &(
            &authority.host, &authority.asset, &authority.custodian, key.to_bytes()))?;
        Ok(Self { issuer: key, scope })
    }
}

/// Public identity commitment; no assertion/factor or membership capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetirementIdentity {
    credential_id_sha256: Hash,
    normalized_key_sha256: Hash,
    enrolled_sha256: Hash,
}
impl RetirementIdentity {
    pub(crate) fn from_credential(credential: &EnrolledCredential) -> EnclaveResult<Self> {
        if credential.credential_id.is_empty() || credential.credential_id.len() > 1023 {
            fail!(EACCES, "RETIREMENT_CREDENTIAL_ID");
        }
        let key = match &credential.key {
            CredentialKey::Ed25519(key) => {
                if key.is_weak() { fail!(EACCES, "RETIREMENT_CREDENTIAL_KEY"); }
                key.to_edwards().compress().to_bytes().to_vec()
            }
            CredentialKey::Es256(key) => key.to_encoded_point(false).as_bytes().to_vec(),
        };
        Ok(Self {
            credential_id_sha256: commitment(b"depot-RetiredCredentialID-v1\0", &(rp_id_hash(), &credential.credential_id))?,
            normalized_key_sha256: commitment(b"depot-RetiredNormalizedKey-v1\0", &(rp_id_hash(), credential.key.alg(), key))?,
            enrolled_sha256: commitment(b"depot-RetiredEnrolledCredential-v1\0", credential)?,
        })
    }
    fn shape(&self) -> bool {
        nonzero(&self.credential_id_sha256) && nonzero(&self.normalized_key_sha256) && nonzero(&self.enrolled_sha256)
    }
    pub(crate) fn aliases(&self, other: &Self) -> bool {
        self.credential_id_sha256 == other.credential_id_sha256 || self.normalized_key_sha256 == other.normalized_key_sha256
    }
}

/// Expected values come from the authenticated current workflow and complete
/// checkpoint, NEVER caller-supplied trust. Wire copies alone carry no authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetirementBinding {
    pub(crate) profile: Profile,
    pub(crate) source_v2_binding: Hash,
    pub(crate) pool_sha256: Hash,
    pub(crate) membership_id: Hash,
    pub(crate) membership_generation: u64,
    pub(crate) complete_sha256: Hash,
    pub(crate) complete_sequence: u64,
    pub(crate) policy_sha256: Hash,
    pub(crate) policy_revision: u64,
    pub(crate) receipt_floor: u64,
    pub(crate) target: RetirementIdentity,
    pub(crate) survivor: RetirementIdentity,
}
impl RetirementBinding {
    fn shape(&self) -> EnclaveResult<()> {
        if self.profile == Profile::L1 || ![self.source_v2_binding, self.pool_sha256, self.membership_id,
            self.complete_sha256, self.policy_sha256].iter().all(nonzero)
            || ![self.membership_generation, self.policy_revision, self.receipt_floor].into_iter().all(bounded)
            || self.complete_sequence > MAX_INTEGER || !self.target.shape() || !self.survivor.shape()
            || self.target.aliases(&self.survivor) { fail!(EACCES, "RETIREMENT_BINDING"); }
        Ok(())
    }
}

/// Independent trusted time interval and current authority expiry supplied by
/// the parent. Upper endpoint is exclusive at every signed expiry boundary.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RetirementObservation {
    pub(crate) lower_unix: i64,
    pub(crate) upper_unix: i64,
    pub(crate) authority_expires_unix: i64,
}
impl RetirementObservation {
    fn until(self, issued: i64, not_before: i64, expires: i64, other_expires: &[i64]) -> EnclaveResult<i64> {
        let maximum = MAX_INTEGER as i64;
        if self.lower_unix < 0 || self.lower_unix > self.upper_unix || self.upper_unix > maximum
            || issued < 0 || issued > not_before || not_before >= expires || expires > maximum
            || self.authority_expires_unix <= 0 || self.authority_expires_unix > maximum
            || other_expires.iter().any(|end| *end <= 0 || *end > maximum) {
            fail!(EACCES, "RETIREMENT_TIME");
        }
        let until = other_expires.iter().copied().fold(expires.min(self.authority_expires_unix), i64::min);
        if self.lower_unix < not_before || self.upper_unix >= until { fail!(EACCES, "RETIREMENT_EXPIRED"); }
        Ok(until)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetirementStatement {
    version: u32,
    kind: String,
    inventory_scope_sha256: Hash,
    event_id: Hash,
    event_sequence: u64,
    binding: RetirementBinding,
    issued_unix: i64,
    not_before_unix: i64,
    expires_unix: i64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedRetirement { statement: RetirementStatement, #[serde(with = "serde_bytes")] signature: Vec<u8> }

/// Move-only denial fact. It cannot authorize a release or replace a member.
#[derive(Debug)]
pub(crate) struct VerifiedRetirement {
    statement: RetirementStatement, digest: Hash, history_sha256: Hash, expires_unix: i64,
}
impl VerifiedRetirement {
    pub(crate) fn statement_sha256(&self) -> Hash { self.digest }
    pub(crate) fn expires_unix(&self) -> i64 { self.expires_unix }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedRetirement { event_id: Hash, statement_sha256: Hash, event_sequence: u64, binding: RetirementBinding }
/// Append-only PUBLIC history to embed in the SAME authoritative workflow
/// record. No open/save path or independent activation store is provided.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetirementHistory {
    version: u32,
    inventory_scope_sha256: Hash,
    events: Vec<RecordedRetirement>,
    tombstones: Vec<RetirementIdentity>,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RetirementAppend { Recorded, AlreadyRecorded }
impl RetirementHistory {
    pub(crate) fn empty(pins: &InventoryRetirementPins) -> Self {
        Self { version: 1, inventory_scope_sha256: pins.scope, events: vec![], tombstones: vec![] }
    }
    /// Must be called after deserializing authenticated parent workflow history.
    pub(crate) fn validate(&self, pins: &InventoryRetirementPins) -> EnclaveResult<()> {
        if self.version != 1 || self.inventory_scope_sha256 != pins.scope || self.events.len() > MAX_EVENTS
            || self.tombstones.len() > MAX_TOMBSTONES || self.events.len() != self.tombstones.len() {
            fail!(EACCES, "RETIREMENT_HISTORY");
        }
        let mut ids = BTreeSet::new(); let mut keys = BTreeSet::new();
        for identity in &self.tombstones {
            if !identity.shape() || !ids.insert(identity.credential_id_sha256) || !keys.insert(identity.normalized_key_sha256) {
                fail!(EACCES, "RETIREMENT_HISTORY");
            }
        }
        let mut event_ids = BTreeSet::new(); let mut digests = BTreeSet::new();
        for (index, event) in self.events.iter().enumerate() {
            event.binding.shape()?;
            if event.event_sequence != index as u64 + 1 || !nonzero(&event.event_id) || !nonzero(&event.statement_sha256)
                || !event_ids.insert(event.event_id) || !digests.insert(event.statement_sha256)
                || event.binding.target != self.tombstones[index] { fail!(EACCES, "RETIREMENT_HISTORY"); }
            // A survivor may later retire, but cannot already have retired at
            // this event. Credential and key aliases independently deny reuse.
            if self.tombstones[..index].iter().any(|old| old.aliases(&event.binding.survivor)) {
                fail!(EACCES, "RETIREMENT_HISTORY");
            }
        }
        if enclave_core::jcs::to_jcs_bytes(self)?.len() > MAX_HISTORY { fail!(E2BIG, "RETIREMENT_SIZE"); }
        Ok(())
    }
    fn digest(&self) -> EnclaveResult<Hash> { commitment(b"depot-MemberRetirementHistory-v1\0", self) }
    /// Checked public history commitment for the parent's SAME workflow pins.
    /// This authenticates neither storage nor current membership by itself.
    pub(crate) fn commitment(&self, pins: &InventoryRetirementPins) -> EnclaveResult<Hash> {
        self.validate(pins)?;
        self.digest()
    }
    /// Next bounded event sequence for a new signed denial statement. Reading
    /// this value neither reserves nor burns it; append still rejects stale
    /// history. Exhaustion never evicts an earlier permanent tombstone.
    pub(crate) fn next_event_sequence(&self, pins: &InventoryRetirementPins) -> EnclaveResult<u64> {
        self.validate(pins)?;
        if self.events.len() >= MAX_EVENTS || self.tombstones.len() >= MAX_TOMBSTONES {
            fail!(E2BIG, "RETIREMENT_HISTORY_EXHAUSTED");
        }
        u64::try_from(self.events.len()).ok().and_then(|count| count.checked_add(1)).filter(|next| bounded(*next))
            .ok_or_else(|| err!(E2BIG, "RETIREMENT_HISTORY_EXHAUSTED"))
    }
    pub(crate) fn denies(&self, pins: &InventoryRetirementPins, identity: &RetirementIdentity) -> EnclaveResult<bool> {
        self.validate(pins)?;
        if !identity.shape() { fail!(EACCES, "RETIREMENT_CREDENTIAL_KEY"); }
        Ok(self.tombstones.iter().any(|old| old.aliases(identity)))
    }
    /// Memory-only atomic append. Parent must save this WITH the irreversible
    /// loss phase and floors, authenticate readback and keep failures sterile.
    pub(crate) fn append(&mut self, pins: &InventoryRetirementPins, verified: VerifiedRetirement) -> EnclaveResult<RetirementAppend> {
        self.validate(pins)?;
        if self.events.iter().any(|event| event.statement_sha256 == verified.digest) {
            return Ok(RetirementAppend::AlreadyRecorded);
        }
        if self.digest()? != verified.history_sha256 || verified.statement.inventory_scope_sha256 != pins.scope
            || verified.statement.event_sequence != self.events.len() as u64 + 1 {
            fail!(EACCES, "RETIREMENT_STALE_HISTORY");
        }
        if self.events.len() >= MAX_EVENTS || self.tombstones.len() >= MAX_TOMBSTONES {
            fail!(E2BIG, "RETIREMENT_HISTORY_EXHAUSTED");
        }
        let mut next = self.clone();
        next.tombstones.push(verified.statement.binding.target.clone());
        next.events.push(RecordedRetirement { event_id: verified.statement.event_id, statement_sha256: verified.digest,
            event_sequence: verified.statement.event_sequence, binding: verified.statement.binding });
        next.validate(pins)?; *self = next; Ok(RetirementAppend::Recorded)
    }
}

/// Verify a fresh denial-only statement. Neither the target nor survivor must
/// present factors; in particular, a lost member's current receipt may expire.
pub(crate) fn verify_retirement(wire: &[u8], pins: &InventoryRetirementPins, expected: &RetirementBinding,
    history: &RetirementHistory, now: RetirementObservation) -> EnclaveResult<VerifiedRetirement> {
    history.validate(pins)?; expected.shape()?;
    let signed: SignedRetirement = parse(wire)?; let statement = signed.statement;
    if statement.version != 1 || statement.kind != "member_retirement" || statement.inventory_scope_sha256 != pins.scope
        || statement.binding != *expected || !nonzero(&statement.event_id) || !bounded(statement.event_sequence) {
        fail!(EACCES, "RETIREMENT_SCOPE");
    }
    let bytes = message(RETIRE_DOMAIN, &statement)?;
    verify_signature(&pins.issuer, &bytes, &signed.signature)?;
    let digest: Hash = Sha256::digest(bytes).into();
    let recorded = history.events.iter().any(|event| event.statement_sha256 == digest);
    if !recorded && (statement.event_sequence != history.events.len() as u64 + 1
        || history.events.iter().any(|event| event.event_id == statement.event_id)
        || history.denies(pins, &expected.target)? || history.denies(pins, &expected.survivor)?) {
        fail!(EACCES, "RETIREMENT_REPLAY_OR_ALIAS");
    }
    let expires_unix = now.until(statement.issued_unix, statement.not_before_unix, statement.expires_unix, &[])?;
    Ok(VerifiedRetirement { statement, digest, history_sha256: history.digest()?, expires_unix })
}

/// Exact inert replacement intent derived by parent from its authenticated
/// loss state, independently verified NEW pending/receipt and code-release
/// checks. Equality binds those inputs; this module DOES NOT verify them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReplacementBinding {
    pub(crate) current: RetirementBinding,
    pub(crate) retirement_sha256: Hash,
    pub(crate) replacement: RetirementIdentity,
    pub(crate) replacement_pending_sha256: Hash,
    pub(crate) replacement_receipt_sha256: Hash,
    pub(crate) replacement_receipt_generation: u64,
    pub(crate) replacement_receipt_expires_unix: i64,
    pub(crate) survivor_receipt_sha256: Hash,
    pub(crate) survivor_receipt_expires_unix: i64,
    pub(crate) proposed_membership_generation: u64,
    pub(crate) boot_epoch_sha256: Hash,
    pub(crate) running_code_sha256: Hash,
    pub(crate) release_policy_sha256: Hash,
    pub(crate) release_policy_revision: u64,
    pub(crate) release_policy_expires_unix: i64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplacementStatement {
    version: u32, kind: String, inventory_scope_sha256: Hash, statement_id: Hash,
    binding: ReplacementBinding, issued_unix: i64, not_before_unix: i64, expires_unix: i64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedReplacement { statement: ReplacementStatement, #[serde(with = "serde_bytes")] signature: Vec<u8> }
/// Move-only checked statement; grants NO release, membership or factor waiver.
/// Parent must burn its digest with same-store Preparing BEFORE fresh factors.
#[derive(Debug)]
pub(crate) struct VerifiedReplacementCandidate { digest: Hash, binding_sha256: Hash, history_sha256: Hash, expires_unix: i64 }
impl VerifiedReplacementCandidate {
    pub(crate) fn statement_sha256(&self) -> Hash { self.digest }
    pub(crate) fn binding_sha256(&self) -> Hash { self.binding_sha256 }
    pub(crate) fn history_sha256(&self) -> Hash { self.history_sha256 }
    pub(crate) fn expires_unix(&self) -> i64 { self.expires_unix }
}

pub(crate) fn verify_replacement(wire: &[u8], pins: &InventoryRetirementPins, expected: &ReplacementBinding,
    history: &RetirementHistory, now: RetirementObservation) -> EnclaveResult<VerifiedReplacementCandidate> {
    history.validate(pins)?; expected.current.shape()?;
    let signed: SignedReplacement = parse(wire)?; let statement = signed.statement;
    if statement.version != 1 || statement.kind != "member_replacement_candidate" || statement.inventory_scope_sha256 != pins.scope
        || !nonzero(&statement.statement_id) || statement.binding != *expected || !expected.replacement.shape()
        || ![expected.replacement_pending_sha256, expected.replacement_receipt_sha256, expected.survivor_receipt_sha256,
            expected.boot_epoch_sha256, expected.running_code_sha256, expected.release_policy_sha256].iter().all(nonzero)
        || !bounded(expected.release_policy_revision) || !bounded(expected.replacement_receipt_generation)
        || expected.replacement_receipt_generation <= expected.current.receipt_floor
        || expected.current.membership_generation.checked_add(1) != Some(expected.proposed_membership_generation)
        || !bounded(expected.proposed_membership_generation)
        || expected.replacement.aliases(&expected.current.target) || expected.replacement.aliases(&expected.current.survivor)
        || history.denies(pins, &expected.replacement)? || history.denies(pins, &expected.current.survivor)? {
        fail!(EACCES, "REPLACEMENT_SCOPE_OR_ALIAS");
    }
    let event = history.events.iter().find(|event| event.statement_sha256 == expected.retirement_sha256)
        .ok_or_else(|| err!(EACCES, "REPLACEMENT_RETIREMENT_REQUIRED"))?;
    let original = &event.binding; let current = &expected.current;
    if original.source_v2_binding != current.source_v2_binding || original.pool_sha256 != current.pool_sha256
        || original.complete_sha256 != current.complete_sha256 || original.complete_sequence != current.complete_sequence
        || original.profile != current.profile || original.target != current.target || original.survivor != current.survivor
        || original.membership_generation > current.membership_generation || original.policy_revision > current.policy_revision
        || original.receipt_floor > current.receipt_floor { fail!(EACCES, "REPLACEMENT_ORIGIN_CHANGED"); }
    let bytes = message(REPLACE_DOMAIN, &statement)?;
    verify_signature(&pins.issuer, &bytes, &signed.signature)?;
    let expires_unix = now.until(statement.issued_unix, statement.not_before_unix, statement.expires_unix, &[
        expected.replacement_receipt_expires_unix, expected.survivor_receipt_expires_unix, expected.release_policy_expires_unix])?;
    Ok(VerifiedReplacementCandidate { digest: Sha256::digest(bytes).into(),
        binding_sha256: commitment(b"depot-MemberReplacementBinding-v1\0", expected)?, history_sha256: history.digest()?, expires_unix })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn authority(seed: u8) -> (SigningKey, InventoryRetirementPins) {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let authority = AssetEnrollmentAuthority { policy_issuer: SigningKey::from_bytes(&[99; 32]).verifying_key(),
            inventory_issuer: key.verifying_key(), policy_file: "/unused-test-policy".into(),
            host: "fixture-host".into(), asset: "fixture-asset".into(), custodian: "fixture-custodian".into() };
        (key, InventoryRetirementPins::from_asset_authority(&authority).unwrap())
    }
    fn credential(id: u8, key: u8) -> EnrolledCredential {
        EnrolledCredential { credential_id: vec![id], key: CredentialKey::Ed25519(SigningKey::from_bytes(&[key; 32]).verifying_key()),
            aaguid: [7; 16], firmware_version: 1 }
    }
    fn identity(id: u8, key: u8) -> RetirementIdentity { RetirementIdentity::from_credential(&credential(id, key)).unwrap() }
    fn binding() -> RetirementBinding {
        RetirementBinding { profile: Profile::L3, source_v2_binding: [1; 32], pool_sha256: [2; 32], membership_id: [3; 32],
            membership_generation: 4, complete_sha256: [5; 32], complete_sequence: 6, policy_sha256: [7; 32],
            policy_revision: 8, receipt_floor: 9, target: identity(1, 1), survivor: identity(2, 2) }
    }
    fn now() -> RetirementObservation { RetirementObservation { lower_unix: 10, upper_unix: 11, authority_expires_unix: 100 } }
    fn retirement(pins: &InventoryRetirementPins, binding: &RetirementBinding, sequence: u64) -> RetirementStatement {
        RetirementStatement { version: 1, kind: "member_retirement".into(), inventory_scope_sha256: pins.scope,
            event_id: [sequence as u8; 32], event_sequence: sequence, binding: binding.clone(),
            issued_unix: 1, not_before_unix: 2, expires_unix: 90 }
    }
    fn sign_retirement(key: &SigningKey, statement: RetirementStatement) -> Vec<u8> {
        let signature = key.sign(&message(RETIRE_DOMAIN, &statement).unwrap()).to_bytes().to_vec();
        serde_json::to_vec(&SignedRetirement { statement, signature }).unwrap()
    }
    fn record(key: &SigningKey, pins: &InventoryRetirementPins, history: &mut RetirementHistory, binding: &RetirementBinding) -> Hash {
        let wire = sign_retirement(key, retirement(pins, binding, history.events.len() as u64 + 1));
        let verified = verify_retirement(&wire, pins, binding, history, now()).unwrap();
        let digest = verified.statement_sha256(); assert_eq!(verified.expires_unix(), 90);
        assert_eq!(history.append(pins, verified).unwrap(), RetirementAppend::Recorded); digest
    }
    fn replacement(binding: RetirementBinding, retired: Hash) -> ReplacementBinding {
        ReplacementBinding { proposed_membership_generation: binding.membership_generation + 1, current: binding,
            retirement_sha256: retired, replacement: identity(3, 3), replacement_pending_sha256: [10; 32],
            replacement_receipt_sha256: [11; 32], replacement_receipt_generation: 10, replacement_receipt_expires_unix: 80,
            survivor_receipt_sha256: [12; 32], survivor_receipt_expires_unix: 70, boot_epoch_sha256: [13; 32],
            running_code_sha256: [14; 32], release_policy_sha256: [15; 32], release_policy_revision: 16,
            release_policy_expires_unix: 60 }
    }
    fn replacement_statement(pins: &InventoryRetirementPins, binding: ReplacementBinding) -> ReplacementStatement {
        ReplacementStatement { version: 1, kind: "member_replacement_candidate".into(), inventory_scope_sha256: pins.scope,
            statement_id: [21; 32], binding, issued_unix: 1, not_before_unix: 2, expires_unix: 90 }
    }
    fn sign_replacement(key: &SigningKey, statement: ReplacementStatement) -> Vec<u8> {
        let signature = key.sign(&message(REPLACE_DOMAIN, &statement).unwrap()).to_bytes().to_vec();
        serde_json::to_vec(&SignedReplacement { statement, signature }).unwrap()
    }
    fn history_bytes(history: &RetirementHistory) -> Vec<u8> { serde_json::to_vec(history).unwrap() }

    #[test]
    fn checked_history_context_matches_real_statements_roundtrip_and_idempotent_replay() {
        let (key, pins) = authority(8); let binding = binding(); let mut history = RetirementHistory::empty(&pins);
        let empty = history.commitment(&pins).unwrap(); let before = history_bytes(&history);
        let sequence = history.next_event_sequence(&pins).unwrap(); assert_eq!(sequence, 1);
        assert_eq!(history_bytes(&history), before, "context reads do not reserve or burn an event");
        let wire = sign_retirement(&key, retirement(&pins, &binding, sequence));
        let verified = verify_retirement(&wire, &pins, &binding, &history, now()).unwrap();
        assert_eq!(verified.history_sha256, empty);
        let retired = verified.statement_sha256(); history.append(&pins, verified).unwrap();
        let current = history.commitment(&pins).unwrap(); assert_ne!(current, empty);
        assert_eq!(history.next_event_sequence(&pins).unwrap(), 2);
        let reopened: RetirementHistory = serde_json::from_slice(&history_bytes(&history)).unwrap();
        assert_eq!(reopened.commitment(&pins).unwrap(), current);
        assert_eq!(reopened.next_event_sequence(&pins).unwrap(), 2);
        let expected = replacement(binding.clone(), retired);
        let replacement_wire = sign_replacement(&key, replacement_statement(&pins, expected.clone()));
        assert_eq!(verify_replacement(&replacement_wire, &pins, &expected, &reopened, now()).unwrap().history_sha256(), current);
        let replay = verify_retirement(&wire, &pins, &binding, &history, now()).unwrap();
        assert_eq!(history.append(&pins, replay).unwrap(), RetirementAppend::AlreadyRecorded);
        assert_eq!(history.commitment(&pins).unwrap(), current);
        assert_eq!(history.next_event_sequence(&pins).unwrap(), 2);
    }
    #[test]
    fn checked_history_context_refuses_wrong_pins_and_malformed_authenticated_parent_body() {
        let (key, pins) = authority(8); let (_, wrong_pins) = authority(9);
        let mut history = RetirementHistory::empty(&pins); record(&key, &pins, &mut history, &binding());
        let before = history_bytes(&history);
        assert!(history.commitment(&wrong_pins).unwrap_err().is("RETIREMENT_HISTORY"));
        assert!(history.next_event_sequence(&wrong_pins).unwrap_err().is("RETIREMENT_HISTORY"));
        assert_eq!(history_bytes(&history), before);
        for case in 0..5 {
            let mut malformed = history.clone();
            match case { 0 => malformed.events[0].event_sequence += 1,
                1 => malformed.events[0].binding.target = identity(4, 4),
                2 => { malformed.tombstones.clear(); }, 3 => malformed.inventory_scope_sha256[0] ^= 1,
                _ => malformed.version += 1 }
            let body = history_bytes(&malformed);
            let reopened: RetirementHistory = serde_json::from_slice(&body).unwrap();
            assert!(reopened.commitment(&pins).is_err(), "case {case}");
            assert!(reopened.next_event_sequence(&pins).is_err(), "case {case}");
            assert_eq!(history_bytes(&reopened), body, "rejected context must not repair history");
        }
    }
    #[test]
    fn denial_only_exact_retirement_and_authenticated_parent_roundtrip_remain_permanent() {
        let (key, pins) = authority(8); let binding = binding(); let mut history = RetirementHistory::empty(&pins);
        let digest = record(&key, &pins, &mut history, &binding);
        assert!(nonzero(&digest)); assert!(history.denies(&pins, &binding.target).unwrap());
        assert!(!history.denies(&pins, &binding.survivor).unwrap());
        let reopened: RetirementHistory = serde_json::from_slice(&history_bytes(&history)).unwrap();
        reopened.validate(&pins).unwrap(); assert!(reopened.denies(&pins, &binding.target).unwrap());
        // History has no expiry removal/clear operation: no lost-member factor,
        // fresh lost-member receipt, wall clock or physical device was supplied.
        assert_eq!(reopened.events.len(), 1); assert_eq!(reopened.tombstones.len(), 1);
    }
    #[test]
    fn exact_credential_id_and_normalized_key_independently_deny_aliases() {
        let (key, pins) = authority(8); let binding = binding(); let mut history = RetirementHistory::empty(&pins);
        record(&key, &pins, &mut history, &binding);
        assert!(history.denies(&pins, &identity(1, 3)).unwrap(), "same ID, changed key");
        assert!(history.denies(&pins, &identity(3, 1)).unwrap(), "changed ID, same key");
        let mut changed_metadata = credential(1, 1); changed_metadata.firmware_version += 1; changed_metadata.aaguid = [6; 16];
        assert!(history.denies(&pins, &RetirementIdentity::from_credential(&changed_metadata).unwrap()).unwrap());
        assert!(!history.denies(&pins, &identity(3, 3)).unwrap(), "v1 cannot infer physical-device identity");
    }
    #[test]
    fn es256_compressed_uncompressed_aliases_and_invalid_id_or_weak_key() {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let public = p256::SecretKey::from_slice(&[9; 32]).unwrap().public_key();
        let mut first = credential(4, 4);
        first.key = CredentialKey::from_raw(-7, public.to_encoded_point(true).as_bytes()).unwrap();
        let mut second = first.clone(); second.credential_id = vec![5];
        second.key = CredentialKey::from_raw(-7, public.to_encoded_point(false).as_bytes()).unwrap();
        let a = RetirementIdentity::from_credential(&first).unwrap(); let b = RetirementIdentity::from_credential(&second).unwrap();
        assert!(a.aliases(&b)); assert_ne!(a.credential_id_sha256, b.credential_id_sha256);
        assert_eq!(a.normalized_key_sha256, b.normalized_key_sha256);
        first.credential_id.clear(); assert!(RetirementIdentity::from_credential(&first).is_err());
        first.credential_id = vec![1; 1024]; assert!(RetirementIdentity::from_credential(&first).is_err());
        first.credential_id = vec![1]; let mut weak = [0; 32]; weak[0] = 1;
        first.key = CredentialKey::Ed25519(ed25519_dalek::VerifyingKey::from_bytes(&weak).unwrap());
        assert!(RetirementIdentity::from_credential(&first).is_err());
    }
    #[test]
    fn every_current_binding_substitution_and_unknown_issuer_refuses() {
        let (key, pins) = authority(8); let (_, wrong_pins) = authority(9); let binding = binding();
        let history = RetirementHistory::empty(&pins); let wire = sign_retirement(&key, retirement(&pins, &binding, 1));
        assert!(verify_retirement(&wire, &wrong_pins, &binding, &RetirementHistory::empty(&wrong_pins), now()).is_err());
        for case in 0..14 {
            let mut expected = binding.clone();
            match case {
                0 => expected.source_v2_binding[0] ^= 1, 1 => expected.pool_sha256[0] ^= 1,
                2 => expected.membership_id[0] ^= 1, 3 => expected.membership_generation += 1,
                4 => expected.complete_sha256[0] ^= 1, 5 => expected.complete_sequence += 1,
                6 => expected.policy_sha256[0] ^= 1, 7 => expected.policy_revision += 1,
                8 => expected.receipt_floor += 1, 9 => expected.profile = Profile::L2,
                10 => expected.target = identity(4, 4), 11 => expected.survivor = identity(5, 5),
                12 => { let old = expected.target.clone(); expected.target = expected.survivor; expected.survivor = old; },
                _ => expected.profile = Profile::L1,
            }
            assert!(verify_retirement(&wire, &pins, &expected, &history, now()).is_err(), "case {case}");
        }
    }
    #[test]
    fn exact_replay_idempotent_and_eventid_sequence_aliases_or_stale_proofs_refuse() {
        let (key, pins) = authority(8); let binding = binding(); let mut history = RetirementHistory::empty(&pins);
        let wire = sign_retirement(&key, retirement(&pins, &binding, 1));
        let proof1 = verify_retirement(&wire, &pins, &binding, &history, now()).unwrap();
        let duplicate = verify_retirement(&wire, &pins, &binding, &history, now()).unwrap();
        let mut other_binding = binding.clone(); other_binding.target = identity(4, 4);
        let other_wire = sign_retirement(&key, retirement(&pins, &other_binding, 1));
        let stale = verify_retirement(&other_wire, &pins, &other_binding, &history, now()).unwrap();
        history.append(&pins, proof1).unwrap(); let before = history_bytes(&history);
        assert_eq!(history.append(&pins, duplicate).unwrap(), RetirementAppend::AlreadyRecorded);
        assert_eq!(history_bytes(&history), before);
        assert!(history.append(&pins, stale).unwrap_err().is("RETIREMENT_STALE_HISTORY"));
        assert!(verify_retirement(&other_wire, &pins, &other_binding, &history, now()).is_err());
        let mut reused_id = retirement(&pins, &other_binding, 2); reused_id.event_id = [1; 32];
        assert!(verify_retirement(&sign_retirement(&key, reused_id), &pins, &other_binding, &history, now()).is_err());
        let exact = verify_retirement(&wire, &pins, &binding, &history, now()).unwrap();
        assert_eq!(history.append(&pins, exact).unwrap(), RetirementAppend::AlreadyRecorded);
    }
    #[test]
    fn retired_target_or_survivor_alias_cannot_start_another_event() {
        let (key, pins) = authority(8); let binding = binding(); let mut history = RetirementHistory::empty(&pins);
        record(&key, &pins, &mut history, &binding);
        for (target, survivor) in [(identity(4, 1), identity(2, 2)), (identity(1, 4), identity(2, 2)),
            (identity(4, 4), identity(5, 1)), (identity(4, 4), identity(1, 5))] {
            let mut next = binding.clone(); next.target = target; next.survivor = survivor;
            let wire = sign_retirement(&key, retirement(&pins, &next, 2));
            assert!(verify_retirement(&wire, &pins, &next, &history, now()).is_err());
        }
    }
    #[test]
    fn earliest_authority_and_statement_expiry_future_clock_and_safe_integer_bounds() {
        let (key, pins) = authority(8); let binding = binding(); let history = RetirementHistory::empty(&pins);
        let wire = sign_retirement(&key, retirement(&pins, &binding, 1));
        for clock in [RetirementObservation { authority_expires_unix: 11, ..now() },
            RetirementObservation { upper_unix: 90, ..now() }, RetirementObservation { lower_unix: 1, upper_unix: 1, ..now() },
            RetirementObservation { lower_unix: -1, ..now() }, RetirementObservation { lower_unix: 12, upper_unix: 11, ..now() }] {
            assert!(verify_retirement(&wire, &pins, &binding, &history, clock).is_err());
        }
        assert_eq!(verify_retirement(&wire, &pins, &binding, &history, RetirementObservation { authority_expires_unix: 50, ..now() }).unwrap().expires_unix(), 50);
        for case in 0..4 {
            let mut s = retirement(&pins, &binding, 1);
            match case { 0 => s.issued_unix = 3, 1 => s.expires_unix = s.not_before_unix,
                2 => s.expires_unix = MAX_INTEGER as i64 + 1, _ => s.event_sequence = MAX_INTEGER + 1 }
            assert!(verify_retirement(&sign_retirement(&key, s), &pins, &binding, &history, now()).is_err());
        }
    }
    #[test]
    fn strict_schema_duplicate_escaped_unknown_fields_and_malformed_signatures() {
        let (key, pins) = authority(8); let binding = binding(); let history = RetirementHistory::empty(&pins);
        let wire = sign_retirement(&key, retirement(&pins, &binding, 1));
        let valid = String::from_utf8(wire.clone()).unwrap();
        for invalid in [valid.replacen("{", "{\"extra\":0,", 1),
            valid.replacen("\"version\":1", "\"version\":1,\"version\":1", 1),
            valid.replacen("\"version\":1", "\"version\":1,\"\\u0076ersion\":1", 1)] {
            assert!(verify_retirement(invalid.as_bytes(), &pins, &binding, &history, now()).unwrap_err().is("RETIREMENT_SCHEMA"));
        }
        for signature in [vec![], vec![0; 63], vec![0; 64], vec![0; 65]] {
            let invalid = serde_json::to_vec(&SignedRetirement { statement: retirement(&pins, &binding, 1), signature }).unwrap();
            assert!(verify_retirement(&invalid, &pins, &binding, &history, now()).unwrap_err().is("RETIREMENT_SIGNATURE"));
        }
        let mut cross_domain: SignedRetirement = serde_json::from_slice(&wire).unwrap();
        cross_domain.signature = key.sign(&message(REPLACE_DOMAIN, &cross_domain.statement).unwrap()).to_bytes().to_vec();
        assert!(verify_retirement(&serde_json::to_vec(&cross_domain).unwrap(), &pins, &binding, &history, now()).is_err());
        assert!(verify_retirement(&[], &pins, &binding, &history, now()).is_err());
        assert!(verify_retirement(&vec![b' '; MAX_WIRE + 1], &pins, &binding, &history, now()).is_err());
    }
    #[test]
    fn bounded_history_exhaustion_is_atomic_and_malformed_reopen_refuses() {
        let (key, pins) = authority(8); let mut history = RetirementHistory::empty(&pins);
        for n in 0..MAX_EVENTS {
            assert_eq!(history.next_event_sequence(&pins).unwrap(), n as u64 + 1);
            let mut next = binding(); next.target = identity(10 + n as u8, 10 + n as u8);
            next.membership_generation += n as u64; record(&key, &pins, &mut history, &next);
        }
        let before = history_bytes(&history); let mut next = binding(); next.target = identity(90, 90);
        assert!(history.next_event_sequence(&pins).unwrap_err().is("RETIREMENT_HISTORY_EXHAUSTED"));
        let exhausted_commitment = history.commitment(&pins).unwrap();
        assert_eq!(history_bytes(&history), before, "exhausted context remains immutable and auditable");
        let wire = sign_retirement(&key, retirement(&pins, &next, MAX_EVENTS as u64 + 1));
        let verified = verify_retirement(&wire, &pins, &next, &history, now()).unwrap();
        assert!(history.append(&pins, verified).unwrap_err().is("RETIREMENT_HISTORY_EXHAUSTED"));
        assert_eq!(history_bytes(&history), before);
        assert_eq!(history.commitment(&pins).unwrap(), exhausted_commitment);
        for case in 0..5 {
            let mut invalid = history.clone();
            match case { 0 => invalid.events[1].event_sequence = 1, 1 => invalid.events[1].event_id = invalid.events[0].event_id,
                2 => invalid.tombstones[1] = invalid.tombstones[0].clone(), 3 => { invalid.tombstones.pop(); },
                _ => invalid.inventory_scope_sha256[0] ^= 1 }
            let reopened: RetirementHistory = serde_json::from_slice(&history_bytes(&invalid)).unwrap();
            assert!(reopened.validate(&pins).is_err());
        }
    }
    #[test]
    fn replacement_is_separately_signed_exact_inert_candidate_with_earliest_expiry() {
        let (key, pins) = authority(8); let binding = binding(); let mut history = RetirementHistory::empty(&pins);
        let retired = record(&key, &pins, &mut history, &binding); let expected = replacement(binding, retired);
        let wire = sign_replacement(&key, replacement_statement(&pins, expected.clone()));
        let candidate = verify_replacement(&wire, &pins, &expected, &history, now()).unwrap();
        assert!(nonzero(&candidate.statement_sha256())); assert!(nonzero(&candidate.binding_sha256()));
        assert_eq!(candidate.history_sha256(), history.digest().unwrap()); assert_eq!(candidate.expires_unix(), 60);
        assert_eq!(history.events.len(), 1, "candidate does not burn/adopt/activate itself");
        // Reverification is deliberately inert. One-use burn/restart belongs to
        // the SAME parent's Preparing transition, never a second helper store.
        assert_eq!(verify_replacement(&wire, &pins, &expected, &history, now()).unwrap().statement_sha256(), candidate.statement_sha256());
        let mut cross_domain: SignedReplacement = serde_json::from_slice(&wire).unwrap();
        cross_domain.signature = key.sign(&message(RETIRE_DOMAIN, &cross_domain.statement).unwrap()).to_bytes().to_vec();
        assert!(verify_replacement(&serde_json::to_vec(&cross_domain).unwrap(), &pins, &expected, &history, now()).is_err());
    }
    #[test]
    fn replacement_every_intent_substitution_unknown_loss_and_alias_refuse() {
        let (key, pins) = authority(8); let binding = binding(); let mut history = RetirementHistory::empty(&pins);
        let retired = record(&key, &pins, &mut history, &binding); let expected = replacement(binding, retired);
        let wire = sign_replacement(&key, replacement_statement(&pins, expected.clone()));
        for case in 0..17 {
            let mut changed = expected.clone();
            match case {
                0 => changed.retirement_sha256[0] ^= 1, 1 => changed.replacement = identity(4, 4),
                2 => changed.replacement_pending_sha256[0] ^= 1, 3 => changed.replacement_receipt_sha256[0] ^= 1,
                4 => changed.replacement_receipt_generation += 1, 5 => changed.replacement_receipt_expires_unix += 1,
                6 => changed.survivor_receipt_sha256[0] ^= 1, 7 => changed.survivor_receipt_expires_unix += 1,
                8 => changed.proposed_membership_generation += 1, 9 => changed.boot_epoch_sha256[0] ^= 1,
                10 => changed.running_code_sha256[0] ^= 1, 11 => changed.release_policy_sha256[0] ^= 1,
                12 => changed.release_policy_revision += 1, 13 => changed.release_policy_expires_unix += 1,
                14 => changed.current.source_v2_binding[0] ^= 1, 15 => changed.current.membership_generation += 1,
                _ => changed.current.target = identity(4, 4),
            }
            assert!(verify_replacement(&wire, &pins, &changed, &history, now()).is_err(), "case {case}");
        }
        for alias in [identity(1, 4), identity(4, 1), identity(2, 4), identity(4, 2)] {
            let mut changed = expected.clone(); changed.replacement = alias;
            assert!(verify_replacement(&sign_replacement(&key, replacement_statement(&pins, changed.clone())), &pins, &changed, &history, now()).is_err());
        }
        assert!(verify_replacement(&wire, &pins, &expected, &RetirementHistory::empty(&pins), now()).is_err());
    }
    #[test]
    fn freshly_signed_replacement_cannot_change_origin_or_reuse_receipt_floor() {
        let (key, pins) = authority(8); let binding = binding(); let mut history = RetirementHistory::empty(&pins);
        let retired = record(&key, &pins, &mut history, &binding); let expected = replacement(binding, retired);
        for case in 0..10 {
            let mut changed = expected.clone();
            match case { 0 => changed.current.source_v2_binding[0] ^= 1, 1 => changed.current.pool_sha256[0] ^= 1,
                2 => changed.current.complete_sha256[0] ^= 1, 3 => changed.current.complete_sequence += 1,
                4 => changed.current.target = identity(5, 5), 5 => changed.current.survivor = identity(5, 5),
                6 => changed.current.profile = Profile::L2, 7 => changed.current.policy_revision -= 1,
                8 => changed.current.receipt_floor -= 1, _ => changed.replacement_receipt_generation = changed.current.receipt_floor }
            assert!(verify_replacement(&sign_replacement(&key, replacement_statement(&pins, changed.clone())), &pins, &changed, &history, now()).is_err(), "case {case}");
        }
        let mut advanced = expected; advanced.current.membership_generation += 1; advanced.proposed_membership_generation += 1;
        let wire = sign_replacement(&key, replacement_statement(&pins, advanced.clone()));
        verify_replacement(&wire, &pins, &advanced, &history, now()).unwrap();
    }
    #[test]
    fn replacement_each_independent_expiry_and_malformed_signature_refuses() {
        let (key, pins) = authority(8); let binding = binding(); let mut history = RetirementHistory::empty(&pins);
        let retired = record(&key, &pins, &mut history, &binding); let expected = replacement(binding, retired);
        for case in 0..5 {
            let mut changed = expected.clone(); let mut observed = now(); let mut expires = 90;
            match case { 0 => changed.replacement_receipt_expires_unix = 11, 1 => changed.survivor_receipt_expires_unix = 11,
                2 => changed.release_policy_expires_unix = 11, 3 => observed.authority_expires_unix = 11, _ => expires = 11 }
            let mut statement = replacement_statement(&pins, changed.clone()); statement.expires_unix = expires;
            assert!(verify_replacement(&sign_replacement(&key, statement), &pins, &changed, &history, observed).is_err());
        }
        let mut invalid = SignedReplacement { statement: replacement_statement(&pins, expected.clone()), signature: vec![0; 64] };
        assert!(verify_replacement(&serde_json::to_vec(&invalid).unwrap(), &pins, &expected, &history, now()).is_err());
        invalid.signature = vec![0; 65];
        assert!(verify_replacement(&serde_json::to_vec(&invalid).unwrap(), &pins, &expected, &history, now()).is_err());
    }
}
