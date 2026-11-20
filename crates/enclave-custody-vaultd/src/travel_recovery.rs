//! Inactive HW §7.2.1 travel-token verification and durable one-use burn.
//!
//! No service, boot, profile switch, signer, factor waiver or tier-key API uses
//! this module. A returned candidate is not an activation authority. Integration
//! still needs the real release fence, explicit audited profile transition,
//! current enterprise admission, independent signer provisioning and no A4/C4.
//! This candidate roster format is not approval of a production protocol.
//!
//! Token preimage: SHA-256(RFC8785-JCS(the exact nine token fields other than
//! quorum)). Each ed25519_sig is a lowercase 64-byte hex Ed25519 signature of
//! that 32-byte digest, not CTAP authenticatorData, SEP approval or TUF bytes.
//! Replay identity is that digest, independent of signature order/subsets.
use std::{cell::Cell, collections::{BTreeMap, BTreeSet}, path::Path};
use ed25519_dalek::{Signature, VerifyingKey};
use enclave_core::{err, error::EnclaveResult, fail, sealed::{Loaded, SealedStore, StateDirectoryLease}};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::clock::Clock;
use crate::service::{TravelAnchorPin,TravelAnchorObservation,TravelRecoveryAnchor};

const MAX_WIRE: usize = 128 * 1024;
const MAX_STATE: usize = 4 * 1024 * 1024;
const MAX_MEMBERS: usize = 32;
// Keep even maximum-length historical IDs well within the sealed envelope.
// Exhaustion is terminal rather than pruning revocations or consumed tokens.
const MAX_HISTORY: usize = 256;
const MAX_REVOKED: usize = 256;
const MAX_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_TTL_MS: u64 = 72 * 3_600_000;

fn digest(bytes: &[u8]) -> [u8; 32] { Sha256::digest(bytes).into() }
fn canonical(value: &impl Serialize) -> EnclaveResult<Vec<u8>> { enclave_core::jcs::to_jcs_bytes(value) }
fn text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}
fn hex_bytes(value: &str, minimum: usize, maximum: usize) -> EnclaveResult<Vec<u8>> {
    if value.len() % 2 != 0 || value.len() < minimum * 2 || value.len() > maximum * 2
        || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        fail!(EINVAL, "TRAVEL_HEX");
    }
    hex::decode(value).map_err(|_| err!(EINVAL, "TRAVEL_HEX"))
}
fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> EnclaveResult<T> {
    if bytes.is_empty() || bytes.len() > MAX_WIRE { fail!(E2BIG, "TRAVEL_INPUT_SIZE"); }
    // All untrusted JSON is typed, closed and unflattened. serde rejects
    // duplicate fields, including escaped duplicate names, before conversion.
    serde_json::from_slice(bytes).map_err(|_| err!(EINVAL, "TRAVEL_SCHEMA"))
}
fn public_key(encoded: &str) -> EnclaveResult<VerifyingKey> {
    let bytes: [u8; 32] = hex_bytes(encoded, 32, 32)?.try_into().map_err(|_| err!(EINVAL, "TRAVEL_KEY"))?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| err!(EINVAL, "TRAVEL_KEY"))?;
    if key.is_weak() || key.to_edwards().compress().to_bytes() != bytes { fail!(EACCES, "TRAVEL_KEY"); }
    Ok(key)
}
fn signature(key: &VerifyingKey, message: &[u8], encoded: &str) -> EnclaveResult<()> {
    let signature = Signature::from_slice(&hex_bytes(encoded, 64, 64)?)
        .map_err(|_| err!(EACCES, "TRAVEL_SIGNATURE"))?;
    key.verify_strict(message, &signature).map_err(|_| err!(EACCES, "TRAVEL_SIGNATURE"))
}

/// Fixed administrator-provisioned trust, never read from the submitted token.
/// Exact configured SecOps threshold is retained and cannot be below two.
#[derive(Clone)]
pub(crate) struct TravelAuthorityPins {
    issuer_id: String,
    issuer: VerifyingKey,
    subject: String,
    device: String,
    threshold: usize,
    maximum_authority_age_ms: u64,
}
impl TravelAuthorityPins {
    pub(crate) fn new(issuer_id: String, issuer: VerifyingKey, subject: String, device: String,
        threshold: usize, maximum_authority_age_ms: u64) -> EnclaveResult<Self> {
        if !text(&issuer_id, 128) || !text(&subject, 1024) || !subject.starts_with("spiffe://")
            || !text(&device, 256) || !(2..=MAX_MEMBERS).contains(&threshold)
            || maximum_authority_age_ms == 0 || maximum_authority_age_ms > MAX_TTL_MS {
            fail!(EACCES, "TRAVEL_TRUST_PINS");
        }
        public_key(&hex::encode(issuer.to_bytes()))?;
        Ok(Self { issuer_id, issuer, subject, device, threshold, maximum_authority_age_ms })
    }
    fn commitment(&self) -> EnclaveResult<[u8; 32]> {
        canonical(&("depot.travel-pins.v1", &self.issuer_id, hex::encode(self.issuer.to_bytes()),
            &self.subject, &self.device, self.threshold, self.maximum_authority_age_ms)).map(|bytes| digest(&bytes))
    }
}

// Candidate independently issuer-signed roster. Fixed SecOps role, explicit
// validity and revocation are checked here; signer hardware/isolation is not.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Custodian {
    custodian_credential_id: String,
    ed25519_public_key: String,
    role: String,
    not_before_utc_ms: u64,
    not_after_utc_ms: u64,
    revoked: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    v: u8,
    kind: String,
    issuer_id: String,
    revision: u64,
    subject_spiffe_id: String,
    device_serial: String,
    issued_utc_ms: u64,
    not_before_utc_ms: u64,
    not_after_utc_ms: u64,
    threshold: usize,
    custodians: Vec<Custodian>,
    revoked_token_sha256: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedAuthority { authority: Authority, ed25519_sig: String }
impl Authority {
    fn signing_message(&self) -> EnclaveResult<Vec<u8>> {
        let body = canonical(self)?;
        let mut message = b"depot-TravelAuthority-v1\0".to_vec();
        message.extend_from_slice(&(body.len() as u32).to_be_bytes()); message.extend(body); Ok(message)
    }
    fn shape(&self, pins: &TravelAuthorityPins) -> EnclaveResult<()> {
        if self.v != 1 || self.kind != "depot.travel-authority.v1" || self.issuer_id != pins.issuer_id
            || self.subject_spiffe_id != pins.subject || self.device_serial != pins.device
            || self.revision == 0 || self.revision > MAX_INTEGER || self.threshold != pins.threshold
            || self.custodians.len() < pins.threshold || self.custodians.len() > MAX_MEMBERS
            || self.revoked_token_sha256.len() > MAX_REVOKED || self.issued_utc_ms > MAX_INTEGER
            || self.not_before_utc_ms < self.issued_utc_ms || self.not_after_utc_ms <= self.not_before_utc_ms
            || self.not_after_utc_ms > MAX_INTEGER {
            fail!(EACCES, "TRAVEL_AUTHORITY_SCOPE");
        }
        let mut ids = BTreeSet::new(); let mut keys = BTreeSet::new(); let mut revoked = BTreeSet::new();
        for member in &self.custodians {
            hex_bytes(&member.custodian_credential_id, 1, 1023)?;
            let key = public_key(&member.ed25519_public_key)?;
            if !ids.insert(&member.custodian_credential_id) || !keys.insert(key.to_bytes()) || member.role != "SecOps"
                || member.not_before_utc_ms < self.not_before_utc_ms || member.not_after_utc_ms > self.not_after_utc_ms
                || member.not_after_utc_ms <= member.not_before_utc_ms {
                fail!(EACCES, "TRAVEL_ROSTER");
            }
        }
        for token in &self.revoked_token_sha256 {
            hex_bytes(token, 32, 32)?; if !revoked.insert(token) { fail!(EACCES, "TRAVEL_ROSTER"); }
        }
        Ok(())
    }
    fn until(&self, pins: &TravelAuthorityPins) -> EnclaveResult<u64> {
        let freshness = self.issued_utc_ms.checked_add(pins.maximum_authority_age_ms)
            .filter(|end| *end <= MAX_INTEGER).ok_or_else(|| err!(EACCES, "TRAVEL_AUTHORITY_EXPIRED"))?;
        Ok(self.not_after_utc_ms.min(freshness))
    }
    fn current(&self, pins: &TravelAuthorityPins, now: Observation) -> EnclaveResult<()> {
        if now.lower_ms < self.not_before_utc_ms || now.upper_ms >= self.until(pins)? {
            fail!(EACCES, "TRAVEL_AUTHORITY_EXPIRED");
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval { custodian_credential_id: String, ed25519_sig: String }
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Token {
    v: u8,
    kind: String,
    subject_spiffe_id: String,
    device_serial: String,
    from_profile: String,
    to_profile: String,
    not_before_utc_ms: u64,
    not_after_utc_ms: u64,
    reason_ticket: String,
    quorum: Vec<Approval>,
}
#[derive(Serialize)]
struct UnsignedToken<'a> {
    v: u8, kind: &'a str, subject_spiffe_id: &'a str, device_serial: &'a str,
    from_profile: &'a str, to_profile: &'a str, not_before_utc_ms: u64,
    not_after_utc_ms: u64, reason_ticket: &'a str,
}
impl Token {
    fn unsigned(&self) -> UnsignedToken<'_> {
        UnsignedToken { v: self.v, kind: &self.kind, subject_spiffe_id: &self.subject_spiffe_id,
            device_serial: &self.device_serial, from_profile: &self.from_profile, to_profile: &self.to_profile,
            not_before_utc_ms: self.not_before_utc_ms, not_after_utc_ms: self.not_after_utc_ms,
            reason_ticket: &self.reason_ticket }
    }
    fn identity(&self) -> EnclaveResult<[u8; 32]> { canonical(&self.unsigned()).map(|bytes| digest(&bytes)) }
    fn verify(&self, pins: &TravelAuthorityPins, authority: &Authority, journal: &Journal, now: Observation) -> EnclaveResult<u64> {
        if self.v != 1 || self.kind != "travel_downgrade" || self.subject_spiffe_id != pins.subject
            || self.device_serial != pins.device || self.from_profile != "L3" || self.to_profile != "L2"
            || self.not_after_utc_ms > MAX_INTEGER || self.not_before_utc_ms >= self.not_after_utc_ms
            || self.not_after_utc_ms - self.not_before_utc_ms > MAX_TTL_MS || !text(&self.reason_ticket, 256)
            || self.quorum.len() < pins.threshold || self.quorum.len() > MAX_MEMBERS {
            fail!(EACCES, "TRAVEL_TOKEN_SCOPE");
        }
        if now.lower_ms < self.not_before_utc_ms || now.upper_ms >= self.not_after_utc_ms {
            fail!(EACCES, "TRAVEL_TOKEN_EXPIRED");
        }
        let token = self.identity()?; let encoded = hex::encode(token);
        if journal.revoked_tokens.contains(&encoded) || authority.revoked_token_sha256.contains(&encoded) {
            fail!(EACCES, "TRAVEL_REVOKED");
        }
        let mut seen = BTreeSet::new(); let mut until = self.not_after_utc_ms.min(authority.until(pins)?);
        for approval in &self.quorum {
            if !seen.insert(&approval.custodian_credential_id) { fail!(EACCES, "TRAVEL_DUPLICATE_APPROVAL"); }
            let member = authority.custodians.iter().find(|member| member.custodian_credential_id == approval.custodian_credential_id)
                .ok_or_else(|| err!(EACCES, "TRAVEL_UNKNOWN_CUSTODIAN"))?;
            if member.revoked || journal.revoked_ids.contains(&member.custodian_credential_id)
                || journal.revoked_keys.contains(&member.ed25519_public_key) || now.lower_ms < member.not_before_utc_ms
                || now.upper_ms >= member.not_after_utc_ms {
                fail!(EACCES, "TRAVEL_REVOKED");
            }
            signature(&public_key(&member.ed25519_public_key)?, &token, &approval.ed25519_sig)?;
            until = until.min(member.not_after_utc_ms);
        }
        Ok(until)
    }
}

#[derive(Clone, Copy)]
struct Observation { boot_ns: u64, lower_ms: u64, upper_ms: u64 }
impl Observation {
    fn capture(clock: &dyn Clock) -> EnclaveResult<Self> {
        // Clock exposes integer seconds. Charge the complete unknown fraction
        // against expiry, sampling boot first to keep the captured bound early.
        let boot_ns = clock.now_ns();
        let lower_ms = u64::try_from(clock.now_unix()).ok().and_then(|seconds| seconds.checked_mul(1000))
            .ok_or_else(|| err!(EACCES, "TRAVEL_CLOCK"))?;
        let upper_ms = lower_ms.checked_add(999).filter(|upper| *upper <= MAX_INTEGER)
            .ok_or_else(|| err!(EACCES, "TRAVEL_CLOCK"))?;
        Ok(Self { boot_ns, lower_ms, upper_ms })
    }
}
struct Window { start: Observation, until_ms: u64, deadline_ns: u64 }
impl Window {
    fn new(start: Observation, until_ms: u64) -> EnclaveResult<Self> {
        let remaining = until_ms.checked_sub(start.upper_ms).filter(|remaining| *remaining > 0)
            .and_then(|remaining| remaining.checked_mul(1_000_000)).ok_or_else(|| err!(ETIMEDOUT, "TRAVEL_DEADLINE"))?;
        let cap = start.boot_ns.checked_add(crate::ceremony::CEREMONY_BUDGET_NS)
            .ok_or_else(|| err!(ETIMEDOUT, "TRAVEL_DEADLINE"))?;
        let deadline_ns = start.boot_ns.checked_add(remaining).ok_or_else(|| err!(ETIMEDOUT, "TRAVEL_DEADLINE"))?.min(cap);
        Ok(Self { start, until_ms, deadline_ns })
    }
    fn shorten(&mut self, until_ms: u64) -> EnclaveResult<()> {
        let shorter = Self::new(self.start, self.until_ms.min(until_ms))?;
        self.until_ms = shorter.until_ms; self.deadline_ns = self.deadline_ns.min(shorter.deadline_ns); Ok(())
    }
    fn check(&self, now: Observation) -> EnclaveResult<()> {
        if now.boot_ns < self.start.boot_ns || now.boot_ns >= self.deadline_ns
            || now.lower_ms < self.start.lower_ms || now.upper_ms >= self.until_ms {
            fail!(ETIMEDOUT, "TRAVEL_DEADLINE");
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    v: u8,
    pins_sha256: [u8; 32],
    attempt: u64,
    authority_revision: u64,
    authority_sha256: Option<[u8; 32]>,
    wall_floor_ms: u64,
    history_exhausted: bool,
    consumed: BTreeMap<String, u64>,
    known_keys: BTreeMap<String, String>,
    revoked_ids: BTreeSet<String>,
    revoked_keys: BTreeSet<String>,
    revoked_tokens: BTreeSet<String>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    service:Option<ServiceJournal>,
}
#[derive(Clone,PartialEq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceJournal {
    scope:[u8;32],generation:u64,previous:TravelAnchorPin,
    active:Option<ActiveTransition>,
    commit_before_utc_ms:Option<u64>,
}
#[derive(Clone,PartialEq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveTransition {
    token:Token,token_sha256:[u8;32],authority_sha256:[u8;32],
    valid_until_utc_ms:u64,original_scope:[u8;32],
    audit:enclave_core::audit::EnclaveAuditEnvelopeV1,
}
impl Journal {
    fn fresh(pins_sha256: [u8; 32]) -> Self {
        Self { v: 1, pins_sha256, attempt: 0, authority_revision: 0, authority_sha256: None,
            wall_floor_ms: 0, history_exhausted: false, consumed: BTreeMap::new(), known_keys: BTreeMap::new(),
            revoked_ids: BTreeSet::new(), revoked_keys: BTreeSet::new(), revoked_tokens: BTreeSet::new(),service:None }
    }
    fn shape(&self, pins: [u8; 32]) -> EnclaveResult<()> {
        if self.v != 1 || self.pins_sha256 != pins || self.attempt > MAX_INTEGER || self.authority_revision > MAX_INTEGER
            || (self.authority_revision == 0) != self.authority_sha256.is_none() || self.wall_floor_ms > MAX_INTEGER
            || self.consumed.len() > MAX_HISTORY || self.known_keys.len() > MAX_HISTORY
            || self.revoked_ids.len() > MAX_HISTORY || self.revoked_keys.len() > MAX_HISTORY || self.revoked_tokens.len() > MAX_HISTORY {
            fail!(EACCES, "TRAVEL_JOURNAL");
        }
        let mut attempts = BTreeSet::new();
        for (token, attempt) in &self.consumed {
            hex_bytes(token, 32, 32)?;
            if *attempt == 0 || *attempt > self.attempt || !attempts.insert(attempt) { fail!(EACCES, "TRAVEL_JOURNAL"); }
        }
        if self.attempt != self.consumed.len() as u64 { fail!(EACCES, "TRAVEL_JOURNAL"); }
        for (id, key) in &self.known_keys { hex_bytes(id, 1, 1023)?; public_key(key)?; }
        for id in &self.revoked_ids { hex_bytes(id, 1, 1023)?; }
        for key in &self.revoked_keys { public_key(key)?; }
        for token in &self.revoked_tokens { hex_bytes(token, 32, 32)?; }
        if let Some(service)=&self.service {
            if service.generation==0||service.previous.generation.checked_add(1)!=Some(service.generation) {fail!(EACCES,"TRAVEL_ANCHOR_STATE");}
            if let Some(active)=&service.active {
                if active.token.identity()?!=active.token_sha256
                    ||!self.consumed.contains_key(&hex::encode(active.token_sha256))
                    ||active.valid_until_utc_ms>active.token.not_after_utc_ms
                    ||active.valid_until_utc_ms<=active.token.not_before_utc_ms {fail!(EACCES,"TRAVEL_ACTIVE_STATE");}
                active.audit.validate()?;
            }
        }
        Ok(())
    }
}

/// Runtime-only, move-only and inactive; a restart can never recreate it.
pub(crate) struct InactiveTravelPermit {
    token: Token,
    identity: [u8; 32],
    attempt: u64,
    nonce: [u8; 32],
    window: Window,
}
impl std::fmt::Debug for InactiveTravelPermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InactiveTravelPermit").field("attempt", &self.attempt).finish_non_exhaustive()
    }
}
/// Public non-secret staging facts, still no profile/lease/key authority. The
/// actual transition must independently log its EnclaveAuditEnvelopeV1 first.
pub(crate) struct InactiveTravelCandidate {
    token_sha256: [u8; 32],
    authority_sha256: [u8; 32],
    valid_until_utc_ms: u64,
    deadline_ns: u64,
    signers: usize,
    token:Token,
}
impl std::fmt::Debug for InactiveTravelCandidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InactiveTravelCandidate").field("signers", &self.signers).finish_non_exhaustive()
    }
}
impl InactiveTravelCandidate {
    pub(crate) fn audit_payload(&self) -> serde_json::Value {
        serde_json::json!({"event":"TRAVEL_TOKEN_CONSUMED_INACTIVE", "token_sha256":hex::encode(self.token_sha256),
            "authority_sha256":hex::encode(self.authority_sha256),"from_profile":"L3","to_profile":"L2",
            "valid_until_utc_ms":self.valid_until_utc_ms,"deadline_ns":self.deadline_ns,"signers":self.signers,
            "permits_a4":false,"permits_c4":false})
    }
    pub(crate) fn activation_payload(&self,original_scope:[u8;32],simulated:bool)->serde_json::Value {
        serde_json::json!({"event":"TRAVEL_DOWNGRADE_AUTHORIZED","token_sha256":hex::encode(self.token_sha256),
            "authority_sha256":hex::encode(self.authority_sha256),"original_scope_sha256":hex::encode(original_scope),
            "configured_profile":"L3","effective_profile":"L2","valid_until_utc_ms":self.valid_until_utc_ms,
            "signers":self.signers,"permits_a3":false,"permits_a4":false,"permits_c4":false,"simulated_hw":simulated})
    }
    pub(crate) fn deadline_ns(&self)->u64 {self.deadline_ns}
    pub(crate) fn shorten_operation_deadline(&mut self,deadline_ns:u64) {self.deadline_ns=self.deadline_ns.min(deadline_ns);}
    pub(crate) fn shorten(&mut self,until_utc_ms:u64)->EnclaveResult<()> {
        self.valid_until_utc_ms=self.valid_until_utc_ms.min(until_utc_ms);
        if self.valid_until_utc_ms<=self.token.not_before_utc_ms {fail!(EACCES,"TRAVEL_TOKEN_EXPIRED");}Ok(())
    }
}

/// One exclusive, bounded own-seed sealed candidate journal. Partial rollback is
/// detected; a privileged replacement of the whole local directory is outside
/// SealedStore's protection and requires a separately provisioned durable anchor.
pub(crate) struct TravelRecoveryStore {
    _lease: StateDirectoryLease,
    store: SealedStore,
    pins: TravelAuthorityPins,
    journal: Journal,
    observed_wall_ms: Cell<u64>,
    observed_boot_ns: Cell<Option<u64>>,
    live: Option<[u8; 32]>,
    faulted: bool,
    anchor:Option<ServiceAnchor>,
}
struct ServiceAnchor {
    provider:Box<dyn TravelRecoveryAnchor>,pin:TravelAnchorPin,scope:[u8;32],
    observation:TravelAnchorObservation,observed_boot_ns:u64,observed_boot_after_ns:u64,
    commit_before_utc_ms:Option<u64>,
}
/// A current explicit public-action exception, not a ceremony or key grant.
/// Constructor is private; revalidation can only shorten this owner's bounds.
#[derive(Clone)]
pub(crate) struct TravelSession {
    pub(crate) token_sha256:[u8;32],
    pub(crate) valid_until_utc_ms:u64,
    pub(crate) deadline_ns:u64,
    pub(crate) original_scope:[u8;32],
}
impl std::fmt::Debug for TravelSession {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.debug_struct("TravelSession").finish_non_exhaustive()}
}
impl TravelRecoveryStore {
    pub(crate) fn service_transition_attempted(&self)->bool {
        !self.journal.consumed.is_empty()||self.journal.service.as_ref().is_some_and(|service|service.active.is_some())
    }
    /// Validate newly shortened caller bounds through the existing independent
    /// trusted-time mapping before appending an authorization audit record.
    /// The actual activation still refreshes/rechecks before its durable CAS.
    pub(crate) fn check_service_candidate_deadlines(&self,candidate:&InactiveTravelCandidate,clock:&dyn Clock)->EnclaveResult<()> {
        let now=self.observe(clock)?;
        if now.boot_ns>=candidate.deadline_ns||now.upper_ms>=candidate.valid_until_utc_ms {fail!(ETIMEDOUT,"TRAVEL_DEADLINE");}
        Ok(())
    }
    /// Independent service store: unlike the inactive candidate journal, every
    /// write, including failed-token revocation/consumption observations, joins
    /// one external exact-state CAS. An old inactive reader cannot open it.
    pub(crate) fn open_anchored(state:&Path,pins:TravelAuthorityPins,original_scope:[u8;32],
        mut provider:Box<dyn TravelRecoveryAnchor>)->EnclaveResult<Self> {
        let scope=digest(&canonical(&("depot.travel-service.v1",pins.commitment()?,original_scope))?);
        let observed_boot_ns=crate::clock::SystemClock.now_ns();let observation=provider.load(scope)?;
        let observed_boot_after_ns=crate::clock::SystemClock.now_ns();
        Self::validate_anchor_observation(observation)?;
        let directory=state.join("travel-recovery-service");let lease=StateDirectoryLease::acquire(&directory)?;
        let (store,loaded)=SealedStore::open_bounded_required(&directory,"travel",MAX_STATE)?;
        let fresh=matches!(&loaded,Loaded::Fresh);
        let journal=match loaded {
            Loaded::Fresh=>{
                if observation.pin!=TravelAnchorPin::default() {fail!(EACCES,"TRAVEL_ANCHOR_ROLLBACK");}
                let mut journal=Journal::fresh(pins.commitment()?);
                journal.service=Some(ServiceJournal {scope,generation:0,previous:TravelAnchorPin::default(),active:None,commit_before_utc_ms:None});journal
            },
            Loaded::State(bytes)=>{
                let journal:Journal=enclave_core::sealed::decode(&bytes)?;
                if canonical(&journal)?!=bytes {fail!(EACCES,"TRAVEL_ANCHOR_STATE");}journal
            },
        };
        let wall=journal.wall_floor_ms;
        let mut result=Self {_lease:lease,store,pins,journal,observed_wall_ms:Cell::new(wall),
            observed_boot_ns:Cell::new(None),live:None,faulted:false,
            anchor:Some(ServiceAnchor {provider,pin:observation.pin,scope,observation,observed_boot_ns,observed_boot_after_ns,commit_before_utc_ms:None})};
        if fresh {result.persist(result.journal.clone())?;} else {
            result.journal.shape(result.pins.commitment()?)?;
            let service=result.journal.service.as_ref().ok_or_else(||err!(EACCES,"TRAVEL_ANCHOR_STATE"))?;
            if service.scope!=scope {fail!(EACCES,"TRAVEL_ANCHOR_SCOPE");}
            let saved=TravelAnchorPin {generation:service.generation,journal_sha256:digest(&canonical(&result.journal)?)};
            if saved!=observation.pin {
                // A crash may leave exactly the authenticated saved successor.
                // Never repair an older, divergent or arbitrary local restore.
                if service.previous!=observation.pin||observation.pin.generation.checked_add(1)!=Some(saved.generation) {fail!(EACCES,"TRAVEL_ANCHOR_ROLLBACK");}
                let anchor=result.anchor.as_mut().unwrap();let before=crate::clock::SystemClock.now_ns();
                let next=anchor.provider.compare_and_advance(scope,observation.pin,saved,service.commit_before_utc_ms)?;
                Self::validate_anchor_observation(next)?;if next.pin!=saved {fail!(EACCES,"TRAVEL_ANCHOR_ROLLBACK");}
                anchor.pin=saved;anchor.observation=next;anchor.observed_boot_ns=before;anchor.observed_boot_after_ns=crate::clock::SystemClock.now_ns();
            }
            result.refresh_anchor()?;
        }Ok(result)
    }
    fn validate_anchor_observation(observation:TravelAnchorObservation)->EnclaveResult<()> {
        if observation.trusted_lower_utc_ms>observation.trusted_upper_utc_ms
            ||observation.trusted_upper_utc_ms-observation.trusted_lower_utc_ms>1000
            ||observation.trusted_upper_utc_ms>MAX_INTEGER
            ||(observation.pin.generation==0)!=(observation.pin.journal_sha256==[0;32]) {fail!(EACCES,"TRAVEL_ANCHOR_OBSERVATION");}Ok(())
    }
    fn refresh_anchor(&mut self)->EnclaveResult<()> {
        self.healthy()?;
        let Some(anchor)=self.anchor.as_mut() else {fail!(EACCES,"TRAVEL_INDEPENDENT_ANCHOR_REQUIRED");};
        let before=crate::clock::SystemClock.now_ns();self.faulted=true;
        let observed=anchor.provider.load(anchor.scope)?;Self::validate_anchor_observation(observed)?;
        if observed.pin!=anchor.pin||observed.trusted_upper_utc_ms<anchor.observation.trusted_lower_utc_ms
            ||observed.trusted_upper_utc_ms<self.journal.wall_floor_ms {fail!(EACCES,"TRAVEL_ANCHOR_ROLLBACK");}
        anchor.observation=observed;anchor.observed_boot_ns=before;anchor.observed_boot_after_ns=crate::clock::SystemClock.now_ns();self.faulted=false;Ok(())
    }
    pub(crate) fn open(state: &Path, pins: TravelAuthorityPins) -> EnclaveResult<Self> {
        let directory = state.join("travel-recovery-candidate");
        let lease = StateDirectoryLease::acquire(&directory)?;
        let (mut store, loaded) = SealedStore::open_bounded_required(&directory, "burns", MAX_STATE)?;
        let journal = match loaded {
            Loaded::Fresh => { let journal = Journal::fresh(pins.commitment()?); store.save_json(&journal)?; journal }
            Loaded::State(bytes) => enclave_core::sealed::decode::<Journal>(&bytes)?,
        };
        journal.shape(pins.commitment()?)?;
        if journal.service.is_some() {fail!(EACCES,"TRAVEL_INDEPENDENT_ANCHOR_REQUIRED");}
        let observed_wall_ms = Cell::new(journal.wall_floor_ms);
        Ok(Self { _lease: lease, store, pins, journal, observed_wall_ms,
            observed_boot_ns: Cell::new(None), live: None, faulted: false,anchor:None })
    }
    fn healthy(&self) -> EnclaveResult<()> {
        if self.faulted { fail!(EIO, "TRAVEL_PERSISTENCE_UNCERTAIN"); }
        if self.journal.history_exhausted { fail!(EACCES, "TRAVEL_HISTORY_FULL"); } Ok(())
    }
    fn observe(&self, clock: &dyn Clock) -> EnclaveResult<Observation> {
        let mut now = Observation::capture(clock)?;
        if let Some(anchor)=&self.anchor {
            let elapsed=now.boot_ns.checked_sub(anchor.observed_boot_ns).ok_or_else(||err!(EACCES,"TRAVEL_CLOCK"))?/1_000_000;
            let elapsed_after=now.boot_ns.checked_sub(anchor.observed_boot_after_ns).ok_or_else(||err!(EACCES,"TRAVEL_CLOCK"))?/1_000_000;
            now.lower_ms=anchor.observation.trusted_lower_utc_ms.checked_add(elapsed_after).ok_or_else(||err!(EACCES,"TRAVEL_CLOCK"))?;
            now.upper_ms=now.upper_ms.max(anchor.observation.trusted_upper_utc_ms.checked_add(elapsed).ok_or_else(||err!(EACCES,"TRAVEL_CLOCK"))?);
        }
        if now.lower_ms < self.journal.wall_floor_ms.max(self.observed_wall_ms.get())
            || self.observed_boot_ns.get().is_some_and(|previous| now.boot_ns < previous) {
            fail!(EACCES, "TRAVEL_CLOCK");
        }
        // Include final post-save observations too. Otherwise a later call can
        // move back behind a time already accepted by this owner while still
        // passing the older durable checkpoint's wall floor.
        self.observed_wall_ms.set(now.lower_ms); self.observed_boot_ns.set(Some(now.boot_ns)); Ok(now)
    }
    fn persist(&mut self, mut next: Journal) -> EnclaveResult<()> {
        next.wall_floor_ms = next.wall_floor_ms.max(self.observed_wall_ms.get());
        if let Some(anchor)=&self.anchor {
            let service=next.service.as_mut().ok_or_else(||err!(EACCES,"TRAVEL_ANCHOR_STATE"))?;
            if service.scope!=anchor.scope {fail!(EACCES,"TRAVEL_ANCHOR_SCOPE");}
            service.previous=anchor.pin;service.generation=anchor.pin.generation.checked_add(1).ok_or_else(||err!(EACCES,"TRAVEL_ANCHOR_GENERATION"))?;
            service.commit_before_utc_ms=anchor.commit_before_utc_ms;
        } else if next.service.is_some() {fail!(EACCES,"TRAVEL_INDEPENDENT_ANCHOR_REQUIRED");}
        self.live = None; next.shape(self.pins.commitment()?)?;
        if serde_json::to_vec(&next).map_err(|_| err!(EIO, "TRAVEL_ENCODE"))?.len() > MAX_STATE / 2 {
            fail!(E2BIG, "TRAVEL_HISTORY_FULL");
        }
        self.faulted = true; self.journal = next;
        if let Some(anchor)=self.anchor.as_mut() {
            let bytes=canonical(&self.journal)?;let next=TravelAnchorPin {generation:self.journal.service.as_ref().unwrap().generation,journal_sha256:digest(&bytes)};
            self.store.save(&bytes)?;let before=crate::clock::SystemClock.now_ns();
            let observed=anchor.provider.compare_and_advance(anchor.scope,anchor.pin,next,anchor.commit_before_utc_ms)?;
            Self::validate_anchor_observation(observed)?;
            if observed.pin!=next||observed.trusted_upper_utc_ms<anchor.observation.trusted_lower_utc_ms {fail!(EACCES,"TRAVEL_ANCHOR_ROLLBACK");}
            anchor.pin=next;anchor.observation=observed;anchor.observed_boot_ns=before;anchor.observed_boot_after_ns=crate::clock::SystemClock.now_ns();
        } else {self.store.save_json(&self.journal)?;}
        self.faulted = false; Ok(())
    }
    fn current_authority(&mut self, source: &mut impl FnMut() -> EnclaveResult<Vec<u8>>, clock: &dyn Clock)
        -> EnclaveResult<(Authority, [u8; 32])> {
        self.healthy()?;
        let signed: SignedAuthority = parse(&source()?)?;
        signed.authority.shape(&self.pins)?;
        signature(&self.pins.issuer, &signed.authority.signing_message()?, &signed.ed25519_sig)?;
        let now = self.observe(clock)?;
        signed.authority.current(&self.pins, now)?;
        let policy_digest = digest(&canonical(&signed.authority)?);
        if signed.authority.revision < self.journal.authority_revision
            || (signed.authority.revision == self.journal.authority_revision && self.journal.authority_sha256 != Some(policy_digest)) {
            fail!(EACCES, "TRAVEL_AUTHORITY_ROLLBACK");
        }
        let mut next = self.journal.clone();
        next.authority_revision = signed.authority.revision; next.authority_sha256 = Some(policy_digest);
        next.wall_floor_ms = now.lower_ms;
        let mut changed_key = false;
        for member in &signed.authority.custodians {
            let previous_key = next.known_keys.get(&member.custodian_credential_id).cloned();
            if next.known_keys.get(&member.custodian_credential_id).is_some_and(|key| key != &member.ed25519_public_key) {
                changed_key = true;
            } else if next.known_keys.contains_key(&member.custodian_credential_id) || next.known_keys.len() < MAX_HISTORY {
                next.known_keys.insert(member.custodian_credential_id.clone(), member.ed25519_public_key.clone());
            } else {
                next.history_exhausted = true;
            }
            if member.revoked {
                if next.revoked_ids.contains(&member.custodian_credential_id) || next.revoked_ids.len() < MAX_HISTORY {
                    next.revoked_ids.insert(member.custodian_credential_id.clone());
                } else { next.history_exhausted = true; }
                // A malformed replacement cannot hide the previously pinned
                // key when its immutable credential ID is explicitly revoked.
                for key in std::iter::once(member.ed25519_public_key.clone()).chain(previous_key) {
                    if next.revoked_keys.contains(&key) || next.revoked_keys.len() < MAX_HISTORY { next.revoked_keys.insert(key); }
                    else { next.history_exhausted = true; }
                }
            }
        }
        for revoked in &signed.authority.revoked_token_sha256 {
            if !next.revoked_tokens.contains(revoked) && next.revoked_tokens.len() >= MAX_HISTORY { next.history_exhausted = true; }
            else { next.revoked_tokens.insert(revoked.clone()); }
        }
        // Persist even when the submitted token later fails: a newly observed
        // authentic revocation/authority floor must not be forgotten on error.
        if next != self.journal { self.persist(next)?; }
        self.healthy()?;
        if changed_key { fail!(EACCES, "TRAVEL_CUSTODIAN_KEY_CHANGED"); }
        signed.authority.current(&self.pins, self.observe(clock)?)?;
        Ok((signed.authority, policy_digest))
    }

    /// Verify current signed issuer/roster and genuine quorum, then durably burn
    /// exact unsigned-token identity before returning a single inactive permit.
    pub(crate) fn burn(&mut self, bytes: &[u8], source: &mut impl FnMut() -> EnclaveResult<Vec<u8>>, clock: &dyn Clock)
        -> EnclaveResult<InactiveTravelPermit> {
        if self.anchor.is_some() {self.refresh_anchor()?;}
        self.healthy()?; self.live = None;
        let start = self.observe(clock)?;
        let token: Token = parse(bytes)?;
        let (authority, _) = self.current_authority(source, clock)?;
        let until = token.verify(&self.pins, &authority, &self.journal, self.observe(clock)?)?;
        let mut window = Window::new(start, until)?; window.check(self.observe(clock)?)?;
        let identity = token.identity()?; let key = hex::encode(identity);
        if self.journal.consumed.contains_key(&key) { fail!(EACCES, "TRAVEL_TOKEN_CONSUMED"); }
        if self.journal.consumed.len() >= MAX_HISTORY { fail!(E2BIG, "TRAVEL_HISTORY_FULL"); }
        let mut next = self.journal.clone();
        next.attempt = next.attempt.checked_add(1).filter(|attempt| *attempt <= MAX_INTEGER)
            .ok_or_else(|| err!(EACCES, "TRAVEL_HISTORY_FULL"))?;
        let attempt = next.attempt; next.consumed.insert(key, attempt); self.persist(next)?;
        // A late signature/metadata change consumes the token, never retries it.
        let (authority, _) = self.current_authority(source, clock)?;
        window.shorten(token.verify(&self.pins, &authority, &self.journal, self.observe(clock)?)?)?;
        window.check(self.observe(clock)?)?;
        let mut nonce = [0; 32]; enclave_core::rng::fill(&mut nonce); self.live = Some(nonce);
        Ok(InactiveTravelPermit { token, identity, attempt, nonce, window })
    }
    /// Consume this runtime-only permit even on refusal. Reread/reverify current
    /// signed authority; newer policy can only shorten the original bounds.
    /// No store method enables L2 or A3/A4/C4, or returns protected key material.
    pub(crate) fn finish(&mut self, mut permit: InactiveTravelPermit,
        source: &mut impl FnMut() -> EnclaveResult<Vec<u8>>, clock: &dyn Clock) -> EnclaveResult<InactiveTravelCandidate> {
        self.healthy()?;
        if self.live.take() != Some(permit.nonce)
            || self.journal.consumed.get(&hex::encode(permit.identity)) != Some(&permit.attempt) {
            fail!(EACCES, "TRAVEL_PERMIT_STERILE");
        }
        permit.window.check(self.observe(clock)?)?;
        let (authority, authority_sha256) = self.current_authority(source, clock)?;
        permit.window.shorten(permit.token.verify(&self.pins, &authority, &self.journal, self.observe(clock)?)?)?;
        permit.window.check(self.observe(clock)?)?;
        Ok(InactiveTravelCandidate { token_sha256: permit.identity, authority_sha256,
            valid_until_utc_ms: permit.window.until_ms, deadline_ns: permit.window.deadline_ns, signers: permit.token.quorum.len(),token:permit.token })
    }

    /// Consume a verified runtime candidate only after the actual fsynced audit
    /// append. The remote CAS atomically enforces the original operation cutoff;
    /// an unaudited/late saved successor cannot activate on a later reopen.
    pub(crate) fn activate_service(&mut self,mut candidate:InactiveTravelCandidate,original_scope:[u8;32],
        audit:enclave_core::audit::EnclaveAuditEnvelopeV1,simulated:bool,
        source:&mut impl FnMut()->EnclaveResult<Vec<u8>>,clock:&dyn Clock)->EnclaveResult<TravelSession> {
        self.refresh_anchor()?;let now=self.observe(clock)?;
        if now.boot_ns>=candidate.deadline_ns||now.upper_ms>=candidate.valid_until_utc_ms {fail!(ETIMEDOUT,"TRAVEL_DEADLINE");}
        if audit.daemon_uid!=enclave_core::daemon::DaemonId::CustodyVault.uid()
            ||audit.payload!=candidate.activation_payload(original_scope,simulated) {fail!(EACCES,"TRAVEL_AUDIT_REQUIRED");}
        audit.validate()?;
        let cutoff=now.lower_ms.checked_add((candidate.deadline_ns-now.boot_ns)/1_000_000)
            .ok_or_else(||err!(ETIMEDOUT,"TRAVEL_DEADLINE"))?.min(candidate.valid_until_utc_ms);
        self.anchor.as_mut().unwrap().commit_before_utc_ms=Some(cutoff);
        let result=(|| {
            let (authority,_)=self.current_authority(source,clock)?;
            candidate.shorten(candidate.token.verify(&self.pins,&authority,&self.journal,self.observe(clock)?)?)?;
            // Shortening after audit cannot silently change the acknowledged
            // audit scope. A fresh explicit authorization is required instead.
            if audit.payload!=candidate.activation_payload(original_scope,simulated) {fail!(ESTALE,"TRAVEL_AUTHORITY_BOUND_CHANGED");}
            let mut next=self.journal.clone();let service=next.service.as_mut().ok_or_else(||err!(EACCES,"TRAVEL_INDEPENDENT_ANCHOR_REQUIRED"))?;
            let expected=digest(&canonical(&("depot.travel-service.v1",self.pins.commitment()?,original_scope))?);
            if service.scope!=expected {fail!(EACCES,"TRAVEL_ANCHOR_SCOPE");}
            service.active=Some(ActiveTransition {token:candidate.token.clone(),token_sha256:candidate.token_sha256,
                authority_sha256:candidate.authority_sha256,valid_until_utc_ms:candidate.valid_until_utc_ms,original_scope,audit});
            self.persist(next)?;
            let now=self.observe(clock)?;
            if now.boot_ns>=candidate.deadline_ns||now.upper_ms>=candidate.valid_until_utc_ms {fail!(ETIMEDOUT,"TRAVEL_DEADLINE");}
            Self::session_from(candidate.token_sha256,candidate.valid_until_utc_ms,original_scope,now)
        })();
        if let Some(anchor)=self.anchor.as_mut() {anchor.commit_before_utc_ms=None;}
        result
    }
    fn session_from(token_sha256:[u8;32],valid_until_utc_ms:u64,original_scope:[u8;32],now:Observation)->EnclaveResult<TravelSession> {
        let remaining=valid_until_utc_ms.checked_sub(now.upper_ms).filter(|remaining|*remaining>0)
            .and_then(|remaining|remaining.checked_mul(1_000_000)).ok_or_else(||err!(EACCES,"TRAVEL_TOKEN_EXPIRED"))?;
        Ok(TravelSession {token_sha256,valid_until_utc_ms,original_scope,
            deadline_ns:now.boot_ns.checked_add(remaining).ok_or_else(||err!(EACCES,"TRAVEL_CLOCK"))?})
    }
    /// Recheck an already anchored activation. This never calls burn/finish,
    /// recreates a permit, extends the stored expiry or authorizes a key action.
    pub(crate) fn current_service_session(&mut self,original_scope:[u8;32],source:&mut impl FnMut()->EnclaveResult<Vec<u8>>,
        clock:&dyn Clock,audit_path:&Path)->EnclaveResult<TravelSession> {
        self.refresh_anchor()?;
        let active=self.journal.service.as_ref().and_then(|service|service.active.clone()).ok_or_else(||err!(EACCES,"TRAVEL_ACTIVATION_REQUIRED"))?;
        if active.original_scope!=original_scope {fail!(EACCES,"TRAVEL_ORIGINAL_SCOPE");}
        let audit_bytes=canonical(&active.audit)?;
        enclave_core::audit::verify_journal(audit_path,Some(enclave_core::audit::ChainAnchor {
            entries:active.audit.log_seq_u64,tip_blake3:*blake3::hash(&audit_bytes).as_bytes()}))?;
        let (authority,_)=self.current_authority(source,clock)?;
        let until=active.token.verify(&self.pins,&authority,&self.journal,self.observe(clock)?)?.min(active.valid_until_utc_ms);
        Self::session_from(active.token_sha256,until,original_scope,self.observe(clock)?)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::clock::TestClock;
    use ed25519_dalek::{Signer, SigningKey};
    use std::{fs, os::unix::fs::{DirBuilderExt, PermissionsExt}, path::PathBuf};

    struct Root(PathBuf);
    impl Root {
        fn new() -> Self {
            let parent = std::env::current_dir().unwrap().join("target"); fs::create_dir_all(&parent).unwrap();
            let path = parent.join(format!("travel-recovery-{}", enclave_core::rng::u64()));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap(); Self(path)
        }
        fn directory(&self) -> PathBuf { self.0.join("travel-recovery-candidate") }
    }
    impl Drop for Root { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
    struct Fixture {
        root: Root,
        issuer: SigningKey,
        custodians: Vec<SigningKey>,
        pins: TravelAuthorityPins,
        authority: Authority,
        token: Token,
        clock: TestClock,
    }
    impl Fixture {
        fn new() -> Self {
            let issuer = SigningKey::from_bytes(&[71; 32]);
            let custodians: Vec<_> = (72..75).map(|seed| SigningKey::from_bytes(&[seed; 32])).collect();
            let subject = "spiffe://corp.example/device/user".to_owned(); let device = "DEVICE-01".to_owned();
            let pins = TravelAuthorityPins::new("independent-SecOps-fixture".into(), issuer.verifying_key(),
                subject.clone(), device.clone(), 2, 3_600_000).unwrap();
            let authority = Authority { v: 1, kind: "depot.travel-authority.v1".into(), issuer_id: pins.issuer_id.clone(),
                revision: 1, subject_spiffe_id: subject.clone(), device_serial: device.clone(),
                issued_utc_ms: 99_999_000, not_before_utc_ms: 99_999_000, not_after_utc_ms: 400_000_000,
                threshold: 2, custodians: custodians.iter().enumerate().map(|(index, key)| Custodian {
                    custodian_credential_id: format!("{:02x}", index + 1), ed25519_public_key: hex::encode(key.verifying_key().to_bytes()),
                    role: "SecOps".into(), not_before_utc_ms: 99_999_000, not_after_utc_ms: 400_000_000, revoked: false,
                }).collect(), revoked_token_sha256: vec![] };
            let mut token = Token { v: 1, kind: "travel_downgrade".into(), subject_spiffe_id: subject, device_serial: device,
                from_profile: "L3".into(), to_profile: "L2".into(), not_before_utc_ms: 99_999_000,
                not_after_utc_ms: 100_060_000, reason_ticket: "INC-123".into(), quorum: vec![] };
            Self::sign_token(&mut token, &custodians, &[0, 2]);
            Self { root: Root::new(), issuer, custodians, pins, authority, token, clock: TestClock::at(100_000) }
        }
        fn sign_token(token: &mut Token, keys: &[SigningKey], indices: &[usize]) {
            let hash = token.identity().unwrap();
            token.quorum = indices.iter().map(|index| Approval { custodian_credential_id: format!("{:02x}", index + 1),
                ed25519_sig: hex::encode(keys[*index].sign(&hash).to_bytes()) }).collect();
        }
        fn authority_bytes(&self, authority: &Authority) -> Vec<u8> {
            let signature = self.issuer.sign(&authority.signing_message().unwrap());
            serde_json::to_vec(&SignedAuthority { authority: authority.clone(), ed25519_sig: hex::encode(signature.to_bytes()) }).unwrap()
        }
        fn open(&self) -> TravelRecoveryStore { TravelRecoveryStore::open(&self.root.0, self.pins.clone()).unwrap() }
        fn burn(&self, store: &mut TravelRecoveryStore) -> EnclaveResult<InactiveTravelPermit> {
            store.burn(&serde_json::to_vec(&self.token).unwrap(), &mut || Ok(self.authority_bytes(&self.authority)), &self.clock)
        }
        fn finish(&self, store: &mut TravelRecoveryStore, permit: InactiveTravelPermit) -> EnclaveResult<InactiveTravelCandidate> {
            store.finish(permit, &mut || Ok(self.authority_bytes(&self.authority)), &self.clock)
        }
    }

    #[derive(Default)] struct AnchorState {scope:Option<[u8;32]>,pin:TravelAnchorPin,offset_ms:u64,unavailable:bool,apply_then_error:bool}
    #[derive(Clone,Default)] pub(crate) struct ServiceTestAnchor(std::sync::Arc<std::sync::Mutex<AnchorState>>);
    impl ServiceTestAnchor {
        pub(crate) fn boxed(&self)->Box<dyn TravelRecoveryAnchor> {Box::new(self.clone())}
        pub(crate) fn advance_ms(&self,offset:u64) {self.0.lock().unwrap().offset_ms+=offset;}
        pub(crate) fn unavailable(&self,value:bool) {self.0.lock().unwrap().unavailable=value;}
        fn observation(state:&AnchorState)->TravelAnchorObservation {
            let now=u64::try_from(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()).unwrap()+state.offset_ms;
            TravelAnchorObservation {pin:state.pin,trusted_lower_utc_ms:now,trusted_upper_utc_ms:now}
        }
        fn scope(state:&mut AnchorState,scope:[u8;32])->EnclaveResult<()> {
            if state.unavailable {fail!(EIO,"FIXTURE_ANCHOR_UNAVAILABLE");}
            if state.scope.is_some_and(|fixed|fixed!=scope) {fail!(EACCES,"FIXTURE_ANCHOR_SCOPE");}
            state.scope=Some(scope);Ok(())
        }
    }
    impl TravelRecoveryAnchor for ServiceTestAnchor {
        fn load(&mut self,scope:[u8;32])->EnclaveResult<TravelAnchorObservation> {
            let mut state=self.0.lock().unwrap();Self::scope(&mut state,scope)?;Ok(Self::observation(&state))
        }
        fn compare_and_advance(&mut self,scope:[u8;32],expected:TravelAnchorPin,next:TravelAnchorPin,valid_before:Option<u64>)->EnclaveResult<TravelAnchorObservation> {
            let mut state=self.0.lock().unwrap();Self::scope(&mut state,scope)?;
            if state.pin!=expected||expected.generation.checked_add(1)!=Some(next.generation) {fail!(EACCES,"FIXTURE_ANCHOR_CAS");}
            if valid_before.is_some_and(|bound|Self::observation(&state).trusted_upper_utc_ms>=bound) {fail!(ETIMEDOUT,"FIXTURE_ANCHOR_DEADLINE");}
            state.pin=next;if state.apply_then_error {fail!(EIO,"FIXTURE_ANCHOR_AMBIGUOUS");}Ok(Self::observation(&state))
        }
    }
    pub(crate) struct ServiceMaterial {
        fixture:Fixture,
        pub(crate) authority:crate::service::TravelAuthorityConfig,
        pub(crate) anchor:ServiceTestAnchor,
    }
    impl ServiceMaterial {
        pub(crate) fn new(directory:&Path)->Self {
            let mut fixture=Fixture::new();let now=u64::try_from(enclave_crypto::time::now_unix()).unwrap()*1000;
            fixture.authority.issued_utc_ms=now-1000;fixture.authority.not_before_utc_ms=now-1000;fixture.authority.not_after_utc_ms=now+3_600_000;
            for member in &mut fixture.authority.custodians {member.not_before_utc_ms=now-1000;member.not_after_utc_ms=now+3_600_000;}
            fixture.token.not_before_utc_ms=now-1000;fixture.token.not_after_utc_ms=now+90_000;
            Fixture::sign_token(&mut fixture.token,&fixture.custodians,&[0,2]);
            let authority=crate::service::TravelAuthorityConfig {issuer_id:fixture.pins.issuer_id.clone(),issuer:fixture.pins.issuer,
                subject_spiffe_id:fixture.pins.subject.clone(),device_serial:fixture.pins.device.clone(),threshold:2,
                maximum_authority_age_ms:3_600_000,roster_file:directory.join("travel-authority.json")};
            fs::write(&authority.roster_file,fixture.authority_bytes(&fixture.authority)).unwrap();fs::set_permissions(&authority.roster_file,fs::Permissions::from_mode(0o644)).unwrap();
            Self {fixture,authority,anchor:ServiceTestAnchor::default()}
        }
        pub(crate) fn token(&self)->Vec<u8> {serde_json::to_vec(&self.fixture.token).unwrap()}
        pub(crate) fn revoke(&mut self) {
            self.fixture.authority.revision+=1;self.fixture.authority.custodians[0].revoked=true;
            fs::write(&self.authority.roster_file,self.fixture.authority_bytes(&self.fixture.authority)).unwrap();
        }
        fn open(&self,directory:&Path,scope:[u8;32])->TravelRecoveryStore {
            TravelRecoveryStore::open_anchored(directory,self.authority.pins().unwrap(),scope,self.anchor.boxed()).unwrap()
        }
        fn candidate(&self,store:&mut TravelRecoveryStore)->InactiveTravelCandidate {
            let mut source=||Ok(fs::read(&self.authority.roster_file).unwrap());let clock=crate::clock::SystemClock;
            let permit=store.burn(&self.token(),&mut source,&clock).unwrap();store.finish(permit,&mut source,&clock).unwrap()
        }
        fn activate(&self,store:&mut TravelRecoveryStore,scope:[u8;32],audit_path:&Path)->TravelSession {
            let candidate=self.candidate(store);let mut audit=enclave_core::audit::AuditJournal::open(audit_path,enclave_core::daemon::DaemonId::CustodyVault,enclave_core::seq::new_boot_epoch_id()).unwrap();
            let audit=audit.append(1,candidate.activation_payload(scope,true)).unwrap();
            store.activate_service(candidate,scope,audit,true,&mut ||Ok(fs::read(&self.authority.roster_file).unwrap()),&crate::clock::SystemClock).unwrap()
        }
    }

    #[test]
    fn anchored_service_real_audit_activation_restart_replay_and_current_revocation() {
        let root=Root::new();let mut f=ServiceMaterial::new(&root.0);let scope=[31;32];let audit=root.0.join("audit.jsonl");
        let mut store=f.open(&root.0,scope);let session=f.activate(&mut store,scope,&audit);assert!(store.journal.service.as_ref().unwrap().active.is_some());
        let mut source=||Ok(fs::read(&f.authority.roster_file).unwrap());
        assert!(store.burn(&f.token(),&mut source,&crate::clock::SystemClock).unwrap_err().is("TRAVEL_TOKEN_CONSUMED"));
        drop(store);let mut store=f.open(&root.0,scope);
        let next=store.current_service_session(scope,&mut source,&crate::clock::SystemClock,&audit).unwrap();assert_eq!(session.token_sha256,next.token_sha256);
        assert!(next.valid_until_utc_ms<=session.valid_until_utc_ms);f.revoke();
        assert!(store.current_service_session(scope,&mut ||Ok(fs::read(&f.authority.roster_file).unwrap()),&crate::clock::SystemClock,&audit).is_err());
        drop(store);let mut store=f.open(&root.0,scope);
        assert!(store.current_service_session(scope,&mut ||Ok(fs::read(&f.authority.roster_file).unwrap()),&crate::clock::SystemClock,&audit).is_err());
    }
    #[test]
    fn anchored_service_whole_local_restore_and_external_unavailability_refuse() {
        let root=Root::new();let f=ServiceMaterial::new(&root.0);let scope=[32;32];let mut store=f.open(&root.0,scope);
        let directory=root.0.join("travel-recovery-service");let files:[(&str,Vec<u8>);3]=["travel.sealed","travel.gen","sealing.key"].map(|name|(name,fs::read(directory.join(name)).unwrap()));
        drop(f.candidate(&mut store));drop(store);
        for (name,bytes) in files {fs::write(directory.join(name),bytes).unwrap();}
        assert!(TravelRecoveryStore::open_anchored(&root.0,f.authority.pins().unwrap(),scope,f.anchor.boxed()).err().unwrap().is("TRAVEL_ANCHOR_ROLLBACK"));
        f.anchor.unavailable(true);assert!(TravelRecoveryStore::open_anchored(&root.0,f.authority.pins().unwrap(),scope,f.anchor.boxed()).is_err());
    }
    #[test]
    fn anchored_service_bad_audit_late_candidate_and_actual_audit_tamper_never_activate() {
        let root=Root::new();let f=ServiceMaterial::new(&root.0);let scope=[33;32];let mut store=f.open(&root.0,scope);let mut candidate=f.candidate(&mut store);
        let path=root.0.join("audit.jsonl");let mut audit=enclave_core::audit::AuditJournal::open(&path,enclave_core::daemon::DaemonId::CustodyVault,enclave_core::seq::new_boot_epoch_id()).unwrap();
        let record=audit.append(1,serde_json::json!({"event":"not-travel"})).unwrap();
        assert!(store.activate_service(candidate,scope,record,true,&mut ||Ok(fs::read(&f.authority.roster_file).unwrap()),&crate::clock::SystemClock).unwrap_err().is("TRAVEL_AUDIT_REQUIRED"));
        assert!(store.journal.service.as_ref().unwrap().active.is_none());
        // A separately signed token is required after the first burn.
        let mut token=f.fixture.token.clone();token.reason_ticket="INC-124".into();Fixture::sign_token(&mut token,&f.fixture.custodians,&[0,2]);
        let mut source=||Ok(fs::read(&f.authority.roster_file).unwrap());let permit=store.burn(&serde_json::to_vec(&token).unwrap(),&mut source,&crate::clock::SystemClock).unwrap();candidate=store.finish(permit,&mut source,&crate::clock::SystemClock).unwrap();
        candidate.shorten_operation_deadline(crate::clock::SystemClock.now_ns());let record=audit.append(2,candidate.activation_payload(scope,true)).unwrap();
        assert!(store.activate_service(candidate,scope,record,true,&mut source,&crate::clock::SystemClock).unwrap_err().is("TRAVEL_DEADLINE"));assert!(store.journal.service.as_ref().unwrap().active.is_none());
        drop(store);
        // A new root/authorization supplies the positive before the actual
        // malformed tail test, rather than permanently refusing every record.
        let other=Root::new();let f=ServiceMaterial::new(&other.0);let audit=other.0.join("audit.jsonl");let mut store=f.open(&other.0,scope);f.activate(&mut store,scope,&audit);
        use std::io::Write;fs::OpenOptions::new().append(true).open(&audit).unwrap().write_all(b"invalid-journal-line\n").unwrap();
        assert!(store.current_service_session(scope,&mut ||Ok(fs::read(&f.authority.roster_file).unwrap()),&crate::clock::SystemClock,&audit).is_err());
    }
    #[test]
    fn anchored_service_trusted_external_expiry_and_ambiguous_cas_remain_sterile() {
        let root=Root::new();let f=ServiceMaterial::new(&root.0);let scope=[34;32];let audit=root.0.join("audit.jsonl");let mut store=f.open(&root.0,scope);f.activate(&mut store,scope,&audit);
        f.anchor.advance_ms(100_000);assert!(store.current_service_session(scope,&mut ||Ok(fs::read(&f.authority.roster_file).unwrap()),&crate::clock::SystemClock,&audit).is_err());
        drop(store);let mut store=f.open(&root.0,scope);assert!(store.current_service_session(scope,&mut ||Ok(fs::read(&f.authority.roster_file).unwrap()),&crate::clock::SystemClock,&audit).is_err());
        let other=Root::new();let f=ServiceMaterial::new(&other.0);let mut store=f.open(&other.0,scope);f.anchor.0.lock().unwrap().apply_then_error=true;
        assert!(store.burn(&f.token(),&mut ||Ok(fs::read(&f.authority.roster_file).unwrap()),&crate::clock::SystemClock).is_err());assert!(store.faulted);drop(store);
        f.anchor.0.lock().unwrap().apply_then_error=false;let mut store=f.open(&other.0,scope);
        assert!(store.current_service_session(scope,&mut ||Ok(fs::read(&f.authority.roster_file).unwrap()),&crate::clock::SystemClock,&other.0.join("missing-audit")).is_err());
    }

    #[test]
    fn exact_jcs_raw_digest_quorum_burn_finish_and_no_a4_facts() {
        let f = Fixture::new();
        let expected = br#"{"device_serial":"DEVICE-01","from_profile":"L3","kind":"travel_downgrade","not_after_utc_ms":100060000,"not_before_utc_ms":99999000,"reason_ticket":"INC-123","subject_spiffe_id":"spiffe://corp.example/device/user","to_profile":"L2","v":1}"#;
        assert_eq!(canonical(&f.token.unsigned()).unwrap(), expected);
        let hash = digest(expected);
        for (approval, index) in f.token.quorum.iter().zip([0, 2]) {
            signature(&f.custodians[index].verifying_key(), &hash, &approval.ed25519_sig).unwrap();
            assert!(signature(&f.custodians[index].verifying_key(), expected, &approval.ed25519_sig).is_err(),
                "raw JSON endorsement cannot replace the specified digest signature");
        }
        let mut store = f.open(); let permit = f.burn(&mut store).unwrap();
        assert_eq!(store.journal.consumed.get(&hex::encode(hash)), Some(&1));
        let candidate = f.finish(&mut store, permit).unwrap();
        let audit = candidate.audit_payload();
        assert_eq!(audit["from_profile"], "L3"); assert_eq!(audit["to_profile"], "L2");
        assert_eq!(audit["permits_a4"], false); assert_eq!(audit["permits_c4"], false);
        assert_eq!(audit["signers"], 2); assert!(store.live.is_none());
        assert!(f.burn(&mut store).unwrap_err().is("TRAVEL_TOKEN_CONSUMED"));
    }

    #[test]
    fn signature_reordering_and_another_valid_quorum_do_not_change_replay_identity() {
        let mut f = Fixture::new(); let mut store = f.open(); let permit = f.burn(&mut store).unwrap();
        f.finish(&mut store, permit).unwrap(); let identity = f.token.identity().unwrap();
        f.token.quorum.reverse(); assert_eq!(f.token.identity().unwrap(), identity);
        assert!(f.burn(&mut store).unwrap_err().is("TRAVEL_TOKEN_CONSUMED"));
        Fixture::sign_token(&mut f.token, &f.custodians, &[0, 1, 2]);
        assert_eq!(f.token.identity().unwrap(), identity);
        drop(store); let mut reopened = f.open();
        assert!(reopened.live.is_none()); assert!(f.burn(&mut reopened).unwrap_err().is("TRAVEL_TOKEN_CONSUMED"));
    }

    #[test]
    fn fixed_pins_exact_threshold_roles_distinct_keys_and_real_signatures_are_required() {
        let f = Fixture::new();
        assert!(TravelAuthorityPins::new(f.pins.issuer_id.clone(), f.issuer.verifying_key(),
            f.pins.subject.clone(), f.pins.device.clone(), 1, 3600).is_err());
        for mutation in 0..9 {
            let mut authority = f.authority.clone();
            match mutation {
                0 => authority.issuer_id.push('x'), 1 => authority.subject_spiffe_id.push('x'),
                2 => authority.device_serial.push('x'), 3 => authority.threshold = 1,
                4 => authority.custodians[0].role = "Publisher".into(),
                5 => authority.custodians[1].ed25519_public_key = authority.custodians[0].ed25519_public_key.clone(),
                6 => authority.custodians[1].custodian_credential_id = authority.custodians[0].custodian_credential_id.clone(),
                7 => authority.custodians[0].ed25519_public_key = "01".to_owned() + &"00".repeat(31),
                _ => authority.custodians[0].revoked = true,
            }
            let mut store = f.open();
            assert!(store.burn(&serde_json::to_vec(&f.token).unwrap(), &mut || Ok(f.authority_bytes(&authority)), &f.clock).is_err());
            assert!(store.journal.consumed.is_empty()); drop(store);
        }
        let mut store = f.open(); let mut signed: SignedAuthority = parse(&f.authority_bytes(&f.authority)).unwrap();
        signed.ed25519_sig = hex::encode(SigningKey::from_bytes(&[99; 32]).sign(&f.authority.signing_message().unwrap()).to_bytes());
        assert!(store.burn(&serde_json::to_vec(&f.token).unwrap(), &mut || Ok(serde_json::to_vec(&signed).unwrap()), &f.clock).is_err());
    }

    #[test]
    fn token_scope_duplicate_unknown_and_wrong_digest_approvals_never_burn() {
        let f = Fixture::new(); let mut store = f.open();
        for mutation in 0..11 {
            let mut token = f.token.clone();
            match mutation {
                0 => token.subject_spiffe_id.push('x'), 1 => token.device_serial.push('x'),
                2 => token.from_profile = "L2".into(), 3 => token.to_profile = "L1".into(),
                4 => token.kind = "unquarantine".into(), 5 => token.v = 2, 6 => token.reason_ticket.push('x'),
                7 => token.quorum.truncate(1), 8 => token.quorum[1] = token.quorum[0].clone(),
                9 => token.quorum[0].custodian_credential_id = "ff".into(),
                _ => token.quorum[0].ed25519_sig = hex::encode(f.custodians[0].sign(b"wrong digest").to_bytes()),
            }
            assert!(store.burn(&serde_json::to_vec(&token).unwrap(), &mut || Ok(f.authority_bytes(&f.authority)), &f.clock).is_err());
            assert!(store.journal.consumed.is_empty());
        }
        let permit = f.burn(&mut store).unwrap(); f.finish(&mut store, permit).unwrap();
    }

    #[test]
    fn typed_closed_json_refuses_duplicates_unknown_fields_float_trailing_and_oversized() {
        let f = Fixture::new(); let mut store = f.open();
        let valid = String::from_utf8(serde_json::to_vec(&f.token).unwrap()).unwrap();
        for invalid in [format!("{{\"v\":1,{}", &valid[1..]), format!("{{\"\\u0076\":1,{}", &valid[1..]),
            valid.replacen("\"v\":1", "\"v\":1.0", 1), format!("{valid}{{}}"),
            format!("{{\"permits_c4\":true,{}", &valid[1..]),
            valid.replacen("\"custodian_credential_id\":\"01\"", "\"custodian_credential_id\":\"01\",\"custodian_credential_id\":\"01\"", 1)] {
            assert!(store.burn(invalid.as_bytes(), &mut || Ok(f.authority_bytes(&f.authority)), &f.clock).is_err());
        }
        assert!(store.burn(&vec![b' '; MAX_WIRE + 1], &mut || panic!("oversized token cannot fetch authority"), &f.clock).unwrap_err().is("TRAVEL_INPUT_SIZE"));
        let mut authority = String::from_utf8(f.authority_bytes(&f.authority)).unwrap();
        authority = authority.replacen("\"revision\":1", "\"revision\":1,\"revision\":1", 1);
        assert!(store.burn(valid.as_bytes(), &mut || Ok(authority.as_bytes().to_vec()), &f.clock).is_err());
        assert!(store.journal.consumed.is_empty());
    }

    #[test]
    fn seventy_two_hour_ceiling_and_conservative_exclusive_expiry_are_enforced() {
        let f = Fixture::new(); let mut store = f.open();
        for mutation in 0..5 {
            let mut token = f.token.clone();
            match mutation {
                0 => token.not_after_utc_ms = token.not_before_utc_ms + MAX_TTL_MS + 1,
                1 => token.not_before_utc_ms = 100_001_000,
                2 => token.not_after_utc_ms = 100_000_999,
                3 => token.not_after_utc_ms = token.not_before_utc_ms,
                _ => token.not_after_utc_ms = MAX_INTEGER + 1,
            }
            Fixture::sign_token(&mut token, &f.custodians, &[0, 2]);
            assert!(store.burn(&serde_json::to_vec(&token).unwrap(), &mut || Ok(f.authority_bytes(&f.authority)), &f.clock).is_err());
        }
        let mut token = f.token.clone(); token.not_after_utc_ms = token.not_before_utc_ms + MAX_TTL_MS;
        Fixture::sign_token(&mut token, &f.custodians, &[0, 2]);
        let permit = store.burn(&serde_json::to_vec(&token).unwrap(), &mut || Ok(f.authority_bytes(&f.authority)), &f.clock).unwrap();
        assert_eq!(permit.window.until_ms, f.authority.issued_utc_ms + f.pins.maximum_authority_age_ms,
            "72h outer token never extends the independently earlier authority freshness");
        assert_eq!(permit.window.deadline_ns, f.clock.now_ns() + crate::ceremony::CEREMONY_BUDGET_NS);
    }

    #[test]
    fn late_roster_revocation_burns_token_and_never_forgets_revoked_id_or_key() {
        let f = Fixture::new(); let mut store = f.open();
        let mut revoked = f.authority.clone(); revoked.revision = 2; revoked.custodians[0].revoked = true;
        let mut calls = 0;
        let result = store.burn(&serde_json::to_vec(&f.token).unwrap(), &mut || {
            calls += 1; Ok(f.authority_bytes(if calls == 1 { &f.authority } else { &revoked }))
        }, &f.clock);
        assert!(result.unwrap_err().is("TRAVEL_REVOKED")); assert_eq!(store.journal.consumed.len(), 1);
        assert!(store.live.is_none()); drop(store); let mut store = f.open();
        let mut unrevoked = f.authority.clone(); unrevoked.revision = 3;
        let mut token = f.token.clone(); token.reason_ticket = "INC-NEW".into();
        Fixture::sign_token(&mut token, &f.custodians, &[0, 2]);
        assert!(store.burn(&serde_json::to_vec(&token).unwrap(), &mut || Ok(f.authority_bytes(&unrevoked)), &f.clock)
            .unwrap_err().is("TRAVEL_REVOKED"));
        unrevoked.revision = 4; unrevoked.custodians[0].custodian_credential_id = "04".into();
        token.quorum[0].custodian_credential_id = "04".into();
        assert!(store.burn(&serde_json::to_vec(&token).unwrap(), &mut || Ok(f.authority_bytes(&unrevoked)), &f.clock)
            .unwrap_err().is("TRAVEL_REVOKED"));
        assert!(f.burn(&mut store).unwrap_err().is("TRAVEL_AUTHORITY_ROLLBACK"));
    }

    #[test]
    fn authority_freshness_token_revocation_and_same_revision_substitution_refuse() {
        let f = Fixture::new(); let mut store = f.open(); let permit = f.burn(&mut store).unwrap();
        let mut changed = f.authority.clone(); changed.revoked_token_sha256.push(hex::encode(f.token.identity().unwrap()));
        assert!(store.finish(permit, &mut || Ok(f.authority_bytes(&changed)), &f.clock).unwrap_err().is("TRAVEL_AUTHORITY_ROLLBACK"));
        changed.revision = 2;
        assert!(store.burn(&serde_json::to_vec(&f.token).unwrap(), &mut || Ok(f.authority_bytes(&changed)), &f.clock)
            .unwrap_err().is("TRAVEL_REVOKED"));
        changed.revision = 3; changed.revoked_token_sha256.clear();
        assert!(store.burn(&serde_json::to_vec(&f.token).unwrap(), &mut || Ok(f.authority_bytes(&changed)), &f.clock)
            .unwrap_err().is("TRAVEL_REVOKED"));
        assert!(store.live.is_none());
        let g = Fixture::new(); let mut other = g.open();
        for future in [false, true] {
            let mut bad = g.authority.clone();
            if future { bad.issued_utc_ms = 100_001_000; bad.not_before_utc_ms = 100_001_000;
                for member in &mut bad.custodians { member.not_before_utc_ms = bad.not_before_utc_ms; }
            } else { bad.issued_utc_ms = 100_000_999 - g.pins.maximum_authority_age_ms;
                bad.not_before_utc_ms = bad.issued_utc_ms;
            }
            assert!(other.burn(&serde_json::to_vec(&g.token).unwrap(), &mut || Ok(g.authority_bytes(&bad)), &g.clock).is_err());
        }
        assert!(other.journal.consumed.is_empty());
    }

    #[test]
    fn complete_original_cap_and_earlier_authority_deadline_never_refresh() {
        let f = Fixture::new(); let mut store = f.open(); let permit = f.burn(&mut store).unwrap();
        f.clock.advance_ms(10_000);
        assert!(f.finish(&mut store, permit).unwrap_err().is("TRAVEL_DEADLINE"));
        let g = Fixture::new(); let mut store = g.open();
        let mut short = g.authority.clone(); short.not_after_utc_ms = 100_003_000;
        for member in &mut short.custodians { member.not_after_utc_ms = short.not_after_utc_ms; }
        let permit = store.burn(&serde_json::to_vec(&g.token).unwrap(), &mut || Ok(g.authority_bytes(&short)), &g.clock).unwrap();
        let deadline = permit.window.deadline_ns;
        let mut renewed = g.authority.clone(); renewed.revision = 2;
        let candidate = store.finish(permit, &mut || Ok(g.authority_bytes(&renewed)), &g.clock).unwrap();
        assert_eq!(candidate.valid_until_utc_ms, 100_003_000); assert_eq!(candidate.deadline_ns, deadline);
        let h = Fixture::new(); let mut store = h.open(); let mut calls = 0;
        assert!(store.burn(&serde_json::to_vec(&h.token).unwrap(), &mut || {
            calls += 1; if calls == 2 { h.clock.advance_ms(10_000); } Ok(h.authority_bytes(&h.authority))
        }, &h.clock).is_err());
        assert_eq!(store.journal.consumed.len(), 1); assert!(store.live.is_none());
    }

    #[test]
    fn restarted_or_competing_owner_and_changed_pins_cannot_restore_runtime_permit() {
        let f = Fixture::new(); let mut store = f.open(); let permit = f.burn(&mut store).unwrap();
        assert!(TravelRecoveryStore::open(&f.root.0, f.pins.clone()).is_err()); drop(store);
        let mut store = f.open(); assert!(f.finish(&mut store, permit).unwrap_err().is("TRAVEL_PERMIT_STERILE"));
        assert!(f.burn(&mut store).unwrap_err().is("TRAVEL_TOKEN_CONSUMED")); drop(store);
        let mut pins = f.pins.clone(); pins.threshold = 3;
        assert!(TravelRecoveryStore::open(&f.root.0, pins).is_err());
    }

    #[test]
    fn partial_burn_save_is_uncertain_then_reopens_consumed_and_old_state_refuses() {
        let f = Fixture::new(); let mut store = f.open();
        store.current_authority(&mut || Ok(f.authority_bytes(&f.authority)), &f.clock).unwrap();
        let directory = f.root.directory(); let old_state = fs::read(directory.join("burns.sealed")).unwrap();
        let old_generation = fs::read(directory.join("burns.gen")).unwrap();
        fs::remove_file(directory.join("burns.gen")).unwrap(); fs::create_dir(directory.join("burns.gen")).unwrap();
        assert!(f.burn(&mut store).is_err()); assert!(store.faulted); assert!(store.live.is_none());
        assert!(f.burn(&mut store).unwrap_err().is("TRAVEL_PERSISTENCE_UNCERTAIN"));
        fs::remove_dir(directory.join("burns.gen")).unwrap(); fs::write(directory.join("burns.gen"), old_generation).unwrap();
        fs::set_permissions(directory.join("burns.gen"), fs::Permissions::from_mode(0o600)).unwrap(); drop(store);
        let mut reopened = f.open(); assert!(reopened.live.is_none());
        assert!(f.burn(&mut reopened).unwrap_err().is("TRAVEL_TOKEN_CONSUMED"));
        let next = reopened.journal.clone(); reopened.persist(next).unwrap(); drop(reopened);
        fs::write(directory.join("burns.sealed"), old_state).unwrap();
        assert!(TravelRecoveryStore::open(&f.root.0, f.pins.clone()).err().unwrap().is("STATE_ROLLBACK"));
    }

    #[test]
    fn initialized_missing_tampered_and_unknown_version_never_reset_consumption() {
        for mutation in 0..3 {
            let f = Fixture::new(); let mut store = f.open(); let _permit = f.burn(&mut store).unwrap(); drop(store);
            let directory = f.root.directory();
            match mutation {
                0 => { fs::remove_file(directory.join("burns.sealed")).unwrap(); fs::remove_file(directory.join("burns.gen")).unwrap(); }
                1 => fs::write(directory.join("burns.sealed"), b"tampered").unwrap(),
                _ => { let (mut sealed, _) = SealedStore::open_bounded_required(&directory, "burns", MAX_STATE).unwrap();
                    let mut journal = Journal::fresh(f.pins.commitment().unwrap()); journal.v = 2; sealed.save_json(&journal).unwrap(); }
            }
            assert!(TravelRecoveryStore::open(&f.root.0, f.pins.clone()).is_err());
        }
    }

    #[test]
    fn rejected_key_replacement_still_advances_authentic_floor_and_history_exhaustion_is_terminal() {
        let f = Fixture::new(); let mut store = f.open();
        store.current_authority(&mut || Ok(f.authority_bytes(&f.authority)), &f.clock).unwrap();
        let mut replacement = f.authority.clone(); replacement.revision = 2;
        replacement.custodians[0].ed25519_public_key = hex::encode(SigningKey::from_bytes(&[98; 32]).verifying_key().to_bytes());
        replacement.custodians[0].revoked = true;
        assert!(store.current_authority(&mut || Ok(f.authority_bytes(&replacement)), &f.clock)
            .err().unwrap().is("TRAVEL_CUSTODIAN_KEY_CHANGED"));
        drop(store); let mut store = f.open();
        assert!(store.current_authority(&mut || Ok(f.authority_bytes(&f.authority)), &f.clock)
            .err().unwrap().is("TRAVEL_AUTHORITY_ROLLBACK"));
        assert_eq!(store.journal.authority_revision, 2);
        let mut aliased = f.authority.clone(); aliased.revision = 3; aliased.custodians[0].custodian_credential_id = "04".into();
        let mut token = f.token.clone(); token.quorum[0].custodian_credential_id = "04".into();
        assert!(store.burn(&serde_json::to_vec(&token).unwrap(), &mut || Ok(f.authority_bytes(&aliased)), &f.clock)
            .unwrap_err().is("TRAVEL_REVOKED"), "a revoked old key cannot escape a rejected replacement through a fresh ID");
        drop(store);

        let g = Fixture::new(); let mut store = g.open();
        // Exercise the real signed-roster refresh until its bounded historical
        // roster is full. Removed IDs do not erase known/revoked identity pins.
        for revision in 1..=9 {
            let mut authority = g.authority.clone(); authority.revision = revision;
            authority.custodians = (0..MAX_MEMBERS).map(|index| {
                let mut member = g.authority.custodians[0].clone();
                member.custodian_credential_id = format!("{:04x}", (revision - 1) * MAX_MEMBERS as u64 + index as u64 + 1);
                let mut seed = [88; 32]; seed[..8].copy_from_slice(&((revision - 1) * MAX_MEMBERS as u64 + index as u64).to_be_bytes());
                member.ed25519_public_key = hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes()); member
            }).collect();
            let result = store.current_authority(&mut || Ok(g.authority_bytes(&authority)), &g.clock);
            if revision <= 8 { assert!(result.is_ok()); } else { assert!(result.err().unwrap().is("TRAVEL_HISTORY_FULL")); }
        }
        assert!(store.journal.history_exhausted); assert_eq!(store.journal.authority_revision, 9); drop(store);
        let mut reopened = g.open();
        assert!(g.burn(&mut reopened).unwrap_err().is("TRAVEL_HISTORY_FULL"));
    }

    #[test]
    fn every_final_clock_observation_is_retained_then_folded_into_the_next_durable_floor() {
        use std::{collections::VecDeque, sync::{Mutex, atomic::{AtomicI64, Ordering}}};
        #[derive(Debug)]
        struct SequenceClock { walls: Mutex<VecDeque<i64>>, last: AtomicI64, boot: u64 }
        impl Clock for SequenceClock {
            fn now_ns(&self) -> u64 { self.boot }
            fn now_unix(&self) -> i64 {
                let now = self.walls.lock().unwrap().pop_front().unwrap_or_else(|| self.last.load(Ordering::SeqCst));
                self.last.store(now, Ordering::SeqCst); now
            }
        }
        let f = Fixture::new(); let mut store = f.open();
        let clock = SequenceClock { walls: Mutex::new(VecDeque::from([100_000, 100_001])),
            last: AtomicI64::new(100_000), boot: f.clock.now_ns() };
        // The second sample occurs AFTER the first authoritative save.
        store.current_authority(&mut || Ok(f.authority_bytes(&f.authority)), &clock).unwrap();
        assert_eq!(store.journal.wall_floor_ms, 100_000_000);
        assert_eq!(store.observed_wall_ms.get(), 100_001_000);
        assert!(f.burn(&mut store).unwrap_err().is("TRAVEL_CLOCK"));
        let newer = TestClock::at(100_001);
        store.current_authority(&mut || Ok(f.authority_bytes(&f.authority)), &newer).unwrap();
        assert_eq!(store.journal.wall_floor_ms, 100_001_000);
        let regressed_boot = SequenceClock { walls: Mutex::new(VecDeque::from([100_001])),
            last: AtomicI64::new(100_001), boot: f.clock.now_ns() - 1 };
        assert!(store.observe(&regressed_boot).err().unwrap().is("TRAVEL_CLOCK"));
        drop(store); let mut reopened = f.open();
        assert!(f.burn(&mut reopened).unwrap_err().is("TRAVEL_CLOCK"), "persisted floor survives reconstruction");
    }
}
