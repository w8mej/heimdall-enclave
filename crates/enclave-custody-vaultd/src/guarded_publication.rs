//! Disabled local diagnostic journal for an eventual isolated signing boundary.
//!
//! This module authenticates no approval, enrollment, revocation or live policy.
//! No production endpoint calls it and it contains no signing key or fallback.
//! An independent, durable, linearizable recovery anchor is mandatory; a second
//! file on this disk is not such an anchor. The callback is a diagnostic seam,
//! not an implementation of hardware/admin signer isolation.
use std::{cell::Cell,collections::BTreeMap,path::Path};
use ed25519_dalek::{Signature,VerifyingKey};
use enclave_core::{err,fail,error::EnclaveResult,sealed::{Loaded,SealedStore,StateDirectoryLease}};
use enclave_crypto::tuf::{Role,TufClient,TufKey};
use serde::{Serialize,Deserialize};
use sha2::{Digest,Sha256};

const MAX_BODY:usize=1024*1024;
const MAX_RECORDS:usize=8;
const STORE_NAME:&str="guarded-publication";

/// Independently configured scope; never obtain this from publisher claims.
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JournalScope {
    pub(crate) repository_id:[u8;32],
    pub(crate) signer_public:[u8;32],
}
/// Independently anchored exact state. Generation zero/hash zero is genesis.
#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AnchorPin {pub(crate) generation:u64,pub(crate) ledger_sha256:[u8;32]}
impl AnchorPin {fn genesis()->Self {Self {generation:0,ledger_sha256:[0;32]}}}
/// Required external authority. Implementations must independently pin scope,
/// durably serialize CAS, reject regression and survive local root/disk restore.
/// An unavailable/unknown anchor returns Err; there is no local-disk substitute.
/// A CAS error may be ambiguous, so the journal always latches closed afterward.
pub(crate) trait ExternalRecoveryAnchor {
    fn load(&mut self,scope:&JournalScope)->EnclaveResult<AnchorPin>;
    fn compare_and_advance(&mut self,scope:&JournalScope,expected:AnchorPin,next:AnchorPin)->EnclaveResult<()>;
}
/// Immutable diagnostic input, separately authenticated by a future guard.
/// All exact bytes and constraints are part of the persistent identity.
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicationBinding {
    pub(crate) publication_id:[u8;32],
    pub(crate) intent_constraints_sha256:[u8;32],
    pub(crate) policy_sha256:[u8;32],
    pub(crate) authority_generation:u64,
    /// Exact current pinned complete root file, including its signatures.
    pub(crate) root_envelope_sha256:[u8;32],
    pub(crate) role:Role,
    pub(crate) metadata_version:u64,
    /// Exact OLPC canonical standard-TUF signed member, excluding signatures.
    pub(crate) signed_body:String,
    pub(crate) valid_from_unix:i64,
    pub(crate) valid_until_unix:i64,
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(tag="state",content="signature",rename_all="kebab-case")]
enum IssueState {Ready,Issuing,Uncertain,Signed(Vec<u8>)}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {binding:PublicationBinding,state:IssueState}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    version:u8,scope:JournalScope,generation:u64,previous:AnchorPin,
    last_observed_unix:i64,records:BTreeMap<String,Record>,
}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub(crate) enum PublicationStatus {Ready,Issuing,Uncertain,Signed}

fn hash(bytes:&[u8])->[u8;32] {Sha256::digest(bytes).into()}
fn canonical<T:Serialize>(value:&T)->EnclaveResult<Vec<u8>> {enclave_core::jcs::to_jcs_bytes(value)}
fn key(scope:&JournalScope)->EnclaveResult<VerifyingKey> {
    let key=VerifyingKey::from_bytes(&scope.signer_public).map_err(|_|err!(EINVAL,"PUBLICATION_SIGNER_KEY"))?;
    if key.is_weak()||key.to_edwards().compress().to_bytes()!=scope.signer_public {fail!(EINVAL,"PUBLICATION_SIGNER_KEY");}Ok(key)
}
fn signature(scope:&JournalScope,binding:&PublicationBinding,bytes:&[u8])->EnclaveResult<()> {
    let signature=Signature::from_slice(bytes).map_err(|_|err!(EACCES,"PUBLICATION_SIGNATURE"))?;
    key(scope)?.verify_strict(binding.signed_body.as_bytes(),&signature).map_err(|_|err!(EACCES,"PUBLICATION_SIGNATURE"))
}
impl PublicationBinding {
    fn validate(&self)->EnclaveResult<()> {
        if self.signed_body.is_empty()||self.signed_body.len()>MAX_BODY||self.metadata_version==0
            ||self.valid_from_unix<0||self.valid_until_unix<=self.valid_from_unix {fail!(EINVAL,"PUBLICATION_BINDING");}
        let value:serde_json::Value=serde_json::from_slice(self.signed_body.as_bytes()).map_err(|_|err!(EINVAL,"PUBLICATION_BODY"))?;
        // Exact-byte comparison rejects duplicate members, private Number-map
        // reinterpretation, whitespace, floats and every changed signed preimage.
        if enclave_crypto::canonical_json::to_canonical_json_bytes(&value)?!=self.signed_body.as_bytes()
            ||value["_type"].as_str()!=Some(self.role.name())||value["version"].as_u64()!=Some(self.metadata_version) {
            fail!(EINVAL,"PUBLICATION_BODY");
        }
        let expiry=value["expires"].as_str().and_then(enclave_crypto::time::parse_rfc3339_utc)
            .ok_or_else(||err!(EINVAL,"PUBLICATION_BODY"))?;
        if self.valid_until_unix>expiry {fail!(EINVAL,"PUBLICATION_BINDING");}Ok(())
    }
    fn current(&self,now:i64)->EnclaveResult<()> {
        if now<self.valid_from_unix||now>=self.valid_until_unix {fail!(EACCES,"PUBLICATION_EXPIRED");}Ok(())
    }
}

/// Exclusive durable diagnostic owner. Any uncertain local or remote persistence
/// error latches it closed. Reopen must reconcile exact state against the anchor.
/// Eight records are retained permanently; exhaustion refuses, never evicts.
pub(crate) struct GuardedPublicationJournal {
    _lease:StateDirectoryLease,store:SealedStore,scope:JournalScope,
    anchor:Box<dyn ExternalRecoveryAnchor>,pin:AnchorPin,ledger:Ledger,faulted:bool,
    observed_unix:Cell<i64>,
}
impl GuardedPublicationJournal {
    pub(crate) fn open(path:&Path,scope:JournalScope,mut anchor:Box<dyn ExternalRecoveryAnchor>)->EnclaveResult<Self> {
        key(&scope)?;
        // Fail before creating local authority state if external authority is absent.
        let observed=anchor.load(&scope)?;
        let lease=StateDirectoryLease::acquire(path)?;
        let (store,loaded)=SealedStore::open_bounded_required(path,STORE_NAME,64*1024*1024)?;
        let fresh=matches!(&loaded,Loaded::Fresh);
        let ledger=match loaded {
            Loaded::Fresh=>{
                if observed!=AnchorPin::genesis() {fail!(EACCES,"PUBLICATION_ANCHOR_ROLLBACK");}
                Ledger {version:1,scope:scope.clone(),generation:0,previous:AnchorPin::genesis(),last_observed_unix:0,records:BTreeMap::new()}
            },
            Loaded::State(bytes)=>{
                let ledger:Ledger=enclave_core::sealed::decode(&bytes)?;
                if canonical(&ledger)?!=bytes {fail!(EACCES,"PUBLICATION_STATE");}ledger
            },
        };
        let observed_unix=Cell::new(ledger.last_observed_unix);
        let mut journal=Self {_lease:lease,store,scope,anchor,pin:observed,ledger,faulted:false,observed_unix};
        if fresh {journal.commit(journal.ledger.clone())?;} else {
            journal.validate_loaded()?;
            let saved=journal.saved_pin()?;
            if saved!=observed {
                // Only a fully authenticated exact one-step successor may
                // repair local-save-before-anchor interruption. Any older,
                // divergent or more-than-one-step state refuses restoration.
                if journal.ledger.previous!=observed||observed.generation.checked_add(1)!=Some(saved.generation) {
                    fail!(EACCES,"PUBLICATION_ANCHOR_ROLLBACK");
                }
                journal.anchor.compare_and_advance(&journal.scope,observed,saved)?;
                journal.pin=saved;
            }
        }
        if journal.ledger.records.values().any(|record|record.state==IssueState::Issuing) {
            let mut next=journal.ledger.clone();
            for record in next.records.values_mut() {if record.state==IssueState::Issuing {record.state=IssueState::Uncertain;}}
            journal.commit(next)?;
        }Ok(journal)
    }
    fn saved_pin(&self)->EnclaveResult<AnchorPin> {
        Ok(AnchorPin {generation:self.ledger.generation,ledger_sha256:hash(&canonical(&self.ledger)?)})
    }
    fn validate_loaded(&self)->EnclaveResult<()> {
        let ledger=&self.ledger;
        if ledger.version!=1||ledger.scope!=self.scope||ledger.records.len()>MAX_RECORDS||ledger.generation==0
            ||ledger.previous.generation.checked_add(1)!=Some(ledger.generation)||ledger.last_observed_unix<0 {fail!(EACCES,"PUBLICATION_STATE");}
        for (id,record) in &ledger.records {
            record.binding.validate()?;
            if *id!=hex::encode(record.binding.publication_id) {fail!(EACCES,"PUBLICATION_STATE");}
            if let IssueState::Signed(bytes)=&record.state {signature(&self.scope,&record.binding,bytes)?;}
        }
        let records:Vec<_>=ledger.records.values().collect();
        for (index,a) in records.iter().enumerate() {for b in records.iter().skip(index+1) {
            if a.binding.role==b.binding.role&&a.binding.metadata_version==b.binding.metadata_version {fail!(EACCES,"PUBLICATION_STATE");}
        }}Ok(())
    }
    fn usable(&self)->EnclaveResult<()> {if self.faulted {fail!(EIO,"PUBLICATION_REOPEN_REQUIRED");}Ok(())}
    fn commit(&mut self,mut next:Ledger)->EnclaveResult<()> {
        self.usable()?;
        next.generation=self.pin.generation.checked_add(1).ok_or_else(||err!(EIO,"PUBLICATION_GENERATION"))?;
        next.previous=self.pin;
        next.last_observed_unix=next.last_observed_unix.max(self.observed_unix.get());
        let bytes=canonical(&next)?;
        if bytes.len()>16*1024*1024 {fail!(E2BIG,"PUBLICATION_STATE_BOUND");}
        let next_pin=AnchorPin {generation:next.generation,ledger_sha256:hash(&bytes)};
        self.faulted=true;
        self.store.save(&bytes)?;
        self.anchor.compare_and_advance(&self.scope,self.pin,next_pin)?;
        self.pin=next_pin;self.ledger=next;self.faulted=false;Ok(())
    }
    fn current_trust(&self,binding:&PublicationBinding,client:&TufClient,now:i64)->EnclaveResult<()> {
        if now<self.ledger.last_observed_unix.max(self.observed_unix.get()) {fail!(EACCES,"PUBLICATION_TIME_REGRESSION");}
        // Final post-persistence reads cannot be followed by infinite writes.
        // Retain EVERY observed highwater in this live owner and fold it into
        // the next durable commit. Cross-restart clock antirollback is external.
        self.observed_unix.set(now);
        binding.current(now)?;
        let state=client.export()?;
        let root=state.roots.last().unwrap_or(&state.anchor);
        if hash(root.as_bytes())!=binding.root_envelope_sha256 {fail!(EACCES,"PUBLICATION_ROOT_CHANGED");}
        // Typed TUF admission must not silently discard an original signed
        // root field on this diagnostic path. The pinned self-threshold was
        // verified by TufClient; require its exact signed preimage to agree.
        let root_value:serde_json::Value=serde_json::from_str(root).map_err(|_|err!(EACCES,"PUBLICATION_ROOT_CHANGED"))?;
        if enclave_crypto::canonical_json::to_canonical_json_bytes(&root_value["signed"])?
            !=enclave_crypto::canonical_json::to_canonical_json_bytes(client.root())? {
            fail!(EACCES,"PUBLICATION_ROOT_PREIMAGE");
        }
        let adopted=match binding.role {Role::Root=>None,Role::Targets=>state.targets.as_ref(),
            Role::Snapshot=>state.snapshot.as_ref(),Role::Timestamp=>state.timestamp.as_ref()};
        let floor=if let Some(bytes)=adopted {
            let value:serde_json::Value=serde_json::from_str(bytes).map_err(|_|err!(EACCES,"PUBLICATION_ADOPTED_STATE"))?;
            value["signed"]["version"].as_u64().ok_or_else(||err!(EACCES,"PUBLICATION_ADOPTED_STATE"))?
        } else {0};
        if (binding.role==Role::Root&&client.root().version.checked_add(1)!=Some(binding.metadata_version))
            ||(binding.role!=Role::Root&&binding.metadata_version<=floor) {fail!(EACCES,"PUBLICATION_ADOPTED_VERSION");}
        let expiry=enclave_crypto::time::parse_rfc3339_utc(&client.root().expires).ok_or_else(||err!(EACCES,"PUBLICATION_ROOT_CHANGED"))?;
        let id=TufKey::ed25519(&key(&self.scope)?).keyid()?;
        let assignment=client.root().roles.get(binding.role.name()).ok_or_else(||err!(EACCES,"PUBLICATION_SIGNER_ROLE"))?;
        if now<0||now>=expiry||assignment.threshold==0||!assignment.keyids.contains(&id)
            ||client.root().keys.get(&id)!=Some(&TufKey::ed25519(&key(&self.scope)?)) {fail!(EACCES,"PUBLICATION_SIGNER_ROLE");}Ok(())
    }
    pub(crate) fn prepare(&mut self,binding:PublicationBinding)->EnclaveResult<()> {
        self.usable()?;binding.validate()?;
        let id=hex::encode(binding.publication_id);
        if let Some(record)=self.ledger.records.get(&id) {
            if record.binding!=binding {fail!(EACCES,"PUBLICATION_BINDING_CONFLICT");}return Ok(());
        }
        if self.ledger.records.len()>=MAX_RECORDS {fail!(E2BIG,"PUBLICATION_RECORD_LIMIT");}
        if self.ledger.records.values().any(|record|record.binding.role==binding.role&&
            (record.binding.metadata_version>=binding.metadata_version||matches!(record.state,IssueState::Issuing|IssueState::Uncertain))) {
            fail!(EACCES,"PUBLICATION_ROLE_CONFLICT");
        }
        let mut next=self.ledger.clone();next.records.insert(id,Record {binding,state:IssueState::Ready});self.commit(next)
    }
    pub(crate) fn status(&self,id:&[u8;32])->EnclaveResult<PublicationStatus> {
        self.usable()?;let record=self.ledger.records.get(&hex::encode(id)).ok_or_else(||err!(EINVAL,"PUBLICATION_UNKNOWN"))?;
        Ok(match record.state {IssueState::Ready=>PublicationStatus::Ready,IssueState::Issuing=>PublicationStatus::Issuing,
            IssueState::Uncertain=>PublicationStatus::Uncertain,IssueState::Signed(_)=>PublicationStatus::Signed})
    }
    /// Diagnostic issue only. Future callers must independently enforce complete
    /// current factor/policy/revocation authority; no success boolean supplies it.
    /// Durable externally anchored ISSUING precedes the callback. The callback
    /// MUST NOT be automatically retried after error, panic or ambiguous crash.
    /// `clock` MUST be independently authenticated and monotonic/regression-
    /// detecting across restarts; return Err if its uncertainty cannot fit the
    /// fixed binding window. A final read can precede a crash before its next
    /// checkpoint. This journal does not supply native clock antirollback.
    pub(crate) fn issue(&mut self,id:&[u8;32],client:&TufClient,
        mut clock:impl FnMut()->EnclaveResult<i64>,callback:impl FnOnce(&PublicationBinding)->EnclaveResult<Vec<u8>>)
        ->EnclaveResult<Vec<u8>> {
        self.usable()?;let id=hex::encode(id);
        let record=self.ledger.records.get(&id).ok_or_else(||err!(EINVAL,"PUBLICATION_UNKNOWN"))?.clone();
        let before=clock()?;self.current_trust(&record.binding,client,before)?;
        match &record.state {
            IssueState::Signed(bytes)=>{
                let mut next=self.ledger.clone();next.last_observed_unix=before;
                self.commit(next)?;
                self.current_trust(&record.binding,client,clock()?)?;return Ok(bytes.clone());
            },
            IssueState::Issuing|IssueState::Uncertain=>fail!(EACCES,"PUBLICATION_RECONCILE_REQUIRED"),
            IssueState::Ready=>(),
        }
        // Refuse a lower/equal version or another uncertain issue even if this
        // Ready record existed before the newer conflicting record was prepared.
        if self.ledger.records.iter().any(|(other_id,other)|other_id!=&id&&other.binding.role==record.binding.role
            &&(other.binding.metadata_version>=record.binding.metadata_version||matches!(other.state,IssueState::Issuing|IssueState::Uncertain))) {
            fail!(EACCES,"PUBLICATION_ROLE_CONFLICT");
        }
        let mut next=self.ledger.clone();next.last_observed_unix=before;
        next.records.get_mut(&id).unwrap().state=IssueState::Issuing;self.commit(next)?;
        // Local fsync and external CAS are charged to the same fixed window.
        // Refusal after ISSUING conservatively requires reconciliation even
        // though this code knows it has not invoked the callback yet.
        let admitted=clock().and_then(|now|self.current_trust(&record.binding,client,now).map(|_|now));
        let issued_at=match admitted {
            Ok(now)=>now,
            Err(error)=>{
                let mut next=self.ledger.clone();next.records.get_mut(&id).unwrap().state=IssueState::Uncertain;
                self.commit(next)?;return Err(error);
            },
        };
        let result=callback(&record.binding);
        let mut next=self.ledger.clone();next.last_observed_unix=issued_at;
        let bytes=match result {
            Ok(bytes) if signature(&self.scope,&record.binding,&bytes).is_ok()=>bytes,
            Ok(_)=>{next.records.get_mut(&id).unwrap().state=IssueState::Uncertain;self.commit(next)?;fail!(EACCES,"PUBLICATION_SIGNATURE");},
            Err(error)=>{next.records.get_mut(&id).unwrap().state=IssueState::Uncertain;self.commit(next)?;return Err(error);},
        };
        // Retain known irreversible signature before checking final time or ack.
        let after=clock();
        if let Ok(now)=after.as_ref() {next.last_observed_unix=issued_at.max(*now);}
        next.records.get_mut(&id).unwrap().state=IssueState::Signed(bytes.clone());self.commit(next)?;
        let after=after?;self.current_trust(&record.binding,client,after)?;
        self.current_trust(&record.binding,client,clock()?)?;Ok(bytes)
    }
    /// Record a queried exact-key signature after an ambiguous issue. No callback
    /// runs and no signature is released here. Expired/revoked results remain
    /// durable history; a later issue/retry still checks current pinned trust/time.
    pub(crate) fn reconcile(&mut self,id:&[u8;32],bytes:&[u8])->EnclaveResult<()> {
        self.usable()?;let id=hex::encode(id);
        let record=self.ledger.records.get(&id).ok_or_else(||err!(EINVAL,"PUBLICATION_UNKNOWN"))?;
        signature(&self.scope,&record.binding,bytes)?;
        match &record.state {
            IssueState::Signed(old) if old==bytes=>return Ok(()),
            IssueState::Issuing|IssueState::Uncertain=>(),
            _=>fail!(EACCES,"PUBLICATION_RECONCILE_STATE"),
        }
        let mut next=self.ledger.clone();next.records.get_mut(&id).unwrap().state=IssueState::Signed(bytes.to_vec());self.commit(next)
    }
}
#[cfg(test)]
#[path="guarded_publication_tests.rs"]
mod tests;
