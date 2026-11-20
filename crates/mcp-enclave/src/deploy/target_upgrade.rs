//! Pure existing-upgrade recovery analysis, never mutation or activation authority.
//!
//! Exact descriptor/inventory bytes rederive the complete fixed public plan.
//! Journal and observation JSON are untrusted inputs, not signed capabilities.
//! A forward action is only a proposal for a future executor. That executor must
//! freshly admit independent release/native/rendered-code and whole-target
//! quiescence, actual accounts and the real host guard, and retain genuine
//! DURABLE start inhibition across crashes until verified forward completion.
//! Activity/registration absence and broker-only idle cannot supply that scope.
//!
//! There is no journal writer, replacement, pin publication, cleanup, rollback,
//! resume, start, CLI, account/release constructor or fixture fallback here.
//! Mutable state, enrollment, counters, floors, keys, wrappers and ciphertexts
//! are never opened. No local JSON/hash proves native antirollback or approval.

use std::{collections::{BTreeMap,BTreeSet},path::PathBuf};
use enclave_core::{deployment::{DeploymentRole,DeploymentTarget,normalized_path},
    error::EnclaveResult,err,fail};
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use super::target_plan::{self,TargetInstallPlan};

const MAX_DESCRIPTOR:usize=65_536;
const MAX_INVENTORY:usize=1_048_576;
const MAX_RECORD:usize=262_144;
const MAX_UNITS:usize=128;
const MAX_BYTES:u64=2*1024*1024*1024;
const JOURNAL_KIND:&str="depot-existing-upgrade-public-journal";
const OBSERVATION_KIND:&str="depot-existing-upgrade-public-observation";

fn digest(value:&str)->bool {
    value.len()==64 && value.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))
}
fn strict<T:serde::de::DeserializeOwned>(raw:&[u8],maximum:usize)->EnclaveResult<T> {
    if raw.is_empty()||raw.len()>maximum {fail!(E2BIG,"UPGRADE_RECORD_BOUND");}
    // Every accepted object is a closed struct (including nested objects).
    // serde's struct visitor rejects both duplicate known and unknown fields.
    serde_json::from_slice(raw).map_err(|_|err!(EINVAL,"UPGRADE_RECORD_SCHEMA"))
}
fn field(hash:&mut Sha256,value:&[u8]) {
    hash.update((value.len() as u64).to_be_bytes());hash.update(value);
}

/// Fixed public unit description only. Bundles are whole units; their members
/// must never be independently replaced to manufacture signed-bundle closure.
#[derive(Clone,Debug,PartialEq,Eq,Serialize)]
pub(crate) struct UpgradeUnitDescriptor {
    pub(crate) unit_id:String,
    pub(crate) destination:PathBuf,
    pub(crate) candidate_fingerprint:String,
    pub(crate) member_count:usize,
    pub(crate) total_bytes:u64,
}
fn fixed_plan(descriptor:&[u8],inventory:&[u8])->EnclaveResult<(DeploymentTarget,TargetInstallPlan)> {
    if descriptor.is_empty()||descriptor.len()>MAX_DESCRIPTOR||inventory.is_empty()||inventory.len()>MAX_INVENTORY {
        fail!(E2BIG,"UPGRADE_RECORD_BOUND");
    }
    let target=DeploymentTarget::parse(descriptor)?;
    if target.role!=DeploymentRole::ExistingUpgrade {fail!(EACCES,"UPGRADE_EXISTING_ROLE_REQUIRED");}
    let descriptor_sha256=hex::encode(Sha256::digest(descriptor));
    let plan=target_plan::describe(&target,&descriptor_sha256,inventory)?;
    if !plan.missing_required_files.is_empty() {fail!(EINVAL,"UPGRADE_COMPLETE_PLAN_REQUIRED");}
    Ok((target,plan))
}
fn public_units(target:&DeploymentTarget,plan:&TargetInstallPlan)->EnclaveResult<Vec<UpgradeUnitDescriptor>> {
    let mut groups=BTreeMap::<String,(PathBuf,Vec<(&target_plan::CopyEntry,String)>)>::new();
    let stage=normalized_path(&target.layout.staging_root)?;
    for copy in &plan.copies {
        if copy.destination==plan.selected_pins_file {continue;}
        let source=normalized_path(&copy.source)?;
        let relative=source.strip_prefix(&stage).map_err(|_|err!(EINVAL,"UPGRADE_FIXED_UNIT_SCOPE"))?
            .to_str().ok_or_else(||err!(EINVAL,"UPGRADE_FIXED_UNIT_SCOPE"))?;
        let bundle=if let Some(member)=relative.strip_prefix("EnclaveCustody.app/") {
            Some(("EnclaveCustody.app",target.layout.custody_bundle.clone(),member))
        } else if let Some(member)=relative.strip_prefix("EnclaveOIDC.app/") {
            Some(("EnclaveOIDC.app",target.layout.support_root.join("EnclaveOIDC.app"),member))
        } else {None};
        let (id,destination,member)=match bundle {
            Some((bundle,destination,member))=>(format!("bundle:{bundle}"),normalized_path(&destination)?,member.to_owned()),
            None=>(format!("file:{relative}"),normalized_path(&copy.destination)?,String::new()),
        };
        if copy.uid!=0||copy.gid!=0||!["0644","0755"].contains(&copy.mode.as_str())||!digest(&copy.sha256)
            ||copy.size==0||copy.size>512*1024*1024 {
            fail!(EINVAL,"UPGRADE_FIXED_UNIT_SCOPE");
        }
        let entry=groups.entry(id).or_insert_with(||(destination.clone(),Vec::new()));
        if entry.0!=destination {fail!(EINVAL,"UPGRADE_FIXED_UNIT_SCOPE");}
        entry.1.push((copy,member));
    }
    if groups.is_empty()||groups.len()>MAX_UNITS {fail!(E2BIG,"UPGRADE_UNIT_BOUND");}
    let mut units=Vec::new();let mut destinations=BTreeSet::new();let mut total=0u64;
    for (unit_id,(destination,mut members)) in groups {
        let key=destination.to_str().ok_or_else(||err!(EINVAL,"UPGRADE_FIXED_UNIT_SCOPE"))?.to_ascii_lowercase();
        if !destinations.insert(key) {fail!(EINVAL,"UPGRADE_FIXED_UNIT_SCOPE");}
        members.sort_by(|a,b|a.1.cmp(&b.1));
        let mut names=BTreeSet::new();let mut bytes=0u64;let mut hash=Sha256::new();
        hash.update(b"depot_UPGRADE_PUBLIC_UNIT_V1\0");
        field(&mut hash,unit_id.as_bytes());field(&mut hash,destination.as_os_str().as_encoded_bytes());
        for (copy,member) in &members {
            if !names.insert(member.as_str()) {fail!(EINVAL,"UPGRADE_FIXED_UNIT_SCOPE");}
            bytes=bytes.checked_add(copy.size).ok_or_else(||err!(E2BIG,"UPGRADE_UNIT_BOUND"))?;
            field(&mut hash,member.as_bytes());field(&mut hash,copy.sha256.as_bytes());
            field(&mut hash,&copy.size.to_be_bytes());field(&mut hash,&copy.uid.to_be_bytes());
            field(&mut hash,&copy.gid.to_be_bytes());field(&mut hash,copy.mode.as_bytes());
        }
        total=total.checked_add(bytes).ok_or_else(||err!(E2BIG,"UPGRADE_UNIT_BOUND"))?;
        if total>MAX_BYTES {fail!(E2BIG,"UPGRADE_UNIT_BOUND");}
        units.push(UpgradeUnitDescriptor {unit_id,destination,candidate_fingerprint:hex::encode(hash.finalize()),
            member_count:members.len(),total_bytes:bytes});
    }
    Ok(units)
}
/// Derive inert fixed units from exact public input bytes; no caller plan or
/// destination map is accepted, and no file is opened or written.
pub(crate) fn describe_upgrade_public_units(descriptor:&[u8],inventory:&[u8])
    ->EnclaveResult<Vec<UpgradeUnitDescriptor>> {
    let (target,plan)=fixed_plan(descriptor,inventory)?;public_units(&target,&plan)
}

#[derive(Clone,Copy,Debug,PartialEq,Eq,Deserialize,Serialize)]
#[serde(rename_all="snake_case")]
enum Phase {Prepared,Replacing,PayloadVerified,PinCutoverIntent,PinsCandidate,Committed}
#[derive(Clone,Copy,Debug,PartialEq,Eq,Deserialize,Serialize)]
#[serde(rename_all="snake_case")]
enum UnitPhase {Pending,ReplaceIntent,Installed}
#[derive(Clone,Copy,Debug,PartialEq,Eq,Deserialize,Serialize)]
#[serde(rename_all="snake_case")]
enum OriginalState {Present,Absent}
#[derive(Clone,Debug,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
struct Original {
    state:OriginalState,
    #[serde(deserialize_with="required_option")]
    fingerprint:Option<String>,
}
fn required_option<'de,D:serde::Deserializer<'de>>(d:D)->Result<Option<String>,D::Error> {
    Option::<String>::deserialize(d)
}
#[derive(Clone,Debug,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
struct JournalUnit {unit_id:String,candidate_fingerprint:String,original:Original,phase:UnitPhase}
#[derive(Clone,Debug,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version:u8,kind:String,target_id:String,descriptor_sha256:String,artifact_inventory_sha256:String,
    transaction_id:String,old_pins_sha256:String,candidate_pins_sha256:String,phase:Phase,units:Vec<JournalUnit>,
}
#[derive(Clone,Copy,Debug,PartialEq,Eq,Deserialize,Serialize)]
#[serde(rename_all="snake_case")]
enum ObservedState {Present,Absent,Unknown}
#[derive(Clone,Debug,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
struct UnitObservation {
    unit_id:String,state:ObservedState,
    #[serde(deserialize_with="required_option")]
    fingerprint:Option<String>,
}
#[derive(Clone,Debug,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
struct PinObservation {
    state:ObservedState,
    #[serde(deserialize_with="required_option")]
    sha256:Option<String>,
}
#[derive(Clone,Debug,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
struct Observations {
    version:u8,kind:String,transaction_id:String,descriptor_sha256:String,artifact_inventory_sha256:String,
    pins:PinObservation,units:Vec<UnitObservation>,
}
fn transaction_id(journal:&Journal)->String {
    let mut hash=Sha256::new();hash.update(b"depot_UPGRADE_TRANSACTION_V1\0");
    for value in [&journal.target_id,&journal.descriptor_sha256,&journal.artifact_inventory_sha256,
        &journal.old_pins_sha256,&journal.candidate_pins_sha256] {field(&mut hash,value.as_bytes());}
    for unit in &journal.units {
        field(&mut hash,unit.unit_id.as_bytes());field(&mut hash,unit.candidate_fingerprint.as_bytes());
        field(&mut hash,match unit.original.state {OriginalState::Present=>b"present",OriginalState::Absent=>b"absent"});
        field(&mut hash,unit.original.fingerprint.as_deref().unwrap_or("").as_bytes());
    }
    hex::encode(hash.finalize())
}
fn journal_binding(journal:&Journal,target:&DeploymentTarget,plan:&TargetInstallPlan,units:&[UpgradeUnitDescriptor])
    ->EnclaveResult<()> {
    if journal.version!=1||journal.kind!=JOURNAL_KIND||journal.target_id!=target.target_id
        ||journal.descriptor_sha256!=plan.deployment_config_sha256
        ||journal.artifact_inventory_sha256!=plan.artifact_inventory_sha256
        ||!digest(&journal.transaction_id)||!digest(&journal.old_pins_sha256)
        ||journal.candidate_pins_sha256!=plan.candidate_codesign_pins_sha256
        ||journal.units.len()!=units.len()||journal.units.len()>MAX_UNITS {
        fail!(ESTALE,"UPGRADE_JOURNAL_BINDING");
    }
    let mut pending=false;let mut intent=false;
    for (record,unit) in journal.units.iter().zip(units) {
        if record.unit_id!=unit.unit_id||record.candidate_fingerprint!=unit.candidate_fingerprint
            ||match record.original.state {
                OriginalState::Present=>record.original.fingerprint.as_deref().is_none_or(|v|!digest(v)),
                OriginalState::Absent=>record.original.fingerprint.is_some(),
            } {fail!(EINVAL,"UPGRADE_JOURNAL_UNIT_BINDING");}
        match record.phase {
            UnitPhase::Installed=>if pending||intent {fail!(EINVAL,"UPGRADE_JOURNAL_UNIT_ORDER");},
            UnitPhase::ReplaceIntent=>{
                if pending||intent {fail!(EINVAL,"UPGRADE_JOURNAL_UNIT_ORDER");}intent=true;
            },
            UnitPhase::Pending=>pending=true,
        }
    }
    let all_installed=journal.units.iter().all(|u|u.phase==UnitPhase::Installed);
    if (journal.phase==Phase::Prepared&&journal.units.iter().any(|u|u.phase!=UnitPhase::Pending))
        ||(!matches!(journal.phase,Phase::Prepared|Phase::Replacing)&&!all_installed) {
        fail!(EINVAL,"UPGRADE_JOURNAL_PHASE");
    }
    if transaction_id(journal)!=journal.transaction_id {fail!(ESTALE,"UPGRADE_TRANSACTION_BINDING");}
    Ok(())
}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum UnitIdentity {Original,Candidate,Equal}
fn identity(record:&JournalUnit,observed:&UnitObservation)->EnclaveResult<UnitIdentity> {
    if observed.unit_id!=record.unit_id {fail!(ESTALE,"UPGRADE_OBSERVATION_BINDING");}
    match observed.state {
        ObservedState::Unknown=>{fail!(EACCES,"UPGRADE_OBSERVATION_UNKNOWN");},
        ObservedState::Absent=>{
            if observed.fingerprint.is_some() {fail!(EINVAL,"UPGRADE_OBSERVATION_SCHEMA");}
            if record.original.state==OriginalState::Absent&&record.phase!=UnitPhase::Installed {Ok(UnitIdentity::Original)}
            else {fail!(ESTALE,"UPGRADE_UNEXPECTED_ABSENCE");}
        },
        ObservedState::Present=>{
            let value=observed.fingerprint.as_deref().filter(|v|digest(v))
                .ok_or_else(||err!(EINVAL,"UPGRADE_OBSERVATION_SCHEMA"))?;
            let original=record.original.state==OriginalState::Present&&record.original.fingerprint.as_deref()==Some(value);
            let candidate=value==record.candidate_fingerprint;
            match (original,candidate) {
                (true,true)=>Ok(UnitIdentity::Equal),(true,false)=>Ok(UnitIdentity::Original),
                (false,true)=>Ok(UnitIdentity::Candidate),(false,false)=>{fail!(ESTALE,"UPGRADE_UNIT_IDENTITY_UNKNOWN");},
            }
        },
    }
}

/// Proposed next step only; an executor must freshly reverify every authority,
/// durable barrier and observed inode before any corresponding effect.
#[derive(Debug,PartialEq,Eq,Serialize)]
#[serde(tag="action",rename_all="snake_case")]
pub(crate) enum ForwardAction {
    PersistReplacingPhase,
    PersistUnitIntent {unit_id:String},
    RetryUnitForward {unit_id:String},
    VerifyAndRecordUnit {unit_id:String},
    VerifyCompletePayload,
    VerifyBeforePinCutover,
    CutoverExactCandidatePins,
    VerifyAndRecordPinCutover,
    ReverifyAndCommit,
    VerifyCommittedGeneration,
}
#[derive(Debug,Serialize)]
pub(crate) struct ForwardRecoveryDecision {
    pub(crate) target_id:String,
    pub(crate) descriptor_sha256:String,
    pub(crate) artifact_inventory_sha256:String,
    pub(crate) transaction_id:String,
    pub(crate) unit_count:usize,
    pub(crate) pins_equal:bool,
    pub(crate) next:ForwardAction,
    pub(crate) durable_start_inhibition_required:bool,
    pub(crate) mutation_allowed:bool,
    pub(crate) activation_allowed:bool,
    pub(crate) inactivity_proven:bool,
    pub(crate) installation_supported:bool,
    pub(crate) qualified:bool,
}

/// Untrusted JSON is analyzed against a freshly rederived fixed plan. This pure
/// result does not authenticate observation, journal durability, release,
/// current accounts, quiescence, native identity or start inhibition.
pub(crate) fn classify_existing_upgrade_forward(descriptor_raw:&[u8],inventory_raw:&[u8],
    journal_raw:&[u8],observed_raw:&[u8])->EnclaveResult<ForwardRecoveryDecision> {
    let (target,plan)=fixed_plan(descriptor_raw,inventory_raw)?;let units=public_units(&target,&plan)?;
    let journal:Journal=strict(journal_raw,MAX_RECORD)?;journal_binding(&journal,&target,&plan,&units)?;
    let observed:Observations=strict(observed_raw,MAX_RECORD)?;
    if observed.version!=1||observed.kind!=OBSERVATION_KIND||observed.transaction_id!=journal.transaction_id
        ||observed.descriptor_sha256!=journal.descriptor_sha256
        ||observed.artifact_inventory_sha256!=journal.artifact_inventory_sha256
        ||observed.units.len()!=journal.units.len() {
        fail!(ESTALE,"UPGRADE_OBSERVATION_BINDING");
    }
    if observed.pins.state!=ObservedState::Present {fail!(EACCES,"UPGRADE_PINS_UNKNOWN");}
    let pins=observed.pins.sha256.as_deref().filter(|v|digest(v)).ok_or_else(||err!(EINVAL,"UPGRADE_OBSERVATION_SCHEMA"))?;
    let old_pins=pins==journal.old_pins_sha256;let candidate_pins=pins==journal.candidate_pins_sha256;
    if !old_pins&&!candidate_pins {fail!(ESTALE,"UPGRADE_PINS_UNKNOWN");}
    let identities=journal.units.iter().zip(&observed.units).map(|(record,observation)|identity(record,observation))
        .collect::<EnclaveResult<Vec<_>>>()?;
    let all_candidate=identities.iter().all(|i|matches!(i,UnitIdentity::Candidate|UnitIdentity::Equal));
    // Equal pin bytes do not attest that a cutover occurred; earlier phases may
    // still progress only through their unit intents. Distinct candidate pins
    // with ANY old unit refuse rather than restoring pins or blessing a mix.
    if candidate_pins&&!old_pins&&!all_candidate {fail!(ESTALE,"UPGRADE_PREMATURE_PIN_CUTOVER");}
    let mut next_unit=None;
    for (record,identity) in journal.units.iter().zip(&identities) {
        match record.phase {
            UnitPhase::Installed=>if !matches!(identity,UnitIdentity::Candidate|UnitIdentity::Equal) {
                fail!(ESTALE,"UPGRADE_INSTALLED_UNIT_REGRESSED");
            },
            UnitPhase::Pending=>{
                if *identity==UnitIdentity::Candidate {fail!(ESTALE,"UPGRADE_REPLACEMENT_WITHOUT_INTENT");}
                if next_unit.is_none() {next_unit=Some(ForwardAction::PersistUnitIntent {unit_id:record.unit_id.clone()});}
            },
            UnitPhase::ReplaceIntent=>{
                if next_unit.is_some() {fail!(EINVAL,"UPGRADE_JOURNAL_UNIT_ORDER");}
                next_unit=Some(if matches!(identity,UnitIdentity::Candidate|UnitIdentity::Equal) {
                    ForwardAction::VerifyAndRecordUnit {unit_id:record.unit_id.clone()}
                }else{ForwardAction::RetryUnitForward {unit_id:record.unit_id.clone()}});
            },
        }
    }
    let next=match journal.phase {
        Phase::Prepared=>{
            if candidate_pins&&!old_pins {fail!(ESTALE,"UPGRADE_PREMATURE_PIN_CUTOVER");}
            ForwardAction::PersistReplacingPhase
        },
        Phase::Replacing=>{
            if candidate_pins&&!old_pins {fail!(ESTALE,"UPGRADE_PREMATURE_PIN_CUTOVER");}
            next_unit.unwrap_or(ForwardAction::VerifyCompletePayload)
        },
        Phase::PayloadVerified=>{
            if !all_candidate||!old_pins {fail!(ESTALE,"UPGRADE_PREMATURE_PIN_CUTOVER");}
            ForwardAction::VerifyBeforePinCutover
        },
        Phase::PinCutoverIntent=>{
            if !all_candidate {fail!(ESTALE,"UPGRADE_PREMATURE_PIN_CUTOVER");}
            if candidate_pins&&!old_pins {ForwardAction::VerifyAndRecordPinCutover}
            else {ForwardAction::CutoverExactCandidatePins}
        },
        Phase::PinsCandidate=>{
            if !all_candidate||!candidate_pins {fail!(ESTALE,"UPGRADE_PIN_CUTOVER_REGRESSED");}
            ForwardAction::ReverifyAndCommit
        },
        Phase::Committed=>{
            if !all_candidate||!candidate_pins {fail!(ESTALE,"UPGRADE_PIN_CUTOVER_REGRESSED");}
            ForwardAction::VerifyCommittedGeneration
        },
    };
    Ok(ForwardRecoveryDecision {target_id:target.target_id,descriptor_sha256:journal.descriptor_sha256,
        artifact_inventory_sha256:journal.artifact_inventory_sha256,transaction_id:journal.transaction_id,
        unit_count:units.len(),pins_equal:journal.old_pins_sha256==journal.candidate_pins_sha256,next,
        durable_start_inhibition_required:true,mutation_allowed:false,activation_allowed:false,inactivity_proven:false,
        installation_supported:false,qualified:false})
}

#[cfg(test)]
#[path="target_upgrade_tests.rs"]
mod tests;
