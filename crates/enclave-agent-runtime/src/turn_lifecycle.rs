//! Trusted in-memory turn ownership. Only handles created by a scoped ingress
//! enter this registry; clients cannot assert ownership of an arbitrary name.
use std::collections::{BTreeMap, BTreeSet};
use enclave_core::error::EnclaveResult;
use enclave_core::ifc_envelope::IfcEnvelopeV1;
use enclave_core::ipc::PeerCredentials;
use enclave_core::label::Label;
use enclave_core::{err, fail};
use crate::heap::CapabilityHeap;

pub(crate) const MAX_TURNS: usize = 64;
const MAX_REFS: usize = 256;
#[derive(Debug)]
struct Turn { owner: PeerCredentials, refs: BTreeSet<String>, root: Option<[u8;32]>, closing: bool, ssm: Option<SsmTurn> }
#[derive(Debug, Clone)]
pub(crate) struct SsmTurn {
    pub scope: [u8;32],
    pub floor: Label,
    pub output_floor: Label,
    pub parents: Vec<String>,
    pub healthy: bool,
    pub generated: bool,
}
#[derive(Debug, Default)]
pub(crate) struct TurnLifecycles {
    turns: BTreeMap<String,Turn>,
    managed: BTreeSet<String>,
    cleanup_pending: bool,
}
impl TurnLifecycles {
    pub(crate) fn contains(&self,id:&str)->bool {self.turns.contains_key(id)}
    pub(crate) fn check_begin(&self, peer:&PeerCredentials) -> EnclaveResult<()> {
        self.check_available()?;
        if peer.pid.is_none_or(|pid|pid<=0) { fail!(EPERM,"TURN_OWNER_IDENTITY_REQUIRED"); }
        if self.turns.len()>=MAX_TURNS {fail!(E2BIG,"TURN_LIMIT");}
        Ok(())
    }
    pub(crate) fn begin(&mut self, owner:PeerCredentials, handles:Vec<String>, root:Option<[u8;32]>) -> EnclaveResult<String> {
        self.check_begin(&owner)?;
        if handles.len()>MAX_REFS {fail!(E2BIG,"TURN_REFERENCE_LIMIT");}
        let id=loop { let id=hex::encode(enclave_core::rng::bytes32());if !self.turns.contains_key(&id){break id;} };
        let refs:BTreeSet<_>=handles.into_iter().collect();self.managed.extend(refs.iter().cloned());
        self.turns.insert(id.clone(),Turn {owner,refs,root,closing:false,ssm:None});Ok(id)
    }
    pub(crate) fn owned(&self, peer:&PeerCredentials,id:&str) -> EnclaveResult<()> {
        let turn=self.turns.get(id).ok_or_else(||err!(EACCES,"TURN_UNKNOWN"))?;
        // Darwin's full audit token includes pidversion; matching uid/pid
        // alone would permit process-ID reuse. Linux development identities
        // lack that attestation and do not claim production process isolation.
        if &turn.owner!=peer {fail!(EPERM,"TURN_OWNER_REJECTED");}Ok(())
    }
    pub(crate) fn check_append(&self,peer:&PeerCredentials,id:&str) -> EnclaveResult<()> {
        self.active(peer,id)?;
        if self.turns[id].refs.len()>=MAX_REFS {fail!(E2BIG,"TURN_REFERENCE_LIMIT");}Ok(())
    }
    pub(crate) fn append(&mut self,id:&str,handle:String) {
        self.managed.insert(handle.clone());
        self.turns.get_mut(id).expect("validated active turn under state lock").refs.insert(handle);
    }
    pub(crate) fn retain(&mut self,peer:&PeerCredentials,id:&str,envelopes:&[IfcEnvelopeV1],heap:&CapabilityHeap) -> EnclaveResult<()> {
        self.active(peer,id)?;
        let mut refs=self.turns[id].refs.clone();
        for env in envelopes {
            heap.verify_presented(env)?;
            if !self.managed.contains(&env.handle) {fail!(EPERM,"TURN_HANDLE_NOT_MANAGED");}
            refs.insert(env.handle.clone());
        }
        if refs.len()>MAX_REFS {fail!(E2BIG,"TURN_REFERENCE_LIMIT");}
        self.turns.get_mut(id).expect("checked turn").refs=refs;Ok(())
    }
    pub(crate) fn check_derived(&self,parent:&str) -> EnclaveResult<()> {
        if self.turns.values().any(|t| t.refs.contains(parent)&&(t.closing||t.refs.len()>=MAX_REFS)) {
            fail!(E2BIG,"TURN_REFERENCE_LIMIT");
        }Ok(())
    }
    pub(crate) fn derived(&mut self,parent:&str,handle:&str) {
        if !self.managed.contains(parent) {return;}
        self.managed.insert(handle.into());
        for turn in self.turns.values_mut().filter(|t|t.refs.contains(parent)) {turn.refs.insert(handle.into());}
    }
    pub(crate) fn is_managed(&self,handle:&str)->bool {self.managed.contains(handle)}
    pub(crate) fn finish(&mut self,peer:&PeerCredentials,id:&str,heap:&mut CapabilityHeap) -> EnclaveResult<(usize,Option<[u8;32]>)> {
        self.owned(peer,id)?;
        let live:BTreeSet<&String>=self.turns.iter().filter(|(other,_)|other.as_str()!=id).flat_map(|(_,t)|t.refs.iter()).collect();
        let dead:Vec<String>=self.managed.iter().filter(|h|!live.contains(h)).cloned().collect();
        // Atomic heap validation precedes ANY lifecycle mutation. Other live
        // turns retain their exact envelopes; no key or exposure is rotated.
        let released=heap.release(&dead)?;
        for handle in dead {self.managed.remove(&handle);}
        let turn=self.turns.remove(id).expect("validated turn");
        self.complete_emergency();Ok((released,turn.root))
    }
    pub(crate) fn cleanup_pending(&self)->bool {self.cleanup_pending}
    pub(crate) fn check_available(&self)->EnclaveResult<()> {
        if self.cleanup_pending {fail!(EPERM,"SSM_CLEANUP_PENDING");} Ok(())
    }
    pub(crate) fn active(&self,peer:&PeerCredentials,id:&str)->EnclaveResult<()> {
        self.check_available()?; self.owned(peer,id)?;
        if self.turns[id].closing {fail!(EPERM,"TURN_CLOSING");} Ok(())
    }
    pub(crate) fn check_inputs(&self,peer:&PeerCredentials,id:&str,envelopes:&[IfcEnvelopeV1],heap:&CapabilityHeap)->EnclaveResult<()> {
        self.check_append(peer,id)?;
        for env in envelopes {
            heap.verify_presented(env)?;
            if !self.turns[id].refs.contains(&env.handle) {fail!(EPERM,"SSM_INPUT_NOT_TURN_OWNED");}
        } Ok(())
    }
    pub(crate) fn check_handle_names(&self,peer:&PeerCredentials,id:&str,handles:&[String])->EnclaveResult<()> {
        self.active(peer,id)?;
        if handles.iter().any(|h|!self.turns[id].refs.contains(h)) {fail!(EPERM,"SSM_INPUT_NOT_TURN_OWNED");}
        Ok(())
    }
    pub(crate) fn session(&self,id:&str)->Option<SsmTurn> {self.turns.get(id).and_then(|t|t.ssm.clone())}
    pub(crate) fn set_session(&mut self,id:&str,ssm:SsmTurn) {self.turns.get_mut(id).expect("checked turn").ssm=Some(ssm);}
    pub(crate) fn close(&mut self,peer:&PeerCredentials,id:&str)->EnclaveResult<()> {
        self.owned(peer,id)?;self.turns.get_mut(id).expect("checked turn").closing=true;Ok(())
    }
    pub(crate) fn clear_session(&mut self,id:&str) {if let Some(t)=self.turns.get_mut(id){t.ssm=None;}}
    // Emergency wiping erases local data immediately while retaining only the
    // owner + pending remote scope. An unreachable runner cannot stop a wipe.
    pub(crate) fn emergency_wipe(&mut self)->Vec<[u8;32]> {
        self.cleanup_pending=true;
        let mut roots=Vec::new();
        for turn in self.turns.values_mut() {
            turn.closing=true; turn.refs.clear();
            if let Some(root)=turn.root.take(){roots.push(root);}
            if let Some(ssm)=turn.ssm.as_mut(){ssm.parents.clear();}
        }
        self.managed.clear(); roots
    }
    pub(crate) fn pending_scopes(&self)->Vec<(String,[u8;32])> {
        self.turns.iter().filter_map(|(id,t)|t.ssm.as_ref().map(|s|(id.clone(),s.scope))).collect()
    }
    pub(crate) fn complete_emergency(&mut self) {
        if self.cleanup_pending && self.turns.values().all(|t|t.ssm.is_none()) {
            self.turns.clear(); self.cleanup_pending=false;
        }
    }
}
