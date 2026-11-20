//! Bounded gateway reconciliation. Only positive incarnation-end observations
//! authorize automatic cancellation; operator/legacy turns are never swept.
use super::*;
use enclave_core::process_identity::{has_local_process_identity, ProcessLiveness, ProcessWatch};
use std::collections::BTreeMap;

const MAX_GATEWAYS: usize = 64;
// In addition to the turn-count limit, cap aggregate retained wire metadata
// and private executor tokens. Large valid tool sets cannot grow an uncharged
// response cache up to the runtime's entire RSS allocation.
const MAX_RETAINED_BYTES: usize = 1024 * 1024;
#[derive(Debug)]
struct Submission {
    digest: [u8; 32],
    caller: PeerCredentials,
    watch: Option<Arc<ProcessWatch>>,
    response: IfcResponse,
    turn_id: String,
    closing: bool,
    retained_bytes: usize,
}
#[derive(Debug)]
struct GatewayCursor {
    owner: PeerCredentials,
    watch: Option<Arc<ProcessWatch>>,
    high_water: u64,
    active: BTreeMap<u64, Submission>,
}
#[derive(Debug, Default)]
pub(super) struct GatewayRecovery {
    owners: BTreeMap<[u8; 32], GatewayCursor>,
}
impl GatewayRecovery {
    pub(super) fn retire_turn(&mut self, id: &str) {
        for owner in self.owners.values_mut() {
            owner.active.retain(|_, s| s.turn_id != id);
        }
    }
    pub(super) fn clear_active(&mut self) {
        for owner in self.owners.values_mut() {
            owner.active.clear();
        }
    }
    pub(super) fn prune_finished(&mut self, turns: &crate::turn_lifecycle::TurnLifecycles) {
        for owner in self.owners.values_mut() {
            owner.active.retain(|_, old| turns.contains(&old.turn_id));
        }
    }
    fn remaining_bytes(&self) -> usize {
        MAX_RETAINED_BYTES.saturating_sub(
            self.owners
                .values()
                .flat_map(|owner| owner.active.values())
                .map(|old| old.retained_bytes)
                .sum::<usize>(),
        )
    }
    fn cursor(&mut self, peer: &PeerCredentials, dev: bool) -> EnclaveResult<&mut GatewayCursor> {
        let key = peer.channel_binding();
        if !self.owners.contains_key(&key) {
            // Never evict a live/Unknown cursor to make room. A late request
            // from a positively ended identity cannot recreate a cursor.
            self.owners
                .retain(|_, owner| !owner.active.is_empty() || !ended(&owner.watch));
            if self.owners.len() >= MAX_GATEWAYS {
                fail!(E2BIG, "GATEWAY_RECOVERY_LIMIT");
            }
            let watch = capture(peer, dev)?;
            self.owners.insert(
                key,
                GatewayCursor {
                    owner: peer.clone(),
                    watch,
                    high_water: 0,
                    active: BTreeMap::new(),
                },
            );
        }
        let owner = self.owners.get_mut(&key).expect("inserted cursor");
        if owner.owner != *peer {
            fail!(EPERM, "GATEWAY_RECOVERY_OWNER");
        }
        Ok(owner)
    }
}
fn ended(watch: &Option<Arc<ProcessWatch>>) -> bool {
    watch
        .as_ref()
        .is_some_and(|watch| watch.liveness() == ProcessLiveness::Dead)
}
fn capture(peer: &PeerCredentials, dev: bool) -> EnclaveResult<Option<Arc<ProcessWatch>>> {
    // Linux same-UID development can exercise reconciliation without claiming
    // Darwin process isolation or inferring death from PID-only credentials.
    if !cfg!(target_os = "macos") && dev {
        return Ok(None);
    }
    Ok(Some(Arc::new(ProcessWatch::capture(peer)?)))
}

impl IfcService {
    fn gateway_peer(st: &State, peer: &PeerCredentials) -> EnclaveResult<()> {
        if st.dev_same_uid
            && peer.uid == enclave_core::ipc::geteuid()
            && peer.pid.is_some_and(|pid| pid > 0)
            && peer.tls_channel_binding.is_none()
        {
            return Ok(());
        }
        if peer.uid != enclave_core::daemon::GATEWAY_UID
            || !has_local_process_identity(peer)
            || !peer
                .code_identity
                .as_ref()
                .is_some_and(|code| code.identifier == enclave_core::daemon::GATEWAY_IDENTIFIER)
        {
            fail!(EPERM, "GATEWAY_RECOVERY_PEER_REQUIRED");
        }
        Ok(())
    }

    pub(super) fn begin_gateway_turn(
        &self,
        peer: &PeerCredentials,
        submission_seq: u64,
        caller: PeerCredentials,
        turn: UserTurnV1,
        attachments: Vec<(String, serde_bytes::ByteBuf)>,
        tools: Vec<ToolSignature>,
        holder_pk: Option<[u8; 32]>,
        budget_mb: i64,
    ) -> EnclaveResult<IfcResponse> {
        {
            let st = self.lock()?;
            Self::gateway_peer(&st, peer)?;
        }
        let _ = self.maintain_gateway_turns();
        let mut guard = self.lock()?;
        let st = &mut *guard;
        Self::gateway_peer(st, peer)?;
        if submission_seq == 0
            || caller.pid.is_none_or(|pid| pid <= 0)
            || caller.tls_channel_binding.is_some()
            || (!st.dev_same_uid
                && (!has_local_process_identity(&caller)
                    || !caller.code_identity.as_ref().is_some_and(|code| {
                        code.identifier == enclave_core::codesign::CTL_IDENTIFIER
                    })))
        {
            fail!(EPERM, "GATEWAY_CALLER_IDENTITY_REQUIRED");
        }
        if attachments.len() > 64
            || tools.len() > 1024
            || attachments
                .iter()
                .map(|(_, bytes)| bytes.len())
                .sum::<usize>()
                > 4 * 1024 * 1024
        {
            fail!(E2BIG, "TURN_BOUNDS");
        }
        let digest = *blake3::hash(&enclave_core::ipc::to_cbor(&(
            &caller,
            &turn,
            &attachments,
            &tools,
            holder_pk,
            budget_mb,
        ))?)
        .as_bytes();
        let dev = st.dev_same_uid;
        // Cursor, digest, mint, registry and response cache share State. A
        // failed/retired sequence cannot replay into a new root or QIF budget.
        {
            let cursor = st.gateway_recovery.cursor(peer, dev)?;
            if let Some(old) = cursor.active.get(&submission_seq) {
                if old.digest != digest {
                    fail!(EPERM, "GATEWAY_SUBMISSION_MISMATCH");
                }
                if old.closing || ended(&cursor.watch) || ended(&old.watch) {
                    fail!(EPERM, "GATEWAY_SUBMISSION_RETIRED");
                }
                st.turns.active(peer, &old.turn_id)?;
                return Ok(old.response.clone());
            }
            if submission_seq <= cursor.high_water {
                fail!(EPERM, "GATEWAY_SUBMISSION_RETIRED");
            }
            if ended(&cursor.watch) {
                fail!(EPERM, "GATEWAY_PROCESS_ENDED");
            }
            cursor.high_water = submission_seq;
        }
        let shared = st
            .gateway_recovery
            .owners
            .values()
            .flat_map(|owner| owner.active.values())
            .find(|old| old.caller == caller)
            .map(|old| old.watch.clone());
        let watch = match shared {
            Some(watch) => watch,
            None => capture(&caller, dev)?,
        };
        if ended(&watch) {
            fail!(EPERM, "GATEWAY_CALLER_ENDED");
        }
        let remaining = st.gateway_recovery.remaining_bytes();
        let (response, event, retained_bytes) = self.begin_turn_locked(
            st,
            peer,
            turn,
            attachments,
            tools,
            holder_pk,
            budget_mb,
            Some(remaining),
        )?;
        let IfcResponse::TurnPlan {turn_id,..}=&response else {fail!(EIO,"GATEWAY_RECOVERY_RESPONSE");};
        st.gateway_recovery.cursor(peer, dev)?.active.insert(
            submission_seq,
            Submission {
                digest,
                caller,
                watch,
                response: response.clone(),
                turn_id: turn_id.clone(),
                closing: false,
                retained_bytes,
            },
        );
        let seq = st.seq.next()?;
        if let (Some(j), Some(event)) = (st.journal.as_mut(), event) {
            j.append(seq, event)?;
        }
        Ok(response)
    }

    pub(super) fn cancel_gateway_submission(
        &self,
        peer: &PeerCredentials,
        submission_seq: u64,
    ) -> EnclaveResult<IfcResponse> {
        if submission_seq == 0 {
            fail!(EINVAL, "GATEWAY_SUBMISSION_SEQUENCE");
        }
        let id = {
            let mut guard = self.lock()?;
            let st = &mut *guard;
            Self::gateway_peer(st, peer)?;
            let cursor = st.gateway_recovery.cursor(peer, st.dev_same_uid)?;
            // Retirement precedes Finish. Even if Cancel overtakes Begin, a
            // later Begin cannot allocate; failed SSM cleanup retains active.
            cursor.high_water = cursor.high_water.max(submission_seq);
            cursor.active.get_mut(&submission_seq).map(|old| {
                old.closing = true;
                old.turn_id.clone()
            })
        };
        if let Some(id) = id {
            self.finish_turn_internal(peer, &id, true, true)?;
        }
        Ok(IfcResponse::Ok)
    }

    pub(super) fn recover_gateway_turns(
        &self,
        peer: &PeerCredentials,
    ) -> EnclaveResult<IfcResponse> {
        {
            let st = self.lock()?;
            Self::gateway_peer(&st, peer)?;
        }
        let _ = self.maintain_gateway_turns();
        let st = self.lock()?;
        let active_turns = st
            .gateway_recovery
            .owners
            .values()
            .filter(|owner| owner.owner == *peer)
            .flat_map(|owner| owner.active.values().map(|old| old.turn_id.clone()))
            .collect();
        Ok(IfcResponse::GatewayTurns { active_turns })
    }

    /// Attempt at most one positively abandoned cancellation per call. The
    /// rotating scan is bounded by 64 active turns; a failed runner cleanup
    /// cannot starve other abandoned turns. No legacy/admin turn is swept.
    pub fn maintain_gateway_turns(&self) -> EnclaveResult<usize> {
        let mut next = match self.recovery_gate.try_lock() {
            Ok(next) => next,
            Err(_) => return Ok(0),
        };
        let candidates = {
            let st = self.lock()?;
            st.gateway_recovery
                .owners
                .values()
                .flat_map(|owner| {
                    owner.active.values().map(|old| {
                        (
                            owner.owner.clone(),
                            old.turn_id.clone(),
                            owner.watch.clone(),
                            old.watch.clone(),
                        )
                    })
                })
                .collect::<Vec<_>>()
        };
        let mut result = Ok(0);
        for offset in 0..candidates.len() {
            let index = (*next + offset) % candidates.len();
            let (owner, id, gateway, caller) = &candidates[index];
            if ended(gateway) || ended(caller) {
                *next = (index + 1) % candidates.len();
                result = self
                    .finish_turn_internal(owner, id, true, true)
                    .map(|response| match response {
                        IfcResponse::TurnFinished { released } => released,
                        _ => 0,
                    });
                break;
            }
        }
        let mut st = self.lock()?;
        let st = &mut *st;
        st.gateway_recovery.prune_finished(&st.turns);
        st.gateway_recovery
            .owners
            .retain(|_, owner| !owner.active.is_empty() || !ended(&owner.watch));
        result
    }

    /// Start the daemon's bounded maintenance trigger. Weak ownership lets an
    /// embedding/service shutdown end the worker; no console admission needed.
    pub(crate) fn start_gateway_maintenance(self: &Arc<Self>) -> EnclaveResult<()> {
        let weak = Arc::downgrade(self);
        std::thread::Builder::new()
            .name("turn-recovery".into())
            .stack_size(256 * 1024)
            .spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_millis(250));
                let Some(service)=weak.upgrade() else {break;};
                let _ = service.maintain_gateway_turns();
            })
            .map_err(|e| err!(EIO, "TURN_RECOVERY_THREAD", "{e}"))?;
        Ok(())
    }
}
