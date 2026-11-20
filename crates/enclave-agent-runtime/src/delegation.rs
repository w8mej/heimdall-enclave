//! Sub-agent delegation with strict additive QIF conservation (FS-704 §5.4):
//! a parent's millibit slice must cover the sum of its children's slices,
//! delegation depth is `<= 4`, and a whole tree may make at most 64 calls.

use std::collections::HashMap;

use enclave_core::error::EnclaveResult;
use enclave_core::fail;
use enclave_crypto::biscuit_auth::Biscuit;
use enclave_crypto::pop_biscuit::{
    attenuate, mint_root, AuthorityClaims, DelegationCaveats, MAX_DEPTH,
};

use crate::pdp::Pdp;

/// Maximum calls per delegation tree.
pub const MAX_TREE_CALLS: u32 = 64;

/// Checked counterpart of the Lean signed-slice admissibility predicate.
/// Neither negative slices nor signed overflow may reach token attenuation.
pub fn checked_slice_total(delegated: i64, slice: i64, budget: i64) -> Option<i64> {
    if delegated < 0 || slice < 0 || budget < 0 {
        return None;
    }
    delegated
        .checked_add(slice)
        .filter(|total| *total <= budget)
}

#[derive(Debug, Clone)]
struct Node {
    budget_mb: i64,
    delegated_mb: i64,
    spent_mb: i64,
    depth: u32,
    root: [u8; 32],
}

/// Tracks budgets and calls of live delegation trees.
#[derive(Debug, Default)]
pub struct DelegationManager {
    nodes: HashMap<[u8; 32], Node>,
    tree_calls: HashMap<[u8; 32], u32>,
}

fn id(t: &Biscuit) -> [u8; 32] {
    // Sealing changes a Biscuit's proof bytes, but not its signed block
    // identifiers. Hash the authenticated chain so transported/sealed tokens
    // resolve to the same accounting node as the minted token. An appended
    // delegation block deliberately gives the child its own identity.
    let mut hash = blake3::Hasher::new();
    hash.update(b"depot-Delegation-Chain-v1\0");
    for signature in t.revocation_identifiers() {
        hash.update(&(signature.len() as u64).to_le_bytes());
        hash.update(&signature);
    }
    *hash.finalize().as_bytes()
}

impl DelegationManager {
    /// New.
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a root token for the orchestrator with the full budget, restricted
    /// to `allowed_tools` (tool URIs). The tool caveat is **always** present:
    /// an empty list yields a token that authorises no tool (DEFECT-F-67;
    /// an absent restriction means no tools, never all tools, cf. F-35).
    pub fn mint_root(
        &mut self,
        pdp: &Pdp,
        holder_pk: &[u8; 32],
        cb: &[u8; 32],
        budget_mb: i64,
        allowed_tools: &[String],
    ) -> EnclaveResult<Biscuit> {
        if budget_mb < 0 {
            fail!(EINVAL, "ROOT_BUDGET_NEGATIVE");
        }
        if let Some(bad) = allowed_tools.iter().find(|t| t.trim().is_empty()) {
            fail!(EINVAL, "ROOT_TOOL_NAME", "empty tool name {bad:?}");
        }
        let mut tools = allowed_tools.to_vec();
        tools.sort();
        tools.dedup();
        let claims = AuthorityClaims {
            boot_uuid: pdp.boot_epoch_id().to_owned(),
            effective_profile: pdp.profile().number(),
            policy_bundle_blake3: pdp.cedar_bundle_blake3(),
            max_c_clearance: 4,
            total_qif_budget_millibits: budget_mb,
            allowed_tools: Some(tools),
        };
        let t = mint_root(pdp.root(), &claims, holder_pk, cb)?;
        let i = id(&t);
        if self.nodes.contains_key(&i) {
            fail!(EACCES, "ROOT_TOKEN_ALREADY_TRACKED");
        }
        self.nodes.insert(
            i,
            Node {
                budget_mb,
                delegated_mb: 0,
                spent_mb: 0,
                depth: 0,
                root: i,
            },
        );
        self.tree_calls.insert(i, 0);
        Ok(t)
    }

    /// Stable identity of a locally tracked root, for trusted turn lifetime.
    pub(crate) fn tracked_root(token: &Biscuit) -> [u8; 32] { id(token) }

    /// Revoke a completed/cancelled scoped tree. Existing tokens then fail
    /// UNKNOWN_TOKEN; this does not refund the persisted per-entity QIF ledger.
    pub(crate) fn retire_root(&mut self, root: [u8; 32]) {
        self.nodes.retain(|_, node| node.root != root);
        self.tree_calls.remove(&root);
    }

    /// Spawn a child with `slice_mb` taken from the parent's remaining budget.
    pub fn spawn(
        &mut self,
        parent: &Biscuit,
        caveats: &DelegationCaveats,
        child_pk: &[u8; 32],
        cb: &[u8; 32],
    ) -> EnclaveResult<Biscuit> {
        let pid = id(parent);
        let p = self
            .nodes
            .get(&pid)
            .cloned()
            .ok_or_else(|| enclave_core::err!(EACCES, "UNKNOWN_PARENT_TOKEN"))?;
        if p.depth + 1 > MAX_DEPTH {
            fail!(E2BIG, "DELEGATION_TOO_DEEP");
        }
        let slice = caveats.max_qif_call_millibits;
        let next_delegated = checked_slice_total(p.delegated_mb, slice, p.budget_mb - p.spent_mb)
            .ok_or_else(|| {
            enclave_core::err!(
                EACCES,
                "QIF_CONSERVATION_VIOLATION",
                "children would exceed parent slice ({} + {slice} > {})",
                p.delegated_mb,
                p.budget_mb
            )
        })?;
        let child = attenuate(parent, caveats, child_pk, cb)?;
        let child_id = id(&child);
        if self.nodes.contains_key(&child_id) {
            fail!(EACCES, "CHILD_TOKEN_ALREADY_TRACKED");
        }
        if let Some(n) = self.nodes.get_mut(&pid) {
            n.delegated_mb = next_delegated;
        }
        self.nodes.insert(
            child_id,
            Node {
                budget_mb: slice,
                delegated_mb: 0,
                spent_mb: 0,
                depth: p.depth + 1,
                root: p.root,
            },
        );
        Ok(child)
    }

    /// Account one call made with `token`'s tree.
    pub fn record_call(&mut self, token: &Biscuit) -> EnclaveResult<u32> {
        self.record_call_with_charge(token, 0)
    }

    /// Reserve a call and its cumulative QIF debit atomically. Delegated slices
    /// are exclusive: a parent cannot spend a slice already assigned to a child.
    /// The reservation remains consumed if later settlement/persistence fails.
    pub fn record_call_with_charge(&mut self, token: &Biscuit, qif_mb: i64) -> EnclaveResult<u32> {
        let token_id = id(token);
        let n = self
            .nodes
            .get(&token_id)
            .ok_or_else(|| enclave_core::err!(EACCES, "UNKNOWN_TOKEN"))?;
        let next_spent = checked_slice_total(n.spent_mb, qif_mb, n.budget_mb - n.delegated_mb)
            .ok_or_else(|| enclave_core::err!(EACCES, "QIF_CONSERVATION_VIOLATION"))?;
        let root = n.root;
        let c = self.tree_calls.entry(root).or_insert(0);
        if *c >= MAX_TREE_CALLS {
            fail!(EAGAIN, "TREE_CALL_BUDGET_EXHAUSTED");
        }
        *c += 1;
        // The node was checked above and no map mutation can remove it here.
        self.nodes
            .get_mut(&token_id)
            .expect("checked accounting node")
            .spent_mb = next_spent;
        Ok(*c)
    }
}
