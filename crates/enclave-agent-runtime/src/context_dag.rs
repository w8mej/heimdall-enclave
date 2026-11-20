//! Multi-turn conversation context DAG provenance & taint tracking (FS-704 §3.1, §5.1, GAP-61).
//!
//! Models multi-turn agent interactions as a directed acyclic graph (DAG), tracking
//! fine-grained Biba integrity labels ($T_0$ to $T_3$) across prompt revisions and tool
//! outputs to prevent indirect prompt injection vectors from silently corrupting
//! privileged agent contexts.

#![forbid(unsafe_code)]

use enclave_core::error::EnclaveResult;
use enclave_core::label::{Conf, Taint};
use enclave_core::{err, fail};
use std::collections::HashMap;

/// Unique identifier of a conversation DAG node.
pub type NodeId = u64;

/// A node in the conversation context DAG representing a prompt turn, attachment, or tool output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextNode {
    /// Unique node ID.
    pub id: NodeId,
    /// Parent node IDs from which this node derives context.
    pub parents: Vec<NodeId>,
    /// Biba integrity taint label ($T_0$ hardware, $T_1$ verified plan, $T_2$ scoped tool, $T_3$ untrusted).
    pub integrity: Taint,
    /// Confidentiality sensitivity level ($C_1$ public to $C_4$ restricted).
    pub confidentiality: Conf,
    /// Whether an attested sanitization filter was successfully applied.
    pub is_sanitized: bool,
    /// Blake3 cryptographic digest of the node payload.
    pub content_hash: [u8; 32],
}

/// Conversation context DAG managing fine-grained provenance tracking.
#[derive(Debug, Default)]
pub struct ContextDag {
    next_id: NodeId,
    nodes: HashMap<NodeId, ContextNode>,
}

impl ContextDag {
    /// Create a new empty context DAG.
    pub fn new() -> Self {
        Self {
            next_id: 1,
            nodes: HashMap::new(),
        }
    }

    /// Add a new node to the DAG.
    ///
    /// If `explicit_integ` is `None`, the node's integrity is automatically computed
    /// by joining the integrity levels of all parent nodes. If any parent carries $T_3$
    /// taint (untrusted external source / prompt injection risk), the child unconditionally
    /// inherits $T_3$.
    pub fn add_node(
        &mut self,
        parents: Vec<NodeId>,
        conf: Conf,
        explicit_integ: Option<Taint>,
        content_hash: [u8; 32],
    ) -> EnclaveResult<NodeId> {
        let mut computed_integ = Taint::T0;

        for &p_id in &parents {
            let p = self
                .nodes
                .get(&p_id)
                .ok_or_else(|| err!(EINVAL, "UNKNOWN_PARENT_NODE", "parent {p_id} not in DAG"))?;
            computed_integ = computed_integ.max(p.integrity);
        }

        let final_integ = match explicit_integ {
            Some(i) => {
                // Cannot assert higher integrity (lower taint) than parents without sanitization
                if i < computed_integ {
                    fail!(
                        EACCES,
                        "INTEGRITY_VIOLATION",
                        "cannot assert integrity {i:?} higher than parent join {computed_integ:?}"
                    );
                }
                i
            }
            None => computed_integ,
        };

        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| err!(E2BIG, "CONTEXT_ID_EXHAUSTED"))?;

        let node = ContextNode {
            id,
            parents,
            integrity: final_integ,
            confidentiality: conf,
            is_sanitized: false,
            content_hash,
        };

        self.nodes.insert(id, node);
        Ok(id)
    }

    /// Retrieve a node by ID.
    pub fn get_node(&self, id: NodeId) -> Option<&ContextNode> {
        self.nodes.get(&id)
    }

    /// Apply an attested sanitization gate to a node, elevating its integrity to $T_1$.
    pub fn sanitize_node(&mut self, id: NodeId, sanitized_hash: [u8; 32]) -> EnclaveResult<()> {
        let node = self
            .nodes
            .get_mut(&id)
            .ok_or_else(|| err!(EINVAL, "UNKNOWN_NODE", "node {id} not found in DAG"))?;
        node.integrity = Taint::T1;
        node.is_sanitized = true;
        node.content_hash = sanitized_hash;
        Ok(())
    }

    /// Check whether a node is tainted with untrusted data ($T_3$).
    pub fn is_untrusted(&self, id: NodeId) -> EnclaveResult<bool> {
        let node = self
            .nodes
            .get(&id)
            .ok_or_else(|| err!(EINVAL, "UNKNOWN_NODE", "node {id} not found in DAG"))?;
        Ok(node.integrity == Taint::T3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhausted_node_ids_never_wrap_or_replace_existing_nodes() {
        let mut dag = ContextDag::new();
        let original = dag
            .add_node(vec![], Conf::C1, Some(Taint::T3), [1; 32])
            .unwrap();
        let before = dag.get_node(original).unwrap().clone();
        dag.next_id = u64::MAX;
        for _ in 0..2 {
            assert!(dag
                .add_node(vec![original], Conf::C1, None, [2; 32])
                .unwrap_err()
                .is("CONTEXT_ID_EXHAUSTED"));
            assert_eq!(dag.next_id, u64::MAX);
            assert_eq!(dag.nodes.len(), 1);
            assert_eq!(dag.get_node(original), Some(&before));
        }
    }

    #[test]
    fn test_context_dag_taint_propagation() {
        let mut dag = ContextDag::new();

        // Node 1: Trusted system prompt (T1)
        let n1 = dag
            .add_node(vec![], Conf::C1, Some(Taint::T1), [1u8; 32])
            .unwrap();
        assert_eq!(dag.get_node(n1).unwrap().integrity, Taint::T1);

        // Node 2: Untrusted external tool response (T3)
        let n2 = dag
            .add_node(vec![], Conf::C2, Some(Taint::T3), [2u8; 32])
            .unwrap();
        assert_eq!(dag.get_node(n2).unwrap().integrity, Taint::T3);

        // Node 3: Derived turn combining N1 and N2 -> must propagate T3
        let n3 = dag
            .add_node(vec![n1, n2], Conf::C2, None, [3u8; 32])
            .unwrap();
        assert_eq!(dag.get_node(n3).unwrap().integrity, Taint::T3);
        assert!(dag.is_untrusted(n3).unwrap());

        // Sanitizing Node 3 elevates integrity to T1
        dag.sanitize_node(n3, [4u8; 32]).unwrap();
        assert_eq!(dag.get_node(n3).unwrap().integrity, Taint::T1);
        assert!(!dag.is_untrusted(n3).unwrap());
    }
}
