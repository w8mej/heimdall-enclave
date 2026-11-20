//! Token-level view of a byte [`Dfa`] for grammar-constrained decoding with
//! a real tokenizer.
//!
//! A token moves the DFA by its whole byte string, so the transitions of each
//! state are the tokens whose bytes the DFA accepts from it. They are found
//! by walking a byte trie of the vocabulary along DFA transitions, which
//! visits only viable prefixes instead of every token from every state.
//!
//! The end-of-text token takes the DFA's [`PAD`] edge, so it can only follow
//! a complete document and repeat to the end of the block. Every other added
//! (special) token, including a diffusion mask token, is never placeable.

use enclave_core::error::EnclaveResult;
use enclave_core::fail;

use crate::dfa::{Dfa, Lattice, PAD};
use crate::tokenizer::Tokenizer;

/// Upper bound on trie nodes (every byte of every token, plus the root).
const MAX_TRIE_NODES: usize = 1 << 24;
/// Upper bound on token transitions across all DFA states.
const MAX_TOKEN_EDGES: usize = 1 << 22;

/// Byte trie of a tokenizer's ordinary tokens; built once per tokenizer
/// and held for the life of the binding, so it is laid out flat: nodes are
/// numbered breadth first, which makes the `k`-th edge lead to node `k + 1`
/// and leaves about nine bytes per node (LLaDA: 286k nodes, ~3 MB) under
/// the runner's resident-memory ceiling.
#[derive(Debug)]
pub struct VocabTrie {
    /// Per node `n`: its edges are `child_start[n]..child_start[n + 1]`.
    child_start: Vec<u32>,
    /// Per edge `k` (sorted by byte within a node): the byte; it leads to node `k + 1`.
    child_byte: Vec<u8>,
    /// Per node `n`: its tokens are `end_ids[end_start[n]..end_start[n + 1]]`.
    end_start: Vec<u32>,
    /// Ids of tokens ending at each node, grouped by node.
    end_ids: Vec<u32>,
}

impl VocabTrie {
    /// Build over every non-empty, non-special token without a [`PAD`] byte.
    pub fn build(tokenizer: &Tokenizer) -> EnclaveResult<Self> {
        let bytes = |id: u32| tokenizer.token(id).unwrap_or_default();
        let mut ids: Vec<u32> = (0..tokenizer.vocab() as u32)
            .filter(|&id| !tokenizer.is_special(id))
            .filter(|&id| tokenizer.token(id).is_some_and(|b| !b.is_empty() && !b.contains(&PAD)))
            .collect();
        ids.sort_by(|a, b| bytes(*a).cmp(bytes(*b)).then(a.cmp(b)));
        let mut trie = Self { child_start: vec![0], child_byte: Vec::new(), end_start: vec![0], end_ids: Vec::new() };
        // Breadth first over (sorted id range, depth): a node's tokens are a
        // contiguous run of `ids`, those ending at this depth first.
        let mut queue = std::collections::VecDeque::from([(0usize, ids.len(), 0usize)]);
        while let Some((lo, hi, depth)) = queue.pop_front() {
            let mut i = lo;
            while i < hi && bytes(ids[i]).len() == depth {
                trie.end_ids.push(ids[i]);
                i += 1;
            }
            while i < hi {
                let b = bytes(ids[i])[depth];
                let start = i;
                while i < hi && bytes(ids[i])[depth] == b {
                    i += 1;
                }
                if trie.child_byte.len() + 1 >= MAX_TRIE_NODES {
                    fail!(E2BIG, "TOKEN_TRIE_BOUNDS");
                }
                trie.child_byte.push(b);
                queue.push_back((start, i, depth + 1));
            }
            trie.child_start.push(trie.child_byte.len() as u32);
            trie.end_start.push(trie.end_ids.len() as u32);
        }
        trie.child_start.shrink_to_fit();
        trie.end_start.shrink_to_fit();
        trie.child_byte.shrink_to_fit();
        trie.end_ids.shrink_to_fit();
        Ok(trie)
    }

    /// Nodes, including the root.
    pub fn nodes(&self) -> usize {
        self.child_start.len() - 1
    }

    /// Heap bytes held (the trie lives as long as the binding).
    pub fn heap_bytes(&self) -> usize {
        4 * (self.child_start.capacity() + self.end_start.capacity() + self.end_ids.capacity())
            + self.child_byte.capacity()
    }

    fn ends(&self, node: usize) -> &[u32] {
        &self.end_ids[self.end_start[node] as usize..self.end_start[node + 1] as usize]
    }

    fn children(&self, node: usize) -> impl Iterator<Item = (u8, usize)> + '_ {
        let (a, b) = (self.child_start[node] as usize, self.child_start[node + 1] as usize);
        (a..b).map(|k| (self.child_byte[k], k + 1))
    }
}

/// The token transitions of one DFA; see the module docs.
#[derive(Debug)]
pub struct TokenLattice<'a> {
    dfa: &'a Dfa,
    /// Per DFA state: `(token, next state)` sorted by token.
    by_state: Vec<Vec<(u32, u32)>>,
    /// End-of-text token, mapped to the DFA's `PAD` edge.
    end: u32,
    edges: usize,
}

impl<'a> TokenLattice<'a> {
    /// Token transitions of `dfa` over `trie`, with `end` as end-of-text.
    pub fn build(dfa: &'a Dfa, trie: &VocabTrie, end: u32) -> EnclaveResult<Self> {
        let mut by_state = Vec::with_capacity(dfa.states());
        let mut edges = 0usize;
        for q in 0..dfa.states() as u32 {
            let mut out = Vec::new();
            // Depth-first over (trie node, DFA state) pairs reachable from q.
            let mut stack = vec![(0usize, q)];
            while let Some((node, state)) = stack.pop() {
                out.extend(trie.ends(node).iter().map(|&id| (id, state)));
                for (b, child) in trie.children(node) {
                    if let Some(next) = dfa.step(state, b) {
                        stack.push((child, next));
                    }
                }
            }
            if let Some(next) = dfa.step(q, PAD) {
                out.push((end, next));
            }
            out.sort_unstable();
            edges += out.len();
            if edges > MAX_TOKEN_EDGES {
                fail!(E2BIG, "TOKEN_LATTICE_BOUNDS");
            }
            by_state.push(out);
        }
        Ok(Self { dfa, by_state, end, edges })
    }

    /// End-of-text token.
    pub fn end(&self) -> u32 {
        self.end
    }
}

impl Lattice for TokenLattice<'_> {
    type Sym = u32;
    fn states(&self) -> usize { self.dfa.states() }
    fn start(&self) -> u32 { self.dfa.start() }
    fn accepting(&self, q: u32) -> bool { self.dfa.accepting(q) }
    fn step(&self, q: u32, token: u32) -> Option<u32> {
        let out = self.by_state.get(q as usize)?;
        out.binary_search_by_key(&token, |(t, _)| *t).ok().map(|at| out[at].1)
    }
    fn out(&self, q: u32) -> impl Iterator<Item = (u32, u32)> + '_ {
        self.by_state[q as usize].iter().copied()
    }
    fn edges(&self) -> usize { self.edges }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dfa::{ArgSchema, Trellis};

    fn schema() -> ArgSchema {
        ArgSchema::Object(vec![("priority".into(), ArgSchema::Enum(vec!["routine".into(), "urgent".into()]))])
    }

    fn setup() -> (Tokenizer, Dfa, VocabTrie, u32) {
        let tokenizer = crate::tokenizer::tiny_for_tests();
        let end = tokenizer.special("<|end|>").unwrap();
        let trie = VocabTrie::build(&tokenizer).unwrap();
        (tokenizer, Dfa::compile(&schema()).unwrap(), trie, end)
    }

    fn walk(dfa: &Dfa, mut q: u32, bytes: &[u8]) -> Option<u32> {
        for b in bytes {
            q = dfa.step(q, *b)?;
        }
        Some(q)
    }

    /// Every token transition equals walking the DFA over the token's bytes.
    /// No special token other than end-of-text ever appears, and padding
    /// comes only from end-of-text, never from a token carrying a PAD byte.
    #[test]
    fn token_steps_equal_byte_walks_for_every_state_and_token() {
        let (tokenizer, dfa, trie, end) = setup();
        let lattice = TokenLattice::build(&dfa, &trie, end).unwrap();
        for q in 0..dfa.states() as u32 {
            for id in 0..tokenizer.vocab() as u32 {
                let bytes = tokenizer.token(id).unwrap();
                let expected = if id == end {
                    dfa.step(q, PAD)
                } else if tokenizer.is_special(id) || bytes.contains(&PAD) {
                    None
                } else {
                    walk(&dfa, q, bytes)
                };
                assert_eq!(lattice.step(q, id), expected, "state {q} token {id}");
            }
        }
    }

    /// Committing the greedy permitted token at each position yields an
    /// accepted document: the trellis keeps every token block satisfiable.
    #[test]
    fn trellis_over_tokens_only_permits_completable_documents() {
        let (tokenizer, dfa, trie, end) = setup();
        let lattice = TokenLattice::build(&dfa, &trie, end).unwrap();
        let len = 40;
        let mut x: Vec<Option<u32>> = vec![None; len];
        let mut tr = Trellis::build(&lattice, &x);
        let (cancel, start, mut budget) = (std::sync::atomic::AtomicBool::new(false), std::time::Instant::now(), usize::MAX);
        // Commit out of order (from the back half first) to exercise both frontiers.
        let order: Vec<usize> = (len / 2..len).chain(0..len / 2).collect();
        for i in order {
            assert!(tr.satisfiable());
            let token = tr.permitted(&lattice, i).max().expect("a satisfiable block permits a token");
            x[i] = Some(token);
            tr.commit(&lattice, &x, i, &mut budget, &cancel, start + std::time::Duration::from_secs(60)).unwrap();
        }
        let ids: Vec<u32> = x.iter().map(|t| t.unwrap()).filter(|t| *t != end).collect();
        let text = tokenizer.decode(&ids).unwrap();
        assert!(dfa.accepts(&text), "{:?}", String::from_utf8_lossy(&text));
        let doc: serde_json::Value = serde_json::from_slice(&text).unwrap();
        assert!(["routine", "urgent"].contains(&doc["priority"].as_str().unwrap()));
    }

    #[test]
    fn a_block_too_short_for_any_document_is_unsatisfiable() {
        let (_, dfa, trie, end) = setup();
        let lattice = TokenLattice::build(&dfa, &trie, end).unwrap();
        // `{"priority":"urgent"}` needs more than three of these tokens.
        assert!(!Trellis::build(&lattice, &[None; 3]).satisfiable());
    }
}
