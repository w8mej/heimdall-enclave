//! Byte-level DFAs compiled ahead of time from bounded-depth (`d <= 4`) depot
//! tool-argument schemas (FS-701 §4.2.1: `<= 4,096` states), plus the
//! `DINGO` forward/backward reachability trellis over partially-masked
//! sequences.
//!
//! The schema language covers what typed depot tool calls need: objects with a
//! fixed key order, string enums, booleans, bounded unsigned integers and
//! nested objects. The accepted language is canonical compact JSON, padded
//! with [`PAD`] bytes to the block length.

use std::collections::BTreeMap;

use enclave_core::error::EnclaveResult;
use enclave_core::fail;
use serde::{Deserialize, Serialize};

/// Maximum DFA size.
pub const MAX_STATES: usize = 4096;
/// Maximum schema nesting depth.
pub const MAX_DEPTH: usize = 4;
/// Padding byte after the accepted document.
pub const PAD: u8 = 0;

/// Tool-argument schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArgSchema {
    /// `{"k1":v1,"k2":v2,...}` in this exact key order.
    Object(Vec<(String, ArgSchema)>),
    /// One of these strings (JSON-quoted on the wire).
    Enum(Vec<String>),
    /// `true` / `false`.
    Bool,
    /// Unsigned integer with at most `max_digits` digits and no leading zero.
    UInt {
        /// Maximum digits (`1..=19`).
        max_digits: u8,
    },
}

impl ArgSchema {
    fn depth(&self) -> usize {
        match self {
            ArgSchema::Object(f) => 1 + f.iter().map(|(_, s)| s.depth()).max().unwrap_or(0),
            _ => 0,
        }
    }
}

/// A deterministic byte automaton.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dfa {
    trans: Vec<BTreeMap<u8, u32>>,
    accept: Vec<bool>,
    start: u32,
}

impl Dfa {
    fn new_state(&mut self) -> EnclaveResult<u32> {
        if self.trans.len() >= MAX_STATES {
            fail!(E2BIG, "DFA_TOO_LARGE", "> {MAX_STATES} states");
        }
        self.trans.push(BTreeMap::new());
        self.accept.push(false);
        Ok((self.trans.len() - 1) as u32)
    }

    /// States.
    pub fn states(&self) -> usize {
        self.trans.len()
    }
    /// Start state.
    pub fn start(&self) -> u32 {
        self.start
    }
    /// Transition (`None` = dead).
    pub fn step(&self, q: u32, b: u8) -> Option<u32> {
        self.trans.get(q as usize)?.get(&b).copied()
    }
    /// Accepting?
    pub fn accepting(&self, q: u32) -> bool {
        self.accept.get(q as usize).copied().unwrap_or(false)
    }
    /// Run over a whole sequence.
    pub fn accepts(&self, s: &[u8]) -> bool {
        let mut q = self.start;
        for b in s {
            match self.step(q, *b) {
                Some(n) => q = n,
                None => return false,
            }
        }
        self.accepting(q)
    }
    /// Outgoing bytes of `q`.
    pub fn out(&self, q: u32) -> impl Iterator<Item = (u8, u32)> + '_ {
        self.trans[q as usize].iter().map(|(b, n)| (*b, *n))
    }

    /// Literal chain `lit` then continue at `k`.
    fn literal(&mut self, lit: &[u8], k: u32) -> EnclaveResult<u32> {
        let mut next = k;
        for b in lit.iter().rev() {
            let s = self.new_state()?;
            self.trans[s as usize].insert(*b, next);
            next = s;
        }
        Ok(next)
    }

    /// Copy `k`'s outgoing edges / acceptance into `s` (epsilon-merge; safe
    /// because the merged alphabets are disjoint by construction).
    fn merge_into(&mut self, s: u32, k: u32) -> EnclaveResult<()> {
        let edges: Vec<(u8, u32)> = self.out(k).collect();
        for (b, n) in edges {
            if self.trans[s as usize]
                .insert(b, n)
                .is_some_and(|old| old != n)
            {
                fail!(EINVAL, "DFA_NONDETERMINISTIC");
            }
        }
        if self.accept[k as usize] {
            self.accept[s as usize] = true;
        }
        Ok(())
    }

    /// Alternatives (trie) of literal strings, each continuing at `k`.
    fn alternatives(&mut self, alts: &[Vec<u8>], k: u32) -> EnclaveResult<u32> {
        let root = self.new_state()?;
        for a in alts {
            let mut q = root;
            for (i, b) in a.iter().enumerate() {
                let last = i + 1 == a.len();
                match self.trans[q as usize].get(b).copied() {
                    Some(n) if n == k && !last => fail!(EINVAL, "SCHEMA_AMBIGUOUS_ENUM"),
                    Some(n) if !last => q = n,
                    Some(n) if n == k => {}
                    Some(_) => fail!(EINVAL, "SCHEMA_AMBIGUOUS_ENUM"),
                    None => {
                        let n = if last { k } else { self.new_state()? };
                        self.trans[q as usize].insert(*b, n);
                        q = n;
                    }
                }
            }
        }
        Ok(root)
    }

    fn compile_value(&mut self, s: &ArgSchema, k: u32) -> EnclaveResult<u32> {
        match s {
            ArgSchema::Bool => self.alternatives(&[b"true".to_vec(), b"false".to_vec()], k),
            ArgSchema::Enum(v) => {
                if v.is_empty() || v.len() > 256 {
                    fail!(EINVAL, "SCHEMA_ENUM_SIZE");
                }
                let alts: Vec<Vec<u8>> = v
                    .iter()
                    .map(|x| {
                        if x.bytes().any(|b| b == b'"' || b == b'\\' || b < 0x20) {
                            Err(enclave_core::err!(EINVAL, "SCHEMA_ENUM_CHARS"))
                        } else {
                            Ok(format!("\"{x}\"").into_bytes())
                        }
                    })
                    .collect::<EnclaveResult<_>>()?;
                self.alternatives(&alts, k)
            }
            ArgSchema::UInt { max_digits } => {
                if !(1..=19).contains(max_digits) {
                    fail!(EINVAL, "SCHEMA_UINT_DIGITS");
                }
                // d_i = "after i digits" (1..=max); each merges k's edges.
                let mut after: Vec<u32> = Vec::new();
                for _ in 0..*max_digits {
                    after.push(self.new_state()?);
                }
                for i in 0..after.len() {
                    if i + 1 < after.len() {
                        for d in b'0'..=b'9' {
                            self.trans[after[i] as usize].insert(d, after[i + 1]);
                        }
                    }
                    self.merge_into(after[i], k)?;
                }
                let start = self.new_state()?;
                let z = self.new_state()?;
                self.merge_into(z, k)?;
                self.trans[start as usize].insert(b'0', z);
                for d in b'1'..=b'9' {
                    self.trans[start as usize].insert(d, after[0]);
                }
                Ok(start)
            }
            ArgSchema::Object(fields) => {
                let mut next = self.literal(b"}", k)?;
                for (i, (name, v)) in fields.iter().enumerate().rev() {
                    if name.is_empty() || name.bytes().any(|b| b == b'"' || b == b'\\' || b < 0x20)
                    {
                        fail!(EINVAL, "SCHEMA_KEY_CHARS");
                    }
                    let val = self.compile_value(v, next)?;
                    let sep = if i == 0 { String::new() } else { ",".into() };
                    next = self.literal(format!("{sep}\"{name}\":").as_bytes(), val)?;
                }
                self.literal(b"{", next)
            }
        }
    }

    /// Compile a schema (`depth <= 4`, `<= 4096` states), accepting the
    /// canonical document followed by any number of [`PAD`] bytes.
    pub fn compile(schema: &ArgSchema) -> EnclaveResult<Self> {
        if schema.depth() > MAX_DEPTH {
            fail!(
                E2BIG,
                "SCHEMA_DEPTH_EXCEEDED",
                "depth {} > {MAX_DEPTH}",
                schema.depth()
            );
        }
        let mut d = Dfa {
            trans: Vec::new(),
            accept: Vec::new(),
            start: 0,
        };
        let pad = d.new_state()?;
        d.accept[pad as usize] = true;
        d.trans[pad as usize].insert(PAD, pad);
        d.start = d.compile_value(schema, pad)?;
        Ok(d)
    }
}

/// A finite automaton a [`Trellis`] can run over: the byte [`Dfa`] itself,
/// or a token-level view of it (`crate::token_lattice::TokenLattice`).
pub trait Lattice {
    /// One position's symbol (a byte, or a token id).
    type Sym: Copy;
    /// Number of states.
    fn states(&self) -> usize;
    /// Start state.
    fn start(&self) -> u32;
    /// Accepting?
    fn accepting(&self, q: u32) -> bool;
    /// Transition on one symbol (`None` = dead).
    fn step(&self, q: u32, s: Self::Sym) -> Option<u32>;
    /// Outgoing `(symbol, next)` pairs of `q`.
    fn out(&self, q: u32) -> impl Iterator<Item = (Self::Sym, u32)> + '_;
    /// Total transitions, the unit of trellis work.
    fn edges(&self) -> usize;
}

impl Lattice for Dfa {
    type Sym = u8;
    fn states(&self) -> usize { Dfa::states(self) }
    fn start(&self) -> u32 { Dfa::start(self) }
    fn accepting(&self, q: u32) -> bool { Dfa::accepting(self, q) }
    fn step(&self, q: u32, b: u8) -> Option<u32> { Dfa::step(self, q, b) }
    fn out(&self, q: u32) -> impl Iterator<Item = (u8, u32)> + '_ { Dfa::out(self, q) }
    fn edges(&self) -> usize { self.trans.iter().map(BTreeMap::len).sum() }
}

/// `DINGO` trellis over a block of `L` positions (`Some(sym)` committed,
/// `None` = `[MASK]`), over any [`Lattice`].
#[derive(Debug, Clone)]
pub struct Trellis {
    fwd: Vec<Vec<bool>>,
    bwd: Vec<Vec<bool>>,
}

/// States reachable from `live` by position `x` (`None` = any symbol).
fn forward<L: Lattice>(l: &L, live: &[bool], x: Option<L::Sym>) -> Vec<bool> {
    let mut next = vec![false; l.states()];
    for (s, on) in live.iter().enumerate() {
        if !on {
            continue;
        }
        match x {
            Some(sym) => {
                if let Some(n) = l.step(s as u32, sym) {
                    next[n as usize] = true;
                }
            }
            None => {
                for (_, n) in l.out(s as u32) {
                    next[n as usize] = true;
                }
            }
        }
    }
    next
}

/// States from which position `x` reaches a state live in `after`.
fn backward<L: Lattice>(l: &L, after: &[bool], x: Option<L::Sym>) -> Vec<bool> {
    (0..l.states())
        .map(|s| match x {
            Some(sym) => l.step(s as u32, sym).is_some_and(|n| after[n as usize]),
            None => l.out(s as u32).any(|(_, n)| after[n as usize]),
        })
        .collect()
}

impl Trellis {
    /// Build `R_fwd`, `R_bwd` in `O(L * |Q| * fanout)`.
    pub fn build<L: Lattice>(l: &L, x: &[Option<L::Sym>]) -> Self {
        let (len, q) = (x.len(), l.states());
        let mut fwd = vec![vec![false; q]; len + 1];
        fwd[0][l.start() as usize] = true;
        for i in 0..len {
            fwd[i + 1] = forward(l, &fwd[i], x[i]);
        }
        let mut bwd = vec![vec![false; q]; len + 1];
        for (s, v) in bwd[len].iter_mut().enumerate() {
            *v = l.accepting(s as u32);
        }
        for i in (0..len).rev() {
            bwd[i] = backward(l, &bwd[i + 1], x[i]);
        }
        Self { fwd, bwd }
    }

    /// Bound storage and initial transition work before allocating reachability.
    pub fn check_budget<L: Lattice>(l: &L, len: usize) -> EnclaveResult<()> {
        let cells = len.checked_add(1).and_then(|n| n.checked_mul(l.states()));
        if !cells.is_some_and(|n| n <= 1_048_576)
            || !len.checked_mul(l.edges()).is_some_and(|n| n <= 2_000_000)
        {
            fail!(E2BIG, "DIFFUSION_WORK_BUDGET");
        }
        Ok(())
    }

    /// Incrementally propagate the constraint at `i` until each frontier stops
    /// changing. Reuse both tables; no full trellis allocation per commitment.
    pub fn commit<L: Lattice>(
        &mut self,
        l: &L,
        x: &[Option<L::Sym>],
        i: usize,
        budget: &mut usize,
        cancel: &std::sync::atomic::AtomicBool,
        deadline: std::time::Instant,
    ) -> EnclaveResult<()> {
        let cost = l.edges().max(l.states());
        let check = |budget: &mut usize| -> EnclaveResult<()> {
            if cancel.load(std::sync::atomic::Ordering::Acquire) {
                fail!(EAGAIN, "GENERATION_CANCELLED");
            }
            if std::time::Instant::now() > deadline {
                fail!(ETIMEDOUT, "GENERATION_DEADLINE");
            }
            *budget = budget
                .checked_sub(cost)
                .ok_or_else(|| enclave_core::err!(E2BIG, "DIFFUSION_WORK_BUDGET"))?;
            Ok(())
        };
        for j in i..x.len() {
            check(budget)?;
            let next = forward(l, &self.fwd[j], x[j]);
            if next == self.fwd[j + 1] {
                break;
            }
            self.fwd[j + 1] = next;
        }
        for j in (0..=i).rev() {
            check(budget)?;
            let prev = backward(l, &self.bwd[j + 1], x[j]);
            if prev == self.bwd[j] {
                break;
            }
            self.bwd[j] = prev;
        }
        Ok(())
    }

    /// Whether some completion of the block is accepted.
    pub fn satisfiable(&self) -> bool {
        self.bwd[0].iter().zip(&self.fwd[0]).any(|(b, f)| *b && *f)
    }

    /// Symbols permitted at masked position `i`, in the lattice's out order
    /// per live state (a symbol may repeat across states).
    pub fn permitted<'a, L: Lattice>(&'a self, l: &'a L, i: usize) -> impl Iterator<Item = L::Sym> + 'a {
        self.fwd[i]
            .iter()
            .enumerate()
            .filter(|(_, live)| **live)
            .flat_map(move |(s, _)| l.out(s as u32))
            .filter(move |(_, n)| self.bwd[i + 1][*n as usize])
            .map(|(sym, _)| sym)
    }

    /// Whether `sym` is permitted at masked position `i`.
    pub fn permits<L: Lattice>(&self, l: &L, i: usize, sym: L::Sym) -> bool
    where
        L::Sym: PartialEq,
    {
        self.fwd[i].iter().enumerate().filter(|(_, live)| **live).any(|(s, _)| {
            l.step(s as u32, sym).is_some_and(|n| self.bwd[i + 1][n as usize])
        })
    }

    /// Bytes permitted at masked position `i`.
    pub fn allowed(&self, dfa: &Dfa, i: usize) -> [bool; 256] {
        let mut a = [false; 256];
        for b in self.permitted(dfa, i) {
            a[b as usize] = true;
        }
        a
    }
}

/// Strip trailing [`PAD`] bytes from this module's canonical JSON language.
/// JSON encodes NUL as an escape, so padding cannot remove content. Binary
/// schemas are unsupported and must not use this framing function.
pub fn unpad(v: &[u8]) -> &[u8] {
    let end = v.iter().rposition(|b| *b != PAD).map_or(0, |p| p + 1);
    &v[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema() -> ArgSchema {
        ArgSchema::Object(vec![
            (
                "action".into(),
                ArgSchema::Enum(vec!["open".into(), "close".into(), "archive".into()]),
            ),
            ("ticket".into(), ArgSchema::UInt { max_digits: 6 }),
            ("notify".into(), ArgSchema::Bool),
            (
                "meta".into(),
                ArgSchema::Object(vec![(
                    "tier".into(),
                    ArgSchema::Enum(vec!["a".into(), "b".into()]),
                )]),
            ),
        ])
    }

    #[test]
    fn f139_incremental_frontiers_match_independent_full_rebuild() {
        use std::sync::atomic::AtomicBool;
        let d = Dfa::compile(&schema()).unwrap();
        let mut x = vec![None; 80];
        let mut tr = Trellis::build(&d, &x);
        let mut budget = 20_000_000;
        let cancel = AtomicBool::new(false);
        let start = std::time::Instant::now();
        // Adversarial nonsequential confidence order, including both ends.
        for i in (0..80).step_by(2).chain((1..80).rev().step_by(2)) {
            let allowed = tr.allowed(&d, i);
            let b = allowed.iter().position(|a| *a).unwrap();
            x[i] = Some(b as u8);
            tr.commit(&d, &x, i, &mut budget, &cancel, start + std::time::Duration::from_secs(60)).unwrap();
            let fresh = Trellis::build(&d, &x);
            assert_eq!(tr.fwd, fresh.fwd);
            assert_eq!(tr.bwd, fresh.bwd);
            assert!(tr.satisfiable());
        }
        assert!(d.accepts(&x.iter().map(|b| b.unwrap()).collect::<Vec<_>>()));
        assert!(Trellis::check_budget(&d, usize::MAX)
            .unwrap_err()
            .is("DIFFUSION_WORK_BUDGET"));
        assert!(Trellis::check_budget(&d, 65_536).is_err());
        assert!(Trellis::check_budget(&d, 80).is_ok());
    }

    #[test]
    fn compiles_and_accepts_only_canonical_documents() {
        let d = Dfa::compile(&schema()).unwrap();
        assert!(d.states() < 200);
        assert!(
            d.accepts(br#"{"action":"close","ticket":40213,"notify":false,"meta":{"tier":"b"}}"#)
        );
        assert!(d.accepts(
            b"{\"action\":\"open\",\"ticket\":0,\"notify\":true,\"meta\":{\"tier\":\"a\"}}\0\0\0"
        ));
        assert!(!d.accepts(br#"{"action":"delete","ticket":1,"notify":true,"meta":{"tier":"a"}}"#));
        assert!(!d.accepts(br#"{"action":"open","ticket":0123,"notify":true,"meta":{"tier":"a"}}"#));
        assert!(
            !d.accepts(br#"{"action":"open","ticket":1234567,"notify":true,"meta":{"tier":"a"}}"#)
        );
        assert!(!d.accepts(br#"{"ticket":1,"action":"open","notify":true,"meta":{"tier":"a"}}"#));
    }

    #[test]
    fn depth_and_size_bounds() {
        let mut s = ArgSchema::Bool;
        for _ in 0..5 {
            s = ArgSchema::Object(vec![("x".into(), s)]);
        }
        assert!(Dfa::compile(&s).unwrap_err().is("SCHEMA_DEPTH_EXCEEDED"));
        let big = ArgSchema::Object(
            (0..40)
                .map(|i| {
                    (
                        format!("field_{i:03}_padding_padding_padding"),
                        ArgSchema::Enum((0..200).map(|j| format!("value_{j:03}_{i}")).collect()),
                    )
                })
                .collect(),
        );
        assert!(Dfa::compile(&big).unwrap_err().is("DFA_TOO_LARGE"));
    }

    #[test]
    fn trellis_masks_only_completable_bytes() {
        let d = Dfa::compile(&ArgSchema::Object(vec![("ok".into(), ArgSchema::Bool)])).unwrap();
        let mut x: Vec<Option<u8>> = vec![None; 14];
        x[0] = Some(b'{');
        let t = Trellis::build(&d, &x);
        assert!(t.satisfiable());
        let a = t.allowed(&d, 1);
        assert!(a[b'"' as usize] && a.iter().filter(|v| **v).count() == 1);
        // `{"ok":` + 7 masks: only `t` / `f` may follow the colon.
        let mut y: Vec<Option<u8>> = br#"{"ok":"#.iter().map(|b| Some(*b)).collect();
        y.extend(std::iter::repeat_n(None, 7));
        let t = Trellis::build(&d, &y);
        let a = t.allowed(&d, 6);
        assert!(a[b't' as usize] && a[b'f' as usize] && a.iter().filter(|v| **v).count() == 2);
        // Too short to finish `false}` → only `true}` remains completable at 5 masks.
        let mut z: Vec<Option<u8>> = br#"{"ok":"#.iter().map(|b| Some(*b)).collect();
        z.extend(std::iter::repeat_n(None, 5));
        let t = Trellis::build(&d, &z);
        let a = t.allowed(&d, 6);
        assert!(a[b't' as usize] && !a[b'f' as usize]);
    }
}
