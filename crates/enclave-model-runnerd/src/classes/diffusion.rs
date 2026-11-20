//! Class 2 `DISCRETE_DIFFUSION` (FS-701 §4.2): `DINGO` trellis-constrained
//! parallel unmasking, zero-draft IPC barrier (intermediate `x_t` live only in
//! an isolated arena and are wiped at `t = 0`), `RAEC` step-watchers at
//! `t ∈ {⌈.75T⌉, ⌈.5T⌉, ⌈.25T⌉}`, and committed-output canary / PII guard.

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};

use crate::arena::{output_guard, wipe_or_abort, Arena, OutputGuardText, WipeReport, Wiped};
use crate::dfa::{unpad, Dfa, Trellis, PAD};
use crate::safetensors::TensorIndex;
use crate::token_lattice::VocabTrie;
use crate::topology::{OpAttestor, OpFamily};

mod tokens;
pub use tokens::DiffusionTokenModel;

/// Default wall-clock bound on one generation (DEFECT-F-139).
pub const DEFAULT_DEADLINE: std::time::Duration =
    std::time::Duration::from_millis(crate::manifest::DEFAULT_DIFFUSION_DEADLINE_MS as u64);

/// Mask sentinel inside the arena (positions are stored as `u16`).
const MASK: u16 = 0x100;

// The complete bound is reserved before any private byte is copied. Only
// fixed-length constructors can fill this owner; no growth API is exposed.
struct DiffusionBytes {
    bytes: Vec<u8>,
    #[cfg(test)]
    owner: &'static str,
}
impl DiffusionBytes {
    fn reserve(length: usize, _owner: &'static str) -> EnclaveResult<Self> {
        let mut guarded = Self {
            bytes: Vec::new(),
            #[cfg(test)]
            owner: _owner,
        };
        guarded.bytes.try_reserve_exact(length)
            .map_err(|_| err!(ENOMEM, "DIFFUSION_BYTE_CAPACITY"))?;
        Ok(guarded)
    }
    fn project(input: &[Option<u8>], missing: u8, owner: &'static str) -> EnclaveResult<Self> {
        let mut guarded = Self::reserve(input.len(), owner)?;
        #[cfg(test)]
        let allocation = (guarded.bytes.as_ptr() as usize, guarded.bytes.capacity());
        for byte in input {
            guarded.bytes.push(byte.unwrap_or(missing));
        }
        #[cfg(test)]
        diffusion_owner_tests::constructed(owner, input.len(),
            allocation == (guarded.bytes.as_ptr() as usize, guarded.bytes.capacity()));
        Ok(guarded)
    }
    fn copy(input: &[u8], owner: &'static str) -> EnclaveResult<Self> {
        let mut guarded = Self::reserve(input.len(), owner)?;
        #[cfg(test)]
        let allocation = (guarded.bytes.as_ptr() as usize, guarded.bytes.capacity());
        guarded.bytes.extend_from_slice(input);
        #[cfg(test)]
        diffusion_owner_tests::constructed(owner, input.len(),
            allocation == (guarded.bytes.as_ptr() as usize, guarded.bytes.capacity()));
        Ok(guarded)
    }
    fn into_vec(mut self) -> Vec<u8> {
        #[cfg(test)]
        diffusion_owner_tests::transferred(self.owner, self.bytes.len());
        std::mem::take(&mut self.bytes)
    }
}
impl std::ops::Deref for DiffusionBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] { &self.bytes }
}
impl Drop for DiffusionBytes {
    fn drop(&mut self) {
        for byte in &mut self.bytes {
            // SAFETY: each byte is live, initialized and exclusively borrowed.
            unsafe { std::ptr::write_volatile(byte, 0); }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        if !self.bytes.is_empty() {
            diffusion_owner_tests::scrubbed(self.owner, &self.bytes);
        }
    }
}

// Derived confidence scores stay in one allocation until every initialized
// field is scrubbed. No Vec/slice mutation or consuming iterator escapes.
struct ConfidenceOrder {
    values: Vec<(usize, f32)>,
    #[cfg(test)]
    allocation: (usize, usize),
}
impl ConfidenceOrder {
    fn from_logits(masked: &[usize], logits: &[[f32; 256]]) -> EnclaveResult<Self> {
        Self::from_scores(masked, |i| logits[i].iter().copied().fold(f32::NEG_INFINITY, f32::max))
    }
    /// Order masked positions by `score` (highest first, lower index on ties).
    fn from_scores(masked: &[usize], score: impl Fn(usize) -> f32) -> EnclaveResult<Self> {
        let mut values = Vec::new();
        values.try_reserve_exact(masked.len())
            .map_err(|_| err!(ENOMEM, "DIFFUSION_ORDER_CAPACITY"))?;
        let mut guarded = Self {
            #[cfg(test)]
            allocation: (values.as_ptr() as usize, values.capacity()),
            values,
        };
        for i in masked {
            guarded.values.push((*i, score(*i)));
        }
        // masked positions are unique by construction. The existing index
        // tie-break therefore makes this a total order with no equal entries;
        // in-place unstable sorting preserves the exact previous result and
        // avoids stable sort's temporary heap copy of private scores.
        guarded.values.sort_unstable_by(|a, b|
            b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        #[cfg(test)]
        diffusion_order_tests::constructed(guarded.values.len(),
            guarded.allocation == (guarded.values.as_ptr() as usize, guarded.values.capacity()));
        Ok(guarded)
    }
    fn positions(&self) -> impl Iterator<Item = usize> + '_ {
        self.values.iter().map(|entry| entry.0)
    }
}
impl Drop for ConfidenceOrder {
    fn drop(&mut self) {
        for (index, score) in &mut self.values {
            // SAFETY: both fields are live, initialized and exclusively
            // borrowed. Tuple padding is not read or claimed as zeroed.
            unsafe {
                std::ptr::write_volatile(index, 0);
                std::ptr::write_volatile(score, 0.0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        diffusion_order_tests::scrubbed(&self.values,
            self.allocation == (self.values.as_ptr() as usize, self.values.capacity()));
    }
}

/// Denoiser: logits `[L][256]` given the partially unmasked block.
pub trait DiffusionBackend: Send + Sync + std::fmt::Debug {
    /// Logits for every position (committed positions may be ignored).
    fn logits(&self, x: &[Option<u8>], t: u32, total: u32) -> EnclaveResult<Vec<[f32; 256]>>;
    /// Token-level view of a real checkpoint, when this backend is one.
    fn token_model(&self) -> Option<&dyn DiffusionTokenModel> {
        None
    }
}

/// Reference bidirectional bigram denoiser:
/// `enclave_adapter.diffusion.bigram [256, 256]` scores `(left, byte)` and
/// `(byte, right)` pairs around each mask.
#[derive(Debug, Clone)]
pub struct BigramDenoiser {
    bigram: Vec<f32>,
}

impl BigramDenoiser {
    /// Load.
    pub fn load(idx: &TensorIndex, file: &[u8]) -> EnclaveResult<Self> {
        Ok(Self {
            bigram: idx.f32(file, "enclave_adapter.diffusion.bigram", &[256, 256])?,
        })
    }
    /// From a raw table (tests / tooling).
    pub fn from_table(bigram: Vec<f32>) -> EnclaveResult<Self> {
        if bigram.len() != 256 * 256 {
            fail!(EINVAL, "TENSOR_SHAPE");
        }
        Ok(Self { bigram })
    }
}

impl DiffusionBackend for BigramDenoiser {
    fn logits(&self, x: &[Option<u8>], _t: u32, _total: u32) -> EnclaveResult<Vec<[f32; 256]>> {
        let mut out = vec![[0f32; 256]; x.len()];
        for i in 0..x.len() {
            let left = if i > 0 { x[i - 1] } else { None };
            let right = x.get(i + 1).copied().flatten();
            for (b, o) in out[i].iter_mut().enumerate() {
                *o = left.map_or(0.0, |l| self.bigram[l as usize * 256 + b])
                    + right.map_or(0.0, |r| self.bigram[b * 256 + r as usize]);
            }
        }
        Ok(out)
    }
}

/// `RAEC` probe verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeVerdict {
    /// Continue.
    Clean,
    /// Refusal-suppression priming.
    RefusalPriming,
    /// Memorized / raw PII emerging in `p(x_0 | x_t)`.
    PiiEmerging,
}

/// Step-watcher probe.
pub trait StepProbe: Send + Sync + std::fmt::Debug {
    /// Inspect the committed prefix at milestone `t`.
    fn inspect(&self, committed: &[Option<u8>], t: u32) -> ProbeVerdict;
}

/// Milestone heuristic over currently committed bytes. Unknown positions are
/// spaces and can hide incomplete identifiers; final output_guard is mandatory.
/// This is not a proof that partially committed blocks are PII-free.
#[derive(Debug, Clone, Default)]
pub struct ReferenceProbe;

impl StepProbe for ReferenceProbe {
    fn inspect(&self, committed: &[Option<u8>], _t: u32) -> ProbeVerdict {
        // This probe trait cannot return allocation errors. Resource refusal
        // stays fail-closed; no unguarded text is constructed on that path.
        let Ok(s) = DiffusionBytes::project(committed, b' ', "diffusion-probe") else {
            return ProbeVerdict::PiiEmerging;
        };
        let Ok(text) = OutputGuardText::from_bytes(&s) else {
            return ProbeVerdict::PiiEmerging;
        };
        if enclave_core::pii::scan(text.as_str())
            .iter()
            .any(|x| x.kind.is_c4())
            || s.windows(9).any(|w| w == b"CNRY_SEP_")
        {
            return ProbeVerdict::PiiEmerging;
        }
        // The previous conversion was ASCII-only lowercasing. Non-ASCII UTF8
        // bytes stay unchanged, including Kelvin sign and other Unicode cases.
        if ["ignore previous instructions", "do not refuse"]
            .iter()
            .any(|p| text.as_str().as_bytes().windows(p.len())
                .any(|window| window.eq_ignore_ascii_case(p.as_bytes())))
        {
            return ProbeVerdict::RefusalPriming;
        }
        ProbeVerdict::Clean
    }
}

/// Milestones `⌈.75T⌉, ⌈.5T⌉, ⌈.25T⌉`.
pub fn milestones(total: u32) -> [u32; 3] {
    [
        (3 * total).div_ceil(4),
        total.div_ceil(2),
        total.div_ceil(4),
    ]
}

/// Result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffusionResult {
    /// Committed `t = 0` output (padding removed).
    pub output: Vec<u8>,
    /// Steps executed.
    pub steps: u32,
    /// Draft arena wipe.
    pub wipe: WipeReport,
}

/// The gate.
#[derive(Debug)]
pub struct DiffusionGate {
    backend: Box<dyn DiffusionBackend>,
    probe: Box<dyn StepProbe>,
    max_steps: u32,
    max_output_bytes: u32,
    last_wipe: std::sync::Mutex<Option<WipeReport>>,
    /// Vocabulary trie of a token-level backend, built once at bind.
    token_trie: Option<VocabTrie>,
    /// Wall-clock bound on one generation, including its trellis work.
    deadline: std::time::Duration,
}

impl DiffusionGate {
    /// Wipe report of the most recent generation (success or abort).
    pub fn last_wipe(&self) -> Option<WipeReport> {
        self.last_wipe.lock().ok().and_then(|g| *g)
    }

    /// Bind (`max_steps <= 64`).
    pub fn new(
        backend: Box<dyn DiffusionBackend>,
        probe: Box<dyn StepProbe>,
        max_steps: u32,
        max_output_bytes: u32,
    ) -> EnclaveResult<Self> {
        if !(1..=64).contains(&max_steps) {
            fail!(EINVAL, "OUTPUT_CAP_DIFFUSION_STEPS");
        }
        let token_trie = backend.token_model().map(|m| VocabTrie::build(m.tokenizer())).transpose()?;
        Ok(Self {
            backend,
            probe,
            max_steps,
            max_output_bytes,
            last_wipe: std::sync::Mutex::new(None),
            token_trie,
            deadline: DEFAULT_DEADLINE,
        })
    }

    /// Replace the generation deadline (the adapter passes the manifest's
    /// signed value after checking it against the profile ceiling).
    pub fn with_deadline(self, deadline: std::time::Duration) -> Self {
        Self { deadline, ..self }
    }

    /// Wall-clock bound on one generation.
    pub fn deadline(&self) -> std::time::Duration {
        self.deadline
    }

    /// Whether this gate decodes whole tokens of a real checkpoint (and so
    /// accepts a prompt) rather than bytes.
    pub fn is_token_level(&self) -> bool {
        self.token_trie.is_some()
    }

    /// Generate a block of `len` bytes constrained by `dfa`.
    pub fn generate(
        &self,
        dfa: &Dfa,
        len: usize,
        attest: &mut OpAttestor,
    ) -> EnclaveResult<DiffusionResult> {
        self.generate_cancellable(dfa, len, attest, &std::sync::atomic::AtomicBool::new(false))
    }

    /// Cooperative cancellation, checked before work and each commitment.
    pub fn generate_cancellable(
        &self,
        dfa: &Dfa,
        len: usize,
        attest: &mut OpAttestor,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> EnclaveResult<DiffusionResult> {
        self.generate_cancellable_with_wipe(dfa, len, attest, cancel)
            .0
    }

    /// Keep this invocation's measured wipe even when generation or its final
    /// guard fails. The service must not infer it from a prior last_wipe value.
    pub(crate) fn generate_cancellable_with_wipe(
        &self,
        dfa: &Dfa,
        len: usize,
        attest: &mut OpAttestor,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> (EnclaveResult<DiffusionResult>, Option<WipeReport>) {
        let mut wipe_report = None;
        let result = (|| -> EnclaveResult<DiffusionResult> {
            let start = std::time::Instant::now();
            Trellis::check_budget(dfa, len)?;
            if cancel.load(std::sync::atomic::Ordering::Acquire) {
                fail!(EAGAIN, "GENERATION_CANCELLED");
            }
            if len == 0 || len > self.max_output_bytes as usize {
                fail!(E2BIG, "OUTPUT_CAP_EXCEEDED");
            }
            attest.admit(OpFamily::BidirectionalMask)?;
            let total = self.max_steps;
            // x_T..x_1 live only here: u16 per position, MASK = 0x100.
            let mut arena = Arena::new(len * 2)?;
            let r = self.denoise(dfa, len, total, &mut arena, attest, cancel, start);
            // Fence-synchronised wipe on every exit path (success, abort, error).
            let out = match r {
                Ok((x, steps)) => {
                    let committed = DiffusionBytes::project(&x, PAD, "diffusion-committed");
                    let wipe = wipe_or_abort(&arena);
                    wipe_report = Some(wipe);
                    if let Ok(mut g) = self.last_wipe.lock() {
                        *g = Some(wipe);
                    }
                    // Even a recoverable committed-buffer allocation refusal
                    // retains this invocation's actual arena wipe receipt.
                    let committed = committed?;
                    let output = DiffusionBytes::copy(unpad(&committed), "diffusion-output")?;
                    if !dfa.accepts(&committed) {
                        fail!(EIO, "DINGO_INVARIANT", "t = 0 output rejected by the DFA");
                    }
                    output_guard(&output, self.max_output_bytes)?;
                    // Scratch cleanup is part of the original window. A
                    // cancellation during cleanup still withholds final output.
                    drop(x);
                    drop(committed);
                    if cancel.load(std::sync::atomic::Ordering::Acquire) {
                        fail!(EAGAIN, "GENERATION_CANCELLED");
                    }
                    if start.elapsed() > self.deadline {
                        fail!(ETIMEDOUT, "GENERATION_DEADLINE");
                    }
                    DiffusionResult {
                        output: output.into_vec(),
                        steps,
                        wipe,
                    }
                }
                Err(e) => {
                    let w = wipe_or_abort(&arena);
                    wipe_report = Some(w);
                    if let Ok(mut g) = self.last_wipe.lock() {
                        *g = Some(w);
                    }
                    return Err(e);
                }
            };
            Ok(out)
        })();
        (result, wipe_report)
    }

    fn denoise(
        &self,
        dfa: &Dfa,
        len: usize,
        total: u32,
        arena: &mut Arena,
        attest: &mut OpAttestor,
        cancel: &std::sync::atomic::AtomicBool,
        start: std::time::Instant,
    ) -> EnclaveResult<(Wiped<Option<u8>>, u32)> {
        let mut budget = 20_000_000usize;
        let read = |a: &Arena| -> EnclaveResult<Wiped<Option<u8>>> {
            Ok(Wiped::new(
                a.bytes()?
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes(*c))
                    .map(|v| if v == MASK { None } else { Some(v as u8) })
                    .collect(),
                None,
            ))
        };
        for c in arena.bytes_mut()?.as_chunks_mut::<2>().0 {
            c.copy_from_slice(&MASK.to_le_bytes());
        }
        let mut tr = Trellis::build(dfa, &vec![None; len]);
        let watch = milestones(total);
        let mut steps = 0;
        for t in (1..=total).rev() {
            if cancel.load(std::sync::atomic::Ordering::Acquire) {
                fail!(EAGAIN, "GENERATION_CANCELLED");
            }
            if start.elapsed() > self.deadline {
                fail!(ETIMEDOUT, "GENERATION_DEADLINE");
            }
            attest.admit(OpFamily::DenoiseStep)?;
            let x = read(arena)?;
            let masked: Vec<usize> = (0..len).filter(|i| x[*i].is_none()).collect();
            if masked.is_empty() {
                break;
            }
            // Linear schedule: after step t, ⌊len * (t-1) / T⌋ positions remain masked.
            let keep = len * (t as usize - 1) / total as usize;
            let commit_n = masked.len().saturating_sub(keep).max(1);
            let logits = Wiped::new(self.backend.logits(&x, t, total)?, [0f32; 256]);
            if cancel.load(std::sync::atomic::Ordering::Acquire) {
                fail!(EAGAIN, "GENERATION_CANCELLED");
            }
            if start.elapsed() > self.deadline {
                fail!(ETIMEDOUT, "GENERATION_DEADLINE");
            }
            if logits.len() != len {
                fail!(EIO, "DENOISER_SHAPE");
            }
            // Confidence order over masked positions (max logit).
            let order = ConfidenceOrder::from_logits(&masked, &logits)?;
            let mut cur = Wiped::new(x.to_vec(), None);
            for i in order.positions().take(commit_n) {
                // Sequential commit within the step keeps the joint block satisfiable.
                if !tr.satisfiable() {
                    fail!(EIO, "DINGO_UNSATISFIABLE");
                }
                let allowed = tr.allowed(dfa, i);
                let best = (0..256usize)
                    .filter(|b| allowed[*b])
                    .max_by(|a, b| logits[i][*a].total_cmp(&logits[i][*b]).then(b.cmp(a)));
                let Some(b) = best else {
                    fail!(EIO, "DINGO_UNSATISFIABLE")
                };
                cur[i] = Some(b as u8);
                tr.commit(dfa, &cur, i, &mut budget, cancel, start + self.deadline)?;
                let o = arena.bytes_mut()?;
                o[2 * i..2 * i + 2].copy_from_slice(&(b as u16).to_le_bytes());
            }
            steps += 1;
            if watch.contains(&(t - 1)) || watch.contains(&t) {
                match self.probe.inspect(&cur, t) {
                    ProbeVerdict::Clean => {}
                    ProbeVerdict::RefusalPriming => fail!(
                        EACCES,
                        "RAEC_REFUSAL_PRIMING",
                        "step-watcher abort at t = {t}"
                    ),
                    ProbeVerdict::PiiEmerging => {
                        fail!(EACCES, "RAEC_PII_EMERGING", "step-watcher abort at t = {t}")
                    }
                }
            }
        }
        let x = read(arena)?;
        if x.iter().any(Option::is_none) {
            return Err(err!(EIO, "DIFFUSION_INCOMPLETE"));
        }
        if cancel.load(std::sync::atomic::Ordering::Acquire) {
            fail!(EAGAIN, "GENERATION_CANCELLED");
        }
        Ok((x, steps))
    }
}

#[cfg(test)]
mod diffusion_owner_tests {
    use super::*;
    use crate::{dfa::ArgSchema, manifest::ExecutionClass};
    use std::{cell::RefCell, sync::{Arc, atomic::{AtomicBool, Ordering}}};

    #[derive(Debug, PartialEq, Eq)]
    enum Event {
        Constructed(&'static str, usize, bool),
        Scrubbed(&'static str, usize, bool),
        Transferred(&'static str, usize),
    }
    thread_local! {
        static EVENTS: RefCell<Option<Vec<Event>>> = const { RefCell::new(None) };
        static CANCEL_ON_SCRUB: RefCell<Option<Arc<AtomicBool>>> = const { RefCell::new(None) };
    }
    fn begin(cancel: Option<Arc<AtomicBool>>) {
        EVENTS.with(|events| *events.borrow_mut() = Some(Vec::new()));
        CANCEL_ON_SCRUB.with(|slot| *slot.borrow_mut() = cancel);
    }
    fn finish() -> Vec<Event> {
        CANCEL_ON_SCRUB.with(|slot| { slot.borrow_mut().take(); });
        EVENTS.with(|events| events.borrow_mut().take().unwrap())
    }
    pub(super) fn constructed(owner: &'static str, length: usize, stable: bool) {
        EVENTS.with(|events| if let Some(events) = events.borrow_mut().as_mut() {
            events.push(Event::Constructed(owner, length, stable));
        });
    }
    // Observe live initialized bytes AFTER the actual production wipe/fence,
    // BEFORE deallocation. Retain only owner/length/allzero, never raw bytes or
    // addresses. The cancellation is a test-only deterministic race endpoint.
    pub(super) fn scrubbed(owner: &'static str, bytes: &[u8]) {
        EVENTS.with(|events| if let Some(events) = events.borrow_mut().as_mut() {
            events.push(Event::Scrubbed(owner, bytes.len(), bytes.iter().all(|b| *b == 0)));
        });
        if owner == "diffusion-committed" {
            CANCEL_ON_SCRUB.with(|slot| if let Some(cancel) = slot.borrow_mut().take() {
                cancel.store(true, Ordering::SeqCst);
            });
        }
    }
    pub(super) fn transferred(owner: &'static str, length: usize) {
        EVENTS.with(|events| if let Some(events) = events.borrow_mut().as_mut() {
            events.push(Event::Transferred(owner, length));
        });
    }

    fn previous_probe(committed: &[Option<u8>]) -> ProbeVerdict {
        // Previous behavior is a synthetic test oracle, with its old copies
        // deliberately confined to cfg(test), never a production fallback.
        let bytes: Vec<u8> = committed.iter().map(|c| c.unwrap_or(b' ')).collect();
        let text = String::from_utf8_lossy(&bytes);
        if enclave_core::pii::scan(&text).iter().any(|span| span.kind.is_c4())
            || bytes.windows(9).any(|window| window == b"CNRY_SEP_")
        {
            return ProbeVerdict::PiiEmerging;
        }
        let lower = text.to_ascii_lowercase();
        if ["ignore previous instructions", "do not refuse"].iter().any(|p| lower.contains(p)) {
            return ProbeVerdict::RefusalPriming;
        }
        ProbeVerdict::Clean
    }

    #[test]
    fn actual_probe_preserves_all_verdicts_ascii_case_unicode_invalid_and_unknown_bytes() {
        let cases: &[&[u8]] = &[
            b"", b"ordinary text", b"SSN 123-45-6789", b"card 4111 1111 1111 1111",
            b"card 4111111111111112", b"CNRY_SEP_fixture", b"password=fixturesecret",
            b"IGNORE PREVIOUS INSTRUCTIONS", b"Do NoT ReFuSe", b"do not refus",
            b"\xffIgnore Previous Instructions\xfe", b"\xff SSN 123-45-6789",
            "café K İ ß DO NOT REFUSE".as_bytes(), "IGNORE PREVIOUS INSTRUCTİONS".as_bytes(),
            "Kgnore previous instructions".as_bytes(), "安全 text".as_bytes(),
        ];
        let mut seen = [false; 3];
        for bytes in cases {
            for masked in [false, true] {
                let committed: Vec<Option<u8>> = bytes.iter().enumerate()
                    .map(|(i, byte)| if masked && i % 5 == 2 { None } else { Some(*byte) })
                    .collect();
                let before = committed.clone();
                let expected = previous_probe(&committed);
                begin(None);
                assert_eq!(ReferenceProbe.inspect(&committed, 4), expected);
                assert_eq!(committed, before, "borrowed committed state is unchanged");
                let mut events = vec![Event::Constructed("diffusion-probe", bytes.len(), true)];
                if !bytes.is_empty() {
                    events.push(Event::Scrubbed("diffusion-probe", bytes.len(), true));
                }
                assert_eq!(finish(), events);
                seen[match expected {
                    ProbeVerdict::Clean => 0,
                    ProbeVerdict::RefusalPriming => 1,
                    ProbeVerdict::PiiEmerging => 2,
                }] = true;
            }
        }
        assert_eq!(seen, [true; 3]);
    }

    #[derive(Debug)]
    struct Spell(Vec<u8>);
    impl DiffusionBackend for Spell {
        fn logits(&self, x: &[Option<u8>], _: u32, _: u32) -> EnclaveResult<Vec<[f32; 256]>> {
            let mut logits = vec![[-1.0; 256]; x.len()];
            for (i, row) in logits.iter_mut().enumerate() {
                row[self.0.get(i).copied().unwrap_or(PAD) as usize] = 1.0;
            }
            Ok(logits)
        }
    }
    #[derive(Debug)]
    struct CleanProbe;
    impl StepProbe for CleanProbe {
        fn inspect(&self, _: &[Option<u8>], _: u32) -> ProbeVerdict { ProbeVerdict::Clean }
    }
    fn gate(value: &str, probe: Box<dyn StepProbe>) -> (DiffusionGate, Dfa, Vec<u8>, usize) {
        let wire = serde_json::to_vec(value).unwrap();
        let length = wire.len() + 3;
        let dfa = Dfa::compile(&ArgSchema::Enum(vec![value.into()])).unwrap();
        let gate = DiffusionGate::new(Box::new(Spell(wire.clone())), probe, 4, 256).unwrap();
        (gate, dfa, wire, length)
    }
    fn check_wipe(wipe: Option<WipeReport>, length: usize) {
        let wipe = wipe.expect("every entered arena retains this invocation's actual receipt");
        assert!(wipe.bytes >= (length * 2) as u64);
        assert_eq!(wipe.residual, 0);
    }

    #[test]
    fn actual_generation_preserves_padded_output_and_transfers_only_final_allocation() {
        let (gate, dfa, wire, length) = gate("safe", Box::new(CleanProbe));
        let mut attest = OpAttestor::new(ExecutionClass::DiscreteDiffusion, &[]);
        begin(None);
        let (result, wipe) = gate.generate_cancellable_with_wipe(
            &dfa, length, &mut attest, &AtomicBool::new(false));
        let result = result.unwrap();
        assert_eq!(result.output, wire);
        assert_eq!(result.steps, 4);
        check_wipe(wipe, length);
        assert_eq!(gate.last_wipe(), wipe);
        assert_eq!(finish(), vec![
            Event::Constructed("diffusion-committed", length, true),
            Event::Constructed("diffusion-output", wire.len(), true),
            Event::Scrubbed("diffusion-committed", length, true),
            Event::Transferred("diffusion-output", wire.len()),
        ]);
    }

    #[test]
    fn actual_final_pii_and_canary_refusals_scrub_complete_output_and_committed_bytes() {
        for (value, reason) in [
            ("4111111111111111", "UNREDACTED_PII_IN_OUTPUT"),
            ("SSN 123-45-6789", "UNREDACTED_PII_IN_OUTPUT"),
            ("CNRY_SEP_fixture", "CANARY_TRIPPED"),
        ] {
            let (gate, dfa, wire, length) = gate(value, Box::new(CleanProbe));
            let mut attest = OpAttestor::new(ExecutionClass::DiscreteDiffusion, &[]);
            begin(None);
            let (result, wipe) = gate.generate_cancellable_with_wipe(
                &dfa, length, &mut attest, &AtomicBool::new(false));
            assert!(result.unwrap_err().is(reason));
            check_wipe(wipe, length);
            assert_eq!(finish(), vec![
                Event::Constructed("diffusion-committed", length, true),
                Event::Constructed("diffusion-output", wire.len(), true),
                Event::Scrubbed("diffusion-output", wire.len(), true),
                Event::Scrubbed("diffusion-committed", length, true),
            ]);
        }
    }

    #[test]
    fn actual_probe_abort_scrubs_each_projection_and_retains_arena_receipt() {
        let (gate, dfa, _, length) = gate("4111111111111111", Box::new(ReferenceProbe));
        let mut attest = OpAttestor::new(ExecutionClass::DiscreteDiffusion, &[]);
        begin(None);
        let (result, wipe) = gate.generate_cancellable_with_wipe(
            &dfa, length, &mut attest, &AtomicBool::new(false));
        assert!(result.unwrap_err().is("RAEC_PII_EMERGING"));
        check_wipe(wipe, length);
        let events = finish();
        assert!(!events.is_empty());
        for pair in events.chunks(2) {
            assert_eq!(pair, &[
                Event::Constructed("diffusion-probe", length, true),
                Event::Scrubbed("diffusion-probe", length, true),
            ]);
        }
    }

    #[test]
    fn cancellation_during_actual_committed_cleanup_withholds_and_scrubs_final_output() {
        let (gate, dfa, wire, length) = gate("safe", Box::new(CleanProbe));
        let cancel = Arc::new(AtomicBool::new(false));
        let mut attest = OpAttestor::new(ExecutionClass::DiscreteDiffusion, &[]);
        begin(Some(cancel.clone()));
        let (result, wipe) = gate.generate_cancellable_with_wipe(&dfa, length, &mut attest, &cancel);
        assert!(cancel.load(Ordering::SeqCst));
        assert!(result.unwrap_err().is("GENERATION_CANCELLED"));
        check_wipe(wipe, length);
        assert_eq!(finish(), vec![
            Event::Constructed("diffusion-committed", length, true),
            Event::Constructed("diffusion-output", wire.len(), true),
            Event::Scrubbed("diffusion-committed", length, true),
            Event::Scrubbed("diffusion-output", wire.len(), true),
        ]);
    }
}

#[cfg(test)]
mod diffusion_order_tests {
    use super::*;
    use crate::{dfa::ArgSchema, manifest::ExecutionClass};
    use std::{cell::RefCell, sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}};

    #[derive(Debug, PartialEq, Eq)]
    enum Event {
        Constructed(usize, bool),
        Scrubbed(usize, bool, bool),
    }
    thread_local! {
        static EVENTS: RefCell<Option<Vec<Event>>> = const { RefCell::new(None) };
    }
    fn begin() { EVENTS.with(|slot| *slot.borrow_mut() = Some(Vec::new())); }
    fn finish() -> Vec<Event> { EVENTS.with(|slot| slot.borrow_mut().take().unwrap()) }
    pub(super) fn constructed(length: usize, stable: bool) {
        EVENTS.with(|slot| if let Some(events) = slot.borrow_mut().as_mut() {
            events.push(Event::Constructed(length, stable));
        });
    }
    // Observe initialized fields after actual volatile cleanup/fence, while
    // allocation remains owned. Retain metadata only, never addresses/values.
    pub(super) fn scrubbed(values: &[(usize, f32)], stable: bool) {
        EVENTS.with(|slot| if let Some(events) = slot.borrow_mut().as_mut() {
            events.push(Event::Scrubbed(values.len(),
                values.iter().all(|(index, score)| *index == 0 && score.to_bits() == 0), stable));
        });
    }
    fn previous_order(masked: &[usize], logits: &[[f32; 256]]) -> Vec<(usize, f32)> {
        // The former copied-score/stable-sort implementation is confined to
        // synthetic test fixtures. It is never a production fallback.
        let mut order: Vec<_> = masked.iter().map(|i|
            (*i, logits[*i].iter().copied().fold(f32::NEG_INFINITY, f32::max))).collect();
        order.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        order
    }

    #[test]
    fn exact_order_matches_previous_stable_sort_nan_infinity_zero_ties_and_masked_permutations() {
        let patterns = [f32::NEG_INFINITY, -f32::MAX, -1.0, -0.0, 0.0,
            f32::MIN_POSITIVE, 1.0, f32::MAX, f32::INFINITY, f32::NAN,
            f32::from_bits(0xffc0_0042), f32::from_bits(1)];
        for length in [0, 1, 2, 7, 32, 129] {
            for seed in 0..24 {
                let logits: Vec<[f32; 256]> = (0..length).map(|i| {
                    let mut row = [patterns[(i + seed) % patterns.len()]; 256];
                    row[(i * 17 + seed) % 256] = patterns[(i * 3 + seed) % patterns.len()];
                    row
                }).collect();
                let mut masked: Vec<_> = (0..length).filter(|i| (i + seed) % 3 != 0).collect();
                if seed % 2 == 0 { masked.reverse(); }
                if !masked.is_empty() {
                    let rotate = seed % masked.len(); masked.rotate_left(rotate);
                }
                let expected = previous_order(&masked, &logits);
                begin();
                let order = ConfidenceOrder::from_logits(&masked, &logits).unwrap();
                assert_eq!(order.positions().collect::<Vec<_>>(),
                    expected.iter().map(|entry| entry.0).collect::<Vec<_>>());
                assert_eq!(order.values.iter().map(|(i, score)| (*i, score.to_bits())).collect::<Vec<_>>(),
                    expected.iter().map(|(i, score)| (*i, score.to_bits())).collect::<Vec<_>>(),
                    "the exact previous f32::max fold is preserved");
                drop(order);
                assert_eq!(finish(), vec![Event::Constructed(masked.len(), true),
                    Event::Scrubbed(masked.len(), true, true)]);
            }
        }
    }

    #[derive(Debug)]
    struct RankedSpell {
        wire: Vec<u8>,
        committed: Arc<Mutex<Vec<Vec<usize>>>>,
    }
    fn scores(wire: &[u8], length: usize) -> Vec<[f32; 256]> {
        (0..length).map(|i| {
            let mut row = [-2.0; 256];
            row[wire.get(i).copied().unwrap_or(PAD) as usize] = 1.0 + ((i * 37) % 19) as f32;
            row
        }).collect()
    }
    impl DiffusionBackend for RankedSpell {
        fn logits(&self, x: &[Option<u8>], _: u32, _: u32) -> EnclaveResult<Vec<[f32; 256]>> {
            self.committed.lock().unwrap().push(x.iter().enumerate()
                .filter_map(|(i, value)| value.map(|_| i)).collect());
            Ok(scores(&self.wire, x.len()))
        }
    }
    #[derive(Debug)]
    struct VerdictProbe(ProbeVerdict);
    impl StepProbe for VerdictProbe {
        fn inspect(&self, _: &[Option<u8>], _: u32) -> ProbeVerdict { self.0 }
    }
    #[derive(Debug)]
    struct CancelProbe(Arc<AtomicBool>);
    impl StepProbe for CancelProbe {
        fn inspect(&self, _: &[Option<u8>], _: u32) -> ProbeVerdict {
            self.0.store(true, Ordering::SeqCst); ProbeVerdict::Clean
        }
    }
    struct Fixture {
        gate: DiffusionGate,
        dfa: Dfa,
        wire: Vec<u8>,
        length: usize,
        committed: Arc<Mutex<Vec<Vec<usize>>>>,
    }
    fn fixture(probe: Box<dyn StepProbe>) -> Fixture {
        let value = "order owner safe value";
        let wire = serde_json::to_vec(value).unwrap();
        let length = wire.len() + 3;
        let committed = Arc::new(Mutex::new(Vec::new()));
        let backend = RankedSpell { wire: wire.clone(), committed: committed.clone() };
        Fixture { gate: DiffusionGate::new(Box::new(backend), probe, 4, 256).unwrap(),
            dfa: Dfa::compile(&ArgSchema::Enum(vec![value.into()])).unwrap(),
            wire, length, committed }
    }
    fn attest() -> OpAttestor { OpAttestor::new(ExecutionClass::DiscreteDiffusion, &[]) }
    fn actual_wipe(wipe: Option<WipeReport>, length: usize) {
        let wipe = wipe.expect("actual arena receipt survives the owner path");
        assert!(wipe.bytes >= (2 * length) as u64); assert_eq!(wipe.residual, 0);
    }

    #[test]
    fn actual_multistep_generation_preserves_commit_order_output_and_scrubs_each_score_allocation() {
        let f = fixture(Box::new(VerdictProbe(ProbeVerdict::Clean)));
        begin();
        let (result, wipe) = f.gate.generate_cancellable_with_wipe(
            &f.dfa, f.length, &mut attest(), &AtomicBool::new(false));
        let result = result.unwrap();
        assert_eq!(result.output, f.wire); assert_eq!(result.steps, 4);
        actual_wipe(wipe, f.length);
        let logits = scores(&f.wire, f.length);
        let mut selected = vec![false; f.length]; let mut expected = Vec::new();
        let mut events = Vec::new();
        for t in (1..=4).rev() {
            expected.push((0..f.length).filter(|i| selected[*i]).collect::<Vec<_>>());
            let masked: Vec<_> = (0..f.length).filter(|i| !selected[*i]).collect();
            let count = masked.len().saturating_sub(f.length * (t - 1) / 4).max(1);
            for (i, _) in previous_order(&masked, &logits).into_iter().take(count) { selected[i] = true; }
            events.push(Event::Constructed(masked.len(), true));
            events.push(Event::Scrubbed(masked.len(), true, true));
        }
        assert_eq!(*f.committed.lock().unwrap(), expected,
            "real backend sees exactly the previous stable-order commitment schedule");
        assert_eq!(finish(), events);
    }

    #[test]
    fn actual_probe_faults_scrub_live_confidence_scores_and_preserve_arena_receipt() {
        for (verdict, reason) in [(ProbeVerdict::RefusalPriming, "RAEC_REFUSAL_PRIMING"),
            (ProbeVerdict::PiiEmerging, "RAEC_PII_EMERGING")] {
            let f = fixture(Box::new(VerdictProbe(verdict)));
            begin();
            let (result, wipe) = f.gate.generate_cancellable_with_wipe(
                &f.dfa, f.length, &mut attest(), &AtomicBool::new(false));
            assert!(result.unwrap_err().is(reason)); actual_wipe(wipe, f.length);
            assert_eq!(finish(), vec![Event::Constructed(f.length, true),
                Event::Scrubbed(f.length, true, true)]);
        }
    }

    #[test]
    fn actual_probe_cancellation_scrubs_live_confidence_scores_and_withholds_output() {
        let cancel = Arc::new(AtomicBool::new(false));
        let f = fixture(Box::new(CancelProbe(cancel.clone())));
        begin();
        let (result, wipe) = f.gate.generate_cancellable_with_wipe(&f.dfa, f.length, &mut attest(), &cancel);
        assert!(cancel.load(Ordering::SeqCst));
        assert!(result.unwrap_err().is("GENERATION_CANCELLED")); actual_wipe(wipe, f.length);
        assert_eq!(f.committed.lock().unwrap().len(), 1, "no next backend call after cancellation");
        assert_eq!(finish(), vec![Event::Constructed(f.length, true),
            Event::Scrubbed(f.length, true, true)]);
    }
}
