//! Class 3 `RECURRENT_SSM_TTT` (FS-701 §4.3): Copy-on-Write
//! `StateSnapshotDAG` — `h_sys` sealed hardware read-only; every session forks
//! an isolated, label-tagged arena `h_task`; dual-trigger anchor re-injection
//! `T(h) = (1-α)h + α h_sys` every `W` tokens **and** at the `Ingest ->
//! Generate` boundary (HiSPA); strict taint monotonicity; fence-synchronised
//! wipe on exit / sleep / screen-lock / YubiKey yank.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use enclave_core::error::EnclaveResult;
use enclave_core::label::Label;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};

use crate::arena::{finite, output_guard, wipe_or_abort, Arena, WipeReport, ZeroizeTrigger};
use crate::safetensors::TensorIndex;
use crate::topology::{OpAttestor, OpFamily};

/// Recurrent backbone.
pub trait RecurrentBackend: Send + Sync + std::fmt::Debug {
    /// State width `d`.
    fn width(&self) -> usize;
    /// Clean system state `h_sys` (after the system prefix).
    fn system_state(&self) -> Vec<f32>;
    /// One recurrent step over a byte.
    fn step(&self, h: &mut [f32], byte: u8) -> EnclaveResult<()>;
    /// Next-byte logits.
    fn logits(&self, h: &[f32]) -> EnclaveResult<[f32; 256]>;
    /// A real token-level model, when this backend is one.
    fn token_model(&self) -> Option<&dyn RecurrentTokenModel> {
        None
    }
}

/// Token-level recurrent model (RWKV-7). Its next-token distribution comes
/// from consuming a token, so the DAG keeps the newest token pending: the
/// state `h` is always the state *before* that token, which lets the
/// boundary anchor act on the state that produces output token #1.
pub trait RecurrentTokenModel: Send + Sync + std::fmt::Debug {
    /// Tokenize untrusted bytes.
    fn encode(&self, bytes: &[u8]) -> EnclaveResult<Vec<u32>>;
    /// Bytes of one token.
    fn token_bytes(&self, id: u32) -> EnclaveResult<&[u8]>;
    /// Whether `id` ends generation.
    fn is_end(&self, id: u32) -> bool;
    /// Consume `ids` from `h` in order; return logits after the last one.
    fn advance(&self, h: &mut [f32], ids: &[u32]) -> EnclaveResult<Vec<f32>>;
}

/// Index of the largest logit; ties go to the lowest index.
fn argmax(logits: &[f32]) -> EnclaveResult<u32> {
    let mut best: Option<(usize, f32)> = None;
    for (i, v) in logits.iter().copied().enumerate() {
        if !v.is_finite() {
            fail!(EIO, "NONFINITE_LOGITS");
        }
        if best.is_none_or(|(_, b)| v > b) {
            best = Some((i, v));
        }
    }
    best.map(|(i, _)| i as u32).ok_or_else(|| err!(EIO, "EMPTY_LOGITS"))
}

/// Reference diagonal linear SSM: `h ← a ⊙ h + E[byte]`, logits `= Oᵀ h`.
/// Tensors: `backbone.mixer.A_log [d]` (`a = exp(-exp(A_log))`),
/// `enclave_adapter.ssm.embed [256, d]`, `enclave_adapter.ssm.out [d, 256]`,
/// `enclave_adapter.ssm.h_sys [d]`.
#[derive(Debug, Clone)]
pub struct DiagonalSsm {
    a: Vec<f32>,
    e: Vec<f32>,
    o: Vec<f32>,
    h_sys: Vec<f32>,
    d: usize,
}

impl DiagonalSsm {
    /// Load.
    pub fn load(idx: &TensorIndex, file: &[u8]) -> EnclaveResult<Self> {
        let d = idx
            .shape("backbone.mixer.A_log")
            .and_then(|s| s.first().copied())
            .ok_or_else(|| err!(EINVAL, "TENSOR_MISSING", "mixer.A_log"))?;
        let a_log = idx.f32(file, "backbone.mixer.A_log", &[d])?;
        Ok(Self {
            a: a_log.iter().map(|x| (-x.exp()).exp()).collect(),
            e: idx.f32(file, "enclave_adapter.ssm.embed", &[256, d])?,
            o: idx.f32(file, "enclave_adapter.ssm.out", &[d, 256])?,
            h_sys: idx.f32(file, "enclave_adapter.ssm.h_sys", &[d])?,
            d,
        })
    }
}

impl RecurrentBackend for DiagonalSsm {
    fn width(&self) -> usize {
        self.d
    }
    fn system_state(&self) -> Vec<f32> {
        self.h_sys.clone()
    }
    fn step(&self, h: &mut [f32], byte: u8) -> EnclaveResult<()> {
        let e = &self.e[byte as usize * self.d..(byte as usize + 1) * self.d];
        for ((h, a), e) in h.iter_mut().zip(&self.a).zip(e) {
            *h = a * *h + e;
        }
        finite(h, "ssm state")
    }
    fn logits(&self, h: &[f32]) -> EnclaveResult<[f32; 256]> {
        let mut out = [0f32; 256];
        for (j, hv) in h.iter().enumerate() {
            for (b, o) in out.iter_mut().enumerate() {
                *o += hv * self.o[j * 256 + b];
            }
        }
        Ok(out)
    }
}

/// Session phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    /// Ingesting untrusted input.
    Ingest,
    /// Generating.
    Generate,
}

struct Session {
    h: Arena,
    label: Label,
    phase: Phase,
    since_anchor: u32,
    boundary_anchor: bool,
    /// Token-level models: newest token, not yet consumed into `h`.
    pending: Option<u32>,
    created_at: Instant,
    last_active_at: Instant,
}

// Daemon policy, never supplied by a caller or a model manifest. An idle
// session expires after five minutes; even useful traffic cannot keep a task
// arena alive beyond thirty minutes. A caller starts a fresh session afterward.
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const SESSION_MAX_LIFETIME: Duration = Duration::from_secs(30 * 60);

/// Session handle (opaque; never a tensor).
pub type SessionId = u64;

/// Generation receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsmReceipt {
    /// Monotone provenance of the complete session, retained across anchors.
    pub label: Label,
    /// Output bytes.
    pub output: Vec<u8>,
    /// Anchor re-injections applied.
    pub anchors: u32,
    /// Boundary (`Ingest -> Generate`) anchor applied.
    pub hispa_boundary_anchor_applied: bool,
}

/// The `StateSnapshotDAG`.
pub struct StateSnapshotDag {
    backend: Box<dyn RecurrentBackend>,
    h_sys: Arena,
    sessions: BTreeMap<SessionId, Session>,
    window: u32,
    alpha: f32,
    max_output_bytes: u32,
    anchors: u32,
    clock: Box<dyn Fn() -> Instant + Send + Sync>,
}

impl std::fmt::Debug for StateSnapshotDag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateSnapshotDag")
            .field("sessions", &self.sessions.len())
            .field("window", &self.window)
            .finish()
    }
}

impl StateSnapshotDag {
    /// Bind: copy `h_sys` into a sealed read-only arena.
    pub fn new(
        backend: Box<dyn RecurrentBackend>,
        window: u32,
        alpha: f64,
        max_output_bytes: u32,
    ) -> EnclaveResult<Self> {
        if !(1..=2048).contains(&window) || !(0.25..=1.0).contains(&alpha) {
            fail!(EINVAL, "SSM_ANCHOR_PARAMS");
        }
        let hs = backend.system_state();
        if hs.len() != backend.width() {
            fail!(EINVAL, "SSM_H_SYS_SHAPE");
        }
        let mut h_sys = Arena::floats(hs.len())?;
        h_sys.f32_mut()?.copy_from_slice(&hs);
        h_sys.seal_read_only()?;
        Ok(Self {
            backend,
            h_sys,
            sessions: BTreeMap::new(),
            window,
            alpha: alpha as f32,
            max_output_bytes,
            anchors: 0,
            clock: Box::new(Instant::now),
        })
    }

    // Tests advance the same server-owned monotonic clock without sleeping.
    // No manifest, request field or environment variable can select it.
    #[cfg(test)]
    pub(crate) fn set_clock(&mut self, clock: impl Fn() -> Instant + Send + Sync + 'static) {
        assert!(self.sessions.is_empty());
        self.clock = Box::new(clock);
    }

    /// Whether `h_sys` is hardware read-only.
    pub fn system_state_sealed(&self) -> bool {
        self.h_sys.is_read_only()
    }

    fn expired(session: &Session, now: Instant) -> bool {
        now.saturating_duration_since(session.last_active_at) >= SESSION_IDLE_TIMEOUT
            || now.saturating_duration_since(session.created_at) >= SESSION_MAX_LIFETIME
    }

    fn require_live(&self, id: SessionId) -> EnclaveResult<()> {
        let s = self.sessions.get(&id).ok_or_else(|| err!(EINVAL, "UNKNOWN_SESSION"))?;
        if Self::expired(s, (self.clock)()) {
            fail!(EAGAIN, "SSM_SESSION_EXPIRED");
        }
        Ok(())
    }

    fn record_activity(&mut self, id: SessionId) -> EnclaveResult<()> {
        self.require_live(id)?;
        let now = (self.clock)();
        let s = self.sessions.get_mut(&id).ok_or_else(|| err!(EINVAL, "UNKNOWN_SESSION"))?;
        // Recheck with the same timestamp stored as the successful activity.
        if Self::expired(s, now) {
            fail!(EAGAIN, "SSM_SESSION_EXPIRED");
        }
        s.last_active_at = now;
        Ok(())
    }

    /// Remove and actually wipe expired task arenas. The service records every
    /// returned measurement before dispatching another request, including when
    /// that request fails. The sealed system arena is not a task session.
    pub(crate) fn reap_expired(&mut self) -> Vec<WipeReport> {
        let now = (self.clock)();
        let expired: Vec<_> = self.sessions.iter()
            .filter_map(|(id, s)| Self::expired(s, now).then_some(*id))
            .collect();
        expired.into_iter().map(|id| {
            let session = self.sessions.remove(&id).expect("selected live session");
            wipe_or_abort(&session.h)
        }).collect()
    }

    /// Fork a CoW task arena tagged with `label`.
    /// The service reaps expired sessions before applying this capacity limit.
    pub fn fork(&mut self, label: Label) -> EnclaveResult<SessionId> {
        if self.sessions.len() >= 8 {
            fail!(
                EAGAIN,
                "ENCLAVE_MEMORY_PRESSURE",
                "429: too many concurrent tainted sessions"
            );
        }
        let mut h = Arena::floats(self.backend.width())?;
        h.f32_mut()?.copy_from_slice(self.h_sys.f32()?);
        let id = loop {
            let candidate = enclave_core::rng::u64();
            if !self.sessions.contains_key(&candidate) { break candidate; }
        };
        let now = (self.clock)();
        self.sessions.insert(
            id,
            Session {
                h,
                label,
                phase: Phase::Ingest,
                since_anchor: 0,
                boundary_anchor: false,
                pending: None,
                created_at: now,
                last_active_at: now,
            },
        );
        Ok(id)
    }

    fn anchor(&mut self, id: SessionId) -> EnclaveResult<()> {
        let alpha = self.alpha;
        let sys: Vec<f32> = self.h_sys.f32()?.to_vec();
        let s = self
            .sessions
            .get_mut(&id)
            .ok_or_else(|| err!(EINVAL, "UNKNOWN_SESSION"))?;
        for (h, hs) in s.h.f32_mut()?.iter_mut().zip(&sys) {
            *h = (1.0 - alpha) * *h + alpha * hs;
        }
        s.since_anchor = 0;
        self.anchors += 1;
        Ok(())
    }

    /// Ingest untrusted bytes. Labels may only rise (taint monotonicity).
    pub fn ingest(
        &mut self,
        id: SessionId,
        label: Label,
        bytes: &[u8],
        attest: &mut OpAttestor,
    ) -> EnclaveResult<()> {
        self.require_live(id)?;
        attest.admit(OpFamily::PersistentStateScan)?;
        {
            let s = self
                .sessions
                .get_mut(&id)
                .ok_or_else(|| err!(EINVAL, "UNKNOWN_SESSION"))?;
            if s.phase != Phase::Ingest {
                fail!(
                    EACCES,
                    "SSM_PHASE",
                    "ingest after generate requires a new session"
                );
            }
            s.label = s.label.join(label);
        }
        if self.backend.token_model().is_some() {
            return self.ingest_tokens(id, bytes);
        }
        for b in bytes {
            self.require_live(id)?;
            let need_anchor = {
                let s = self
                    .sessions
                    .get_mut(&id)
                    .ok_or_else(|| err!(EINVAL, "UNKNOWN_SESSION"))?;
                self.backend.step(s.h.f32_mut()?, *b)?;
                s.since_anchor += 1;
                s.since_anchor >= self.window
            };
            if need_anchor {
                self.anchor(id)?;
            }
        }
        self.require_live(id)?;
        if !bytes.is_empty() { self.record_activity(id)?; }
        Ok(())
    }

    /// Current label.
    pub fn label(&self, id: SessionId) -> Option<Label> {
        self.sessions.get(&id).map(|s| s.label)
    }

    /// Request a label decrease (always refused: taint is monotone).
    pub fn relabel(&mut self, id: SessionId, to: Label) -> EnclaveResult<()> {
        self.require_live(id)?;
        let s = self
            .sessions
            .get_mut(&id)
            .ok_or_else(|| err!(EINVAL, "UNKNOWN_SESSION"))?;
        if !s.label.leq(to) {
            fail!(
                EACCES,
                "TAINT_MONOTONICITY",
                "labels never decrease inside a session"
            );
        }
        s.label = to;
        Ok(())
    }

    /// Generate `n` bytes greedily. The boundary anchor fires unconditionally
    /// before output byte #1.
    pub fn generate(
        &mut self,
        id: SessionId,
        n: usize,
        attest: &mut OpAttestor,
    ) -> EnclaveResult<SsmReceipt> {
        self.generate_cancellable(id, n, attest, None)
    }

    /// As [`Self::generate`], but a real checkpoint's token loop stops before
    /// its next step once `cancel` is set; the partial output is wiped. The
    /// session is left mid-generation, so callers wipe it (a wipe sets `cancel`).
    pub fn generate_cancellable(
        &mut self,
        id: SessionId,
        n: usize,
        attest: &mut OpAttestor,
        cancel: Option<&std::sync::atomic::AtomicBool>,
    ) -> EnclaveResult<SsmReceipt> {
        self.require_live(id)?;
        attest.admit(OpFamily::CausalDecode)?;
        if n > self.max_output_bytes as usize {
            fail!(E2BIG, "OUTPUT_CAP_EXCEEDED");
        }
        let before = self.anchors;
        let boundary = {
            let s = self
                .sessions
                .get_mut(&id)
                .ok_or_else(|| err!(EINVAL, "UNKNOWN_SESSION"))?;
            let b = s.phase == Phase::Ingest;
            s.phase = Phase::Generate;
            b
        };
        if boundary {
            self.anchor(id)?;
            if let Some(s) = self.sessions.get_mut(&id) {
                s.boundary_anchor = true;
            }
        }
        if self.backend.token_model().is_some() {
            return self.generate_tokens(id, n, before, cancel);
        }
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            self.require_live(id)?;
            let need_anchor = {
                let s = self
                    .sessions
                    .get_mut(&id)
                    .ok_or_else(|| err!(EINVAL, "UNKNOWN_SESSION"))?;
                let logits = self.backend.logits(s.h.f32()?)?;
                let b = (0..256usize)
                    .max_by(|a, c| logits[*a].total_cmp(&logits[*c]).then(c.cmp(a)))
                    .unwrap_or(0) as u8;
                out.push(b);
                self.backend.step(s.h.f32_mut()?, b)?;
                s.since_anchor += 1;
                s.since_anchor >= self.window
            };
            if need_anchor {
                self.anchor(id)?;
            }
        }
        output_guard(&out, self.max_output_bytes)?;
        self.require_live(id)?;
        if n != 0 { self.record_activity(id)?; }
        let applied = self.sessions.get(&id).is_some_and(|s| s.boundary_anchor);
        Ok(SsmReceipt {
            label: self
                .label(id)
                .ok_or_else(|| err!(EINVAL, "UNKNOWN_SESSION"))?,
            output: out,
            anchors: self.anchors - before,
            hispa_boundary_anchor_applied: applied,
        })
    }

    /// Token path of `ingest`: consume the previous pending token and all
    /// new ones but the last, in windows that end exactly at anchor points.
    fn ingest_tokens(&mut self, id: SessionId, bytes: &[u8]) -> EnclaveResult<()> {
        let tm = self.backend.token_model().ok_or_else(|| err!(EINVAL, "SSM_TOKEN_MODEL"))?;
        let ids = tm.encode(bytes)?;
        let Some((&last, rest)) = ids.split_last() else {
            return Ok(());
        };
        let mut queue: Vec<u32> = Vec::with_capacity(ids.len());
        {
            let s = self.sessions.get_mut(&id).ok_or_else(|| err!(EINVAL, "UNKNOWN_SESSION"))?;
            queue.extend(s.pending.replace(last));
        }
        queue.extend_from_slice(rest);
        let mut at = 0;
        while at < queue.len() {
            self.require_live(id)?;
            let need_anchor = {
                let tm = self.backend.token_model().ok_or_else(|| err!(EINVAL, "SSM_TOKEN_MODEL"))?;
                let s = self.sessions.get_mut(&id).ok_or_else(|| err!(EINVAL, "UNKNOWN_SESSION"))?;
                let room = self.window.saturating_sub(s.since_anchor).max(1) as usize;
                let chunk = &queue[at..queue.len().min(at + room)];
                tm.advance(s.h.f32_mut()?, chunk)?;
                finite(s.h.f32()?, "ssm state")?;
                at += chunk.len();
                s.since_anchor += chunk.len() as u32;
                s.since_anchor >= self.window
            };
            if need_anchor {
                self.anchor(id)?;
            }
        }
        self.require_live(id)?;
        self.record_activity(id)
    }

    /// Token path of `generate`: greedy tokens until `n` bytes or end-of-text.
    fn generate_tokens(
        &mut self, id: SessionId, n: usize, before: u32, cancel: Option<&std::sync::atomic::AtomicBool>,
    ) -> EnclaveResult<SsmReceipt> {
        // Wiped on every early return; moved out only on success.
        let mut out = crate::arena::Wiped::new(Vec::with_capacity(n), 0u8);
        while out.len() < n {
            if cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::Acquire)) {
                fail!(EAGAIN, "GENERATION_CANCELLED");
            }
            self.require_live(id)?;
            let (need_anchor, ended) = {
                let tm = self.backend.token_model().ok_or_else(|| err!(EINVAL, "SSM_TOKEN_MODEL"))?;
                let s = self.sessions.get_mut(&id).ok_or_else(|| err!(EINVAL, "UNKNOWN_SESSION"))?;
                let pending = s.pending.take().ok_or_else(|| err!(EINVAL, "SSM_PROMPT_REQUIRED"))?;
                let logits = tm.advance(s.h.f32_mut()?, &[pending])?;
                finite(s.h.f32()?, "ssm state")?;
                s.since_anchor += 1;
                let next = argmax(&logits)?;
                let ended = tm.is_end(next);
                if !ended {
                    out.extend_from_slice(tm.token_bytes(next)?);
                    s.pending = Some(next);
                }
                (s.since_anchor >= self.window, ended)
            };
            if need_anchor {
                self.anchor(id)?;
            }
            if ended {
                break;
            }
        }
        out.truncate(n);
        output_guard(&out, self.max_output_bytes)?;
        self.require_live(id)?;
        if n != 0 { self.record_activity(id)?; }
        let applied = self.sessions.get(&id).is_some_and(|s| s.boundary_anchor);
        let label = self.label(id).ok_or_else(|| err!(EINVAL, "UNKNOWN_SESSION"))?;
        Ok(SsmReceipt {
            label,
            output: std::mem::take(&mut *out),
            anchors: self.anchors - before,
            hispa_boundary_anchor_applied: applied,
        })
    }

    /// Exit a session: fence-synchronised wipe of `h_task`.
    pub fn exit(&mut self, id: SessionId) -> EnclaveResult<WipeReport> {
        let s = self
            .sessions
            .remove(&id)
            .ok_or_else(|| err!(EINVAL, "UNKNOWN_SESSION"))?;
        Ok(wipe_or_abort(&s.h))
    }

    /// System trigger (sleep / lock / yank): wipe **every** task arena before
    /// acknowledging. Returns the reports.
    pub fn on_trigger(&mut self, _t: ZeroizeTrigger) -> Vec<WipeReport> {
        std::mem::take(&mut self.sessions)
            .into_values()
            .map(|s| wipe_or_abort(&s.h))
            .collect()
    }

    /// Live sessions.
    pub fn sessions(&self) -> usize {
        self.sessions.len()
    }
}

#[cfg(test)]
mod label_receipt_tests {
    use super::*;
    use enclave_core::label::{Conf, Taint};
    #[derive(Debug)]
    struct Retaining;
    impl RecurrentBackend for Retaining {
        fn width(&self) -> usize {
            1
        }
        fn system_state(&self) -> Vec<f32> {
            vec![0.0]
        }
        fn step(&self, h: &mut [f32], b: u8) -> EnclaveResult<()> {
            h[0] += b as f32;
            Ok(())
        }
        fn logits(&self, h: &[f32]) -> EnclaveResult<[f32; 256]> {
            let mut out = [0.0; 256];
            out[if h[0] > 0.0 { b'x' } else { b'.' } as usize] = 1.0;
            Ok(out)
        }
    }
    #[test]
    fn f140_partial_anchor_retains_influence_and_never_downgrades_label() {
        let mut dag = StateSnapshotDag::new(Box::new(Retaining), 64, 0.5, 64).unwrap();
        let low = Label::new(Conf::C1, Taint::T0);
        let high = Label::new(Conf::C4, Taint::T3);
        let mut attest = OpAttestor::new(crate::manifest::ExecutionClass::RecurrentSsmTtt, &[]);
        let clean = dag.fork(low).unwrap();
        let dirty = dag.fork(low).unwrap();
        dag.ingest(dirty, high, b"z", &mut attest).unwrap();
        let a = dag.generate(clean, 1, &mut attest).unwrap();
        let b = dag.generate(dirty, 1, &mut attest).unwrap();
        assert_eq!(a.output, b".");
        assert_eq!(a.label, low);
        assert_eq!(b.output, b"x");
        assert_eq!(b.label, high);
        assert!(b.hispa_boundary_anchor_applied);
        assert_eq!(dag.generate(dirty, 1, &mut attest).unwrap().label, high);
        assert!(dag.relabel(dirty, low).is_err());
        assert_eq!(dag.exit(dirty).unwrap().residual, 0);
    }
}

#[cfg(test)]
mod token_path_tests {
    use super::*;
    use enclave_core::label::{Conf, Taint};
    use std::sync::{Arc, Mutex};

    /// Tokens 1..=3 are the bytes `a`..`c`; 0 ends. `h[0]` counts consumed
    /// tokens, `h[1]` holds the last one; the next token cycles a -> b -> c ->
    /// a, or ends after `c` when `ends_after_c`.
    #[derive(Debug, Default)]
    struct Cycle {
        calls: Arc<Mutex<Vec<Vec<u32>>>>,
        ends_after_c: bool,
    }
    impl RecurrentBackend for Cycle {
        fn width(&self) -> usize { 2 }
        fn system_state(&self) -> Vec<f32> { vec![0.0, 0.0] }
        fn step(&self, _: &mut [f32], _: u8) -> EnclaveResult<()> { fail!(ENOSYS, "BYTE") }
        fn logits(&self, _: &[f32]) -> EnclaveResult<[f32; 256]> { fail!(ENOSYS, "BYTE") }
        fn token_model(&self) -> Option<&dyn RecurrentTokenModel> { Some(self) }
    }
    impl RecurrentTokenModel for Cycle {
        fn encode(&self, bytes: &[u8]) -> EnclaveResult<Vec<u32>> {
            Ok(bytes.iter().map(|b| u32::from(b - b'a' + 1)).collect())
        }
        fn token_bytes(&self, id: u32) -> EnclaveResult<&[u8]> {
            Ok(&b"abc"[id as usize - 1..id as usize])
        }
        fn is_end(&self, id: u32) -> bool { id == 0 }
        fn advance(&self, h: &mut [f32], ids: &[u32]) -> EnclaveResult<Vec<f32>> {
            self.calls.lock().unwrap().push(ids.to_vec());
            h[0] += ids.len() as f32;
            let last = *ids.last().unwrap();
            h[1] = last as f32;
            let next = if last == 3 && self.ends_after_c { 0 } else { last % 3 + 1 };
            let mut logits = vec![0.0; 4];
            logits[next as usize] = 1.0;
            Ok(logits)
        }
    }

    type Log = Arc<Mutex<Vec<Vec<u32>>>>;

    fn dag(model: Cycle, window: u32) -> (StateSnapshotDag, SessionId, OpAttestor, Log) {
        let log = model.calls.clone();
        let mut dag = StateSnapshotDag::new(Box::new(model), window, 1.0, 64).unwrap();
        let id = dag.fork(Label::new(Conf::C1, Taint::T0)).unwrap();
        (dag, id, OpAttestor::new(crate::manifest::ExecutionClass::RecurrentSsmTtt, &[]), log)
    }

    fn calls(log: &Log) -> Vec<Vec<u32>> {
        log.lock().unwrap().clone()
    }

    #[test]
    fn newest_token_stays_pending_until_generation_after_the_boundary_anchor() {
        let (mut dag, id, mut attest, log) = dag(Cycle::default(), 2048);
        dag.ingest(id, Label::new(Conf::C1, Taint::T0), b"abc", &mut attest).unwrap();
        assert_eq!(calls(&log), vec![vec![1, 2]], "`c` stays pending");
        let receipt = dag.generate(id, 4, &mut attest).unwrap();
        assert_eq!(receipt.output, b"abca");
        assert!(receipt.hispa_boundary_anchor_applied);
        // alpha 1.0 resets to h_sys at the boundary, before `c` is consumed.
        assert_eq!(calls(&log)[1..], [vec![3], vec![1], vec![2], vec![3]]);
    }

    #[test]
    fn set_cancel_stops_token_generation_before_the_next_step() {
        let (mut dag, id, mut attest, log) = dag(Cycle::default(), 64);
        dag.ingest(id, Label::new(Conf::C1, Taint::T0), b"abc", &mut attest).unwrap();
        let steps_before = calls(&log).len();
        let cancel = std::sync::atomic::AtomicBool::new(true);
        let error = dag.generate_cancellable(id, 8, &mut attest, Some(&cancel)).unwrap_err();
        assert!(error.is("GENERATION_CANCELLED"));
        assert_eq!(calls(&log).len(), steps_before, "no model step after cancel");
        // Unset, the same path generates as before.
        cancel.store(false, std::sync::atomic::Ordering::Release);
        assert!(!dag.generate_cancellable(id, 4, &mut attest, Some(&cancel)).unwrap().output.is_empty());
    }

    #[test]
    fn ingest_is_chunked_at_anchor_points_and_end_of_text_stops_output() {
        let (mut dag, id, mut attest, log) = dag(Cycle { ends_after_c: true, ..Default::default() }, 2);
        dag.ingest(id, Label::new(Conf::C1, Taint::T0), b"abcab", &mut attest).unwrap();
        assert_eq!(calls(&log), vec![vec![1, 2], vec![3, 1]]);
        let receipt = dag.generate(id, 8, &mut attest).unwrap();
        // pending `b` -> c, then c -> end-of-text.
        assert_eq!(receipt.output, b"c");
        assert_eq!(receipt.anchors, 2, "boundary plus one window");
    }

    #[test]
    fn generation_needs_a_prompt_and_output_is_cut_to_the_request() {
        let (mut dag, id, mut attest, _) = dag(Cycle::default(), 2048);
        assert!(dag.generate(id, 2, &mut attest).unwrap_err().is("SSM_PROMPT_REQUIRED"));
        let (mut dag, id, mut attest, _) = self::dag(Cycle::default(), 2048);
        dag.ingest(id, Label::new(Conf::C1, Taint::T0), b"a", &mut attest).unwrap();
        assert_eq!(dag.generate(id, 2, &mut attest).unwrap().output, b"bc");
    }
}
