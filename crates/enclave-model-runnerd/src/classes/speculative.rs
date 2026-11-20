//! Class 5 `SPECULATIVE_OR_RECURRENT_DEPTH` (FS-701 §4.5): thermal-coupled
//! iteration watchdog (`r_max`: nominal/AC → manifest; battery or `.fair` →
//! `<= 8`; `.serious` → 4; `.critical` → refuse), KL early-exit, in-loop
//! latent circuit breaker, rejected-draft zeroization, and reply latency rounding
//! to 20 ms ticks (without a constant-time guarantee).

use std::collections::VecDeque;

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};

use crate::arena::{finite, matvec, output_guard, softmax, wipe_or_abort, Arena, FloatScratch, WipeReport, Wiped};
use crate::safetensors::TensorIndex;
use crate::topology::{OpAttestor, OpFamily};

/// `ProcessInfo.thermalState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ThermalState {
    /// `.nominal`.
    Nominal,
    /// `.fair`.
    Fair,
    /// `.serious`.
    Serious,
    /// `.critical`.
    Critical,
}

/// Power source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PowerSource {
    /// AC.
    Ac,
    /// Battery.
    Battery,
}

/// Thermal / power telemetry.
pub trait ThermalProvider: Send + Sync + std::fmt::Debug {
    /// Current state.
    fn sample(&self) -> (ThermalState, PowerSource);
}

/// Fixed telemetry (tests / Linux CI).
#[derive(Debug, Clone, Copy)]
pub struct FixedThermal(pub ThermalState, pub PowerSource);

impl ThermalProvider for FixedThermal {
    fn sample(&self) -> (ThermalState, PowerSource) {
        (self.0, self.1)
    }
}

/// macOS telemetry: subscribes to Darwin thermal pressure notification
/// `kOSThermalNotificationPressureLevelName` (`com.apple.system.thermalpressurelevel`)
/// via `notify_register_file_descriptor` with zero-syscall atomic cache (GAP-37).
#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
pub struct DarwinThermal {
    state: std::sync::Arc<std::sync::atomic::AtomicU8>,
}

#[cfg(target_os = "macos")]
static SHARED_THERMAL_STATE: std::sync::OnceLock<std::sync::Arc<std::sync::atomic::AtomicU8>> =
    std::sync::OnceLock::new();
#[cfg(any(test, target_os = "macos"))]
fn thermal_reading(level: Option<u64>) -> u8 {
    match level.unwrap_or(u64::MAX) {
        0 => 0, // Nominal
        1 => 1, // Moderate -> Fair
        2 => 2, // Heavy -> Serious
        _ => 3, // Trapping / Sleeping / other -> Critical
    }
}

#[cfg(target_os = "macos")]
impl DarwinThermal {
    /// Initialize the thermal telemetry subscriber.
    pub fn new() -> Self {
        let state = SHARED_THERMAL_STATE.get_or_init(|| {
            let state = std::sync::Arc::new(std::sync::atomic::AtomicU8::new(3));
            let s_clone = state.clone();
            std::thread::Builder::new()
                .name("darwin-thermal-sub".into())
                .spawn(move || {
                    let mut fd: libc::c_int = -1;
                    let mut token: libc::c_int = -1;
                    let rc = unsafe {
                        darwin::notify_register_file_descriptor(
                            c"com.apple.system.thermalpressurelevel".as_ptr(),
                            &mut fd,
                            0,
                            &mut token,
                        )
                    };
                    if rc == 0 && fd >= 0 {
                        let mut initial: u64 = 0;
                        let rc = unsafe { darwin::notify_get_state(token, &mut initial) };
                        s_clone.store(
                            thermal_reading((rc == 0).then_some(initial)),
                            std::sync::atomic::Ordering::Release,
                        );
                        let mut buf = [0u8; 4];
                        loop {
                            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), 4) };
                            if n != 4 {
                                break;
                            }
                            let mut level: u64 = 0;
                            let rc = unsafe { darwin::notify_get_state(token, &mut level) };
                            s_clone.store(
                                thermal_reading((rc == 0).then_some(level)),
                                std::sync::atomic::Ordering::Release,
                            );
                        }
                        unsafe {
                            darwin::notify_cancel(token);
                            libc::close(fd);
                        }
                    }
                    s_clone.store(3, std::sync::atomic::Ordering::Release);
                })
                .ok();
            state
        });
        Self {
            state: state.clone(),
        }
    }
}

#[cfg(target_os = "macos")]
impl Default for DarwinThermal {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "macos")]
mod darwin {
    use std::ffi::c_char;
    #[link(name = "IOKit", kind = "framework")]
    extern "C" {
        pub fn IOPSGetTimeRemainingEstimate() -> f64;
    }
    extern "C" {
        pub fn notify_register_file_descriptor(
            name: *const c_char,
            notify_fd: *mut libc::c_int,
            flags: libc::c_int,
            out_token: *mut libc::c_int,
        ) -> u32;
        pub fn notify_get_state(token: libc::c_int, state: *mut u64) -> u32;
        pub fn notify_cancel(token: libc::c_int) -> u32;
    }
}

#[cfg(target_os = "macos")]
impl ThermalProvider for DarwinThermal {
    fn sample(&self) -> (ThermalState, PowerSource) {
        let raw = self.state.load(std::sync::atomic::Ordering::Acquire);
        let t = match raw {
            0 => ThermalState::Nominal,
            1 => ThermalState::Fair,
            2 => ThermalState::Serious,
            _ => ThermalState::Critical,
        };
        // SAFETY: plain C function without arguments.
        let remaining = unsafe { darwin::IOPSGetTimeRemainingEstimate() };
        (
            t,
            if remaining == -2.0 {
                PowerSource::Ac
            } else {
                PowerSource::Battery
            },
        )
    }
}

/// `r_max` for the current conditions.
pub fn r_max(nominal: u32, fair: u32, t: ThermalState, p: PowerSource) -> EnclaveResult<u32> {
    Ok(match (t, p) {
        (ThermalState::Critical, _) => fail!(
            EAGAIN,
            "THERMAL_CRITICAL_YIELD",
            "GPU yielded; retry after cooling"
        ),
        (ThermalState::Serious, _) => 4.min(nominal),
        (ThermalState::Fair, _) | (_, PowerSource::Battery) => fair.min(8).min(nominal),
        (ThermalState::Nominal, PowerSource::Ac) => nominal.min(32),
    })
}

/// Recurrent-depth backbone with continuous latent feedback.
pub trait DepthBackend: Send + Sync + std::fmt::Debug {
    /// Hidden width.
    fn width(&self) -> usize;
    /// Prelude: embed the input.
    fn prelude(&self, input: &[u8], h: &mut [f32]) -> EnclaveResult<()>;
    /// One shared-weight core iteration (hidden-to-embedding feedback).
    fn core(&self, h: &mut [f32]) -> EnclaveResult<()>;
    /// Coda: next-byte logits.
    fn coda(&self, h: &[f32]) -> EnclaveResult<Vec<f32>>;
    /// Draft head: next-byte proposal given the previous byte.
    fn draft(&self, prev: u8) -> u8;
    /// A real token-level speculative pair, when this backend is one.
    fn token_model(&self) -> Option<&dyn SpeculativeTokenModel> {
        None
    }
}

/// Token-level speculative pair (EAGLE-3): a target model and a draft head
/// fed the target's hidden-state features. Stateless: every call carries the
/// full context, so the gate owns context, features and drafts.
pub trait SpeculativeTokenModel: Send + Sync + std::fmt::Debug {
    /// Tokenize untrusted bytes.
    fn encode(&self, bytes: &[u8]) -> EnclaveResult<Vec<u32>>;
    /// Bytes of one token.
    fn token_bytes(&self, id: u32) -> EnclaveResult<&[u8]>;
    /// Whether `id` ends generation.
    fn is_end(&self, id: u32) -> bool;
    /// Feature floats per position.
    fn feature_width(&self) -> usize;
    /// Target pass over `ids`: greedy next ids for the last `tail` positions
    /// and the features of every position.
    fn verify(&self, ids: &[u32], tail: usize) -> EnclaveResult<(Vec<u32>, Vec<f32>)>;
    /// Draft `k` ids after `ids`, given features for positions `0..ids.len()-1`.
    fn draft(&self, ids: &[u32], features: &[f32], k: usize) -> EnclaveResult<Vec<u32>>;
}

/// Longest context a token-level pair is asked to process.
const MAX_TOKEN_CONTEXT: usize = 4096;
/// Largest draft width, as for the byte path.
const MAX_DRAFT_WIDTH: usize = 16;
/// Computation window for the reference byte backends.
const BYTE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(2);
/// Computation window for a real token-level pair (full recompute on CPU).
const TOKEN_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

/// Reference: `enclave_adapter.recurrent_core.embed [256, d]`,
/// `enclave_adapter.latent_thought_proj.weight [d, d]`,
/// `enclave_adapter.recurrent_core.out [256, d]`,
/// `enclave_adapter.eagle_fc.weight [256, 256]` (draft bigram).
#[derive(Debug, Clone)]
pub struct ReferenceDepth {
    embed: Vec<f32>,
    core: Vec<f32>,
    out: Vec<f32>,
    draft: Vec<u8>,
    d: usize,
}

impl ReferenceDepth {
    /// Load.
    pub fn load(idx: &TensorIndex, file: &[u8]) -> EnclaveResult<Self> {
        let d = idx
            .shape("enclave_adapter.latent_thought_proj.weight")
            .and_then(|s| s.first().copied())
            .ok_or_else(|| err!(EINVAL, "TENSOR_MISSING", "latent_thought_proj"))?;
        let fc = if idx.shape("enclave_adapter.eagle_fc.weight").is_some() {
            idx.f32(file, "enclave_adapter.eagle_fc.weight", &[256, 256])?
        } else {
            vec![0.0; 256 * 256]
        };
        let draft = fc
            .as_chunks::<256>()
            .0
            .iter()
            .map(|r| {
                (0..256)
                    .max_by(|a, b| r[*a].total_cmp(&r[*b]).then(b.cmp(a)))
                    .unwrap_or(0) as u8
            })
            .collect();
        Ok(Self {
            embed: idx.f32(file, "enclave_adapter.recurrent_core.embed", &[256, d])?,
            core: idx.f32(file, "enclave_adapter.latent_thought_proj.weight", &[d, d])?,
            out: idx.f32(file, "enclave_adapter.recurrent_core.out", &[256, d])?,
            draft,
            d,
        })
    }
}

impl DepthBackend for ReferenceDepth {
    fn width(&self) -> usize {
        self.d
    }
    fn prelude(&self, input: &[u8], h: &mut [f32]) -> EnclaveResult<()> {
        h.iter_mut().for_each(|x| *x = 0.0);
        for b in input {
            let e = &self.embed[*b as usize * self.d..(*b as usize + 1) * self.d];
            h.iter_mut().zip(e).for_each(|(x, y)| *x = 0.5 * *x + y);
        }
        finite(h, "prelude")
    }
    fn core(&self, h: &mut [f32]) -> EnclaveResult<()> {
        let y = FloatScratch::new(matvec(&self.core, self.d, self.d, h)?, "depth_core");
        h.iter_mut().zip(y.iter()).for_each(|(x, v)| *x = v.tanh());
        finite(h, "core")
    }
    fn coda(&self, h: &[f32]) -> EnclaveResult<Vec<f32>> {
        matvec(&self.out, 256, self.d, h)
    }
    fn draft(&self, prev: u8) -> u8 {
        self.draft[prev as usize]
    }
}

/// Linear safety-cone probe on the continuous latent `h_r`.
#[derive(Debug, Clone)]
pub struct LatentProbe {
    /// Direction.
    pub w: Vec<f32>,
    /// Threshold on the normalised projection.
    pub tau: f32,
}

impl LatentProbe {
    fn trips(&self, h: &[f32]) -> bool {
        let n = h.iter().map(|x| x * x).sum::<f32>().sqrt();
        let wn = self.w.iter().map(|x| x * x).sum::<f32>().sqrt();
        n > 0.0
            && wn > 0.0
            && h.iter().zip(&self.w).map(|(a, b)| a * b).sum::<f32>() / (n * wn) > self.tau
    }
}

/// Loop result.
#[derive(Debug, Clone, PartialEq)]
pub struct DepthResult {
    /// Next byte.
    pub byte: u8,
    /// Iterations run.
    pub iterations: u32,
    /// Halted by KL early-exit.
    pub kl_exit: bool,
}

fn kl(p: &[f64], q: &[f64]) -> f64 {
    p.iter()
        .zip(q)
        .filter(|(a, _)| **a > 0.0)
        .map(|(a, b)| a * (a / b.max(1e-300)).ln())
        .sum()
}

// Private current-allocation byte owner. Reserve the complete admitted bound
// before copying sensitive bytes; checked pushes can never reallocate. Existing
// Wiped exposes a mutable Vec, while SecretBytes fixes length and cannot transfer
// an accepted output allocation. Neither supplies this bounded growth seam.
struct SpeculationBytes {
    bytes: Vec<u8>,
    limit: usize,
    #[cfg(test)]
    owner: &'static str,
    #[cfg(test)]
    allocation: (usize, usize),
}
impl SpeculationBytes {
    fn new(initial: &[u8], limit: usize, _owner: &'static str) -> EnclaveResult<Self> {
        if initial.len() > limit { fail!(EIO, "SPECULATION_CAPACITY"); }
        let mut bytes = Vec::with_capacity(limit);
        bytes.extend_from_slice(initial);
        Ok(Self { #[cfg(test)] allocation: (bytes.as_ptr() as usize, bytes.capacity()),
            bytes, limit, #[cfg(test)] owner: _owner })
    }
    fn push(&mut self, byte: u8) -> EnclaveResult<()> {
        if self.bytes.len() >= self.limit { fail!(EIO, "SPECULATION_CAPACITY"); }
        self.bytes.push(byte); Ok(())
    }
    fn into_vec(mut self) -> Vec<u8> {
        #[cfg(test)]
        speculation_owner_tests::transferred(self.owner, &self.bytes, self.allocation);
        std::mem::take(&mut self.bytes)
    }
}
impl std::ops::Deref for SpeculationBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] { &self.bytes }
}
impl Drop for SpeculationBytes {
    fn drop(&mut self) {
        for byte in &mut self.bytes {
            // SAFETY: live initialized, exclusively borrowed byte.
            unsafe { std::ptr::write_volatile(byte, 0); }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        if !self.bytes.is_empty() {
            speculation_owner_tests::scrubbed(self.owner, &self.bytes, self.allocation);
        }
    }
}

/// The gate.
#[derive(Debug)]
pub struct DepthGate {
    backend: Box<dyn DepthBackend>,
    /// Latent-cone breaker for the recurrent-depth loop; absent for a
    /// token-level speculative pair, which has no continuous-thought loop.
    probe: Option<LatentProbe>,
    deadline: std::time::Duration,
    thermal: Box<dyn ThermalProvider>,
    nominal: u32,
    fair: u32,
    max_output_bytes: u32,
}

impl DepthGate {
    /// Bind.
    pub fn new(
        backend: Box<dyn DepthBackend>,
        probe: LatentProbe,
        thermal: Box<dyn ThermalProvider>,
        nominal: u32,
        fair: u32,
        max_output_bytes: u32,
    ) -> EnclaveResult<Self> {
        if probe.w.len() != backend.width() {
            fail!(EINVAL, "LATENT_PROBE_SHAPE");
        }
        crate::arena::validate_probe(&probe.w, backend.width())?;
        if !(probe.tau.is_finite() && probe.tau > 0.0 && probe.tau < 1.0) {
            fail!(EINVAL, "LATENT_PROBE_THRESHOLD");
        }
        Ok(Self {
            backend,
            probe: Some(probe),
            deadline: BYTE_DEADLINE,
            thermal,
            nominal: nominal.min(32),
            fair: fair.min(8),
            max_output_bytes,
        })
    }

    /// Bind a token-level speculative pair (no recurrent-depth loop, so no
    /// latent probe); the thermal watchdog bounds the draft width.
    pub fn speculative(
        backend: Box<dyn DepthBackend>,
        thermal: Box<dyn ThermalProvider>,
        nominal: u32,
        fair: u32,
        max_output_bytes: u32,
    ) -> EnclaveResult<Self> {
        if backend.token_model().is_none() {
            fail!(EINVAL, "SPECULATIVE_TOKEN_MODEL_REQUIRED");
        }
        Ok(Self {
            backend,
            probe: None,
            deadline: TOKEN_DEADLINE,
            thermal,
            nominal: nominal.min(32),
            fair: fair.min(8),
            max_output_bytes,
        })
    }

    /// Run the recurrent-depth loop for one output byte.
    pub fn think(
        &self,
        input: &[u8],
        attest: &mut OpAttestor,
    ) -> EnclaveResult<(DepthResult, WipeReport)> {
        self.think_with_wipe(input, attest, None).0
    }

    fn think_with_wipe(
        &self,
        input: &[u8],
        attest: &mut OpAttestor,
        checkpoint: Option<&dyn Fn() -> EnclaveResult<()>>,
    ) -> (EnclaveResult<(DepthResult, WipeReport)>, Option<WipeReport>) {
        let check = || checkpoint.map_or(Ok(()), |check| check());
        let mut wipe_report = None;
        let result = (|| -> EnclaveResult<(DepthResult, WipeReport)> {
            check()?;
            let probe = self.probe.as_ref().ok_or_else(|| err!(ENOSYS, "DEPTH_LOOP_UNSUPPORTED"))?;
            attest.admit(OpFamily::RecurrentDepthLoop)?;
            let (t, p) = self.thermal.sample();
            check()?;
            let rmax = r_max(self.nominal, self.fair, t, p)?;
            let d = self.backend.width();
            let mut arena = Arena::floats(d)?;
            let res = (|| -> EnclaveResult<DepthResult> {
                let h = &mut arena.f32_mut()?[..d];
                self.backend.prelude(input, h)?;
                check()?;
                let mut prev: Option<FloatScratch<f64>> = None;
                let mut r = 0;
                let mut kl_exit = false;
                while r < rmax {
                    check()?;
                    self.backend.core(h)?;
                    check()?;
                    r += 1;
                    if probe.trips(h) {
                        fail!(
                            EACCES,
                            "LATENT_CIRCUIT_BREAKER",
                            "continuous thought entered a policy-evasion cone at r = {r}"
                        );
                    }
                    // Adopt before the cancellation checkpoint: a backend may
                    // finish after cancellation while returning a live Vec.
                    let logits = FloatScratch::new(self.backend.coda(h)?, "depth_logits");
                    check()?;
                    let p = FloatScratch::new(softmax(&logits)
                        .ok_or_else(|| err!(EIO, "NON_FINITE_ACTIVATION"))?, "depth_probabilities");
                    if let Some(q) = &prev {
                        if kl(&p, q) < 1e-3 {
                            kl_exit = true;
                            prev = Some(p);
                            break;
                        }
                    }
                    prev = Some(p);
                }
                let p = prev.ok_or_else(|| err!(EIO, "DEPTH_NO_ITERATION"))?;
                let byte = (0..p.len())
                    .max_by(|a, b| p[*a].total_cmp(&p[*b]).then(b.cmp(a)))
                    .unwrap_or(0) as u8;
                Ok(DepthResult {
                    byte,
                    iterations: r,
                    kl_exit,
                })
            })();
            // Zeroize on every path (breaker abort included).
            let w = wipe_or_abort(&arena);
            wipe_report = Some(w);
            let res = res?;
            check()?;
            Ok((res, w))
        })();
        (result, wipe_report)
    }

    /// Speculative decode of `n` bytes: draft `k` tokens per round in an
    /// isolated arena, verify with the target loop, zero rejected subtrees
    /// before commit. Returns `(output, rejected_bytes_zeroized)`.
    pub fn speculate(
        &self,
        prompt: &[u8],
        n: usize,
        k: usize,
        attest: &mut OpAttestor,
    ) -> EnclaveResult<(Vec<u8>, usize)> {
        self.speculate_cancellable(
            prompt,
            n,
            k,
            attest,
            &std::sync::atomic::AtomicBool::new(false),
        )
    }

    /// Cooperative request cancellation plus a bound on repeated-context work.
    pub fn speculate_cancellable(
        &self,
        prompt: &[u8],
        n: usize,
        k: usize,
        attest: &mut OpAttestor,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> EnclaveResult<(Vec<u8>, usize)> {
        self.speculate_cancellable_with_wipes(prompt, n, k, attest, cancel)
            .0
    }

    /// Every target and draft arena receipt belongs to this invocation, including
    /// receipts produced before backend, breaker, guard or cancellation errors.
    pub(crate) fn speculate_cancellable_with_wipes(
        &self,
        prompt: &[u8],
        n: usize,
        k: usize,
        attest: &mut OpAttestor,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> (EnclaveResult<(Vec<u8>, usize)>, Vec<WipeReport>) {
        if let Some(tm) = self.backend.token_model() {
            return self.speculate_tokens(tm, prompt, n, k, attest, cancel);
        }
        let mut wipe_reports = Vec::new();
        let result = (|| -> EnclaveResult<(Vec<u8>, usize)> {
            let context_capacity = prompt.len().checked_add(n)
                .ok_or_else(|| err!(E2BIG, "SPECULATION_WORK_BUDGET"))?;
            if !context_capacity.checked_mul(n.max(1))
                .is_some_and(|work| work <= 1_000_000)
            {
                fail!(E2BIG, "SPECULATION_WORK_BUDGET");
            }
            let start = std::time::Instant::now();
            // Synchronous backends cannot be interrupted inside a call. Check
            // again when each call returns: even the final target must never
            // release output after the server-owned computation deadline.
            let checkpoint = || -> EnclaveResult<()> {
                if cancel.load(std::sync::atomic::Ordering::Acquire) {
                    fail!(EAGAIN, "GENERATION_CANCELLED");
                }
                if start.elapsed() > self.deadline {
                    fail!(ETIMEDOUT, "GENERATION_DEADLINE");
                }
                Ok(())
            };
            checkpoint()?;
            attest.admit(OpFamily::DraftTree)?;
            if n > self.max_output_bytes as usize || !(1..=16).contains(&k) {
                fail!(E2BIG, "SPECULATION_BOUNDS");
            }
            let mut ctx = SpeculationBytes::new(prompt, context_capacity, "speculation_context")?;
            let mut out = SpeculationBytes::new(&[], n, "speculation_output")?;
            let mut zeroed = 0;
            let mut drafts = Arena::new(k)?;
            let generated = (|| -> EnclaveResult<()> {
                while out.len() < n {
                    let mut last = *ctx.last().unwrap_or(&0);
                    {
                        let dbuf = drafts.bytes_mut()?;
                        for slot in dbuf.iter_mut().take(k) {
                            checkpoint()?;
                            last = self.backend.draft(last);
                            checkpoint()?;
                            *slot = last;
                        }
                    }
                    let mut accepted = 0;
                    for i in 0..k {
                        if out.len() >= n {
                            break;
                        }
                        checkpoint()?;
                        let (result, wipe) = self.think_with_wipe(&ctx, attest, Some(&checkpoint));
                        wipe_reports.extend(wipe);
                        let (target, _) = result?;
                        checkpoint()?;
                        let proposed = drafts.bytes()?[i];
                        let tok = target.byte;
                        out.push(tok)?;
                        ctx.push(tok)?;
                        if tok != proposed {
                            break;
                        }
                        accepted += 1;
                    }
                    // Rejected subtree: overwrite before the commit is released.
                    let dbuf = drafts.bytes_mut()?;
                    for b in dbuf.iter_mut().take(k).skip(accepted) {
                        // SAFETY: in-bounds exclusive element of the arena.
                        unsafe { std::ptr::write_volatile(b, 0) };
                        zeroed += 1;
                    }
                    if dbuf[accepted.min(k)..k].iter().any(|b| *b != 0) {
                        fail!(EIO, "DRAFT_ZEROIZE_FAILED");
                    }
                }
                Ok(())
            })();
            // Explicitly measure the draft wipe on cancellation/error as well as
            // success, after every target arena has completed its own measured wipe.
            wipe_reports.push(wipe_or_abort(&drafts));
            generated?;
            checkpoint()?;
            output_guard(&out, self.max_output_bytes)?;
            // Include context cleanup in the original computation window.
            // A cancellation/expiry during scrub must still withhold output.
            drop(ctx);
            checkpoint()?;
            Ok((out.into_vec(), zeroed))
        })();
        (result, wipe_reports)
    }
}

impl DepthGate {
    /// Token-level speculative decoding: draft `k` ids per round into an
    /// isolated arena, verify them with one target pass, commit the matching
    /// prefix plus the target's own next id, and zero the rejected drafts
    /// before anything is released. Output equals greedy target decoding.
    fn speculate_tokens(
        &self,
        tm: &dyn SpeculativeTokenModel,
        prompt: &[u8],
        n: usize,
        k: usize,
        attest: &mut OpAttestor,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> (EnclaveResult<(Vec<u8>, usize)>, Vec<WipeReport>) {
        let mut wipe_reports = Vec::new();
        let result = (|| -> EnclaveResult<(Vec<u8>, usize)> {
            let start = std::time::Instant::now();
            let checkpoint = || -> EnclaveResult<()> {
                if cancel.load(std::sync::atomic::Ordering::Acquire) {
                    fail!(EAGAIN, "GENERATION_CANCELLED");
                }
                if start.elapsed() > self.deadline {
                    fail!(ETIMEDOUT, "GENERATION_DEADLINE");
                }
                Ok(())
            };
            checkpoint()?;
            attest.admit(OpFamily::DraftTree)?;
            attest.admit(OpFamily::CausalDecode)?;
            if n > self.max_output_bytes as usize || !(1..=MAX_DRAFT_WIDTH).contains(&k) {
                fail!(E2BIG, "SPECULATION_BOUNDS");
            }
            let (t, p) = self.thermal.sample();
            let width = (k as u32).min(r_max(self.nominal, self.fair, t, p)?).max(1) as usize;
            let mut ctx = Wiped::new(tm.encode(prompt)?, 0u32);
            if ctx.is_empty() {
                fail!(EINVAL, "SPECULATION_PROMPT_REQUIRED");
            }
            if ctx.len() + n + width + 1 > MAX_TOKEN_CONTEXT {
                fail!(E2BIG, "SPECULATION_CONTEXT");
            }
            let mut out = SpeculationBytes::new(&[], n, "speculation_output")?;
            let mut drafts = Arena::new(4 * MAX_DRAFT_WIDTH)?;
            let mut zeroed = 0;
            let fw = tm.feature_width();
            let generated = (|| -> EnclaveResult<()> {
                let (next, features) = tm.verify(&ctx, 1)?;
                let mut features = FloatScratch::new(features, "speculation_features");
                checkpoint()?;
                let mut pending = *next.first().ok_or_else(|| err!(EIO, "SPECULATION_VERIFY_SHAPE"))?;
                loop {
                    if tm.is_end(pending) {
                        break;
                    }
                    for b in tm.token_bytes(pending)? {
                        if out.len() < n {
                            out.push(*b)?;
                        }
                    }
                    ctx.push(pending);
                    if out.len() >= n {
                        break;
                    }
                    let rows = ctx.len() - 1;
                    if features.len() < rows * fw {
                        fail!(EIO, "SPECULATION_FEATURE_SHAPE");
                    }
                    let drafted = Wiped::new(tm.draft(&ctx, &features[..rows * fw], width)?, 0u32);
                    checkpoint()?;
                    if drafted.len() != width {
                        fail!(EIO, "SPECULATION_DRAFT_SHAPE");
                    }
                    {
                        let slots = drafts.bytes_mut()?;
                        for (slot, id) in slots.chunks_exact_mut(4).zip(drafted.iter()) {
                            slot.copy_from_slice(&id.to_le_bytes());
                        }
                    }
                    let mut probe = Wiped::new(Vec::with_capacity(ctx.len() + width), 0u32);
                    probe.extend_from_slice(&ctx);
                    probe.extend_from_slice(&drafted);
                    let (preds, next_features) = tm.verify(&probe, width + 1)?;
                    features = FloatScratch::new(next_features, "speculation_features");
                    checkpoint()?;
                    if preds.len() != width + 1 {
                        fail!(EIO, "SPECULATION_VERIFY_SHAPE");
                    }
                    let accepted = drafted.iter().zip(&preds).take_while(|(d, p)| d == p).count();
                    // Rejected subtree: overwrite before the commit is released.
                    let slots = drafts.bytes_mut()?;
                    for b in slots.iter_mut().take(4 * width).skip(4 * accepted) {
                        // SAFETY: in-bounds exclusive element of the arena.
                        unsafe { std::ptr::write_volatile(b, 0) };
                    }
                    if slots[4 * accepted..4 * width].iter().any(|b| *b != 0) {
                        fail!(EIO, "DRAFT_ZEROIZE_FAILED");
                    }
                    zeroed += width - accepted;
                    let mut ended = false;
                    for id in drafted.iter().take(accepted) {
                        if tm.is_end(*id) {
                            ended = true;
                            break;
                        }
                        for b in tm.token_bytes(*id)? {
                            if out.len() < n {
                                out.push(*b)?;
                            }
                        }
                        ctx.push(*id);
                    }
                    if ended || out.len() >= n {
                        break;
                    }
                    pending = preds[accepted];
                }
                Ok(())
            })();
            wipe_reports.push(wipe_or_abort(&drafts));
            generated?;
            checkpoint()?;
            output_guard(&out, self.max_output_bytes)?;
            drop(ctx);
            checkpoint()?;
            Ok((out.into_vec(), zeroed))
        })();
        (result, wipe_reports)
    }
}

/// Buffered tick helper. The service rounds a complete reply to a tick;
/// this does not hide generation duration or provide constant-work release.
#[derive(Debug)]
pub struct CadencePacer {
    tick_ms: u64,
    per_tick: usize,
    start_ms: u64,
    released_ticks: u64,
    queue: VecDeque<u8>,
}

impl CadencePacer {
    /// 20 ms ticks.
    pub fn new(start_ms: u64, per_tick: usize) -> Self {
        Self {
            tick_ms: 20,
            per_tick: per_tick.max(1),
            start_ms,
            released_ticks: 0,
            queue: VecDeque::new(),
        }
    }
    /// Accepted tokens enter the queue.
    pub fn push(&mut self, toks: &[u8]) {
        self.queue.extend(toks);
    }
    /// Tokens due at `now_ms` (only on tick boundaries; never more than
    /// `per_tick` per elapsed tick).
    pub fn release(&mut self, now_ms: u64) -> Vec<u8> {
        let ticks = now_ms.saturating_sub(self.start_ms) / self.tick_ms;
        let mut out = Vec::new();
        while self.released_ticks < ticks {
            self.released_ticks += 1;
            for _ in 0..self.per_tick {
                match self.queue.front_mut() {
                    Some(front) => {
                        let token = *front;
                        // Clear the still-owned slot before removing it; deque
                        // pop alone leaves the old byte in reusable storage.
                        unsafe { std::ptr::write_volatile(front, 0); }
                        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
                        self.queue.pop_front();
                        out.push(token);
                    },
                    None => break,
                }
            }
        }
        out
    }
    /// Yank / screen-lock mid-tick: drop and zeroize everything pending.
    pub fn yank(&mut self) -> usize {
        let n = self.queue.len();
        for b in self.queue.iter_mut() {
            // SAFETY: valid exclusive element.
            unsafe { std::ptr::write_volatile(b, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        self.queue.clear();
        n
    }
}

impl Drop for CadencePacer {
    fn drop(&mut self) {self.yank();}
}

#[cfg(test)]
mod telemetry_failure_tests {
    use super::*;
    #[test]
    fn f142_missing_or_failed_thermal_reading_is_critical() {
        assert_eq!(thermal_reading(None), 3);
        for (value, expected) in [(0, 0), (1, 1), (2, 2), (3, 3), (u64::MAX, 3)] {
            assert_eq!(thermal_reading(Some(value)), expected);
        }
        assert!(r_max(32, 8, ThermalState::Critical, PowerSource::Ac).is_err());
    }
}

#[cfg(test)]
mod pacing_owner_tests {
    use super::*;
    #[test]
    fn yk11_actual_pacer_clears_removed_and_cancelled_slots_without_changing_released_bytes() {
        let mut pacer=CadencePacer::new(100,1);pacer.push(b"secret");
        // The deque allocation remains owned and unchanged in capacity during
        // these reads. Inspect initialized u8 slots before any deallocation.
        let original=pacer.queue.as_slices().0.as_ptr();
        assert_eq!(pacer.release(120),b"s");
        assert_eq!(unsafe{std::ptr::read_volatile(original)},0,"released slot must clear before reuse");
        let (first,second)=pacer.queue.as_slices();
        let pending=first.iter().chain(second).map(|byte|byte as *const u8).collect::<Vec<_>>();
        assert_eq!(pacer.yank(),5);
        for pointer in pending {assert_eq!(unsafe{std::ptr::read_volatile(pointer)},0);}
        assert!(pacer.release(1000).is_empty());
        pacer.push(b"new");assert_eq!(pacer.release(1020),b"n");
        // Drop calls the same yank primitive for any remaining live slots.
    }
}

#[cfg(test)]
mod depth_owner_tests {
    use super::*;
    use crate::arena::float_scratch_tests::{self, Event};
    use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}};

    fn assert_owners(logits: usize, probabilities: usize, cores: usize) {
        let events = float_scratch_tests::finish();
        let mut actual = Vec::new(); let mut transfers = 0;
        for event in events {
            match event {
                Event::Scrubbed(owner, len, wiped) => {
                    assert!(wiped, "initialized allocation must scrub before deallocation");
                    actual.push((owner, len));
                }
                Event::Transferred("softmax", 2) => transfers += 1,
                other => panic!("unexpected transfer {other:?}"),
            }
        }
        let mut expected = Vec::new();
        expected.extend(std::iter::repeat_n(("depth_logits", 2), logits));
        expected.extend(std::iter::repeat_n(("depth_probabilities", 2), probabilities));
        expected.extend(std::iter::repeat_n(("depth_core", 2), cores));
        actual.sort_unstable(); expected.sort_unstable(); assert_eq!(actual, expected);
        assert_eq!(transfers, probabilities, "every exact softmax allocation moves into its caller owner");
    }

    #[test]
    fn actual_reference_core_preserves_tanh_and_scrubs_success_and_nonfinite_error() {
        let mut backend = ReferenceDepth { embed: vec![], core: vec![1.0,0.0,0.0,2.0],
            out: vec![], draft: vec![], d: 2 };
        let mut latent = [0.25, -0.5];
        float_scratch_tests::begin(); backend.core(&mut latent).unwrap();
        assert_eq!(latent, [0.25_f32.tanh(), (-1.0_f32).tanh()]); assert_owners(0,0,1);
        // An actual matvec succeeds with a non-finite owned result; the later
        // validation error must scrub it, not merely the caller's arena.
        let mut invalid = [f32::INFINITY, 1.0];
        float_scratch_tests::begin();
        assert!(backend.core(&mut invalid).unwrap_err().is("NON_FINITE_ACTIVATION")); assert_owners(0,0,1);
        backend.core.pop(); let mut unchanged = [0.25, -0.5];
        float_scratch_tests::begin(); assert!(backend.core(&mut unchanged).unwrap_err().is("MATVEC_SHAPE"));
        assert_eq!(unchanged, [0.25,-0.5]); assert_owners(0,0,0);
    }

    #[derive(Debug, Clone, Copy)]
    enum Mode { Stable, Alternating, CoreError, CodaError, Breaker, Nonfinite, CancelAfterCoda }
    #[derive(Debug)]
    struct Backend { mode: Mode, core_calls: AtomicUsize, cancel: Arc<AtomicBool> }
    impl DepthBackend for Backend {
        fn width(&self) -> usize { 2 }
        fn prelude(&self, _: &[u8], hidden: &mut [f32]) -> EnclaveResult<()> {
            hidden.copy_from_slice(&[-1.0,0.0]); Ok(())
        }
        fn core(&self, hidden: &mut [f32]) -> EnclaveResult<()> {
            let count = self.core_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if count == 2 {
                match self.mode {
                    Mode::CoreError => fail!(EIO, "FIXTURE_DEPTH_CORE"),
                    Mode::Breaker => hidden.copy_from_slice(&[1.0,0.0]),
                    _ => (),
                }
            }
            Ok(())
        }
        fn coda(&self, _: &[f32]) -> EnclaveResult<Vec<f32>> {
            let count = self.core_calls.load(Ordering::SeqCst);
            if count == 2 {
                match self.mode {
                    Mode::CodaError => fail!(EIO, "FIXTURE_DEPTH_CODA"),
                    Mode::Nonfinite => return Ok(vec![f32::NAN, 0.0]),
                    Mode::CancelAfterCoda => self.cancel.store(true, Ordering::SeqCst),
                    _ => (),
                }
            }
            Ok(if matches!(self.mode, Mode::Alternating) && count % 2 == 1 { vec![3.0,-3.0] }
                else { vec![-3.0,3.0] })
        }
        fn draft(&self, _: u8) -> u8 { 0 }
    }
    fn gate(mode: Mode) -> (DepthGate, Arc<AtomicBool>) {
        let cancel = Arc::new(AtomicBool::new(false));
        let gate = DepthGate::new(Box::new(Backend { mode, core_calls: AtomicUsize::new(0), cancel: cancel.clone() }),
            LatentProbe { w: vec![1.0,0.0], tau: 0.9 },
            Box::new(FixedThermal(ThermalState::Nominal,PowerSource::Ac)), 3,3,32).unwrap();
        (gate,cancel)
    }
    fn attest() -> OpAttestor { OpAttestor::new(crate::manifest::ExecutionClass::SpeculativeOrRecurrentDepth,&[]) }
    fn wiped(report: Option<WipeReport>) {
        let report = report.expect("actual hidden arena wiped on every entered path");
        assert!(report.bytes > 0); assert_eq!(report.residual,0);
    }

    #[test]
    fn actual_depth_kl_exit_and_full_depth_scrub_replaced_and_final_distributions() {
        for (mode, iterations, byte, kl_exit) in [(Mode::Stable,2,1,true),(Mode::Alternating,3,0,false)] {
            let (gate,_) = gate(mode); float_scratch_tests::begin();
            let (result, report) = gate.think_with_wipe(b"synthetic",&mut attest(),None);
            let (result, returned_report) = result.unwrap();
            assert_eq!((result.iterations,result.byte,result.kl_exit),(iterations,byte,kl_exit));
            assert_eq!(returned_report.residual,0); wiped(report);
            assert_owners(iterations as usize,iterations as usize,0);
        }
    }

    #[test]
    fn late_backend_errors_and_breaker_scrub_earlier_distribution_before_refusal() {
        for (mode, reason) in [(Mode::CoreError,"FIXTURE_DEPTH_CORE"),(Mode::CodaError,"FIXTURE_DEPTH_CODA"),
            (Mode::Breaker,"LATENT_CIRCUIT_BREAKER")] {
            let (gate,_) = gate(mode); float_scratch_tests::begin();
            let (result, report) = gate.think_with_wipe(b"synthetic",&mut attest(),None);
            assert!(result.unwrap_err().is(reason)); wiped(report); assert_owners(1,1,0);
        }
    }

    #[test]
    fn nonfinite_coda_scrubs_new_logits_and_previous_valid_probabilities() {
        let (gate,_) = gate(Mode::Nonfinite); float_scratch_tests::begin();
        let (result, report) = gate.think_with_wipe(b"synthetic",&mut attest(),None);
        assert!(result.unwrap_err().is("NON_FINITE_ACTIVATION")); wiped(report); assert_owners(2,1,0);
    }

    #[test]
    fn cancellation_observed_after_coda_scrubs_just_returned_logits_and_previous_result() {
        let (gate,cancel) = gate(Mode::CancelAfterCoda);
        let checkpoint = || { if cancel.load(Ordering::SeqCst) { fail!(EAGAIN,"GENERATION_CANCELLED"); } Ok(()) };
        float_scratch_tests::begin();
        let (result, report) = gate.think_with_wipe(b"synthetic",&mut attest(),Some(&checkpoint));
        assert!(result.unwrap_err().is("GENERATION_CANCELLED")); wiped(report); assert_owners(2,1,0);
    }
}

#[cfg(test)]
mod speculation_owner_tests {
    use super::*;
    use std::{cell::RefCell, sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}}};

    #[derive(Debug, PartialEq, Eq)]
    enum Event {
        Scrubbed(&'static str, usize, bool, bool),
        Transferred(&'static str, usize, bool),
    }
    thread_local! {
        static EVENTS: RefCell<Option<Vec<Event>>> = const { RefCell::new(None) };
        static CANCEL_ON_CONTEXT_SCRUB: RefCell<Option<Arc<AtomicBool>>> = const { RefCell::new(None) };
    }
    fn stable(bytes: &[u8], allocation: (usize, usize)) -> bool {
        bytes.as_ptr() as usize == allocation.0
    }
    // Observe initialized storage only after the real production volatile
    // scrub/fence and before Vec deallocation. No raw byte/address is recorded.
    pub(super) fn scrubbed(owner: &'static str, bytes: &Vec<u8>, allocation: (usize, usize)) {
        EVENTS.with(|events| if let Some(events) = events.borrow_mut().as_mut() {
            events.push(Event::Scrubbed(owner, bytes.len(), bytes.iter().all(|byte| *byte == 0),
                stable(bytes, allocation) && bytes.capacity() == allocation.1));
        });
        if owner == "speculation_context" {
            CANCEL_ON_CONTEXT_SCRUB.with(|cancel| if let Some(cancel) = cancel.borrow_mut().take() {
                cancel.store(true, Ordering::SeqCst);
            });
        }
    }
    pub(super) fn transferred(owner: &'static str, bytes: &Vec<u8>, allocation: (usize, usize)) {
        EVENTS.with(|events| if let Some(events) = events.borrow_mut().as_mut() {
            events.push(Event::Transferred(owner, bytes.len(),
                stable(bytes, allocation) && bytes.capacity() == allocation.1));
        });
    }
    fn begin() {
        EVENTS.with(|events| *events.borrow_mut() = Some(Vec::new()));
        CANCEL_ON_CONTEXT_SCRUB.with(|cancel| *cancel.borrow_mut() = None);
    }
    fn finish(context: usize, output: Option<usize>, transferred: Option<usize>) {
        let events = EVENTS.with(|events| events.borrow_mut().take().unwrap());
        let mut expected = Vec::new();
        if let Some(len) = transferred {
            if context > 0 { expected.push(Event::Scrubbed("speculation_context", context, true, true)); }
            expected.push(Event::Transferred("speculation_output", len, true));
        } else {
            if let Some(len) = output { expected.push(Event::Scrubbed("speculation_output", len, true, true)); }
            if context > 0 { expected.push(Event::Scrubbed("speculation_context", context, true, true)); }
        }
        assert_eq!(events, expected, "exact current owners, no reallocation or hidden output transfer");
    }
    const PROMPT: &[u8] = b"synthetic-context";
    #[derive(Debug, Clone, Copy)]
    enum Mode { Normal, LateError, LateCancel }
    #[derive(Debug)]
    struct Backend {
        bytes: &'static [u8], proposed: u8, mode: Mode,
        prelude_calls: AtomicUsize, output_index: AtomicUsize, context_pointer: AtomicUsize,
        cancel: Arc<AtomicBool>,
    }
    impl DepthBackend for Backend {
        fn width(&self) -> usize { 2 }
        fn prelude(&self, input: &[u8], hidden: &mut [f32]) -> EnclaveResult<()> {
            assert_eq!(&input[..PROMPT.len()], PROMPT, "borrowed prompt copied unchanged");
            let emitted = input.len() - PROMPT.len();
            assert_eq!(&input[PROMPT.len()..], &self.bytes[..emitted], "target sees exact previously committed bytes");
            let pointer = input.as_ptr() as usize;
            let previous = self.context_pointer.swap(pointer, Ordering::SeqCst);
            assert!(previous == 0 || previous == pointer, "context growth must not free a prior sensitive allocation");
            self.output_index.store(emitted, Ordering::SeqCst);
            let call = self.prelude_calls.fetch_add(1, Ordering::SeqCst) + 1;
            hidden.copy_from_slice(&[-1.0, 0.0]);
            if call == 2 && matches!(self.mode, Mode::LateCancel) { self.cancel.store(true, Ordering::SeqCst); }
            Ok(())
        }
        fn core(&self, _: &mut [f32]) -> EnclaveResult<()> { Ok(()) }
        fn coda(&self, _: &[f32]) -> EnclaveResult<Vec<f32>> {
            if self.prelude_calls.load(Ordering::SeqCst) == 2 && matches!(self.mode, Mode::LateError) {
                fail!(EIO, "FIXTURE_SPECULATION_CODA");
            }
            let byte = self.bytes[self.output_index.load(Ordering::SeqCst)];
            let mut logits = vec![-5.0; 256]; logits[byte as usize] = 5.0; Ok(logits)
        }
        fn draft(&self, _: u8) -> u8 { self.proposed }
    }
    fn gate(bytes: &'static [u8], proposed: u8, mode: Mode) -> (DepthGate, Arc<AtomicBool>) {
        let cancel = Arc::new(AtomicBool::new(false));
        let backend = Backend { bytes, proposed, mode, prelude_calls: AtomicUsize::new(0),
            output_index: AtomicUsize::new(0), context_pointer: AtomicUsize::new(0), cancel: cancel.clone() };
        (DepthGate::new(Box::new(backend), LatentProbe { w: vec![1.0,0.0], tau: 0.9 },
            Box::new(FixedThermal(ThermalState::Nominal,PowerSource::Ac)),3,3,32).unwrap(), cancel)
    }
    fn attest() -> OpAttestor { OpAttestor::new(crate::manifest::ExecutionClass::SpeculativeOrRecurrentDepth,&[]) }
    fn actual_wipes(reports: &[WipeReport], count: usize) {
        assert_eq!(reports.len(), count, "every entered target plus the draft arena retains its real receipt");
        assert!(reports.iter().all(|report| report.bytes > 0 && report.residual == 0));
    }

    #[test]
    fn actual_speculation_success_preserves_accept_reject_bytes_and_transfers_only_final_output() {
        for (proposed, zeroed) in [(b'x',1),(b'z',6)] {
            let (gate,cancel) = gate(b"xxx", proposed, Mode::Normal); begin();
            let (result,reports) = gate.speculate_cancellable_with_wipes(PROMPT,3,2,&mut attest(),&cancel);
            let (output,rejected) = result.unwrap();
            assert_eq!(output,b"xxx"); assert_eq!(rejected,zeroed); assert_eq!(PROMPT,b"synthetic-context");
            actual_wipes(&reports,4); finish(PROMPT.len()+3,None,Some(3));
            assert_eq!(output,b"xxx", "successful allocation remains live and unchanged under caller ownership");
        }
        let (gate,cancel) = gate(b"", b'x', Mode::Normal); begin();
        let (result,reports) = gate.speculate_cancellable_with_wipes(PROMPT,0,1,&mut attest(),&cancel);
        assert_eq!(result.unwrap(),(vec![],0)); actual_wipes(&reports,1); finish(PROMPT.len(),None,Some(0));
    }

    #[test]
    fn actual_late_coda_error_scrubs_partial_output_and_extended_context() {
        let (gate,cancel) = gate(b"xxx", b'z', Mode::LateError); begin();
        let (result,reports) = gate.speculate_cancellable_with_wipes(PROMPT,3,1,&mut attest(),&cancel);
        assert!(result.unwrap_err().is("FIXTURE_SPECULATION_CODA"));
        actual_wipes(&reports,3); finish(PROMPT.len()+1,Some(1),None);
    }

    #[test]
    fn actual_mid_decode_cancellation_scrubs_earlier_output_and_context() {
        let (gate,cancel) = gate(b"xxx", b'z', Mode::LateCancel); begin();
        let (result,reports) = gate.speculate_cancellable_with_wipes(PROMPT,3,1,&mut attest(),&cancel);
        assert!(result.unwrap_err().is("GENERATION_CANCELLED"));
        actual_wipes(&reports,3); finish(PROMPT.len()+1,Some(1),None);
    }

    #[test]
    fn cancellation_during_actual_context_cleanup_still_withholds_and_scrubs_final_output() {
        let (gate,cancel) = gate(b"xxx", b'z', Mode::Normal); begin();
        CANCEL_ON_CONTEXT_SCRUB.with(|event| *event.borrow_mut() = Some(cancel.clone()));
        let (result,reports) = gate.speculate_cancellable_with_wipes(PROMPT,3,1,&mut attest(),&cancel);
        assert!(result.unwrap_err().is("GENERATION_CANCELLED")); actual_wipes(&reports,4);
        let events = EVENTS.with(|events| events.borrow_mut().take().unwrap());
        assert_eq!(events,vec![Event::Scrubbed("speculation_context",PROMPT.len()+3,true,true),
            Event::Scrubbed("speculation_output",3,true,true)]);
    }

    #[test]
    fn actual_final_output_guard_refusals_scrub_complete_output_and_context() {
        for (bytes, reason) in [(&b"CNRY_SEP_"[..],"CANARY_TRIPPED"),
            (&b"SSN 123-45-6789"[..],"UNREDACTED_PII_IN_OUTPUT")] {
            let (gate,cancel) = gate(bytes, b'z', Mode::Normal); begin();
            let (result,reports) = gate.speculate_cancellable_with_wipes(PROMPT,bytes.len(),1,&mut attest(),&cancel);
            assert!(result.unwrap_err().is(reason)); actual_wipes(&reports,bytes.len()+1);
            finish(PROMPT.len()+bytes.len(),Some(bytes.len()),None);
        }
    }

    #[test]
    fn actual_preflight_refusals_create_no_private_byte_owners_or_arena_receipts() {
        for (n,k,cancelled,reason) in [(3,1,true,"GENERATION_CANCELLED"),(33,1,false,"SPECULATION_BOUNDS"),
            (3,0,false,"SPECULATION_BOUNDS"),(usize::MAX,1,false,"SPECULATION_WORK_BUDGET")] {
            let (gate,cancel) = gate(b"xxx", b'z', Mode::Normal); cancel.store(cancelled,Ordering::SeqCst); begin();
            let (result,reports) = gate.speculate_cancellable_with_wipes(PROMPT,n,k,&mut attest(),&cancel);
            assert!(result.unwrap_err().is(reason)); assert!(reports.is_empty()); finish(0,None,None);
        }
    }
}

#[cfg(test)]
mod token_speculation_tests {
    use super::*;
    use std::sync::Mutex;

    /// Bytes `a`..`e` are tokens 1..=5, 0 ends. The target continues the
    /// cycle a b c d e a ... ; the draft proposes the cycle too but makes
    /// its second proposal of every round wrong, so each round accepts one
    /// draft, rejects the rest, and adds the target's own token.
    #[derive(Debug, Default)]
    struct Cycle {
        rounds: Mutex<usize>,
        end_after: Option<u32>,
    }
    fn next(t: u32) -> u32 { t % 5 + 1 }
    impl SpeculativeTokenModel for Cycle {
        fn encode(&self, bytes: &[u8]) -> EnclaveResult<Vec<u32>> { Ok(bytes.iter().map(|b| u32::from(b - b'a' + 1)).collect()) }
        fn token_bytes(&self, id: u32) -> EnclaveResult<&[u8]> { Ok(&b"abcde"[id as usize - 1..id as usize]) }
        fn is_end(&self, id: u32) -> bool { id == 0 }
        fn feature_width(&self) -> usize { 2 }
        fn verify(&self, ids: &[u32], tail: usize) -> EnclaveResult<(Vec<u32>, Vec<f32>)> {
            let preds = ids[ids.len() - tail..].iter()
                .map(|t| if Some(*t) == self.end_after { 0 } else { next(*t) }).collect();
            Ok((preds, vec![1.0; ids.len() * 2]))
        }
        fn draft(&self, ids: &[u32], features: &[f32], k: usize) -> EnclaveResult<Vec<u32>> {
            assert_eq!(features.len(), (ids.len() - 1) * 2, "features cover all but the newest token");
            *self.rounds.lock().unwrap() += 1;
            let mut last = *ids.last().unwrap();
            Ok((0..k).map(|i| { last = if i == 1 { 0 } else { next(last) }; last }).collect())
        }
    }
    impl DepthBackend for Cycle {
        fn width(&self) -> usize { 2 }
        fn prelude(&self, _: &[u8], _: &mut [f32]) -> EnclaveResult<()> { fail!(ENOSYS, "X") }
        fn core(&self, _: &mut [f32]) -> EnclaveResult<()> { fail!(ENOSYS, "X") }
        fn coda(&self, _: &[f32]) -> EnclaveResult<Vec<f32>> { fail!(ENOSYS, "X") }
        fn draft(&self, _: u8) -> u8 { 0 }
        fn token_model(&self) -> Option<&dyn SpeculativeTokenModel> { Some(self) }
    }
    fn gate(model: Cycle, thermal: ThermalState) -> DepthGate {
        DepthGate::speculative(Box::new(model), Box::new(FixedThermal(thermal, PowerSource::Ac)), 8, 4, 64).unwrap()
    }
    fn attest() -> OpAttestor { OpAttestor::new(crate::manifest::ExecutionClass::SpeculativeOrRecurrentDepth, &[]) }

    #[test]
    fn output_equals_greedy_target_and_rejected_drafts_are_counted() {
        let g = gate(Cycle::default(), ThermalState::Nominal);
        let (out, zeroed) = g.speculate(b"a", 9, 3, &mut attest()).unwrap();
        assert_eq!(out, b"bcdeabcde");
        // First token from the prefill, then rounds of (1 accepted + 1 target): 4 rounds, 2 rejected each.
        assert_eq!(zeroed, 8);
    }

    #[test]
    fn end_of_text_stops_and_thermal_state_bounds_or_refuses() {
        let g = gate(Cycle { end_after: Some(3), ..Default::default() }, ThermalState::Nominal);
        assert_eq!(g.speculate(b"a", 20, 3, &mut attest()).unwrap().0, b"bc");
        let g = gate(Cycle::default(), ThermalState::Critical);
        assert!(g.speculate(b"a", 4, 3, &mut attest()).unwrap_err().is("THERMAL_CRITICAL_YIELD"));
        let g = gate(Cycle::default(), ThermalState::Nominal);
        assert!(g.speculate(b"", 4, 3, &mut attest()).unwrap_err().is("SPECULATION_PROMPT_REQUIRED"));
        assert!(g.think(b"a", &mut attest()).unwrap_err().is("DEPTH_LOOP_UNSUPPORTED"));
        assert!(DepthGate::speculative(Box::new(ReferenceDepthStub), Box::new(FixedThermal(ThermalState::Nominal, PowerSource::Ac)), 8, 4, 64)
            .unwrap_err().is("SPECULATIVE_TOKEN_MODEL_REQUIRED"));
    }

    #[derive(Debug)]
    struct ReferenceDepthStub;
    impl DepthBackend for ReferenceDepthStub {
        fn width(&self) -> usize { 1 }
        fn prelude(&self, _: &[u8], _: &mut [f32]) -> EnclaveResult<()> { Ok(()) }
        fn core(&self, _: &mut [f32]) -> EnclaveResult<()> { Ok(()) }
        fn coda(&self, _: &[f32]) -> EnclaveResult<Vec<f32>> { Ok(vec![0.0; 256]) }
        fn draft(&self, _: u8) -> u8 { 0 }
    }
}
