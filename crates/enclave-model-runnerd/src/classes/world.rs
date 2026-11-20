//! Class 6 `JEPA_EBM_WORLD_PLANNER` (FS-701 §4.6): pre-encoder frame masking,
//! hard-wired `C_intrinsic = +∞` barrier over **resolved** DOM/AX targets,
//! clamped EBM energy (`NaN`/`±∞` cannot cancel the barrier), conformal OOD
//! halt, bounded CEM planning (`horizon <= 5`, `candidates <= 64`, `iters <=
//! 4`, `<= 150 ms`), quantized discrete actions, post-step surprise abort, and
//! actuation only through a sandboxed CDP browser pipe.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::arena::{finite, matvec, wipe_or_abort, Arena, WipeReport};
use crate::manifest::WorldPlannerCaps;
use crate::safetensors::TensorIndex;
use crate::topology::{OpAttestor, OpFamily};

/// Targets the barrier always denies (FS-701 §4.6.2, `F-026`).
pub const FORBIDDEN_BUNDLES: &[&str] = &[
    "com.enterprise.enclave.intent",
    "com.enterprise.enclave.oidc-broker",
    "com.apple.CoreAuthUI",
    "com.apple.systempreferences",
    "com.apple.Settings",
    "com.apple.keychainaccess",
    "com.apple.Terminal",
];

/// Planner target request. Browser facts must be read back before actuation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedTarget {
    /// App bundle id.
    pub app_bundle_id: String,
    /// AX role.
    pub ax_role: String,
    /// AX title.
    pub ax_title: String,
    /// Origin.
    pub url_origin: String,
    /// DOM selector.
    pub dom_selector: String,
}

impl ResolvedTarget {
    /// Hard-denied?
    pub fn forbidden(&self) -> bool {
        FORBIDDEN_BUNDLES.contains(&self.app_bundle_id.as_str())
            || self.ax_title.contains("_enclaveintent")
            || self.ax_title == "Keychain Access"
            || self.ax_title == "Terminal"
            || self.ax_title == "System Settings"
            || self.dom_selector == "#delete-repo"
    }
}

/// Quantized discrete action (zero raw floats on the wire).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    /// Authorised tool / AX action id (bit index in the micro-capability mask).
    pub tool_id: u8,
    /// Resolved target.
    pub target: ResolvedTarget,
    /// Parameters quantized to `1/64` steps in `[-1, 1]`.
    pub params_q: Vec<i8>,
}

/// Quantize continuous parameters (defeats sub-pixel / timing steganography).
pub fn quantize(params: &[f32]) -> Vec<i8> {
    params
        .iter()
        .map(|p| (p.clamp(-1.0, 1.0) * 64.0).round().clamp(-64.0, 64.0) as i8)
        .collect()
}

/// Policy for resolved targets (UID 704 Cedar in production).
pub trait TargetPolicy: Send + Sync + std::fmt::Debug {
    /// Allow?
    fn allow(&self, a: &Action) -> bool;
}

/// Bitmask over attenuated `B_micro` tool ids + allowed origins; forbidden
/// targets are denied regardless.
#[derive(Debug, Clone)]
pub struct MicroCapabilities {
    /// Bit `i` set ⇒ tool `i` allowed.
    pub tools: u64,
    /// Allowed URL origins.
    pub origins: Vec<String>,
}

impl TargetPolicy for MicroCapabilities {
    fn allow(&self, a: &Action) -> bool {
        a.tool_id < 64
            && self.tools >> a.tool_id & 1 == 1
            && !a.target.forbidden()
            && self.origins.contains(&a.target.url_origin)
    }
}

/// `E_total = clamp(C_EBM, ±E_max) + ∞·[¬allow] + ∞·[cone > τ]`.
pub fn total_energy(c_ebm: f32, allow: bool, cone: f32, tau_cone: f32, e_max: f32) -> f32 {
    if !allow || !cone.is_finite() || cone > tau_cone {
        return f32::INFINITY;
    }
    if c_ebm.is_nan() {
        return f32::INFINITY;
    }
    c_ebm.clamp(-e_max, e_max)
}

/// World model.
pub trait WorldModel: Send + Sync + std::fmt::Debug {
    /// Latent width.
    fn width(&self) -> usize;
    /// Encoder over a (masked) frame.
    fn encode(&self, frame: &Frame) -> EnclaveResult<Vec<f32>>;
    /// Predictor `s̃_{t+1} = P(s_t, a_t)`.
    fn predict(&self, s: &[f32], a: &Action) -> EnclaveResult<Vec<f32>>;
    /// Unnormalised EBM cost.
    fn cost(&self, s_next: &[f32], goal: &[f32]) -> f32;
    /// Safety-cone score of a predicted state.
    fn cone(&self, s_next: &[f32]) -> f32;
}

/// Grayscale frame.
#[derive(Clone, PartialEq)]
pub struct Frame {
    /// Width.
    pub w: usize,
    /// Height.
    pub h: usize,
    /// Pixels.
    pub px: Vec<u8>,
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Frame").field("w", &self.w).field("h", &self.h)
            .field("pixel_bytes", &self.px.len()).finish_non_exhaustive()
    }
}

impl Drop for Frame {
    fn drop(&mut self) {
        self.scrub_pixels();
        #[cfg(test)]
        frame_owner_tests::observe_before_deallocation(&self.px);
    }
}

/// Rectangle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rect {
    /// x.
    pub x: usize,
    /// y.
    pub y: usize,
    /// w.
    pub w: usize,
    /// h.
    pub h: usize,
}

impl Frame {
    fn scrub_pixels(&mut self) {
        for pixel in &mut self.px {
            // SAFETY: valid exclusively borrowed initialized pixel byte.
            unsafe { std::ptr::write_volatile(pixel, 0); }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
    /// Validate before any masking/indexing, including direct library callers.
    pub fn validate(&self) -> EnclaveResult<()> {
        if self.w == 0 || self.h == 0 || self.w.checked_mul(self.h) != Some(self.px.len()) {
            fail!(EINVAL, "FRAME_SHAPE");
        }
        Ok(())
    }
}

impl Rect {
    /// Checked half-open bounds; an out-of-frame or overflowing box is invalid.
    pub fn bounds(&self, frame: &Frame) -> EnclaveResult<(usize, usize)> {
        let right = self
            .x
            .checked_add(self.w)
            .ok_or_else(|| err!(EINVAL, "PII_RECT_BOUNDS"))?;
        let bottom = self
            .y
            .checked_add(self.h)
            .ok_or_else(|| err!(EINVAL, "PII_RECT_BOUNDS"))?;
        if self.w == 0 || self.h == 0 || right > frame.w || bottom > frame.h {
            fail!(EINVAL, "PII_RECT_BOUNDS");
        }
        Ok((right, bottom))
    }
}

/// Pre-encoder masking: union of AX bounds and in-frame detector boxes is
/// zeroed; during high-velocity scroll the whole frame is blurred to its mean.
pub fn mask_frame(
    f: &mut Frame,
    boxes: &[Rect],
    scroll_velocity: f32,
    max_velocity: f32,
) -> EnclaveResult<()> {
    f.validate()?;
    // Validate the entire request before mutating the frame, even on the blur path.
    for r in boxes {
        r.bounds(f)?;
    }
    if scroll_velocity > max_velocity {
        let mean = (f.px.iter().map(|p| *p as u64).sum::<u64>() / f.px.len().max(1) as u64) as u8;
        f.px.iter_mut().for_each(|p| *p = mean);
        return Ok(());
    }
    for r in boxes {
        let (right, bottom) = r.bounds(f)?;
        for y in r.y..bottom {
            for x in r.x..right {
                f.px[y * f.w + x] = 0;
            }
        }
    }
    Ok(())
}

/// Reference JEPA: `enclave_adapter.context_encoder.weight [d, 64]` over an
/// 8x8 average-pooled frame; `enclave_adapter.predictor.weight [d, d + 8]`
/// over `(s, action features)`; `enclave_adapter.ebm_cost_head.weight [d]`
/// (cost = `|w ⊙ (s - goal)|²`); `enclave_adapter.safety_cone.weight [d]`.
#[derive(Debug, Clone)]
pub struct ReferenceJepa {
    enc: Vec<f32>,
    pred: Vec<f32>,
    cost_w: Vec<f32>,
    cone_w: Vec<f32>,
    d: usize,
}

impl ReferenceJepa {
    /// Only the adapter heads (predictor, EBM cost, safety cone) over a
    /// latent of width `d` produced by some other encoder; `encode` refuses.
    pub fn heads(idx: &TensorIndex, file: &[u8], d: usize) -> EnclaveResult<Self> {
        let cone_w = idx.f32(file, "enclave_adapter.safety_cone.weight", &[d])?;
        crate::arena::validate_probe(&cone_w, d)?;
        Ok(Self {
            enc: Vec::new(),
            pred: idx.f32(file, "enclave_adapter.predictor.weight", &[d, d + 8])?,
            cost_w: idx.f32(file, "enclave_adapter.ebm_cost_head.weight", &[d])?,
            cone_w,
            d,
        })
    }

    /// Load.
    pub fn load(idx: &TensorIndex, file: &[u8]) -> EnclaveResult<Self> {
        let d = idx
            .shape("enclave_adapter.context_encoder.weight")
            .and_then(|s| s.first().copied())
            .ok_or_else(|| err!(EINVAL, "TENSOR_MISSING", "context_encoder"))?;
        let cone_w = idx.f32(file, "enclave_adapter.safety_cone.weight", &[d])?;
        crate::arena::validate_probe(&cone_w, d)?;
        Ok(Self {
            enc: idx.f32(file, "enclave_adapter.context_encoder.weight", &[d, 64])?,
            pred: idx.f32(file, "enclave_adapter.predictor.weight", &[d, d + 8])?,
            cost_w: idx.f32(file, "enclave_adapter.ebm_cost_head.weight", &[d])?,
            cone_w,
            d,
        })
    }
}

// Keep current initialized float allocations owned through fallible encoder,
// predictor, STM and planner operations. A successful return explicitly transfers its Vec to the caller;
// this does not certify earlier allocator copies or the caller's later cleanup.
struct SensitiveFloats(Vec<f32>);

impl SensitiveFloats {
    fn into_vec(mut self) -> Vec<f32> {
        std::mem::take(&mut self.0)
    }
}

impl std::ops::Deref for SensitiveFloats {
    type Target = [f32];
    fn deref(&self) -> &[f32] {
        &self.0
    }
}

impl std::ops::DerefMut for SensitiveFloats {
    fn deref_mut(&mut self) -> &mut [f32] {
        &mut self.0
    }
}

impl Drop for SensitiveFloats {
    fn drop(&mut self) {
        for value in &mut self.0 {
            // SAFETY: valid exclusively borrowed initialized float.
            unsafe { std::ptr::write_volatile(value, 0.0); }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        float_owner_tests::observe_before_deallocation(&self.0);
    }
}

fn pool8(f: &Frame) -> SensitiveFloats {
    let mut v = SensitiveFloats(vec![0f32; 64]);
    let (cw, ch) = (f.w.div_ceil(8).max(1), f.h.div_ceil(8).max(1));
    let mut n = SensitiveFloats(vec![0f32; 64]);
    for y in 0..f.h {
        for x in 0..f.w {
            let i = (y / ch).min(7) * 8 + (x / cw).min(7);
            v[i] += f.px[y * f.w + x] as f32 / 255.0;
            n[i] += 1.0;
        }
    }
    v.iter_mut().zip(n.iter()).for_each(|(a, c)| *a /= c.max(1.0));
    v
}

fn action_features(a: &Action) -> [f32; 8] {
    let mut f = [0f32; 8];
    f[0] = a.tool_id as f32 / 64.0;
    for (i, p) in a.params_q.iter().take(7).enumerate() {
        f[i + 1] = *p as f32 / 64.0;
    }
    f
}

impl WorldModel for ReferenceJepa {
    fn width(&self) -> usize {
        self.d
    }
    fn encode(&self, frame: &Frame) -> EnclaveResult<Vec<f32>> {
        if self.enc.is_empty() {
            fail!(ENOSYS, "WORLD_ENCODER_EXTERNAL");
        }
        let pooled = pool8(frame);
        let s = SensitiveFloats(matvec(&self.enc, self.d, 64, &pooled)?);
        finite(&s, "encoder")?;
        Ok(s.into_vec())
    }
    fn predict(&self, s: &[f32], a: &Action) -> EnclaveResult<Vec<f32>> {
        let columns = self.d.checked_add(8).ok_or_else(|| err!(EINVAL, "MATVEC_SHAPE"))?;
        if s.len() != self.d { fail!(EINVAL, "MATVEC_SHAPE"); }
        // Allocate the complete input before copying the latent. Growing a
        // secret-bearing Vec could otherwise leave an unwiped old allocation.
        let mut x = SensitiveFloats(Vec::with_capacity(columns));
        x.0.extend_from_slice(s);
        x.0.extend_from_slice(&action_features(a));
        let mut y = SensitiveFloats(matvec(&self.pred, self.d, columns, &x)?);
        for value in y.iter_mut() { *value = value.tanh(); }
        Ok(y.into_vec())
    }
    fn cost(&self, s: &[f32], goal: &[f32]) -> f32 {
        s.iter()
            .zip(goal)
            .zip(&self.cost_w)
            .map(|((a, g), w)| (w * (a - g)).powi(2))
            .sum()
    }
    fn cone(&self, s: &[f32]) -> f32 {
        s.iter().zip(&self.cone_w).map(|(a, b)| a * b).sum()
    }
}

/// Planner outcome.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    /// First action to execute.
    pub action: Action,
    /// Its predicted next state.
    pub predicted: Vec<f32>,
    /// Energy.
    pub energy: f32,
    /// Candidates vetoed by the intrinsic barrier.
    pub vetoes: u32,
}

/// The gate.
#[derive(Debug)]
pub struct WorldGate {
    model: Box<dyn WorldModel>,
    caps: WorldPlannerCaps,
    tau_cone: f32,
    /// Conformal `E_0.99`.
    e_alpha: f32,
    stm: Option<Arena>,
}

impl WorldGate {
    /// Bind.
    pub fn new(
        model: Box<dyn WorldModel>,
        caps: WorldPlannerCaps,
        tau_cone: f32,
        e_alpha: f32,
    ) -> EnclaveResult<Self> {
        if caps.max_horizon > 5
            || caps.max_candidates > 64
            || caps.max_cem_iters > 4
            || caps.step_wallclock_ms > 150
            || !(caps.e_max > 0.0 && caps.e_max <= 1000.0)
        {
            fail!(EACCES, "WORLD_PLANNER_CAPS");
        }
        if !(tau_cone.is_finite() && tau_cone > 0.0 && tau_cone < 1.0) {
            fail!(EINVAL, "SAFETY_CONE_THRESHOLD");
        }
        if !(e_alpha.is_finite() && e_alpha > 0.0) {
            fail!(EINVAL, "CONFORMAL_ENERGY_LUT");
        }
        Ok(Self {
            model,
            caps,
            tau_cone,
            e_alpha,
            stm: None,
        })
    }

    /// Encode an observation after pre-encoder masking.
    pub fn observe(
        &mut self,
        mut frame: Frame,
        pii_boxes: &[Rect],
        scroll_velocity: f32,
    ) -> EnclaveResult<Vec<f32>> {
        mask_frame(&mut frame, pii_boxes, scroll_velocity, 2000.0)?;
        let s = SensitiveFloats(self.model.encode(&frame)?);
        frame.scrub_pixels();
        // Episodic STM lives in its own CoW arena.
        let d = self.model.width();
        if self.stm.is_none() {
            self.stm = Some(Arena::floats(d)?);
        }
        if let Some(stm) = self.stm.as_mut() {
            stm.f32_mut()?[..d].copy_from_slice(&s);
        }
        Ok(s.into_vec())
    }

    /// CEM over the discrete candidate set; candidates are scored over the
    /// first-step energy with the barrier applied to every step's target.
    pub fn plan(
        &self,
        s: &[f32],
        goal: &[f32],
        candidates: &[Action],
        policy: &dyn TargetPolicy,
        attest: &mut OpAttestor,
    ) -> EnclaveResult<Plan> {
        attest.admit(OpFamily::JepaPredict)?;
        attest.admit(OpFamily::MpcRollout)?;
        if candidates.is_empty() || candidates.len() > self.caps.max_candidates as usize {
            fail!(E2BIG, "WORLD_PLANNER_CANDIDATES");
        }
        let start = Instant::now();
        let deadline = std::time::Duration::from_millis(self.caps.step_wallclock_ms as u64);
        let e_max = self.caps.e_max as f32;
        // Vectorised capability check first (bitmask), before any rollout.
        let allowed: Vec<bool> = candidates.iter().map(|a| policy.allow(a)).collect();
        let mut vetoes = allowed.iter().filter(|a| !**a).count() as u32;
        let mut elite: Vec<usize> = (0..candidates.len()).collect();
        let mut best: Option<(usize, f32, SensitiveFloats)> = None;
        for _iter in 0..self.caps.max_cem_iters {
            let mut scored: Vec<(usize, f32, SensitiveFloats)> = Vec::new();
            for &i in &elite {
                if start.elapsed() > deadline {
                    fail!(
                        ETIMEDOUT,
                        "PLANNER_DEADLINE",
                        "> {} ms",
                        self.caps.step_wallclock_ms
                    );
                }
                let a = &candidates[i];
                let mut st = SensitiveFloats(s.to_vec());
                let mut e_sum = 0f32;
                let mut first = None;
                for _h in 0..self.caps.max_horizon {
                    let nxt = SensitiveFloats(self.model.predict(&st, a)?);
                    let e = total_energy(
                        self.model.cost(&nxt, goal),
                        allowed[i],
                        self.model.cone(&nxt),
                        self.tau_cone,
                        e_max,
                    );
                    if first.is_none() {
                        first = Some(SensitiveFloats(nxt.to_vec()));
                    }
                    e_sum += e;
                    if !e.is_finite() {
                        break;
                    }
                    st = nxt;
                }
                if allowed[i] && !e_sum.is_finite() {
                    vetoes += 1;
                }
                scored.push((i, e_sum, first.unwrap_or_else(|| SensitiveFloats(Vec::new()))));
            }
            scored.sort_by(|a, b| a.1.total_cmp(&b.1));
            if let Some(top) = scored.first() {
                if best.as_ref().is_none_or(|b| top.1 < b.1) {
                    best = Some((top.0, top.1, SensitiveFloats(top.2.to_vec())));
                }
            }
            let keep = (scored.len() / 2).max(1);
            elite = scored.into_iter().take(keep).map(|x| x.0).collect();
            if elite.len() == 1 {
                break;
            }
        }
        let (i, energy, predicted) = best.ok_or_else(|| err!(EACCES, "NO_SAFE_ACTION"))?;
        if !energy.is_finite() {
            fail!(
                EACCES,
                "NO_SAFE_ACTION",
                "every candidate hit the C_intrinsic barrier"
            );
        }
        if energy / self.caps.max_horizon as f32 > self.e_alpha {
            fail!(EAGAIN, "ENERGY_OOD_HALT", "E > E_0.99");
        }
        Ok(Plan {
            action: candidates[i].clone(),
            predicted: predicted.into_vec(),
            energy,
            vetoes,
        })
    }

    /// Post-step surprise gate.
    pub fn surprise(&self, predicted: &[f32], observed: &[f32]) -> EnclaveResult<f32> {
        if predicted.len() != self.model.width() || observed.len() != self.model.width() {
            fail!(EINVAL, "WORLD_MODEL_SURPRISE_SHAPE");
        }
        finite(predicted, "surprise prediction")?;
        finite(observed, "surprise observation")?;
        let d = predicted
            .iter()
            .zip(observed)
            .map(|(a, b)| (a - b).powi(2))
            .sum::<f32>()
            .sqrt();
        if d > self.caps.tau_surprise as f32 {
            fail!(
                EAGAIN,
                "WORLD_MODEL_SURPRISE_ABORT",
                "‖Enc(x) - s̃‖ = {d:.3}"
            );
        }
        Ok(d)
    }

    /// Episode exit / sleep / lock / yank: wipe the STM arena.
    pub fn end_episode(&mut self) -> Option<WipeReport> {
        self.stm.take().map(|a| wipe_or_abort(&a))
    }
}

/// Actuator (no TCC Accessibility, no `CGEventPost`: the only implementation
/// drives a Seatbelt-confined browser over `--remote-debugging-pipe`).
pub trait Actuator {
    /// Execute an authorised action.
    fn execute(&mut self, a: &Action) -> EnclaveResult<()>;
    /// Prepare authenticated nonblocking transport outside the release serial.
    /// Implementations must explicitly support the absolute whole-action bound;
    /// arbitrary legacy `execute` implementations cannot enter the final gate.
    /// Bind and validate the action without dispatching any browser command.
    fn prepare_bounded(&mut self, _action: &Action, _deadline: Instant) -> EnclaveResult<()> {
        fail!(ENOSYS, "ACTUATOR_BOUNDED_UNSUPPORTED");
    }
    /// Consume the action bound by preparation, including every reply and both
    /// mouse events. No caller-controlled action encoding runs under the gate.
    /// Errors may follow an effect; callers must retain observation.
    fn execute_bounded(&mut self, _deadline: Instant) -> EnclaveResult<()> {
        fail!(ENOSYS, "ACTUATOR_BOUNDED_UNSUPPORTED");
    }
    /// Discard prepared transport after a gate refusal or uncertain failure.
    fn cancel_bounded(&mut self) {}
}

/// Caller-controlled scans/parsing/JSON escaping occur during preparation, before
/// service serialization. Reuse the existing IPC/frame ceiling, including direct
/// library calls which have not passed through core's wire-frame admission.
#[derive(Debug)]
struct PreparedCdpAction {
    origin: url::Origin,
    selector_json: Vec<u8>,
}
impl PreparedCdpAction {
    fn new(action: &Action) -> EnclaveResult<Self> {
        let target = &action.target;
        let total = [target.app_bundle_id.len(), target.ax_role.len(), target.ax_title.len(),
            target.url_origin.len(), target.dom_selector.len(), action.params_q.len()]
            .into_iter().try_fold(0usize, usize::checked_add);
        if total.is_none_or(|size| size > enclave_core::ipc::MAX_FRAME) {
            fail!(E2BIG, "CDP_ACTION_TOO_LARGE");
        }
        if target.forbidden() { fail!(EACCES, "ACTUATION_TARGET_FORBIDDEN"); }
        if action.tool_id != 1 { fail!(EACCES, "ACTUATION_TOOL_UNSUPPORTED"); }
        let expected = url::Url::parse(&target.url_origin)
            .map_err(|_| err!(EACCES, "ACTUATION_ORIGIN_INVALID"))?;
        if !matches!(expected.scheme(), "http" | "https")
            || expected.as_str() != format!("{}/", expected.origin().ascii_serialization()) {
            fail!(EACCES, "ACTUATION_ORIGIN_MISMATCH");
        }
        let selector_json = serde_json::to_vec(&target.dom_selector).map_err(|_| err!(EIO, "CDP_ENCODE"))?;
        // Maximum-width request IDs and node IDs give the exact worst-case
        // framing overhead for this one caller-controlled encoded parameter.
        let overhead = format!("{{\"id\":{},\"method\":\"DOM.querySelector\",\"params\":{{\"nodeId\":{},\"selector\":}}}}\0", u64::MAX, u64::MAX).len();
        if selector_json.len().checked_add(overhead).is_none_or(|size| size > enclave_core::ipc::MAX_FRAME) {
            fail!(E2BIG, "CDP_FRAME_TOO_LARGE");
        }
        Ok(Self { origin: expected.origin(), selector_json })
    }
}

fn check_cdp_deadline(deadline: Option<Instant>) -> EnclaveResult<()> {
    if deadline.is_some_and(|end| Instant::now() >= end) {
        fail!(ETIMEDOUT, "CDP_DEADLINE");
    }
    Ok(())
}

fn cdp_retry(deadline: Option<Instant>, error: &std::io::Error) -> EnclaveResult<bool> {
    check_cdp_deadline(deadline)?;
    match error.kind() {
        std::io::ErrorKind::Interrupted => Ok(true),
        std::io::ErrorKind::WouldBlock if deadline.is_some() => {
            let left = deadline.unwrap().saturating_duration_since(Instant::now());
            std::thread::sleep(left.min(Duration::from_millis(1)));
            check_cdp_deadline(deadline)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// Chrome DevTools Protocol over the pipe transport (NUL-delimited JSON on
/// fds 3/4 of the sandboxed browser).
#[derive(Debug)]
pub struct CdpPipeDriver<W: Write, R: Read> {
    w: W,
    r: R,
    id: u64,
    buf: Vec<u8>,
    // Set only by the concrete authenticated nonblocking socket actuator.
    deadline: Option<Instant>,
}

impl<W: Write, R: Read> CdpPipeDriver<W, R> {
    /// Wrap the pipe ends.
    pub fn new(w: W, r: R) -> Self {
        Self {
            w,
            r,
            id: 0,
            buf: Vec::new(),
            deadline: None,
        }
    }

    fn check_origin(&mut self, expected: &url::Origin) -> EnclaveResult<()> {
        let frame = self.call("Page.getFrameTree", json!({}))?;
        let actual = frame["frameTree"]["frame"]["url"]
            .as_str()
            .ok_or_else(|| err!(EACCES, "ACTUATION_ORIGIN_MISSING"))?;
        let actual =
            url::Url::parse(actual).map_err(|_| err!(EACCES, "ACTUATION_ORIGIN_INVALID"))?;
        if !matches!(actual.scheme(), "http" | "https")
            || &actual.origin() != expected
        {
            fail!(EACCES, "ACTUATION_ORIGIN_MISMATCH");
        }
        Ok(())
    }

    fn call(&mut self, method: &str, params: Value) -> EnclaveResult<Value> {
        // All uses here have fixed-size parameters obtained from bounded CDP
        // replies. The caller-controlled selector is encoded before the gate.
        let params = serde_json::to_vec(&params).map_err(|_| err!(EIO, "CDP_ENCODE"))?;
        self.call_parts(method, &[&params])
    }

    fn call_parts(&mut self, method: &str, params: &[&[u8]]) -> EnclaveResult<Value> {
        check_cdp_deadline(self.deadline)?;
        self.id = self.id.checked_add(1).ok_or_else(|| err!(EIO, "CDP_ID_EXHAUSTED"))?;
        let id = self.id;
        // Method names are private fixed literals; IDs are bounded integers.
        let header = format!("{{\"id\":{id},\"method\":\"{method}\",\"params\":");
        let size = params.iter().try_fold(header.len() + 2, |size, part| size.checked_add(part.len()));
        if size.is_none_or(|size| size > enclave_core::ipc::MAX_FRAME) { fail!(E2BIG, "CDP_FRAME_TOO_LARGE"); }
        for part in std::iter::once(header.as_bytes()).chain(params.iter().copied()).chain(std::iter::once(b"}\0".as_slice())) {
            let mut offset = 0;
            while offset < part.len() {
                check_cdp_deadline(self.deadline)?;
                match self.w.write(&part[offset..]) {
                    Ok(0) => fail!(EIO, "CDP_WRITE"),
                    Ok(n) => offset += n,
                    Err(error) if cdp_retry(self.deadline, &error)? => continue,
                    Err(error) => return Err(err!(EIO, "CDP_WRITE", "{error}")),
                }
            }
        }
        loop {
            check_cdp_deadline(self.deadline)?;
            match self.w.flush() {
                Ok(()) => break,
                Err(error) if cdp_retry(self.deadline, &error)? => continue,
                Err(error) => return Err(err!(EIO, "CDP_WRITE", "{error}")),
            }
        }
        loop {
            check_cdp_deadline(self.deadline)?;
            while let Some(p) = self.buf.iter().position(|b| *b == 0) {
                check_cdp_deadline(self.deadline)?;
                let frame: Vec<u8> = self.buf.drain(..=p).collect();
                let v: Value = serde_json::from_slice(&frame[..frame.len() - 1])
                    .map_err(|e| err!(EIO, "CDP_DECODE", "{e}"))?;
                check_cdp_deadline(self.deadline)?;
                if v["id"].as_u64() == Some(id) {
                    if let Some(e) = v.get("error") {
                        fail!(EIO, "CDP_ERROR", "{e}");
                    }
                    return Ok(v["result"].clone());
                }
            }
            let mut chunk = [0u8; 4096];
            let n = match self.r.read(&mut chunk) {
                Ok(n) => n,
                Err(error) if cdp_retry(self.deadline, &error)? => continue,
                Err(error) => return Err(err!(EIO, "CDP_READ", "{error}")),
            };
            check_cdp_deadline(self.deadline)?;
            if n == 0 { fail!(EIO, "CDP_CLOSED"); }
            if self.buf.len() + n > 1 << 20 { fail!(E2BIG, "CDP_FRAME_TOO_LARGE"); }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

impl<W: Write, R: Read> CdpPipeDriver<W, R> {
    fn execute_prepared(&mut self, a: &PreparedCdpAction) -> EnclaveResult<()> {
        check_cdp_deadline(self.deadline)?;
        self.check_origin(&a.origin)?;
        // Read the tree so equivalent selectors and descendants of forbidden
        // nodes receive the same decision. Large/incomplete trees deny safely.
        let doc = self.call("DOM.getDocument", json!({"depth": -1}))?;
        let root = doc["root"]["nodeId"]
            .as_u64()
            .ok_or_else(|| err!(EIO, "CDP_DOM"))?;
        let prefix = format!("{{\"nodeId\":{root},\"selector\":");
        let q = self.call_parts("DOM.querySelector", &[prefix.as_bytes(), &a.selector_json, b"}"])?;
        let node = q["nodeId"]
            .as_u64()
            .filter(|n| *n != 0)
            .ok_or_else(|| err!(EACCES, "CDP_TARGET_NOT_FOUND"))?;
        let mut descendants = Vec::new();
        fn walk(v: &Value, wanted: u64, denied: bool, inside: bool, out: &mut Vec<u64>, deadline: Option<Instant>) -> EnclaveResult<bool> {
            check_cdp_deadline(deadline)?;
            let bad_id = v["attributes"].as_array().is_some_and(|attrs| {
                attrs
                    .chunks_exact(2)
                    .any(|p| p[0] == "id" && p[1] == "delete-repo")
            });
            let denied = denied || bad_id;
            let selected = v["nodeId"].as_u64() == Some(wanted);
            if selected && denied {
                return Ok(false);
            }
            let inside = inside || selected;
            if inside && !denied {
                if let Some(id) = v["backendNodeId"].as_u64() {
                    out.push(id);
                }
            }
            if let Some(children) = v["children"].as_array() {
                for c in children {
                    if !walk(c, wanted, denied, inside, out, deadline)? {
                        return Ok(false);
                    }
                }
            }
            Ok(true)
        }
        if !walk(&doc["root"], node, false, false, &mut descendants, self.deadline)? || descendants.is_empty() {
            fail!(EACCES, "ACTUATION_NODE_FORBIDDEN_OR_STALE");
        }
        let bm = self.call("DOM.getBoxModel", json!({"nodeId": node}))?;
        let quad: Vec<f64> = bm["model"]["content"]
            .as_array()
            .ok_or_else(|| err!(EIO, "CDP_BOX"))?
            .iter()
            .filter_map(Value::as_f64)
            .collect();
        if quad.len() != 8 || quad.iter().any(|v| !v.is_finite()) {
            fail!(EIO, "CDP_BOX");
        }
        let (x, y) = (
            (quad[0] + quad[2] + quad[4] + quad[6]) / 4.0,
            (quad[1] + quad[3] + quad[5] + quad[7]) / 4.0,
        );
        if !x.is_finite()
            || !y.is_finite()
            || x.abs() > i32::MAX as f64
            || y.abs() > i32::MAX as f64
        {
            fail!(EIO, "CDP_BOX");
        }
        let hit = self.call("DOM.getNodeForLocation", json!({"x": x.round() as i32, "y": y.round() as i32, "includeUserAgentShadowDOM": true}))?;
        if !hit["backendNodeId"]
            .as_u64()
            .is_some_and(|id| descendants.contains(&id))
        {
            fail!(EACCES, "ACTUATION_OCCLUDED_OR_STALE");
        }
        self.check_origin(&a.origin)?;
        for t in ["mousePressed", "mouseReleased"] {
            self.call("Input.dispatchMouseEvent", json!({"type": t, "x": x.round(), "y": y.round(), "button": "left", "clickCount": 1}))?;
        }
        Ok(())
    }
}

// The generic fixture path deliberately does not implement bounded admission:
// arbitrary Read/Write may block, even though its action encoding is capped.
impl<W: Write, R: Read> Actuator for CdpPipeDriver<W, R> {
    fn execute(&mut self, action: &Action) -> EnclaveResult<()> {
        self.execute_prepared(&PreparedCdpAction::new(action)?)
    }
}

/// Actuator that connects lazily to the sandboxed CDP browser Unix domain socket (GAP-34).
#[derive(Debug)]
pub struct CdpSocketActuator {
    socket_path: PathBuf,
    driver: Option<CdpPipeDriver<UnixStream, UnixStream>>,
    expected_uid: u32,
    prepared_deadline: Option<Instant>,
    prepared_action: Option<PreparedCdpAction>,
}

impl CdpSocketActuator {
    /// Create a new actuator pointing to the browser socket path.
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            driver: None,
            expected_uid: enclave_core::daemon::BROWSER_UID,
            prepared_deadline: None,
            prepared_action: None,
        }
    }

    /// Explicit development/test override; production pins the browser daemon UID.
    pub fn with_expected_uid(mut self, uid: u32) -> Self {
        self.expected_uid = uid;
        self
    }

    fn discard(&mut self) {
        self.prepared_deadline = None;
        self.prepared_action = None;
        if let Some(driver) = self.driver.take() {
            // Cloned descriptors share a socket; shut down both explicitly so
            // neither handle nor a timed-out partial request can be reused.
            let _ = driver.w.shutdown(std::net::Shutdown::Both);
            let _ = driver.r.shutdown(std::net::Shutdown::Both);
        }
    }
}

impl Actuator for CdpSocketActuator {
    fn execute(&mut self, a: &Action) -> EnclaveResult<()> {
        let deadline = Instant::now() + enclave_core::ipc::RELEASE_TIMEOUT;
        self.prepare_bounded(a, deadline)?;
        self.execute_bounded(deadline)
    }

    fn prepare_bounded(&mut self, action: &Action, deadline: Instant) -> EnclaveResult<()> {
        let result = (|| {
            // Repeated preparation cannot extend an already prepared action.
            let deadline = self.prepared_deadline.map_or(deadline, |old| old.min(deadline));
            check_cdp_deadline(Some(deadline))?;
            let prepared_action = PreparedCdpAction::new(action)?;
            check_cdp_deadline(Some(deadline))?;
            if self.driver.is_none() {
                let code = (self.expected_uid == enclave_core::daemon::BROWSER_UID)
                    .then(enclave_core::codesign::CodeRequirement::browser);
                let client = enclave_core::ipc::Client::connect_verified_deadline(
                    &self.socket_path, self.expected_uid, code.as_ref(),
                    deadline.saturating_duration_since(Instant::now()),
                ).map_err(|error| {
                    if error.is("SERVER_UID_MISMATCH") { err!(EACCES, "BROWSER_PEER_UID_MISMATCH") }
                    else { error }
                })?;
                check_cdp_deadline(Some(deadline))?;
                let stream = client.into_authenticated_stream();
                stream.set_nonblocking(true).map_err(|e| err!(EIO, "BROWSER_NONBLOCKING", "{e}"))?;
                let reader = stream.try_clone().map_err(|e| err!(EIO, "BROWSER_STREAM_CLONE", "{e}"))?;
                self.driver = Some(CdpPipeDriver::new(stream, reader));
            }
            self.driver.as_mut().unwrap().deadline = Some(deadline);
            self.prepared_deadline = Some(deadline);
            self.prepared_action = Some(prepared_action);
            check_cdp_deadline(Some(deadline))
        })();
        if result.is_err() { self.discard(); }
        result
    }

    fn cancel_bounded(&mut self) { self.discard(); }

    fn execute_bounded(&mut self, deadline: Instant) -> EnclaveResult<()> {
        let result = (|| {
            let prepared = self.prepared_deadline.take().ok_or_else(|| err!(EACCES, "ACTUATOR_NOT_PREPARED"))?;
            let deadline = prepared.min(deadline);
            check_cdp_deadline(Some(deadline))?;
            let driver = self.driver.as_mut().ok_or_else(|| err!(EACCES, "ACTUATOR_NOT_PREPARED"))?;
            driver.deadline = Some(deadline);
            let action = self.prepared_action.take().ok_or_else(|| err!(EACCES, "ACTUATOR_NOT_PREPARED"))?;
            driver.execute_prepared(&action)?;
            check_cdp_deadline(Some(deadline))
        })();
        if result.is_err() { self.discard(); }
        result
    }
}

#[cfg(test)]
mod float_owner_tests {
    use super::*;
    use std::cell::RefCell;

    thread_local! {
        static OBSERVED: RefCell<Option<Vec<(usize, bool)>>> = const { RefCell::new(None) };
    }

    // Only inspect initialized elements while the Vec is still owned. This
    // observer is absent from production and never reads freed allocations.
    pub(super) fn observe_before_deallocation(values: &[f32]) {
        if !values.is_empty() {
            OBSERVED.with(|observed| {
                if let Some(records) = observed.borrow_mut().as_mut() {
                    records.push((values.len(), values.iter().all(|v| v.to_bits() == 0)));
                }
            });
        }
    }

    fn begin() {
        OBSERVED.with(|observed| *observed.borrow_mut() = Some(Vec::new()));
    }

    fn finish() -> Vec<(usize, bool)> {
        OBSERVED.with(|observed| observed.borrow_mut().take().unwrap())
    }

    fn model() -> ReferenceJepa {
        let mut enc = vec![0.0; 128];
        enc[0] = 1.0;
        enc[65] = 2.0;
        ReferenceJepa { enc, pred: vec![], cost_w: vec![1.0; 2], cone_w: vec![1.0; 2], d: 2 }
    }

    #[test]
    fn yk11_actual_encoder_scrubs_pool_on_success_and_matvec_failure() {
        let frame = Frame { w: 8, h: 8, px: vec![91; 64] };
        let mut model = model();
        begin();
        let encoded = model.encode(&frame).unwrap();
        // Successful transfer preserves the exact caller-owned result.
        assert_eq!(encoded, vec![91.0 / 255.0, 182.0 / 255.0]);
        assert_eq!(finish(), vec![(64, true), (64, true)]);
        drop(SensitiveFloats(encoded));

        model.enc.pop();
        begin();
        assert!(model.encode(&frame).unwrap_err().is("MATVEC_SHAPE"));
        assert_eq!(finish(), vec![(64, true), (64, true)]);
    }

    #[test]
    fn yk11_actual_encoder_scrubs_nonfinite_result_before_refusal() {
        let frame = Frame { w: 8, h: 8, px: vec![91; 64] };
        let mut model = model();
        model.enc[0] = f32::NAN;
        begin();
        assert!(model.encode(&frame).unwrap_err().is("NON_FINITE_ACTIVATION"));
        assert_eq!(finish(), vec![(64, true), (2, true), (64, true)]);
    }

    #[test]
    fn yk11_actual_observe_scrubs_latent_when_stm_is_read_only() {
        let mut gate = WorldGate::new(
            Box::new(model()),
            WorldPlannerCaps { max_horizon: 1, max_candidates: 1, max_cem_iters: 1,
                e_max: 1.0, step_wallclock_ms: 100, tau_surprise: 1.0, actuation_sandbox: None },
            0.5, 1.0,
        ).unwrap();
        let stm = Arena::floats(2).unwrap();
        stm.seal_read_only().unwrap();
        gate.stm = Some(stm);
        begin();
        let result = gate.observe(Frame { w: 8, h: 8, px: vec![91; 64] }, &[], 0.0);
        assert!(result.unwrap_err().is("GUARDED_REGION_FROZEN"));
        assert_eq!(finish(), vec![(64, true), (64, true), (2, true)]);
    }

    #[test]
    fn yk11_actual_predictor_scrubs_complete_input_on_success_and_shape_error() {
        let mut model = model();
        model.pred = vec![0.0; 20];
        model.pred[0] = 0.5;
        model.pred[11] = -1.0;
        let latent = [2.0, 3.0];
        begin();
        let predicted = model.predict(&latent, &action(1)).unwrap();
        assert_eq!(predicted, vec![1.0f32.tanh(), (-3.0f32).tanh()]);
        assert_eq!(latent, [2.0, 3.0], "borrowed caller input is unchanged");
        assert_eq!(finish(), vec![(10, true)]);
        drop(SensitiveFloats(predicted));

        model.pred.pop();
        begin();
        assert!(model.predict(&latent, &action(1)).unwrap_err().is("MATVEC_SHAPE"));
        assert_eq!(finish(), vec![(10, true)]);
    }

    fn action(tool_id: u8) -> Action {
        Action { tool_id, target: ResolvedTarget { app_bundle_id:"com.example.browser".into(),
            ax_role:"button".into(), ax_title:"fixture".into(), url_origin:"https://example.test".into(),
            dom_selector:"#fixture".into() }, params_q:vec![1] }
    }
    fn policy(tools: u64) -> MicroCapabilities {
        MicroCapabilities {tools,origins:vec!["https://example.test".into()]}
    }
    #[derive(Debug)]
    struct Predictor {
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        fail_at: usize,
        slow_at: usize,
    }
    impl WorldModel for Predictor {
        fn width(&self) -> usize { 2 }
        fn encode(&self, _: &Frame) -> EnclaveResult<Vec<f32>> { fail!(EIO,"ENCODER_UNUSED"); }
        fn predict(&self, s: &[f32], a: &Action) -> EnclaveResult<Vec<f32>> {
            assert_eq!(s.len(),2);
            let call = self.calls.fetch_add(1,std::sync::atomic::Ordering::SeqCst)+1;
            if call == self.fail_at { fail!(EIO,"PREDICTOR_FIXTURE_FAILURE"); }
            if call == self.slow_at { std::thread::sleep(std::time::Duration::from_millis(3)); }
            Ok(vec![a.tool_id as f32,call as f32])
        }
        fn cost(&self, next: &[f32], _: &[f32]) -> f32 { next[0]/(next[1]+1.0) }
        fn cone(&self, _: &[f32]) -> f32 { 0.0 }
    }
    fn planner(fail_at: usize, slow_at: usize, step_ms: u32, e_alpha: f32)
        -> (WorldGate, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let model = Predictor {calls:calls.clone(),fail_at,slow_at};
        let gate = WorldGate::new(Box::new(model),WorldPlannerCaps {
            max_horizon:2,max_candidates:4,max_cem_iters:2,e_max:10.0,
            step_wallclock_ms:step_ms,tau_surprise:1.0,actuation_sandbox:None },0.5,e_alpha).unwrap();
        (gate,calls)
    }
    fn attest() -> OpAttestor {
        OpAttestor::new(crate::manifest::ExecutionClass::JepaEbmWorldPlanner,&[])
    }

    #[test]
    fn yk11_actual_planner_scrubs_rollouts_scored_and_replaced_best_then_transfers_result() {
        let (gate,calls) = planner(0,0,150,10.0);
        let candidates = [action(4),action(3),action(2),action(1)];
        let latent = [0.25,-0.5]; let goal = [0.75,0.5];
        begin();
        let plan = gate.plan(&latent,&goal,&candidates,&policy(u64::MAX),&mut attest()).unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst),12);
        assert_eq!(plan.action.tool_id,1);
        assert_eq!(plan.predicted,vec![1.0,9.0],"fresh best result transfers intact");
        assert_eq!(latent,[0.25,-0.5]); assert_eq!(goal,[0.75,0.5]);
        // Includes first-iteration best replacement, all scored copies and
        // every initial/intermediate rollout. The transferred Vec stays live.
        assert_eq!(finish(),vec![(2,true);25]);
        drop(SensitiveFloats(plan.predicted));
    }

    #[test]
    fn yk11_actual_planner_predictor_error_scrubs_existing_best_scored_and_current_rollout() {
        let (gate,calls) = planner(12,0,150,10.0);
        begin();
        let error = gate.plan(&[0.25,-0.5],&[0.75,0.5],
            &[action(4),action(3),action(2),action(1)],&policy(u64::MAX),&mut attest()).unwrap_err();
        assert!(error.is("PREDICTOR_FIXTURE_FAILURE"));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst),12);
        assert_eq!(finish(),vec![(2,true);24]);
    }

    #[test]
    fn yk11_actual_planner_barrier_ood_and_loop_deadline_scrub_unreturned_predictions() {
        for (tools,threshold,slow_at,step_ms,reason,owners) in [
            (0,10.0,0,150,"NO_SAFE_ACTION",4),
            (u64::MAX,0.01,0,150,"ENERGY_OOD_HALT",5),
            (u64::MAX,10.0,1,1,"PLANNER_DEADLINE",4),
        ] {
            let (gate,_) = planner(0,slow_at,step_ms,threshold);
            let candidates = if slow_at==0 {vec![action(1)]} else {vec![action(1),action(2)]};
            begin();
            let error = gate.plan(&[0.25,-0.5],&[0.75,0.5],&candidates,&policy(tools),&mut attest()).unwrap_err();
            assert!(error.is(reason),"expected {reason}, got {error:?}");
            assert_eq!(finish(),vec![(2,true);owners],"{reason}");
        }
    }
}

#[cfg(test)]
mod frame_owner_tests {
    use super::*;
    use std::cell::RefCell;
    thread_local! {static OBSERVED:RefCell<Option<(usize,bool)>>=const{RefCell::new(None)};}
    // Test-only observation before Vec deallocation. No freed-memory reads or
    // production observer/allocator override; this is software owner evidence.
    pub(super) fn observe_before_deallocation(bytes:&[u8]) {
        OBSERVED.with(|observed|{if let Some((count,zero))=observed.borrow_mut().as_mut(){*count+=1;*zero&=bytes.iter().all(|byte|*byte==0);}});
    }
    #[derive(Debug)]
    struct Encoder {fail:bool}
    impl WorldModel for Encoder {
        fn width(&self)->usize{1}
        fn encode(&self,frame:&Frame)->EnclaveResult<Vec<f32>> {
            assert_eq!(frame.px,vec![91;4]);
            if self.fail {fail!(EIO,"SYNTHETIC_ENCODER_FAILURE");}Ok(vec![0.5])
        }
        fn predict(&self,s:&[f32],_:&Action)->EnclaveResult<Vec<f32>>{Ok(s.to_vec())}
        fn cost(&self,_:&[f32],_:&[f32])->f32{0.0}
        fn cone(&self,_:&[f32])->f32{0.0}
    }
    fn gate(fail:bool)->WorldGate {
        WorldGate::new(Box::new(Encoder{fail}),WorldPlannerCaps{max_horizon:1,max_candidates:1,max_cem_iters:1,e_max:1.0,step_wallclock_ms:100,tau_surprise:1.0,actuation_sandbox:None},0.5,1.0).unwrap()
    }
    #[test]
    fn yk29_explicit_oidc_broker_target_is_denied_even_with_matching_origin_and_tool() {
        let mut action=Action{tool_id:1,target:ResolvedTarget{app_bundle_id:"com.example.browser".into(),ax_role:"AXButton".into(),ax_title:"Continue".into(),url_origin:"https://example.test".into(),dom_selector:"#continue".into()},params_q:vec![]};
        let policy=MicroCapabilities{tools:2,origins:vec!["https://example.test".into()]};
        assert!(policy.allow(&action));
        action.target.app_bundle_id="com.enterprise.enclave.oidc-broker".into();
        assert!(action.target.forbidden());assert!(!policy.allow(&action));
    }

    #[test]
    fn yk11_actual_world_observe_scrubs_frame_before_free_on_success_and_both_error_paths() {
        for mode in 0..3 {
            OBSERVED.with(|observed|*observed.borrow_mut()=Some((0,true)));
            let frame=Frame{w:2,h:2,px:vec![91;4]};
            assert!(!format!("{frame:?}").contains("91"),"debug must not emit raw pixels");
            let mut gate=gate(mode==1);
            let invalid=[Rect{x:2,y:0,w:1,h:1}];
            let result=gate.observe(frame,if mode==2{&invalid}else{&[]},0.0);
            match mode {0=>assert_eq!(result.unwrap(),vec![0.5]),1=>assert!(result.unwrap_err().is("SYNTHETIC_ENCODER_FAILURE")),_=>assert!(result.is_err()),}
            let observed=OBSERVED.with(|observed|observed.borrow_mut().take().unwrap());
            assert_eq!(observed,(1,true),"actual owned frame must scrub before its allocation is released");
        }
    }
}

#[cfg(test)]
mod bounded_driver_tests {
    use super::*;
    #[test]
    fn generic_unbounded_driver_cannot_opt_into_service_gate_and_id_never_wraps() {
        let mut output = Vec::new();
        let mut driver = CdpPipeDriver::new(&mut output, std::io::Cursor::new(Vec::<u8>::new()));
        assert!(driver.prepare_bounded(&Action { tool_id: 1, params_q: vec![], target: ResolvedTarget { app_bundle_id: String::new(), ax_role: String::new(), ax_title: String::new(), url_origin: "https://example.invalid".into(), dom_selector: "#ok".into() } }, Instant::now() + Duration::from_secs(1)).unwrap_err().is("ACTUATOR_BOUNDED_UNSUPPORTED"));
        driver.id = u64::MAX;
        assert!(driver.call("Page.getFrameTree", json!({})).unwrap_err().is("CDP_ID_EXHAUSTED"));
        assert!(output.is_empty());
    }
}
