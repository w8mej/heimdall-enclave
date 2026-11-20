//! `mlx_vjepa2_v1` artifact format and its native-worker world-model backend.
//!
//! One safetensors file holds the publisher's V-JEPA 2 tensors unchanged
//! (encoder and predictor; the worker reads only the encoder) plus the
//! planner's adapter heads over the encoder's pooled latent:
//! - `enclave_adapter.predictor.weight [d, d + 8]` = `[I | A]`: the state
//!   persists and each action feature shifts it along a fixed direction
//! - `enclave_adapter.ebm_cost_head.weight [d]` = `1/sqrt(d)`: cost is the
//!   mean squared latent distance to the goal frame's latent
//! - `enclave_adapter.safety_cone.weight [d]`: a fixed unit direction x 0.1
//! - `enclave_adapter.conformal_energy_lut [1]`
//! These heads are deterministic and UNCALIBRATED: the published checkpoint
//! is the self-supervised video model, which has no action-conditioned
//! dynamics (that is V-JEPA 2-AC, trained on robot end-effector actions).
//! A trained UI-action head is beta work. Metadata: backend, the closed
//! encoder config and the cone threshold.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::runtime::{receive, send, spawn_native, Worker};
use crate::classes::world::{Action, Frame, ReferenceJepa, WorldModel};
use crate::safetensors::TensorIndex;
use crate::topology::{OpAttestor, OpFamily};

/// Backend identifier in artifact metadata.
pub const BACKEND: &str = "mlx_vjepa2_v1";
/// Metadata key for the encoder config.
pub const CONFIG_KEY: &str = "enclave_adapter.vjepa2.config";
const LOAD_DEADLINE: Duration = Duration::from_secs(180);
const ENCODE_DEADLINE: Duration = Duration::from_secs(30);
/// Strength of each action feature's latent shift in the adapter predictor.
const ACTION_SCALE: f32 = 0.05;
/// Length of the adapter safety-cone direction.
const CONE_SCALE: f32 = 0.1;
/// Per-step energy bound above which the planner halts as out of distribution.
const CONFORMAL_ENERGY: f32 = 50.0;
const CONE_TAU: &str = "0.9";

/// Closed encoder geometry understood by the worker's `vjepa2-v1` graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VjepaConfig {
    /// Latent width.
    pub hidden: usize,
    /// Encoder blocks.
    pub layers: usize,
    /// Attention heads.
    pub heads: usize,
    /// MLP width.
    pub mlp: usize,
    /// Patch side.
    pub patch: usize,
    /// Frames per tubelet.
    pub tubelet: usize,
    /// Input side in pixels.
    pub image: usize,
    /// LayerNorm epsilon.
    pub eps: f32,
}

impl VjepaConfig {
    /// Derive from the publisher `config.json`, refusing other variants.
    pub fn from_hf(config_json: &str) -> EnclaveResult<Self> {
        let c: Value =
            serde_json::from_str(config_json).map_err(|_| err!(EINVAL, "VJEPA2_CONFIG_JSON"))?;
        let unsupported = c["model_type"] != "vjepa2"
            || c["hidden_act"] != "gelu"
            || c["qkv_bias"] != true
            || c["use_SiLU"] == true
            || c["in_chans"] != 3
            || c["crop_size"] != c["image_size"];
        if unsupported {
            fail!(EINVAL, "VJEPA2_CONFIG_UNSUPPORTED");
        }
        let field = |k: &str| {
            c[k].as_u64()
                .filter(|v| (1..=1 << 16).contains(v))
                .map(|v| v as usize)
                .ok_or_else(|| err!(EINVAL, "VJEPA2_CONFIG_FIELD", "{k}"))
        };
        let hidden = field("hidden_size")?;
        let mlp_ratio = c["mlp_ratio"]
            .as_f64()
            .ok_or_else(|| err!(EINVAL, "VJEPA2_CONFIG_FIELD", "mlp_ratio"))?;
        let config = Self {
            hidden,
            layers: field("num_hidden_layers")?,
            heads: field("num_attention_heads")?,
            mlp: (hidden as f64 * mlp_ratio) as usize,
            patch: field("patch_size")?,
            tubelet: field("tubelet_size")?,
            image: field("image_size")?,
            eps: c["layer_norm_eps"]
                .as_f64()
                .ok_or_else(|| err!(EINVAL, "VJEPA2_CONFIG_FIELD", "layer_norm_eps"))?
                as f32,
        };
        config.validate()?;
        Ok(config)
    }

    /// Invariants the worker also checks.
    pub fn validate(&self) -> EnclaveResult<()> {
        if self.hidden % self.heads != 0
            || self.image % self.patch != 0
            || self.image > 1024
            || !(self.eps.is_finite() && self.eps > 0.0)
            || self.mlp == 0
        {
            fail!(EINVAL, "VJEPA2_CONFIG_UNSUPPORTED");
        }
        Ok(())
    }
}

/// The adapter heads, deterministic from fixed seeds.
fn adapter_heads(d: usize) -> Vec<(&'static str, Vec<u64>, Vec<f32>)> {
    let mut predictor = vec![0f32; d * (d + 8)];
    let action = crate::zoo::weights("vjepa2.action", d * 8, ACTION_SCALE);
    for row in 0..d {
        predictor[row * (d + 8) + row] = 1.0;
        predictor[row * (d + 8) + d..(row + 1) * (d + 8)]
            .copy_from_slice(&action[row * 8..(row + 1) * 8]);
    }
    let cone = crate::zoo::weights("vjepa2.cone", d, 1.0);
    let norm = cone
        .iter()
        .map(|v| v * v)
        .sum::<f32>()
        .sqrt()
        .max(f32::MIN_POSITIVE);
    vec![
        (
            "enclave_adapter.predictor.weight",
            vec![d as u64, d as u64 + 8],
            predictor,
        ),
        (
            "enclave_adapter.ebm_cost_head.weight",
            vec![d as u64],
            vec![1.0 / (d as f32).sqrt(); d],
        ),
        (
            "enclave_adapter.safety_cone.weight",
            vec![d as u64],
            cone.iter().map(|v| v / norm * CONE_SCALE).collect(),
        ),
        (
            "enclave_adapter.conformal_energy_lut",
            vec![1],
            vec![CONFORMAL_ENERGY],
        ),
    ]
}

/// Repack a publisher V-JEPA 2 checkpoint into an `mlx_vjepa2_v1` artifact.
pub fn repack(config_json: &str, weights: &[u8]) -> EnclaveResult<Vec<u8>> {
    let config = VjepaConfig::from_hf(config_json)?;
    let len = weights
        .get(..8)
        .map(|b| u64::from_le_bytes(b.try_into().expect("eight bytes")) as usize)
        .ok_or_else(|| err!(EINVAL, "SAFETENSORS_TRUNCATED"))?;
    let start = 8usize
        .checked_add(len)
        .filter(|end| *end <= weights.len())
        .ok_or_else(|| err!(EINVAL, "SAFETENSORS_HEADER_LEN"))?;
    let mut header: Map<String, Value> = serde_json::from_slice(&weights[8..start])
        .map_err(|_| err!(EINVAL, "SAFETENSORS_HEADER_JSON"))?;
    header.remove("__metadata__");
    if header.keys().any(|k| k.starts_with("enclave_adapter.")) {
        fail!(EINVAL, "VJEPA2_ADAPTER_PRESENT");
    }
    let mut data = weights[start..].to_vec();
    for (name, shape, values) in adapter_heads(config.hidden) {
        let at = data.len();
        values
            .iter()
            .for_each(|v| data.extend_from_slice(&v.to_le_bytes()));
        header.insert(
            name.into(),
            json!({"dtype": "F32", "shape": shape, "data_offsets": [at, data.len()]}),
        );
    }
    let metadata: BTreeMap<&str, String> = BTreeMap::from([
        ("enclave_adapter.backend", BACKEND.to_owned()),
        (
            CONFIG_KEY,
            serde_json::to_string(&config).map_err(|_| err!(EIO, "VJEPA2_CONFIG_ENCODE"))?,
        ),
        ("enclave_adapter.safety_cone.tau", CONE_TAU.to_owned()),
    ]);
    header.insert("__metadata__".into(), json!(metadata));
    let mut encoded =
        serde_json::to_vec(&header).map_err(|_| err!(EIO, "SAFETENSORS_HEADER_ENCODE"))?;
    while encoded.len() % 8 != 0 {
        encoded.push(b' ');
    }
    let mut out = Vec::with_capacity(8 + encoded.len() + data.len());
    out.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
    out.extend_from_slice(&encoded);
    out.extend_from_slice(&data);
    Ok(out)
}

/// Nearest-neighbour resample of a grey frame to `side x side`.
pub fn resample(frame: &Frame, side: usize) -> EnclaveResult<Vec<u8>> {
    frame.validate()?;
    let mut out = Vec::with_capacity(side * side);
    for y in 0..side {
        let sy = y * frame.h / side;
        for x in 0..side {
            out.push(frame.px[sy * frame.w + x * frame.w / side]);
        }
    }
    Ok(out)
}

/// V-JEPA 2 encoder in the native worker plus the adapter heads. Development
/// backend: debug builds only, native worker (depot_MLX_WORKER) only.
pub struct MlxVjepa2 {
    worker: Mutex<Worker>,
    heads: ReferenceJepa,
    config: VjepaConfig,
}

impl std::fmt::Debug for MlxVjepa2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlxVjepa2")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl MlxVjepa2 {
    /// Start the worker on the authenticated artifact bytes.
    pub fn load(idx: &TensorIndex, bytes: &[u8], attest: &mut OpAttestor) -> EnclaveResult<Self> {
        if !cfg!(debug_assertions) {
            fail!(EPERM, "MLX_DEVELOPMENT_ONLY");
        }
        if !cfg!(target_os = "macos") {
            fail!(ENOSYS, "MLX_PLATFORM_UNAVAILABLE");
        }
        let config: VjepaConfig = serde_json::from_str(
            idx.metadata
                .get(CONFIG_KEY)
                .ok_or_else(|| err!(EACCES, "VJEPA2_CONFIG_MISSING"))?,
        )
        .map_err(|_| err!(EINVAL, "VJEPA2_CONFIG_JSON"))?;
        config.validate()?;
        let heads = ReferenceJepa::heads(idx, bytes, config.hidden)?;
        attest.admit(OpFamily::JepaPredict)?;
        let mut worker = spawn_native("vjepa2-v1")?;
        let deadline = Instant::now() + LOAD_DEADLINE;
        let config_bytes =
            serde_json::to_vec(&config).map_err(|_| err!(EIO, "VJEPA2_CONFIG_ENCODE"))?;
        let mut header = b"VJE1".to_vec();
        header.extend_from_slice(&(config_bytes.len() as u32).to_le_bytes());
        header.extend_from_slice(&config_bytes);
        header.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        send(&mut worker.input, &header, deadline)?;
        send(&mut worker.input, bytes, deadline)?;
        let mut ready = [0u8; 8];
        receive(&mut worker.output, &mut ready, deadline)?;
        if &ready[..4] != b"MLX5"
            || u32::from_le_bytes([ready[4], ready[5], ready[6], ready[7]]) as usize
                != config.hidden
        {
            fail!(EIO, "MLX_WORKER_READY");
        }
        Ok(Self {
            worker: Mutex::new(worker),
            heads,
            config,
        })
    }

    /// Latent of an already-sized `image x image` grey frame.
    pub fn latent(&self, pixels: &[u8]) -> EnclaveResult<Vec<f32>> {
        if pixels.len() != self.config.image * self.config.image {
            fail!(EINVAL, "FRAME_SHAPE");
        }
        let mut worker = self
            .worker
            .lock()
            .map_err(|_| err!(EIO, "MLX_WORKER_LOCK"))?;
        if worker.failed {
            fail!(EIO, "MLX_WORKER_REVOKED");
        }
        let deadline = Instant::now() + ENCODE_DEADLINE;
        let result = (|| {
            send(&mut worker.input, pixels, deadline)?;
            let mut raw = vec![0u8; 4 * self.config.hidden];
            receive(&mut worker.output, &mut raw, deadline)?;
            let latent: Vec<f32> = raw
                .chunks_exact(4)
                .map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                .collect();
            raw.fill(0);
            Ok(latent)
        })();
        if result.is_err() {
            worker.failed = true;
            let _ = worker.child.kill();
        }
        result
    }
}

impl WorldModel for MlxVjepa2 {
    fn width(&self) -> usize {
        self.config.hidden
    }
    fn encode(&self, frame: &Frame) -> EnclaveResult<Vec<f32>> {
        let mut pixels = resample(frame, self.config.image)?;
        let latent = self.latent(&pixels);
        pixels.iter_mut().for_each(|p| *p = 0);
        let latent = latent?;
        crate::arena::finite(&latent, "vjepa2 latent")?;
        Ok(latent)
    }
    fn predict(&self, s: &[f32], a: &Action) -> EnclaveResult<Vec<f32>> {
        self.heads.predict(s, a)
    }
    fn cost(&self, s_next: &[f32], goal: &[f32]) -> f32 {
        self.heads.cost(s_next, goal)
    }
    fn cone(&self, s_next: &[f32]) -> f32 {
        self.heads.cone(s_next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resample_is_identity_at_size_and_nearest_otherwise() {
        let frame = Frame {
            w: 4,
            h: 2,
            px: vec![1, 2, 3, 4, 5, 6, 7, 8],
        };
        assert_eq!(resample(&frame, 2).unwrap(), vec![1, 3, 5, 7]);
        let square = Frame {
            w: 2,
            h: 2,
            px: vec![9, 8, 7, 6],
        };
        assert_eq!(resample(&square, 2).unwrap(), vec![9, 8, 7, 6]);
        assert_eq!(
            resample(&square, 4).unwrap(),
            vec![9, 9, 8, 8, 9, 9, 8, 8, 7, 7, 6, 6, 7, 7, 6, 6]
        );
    }

    #[test]
    fn adapter_predictor_keeps_the_state_and_heads_are_well_formed() {
        let heads = adapter_heads(16);
        let predictor = &heads[0].2;
        for row in 0..16 {
            assert_eq!(predictor[row * 24 + row], 1.0);
            assert!(predictor[row * 24 + 16..row * 24 + 24]
                .iter()
                .all(|v| v.abs() <= ACTION_SCALE));
        }
        let cone_norm: f32 = heads[2].2.iter().map(|v| v * v).sum::<f32>().sqrt();
        assert!((cone_norm - CONE_SCALE).abs() < 1e-6);
    }
}
