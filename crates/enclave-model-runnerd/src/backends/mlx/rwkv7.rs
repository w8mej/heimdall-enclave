//! `mlx_rwkv7_v1` artifact format and its native-worker recurrent backend.
//!
//! An admissible artifact (scripts/convert-rwkv7.py) is one safetensors file
//! holding the upstream RWKV-7 tensors unchanged plus metadata:
//! - `enclave_adapter.backend` = `mlx_rwkv7_v1`
//! - `enclave_adapter.rwkv7.config` = the worker's closed `Rwkv7Config` JSON
//! - `enclave_adapter.tokenizer` = the RWKV World vocabulary (`rwkv_world_trie_v1`)
//! All of it is covered by the artifact digest the manifest signs.
//!
//! The recurrent state stays in the runner's `StateSnapshotDag` arenas (sealed
//! system snapshot, per-session copy-on-write, anchoring, wipe); the worker is
//! sent the state with every request and keeps nothing between requests.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};

use super::runtime::{receive, send, spawn_native, Worker};
use crate::classes::ssm::{RecurrentBackend, RecurrentTokenModel};
use crate::safetensors::TensorIndex;
use crate::topology::{OpAttestor, OpFamily};
use crate::world_tokenizer::{WorldTokenizer, END_OF_TEXT};

/// Backend identifier in artifact metadata.
pub const BACKEND: &str = "mlx_rwkv7_v1";
/// Metadata key for the worker config.
pub const CONFIG_KEY: &str = "enclave_adapter.rwkv7.config";
/// Metadata key for the tokenizer.
pub const TOKENIZER_KEY: &str = "enclave_adapter.tokenizer";
/// Load (pipe transfer plus graph materialization) bound.
const LOAD_DEADLINE: Duration = Duration::from_secs(120);
/// Per-token bound for one request.
const PER_TOKEN_DEADLINE: Duration = Duration::from_millis(500);
const REQUEST_FLOOR: Duration = Duration::from_secs(5);
/// Largest request the worker accepts.
const MAX_TOKENS: usize = 4096;
/// Largest admitted state, in f32s (64 MiB).
const MAX_STATE: usize = 16 << 20;

/// Closed architecture parameters understood by the worker's `rwkv7-v1` graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rwkv7Config {
    /// Model width `C`.
    pub hidden: usize,
    /// Blocks.
    pub layers: usize,
    /// Heads `H`.
    pub heads: usize,
    /// Per-head width `N`.
    pub head_size: usize,
    /// Channel-mix width.
    pub ffn: usize,
    /// Embedding rows.
    pub vocab: usize,
}

impl Rwkv7Config {
    /// Structural invariants the worker also checks.
    pub fn validate(&self) -> EnclaveResult<()> {
        let sizes = [
            self.hidden,
            self.layers,
            self.heads,
            self.head_size,
            self.ffn,
            self.vocab,
        ];
        if !sizes.iter().all(|v| (1..=1 << 20).contains(v))
            || self.heads * self.head_size != self.hidden
            || self.layers < 2
            || self.state_len() > MAX_STATE
        {
            fail!(EINVAL, "RWKV7_CONFIG_UNSUPPORTED");
        }
        Ok(())
    }

    /// Recurrent state length in f32s: per layer `2C + H N N`.
    pub fn state_len(&self) -> usize {
        self.layers
            .saturating_mul(2 * self.hidden + self.heads * self.head_size * self.head_size)
    }
}

/// RWKV-7 served by the native worker. Development backend: debug builds
/// only, and only the native worker (MCPMAC_MLX_WORKER) implements this mode.
pub struct MlxRwkv7 {
    worker: Mutex<Worker>,
    tokenizer: WorldTokenizer,
    config: Rwkv7Config,
    h_sys: Vec<f32>,
}

impl std::fmt::Debug for MlxRwkv7 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlxRwkv7")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl MlxRwkv7 {
    /// Start the worker on the authenticated artifact bytes.
    pub fn load(idx: &TensorIndex, bytes: &[u8], attest: &mut OpAttestor) -> EnclaveResult<Self> {
        if !cfg!(debug_assertions) {
            fail!(EPERM, "MLX_DEVELOPMENT_ONLY");
        }
        if !cfg!(target_os = "macos") {
            fail!(ENOSYS, "MLX_PLATFORM_UNAVAILABLE");
        }
        let config_json = idx
            .metadata
            .get(CONFIG_KEY)
            .ok_or_else(|| err!(EACCES, "RWKV7_CONFIG_MISSING"))?;
        let config: Rwkv7Config =
            serde_json::from_str(config_json).map_err(|_| err!(EINVAL, "RWKV7_CONFIG_JSON"))?;
        config.validate()?;
        let tokenizer = WorldTokenizer::from_json(
            idx.metadata
                .get(TOKENIZER_KEY)
                .ok_or_else(|| err!(EACCES, "TOKENIZER_MISSING"))?,
        )?;
        if tokenizer.vocab() > config.vocab {
            fail!(EINVAL, "TOKENIZER_VOCAB_EXCEEDS_MODEL");
        }
        attest.admit(OpFamily::PersistentStateScan)?;
        attest.admit(OpFamily::CausalDecode)?;
        let mut worker = spawn_native("rwkv7-v1")?;
        let deadline = Instant::now() + LOAD_DEADLINE;
        let config_bytes =
            serde_json::to_vec(&config).map_err(|_| err!(EIO, "RWKV7_CONFIG_ENCODE"))?;
        let mut header = b"RWK1".to_vec();
        header.extend_from_slice(&(config_bytes.len() as u32).to_le_bytes());
        header.extend_from_slice(&config_bytes);
        header.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        send(&mut worker.input, &header, deadline)?;
        send(&mut worker.input, bytes, deadline)?;
        let mut ready = [0u8; 12];
        receive(&mut worker.output, &mut ready, deadline)?;
        let word = |i: usize| {
            u32::from_le_bytes([ready[i], ready[i + 1], ready[i + 2], ready[i + 3]]) as usize
        };
        if &ready[..4] != b"MLX3" || word(4) != config.vocab || word(8) != config.state_len() {
            fail!(EIO, "MLX_WORKER_READY");
        }
        // No system prefix is declared yet: the clean system state is zero.
        let h_sys = vec![0f32; config.state_len()];
        Ok(Self {
            worker: Mutex::new(worker),
            tokenizer,
            config,
            h_sys,
        })
    }
}

impl RecurrentBackend for MlxRwkv7 {
    fn width(&self) -> usize {
        self.config.state_len()
    }
    fn system_state(&self) -> Vec<f32> {
        self.h_sys.clone()
    }
    fn step(&self, _h: &mut [f32], _byte: u8) -> EnclaveResult<()> {
        fail!(ENOSYS, "BYTE_DECODE_UNSUPPORTED_BY_TOKEN_MODEL")
    }
    fn logits(&self, _h: &[f32]) -> EnclaveResult<[f32; 256]> {
        fail!(ENOSYS, "BYTE_DECODE_UNSUPPORTED_BY_TOKEN_MODEL")
    }
    fn token_model(&self) -> Option<&dyn RecurrentTokenModel> {
        Some(self)
    }
}

impl RecurrentTokenModel for MlxRwkv7 {
    fn encode(&self, bytes: &[u8]) -> EnclaveResult<Vec<u32>> {
        self.tokenizer.encode(bytes)
    }
    fn token_bytes(&self, id: u32) -> EnclaveResult<&[u8]> {
        self.tokenizer
            .token(id)
            .ok_or_else(|| err!(EINVAL, "TOKEN_ID_RANGE"))
    }
    fn is_end(&self, id: u32) -> bool {
        id == END_OF_TEXT
    }
    fn advance(&self, h: &mut [f32], ids: &[u32]) -> EnclaveResult<Vec<f32>> {
        if ids.is_empty() || ids.len() > MAX_TOKENS {
            fail!(EINVAL, "TOKEN_CONTEXT_LENGTH");
        }
        if h.len() != self.config.state_len() {
            fail!(EINVAL, "SSM_STATE_SHAPE");
        }
        if ids.iter().any(|id| *id as usize >= self.tokenizer.vocab()) {
            fail!(EINVAL, "TOKEN_ID_RANGE");
        }
        let mut worker = self
            .worker
            .lock()
            .map_err(|_| err!(EIO, "MLX_WORKER_LOCK"))?;
        if worker.failed {
            fail!(EIO, "MLX_WORKER_REVOKED");
        }
        let deadline = Instant::now() + REQUEST_FLOOR + PER_TOKEN_DEADLINE * ids.len() as u32;
        let result = (|| {
            let mut request = Vec::with_capacity(4 + 4 * (h.len() + ids.len()));
            request.extend_from_slice(&(ids.len() as u32).to_le_bytes());
            for v in h.iter() {
                request.extend_from_slice(&v.to_le_bytes());
            }
            for id in ids {
                request.extend_from_slice(&id.to_le_bytes());
            }
            send(&mut worker.input, &request, deadline)?;
            request.fill(0);
            let mut raw = vec![0u8; 4 * (h.len() + self.config.vocab)];
            receive(&mut worker.output, &mut raw, deadline)?;
            let (state, logits) = raw.split_at(4 * h.len());
            for (slot, b) in h.iter_mut().zip(state.chunks_exact(4)) {
                *slot = f32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            }
            // The embedding may be padded beyond the tokenizer's vocabulary.
            let logits = logits
                .chunks_exact(4)
                .take(self.tokenizer.vocab())
                .map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                .collect();
            raw.fill(0);
            Ok(logits)
        })();
        if result.is_err() {
            worker.failed = true;
            let _ = worker.child.kill();
        }
        result
    }
}
