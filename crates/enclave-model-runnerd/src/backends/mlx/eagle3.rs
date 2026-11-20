//! `mlx_eagle3_v1` artifact format and its native-worker speculative backend.
//!
//! One safetensors file holds the publisher's Qwen3 target tensors unchanged
//! (plus an explicit `lm_head.weight` when the publisher ties it), the
//! EAGLE-3 draft head under `eagle3.` (its `fc` renamed `eagle3.eagle_fc` so
//! topology detection sees the draft head, `d2t` stored as exact F32, the
//! unused `t2d` mask dropped), and metadata:
//! - `enclave_adapter.backend` = `mlx_eagle3_v1`
//! - `enclave_adapter.llama.config` = the target's closed `LlamaConfig`
//! - `enclave_adapter.eagle3.config` = the closed `DraftConfig`
//! The publisher's `tokenizer.json` travels verbatim as the U8 tensor
//! `enclave_adapter.tokenizer_json`, not as header metadata: an 11 MB header
//! string would be held several times over by every header parser (the CAS
//! sanitizer included) and breach the daemons' memory ceilings. All of it is
//! covered by the artifact digest the manifest signs.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::llama::{LlamaConfig, CONFIG_KEY as LLAMA_CONFIG_KEY};
use super::runtime::{receive, send, spawn_native, Worker};
use crate::classes::speculative::{DepthBackend, SpeculativeTokenModel};
use crate::safetensors::TensorIndex;
use crate::tokenizer::Tokenizer;
use crate::topology::{OpAttestor, OpFamily};

/// Backend identifier in artifact metadata.
pub const BACKEND: &str = "mlx_eagle3_v1";
/// Metadata key for the draft config.
pub const DRAFT_CONFIG_KEY: &str = "enclave_adapter.eagle3.config";
/// Tensor carrying the verbatim tokenizer.json bytes.
pub const TOKENIZER_TENSOR: &str = "enclave_adapter.tokenizer_json";
/// Draft tensor prefix.
pub const PREFIX: &str = "eagle3.";
/// Default capture: residual stream at the input of these target layers
/// (the outputs of layers 1, n/2 - 1, n - 4, as SpecForge and SGLang use).
fn default_capture(layers: usize) -> [usize; 3] {
    [2, layers / 2, layers - 3]
}
const LOAD_DEADLINE: Duration = Duration::from_secs(180);
const REQUEST_DEADLINE: Duration = Duration::from_secs(30);
const MAX_CONTEXT: usize = 4096;
const END_TOKENS: [&str; 2] = ["<|im_end|>", "<|endoftext|>"];

/// Closed EAGLE-3 draft-head parameters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftConfig {
    /// Draft width (equals the target width).
    pub hidden: usize,
    /// Query heads.
    pub heads: usize,
    /// Key/value heads.
    pub kv_heads: usize,
    /// Per-head width.
    pub head_dim: usize,
    /// MLP width.
    pub intermediate: usize,
    /// Draft vocabulary (mapped to the target's by `d2t`).
    pub draft_vocab: usize,
    /// RMSNorm epsilon.
    pub rms_eps: f32,
    /// RoPE base.
    pub rope_theta: f32,
    /// Target layer inputs captured as features.
    pub capture: [usize; 3],
}

impl DraftConfig {
    /// Derive from the head's `config.json`, refusing what the graph lacks.
    pub fn from_hf(config_json: &str, target: &LlamaConfig) -> EnclaveResult<Self> {
        let c: Value =
            serde_json::from_str(config_json).map_err(|_| err!(EINVAL, "EAGLE3_CONFIG_JSON"))?;
        let unsupported = c["architectures"] != json!(["LlamaForCausalLMEagle3"])
            || c["num_hidden_layers"] != 1
            || c["hidden_act"] != "silu"
            || !c["rope_scaling"].is_null()
            || c["attention_bias"] == true
            || c["mlp_bias"] == true
            || c["fc_norm"] == true
            || c["norm_output"] == true
            || c.get("eagle_config").is_some()
            || c["target_hidden_size"]
                .as_u64()
                .is_some_and(|h| h as usize != target.hidden);
        if unsupported {
            fail!(EINVAL, "EAGLE3_CONFIG_UNSUPPORTED");
        }
        let field = |k: &str| {
            c[k].as_u64()
                .filter(|v| (1..=1 << 20).contains(v))
                .map(|v| v as usize)
                .ok_or_else(|| err!(EINVAL, "EAGLE3_CONFIG_FIELD", "{k}"))
        };
        let config = Self {
            hidden: field("hidden_size")?,
            heads: field("num_attention_heads")?,
            kv_heads: field("num_key_value_heads")?,
            head_dim: field("head_dim")?,
            intermediate: field("intermediate_size")?,
            draft_vocab: field("draft_vocab_size")?,
            rms_eps: c["rms_norm_eps"]
                .as_f64()
                .ok_or_else(|| err!(EINVAL, "EAGLE3_CONFIG_FIELD", "rms_norm_eps"))?
                as f32,
            rope_theta: c["rope_theta"]
                .as_f64()
                .ok_or_else(|| err!(EINVAL, "EAGLE3_CONFIG_FIELD", "rope_theta"))?
                as f32,
            capture: default_capture(target.layers),
        };
        config.validate(target)?;
        Ok(config)
    }

    /// Invariants the worker also checks.
    pub fn validate(&self, target: &LlamaConfig) -> EnclaveResult<()> {
        if self.hidden != target.hidden
            || self.draft_vocab > target.vocab
            || self.heads % self.kv_heads != 0
            || self.head_dim % 2 != 0
            || !(self.rms_eps.is_finite() && self.rms_eps > 0.0)
            || !(self.rope_theta.is_finite() && self.rope_theta > 0.0)
            || target.layers < 4
            || self.capture.iter().any(|c| *c > target.layers)
            || !self.capture.windows(2).all(|w| w[0] < w[1])
        {
            fail!(EINVAL, "EAGLE3_CONFIG_UNSUPPORTED");
        }
        Ok(())
    }
}

/// Parsed safetensors: header entries (without metadata) and the data section.
fn split_safetensors(bytes: &[u8]) -> EnclaveResult<(Map<String, Value>, &[u8])> {
    let len = bytes
        .get(..8)
        .map(|b| u64::from_le_bytes(b.try_into().expect("eight bytes")) as usize)
        .ok_or_else(|| err!(EINVAL, "SAFETENSORS_TRUNCATED"))?;
    let start = 8usize
        .checked_add(len)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| err!(EINVAL, "SAFETENSORS_HEADER_LEN"))?;
    let mut header: Map<String, Value> = serde_json::from_slice(&bytes[8..start])
        .map_err(|_| err!(EINVAL, "SAFETENSORS_HEADER_JSON"))?;
    header.remove("__metadata__");
    Ok((header, &bytes[start..]))
}

fn tensor<'a>(
    header: &Map<String, Value>,
    data: &'a [u8],
    name: &str,
) -> EnclaveResult<(String, Vec<u64>, &'a [u8])> {
    let entry = header
        .get(name)
        .ok_or_else(|| err!(EINVAL, "TENSOR_MISSING", "{name}"))?;
    let [start, end] =
        [0, 1].map(|i| entry["data_offsets"][i].as_u64().unwrap_or(u64::MAX) as usize);
    if start > end || end > data.len() {
        fail!(EINVAL, "SAFETENSORS_OFFSETS");
    }
    let shape = entry["shape"]
        .as_array()
        .ok_or_else(|| err!(EINVAL, "SAFETENSORS_SHAPE"))?
        .iter()
        .map(|d| d.as_u64().ok_or_else(|| err!(EINVAL, "SAFETENSORS_SHAPE")))
        .collect::<EnclaveResult<_>>()?;
    let dtype = entry["dtype"]
        .as_str()
        .ok_or_else(|| err!(EINVAL, "SAFETENSORS_DTYPE"))?
        .to_owned();
    Ok((dtype, shape, &data[start..end]))
}

/// Accumulates tensors and writes one safetensors file.
#[derive(Default)]
struct Builder {
    header: Map<String, Value>,
    data: Vec<u8>,
}

impl Builder {
    fn add(&mut self, name: &str, dtype: &str, shape: &[u64], bytes: &[u8]) -> EnclaveResult<()> {
        if self.header.contains_key(name) {
            fail!(EINVAL, "TENSOR_DUPLICATE", "{name}");
        }
        let at = self.data.len();
        self.data.extend_from_slice(bytes);
        self.header.insert(
            name.to_owned(),
            json!({"dtype": dtype, "shape": shape, "data_offsets": [at, self.data.len()]}),
        );
        Ok(())
    }

    fn finish(mut self, metadata: BTreeMap<&str, String>) -> EnclaveResult<Vec<u8>> {
        self.header.insert("__metadata__".into(), json!(metadata));
        let mut encoded =
            serde_json::to_vec(&self.header).map_err(|_| err!(EIO, "SAFETENSORS_HEADER_ENCODE"))?;
        while encoded.len() % 8 != 0 {
            encoded.push(b' ');
        }
        let mut out = Vec::with_capacity(8 + encoded.len() + self.data.len());
        out.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
        out.extend_from_slice(&encoded);
        out.extend_from_slice(&self.data);
        Ok(out)
    }
}

/// Repack a Qwen3 target and its EAGLE-3 head into one `mlx_eagle3_v1` artifact.
pub fn repack(
    target_config: &str,
    tokenizer_json: &str,
    target_weights: &[u8],
    head_config: &str,
    head_weights: &[u8],
) -> EnclaveResult<Vec<u8>> {
    let mut target = LlamaConfig::from_hf(target_config)?;
    if !target.qk_norm {
        fail!(
            EINVAL,
            "EAGLE3_TARGET_UNSUPPORTED",
            "the admitted pair is a Qwen3 target"
        );
    }
    let draft = DraftConfig::from_hf(head_config, &target)?;
    let tokenizer = Tokenizer::from_hf_json(tokenizer_json)?;
    if tokenizer.vocab() > target.vocab || END_TOKENS.iter().any(|t| tokenizer.special(t).is_none())
    {
        fail!(EINVAL, "EAGLE3_TOKENIZER_UNSUPPORTED");
    }
    let mut out = Builder::default();
    let (header, data) = split_safetensors(target_weights)?;
    for name in header.keys() {
        let (dtype, shape, bytes) = tensor(&header, data, name)?;
        out.add(name, &dtype, &shape, bytes)?;
    }
    if target.tie_embeddings {
        let embed = tensor(&header, data, "model.embed_tokens.weight")?;
        if header.contains_key("lm_head.weight") {
            // Some publishers store the tied head anyway; it must be the embedding.
            if tensor(&header, data, "lm_head.weight")? != embed {
                fail!(EINVAL, "LLAMA_TIED_HEAD_DIFFERS");
            }
        } else {
            out.add("lm_head.weight", &embed.0, &embed.1, embed.2)?;
        }
        target.tie_embeddings = false;
    }
    let (header, data) = split_safetensors(head_weights)?;
    for name in header.keys() {
        let (dtype, shape, bytes) = tensor(&header, data, name)?;
        match name.as_str() {
            "t2d" => continue,
            "d2t" => {
                if dtype != "I64" || shape != [draft.draft_vocab as u64] {
                    fail!(EINVAL, "EAGLE3_D2T_SHAPE");
                }
                let mut exact = Vec::with_capacity(bytes.len() / 2);
                for (i, chunk) in bytes.chunks_exact(8).enumerate() {
                    let offset = i64::from_le_bytes(chunk.try_into().expect("eight bytes"));
                    if !(0..target.vocab as i64).contains(&(i as i64 + offset))
                        || offset.unsigned_abs() >= 1 << 24
                    {
                        fail!(EINVAL, "EAGLE3_D2T_RANGE");
                    }
                    exact.extend_from_slice(&(offset as f32).to_le_bytes());
                }
                out.add("eagle3.d2t", "F32", &shape, &exact)?;
            }
            "fc.weight" => out.add("eagle3.eagle_fc.weight", &dtype, &shape, bytes)?,
            other => out.add(&format!("{PREFIX}{other}"), &dtype, &shape, bytes)?,
        }
    }
    out.add(
        TOKENIZER_TENSOR,
        "U8",
        &[tokenizer_json.len() as u64],
        tokenizer_json.as_bytes(),
    )?;
    out.finish(BTreeMap::from([
        ("enclave_adapter.backend", BACKEND.to_owned()),
        (
            LLAMA_CONFIG_KEY,
            serde_json::to_string(&target).map_err(|_| err!(EIO, "LLAMA_CONFIG_ENCODE"))?,
        ),
        (
            DRAFT_CONFIG_KEY,
            serde_json::to_string(&draft).map_err(|_| err!(EIO, "EAGLE3_CONFIG_ENCODE"))?,
        ),
    ]))
}

/// The pair served by the native worker. Development backend: debug builds
/// only, and only the native worker (depot_MLX_WORKER) implements it.
pub struct MlxEagle3 {
    worker: Mutex<Worker>,
    tokenizer: Tokenizer,
    vocab: usize,
    feature_width: usize,
    end: [u32; 2],
}

impl std::fmt::Debug for MlxEagle3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlxEagle3")
            .field("vocab", &self.vocab)
            .finish_non_exhaustive()
    }
}

impl MlxEagle3 {
    /// Start the worker on the authenticated artifact bytes.
    pub fn load(idx: &TensorIndex, bytes: &[u8], attest: &mut OpAttestor) -> EnclaveResult<Self> {
        if !cfg!(debug_assertions) {
            fail!(EPERM, "MLX_DEVELOPMENT_ONLY");
        }
        if !cfg!(target_os = "macos") {
            fail!(ENOSYS, "MLX_PLATFORM_UNAVAILABLE");
        }
        let meta = |k: &str| {
            idx.metadata
                .get(k)
                .ok_or_else(|| err!(EACCES, "EAGLE3_METADATA_MISSING", "{k}"))
        };
        let target: LlamaConfig = serde_json::from_str(meta(LLAMA_CONFIG_KEY)?)
            .map_err(|_| err!(EINVAL, "LLAMA_CONFIG_JSON"))?;
        target.validate()?;
        let draft: DraftConfig = serde_json::from_str(meta(DRAFT_CONFIG_KEY)?)
            .map_err(|_| err!(EINVAL, "EAGLE3_CONFIG_JSON"))?;
        draft.validate(&target)?;
        let tensor = idx
            .tensors
            .get(TOKENIZER_TENSOR)
            .ok_or_else(|| err!(EACCES, "TOKENIZER_MISSING"))?;
        let raw = bytes
            .get(tensor.range.0..tensor.range.1)
            .ok_or_else(|| err!(EINVAL, "TOKENIZER_RANGE"))?;
        let tokenizer = Tokenizer::from_hf_json(
            std::str::from_utf8(raw).map_err(|_| err!(EINVAL, "TOKENIZER_UTF8"))?,
        )?;
        let end = END_TOKENS.map(|t| tokenizer.special(t));
        let [Some(im_end), Some(eot)] = end else { fail!(EINVAL, "EAGLE3_TOKENIZER_UNSUPPORTED") };
        if tokenizer.vocab() > target.vocab {
            fail!(EINVAL, "TOKENIZER_VOCAB_EXCEEDS_MODEL");
        }
        attest.admit(OpFamily::DraftTree)?;
        attest.admit(OpFamily::CausalDecode)?;
        let mut worker = spawn_native("eagle3-v1")?;
        let deadline = Instant::now() + LOAD_DEADLINE;
        let config = serde_json::to_vec(&json!({"target": target, "draft": draft}))
            .map_err(|_| err!(EIO, "EAGLE3_CONFIG_ENCODE"))?;
        let mut header = b"EAG1".to_vec();
        header.extend_from_slice(&(config.len() as u32).to_le_bytes());
        header.extend_from_slice(&config);
        header.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        send(&mut worker.input, &header, deadline)?;
        send(&mut worker.input, bytes, deadline)?;
        let mut ready = [0u8; 12];
        receive(&mut worker.output, &mut ready, deadline)?;
        let word = |i: usize| {
            u32::from_le_bytes([ready[i], ready[i + 1], ready[i + 2], ready[i + 3]]) as usize
        };
        if &ready[..4] != b"MLX4" || word(4) != target.vocab || word(8) != 3 * target.hidden {
            fail!(EIO, "MLX_WORKER_READY");
        }
        Ok(Self {
            worker: Mutex::new(worker),
            tokenizer,
            vocab: target.vocab,
            feature_width: 3 * target.hidden,
            end: [im_end, eot],
        })
    }

    fn call<T>(
        &self,
        request: &[u8],
        reply_len: usize,
        decode: impl FnOnce(&[u8]) -> T,
    ) -> EnclaveResult<T> {
        let mut worker = self
            .worker
            .lock()
            .map_err(|_| err!(EIO, "MLX_WORKER_LOCK"))?;
        if worker.failed {
            fail!(EIO, "MLX_WORKER_REVOKED");
        }
        let deadline = Instant::now() + REQUEST_DEADLINE;
        let result = (|| {
            send(&mut worker.input, request, deadline)?;
            let mut raw = vec![0u8; reply_len];
            receive(&mut worker.output, &mut raw, deadline)?;
            let value = decode(&raw);
            raw.fill(0);
            Ok(value)
        })();
        if result.is_err() {
            worker.failed = true;
            let _ = worker.child.kill();
        }
        result
    }

    fn check_ids(&self, ids: &[u32]) -> EnclaveResult<()> {
        if ids.is_empty() || ids.len() > MAX_CONTEXT {
            fail!(EINVAL, "TOKEN_CONTEXT_LENGTH");
        }
        if ids.iter().any(|id| *id as usize >= self.vocab) {
            fail!(EINVAL, "TOKEN_ID_RANGE");
        }
        Ok(())
    }
}

fn request(op: u8, a: usize, b: usize, ids: &[u32]) -> Vec<u8> {
    let mut r = Vec::with_capacity(9 + 4 * ids.len());
    r.push(op);
    r.extend_from_slice(&(a as u32).to_le_bytes());
    r.extend_from_slice(&(b as u32).to_le_bytes());
    ids.iter()
        .for_each(|id| r.extend_from_slice(&id.to_le_bytes()));
    r
}

fn words(raw: &[u8]) -> Vec<u32> {
    raw.chunks_exact(4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .collect()
}

fn floats(raw: &[u8]) -> Vec<f32> {
    raw.chunks_exact(4)
        .map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .collect()
}

impl SpeculativeTokenModel for MlxEagle3 {
    fn encode(&self, bytes: &[u8]) -> EnclaveResult<Vec<u32>> {
        let text = std::str::from_utf8(bytes).map_err(|_| err!(EINVAL, "PROMPT_NOT_UTF8"))?;
        self.tokenizer.encode(text)
    }
    fn token_bytes(&self, id: u32) -> EnclaveResult<&[u8]> {
        self.tokenizer
            .token(id)
            .ok_or_else(|| err!(EINVAL, "TOKEN_ID_RANGE"))
    }
    fn is_end(&self, id: u32) -> bool {
        self.end.contains(&id)
    }
    fn feature_width(&self) -> usize {
        self.feature_width
    }
    fn verify(&self, ids: &[u32], tail: usize) -> EnclaveResult<(Vec<u32>, Vec<f32>)> {
        self.check_ids(ids)?;
        if !(1..=ids.len().min(64)).contains(&tail) {
            fail!(EINVAL, "SPECULATION_TAIL");
        }
        let mut req = request(1, ids.len(), tail, ids);
        let fw = self.feature_width;
        let result = self.call(&req, 4 * (tail + ids.len() * fw), |raw| {
            let (next, feats) = raw.split_at(4 * tail);
            (words(next), floats(feats))
        });
        req.fill(0);
        let (next, feats) = result?;
        if next.iter().any(|id| *id as usize >= self.vocab) {
            fail!(EIO, "MLX_WORKER_REPLY");
        }
        Ok((next, feats))
    }
    fn draft(&self, ids: &[u32], features: &[f32], k: usize) -> EnclaveResult<Vec<u32>> {
        self.check_ids(ids)?;
        if ids.len() < 2
            || features.len() != (ids.len() - 1) * self.feature_width
            || !(1..=16).contains(&k)
        {
            fail!(EINVAL, "SPECULATION_DRAFT_SHAPE");
        }
        let mut req = request(2, ids.len(), k, ids);
        features
            .iter()
            .for_each(|v| req.extend_from_slice(&v.to_le_bytes()));
        let result = self.call(&req, 4 * k, words);
        req.fill(0);
        let drafted = result?;
        if drafted.iter().any(|id| *id as usize >= self.vocab) {
            fail!(EIO, "MLX_WORKER_REPLY");
        }
        Ok(drafted)
    }
}

impl DepthBackend for MlxEagle3 {
    fn width(&self) -> usize {
        self.feature_width
    }
    fn prelude(&self, _: &[u8], _: &mut [f32]) -> EnclaveResult<()> {
        fail!(ENOSYS, "DEPTH_LOOP_UNSUPPORTED")
    }
    fn core(&self, _: &mut [f32]) -> EnclaveResult<()> {
        fail!(ENOSYS, "DEPTH_LOOP_UNSUPPORTED")
    }
    fn coda(&self, _: &[f32]) -> EnclaveResult<Vec<f32>> {
        fail!(ENOSYS, "DEPTH_LOOP_UNSUPPORTED")
    }
    fn draft(&self, _: u8) -> u8 {
        0
    }
    fn token_model(&self) -> Option<&dyn SpeculativeTokenModel> {
        Some(self)
    }
}
