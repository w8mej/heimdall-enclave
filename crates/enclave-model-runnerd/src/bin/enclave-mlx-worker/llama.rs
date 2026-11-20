//! Closed Llama-family graph (`llama-v1` worker mode; also the Qwen3 target of
//! `eagle3-v1`: Qwen3 is this graph plus per-head QK RMSNorm).
//!
//! Protocol on the private pipes, all integers little-endian:
//!   in:  "LLM1", u32 config length, config JSON (`LlamaConfig`, unknown
//!        fields refused), u64 checkpoint length, safetensors bytes
//!   out: "MLX2", u32 vocabulary size
//!   then per request  in: u32 n (1..=MAX_TOKENS), n x u32 token ids
//!                     out: vocabulary x f32 logits for the last position
//! The checkpoint must contain exactly the tensors this graph names, with the
//! shapes the config implies (BF16 or F32). No other code or graph is loaded.

use std::collections::BTreeMap;
use std::io::{Read, Write};

use serde::Deserialize;

use crate::mlx::{Array, Dtype, Stream};

pub const MAGIC: &[u8; 4] = b"LLM1";
pub const READY: &[u8; 4] = b"MLX2";
/// Largest accepted request, in tokens.
pub const MAX_TOKENS: usize = 4096;
const MAX_CONFIG_BYTES: usize = 4096;
const MAX_CHECKPOINT_BYTES: u64 = 4 << 30;
pub const EXIT_PROTOCOL: i32 = 7;
pub const EXIT_CHECKPOINT: i32 = 8;

/// Architecture parameters, validated by the runner before sending.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlamaConfig {
    pub hidden: usize,
    pub layers: usize,
    pub heads: usize,
    pub kv_heads: usize,
    pub head_dim: usize,
    pub intermediate: usize,
    pub vocab: usize,
    pub rope_theta: f32,
    pub rms_eps: f32,
    pub tie_embeddings: bool,
    /// Per-head RMSNorm on queries and keys before RoPE (Qwen3).
    #[serde(default)]
    pub qk_norm: bool,
}

impl LlamaConfig {
    fn valid(&self) -> bool {
        let positive = [
            self.hidden,
            self.layers,
            self.heads,
            self.kv_heads,
            self.head_dim,
            self.intermediate,
            self.vocab,
        ];
        positive.iter().all(|v| (1..=1 << 20).contains(v))
            && self.heads % self.kv_heads == 0
            && self.head_dim % 2 == 0
            && self.rope_theta.is_finite()
            && self.rope_theta > 0.0
            && self.rms_eps.is_finite()
            && self.rms_eps > 0.0
    }

    /// Every tensor the graph reads, with its expected shape.
    pub fn expected_tensors(&self) -> BTreeMap<String, Vec<usize>> {
        let kv = self.kv_heads * self.head_dim;
        let q = self.heads * self.head_dim;
        let mut t = BTreeMap::new();
        t.insert(
            "model.embed_tokens.weight".into(),
            vec![self.vocab, self.hidden],
        );
        t.insert("model.norm.weight".into(), vec![self.hidden]);
        if !self.tie_embeddings {
            t.insert("lm_head.weight".into(), vec![self.vocab, self.hidden]);
        }
        for l in 0..self.layers {
            let p = format!("model.layers.{l}.");
            for (name, shape) in [
                ("input_layernorm.weight", vec![self.hidden]),
                ("post_attention_layernorm.weight", vec![self.hidden]),
                ("self_attn.q_proj.weight", vec![q, self.hidden]),
                ("self_attn.k_proj.weight", vec![kv, self.hidden]),
                ("self_attn.v_proj.weight", vec![kv, self.hidden]),
                ("self_attn.o_proj.weight", vec![self.hidden, q]),
                ("mlp.gate_proj.weight", vec![self.intermediate, self.hidden]),
                ("mlp.up_proj.weight", vec![self.intermediate, self.hidden]),
                ("mlp.down_proj.weight", vec![self.hidden, self.intermediate]),
            ] {
                t.insert(format!("{p}{name}"), shape);
            }
            if self.qk_norm {
                t.insert(format!("{p}self_attn.q_norm.weight"), vec![self.head_dim]);
                t.insert(format!("{p}self_attn.k_norm.weight"), vec![self.head_dim]);
            }
        }
        t
    }
}

#[derive(Deserialize)]
struct TensorEntry {
    dtype: String,
    shape: Vec<usize>,
    data_offsets: [usize; 2],
}

fn fail(code: i32) -> ! {
    std::process::exit(code)
}

/// Parse a safetensors checkpoint that must hold exactly the `expected`
/// tensors (name -> shape, BF16 or F32); return them as f32 arrays.
pub fn load_tensors(
    expected: &BTreeMap<String, Vec<usize>>,
    bytes: &[u8],
    s: &Stream,
) -> BTreeMap<String, Array> {
    load_tensors_ignoring(expected, &[], bytes, s)
}

/// As `load_tensors`, but tensors under any of `ignore` (exact prefixes)
/// are skipped unread, e.g. upstream modules this graph never runs.
pub fn load_tensors_ignoring(
    expected: &BTreeMap<String, Vec<usize>>,
    ignore: &[&str],
    bytes: &[u8],
    s: &Stream,
) -> BTreeMap<String, Array> {
    let specs = expected
        .iter()
        .map(|(k, shape)| {
            (
                k.clone(),
                Spec {
                    shape: shape.clone(),
                    packed: false,
                },
            )
        })
        .collect();
    load_typed(&specs, ignore, bytes, s)
}

/// One expected tensor: its shape, and whether it is packed quantized
/// codes (U32, kept as uint32) rather than floats (BF16/F32, made f32).
pub struct Spec {
    pub shape: Vec<usize>,
    pub packed: bool,
}

/// Parse a checkpoint that must hold exactly the `expected` tensors, each
/// with the shape and kind its spec names.
pub fn load_typed(
    expected: &BTreeMap<String, Spec>,
    ignore: &[&str],
    bytes: &[u8],
    s: &Stream,
) -> BTreeMap<String, Array> {
    let header_len = bytes
        .get(..8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()) as usize)
        .unwrap_or_else(|| fail(EXIT_CHECKPOINT));
    let data_start = 8usize
        .checked_add(header_len)
        .filter(|end| *end <= bytes.len())
        .unwrap_or_else(|| fail(EXIT_CHECKPOINT));
    let mut header: BTreeMap<String, serde_json::Value> =
        serde_json::from_slice(&bytes[8..data_start]).unwrap_or_else(|_| fail(EXIT_CHECKPOINT));
    header.remove("__metadata__");
    // Runner-side bytes (the verbatim tokenizer) are never part of a graph.
    header.remove("enclave_adapter.tokenizer_json");
    header.retain(|name, _| !ignore.iter().any(|prefix| name.starts_with(prefix)));
    if header.keys().ne(expected.keys()) {
        fail(EXIT_CHECKPOINT);
    }
    let data = &bytes[data_start..];
    let mut tensors = BTreeMap::new();
    for (name, value) in header {
        let entry: TensorEntry =
            serde_json::from_value(value).unwrap_or_else(|_| fail(EXIT_CHECKPOINT));
        let spec = &expected[&name];
        let (dtype, width) = match (entry.dtype.as_str(), spec.packed) {
            ("BF16", false) => (Dtype::Bfloat16, 2),
            ("F32", false) => (Dtype::Float32, 4),
            ("U32", true) => (Dtype::Uint32, 4),
            _ => fail(EXIT_CHECKPOINT),
        };
        let [start, end] = entry.data_offsets;
        let count: usize = entry.shape.iter().product();
        if entry.shape != spec.shape
            || end > data.len()
            || start > end
            || end - start != count * width
        {
            fail(EXIT_CHECKPOINT);
        }
        let shape: Vec<i32> = entry.shape.iter().map(|&d| d as i32).collect();
        let array = Array::from_raw(&data[start..end], &shape, dtype);
        tensors.insert(name, if spec.packed { array } else { array.to_f32(s) });
    }
    tensors
}

struct Layer {
    attn_norm: Array,
    mlp_norm: Array,
    q_t: Array,
    k_t: Array,
    v_t: Array,
    o_t: Array,
    gate_t: Array,
    up_t: Array,
    down_t: Array,
    qk_norm: Option<(Array, Array)>,
}

/// Loaded model: weights pre-transposed for `x @ W^T`, materialized once.
pub struct Llama {
    config: LlamaConfig,
    embed: Array,
    head_t: Array,
    norm: Array,
    layers: Vec<Layer>,
}

impl Llama {
    pub fn load(config: LlamaConfig, bytes: &[u8], s: &Stream) -> Self {
        if !config.valid() {
            fail(EXIT_PROTOCOL);
        }
        let mut w = load_tensors(&config.expected_tensors(), bytes, s);
        Self::from_tensors(config, &mut w, s)
    }

    /// Build from already-loaded tensors, taking exactly the ones it names.
    pub fn from_tensors(config: LlamaConfig, w: &mut BTreeMap<String, Array>, s: &Stream) -> Self {
        if !config.valid() {
            fail(EXIT_PROTOCOL);
        }
        let mut take = |name: &str| w.remove(name).unwrap_or_else(|| fail(EXIT_CHECKPOINT));
        let embed = take("model.embed_tokens.weight");
        let head_t = if config.tie_embeddings {
            embed.t(s)
        } else {
            take("lm_head.weight").t(s)
        };
        let norm = take("model.norm.weight");
        let layers = (0..config.layers)
            .map(|l| {
                let mut get = |n: &str| take(&format!("model.layers.{l}.{n}"));
                Layer {
                    attn_norm: get("input_layernorm.weight"),
                    mlp_norm: get("post_attention_layernorm.weight"),
                    q_t: get("self_attn.q_proj.weight").t(s),
                    k_t: get("self_attn.k_proj.weight").t(s),
                    v_t: get("self_attn.v_proj.weight").t(s),
                    o_t: get("self_attn.o_proj.weight").t(s),
                    gate_t: get("mlp.gate_proj.weight").t(s),
                    up_t: get("mlp.up_proj.weight").t(s),
                    down_t: get("mlp.down_proj.weight").t(s),
                    qk_norm: config.qk_norm.then(|| {
                        (
                            get("self_attn.q_norm.weight"),
                            get("self_attn.k_norm.weight"),
                        )
                    }),
                }
            })
            .collect::<Vec<_>>();
        for array in [&embed, &head_t, &norm] {
            array.eval();
        }
        for layer in &layers {
            for array in [
                &layer.attn_norm,
                &layer.mlp_norm,
                &layer.q_t,
                &layer.k_t,
                &layer.v_t,
                &layer.o_t,
                &layer.gate_t,
                &layer.up_t,
                &layer.down_t,
            ] {
                array.eval();
            }
            if let Some((q, k)) = &layer.qk_norm {
                q.eval();
                k.eval();
            }
        }
        Self {
            config,
            embed,
            head_t,
            norm,
            layers,
        }
    }

    /// Run the decoder over `ids` (full causal recompute). Returns the
    /// final-normed hidden states `[t, hidden]` and the residual stream at
    /// the input of each layer index in `capture` (index `layers` = output).
    pub fn hidden(&self, ids: &[u32], capture: &[usize], s: &Stream) -> (Array, Vec<Array>) {
        let c = &self.config;
        let t = ids.len() as i32;
        let (h, d) = (c.hidden as i32, c.head_dim as i32);
        let q_width = (c.heads * c.head_dim) as i32;
        let heads = |x: &Array, n: usize, norm: Option<&Array>| {
            let x = x.reshape(&[1, t, n as i32, d], s);
            let x = match norm {
                Some(w) => x.rms_norm(w, c.rms_eps, s),
                None => x,
            };
            x.permute(&[0, 2, 1, 3], s)
        };
        let mut x = self.embed.take_rows(&Array::from_u32(ids, &[t]), s);
        let mut captured = Vec::with_capacity(capture.len());
        let scale = 1.0 / (c.head_dim as f32).sqrt();
        for (index, layer) in self.layers.iter().enumerate() {
            if capture.contains(&index) {
                captured.push(x.reshape(&[t, h], s));
            }
            let a = x.rms_norm(&layer.attn_norm, c.rms_eps, s);
            let (qn, kn) = layer
                .qk_norm
                .as_ref()
                .map_or((None, None), |(q, k)| (Some(q), Some(k)));
            let q = heads(&a.matmul(&layer.q_t, s), c.heads, qn).rope(d, c.rope_theta, 0, s);
            let k = heads(&a.matmul(&layer.k_t, s), c.kv_heads, kn).rope(d, c.rope_theta, 0, s);
            let v = heads(&a.matmul(&layer.v_t, s), c.kv_heads, None);
            let attn = Array::causal_attention(&q, &k, &v, scale, s)
                .permute(&[0, 2, 1, 3], s)
                .reshape(&[t, q_width], s);
            x = x.add(&attn.matmul(&layer.o_t, s), s);
            let m = x.rms_norm(&layer.mlp_norm, c.rms_eps, s);
            let gate = m.matmul(&layer.gate_t, s);
            let act = gate
                .multiply(&gate.sigmoid(s), s)
                .multiply(&m.matmul(&layer.up_t, s), s);
            x = x.add(&act.matmul(&layer.down_t, s), s);
        }
        if capture.contains(&c.layers) {
            captured.push(x.reshape(&[t, h], s));
        }
        (
            x.reshape(&[t, h], s).rms_norm(&self.norm, c.rms_eps, s),
            captured,
        )
    }

    /// Logits for the last position of `ids`.
    pub fn last_logits(&self, ids: &[u32], s: &Stream) -> Vec<f32> {
        let t = ids.len() as i32;
        let (normed, _) = self.hidden(ids, &[], s);
        let last = normed.slice(&[t - 1, 0], &[t, self.config.hidden as i32], s);
        last.matmul(&self.head_t, s).to_vec_f32()
    }

    /// Greedy next-token ids for the last `tail` positions of `ids`.
    pub fn tail_argmax(&self, normed: &Array, t: usize, tail: usize, s: &Stream) -> Vec<u32> {
        let rows = normed.slice(
            &[(t - tail) as i32, 0],
            &[t as i32, self.config.hidden as i32],
            s,
        );
        rows.matmul(&self.head_t, s).argmax(-1, s).to_vec_u32()
    }

    /// Embedding rows for `ids`, `[n, hidden]`.
    pub fn embed(&self, ids: &[u32], s: &Stream) -> Array {
        self.embed
            .take_rows(&Array::from_u32(ids, &[ids.len() as i32]), s)
    }

    pub fn config(&self) -> &LlamaConfig {
        &self.config
    }
}

pub fn read_u32(input: &mut impl Read) -> Option<u32> {
    let mut b = [0u8; 4];
    input.read_exact(&mut b).ok().map(|_| u32::from_le_bytes(b))
}

/// Serve the `llama-v1` protocol until the runner closes stdin.
pub fn serve(input: &mut impl Read, output: &mut impl Write) {
    let mut magic = [0u8; 4];
    if input.read_exact(&mut magic).is_err() || &magic != MAGIC {
        fail(EXIT_PROTOCOL);
    }
    let config_len = read_u32(input)
        .map(|n| n as usize)
        .filter(|n| (1..=MAX_CONFIG_BYTES).contains(n))
        .unwrap_or_else(|| fail(EXIT_PROTOCOL));
    let mut config = vec![0u8; config_len];
    input
        .read_exact(&mut config)
        .unwrap_or_else(|_| fail(EXIT_PROTOCOL));
    let config: LlamaConfig =
        serde_json::from_slice(&config).unwrap_or_else(|_| fail(EXIT_PROTOCOL));
    let mut len = [0u8; 8];
    input
        .read_exact(&mut len)
        .unwrap_or_else(|_| fail(EXIT_PROTOCOL));
    let len = u64::from_le_bytes(len);
    if len == 0 || len > MAX_CHECKPOINT_BYTES {
        fail(EXIT_CHECKPOINT);
    }
    let mut bytes = vec![0u8; len as usize];
    input
        .read_exact(&mut bytes)
        .unwrap_or_else(|_| fail(EXIT_CHECKPOINT));
    let s = Stream::cpu();
    let vocab = config.vocab;
    let model = Llama::load(config, &bytes, &s);
    bytes.fill(0);
    drop(bytes);
    let mut ready = READY.to_vec();
    ready.extend_from_slice(&(vocab as u32).to_le_bytes());
    if output
        .write_all(&ready)
        .and_then(|_| output.flush())
        .is_err()
    {
        return;
    }
    while let Some(n) = read_u32(input) {
        let n = n as usize;
        if n == 0 || n > MAX_TOKENS {
            fail(EXIT_PROTOCOL);
        }
        let mut raw = vec![0u8; n * 4];
        input
            .read_exact(&mut raw)
            .unwrap_or_else(|_| fail(EXIT_PROTOCOL));
        let ids: Vec<u32> = raw
            .chunks_exact(4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .collect();
        if ids.iter().any(|&id| id as usize >= vocab) {
            fail(EXIT_PROTOCOL);
        }
        let logits = model.last_logits(&ids, &s);
        if logits.len() != vocab || !logits.iter().all(|v| v.is_finite()) {
            fail(crate::EXIT_NONFINITE_RESULT);
        }
        let mut reply = Vec::with_capacity(vocab * 4);
        for v in &logits {
            reply.extend_from_slice(&v.to_le_bytes());
        }
        if output
            .write_all(&reply)
            .and_then(|_| output.flush())
            .is_err()
        {
            return;
        }
    }
}
