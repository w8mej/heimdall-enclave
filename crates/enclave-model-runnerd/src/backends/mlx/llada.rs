//! `mlx_llada_v1` artifact format: LLaDA-8B (a Llama-block masked diffusion
//! model) with affine-quantized linear layers for the native worker's
//! `llada-v1` graph (bidirectional attention, no KV cache).
//!
//! The publisher's OLMo-style tensors are renamed to Llama names, so the
//! worker reuses its Llama layer code and topology detection sees the head:
//!
//! | upstream (`model.transformer.`) | artifact                              |
//! |---------------------------------|---------------------------------------|
//! | `wte.weight`                    | `model.embed_tokens.weight` (dense)   |
//! | `ln_f.weight`                   | `model.norm.weight` (dense)           |
//! | `ff_out.weight`                 | `lm_head` (quantized, `head_bits`)    |
//! | `blocks.N.attn_norm.weight`     | `model.layers.N.input_layernorm.weight` |
//! | `blocks.N.ff_norm.weight`       | `model.layers.N.post_attention_layernorm.weight` |
//! | `blocks.N.{q,k,v}_proj.weight`  | `model.layers.N.self_attn.{q,k,v}_proj` |
//! | `blocks.N.attn_out.weight`      | `model.layers.N.self_attn.o_proj`     |
//! | `blocks.N.ff_proj.weight`       | `model.layers.N.mlp.gate_proj` (SiLU side) |
//! | `blocks.N.up_proj.weight`       | `model.layers.N.mlp.up_proj`          |
//! | `blocks.N.ff_out.weight`        | `model.layers.N.mlp.down_proj`        |
//!
//! A quantized linear `P` of shape `[out, in]` is three tensors in MLX's
//! affine layout: `P.weight` (U32 `[out, in * bits / 32]`, element `j` of
//! each word at bits `j * bits..`), `P.scales` and `P.biases` (BF16
//! `[out, in / group]`), with `w ≈ scale * q + bias` per group of `group`
//! consecutive inputs. Dense tensors stay BF16. Metadata:
//! - `enclave_adapter.backend` = `mlx_llada_v1`
//! - `enclave_adapter.llada.config` = the closed [`LladaConfig`] JSON
//! - `enclave_adapter.tokenizer` = the publisher's `tokenizer.json`, verbatim
//! - `is_causal` = `false`
//! All of it is covered by the artifact digest the manifest signs.

use std::collections::BTreeMap;

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use half::bf16;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

/// Backend identifier in artifact metadata.
pub const BACKEND: &str = "mlx_llada_v1";
/// Metadata key for the worker config.
pub const CONFIG_KEY: &str = "enclave_adapter.llada.config";
/// Metadata key for the verbatim tokenizer.json.
pub const TOKENIZER_KEY: &str = super::llama::TOKENIZER_KEY;
/// Mask token name in the LLaDA tokenizer.
pub const MASK_TOKEN: &str = "<|mdm_mask|>";

/// Closed architecture parameters of the worker's `llada-v1` graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LladaConfig {
    /// Model width.
    pub hidden: usize,
    /// Transformer blocks.
    pub layers: usize,
    /// Query heads.
    pub heads: usize,
    /// Key/value heads.
    pub kv_heads: usize,
    /// Per-head width.
    pub head_dim: usize,
    /// MLP width.
    pub intermediate: usize,
    /// Model vocabulary (embedding rows; may exceed the tokenizer's).
    pub vocab: usize,
    /// RoPE base.
    pub rope_theta: f32,
    /// RMSNorm epsilon.
    pub rms_eps: f32,
    /// Bits per quantized block weight (4 or 8).
    pub bits: u32,
    /// Bits per quantized output-head weight (4 or 8).
    pub head_bits: u32,
    /// Inputs per quantization group (32, 64 or 128).
    pub group: usize,
    /// Mask token id (`<|mdm_mask|>`).
    pub mask_token: u32,
}

fn field(c: &Value, key: &str) -> EnclaveResult<usize> {
    c[key]
        .as_u64()
        .filter(|v| (1..=1 << 20).contains(v))
        .map(|v| v as usize)
        .ok_or_else(|| err!(EINVAL, "LLADA_CONFIG_FIELD", "{key}"))
}

fn float(c: &Value, key: &str) -> EnclaveResult<f32> {
    c[key]
        .as_f64()
        .map(|v| v as f32)
        .ok_or_else(|| err!(EINVAL, "LLADA_CONFIG_FIELD", "{key}"))
}

impl LladaConfig {
    /// Derive from the publisher `config.json`, refusing every variant this
    /// graph does not implement exactly (ALiBi, biases, non-RMS norms, QK
    /// norms, tied or scaled logits, other activations or block types).
    pub fn from_hf(config_json: &str, bits: u32, head_bits: u32) -> EnclaveResult<Self> {
        let c: Value =
            serde_json::from_str(config_json).map_err(|_| err!(EINVAL, "LLADA_CONFIG_JSON"))?;
        let exact = [
            ("model_type", json!("llada")),
            ("block_type", json!("llama")),
            ("activation_type", json!("silu")),
            ("layer_norm_type", json!("rms")),
            ("layer_norm_with_affine", json!(true)),
            ("rope", json!(true)),
            ("alibi", json!(false)),
            ("include_bias", json!(false)),
            ("include_qkv_bias", json!(false)),
            ("bias_for_layer_norm", json!(false)),
            ("attention_layer_norm", json!(false)),
            ("input_emb_norm", json!(false)),
            ("scale_logits", json!(false)),
            ("weight_tying", json!(false)),
            ("block_group_size", json!(1)),
        ];
        if exact.iter().any(|(key, want)| &c[*key] != want) || !c["rope_scaling"].is_null() {
            fail!(EINVAL, "LLADA_CONFIG_UNSUPPORTED");
        }
        let hidden = field(&c, "d_model")?;
        let heads = field(&c, "n_heads")?;
        let config = Self {
            hidden,
            layers: field(&c, "n_layers")?,
            heads,
            kv_heads: field(&c, "n_kv_heads")?,
            head_dim: hidden / heads,
            intermediate: field(&c, "mlp_hidden_size")?,
            vocab: field(&c, "embedding_size")?,
            rope_theta: float(&c, "rope_theta")?,
            rms_eps: float(&c, "rms_norm_eps")?,
            bits,
            head_bits,
            group: 64,
            mask_token: field(&c, "mask_token_id")? as u32,
        };
        if field(&c, "vocab_size")? > config.vocab {
            fail!(EINVAL, "LLADA_CONFIG_UNSUPPORTED");
        }
        config.validate()?;
        Ok(config)
    }

    /// Structural invariants the worker also checks.
    pub fn validate(&self) -> EnclaveResult<()> {
        let quant = |b: u32| b == 4 || b == 8;
        let divisible = [self.hidden, self.intermediate, self.heads * self.head_dim]
            .iter()
            .all(|d| d % self.group == 0);
        if self.heads % self.kv_heads != 0
            || self.heads * self.head_dim != self.hidden
            || self.head_dim % 2 != 0
            || !quant(self.bits)
            || !quant(self.head_bits)
            || ![32, 64, 128].contains(&self.group)
            || !divisible
            || self.mask_token as usize >= self.vocab
            || !(self.rope_theta.is_finite() && self.rope_theta > 0.0)
            || !(self.rms_eps.is_finite() && self.rms_eps > 0.0)
        {
            fail!(EINVAL, "LLADA_CONFIG_UNSUPPORTED");
        }
        Ok(())
    }

    /// Artifact layout: dense tensor name -> shape, and quantized linear
    /// prefix -> (`[out, in]`, bits).
    fn layout(
        &self,
    ) -> (
        BTreeMap<String, Vec<usize>>,
        BTreeMap<String, ([usize; 2], u32)>,
    ) {
        let (h, i, q, kv) = (
            self.hidden,
            self.intermediate,
            self.heads * self.head_dim,
            self.kv_heads * self.head_dim,
        );
        let mut dense = BTreeMap::from([
            ("model.embed_tokens.weight".to_owned(), vec![self.vocab, h]),
            ("model.norm.weight".to_owned(), vec![h]),
        ]);
        let mut quant = BTreeMap::from([("lm_head".to_owned(), ([self.vocab, h], self.head_bits))]);
        for l in 0..self.layers {
            let p = format!("model.layers.{l}.");
            dense.insert(format!("{p}input_layernorm.weight"), vec![h]);
            dense.insert(format!("{p}post_attention_layernorm.weight"), vec![h]);
            for (name, shape) in [
                ("self_attn.q_proj", [q, h]),
                ("self_attn.k_proj", [kv, h]),
                ("self_attn.v_proj", [kv, h]),
                ("self_attn.o_proj", [h, q]),
                ("mlp.gate_proj", [i, h]),
                ("mlp.up_proj", [i, h]),
                ("mlp.down_proj", [h, i]),
            ] {
                quant.insert(format!("{p}{name}"), (shape, self.bits));
            }
        }
        (dense, quant)
    }
}

/// Artifact name for an upstream tensor (`None` for anything unknown).
fn rename(upstream: &str) -> Option<String> {
    let rest = upstream.strip_prefix("model.transformer.")?;
    let top = match rest {
        "wte.weight" => Some("model.embed_tokens.weight"),
        "ln_f.weight" => Some("model.norm.weight"),
        "ff_out.weight" => Some("lm_head"),
        _ => None,
    };
    if let Some(name) = top {
        return Some(name.to_owned());
    }
    let (layer, leaf) = rest.strip_prefix("blocks.")?.split_once('.')?;
    let layer: usize = layer
        .parse()
        .ok()
        .filter(|_| !layer.starts_with('0') || layer == "0")?;
    let leaf = match leaf {
        "attn_norm.weight" => "input_layernorm.weight",
        "ff_norm.weight" => "post_attention_layernorm.weight",
        "q_proj.weight" => "self_attn.q_proj",
        "k_proj.weight" => "self_attn.k_proj",
        "v_proj.weight" => "self_attn.v_proj",
        "attn_out.weight" => "self_attn.o_proj",
        "ff_proj.weight" => "mlp.gate_proj",
        "up_proj.weight" => "mlp.up_proj",
        "ff_out.weight" => "mlp.down_proj",
        _ => return None,
    };
    Some(format!("model.layers.{layer}.{leaf}"))
}

/// Affine-quantize a row-major `[rows, cols]` matrix along `cols`.
/// Returns (packed words, BF16 scales, BF16 biases).
pub fn quantize(
    w: &[f32],
    cols: usize,
    bits: u32,
    group: usize,
) -> EnclaveResult<(Vec<u32>, Vec<bf16>, Vec<bf16>)> {
    if !(bits == 4 || bits == 8)
        || group == 0
        || cols % group != 0
        || w.len() % cols != 0
        || !w.iter().all(|v| v.is_finite())
    {
        fail!(EINVAL, "QUANTIZE_INPUT");
    }
    let per_word = (32 / bits) as usize;
    let top = ((1u32 << bits) - 1) as f32;
    let groups = w.len() / group;
    let (mut words, mut scales, mut biases) = (
        Vec::with_capacity(w.len() / per_word),
        Vec::with_capacity(groups),
        Vec::with_capacity(groups),
    );
    for chunk in w.chunks_exact(group) {
        let (lo, hi) = chunk
            .iter()
            .fold((f32::INFINITY, f32::NEG_INFINITY), |(a, b), &v| {
                (a.min(v), b.max(v))
            });
        // Round the group parameters first, then choose codes against the
        // values the worker will actually dequantize with.
        let scale = bf16::from_f32((hi - lo) / top);
        let bias = bf16::from_f32(lo);
        let (s, b) = (scale.to_f32(), bias.to_f32());
        for pack in chunk.chunks_exact(per_word) {
            let mut word = 0u32;
            for (j, &v) in pack.iter().enumerate() {
                let q = if s > 0.0 {
                    ((v - b) / s).round().clamp(0.0, top) as u32
                } else {
                    0
                };
                word |= q << (j as u32 * bits);
            }
            words.push(word);
        }
        scales.push(scale);
        biases.push(bias);
    }
    Ok((words, scales, biases))
}

/// Inverse of [`quantize`] (reference for tests and golden checks).
pub fn dequantize(
    words: &[u32],
    scales: &[bf16],
    biases: &[bf16],
    bits: u32,
    group: usize,
) -> Vec<f32> {
    let per_word = (32 / bits) as usize;
    let mask = (1u32 << bits) - 1;
    let mut out = Vec::with_capacity(words.len() * per_word);
    for (g, chunk) in words.chunks_exact(group / per_word).enumerate() {
        let (s, b) = (scales[g].to_f32(), biases[g].to_f32());
        for word in chunk {
            for j in 0..per_word {
                out.push(s * ((word >> (j as u32 * bits)) & mask) as f32 + b);
            }
        }
    }
    out
}

/// Decode a BF16 or F32 safetensors payload.
fn decode(dtype: &str, bytes: &[u8]) -> EnclaveResult<Vec<f32>> {
    Ok(match dtype {
        "BF16" => bytes
            .chunks_exact(2)
            .map(|b| bf16::from_le_bytes([b[0], b[1]]).to_f32())
            .collect(),
        "F32" => bytes
            .chunks_exact(4)
            .map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .collect(),
        _ => fail!(EINVAL, "LLADA_SOURCE_DTYPE"),
    })
}

struct Stored {
    dtype: &'static str,
    shape: Vec<usize>,
    bytes: Vec<u8>,
}

/// Streaming repacker: feed every upstream tensor once (in any order, e.g.
/// shard by shard), then [`LladaPacker::finish`].
pub struct LladaPacker {
    config: LladaConfig,
    tokenizer_json: String,
    dense: BTreeMap<String, Vec<usize>>,
    quant: BTreeMap<String, ([usize; 2], u32)>,
    out: BTreeMap<String, Stored>,
}

impl LladaPacker {
    /// Start from the publisher config and tokenizer; checks the tokenizer
    /// parses and names the config's mask token.
    pub fn new(
        config_json: &str,
        tokenizer_json: &str,
        bits: u32,
        head_bits: u32,
    ) -> EnclaveResult<Self> {
        let config = LladaConfig::from_hf(config_json, bits, head_bits)?;
        let tokenizer = crate::tokenizer::Tokenizer::from_hf_json(tokenizer_json)?;
        if tokenizer.special(MASK_TOKEN) != Some(config.mask_token)
            || tokenizer.vocab() > config.vocab
        {
            fail!(EINVAL, "LLADA_TOKENIZER_MISMATCH");
        }
        let (dense, quant) = config.layout();
        Ok(Self {
            config,
            tokenizer_json: tokenizer_json.to_owned(),
            dense,
            quant,
            out: BTreeMap::new(),
        })
    }

    /// The closed config this artifact will carry.
    pub fn config(&self) -> &LladaConfig {
        &self.config
    }

    /// Add one upstream tensor (`dtype` BF16 or F32, raw little-endian bytes).
    pub fn add(
        &mut self,
        upstream: &str,
        dtype: &str,
        shape: &[usize],
        bytes: &[u8],
    ) -> EnclaveResult<()> {
        let name =
            rename(upstream).ok_or_else(|| err!(EINVAL, "LLADA_UNKNOWN_TENSOR", "{upstream}"))?;
        let values = decode(dtype, bytes)?;
        if values.len() != shape.iter().product::<usize>() {
            fail!(EINVAL, "LLADA_TENSOR_SIZE", "{upstream}");
        }
        let taken = |out: &BTreeMap<String, Stored>, key: &str| out.contains_key(key);
        if let Some(want) = self.dense.get(&name) {
            if shape != want.as_slice() || taken(&self.out, &name) {
                fail!(EINVAL, "LLADA_TENSOR_SHAPE", "{upstream}");
            }
            let bytes = values
                .iter()
                .flat_map(|v| bf16::from_f32(*v).to_le_bytes())
                .collect();
            self.out.insert(
                name,
                Stored {
                    dtype: "BF16",
                    shape: shape.to_vec(),
                    bytes,
                },
            );
            return Ok(());
        }
        let ([rows, cols], bits) = *self
            .quant
            .get(&name)
            .ok_or_else(|| err!(EINVAL, "LLADA_UNKNOWN_TENSOR", "{upstream}"))?;
        let weight = format!("{name}.weight");
        if shape != [rows, cols] || taken(&self.out, &weight) {
            fail!(EINVAL, "LLADA_TENSOR_SHAPE", "{upstream}");
        }
        let (words, scales, biases) = quantize(&values, cols, bits, self.config.group)?;
        let groups = vec![rows, cols / self.config.group];
        let half_bytes = |v: Vec<bf16>| v.into_iter().flat_map(|x| x.to_le_bytes()).collect();
        self.out.insert(
            weight,
            Stored {
                dtype: "U32",
                shape: vec![rows, cols * bits as usize / 32],
                bytes: words.into_iter().flat_map(u32::to_le_bytes).collect(),
            },
        );
        self.out.insert(
            format!("{name}.scales"),
            Stored {
                dtype: "BF16",
                shape: groups.clone(),
                bytes: half_bytes(scales),
            },
        );
        self.out.insert(
            format!("{name}.biases"),
            Stored {
                dtype: "BF16",
                shape: groups,
                bytes: half_bytes(biases),
            },
        );
        Ok(())
    }

    /// Assemble the artifact; refuses unless every expected tensor arrived.
    pub fn finish(self) -> EnclaveResult<Vec<u8>> {
        let missing = self
            .dense
            .keys()
            .find(|k| !self.out.contains_key(*k))
            .or_else(|| {
                self.quant
                    .keys()
                    .find(|k| !self.out.contains_key(&format!("{k}.weight")))
            });
        if let Some(name) = missing {
            fail!(EINVAL, "LLADA_TENSOR_MISSING", "{name}");
        }
        let mut header = Map::new();
        let mut at = 0usize;
        for (name, t) in &self.out {
            header.insert(name.clone(), json!({"dtype": t.dtype, "shape": t.shape, "data_offsets": [at, at + t.bytes.len()]}));
            at += t.bytes.len();
        }
        let metadata = json!({
            "enclave_adapter.backend": BACKEND,
            CONFIG_KEY: serde_json::to_string(&self.config).map_err(|_| err!(EIO, "LLADA_CONFIG_ENCODE"))?,
            TOKENIZER_KEY: self.tokenizer_json,
            "is_causal": "false",
        });
        header.insert("__metadata__".into(), metadata);
        let mut encoded =
            serde_json::to_vec(&header).map_err(|_| err!(EIO, "SAFETENSORS_HEADER_ENCODE"))?;
        while encoded.len() % 8 != 0 {
            encoded.push(b' ');
        }
        let mut out = Vec::with_capacity(8 + encoded.len() + at);
        out.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
        out.extend_from_slice(&encoded);
        for (_, t) in self.out {
            out.extend_from_slice(&t.bytes);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
