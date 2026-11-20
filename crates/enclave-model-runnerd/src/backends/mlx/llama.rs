//! `mlx_llama_v1` artifact format and its native-worker backend.
//!
//! An admissible artifact is one safetensors file holding the publisher's
//! Llama-family tensors unchanged, plus an explicit `lm_head.weight` (a copy
//! of the embedding when the publisher ties them, so topology detection sees
//! the generative head that really exists), and metadata:
//! - `enclave_adapter.backend` = `mlx_llama_v1`
//! - `enclave_adapter.llama.config` = the worker's closed `LlamaConfig` JSON
//! - `enclave_adapter.tokenizer` = the publisher's `tokenizer.json`, verbatim
//! All of it is covered by the artifact digest the manifest signs.

use std::collections::BTreeMap;

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

/// Backend identifier in artifact metadata.
pub const BACKEND: &str = "mlx_llama_v1";
/// Metadata key for the worker config.
pub const CONFIG_KEY: &str = "enclave_adapter.llama.config";
/// Metadata key for the verbatim tokenizer.json.
pub const TOKENIZER_KEY: &str = "enclave_adapter.tokenizer";
const HEAD: &str = "lm_head.weight";
const EMBED: &str = "model.embed_tokens.weight";

/// Closed architecture parameters understood by the worker's `llama-v1` graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlamaConfig {
    /// Model width.
    pub hidden: usize,
    /// Decoder layers.
    pub layers: usize,
    /// Query heads.
    pub heads: usize,
    /// Key/value heads.
    pub kv_heads: usize,
    /// Per-head width.
    pub head_dim: usize,
    /// MLP width.
    pub intermediate: usize,
    /// Vocabulary size.
    pub vocab: usize,
    /// RoPE base.
    pub rope_theta: f32,
    /// RMSNorm epsilon.
    pub rms_eps: f32,
    /// Output head tied to the embedding.
    pub tie_embeddings: bool,
    /// Per-head RMSNorm on queries and keys before RoPE (Qwen3).
    #[serde(default)]
    pub qk_norm: bool,
}

fn field(config: &Value, key: &str) -> EnclaveResult<usize> {
    config[key]
        .as_u64()
        .filter(|v| (1..=1 << 20).contains(v))
        .map(|v| v as usize)
        .ok_or_else(|| err!(EINVAL, "LLAMA_CONFIG_FIELD", "{key}"))
}

impl LlamaConfig {
    /// Derive from a publisher `config.json` (`llama`, or `qwen3` = Llama
    /// plus QK norm), refusing anything this graph does not implement exactly
    /// (biases, rope scaling, sliding windows, other activations).
    pub fn from_hf(config_json: &str) -> EnclaveResult<Self> {
        let c: Value =
            serde_json::from_str(config_json).map_err(|_| err!(EINVAL, "LLAMA_CONFIG_JSON"))?;
        let qk_norm = c["model_type"] == "qwen3";
        let unsupported = !(c["model_type"] == "llama" || qk_norm)
            || c["use_sliding_window"] == true
            || c["hidden_act"] != "silu"
            || !c["rope_scaling"].is_null()
            || c["attention_bias"] == true
            || c["mlp_bias"] == true;
        if unsupported {
            fail!(EINVAL, "LLAMA_CONFIG_UNSUPPORTED");
        }
        let hidden = field(&c, "hidden_size")?;
        let heads = field(&c, "num_attention_heads")?;
        let kv_heads = field(&c, "num_key_value_heads")?;
        let head_dim = if c["head_dim"].is_null() {
            hidden / heads
        } else {
            field(&c, "head_dim")?
        };
        let rope_theta = c["rope_theta"]
            .as_f64()
            .ok_or_else(|| err!(EINVAL, "LLAMA_CONFIG_FIELD", "rope_theta"))?
            as f32;
        let rms_eps = c["rms_norm_eps"]
            .as_f64()
            .ok_or_else(|| err!(EINVAL, "LLAMA_CONFIG_FIELD", "rms_norm_eps"))?
            as f32;
        let config = Self {
            hidden,
            layers: field(&c, "num_hidden_layers")?,
            heads,
            kv_heads,
            head_dim,
            intermediate: field(&c, "intermediate_size")?,
            vocab: field(&c, "vocab_size")?,
            rope_theta,
            rms_eps,
            tie_embeddings: c["tie_word_embeddings"] == true,
            qk_norm,
        };
        config.validate()?;
        Ok(config)
    }

    /// Structural invariants the worker also checks.
    pub fn validate(&self) -> EnclaveResult<()> {
        let llama_width = self.qk_norm || self.heads * self.head_dim == self.hidden;
        if self.heads % self.kv_heads != 0
            || !llama_width
            || self.head_dim % 2 != 0
            || !(self.rope_theta.is_finite() && self.rope_theta > 0.0)
            || !(self.rms_eps.is_finite() && self.rms_eps > 0.0)
        {
            fail!(EINVAL, "LLAMA_CONFIG_UNSUPPORTED");
        }
        Ok(())
    }
}

/// Repack a publisher checkpoint into an `mlx_llama_v1` artifact.
pub fn repack_hf(
    config_json: &str,
    tokenizer_json: &str,
    weights: &[u8],
) -> EnclaveResult<Vec<u8>> {
    let mut config = LlamaConfig::from_hf(config_json)?;
    crate::tokenizer::Tokenizer::from_hf_json(tokenizer_json)?;
    let header_len = weights
        .get(..8)
        .map(|b| u64::from_le_bytes(b.try_into().expect("eight bytes")) as usize)
        .ok_or_else(|| err!(EINVAL, "SAFETENSORS_TRUNCATED"))?;
    let data_start = 8usize
        .checked_add(header_len)
        .filter(|end| *end <= weights.len())
        .ok_or_else(|| err!(EINVAL, "SAFETENSORS_HEADER_LEN"))?;
    let mut header: Map<String, Value> = serde_json::from_slice(&weights[8..data_start])
        .map_err(|_| err!(EINVAL, "SAFETENSORS_HEADER_JSON"))?;
    header.remove("__metadata__");
    let mut data = weights[data_start..].to_vec();
    if config.tie_embeddings {
        if header.contains_key(HEAD) {
            fail!(EINVAL, "LLAMA_TIED_HEAD_PRESENT");
        }
        let mut entry = header
            .get(EMBED)
            .cloned()
            .ok_or_else(|| err!(EINVAL, "LLAMA_EMBEDDING_MISSING"))?;
        let [start, end] =
            [0, 1].map(|i| entry["data_offsets"][i].as_u64().unwrap_or(u64::MAX) as usize);
        if start > end || end > data.len() {
            fail!(EINVAL, "SAFETENSORS_OFFSETS");
        }
        let copy = data[start..end].to_vec();
        let at = data.len();
        data.extend_from_slice(&copy);
        entry["data_offsets"] = json!([at, at + copy.len()]);
        header.insert(HEAD.into(), entry);
        config.tie_embeddings = false;
    }
    let metadata: BTreeMap<&str, String> = BTreeMap::from([
        ("enclave_adapter.backend", BACKEND.to_owned()),
        (
            CONFIG_KEY,
            serde_json::to_string(&config).map_err(|_| err!(EIO, "LLAMA_CONFIG_ENCODE"))?,
        ),
        (TOKENIZER_KEY, tokenizer_json.to_owned()),
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

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"{"model_type":"llama","hidden_act":"silu","rope_scaling":null,
        "hidden_size":8,"num_attention_heads":2,"num_key_value_heads":1,"num_hidden_layers":1,
        "intermediate_size":16,"vocab_size":300,"rope_theta":10000.0,"rms_norm_eps":1e-5,
        "tie_word_embeddings":true}"#;

    #[test]
    fn unsupported_architecture_variants_are_refused() {
        for (from, to) in [
            ("\"silu\"", "\"gelu\""),
            ("null", "{\"type\":\"linear\"}"),
            ("\"llama\"", "\"mistral\""),
        ] {
            let changed = CONFIG.replacen(from, to, 1);
            assert!(
                LlamaConfig::from_hf(&changed)
                    .unwrap_err()
                    .is("LLAMA_CONFIG_UNSUPPORTED"),
                "{to}"
            );
        }
        let c = LlamaConfig::from_hf(CONFIG).unwrap();
        assert_eq!((c.head_dim, c.tie_embeddings), (4, true));
    }
}
