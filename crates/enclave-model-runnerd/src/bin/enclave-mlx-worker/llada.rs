//! Closed LLaDA graph (`llada-v1` worker mode): Llama blocks with
//! bidirectional attention and affine-quantized linear layers, on the GPU.
//! The runner's `backends/mlx/llada.rs` defines the artifact layout.
//!
//! Protocol on the private pipes, all integers little-endian:
//!   in:  "LDA1", u32 config length, config JSON (`LladaConfig`, unknown
//!        fields refused), u64 checkpoint length, safetensors bytes
//!   out: "MLX2", u32 vocabulary size
//!   then per request  in: u32 n (1..=MAX_TOKENS), u32 tail (1..=min(n,
//!                         MAX_TAIL)), n x u32 token ids (< vocabulary)
//!                     out: tail x vocabulary f32 logits, one row per each
//!                          of the last `tail` positions
//! The whole sequence is recomputed per request (no cache): every position
//! attends to every other, as masked diffusion requires.

use std::collections::BTreeMap;
use std::io::{Read, Write};

use serde::Deserialize;

use crate::llama::{load_typed, read_u32, Spec, EXIT_CHECKPOINT, EXIT_PROTOCOL};
use crate::mlx::{Array, Stream};

pub const MAGIC: &[u8; 4] = b"LDA1";
pub const READY: &[u8; 4] = b"MLX2";
/// Largest accepted sequence (prompt plus block), in tokens.
pub const MAX_TOKENS: usize = 2048;
/// Largest number of logit rows one request returns.
pub const MAX_TAIL: usize = 256;
const MAX_CONFIG_BYTES: usize = 4096;
const MAX_CHECKPOINT_BYTES: u64 = 8 << 30;

/// Architecture parameters, validated by the runner before sending.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LladaConfig {
    pub hidden: usize,
    pub layers: usize,
    pub heads: usize,
    pub kv_heads: usize,
    pub head_dim: usize,
    pub intermediate: usize,
    pub vocab: usize,
    pub rope_theta: f32,
    pub rms_eps: f32,
    pub bits: u32,
    pub head_bits: u32,
    pub group: usize,
    pub mask_token: u32,
}

impl LladaConfig {
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
        let quant = |b: u32| b == 4 || b == 8;
        positive.iter().all(|v| (1..=1 << 20).contains(v))
            && self.heads % self.kv_heads == 0
            && self.heads * self.head_dim == self.hidden
            && self.head_dim % 2 == 0
            && quant(self.bits)
            && quant(self.head_bits)
            && [32, 64, 128].contains(&self.group)
            && [self.hidden, self.intermediate]
                .iter()
                .all(|d| d % self.group == 0)
            && (self.mask_token as usize) < self.vocab
            && self.rope_theta.is_finite()
            && self.rope_theta > 0.0
            && self.rms_eps.is_finite()
            && self.rms_eps > 0.0
    }

    /// Every tensor the graph reads, with its shape and kind.
    fn expected(&self) -> BTreeMap<String, Spec> {
        let (h, i, q, kv) = (
            self.hidden,
            self.intermediate,
            self.heads * self.head_dim,
            self.kv_heads * self.head_dim,
        );
        let mut t = BTreeMap::new();
        let dense = |shape: Vec<usize>| Spec {
            shape,
            packed: false,
        };
        let mut linear =
            |t: &mut BTreeMap<String, Spec>, prefix: String, [out, inp]: [usize; 2], bits: u32| {
                t.insert(
                    format!("{prefix}.weight"),
                    Spec {
                        shape: vec![out, inp * bits as usize / 32],
                        packed: true,
                    },
                );
                t.insert(
                    format!("{prefix}.scales"),
                    dense(vec![out, inp / self.group]),
                );
                t.insert(
                    format!("{prefix}.biases"),
                    dense(vec![out, inp / self.group]),
                );
            };
        t.insert(
            "model.embed_tokens.weight".into(),
            dense(vec![self.vocab, h]),
        );
        t.insert("model.norm.weight".into(), dense(vec![h]));
        linear(&mut t, "lm_head".into(), [self.vocab, h], self.head_bits);
        for l in 0..self.layers {
            let p = format!("model.layers.{l}.");
            t.insert(format!("{p}input_layernorm.weight"), dense(vec![h]));
            t.insert(
                format!("{p}post_attention_layernorm.weight"),
                dense(vec![h]),
            );
            for (name, shape) in [
                ("self_attn.q_proj", [q, h]),
                ("self_attn.k_proj", [kv, h]),
                ("self_attn.v_proj", [kv, h]),
                ("self_attn.o_proj", [h, q]),
                ("mlp.gate_proj", [i, h]),
                ("mlp.up_proj", [i, h]),
                ("mlp.down_proj", [h, i]),
            ] {
                linear(&mut t, format!("{p}{name}"), shape, self.bits);
            }
        }
        t
    }
}

/// An affine-quantized linear layer (`x @ W^T`).
struct Linear {
    w: Array,
    scales: Array,
    biases: Array,
    group: i32,
    bits: i32,
}

impl Linear {
    fn apply(&self, x: &Array, s: &Stream) -> Array {
        x.quantized_matmul(
            &self.w,
            &self.scales,
            &self.biases,
            self.group,
            self.bits,
            s,
        )
    }
    fn arrays(&self) -> [&Array; 3] {
        [&self.w, &self.scales, &self.biases]
    }
}

struct Block {
    attn_norm: Array,
    mlp_norm: Array,
    q: Linear,
    k: Linear,
    v: Linear,
    o: Linear,
    gate: Linear,
    up: Linear,
    down: Linear,
}

pub struct Llada {
    config: LladaConfig,
    embed: Array,
    norm: Array,
    head: Linear,
    blocks: Vec<Block>,
}

impl Llada {
    pub fn load(config: LladaConfig, bytes: &[u8], s: &Stream) -> Self {
        if !config.valid() {
            std::process::exit(EXIT_PROTOCOL);
        }
        let mut w = load_typed(&config.expected(), &[], bytes, s);
        let mut take = |name: &str| {
            w.remove(name)
                .unwrap_or_else(|| std::process::exit(EXIT_CHECKPOINT))
        };
        let group = config.group as i32;
        let mut linear = |prefix: &str, bits: u32, take: &mut dyn FnMut(&str) -> Array| Linear {
            w: take(&format!("{prefix}.weight")),
            scales: take(&format!("{prefix}.scales")),
            biases: take(&format!("{prefix}.biases")),
            group,
            bits: bits as i32,
        };
        let embed = take("model.embed_tokens.weight");
        let norm = take("model.norm.weight");
        let head = linear("lm_head", config.head_bits, &mut take);
        let blocks: Vec<Block> = (0..config.layers)
            .map(|l| {
                let p = format!("model.layers.{l}.");
                let mut q = |n: &str| linear(&format!("{p}{n}"), config.bits, &mut take);
                let (qp, kp, vp, op) = (
                    q("self_attn.q_proj"),
                    q("self_attn.k_proj"),
                    q("self_attn.v_proj"),
                    q("self_attn.o_proj"),
                );
                let (gate, up, down) = (q("mlp.gate_proj"), q("mlp.up_proj"), q("mlp.down_proj"));
                Block {
                    attn_norm: take(&format!("{p}input_layernorm.weight")),
                    mlp_norm: take(&format!("{p}post_attention_layernorm.weight")),
                    q: qp,
                    k: kp,
                    v: vp,
                    o: op,
                    gate,
                    up,
                    down,
                }
            })
            .collect();
        for array in [&embed, &norm].into_iter().chain(head.arrays()) {
            array.eval();
        }
        for b in &blocks {
            for array in [&b.attn_norm, &b.mlp_norm] {
                array.eval();
            }
            for lin in [&b.q, &b.k, &b.v, &b.o, &b.gate, &b.up, &b.down] {
                for array in lin.arrays() {
                    array.eval();
                }
            }
        }
        Self {
            config,
            embed,
            norm,
            head,
            blocks,
        }
    }

    /// Logits `[tail, vocab]` for the last `tail` positions of `ids`.
    pub fn tail_logits(&self, ids: &[u32], tail: usize, s: &Stream) -> Vec<f32> {
        let c = &self.config;
        let t = ids.len() as i32;
        let (h, d) = (c.hidden as i32, c.head_dim as i32);
        let heads =
            |x: &Array, n: usize| x.reshape(&[1, t, n as i32, d], s).permute(&[0, 2, 1, 3], s);
        let scale = 1.0 / (c.head_dim as f32).sqrt();
        let mut x = self.embed.take_rows(&Array::from_u32(ids, &[t]), s);
        for b in &self.blocks {
            let a = x.rms_norm(&b.attn_norm, c.rms_eps, s);
            let q = heads(&b.q.apply(&a, s), c.heads).rope(d, c.rope_theta, 0, s);
            let k = heads(&b.k.apply(&a, s), c.kv_heads).rope(d, c.rope_theta, 0, s);
            let v = heads(&b.v.apply(&a, s), c.kv_heads);
            let attn = Array::full_attention(&q, &k, &v, scale, s)
                .permute(&[0, 2, 1, 3], s)
                .reshape(&[t, h], s);
            x = x.add(&b.o.apply(&attn, s), s);
            let m = x.rms_norm(&b.mlp_norm, c.rms_eps, s);
            let gate = b.gate.apply(&m, s);
            let act = gate
                .multiply(&gate.sigmoid(s), s)
                .multiply(&b.up.apply(&m, s), s);
            x = x.add(&b.down.apply(&act, s), s);
        }
        let rows = x
            .slice(&[t - tail as i32, 0], &[t, h], s)
            .rms_norm(&self.norm, c.rms_eps, s);
        self.head.apply(&rows, s).to_f32(s).to_vec_f32()
    }
}

/// Serve the `llada-v1` protocol until the runner closes stdin.
pub fn serve(input: &mut impl Read, output: &mut impl Write) {
    let fail = |code: i32| -> ! { std::process::exit(code) };
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
    let config: LladaConfig =
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
    let s = Stream::gpu();
    let vocab = config.vocab;
    let model = Llada::load(config, &bytes, &s);
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
        let tail = read_u32(input)
            .map(|t| t as usize)
            .unwrap_or_else(|| fail(EXIT_PROTOCOL));
        if n == 0 || n > MAX_TOKENS || tail == 0 || tail > n.min(MAX_TAIL) {
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
        let logits = model.tail_logits(&ids, tail, &s);
        if logits.len() != tail * vocab || !logits.iter().all(|v| v.is_finite()) {
            fail(crate::EXIT_NONFINITE_RESULT);
        }
        let reply: Vec<u8> = logits.iter().flat_map(|v| v.to_le_bytes()).collect();
        if output
            .write_all(&reply)
            .and_then(|_| output.flush())
            .is_err()
        {
            return;
        }
    }
}
