//! Closed EAGLE-3 speculative pair (`eagle3-v1` worker mode): a Qwen3 target
//! (the `llama.rs` graph with QK norm) and a one-layer EAGLE-3 draft head
//! whose forward follows SpecForge's `LlamaForCausalLMEagle3`.
//!
//! The worker keeps nothing between requests; the runner owns the context,
//! the target features, the drafts and the accept/reject decision. Protocol,
//! all integers little-endian:
//!   in:  "EAG1", u32 config length, config JSON `{"target":LlamaConfig,
//!        "draft":DraftConfig}`, u64 checkpoint length, safetensors bytes
//!   out: "MLX4", u32 vocabulary size, u32 feature width (3 x target hidden)
//!   then requests, each a u8 op:
//!   1 VERIFY  in:  u32 t, u32 tail (1..=t, <= MAX_TAIL), t x u32 ids
//!             out: tail x u32 greedy next ids (last `tail` positions),
//!                  t x feature-width f32 target features
//!   2 DRAFT   in:  u32 n (context length, >= 2), u32 k (1..=MAX_DRAFT),
//!                  n x u32 ids, (n - 1) x feature-width f32 features
//!             out: k x u32 drafted target-vocabulary ids
//! Features are the target residual stream at the input of the configured
//! layers (default 2, 14, 25: the outputs of layers 1, 13, 24).

use std::collections::BTreeMap;
use std::io::{Read, Write};

use serde::Deserialize;

use crate::llama::{load_tensors, read_u32, Llama, LlamaConfig, EXIT_CHECKPOINT, EXIT_PROTOCOL};
use crate::mlx::{Array, Stream};

pub const MAGIC: &[u8; 4] = b"EAG1";
pub const READY: &[u8; 4] = b"MLX4";
const MAX_TOKENS: usize = 4096;
const MAX_TAIL: usize = 64;
const MAX_DRAFT: usize = 16;
const MAX_CONFIG_BYTES: usize = 8192;
const MAX_CHECKPOINT_BYTES: u64 = 8 << 30;
const OP_VERIFY: u8 = 1;
const OP_DRAFT: u8 = 2;
const PREFIX: &str = "eagle3.";

/// Draft head parameters, validated by the runner before sending.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftConfig {
    pub hidden: usize,
    pub heads: usize,
    pub kv_heads: usize,
    pub head_dim: usize,
    pub intermediate: usize,
    pub draft_vocab: usize,
    pub rms_eps: f32,
    pub rope_theta: f32,
    pub capture: [usize; 3],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PairConfig {
    target: LlamaConfig,
    draft: DraftConfig,
}

impl DraftConfig {
    fn valid(&self, target: &LlamaConfig) -> bool {
        [
            self.hidden,
            self.heads,
            self.kv_heads,
            self.head_dim,
            self.intermediate,
            self.draft_vocab,
        ]
        .iter()
        .all(|v| (1..=1 << 20).contains(v))
            && self.hidden == target.hidden
            && self.draft_vocab <= target.vocab
            && self.heads % self.kv_heads == 0
            && self.head_dim % 2 == 0
            && self.rms_eps.is_finite()
            && self.rms_eps > 0.0
            && self.rope_theta.is_finite()
            && self.rope_theta > 0.0
            && self.capture.iter().all(|c| *c <= target.layers)
            && self.capture.windows(2).all(|w| w[0] < w[1])
    }

    fn expected_tensors(&self, target_hidden: usize) -> BTreeMap<String, Vec<usize>> {
        let (h, q, kv) = (
            self.hidden,
            self.heads * self.head_dim,
            self.kv_heads * self.head_dim,
        );
        [
            ("eagle_fc.weight", vec![h, 3 * target_hidden]),
            ("d2t", vec![self.draft_vocab]),
            ("lm_head.weight", vec![self.draft_vocab, h]),
            ("norm.weight", vec![h]),
            ("midlayer.hidden_norm.weight", vec![h]),
            ("midlayer.input_layernorm.weight", vec![h]),
            ("midlayer.post_attention_layernorm.weight", vec![h]),
            ("midlayer.self_attn.q_proj.weight", vec![q, 2 * h]),
            ("midlayer.self_attn.k_proj.weight", vec![kv, 2 * h]),
            ("midlayer.self_attn.v_proj.weight", vec![kv, 2 * h]),
            ("midlayer.self_attn.o_proj.weight", vec![h, q]),
            ("midlayer.mlp.gate_proj.weight", vec![self.intermediate, h]),
            ("midlayer.mlp.up_proj.weight", vec![self.intermediate, h]),
            ("midlayer.mlp.down_proj.weight", vec![h, self.intermediate]),
        ]
        .into_iter()
        .map(|(n, s)| (format!("{PREFIX}{n}"), s))
        .collect()
    }
}

/// `x @ W^T` split by input half: `cat(a, b) @ W^T = a @ Wa^T + b @ Wb^T`.
struct SplitProjection {
    first_t: Array,
    second_t: Array,
}

impl SplitProjection {
    fn new(weight: &Array, half: i32, out: i32, s: &Stream) -> Self {
        let t = weight.t(s);
        Self {
            first_t: t.slice(&[0, 0], &[half, out], s),
            second_t: t.slice(&[half, 0], &[2 * half, out], s),
        }
    }
    fn apply(&self, a: &Array, b: &Array, s: &Stream) -> Array {
        a.matmul(&self.first_t, s)
            .add(&b.matmul(&self.second_t, s), s)
    }
    fn eval(&self) {
        self.first_t.eval();
        self.second_t.eval();
    }
}

struct Draft {
    config: DraftConfig,
    fc_t: Array,
    d2t: Vec<i64>,
    head_t: Array,
    norm: Array,
    hidden_norm: Array,
    input_norm: Array,
    post_norm: Array,
    q: SplitProjection,
    k: SplitProjection,
    v: SplitProjection,
    o_t: Array,
    gate_t: Array,
    up_t: Array,
    down_t: Array,
}

pub struct Pair {
    target: Llama,
    draft: Draft,
}

impl Pair {
    fn load(config: PairConfig, bytes: &[u8], s: &Stream) -> Self {
        if !config.draft.valid(&config.target) {
            std::process::exit(EXIT_PROTOCOL);
        }
        let mut expected = config.target.expected_tensors();
        expected.extend(config.draft.expected_tensors(config.target.hidden));
        let mut w = load_tensors(&expected, bytes, s);
        let mut draft_w: BTreeMap<String, Array> = BTreeMap::new();
        let names: Vec<String> = w
            .keys()
            .filter(|k| k.starts_with(PREFIX))
            .cloned()
            .collect();
        for name in names {
            let array = w.remove(&name).expect("listed");
            draft_w.insert(name[PREFIX.len()..].to_owned(), array);
        }
        let vocab = config.target.vocab;
        let target = Llama::from_tensors(config.target, &mut w, s);
        let dc = config.draft;
        let mut take = |n: &str| {
            draft_w
                .remove(n)
                .unwrap_or_else(|| std::process::exit(EXIT_CHECKPOINT))
        };
        let d2t: Vec<i64> = take("d2t")
            .to_vec_f32()
            .into_iter()
            .enumerate()
            .map(|(i, v)| {
                let offset = v as i64;
                let target_id = i as i64 + offset;
                if v.fract() != 0.0 || !(0..vocab as i64).contains(&target_id) {
                    std::process::exit(EXIT_CHECKPOINT);
                }
                offset
            })
            .collect();
        let (h, q, kv) = (
            dc.hidden as i32,
            (dc.heads * dc.head_dim) as i32,
            (dc.kv_heads * dc.head_dim) as i32,
        );
        let draft = Draft {
            fc_t: take("eagle_fc.weight").t(s),
            head_t: take("lm_head.weight").t(s),
            norm: take("norm.weight"),
            hidden_norm: take("midlayer.hidden_norm.weight"),
            input_norm: take("midlayer.input_layernorm.weight"),
            post_norm: take("midlayer.post_attention_layernorm.weight"),
            q: SplitProjection::new(&take("midlayer.self_attn.q_proj.weight"), h, q, s),
            k: SplitProjection::new(&take("midlayer.self_attn.k_proj.weight"), h, kv, s),
            v: SplitProjection::new(&take("midlayer.self_attn.v_proj.weight"), h, kv, s),
            o_t: take("midlayer.self_attn.o_proj.weight").t(s),
            gate_t: take("midlayer.mlp.gate_proj.weight").t(s),
            up_t: take("midlayer.mlp.up_proj.weight").t(s),
            down_t: take("midlayer.mlp.down_proj.weight").t(s),
            d2t,
            config: dc,
        };
        for a in [
            &draft.fc_t,
            &draft.head_t,
            &draft.norm,
            &draft.hidden_norm,
            &draft.input_norm,
            &draft.post_norm,
            &draft.o_t,
            &draft.gate_t,
            &draft.up_t,
            &draft.down_t,
        ] {
            a.eval();
        }
        for p in [&draft.q, &draft.k, &draft.v] {
            p.eval();
        }
        Self { target, draft }
    }

    fn feature_width(&self) -> usize {
        3 * self.target.config().hidden
    }

    /// Greedy next ids for the last `tail` positions and every position's features.
    fn verify(&self, ids: &[u32], tail: usize, s: &Stream) -> (Vec<u32>, Vec<f32>) {
        let (normed, captured) = self.target.hidden(ids, &self.draft.config.capture, s);
        let next = self.target.tail_argmax(&normed, ids.len(), tail, s);
        let h = self.target.config().hidden;
        let parts: Vec<Vec<f32>> = captured.iter().map(Array::to_vec_f32).collect();
        let mut features = Vec::with_capacity(ids.len() * 3 * h);
        for row in 0..ids.len() {
            for part in &parts {
                features.extend_from_slice(&part[row * h..(row + 1) * h]);
            }
        }
        (next, features)
    }

    /// One draft-layer pass over `n` positions; returns `[n, hidden]`.
    fn draft_layer(&self, emb: &Array, hid: &Array, n: i32, s: &Stream) -> Array {
        let d = &self.draft;
        let c = &d.config;
        let hd = c.head_dim as i32;
        let en = emb.rms_norm(&d.input_norm, c.rms_eps, s);
        let hn = hid.rms_norm(&d.hidden_norm, c.rms_eps, s);
        let heads = |x: Array, count: usize| {
            x.reshape(&[1, n, count as i32, hd], s)
                .permute(&[0, 2, 1, 3], s)
        };
        let q = heads(d.q.apply(&en, &hn, s), c.heads).rope(hd, c.rope_theta, 0, s);
        let k = heads(d.k.apply(&en, &hn, s), c.kv_heads).rope(hd, c.rope_theta, 0, s);
        let v = heads(d.v.apply(&en, &hn, s), c.kv_heads);
        let attn = Array::causal_attention(&q, &k, &v, 1.0 / (c.head_dim as f32).sqrt(), s)
            .permute(&[0, 2, 1, 3], s)
            .reshape(&[n, (c.heads * c.head_dim) as i32], s);
        let x = hid.add(&attn.matmul(&d.o_t, s), s);
        let m = x.rms_norm(&d.post_norm, c.rms_eps, s);
        let gate = m.matmul(&d.gate_t, s);
        let act = gate
            .multiply(&gate.sigmoid(s), s)
            .multiply(&m.matmul(&d.up_t, s), s);
        x.add(&act.matmul(&d.down_t, s), s)
    }

    /// Draft `k` tokens after `ids`, given features for positions `0..n-1`.
    fn draft(&self, ids: &[u32], features: &[f32], k: usize, s: &Stream) -> Vec<u32> {
        let d = &self.draft;
        let h = d.config.hidden;
        let positions = ids.len() - 1;
        let feats = Array::from_f32(features, &[positions as i32, self.feature_width() as i32]);
        let mut hid_host = feats.matmul(&d.fc_t, s).to_vec_f32();
        let mut inputs: Vec<u32> = ids[1..].to_vec();
        let mut out = Vec::with_capacity(k);
        for _ in 0..k {
            let n = inputs.len() as i32;
            let emb = self.target.embed(&inputs, s);
            let hid = Array::from_f32(&hid_host, &[n, h as i32]);
            let g = self.draft_layer(&emb, &hid, n, s);
            let last = g.slice(&[n - 1, 0], &[n, h as i32], s);
            let draft_id = last
                .rms_norm(&d.norm, d.config.rms_eps, s)
                .matmul(&d.head_t, s)
                .argmax(-1, s)
                .to_vec_u32()[0] as usize;
            let target_id = (draft_id as i64 + d.d2t[draft_id]) as u32;
            out.push(target_id);
            inputs.push(target_id);
            hid_host.extend(last.to_vec_f32());
        }
        out
    }
}

fn read_exact_or_exit(input: &mut impl Read, buf: &mut [u8]) {
    input
        .read_exact(buf)
        .unwrap_or_else(|_| std::process::exit(EXIT_PROTOCOL));
}

fn read_ids(input: &mut impl Read, n: usize, vocab: usize) -> Vec<u32> {
    let mut raw = vec![0u8; n * 4];
    read_exact_or_exit(input, &mut raw);
    let ids: Vec<u32> = raw
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .collect();
    raw.fill(0);
    if ids.iter().any(|id| *id as usize >= vocab) {
        std::process::exit(EXIT_PROTOCOL);
    }
    ids
}

fn write_or_stop(output: &mut impl Write, reply: &[u8]) -> bool {
    output.write_all(reply).and_then(|_| output.flush()).is_ok()
}

/// Serve the `eagle3-v1` protocol until the runner closes stdin.
pub fn serve(input: &mut impl Read, output: &mut impl Write) {
    let mut magic = [0u8; 4];
    read_exact_or_exit(input, &mut magic);
    if &magic != MAGIC {
        std::process::exit(EXIT_PROTOCOL);
    }
    let config_len = read_u32(input)
        .map(|n| n as usize)
        .filter(|n| (1..=MAX_CONFIG_BYTES).contains(n))
        .unwrap_or_else(|| std::process::exit(EXIT_PROTOCOL));
    let mut config = vec![0u8; config_len];
    read_exact_or_exit(input, &mut config);
    let config: PairConfig =
        serde_json::from_slice(&config).unwrap_or_else(|_| std::process::exit(EXIT_PROTOCOL));
    let mut len = [0u8; 8];
    read_exact_or_exit(input, &mut len);
    let len = u64::from_le_bytes(len);
    if len == 0 || len > MAX_CHECKPOINT_BYTES {
        std::process::exit(EXIT_CHECKPOINT);
    }
    let mut bytes = vec![0u8; len as usize];
    input
        .read_exact(&mut bytes)
        .unwrap_or_else(|_| std::process::exit(EXIT_CHECKPOINT));
    let s = Stream::cpu();
    let vocab = config.target.vocab;
    let pair = Pair::load(config, &bytes, &s);
    bytes.fill(0);
    drop(bytes);
    let width = pair.feature_width();
    let mut ready = READY.to_vec();
    ready.extend_from_slice(&(vocab as u32).to_le_bytes());
    ready.extend_from_slice(&(width as u32).to_le_bytes());
    if !write_or_stop(output, &ready) {
        return;
    }
    let mut op = [0u8; 1];
    while input.read_exact(&mut op).is_ok() {
        let first = read_u32(input)
            .map(|v| v as usize)
            .unwrap_or_else(|| std::process::exit(EXIT_PROTOCOL));
        let second = read_u32(input)
            .map(|v| v as usize)
            .unwrap_or_else(|| std::process::exit(EXIT_PROTOCOL));
        let reply = match op[0] {
            OP_VERIFY => {
                let (t, tail) = (first, second);
                if !(1..=MAX_TOKENS).contains(&t) || !(1..=t.min(MAX_TAIL)).contains(&tail) {
                    std::process::exit(EXIT_PROTOCOL);
                }
                let ids = read_ids(input, t, vocab);
                let (next, features) = pair.verify(&ids, tail, &s);
                if next.len() != tail
                    || features.len() != t * width
                    || !features.iter().all(|v| v.is_finite())
                {
                    std::process::exit(crate::EXIT_NONFINITE_RESULT);
                }
                let mut reply = Vec::with_capacity(4 * (tail + features.len()));
                next.iter()
                    .for_each(|v| reply.extend_from_slice(&v.to_le_bytes()));
                features
                    .iter()
                    .for_each(|v| reply.extend_from_slice(&v.to_le_bytes()));
                reply
            }
            OP_DRAFT => {
                let (n, k) = (first, second);
                if !(2..=MAX_TOKENS).contains(&n) || !(1..=MAX_DRAFT).contains(&k) {
                    std::process::exit(EXIT_PROTOCOL);
                }
                let ids = read_ids(input, n, vocab);
                let mut raw = vec![0u8; (n - 1) * width * 4];
                read_exact_or_exit(input, &mut raw);
                let features: Vec<f32> = raw
                    .chunks_exact(4)
                    .map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                    .collect();
                raw.fill(0);
                if !features.iter().all(|v| v.is_finite()) {
                    std::process::exit(EXIT_PROTOCOL);
                }
                let drafted = pair.draft(&ids, &features, k, &s);
                drafted.iter().flat_map(|v| v.to_le_bytes()).collect()
            }
            _ => std::process::exit(EXIT_PROTOCOL),
        };
        if !write_or_stop(output, &reply) {
            return;
        }
    }
}
