//! Closed RWKV-7 ("x070") graph (`rwkv7-v1` worker mode).
//!
//! The recurrent state never lives here between requests: the runner owns it
//! (sealed system snapshot, per-session arenas, anchoring, wipe) and sends it
//! with every request. Protocol, all integers little-endian:
//!   in:  "RWK1", u32 config length, config JSON (`Rwkv7Config`, unknown
//!        fields refused), u64 checkpoint length, safetensors bytes
//!   out: "MLX3", u32 vocabulary size, u32 state length (f32 count)
//!   then per request  in: u32 n (1..=MAX_TOKENS), state, n x u32 token ids
//!                     out: new state, vocabulary x f32 logits after the last id
//! State layout per layer: att_x_prev[C], att_kv[H, N_v, N_k], ffn_x_prev[C].
//! The math follows the reference `RWKV_x070` CPU path of `rwkv` 0.8.32.

use std::collections::BTreeMap;
use std::io::{Read, Write};

use serde::Deserialize;

use crate::llama::{load_tensors, read_u32, EXIT_CHECKPOINT, EXIT_PROTOCOL};
use crate::mlx::{Array, Stream};

pub const MAGIC: &[u8; 4] = b"RWK1";
pub const READY: &[u8; 4] = b"MLX3";
/// Largest accepted request, in tokens.
pub const MAX_TOKENS: usize = 4096;
const MAX_CONFIG_BYTES: usize = 4096;
const MAX_CHECKPOINT_BYTES: u64 = 4 << 30;
const LN_EPS: f32 = 1e-5;
const GROUP_NORM_EPS: f32 = 64e-5;
/// `exp(-0.5)`, the reference decay scale.
const DECAY_SCALE: f32 = 0.606531;
const NORMALIZE_EPS: f32 = 1e-12;

/// Architecture parameters, validated by the runner before sending.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rwkv7Config {
    pub hidden: usize,
    pub layers: usize,
    pub heads: usize,
    pub head_size: usize,
    pub ffn: usize,
    pub vocab: usize,
}

/// Low-rank widths, read from block 0/1 and then required everywhere.
struct Ranks {
    decay: usize,
    iclr: usize,
    gate: usize,
    value: usize,
}

impl Rwkv7Config {
    fn valid(&self) -> bool {
        [
            self.hidden,
            self.layers,
            self.heads,
            self.head_size,
            self.ffn,
            self.vocab,
        ]
        .iter()
        .all(|v| (1..=1 << 20).contains(v))
            && self.heads * self.head_size == self.hidden
            && self.layers >= 2
    }

    fn state_len(&self) -> usize {
        self.layers * (2 * self.hidden + self.heads * self.head_size * self.head_size)
    }

    fn expected_tensors(&self, r: &Ranks) -> BTreeMap<String, Vec<usize>> {
        let c = self.hidden;
        let mut t = BTreeMap::new();
        for (name, shape) in [
            ("emb.weight", vec![self.vocab, c]),
            ("head.weight", vec![self.vocab, c]),
            ("ln_out.weight", vec![c]),
            ("ln_out.bias", vec![c]),
            ("blocks.0.ln0.weight", vec![c]),
            ("blocks.0.ln0.bias", vec![c]),
        ] {
            t.insert(name.to_owned(), shape);
        }
        for l in 0..self.layers {
            let mut entries = vec![
                ("ln1.weight", vec![c]),
                ("ln1.bias", vec![c]),
                ("ln2.weight", vec![c]),
                ("ln2.bias", vec![c]),
                ("att.x_r", vec![1, 1, c]),
                ("att.x_w", vec![1, 1, c]),
                ("att.x_k", vec![1, 1, c]),
                ("att.x_v", vec![1, 1, c]),
                ("att.x_a", vec![1, 1, c]),
                ("att.x_g", vec![1, 1, c]),
                ("att.w0", vec![1, 1, c]),
                ("att.w1", vec![c, r.decay]),
                ("att.w2", vec![r.decay, c]),
                ("att.a0", vec![1, 1, c]),
                ("att.a1", vec![c, r.iclr]),
                ("att.a2", vec![r.iclr, c]),
                ("att.g1", vec![c, r.gate]),
                ("att.g2", vec![r.gate, c]),
                ("att.k_k", vec![1, 1, c]),
                ("att.k_a", vec![1, 1, c]),
                ("att.r_k", vec![self.heads, self.head_size]),
                ("att.receptance.weight", vec![c, c]),
                ("att.key.weight", vec![c, c]),
                ("att.value.weight", vec![c, c]),
                ("att.output.weight", vec![c, c]),
                ("att.ln_x.weight", vec![c]),
                ("att.ln_x.bias", vec![c]),
                ("ffn.x_k", vec![1, 1, c]),
                ("ffn.key.weight", vec![self.ffn, c]),
                ("ffn.value.weight", vec![c, self.ffn]),
            ];
            if l > 0 {
                entries.extend([
                    ("att.v0", vec![1, 1, c]),
                    ("att.v1", vec![c, r.value]),
                    ("att.v2", vec![r.value, c]),
                ]);
            }
            for (name, shape) in entries {
                t.insert(format!("blocks.{l}.{name}"), shape);
            }
        }
        t
    }
}

/// Second dimension of a named 2-D tensor in the raw header.
fn rank_of(header: &serde_json::Value, name: &str) -> usize {
    header[name]["shape"]
        .as_array()
        .filter(|s| s.len() == 2)
        .and_then(|s| s[1].as_u64())
        .filter(|v| (1..=4096).contains(v))
        .unwrap_or_else(|| std::process::exit(EXIT_CHECKPOINT)) as usize
}

fn ranks(bytes: &[u8]) -> Ranks {
    let len = bytes
        .get(..8)
        .map(|b| u64::from_le_bytes(b.try_into().expect("eight bytes")) as usize)
        .unwrap_or_else(|| std::process::exit(EXIT_CHECKPOINT));
    let header: serde_json::Value = bytes
        .get(8..8usize.saturating_add(len))
        .and_then(|h| serde_json::from_slice(h).ok())
        .unwrap_or_else(|| std::process::exit(EXIT_CHECKPOINT));
    Ranks {
        decay: rank_of(&header, "blocks.0.att.w1"),
        iclr: rank_of(&header, "blocks.0.att.a1"),
        gate: rank_of(&header, "blocks.0.att.g1"),
        value: rank_of(&header, "blocks.1.att.v1"),
    }
}

struct Layer {
    ln1: (Array, Array),
    ln2: (Array, Array),
    x_r: Array,
    x_w: Array,
    x_k: Array,
    x_v: Array,
    x_a: Array,
    x_g: Array,
    w0: Array,
    w1: Array,
    w2: Array,
    a0: Array,
    a1: Array,
    a2: Array,
    v: Option<(Array, Array, Array)>,
    g1: Array,
    g2: Array,
    k_k: Array,
    k_a: Array,
    r_k: Array,
    receptance_t: Array,
    key_t: Array,
    value_t: Array,
    output_t: Array,
    ln_x: (Array, Array),
    ffn_x_k: Array,
    ffn_key_t: Array,
    ffn_value_t: Array,
}

/// Loaded model: vectors flattened to `[C]`, matrices pre-transposed.
pub struct Rwkv7 {
    config: Rwkv7Config,
    emb: Array,
    ln0: (Array, Array),
    layers: Vec<Layer>,
    ln_out: (Array, Array),
    head_t: Array,
}

/// One layer's slice of the runner-owned state.
struct LayerState {
    att_x: Array,
    kv: Array,
    ffn_x: Array,
}

impl Rwkv7 {
    pub fn load(config: Rwkv7Config, bytes: &[u8], s: &Stream) -> Self {
        if !config.valid() {
            std::process::exit(EXIT_PROTOCOL);
        }
        let mut w = load_tensors(&config.expected_tensors(&ranks(bytes)), bytes, s);
        let c = config.hidden as i32;
        let mut take = |name: String| {
            w.remove(&name)
                .unwrap_or_else(|| std::process::exit(EXIT_CHECKPOINT))
        };
        let emb = take("emb.weight".into());
        let head_t = take("head.weight".into()).t(s);
        let ln_out = (take("ln_out.weight".into()), take("ln_out.bias".into()));
        let ln0 = (
            take("blocks.0.ln0.weight".into()),
            take("blocks.0.ln0.bias".into()),
        );
        let layers = (0..config.layers)
            .map(|l| {
                let mut get = |n: &str| take(format!("blocks.{l}.{n}"));
                let mut vec = |n: &str| get(n).reshape(&[c], s);
                let ln1 = (vec("ln1.weight"), vec("ln1.bias"));
                let ln2 = (vec("ln2.weight"), vec("ln2.bias"));
                let [x_r, x_w, x_k, x_v, x_a, x_g] = [
                    "att.x_r", "att.x_w", "att.x_k", "att.x_v", "att.x_a", "att.x_g",
                ]
                .map(&mut vec);
                let [w0, a0, k_k, k_a, ffn_x_k] =
                    ["att.w0", "att.a0", "att.k_k", "att.k_a", "ffn.x_k"].map(&mut vec);
                let ln_x = (vec("att.ln_x.weight"), vec("att.ln_x.bias"));
                let v =
                    (l > 0).then(|| (get("att.v0").reshape(&[c], s), get("att.v1"), get("att.v2")));
                Layer {
                    ln1,
                    ln2,
                    x_r,
                    x_w,
                    x_k,
                    x_v,
                    x_a,
                    x_g,
                    w0,
                    a0,
                    k_k,
                    k_a,
                    ffn_x_k,
                    ln_x,
                    v,
                    w1: get("att.w1"),
                    w2: get("att.w2"),
                    a1: get("att.a1"),
                    a2: get("att.a2"),
                    g1: get("att.g1"),
                    g2: get("att.g2"),
                    r_k: get("att.r_k"),
                    receptance_t: get("att.receptance.weight").t(s),
                    key_t: get("att.key.weight").t(s),
                    value_t: get("att.value.weight").t(s),
                    output_t: get("att.output.weight").t(s),
                    ffn_key_t: get("ffn.key.weight").t(s),
                    ffn_value_t: get("ffn.value.weight").t(s),
                }
            })
            .collect::<Vec<_>>();
        let model = Self {
            config,
            emb,
            ln0,
            layers,
            ln_out,
            head_t,
        };
        model.materialize();
        model
    }

    fn materialize(&self) {
        for a in [
            &self.emb,
            &self.ln0.0,
            &self.ln0.1,
            &self.ln_out.0,
            &self.ln_out.1,
            &self.head_t,
        ] {
            a.eval();
        }
        for l in &self.layers {
            let mut all = vec![
                &l.ln1.0,
                &l.ln1.1,
                &l.ln2.0,
                &l.ln2.1,
                &l.x_r,
                &l.x_w,
                &l.x_k,
                &l.x_v,
                &l.x_a,
                &l.x_g,
                &l.w0,
                &l.w1,
                &l.w2,
                &l.a0,
                &l.a1,
                &l.a2,
                &l.g1,
                &l.g2,
                &l.k_k,
                &l.k_a,
                &l.r_k,
                &l.receptance_t,
                &l.key_t,
                &l.value_t,
                &l.output_t,
                &l.ln_x.0,
                &l.ln_x.1,
                &l.ffn_x_k,
                &l.ffn_key_t,
                &l.ffn_value_t,
            ];
            if let Some((v0, v1, v2)) = &l.v {
                all.extend([v0, v1, v2]);
            }
            for a in all {
                a.eval();
            }
        }
    }

    fn time_mix(
        &self,
        l: &Layer,
        x: &Array,
        st: &mut LayerState,
        v_first: &mut Option<Array>,
        s: &Stream,
    ) -> Array {
        let (h, n) = (self.config.heads as i32, self.config.head_size as i32);
        let c = h * n;
        let d = st.att_x.subtract(x, s);
        let mix = |m: &Array| x.add(&d.multiply(m, s), s);
        let (xr, xw, xk, xv, xa, xg) = (
            mix(&l.x_r),
            mix(&l.x_w),
            mix(&l.x_k),
            mix(&l.x_v),
            mix(&l.x_a),
            mix(&l.x_g),
        );
        let r = xr.matmul(&l.receptance_t, s);
        let w = xw.matmul(&l.w1, s).tanh(s).matmul(&l.w2, s);
        let k = xk.matmul(&l.key_t, s);
        let mut v = xv.matmul(&l.value_t, s);
        let a =
            l.a0.add(&xa.matmul(&l.a1, s).matmul(&l.a2, s), s)
                .sigmoid(s);
        let g = xg.matmul(&l.g1, s).sigmoid(s).matmul(&l.g2, s);
        let kk = k.multiply(&l.k_k, s).reshape(&[h, n], s);
        let norm = kk
            .square(s)
            .sum_keep(-1, s)
            .sqrt(s)
            .maximum(&Array::scalar(NORMALIZE_EPS), s);
        let kk = kk.divide(&norm, s).reshape(&[c], s);
        let one = Array::scalar(1.0);
        let k = k.multiply(&one.add(&a.subtract(&one, s).multiply(&l.k_a, s), s), s);
        match (&l.v, v_first.as_ref()) {
            (None, _) => *v_first = Some(v.reshape(&[c], s)),
            (Some((v0, v1, v2)), Some(first)) => {
                let gate = v0.add(&xv.matmul(v1, s).matmul(v2, s), s).sigmoid(s);
                v = v.add(&first.subtract(&v, s).multiply(&gate, s), s);
            }
            (Some(_), None) => std::process::exit(EXIT_PROTOCOL),
        }
        let decay = Array::scalar(-DECAY_SCALE)
            .multiply(&l.w0.add(&w, s).sigmoid(s), s)
            .exp(s);
        // S' = S * w_j - (S kk)_i (kk a)_j + v_i k_j, per head.
        let kv = &st.kv;
        let s_kk = kv.matmul(&kk.reshape(&[h, n, 1], s), s);
        let kka = kk.multiply(&a, s).reshape(&[h, 1, n], s);
        let vk = v
            .reshape(&[h, n, 1], s)
            .matmul(&k.reshape(&[h, 1, n], s), s);
        let new_kv = kv
            .multiply(&decay.reshape(&[h, 1, n], s), s)
            .subtract(&s_kk.matmul(&kka, s), s)
            .add(&vk, s);
        let out = new_kv
            .matmul(&r.reshape(&[h, n, 1], s), s)
            .reshape(&[h, n], s);
        let out = out
            .layer_norm(None, GROUP_NORM_EPS, s)
            .reshape(&[c], s)
            .multiply(&l.ln_x.0, s)
            .add(&l.ln_x.1, s);
        let bonus = r
            .multiply(&k, s)
            .reshape(&[h, n], s)
            .multiply(&l.r_k, s)
            .sum_keep(-1, s)
            .multiply(&v.reshape(&[h, n], s), s)
            .reshape(&[c], s);
        st.kv = new_kv;
        st.att_x = x.reshape(&[c], s);
        out.add(&bonus, s).multiply(&g, s).matmul(&l.output_t, s)
    }

    fn channel_mix(l: &Layer, x: &Array, st: &mut LayerState, c: i32, s: &Stream) -> Array {
        let k = x.add(&st.ffn_x.subtract(x, s).multiply(&l.ffn_x_k, s), s);
        let k = k
            .matmul(&l.ffn_key_t, s)
            .maximum(&Array::scalar(0.0), s)
            .square(s);
        st.ffn_x = x.reshape(&[c], s);
        k.matmul(&l.ffn_value_t, s)
    }

    /// Advance `state` over `ids`; return the new state and the last logits.
    pub fn advance(&self, state: &[f32], ids: &[u32], s: &Stream) -> (Vec<f32>, Vec<f32>) {
        let cfg = &self.config;
        let (c, h, n) = (cfg.hidden, cfg.heads as i32, cfg.head_size as i32);
        let per = 2 * c + cfg.heads * cfg.head_size * cfg.head_size;
        let mut layers: Vec<LayerState> = state
            .chunks_exact(per)
            .map(|chunk| LayerState {
                att_x: Array::from_f32(&chunk[..c], &[c as i32]),
                kv: Array::from_f32(&chunk[c..per - c], &[h, n, n]),
                ffn_x: Array::from_f32(&chunk[per - c..], &[c as i32]),
            })
            .collect();
        let mut x = Array::scalar(0.0);
        for &id in ids {
            x = self
                .emb
                .take_rows(&Array::from_u32(&[id], &[1]), s)
                .reshape(&[c as i32], s)
                .layer_norm(Some((&self.ln0.0, &self.ln0.1)), LN_EPS, s);
            let mut v_first = None;
            for (layer, st) in self.layers.iter().zip(layers.iter_mut()) {
                let a = x.layer_norm(Some((&layer.ln1.0, &layer.ln1.1)), LN_EPS, s);
                x = x.add(&self.time_mix(layer, &a, st, &mut v_first, s), s);
                let f = x.layer_norm(Some((&layer.ln2.0, &layer.ln2.1)), LN_EPS, s);
                x = x.add(&Self::channel_mix(layer, &f, st, c as i32, s), s);
            }
            // Bound the lazy graph to one token.
            x.eval();
            for st in &layers {
                st.att_x.eval();
                st.kv.eval();
                st.ffn_x.eval();
            }
        }
        let logits = x
            .layer_norm(Some((&self.ln_out.0, &self.ln_out.1)), LN_EPS, s)
            .reshape(&[1, c as i32], s)
            .matmul(&self.head_t, s)
            .to_vec_f32();
        let mut out = Vec::with_capacity(state.len());
        for st in &layers {
            out.extend(st.att_x.to_vec_f32());
            out.extend(st.kv.to_vec_f32());
            out.extend(st.ffn_x.to_vec_f32());
        }
        (out, logits)
    }
}

fn read_exact_or_exit(input: &mut impl Read, buf: &mut [u8], code: i32) {
    input
        .read_exact(buf)
        .unwrap_or_else(|_| std::process::exit(code));
}

/// Serve the `rwkv7-v1` protocol until the runner closes stdin.
pub fn serve(input: &mut impl Read, output: &mut impl Write) {
    let mut magic = [0u8; 4];
    read_exact_or_exit(input, &mut magic, EXIT_PROTOCOL);
    if &magic != MAGIC {
        std::process::exit(EXIT_PROTOCOL);
    }
    let config_len = read_u32(input)
        .map(|n| n as usize)
        .filter(|n| (1..=MAX_CONFIG_BYTES).contains(n))
        .unwrap_or_else(|| std::process::exit(EXIT_PROTOCOL));
    let mut config = vec![0u8; config_len];
    read_exact_or_exit(input, &mut config, EXIT_PROTOCOL);
    let config: Rwkv7Config =
        serde_json::from_slice(&config).unwrap_or_else(|_| std::process::exit(EXIT_PROTOCOL));
    let mut len = [0u8; 8];
    read_exact_or_exit(input, &mut len, EXIT_PROTOCOL);
    let len = u64::from_le_bytes(len);
    if len == 0 || len > MAX_CHECKPOINT_BYTES {
        std::process::exit(EXIT_CHECKPOINT);
    }
    let mut bytes = vec![0u8; len as usize];
    read_exact_or_exit(input, &mut bytes, EXIT_CHECKPOINT);
    let s = Stream::cpu();
    let (vocab, state_len) = (config.vocab, config.state_len());
    let model = Rwkv7::load(config, &bytes, &s);
    bytes.fill(0);
    drop(bytes);
    let mut ready = READY.to_vec();
    ready.extend_from_slice(&(vocab as u32).to_le_bytes());
    ready.extend_from_slice(&(state_len as u32).to_le_bytes());
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
            std::process::exit(EXIT_PROTOCOL);
        }
        let mut raw = vec![0u8; state_len * 4 + n * 4];
        read_exact_or_exit(input, &mut raw, EXIT_PROTOCOL);
        let state: Vec<f32> = raw[..state_len * 4]
            .chunks_exact(4)
            .map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .collect();
        let ids: Vec<u32> = raw[state_len * 4..]
            .chunks_exact(4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .collect();
        raw.fill(0);
        if ids.iter().any(|&id| id as usize >= vocab) || !state.iter().all(|v| v.is_finite()) {
            std::process::exit(EXIT_PROTOCOL);
        }
        let (new_state, logits) = model.advance(&state, &ids, &s);
        if new_state.len() != state_len
            || logits.len() != vocab
            || !new_state.iter().chain(&logits).all(|v| v.is_finite())
        {
            std::process::exit(crate::EXIT_NONFINITE_RESULT);
        }
        let mut reply = Vec::with_capacity((state_len + vocab) * 4);
        for v in new_state.iter().chain(&logits) {
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
