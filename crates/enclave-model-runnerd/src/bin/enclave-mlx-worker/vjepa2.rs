//! Closed V-JEPA 2 ViT encoder (`vjepa2-v1` worker mode).
//!
//! Follows transformers' `VJEPA2Model.encoder`: a Conv3d tubelet patch
//! embedding, pre-LN blocks with 3-axis rotary attention (depth, height,
//! width sections of each head; pairs rotated interleaved with a repeated
//! frequency table, exactly as `rotate_queries_or_keys`), exact-erf GELU
//! MLPs and a final LayerNorm. The predictor and any runner-side heads in
//! the checkpoint are never read. Protocol, integers little-endian:
//!   in:  "VJE1", u32 config length, config JSON (`VjepaConfig`), u64
//!        checkpoint length, safetensors bytes
//!   out: "MLX5", u32 latent width
//!   then per request  in: image x image grey u8 pixels (one frame)
//!                     out: latent width x f32 (mean of the final tokens)
//! The frame is replicated to RGB, scaled to [0, 1], ImageNet-normalised and
//! repeated across the tubelet, as the reference preprocessing does.

use std::collections::BTreeMap;
use std::io::{Read, Write};

use serde::Deserialize;

use crate::llama::{load_tensors_ignoring, read_u32, EXIT_CHECKPOINT, EXIT_PROTOCOL};
use crate::mlx::{Array, Stream};

pub const MAGIC: &[u8; 4] = b"VJE1";
pub const READY: &[u8; 4] = b"MLX5";
const MAX_CONFIG_BYTES: usize = 4096;
const MAX_CHECKPOINT_BYTES: u64 = 4 << 30;
const MEAN: [f32; 3] = [0.485, 0.456, 0.406];
const STD: [f32; 3] = [0.229, 0.224, 0.225];
const ROPE_BASE: f32 = 10000.0;

/// Encoder geometry, validated by the runner before sending.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VjepaConfig {
    pub hidden: usize,
    pub layers: usize,
    pub heads: usize,
    pub mlp: usize,
    pub patch: usize,
    pub tubelet: usize,
    pub image: usize,
    pub eps: f32,
}

impl VjepaConfig {
    fn valid(&self) -> bool {
        [
            self.hidden,
            self.layers,
            self.heads,
            self.mlp,
            self.patch,
            self.tubelet,
            self.image,
        ]
        .iter()
        .all(|v| (1..=1 << 16).contains(v))
            && self.hidden % self.heads == 0
            && self.image % self.patch == 0
            && self.eps.is_finite()
            && self.eps > 0.0
            && self.image <= 1024
    }
    fn head_dim(&self) -> usize {
        self.hidden / self.heads
    }
    fn grid(&self) -> usize {
        self.image / self.patch
    }
    fn tokens(&self) -> usize {
        self.grid() * self.grid()
    }
    fn patch_len(&self) -> usize {
        3 * self.tubelet * self.patch * self.patch
    }

    fn expected_tensors(&self) -> BTreeMap<String, Vec<usize>> {
        let (h, m) = (self.hidden, self.mlp);
        let mut t = BTreeMap::new();
        t.insert(
            "encoder.embeddings.patch_embeddings.proj.weight".into(),
            vec![h, 3, self.tubelet, self.patch, self.patch],
        );
        t.insert(
            "encoder.embeddings.patch_embeddings.proj.bias".into(),
            vec![h],
        );
        t.insert("encoder.layernorm.weight".into(), vec![h]);
        t.insert("encoder.layernorm.bias".into(), vec![h]);
        for l in 0..self.layers {
            for (name, shape) in [
                ("norm1.weight", vec![h]),
                ("norm1.bias", vec![h]),
                ("norm2.weight", vec![h]),
                ("norm2.bias", vec![h]),
                ("attention.query.weight", vec![h, h]),
                ("attention.query.bias", vec![h]),
                ("attention.key.weight", vec![h, h]),
                ("attention.key.bias", vec![h]),
                ("attention.value.weight", vec![h, h]),
                ("attention.value.bias", vec![h]),
                ("attention.proj.weight", vec![h, h]),
                ("attention.proj.bias", vec![h]),
                ("mlp.fc1.weight", vec![m, h]),
                ("mlp.fc1.bias", vec![m]),
                ("mlp.fc2.weight", vec![h, m]),
                ("mlp.fc2.bias", vec![h]),
            ] {
                t.insert(format!("encoder.layer.{l}.{name}"), shape);
            }
        }
        t
    }
}

struct Linear {
    weight_t: Array,
    bias: Array,
}

impl Linear {
    fn apply(&self, x: &Array, s: &Stream) -> Array {
        x.matmul(&self.weight_t, s).add(&self.bias, s)
    }
}

struct Block {
    norm1: (Array, Array),
    norm2: (Array, Array),
    query: Linear,
    key: Linear,
    value: Linear,
    proj: Linear,
    fc1: Linear,
    fc2: Linear,
}

pub struct Encoder {
    config: VjepaConfig,
    patch: Linear,
    blocks: Vec<Block>,
    norm: (Array, Array),
    cos: Array,
    sin: Array,
    swap: Array,
}

/// Per-token cos/sin tables `[tokens, head_dim]` for the three rotary
/// sections (frame, row, column); trailing dims stay unrotated.
fn rope_tables(c: &VjepaConfig) -> (Vec<f32>, Vec<f32>) {
    let d = c.head_dim();
    let section = 2 * ((d / 3) / 2);
    let half = section / 2;
    let omega: Vec<f32> = (0..half)
        .map(|j| 1.0 / ROPE_BASE.powf(j as f32 / half as f32))
        .collect();
    let (mut cos, mut sin) = (vec![1.0f32; c.tokens() * d], vec![0.0f32; c.tokens() * d]);
    for token in 0..c.tokens() {
        // One tubelet: every token sits in frame 0.
        let positions = [0.0f32, (token / c.grid()) as f32, (token % c.grid()) as f32];
        for (k, pos) in positions.iter().enumerate() {
            for i in 0..section {
                let f = pos * omega[i % half];
                cos[token * d + k * section + i] = f.cos();
                sin[token * d + k * section + i] = f.sin();
            }
        }
    }
    (cos, sin)
}

/// `y = x @ S` swaps each pair with a sign: `(x0, x1) -> (-x1, x0)`.
fn pair_swap(d: usize) -> Vec<f32> {
    let mut m = vec![0.0f32; d * d];
    for k in 0..d / 2 {
        m[(2 * k + 1) * d + 2 * k] = -1.0;
        m[(2 * k) * d + 2 * k + 1] = 1.0;
    }
    m
}

impl Encoder {
    fn load(config: VjepaConfig, bytes: &[u8], s: &Stream) -> Self {
        if !config.valid() {
            std::process::exit(EXIT_PROTOCOL);
        }
        let mut w = load_tensors_ignoring(
            &config.expected_tensors(),
            &["predictor.", "enclave_adapter."],
            bytes,
            s,
        );
        let mut take = |n: &str| {
            w.remove(n)
                .unwrap_or_else(|| std::process::exit(EXIT_CHECKPOINT))
        };
        let h = config.hidden as i32;
        let patch = Linear {
            weight_t: take("encoder.embeddings.patch_embeddings.proj.weight")
                .reshape(&[h, config.patch_len() as i32], s)
                .t(s),
            bias: take("encoder.embeddings.patch_embeddings.proj.bias"),
        };
        let norm = (
            take("encoder.layernorm.weight"),
            take("encoder.layernorm.bias"),
        );
        let blocks = (0..config.layers)
            .map(|l| {
                let mut lin = |n: &str| Linear {
                    weight_t: take(&format!("encoder.layer.{l}.{n}.weight")).t(s),
                    bias: take(&format!("encoder.layer.{l}.{n}.bias")),
                };
                let (query, key, value, proj) = (
                    lin("attention.query"),
                    lin("attention.key"),
                    lin("attention.value"),
                    lin("attention.proj"),
                );
                let (fc1, fc2) = (lin("mlp.fc1"), lin("mlp.fc2"));
                let mut vec = |n: &str| take(&format!("encoder.layer.{l}.{n}"));
                Block {
                    norm1: (vec("norm1.weight"), vec("norm1.bias")),
                    norm2: (vec("norm2.weight"), vec("norm2.bias")),
                    query,
                    key,
                    value,
                    proj,
                    fc1,
                    fc2,
                }
            })
            .collect::<Vec<_>>();
        let d = config.head_dim();
        let (cos, sin) = rope_tables(&config);
        let shape = [config.tokens() as i32, d as i32];
        let encoder = Self {
            cos: Array::from_f32(&cos, &shape),
            sin: Array::from_f32(&sin, &shape),
            swap: Array::from_f32(&pair_swap(d), &[d as i32, d as i32]),
            config,
            patch,
            blocks,
            norm,
        };
        for a in [
            &encoder.patch.weight_t,
            &encoder.patch.bias,
            &encoder.norm.0,
            &encoder.norm.1,
        ] {
            a.eval();
        }
        for b in &encoder.blocks {
            for a in [&b.norm1.0, &b.norm1.1, &b.norm2.0, &b.norm2.1] {
                a.eval();
            }
            for lin in [&b.query, &b.key, &b.value, &b.proj, &b.fc1, &b.fc2] {
                lin.weight_t.eval();
                lin.bias.eval();
            }
        }
        encoder
    }

    /// `[tokens, patch_len]` in Conv3d weight order (channel, time, row, col).
    fn patches(&self, pixels: &[u8]) -> Vec<f32> {
        let c = &self.config;
        let (p, t, image) = (c.patch, c.tubelet, c.image);
        let mut out = Vec::with_capacity(c.tokens() * c.patch_len());
        for token in 0..c.tokens() {
            let (gy, gx) = (token / c.grid(), token % c.grid());
            for ch in 0..3 {
                for _time in 0..t {
                    for y in 0..p {
                        for x in 0..p {
                            let v = pixels[(gy * p + y) * image + gx * p + x] as f32 / 255.0;
                            out.push((v - MEAN[ch]) / STD[ch]);
                        }
                    }
                }
            }
        }
        out
    }

    fn rotate(&self, x: &Array, s: &Stream) -> Array {
        x.multiply(&self.cos, s)
            .add(&x.matmul(&self.swap, s).multiply(&self.sin, s), s)
    }

    pub fn latent(&self, pixels: &[u8], s: &Stream) -> Vec<f32> {
        let c = &self.config;
        let (n, h, heads, d) = (
            c.tokens() as i32,
            c.hidden as i32,
            c.heads as i32,
            c.head_dim() as i32,
        );
        let patches = Array::from_f32(&self.patches(pixels), &[n, c.patch_len() as i32]);
        let mut x = self.patch.apply(&patches, s);
        let split = |t: Array| t.reshape(&[1, n, heads, d], s).permute(&[0, 2, 1, 3], s);
        let scale = 1.0 / (c.head_dim() as f32).sqrt();
        let half = Array::scalar(0.5);
        let one = Array::scalar(1.0);
        let inv_sqrt2 = Array::scalar(std::f32::consts::FRAC_1_SQRT_2);
        for b in &self.blocks {
            let a = x.layer_norm(Some((&b.norm1.0, &b.norm1.1)), c.eps, s);
            let q = self.rotate(&split(b.query.apply(&a, s)), s);
            let k = self.rotate(&split(b.key.apply(&a, s)), s);
            let v = split(b.value.apply(&a, s));
            let attn = Array::full_attention(&q, &k, &v, scale, s)
                .permute(&[0, 2, 1, 3], s)
                .reshape(&[n, h], s);
            x = x.add(&b.proj.apply(&attn, s), s);
            let m = b
                .fc1
                .apply(&x.layer_norm(Some((&b.norm2.0, &b.norm2.1)), c.eps, s), s);
            let gelu = m
                .multiply(&half, s)
                .multiply(&one.add(&m.multiply(&inv_sqrt2, s).erf(s), s), s);
            x = x.add(&b.fc2.apply(&gelu, s), s);
        }
        let normed = x.layer_norm(Some((&self.norm.0, &self.norm.1)), c.eps, s);
        normed
            .sum_keep(0, s)
            .multiply(&Array::scalar(1.0 / n as f32), s)
            .to_vec_f32()
    }
}

/// Serve the `vjepa2-v1` protocol until the runner closes stdin.
pub fn serve(input: &mut impl Read, output: &mut impl Write) {
    let mut magic = [0u8; 4];
    input
        .read_exact(&mut magic)
        .unwrap_or_else(|_| std::process::exit(EXIT_PROTOCOL));
    if &magic != MAGIC {
        std::process::exit(EXIT_PROTOCOL);
    }
    let config_len = read_u32(input)
        .map(|n| n as usize)
        .filter(|n| (1..=MAX_CONFIG_BYTES).contains(n))
        .unwrap_or_else(|| std::process::exit(EXIT_PROTOCOL));
    let mut config = vec![0u8; config_len];
    input
        .read_exact(&mut config)
        .unwrap_or_else(|_| std::process::exit(EXIT_PROTOCOL));
    let config: VjepaConfig =
        serde_json::from_slice(&config).unwrap_or_else(|_| std::process::exit(EXIT_PROTOCOL));
    let mut len = [0u8; 8];
    input
        .read_exact(&mut len)
        .unwrap_or_else(|_| std::process::exit(EXIT_PROTOCOL));
    let len = u64::from_le_bytes(len);
    if len == 0 || len > MAX_CHECKPOINT_BYTES {
        std::process::exit(EXIT_CHECKPOINT);
    }
    let mut bytes = vec![0u8; len as usize];
    input
        .read_exact(&mut bytes)
        .unwrap_or_else(|_| std::process::exit(EXIT_CHECKPOINT));
    let s = Stream::cpu();
    let (width, frame) = (config.hidden, config.image * config.image);
    let encoder = Encoder::load(config, &bytes, &s);
    bytes.fill(0);
    drop(bytes);
    let mut ready = READY.to_vec();
    ready.extend_from_slice(&(width as u32).to_le_bytes());
    if output
        .write_all(&ready)
        .and_then(|_| output.flush())
        .is_err()
    {
        return;
    }
    let mut pixels = vec![0u8; frame];
    while input.read_exact(&mut pixels).is_ok() {
        let latent = encoder.latent(&pixels, &s);
        pixels.fill(0);
        if latent.len() != width || !latent.iter().all(|v| v.is_finite()) {
            std::process::exit(crate::EXIT_NONFINITE_RESULT);
        }
        let reply: Vec<u8> = latent.iter().flat_map(|v| v.to_le_bytes()).collect();
        if output
            .write_all(&reply)
            .and_then(|_| output.flush())
            .is_err()
        {
            return;
        }
    }
}
