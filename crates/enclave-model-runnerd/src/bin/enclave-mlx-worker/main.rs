//! Native MLX compute worker (L1 alpha, milestone M1).
//!
//! Modes, selected by one exact argument (never a path or graph):
//! - none: the bigram protocol of the Python worker (`backends/mlx/worker.py`):
//!   one 256x256 little-endian f32 table on stdin, reply `MLX1`, then 256 f32
//!   logits (`one_hot(byte) @ table`) per one-byte request.
//! - `llama-v1`: the closed Llama-family graph in `llama.rs`.
//! - `rwkv7-v1`: the closed RWKV-7 graph in `rwkv7.rs` (runner-owned state).
//! - `eagle3-v1`: the closed Qwen3 target + EAGLE-3 draft pair in `eagle3.rs`.
//! - `vjepa2-v1`: the closed V-JEPA 2 ViT encoder in `vjepa2.rs`.
//! - `llada-v1`: the closed quantized LLaDA diffusion graph in `llada.rs` (GPU).
//!
//! No Python interpreter, wheel, model-defined code or arbitrary graph is
//! involved. Exit codes 2-5 match the Python worker; 6 is an MLX error, 7 a
//! protocol violation and 8 a refused checkpoint. Built only with the
//! `mlx-native` feature, linking the system `libmlxc`.

mod eagle3;
mod llada;
mod llama;
mod mlx;
mod rwkv7;
mod vjepa2;

use std::io::{Read, Write};

use mlx::{Array, Stream};

const SIDE: usize = 256;
const TABLE_BYTES: usize = SIDE * SIDE * 4;
const READY: &[u8; 4] = b"MLX1";
const EXIT_ARGUMENTS: i32 = 2;
const EXIT_SHORT_TABLE: i32 = 3;
const EXIT_NONFINITE_TABLE: i32 = 4;
pub const EXIT_NONFINITE_RESULT: i32 = 5;

fn bigram(stdin: &mut impl Read, stdout: &mut impl Write) {
    let mut raw = vec![0u8; TABLE_BYTES];
    if stdin.read_exact(&mut raw).is_err() {
        std::process::exit(EXIT_SHORT_TABLE);
    }
    let weights: Vec<f32> = raw.chunks_exact(4).map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]])).collect();
    raw.fill(0);
    drop(raw);
    if !weights.iter().all(|w| w.is_finite()) {
        std::process::exit(EXIT_NONFINITE_TABLE);
    }
    let stream = Stream::cpu();
    let table = Array::from_f32(&weights, &[SIDE as i32, SIDE as i32]);
    table.eval();
    drop(weights);
    if stdout.write_all(READY).and_then(|_| stdout.flush()).is_err() {
        return;
    }
    let mut request = [0u8; 1];
    let mut one_hot = vec![0f32; SIDE];
    while let Ok(1) = stdin.read(&mut request) {
        one_hot.fill(0.0);
        one_hot[request[0] as usize] = 1.0;
        let input = Array::from_f32(&one_hot, &[1, SIDE as i32]);
        let logits = input.matmul(&table, &stream).to_vec_f32();
        if logits.len() != SIDE || !logits.iter().all(|v| v.is_finite()) {
            std::process::exit(EXIT_NONFINITE_RESULT);
        }
        let reply: Vec<u8> = logits.iter().flat_map(|v| v.to_le_bytes()).collect();
        if stdout.write_all(&reply).and_then(|_| stdout.flush()).is_err() {
            break;
        }
    }
}

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    mlx::install_error_handler();
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    match args.as_slice() {
        [] => bigram(&mut stdin, &mut stdout),
        [mode] if mode == "llama-v1" => llama::serve(&mut stdin, &mut stdout),
        [mode] if mode == "rwkv7-v1" => rwkv7::serve(&mut stdin, &mut stdout),
        [mode] if mode == "eagle3-v1" => eagle3::serve(&mut stdin, &mut stdout),
        [mode] if mode == "vjepa2-v1" => vjepa2::serve(&mut stdin, &mut stdout),
        [mode] if mode == "llada-v1" => llada::serve(&mut stdin, &mut stdout),
        _ => std::process::exit(EXIT_ARGUMENTS),
    }
}
