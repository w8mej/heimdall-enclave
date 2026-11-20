//! Actual MLX CPU compute in an owned private-pipe worker (debug builds only).
//!
//! The worker source is embedded in this binary, and receives only a fixed
//! bounded dense bigram tensor; it imports no model-defined Python or pickle.
//! Python/framework provisioning, child resource aggregation and physical state
//! erasure are not production-approved by this bounded development backend.
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};

use crate::classes::ar::CausalBackend;
use crate::safetensors::TensorIndex;
use crate::topology::{OpAttestor, OpFamily};

#[path = "current_owner.rs"]
mod current_owner;

/// Audited code constructing the only admitted MLX graph for this backend.
pub const WORKER_SOURCE: &str = include_str!("worker.py");

pub(super) struct Worker {
    pub(super) child: Child,
    pub(super) input: ChildStdin,
    pub(super) output: ChildStdout,
    pub(super) failed: bool,
}
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn nonblocking(fd: i32) -> EnclaveResult<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        fail!(EIO, "MLX_PIPE_FLAGS");
    }
    Ok(())
}

fn wait_ready(fd: i32, event: i16, deadline: Instant) -> EnclaveResult<()> {
    loop {
        let left = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| err!(ETIMEDOUT, "MLX_WORKER_DEADLINE"))?;
        let mut descriptor = libc::pollfd {
            fd,
            events: event,
            revents: 0,
        };
        let milliseconds = left.as_millis().clamp(1, i32::MAX as u128) as i32;
        let status = unsafe { libc::poll(&mut descriptor, 1, milliseconds) };
        if status < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            fail!(EIO, "MLX_PIPE_POLL");
        }
        if status > 0 {
            if descriptor.revents & event != 0 {
                return Ok(());
            }
            fail!(EIO, "MLX_WORKER_CLOSED");
        }
    }
}

pub(super) fn send(
    writer: &mut ChildStdin,
    mut data: &[u8],
    deadline: Instant,
) -> EnclaveResult<()> {
    while !data.is_empty() {
        wait_ready(writer.as_raw_fd(), libc::POLLOUT, deadline)?;
        match writer.write(data) {
            Ok(0) => fail!(EIO, "MLX_WRITE_CLOSED"),
            Ok(count) => data = &data[count..],
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) =>
            {
                continue
            }
            Err(_) => fail!(EIO, "MLX_WRITE_FAILED"),
        }
    }
    Ok(())
}

pub(super) fn receive(
    reader: &mut ChildStdout,
    data: &mut [u8],
    deadline: Instant,
) -> EnclaveResult<()> {
    let mut offset = 0;
    while offset < data.len() {
        wait_ready(reader.as_raw_fd(), libc::POLLIN, deadline)?;
        match reader.read(&mut data[offset..]) {
            Ok(0) => fail!(EIO, "MLX_READ_CLOSED"),
            Ok(count) => offset += count,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) =>
            {
                continue
            }
            Err(_) => fail!(EIO, "MLX_READ_FAILED"),
        }
    }
    Ok(())
}

/// Select the worker: the native `enclave-mlx-worker` when MCPMAC_MLX_WORKER
/// names it, otherwise the embedded Python worker under MCPMAC_MLX_PYTHON and
/// MCPMAC_MLX_SITE. Both speak the same pipe protocol. Absolute paths only.
fn worker_command() -> EnclaveResult<Command> {
    if let Some(worker) = std::env::var_os("MCPMAC_MLX_WORKER").map(PathBuf::from) {
        if !worker.is_absolute() || !worker.is_file() {
            fail!(EINVAL, "MLX_RUNTIME_PATH_INVALID");
        }
        return Ok(Command::new(worker));
    }
    let python = std::env::var_os("MCPMAC_MLX_PYTHON")
        .map(PathBuf::from)
        .ok_or_else(|| err!(ENOSYS, "MLX_RUNTIME_NOT_CONFIGURED"))?;
    let site = std::env::var_os("MCPMAC_MLX_SITE")
        .map(PathBuf::from)
        .ok_or_else(|| err!(ENOSYS, "MLX_RUNTIME_NOT_CONFIGURED"))?;
    if !python.is_absolute() || !python.is_file() || !site.is_absolute() || !site.is_dir() {
        fail!(EINVAL, "MLX_RUNTIME_PATH_INVALID");
    }
    let mut command = Command::new(python);
    command
        .args(["-I", "-S", "-u", "-c", WORKER_SOURCE])
        .arg(site);
    Ok(command)
}

/// Private real framework worker for the bounded 256x256 mechanical model.
pub struct MlxBigram {
    worker: Mutex<Worker>,
}
impl std::fmt::Debug for MlxBigram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlxBigram").finish_non_exhaustive()
    }
}

impl MlxBigram {
    /// Load actual authenticated tensor bytes and start the fixed MLX graph.
    /// Debug-only configuration uses an explicit absolute MCPMAC_MLX_WORKER
    /// (native) or MCPMAC_MLX_PYTHON and MCPMAC_MLX_SITE paths. No inherited
    /// Python path or global installation.
    pub fn load(idx: &TensorIndex, bytes: &[u8], attest: &mut OpAttestor) -> EnclaveResult<Self> {
        if !cfg!(debug_assertions) {
            fail!(EPERM, "MLX_DEVELOPMENT_ONLY");
        }
        if !cfg!(target_os = "macos") {
            fail!(ENOSYS, "MLX_PLATFORM_UNAVAILABLE");
        }
        if idx.tensors.keys().any(|name| {
            !matches!(
                name.as_str(),
                "lm_head.weight" | "enclave_adapter.ar.bigram"
            )
        }) {
            fail!(EACCES, "MLX_UNSUPPORTED_CHECKPOINT_TENSOR");
        }
        current_owner::with_weights(
            idx.f32(bytes, "enclave_adapter.ar.bigram", &[256, 256])?,
            |weights| {
                if weights.iter().any(|v| !v.is_finite()) {
                    fail!(EINVAL, "MLX_NONFINITE_CHECKPOINT");
                }
                attest.admit(OpFamily::CausalDecode)?;
                let mut command = worker_command()?;
                let mut child = command
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                    .map_err(|_| err!(EIO, "MLX_WORKER_SPAWN"))?;
                let input = child.stdin.take().ok_or_else(|| err!(EIO, "MLX_STDIN"))?;
                let output = child.stdout.take().ok_or_else(|| err!(EIO, "MLX_STDOUT"))?;
                let mut worker = Worker {
                    child,
                    input,
                    output,
                    failed: false,
                };
                nonblocking(worker.input.as_raw_fd())?;
                nonblocking(worker.output.as_raw_fd())?;
                let deadline = Instant::now() + Duration::from_secs(10);
                current_owner::with_load_frame(weights, |raw| {
                    send(&mut worker.input, raw, deadline)?;
                    current_owner::read_ready(|ready| receive(&mut worker.output, ready, deadline))
                })?;
                Ok(Self {
                    worker: Mutex::new(worker),
                })
            },
        )
    }
}

impl CausalBackend for MlxBigram {
    fn next(&self, prefix: &[u8]) -> EnclaveResult<[f32; 256]> {
        let mut worker = self
            .worker
            .lock()
            .map_err(|_| err!(EIO, "MLX_WORKER_LOCK"))?;
        if worker.failed {
            fail!(EIO, "MLX_WORKER_REVOKED");
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        let result = (|| {
            current_owner::send_request(prefix, |request| {
                send(&mut worker.input, request, deadline)
            })?;
            current_owner::read_logits(|raw| receive(&mut worker.output, raw, deadline))
        })();
        if result.is_err() {
            worker.failed = true;
            let _ = worker.child.kill();
        }
        result
    }
}

/// Start the native worker (MCPMAC_MLX_WORKER) in one closed graph mode,
/// with an empty environment and non-blocking private pipes.
pub(super) fn spawn_native(mode: &str) -> EnclaveResult<Worker> {
    let worker = std::env::var_os("MCPMAC_MLX_WORKER")
        .map(PathBuf::from)
        .ok_or_else(|| err!(ENOSYS, "MLX_RUNTIME_NOT_CONFIGURED"))?;
    if !worker.is_absolute() || !worker.is_file() {
        fail!(EINVAL, "MLX_RUNTIME_PATH_INVALID");
    }
    let mut child = Command::new(worker)
        .arg(mode)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| err!(EIO, "MLX_WORKER_SPAWN"))?;
    let input = child.stdin.take().ok_or_else(|| err!(EIO, "MLX_STDIN"))?;
    let output = child.stdout.take().ok_or_else(|| err!(EIO, "MLX_STDOUT"))?;
    let worker = Worker {
        child,
        input,
        output,
        failed: false,
    };
    nonblocking(worker.input.as_raw_fd())?;
    nonblocking(worker.output.as_raw_fd())?;
    Ok(worker)
}

/// Real Llama-family checkpoint (`mlx_llama_v1`) served by the native
/// worker's closed `llama-v1` graph. Development backend: debug builds only,
/// and only the native worker (MCPMAC_MLX_WORKER) implements this mode.
pub struct MlxLlama {
    worker: Mutex<Worker>,
    tokenizer: crate::tokenizer::Tokenizer,
    vocab: usize,
}
impl std::fmt::Debug for MlxLlama {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlxLlama")
            .field("vocab", &self.vocab)
            .finish_non_exhaustive()
    }
}

/// Load (pipe transfer plus graph materialization) bound.
const LLAMA_LOAD_DEADLINE: Duration = Duration::from_secs(120);
/// One full-recompute forward pass bound.
const LLAMA_REQUEST_DEADLINE: Duration = Duration::from_secs(30);

impl MlxLlama {
    /// Start the worker on the authenticated artifact bytes.
    pub fn load(idx: &TensorIndex, bytes: &[u8], attest: &mut OpAttestor) -> EnclaveResult<Self> {
        use super::llama::{LlamaConfig, CONFIG_KEY, TOKENIZER_KEY};
        if !cfg!(debug_assertions) {
            fail!(EPERM, "MLX_DEVELOPMENT_ONLY");
        }
        if !cfg!(target_os = "macos") {
            fail!(ENOSYS, "MLX_PLATFORM_UNAVAILABLE");
        }
        let config_json = idx
            .metadata
            .get(CONFIG_KEY)
            .ok_or_else(|| err!(EACCES, "LLAMA_CONFIG_MISSING"))?;
        let config: LlamaConfig =
            serde_json::from_str(config_json).map_err(|_| err!(EINVAL, "LLAMA_CONFIG_JSON"))?;
        config.validate()?;
        let tokenizer = crate::tokenizer::Tokenizer::from_hf_json(
            idx.metadata
                .get(TOKENIZER_KEY)
                .ok_or_else(|| err!(EACCES, "TOKENIZER_MISSING"))?,
        )?;
        if tokenizer.vocab() > config.vocab {
            fail!(EINVAL, "TOKENIZER_VOCAB_EXCEEDS_MODEL");
        }
        attest.admit(OpFamily::CausalDecode)?;
        let mut worker = spawn_native("llama-v1")?;
        let deadline = Instant::now() + LLAMA_LOAD_DEADLINE;
        let config_bytes =
            serde_json::to_vec(&config).map_err(|_| err!(EIO, "LLAMA_CONFIG_ENCODE"))?;
        let mut header = b"LLM1".to_vec();
        header.extend_from_slice(&(config_bytes.len() as u32).to_le_bytes());
        header.extend_from_slice(&config_bytes);
        header.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        send(&mut worker.input, &header, deadline)?;
        send(&mut worker.input, bytes, deadline)?;
        let mut ready = [0u8; 8];
        receive(&mut worker.output, &mut ready, deadline)?;
        let vocab = u32::from_le_bytes([ready[4], ready[5], ready[6], ready[7]]) as usize;
        if &ready[..4] != b"MLX2" || vocab != config.vocab {
            fail!(EIO, "MLX_WORKER_READY");
        }
        Ok(Self {
            worker: Mutex::new(worker),
            tokenizer,
            vocab,
        })
    }
}

impl crate::classes::ar::TokenModel for MlxLlama {
    fn tokenizer(&self) -> &crate::tokenizer::Tokenizer {
        &self.tokenizer
    }
    fn logits(&self, ids: &[u32]) -> EnclaveResult<Vec<f32>> {
        if ids.is_empty() || ids.len() > 4096 {
            fail!(EINVAL, "TOKEN_CONTEXT_LENGTH");
        }
        let mut worker = self
            .worker
            .lock()
            .map_err(|_| err!(EIO, "MLX_WORKER_LOCK"))?;
        if worker.failed {
            fail!(EIO, "MLX_WORKER_REVOKED");
        }
        let deadline = Instant::now() + LLAMA_REQUEST_DEADLINE;
        let result = (|| {
            let mut request = (ids.len() as u32).to_le_bytes().to_vec();
            for id in ids {
                request.extend_from_slice(&id.to_le_bytes());
            }
            send(&mut worker.input, &request, deadline)?;
            let mut raw = vec![0u8; self.vocab * 4];
            receive(&mut worker.output, &mut raw, deadline)?;
            let logits: Vec<f32> = raw
                .chunks_exact(4)
                .map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                .collect();
            // The worker's vocabulary may be padded beyond the tokenizer's.
            Ok(logits[..self.tokenizer.vocab()].to_vec())
        })();
        if result.is_err() {
            worker.failed = true;
            let _ = worker.child.kill();
        }
        result
    }
}

impl CausalBackend for MlxLlama {
    fn next(&self, _prefix: &[u8]) -> EnclaveResult<[f32; 256]> {
        fail!(ENOSYS, "BYTE_DECODE_UNSUPPORTED_BY_TOKEN_MODEL")
    }
    fn token_model(&self) -> Option<&dyn crate::classes::ar::TokenModel> {
        Some(self)
    }
}

/// Real LLaDA checkpoint (`mlx_llada_v1`) served by the native worker's
/// closed bidirectional `llada-v1` graph on the GPU. Development backend:
/// debug builds only, native worker only.
pub struct MlxLlada {
    worker: Mutex<Worker>,
    tokenizer: crate::tokenizer::Tokenizer,
    config: super::llada::LladaConfig,
    end: u32,
}
impl std::fmt::Debug for MlxLlada {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlxLlada")
            .field("vocab", &self.config.vocab)
            .finish_non_exhaustive()
    }
}

/// End-of-text token that pads a LLaDA block after the document.
const LLADA_END_TOKEN: &str = "<|endoftext|>";
/// Load bound: pipe transfer of a multi-GB artifact plus materialization.
const LLADA_LOAD_DEADLINE: Duration = Duration::from_secs(300);
/// One full bidirectional forward pass bound.
const LLADA_REQUEST_DEADLINE: Duration = Duration::from_secs(20);
/// Mirrors the worker's sequence and logit-row limits.
const LLADA_MAX_TOKENS: usize = 2048;
const LLADA_MAX_TAIL: usize = 256;

impl MlxLlada {
    /// Start the worker on the authenticated artifact bytes; `tokenizer_json`
    /// is the artifact's tokenizer metadata, taken by value and dropped once
    /// parsed (it is several MB under the runner's ceiling).
    pub fn load(
        idx: &TensorIndex,
        tokenizer_json: String,
        bytes: &[u8],
        attest: &mut OpAttestor,
    ) -> EnclaveResult<Self> {
        use super::llada::{LladaConfig, CONFIG_KEY, MASK_TOKEN};
        if !cfg!(debug_assertions) {
            fail!(EPERM, "MLX_DEVELOPMENT_ONLY");
        }
        if !cfg!(target_os = "macos") {
            fail!(ENOSYS, "MLX_PLATFORM_UNAVAILABLE");
        }
        let config_json = idx
            .metadata
            .get(CONFIG_KEY)
            .ok_or_else(|| err!(EACCES, "LLADA_CONFIG_MISSING"))?;
        let config: LladaConfig =
            serde_json::from_str(config_json).map_err(|_| err!(EINVAL, "LLADA_CONFIG_JSON"))?;
        config.validate()?;
        let tokenizer = crate::tokenizer::Tokenizer::from_hf_json(&tokenizer_json)?;
        drop(tokenizer_json);
        let end = tokenizer
            .special(LLADA_END_TOKEN)
            .ok_or_else(|| err!(EINVAL, "LLADA_TOKENIZER_MISMATCH"))?;
        if tokenizer.vocab() > config.vocab
            || tokenizer.special(MASK_TOKEN) != Some(config.mask_token)
        {
            fail!(EINVAL, "LLADA_TOKENIZER_MISMATCH");
        }
        attest.admit(OpFamily::BidirectionalMask)?;
        let mut worker = spawn_native("llada-v1")?;
        let deadline = Instant::now() + LLADA_LOAD_DEADLINE;
        let config_bytes =
            serde_json::to_vec(&config).map_err(|_| err!(EIO, "LLADA_CONFIG_ENCODE"))?;
        let mut header = b"LDA1".to_vec();
        header.extend_from_slice(&(config_bytes.len() as u32).to_le_bytes());
        header.extend_from_slice(&config_bytes);
        header.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        send(&mut worker.input, &header, deadline)?;
        send(&mut worker.input, bytes, deadline)?;
        let mut ready = [0u8; 8];
        receive(&mut worker.output, &mut ready, deadline)?;
        let vocab = u32::from_le_bytes([ready[4], ready[5], ready[6], ready[7]]) as usize;
        if &ready[..4] != b"MLX2" || vocab != config.vocab {
            fail!(EIO, "MLX_WORKER_READY");
        }
        Ok(Self {
            worker: Mutex::new(worker),
            tokenizer,
            config,
            end,
        })
    }
}

impl crate::classes::diffusion::DiffusionTokenModel for MlxLlada {
    fn tokenizer(&self) -> &crate::tokenizer::Tokenizer {
        &self.tokenizer
    }
    fn end_token(&self) -> u32 {
        self.end
    }
    /// Rows are received and decoded one at a time (about 0.5 MB each at
    /// LLaDA's vocabulary), never as a whole block: 32 positions would be
    /// 16 MB raw plus 16 MB decoded, over UID 701's owned-memory ceiling.
    fn rows(
        &self,
        prompt: &[u32],
        x: &[Option<u32>],
        row: &mut dyn FnMut(usize, &[f32]) -> EnclaveResult<()>,
    ) -> EnclaveResult<()> {
        let n = prompt.len() + x.len();
        if x.is_empty() || x.len() > LLADA_MAX_TAIL || n > LLADA_MAX_TOKENS {
            fail!(EINVAL, "TOKEN_CONTEXT_LENGTH");
        }
        let mut worker = self
            .worker
            .lock()
            .map_err(|_| err!(EIO, "MLX_WORKER_LOCK"))?;
        if worker.failed {
            fail!(EIO, "MLX_WORKER_REVOKED");
        }
        let deadline = Instant::now() + LLADA_REQUEST_DEADLINE;
        let (vocab, kept) = (self.config.vocab, self.tokenizer.vocab());
        let result = (|| {
            let mut request = Vec::with_capacity(8 + n * 4);
            request.extend_from_slice(&(n as u32).to_le_bytes());
            request.extend_from_slice(&(x.len() as u32).to_le_bytes());
            let ids = prompt
                .iter()
                .copied()
                .chain(x.iter().map(|t| t.unwrap_or(self.config.mask_token)));
            for id in ids {
                request.extend_from_slice(&id.to_le_bytes());
            }
            send(&mut worker.input, &request, deadline)?;
            let mut raw = crate::arena::Wiped::new(vec![0u8; vocab * 4], 0u8);
            let mut decoded = crate::arena::Wiped::new(vec![0f32; kept], 0f32);
            for i in 0..x.len() {
                receive(&mut worker.output, &mut raw, deadline)?;
                // Rows are padded to the model vocabulary; keep the tokenizer's ids.
                for (v, b) in decoded.iter_mut().zip(raw[..kept * 4].as_chunks::<4>().0) {
                    *v = f32::from_le_bytes(*b);
                }
                row(i, &decoded)?;
            }
            Ok(())
        })();
        // A failed or abandoned stream leaves the pipe mid-reply: revoke.
        if result.is_err() {
            worker.failed = true;
            let _ = worker.child.kill();
        }
        result
    }
}

impl crate::classes::diffusion::DiffusionBackend for MlxLlada {
    fn logits(&self, _x: &[Option<u8>], _t: u32, _total: u32) -> EnclaveResult<Vec<[f32; 256]>> {
        fail!(ENOSYS, "BYTE_DENOISE_UNSUPPORTED_BY_TOKEN_MODEL")
    }
    fn token_model(&self) -> Option<&dyn crate::classes::diffusion::DiffusionTokenModel> {
        Some(self)
    }
}
