//! Zero-trust local IPC over UNIX domain sockets (ADR-010, FS-702 §3.2).
//!
//! * Frames: `u32` big-endian length ‖ CBOR body, capped at [`MAX_FRAME`].
//! * **Mutual peer authentication**: the server reads the client's kernel
//!   credentials (`LOCAL_PEERTOKEN` `audit_token_t` + `getpeereid` on macOS,
//!   `SO_PEERCRED` on Linux) and checks them against a [`PeerPolicy`]; the
//!   client independently checks the *server's* effective UID before sending
//!   anything. PIDs are recorded for telemetry only — never for authorization
//!   (`LOCAL_PEERPID` reuse races, F-028).
//! * Each server binds inside its own directory (`<mesh>/<suffix>/`). In
//!   production that directory is provisioned by root as
//!   `daemon:<client group> 2750` and the socket is `0660`, so the permitted
//!   peer daemons can connect while no daemon can touch another's socket
//!   ([`SocketAccess`], GAP-01). Development uses `0700` / `0600`.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::codesign::{self, CodeIdentity, CodeRequirement};
use crate::daemon::DaemonId;
use crate::error::{EnclaveError, EnclaveResult};
use crate::{err, fail};

mod server_progress;
pub(crate) use server_progress::ServerProgress;

/// Maximum IPC frame (1 MiB).
pub const MAX_FRAME: usize = 1024 * 1024;
/// Maximum concurrent connections per daemon (bounded memory).
pub const MAX_CONNECTIONS: usize = 16;
/// Per-connection I/O timeout.
pub const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// Inbound frames are buffered in steps of this size, each charged to the
/// server's in-flight budget before it is allocated (GAP-39).
pub const ALLOC_STEP: usize = 64 * 1024;

/// Server-side resource limits (GAP-39, ADR-006 RSS ceilings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeLimits {
    /// Largest inbound request frame.
    pub max_frame: usize,
    /// Concurrent connections.
    pub max_connections: usize,
    /// Concurrent connections from one peer UID.
    pub max_per_uid: usize,
    /// Bytes of inbound frames buffered across all connections at once.
    pub inflight_bytes: usize,
    /// A frame — including the wait for its first byte — must arrive within
    /// this deadline, however slowly the peer trickles bytes.
    pub frame_deadline: Duration,
}

impl ServeLimits {
    /// Limits for `d`. UID 703 (24 MiB ceiling) takes requests of at most
    /// 256 KiB (`ScrubText` carries whole tool outputs from UID 704) and
    /// buffers at most 1 MiB in total. With every daemon under one UID
    /// (development) the per-UID quota cannot separate peers and equals the
    /// connection cap.
    pub fn for_daemon(d: DaemonId, dev_same_uid: bool) -> Self {
        let (max_frame, inflight_bytes) = match d {
            DaemonId::CustodyVault => (256 * 1024, 1024 * 1024),
            _ => (MAX_FRAME, 4 * MAX_FRAME),
        };
        Self {
            max_frame,
            max_connections: MAX_CONNECTIONS,
            max_per_uid: if dev_same_uid {
                MAX_CONNECTIONS
            } else {
                MAX_CONNECTIONS / 2
            },
            inflight_bytes,
            frame_deadline: IO_TIMEOUT,
        }
    }
}

impl Default for ServeLimits {
    fn default() -> Self {
        Self {
            max_frame: MAX_FRAME,
            max_connections: MAX_CONNECTIONS,
            max_per_uid: MAX_CONNECTIONS,
            inflight_bytes: 4 * MAX_FRAME,
            frame_deadline: IO_TIMEOUT,
        }
    }
}

/// Live counters of a server (tests, `Status`).
#[derive(Debug, Default)]
pub struct ServeStats {
    /// Inbound bytes buffered right now.
    pub inflight: AtomicUsize,
    /// Highest value `inflight` reached.
    pub inflight_high_water: AtomicUsize,
    /// Frames refused because the in-flight budget was exhausted.
    pub busy_rejections: AtomicUsize,
    /// Connections refused by the per-UID quota.
    pub quota_rejections: AtomicUsize,
}

impl ServeStats {
    fn charge(&self, n: usize, limit: usize) -> bool {
        let mut cur = self.inflight.load(Ordering::SeqCst);
        loop {
            let Some(next) = cur.checked_add(n).filter(|v| *v <= limit) else {
                return false;
            };
            match self
                .inflight
                .compare_exchange(cur, next, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => {
                    self.inflight_high_water.fetch_max(next, Ordering::SeqCst);
                    return true;
                }
                Err(v) => cur = v,
            }
        }
    }
    fn release(&self, n: usize) {
        self.inflight.fetch_sub(n, Ordering::SeqCst);
    }
}

/// An inbound frame whose buffer is charged to the in-flight budget until
/// it is dropped.
struct Charged<'a> {
    buf: Vec<u8>,
    charged: usize,
    stats: &'a ServeStats,
}

impl Drop for Charged<'_> {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.buf);
        self.stats.release(self.charged);
    }
}

fn read_exact_by(
    s: &mut UnixStream,
    mut buf: &mut [u8],
    deadline: std::time::Instant,
) -> EnclaveResult<()> {
    while !buf.is_empty() {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            fail!(ETIMEDOUT, "IPC_FRAME_DEADLINE");
        }
        s.set_read_timeout(Some(left))
            .map_err(|e| err!(EIO, "IPC_READ", "{e}"))?;
        match s.read(buf) {
            Ok(0) => fail!(EIO, "IPC_READ", "peer closed"),
            Ok(n) => buf = &mut buf[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(err!(EIO, "IPC_READ", "{e}")),
        }
    }
    Ok(())
}

/// Read one inbound frame under `limits`: the length is checked before any
/// allocation, the body is buffered in [`ALLOC_STEP`] increments each charged
/// to the shared budget, and the whole frame must arrive by the deadline.
fn read_frame_limited<'a>(
    s: &mut UnixStream,
    limits: &ServeLimits,
    stats: &'a ServeStats,
) -> EnclaveResult<Charged<'a>> {
    let deadline = std::time::Instant::now() + limits.frame_deadline;
    let mut len = [0u8; 4];
    read_exact_by(s, &mut len, deadline)?;
    let n = u32::from_be_bytes(len) as usize;
    if n > limits.max_frame {
        fail!(E2BIG, "IPC_FRAME_TOO_LARGE", "{n} > {}", limits.max_frame);
    }
    let mut c = Charged {
        buf: Vec::new(),
        charged: 0,
        stats,
    };
    while c.buf.len() < n {
        let step = (n - c.buf.len()).min(ALLOC_STEP);
        if !stats.charge(step, limits.inflight_bytes) {
            stats.busy_rejections.fetch_add(1, Ordering::SeqCst);
            fail!(
                EAGAIN,
                "IPC_BUSY",
                "in-flight budget of {} bytes exhausted",
                limits.inflight_bytes
            );
        }
        c.charged += step;
        let start = c.buf.len();
        // Exactly the charged size: no amortised over-allocation.
        c.buf.reserve_exact(step);
        c.buf.resize(start + step, 0);
        read_exact_by(s, &mut c.buf[start..], deadline)?;
    }
    Ok(c)
}

/// Kernel-attested peer identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerCredentials {
    /// Effective UID.
    pub uid: u32,
    /// Effective GID.
    pub gid: u32,
    /// PID at connect time (telemetry only).
    pub pid: Option<i32>,
    /// macOS `audit_token_t` (8 x u32) when available.
    pub audit_token: Option<[u32; 8]>,
    /// Code identity verified against the peer policy's requirement
    /// (macOS; `None` on Linux CI or before [`PeerPolicy::check`]).
    #[serde(default)]
    pub code_identity: Option<CodeIdentity>,
    /// RFC 9266 TLS exporter channel binding for mTLS A2A connections.
    #[serde(default)]
    pub tls_channel_binding: Option<[u8; 32]>,
}

impl PeerCredentials {
    /// Credentials for in-process callers and tests (no kernel token).
    pub fn local(uid: u32, gid: u32) -> Self {
        Self {
            uid,
            gid,
            pid: None,
            audit_token: None,
            code_identity: None,
            tls_channel_binding: None,
        }
    }
    /// Credentials for cross-node mTLS A2A sessions using RFC 9266 TLS exporter binding.
    pub fn mtls(channel_binding: [u8; 32]) -> Self {
        Self {
            uid: 704,
            gid: 8704,
            pid: None,
            audit_token: None,
            code_identity: None,
            tls_channel_binding: Some(channel_binding),
        }
    }
    /// 32-byte channel binding for PoP tokens: RFC 9266 TLS exporter binding when
    /// present (mTLS), or BLAKE3 over the verified `cdhash` (when present) and the
    /// audit token (macOS), or `uid ‖ gid ‖ pid` (Linux CI).
    pub fn channel_binding(&self) -> [u8; 32] {
        if let Some(cb) = self.tls_channel_binding {
            return cb;
        }
        let mut h = blake3::Hasher::new_derive_key("MCPMac-UDS-ChannelBinding-v1");
        h.update(&self.uid.to_be_bytes());
        h.update(&self.gid.to_be_bytes());
        if let Some(c) = &self.code_identity {
            h.update(b"cdhash:");
            h.update(c.cdhash.as_bytes());
        }
        if let Some(t) = self.audit_token {
            for w in t {
                h.update(&w.to_be_bytes());
            }
        } else if let Some(p) = self.pid {
            h.update(&p.to_be_bytes());
        }
        *h.finalize().as_bytes()
    }
}

/// Read the peer's credentials from a connected socket.
#[cfg(target_os = "linux")]
pub fn peer_credentials(s: &UnixStream) -> EnclaveResult<PeerCredentials> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: valid fd and correctly sized out-buffer.
    let rc = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        fail!(EACCES, "PEERCRED_UNAVAILABLE");
    }
    Ok(PeerCredentials {
        uid: cred.uid,
        gid: cred.gid,
        pid: Some(cred.pid),
        audit_token: None,
        code_identity: None,
        tls_channel_binding: None,
    })
}

/// Read the peer's credentials from a connected socket.
#[cfg(target_os = "macos")]
pub fn peer_credentials(s: &UnixStream) -> EnclaveResult<PeerCredentials> {
    let fd = s.as_raw_fd();
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: valid fd and out-pointers.
    if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
        fail!(EACCES, "GETPEEREID_FAILED");
    }
    let mut token = [0u32; 8];
    let mut len = std::mem::size_of::<[u32; 8]>() as libc::socklen_t;
    // SAFETY: LOCAL_PEERTOKEN fills an audit_token_t (8 x u32).
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            token.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 || len as usize != std::mem::size_of::<[u32; 8]>() {
        fail!(EACCES, "LOCAL_PEERTOKEN_UNAVAILABLE");
    }
    // audit_token_t[5] is the PID (telemetry only).
    Ok(PeerCredentials {
        uid,
        gid,
        pid: Some(token[5] as i32),
        audit_token: Some(token),
        code_identity: None,
        tls_channel_binding: None,
    })
}

/// Who may talk to a daemon: a kernel UID **and**, where a requirement is
/// set and the platform can verify it, the signed program (GAP-02).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPolicy {
    /// Allowed client UIDs.
    pub allowed_uids: BTreeSet<u32>,
    /// Code requirement per UID. A UID without an entry is admitted on its
    /// UID alone (development policies only).
    pub code: BTreeMap<u32, CodeRequirement>,
}

impl PeerPolicy {
    /// Allow exactly these UIDs, with no code requirement (development).
    pub fn allow(uids: impl IntoIterator<Item = u32>) -> Self {
        Self {
            allowed_uids: uids.into_iter().collect(),
            code: BTreeMap::new(),
        }
    }
    /// Admit `uid` only when its code satisfies `req`.
    pub fn require(mut self, uid: u32, req: CodeRequirement) -> Self {
        self.allowed_uids.insert(uid);
        self.code.insert(uid, req);
        self
    }
    /// Check a peer; returns the credentials with the verified code identity.
    pub fn check(&self, p: &PeerCredentials) -> EnclaveResult<PeerCredentials> {
        self.check_with(p, codesign::enforced(), &codesign::verify_peer)
    }
    /// [`Self::check`] with an explicit verifier (unit tests on Linux).
    pub fn check_with(
        &self,
        p: &PeerCredentials,
        enforce_code: bool,
        verify: &dyn Fn(&[u32; 8], &CodeRequirement) -> EnclaveResult<CodeIdentity>,
    ) -> EnclaveResult<PeerCredentials> {
        if !self.allowed_uids.contains(&p.uid) {
            fail!(
                EACCES,
                "PEER_UID_REJECTED",
                "uid {} not in {:?}",
                p.uid,
                self.allowed_uids
            );
        }
        let mut out = p.clone();
        out.code_identity = None;
        if let (true, Some(req)) = (enforce_code, self.code.get(&p.uid)) {
            let tok = p
                .audit_token
                .ok_or_else(|| err!(EACCES, "PEER_AUDIT_TOKEN_MISSING"))?;
            out.code_identity = Some(verify(&tok, req)?);
        }
        Ok(out)
    }
}

/// Production adjacency matrix: which daemons may call `server`, each pinned
/// to its own signing identity, plus `uid 0` admitted **only** as the signed
/// operator CLI (`com.enterprise.enclave.ctl`) — not any root process
/// (GAP-02). On Linux CI the code requirements cannot be evaluated and the
/// UID matrix alone applies.
pub fn production_policy(server: DaemonId) -> PeerPolicy {
    use DaemonId::*;
    let callers: &[DaemonId] = match server {
        ModelRunner => &[AgentRuntime],
        SwarmSync => &[ModelRunner, AgentRuntime, CustodyVault, ZkAuditor],
        CustodyVault => &[AgentRuntime, ZkAuditor, SwarmSync],
        AgentRuntime => &[ModelRunner, CustodyVault, ZkAuditor],
        ZkAuditor => &[CustodyVault, AgentRuntime, ModelRunner, SwarmSync],
    };
    let policy = callers
        .iter()
        .fold(PeerPolicy::allow([]), |p, d| {
            p.require(d.uid(), CodeRequirement::daemon(*d))
        })
        .require(0, CodeRequirement::ctl());
    if server == DaemonId::AgentRuntime {
        policy.require(crate::daemon::GATEWAY_UID, CodeRequirement::gateway())
    } else { policy }
}

/// Dedicated witness channel policy (GAP-10): only UID 703 (`_piivault`)
/// is admitted, pinned to its code identity.
pub fn witness_channel_policy() -> PeerPolicy {
    PeerPolicy::allow([DaemonId::CustodyVault.uid()]).require(
        DaemonId::CustodyVault.uid(),
        CodeRequirement::daemon(DaemonId::CustodyVault),
    )
}

/// Write one frame.
pub fn write_frame<W: Write>(w: &mut W, body: &[u8]) -> EnclaveResult<()> {
    if body.len() > MAX_FRAME {
        fail!(E2BIG, "IPC_FRAME_TOO_LARGE");
    }
    w.write_all(&(body.len() as u32).to_be_bytes())
        .map_err(|e| err!(EIO, "IPC_WRITE", "{e}"))?;
    w.write_all(body)
        .map_err(|e| err!(EIO, "IPC_WRITE", "{e}"))?;
    w.flush().map_err(|e| err!(EIO, "IPC_WRITE", "{e}"))
}

/// Read one frame.
pub fn read_frame<R: Read>(r: &mut R) -> EnclaveResult<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)
        .map_err(|e| err!(EIO, "IPC_READ", "{e}"))?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_FRAME {
        fail!(E2BIG, "IPC_FRAME_TOO_LARGE");
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)
        .map_err(|e| err!(EIO, "IPC_READ", "{e}"))?;
    Ok(buf)
}

/// One-shot raw Unix-frame limits. These do not bound authentication, dispatch,
/// serialization or a complete request/reply transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameIoLimits {
    /// Largest body; the global protocol maximum also always applies.
    pub max_frame: usize,
    /// Absolute allowance shared by first byte, header and body.
    pub frame_deadline: Duration,
    /// Progress inactivity allowance; renewed only after actual bytes.
    pub idle_timeout: Duration,
}

impl FrameIoLimits {
    /// Dedicated witness channel policy, using the existing auditor frame bound.
    pub fn witness() -> Self {
        let limits = ServeLimits::for_daemon(DaemonId::ZkAuditor, false);
        Self { max_frame: limits.max_frame, frame_deadline: limits.frame_deadline,
            idle_timeout: Duration::from_millis(1500) }
    }
}

struct FrameClock {
    end: Instant,
    idle_end: Instant,
    idle_timeout: Duration,
}
impl FrameClock {
    fn new(limits: &FrameIoLimits) -> EnclaveResult<Self> {
        let now = Instant::now();
        Ok(Self {
            end: now.checked_add(limits.frame_deadline).ok_or_else(|| err!(EINVAL, "IPC_FRAME_LIMITS"))?,
            idle_end: now.checked_add(limits.idle_timeout).ok_or_else(|| err!(EINVAL, "IPC_FRAME_LIMITS"))?,
            idle_timeout: limits.idle_timeout,
        })
    }
    fn check(&self) -> EnclaveResult<()> { self.check_at(Instant::now()) }
    fn check_at(&self, now: Instant) -> EnclaveResult<()> {
        if now >= self.end { fail!(ETIMEDOUT, "IPC_FRAME_DEADLINE"); }
        if now >= self.idle_end { fail!(ETIMEDOUT, "IPC_FRAME_IDLE_TIMEOUT"); }
        Ok(())
    }
    fn progress(&mut self) -> EnclaveResult<()> {
        // Check the previous idle boundary before renewing it. A delayed final
        // syscall cannot retroactively turn expired completion into success.
        let now = Instant::now();
        self.check_at(now)?;
        self.idle_end = now.checked_add(self.idle_timeout)
            .ok_or_else(|| err!(EINVAL, "IPC_FRAME_LIMITS"))?;
        Ok(())
    }
    fn pause(&self) -> EnclaveResult<()> {
        self.check()?;
        let now = Instant::now();
        std::thread::sleep(self.end.saturating_duration_since(now)
            .min(self.idle_end.saturating_duration_since(now)).min(Duration::from_millis(2)));
        Ok(())
    }
}

fn read_exact_timed(stream: &mut UnixStream, mut bytes: &mut [u8], clock: &mut FrameClock) -> EnclaveResult<()> {
    while !bytes.is_empty() {
        clock.check()?;
        match stream.read(bytes) {
            Ok(0) => fail!(EIO, "IPC_READ"),
            Ok(count) => { clock.progress()?; bytes = &mut bytes[count..]; }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => clock.pause()?,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {},
            Err(_) => fail!(EIO, "IPC_READ"),
        }
    }
    clock.check()
}

/// Read a raw frame on an owned one-shot connection, left nonblocking.
/// The header is checked before a fallible body allocation. Storage is bounded
/// and zeroized on drop; this is not the generic server's inflight slab budget.
pub fn read_frame_timed(stream: &mut UnixStream, limits: &FrameIoLimits) -> EnclaveResult<zeroize::Zeroizing<Vec<u8>>> {
    let mut clock = FrameClock::new(limits)?;
    stream.set_nonblocking(true).map_err(|_| err!(EIO, "IPC_NONBLOCKING"))?;
    let mut header = [0u8; 4];
    read_exact_timed(stream, &mut header, &mut clock)?;
    let length = u32::from_be_bytes(header) as usize;
    if length > limits.max_frame.min(MAX_FRAME) { fail!(E2BIG, "IPC_FRAME_TOO_LARGE"); }
    let mut body = zeroize::Zeroizing::new(Vec::new());
    body.try_reserve_exact(length).map_err(|_| err!(ENOMEM, "IPC_FRAME_ALLOC"))?;
    body.resize(length, 0);
    read_exact_timed(stream, &mut body, &mut clock)?;
    Ok(body)
}

/// Write a raw frame from the caller's preencoded body without copying it.
/// Leaves this owned one-shot connection nonblocking. Failure after a partial
/// write is uncertain receipt: callers must drop the connection and never retry.
pub fn write_frame_timed(stream: &mut UnixStream, body: &[u8], limits: &FrameIoLimits) -> EnclaveResult<()> {
    if body.len() > limits.max_frame.min(MAX_FRAME) { fail!(E2BIG, "IPC_FRAME_TOO_LARGE"); }
    let mut clock = FrameClock::new(limits)?;
    stream.set_nonblocking(true).map_err(|_| err!(EIO, "IPC_NONBLOCKING"))?;
    let header = (body.len() as u32).to_be_bytes();
    for mut remaining in [&header[..], body] {
        while !remaining.is_empty() {
            clock.check()?;
            match stream.write(remaining) {
                Ok(0) => fail!(EIO, "IPC_WRITE"),
                Ok(count) => { clock.progress()?; remaining = &remaining[count..]; }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => clock.pause()?,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {},
                Err(_) => fail!(EIO, "IPC_WRITE"),
            }
        }
    }
    clock.check()
}

/// CBOR encode.
pub fn to_cbor<T: Serialize>(v: &T) -> EnclaveResult<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).map_err(|e| err!(EINVAL, "IPC_ENCODE", "{e}"))?;
    Ok(out)
}

/// CBOR decode.
pub fn from_cbor<T: DeserializeOwned>(b: &[u8]) -> EnclaveResult<T> {
    ciborium::from_reader(b).map_err(|e| err!(EINVAL, "IPC_DECODE", "{e}"))
}

/// Response wrapper carried on the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Reply<T> {
    /// Success.
    Ok(T),
    /// Fail-closed error.
    Err(EnclaveError),
}

/// Common status shape every daemon reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonStatus {
    /// Daemon UID (production identity).
    pub daemon_uid: u32,
    /// Binary.
    pub binary: String,
    /// PID.
    pub pid: u32,
    /// Current RSS (bytes).
    pub rss_bytes: u64,
    /// Ceiling (bytes).
    pub rss_ceiling_bytes: u64,
    /// Boot epoch.
    pub boot_epoch_id: String,
    /// Next `rpc_seq_u64`.
    pub rpc_seq_u64: u64,
    /// Daemon-specific state summary.
    pub state: String,
    /// Physical footprint (`task_vm_info.phys_footprint` on macOS) in bytes (GAP-38).
    #[serde(default)]
    pub phys_footprint_bytes: u64,
    /// Measurement origin; older peers default to unknown and cannot establish compliance.
    #[serde(default)]
    pub phys_footprint_source: crate::resource::FootprintSource,
}

/// How a socket is exposed on the filesystem (GAP-01).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketAccess {
    /// Development / tests: every daemon runs under one UID. The server
    /// directory is created `0700` if missing and the socket is `0600`.
    OwnerOnly,
    /// Production: the server directory was provisioned by root as
    /// `daemon:<client group> 2750` inside a root-owned, non-writable mesh
    /// directory. The daemon never creates or chmods directories; it refuses
    /// to start if the layout is wrong, and its socket is `0660` with the
    /// client group so exactly the permitted daemons can `connect(2)`.
    Group {
        /// GID of the server's client group.
        gid: u32,
    },
}

fn insecure_dir(p: &Path, why: &str) -> EnclaveError {
    err!(EACCES, "IPC_DIR_INSECURE", "{}: {why}", p.display())
}

/// Validate (and in [`SocketAccess::OwnerOnly`] create) the server
/// directory. Never chmods or chowns an existing directory: a directory with
/// the wrong owner or mode is a provisioning error or an attack, not
/// something to repair from inside a daemon.
fn prepare_server_dir(dir: &Path, access: SocketAccess) -> EnclaveResult<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let me = geteuid();
    if access == SocketAccess::OwnerOnly && !dir.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| err!(EIO, "IPC_MKDIR", "{}: {e}", dir.display()))?;
    }
    let m = std::fs::symlink_metadata(dir)
        .map_err(|e| err!(EIO, "IPC_DIR_MISSING", "{}: {e}", dir.display()))?;
    if !m.file_type().is_dir() {
        return Err(insecure_dir(dir, "not a directory (symlinks are refused)"));
    }
    if m.uid() != me {
        return Err(insecure_dir(
            dir,
            &format!("owned by uid {} (expected {me})", m.uid()),
        ));
    }
    let mode = m.mode() & 0o7777;
    match access {
        SocketAccess::OwnerOnly => {
            if mode & 0o022 != 0 {
                return Err(insecure_dir(
                    dir,
                    &format!("mode {mode:o} is group/other writable"),
                ));
            }
        }
        SocketAccess::Group { gid } => {
            if m.gid() != gid {
                return Err(insecure_dir(
                    dir,
                    &format!("group {} (expected client group {gid})", m.gid()),
                ));
            }
            if mode & 0o027 != 0 || mode & 0o010 == 0 {
                return Err(insecure_dir(dir, &format!("mode {mode:o} (expected 2750)")));
            }
            // The mesh directory above must be root-owned and not writable by
            // anyone else, so a server directory cannot be swapped out.
            let parent = dir
                .parent()
                .ok_or_else(|| insecure_dir(dir, "no mesh directory"))?;
            let pm = std::fs::symlink_metadata(parent)
                .map_err(|e| err!(EIO, "IPC_DIR_MISSING", "{}: {e}", parent.display()))?;
            if !pm.file_type().is_dir() || pm.uid() != 0 || pm.mode() & 0o022 != 0 {
                return Err(insecure_dir(
                    parent,
                    "mesh directory must be root-owned and not group/other writable",
                ));
            }
        }
    }
    Ok(())
}

/// Bind a listener inside its server directory (see [`SocketAccess`]).
/// A stale *socket* at `path` is replaced; any other file type is refused,
/// so a planted symlink or regular file is never followed or deleted.
pub fn bind(path: &Path, access: SocketAccess) -> EnclaveResult<UnixListener> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    let dir = path
        .parent()
        .ok_or_else(|| err!(EINVAL, "IPC_PATH", "{}", path.display()))?;
    prepare_server_dir(dir, access)?;
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() && m.uid() == geteuid() => {
            std::fs::remove_file(path).map_err(|e| err!(EIO, "IPC_UNLINK", "{e}"))?;
        }
        Ok(_) => fail!(
            EACCES,
            "IPC_PATH_OCCUPIED",
            "{} exists and is not this daemon's socket",
            path.display()
        ),
        Err(_) => {}
    }
    let l = UnixListener::bind(path).map_err(|e| err!(EIO, "IPC_BIND", "{e}"))?;
    // The socket is created under the process umask (077 under launchd), i.e.
    // never more open than intended; it is then widened to exactly its mode.
    let mode = match access {
        SocketAccess::OwnerOnly => 0o600,
        SocketAccess::Group { gid } => {
            // BSD semantics (and the set-gid server directory on Linux) give
            // the socket the directory's group; verify instead of assuming.
            let g = std::fs::symlink_metadata(path)
                .map_err(|e| err!(EIO, "IPC_STAT", "{e}"))?
                .gid();
            if g != gid {
                let _ = std::fs::remove_file(path);
                fail!(
                    EACCES,
                    "IPC_SOCKET_GROUP",
                    "socket group {g} != client group {gid}"
                );
            }
            0o660
        }
    };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| err!(EIO, "IPC_CHMOD", "{e}"))?;
    Ok(l)
}

/// Serve typed requests forever (until `stop` returns true) under the
/// default [`ServeLimits`]. Every connection is authenticated before its
/// first frame is read; rejected peers get a single `Reply::Err` and the
/// connection is closed.
pub fn serve<Req, Resp, H>(
    listener: UnixListener,
    policy: PeerPolicy,
    handler: Arc<H>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) -> EnclaveResult<()>
where
    Req: DeserializeOwned + Send + 'static,
    Resp: Serialize + Send + 'static,
    H: Fn(&PeerCredentials, Req) -> EnclaveResult<Resp> + Send + Sync + 'static,
{
    serve_with(
        listener,
        policy,
        ServeLimits::default(),
        Arc::new(ServeStats::default()),
        handler,
        stop,
    )
}

/// [`serve`] with explicit limits and counters (GAP-39): a connection cap,
/// a per-peer-UID connection quota, a global in-flight byte budget with lazy
/// allocation, and a per-frame deadline.
pub fn serve_with<Req, Resp, H>(
    listener: UnixListener,
    policy: PeerPolicy,
    limits: ServeLimits,
    stats: Arc<ServeStats>,
    handler: Arc<H>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) -> EnclaveResult<()>
where
    Req: DeserializeOwned + Send + 'static,
    Resp: Serialize + Send + 'static,
    H: Fn(&PeerCredentials, Req) -> EnclaveResult<Resp> + Send + Sync + 'static,
{
    serve_with_authenticator(listener, Arc::new(move |peer: &PeerCredentials| policy.check(peer)),
        limits, stats, handler, stop)
}

/// Bounded serving with a trusted dynamic peer authenticator. Authentication runs
/// before any frame is read; request handlers must recheck changing session state.
/// This supports active-console ingress without broadening daemon UID policies.
pub fn serve_with_authenticator<Req, Resp, H, A>(
    listener: UnixListener,
    authenticate: Arc<A>,
    limits: ServeLimits,
    stats: Arc<ServeStats>,
    handler: Arc<H>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) -> EnclaveResult<()>
where
    Req: DeserializeOwned + Send + 'static,
    Resp: Serialize + Send + 'static,
    H: Fn(&PeerCredentials, Req) -> EnclaveResult<Resp> + Send + Sync + 'static,
    A: Fn(&PeerCredentials) -> EnclaveResult<PeerCredentials> + Send + Sync + 'static,
{
    serve_with_authenticator_fds(listener, authenticate, limits, stats,
        Arc::new(move |peer: &PeerCredentials, req, _fds| handler(peer, req)),
        Arc::new(|_: &Req| None), stop)
}

/// Serve versioned descriptor-bearing requests alongside legacy frame-only
/// requests. The trusted selector names the exact count (including zero for
/// an explicit empty packet); authentication precedes all descriptor reads.
pub fn serve_with_fds<Req, Resp, H, F>(listener: UnixListener, policy: PeerPolicy,
    handler: Arc<H>, fd_count: Arc<F>, stop: Arc<std::sync::atomic::AtomicBool>) -> EnclaveResult<()>
where Req: DeserializeOwned + Send + 'static, Resp: Serialize + Send + 'static,
    H: Fn(&PeerCredentials, Req, Vec<std::os::fd::OwnedFd>) -> EnclaveResult<Resp> + Send + Sync + 'static,
    F: Fn(&Req) -> Option<usize> + Send + Sync + 'static,
{
    serve_with_authenticator_fds(listener, Arc::new(move |peer: &PeerCredentials| policy.check(peer)),
        ServeLimits::default(), Arc::new(ServeStats::default()), handler, fd_count, stop)
}

fn serve_with_authenticator_fds<Req, Resp, H, A, F>(listener: UnixListener,
    authenticate: Arc<A>, limits: ServeLimits, stats: Arc<ServeStats>, handler: Arc<H>,
    fd_count: Arc<F>, stop: Arc<std::sync::atomic::AtomicBool>) -> EnclaveResult<()>
where Req: DeserializeOwned + Send + 'static, Resp: Serialize + Send + 'static,
    H: Fn(&PeerCredentials, Req, Vec<std::os::fd::OwnedFd>) -> EnclaveResult<Resp> + Send + Sync + 'static,
    A: Fn(&PeerCredentials) -> EnclaveResult<PeerCredentials> + Send + Sync + 'static,
    F: Fn(&Req) -> Option<usize> + Send + Sync + 'static,
{
    serve_owned_loop(listener, authenticate, limits, stats, handler, fd_count, stop, None)
}

/// Start an owned accept loop with the same authentication, quotas and frame
/// handling as serve. Its progress checks say nothing about handler completion.
pub(crate) fn spawn_monitored<Req, Resp, H>(listener: UnixListener, policy: PeerPolicy,
    handler: Arc<H>, stop: Arc<std::sync::atomic::AtomicBool>) -> EnclaveResult<ServerProgress>
where Req: DeserializeOwned + Send + 'static, Resp: Serialize + Send + 'static,
    H: Fn(&PeerCredentials, Req) -> EnclaveResult<Resp> + Send + Sync + 'static,
{
    spawn_monitored_with_fds(listener, policy,
        Arc::new(move |peer: &PeerCredentials, req, _fds| handler(peer, req)),
        Arc::new(|_: &Req| None), stop)
}

/// Descriptor-bearing counterpart; no progress producer is exposed to callers.
pub(crate) fn spawn_monitored_with_fds<Req, Resp, H, F>(listener: UnixListener,
    policy: PeerPolicy, handler: Arc<H>, fd_count: Arc<F>,
    stop: Arc<std::sync::atomic::AtomicBool>) -> EnclaveResult<ServerProgress>
where Req: DeserializeOwned + Send + 'static, Resp: Serialize + Send + 'static,
    H: Fn(&PeerCredentials, Req, Vec<std::os::fd::OwnedFd>) -> EnclaveResult<Resp> + Send + Sync + 'static,
    F: Fn(&Req) -> Option<usize> + Send + Sync + 'static,
{
    let (owner, progress) = server_progress::prepare(stop.clone());
    let terminal = owner.terminal_observer();
    let thread = std::thread::Builder::new().name("ipc-accept-owner".into()).stack_size(256 * 1024)
        .spawn(move || {
            let result = serve_owned_loop(listener,
            Arc::new(move |peer: &PeerCredentials| policy.check(peer)),
            ServeLimits::default(), Arc::new(ServeStats::default()), handler, fd_count,
            stop, Some(progress));
            terminal(&result); result
        })
        .map_err(|e| err!(EIO, "IPC_SPAWN", "{e}"))?;
    Ok(owner.attach(thread))
}

fn serve_owned_loop<Req, Resp, H, A, F>(listener: UnixListener,
    authenticate: Arc<A>, limits: ServeLimits, stats: Arc<ServeStats>, handler: Arc<H>,
    fd_count: Arc<F>, stop: Arc<std::sync::atomic::AtomicBool>,
    mut progress: Option<server_progress::LoopProgress>) -> EnclaveResult<()>
where Req: DeserializeOwned + Send + 'static, Resp: Serialize + Send + 'static,
    H: Fn(&PeerCredentials, Req, Vec<std::os::fd::OwnedFd>) -> EnclaveResult<Resp> + Send + Sync + 'static,
    A: Fn(&PeerCredentials) -> EnclaveResult<PeerCredentials> + Send + Sync + 'static,
    F: Fn(&Req) -> Option<usize> + Send + Sync + 'static,
{
    let active = Arc::new(AtomicUsize::new(0));
    let per_uid: Arc<std::sync::Mutex<BTreeMap<u32, usize>>> = Arc::default();
    let limits = Arc::new(limits);
    listener
        .set_nonblocking(true)
        .map_err(|e| err!(EIO, "IPC_NONBLOCK", "{e}"))?;
    if let Some(progress) = &mut progress { progress.bind(&listener)?; }
    while !stop.load(Ordering::SeqCst) {
        let (stream, _) = match listener.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if let Some(progress) = &mut progress { progress.observe_iteration(&listener)?; }
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => return Err(err!(EIO, "IPC_ACCEPT", "{e}")),
        };
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        if active.load(Ordering::SeqCst) >= limits.max_connections {
            let mut s = stream;
            let _ = write_frame(
                &mut s,
                &to_cbor(&Reply::<()>::Err(err!(EAGAIN, "IPC_TOO_MANY_CONNECTIONS")))?,
            );
            continue;
        }
        // The quota key is the kernel-attested UID (authorization still
        // happens per connection in `handle_conn`).
        let uid = match peer_credentials(&stream) {
            Ok(p) => p.uid,
            Err(_) => continue,
        };
        {
            let mut q = per_uid
                .lock()
                .map_err(|_| err!(EIO, "IPC_QUOTA_POISONED"))?;
            let n = q.entry(uid).or_insert(0);
            if *n >= limits.max_per_uid {
                stats.quota_rejections.fetch_add(1, Ordering::SeqCst);
                let mut s = stream;
                let _ = write_frame(
                    &mut s,
                    &to_cbor(&Reply::<()>::Err(err!(
                        EAGAIN,
                        "IPC_PEER_QUOTA",
                        "uid {uid} holds {n} connections"
                    )))?,
                );
                continue;
            }
            *n += 1;
        }
        active.fetch_add(1, Ordering::SeqCst);
        let (authenticate, handler, active, per_uid, limits, stats, fd_count) = (
            authenticate.clone(),
            handler.clone(),
            active.clone(),
            per_uid.clone(),
            limits.clone(),
            stats.clone(),
            fd_count.clone(),
        );
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || {
                let _ = handle_conn::<Req, Resp, H, A, F>(stream, &*authenticate, &limits, &stats, &*handler, &*fd_count);
                if let Ok(mut q) = per_uid.lock() {
                    if let Some(n) = q.get_mut(&uid) {
                        *n = n.saturating_sub(1);
                    }
                }
                active.fetch_sub(1, Ordering::SeqCst);
            })
            .map_err(|e| err!(EIO, "IPC_SPAWN", "{e}"))?;
        if let Some(progress) = &mut progress { progress.observe_iteration(&listener)?; }
    }
    Ok(())
}

fn handle_conn<Req, Resp, H, A, F>(
    mut s: UnixStream,
    authenticate: &A,
    limits: &ServeLimits,
    stats: &ServeStats,
    handler: &H,
    fd_count: &F,
) -> EnclaveResult<()>
where
    Req: DeserializeOwned,
    Resp: Serialize,
    H: Fn(&PeerCredentials, Req, Vec<std::os::fd::OwnedFd>) -> EnclaveResult<Resp>,
    F: Fn(&Req) -> Option<usize>,
    A: Fn(&PeerCredentials) -> EnclaveResult<PeerCredentials>,
{
    s.set_read_timeout(Some(IO_TIMEOUT)).ok();
    s.set_write_timeout(Some(IO_TIMEOUT)).ok();
    let peer = match peer_credentials(&s).and_then(|p| authenticate(&p)) {
        Ok(p) => p,
        Err(e) => {
            let _ = write_frame(&mut s, &to_cbor(&Reply::<()>::Err(e))?);
            return Ok(());
        }
    };
    loop {
        drop(take_reply_resources());
        let frame = match read_frame_limited(&mut s, limits, stats) {
            Ok(f) => f,
            Err(e) => {
                // Oversized / over-budget frames get one error reply; the
                // connection is closed either way (its byte stream is no
                // longer frame-aligned).
                if e.is("IPC_FRAME_TOO_LARGE") || e.is("IPC_BUSY") {
                    let _ = write_frame(&mut s, &to_cbor(&Reply::<()>::Err(e))?);
                }
                return Ok(());
            }
        };
        // The frame stays charged to the budget until its reply is written.
        let reply = match from_cbor::<Req>(&frame.buf).and_then(|req| {
            let fds = match fd_count(&req) {
                None => Vec::new(),
                Some(count) => {
                    let fds=recv_fd_packet(&s,count)?;
                    if fds.len()!=count { fail!(EINVAL,"IPC_REQUEST_FD_COUNT"); }
                    fds
                }
            };
            handler(&peer, req, fds)
        }) {
            Ok(r) => Reply::Ok(r),
            Err(e) => Reply::Err(e),
        };
        // Take resources BEFORE any fallible serialization/write. No stale
        // descriptor or permit can survive an error into another request.
        let resources=take_reply_resources();
        let fds=&resources.fds;
        let ok = matches!(reply, Reply::Ok(_));
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        ciborium::into_writer(&reply, &mut *bytes).map_err(|_|err!(EINVAL,"IPC_ENCODE"))?;
        if ok {
            if let Some(permit)=&resources.permit {
                // If Wipe fenced while queued, emit an error without any FD.
                if let Err(error)=permit.release(|| write_release_before(&mut s,&bytes,&fds,permit.handoff_deadline,permit.handoff_boot_deadline)) {
                    // A failed/partial handoff is never followed by a second
                    // frame: close the connection; no stale success retry.
                    return Err(error);
                }
            } else {
                write_frame(&mut s,&bytes)?;
                if !fds.is_empty() { send_fds(&s,&fds.iter().map(|f|f.as_raw_fd()).collect::<Vec<_>>())?; }
            }
        } else { write_frame(&mut s,&bytes)?; }
        drop(frame);
    }
}

thread_local! {
    static OUTBOX_RELEASE: std::cell::RefCell<Option<ReleasePermit>> = const { std::cell::RefCell::new(None) };
    static OUTBOX_FDS: std::cell::RefCell<Vec<std::os::unix::io::OwnedFd>> = const { std::cell::RefCell::new(Vec::new()) };
    static OUTBOX_GUARDS: std::cell::RefCell<Vec<Box<dyn Send>>> = const { std::cell::RefCell::new(Vec::new()) };
}

// A distinct origin from Instant: the enclave's local raw boot_clock_ns.
// Invalid endpoints become a sticky refusing cap, never an unbounded option.
#[derive(Clone, Copy)]
struct HandoffBootDeadline(u64);
impl HandoffBootDeadline {
    fn new(end: u64) -> Self { Self(if end == u64::MAX { 0 } else { end }) }
    fn require_at(self, now: u64) -> EnclaveResult<()> {
        if self.0 == 0 || self.0 == u64::MAX || now == 0 || now == u64::MAX || now >= self.0 {
            fail!(ETIMEDOUT, "IPC_RELEASE_DEADLINE");
        }
        Ok(())
    }
    fn require_current(self) -> EnclaveResult<()> { self.require_at(crate::clock::boot_clock_ns()) }
}

/// A one-reply authority check serialized with the owner's cancellation fence.
/// Only bounded socket handoff belongs inside this lock, never fsync/network RPC.
pub struct ReleasePermit {
    serial: Arc<std::sync::Mutex<()>>,
    validate: Arc<dyn Fn() -> EnclaveResult<()> + Send + Sync>,
    preflight: Option<Arc<dyn Fn() -> EnclaveResult<()> + Send + Sync>>,
    handoff_deadline: Option<Instant>,
    handoff_boot_deadline: Option<HandoffBootDeadline>,
}
impl ReleasePermit {
    /// Bind a captured generation to its service-owned cancellation mutex.
    pub fn new(serial: Arc<std::sync::Mutex<()>>, validate: Arc<dyn Fn() -> EnclaveResult<()> + Send + Sync>) -> Self { Self { serial, validate, preflight: None, handoff_deadline: None, handoff_boot_deadline: None } }
    /// Preserve an enclosing ceremony's exclusive deadline through the actual
    /// socket handoff. This may shorten, never extend, the release timeout.
    pub fn with_handoff_deadline(mut self, deadline: Instant) -> Self {
        self.handoff_deadline = Some(self.handoff_deadline.map_or(deadline, |original| original.min(deadline))); self
    }
    /// Preserve an independent exclusive raw boot-clock endpoint through each
    /// actual write and final completion. Uses crate::clock::boot_clock_ns,
    /// never Instant conversion or a caller-supplied clock callback. Invalid
    /// zero/MAX endpoints refuse and cannot be revived by later decoration.
    pub fn with_handoff_boot_deadline(mut self, deadline: u64) -> Self {
        let deadline = HandoffBootDeadline::new(deadline);
        self.handoff_boot_deadline = Some(self.handoff_boot_deadline
            .map_or(deadline, |original| HandoffBootDeadline(original.0.min(deadline.0))));
        self
    }
    /// Revalidate remote custody outside the release mutex. The local captured
    /// generation and expiry are checked again after this potentially slow RPC.
    pub fn with_preflight(mut self, preflight: Arc<dyn Fn() -> EnclaveResult<()> + Send + Sync>) -> Self {
        self.preflight=Some(preflight); self
    }
    fn release(&self, send: impl FnOnce() -> EnclaveResult<()>) -> EnclaveResult<()> {
        (self.validate)()?;
        if let Some(preflight)=&self.preflight {preflight()?;}
        let _guard=self.serial.lock().map_err(|_|err!(EIO,"IPC_RELEASE_LOCK"))?;
        (self.validate)()?; send()
    }
}
/// Attach the final authority permit to this handler's reply, including replies
/// without descriptors. It is consumed once and discarded on every error path.
pub fn attach_release_permit(permit: ReleasePermit) { OUTBOX_RELEASE.with(|p| *p.borrow_mut()=Some(permit)); }
// Struct field drop order closes owned FDs before releasing their charges,
// including every early-return/serialization failure path.
struct ReplyResources {fds:Vec<std::os::fd::OwnedFd>,permit:Option<ReleasePermit>,_guards:Vec<Box<dyn Send>>}
fn take_reply_resources() -> ReplyResources {
    ReplyResources {fds:OUTBOX_FDS.with(|o|std::mem::take(&mut *o.borrow_mut())),permit:OUTBOX_RELEASE.with(|o|o.borrow_mut().take()),_guards:OUTBOX_GUARDS.with(|o|std::mem::take(&mut *o.borrow_mut()))}
}
/// Keep transient ownership through serialization and the final FD handoff.
/// Error paths drop it with the failed reply; success promotes the sent object
/// to caller-owned storage when the handoff has finished.
pub fn attach_reply_guard(guard:impl Send+'static) {OUTBOX_GUARDS.with(|o|o.borrow_mut().push(Box::new(guard)));}
/// Absolute maximum duration of a final handoff holding the release fence.
pub const RELEASE_TIMEOUT: Duration = Duration::from_secs(2);
/// Write one complete final frame under the existing absolute handoff deadline.
/// The caller owns release serialization and must close the stream after any
/// error: a partial frame is an uncertain delivered prefix and cannot be retried.
pub fn write_release_frame(s: &mut UnixStream, bytes: &[u8]) -> EnclaveResult<()> {
    write_release(s, bytes, &[])
}

fn write_release(s: &mut UnixStream, bytes: &[u8], fds: &[std::os::fd::OwnedFd]) -> EnclaveResult<()> {
    write_release_before(s,bytes,fds,None,None)
}

fn write_release_before(s: &mut UnixStream, bytes: &[u8], fds: &[std::os::fd::OwnedFd],
    outer_deadline: Option<Instant>, boot_deadline: Option<HandoffBootDeadline>) -> EnclaveResult<()> {
    if bytes.len()>MAX_FRAME {fail!(E2BIG,"IPC_FRAME_TOO_LARGE");}
    s.set_nonblocking(true).map_err(|e|err!(EIO,"IPC_RELEASE_NONBLOCK","{e}"))?;
    let local_deadline=Instant::now()+RELEASE_TIMEOUT;
    let deadline=outer_deadline.map(|deadline|deadline.min(local_deadline)).unwrap_or(local_deadline);
    let result=(|| {
        let size=u32::try_from(bytes.len()).map_err(|_|err!(E2BIG,"IPC_FRAME_TOO_LARGE"))?;
        for mut rest in [&size.to_be_bytes()[..],bytes] {
            while !rest.is_empty() {
                if Instant::now()>=deadline { fail!(ETIMEDOUT,"IPC_RELEASE_DEADLINE"); }
                if let Some(end) = boot_deadline { end.require_current()?; }
                match s.write(rest) {
                    Ok(0)=>fail!(EIO,"IPC_RELEASE_CLOSED"),
                    Ok(n)=>rest=&rest[n..],
                    Err(e) if e.kind()==std::io::ErrorKind::Interrupted=>(),
                    Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>std::thread::sleep(Duration::from_millis(1)),
                    Err(e)=>return Err(err!(EIO,"IPC_RELEASE_WRITE","{e}")),
                }
            }
        }
        if Instant::now()>=deadline { fail!(ETIMEDOUT,"IPC_RELEASE_DEADLINE"); }
        if let Some(end) = boot_deadline { end.require_current()?; }
        if !fds.is_empty() { send_fds(s,&fds.iter().map(|f|f.as_raw_fd()).collect::<Vec<_>>())?; }
        if let Some(end) = boot_deadline { end.require_current()?; }
        if Instant::now()>=deadline { fail!(ETIMEDOUT,"IPC_RELEASE_DEADLINE"); }
        Ok(())
    })();
    // The connection is closed on failure; a successful persistent connection
    // restores its ordinary read framing mode.
    let restore=s.set_nonblocking(false).map_err(|e|err!(EIO,"IPC_RELEASE_NONBLOCK","{e}"));
    result.and(restore)?;
    // A late native completion may have delivered a prefix or FD. Refuse the
    // success receipt after either endpoint; never replay or recall delivery.
    if let Some(end) = boot_deadline { end.require_current()?; }
    if Instant::now()>=deadline { fail!(ETIMEDOUT,"IPC_RELEASE_DEADLINE"); }
    Ok(())
}

/// From inside a request handler: attach read-only FDs to be delivered with
/// `SCM_RIGHTS` immediately after the successful reply frame.
pub fn attach_fds(fds: Vec<std::os::unix::io::OwnedFd>) {
    OUTBOX_FDS.with(|o| o.borrow_mut().extend(fds));
}

/// A client connection that has verified the server's identity.
#[derive(Debug)]
pub struct Client {
    stream: UnixStream,
    /// The server's kernel credentials.
    pub server: PeerCredentials,
}

/// Endpoint-only consumed transport. Selected fault dispatch must use the
/// distinct concrete-guard constructor, never promote this into actor validity.
#[derive(Debug)]
pub(crate) struct AbsoluteClient {
    exchange: AbsoluteExchange<'static, 'static>,
}

/// One original selected-fault exchange borrowing the opaque Native-only guard.
/// No raw stream, clone, reconnect, or deadline substitution is exposed.
#[cfg(any(test, target_os = "macos"))]
#[derive(Debug)]
pub(crate) struct SelectedFaultClient<'guard, 'owner> {
    exchange: AbsoluteExchange<'guard, 'owner>,
}

// Closed concrete choices, not a supplied callback, trait, verifier or permit.
// PhantomData retains valid lifetime parameters in non-macOS production builds.
enum AbsoluteProgress<'guard, 'owner> {
    TransportOnly(std::marker::PhantomData<&'guard &'owner ()>),
    #[cfg(any(test, target_os = "macos"))]
    Selected { guard: &'guard mut crate::supervisor::SelectedFaultIoGuard<'owner>, armed: bool },
}
impl std::fmt::Debug for AbsoluteProgress<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TransportOnly(_) => f.write_str("TransportOnly"),
            #[cfg(any(test, target_os = "macos"))]
            Self::Selected { armed, .. } => f.debug_struct("OriginalSelectedFault").field("armed", armed).finish(),
        }
    }
}
impl AbsoluteProgress<'_, '_> {
    fn current(&mut self, end: Instant) -> EnclaveResult<()> {
        absolute_current(end)?;
        match self {
            Self::TransportOnly(_) => (),
            #[cfg(any(test, target_os = "macos"))]
            Self::Selected { guard, .. } => {
                let result = guard.current(end);
                // Native guard work may itself finish after the endpoint,
                // including an error. Never advance directly from that result.
                absolute_current(end)?;
                result?;
            },
        }
        absolute_current(end)
    }
    fn veto_if_armed(&self) {
        match self {
            Self::TransportOnly(_) => (),
            #[cfg(any(test, target_os = "macos"))]
            Self::Selected { guard, armed: true } => guard.veto(),
            #[cfg(any(test, target_os = "macos"))]
            Self::Selected { armed: false, .. } => (),
        }
    }
    fn complete(&mut self) {
        match self {
            Self::TransportOnly(_) => (),
            #[cfg(any(test, target_os = "macos"))]
            Self::Selected { armed, .. } => *armed = false,
        }
    }
}

/// Owns progress validity BEFORE the first socket is created. Every failure or
/// unwind vetoes the same selected certificate/session before stream teardown.
/// Sync native/codec/destructor work cannot be preempted. Late success is
/// refused; native-call completion and OS scheduling have no hard bound.
#[derive(Debug)]
struct AbsoluteExchange<'guard, 'owner> {
    progress: AbsoluteProgress<'guard, 'owner>,
    stream: Option<UnixStream>,
    server: Option<PeerCredentials>,
    end: Instant,
}
impl Drop for AbsoluteExchange<'_, '_> {
    fn drop(&mut self) { self.progress.veto_if_armed(); }
}

fn absolute_current(end: Instant) -> EnclaveResult<()> {
    if Instant::now() >= end { fail!(ETIMEDOUT, "IPC_ABSOLUTE_DEADLINE"); }
    Ok(())
}

// Delays exist only in test builds, never as a production verifier callback.
#[cfg(test)]
thread_local! {
    static ABSOLUTE_AUTH_DELAY: std::cell::Cell<Duration> = const { std::cell::Cell::new(Duration::ZERO) };
    static ABSOLUTE_AUTH_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl AbsoluteClient {
    fn verify(stream: UnixStream, expected_uid: u32, code: Option<&CodeRequirement>, end: Instant) -> EnclaveResult<Self> {
        let exchange = AbsoluteExchange::verify(stream, expected_uid, code, end,
            AbsoluteProgress::TransportOnly(std::marker::PhantomData))?;
        Ok(Self { exchange })
    }
    /// Original kernel metadata, including the full audit token and channel.
    pub(crate) fn server(&self) -> &PeerCredentials { self.exchange.server() }
    /// Endpoint-only transport; never selected actor/session authority.
    pub(crate) fn call<Req: Serialize, Resp: DeserializeOwned>(mut self, request: &Req) -> EnclaveResult<Resp> {
        self.exchange.call(request)
    }
}

#[cfg(any(test, target_os = "macos"))]
impl SelectedFaultClient<'_, '_> {
    /// Immutable server metadata for the selected wrapper's fixed UID705,
    /// daemon-signature, full native audit-token and non-TLS checks.
    pub(crate) fn server(&self) -> &PeerCredentials { self.exchange.server() }
    /// Consume this one original stream/guard. Missing or malformed receipt
    /// leaves possible request delivery; every error/unwind vetoes before close.
    pub(crate) fn call<Req: Serialize, Resp: DeserializeOwned>(mut self, request: &Req) -> EnclaveResult<Resp> {
        self.exchange.call(request)
    }
}

impl<'guard, 'owner> AbsoluteExchange<'guard, 'owner> {
    fn empty(end: Instant, progress: AbsoluteProgress<'guard, 'owner>) -> Self {
        Self { progress, stream: None, server: None, end }
    }
    fn current(&mut self) -> EnclaveResult<()> { self.progress.current(self.end) }
    fn pause(&mut self) -> EnclaveResult<()> {
        self.current()?;
        std::thread::park_timeout(self.end.saturating_duration_since(Instant::now()).min(Duration::from_millis(1)));
        self.current()
    }
    fn stream(&mut self) -> &mut UnixStream {
        self.stream.as_mut().expect("private absolute exchange owns its socket")
    }
    fn server(&self) -> &PeerCredentials {
        self.server.as_ref().expect("private absolute exchange authenticated before exposure")
    }
    fn verify(stream: UnixStream, expected_uid: u32, code: Option<&CodeRequirement>, end: Instant,
        progress: AbsoluteProgress<'guard, 'owner>) -> EnclaveResult<Self> {
        let mut exchange = Self::empty(end, progress);
        exchange.stream = Some(stream);
        exchange.authenticate(expected_uid, code)?;
        Ok(exchange)
    }
    fn authenticate(&mut self, expected_uid: u32, code: Option<&CodeRequirement>) -> EnclaveResult<()> {
        self.current()?;
        let nonblocking = self.stream().set_nonblocking(true);
        self.current()?;
        nonblocking.map_err(|error| err!(EIO, "IPC_CONNECT", "{error}"))?;
        self.current()?;
        #[cfg(test)]
        ABSOLUTE_AUTH_CALLS.with(|count| count.set(count.get() + 1));
        let credentials = peer_credentials(self.stream());
        #[cfg(test)]
        ABSOLUTE_AUTH_DELAY.with(|delay| std::thread::sleep(delay.replace(Duration::ZERO)));
        self.current()?;
        let mut server = credentials?;
        if server.uid != expected_uid { fail!(EACCES, "SERVER_UID_MISMATCH"); }
        if let (true, Some(requirement)) = (codesign::enforced(), code) {
            let token = server.audit_token.ok_or_else(|| err!(EACCES, "PEER_AUDIT_TOKEN_MISSING"))?;
            self.current()?;
            let identity = codesign::verify_peer(&token, requirement);
            self.current()?;
            server.code_identity = Some(identity.map_err(|error| err!(EACCES, "SERVER_CODESIGN_REJECTED", "{error}"))?);
        }
        self.current()?;
        self.server = Some(server);
        Ok(())
    }
    fn connect(path: &Path, expected_uid: u32, code: Option<&CodeRequirement>, end: Instant,
        progress: AbsoluteProgress<'guard, 'owner>) -> EnclaveResult<Self> {
        use std::os::{fd::FromRawFd, unix::ffi::OsStrExt};
        let mut exchange = Self::empty(end, progress);
        exchange.current()?;
        let bytes = path.as_os_str().as_bytes();
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        if bytes.is_empty() || bytes.contains(&0) || bytes.len() >= address.sun_path.len() { fail!(EINVAL, "IPC_CONNECT_PATH"); }
        address.sun_family = libc::AF_UNIX as _;
        for (target, source) in address.sun_path.iter_mut().zip(bytes) { *target = *source as libc::c_char; }
        let length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
        #[cfg(target_os = "macos")]
        { address.sun_len = length as _; }
        exchange.current()?;
        let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        // Attach owned socket before ANY fallible check or guard call. The
        // exchange Drop then vetoes the original before this stream closes.
        if raw >= 0 { exchange.stream = Some(unsafe { UnixStream::from_raw_fd(raw) }); }
        exchange.current()?;
        if raw < 0 { fail!(EIO, "IPC_CONNECT"); }
        for (get, set, addition) in [(libc::F_GETFD, libc::F_SETFD, libc::FD_CLOEXEC), (libc::F_GETFL, libc::F_SETFL, libc::O_NONBLOCK)] {
            exchange.current()?;
            let flags = unsafe { libc::fcntl(raw, get) };
            exchange.current()?;
            if flags < 0 { fail!(EIO, "IPC_CONNECT"); }
            let status = unsafe { libc::fcntl(raw, set, flags | addition) };
            exchange.current()?;
            if status < 0 { fail!(EIO, "IPC_CONNECT"); }
        }
        loop {
            exchange.current()?;
            let status = unsafe { libc::connect(raw, std::ptr::addr_of!(address).cast(), length as libc::socklen_t) };
            let error = if status < 0 { std::io::Error::last_os_error().raw_os_error().unwrap_or(0) } else { 0 };
            exchange.current()?;
            if status == 0 || error == libc::EISCONN { break; }
            if error == libc::EAGAIN || error == libc::EWOULDBLOCK || error == libc::EINTR {
                exchange.pause()?;
                continue;
            }
            if error != libc::EINPROGRESS && error != libc::EALREADY { fail!(EIO, "IPC_CONNECT"); }
            loop {
                exchange.current()?;
                let mut poll = libc::pollfd { fd: raw, events: libc::POLLOUT, revents: 0 };
                let ready = unsafe { libc::poll(&mut poll, 1, 1) };
                let poll_error = if ready < 0 { std::io::Error::last_os_error().raw_os_error() } else { None };
                exchange.current()?;
                if ready == 0 || poll_error == Some(libc::EINTR) { continue; }
                if ready < 0 || poll.revents & libc::POLLNVAL != 0 { fail!(EIO, "IPC_CONNECT"); }
                let mut pending: libc::c_int = 0;
                let mut size = std::mem::size_of_val(&pending) as libc::socklen_t;
                let status = unsafe { libc::getsockopt(raw, libc::SOL_SOCKET, libc::SO_ERROR, std::ptr::addr_of_mut!(pending).cast(), &mut size) };
                exchange.current()?;
                if status != 0 { fail!(EIO, "IPC_CONNECT"); }
                if pending == libc::EINPROGRESS || pending == libc::EALREADY { continue; }
                if pending != 0 { fail!(EIO, "IPC_CONNECT"); }
                break;
            }
            break;
        }
        exchange.current()?;
        exchange.authenticate(expected_uid, code)?;
        Ok(exchange)
    }
    fn call<Req: Serialize, Resp: DeserializeOwned>(&mut self, request: &Req) -> EnclaveResult<Resp> {
        self.current()?;
        let mut encoded = AbsoluteEncoding::new(self.end);
        let result = ciborium::into_writer(request, &mut encoded);
        // Original actor/session must still hold AFTER all serialization and
        // before the FIRST length byte. No caller-supplied encoder authority.
        self.current()?;
        if encoded.oversized { fail!(E2BIG, "IPC_FRAME_TOO_LARGE"); }
        if encoded.allocation_failed { fail!(ENOMEM, "IPC_FRAME_ALLOC"); }
        result.map_err(|_| err!(EINVAL, "IPC_ENCODE"))?;
        let length = (encoded.bytes.len() as u32).to_be_bytes();
        self.write_all(&length)?;
        self.write_all(&encoded.bytes)?;
        let mut length = [0; 4];
        self.read_exact(&mut length)?;
        let size = u32::from_be_bytes(length) as usize;
        if size > MAX_FRAME { fail!(E2BIG, "IPC_FRAME_TOO_LARGE"); }
        self.current()?;
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        let allocation = bytes.try_reserve_exact(size);
        self.current()?;
        allocation.map_err(|_| err!(ENOMEM, "IPC_FRAME_ALLOC"))?;
        bytes.resize(size, 0);
        self.read_exact(&mut bytes)?;
        self.current()?;
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let decoded = ciborium::from_reader::<Reply<Resp>, _>(&mut cursor);
        self.current()?;
        let decoded = decoded.map_err(|_| err!(EINVAL, "IPC_DECODE"))?;
        if cursor.position() != size as u64 { fail!(EINVAL, "IPC_DECODE", "trailing bytes"); }
        self.current()?;
        match decoded {
            Reply::Ok(reply) => { self.progress.complete(); Ok(reply) },
            Reply::Err(error) => Err(error),
        }
    }
    fn write_all(&mut self, mut bytes: &[u8]) -> EnclaveResult<()> {
        while !bytes.is_empty() {
            self.current()?;
            let result = self.stream().write(bytes);
            self.current()?;
            match result {
                Ok(0) => fail!(EIO, "IPC_WRITE", "zero write"),
                Ok(size) => bytes = &bytes[size..],
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => (),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => self.pause()?,
                Err(error) => return Err(err!(EIO, "IPC_WRITE", "{error}")),
            }
        }
        self.current()
    }
    fn read_exact(&mut self, mut bytes: &mut [u8]) -> EnclaveResult<()> {
        while !bytes.is_empty() {
            self.current()?;
            let result = self.stream().read(bytes);
            self.current()?;
            match result {
                Ok(0) => fail!(EIO, "IPC_READ", "peer closed"),
                Ok(size) => bytes = &mut bytes[size..],
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => (),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => self.pause()?,
                Err(error) => return Err(err!(EIO, "IPC_READ", "{error}")),
            }
        }
        self.current()
    }
}

/// Capped, zeroizing CBOR sink. A custom serializer still needs the postcheck.
struct AbsoluteEncoding {
    bytes: zeroize::Zeroizing<Vec<u8>>,
    end: Instant,
    oversized: bool,
    allocation_failed: bool,
}

impl AbsoluteEncoding {
    fn new(end: Instant) -> Self {
        Self { bytes: zeroize::Zeroizing::new(Vec::new()), end, oversized: false, allocation_failed: false }
    }
}

impl Write for AbsoluteEncoding {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        if Instant::now() >= self.end { return Err(std::io::ErrorKind::TimedOut.into()); }
        if input.len() > MAX_FRAME - self.bytes.len() {
            self.oversized = true;
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        let size = self.bytes.len() + input.len();
        if size > self.bytes.capacity() {
            let capacity = size.max(self.bytes.capacity().saturating_mul(2)).min(MAX_FRAME);
            let additional = capacity - self.bytes.len();
            if self.bytes.try_reserve_exact(additional).is_err() {
                self.allocation_failed = true;
                return Err(std::io::ErrorKind::Other.into());
            }
        }
        self.bytes.extend_from_slice(input);
        if Instant::now() >= self.end { return Err(std::io::ErrorKind::TimedOut.into()); }
        Ok(input.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

impl Client {
    /// Endpoint-only connect/authentication under the caller's original end.
    /// No actor/session validity is granted by this generic transport.
    pub(crate) fn connect_verified_until(path: &Path, expected_uid: u32, code: Option<&CodeRequirement>, end: Instant) -> EnclaveResult<AbsoluteClient> {
        Ok(AbsoluteClient { exchange: AbsoluteExchange::connect(path, expected_uid, code, end,
            AbsoluteProgress::TransportOnly(std::marker::PhantomData))? })
    }

    /// Retain the opaque original selected-fault guard BEFORE creating a socket
    /// and throughout authentication, serialization, framing and typed decode.
    /// The selected Native wrapper separately fixes UID705/daemon policy and
    /// checks native code identity/full audit token/non-TLS before calling.
    #[cfg(any(test, target_os = "macos"))]
    pub(crate) fn connect_selected_fault_until<'guard, 'owner>(path: &Path, expected_uid: u32,
        code: Option<&CodeRequirement>, end: Instant,
        guard: &'guard mut crate::supervisor::SelectedFaultIoGuard<'owner>)
        -> EnclaveResult<SelectedFaultClient<'guard, 'owner>> {
        Ok(SelectedFaultClient { exchange: AbsoluteExchange::connect(path, expected_uid, code, end,
            AbsoluteProgress::Selected { guard, armed: true })? })
    }
}

// Separate selected-readiness transport. It borrows actual retained client
// components through the sealed concrete guard, plus the actual stream slot.
// Existing legacy and selected-fault engines are deliberately unchanged.
struct ReadinessIoAttempt<'io,'owner> {
    guard:&'io mut crate::supervisor::SelectedReadinessIoGuard<'owner>,
    stream:&'io mut Option<UnixStream>,end:Instant,frame_end:Option<Instant>,armed:bool,
}
impl Drop for ReadinessIoAttempt<'_, '_> {
    fn drop(&mut self) {
        if self.armed {
            self.guard.veto();
            if let Some(original)=self.stream.take() {let _=original.shutdown(std::net::Shutdown::Both);}
        }
    }
}
// Inert unless the private backlog fixture explicitly enables it. Only the
// actual syscall sites below write errno/results; no supplied-result seam.
#[cfg(test)]
#[derive(Debug, Default)]
struct ReadinessConnectObservation {
    path:Option<std::path::PathBuf>,descriptor:Option<libc::c_int>,same_endpoint:bool,
    socket_calls:usize,socket_result:Option<libc::c_int>,authentication_calls:usize,
    connect_calls:usize,last_connect:Option<(libc::c_int,libc::c_int)>,wait_connect_calls:usize,
    so_error_calls:usize,last_so_error:Option<(libc::c_int,Option<libc::c_int>,libc::socklen_t,libc::c_int)>,
}
#[cfg(test)]
thread_local! {
    static READINESS_CONNECT_OBSERVATION: std::cell::RefCell<Option<ReadinessConnectObservation>> = const { std::cell::RefCell::new(None) };
    static READINESS_AUTH_DELAY: std::cell::Cell<Duration> = const { std::cell::Cell::new(Duration::ZERO) };
    static READINESS_AUTH_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static READINESS_IO_CHUNK: std::cell::Cell<usize> = const { std::cell::Cell::new(usize::MAX) };
    static READINESS_IO_DELAY: std::cell::Cell<Duration> = const { std::cell::Cell::new(Duration::ZERO) };
}
fn readiness_poll_millis(left:Duration)->EnclaveResult<i32> {
    // Floor the remaining original budget, including nonblocking0ms for a
    // live submillisecond cap; never request a rounded-up1ms wait.
    i32::try_from(left.min(Duration::from_millis(1)).as_millis())
        .map_err(|_|err!(EINVAL,"IPC_CONNECT_DEADLINE"))
}
impl ReadinessIoAttempt<'_, '_> {
    fn current(&mut self)->EnclaveResult<()> {
        absolute_current(self.end)?;
        if let Some(frame)=self.frame_end {absolute_current(frame)?;}
        self.guard.current(self.end,self.stream.as_ref())?;
        // Context/native checks can block. Never let late completion renew
        // the exact original end or this frame's one earlier absolute cap.
        absolute_current(self.end)?;
        if let Some(frame)=self.frame_end {absolute_current(frame)?;}
        Ok(())
    }
    fn stream(&mut self)->EnclaveResult<&mut UnixStream> {
        self.stream.as_mut().ok_or_else(||err!(EACCES,"SUPERVISOR_DEPENDENCY_STREAM_REQUIRED"))
    }
    fn pause(&mut self)->EnclaveResult<()> {
        self.current()?;
        let end=self.frame_end.map_or(self.end,|frame|frame.min(self.end));
        std::thread::park_timeout(end.saturating_duration_since(Instant::now()).min(Duration::from_millis(1)));
        self.current()
    }
    fn begin_frame(&mut self)->EnclaveResult<()> {
        // Existing separate2s write/read frame budgets are preserved. Resetting
        // a frame cannot extend the independent original operation end.
        self.current()?;self.frame_end=Some(self.guard.frame_end(self.end)?);self.current()
    }
    fn write_all(&mut self,mut bytes:&[u8])->EnclaveResult<()> {
        while !bytes.is_empty() {
            self.current()?;
            #[cfg(test)] let bytes_to_offer=&bytes[..READINESS_IO_CHUNK.with(|cap|cap.get()).max(1).min(bytes.len())];
            #[cfg(not(test))] let bytes_to_offer=bytes;
            let result=self.stream()?.write(bytes_to_offer);
            #[cfg(test)] READINESS_IO_DELAY.with(|delay|std::thread::sleep(delay.get()));
            self.current()?;
            match result {
                Ok(0)=>fail!(EIO,"IPC_WRITE"),Ok(count)=>bytes=&bytes[count..],
                Err(error) if error.kind()==std::io::ErrorKind::Interrupted=>{},
                Err(error) if error.kind()==std::io::ErrorKind::WouldBlock=>self.pause()?,
                Err(_)=>fail!(EIO,"IPC_WRITE"),
            }
        }
        self.current()
    }
    fn read_exact(&mut self,mut bytes:&mut[u8])->EnclaveResult<()> {
        while !bytes.is_empty() {
            self.current()?;
            #[cfg(test)] let offered=READINESS_IO_CHUNK.with(|cap|cap.get()).max(1).min(bytes.len());
            #[cfg(not(test))] let offered=bytes.len();
            let result=self.stream()?.read(&mut bytes[..offered]);
            #[cfg(test)] READINESS_IO_DELAY.with(|delay|std::thread::sleep(delay.get()));
            self.current()?;
            match result {
                Ok(0)=>fail!(EIO,"IPC_READ"),Ok(count)=>bytes=&mut bytes[count..],
                Err(error) if error.kind()==std::io::ErrorKind::Interrupted=>{},
                Err(error) if error.kind()==std::io::ErrorKind::WouldBlock=>self.pause()?,
                Err(_)=>fail!(EIO,"IPC_READ"),
            }
        }
        self.current()
    }
    fn connect(&mut self,path:&Path)->EnclaveResult<()> {
        use std::os::{fd::FromRawFd,unix::ffi::OsStrExt};
        self.current()?;
        if self.stream.is_some() {fail!(EACCES,"SUPERVISOR_DEPENDENCY_STREAM_REPLACEMENT");}
        let bytes=path.as_os_str().as_bytes();
        let mut address:libc::sockaddr_un=unsafe{std::mem::zeroed()};
        if bytes.is_empty() || bytes.contains(&0) || bytes.len()>=address.sun_path.len() {fail!(EINVAL,"IPC_CONNECT_PATH");}
        address.sun_family=libc::AF_UNIX as _;
        for (target,source) in address.sun_path.iter_mut().zip(bytes) {*target=*source as libc::c_char;}
        let length=std::mem::offset_of!(libc::sockaddr_un,sun_path)+bytes.len()+1;
        #[cfg(target_os="macos")] {address.sun_len=length as _;}
        self.current()?;
        let raw=unsafe{libc::socket(libc::AF_UNIX,libc::SOCK_STREAM,0)};
        // Attach before ANY postcheck/fcntl/authentication or fallible work.
        if raw>=0 {*self.stream=Some(unsafe{UnixStream::from_raw_fd(raw)});}
        #[cfg(test)] READINESS_CONNECT_OBSERVATION.with(|slot| {
            if let Some(observed)=slot.borrow_mut().as_mut() {
                observed.socket_calls+=1;observed.socket_result=Some(raw);
            }
        });
        self.current()?;
        if raw<0 {fail!(EIO,"IPC_CONNECT");}
        for (get,set,addition) in [(libc::F_GETFD,libc::F_SETFD,libc::FD_CLOEXEC),(libc::F_GETFL,libc::F_SETFL,libc::O_NONBLOCK)] {
            self.current()?;let flags=unsafe{libc::fcntl(raw,get)};self.current()?;
            if flags<0 {fail!(EIO,"IPC_CONNECT");}
            let result=unsafe{libc::fcntl(raw,set,flags|addition)};self.current()?;
            if result<0 {fail!(EIO,"IPC_CONNECT");}
        }
        loop {
            self.current()?;
            let status=unsafe{libc::connect(raw,std::ptr::addr_of!(address).cast(),length as libc::socklen_t)};
            let error=if status<0 {std::io::Error::last_os_error().raw_os_error().unwrap_or(0)}else{0};
            #[cfg(test)] READINESS_CONNECT_OBSERVATION.with(|slot| {
                if let Some(observed)=slot.borrow_mut().as_mut() {
                    observed.same_endpoint &= observed.path.as_deref().map_or(true,|original|original==path)
                        && observed.descriptor.map_or(true,|original|original==raw);
                    observed.path.get_or_insert_with(||path.to_path_buf());observed.descriptor.get_or_insert(raw);
                    observed.connect_calls+=1;observed.last_connect=Some((status,error));
                    if error==libc::EAGAIN || error==libc::EWOULDBLOCK
                        || error==libc::EINPROGRESS || error==libc::EALREADY {observed.wait_connect_calls+=1;}
                }
            });
            self.current()?;
            if status==0 || error==libc::EISCONN {break;}
            if error==libc::EAGAIN || error==libc::EWOULDBLOCK || error==libc::EINTR {self.pause()?;continue;}
            if error!=libc::EINPROGRESS && error!=libc::EALREADY {fail!(EIO,"IPC_CONNECT");}
            loop {
                self.current()?;
                let mut poll=libc::pollfd {fd:raw,events:libc::POLLOUT,revents:0};
                let timeout=readiness_poll_millis(self.end.saturating_duration_since(Instant::now()))?;
                let status=unsafe{libc::poll(&mut poll,1,timeout)};
                let error=if status<0 {std::io::Error::last_os_error().raw_os_error()}else{None};
                self.current()?;
                if status==0 || error==Some(libc::EINTR) {continue;}
                if status<0 || poll.revents&libc::POLLNVAL!=0 {fail!(EIO,"IPC_CONNECT");}
                let mut pending:libc::c_int=0;let mut size=std::mem::size_of_val(&pending) as libc::socklen_t;
                let result=unsafe{libc::getsockopt(raw,libc::SOL_SOCKET,libc::SO_ERROR,std::ptr::addr_of_mut!(pending).cast(),&mut size)};
                #[cfg(test)] {
                    let option_error=if result<0 {std::io::Error::last_os_error().raw_os_error()}else{None};
                    READINESS_CONNECT_OBSERVATION.with(|slot| {
                        if let Some(observed)=slot.borrow_mut().as_mut() {
                            observed.same_endpoint &= observed.descriptor==Some(raw);
                            observed.so_error_calls+=1;observed.last_so_error=Some((result,option_error,size,pending));
                        }
                    });
                }
                self.current()?;
                if result!=0 || size!=std::mem::size_of_val(&pending) as libc::socklen_t {fail!(EIO,"IPC_CONNECT");}
                if pending==libc::EINPROGRESS || pending==libc::EALREADY {continue;}
                if pending!=0 {fail!(EIO,"IPC_CONNECT");}break;
            }
            break;
        }
        self.current()?;
        let stream=self.stream.as_ref().ok_or_else(||err!(EACCES,"SUPERVISOR_DEPENDENCY_STREAM_REQUIRED"))?;
        #[cfg(test)] READINESS_CONNECT_OBSERVATION.with(|slot| {
            if let Some(observed)=slot.borrow_mut().as_mut() {observed.authentication_calls+=1;}
        });
        self.guard.authenticate(stream,self.end)?;
        #[cfg(test)] {
            READINESS_AUTH_CALLS.with(|count|count.set(count.get()+1));
            READINESS_AUTH_DELAY.with(|delay|std::thread::sleep(delay.replace(Duration::ZERO)));
        }
        self.current()
    }
}

// Crate-private and concrete-guard only; no raw stream, callback/provider,
// replacement UID or alternative authentication policy is accepted.
pub(crate) fn connect_selected_readiness_until(path:&Path,stream:&mut Option<UnixStream>,
    guard:&mut crate::supervisor::SelectedReadinessIoGuard<'_>,end:Instant)->EnclaveResult<()> {
    let mut owner=ReadinessIoAttempt {guard,stream,end,frame_end:None,armed:true};
    owner.connect(path)?;owner.current()?;owner.armed=false;Ok(())
}
// A raw bounded frame is not readiness authority. Caller keeps its independent
// outer original veto armed across strict CBOR and all observation checks.
pub(crate) fn exchange_selected_readiness_until(stream:&mut Option<UnixStream>,
    guard:&mut crate::supervisor::SelectedReadinessIoGuard<'_>,body:&[u8],end:Instant)
    ->EnclaveResult<zeroize::Zeroizing<Vec<u8>>> {
    const READINESS_FRAME:usize=8192;
    let mut owner=ReadinessIoAttempt {guard,stream,end,frame_end:None,armed:true};
    owner.current()?;
    if body.len()>READINESS_FRAME {fail!(E2BIG,"IPC_FRAME_TOO_LARGE");}
    // A retained connection is always nonblocking, including fixture streams.
    let result=owner.stream()?.set_nonblocking(true);owner.current()?;result.map_err(|_|err!(EIO,"IPC_NONBLOCKING"))?;
    owner.begin_frame()?;
    owner.write_all(&(body.len() as u32).to_be_bytes())?;owner.write_all(body)?;
    // Discard only the completed write-frame cap, never original operation end.
    owner.frame_end=None;owner.begin_frame()?;
    let mut header=[0;4];owner.read_exact(&mut header)?;
    let size=u32::from_be_bytes(header) as usize;
    if size>READINESS_FRAME {fail!(E2BIG,"IPC_FRAME_TOO_LARGE");}
    owner.current()?;
    let mut bytes=zeroize::Zeroizing::new(Vec::new());let result=bytes.try_reserve_exact(size);
    owner.current()?;result.map_err(|_|err!(ENOMEM,"IPC_FRAME_ALLOC"))?;
    bytes.resize(size,0);owner.current()?;owner.read_exact(&mut bytes)?;
    owner.current()?;owner.armed=false;Ok(bytes)
}

/// A serialized, authenticated one-shot request that has emitted no bytes.
///
/// Prepare this outside an authority owner's release mutex. Its concrete,
/// consuming [`Self::handoff`] method may run beneath that mutex: it performs
/// only a bounded socket write, with no callback, connection lookup or reply
/// wait. Private fields prevent replacing its authenticated stream or payload.
pub struct PreparedCall {
    client: Client,
    bytes: zeroize::Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for PreparedCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedCall")
            .field("server_uid", &self.client.server.uid)
            .field("serialized_bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl PreparedCall {
    /// Transfer the complete request under the absolute [`RELEASE_TIMEOUT`].
    /// Success means the final request byte reached the local socket, not that
    /// the peer accepted or durably stored it. Any error after this is called
    /// must conservatively be treated as possible delivery; this consumes the
    /// connection and never retries a partial or uncertain request.
    pub fn handoff(mut self) -> EnclaveResult<PendingReply> {
        write_release(&mut self.client.stream, &self.bytes, &[])?;
        Ok(PendingReply { client: self.client })
    }
}

/// A completely written one-shot request awaiting its peer's acknowledgement.
/// Drop the owner's release mutex before waiting for this receipt. A lost or
/// invalid reply does not prove that the peer did not accept the request.
pub struct PendingReply {
    client: Client,
}

impl std::fmt::Debug for PendingReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingReply")
            .field("server_uid", &self.client.server.uid)
            .finish_non_exhaustive()
    }
}

impl PendingReply {
    /// Receive and decode a bounded frame under one absolute deadline, including
    /// both its length and body. The connection is consumed on every outcome.
    pub fn receive<R: DeserializeOwned>(self) -> EnclaveResult<R> {
        self.receive_before(Instant::now() + RELEASE_TIMEOUT)
    }

    /// Use one absolute whole-reply deadline, capped at the existing generic
    /// RPC timeout. Fragment progress cannot extend this owner lifetime.
    pub fn receive_with_timeout<R: DeserializeOwned>(self, timeout: Duration) -> EnclaveResult<R> {
        self.receive_before(Instant::now() + timeout.min(IO_TIMEOUT))
    }

    fn receive_before<R: DeserializeOwned>(mut self, deadline: Instant) -> EnclaveResult<R> {
        // This connection is consumed, so no blocking-mode restoration is
        // needed. Darwin can reject SO_RCVTIMEO after the peer closes even
        // when a complete valid reply remains buffered: read those bytes
        // directly without configuring a timeout on a disconnected socket.
        self.client.stream.set_nonblocking(true)
            .map_err(|error| err!(EIO, "IPC_REPLY_NONBLOCK", "{error}"))?;
        let mut len = [0u8; 4];
        self.read_exact_before(&mut len, deadline)?;
        let size = u32::from_be_bytes(len) as usize;
        if size > MAX_FRAME {
            fail!(E2BIG, "IPC_FRAME_TOO_LARGE", "{size} > {MAX_FRAME}");
        }
        let mut frame = zeroize::Zeroizing::new(vec![0; size]);
        self.read_exact_before(&mut frame, deadline)?;
        match from_cbor::<Reply<R>>(&frame)? {
            Reply::Ok(reply) => Ok(reply),
            Reply::Err(error) => Err(error),
        }
    }

    fn read_exact_before(&mut self, mut buf: &mut [u8], deadline: Instant) -> EnclaveResult<()> {
        while !buf.is_empty() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() { fail!(ETIMEDOUT, "IPC_FRAME_DEADLINE"); }
            match self.client.stream.read(buf) {
                Ok(0) => fail!(EIO, "IPC_READ", "peer closed"),
                Ok(count) => buf = &mut buf[count..],
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => (),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(remaining.min(Duration::from_millis(1)));
                }
                Err(error) => return Err(err!(EIO, "IPC_READ", "{error}")),
            }
        }
        if Instant::now() >= deadline { fail!(ETIMEDOUT, "IPC_FRAME_DEADLINE"); }
        Ok(())
    }
}

impl Client {
    /// Connect and verify the server's effective UID (mutual authentication).
    pub fn connect(path: &Path, expected_server_uid: u32) -> EnclaveResult<Self> {
        Self::connect_verified(path, expected_server_uid, None)
    }
    /// Connect and verify the server's UID and, where the platform can,
    /// that it is the expected signed binary (GAP-02), before sending a byte.
    pub fn connect_verified(
        path: &Path,
        expected_server_uid: u32,
        code: Option<&CodeRequirement>,
    ) -> EnclaveResult<Self> {
        let stream = UnixStream::connect(path)
            .map_err(|e| err!(EIO, "IPC_CONNECT", "{}: {e}", path.display()))?;
        Self::verify_stream(stream,expected_server_uid,code)
    }
    /// Bound Unix connection establishment itself before kernel/code identity
    /// verification. This avoids a full listener backlog stalling a health probe.
    pub fn connect_verified_deadline(path:&Path,expected_server_uid:u32,code:Option<&CodeRequirement>,timeout:Duration)->EnclaveResult<Self>{
        use std::os::{fd::{FromRawFd,OwnedFd},unix::ffi::OsStrExt};
        let bytes=path.as_os_str().as_bytes();let mut address:libc::sockaddr_un=unsafe{std::mem::zeroed()};if bytes.is_empty()||bytes.contains(&0)||bytes.len()>=address.sun_path.len(){fail!(EINVAL,"IPC_CONNECT_PATH");}
        address.sun_family=libc::AF_UNIX as _;for (target,source) in address.sun_path.iter_mut().zip(bytes){*target=*source as libc::c_char;}
        let length=std::mem::offset_of!(libc::sockaddr_un,sun_path)+bytes.len()+1;
        #[cfg(target_os="macos")] {address.sun_len=length as _;}
        let raw=unsafe{libc::socket(libc::AF_UNIX,libc::SOCK_STREAM,0)};if raw<0{fail!(EIO,"IPC_CONNECT");}let fd=unsafe{OwnedFd::from_raw_fd(raw)};
        if unsafe{libc::fcntl(raw,libc::F_SETFD,libc::FD_CLOEXEC)}<0||unsafe{libc::fcntl(raw,libc::F_SETFL,libc::O_NONBLOCK)}<0{fail!(EIO,"IPC_CONNECT");}
        let deadline=std::time::Instant::now()+timeout;
        loop {let left=deadline.saturating_duration_since(std::time::Instant::now());if left.is_zero(){fail!(ETIMEDOUT,"IPC_CONNECT_DEADLINE");}
            if unsafe{libc::connect(raw,std::ptr::addr_of!(address).cast(),length as libc::socklen_t)}==0{break;}
            let error=std::io::Error::last_os_error().raw_os_error().unwrap_or(0);if error==libc::EISCONN{break;}if error==libc::EINTR{continue;}if error==libc::EAGAIN||error==libc::EWOULDBLOCK{std::thread::sleep(left.min(Duration::from_millis(2)));continue;}
            if error!=libc::EINPROGRESS&&error!=libc::EALREADY{fail!(EIO,"IPC_CONNECT");}
            let mut poll=libc::pollfd{fd:raw,events:libc::POLLOUT,revents:0};let milliseconds=left.as_millis().max(1).min(i32::MAX as u128) as i32;let status=unsafe{libc::poll(&mut poll,1,milliseconds)};if status==0{fail!(ETIMEDOUT,"IPC_CONNECT_DEADLINE");}if status<0{continue;}
            let mut pending:libc::c_int=0;let mut size=std::mem::size_of_val(&pending) as libc::socklen_t;if unsafe{libc::getsockopt(raw,libc::SOL_SOCKET,libc::SO_ERROR,std::ptr::addr_of_mut!(pending).cast(),&mut size)}!=0||pending!=0{fail!(EIO,"IPC_CONNECT");}
        }
        let stream=UnixStream::from(fd);stream.set_nonblocking(false).map_err(|_|err!(EIO,"IPC_CONNECT"))?;Self::verify_stream(stream,expected_server_uid,code)
    }
    fn verify_stream(stream:UnixStream,expected_server_uid:u32,code:Option<&CodeRequirement>)->EnclaveResult<Self>{
        stream.set_read_timeout(Some(IO_TIMEOUT)).ok();
        stream.set_write_timeout(Some(IO_TIMEOUT)).ok();
        let mut server = peer_credentials(&stream)?;
        if server.uid != expected_server_uid {
            fail!(
                EACCES,
                "SERVER_UID_MISMATCH",
                "expected {expected_server_uid}, socket owned by {}",
                server.uid
            );
        }
        if let (true, Some(req)) = (codesign::enforced(), code) {
            let tok = server
                .audit_token
                .ok_or_else(|| err!(EACCES, "PEER_AUDIT_TOKEN_MISSING"))?;
            server.code_identity = Some(
                codesign::verify_peer(&tok, req)
                    .map_err(|e| err!(EACCES, "SERVER_CODESIGN_REJECTED", "{e}"))?,
            );
        }
        Ok(Self { stream, server })
    }
    /// Consume this verified client without reconnecting or sending bytes.
    /// The caller owns subsequent framing, I/O bounds and connection lifetime;
    /// existing socket deadlines remain in force until the caller changes them.
    pub fn into_authenticated_stream(self) -> UnixStream {
        self.stream
    }
    /// Clone this already authenticated connection for a lifecycle owner to
    /// shut down an in-flight call. Dropping the clone alone does not cancel;
    /// callers must use `shutdown(Both)` and retain their own release fence.
    pub fn cancellation_stream(&self) -> EnclaveResult<UnixStream> {
        self.stream.try_clone().map_err(|_| err!(EIO, "IPC_CANCEL_HANDLE"))
    }
    /// Consume an authenticated one-shot client for a preencoded bare-frame
    /// exchange. No reserialization, request copy, Reply envelope or retry.
    /// Each frame has its own deadline; authentication and caller encoding
    /// are outside these I/O bounds. The connection is dropped on every exit.
    pub fn exchange_preencoded(mut self, body: &[u8], limits: &FrameIoLimits) -> EnclaveResult<zeroize::Zeroizing<Vec<u8>>> {
        write_frame_timed(&mut self.stream, body, limits)?;
        read_frame_timed(&mut self.stream, limits)
    }

    /// Receive file descriptors that the server sends after a reply.
    pub fn recv_fds(&self, max: usize) -> EnclaveResult<Vec<std::os::unix::io::OwnedFd>> {
        recv_fds(&self.stream, max)
    }

    /// Set read and write timeouts on the underlying connection stream.
    pub fn set_timeout(&mut self, timeout: Option<std::time::Duration>) -> EnclaveResult<()> {
        self.stream
            .set_read_timeout(timeout)
            .map_err(|e| err!(EIO, "TIMEOUT_SET", "{e}"))?;
        self.stream
            .set_write_timeout(timeout)
            .map_err(|e| err!(EIO, "TIMEOUT_SET", "{e}"))?;
        Ok(())
    }

    /// Serialize a one-shot request without emitting any request bytes. This
    /// consumes the already authenticated client so final handoff cannot wait
    /// for another request's connection-cache mutex or reuse an uncertain wire.
    pub fn prepare_call<Req: Serialize>(self, req: &Req) -> EnclaveResult<PreparedCall> {
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        ciborium::into_writer(req, &mut *bytes).map_err(|_| err!(EINVAL, "IPC_ENCODE"))?;
        if bytes.len() > MAX_FRAME {
            fail!(E2BIG, "IPC_FRAME_TOO_LARGE", "{} > {MAX_FRAME}", bytes.len());
        }
        Ok(PreparedCall { client: self, bytes })
    }

    /// One typed round trip carrying bounded descriptors before the reply.
    /// The authenticated server must expect this exact descriptor-bearing wire.
    pub fn call_with_fds<Req: Serialize, Resp: DeserializeOwned>(&mut self, req: &Req, fds: &[std::os::fd::RawFd]) -> EnclaveResult<Resp> {
        write_frame(&mut self.stream, &to_cbor(req)?)?;
        send_fd_packet(&self.stream, fds)?;
        match from_cbor::<Reply<Resp>>(&read_frame(&mut self.stream)?)? { Reply::Ok(reply) => Ok(reply), Reply::Err(error) => Err(error) }
    }

    /// One typed round trip.
    pub fn call<Req: Serialize, Resp: DeserializeOwned>(
        &mut self,
        req: &Req,
    ) -> EnclaveResult<Resp> {
        write_frame(&mut self.stream, &to_cbor(req)?)?;
        let f = read_frame(&mut self.stream)?;
        match from_cbor::<Reply<Resp>>(&f)? {
            Reply::Ok(r) => Ok(r),
            Reply::Err(e) => Err(e),
        }
    }
}

/// Send file descriptors over a connected socket with `SCM_RIGHTS`
/// (one marker byte carries the control message).
pub fn send_fds(s: &UnixStream, fds: &[std::os::unix::io::RawFd]) -> EnclaveResult<()> {
    if fds.is_empty() || fds.len() > 16 {
        fail!(EINVAL, "SCM_RIGHTS_COUNT");
    }
    let mut byte = [0x46u8];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let fd_bytes = std::mem::size_of_val(fds);
    // SAFETY: CMSG_SPACE is a pure computation.
    let space = unsafe { libc::CMSG_SPACE(fd_bytes as u32) } as usize;
    let mut cbuf = vec![0u8; space];
    // SAFETY: zeroed msghdr is valid; fields are filled below.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr().cast();
    msg.msg_controllen = space as _;
    // SAFETY: msg_control points at `space` bytes, enough for one cmsg of fd_bytes.
    unsafe {
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(fd_bytes as u32) as _;
        std::ptr::copy_nonoverlapping(fds.as_ptr().cast::<u8>(), libc::CMSG_DATA(c), fd_bytes);
    }
    // SAFETY: valid socket and fully initialised msghdr.
    let n = unsafe { libc::sendmsg(s.as_raw_fd(), &msg, 0) };
    if n != 1 {
        fail!(
            EIO,
            "SCM_RIGHTS_SEND",
            "{}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

/// Send an explicit descriptor packet even when no descriptors are allowed.
pub fn send_fd_packet(s: &UnixStream, fds: &[std::os::fd::RawFd]) -> EnclaveResult<()> {
    if !fds.is_empty() { return send_fds(s, fds); }
    (&*s).write_all(&[0x46]).map_err(|_| err!(EIO, "SCM_RIGHTS_SEND"))
}

/// Receive up to `max` file descriptors sent with [`send_fds`].
pub fn recv_fds(s: &UnixStream, max: usize) -> EnclaveResult<Vec<std::os::unix::io::OwnedFd>> {
    let out = recv_fd_packet(s, max)?;
    if out.is_empty() { fail!(EIO, "SCM_RIGHTS_NONE"); }
    Ok(out)
}

/// Receive one descriptor packet, including the explicit zero-descriptor marker.
/// The caller enforces the operation-specific exact descriptor count.
pub fn recv_fd_packet(s: &UnixStream, max: usize) -> EnclaveResult<Vec<std::os::unix::io::OwnedFd>> {
    use std::os::unix::io::FromRawFd;
    if max > 16 { fail!(EINVAL, "SCM_RIGHTS_COUNT"); }
    let mut byte = [0u8];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    // Receive well beyond the supported 16-FD wire limit, then reject excess
    // after adopting all delivered handles. Darwin externalizes all rights
    // before truncating the user's control buffer; too small a buffer leaks
    // handles whose integers are never returned. Its kernel SCM_RIGHTS limit
    // is at most one MCLBYTES control message (512 FDs); Linux caps at 253.
    // 64 KiB covers both kernels, including headers, with a fixed memory bound.
    let space = 64 * 1024;
    let mut cbuf = vec![0u8; space];
    // SAFETY: zeroed msghdr is valid.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr().cast();
    msg.msg_controllen = space as _;
    // SAFETY: valid socket and buffers.
    let n = unsafe { libc::recvmsg(s.as_raw_fd(), &mut msg, 0) };
    if n < 0 {
        fail!(EIO, "SCM_RIGHTS_RECV");
    }
    let mut out = Vec::new();
    let mut invalid_control = msg.msg_controllen as usize > space;
    // Darwin can retain the original cmsg_len on MSG_CTRUNC. It therefore
    // cannot be used alone as the number of delivered descriptors: doing so
    // reads beyond cbuf and can adopt/close unrelated process descriptors.
    let control_end = cbuf.as_ptr() as usize + (msg.msg_controllen as usize).min(space);
    // SAFETY: validate each header and bound its data by the actual allocation
    // and returned control length before reading any delivered descriptor.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (c as usize).saturating_add(std::mem::size_of::<libc::cmsghdr>()) > control_end {
                invalid_control = true;
                break;
            }
            let data = libc::CMSG_DATA(c);
            let header = data as usize - c as usize;
            let advertised = (*c).cmsg_len as usize;
            if advertised < header {
                invalid_control = true;
                break;
            }
            let available = control_end.saturating_sub(data as usize);
            let len = (advertised - header).min(available);
            let truncated = advertised - header > available;
            invalid_control |= truncated;
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                invalid_control |= len % std::mem::size_of::<libc::c_int>() != 0;
                for i in 0..len / std::mem::size_of::<libc::c_int>() {
                    let fd = std::ptr::read_unaligned(data.cast::<libc::c_int>().add(i));
                    out.push(std::os::unix::io::OwnedFd::from_raw_fd(fd));
                }
            }
            if truncated { break; }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    // Adopt every delivered descriptor before checking flags/marker so errors
    // drop and close them, including a truncated ancillary message.
    if invalid_control || n != 1 || byte[0] != 0x46 || msg.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 || out.len() > max {
        fail!(EIO, "SCM_RIGHTS_TRUNCATED_OR_INVALID");
    }
    for fd in &out {
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        if flags < 0 || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            fail!(EIO, "SCM_RIGHTS_CLOEXEC");
        }
    }
    Ok(out)
}

/// Current effective UID.
pub fn geteuid() -> u32 {
    // SAFETY: no preconditions.
    unsafe { libc::geteuid() }
}

/// Inherit an existing listening socket FD passed via `SCM_RIGHTS` or parent spawn (GAP-63).
pub fn inherit_listener(raw_fd: std::os::unix::io::RawFd) -> EnclaveResult<UnixListener> {
    use std::os::unix::io::FromRawFd;
    if raw_fd < 0 {
        fail!(EINVAL, "INVALID_LISTENER_FD", "raw_fd {raw_fd} is negative");
    }
    // SAFETY: the caller passes a valid listening Unix domain socket descriptor.
    let listener = unsafe { UnixListener::from_raw_fd(raw_fd) };
    listener
        .set_nonblocking(true)
        .map_err(|e| err!(EIO, "IPC_NONBLOCKING", "{e}"))?;
    Ok(listener)
}

/// W3C Trace Context (RFC W3C TraceContext Level 1, GAP-54).
/// Format: `version-trace_id-parent_id-trace_flags`
/// E.g.: `00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct W3cTraceparent {
    /// Specification version (0x00).
    pub version: u8,
    /// 16-byte unique trace identifier.
    pub trace_id: [u8; 16],
    /// 8-byte parent span identifier.
    pub parent_id: [u8; 8],
    /// Trace flags (0x01 = sampled).
    pub trace_flags: u8,
}

impl W3cTraceparent {
    /// Mint a fresh, sampled root trace context.
    pub fn new() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut trace_id = [0u8; 16];
        let mut parent_id = [0u8; 8];
        OsRng.fill_bytes(&mut trace_id);
        OsRng.fill_bytes(&mut parent_id);
        Self {
            version: 0,
            trace_id,
            parent_id,
            trace_flags: 1,
        }
    }

    /// Derive a child span sharing the same `trace_id` with a newly generated `parent_id`.
    pub fn child_span(&self) -> Self {
        use rand_core::{OsRng, RngCore};
        let mut parent_id = [0u8; 8];
        OsRng.fill_bytes(&mut parent_id);
        Self {
            version: self.version,
            trace_id: self.trace_id,
            parent_id,
            trace_flags: self.trace_flags,
        }
    }

    /// Parse a W3C traceparent header string.
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 4 || parts[0] != "00" {
            return None;
        }
        let version = u8::from_str_radix(parts[0], 16).ok()?;
        if parts[1].len() != 32 || parts[2].len() != 16 || parts[3].len() != 2 {
            return None;
        }
        let mut trace_id = [0u8; 16];
        for i in 0..16 {
            trace_id[i] = u8::from_str_radix(&parts[1][i * 2..i * 2 + 2], 16).ok()?;
        }
        let mut parent_id = [0u8; 8];
        for i in 0..8 {
            parent_id[i] = u8::from_str_radix(&parts[2][i * 2..i * 2 + 2], 16).ok()?;
        }
        let trace_flags = u8::from_str_radix(parts[3], 16).ok()?;
        Some(Self {
            version,
            trace_id,
            parent_id,
            trace_flags,
        })
    }

    /// Format as canonical RFC header string.
    pub fn to_header(&self) -> String {
        format!(
            "{:02x}-{}-{}-{:02x}",
            self.version,
            hex::encode(self.trace_id),
            hex::encode(self.parent_id),
            self.trace_flags
        )
    }
}

impl Default for W3cTraceparent {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for W3cTraceparent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_header())
    }
}

/// Outer IPC Envelope with distributed tracing headers (GAP-54).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnclaveIpcEnvelope<T> {
    /// W3C traceparent header.
    pub traceparent: Option<W3cTraceparent>,
    /// Optional W3C tracestate vendor metadata.
    pub tracestate: Option<String>,
    /// Message body payload.
    pub payload: T,
}

impl<T> EnclaveIpcEnvelope<T> {
    /// Wrap payload in an envelope with trace context.
    pub fn new(payload: T, traceparent: Option<W3cTraceparent>) -> Self {
        Self {
            traceparent,
            tracestate: None,
            payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[derive(Debug, Serialize, Deserialize)]
    enum Req {
        Echo(String),
        Fail,
    }

    fn start(policy: PeerPolicy) -> (std::path::PathBuf, Arc<AtomicBool>) {
        let dir = std::env::temp_dir().join(format!("mcpmac-ipc-{}", crate::rng::u64()));
        let path = dir.join("t.sock");
        let l = bind(&path, SocketAccess::OwnerOnly).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let s2 = stop.clone();
        let h = Arc::new(|p: &PeerCredentials, r: Req| -> EnclaveResult<String> {
            match r {
                Req::Echo(x) => Ok(format!("{x}:{}", p.uid)),
                Req::Fail => Err(err!(EPERM, "NOPE")),
            }
        });
        std::thread::spawn(move || serve::<Req, String, _>(l, policy, h, s2));
        (path, stop)
    }

    #[test]
    fn mutual_auth_roundtrip_and_errors() {
        let me = geteuid();
        let (path, stop) = start(PeerPolicy::allow([me]));
        let mut c = Client::connect(&path, me).unwrap();
        assert_eq!(
            c.call::<_, String>(&Req::Echo("hi".into())).unwrap(),
            format!("hi:{me}")
        );
        assert!(c.call::<_, String>(&Req::Fail).unwrap_err().is("NOPE"));
        // Client refuses a server running under the wrong UID.
        assert!(Client::connect(&path, me.wrapping_add(1))
            .unwrap_err()
            .is("SERVER_UID_MISMATCH"));
        stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn server_rejects_unlisted_peer_uid() {
        let me = geteuid();
        let (path, stop) = start(PeerPolicy::allow([me.wrapping_add(1)]));
        let mut c = Client::connect(&path, me).unwrap();
        assert!(c
            .call::<_, String>(&Req::Echo("x".into()))
            .unwrap_err()
            .is("PEER_UID_REJECTED"));
        stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn scm_rights_roundtrip() {
        use std::io::{Read, Seek};
        let (a, b) = UnixStream::pair().unwrap();
        let p = std::env::temp_dir().join(format!("mcpmac-fd-{}", crate::rng::u64()));
        std::fs::write(&p, b"weights").unwrap();
        let f = std::fs::File::open(&p).unwrap();
        send_fds(&a, &[f.as_raw_fd()]).unwrap();
        let fds = recv_fds(&b, 4).unwrap();
        let mut g = std::fs::File::from(fds.into_iter().next().unwrap());
        assert_ne!(unsafe {libc::fcntl(g.as_raw_fd(),libc::F_GETFD)} & libc::FD_CLOEXEC,0);
        g.rewind().unwrap();
        let mut s = String::new();
        g.read_to_string(&mut s).unwrap();
        assert_eq!(s, "weights");
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn scm_rights_rejects_truncated_descriptor_lists() {
        let (a,b)=UnixStream::pair().unwrap();
        let f=std::fs::File::open("/dev/null").unwrap();
        send_fds(&a,&[f.as_raw_fd(),f.as_raw_fd(),f.as_raw_fd()]).unwrap();
        assert!(recv_fds(&b,1).unwrap_err().is("SCM_RIGHTS_TRUNCATED_OR_INVALID"));
    }

    #[test]
    fn scm_rights_excess_handles_do_not_leak_or_close_unrelated_files() {
        const CHILD: &str = "MCPMAC_F13_FD_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "ipc::tests::scm_rights_excess_handles_do_not_leak_or_close_unrelated_files", "--nocapture"])
                .env(CHILD, "1").status().unwrap();
            assert!(status.success());
            return;
        }
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        use std::os::unix::fs::FileExt;
        let (a,b)=UnixStream::pair().unwrap();
        let path=std::env::temp_dir().join(format!("mcpmac-f13-fd-{}",crate::rng::u64()));
        let mut sentinel=std::fs::OpenOptions::new().read(true).write(true).create_new(true)
            .mode(0o600).open(&path).unwrap();
        sentinel.write_all(b"unrelated private sentinel").unwrap();
        std::fs::remove_file(&path).unwrap();
        let identity=sentinel.metadata().unwrap();
        let fd_inventory=|| {
            let directory=if cfg!(target_os="macos") {"/dev/fd"} else {"/proc/self/fd"};
            // Consume and drop ReadDir before comparing. This isolated child
            // executes exactly one test, so no concurrent test opens interfere.
            std::fs::read_dir(directory).unwrap().map(|entry|entry.unwrap().file_name())
                .collect::<BTreeSet<_>>()
        };
        let lowest_free=|| {
            let duplicate=unsafe {libc::fcntl(sentinel.as_raw_fd(),libc::F_DUPFD,0)};
            assert!(duplicate>=0);
            assert_eq!(unsafe {libc::close(duplicate)},0);
            duplicate
        };
        let baseline=lowest_free();
        let inventory=fd_inventory();
        for count in [3usize,17,64].into_iter().cycle().take(64) {
            // Bypass send_fds' cooperative 16-FD limit like a malformed peer.
            let fds=vec![sentinel.as_raw_fd();count];
            let mut marker=[0x46u8];
            let mut iov=libc::iovec{iov_base:marker.as_mut_ptr().cast(),iov_len:1};
            let bytes=std::mem::size_of_val(fds.as_slice());
            let space=unsafe {libc::CMSG_SPACE(bytes as u32)} as usize;
            let mut buffer=vec![0u8;space];
            let mut msg:libc::msghdr=unsafe {std::mem::zeroed()};
            msg.msg_iov=&mut iov;msg.msg_iovlen=1;
            msg.msg_control=buffer.as_mut_ptr().cast();msg.msg_controllen=space as _;
            unsafe {
                let c=libc::CMSG_FIRSTHDR(&msg);
                (*c).cmsg_level=libc::SOL_SOCKET;(*c).cmsg_type=libc::SCM_RIGHTS;
                (*c).cmsg_len=libc::CMSG_LEN(bytes as u32) as _;
                std::ptr::copy_nonoverlapping(fds.as_ptr().cast::<u8>(),libc::CMSG_DATA(c),bytes);
                assert_eq!(libc::sendmsg(a.as_raw_fd(),&msg,0),1);
            }
            assert!(recv_fds(&b,1).unwrap_err().is("SCM_RIGHTS_TRUNCATED_OR_INVALID"));
            let metadata=sentinel.metadata().unwrap();
            assert_eq!((metadata.dev(),metadata.ino()),(identity.dev(),identity.ino()));
            let mut contents=[0u8;26];assert_eq!(sentinel.read_at(&mut contents,0).unwrap(),26);
            assert_eq!(&contents,b"unrelated private sentinel");
            assert_eq!(fd_inventory(),inventory,"descriptor inventory changed after {count} sent handles");
            assert_eq!(lowest_free(),baseline,"descriptor leak after {count} sent handles");
        }
        send_fds(&a,&[sentinel.as_raw_fd()]).unwrap();
        assert_eq!(recv_fds(&b,1).unwrap().len(),1);
        assert_eq!(lowest_free(),baseline);
    }

    fn start_limited(
        limits: ServeLimits,
    ) -> (std::path::PathBuf, Arc<AtomicBool>, Arc<ServeStats>) {
        let dir = std::env::temp_dir().join(format!("mcpmac-ipcl-{}", crate::rng::u64()));
        let path = dir.join("t.sock");
        let l = bind(&path, SocketAccess::OwnerOnly).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(ServeStats::default());
        let (s2, st2) = (stop.clone(), stats.clone());
        let h = Arc::new(|p: &PeerCredentials, r: Req| -> EnclaveResult<String> {
            match r {
                Req::Echo(x) => Ok(format!("{}:{}", x.len(), p.uid)),
                Req::Fail => Err(err!(EPERM, "NOPE")),
            }
        });
        std::thread::spawn(move || {
            serve_with::<Req, String, _>(l, PeerPolicy::allow([geteuid()]), limits, st2, h, s2)
        });
        (path, stop, stats)
    }

    fn reply_err(s: &mut UnixStream) -> Option<EnclaveError> {
        s.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let f = read_frame(s).ok()?;
        match from_cbor::<Reply<String>>(&f).ok()? {
            Reply::Err(e) => Some(e),
            Reply::Ok(_) => None,
        }
    }

    /// GAP-39: sixteen peers each announcing a 1 MiB frame to UID 703 cost no
    /// allocation, partial frames are bounded by the in-flight budget, and
    /// the daemon keeps answering.
    #[test]
    fn sixteen_concurrent_one_mib_frames_keep_custody_bounded_and_alive() {
        let mut limits = ServeLimits::for_daemon(DaemonId::CustodyVault, true);
        limits.frame_deadline = Duration::from_millis(800);
        let (path, stop, stats) = start_limited(limits.clone());
        let rss0 = crate::resource::current_rss_bytes().unwrap_or(0);
        // 1) 1 MiB frames are refused from the header alone.
        let hs: Vec<_> = (0..16)
            .map(|_| {
                let p = path.clone();
                std::thread::spawn(move || {
                    let mut s = UnixStream::connect(&p).unwrap();
                    s.write_all(&(MAX_FRAME as u32).to_be_bytes()).unwrap();
                    let _ = s.write_all(&[0u8; 4096]);
                    reply_err(&mut s).map(|e| e.reason)
                })
            })
            .collect();
        for h in hs {
            assert_eq!(h.join().unwrap().as_deref(), Some("IPC_FRAME_TOO_LARGE"));
        }
        assert_eq!(
            stats.inflight_high_water.load(Ordering::SeqCst),
            0,
            "nothing allocated for refused frames"
        );
        // 2) Sixteen peers each send most of a 250 KiB frame and stall: the
        //    buffered total never exceeds UID 703's 1 MiB budget.
        let stalled: Vec<_> = (0..16)
            .map(|_| {
                let mut s = UnixStream::connect(&path).unwrap();
                s.write_all(&(250u32 * 1024).to_be_bytes()).unwrap();
                let _ = s.write_all(&vec![0u8; 200 * 1024]);
                s
            })
            .collect();
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            stats.inflight_high_water.load(Ordering::SeqCst) <= limits.inflight_bytes,
            "{:?}",
            stats
        );
        assert!(
            stats.busy_rejections.load(Ordering::SeqCst) > 0,
            "the budget, not the connection count, bounds memory"
        );
        let grown = crate::resource::current_rss_bytes()
            .unwrap_or(0)
            .saturating_sub(rss0);
        assert!(grown < 8 * 1024 * 1024, "RSS grew by {grown} bytes");
        // 3) Stalled frames expire at the deadline; the daemon is alive.
        std::thread::sleep(Duration::from_millis(900));
        drop(stalled);
        let mut c = Client::connect(&path, geteuid()).unwrap();
        assert_eq!(
            c.call::<_, String>(&Req::Echo("x".repeat(100_000)))
                .unwrap(),
            format!("100000:{}", geteuid())
        );
        assert_eq!(stats.inflight.load(Ordering::SeqCst), 0);
        stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn per_uid_quota_and_slow_drip_deadline() {
        let limits = ServeLimits {
            max_per_uid: 2,
            frame_deadline: Duration::from_millis(300),
            ..ServeLimits::default()
        };
        let (path, stop, stats) = start_limited(limits);
        let a = Client::connect(&path, geteuid()).unwrap();
        let b = Client::connect(&path, geteuid()).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        let mut third = UnixStream::connect(&path).unwrap();
        assert_eq!(
            reply_err(&mut third).map(|e| e.reason).as_deref(),
            Some("IPC_PEER_QUOTA")
        );
        assert_eq!(stats.quota_rejections.load(Ordering::SeqCst), 1);
        drop((a, b));
        std::thread::sleep(Duration::from_millis(50));
        // A peer trickling one byte every 100 ms is cut off at the frame
        // deadline instead of resetting a per-read timeout forever.
        let mut s = UnixStream::connect(&path).unwrap();
        s.write_all(&1000u32.to_be_bytes()).unwrap();
        let t = std::time::Instant::now();
        let mut closed = false;
        for _ in 0..30 {
            std::thread::sleep(Duration::from_millis(100));
            if s.write_all(&[0u8]).is_err() {
                closed = true;
                break;
            }
            let mut probe = [0u8; 1];
            s.set_nonblocking(true).unwrap();
            let r = s.read(&mut probe);
            s.set_nonblocking(false).unwrap();
            if matches!(r, Ok(0)) {
                closed = true;
                break;
            }
        }
        assert!(
            closed && t.elapsed() < Duration::from_secs(2),
            "slow drip held the connection for {:?}",
            t.elapsed()
        );
        stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn oversized_frames_rejected() {
        let mut buf = Vec::new();
        assert!(write_frame(&mut buf, &vec![0u8; MAX_FRAME + 1]).is_err());
        let mut hdr = ((MAX_FRAME + 1) as u32).to_be_bytes().to_vec();
        hdr.extend([0u8; 8]);
        assert!(read_frame(&mut hdr.as_slice())
            .unwrap_err()
            .is("IPC_FRAME_TOO_LARGE"));
    }

    #[test]
    fn production_matrix_is_least_privilege() {
        // Nobody but UID 704 (and root admin) can reach the model runner.
        assert_eq!(
            production_policy(DaemonId::ModelRunner).allowed_uids,
            BTreeSet::from([0, 704])
        );
        // Every admitted UID is pinned to a signing identity; root only as the CLI.
        for d in DaemonId::ALL {
            let p = production_policy(d);
            assert_eq!(
                p.code.keys().copied().collect::<BTreeSet<_>>(),
                p.allowed_uids
            );
            assert_eq!(p.code[&0].identifier, crate::codesign::CTL_IDENTIFIER);
            for (uid, req) in &p.code {
                if *uid == crate::daemon::GATEWAY_UID {
                    // The auxiliary ingress is deliberately outside DaemonId's
                    // five roles and may reach only the agent runtime.
                    assert_eq!(d, DaemonId::AgentRuntime);
                    assert_eq!(req.identifier, crate::daemon::GATEWAY_IDENTIFIER);
                } else if *uid != 0 {
                    assert_eq!(
                        req.identifier,
                        DaemonId::from_uid(*uid).unwrap().launchd_label()
                    );
                }
            }
        }
        // UID 701 (the model) can never reach the custody vault.
        assert!(!production_policy(DaemonId::CustodyVault)
            .allowed_uids
            .contains(&701));
        // uid=501 user processes reach no daemon.
        for d in DaemonId::ALL {
            assert!(!production_policy(d).allowed_uids.contains(&501));
        }
    }

    #[test]
    fn code_requirement_is_enforced_when_the_platform_can() {
        let p = production_policy(DaemonId::CustodyVault);
        let mut peer = PeerCredentials::local(704, 704);
        peer.audit_token = Some([7; 8]);
        let good = |_: &[u32; 8], r: &CodeRequirement| {
            Ok(CodeIdentity {
                identifier: r.identifier.clone(),
                team_id: r.team_id.clone(),
                cdhash: "aa".into(),
            })
        };
        let impostor = |_: &[u32; 8], r: &CodeRequirement| {
            Err(err!(EACCES, "PEER_CODESIGN_REJECTED", "{}", r.identifier))
        };
        // Right UID + right signature: admitted, identity recorded and bound.
        let ok = p.check_with(&peer, true, &good).unwrap();
        assert_eq!(
            ok.code_identity.as_ref().unwrap().identifier,
            "com.enterprise.enclave.ifc"
        );
        assert_ne!(ok.channel_binding(), peer.channel_binding());
        // Right UID, wrong binary (or any root process that is not the CLI): refused.
        assert!(p
            .check_with(&peer, true, &impostor)
            .unwrap_err()
            .is("PEER_CODESIGN_REJECTED"));
        let mut root = PeerCredentials::local(0, 0);
        root.audit_token = Some([1; 8]);
        assert!(p.check_with(&root, true, &impostor).is_err());
        // No audit token while enforcing: refused, never silently UID-only.
        assert!(p
            .check_with(&PeerCredentials::local(704, 704), true, &good)
            .unwrap_err()
            .is("PEER_AUDIT_TOKEN_MISSING"));
        // Platform without code signing (Linux CI): UID matrix alone.
        assert!(p
            .check_with(&PeerCredentials::local(704, 704), false, &impostor)
            .is_ok());
        assert!(p
            .check_with(&PeerCredentials::local(701, 701), false, &good)
            .unwrap_err()
            .is("PEER_UID_REJECTED"));
    }
}

#[cfg(test)]
mod prepared_call_tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;
    use std::sync::{mpsc, Mutex};

    fn pair() -> (Client, UnixStream) {
        let (client, peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(RELEASE_TIMEOUT)).unwrap();
        peer.set_write_timeout(Some(RELEASE_TIMEOUT)).unwrap();
        (Client::verify_stream(client, geteuid(), None).unwrap(), peer)
    }

    #[test]
    fn prepared_call_real_listener_verifies_uid_before_emitting_and_roundtrips() {
        struct Directory(std::path::PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
        }
        // Native runner checkouts can exceed sockaddr_un's path limit. Only
        // this private owned socket fixture lives in the short runner TMPDIR.
        let root = std::env::temp_dir().canonicalize().unwrap();
        let dir = Directory(root.join(format!("pc-{:x}", crate::rng::u64())));
        std::fs::DirBuilder::new().mode(0o700).create(&dir.0).unwrap();
        let path = dir.0.join("s");
        let listener = UnixListener::bind(&path).unwrap();
        let client = Client::connect_verified_deadline(&path, geteuid(), None, RELEASE_TIMEOUT).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        let prepared = client.prepare_call(&23u64).unwrap();
        peer.set_nonblocking(true).unwrap();
        assert_eq!(peer.read(&mut [0]).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        peer.set_nonblocking(false).unwrap();
        peer.set_read_timeout(Some(RELEASE_TIMEOUT)).unwrap();
        let pending = prepared.handoff().unwrap();
        assert_eq!(from_cbor::<u64>(&read_frame(&mut peer).unwrap()).unwrap(), 23);
        write_frame(&mut peer, &to_cbor(&Reply::Ok(24u64)).unwrap()).unwrap();
        assert_eq!(pending.receive::<u64>().unwrap(), 24);

        let error = Client::connect_verified_deadline(&path, geteuid().wrapping_add(1), None, RELEASE_TIMEOUT)
            .err().unwrap();
        assert!(error.is("SERVER_UID_MISMATCH"));
        let (mut rejected, _) = listener.accept().unwrap();
        rejected.set_nonblocking(true).unwrap();
        assert_eq!(rejected.read(&mut [0]).unwrap(), 0, "UID refusal emits no request");
    }

    #[test]
    fn prepared_call_preparation_errors_emit_no_bytes() {
        struct Invalid;
        impl Serialize for Invalid {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("owned serialization refusal"))
            }
        }
        let (client, mut peer) = pair();
        assert!(client.prepare_call(&Invalid).is_err());
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        let (client, mut peer) = pair();
        let too_large = vec![7u8; MAX_FRAME];
        assert!(client.prepare_call(&serde_bytes::Bytes::new(&too_large)).err().unwrap().is("IPC_FRAME_TOO_LARGE"));
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn prepared_call_complete_handoff_does_not_hold_fence_waiting_for_ack() {
        let (client, mut peer) = pair();
        let serial = Arc::new(Mutex::new(()));
        let prepared = client.prepare_call(&31u64).unwrap();
        let pending = {
            let _release = serial.lock().unwrap();
            prepared.handoff().unwrap()
        };
        assert_eq!(from_cbor::<u64>(&read_frame(&mut peer).unwrap()).unwrap(), 31);
        // No reply exists yet. Establishing this fence must not require one.
        { let _fence = serial.try_lock().expect("completed local send released the fence"); }
        write_frame(&mut peer, &to_cbor(&Reply::Ok(32u64)).unwrap()).unwrap();
        assert_eq!(pending.receive::<u64>().unwrap(), 32, "a pre-fence completed handoff can be acknowledged later");
    }

    #[test]
    fn prepared_call_backpressure_is_bounded_and_releases_serial() {
        let (client, _peer) = pair();
        let send_buffer: libc::c_int = 4096;
        assert_eq!(unsafe {
            libc::setsockopt(client.stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_SNDBUF,
                std::ptr::addr_of!(send_buffer).cast(), std::mem::size_of_val(&send_buffer) as libc::socklen_t)
        }, 0);
        let bytes = vec![1u8; MAX_FRAME - 64];
        let prepared = client.prepare_call(&serde_bytes::Bytes::new(&bytes)).unwrap();
        let serial = Arc::new(Mutex::new(()));
        let gate = serial.clone();
        let (entered, reached) = mpsc::channel();
        let started = Instant::now();
        let worker = std::thread::spawn(move || {
            let _release = gate.lock().unwrap();
            entered.send(()).unwrap();
            prepared.handoff()
        });
        reached.recv_timeout(Duration::from_secs(3)).unwrap();
        { let _fence = serial.lock().unwrap(); }
        assert!(started.elapsed() < Duration::from_secs(5), "finite software timeout, not a hardware/SLO measurement");
        assert!(worker.join().unwrap().err().unwrap().is("IPC_RELEASE_DEADLINE"));
    }

    #[test]
    fn prepared_call_full_request_and_lost_reply_remain_an_error_without_retry() {
        let (client, mut peer) = pair();
        let pending = client.prepare_call(&41u64).unwrap().handoff().unwrap();
        assert_eq!(from_cbor::<u64>(&read_frame(&mut peer).unwrap()).unwrap(), 41);
        // The peer owns the complete request despite this missing receipt.
        drop(peer);
        assert!(pending.receive::<u64>().is_err());
    }

    #[test]
    fn prepared_call_complete_reply_buffered_before_peer_close_remains_valid() {
        let (client, mut peer) = pair();
        let pending = client.prepare_call(&71u64).unwrap().handoff().unwrap();
        assert_eq!(from_cbor::<u64>(&read_frame(&mut peer).unwrap()).unwrap(), 71);
        write_frame(&mut peer, &to_cbor(&Reply::Ok(72u64)).unwrap()).unwrap();
        // A normal one-shot peer can finish and close before receive starts.
        // The complete buffered reply remains valid despite the subsequent EOF.
        drop(peer);
        assert_eq!(pending.receive::<u64>().unwrap(), 72);
    }

    #[test]
    fn prepared_call_reply_length_and_body_share_one_absolute_deadline() {
        let (client, mut peer) = pair();
        let pending = client.prepare_call(&51u64).unwrap().handoff().unwrap();
        assert_eq!(from_cbor::<u64>(&read_frame(&mut peer).unwrap()).unwrap(), 51);
        let reply = to_cbor(&Reply::Ok("x".repeat(128))).unwrap();
        let worker = std::thread::spawn(move || {
            let mut wire = (reply.len() as u32).to_be_bytes().to_vec();
            wire.extend(reply);
            for byte in wire {
                if peer.write_all(&[byte]).is_err() { break; }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let started = Instant::now();
        assert!(pending.receive_before::<String>(started + Duration::from_millis(140)).is_err());
        assert!(started.elapsed() < Duration::from_secs(1), "trickle cannot renew the whole-reply deadline");
        worker.join().unwrap();
    }

    #[test]
    fn prepared_call_peer_errors_malformed_and_oversized_replies_are_not_success() {
        let (client, mut peer) = pair();
        let pending = client.prepare_call(&61u64).unwrap().handoff().unwrap();
        read_frame(&mut peer).unwrap();
        write_frame(&mut peer, &to_cbor(&Reply::<u64>::Err(err!(EPERM, "OWNED_RELAY_REFUSAL"))).unwrap()).unwrap();
        assert!(pending.receive::<u64>().unwrap_err().is("OWNED_RELAY_REFUSAL"));
        let (client, mut peer) = pair();
        let pending = client.prepare_call(&62u64).unwrap().handoff().unwrap();
        read_frame(&mut peer).unwrap();
        write_frame(&mut peer, &[0xff]).unwrap();
        assert!(pending.receive::<u64>().is_err());
        let (client, mut peer) = pair();
        let pending = client.prepare_call(&63u64).unwrap().handoff().unwrap();
        read_frame(&mut peer).unwrap();
        peer.write_all(&((MAX_FRAME + 1) as u32).to_be_bytes()).unwrap();
        assert!(pending.receive::<u64>().unwrap_err().is("IPC_FRAME_TOO_LARGE"));
    }
}

#[cfg(test)]
mod release_tests {
    use super::*;
    use std::sync::{Mutex,atomic::AtomicBool,mpsc};
    fn permit(serial:Arc<Mutex<()>>,valid:Arc<AtomicBool>)->ReleasePermit {
        ReleasePermit::new(serial,Arc::new(move||if valid.load(Ordering::SeqCst){Ok(())}else{Err(err!(EACCES,"TEST_FENCED"))}))
    }
    #[test]
    fn phase1_serialization_error_closes_fds_before_refunding_reply_guard() {
        struct Bad;
        impl Serialize for Bad {fn serialize<S:serde::Serializer>(&self,_:S)->Result<S::Ok,S::Error>{Err(serde::ser::Error::custom("injected serialization failure"))}}
        struct Guard {fd:i32,dropped:Arc<AtomicBool>}
        impl Drop for Guard {fn drop(&mut self){assert_eq!(unsafe{libc::fcntl(self.fd,libc::F_GETFD)},-1);self.dropped.store(true,Ordering::SeqCst);}}
        let (mut client,server)=UnixStream::pair().unwrap();let dropped=Arc::new(AtomicBool::new(false));let seen=dropped.clone();
        let worker=std::thread::spawn(move||handle_conn::<u64,Bad,_,_,_>(server,&|p:&PeerCredentials|Ok(p.clone()),&ServeLimits::default(),&ServeStats::default(),&|_,_,_| {
            let fd:std::os::fd::OwnedFd=std::fs::File::open("Cargo.toml").unwrap().into();
            attach_reply_guard(Guard{fd:fd.as_raw_fd(),dropped:seen.clone()});attach_fds(vec![fd]);Ok(Bad)
        },&|_:&u64|None));
        write_frame(&mut client,&to_cbor(&1u64).unwrap()).unwrap();assert!(read_frame(&mut client).is_err());assert!(worker.join().unwrap().is_err());assert!(dropped.load(Ordering::SeqCst));
    }
    #[test]
    fn phase1_success_sends_reply_and_readonly_fd_and_zero_packet_preserves_next_frame() {
        let (mut a,mut b)=UnixStream::pair().unwrap();
        send_fd_packet(&a,&[]).unwrap();assert!(recv_fd_packet(&b,0).unwrap().is_empty());
        write_frame(&mut a,b"next").unwrap();assert_eq!(read_frame(&mut b).unwrap(),b"next");
        let file=std::fs::File::open("Cargo.toml").unwrap();
        let fds=vec![file.into()];let bytes=to_cbor(&Reply::Ok(7u64)).unwrap();
        permit(Arc::new(Mutex::new(())),Arc::new(AtomicBool::new(true))).release(||write_release(&mut a,&bytes,&fds)).unwrap();
        assert!(matches!(from_cbor::<Reply<u64>>(&read_frame(&mut b).unwrap()).unwrap(),Reply::Ok(7)));
        let received=recv_fds(&b,1).unwrap();assert_eq!(received.len(),1);
        assert_eq!(unsafe{libc::fcntl(received[0].as_raw_fd(),libc::F_GETFL)}&libc::O_ACCMODE,libc::O_RDONLY);
    }
    #[test]
    fn phase1_fence_during_remote_preflight_does_not_block_or_emit() {
        let serial=Arc::new(Mutex::new(()));let valid=Arc::new(AtomicBool::new(true));
        let (entered_tx,entered_rx)=mpsc::channel();let (resume_tx,resume_rx)=mpsc::channel();
        let resume=Arc::new(Mutex::new(resume_rx));
        let p=permit(serial.clone(),valid.clone()).with_preflight(Arc::new(move||{
            entered_tx.send(()).unwrap();resume.lock().unwrap().recv_timeout(Duration::from_secs(3)).unwrap();Ok(())
        }));
        let worker=std::thread::spawn(move||p.release(||panic!("a stale permit must not send")));
        entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        {let _fence=serial.lock().unwrap();valid.store(false,Ordering::SeqCst);}
        resume_tx.send(()).unwrap();assert!(worker.join().unwrap().unwrap_err().is("TEST_FENCED"));
    }
    #[test]
    fn phase1_backpressure_has_absolute_deadline_and_releases_fence() {
        let (mut a,_b)=UnixStream::pair().unwrap();
        let serial=Arc::new(Mutex::new(()));let valid=Arc::new(AtomicBool::new(true));
        let p=permit(serial.clone(),valid);let (tx,rx)=mpsc::channel();let begin=Instant::now();
        let worker=std::thread::spawn(move||p.release(||{tx.send(()).unwrap();write_release(&mut a,&vec![0;MAX_FRAME],&[])}));
        rx.recv_timeout(Duration::from_secs(3)).unwrap();
        {let _fence=serial.lock().unwrap();}
        assert!(begin.elapsed()<Duration::from_secs(4));
        assert!(worker.join().unwrap().unwrap_err().is("IPC_RELEASE_DEADLINE"));
    }
    #[test]
    fn yk03_outer_ceremony_deadline_refuses_before_any_reply_bytes() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let serial = Arc::new(Mutex::new(()));
        let permit = permit(serial.clone(), Arc::new(AtomicBool::new(true)))
            .with_handoff_deadline(Instant::now());
        let error = permit.release(|| write_release_before(&mut sender,
            b"synthetic-secret-must-never-leave", &[], permit.handoff_deadline, permit.handoff_boot_deadline)).unwrap_err();
        assert!(error.is("IPC_RELEASE_DEADLINE"));
        receiver.set_nonblocking(true).unwrap();
        assert_eq!(receiver.read(&mut [0]).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        assert!(serial.try_lock().is_ok(), "expired handoff must release the serial");
    }
    #[test]
    fn phase1_frame_limit_is_checked_before_any_write() {
        let (mut a,mut b)=UnixStream::pair().unwrap();
        assert!(write_release(&mut a,&vec![0;MAX_FRAME+1],&[]).unwrap_err().is("IPC_FRAME_TOO_LARGE"));
        b.set_nonblocking(true).unwrap();assert_eq!(b.read(&mut [0]).unwrap_err().kind(),std::io::ErrorKind::WouldBlock);
    }
    #[test]
    fn phase1_actual_server_discards_queued_success_after_fence() {
        let (mut client,server)=UnixStream::pair().unwrap();
        let serial=Arc::new(Mutex::new(()));let valid=Arc::new(AtomicBool::new(true));
        let (entered_tx,entered_rx)=mpsc::channel();let (resume_tx,resume_rx)=mpsc::channel();
        let resume=Arc::new(Mutex::new(resume_rx));let gate=serial.clone();let current=valid.clone();
        let worker=std::thread::spawn(move||handle_conn::<u64,u64,_,_,_>(server,&|p:&PeerCredentials|Ok(p.clone()),
            &ServeLimits::default(),&ServeStats::default(),&|_,req,_| {
                attach_fds(vec![std::fs::File::open("Cargo.toml").unwrap().into()]);
                attach_release_permit(permit(gate.clone(),current.clone()));
                entered_tx.send(()).unwrap();resume.lock().unwrap().recv_timeout(Duration::from_secs(3)).unwrap();Ok(req)
            },&|_:&u64|None));
        write_frame(&mut client,&to_cbor(&1u64).unwrap()).unwrap();entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        {let _fence=serial.lock().unwrap();valid.store(false,Ordering::SeqCst);}
        resume_tx.send(()).unwrap();assert!(read_frame(&mut client).is_err());
        assert!(worker.join().unwrap().unwrap_err().is("TEST_FENCED"));
    }
    #[test]
    fn phase1_failed_handler_cannot_leak_fd_or_permit_to_next_reply() {
        let (mut client,server)=UnixStream::pair().unwrap();
        let worker=std::thread::spawn(move||handle_conn::<u64,u64,_,_,_>(server,&|p:&PeerCredentials|Ok(p.clone()),
            &ServeLimits::default(),&ServeStats::default(),&|_,req,_| {
                if req==1 {
                    attach_fds(vec![std::fs::File::open("Cargo.toml").unwrap().into()]);
                    attach_release_permit(permit(Arc::new(Mutex::new(())),Arc::new(AtomicBool::new(false))));
                    return Err(err!(EIO,"TEST_HANDLER_ERROR"));
                }
                Ok(req)
            },&|_:&u64|None));
        for n in [1u64,2] {
            write_frame(&mut client,&to_cbor(&n).unwrap()).unwrap();
            let reply=from_cbor::<Reply<u64>>(&read_frame(&mut client).unwrap()).unwrap();
            assert!(if n==1{matches!(reply,Reply::Err(_))}else{matches!(reply,Reply::Ok(2))});
        }
        drop(client);assert!(worker.join().unwrap().is_ok());
    }
    #[test]
    fn yk03_composed_handoff_caps_never_extend_the_original_or_emit_after_it() {
        let expired = Instant::now();
        let later = expired + Duration::from_secs(60);
        for (first, second) in [(expired, later), (later, expired)] {
            let (mut sender, mut receiver) = UnixStream::pair().unwrap();
            let serial = Arc::new(Mutex::new(()));
            let composed = permit(serial.clone(), Arc::new(AtomicBool::new(true)))
                .with_handoff_deadline(first).with_handoff_deadline(second);
            let error = composed.release(|| write_release_before(&mut sender,
                b"synthetic-original-cap-must-not-be-extended", &[], composed.handoff_deadline, composed.handoff_boot_deadline)).unwrap_err();
            assert!(error.is("IPC_RELEASE_DEADLINE"));
            receiver.set_nonblocking(true).unwrap();
            assert_eq!(receiver.read(&mut [0]).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
            assert!(serial.try_lock().is_ok());
        }
    }

    #[test]
    fn yk03_live_raw_boot_cap_allows_actual_frame_and_fd_but_preserves_earlier_instant() {
        let boot = crate::clock::boot_clock_ns();
        assert!(boot != 0 && boot != u64::MAX);
        let end = boot.checked_add(60_000_000_000).unwrap();
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let serial = Arc::new(Mutex::new(()));
        let p = permit(serial.clone(), Arc::new(AtomicBool::new(true)))
            .with_handoff_deadline(Instant::now() + Duration::from_secs(60))
            .with_handoff_boot_deadline(end);
        let fds = vec![std::fs::File::open("Cargo.toml").unwrap().into()];
        p.release(|| write_release_before(&mut sender, b"synthetic-live-raw-cap", &fds,
            p.handoff_deadline, p.handoff_boot_deadline)).unwrap();
        assert_eq!(read_frame(&mut receiver).unwrap(), b"synthetic-live-raw-cap");
        let received = recv_fds(&receiver, 1).unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(unsafe { libc::fcntl(received[0].as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE, libc::O_RDONLY);
        assert!(serial.try_lock().is_ok());
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let p = permit(serial.clone(), Arc::new(AtomicBool::new(true)))
            .with_handoff_deadline(Instant::now()).with_handoff_boot_deadline(end);
        assert!(p.release(|| write_release_before(&mut sender, b"no-instant-extension", &[],
            p.handoff_deadline, p.handoff_boot_deadline)).unwrap_err().is("IPC_RELEASE_DEADLINE"));
        receiver.set_nonblocking(true).unwrap();
        assert_eq!(receiver.read(&mut [0]).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        assert!(serial.try_lock().is_ok());
    }

    #[test]
    fn yk03_raw_boot_cap_rejects_exact_expiry_and_fault_sentinels_without_bytes() {
        assert!(HandoffBootDeadline::new(42).require_at(41).is_ok());
        for now in [0, 42, 43, u64::MAX] {
            assert!(HandoffBootDeadline::new(42).require_at(now).unwrap_err().is("IPC_RELEASE_DEADLINE"));
        }
        for end in [0, u64::MAX, crate::clock::boot_clock_ns()] {
            let (mut sender, mut receiver) = UnixStream::pair().unwrap();
            let serial = Arc::new(Mutex::new(()));
            let p = permit(serial.clone(), Arc::new(AtomicBool::new(true)))
                .with_handoff_deadline(Instant::now() + Duration::from_secs(60))
                .with_handoff_boot_deadline(end);
            let error = p.release(|| write_release_before(&mut sender,
                b"synthetic-expired-raw-cap", &[], p.handoff_deadline, p.handoff_boot_deadline)).unwrap_err();
            assert!(error.is("IPC_RELEASE_DEADLINE"));
            receiver.set_nonblocking(true).unwrap();
            assert_eq!(receiver.read(&mut [0]).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
            assert!(serial.try_lock().is_ok());
        }
        let valid = crate::clock::boot_clock_ns().checked_add(60_000_000_000).unwrap();
        for invalid in [0, u64::MAX] {
            for (first, second) in [(invalid, valid), (valid, invalid)] {
                let p = permit(Arc::new(Mutex::new(())), Arc::new(AtomicBool::new(true)))
                    .with_handoff_boot_deadline(first).with_handoff_boot_deadline(second);
                assert!(p.handoff_boot_deadline.unwrap().require_at(1).is_err());
            }
        }
    }

    #[test]
    fn yk03_actual_backpressure_raw_boot_cap_precedes_later_instant_in_both_orders() {
        for earlier_first in [true, false] {
            let (mut sender, mut receiver) = UnixStream::pair().unwrap();
            let small: libc::c_int = 4096;
            for (fd, option) in [(sender.as_raw_fd(), libc::SO_SNDBUF), (receiver.as_raw_fd(), libc::SO_RCVBUF)] {
                assert_eq!(unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, option,
                    std::ptr::addr_of!(small).cast(), std::mem::size_of_val(&small) as libc::socklen_t) }, 0);
            }
            receiver.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let serial = Arc::new(Mutex::new(()));
            let release_serial = serial.clone();
            let (ready, prepared) = mpsc::channel();
            let worker = std::thread::spawn(move || {
                let began = Instant::now();
                let boot = crate::clock::boot_clock_ns();
                assert!(boot != 0 && boot != u64::MAX);
                let earlier = boot.checked_add(500_000_000).unwrap();
                let later = boot.checked_add(60_000_000_000).unwrap();
                let (first, second) = if earlier_first { (earlier, later) } else { (later, earlier) };
                let p = permit(release_serial, Arc::new(AtomicBool::new(true)))
                    .with_handoff_deadline(Instant::now() + Duration::from_secs(60))
                    .with_handoff_boot_deadline(first).with_handoff_boot_deadline(second);
                ready.send((earlier, began)).unwrap();
                // The real writer must stop on raw time; its Instant/local 2 s
                // endpoints are later. The peer intentionally does not drain.
                p.release(|| write_release_before(&mut sender, &vec![0x5a; MAX_FRAME], &[],
                    p.handoff_deadline, p.handoff_boot_deadline))
            });
            let (end, began) = prepared.recv_timeout(Duration::from_secs(3)).unwrap();
            let scheduling_end = Instant::now() + Duration::from_secs(3);
            loop {
                let mut byte = 0u8;
                if unsafe { libc::recv(receiver.as_raw_fd(), std::ptr::addr_of_mut!(byte).cast(),
                    1, libc::MSG_PEEK | libc::MSG_DONTWAIT) } == 1 { break; }
                assert!(Instant::now() < scheduling_end, "actual queued prefix required");
                std::thread::yield_now();
            }
            assert!(crate::clock::boot_clock_ns() < end, "prefix must be observed before the raw endpoint");
            loop {
                let now = crate::clock::boot_clock_ns();
                assert!(now != 0 && now != u64::MAX);
                if now >= end { break; }
                assert!(Instant::now() < scheduling_end);
                std::thread::sleep(Duration::from_millis(1));
            }
            // This scheduling admission distinguishes the raw 500 ms endpoint
            // from a generic 2 s timeout; it is not a native timing measurement.
            assert!(began.elapsed() < Duration::from_secs(1), "fixture must drain before generic local timeout");
            // Draining after raw expiry would let an Instant-only writer finish
            // before its 2 s local cap. The original raw cap must close instead.
            let mut received = Vec::new();
            receiver.read_to_end(&mut received).unwrap();
            assert!(worker.join().unwrap().unwrap_err().is("IPC_RELEASE_DEADLINE"));
            assert!(!received.is_empty(), "pre-expiry prefix stands");
            assert!(received.len() < MAX_FRAME + 4, "no complete frame after raw expiry");
            assert!(serial.try_lock().is_ok());
        }
    }

}


#[cfg(test)]
mod absolute_client_tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;

    struct Fixture { listener: UnixListener, path: std::path::PathBuf, directory: std::path::PathBuf }
    impl Fixture {
        fn new() -> Self {
            // A relative pathname stays short on Darwin even under a long
            // capture cwd. The fixture owns only this private capture child.
            let directory = std::path::PathBuf::from(format!(".aipc-{:x}-{:x}", std::process::id(), crate::rng::u64()));
            std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
            let path = directory.join("s");
            use std::os::unix::ffi::OsStrExt;
            assert!(path.as_os_str().as_bytes().len() < 104);
            let listener = UnixListener::bind(&path).unwrap();
            Self { listener, path, directory }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_dir(&self.directory);
        }
    }
    fn pair(budget: Duration) -> (AbsoluteClient, UnixStream) {
        let (stream, peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        (AbsoluteClient::verify(stream, geteuid(), None, Instant::now() + budget).unwrap(), peer)
    }
    fn timeout(error: EnclaveError) { assert!(error.is("IPC_ABSOLUTE_DEADLINE"), "{error}"); }

    #[test]
    fn absolute_expired_connect_precedes_socket_and_authentication() {
        let fixture = Fixture::new();
        ABSOLUTE_AUTH_CALLS.with(|calls| calls.set(0));
        timeout(Client::connect_verified_until(&fixture.path, geteuid(), None, Instant::now()).unwrap_err());
        ABSOLUTE_AUTH_CALLS.with(|calls| assert_eq!(calls.get(), 0));
        fixture.listener.set_nonblocking(true).unwrap();
        assert_eq!(fixture.listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    }

    #[test]
    fn absolute_listener_preserves_credentials_and_emits_only_on_consuming_call() {
        let fixture = Fixture::new();
        let client = Client::connect_verified_until(&fixture.path, geteuid(), None, Instant::now() + Duration::from_secs(2)).unwrap();
        assert_eq!(client.server().uid, geteuid());
        assert!(client.server().tls_channel_binding.is_none());
        #[cfg(target_os = "macos")]
        assert!(client.server().audit_token.is_some());
        let (mut peer, _) = fixture.listener.accept().unwrap();
        peer.set_nonblocking(true).unwrap();
        assert_eq!(peer.read(&mut [0]).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        peer.set_nonblocking(false).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let worker = std::thread::spawn(move || {
            assert_eq!(from_cbor::<u64>(&read_frame(&mut peer).unwrap()).unwrap(), 21);
            write_frame(&mut peer, &to_cbor(&Reply::Ok(22u64)).unwrap()).unwrap();
            // Buffered complete reply followed by EOF remains a valid reply.
        });
        assert_eq!(client.call::<_, u64>(&21u64).unwrap(), 22);
        worker.join().unwrap();
        fixture.listener.set_nonblocking(true).unwrap();
        assert_eq!(fixture.listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    }

    #[test]
    fn absolute_wrong_uid_or_late_authentication_emits_no_request() {
        let fixture = Fixture::new();
        let error = Client::connect_verified_until(&fixture.path, geteuid().wrapping_add(1), None, Instant::now() + Duration::from_secs(2)).unwrap_err();
        assert!(error.is("SERVER_UID_MISMATCH"));
        let (mut peer, _) = fixture.listener.accept().unwrap();
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        ABSOLUTE_AUTH_DELAY.with(|delay| delay.set(Duration::from_millis(80)));
        timeout(Client::connect_verified_until(&fixture.path, geteuid(), None, Instant::now() + Duration::from_millis(40)).unwrap_err());
        let (mut peer, _) = fixture.listener.accept().unwrap();
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }

    struct MustNotSerialize;
    impl Serialize for MustNotSerialize {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> { panic!("expired call reached serialization") }
    }
    #[test]
    fn absolute_expired_call_never_serializes_or_writes() {
        let (mut client, mut peer) = pair(Duration::from_secs(2));
        client.exchange.end = Instant::now(); // Test-only access; no setter in the API.
        timeout(client.call::<_, u64>(&MustNotSerialize).unwrap_err());
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn absolute_late_serialization_and_oversized_encoding_emit_no_bytes() {
        struct Slow;
        impl Serialize for Slow {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                std::thread::sleep(Duration::from_millis(80));
                serializer.serialize_u64(1)
            }
        }
        let (client, mut peer) = pair(Duration::from_millis(40));
        timeout(client.call::<_, u64>(&Slow).unwrap_err());
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        let (client, mut peer) = pair(Duration::from_secs(2));
        let bytes = vec![7; MAX_FRAME];
        assert!(client.call::<_, u64>(&serde_bytes::Bytes::new(&bytes)).unwrap_err().is("IPC_FRAME_TOO_LARGE"));
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        let mut encoding = AbsoluteEncoding::new(Instant::now() + Duration::from_secs(2));
        encoding.write_all(&bytes).unwrap();
        assert_eq!(encoding.bytes.len(), MAX_FRAME);
        assert!(encoding.write_all(&[0]).is_err());
        assert_eq!(encoding.bytes.len(), MAX_FRAME);
        assert!(encoding.oversized);
    }

    #[test]
    fn absolute_backpressure_expires_and_consumes_uncertain_partial_request() {
        let (client, mut peer) = pair(Duration::from_millis(100));
        let size: libc::c_int = 4096;
        assert_eq!(unsafe { libc::setsockopt(client.exchange.stream.as_ref().unwrap().as_raw_fd(), libc::SOL_SOCKET, libc::SO_SNDBUF,
            std::ptr::addr_of!(size).cast(), std::mem::size_of_val(&size) as libc::socklen_t) }, 0);
        let bytes = vec![3; MAX_FRAME - 64];
        timeout(client.call::<_, u64>(&serde_bytes::Bytes::new(&bytes)).unwrap_err());
        let mut received = Vec::new();
        peer.read_to_end(&mut received).unwrap();
        assert!(received.len() > 4);
        assert!(received.len() < bytes.len());
    }

    #[test]
    fn absolute_backpressure_and_reply_wait_cannot_each_mint_a_budget() {
        let (client, mut peer) = pair(Duration::from_millis(240));
        let size: libc::c_int = 4096;
        assert_eq!(unsafe { libc::setsockopt(client.exchange.stream.as_ref().unwrap().as_raw_fd(), libc::SOL_SOCKET, libc::SO_SNDBUF,
            std::ptr::addr_of!(size).cast(), std::mem::size_of_val(&size) as libc::socklen_t) }, 0);
        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(140));
            // Read until EOF if the original endpoint passes while writing.
            let request = match read_frame(&mut peer) { Ok(request) => request, Err(_) => return };
            assert!(request.len() > 4096);
            std::thread::sleep(Duration::from_millis(140));
            let _ = write_frame(&mut peer, &to_cbor(&Reply::Ok(1u64)).unwrap());
        });
        let bytes = vec![4; 128 * 1024];
        timeout(client.call::<_, u64>(&serde_bytes::Bytes::new(&bytes)).unwrap_err());
        worker.join().unwrap();
    }

    fn trickle(length_delay: bool, body_delay: bool) {
        let (client, mut peer) = pair(Duration::from_millis(120));
        let worker = std::thread::spawn(move || {
            read_frame(&mut peer).unwrap();
            let reply = to_cbor(&Reply::Ok("x".repeat(128))).unwrap();
            for byte in (reply.len() as u32).to_be_bytes() {
                if peer.write_all(&[byte]).is_err() { return; }
                if length_delay { std::thread::sleep(Duration::from_millis(45)); }
            }
            for byte in reply {
                if peer.write_all(&[byte]).is_err() { return; }
                if body_delay { std::thread::sleep(Duration::from_millis(45)); }
            }
        });
        timeout(client.call::<_, String>(&1u64).unwrap_err());
        worker.join().unwrap();
    }
    #[test]
    fn absolute_trickled_length_cannot_renew_deadline() { trickle(true, false); }
    #[test]
    fn absolute_trickled_body_cannot_renew_deadline() { trickle(false, true); }

    #[test]
    fn absolute_length_body_and_preparation_share_original_endpoint() {
        let (client, mut peer) = pair(Duration::from_millis(160));
        let worker = std::thread::spawn(move || {
            read_frame(&mut peer).unwrap();
            let reply = to_cbor(&Reply::Ok(9u64)).unwrap();
            for byte in (reply.len() as u32).to_be_bytes() {
                if peer.write_all(&[byte]).is_err() { return; }
                std::thread::sleep(Duration::from_millis(25));
            }
            std::thread::sleep(Duration::from_millis(100));
            let _ = peer.write_all(&reply);
        });
        timeout(client.call::<_, u64>(&1u64).unwrap_err());
        worker.join().unwrap();
        // Time spent after authentication but before call is also charged.
        let (client, mut peer) = pair(Duration::from_millis(40));
        std::thread::sleep(Duration::from_millis(80));
        timeout(client.call::<_, u64>(&MustNotSerialize).unwrap_err());
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }

    fn rejected_reply(wire: Vec<u8>, expected: &str) {
        let (client, mut peer) = pair(Duration::from_secs(2));
        let worker = std::thread::spawn(move || {
            assert_eq!(from_cbor::<u64>(&read_frame(&mut peer).unwrap()).unwrap(), 41);
            peer.write_all(&wire).unwrap();
            let mut rest = Vec::new();
            peer.read_to_end(&mut rest).unwrap();
            assert!(rest.is_empty(), "consumed failure did not resend request");
        });
        assert!(client.call::<_, u64>(&41u64).unwrap_err().is(expected));
        worker.join().unwrap();
    }
    fn wire(body: &[u8]) -> Vec<u8> {
        let mut result = (body.len() as u32).to_be_bytes().to_vec();
        result.extend_from_slice(body);
        result
    }
    #[test]
    fn absolute_malformed_oversized_trailing_and_peer_error_replies_fail_without_resend() {
        rejected_reply(wire(&[0xff]), "IPC_DECODE");
        rejected_reply(((MAX_FRAME + 1) as u32).to_be_bytes().to_vec(), "IPC_FRAME_TOO_LARGE");
        let mut trailing = to_cbor(&Reply::Ok(42u64)).unwrap();
        trailing.push(0);
        rejected_reply(wire(&trailing), "IPC_DECODE");
        rejected_reply(wire(&to_cbor(&Reply::<u64>::Err(err!(EPERM, "ABSOLUTE_PEER_REFUSAL"))).unwrap()), "ABSOLUTE_PEER_REFUSAL");
    }

    #[test]
    fn absolute_lost_or_truncated_reply_preserves_uncertain_delivery() {
        for partial in [vec![], vec![0, 0], vec![0, 0, 0, 2, 0]] {
            let (client, mut peer) = pair(Duration::from_secs(2));
            let worker = std::thread::spawn(move || {
                assert_eq!(from_cbor::<u64>(&read_frame(&mut peer).unwrap()).unwrap(), 51);
                peer.write_all(&partial).unwrap();
                // Full request accepted; EOF never grants success or retry.
            });
            assert!(client.call::<_, u64>(&51u64).unwrap_err().is("IPC_READ"));
            worker.join().unwrap();
        }
    }

    #[derive(Debug)]
    struct SlowDecode;
    impl<'de> Deserialize<'de> for SlowDecode {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let _ = u64::deserialize(deserializer)?;
            std::thread::sleep(Duration::from_millis(160));
            Ok(Self)
        }
    }
    #[test]
    fn absolute_complete_but_late_deserialization_is_not_success() {
        let (client, mut peer) = pair(Duration::from_millis(100));
        let worker = std::thread::spawn(move || {
            read_frame(&mut peer).unwrap();
            write_frame(&mut peer, &to_cbor(&Reply::Ok(61u64)).unwrap()).unwrap();
        });
        timeout(client.call::<_, SlowDecode>(&1u64).unwrap_err());
        worker.join().unwrap();
    }
}


#[cfg(test)]
mod selected_fault_client_tests {
    use super::*;
    use crate::supervisor::SelectedFaultIoGuard;
    use std::sync::atomic::AtomicBool;
    use std::os::unix::fs::DirBuilderExt;

    fn pair<'guard, 'owner>(end: Instant, guard: &'guard mut SelectedFaultIoGuard<'owner>)
        -> (SelectedFaultClient<'guard, 'owner>, UnixStream) {
        let (stream, peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        let exchange = AbsoluteExchange::verify(stream, geteuid(), None, end,
            AbsoluteProgress::Selected { guard, armed: true }).unwrap();
        (SelectedFaultClient { exchange }, peer)
    }
    fn context(error: EnclaveError) {
        assert!(error.is("SUPERVISOR_SELECTED_FAULT_IO_CONTEXT"), "{error}");
    }
    struct Fixture { listener: UnixListener, path: std::path::PathBuf, directory: std::path::PathBuf }
    impl Fixture {
        fn new() -> Self {
            let directory = std::path::PathBuf::from(format!(".sfipc-{:x}-{:x}", std::process::id(), crate::rng::u64()));
            std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
            let path = directory.join("s");
            use std::os::unix::ffi::OsStrExt;
            assert!(path.as_os_str().as_bytes().len() < 104);
            let listener = UnixListener::bind(&path).unwrap();
            Self { listener, path, directory }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_dir(&self.directory);
        }
    }

    #[test]
    fn selected_fault_real_listener_keeps_original_guard_through_typed_receipt() {
        let fixture = Fixture::new();
        let valid = AtomicBool::new(true); let calls = AtomicUsize::new(0);
        let end = Instant::now() + Duration::from_secs(2);
        let mut guard = SelectedFaultIoGuard::fixture(end, &valid, &calls);
        let client = Client::connect_selected_fault_until(&fixture.path, geteuid(), None, end, &mut guard).unwrap();
        assert_eq!(client.server().uid, geteuid());
        assert!(client.server().tls_channel_binding.is_none());
        let (mut peer, _) = fixture.listener.accept().unwrap();
        peer.set_nonblocking(true).unwrap();
        assert_eq!(peer.read(&mut [0]).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        peer.set_nonblocking(false).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let worker = std::thread::spawn(move || {
            assert_eq!(from_cbor::<u64>(&read_frame(&mut peer).unwrap()).unwrap(), 11);
            write_frame(&mut peer, &to_cbor(&Reply::Ok(12u64)).unwrap()).unwrap();
        });
        assert_eq!(client.call::<_, u64>(&11u64).unwrap(), 12);
        worker.join().unwrap();
        assert!(valid.load(Ordering::SeqCst), "known success disarms only this transport veto");
        guard.current(end).unwrap();
        assert!(calls.load(Ordering::SeqCst) > 10, "same concrete guard consulted through the exchange");
        fixture.listener.set_nonblocking(true).unwrap();
        assert_eq!(fixture.listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    }

    #[test]
    fn selected_fault_expired_or_vetoed_connect_creates_no_connection() {
        for expired in [false, true] {
            let fixture = Fixture::new();
            let valid = AtomicBool::new(expired); let calls = AtomicUsize::new(0);
            let end = if expired { Instant::now() } else { Instant::now() + Duration::from_secs(2) };
            let mut guard = SelectedFaultIoGuard::fixture(end, &valid, &calls);
            let error = Client::connect_selected_fault_until(&fixture.path, geteuid(), None, end, &mut guard).unwrap_err();
            if expired { assert!(error.is("IPC_ABSOLUTE_DEADLINE")); } else { context(error); }
            assert!(!valid.load(Ordering::SeqCst));
            fixture.listener.set_nonblocking(true).unwrap();
            assert_eq!(fixture.listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        }
    }

    #[test]
    fn selected_fault_replaced_endpoint_retires_original_before_connect() {
        let fixture = Fixture::new();
        let valid = AtomicBool::new(true); let calls = AtomicUsize::new(0);
        let original_end = Instant::now() + Duration::from_secs(2);
        let mut guard = SelectedFaultIoGuard::fixture(original_end, &valid, &calls);
        let error = Client::connect_selected_fault_until(&fixture.path, geteuid(), None,
            original_end + Duration::from_secs(1), &mut guard).unwrap_err();
        context(error);
        assert!(!valid.load(Ordering::SeqCst));
        assert_eq!(calls.load(Ordering::SeqCst), 0, "endpoint substitution precedes concrete fixture/native work");
        fixture.listener.set_nonblocking(true).unwrap();
        assert_eq!(fixture.listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    }

    #[test]
    fn selected_fault_auth_refusal_or_unused_client_drop_vetoes_before_peer_eof() {
        for mode in ["unused", "wrong_uid", "late_auth"] {
            let valid = AtomicBool::new(true); let calls = AtomicUsize::new(0);
            let end = Instant::now() + if mode == "late_auth" { Duration::from_millis(40) } else { Duration::from_secs(2) };
            let mut guard = SelectedFaultIoGuard::fixture(end, &valid, &calls);
            let (stream, mut peer) = UnixStream::pair().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            std::thread::scope(|scope| {
                let observer = scope.spawn(|| {
                    assert_eq!(peer.read(&mut [0]).unwrap(), 0);
                    assert!(!valid.load(Ordering::SeqCst), "negative original owner precedes stream teardown");
                });
                if mode == "late_auth" { ABSOLUTE_AUTH_DELAY.with(|delay| delay.set(Duration::from_millis(80))); }
                let expected_uid = geteuid().wrapping_add(if mode == "wrong_uid" { 1 } else { 0 });
                let exchange = AbsoluteExchange::verify(stream, expected_uid, None, end,
                    AbsoluteProgress::Selected { guard: &mut guard, armed: true });
                match mode {
                    "wrong_uid" => assert!(exchange.unwrap_err().is("SERVER_UID_MISMATCH")),
                    "late_auth" => assert!(exchange.unwrap_err().is("IPC_ABSOLUTE_DEADLINE")),
                    _ => drop(SelectedFaultClient { exchange: exchange.unwrap() }),
                }
                observer.join().unwrap();
            });
            assert!(!valid.load(Ordering::SeqCst));
        }
    }

    #[test]
    fn selected_fault_serialization_veto_precedes_first_length_byte() {
        struct Fence<'a>(&'a AtomicBool);
        impl Serialize for Fence<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.0.store(false, Ordering::SeqCst);
                serializer.serialize_u64(1)
            }
        }
        let valid = AtomicBool::new(true); let calls = AtomicUsize::new(0);
        let end = Instant::now() + Duration::from_secs(2);
        let mut guard = SelectedFaultIoGuard::fixture(end, &valid, &calls);
        let (client, mut peer) = pair(end, &mut guard);
        context(client.call::<_, u64>(&Fence(&valid)).unwrap_err());
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        // Synthetic validity reset cannot revive the privately retired guard.
        valid.store(true, Ordering::SeqCst);
        context(guard.current(end).unwrap_err());
        assert!(!valid.load(Ordering::SeqCst));
    }

    #[test]
    fn selected_fault_serializer_unwind_vetoes_before_socket_teardown() {
        struct Panic;
        impl Serialize for Panic {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> { panic!("selected serialization unwind") }
        }
        let valid = AtomicBool::new(true); let calls = AtomicUsize::new(0);
        let end = Instant::now() + Duration::from_secs(2);
        let mut guard = SelectedFaultIoGuard::fixture(end, &valid, &calls);
        let (client, mut peer) = pair(end, &mut guard);
        std::thread::scope(|scope| {
            let observer = scope.spawn(|| {
                assert_eq!(peer.read(&mut [0]).unwrap(), 0);
                assert!(!valid.load(Ordering::SeqCst));
            });
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _ = client.call::<_, u64>(&Panic);
            })).is_err());
            observer.join().unwrap();
        });
        assert!(!valid.load(Ordering::SeqCst));
    }

    #[test]
    fn selected_fault_original_veto_stops_backpressured_partial_request_without_resend() {
        let valid = AtomicBool::new(true); let calls = AtomicUsize::new(0);
        let end = Instant::now() + Duration::from_secs(2);
        let mut guard = SelectedFaultIoGuard::fixture(end, &valid, &calls);
        let (client, mut peer) = pair(end, &mut guard);
        let size: libc::c_int = 4096;
        assert_eq!(unsafe { libc::setsockopt(client.exchange.stream.as_ref().unwrap().as_raw_fd(), libc::SOL_SOCKET, libc::SO_SNDBUF,
            std::ptr::addr_of!(size).cast(), std::mem::size_of_val(&size) as libc::socklen_t) }, 0);
        std::thread::scope(|scope| {
            let observer = scope.spawn(|| {
                let mut prefix = [0; 4096];
                let first = peer.read(&mut prefix).unwrap();
                assert!(first > 0);
                valid.store(false, Ordering::SeqCst);
                let mut remaining = Vec::new(); peer.read_to_end(&mut remaining).unwrap();
                first + remaining.len()
            });
            let bytes = vec![7; 128 * 1024];
            context(client.call::<_, u64>(&serde_bytes::Bytes::new(&bytes)).unwrap_err());
            let received = observer.join().unwrap();
            assert!(received > 0 && received < bytes.len(), "uncertain prefix is retained, no remaining syscall or replay");
        });
        assert!(!valid.load(Ordering::SeqCst));
    }

    #[test]
    fn selected_fault_veto_during_reply_length_or_body_rejects_buffered_success() {
        for body_started in [false, true] {
            let valid = AtomicBool::new(true); let calls = AtomicUsize::new(0);
            let end = Instant::now() + Duration::from_secs(2);
            let mut guard = SelectedFaultIoGuard::fixture(end, &valid, &calls);
            let (client, mut peer) = pair(end, &mut guard);
            std::thread::scope(|scope| {
                let worker = scope.spawn(|| {
                    read_frame(&mut peer).unwrap();
                    let reply = to_cbor(&Reply::Ok(8u64)).unwrap();
                    let mut wire = (reply.len() as u32).to_be_bytes().to_vec(); wire.extend(reply);
                    let split = if body_started { 5 } else { 2 };
                    peer.write_all(&wire[..split]).unwrap();
                    valid.store(false, Ordering::SeqCst);
                    let _ = peer.write_all(&wire[split..]);
                });
                context(client.call::<_, u64>(&1u64).unwrap_err());
                worker.join().unwrap();
            });
            assert!(!valid.load(Ordering::SeqCst));
        }
    }

    thread_local! {
        static DECODE_VALIDITY: std::cell::RefCell<Option<Arc<AtomicBool>>> = const { std::cell::RefCell::new(None) };
    }
    #[derive(Debug)]
    struct FenceDecode;
    impl<'de> Deserialize<'de> for FenceDecode {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let _ = u64::deserialize(deserializer)?;
            DECODE_VALIDITY.with(|valid| valid.borrow().as_ref().unwrap().store(false, Ordering::SeqCst));
            Ok(Self)
        }
    }
    #[test]
    fn selected_fault_context_loss_inside_deserialization_cannot_publish_positive_reply() {
        let valid = Arc::new(AtomicBool::new(true)); let calls = AtomicUsize::new(0);
        let end = Instant::now() + Duration::from_secs(2);
        let mut guard = SelectedFaultIoGuard::fixture(end, &valid, &calls);
        let (client, mut peer) = pair(end, &mut guard);
        DECODE_VALIDITY.with(|slot| *slot.borrow_mut() = Some(valid.clone()));
        let worker = std::thread::spawn(move || {
            read_frame(&mut peer).unwrap();
            write_frame(&mut peer, &to_cbor(&Reply::Ok(8u64)).unwrap()).unwrap();
        });
        context(client.call::<_, FenceDecode>(&1u64).unwrap_err());
        worker.join().unwrap();
        DECODE_VALIDITY.with(|slot| *slot.borrow_mut() = None);
        assert!(!valid.load(Ordering::SeqCst));
    }

    #[test]
    fn selected_fault_malformed_lost_and_peer_error_receipts_retire_original() {
        for kind in ["malformed", "lost", "peer_error"] {
            let valid = AtomicBool::new(true); let calls = AtomicUsize::new(0);
            let end = Instant::now() + Duration::from_secs(2);
            let mut guard = SelectedFaultIoGuard::fixture(end, &valid, &calls);
            let (client, mut peer) = pair(end, &mut guard);
            let worker = std::thread::spawn(move || {
                read_frame(&mut peer).unwrap();
                match kind {
                    "malformed" => write_frame(&mut peer, &[0xff]).unwrap(),
                    "peer_error" => write_frame(&mut peer, &to_cbor(&Reply::<u64>::Err(err!(EPERM, "SELECTED_PEER_REFUSAL"))).unwrap()).unwrap(),
                    _ => (),
                }
            });
            assert!(client.call::<_, u64>(&1u64).is_err());
            worker.join().unwrap();
            assert!(!valid.load(Ordering::SeqCst));
        }
    }
}


#[cfg(test)]
mod selected_readiness_client_tests {
    use super::*;
    use crate::supervisor::SelectedReadinessIoGuard;
    use std::sync::{Arc,atomic::AtomicBool};
    use std::os::{fd::AsRawFd,unix::fs::DirBuilderExt};
    struct Fixture {listener:UnixListener,path:std::path::PathBuf,directory:std::path::PathBuf}
    impl Fixture {
        fn new()->Self {
            let directory=std::path::PathBuf::from(format!(".sripc-{:x}-{:x}",std::process::id(),crate::rng::u64()));
            std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();let path=directory.join("s");
            let listener=UnixListener::bind(&path).unwrap();Self {listener,path,directory}
        }
    }
    impl Drop for Fixture {fn drop(&mut self){let _=std::fs::remove_file(&self.path);let _=std::fs::remove_dir(&self.directory);}}
    struct IoReset;
    impl Drop for IoReset {
        fn drop(&mut self) {READINESS_IO_CHUNK.with(|cap|cap.set(usize::MAX));READINESS_IO_DELAY.with(|delay|delay.set(Duration::ZERO));READINESS_AUTH_DELAY.with(|delay|delay.set(Duration::ZERO));READINESS_CONNECT_OBSERVATION.with(|slot|slot.replace(None));}
    }
    fn limits()->FrameIoLimits {FrameIoLimits {max_frame:8192,frame_deadline:Duration::from_secs(2),idle_timeout:Duration::from_secs(2)}}

    #[test]
    fn readiness_connect_poll_floor_never_rounds_live_submillisecond_original_cap_up() {
        for left in [Duration::ZERO,Duration::from_nanos(1),Duration::from_nanos(999_999)] {
            assert_eq!(readiness_poll_millis(left).unwrap(),0);
        }
        for left in [Duration::from_millis(1),Duration::from_secs(30),Duration::MAX] {
            assert_eq!(readiness_poll_millis(left).unwrap(),1);
        }
    }

    #[test]
    fn readiness_expired_or_changed_original_end_creates_no_connection_and_sticky_veto_precedes_close() {
        for changed in [false,true] {
            let fixture=Fixture::new();fixture.listener.set_nonblocking(true).unwrap();
            let end=if changed {Instant::now()+Duration::from_secs(2)}else{Instant::now()};
            let valid=AtomicBool::new(true);let calls=AtomicUsize::new(0);let failed=AtomicBool::new(false);
            let mut guard=SelectedReadinessIoGuard::fixture(end,&valid,&calls,&failed);let mut stream=None;
            let offered=if changed {end+Duration::from_secs(1)}else{end};
            assert!(connect_selected_readiness_until(&fixture.path,&mut stream,&mut guard,offered).is_err());
            assert!(stream.is_none());assert!(failed.load(Ordering::SeqCst));assert!(!valid.load(Ordering::SeqCst));
            assert_eq!(calls.load(Ordering::SeqCst),0);
            assert_eq!(fixture.listener.accept().unwrap_err().kind(),std::io::ErrorKind::WouldBlock);
            valid.store(true,Ordering::SeqCst);
            assert!(connect_selected_readiness_until(&fixture.path,&mut stream,&mut guard,end).is_err());
            assert_eq!(calls.load(Ordering::SeqCst),0);
        }
    }

    #[test]
    fn readiness_real_listener_connection_stays_nonblocking_cloexec_and_same_stream_survives_repeated_frames() {
        let fixture=Fixture::new();let end=Instant::now()+Duration::from_secs(2);
        let valid=AtomicBool::new(true);let calls=AtomicUsize::new(0);let failed=AtomicBool::new(false);
        let mut guard=SelectedReadinessIoGuard::fixture(end,&valid,&calls,&failed);let mut stream=None;
        connect_selected_readiness_until(&fixture.path,&mut stream,&mut guard,end).unwrap();
        let original_fd=stream.as_ref().unwrap().as_raw_fd();
        assert_ne!(unsafe{libc::fcntl(original_fd,libc::F_GETFD)}&libc::FD_CLOEXEC,0);
        assert_ne!(unsafe{libc::fcntl(original_fd,libc::F_GETFL)}&libc::O_NONBLOCK,0);
        let (mut server,_)=fixture.listener.accept().unwrap();
        let worker=std::thread::spawn(move|| {
            for expected in [b"first".as_slice(),b"second".as_slice()] {
                assert_eq!(read_frame_timed(&mut server,&limits()).unwrap().as_slice(),expected);
                write_frame_timed(&mut server,expected,&limits()).unwrap();
            }
        });
        for request in [b"first".as_slice(),b"second".as_slice()] {
            assert_eq!(exchange_selected_readiness_until(&mut stream,&mut guard,request,end).unwrap().as_slice(),request);
            assert_eq!(stream.as_ref().unwrap().as_raw_fd(),original_fd);assert!(!failed.load(Ordering::SeqCst));
        }
        assert!(calls.load(Ordering::SeqCst)>20);worker.join().unwrap();
    }

    #[test]
    fn readiness_late_authentication_refuses_original_cap_and_vetoes_before_peer_eof() {
        let _reset=IoReset;let fixture=Fixture::new();let end=Instant::now()+Duration::from_millis(40);
        let valid=Arc::new(AtomicBool::new(true));let failed=Arc::new(AtomicBool::new(false));let calls=AtomicUsize::new(0);
        let listener=fixture.listener.try_clone().unwrap();listener.set_nonblocking(true).unwrap();
        let observed=valid.clone();let terminal=failed.clone();
        let worker=std::thread::spawn(move|| {
            let accept_end=Instant::now()+Duration::from_secs(2);
            let (mut server,_)=loop {match listener.accept() {
                Ok(accepted)=>break accepted,
                Err(error) if error.kind()==std::io::ErrorKind::WouldBlock && Instant::now()<accept_end=>std::thread::yield_now(),
                other=>panic!("bounded late-auth fixture accept failed: {other:?}"),
            }};
            server.set_nonblocking(false).unwrap();server.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            assert_eq!(server.read(&mut[0;1]).unwrap(),0);assert!(terminal.load(Ordering::SeqCst));assert!(!observed.load(Ordering::SeqCst));
        });
        READINESS_AUTH_CALLS.with(|count|count.set(0));READINESS_AUTH_DELAY.with(|delay|delay.set(Duration::from_millis(80)));
        let mut guard=SelectedReadinessIoGuard::fixture(end,&valid,&calls,&failed);let mut stream=None;
        assert!(connect_selected_readiness_until(&fixture.path,&mut stream,&mut guard,end).is_err());
        READINESS_AUTH_CALLS.with(|count|assert_eq!(count.get(),1));assert!(stream.is_none());worker.join().unwrap();
    }

    #[test]
    fn readiness_full_private_backlog_refusal_preserves_original_end_without_authentication() {
        use std::os::unix::fs::{FileTypeExt,MetadataExt};
        let _reset=IoReset;let fixture=Fixture::new();
        let original_listener=fixture.listener.as_raw_fd();
        let original_path=std::fs::symlink_metadata(&fixture.path).unwrap();assert!(original_path.file_type().is_socket());
        assert_eq!(unsafe{libc::listen(original_listener,1)},0);
        let same_listener=|| {
            let current=std::fs::symlink_metadata(&fixture.path).unwrap();
            assert_eq!(fixture.listener.as_raw_fd(),original_listener);
            assert!(current.file_type().is_socket());assert_eq!((current.dev(),current.ino()),(original_path.dev(),original_path.ino()));
        };
        let observe=|| READINESS_CONNECT_OBSERVATION.with(|slot| {
            slot.replace(Some(ReadinessConnectObservation {same_endpoint:true,..Default::default()}));
        });
        let observation=|| READINESS_CONNECT_OBSERVATION.with(|slot|slot.borrow_mut().take().unwrap());
        let check_refusal=|error:&crate::error::EnclaveError,observed:&ReadinessConnectObservation,end:Instant,completed:Instant| {
            assert!(observed.same_endpoint && observed.path.as_deref()==Some(fixture.path.as_path()));
            assert!(observed.descriptor.is_some() && observed.connect_calls>0);
            assert_eq!(observed.socket_calls,1);assert_eq!(observed.socket_result,observed.descriptor);
            assert_eq!(observed.authentication_calls,0);
            #[cfg(target_os="linux")] {
                assert!(error.is("IPC_ABSOLUTE_DEADLINE") || error.is("SUPERVISOR_DEPENDENCY_DEADLINE"));
                assert!(observed.wait_connect_calls>0,"Linux must observe an actual backlog wait: {observed:?}");
                assert!(completed>=end && completed.saturating_duration_since(end)<Duration::from_millis(250));
            }
            #[cfg(target_os="macos")] {
                // Actual guarded private-listener probe observed ECONNREFUSED.
                // This branch proves immediate refusal, NOT deadline waiting.
                assert!(error.is("IPC_CONNECT"));assert_eq!(observed.connect_calls,1);
                assert_eq!(observed.last_connect,Some((-1,libc::ECONNREFUSED)));
                assert_eq!(observed.wait_connect_calls,0);assert_eq!(observed.so_error_calls,0);
                assert_eq!(observed.last_so_error,None);assert!(completed<end);
            }
            #[cfg(not(any(target_os="linux",target_os="macos")))]
            panic!("backlog behavior has no reviewed platform contract: {error:?} {observed:?} {end:?} {completed:?}");
            READINESS_AUTH_CALLS.with(|count|assert_eq!(count.get(),0));
        };
        let mut fillers=Vec::new();let mut reached_full=false;
        for _ in 0..16 {
            same_listener();observe();READINESS_AUTH_CALLS.with(|count|count.set(0));
            let end=Instant::now()+Duration::from_millis(25);let valid=AtomicBool::new(true);let calls=AtomicUsize::new(0);let failed=AtomicBool::new(false);
            let mut guard=SelectedReadinessIoGuard::fixture(end,&valid,&calls,&failed);let mut stream=None;
            let result=connect_selected_readiness_until(&fixture.path,&mut stream,&mut guard,end);let completed=Instant::now();
            let observed=observation();
            match result {
                Ok(())=>{
                    assert!(observed.same_endpoint && observed.path.as_deref()==Some(fixture.path.as_path()));
                    assert_eq!(observed.descriptor,Some(stream.as_ref().unwrap().as_raw_fd()));
                    assert!(observed.connect_calls>0 && completed<end);assert!(!failed.load(Ordering::SeqCst));
                    assert_eq!(observed.socket_calls,1);assert_eq!(observed.socket_result,observed.descriptor);assert_eq!(observed.authentication_calls,1);
                    READINESS_AUTH_CALLS.with(|count|assert_eq!(count.get(),1));fillers.push(stream.take().unwrap());
                },
                Err(error)=>{
                    assert!(!fillers.is_empty(),"full backlog requires at least one actual queued connection");
                    check_refusal(&error,&observed,end,completed);
                    assert!(stream.is_none() && failed.load(Ordering::SeqCst) && !valid.load(Ordering::SeqCst));
                    reached_full=true;break;
                },
            }
        }
        assert!(reached_full && !fillers.is_empty(),"bounded private backlog must actually be observed full");same_listener();
        observe();READINESS_AUTH_CALLS.with(|count|count.set(0));
        let end=Instant::now()+Duration::from_millis(30);let valid=AtomicBool::new(true);let calls=AtomicUsize::new(0);let failed=AtomicBool::new(false);
        let mut guard=SelectedReadinessIoGuard::fixture(end,&valid,&calls,&failed);let mut stream=None;
        let error=connect_selected_readiness_until(&fixture.path,&mut stream,&mut guard,end).unwrap_err();let completed=Instant::now();
        let observed=observation();check_refusal(&error,&observed,end,completed);
        assert!(stream.is_none() && failed.load(Ordering::SeqCst) && !valid.load(Ordering::SeqCst));same_listener();
        // Restoring fixture liveness cannot create a replacement connection.
        observe();let calls_before=calls.load(Ordering::SeqCst);valid.store(true,Ordering::SeqCst);
        assert!(connect_selected_readiness_until(&fixture.path,&mut stream,&mut guard,end).is_err());
        let retry=observation();assert_eq!(retry.socket_calls,0);assert_eq!(retry.connect_calls,0);assert_eq!(retry.so_error_calls,0);
        assert_eq!(retry.authentication_calls,0);assert!(retry.descriptor.is_none());
        assert_eq!(calls.load(Ordering::SeqCst),calls_before);assert!(stream.is_none() && failed.load(Ordering::SeqCst));
        READINESS_AUTH_CALLS.with(|count|assert_eq!(count.get(),0));same_listener();
        // Exact queued filler count, zero request bytes, and EOF after close.
        let queued=fillers.len();drop(fillers);fixture.listener.set_nonblocking(true).unwrap();let mut accepted=0;
        loop {match fixture.listener.accept() {
            Ok((mut server,_))=>{
                accepted+=1;assert!(accepted<=queued);
                // Darwin may reject SO_RCVTIMEO after the queued peer closed.
                // Keep the actual accepted FD nonblocking; require real EOF
                // under one absolute cap, never infer EOF from a poll event.
                server.set_nonblocking(true).unwrap();let eof_end=Instant::now()+Duration::from_secs(2);
                loop {
                    assert!(Instant::now()<eof_end,"private backlog EOF deadline");
                    match server.read(&mut[0;1]) {
                        Ok(0)=>{assert!(Instant::now()<eof_end);break;},
                        Ok(count)=>panic!("private backlog peer emitted {count} request bytes"),
                        Err(error) if error.kind()==std::io::ErrorKind::Interrupted=>{},
                        Err(error) if error.kind()==std::io::ErrorKind::WouldBlock=>{
                            let left=eof_end.saturating_duration_since(Instant::now());assert!(!left.is_zero());
                            let mut poll=libc::pollfd {fd:server.as_raw_fd(),events:libc::POLLIN,revents:0};
                            let milliseconds=i32::try_from(left.min(Duration::from_millis(1)).as_millis()).unwrap();
                            let status=unsafe{libc::poll(&mut poll,1,milliseconds)};
                            let error=if status<0 {std::io::Error::last_os_error().raw_os_error()}else{None};
                            assert!(Instant::now()<eof_end,"private backlog poll completed after EOF deadline");
                            if status<0 {assert_eq!(error,Some(libc::EINTR));}
                            else {assert!(status<=1);assert_eq!(poll.revents&!(libc::POLLIN|libc::POLLHUP),0);}
                        },
                        Err(error)=>panic!("private backlog EOF read failed: {error:?}"),
                    }
                }
                assert!(failed.load(Ordering::SeqCst));
            },
            Err(error) if error.kind()==std::io::ErrorKind::WouldBlock=>break,
            other=>panic!("bounded private backlog drain failed: {other:?}"),
        }}
        assert_eq!(accepted,queued);same_listener();
    }

    #[test]
    fn readiness_existing_stream_is_not_replaced_and_terminal_cleanup_precedes_peer_eof() {
        let fixture=Fixture::new();let (client,mut server)=UnixStream::pair().unwrap();let mut stream=Some(client);
        let end=Instant::now()+Duration::from_secs(2);let valid=AtomicBool::new(true);let calls=AtomicUsize::new(0);let failed=AtomicBool::new(false);
        let mut guard=SelectedReadinessIoGuard::fixture(end,&valid,&calls,&failed);
        assert!(connect_selected_readiness_until(&fixture.path,&mut stream,&mut guard,end).unwrap_err().is("SUPERVISOR_DEPENDENCY_STREAM_REPLACEMENT"));
        assert!(failed.load(Ordering::SeqCst));assert!(!valid.load(Ordering::SeqCst));assert!(stream.is_none());
        assert_eq!(server.read(&mut[0;1]).unwrap(),0);
    }

    #[test]
    fn readiness_partial_request_progress_cannot_renew_original_end_or_resend_after_uncertain_delivery() {
        let _reset=IoReset;READINESS_IO_CHUNK.with(|cap|cap.set(1));READINESS_IO_DELAY.with(|delay|delay.set(Duration::from_millis(2)));
        let (client,mut server)=UnixStream::pair().unwrap();let mut stream=Some(client);
        let end=Instant::now()+Duration::from_millis(40);let valid=AtomicBool::new(true);let calls=AtomicUsize::new(0);let failed=AtomicBool::new(false);
        let mut guard=SelectedReadinessIoGuard::fixture(end,&valid,&calls,&failed);
        assert!(exchange_selected_readiness_until(&mut stream,&mut guard,&[7;1024],end).is_err());
        assert!(stream.is_none() && failed.load(Ordering::SeqCst));
        let mut partial=Vec::new();server.read_to_end(&mut partial).unwrap();assert!(!partial.is_empty() && partial.len()<1028);
        let observed=calls.load(Ordering::SeqCst);valid.store(true,Ordering::SeqCst);
        assert!(exchange_selected_readiness_until(&mut stream,&mut guard,&[7;1024],end).is_err());
        assert_eq!(calls.load(Ordering::SeqCst),observed);
    }

    #[test]
    fn readiness_partial_reply_length_and_body_keep_original_cap_despite_real_byte_progress() {
        for delay_header in [false,true] {
            let (client,mut server)=UnixStream::pair().unwrap();let mut stream=Some(client);
            let worker=std::thread::spawn(move|| {
                let _=read_frame_timed(&mut server,&limits()).unwrap();
                let header=64u32.to_be_bytes();
                if delay_header {
                    for byte in header {if server.write_all(&[byte]).is_err(){return;}std::thread::sleep(Duration::from_millis(20));}
                } else {server.write_all(&header).unwrap();}
                for _ in 0..64 {if server.write_all(&[7]).is_err(){return;}std::thread::sleep(Duration::from_millis(20));}
            });
            let end=Instant::now()+Duration::from_millis(50);let valid=AtomicBool::new(true);let calls=AtomicUsize::new(0);let failed=AtomicBool::new(false);
            let mut guard=SelectedReadinessIoGuard::fixture(end,&valid,&calls,&failed);
            assert!(exchange_selected_readiness_until(&mut stream,&mut guard,&[0],end).is_err());
            assert!(Instant::now()>=end && stream.is_none() && failed.load(Ordering::SeqCst));worker.join().unwrap();
        }
    }

    #[test]
    fn readiness_buffered_reply_cannot_survive_original_context_veto_after_request_delivery() {
        let (client,mut server)=UnixStream::pair().unwrap();let mut stream=Some(client);
        let valid=Arc::new(AtomicBool::new(true));let changed=valid.clone();let calls=AtomicUsize::new(0);let failed=AtomicBool::new(false);
        let worker=std::thread::spawn(move|| {
            assert_eq!(read_frame_timed(&mut server,&limits()).unwrap().as_slice(),&[1,2,3]);
            changed.store(false,Ordering::SeqCst);let _=write_frame_timed(&mut server,&[8],&limits());
        });
        let end=Instant::now()+Duration::from_secs(2);let mut guard=SelectedReadinessIoGuard::fixture(end,&valid,&calls,&failed);
        assert!(exchange_selected_readiness_until(&mut stream,&mut guard,&[1,2,3],end).is_err());
        assert!(stream.is_none() && failed.load(Ordering::SeqCst));worker.join().unwrap();
    }

    #[test]
    fn readiness_oversized_reply_is_refused_without_allocating_unbounded_body_and_vetoes_before_close() {
        let (client,mut server)=UnixStream::pair().unwrap();let mut stream=Some(client);
        let worker=std::thread::spawn(move|| {
            let _=read_frame_timed(&mut server,&limits()).unwrap();server.write_all(&8193u32.to_be_bytes()).unwrap();
            server.set_nonblocking(false).unwrap();server.set_read_timeout(Some(Duration::from_secs(2))).unwrap();assert_eq!(server.read(&mut[0;1]).unwrap(),0);
        });
        let end=Instant::now()+Duration::from_secs(2);let valid=AtomicBool::new(true);let calls=AtomicUsize::new(0);let failed=AtomicBool::new(false);
        let mut guard=SelectedReadinessIoGuard::fixture(end,&valid,&calls,&failed);
        assert!(exchange_selected_readiness_until(&mut stream,&mut guard,&[0],end).unwrap_err().is("IPC_FRAME_TOO_LARGE"));
        assert!(failed.load(Ordering::SeqCst) && stream.is_none());worker.join().unwrap();
    }
}
