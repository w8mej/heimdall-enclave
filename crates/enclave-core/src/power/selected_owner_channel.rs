//! Dedicated selected-attachment connection; never credential/action authority.
//!
//! A custody caller must additionally retain its SAME native transport lifetime
//! token and check it before/after every connect/probe. A local selection witness
//! alone does not prove the original HID owner is alive. No startup is enabled.
//!
//! Root retains the original non-Send native owner on its creating thread. A
//! separate negative-only watcher shuts down the same socket and cancels its
//! original generation on EOF/error/stop/deadline even while the actor is in a
//! native call. This neither interrupts that call nor proves wipe completion.
//! Do not turn this foundation into a readiness/startup permit.
//! Socket audit credentials identify the connected peer, not each byte's writer
//! if that peer exports its FD. This API exposes no FD clone/export; its pinned
//! peer and protected-listener integration must retain that private-stream rule.
//! Version2 requires each native side's independently loaded SAME retained
//! policy-session record. Digest, nonzero policy ID and exact raw boot end are
//! bound before root owner creation and retained across every exchange. The
//! local original Instant only shortens I/O admission; it never chooses raw end.
use std::{io::Cursor, net::Shutdown, os::unix::net::UnixStream, time::{Duration, Instant}};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::{codesign::{self, CodeRequirement}, daemon::DaemonId,
    deployment::{self, CheckedDeploymentTarget, DeploymentRole, DeploymentSigningMode},
    error::EnclaveResult, ipc::{self, FrameIoLimits, PeerCredentials, PeerPolicy},
    Profile, err, fail};
use super::selected_attachment::{AttachmentHint, LocalSelectionWitness};
use super::selected_owner_session::SelectedOwnerSession;

/// A separate connection from the operation-local supervisor readiness socket.
pub const SOCKET_LEAF: &str = "selected-owner-v2.sock";
const FRAME: usize = 8192;
// Per-exchange I/O admission only; not a measured removal/wipe/profile budget.
const EXCHANGE: Duration = Duration::from_secs(2);

fn within(end: Instant) -> EnclaveResult<()> {
    if Instant::now() >= end { fail!(ETIMEDOUT, "SELECTED_OWNER_DEADLINE"); }
    Ok(())
}
fn endpoint(original: Instant, requested: Instant) -> EnclaveResult<Instant> {
    let end = original.min(requested).min(Instant::now() + EXCHANGE);
    within(end)?; Ok(end)
}
fn boot_now() -> EnclaveResult<u64> {
    let now = crate::clock::boot_clock_ns();
    if now == 0 || now == u64::MAX { fail!(EIO, "SELECTED_OWNER_CLOCK"); } Ok(now)
}
fn before_boot(limit: u64) -> EnclaveResult<()> {
    if limit == 0 || limit == u64::MAX || boot_now()? >= limit {
        fail!(ETIMEDOUT, "SELECTED_OWNER_LIFETIME");
    } Ok(())
}
fn nonce() -> EnclaveResult<[u8; 32]> {
    let value = crate::rng::bytes32();
    if value == [0; 32] { fail!(EIO, "SELECTED_OWNER_NONCE"); } Ok(value)
}
fn limits(end: Instant) -> EnclaveResult<FrameIoLimits> {
    within(end)?;
    let left = end.saturating_duration_since(Instant::now());
    Ok(FrameIoLimits { max_frame: FRAME, frame_deadline: left, idle_timeout: left })
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> EnclaveResult<T> {
    if bytes.is_empty() || bytes.len() > FRAME { fail!(EINVAL, "SELECTED_OWNER_SCHEMA"); }
    let mut cursor = Cursor::new(bytes);
    let raw: ciborium::value::Value = ciborium::de::from_reader_with_recursion_limit(&mut cursor, 16)
        .map_err(|_| err!(EINVAL, "SELECTED_OWNER_SCHEMA"))?;
    fn unique(value: &ciborium::value::Value, depth: usize) -> bool {
        if depth > 12 { return false; }
        match value {
            ciborium::value::Value::Map(entries) => entries.iter().enumerate().all(|(i, (key, value))|
                !entries[..i].iter().any(|(old, _)| old == key)
                    && unique(key, depth + 1) && unique(value, depth + 1)),
            ciborium::value::Value::Array(entries) => entries.iter().all(|v| unique(v, depth + 1)),
            ciborium::value::Value::Tag(_, _) => false,
            _ => true,
        }
    }
    if cursor.position() != bytes.len() as u64 || !matches!(raw, ciborium::value::Value::Map(_)) || !unique(&raw, 0) {
        fail!(EINVAL, "SELECTED_OWNER_SCHEMA");
    }
    ciborium::de::from_reader_with_recursion_limit(bytes, 16).map_err(|_| err!(EINVAL, "SELECTED_OWNER_SCHEMA"))
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding { target_id: String, descriptor_sha256: String, profile: Profile, signing: DeploymentSigningMode }
impl Binding {
    fn selected(checked: &CheckedDeploymentTarget) -> Self {
        Self { target_id: checked.target().target_id.clone(), descriptor_sha256: checked.descriptor_sha256().into(),
            profile: checked.target().profile, signing: checked.target().signing_identity_mode }
    }
}
// Private wire metadata, independently captured on each native side from its
// SAME retained protected record. Never derive the raw endpoint from Instant
// or trust a peer's first Bind as authority to choose this session.
#[derive(Clone, Copy, PartialEq, Eq)]
struct PolicySession { record_sha256: [u8; 32], policy_session_id: [u8; 32], expires_boot_ns: u64 }
impl PolicySession {
    fn capture(session: &SelectedOwnerSession) -> EnclaveResult<Self> {
        session.require_current()?;
        let policy = Self { record_sha256: session.record_sha256(), policy_session_id: session.policy_session_id(),
            expires_boot_ns: session.expires_boot_ns() };
        policy.require_current()?; session.require_current()?; Ok(policy)
    }
    fn require_current(&self) -> EnclaveResult<()> {
        if self.policy_session_id == [0; 32] { fail!(EACCES, "SELECTED_OWNER_POLICY_SESSION"); }
        before_boot(self.expires_boot_ns)
    }
    fn matches(&self, record: [u8; 32], policy: [u8; 32], end: u64) -> bool {
        self.record_sha256 == record && self.policy_session_id == policy && self.expires_boot_ns == end
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Kind { Bind, Probe }
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request { version: u8, kind: Kind, binding: Binding, hint: AttachmentHint,
    client: [u8; 32], session: [u8; 32], sequence: u64, challenge: [u8; 32], expires_boot_ns: u64,
    record_sha256: [u8; 32], policy_session_id: [u8; 32] }
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response { version: u8, binding: Binding, hint: AttachmentHint, client: [u8; 32],
    session: [u8; 32], sequence: u64, challenge: [u8; 32], expires_boot_ns: u64,
    record_sha256: [u8; 32], policy_session_id: [u8; 32], started_boot_ns: u64, ended_boot_ns: u64 }

struct Connection(UnixStream, Option<Arc<SelectedOwnerSession>>);
impl Connection {
    fn close(&self) {
        // A native Connection can drop before its outer actor/attempt guard.
        // Invalidate SAME policy first, even if socket cleanup then blocks.
        if let Some(session) = &self.1 { session.revoke(); }
        let _ = self.0.shutdown(Shutdown::Both);
    }
}
impl Drop for Connection { fn drop(&mut self) { self.close(); } }

// Also poison when a caller catches an unwind while retaining the channel.
// Merely relying on the channel's eventual Drop would leave that owner live.
trait CloseOnFailure { fn close_on_failure(&mut self); }
struct FailureGuard<'a, T: CloseOnFailure> { owner: &'a mut T, armed: bool }
impl<'a, T: CloseOnFailure> FailureGuard<'a, T> {
    fn new(owner: &'a mut T) -> Self { Self { owner, armed: true } }
    fn finish(mut self, result: EnclaveResult<()>) -> EnclaveResult<()> {
        if result.is_ok() { self.armed = false; } result
    }
}
impl<T: CloseOnFailure> Drop for FailureGuard<'_, T> {
    fn drop(&mut self) { if self.armed { self.owner.close_on_failure(); } }
}

// Native authentication is never replaceable by a public bool/provider. Pure
// comparison tests below cannot construct a production Context or channel.
fn same_peer(original: &PeerCredentials, current: &PeerCredentials) -> EnclaveResult<()> {
    if original.audit_token.is_none() || original.code_identity.is_none()
        || current.audit_token.is_none() || current.code_identity.is_none()
        || current != original { fail!(EACCES, "SELECTED_OWNER_PEER_CHANGED"); }
    Ok(())
}
fn authenticate(stream: &UnixStream, uid: u32, requirement: &CodeRequirement, end: Instant) -> EnclaveResult<PeerCredentials> {
    within(end)?;
    if !cfg!(target_os = "macos") || !codesign::enforced() || requirement.cdhash_allowlist.is_empty() {
        fail!(ENOSYS, "SELECTED_OWNER_NATIVE_CODE_REQUIRED");
    }
    let raw = ipc::peer_credentials(stream)?;
    let peer = PeerPolicy::allow([]).require(uid, requirement.clone()).check(&raw)?;
    if peer.uid != uid || peer.audit_token.is_none()
        || peer.code_identity.as_ref().is_none_or(|code| !requirement.matches(code)) {
        fail!(EACCES, "SELECTED_OWNER_PEER_REJECTED");
    }
    within(end)?; Ok(peer)
}
fn process(uid: u32) -> EnclaveResult<()> {
    if !cfg!(target_os = "macos") || !codesign::enforced() { fail!(ENOSYS, "SELECTED_OWNER_NATIVE_REQUIRED"); }
    if ipc::geteuid() != uid { fail!(EPERM, "SELECTED_OWNER_PROCESS"); } Ok(())
}
struct Context { checked: &'static CheckedDeploymentTarget, binding: Binding, pins_hash: [u8; 32],
    root: CodeRequirement, custody: CodeRequirement }
impl Context {
    fn capture(end: Instant) -> EnclaveResult<Self> {
        within(end)?;
        let checked = deployment::selected().ok_or_else(|| err!(EACCES, "DEPLOYMENT_CONTEXT_REQUIRED"))?;
        let raw = deployment::read_protected_public(&checked.target().codesign_pins_file, 1024 * 1024)?;
        let pins = codesign::pins::parse(&raw)?;
        let context = Self { checked, binding: Binding::selected(checked), pins_hash: Sha256::digest(&raw).into(),
            root: CodeRequirement::pinned_from_manifest(codesign::CTL_IDENTIFIER, &pins)?,
            custody: CodeRequirement::pinned_from_manifest(&DaemonId::CustodyVault.launchd_label(), &pins)? };
        context.current(end)?; Ok(context)
    }
    fn current(&self, end: Instant) -> EnclaveResult<()> {
        within(end)?;
        // Preserve the current selected experimental scope; no new profile or
        // installed operation is admitted merely by this connection primitive.
        let selected = deployment::selected().ok_or_else(|| err!(EACCES, "DEPLOYMENT_CONTEXT_REQUIRED"))?;
        if !std::ptr::eq(selected, self.checked) || selected.target().role != DeploymentRole::DedicatedTest
            || selected.target().profile != Profile::L2
            || selected.target().signing_identity_mode != DeploymentSigningMode::LocalPins
            || codesign::signing_mode() != codesign::SigningMode::LocalPins
            || selected.target().broker.is_some() || !selected.target().shared_read_only_inputs.is_empty() {
            fail!(EACCES, "SELECTED_OWNER_CONTEXT");
        }
        let fresh = deployment::load(self.checked.config_path())?;
        if fresh.descriptor_sha256() != self.checked.descriptor_sha256() || fresh.target() != self.checked.target() {
            fail!(ESTALE, "SELECTED_OWNER_CONTEXT_CHANGED");
        }
        let raw = deployment::read_protected_public(&self.checked.target().codesign_pins_file, 1024 * 1024)?;
        let hash: [u8; 32] = Sha256::digest(&raw).into();
        if hash != self.pins_hash { fail!(ESTALE, "SELECTED_OWNER_PINS_CHANGED"); }
        deployment::upgrade::assert_start_allowed(self.checked)?;
        within(end)
    }
    fn peer(&self, stream: &UnixStream, original: &PeerCredentials, uid: u32, end: Instant) -> EnclaveResult<()> {
        self.current(end)?;
        let requirement = if uid == 0 { &self.root } else if uid == DaemonId::CustodyVault.uid() { &self.custody }
            else { fail!(EACCES, "SELECTED_OWNER_PEER_REJECTED"); };
        same_peer(original, &authenticate(stream, uid, requirement, end)?)?;
        self.current(end)
    }
}

// Wire state is private. Fixtures exercise the same real framing/sequence/
// ownership code; they cannot supply successful native authentication publicly.
struct ClientWire { connection: Connection, binding: Binding, hint: AttachmentHint, client: [u8; 32],
    session: [u8; 32], next: u64, policy: PolicySession, end: Instant, poisoned: bool }
impl ClientWire {
    #[cfg(test)]
    fn open(stream: UnixStream, binding: Binding, hint: AttachmentHint, end: Instant, requested: Instant,
        verify: impl FnMut(&UnixStream, Instant) -> EnclaveResult<()>, policy: PolicySession) -> EnclaveResult<Self> {
        Self::open_inner(Connection(stream, None), binding, hint, end, requested, verify, |_| Ok(()), policy)
    }
    fn open_inner(connection: Connection, binding: Binding, hint: AttachmentHint, end: Instant, requested: Instant,
        verify: impl FnMut(&UnixStream, Instant) -> EnclaveResult<()>,
        bind_boot: impl FnOnce(u64) -> EnclaveResult<()>, policy: PolicySession) -> EnclaveResult<Self> {
        let mut owner = Self { connection, binding, hint, client: nonce()?, session: [0; 32],
            next: 0, policy, end, poisoned: false };
        owner.policy.require_current()?;
        bind_boot(owner.policy.expires_boot_ns)?;
        owner.exchange(Kind::Bind, requested, verify)?; Ok(owner)
    }
    fn stop(&mut self) { self.poisoned = true; self.connection.close(); }
    fn exchange(&mut self, kind: Kind, requested: Instant,
        verify: impl FnMut(&UnixStream, Instant) -> EnclaveResult<()>) -> EnclaveResult<()> {
        if self.poisoned { fail!(EACCES, "SELECTED_OWNER_POISONED"); }
        let guard = FailureGuard::new(self);
        let result = guard.owner.exchange_inner(kind, requested, verify);
        guard.finish(result)
    }
    fn exchange_inner(&mut self, kind: Kind, requested: Instant,
        mut verify: impl FnMut(&UnixStream, Instant) -> EnclaveResult<()>) -> EnclaveResult<()> {
        if self.poisoned { fail!(EACCES, "SELECTED_OWNER_POISONED"); }
        let result = (|| {
            let end = endpoint(self.end, requested)?;
            self.policy.require_current()?;
            verify(&self.connection.0, end)?; within(end)?;
            let started = boot_now()?;
            let request = Request { version: 2, kind, binding: self.binding.clone(), hint: self.hint,
                client: self.client, session: self.session, sequence: self.next, challenge: nonce()?,
                expires_boot_ns: self.policy.expires_boot_ns, record_sha256: self.policy.record_sha256,
                policy_session_id: self.policy.policy_session_id };
            ipc::write_frame_timed(&mut self.connection.0, &ipc::to_cbor(&request)?, &limits(end)?)?;
            verify(&self.connection.0, end)?; within(end)?;
            let response: Response = decode(&ipc::read_frame_timed(&mut self.connection.0, &limits(end)?)?)?;
            let now = boot_now()?;
            if response.version != 2 || response.binding != self.binding || response.hint != self.hint
                || response.client != self.client || response.session == [0; 32]
                || (self.session != [0; 32] && response.session != self.session)
                || response.sequence != request.sequence || response.challenge != request.challenge
                || !self.policy.matches(response.record_sha256, response.policy_session_id, response.expires_boot_ns) || now < started
                || response.started_boot_ns < started || response.ended_boot_ns < response.started_boot_ns
                || response.ended_boot_ns > now { fail!(ESTALE, "SELECTED_OWNER_REPLY_BINDING"); }
            verify(&self.connection.0, end)?;
            self.policy.require_current()?; within(end)?;
            self.next = self.next.checked_add(1).ok_or_else(|| err!(EACCES, "SELECTED_OWNER_SEQUENCE"))?;
            self.session = response.session;
            Ok(())
        })();
        if result.is_err() { self.stop(); } result
    }
}
impl Drop for ClientWire { fn drop(&mut self) { self.stop(); } }
impl CloseOnFailure for ClientWire { fn close_on_failure(&mut self) { self.stop(); } }

/// Negative-only cancellation of one original custody connection attempt. The
/// wrapper publishes this before connect, then stops it on SAME HID token loss.
/// Pending stop is terminal: a later socket/constructor cannot become usable.
#[derive(Clone)]
pub struct CustodySelectedOwnerStop { control: WatchControl<NoGeneration> }
impl CustodySelectedOwnerStop {
    /// Capture min(original enclosing lifetime, original policy-session Instant)
    /// for negative-only pending/socket shutdown. A constructor refuses any
    /// stop whose original cap differs from that same effective minimum.
    pub fn new(lifetime_end: Instant) -> Self { Self { control: WatchControl::new(lifetime_end, NoGeneration) } }
    /// Permanently stop this pending or established original connection.
    pub fn stop(&self) { self.control.stop(); }
    /// Observe terminal stop or the original active/boot/lifetime deadline.
    /// Success supplies no connection, authentication, fresh ACK or readiness
    /// evidence. Failure permanently stops this SAME pending/socket control.
    pub fn require_not_stopped(&self) -> EnclaveResult<()> { self.control.check() }
}

/// One original selected transport's dedicated authenticated root connection.
/// It is not clonable, reconnectable or serializable. The custody wrapper MUST
/// retain/check its same opaque native transport lifetime before/after all calls
/// and independently invoke the prepublished stop on transport loss/abandonment.
pub struct CustodySelectedOwnerChannel { wire: ClientWire, witness: LocalSelectionWitness,
    context: Context, peer: PeerCredentials, stop: CustodySelectedOwnerStop, policy_session: Arc<SelectedOwnerSession>,
    #[cfg(target_os = "macos")]
    _watcher: WatchWorker<NoGeneration> }
impl CustodySelectedOwnerChannel {
    /// Lifetime is captured once from the real transport owner. For independent
    /// stop during constructor work, use connect_stoppable with a preowned handle.
    pub fn connect_custody(monitor: &super::darwin::PowerMonitor, lifetime_end: Instant, exchange_end: Instant,
        session: Arc<SelectedOwnerSession>) -> EnclaveResult<Self> {
        let lifetime_end = lifetime_end.min(session.original_instant_end());
        let stop = CustodySelectedOwnerStop::new(lifetime_end);
        Self::connect_stoppable(monitor, lifetime_end, exchange_end, &stop, session)
    }
    /// Connect using the same prepublished stop handle throughout native work.
    /// Its cap must already include the SAME retained session's original Instant.
    pub fn connect_stoppable(monitor: &super::darwin::PowerMonitor, lifetime_end: Instant,
        exchange_end: Instant, stop: &CustodySelectedOwnerStop, session: Arc<SelectedOwnerSession>) -> EnclaveResult<Self> {
        let mut attempt = StopAttempt { control: stop.control.clone(), armed: true };
        stop.control.bind_session(session.clone())?;
        let lifetime_end = lifetime_end.min(session.original_instant_end());
        if stop.control.original != lifetime_end { fail!(EINVAL, "SELECTED_OWNER_LIFETIME"); }
        process(DaemonId::CustodyVault.uid())?;
        let policy = PolicySession::capture(&session)?;
        stop.control.bind_boot(policy.expires_boot_ns)?;
        let phase = stop.control.begin(exchange_end)?;
        #[cfg(not(target_os = "macos"))]
        { let _ = (monitor, phase, policy, &mut attempt); fail!(ENOSYS, "SELECTED_OWNER_NATIVE_REQUIRED"); }
        #[cfg(target_os = "macos")]
        {
            let context = Context::capture(phase.end)?;
            session.require_current()?;
            stop.control.check()?;
            let witness = LocalSelectionWitness::capture_singleton(monitor, phase.end)?;
            stop.control.check()?;
            let path = context.checked.target().layout.socket_root.join(SOCKET_LEAF);
            // Attach negative shutdown capability BEFORE socket connect/auth.
            // No frame is sent until actual root code/audit verification passes.
            let connection = connect_pending(&path, &stop.control, phase.end, session.clone())?;
            let watcher = WatchWorker::start_attached(stop.control.clone())?;
            let peer = authenticate(&connection.0, 0, &context.root, phase.end)?;
            stop.control.check()?;
            let wire = ClientWire::open_inner(connection, context.binding.clone(), witness.hint(), lifetime_end, phase.end,
                |stream, until| {
                    session.require_current()?;
                    stop.control.check()?; process(DaemonId::CustodyVault.uid())?;
                    context.peer(stream, &peer, 0, until)?; stop.control.check()?;
                    witness.require_current(monitor, until)?; stop.control.check()?;
                    context.peer(stream, &peer, 0, until)?; stop.control.check()?;
                    session.require_current()
                }, |limit| stop.control.require_boot(limit), policy)?;
            session.require_current()?;
            stop.control.finish(phase)?;
            attempt.armed = false;
            Ok(Self { wire, witness, context, peer, stop: stop.clone(), policy_session: session, _watcher: watcher })
        }
    }
    /// Clone negative-only shutdown for this original connection.
    pub fn stop_handle(&self) -> CustodySelectedOwnerStop { self.stop.clone() }
    /// Same stream/root peer, witness, transport token and original hard end.
    pub fn probe(&mut self, monitor: &super::darwin::PowerMonitor, end: Instant) -> EnclaveResult<()> {
        let guard = FailureGuard::new(self);
        let result = guard.owner.probe_inner(monitor, end);
        guard.finish(result)
    }
    fn probe_inner(&mut self, monitor: &super::darwin::PowerMonitor, end: Instant) -> EnclaveResult<()> {
        self.policy_session.require_current()?;
        let phase = self.stop.control.begin(end)?;
        let context = &self.context; let witness = &self.witness; let peer = &self.peer; let control = &self.stop.control;
        let session = &self.policy_session;
        self.wire.exchange(Kind::Probe, phase.end, |stream, until| {
            session.require_current()?;
            control.check()?; process(DaemonId::CustodyVault.uid())?;
            context.peer(stream, peer, 0, until)?; control.check()?;
            witness.require_current(monitor, until)?; control.check()?;
            context.peer(stream, peer, 0, until)?; control.check()?;
            session.require_current()
        })?;
        session.require_current()?;
        control.finish(phase)
    }
    /// Shutdown is independent of the actor mutex. Borrowed witness Drop never
    /// revokes a replacement HID owner or proves original native cleanup.
    pub fn stop(&mut self) { self.policy_session.revoke(); self.stop.stop(); self.wire.stop(); }
}
impl CloseOnFailure for CustodySelectedOwnerChannel { fn close_on_failure(&mut self) { self.stop(); } }
impl Drop for CustodySelectedOwnerChannel { fn drop(&mut self) { self.stop(); } }

// Establish the original Unix connection with negative shutdown already bound.
// Unlike Client::connect_verified_deadline, this exposes no interval where peer
// code authentication blocks before the external stop owns the original socket.
#[cfg(target_os = "macos")]
fn connect_pending(path: &std::path::Path, control: &WatchControl<NoGeneration>, end: Instant,
    policy_session: Arc<SelectedOwnerSession>) -> EnclaveResult<Connection> {
    connect_pending_inner(path, control, end, Some(policy_session))
}
#[cfg(target_os = "macos")]
fn connect_pending_inner(path: &std::path::Path, control: &WatchControl<NoGeneration>, end: Instant,
    policy_session: Option<Arc<SelectedOwnerSession>>) -> EnclaveResult<Connection> {
    let mut attempt = StopAttempt { control: control.clone(), armed: true };
    use std::os::{fd::{AsRawFd, FromRawFd}, unix::ffi::OsStrExt};
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.is_empty() || bytes.contains(&0) || bytes.len() >= address.sun_path.len() { fail!(EINVAL, "SELECTED_OWNER_CONNECT_PATH"); }
    address.sun_family = libc::AF_UNIX as _;
    for (target, source) in address.sun_path.iter_mut().zip(bytes) { *target = *source as libc::c_char; }
    let length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
    address.sun_len = length as _;
    control.check()?;
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if raw < 0 { fail!(EIO, "SELECTED_OWNER_CONNECT"); }
    // Retain policy invalidation from the instant this socket FD is owned,
    // including failures during descriptor flag setup before connect/attach.
    let connection = Connection(unsafe { UnixStream::from_raw_fd(raw) }, policy_session);
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    let status = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    if flags < 0 || status < 0 || unsafe { libc::fcntl(raw, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
        || unsafe { libc::fcntl(raw, libc::F_SETFL, status | libc::O_NONBLOCK) } < 0 { fail!(EIO, "SELECTED_OWNER_CONNECT"); }
    let stream = &connection.0;
    control.attach(Arc::new(stream.try_clone().map_err(|_| err!(EIO, "SELECTED_OWNER_CONNECT"))?))?;
    loop {
        control.check()?; within(end)?;
        let result = unsafe { libc::connect(stream.as_raw_fd(), std::ptr::addr_of!(address).cast(), length as libc::socklen_t) };
        if result == 0 { break; }
        let error = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if error == libc::EISCONN { break; }
        if error == libc::EINTR { continue; }
        if error == libc::EAGAIN || error == libc::EWOULDBLOCK {
            std::thread::sleep(end.saturating_duration_since(Instant::now()).min(Duration::from_millis(2))); continue;
        }
        if error != libc::EINPROGRESS && error != libc::EALREADY { fail!(EIO, "SELECTED_OWNER_CONNECT"); }
        let left = end.saturating_duration_since(Instant::now()).min(Duration::from_millis(10));
        let mut poll = libc::pollfd { fd: stream.as_raw_fd(), events: libc::POLLOUT, revents: 0 };
        let count = unsafe { libc::poll(&mut poll, 1, left.as_millis().max(1) as i32) };
        if count < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) { continue; }
            fail!(EIO, "SELECTED_OWNER_CONNECT");
        }
        if count == 0 { continue; }
        let mut pending: libc::c_int = 0; let mut size = std::mem::size_of_val(&pending) as libc::socklen_t;
        if unsafe { libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_ERROR,
            std::ptr::addr_of_mut!(pending).cast(), &mut size) } != 0 || size as usize != std::mem::size_of_val(&pending)
            || pending != 0 { fail!(EIO, "SELECTED_OWNER_CONNECT"); }
    }
    control.check()?; within(end)?;
    stream.set_nonblocking(false).map_err(|_| err!(EIO, "SELECTED_OWNER_CONNECT"))?;
    control.check()?; attempt.armed = false; Ok(connection)
}

struct Book { binding: Binding, hint: AttachmentHint, client: [u8; 32], session: [u8; 32],
    next: u64, policy: PolicySession }
impl Book {
    fn bind(request: &Request, binding: &Binding, policy: PolicySession) -> EnclaveResult<Self> {
        policy.require_current()?;
        if request.version != 2 || request.kind != Kind::Bind || &request.binding != binding
            || request.client == [0; 32] || request.session != [0; 32] || request.sequence != 0
            || request.challenge == [0; 32]
            || !policy.matches(request.record_sha256, request.policy_session_id, request.expires_boot_ns) {
            fail!(EINVAL, "SELECTED_OWNER_BINDING");
        }
        Ok(Self { binding: binding.clone(), hint: request.hint, client: request.client,
            session: nonce()?, next: 1, policy })
    }
    fn probe(&self, request: &Request) -> EnclaveResult<u64> {
        self.policy.require_current()?;
        if request.version != 2 || request.kind != Kind::Probe || request.binding != self.binding
            || request.hint != self.hint || request.client != self.client || request.session != self.session
            || request.sequence != self.next || request.challenge == [0; 32]
            || !self.policy.matches(request.record_sha256, request.policy_session_id, request.expires_boot_ns) {
            fail!(ESTALE, "SELECTED_OWNER_BINDING");
        }
        self.next.checked_add(1).ok_or_else(|| err!(EACCES, "SELECTED_OWNER_SEQUENCE"))
    }
    fn response(&self, request: &Request, started_boot_ns: u64) -> EnclaveResult<Response> {
        self.policy.require_current()?;
        let ended_boot_ns = boot_now()?;
        if ended_boot_ns < started_boot_ns { fail!(EIO, "SELECTED_OWNER_CLOCK"); }
        Ok(Response { version: 2, binding: self.binding.clone(), hint: self.hint, client: self.client,
            session: self.session, sequence: request.sequence, challenge: request.challenge,
            expires_boot_ns: self.policy.expires_boot_ns, record_sha256: self.policy.record_sha256,
            policy_session_id: self.policy.policy_session_id, started_boot_ns, ended_boot_ns })
    }
}
// Only short metadata transitions happen under this mutex. Socket shutdown and
// generation revocation (which can invoke synchronous wipe hooks) happen outside.
trait CancelOriginal: Clone + Send + Sync + 'static { fn cancel_original(&self); }
#[derive(Clone)]
struct NoGeneration;
impl CancelOriginal for NoGeneration { fn cancel_original(&self) {} }
struct StopAttempt<C: CancelOriginal> { control: WatchControl<C>, armed: bool }
impl<C: CancelOriginal> Drop for StopAttempt<C> {
    fn drop(&mut self) { if self.armed { self.control.stop(); } }
}
impl CancelOriginal for super::selected_attachment::RootAttachmentCancellation {
    fn cancel_original(&self) { self.cancel(); }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Phase { serial: u64, end: Instant }
struct WatchState {
    phase: Option<Phase>, serial: u64, terminal: bool, boot_limit: Option<u64>,
    socket: Option<Arc<UnixStream>>, stopped: Option<Arc<AtomicBool>>,
}
#[derive(Clone)]
struct WatchControl<C: CancelOriginal> { original: Instant, state: Arc<Mutex<WatchState>>, cancellation: C,
    policy_session: Arc<std::sync::OnceLock<Arc<SelectedOwnerSession>>> }
impl<C: CancelOriginal> WatchControl<C> {
    fn new(original: Instant, cancellation: C) -> Self {
        Self { original, cancellation, policy_session: Arc::new(std::sync::OnceLock::new()), state: Arc::new(Mutex::new(WatchState {
            phase: None, serial: 0, terminal: false, boot_limit: None, socket: None, stopped: None,
        })) }
    }
    fn stop(&self) {
        // This newly added negative authority must not wait for metadata,
        // shutdown, synchronous generation callbacks or native owner cleanup.
        if let Some(session) = self.policy_session.get() { session.revoke(); }
        let socket = {
            // Poison only drains authority; it never admits another exchange.
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if state.terminal { return; }
            state.terminal = true;
            state.socket.clone()
        };
        // Close BEFORE callbacks: cleanup/native release can block indefinitely.
        if let Some(socket) = socket { let _ = socket.shutdown(Shutdown::Both); }
        self.cancellation.cancel_original();
    }
    fn bind_session(&self, session: Arc<SelectedOwnerSession>) -> EnclaveResult<()> {
        if self.policy_session.set(session.clone()).is_err() {
            session.revoke(); self.stop(); fail!(EACCES, "SELECTED_OWNER_SESSION_ALREADY_BOUND");
        }
        let result = session.require_current().and_then(|()| {
            if self.original > session.original_instant_end() { fail!(EACCES, "SELECTED_OWNER_LIFETIME"); }
            self.check()
        });
        if result.is_err() { self.stop(); } result
    }
    fn transition<T>(&self, sample: impl FnOnce() -> EnclaveResult<(Instant, u64)>,
        change: impl FnOnce(&mut WatchState) -> EnclaveResult<T>) -> EnclaveResult<T> {
        let result = (|| {
            let mut state = self.state.lock().map_err(|_| err!(EIO, "SELECTED_OWNER_WATCH_POISONED"))?;
            // Sample AFTER acquiring metadata so contention cannot admit using
            // a stale pre-lock clock. Only monotonic clock reads occur here.
            let (now, boot) = sample()?;
            if state.terminal || state.stopped.as_ref().is_some_and(|flag| flag.load(Ordering::Acquire)) {
                fail!(EACCES, "SELECTED_OWNER_STOPPED");
            }
            if now >= self.original || state.phase.is_some_and(|phase| now >= phase.end)
                || boot == u64::MAX || state.boot_limit.is_some_and(|limit| boot >= limit) {
                fail!(ETIMEDOUT, "SELECTED_OWNER_DEADLINE");
            }
            change(&mut state)
        })();
        if result.is_err() { self.stop(); }
        result
    }
    #[cfg(test)]
    fn apply_at<T>(&self, now: Instant, boot: u64,
        change: impl FnOnce(&mut WatchState) -> EnclaveResult<T>) -> EnclaveResult<T> {
        self.transition(|| Ok((now, boot)), change)
    }
    fn apply<T>(&self, change: impl FnOnce(&mut WatchState) -> EnclaveResult<T>) -> EnclaveResult<T> {
        self.transition(|| Ok((Instant::now(), boot_now()?)), change)
    }
    #[cfg(test)]
    fn begin_at(&self, requested: Instant, now: Instant, boot: u64) -> EnclaveResult<Phase> {
        self.apply_at(now, boot, |state| {
            if state.phase.is_some() { fail!(EACCES, "SELECTED_OWNER_EXCHANGE_ACTIVE"); }
            let end = self.original.min(requested).min(now + EXCHANGE);
            if now >= end { fail!(ETIMEDOUT, "SELECTED_OWNER_DEADLINE"); }
            state.serial = state.serial.checked_add(1).ok_or_else(|| err!(EACCES, "SELECTED_OWNER_SEQUENCE"))?;
            let phase = Phase { serial: state.serial, end }; state.phase = Some(phase); Ok(phase)
        })
    }
    fn begin(&self, requested: Instant) -> EnclaveResult<Phase> {
        self.apply(|state| {
            if state.phase.is_some() { fail!(EACCES, "SELECTED_OWNER_EXCHANGE_ACTIVE"); }
            let now = Instant::now(); let end = self.original.min(requested).min(now + EXCHANGE);
            if now >= end { fail!(ETIMEDOUT, "SELECTED_OWNER_DEADLINE"); }
            state.serial = state.serial.checked_add(1).ok_or_else(|| err!(EACCES, "SELECTED_OWNER_SEQUENCE"))?;
            let phase = Phase { serial: state.serial, end }; state.phase = Some(phase); Ok(phase)
        })
    }
    #[cfg(test)]
    fn finish_at(&self, phase: Phase, now: Instant, boot: u64) -> EnclaveResult<()> {
        self.apply_at(now, boot, |state| {
            if state.phase != Some(phase) { fail!(ESTALE, "SELECTED_OWNER_EXCHANGE_CHANGED"); }
            state.phase = None; Ok(())
        })
    }
    fn finish(&self, phase: Phase) -> EnclaveResult<()> {
        self.apply(|state| {
            if state.phase != Some(phase) { fail!(ESTALE, "SELECTED_OWNER_EXCHANGE_CHANGED"); }
            state.phase = None; Ok(())
        })
    }
    fn bind_boot(&self, limit: u64) -> EnclaveResult<()> {
        self.apply(|state| {
            if limit == 0 || limit == u64::MAX || limit <= boot_now()? || state.boot_limit.is_some() {
                fail!(EACCES, "SELECTED_OWNER_LIFETIME");
            }
            state.boot_limit = Some(limit); Ok(())
        })
    }
    // Native peers bind their own independently loaded raw end before any
    // connect/auth/read work. A wire value may only confirm that SAME end.
    fn require_boot(&self, limit: u64) -> EnclaveResult<()> {
        self.apply(|state| {
            if state.boot_limit != Some(limit) { fail!(EACCES, "SELECTED_OWNER_LIFETIME"); }
            Ok(())
        })
    }
    fn check(&self) -> EnclaveResult<()> { self.apply(|_| Ok(())) }
    fn poll_end(&self) -> EnclaveResult<Instant> {
        self.apply(|state| Ok(state.phase.map_or(self.original, |phase| phase.end).min(self.original)))
    }
    fn attach(&self, socket: Arc<UnixStream>) -> EnclaveResult<()> {
        let result = self.apply(|state| {
            if state.socket.is_some() { fail!(EACCES, "SELECTED_OWNER_WATCH_USED"); }
            state.socket = Some(socket.clone()); Ok(())
        });
        // A pre-stopped handle still closes the newly offered original stream.
        if result.is_err() { let _ = socket.shutdown(Shutdown::Both); }
        result
    }
    fn observe_stop(&self, stopped: Arc<AtomicBool>) -> EnclaveResult<()> {
        self.apply(|state| { state.stopped = Some(stopped); Ok(()) })?; self.check()
    }
}

#[cfg(target_os = "macos")]
struct WatchWorker<C: CancelOriginal> { control: WatchControl<C>, worker: Option<std::thread::JoinHandle<()>> }
#[cfg(target_os = "macos")]
impl<C: CancelOriginal> WatchWorker<C> {
    fn start(stream: &UnixStream, control: WatchControl<C>) -> EnclaveResult<Self> {
        let socket = Arc::new(stream.try_clone().map_err(|_| err!(EIO, "SELECTED_OWNER_WATCH_SOCKET"))?);
        control.attach(socket)?;
        Self::start_attached(control)
    }
    fn start_attached(control: WatchControl<C>) -> EnclaveResult<Self> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let socket = control.apply(|state| state.socket.clone().ok_or_else(|| err!(EACCES, "SELECTED_OWNER_WATCH_SOCKET")))?;
        // Own the duplicate for the full registration/thread lifetime. No actor
        // closure can allow this numeric descriptor to identify a replacement.
        let raw = unsafe { libc::kqueue() };
        if raw < 0 { control.stop(); fail!(EIO, "SELECTED_OWNER_WATCH_CREATE"); }
        let queue = unsafe { OwnedFd::from_raw_fd(raw) };
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
        if flags < 0 || unsafe { libc::fcntl(raw, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            control.stop(); fail!(EIO, "SELECTED_OWNER_WATCH_CREATE");
        }
        let change = libc::kevent { ident: socket.as_raw_fd() as usize, filter: libc::EVFILT_READ,
            flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_CLEAR | libc::EV_RECEIPT,
            fflags: 0, data: 0, udata: std::ptr::null_mut() };
        let mut receipt = change;
        let zero = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        let count = unsafe { libc::kevent(raw, &change, 1, &mut receipt, 1, &zero) };
        if count != 1 || receipt.ident != change.ident || receipt.filter != change.filter
            || receipt.flags & libc::EV_ERROR == 0 || receipt.data != 0 || !receipt.udata.is_null() {
            control.stop(); fail!(EIO, "SELECTED_OWNER_WATCH_REGISTER");
        }
        control.check()?;
        let thread_control = control.clone();
        let worker = std::thread::Builder::new().name("selected-owner-cancel".into()).spawn(move || {
            struct Exit<C: CancelOriginal>(WatchControl<C>);
            impl<C: CancelOriginal> Drop for Exit<C> { fn drop(&mut self) { self.0.stop(); } }
            let exit = Exit(thread_control);
            loop {
                let end = match exit.0.poll_end() { Ok(end) => end, Err(_) => break };
                // This polling admission is not a measured revocation budget.
                let left = end.saturating_duration_since(Instant::now()).min(Duration::from_millis(10));
                let timeout = libc::timespec { tv_sec: 0, tv_nsec: left.as_nanos() as libc::c_long };
                let mut event = libc::kevent { ident: 0, filter: 0, flags: 0, fflags: 0, data: 0, udata: std::ptr::null_mut() };
                let count = unsafe { libc::kevent(queue.as_raw_fd(), std::ptr::null(), 0, &mut event, 1, &timeout) };
                if count < 0 || count > 1 { break; }
                if count == 1 {
                    if event.ident != socket.as_raw_fd() as usize || event.filter != libc::EVFILT_READ
                        || !event.udata.is_null() || event.flags & (libc::EV_ERROR | libc::EV_EOF) != 0
                        || event.fflags != 0 { break; }
                    // Never consume/peek frames. EV_EOF is visible even with
                    // buffered request bytes (Apple kqueue socket contract).
                }
            }
        }).map_err(|_| { control.stop(); err!(EIO, "SELECTED_OWNER_WATCH_THREAD") })?;
        Ok(Self { control, worker: Some(worker) })
    }
}
#[cfg(target_os = "macos")]
impl<C: CancelOriginal> Drop for WatchWorker<C> {
    fn drop(&mut self) {
        self.control.stop();
        // A synchronous wipe callback may itself block. Join only an already
        // finished watcher; otherwise retain its socket/queue until it exits.
        // Dropping JoinHandle detaches; it is not proof of cleanup completion.
        if let Some(worker) = self.worker.take() {
            if worker.is_finished() { let _ = worker.join(); }
        }
    }
}

struct RootSession<O> { connection: Connection, owner: Option<O>, book: Option<Book>, end: Instant, poisoned: bool }
impl<O> RootSession<O> {
    // Actor-thread-only identity observation. No wire read/write, FD clone,
    // timeout change, sequence advancement or owner replacement occurs here.
    // The mailbox's atomic abort guard is installed before this method runs;
    // it revokes before outer channel/socket/native-owner cleanup on unwind.
    fn compare_peer_with(&mut self, requested: Instant,
        mut verify: impl FnMut(&UnixStream, Instant) -> EnclaveResult<()>,
        mut require: impl FnMut(&mut O, AttachmentHint, Instant) -> EnclaveResult<()>,
        compare: impl FnOnce() -> EnclaveResult<()>) -> EnclaveResult<()> {
        if self.poisoned { fail!(EACCES, "SELECTED_OWNER_POISONED"); }
        let end = self.end.min(requested); within(end)?;
        let book = self.book.as_ref().ok_or_else(|| err!(EACCES, "SELECTED_OWNER_UNBOUND"))?;
        let owner = self.owner.as_mut().ok_or_else(|| err!(EACCES, "SELECTED_OWNER_UNBOUND"))?;
        book.policy.require_current()?;
        verify(&self.connection.0, end)?;
        require(owner, book.hint, end)?; within(end)?;
        compare()?; within(end)?;
        require(owner, book.hint, end)?;
        verify(&self.connection.0, end)?;
        book.policy.require_current()?; within(end)
    }
    #[cfg(test)]
    fn accept_with(stream: UnixStream, binding: &Binding, original_end: Instant, requested: Instant,
        verify: impl FnMut(&UnixStream, Instant) -> EnclaveResult<()>,
        construct: impl FnOnce(AttachmentHint, Instant) -> EnclaveResult<O>,
        require: impl FnMut(&mut O, AttachmentHint, Instant) -> EnclaveResult<()>, policy: PolicySession) -> EnclaveResult<Self> {
        Self::accept_inner(Connection(stream, None), binding, original_end, requested, verify, construct, require, |_| Ok(()), policy)
    }
    fn accept_inner(connection: Connection, binding: &Binding, original_end: Instant, requested: Instant,
        mut verify: impl FnMut(&UnixStream, Instant) -> EnclaveResult<()>,
        construct: impl FnOnce(AttachmentHint, Instant) -> EnclaveResult<O>,
        mut require: impl FnMut(&mut O, AttachmentHint, Instant) -> EnclaveResult<()>,
        bind_boot: impl FnOnce(u64) -> EnclaveResult<()>, policy: PolicySession) -> EnclaveResult<Self> {
        let mut session = Self { connection, owner: None, book: None, end: original_end, poisoned: false };
        let result = (|| {
            let end = endpoint(original_end, requested)?;
            policy.require_current()?;
            verify(&session.connection.0, end)?; within(end)?;
            let request: Request = decode(&ipc::read_frame_timed(&mut session.connection.0, &limits(end)?)?)?;
            let book = Book::bind(&request, binding, policy)?;
            bind_boot(book.policy.expires_boot_ns)?;
            // Reading the Bind may have blocked after the first independent
            // session check. Recheck before creating ANY selected root owner.
            verify(&session.connection.0, end)?; within(end)?;
            let started = boot_now()?;
            session.owner = Some(construct(book.hint, end)?);
            // Store the actual owner BEFORE any subsequent fallible operation.
            require(session.owner.as_mut().expect("stored original"), book.hint, end)?;
            verify(&session.connection.0, end)?; within(end)?;
            book.policy.require_current()?;
            let response = book.response(&request, started)?;
            ipc::write_frame_timed(&mut session.connection.0, &ipc::to_cbor(&response)?, &limits(end)?)?;
            require(session.owner.as_mut().expect("stored original"), book.hint, end)?;
            verify(&session.connection.0, end)?;
            book.policy.require_current()?; within(end)?;
            session.book = Some(book); Ok(())
        })();
        if let Err(error) = result { session.stop(); return Err(error); }
        Ok(session)
    }
    fn stop(&mut self) {
        self.poisoned = true;
        // Actual root guard Drop revokes outside the topology mutex before the
        // retained native object is released. No queued cleanup is substituted.
        self.connection.close(); drop(self.owner.take());
    }
    fn step_with(&mut self, requested: Instant,
        verify: impl FnMut(&UnixStream, Instant) -> EnclaveResult<()>,
        require: impl FnMut(&mut O, AttachmentHint, Instant) -> EnclaveResult<()>) -> EnclaveResult<()> {
        if self.poisoned { fail!(EACCES, "SELECTED_OWNER_POISONED"); }
        let guard = FailureGuard::new(self);
        let result = guard.owner.step_inner(requested, verify, require);
        guard.finish(result)
    }
    fn step_inner(&mut self, requested: Instant,
        mut verify: impl FnMut(&UnixStream, Instant) -> EnclaveResult<()>,
        mut require: impl FnMut(&mut O, AttachmentHint, Instant) -> EnclaveResult<()>) -> EnclaveResult<()> {
        if self.poisoned { fail!(EACCES, "SELECTED_OWNER_POISONED"); }
        let result = (|| {
            let end = endpoint(self.end, requested)?;
            let book = self.book.as_ref().ok_or_else(|| err!(EACCES, "SELECTED_OWNER_UNBOUND"))?;
            book.policy.require_current()?;
            verify(&self.connection.0, end)?;
            let owner = self.owner.as_mut().ok_or_else(|| err!(EACCES, "SELECTED_OWNER_UNBOUND"))?;
            require(owner, book.hint, end)?; within(end)?;
            let request: Request = decode(&ipc::read_frame_timed(&mut self.connection.0, &limits(end)?)?)?;
            let next = book.probe(&request)?;
            let started = boot_now()?;
            require(owner, book.hint, end)?;
            verify(&self.connection.0, end)?; within(end)?;
            let response = book.response(&request, started)?;
            ipc::write_frame_timed(&mut self.connection.0, &ipc::to_cbor(&response)?, &limits(end)?)?;
            require(owner, book.hint, end)?;
            verify(&self.connection.0, end)?;
            book.policy.require_current()?; within(end)?;
            self.book.as_mut().expect("bound original").next = next;
            Ok(())
        })();
        if result.is_err() { self.stop(); } result
    }
}
impl<O> Drop for RootSession<O> { fn drop(&mut self) { self.stop(); } }
impl<O> CloseOnFailure for RootSession<O> { fn close_on_failure(&mut self) { self.stop(); } }

/// Cloneable negative-only stop for ONE original connection. Publish it before
/// accept_stoppable so shutdown cannot wait behind blocked handshake/native work.
#[cfg(target_os = "macos")]
#[derive(Clone)]
pub(crate) struct RootSelectedOwnerStop { control: WatchControl<super::selected_attachment::RootAttachmentCancellation> }
#[cfg(target_os = "macos")]
impl RootSelectedOwnerStop {
    pub(crate) fn new(lifetime_end: Instant) -> Self {
        Self { control: WatchControl::new(lifetime_end, super::selected_attachment::RootAttachmentCancellation::new()) }
    }
    pub(crate) fn stop(&self) { self.control.stop(); }
}

/// Actual native root owner for ONE authenticated UID703 connection. The native
/// original remains on its creating thread. The watcher has negative authority
/// only; protected listener/retained monitor/custody transport remain integration.
/// The caller supplies its own independently captured policy-session Arc; no
/// peer-proposed deadline, replacement record or v1 compatibility can supply it.
#[cfg(target_os = "macos")]
pub(crate) struct RootSelectedOwnerChannel { session: RootSession<super::selected_attachment::RootAttachmentOwner>,
    context: Context, peer: PeerCredentials, stop: RootSelectedOwnerStop, policy_session: Arc<SelectedOwnerSession>,
    _watcher: WatchWorker<super::selected_attachment::RootAttachmentCancellation> }
#[cfg(target_os = "macos")]
impl RootSelectedOwnerChannel {
    // Only the actual channel-owning listener actor calls this fixed method.
    // The opaque certificate has no caller token/peer/right constructor. Its
    // original Mach message remains owned on the independent receive worker.
    pub(super) fn compare_received_task(&mut self,
        audit: &crate::supervisor::CertifiedReceivedTaskAudit,
        session: &Arc<SelectedOwnerSession>, monitor: &super::darwin::PowerMonitor,
        end: Instant) -> EnclaveResult<()> {
        if !Arc::ptr_eq(session, &self.policy_session) {
            session.revoke(); self.policy_session.revoke();
            fail!(EACCES, "SELECTED_OWNER_ACTOR_SESSION_CHANGED");
        }
        audit.require_same_session(session, end)?;
        self.policy_session.require_current()?;
        let phase = self.stop.control.begin(end)?;
        let context = &self.context; let peer = &self.peer; let control = &self.stop.control;
        let policy_session = &self.policy_session;
        monitor.observe_health(phase.end)?;
        self.session.compare_peer_with(phase.end,
            |stream, until| { policy_session.require_current()?; control.check()?; process(0)?;
                context.peer(stream, peer, DaemonId::CustodyVault.uid(), until)?;
                control.check()?; policy_session.require_current() },
            |owner, hint, until| { policy_session.require_current()?; control.check()?;
                owner.require_current(hint, monitor, until)?;
                control.check()?; policy_session.require_current() },
            || audit.matches_original_peer(peer))?;
        monitor.observe_health(phase.end)?;
        audit.require_same_session(session, phase.end)?;
        policy_session.require_current()?;
        control.finish(phase)
    }
    pub(crate) fn accept(stream: UnixStream, monitor: &super::darwin::PowerMonitor,
        lifetime_end: Instant, exchange_end: Instant, session: Arc<SelectedOwnerSession>) -> EnclaveResult<Self> {
        let lifetime_end = lifetime_end.min(session.original_instant_end());
        let stop = RootSelectedOwnerStop::new(lifetime_end);
        Self::accept_stoppable(stream, monitor, lifetime_end, exchange_end, &stop, session)
    }
    pub(crate) fn accept_stoppable(stream: UnixStream, monitor: &super::darwin::PowerMonitor,
        lifetime_end: Instant, exchange_end: Instant, stop: &RootSelectedOwnerStop,
        policy_session: Arc<SelectedOwnerSession>) -> EnclaveResult<Self> {
        let mut attempt = StopAttempt { control: stop.control.clone(), armed: true };
        // Own shutdown even if setup/authentication returns early or unwinds.
        let connection = Connection(stream, Some(policy_session.clone()));
        stop.control.bind_session(policy_session.clone())?;
        let lifetime_end = lifetime_end.min(policy_session.original_instant_end());
        if stop.control.original != lifetime_end { stop.stop(); fail!(EINVAL, "SELECTED_OWNER_LIFETIME"); }
        process(0)?;
        let policy = PolicySession::capture(&policy_session)?;
        stop.control.bind_boot(policy.expires_boot_ns)?;
        let phase = stop.control.begin(exchange_end)?;
        let watcher = WatchWorker::start(&connection.0, stop.control.clone())?;
        let context = Context::capture(phase.end)?;
        policy_session.require_current()?;
        let peer = authenticate(&connection.0, DaemonId::CustodyVault.uid(), &context.custody, phase.end)?;
        stop.control.check()?;
        // Move the same connection wrapper; no shutdown or stream export.
        let session = RootSession::accept_inner(connection, &context.binding, lifetime_end, phase.end,
            |stream, until| { policy_session.require_current()?; stop.control.check()?; process(0)?;
                context.peer(stream, &peer, DaemonId::CustodyVault.uid(), until)?; stop.control.check()?;
                policy_session.require_current() },
            |hint, until| { policy_session.require_current()?; stop.control.check()?;
                super::selected_attachment::RootAttachmentOwner::observe_cancellable(hint, monitor, until, &stop.control.cancellation) },
            |owner, hint, until| { policy_session.require_current()?; stop.control.check()?;
                owner.require_current(hint, monitor, until)?; stop.control.check()?; policy_session.require_current() },
            |limit| stop.control.require_boot(limit), policy)?;
        policy_session.require_current()?;
        stop.control.finish(phase)?;
        attempt.armed = false;
        Ok(Self { session, context, peer, stop: stop.clone(), policy_session, _watcher: watcher })
    }
    pub(crate) fn stop_handle(&self) -> RootSelectedOwnerStop { self.stop.clone() }
    pub(crate) fn step(&mut self, monitor: &super::darwin::PowerMonitor, end: Instant) -> EnclaveResult<()> {
        let guard = FailureGuard::new(self);
        let result = guard.owner.step_inner(monitor, end);
        guard.finish(result)
    }
    fn step_inner(&mut self, monitor: &super::darwin::PowerMonitor, end: Instant) -> EnclaveResult<()> {
        self.policy_session.require_current()?;
        let phase = self.stop.control.begin(end)?;
        let context = &self.context; let peer = &self.peer; let control = &self.stop.control;
        let policy_session = &self.policy_session;
        let result = self.session.step_with(phase.end,
            |stream, until| { policy_session.require_current()?; control.check()?; process(0)?;
                context.peer(stream, peer, DaemonId::CustodyVault.uid(), until)?; control.check()?; policy_session.require_current() },
            |owner, hint, until| { policy_session.require_current()?; control.check()?;
                owner.require_current(hint, monitor, until)?; control.check()?; policy_session.require_current() });
        if result.is_err() { self.stop(); return result; }
        policy_session.require_current()?;
        if let Err(error) = self.stop.control.finish(phase) { self.stop(); return Err(error); }
        Ok(())
    }
    pub(crate) fn stop(&mut self) { self.policy_session.revoke(); self.stop.stop(); self.session.stop(); }
    pub(crate) fn serve(mut self, monitor: &super::darwin::PowerMonitor, stopped: Arc<AtomicBool>) -> EnclaveResult<()> {
        // Watcher checks the SAME owned flag independently of the actor.
        self.stop.control.observe_stop(stopped)?;
        // Idle/read admission intentionally retains the fixed <=2s exchange
        // cap. Completing a probe does not renew original/boot lifetime caps.
        loop { self.step(monitor, self.session.end)?; }
    }
}
#[cfg(target_os = "macos")]
impl Drop for RootSelectedOwnerChannel { fn drop(&mut self) { self.stop(); } }
#[cfg(target_os = "macos")]
impl CloseOnFailure for RootSelectedOwnerChannel { fn close_on_failure(&mut self) { self.stop(); } }

#[cfg(test)]
#[path = "selected_owner_channel_tests.rs"]
mod tests;
