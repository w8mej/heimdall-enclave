//! Original authenticated readiness-server connection, with negative authority
//! only. A current peer never supplies an observation, task match or ready term.
use std::{net::Shutdown, os::unix::net::UnixStream,
    sync::{Arc, atomic::{AtomicBool, Ordering}}, time::Instant};
use crate::{codesign, daemon::DaemonId, error::EnclaveResult,
    ipc::{self, FrameIoLimits, PeerCredentials, PeerPolicy}, err, fail};

fn current(stopped: &AtomicBool, end: Instant) -> EnclaveResult<()> {
    if stopped.load(Ordering::Acquire) { fail!(EACCES, "SUPERVISOR_SERVER_PEER_STOPPED"); }
    if Instant::now() >= end { fail!(ETIMEDOUT, "SUPERVISOR_SERVER_PEER_DEADLINE"); }
    Ok(())
}

fn authenticated(peer: &PeerCredentials) -> EnclaveResult<()> {
    if (peer.uid != 0 && peer.uid != DaemonId::CustodyVault.uid())
        || peer.audit_token.is_none() || peer.code_identity.is_none()
        || peer.tls_channel_binding.is_some() {
        fail!(EACCES, "SUPERVISOR_SERVER_PEER_AUTHENTICATION_REQUIRED");
    }
    Ok(())
}

// Private shared sequencing seam. Only the concrete native wrapper below can
// authenticate a production stream; fixtures cannot construct that wrapper.
struct OriginalPeer { original: PeerCredentials, end: Instant, consumed: bool }
impl OriginalPeer {
    fn new(original: PeerCredentials, admitted_uid: u32, end: Instant) -> EnclaveResult<Self> {
        authenticated(&original)?;
        // The preliminary UID charged to the connection quota is not identity
        // authority. It must agree with the independently verified actual peer.
        if original.uid != admitted_uid { fail!(ESTALE, "SUPERVISOR_SERVER_PEER_QUOTA_CHANGED"); }
        Ok(Self { original, end, consumed: false })
    }
    fn same(&self, observed: &PeerCredentials) -> EnclaveResult<()> {
        authenticated(observed)?;
        if observed.uid != self.original.uid || observed.gid != self.original.gid
            || observed.audit_token != self.original.audit_token
            || observed.code_identity != self.original.code_identity {
            fail!(ESTALE, "SUPERVISOR_SERVER_PEER_CHANGED");
        }
        // PID is telemetry only. No PID lookup or PID-only equality substitutes
        // for any word of the complete kernel audit token above.
        Ok(())
    }
    fn begin<'a, S>(&'a mut self, stream: &'a mut S, stopped: &'a AtomicBool)
        -> EnclaveResult<Exchange<'a, S>> {
        if self.consumed { fail!(EACCES, "SUPERVISOR_SERVER_PEER_RETIRED"); }
        self.consumed = true; // BEFORE any verification, I/O or caller callback.
        current(stopped, self.end)?;
        Ok(Exchange { pin: self, stream, stopped, phase: Phase::Fresh,
            reply_end: None, failed: false, completed: false })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase { Fresh, Read, Published, Complete }
struct Exchange<'a, S> {
    pin: &'a mut OriginalPeer, stream: &'a mut S, stopped: &'a AtomicBool,
    phase: Phase, reply_end: Option<Instant>, failed: bool, completed: bool,
}
impl<S> Exchange<'_, S> {
    fn require_phase(&mut self, expected: Phase) -> EnclaveResult<()> {
        if self.failed || self.phase != expected {
            self.failed = true; self.completed = false; self.pin.consumed = true;
            fail!(EACCES, "SUPERVISOR_SERVER_PEER_SEQUENCE");
        }
        Ok(())
    }
    fn checked<T>(&mut self, end: Instant,
        mut verify: impl FnMut(&S, Instant) -> EnclaveResult<PeerCredentials>,
        operation: impl FnOnce(&mut S, Instant) -> EnclaveResult<T>) -> EnclaveResult<T> {
        if self.failed { fail!(EACCES, "SUPERVISOR_SERVER_PEER_RETIRED"); }
        self.failed = true; // Error or caught unwind cannot resume this exchange.
        let end = self.pin.end.min(end);
        current(self.stopped, end)?;
        self.pin.same(&verify(self.stream, end)?)?;
        current(self.stopped, end)?;
        let value = operation(self.stream, end)?;
        current(self.stopped, end)?;
        self.pin.same(&verify(self.stream, end)?)?;
        current(self.stopped, end)?;
        self.failed = false;
        Ok(value)
    }
    fn read_with<T>(&mut self,
        verify: impl FnMut(&S, Instant) -> EnclaveResult<PeerCredentials>,
        read: impl FnOnce(&mut S, Instant) -> EnclaveResult<T>) -> EnclaveResult<T> {
        self.require_phase(Phase::Fresh)?;
        let value = self.checked(self.pin.end, verify, read)?;
        self.phase = Phase::Read;
        Ok(value)
    }
    fn publish_with<T>(&mut self,
        verify: impl FnMut(&S, Instant) -> EnclaveResult<PeerCredentials>,
        publish: impl FnOnce(Instant) -> T) -> EnclaveResult<(Instant, T)> {
        self.require_phase(Phase::Read)?;
        // Same original 30-second connection and existing 2-second request
        // cap. Authentication spends this endpoint; no progress renews it.
        let end = self.pin.end.min(Instant::now() + super::PROBE);
        self.reply_end = Some(end);
        let value = self.checked(end, verify, |_, end| Ok(publish(end)))?;
        self.phase = Phase::Published;
        Ok((end, value))
    }
    fn reply_with(&mut self,
        verify: impl FnMut(&S, Instant) -> EnclaveResult<PeerCredentials>,
        reply: impl FnOnce(&mut S, Instant) -> EnclaveResult<()>) -> EnclaveResult<()> {
        self.require_phase(Phase::Published)?;
        let end = self.reply_end.ok_or_else(|| err!(EACCES, "SUPERVISOR_SERVER_PEER_SEQUENCE"))?;
        self.checked(end, verify, reply)?;
        // Only a complete pre/post verified reply allows another request on
        // this SAME connection. The original peer and endpoint never change.
        self.phase = Phase::Complete; self.completed = true; self.pin.consumed = false;
        Ok(())
    }
}
impl<S> Drop for Exchange<'_, S> {
    fn drop(&mut self) { if !self.completed { self.pin.consumed = true; } }
}

fn native_peer(stream: &UnixStream, policy: &PeerPolicy, end: Instant) -> EnclaveResult<PeerCredentials> {
    if !cfg!(target_os = "macos") || !codesign::enforced() {
        fail!(ENOSYS, "SUPERVISOR_SERVER_PEER_NATIVE_REQUIRED");
    }
    super::within(end)?;
    let actual = ipc::peer_credentials(stream)?;
    if !policy.code.contains_key(&actual.uid) {
        fail!(EACCES, "SUPERVISOR_SERVER_PEER_CODE_POLICY_REQUIRED");
    }
    let verified = policy.check(&actual)?;
    authenticated(&verified)?;
    super::within(end)?;
    Ok(verified)
}

// Own the actual input INSIDE the authentication callee before any native
// verification. The caller cannot veto before a callee-owned stream unwinds.
// Only this private algorithm is shared with cleanup-observing software tests;
// the production factory always supplies native_peer over its actual policy.
struct Authentication<S> {
    stream:S,pin:Option<OriginalPeer>,shutdown:Arc<super::IpcShutdown>,
}
impl<S> Drop for Authentication<S> {
    fn drop(&mut self) {
        // Normal refused/closed peers remain connection-local. On unwind the
        // SAME root session/stop is vetoed BEFORE the stream field can close.
        if std::thread::panicking() {self.shutdown.veto();}
    }
}
fn authenticate_owned<S>(stream:S,admitted_uid:u32,shutdown:Arc<super::IpcShutdown>,end:Instant,
    mut verify:impl FnMut(&S,Instant)->EnclaveResult<PeerCredentials>)->EnclaveResult<Authentication<S>> {
    let mut owner=Authentication {stream,pin:None,shutdown};
    let end=end.min(Instant::now()+super::PREFLIGHT);
    current(&owner.shutdown.stop,end)?;
    let original=verify(&owner.stream,end)?;
    current(&owner.shutdown.stop,end)?;
    owner.pin=Some(OriginalPeer::new(original,admitted_uid,end)?);
    // The SAME owning guard spans postconstruction verification too. No
    // native call sees a moved/replacement stream or a caller ready receipt.
    current(&owner.shutdown.stop,end)?;
    owner.pin.as_ref().expect("original pin").same(&verify(&owner.stream,end)?)?;
    current(&owner.shutdown.stop,end)?;
    Ok(owner)
}

/// Owns one actual accepted native stream. No stream getter, Clone, serde,
/// external peer constructor, fixture/native provider or positive receipt.
pub(super) struct ServerPeer {owner:Authentication<UnixStream>,policy:PeerPolicy}
impl ServerPeer {
    pub(super) fn authenticate(stream:UnixStream,policy:PeerPolicy,admitted_uid:u32,
        shutdown:Arc<super::IpcShutdown>,end:Instant)->EnclaveResult<Self> {
        let owner=authenticate_owned(stream,admitted_uid,shutdown,end,
            |stream,end|native_peer(stream,&policy,end))?;
        Ok(Self {owner,policy})
    }
    pub(super) fn begin(&mut self)->EnclaveResult<PeerRequest<'_>> {
        let owner=&mut self.owner;
        let inner=owner.pin.as_mut().expect("original pin").begin(&mut owner.stream,owner.shutdown.stop.as_ref())?;
        Ok(PeerRequest {inner,policy:&self.policy,shutdown:owner.shutdown.as_ref()})
    }
}
impl Drop for ServerPeer {
    fn drop(&mut self) {
        if std::thread::panicking() {self.owner.shutdown.veto();}
        self.owner.pin.as_mut().expect("original pin").consumed=true;
        let _=self.owner.stream.shutdown(Shutdown::Both);
    }
}

/// Borrows the SAME owned stream through read, queue publication and reply.
/// Abandoning it retires the connection before any socket teardown.
pub(super) struct PeerRequest<'a> { inner: Exchange<'a, UnixStream>, policy: &'a PeerPolicy,shutdown:&'a super::IpcShutdown }
impl PeerRequest<'_> {
    pub(super) fn read_frame(&mut self) -> EnclaveResult<zeroize::Zeroizing<Vec<u8>>> {
        let policy = self.policy;
        self.inner.read_with(|stream, end| native_peer(stream, policy, end), |stream, end| {
            let remaining = end.saturating_duration_since(Instant::now());
            let limits = FrameIoLimits { max_frame: super::FRAME, frame_deadline: remaining, idle_timeout: remaining };
            ipc::read_frame_timed(stream, &limits)
        })
    }
    pub(super) fn publish<T>(&mut self, publish: impl FnOnce(Instant) -> T) -> EnclaveResult<(Instant, T)> {
        let policy = self.policy;
        self.inner.publish_with(|stream, end| native_peer(stream, policy, end), publish)
    }
    pub(super) fn reply(mut self, bytes: &[u8]) -> EnclaveResult<()> {
        let policy = self.policy;
        self.inner.reply_with(|stream, end| native_peer(stream, policy, end), |stream, end| {
            ipc::write_frame_timed(stream, bytes, &super::frame_limits(end)?)
        })
    }
}
impl Drop for PeerRequest<'_> {
    fn drop(&mut self) {
        // Includes a moved reply transaction unwinding inside its callee.
        if std::thread::panicking() {self.shutdown.veto();}
        if !self.inner.completed {
            self.inner.pin.consumed = true;
            let _ = self.inner.stream.shutdown(Shutdown::Both);
        }
    }
}

#[cfg(test)]
#[path = "readiness_server_peer_tests.rs"]
mod tests;
