//! Trusted tool-host lifecycle and wall-clock boundary (F103).
//!
//! Provision once with the durable issuer key, then open on every daemon start.
//! A separate durable provisioning marker prevents a missing replay database from
//! being treated as a fresh installation under that same issuer. Neither startup
//! nor request handling creates, repairs or resets replay state.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};

use crate::{ExecutionTicket, TicketReplayFilter, ToolHost, ToolOutput};

fn storage(e: impl std::fmt::Display) -> enclave_core::error::EnclaveError {
    err!(EIO, "TOOL_HOST_STATE", "{e}")
}

fn marker(path: &Path) -> EnclaveResult<PathBuf> {
    let name = path.file_name().ok_or_else(|| err!(EINVAL, "TOOL_HOST_PATH"))?;
    let mut name = name.to_os_string();
    name.push(".provisioned");
    Ok(path.with_file_name(name))
}

fn private_parent(path: &Path) -> EnclaveResult<()> {
    validate_trusted_ancestry(path)?;
    let parent = path.parent().ok_or_else(|| err!(EINVAL, "TOOL_HOST_PATH"))?;
    if !path.is_absolute() || std::fs::canonicalize(parent).map_err(storage)? != parent {
        fail!(EACCES, "TOOL_HOST_DIRECTORY");
    }
    let meta = std::fs::metadata(parent).map_err(storage)?;
    // SAFETY: geteuid has no preconditions.
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        fail!(EACCES, "TOOL_HOST_DIRECTORY");
    }
    Ok(())
}

/// Require root/daemon-controlled ancestry for trusted configuration/state paths.
/// A root/daemon-owned sticky shared directory is allowed; its next component
/// must still be owned by root/the daemon. Both lexical symlink ownership and
/// resolved directory ancestry are checked. Same-UID/root state replacement is
/// outside the unprivileged request boundary; no rollback-proof storage is claimed.
pub fn validate_trusted_ancestry(path: &Path) -> EnclaveResult<()> {
    if !path.is_absolute() { fail!(EACCES, "TOOL_HOST_DIRECTORY"); }
    let parent=path.parent().ok_or_else(||err!(EINVAL,"TOOL_HOST_PATH"))?;
    let canonical=std::fs::canonicalize(parent).map_err(storage)?;
    // SAFETY: geteuid has no preconditions.
    let uid=unsafe {libc::geteuid()};
    for root in [parent,canonical.as_path()] {
        for ancestor in root.ancestors() {
            let meta=std::fs::symlink_metadata(ancestor).map_err(storage)?;
            if meta.uid()!=0 && meta.uid()!=uid {fail!(EACCES,"TOOL_HOST_ANCESTRY");}
            if meta.file_type().is_symlink() {continue;}
            if !meta.is_dir() || (meta.mode()&0o022!=0 && meta.mode()&0o1000==0) {
                fail!(EACCES,"TOOL_HOST_ANCESTRY");
            }
        }
    }
    Ok(())
}

/// Read the host clock inside the trusted dispatcher, never from an IPC request.
pub fn trusted_unix_ns() -> EnclaveResult<u64> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(storage)?;
    u64::try_from(now.as_nanos()).map_err(storage)
}

/// Original exclusive custody endpoints. These public facts can only shorten an
/// already authorized dispatch; they are not a grant or a live revocation proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchExpiry {
    wall_ns: Option<u64>,
    boot_ns: u64,
    observed_wall_ns: u64,
    observed_boot_ns: u64,
}
impl DispatchExpiry {
    /// Capture existing endpoints using this host's clocks. Never starts a new
    /// lifetime. The trusted caller must obtain the endpoints from actual custody.
    pub fn from_original(wall_unix: Option<i64>, boot_ns: u64) -> EnclaveResult<Self> {
        let wall_ns = wall_unix.map(|value| u64::try_from(value).ok()
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .ok_or_else(|| err!(EINVAL, "TOOL_AUTHORITY_TIME"))).transpose()?;
        let observed_wall_ns = trusted_unix_ns()?;
        let observed_boot_ns = enclave_core::clock::boot_clock_ns();
        let value = Self { wall_ns, boot_ns, observed_wall_ns, observed_boot_ns };
        value.check_at(observed_wall_ns, observed_boot_ns)?;
        Ok(value)
    }
    fn check_at(&self, wall: u64, boot: u64) -> EnclaveResult<()> {
        if wall < self.observed_wall_ns || boot < self.observed_boot_ns {
            fail!(ESTALE, "TOOL_AUTHORITY_CLOCK_REGRESSION");
        }
        if boot >= self.boot_ns || self.wall_ns.is_some_and(|expiry| wall >= expiry) {
            fail!(ESTALE, "TOOL_AUTHORITY_EXPIRED");
        }
        Ok(())
    }
    /// Recheck the SAME exclusive endpoints at a later actual dispatch boundary.
    pub fn check(&self) -> EnclaveResult<()> {
        self.check_at(trusted_unix_ns()?, enclave_core::clock::boot_clock_ns())
    }
    /// Original boot endpoint, suitable for observation, never a fresh TTL.
    pub fn boot_deadline_ns(&self) -> u64 { self.boot_ns }
    /// Original independent wall endpoint in nanoseconds, when one applies.
    pub fn wall_deadline_ns(&self) -> Option<u64> { self.wall_ns }
    pub(crate) fn ticket_window(&self) -> EnclaveResult<(u64, u64)> {
        // UTC BEFORE boot makes this projection conservative: time spent between
        // observations is subtracted, never added to the original boot remainder.
        let wall = trusted_unix_ns()?;
        let boot = enclave_core::clock::boot_clock_ns();
        self.window_at(wall, boot)
    }
    fn window_at(&self, wall: u64, boot: u64) -> EnclaveResult<(u64, u64)> {
        self.check_at(wall, boot)?;
        let projected = wall.checked_add(self.boot_ns - boot)
            .ok_or_else(|| err!(EINVAL, "TOOL_AUTHORITY_TIME"))?;
        let maximum = wall.checked_add(60_000_000_000)
            .ok_or_else(|| err!(EINVAL, "TOOL_AUTHORITY_TIME"))?;
        let expiry = self.wall_ns.into_iter().chain([projected, maximum]).min()
            .ok_or_else(|| err!(EINVAL, "TOOL_AUTHORITY_TIME"))?;
        let ttl = expiry.checked_sub(wall).filter(|value| *value > 0)
            .ok_or_else(|| err!(ESTALE, "TOOL_AUTHORITY_EXPIRED"))?;
        Ok((wall, ttl))
    }
}

/// A reopened durable host whose public execution methods obtain time locally.
#[derive(Debug)]
pub struct DurableToolHost {
    host: ToolHost,
}

impl DurableToolHost {
    /// Explicit first installation only. The parent must already be private and
    /// canonical. Refuses any previous marker, including after database deletion.
    /// Failure leaves the marker in place; recovery requires an explicit operator
    /// decision about issuer rotation, never an automatic retry/reset.
    pub fn provision(path: &Path, key: VerifyingKey, capacity: u64) -> EnclaveResult<Self> {
        private_parent(path)?;
        if capacity == 0 || capacity > 65_536 {
            fail!(EINVAL, "REPLAY_CAPACITY_INVALID");
        }
        let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(marker(path)?).map_err(storage)?;
        f.write_all(key.as_bytes()).map_err(storage)?;
        f.sync_all().map_err(storage)?;
        File::open(path.parent().unwrap()).map_err(storage)?.sync_all().map_err(storage)?;
        let replay = TicketReplayFilter::initialize(path, capacity)?;
        Ok(Self { host: ToolHost::new(key, replay) })
    }

    /// Normal startup. Refuses absent/corrupt/insecure state or issuer mismatch.
    pub fn open(path: &Path, key: VerifyingKey) -> EnclaveResult<Self> {
        private_parent(path)?;
        let mut f = OpenOptions::new().read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(marker(path)?).map_err(storage)?;
        let meta = f.metadata().map_err(storage)?;
        // SAFETY: geteuid has no preconditions.
        if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o077 != 0 || meta.nlink() != 1 || meta.len() != 32 {
            fail!(EACCES, "TOOL_HOST_MARKER");
        }
        let mut expected = [0u8; 32];
        f.read_exact(&mut expected).map_err(storage)?;
        if expected != *key.as_bytes() {
            fail!(EACCES, "TOOL_HOST_ISSUER_MISMATCH");
        }
        Ok(Self { host: ToolHost::new(key, TicketReplayFilter::open(path)?) })
    }

    /// Execute an independently selected depot target using the current host clock.
    pub fn execute<F>(&self, ticket: &ExecutionTicket, server: &str, tool: &str,
        args_jcs: &[u8], run: F) -> EnclaveResult<ToolOutput>
    where F: FnOnce(&str, &str, &[u8]) -> EnclaveResult<Vec<u8>> {
        self.host.execute(ticket, server, tool, args_jcs, trusted_unix_ns()?, run)
    }

    /// Execute independently approved native bytes using the current host clock.
    pub fn execute_cwasm(&self, ticket: &ExecutionTicket, server: &str, tool: &str,
        module: &[u8], args_jcs: &[u8]) -> EnclaveResult<ToolOutput> {
        self.host.execute_cwasm(ticket, server, tool, module, args_jcs, trusted_unix_ns()?)
    }

    /// Execute with the original custody endpoints at every code-capable stage.
    /// Durable replay consumption is unchanged, including on a later refusal.
    pub fn execute_cwasm_before(&self, ticket: &ExecutionTicket, server: &str, tool: &str,
        module: &[u8], args_jcs: &[u8], expiry: &DispatchExpiry) -> EnclaveResult<ToolOutput> {
        expiry.check()?;
        self.host.execute_cwasm_before(ticket, server, tool, module, args_jcs, trusted_unix_ns()?, expiry)
    }
}

#[cfg(test)]
mod expiry_tests {
    use super::*;
    #[test]
    fn original_dispatch_endpoints_shorten_ticket_and_refuse_exact_expiry_regression_and_overflow() {
        let value = DispatchExpiry {wall_ns:Some(140),boot_ns:230,observed_wall_ns:100,observed_boot_ns:200};
        assert_eq!(value.window_at(110,210).unwrap(),(110,20));
        assert!(value.check_at(140,210).unwrap_err().is("TOOL_AUTHORITY_EXPIRED"));
        assert!(value.check_at(110,230).unwrap_err().is("TOOL_AUTHORITY_EXPIRED"));
        assert!(value.check_at(99,210).unwrap_err().is("TOOL_AUTHORITY_CLOCK_REGRESSION"));
        assert!(value.check_at(110,199).unwrap_err().is("TOOL_AUTHORITY_CLOCK_REGRESSION"));
        let earlier_wall = DispatchExpiry {wall_ns:Some(115),..value};
        assert_eq!(earlier_wall.window_at(110,210).unwrap(),(110,5));
        let long = DispatchExpiry {wall_ns:None,boot_ns:u64::MAX,observed_wall_ns:0,observed_boot_ns:0};
        assert_eq!(long.window_at(10,u64::MAX-70_000_000_000).unwrap(),(10,60_000_000_000));
        assert!(long.window_at(u64::MAX-5,u64::MAX-10).unwrap_err().is("TOOL_AUTHORITY_TIME"));
        assert!(DispatchExpiry::from_original(Some(-1),u64::MAX).unwrap_err().is("TOOL_AUTHORITY_TIME"));
        assert!(DispatchExpiry::from_original(Some(i64::MAX),u64::MAX).unwrap_err().is("TOOL_AUTHORITY_TIME"));
        assert!(DispatchExpiry::from_original(None,0).unwrap_err().is("TOOL_AUTHORITY_EXPIRED"));
    }
}
