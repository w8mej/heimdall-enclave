//! Public setup transport only; no guard/birth/checked/approval capability.
//! Concrete stdio must already be nonblocking pipes/sockets, so this process
//! never changes an inherited open-file description's flags for another owner.
use super::*;
use crate::deploy::target_birth_inputs::{BirthSourceRole, BirthSourceSpec};
use serde::Deserialize;
use std::{
    fs::File,
    os::fd::{AsRawFd, FromRawFd},
    time::{Duration, Instant},
};
const MAX_COMMAND: usize = 16 * 1024;
pub(super) const MAX_PICKUP: u64 = 1024 * 1024;
pub(super) const SETUP_WAIT: Duration = Duration::from_secs(900);
pub(super) const OUTPUT_WAIT: Duration = Duration::from_secs(5);
const MAX_OUTPUT: usize = 1024 * 1024;

struct Stream {
    file: File,
    identity: (u64, u64),
    input: bool,
}
impl Stream {
    fn new(file: File, input: bool) -> EnclaveResult<Self> {
        let m = file
            .metadata()
            .map_err(|_| err!(EIO, "BIRTH_SESSION_STREAM_STAT"))?;
        let result = Self {
            identity: (m.dev(), m.ino()),
            file,
            input,
        };
        result.current()?;
        Ok(result)
    }
    fn current(&self) -> EnclaveResult<()> {
        let m = self
            .file
            .metadata()
            .map_err(|_| err!(EIO, "BIRTH_SESSION_STREAM_STAT"))?;
        let kind = m.mode() & libc::S_IFMT as u32;
        let flags = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GETFL) };
        let fdflags = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GETFD) };
        let access = flags & libc::O_ACCMODE;
        if (m.dev(), m.ino()) != self.identity
            || ![libc::S_IFIFO as u32, libc::S_IFSOCK as u32].contains(&kind)
            || flags < 0
            || flags & libc::O_NONBLOCK == 0
            || fdflags < 0
            || fdflags & libc::FD_CLOEXEC == 0
            || (self.input && access == libc::O_WRONLY)
            || (!self.input && access == libc::O_RDONLY)
        {
            fail!(EACCES, "BIRTH_SESSION_NONBLOCKING_PIPE_STREAMS_REQUIRED");
        }
        Ok(())
    }
    fn wait(&self, until: Instant) -> EnclaveResult<()> {
        loop {
            self.current()?;
            let now = Instant::now();
            if now >= until {
                fail!(ETIMEDOUT, "BIRTH_SESSION_IO_TIMEOUT");
            }
            let millis =
                (until.saturating_duration_since(now).as_millis() + 1).min(i32::MAX as u128) as i32;
            let mut fd = libc::pollfd {
                fd: self.file.as_raw_fd(),
                events: if self.input {
                    libc::POLLIN
                } else {
                    libc::POLLOUT
                },
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut fd, 1, millis) };
            if result < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                fail!(EIO, "BIRTH_SESSION_IO_POLL");
            }
            if Instant::now() >= until || result == 0 {
                fail!(ETIMEDOUT, "BIRTH_SESSION_IO_TIMEOUT");
            }
            if fd.revents & libc::POLLNVAL != 0
                || (!self.input && fd.revents & (libc::POLLERR | libc::POLLHUP) != 0)
            {
                fail!(EIO, "BIRTH_SESSION_IO_CLOSED");
            }
            if fd.revents & (fd.events | libc::POLLHUP | libc::POLLERR) != 0 {
                return self.current();
            }
        }
    }
}
pub(super) struct NativeStreams {
    input: Stream,
    output: Stream,
}
impl NativeStreams {
    pub(super) fn standard() -> EnclaveResult<Self> {
        fn duplicate(fd: i32) -> EnclaveResult<File> {
            let owned = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
            if owned < 0 {
                fail!(EIO, "BIRTH_SESSION_STREAM_DUPLICATE");
            }
            Ok(unsafe { File::from_raw_fd(owned) })
        }
        // No F_SETFL: inherited controller stream status is never changed.
        Ok(Self {
            input: Stream::new(duplicate(libc::STDIN_FILENO)?, true)?,
            output: Stream::new(duplicate(libc::STDOUT_FILENO)?, false)?,
        })
    }
    pub(super) fn command(&self, until: Instant) -> EnclaveResult<SetupCommand> {
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            self.input.wait(until)?;
            let count = unsafe {
                libc::read(
                    self.input.file.as_raw_fd(),
                    chunk.as_mut_ptr().cast(),
                    chunk.len(),
                )
            };
            if count < 0 {
                match std::io::Error::last_os_error().kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => continue,
                    _ => fail!(EIO, "BIRTH_SESSION_INPUT_READ"),
                }
            }
            if count == 0 {
                fail!(EIO, "BIRTH_SESSION_INPUT_EOF");
            }
            let observed = &chunk[..count as usize];
            if bytes
                .len()
                .checked_add(observed.len())
                .is_none_or(|size| size > MAX_COMMAND)
            {
                fail!(E2BIG, "BIRTH_SESSION_INPUT_BOUND");
            }
            if let Some(newline) = observed.iter().position(|byte| *byte == b'\n') {
                if newline + 1 != observed.len() {
                    fail!(EINVAL, "BIRTH_SESSION_ONE_COMMAND_REQUIRED");
                }
                bytes.extend_from_slice(&observed[..newline]);
                return command(&bytes);
            }
            bytes.extend_from_slice(observed);
        }
    }
    pub(super) fn frame(&self, value: &impl Serialize, until: Instant) -> EnclaveResult<()> {
        self.output.frame(value, until)
    }
}
impl Stream {
    fn frame(&self, value: &impl Serialize, until: Instant) -> EnclaveResult<()> {
        let mut bytes =
            serde_json::to_vec(value).map_err(|_| err!(EIO, "BIRTH_SESSION_OUTPUT_ENCODE"))?;
        if bytes.len() >= MAX_OUTPUT {
            fail!(E2BIG, "BIRTH_SESSION_OUTPUT_BOUND");
        }
        bytes.push(b'\n');
        let mut offset = 0;
        while offset < bytes.len() {
            self.wait(until)?;
            let end = (offset + 4096).min(bytes.len());
            let count = unsafe {
                libc::write(
                    self.file.as_raw_fd(),
                    bytes[offset..end].as_ptr().cast(),
                    end - offset,
                )
            };
            if count < 0 {
                match std::io::Error::last_os_error().kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => continue,
                    _ => fail!(EIO, "BIRTH_SESSION_OUTPUT_WRITE"),
                }
            }
            if count == 0 {
                fail!(EIO, "BIRTH_SESSION_OUTPUT_WRITE");
            }
            offset += count as usize;
        }
        self.current()?;
        if Instant::now() >= until {
            fail!(ETIMEDOUT, "BIRTH_SESSION_IO_TIMEOUT");
        }
        Ok(())
    }
}
/// Same bounded concrete nonblocking stdout route for public-only producer.
pub(super) fn public_frame(value: &impl Serialize) -> EnclaveResult<()> {
    let fd = unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
    if fd < 0 {
        fail!(EIO, "BIRTH_SESSION_STREAM_DUPLICATE");
    }
    Stream::new(unsafe { File::from_raw_fd(fd) }, false)?.frame(value, Instant::now() + OUTPUT_WAIT)
}
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum SetupCommand {
    Continue {
        version: u8,
        input_manifest: PathBuf,
    },
    Cancel {
        version: u8,
    },
}
fn json(bytes: &[u8], maximum: usize) -> EnclaveResult<()> {
    if !bytes.is_ascii() || bytes.contains(&b'\\') {
        fail!(EINVAL, "BIRTH_SESSION_JSON_SCHEMA");
    }
    crate::deploy::target_release_json::strict(bytes, maximum)
        .map(|_| ())
        .map_err(|_| err!(EINVAL, "BIRTH_SESSION_JSON_SCHEMA"))
}
fn command(bytes: &[u8]) -> EnclaveResult<SetupCommand> {
    json(bytes, MAX_COMMAND)?;
    let parsed: SetupCommand =
        serde_json::from_slice(bytes).map_err(|_| err!(EINVAL, "BIRTH_SESSION_COMMAND_SCHEMA"))?;
    match &parsed {
        SetupCommand::Continue {
            version,
            input_manifest,
        } => {
            if *version != 1 {
                fail!(EINVAL, "BIRTH_SESSION_COMMAND_VERSION");
            }
            exact(input_manifest)?;
        }
        SetupCommand::Cancel { version } => {
            if *version != 1 {
                fail!(EINVAL, "BIRTH_SESSION_COMMAND_VERSION");
            }
        }
    }
    Ok(parsed)
}
pub(super) fn exact(path: &Path) -> EnclaveResult<()> {
    if normalized_path(path)? != path
        || path.components().count() > 96
        || path
            .components()
            .any(|part| matches!(part,Component::Normal(name)if name.as_encoded_bytes().len()>255))
    {
        fail!(EINVAL, "BIRTH_SESSION_PATH");
    }
    Ok(())
}
#[derive(Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum InitialRole {
    Inventory,
    CustodyManifest,
    CustodyPolicy,
    PolicyIssuerKey,
    InventoryIssuerKey,
    EnvelopeIssuerKey,
    StagedPins,
}
impl InitialRole {
    fn actual(self) -> BirthSourceRole {
        match self {
            Self::Inventory => BirthSourceRole::Inventory,
            Self::CustodyManifest => BirthSourceRole::CustodyManifest,
            Self::CustodyPolicy => BirthSourceRole::CustodyPolicy,
            Self::PolicyIssuerKey => BirthSourceRole::PolicyIssuerKey,
            Self::InventoryIssuerKey => BirthSourceRole::InventoryIssuerKey,
            Self::EnvelopeIssuerKey => BirthSourceRole::EnvelopeIssuerKey,
            Self::StagedPins => BirthSourceRole::Staged("codesign-pins.json".into()),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InitialSource {
    role: InitialRole,
    path: PathBuf,
    sha256: String,
    size: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StagedSource {
    relative: PathBuf,
    path: PathBuf,
    sha256: String,
    size: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pickup {
    version: u8,
    kind: String,
    target_id: String,
    descriptor_sha256: String,
    pub(super) package_root: PathBuf,
    initial_sources: Vec<InitialSource>,
    remaining_staged_sources: Vec<StagedSource>,
    pub(super) software_release_config: PathBuf,
    pub(super) operator_runtime_pin_record: PathBuf,
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
impl Pickup {
    pub(super) fn parse(
        bytes: &[u8],
        target_id: &str,
        descriptor_sha256: &str,
        root: &Path,
    ) -> EnclaveResult<Self> {
        json(bytes, MAX_PICKUP as usize)?;
        let parsed: Self = serde_json::from_slice(bytes)
            .map_err(|_| err!(EINVAL, "BIRTH_SESSION_PICKUP_SCHEMA"))?;
        if parsed.version != 1
            || parsed.kind != "depot-dedicated-birth-public-inputs"
            || parsed.target_id != target_id
            || parsed.descriptor_sha256 != descriptor_sha256
            || !digest(&parsed.descriptor_sha256)
            || parsed.initial_sources.len() != 7
            || parsed.remaining_staged_sources.is_empty()
            || parsed.remaining_staged_sources.len() > 128
        {
            fail!(EACCES, "BIRTH_SESSION_PICKUP_SCOPE");
        }
        for path in [
            &parsed.package_root,
            &parsed.software_release_config,
            &parsed.operator_runtime_pin_record,
        ] {
            exact(path)?;
            if overlaps(path, root)? {
                fail!(EACCES, "BIRTH_SESSION_EXTERNAL_INPUT_REQUIRED");
            }
        }
        let mut roles = BTreeSet::new();
        let mut names = BTreeSet::new();
        for source in &parsed.initial_sources {
            if !roles.insert(source.role) {
                fail!(EINVAL, "BIRTH_SESSION_PICKUP_ROLE_SET");
            }
            parsed.source(&source.path, &source.sha256, source.size, root, &mut names)?;
        }
        let mut relatives = BTreeSet::new();
        for source in &parsed.remaining_staged_sources {
            let relative = &source.relative;
            if relative.as_os_str().is_empty()
                || relative.as_os_str().as_encoded_bytes().len() > 4096
                || !relative
                    .components()
                    .all(|part| matches!(part, Component::Normal(_)))
                || relative.components().collect::<PathBuf>() != *relative
                || relative == Path::new("codesign-pins.json")
                || !relatives.insert(
                    relative
                        .to_str()
                        .ok_or_else(|| err!(EINVAL, "BIRTH_SESSION_STAGED_PATH"))?
                        .to_ascii_lowercase(),
                )
            {
                fail!(EINVAL, "BIRTH_SESSION_STAGED_PATH");
            }
            parsed.source(&source.path, &source.sha256, source.size, root, &mut names)?;
        }
        Ok(parsed)
    }
    fn source(
        &self,
        path: &Path,
        hash: &str,
        size: u64,
        root: &Path,
        names: &mut BTreeSet<String>,
    ) -> EnclaveResult<()> {
        exact(path)?;
        if !path.starts_with(&self.package_root)
            || path == self.package_root
            || overlaps(path, root)?
            || !digest(hash)
            || size == 0
            || size > 512 * 1024 * 1024
            || !names.insert(
                path.to_str()
                    .ok_or_else(|| err!(EINVAL, "BIRTH_SESSION_PATH"))?
                    .to_ascii_lowercase(),
            )
        {
            fail!(EINVAL, "BIRTH_SESSION_SOURCE_EXPECTATION");
        }
        Ok(())
    }
    pub(super) fn initial(&self) -> Vec<BirthSourceSpec> {
        self.initial_sources
            .iter()
            .map(|source| BirthSourceSpec {
                role: source.role.actual(),
                path: source.path.clone(),
                sha256: source.sha256.clone(),
                size: source.size,
            })
            .collect()
    }
    pub(super) fn staged(&self) -> Vec<BirthSourceSpec> {
        self.remaining_staged_sources
            .iter()
            .map(|source| BirthSourceSpec {
                role: BirthSourceRole::Staged(source.relative.clone()),
                path: source.path.clone(),
                sha256: source.sha256.clone(),
                size: source.size,
            })
            .collect()
    }
}

#[cfg(test)]
#[path = "target_birth_session_protocol_tests.rs"]
mod tests;
