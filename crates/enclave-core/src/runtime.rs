//! Shared daemon runtime: argument parsing, socket directory, peer policy,
//! process hardening and the RSS-ceiling watchdog.
//!
//! Every daemon binary calls [`DaemonArgs::from_env`] and then
//! [`run_service`]. In **production** mode peers are authorised by the
//! ADR-006 UID matrix ([`crate::ipc::production_policy`]) and daemons expect
//! each other at their production UIDs. **Development** mode
//! (`--dev-same-uid`, used by `mcp-enclave daemon start --dev` and the
//! integration tests) runs all five daemons under the invoking UID; it is
//! reported in every status reply and never enabled by the LaunchDaemon plists.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::daemon::DaemonId;
use crate::error::EnclaveResult;
use crate::ipc::{self, PeerCredentials, PeerPolicy};
use crate::profile::Profile;
use crate::resource::MemoryCeiling;
use crate::{err, fail};

/// Default production socket directory.
pub const DEFAULT_SOCKET_DIR: &str = "/var/run/enclave";
/// Default production audit directory.
pub const DEFAULT_AUDIT_DIR: &str = "/var/log/enclave";
/// Exit code used when the RSS ceiling is breached (fail closed).
pub const EXIT_RSS_CEILING: i32 = 70;

/// Parsed daemon arguments.
#[derive(Debug, Clone)]
pub struct DaemonArgs {
    /// Socket directory.
    pub socket_dir: PathBuf,
    /// Audit directory (`None` disables journaling).
    pub audit_dir: Option<PathBuf>,
    /// Effective profile.
    pub profile: Profile,
    /// Development mode: every daemon runs under the invoking UID.
    pub dev_same_uid: bool,
    /// Use simulated hardware providers (SEP / CoreAuthUI / YubiKey).
    pub simulated_hardware: bool,
    /// Per-daemon persistent state directory (`--state-dir`; `None` keeps
    /// state in memory — tests only).
    pub state_dir: Option<PathBuf>,
    /// In-process Darwin Seatbelt sandbox profile path (`--sandbox-profile`; GAP-50).
    pub sandbox_profile: Option<PathBuf>,
    /// Inherited listening socket file descriptor passed via `SCM_RIGHTS` (`--inherit-listener-fd`; GAP-63).
    pub inherit_listener_fd: Option<i32>,
    /// Extra free-form `--key value` options for the specific daemon.
    pub extra: Vec<(String, String)>,
}

impl DaemonArgs {
    /// Parse `--socket-dir D --audit-dir D --profile L2 [--dev-same-uid] [--simulated-hardware] [--k v]...`.
    pub fn parse<I: IntoIterator<Item = String>>(it: I) -> EnclaveResult<Self> {
        let mut a = DaemonArgs {
            socket_dir: PathBuf::from(DEFAULT_SOCKET_DIR),
            audit_dir: Some(PathBuf::from(DEFAULT_AUDIT_DIR)),
            profile: Profile::L1,
            dev_same_uid: false,
            simulated_hardware: false,
            state_dir: None,
            sandbox_profile: None,
            inherit_listener_fd: None,
            extra: vec![],
        };
        let mut it = it.into_iter().skip(1).peekable();
        while let Some(k) = it.next() {
            match k.as_str() {
                "--dev-same-uid" => a.dev_same_uid = true,
                "--simulated-hardware" => a.simulated_hardware = true,
                "--accelerated-schedule" => {
                    a.extra.push(("accelerated-schedule".into(), "true".into()))
                }
                "--no-audit" => a.audit_dir = None,
                _ => {
                    let v = it
                        .next()
                        .ok_or_else(|| err!(EINVAL, "ARG_MISSING_VALUE", "{k}"))?;
                    match k.as_str() {
                        "--socket-dir" => a.socket_dir = PathBuf::from(v),
                        "--audit-dir" => a.audit_dir = Some(PathBuf::from(v)),
                        "--profile" => a.profile = Profile::parse(&v)?,
                        "--state-dir" => a.state_dir = Some(PathBuf::from(v)),
                        "--sandbox-profile" => a.sandbox_profile = Some(PathBuf::from(v)),
                        "--inherit-listener-fd" => {
                            let fd = v
                                .parse::<i32>()
                                .map_err(|e| err!(EINVAL, "ARG_INVALID_FD", "{v}: {e}"))?;
                            a.inherit_listener_fd = Some(fd);
                        }
                        _ if k.starts_with("--") => a.extra.push((k[2..].to_owned(), v)),
                        _ => fail!(EINVAL, "ARG_UNKNOWN", "{k}"),
                    }
                }
            }
        }
        if a.simulated_hardware && !a.dev_same_uid {
            fail!(
                EPERM,
                "SIMULATION_REQUIRES_DEV_MODE",
                "--simulated-hardware is only valid with --dev-same-uid"
            );
        }
        Ok(a)
    }
    /// GAP-03: simulated providers may only run where no production peer can
    /// reach them: development mode, not under a daemon UID 701–705, and not
    /// on the production socket directory (whose clients expect UID 701–705).
    pub fn check_simulation_allowed(&self) -> EnclaveResult<()> {
        if !self.simulated_hardware {
            return Ok(());
        }
        if !self.dev_same_uid {
            fail!(EPERM, "SIMULATION_REQUIRES_DEV_MODE");
        }
        let uid = ipc::geteuid();
        if DaemonId::from_uid(uid).is_some() {
            fail!(
                EPERM,
                "SIMULATION_FORBIDDEN_UID",
                "uid {uid} is a production daemon identity"
            );
        }
        if self.socket_dir == Path::new(DEFAULT_SOCKET_DIR) {
            fail!(
                EPERM,
                "SIMULATION_FORBIDDEN_SOCKET_DIR",
                "{DEFAULT_SOCKET_DIR} is the production mesh"
            );
        }
        Ok(())
    }
    /// Parse from the process arguments.
    pub fn from_env() -> EnclaveResult<Self> {
        let args = Self::parse(std::env::args())?;
        args.bind_deployment_context()?;
        Ok(args)
    }
    /// Bind a protected target before the FIRST code requirement or IPC call.
    /// Embedded entrypoints that use pure `parse` must call this immediately.
    /// Reusing an already selected identical context checks argv and fresh
    /// upgrade start inhibition and the retained process-lifetime SH lease;
    /// it never replaces process authority. General `deployment::select`
    /// remains one-shot and does not acquire an actor lease.
    pub fn bind_deployment_context(&self) -> EnclaveResult<()> {
        let paths: Vec<_> = self.extra.iter().filter(|(k,_)| k == "deployment-target").collect();
        if paths.len() > 1 { fail!(EINVAL, "DEPLOYMENT_ARGUMENTS"); }
        let Some((_,path)) = paths.first() else {
            if crate::deployment::selected().is_some() { fail!(EINVAL, "DEPLOYMENT_ARGUMENTS"); }
            return Ok(());
        };
        // Selected deployments have no authenticated inherited-listener route
        // yet. A received descriptor must not bypass the selected pathname.
        if self.inherit_listener_fd.is_some() { fail!(EACCES, "DEPLOYMENT_INHERITED_LISTENER_UNAVAILABLE"); }
        if self.dev_same_uid || self.simulated_hardware { fail!(EACCES, "DEPLOYMENT_NATIVE_REQUIRED"); }
        if let Some(checked) = crate::deployment::selected() {
            if crate::deployment::normalized_path(Path::new(path))?
                != crate::deployment::normalized_path(checked.config_path())? {
                fail!(EACCES, "DEPLOYMENT_CONTEXT_CONFLICT");
            }
            self.check_deployment_arguments(checked.target())?;
            // Recheck through the retained owner so marker loss cannot revive
            // an actor poisoned by an earlier inhibited startup attempt.
            return crate::deployment::startup_lease::retain_selected_startup_lease();
        }
        let checked = crate::deployment::load(Path::new(path))?;
        self.check_deployment_arguments(checked.target())?;
        crate::deployment::upgrade::assert_start_allowed(&checked)?;
        crate::deployment::select(checked)?;
        crate::deployment::startup_lease::retain_selected_startup_lease()
    }
    /// Bind before daemon-specific effects and require that daemon's exact
    /// persistent-state and confinement routes in a selected deployment.
    /// This performs no UID observation, service initialization or file writes.
    pub fn bind_deployment_for_daemon(&self, d: DaemonId) -> EnclaveResult<()> {
        self.bind_deployment_context()?;
        if let Some(checked) = crate::deployment::selected() {
            use crate::deployment::normalized_path;
            let layout = &checked.target().layout;
            if self.state_dir.as_ref().map(|p| normalized_path(p)).transpose()?
                != Some(normalized_path(&layout.state_root.join(d.dir_name()))?)
                || self.sandbox_profile.as_ref().map(|p| normalized_path(p)).transpose()?
                    != Some(normalized_path(&layout.sandbox_dir.join(format!("{}.sb", d.plist_suffix())))?) {
                fail!(EINVAL, "DEPLOYMENT_ARGUMENTS");
            }
        }
        Ok(())
    }
    fn check_deployment_arguments(&self, target: &crate::deployment::DeploymentTarget) -> EnclaveResult<()> {
        use crate::deployment::normalized_path;
        if self.profile != target.profile
            || normalized_path(&self.socket_dir)? != normalized_path(&target.layout.socket_root)?
            || self.audit_dir.as_ref().map(|p|normalized_path(p)).transpose()?
                != Some(normalized_path(&target.layout.audit_root)?) {
            fail!(EINVAL, "DEPLOYMENT_ARGUMENTS");
        }
        for (supplied, root) in [(&self.state_dir, &target.layout.state_root),
            (&self.sandbox_profile, &target.layout.sandbox_dir)] {
            if let Some(path) = supplied {
                let path = normalized_path(path)?; let root = normalized_path(root)?;
                if path == root || !path.starts_with(root) { fail!(EINVAL, "DEPLOYMENT_ARGUMENTS"); }
            }
        }
        for (_, path) in self.extra.iter().filter(|(key,_)|key == "custody-authority-config") {
            if normalized_path(Path::new(path))? != normalized_path(&target.authority_config)? {
                fail!(EINVAL, "DEPLOYMENT_ARGUMENTS");
            }
        }
        Ok(())
    }
    /// Look up an extra option.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.extra
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
    /// Socket path of a daemon.
    pub fn socket_path(&self, d: DaemonId) -> PathBuf {
        self.socket_dir.join(d.socket_name())
    }
    /// UID a peer daemon is expected to run as.
    pub fn expected_uid(&self, d: DaemonId) -> u32 {
        if self.dev_same_uid {
            ipc::geteuid()
        } else {
            d.uid()
        }
    }
    /// Filesystem exposure of `server`'s socket (GAP-01).
    pub fn socket_access(&self, server: DaemonId) -> ipc::SocketAccess {
        if self.dev_same_uid {
            ipc::SocketAccess::OwnerOnly
        } else {
            ipc::SocketAccess::Group {
                gid: server.client_gid(),
            }
        }
    }
    /// Peer policy for `server`.
    pub fn peer_policy(&self, server: DaemonId) -> PeerPolicy {
        if self.dev_same_uid {
            PeerPolicy::allow([ipc::geteuid()])
        } else {
            ipc::production_policy(server)
        }
    }
    /// Audit journal path for a daemon: `<audit>/<suffix>/<suffix>-audit.jsonl`.
    /// Each daemon writes only inside its own journal directory (GAP-01 /
    /// GAP-36), so one compromised daemon cannot rewrite another's journal.
    pub fn audit_path(&self, d: DaemonId) -> Option<PathBuf> {
        self.audit_dir.as_ref().map(|a| {
            a.join(d.dir_name())
                .join(format!("{}-audit.jsonl", d.plist_suffix()))
        })
    }
    /// Connect to a peer daemon with mutual authentication.
    pub fn connect(&self, d: DaemonId) -> EnclaveResult<ipc::Client> {
        // Production clients also pin the server's signing identity (GAP-02).
        let req = (!self.dev_same_uid).then(|| crate::codesign::CodeRequirement::daemon(d));
        ipc::Client::connect_verified(&self.socket_path(d), self.expected_uid(d), req.as_ref())
    }
}

/// Trusted host observations for startup validation. Production obtains these
/// from the kernel/build; callers must never populate them from daemon arguments.
/// Tests can supply explicit fixture observations without changing accounts or
/// weakening the normal release configuration being validated.
#[derive(Debug, Clone, Copy)]
pub struct StartupContext {
    /// Kernel-derived effective UID.
    pub effective_uid: u32,
    /// Whether this build/platform requires production Seatbelt confinement.
    pub require_sandbox: bool,
    /// Owner of provisioned confinement profiles (root in production).
    pub profile_owner_uid: u32,
}

/// Shared production startup validator, also used by generated-argv regression
/// tests. Successful validation is configuration evidence, not installed serving
/// readiness or proof that Seatbelt has been applied.
pub fn validate_startup(d: DaemonId, args: &DaemonArgs, context: StartupContext) -> EnclaveResult<()> {
    if !args.dev_same_uid && context.effective_uid != d.uid() {
        fail!(EPERM, "WRONG_DAEMON_UID", "{d} must run as uid {} (got {})", d.uid(), context.effective_uid);
    }
    if args.simulated_hardware {
        if !args.dev_same_uid { fail!(EPERM, "SIMULATION_REQUIRES_DEV_MODE"); }
        if DaemonId::from_uid(context.effective_uid).is_some() {
            fail!(EPERM, "SIMULATION_FORBIDDEN_UID");
        }
        if args.socket_dir == Path::new(DEFAULT_SOCKET_DIR) {
            fail!(EPERM, "SIMULATION_FORBIDDEN_SOCKET_DIR");
        }
    }
    if context.require_sandbox && !args.dev_same_uid {
        let path = args.sandbox_profile.as_ref().ok_or_else(||
            err!(EPERM, "SANDBOX_PROFILE_REQUIRED", "{d} must specify --sandbox-profile in production release builds"))?;
        sandbox::read_profile(path, context.profile_owner_uid)?;
    }
    Ok(())
}

/// Refuse wrong identities and missing/unsafe production confinement before any
/// serving socket is bound. Runtime observations cannot be overridden by argv.
pub fn check_identity(d: DaemonId, args: &DaemonArgs) -> EnclaveResult<()> {
    // Signed host floors may have changed args since early parsing. Refuse a
    // selected target/profile mismatch again before any serving initialization.
    args.bind_deployment_for_daemon(d)?;
    validate_startup(d, args, StartupContext {
        effective_uid: ipc::geteuid(),
        require_sandbox: cfg!(target_os = "macos") && !cfg!(test) && !cfg!(debug_assertions),
        profile_owner_uid: 0,
    })
}

/// Start the RSS watchdog: if the process ever exceeds its ceiling it calls
/// `on_breach` (zeroize) and exits with [`EXIT_RSS_CEILING`].
pub fn spawn_rss_watchdog(d: DaemonId, period: Duration, on_breach: impl Fn() + Send + 'static) {
    let ceiling = MemoryCeiling::for_daemon(d);
    let _ = std::thread::Builder::new()
        .name("rss-watchdog".into())
        .stack_size(64 * 1024)
        .spawn(move || loop {
            std::thread::sleep(period);
            if let Err(breach) = ceiling.check() {
                on_breach();
                // A silent exit is undiagnosable: name the measurement on
                // stderr (the daemon log) before failing closed.
                eprintln!("fatal: {breach}");
                std::process::exit(EXIT_RSS_CEILING);
            }
        });
}

/// Bind, harden and serve a typed handler until SIGTERM/SIGINT.
pub fn run_service<Req, Resp, H>(
    d: DaemonId,
    args: &DaemonArgs,
    handler: H,
    on_breach: impl Fn() + Send + 'static,
) -> EnclaveResult<()>
where
    Req: DeserializeOwned + Send + 'static,
    Resp: Serialize + Send + 'static,
    H: Fn(&PeerCredentials, Req) -> EnclaveResult<Resp> + Send + Sync + 'static,
{
    run_service_with_startup(d, args, || Ok((handler, ())), on_breach)
}

/// Apply identity, code-pin, hardening and confinement before constructing any
/// service-owned listener or resource. The initializer returns its handler and
/// an ownership guard retained until serving ends, including failed IPC binding.
/// Existing callers can keep using [`run_service`].
pub fn run_service_with_startup<Req, Resp, H, G, Init>(
    d: DaemonId,
    args: &DaemonArgs,
    initialize: Init,
    on_breach: impl Fn() + Send + 'static,
) -> EnclaveResult<()>
where
    Req: DeserializeOwned + Send + 'static,
    Resp: Serialize + Send + 'static,
    H: Fn(&PeerCredentials, Req) -> EnclaveResult<Resp> + Send + Sync + 'static,
    Init: FnOnce() -> EnclaveResult<(H, G)>,
{
    check_identity(d, args)?;
    // Ad-hoc signed install (no Team ID): peers authenticate by pinned cdhash.
    if cfg!(target_os = "macos")
        && !args.dev_same_uid
        && crate::codesign::signing_mode() == crate::codesign::SigningMode::LocalPins
    {
        crate::codesign::pins::require(&d.launchd_label())?;
    }
    let hardened = crate::resource::harden_process();
    if !hardened && !args.dev_same_uid {
        fail!(EPERM, "HARDENING_FAILED", "RLIMIT_CORE / PT_DENY_ATTACH");
    }
    // In-process Darwin Seatbelt sandboxing (GAP-50)
    if let Some(ref sb_path) = args.sandbox_profile {
        sandbox::init_sandbox_with_owner(
            sb_path,
            if args.dev_same_uid { ipc::geteuid() } else { 0 },
        )?;
    }
    let (handler, _owned_resources) = initialize()?;
    // Zero-downtime listener FD inheritance via SCM_RIGHTS (GAP-63)
    let listener = if let Some(fd) = args.inherit_listener_fd {
        ipc::inherit_listener(fd)?
    } else {
        ipc::bind(&args.socket_path(d), args.socket_access(d))?
    };
    spawn_rss_watchdog(d, Duration::from_millis(500), on_breach);
    let stop = Arc::new(AtomicBool::new(false));
    install_signal_flag(stop.clone());
    // GAP-39: per-daemon frame cap, per-UID quota, in-flight budget, deadline.
    let limits = ipc::ServeLimits::for_daemon(d, args.dev_same_uid);
    let r = ipc::serve_with::<Req, Resp, H>(
        listener,
        args.peer_policy(d),
        limits,
        Arc::new(ipc::ServeStats::default()),
        Arc::new(handler),
        stop,
    );
    let _ = std::fs::remove_file(args.socket_path(d));
    r
}

static STOP_FLAG: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();

extern "C" fn on_signal(_: libc::c_int) {
    if let Some(f) = STOP_FLAG.get() {
        f.store(true, Ordering::SeqCst);
    }
}

/// Set `flag` on SIGTERM / SIGINT (async-signal-safe store only).
pub fn install_signal_flag(flag: Arc<AtomicBool>) {
    let _ = STOP_FLAG.set(flag);
    // SAFETY: the handler only performs an atomic store (async-signal-safe).
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
    }
}

/// Print a fatal startup error and exit non-zero (fail closed).
pub fn exit_with(e: &crate::EnclaveError) -> ! {
    eprintln!("fatal: {e}");
    std::process::exit(1)
}

/// Resolve a path argument relative to the socket directory if not absolute.
pub fn resolve(base: &Path, p: &str) -> PathBuf {
    let pb = PathBuf::from(p);
    if pb.is_absolute() {
        pb
    } else {
        base.join(pb)
    }
}

/// Native in-process Darwin Seatbelt sandboxing (GAP-50).
pub mod sandbox {
    use crate::error::EnclaveResult;
    use std::path::Path;

    #[cfg(target_os = "macos")]
    use crate::{err, fail};
    #[cfg(target_os = "macos")]
    use std::ffi::{CStr, CString};
    #[cfg(target_os = "macos")]
    use std::os::raw::{c_char, c_int};

    #[cfg(target_os = "macos")]
    extern "C" {
        fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
        fn sandbox_free_error(errorbuf: *mut c_char);
    }

    /// Bounded trusted profile loading. Never follow the final path component,
    /// accept mutable profile files, or interpret a supplied path as a built-in
    /// sandbox name. The profile text is installed by root in production.
    pub fn read_profile(profile_path: &Path, owner_uid: u32) -> EnclaveResult<Vec<u8>> {
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        const MAX_PROFILE: u64 = 1024 * 1024;
        if !profile_path.is_absolute() || profile_path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            crate::fail!(EPERM, "SANDBOX_PATH_INVALID");
        }
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let parent = profile_path.parent().ok_or_else(|| crate::err!(EPERM, "SANDBOX_PATH_INVALID"))?;
        // Original traversal must be root-provisioned too: otherwise an attacker
        // could redirect a symlink between opening the file and checking a
        // different canonical parent. Root-owned system aliases (/var etc.) are
        // allowed only along an otherwise immutable root-owned original chain.
        if owner_uid == 0 {
            for original in parent.ancestors() {
                let m = std::fs::symlink_metadata(original).map_err(|e| crate::err!(EPERM, "SANDBOX_PROFILE_DIRECTORY", "{e}"))?;
                if m.uid() != 0 || (!m.file_type().is_symlink() && (!m.is_dir() || m.mode() & 0o022 != 0)) {
                    crate::fail!(EPERM, "SANDBOX_PROFILE_DIRECTORY_INSECURE");
                }
            }
        }
        let resolved = std::fs::canonicalize(parent).map_err(|e| crate::err!(EPERM, "SANDBOX_PROFILE_DIRECTORY", "{e}"))?;
        // Walk the canonical chain through held directory FDs with O_NOFOLLOW.
        // Every production component is checked before descending into it.
        let mut directory = std::fs::OpenOptions::new().read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/").map_err(|e| crate::err!(EPERM, "SANDBOX_PROFILE_DIRECTORY", "{e}"))?;
        for part in resolved.components() {
            let std::path::Component::Normal(part) = part else { continue; };
            use std::os::unix::ffi::OsStrExt;
            let part = std::ffi::CString::new(part.as_bytes()).map_err(|_| crate::err!(EPERM, "SANDBOX_PATH_INVALID"))?;
            let fd = unsafe { libc::openat(directory.as_raw_fd(), part.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
            if fd < 0 { crate::fail!(EPERM, "SANDBOX_PROFILE_DIRECTORY"); }
            let held = unsafe { OwnedFd::from_raw_fd(fd) };
            directory = std::fs::File::from(held);
            if owner_uid == 0 {
                let m = directory.metadata().map_err(|e| crate::err!(EPERM, "SANDBOX_PROFILE_DIRECTORY", "{e}"))?;
                if m.uid() != 0 || m.mode() & 0o022 != 0 { crate::fail!(EPERM, "SANDBOX_PROFILE_DIRECTORY_INSECURE"); }
            }
        }
        let parent_meta = directory.metadata().map_err(|e| crate::err!(EPERM, "SANDBOX_PROFILE_DIRECTORY", "{e}"))?;
        if parent_meta.uid() != owner_uid || parent_meta.mode() & 0o022 != 0 { crate::fail!(EPERM, "SANDBOX_PROFILE_DIRECTORY_INSECURE"); }
        use std::os::unix::ffi::OsStrExt;
        let name = profile_path.file_name().ok_or_else(|| crate::err!(EPERM, "SANDBOX_PATH_INVALID"))?;
        let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| crate::err!(EPERM, "SANDBOX_PATH_INVALID"))?;
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK) };
        if fd < 0 { crate::fail!(EPERM, "SANDBOX_PROFILE_OPEN"); }
        let file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
        let m = file.metadata().map_err(|e| crate::err!(EPERM, "SANDBOX_PROFILE_METADATA", "{e}"))?;
        if !m.is_file() || m.uid() != owner_uid || m.mode() & 0o022 != 0 || m.len() == 0 || m.len() > MAX_PROFILE {
            crate::fail!(EPERM, "SANDBOX_PROFILE_INSECURE");
        }
        let mut bytes = Vec::new();
        file.take(MAX_PROFILE + 1).read_to_end(&mut bytes).map_err(|e| crate::err!(EPERM, "SANDBOX_PROFILE_READ", "{e}"))?;
        if bytes.len() as u64 != m.len() || bytes.contains(&0) || std::str::from_utf8(&bytes).is_err() {
            crate::fail!(EPERM, "SANDBOX_PROFILE_INVALID");
        }
        Ok(bytes)
    }

    /// Apply a root-provisioned profile. The platform call compiles the actual
    /// profile text with flags=0; SANDBOX_NAMED accepts built-in names, not files.
    pub fn init_sandbox_in_process(profile_path: &Path) -> EnclaveResult<()> {
        init_sandbox_with_owner(profile_path, 0)
    }

    /// Apply a profile whose trusted owner was established by the caller. Normal
    /// production callers always use root; private development fixtures use their
    /// own UID and do not establish installed confinement or identity evidence.
    pub fn init_sandbox_with_owner(profile_path: &Path, owner_uid: u32) -> EnclaveResult<()> {
        let bytes = read_profile(profile_path, owner_uid)?;
        #[cfg(target_os = "macos")]
        {
            let c_profile = CString::new(bytes).map_err(|e| err!(EINVAL, "SANDBOX_PARAM_ERR", "{e}"))?;
            let mut errorbuf: *mut c_char = std::ptr::null_mut();

            // SAFETY: FFI to Apple Darwin libsystem_sandbox.dylib.
            let rc = unsafe { sandbox_init(c_profile.as_ptr(), 0, &mut errorbuf) };
            if rc != 0 {
                let msg = if !errorbuf.is_null() {
                    let err_str =
                        unsafe { CStr::from_ptr(errorbuf).to_string_lossy().into_owned() };
                    unsafe { sandbox_free_error(errorbuf) };
                    err_str
                } else {
                    format!("errno {rc}")
                };
                fail!(EPERM, "SANDBOX_INIT_FAILED", "sandbox_init failed: {msg}");
            }
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = bytes;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args() {
        let a = DaemonArgs::parse(
            [
                "x",
                "--socket-dir",
                "/tmp/s",
                "--profile",
                "L3",
                "--dev-same-uid",
                "--no-audit",
                "--repo",
                "/r",
            ]
            .map(String::from),
        )
        .unwrap();
        assert_eq!(a.profile, Profile::L3);
        assert!(a.dev_same_uid && a.audit_dir.is_none());
        assert_eq!(a.get("repo"), Some("/r"));
        assert_eq!(
            a.socket_path(DaemonId::ZkAuditor),
            PathBuf::from("/tmp/s/zk/zk.sock")
        );
        assert!(DaemonArgs::parse(["x", "--profile"].map(String::from)).is_err());
    }

    #[test]
    fn simulation_never_in_production_layout() {
        // Without dev mode the flag is rejected at parse time.
        assert!(
            DaemonArgs::parse(["x", "--simulated-hardware"].map(String::from))
                .unwrap_err()
                .is("SIMULATION_REQUIRES_DEV_MODE")
        );
        // Dev mode on the production socket directory is still refused.
        let a =
            DaemonArgs::parse(["x", "--dev-same-uid", "--simulated-hardware"].map(String::from))
                .unwrap();
        let e = a.check_simulation_allowed().unwrap_err();
        assert!(e.is("SIMULATION_FORBIDDEN_SOCKET_DIR") || e.is("SIMULATION_FORBIDDEN_UID"));
        let ok = DaemonArgs::parse(
            [
                "x",
                "--socket-dir",
                "/tmp/dev",
                "--dev-same-uid",
                "--simulated-hardware",
            ]
            .map(String::from),
        )
        .unwrap();
        if DaemonId::from_uid(ipc::geteuid()).is_none() {
            ok.check_simulation_allowed().unwrap();
        }
    }

    #[test]
    fn production_identity_enforced() {
        let a = DaemonArgs::parse(["x"].map(String::from)).unwrap();
        if ipc::geteuid() != 703 {
            assert!(check_identity(DaemonId::CustodyVault, &a)
                .unwrap_err()
                .is("WRONG_DAEMON_UID"));
        }
    }
}

#[cfg(test)]
mod startup_resource_tests {
    use super::*;
    #[test]
    fn f38_production_identity_refusal_never_constructs_service_resources() {
        for daemon in DaemonId::ALL {
            if ipc::geteuid() == daemon.uid() {
                continue;
            }
            let args = DaemonArgs::parse(["daemon", "--profile", "L2"].map(String::from)).unwrap();
            let called = AtomicBool::new(false);
            let error = run_service_with_startup::<serde_json::Value, serde_json::Value, _, _, _>(
                daemon,
                &args,
                || {
                    called.store(true, Ordering::SeqCst);
                    Ok((
                        |_: &PeerCredentials, value: serde_json::Value| Ok(value),
                        (),
                    ))
                },
                || {},
            )
            .unwrap_err();
            assert!(error.is("WRONG_DAEMON_UID"));
            assert!(!called.load(Ordering::SeqCst));
        }
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn f38_confined_initializer_owns_listener_until_failed_ipc_bind_then_drops_it() {
        use std::os::unix::fs::PermissionsExt;
        if let Some(root) = std::env::var_os("MCPMAC_STARTUP_RESOURCE_CHILD") {
            let root = PathBuf::from(root);
            let mut args = DaemonArgs::parse(
                ["daemon", "--dev-same-uid", "--profile", "L2"].map(String::from),
            )
            .unwrap();
            args.socket_dir = root.join("not-directory");
            args.sandbox_profile = Some(root.join("profile.sb"));
            let dropped = Arc::new(AtomicBool::new(false));
            let local = dropped.clone();
            let address = std::cell::Cell::new(None);
            struct OwnedSocket {
                socket: Option<std::net::UdpSocket>,
                dropped: Arc<AtomicBool>,
            }
            impl Drop for OwnedSocket {
                fn drop(&mut self) {
                    drop(self.socket.take());
                    self.dropped.store(true, Ordering::SeqCst);
                }
            }
            let error = run_service_with_startup::<serde_json::Value, serde_json::Value, _, _, _>(
                DaemonId::SwarmSync,
                &args,
                || {
                    assert!(
                        std::fs::read(root.join("forbidden")).is_err(),
                        "initializer must run after actual sandbox application"
                    );
                    assert_eq!(std::fs::read(root.join("allowed")).unwrap(), b"allowed");
                    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                    address.set(Some(socket.local_addr().unwrap()));
                    Ok((
                        |_: &PeerCredentials, value: serde_json::Value| Ok(value),
                        OwnedSocket {
                            socket: Some(socket),
                            dropped: local,
                        },
                    ))
                },
                || {},
            )
            .unwrap_err();
            assert!(!error.reason.is_empty());
            assert!(dropped.load(Ordering::SeqCst));
            let socket =
                std::net::UdpSocket::bind(address.get().expect("initializer ran")).unwrap();
            drop(socket);
            return;
        }
        let root = std::env::temp_dir().join(format!("startup-owned-{:x}", crate::rng::u64()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        std::fs::write(root.join("allowed"), b"allowed").unwrap();
        std::fs::write(root.join("forbidden"), b"forbidden").unwrap();
        std::fs::write(root.join("not-directory"), b"ordinary file").unwrap();
        let executable = std::env::current_exe().unwrap();
        let mut profile=format!("(version 1)\n(deny default)\n(import \"bsd.sb\")\n(allow process-exec (literal \"{}\"))\n(allow file-read* (literal \"{}\") (subpath \"/System\") (subpath \"/usr/lib\") (literal \"{}/allowed\") (literal \"{}/profile.sb\"))\n(allow file-read-metadata)\n(allow network-bind (local udp \"localhost:*\"))\n",executable.display(),executable.display(),root.display(),root.display());
        for directory in root.ancestors() {
            use std::fmt::Write;
            writeln!(
                profile,
                "(allow file-read-data file-read-metadata (literal \"{}\"))",
                directory.display()
            )
            .unwrap();
        }
        std::fs::write(root.join("profile.sb"), profile).unwrap();
        std::fs::set_permissions(
            root.join("profile.sb"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let output=std::process::Command::new(executable).args(["--exact","runtime::startup_resource_tests::f38_confined_initializer_owns_listener_until_failed_ipc_bind_then_drops_it","--nocapture"]).env("MCPMAC_STARTUP_RESOURCE_CHILD",&root).output().unwrap();
        let result = output.status.success();
        let _ = std::fs::remove_dir_all(root);
        assert!(
            result,
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
