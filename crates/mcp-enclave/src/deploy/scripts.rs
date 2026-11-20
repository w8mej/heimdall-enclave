//! Packaging scripts embedded in the binary and the execution context the
//! root deploy verbs run them in (DEFECT-F-90).
//!
//! `install`, `purge` and `verify` used to run `packaging/macos/*.sh`
//! resolved relative to the caller's working directory, so `sudo mcp-enclave
//! deploy …` from a user-owned checkout executed that user's file as root.
//! The scripts are now compiled into the (root-owned, code-signed) binary and
//! run with `/bin/sh -c <embedded body>` from `/`, with a scrubbed
//! environment. Nothing in the current directory is consulted.

use crate::syscmd::{self, Runner};
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

/// `packaging/macos/install.sh` as built into this binary.
pub const INSTALL_SH: &str = include_str!("../../../../packaging/macos/install.sh");
/// `packaging/macos/uninstall.sh` as built into this binary.
pub const UNINSTALL_SH: &str = include_str!("../../../../packaging/macos/uninstall.sh");
/// `packaging/macos/verify-install.sh` as built into this binary.
pub const VERIFY_INSTALL_SH: &str = include_str!("../../../../packaging/macos/verify-install.sh");

/// An embedded packaging script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Script {
    /// Install and bootstrap from a build distribution.
    Install,
    /// Undo the install.
    Uninstall,
    /// Post-install exit-criteria checks.
    VerifyInstall,
}

impl Script {
    /// Embedded script body.
    pub const fn body(self) -> &'static str {
        match self {
            Script::Install => INSTALL_SH,
            Script::Uninstall => UNINSTALL_SH,
            Script::VerifyInstall => VERIFY_INSTALL_SH,
        }
    }

    /// `$0` the script sees (names the embedded origin in its messages).
    pub const fn argv0(self) -> &'static str {
        match self {
            Script::Install => "mcp-enclave(embedded)/install.sh",
            Script::Uninstall => "mcp-enclave(embedded)/uninstall.sh",
            Script::VerifyInstall => "mcp-enclave(embedded)/verify-install.sh",
        }
    }
}

/// Everything a root deploy verb needs from the host. Production code uses
/// [`DeployCtx::system`]; tests substitute the root bit, the runner and the
/// pf paths so nothing privileged is executed.
pub struct DeployCtx<'a> {
    /// Effective UID is 0.
    pub is_root: bool,
    /// Process launcher.
    pub runner: &'a dyn Runner,
    /// Directory that receives the rendered pf anchors.
    pub anchors_dir: PathBuf,
    /// The pf.conf to patch.
    pub pf_conf: PathBuf,
}

impl std::fmt::Debug for DeployCtx<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeployCtx")
            .field("is_root", &self.is_root)
            .field("anchors_dir", &self.anchors_dir)
            .field("pf_conf", &self.pf_conf)
            .finish_non_exhaustive()
    }
}

impl DeployCtx<'static> {
    /// The real host: euid from the kernel, real processes, `/etc` pf paths.
    pub fn system() -> Self {
        // SAFETY: geteuid has no preconditions and cannot fail.
        let is_root = unsafe { libc::geteuid() } == 0;
        Self {
            is_root,
            runner: &syscmd::SystemRunner,
            anchors_dir: PathBuf::from("/etc/pf.anchors"),
            pf_conf: PathBuf::from("/etc/pf.conf"),
        }
    }
}

/// Run an embedded script through `ctx.runner`.
pub fn run_script(
    ctx: &DeployCtx<'_>,
    script: Script,
    args: &[&str],
    extra_env: &[(&str, &str)],
) -> std::io::Result<ExitStatus> {
    let cmd = syscmd::script_command(script.body(), script.argv0(), args, extra_env);
    if matches!(script, Script::VerifyInstall) {
        // Drain both streams, then keep checker diagnostics off the CLI's
        // machine-readable stdout. A script's text never establishes success.
        use std::io::Write;
        let output = ctx.runner.output(cmd)?;
        let mut diagnostics = std::io::stderr().lock();
        let _ = diagnostics.write_all(&output.stdout);
        let _ = diagnostics.write_all(&output.stderr);
        Ok(output.status)
    } else {
        ctx.runner.status(cmd)
    }
}

/// Resolve the `--dist` directory for `deploy install` to an absolute,
/// canonical path that holds a build (`codesign-pins.json`). The dist is data
/// that install.sh verifies and stages root-owned (DEFECT-F-12); it is never
/// executed from its original location.
pub fn resolve_dist(dist: &str) -> Result<PathBuf, String> {
    let canon = std::fs::canonicalize(Path::new(dist))
        .map_err(|e| format!("INSTALL_DIST_MISSING: --dist {dist}: {e}"))?;
    if !canon.join("codesign-pins.json").is_file() {
        return Err(format!(
            "INSTALL_DIST_MISSING: {} holds no build (codesign-pins.json); run packaging/macos/build.sh",
            canon.display()
        ));
    }
    if canon.to_str().is_none() {
        return Err(format!(
            "INSTALL_DIST_MISSING: {} is not UTF-8",
            canon.display()
        ));
    }
    Ok(canon)
}

/// Install the pf anchors and load them, failing if any step fails.
pub fn load_pf_anchors(ctx: &DeployCtx<'_>) -> Result<(), String> {
    // Snapshot every disk object that install_pf_with publishes. Restore all
    // objects even when rendering/validation fails before kernel activation.
    let paths = [ctx.pf_conf.clone(), ctx.anchors_dir.join(crate::pf::LLM_ISOLATION_ANCHOR), ctx.anchors_dir.join(crate::pf::CAS_SWARM_ANCHOR)];
    let mut previous = Vec::new();
    for path in &paths {
        let state = match std::fs::read(path) {
            Ok(bytes) => Some((bytes, std::fs::metadata(path).map_err(|e| e.to_string())?.permissions())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(format!("PF_CONFIG_READ_FAILED: {e}")),
        };
        previous.push((path, state));
    }
    let restore = |mut reason: String| -> String {
        for (path, state) in &previous {
            let result = match state {
                Some((bytes, permissions)) => enclave_core::fsutil::write_private(path, bytes)
                    .map_err(|e| e.to_string())
                    .and_then(|_| std::fs::set_permissions(path, permissions.clone()).map_err(|e| e.to_string())),
                None => match std::fs::remove_file(path) {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(e) => Err(e.to_string()),
                },
            };
            if let Err(e) = result { reason.push_str(&format!("; PF_CONFIG_RESTORE_FAILED {}: {e}", path.display())); }
        }
        reason
    };
    crate::pf::install_pf_with(&ctx.anchors_dir, &ctx.pf_conf, ctx.runner)
        .map_err(|e| restore(format!("PF_INSTALL_FAILED: {e}")))?;
    let anchor_file = |a: &str| ctx.anchors_dir.join(a).display().to_string();
    let pf_conf = ctx.pf_conf.display().to_string();
    let steps: [Vec<String>; 4] = [
        vec![
            "-a".into(),
            crate::pf::LLM_ISOLATION_ANCHOR.into(),
            "-f".into(),
            anchor_file(crate::pf::LLM_ISOLATION_ANCHOR),
        ],
        vec![
            "-a".into(),
            crate::pf::CAS_SWARM_ANCHOR.into(),
            "-f".into(),
            anchor_file(crate::pf::CAS_SWARM_ANCHOR),
        ],
        vec!["-f".into(), pf_conf],
        vec!["-E".into()],
    ];
    for args in steps {
        let mut cmd = syscmd::command(syscmd::Tool::Pfctl);
        cmd.args(&args);
        match ctx.runner.status(cmd) {
            Ok(s) if s.success() => {}
            Ok(s) => {
                return Err(restore(format!(
                    "PF_LOAD_FAILED: pfctl {} exited {s}",
                    args.join(" ")
                )))
            }
            Err(e) => return Err(restore(format!("PF_LOAD_FAILED: pfctl {}: {e}", args.join(" ")))),
        }
    }
    Ok(())
}
