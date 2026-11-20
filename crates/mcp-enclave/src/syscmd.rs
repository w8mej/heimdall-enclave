//! Pinned system tools and a scrubbed process environment for privileged
//! operator verbs (DEFECT-F-90).
//!
//! The deploy verbs run as root. Every program they launch is named by an
//! absolute path under the SIP-protected system volume, and every child starts
//! from an empty environment with a fixed `PATH`, so neither the caller's
//! current directory nor an inherited `PATH` (`sudo -E`, a root shell that
//! kept the user's environment, an MDM agent) can substitute a binary.
//!
//! All launches go through a [`Runner`] so tests can record the exact command
//! without executing privileged tools.

use std::io;
use std::path::Path;
use std::process::{Command, ExitStatus, Output};

/// `PATH` given to every child (and therefore to the packaging scripts).
/// System directories only, all on the sealed system volume.
pub const SAFE_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// A system tool launched by the operator CLI, pinned to its absolute path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    /// POSIX shell used to run the embedded packaging scripts.
    Sh,
    /// Packet Filter control.
    Pfctl,
    /// launchd control.
    Launchctl,
    /// FileVault status.
    Fdesetup,
    /// System Integrity Protection status.
    Csrutil,
    /// File status (console owner).
    Stat,
    /// Kernel state (fallback memory probe).
    Sysctl,
    /// Disk image attach/detach.
    Hdiutil,
    /// Extended attributes.
    Xattr,
}

impl Tool {
    /// Absolute path of the tool on macOS.
    pub const fn path(self) -> &'static str {
        match self {
            Tool::Sh => "/bin/sh",
            Tool::Pfctl => "/sbin/pfctl",
            Tool::Launchctl => "/bin/launchctl",
            Tool::Fdesetup => "/usr/bin/fdesetup",
            Tool::Csrutil => "/usr/bin/csrutil",
            Tool::Stat => "/usr/bin/stat",
            Tool::Sysctl => "/usr/sbin/sysctl",
            Tool::Hdiutil => "/usr/bin/hdiutil",
            Tool::Xattr => "/usr/bin/xattr",
        }
    }

    /// Every pinned tool, for exhaustive tests.
    pub const ALL: [Tool; 9] = [
        Tool::Sh,
        Tool::Pfctl,
        Tool::Launchctl,
        Tool::Fdesetup,
        Tool::Csrutil,
        Tool::Stat,
        Tool::Sysctl,
        Tool::Hdiutil,
        Tool::Xattr,
    ];
}

/// Build a command for `tool`: absolute program path, empty environment
/// except `PATH` = [`SAFE_PATH`] and `LC_ALL=C` (stable, parseable output).
pub fn command(tool: Tool) -> Command {
    let mut cmd = Command::new(tool.path());
    cmd.env_clear().env("PATH", SAFE_PATH).env("LC_ALL", "C");
    cmd
}

/// Build a command that runs an embedded shell script with `/bin/sh -c`.
///
/// The script body comes from the binary, never from the file system. `argv0`
/// becomes the script's `$0`; `args` become `$1..`. The working directory is
/// `/` so nothing in the script can resolve relative to the caller's
/// directory. `extra_env` is applied on top of the scrubbed environment.
pub fn script_command(
    script: &str,
    argv0: &str,
    args: &[&str],
    extra_env: &[(&str, &str)],
) -> Command {
    let mut cmd = command(Tool::Sh);
    cmd.arg("-c").arg(script).arg(argv0).args(args);
    cmd.current_dir(Path::new("/"));
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd
}

/// Executes commands. The system runner spawns them; tests record them.
pub trait Runner {
    /// Run to completion with inherited stdio.
    fn status(&self, cmd: Command) -> io::Result<ExitStatus>;
    /// Run to completion capturing stdout and stderr.
    fn output(&self, cmd: Command) -> io::Result<Output>;
}

/// The real runner.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRunner;

impl Runner for SystemRunner {
    fn status(&self, mut cmd: Command) -> io::Result<ExitStatus> {
        cmd.status()
    }
    fn output(&self, mut cmd: Command) -> io::Result<Output> {
        cmd.output()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tool_is_absolute_and_exists_on_this_host() {
        for t in Tool::ALL {
            let p = Path::new(t.path());
            assert!(p.is_absolute(), "{t:?} not absolute");
            #[cfg(target_os = "macos")]
            assert!(p.exists(), "{t:?} missing at {}", t.path());
        }
    }

    #[test]
    fn command_clears_environment_and_pins_path() {
        std::env::set_var("MCPMAC_F90_UNIT_CANARY", "leak");
        let out = command(Tool::Sh)
            .arg("-c")
            .arg(
                "printf '%s|%s|%s' \"$PATH\" \"${MCPMAC_F90_UNIT_CANARY-unset}\" \"${HOME-unset}\"",
            )
            .output()
            .expect("spawn /bin/sh");
        let s = String::from_utf8_lossy(&out.stdout);
        assert_eq!(s, format!("{SAFE_PATH}|unset|unset"));
    }

    #[test]
    fn script_command_runs_body_from_memory_in_root_dir() {
        let cmd = script_command(
            "printf '%s %s' \"$0\" \"$(pwd)\"",
            "embedded/x.sh",
            &[],
            &[],
        );
        assert_eq!(cmd.get_program(), "/bin/sh");
        assert_eq!(cmd.get_current_dir(), Some(Path::new("/")));
        let out = SystemRunner.output(cmd).expect("spawn");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "embedded/x.sh /");
    }
}
