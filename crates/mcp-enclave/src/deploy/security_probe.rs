//! FileVault and SIP probes for the deploy preflight (DEFECT-F-91).
//!
//! Both probes fail closed: a probe that cannot be launched, exits non-zero,
//! or prints anything other than the exact "on" line is not a pass. SIP is
//! on only when the *first* line of `csrutil status` is exactly
//! `System Integrity Protection status: enabled.` — a custom configuration
//! (`unknown (Custom Configuration).` / `enabled (Custom Configuration).`,
//! followed by per-component `…: enabled` lines) does not pass.

use crate::syscmd::{self, Runner, Tool};

/// The exact line `fdesetup status` prints when FileVault is on.
pub const FILEVAULT_ON_LINE: &str = "FileVault is On.";
/// The exact first line `csrutil status` prints when SIP is fully enabled.
pub const SIP_ENABLED_LINE: &str = "System Integrity Protection status: enabled.";

/// Outcome of one security probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    /// The protection is on.
    On,
    /// The probe ran and the protection is not (fully) on; carries the
    /// observed status line.
    Off(String),
    /// The probe could not produce a verdict (spawn failure, non-zero exit,
    /// unsupported platform). Treated as a failed gate.
    Unavailable(String),
}

impl Probe {
    /// Whether this probe passes the gate.
    pub fn is_on(&self) -> bool {
        matches!(self, Probe::On)
    }
}

fn first_line(stdout: &str) -> &str {
    stdout
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("")
}

/// `csrutil status` stdout → SIP fully enabled.
pub fn parse_sip(stdout: &str) -> bool {
    first_line(stdout) == SIP_ENABLED_LINE
}

/// `fdesetup status` stdout → FileVault on.
pub fn parse_filevault(stdout: &str) -> bool {
    stdout.lines().any(|l| l.trim() == FILEVAULT_ON_LINE)
}

fn run_probe(runner: &dyn Runner, tool: Tool, parse: fn(&str) -> bool) -> Probe {
    if !cfg!(target_os = "macos") {
        return Probe::Unavailable("not macOS".into());
    }
    let mut cmd = syscmd::command(tool);
    cmd.arg("status");
    let out = match runner.output(cmd) {
        Ok(o) => o,
        Err(e) => return Probe::Unavailable(format!("{} status could not run: {e}", tool.path())),
    };
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Probe::Unavailable(format!(
            "{} status exited {}: {}",
            tool.path(),
            out.status,
            err.trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    if parse(&stdout) {
        Probe::On
    } else {
        Probe::Off(first_line(&stdout).to_string())
    }
}

/// Probe SIP with `/usr/bin/csrutil status`.
pub fn probe_sip(runner: &dyn Runner) -> Probe {
    run_probe(runner, Tool::Csrutil, parse_sip)
}

/// Probe FileVault with `/usr/bin/fdesetup status`.
pub fn probe_filevault(runner: &dyn Runner) -> Probe {
    run_probe(runner, Tool::Fdesetup, parse_filevault)
}

/// The D-R13 security gate: both protections must be on.
pub fn security_gate(filevault: &Probe, sip: &Probe) -> Result<(), String> {
    match filevault {
        Probe::On => {}
        Probe::Off(seen) => {
            return Err(format!(
                "FileVault is disabled; FileVault encryption is required per D-R13 (fdesetup: {seen:?})"
            ))
        }
        Probe::Unavailable(why) => {
            return Err(format!("FileVault status could not be verified ({why}); failing closed per D-R13"))
        }
    }
    match sip {
        Probe::On => Ok(()),
        Probe::Off(seen) => Err(format!(
            "System Integrity Protection (SIP) is not fully enabled; SIP is required per D-R13 (csrutil: {seen:?})"
        )),
        Probe::Unavailable(why) => Err(format!(
            "System Integrity Protection status could not be verified ({why}); failing closed per D-R13"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIP_CUSTOM: &str = "System Integrity Protection status: unknown (Custom Configuration).\n\nConfiguration:\n\tApple Internal: disabled\n\tKext Signing: enabled\n\tFilesystem Protections: enabled\n\tDebugging Restrictions: disabled\n\tDTrace Restrictions: enabled\n\tNVRAM Protections: enabled\n\tBaseSystem Verification: enabled\n\nThis is an unsupported configuration, likely to break in the future and leave your machine in an unknown state.\n";
    const SIP_ENABLED_CUSTOM: &str = "System Integrity Protection status: enabled (Custom Configuration).\n\nConfiguration:\n\tDebugging Restrictions: disabled\n";

    #[test]
    fn sip_exact_line_only() {
        assert!(parse_sip("System Integrity Protection status: enabled.\n"));
        assert!(!parse_sip(SIP_CUSTOM), "custom configuration must not pass");
        assert!(!parse_sip(SIP_ENABLED_CUSTOM));
        assert!(!parse_sip(
            "System Integrity Protection status: disabled.\n"
        ));
        assert!(!parse_sip(""));
        assert!(!parse_sip("enabled\n"));
        // The exact line buried below another first line is not accepted.
        assert!(!parse_sip(
            "note: x\nSystem Integrity Protection status: enabled.\n"
        ));
        // The old substring check passed all of these custom outputs.
        assert!(SIP_CUSTOM.contains("enabled") && SIP_ENABLED_CUSTOM.contains("enabled"));
    }

    #[test]
    fn filevault_exact_line_only() {
        assert!(parse_filevault("FileVault is On.\n"));
        assert!(parse_filevault(
            "FileVault is On.\nEncryption in progress: Percent completed = 40\n"
        ));
        assert!(!parse_filevault("FileVault is Off.\n"));
        assert!(!parse_filevault(
            "FileVault is On, but needs to be restarted to finish.\n"
        ));
        assert!(!parse_filevault(
            "Decryption in progress: FileVault is On. soon off\n"
        ));
        assert!(!parse_filevault(""));
    }

    #[test]
    fn gate_requires_both_on_and_fails_closed_on_unavailable() {
        let on = Probe::On;
        let off = Probe::Off("x".into());
        let na = Probe::Unavailable("spawn".into());
        assert!(security_gate(&on, &on).is_ok());
        for (fv, sip) in [(&off, &on), (&on, &off), (&na, &on), (&on, &na), (&na, &na)] {
            assert!(security_gate(fv, sip).is_err(), "{fv:?} {sip:?} passed");
        }
        assert!(security_gate(&on, &na)
            .unwrap_err()
            .contains("failing closed"));
    }
}
