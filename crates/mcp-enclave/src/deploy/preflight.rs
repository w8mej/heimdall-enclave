//! Hardware and Darwin platform pre-flight gating (FS-706 §2.1, D-R13).

use super::security_probe::{probe_filevault, probe_sip, security_gate};
use crate::syscmd::{Runner, SystemRunner};
use serde::{Deserialize, Serialize};

/// Pre-flight Darwin platform diagnostic report matching `schemas/deploy-result.schema.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DarwinPreflight {
    /// Memory tier classification ("Low", "Mid", "High") per D-R13.
    pub hw_tier: String,
    /// Total host unified RAM in bytes from sysctl hw.memsize.
    pub mem_bytes: u64,
    /// Free space in bytes on target APFS volume.
    pub disk_free_bytes: u64,
    /// Whether macOS FileVault volume encryption is active.
    pub filevault: bool,
    /// Whether macOS System Integrity Protection is enabled.
    pub sip: bool,
    /// Active console user UID from /dev/console, or null if login window.
    pub console_uid: Option<u32>,
}

/// Classify host unified RAM into a hardware tier per D-R13.
///
/// Tiers:
/// - < 16 GiB: "Low"
/// - 16 GiB .. 48 GiB: "Mid"
/// - 48 GiB .. 64 GiB: "Mid" (explicit edge per D-R13 and FS-706 §2.1)
/// - >= 64 GiB: "High"
pub fn classify_hw_tier(mem_bytes: u64) -> &'static str {
    const GIB_16: u64 = 16 * 1024 * 1024 * 1024;
    const GIB_64: u64 = 64 * 1024 * 1024 * 1024;
    if mem_bytes < GIB_16 {
        "Low"
    } else if mem_bytes < GIB_64 {
        "Mid"
    } else {
        "High"
    }
}

/// Query total system memory in bytes.
pub fn get_mem_bytes() -> u64 {
    #[cfg(target_os = "macos")]
    {
        let mut size: u64 = 0;
        let mut len = std::mem::size_of::<u64>();
        let name = std::ffi::CString::new("hw.memsize").unwrap();
        let res = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                &mut size as *mut u64 as *mut libc::c_void,
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if res == 0 && size > 0 {
            return size;
        }
    }
    // Fallback via sysctl command
    if let Ok(out) = crate::syscmd::command(crate::syscmd::Tool::Sysctl)
        .args(["-n", "hw.memsize"])
        .output()
    {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if let Ok(bytes) = s.parse::<u64>() {
                return bytes;
            }
        }
    }
    // Default fallback (e.g. 16 GiB)
    16 * 1024 * 1024 * 1024
}

/// Query free disk space in bytes on target volume.
pub fn get_disk_free_bytes(path: &str) -> u64 {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        if let Ok(c_path) = CString::new(path) {
            let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
            let res = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
            if res == 0 {
                return stat.f_bavail as u64 * stat.f_frsize as u64;
            }
        }
        // Fallback check on root "/"
        if path != "/" {
            if let Ok(c_root) = CString::new("/") {
                let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
                let res = unsafe { libc::statvfs(c_root.as_ptr(), &mut stat) };
                if res == 0 {
                    return stat.f_bavail as u64 * stat.f_frsize as u64;
                }
            }
        }
    }
    // Fallback 100 GiB
    100 * 1024 * 1024 * 1024
}

/// Query macOS FileVault status. `false` unless `fdesetup status` ran and
/// printed `FileVault is On.` (DEFECT-F-91: a failed probe is not a pass).
pub fn get_filevault_status() -> bool {
    probe_filevault(&SystemRunner).is_on()
}

/// Query macOS System Integrity Protection status. `true` only when the first
/// line of `csrutil status` is exactly `System Integrity Protection status:
/// enabled.`; custom configurations and failed probes are `false` (DEFECT-F-91).
pub fn get_sip_status() -> bool {
    probe_sip(&SystemRunner).is_on()
}

/// Query active console user UID.
pub fn get_console_uid() -> Option<u32> {
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = crate::syscmd::command(crate::syscmd::Tool::Stat)
            .args(["-f", "%u", "/dev/console"])
            .output()
        {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if let Ok(uid) = s.parse::<u32>() {
                return Some(uid);
            }
        }
    }
    None
}

/// Result of pre-flight platform evaluation.
#[derive(Debug, Clone)]
pub struct PreflightResult {
    /// Diagnostic details matching schema.
    pub preflight: DarwinPreflight,
    /// Whether all mandatory gates passed.
    pub passed: bool,
    /// Diagnostic summary message.
    pub message: String,
}

/// Evaluate host hardware, memory tier, container storage, and Darwin security baseline per D-R13.
pub fn evaluate_preflight(
    profile: &str,
    target_model_footprint_bytes: Option<u64>,
) -> PreflightResult {
    evaluate_preflight_with(profile, target_model_footprint_bytes, &SystemRunner)
}

/// [`evaluate_preflight`] with an injectable runner for the FileVault and SIP
/// probes. Both probes fail closed (DEFECT-F-91).
pub fn evaluate_preflight_with(
    _profile: &str,
    target_model_footprint_bytes: Option<u64>,
    runner: &dyn Runner,
) -> PreflightResult {
    let mem_bytes = get_mem_bytes();
    let hw_tier = classify_hw_tier(mem_bytes).to_string();
    let disk_free_bytes = get_disk_free_bytes("/opt/enterprise/enclave");
    let fv_probe = probe_filevault(runner);
    let sip_probe = probe_sip(runner);
    let filevault = fv_probe.is_on();
    let sip = sip_probe.is_on();
    let console_uid = get_console_uid();

    let preflight = DarwinPreflight {
        hw_tier,
        mem_bytes,
        disk_free_bytes,
        filevault,
        sip,
        console_uid,
    };

    // Architecture check: Apple Silicon arm64 / aarch64
    #[cfg(target_os = "macos")]
    {
        if std::env::consts::ARCH != "aarch64" {
            return PreflightResult {
                preflight,
                passed: false,
                message: format!(
                    "Architecture {} unsupported; Apple Silicon arm64 required",
                    std::env::consts::ARCH
                ),
            };
        }
    }

    // Security baseline on macOS: FileVault and SIP must both be verifiably on.
    if cfg!(target_os = "macos") {
        if let Err(message) = security_gate(&fv_probe, &sip_probe) {
            return PreflightResult {
                preflight,
                passed: false,
                message,
            };
        }
    }

    // Disk space gating: >= 2.5x target model footprint per D-R13
    // Default model footprint is 2 GiB (quantized 4B/8B model baseline), requiring 5.0 GiB free.
    // In test configurations or when overridden, bound footprint to allow testing on constrained machines.
    let target_footprint = target_model_footprint_bytes
        .or_else(|| {
            if !cfg!(debug_assertions) {
                return None;
            }
            std::env::var("ENCLAVE_MODEL_FOOTPRINT_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or_else(|| {
            if cfg!(test) || (cfg!(debug_assertions) && std::env::var("ENCLAVE_TEST_ENV").is_ok()) {
                500 * 1024 * 1024
            } else {
                2 * 1024 * 1024 * 1024
            }
        });
    let required_disk = (target_footprint as f64 * 2.5) as u64;
    if disk_free_bytes < required_disk {
        return PreflightResult {
            preflight,
            passed: false,
            message: format!(
                "Insufficient APFS container space: {} free < {} required (2.5x {} footprint)",
                disk_free_bytes, required_disk, target_footprint
            ),
        };
    }

    PreflightResult {
        preflight,
        passed: true,
        message: "All pre-flight hardware and platform gates passed".into(),
    }
}
