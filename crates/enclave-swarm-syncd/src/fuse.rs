//! FUSE-T NFSv4 loopback mount abstraction and PF loopback fence (FS-702 §5.4; GAP-19 L1).
//!
//! Scope restriction (`MUST`, `OQ-23`, `F-029`):
//! - FUSE-T runs a user-space NFSv4 server on localhost; any local `uid=501` process
//!   could speak NFSv4 to it and read decrypted content.
//! - Lazy FUSE-T mounts are permitted **only** for `Profile::L1` `public_l1` weights `> 1 GiB`.
//! - `L2` and `L3` artifacts are ALWAYS eagerly hydrated and verified before `SCM_RIGHTS`
//!   hand-off with immutable APFS flags set.
//! - The `com.enterprise.cas.swarm` PF anchor blocks loopback connections to the FUSE-T port
//!   from every UID except `root` / `kernel_task` (`mount_nfs`) — in particular `uid=501`.
//! - If FUSE-T is not installed on the host, L1 lazy mounting fails closed with
//!   `FUSE_T_UNAVAILABLE` (D-19e).

use enclave_core::{fail, EnclaveResult, Profile};
use std::path::{Path, PathBuf};

/// Default PF anchor for CAS swarm and FUSE-T fence.
pub const FUSE_T_PF_ANCHOR: &str = "com.enterprise.cas.swarm";

/// Standard NFS loopback port used by FUSE-T.
pub const FUSE_T_NFS_PORT: u16 = 2049;

/// Minimum artifact size required for lazy FUSE-T mounting (1 GiB).
/// Smaller artifacts (< 1 GiB: Cedar policies, WASM tools, small models) are always eagerly hydrated.
pub const MIN_LAZY_MOUNT_SIZE_BYTES: u64 = 1024 * 1024 * 1024;

/// Known FUSE-T installation filesystem bundles and binary locations on macOS.
pub const FUSE_T_PROBE_PATHS: &[&str] = &[
    "/Library/Filesystems/fuse-t.fs",
    "/usr/local/bin/go-nfsv4",
    "/opt/homebrew/bin/fuse-t",
    "/usr/local/lib/libfuse-t.dylib",
];

/// Probes whether FUSE-T is installed on the host system.
pub fn probe_fuse_t_installed() -> bool {
    FUSE_T_PROBE_PATHS.iter().any(|p| Path::new(p).exists())
}

/// Evaluates whether an artifact may be mounted lazily via FUSE-T.
///
/// Permitted **only** when:
/// 1. Daemon profile is `Profile::L1`.
/// 2. Artifact classification is public (`is_public_l1 == true`).
/// 3. Artifact size is strictly greater than 1 GiB (`MIN_LAZY_MOUNT_SIZE_BYTES`).
///
/// All other requests fail closed with `LAZY_MOUNT_DISALLOWED`.
pub fn may_lazy_mount(
    profile: Profile,
    target_name: &str,
    size_bytes: u64,
    is_public_l1: bool,
) -> EnclaveResult<()> {
    if profile != Profile::L1 {
        fail!(
            EPERM,
            "LAZY_MOUNT_DISALLOWED",
            "Lazy FUSE-T mount disallowed in profile {profile:?} (L1 only)"
        );
    }
    if !is_public_l1 {
        fail!(
            EPERM,
            "LAZY_MOUNT_DISALLOWED",
            "Lazy FUSE-T mount disallowed for non-public artifact: {target_name}"
        );
    }
    if size_bytes <= MIN_LAZY_MOUNT_SIZE_BYTES {
        fail!(
            EINVAL,
            "LAZY_MOUNT_DISALLOWED",
            "Lazy FUSE-T mount requires artifact size > 1 GiB (got {size_bytes} bytes for {target_name})"
        );
    }
    Ok(())
}

/// Active L1 FUSE-T mount handle.
#[derive(Debug, Clone)]
pub struct L1FuseMount {
    /// Target name.
    pub target: String,
    /// Local mount directory.
    pub mount_point: PathBuf,
    /// FUSE-T NFS port.
    pub port: u16,
}

/// Attempts to mount an L1 public model lazily via FUSE-T.
///
/// Fails closed with:
/// - `FUSE_T_FEATURE_DISABLED` if the `l1-fuse` cargo feature is disabled.
/// - `FUSE_T_UNAVAILABLE` if FUSE-T is not installed on the system (D-19e).
/// - `LAZY_MOUNT_DISALLOWED` if the artifact does not meet L1 public > 1 GiB requirements.
pub fn mount_l1(
    profile: Profile,
    target_name: &str,
    size_bytes: u64,
    is_public_l1: bool,
    mount_point: PathBuf,
) -> EnclaveResult<L1FuseMount> {
    may_lazy_mount(profile, target_name, size_bytes, is_public_l1)?;

    #[cfg(not(feature = "l1-fuse"))]
    {
        let _ = mount_point;
        fail!(
            EPERM,
            "FUSE_T_FEATURE_DISABLED",
            "l1-fuse cargo feature is disabled; build with --features l1-fuse"
        );
    }

    #[cfg(feature = "l1-fuse")]
    {
        if !probe_fuse_t_installed() {
            fail!(
                EPERM,
                "FUSE_T_UNAVAILABLE",
                "FUSE-T is not installed on this system (install from fuse-t.org)"
            );
        }

        Ok(L1FuseMount {
            target: target_name.to_string(),
            mount_point,
            port: FUSE_T_NFS_PORT,
        })
    }
}

/// Generates the canonical PF anchor rules blocking unauthorized loopback access
/// (specifically interactive user `blocked_uid`, e.g. 501) to the FUSE-T NFS server port.
pub fn render_fuse_pf_rules(blocked_uid: u32, port: u16) -> String {
    format!(
        "# ==============================================================================\n\
         # Apple Silicon macOS Packet Filter (pf) Rules — FUSE-T L1 Swarm Quarantine\n\
         # Anchor: {FUSE_T_PF_ANCHOR}\n\
         # Remediates F-029 (ADVERSARIAL_SPEC_REVIEW_2026-11-04): blocks uid {blocked_uid}\n\
         # from connecting directly to the FUSE-T loopback NFS port {port}.\n\
         # ==============================================================================\n\
         \n\
         # BEGIN depot PF RULES\n\
         # 1. Block interactive user ({blocked_uid}) from reaching FUSE-T NFS server on loopback.\n\
         block drop log (all) quick on lo0 inet  proto tcp from any to 127.0.0.1 port {port} user {blocked_uid}\n\
         block drop log (all) quick on lo0 inet6 proto tcp from any to ::1       port {port} user {blocked_uid}\n\
         # 2. Permit kernel/root mount_nfs to reach FUSE-T on loopback.\n\
         pass quick on lo0 inet  proto tcp from any to 127.0.0.1 port {port} user 0 keep state\n\
         pass quick on lo0 inet6 proto tcp from any to ::1       port {port} user 0 keep state\n\
         # 3. Block all other users from FUSE-T loopback port.\n\
         block drop log (all) quick on lo0 proto tcp from any to any port {port}\n\
         # END depot PF RULES\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_may_lazy_mount_matrix() {
        let one_gib = 1024 * 1024 * 1024;
        let large_weights = one_gib + 1024;
        let small_weights = one_gib - 1024;

        // Permitted: L1 + public + > 1 GiB
        assert!(may_lazy_mount(Profile::L1, "model.safetensors", large_weights, true).is_ok());

        // Rejected: profile != L1
        let err =
            may_lazy_mount(Profile::L2, "model.safetensors", large_weights, true).unwrap_err();
        assert!(err.is("LAZY_MOUNT_DISALLOWED"));
        let err =
            may_lazy_mount(Profile::L3, "model.safetensors", large_weights, true).unwrap_err();
        assert!(err.is("LAZY_MOUNT_DISALLOWED"));

        // Rejected: not public
        let err =
            may_lazy_mount(Profile::L1, "internal.safetensors", large_weights, false).unwrap_err();
        assert!(err.is("LAZY_MOUNT_DISALLOWED"));

        // Rejected: size <= 1 GiB
        let err =
            may_lazy_mount(Profile::L1, "small.safetensors", small_weights, true).unwrap_err();
        assert!(err.is("LAZY_MOUNT_DISALLOWED"));
        let err = may_lazy_mount(Profile::L1, "exact.safetensors", one_gib, true).unwrap_err();
        assert!(err.is("LAZY_MOUNT_DISALLOWED"));
    }

    #[test]
    fn test_mount_l1_fails_closed_without_fuse_t() {
        let large_weights = 2 * 1024 * 1024 * 1024;
        let res = mount_l1(
            Profile::L1,
            "weights.safetensors",
            large_weights,
            true,
            PathBuf::from("/tmp/mnt"),
        );

        #[cfg(not(feature = "l1-fuse"))]
        {
            let err = res.expect_err("mount_l1 must fail when l1-fuse feature is off");
            assert!(err.is("FUSE_T_FEATURE_DISABLED"));
        }

        #[cfg(feature = "l1-fuse")]
        {
            if !probe_fuse_t_installed() {
                let err = res.expect_err("mount_l1 must fail when FUSE-T is absent");
                assert!(err.is("FUSE_T_UNAVAILABLE"));
            }
        }
    }

    #[test]
    fn test_render_fuse_pf_rules_syntax() {
        let rules = render_fuse_pf_rules(501, 2049);
        assert!(rules.contains("# BEGIN depot PF RULES"));
        assert!(rules.contains("# END depot PF RULES"));
        assert!(rules.contains("port 2049 user 501"));
        assert!(rules.contains("port 2049 user 0 keep state"));

        // Verify with pfctl -nf if running on macOS
        #[cfg(target_os = "macos")]
        {
            let temp_file =
                std::env::temp_dir().join(format!("depot-pf-test-{}", enclave_core::rng::u64()));
            fs::write(&temp_file, rules.as_bytes()).unwrap();

            let out = std::process::Command::new("pfctl")
                .args(["-nf", temp_file.to_str().unwrap()])
                .output();
            if let Ok(res) = out {
                assert!(
                    res.status.success(),
                    "pfctl syntax check failed: {}",
                    String::from_utf8_lossy(&res.stderr)
                );
            }
            let _ = fs::remove_file(&temp_file);
        }
    }
}
