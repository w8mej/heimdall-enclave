//! BSD Packet Filter (`pf`) anchor generation, installation, and verification (FS-706 §4.3, D-R12).

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use std::path::{Path, PathBuf};

/// Anchor identifier for UID 701 (_llmagent) isolation.
pub const LLM_ISOLATION_ANCHOR: &str = "com.enterprise.llm.isolation";
/// Anchor identifier for UID 702 (_enclavecas) swarm governance.
pub const CAS_SWARM_ANCHOR: &str = "com.enterprise.cas.swarm";

/// Start marker in pf.conf.
pub const PF_CONF_MARKER_START: &str = "# BEGIN depot PF RULES";
/// End marker in pf.conf.
pub const PF_CONF_MARKER_END: &str = "# END depot PF RULES";

/// Render the canonical rules for `com.enterprise.llm.isolation` matching `gateway/pf-rules.conf`.
pub fn render_llm_isolation_rules() -> String {
    include_str!("../../enclave-core/src/supervisor/pf_policy_llm.pf").to_owned()
}

/// Render the canonical rules for `com.enterprise.cas.swarm`.
pub fn render_cas_swarm_rules() -> String {
    include_str!("../../enclave-core/src/supervisor/pf_policy_cas.pf").to_owned()
}

/// Render both anchors into destination directory.
pub fn render_anchors(out_dir: &Path) -> EnclaveResult<()> {
    std::fs::create_dir_all(out_dir).map_err(|e| {
        err!(
            EIO,
            "PF_DIR_CREATE_FAILED",
            "create {}: {e}",
            out_dir.display()
        )
    })?;

    let llm_path = out_dir.join(LLM_ISOLATION_ANCHOR);
    std::fs::write(&llm_path, render_llm_isolation_rules())
        .map_err(|e| err!(EIO, "PF_WRITE_FAILED", "write {}: {e}", llm_path.display()))?;

    let cas_path = out_dir.join(CAS_SWARM_ANCHOR);
    std::fs::write(&cas_path, render_cas_swarm_rules())
        .map_err(|e| err!(EIO, "PF_WRITE_FAILED", "write {}: {e}", cas_path.display()))?;

    Ok(())
}

/// Render the configuration block to inject into `/etc/pf.conf`.
pub fn render_pf_conf_block(anchors_dir: &Path) -> String {
    format!(
        "{}\n\
         anchor \"{}\"\n\
         load anchor \"{}\" from \"{}/{}\"\n\
         anchor \"{}\"\n\
         load anchor \"{}\" from \"{}/{}\"\n\
         {}\n",
        PF_CONF_MARKER_START,
        LLM_ISOLATION_ANCHOR,
        LLM_ISOLATION_ANCHOR,
        anchors_dir.display(),
        LLM_ISOLATION_ANCHOR,
        CAS_SWARM_ANCHOR,
        CAS_SWARM_ANCHOR,
        anchors_dir.display(),
        CAS_SWARM_ANCHOR,
        PF_CONF_MARKER_END
    )
}

/// Inject the managed anchor lines into a pf.conf string, idempotently.
pub fn inject_pf_conf(original: &str, anchors_dir: &Path) -> String {
    let block = render_pf_conf_block(anchors_dir);
    if let (Some(start_idx), Some(end_idx)) = (
        original.find(PF_CONF_MARKER_START),
        original.find(PF_CONF_MARKER_END),
    ) {
        let full_end = end_idx + PF_CONF_MARKER_END.len();
        // Replace existing block
        let mut out = String::new();
        out.push_str(&original[..start_idx]);
        out.push_str(&block);
        if full_end < original.len() {
            let rest = &original[full_end..];
            let rest_trimmed = rest.strip_prefix('\n').unwrap_or(rest);
            out.push_str(rest_trimmed);
        }
        out
    } else {
        // Append block
        let mut out = original.to_string();
        if !out.ends_with('\n') && !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&block);
        out
    }
}

/// Remove the managed anchor lines from a pf.conf string.
pub fn remove_pf_conf(content: &str) -> String {
    if let (Some(start_idx), Some(end_idx)) = (
        content.find(PF_CONF_MARKER_START),
        content.find(PF_CONF_MARKER_END),
    ) {
        let full_end = end_idx + PF_CONF_MARKER_END.len();
        let mut out = String::new();
        out.push_str(&content[..start_idx]);
        if full_end < content.len() {
            let rest = &content[full_end..];
            let rest_trimmed = rest.strip_prefix('\n').unwrap_or(rest);
            out.push_str(rest_trimmed);
        }
        out
    } else {
        content.to_string()
    }
}

/// Install anchors and update pf.conf, validating with `/sbin/pfctl -vnf`.
pub fn install_pf(anchors_dir: &Path, pf_conf_path: &Path) -> EnclaveResult<()> {
    install_pf_with(anchors_dir, pf_conf_path, &crate::syscmd::SystemRunner)
}

/// [`install_pf`] with an injectable process runner.
///
/// DEFECT-F-90: `pfctl` is launched by absolute path with a scrubbed
/// environment, and a validator that cannot be launched counts as a failed
/// validation (the original pf.conf is restored).
pub fn install_pf_with(
    anchors_dir: &Path,
    pf_conf_path: &Path,
    runner: &dyn crate::syscmd::Runner,
) -> EnclaveResult<()> {
    render_anchors(anchors_dir)?;

    if !pf_conf_path.exists() {
        fail!(
            EINVAL,
            "PF_CONF_MISSING",
            "{} not found",
            pf_conf_path.display()
        );
    }

    let orig_content = std::fs::read_to_string(pf_conf_path).map_err(|e| {
        err!(
            EIO,
            "PF_READ_FAILED",
            "read {}: {e}",
            pf_conf_path.display()
        )
    })?;

    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let backup_path = PathBuf::from(format!("{}.orig-enclave", pf_conf_path.display()));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&backup_path)
    {
        Ok(mut backup) => {
            backup
                .write_all(orig_content.as_bytes())
                .map_err(|e| err!(EIO, "PF_BACKUP", "{e}"))?;
            enclave_core::fsutil::full_fsync(&backup)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(err!(EIO, "PF_BACKUP", "{e}")),
    }
    let new_content = inject_pf_conf(&orig_content, anchors_dir);
    let temp = pf_conf_path.with_extension(format!(
        "{}.candidate",
        hex::encode(enclave_core::rng::bytes32())
    ));
    let mode = std::fs::metadata(pf_conf_path)
        .map_err(|e| err!(EIO, "PF_STAT", "{e}"))?
        .mode()
        & 0o777;
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temp)
            .map_err(|e| err!(EIO, "PF_WRITE_FAILED", "{e}"))?;
        file.write_all(new_content.as_bytes())
            .map_err(|e| err!(EIO, "PF_WRITE_FAILED", "{e}"))?;
        enclave_core::fsutil::full_fsync(&file)?;
        if cfg!(target_os = "macos") {
            let mut cmd = crate::syscmd::command(crate::syscmd::Tool::Pfctl);
            cmd.arg("-vnf").arg(&temp);
            match runner.status(cmd) {
                Ok(status) if status.success() => {}
                _ => fail!(
                    EINVAL,
                    "PFCTL_SYNTAX_ERROR",
                    "candidate rejected; live pf.conf unchanged"
                ),
            }
        }
        std::fs::rename(&temp, pf_conf_path).map_err(|e| err!(EIO, "PF_COMMIT", "{e}"))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    // Independent golden lengths/digests were captured from the original
    // literal-only renderer bodies BEFORE extraction. They do not read the
    // include_str! assets as their expected value. The source-bound capture is
    // agent1/pf-policy-extraction/source-before-attempt1.json (2026-11-15).
    #[test]
    fn llm_policy_preserves_original_exact_utf8_bytes() {
        let rendered = render_llm_isolation_rules();
        assert_eq!(rendered.len(), 1933);
        assert_eq!(
            hex::encode(Sha256::digest(rendered.as_bytes())),
            "fcb0fe55616bd781aa2611533816ba510c2769459c3385e374fc07001f9b55a1"
        );
    }

    #[test]
    fn cas_policy_preserves_original_exact_utf8_bytes() {
        let rendered = render_cas_swarm_rules();
        assert_eq!(rendered.len(), 982);
        assert_eq!(
            hex::encode(Sha256::digest(rendered.as_bytes())),
            "b3850628b94877cb804f93b3ccd35b789a2cf2f73fb8c998bfc961a1925ec73b"
        );
    }
}
