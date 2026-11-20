//! Integration and unit tests for Packet Filter anchor generation and supervisor watcher (FS-706 §4.3, Prompt 3).

use mcp_enclave::pf::{
    inject_pf_conf, remove_pf_conf, render_anchors, render_cas_swarm_rules,
    render_llm_isolation_rules, CAS_SWARM_ANCHOR, LLM_ISOLATION_ANCHOR,
};
use std::fs;
use std::path::Path;

#[test]
fn test_llm_anchor_matches_gateway_pf_rules() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let canonical_file = repo_root.join("examples/executive-poc/gateway/pf-rules.conf");
    let canonical_text = fs::read_to_string(&canonical_file)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", canonical_file.display()));

    let generated_text = render_llm_isolation_rules();
    assert_eq!(
        generated_text, canonical_text,
        "Generated com.enterprise.llm.isolation anchor does not match gateway/pf-rules.conf"
    );
}

#[test]
fn test_pfctl_syntax_validation() {
    let temp_dir = std::env::temp_dir().join(format!("mcpmac-pf-test-{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();

    render_anchors(&temp_dir).unwrap();
    let llm_path = temp_dir.join(LLM_ISOLATION_ANCHOR);
    let cas_path = temp_dir.join(CAS_SWARM_ANCHOR);

    assert!(llm_path.exists());
    assert!(cas_path.exists());

    let cas_text = render_cas_swarm_rules();
    assert!(cas_text.contains("# BEGIN MCPMAC PF RULES"));
    assert!(cas_text.contains("port 2049 user 501"));
    assert!(cas_text.contains("group $cas_group keep state"));

    #[cfg(target_os = "macos")]
    {
        if unsafe { libc::geteuid() == 0 } {
            for p in [&llm_path, &cas_path] {
                let status = std::process::Command::new("pfctl")
                    .args(["-vnf", &p.display().to_string()])
                    .status();
                if let Ok(s) = status {
                    assert!(s.success(), "pfctl -vnf failed on {}", p.display());
                }
            }
        }
    }

    let _ = fs::remove_dir_all(temp_dir);
}

#[test]
fn test_inject_pf_conf_idempotency() {
    let mock_pf_conf = "\
#
# Default PF configuration file.
#
scrub-anchor \"com.apple/*\"
nat-anchor \"com.apple/*\"
rdr-anchor \"com.apple/*\"
dummynet-anchor \"com.apple/*\"
anchor \"com.apple/*\"
load anchor \"com.apple/*\" from \"/etc/pf.anchors/com.apple\"
";

    let anchors_dir = Path::new("/etc/pf.anchors");

    // First injection
    let injected = inject_pf_conf(mock_pf_conf, anchors_dir);
    assert!(injected.contains("# BEGIN MCPMAC PF RULES"));
    assert!(injected.contains("# END MCPMAC PF RULES"));
    assert!(injected.contains("anchor \"com.enterprise.llm.isolation\""));
    assert!(injected.contains("anchor \"com.enterprise.cas.swarm\""));

    // Second injection must be identical (idempotent)
    let injected_again = inject_pf_conf(&injected, anchors_dir);
    assert_eq!(
        injected, injected_again,
        "Secondary injection modified pf.conf; must be idempotent"
    );

    // Removal must restore original content
    let removed = remove_pf_conf(&injected);
    assert_eq!(
        removed.trim(),
        mock_pf_conf.trim(),
        "Removal did not cleanly restore original pf.conf"
    );
}

#[test]
fn test_supervisor_pf_watcher_reload() {
    let temp_dir = std::env::temp_dir().join(format!("mcpmac-sup-pf-{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();

    let anchor_file = temp_dir.join("com.enterprise.llm.isolation");
    fs::write(&anchor_file, render_llm_isolation_rules()).unwrap();

    // Invoking check_and_restore_pf_anchor with non-root or non-existent anchor handles cleanly
    let res = enclave_core::supervisor::check_and_restore_pf_anchor(
        "com.enterprise.test.nonexistent",
        &anchor_file,
    );
    assert!(res.is_ok());

    let _ = fs::remove_dir_all(temp_dir);
}
