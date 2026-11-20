//! Browser execution must use the root-installed enclave browser directory.
#[test]
fn browser_exec_is_scoped_to_controlled_install_path() {
    let generated = mcp_enclave::launchd::browser_sandbox_profile(&Default::default());
    assert!(!generated.contains("\"/Applications/"));
    assert!(generated.contains("/Library/Application Support/EnterpriseEnclave/browser/Chromium.app/Contents/MacOS/Chromium"));
    assert!(generated.contains("(deny default)"));
    assert!(!generated.contains("remote tcp"));
    let checked_in = include_str!("../../../launchd/browser.sb");
    assert_eq!(generated, checked_in);
}
