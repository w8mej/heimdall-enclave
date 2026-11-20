//! Integration and unit tests for GUI intent agent and Background Task Management (FS-706 §4.4, §4.5, Prompt 5).

use std::path::PathBuf;
use std::process::Command;

use depot_enclave::deploy::{evaluate_intent_bootstrap, ConsoleUidProvider};
use depot_enclave::launchd::{intent_plist, Layout, INTENT_LABEL};

struct MockConsoleProvider {
    uid: Option<u32>,
}

impl ConsoleUidProvider for MockConsoleProvider {
    fn console_uid(&self) -> Option<u32> {
        self.uid
    }
}

#[test]
fn test_intent_plist_golden() {
    let layout = Layout::default();
    let rendered = intent_plist(&layout);

    // Verify plist structure and key properties
    assert!(rendered.contains(&format!("<string>{INTENT_LABEL}</string>")));
    assert!(rendered.contains("<key>RunAtLoad</key>\n\t<true/>"));
    assert!(rendered.contains("<key>KeepAlive</key>\n\t<true/>"));
    assert!(rendered.contains("<key>ProcessType</key>\n\t<string>Interactive</string>"));
    assert!(rendered.contains("/opt/enterprise/enclave/bin/enclave-intent"));
    assert!(rendered.contains("/var/run/enclave/intent/intent.sock"));

    // Verify committed launchd/com.enterprise.enclave.intent.plist matches rendered
    let committed_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../launchd/com.enterprise.enclave.intent.plist");
    assert!(committed_path.exists());
    let committed = std::fs::read_to_string(&committed_path).unwrap();
    assert_eq!(
        rendered, committed,
        "launchd/com.enterprise.enclave.intent.plist does not match generator"
    );

    // On macOS, run plutil -lint on committed plist
    #[cfg(target_os = "macos")]
    {
        let status = Command::new("plutil")
            .args(["-lint", committed_path.to_str().unwrap()])
            .status()
            .expect("plutil command failed");
        assert!(status.success(), "plutil -lint failed on intent plist");
    }
}

#[test]
fn test_console_uid_logic_injected_provider() {
    // Case 1: Standard interactive Aqua user (e.g. UID 501)
    let user_provider = MockConsoleProvider { uid: Some(501) };
    let outcome1 = evaluate_intent_bootstrap(&user_provider);
    assert_eq!(outcome1.console_uid, Some(501));
    assert!(!outcome1.deferred);
    assert!(outcome1.message.contains("501"));

    // Case 2: Login window / root console (UID 0) -> Cleanly deferred
    let root_provider = MockConsoleProvider { uid: Some(0) };
    let outcome2 = evaluate_intent_bootstrap(&root_provider);
    assert_eq!(outcome2.console_uid, Some(0));
    assert!(outcome2.deferred);
    assert!(!outcome2.bootstrapped);
    assert!(outcome2.message.contains("loginwindow"));

    // Case 3: Headless / No active console session (None) -> Cleanly deferred
    let headless_provider = MockConsoleProvider { uid: None };
    let outcome3 = evaluate_intent_bootstrap(&headless_provider);
    assert_eq!(outcome3.console_uid, None);
    assert!(outcome3.deferred);
    assert!(!outcome3.bootstrapped);
    assert!(outcome3.message.contains("No active Aqua console session"));
}

#[test]
fn test_healthcheck_reports_intent_telemetry() {
    let (_, _, details) = depot_enclave::deploy::health::run_healthcheck("L1");
    let intent_info = details
        .get("intent_agent")
        .expect("intent_agent missing in health telemetry");

    assert_eq!(intent_info["label"], "com.enterprise.enclave.intent");
    assert!(intent_info.get("socket_present").is_some());
    assert!(intent_info.get("deferred").is_some());
}
