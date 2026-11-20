//! Structural deployment checks; these do not exercise GUI/IdP authentication.
use enclave_core::daemon::DaemonId;
use depot_enclave::launchd::{self, Layout};

#[test]
fn separate_broker_runs_once_in_aqua_with_protected_configuration() {
    let rendered = launchd::oidc_plist();
    assert!(rendered.contains("<key>LimitLoadToSessionType</key><string>Aqua</string>"));
    assert!(rendered.contains("<key>KeepAlive</key><false/>"));
    assert!(rendered.contains("EnclaveOIDC.app/Contents/MacOS/enclave-oidc"));
    assert!(rendered.contains(launchd::OIDC_IDENTITY_CONFIG));
    assert!(rendered.contains(launchd::OIDC_OAUTH_CONFIG));
    assert!(!rendered.contains("<key>UserName</key>"));
    let committed = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"),
        "/../../launchd/com.enterprise.enclave.oidc-broker.plist")).unwrap();
    assert_eq!(rendered, committed);
}

#[test]
fn custody_receives_only_peer_binding_and_prepares_separate_runtime_parent() {
    let layout = Layout::default();
    let args = launchd::daemon_args(DaemonId::CustodyVault, &layout);
    assert!(args.windows(2).any(|pair| pair == ["--oidc-broker-config", launchd::OIDC_IDENTITY_CONFIG]));
    assert!(!args.iter().any(|arg| arg == launchd::OIDC_OAUTH_CONFIG));
    let sandbox = launchd::sandbox_profile(DaemonId::CustodyVault, &layout);
    assert!(sandbox.contains(launchd::OIDC_IDENTITY_CONFIG));
    assert!(!sandbox.contains(launchd::OIDC_OAUTH_CONFIG));
    assert!(launchd::provision_script(&layout).contains("mkdirp /var/run/enclave/oidc root \"$WHEEL\" 0755"));
}
