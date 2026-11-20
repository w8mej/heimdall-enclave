//! Public CLI refusal checks; no root/session provisioning is invoked.
#[cfg(not(target_os = "macos"))]
#[test]
fn foreign_platform_refuses_before_any_host_identity_operation() {
    assert!(depot_enclave::oidc_session::renew_current_session(i64::MAX)
        .unwrap_err().is("OIDC_SESSION_NATIVE_REQUIRED"));
}
