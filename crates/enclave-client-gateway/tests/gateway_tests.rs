use enclave_client_gateway::{ClientGateway, ClientGatewayRequest, RateLimiter};
use enclave_core::ipc::PeerCredentials;
use std::time::Duration;

#[test]
fn rate_limiter_throttles_excess_requests() {
    let limiter = RateLimiter::new(3, Duration::from_secs(60));
    let uid = 501;

    assert!(limiter.check_and_record(uid).is_ok());
    assert!(limiter.check_and_record(uid).is_ok());
    assert!(limiter.check_and_record(uid).is_ok());

    let err = limiter.check_and_record(uid).unwrap_err();
    assert!(err.is("ERR_GATEWAY_RATE_LIMITED"));
}

#[test]
fn peer_authorization_rejects_unauthorized_uids() {
    let dummy_path = std::path::PathBuf::from("/tmp/dummy.sock");
    let gateway = ClientGateway::new(
        dummy_path.clone(),
        dummy_path,
        10,
        Duration::from_secs(60),
        false,
    );

    let allowed_peer = PeerCredentials::local(502, 20);
    // There is no attested console on Linux; production must not guess 501.
    #[cfg(not(target_os = "macos"))]
    assert!(gateway.authorize_peer(&allowed_peer).is_err());

    let bad_peer = PeerCredentials::local(999, 999);
    let err = gateway.authorize_peer(&bad_peer).unwrap_err();
    #[cfg(not(target_os = "macos"))]
    assert!(err.is("ERR_GATEWAY_PEER_DENIED") || err.is("GATEWAY_NO_CONSOLE"));
    #[cfg(target_os = "macos")]
    assert!(err.is("PEER_AUDIT_TOKEN_MISSING"), "unattested peers must fail identity verification");
}

#[test]
fn gateway_wire_rejects_unknown_operations() {
    assert!(serde_json::from_str::<ClientGatewayRequest>(r#"{"Unsupported":"Wipe"}"#).is_err());
    assert!(serde_json::from_str::<ClientGatewayRequest>(r#"{"Wipe":{}}"#).is_err());
}
