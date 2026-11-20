//! Tests for L2 cross-node A2A mTLS with SPIFFE SVIDs and RFC 9266 exporter binding (GAP-35, D-35a).

#![cfg(feature = "l2-a2a")]

use std::time::Duration;

use ed25519_dalek::SigningKey;
use enclave_agent_runtime::a2a::*;
use enclave_agent_runtime::cedar_engine::{CedarEngine, ToolResource};
use enclave_agent_runtime::delegation::DelegationManager;
use enclave_agent_runtime::heap::CapabilityHeap;
use enclave_agent_runtime::pdp::Pdp;
use enclave_core::profile::{ActionClass, Profile};
use enclave_crypto::biscuit_auth::AuthorizerLimits;
use enclave_crypto::pop_biscuit::{
    make_call, spec_limits, ClockCaveat, DelegationCaveats, Transport, WireClock, MAX_SKEW_MS,
    MAX_TTL_MS,
};

#[path = "support/spiffe_test_ca.rs"]
mod spiffe_test_ca;
use spiffe_test_ca::SpiffeTestCa;

const TRUST_DOMAIN: &str = "corporate.internal";

struct TestMesh {
    ca: SpiffeTestCa,
    server_svid: SpiffeSvid,
    client_svid: SpiffeSvid,
    attacker_svid: SpiffeSvid,
}

fn setup_mesh() -> TestMesh {
    let ca = SpiffeTestCa::new(TRUST_DOMAIN).unwrap();
    let server_id = SpiffeId::new(TRUST_DOMAIN, "/enclave/uid/704/server_node").unwrap();
    let client_id = SpiffeId::new(TRUST_DOMAIN, "/enclave/uid/704/client_node").unwrap();
    let attacker_id = SpiffeId::new(TRUST_DOMAIN, "/enclave/uid/704/rogue_worker").unwrap();

    let server_svid = ca.issue_svid(&server_id).unwrap();
    let client_svid = ca.issue_svid(&client_id).unwrap();
    let attacker_svid = ca.issue_svid(&attacker_id).unwrap();

    TestMesh {
        ca,
        server_svid,
        client_svid,
        attacker_svid,
    }
}

fn setup_pdp(
    profile: Profile,
) -> (
    Pdp,
    CapabilityHeap,
    DelegationManager,
    SigningKey,
    SigningKey,
) {
    let boot = enclave_core::seq::new_boot_epoch_id();
    let limits = AuthorizerLimits {
        max_time: Duration::from_millis(50),
        ..spec_limits()
    };
    let pdp = Pdp::new(
        CedarEngine::baseline_bundle().unwrap(),
        boot.clone(),
        profile,
        limits,
    );
    let heap = CapabilityHeap::new(boot);
    let dm = DelegationManager::new();
    let orch = SigningKey::generate(&mut rand_core::OsRng);
    let child = SigningKey::generate(&mut rand_core::OsRng);
    (pdp, heap, dm, orch, child)
}

fn tool() -> ToolResource {
    ToolResource {
        name: "depot://postgres/select_bounded".into(),
        action_class: ActionClass::A1,
        sink_clearance: enclave_core::Conf::C2,
        namespace: "dev-billing".into(),
        mutates_root: false,
    }
}

async fn open_session_pair(
    mesh: &TestMesh,
    client_svid: SpiffeSvid,
    server_svid: SpiffeSvid,
    allowed_client_id: Option<SpiffeId>,
) -> (
    A2aClientSession<tokio::net::TcpStream>,
    A2aServerSession<tokio::net::TcpStream>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let client = A2aClient::new(A2aClientConfig {
        svid: client_svid,
        trust_domain: TRUST_DOMAIN.to_string(),
        ca_bundle_der: mesh.ca.ca_bundle_der(),
        expected_server_id: Some(server_svid.spiffe_id.clone()),
    })
    .unwrap();

    let server = A2aServer::new(A2aServerConfig {
        svid: server_svid,
        trust_domain: TRUST_DOMAIN.to_string(),
        ca_bundle_der: mesh.ca.ca_bundle_der(),
        allowed_client_id,
    })
    .unwrap();

    let client_fut = async {
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        client.connect(stream).await.unwrap()
    };

    let server_fut = async {
        let (stream, _) = listener.accept().await.unwrap();
        server.accept(stream).await.unwrap()
    };

    tokio::join!(client_fut, server_fut)
}

#[tokio::test]
async fn happy_path_a2a_delegation_over_mtls() {
    let mesh = setup_mesh();
    let (mut client_sess, mut server_sess) = open_session_pair(
        &mesh,
        mesh.client_svid.clone(),
        mesh.server_svid.clone(),
        Some(mesh.client_svid.spiffe_id.clone()),
    )
    .await;

    // Both ends agree on the exact same RFC 9266 exporter channel binding
    let cb = client_sess.channel_binding();
    assert_eq!(cb, server_sess.channel_binding());
    assert_ne!(cb, [0u8; 32]);

    // Setup PDP and mint token bound to this session's exporter binding
    let (mut pdp, heap, mut dm, orch, child) = setup_pdp(Profile::L2);
    let root = dm
        .mint_root(
            &pdp,
            &orch.verifying_key().to_bytes(),
            &cb,
            12_000,
            &[tool().name],
        )
        .unwrap();

    let now_utc = 1_700_000_000_000u64;
    let caveats = DelegationCaveats {
        clock: ClockCaveat::Mtls {
            utc_epoch_ms_expiry: now_utc + 10_000,
        },
        tools: vec![tool().name],
        target_namespace: tool().namespace,
        max_row_count: 25,
        max_qif_call_millibits: 4_000,
    };
    let child_token = dm
        .spawn(&root, &caveats, &child.verifying_key().to_bytes(), &cb)
        .unwrap();

    let clock = WireClock {
        utc_epoch_ms_expiry: Some(now_utc + 10_000),
        max_ttl_ms: Some(MAX_TTL_MS),
        skew_ms: Some(MAX_SKEW_MS),
        ..Default::default()
    };

    let wire = make_call(
        &child_token,
        &child,
        &cb,
        b"{}",
        1,
        Transport::MtlsExporter,
        clock,
    )
    .unwrap();

    let req = A2aRequest {
        wire,
        tool_name: tool().name,
        target_namespace: tool().namespace,
        args_json: "{}".to_string(),
        qif_mb: 1_000,
    };

    let client_task = tokio::spawn(async move { client_sess.send_request(&req).await.unwrap() });

    let server_task = tokio::spawn(async move {
        server_sess
            .process_one_call(&mut pdp, &heap, 1_000_000, now_utc)
            .await
            .unwrap()
    });

    let (resp_client, resp_server) = tokio::join!(client_task, server_task);
    let resp = resp_client.unwrap();
    assert_eq!(resp, resp_server.unwrap());
    assert!(resp.success, "failed: {:?}", resp.error_code);
    assert!(resp.payload.is_some());
}

#[tokio::test]
async fn token_bound_to_session_a_is_rejected_on_session_b() {
    let mesh = setup_mesh();
    let (client_a, _server_a) = open_session_pair(
        &mesh,
        mesh.client_svid.clone(),
        mesh.server_svid.clone(),
        None,
    )
    .await;
    let (mut client_b, mut server_b) = open_session_pair(
        &mesh,
        mesh.client_svid.clone(),
        mesh.server_svid.clone(),
        None,
    )
    .await;

    let cb_a = client_a.channel_binding();
    let cb_b = client_b.channel_binding();
    assert_ne!(
        cb_a, cb_b,
        "two distinct TLS sessions must yield distinct exporter bindings"
    );

    let (mut pdp, heap, mut dm, orch, child) = setup_pdp(Profile::L2);
    let root = dm
        .mint_root(
            &pdp,
            &orch.verifying_key().to_bytes(),
            &cb_a,
            12_000,
            &[tool().name],
        )
        .unwrap();

    let now_utc = 1_700_000_000_000u64;
    let caveats = DelegationCaveats {
        clock: ClockCaveat::Mtls {
            utc_epoch_ms_expiry: now_utc + 10_000,
        },
        tools: vec![tool().name],
        target_namespace: tool().namespace,
        max_row_count: 25,
        max_qif_call_millibits: 4_000,
    };
    let child_token = dm
        .spawn(&root, &caveats, &child.verifying_key().to_bytes(), &cb_a)
        .unwrap();

    let clock = WireClock {
        utc_epoch_ms_expiry: Some(now_utc + 10_000),
        max_ttl_ms: Some(MAX_TTL_MS),
        skew_ms: Some(MAX_SKEW_MS),
        ..Default::default()
    };

    // Make call with session A's token
    let wire_a = make_call(
        &child_token,
        &child,
        &cb_a,
        b"{}",
        1,
        Transport::MtlsExporter,
        clock,
    )
    .unwrap();

    let req = A2aRequest {
        wire: wire_a,
        tool_name: tool().name,
        target_namespace: tool().namespace,
        args_json: "{}".to_string(),
        qif_mb: 1_000,
    };

    // Send session A's token over session B!
    let client_task = tokio::spawn(async move { client_b.send_request(&req).await.unwrap() });
    let server_task = tokio::spawn(async move {
        server_b
            .process_one_call(&mut pdp, &heap, 1_000_000, now_utc)
            .await
            .unwrap()
    });

    let (resp_client, _) = tokio::join!(client_task, server_task);
    let resp = resp_client.unwrap();
    assert!(
        !resp.success,
        "token bound to session A must not succeed on session B"
    );
    let err = resp.error_code.unwrap();
    assert!(
        err.contains("POP_BAD_SIGNATURE")
            || err.contains("POP_CHANNEL_BINDING_MISMATCH")
            || err.contains("biscuit"),
        "expected channel binding rejection, got {err}"
    );
}

#[tokio::test]
async fn skew_outside_the_window_is_rejected() {
    let mesh = setup_mesh();
    let (mut client_sess, mut server_sess) = open_session_pair(
        &mesh,
        mesh.client_svid.clone(),
        mesh.server_svid.clone(),
        None,
    )
    .await;

    let cb = client_sess.channel_binding();
    let (mut pdp, heap, mut dm, orch, child) = setup_pdp(Profile::L2);
    let root = dm
        .mint_root(
            &pdp,
            &orch.verifying_key().to_bytes(),
            &cb,
            12_000,
            &[tool().name],
        )
        .unwrap();

    let now_utc = 1_700_000_000_000u64;
    // Token expired in the past: expiry is now_utc - 5,000 ms (outside 2,000 ms skew)
    let expired_utc = now_utc - 5_000;
    let caveats = DelegationCaveats {
        clock: ClockCaveat::Mtls {
            utc_epoch_ms_expiry: expired_utc,
        },
        tools: vec![tool().name],
        target_namespace: tool().namespace,
        max_row_count: 25,
        max_qif_call_millibits: 4_000,
    };
    let child_token = dm
        .spawn(&root, &caveats, &child.verifying_key().to_bytes(), &cb)
        .unwrap();

    let clock = WireClock {
        utc_epoch_ms_expiry: Some(expired_utc),
        max_ttl_ms: Some(MAX_TTL_MS),
        skew_ms: Some(MAX_SKEW_MS),
        ..Default::default()
    };

    let wire = make_call(
        &child_token,
        &child,
        &cb,
        b"{}",
        1,
        Transport::MtlsExporter,
        clock,
    )
    .unwrap();

    let req = A2aRequest {
        wire,
        tool_name: tool().name,
        target_namespace: tool().namespace,
        args_json: "{}".to_string(),
        qif_mb: 1_000,
    };

    let client_task = tokio::spawn(async move { client_sess.send_request(&req).await.unwrap() });
    let server_task = tokio::spawn(async move {
        server_sess
            .process_one_call(&mut pdp, &heap, 1_000_000, now_utc)
            .await
            .unwrap()
    });

    let (resp_client, _) = tokio::join!(client_task, server_task);
    let resp = resp_client.unwrap();
    assert!(!resp.success, "expired token outside skew must be rejected");
}

#[tokio::test]
async fn wrong_spiffe_id_is_rejected_at_handshake() {
    let mesh = setup_mesh();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Server expects strictly client_svid
    let server = A2aServer::new(A2aServerConfig {
        svid: mesh.server_svid.clone(),
        trust_domain: TRUST_DOMAIN.to_string(),
        ca_bundle_der: mesh.ca.ca_bundle_der(),
        allowed_client_id: Some(mesh.client_svid.spiffe_id.clone()),
    })
    .unwrap();

    // Attacker connects presenting attacker_svid
    let attacker_client = A2aClient::new(A2aClientConfig {
        svid: mesh.attacker_svid.clone(),
        trust_domain: TRUST_DOMAIN.to_string(),
        ca_bundle_der: mesh.ca.ca_bundle_der(),
        expected_server_id: Some(mesh.server_svid.spiffe_id.clone()),
    })
    .unwrap();

    let client_fut = async {
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        attacker_client.connect(stream).await
    };

    let server_fut = async {
        let (stream, _) = listener.accept().await.unwrap();
        server.accept(stream).await
    };

    let (client_res, server_res) = tokio::join!(client_fut, server_fut);
    assert!(
        client_res.is_err() || server_res.is_err(),
        "handshake with wrong SPIFFE ID must fail"
    );
}

#[tokio::test]
async fn l3_build_profile_rejects_mtls_with_mtls_disabled() {
    let mesh = setup_mesh();
    let (mut client_sess, mut server_sess) = open_session_pair(
        &mesh,
        mesh.client_svid.clone(),
        mesh.server_svid.clone(),
        None,
    )
    .await;

    let cb = client_sess.channel_binding();

    // Server runs under Profile L3!
    let (mut pdp, heap, mut dm, orch, child) = setup_pdp(Profile::L3);
    assert_eq!(pdp.profile(), Profile::L3);

    let root = dm
        .mint_root(
            &pdp,
            &orch.verifying_key().to_bytes(),
            &cb,
            12_000,
            &[tool().name],
        )
        .unwrap();

    let now_utc = 1_700_000_000_000u64;
    let caveats = DelegationCaveats {
        clock: ClockCaveat::Mtls {
            utc_epoch_ms_expiry: now_utc + 10_000,
        },
        tools: vec![tool().name],
        target_namespace: tool().namespace,
        max_row_count: 25,
        max_qif_call_millibits: 4_000,
    };
    let child_token = dm
        .spawn(&root, &caveats, &child.verifying_key().to_bytes(), &cb)
        .unwrap();

    let clock = WireClock {
        utc_epoch_ms_expiry: Some(now_utc + 10_000),
        max_ttl_ms: Some(MAX_TTL_MS),
        skew_ms: Some(MAX_SKEW_MS),
        ..Default::default()
    };

    let wire = make_call(
        &child_token,
        &child,
        &cb,
        b"{}",
        1,
        Transport::MtlsExporter,
        clock,
    )
    .unwrap();

    let req = A2aRequest {
        wire,
        tool_name: tool().name,
        target_namespace: tool().namespace,
        args_json: "{}".to_string(),
        qif_mb: 1_000,
    };

    let client_task = tokio::spawn(async move { client_sess.send_request(&req).await.unwrap() });
    let server_task = tokio::spawn(async move {
        server_sess
            .process_one_call(&mut pdp, &heap, 1_000_000, now_utc)
            .await
            .unwrap()
    });

    let (resp_client, _) = tokio::join!(client_task, server_task);
    let resp = resp_client.unwrap();
    assert!(!resp.success, "Profile L3 must refuse mTLS A2A calls");
    assert_eq!(resp.error_code.as_deref(), Some("MTLS_DISABLED"));
}

#[test]
fn f73_uri_san_count_and_der_boundaries() {
    use enclave_agent_runtime::a2a::verifier::extract_spiffe_id;
    let make = |uris: &[&str]| {
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = uris
            .iter()
            .map(|u| rcgen::SanType::URI((*u).into()))
            .collect();
        rcgen::Certificate::from_params(params)
            .unwrap()
            .serialize_der()
            .unwrap()
    };
    let good = make(&["spiffe://corporate.internal/enclave/node"]);
    assert_eq!(
        extract_spiffe_id(&good).unwrap().trust_domain(),
        "corporate.internal"
    );
    for uris in [
        vec![],
        vec![
            "spiffe://corporate.internal/a",
            "spiffe://corporate.internal/b",
        ],
        vec!["spiffe://corporate.internal/a", "https://other.test/"],
    ] {
        assert!(extract_spiffe_id(&make(&uris)).is_err());
    }
    let mut trailing = good;
    trailing.push(0);
    assert!(extract_spiffe_id(&trailing)
        .unwrap_err()
        .is("X509_TRAILING_BYTES"));
}

#[test]
fn f73_signed_svid_validity_and_revocation_bound() {
    use rustls::pki_types::{CertificateDer, UnixTime};
    let ca = SpiffeTestCa::new(TRUST_DOMAIN).unwrap();
    let id = SpiffeId::new(TRUST_DOMAIN, "/enclave/uid/704/client").unwrap();
    let verifier = SpiffeCertVerifier::new(TRUST_DOMAIN, &ca.ca_bundle_der()).unwrap();
    let check = |before, after| {
        let svid = ca.issue_svid_with_validity(&id, before, after).unwrap();
        verifier.verify_spiffe_cert(
            &CertificateDer::from(svid.cert_der_chain[0].clone()),
            &[],
            UnixTime::now(),
        )
    };
    assert_eq!(check(-60, 300).unwrap(), id);
    assert!(check(-60, 3540).is_ok(), "exact one-hour lifetime is valid");
    assert!(check(-60, 3541)
        .unwrap_err()
        .to_string()
        .contains("SVID_LIFETIME_EXCEEDS_ONE_HOUR"));
    assert!(check(-120, -60).is_err(), "signed expired leaf is refused");
    assert!(check(60, 120).is_err(), "signed future leaf is refused");
}
