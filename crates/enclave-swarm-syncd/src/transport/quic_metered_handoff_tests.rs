//! Actual mTLS QUIC final-writer tests with synthetic signed membership.
//! The local one-shot scheduling seam exists only in library test builds and
//! runs before file leases or final authority guards, never inside a handoff.
//! These tests do not exercise issuer/request admission or hardware observers.
use super::*;
use crate::{
    governance::Shard,
    seedgate::{HostConditions, SeedGateFSM},
    transport::{iroh::L2CapabilityPolicy, quic_seed::SeedPeerAuthority},
};
use enclave_core::{
    enterprise_authority::{
        EnterpriseAuthority, EnterpriseMember, EnterprisePolicy, SignedEnterprisePolicy,
    },
    profile::Profile,
};
use std::{cell::RefCell, os::unix::fs::PermissionsExt, path::PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Boundary {
    Payload,
    Fin,
}
struct Update {
    boundary: Boundary,
    conditions: HostConditions,
    applied: usize,
}
thread_local! {static UPDATE: RefCell<Option<Update>> = const {RefCell::new(None)};}

pub(super) fn apply_host_update(node: &L2SwarmNode, boundary: Boundary) {
    UPDATE.with(|selected| {
        let mut selected = selected.borrow_mut();
        if let Some(update) = selected.as_mut() {
            if update.boundary == boundary && update.applied == 0 {
                // This is the existing current-condition transition and its
                // release serialization, not direct mutation of cached state.
                node.update_host_conditions(Some(update.conditions))
                    .unwrap();
                update.applied += 1;
            }
        }
    });
}
struct UpdateScope;
impl UpdateScope {
    fn new(boundary: Boundary, conditions: HostConditions) -> Self {
        UPDATE.with(|selected| {
            let mut selected = selected.borrow_mut();
            assert!(selected.is_none(), "one local release schedule at a time");
            *selected = Some(Update {
                boundary,
                conditions,
                applied: 0,
            });
        });
        Self
    }
    fn verify(&self) {
        UPDATE.with(|selected| assert_eq!(selected.borrow().as_ref().unwrap().applied, 1));
    }
}
impl Drop for UpdateScope {
    fn drop(&mut self) {
        UPDATE.with(|selected| *selected.borrow_mut() = None);
    }
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        // Canonical private test parent preserves the production nofollow
        // ancestry checks on Darwin, where /tmp itself is a symlink.
        let parent = std::env::temp_dir().canonicalize().unwrap();
        let path = parent.join(format!("depot-metered-{:x}", enclave_core::rng::u64()));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const BODY: &[u8] = b"bounded metered-only QUIC final handoff";
async fn exchange_writer(
    client: &quinn::Connection,
    server: &quinn::Connection,
    node: &L2SwarmNode,
    peer: &L2AuthenticatedPeer,
    authority: &SeedPeerAuthority,
    boundary: Boundary,
    metered: bool,
) {
    node.update_host_conditions(Some(HostConditions::default()))
        .unwrap();
    assert!(
        node.seed_gate.lock().unwrap().can_seed(),
        "healthy control must start active"
    );
    let membership = node
        .enterprise_authority()
        .unwrap()
        .authorize(&peer.public_key, "models", enclave_crypto::time::now_unix())
        .unwrap();
    let now = now_ms().unwrap();
    let authorization = super::super::iroh::L2DataAuthorization {
        membership,
        started_ms: now,
        expires_ms: now + 30_000,
    };
    let (mut request, mut receive) = client.open_bi().await.unwrap();
    request.write_all(b"fixture request").await.unwrap();
    request.finish().unwrap();
    let (mut send, mut request_receive) =
        tokio::time::timeout(Duration::from_secs(2), server.accept_bi())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        request_receive.read_to_end(64).await.unwrap(),
        b"fixture request"
    );
    let schedule = UpdateScope::new(
        boundary,
        HostConditions {
            unmetered: !metered,
            ..HostConditions::default()
        },
    );
    let mut data_started = false;
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        write_authorized_frame(
            &mut send,
            BODY,
            node,
            peer,
            &authorization,
            authority,
            &mut data_started,
        ),
    )
    .await
    .unwrap();
    schedule.verify();
    assert_eq!(node.seed_gate.lock().unwrap().can_seed(), !metered);
    let mut expected = (BODY.len() as u32).to_be_bytes().to_vec();
    expected.extend_from_slice(BODY);
    if !metered {
        result.unwrap();
        assert!(data_started);
        let received = tokio::time::timeout(Duration::from_secs(2), receive.read_to_end(1024))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            received, expected,
            "actual receiver must get exact bytes and clean FIN"
        );
    } else {
        assert!(result.unwrap_err().is("SEEDING_SCAVENGER_ONLY"));
        assert_eq!(data_started, boundary == Boundary::Fin);
        if boundary == Boundary::Fin {
            let mut received = vec![0; expected.len()];
            tokio::time::timeout(Duration::from_secs(2), receive.read_exact(&mut received))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received, expected, "preupdate enqueues remain valid");
        }
        let mut byte = [0];
        // Keep SendStream alive until this observation. Dropping or resetting
        // first could hide an incorrect FIN behind teardown's stream error.
        assert!(
            tokio::time::timeout(Duration::from_millis(80), receive.read(&mut byte))
                .await
                .is_err(),
            "forbidden payload or FIN reached actual receiver after metered update"
        );
        send.reset(1u32.into()).unwrap();
    }
    drop(schedule);
}

fn run(boundary: Boundary) {
    let directory = Directory::new();
    let mut params = rcgen::CertificateParams::new(vec!["metered-handoff-ca".into()]);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = rcgen::Certificate::from_params(params).unwrap();
    let root = ca.serialize_der().unwrap();
    let client_seed = enclave_core::rng::bytes32();
    let server_seed = enclave_core::rng::bytes32();
    let client_key = SigningKey::from_bytes(&client_seed)
        .verifying_key()
        .to_bytes();
    let server_key = SigningKey::from_bytes(&server_seed)
        .verifying_key()
        .to_bytes();
    let client_cert = fence_tests::identity(&ca, client_seed, "EU");
    let server_cert = fence_tests::identity(&ca, server_seed, "EU");
    let admin = SigningKey::from_bytes(&enclave_core::rng::bytes32());
    let now = enclave_crypto::time::now_unix();
    let membership = EnterpriseAuthority::ephemeral(
        admin.verifying_key().to_bytes(),
        SignedEnterprisePolicy::sign(
            EnterprisePolicy {
                version: 1,
                revision: 1,
                trust_domain: "metered.example".into(),
                issued_unix: now - 1,
                expires_unix: now + 3600,
                members: vec![EnterpriseMember {
                    principal: "spiffe://metered.example/engineer/alice".into(),
                    generation: 1,
                    holder_public_keys: vec![hex::encode(client_key)],
                    namespaces: vec!["models".into()],
                }],
            },
            &admin,
        )
        .unwrap(),
    );
    let node = L2SwarmNode::new(
        SigningKey::from_bytes(&server_seed),
        Shard::EU,
        SeedGateFSM::new(Profile::L2),
        L2CapabilityPolicy::new(KeyPair::new().public(), [9; 32])
            .with_enterprise_authority(membership),
    );
    node.authorize_peer(&hex::encode(client_key));
    let authority = SeedPeerAuthority::from_trusted_peers(
        directory.0.to_str().unwrap(),
        server_key,
        &[client_key],
    )
    .unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let server_endpoint = server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            server_cert,
            &server_seed,
            &[root.clone()],
        )
        .unwrap();
        let address = server_endpoint.local_addr().unwrap();
        let tls = client_tls(
            &fence_tests::registry(address, &root),
            &client_cert,
            &client_seed,
        )
        .unwrap();
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
        let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        let client_connect = client_endpoint.connect(address, "localhost").unwrap();
        let (client, server) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(client_connect, async {
                server_endpoint.accept().await.unwrap().await
            })
        })
        .await
        .unwrap();
        let client = client.unwrap();
        let server = server.unwrap();
        let (holder, shard, exporter) = connection_peer(&server).unwrap();
        assert_eq!(holder, client_key);
        assert_eq!(shard, "EU");
        assert_ne!(exporter, [0; 32]);
        let (remote, remote_shard, remote_exporter) = connection_peer(&client).unwrap();
        assert_eq!(remote, server_key);
        assert_eq!(remote_shard, "EU");
        assert_eq!(remote_exporter, exporter);
        let peer = L2AuthenticatedPeer {
            public_key: holder,
            channel_binding: exporter,
        };
        exchange_writer(&client, &server, &node, &peer, &authority, boundary, false).await;
        exchange_writer(&client, &server, &node, &peer, &authority, boundary, true).await;
        exchange_writer(&client, &server, &node, &peer, &authority, boundary, false).await;
        client.close(0u32.into(), b"fixture complete");
        server.close(0u32.into(), b"fixture complete");
        client_endpoint.close(0u32.into(), b"fixture complete");
        server_endpoint.close(0u32.into(), b"fixture complete");
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(client_endpoint.wait_idle(), server_endpoint.wait_idle());
        })
        .await
        .expect("both owned endpoint drivers become idle");
    });
    runtime.shutdown_timeout(Duration::from_secs(1));
}

#[test]
fn metered_only_update_before_payload_blocks_actual_quic_bytes_and_recovers() {
    run(Boundary::Payload);
}
#[test]
fn metered_only_update_before_fin_preserves_preupdate_payload_but_blocks_fin_and_recovers() {
    run(Boundary::Fin);
}
