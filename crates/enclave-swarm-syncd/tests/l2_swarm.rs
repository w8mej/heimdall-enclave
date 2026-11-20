//! Integration tests for Profile L2 P2P Swarm Transport (FS-702 §4.2, Prompt 1C).
//!
//! Verifies:
//! 1. Two-node in-process helper fixture (no QUIC endpoint) exchanging 16 KiB encrypted Bao slices.
//! 2. In-RAM slice Merkle verification and CAS store commit.
//! 3. Byzantine poisoning detection, PoisonReceipt generation, and peer quarantine.
//! 4. Constant-time 256-byte CHUNK_UNAVAILABLE frame rejection.

use ed25519_dalek::SigningKey;
use enclave_core::profile::Profile;
use enclave_swarm_syncd::cas::ContentStore;
use enclave_swarm_syncd::governance::Shard;
use enclave_swarm_syncd::seedgate::{HostConditions, SeedGateFSM, Thermal};
use enclave_swarm_syncd::transport::constant_time::{is_unavailable_frame, UNAVAILABLE_FRAME_SIZE};
use enclave_swarm_syncd::transport::iroh::{L2AuthenticatedPeer, L2CapabilityPolicy, L2ChunkRequest, L2ChunkResponse, L2SwarmNode, L2_READ_TOOL};
use enclave_swarm_syncd::transport::ohttp_fetch::package_transport_artifact;
use std::sync::Arc;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use enclave_crypto::biscuit_auth::{builder::Term, Biscuit, KeyPair};
use enclave_crypto::pop_biscuit::{make_call, Transport, WireClock};

const POLICY: [u8; 32] = [9; 32];
fn now_ms() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64 }
fn grant(issuer: &KeyPair, node: &L2SwarmNode, peer: &L2AuthenticatedPeer, root: &str) -> Biscuit {
    let mut p = HashMap::new();
    p.insert("epoch".into(), Term::Str(node.authorization_epoch().into()));
    p.insert("policy".into(), Term::Bytes(POLICY.to_vec()));
    p.insert("holder".into(), Term::Bytes(peer.public_key.to_vec()));
    p.insert("cb".into(), Term::Bytes(peer.channel_binding.to_vec()));
    p.insert("root".into(), Term::Str(root.into()));
    p.insert("peer".into(), Term::Str(hex::encode(peer.public_key)));
    p.insert("exp".into(), Term::Integer((now_ms() + 10_000) as i64));
    p.insert("tool".into(), Term::Str(L2_READ_TOOL.into()));
    Biscuit::builder().code_with_params(
        "boot_uuid({epoch}); policy_bundle_blake3({policy}); pop_holder(0, {holder}, {cb}); cas_read(\"models\", {root}, {peer}); right(\"cas:pull\", \"models\"); jurisdiction_shard(\"EU\"); check if tool({tool}); check if utc_epoch_ms($ms), $ms <= {exp};",
        p, HashMap::new()).unwrap().build(issuer).unwrap()
}
fn sign(token: &Biscuit, holder: &SigningKey, peer: &L2AuthenticatedPeer, req: &mut L2ChunkRequest, seq: u64) {
    let wire = make_call(token, holder, &peer.channel_binding, &req.capability_args().unwrap(), seq,
        Transport::MtlsExporter, WireClock { utc_epoch_ms_expiry: Some(now_ms() + 10_000), max_ttl_ms: Some(30_000), skew_ms: Some(2_000), ..Default::default() }).unwrap();
    req.pop_biscuit_token = Some(wire.to_cbor().unwrap());
}

#[test]
fn test_two_node_l2_swarm_authenticated_helper_and_byzantine_receipt() {
    let temp_a = std::env::temp_dir().join(format!("l2_swarm_a_{}", enclave_core::rng::u64()));
    let temp_b = std::env::temp_dir().join(format!("l2_swarm_b_{}", enclave_core::rng::u64()));

    let store_a = ContentStore::open(&temp_a).expect("open store a");
    let store_b = ContentStore::open(&temp_b).expect("open store b");

    // Key generation for Node A (Seeder) and Node B (Leecher)
    let key_a = SigningKey::generate(&mut rand::thread_rng());
    let id_a = hex::encode(key_a.verifying_key().as_bytes());

    let key_b = SigningKey::generate(&mut rand::thread_rng());
    let id_b = hex::encode(key_b.verifying_key().as_bytes());

    // Configure SeedGate on Seeder to ActiveLanOrMeshSeed
    let mut fsm_a = SeedGateFSM::new(Profile::L2);
    fsm_a.update(HostConditions {
        ac_power: true,
        unmetered: true,
        hotspot: false,
        thermal: Thermal::Nominal,
        low_power: false,
    });
    let issuer = KeyPair::new();
    use enclave_core::enterprise_authority::{EnterpriseAuthority,EnterpriseMember,EnterprisePolicy,SignedEnterprisePolicy};
    let membership_issuer=SigningKey::from_bytes(&[42;32]);let now=enclave_crypto::time::now_unix();
    let membership=EnterpriseAuthority::ephemeral(membership_issuer.verifying_key().to_bytes(),SignedEnterprisePolicy::sign(EnterprisePolicy{
        version:1,revision:1,trust_domain:"fixture.example".into(),issued_unix:now-1,expires_unix:now+3600,
        members:vec![EnterpriseMember{principal:"spiffe://fixture.example/engineer/alice".into(),generation:1,holder_public_keys:vec![id_a.clone(),id_b.clone()],namespaces:vec!["models".into()]}],
    },&membership_issuer).unwrap());
    let policy = L2CapabilityPolicy::new(issuer.public(), POLICY).with_enterprise_authority(membership);
    // Fixture transport facts, not evidence of a real TLS exporter or QUIC peer.
    let peer_b = L2AuthenticatedPeer { public_key: key_b.verifying_key().to_bytes(), channel_binding: [7; 32] };
    let node_a = Arc::new(L2SwarmNode::new(key_a, Shard::EU, fsm_a, policy.clone()));
    node_a.authorize_peer(&id_b);

    let fsm_b = SeedGateFSM::new(Profile::L2);
    let node_b = Arc::new(L2SwarmNode::new(key_b, Shard::EU, fsm_b, policy));
    node_b.authorize_peer(&id_a);

    // Prepare 64 KiB test payload on Node A
    let plaintext = vec![0x2au8; 65536];
    let dek = [0x55u8; 32];
    let plain_root = enclave_swarm_syncd::bao::bao_root(&plaintext);
    let pkg = package_transport_artifact(&plaintext, &dek).expect("package artifact");
    let cipher_root = pkg.transport_ciphertext_bao_root;

    // Node A commits plaintext into CAS
    let _meta_a = store_a.put(&plaintext).expect("store a put");

    // Compute expected BLAKE3 hash for each 16 KiB slice
    let slice_size = 16384;
    let num_slices = pkg.bao_stream.len().div_ceil(slice_size);
    let mut expected_slice_hashes = Vec::new();
    for i in 0..num_slices {
        let start = i * slice_size;
        let end = (start + slice_size).min(pkg.bao_stream.len());
        expected_slice_hashes.push(*blake3::hash(&pkg.bao_stream[start..end]).as_bytes());
    }

    let valid_biscuit = grant(&issuer, &node_a, &peer_b, &cipher_root);

    // --- Phase 1: Happy Path Swarm Transfer ---
    let mut received_slices = Vec::new();
    for (i, expected_hash) in expected_slice_hashes.iter().enumerate() {
        let mut req = L2ChunkRequest {
            namespace_id: "models".into(),
            root_hash: cipher_root.clone(),
            slice_index: i as u64,
            pop_biscuit_token: None,
            client_node_id: id_b.clone(),
        };

        sign(&valid_biscuit, &node_b.signing_key, &peer_b, &mut req, i as u64);

        // Node A serves slice
        let resp = node_a
            .handle_request(&peer_b, &req, |_root, idx| {
                let s = idx as usize * slice_size;
                let e = (s + slice_size).min(pkg.bao_stream.len());
                Some(pkg.bao_stream[s..e].to_vec())
            })
            .expect("node a handle");

        // Node B verifies slice in RAM
        let slice_data = node_b
            .verify_slice_or_quarantine(
                &id_a,
                &cipher_root,
                i as u64,
                expected_hash,
                resp,
                "session-export-token-123",
            )
            .expect("node b verify slice");

        received_slices.extend_from_slice(&slice_data);
    }

    assert_eq!(received_slices.len(), pkg.bao_stream.len());

    // Verify and decrypt stream on Node B, then commit to CAS
    let decrypted = enclave_swarm_syncd::transport::ohttp_fetch::verify_and_decrypt_stream(
        &cipher_root,
        pkg.ciphertext_len,
        &received_slices,
        &dek,
        &plain_root,
    )
    .expect("verify and decrypt");

    let meta_b = store_b.put(&decrypted).expect("store b put");
    assert_eq!(meta_b.blake3, plain_root);
    assert!(store_b.contains(&plain_root));

    // --- Phase 2: Byzantine Injection & Quarantine ---
    let poisoned_resp = L2ChunkResponse::Data {
        slice_index: 0,
        slice_bytes: vec![0xde, 0xad, 0xbe, 0xef], // Corrupted slice
    };

    let res = node_b.verify_slice_or_quarantine(
        &id_a,
        &cipher_root,
        0,
        &expected_slice_hashes[0],
        poisoned_resp,
        "session-export-token-123",
    );

    assert!(res.is_err(), "poisoned slice must fail");
    let err_str = format!("{:?}", res.err().unwrap());
    assert!(err_str.contains("BAO_SLICE_CORRUPT"));

    // Offending peer Node A is now quarantined (removed from authorized peers and entered into QuarantineTable)
    assert!(
        !node_b.authorized_peers.lock().unwrap().contains(&id_a),
        "Node A must be quarantined after Byzantine poisoning"
    );
    assert!(node_b.quarantine_table.is_quarantined(&id_a));
    assert_eq!(node_b.poison_receipts.lock().unwrap().len(), 1);

    // --- Phase 3: Constant-time CHUNK_UNAVAILABLE ---
    let mut req_unknown = L2ChunkRequest {
        namespace_id: "models".into(),
        root_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
        slice_index: 0,
        pop_biscuit_token: None,
        client_node_id: id_b.clone(),
    };

    let unknown_grant = grant(&issuer, &node_a, &peer_b, &req_unknown.root_hash);
    sign(&unknown_grant, &node_b.signing_key, &peer_b, &mut req_unknown, 0);
    let mut storage_reads = 0;
    let resp_unavail = node_a
        .handle_request(&peer_b, &req_unknown, |_, _| { storage_reads += 1; None })
        .expect("handle unknown");

    assert_eq!(storage_reads, 1, "authorized cache miss must reach storage");
    match resp_unavail {
        L2ChunkResponse::Unavailable(frame) => {
            assert_eq!(frame.len(), UNAVAILABLE_FRAME_SIZE);
            assert!(is_unavailable_frame(&frame));
        }
        _ => panic!("expected unavailable frame"),
    }
}
