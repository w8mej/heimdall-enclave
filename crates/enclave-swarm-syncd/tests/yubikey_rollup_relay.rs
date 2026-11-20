//! YK-23 / YKD-10: real CAS -> OHTTP -> ledger accounting path, with independently
//! TUF-distributed software test authorities. No hardware/privacy qualification.
use enclave_core::{ipc::PeerCredentials, profile::Profile};
use enclave_crypto::{ohttp::gateway_keypair, tuf::RepoBuilder};
use enclave_swarm_syncd::{outbox::measure_outbox_disk, revocation::Enforcement,
    service::{CasConfig, CasRequest, CasResponse, CasService}};
use enclave_zk_auditor::{receiver_trust::ReceiverTrust,
    rollup::{ComplianceRollupProofV1 as Frame, MAX_FRAME_BYTES}, zk::manifest::VkManifestV1};

#[path = "support/rollup_authority.rs"]
mod rollup_authority;

#[test]
fn relay_verifies_signed_authority_exact_bytes_and_shared_receiver_path() {
    for profile in [Profile::L2, Profile::L3] {
        let directory = std::env::temp_dir().join(format!("yk-relay-{}-{:x}",
            std::process::id(), enclave_core::rng::u64()));
        let repository = RepoBuilder::new(3, 2);
        let (key_config, secret) = gateway_keypair(3);
        let peer = PeerCredentials::local(enclave_core::ipc::geteuid(), 0);
        let store = directory.join("store");
        let service = CasService::start(CasConfig { dev_same_uid: true, profile,
            store_dir: store.clone(), audit_path: None,
            tuf_root: Some(repository.root(rollup_authority::EXP).unwrap()),
            ohttp_gateway: Some(key_config.clone()), state_dir: None,
            revocation: Enforcement::InProcess }).unwrap();
        let authority = rollup_authority::Authority::new(profile);
        let valid = authority.frame(0x11);
        assert!(service.handle(&peer, CasRequest::RelayRollup {frame: valid.clone().into()}).is_err(),
            "an unrefreshed root alone cannot supply receiver authority");
        authority.install(&service, &store, &repository, &peer);
        assert!(service.handle(&peer, CasRequest::RelayRollup {
            frame: vec![0xff; MAX_FRAME_BYTES + 1].into() }).unwrap_err().is("ROLLUP_FRAME_TOO_LARGE"));
        assert!(measure_outbox_disk(&store.join("ohttp-outbox")).unwrap().1.is_empty());

        let mut changed = Frame::decode(&valid).unwrap();
        changed.proof[0] ^= 0x40;
        let mut encoded = Vec::new();
        ciborium::into_writer(&changed, &mut encoded).unwrap();
        assert!(service.handle(&peer, CasRequest::RelayRollup {frame: encoded.into()}).is_err());
        let mut changed = Frame::decode(&valid).unwrap();
        changed.v = 3;
        let mut encoded = Vec::new();
        ciborium::into_writer(&changed, &mut encoded).unwrap();
        assert!(service.handle(&peer, CasRequest::RelayRollup {frame: encoded.into()}).is_err());

        // The same public document under different bytes is not TUF authority.
        let trust_path = store.join(enclave_zk_auditor::receiver_trust::TRUST_TARGET);
        std::fs::write(&trust_path, b"{}").unwrap();
        assert!(service.handle(&peer, CasRequest::RelayRollup {frame: valid.clone().into()}).is_err());
        std::fs::write(&trust_path, &authority.trust).unwrap();
        assert!(measure_outbox_disk(&store.join("ohttp-outbox")).unwrap().1.is_empty());

        assert!(matches!(service.handle(&peer, CasRequest::RelayRollup {frame: valid.into()}).unwrap(), CasResponse::Queued));
        let pending = measure_outbox_disk(&store.join("ohttp-outbox")).unwrap().1;
        assert_eq!(pending.len(), 1);
        let gateway = ledger_gateway::LedgerGateway::with_keys(key_config, secret.clone(),
            VkManifestV1::production_hiding())
            .with_receiver_trust(ReceiverTrust::from_json(&authority.trust).unwrap());
        let encrypted = std::fs::read(&pending[0]).unwrap();
        // Outer transport has measured, bounded overhead beyond the complete
        // compliance frame: fixed BHTTP headers, 7-byte suite header, hybrid
        // encapsulation and AEAD tag. The 320 KiB bound ends before these.
        let (path, body) = enclave_crypto::ohttp::bhttp_parse(
            &enclave_crypto::ohttp::decapsulate(3, &secret, &encrypted).unwrap()).unwrap();
        assert_eq!(path, enclave_zk_auditor::rollup::LEDGER_PATH);
        let bhttp = enclave_crypto::ohttp::bhttp_post(
            enclave_zk_auditor::rollup::LEDGER_AUTHORITY, &path, "application/cbor", &body);
        assert_eq!(encrypted.len(), bhttp.len() + 7
            + enclave_crypto::pqc::HYBRID_KEM_CIPHERTEXT_SIZE + 16);
        assert!(bhttp.len() - body.len() < 256);
        assert!(body.len() <= MAX_FRAME_BYTES);
        if profile == Profile::L3 { assert_eq!(body.len(), MAX_FRAME_BYTES); }
        let accepted = gateway.handle_ohttp_post(&encrypted).unwrap();
        assert!(accepted.accepted);
        assert_eq!(accepted.profile, profile.number());
        assert!(gateway.handle_ohttp_post(&encrypted).unwrap().duplicate);
        drop(service);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
