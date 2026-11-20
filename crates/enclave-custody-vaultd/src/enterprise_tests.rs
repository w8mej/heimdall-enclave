//! Portable actual-service authority fixtures; simulated factors remain marked.
use super::*;
use enclave_core::enterprise_authority::{
    EnterpriseAuthority, EnterpriseMember, EnterprisePolicy, NamespaceProof, SignedEnterprisePolicy,
};
use enclave_crypto::namespace::{CasKeyLease, WrappedNamespaceKey};

struct Fixture {
    service: Arc<VaultService>,
    authority: Arc<EnterpriseAuthority>,
    wrapped: WrappedNamespaceKey,
    issuer: SigningKey,
    alice: SigningKey,
    bob: SigningKey,
}
impl Fixture {
    fn new() -> Self {
        let now = enclave_crypto::time::now_unix();
        let issuer = SigningKey::from_bytes(&[41; 32]);
        let alice = SigningKey::from_bytes(&[42; 32]);
        let bob = SigningKey::from_bytes(&[43; 32]);
        let service = VaultService::start(
            VaultConfig {
                profile: Profile::L2,
                ..VaultConfig::default()
            },
            VaultHardware::simulated(Profile::L2, now).unwrap(),
        )
        .unwrap();
        let wrapped = match service
            .handle(
                &PeerCredentials::local(0, 0),
                VaultRequest::WrapCasKey {
                    namespace: "models".into(),
                    epoch: 1,
                    wrapping_epoch: 1,
                    key: enclave_crypto::namespace::SecretMaterial(vec![7; 32]),
                },
            )
            .unwrap()
        {
            VaultResponse::WrappedCasKey(wrapped) => wrapped,
            _ => panic!("wrap response"),
        };
        let policy = Self::policy(&alice, &bob, 1, true);
        let authority = EnterpriseAuthority::ephemeral_with_release_serial(
            issuer.verifying_key().to_bytes(),
            SignedEnterprisePolicy::sign(policy, &issuer).unwrap(),
            service.namespace_release_serial(),
        );
        service.set_enterprise_authority(authority.clone()).unwrap();
        Self {
            service,
            authority,
            wrapped,
            issuer,
            alice,
            bob,
        }
    }
    fn policy(
        alice: &SigningKey,
        bob: &SigningKey,
        revision: u64,
        include_alice: bool,
    ) -> EnterprisePolicy {
        let now = enclave_crypto::time::now_unix();
        let mut members = vec![EnterpriseMember {
            principal: "spiffe://fixture.example/engineer/bob".into(),
            generation: 1,
            holder_public_keys: vec![hex::encode(bob.verifying_key().as_bytes())],
            namespaces: vec!["models".into()],
        }];
        if include_alice {
            members.push(EnterpriseMember {
                principal: "spiffe://fixture.example/engineer/alice".into(),
                generation: 1,
                holder_public_keys: vec![hex::encode(alice.verifying_key().as_bytes())],
                namespaces: vec!["models".into()],
            });
        }
        EnterprisePolicy {
            version: 1,
            revision,
            trust_domain: "fixture.example".into(),
            issued_unix: now - 1,
            expires_unix: now + 3600,
            members,
        }
    }
    fn proof(&self, holder: &SigningKey, principal: &str) -> NamespaceProof {
        self.proof_for_peer(holder, principal, &PeerCredentials::local(0, 0))
    }
    fn proof_for_peer(
        &self,
        holder: &SigningKey,
        principal: &str,
        peer: &PeerCredentials,
    ) -> NamespaceProof {
        let (challenge, boot_epoch, expires_unix) = match self
            .service
            .handle(
                peer,
                VaultRequest::NamespaceKeyChallenge {
                    wrapped: self.wrapped.clone(),
                },
            )
            .unwrap()
        {
            VaultResponse::NamespaceKeyChallenge {
                challenge,
                boot_epoch,
                expires_unix,
            } => (challenge, boot_epoch, expires_unix),
            _ => panic!("challenge response"),
        };
        let mut proof = NamespaceProof {
            principal: format!("spiffe://fixture.example/engineer/{principal}"),
            holder_public_key: String::new(),
            challenge,
            boot_epoch,
            envelope_blake3: VaultService::envelope_digest(&self.wrapped).unwrap(),
            expires_unix,
            signature_hex: String::new(),
        };
        proof.sign(holder).unwrap();
        proof
    }
    fn release(&self, holder: &SigningKey, principal: &str) -> EnclaveResult<CasKeyLease> {
        match self.service.handle(
            &PeerCredentials::local(0, 0),
            VaultRequest::UnwrapCasKeyAuthorized {
                wrapped: self.wrapped.clone(),
                proof: self.proof(holder, principal),
            },
        )? {
            VaultResponse::CasKey { key, lease } => {
                assert_eq!(key.0, vec![7; 32]);
                Ok(lease)
            }
            _ => panic!("key response"),
        }
    }
    fn offboard_alice(&self) {
        self.authority
            .replace_ephemeral(
                SignedEnterprisePolicy::sign(
                    Self::policy(&self.alice, &self.bob, 2, false),
                    &self.issuer,
                )
                .unwrap(),
            )
            .unwrap();
        self.authority
            .refresh(enclave_crypto::time::now_unix())
            .unwrap();
    }
}
#[test]
fn enterprise_actual_vault_requires_proof_and_rejects_wrong_principal_holder_and_replay() {
    let f = Fixture::new();
    let operator = PeerCredentials::local(0, 0);
    assert!(f
        .service
        .handle(
            &operator,
            VaultRequest::UnwrapCasKey {
                wrapped: f.wrapped.clone()
            }
        )
        .unwrap_err()
        .is("ENTERPRISE_PROOF_REQUIRED"));
    assert!(f
        .release(&f.alice, "bob")
        .unwrap_err()
        .is("ENTERPRISE_PRINCIPAL_MISMATCH"));
    assert!(f
        .release(&SigningKey::from_bytes(&[44; 32]), "alice")
        .is_err());
    let proof = f.proof(&f.alice, "alice");
    let request = VaultRequest::UnwrapCasKeyAuthorized {
        wrapped: f.wrapped.clone(),
        proof,
    };
    let lease = match f.service.handle(&operator, request.clone()).unwrap() {
        VaultResponse::CasKey { key, lease } => {
            assert_eq!(key.0, vec![7; 32]);
            lease
        }
        _ => panic!(),
    };
    assert_eq!(
        lease.enterprise.as_ref().unwrap().principal,
        "spiffe://fixture.example/engineer/alice"
    );
    assert!(f
        .service
        .handle(&operator, request)
        .unwrap_err()
        .is("ENTERPRISE_CHALLENGE_REPLAY"));
    assert!(f
        .service
        .handle(
            &PeerCredentials::local(999, 0),
            VaultRequest::CheckCasKeyLease(lease)
        )
        .is_err());
}
#[test]
fn enterprise_actual_vault_offboarding_revokes_one_principal_and_preserves_other() {
    let f = Fixture::new();
    let operator = PeerCredentials::local(0, 0);
    let alice = f.release(&f.alice, "alice").unwrap();
    let bob = f.release(&f.bob, "bob").unwrap();
    f.offboard_alice();
    assert!(f
        .service
        .handle(&operator, VaultRequest::CheckCasKeyLease(alice))
        .is_err());
    assert!(f
        .service
        .handle(&operator, VaultRequest::CheckCasKeyLease(bob))
        .is_ok());
    assert!(f.release(&f.alice, "alice").is_err());
    assert!(f.release(&f.bob, "bob").is_ok());
}
#[test]
fn enterprise_actual_vault_challenge_binds_envelope_boot_signature_and_expiry() {
    for field in 0..5 {
        let f = Fixture::new();
        let mut proof = f.proof(&f.alice, "alice");
        let mut wrapped = f.wrapped.clone();
        match field {
            0 => wrapped.epoch += 1,
            1 => {
                proof.boot_epoch.push('x');
                proof.sign(&f.alice).unwrap();
            }
            2 => {
                proof.expires_unix -= 1;
                proof.sign(&f.alice).unwrap();
            }
            3 => proof.signature_hex = "00".repeat(64),
            _ => {
                proof.envelope_blake3 = "11".repeat(32);
                proof.sign(&f.alice).unwrap();
            }
        }
        assert!(
            f.service
                .handle(
                    &PeerCredentials::local(0, 0),
                    VaultRequest::UnwrapCasKeyAuthorized { wrapped, proof }
                )
                .is_err(),
            "field {field}"
        );
    }
}
#[test]
fn enterprise_actual_ipc_final_key_handoff_observes_offboarding_and_tamper_fences() {
    use enclave_core::ipc::{self, PeerPolicy, SocketAccess};
    use std::os::unix::fs::PermissionsExt;
    use std::{
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };
    for offboard in [true, false] {
        let f = Fixture::new();
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .canonicalize()
            .unwrap()
            .join(format!("ei-{:x}", enclave_core::rng::u64()));
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Keep the bound pathname below Darwin SUN_LEN even when the runner's
        // checkout has a long absolute prefix. Do not change the process-wide cwd.
        let current = std::env::current_dir().unwrap();
        let from: Vec<_> = current.components().collect();
        let to: Vec<_> = directory.components().collect();
        let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
        let mut relative = std::path::PathBuf::new();
        for _ in common..from.len() {
            relative.push("..");
        }
        for component in &to[common..] {
            relative.push(component.as_os_str());
        }
        let socket = relative.join("vault.sock");
        let listener = ipc::bind(&socket, SocketAccess::OwnerOnly).unwrap();
        let service = f.service.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let (prepared_tx, prepared_rx) = std::sync::mpsc::channel();
        let (continue_tx, continue_rx) = std::sync::mpsc::channel();
        let gate = Mutex::new(Some((prepared_tx, continue_rx)));
        let server = std::thread::spawn(move || {
            ipc::serve(
                listener,
                PeerPolicy::allow([ipc::geteuid()]),
                Arc::new(move |peer: &PeerCredentials, request: VaultRequest| {
                    let result = service.handle(peer, request);
                    if let Some((prepared, continuation)) = gate.lock().unwrap().take() {
                        assert!(result.is_ok(), "{result:?}");
                        prepared.send(()).unwrap();
                        continuation.recv_timeout(Duration::from_secs(5)).unwrap();
                    }
                    result
                }),
                stopped,
            )
        });
        let request = VaultRequest::UnwrapCasKeyAuthorized {
            wrapped: f.wrapped.clone(),
            proof: f.proof_for_peer(
                &f.alice,
                "alice",
                &PeerCredentials::local(ipc::geteuid(), 0),
            ),
        };
        let path = socket.clone();
        let client = std::thread::spawn(move || {
            let mut client = ipc::Client::connect(&path, ipc::geteuid()).unwrap();
            client.set_timeout(Some(Duration::from_secs(5))).unwrap();
            client.call::<_, VaultResponse>(&request)
        });
        prepared_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        if offboard {
            f.offboard_alice();
        } else {
            f.service
                .handle(
                    &PeerCredentials::local(0, 0),
                    VaultRequest::Tamper(TamperEvent::ScreenLock),
                )
                .unwrap();
        }
        continue_tx.send(()).unwrap();
        assert!(client.join().unwrap().is_err());
        stop.store(true, Ordering::SeqCst);
        server.join().unwrap().unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }
}
