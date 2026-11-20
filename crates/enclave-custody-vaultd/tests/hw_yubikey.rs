//! Real authenticator checks. Run explicitly via scripts/validate-custody-hardware.sh.
//! Enrollment creates a retained nonresident credential; deletion is not assumed.
//! This is never a read-only diagnostic. Use enclave-fido-diagnostic for discovery.
#[cfg(all(target_os = "macos", feature = "macos-hid"))]
#[test]
#[ignore = "requires physical authenticator, actual UV and MCPMAC_HW=1"]
fn physical_yubikey_gap13_matrix() {
    use enclave_core::profile::Profile;
    use enclave_custody_vaultd::ctap::{
        assertion::{verify_assertion, SignCountStore, FLAG_UV},
        client::{decrypt_prf, enroll, CtapClient},
        macos_hid::MacHidDevice,
        mds::MdsState,
    };
    assert_eq!(
        std::env::var("MCPMAC_HW").as_deref(),
        Ok("1"),
        "physical tests require explicit opt-in"
    );
    assert_eq!(std::env::var("MCPMAC_HW_OPERATION").as_deref(), Ok("enroll-and-assert"),
        "explicit enrollment/assertion scope required; use the diagnostic binary for read-only discovery");
    let mut dev: Box<dyn enclave_custody_vaultd::ctap::hid::HidDevice + Send> = if let Ok(value) =
        std::env::var("MCPMAC_EXPECTED_AAGUID")
    {
        let expected: [u8; 16] = hex::decode(value)
            .unwrap()
            .try_into()
            .expect("32-hex AAGUID");
        enclave_custody_vaultd::ctap::transport::Transport::Hid
            .open_enrolled(enclave_core::ipc::geteuid(), &expected)
            .unwrap()
    } else {
        Box::new(
            MacHidDevice::open_first().expect("one physical FIDO authenticator must be present"),
        )
    };
    let depth = dev.hub_depth();
    let mut client = CtapClient::open(dev.as_mut()).unwrap();
    let info = client.get_info().unwrap();
    // Before makeCredential: this harness has no secure host PIN provider.
    // Refuse PIN-only devices without creating an unusable test credential.
    assert!(info.built_in_uv, "BLOCKED: no secure PIN provider in this harness; no credential created");
    assert!(info.extensions.iter().any(|e| e == "hmac-secret") && info.pin_uv_protocols.contains(&2),
        "BLOCKED: required PRF/protocol-2 capabilities missing; no credential created");
    eprintln!("EFFECTS: scoped nonresident enrollment + UV assertions; counters/authentication state may advance. Existing PINs, credentials, applets and interfaces are preserved. No deletion/reset rollback is available.");
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../packaging/fido-mds/yubico.json");
    let mds = MdsState::from_verified_target(
        &std::fs::read(path).unwrap(),
        enclave_crypto::time::now_unix(),
    )
    .unwrap();
    let cred = enroll(
        &mut client,
        &mds,
        Profile::L3,
        enclave_crypto::time::now_unix(),
    )
    .unwrap();
    eprintln!("RETAINED_ARTIFACT: MCPMac nonresident credential created; its handle is intentionally not logged. This harness does not persist an enrolled identity or delete the credential; use controlled enrollment for reusable custody state.");
    let mut counts = SignCountStore::default();
    let salt = [0x55; 32];
    let mut first_prf: Option<enclave_core::secret::SecretBytes> = None;
    let mut uv_flags = Vec::new();
    for _ in 0..2 {
        let mut challenge = [0; 32];
        enclave_core::rng::fill(&mut challenge);
        let (resp,shared)=client.get_assertion(&cred.credential_id,&challenge,true,Some(&salt))
    .expect("actual required UV must succeed; PIN-only models remain blocked until secure PIN token support exists");
        let verified = verify_assertion(&cred, &resp, &challenge, true, &mut counts)
            .expect("signature,UP,UV,counter");
        assert!(verified.user_verified);
        let flags = resp.auth_data[32];
        assert_ne!(flags & FLAG_UV, 0);
        uv_flags.push(flags);
        let prf = decrypt_prf(
            &shared.unwrap(),
            verified
                .hmac_secret_enc
                .as_ref()
                .expect("signed hmac-secret extension"),
        )
        .unwrap();
        if let Some(first) = &first_prf {
            assert_eq!(
                first.expose(),
                prf.expose(),
                "UV hmac-secret must reproduce"
            );
        } else {
            first_prf = Some(prf);
        }
        assert!(
            verify_assertion(&cred, &resp, &challenge, true, &mut counts)
                .unwrap_err()
                .is("SIGN_COUNT_REGRESSION")
        );
    }
    println!(
        "{}",
        serde_json::json!({"event":"AUTHENTICATOR_UV_RESULT","aaguid":hex::encode(info.aaguid),
 "firmware":info.firmware_version,"hub_depth":depth,"built_in_uv":info.built_in_uv,"verified_uv_flags":uv_flags,
 "scope":"CTAP assertions only; complete L3 A4 SEP/UI ceremony separately required","status":"PASS"})
    );
}
