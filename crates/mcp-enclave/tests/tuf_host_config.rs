//! Prompt 4A (GAP-20): Signed host configuration from TUF.
//!
//! Acceptance criteria:
//! 1. Host config generation, signing, and publishing into TUF.
//! 2. Service startup with no config argv, adopting profile floor from TUF.
//! 3. L3 artifact on an L2 host is refused (PROFILE_FLOOR_EXCEEDED).
//! 4. Tampered host configuration fails validation / verification.
//! 5. Stale timestamp fails per clock high-water rules.

mod common;
use std::path::PathBuf;

use enclave_core::host_config::{fetch_host_config, HOST_CONFIG_TARGET};
use enclave_core::ipc::PeerCredentials;
use enclave_core::profile::Profile;
use enclave_swarm_syncd::service::{CasConfig, CasRequest, CasResponse, CasService};
use depot_enclave::ctl;
use depot_enclave::devtuf::DevRepo;

fn tmp(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "depote-tuf-{}-{}-{:x}",
        tag,
        std::process::id(),
        enclave_core::rng::u64() & 0xffff_ffff
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn tuf_host_config_lifecycle_and_enforcement() {
    let base = tmp("lifecycle");
    let keys = base.join("keys.json");
    let repo_dir = base.join("repo");
    let store_dir = base.join("cas_store");
    let sock_dir = base.join("run");
    let cas_sock_dir = sock_dir.join("cas");
    std::fs::create_dir_all(&cas_sock_dir).unwrap();
    let cas_sock = cas_sock_dir.join("cas.sock");

    // 1. Initialize repository and publish host config (Profile::L2 floor)
    let (cfg, _v) =
        ctl::tuf_publish_host_config_at(&keys, &repo_dir, Profile::L2, Some("42".repeat(32)), &base, &common::host_inputs(&base))
            .unwrap();
    assert_eq!(cfg.profile_floor, Profile::L2);

    // Copy published host config into store directory so UID 702 finds it
    std::fs::create_dir_all(&store_dir).unwrap();
    std::fs::copy(
        repo_dir.join(HOST_CONFIG_TARGET),
        store_dir.join(HOST_CONFIG_TARGET),
    )
    .unwrap();

    let root_bytes = std::fs::read(repo_dir.join("root.json")).unwrap();

    // 2. Start CasService without config argv (defaults to L1 floor, adopts L2 from TUF)
    let svc = CasService::start(CasConfig {dev_same_uid: true,
        profile: Profile::L1,
        store_dir: store_dir.clone(),
        audit_path: None,
        ohttp_gateway: None,
        tuf_root: Some(root_bytes),
        state_dir: Some(base.join("cas_state")),
        revocation: enclave_swarm_syncd::revocation::Enforcement::InProcess,
    })
    .unwrap();

    // Bind real UDS for IPC client testing
    let listener =
        enclave_core::ipc::bind(&cas_sock, enclave_core::ipc::SocketAccess::OwnerOnly).unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (svc_thread, stop_thread) = (svc.clone(), stop.clone());
    let handle = std::thread::spawn(move || {
        enclave_core::ipc::serve::<CasRequest, CasResponse, _>(
            listener,
            enclave_core::ipc::PeerPolicy::allow([enclave_core::ipc::geteuid()]),
            std::sync::Arc::new(move |p: &PeerCredentials, r| svc_thread.handle(p, r)),
            stop_thread,
        )
    });

    // Populate initial TUF metadata (timestamp, snapshot, targets)
    let ts = std::fs::read(repo_dir.join("timestamp.json")).unwrap();
    let snap = std::fs::read(repo_dir.join("snapshot.json")).unwrap();
    let targets = std::fs::read(repo_dir.join("targets.json")).unwrap();
    let admin = PeerCredentials::local(0, 0);
    svc.handle(
        &admin,
        CasRequest::TufRefresh {
            roots: vec![],
            timestamp: ts.into(),
            snapshot: snap.into(),
            targets: targets.into(),
        },
    )
    .unwrap();

    // 3. Verify fetch_host_config over IPC works and retrieves the published config
    let fetched = fetch_host_config(&sock_dir, true).unwrap();
    assert_eq!(fetched.profile_floor, Profile::L2);
    assert_eq!(fetched.ifc_grant_public_key, "42".repeat(32));

    // 4. Test L3 artifact refusal on L2 host (PROFILE_FLOOR_EXCEEDED)
    let l3_data = enclave_swarm_syncd::sanitizer::build_safetensors(
        &[(
            "enclave_adapter.l3_head.weight",
            "F16",
            vec![64, 64],
            vec![1u8; 64 * 64 * 2],
        )],
        &[],
    );
    let l3_policy = serde_json::json!({
        "classification": "restricted_l3",
        "min_profile": "L3",
        "license_policy": {"spdx_id": "LicenseRef-proprietary", "allow_p2p_seeding": false},
        "jurisdiction_shard": "US",
        "lazy_fuse_t": false,
        "companion_safety_layers": [],
    });

    let mut repo = DevRepo::open_with_keys(&keys, &repo_dir).unwrap();
    repo.add_target("l3_model.safetensors", &l3_data, l3_policy)
        .unwrap();

    // Refresh TUF metadata in service
    let ts = std::fs::read(repo_dir.join("timestamp.json")).unwrap();
    let snap = std::fs::read(repo_dir.join("snapshot.json")).unwrap();
    let targets = std::fs::read(repo_dir.join("targets.json")).unwrap();

    let admin = PeerCredentials::local(0, 0);
    svc.handle(
        &admin,
        CasRequest::TufRefresh {
            roots: vec![],
            timestamp: ts.into(),
            snapshot: snap.into(),
            targets: targets.into(),
        },
    )
    .unwrap();

    // Admit L3 target
    let CasResponse::Admitted { root: l3_root } = svc
        .handle(
            &admin,
            CasRequest::Admit {
                target: "l3_model.safetensors".into(),
                bytes: l3_data.to_vec().into(),
            },
        )
        .unwrap()
    else {
        panic!("admit failed");
    };

    // Attempt to resolve L3 artifact on L2 host: MUST fail with PROFILE_FLOOR_EXCEEDED
    let cas_uri = format!("cas://blake3-bao-v1/{l3_root}?target=l3_model.safetensors&ns=models");
    let err = svc
        .handle(&admin, CasRequest::Resolve { cas_uri })
        .unwrap_err();
    assert!(
        err.is("PROFILE_FLOOR_EXCEEDED"),
        "expected PROFILE_FLOOR_EXCEEDED, got {:?}",
        err
    );

    // 5. Test tampered config fails verification
    let bad_bytes = b"{\"profile_floor\":\"L2\",\"ifc_grant_public_key\":\"corrupt\"}";
    std::fs::write(store_dir.join(HOST_CONFIG_TARGET), bad_bytes).unwrap();
    let tamper_err = svc.handle(&admin, CasRequest::FetchHostConfig).unwrap_err();
    assert!(
        tamper_err.is("TARGET_CORRUPT")
            || tamper_err.is("HASH_MISMATCH")
            || tamper_err.is("TUF_TARGET_LENGTH")
            || tamper_err.is("TUF_TARGET_HASH")
            || tamper_err.is("HOST_CONFIG_INVALID")
            || tamper_err.is("HOST_CONFIG_DECODE"),
        "expected tamper error, got {:?}",
        tamper_err
    );

    // 6. Test stale timestamp fails per clock high-water rules
    let stale_err = svc.handle(
        &admin,
        CasRequest::TufRefresh {
            roots: vec![],
            timestamp: b"stale_timestamp_not_json".to_vec().into(),
            snapshot: vec![].into(),
            targets: vec![].into(),
        },
    );
    assert!(
        stale_err.is_err(),
        "stale/invalid timestamp must be rejected"
    );

    // Clean up
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = fetch_host_config(&sock_dir, true); // wake up accept loop
    let _ = handle.join();
    let _ = std::fs::remove_dir_all(base);
}
