//! Prompt 1D (GAP-19 L1): GC, 168-hour offline TTL with fake clock, APFS clonefile, and PF fence.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicI64, Ordering};

use enclave_core::ipc::PeerCredentials;
use enclave_core::profile::Profile;
use enclave_crypto::tuf::{target_file, RepoBuilder};
use enclave_swarm_syncd::cas::ContentStore;
use enclave_swarm_syncd::fuse::{render_fuse_pf_rules, FUSE_T_NFS_PORT, FUSE_T_PF_ANCHOR};
use enclave_swarm_syncd::sanitizer::build_safetensors;
use enclave_swarm_syncd::service::{CasConfig, CasRequest, CasResponse, CasService};
use enclave_swarm_syncd::snapshot::{clonefile, probe_fs_snapshot_capability};
use serde_json::json;

const EXP: &str = "2030-01-01T00:00:00Z";
const NOW: i64 = 1_793_884_860;
static WALL: AtomicI64 = AtomicI64::new(NOW);

fn wall() -> i64 {
    WALL.load(Ordering::SeqCst)
}

fn tmp_dir(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "mcpmac-l1-test-{}-{name}",
        enclave_core::rng::u64()
    ));
    use std::os::unix::fs::DirBuilderExt;
    // This helper also provisions persisted TUF authority. Match the daemon's
    // private state contract explicitly instead of depending on process umask.
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&p).unwrap();
    p.canonicalize().unwrap()
}

fn sample_weights(tag: u8) -> Vec<u8> {
    build_safetensors(
        &[(
            "enclave_adapter.test.weight",
            "F16",
            vec![16, 16],
            vec![tag; 16 * 16 * 2],
        )],
        &[],
    )
}

#[test]
fn test_cas_ref_counted_gc_pruning() {
    let dir = tmp_dir("gc");
    let store = ContentStore::open(&dir).unwrap();

    let data_a = b"Data blob A: chunk A and shared chunk S 12345678901234567890";
    let data_b = b"Data blob B: chunk B and shared chunk S 12345678901234567890";

    // Commit both blobs into the store
    let root_a = store.put(data_a).unwrap().blake3;
    let root_b = store.put(data_b).unwrap().blake3;

    let roots = store.roots().unwrap();
    assert_eq!(roots.len(), 2);
    assert!(roots.contains(&root_a));
    assert!(roots.contains(&root_b));

    // Get chunks referenced by A and B
    let chunks_a: BTreeSet<String> = store
        .manifest(&root_a)
        .unwrap()
        .chunks
        .into_iter()
        .map(|c| c.blake3)
        .collect();
    let chunks_b: BTreeSet<String> = store
        .manifest(&root_b)
        .unwrap()
        .chunks
        .into_iter()
        .map(|c| c.blake3)
        .collect();

    // Verify all chunks exist in the chunks directory
    for c in chunks_a.union(&chunks_b) {
        assert!(dir.join("chunks").join(c).exists(), "Chunk {c} must exist");
    }

    // Now revoke A
    let removed = store.revoke(&root_a).unwrap();
    assert!(removed > 0, "Revoking A must delete at least 1 chunk");

    // Manifest and materialised object for A must be gone
    assert!(!store.contains(&root_a));
    assert!(!dir.join("objects").join(&root_a).exists());

    // Manifest and materialised object for B must remain
    assert!(store.contains(&root_b));

    // Chunks unique to A must be deleted
    for c in chunks_a.difference(&chunks_b) {
        assert!(
            !dir.join("chunks").join(c).exists(),
            "Unique chunk {c} must be pruned by GC"
        );
    }

    // Chunks belonging to B must remain
    for c in &chunks_b {
        assert!(
            dir.join("chunks").join(c).exists(),
            "Chunk {c} belonging to B must remain"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_168h_offline_ttl_safe_fail_lockdown() {
    let r = RepoBuilder::new(3, 2);
    let root = r.root(EXP).unwrap();

    let pub_data = sample_weights(1);
    let int_data = sample_weights(2);

    let pub_policy = json!({
        "classification": "public_l1",
        "min_profile": "L1",
        "license_policy": {"spdx_id": "Apache-2.0", "allow_p2p_seeding": true},
        "jurisdiction_shard": "EU",
        "lazy_fuse_t": false,
        "companion_safety_layers": []
    });

    let int_policy = json!({
        "classification": "internal_l2",
        "min_profile": "L2",
        "license_policy": {"spdx_id": "LicenseRef-proprietary", "allow_p2p_seeding": false},
        "jurisdiction_shard": "EU",
        "lazy_fuse_t": false,
        "companion_safety_layers": []
    });

    let mut t = BTreeMap::new();
    t.insert(
        "public.safetensors".to_string(),
        target_file(&pub_data, Some(pub_policy)),
    );
    t.insert(
        "internal.safetensors".to_string(),
        target_file(&int_data, Some(int_policy)),
    );

    let t_bytes = r.targets(1, EXP, t).unwrap();
    let s_bytes = r.snapshot(1, EXP, 1, &t_bytes).unwrap();
    let ts_bytes = r.timestamp(1, EXP, 1, &s_bytes).unwrap();

    let store_dir = tmp_dir("ttl_store");
    let state_dir = tmp_dir("ttl_state");

    let cfg = CasConfig {dev_same_uid: true,
        profile: Profile::L1,
        store_dir: store_dir.clone(),
        audit_path: None,
        tuf_root: Some(root.clone()),
        ohttp_gateway: None,
        state_dir: Some(state_dir.clone()),
        revocation: enclave_swarm_syncd::revocation::Enforcement::Unavailable,
    };

    let me = PeerCredentials::local(0, 0);
    WALL.store(NOW, Ordering::SeqCst);
    let svc = CasService::start_with_wall_clock(cfg, wall).unwrap();

    // Refresh TUF
    let refresh_req = CasRequest::TufRefresh {
        roots: vec![],
        timestamp: ts_bytes.into(),
        snapshot: s_bytes.into(),
        targets: t_bytes.into(),
    };
    let resp = svc.handle(&me, refresh_req).unwrap();
    match resp {
        CasResponse::Tuf { versions } => assert_eq!(versions, (1, 1, 1)),
        other => panic!("Unexpected response: {other:?}"),
    }

    // Admit both targets
    svc.handle(
        &me,
        CasRequest::Admit {
            target: "public.safetensors".to_string(),
            bytes: pub_data.clone().into(),
        },
    )
    .unwrap();

    svc.handle(
        &me,
        CasRequest::Admit {
            target: "internal.safetensors".to_string(),
            bytes: int_data.clone().into(),
        },
    )
    .unwrap();

    let pub_root = enclave_swarm_syncd::bao::bao_root(&pub_data);
    let int_root = enclave_swarm_syncd::bao::bao_root(&int_data);

    let pub_uri = format!("cas://blake3-bao-v1/{pub_root}?target=public.safetensors&ns=corp");
    let int_uri = format!("cas://blake3-bao-v1/{int_root}?target=internal.safetensors&ns=corp");

    // Both resolve initially
    let pub_init = svc.handle(
        &me,
        CasRequest::Fetch {
            cas_uri: pub_uri.clone(),
        },
    );
    assert!(pub_init.is_ok(), "Initial pub fetch failed: {pub_init:?}");
    let int_init = svc.handle(
        &me,
        CasRequest::Fetch {
            cas_uri: int_uri.clone(),
        },
    );
    assert!(int_init.is_ok(), "Initial int fetch failed: {int_init:?}");

    // Advance clock past 168 hours offline TTL: 169 hours elapsed without TUF refresh
    WALL.store(NOW + 169 * 3600, Ordering::SeqCst);

    // Public L1 remains accessible during offline grace period
    let pub_fetch = svc.handle(&me, CasRequest::Fetch { cas_uri: pub_uri });
    assert!(
        pub_fetch.is_ok(),
        "public_l1 must remain accessible after offline TTL: {pub_fetch:?}"
    );

    // Internal artifact must fail closed with TUF_OFFLINE_TTL
    let int_fetch = svc.handle(&me, CasRequest::Fetch { cas_uri: int_uri });
    let err = int_fetch.expect_err("internal artifact must lock down after offline TTL");
    assert!(
        err.is("TUF_OFFLINE_TTL"),
        "Expected TUF_OFFLINE_TTL, got: {err:?}"
    );

    let _ = std::fs::remove_dir_all(&store_dir);
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn test_l1_clonefile_and_snapshot_entitlement() {
    let dir = tmp_dir("clonefile");
    let src = dir.join("original.bin");
    let dst = dir.join("cloned.bin");

    let test_data = b"L1 APFS clonefile test vector 2026-11-06";
    std::fs::write(&src, test_data).unwrap();

    clonefile(&src, &dst).expect("clonefile must succeed on APFS volume");
    assert_eq!(std::fs::read(&dst).unwrap(), test_data);

    // Capability probe must fail closed with ENTITLEMENT_REQUIRED on macOS without Team ID
    #[cfg(target_os = "macos")]
    {
        let probe = probe_fs_snapshot_capability(&dir);
        let err = probe.expect_err("fs_snapshot_create without entitlement must fail");
        assert!(
            err.is("ENTITLEMENT_REQUIRED"),
            "Expected ENTITLEMENT_REQUIRED, got: {err:?}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_l1_pf_fence_rules() {
    let rendered = render_fuse_pf_rules(501, FUSE_T_NFS_PORT);
    assert_eq!(FUSE_T_PF_ANCHOR, "com.enterprise.cas.swarm");
    assert_eq!(FUSE_T_NFS_PORT, 2049);
    assert!(rendered.contains("# BEGIN MCPMAC PF RULES"));
    assert!(rendered.contains("# END MCPMAC PF RULES"));
    assert!(rendered.contains("port 2049 user 501"));
    assert!(rendered.contains("port 2049 user 0 keep state"));
}
