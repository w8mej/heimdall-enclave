//! FS-702 end-to-end: TUF-signed admission → sanitizer → CAS → resolution
//! with anti-downgrade, companion hydration, rollback / freeze / tamper
//! rejection, and the service-level `SCM_RIGHTS` hand-off.

use std::collections::BTreeMap;

use enclave_core::ipc::PeerCredentials;
use enclave_core::profile::Profile;
use enclave_crypto::tuf::{target_file, RepoBuilder, TufClient};
use enclave_swarm_syncd::admission::{admit, resolve};
use enclave_swarm_syncd::cas::ContentStore;
use enclave_swarm_syncd::sanitizer::{build_safetensors, build_stored_zip};
use enclave_swarm_syncd::service::{CasConfig, CasRequest, CasResponse, CasService};
use serde_json::json;

#[path = "support/rollup_authority.rs"]
mod rollup_authority;

const EXP: &str = "2030-01-01T00:00:00Z";
const NOW: i64 = 1_793_884_860;

fn weights() -> Vec<u8> {
    build_safetensors(
        &[(
            "enclave_adapter.rlcd_head.weight",
            "F16",
            vec![64, 64],
            vec![1u8; 64 * 64 * 2],
        )],
        &[],
    )
}

fn lut() -> Vec<u8> {
    build_safetensors(
        &[(
            "enclave_adapter.ece_calibration_lut",
            "F32",
            vec![15],
            vec![0u8; 60],
        )],
        &[],
    )
}

fn policy(min: &str, companion: Option<&str>) -> serde_json::Value {
    let mut c = vec![];
    if let Some(b3) = companion {
        c.push(
            json!({"role": "ece_calibration_lut", "blake3": b3, "eager_hydrate_required": true}),
        );
    }
    json!({"classification": "internal_l2", "min_profile": min,
           "license_policy": {"spdx_id": "LicenseRef-proprietary", "allow_p2p_seeding": false},
           "jurisdiction_shard": "EU", "lazy_fuse_t": false, "companion_safety_layers": c})
}

struct Repo {
    r: RepoBuilder,
    root: Vec<u8>,
}

fn repo() -> Repo {
    let r = RepoBuilder::new(3, 2);
    let root = r.root(EXP).unwrap();
    Repo { r, root }
}

fn publish(
    repo: &Repo,
    v: u64,
    targets: BTreeMap<String, enclave_crypto::tuf::TargetFile>,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let t = repo.r.targets(v, EXP, targets).unwrap();
    let s = repo.r.snapshot(v, EXP, v, &t).unwrap();
    let ts = repo.r.timestamp(v, EXP, v, &s).unwrap();
    (ts, s, t)
}

fn tmp() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("depot-swarm-it-{}", enclave_core::rng::u64()))
}

#[test]
fn admit_resolve_with_companion_and_anti_downgrade() {
    let repo = repo();
    let (w, l) = (weights(), lut());
    let lut_b3 = blake3::hash(&l).to_hex().to_string();
    let mut t = BTreeMap::new();
    t.insert(
        "rlcd.safetensors".to_owned(),
        target_file(&w, Some(policy("L2", Some(&lut_b3)))),
    );
    t.insert(
        "rlcd-lut.safetensors".to_owned(),
        target_file(&l, Some(policy("L2", None))),
    );
    let (ts, s, tg) = publish(&repo, 1, t);
    let mut tuf = TufClient::bootstrap(&repo.root).unwrap();
    tuf.refresh(&ts, &s, &tg, NOW).unwrap();
    let dir = tmp();
    let store = ContentStore::open(&dir).unwrap();
    let root = admit(&store, &tuf, "rlcd.safetensors", &w, NOW).unwrap();
    let uri =
        format!("cas://blake3-bao-v1/{root}?target=rlcd.safetensors&ns=models&min_profile=L1");
    // Companion not yet hydrated: fail closed.
    assert!(resolve(&store, &tuf, &uri, Profile::L1, NOW)
        .unwrap_err()
        .is("COMPANION_NOT_HYDRATED"));
    admit(&store, &tuf, "rlcd-lut.safetensors", &l, NOW).unwrap();
    let r = resolve(&store, &tuf, &uri, Profile::L1, NOW).unwrap();
    // URI hint says L1 and workstation says L1, but the signed target pins L2.
    assert_eq!(r.effective_profile, Profile::L2);
    assert_eq!(r.fds.len(), 2);
    // An arbitrary (unsigned) hash is never resolved.
    let bogus = format!(
        "cas://blake3-bao-v1/{}?target=rlcd.safetensors&ns=models",
        "0".repeat(64)
    );
    assert!(resolve(&store, &tuf, &bogus, Profile::L1, NOW)
        .unwrap_err()
        .is("ROOT_NOT_IN_SIGNED_TARGETS"));
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn tampered_unsigned_and_malicious_artifacts_rejected() {
    let repo = repo();
    let w = weights();
    let mut pickle = vec![0x80, 0x04, 0x95];
    pickle.extend(vec![0u8; 64]);
    let bomb_src = build_stored_zip(&[("model.mlmodel", &[0u8; 16], false)]);
    let mut bomb = bomb_src.clone();
    let cd = bomb
        .windows(4)
        .rposition(|x| x == [0x50, 0x4b, 0x01, 0x02])
        .unwrap();
    bomb[cd + 10] = 8;
    bomb[cd + 24..cd + 28].copy_from_slice(&(64u32 << 20).to_le_bytes());
    let mut t = BTreeMap::new();
    t.insert(
        "w.safetensors".to_owned(),
        target_file(&w, Some(policy("L1", None))),
    );
    t.insert(
        "evil.bin".to_owned(),
        target_file(&pickle, Some(policy("L1", None))),
    );
    t.insert(
        "bomb.mlpackage.zip".to_owned(),
        target_file(&bomb, Some(policy("L1", None))),
    );
    let (ts, s, tg) = publish(&repo, 1, t);
    let mut tuf = TufClient::bootstrap(&repo.root).unwrap();
    tuf.refresh(&ts, &s, &tg, NOW).unwrap();
    let dir = tmp();
    let store = ContentStore::open(&dir).unwrap();
    let mut tampered = w.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(admit(&store, &tuf, "w.safetensors", &tampered, NOW)
        .unwrap_err()
        .is("TUF_TARGET_SHA256"));
    assert!(admit(&store, &tuf, "unknown.safetensors", &w, NOW)
        .unwrap_err()
        .is("TUF_UNKNOWN_TARGET"));
    // Even a correctly signed pickle / zip bomb is refused by the sanitizer.
    assert!(admit(&store, &tuf, "evil.bin", &pickle, NOW)
        .unwrap_err()
        .is("PICKLE_DETECTED"));
    assert!(admit(&store, &tuf, "bomb.mlpackage.zip", &bomb, NOW)
        .unwrap_err()
        .is("ZIP_BOMB"));
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn rollback_attack_on_live_client_rejected_and_state_kept() {
    let repo = repo();
    let w1 = weights();
    let mut w2 = weights();
    w2.push(0); // invalid safetensors but distinct target bytes
    let mut t1 = BTreeMap::new();
    t1.insert("w".to_owned(), target_file(&w1, Some(policy("L1", None))));
    let mut t2 = BTreeMap::new();
    t2.insert("w".to_owned(), target_file(&w2, Some(policy("L1", None))));
    let v1 = publish(&repo, 1, t1);
    let v2 = publish(&repo, 2, t2);
    let mut tuf = TufClient::bootstrap(&repo.root).unwrap();
    tuf.refresh(&v2.0, &v2.1, &v2.2, NOW).unwrap();
    assert!(tuf
        .refresh(&v1.0, &v1.1, &v1.2, NOW)
        .unwrap_err()
        .is("TUF_ROLLBACK"));
    assert_eq!(tuf.versions(), (2, 2, 2));
}

#[test]
fn service_resolve_delivers_readonly_fds_over_scm_rights() {
    use std::io::Read;
    let repo = repo();
    let w = weights();
    let mut t = BTreeMap::new();
    t.insert(
        "w.safetensors".to_owned(),
        target_file(&w, Some(policy("L1", None))),
    );
    let (ts, s, tg) = publish(&repo, 1, t);
    let dir = tmp();
    let svc = CasService::start(CasConfig {dev_same_uid: true,
        profile: Profile::L2,
        store_dir: dir.join("store"),
        audit_path: Some(dir.join("cas-audit.jsonl")),
        ohttp_gateway: None,
        tuf_root: None,
        state_dir: None,
        revocation: enclave_swarm_syncd::revocation::Enforcement::InProcess,
    })
    .unwrap();
    let me = PeerCredentials {
        uid: enclave_core::ipc::geteuid(),
        gid: 0,
        pid: None,
        audit_token: None,
        code_identity: None,
        tls_channel_binding: None,
    };
    svc.handle(
        &me,
        CasRequest::TufBootstrap {
            root: repo.root.clone().into(),
        },
    )
    .unwrap();
    // Trust root is bootstrapped once, by an administrator only.
    assert!(svc
        .handle(
            &me,
            CasRequest::TufBootstrap {
                root: repo.root.clone().into()
            }
        )
        .unwrap_err()
        .is("TUF_ALREADY_BOOTSTRAPPED"));
    let daemon_peer = PeerCredentials {
        uid: 704,
        gid: 704,
        pid: None,
        audit_token: None,
        code_identity: None,
        tls_channel_binding: None,
    };
    if enclave_core::ipc::geteuid() != 704 {
        let fresh = CasService::start(CasConfig {dev_same_uid: true,
            profile: Profile::L1,
            store_dir: dir.join("store2"),
            audit_path: None,
            ohttp_gateway: None,
            tuf_root: None,
            state_dir: None,
            revocation: enclave_swarm_syncd::revocation::Enforcement::InProcess,
        })
        .unwrap();
        assert!(fresh
            .handle(
                &daemon_peer,
                CasRequest::TufBootstrap {
                    root: repo.root.clone().into()
                }
            )
            .unwrap_err()
            .is("TUF_BOOTSTRAP_ADMIN_ONLY"));
    }
    // Service clock is the real wall clock; metadata expires 2030.
    svc.handle(
        &me,
        CasRequest::TufRefresh {
            roots: vec![],
            timestamp: ts.into(),
            snapshot: s.into(),
            targets: tg.into(),
        },
    )
    .unwrap();
    let CasResponse::Admitted { root } = svc
        .handle(
            &me,
            CasRequest::Admit {
                target: "w.safetensors".into(),
                bytes: w.clone().into(),
            },
        )
        .unwrap()
    else {
        panic!()
    };
    // Over a real socket pair, through the generic IPC server.
    let sock = dir.join("cas.sock");
    let l = enclave_core::ipc::bind(&sock, enclave_core::ipc::SocketAccess::OwnerOnly).unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (h, st) = (svc.clone(), stop.clone());
    std::thread::spawn(move || {
        enclave_core::ipc::serve::<CasRequest, CasResponse, _>(
            l,
            enclave_core::ipc::PeerPolicy::allow([enclave_core::ipc::geteuid()]),
            std::sync::Arc::new(move |p: &PeerCredentials, r| h.handle(p, r)),
            st,
        )
    });
    let mut c = enclave_core::ipc::Client::connect(&sock, enclave_core::ipc::geteuid()).unwrap();
    let uri = format!("cas://blake3-bao-v1/{root}?target=w.safetensors&ns=models");
    let r: CasResponse = c.call(&CasRequest::Resolve { cas_uri: uri }).unwrap();
    let CasResponse::Resolved { fds, .. } = r else {
        panic!()
    };
    assert_eq!(fds, 1);
    let got = c.recv_fds(4).unwrap();
    let mut f = std::fs::File::from(got.into_iter().next().unwrap());
    let mut buf = vec![];
    f.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, w);
    // The FD is read-only.
    use std::io::Write;
    assert!(f.write_all(b"x").is_err());
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    // Zero-PII receipts chained in the journal.
    let s = enclave_core::audit::verify_journal(&dir.join("cas-audit.jsonl"), None).unwrap();
    assert!(s.entries >= 4);
    std::fs::remove_dir_all(dir).ok();
}

/// ADR-016: rollups leave only OHTTP-encapsulated, and in `L3` every relayed
/// request has an identical size.
#[test]
fn rollup_relay_is_ohttp_encapsulated_and_constant_size_in_l3() {
    use enclave_crypto::ohttp::{bhttp_parse, decapsulate, gateway_keypair};
    use enclave_swarm_syncd::service::L3_FRAME;
    let me = PeerCredentials {
        uid: enclave_core::ipc::geteuid(),
        gid: 0,
        pid: None,
        audit_token: None,
        code_identity: None,
        tls_channel_binding: None,
    };
    let dir = tmp();
    let none = CasService::start(CasConfig {dev_same_uid: true,
        profile: Profile::L3,
        store_dir: dir.join("a"),
        audit_path: None,
        ohttp_gateway: None,
        tuf_root: None,
        state_dir: None,
        revocation: enclave_swarm_syncd::revocation::Enforcement::InProcess,
    })
    .unwrap();
    assert!(none
        .handle(
            &me,
            CasRequest::RelayRollup {
                frame: vec![0; L3_FRAME].into()
            }
        )
        .unwrap_err()
        .is("OHTTP_GATEWAY_UNCONFIGURED"));
    let (cfg, sk) = gateway_keypair(3);
    let relay_repo = RepoBuilder::new(3, 2);
    let svc = CasService::start(CasConfig {dev_same_uid: true,
        profile: Profile::L3,
        store_dir: dir.join("b"),
        audit_path: None,
        ohttp_gateway: Some(cfg),
        tuf_root: Some(relay_repo.root(EXP).unwrap()),
        state_dir: None,
        revocation: enclave_swarm_syncd::revocation::Enforcement::InProcess,
    })
    .unwrap();
    let authority = rollup_authority::Authority::new(Profile::L3);
    authority.install(&svc, &dir.join("b"), &relay_repo, &me);
    assert!(svc
        .handle(
            &me,
            CasRequest::RelayRollup {
                frame: vec![0; 4096].into()
            }
        )
        .unwrap_err()
        .is("L3_FRAME_NOT_PADDED"));
    for b in [0x11u8, 0x22] {
        assert!(matches!(
            svc.handle(
                &me,
                CasRequest::RelayRollup {
                    frame: authority.frame(b).into()
                }
            )
            .unwrap(),
            CasResponse::Queued
        ));
    }
    let mut out: Vec<_> = std::fs::read_dir(dir.join("b/ohttp-outbox"))
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    out.sort();
    assert_eq!(out.len(), 2);
    assert_eq!(
        out[0].len(),
        out[1].len(),
        "L3 relay requests must be indistinguishable by size"
    );
    let (path, body) = bhttp_parse(&decapsulate(3, &sk, &out[0]).unwrap()).unwrap();
    assert_eq!(path, enclave_swarm_syncd::service::LEDGER_PATH);
    assert_eq!(body.len(), L3_FRAME);
    assert!(
        !out[0].windows(64).any(|w| w == [0x11; 64]),
        "frame bytes visible in ciphertext"
    );
}

static WALL: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(NOW);

fn wall() -> i64 {
    WALL.load(std::sync::atomic::Ordering::SeqCst)
}

fn public_policy() -> serde_json::Value {
    json!({"classification": "public_l1", "min_profile": "L1",
           "license_policy": {"spdx_id": "Apache-2.0", "allow_p2p_seeding": true},
           "lazy_fuse_t": false, "companion_safety_layers": []})
}

/// GAP-30: TUF trusted state, the clock high-water mark and the last refresh
/// time survive a restart of UID 702.
#[test]
fn tuf_trust_state_survives_restart_rollback_freeze_and_offline_ttl() {
    const DAY: i64 = 86_400;
    let repo = repo();
    let (w, p) = (weights(), lut());
    let targets = |ts_exp: &str, v: u64| {
        let mut t = BTreeMap::new();
        t.insert(
            "internal.safetensors".to_owned(),
            target_file(&w, Some(policy("L1", None))),
        );
        t.insert(
            "public.safetensors".to_owned(),
            target_file(&p, Some(public_policy())),
        );
        let tg = repo.r.targets(v, EXP, t).unwrap();
        let s = repo.r.snapshot(v, EXP, v, &tg).unwrap();
        let ts = repo.r.timestamp(v, ts_exp, v, &s).unwrap();
        (ts, s, tg)
    };
    let refresh = |svc: &CasService, (ts, s, tg): (Vec<u8>, Vec<u8>, Vec<u8>)| {
        svc.handle(
            &PeerCredentials::local(0, 0),
            CasRequest::TufRefresh {
                roots: vec![],
                timestamp: ts.into(),
                snapshot: s.into(),
                targets: tg.into(),
            },
        )
    };
    let dir = tmp();
    let cfg = |pin: &[u8]| CasConfig {dev_same_uid: true,
        profile: Profile::L2,
        store_dir: dir.join("store"),
        audit_path: None,
        ohttp_gateway: None,
        tuf_root: Some(pin.to_vec()),
        state_dir: Some(dir.join("state")),
        revocation: enclave_swarm_syncd::revocation::Enforcement::InProcess,
    };
    let me = PeerCredentials::local(0, 0);
    let uri = |name: &str, b: &[u8]| {
        format!(
            "cas://blake3-bao-v1/{}?target={name}&ns=models&min_profile=L1",
            blake3::hash(b).to_hex()
        )
    };
    let fetch = |svc: &CasService, name: &str, b: &[u8]| {
        svc.handle(
            &me,
            CasRequest::Fetch {
                cas_uri: uri(name, b),
            },
        )
    };
    let status = |svc: &CasService| match svc.handle(&me, CasRequest::Status).unwrap() {
        CasResponse::Status(s) => s.state,
        _ => panic!(),
    };

    // Boot 1 at NOW: adopt v7 (timestamp valid for 2 days), admit both targets.
    WALL.store(NOW, std::sync::atomic::Ordering::SeqCst);
    let svc = CasService::start_with_wall_clock(cfg(&repo.root), wall).unwrap();
    refresh(&svc, targets("2026-11-07T13:21:00Z", 7)).unwrap();
    for (n, b) in [("internal.safetensors", &w), ("public.safetensors", &p)] {
        svc.handle(
            &me,
            CasRequest::Admit {
                target: n.into(),
                bytes: b.clone().into(),
            },
        )
        .unwrap();
    }
    fetch(&svc, "internal.safetensors", &w).unwrap();
    assert!(
        status(&svc).contains("tuf_state=sealed"),
        "{}",
        status(&svc)
    );
    drop(svc);

    // Boot 2: a validly signed, unexpired v5 replayed after the restart is a rollback.
    let svc = CasService::start_with_wall_clock(cfg(&repo.root), wall).unwrap();
    assert!(refresh(&svc, targets(EXP, 5))
        .unwrap_err()
        .is("TUF_ROLLBACK"));
    assert!(
        status(&svc).contains("tuf=Some((7, 7, 7))"),
        "{}",
        status(&svc)
    );
    // Three days later the v7 timestamp is expired (freeze defence on use).
    WALL.store(NOW + 3 * DAY, std::sync::atomic::Ordering::SeqCst);
    assert!(fetch(&svc, "internal.safetensors", &w)
        .unwrap_err()
        .is("TUF_METADATA_EXPIRED"));
    drop(svc);

    // Boot 3 with the wall clock set back to NOW: the persisted high-water
    // mark keeps the metadata expired.
    WALL.store(NOW, std::sync::atomic::Ordering::SeqCst);
    let svc = CasService::start_with_wall_clock(cfg(&repo.root), wall).unwrap();
    assert!(fetch(&svc, "internal.safetensors", &w)
        .unwrap_err()
        .is("TUF_METADATA_EXPIRED"));
    // A fresh v8 (long-lived metadata) restores service...
    refresh(&svc, targets(EXP, 8)).unwrap();
    fetch(&svc, "internal.safetensors", &w).unwrap();
    // ...until 168 h pass without a refresh: Safe-Fail Lockdown for all but
    // public_l1 artifacts, even though the metadata itself has not expired.
    WALL.store(
        NOW + 3 * DAY + 169 * 3600,
        std::sync::atomic::Ordering::SeqCst,
    );
    assert!(fetch(&svc, "internal.safetensors", &w)
        .unwrap_err()
        .is("TUF_OFFLINE_TTL"));
    fetch(&svc, "public.safetensors", &p).unwrap();
    assert!(
        status(&svc).contains("offline_lockdown=true"),
        "{}",
        status(&svc)
    );
    drop(svc);
    // The lockdown survives a restart; a refresh clears it.
    let svc = CasService::start_with_wall_clock(cfg(&repo.root), wall).unwrap();
    assert!(fetch(&svc, "internal.safetensors", &w)
        .unwrap_err()
        .is("TUF_OFFLINE_TTL"));
    refresh(&svc, targets(EXP, 9)).unwrap();
    fetch(&svc, "internal.safetensors", &w).unwrap();
    drop(svc);

    // A different install-time root cannot replace the persisted chain.
    let other = RepoBuilder::new(3, 2).root(EXP).unwrap();
    assert!(CasService::start_with_wall_clock(cfg(&other), wall)
        .unwrap_err()
        .is("TUF_ROOT_PIN_CHANGED"));
    // Deleting the sealed state is not a first boot.
    std::fs::remove_file(dir.join("state/tuf.sealed")).unwrap();
    assert!(CasService::start_with_wall_clock(cfg(&repo.root), wall)
        .unwrap_err()
        .is("TUF_STATE"));
    std::fs::remove_dir_all(dir).ok();
}

/// GAP-21: revocation comes only from signed TUF metadata. The artifact is
/// truncated (open descriptors read nothing, mappings fault), a holder that
/// ignores SIGHUP is killed after 500 ms, the target stops resolving, and the
/// peer `Revoke` RPC no longer exists.
#[test]
fn tuf_revocation_truncates_and_kills_holders_and_peer_revoke_is_gone() {
    use std::io::Read;
    use std::os::unix::process::ExitStatusExt;
    let repo = repo();
    let (w, keep) = (weights(), lut());
    let mut revoked_policy = policy("L1", None);
    revoked_policy["revoked"] = json!(true);
    let publish_with = |v: u64, w_policy: serde_json::Value| {
        let mut t = BTreeMap::new();
        t.insert("w.safetensors".to_owned(), target_file(&w, Some(w_policy)));
        t.insert(
            "keep.safetensors".to_owned(),
            target_file(&keep, Some(policy("L1", None))),
        );
        publish(&repo, v, t)
    };
    let dir = tmp();
    let svc = CasService::start(CasConfig {dev_same_uid: true,
        profile: Profile::L2,
        store_dir: dir.join("store"),
        audit_path: Some(dir.join("cas-audit.jsonl")),
        ohttp_gateway: None,
        tuf_root: Some(repo.root.clone()),
        state_dir: None,
        revocation: enclave_swarm_syncd::revocation::Enforcement::InProcess,
    })
    .unwrap();
    let admin = PeerCredentials::local(0, 0);
    let refresh = |(ts, s, tg): (Vec<u8>, Vec<u8>, Vec<u8>)| {
        svc.handle(
            &admin,
            CasRequest::TufRefresh {
                roots: vec![],
                timestamp: ts.into(),
                snapshot: s.into(),
                targets: tg.into(),
            },
        )
    };
    refresh(publish_with(1, policy("L1", None))).unwrap();
    let mut root = String::new();
    for (n, b) in [("w.safetensors", &w), ("keep.safetensors", &keep)] {
        let CasResponse::Admitted { root: r } = svc
            .handle(
                &admin,
                CasRequest::Admit {
                    target: n.into(),
                    bytes: b.clone().into(),
                },
            )
            .unwrap()
        else {
            panic!()
        };
        if n == "w.safetensors" {
            root = r;
        }
    }
    let uri = format!("cas://blake3-bao-v1/{root}?target=w.safetensors&ns=models&min_profile=L1");
    svc.handle(
        &admin,
        CasRequest::Resolve {
            cas_uri: uri.clone(),
        },
    )
    .unwrap();
    let obj = dir.join("store/objects").join(&root);
    // A consumer process holding the object and ignoring SIGHUP...
    let mut holder = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!(
            "exec 3<'{}'; trap '' HUP; exec sleep 30",
            obj.display()
        ))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    // ...and a descriptor held by this test (never signalled: it is UID 702 itself).
    let mut held = std::fs::File::open(&obj).unwrap();
    let (dev, ino) = enclave_core::supervisor::inode_of(&obj).unwrap();
    let t = std::time::Instant::now();
    while enclave_core::supervisor::holders(dev, ino).is_empty()
        && t.elapsed() < std::time::Duration::from_secs(5)
    {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // A refresh that revokes nothing kills nothing.
    refresh(publish_with(2, policy("L1", None))).unwrap();
    assert!(holder.try_wait().unwrap().is_none());

    // The signed revocation.
    refresh(publish_with(3, revoked_policy.clone())).unwrap();
    assert_eq!(holder.wait().unwrap().signal(), Some(libc::SIGKILL));
    let mut rest = Vec::new();
    assert_eq!(
        held.read_to_end(&mut rest).unwrap(),
        0,
        "the revoked object is truncated for every holder"
    );
    assert_eq!(held.metadata().unwrap().len(), 0);
    assert!(!obj.exists());
    let journal = std::fs::read_to_string(dir.join("cas-audit.jsonl")).unwrap();
    let kill: serde_json::Value = journal
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .find(|v| v["payload"]["event"] == "KILL")
        .expect("KILL line");
    assert_eq!(kill["payload"]["killed"], json!([holder.id()]));
    let ms = kill["payload"]["elapsed_ms"].as_u64().unwrap();
    assert!((500..=700).contains(&ms), "{ms} ms");
    let revoke: serde_json::Value = journal
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .find(|v| v["payload"]["event"] == "REVOKE")
        .unwrap();
    assert_eq!(
        revoke["rpc_seq_u64"], kill["rpc_seq_u64"],
        "REVOKE and KILL share the revocation rpc_seq_u64 (RB-202)"
    );
    enclave_core::audit::verify_journal(&dir.join("cas-audit.jsonl"), None).unwrap();

    // The target no longer resolves or admits; the unrevoked one still does.
    assert!(svc
        .handle(&admin, CasRequest::Resolve { cas_uri: uri })
        .unwrap_err()
        .is("TARGET_REVOKED"));
    assert!(svc
        .handle(
            &admin,
            CasRequest::Admit {
                target: "w.safetensors".into(),
                bytes: w.clone().into()
            }
        )
        .unwrap_err()
        .is("TARGET_REVOKED"));
    let keep_uri = format!(
        "cas://blake3-bao-v1/{}?target=keep.safetensors&ns=models&min_profile=L1",
        blake3::hash(&keep).to_hex()
    );
    svc.handle(&admin, CasRequest::Resolve { cas_uri: keep_uri })
        .unwrap();

    // There is no peer-callable revocation: an old `Revoke` frame does not decode.
    let frame =
        enclave_core::ipc::to_cbor(&json!({"Revoke": {"root": root, "consumer_pids": [1]}}))
            .unwrap();
    assert!(enclave_core::ipc::from_cbor::<CasRequest>(&frame).is_err());
    std::fs::remove_dir_all(dir).ok();
}

// F38: Hydrate may acknowledge an already verified local object, but cannot
// invent a successful download while every production transport is unwired.
fn hydrate_requires_real_object(profile: Profile) {
    let repo = repo();
    let bytes = weights();
    let mut targets = BTreeMap::new();
    targets.insert(
        "w.safetensors".to_owned(),
        target_file(&bytes, Some(public_policy())),
    );
    let (ts, snapshot, targets) = publish(&repo, 1, targets);
    let dir = tmp();
    let audit = dir.join("audit.jsonl");
    let svc = CasService::start(CasConfig {dev_same_uid: true,
        profile,
        store_dir: dir.join("store"),
        audit_path: Some(audit.clone()),
        tuf_root: Some(repo.root.clone()),
        state_dir: None,
        ohttp_gateway: None,
        revocation: enclave_swarm_syncd::revocation::Enforcement::InProcess,
    })
    .unwrap();
    let admin = PeerCredentials::local(enclave_core::ipc::geteuid(), 0);
    svc.handle(
        &admin,
        CasRequest::TufRefresh {
            roots: vec![],
            timestamp: ts.into(),
            snapshot: snapshot.into(),
            targets: targets.into(),
        },
    )
    .unwrap();
    let root = blake3::hash(&bytes).to_hex().to_string();
    let uri = format!("cas://blake3-bao-v1/{root}?target=w.safetensors&ns=models");
    let before = std::fs::read(&audit).unwrap();
    let result = svc.handle(
        &admin,
        CasRequest::Hydrate {
            cas_uri: uri.clone(),
        },
    );
    assert!(
        result
            .as_ref()
            .err()
            .is_some_and(|e| e.is("HYDRATION_TRANSPORT_UNAVAILABLE")),
        "absent object must not be acknowledged: {result:?}"
    );
    assert_eq!(
        std::fs::read(&audit).unwrap(),
        before,
        "no false HYDRATED receipt"
    );
    assert!(!dir.join("store/objects").join(&root).exists());
    svc.handle(
        &admin,
        CasRequest::Admit {
            target: "w.safetensors".into(),
            bytes: bytes.clone().into(),
        },
    )
    .unwrap();
    let response = svc
        .handle(
            &admin,
            CasRequest::Hydrate {
                cas_uri: uri.clone(),
            },
        )
        .unwrap();
    assert!(matches!(response, CasResponse::Admitted { root: r } if r == root));
    let fetched = svc
        .handle(&admin, CasRequest::Fetch { cas_uri: uri })
        .unwrap();
    assert!(matches!(fetched, CasResponse::Bytes(b) if b.as_ref() == bytes));
    // A manifest and a previously materialized file are insufficient after
    // corruption. Never emit another successful receipt for these bytes.
    let object = dir.join("store/objects").join(&root);
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&object, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&object, b"corrupt").unwrap();
    let before = std::fs::read(&audit).unwrap();
    let error = svc
        .handle(
            &admin,
            CasRequest::Hydrate {
                cas_uri: format!("cas://blake3-bao-v1/{root}?target=w.safetensors&ns=models"),
            },
        )
        .unwrap_err();
    assert!(error.is("HYDRATION_CACHE_MISMATCH"), "{error}");
    assert_eq!(std::fs::read(&audit).unwrap(), before);
    drop(svc);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn f38_l1_hydrate_requires_real_object() {
    hydrate_requires_real_object(Profile::L1);
}
#[test]
fn f38_l2_hydrate_requires_real_object() {
    hydrate_requires_real_object(Profile::L2);
}
#[test]
fn f38_l3_hydrate_requires_real_object() {
    hydrate_requires_real_object(Profile::L3);
}

#[test]
fn f38_hydrate_obeys_signed_profile_floor() {
    let repo = repo();
    let bytes = weights();
    let mut targets = BTreeMap::new();
    targets.insert(
        "w.safetensors".to_owned(),
        target_file(&bytes, Some(policy("L3", None))),
    );
    targets.insert(
        "classification.safetensors".to_owned(),
        target_file(&bytes, Some(policy("L1", None))),
    );
    let (ts, snapshot, targets) = publish(&repo, 1, targets);
    let dir = tmp();
    let audit = dir.join("audit.jsonl");
    let svc = CasService::start(CasConfig {dev_same_uid: true,
        profile: Profile::L1,
        store_dir: dir.join("store"),
        audit_path: Some(audit.clone()),
        tuf_root: Some(repo.root.clone()),
        state_dir: None,
        ohttp_gateway: None,
        revocation: enclave_swarm_syncd::revocation::Enforcement::InProcess,
    })
    .unwrap();
    let admin = PeerCredentials::local(enclave_core::ipc::geteuid(), 0);
    svc.handle(
        &admin,
        CasRequest::TufRefresh {
            roots: vec![],
            timestamp: ts.into(),
            snapshot: snapshot.into(),
            targets: targets.into(),
        },
    )
    .unwrap();
    let CasResponse::Admitted { root } = svc
        .handle(
            &admin,
            CasRequest::Admit {
                target: "w.safetensors".into(),
                bytes: bytes.into(),
            },
        )
        .unwrap()
    else {
        panic!()
    };
    // Both a signed explicit floor and the classification floor must gate
    // cached acknowledgement; a lower URI hint cannot override either.
    for target in ["w.safetensors", "classification.safetensors"] {
        let uri = format!("cas://blake3-bao-v1/{root}?target={target}&ns=models&min_profile=L1");
        let before = std::fs::read(&audit).unwrap();
        let result = svc.handle(
            &admin,
            CasRequest::Hydrate {
                cas_uri: uri.clone(),
            },
        );
        assert!(
            result
                .as_ref()
                .err()
                .is_some_and(|e| e.is("PROFILE_FLOOR_EXCEEDED")),
            "{result:?}"
        );
        assert_eq!(std::fs::read(&audit).unwrap(), before);
        assert!(svc
            .handle(&admin, CasRequest::Resolve { cas_uri: uri })
            .unwrap_err()
            .is("PROFILE_FLOOR_EXCEEDED"));
    }
    drop(svc);
    std::fs::remove_dir_all(dir).unwrap();
}
