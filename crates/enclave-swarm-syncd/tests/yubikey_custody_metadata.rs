//! Software-only live CAS/TUF custody metadata contract; no native key or UID evidence.
//! Portable receipt fixture starts L2, then adopts the signed L3 floor. Actual
//! L3 startup kernel-FD qualification is a separate macOS-only test below.
use std::{collections::BTreeMap, path::PathBuf, sync::atomic::{AtomicI64, Ordering}};
use enclave_core::{custody_metadata::FIDO_MDS_TARGET, daemon::DaemonId, host_config::{EnclaveHostConfig, HOST_CONFIG_TARGET}, ipc::PeerCredentials, profile::Profile};
use enclave_crypto::tuf::{RepoBuilder, target_file};
use enclave_swarm_syncd::{revocation::Enforcement, service::{CasConfig, CasRequest, CasResponse, CasService}};
const NOW: i64 = 1_800_000_000;
const EXP: &str = "2030-01-01T00:00:00Z";
static WALL: AtomicI64 = AtomicI64::new(NOW);
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn wall() -> i64 { WALL.load(Ordering::SeqCst) }
struct Root(PathBuf);
impl Drop for Root { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }

fn metadata_contract(startup_profile: Profile) {
    let _serial = SERIAL.lock().unwrap();
    WALL.store(NOW, Ordering::SeqCst);
    let root = Root(std::env::temp_dir().join(format!("yk-mds-{}",hex::encode(&enclave_core::rng::bytes32()[..12]))));
    std::fs::create_dir(&root.0).unwrap();
    let repo = RepoBuilder::new(3,2);
    let service = CasService::start_with_wall_clock(CasConfig { dev_same_uid: false, profile: startup_profile,
        store_dir: root.0.join("store"), audit_path: None, tuf_root: Some(repo.root(EXP).unwrap()),
        ohttp_gateway: None, state_dir: None, revocation: Enforcement::Unavailable }, wall).unwrap();
    let admin = PeerCredentials::local(enclave_core::ipc::geteuid(), 0);
    let custody = PeerCredentials::local(DaemonId::CustodyVault.uid(), 0);
    let mds = b"{\"entries\":[]}";
    std::fs::write(root.0.join("store").join(FIDO_MDS_TARGET), mds).unwrap();
    let refresh = |version: u64, expiry: &str, matching_digest: bool| {
        let cfg = EnclaveHostConfig { profile_floor: Profile::L3, ifc_grant_public_key: "01".repeat(32),
            ohttp_key_config: None, calibration_corpus_digest: "02".repeat(32), vk_digest: "03".repeat(32),
            mcp_lock_digest: "04".repeat(32), fido_mds_allowlist_digest: if matching_digest {
                blake3::hash(mds).to_hex().to_string() } else { "00".repeat(32) }, codesign_pins: None };
        let cfg = serde_json::to_vec(&cfg).unwrap();
        std::fs::write(root.0.join("store").join(HOST_CONFIG_TARGET), &cfg).unwrap();
        let targets = repo.targets(version, EXP, BTreeMap::from([
            (FIDO_MDS_TARGET.into(), target_file(mds,None)),
            (HOST_CONFIG_TARGET.into(), target_file(&cfg,None)),
        ])).unwrap();
        let snapshot = repo.snapshot(version, EXP, version, &targets).unwrap();
        let timestamp = repo.timestamp(version, expiry, version, &snapshot).unwrap();
        service.handle(&admin, CasRequest::TufRefresh { roots: vec![], timestamp: timestamp.into(),
            snapshot: snapshot.into(), targets: targets.into() }).unwrap();
    };
    assert!(service.handle(&admin,CasRequest::FetchCustodyMetadata).unwrap_err().is("CUSTODY_METADATA_PEER_REJECTED"));
    refresh(1,"2027-01-15T08:00:10Z",true);
    let CasResponse::CustodyMetadata(receipt) = service.handle(&custody,CasRequest::FetchCustodyMetadata).unwrap() else { panic!("typed receipt") };
    assert_eq!(receipt.refreshed_at,NOW); assert_eq!(receipt.expires_at,NOW+10);
    assert_eq!(receipt.bytes.as_ref(),mds); receipt.validate(NOW,Profile::L3).unwrap();
    assert_eq!(receipt.effective_profile,Profile::L3);
    assert_eq!(receipt.valid_until_unix(Profile::L1).unwrap(),NOW+10);
    WALL.store(NOW+10,Ordering::SeqCst);
    assert!(service.handle(&custody,CasRequest::FetchCustodyMetadata).is_err());
    refresh(2,EXP,true);
    let CasResponse::CustodyMetadata(floor_receipt) = service.handle(&custody,CasRequest::FetchCustodyMetadata).unwrap() else { panic!("typed floor receipt") };
    assert!(floor_receipt.expires_at > NOW+10+24*3600);
    assert_eq!(floor_receipt.valid_until_unix(Profile::L1).unwrap(),NOW+10+24*3600);
    // Touching/replacing identical loose bytes cannot reset the trusted refresh.
    std::fs::write(root.0.join("store").join(FIDO_MDS_TARGET),mds).unwrap();
    WALL.store(NOW+10+24*3600,Ordering::SeqCst);
    assert!(service.handle(&custody,CasRequest::FetchCustodyMetadata).unwrap_err().is("CUSTODY_METADATA_STALE"));
    assert!(floor_receipt.validate(NOW+10+24*3600,Profile::L1).is_err());
    refresh(3,EXP,false);
    assert!(service.handle(&custody,CasRequest::FetchCustodyMetadata).unwrap_err().is("CUSTODY_METADATA_CONFIG_DIGEST"));
}

#[test]
fn live_metadata_requires_custody_peer_signed_config_real_refresh_and_earliest_expiry() {
    metadata_contract(Profile::L2);
}

#[cfg(target_os = "macos")]
#[test]
fn native_l3_startup_live_metadata_requires_real_kernel_observation() {
    metadata_contract(Profile::L3);
}
