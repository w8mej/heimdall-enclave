//! Software CAS/TUF fixed custody target receipts; no installed UID/native evidence.
//! Portable fixtures start L2 and adopt a signed L3 host floor on real refresh.
//! This isolates receipt policy from the separate L3 startup kernel-FD guard;
//! an explicit macOS-only L3-start fixture below exercises that guard natively.
use std::{collections::BTreeMap, path::PathBuf, sync::{Mutex, atomic::{AtomicI64, Ordering}}};
use enclave_core::{custody_metadata::{CustodyTarget, CustodyTargetReceipt}, daemon::DaemonId,
    host_config::{EnclaveHostConfig, HOST_CONFIG_TARGET}, ipc::PeerCredentials, profile::Profile};
use enclave_crypto::tuf::{RepoBuilder, target_file};
use enclave_swarm_syncd::{revocation::Enforcement, service::{CasConfig, CasRequest, CasResponse, CasService}};

const NOW: i64 = 1_800_000_000;
const EXP: &str = "2030-01-01T00:00:00Z";
const SOON: &str = "2027-01-15T08:00:10Z";
const BODY: &[u8] = b"{\"policy\":1}";
static WALL: AtomicI64 = AtomicI64::new(NOW);
static SERIAL: Mutex<()> = Mutex::new(());
fn wall() -> i64 { WALL.load(Ordering::SeqCst) }
struct Fixture { root: PathBuf, repo: RepoBuilder, service: std::sync::Arc<CasService> }
impl Drop for Fixture { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.root); } }
impl Fixture {
    fn new(root_expiry: &str, dev: bool) -> Self {
        Self::new_with_profile(root_expiry,dev,Profile::L2)
    }
    fn new_with_profile(root_expiry: &str, dev: bool, startup_profile: Profile) -> Self {
        WALL.store(NOW, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("yk-target-{}",hex::encode(&enclave_core::rng::bytes32()[..12])));
        std::fs::create_dir(&root).unwrap();
        let repo = RepoBuilder::new(3,2);
        let service = CasService::start_with_wall_clock(CasConfig { dev_same_uid:dev, profile:startup_profile,
            store_dir:root.join("store"), audit_path:None, tuf_root:Some(repo.root(root_expiry).unwrap()),
            ohttp_gateway:None, state_dir:None, revocation:Enforcement::Unavailable },wall).unwrap();
        Self {root,repo,service}
    }
    fn admin(&self) -> PeerCredentials { PeerCredentials::local(enclave_core::ipc::geteuid(),0) }
    fn custody(&self) -> PeerCredentials { PeerCredentials::local(DaemonId::CustodyVault.uid(),0) }
    fn refresh(&self, version: u64, expiries: [&str;3], custom: Option<serde_json::Value>, body: &[u8]) {
        let cfg = EnclaveHostConfig { profile_floor:Profile::L3, ifc_grant_public_key:"01".repeat(32),
            ohttp_key_config:None, calibration_corpus_digest:"02".repeat(32), vk_digest:"03".repeat(32),
            mcp_lock_digest:"04".repeat(32), fido_mds_allowlist_digest:"05".repeat(32), codesign_pins:None };
        let cfg = serde_json::to_vec(&cfg).unwrap();
        std::fs::write(self.root.join("store").join(HOST_CONFIG_TARGET),&cfg).unwrap();
        let mut files = BTreeMap::from([(HOST_CONFIG_TARGET.into(),target_file(&cfg,None))]);
        for target in [CustodyTarget::EnvelopePolicy,CustodyTarget::OidcAuthority] {
            std::fs::write(self.root.join("store").join(target.target_name()),body).unwrap();
            files.insert(target.target_name().into(),target_file(body,custom.clone()));
        }
        let targets = self.repo.targets(version,expiries[2],files).unwrap();
        let snapshot = self.repo.snapshot(version,expiries[1],version,&targets).unwrap();
        let timestamp = self.repo.timestamp(version,expiries[0],version,&snapshot).unwrap();
        self.service.handle(&self.admin(),CasRequest::TufRefresh { roots:vec![],
            timestamp:timestamp.into(), snapshot:snapshot.into(), targets:targets.into() }).unwrap();
    }
    fn fetch(&self, target: CustodyTarget) -> enclave_core::EnclaveResult<CustodyTargetReceipt> {
        match self.service.handle(&self.custody(),CasRequest::FetchCustodyTarget {target})? {
            CasResponse::CustodyTarget(r) => Ok(r), _ => panic!("typed fixed receipt"),
        }
    }
}

#[test]
fn fixed_receipts_authenticate_peer_wire_exact_target_and_each_chain_expiry() {
    let _serial = SERIAL.lock().unwrap();
    for earliest in 0..4 {
        let f = Fixture::new(if earliest==0 {SOON} else {EXP},false);
        for uid in [0,701,702,704,705] {
            assert!(f.service.handle(&PeerCredentials::local(uid,0),CasRequest::FetchCustodyTarget {
                target:CustodyTarget::EnvelopePolicy }).unwrap_err().is("CUSTODY_TARGET_PEER_REJECTED"));
        }
        let mut expiries = [EXP;3]; if earliest>0 { expiries[earliest-1]=SOON; }
        f.refresh(1,expiries,None,BODY);
        for target in [CustodyTarget::EnvelopePolicy,CustodyTarget::OidcAuthority] {
            let request = CasRequest::FetchCustodyTarget {target};
            let wire = enclave_core::ipc::to_cbor(&request).unwrap();
            let request: CasRequest = enclave_core::ipc::from_cbor(&wire).unwrap();
            let response = f.service.handle(&f.custody(),request).unwrap();
            let wire = enclave_core::ipc::to_cbor(&response).unwrap();
            let CasResponse::CustodyTarget(r) = enclave_core::ipc::from_cbor(&wire).unwrap() else { panic!("wire receipt") };
            assert_eq!(r.target,target.target_name()); assert_eq!(r.bytes.as_ref(),BODY);
            assert_eq!(r.refreshed_at,NOW); assert_eq!(r.verified_now,NOW);
            assert_eq!(r.effective_profile,Profile::L3);
            assert_eq!(r.versions,(1,1,1)); assert_eq!(r.expires_at,NOW+10);
            assert_eq!(r.valid_until_unix(Profile::L3).unwrap(),NOW+10);
            r.validate(NOW,Profile::L3,target).unwrap();
        }
        WALL.store(NOW+10,Ordering::SeqCst);
        assert!(f.fetch(CustodyTarget::EnvelopePolicy).is_err());
        assert!(f.fetch(CustodyTarget::OidcAuthority).is_err());
    }
    let unknown = serde_json::json!({"FetchCustodyTarget":{"target":"HostConfig"}});
    assert!(serde_json::from_value::<CasRequest>(unknown).is_err());
    let unknown = serde_json::json!({"FetchCustodyTarget":{"target":"../../private"}});
    assert!(serde_json::from_value::<CasRequest>(unknown).is_err());
}

#[test]
fn fixed_receipts_refuse_stale_mutated_revoked_model_or_oversized_targets() {
    let _serial = SERIAL.lock().unwrap();
    let f = Fixture::new(EXP,false);
    assert!(f.fetch(CustodyTarget::OidcAuthority).is_err());
    f.refresh(1,[EXP;3],None,BODY);
    let captured = f.fetch(CustodyTarget::OidcAuthority).unwrap();
    assert_eq!(captured.valid_until_unix(Profile::L1).unwrap(),NOW+24*3600);
    // Rewriting a loose payload cannot reset authenticated metadata freshness.
    std::fs::write(f.root.join("store").join(CustodyTarget::OidcAuthority.target_name()),BODY).unwrap();
    WALL.store(NOW+24*3600,Ordering::SeqCst);
    assert!(f.fetch(CustodyTarget::OidcAuthority).unwrap_err().is("CUSTODY_TARGET_STALE"));
    f.refresh(2,[EXP;3],None,BODY);
    let fresh = f.fetch(CustodyTarget::OidcAuthority).unwrap();
    assert!(fresh.valid_until_unix(Profile::L3).unwrap()>captured.valid_until_unix(Profile::L3).unwrap());
    assert!(captured.validate(wall(),Profile::L3,CustodyTarget::OidcAuthority).is_err());
    assert!(captured.validate(wall(),Profile::L1,CustodyTarget::OidcAuthority).is_err());
    std::fs::write(f.root.join("store").join(CustodyTarget::OidcAuthority.target_name()),b"{\"policy\":2}").unwrap();
    assert!(f.fetch(CustodyTarget::OidcAuthority).is_err());
    f.refresh(3,[EXP;3],Some(serde_json::json!({"revoked":true})),BODY);
    assert!(f.fetch(CustodyTarget::EnvelopePolicy).unwrap_err().is("TARGET_REVOKED"));
    f.refresh(4,[EXP;3],Some(serde_json::json!({"classification":"public_l1"})),BODY);
    assert!(f.fetch(CustodyTarget::EnvelopePolicy).unwrap_err().is("MODEL_DESCRIPTOR_REQUIRED"));
    f.refresh(5,[EXP;3],None,&vec![0;16*1024+1]);
    assert!(f.fetch(CustodyTarget::OidcAuthority).unwrap_err().is("TARGET_TOO_LARGE"));
    f.refresh(6,[EXP;3],None,BODY);
    std::fs::remove_file(f.root.join("store").join(HOST_CONFIG_TARGET)).unwrap();
    assert!(f.fetch(CustodyTarget::EnvelopePolicy).is_err());
}

#[test]
fn fixed_receipts_allow_actual_same_uid_only_with_explicit_development_mode() {
    let _serial = SERIAL.lock().unwrap();
    let f = Fixture::new(EXP,true); f.refresh(1,[EXP;3],None,BODY);
    let response = f.service.handle(&f.admin(),CasRequest::FetchCustodyTarget {target:CustodyTarget::EnvelopePolicy}).unwrap();
    assert!(matches!(response,CasResponse::CustodyTarget(_)));
    let other = PeerCredentials::local(enclave_core::ipc::geteuid().saturating_add(1000),0);
    assert!(f.service.handle(&other,CasRequest::FetchCustodyTarget {target:CustodyTarget::OidcAuthority})
        .unwrap_err().is("CUSTODY_TARGET_PEER_REJECTED"));
}

// Native-only actual L3 startup is deliberately separate from portable receipt
// qualification; software L2-start tests never claim this kernel observation.
#[cfg(target_os = "macos")]
#[test]
fn native_l3_startup_and_fixed_receipts_require_real_kernel_observation() {
    let _serial = SERIAL.lock().unwrap();
    let f = Fixture::new_with_profile(EXP,false,Profile::L3);
    f.refresh(1,[EXP;3],None,BODY);
    for target in [CustodyTarget::EnvelopePolicy,CustodyTarget::OidcAuthority] {
        let r = f.fetch(target).unwrap();
        assert_eq!(r.effective_profile,Profile::L3);
        r.validate(NOW,Profile::L3,target).unwrap();
    }
}
