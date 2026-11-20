//! Public synthetic TUF and private filesystem fixtures only. These exercise
//! production verifier/state helpers; none constructs SoftwareApproval, a real
//! host guard, native release authority or an installed-readiness receipt.
use super::*;
use enclave_crypto::tuf::{self,RepoBuilder,Signed,RootMeta};
use serde_json::{json,Value};
use std::os::unix::fs::{PermissionsExt,OpenOptionsExt};

const NOW:i64=1_800_000_000;
const EXP:&str="2040-01-01T00:00:00Z";
const TARGET:&str="mcpmac/software-release/fixture-inventory.json";
const INVENTORY:&[u8]=b"synthetic exact public inventory bytes";
fn minimum()->MinimumThresholds {MinimumThresholds {root:2,timestamp:1,snapshot:1,targets:2}}
fn configuration()->ReleaseConfig {
    ReleaseConfig {version:1,kind:KIND.into(),purpose:PURPOSE.into(),target_id:"fixture".into(),
        descriptor_sha256:"aa".repeat(32),profile:Profile::L2,
        signing_identity_mode:if enclave_core::codesign::TEAM_ID.is_empty(){DeploymentSigningMode::LocalPins}else{DeploymentSigningMode::TeamId},
        bootstrap_root_file:"/fixture-authority/bootstrap.json".into(),bootstrap_root_sha256:"bb".repeat(32),
        approval_repository:"/fixture-approval-replica".into(),trust_state_directory:"/fixture-release-state".into(),
        inventory_target:TARGET.into(),minimum_thresholds:minimum(),minimum_time_unix:NOW-1}
}
fn target()->DeploymentTarget {
    serde_json::from_value(json!({"version":1,"target_id":"fixture","role":"dedicated-test","profile":"L2",
        "authority_config":"/fixture-custody-authority.json","expected_artifacts_manifest":"/fixture-inventory.json",
        "codesign_pins_file":"/fixture-current-pins.json",
        "signing_identity_mode":if enclave_core::codesign::TEAM_ID.is_empty(){"local-pins"}else{"team-id"},
        "layout":{"binary_dir":"/fixture-output/bin","custody_bundle":"/fixture-output/support/Custody.app",
            "sandbox_dir":"/fixture-output/sandbox","socket_root":"/fixture-output/run","state_root":"/fixture-output/state",
            "audit_root":"/fixture-output/log","cas_store_root":"/fixture-output/cas","staging_root":"/fixture-output/staging",
            "support_root":"/fixture-output/support","launchd_namespace":"com.fixture.enclave","mach_service":"com.fixture.exception"},
        "broker":null,"shared_read_only_inputs":[]})).unwrap()
}
fn config_value()->Value {
    let c=configuration();
    json!({"version":c.version,"kind":c.kind,"purpose":c.purpose,"target_id":c.target_id,
        "descriptor_sha256":c.descriptor_sha256,"profile":c.profile,"signing_identity_mode":c.signing_identity_mode,
        "bootstrap_root_file":c.bootstrap_root_file,"bootstrap_root_sha256":c.bootstrap_root_sha256,
        "approval_repository":c.approval_repository,"trust_state_directory":c.trust_state_directory,
        "inventory_target":c.inventory_target,"minimum_thresholds":c.minimum_thresholds,"minimum_time_unix":c.minimum_time_unix})
}
struct MetadataSet {root:Vec<u8>,timestamp:Vec<u8>,snapshot:Vec<u8>,targets:Vec<u8>}
fn metadata_set(repo:&RepoBuilder,version:u64,inventory:&[u8],expiry:[&str;4])->MetadataSet {
    let root=repo.root(expiry[0]).unwrap();
    let targets=repo.targets(version,expiry[3],BTreeMap::from([(TARGET.into(),tuf::target_file(inventory,None))])).unwrap();
    let snapshot=repo.snapshot(version,expiry[2],version,&targets).unwrap();
    let timestamp=repo.timestamp(version,expiry[1],version,&snapshot).unwrap();
    MetadataSet {root,timestamp,snapshot,targets}
}
fn refresh(current:&TufClient,set:&MetadataSet,c:&ReleaseConfig)->EnclaveResult<TufClient> {
    refresh_verified(current,&[],&set.timestamp,&set.snapshot,&set.targets,NOW,c)
}
fn state_for(c:&ReleaseConfig,client:&TufClient,high_water:i64)->ReleaseState {
    ReleaseState {version:1,purpose:PURPOSE.into(),target_id:c.target_id.clone(),inventory_target:c.inventory_target.clone(),
        minimum_thresholds:c.minimum_thresholds.clone(),high_water,trusted:client.export().unwrap()}
}
fn complete_inventory(t:&DeploymentTarget,descriptor:&str)->Vec<u8> {
    let mut paths=BTreeSet::<String>::from(["codesign-pins.json".into()]);
    for binary in ["mcp-enclave","enclave-model-runnerd","enclave-swarm-syncd","enclave-apfs-broker",
        "enclave-agent-runtime","enclave-zk-auditor","enclave-cdp-browser","enclave-client-gateway","enclave-intent"] {
        paths.insert(format!("bin/{binary}"));
    }
    for (bundle,binary) in [("EnclaveCustody.app","enclave-custody-vaultd"),("EnclaveOIDC.app","enclave-oidc")] {
        for member in ["Contents/Info.plist".to_owned(),"Contents/_CodeSignature/CodeResources".into(),format!("Contents/MacOS/{binary}")] {
            paths.insert(format!("{bundle}/{member}"));
        }
    }
    for sandbox in ["adapter","cas","custody","ifc","zk","browser","gateway"] {paths.insert(format!("launchd/{sandbox}.sb"));}
    for job in ["adapter","cas","custody","ifc","zk","supervisor","intent","oidc-broker","hydrate","browser","gateway"] {
        paths.insert(format!("launchd/{}.{job}.plist",t.layout.launchd_namespace));
    }
    if t.profile==Profile::L3 {paths.insert(format!("launchd/{}.apfs-broker.plist",t.layout.launchd_namespace));}
    for path in ["SHA256SUMS","custody.entitlements","yubikey-transport","install.sh","uninstall.sh","public-trust.sh",
        "fido-mds/yubico.json","launchd/provision-accounts.sh","launchd/enclave-daemon.entitlements"] {paths.insert(path.into());}
    for name in ["root.json","timestamp.json","snapshot.json","targets.json","enclave-host-config.json",
        "enclave-policy.cedar.v1.json","vk_manifest.json","enclave-distribution-v1.json"] {paths.insert(format!("tuf/repo/{name}"));}
    if t.profile!=Profile::L1 {
        for name in [enclave_core::custody_metadata::FIDO_MDS_TARGET,
            enclave_core::custody_metadata::CustodyTarget::EnvelopePolicy.target_name()] {
            paths.insert(format!("tuf/repo/{name}"));
        }
    }
    let files=paths.into_iter().map(|path|json!({"path":path,"sha256":"cc".repeat(32),"size":1})).collect::<Vec<_>>();
    serde_json::to_vec(&json!({"version":1,"kind":"mcpmac-first-touch-artifact-inventory","target_id":t.target_id,
        "profile":t.profile,"signing_identity_mode":t.signing_identity_mode,"deployment_config_sha256":descriptor,
        "source_git_commit":"d".repeat(40),"source_manifest_sha256":"e".repeat(64),"source_input_count":1,
        "codesign_pins_sha256":"cc".repeat(32),"staging_root":normalized_path(&t.layout.staging_root).unwrap(),
        "external_provenance":"UNKNOWN","files":files})).unwrap()
}

#[test]
fn release_config_requires_independent_purpose_exact_context_time_and_closed_scope() {
    let t=target();t.validate().unwrap();
    let original=config_value();let raw=serde_json::to_vec(&original).unwrap();
    let c=config(&raw,&t,&"aa".repeat(32)).unwrap();
    isolation(&c,Path::new("/fixture-release-config.json"),Path::new("/fixture-descriptor.json"),&t).unwrap();
    for (field,value) in [("purpose",json!("custody")),("kind",json!("other")),("target_id",json!("foreign")),
        ("descriptor_sha256",json!("cc".repeat(32))),("profile",json!("L3")),("minimum_time_unix",json!(0)),
        ("minimum_time_unix",json!(i64::MAX)),("inventory_target",json!("mcpmac/software-release/../other.json")),
        ("inventory_target",json!("enclave-host-config.json")),("unrecognized",json!(true))] {
        let mut bad=original.clone();bad[field]=value;
        assert!(config(&serde_json::to_vec(&bad).unwrap(),&t,&"aa".repeat(32)).is_err(),"{field}");
    }
    let raw=String::from_utf8(raw).unwrap().replacen("\"version\":1","\"version\":1,\"versi\\u006fn\":1",1);
    assert!(config(raw.as_bytes(),&t,&"aa".repeat(32)).is_err());
    assert!(config(&serde_json::to_vec(&original).unwrap(),&t,&"dd".repeat(32)).is_err());
}

#[test]
fn release_authority_routes_refuse_every_mutation_domain_and_fixed_alias_collision() {
    let t=target();
    for domain in excluded(&t) {
        let mut c=configuration();c.approval_repository=domain.join("approval");
        assert!(isolation(&c,Path::new("/fixture-release-config.json"),Path::new("/fixture-descriptor.json"),&t).is_err());
    }
    let mut c=configuration();c.trust_state_directory=c.approval_repository.join("state");
    assert!(isolation(&c,Path::new("/fixture-release-config.json"),Path::new("/fixture-descriptor.json"),&t).is_err());
    assert!(overlaps(Path::new("/var/db/release"),Path::new("/private/var/db/release/state")).unwrap());
    assert!(overlaps(Path::new("/etc/Release"),Path::new("/private/etc/release")).unwrap());
    let mut t=t;t.expected_artifacts_manifest=t.layout.staging_root.join("inventory.json");
    assert!(isolation(&configuration(),Path::new("/fixture-release-config.json"),Path::new("/fixture-descriptor.json"),&t).is_err());
}

#[test]
fn release_actual_crypto_accepts_exact_inventory_and_preserves_trust_on_target_refusal() {
    let c=configuration();let repo=RepoBuilder::new(2,2);let set=metadata_set(&repo,1,INVENTORY,[EXP;4]);
    json::metadata(&set.root,Role::Root,&c.minimum_thresholds,TARGET).unwrap();
    let anchor=TufClient::bootstrap(&set.root).unwrap();
    let client=refresh(&anchor,&set,&c).unwrap();
    client.verify_target(TARGET,INVENTORY,NOW).unwrap();
    let before=client.export().unwrap();
    assert!(client.verify_target(TARGET,b"changed public inventory",NOW).is_err());
    assert!(client.verify_target("mcpmac/software-release/foreign.json",INVENTORY,NOW).is_err());
    assert_eq!(client.export().unwrap(),before);assert_eq!(client.versions(),(1,1,1));
    assert_eq!(anchor.versions(),(0,0,0));
}

#[test]
fn release_signed_complete_inventory_composes_real_plan_but_never_mints_native_authority() {
    for profile in [Profile::L2,Profile::L3] {
        let mut t=target();let mut c=configuration();t.profile=profile;c.profile=profile;
        if profile==Profile::L3 {t.broker=Some(enclave_core::deployment::DeploymentBroker {
            base_dir:t.layout.state_root.join("apfs-broker"),tuf_root_file:"/fixture-model-root.json".into()});}
        let inventory=complete_inventory(&t,&c.descriptor_sha256);
        let repo=RepoBuilder::new(2,2);let set=metadata_set(&repo,1,&inventory,[EXP;4]);
        let client=refresh(&TufClient::bootstrap(&set.root).unwrap(),&set,&c).unwrap();
        let plan=verify_inventory(&client,&c,&t,&c.descriptor_sha256,&inventory,NOW).unwrap();
        assert_eq!(plan.artifact_inventory_sha256,hex::encode(Sha256::digest(&inventory)));
        assert_eq!(plan.candidate_codesign_pins_sha256,"cc".repeat(32));
        assert!(plan.missing_required_files.is_empty());assert!(!plan.apply_supported);
        assert_eq!(plan.external_provenance,"UNKNOWN");
        // A valid independent SOFTWARE signature cannot approve a package
        // missing either mandatory custody runtime transport input.
        for name in [enclave_core::custody_metadata::FIDO_MDS_TARGET,
            enclave_core::custody_metadata::CustodyTarget::EnvelopePolicy.target_name()] {
            let mut incomplete:Value=serde_json::from_slice(&inventory).unwrap();
            let path=format!("tuf/repo/{name}");
            incomplete["files"].as_array_mut().unwrap().retain(|file|file["path"]!=path);
            let incomplete=serde_json::to_vec(&incomplete).unwrap();
            let set=metadata_set(&repo,2,&incomplete,[EXP;4]);
            let refreshed=refresh(&client,&set,&c).unwrap();
            let error=verify_inventory(&refreshed,&c,&t,&c.descriptor_sha256,&incomplete,NOW).unwrap_err();
            assert!(error.is("RELEASE_INVENTORY_INCOMPLETE"));
        }
        let mut changed:Value=serde_json::from_slice(&inventory).unwrap();changed["external_provenance"]=json!("APPROVED");
        let changed=serde_json::to_vec(&changed).unwrap();let set=metadata_set(&repo,2,&changed,[EXP;4]);
        let client=refresh(&client,&set,&c).unwrap();
        assert!(verify_inventory(&client,&c,&t,&c.descriptor_sha256,&changed,NOW).is_err());
        assert_eq!(client.versions(),(2,2,2));
    }
}

#[test]
fn release_actual_crypto_thresholds_foreign_roots_and_legacy_preimages_refuse() {
    use ed25519_dalek::Signer;
    let c=configuration();let repo=RepoBuilder::new(2,2);let set=metadata_set(&repo,1,INVENTORY,[EXP;4]);
    let anchor=TufClient::bootstrap(&set.root).unwrap();
    let mut targets:Signed<tuf::TargetsMeta>=serde_json::from_slice(&set.targets).unwrap();
    targets.signatures.pop();let targets=tuf::to_bytes(&targets).unwrap();
    let snap=repo.snapshot(1,EXP,1,&targets).unwrap();let ts=repo.timestamp(1,EXP,1,&snap).unwrap();
    assert!(refresh_verified(&anchor,&[],&ts,&snap,&targets,NOW,&c).is_err());
    let foreign=RepoBuilder::new(2,2);let other=metadata_set(&foreign,1,INVENTORY,[EXP;4]);
    assert!(refresh(&anchor,&other,&c).is_err());
    let mut root:Signed<RootMeta>=serde_json::from_slice(&set.root).unwrap();
    let jcs=enclave_core::jcs::to_jcs_bytes(&root.signed).unwrap();
    // The closed root subset has plain ASCII strings and bounded integers:
    // these two canonical algorithms produce the SAME signed preimage here.
    // Signature verification cannot and must not infer an algorithm label.
    assert_eq!(jcs,enclave_crypto::canonical_json::to_canonical_json_bytes(&root.signed).unwrap());
    for (signature,key) in root.signatures.iter_mut().zip(&repo.keys[&Role::Root]) {
        signature.sig=hex::encode(key.sign(&jcs).to_bytes());
    }
    let equivalent=tuf::to_bytes(&root).unwrap();json::metadata(&equivalent,Role::Root,&c.minimum_thresholds,TARGET).unwrap();
    TufClient::bootstrap(&equivalent).unwrap();
    // A deliberately non-release schema string supplies distinct real
    // preimages for the core verifier's legacy-canonicalization refusal.
    root.signed.spec_version.push('\n');
    let jcs=enclave_core::jcs::to_jcs_bytes(&root.signed).unwrap();
    assert_ne!(jcs,enclave_crypto::canonical_json::to_canonical_json_bytes(&root.signed).unwrap());
    for (signature,key) in root.signatures.iter_mut().zip(&repo.keys[&Role::Root]) {
        signature.sig=hex::encode(key.sign(&jcs).to_bytes());
    }
    let legacy=tuf::to_bytes(&root).unwrap();
    assert!(json::metadata(&legacy,Role::Root,&c.minimum_thresholds,TARGET).is_err());
    assert!(TufClient::bootstrap(&legacy).unwrap_err().is("TUF_CANONICALISATION_LEGACY"));
}

#[test]
fn release_actual_crypto_rejects_mix_match_rollback_and_equal_version_changed_bytes() {
    let c=configuration();let repo=RepoBuilder::new(2,2);
    let one=metadata_set(&repo,1,INVENTORY,[EXP;4]);let two=metadata_set(&repo,2,INVENTORY,[EXP;4]);
    let anchor=TufClient::bootstrap(&one.root).unwrap();let current=refresh(&anchor,&two,&c).unwrap();
    let before=current.export().unwrap();assert!(refresh(&current,&one,&c).is_err());
    let changed=metadata_set(&repo,2,b"other signed inventory",[EXP;4]);assert!(refresh(&current,&changed,&c).is_err());
    assert!(refresh_verified(&anchor,&[],&two.timestamp,&one.snapshot,&two.targets,NOW,&c).is_err());
    assert!(refresh_verified(&anchor,&[],&two.timestamp,&two.snapshot,&one.targets,NOW,&c).is_err());
    assert_eq!(current.export().unwrap(),before);
}

#[test]
fn release_expiry_checks_every_role_and_earliest_exclusive_cutoff() {
    let c=configuration();let repo=RepoBuilder::new(2,2);
    for i in 0..4 {
        let mut expiry=[EXP;4];expiry[i]="2020-01-01T00:00:00Z";
        let set=metadata_set(&repo,1,INVENTORY,expiry);let anchor=TufClient::bootstrap(&set.root).unwrap();
        assert!(refresh(&anchor,&set,&c).is_err(),"role {i}");
    }
    let set=metadata_set(&repo,1,INVENTORY,[EXP,"2030-01-01T00:00:00Z",EXP,EXP]);
    let client=refresh(&TufClient::bootstrap(&set.root).unwrap(),&set,&c).unwrap();
    let expiry=enclave_crypto::time::parse_rfc3339_utc("2030-01-01T00:00:00Z").unwrap();
    assert_eq!(client.fresh_until().unwrap(),expiry);
    assert!(client.ensure_fresh(expiry-1).is_ok());assert!(client.ensure_fresh(expiry).is_err());
}

#[test]
fn release_root_rotation_requires_consecutive_names_bodies_and_both_thresholds() {
    let c=configuration();let old=RepoBuilder::new(2,2);let one=metadata_set(&old,1,INVENTORY,[EXP;4]);
    let current=refresh(&TufClient::bootstrap(&one.root).unwrap(),&one,&c).unwrap();
    let mut new=RepoBuilder::new(2,2);new.root_version=2;let two=metadata_set(&new,2,INVENTORY,[EXP;4]);
    let body=new.root_body(EXP).unwrap();
    let signers=old.keys[&Role::Root].iter().chain(&new.keys[&Role::Root]).collect::<Vec<_>>();
    let dual=tuf::to_bytes(&tuf::sign(&body,&signers).unwrap()).unwrap();
    let rotated=refresh_verified(&current,&[(2,dual.clone())],&two.timestamp,&two.snapshot,&two.targets,NOW,&c).unwrap();
    assert_eq!(rotated.root().version,2);assert!(rotated.chain_contains(&one.root));assert!(rotated.chain_contains(&dual));
    assert!(refresh_verified(&current,&[(2,two.root.clone())],&two.timestamp,&two.snapshot,&two.targets,NOW,&c).is_err());
    assert!(refresh_verified(&current,&[(3,dual.clone())],&two.timestamp,&two.snapshot,&two.targets,NOW,&c).is_err());
    assert!(refresh_verified(&current,&[(2,dual.clone()),(2,dual)],&two.timestamp,&two.snapshot,&two.targets,NOW,&c).is_err());
    let mut skipped=new.root_body(EXP).unwrap();skipped.version=3;
    let skipped=tuf::to_bytes(&tuf::sign(&skipped,&signers).unwrap()).unwrap();
    assert!(refresh_verified(&current,&[(3,skipped)],&two.timestamp,&two.snapshot,&two.targets,NOW,&c).is_err());
}

#[test]
fn release_restore_rechecks_scope_schema_chain_floors_and_keeps_expired_state() {
    let c=configuration();let repo=RepoBuilder::new(2,2);let set=metadata_set(&repo,2,INVENTORY,[EXP;4]);
    let client=refresh(&TufClient::bootstrap(&set.root).unwrap(),&set,&c).unwrap();
    let state=state_for(&c,&client,NOW+100);let bytes=serde_json::to_vec(&state).unwrap();
    let (restored,client)=restore_state(&bytes,&c,&set.root).unwrap();
    assert_eq!(client.versions(),(2,2,2));
    let mut clock=TrustedClock::resumed(NOW-100,restored.high_water);assert!(clock.now(NOW-200)>=NOW+100);
    assert!(client.ensure_fresh(enclave_crypto::time::parse_rfc3339_utc(EXP).unwrap()).is_err());
    let foreign=RepoBuilder::new(2,2).root(EXP).unwrap();assert!(restore_state(&bytes,&c,&foreign).is_err());
    let original:Value=serde_json::from_slice(&bytes).unwrap();
    for (field,value) in [("target_id",json!("foreign")),("purpose",json!("custody")),
        ("inventory_target",json!("other")),("high_water",json!(i64::MAX)),("version",json!(2))] {
        let mut bad=original.clone();bad[field]=value;
        assert!(restore_state(&serde_json::to_vec(&bad).unwrap(),&c,&set.root).is_err());
    }
    let mut bad=original.clone();bad["trusted"]["unknown"]=json!(true);
    assert!(restore_state(&serde_json::to_vec(&bad).unwrap(),&c,&set.root).is_err());
    let mut bad=original.clone();bad["minimum_thresholds"]["root"]=json!(3);
    assert!(restore_state(&serde_json::to_vec(&bad).unwrap(),&c,&set.root).is_err());
}

struct Fixture {base:PathBuf}
impl Fixture {
    fn new()->Self {
        // Preserve configured repository-local temporary routing. Linux tests
        // that need the REAL sealed ancestry walk run explicitly in the
        // coordinator's private-root fixture environment, with its /tmp backed
        // by repository-local storage. Ordinary model-root tests need no bypass.
        let base=std::env::temp_dir().canonicalize().unwrap().join(format!("software-release-{}-{}",std::process::id(),enclave_core::rng::u64()));
        std::fs::create_dir(&base).unwrap();std::fs::set_permissions(&base,std::fs::Permissions::from_mode(0o700)).unwrap();
        let m=std::fs::metadata(&base).unwrap();assert_eq!(m.uid(),unsafe{libc::geteuid()});assert_eq!(m.mode()&0o7777,0o700);
        Self {base}
    }
    fn directory(&self,name:&str)->PathBuf {
        let path=self.base.join(name);std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o700)).unwrap();
        let m=std::fs::metadata(&path).unwrap();assert_eq!(m.uid(),unsafe{libc::geteuid()});assert_eq!(m.mode()&0o7777,0o700);
        path
    }
    fn inputs(&self)->ProtectedInputs {
        // Model root is only this private fixture, never the production '/' walk.
        ProtectedInputs::at_root(self.base.clone(),File::open(&self.base).unwrap(),unsafe{libc::geteuid()}).unwrap()
    }
    fn file(&self,name:&str,bytes:&[u8])->PathBuf {
        use std::io::Write;
        let path=self.base.join(name);let mut file=File::options().create_new(true).write(true).mode(0o600).open(&path).unwrap();
        file.write_all(bytes).unwrap();path
    }
    fn owner(&self,c:&ReleaseConfig,client:TufClient)->TrustOwner {
        // Actual hardening, once for this fixture test process. This is not a
        // production gate override; native failure remains an actual test FAIL.
        static HARDENED:std::sync::OnceLock<bool>=std::sync::OnceLock::new();
        assert!(*HARDENED.get_or_init(enclave_core::resource::harden_process));
        let path=self.directory("state");
        state_names(ReleaseStateMode::FirstProvisioning,&path).unwrap();
        let mut inputs=self.inputs();inputs.directory(&path).unwrap();
        let lease=StateDirectoryLease::acquire(&path).unwrap();
        let binding=StateBinding::capture(&inputs,&path).unwrap();
        let (store,loaded)=SealedStore::open_bounded_required(&path,STORE,MAX_STATE_ENVELOPE).unwrap();
        assert!(matches!(loaded,Loaded::Fresh));
        TrustOwner {store,state:state_for(c,&client,NOW),client,clock:TrustedClock::anchored(NOW),path,
            persisted:None,poisoned:false,saves:0,saved_versions:None,binding,_lease:lease}
    }
}
impl Drop for Fixture {fn drop(&mut self){let _=std::fs::remove_dir_all(&self.base);}}

#[test]
fn release_held_files_refuse_symlinks_hardlinks_modes_and_named_or_inplace_changes() {
    for variant in ["symlink","hardlink","writable","renamed","inplace"] {
        let f=Fixture::new();let path=f.file("public.json",b"original public bytes");let mut inputs=f.inputs();
        match variant {
            "symlink"=>{let alias=f.base.join("alias");std::os::unix::fs::symlink(&path,&alias).unwrap();assert!(inputs.read(&alias,100).is_err());}
            "hardlink"=>{std::fs::hard_link(&path,f.base.join("alias")).unwrap();assert!(inputs.read(&path,100).is_err());}
            "writable"=>{std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o622)).unwrap();assert!(inputs.read(&path,100).is_err());}
            "renamed"=>{inputs.read(&path,100).unwrap();std::fs::rename(&path,f.base.join("prior")).unwrap();f.file("public.json",b"original public bytes");assert!(inputs.validate().is_err());}
            "inplace"=>{inputs.read(&path,100).unwrap();std::fs::write(&path,b"different public bytes").unwrap();assert!(inputs.validate().is_err());}
            _=>unreachable!(),
        }
    }
}

#[test]
fn release_held_directory_replacement_and_actual_domain_inode_alias_refuse() {
    let f=Fixture::new();let dir=f.directory("protected");
    let mut inputs=f.inputs();inputs.directory(&dir).unwrap();
    assert!(inputs.reject_domain_aliases(&[dir.clone()]).is_err());
    std::fs::rename(&dir,f.base.join("old-protected")).unwrap();f.directory("protected");
    assert!(inputs.validate().is_err());
    let alias=f.base.join("domain-alias");std::os::unix::fs::symlink(&dir,&alias).unwrap();
    assert!(probe_domain(&alias).is_err());
    assert!(probe_domain(&f.base.join("absent/child")).unwrap().is_none());
}

#[test]
#[cfg_attr(target_os="linux",ignore="requires protected ancestry; run explicitly with the coordinator private-root fixture runner and repository-local backing")]
fn release_real_sealed_state_restart_preserves_signed_floors_and_time_after_inventory_refusal() {
    let f=Fixture::new();let c=configuration();let repo=RepoBuilder::new(2,2);let set=metadata_set(&repo,2,INVENTORY,[EXP;4]);
    let client=refresh(&TufClient::bootstrap(&set.root).unwrap(),&set,&c).unwrap();
    let mut owner=f.owner(&c,client);owner.save().unwrap();
    owner.clock.now(NOW+100);owner.save().unwrap();let generation=owner.store.generation();
    assert!(owner.client.verify_target(TARGET,b"changed",NOW).is_err());
    let path=owner.path.clone();drop(owner);
    state_names(ReleaseStateMode::Existing,&path).unwrap();
    assert!(state_names(ReleaseStateMode::FirstProvisioning,&path).is_err());
    let lease=StateDirectoryLease::acquire(&path).unwrap();
    let (store,loaded)=SealedStore::open_bounded_required(&path,STORE,MAX_STATE_ENVELOPE).unwrap();
    assert_eq!(store.generation(),generation);
    let Loaded::State(bytes)=loaded else{panic!("retained state required")};
    let (state,client)=restore_state(&bytes,&c,&set.root).unwrap();assert_eq!(client.versions(),(2,2,2));
    assert!(state.high_water>=NOW+100);
    let mut resumed=TrustedClock::resumed(NOW-100,state.high_water);assert!(resumed.now(NOW-200)>=NOW+100);
    let one=metadata_set(&repo,1,INVENTORY,[EXP;4]);assert!(refresh(&client,&one,&c).is_err());
    drop(lease);
}

#[test]
#[cfg_attr(target_os="linux",ignore="requires protected ancestry; run explicitly with the coordinator private-root fixture runner and repository-local backing")]
fn release_state_deletion_tamper_or_named_replacement_poison_without_reset() {
    for variant in ["seed","state","checkpoint","both","corrupt","directory"] {
        let f=Fixture::new();let c=configuration();let repo=RepoBuilder::new(2,2);
        let client=TufClient::bootstrap(&repo.root(EXP).unwrap()).unwrap();let mut owner=f.owner(&c,client);owner.save().unwrap();
        let state=owner.path.join(format!("{STORE}.sealed"));let checkpoint=owner.path.join(format!("{STORE}.gen"));
        match variant {
            "seed"=>std::fs::remove_file(owner.path.join("sealing.key")).unwrap(),
            "state"=>std::fs::remove_file(&state).unwrap(),
            "checkpoint"=>std::fs::remove_file(&checkpoint).unwrap(),
            "both"=>{std::fs::remove_file(&state).unwrap();std::fs::remove_file(&checkpoint).unwrap();}
            "corrupt"=>std::fs::write(&state,b"corrupt public synthetic state").unwrap(),
            "directory"=>{std::fs::rename(&owner.path,f.base.join("retained-state")).unwrap();f.directory("state");}
            _=>unreachable!(),
        }
        assert!(owner.save().is_err(),"{variant}");assert!(owner.poisoned);
        assert!(owner.save().unwrap_err().is("RELEASE_AUTHORITY_POISONED"));
        assert!(state_names(ReleaseStateMode::FirstProvisioning,&owner.path).is_err() || variant=="directory");
        if variant=="both" {assert!(!state.exists());assert!(!checkpoint.exists());}
        if variant=="seed" {assert!(!owner.path.join("sealing.key").exists());}
    }
}

#[test]
#[cfg_attr(target_os="linux",ignore="requires protected ancestry; run explicitly with the coordinator private-root fixture runner and repository-local backing")]
fn release_existing_state_mode_never_creates_missing_authority_and_lease_contention_refuses() {
    let f=Fixture::new();let empty=f.directory("empty");
    assert!(state_names(ReleaseStateMode::Existing,&empty).is_err());
    assert_eq!(std::fs::read_dir(&empty).unwrap().count(),0);
    state_names(ReleaseStateMode::FirstProvisioning,&empty).unwrap();
    let _lease=StateDirectoryLease::acquire(&empty).unwrap();assert!(StateDirectoryLease::acquire(&empty).is_err());
    f.file("unrelated",b"public");
    std::fs::write(empty.join("unrelated"),b"public").unwrap();
    assert!(state_names(ReleaseStateMode::FirstProvisioning,&empty).is_err());
}

#[test]
fn release_platform_gate_requires_actual_native_and_root_without_fixture_fallback() {
    assert!(require_native_root(false,0).unwrap_err().is("RELEASE_NATIVE_REQUIRED"));
    assert!(require_native_root(true,501).unwrap_err().is("RELEASE_ROOT_REQUIRED"));
    assert!(require_native_root(true,0).is_ok());
    // No production SoftwareApproval is minted by these numeric predicates.
}

#[test]
fn release_failure_preserves_original_and_all_final_errors_in_existing_precedence() {
    let failure=SoftwareApprovalFailure::retain(err!(EACCES,"FIXTURE_ORIGINAL_REFUSAL"),
        SoftwareApprovalProgress::default(),None,None,None,[
            Err(err!(EIO,"FIXTURE_FINAL_SAVE")),Err(err!(ESTALE,"FIXTURE_FINAL_BINDING")),
            Err(err!(ESTALE,"FIXTURE_FINAL_CONTEXT")),Err(err!(EACCES,"FIXTURE_FINAL_GUARD"))]);
    assert!(failure.error.is("FIXTURE_FINAL_SAVE"));
    assert!(failure.operation_error.as_ref().unwrap().is("FIXTURE_ORIGINAL_REFUSAL"));
    assert_eq!(failure.final_errors.iter().map(|e|e.reason.as_str()).collect::<Vec<_>>(),
        ["FIXTURE_FINAL_SAVE","FIXTURE_FINAL_BINDING","FIXTURE_FINAL_CONTEXT","FIXTURE_FINAL_GUARD"]);
    assert!(failure.retained_checks().is_empty());
    assert!(!failure.progress.state_initialized&&!failure.progress.trust_state_saved);
    let early=SoftwareApprovalFailure::retain(err!(EACCES,"FIXTURE_EARLY_REFUSAL"),
        SoftwareApprovalProgress::default(),None,None,None,[Ok(()),Ok(()),Ok(()),Ok(())]);
    assert!(early.error.is("FIXTURE_EARLY_REFUSAL"));
    assert!(early.operation_error.is_none()&&early.final_errors.is_empty());
}

#[test]
fn release_failure_keeps_original_inputs_rechecks_replacement_and_redacts_owners() {
    let f=Fixture::new();let path=f.file("retained-public-input",b"original retained public marker");
    let mut inputs=f.inputs();inputs.read(&path,100).unwrap();
    // Exercise the same refusal-owner constructor; this is not admission and
    // does not manufacture a host guard or a SoftwareApproval capability.
    let failure=SoftwareApprovalFailure::retain(err!(EACCES,"FIXTURE_INPUT_REFUSAL"),
        SoftwareApprovalProgress::default(),Some(inputs),None,None,[Ok(()),Ok(()),Ok(()),Ok(())]);
    assert!(failure.retained_checks().is_empty());
    let debug=format!("{failure:?}");
    assert!(debug.contains("<redacted>"));assert!(!debug.contains("original retained public marker"));
    assert!(!debug.contains(path.to_str().unwrap()));assert!(!debug.contains("HeldInput"));
    std::fs::rename(&path,f.base.join("original-retained-input")).unwrap();
    f.file("retained-public-input",b"original retained public marker");
    assert!(!failure.retained_checks().is_empty());
    assert!(failure.error.is("FIXTURE_INPUT_REFUSAL"));
    assert!(!failure.progress.trust_state_saved&&failure.progress.generation.is_none());
}

#[test]
fn release_retained_directory_membership_denies_original_identity_after_named_metadata_loss() {
    let f=Fixture::new();let path=f.directory("retained-directory");let mut inputs=f.inputs();
    inputs.directory(&path).unwrap();let binding=StateBinding::capture(&inputs,&path).unwrap();
    let original=std::fs::metadata(&path).unwrap();
    assert!(retains_directory_identity(&inputs.directories,original.dev(),original.ino()));
    assert!(retains_directory_identity(&binding.directories,original.dev(),original.ino()));
    assert!(!retains_directory_identity(&inputs.directories,original.dev(),0));
    std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(inputs.validate().is_err()&&binding.validate().is_err());
    // The original owned identity remains excluded even after currentness is
    // lost. Membership is never a substitute for a successful current gate.
    assert!(retains_directory_identity(&inputs.directories,original.dev(),original.ino()));
    assert!(retains_directory_identity(&binding.directories,original.dev(),original.ino()));
}

#[test]
fn release_state_binding_capture_keeps_original_stamp_and_refuses_current_stat_adoption() {
    let f=Fixture::new();let path=f.directory("original-state-parent");let mut inputs=f.inputs();
    inputs.directory(&path).unwrap();let original=inputs.directories[&path].stamp;
    let descriptor=inputs.directories[&path].file.as_raw_fd();
    std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o755)).unwrap();
    // A changed current stat cannot become a new state-binding baseline.
    assert!(StateBinding::capture(&inputs,&path).is_err());
    assert_eq!(inputs.directories[&path].stamp,original);
    assert_eq!(inputs.directories[&path].file.as_raw_fd(),descriptor);
    assert!(inputs.directories[&path].mode_change.is_none());
    assert!(inputs.validate().is_err());
}

#[test]
fn release_directory_observations_report_all_changes_and_keep_both_original_owners() {
    let f=Fixture::new();let first=f.directory("first");let second=f.directory("second");
    let mut inputs=f.inputs();inputs.directory(&first).unwrap();inputs.directory(&second).unwrap();
    let binding=StateBinding::capture(&inputs,&first).unwrap();
    let originals=inputs.directories.iter().map(|(path,d)|(path.clone(),d.stamp,d.file.as_raw_fd())).collect::<Vec<_>>();
    // Ordinary DirStamp intentionally permits owned namespace changes. It does
    // not freeze mtime/ctime/nlink; actual event admission separately checks
    // the complete event snapshot before installing its bounded mode overlay.
    std::fs::create_dir(first.join("owned-child")).unwrap();
    inputs.validate().unwrap();binding.validate().unwrap();
    for path in [&first,&second] {std::fs::set_permissions(path,std::fs::Permissions::from_mode(0o755)).unwrap();}
    let renamed=f.base.join("retained-first");std::fs::rename(&first,&renamed).unwrap();
    std::fs::create_dir(&first).unwrap();std::fs::set_permissions(&first,std::fs::Permissions::from_mode(0o700)).unwrap();
    let errors=directory_observations(&inputs.directories,&inputs.base,None);
    assert_eq!(errors.len(),2);assert!(errors.iter().all(|e|e.is("RELEASE_DIRECTORY_CHANGED")));
    assert!(binding.validate().unwrap_err().is("RELEASE_STATE_DIRECTORY_CHANGED"));
    for (path,stamp,descriptor) in originals {
        let original=&inputs.directories[&path];assert_eq!(original.stamp,stamp);
        assert_eq!(original.file.as_raw_fd(),descriptor);assert!(original.mode_change.is_none());
    }
    assert_eq!(binding.directories[&first].stamp,inputs.directories[&first].stamp);
    assert_ne!(std::fs::metadata(&first).unwrap().ino(),inputs.directories[&first].stamp.ino);
    // No actual event, EX, checked target, guard or SoftwareApproval is made.
}

#[test]
fn release_mode_projection_is_only_root_directory700_to755_and_mints_no_event() {
    // These are inert public metadata values, never an actual core event or
    // a recipient overlay. Production must ALSO verify a genuine event and
    // SAME EX plus every actual held/named original before using a projection.
    let before=DirectoryModeIdentity {dev:7,ino:19,uid:0,gid:0,mode:libc::S_IFDIR as u32|0o700};
    let after=DirectoryModeIdentity {mode:libc::S_IFDIR as u32|0o755,..before};
    let original=DirStamp::from_identity(before);
    assert_eq!(predicted_mode_stamp(original,before,after).unwrap().identity(),after);
    assert_eq!(original.identity(),before);
    for invalid in [DirectoryModeIdentity {dev:8,..after},DirectoryModeIdentity {ino:20,..after},
        DirectoryModeIdentity {uid:501,..after},DirectoryModeIdentity {gid:20,..after},
        DirectoryModeIdentity {mode:libc::S_IFREG as u32|0o755,..after},
        DirectoryModeIdentity {mode:libc::S_IFDIR as u32|0o700,..after},
        DirectoryModeIdentity {mode:libc::S_IFDIR as u32|0o777,..after},
        DirectoryModeIdentity {mode:libc::S_IFDIR as u32|0o4755,..after}] {
        assert!(predicted_mode_stamp(original,before,invalid).unwrap_err().is("RELEASE_DIRECTORY_MODE_DELTA"));
    }
    for invalid in [DirectoryModeIdentity {dev:8,..before},DirectoryModeIdentity {ino:20,..before},
        DirectoryModeIdentity {uid:501,..before},DirectoryModeIdentity {gid:20,..before},
        DirectoryModeIdentity {mode:libc::S_IFREG as u32|0o700,..before},
        DirectoryModeIdentity {mode:libc::S_IFDIR as u32|0o755,..before}] {
        assert!(predicted_mode_stamp(original,invalid,after).is_err());
        assert!(predicted_mode_stamp(DirStamp::from_identity(invalid),invalid,after).is_err());
    }
}

#[test]
fn release_external_runtime_sources_refuse_real_input_identity_domains_and_source_aliases() {
    let f=Fixture::new();let original=f.file("software-config",b"original public SOFTWARE input");
    let mut inputs=f.inputs();inputs.read(&original,100).unwrap();
    let repository=f.directory("approval-repository");let state=f.directory("approval-state");
    let record=f.file("operator-record",b"public external record");let pin=f.file("operator-pin",b"public external pin");
    let record_fd=File::open(&record).unwrap();let pin_fd=File::open(&pin).unwrap();
    external_runtime_sources_separate(&inputs,&repository,&state,&[(&record,&record_fd),(&pin,&pin_fd)]).unwrap();
    assert!(external_runtime_sources_separate(&inputs,&repository,&state,&[]).is_err());
    assert!(external_runtime_sources_separate(&inputs,&repository,&state,
        &[(&record,&record_fd),(&pin,&pin_fd),(&record,&record_fd)]).is_err());
    for path in [original.clone(),original.join("child"),repository.join("operator-pin"),state.join("operator-pin")] {
        assert!(external_runtime_sources_separate(&inputs,&repository,&state,&[(&path,&pin_fd)]).unwrap_err()
            .is("RELEASE_EXTERNAL_RUNTIME_SOURCE_DOMAIN"));
    }
    let duplicate=inputs.files[&original].file.try_clone().unwrap();let different_spelling=f.base.join("unowned-alias");
    assert!(external_runtime_sources_separate(&inputs,&repository,&state,&[(&different_spelling,&duplicate)]).unwrap_err()
        .is("RELEASE_EXTERNAL_RUNTIME_SOURCE_INODE"));
    assert!(external_runtime_sources_separate(&inputs,&repository,&state,
        &[(&record,&record_fd),(&different_spelling,&record_fd)]).unwrap_err().is("RELEASE_EXTERNAL_RUNTIME_SOURCE_INODE"));
    inputs.validate().unwrap();assert_eq!(std::fs::read(&original).unwrap(),b"original public SOFTWARE input");
    // No SoftwareApproval or native/guard/operator authority is constructed.
}

#[test]
#[cfg_attr(target_os="linux",ignore="requires protected ancestry; run explicitly with the coordinator private-root fixture runner and repository-local backing")]
fn release_failure_after_actual_lease_keeps_lock_without_creating_or_repairing_state() {
    let f=Fixture::new();let path=f.directory("pending-state");let mut inputs=f.inputs();
    inputs.directory(&path).unwrap();state_names(ReleaseStateMode::FirstProvisioning,&path).unwrap();
    let lease=StateDirectoryLease::acquire(&path).unwrap();
    // The genuine post-acquire admission state-name check refuses. No native
    // gate is overridden: only these production lease/refusal primitives run.
    std::fs::write(path.join("intervening-public-file"),b"keep exactly").unwrap();
    let error=state_names(ReleaseStateMode::FirstProvisioning,&path).unwrap_err();
    let binding=inputs.validate();
    let failure=SoftwareApprovalFailure::retain(error,SoftwareApprovalProgress::default(),
        Some(inputs),None,Some(lease),[Ok(()),binding,Ok(()),Ok(())]);
    assert!(failure.error.is("RELEASE_STATE_MODE"));
    assert!(failure.retained_checks().is_empty());
    assert!(StateDirectoryLease::acquire(&path).err().unwrap().is("STATE_DIRECTORY_BUSY"));
    assert_eq!(std::fs::read_dir(&path).unwrap().count(),1);
    assert!(!path.join("sealing.key").exists());
    assert!(!failure.progress.state_initialization_attempted&&!failure.progress.trust_state_saved);
    assert!(failure.progress.generation.is_none());
    drop(failure);
    let _released=StateDirectoryLease::acquire(&path).unwrap();
    assert_eq!(std::fs::read(path.join("intervening-public-file")).unwrap(),b"keep exactly");
    assert_eq!(std::fs::read_dir(&path).unwrap().count(),1);
}

#[test]
#[cfg_attr(target_os="linux",ignore="requires protected ancestry; run explicitly with the coordinator private-root fixture runner and repository-local backing")]
fn release_failure_retains_real_trust_owner_checks_both_gates_and_never_saves_on_recheck() {
    let f=Fixture::new();let c=configuration();let repo=RepoBuilder::new(2,2);
    let set=metadata_set(&repo,2,INVENTORY,[EXP;4]);
    let client=refresh(&TufClient::bootstrap(&set.root).unwrap(),&set,&c).unwrap();
    let mut owner=f.owner(&c,client);owner.save().unwrap();let path=owner.path.clone();
    let input=f.file("public-input",b"original public input");let mut inputs=f.inputs();
    inputs.read(&input,100).unwrap();
    let error=owner.client.verify_target(TARGET,b"changed signed inventory",NOW).unwrap_err();
    let mut progress=SoftwareApprovalProgress::default();progress.observe(&owner);
    let failure=SoftwareApprovalFailure::retain(error,progress,Some(inputs),Some(owner),None,
        [Ok(()),Ok(()),Ok(()),Ok(())]);
    assert!(failure.progress.trust_state_saved);
    let generation=failure.progress.generation;let versions=failure.progress.versions;
    let paths=[path.join("sealing.key"),path.join(format!("{STORE}.sealed")),path.join(format!("{STORE}.gen"))];
    // Inspect metadata only: never read/copy the sealing key. Rechecks must not
    // restamp/save public trust state or turn this refusal into a fresh owner.
    let before=paths.iter().map(|p|Stamp::of(&std::fs::metadata(p).unwrap())).collect::<Vec<_>>();
    assert!(failure.retained_checks().is_empty());assert!(failure.retained_checks().is_empty());
    assert_eq!(before,paths.iter().map(|p|Stamp::of(&std::fs::metadata(p).unwrap())).collect::<Vec<_>>());
    assert_eq!((failure.progress.generation,failure.progress.versions),(generation,versions));
    assert!(StateDirectoryLease::acquire(&path).err().unwrap().is("STATE_DIRECTORY_BUSY"));
    std::fs::write(&input,b"changed public input").unwrap();
    std::fs::write(&paths[1],b"corrupted synthetic sealed state").unwrap();
    let errors=failure.retained_checks();assert_eq!(errors.len(),2);
    assert!(errors[0].is("RELEASE_INPUT_CHANGED"));
    assert!(failure.operation_error.is_none()&&failure.final_errors.is_empty());
    assert_eq!((failure.progress.generation,failure.progress.versions),(generation,versions));
    drop(failure);
    let _released=StateDirectoryLease::acquire(&path).unwrap();
    assert_eq!(std::fs::read(&paths[1]).unwrap(),b"corrupted synthetic sealed state");
}
