// Included only inside ctl::target_grant_key for focused SOFTWARE fixtures.
mod tests {
    use super::*;
    use enclave_core::deployment::{self,DeploymentLayout,DeploymentRole,DeploymentSigningMode};
    use std::{fs,os::unix::fs::{PermissionsExt,symlink}};

    fn target(root:&Path,role:DeploymentRole)->DeploymentTarget {
        DeploymentTarget {version:1,target_id:if role==DeploymentRole::DedicatedTest {"grant-dedicated"} else {"grant-upgrade"}.into(),
            role,profile:Profile::L2,authority_config:root.join("support/authority.json"),
            expected_artifacts_manifest:root.join("support/artifacts.json"),codesign_pins_file:root.join("support/pins.json"),
            signing_identity_mode:match enclave_core::codesign::signing_mode() {
                enclave_core::codesign::SigningMode::LocalPins=>DeploymentSigningMode::LocalPins,
                enclave_core::codesign::SigningMode::TeamId=>DeploymentSigningMode::TeamId,
            },
            layout:DeploymentLayout {binary_dir:root.join("bin"),custody_bundle:root.join("support/Custody.app"),
                sandbox_dir:root.join("sandbox"),socket_root:root.join("run"),state_root:root.join("state"),
                audit_root:root.join("audit"),cas_store_root:root.join("cas"),staging_root:root.join("stage"),
                support_root:root.join("support"),launchd_namespace:if role==DeploymentRole::DedicatedTest {"com.depot.grant-dedicated"} else {"com.depot.grant-upgrade"}.into(),
                mach_service:if role==DeploymentRole::DedicatedTest {"com.depot.grant-dedicated.exception"} else {"com.depot.grant-upgrade.exception"}.into()},
            broker:None,shared_read_only_inputs:vec![]}
    }
    fn env(t:&DeploymentTarget)->Env {Env {dev:false,profile:t.profile,state_dir:t.layout.state_root.clone(),
        socket_dir:t.layout.socket_root.clone(),audit_dir:t.layout.audit_root.clone()}}
    #[test]
    fn exact_selected_state_and_all_environment_routes_are_required_before_io() {
        for role in [DeploymentRole::DedicatedTest,DeploymentRole::ExistingUpgrade] {
            let t=target(Path::new("/unopened-grant-fixture"),role);let good=env(&t);
            assert!(bind(&good,None,&t).unwrap()==t.layout.state_root);
            assert!(bind(&good,Some(&t.layout.state_root),&t).is_ok());
            for wrong in [Path::new("/var/db/enclave"),Path::new("/other-target/state"),Path::new("/unopened-grant-fixture/STATE")] {
                assert!(bind(&good,Some(wrong),&t).unwrap_err().is("DEPLOYMENT_GRANT_STATE_MISMATCH"));
            }
            for slot in 0..5 {let mut bad=good.clone();match slot {0=>bad.dev=true,1=>bad.profile=Profile::L3,
                2=>bad.state_dir="/var/db/enclave".into(),3=>bad.socket_dir="/other-target/run".into(),_=>bad.audit_dir="/other-target/audit".into()}
                assert!(bind(&bad,None,&t).unwrap_err().is("DEPLOYMENT_GRANT_CONTEXT_MISMATCH"));}
        }
    }
    #[test]
    fn invalid_key_material_refuses_without_secret_diagnostics() {
        for raw in [b"".as_slice(),b"00",b"zzzz",b"\xff",b"private seed"] {
            let error=parsed(raw).unwrap_err();assert!(error.is("GRANT_KEY_INVALID"));
            assert!(!format!("{error}").contains("private seed"));
        }
        let input=SecretBytes::new(format!("\n {} \n","AB".repeat(32)).into_bytes());
        let parsed=parsed(input.expose()).unwrap();assert!(parsed.expose().iter().all(|b|*b==0xab));
    }

    struct Fixture {base:PathBuf,config:PathBuf,checked:CheckedDeploymentTarget,env:Env,owners:KeyOwners}
    impl Fixture {
        fn new(role:DeploymentRole)->Self {
            Self::with_owners(role,KeyOwners::production())
        }
        fn neutral(role:DeploymentRole)->Self {
            Self::with_owners(role,KeyOwners::neutral())
        }
        fn with_owners(role:DeploymentRole,owners:KeyOwners)->Self {
            assert!(enclave_core::ipc::geteuid()==0,"actual root private fixture required");
            let parent=PathBuf::from(std::env::var_os("ENCLAVE_TEST_STATE_ROOT").expect("explicit private fixture root"));
            let base=parent.join(format!("target-grant-key-{}",hex::encode(enclave_core::rng::bytes32())));
            fs::create_dir(&base).unwrap();fs::set_permissions(&base,fs::Permissions::from_mode(0o700)).unwrap();
            let t=target(&base,role);t.validate().unwrap();
            fs::create_dir(&t.layout.support_root).unwrap();fs::set_permissions(&t.layout.support_root,fs::Permissions::from_mode(0o700)).unwrap();
            let config=t.layout.support_root.join("target.json");
            let pins=br#"{"v":1,"pins":{"com.enterprise.enclave.ctl":["abababababababababababababababababababab"],"com.enterprise.enclave.custody":["abababababababababababababababababababab"]}}"#;
            for (path,bytes) in [(&config,serde_json::to_vec(&t).unwrap()),(&t.authority_config,b"{}".to_vec()),
                (&t.expected_artifacts_manifest,b"{}".to_vec()),(&t.codesign_pins_file,pins.to_vec())] {
                fs::write(path,bytes).unwrap();fs::set_permissions(path,fs::Permissions::from_mode(0o600)).unwrap();
            }
            fs::create_dir(&t.layout.state_root).unwrap();fs::set_permissions(&t.layout.state_root,fs::Permissions::from_mode(0o755)).unwrap();
            for d in [DaemonId::AgentRuntime,DaemonId::CustodyVault] {
                let owner=if d==DaemonId::AgentRuntime {owners.ifc} else {owners.custody};
                let path=t.layout.state_root.join(d.dir_name());fs::create_dir(&path).unwrap();
                fs::set_permissions(&path,fs::Permissions::from_mode(0o700)).unwrap();
                std::os::unix::fs::chown(&path,Some(owner.uid),Some(owner.gid)).unwrap();
                let observed=fs::metadata(&path).unwrap();
                assert!(observed.uid()==owner.uid && observed.gid()==owner.gid,"private filesystem must apply required ownership");
            }
            let checked=deployment::load(&config).unwrap();let env=env(&t);
            Self {base,config,checked,env,owners}
        }
        fn seed_path(&self)->PathBuf {self.env.state_dir.join("ifc").join(crate::launchd::GRANT_SEED_FILE)}
        fn public_path(&self)->PathBuf {self.env.state_dir.join("custody").join(crate::launchd::GRANT_PUBLIC_FILE)}
        fn put(&self,path:&Path,raw:&[u8],d:DaemonId) {
            let owner=if d==DaemonId::AgentRuntime {self.owners.ifc} else {self.owners.custody};
            fs::write(path,raw).unwrap();fs::set_permissions(path,fs::Permissions::from_mode(0o600)).unwrap();
            std::os::unix::fs::chown(path,Some(owner.uid),Some(owner.gid)).unwrap();
        }
        fn call(&self)->EnclaveResult<String> {provision(&self.env,None,&self.checked)}
        // Exercises the real algorithm with explicit test-only neutral owner
        // arguments. It does not exercise/admit the fixed-UID public wrapper.
        fn neutral_call(&self)->EnclaveResult<String> {
            let state=open_root(&self.env.state_dir)?;work(&state,&self.checked,self.owners)
        }
        fn seed_only(&self)->SecretBytes {
            let raw=SecretBytes::new(format!("  {}\n","AB".repeat(32)).into_bytes());
            self.put(&self.seed_path(),raw.expose(),DaemonId::AgentRuntime);raw
        }
    }
    impl Drop for Fixture {fn drop(&mut self){let _=fs::remove_dir_all(&self.base);}}

    #[test]
    #[ignore="requires actual root private filesystem; no ordinary ownership skip"]
    fn selected_public_api_dedicated_and_upgrade_are_idempotent_and_isolated() {
        const CHILD:&str="depot_TARGET_GRANT_KEY_ROLE";
        if let Some(role)=std::env::var_os(CHILD) {
            let role=if role=="dedicated" {DeploymentRole::DedicatedTest} else {DeploymentRole::ExistingUpgrade};
            let f=Fixture::new(role);deployment::select(f.checked.clone()).unwrap();
            let selected=deployment::selected().unwrap();let env=Env::production_for_target(selected).unwrap();
            let other=f.base.join("other-state");fs::create_dir(&other).unwrap();fs::write(other.join("marker"),b"peer target untouched").unwrap();
            let public=super::super::provision_target_grant_key(&env,None).unwrap();
            let seed=SecretBytes::new(fs::read(f.seed_path()).unwrap());let bytes=fs::read(f.public_path()).unwrap();
            let before=fs::metadata(f.seed_path()).unwrap();let public_before=fs::metadata(f.public_path()).unwrap();
            let again=super::super::provision_target_grant_key(&env,Some(&env.state_dir)).unwrap();
            assert!(public==again && public.as_bytes()==bytes.as_slice());
            assert!(fs::read(f.seed_path()).unwrap().as_slice()==seed.expose());
            assert!(fs::read(f.public_path()).unwrap()==bytes);
            assert!(unchanged(&before,&fs::metadata(f.seed_path()).unwrap()));
            assert!(unchanged(&public_before,&fs::metadata(f.public_path()).unwrap()));
            assert!(fs::read(other.join("marker")).unwrap()==b"peer target untouched");
            assert!(fs::metadata(f.seed_path()).unwrap().uid()==704 && fs::metadata(f.public_path()).unwrap().uid()==703);
            assert!(super::super::provision_target_grant_key(&env,Some(Path::new("/var/db/enclave"))).unwrap_err().is("DEPLOYMENT_GRANT_STATE_MISMATCH"));
            return;
        }
        for role in ["dedicated","upgrade"] {
            let output=std::process::Command::new(std::env::current_exe().unwrap())
                .args(["ctl::target_grant_key::tests::selected_public_api_dedicated_and_upgrade_are_idempotent_and_isolated",
                    "--exact","--ignored","--nocapture"]).env(CHILD,role).output().unwrap();
            assert!(output.status.success(),"selected role subprocess failed: {}",String::from_utf8_lossy(&output.stderr));
        }
    }
    #[test]
    #[ignore="requires actual root private filesystem; no ordinary ownership skip"]
    fn existing_seed_and_matching_public_bytes_are_preserved_exactly() {
        let f=Fixture::new(DeploymentRole::ExistingUpgrade);let raw=f.seed_only();let expected=key_public(&parsed(raw.expose()).unwrap()).unwrap();
        let public=format!("\n {} \n",expected.to_uppercase());f.put(&f.public_path(),public.as_bytes(),DaemonId::CustodyVault);
        let seed_before=fs::metadata(f.seed_path()).unwrap();let public_before=fs::metadata(f.public_path()).unwrap();
        assert!(f.call().unwrap()==expected);
        assert!(fs::read(f.seed_path()).unwrap().as_slice()==raw.expose());assert!(fs::read(f.public_path()).unwrap()==public.as_bytes());
        assert!(unchanged(&seed_before,&fs::metadata(f.seed_path()).unwrap()));assert!(unchanged(&public_before,&fs::metadata(f.public_path()).unwrap()));
    }
    #[test]
    #[ignore="requires actual root private filesystem; no ordinary ownership skip"]
    fn durable_seed_only_prefix_recovers_same_key_without_rotation() {
        let f=Fixture::new(DeploymentRole::DedicatedTest);let state=open_root(&f.env.state_dir).unwrap();let ifc=child(&state,DaemonId::AgentRuntime).unwrap();
        let raw=SecretBytes::new("cd".repeat(32).into_bytes());
        create(&state,&ifc,crate::launchd::GRANT_SEED_FILE,DaemonId::AgentRuntime,raw.expose()).unwrap();
        let before=fs::metadata(f.seed_path()).unwrap();let expected=key_public(&parsed(raw.expose()).unwrap()).unwrap();
        assert!(!f.public_path().exists());assert!(f.call().unwrap()==expected);assert!(f.call().unwrap()==expected);
        assert!(fs::read(f.seed_path()).unwrap().as_slice()==raw.expose());assert!(unchanged(&before,&fs::metadata(f.seed_path()).unwrap()));
    }
    #[test]
    #[ignore="requires actual root private filesystem; no ordinary ownership skip"]
    fn orphan_public_mismatch_and_invalid_existing_seed_refuse_without_overwrite() {
        for case in 0..3 {
            let f=Fixture::new(DeploymentRole::ExistingUpgrade);
            if case==2 {f.put(&f.seed_path(),b"invalid seed",DaemonId::AgentRuntime);}
            else {f.put(&f.public_path(),"ef".repeat(32).as_bytes(),DaemonId::CustodyVault);}
            if case==1 {f.seed_only();}
            let seed=fs::read(f.seed_path()).ok().map(SecretBytes::new);let public=fs::read(f.public_path()).ok();
            let error=f.call().unwrap_err();assert!(match case {0=>error.is("GRANT_KEY_ORPHAN_PUBLIC"),1=>error.is("GRANT_KEY_PUBLIC_MISMATCH"),_=>error.is("GRANT_KEY_INVALID")});
            assert!(match seed {Some(raw)=>fs::read(f.seed_path()).unwrap().as_slice()==raw.expose(),None=>!f.seed_path().exists()});
            assert!(fs::read(f.public_path()).ok()==public);
        }
    }
    #[test]
    #[ignore="requires actual root private filesystem; no ordinary ownership skip"]
    fn unsafe_seed_paths_permissions_owners_and_links_refuse() {
        for case in 0..5 {
            let f=Fixture::new(DeploymentRole::DedicatedTest);let raw=f.seed_only();
            match case {
                0=>fs::set_permissions(f.seed_path(),fs::Permissions::from_mode(0o644)).unwrap(),
                1=>std::os::unix::fs::chown(f.seed_path(),Some(703),None).unwrap(),
                2=>fs::hard_link(f.seed_path(),f.base.join("extra-seed-link")).unwrap(),
                3=>{let saved=f.base.join("seed-save");fs::rename(f.seed_path(),&saved).unwrap();symlink(saved,f.seed_path()).unwrap();},
                _=>{let directory=f.env.state_dir.join("ifc");let saved=f.base.join("ifc-save");fs::rename(&directory,&saved).unwrap();symlink(saved,directory).unwrap();},
            }
            assert!(f.call().is_err());assert!(!f.public_path().exists());
            if case<3 {assert!(fs::read(f.seed_path()).unwrap().as_slice()==raw.expose());}
        }
    }
    #[test]
    #[ignore="requires actual root private filesystem; no ordinary ownership skip"]
    fn changed_descriptor_or_wrong_state_refuses_before_key_creation() {
        let f=Fixture::new(DeploymentRole::DedicatedTest);
        assert!(provision(&f.env,Some(Path::new("/var/db/enclave")),&f.checked).unwrap_err().is("DEPLOYMENT_GRANT_STATE_MISMATCH"));
        let mut bad=f.env.clone();bad.dev=true;assert!(provision(&bad,None,&f.checked).unwrap_err().is("DEPLOYMENT_GRANT_CONTEXT_MISMATCH"));
        assert!(!f.env.state_dir.join(LOCK).exists());
        let mut changed=fs::read(&f.config).unwrap();changed.push(b'\n');fs::write(&f.config,changed).unwrap();
        assert!(f.call().unwrap_err().is("DEPLOYMENT_CHANGED"));
        assert!(!f.seed_path().exists() && !f.public_path().exists() && !f.env.state_dir.join(LOCK).exists());
    }
    #[test]
    #[ignore="requires actual root private filesystem; no ordinary ownership skip"]
    fn root_directory_permissions_and_same_target_concurrency_are_checked() {
        let f=Fixture::new(DeploymentRole::DedicatedTest);let state=open_root(&f.env.state_dir).unwrap();let guard=lock(&state).unwrap();
        assert!(f.call().unwrap_err().is("GRANT_KEY_BUSY"));assert!(!f.seed_path().exists() && !f.public_path().exists());
        drop(guard);assert!(f.call().is_ok());
        let raw=SecretBytes::new(fs::read(f.seed_path()).unwrap());
        fs::set_permissions(&f.env.state_dir,fs::Permissions::from_mode(0o777)).unwrap();
        assert!(f.call().unwrap_err().is("GRANT_KEY_PROTECTED_ROOT"));
        assert!(fs::read(f.seed_path()).unwrap().as_slice()==raw.expose());
    }
    #[test]
    #[ignore="requires actual root private filesystem; no ordinary ownership skip"]
    fn create_only_publication_never_replaces_an_existing_key() {
        let f=Fixture::new(DeploymentRole::ExistingUpgrade);let raw=f.seed_only();let state=open_root(&f.env.state_dir).unwrap();let ifc=child(&state,DaemonId::AgentRuntime).unwrap();
        assert!(create(&state,&ifc,crate::launchd::GRANT_SEED_FILE,DaemonId::AgentRuntime,"aa".repeat(32).as_bytes()).unwrap_err().is("GRANT_KEY_PUBLICATION_REFUSED"));
        assert!(fs::read(f.seed_path()).unwrap().as_slice()==raw.expose());
        assert!(!fs::read_dir(&f.env.state_dir).unwrap().any(|e|e.unwrap().file_name().to_string_lossy().starts_with(".ifc-grant-tmp-")));
    }

    #[test]
    #[ignore="SOFTWARE neutral ownership; requires private root filesystem, not distinct-UID evidence"]
    fn neutral_software_algorithm_creates_and_preserves_keys_for_both_roles() {
        for role in [DeploymentRole::DedicatedTest,DeploymentRole::ExistingUpgrade] {
            let f=Fixture::neutral(role);let public=f.neutral_call().unwrap();
            let raw=SecretBytes::new(fs::read(f.seed_path()).unwrap());let before=fs::metadata(f.seed_path()).unwrap();
            let old_public=fs::read(f.public_path()).unwrap();let public_before=fs::metadata(f.public_path()).unwrap();
            assert!(key_public(&parsed(raw.expose()).unwrap()).unwrap()==public);
            assert!(f.neutral_call().unwrap()==public && fs::read(f.seed_path()).unwrap().as_slice()==raw.expose());
            assert!(fs::read(f.public_path()).unwrap()==old_public);
            assert!(unchanged(&before,&fs::metadata(f.seed_path()).unwrap()) && unchanged(&public_before,&fs::metadata(f.public_path()).unwrap()));
            assert!(fs::metadata(f.seed_path()).unwrap().uid()==0 && fs::metadata(f.public_path()).unwrap().uid()==0);
        }
    }
    #[test]
    #[ignore="SOFTWARE neutral ownership; requires private root filesystem, not distinct-UID evidence"]
    fn neutral_software_existing_bytes_and_seed_only_prefix_survive_recovery() {
        for full in [false,true] {
            let f=Fixture::neutral(DeploymentRole::ExistingUpgrade);let raw=f.seed_only();
            let expected=key_public(&parsed(raw.expose()).unwrap()).unwrap();
            let public=format!(" {}\n",expected.to_uppercase());
            if full {f.put(&f.public_path(),public.as_bytes(),DaemonId::CustodyVault);}
            let before=fs::metadata(f.seed_path()).unwrap();assert!(f.neutral_call().unwrap()==expected);
            assert!(fs::read(f.seed_path()).unwrap().as_slice()==raw.expose());assert!(unchanged(&before,&fs::metadata(f.seed_path()).unwrap()));
            assert!(fs::read(f.public_path()).unwrap().as_slice()==if full {public.as_bytes()} else {expected.as_bytes()});
        }
    }
    #[test]
    #[ignore="SOFTWARE neutral ownership; requires private root filesystem, not distinct-UID evidence"]
    fn neutral_software_orphan_mismatch_and_invalid_seed_refuse_without_overwrite() {
        for case in 0..3 {
            let f=Fixture::neutral(DeploymentRole::DedicatedTest);
            if case==2 {f.put(&f.seed_path(),b"invalid",DaemonId::AgentRuntime);}
            else {f.put(&f.public_path(),"ef".repeat(32).as_bytes(),DaemonId::CustodyVault);}
            if case==1 {f.seed_only();}
            let seed=fs::read(f.seed_path()).ok().map(SecretBytes::new);let public=fs::read(f.public_path()).ok();
            let error=f.neutral_call().unwrap_err();assert!(match case {0=>error.is("GRANT_KEY_ORPHAN_PUBLIC"),1=>error.is("GRANT_KEY_PUBLIC_MISMATCH"),_=>error.is("GRANT_KEY_INVALID")});
            assert!(match seed {Some(raw)=>fs::read(f.seed_path()).unwrap().as_slice()==raw.expose(),None=>!f.seed_path().exists()});
            assert!(fs::read(f.public_path()).ok()==public);
        }
    }
    #[test]
    #[ignore="SOFTWARE neutral ownership; requires private root filesystem, not distinct-UID evidence"]
    fn neutral_software_nofollow_modes_links_and_context_drift_refuse() {
        for case in 0..5 {
            let f=Fixture::neutral(DeploymentRole::DedicatedTest);let raw=f.seed_only();
            match case {
                0=>fs::set_permissions(f.seed_path(),fs::Permissions::from_mode(0o644)).unwrap(),
                1=>fs::hard_link(f.seed_path(),f.base.join("extra-link")).unwrap(),
                2=>{let saved=f.base.join("seed-saved");fs::rename(f.seed_path(),&saved).unwrap();symlink(saved,f.seed_path()).unwrap();},
                3=>fs::set_permissions(f.env.state_dir.join("custody"),fs::Permissions::from_mode(0o777)).unwrap(),
                _=>{let mut bytes=fs::read(&f.config).unwrap();bytes.push(b'\n');fs::write(&f.config,bytes).unwrap();},
            }
            assert!(f.neutral_call().is_err());assert!(!f.public_path().exists());
            if case!=2 {assert!(fs::read(f.seed_path()).unwrap().as_slice()==raw.expose());}
        }
    }
    #[test]
    #[ignore="SOFTWARE neutral ownership; requires private root filesystem, not distinct-UID evidence"]
    fn neutral_software_create_only_publication_and_concurrent_lock_are_real_fd_operations() {
        let f=Fixture::neutral(DeploymentRole::DedicatedTest);let raw=f.seed_only();let state=open_root(&f.env.state_dir).unwrap();
        let ifc=child_owned(&state,DaemonId::AgentRuntime,f.owners.ifc).unwrap();
        assert!(create_owned(&state,&ifc,crate::launchd::GRANT_SEED_FILE,f.owners.ifc,"ab".repeat(32).as_bytes())
            .unwrap_err().is("GRANT_KEY_PUBLICATION_REFUSED"));
        assert!(fs::read(f.seed_path()).unwrap().as_slice()==raw.expose());
        let guard=lock(&state).unwrap();assert!(f.neutral_call().unwrap_err().is("GRANT_KEY_BUSY"));assert!(!f.public_path().exists());
        drop(guard);assert!(f.neutral_call().is_ok());
        assert!(!fs::read_dir(&f.env.state_dir).unwrap().any(|e|e.unwrap().file_name().to_string_lossy().starts_with(".ifc-grant-tmp-")));
    }
    #[test]
    #[ignore="SOFTWARE negative only; requires private root filesystem, fixed production owners unchanged"]
    fn neutral_software_fixture_cannot_bypass_fixed_production_directory_owners() {
        let f=Fixture::neutral(DeploymentRole::ExistingUpgrade);
        assert!(f.call().unwrap_err().is("GRANT_KEY_DIRECTORY"));assert!(!f.seed_path().exists() && !f.public_path().exists());
    }
    #[test]
    #[ignore="SOFTWARE actual-FD owner mismatch; requires private root filesystem, not actual fchown acceptance"]
    fn neutral_software_wrong_observed_owner_refuses_before_final_name_publication() {
        use std::os::unix::fs::OpenOptionsExt;
        let f=Fixture::neutral(DeploymentRole::DedicatedTest);let state=open_root(&f.env.state_dir).unwrap();
        let ifc=child_owned(&state,DaemonId::AgentRuntime,f.owners.ifc).unwrap();
        let component=name(".ifc-grant-tmp-owner-negative").unwrap();
        let _temporary=Temporary {state:&state,component:component.clone()};
        let path=f.env.state_dir.join(component.to_str().unwrap());
        let mut file=fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).unwrap();
        fs::set_permissions(f.env.state_dir.join(component.to_str().unwrap()),fs::Permissions::from_mode(0o600)).unwrap();
        file.write_all(b"known synthetic fixture").unwrap();
        let m=metadata(&file).unwrap();assert!(m.uid()==0 && m.gid()==0 && m.nlink()==1 && m.mode()&0o7777==0o600);
        // Observe a genuinely root-owned held FD while requiring the fixed IFC
        // owner. This exercises the complete publication gate, without claiming
        // a real chown succeeded or replacing OS metadata with a fake value.
        assert!(publish_created(&state,&ifc,crate::launchd::GRANT_SEED_FILE,KeyOwner::daemon(DaemonId::AgentRuntime),
            b"known synthetic fixture".len(),&component,&file).unwrap_err().is("GRANT_KEY_CREATE"));
        assert!(!f.seed_path().exists() && !f.public_path().exists());
    }
}
