//! SOFTWARE report/schema tests. Synthetic hashes are declared observations,
//! never native signatures, independent provenance or installed acceptance.
use std::path::{Path, PathBuf};
use enclave_core::{deployment::*, Profile};
use depot_enclave::deploy::target_plan::{describe, prepare};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn target(profile: Profile, role: DeploymentRole) -> DeploymentTarget {
    let root=Path::new("/state/target-install-plan");
    DeploymentTarget {version:1,target_id:"plan-fixture".into(),role,profile,
        authority_config:root.join("support/authority.json"),
        expected_artifacts_manifest:root.join("support/artifacts.json"),
        codesign_pins_file:root.join("support/pins.json"),
        signing_identity_mode:match enclave_core::codesign::signing_mode() {
            enclave_core::codesign::SigningMode::LocalPins=>DeploymentSigningMode::LocalPins,
            enclave_core::codesign::SigningMode::TeamId=>DeploymentSigningMode::TeamId,
        },
        layout:DeploymentLayout {binary_dir:root.join("bin"),custody_bundle:root.join("support/Custody.app"),
            sandbox_dir:root.join("sandbox"),socket_root:root.join("run"),state_root:root.join("state"),
            audit_root:root.join("audit"),cas_store_root:root.join("objects"),staging_root:root.join("stage"),
            support_root:root.join("support"),launchd_namespace:"com.depot.plan-fixture".into(),
            mach_service:"com.depot.plan-fixture.exception".into()},
        broker:(profile==Profile::L3).then(||DeploymentBroker {base_dir:root.join("state/apfs-broker"),
            tuf_root_file:root.join("support/tuf-root.json")}),shared_read_only_inputs:vec![]}
}
fn descriptor_hash(t:&DeploymentTarget)->String {hex::encode(Sha256::digest(serde_json::to_vec(t).unwrap()))}
fn inventory(t:&DeploymentTarget)->Value {
    let mut paths=vec!["codesign-pins.json".to_owned()];
    for binary in ["depot-enclave","enclave-model-runnerd","enclave-swarm-syncd","enclave-apfs-broker",
        "enclave-agent-runtime","enclave-zk-auditor","enclave-cdp-browser","enclave-client-gateway","enclave-intent"] {
        paths.push(format!("bin/{binary}"));
    }
    for (bundle,binary) in [("EnclaveCustody.app","enclave-custody-vaultd"),("EnclaveOIDC.app","enclave-oidc")] {
        for suffix in ["Contents/Info.plist".to_owned(),"Contents/_CodeSignature/CodeResources".into(),
            format!("Contents/MacOS/{binary}")] {paths.push(format!("{bundle}/{suffix}"));}
    }
    for name in ["adapter","cas","custody","ifc","zk","browser","gateway"] {paths.push(format!("launchd/{name}.sb"));}
    for job in ["adapter","cas","custody","ifc","zk","supervisor","intent","oidc-broker","hydrate","browser","gateway"] {
        paths.push(format!("launchd/{}.{job}.plist",t.layout.launchd_namespace));
    }
    if t.profile==Profile::L3 {paths.push(format!("launchd/{}.apfs-broker.plist",t.layout.launchd_namespace));}
    for file in ["SHA256SUMS","custody.entitlements","yubikey-transport","install.sh","uninstall.sh",
        "public-trust.sh","fido-mds/yubico.json","launchd/provision-accounts.sh","launchd/enclave-daemon.entitlements"] {
        paths.push(file.into());
    }
    for name in ["root.json","timestamp.json","snapshot.json","targets.json","enclave-host-config.json",
        "enclave-policy.cedar.v1.json","vk_manifest.json","enclave-distribution-v1.json",
        "fido-mds-allowlist.json","custody-envelope-policy-v1.json"] {paths.push(format!("tuf/repo/{name}"));}
    paths.sort();
    json!({"version":1,"kind":"depot-first-touch-artifact-inventory","target_id":t.target_id,"profile":t.profile,
        "signing_identity_mode":t.signing_identity_mode,"deployment_config_sha256":descriptor_hash(t),
        "source_git_commit":"a".repeat(40),"source_manifest_sha256":"b".repeat(64),"source_input_count":3,
        "codesign_pins_sha256":"c".repeat(64),"staging_root":normalized_path(&t.layout.staging_root).unwrap(),
        "external_provenance":"UNKNOWN","files":paths.into_iter().map(|path|json!({"path":path,
            "sha256":"c".repeat(64),"size":37})).collect::<Vec<_>>()})
}
fn report(t:&DeploymentTarget,v:&Value)->Value {
    serde_json::to_value(describe(t,&descriptor_hash(t),&serde_json::to_vec(v).unwrap()).unwrap()).unwrap()
}
fn refused(t:&DeploymentTarget,v:&Value) {
    assert!(describe(t,&descriptor_hash(t),&serde_json::to_vec(v).unwrap()).is_err());
}

#[test]
fn both_roles_and_profiles_have_exact_inert_destinations_and_preservation() {
    for role in [DeploymentRole::DedicatedTest,DeploymentRole::ExistingUpgrade] {
        for profile in [Profile::L2,Profile::L3] {
            let t=target(profile,role);let input=inventory(&t);let p=report(&t,&input);
            assert_eq!(p["apply_supported"],false);assert_eq!(p["readiness"],"NOT_QUALIFIED");
            assert_eq!(p["external_provenance"],"UNKNOWN");assert_eq!(p["missing_required_files"],json!([]));
            let copies=p["copies"].as_array().unwrap();
            for (source,destination,mode) in [
                ("bin/depot-enclave",t.layout.binary_dir.join("depot-enclave"),"0755"),
                ("EnclaveCustody.app/Contents/MacOS/enclave-custody-vaultd",t.layout.custody_bundle.join("Contents/MacOS/enclave-custody-vaultd"),"0755"),
                ("EnclaveOIDC.app/Contents/Info.plist",t.layout.support_root.join("EnclaveOIDC.app/Contents/Info.plist"),"0644"),
                ("codesign-pins.json",t.codesign_pins_file.clone(),"0644"),
                ("launchd/com.depot.plan-fixture.intent.plist",PathBuf::from("/Library/LaunchAgents/com.depot.plan-fixture.intent.plist"),"0644"),
                ("launchd/com.depot.plan-fixture.cas.plist",PathBuf::from("/Library/LaunchDaemons/com.depot.plan-fixture.cas.plist"),"0644"),
            ] {
                let entry=copies.iter().find(|v|v["source"]==json!(normalized_path(&t.layout.staging_root).unwrap().join(source))).unwrap();
                assert_eq!(entry["destination"],json!(destination));assert_eq!(entry["mode"],mode);
                assert_eq!(entry["uid"],0);assert_eq!(entry["gid"],0);assert_eq!(entry["sha256"],"c".repeat(64));
            }
            assert!(p["retained_in_staging"].as_array().unwrap().iter().any(|v|v["source"].as_str().unwrap().ends_with("tuf/repo/root.json")));
            for entry in copies {let path=Path::new(entry["destination"].as_str().unwrap());
                for root in [&t.layout.state_root,&t.layout.audit_root,&t.layout.cas_store_root] {assert!(!path.starts_with(root));}}
            let state=p["directories"].as_array().unwrap().iter().find(|v|v["path"]==json!(t.layout.state_root.join("custody"))).unwrap();
            assert_eq!(state["uid"],703);assert_eq!(state["gid"],8703);assert_eq!(state["mode"],"0700");
            let text=serde_json::to_string(&p).unwrap();assert!(!text.contains("/opt/enterprise/enclave"));
            assert!(!text.contains("com.enterprise.enclave."));assert!(text.contains("preserve_enrollment_counters"));
        }
    }
}
#[test]
fn inventory_is_bound_to_exact_target_descriptor_profile_signing_and_source() {
    let t=target(Profile::L3,DeploymentRole::DedicatedTest);let good=inventory(&t);
    for (field,value) in [("target_id",json!("other")),("profile",json!("L2")),("version",json!(2)),
        ("deployment_config_sha256",json!("d".repeat(64))),("staging_root",json!("/other-stage")),
        ("source_git_commit",json!("A".repeat(40))),("source_manifest_sha256",json!("e".repeat(63))),
        ("source_input_count",json!(0)),("source_input_count",json!(100001)),("external_provenance",json!("PASS")),
        ("signing_identity_mode",json!(if t.signing_identity_mode==DeploymentSigningMode::LocalPins {"team-id"} else {"local-pins"}))] {
        let mut v=good.clone();v[field]=value;refused(&t,&v);
    }
}
#[test]
fn schema_refuses_unknown_duplicate_missing_and_per_file_authority_fields() {
    let t=target(Profile::L2,DeploymentRole::DedicatedTest);let good=inventory(&t);
    let mut v=good.clone();v["approval"]=json!(true);refused(&t,&v);
    for field in ["external_provenance","files","source_input_count"] {let mut v=good.clone();v.as_object_mut().unwrap().remove(field);refused(&t,&v);}
    for field in ["destination","role","signing_identity"] {let mut v=good.clone();v["files"][0][field]=json!("injected");refused(&t,&v);}
    let raw=serde_json::to_string(&good).unwrap().replacen('{',"{\"version\":1,",1);
    assert!(describe(&t,&descriptor_hash(&t),raw.as_bytes()).is_err());
    assert!(describe(&t,&descriptor_hash(&t),&vec![b' ';1024*1024+1]).is_err());
}
#[test]
fn path_escape_alias_unsorted_private_emulator_and_other_namespace_are_refused() {
    let t=target(Profile::L2,DeploymentRole::DedicatedTest);let good=inventory(&t);
    for path in ["../escape","/absolute","bin//depot-enclave","bin/./depot-enclave","bin/depot-enclave",
        "bin/enclave-fido-emulator","tuf/keys/keys.json","launchd/com.enterprise.enclave.cas.plist",
        "EnclaveOIDC.app/Contents/secret.key","tuf/repo/00.root.json","tuf/repo/2147483648.root.json"] {
        let mut v=good.clone();v["files"][0]["path"]=json!(path);
        v["files"].as_array_mut().unwrap().sort_by_key(|f|f["path"].as_str().unwrap().to_owned());refused(&t,&v);
    }
    let mut v=good.clone();v["files"].as_array_mut().unwrap().swap(0,1);refused(&t,&v);
    let mut v=good.clone();let entry=v["files"][0].clone();v["files"].as_array_mut().unwrap().insert(0,entry);refused(&t,&v);
}
#[test]
fn file_sizes_hashes_counts_and_pin_binding_are_enforced() {
    let t=target(Profile::L2,DeploymentRole::DedicatedTest);let good=inventory(&t);
    for (field,value) in [("size",json!(512*1024*1024u64+1)),("size",json!(-1)),("size",json!(0)),
        ("sha256",json!("C".repeat(64))),("sha256",json!("00"))] {
        let mut v=good.clone();v["files"][0][field]=value;refused(&t,&v);
    }
    let mut v=good.clone();v["codesign_pins_sha256"]=json!("d".repeat(64));refused(&t,&v);
    let mut v=good.clone();v["files"]=json!([]);refused(&t,&v);
    let mut v=good.clone();v["files"]=json!(vec![good["files"][0].clone();4097]);refused(&t,&v);
    for path in ["codesign-pins.json","bin/depot-enclave"] {let mut v=good.clone();
        v["files"].as_array_mut().unwrap().retain(|f|f["path"]!=path);refused(&t,&v);}
    let mut v=good.clone();
    v["files"].as_array_mut().unwrap().iter_mut().find(|f|f["path"]=="fido-mds/yubico.json").unwrap()["size"]=json!(16*1024*1024+1);
    refused(&t,&v);
}
#[test]
fn bounded_public_root_rotations_are_retained_without_overwriting_authority() {
    let t=target(Profile::L3,DeploymentRole::DedicatedTest);let mut v=inventory(&t);
    for n in 1..=32 {v["files"].as_array_mut().unwrap().push(json!({"path":format!("tuf/repo/{n}.root.json"),
        "sha256":"d".repeat(64),"size":1}));}
    v["files"].as_array_mut().unwrap().sort_by_key(|f|f["path"].as_str().unwrap().to_owned());
    let p=report(&t,&v);assert_eq!(p["retained_in_staging"].as_array().unwrap().iter()
        .filter(|f|f["source"].as_str().unwrap().ends_with(".root.json")).count(),32);
    v["files"].as_array_mut().unwrap().push(json!({"path":"tuf/repo/33.root.json","sha256":"d".repeat(64),"size":1}));
    v["files"].as_array_mut().unwrap().sort_by_key(|f|f["path"].as_str().unwrap().to_owned());refused(&t,&v);
}
#[test]
fn partial_payload_reports_missing_files_without_claiming_readiness() {
    let t=target(Profile::L2,DeploymentRole::DedicatedTest);let mut v=inventory(&t);
    v["files"].as_array_mut().unwrap().retain(|f|["bin/depot-enclave","codesign-pins.json"].contains(&f["path"].as_str().unwrap()));
    let p=report(&t,&v);assert!(p["missing_required_files"].as_array().unwrap().len()>20);
    assert_eq!(p["apply_supported"],false);assert_eq!(p["readiness"],"NOT_QUALIFIED");
}

#[test]
fn runtime_custody_inputs_are_required_bounded_and_never_payload_or_pin_copies() {
    for profile in [Profile::L2,Profile::L3] {
        let t=target(profile,DeploymentRole::DedicatedTest);let good=inventory(&t);
        for (name,maximum) in [
            ("fido-mds-allowlist.json",enclave_core::custody_metadata::MAX_MDS_BYTES),
            ("custody-envelope-policy-v1.json",enclave_core::custody_metadata::CustodyTarget::EnvelopePolicy.max_bytes())] {
            let path=format!("tuf/repo/{name}");let p=report(&t,&good);
            assert!(p["retained_in_staging"].as_array().unwrap().iter().any(|f|f["source"]==json!(t.layout.staging_root.join(&path))));
            assert!(!p["copies"].as_array().unwrap().iter().any(|f|f["source"]==json!(t.layout.staging_root.join(&path))));
            let mut missing=good.clone();missing["files"].as_array_mut().unwrap().retain(|f|f["path"]!=path);
            assert!(report(&t,&missing)["missing_required_files"].as_array().unwrap().contains(&json!(path)));
            let mut oversized=good.clone();oversized["files"].as_array_mut().unwrap().iter_mut()
                .find(|f|f["path"]==path).unwrap()["size"]=json!(maximum+1);refused(&t,&oversized);
        }
    }
}
#[test]
fn bundle_destination_and_public_authority_collisions_are_refused() {
    let mut t=target(Profile::L3,DeploymentRole::DedicatedTest);
    t.layout.custody_bundle=t.layout.support_root.join("EnclaveOIDC.app");
    refused(&t,&inventory(&t));
    let mut t=target(Profile::L3,DeploymentRole::DedicatedTest);
    t.authority_config=t.layout.support_root.join("EnclaveOIDC.app/Contents/Info.plist");
    refused(&t,&inventory(&t));
    let mut t=target(Profile::L3,DeploymentRole::ExistingUpgrade);
    t.layout.state_root="/Library/LaunchDaemons".into();t.broker.as_mut().unwrap().base_dir=t.layout.state_root.join("apfs-broker");
    refused(&t,&inventory(&t));
}
#[test]
fn case_aliases_cannot_hide_payload_authority_state_or_directory_collisions() {
    let mut t=target(Profile::L3,DeploymentRole::DedicatedTest);
    t.layout.custody_bundle=t.layout.support_root.join("enclaveoidc.app");
    refused(&t,&inventory(&t));
    let mut t=target(Profile::L3,DeploymentRole::DedicatedTest);
    t.authority_config=t.layout.support_root.join("ENCLAVEOIDC.APP/CONTENTS/INFO.PLIST");
    refused(&t,&inventory(&t));
    let mut t=target(Profile::L3,DeploymentRole::ExistingUpgrade);
    t.layout.state_root="/LIBRARY/LAUNCHDAEMONS".into();t.broker.as_mut().unwrap().base_dir=t.layout.state_root.join("apfs-broker");
    refused(&t,&inventory(&t));
    let mut t=target(Profile::L2,DeploymentRole::ExistingUpgrade);
    t.layout.binary_dir="/LIBRARY/Customdepot/bin".into();
    let p=report(&t,&inventory(&t));
    let paths=p["directories"].as_array().unwrap().iter().map(|d|d["path"].as_str().unwrap().to_ascii_lowercase()).collect::<Vec<_>>();
    assert_eq!(paths.len(),paths.iter().collect::<std::collections::BTreeSet<_>>().len());
    assert!(p["copies"].as_array().unwrap().iter().any(|c|c["destination"]=="/LIBRARY/Customdepot/bin/depot-enclave"));
}
#[test]
fn l2_cannot_publish_an_l3_broker_job() {
    let t=target(Profile::L2,DeploymentRole::DedicatedTest);let mut v=inventory(&t);
    v["files"].as_array_mut().unwrap().push(json!({"path":"launchd/com.depot.plan-fixture.apfs-broker.plist","sha256":"c".repeat(64),"size":1}));
    v["files"].as_array_mut().unwrap().sort_by_key(|f|f["path"].as_str().unwrap().to_owned());refused(&t,&v);
}
#[test]
fn cli_requires_protected_selection_and_exposes_no_apply_option() {
    for extra in [vec![],vec!["--apply"]] {
        let output=std::process::Command::new(env!("CARGO_BIN_EXE_depot-enclave"))
            .args(["launchd","deployment-install-plan"]).args(&extra).output().unwrap();
        assert!(!output.status.success());assert!(output.stdout.is_empty());
        let stderr=String::from_utf8_lossy(&output.stderr);
        assert!(if extra.is_empty(){stderr.contains("DEPLOYMENT_CONTEXT_REQUIRED")}else{stderr.contains("unexpected argument")});
    }
}

/// Run through the coordinator's root-owned private fixture. Explicitly ignored
/// by ordinary tests: no permissive-host skip can be mistaken for protected PASS.
#[test]
#[ignore = "requires coordinator private root fixture with ENCLAVE_TEST_STATE_ROOT"]
fn protected_inventory_plan_preserves_old_pins_and_rejects_changed_context() {
    use std::{fs,os::unix::fs::{MetadataExt,PermissionsExt}};
    let parent=PathBuf::from(std::env::var_os("ENCLAVE_TEST_STATE_ROOT").expect("explicit private fixture root"));
    let base=parent.join(format!("target-plan-{}",std::process::id()));
    fs::create_dir(&base).unwrap();fs::set_permissions(&base,fs::Permissions::from_mode(0o700)).unwrap();
    struct Cleanup(PathBuf);impl Drop for Cleanup {fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}
    let _cleanup=Cleanup(base.clone());
    let support=base.join("support");fs::create_dir(&support).unwrap();
    let mut t=target(Profile::L2,DeploymentRole::DedicatedTest);
    t.layout.support_root=support.clone();t.layout.custody_bundle=support.join("Custody.app");
    t.authority_config=support.join("authority.json");t.codesign_pins_file=support.join("pins.json");
    t.expected_artifacts_manifest=support.join("artifacts.json");
    let config=base.join("target.json");
    let pins=br#"{"v":1,"pins":{"com.enterprise.enclave.ctl":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}}"#;
    for (path,bytes) in [(&config,serde_json::to_vec(&t).unwrap()),(&t.authority_config,b"{}".to_vec()),
        (&t.codesign_pins_file,pins.to_vec()),(&t.expected_artifacts_manifest,serde_json::to_vec(&inventory(&t)).unwrap())] {
        fs::write(path,bytes).unwrap();fs::set_permissions(path,fs::Permissions::from_mode(0o644)).unwrap();
    }
    for ancestor in config.ancestors() {let m=fs::symlink_metadata(ancestor).unwrap();
        assert_eq!(m.uid(),0,"private fixture must be actually root-owned");assert_eq!(m.mode()&0o022,0);assert!(!m.file_type().is_symlink());}
    let checked=load(&config).unwrap();let plan=prepare(&checked).unwrap();
    assert_eq!(plan.candidate_codesign_pins_sha256,"c".repeat(64));
    assert_ne!(plan.candidate_codesign_pins_sha256,hex::encode(Sha256::digest(pins)));
    assert_eq!(fs::read(&t.codesign_pins_file).unwrap(),pins);
    assert!(!t.layout.binary_dir.join("depot-enclave").exists());
    let mut changed=fs::read(&config).unwrap();changed.push(b'\n');fs::write(&config,changed).unwrap();
    assert!(prepare(&checked).unwrap_err().is("DEPLOYMENT_CHANGED"));
    assert_eq!(fs::read(&t.codesign_pins_file).unwrap(),pins);
}
