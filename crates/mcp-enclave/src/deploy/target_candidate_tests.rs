//! Pure/software verification fixtures; no genuine approval/guard is minted.
use super::*;
use std::{
    cell::{Cell, RefCell},
    io::{Seek, SeekFrom},
    os::unix::fs::PermissionsExt,
};

fn pins(mode: DeploymentSigningMode) -> serde_json::Value {
    let map = EXECUTABLES
        .iter()
        .map(|(_, id)| *id)
        .chain(BUNDLES.iter().map(|(_, _, id, _)| *id))
        .map(|id| (id.to_owned(), serde_json::json!(["ab".repeat(20)])))
        .collect::<serde_json::Map<_, _>>();
    serde_json::json!({"v":1,"mode":mode_text(mode),"pins":map})
}
fn parsed(
    value: &serde_json::Value,
    mode: DeploymentSigningMode,
) -> EnclaveResult<BTreeMap<String, CodeRequirement>> {
    requirements(&serde_json::to_vec(value).unwrap(), mode)
}
#[test]
fn exact_candidate_pin_set_preserves_original_ids_compiled_team_and_disjoint_hashes() {
    for mode in [
        DeploymentSigningMode::LocalPins,
        DeploymentSigningMode::TeamId,
    ] {
        let mut value = pins(mode);
        value["pins"]["com.enterprise.enclave.ctl"] =
            serde_json::json!(["01".repeat(20), "fe".repeat(20)]);
        let result = parsed(&value, mode).unwrap();
        assert_eq!(result.len(), 11);
        for (id, requirement) in &result {
            assert_eq!(&requirement.identifier, id);
            assert_eq!(requirement.team_id, codesign::TEAM_ID);
            assert!(!id.starts_with("com.mcpmac."));
        }
        assert_eq!(
            result["com.enterprise.enclave.ctl"].cdhash_allowlist,
            vec!["01".repeat(20), "fe".repeat(20)]
        );
    }
}
#[test]
fn candidate_pins_reject_missing_extra_relocated_and_emulator_roles() {
    let mode = DeploymentSigningMode::LocalPins;
    for change in 0..4 {
        let mut value = pins(mode);
        let map = value["pins"].as_object_mut().unwrap();
        match change {
            0 => {
                map.remove("com.enterprise.enclave.apfs-broker");
            }
            1 => {
                map.insert(
                    "com.enterprise.enclave.fido".into(),
                    serde_json::json!(["ab".repeat(20)]),
                );
            }
            2 => {
                let hashes = map.remove("com.enterprise.enclave.ctl").unwrap();
                map.insert("com.mcpmac.target.ctl".into(), hashes);
            }
            _ => {
                map.insert("unrelated.app".into(), serde_json::json!(["ab".repeat(20)]));
            }
        }
        assert!(parsed(&value, mode).is_err());
    }
}
#[test]
fn candidate_pins_reject_wrong_mode_version_unknown_and_missing_fields() {
    let mode = DeploymentSigningMode::LocalPins;
    for change in 0..5 {
        let mut value = pins(mode);
        match change {
            0 => value["mode"] = serde_json::json!("team-id"),
            1 => value["v"] = serde_json::json!(2),
            2 => value["approved"] = serde_json::json!(true),
            3 => {
                value.as_object_mut().unwrap().remove("mode");
            }
            _ => value["mode"] = serde_json::json!("development"),
        }
        assert!(parsed(&value, mode).is_err());
    }
}
#[test]
fn candidate_pins_reject_duplicate_top_level_and_nested_keys_before_native_parser() {
    let raw = serde_json::to_string(&pins(DeploymentSigningMode::LocalPins)).unwrap();
    let duplicate_top = raw.replacen("{", "{\"v\":1,", 1);
    let duplicate_id = raw.replacen(
        "\"pins\":{",
        "\"pins\":{\"com.enterprise.enclave.ctl\":[\"0000000000000000000000000000000000000000\"],",
        1,
    );
    for value in [duplicate_top, duplicate_id] {
        assert!(requirements(value.as_bytes(), DeploymentSigningMode::LocalPins).is_err());
    }
}
#[test]
fn candidate_pins_reject_empty_malformed_duplicate_and_unbounded_cdhashes() {
    let mode = DeploymentSigningMode::LocalPins;
    for hashes in [
        vec![],
        vec!["xx".repeat(20)],
        vec!["ab".repeat(19)],
        vec!["ab".repeat(20), "AB".repeat(20)],
        vec!["ab".repeat(20); 33],
    ] {
        let mut value = pins(mode);
        value["pins"]["com.enterprise.enclave.ctl"] = serde_json::json!(hashes);
        assert!(parsed(&value, mode).is_err());
    }
}
#[test]
fn candidate_pins_enforce_raw_size_trailing_and_integer_schema() {
    let mode = DeploymentSigningMode::LocalPins;
    assert!(requirements(&vec![b' '; MAX_CONFIG + 1], mode).is_err());
    let raw = serde_json::to_string(&pins(mode)).unwrap();
    assert!(requirements(format!("{raw} false").as_bytes(), mode).is_err());
    assert!(requirements(raw.replacen("\"v\":1", "\"v\":1.0", 1).as_bytes(), mode).is_err());
}
#[test]
fn descriptor_cannot_select_a_different_compiled_signing_mode() {
    let (actual, other) = match codesign::signing_mode() {
        codesign::SigningMode::LocalPins => (
            DeploymentSigningMode::LocalPins,
            DeploymentSigningMode::TeamId,
        ),
        codesign::SigningMode::TeamId => (
            DeploymentSigningMode::TeamId,
            DeploymentSigningMode::LocalPins,
        ),
    };
    compiled_mode(actual).unwrap();
    assert!(compiled_mode(other).is_err());
}

struct Fixture {
    root: PathBuf,
    path: PathBuf,
    file: File,
    hash: String,
    size: u64,
}
impl Fixture {
    fn new(value: &[u8]) -> Self {
        let root =
            std::env::temp_dir().join(format!("mc-candidate-{:x}", enclave_core::rng::u64()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("public");
        std::fs::write(&path, value).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        Self {
            root,
            file: File::open(&path).unwrap(),
            path,
            hash: hex::encode(Sha256::digest(value)),
            size: value.len() as u64,
        }
    }
    fn view(&self) -> CandidateFileView<'_> {
        CandidateFileView {
            path: &self.path,
            file: &self.file,
            sha256: &self.hash,
            size: self.size,
        }
    }
    fn expected(&self) -> BTreeMap<PathBuf, (String, u64)> {
        BTreeMap::from([(
            normalized_path(&self.path).unwrap(),
            (self.hash.clone(), self.size),
        )])
    }
    fn owner(&self) -> u32 {
        self.file.metadata().unwrap().uid()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
#[test]
fn held_reads_verify_digest_and_size_without_changing_shared_file_offset() {
    let mut fixture = Fixture::new(b"approved bytes\n");
    fixture.file.seek(SeekFrom::Start(3)).unwrap();
    verify_digest(fixture.view(), fixture.owner()).unwrap();
    assert_eq!(
        bytes(fixture.view(), MAX_CONFIG, fixture.owner()).unwrap(),
        b"approved bytes\n"
    );
    assert_eq!(fixture.file.stream_position().unwrap(), 3);
}
#[test]
fn held_reads_refuse_same_size_edits_truncation_growth_and_incorrect_claims() {
    for changed in [
        b"tampered bytes\n".as_slice(),
        b"short".as_slice(),
        b"approved bytes\nextra".as_slice(),
    ] {
        let fixture = Fixture::new(b"approved bytes\n");
        std::fs::write(&fixture.path, changed).unwrap();
        assert!(verify_digest(fixture.view(), fixture.owner()).is_err());
        assert!(bytes(fixture.view(), MAX_CONFIG, fixture.owner()).is_err());
    }
    let fixture = Fixture::new(b"data");
    let bad_hash = "00".repeat(32);
    let bad = CandidateFileView {
        sha256: &bad_hash,
        ..fixture.view()
    };
    assert!(verify_digest(bad, fixture.owner()).is_err());
    assert!(bytes(bad, MAX_CONFIG, fixture.owner()).is_err());
}
#[test]
fn held_reads_refuse_writable_descriptors_and_hardlink_aliases() {
    let fixture = Fixture::new(b"data");
    let writable = File::options()
        .read(true)
        .write(true)
        .open(&fixture.path)
        .unwrap();
    assert!(verify_digest(
        CandidateFileView {
            file: &writable,
            ..fixture.view()
        },
        fixture.owner()
    )
    .is_err());
    std::fs::hard_link(&fixture.path, fixture.root.join("alias")).unwrap();
    assert!(verify_digest(fixture.view(), fixture.owner()).is_err());
}
#[test]
fn held_reads_refuse_unprotected_metadata_and_bound_buffer_allocations() {
    let fixture = Fixture::new(b"data");
    assert!(bytes(fixture.view(), 3, fixture.owner()).is_err());
    for mode in [0o622, 0o660, 0o4600] {
        std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(verify_digest(fixture.view(), fixture.owner()).is_err());
    }
}
#[test]
fn exact_held_set_refuses_omission_extra_duplicate_hash_size_and_path_changes() {
    let fixture = Fixture::new(b"data");
    let expected = fixture.expected();
    assert!(bind_views(&expected, &[fixture.view()]).is_ok());
    assert!(bind_views(&expected, &[]).is_err());
    assert!(bind_views(&expected, &[fixture.view(), fixture.view()]).is_err());
    let different_path = fixture.root.join("different");
    let different_hash = "00".repeat(32);
    for view in [
        CandidateFileView {
            path: &different_path,
            ..fixture.view()
        },
        CandidateFileView {
            sha256: &different_hash,
            ..fixture.view()
        },
        CandidateFileView {
            size: 5,
            ..fixture.view()
        },
    ] {
        assert!(bind_views(&expected, &[view]).is_err());
    }
    let other = Fixture::new(b"more");
    let expected_two = expected
        .into_iter()
        .chain(other.expected())
        .collect::<BTreeMap<_, _>>();
    assert!(bind_views(&expected_two, &[fixture.view(), fixture.view()]).is_err());
    assert!(bind_views(&expected_two, &[fixture.view(), other.view()]).is_ok());
}
#[test]
fn exact_held_set_enforces_aggregate_byte_budget_before_native_work() {
    let fixture = Fixture::new(b"data");
    let hash = "ab".repeat(32);
    let paths = (0..5)
        .map(|n| fixture.root.join(format!("input-{n}")))
        .collect::<Vec<_>>();
    let views = paths
        .iter()
        .map(|path| CandidateFileView {
            path,
            file: &fixture.file,
            sha256: &hash,
            size: MAX_FILE,
        })
        .collect::<Vec<_>>();
    let expected = paths
        .iter()
        .map(|p| (normalized_path(p).unwrap(), (hash.clone(), MAX_FILE)))
        .collect::<BTreeMap<_, _>>();
    assert!(bind_views(&expected, &views).is_err());
}
#[test]
fn physical_renderer_map_covers_every_core_auxiliary_sandbox_and_profile_broker() {
    for profile in ["L2", "L3"] {
        let layout = crate::launchd::Layout {
            profile: profile.into(),
            ..Default::default()
        };
        let map = rendered(&layout, DeploymentSigningMode::LocalPins).unwrap();
        assert_eq!(map.len(), if profile == "L3" { 23 } else { 22 });
        for daemon in DaemonId::ALL {
            assert_eq!(
                map[&format!("launchd/{}.plist", daemon.launchd_label())],
                crate::launchd::plist(daemon, &layout).as_bytes()
            );
            assert!(map.contains_key(&format!("launchd/{}.sb", daemon.plist_suffix())));
        }
        for role in [
            "supervisor",
            "intent",
            "oidc-broker",
            "hydrate",
            "browser",
            "gateway",
        ] {
            assert!(map.contains_key(&format!("launchd/com.enterprise.enclave.{role}.plist")));
        }
        for sandbox in [
            "adapter", "cas", "custody", "ifc", "zk", "browser", "gateway",
        ] {
            assert!(map.contains_key(&format!("launchd/{sandbox}.sb")));
        }
        assert_eq!(
            map.contains_key("launchd/com.enterprise.enclave.apfs-broker.plist"),
            profile == "L3"
        );
        assert_eq!(map["yubikey-transport"], b"hid\n");
        assert_eq!(
            map["custody.entitlements"],
            map["launchd/enclave-daemon.entitlements"]
        );
    }
}
#[test]
fn renderer_refuses_emulation_and_unsupported_profile() {
    let mut layout = crate::launchd::Layout {
        fido_emulator: true,
        ..Default::default()
    };
    assert!(rendered(&layout, DeploymentSigningMode::LocalPins).is_err());
    layout.fido_emulator = false;
    layout.profile = "L1".into();
    assert!(rendered(&layout, DeploymentSigningMode::LocalPins).is_err());
}
#[test]
fn custody_entitlement_bytes_follow_the_compiled_template_and_baseline_modes() {
    let layout = crate::launchd::Layout::default();
    let local = rendered(&layout, DeploymentSigningMode::LocalPins).unwrap();
    let team = rendered(&layout, DeploymentSigningMode::TeamId).unwrap();
    assert_eq!(
        local["custody.entitlements"],
        crate::launchd::entitlements().as_bytes()
    );
    assert_eq!(
        team["custody.entitlements"],
        CUSTODY_TEMPLATE
            .replace("@TEAM_ID@", codesign::TEAM_ID)
            .as_bytes()
    );
    assert_eq!(
        local["launchd/enclave-daemon.entitlements"],
        team["launchd/enclave-daemon.entitlements"]
    );
    assert!(!String::from_utf8(team["custody.entitlements"].clone())
        .unwrap()
        .contains("@TEAM_ID@"));
}
#[test]
fn rendered_comparison_requires_exact_bytes_not_a_semantically_similar_config() {
    let fixture = Fixture::new(b"hid\n");
    let views = bind_views(&fixture.expected(), &[fixture.view()]).unwrap();
    let expected = BTreeMap::from([("public".to_owned(), b"hid\n".to_vec())]);
    compare_rendered(&views, &fixture.root, &expected, fixture.owner()).unwrap();
    for value in [
        b"hid".to_vec(),
        b"hid\r\n".to_vec(),
        b"emulated:socket\n".to_vec(),
    ] {
        assert!(compare_rendered(
            &views,
            &fixture.root,
            &BTreeMap::from([("public".into(), value)]),
            fixture.owner()
        )
        .is_err());
    }
    assert!(compare_rendered(
        &views,
        &fixture.root,
        &BTreeMap::from([("missing".into(), b"hid\n".to_vec())]),
        fixture.owner()
    )
    .is_err());
}
#[test]
fn native_step_rechecks_authority_after_native_refusal_and_never_runs_after_precheck_refusal() {
    for native_fails in [false, true] {
        let events = RefCell::new(Vec::new());
        let result = native_step(
            &mut || {
                events.borrow_mut().push("check");
                Ok(())
            },
            || {
                events.borrow_mut().push("native");
                if native_fails {
                    Err(err!(EACCES, "SYNTHETIC_NATIVE"))
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(*events.borrow(), vec!["check", "native", "check"]);
        assert_eq!(result.is_err(), native_fails);
    }
    let ran = Cell::new(false);
    let result = native_step(&mut || Err(err!(ESTALE, "SYNTHETIC_PRECHECK")), || {
        ran.set(true);
        Ok(())
    });
    assert!(result.is_err());
    assert!(!ran.get());
}
#[test]
fn native_step_refuses_successful_native_result_when_final_authority_has_expired() {
    let checks = Cell::new(0);
    let ran = Cell::new(false);
    let result = native_step(
        &mut || {
            checks.set(checks.get() + 1);
            if checks.get() == 2 {
                Err(err!(ESTALE, "SYNTHETIC_EXPIRED"))
            } else {
                Ok(())
            }
        },
        || {
            ran.set(true);
            Ok(())
        },
    );
    assert!(result.unwrap_err().is("SYNTHETIC_EXPIRED"));
    assert!(ran.get());
    assert_eq!(checks.get(), 2);
}
