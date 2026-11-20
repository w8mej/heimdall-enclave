//! Synthetic public JSON/key fixtures. No production authority is constructed.
use super::*;
use enclave_crypto::tuf::RepoBuilder;
use serde_json::json;
use std::collections::BTreeMap;

const TARGET: &str = "mcpmac/software-release/fixture-inventory.json";
const EXP: &str = "2040-01-01T00:00:00Z";
fn minimum() -> MinimumThresholds {
    MinimumThresholds {
        root: 2,
        timestamp: 1,
        snapshot: 1,
        targets: 2,
    }
}
fn bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}
fn root() -> Value {
    serde_json::from_slice(&RepoBuilder::new(2, 2).root(EXP).unwrap()).unwrap()
}

#[test]
fn release_json_rejects_decoded_duplicates_at_every_depth_and_keeps_literal_number_maps() {
    for raw in [
        br#"{"signed":{},"sign\u0065d":{}}"#.as_slice(),
        br#"{"outer":[{"k":1,"\u006b":2}]}"#,
        br#"{"signatures":[{"sig":"a","sig":"b"}]}"#,
    ] {
        assert!(strict(raw, MAX_METADATA).is_err());
    }
    // serde_json arbitrary_precision has a reserved map token. An actual input
    // object is retained as an object, never transformed into a signed number.
    let raw = br#"{"$serde_json::private::Number":"12"}"#;
    let parsed = strict(raw, MAX_METADATA).unwrap();
    assert!(parsed.is_object());
    assert_eq!(parsed.as_object().unwrap().len(), 1);
    assert!(strict(br#"{"quoted":"1e8 -1.0"}"#, MAX_METADATA).is_ok());
}

#[test]
fn release_json_bounds_integer_tokens_depth_nodes_strings_and_complete_input() {
    for token in [
        "1.0",
        "1e0",
        "-1e2",
        "18446744073709551616",
        "-9223372036854775809",
        "01",
        "+1",
        "1 2",
        "[1,]",
    ] {
        assert!(strict(token.as_bytes(), MAX_METADATA).is_err(), "{token}");
    }
    assert!(strict(b"18446744073709551615", MAX_METADATA).is_ok());
    assert!(strict(b"-9223372036854775808", MAX_METADATA).is_ok());
    assert!(strict(b"{}", 1).is_err());
    assert!(strict(b"", MAX_METADATA).is_err());
    let deep = format!(
        "{}0{}",
        "[".repeat(MAX_DEPTH + 1),
        "]".repeat(MAX_DEPTH + 1)
    );
    assert!(strict(deep.as_bytes(), MAX_METADATA).is_err());
    let many = format!("[{}]", vec!["0"; MAX_NODES].join(","));
    assert!(strict(many.as_bytes(), MAX_METADATA).is_err());
    let huge = format!("\"{}\"", "a".repeat(MAX_STRING + 1));
    assert!(strict(huge.as_bytes(), huge.len()).is_err());
}

#[test]
fn release_root_closed_schema_and_typed_body_equality_preserve_signed_semantics() {
    let original = root();
    metadata(&bytes(&original), Role::Root, &minimum(), TARGET).unwrap();
    for field in ["unknown", "delegations", "consistent-snapshot"] {
        let mut bad = original.clone();
        bad["signed"][field] = json!(true);
        assert!(metadata(&bytes(&bad), Role::Root, &minimum(), TARGET).is_err());
    }
    let mut bad = original.clone();
    bad["unsigned-extra"] = json!(false);
    assert!(metadata(&bytes(&bad), Role::Root, &minimum(), TARGET).is_err());
    let mut bad = original.clone();
    bad["signed"]
        .as_object_mut()
        .unwrap()
        .remove("consistent_snapshot");
    // This is a real serde-default difference, detected even before schema.
    assert!(signed_matches::<RootMeta>(&bytes(&bad), &bad).is_err());
    assert!(metadata(&bytes(&bad), Role::Root, &minimum(), TARGET).is_err());
    let mut bad = original.clone();
    bad["signed"]["consistent_snapshot"] = json!(true);
    assert!(metadata(&bytes(&bad), Role::Root, &minimum(), TARGET).is_err());
    let pretty = serde_json::to_vec_pretty(&original).unwrap();
    metadata(&pretty, Role::Root, &minimum(), TARGET).unwrap();
}

#[test]
fn release_root_refuses_key_aliases_weak_points_role_duplicates_and_threshold_downgrades() {
    let original = root();
    let id = original["signed"]["keys"]
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap()
        .clone();
    let mut bad = original.clone();
    let entry = bad["signed"]["keys"]
        .as_object_mut()
        .unwrap()
        .remove(&id)
        .unwrap();
    bad["signed"]["keys"]["00".repeat(32)] = entry;
    assert!(metadata(&bytes(&bad), Role::Root, &minimum(), TARGET).is_err());
    let mut bad = original.clone();
    bad["signed"]["keys"][&id]["keyval"]["public"] = json!(format!("01{}", "00".repeat(31)));
    assert!(metadata(&bytes(&bad), Role::Root, &minimum(), TARGET).is_err());
    let mut bad = original.clone();
    bad["signed"]["roles"]["root"]["threshold"] = json!(1);
    assert!(metadata(&bytes(&bad), Role::Root, &minimum(), TARGET).is_err());
    for field in ["root", "timestamp", "snapshot", "targets"] {
        let mut bad = original.clone();
        bad["signed"]["roles"][field]["threshold"] = json!(0);
        assert!(metadata(&bytes(&bad), Role::Root, &minimum(), TARGET).is_err());
        let mut bad = original.clone();
        bad["signed"]["roles"][field]["threshold"] = json!(65);
        assert!(metadata(&bytes(&bad), Role::Root, &minimum(), TARGET).is_err());
    }
    let mut bad = original.clone();
    let id = bad["signed"]["roles"]["targets"]["keyids"][0].clone();
    bad["signed"]["roles"]["targets"]["keyids"] = json!([id.clone(), id]);
    assert!(metadata(&bytes(&bad), Role::Root, &minimum(), TARGET).is_err());
    let mut bad = original.clone();
    bad["signed"]["roles"]["unrelated"] = json!({"keyids":[],"threshold":1});
    assert!(metadata(&bytes(&bad), Role::Root, &minimum(), TARGET).is_err());
    assert!(!MinimumThresholds {
        root: 1,
        timestamp: 1,
        snapshot: 1,
        targets: 1
    }
    .valid(true));
    assert!(!MinimumThresholds {
        root: 1,
        timestamp: 1,
        snapshot: 1,
        targets: 2
    }
    .preserves(&minimum()));
}

#[test]
fn release_role_links_require_both_complete_hashes_lengths_and_exact_target_purpose() {
    let r = RepoBuilder::new(2, 2);
    let target = enclave_crypto::tuf::target_file(b"public fixture", None);
    let targets = r
        .targets(1, EXP, BTreeMap::from([(TARGET.into(), target)]))
        .unwrap();
    let snapshot = r.snapshot(1, EXP, 1, &targets).unwrap();
    let timestamp = r.timestamp(1, EXP, 1, &snapshot).unwrap();
    for (raw, role, child) in [
        (&snapshot, Role::Snapshot, "targets.json"),
        (&timestamp, Role::Timestamp, "snapshot.json"),
    ] {
        metadata(raw, role, &minimum(), TARGET).unwrap();
        let original: Value = serde_json::from_slice(raw).unwrap();
        for field in ["length", "hashes"] {
            let mut bad = original.clone();
            bad["signed"]["meta"][child]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(metadata(&bytes(&bad), role, &minimum(), TARGET).is_err());
        }
        for algorithm in ["sha256", "blake3"] {
            let mut bad = original.clone();
            bad["signed"]["meta"][child]["hashes"]
                .as_object_mut()
                .unwrap()
                .remove(algorithm);
            assert!(metadata(&bytes(&bad), role, &minimum(), TARGET).is_err());
        }
        let mut bad = original.clone();
        bad["signed"]["meta"]["foreign.json"] = json!({});
        assert!(metadata(&bytes(&bad), role, &minimum(), TARGET).is_err());
    }
    metadata(&targets, Role::Targets, &minimum(), TARGET).unwrap();
    assert!(metadata(
        &targets,
        Role::Targets,
        &minimum(),
        "mcpmac/software-release/foreign.json"
    )
    .is_err());
    let mut bad: Value = serde_json::from_slice(&targets).unwrap();
    bad["signed"]["delegations"] = json!({});
    assert!(metadata(&bytes(&bad), Role::Targets, &minimum(), TARGET).is_err());
    let mut bad: Value = serde_json::from_slice(&targets).unwrap();
    bad["signed"]["targets"][TARGET]["custom"] = json!({"purpose":"other"});
    assert!(metadata(&bytes(&bad), Role::Targets, &minimum(), TARGET).is_err());
}

#[test]
fn release_signature_shape_refuses_duplicate_ids_malformed_hashes_and_excess_count() {
    let original = root();
    let mut bad = original.clone();
    let sig = bad["signatures"][0].clone();
    bad["signatures"].as_array_mut().unwrap().push(sig);
    assert!(metadata(&bytes(&bad), Role::Root, &minimum(), TARGET).is_err());
    let mut bad = original.clone();
    bad["signatures"][0]["sig"] = json!("00");
    assert!(metadata(&bytes(&bad), Role::Root, &minimum(), TARGET).is_err());
    let mut bad = original.clone();
    bad["signatures"] = json!(vec![original["signatures"][0].clone(); 65]);
    assert!(metadata(&bytes(&bad), Role::Root, &minimum(), TARGET).is_err());
}
