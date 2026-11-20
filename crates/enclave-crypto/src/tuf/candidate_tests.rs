use super::*;
use serde_json::json;
const NOW: i64 = 1_800_000_000;
const ROOT: &[u8] = include_bytes!("../../tests/data/yubikey-olpc1/root.json");
const TARGETS: &[u8] = include_bytes!("../../tests/data/yubikey-olpc1/targets.json");
const SNAPSHOT: &[u8] = include_bytes!("../../tests/data/yubikey-olpc1/snapshot.json");
const TIMESTAMP: &[u8] = include_bytes!("../../tests/data/yubikey-olpc1/timestamp.json");
fn expected(role: Role, version: u64, bytes: &[u8]) -> ExpectedChild {
    ExpectedChild {
        role,
        version,
        length: bytes.len() as u64,
        sha256: Sha256::digest(bytes).into(),
    }
}
fn wire(value: &impl Serialize) -> Vec<u8> {
    crate::canonical_json::to_canonical_json_bytes(value).unwrap()
}
fn signed(body: &Value, keys: &[&SigningKey]) -> Vec<u8> {
    let mut envelope = super::super::sign(body, keys).unwrap();
    envelope.signatures.sort_by(|a, b| a.keyid.cmp(&b.keyid));
    wire(&envelope)
}
fn body(role: Role, version: u64) -> Value {
    let mut common = json!({"_type":role.name(),"spec_version":SPEC_VERSION,"version":version,"expires":"2035-01-01T00:00:00Z"});
    if role == Role::Targets {
        common["targets"] = json!({"synthetic.txt":{"length":3,"hashes":{"sha256":hex::encode(Sha256::digest(b"abc")),
            "blake3":blake3::hash(b"abc").to_hex().to_string()},"custom":{"complete_signed_extension":"retained","integer":9007199254740991u64}}});
    } else {
        common["meta"] =
            json!({"targets.json":{"version":1,"length":123,"hashes":{"sha256":"11".repeat(32)}}});
    }
    common
}
fn trust(threshold: u32) -> (TufClient, Vec<SigningKey>) {
    let keys = vec![
        SigningKey::from_bytes(&[73; 32]),
        SigningKey::from_bytes(&[74; 32]),
    ];
    let mut root_keys = BTreeMap::new();
    let mut ids = Vec::new();
    for key in &keys {
        let key = TufKey::ed25519(&key.verifying_key());
        let id = key.keyid().unwrap();
        ids.push(id.clone());
        root_keys.insert(id, key);
    }
    ids.sort();
    let mut roles = BTreeMap::new();
    for role in [Role::Root, Role::Timestamp, Role::Snapshot, Role::Targets] {
        roles.insert(
            role.name().into(),
            RoleKeys {
                keyids: ids.clone(),
                threshold,
            },
        );
    }
    let root = RootMeta {
        _type: "root".into(),
        spec_version: SPEC_VERSION.into(),
        version: 1,
        expires: "2035-01-01T00:00:00Z".into(),
        keys: root_keys,
        roles,
        consistent_snapshot: false,
    };
    let mut root = super::super::sign(&root, &keys.iter().collect::<Vec<_>>()).unwrap();
    root.signatures.sort_by(|a, b| a.keyid.cmp(&b.keyid));
    (TufClient::bootstrap(&wire(&root)).unwrap(), keys)
}
fn listing(role: Role, version: u64, child_version: u64, child: &[u8]) -> Value {
    let name = if role == Role::Snapshot {
        "targets.json"
    } else {
        "snapshot.json"
    };
    json!({"_type":role.name(),"spec_version":SPEC_VERSION,"version":version,"expires":"2035-01-01T00:00:00Z",
        "meta":{(name):{"version":child_version,"length":child.len(),"hashes":{"sha256":hex::encode(Sha256::digest(child))}}}})
}
fn parent_expected(
    role: Role,
    base: u64,
    body: &Value,
    child_role: Role,
    child_version: u64,
    child: &[u8],
) -> ExpectedParent {
    let bytes = wire(body);
    ExpectedParent {
        role,
        base_version: base,
        new_version: number(body, "version").unwrap(),
        signed_body_bytes: bytes.len() as u64,
        signed_body_sha256: Sha256::digest(&bytes).into(),
        expires_utc_ms: (parse_rfc3339_utc(text(body, "expires").unwrap()).unwrap() as u64) * 1000,
        linked_child: expected(child_role, child_version, child),
    }
}
fn staged(role: Role) -> (TufClient, Vec<SigningKey>, Vec<u8>, Value, ExpectedParent) {
    let (client, keys) = trust(1);
    let targets = signed(&body(Role::Targets, 1), &[&keys[0]]);
    let (child_role, child_version, child) = if role == Role::Snapshot {
        (Role::Targets, 1, targets)
    } else {
        (
            Role::Snapshot,
            3,
            signed(&listing(Role::Snapshot, 3, 1, &targets), &[&keys[0]]),
        )
    };
    let parent = listing(role, 5, child_version, &child);
    let want = parent_expected(role, 0, &parent, child_role, child_version, &child);
    (client, keys, child, parent, want)
}

#[test]
fn snapshot_and_timestamp_parent_bodies_bind_genuine_complete_children_without_adoption() {
    for role in [Role::Snapshot, Role::Timestamp] {
        let (client, _, child, parent, want) = staged(role);
        let before = client.export().unwrap();
        let facts = verify_parent_linkage(&client, &want, &wire(&parent), &[child.as_slice()], NOW)
            .unwrap();
        assert_eq!(facts.role, role);
        assert_eq!(facts.version, 5);
        assert_eq!(facts.child.signatures, 1);
        let digest: [u8; 32] = Sha256::digest(&child).into();
        assert_eq!(facts.child.sha256, digest);
        assert_eq!(facts.signed_body_sha256, want.signed_body_sha256);
        assert_eq!(
            client.export().unwrap(),
            before,
            "diagnostics never adopt or sign the proposed parent"
        );
    }
}

#[test]
fn parent_commitments_roles_versions_expiry_and_exact_attachment_count_refuse_substitution() {
    let (client, _, child, parent, want) = staged(Role::Snapshot);
    let bytes = wire(&parent);
    let check = |want: &ExpectedParent, body: &[u8], children: &[&[u8]]| {
        verify_parent_linkage(&client, want, body, children, NOW)
    };
    for role in [Role::Root, Role::Targets] {
        let mut changed = want.clone();
        changed.role = role;
        assert!(check(&changed, &bytes, &[child.as_slice()])
            .unwrap_err()
            .is("TUF_CANDIDATE_PARENT_ROLE"));
    }
    assert!(check(&want, &bytes, &[])
        .unwrap_err()
        .is("TUF_CANDIDATE_PARENT_ATTACHMENTS"));
    assert!(check(&want, &bytes, &[child.as_slice(), child.as_slice()])
        .unwrap_err()
        .is("TUF_CANDIDATE_PARENT_ATTACHMENTS"));
    for mutation in 0..7 {
        let mut changed = want.clone();
        match mutation {
            0 => changed.signed_body_bytes += 1,
            1 => changed.signed_body_sha256[0] ^= 1,
            2 => changed.new_version += 1,
            3 => changed.expires_utc_ms += 1,
            4 => changed.linked_child.role = Role::Snapshot,
            5 => changed.linked_child.version += 1,
            _ => changed.linked_child.sha256[0] ^= 1,
        }
        assert!(
            check(&changed, &bytes, &[child.as_slice()]).is_err(),
            "mutation {mutation}"
        );
    }
    let pretty = serde_json::to_vec_pretty(&parent).unwrap();
    let mut changed = want.clone();
    changed.signed_body_bytes = pretty.len() as u64;
    changed.signed_body_sha256 = Sha256::digest(&pretty).into();
    assert!(check(&changed, &pretty, &[child.as_slice()])
        .unwrap_err()
        .is("TUF_CANDIDATE_OUTER_CANONICAL"));
    let duplicate = String::from_utf8(bytes.clone())
        .unwrap()
        .replacen("{", "{\"version\":9,", 1)
        .into_bytes();
    changed.signed_body_bytes = duplicate.len() as u64;
    changed.signed_body_sha256 = Sha256::digest(&duplicate).into();
    assert!(check(&changed, &duplicate, &[child.as_slice()])
        .unwrap_err()
        .is("TUF_CANDIDATE_JSON"));
}

#[test]
fn parent_meta_links_compare_complete_child_version_length_and_hash_not_signed_member() {
    for role in [Role::Snapshot, Role::Timestamp] {
        let (client, _, child, parent, want) = staged(role);
        let name = if role == Role::Snapshot {
            "targets.json"
        } else {
            "snapshot.json"
        };
        for mutation in 0..6 {
            let mut changed = parent.clone();
            match mutation {
                0 => changed["meta"][name]["version"] = json!(want.linked_child.version + 1),
                1 => changed["meta"][name]["length"] = json!(child.len() + 1),
                2 => changed["meta"][name]["hashes"]["sha256"] = json!("11".repeat(32)),
                3 => {
                    let value: Value = serde_json::from_slice(&child).unwrap();
                    changed["meta"][name]["hashes"]["sha256"] =
                        json!(hex::encode(Sha256::digest(wire(&value["signed"]))));
                }
                4 => changed["meta"]["unexpected.json"] = changed["meta"][name].clone(),
                _ => changed["admin_bypass"] = json!(true),
            }
            // Commit the hostile parent body exactly: failure must follow from
            // its link/schema, not an obsolete parent body hash or signature.
            let checked = parent_expected(
                role,
                0,
                &changed,
                want.linked_child.role,
                want.linked_child.version,
                &child,
            );
            assert!(
                verify_parent_linkage(&client, &checked, &wire(&changed), &[child.as_slice()], NOW)
                    .is_err(),
                "{role:?}/{mutation}"
            );
        }
        let mut invalid_child: Value = serde_json::from_slice(&child).unwrap();
        invalid_child["signatures"][0]["sig"] = json!("00".repeat(64));
        let invalid_child = wire(&invalid_child);
        let parent = listing(role, 5, want.linked_child.version, &invalid_child);
        let checked = parent_expected(
            role,
            0,
            &parent,
            want.linked_child.role,
            want.linked_child.version,
            &invalid_child,
        );
        assert!(verify_parent_linkage(
            &client,
            &checked,
            &wire(&parent),
            &[invalid_child.as_slice()],
            NOW
        )
        .is_err());
    }
}

#[test]
fn parent_base_is_exact_adopted_floor_and_proposed_version_is_strictly_newer() {
    let (mut client, keys) = trust(1);
    let targets = signed(&body(Role::Targets, 1), &[&keys[0]]);
    let snapshot = signed(&listing(Role::Snapshot, 5, 1, &targets), &[&keys[0]]);
    let timestamp = signed(&listing(Role::Timestamp, 7, 5, &snapshot), &[&keys[0]]);
    client
        .refresh(&timestamp, &snapshot, &targets, NOW)
        .unwrap();
    for (role, base, child_role, version, child) in [
        (Role::Snapshot, 5, Role::Targets, 1, &targets),
        (Role::Timestamp, 7, Role::Snapshot, 5, &snapshot),
    ] {
        let parent = listing(role, base + 1, version, child);
        let want = parent_expected(role, base, &parent, child_role, version, child);
        verify_parent_linkage(&client, &want, &wire(&parent), &[child.as_slice()], NOW).unwrap();
        let mut changed = want.clone();
        changed.base_version = base - 1;
        assert!(
            verify_parent_linkage(&client, &changed, &wire(&parent), &[child.as_slice()], NOW)
                .unwrap_err()
                .is("TUF_CANDIDATE_PARENT_BASE")
        );
        changed = want;
        changed.new_version = base;
        assert!(
            verify_parent_linkage(&client, &changed, &wire(&parent), &[child.as_slice()], NOW)
                .unwrap_err()
                .is("TUF_CANDIDATE_PARENT_VERSION")
        );
    }
}

#[test]
fn parent_and_signed_child_expiry_both_attenuate_facts_and_expired_links_refuse() {
    let (client, keys) = trust(1);
    let mut child_body = body(Role::Targets, 1);
    child_body["expires"] = json!("2029-01-01T00:00:00Z");
    for expiry in [
        "2030-01-01T00:00:00Z",
        "2028-01-01T00:00:00Z",
        "2020-01-01T00:00:00Z",
    ] {
        let child = signed(&child_body, &[&keys[0]]);
        let mut parent = listing(Role::Snapshot, 1, 1, &child);
        parent["expires"] = json!(expiry);
        let want = parent_expected(Role::Snapshot, 0, &parent, Role::Targets, 1, &child);
        let result =
            verify_parent_linkage(&client, &want, &wire(&parent), &[child.as_slice()], NOW);
        if expiry.starts_with("2020") {
            assert!(result.is_err());
        } else {
            assert_eq!(
                result.unwrap().valid_until_unix,
                parse_rfc3339_utc(expiry)
                    .unwrap()
                    .min(parse_rfc3339_utc("2029-01-01T00:00:00Z").unwrap())
            );
        }
    }
    child_body["expires"] = json!("2020-01-01T00:00:00Z");
    let child = signed(&child_body, &[&keys[0]]);
    let parent = listing(Role::Snapshot, 1, 1, &child);
    let want = parent_expected(Role::Snapshot, 0, &parent, Role::Targets, 1, &child);
    assert!(
        verify_parent_linkage(&client, &want, &wire(&parent), &[child.as_slice()], NOW).is_err()
    );
}

#[test]
fn external_snapshot_and_genuine_control_free_targets_preserve_complete_bytes() {
    let client = TufClient::bootstrap(ROOT).unwrap();
    let facts = verify_complete_child(
        &client,
        &expected(Role::Snapshot, 1, SNAPSHOT),
        SNAPSHOT,
        NOW,
    )
    .unwrap();
    assert_eq!(facts.role, Role::Snapshot);
    assert_eq!(facts.length, SNAPSHOT.len() as u64);
    assert_eq!(facts.signatures, 1);
    let provenance: Value = serde_json::from_slice(include_bytes!(
        "../../tests/data/yubikey-olpc1/provenance.json"
    ))
    .unwrap();
    assert_eq!(
        hex::encode(facts.signed_body_sha256),
        hex::encode(Sha256::digest(
            hex::decode(
                provenance["signed_preimages_hex"]["snapshot"]
                    .as_str()
                    .unwrap()
            )
            .unwrap()
        ))
    );
    let key = SigningKey::from_bytes(&[73; 32]);
    let targets = signed(&body(Role::Targets, 1), &[&key]);
    let facts = verify_complete_child(
        &client,
        &expected(Role::Targets, 1, &targets),
        &targets,
        NOW,
    )
    .unwrap();
    let digest: [u8; 32] = Sha256::digest(&targets).into();
    assert_eq!(facts.sha256, digest);
    assert_ne!(facts.signed_body_sha256, facts.sha256);
    assert_eq!(
        facts.valid_until_unix,
        parse_rfc3339_utc("2035-01-01T00:00:00Z").unwrap()
    );
}

#[test]
fn strict_json_plus_olpc_outer_refuses_control_character_incompatibility() {
    let client = TufClient::bootstrap(ROOT).unwrap();
    assert!(
        verify_complete_child(&client, &expected(Role::Targets, 1, TARGETS), TARGETS, NOW)
            .unwrap_err()
            .is("TUF_CANDIDATE_OUTER_CANONICAL")
    );
    let value: Value = serde_json::from_slice(TARGETS).unwrap();
    let raw_olpc = wire(&value);
    assert!(verify_complete_child(
        &client,
        &expected(Role::Targets, 1, &raw_olpc),
        &raw_olpc,
        NOW
    )
    .unwrap_err()
    .is("TUF_CANDIDATE_JSON"));
    // Existing normal-wire TUF interoperability is a separate, unchanged path.
    let mut ordinary = TufClient::bootstrap(ROOT).unwrap();
    ordinary.refresh(TIMESTAMP, SNAPSHOT, TARGETS, NOW).unwrap();
}

#[test]
fn exact_length_hash_version_role_and_root_or_child_expiry_are_mandatory() {
    let (client, keys) = trust(1);
    let bytes = signed(&body(Role::Targets, 1), &[&keys[0]]);
    let want = expected(Role::Targets, 1, &bytes);
    let mut changed = want.clone();
    changed.length += 1;
    assert!(verify_complete_child(&client, &changed, &bytes, NOW)
        .unwrap_err()
        .is("TUF_CANDIDATE_LENGTH"));
    changed = want.clone();
    changed.sha256[0] ^= 1;
    assert!(verify_complete_child(&client, &changed, &bytes, NOW)
        .unwrap_err()
        .is("TUF_CANDIDATE_HASH"));
    changed = want.clone();
    changed.version = 2;
    assert!(verify_complete_child(&client, &changed, &bytes, NOW)
        .unwrap_err()
        .is("TUF_CANDIDATE_VERSION"));
    for role in [Role::Root, Role::Timestamp] {
        changed = want.clone();
        changed.role = role;
        assert!(verify_complete_child(&client, &changed, &bytes, NOW)
            .unwrap_err()
            .is("TUF_CANDIDATE_ROLE"));
    }
    let pretty =
        serde_json::to_vec_pretty(&serde_json::from_slice::<Value>(&bytes).unwrap()).unwrap();
    assert!(
        verify_complete_child(&client, &expected(Role::Targets, 1, &pretty), &pretty, NOW)
            .unwrap_err()
            .is("TUF_CANDIDATE_OUTER_CANONICAL")
    );
    let mut expired = body(Role::Targets, 1);
    expired["expires"] = "2020-01-01T00:00:00Z".into();
    let expired = signed(&expired, &[&keys[0]]);
    assert!(verify_complete_child(
        &client,
        &expected(Role::Targets, 1, &expired),
        &expired,
        NOW
    )
    .unwrap_err()
    .is("TUF_METADATA_EXPIRED"));
    let mut long = body(Role::Targets, 1);
    long["expires"] = "2040-01-01T00:00:00Z".into();
    let long = signed(&long, &[&keys[0]]);
    assert!(verify_complete_child(
        &client,
        &expected(Role::Targets, 1, &long),
        &long,
        parse_rfc3339_utc("2036-01-01T00:00:00Z").unwrap()
    )
    .unwrap_err()
    .is("TUF_METADATA_EXPIRED"));
}

#[test]
fn duplicate_decoded_keys_unknown_members_floats_depth_and_size_refuse() {
    let (client, keys) = trust(1);
    let bytes = signed(&body(Role::Targets, 1), &[&keys[0]]);
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let check =
        |raw: &[u8]| verify_complete_child(&client, &expected(Role::Targets, 1, raw), raw, NOW);
    let text = String::from_utf8(bytes.clone()).unwrap();
    for raw in [
        text.replacen("{", "{\"signed\":{},", 1),
        text.replace(
            "\"integer\":9007199254740991",
            "\"integer\":1,\"\\u0069nteger\":9007199254740991",
        ),
    ] {
        assert!(check(raw.as_bytes()).unwrap_err().is("TUF_CANDIDATE_JSON"));
    }
    let mut unknown = value.clone();
    unknown["outer_admin_bypass"] = true.into();
    assert!(check(&wire(&unknown))
        .unwrap_err()
        .is("TUF_CANDIDATE_SCHEMA"));
    unknown = value.clone();
    unknown["signatures"][0]["admin"] = true.into();
    assert!(check(&wire(&unknown))
        .unwrap_err()
        .is("TUF_CANDIDATE_SCHEMA"));
    let mut unknown_signed = body(Role::Targets, 1);
    unknown_signed["delegations"] = json!({});
    assert!(check(&signed(&unknown_signed, &[&keys[0]]))
        .unwrap_err()
        .is("TUF_CANDIDATE_SCHEMA"));
    for numeric in [
        "1.5",
        "1e0",
        "1E+3",
        "18446744073709551616",
        "-9223372036854775809",
    ] {
        let invalid = text.replace("9007199254740991", numeric);
        assert!(
            check(invalid.as_bytes())
                .unwrap_err()
                .is("TUF_CANDIDATE_JSON"),
            "{numeric}"
        );
    }
    let mut deep = Value::Null;
    for _ in 0..MAX_DEPTH + 1 {
        deep = json!([deep]);
    }
    let mut nested = value.clone();
    nested["signed"]["targets"]["synthetic.txt"]["custom"] = deep;
    assert!(check(&serde_json::to_vec(&nested).unwrap())
        .unwrap_err()
        .is("TUF_CANDIDATE_JSON"));
    let mut nodes = value;
    nodes["signed"]["targets"]["synthetic.txt"]["custom"] = json!(vec![0; MAX_NODES]);
    assert!(check(&serde_json::to_vec(&nodes).unwrap())
        .unwrap_err()
        .is("TUF_CANDIDATE_JSON"));
    assert!(check(&vec![b' '; MAX_CHILD_BYTES + 1])
        .unwrap_err()
        .is("TUF_CANDIDATE_SIZE"));
    assert!(check(b"\xff").unwrap_err().is("TUF_CANDIDATE_JSON"));
}

#[test]
fn every_signature_is_sorted_distinct_authorized_and_valid_even_above_threshold() {
    let (client, keys) = trust(1);
    let all = signed(&body(Role::Targets, 1), &[&keys[0], &keys[1]]);
    let check =
        |raw: &[u8]| verify_complete_child(&client, &expected(Role::Targets, 1, raw), raw, NOW);
    assert_eq!(check(&all).unwrap().signatures, 2);
    let original: Value = serde_json::from_slice(&all).unwrap();
    let mut changed = original.clone();
    changed["signatures"].as_array_mut().unwrap().reverse();
    assert!(check(&wire(&changed))
        .unwrap_err()
        .is("TUF_CANDIDATE_SIGNATURE_ORDER"));
    changed = original.clone();
    let duplicate = changed["signatures"][0].clone();
    changed["signatures"] = json!([duplicate.clone(), duplicate]);
    assert!(check(&wire(&changed))
        .unwrap_err()
        .is("TUF_CANDIDATE_SIGNATURE_ORDER"));
    changed = original.clone();
    changed["signatures"][1]["sig"] = "00".repeat(64).into();
    assert!(check(&wire(&changed))
        .unwrap_err()
        .is("TUF_CANDIDATE_SIGNATURE_INVALID"));
    let outsider = SigningKey::from_bytes(&[75; 32]);
    let outsider = signed(&body(Role::Targets, 1), &[&outsider]);
    let outsider: Value = serde_json::from_slice(&outsider).unwrap();
    changed = original.clone();
    changed["signatures"]
        .as_array_mut()
        .unwrap()
        .push(outsider["signatures"][0].clone());
    changed["signatures"]
        .as_array_mut()
        .unwrap()
        .sort_by(|a, b| a["keyid"].as_str().cmp(&b["keyid"].as_str()));
    assert!(check(&wire(&changed))
        .unwrap_err()
        .is("TUF_CANDIDATE_SIGNATURE_UNAUTHORIZED"));
    let (threshold_client, _) = trust(2);
    let one = signed(&body(Role::Targets, 1), &[&keys[0]]);
    assert!(verify_complete_child(
        &threshold_client,
        &expected(Role::Targets, 1, &one),
        &one,
        NOW
    )
    .unwrap_err()
    .is("TUF_THRESHOLD_NOT_MET"));
}

#[test]
fn complete_signed_custom_fields_and_original_root_fields_are_never_dropped() {
    let (client, keys) = trust(1);
    let bytes = signed(&body(Role::Targets, 1), &[&keys[0]]);
    let mut tampered: Value = serde_json::from_slice(&bytes).unwrap();
    tampered["signed"]["targets"]["synthetic.txt"]["custom"]["complete_signed_extension"] =
        "changed".into();
    let tampered = wire(&tampered);
    assert!(verify_complete_child(
        &client,
        &expected(Role::Targets, 1, &tampered),
        &tampered,
        NOW
    )
    .unwrap_err()
    .is("TUF_CANDIDATE_SIGNATURE_INVALID"));
    let mut literal = body(Role::Targets, 1);
    literal["targets"]["synthetic.txt"]["custom"] = json!({"$serde_json::private::Number":"1"});
    let literal_bytes = signed(&literal, &[&keys[0]]);
    let literal_facts = verify_complete_child(
        &client,
        &expected(Role::Targets, 1, &literal_bytes),
        &literal_bytes,
        NOW,
    )
    .unwrap();
    let exact_digest: [u8; 32] = Sha256::digest(wire(&literal)).into();
    assert_eq!(literal_facts.signed_body_sha256, exact_digest);
    let mut reinterpreted = literal.clone();
    reinterpreted["targets"]["synthetic.txt"]["custom"] = json!(1);
    let wrong = super::super::sign(&reinterpreted, &[&keys[0]]).unwrap();
    let forged = wire(&Signed {
        signed: literal,
        signatures: wrong.signatures,
    });
    assert!(
        verify_complete_child(&client, &expected(Role::Targets, 1, &forged), &forged, NOW)
            .unwrap_err()
            .is("TUF_CANDIDATE_SIGNATURE_INVALID")
    );
    // Existing typed bootstrap ignores unknown root signed members. This
    // diagnostic path re-verifies the EXACT pinned root body and refuses such
    // a signature that covered only the typed subset; production is unchanged.
    let mut root: Value = serde_json::from_slice(&client.anchor).unwrap();
    root["signed"]["uncovered_signed_root_field"] = true.into();
    let forged = TufClient::bootstrap(&wire(&root)).unwrap();
    assert!(
        verify_complete_child(&forged, &expected(Role::Targets, 1, &bytes), &bytes, NOW).is_err()
    );
}

#[test]
fn adopted_role_floor_refuses_rollback_and_same_version_changed_complete_bytes() {
    let (mut client, keys) = trust(1);
    let targets = signed(&body(Role::Targets, 2), &[&keys[0]]);
    let mut snapshot = body(Role::Snapshot, 2);
    snapshot["meta"]["targets.json"] = json!({"version":2,"length":targets.len(),"hashes":{"sha256":hex::encode(Sha256::digest(&targets))}});
    let snapshot = signed(&snapshot, &[&keys[0]]);
    let timestamp = json!({"_type":"timestamp","spec_version":SPEC_VERSION,"version":2,"expires":"2035-01-01T00:00:00Z",
        "meta":{"snapshot.json":{"version":2,"length":snapshot.len(),"hashes":{"sha256":hex::encode(Sha256::digest(&snapshot))}}}});
    let timestamp = signed(&timestamp, &[&keys[0]]);
    client
        .refresh(&timestamp, &snapshot, &targets, NOW)
        .unwrap();
    assert!(verify_complete_child(
        &client,
        &expected(Role::Targets, 2, &targets),
        &targets,
        NOW
    )
    .is_ok());
    let old = signed(&body(Role::Targets, 1), &[&keys[0]]);
    assert!(
        verify_complete_child(&client, &expected(Role::Targets, 1, &old), &old, NOW)
            .unwrap_err()
            .is("TUF_ROLLBACK")
    );
    let mut changed = body(Role::Targets, 2);
    changed["targets"]["synthetic.txt"]["custom"]["complete_signed_extension"] =
        "equivocation".into();
    let changed = signed(&changed, &[&keys[0]]);
    assert!(verify_complete_child(
        &client,
        &expected(Role::Targets, 2, &changed),
        &changed,
        NOW
    )
    .unwrap_err()
    .is("TUF_EQUIVOCATION"));
}

fn migration_expected(client: &TufClient, body: &Value) -> ExpectedRootMigration {
    let old =
        envelope(strict_json(client.chain.last().unwrap_or(&client.anchor)).unwrap()).unwrap();
    let bytes = wire(body);
    ExpectedRootMigration {
        base_version: client.root().version,
        new_version: number(body, "version").unwrap(),
        old_root_signed_sha256: Sha256::digest(wire(&old.signed)).into(),
        new_root_signed_sha256: Sha256::digest(&bytes).into(),
        new_root_signed_bytes: bytes.len() as u64,
        expires_utc_ms: parse_rfc3339_utc(text(body, "expires").unwrap()).unwrap() as u64 * 1000,
        old_tuf_assignment_sha256: assignment_hash(&old.signed).unwrap(),
        new_tuf_assignment_sha256: assignment_hash(body).unwrap(),
    }
}
fn migration_fixture() -> (TufClient, Vec<SigningKey>, Vec<SigningKey>, Value) {
    let (client, old) = trust(2);
    let new = vec![
        SigningKey::from_bytes(&[91; 32]),
        SigningKey::from_bytes(&[92; 32]),
    ];
    let mut root = client.root().clone();
    root.version = 2;
    root.keys.clear();
    let mut ids = Vec::new();
    for key in &new {
        let key = TufKey::ed25519(&key.verifying_key());
        let id = key.keyid().unwrap();
        ids.push(id.clone());
        root.keys.insert(id, key);
    }
    ids.sort();
    for assignment in root.roles.values_mut() {
        assignment.keyids = ids.clone();
        assignment.threshold = 2;
    }
    (client, old, new, serde_json::to_value(root).unwrap())
}
fn all_migration_signers<'a>(old: &'a [SigningKey], new: &'a [SigningKey]) -> Vec<&'a SigningKey> {
    old.iter().chain(new.iter()).collect()
}

#[test]
fn root_migration_requires_actual_disjoint_old_and_new_thresholds_without_adoption() {
    let (client, old, new, body) = migration_fixture();
    let want = migration_expected(&client, &body);
    let before = client.export().unwrap();
    let proposed = signed(&body, &all_migration_signers(&old, &new));
    let facts = verify_root_migration(&client, &want, &proposed, NOW).unwrap();
    assert_eq!(
        (
            facts.old_version,
            facts.new_version,
            facts.old_signatures,
            facts.new_signatures
        ),
        (1, 2, 2, 2)
    );
    assert_eq!(facts.envelope_bytes, proposed.len() as u64);
    let hash: [u8; 32] = Sha256::digest(&proposed).into();
    assert_eq!(facts.envelope_sha256, hash);
    assert_eq!(facts.signed_body_sha256, want.new_root_signed_sha256);
    assert_eq!(
        client.export().unwrap(),
        before,
        "migration diagnostics never adopt a root or clear child floors"
    );
    for keys in [&old[..], &new[..]] {
        assert!(verify_root_migration(
            &client,
            &want,
            &signed(&body, &keys.iter().collect::<Vec<_>>()),
            NOW
        )
        .unwrap_err()
        .is("TUF_THRESHOLD_NOT_MET"));
    }
    for keys in [
        vec![&old[0], &new[0], &new[1]],
        vec![&old[0], &old[1], &new[0]],
    ] {
        assert!(
            verify_root_migration(&client, &want, &signed(&body, &keys), NOW)
                .unwrap_err()
                .is("TUF_THRESHOLD_NOT_MET")
        );
    }
}

#[test]
fn root_migration_commitments_version_expiry_and_time_refuse_substitution() {
    let (client, old, new, body) = migration_fixture();
    let want = migration_expected(&client, &body);
    let proposed = signed(&body, &all_migration_signers(&old, &new));
    for mutation in 0..9 {
        let mut changed = want.clone();
        match mutation {
            0 => changed.base_version += 1,
            1 => changed.new_version += 1,
            2 => changed.old_root_signed_sha256[0] ^= 1,
            3 => changed.new_root_signed_sha256[0] ^= 1,
            4 => changed.new_root_signed_bytes += 1,
            5 => changed.expires_utc_ms += 1,
            6 => changed.old_tuf_assignment_sha256[0] ^= 1,
            7 => changed.new_tuf_assignment_sha256[0] ^= 1,
            _ => changed.new_version = 0,
        }
        assert!(
            verify_root_migration(&client, &changed, &proposed, NOW).is_err(),
            "commitment {mutation}"
        );
    }
    assert!(verify_root_migration(&client, &want, &proposed, -1).is_err());
    let mut changed = body.clone();
    changed["version"] = json!(3);
    let expected = migration_expected(&client, &changed);
    assert!(verify_root_migration(
        &client,
        &expected,
        &signed(&changed, &all_migration_signers(&old, &new)),
        NOW
    )
    .unwrap_err()
    .is("TUF_CANDIDATE_ROOT_VERSION"));
    for expires in ["2020-01-01T00:00:00Z", "2030-01-01T00:00:00Z"] {
        let mut changed = body.clone();
        changed["expires"] = json!(expires);
        let expected = migration_expected(&client, &changed);
        let wire = signed(&changed, &all_migration_signers(&old, &new));
        if expires.starts_with("2020") {
            assert!(verify_root_migration(&client, &expected, &wire, NOW).is_err());
        } else {
            let expiry = parse_rfc3339_utc(expires).unwrap();
            assert_eq!(
                verify_root_migration(&client, &expected, &wire, NOW)
                    .unwrap()
                    .valid_until_unix,
                expiry
            );
            assert!(verify_root_migration(&client, &expected, &wire, expiry).is_err());
        }
    }
}

#[test]
fn root_migration_rejects_invalid_unauthorized_duplicate_or_unsorted_extra_signatures() {
    let (client, old, new, body) = migration_fixture();
    let want = migration_expected(&client, &body);
    let wire = signed(&body, &all_migration_signers(&old, &new));
    let good: Value = serde_json::from_slice(&wire).unwrap();
    for mutation in 0..4 {
        let mut changed = good.clone();
        let signatures = changed["signatures"].as_array_mut().unwrap();
        match mutation {
            0 => signatures[0]["sig"] = json!("00".repeat(64)),
            1 => {
                let unrelated = SigningKey::from_bytes(&[93; 32]);
                let extra: Value = serde_json::from_slice(&signed(&body, &[&unrelated])).unwrap();
                signatures.push(extra["signatures"][0].clone());
                signatures.sort_by(|a, b| a["keyid"].as_str().cmp(&b["keyid"].as_str()));
            }
            2 => {
                let duplicate = signatures[0].clone();
                signatures.insert(0, duplicate);
            }
            _ => signatures.reverse(),
        }
        assert!(
            verify_root_migration(
                &client,
                &want,
                &crate::canonical_json::to_canonical_json_bytes(&changed).unwrap(),
                NOW
            )
            .is_err(),
            "signature mutation {mutation}"
        );
    }
}

#[test]
fn root_migration_closed_key_and_role_schema_cannot_weaken_ordinary_thresholds() {
    let (client, old, new, body) = migration_fixture();
    for mutation in 0..9 {
        let mut changed = body.clone();
        let first = changed["keys"]
            .as_object()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone();
        match mutation {
            0 => changed["roles"]["root"]["threshold"] = json!(0),
            1 => changed["roles"]["root"]["threshold"] = json!(3),
            2 => {
                let id = changed["roles"]["root"]["keyids"][0].clone();
                changed["roles"]["root"]["keyids"][1] = id;
            }
            3 => changed["roles"]["root"]["keyids"][0] = json!("ff".repeat(32)),
            4 => changed["keys"][&first]["ignored_key_extension"] = json!(true),
            5 => {
                changed["roles"].as_object_mut().unwrap().remove("targets");
            }
            6 => changed["uncovered_root_member"] = json!({"$serde_json::private::Number":"1"}),
            7 => changed["roles"]["root"]["keyids"]
                .as_array_mut()
                .unwrap()
                .reverse(),
            _ => {
                let key = changed["keys"][&first].clone();
                changed["keys"]
                    .as_object_mut()
                    .unwrap()
                    .insert("ff".repeat(32), key);
            }
        }
        let expected = migration_expected(&client, &changed);
        assert!(
            verify_root_migration(
                &client,
                &expected,
                &signed(&changed, &all_migration_signers(&old, &new)),
                NOW
            )
            .is_err(),
            "schema {mutation}"
        );
    }
    let want = migration_expected(&client, &body);
    let good = signed(&body, &all_migration_signers(&old, &new));
    let mut spaced = good.clone();
    spaced.push(b' ');
    assert!(verify_root_migration(&client, &want, &spaced, NOW)
        .unwrap_err()
        .is("TUF_CANDIDATE_OUTER_CANONICAL"));
    let text = String::from_utf8(good).unwrap();
    let duplicate = text.replacen("\"signed\":", "\"signed\":{},\"signed\":", 1);
    assert!(
        verify_root_migration(&client, &want, duplicate.as_bytes(), NOW)
            .unwrap_err()
            .is("TUF_CANDIDATE_JSON")
    );
}

#[test]
fn root_migration_after_adopted_dual_signed_rotation_preserves_retired_signatures_and_floors() {
    let (mut client, old, new, body) = migration_fixture();
    let rotation = signed(&body, &all_migration_signers(&old, &new));
    client.update_root(&rotation).unwrap();
    let before = client.export().unwrap();
    let mut next = body.clone();
    next["version"] = json!(3);
    let want = migration_expected(&client, &next);
    let proposed = signed(&next, &new.iter().collect::<Vec<_>>());
    let facts = verify_root_migration(&client, &want, &proposed, NOW).unwrap();
    assert_eq!(
        (
            facts.old_version,
            facts.new_version,
            facts.old_signatures,
            facts.new_signatures
        ),
        (2, 3, 2, 2)
    );
    assert_eq!(client.export().unwrap(), before);
    let expiry = parse_rfc3339_utc(&client.root().expires).unwrap();
    assert!(verify_root_migration(&client, &want, &proposed, expiry).is_err());
}

#[test]
fn root_migration_rejects_noncanonical_curve_aliases_and_weak_root_keys() {
    let (_, _, _, body) = migration_fixture();
    let (canonical, alias) = (0u8..19)
        .find_map(|y| {
            let mut first = [0u8; 32];
            first[0] = y;
            let mut second = [0xffu8; 32];
            second[0] = 0xed + y;
            second[31] = 0x7f;
            let canonical = VerifyingKey::from_bytes(&first).ok()?;
            let alias = VerifyingKey::from_bytes(&second).ok()?;
            if canonical.is_weak()
                || canonical.to_edwards().compress().to_bytes()
                    != alias.to_edwards().compress().to_bytes()
            {
                return None;
            }
            Some((canonical, alias))
        })
        .expect("dalek accepts a nonweak alternate compressed-point encoding");
    assert_ne!(canonical.to_bytes(), alias.to_bytes());
    let prepare = |keys: &[VerifyingKey]| {
        let mut changed = body.clone();
        let mut public = BTreeMap::new();
        let mut ids = Vec::new();
        for key in keys {
            let key = TufKey::ed25519(key);
            let id = key.keyid().unwrap();
            ids.push(id.clone());
            public.insert(id, key);
        }
        ids.sort();
        changed["keys"] = serde_json::to_value(public).unwrap();
        for role in ["root", "targets", "snapshot", "timestamp"] {
            changed["roles"][role] = json!({"keyids":ids,"threshold":keys.len()});
        }
        changed
    };
    assert!(
        migration_root(&prepare(&[canonical])).is_ok(),
        "canonical nonweak representation remains admissible"
    );
    assert!(migration_root(&prepare(&[alias]))
        .unwrap_err()
        .is("TUF_CANDIDATE_ROOT_KEY"));
    assert!(migration_root(&prepare(&[canonical, alias]))
        .unwrap_err()
        .is("TUF_CANDIDATE_ROOT_KEY"));
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let weak = VerifyingKey::from_bytes(&identity).unwrap();
    assert!(weak.is_weak());
    assert!(migration_root(&prepare(&[weak]))
        .unwrap_err()
        .is("TUF_CANDIDATE_ROOT_KEY"));
}
