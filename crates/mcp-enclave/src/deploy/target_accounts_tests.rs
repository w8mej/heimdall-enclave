//! Pure fixed-record fixtures only. These neither query nor provision accounts,
//! and do not establish real directory authority or installed readiness.
use super::*;

struct Fake {
    users: Vec<User>,
    groups: Vec<Group>,
    memberships: BTreeSet<(String, String)>,
    user_reverse: bool,
    group_reverse: bool,
    user_reverse_aliases: bool,
    group_reverse_aliases: bool,
    unavailable: bool,
    calls: usize,
    change_after: Option<usize>,
    alias_change_after: Option<usize>,
}
impl Fake {
    fn exact() -> Self {
        let users = USERS
            .into_iter()
            .enumerate()
            .map(|(index, (name, uid, gid))| User {
                name: name.into(),
                aliases: BTreeSet::from([name.into()]),
                uid,
                primary_gid: gid,
                record_id: format!("00000000-0000-0000-0000-{:012x}", index + 1),
                node: "/Local/Default".into(),
            })
            .collect();
        let groups = GROUPS
            .into_iter()
            .enumerate()
            .map(|(index, (name, gid))| Group {
                name: name.into(),
                aliases: BTreeSet::from([name.into()]),
                gid,
                record_id: format!("00000000-0000-0000-0001-{:012x}", index + 1),
                node: "/Local/Default".into(),
            })
            .collect();
        Self {
            users,
            groups,
            memberships: MEMBERSHIPS
                .into_iter()
                .map(|(g, u)| (g.into(), u.into()))
                .collect(),
            user_reverse: false,
            group_reverse: false,
            user_reverse_aliases: false,
            group_reverse_aliases: false,
            unavailable: false,
            calls: 0,
            change_after: None,
            alias_change_after: None,
        }
    }
    fn called(&mut self) -> EnclaveResult<()> {
        self.calls += 1;
        if self.unavailable {
            fail!(EIO, "SYNTHETIC_DIRECTORY_UNAVAILABLE");
        }
        if self.change_after == Some(self.calls) {
            self.users[0].node = "/Local/Changed".into();
        }
        if self.alias_change_after == Some(self.calls) {
            self.users[0].aliases.insert("changed alias".into());
        }
        Ok(())
    }
}
impl DirectoryBackend for Fake {
    fn users(&mut self, lookup: Lookup) -> EnclaveResult<Vec<User>> {
        self.called()?;
        let mut users = self
            .users
            .iter()
            .filter(|user| match lookup {
                Lookup::Name(name) => user.name == name || user.aliases.contains(name),
                Lookup::Id(uid) => user.uid == uid,
            })
            .cloned()
            .collect::<Vec<_>>();
        if self.user_reverse && matches!(lookup, Lookup::Id(_)) {
            for user in &mut users {
                user.record_id = "ffffffff-ffff-ffff-ffff-ffffffffffff".into();
            }
        }
        if self.user_reverse_aliases && matches!(lookup, Lookup::Id(_)) {
            for user in &mut users {
                user.aliases.insert("numeric-only alias".into());
            }
        }
        Ok(users)
    }
    fn groups(&mut self, lookup: Lookup) -> EnclaveResult<Vec<Group>> {
        self.called()?;
        let mut groups = self
            .groups
            .iter()
            .filter(|group| match lookup {
                Lookup::Name(name) => group.name == name || group.aliases.contains(name),
                Lookup::Id(gid) => group.gid == gid,
            })
            .cloned()
            .collect::<Vec<_>>();
        if self.group_reverse && matches!(lookup, Lookup::Id(_)) {
            for group in &mut groups {
                group.record_id = "ffffffff-ffff-ffff-ffff-ffffffffffff".into();
            }
        }
        if self.group_reverse_aliases && matches!(lookup, Lookup::Id(_)) {
            for group in &mut groups {
                group.aliases.insert("numeric-only alias".into());
            }
        }
        Ok(groups)
    }
    fn contains(&mut self, group: &Group, user: &User) -> EnclaveResult<bool> {
        self.called()?;
        Ok(self
            .memberships
            .contains(&(group.name.clone(), user.name.clone())))
    }
}

#[test]
fn fixed_required_contract_has_original_names_ids_and_memberships() {
    assert_eq!(USERS.len(), 8);
    assert_eq!(GROUPS.len(), 17);
    assert_eq!(MEMBERSHIPS.len(), 20);
    assert!(USERS.contains(&("root", 0, 0)));
    assert!(GROUPS.contains(&("wheel", 0)));
    assert!(USERS.contains(&("_enclaveingress", 708, 8708)));
    assert!(MEMBERSHIPS.contains(&("_enclave_ifc_c", "_enclaveingress")));
    assert!(MEMBERSHIPS.contains(&("_enclave_witness_c", "_piivault")));
    for (group, user) in MEMBERSHIPS {
        assert!(GROUPS.iter().any(|(name, _)| *name == group));
        assert!(USERS.iter().any(|(name, _, _)| *name == user));
    }
    assert_eq!(
        USERS
            .iter()
            .map(|(_, id, _)| id)
            .collect::<BTreeSet<_>>()
            .len(),
        USERS.len()
    );
    assert_eq!(
        GROUPS
            .iter()
            .map(|(_, id)| id)
            .collect::<BTreeSet<_>>()
            .len(),
        GROUPS.len()
    );
}

#[test]
fn exact_records_require_independent_name_and_numeric_queries_and_stable_repeat() {
    let mut fake = Fake::exact();
    let snapshot = stable_observation(&mut fake).unwrap();
    assert_eq!(snapshot.users.len(), 8);
    assert_eq!(snapshot.groups.len(), 17);
    assert_eq!(snapshot.memberships.len(), 20);
    assert_eq!(
        fake.calls,
        2 * (2 * USERS.len() + 2 * GROUPS.len() + MEMBERSHIPS.len())
    );
    assert!(format!(
        "{:?}",
        FixedAccountAdmission {
            target_id: "synthetic".into(),
            descriptor_sha256: "aa".repeat(32),
            inventory_sha256: "bb".repeat(32),
            snapshot
        }
    )
    .contains("FixedAccountAdmission"));
}

#[test]
fn bounded_alias_sets_preserve_exact_official_identity_without_array_order_authority() {
    let expected = BTreeSet::from(["root".to_owned(), "public synthetic alias".to_owned()]);
    assert_eq!(
        checked_aliases("root", vec!["root".into(), "public synthetic alias".into()]).unwrap(),
        expected
    );
    assert_eq!(
        checked_aliases("root", vec!["public synthetic alias".into(), "root".into()]).unwrap(),
        expected
    );
    assert!(checked_aliases("root", vec!["foreign-primary".into()]).is_err());
    assert!(checked_aliases("root", vec!["root".into(), "root".into()]).is_err());
    let mut at_count = vec!["root".into()];
    at_count.extend((1..MAX_ALIASES).map(|i| format!("alias-{i}")));
    assert_eq!(
        checked_aliases("root", at_count).unwrap().len(),
        MAX_ALIASES
    );
    let at_bytes = vec![
        "root".into(),
        "a".repeat(1024),
        "b".repeat(1024),
        "c".repeat(1024),
        "d".repeat(1020),
    ];
    assert_eq!(
        at_bytes.iter().map(String::len).sum::<usize>(),
        MAX_ALIAS_BYTES
    );
    checked_aliases("root", at_bytes).unwrap();
    let mut fake = Fake::exact();
    fake.users[0].aliases = expected.clone();
    fake.groups[0]
        .aliases
        .insert("public synthetic group alias".into());
    let snapshot = stable_observation(&mut fake).unwrap();
    assert_eq!(snapshot.users["root"].name, "root");
    assert_eq!(snapshot.users["root"].aliases, expected);
    // A matching alias cannot replace the fixed official primary name.
    let mut fake = Fake::exact();
    fake.users[0].name = "foreign-primary".into();
    fake.users[0].aliases.insert("foreign-primary".into());
    assert!(observe(&mut fake).is_err());
}

#[test]
fn portable_admission_refuses_missing_official_and_unbounded_or_ambiguous_alias_sets() {
    for entity in ["user", "group"] {
        for change in [
            "empty",
            "missing-official",
            "ascii-case",
            "count",
            "length",
            "bytes",
            "control",
            "empty-value",
        ] {
            let mut fake = Fake::exact();
            let official = if entity == "user" { "root" } else { "wheel" };
            let aliases = if entity == "user" {
                &mut fake.users[0].aliases
            } else {
                &mut fake.groups[0].aliases
            };
            match change {
                "empty" => aliases.clear(),
                "missing-official" => {
                    aliases.remove(official);
                    aliases.insert("foreign-alias".into());
                }
                "ascii-case" => {
                    aliases.insert(official.to_ascii_uppercase());
                }
                "count" => {
                    aliases.extend((0..MAX_ALIASES).map(|i| format!("alias-{i}")));
                }
                "length" => {
                    aliases.insert("a".repeat(1025));
                }
                "bytes" => {
                    aliases.extend((0..5).map(|i| format!("{i}{}", "a".repeat(999))));
                }
                "control" => {
                    aliases.insert("root\0suffix".into());
                }
                "empty-value" => {
                    aliases.insert(String::new());
                }
                _ => unreachable!(),
            }
            assert!(
                observe(&mut fake)
                    .unwrap_err()
                    .is("ACCOUNTS_NATIVE_ALIASES"),
                "{entity}/{change}"
            );
        }
    }
}

#[test]
fn alias_drift_between_name_numeric_or_repeated_observations_refuses() {
    let mut fake = Fake::exact();
    fake.user_reverse_aliases = true;
    assert!(observe(&mut fake)
        .unwrap_err()
        .is("ACCOUNTS_USER_COLLISION"));
    let mut fake = Fake::exact();
    fake.group_reverse_aliases = true;
    assert!(observe(&mut fake)
        .unwrap_err()
        .is("ACCOUNTS_GROUP_COLLISION"));
    let mut fake = Fake::exact();
    fake.alias_change_after = Some(2 * USERS.len() + 2 * GROUPS.len() + MEMBERSHIPS.len() + 1);
    assert!(stable_observation(&mut fake)
        .unwrap_err()
        .is("ACCOUNTS_CHANGED"));
}

#[test]
fn missing_duplicate_name_or_numeric_collisions_and_wrong_primary_group_refuse() {
    for change in [
        "missing-user",
        "missing-group",
        "duplicate-user",
        "duplicate-group",
        "uid-collision",
        "gid-collision",
        "primary-gid",
    ] {
        let mut fake = Fake::exact();
        match change {
            "missing-user" => {
                fake.users.remove(1);
            }
            "missing-group" => {
                fake.groups.remove(1);
            }
            "duplicate-user" => fake.users.push(fake.users[1].clone()),
            "duplicate-group" => fake.groups.push(fake.groups[1].clone()),
            "uid-collision" => {
                let mut other = fake.users[1].clone();
                other.name = "foreign-user".into();
                fake.users.push(other);
            }
            "gid-collision" => {
                let mut other = fake.groups[1].clone();
                other.name = "foreign-group".into();
                fake.groups.push(other);
            }
            "primary-gid" => fake.users[1].primary_gid = 0,
            _ => unreachable!(),
        }
        assert!(observe(&mut fake).is_err(), "{change}");
    }
}

#[test]
fn reverse_record_identity_mismatch_and_reused_or_malformed_record_identity_refuse() {
    for change in [
        "user-reverse",
        "group-reverse",
        "reused-user-id",
        "reused-group-id",
        "bad-id",
        "empty-node",
        "relative-node",
        "control-node",
    ] {
        let mut fake = Fake::exact();
        match change {
            "user-reverse" => fake.user_reverse = true,
            "group-reverse" => fake.group_reverse = true,
            "reused-user-id" => fake.users[1].record_id = fake.users[0].record_id.clone(),
            "reused-group-id" => fake.groups[1].record_id = fake.groups[0].record_id.clone(),
            "bad-id" => fake.users[0].record_id = "opaque".into(),
            "empty-node" => fake.users[0].node.clear(),
            "relative-node" => fake.users[0].node = "Local/Default".into(),
            "control-node" => fake.users[0].node = "/Local/Default\0suffix".into(),
            _ => unreachable!(),
        }
        assert!(observe(&mut fake).is_err(), "{change}");
    }
}

#[test]
fn every_required_membership_and_directory_availability_are_mandatory() {
    for (group, user) in MEMBERSHIPS {
        let mut fake = Fake::exact();
        fake.memberships.remove(&(group.into(), user.into()));
        assert!(observe(&mut fake)
            .unwrap_err()
            .is("ACCOUNTS_REQUIRED_MEMBERSHIP"));
    }
    let mut fake = Fake::exact();
    fake.unavailable = true;
    assert!(observe(&mut fake)
        .unwrap_err()
        .is("SYNTHETIC_DIRECTORY_UNAVAILABLE"));
    assert_eq!(fake.calls, 1);
}

#[test]
fn repeated_observation_refuses_changed_directory_instead_of_reissuing_old_observation() {
    let mut fake = Fake::exact();
    fake.change_after = Some(2 * USERS.len() + 2 * GROUPS.len() + MEMBERSHIPS.len() + 1);
    assert!(stable_observation(&mut fake)
        .unwrap_err()
        .is("ACCOUNTS_CHANGED"));
}

#[test]
fn actual_root_gate_cannot_be_satisfied_by_directory_record_or_target_fields() {
    require_root(0).unwrap();
    assert!(require_root(501).unwrap_err().is("ACCOUNTS_ROOT_REQUIRED"));
}

#[cfg(not(target_os = "macos"))]
#[test]
fn nonnative_directory_observation_has_no_libc_command_or_fixture_fallback() {
    assert!(native_observation()
        .unwrap_err()
        .is("ACCOUNTS_NATIVE_REQUIRED"));
}

#[cfg(target_os = "macos")]
#[test]
fn native_cf_and_decimal_type_boundaries_refuse_lossy_account_metadata() {
    darwin::test_cf_boundaries();
}

#[cfg(target_os = "macos")]
#[test]
fn native_alias_array_boundaries_reject_wrong_types_duplicates_and_unbounded_values() {
    darwin::test_alias_boundaries();
}

/// Public system records only, no service-account provisioning or application
/// admission. Explicitly ignored so directory-service host reads are visible.
#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires explicit read-only public root/wheel OpenDirectory observation"]
fn native_public_root_wheel_records_match_exact_name_and_numeric_identity() {
    let mut directory = darwin::Directory::new().unwrap();
    let root = one(directory.users(Lookup::Name("root")).unwrap()).unwrap();
    assert!(
        root == one(directory.users(Lookup::Id(0)).unwrap()).unwrap(),
        "root name/numeric identity differs"
    );
    assert_eq!(root.name, "root");
    assert_eq!(root.uid, 0);
    assert_eq!(root.primary_gid, 0);
    validate_aliases(&root.name, &root.aliases).unwrap();
    public_identity(&root.record_id, &root.node).unwrap();
    let wheel = one(directory.groups(Lookup::Name("wheel")).unwrap()).unwrap();
    assert!(
        wheel == one(directory.groups(Lookup::Id(0)).unwrap()).unwrap(),
        "wheel name/numeric identity differs"
    );
    assert_eq!(wheel.name, "wheel");
    assert_eq!(wheel.gid, 0);
    public_identity(&wheel.record_id, &wheel.node).unwrap();
    validate_aliases(&wheel.name, &wheel.aliases).unwrap();
}
