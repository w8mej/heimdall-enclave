//! Primitive SOFTWARE identity/path checks only. No opaque actual event,
//! native birth/guard/checked load or EX capability is constructed or faked.
use super::*;

fn old() -> DirStamp {
    DirStamp {
        dev: 19,
        ino: 73,
        uid: 0,
        gid: 0,
        mode: libc::S_IFDIR as u32 | 0o700,
    }
}
fn after() -> DirectoryModeIdentity {
    let mut value = identity(&old());
    value.mode = libc::S_IFDIR as u32 | 0o755;
    value
}

#[test]
fn metadata_only_exact_original_root700_to755_prediction_preserves_identity_and_type() {
    let old = old();
    let predicted = predicted(&old, identity(&old), after()).unwrap();
    assert_eq!(
        (predicted.dev, predicted.ino, predicted.uid, predicted.gid),
        (old.dev, old.ino, old.uid, old.gid)
    );
    assert_eq!(predicted.mode, libc::S_IFDIR as u32 | 0o755);
    assert_eq!(old.mode, libc::S_IFDIR as u32 | 0o700);
    // These public metadata values are NOT an event or an accepted recipient.
}
#[test]
fn changed_old_metadata_or_nonprivate_initial_identity_cannot_be_accepted_as_original() {
    for variant in 0..10 {
        let mut original = old();
        let mut before = identity(&original);
        match variant {
            0 => before.dev += 1,
            1 => before.ino += 1,
            2 => before.uid = 1,
            3 => before.gid = 1,
            4 => before.mode = libc::S_IFDIR as u32 | 0o755,
            5 => original.uid = 1,
            6 => original.gid = 1,
            7 => {
                original.mode = libc::S_IFREG as u32 | 0o700;
                before = identity(&original);
            }
            8 => {
                original.mode = libc::S_IFDIR as u32 | 0o755;
                before = identity(&original);
            }
            _ => {
                original.mode = libc::S_IFDIR as u32 | 0o2700;
                before = identity(&original);
            }
        }
        assert!(predicted(&original, before, after())
            .err()
            .expect("must refuse")
            .is("BIRTH_DIRECTORY_EVENT_ORIGINAL_IDENTITY"));
    }
}
#[test]
fn changed_after_identity_extra_permissions_or_file_type_never_become_predicted_metadata() {
    for variant in 0..8 {
        let original = old();
        let mut changed = after();
        match variant {
            0 => changed.dev += 1,
            1 => changed.ino += 1,
            2 => changed.uid = 702,
            3 => changed.gid = 8702,
            4 => changed.mode = libc::S_IFDIR as u32 | 0o775,
            5 => changed.mode = libc::S_IFDIR as u32 | 0o2755,
            6 => changed.mode = libc::S_IFDIR as u32 | 0o700,
            _ => changed.mode = libc::S_IFREG as u32 | 0o755,
        }
        assert!(predicted(&original, identity(&original), changed)
            .err()
            .expect("must refuse")
            .is("BIRTH_DIRECTORY_EVENT_PREDICTED_DELTA"));
    }
}
#[test]
fn fixed_role_scope_refuses_other_paths_spelling_aliases_and_external_or_equal_support() {
    let root = Path::new("/allocated/00112233445566778899aabbccddeeff");
    let support = root.join("support");
    fixed_path(root, &support, PrivateBirthAncestor::SupportRoot, &support).unwrap();
    fixed_path(root, &support, PrivateBirthAncestor::NonceRoot, root).unwrap();
    for path in [
        root.join("Support"),
        support.join("child"),
        root.join("config"),
        PathBuf::from("/outside/support"),
    ] {
        assert!(fixed_path(root, &support, PrivateBirthAncestor::SupportRoot, &path).is_err());
        assert!(fixed_path(root, &support, PrivateBirthAncestor::NonceRoot, &path).is_err());
    }
    assert!(fixed_path(root, root, PrivateBirthAncestor::NonceRoot, root).is_err());
    assert!(fixed_path(
        root,
        Path::new("/outside/support"),
        PrivateBirthAncestor::NonceRoot,
        root
    )
    .is_err());
    assert!(fixed_path(
        Path::new("/allocated//nonce"),
        Path::new("/allocated/nonce/support"),
        PrivateBirthAncestor::NonceRoot,
        Path::new("/allocated/nonce")
    )
    .is_err());
}
