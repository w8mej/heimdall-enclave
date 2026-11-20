use super::*;
use std::{
    ffi::CString,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
};

fn receipt() -> IntentStartReceipt {
    IntentStartReceipt {
        target_id: "intent-fixture".into(),
        descriptor_sha256: "a".repeat(64),
        scope: "SELECTED_CURRENT_CONSOLE_INTENT_REGISTRATION_ONLY",
        console_uid: Some(501),
        audit_session_id: Some(42),
        label: "com.mcpmac.fixture.intent".into(),
        plist: "/Library/LaunchAgents/com.mcpmac.fixture.intent.plist".into(),
        preflight_complete: false,
        bootstrap_attempted: false,
        bootstrap_succeeded: false,
        uncertain_command_effects: false,
        complete: false,
        readiness: "UNKNOWN_HELPER_IPC_BIOMETRIC_YUBIKEY_AND_INSTALLATION_READINESS",
        qualified: false,
    }
}

#[test]
fn native_session_metadata_never_accepts_guessed_loginwindow_or_invalid_audit_identity() {
    for value in [
        None,
        Some((0, 42)),
        Some((499, 42)),
        Some((u32::MAX, 42)),
        Some((501, 0)),
        Some((501, u32::MAX)),
    ] {
        assert!(session_value(value)
            .unwrap_err()
            .is("DEPLOYMENT_INTENT_CONSOLE_SESSION_UNAVAILABLE"));
    }
    assert_eq!(
        session_value(Some((501, 42))).unwrap(),
        ConsoleSession {
            uid: 501,
            audit: 42
        }
    );
    assert_eq!(
        session_value(Some((500, 1))).unwrap(),
        ConsoleSession { uid: 500, audit: 1 }
    );
}

#[test]
fn user_switch_and_same_uid_new_audit_session_both_refuse() {
    let expected = ConsoleSession {
        uid: 501,
        audit: 42,
    };
    same_session(expected, expected).unwrap();
    for actual in [
        ConsoleSession {
            uid: 502,
            audit: 42,
        },
        ConsoleSession {
            uid: 501,
            audit: 43,
        },
    ] {
        assert!(same_session(expected, actual)
            .unwrap_err()
            .is("DEPLOYMENT_INTENT_CONSOLE_SESSION_CHANGED"));
    }
}

#[test]
fn command_is_exact_selected_gui_bootstrap_without_stop_restart_or_environment_overrides() {
    let fixed = IntentCommand::from_namespace(
        "com.mcpmac.test-selected",
        ConsoleSession {
            uid: 1234,
            audit: 42,
        },
    );
    assert_eq!(fixed.label, "com.mcpmac.test-selected.intent");
    let command = fixed.command();
    assert_eq!(command.get_program(), "/bin/launchctl");
    assert_eq!(command.get_current_dir(), Some(Path::new("/")));
    let args = command
        .get_args()
        .map(|a| a.to_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        args,
        [
            "bootstrap",
            "gui/1234",
            "/Library/LaunchAgents/com.mcpmac.test-selected.intent.plist"
        ]
    );
    let environment = command
        .get_envs()
        .map(|(k, v)| (k.to_str().unwrap(), v.map(|v| v.to_str().unwrap())))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(environment.len(), 2);
    assert_eq!(
        environment.get("PATH"),
        Some(&Some(crate::syscmd::SAFE_PATH))
    );
    assert_eq!(environment.get("LC_ALL"), Some(&Some("C")));
}

#[test]
fn intent_requirement_uses_only_original_identifier_exact_selected_entry_and_compiled_team() {
    let bytes = serde_json::to_vec(&serde_json::json!({"v":1,"pins":{
        "com.enterprise.enclave.intent":["1".repeat(40)],"com.other.intent":["2".repeat(40)],
        "com.enterprise.enclave.custody":["3".repeat(40)]}}))
    .unwrap();
    let requirement = intent_requirement(&bytes).unwrap();
    assert_eq!(requirement.identifier, INTENT_ID);
    assert_eq!(requirement.team_id, codesign::TEAM_ID);
    assert_eq!(requirement.cdhash_allowlist, vec!["1".repeat(40)]);
    for bytes in [
        br#"{"v":1,"pins":{"com.other.intent":["1111111111111111111111111111111111111111"]}}"#
            .as_slice(),
        br#"{"v":1,"pins":{"com.enterprise.enclave.intent":[]}}"#.as_slice(),
        br#"{"v":1,"pins":{"com.enterprise.enclave.intent":["invalid"]}}"#.as_slice(),
    ] {
        assert!(intent_requirement(bytes).is_err());
    }
}

#[test]
fn every_command_failure_is_redacted_and_nonzero_exit_never_counts_as_success() {
    for (failure, reason) in [
        (
            CommandFailure::Timeout,
            "DEPLOYMENT_INTENT_BOOTSTRAP_TIMEOUT",
        ),
        (
            CommandFailure::OutputLimit,
            "DEPLOYMENT_INTENT_BOOTSTRAP_OUTPUT_LIMIT",
        ),
        (
            CommandFailure::OwnershipUnknown,
            "DEPLOYMENT_INTENT_BOOTSTRAP_CLEANUP_UNCERTAIN",
        ),
        (
            CommandFailure::Unavailable,
            "DEPLOYMENT_INTENT_BOOTSTRAP_UNAVAILABLE",
        ),
        (
            CommandFailure::Io,
            "DEPLOYMENT_INTENT_BOOTSTRAP_UNAVAILABLE",
        ),
    ] {
        assert!(command_result(Err(failure)).unwrap_err().is(reason));
    }
    for code in [None, Some(1), Some(5)] {
        let error = command_result(Ok(NativeOutput {
            code,
            stdout: b"PRIVATE_CHILD_OUTPUT".to_vec(),
            stderr: b"PRIVATE_CHILD_ERROR".to_vec(),
            contract: None,
        }))
        .unwrap_err();
        assert!(error.is("DEPLOYMENT_INTENT_BOOTSTRAP_FAILED"));
        assert!(!serde_json::to_string(&error)
            .unwrap()
            .contains("PRIVATE_CHILD"));
    }
    command_result(Ok(NativeOutput {
        code: Some(0),
        stdout: vec![],
        stderr: vec![],
        contract: None,
    }))
    .unwrap();
}

#[test]
fn registration_success_remains_unknown_runtime_and_physical_qualification() {
    let mut value = receipt();
    value.preflight_complete = true;
    value.bootstrap_attempted = true;
    value.bootstrap_succeeded = true;
    let report = finish(value, Ok(()), Ok(()), Ok(()));
    assert!(report.successful && report.receipt.complete);
    assert!(!report.receipt.uncertain_command_effects && !report.receipt.qualified);
    assert!(report.receipt.readiness.starts_with("UNKNOWN"));
    assert_eq!(
        report.receipt.scope,
        "SELECTED_CURRENT_CONSOLE_INTENT_REGISTRATION_ONLY"
    );
}

#[test]
fn final_binding_and_guard_failures_preserve_successful_bootstrap_evidence_and_uncertainty() {
    let mut value = receipt();
    value.preflight_complete = true;
    value.bootstrap_attempted = true;
    value.bootstrap_succeeded = true;
    let report = finish(
        value,
        Ok(()),
        Err(err!(ESTALE, "TEST_SESSION_CHANGED")),
        Err(err!(ESTALE, "TEST_GUARD_CHANGED")),
    );
    assert!(!report.successful && !report.receipt.complete);
    assert!(
        report.receipt.bootstrap_attempted
            && report.receipt.bootstrap_succeeded
            && report.receipt.uncertain_command_effects
    );
    assert!(report.error.is_none());
    assert!(report
        .final_binding_error
        .unwrap()
        .is("TEST_SESSION_CHANGED"));
    assert!(report.maintenance_error.unwrap().is("TEST_GUARD_CHANGED"));
}

#[test]
fn original_command_failure_and_independent_final_failures_are_all_retained() {
    let mut value = receipt();
    value.preflight_complete = true;
    value.bootstrap_attempted = true;
    let report = finish(
        value,
        Err(err!(EIO, "TEST_COMMAND_UNCERTAIN")),
        Err(err!(ESTALE, "TEST_DESCRIPTOR_CHANGED")),
        Err(err!(ESTALE, "TEST_GUARD_CHANGED")),
    );
    assert!(!report.successful && !report.receipt.complete && !report.receipt.bootstrap_succeeded);
    assert!(report.receipt.uncertain_command_effects);
    assert!(report.error.unwrap().is("TEST_COMMAND_UNCERTAIN"));
    assert!(report
        .final_binding_error
        .unwrap()
        .is("TEST_DESCRIPTOR_CHANGED"));
    assert!(report.maintenance_error.unwrap().is("TEST_GUARD_CHANGED"));
}

#[test]
fn preflight_refusal_has_no_command_effects_and_expired_deadline_refuses() {
    let report = finish(
        receipt(),
        Err(err!(EACCES, "TEST_PREFLIGHT_REFUSED")),
        Ok(()),
        Ok(()),
    );
    assert!(
        !report.successful
            && !report.receipt.bootstrap_attempted
            && !report.receipt.uncertain_command_effects
    );
    assert!(deadline(Instant::now())
        .unwrap_err()
        .is("DEPLOYMENT_INTENT_TIMEOUT"));
    deadline(Instant::now() + Duration::from_secs(1)).unwrap();
}

#[cfg(not(target_os = "macos"))]
#[test]
fn unavailable_native_session_never_returns_a_mock_console_identity() {
    assert!(current_session()
        .unwrap_err()
        .is("DEPLOYMENT_INTENT_NATIVE_REQUIRED"));
}

// Actual root filesystem fixtures are deliberately separate from ordinary unit
// acceptance. They never select a deployment, acquire native maintenance, run a
// command or claim installed/root/Aqua authority. Coordinator executes explicitly.
struct RootFixture {
    base: PathBuf,
}
impl RootFixture {
    fn new() -> Self {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "actual private root fixture required"
        );
        let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
        std::fs::create_dir_all(&parent).unwrap();
        let base = parent.join(format!(
            "intent-start-root-{}",
            hex::encode(enclave_core::rng::bytes32())
        ));
        std::fs::create_dir(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            base: base.canonicalize().unwrap(),
        }
    }
    fn file(&self, name: &str, value: &[u8]) -> PathBuf {
        let path = self.base.join(name);
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o644)
            .open(&path)
            .unwrap();
        use std::io::Write;
        file.write_all(value).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        path
    }
}
impl Drop for RootFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

#[test]
#[ignore = "requires actual protected private-root filesystem"]
fn held_selected_input_rejects_content_replacement_symlink_hardlink_and_writable_ancestor() {
    let fixture = RootFixture::new();
    let path = fixture.file("authority.json", b"original");
    let mut paths = HeldPaths::new().unwrap();
    let (held, bytes) = HeldFile::open(&mut paths, &path, MAX_PUBLIC, Some(0o644)).unwrap();
    assert_eq!(bytes, b"original");
    held.revalidate(&paths).unwrap();
    std::fs::write(&path, b"modified").unwrap();
    assert!(held.revalidate(&paths).is_err());
    let alias = fixture.base.join("alias.json");
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    assert!(HeldFile::open(&mut paths, &alias, MAX_PUBLIC, None).is_err());
    std::fs::remove_file(&alias).unwrap();
    std::fs::hard_link(&path, &alias).unwrap();
    assert!(HeldFile::open(&mut paths, &path, MAX_PUBLIC, None).is_err());
    std::fs::remove_file(&alias).unwrap();
    let (fresh, _) = HeldFile::open(&mut paths, &path, MAX_PUBLIC, None).unwrap();
    std::fs::rename(&path, fixture.base.join("old.json")).unwrap();
    fixture.file("authority.json", b"modified");
    assert!(fresh.revalidate(&paths).is_err());
    std::fs::set_permissions(&fixture.base, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(paths.revalidate().is_err());
}

#[test]
#[ignore = "requires actual protected private-root filesystem"]
fn absent_or_wrong_existing_console_child_refuses_without_create_or_permission_repair() {
    let fixture = RootFixture::new();
    let missing = fixture.base.join("501");
    let mut paths = HeldPaths::new().unwrap();
    assert!(paths
        .hold_directory(&missing, Some((501, 8703, 0o2710)))
        .is_err());
    assert!(!missing.exists());
    std::fs::create_dir(&missing).unwrap();
    std::fs::set_permissions(&missing, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(paths
        .hold_directory(&missing, Some((501, 8703, 0o2710)))
        .unwrap_err()
        .is("DEPLOYMENT_LIFECYCLE_RUNTIME_IDENTITY"));
    let value = std::fs::metadata(&missing).unwrap();
    assert_eq!(
        (value.uid(), value.gid(), value.mode() & 0o7777),
        (0, 0, 0o700)
    );
}

#[test]
#[ignore = "requires actual protected private-root filesystem and distinct UID/GID ownership"]
fn exact_console_child_ownership_is_retained_and_replacement_denied() {
    let fixture = RootFixture::new();
    let child = fixture.base.join("501");
    std::fs::create_dir(&child).unwrap();
    let name = CString::new(child.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::chown(name.as_ptr(), 501, 8703) }, 0);
    std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o2710)).unwrap();
    let observed = std::fs::symlink_metadata(&child).unwrap();
    assert!(
        observed.is_dir(),
        "FIXTURE_DISTINCT_UID_GID_UNAVAILABLE: child is not a directory"
    );
    assert_eq!((observed.uid(),observed.gid(),observed.mode()&0o7777),(501,8703,0o2710),
        "FIXTURE_DISTINCT_UID_GID_UNAVAILABLE: syscall success did not establish actual requested metadata; production acceptance remains UNEXERCISED");
    let mut paths = HeldPaths::new().unwrap();
    paths
        .hold_directory(&child, Some((501, 8703, 0o2710)))
        .unwrap();
    paths.revalidate().unwrap();
    std::fs::rename(&child, fixture.base.join("old501")).unwrap();
    std::fs::create_dir(&child).unwrap();
    assert!(paths.revalidate().is_err());
}
