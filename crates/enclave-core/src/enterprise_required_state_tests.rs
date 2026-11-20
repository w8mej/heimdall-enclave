//! Actual required-opener persistence regressions with explicit synthetic
//! issuer authority. No injected authority struct or installed identity claim.
use super::*;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

const NOW: i64 = 1_800_000_000;
fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}
fn policy() -> EnterprisePolicy {
    EnterprisePolicy {
        version: 1,
        revision: 1,
        trust_domain: "required.example".into(),
        issued_unix: NOW - 1,
        expires_unix: NOW + 3600,
        members: vec![EnterpriseMember {
            principal: "spiffe://required.example/engineer/alice".into(),
            generation: 1,
            holder_public_keys: vec![hex::encode(key(2).verifying_key().as_bytes())],
            namespaces: vec!["models".into()],
        }],
    }
}

struct Fixture {
    directory: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        // The repository may have writable ancestors. Test the real strict
        // opener under a genuinely private trusted temporary path instead.
        let directory = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "depot-enterprise-required-{}-{}",
            std::process::id(),
            crate::rng::u64()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let fixture = Self { directory };
        fixture.write_policy(policy(), 1);
        fixture
    }
    fn state(&self) -> PathBuf {
        self.directory.join("state")
    }
    fn config(&self, issuer: u8) -> AuthorityConfig {
        AuthorityConfig {
            issuer_public_key_hex: hex::encode(key(issuer).verifying_key().as_bytes()),
            policy_path: self.directory.join("policy.json"),
        }
    }
    fn write_policy(&self, policy: EnterprisePolicy, issuer: u8) {
        let bytes =
            serde_json::to_vec(&SignedEnterprisePolicy::sign(policy, &key(issuer)).unwrap())
                .unwrap();
        std::fs::write(self.config(issuer).policy_path, bytes).unwrap();
        std::fs::set_permissions(
            self.config(issuer).policy_path,
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    fn open(&self, issuer: u8) -> EnclaveResult<Arc<EnterpriseAuthority>> {
        EnterpriseAuthority::open(self.config(issuer), &self.state())
    }
    fn files(&self) -> [Option<Vec<u8>>; 3] {
        [
            "sealing.key",
            "enterprise-authority.sealed",
            "enterprise-authority.gen",
        ]
        .map(|name| match std::fs::read(self.state().join(name)) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("reading owned fixture {name}: {error}"),
        })
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn enterprise_required_state_first_open_is_durable_before_first_refresh() {
    let fixture = Fixture::new();
    let authority = fixture.open(1).unwrap();
    assert_eq!(authority.current.lock().unwrap().watermark.revision, 0);
    assert!(!authority.current.lock().unwrap().available);
    let files = fixture.files();
    assert!(files.iter().all(Option::is_some));
    drop(authority); // No refresh/authorization occurred before this restart.
    let authority = fixture.open(1).unwrap();
    assert_eq!(
        fixture.files(),
        files,
        "opening valid state must not reset/rewrite floors"
    );
    assert_eq!(authority.current.lock().unwrap().watermark.revision, 0);
    let lease = authority
        .authorize(&key(2).verifying_key().to_bytes(), "models", NOW)
        .unwrap();
    assert_eq!(lease.generation, 1);
    assert_eq!(authority.current.lock().unwrap().watermark.revision, 1);
}

#[test]
fn enterprise_required_state_each_partial_loss_refuses_without_recreating_authority() {
    for missing in ["state", "checkpoint", "both"] {
        let fixture = Fixture::new();
        let mut newer = policy();
        newer.revision = 7;
        newer.members[0].generation = 3;
        fixture.write_policy(newer, 1);
        let authority = fixture.open(1).unwrap();
        authority
            .authorize(&key(2).verifying_key().to_bytes(), "models", NOW + 600)
            .unwrap();
        drop(authority);
        if missing != "checkpoint" {
            std::fs::remove_file(fixture.state().join("enterprise-authority.sealed")).unwrap();
        }
        if missing != "state" {
            std::fs::remove_file(fixture.state().join("enterprise-authority.gen")).unwrap();
        }
        // The old still-valid signed policy must not be able to initialize a
        // replacement floor after this partial loss.
        fixture.write_policy(policy(), 1);
        let retained = fixture.files();
        assert!(retained[0].is_some());
        for _ in 0..2 {
            let error = fixture.open(1).unwrap_err();
            assert!(
                error.is(if missing == "checkpoint" {
                    "STATE_ROLLBACK"
                } else {
                    "STATE_MISSING"
                }),
                "{missing}: {error}"
            );
            assert_eq!(
                fixture.files(),
                retained,
                "{missing}: refusal changed persistence"
            );
        }
    }
}

#[test]
fn enterprise_required_state_seed_only_interruption_refuses_without_default_save() {
    let fixture = Fixture::new();
    let (store, loaded) =
        SealedStore::open_bounded(&fixture.state(), "enterprise-authority", 1024 * 1024).unwrap();
    assert!(matches!(loaded, Loaded::Fresh));
    drop(store); // Interrupt before the required authority's initial save.
    let retained = fixture.files();
    assert!(retained[0].is_some());
    assert!(retained[1].is_none() && retained[2].is_none());
    for _ in 0..2 {
        assert!(fixture.open(1).unwrap_err().is("STATE_MISSING"));
        assert_eq!(fixture.files(), retained);
    }
}

#[test]
fn enterprise_required_state_restart_preserves_revision_issuer_generation_and_clock() {
    let fixture = Fixture::new();
    let holder = key(2).verifying_key().to_bytes();
    let mut current = policy();
    current.revision = 7;
    current.members[0].generation = 2;
    fixture.write_policy(current.clone(), 1);
    let authority = fixture.open(1).unwrap();
    let retired_lease = authority.authorize(&holder, "models", NOW).unwrap();
    let mut removed = current.clone();
    removed.revision = 8;
    removed.members.clear();
    fixture.write_policy(removed, 1);
    authority.refresh(NOW + 1).unwrap();
    drop(authority);

    let authority = fixture.open(1).unwrap();
    current.revision = 9;
    fixture.write_policy(current.clone(), 1);
    assert!(authority
        .authorize(&holder, "models", NOW + 2)
        .unwrap_err()
        .is("ENTERPRISE_GENERATION_ROLLBACK"));
    current.members[0].generation = 3;
    fixture.write_policy(current.clone(), 1);
    let replacement = authority.authorize(&holder, "models", NOW + 2).unwrap();
    assert_eq!(replacement.principal, retired_lease.principal);
    assert_eq!(replacement.generation, 3);
    drop(authority);

    let authority = fixture.open(1).unwrap();
    let mut older = current.clone();
    older.revision = 8;
    fixture.write_policy(older, 1);
    assert!(authority
        .authorize(&holder, "models", NOW + 3)
        .unwrap_err()
        .is("ENTERPRISE_POLICY_ROLLBACK"));
    let mut equivocation = current.clone();
    equivocation.expires_unix += 1;
    fixture.write_policy(equivocation, 1);
    assert!(authority
        .authorize(&holder, "models", NOW + 3)
        .unwrap_err()
        .is("ENTERPRISE_POLICY_ROLLBACK"));
    drop(authority);

    // A configured issuer rekey is not permitted to equivocate at revision 9.
    fixture.write_policy(current.clone(), 9);
    let authority = fixture.open(9).unwrap();
    assert!(authority
        .authorize(&holder, "models", NOW + 3)
        .unwrap_err()
        .is("ENTERPRISE_POLICY_ROLLBACK"));
    current.revision = 10;
    fixture.write_policy(current.clone(), 9);
    authority.authorize(&holder, "models", NOW + 300).unwrap();
    drop(authority);

    let authority = fixture.open(9).unwrap();
    assert!(authority
        .authorize(&holder, "models", NOW + 299)
        .unwrap_err()
        .is("ENTERPRISE_POLICY_ROLLBACK"));
    authority.authorize(&holder, "models", NOW + 301).unwrap();
    assert!(authority.revalidate(&retired_lease, NOW + 301).is_err());
    let state = authority.current.lock().unwrap();
    assert_eq!(state.watermark.revision, 10);
    assert_eq!(
        state.watermark.issuer_public_key_hex,
        hex::encode(key(9).verifying_key().as_bytes())
    );
    assert_eq!(
        state.watermark.member_generations[&replacement.principal],
        3
    );
    assert_eq!(state.persisted_wall, NOW + 300);
}

#[test]
fn enterprise_required_state_legacy_bounded_format_and_one_mib_cap_remain_compatible() {
    let fixture = Fixture::new();
    let mut accepted = policy();
    accepted.revision = 7;
    accepted.members[0].generation = 3;
    fixture.write_policy(accepted.clone(), 1);
    // Legacy-format fixture only: the authority under test is always opened
    // through its actual public strict entrypoint below, never injected.
    let mut generations = BTreeMap::new();
    generations.insert(accepted.members[0].principal.clone(), 3);
    let watermark = Watermark {
        revision: 7,
        digest: hex::encode(blake3::hash(&crate::jcs::to_jcs_bytes(&accepted).unwrap()).as_bytes()),
        last_wall: NOW,
        issuer_public_key_hex: hex::encode(key(1).verifying_key().as_bytes()),
        member_generations: generations,
        active_members: accepted.members.clone(),
    };
    let (mut legacy, _) =
        SealedStore::open_bounded(&fixture.state(), "enterprise-authority", 1024 * 1024).unwrap();
    legacy.save_json(&watermark).unwrap();
    drop(legacy);
    let retained = fixture.files();
    let authority = fixture.open(1).unwrap();
    assert_eq!(fixture.files(), retained);
    assert_eq!(
        authority
            .authorize(&key(2).verifying_key().to_bytes(), "models", NOW)
            .unwrap()
            .generation,
        3
    );
    assert_eq!(
        fixture.files(),
        retained,
        "same accepted policy must not reset persistence on open/refresh"
    );
    drop(authority);
    let path = fixture.state().join("enterprise-authority.sealed");
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_len(1024 * 1024 + 1)
        .unwrap();
    assert!(fixture.open(1).unwrap_err().is("STATE_FILE_BOUNDS"));
}

#[test]
fn enterprise_required_state_initial_save_failure_never_returns_usable_authority() {
    const CHILD_DIRECTORY: &str = "depot_TEST_ENTERPRISE_REQUIRED_SAVE_FAILURE";
    if let Some(directory) = std::env::var_os(CHILD_DIRECTORY) {
        // Only the isolated child changes its file-size limit or SIGXFSZ policy.
        let directory = PathBuf::from(directory);
        let config = AuthorityConfig {
            issuer_public_key_hex: hex::encode(key(1).verifying_key().as_bytes()),
            policy_path: directory.join("policy.json"),
        };
        let mut original = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, original.as_mut_ptr()) },
            0
        );
        let original = unsafe { original.assume_init() };
        let previous_signal = unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_IGN) };
        let limited = libc::rlimit {
            rlim_cur: 32,
            rlim_max: original.rlim_max,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &limited) }, 0);
        let result = EnterpriseAuthority::open(config.clone(), &directory.join("state"));
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &original) }, 0);
        unsafe {
            libc::signal(libc::SIGXFSZ, previous_signal);
        }
        assert!(result.unwrap_err().is("STATE_WRITE"));
        let seed = std::fs::read(directory.join("state/sealing.key")).unwrap();
        assert_eq!(seed.len(), 32);
        assert!(!directory.join("state/enterprise-authority.sealed").exists());
        assert!(!directory.join("state/enterprise-authority.gen").exists());
        assert!(EnterpriseAuthority::open(config, &directory.join("state"))
            .unwrap_err()
            .is("STATE_MISSING"));
        assert_eq!(
            std::fs::read(directory.join("state/sealing.key")).unwrap(),
            seed
        );
        println!("EXPECTED_ENTERPRISE_INITIAL_SAVE_FAILURE_WITH_NO_AUTHORITY");
        return;
    }
    let fixture = Fixture::new();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "enterprise_authority::required_state_tests::enterprise_required_state_initial_save_failure_never_returns_usable_authority", "--nocapture"])
        .env(CHILD_DIRECTORY, &fixture.directory)
        .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "initial-save failure child exceeded ten seconds: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout)
        .contains("EXPECTED_ENTERPRISE_INITIAL_SAVE_FAILURE_WITH_NO_AUTHORITY"));
    let retained = fixture.files();
    assert!(retained[0].is_some());
    assert!(retained[1].is_none() && retained[2].is_none());
}
