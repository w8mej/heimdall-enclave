//! Test-only evidence. No test helper changes admission or bucket state.
use std::{
    fs::OpenOptions,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

pub(crate) const SQ01: &[&str] = &[
    "signed_same_principal_two_holder_preconditions",
    "fifty_unique_calls_return_exact_data",
    "fifty_first_refuses_before_source",
    "fifty_first_certificate_still_has_credit",
    "independently_signed_other_principal_progresses",
    "exact_source_response_and_authorization_counts",
];
pub(crate) const SQ02: &[&str] = &[
    "deplete_fifty_with_certificate_headroom",
    "at_99ms_refuses_without_source",
    "at_100ms_one_call_succeeds",
    "at_199ms_refuses_without_source",
    "at_200ms_one_call_succeeds",
    "regressed_150ms_grants_no_credit",
    "at_1200ms_exactly_ten_calls_succeed",
    "same_1200ms_eleventh_refuses_with_certificate_credit",
];
pub(crate) const SQ03: &[&str] = &[
    "deplete_signed_principal_across_two_holders",
    "cloned_node_cannot_reset_debt",
    "fresh_channel_and_valid_pop_cannot_reset_debt",
    "signed_replacement_holder_cannot_reset_debt",
    "allowlisted_unregistered_holder_refuses_before_source",
    "separately_signed_principal_still_progresses",
    "all_quota_probes_have_unused_replay_identity",
    "all_quota_probes_have_certificate_credit",
];
pub(crate) const SQ04: &[&str] = &[
    "preconsume_49_with_certificate_headroom",
    "distinct_holder_calls_cross_explicit_barrier",
    "exactly_one_data_source_and_one_unavailable",
    "exact_losing_request_succeeds_after_100ms",
    "unrelated_signed_principal_progresses",
    "exact_source_response_counts_and_joined_workers",
];
pub(crate) const SQ05: &[&str] = &[
    "valid_signed_policy_has_exactly_1024_members",
    "actual_dispatch_populates_1024_principal_entries",
    "certificate_and_source_counts_prove_nonvacuous_fill",
    "higher_signed_revision_replaces_member_reusing_holder",
    "new_current_principal_at_0ms_refuses_without_growth",
    "existing_current_principal_progresses_with_full_map",
    "new_current_principal_at_99ms_still_refuses",
    "at_100ms_eligible_replenished_entries_are_reclaimed",
    "active_current_principal_debt_and_1024_bound_survive",
    "new_and_existing_current_principals_make_positive_progress",
];
pub(crate) const SQ06: &[&str] = &[
    "wrong_issuer_refuses_before_source",
    "wrong_holder_refuses_before_source",
    "wrong_exporter_refuses_before_source",
    "wrong_namespace_refuses_before_source",
    "wrong_root_refuses_before_source",
    "expired_capability_refuses_before_source",
    "exact_replay_refuses_before_source",
    "healthy_actual_handler_controls_before_and_after_each_case",
];
pub(crate) const SQ07: &[&str] = &[
    "actual_pinned_tls_for_two_holders_of_one_principal",
    "actual_session_hello_exporter_and_distinct_valid_pop",
    "fifty_actual_received_data_frames_across_shared_principal",
    "fifty_first_holder_has_certificate_credit",
    "fifty_first_actual_unavailable_256_has_no_source_call",
    "fresh_tls_reconnect_same_principal_stays_depleted",
    "independent_signed_principal_receives_exact_payload_and_fin",
    "actual_source_data_and_unavailable_counts_match",
    "bounded_receiver_server_driver_and_child_teardown",
];

pub(crate) struct Run {
    pub(crate) fixture: PathBuf,
    evidence: PathBuf,
    outer: &'static str,
    expected: &'static [&'static str],
    completed: Vec<&'static str>,
    deadline: Instant,
    active: Arc<AtomicBool>,
    finished: bool,
}
fn private_directory(path: &Path) {
    std::fs::create_dir(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let meta = std::fs::symlink_metadata(path).unwrap();
    assert!(meta.is_dir() && !meta.file_type().is_symlink());
    assert_eq!(meta.uid(), enclave_core::ipc::geteuid());
    assert_eq!(meta.mode() & 0o7777, 0o700);
}
fn write_json(path: &Path, value: &serde_json::Value) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    assert!(bytes.len() <= 1024 * 1024);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    assert!(meta.is_file() && meta.nlink() == 1 && meta.uid() == enclave_core::ipc::geteuid());
    assert_eq!(meta.mode() & 0o7777, 0o600);
    file.write_all(&bytes)?;
    file.sync_all()
}
impl Run {
    pub(crate) fn new(
        outer: &'static str,
        expected: &'static [&'static str],
        seconds: u64,
    ) -> Self {
        assert!(!expected.is_empty());
        let root = PathBuf::from(
            std::env::var_os("depot_ADMISSION_BROKER_EVIDENCE_DIR")
                .expect("explicit owned quota evidence root"),
        );
        assert!(root.is_absolute());
        let meta = std::fs::symlink_metadata(&root).unwrap();
        assert!(meta.is_dir() && !meta.file_type().is_symlink());
        assert_eq!(meta.uid(), enclave_core::ipc::geteuid());
        assert_eq!(meta.mode() & 0o7777, 0o700);
        assert_eq!(root.canonicalize().unwrap(), root);
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .canonicalize()
            .unwrap();
        assert_eq!(root.parent(), Some(repository.join("target").as_path()));
        let name = root.file_name().unwrap().to_str().unwrap();
        assert!(
            name.starts_with("sq-evidence-")
                && name.len() <= 128
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        );
        let evidence = root.join(format!(
            "sq-{}-{:016x}",
            &blake3::hash(outer.as_bytes()).to_hex()[..16],
            enclave_core::rng::u64()
        ));
        private_directory(&evidence);
        let fixture = PathBuf::from("/tmp").join(format!("mcsq-{:016x}", enclave_core::rng::u64()));
        private_directory(&fixture);
        let fixture_meta = std::fs::symlink_metadata(&fixture).unwrap();
        write_json(&evidence.join("fixture-created.json"),&serde_json::json!({
            "owned_fixture_path":fixture,"uid":fixture_meta.uid(),"dev":fixture_meta.dev(),
            "ino":fixture_meta.ino(),"mode":fixture_meta.mode()&0o7777,
            "failure_policy":"retain exact owned path and failed evidence; no success cleanup claim"
        })).unwrap();
        let deadline = Instant::now() + Duration::from_secs(seconds);
        let active = Arc::new(AtomicBool::new(true));
        let watched = active.clone();
        std::thread::spawn(move || {
            std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
            if watched.load(Ordering::SeqCst) {
                eprintln!("SQ_OWNED_OUTER_DEADLINE");
                unsafe { libc::_exit(124) }
            }
        });
        Self {
            fixture,
            evidence,
            outer,
            expected,
            completed: Vec::new(),
            deadline,
            active,
            finished: false,
        }
    }
    pub(crate) fn complete(&mut self, case: &'static str, observation: serde_json::Value) {
        assert!(Instant::now() < self.deadline);
        assert!(self.expected.contains(&case) && !self.completed.contains(&case));
        assert!(
            !case.is_empty()
                && case.len() <= 128
                && case.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        );
        write_json(&self.evidence.join(format!("{case}.json")), &observation).unwrap();
        self.completed.push(case);
    }
    pub(crate) fn progress(&self, name: &str, observation: serde_json::Value) {
        assert!(Instant::now() < self.deadline);
        assert!(
            !name.is_empty()
                && name.len() <= 128
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        );
        write_json(&self.evidence.join(format!("{name}.json")), &observation).unwrap();
    }
    fn receipt(&self, status: &str) -> serde_json::Value {
        serde_json::json!({"schema":1,"outer_test":self.outer,"status":status,"expected_subcases":self.expected,"completed_subcases":self.completed,"children":[]})
    }
    pub(crate) fn finish(&mut self) {
        assert!(Instant::now() < self.deadline);
        let mut actual = self.completed.clone();
        actual.sort();
        let mut expected = self.expected.to_vec();
        expected.sort();
        assert_eq!(actual, expected);
        std::fs::remove_dir_all(&self.fixture)
            .expect("owned ephemeral fixture cleanup before PASS");
        assert!(
            matches!(std::fs::symlink_metadata(&self.fixture),Err(error) if error.kind()==std::io::ErrorKind::NotFound)
        );
        write_json(&self.evidence.join("fixture-cleaned.json"),&serde_json::json!({"owned_fixture_path":self.fixture,"actual_absence_after_cleanup":true})).unwrap();
        write_json(
            &self.evidence.join("outer-receipt.json"),
            &self.receipt("PASS"),
        )
        .unwrap();
        self.finished = true;
        self.active.store(false, Ordering::SeqCst);
    }
}
impl Drop for Run {
    fn drop(&mut self) {
        self.active.store(false, Ordering::SeqCst);
        if !self.finished {
            let _ = write_json(
                &self.evidence.join("outer-receipt.json"),
                &self.receipt("FAIL"),
            );
        }
    }
}
