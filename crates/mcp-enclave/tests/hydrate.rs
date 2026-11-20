//! Authenticated hydration over actual TUF+CAS IPC. Fixture authority is local
//! and explicit; it is not a production publisher or hardware assurance claim.
use enclave_core::{ipc::PeerCredentials, profile::Profile};
use enclave_swarm_syncd::service::{CasConfig, CasRequest, CasResponse, CasService};
use mcp_enclave::deploy::{
    EXIT_HYDRATION_FAILED, EXIT_HYDRATION_PENDING, EXIT_INSTALL_FAILED, EXIT_SUCCESS,
};
use mcp_enclave::{
    ctl::Env,
    deploy::hydrate::{
        run_hydrate, run_hydrate_worker, run_worker_job_with_env, HydrationJob, HydrationStatus,
    },
    devtuf::DevRepo,
};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

struct Fixture {
    base: PathBuf,
    env: Env,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Fixture {
    fn new(payload: &[u8]) -> Self {
        use std::os::unix::fs::DirBuilderExt;
        // Darwin's user TMPDIR plus the former 64-hex prefix exceeded sun_path
        // before any hydration assertion ran. Use an exclusive private directory
        // under the short system temporary prefix, retaining 128 random bits.
        let base = PathBuf::from("/tmp").join(format!(
            "mcpmac-hy-{}",
            hex::encode(&enclave_core::rng::bytes32()[..16])
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        // Resolve Darwin's /tmp alias only for this already-created private
        // fixture. Production authority traversal keeps refusing symlinks.
        let base = base.canonicalize().unwrap();
        let env = Env::dev(&base, Profile::L1);
        let repo = base.join("repo");
        let store = base.join("store");
        std::fs::create_dir_all(&store).unwrap();
        let mut authority = DevRepo::open_with_keys(&base.join("keys.json"), &repo).unwrap();
        authority
            .add_target("test-model", payload, serde_json::json!({}))
            .unwrap();
        std::fs::write(store.join("test-model"), payload).unwrap();
        let svc = CasService::start(CasConfig {dev_same_uid: true,
            profile: Profile::L1,
            store_dir: store,
            audit_path: None,
            ohttp_gateway: None,
            tuf_root: Some(std::fs::read(repo.join("root.json")).unwrap()),
            state_dir: Some(base.join("state")),
            revocation: enclave_swarm_syncd::revocation::Enforcement::InProcess,
        })
        .unwrap();
        svc.handle(
            &PeerCredentials::local(0, 0),
            CasRequest::TufRefresh {
                roots: vec![],
                timestamp: std::fs::read(repo.join("timestamp.json")).unwrap().into(),
                snapshot: std::fs::read(repo.join("snapshot.json")).unwrap().into(),
                targets: std::fs::read(repo.join("targets.json")).unwrap().into(),
            },
        )
        .unwrap();
        let dir = env.socket_dir.join("cas");
        std::fs::create_dir_all(&dir).unwrap();
        let listener = enclave_core::ipc::bind(
            &dir.join("cas.sock"),
            enclave_core::ipc::SocketAccess::OwnerOnly,
        )
        .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = std::thread::spawn(move || {
            enclave_core::ipc::serve::<CasRequest, CasResponse, _>(
                listener,
                enclave_core::ipc::PeerPolicy::allow([enclave_core::ipc::geteuid()]),
                Arc::new(move |p: &PeerCredentials, r| svc.handle(p, r)),
                flag,
            )
            .unwrap()
        });
        Self {
            base,
            env,
            stop,
            thread: Some(thread),
        }
    }
    fn job(&self) -> HydrationJob {
        HydrationJob {
            job_id: "test-job".into(),
            target: "test-model".into(),
            profile: "L1".into(),
            created_at: 1,
            source: "r2".into(),
            dmg_path: None,
        }
    }
    fn run(&self, job: &HydrationJob) -> (i32, String, serde_json::Value) {
        run_worker_job_with_env(
            job,
            &self.base.join("jobs"),
            &self.base.join("cas"),
            &self.env,
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

#[test]
fn authenticated_job_lifecycle_and_status_schema() {
    let payload = b"genuine signed test artifact, not synthesized by worker";
    let f = Fixture::new(payload);
    let jobs = f.base.join("jobs");
    let cas = f.base.join("cas");
    let started = std::time::Instant::now();
    let (code, _, details) = run_hydrate(
        "L1",
        Some("test-model"),
        None,
        true,
        Some(&jobs),
        Some(&cas),
    );
    assert_eq!(code, EXIT_HYDRATION_PENDING);
    assert!(started.elapsed().as_secs_f64() < 2.0);
    assert_eq!(details["status"], "pending");
    let job: HydrationJob =
        serde_json::from_slice(&std::fs::read(jobs.join("hydration.json")).unwrap()).unwrap();
    let (code, _, details) = f.run(&job);
    assert_eq!(code, EXIT_SUCCESS, "{details}");
    assert_eq!(details["status"], "completed");
    assert_eq!(details["bytes_synced"], payload.len());
    assert_eq!(details["percent"], 100.0);
    assert_eq!(
        std::fs::read(cas.join("models/test-model")).unwrap(),
        payload
    );
    assert_eq!(
        details["bao_root"],
        enclave_swarm_syncd::bao::bao_root(payload)
    );
    let status: HydrationStatus =
        serde_json::from_slice(&std::fs::read(jobs.join("hydration-status.json")).unwrap())
            .unwrap();
    assert_eq!(status.status, "completed");
    assert!(!jobs.join("hydration.json").exists());
}

#[test]
fn tampered_source_fails_then_retry_repairs_untrusted_cache() {
    let payload = b"TAMPERED_PAYLOAD is allowed when authentic publisher signed these exact bytes";
    let f = Fixture::new(payload);
    let job = f.job();
    std::fs::write(f.base.join("store/test-model"), b"unapproved payload").unwrap();
    let (code, _, details) = f.run(&job);
    assert_eq!(code, EXIT_HYDRATION_FAILED);
    assert_eq!(details["status"], "failed");
    assert_eq!(details["bytes_synced"], 0);
    assert!(!f.base.join("cas/models/test-model").exists());
    // A retry uses actual authenticated data, and cache corruption is not resume authority.
    std::fs::write(f.base.join("store/test-model"), payload).unwrap();
    assert_eq!(f.run(&job).0, EXIT_SUCCESS);
    std::fs::write(f.base.join("cas/models/test-model"), b"corrupt cache").unwrap();
    assert_eq!(f.run(&job).0, EXIT_SUCCESS);
    assert_eq!(
        std::fs::read(f.base.join("cas/models/test-model")).unwrap(),
        payload
    );
}

#[test]
fn unavailable_authority_does_not_fabricate_completion() {
    let f = Fixture::new(b"real artifact");
    let jobs = f.base.join("jobs");
    run_hydrate(
        "L1",
        Some("test-model"),
        None,
        true,
        Some(&jobs),
        Some(&f.base.join("cas")),
    );
    // Production worker must not use development environment as implicit authority.
    let (code, _, details) = run_hydrate_worker(Some(&jobs), Some(&f.base.join("cas")));
    assert_eq!(code, EXIT_HYDRATION_FAILED);
    assert_eq!(details["status"], "failed");
    assert_eq!(details["bytes_synced"], 0);
}

#[test]
fn l3_requires_team_id_and_rejects_traversal() {
    let f = Fixture::new(b"payload");
    std::env::remove_var("MCPMAC_L3_ADHOC_DEV");
    let (code, _, details) = run_hydrate(
        "L3",
        Some("test-model"),
        None,
        true,
        Some(&f.base.join("jobs")),
        Some(&f.base.join("cas")),
    );
    if enclave_core::codesign::signing_mode() != enclave_core::codesign::SigningMode::TeamId {
        assert_eq!(code, EXIT_INSTALL_FAILED);
        assert_eq!(details["error"], "L3_REQUIRES_TEAM_ID");
    }
    for target in ["../test", "a/b", "a\\b", ""] {
        assert_eq!(
            run_hydrate(
                "L1",
                Some(target),
                None,
                false,
                Some(&f.base.join("jobs")),
                Some(&f.base.join("cas"))
            )
            .0,
            EXIT_HYDRATION_FAILED
        );
    }
}

#[test]
#[cfg(not(target_os = "macos"))]
fn dmg_import_is_not_reported_as_run_on_linux() {
    let f = Fixture::new(b"payload");
    let mut job = f.job();
    job.source = "dmg".into();
    job.dmg_path = Some("ordinary-name.dmg".into());
    let (code, message, _) = f.run(&job);
    assert_eq!(code, EXIT_HYDRATION_FAILED);
    assert!(message.contains("DMG_IMPORT_NOT_RUN"));
}

#[test]
#[ignore = "requires root; execute explicitly with --ignored for cross-UID evidence"]
fn root_publication_is_readable_and_status_writable_by_actual_worker_uid() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::process::CommandExt;
    if enclave_core::ipc::geteuid() != 0 {
        panic!("BLOCKED: run this cross-UID regression as root; no native hardware claim");
    }
    let base = std::env::temp_dir().join(format!(
        "mcpmac-hydration-uids-{}",
        hex::encode(enclave_core::rng::bytes32())
    ));
    std::fs::create_dir(&base).unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
    let jobs = base.join("jobs");
    std::fs::create_dir(&jobs).unwrap();
    let path = std::ffi::CString::new(jobs.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::chown(path.as_ptr(), 702, 8702) }, 0);
    std::fs::set_permissions(&jobs, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        run_hydrate(
            "L1",
            Some("test-model"),
            None,
            true,
            Some(&jobs),
            Some(&base.join("cas"))
        )
        .0,
        EXIT_HYDRATION_PENDING
    );
    for name in ["hydration.json", "hydration-status.json"] {
        let m = std::fs::metadata(jobs.join(name)).unwrap();
        assert_eq!((m.uid(), m.gid(), m.mode() & 0o777), (702, 8702, 0o600));
    }
    let run_as = |uid, gid| {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_mcp-enclave"));
        command
            .args([
                "--profile",
                "L1",
                "--json",
                "deploy",
                "hydrate-worker",
                "--jobs-dir",
            ])
            .arg(&jobs)
            .arg("--cas-dir")
            .arg(base.join("cas"));
        // Clear inherited root groups before dropping to the actual daemon UID.
        unsafe {
            command.pre_exec(move || {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(gid) != 0
                    || libc::setuid(uid) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command.output().unwrap()
    };
    let denied = run_as(701, 8701);
    assert_ne!(denied.status.code(), Some(EXIT_SUCCESS));
    let output = run_as(702, 8702);
    assert_eq!(
        output.status.code(),
        Some(EXIT_HYDRATION_FAILED),
        "{:?}",
        output
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        result["summary"]
            .as_str()
            .unwrap()
            .contains("AUTHENTICATED_TARGET_UNAVAILABLE"),
        "{result}"
    );
    let status: HydrationStatus =
        serde_json::from_slice(&std::fs::read(jobs.join("hydration-status.json")).unwrap())
            .unwrap();
    assert_eq!(status.status, "failed");
    assert!(status
        .error
        .unwrap()
        .contains("AUTHENTICATED_TARGET_UNAVAILABLE"));
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn job_queue_rejects_symlinks_and_nonregular_files() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new(b"signed payload");
    let jobs = f.base.join("jobs");
    std::fs::create_dir(&jobs).unwrap();
    symlink(f.base.join("store/test-model"), jobs.join("hydration.json")).unwrap();
    assert_eq!(
        run_hydrate_worker(Some(&jobs), Some(&f.base.join("cas"))).2["error"],
        "JOB_READ_ERROR"
    );
    std::fs::remove_file(jobs.join("hydration.json")).unwrap();
    let fifo = std::ffi::CString::new(jobs.join("hydration.json").to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let started = std::time::Instant::now();
    assert_eq!(
        run_hydrate_worker(Some(&jobs), Some(&f.base.join("cas"))).2["error"],
        "JOB_READ_ERROR"
    );
    assert!(started.elapsed().as_secs() < 1);
}

#[test]
#[cfg(target_os = "macos")]
fn dmg_content_compared_to_tuf_and_detached_on_success_and_failure() {
    let payload = b"authenticated model weight test payload";
    let f = Fixture::new(payload);
    let src = f.base.join("src");
    std::fs::create_dir(&src).unwrap();
    let mut corrupt = payload.to_vec();
    corrupt[0] ^= 1;
    for (name, bytes, expected) in [
        ("tampered-in-name.dmg", payload.as_slice(), EXIT_SUCCESS),
        ("ordinary-name.dmg", corrupt.as_slice(), EXIT_HYDRATION_FAILED),
        (
            "ordinary-short-payload.dmg",
            b"wrong unsigned payload".as_slice(),
            EXIT_HYDRATION_FAILED,
        ),
    ] {
        std::fs::write(src.join("model.safetensors"), bytes).unwrap();
        let image = f.base.join(name);
        assert!(std::process::Command::new("/usr/bin/hdiutil")
            .args(["create", "-size", "4m", "-fs", "HFS+", "-srcfolder"])
            .arg(&src)
            .arg(&image)
            .status()
            .unwrap()
            .success());
        let mut job = f.job();
        job.source = "dmg".into();
        job.dmg_path = Some(image.display().to_string());
        let (code, _, details) = f.run(&job);
        assert_eq!(code, expected, "{details}");
        if name == "ordinary-name.dmg" {
            assert_eq!(details["error"], "TUF_MODEL_CONTENT_MISMATCH", "same-length corruption must reach independently authenticated byte comparison");
            assert_eq!(details["bytes_synced"], 0);
        }
        assert_eq!(std::fs::read(f.base.join("cas/models/test-model")).unwrap(), payload,
            "successful import installs actual authenticated bytes; later failures cannot replace them");
        let info = std::process::Command::new("/usr/bin/hdiutil")
            .args(["info", "-plist"])
            .output()
            .unwrap();
        assert!(info.status.success(), "detach observation failed: {info:?}");
        assert!(
            !String::from_utf8_lossy(&info.stdout).contains(image.to_str().unwrap()),
            "image must be detached"
        );
    }
}
