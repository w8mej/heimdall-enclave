//! Model weight hydration and asynchronous MDM detachment orchestration (FS-706 §3, D-R3, D-R8).

use std::path::Path;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::deploy::{
    EXIT_HYDRATION_FAILED, EXIT_HYDRATION_PENDING, EXIT_INSTALL_FAILED, EXIT_SUCCESS,
};

/// Job descriptor conforming to `schemas/hydration-job.schema.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HydrationJob {
    /// Unique identifier for this hydration task.
    pub job_id: String,
    /// Model target artifact slug from enclave.lock.toml.
    pub target: String,
    /// Deployment profile tier governing transport.
    pub profile: String,
    /// Unix timestamp in seconds when the job was dispatched.
    pub created_at: u64,
    /// Transport source used for hydration.
    pub source: String,
    /// Optional filesystem path to pre-staged DMG image for Profile L3.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dmg_path: Option<String>,
}

/// Status descriptor conforming to `schemas/hydration-status.schema.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HydrationStatus {
    /// Unique identifier of the corresponding hydration job.
    pub job_id: String,
    /// Model target artifact slug.
    pub target: String,
    /// Deployment profile tier.
    pub profile: String,
    /// Current lifecycle status of the hydration process.
    pub status: String,
    /// Number of bytes downloaded and verified so far.
    pub bytes_synced: u64,
    /// Total size in bytes of the target model artifact.
    pub bytes_total: u64,
    /// Progress percentage (0.0 to 100.0).
    pub percent: f64,
    /// Verified BLAKE3 Bao Merkle tree root hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bao_root: Option<String>,
    /// Error diagnostic message if status is failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Total elapsed time in milliseconds.
    pub elapsed_ms: u64,
}

/// Helper to remove quarantine extended attribute only after cryptographic verification (Prompt 4).
#[cfg(target_os = "macos")]
pub fn remove_quarantine_if_verified(path: &Path) {
    if path.exists() {
        let _ = crate::syscmd::command(crate::syscmd::Tool::Xattr)
            .args(["-d", "com.apple.quarantine", path.to_str().unwrap_or("")])
            .output();
    }
}

/// No-op on non-macOS platforms.
#[cfg(not(target_os = "macos"))]
pub fn remove_quarantine_if_verified(_path: &Path) {}

/// Validate target artifact slug to prevent path traversal (GAP-36).
pub fn validate_target_slug(target: &str) -> Result<(), &'static str> {
    if target.is_empty() || target.len() > 128 {
        return Err("target slug length must be between 1 and 128 characters");
    }
    if target.contains('/') || target.contains('\\') || target.contains("..") {
        return Err("target slug must not contain path traversal characters");
    }
    if !target
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(
            "target slug must contain only ASCII alphanumeric, hyphen, underscore, or period",
        );
    }
    Ok(())
}

/// Execute model weight hydration (synchronously or asynchronously).
pub fn run_hydrate(
    profile: &str,
    target: Option<&str>,
    dmg: Option<&str>,
    is_async: bool,
    jobs_dir_override: Option<&Path>,
    cas_dir_override: Option<&Path>,
) -> (i32, String, serde_json::Value) {
    let model_target = target.unwrap_or("llada-8b-instruct");
    if let Err(e) = validate_target_slug(model_target) {
        return (
            EXIT_HYDRATION_FAILED,
            format!("Invalid target slug: {e}"),
            json!({ "error": "INVALID_TARGET_SLUG", "target": model_target }),
        );
    }

    // Profile L3 requires Mode B (Apple Team ID) per D-R6
    if profile == "L3" {
        let has_team_id =
            enclave_core::codesign::signing_mode() == enclave_core::codesign::SigningMode::TeamId;
        let adhoc_dev =
            cfg!(debug_assertions) && std::env::var("MCPMAC_L3_ADHOC_DEV").as_deref() == Ok("1");
        if !has_team_id && !adhoc_dev {
            return (
                EXIT_INSTALL_FAILED,
                "Profile L3 strictly requires Mode B (Apple Team ID); ad-hoc Mode A refused in production builds (D-R6)".into(),
                json!({
                    "error": "L3_REQUIRES_TEAM_ID",
                    "profile": "L3",
                    "decision": "D-R6"
                }),
            );
        }
    }

    let default_jobs_dir = Path::new("/var/run/enclave/jobs");
    let jobs_dir = jobs_dir_override.unwrap_or(default_jobs_dir);

    let default_cas_dir = Path::new("/opt/enterprise/enclave/cas");
    let cas_dir = cas_dir_override.unwrap_or(default_cas_dir);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let source = if dmg.is_some() || profile == "L3" {
        "dmg"
    } else if profile == "L2" {
        "swarm"
    } else {
        "r2"
    };

    let job_id = format!("hyd-{now}");
    let job = HydrationJob {
        job_id: job_id.clone(),
        target: model_target.to_string(),
        profile: profile.to_string(),
        created_at: now,
        source: source.to_string(),
        dmg_path: dmg.map(|s| s.to_string()),
    };

    if is_async {
        // Two-phase detached pattern: write job descriptor and return < 5s to MDM
        if let Err(e) = std::fs::create_dir_all(jobs_dir) {
            return (
                EXIT_HYDRATION_FAILED,
                e.to_string(),
                json!({"error":"JOB_DIRECTORY"}),
            );
        }
        let job_file = jobs_dir.join("hydration.json");

        // Emit initial status file
        let initial_status = HydrationStatus {
            job_id: job_id.clone(),
            target: model_target.to_string(),
            profile: profile.to_string(),
            status: "pending".to_string(),
            bytes_synced: 0,
            bytes_total: 0,
            percent: 0.0,
            bao_root: None,
            error: None,
            elapsed_ms: 0,
        };
        let status_file = jobs_dir.join("hydration-status.json");
        if let Err(e) = write_status(&initial_status, &status_file, jobs_dir) {
            return (
                EXIT_HYDRATION_FAILED,
                e,
                json!({"error":"JOB_STATUS_PUBLISH"}),
            );
        }
        // Publish the readable job last: WatchPaths may start UID702 as soon
        // as it appears. Root's mode0600 file must not strand that worker.
        let published = serde_json::to_vec_pretty(&job)
            .map_err(|e| e.to_string())
            .and_then(|bytes| write_queue_file(jobs_dir, "hydration.json", &bytes));
        if let Err(e) = published {
            return (EXIT_HYDRATION_FAILED, e, json!({"error":"JOB_PUBLISH"}));
        }

        // Kickstart the background hydration worker daemon if running on macOS
        #[cfg(target_os = "macos")]
        {
            let _ = crate::syscmd::command(crate::syscmd::Tool::Launchctl)
                .args(["kickstart", "-k", "system/com.enterprise.enclave.hydrate"])
                .output();
        }

        (
            EXIT_HYDRATION_PENDING,
            format!("Asynchronous hydration job submitted for {model_target} ({profile}); awaiting worker execution"),
            json!({
                "status": "pending",
                "exit_code": EXIT_HYDRATION_PENDING,
                "job_id": job_id,
                "target": model_target,
                "job_file": job_file.display().to_string(),
                "profile": profile,
                "source": source,
            }),
        )
    } else {
        // Synchronous hydration execution
        run_worker_job(&job, jobs_dir, cas_dir)
    }
}

/// Execute the background hydration worker consuming jobs from `jobs_dir`.
pub fn run_hydrate_worker(
    jobs_dir_override: Option<&Path>,
    cas_dir_override: Option<&Path>,
) -> (i32, String, serde_json::Value) {
    let default_jobs_dir = Path::new("/var/run/enclave/jobs");
    let jobs_dir = jobs_dir_override.unwrap_or(default_jobs_dir);

    let default_cas_dir = Path::new("/opt/enterprise/enclave/cas");
    let cas_dir = cas_dir_override.unwrap_or(default_cas_dir);

    let job_file = jobs_dir.join("hydration.json");
    match std::fs::symlink_metadata(&job_file) {
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return (
                EXIT_SUCCESS,
                "No pending hydration jobs in queue".into(),
                json!({ "status": "idle", "jobs_dir": jobs_dir.display().to_string() }),
            );
        }
        Err(e) => {
            return (
                EXIT_HYDRATION_FAILED,
                e.to_string(),
                json!({"error":"JOB_READ_ERROR"}),
            );
        }
    }

    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let job_bytes = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&job_file)
        .and_then(|file| {
            let meta = file.metadata()?;
            if !meta.is_file() || meta.nlink() != 1 || meta.len() > 16 * 1024 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid hydration job file",
                ));
            }
            let mut bytes = Vec::new();
            file.take(16 * 1024 + 1).read_to_end(&mut bytes)?;
            if bytes.len() > 16 * 1024 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "oversized hydration job",
                ));
            }
            Ok(bytes)
        }) {
        Ok(b) => b,
        Err(e) => {
            return (
                EXIT_HYDRATION_FAILED,
                format!(
                    "Failed to read hydration job file {}: {e}",
                    job_file.display()
                ),
                json!({ "error": "JOB_READ_ERROR" }),
            );
        }
    };

    let job: HydrationJob = match serde_json::from_slice(&job_bytes) {
        Ok(j) => j,
        Err(e) => {
            return (
                EXIT_HYDRATION_FAILED,
                format!("Failed to parse hydration job descriptor: {e}"),
                json!({ "error": "JOB_PARSE_ERROR" }),
            );
        }
    };

    run_worker_job(&job, jobs_dir, cas_dir)
}

/// Internal pipeline executor for a single hydration job.
pub fn run_worker_job(
    job: &HydrationJob,
    jobs_dir: &Path,
    cas_dir: &Path,
) -> (i32, String, serde_json::Value) {
    let profile = match enclave_core::profile::Profile::parse(&job.profile) {
        Ok(p) => p,
        Err(e) => {
            return (
                EXIT_HYDRATION_FAILED,
                e.to_string(),
                json!({"status":"failed", "error":e.to_string()}),
            )
        }
    };
    run_worker_job_with_env(
        job,
        jobs_dir,
        cas_dir,
        &crate::ctl::Env::production(profile),
    )
}

/// Run the same pipeline against an explicit daemon environment. Development
/// callers must supply their environment; the production worker always uses
/// code-verified UID702 at the fixed production socket directory.
pub fn run_worker_job_with_env(
    job: &HydrationJob,
    jobs_dir: &Path,
    cas_dir: &Path,
    env: &crate::ctl::Env,
) -> (i32, String, serde_json::Value) {
    let started = Instant::now();
    let mut status = HydrationStatus {
        job_id: job.job_id.clone(),
        target: job.target.clone(),
        profile: job.profile.clone(),
        status: "syncing".into(),
        bytes_synced: 0,
        bytes_total: 0,
        percent: 0.0,
        bao_root: None,
        error: None,
        elapsed_ms: 0,
    };
    let result = (|| -> Result<(), String> {
        validate_target_slug(&job.target).map_err(str::to_string)?;
        if !matches!(job.profile.as_str(), "L1" | "L2" | "L3")
            || env.profile.to_string() != job.profile
        {
            return Err("HYDRATION_PROFILE_MISMATCH".into());
        }
        if !matches!(job.source.as_str(), "r2" | "swarm" | "dmg")
            || (job.profile == "L3" && job.source != "dmg")
        {
            return Err("HYDRATION_SOURCE_INVALID".into());
        }
        std::fs::create_dir_all(jobs_dir).map_err(|e| e.to_string())?;
        // OpenTarget verifies signed metadata and returns a private read-only
        // snapshot. Only bounded metadata crosses CBOR; model bytes never do.
        let mut expected = crate::artifact_stream::fetch_verified_target(env, &job.target)
            .map_err(|e| format!("AUTHENTICATED_TARGET_UNAVAILABLE: {e}"))?;
        status.bytes_total = expected.length;
        let chunks = cas_dir.join("chunks");
        let models = cas_dir.join("models");
        private_cache_directory(cas_dir)?;
        private_cache_directory(&chunks)?;
        private_cache_directory(&models)?;
        let mut staged = StagedModel::new(&models, expected.length.checked_mul(2).ok_or("MODEL_SIZE_OVERFLOW")?)?;
        if job.source == "dmg" {
            stage_dmg_model(job.dmg_path.as_deref().ok_or("DMG_PATH_REQUIRED")?, &expected, &mut staged.file)?;
        } else {
            copy_verified_model(&mut expected.file, expected.length, &expected.blake3, &expected.sha256, &mut staged.file)?;
        }
        // Both destinations receive only completely verified bytes. A failed
        // second publication may leave an orphan valid chunk, never replace a
        // previous model with an unverified/partial payload.
        use std::io::{Seek, SeekFrom};
        staged.file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let mut chunk = StagedModel::new(&chunks, expected.length)?;
        copy_verified_model(&mut staged.file, expected.length, &expected.blake3, &expected.sha256, &mut chunk.file)?;
        chunk.publish(&expected.blake3)?;
        staged.publish(&job.target)?;
        remove_quarantine_if_verified(&models.join(&job.target));
        status.bytes_synced = expected.length;
        let root = expected.blake3;
        status.percent = 100.0;
        status.bao_root = Some(root);
        Ok(())
    })();
    status.elapsed_ms = started.elapsed().as_millis() as u64;
    match result {
        Ok(()) => status.status = "completed".into(),
        Err(e) => {
            status.status = "failed".into();
            status.error = Some(e);
        }
    }
    if let Err(e) = write_status(&status, &jobs_dir.join("hydration-status.json"), jobs_dir) {
        status.status = "failed".into();
        status.error = Some(format!("STATUS_PERSIST_FAILED: {e}"));
    }
    if status.status == "completed" {
        let job_file = jobs_dir.join("hydration.json");
        if let Err(e) = std::fs::remove_file(job_file) {
            if e.kind() != std::io::ErrorKind::NotFound {
                status.status = "failed".into();
                status.error = Some(format!("JOB_REMOVE_FAILED: {e}"));
                let _ = write_status(&status, &jobs_dir.join("hydration-status.json"), jobs_dir);
            }
        }
    }
    if status.status == "completed" {
        (
            EXIT_SUCCESS,
            format!(
                "Model {} successfully verified and hydrated ({})",
                job.target, job.profile
            ),
            json!(status),
        )
    } else {
        (
            EXIT_HYDRATION_FAILED,
            status.error.clone().unwrap_or_default(),
            json!(status),
        )
    }
}

// Cache roots remain trusted daemon-owned state. Hold each destination directory
// open so a leaf replacement cannot redirect temporary writes or rename.
fn private_cache_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    if !path.exists() {
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(path).map_err(|e| e.to_string())?;
    }
    let m = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !m.is_dir() || m.uid() != enclave_core::ipc::geteuid() || m.mode() & 0o022 != 0 {
        return Err("HYDRATION_CACHE_DIRECTORY_UNSAFE".into());
    }
    Ok(())
}
struct StagedModel { directory: std::fs::File, name: std::ffi::CString, file: std::fs::File }
impl StagedModel {
    fn new(path: &Path, needed: u64) -> Result<Self, String> {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::fs::{OpenOptionsExt, MetadataExt};
        let directory = std::fs::OpenOptions::new().read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path).map_err(|e| e.to_string())?;
        let m = directory.metadata().map_err(|e| e.to_string())?;
        if m.uid() != enclave_core::ipc::geteuid() || m.mode() & 0o022 != 0 { return Err("HYDRATION_CACHE_DIRECTORY_UNSAFE".into()); }
        // Keep ample host capacity; the personal native runner is never a disk
        // exhaustion fixture. Account for both unpublished output copies.
        let mut space: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatvfs(directory.as_raw_fd(), &mut space) } != 0 { return Err("HYDRATION_DISK_SPACE_UNKNOWN".into()); }
        let available = (space.f_bavail as u64).saturating_mul(space.f_frsize as u64);
        if available < needed.saturating_add(4 * 1024 * 1024 * 1024) { return Err("HYDRATION_DISK_RESERVE".into()); }
        let name = std::ffi::CString::new(format!(".hydrate-{}",hex::encode(enclave_core::rng::bytes32()))).unwrap();
        let fd = unsafe { libc::openat(directory.as_raw_fd(),name.as_ptr(),libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,0o600) };
        if fd < 0 { return Err(std::io::Error::last_os_error().to_string()); }
        Ok(Self {directory,name,file:unsafe {std::fs::File::from_raw_fd(fd)}})
    }
    fn publish(self, leaf: &str) -> Result<(), String> {
        use std::os::fd::AsRawFd;
        if leaf.is_empty() || leaf.contains('/') || leaf.contains("..") {return Err("HYDRATION_DESTINATION_INVALID".into());}
        let destination = std::ffi::CString::new(leaf).map_err(|e| e.to_string())?;
        enclave_core::fsutil::full_fsync(&self.file).map_err(|e| e.to_string())?;
        if unsafe {libc::renameat(self.directory.as_raw_fd(),self.name.as_ptr(),self.directory.as_raw_fd(),destination.as_ptr())} != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    }
}
impl Drop for StagedModel {
    fn drop(&mut self) { use std::os::fd::AsRawFd; unsafe {libc::unlinkat(self.directory.as_raw_fd(),self.name.as_ptr(),0);}}
}
fn copy_verified_model<R: std::io::Read>(input: &mut R, length: u64, b3: &str, sha: &str, output: &mut std::fs::File) -> Result<(), String> {
    use std::io::Write;
    use sha2::{Digest, Sha256};
    let mut buffer = [0u8;64*1024]; let mut received=0u64;
    let mut bh=blake3::Hasher::new();let mut sh=Sha256::new();
    loop {
        // Read at most one byte beyond the authenticated length for exact EOF.
        let limit = (length.saturating_sub(received).saturating_add(1)).min(buffer.len() as u64) as usize;
        let n=input.read(&mut buffer[..limit]).map_err(|e| e.to_string())?;
        if n==0 {break;}
        received=received.checked_add(n as u64).ok_or("MODEL_SIZE_OVERFLOW")?;
        if received>length {return Err("TUF_MODEL_CONTENT_MISMATCH".into());}
        bh.update(&buffer[..n]); sh.update(&buffer[..n]);
        output.write_all(&buffer[..n]).map_err(|e| e.to_string())?;
    }
    if received != length || blake3::Hasher::finalize(&bh).to_hex().as_str()!=b3 || hex::encode(sh.finalize())!=sha {
        return Err("TUF_MODEL_CONTENT_MISMATCH".into());
    }
    Ok(())
}
#[cfg(not(target_os = "macos"))]
fn stage_dmg_model(_image: &str, _expected: &crate::artifact_stream::VerifiedTarget, _output: &mut std::fs::File) -> Result<(), String> {
    Err("DMG_IMPORT_NOT_RUN: requires macOS hdiutil".into())
}
#[cfg(target_os = "macos")]
fn stage_dmg_model(image: &str, expected: &crate::artifact_stream::VerifiedTarget, destination: &mut std::fs::File) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let image=std::fs::canonicalize(image).map_err(|e|e.to_string())?;
    let mount=std::env::temp_dir().join(format!("enclave-hydrate-{}",hex::encode(enclave_core::rng::bytes32())));
    std::fs::create_dir(&mount).map_err(|e|e.to_string())?;
    std::fs::set_permissions(&mount,std::os::unix::fs::PermissionsExt::from_mode(0o700)).map_err(|e|e.to_string())?;
    let result=(|| {
        let output=crate::syscmd::command(crate::syscmd::Tool::Hdiutil)
            .args(["attach","-readonly","-nobrowse","-noautoopen","-mountpoint"]).arg(&mount).arg(&image).output().map_err(|e|e.to_string())?;
        if !output.status.success() {return Err("HDIUTIL_ATTACH_FAILED".into());}
        let mut file=std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)
            .open(mount.join("model.safetensors")).map_err(|e|e.to_string())?;
        let meta=file.metadata().map_err(|e|e.to_string())?;
        if !meta.is_file() || meta.nlink()!=1 || meta.len()!=expected.length {return Err("DMG_MODEL_LENGTH_OR_TYPE".into());}
        copy_verified_model(&mut file,expected.length,&expected.blake3,&expected.sha256,destination)
    })();
    let detached=crate::syscmd::command(crate::syscmd::Tool::Hdiutil).arg("detach").arg(&mount).status();
    let cleanup=std::fs::remove_dir(&mount);
    if result.is_ok() && (!detached.is_ok_and(|s|s.success()) || cleanup.is_err()) {return Err("DMG_DETACH_OR_CLEANUP_FAILED".into());}
    result
}

fn write_status(
    status: &HydrationStatus,
    _status_file: &Path,
    jobs_dir: &Path,
) -> Result<(), String> {
    let serialized = serde_json::to_vec_pretty(status).map_err(|e| e.to_string())?;
    // The canonical status lives in the worker's private queue. UID702 cannot
    // publish a second copy in the root-owned /var/run/enclave parent.
    write_queue_file(jobs_dir, "hydration-status.json", &serialized)
}

/// Atomic queue handoff through a held directory descriptor. Production uses
/// the provisioned private UID702:8702 directory; explicit development paths
/// may instead belong to the calling principal. Ownership changes happen on
/// the new descriptor before publication, never on an attacker-replaced path.
fn write_queue_file(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    use std::ffi::CString;
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir)
        .map_err(|e| e.to_string())?;
    let meta = directory.metadata().map_err(|e| e.to_string())?;
    let production_owner = meta.uid() == 702 && meta.gid() == 8702 && meta.mode() & 0o7777 == 0o700;
    if (dir == Path::new("/var/run/enclave/jobs") && !production_owner)
        || (!production_owner && meta.uid() != enclave_core::ipc::geteuid())
    {
        return Err("HYDRATION_QUEUE_OWNER_OR_MODE".into());
    }
    let tmp = CString::new(format!(
        ".hydrate-{}",
        hex::encode(enclave_core::rng::bytes32())
    ))
    .unwrap();
    let destination = CString::new(name).map_err(|e| e.to_string())?;
    let fd = directory.as_raw_fd();
    // SAFETY: names are live CStrings and fd is a held directory. O_EXCL
    // refuses existing links; all subsequent writes/ownership use the file fd.
    let created = unsafe {
        libc::openat(
            fd,
            tmp.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if created < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(created) };
    let result = (|| {
        if production_owner
            && enclave_core::ipc::geteuid() == 0
            && unsafe { libc::fchown(created, 702, 8702) } != 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        if unsafe { libc::fchmod(created, 0o600) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        file.write_all(bytes).map_err(|e| e.to_string())?;
        enclave_core::fsutil::full_fsync(&file).map_err(|e| e.to_string())?;
        if unsafe { libc::renameat(fd, tmp.as_ptr(), fd, destination.as_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    })();
    if result.is_err() {
        unsafe {
            libc::unlinkat(fd, tmp.as_ptr(), 0);
        }
    }
    result
}
