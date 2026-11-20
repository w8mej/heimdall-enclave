//! F103 trusted-clock/lifecycle regressions, private files and child processes.
use ed25519_dalek::SigningKey;
use enclave_tool_host::{DurableToolHost, ExecutionTicket};
use enclave_tool_host::lifecycle::trusted_unix_ns;
use std::os::unix::fs::PermissionsExt;

fn directory() -> tempfile::TempDir {
    tempfile::Builder::new().permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir().unwrap()
}
fn ticket(key: &SigningKey, id: &str) -> ExecutionTicket {
    ExecutionTicket::issue(key, id.into(), "server".into(), "tool".into(),
        blake3::hash(b"{}").to_hex().to_string(), 1, trusted_unix_ns().unwrap(), 60_000_000_000)
}

#[test]
fn lifecycle_child() {
    let Some(root) = std::env::var_os("depot_LIFECYCLE_ROOT") else { return; };
    let root = std::path::Path::new(&root);
    let key = SigningKey::from_bytes(&[41; 32]);
    let host = DurableToolHost::open(&root.join("replay"), key.verifying_key()).unwrap();
    let t: ExecutionTicket = serde_json::from_slice(&std::fs::read(root.join("ticket")).unwrap()).unwrap();
    assert!(host.execute(&t, "server", "tool", b"{}", |_, _, _| panic!("replayed side effect"))
        .unwrap_err().is("TICKET_REPLAYED"));
    let fresh = ticket(&key, "child-fresh");
    assert_eq!(host.execute(&fresh, "server", "tool", b"{}", |_, _, args| {
        assert_eq!(args, b"{}");
        Ok(b"[7]".to_vec())
    }).unwrap().bytes, b"[7]");
}

#[test]
fn actual_child_restart_preserves_consumption_and_allows_fresh_work() {
    let dir = directory();
    let root = dir.path().canonicalize().unwrap();
    let key = SigningKey::from_bytes(&[41; 32]);
    let host = DurableToolHost::provision(&root.join("replay"), key.verifying_key(), 16).unwrap();
    let t = ticket(&key, "parent-spent");
    std::fs::write(root.join("ticket"), serde_json::to_vec(&t).unwrap()).unwrap();
    assert!(host.execute(&t, "server", "tool", b"{}", |_, _, _| Ok(b"[1]".to_vec())).is_ok());
    drop(host);
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "lifecycle_child", "--nocapture"])
        .env("depot_LIFECYCLE_ROOT", &root).output().unwrap();
    assert!(out.status.success(), "{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    let host = DurableToolHost::open(&root.join("replay"), key.verifying_key()).unwrap();
    assert!(host.execute(&t, "server", "tool", b"{}", |_, _, _| panic!("replayed"))
        .unwrap_err().is("TICKET_REPLAYED"));
}

#[test]
fn missing_database_and_wrong_issuer_never_provision_on_restart() {
    let dir = directory();
    let path = dir.path().canonicalize().unwrap().join("replay");
    let key = SigningKey::from_bytes(&[41; 32]);
    assert!(DurableToolHost::open(&path, key.verifying_key()).is_err());
    assert!(!path.exists());
    drop(DurableToolHost::provision(&path, key.verifying_key(), 8).unwrap());
    assert!(DurableToolHost::open(&path, SigningKey::from_bytes(&[42; 32]).verifying_key())
        .unwrap_err().is("TOOL_HOST_ISSUER_MISMATCH"));
    std::fs::remove_file(&path).unwrap();
    assert!(DurableToolHost::open(&path, key.verifying_key()).is_err());
    assert!(DurableToolHost::provision(&path, key.verifying_key(), 8).is_err());
    assert!(!path.exists(), "must not recreate deleted replay state under old key");
}

#[test]
fn request_cannot_supply_a_past_clock_and_failed_execution_is_spent() {
    let dir = directory();
    let path = dir.path().canonicalize().unwrap().join("replay");
    let key = SigningKey::from_bytes(&[41; 32]);
    let host = DurableToolHost::provision(&path, key.verifying_key(), 8).unwrap();
    let expired = ExecutionTicket::issue(&key, "expired".into(), "server".into(), "tool".into(),
        blake3::hash(b"{}").to_hex().to_string(), 1, 1, 1);
    assert!(host.execute(&expired, "server", "tool", b"{}", |_, _, _| panic!("expired side effect"))
        .unwrap_err().is("TICKET_EXPIRED"));
    let t = ticket(&key, "failed-execution");
    assert!(host.execute(&t, "server", "tool", b"{}", |_, _, _|
        Err(enclave_core::err!(EIO, "TOOL_FAILURE"))).unwrap_err().is("TOOL_FAILURE"));
    drop(host);
    let host = DurableToolHost::open(&path, key.verifying_key()).unwrap();
    assert!(host.execute(&t, "server", "tool", b"{}", |_, _, _| panic!("retry side effect"))
        .unwrap_err().is("TICKET_REPLAYED"));
}

#[test]
fn malformed_insecure_or_linked_marker_is_refused() {
    use std::os::unix::fs::symlink;
    let dir = directory();
    let path = dir.path().canonicalize().unwrap().join("replay");
    let mark = path.with_file_name("replay.provisioned");
    let key = SigningKey::from_bytes(&[41; 32]);
    drop(DurableToolHost::provision(&path, key.verifying_key(), 8).unwrap());
    std::fs::set_permissions(&mark, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(DurableToolHost::open(&path, key.verifying_key()).is_err());
    std::fs::set_permissions(&mark, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&mark, b"bad").unwrap();
    assert!(DurableToolHost::open(&path, key.verifying_key()).is_err());
    std::fs::remove_file(&mark).unwrap();
    symlink(&path, &mark).unwrap();
    assert!(DurableToolHost::open(&path, key.verifying_key()).is_err());
}

#[test]
fn missing_marker_hardlink_and_fifo_are_refused_without_blocking() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let dir = directory();
    let root = dir.path().canonicalize().unwrap();
    let path = root.join("replay");
    let mark = root.join("replay.provisioned");
    let key = SigningKey::from_bytes(&[41; 32]);
    drop(DurableToolHost::provision(&path, key.verifying_key(), 8).unwrap());
    std::fs::hard_link(&mark, root.join("marker-link")).unwrap();
    assert!(DurableToolHost::open(&path, key.verifying_key()).is_err());
    std::fs::remove_file(root.join("marker-link")).unwrap();
    std::fs::remove_file(&mark).unwrap();
    assert!(DurableToolHost::open(&path, key.verifying_key()).is_err());
    let name = CString::new(mark.as_os_str().as_bytes()).unwrap();
    // SAFETY: name is a valid NUL-terminated private fixture path.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let started = std::time::Instant::now();
    assert!(DurableToolHost::open(&path, key.verifying_key()).is_err());
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    std::fs::remove_file(&mark).unwrap();
    std::fs::write(&mark, key.verifying_key().as_bytes()).unwrap();
    std::fs::set_permissions(&mark, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::remove_file(&path).unwrap();
    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: name is a valid NUL-terminated private fixture path.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(DurableToolHost::open(&path, key.verifying_key()).is_err());
}

#[test]
fn failed_or_competing_provisioning_never_overwrites_existing_state() {
    let dir = directory();
    let root = dir.path().canonicalize().unwrap();
    let path = root.join("replay");
    let key = SigningKey::from_bytes(&[41; 32]);
    std::fs::write(&path, b"existing-state").unwrap();
    assert!(DurableToolHost::provision(&path, key.verifying_key(), 8).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"existing-state");
    assert!(root.join("replay.provisioned").exists());
    std::fs::remove_file(&path).unwrap();
    assert!(DurableToolHost::provision(&path, key.verifying_key(), 8).is_err());
    assert!(!path.exists());
    let path = root.join("competing");
    let jobs: Vec<_> = (0..4).map(|_| {
        let path = path.clone();
        let verifying_key = key.verifying_key();
        std::thread::spawn(move || DurableToolHost::provision(&path, verifying_key, 8).is_ok())
    }).collect();
    assert_eq!(jobs.into_iter().map(|j| j.join().unwrap()).filter(|ok| *ok).count(), 1);
    assert!(DurableToolHost::open(&path, key.verifying_key()).is_ok());
}

#[test]
fn nonsticky_writable_ancestor_cannot_select_or_replace_replay_state() {
    let dir=directory();let root=dir.path().canonicalize().unwrap();
    let child=root.join("private");std::fs::create_dir(&child).unwrap();
    std::fs::set_permissions(&child,std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&root,std::fs::Permissions::from_mode(0o777)).unwrap();
    let path=child.join("replay");
    let key=SigningKey::from_bytes(&[41;32]);
    let result=DurableToolHost::provision(&path,key.verifying_key(),8);
    std::fs::set_permissions(&root,std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(result.unwrap_err().is("TOOL_HOST_ANCESTRY"));
    assert!(!path.exists());assert!(!child.join("replay.provisioned").exists());
}
