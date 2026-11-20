//! F103: canonical signatures, durable replay, bounded state, fail-closed storage.
use ed25519_dalek::SigningKey;
use enclave_tool_host::{ExecutionTicket, TicketReplayFilter};
use std::{process::Command, sync::Arc};
fn ticket(server: &str, tool: &str) -> ExecutionTicket {
    ExecutionTicket::issue(
        &SigningKey::from_bytes(&[7; 32]),
        "id".into(),
        server.into(),
        tool.into(),
        blake3::hash(b"{}").to_hex().to_string(),
        1,
        100,
        100,
    )
}
#[test]
fn length_prefixes_and_all_time_fields_are_signed() {
    let a = ticket("a:b", "c");
    let b = ticket("a", "b:c");
    assert_ne!(a.signing_bytes(), b.signing_bytes());
    let mut changed = a.clone();
    changed.server = b.server;
    changed.tool_name = b.tool_name;
    let vk = SigningKey::from_bytes(&[7; 32]).verifying_key();
    assert!(changed
        .verify(&vk, 101, "a", "b:c", &a.args_blake3)
        .unwrap_err()
        .is("TICKET_SIG_VERIFY_FAILED"));
    let mut changed = a.clone();
    changed.issued_at_unix_ns = 99;
    assert!(changed
        .verify(&vk, 101, "a:b", "c", &a.args_blake3)
        .unwrap_err()
        .is("TICKET_SIG_VERIFY_FAILED"));
    assert!(a
        .verify(&vk, 99, "a:b", "c", &a.args_blake3)
        .unwrap_err()
        .is("TICKET_TIME_INVALID"));
}
#[test]
fn replay_child_process() {
    let Some(path) = std::env::var_os("MCPMAC_TEST_REPLAY_PATH") else {
        return;
    };
    let filter = TicketReplayFilter::open(std::path::Path::new(&path)).unwrap();
    assert!(filter
        .consume("spent", 200, 101)
        .unwrap_err()
        .is("TICKET_REPLAYED"));
    filter.consume("new", 200, 102).unwrap();
}
#[test]
fn replay_survives_actual_process_restart_and_missing_state_is_not_recreated() {
    let dir = tempfile::Builder::new()
        .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .tempdir()
        .unwrap();
    let path = dir.path().canonicalize().unwrap().join("state");
    assert!(TicketReplayFilter::open(&path).is_err());
    let filter = TicketReplayFilter::initialize(&path, 4).unwrap();
    filter.consume("spent", 200, 100).unwrap();
    drop(filter);
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "replay_child_process", "--nocapture"])
        .env("MCPMAC_TEST_REPLAY_PATH", &path)
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "{}",
        String::from_utf8_lossy(&child.stdout)
    );
    let filter = TicketReplayFilter::open(&path).unwrap();
    assert!(filter
        .consume("new", 200, 103)
        .unwrap_err()
        .is("TICKET_REPLAYED"));
    assert!(filter
        .consume("rollback", 200, 99)
        .unwrap_err()
        .is("TICKET_CLOCK_ROLLBACK"));
    drop(filter);
    std::fs::remove_file(&path).unwrap();
    assert!(TicketReplayFilter::open(&path).is_err());
}
#[test]
fn bounded_state_reclaims_only_expired_entries_and_serializes_concurrent_calls() {
    let dir = tempfile::Builder::new()
        .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .tempdir()
        .unwrap();
    let path = dir.path().canonicalize().unwrap().join("state");
    let filter = Arc::new(TicketReplayFilter::initialize(&path, 2).unwrap());
    let mut jobs = Vec::new();
    for _ in 0..16 {
        let f = filter.clone();
        jobs.push(std::thread::spawn(move || {
            f.consume("same", 110, 100).is_ok()
        }));
    }
    assert_eq!(
        jobs.into_iter()
            .filter_map(|x| x.join().ok())
            .filter(|x| *x)
            .count(),
        1
    );
    filter.consume("second", 120, 101).unwrap();
    assert!(filter
        .consume("third", 120, 110)
        .unwrap_err()
        .is("TICKET_REPLAY_CAPACITY"));
    filter.consume("third", 120, 111).unwrap();
    assert!(filter
        .consume("second", 120, 112)
        .unwrap_err()
        .is("TICKET_REPLAYED"));
}
#[test]
fn symlinks_corruption_and_open_permissions_fail_closed() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = tempfile::Builder::new()
        .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .tempdir()
        .unwrap();
    let path = dir.path().canonicalize().unwrap().join("state");
    let filter = TicketReplayFilter::initialize(&path, 2).unwrap();
    drop(filter);
    let link = dir.path().canonicalize().unwrap().join("link");
    symlink(&path, &link).unwrap();
    assert!(TicketReplayFilter::open(&link).is_err());
    assert!(TicketReplayFilter::initialize(&path, 2).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(TicketReplayFilter::open(&path).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&path, b"corrupt").unwrap();
    assert!(TicketReplayFilter::open(&path).is_err());
}

#[test]
fn real_host_rejects_replay_after_reopening_and_executes_new_ticket() {
    use enclave_tool_host::host::ToolHost;
    let dir = tempfile::Builder::new()
        .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .tempdir()
        .unwrap();
    let path = dir.path().canonicalize().unwrap().join("state");
    let sk = SigningKey::from_bytes(&[7; 32]);
    let host = ToolHost::new(
        sk.verifying_key(),
        TicketReplayFilter::initialize(&path, 4).unwrap(),
    );
    let t = ticket("server", "tool");
    assert_eq!(
        host.execute(&t, "server", "tool", b"{}", 101, |_, _, _| Ok(
            b"[1]".to_vec()
        ))
        .unwrap()
        .bytes,
        b"[1]"
    );
    drop(host);
    let host = ToolHost::new(sk.verifying_key(), TicketReplayFilter::open(&path).unwrap());
    assert!(host
        .execute(&t, "server", "tool", b"{}", 102, |_, _, _| panic!(
            "replayed side effect"
        ))
        .unwrap_err()
        .is("TICKET_REPLAYED"));
    let fresh = ExecutionTicket::issue(
        &sk,
        "fresh".into(),
        "server".into(),
        "tool".into(),
        t.args_blake3,
        1,
        102,
        100,
    );
    assert!(host
        .execute(&fresh, "server", "tool", b"{}", 103, |_, _, _| Ok(
            b"[]".to_vec()
        ))
        .is_ok());
}
