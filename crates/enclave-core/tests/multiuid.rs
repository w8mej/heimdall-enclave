//! GAP-01 acceptance: the production socket layout works with five distinct
//! daemon UIDs. Servers bind with `SocketAccess::Group` inside root-provisioned
//! `daemon:<client group> 2750` directories; every edge of the ADR-006
//! adjacency matrix connects and authenticates, every non-edge fails, and a
//! daemon refuses to start on an unsafe directory.
//!
//! Needs real UID switching, so it runs only as root on Linux (the CI VM
//! job); elsewhere it prints a skip notice. Child processes re-enter this
//! test binary with `MCPMAC_MU_ROLE` set.

use std::collections::BTreeSet;
use std::os::unix::fs::{chown, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use enclave_core::daemon::DaemonId;
use enclave_core::error::EnclaveResult;
use enclave_core::ipc::{self, Client, PeerCredentials, SocketAccess};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
enum Req {
    WhoAmI,
}

const ROLE: &str = "MCPMAC_MU_ROLE";
const MESH: &str = "MCPMAC_MU_MESH";
/// A non-daemon user (`uid=501`).
const USER_UID: u32 = 501;

/// Supplementary groups = client groups of every server this UID may call
/// (what `provision-accounts.sh` configures).
fn groups_of(uid: u32) -> Vec<u32> {
    let mut g: Vec<u32> = DaemonId::ALL
        .into_iter()
        .filter(|s| ipc::production_policy(*s).allowed_uids.contains(&uid))
        .map(|s| s.client_gid())
        .collect();
    if uid == DaemonId::CustodyVault.uid() {
        g.push(enclave_core::daemon::WITNESS_CLIENT_GID);
    }
    g
}

fn as_uid(cmd: &mut Command, uid: u32, gid: u32, groups: Vec<u32>) {
    // std's `CommandExt::uid` switches identity *before* `pre_exec` runs,
    // after which `setgroups` would fail; do the whole switch here instead.
    // SAFETY: setgroups/setgid/setuid are async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            let g: Vec<libc::gid_t> = groups.clone();
            if libc::setgroups(g.len() as _, g.as_ptr()) != 0
                || libc::setgid(gid) != 0
                || libc::setuid(uid) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

fn child(role: String, mesh: &Path) -> Command {
    let mut c = Command::new(std::env::current_exe().unwrap());
    c.args([
        "--exact",
        "multi_uid_mesh",
        "--nocapture",
        "--test-threads=1",
    ])
    .env(ROLE, role)
    .env(MESH, mesh)
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    c
}

fn run_role(role: &str, mesh: &Path) {
    let mut it = role.split(':');
    match (it.next(), it.next()) {
        (Some("server"), Some(uid)) => {
            let d = DaemonId::from_uid(uid.parse().unwrap()).unwrap();
            let l = match ipc::bind(
                &mesh.join(d.socket_name()),
                SocketAccess::Group {
                    gid: d.client_gid(),
                },
            ) {
                Ok(l) => l,
                Err(e) => {
                    println!("RESULT bind-error {}", e.reason);
                    return;
                }
            };
            println!("RESULT bound");
            let h = Arc::new(|p: &PeerCredentials, _r: Req| -> EnclaveResult<u32> { Ok(p.uid) });
            let _ = ipc::serve::<Req, u32, _>(
                l,
                ipc::production_policy(d),
                h,
                Arc::new(AtomicBool::new(false)),
            );
        }
        (Some("client"), Some(server)) => {
            let d = DaemonId::from_uid(server.parse().unwrap()).unwrap();
            match Client::connect(&mesh.join(d.socket_name()), d.uid())
                .and_then(|mut c| c.call::<_, u32>(&Req::WhoAmI))
            {
                Ok(uid) => println!("RESULT ok {uid}"),
                Err(e) => println!("RESULT err {}", e.reason),
            }
        }
        _ => panic!("bad role {role}"),
    }
}

fn result_line(out: &[u8]) -> String {
    String::from_utf8_lossy(out)
        .lines()
        .find_map(|l| l.split_once("RESULT ").map(|(_, r)| r.trim().to_owned()))
        .unwrap_or_else(|| format!("no result: {}", String::from_utf8_lossy(out)))
}

/// What `provision-accounts.sh` does for the socket mesh.
fn provision(mesh: &Path) {
    std::fs::create_dir_all(mesh).unwrap();
    chown(mesh, Some(0), Some(0)).unwrap();
    std::fs::set_permissions(mesh, std::fs::Permissions::from_mode(0o755)).unwrap();
    for d in DaemonId::ALL {
        let dir = mesh.join(d.dir_name());
        std::fs::create_dir_all(&dir).unwrap();
        chown(&dir, Some(d.uid()), Some(d.client_gid())).unwrap();
        // set-gid: on Linux sockets inherit the directory group only with it.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o2750)).unwrap();
    }
}

fn wait_bound(c: &mut Child) {
    use std::io::{BufRead, BufReader};
    let mut r = BufReader::new(c.stdout.take().unwrap());
    let t = Instant::now();
    let mut line = String::new();
    while t.elapsed() < Duration::from_secs(10) {
        line.clear();
        if r.read_line(&mut line).unwrap() == 0 {
            break;
        }
        // libtest prints `test multi_uid_mesh ... ` before the child's output.
        if let Some((_, x)) = line.split_once("RESULT ") {
            assert_eq!(x.trim(), "bound", "server failed: {x}");
            return;
        }
    }
    panic!("server did not bind");
}

#[test]
fn multi_uid_mesh() {
    if let Ok(role) = std::env::var(ROLE) {
        run_role(&role, &PathBuf::from(std::env::var(MESH).unwrap()));
        return;
    }
    if !cfg!(target_os = "linux") || ipc::geteuid() != 0 {
        eprintln!("multi_uid_mesh: skipped (needs root on Linux; the CI VM job runs it)");
        return;
    }
    let mesh = PathBuf::from(format!(
        "/tmp/mcpmac-mu-{:x}",
        enclave_core::rng::u64() & 0xffff_ffff
    ));
    provision(&mesh);

    let mut servers = Vec::new();
    for d in DaemonId::ALL {
        let mut c = child(format!("server:{}", d.uid()), &mesh);
        as_uid(&mut c, d.uid(), d.gid(), vec![d.gid()]);
        let mut ch = c.spawn().unwrap();
        wait_bound(&mut ch);
        servers.push(ch);
    }
    // Sockets carry exactly the provisioned owner, client group and mode.
    for d in DaemonId::ALL {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::symlink_metadata(mesh.join(d.socket_name())).unwrap();
        assert_eq!(
            (m.uid(), m.gid(), m.mode() & 0o777),
            (d.uid(), d.client_gid(), 0o660),
            "{d}"
        );
    }

    let mut callers: Vec<u32> = DaemonId::ALL.iter().map(|d| d.uid()).collect();
    callers.push(USER_UID);
    let mut checked = 0;
    for server in DaemonId::ALL {
        let allowed: BTreeSet<u32> = ipc::production_policy(server).allowed_uids;
        for &caller in &callers {
            if caller == server.uid() {
                continue;
            }
            let mut c = child(format!("client:{}", server.uid()), &mesh);
            as_uid(&mut c, caller, caller, groups_of(caller));
            let r = result_line(&c.output().unwrap().stdout);
            if allowed.contains(&caller) {
                assert_eq!(
                    r,
                    format!("ok {caller}"),
                    "uid {caller} -> {server} must connect"
                );
            } else {
                // Refused by the filesystem: no client-group membership.
                assert!(
                    r.starts_with("err "),
                    "uid {caller} -> {server} must be refused, got {r}"
                );
            }
            checked += 1;
        }
        // Defence in depth: holding the group is not enough — the kernel peer
        // check still refuses a UID outside the adjacency matrix.
        let mut c = child(format!("client:{}", server.uid()), &mesh);
        as_uid(&mut c, USER_UID, USER_UID, vec![server.client_gid()]);
        assert_eq!(
            result_line(&c.output().unwrap().stdout),
            "err PEER_UID_REJECTED",
            "uid 501 in {}",
            server.client_group()
        );
    }
    assert_eq!(checked, 5 * 5);

    // A daemon refuses an unsafe directory instead of repairing it.
    let zk = DaemonId::ZkAuditor;
    std::fs::set_permissions(
        mesh.join(zk.dir_name()),
        std::fs::Permissions::from_mode(0o2777),
    )
    .unwrap();
    let mut c = child(format!("server:{}", zk.uid()), &mesh);
    as_uid(&mut c, zk.uid(), zk.gid(), vec![zk.gid()]);
    assert_eq!(
        result_line(&c.output().unwrap().stdout),
        "bind-error IPC_DIR_INSECURE"
    );

    for mut s in servers {
        let _ = s.kill();
        let _ = s.wait();
    }
    let _ = std::fs::remove_dir_all(&mesh);
}

/// GAP-21 acceptance (cross-UID): UID 702 cannot signal a UID 701 consumer
/// (the old in-daemon `kill` failed open), but the root supervisor kills a
/// UID 701 holder of a revoked inode that ignores `SIGHUP`, after the grace
/// period, and never signals a non-daemon (`uid=501`) holder.
#[test]
fn multi_uid_revocation_supervisor_kills_cross_uid_holder() {
    use enclave_core::supervisor::{
        enforce_revocation, holders, inode_of, production_may_signal, RELEASE_GRACE,
    };
    use std::os::unix::process::ExitStatusExt;
    if !cfg!(target_os = "linux") || ipc::geteuid() != 0 {
        eprintln!("multi_uid_revocation: skipped (needs root on Linux)");
        return;
    }
    let f = std::env::temp_dir().join(format!("mcpmac-mu-revoked-{}", enclave_core::rng::u64()));
    std::fs::write(&f, b"weights").unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (dev, ino) = inode_of(&f).unwrap();
    let hold = |uid: u32| {
        let mut c = Command::new("sh");
        c.arg("-c")
            .arg(format!(
                "exec 3<'{}'; trap '' HUP; exec sleep 30",
                f.display()
            ))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        as_uid(&mut c, uid, uid, vec![uid]);
        c.spawn().unwrap()
    };
    let mut consumer = hold(DaemonId::ModelRunner.uid());
    let mut user = hold(USER_UID);
    let t = Instant::now();
    while holders(dev, ino).len() < 2 && t.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(10));
    }
    // UID 702 itself cannot terminate the UID 701 consumer.
    let mut k = Command::new("kill");
    k.arg("-9")
        .arg(consumer.id().to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    as_uid(
        &mut k,
        DaemonId::SwarmSync.uid(),
        DaemonId::SwarmSync.uid(),
        vec![],
    );
    assert!(
        !k.status().unwrap().success(),
        "kill from UID 702 must fail with EPERM"
    );
    assert!(consumer.try_wait().unwrap().is_none());
    // The supervisor (root) does, after the grace period.
    let rep = enforce_revocation(dev, ino, RELEASE_GRACE, production_may_signal);
    assert_eq!(rep.killed, vec![consumer.id() as i32], "{rep:?}");
    assert_eq!(rep.refused, vec![user.id() as i32], "{rep:?}");
    assert!((500..700).contains(&rep.elapsed_ms), "{}", rep.elapsed_ms);
    assert_eq!(consumer.wait().unwrap().signal(), Some(libc::SIGKILL));
    assert!(user.try_wait().unwrap().is_none());
    let _ = user.kill();
    let _ = user.wait();
    let _ = std::fs::remove_file(f);
}
