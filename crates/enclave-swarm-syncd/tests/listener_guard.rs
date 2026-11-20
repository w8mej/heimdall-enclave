//! Process-isolated production L3 descriptor, startup and fetch guards.
//! All traffic is private loopback; no installed service or host policy changes.

use enclave_core::profile::Profile;
use enclave_swarm_syncd::{
    cas::ContentStore,
    revocation::Enforcement,
    service::{CasConfig, CasService},
    transport::ohttp_fetch::{assert_l3_zero_listeners, fetch_and_commit_l3, L3FetchTarget},
};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::time::Duration;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        // Darwin Unix socket paths have a small SUN_LEN ceiling. This is an
        // exclusive private directory, never a shared socket pathname.
        let path = PathBuf::from("/tmp").join(format!("ml3-{:016x}", enclave_core::rng::u64()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn startup(&self) -> enclave_core::error::EnclaveResult<std::sync::Arc<CasService>> {
        CasService::start(CasConfig {dev_same_uid: true,
            profile: Profile::L3, store_dir: self.0.join("store"), audit_path: None,
            tuf_root: None, ohttp_gateway: None, state_dir: None,
            revocation: Enforcement::Unavailable,
        })
    }
    fn expect_receiver_refused(&self) {
        let error = assert_l3_zero_listeners().unwrap_err();
        assert_eq!(error.reason, "L3_LISTENER_FORBIDDEN", "{error:?}");
        assert_eq!(self.startup().err().expect("L3 startup must reject receiver").reason, "L3_LISTENER_FORBIDDEN");
        let store = ContentStore::open(&self.0.join("fetch")).unwrap();
        // The enforced public fetch must reject before key processing or connect.
        let key = enclave_crypto::ohttp::KeyConfig { key_id: 0, public_key: vec![] };
        let target = L3FetchTarget { target_name: "fixture", transport_ciphertext_bao_root: "invalid", expected_plaintext_root: "invalid", dek: &[0; 32] };
        assert_eq!(fetch_and_commit_l3("invalid-address", &key, &target, &store).unwrap_err().reason, "L3_LISTENER_FORBIDDEN");
    }
    fn expect_allowed(&self) {
        assert_l3_zero_listeners().expect("no inbound Internet receiver");
        self.startup().expect("L3 startup with no inbound Internet receiver");
    }
}
impl Drop for Fixture {
    fn drop(&mut self) { std::fs::remove_dir_all(&self.0).unwrap(); }
}

fn scenario(case: &str) {
    let f = Fixture::new();
    f.expect_allowed();
    match case {
        "none" => (),
        "tcp4" | "tcp6" => {
            let addr = if case == "tcp4" { "127.0.0.1:0" } else { "[::1]:0" };
            let listener = TcpListener::bind(addr).unwrap();
            f.expect_receiver_refused();
            drop(listener);
        },
        "udp4" | "udp6" => {
            let addr = if case == "udp4" { "127.0.0.1:0" } else { "[::1]:0" };
            let receiver = UdpSocket::bind(addr).unwrap();
            receiver.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            // A separate sender cannot contaminate another case; it is dropped
            // before inspecting the receiver in the actual process guard.
            let sender = UdpSocket::bind(addr).unwrap();
            sender.send_to(b"private-udp-fixture", receiver.local_addr().unwrap()).unwrap();
            drop(sender);
            let mut buf = [0u8; 32];
            let (got, _) = receiver.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..got], b"private-udp-fixture");
            f.expect_receiver_refused();
            drop(receiver);
        },
        "tcp-client" => {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (server, _) = listener.accept().unwrap();
            drop(listener);
            // Connected TCP clients are required by the relay transport. An
            // established endpoint is not a listening descriptor.
            f.expect_allowed();
            drop((client, server));
        },
        "udp-client4" | "udp-client6" => {
            let addr = if case == "udp-client4" { "127.0.0.1:0" } else { "[::1]:0" };
            let peer = UdpSocket::bind(addr).unwrap();
            let client = UdpSocket::bind(addr).unwrap();
            client.connect(peer.local_addr().unwrap()).unwrap();
            drop(peer);
            // A kernel-connected client may only receive its selected peer's
            // traffic. This is a socket-role check, not relay allowlist proof.
            f.expect_allowed();
            drop(client);
        },
        "udp-unbound" => {
            use std::os::fd::{FromRawFd, OwnedFd};
            let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
            assert!(raw >= 0);
            let socket = unsafe { OwnedFd::from_raw_fd(raw) };
            f.expect_allowed();
            drop(socket);
        },
        "unix-ipc" => {
            let listener = std::os::unix::net::UnixListener::bind(f.0.join("private.sock")).unwrap();
            f.expect_allowed();
            drop(listener);
        },
        _ => panic!("unknown private fixture"),
    }
    f.expect_allowed();
}

#[test]
fn process_isolated_l3_descriptor_guard() {
    if let Ok(case) = std::env::var("MCPMAC_L3_GUARD_CASE") {
        scenario(&case);
        return;
    }
    for case in ["none", "tcp4", "tcp6", "udp4", "udp6", "tcp-client", "udp-client4", "udp-client6", "udp-unbound", "unix-ipc"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "process_isolated_l3_descriptor_guard", "--nocapture"])
            .env("MCPMAC_L3_GUARD_CASE", case).output().unwrap();
        assert!(output.status.success(), "{case}: {}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        println!("L3 private descriptor case {case}: PASS");
    }
}
