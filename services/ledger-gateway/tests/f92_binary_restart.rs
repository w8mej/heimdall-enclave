//! F92 binary default durability: actual OHTTP acknowledgments survive process restart.

use ed25519_dalek::SigningKey;
use enclave_core::poseidon2::hash_bytes;
use enclave_zk_auditor::relation::{prove_rollup_series, EpochChunk, EpochPublic, SlotWitness};
use enclave_zk_auditor::tombstone::TombstoneKeys;
use ledger_gateway::{create_ohttp_rollup_request, Ledger};

fn issuer()->&'static enclave_crypto::pqc::HybridSigningKey {
    static KEY:std::sync::OnceLock<enclave_crypto::pqc::HybridSigningKey>=std::sync::OnceLock::new();
    KEY.get_or_init(enclave_crypto::pqc::HybridSigningKey::generate)
}

fn keys() -> TombstoneKeys {
    let mut r = rand_core::OsRng;
    TombstoneKeys {
        k703: SigningKey::generate(&mut r).verifying_key(),
        k704: SigningKey::generate(&mut r).verifying_key(),
    }
}

fn chunk(s_start: u64, n: u64) -> EpochChunk {
    EpochChunk {
        slots: (0..n)
            .map(|i| SlotWitness::Fold {
                seq: s_start + i,
                scrubbed: b"[REDACTED]".to_vec(),
                qif_delta_mb: 5,
            })
            .collect(),
        journal_lines: (0..n)
            .map(|i| format!("{{\"line\":{}}}", s_start + i).into_bytes())
            .collect(),
    }
}

/// A three-frame series for one enclave (`id`) in one epoch.
fn series(id: u8) -> Vec<Vec<u8>> {
    let public = EpochPublic {
        profile: 2,
        policy_blake3: [1; 32],
        tuf_snapshot_root: [2; 32],
        j_prev: hash_bytes(b"MCPMac-Genesis-v1", b""),
    };
    prove_rollup_series(
        &public,
        &[id; 32],
        "acct:corp",
        &[chunk(1, 2), chunk(3, 2), chunk(5, 2)],
        &keys(),
        None,
        Some(vec!["3045".into()]),
        false,
    )
    .expect("prove series").into_iter().map(|bytes|{
        let frame=enclave_zk_auditor::rollup::ComplianceRollupProofV1::decode(&bytes).unwrap();
        let statement=frame.statement().unwrap();
        enclave_zk_auditor::rollup::ComplianceRollupProofV1::build(&statement,frame.proof,None,false,
            Some(vec![enclave_zk_auditor::rollup::ComplianceRollupProofV1::sign_l2_hybrid_anchor(&statement,issuer())])).unwrap()
    }).collect()
}


// This exercises the actual binary's storage selection, not an explicitly
// constructed Ledger::open fixture. A successful HTTP acknowledgment precedes
// SIGKILL; a separately started process must recover its replay and chain tips.
struct GatewayProcess {
    child: std::process::Child,
    address: std::net::SocketAddr,
    key: enclave_crypto::ohttp::KeyConfig,
}

impl GatewayProcess {
    fn start(state_dir: &std::path::Path) -> Self {
        use std::io::BufRead;
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = port.local_addr().unwrap();
        drop(port);
        let trust_file=state_dir.parent().unwrap().canonicalize().unwrap().join("receiver-trust.json");
        std::fs::write(&trust_file,serde_json::to_vec(&serde_json::json!({"v":1,"authority":{"kind":"l2_hybrid_anchor","public_key_hex":hex::encode(issuer().verifying_key().to_bytes())}})).unwrap()).unwrap();
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_ledger-gateway"))
            .args(["--run", "--listen", &address.to_string(), "--state-dir"])
            .arg(state_dir).arg("--receiver-trust-file").arg(&trust_file)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                if tx.send(line.unwrap()).is_err() {
                    break;
                }
            }
        });
        let mut process = Self {
            child,
            address,
            key: enclave_crypto::ohttp::KeyConfig { key_id: 1, public_key: vec![] },
        };
        loop {
            let line = rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
            if let Some(rendered) = line.trim().strip_prefix("Gateway key config: ") {
                process.key = enclave_crypto::ohttp::KeyConfig::parse(rendered).unwrap();
            }
            if line.starts_with("Listening for OHTTP") {
                assert!(!process.key.public_key.is_empty());
                break;
            }
        }
        process
    }

    fn post(&self, frame: &[u8]) -> (u16, serde_json::Value) {
        use std::io::{Read, Write};
        let body = create_ohttp_rollup_request(&self.key, frame).unwrap();
        let mut stream = std::net::TcpStream::connect(self.address).unwrap();
        stream.set_read_timeout(Some(std::time::Duration::from_secs(30))).unwrap();
        stream.set_write_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        write!(stream, "POST /v1/rollup HTTP/1.1\r\nHost: ledger.corporate.internal\r\nContent-Length: {}\r\n\r\n", body.len()).unwrap();
        stream.write_all(&body).unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        let body_start = response.windows(4).position(|b| b == b"\r\n\r\n").unwrap() + 4;
        let header = std::str::from_utf8(&response[..body_start]).unwrap();
        let status = header.split_whitespace().nth(1).unwrap().parse().unwrap();
        let value = if status == 200 {
            let mut reader = &response[body_start..];
            let body: ledger_gateway::LedgerResponse = ciborium::de::from_reader(&mut reader).unwrap();
            serde_json::to_value(body).unwrap()
        } else {
            serde_json::json!({"error": String::from_utf8_lossy(&response[body_start..])})
        };
        (status, value)
    }
}

impl Drop for GatewayProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn f92_default_binary_recovers_acknowledged_frames_after_process_restart() {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let dir = std::env::temp_dir().join(format!("f92-binary-{}", enclave_core::rng::u64()));
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let state = dir.join("state");
    let frames = series(10);
    {
        let first = GatewayProcess::start(&state);
        let (status, result) = first.post(&frames[0]);
        assert_eq!(status, 200);
        assert_eq!(result["accepted"], true);
        assert_eq!(result["duplicate"], false);
    }
    {
        let second = GatewayProcess::start(&state);
        let (status, result) = second.post(&frames[0]);
        assert_eq!(status, 200);
        assert_eq!(result["accepted"], false, "restart must not forget an acknowledged frame");
        assert_eq!(result["duplicate"], true);
        let (status, result) = second.post(&frames[2]);
        assert_ne!(status, 200, "restart must retain chain gap rejection: {result}");
        let (status, result) = second.post(&frames[1]);
        assert_eq!(status, 200, "valid next frame: {result}");
        assert_eq!(result["accepted"], true);
    }
    assert_eq!(std::fs::metadata(&state).unwrap().mode() & 0o777, 0o700);
    assert_eq!(std::fs::metadata(state.join("frames.jsonl")).unwrap().mode() & 0o777, 0o600);
    let ledger = Ledger::open(&state.join("frames.jsonl"), 100).unwrap();
    assert_eq!(ledger.frames().len(), 2);
    drop(ledger);
    std::fs::remove_dir_all(dir).unwrap();
}

struct PrivateDirectory(std::path::PathBuf);

impl PrivateDirectory {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(format!("f92-storage-{}", enclave_core::rng::u64()));
        std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}

impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn binary_output(args: &[&std::ffi::OsStr]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_ledger-gateway"))
        .arg("--accounting-fixture").args(args)
        .output()
        .unwrap()
}

fn startup_refused(output: std::process::Output, reason: &str) {
    assert!(!output.status.success(), "startup unexpectedly succeeded");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(reason), "expected {reason}, got {stderr}");
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("Gateway key config:"),
        "storage failure must occur before publishing a gateway identity"
    );
}

#[test]
fn f92_binary_storage_selection_requires_explicit_development_mode() {
    use std::ffi::OsStr;
    let dir = PrivateDirectory::new();
    let state = dir.0.join("state");
    let journal = dir.0.join("custom.jsonl");
    let help = binary_output(&[OsStr::new("--help")]);
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("default /var/db/enclave/ledger"));
    assert!(help.contains("--dev-in-memory"));

    for args in [
        vec![OsStr::new("--dev-in-memory"), OsStr::new("--state-dir"), state.as_os_str()],
        vec![OsStr::new("--dev-in-memory"), OsStr::new("--ledger-journal"), journal.as_os_str()],
        vec![OsStr::new("--state-dir"), state.as_os_str(), OsStr::new("--ledger-journal"), journal.as_os_str()],
        vec![OsStr::new("--state-dir")],
        vec![OsStr::new("--state-dr"), state.as_os_str()],
    ] {
        startup_refused(binary_output(&args), "USAGE");
    }
    assert!(!state.exists());
    assert!(!journal.exists());

    let dev = binary_output(&[OsStr::new("--dev-in-memory")]);
    assert!(dev.status.success(), "{:?}", dev);
    assert!(String::from_utf8(dev.stdout).unwrap().contains("explicit development mode"));
    let custom = binary_output(&[OsStr::new("--ledger-journal"), journal.as_os_str()]);
    assert!(custom.status.success(), "{:?}", custom);
    assert!(journal.is_file());
    assert!(Ledger::open(&journal, 10).unwrap().frames().is_empty());
}

#[test]
fn f92_binary_refuses_storage_errors_without_memory_fallback() {
    use std::ffi::OsStr;
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = PrivateDirectory::new();
    let state = dir.0.join("state");
    let run = || binary_output(&[OsStr::new("--state-dir"), state.as_os_str()]);
    let output = run();
    assert!(output.status.success(), "{:?}", output);
    assert!(String::from_utf8(output.stdout).unwrap().contains("frames.jsonl (0 frames)"));
    let journal = state.join("frames.jsonl");
    std::fs::write(&journal, b"not json\n").unwrap();
    startup_refused(run(), "LEDGER_JOURNAL_CORRUPT");
    std::fs::write(&journal, b"{}").unwrap();
    startup_refused(run(), "LEDGER_JOURNAL_PARTIAL");
    std::fs::write(&journal, b"").unwrap();
    let locked = Ledger::open(&journal, 10).unwrap();
    startup_refused(run(), "LEDGER_JOURNAL_LOCKED");
    drop(locked);
    let extra_link = state.join("alias.jsonl");
    std::fs::hard_link(&journal, &extra_link).unwrap();
    startup_refused(run(), "LEDGER_JOURNAL_UNTRUSTED");
    std::fs::remove_file(&extra_link).unwrap();
    let moved_journal = state.join("moved.jsonl");
    std::fs::rename(&journal, &moved_journal).unwrap();
    symlink(&moved_journal, &journal).unwrap();
    startup_refused(run(), "LEDGER_JOURNAL_OPEN");
    std::fs::remove_file(&journal).unwrap();
    std::fs::rename(&moved_journal, &journal).unwrap();
    std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o644)).unwrap();
    startup_refused(run(), "LEDGER_JOURNAL_UNTRUSTED");
    std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o755)).unwrap();
    startup_refused(run(), "LEDGER_STATE_UNTRUSTED");
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let moved = dir.0.join("moved");
    std::fs::rename(&state, &moved).unwrap();
    symlink(&moved, &state).unwrap();
    startup_refused(run(), "LEDGER_STATE_UNTRUSTED");
    std::fs::remove_file(&state).unwrap();
    std::fs::write(&state, b"not a directory").unwrap();
    startup_refused(run(), "LEDGER_STATE_UNTRUSTED");
    std::fs::remove_file(&state).unwrap();
    std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o777)).unwrap();
    startup_refused(run(), "LEDGER_STATE_PARENT_UNTRUSTED");
    std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(!state.exists(), "an untrusted parent must not receive new state");
    let missing = dir.0.join("missing").join("state");
    startup_refused(binary_output(&[OsStr::new("--state-dir"), missing.as_os_str()]), "LEDGER_STATE_PARENT");
    assert!(!dir.0.join("missing").exists(), "parent provisioning stays explicit");
}
