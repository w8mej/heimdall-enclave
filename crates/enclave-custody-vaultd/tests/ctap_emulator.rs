//! GAP-13: the full FS-703 chained ceremony over the out-of-process CTAPHID
//! emulator. The authenticator sits behind a socket in a separate thread
//! (the emulator binary is the same code in its own process), speaking raw
//! 64-byte reports, so everything above the wire is what drives a physical
//! YubiKey.
#![cfg(feature = "ctap-emulator")]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use enclave_core::ipc::SocketAccess;
use enclave_core::profile::{ActionClass, Profile};
use enclave_custody_vaultd::biometric::{Scripted, ScriptedCoreAuthUi};
use enclave_custody_vaultd::ceremony::{CeremonyEngine, CeremonyHardware, PrfTier};
use enclave_custody_vaultd::clock::TestClock;
use enclave_custody_vaultd::ctap::assertion::{EnrolledCredential, SignCountStore};
use enclave_custody_vaultd::ctap::client::{enroll, CtapClient};
use enclave_custody_vaultd::ctap::emulator::{Emulator, EmulatorConfig, SocketHidDevice};
use enclave_custody_vaultd::ctap::hid::HidDevice;
use enclave_custody_vaultd::ctap::mds::{MdsAllowlist, MdsState};
use enclave_custody_vaultd::factors::{required_factors, Factor};
use enclave_custody_vaultd::intent::{CustodyGrant, IntentPayloadV1};

const NOW: i64 = 1_793_884_860;

fn intent() -> IntentPayloadV1 {
    IntentPayloadV1 {
        v: 1,
        schema_version: Some("enclave.intent.v1".into()),
        action_class: ActionClass::A3,
        profile: Profile::L2,
        data_class: None,
        spiffe_id: "spiffe://corporate.internal/enclave/uid/704".into(),
        tool_name: "detokenize_row".into(),
        target_namespace: Some("dev-billing".into()),
        human_summary_trusted: None,
        row_count_bound: Some(1),
        arguments_jcs_sha256: None,
        canonical_arguments_blake3: "5".repeat(64),
        model_blake3: None,
        policy_blake3: "6".repeat(64),
        qif_millibits_delta: Some(0),
        custody_grant: Some(CustodyGrant::None),
        boot_epoch_id: enclave_core::seq::new_boot_epoch_id(),
        rpc_seq_u64: 1,
        ts_utc_ms: 1_762_308_012_405,
        required_factors: required_factors(Profile::L2, ActionClass::A3, false)
            .into_iter()
            .collect(),
        user_turn: None,
    }
}

/// A running emulator: socket, stop flag, server thread.
struct Running {
    socket: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Running {
    fn start(dir: &Path, state: &Path, cfg: EmulatorConfig) -> (Self, MdsState) {
        let socket = dir.join("fido").join("ctaphid.sock");
        let mut emu = Emulator::open(Some(state), cfg).unwrap();
        let mds = MdsState {
            allowlist: MdsAllowlist {
                entries: vec![emu.mds_entry()],
            },
            refreshed_at: NOW,
            expires_at:i64::MAX,
        };
        let listener = enclave_core::ipc::bind(&socket, SocketAccess::OwnerOnly).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let s2 = stop.clone();
        let thread = std::thread::spawn(move || emu.serve(&listener, &s2).unwrap());
        (
            Self {
                socket,
                stop,
                thread: Some(thread),
            },
            mds,
        )
    }
    fn connect(&self) -> SocketHidDevice {
        SocketHidDevice::connect(
            &self.socket,
            enclave_core::ipc::geteuid(),
            Duration::from_secs(5),
        )
        .unwrap()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn cfg() -> EmulatorConfig {
    EmulatorConfig {
        touch_delay: Duration::from_millis(250),
        allow_uid: enclave_core::ipc::geteuid(),
        ..Default::default()
    }
}

/// One chained ceremony (scripted Touch ID → emulated YubiKey) on a fresh
/// engine; returns the tier PRF.
fn ceremony(
    dev: &mut dyn HidDevice,
    cred: &EnrolledCredential,
    mds: &MdsState,
    counters: &mut SignCountStore,
) -> enclave_core::EnclaveResult<Vec<u8>> {
    let mut ui = ScriptedCoreAuthUi::new([Scripted::Approve]);
    let k = ui.enrolled_key();
    let g = CeremonyEngine::new(Profile::L2).run(
        &intent(),
        Some(PrfTier::A3),
        CeremonyHardware {
            biometric: Some(&mut ui),
            sep_key: Some(k),
            sep_bio_blob: None,
            yubikey: Some(dev),
            credential: Some(cred),
            mds: Some(mds),
            counters: Some(counters),
            egress: None,
            ..Default::default()
        },
        &TestClock::at(NOW),
    )?;
    assert!(
        g.factors.contains(&Factor::TouchIdCoreauthui) && g.factors.contains(&Factor::YubikeyUp)
    );
    Ok(g.prf.expect("L2 A3 releases a tier PRF").expose().to_vec())
}

fn tmpdir() -> PathBuf {
    let d = PathBuf::from("/tmp").join(format!("mcpemu-{:x}", enclave_core::rng::u64()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn chained_ceremony_over_the_emulator_socket_with_keepalives_and_restart() {
    let dir = tmpdir();
    let state = dir.join("emulator.state");
    let (run, mds) = Running::start(&dir, &state, cfg());
    let mut dev = run.connect();
    assert_eq!(dev.hub_depth(), 1);
    assert_eq!(dev.firmware(), 0x05_07_01);
    // Enrollment: getInfo, MDS check, makeCredential with packed attestation
    // verified against the emulator's MDS entry — the real-key path.
    let cred = enroll(
        &mut CtapClient::open(&mut dev).unwrap(),
        &mds,
        Profile::L2,
        NOW,
    )
    .unwrap();
    let mut counters = SignCountStore::default();
    // Each assertion waits ~250 ms for the "touch", streaming keep-alives.
    let t = std::time::Instant::now();
    let prf1 = ceremony(&mut dev, &cred, &mds, &mut counters).unwrap();
    assert!(
        t.elapsed() >= Duration::from_millis(200),
        "keep-alives were not exercised"
    );
    let prf2 = ceremony(&mut dev, &cred, &mds, &mut counters).unwrap();
    assert_eq!(prf1, prf2, "hmac-secret reproduces the same tier PRF");
    // The device is seized: a second opener is refused while we hold it.
    let second = SocketHidDevice::connect(
        &run.socket,
        enclave_core::ipc::geteuid(),
        Duration::from_secs(2),
    );
    assert!(second.unwrap_err().is("HID_SEIZED"));
    drop(dev);
    drop(run);
    // Restart the emulator: like a physical key, its credential and counter
    // survive, so the enrolled credential still unlocks the same PRF.
    let (run, _) = Running::start(&dir, &state, cfg());
    let mut dev = run.connect();
    let prf3 = ceremony(&mut dev, &cred, &mds, &mut counters).unwrap();
    assert_eq!(prf1, prf3);
    drop(dev);
    drop(run);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn emulated_key_failures_fail_closed() {
    let dir = tmpdir();
    // The user never touches.
    let (run, mds) = Running::start(
        &dir,
        &dir.join("a.state"),
        EmulatorConfig {
            no_touch: true,
            ..cfg()
        },
    );
    let mut dev = run.connect();
    let cred = {
        // Enrollment needs a touch: enroll against a touching instance of
        // the same device state first.
        drop(dev);
        drop(run);
        let (run, _) = Running::start(&dir, &dir.join("a.state"), cfg());
        let mut d = run.connect();
        let c = enroll(
            &mut CtapClient::open(&mut d).unwrap(),
            &mds,
            Profile::L2,
            NOW,
        )
        .unwrap();
        drop(d);
        drop(run);
        c
    };
    let (run, _) = Running::start(
        &dir,
        &dir.join("a.state"),
        EmulatorConfig {
            no_touch: true,
            ..cfg()
        },
    );
    dev = run.connect();
    let mut counters = SignCountStore::default();
    assert!(ceremony(&mut dev, &cred, &mds, &mut counters)
        .unwrap_err()
        .is("YUBIKEY_TOUCH_TIMEOUT"));
    drop(dev);
    drop(run);
    // A rolled-back device state (a cloned key replaying an old counter).
    let (run, _) = Running::start(&dir, &dir.join("a.state"), cfg());
    let mut dev = run.connect();
    ceremony(&mut dev, &cred, &mds, &mut counters).unwrap();
    let snapshot = std::fs::read(dir.join("a.state")).unwrap();
    ceremony(&mut dev, &cred, &mds, &mut counters).unwrap();
    drop(dev);
    drop(run);
    std::fs::write(dir.join("a.state"), &snapshot).unwrap();
    let (run, _) = Running::start(&dir, &dir.join("a.state"), cfg());
    let mut dev = run.connect();
    assert!(ceremony(&mut dev, &cred, &mds, &mut counters)
        .unwrap_err()
        .is("SIGN_COUNT_REGRESSION"));
    drop(dev);
    drop(run);
    // Yanked mid-ceremony: the device goes away after the hello.
    let sock = dir.join("yank").join("ctaphid.sock");
    let l = enclave_core::ipc::bind(&sock, SocketAccess::OwnerOnly).unwrap();
    let t = std::thread::spawn(move || {
        use std::io::Write;
        let (mut s, _) = l.accept().unwrap();
        let mut h = [0u8; 64];
        h[..26].copy_from_slice(enclave_custody_vaultd::ctap::emulator::HELLO_MAGIC);
        h[30] = 1;
        s.write_all(&h).unwrap();
        // ...and is pulled out.
    });
    let mut dev =
        SocketHidDevice::connect(&sock, enclave_core::ipc::geteuid(), Duration::from_secs(2))
            .unwrap();
    t.join().unwrap();
    assert!(ceremony(&mut dev, &cred, &mds, &mut counters)
        .unwrap_err()
        .is("DEVICE_REMOVED"));
    // A server running as the wrong account is refused before any byte.
    let (run, _) = Running::start(&dir, &dir.join("b.state"), cfg());
    let wrong = SocketHidDevice::connect(
        &run.socket,
        enclave_core::ipc::geteuid() + 1,
        Duration::from_secs(2),
    );
    assert!(wrong.unwrap_err().is("EMULATOR_PEER_REJECTED"));
    drop(run);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn daemon_probe_reaches_the_emulator_and_checks_mds() {
    use enclave_custody_vaultd::entry::probe_yubikey;
    let dir = tmpdir();
    let (run, mds) = Running::start(&dir, &dir.join("p.state"), cfg());
    let mds_file = dir.join("fido-mds.json");
    std::fs::write(&mds_file, serde_json::to_vec(&mds.allowlist).unwrap()).unwrap();
    let args = |extra: &[&str]| {
        let mut a: Vec<String> = [
            "enclave-custody-vaultd",
            "--dev-same-uid",
            "--socket-dir",
            "/tmp",
            "--no-audit",
            "--profile",
            "L2",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        a.extend(extra.iter().map(|s| s.to_string()));
        enclave_core::runtime::DaemonArgs::parse(a).unwrap()
    };
    let transport = format!("emulated:{}", run.socket.display());
    let v = probe_yubikey(&args(&[
        "--yubikey-transport",
        &transport,
        "--mds-file",
        mds_file.to_str().unwrap(),
    ]));
    assert_eq!(v["event"], "YUBIKEY_READY", "{v}");
    assert_eq!(v["firmware"], "5.7.1");
    // A raw allowlist file and its mtime are not authenticated TUF freshness.
    assert_eq!(v["mds"]["allowed"], false, "{v}");
    assert!(v["mds"]["reason"].as_str().unwrap().contains("CUSTODY_METADATA_STALE"));
    assert!(v["extensions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e == "hmac-secret"));
    // Each probe owns and then drops a seized connection. Join the first
    // server before the independent missing-MDS case: its asynchronous
    // refuser may still reject immediate reconnects while processing EOF.
    // Restarting the same persisted fixture avoids a scheduler-dependent
    // HID_SEIZED result without changing transport retries or admission.
    drop(run);
    let (run, _) = Running::start(&dir, &dir.join("p.state"), cfg());
    // Without an MDS allowlist the key is reachable but not allowed.
    let v = probe_yubikey(&args(&["--yubikey-transport", &transport]));
    assert_eq!(v["event"], "YUBIKEY_READY", "{v}");
    assert_eq!(v["mds"]["allowed"], false, "{v}");
    assert_eq!(v["mds"]["reason"], "no --mds-file installed", "{v}");
    drop(run);
    // Default transport is the physical key over IOKit HID.
    let v = probe_yubikey(&args(&[]));
    assert_eq!(v["event"], "YUBIKEY_UNAVAILABLE");
    assert_eq!(v["transport"], "hid");
    let _ = std::fs::remove_dir_all(dir);
}
