//! Out-of-process FIDO2 authenticator emulator over raw CTAPHID reports
//! (GAP-13, build feature `ctap-emulator`).
//!
//! A physical YubiKey is a separate device that UID 703 reaches through
//! IOKit HID, exchanging 64-byte CTAPHID reports. The emulator keeps that
//! shape exactly. It runs as its own process and account (`_enclavefido`),
//! holds its own secrets (persisted like a key's flash), and exchanges the
//! same 64-byte reports over a Unix socket. Everything above the transport
//! is the code that drives a real key:
//!
//! * CTAPHID framing: channel allocation, continuation packets,
//!   keep-alives while waiting for a touch;
//! * CTAP2 CBOR and `pinUvAuthProtocol = 2`;
//! * `hmac-secret` and MDS / attestation checks;
//! * assertion verification and the `signCount` monotonicity check.
//!
//! The choice is one daemon flag, `--yubikey-transport emulated:<socket>`
//! (default `hid`). Without it, and in any build without `ctap-emulator`,
//! the vault opens the physical key with `kIOHIDOptionsTypeSeizeDevice`.
//!
//! Wire protocol: on accept, the server sends one 64-byte hello report:
//!
//! ```text
//! HELLO_MAGIC(26) ‖ firmware u32 BE ‖ hub_depth u8 ‖ uv u8 ‖ 0…
//! ```
//!
//! After that, both directions carry nothing but CTAPHID reports. Like a
//! seized HID device, the emulator serves one client at a time; a second
//! connection is closed at once (`HID_SEIZED`). Mid-ceremony removal is the
//! emulator process exiting: the client sees EOF (`DEVICE_REMOVED`).

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};

use super::hid::{HidDevice, CMD_CBOR, CMD_KEEPALIVE, REPORT};

/// First bytes of the hello report (also the release-build absence marker).
pub const HELLO_MAGIC: &[u8; 26] = b"MCPMac CTAPHID emulator v1";

/// `CTAPHID_KEEPALIVE` status: waiting for user presence.
const KEEPALIVE_UPNEEDED: u8 = 0x02;

/// Device behaviour, fixed at emulator start.
#[derive(Debug, Clone)]
pub struct EmulatorConfig {
    /// Firmware reported by `getInfo` (e.g. `0x05_07_01`).
    pub firmware: u32,
    /// USB topology depth reported to the vault (1 = Apple root port).
    pub hub_depth: u8,
    /// Whether the device can perform on-key UV.
    pub uv_capable: bool,
    /// How long the "user" takes to touch: keep-alive frames are sent for
    /// this long before a `makeCredential` / `getAssertion` reply.
    pub touch_delay: Duration,
    /// The user never touches (`CTAP2_ERR_USER_ACTION_TIMEOUT`).
    pub no_touch: bool,
    /// Only this peer UID may connect (UID 703, or the dev UID).
    pub allow_uid: u32,
}

impl Default for EmulatorConfig {
    fn default() -> Self {
        Self {
            firmware: 0x05_07_01,
            hub_depth: 1,
            uv_capable: true,
            touch_delay: Duration::from_millis(300),
            no_touch: false,
            allow_uid: enclave_core::daemon::DaemonId::CustodyVault.uid(),
        }
    }
}

/// The emulated device and where its secrets persist.
#[derive(Debug)]
pub struct Emulator {
    dev: super::virtual_device::VirtualAuthenticator,
    state: Option<PathBuf>,
    cfg: EmulatorConfig,
}

impl Emulator {
    /// Load the device from `state` (created on first start, like a factory
    /// reset key) or keep it in memory only (`state = None`).
    pub fn open(state: Option<&Path>, cfg: EmulatorConfig) -> EnclaveResult<Self> {
        let mut dev = match state.map(std::fs::read) {
            Some(Ok(raw)) => super::virtual_device::VirtualAuthenticator::import_state(&raw)?,
            Some(Err(e)) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(err!(EIO, "EMULATOR_STATE_READ", "{e}"))
            }
            _ => {
                let mut aaguid = [0u8; 16];
                enclave_core::rng::fill(&mut aaguid);
                super::virtual_device::VirtualAuthenticator::new(aaguid)
            }
        };
        dev.firmware = cfg.firmware;
        dev.uv_capable = cfg.uv_capable;
        dev.hub_depth = cfg.hub_depth;
        dev.presence = if cfg.no_touch {
            super::virtual_device::Presence::NoTouch
        } else {
            super::virtual_device::Presence::Touch
        };
        let e = Self {
            dev,
            state: state.map(Path::to_owned),
            cfg,
        };
        e.persist()?;
        Ok(e)
    }

    /// This device's FIDO MDS allowlist entry (AAGUID, firmware floor and
    /// attestation key), which the operator installs for UID 703 the same
    /// way as Yubico's published entries.
    pub fn mds_entry(&self) -> super::mds::MdsEntry {
        super::mds::MdsEntry {
            aaguid: hex::encode(self.dev.aaguid),
            description: "MCPMac CTAPHID emulator (out-of-process authenticator)".into(),
            min_firmware_version: 0x05_04_00,
            status_reports: vec!["FIDO_CERTIFIED".into()],
            attestation_public_keys: vec![self.dev.attestation_key_mds()],
            attestation_root_certificates: Vec::new(),
        }
    }

    /// Current signature counter.
    pub fn sign_count(&self) -> u32 {
        self.dev.sign_count()
    }

    fn persist(&self) -> EnclaveResult<()> {
        match &self.state {
            Some(p) => enclave_core::fsutil::write_private(p, &self.dev.export_state()),
            None => Ok(()),
        }
    }

    fn hello(&self) -> [u8; REPORT] {
        let mut h = [0u8; REPORT];
        h[..HELLO_MAGIC.len()].copy_from_slice(HELLO_MAGIC);
        let o = HELLO_MAGIC.len();
        h[o..o + 4].copy_from_slice(&self.cfg.firmware.to_be_bytes());
        h[o + 4] = self.cfg.hub_depth;
        h[o + 5] = u8::from(self.cfg.uv_capable);
        h
    }

    /// Serve one connected client until it disconnects.
    pub fn serve_client(&mut self, s: &mut UnixStream) -> EnclaveResult<()> {
        s.write_all(&self.hello())
            .map_err(|e| err!(EIO, "EMULATOR_IO", "{e}"))?;
        let mut needs_touch: Option<u32> = None;
        loop {
            let mut r = [0u8; REPORT];
            match s.read_exact(&mut r) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(err!(EIO, "EMULATOR_IO", "{e}")),
            }
            // A makeCredential / getAssertion init packet: the reply waits
            // for a touch, and a real key sends keep-alives meanwhile.
            if r[4] == (CMD_CBOR | 0x80)
                && matches!(
                    r[7],
                    super::cmd::MAKE_CREDENTIAL | super::cmd::GET_ASSERTION
                )
            {
                needs_touch = Some(u32::from_be_bytes([r[0], r[1], r[2], r[3]]));
            }
            self.dev.write_report(&r)?;
            let mut first = true;
            while let Ok(out) = self.dev.read_report() {
                if first {
                    if let Some(cid) = needs_touch.take() {
                        self.keepalives(s, cid)?;
                    }
                    first = false;
                }
                s.write_all(&out)
                    .map_err(|e| err!(EIO, "EMULATOR_IO", "{e}"))?;
            }
            if !first {
                // A reply went out; credentials or the counter may have changed.
                self.persist()?;
            }
        }
    }

    fn keepalives(&self, s: &mut UnixStream, cid: u32) -> EnclaveResult<()> {
        let step = Duration::from_millis(100);
        let mut waited = Duration::ZERO;
        while waited < self.cfg.touch_delay {
            let mut k = [0u8; REPORT];
            k[..4].copy_from_slice(&cid.to_be_bytes());
            k[4] = CMD_KEEPALIVE | 0x80;
            k[5..7].copy_from_slice(&1u16.to_be_bytes());
            k[7] = KEEPALIVE_UPNEEDED;
            s.write_all(&k)
                .map_err(|e| err!(EIO, "EMULATOR_IO", "{e}"))?;
            std::thread::sleep(step);
            waited += step;
        }
        Ok(())
    }

    /// Accept loop: one client at a time (a second connection is refused,
    /// as `kIOHIDOptionsTypeSeizeDevice` refuses a second opener); peers
    /// other than `allow_uid` are dropped.
    pub fn serve(&mut self, listener: &UnixListener, stop: &AtomicBool) -> EnclaveResult<()> {
        listener
            .set_nonblocking(true)
            .map_err(|e| err!(EIO, "EMULATOR_IO", "{e}"))?;
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut s, _)) => {
                    let _ = s.set_nonblocking(false);
                    match enclave_core::ipc::peer_credentials(&s) {
                        Ok(p) if p.uid == self.cfg.allow_uid => {}
                        _ => continue,
                    }
                    let busy = Arc::new(AtomicBool::new(true));
                    let refuser = spawn_refuser(listener, busy.clone());
                    let r = self.serve_client(&mut s);
                    busy.store(false, Ordering::SeqCst);
                    if let Some(t) = refuser {
                        let _ = t.join();
                    }
                    if let Err(e) = r {
                        eprintln!(
                            "{}",
                            serde_json::json!({"event": "EMULATOR_CLIENT_ERROR", "error": e.to_string()})
                        );
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Err(err!(EIO, "EMULATOR_ACCEPT", "{e}")),
            }
        }
        Ok(())
    }
}

/// While a client holds the device, close every other connection at once.
fn spawn_refuser(
    listener: &UnixListener,
    busy: Arc<AtomicBool>,
) -> Option<std::thread::JoinHandle<()>> {
    let l = listener.try_clone().ok()?;
    Some(std::thread::spawn(move || {
        while busy.load(Ordering::SeqCst) {
            match l.accept() {
                Ok((s, _)) => drop(s),
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }))
}

/// UID 703's side: a [`HidDevice`] over the emulator socket.
#[derive(Debug)]
pub struct SocketHidDevice {
    s: UnixStream,
    hub_depth: u8,
    firmware: u32,
    deadline_ns: Option<u64>,
    io_timeout: Duration,
}

impl SocketHidDevice {
    /// Connect, require the server to run as `server_uid` (the emulator's
    /// own account), and read its hello.
    pub fn connect(path: &Path, server_uid: u32, timeout: Duration) -> EnclaveResult<Self> {
        let mut s = UnixStream::connect(path)
            .map_err(|e| err!(EIO, "YUBIKEY_NOT_PRESENT", "{}: {e}", path.display()))?;
        let peer = enclave_core::ipc::peer_credentials(&s)?;
        if peer.uid != server_uid {
            fail!(
                EACCES,
                "EMULATOR_PEER_REJECTED",
                "emulator socket served by uid {} (expected {server_uid})",
                peer.uid
            );
        }
        s.set_read_timeout(Some(timeout))
            .map_err(|e| err!(EIO, "HID_IO", "{e}"))?;
        let mut h = [0u8; REPORT];
        s.read_exact(&mut h).map_err(|e| match e.kind() {
            std::io::ErrorKind::UnexpectedEof => err!(
                EAGAIN,
                "HID_SEIZED",
                "another process holds the authenticator"
            ),
            _ => err!(EIO, "HID_IO", "{e}"),
        })?;
        if &h[..HELLO_MAGIC.len()] != HELLO_MAGIC {
            fail!(EINVAL, "EMULATOR_HELLO_INVALID");
        }
        let o = HELLO_MAGIC.len();
        Ok(Self {
            s,
            firmware: u32::from_be_bytes([h[o], h[o + 1], h[o + 2], h[o + 3]]),
            hub_depth: h[o + 4],
            deadline_ns: None,
            io_timeout: timeout,
        })
    }

    fn remaining_timeout(&self) -> EnclaveResult<Duration> {
        super::hid::check_deadline(self)?;
        Ok(self.deadline_ns.map_or(self.io_timeout, |deadline| {
            self.io_timeout.min(Duration::from_nanos(
                deadline
                    .saturating_sub(enclave_core::power::continuous_time_ns())
                    .max(1),
            ))
        }))
    }

    /// Firmware the emulator announced.
    pub fn firmware(&self) -> u32 {
        self.firmware
    }
}

impl HidDevice for SocketHidDevice {
    fn write_report(&mut self, report: &[u8; REPORT]) -> EnclaveResult<()> {
        let mut sent = 0;
        while sent < REPORT {
            self.s
                .set_write_timeout(Some(self.remaining_timeout()?))
                .map_err(|_| err!(EIO, "HID_IO"))?;
            match self.s.write(&report[sent..]) {
                Ok(0) => return Err(err!(EIO, "DEVICE_REMOVED")),
                Ok(count) => sent += count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(err!(ETIMEDOUT, "HID_WRITE_TIMEOUT"))
                }
                Err(_) => {
                    enclave_core::power::registry()
                        .execute(enclave_core::power::WipeTrigger::AuthenticatorYank);
                    return Err(err!(EIO, "DEVICE_REMOVED"));
                }
            }
        }
        super::hid::check_deadline(self)
    }

    fn read_report(&mut self) -> EnclaveResult<[u8; REPORT]> {
        let mut report = [0u8; REPORT];
        let mut received = 0;
        while received < REPORT {
            self.s
                .set_read_timeout(Some(self.remaining_timeout()?))
                .map_err(|_| err!(EIO, "HID_IO"))?;
            match self.s.read(&mut report[received..]) {
                Ok(0) => {
                    enclave_core::power::registry()
                        .execute(enclave_core::power::WipeTrigger::AuthenticatorYank);
                    return Err(err!(EIO, "DEVICE_REMOVED"));
                }
                Ok(count) => received += count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(err!(ETIMEDOUT, "HID_READ_TIMEOUT"))
                }
                Err(_) => {
                    enclave_core::power::registry()
                        .execute(enclave_core::power::WipeTrigger::AuthenticatorYank);
                    return Err(err!(EIO, "DEVICE_REMOVED"));
                }
            }
        }
        super::hid::check_deadline(self)?;
        Ok(report)
    }
    fn hub_depth(&self) -> u8 {
        self.hub_depth
    }
    fn deadline_ns(&self) -> Option<u64> {
        self.deadline_ns
    }
    fn set_deadline_ns(&mut self, deadline: Option<u64>) -> EnclaveResult<()> {
        self.deadline_ns = deadline;
        Ok(())
    }
}

#[cfg(test)]
mod absolute_deadline_tests {
    use super::*;
    #[test]
    fn partial_frame_trickle_cannot_restart_the_absolute_deadline() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let mut device = SocketHidDevice {
            s: reader,
            hub_depth: 1,
            firmware: 0x050701,
            deadline_ns: Some(enclave_core::power::continuous_time_ns() + 20_000_000),
            io_timeout: Duration::from_secs(2),
        };
        let worker = std::thread::spawn(move || {
            for _ in 0..REPORT {
                if writer.write_all(&[0]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(3));
            }
        });
        let start = std::time::Instant::now();
        assert!(device.read_report().is_err());
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "partial reads extended absolute deadline"
        );
        drop(device);
        worker.join().unwrap();
    }
}
