//! `enclave-fido-emulator` — out-of-process CTAPHID authenticator (GAP-13).
//! Built only with `--features ctap-emulator`.
//!
//! ```text
//! enclave-fido-emulator --socket <path> [--state <file>] [--mds-out <file>]
//!     [--firmware 5.7.1] [--hub-depth 1] [--no-uv] [--touch-delay-ms 300]
//!     [--no-touch] [--allow-uid 703] [--dev]
//! ```
//!
//! Production: runs as `_enclavefido` (UID 706) under launchd and Seatbelt,
//! serves `<mesh>/fido/ctaphid.sock` to UID 703 only (client group
//! `_enclave_fido_c`), and keeps its secrets in `--state`. `--dev`: any UID,
//! owner-only socket, peers must be the same UID.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use enclave_core::error::EnclaveResult;
use enclave_core::ipc::SocketAccess;
use enclave_core::{err, fail};
use enclave_custody_vaultd::ctap::emulator::{Emulator, EmulatorConfig};
use enclave_custody_vaultd::ctap::transport::{EMULATOR_CLIENT_GID, EMULATOR_UID};

fn firmware(s: &str) -> EnclaveResult<u32> {
    let p: Vec<u32> = s
        .split('.')
        .map(|x| {
            x.parse::<u32>()
                .map_err(|_| err!(EINVAL, "ARG_FIRMWARE", "{s}"))
        })
        .collect::<EnclaveResult<_>>()?;
    match p.as_slice() {
        [a, b, c] if *a < 256 && *b < 256 && *c < 256 => Ok(a << 16 | b << 8 | c),
        _ => fail!(
            EINVAL,
            "ARG_FIRMWARE",
            "expected MAJOR.MINOR.PATCH, got {s}"
        ),
    }
}

fn run() -> EnclaveResult<()> {
    let mut socket: Option<PathBuf> = None;
    let mut state: Option<PathBuf> = None;
    let mut mds_out: Option<PathBuf> = None;
    let mut cfg = EmulatorConfig::default();
    let mut dev = false;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut val = || {
            it.next()
                .ok_or_else(|| err!(EINVAL, "ARG_MISSING_VALUE", "{a}"))
        };
        match a.as_str() {
            "--socket" => socket = Some(val()?.into()),
            "--state" => state = Some(val()?.into()),
            "--mds-out" => mds_out = Some(val()?.into()),
            "--firmware" => cfg.firmware = firmware(&val()?)?,
            "--hub-depth" => {
                cfg.hub_depth = val()?.parse().map_err(|_| err!(EINVAL, "ARG_HUB_DEPTH"))?
            }
            "--touch-delay-ms" => {
                cfg.touch_delay = Duration::from_millis(
                    val()?
                        .parse()
                        .map_err(|_| err!(EINVAL, "ARG_TOUCH_DELAY"))?,
                )
            }
            "--allow-uid" => {
                cfg.allow_uid = val()?.parse().map_err(|_| err!(EINVAL, "ARG_ALLOW_UID"))?
            }
            "--no-uv" => cfg.uv_capable = false,
            "--no-touch" => cfg.no_touch = true,
            "--dev" => dev = true,
            _ => fail!(EINVAL, "ARG_UNKNOWN", "{a}"),
        }
    }
    let socket = socket.ok_or_else(|| err!(EINVAL, "ARG_SOCKET_REQUIRED"))?;
    let me = enclave_core::ipc::geteuid();
    let access = if dev {
        cfg.allow_uid = me;
        SocketAccess::OwnerOnly
    } else {
        if me != EMULATOR_UID {
            fail!(EPERM, "WRONG_EMULATOR_UID", "the emulator runs as _enclavefido (uid {EMULATOR_UID}), got {me}; use --dev for development");
        }
        if !enclave_core::resource::harden_process() {
            fail!(EPERM, "HARDENING_FAILED");
        }
        SocketAccess::Group {
            gid: EMULATOR_CLIENT_GID,
        }
    };
    let mut emu = Emulator::open(state.as_deref(), cfg)?;
    if let Some(p) = mds_out {
        let entry = serde_json::to_vec_pretty(&emu.mds_entry())
            .map_err(|e| err!(EIO, "MDS_ENCODE", "{e}"))?;
        std::fs::write(&p, entry).map_err(|e| err!(EIO, "MDS_WRITE", "{}: {e}", p.display()))?;
    }
    let listener = enclave_core::ipc::bind(&socket, access)?;
    eprintln!(
        "{}",
        serde_json::json!({"event": "EMULATOR_READY", "socket": socket, "sign_count": emu.sign_count(), "mds_entry": emu.mds_entry()})
    );
    let stop = Arc::new(AtomicBool::new(false));
    enclave_core::runtime::install_signal_flag(stop.clone());
    let r = emu.serve(&listener, &stop);
    let _ = std::fs::remove_file(&socket);
    r
}

fn main() {
    if let Err(e) = run() {
        enclave_core::runtime::exit_with(&e);
    }
}
