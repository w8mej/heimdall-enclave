//! Which wire reaches the authenticator (GAP-13): one daemon flag,
//! `--yubikey-transport`.
//!
//! * `hid` (default): the physical key over IOKit HID, seized
//!   (`kIOHIDOptionsTypeSeizeDevice`). Needs the `macos-hid` build.
//! * `emulated:<socket>`: the out-of-process CTAPHID emulator
//!   ([`super::emulator`]). Only in a `ctap-emulator` build. The server must
//!   run as the emulator account, `_enclavefido` (UID 706), or as the dev UID
//!   in development.
//!
//! Above this point, both transports run identical code. Going from the
//! emulator to a real YubiKey means building without `ctap-emulator`,
//! dropping the flag and enrolling the key.

use enclave_core::error::EnclaveResult;
use enclave_core::fail;

use super::hid::HidDevice;

/// The emulator's account (`_enclavefido`): UID 706, primary group 8706.
pub const EMULATOR_UID: u32 = 706;
/// Primary GID of `_enclavefido` (87xx block, ADR-006 amendment).
pub const EMULATOR_GID: u32 = 8706;
/// Account name.
pub const EMULATOR_ACCOUNT: &str = "_enclavefido";
/// Client group of the emulator socket (sole member: `_piivault`).
pub const EMULATOR_CLIENT_GROUP: &str = "_enclave_fido_c";
/// Its GID.
pub const EMULATOR_CLIENT_GID: u32 = 8717;
/// Socket sub-directory of the mesh (`<socket_dir>/fido/ctaphid.sock`).
pub const EMULATOR_SOCKET_DIR: &str = "fido";
/// Socket file name.
pub const EMULATOR_SOCKET: &str = "ctaphid.sock";

/// A parsed `--yubikey-transport` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    /// IOKit HID.
    Hid,
    /// The CTAPHID emulator at this socket.
    Emulated(std::path::PathBuf),
}

impl Transport {
    /// Parse `hid` | `emulated:<path>`. A build without `ctap-emulator`
    /// refuses `emulated:` (`CTAP_EMULATOR_NOT_COMPILED`), so a plist edit
    /// cannot point a release vault at a software authenticator.
    pub fn parse(s: &str) -> EnclaveResult<Self> {
        match s.split_once(':') {
            None if s == "hid" => Ok(Self::Hid),
            Some(("emulated", p)) if !p.is_empty() => {
                if cfg!(feature = "ctap-emulator") {
                    Ok(Self::Emulated(p.into()))
                } else {
                    fail!(
                        EPERM,
                        "CTAP_EMULATOR_NOT_COMPILED",
                        "this build has no CTAPHID emulator transport; use `hid` (a physical key)"
                    )
                }
            }
            _ => fail!(
                EINVAL,
                "YUBIKEY_TRANSPORT_INVALID",
                "expected `hid` or `emulated:<socket>`, got {s:?}"
            ),
        }
    }

    /// Open the authenticator. `server_uid` is the emulator account expected
    /// on the socket (ignored for HID).
    pub fn open(&self, server_uid: u32) -> EnclaveResult<Box<dyn HidDevice + Send>> {
        match self {
            Self::Hid => open_hid(None),
            Self::Emulated(p) => open_emulated(p, server_uid),
        }
    }
    /// Select by the enrolled model AAGUID; no credential/key-agreement traffic
    /// is sent to candidates before selection (only INIT and getInfo).
    pub fn open_enrolled(
        &self,
        server_uid: u32,
        aaguid: &[u8; 16],
    ) -> EnclaveResult<Box<dyn HidDevice + Send>> {
        match self {
            Self::Hid => open_hid(Some(aaguid)),
            Self::Emulated(p) => select_device(vec![open_emulated(p, server_uid)?], Some(aaguid)),
        }
    }
}

/// Shared selection logic, exercised with actual CTAP virtual transports.
/// AAGUID identifies a model, not one physical credential: ambiguous matches
/// fail closed; later assertions must still verify the enrolled credential.
pub(crate) fn select_device(
    devices: Vec<Box<dyn HidDevice + Send>>,
    expected: Option<&[u8; 16]>,
) -> EnclaveResult<Box<dyn HidDevice + Send>> {
    let mut selected = None;
    for mut device in devices {
        // An unresponsive candidate may be another matching authenticator.
        // Do not silently select a different key after busy/removal/parse errors.
        let info = super::client::CtapClient::open(device.as_mut())?.get_info()?;
        if expected.is_some_and(|a| *a != info.aaguid) {
            continue;
        }
        if selected.is_some() {
            fail!(EACCES, "FIDO_MULTIPLE_MATCHING_DEVICES");
        }
        selected = Some(device);
    }
    let mut selected =
        selected.ok_or_else(|| enclave_core::err!(EACCES, "ENROLLED_FIDO_DEVICE_NOT_FOUND"))?;
    selected.bind_selected_instance()?;
    Ok(selected)
}

#[cfg(all(target_os = "macos", feature = "macos-hid"))]
fn open_hid(expected: Option<&[u8; 16]>) -> EnclaveResult<Box<dyn HidDevice + Send>> {
    let devices = super::macos_hid::MacHidDevice::enumerate()?
        .into_iter()
        .map(|d| Box::new(d) as Box<dyn HidDevice + Send>)
        .collect();
    select_device(devices, expected)
}

#[cfg(not(all(target_os = "macos", feature = "macos-hid")))]
fn open_hid(_expected: Option<&[u8; 16]>) -> EnclaveResult<Box<dyn HidDevice + Send>> {
    fail!(
        EPERM,
        "HID_TRANSPORT_NOT_COMPILED",
        "IOKit HID needs a macOS build with the `macos-hid` feature"
    )
}

#[cfg(feature = "ctap-emulator")]
fn open_emulated(p: &std::path::Path, server_uid: u32) -> EnclaveResult<Box<dyn HidDevice + Send>> {
    Ok(Box::new(super::emulator::SocketHidDevice::connect(
        p,
        server_uid,
        std::time::Duration::from_secs(30),
    )?))
}

#[cfg(not(feature = "ctap-emulator"))]
fn open_emulated(
    _p: &std::path::Path,
    _server_uid: u32,
) -> EnclaveResult<Box<dyn HidDevice + Send>> {
    fail!(EPERM, "CTAP_EMULATOR_NOT_COMPILED")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_transport() {
        assert_eq!(Transport::parse("hid").unwrap(), Transport::Hid);
        assert!(Transport::parse("usb")
            .unwrap_err()
            .is("YUBIKEY_TRANSPORT_INVALID"));
        assert!(Transport::parse("emulated:")
            .unwrap_err()
            .is("YUBIKEY_TRANSPORT_INVALID"));
        let e = Transport::parse("emulated:/tmp/x.sock");
        if cfg!(feature = "ctap-emulator") {
            assert_eq!(e.unwrap(), Transport::Emulated("/tmp/x.sock".into()));
        } else {
            assert!(e.unwrap_err().is("CTAP_EMULATOR_NOT_COMPILED"));
        }
    }
    #[test]
    fn foreign_before_enrolled_is_skipped_and_ambiguous_models_are_refused() {
        use crate::ctap::{client::CtapClient, virtual_device::VirtualAuthenticator};
        let devices = || {
            vec![
                Box::new(VirtualAuthenticator::new([1; 16])) as Box<dyn HidDevice + Send>,
                Box::new(VirtualAuthenticator::new([2; 16])) as Box<dyn HidDevice + Send>,
            ]
        };
        let mut selected = select_device(devices(), Some(&[2; 16])).unwrap();
        assert_eq!(
            CtapClient::open(selected.as_mut())
                .unwrap()
                .get_info()
                .unwrap()
                .aaguid,
            [2; 16]
        );
        assert!(select_device(devices(), Some(&[3; 16]))
            .unwrap_err()
            .is("ENROLLED_FIDO_DEVICE_NOT_FOUND"));
        assert!(select_device(devices(), None)
            .unwrap_err()
            .is("FIDO_MULTIPLE_MATCHING_DEVICES"));
        let same = vec![
            Box::new(VirtualAuthenticator::new([2; 16])) as Box<dyn HidDevice + Send>,
            Box::new(VirtualAuthenticator::new([2; 16])) as Box<dyn HidDevice + Send>,
        ];
        assert!(select_device(same, Some(&[2; 16]))
            .unwrap_err()
            .is("FIDO_MULTIPLE_MATCHING_DEVICES"));
    }
    #[cfg(all(target_os = "macos", feature = "macos-hid"))]
    #[test]
    #[ignore = "two actual FIDO devices, depot_HW=1, depot_EXPECTED_AAGUID required"]
    fn physical_foreign_before_enrolled_selection() {
        assert_eq!(std::env::var("depot_HW").as_deref(), Ok("1"));
        let expected: [u8; 16] = hex::decode(std::env::var("depot_EXPECTED_AAGUID").unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let mut devices = Vec::new();
        for mut dev in super::super::macos_hid::MacHidDevice::enumerate().unwrap() {
            let info = super::super::client::CtapClient::open(&mut dev)
                .unwrap()
                .get_info()
                .unwrap();
            devices.push((
                info.aaguid == expected,
                Box::new(dev) as Box<dyn HidDevice + Send>,
            ));
        }
        devices.sort_by_key(|(matches, _)| *matches);
        assert!(
            devices.len() >= 2 && !devices[0].0 && devices.iter().any(|(matches, _)| *matches),
            "connect both a foreign model and the enrolled model"
        );
        let mut selected = select_device(
            devices.into_iter().map(|(_, d)| d).collect(),
            Some(&expected),
        )
        .unwrap();
        let info = super::super::client::CtapClient::open(selected.as_mut())
            .unwrap()
            .get_info()
            .unwrap();
        assert_eq!(info.aaguid, expected);
        println!("F84 ACTUAL_HID_SELECTION PASS foreign-first ordered candidates selected enrolled AAGUID {}",hex::encode(expected));
    }
}
