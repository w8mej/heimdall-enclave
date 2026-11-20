//! Capability-only diagnostics. The wire guard makes credential/PIN operations
//! unreachable even if a future caller accidentally uses a mutating client API.

use std::time::{Duration, Instant};

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};

use super::client::{AuthenticatorInfo, CtapClient};
use super::hid::{HidDevice, BROADCAST_CID, CMD_CBOR, CMD_INIT, REPORT};

/// Device I/O restricted to INIT and GetInfo, with an absolute deadline.
/// Underlying reads/writes must also have a bounded native transport timeout.
#[derive(Debug)]
pub struct ReadOnlyDevice<D> {
    inner: D,
    deadline: Instant,
}

impl<D: HidDevice> ReadOnlyDevice<D> {
    /// Establish the deadline once, including all subsequent frames/keepalives.
    pub fn new(inner: D, budget: Duration) -> EnclaveResult<Self> {
        if budget.is_zero() || budget > Duration::from_secs(10) {
            fail!(EINVAL, "FIDO_DIAGNOSTIC_BUDGET");
        }
        Ok(Self {
            inner,
            deadline: Instant::now() + budget,
        })
    }

    fn check_deadline(&self) -> EnclaveResult<()> {
        if Instant::now() >= self.deadline {
            fail!(ETIMEDOUT, "FIDO_DIAGNOSTIC_TIMEOUT");
        }
        Ok(())
    }
}

impl<D: HidDevice> HidDevice for ReadOnlyDevice<D> {
    fn write_report(&mut self, report: &[u8; REPORT]) -> EnclaveResult<()> {
        self.check_deadline()?;
        let cid = u32::from_be_bytes(report[..4].try_into().expect("four bytes"));
        let len = u16::from_be_bytes([report[5], report[6]]);
        let init = report[4] == CMD_INIT | 0x80 && cid == BROADCAST_CID && len == 8;
        let info = report[4] == CMD_CBOR | 0x80
            && cid != 0
            && cid != BROADCAST_CID
            && len == 1
            && report[7] == super::cmd::GET_INFO;
        if !init && !info {
            fail!(EPERM, "FIDO_DIAGNOSTIC_OPERATION_FORBIDDEN");
        }
        self.inner.write_report(report)?;
        self.check_deadline()
    }

    fn read_report(&mut self) -> EnclaveResult<[u8; REPORT]> {
        self.check_deadline()?;
        let result = self.inner.read_report()?;
        self.check_deadline()?;
        Ok(result)
    }

    fn hub_depth(&self) -> u8 {
        self.inner.hub_depth()
    }
}

/// A capabilities/topology observation, never authenticated enrolled-key proof.
#[derive(Debug)]
pub struct Observation {
    /// Advertised, untrusted capabilities.
    pub info: AuthenticatorInfo,
    /// Topology observation (not a proof of a root-port-only chain).
    pub hub_depth: u8,
}

/// Probe every candidate with the production client and refuse ambiguity.
/// Any unresponsive candidate prevents a claim of unique selection.
pub fn observe<D: HidDevice>(
    devices: Vec<D>,
    expected_model: Option<&[u8; 16]>,
    budget: Duration,
) -> EnclaveResult<Observation> {
    if devices.is_empty() {
        fail!(EIO, "NO_FIDO_DEVICE");
    }
    if devices.len() > 32 {
        fail!(E2BIG, "FIDO_DEVICE_LIMIT");
    }
    let started = Instant::now();
    let mut selected = None;
    for device in devices {
        let remaining = budget
            .checked_sub(started.elapsed())
            .ok_or_else(|| err!(ETIMEDOUT, "FIDO_DIAGNOSTIC_TIMEOUT"))?;
        let mut guarded = ReadOnlyDevice::new(device, remaining)?;
        let hub_depth = guarded.hub_depth();
        let info = CtapClient::open(&mut guarded)?.get_info()?;
        if expected_model.is_some_and(|expected| expected != &info.aaguid) {
            continue;
        }
        if selected.is_some() {
            fail!(EACCES, "FIDO_MULTIPLE_MATCHING_DEVICES");
        }
        selected = Some(Observation { info, hub_depth });
    }
    selected.ok_or_else(|| err!(EACCES, "ENROLLED_FIDO_DEVICE_NOT_FOUND"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctap::hid::packetize;
    use crate::ctap::virtual_device::VirtualAuthenticator;

    #[test]
    fn actual_client_get_info_allowed_and_credential_pin_commands_unreachable() {
        let mut guarded =
            ReadOnlyDevice::new(VirtualAuthenticator::new([7; 16]), Duration::from_secs(1))
                .unwrap();
        let mut client = CtapClient::open(&mut guarded).unwrap();
        assert_eq!(client.get_info().unwrap().aaguid, [7; 16]);
        assert!(client
            .make_credential(&[1; 32], b"synthetic", &[-8])
            .unwrap_err()
            .is("FIDO_DIAGNOSTIC_OPERATION_FORBIDDEN"));
        assert!(client
            .key_agreement()
            .unwrap_err()
            .is("FIDO_DIAGNOSTIC_OPERATION_FORBIDDEN"));
        assert!(client
            .get_assertion(b"synthetic", &[1; 32], false, None)
            .unwrap_err()
            .is("FIDO_DIAGNOSTIC_OPERATION_FORBIDDEN"));
    }

    #[test]
    fn diagnostic_selection_matches_model_and_refuses_ambiguity() {
        let observation = observe(
            vec![
                VirtualAuthenticator::new([1; 16]),
                VirtualAuthenticator::new([2; 16]),
            ],
            Some(&[2; 16]),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(observation.info.aaguid, [2; 16]);
        assert!(observe(
            vec![
                VirtualAuthenticator::new([1; 16]),
                VirtualAuthenticator::new([1; 16])
            ],
            Some(&[1; 16]),
            Duration::from_secs(1)
        )
        .unwrap_err()
        .is("FIDO_MULTIPLE_MATCHING_DEVICES"));
        assert!(observe(
            vec![VirtualAuthenticator::new([1; 16])],
            Some(&[2; 16]),
            Duration::from_secs(1)
        )
        .unwrap_err()
        .is("ENROLLED_FIDO_DEVICE_NOT_FOUND"));
        assert!(observe(
            Vec::<VirtualAuthenticator>::new(),
            None,
            Duration::from_secs(1)
        )
        .unwrap_err()
        .is("NO_FIDO_DEVICE"));
    }

    #[derive(Debug)]
    struct Broken;
    impl HidDevice for Broken {
        fn write_report(&mut self, _: &[u8; REPORT]) -> EnclaveResult<()> {
            Ok(())
        }
        fn read_report(&mut self) -> EnclaveResult<[u8; REPORT]> {
            Ok(packetize(BROADCAST_CID, CMD_INIT, &[0; 17])?.remove(0))
        }
        fn hub_depth(&self) -> u8 {
            1
        }
    }
    #[test]
    fn malformed_init_is_not_hidden_as_missing_key() {
        assert!(observe(vec![Broken], None, Duration::from_secs(1))
            .unwrap_err()
            .is("CTAPHID_INIT_NONCE_MISMATCH"));
    }

    #[test]
    fn expired_budget_blocks_io_and_mutated_framing_cannot_smuggle_commands() {
        let mut guarded = ReadOnlyDevice::new(Broken, Duration::from_secs(1)).unwrap();
        for command in [
            super::super::cmd::MAKE_CREDENTIAL,
            super::super::cmd::GET_ASSERTION,
            super::super::cmd::CLIENT_PIN,
        ] {
            let report = packetize(7, CMD_CBOR, &[command]).unwrap().remove(0);
            assert!(guarded
                .write_report(&report)
                .unwrap_err()
                .is("FIDO_DIAGNOSTIC_OPERATION_FORBIDDEN"));
        }
        let mut report = packetize(7, CMD_CBOR, &[super::super::cmd::GET_INFO])
            .unwrap()
            .remove(0);
        report[6] = 2;
        assert!(guarded.write_report(&report).is_err());
        report[4] = 0;
        assert!(guarded.write_report(&report).is_err());
        guarded.deadline = Instant::now();
        assert!(guarded
            .read_report()
            .unwrap_err()
            .is("FIDO_DIAGNOSTIC_TIMEOUT"));
    }
}
